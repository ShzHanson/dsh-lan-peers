// dsh-lan-peers · v0.8.5-α 群身份核心（P1：签名与加密分离）
//
// 解决的问题：现有群消息签名 = HMAC-SHA256(HKDF(groupKey), canonical)，groupKey 全体共享
// → 任何成员都能用别人的 senderPeerId 签名。本模块把**真实性**换成每成员 Ed25519 私钥签名，
// groupKey 只留作广播加密（泄露也不能再冒充他人）。
//
// 本文件只做原语与文件格式，**不接线协议层**：协议层只调用这里导出的函数，
// 不许自己拼 canonical（拼错了会静默降级成"验不过"）。
//
// 零依赖：只用 node 内置模块（crypto / fs / path / os，外加 child_process —— 读 Windows
// 注册表的 MachineGuid 只能问 reg.exe，node 没有注册表 API），没有任何第三方依赖。
//
// 设计冻结文档：internal-docs/group-identity-design.md §2/§3/§5
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';

/** 私钥文件相对 stateDir 的位置：<stateDir>/group/member-key.json */
export const MEMBER_KEY_DIR = 'group';
export const MEMBER_KEY_FILE = 'member-key.json';

/** HKDF 的 info：设备绑定派生密钥的域标签 */
export const IDENTITY_INFO = 'lan-peers-group-identity';

/** 私钥文件格式版本 */
export const KEY_FILE_VERSION = 1;

/** 证书签名算法标识 */
export const CERT_ALG = 'ed25519';

/** 旧证书过期后仍被接受的宽限（7 天） */
export const DEFAULT_GRACE_MS = 7 * 24 * 60 * 60 * 1000;

/** 轮换周期（30 天） */
export const DEFAULT_ROTATE_AFTER_MS = 30 * 24 * 60 * 60 * 1000;

/** 稳定错误码：私钥文件存在但解不开（换机器 / 指纹变了 / 文件被改） */
export const IDENTITY_UNAVAILABLE = 'identity-unavailable';
/** 稳定错误码：私钥文件根本不存在（调用方可以先 createKeypair + saveKeypair） */
export const IDENTITY_MISSING = 'identity-missing';

const KEY_LEN = 32;
const SALT_LEN = 16;
const GCM_NONCE_LEN = 12;
const GCM_TAG_LEN = 16;

const emptyBuffer = () => Buffer.alloc(0);

const identityError = (code, detail) => {
  const err = new Error(detail ? `${code}: ${detail}` : code);
  err.code = code;
  return err;
};

const sha256 = (value) => createHash('sha256')
  .update(value == null ? emptyBuffer() : Buffer.isBuffer(value) ? value : Buffer.from(String(value), 'utf8'))
  .digest();

const sha256Hex = (value) => sha256(value).toString('hex');

/** 私钥文件绝对路径：<stateDir>/group/member-key.json */
export function memberKeyPath(stateDir) {
  return path.join(String(stateDir ?? ''), MEMBER_KEY_DIR, MEMBER_KEY_FILE);
}

// ---------------------------------------------------------------------------
// 1. 设备指纹：machineId + 用户名 + 主机名 → sha256 前 32 字节
// ---------------------------------------------------------------------------

let cachedMachineId;

/**
 * 读本机 machineId：
 *   Windows  HKLM\SOFTWARE\Microsoft\Cryptography 的 MachineGuid（走 reg.exe query）
 *   Linux    /etc/machine-id（回落 /var/lib/dbus/machine-id）
 * 取不到返回 ''（**不抛错**，交给 deviceFingerprint 标记 degraded）。
 */
export function readMachineId() {
  if (cachedMachineId !== undefined) return cachedMachineId;
  let value = '';
  try {
    if (process.platform === 'win32') {
      // 注册表没有 node 原生 API：问系统自带的 reg.exe（内置 child_process，不是第三方依赖）
      const out = execFileSync(
        'reg.exe',
        ['query', 'HKLM\\SOFTWARE\\Microsoft\\Cryptography', '/v', 'MachineGuid', '/reg:64'],
        { encoding: 'utf8', windowsHide: true, timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] },
      );
      const matched = /MachineGuid\s+REG_SZ\s+(\S+)/.exec(String(out ?? ''));
      value = matched ? matched[1].trim() : '';
    } else {
      for (const candidate of ['/etc/machine-id', '/var/lib/dbus/machine-id']) {
        try {
          const text = fs.readFileSync(candidate, 'utf8').trim();
          if (text !== '') { value = text; break; }
        } catch { /* 试下一个候选 */ }
      }
    }
  } catch {
    value = '';
  }
  cachedMachineId = value;
  return value;
}

/** 用户名（取不到退环境变量，再取不到空串） */
function currentUsername() {
  try {
    const name = os.userInfo().username;
    if (name) return String(name);
  } catch { /* 落到环境变量 */ }
  return String(process.env.USERNAME ?? process.env.USER ?? '');
}

function currentHostname() {
  try {
    return String(os.hostname() ?? '');
  } catch {
    return '';
  }
}

/**
 * 设备指纹 = sha256(machineId + username + hostname)（32 字节）。
 * 返回 { fingerprint: Buffer(32), hex, degraded, machineId }：
 *   - machineId 取不到时 degraded=true，指纹退化为 username+hostname（**不抛错**）；
 *   - 全部料都取不到时同样 degraded=true（指纹仍是 32 字节，只是熵低）。
 * options.machineId / username / hostname 用于注入（测试与"换机器模拟"）；传 undefined 走真机。
 */
export function deviceFingerprint(options = {}) {
  const machineId = options.machineId === undefined ? readMachineId() : String(options.machineId ?? '');
  const username = options.username === undefined ? currentUsername() : String(options.username ?? '');
  const hostname = options.hostname === undefined ? currentHostname() : String(options.hostname ?? '');
  const degraded = String(machineId).trim() === '';
  // 规格：直接拼接（machineId + username + hostname），不加分隔符
  const fingerprint = sha256(`${machineId}${username}${hostname}`);
  return { fingerprint, hex: fingerprint.toString('hex'), degraded, machineId: String(machineId) };
}

/** 把 Buffer / hex / deviceFingerprint() 结果 / 任意字符串统一成 32 字节 Buffer */
export function normalizeFingerprint(value) {
  if (Buffer.isBuffer(value)) {
    if (value.length !== KEY_LEN) throw new TypeError('bad-fingerprint-length');
    return Buffer.from(value);
  }
  if (value && typeof value === 'object') {
    if (Buffer.isBuffer(value.fingerprint)) return normalizeFingerprint(value.fingerprint);
    if (typeof value.hex === 'string') return normalizeFingerprint(value.hex);
  }
  if (typeof value !== 'string') throw new TypeError('bad-fingerprint');
  const hex = value.trim();
  if (/^[0-9a-fA-F]{64}$/.test(hex)) return Buffer.from(hex, 'hex');
  return sha256(hex); // 任意口令/字符串也接受，按 sha256 归一
}

const resolveFingerprint = (override) => (override === undefined
  ? deviceFingerprint().fingerprint
  : normalizeFingerprint(override));

// ---------------------------------------------------------------------------
// 2. 密钥对：Ed25519
// ---------------------------------------------------------------------------

const keyToPrivate = (key) => (key && typeof key === 'object' && key.type === 'private'
  ? key
  : createPrivateKey(key));

const keyToPublic = (key) => (key && typeof key === 'object' && key.type === 'public'
  ? key
  : createPublicKey(key));

/** 公钥指纹：sha256(SPKI DER) hex —— 只用于 hint / 日志 / 信任根比对，不是密钥材料 */
export function publicKeyFingerprint(publicKey) {
  const key = keyToPublic(publicKey);
  return sha256Hex(key.export({ type: 'spki', format: 'der' }));
}

const publicKeyText = (publicKey) => keyToPublic(publicKey).export({ type: 'spki', format: 'der' }).toString('base64');

/** 从证书里的 pubKey 文本（base64 SPKI DER 或 PEM）还原 KeyObject */
export function publicKeyFromText(text) {
  const value = String(text ?? '');
  if (value.includes('-----BEGIN')) return createPublicKey(value);
  return createPublicKey({ key: Buffer.from(value, 'base64'), format: 'der', type: 'spki' });
}

/**
 * 生成成员密钥对（Ed25519）。
 * 返回 { alg, publicKey, privateKey, publicKeyDer, publicKeyPem, privateKeyPem, publicKeyFingerprint, shortId }
 *   publicKeyDer = base64(SPKI DER)（证书里的 pubKey 就用这个）
 *   shortId      = 指纹前 8 位，只用于人看的短 id
 */
export function createKeypair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publicKeyDer = publicKeyText(publicKey);
  const fingerprint = publicKeyFingerprint(publicKey);
  return {
    alg: 'ed25519',
    publicKey,
    privateKey,
    publicKeyDer,
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicKeyFingerprint: fingerprint,
    shortId: fingerprint.slice(0, 8),
  };
}

// ---------------------------------------------------------------------------
// 3. 私钥加密落盘（铁律）：member-key.json = { v, salt, nonce, ct, hint }
//    K  = HKDF-SHA256(设备指纹, salt, 'lan-peers-group-identity', 32)
//    ct = base64url(AES-256-GCM(K, pkcs8-DER(私钥)) || tag)   ← tag 附在末尾
//    hint 只放公钥指纹 / 短 id，**绝不放私钥**
// ---------------------------------------------------------------------------

const deriveKeyFromFingerprint = (fingerprint, salt) => Buffer.from(
  hkdfSync('sha256', fingerprint, salt, IDENTITY_INFO, KEY_LEN),
);

function sealPrivateKey(privateKey, fingerprint) {
  const der = keyToPrivate(privateKey).export({ type: 'pkcs8', format: 'der' });
  const salt = randomBytes(SALT_LEN);
  const nonce = randomBytes(GCM_NONCE_LEN);
  const key = deriveKeyFromFingerprint(fingerprint, salt);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  const body = Buffer.concat([cipher.update(der), cipher.final()]);
  return {
    salt: salt.toString('base64url'),
    nonce: nonce.toString('base64url'),
    ct: Buffer.concat([body, cipher.getAuthTag()]).toString('base64url'),
  };
}

function openPrivateKey({ salt, nonce, ct }, fingerprint) {
  const rawSalt = Buffer.from(String(salt ?? ''), 'base64url');
  const rawNonce = Buffer.from(String(nonce ?? ''), 'base64url');
  const rawCt = Buffer.from(String(ct ?? ''), 'base64url');
  if (rawSalt.length === 0 || rawNonce.length !== GCM_NONCE_LEN || rawCt.length <= GCM_TAG_LEN) {
    throw identityError(IDENTITY_UNAVAILABLE, 'malformed-key-file');
  }
  const key = deriveKeyFromFingerprint(fingerprint, rawSalt);
  const tag = rawCt.subarray(rawCt.length - GCM_TAG_LEN);
  const body = rawCt.subarray(0, rawCt.length - GCM_TAG_LEN);
  let der;
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, rawNonce);
    decipher.setAuthTag(tag);
    der = Buffer.concat([decipher.update(body), decipher.final()]);
  } catch {
    // GCM tag 不过 = 指纹不对（换机器）或被改过 → 报稳定 code，绝不静默重建
    throw identityError(IDENTITY_UNAVAILABLE, 'device-fingerprint-mismatch');
  }
  try {
    return createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  } catch {
    throw identityError(IDENTITY_UNAVAILABLE, 'bad-private-key-der');
  }
}

/** 同目录临时文件 + fsync + rename：崩在中间不会留下半个 member-key.json */
function writeFileAtomic(file, data, mode) {
  const dir = path.dirname(file);
  const tmp = path.join(dir, `.${path.basename(file)}.${randomBytes(6).toString('hex')}.tmp`);
  let fd;
  try {
    fd = fs.openSync(tmp, 'wx', mode);
    fs.writeFileSync(fd, data);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(tmp, file);
  } catch (err) {
    if (fd !== undefined) { try { fs.closeSync(fd); } catch { /* 已经关了 */ } }
    try { fs.unlinkSync(tmp); } catch { /* 临时文件可能没建出来 */ }
    throw err;
  }
}

/**
 * 私钥落盘：<stateDir>/group/member-key.json（目录 0700、文件 0600、原子写）。
 * options.fingerprint 可注入（Buffer / hex / deviceFingerprint() 结果），缺省走真机指纹。
 * 返回落盘后的文件对象（不含私钥）。
 */
export function saveKeypair(stateDir, keypair, options = {}) {
  if (!keypair || !keypair.privateKey) throw new TypeError('privateKey-required');
  const dir = path.join(String(stateDir ?? ''), MEMBER_KEY_DIR);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  try { fs.chmodSync(dir, 0o700); } catch { /* Windows 上 chmod 是空操作 */ }
  const fingerprint = resolveFingerprint(options.fingerprint);
  const publicKey = keypair.publicKey ?? createPublicKey(keypair.privateKey);
  const pubFingerprint = publicKeyFingerprint(publicKey);
  const { salt, nonce, ct } = sealPrivateKey(keypair.privateKey, fingerprint);
  const hint = {
    alg: 'ed25519',
    pubKeyFingerprint: pubFingerprint,
    shortId: pubFingerprint.slice(0, 8),
    ...(options.peerId ? { peerId: String(options.peerId) } : {}),
  };
  const file = { v: KEY_FILE_VERSION, salt, nonce, ct, hint };
  writeFileAtomic(memberKeyPath(stateDir), `${JSON.stringify(file, null, 2)}\n`, 0o600);
  try { fs.chmodSync(memberKeyPath(stateDir), 0o600); } catch { /* Windows 上 chmod 是空操作 */ }
  return { path: memberKeyPath(stateDir), v: file.v, hint };
}

/**
 * 读回私钥：解不开（换机器 / 指纹变了 / 文件被改）抛 code='identity-unavailable'，
 * 文件不存在抛 code='identity-missing'。**绝不静默重建**。
 * options.fingerprint 可注入（"换机器模拟"用不同指纹）。
 * 返回与 createKeypair() 同形的对象（publicKeyDer / publicKeyPem 由私钥导出）。
 */
export function loadKeypair(stateDir, options = {}) {
  const file = memberKeyPath(stateDir);
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch {
    throw identityError(IDENTITY_MISSING, file);
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw identityError(IDENTITY_UNAVAILABLE, 'malformed-key-file');
  }
  if (!parsed || parsed.v !== KEY_FILE_VERSION) throw identityError(IDENTITY_UNAVAILABLE, 'unsupported-key-file-version');
  const fingerprint = resolveFingerprint(options.fingerprint);
  const privateKey = openPrivateKey(parsed, fingerprint);
  const publicKey = createPublicKey(privateKey);
  const fingerprintHex = publicKeyFingerprint(publicKey);
  return {
    alg: 'ed25519',
    privateKey,
    publicKey,
    publicKeyDer: publicKeyText(publicKey),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicKeyFingerprint: fingerprintHex,
    shortId: fingerprintHex.slice(0, 8),
    hint: parsed.hint ?? null,
  };
}

// ---------------------------------------------------------------------------
// 4. 证书：hub 是 CA（它不参与消息签名），证书字段顺序固定
//    字段序：peerId / pubKey / groupId / issuedAt / expiresAt / hubEpoch
// ---------------------------------------------------------------------------

export const CERT_FIELDS = Object.freeze(['peerId', 'pubKey', 'groupId', 'issuedAt', 'expiresAt', 'hubEpoch']);

const asIntString = (value) => {
  if (value === undefined || value === null || value === '') return '';
  if (value instanceof Date) return String(value.getTime());
  const num = Number(value);
  return Number.isFinite(num) ? String(Math.trunc(num)) : String(value);
};

/**
 * 证书 canonical：字段按 CERT_FIELDS 的固定顺序用 \n 连接，无尾随换行。
 * 只吃这六项；alg/sig 不参与（否则签自己签不出来）。
 */
export function buildCertificateCanonical(cert) {
  const src = cert ?? {};
  return [
    String(src.peerId ?? ''),
    String(src.pubKey ?? ''),
    String(src.groupId ?? ''),
    asIntString(src.issuedAt),
    asIntString(src.expiresAt),
    asIntString(src.hubEpoch),
  ].join('\n');
}

/**
 * hub 用 CA 私钥签证书：返回**新对象**，多出 { alg:'ed25519', sig }（sig = base64url）。
 * 签名字节 = buildCertificateCanonical(cert) 的 UTF-8。
 */
export function signCertificate(caPrivateKey, cert) {
  if (!cert || typeof cert !== 'object') throw new TypeError('cert-required');
  const canonical = buildCertificateCanonical(cert);
  const signature = cryptoSign(null, Buffer.from(canonical, 'utf8'), keyToPrivate(caPrivateKey));
  return { ...cert, alg: CERT_ALG, sig: signature.toString('base64url') };
}

// 返回形状对外统一为 { ok, reason? , grace? }，避免协议层要认两种结构
const certMalformed = () => ({ ok: false, reason: 'malformed' });

/**
 * 验证书。检查顺序（决定的 reason 优先级）：
 *   形状 → 签名（防篡改）/ 防篡改必须最先于时间与匹配 → not-yet-valid → expired(+7 天宽限) → peer/group 匹配
 * 返回 { ok, reason?, grace? }：
 *   ok:true / ok:true+grace:true（过期但仍在 graceMs 内）/ ok:false+reason（稳定短码）
 * reason ∈ bad-signature | expired | not-yet-valid | peer-mismatch | group-mismatch | malformed
 */
export function verifyCertificate(caPublicKey, cert, options = {}) {
  const now = Number(options.now ?? Date.now());
  const graceMs = Number(options.graceMs ?? DEFAULT_GRACE_MS);
  if (!cert || typeof cert !== 'object') return certMalformed();
  if (typeof cert.peerId !== 'string' || cert.peerId === '') return certMalformed();
  if (typeof cert.pubKey !== 'string' || cert.pubKey === '') return certMalformed();
  if (typeof cert.groupId !== 'string' || cert.groupId === '') return certMalformed();
  if (cert.alg !== CERT_ALG) return certMalformed();
  if (typeof cert.sig !== 'string' || cert.sig === '') return certMalformed();
  const issuedAt = Number(cert.issuedAt);
  const expiresAt = Number(cert.expiresAt);
  if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt)) return certMalformed();

  try {
    const publicKey = keyToPublic(caPublicKey);
    const canonical = Buffer.from(buildCertificateCanonical(cert), 'utf8');
    const ok = cryptoVerify(null, canonical, publicKey, Buffer.from(cert.sig, 'base64url'));
    if (!ok) return { ok: false, reason: 'bad-signature' };
  } catch {
    return { ok: false, reason: 'bad-signature' };
  }

  if (Number.isFinite(now) && now < issuedAt) return { ok: false, reason: 'not-yet-valid' };
  if (options.expectedPeerId !== undefined && String(options.expectedPeerId) !== cert.peerId) {
    return { ok: false, reason: 'peer-mismatch' };
  }
  if (options.expectedGroupId !== undefined && String(options.expectedGroupId) !== cert.groupId) {
    return { ok: false, reason: 'group-mismatch' };
  }
  if (Number.isFinite(now) && now > expiresAt) {
    const grace = graceMs > 0 && now <= expiresAt + graceMs;
    if (!grace) return { ok: false, reason: 'expired' };
    return { ok: true, grace: true };
  }
  return { ok: true };
}

// ---------------------------------------------------------------------------
// 5. 消息签名 / 验签
//    canonical v2 = **与既有 v1（buildGroupCanonical）逐字节相同**的那一套（用户 2026-11-07 裁决）：
//      GROUP / METHOD / path(含 query) / ts / nonce / groupId / senderPeerId / sha256(body)
//    行分隔 \n、无尾随换行、method 大写、body 取 sha256 hex（GET 无 body = sha256("")）。
//    为什么是同一套而不是另起一套：v1 已在两端真机跑着，两套 canonical 并存 = 两个权威，
//    P2 接线时任何一处拼错都是"签名对不上"这种极难排查的故障。
//    域分离不靠字符串：v1/v2 由 X-Peer-Auth: group-v2 头 + 证书 + 签名算法（HMAC vs ed25519）区分。
// ---------------------------------------------------------------------------

export const GROUP_CANONICAL_V2_PREFIX = 'GROUP';

export const GROUP_CANONICAL_V2_FIELDS = Object.freeze([
  'method', 'path', 'ts', 'nonce', 'groupId', 'senderPeerId', 'bodySha256',
]);

const bodyDigest = (input) => {
  const { body, rawBody, bodySha256, sha256: precomputed } = input ?? {};
  const given = precomputed ?? bodySha256;
  if (typeof given === 'string' && /^[0-9a-fA-F]{64}$/.test(given)) return given.toLowerCase();
  const raw = rawBody !== undefined ? rawBody : body;
  if (raw === undefined || raw === null) return sha256Hex(emptyBuffer());
  if (Buffer.isBuffer(raw)) return sha256Hex(raw);
  if (typeof raw === 'string') return sha256Hex(Buffer.from(raw, 'utf8'));
  return sha256Hex(Buffer.from(JSON.stringify(raw), 'utf8'));
};

/**
 * 群消息 canonical v2：**与 v1 buildGroupCanonical 逐字节相同**（8 行，首行字面量 GROUP）。
 * 返回 UTF-8 字符串，签名字节就是它的 UTF-8。
 * 接受 { groupId, method, path | apiPath, ts, nonce, senderPeerId, body | rawBody | bodySha256 }。
 * 协议层只许调这个，不许自己拼。
 */
export function buildGroupCanonicalV2(input = {}) {
  const src = input ?? {};
  return [
    GROUP_CANONICAL_V2_PREFIX,
    String(src.method ?? '').toUpperCase(),
    String(src.path ?? src.apiPath ?? ''),
    String(src.ts ?? ''),
    String(src.nonce ?? ''),
    String(src.groupId ?? ''),
    String(src.senderPeerId ?? ''),
    bodyDigest(src),
  ].join('\n');
}

const toCanonicalBytes = (fields) => Buffer.from(
  typeof fields === 'string' ? fields : buildGroupCanonicalV2(fields),
  'utf8',
);

/**
 * 用成员私钥签消息：fields 是 canonical 字符串（或 canonical 输入对象）。
 * 返回 base64url 签名（协议层放进 X-Peer-Sign，配合 X-Peer-Auth: group-v2）。
 */
export function signMessage(privateKey, fields) {
  return cryptoSign(null, toCanonicalBytes(fields), keyToPrivate(privateKey)).toString('base64url');
}

/** 验消息：任何不可验证的情况都返回 false，不抛错。 */
export function verifyMessage(publicKey, fields, signature) {
  try {
    const sig = typeof signature === 'string' ? Buffer.from(signature, 'base64url') : Buffer.from(signature ?? emptyBuffer());
    if (sig.length === 0) return false;
    return cryptoVerify(null, toCanonicalBytes(fields), keyToPublic(publicKey), sig) === true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// 6. 轮换辅助
// ---------------------------------------------------------------------------

/** 应轮换时刻（ms）：issuedAt + rotateAfterMs */
export function rotationDueAt(cert, options = {}) {
  const rotateAfterMs = Number(options.rotateAfterMs ?? DEFAULT_ROTATE_AFTER_MS);
  const issuedAt = Number(cert?.issuedAt);
  if (!Number.isFinite(issuedAt)) return NaN;
  return issuedAt + rotateAfterMs;
}

/** 是否该轮换：到达 issuedAt+rotateAfterMs，或证书已经过期（过期了当然要换） */
export function needsRotation(cert, options = {}) {
  const now = Number(options.now ?? Date.now());
  const dueAt = rotationDueAt(cert, options);
  if (Number.isFinite(dueAt) && now >= dueAt) return true;
  const expiresAt = Number(cert?.expiresAt);
  return Number.isFinite(expiresAt) && now >= expiresAt;
}
