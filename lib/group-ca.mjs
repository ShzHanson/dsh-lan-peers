// dsh-lan-peers · v0.9.0-α 群身份 P2 服务端：hub CA（签发成员证书）+ 成员证书台账
//
// 线格式契约（唯一权威）：internal-docs/group-v2-wire-contract.md §4/§5。
// 本文件只负责「信任根落盘 + 签发/轮换 + 台账」；九步校验与两条端点在 host/server.mjs。
// 密码学原语全部复用 lib/group-identity.mjs（这里**不重写**任何签名/加密代码）。
//
// 落盘全部在 <stateDir>/group/ 下，0600 + 原子写，且**可重建**：
//   hub-ca-key.json      设备绑定（换机解不开 → identity-unavailable，绝不静默重建）
//   member-certs.json    { v, members: { <peerId>: { current, previous } } }，丢了重新注册即恢复
// 客户端侧的 member-cert.json / trusted-hub-ca.json 由客户端侧自己写；这里只读后者当信任根。
import fs from 'node:fs';
import path from 'node:path';
import {
  DEFAULT_GRACE_MS,
  DEFAULT_ROTATE_AFTER_MS,
  IDENTITY_MISSING,
  IDENTITY_UNAVAILABLE,
  createKeypair,
  loadBoundKeypair,
  saveBoundKeypair,
  signCertificate,
  writeAtomic0600,
} from './group-identity.mjs';

/** 身份文件都在 <stateDir>/group/ 下（与 member-key.json 同目录） */
export const GROUP_IDENTITY_DIR = 'group';
export const HUB_CA_KEY_FILE = 'hub-ca-key.json';
export const MEMBER_CERTS_FILE = 'member-certs.json';
export const MEMBER_CERT_FILE = 'member-cert.json';
export const TRUSTED_HUB_CA_FILE = 'trusted-hub-ca.json';
export const MEMBER_CERTS_VERSION = 1;

/**
 * P2 的服务端本地常量（契约 §7：两侧各自写字面量，不从对方正在改的文件里 import）。
 */
export const GROUP_AUTH_V2_VALUE = 'group-v2';
export const PEER_CERT_HEADER = 'X-Peer-Cert';
export const GROUP_IDENTITY_PATHS = Object.freeze([
  '/v1/group/identity/register',
  '/v1/group/identity/rotate',
]);

export function groupIdentityDir(stateDir) {
  return path.join(String(stateDir ?? ''), GROUP_IDENTITY_DIR);
}

export function hubCaKeyPath(stateDir) {
  return path.join(groupIdentityDir(stateDir), HUB_CA_KEY_FILE);
}

export function memberCertsPath(stateDir) {
  return path.join(groupIdentityDir(stateDir), MEMBER_CERTS_FILE);
}

export function memberCertPath(stateDir) {
  return path.join(groupIdentityDir(stateDir), MEMBER_CERT_FILE);
}

export function trustedHubCaPath(stateDir) {
  return path.join(groupIdentityDir(stateDir), TRUSTED_HUB_CA_FILE);
}

const asInt = (value, fallback) => {
  const num = Number(value);
  return Number.isFinite(num) ? Math.trunc(num) : fallback;
};

// ---------------------------------------------------------------------------
// 1. hub CA 私钥：<stateDir>/group/hub-ca-key.json（设备绑定、0600、原子写）
// ---------------------------------------------------------------------------

/**
 * 取本机 hub CA；文件不存在时按 options.create（默认 true）生成一把再落盘。
 * 返回 { ok:true, created, privateKey, publicKey, pubKey } 或
 *      { ok:false, error:'identity-unavailable'|'identity-missing', detail? }。
 * **解不开一律报错，不静默重建**（换机器后旧证书全部作废这件事必须让人看见）。
 */
export function loadOrCreateHubCa(stateDir, options = {}) {
  const file = hubCaKeyPath(stateDir);
  let loaded = null;
  try {
    loaded = loadBoundKeypair(file, { fingerprint: options.fingerprint });
  } catch (error) {
    const code = String(error?.code ?? '');
    if (code !== IDENTITY_MISSING) {
      return { ok: false, error: IDENTITY_UNAVAILABLE, detail: String(error?.message ?? error) };
    }
  }
  if (loaded) {
    return {
      ok: true,
      created: false,
      privateKey: loaded.privateKey,
      publicKey: loaded.publicKey,
      pubKey: loaded.pubKey,
    };
  }
  if (options.create === false) return { ok: false, error: IDENTITY_MISSING };
  const keypair = createKeypair();
  saveBoundKeypair(file, keypair, {
    fingerprint: options.fingerprint,
    fingerprintHint: keypair.shortId,
  });
  return {
    ok: true,
    created: true,
    privateKey: keypair.privateKey,
    publicKey: keypair.publicKey,
    pubKey: keypair.publicKeyDer,
  };
}

// ---------------------------------------------------------------------------
// 2. 信任根（成员侧）：<stateDir>/group/trusted-hub-ca.json 里的 hubCaPubKey
// ---------------------------------------------------------------------------

/** 读成员侧记下的 hub CA 公钥（base64 SPKI DER）；缺失/坏文件返回 null */
export function readTrustedHubCaPubKey(stateDir) {
  try {
    const parsed = JSON.parse(fs.readFileSync(trustedHubCaPath(stateDir), 'utf8'));
    const pubKey = String(parsed?.hubCaPubKey ?? '');
    return pubKey === '' ? null : pubKey;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// 3. 成员证书台账（hub 侧）：<stateDir>/group/member-certs.json
//    形状 { v:1, members: { <peerId>: { current: cert, previous: cert & { graceUntil } } } }
//    台账不是秘密，丢了一律按空表重建（重新注册就回来了）。
// ---------------------------------------------------------------------------

export function readMemberCerts(stateDir) {
  let parsed = null;
  try {
    parsed = JSON.parse(fs.readFileSync(memberCertsPath(stateDir), 'utf8'));
  } catch {
    parsed = null;
  }
  const members = parsed && typeof parsed === 'object' && parsed.members && typeof parsed.members === 'object'
    ? parsed.members
    : {};
  return { v: MEMBER_CERTS_VERSION, members: { ...members } };
}

export function writeMemberCerts(stateDir, data) {
  const members = data && typeof data.members === 'object' && data.members ? data.members : {};
  writeAtomic0600(
    memberCertsPath(stateDir),
    `${JSON.stringify({ v: MEMBER_CERTS_VERSION, members }, null, 2)}\n`,
  );
  return memberCertsPath(stateDir);
}

/** 某成员的台账行（没有就 null）；只读 */
export function memberCertRecord(stateDir, peerId) {
  const id = String(peerId ?? '');
  if (id === '') return null;
  const record = readMemberCerts(stateDir).members[id];
  return record && typeof record === 'object' ? record : null;
}

/**
 * 契约 §8.1（校验第 8.5 步）：台账吊销检查。
 *
 * 只有**本机有台账且该 peerId 有记录**时才判定 —— 没有记录就跳过（首注册成员立刻可用，
 * P2 不在成员侧强制同步台账：群请求是星型经 hub，hub 侧强制已覆盖主路径）。
 * 有记录时只有 current 证书算合法（pubKey + issuedAt 都对上）：
 * previous 是审计记录，**不是备选凭证**，一律不接受。
 *
 * 返回 { checked, ok }；checked=false = 跳过本次检查。
 */
export function ledgerAcceptsCertificate(stateDir, peerId, cert) {
  const record = memberCertRecord(stateDir, peerId);
  if (!record) return { checked: false, ok: true };
  const current = record.current;
  if (!current || typeof current !== 'object') return { checked: true, ok: false };
  const same = String(current.pubKey ?? '') === String(cert?.pubKey ?? '')
    && asInt(current.issuedAt, NaN) === asInt(cert?.issuedAt, NaN);
  return { checked: true, ok: same };
}

// ---------------------------------------------------------------------------
// 4. 签发 / 轮换
// ---------------------------------------------------------------------------

const certOptions = (options) => {
  const now = asInt(options.now ?? Date.now(), Date.now());
  return {
    now,
    issuedAt: now,
    expiresAt: now + asInt(options.rotateAfterMs, DEFAULT_ROTATE_AFTER_MS),
    graceMs: asInt(options.graceMs, DEFAULT_GRACE_MS),
  };
};

/**
 * 首次签发。**已经有 current 证书就拒绝**（reason='cert-exists'）：
 * 换钥只能走 v2 鉴权的 rotate —— 否则握有 groupKey 的人可以用别人的 peerId
 * 登记自己的公钥，把「私钥才能代表身份」这条收益当场还回去。
 */
export function issueMemberCertificate(options = {}) {
  const stateDir = String(options.stateDir ?? '');
  const peerId = String(options.peerId ?? '');
  const pubKey = String(options.pubKey ?? '');
  const groupId = String(options.groupId ?? '');
  if (peerId === '' || pubKey === '' || groupId === '') return { ok: false, reason: 'bad-request' };
  const store = readMemberCerts(stateDir);
  const existing = store.members[peerId];
  if (existing && typeof existing === 'object' && existing.current) {
    return { ok: false, reason: 'cert-exists' };
  }
  const { now, issuedAt, expiresAt } = certOptions(options);
  const cert = signCertificate(options.caPrivateKey, {
    peerId,
    pubKey,
    groupId,
    issuedAt,
    expiresAt,
    hubEpoch: asInt(options.hubEpoch, 0),
  });
  store.members[peerId] = { current: cert, previous: existing?.previous ?? null };
  writeMemberCerts(stateDir, store);
  return { ok: true, cert, at: now };
}

/**
 * 轮换：签新证书，旧证书降为 previous 并记 `revokedAt = now`。
 *
 * 契约 §8.1（r2）：宽限（graceUntil）只管「证书自身过期」，**不是吊销容忍** ——
 * rotate 之后旧证书立刻失效（校验第 8.5 步按 current 比对，previous 一律不接受）。
 * previous 只是审计记录，所以 graceUntil 仍然保留（它解释旧证书本可以活到什么时候）。
 * 台账里没有 current（成员从没注册过）→ reason='cert-missing'，不凭空补发。
 */
export function rotateMemberCertificate(options = {}) {
  const stateDir = String(options.stateDir ?? '');
  const peerId = String(options.peerId ?? '');
  const newPubKey = String(options.newPubKey ?? '');
  const groupId = String(options.groupId ?? '');
  if (peerId === '' || newPubKey === '' || groupId === '') return { ok: false, reason: 'bad-request' };
  const store = readMemberCerts(stateDir);
  const existing = store.members[peerId];
  const old = existing && typeof existing === 'object' ? existing.current : null;
  if (!old) return { ok: false, reason: 'cert-missing' };
  const { now, issuedAt, expiresAt, graceMs } = certOptions(options);
  const cert = signCertificate(options.caPrivateKey, {
    peerId,
    pubKey: newPubKey,
    groupId,
    issuedAt,
    expiresAt,
    hubEpoch: asInt(options.hubEpoch, 0),
  });
  const previous = { ...old, graceUntil: asInt(old.expiresAt, 0) + graceMs, revokedAt: now };
  store.members[peerId] = { current: cert, previous };
  writeMemberCerts(stateDir, store);
  return { ok: true, cert, previous, at: now };
}
