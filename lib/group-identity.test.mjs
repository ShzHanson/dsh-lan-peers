// dsh-lan-peers · v0.8.5-α 群身份核心（P1：签名与加密分离）的钉子。
//
// 这里钉死七件事（都是"改坏了会静默失效"的那种）：
//   1. 设备指纹：32 字节、可注入、取不到 machineId 时**降级不抛错**；
//   2. 私钥文件格式：字段只有 { v, salt, nonce, ct, hint }，**文件里绝不出现私钥明文**；
//   3. 换机器（指纹变了）→ loadKeypair 抛 code='identity-unavailable'，**绝不静默重建**；
//   4. 证书 canonical 字段序固定；改 pubKey/peerId/expiresAt 任一项 → bad-signature；
//   5. 过期 1 天内 ok+grace，过期 8 天 reason='expired'；
//   6. 消息 canonical v2 与既有群 canonical **同字段同值**（协议层不许自己拼）；
//   7. 轮换：issuedAt+30 天到期，已过期也算必须换。
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash, generateKeyPairSync, verify as cryptoVerify } from 'node:crypto';
import { makeTempStateDir } from '../host/test/helpers.mjs';
import { buildGroupCanonical } from './group-client.mjs';
import {
  CERT_ALG,
  DEFAULT_CERT_CLOCK_SKEW_MS,
  DEFAULT_GRACE_MS,
  DEFAULT_ROTATE_AFTER_MS,
  IDENTITY_MISSING,
  IDENTITY_UNAVAILABLE,
  GROUP_CANONICAL_V2_FIELDS,
  GROUP_CANONICAL_V2_PREFIX,
  MEMBER_KEY_FILE,
  buildCertificateCanonical,
  buildGroupCanonicalV2,
  createKeypair,
  deviceFingerprint,
  loadKeypair,
  memberKeyPath,
  needsRotation,
  normalizeFingerprint,
  publicKeyFingerprint,
  publicKeyFromText,
  readMachineId,
  rotationDueAt,
  saveKeypair,
  signCertificate,
  signMessage,
  verifyCertificate,
  verifyMessage,
} from './group-identity.mjs';

const DAY = 24 * 60 * 60 * 1000;
const sha256hex = (value) => createHash('sha256').update(value).digest('hex');
const tmpDir = () => makeTempStateDir('dsh-group-identity-');
const withTempDir = (fn) => {
  const dir = tmpDir();
  try {
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
};

/** 一套 hub CA + 一张成员证书（时间可覆盖） */
function makeCa() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return { caPublicKey: publicKey, caPrivateKey: privateKey };
}

function makeCert(caPrivateKey, overrides = {}) {
  const now = Date.now();
  const member = createKeypair();
  return signCertificate(caPrivateKey, {
    peerId: 'peer-a',
    pubKey: member.publicKeyDer,
    groupId: 'group-1',
    issuedAt: now - DAY,
    expiresAt: now + 29 * DAY,
    hubEpoch: 7,
    ...overrides,
  });
}

// ---------------------------------------------------------------------------
// 1. 设备指纹
// ---------------------------------------------------------------------------

test('deviceFingerprint：32 字节 + hex，同一台机器两次一致', () => {
  const first = deviceFingerprint();
  const second = deviceFingerprint();
  assert.equal(first.fingerprint.length, 32);
  assert.equal(first.hex.length, 64);
  assert.match(first.hex, /^[0-9a-f]{64}$/);
  assert.equal(first.hex, second.hex);
  assert.equal(typeof first.degraded, 'boolean');
});

test('deviceFingerprint：注入 machineId 时 degraded=false，且不同 machineId 得到不同指纹', () => {
  const a = deviceFingerprint({ machineId: 'guid-a', username: 'u', hostname: 'h' });
  const b = deviceFingerprint({ machineId: 'guid-b', username: 'u', hostname: 'h' });
  assert.equal(a.degraded, false);
  assert.equal(a.hex, sha256hex('guid-a' + 'u' + 'h'));   // 拼接口径钉死：无分隔符
  assert.notEqual(a.hex, b.hex);
});

test('deviceFingerprint：取不到 machineId 时降级不抛错（degraded=true，仍 32 字节）', () => {
  const degraded = deviceFingerprint({ machineId: '', username: 'u', hostname: 'h' });
  assert.equal(degraded.degraded, true);
  assert.equal(degraded.fingerprint.length, 32);
  assert.equal(degraded.hex, sha256hex('u' + 'h'));
  // 空机器信息也不能抛
  const empty = deviceFingerprint({ machineId: '', username: '', hostname: '' });
  assert.equal(empty.degraded, true);
  assert.equal(empty.fingerprint.length, 32);
});

test('readMachineId + normalizeFingerprint：真机读到非空、归一化接受 Buffer/hex/对象', () => {
  assert.equal(typeof readMachineId(), 'string');
  const fp = Buffer.alloc(32, 7);
  assert.deepEqual(normalizeFingerprint(fp), fp);
  assert.deepEqual(normalizeFingerprint(fp.toString('hex')), fp);
  assert.deepEqual(normalizeFingerprint({ fingerprint: fp }), fp);
  assert.deepEqual(normalizeFingerprint({ hex: fp.toString('hex') }), fp);
  assert.equal(normalizeFingerprint('随便一个口令').length, 32);
  assert.throws(() => normalizeFingerprint(Buffer.alloc(5)), /bad-fingerprint-length/);
});

// ---------------------------------------------------------------------------
// 2. 密钥对
// ---------------------------------------------------------------------------

test('createKeypair：Ed25519，签/验自洽，PEM 与 DER 都能还原同一把公钥', () => {
  const kp = createKeypair();
  assert.equal(kp.alg, 'ed25519');
  assert.equal(kp.privateKey.asymmetricKeyType, 'ed25519');
  const signature = signMessage(kp.privateKey, 'hello');
  assert.equal(verifyMessage(kp.publicKey, 'hello', signature), true);

  // DER(base64) 与 PEM 两条还原路线都要一致
  const fromDer = publicKeyFromText(kp.publicKeyDer);
  assert.equal(publicKeyFingerprint(fromDer), kp.publicKeyFingerprint);
  assert.equal(publicKeyFingerprint(kp.publicKeyPem), kp.publicKeyFingerprint);
  assert.equal(verifyMessage(fromDer, 'hello', signature), true);
  // 短 id 是公钥指纹前 8 位（只给人看，不是密钥材料）
  assert.equal(kp.shortId, kp.publicKeyFingerprint.slice(0, 8));
  assert.equal(kp.publicKeyFingerprint.length, 64);
});

// ---------------------------------------------------------------------------
// 3. 私钥加密落盘
// ---------------------------------------------------------------------------

test('saveKeypair/loadKeypair：落盘→读回→签名→验签全部走通，文件字段只有 v/salt/nonce/ct/hint', () => {
  withTempDir((stateDir) => {
    const fingerprint = deviceFingerprint();
    const kp = createKeypair();
    const saved = saveKeypair(stateDir, kp, { fingerprint });
    assert.equal(saved.path, memberKeyPath(stateDir));
    assert.equal(path.basename(saved.path), MEMBER_KEY_FILE);
    assert.equal(saved.path, path.join(stateDir, 'group', MEMBER_KEY_FILE));

    const file = JSON.parse(fs.readFileSync(saved.path, 'utf8'));
    assert.deepEqual(Object.keys(file).sort(), ['ct', 'hint', 'nonce', 'salt', 'v']);
    assert.equal(file.v, 1);
    assert.equal(typeof file.salt, 'string');
    assert.equal(typeof file.nonce, 'string');
    assert.equal(typeof file.ct, 'string');
    assert.equal(file.hint.alg, 'ed25519');
    assert.equal(file.hint.pubKeyFingerprint, kp.publicKeyFingerprint);

    // 私钥明文（PEM base64 / DER base64 前 16 位）绝不出现
    const raw = fs.readFileSync(saved.path, 'utf8');
    const privateText = kp.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
    assert.equal(raw.includes(privateText.slice(0, 16)), false);
    assert.equal(raw.includes('PRIVATE KEY'), false);

    // 原子写：临时文件不留残留
    assert.deepEqual(fs.readdirSync(path.join(stateDir, 'group')).filter((name) => name.endsWith('.tmp')), []);

    const loaded = loadKeypair(stateDir, { fingerprint });
    assert.equal(loaded.publicKeyFingerprint, kp.publicKeyFingerprint);
    assert.equal(loaded.publicKeyDer, kp.publicKeyDer);
    const signature = signMessage(loaded.privateKey, 'after-reload');
    assert.equal(verifyMessage(kp.publicKey, 'after-reload', signature), true);
  });
});

test('saveKeypair：目录 0700 / 文件 0600（POSIX 才断言，Windows 无此语义）', (t) => {
  if (process.platform === 'win32') return t.skip('Windows 上 chmod 是空操作');
  withTempDir((stateDir) => {
    const saved = saveKeypair(stateDir, createKeypair());
    assert.equal(fs.statSync(path.dirname(saved.path)).mode & 0o777, 0o700);
    assert.equal(fs.statSync(saved.path).mode & 0o777, 0o600);
    return undefined;
  });
});

test('loadKeypair：换成别的指纹（换机器）→ identity-unavailable，绝不静默重建', () => {
  withTempDir((stateDir) => {
    const kp = createKeypair();
    saveKeypair(stateDir, kp, { fingerprint: 'machine-A' });
    const before = fs.readFileSync(memberKeyPath(stateDir), 'utf8');
    assert.throws(
      () => loadKeypair(stateDir, { fingerprint: 'machine-B' }),
      (err) => err.code === IDENTITY_UNAVAILABLE && /device-fingerprint-mismatch/.test(err.message),
    );
    // 挫败之后文件必须原样还在（没有静默重建/覆盖）
    assert.equal(fs.readFileSync(memberKeyPath(stateDir), 'utf8'), before);
  });
});

test('loadKeypair：文件不存在 → identity-missing；ct 被改 → identity-unavailable', () => {
  withTempDir((stateDir) => {
    assert.throws(() => loadKeypair(stateDir, { fingerprint: 'x' }), (err) => err.code === IDENTITY_MISSING);
    saveKeypair(stateDir, createKeypair(), { fingerprint: 'x' });
    const file = JSON.parse(fs.readFileSync(memberKeyPath(stateDir), 'utf8'));
    const bytes = Buffer.from(file.ct, 'base64url');
    bytes[0] ^= 0xff;
    file.ct = bytes.toString('base64url');
    fs.writeFileSync(memberKeyPath(stateDir), JSON.stringify(file));
    assert.throws(() => loadKeypair(stateDir, { fingerprint: 'x' }), (err) => err.code === IDENTITY_UNAVAILABLE);
    // 版本号不认识也要报同一个 code
    fs.writeFileSync(memberKeyPath(stateDir), JSON.stringify({ ...file, v: 99 }));
    assert.throws(() => loadKeypair(stateDir, { fingerprint: 'x' }), (err) => err.code === IDENTITY_UNAVAILABLE);
  });
});

// ---------------------------------------------------------------------------
// 4. 证书
// ---------------------------------------------------------------------------

test('buildCertificateCanonical：字段序固定 peerId/pubKey/groupId/issuedAt/expiresAt/hubEpoch', () => {
  const canonical = buildCertificateCanonical({
    peerId: 'p', pubKey: 'k', groupId: 'g', issuedAt: 1, expiresAt: 2, hubEpoch: 3,
    sig: 'IGNORED', alg: 'IGNORED',
  });
  assert.equal(canonical, 'p\nk\ng\n1\n2\n3');
});

test('signCertificate/verifyCertificate：正常证书 ok:true 且无 grace', () => {
  const { caPublicKey, caPrivateKey } = makeCa();
  const cert = makeCert(caPrivateKey);
  assert.equal(cert.alg, CERT_ALG);
  assert.equal(typeof cert.sig, 'string');
  assert.deepEqual(verifyCertificate(caPublicKey, cert), { ok: true });
  assert.deepEqual(
    verifyCertificate(caPublicKey, cert, { expectedPeerId: 'peer-a', expectedGroupId: 'group-1' }),
    { ok: true },
  );
  // 签名确实是"证书 canonical 的 UTF-8"上的 ed25519
  assert.equal(
    cryptoVerify(
      null,
      Buffer.from(buildCertificateCanonical(cert), 'utf8'),
      caPublicKey,
      Buffer.from(cert.sig, 'base64url'),
    ),
    true,
  );
});

test('verifyCertificate：改 pubKey / peerId / expiresAt 各一次 → bad-signature', () => {
  const { caPublicKey, caPrivateKey } = makeCa();
  const cert = makeCert(caPrivateKey);
  const other = createKeypair();
  const tampered = [
    { ...cert, pubKey: other.publicKeyDer },
    { ...cert, peerId: 'peer-b' },
    { ...cert, expiresAt: cert.expiresAt + 1 },
    { ...cert, groupId: 'group-2' },
    { ...cert, hubEpoch: cert.hubEpoch + 1 },
  ];
  for (const bad of tampered) {
    assert.deepEqual(verifyCertificate(caPublicKey, bad), { ok: false, reason: 'bad-signature' });
  }
  // 别人（非本 hub CA）签的证书同样不过
  const rogue = makeCa();
  assert.deepEqual(verifyCertificate(caPublicKey, makeCert(rogue.caPrivateKey)), { ok: false, reason: 'bad-signature' });
});

test('verifyCertificate：过期 1 天 → ok+grace，过期 8 天 → expired', () => {
  const { caPublicKey, caPrivateKey } = makeCa();
  const now = Date.now();
  const grace = makeCert(caPrivateKey, { issuedAt: now - 20 * DAY, expiresAt: now - DAY });
  assert.deepEqual(verifyCertificate(caPublicKey, grace, { now }), { ok: true, grace: true });

  const expired = makeCert(caPrivateKey, { issuedAt: now - 40 * DAY, expiresAt: now - 8 * DAY });
  assert.deepEqual(verifyCertificate(caPublicKey, expired, { now }), { ok: false, reason: 'expired' });

  // 宽限边界：正好卡在 graceMs 上仍算 ok，多 1ms 就 expired
  const edge = makeCert(caPrivateKey, { issuedAt: now - 40 * DAY, expiresAt: now - DEFAULT_GRACE_MS });
  assert.deepEqual(verifyCertificate(caPublicKey, edge, { now }), { ok: true, grace: true });
  assert.deepEqual(verifyCertificate(caPublicKey, edge, { now: now + 1 }), { ok: false, reason: 'expired' });
  // graceMs 可关掉（hub 侧收紧时）
  assert.deepEqual(verifyCertificate(caPublicKey, grace, { now, graceMs: 0 }), { ok: false, reason: 'expired' });
});

test('verifyCertificate：not-yet-valid / peer-mismatch / group-mismatch / malformed', () => {
  const { caPublicKey, caPrivateKey } = makeCa();
  const now = Date.now();
  // 前向时钟容差（DEFAULT_CERT_CLOCK_SKEW_MS = 60 秒）：真机 hub 时钟快 250–325ms 是常态，
  // 「刚签发/刚轮换就用」不该被判 not-yet-valid。旧的「未来签发一律拒绝」改成带容差的边界用例。
  assert.equal(DEFAULT_CERT_CLOCK_SKEW_MS, 60_000);
  const skewEdge = makeCert(caPrivateKey, { issuedAt: now, expiresAt: now + 30 * DAY });
  assert.deepEqual(verifyCertificate(caPublicKey, skewEdge, { now: now - DEFAULT_CERT_CLOCK_SKEW_MS }), { ok: true });
  assert.deepEqual(verifyCertificate(caPublicKey, skewEdge, { now: now - 59_999 }), { ok: true });
  assert.deepEqual(verifyCertificate(caPublicKey, skewEdge, { now: now - 60_001 }), { ok: false, reason: 'not-yet-valid' });
  // clockSkewMs: 0 = 零容忍（老行为），1ms 就拒
  assert.deepEqual(verifyCertificate(caPublicKey, skewEdge, { now: now - 1, clockSkewMs: 0 }), { ok: false, reason: 'not-yet-valid' });
  // 容差是有限窗口，不是「未来都放行」
  const future = makeCert(caPrivateKey, { issuedAt: now + DAY, expiresAt: now + 30 * DAY });
  assert.deepEqual(verifyCertificate(caPublicKey, future, { now }), { ok: false, reason: 'not-yet-valid' });

  const cert = makeCert(caPrivateKey);
  assert.deepEqual(verifyCertificate(caPublicKey, cert, { expectedPeerId: 'peer-b' }), { ok: false, reason: 'peer-mismatch' });
  assert.deepEqual(verifyCertificate(caPublicKey, cert, { expectedGroupId: 'group-2' }), { ok: false, reason: 'group-mismatch' });

  assert.deepEqual(verifyCertificate(caPublicKey, null), { ok: false, reason: 'malformed' });
  assert.deepEqual(verifyCertificate(caPublicKey, { ...cert, alg: 'hmac' }), { ok: false, reason: 'malformed' });
  assert.deepEqual(verifyCertificate(caPublicKey, { ...cert, sig: '' }), { ok: false, reason: 'malformed' });
  assert.deepEqual(verifyCertificate(caPublicKey, { ...cert, expiresAt: 'soon' }), { ok: false, reason: 'malformed' });
});

// ---------------------------------------------------------------------------
// 5. 消息签名 / canonical v2
// ---------------------------------------------------------------------------

test('buildGroupCanonicalV2：字节布局钉死（首行 GROUP，8 行，无尾随换行）', () => {
  assert.equal(GROUP_CANONICAL_V2_PREFIX, 'GROUP');
  assert.deepEqual([...GROUP_CANONICAL_V2_FIELDS], [
    'method', 'path', 'ts', 'nonce', 'groupId', 'senderPeerId', 'bodySha256',
  ]);
  const canonical = buildGroupCanonicalV2({
    groupId: 'g1',
    method: 'post',
    path: '/v1/group/send?x=1',
    ts: 1700000000000,
    nonce: 'n1',
    senderPeerId: 'peer-a',
    body: '{"a":1}',
  });
  assert.equal(canonical, [
    'GROUP',
    'POST',
    '/v1/group/send?x=1',
    '1700000000000',
    'n1',
    'g1',
    'peer-a',
    sha256hex('{"a":1}'),
  ].join('\n'));
  assert.equal(canonical.endsWith('\n'), false);
  assert.equal(canonical.split('\n').length, 8);
});

test('buildGroupCanonicalV2 与既有 buildGroupCanonical **逐字节相同**（3 组输入，严格相等）', () => {
  const cases = [
    // ① GET 无 query、无 body
    { label: 'GET 无 body', input: { groupId: 'g-1', method: 'GET', path: '/api/lan-peers/group/state', ts: 1750000000001, nonce: 'n1', senderPeerId: 'peer-a' } },
    // ② GET 带 query + 小写 method（v1 会大写）
    { label: 'GET 带 query + 小写 method', input: { groupId: 'g-2', method: 'get', path: '/api/lan-peers/group/messages?since=42&limit=20', ts: 1750000000002, nonce: 'n2', senderPeerId: 'peer-b' } },
    // ③ POST 有 body（Buffer 形式，走 sha256(body) 那一行）
    { label: 'POST 有 body', input: { groupId: 'g-3', method: 'POST', path: '/api/lan-peers/group/send', ts: 1750000000003, nonce: 'n3', senderPeerId: 'peer-c', rawBody: Buffer.from(JSON.stringify({ text: '你好 group' }), 'utf8') } },
  ];
  for (const { label, input } of cases) {
    assert.equal(buildGroupCanonicalV2(input), buildGroupCanonical(input), `字节不一致：${label}`);
  }
  // 第三条对拍的逐行形态也贴一下，防止两边同时"整段漂移"却仍然相等
  const post = cases[2].input;
  assert.deepEqual(buildGroupCanonicalV2(post).split('\n'), [
    'GROUP', 'POST', post.path, String(post.ts), post.nonce, post.groupId, post.senderPeerId,
    sha256hex(Buffer.from(JSON.stringify({ text: '你好 group' }), 'utf8')),
  ]);
  // GET 无 body 时与既有实现一样是 sha256("")
  assert.equal(buildGroupCanonicalV2({ groupId: 'g' }).split('\n')[7], sha256hex(''));
});

test('signMessage/verifyMessage：body/ts/nonce/senderPeerId 任一被改都验不过；换人签名也验不过', () => {
  const a = createKeypair();
  const b = createKeypair();
  const fields = {
    groupId: 'g1', method: 'POST', path: '/v1/group/send', ts: 1, nonce: 'n', senderPeerId: 'peer-a', body: '{"m":"hi"}',
  };
  const canonical = buildGroupCanonicalV2(fields);
  const signature = signMessage(a.privateKey, canonical);
  assert.equal(verifyMessage(a.publicKey, canonical, signature), true);
  // 直接传对象等价于先拼 canonical
  assert.equal(verifyMessage(a.publicKey, fields, signature), true);

  for (const bad of [
    { ...fields, body: '{"m":"hacked"}' },
    { ...fields, ts: 2 },
    { ...fields, nonce: 'n2' },
    { ...fields, senderPeerId: 'peer-b' },
    { ...fields, groupId: 'g2' },
    { ...fields, method: 'GET' },
    { ...fields, path: '/v1/group/other' },
  ]) {
    assert.equal(verifyMessage(a.publicKey, bad, signature), false, JSON.stringify(bad));
  }
  // A 拿自己的私钥冒 B 的 peerId 签名（用 B 的公钥验）→ 失败
  assert.equal(verifyMessage(b.publicKey, canonical, signature), false);
  // 畸形输入只返回 false，不抛错
  assert.equal(verifyMessage(a.publicKey, canonical, 'not-base64!!'), false);
  assert.equal(verifyMessage(a.publicKey, canonical, ''), false);
  assert.equal(verifyMessage('not-a-key', canonical, signature), false);
});

// ---------------------------------------------------------------------------
// 6. 轮换
// ---------------------------------------------------------------------------

test('needsRotation/rotationDueAt：30 天到期，已过期也算必须换', () => {
  const { caPrivateKey } = makeCa();
  const now = Date.now();
  const cert = makeCert(caPrivateKey, { issuedAt: now, expiresAt: now + 90 * DAY });
  assert.equal(rotationDueAt(cert), now + DEFAULT_ROTATE_AFTER_MS);
  assert.equal(DEFAULT_ROTATE_AFTER_MS, 30 * DAY);
  assert.equal(needsRotation(cert, { now }), false);
  assert.equal(needsRotation(cert, { now: now + DEFAULT_ROTATE_AFTER_MS - 1 }), false);
  assert.equal(needsRotation(cert, { now: now + DEFAULT_ROTATE_AFTER_MS }), true);
  assert.equal(needsRotation(cert, { now, rotateAfterMs: 10 * DAY }), false);
  assert.equal(needsRotation(cert, { now: now + 10 * DAY, rotateAfterMs: 10 * DAY }), true);
  // 签发时间未知 → 不炸
  assert.equal(Number.isNaN(rotationDueAt({})), true);
  assert.equal(needsRotation({}), false);
  // 已过期（哪怕还没到 rotateAfter）→ 必须换
  const stale = makeCert(caPrivateKey, { issuedAt: now - 40 * DAY, expiresAt: now - 8 * DAY });
  assert.equal(needsRotation(stale, { now }), true);
});
