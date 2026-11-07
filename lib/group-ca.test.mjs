// dsh-lan-peers · v0.9.0-α 群身份 P2 服务端 CA（hub 签发成员证书 + 台账）的钉子。
//
// 钉死七件事（都是"改坏了会静默失效"的那种）：
//   1. hub-ca-key.json 形状固定 { v, salt, nonce, ct, fingerprintHint, pubKey }，0600，
//      文件里**绝不出现私钥明文**，第二次读取复用同一把（不重建）；
//   2. 换机器（指纹变了）/ 文件被改 → 稳定码 identity-unavailable，**绝不静默重建**；
//   3. 首次签发：7 个字段（含 alg/sig）、verifyCertificate 通过、有效期 = 30 天；
//   4. **已有证书一律拒绝重登记**（cert-exists）—— 否则握有 groupKey 的人能顶别人身份；
//   5. 轮换：新证书生效，旧证书降为 previous，graceUntil = 旧 expiresAt + 7 天宽限；
//   6. 台账丢了按空表重建（重新注册即恢复），不留半截状态；
//   7. 成员侧信任根读不到就是 null（不抛错、不臆造）。
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {
  DEFAULT_GRACE_MS,
  DEFAULT_ROTATE_AFTER_MS,
  IDENTITY_MISSING,
  IDENTITY_UNAVAILABLE,
  CERT_FIELDS,
  createKeypair,
  publicKeyFromText,
  verifyCertificate,
} from './group-identity.mjs';
import {
  GROUP_IDENTITY_PATHS,
  HUB_CA_KEY_FILE,
  MEMBER_CERTS_FILE,
  MEMBER_CERTS_VERSION,
  issueMemberCertificate,
  ledgerAcceptsCertificate,
  loadOrCreateHubCa,
  memberCertRecord,
  memberCertsPath,
  readMemberCerts,
  readTrustedHubCaPubKey,
  rotateMemberCertificate,
  trustedHubCaPath,
  hubCaKeyPath,
  writeMemberCerts,
} from './group-ca.mjs';
import { makeTempStateDir } from '../host/test/helpers.mjs';

const DAY = 24 * 60 * 60 * 1000;
const NOW = 1_700_000_000_000;

const withTempDir = (fn) => {
  const dir = makeTempStateDir('dsh-group-ca-');
  try {
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
};

const memberFixture = () => ({
  peerId: 'peer-identity-alpha',
  groupId: 'group-identity-1',
  keypair: createKeypair(),
});

test('CA 私钥首次创建：形状固定、公钥明文可读、第二次复用不重建', () => withTempDir((dir) => {
  const first = loadOrCreateHubCa(dir);
  assert.equal(first.ok, true);
  assert.equal(first.created, true);
  assert.equal(first.error, undefined);
  const file = hubCaKeyPath(dir);
  assert.equal(file, path.join(dir, 'group', HUB_CA_KEY_FILE));
  const raw = fs.readFileSync(file, 'utf8');
  const parsed = JSON.parse(raw);
  assert.deepEqual(Object.keys(parsed).sort(), ['ct', 'fingerprintHint', 'nonce', 'pubKey', 'salt', 'v'].sort());
  assert.equal(parsed.v, 1);
  assert.equal(typeof parsed.pubKey, 'string');
  assert.equal(publicKeyFromText(parsed.pubKey).asymmetricKeyType, 'ed25519');
  // 私钥不得以明文出现：既不是 PEM，也不是 pkcs8 DER 的 base64 原样
  assert.equal(/BEGIN\s+(?:PRIVATE|ENCRYPTED)/.test(raw), false);
  assert.equal(raw.includes(first.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64')), false);

  const second = loadOrCreateHubCa(dir);
  assert.equal(second.ok, true);
  assert.equal(second.created, false);
  assert.equal(second.pubKey, first.pubKey);
  assert.equal(fs.readFileSync(file, 'utf8'), raw);
}));

test('CA 换机器（指纹变了）：identity-unavailable，文件逐字节未变', () => withTempDir((dir) => {
  const created = loadOrCreateHubCa(dir);
  assert.equal(created.ok, true);
  const file = hubCaKeyPath(dir);
  const before = fs.readFileSync(file);
  const other = loadOrCreateHubCa(dir, { fingerprint: 'another-machine-fingerprint' });
  assert.equal(other.ok, false);
  assert.equal(other.error, IDENTITY_UNAVAILABLE);
  assert.equal(fs.readFileSync(file).equals(before), true, '解不开时不许重写/重建');
}));

test('CA 文件被改成垃圾：identity-unavailable，不重建', () => withTempDir((dir) => {
  loadOrCreateHubCa(dir);
  const file = hubCaKeyPath(dir);
  fs.writeFileSync(file, '{not json', { mode: 0o600 });
  const again = loadOrCreateHubCa(dir);
  assert.equal(again.ok, false);
  assert.equal(again.error, IDENTITY_UNAVAILABLE);
  assert.equal(fs.readFileSync(file, 'utf8'), '{not json');
}));

test('create:false 且文件不存在 → identity-missing（不生成）', () => withTempDir((dir) => {
  const ca = loadOrCreateHubCa(dir, { create: false });
  assert.equal(ca.ok, false);
  assert.equal(ca.error, IDENTITY_MISSING);
  assert.equal(fs.existsSync(hubCaKeyPath(dir)), false);
}));

test('首次签发：七字段 + alg/sig、能被信任根验过、有效期 30 天', () => withTempDir((dir) => {
  const ca = loadOrCreateHubCa(dir);
  const member = memberFixture();
  const issued = issueMemberCertificate({
    stateDir: dir,
    caPrivateKey: ca.privateKey,
    peerId: member.peerId,
    pubKey: member.keypair.publicKeyDer,
    groupId: member.groupId,
    hubEpoch: 3,
    now: NOW,
  });
  assert.equal(issued.ok, true);
  const cert = issued.cert;
  assert.deepEqual(Object.keys(cert).sort(), [...CERT_FIELDS, 'alg', 'sig'].sort());
  assert.equal(cert.peerId, member.peerId);
  assert.equal(cert.groupId, member.groupId);
  assert.equal(cert.hubEpoch, 3);
  assert.equal(cert.alg, 'ed25519');
  assert.equal(cert.issuedAt, NOW);
  assert.equal(cert.expiresAt, NOW + DEFAULT_ROTATE_AFTER_MS);
  assert.equal(verifyCertificate(ca.publicKey, cert, { now: NOW }).ok, true);

  const record = memberCertRecord(dir, member.peerId);
  assert.deepEqual(record.current, cert);
  assert.equal(record.previous, null);
  const file = JSON.parse(fs.readFileSync(memberCertsPath(dir), 'utf8'));
  assert.equal(file.v, MEMBER_CERTS_VERSION);
  assert.deepEqual(Object.keys(file.members), [member.peerId]);
}));

test('已有证书重登记一律拒绝（cert-exists）：groupKey 持有者不能顶别人身份', () => withTempDir((dir) => {
  const ca = loadOrCreateHubCa(dir);
  const victim = memberFixture();
  const attacker = memberFixture();
  const first = issueMemberCertificate({
    stateDir: dir,
    caPrivateKey: ca.privateKey,
    peerId: victim.peerId,
    pubKey: victim.keypair.publicKeyDer,
    groupId: victim.groupId,
    now: NOW,
  });
  assert.equal(first.ok, true);
  // 攻击者手握 groupKey（能拿别人的 peerId 发 v1 请求），但拿不到别人的私钥：
  // 唯一能做的就是「用同一个 peerId 重新登记自己的公钥」，这里必须被拒。
  const retry = issueMemberCertificate({
    stateDir: dir,
    caPrivateKey: ca.privateKey,
    peerId: victim.peerId,
    pubKey: attacker.keypair.publicKeyDer,
    groupId: victim.groupId,
    now: NOW + 1000,
  });
  assert.equal(retry.ok, false);
  assert.equal(retry.reason, 'cert-exists');
  assert.equal(memberCertRecord(dir, victim.peerId).current.pubKey, victim.keypair.publicKeyDer);
}));

test('轮换：新证书生效，旧证书降为 previous 且 graceUntil = 旧 expiresAt + 7 天', () => withTempDir((dir) => {
  const ca = loadOrCreateHubCa(dir);
  const member = memberFixture();
  const next = createKeypair();
  issueMemberCertificate({
    stateDir: dir,
    caPrivateKey: ca.privateKey,
    peerId: member.peerId,
    pubKey: member.keypair.publicKeyDer,
    groupId: member.groupId,
    now: NOW,
  });
  const rotatedAt = NOW + 30 * DAY;
  const rotated = rotateMemberCertificate({
    stateDir: dir,
    caPrivateKey: ca.privateKey,
    peerId: member.peerId,
    newPubKey: next.publicKeyDer,
    groupId: member.groupId,
    hubEpoch: 5,
    now: rotatedAt,
  });
  assert.equal(rotated.ok, true);
  assert.equal(rotated.cert.pubKey, next.publicKeyDer);
  assert.equal(rotated.cert.issuedAt, rotatedAt);
  assert.equal(rotated.previous.pubKey, member.keypair.publicKeyDer);
  assert.equal(rotated.previous.graceUntil, NOW + DEFAULT_ROTATE_AFTER_MS + DEFAULT_GRACE_MS);
  // 契约 §8.1（r2）：旧证书进 previous 时带 revokedAt；宽限只管「证书自身过期」，不是吊销容忍
  assert.equal(rotated.previous.revokedAt, rotatedAt);

  const record = memberCertRecord(dir, member.peerId);
  assert.equal(record.current.pubKey, next.publicKeyDer);
  assert.equal(record.previous.graceUntil, rotated.previous.graceUntil);
  assert.equal(record.previous.revokedAt, rotatedAt);
  // 旧证书在宽限内仍可验（协议层靠它给客户端留 7 天换钥时间）
  assert.equal(verifyCertificate(ca.publicKey, record.previous, { now: rotatedAt }).ok, true);
  assert.equal(
    verifyCertificate(ca.publicKey, record.previous, { now: rotated.previous.graceUntil + 1 }).ok,
    false,
  );
}));

test('轮换一个从没注册过的 peerId：cert-missing，不凭空补发', () => withTempDir((dir) => {
  const ca = loadOrCreateHubCa(dir);
  const keypair = createKeypair();
  const rotated = rotateMemberCertificate({
    stateDir: dir,
    caPrivateKey: ca.privateKey,
    peerId: 'peer-never-registered',
    newPubKey: keypair.publicKeyDer,
    groupId: 'group-identity-1',
    now: NOW,
  });
  assert.equal(rotated.ok, false);
  assert.equal(rotated.reason, 'cert-missing');
  assert.deepEqual(readMemberCerts(dir).members, {});
}));

test('台账丢失 → 空表重建，重新注册即恢复（落盘态可重建）', () => withTempDir((dir) => {
  const ca = loadOrCreateHubCa(dir);
  const member = memberFixture();
  issueMemberCertificate({
    stateDir: dir,
    caPrivateKey: ca.privateKey,
    peerId: member.peerId,
    pubKey: member.keypair.publicKeyDer,
    groupId: member.groupId,
    now: NOW,
  });
  fs.rmSync(memberCertsPath(dir));
  assert.deepEqual(readMemberCerts(dir), { v: MEMBER_CERTS_VERSION, members: {} });
  const again = issueMemberCertificate({
    stateDir: dir,
    caPrivateKey: ca.privateKey,
    peerId: member.peerId,
    pubKey: member.keypair.publicKeyDer,
    groupId: member.groupId,
    now: NOW + 5000,
  });
  assert.equal(again.ok, true);
  assert.equal(memberCertRecord(dir, member.peerId).current.issuedAt, NOW + 5000);
}));

test('落盘文件在 POSIX 上是 0600', { skip: process.platform === 'win32' ? 'Windows 上 chmod 是空操作' : false }, () => withTempDir((dir) => {
  const ca = loadOrCreateHubCa(dir);
  writeMemberCerts(dir, { members: {} });
  assert.equal(fs.statSync(hubCaKeyPath(dir)).mode & 0o777, 0o600);
  assert.equal(fs.statSync(memberCertsPath(dir)).mode & 0o777, 0o600);
  assert.equal(fs.statSync(path.dirname(hubCaKeyPath(dir))).mode & 0o777, 0o700);
  assert.equal(ca.ok, true);
}));

test('成员侧信任根：缺失返回 null，坏文件也返回 null（不抛错）', () => withTempDir((dir) => {
  assert.equal(readTrustedHubCaPubKey(dir), null);
  fs.mkdirSync(path.dirname(trustedHubCaPath(dir)), { recursive: true });
  fs.writeFileSync(trustedHubCaPath(dir), '{broken', { mode: 0o600 });
  assert.equal(readTrustedHubCaPubKey(dir), null);
  fs.writeFileSync(
    trustedHubCaPath(dir),
    JSON.stringify({ hubCaPubKey: 'abc', hubEpoch: 1, at: NOW, source: 'register' }),
    { mode: 0o600 },
  );
  assert.equal(readTrustedHubCaPubKey(dir), 'abc');
}));

test('身份端点路径在服务端本地集合里（契约 §7）', () => {
  assert.deepEqual([...GROUP_IDENTITY_PATHS], ['/v1/group/identity/register', '/v1/group/identity/rotate']);
  // 台账文件名固定（换名会让「可重建」失效）
  assert.equal(path.basename(memberCertsPath('x')), MEMBER_CERTS_FILE);
});

test('台账吊销判定（契约 §8.1 第 8.5 步）：只有 current 放行，previous 一律不接受', () => withTempDir((dir) => {
  const ca = loadOrCreateHubCa(dir);
  const member = memberFixture();
  const issued = issueMemberCertificate({
    stateDir: dir,
    caPrivateKey: ca.privateKey,
    peerId: member.peerId,
    pubKey: member.keypair.publicKeyDer,
    groupId: member.groupId,
    now: NOW,
  });
  // 没有该 peerId 的记录（含台账文件都不存在）→ 跳过检查，首注册成员立刻可用
  assert.deepEqual(ledgerAcceptsCertificate(dir, 'peer-never-registered', { pubKey: 'x', issuedAt: 1 }), {
    checked: false,
    ok: true,
  });
  // current → 放行
  assert.deepEqual(ledgerAcceptsCertificate(dir, member.peerId, issued.cert), { checked: true, ok: true });

  // 同一 peerId 的别的证书（哪怕签名合法、没过期）→ 不接受，调用方回 401 cert-revoked
  const stray = createKeypair();
  const other = issueMemberCertificate({
    stateDir: dir,
    caPrivateKey: ca.privateKey,
    peerId: 'peer-someone-else',
    pubKey: stray.publicKeyDer,
    groupId: member.groupId,
    now: NOW,
  });
  assert.deepEqual(ledgerAcceptsCertificate(dir, 'peer-someone-else', other.cert), { checked: true, ok: true });
  assert.deepEqual(ledgerAcceptsCertificate(dir, 'peer-someone-else', issued.cert), { checked: true, ok: false });

  // rotate 之后：旧证书（previous，带 revokedAt）立刻不接受，新证书接受
  const rotated = rotateMemberCertificate({
    stateDir: dir,
    caPrivateKey: ca.privateKey,
    peerId: member.peerId,
    newPubKey: stray.publicKeyDer,
    groupId: member.groupId,
    now: NOW + 1,
  });
  assert.deepEqual(ledgerAcceptsCertificate(dir, member.peerId, issued.cert), { checked: true, ok: false });
  assert.deepEqual(ledgerAcceptsCertificate(dir, member.peerId, rotated.cert), { checked: true, ok: true });
  assert.deepEqual(ledgerAcceptsCertificate(dir, member.peerId, rotated.previous), { checked: true, ok: false });

  // 台账写坏 → 当空表（跳过），绝不让服务拒绝启动
  fs.writeFileSync(memberCertsPath(dir), '{broken', { mode: 0o600 });
  assert.deepEqual(ledgerAcceptsCertificate(dir, member.peerId, issued.cert), { checked: false, ok: true });
}));
