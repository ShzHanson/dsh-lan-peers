/**
 * P2（0.9.0-α）群级鉴权 v2：证书 + ed25519（契约 group-v2-wire-contract.md §1/§3/§5）。
 *
 * 覆盖：
 *   - 九步校验的正例与逐条负例（头缺失 / cert 坏 / 别的 CA / peerId 不符 / 过期与宽限 /
 *     时钟 / 重放（与 v1 共用 groupNonces）/ 成员表 / 签名）；
 *   - **核心收益**：握有 groupKey 但无私钥 → 既不能重登记别人的 peerId，也不能在 v2 里冒充；
 *   - v1 头行为不变 + legacy 告警（每 peer 60 秒一行）+ allowLegacyGroupAuth=false；
 *   - 两条身份端点：register（v1 头）/ rotate（v2 头）/ 非 hub 404 / 白名单门禁扩展没放宽。
 *
 * 契约 §7：本侧自己造 v2 头（字面量 'group-v2' / 'X-Peer-Cert'），不 import 客户端侧的 v2 辅助；
 * v1 头与信封用 group-client 的原语（服务端也用同一份 canonical，拼错了才会静默验不过）。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import {
  GROUP_AUTH_HEADER,
  GROUP_AUTH_VALUE,
  GROUP_ID_HEADER,
  buildGroupCanonical,
  decryptGroupJson,
  deriveGroupKeys,
  encryptGroupBody,
  signGroupCanonical,
  writeGroupKeyFile,
} from '../../lib/group-client.mjs';
import {
  DEFAULT_GRACE_MS,
  DEFAULT_ROTATE_AFTER_MS,
  buildGroupCanonicalV2,
  createKeypair,
  signCertificate,
  signMessage,
} from '../../lib/group-identity.mjs';
import { loadOrCreateHubCa, memberCertsPath } from '../../lib/group-ca.mjs';
// pairProof（§8.2）用的就是既有 per-peer 的 5 行 canonical 与 HMAC：服务端导出的这两个函数
// 是同一份实现，测试必须用它们（自己拼 canonical 拼错了会静默变成「验不过」）。
import { buildCanonical, signCanonical } from '../server.mjs';
import { setTimeout as sleep } from 'node:timers/promises';
import { makeTempStateDir, peerFixture, seedPeers, startServer } from './helpers.mjs';

const DAY = 24 * 60 * 60 * 1000;
const CERT_HEADER = 'X-Peer-Cert';
const AUTH_V2 = 'group-v2';

// 三个已配对的 peer：A 是普通成员（被冒充的对象），B 是**握有 groupKey 的攻击者**，C 不在群里
const MEMBER_A = peerFixture('peer-v2-alpha');
const MEMBER_B = peerFixture('peer-v2-bravo');
const OUTSIDER = peerFixture('peer-v2-outsider');
// 刻意**不**种进 peers.json：靠群名入群的那种成员（契约 §8.2 允许它不带 pairProof）
const UNPAIRED = peerFixture('peer-v2-unpaired');

const dirOf = (hub) => hub.stateDir;

async function startHub(t, overrides = {}) {
  const stateDir = overrides.stateDir ?? makeTempStateDir();
  seedPeers(stateDir, [MEMBER_A, MEMBER_B, OUTSIDER]);
  // 假 peerId 成员无法 ack：与 group.test.mjs 同理固定 quorum:none
  const group = { enabled: true, name: 'default', autoJoin: false, retentionDays: 7, quorum: 'none' };
  const started = await startServer(t, {
    stateDir,
    allowRemotePrompts: true,
    ...overrides,
    group: { ...group, ...(overrides.group ?? {}) },
  });
  return started;
}

const groupKeyOf = (hub) => hub.server.group.state({ includeKey: true }).groupKey;
const groupIdOf = (hub) => hub.server.group.state().groupId;
const epochOf = (hub) => hub.server.group.state().epoch;

/** 群信封请求：plain 参与签名，线上传 bodyKey 加密后的密文；响应按需解密 */
async function sendGroup(baseUrl, { groupKey, headers, method = 'GET', apiPath, plain }) {
  const { bodyKey } = deriveGroupKeys(groupKey);
  const payload = plain ?? Buffer.alloc(0);
  const wire = payload.length > 0 && method !== 'GET' && method !== 'HEAD'
    ? Buffer.from(encryptGroupBody(bodyKey, payload), 'utf8')
    : Buffer.alloc(0);
  const res = await fetch(new URL(apiPath, baseUrl), {
    method,
    headers: { ...headers, 'x-peer-enc': 'v1' },
    body: wire.length ? wire : undefined,
  });
  const text = await res.text();
  let json = null;
  try {
    const parsed = JSON.parse(text);
    json = parsed && parsed.enc === 'v1' && typeof parsed.data === 'string'
      ? decryptGroupJson(bodyKey, parsed.data)
      : parsed;
  } catch {
    /* 非 JSON 留给调用方看 text */
  }
  return { status: res.status, json, text };
}

/** v1 头（groupKey HMAC）：ts/nonce/groupId/senderId/signature 都可覆盖 */
function v1Headers({
  groupKey, groupId, senderId, method = 'GET', apiPath, body, ts, nonce, signature, groupIdHeader,
}) {
  const { signKey } = deriveGroupKeys(groupKey);
  const plain = body === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(body), 'utf8');
  const stamp = ts ?? Date.now();
  const fresh = nonce ?? randomBytes(16).toString('hex');
  const canonical = buildGroupCanonical({
    method,
    path: apiPath,
    ts: stamp,
    nonce: fresh,
    groupId,
    senderPeerId: senderId,
    rawBody: plain,
  });
  return {
    plain,
    nonce: fresh,
    headers: {
      [GROUP_AUTH_HEADER]: GROUP_AUTH_VALUE,
      'X-Peer-Id': String(senderId ?? ''),
      [GROUP_ID_HEADER]: String(groupIdHeader ?? groupId ?? ''),
      'X-Peer-Ts': String(stamp),
      'X-Peer-Nonce': fresh,
      'X-Peer-Sign': signature ?? signGroupCanonical({ signKey, canonical }),
    },
  };
}

/** v2 头（证书 + ed25519，契约 §2）：字段名与 v1 一致，只多 X-Peer-Cert */
function v2Headers({
  cert, privateKey, groupId, senderId, method = 'GET', apiPath, body, ts, nonce, signature, omitCert = false,
}) {
  const plain = body === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(body), 'utf8');
  const stamp = ts ?? Date.now();
  const fresh = nonce ?? randomBytes(16).toString('hex');
  const peerId = String(senderId ?? cert.peerId ?? '');
  const canonical = buildGroupCanonicalV2({
    method,
    path: apiPath,
    ts: stamp,
    nonce: fresh,
    groupId,
    senderPeerId: peerId,
    rawBody: plain,
  });
  const headers = {
    [GROUP_AUTH_HEADER]: AUTH_V2,
    'X-Peer-Id': peerId,
    [GROUP_ID_HEADER]: String(groupId ?? ''),
    'X-Peer-Ts': String(stamp),
    'X-Peer-Nonce': fresh,
    'X-Peer-Sign': signature ?? signMessage(privateKey, canonical),
  };
  if (!omitCert) headers[CERT_HEADER] = Buffer.from(JSON.stringify(cert), 'utf8').toString('base64url');
  return { plain, nonce: fresh, headers };
}

/** 契约 §8.2：pairProof 的签名对象固定三字段（顺序固定、不含 pairProof 自身） */
function pairProofFor(member, { peerId, pubKey, groupId }, overrides = {}) {
  const proofBody = Buffer.from(JSON.stringify({ peerId, pubKey, groupId }), 'utf8');
  const ts = overrides.ts ?? Date.now();
  const nonce = overrides.nonce ?? randomBytes(16).toString('hex');
  const canonical = buildCanonical({
    method: 'POST',
    path: '/v1/group/identity/register',
    ts,
    nonce,
    rawBody: proofBody,
  });
  return {
    ts,
    nonce,
    sig: overrides.sig ?? signCanonical({ secret: member.inboundSecret, canonical }),
  };
}

/**
 * 走 v1 头注册一个成员，返回 hub 签的证书。
 * 契约 §8.2：`peers.json` 里有该 peerId 的配对记录时必须带 pairProof —— 默认自动带，
 * `omitProof: true`（未配对成员的场景）或 `proof`（负例）可覆盖。
 */
async function register(hub, member, options = {}) {
  const groupKey = groupKeyOf(hub);
  const groupId = groupIdOf(hub);
  const keypair = member.keypair ?? createKeypair();
  const apiPath = '/v1/group/identity/register';
  const body = { peerId: member.peerId, pubKey: keypair.publicKeyDer, groupId };
  const proof = options.proof !== undefined
    ? options.proof
    : (options.omitProof === true || !member.inboundSecret ? undefined : pairProofFor(member, body));
  if (proof !== undefined) body.pairProof = proof;
  const sent = v1Headers({
    groupKey, groupId, senderId: member.peerId, method: 'POST', apiPath, body,
  });
  const res = await sendGroup(hub.baseUrl, {
    groupKey, headers: sent.headers, method: 'POST', apiPath, plain: sent.plain,
  });
  return { ...res, keypair, body, cert: res.json?.cert ?? null };
}

/** 手搓一张证书（拿 hub CA 私钥签）：用于过期 / 别人 CA / 幽灵成员的负例 */
function craftCert(hub, overrides = {}) {
  const ca = loadOrCreateHubCa(dirOf(hub));
  assert.equal(ca.ok, true);
  const now = Date.now();
  return signCertificate(ca.privateKey, {
    peerId: MEMBER_A.peerId,
    pubKey: createKeypair().publicKeyDer,
    groupId: groupIdOf(hub),
    issuedAt: now,
    expiresAt: now + DEFAULT_ROTATE_AFTER_MS,
    hubEpoch: 0,
    ...overrides,
  });
}

const probe = (hub, headers, plain) => sendGroup(hub.baseUrl, {
  groupKey: groupKeyOf(hub), headers, method: 'GET', apiPath: '/v1/group/probe', plain,
});

const ledger = (hub) => JSON.parse(fs.readFileSync(memberCertsPath(dirOf(hub)), 'utf8'));

// ---------------------------------------------------------------------------
// 正例：注册 + v2 请求
// ---------------------------------------------------------------------------

test('register：用 v1 头鉴权，返回 {cert, hubCaPubKey, hubEpoch} 并落台账', async (t) => {
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER_A.peerId, MEMBER_A.name);

  const registered = await register(hub, MEMBER_A);
  assert.equal(registered.status, 200, registered.text);
  const { cert, hubCaPubKey, hubEpoch } = registered.json;
  assert.equal(cert.peerId, MEMBER_A.peerId);
  assert.equal(cert.groupId, groupIdOf(hub));
  assert.equal(cert.pubKey, registered.keypair.publicKeyDer);
  assert.equal(cert.alg, 'ed25519');
  assert.equal(typeof cert.sig, 'string');
  assert.equal(cert.expiresAt, cert.issuedAt + DEFAULT_ROTATE_AFTER_MS);
  assert.equal(hubEpoch, epochOf(hub));
  assert.equal(hubCaPubKey, loadOrCreateHubCa(dirOf(hub)).pubKey);

  const file = ledger(hub);
  assert.deepEqual(Object.keys(file.members), [MEMBER_A.peerId]);
  assert.equal(file.members[MEMBER_A.peerId].current.sig, cert.sig);
});

test('v2 头走证书 + ed25519：GET /v1/group/probe 200（白名单门禁放行）', async (t) => {
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER_A.peerId, MEMBER_A.name);
  const registered = await register(hub, MEMBER_A);
  const sent = v2Headers({
    cert: registered.cert,
    privateKey: registered.keypair.privateKey,
    groupId: groupIdOf(hub),
    senderId: MEMBER_A.peerId,
    apiPath: '/v1/group/probe',
  });
  const res = await probe(hub, sent.headers, sent.plain);
  assert.equal(res.status, 200, res.text);
  assert.equal(res.json.ok, true);
  assert.equal(res.json.groupId, groupIdOf(hub));
});

// ---------------------------------------------------------------------------
// 负例：契约 §3 九步逐一
// ---------------------------------------------------------------------------

test('第1步：缺 X-Peer-Cert → 401 bad-signature', async (t) => {
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER_A.peerId, MEMBER_A.name);
  const registered = await register(hub, MEMBER_A);
  const sent = v2Headers({
    cert: registered.cert,
    privateKey: registered.keypair.privateKey,
    groupId: groupIdOf(hub),
    senderId: MEMBER_A.peerId,
    apiPath: '/v1/group/probe',
    omitCert: true,
  });
  const res = await probe(hub, sent.headers, sent.plain);
  assert.equal(res.status, 401);
  assert.equal(res.json.error, 'bad-signature');
});

test('第2步：cert 不是合法的 base64url(JSON) → 401 bad-certificate', async (t) => {
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER_A.peerId, MEMBER_A.name);
  const registered = await register(hub, MEMBER_A);
  const sent = v2Headers({
    cert: registered.cert,
    privateKey: registered.keypair.privateKey,
    groupId: groupIdOf(hub),
    senderId: MEMBER_A.peerId,
    apiPath: '/v1/group/probe',
  });
  sent.headers[CERT_HEADER] = Buffer.from('not-json', 'utf8').toString('base64url');
  const res = await probe(hub, sent.headers, sent.plain);
  assert.equal(res.status, 401);
  assert.equal(res.json.error, 'bad-certificate');
});

test('第3步：别的 CA 私钥签的证书 → 401 untrusted-ca', async (t) => {
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER_A.peerId, MEMBER_A.name);
  await register(hub, MEMBER_A);
  const rogue = createKeypair();
  const now = Date.now();
  const cert = signCertificate(rogue.privateKey, {
    peerId: MEMBER_A.peerId,
    pubKey: rogue.publicKeyDer,
    groupId: groupIdOf(hub),
    issuedAt: now,
    expiresAt: now + DEFAULT_ROTATE_AFTER_MS,
    hubEpoch: 0,
  });
  const sent = v2Headers({
    cert,
    privateKey: rogue.privateKey,
    groupId: groupIdOf(hub),
    senderId: MEMBER_A.peerId,
    apiPath: '/v1/group/probe',
  });
  const res = await probe(hub, sent.headers, sent.plain);
  assert.equal(res.status, 401);
  assert.equal(res.json.error, 'untrusted-ca');
});

test('第3步：过期 8 天 → 401 cert-expired；过期 1 天 → 200（7 天宽限内）', async (t) => {
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER_A.peerId, MEMBER_A.name);
  hub.server.group.addMember(MEMBER_B.peerId, MEMBER_B.name);
  await register(hub, MEMBER_A);
  const keypair = createKeypair();
  const now = Date.now();

  const stale = craftCert(hub, {
    peerId: MEMBER_A.peerId,
    pubKey: keypair.publicKeyDer,
    issuedAt: now - 60 * DAY,
    expiresAt: now - 8 * DAY,
  });
  const staleRes = await probe(hub, v2Headers({
    cert: stale,
    privateKey: keypair.privateKey,
    groupId: groupIdOf(hub),
    senderId: MEMBER_A.peerId,
    apiPath: '/v1/group/probe',
  }).headers);
  assert.equal(staleRes.status, 401);
  assert.equal(staleRes.json.error, 'cert-expired', '过期超宽限：第 3 步先于第 8.5 步');

  // 宽限只管「证书自身过期」这件事，用**台账里没有的**成员验它（否则第 8.5 步会先判 cert-revoked）
  const inGrace = craftCert(hub, {
    peerId: MEMBER_B.peerId,
    pubKey: keypair.publicKeyDer,
    issuedAt: now - 31 * DAY,
    expiresAt: now - 1 * DAY,
  });
  const graceSent = v2Headers({
    cert: inGrace,
    privateKey: keypair.privateKey,
    groupId: groupIdOf(hub),
    senderId: MEMBER_B.peerId,
    apiPath: '/v1/group/probe',
  });
  const graceRes = await probe(hub, graceSent.headers, graceSent.plain);
  assert.equal(graceRes.status, 200, graceRes.text);
  assert.equal(graceRes.json.ok, true);
});

test('第4步：cert.peerId 与 X-Peer-Id 不符 → 401 cert-peer-mismatch', async (t) => {
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER_A.peerId, MEMBER_A.name);
  hub.server.group.addMember(MEMBER_B.peerId, MEMBER_B.name);
  const registered = await register(hub, MEMBER_A);
  // 用 A 的证书/私钥，但头里自称 B（签名是按 B 算的，所以能过验签那一步）
  const sent = v2Headers({
    cert: registered.cert,
    privateKey: registered.keypair.privateKey,
    groupId: groupIdOf(hub),
    senderId: MEMBER_B.peerId,
    apiPath: '/v1/group/probe',
  });
  const res = await probe(hub, sent.headers, sent.plain);
  assert.equal(res.status, 401);
  assert.equal(res.json.error, 'cert-peer-mismatch');
});

test('第4步：证书的 groupId 与本群不符 → 401 group-mismatch', async (t) => {
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER_A.peerId, MEMBER_A.name);
  await register(hub, MEMBER_A);
  const keypair = createKeypair();
  const now = Date.now();
  const otherGroupCert = signCertificate(loadOrCreateHubCa(dirOf(hub)).privateKey, {
    peerId: MEMBER_A.peerId,
    pubKey: keypair.publicKeyDer,
    groupId: 'some-other-group',
    issuedAt: now,
    expiresAt: now + DEFAULT_ROTATE_AFTER_MS,
    hubEpoch: 0,
  });
  const sent = v2Headers({
    cert: otherGroupCert,
    privateKey: keypair.privateKey,
    groupId: 'some-other-group',
    senderId: MEMBER_A.peerId,
    apiPath: '/v1/group/probe',
  });
  const res = await probe(hub, sent.headers, sent.plain);
  assert.equal(res.status, 401);
  assert.equal(res.json.error, 'group-mismatch');
});

test('第5步：ts 偏移 120 秒 → 401 clock-skew', async (t) => {
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER_A.peerId, MEMBER_A.name);
  const registered = await register(hub, MEMBER_A);
  const sent = v2Headers({
    cert: registered.cert,
    privateKey: registered.keypair.privateKey,
    groupId: groupIdOf(hub),
    senderId: MEMBER_A.peerId,
    apiPath: '/v1/group/probe',
    ts: Date.now() - 120_000,
  });
  const res = await probe(hub, sent.headers, sent.plain);
  assert.equal(res.status, 401);
  assert.equal(res.json.error, 'clock-skew');
});

test('第6步：nonce 与 v1 共用同一张表（v1 用过的 nonce，v2 重放 → 401 replay）', async (t) => {
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER_A.peerId, MEMBER_A.name);
  const registered = await register(hub, MEMBER_A);
  const groupKey = groupKeyOf(hub);
  const groupId = groupIdOf(hub);
  const sharedNonce = randomBytes(16).toString('hex');

  const v1Sent = v1Headers({
    groupKey, groupId, senderId: MEMBER_A.peerId, apiPath: '/v1/group/probe', nonce: sharedNonce,
  });
  const first = await probe(hub, v1Sent.headers, v1Sent.plain);
  assert.equal(first.status, 200, first.text);

  const v2Sent = v2Headers({
    cert: registered.cert,
    privateKey: registered.keypair.privateKey,
    groupId,
    senderId: MEMBER_A.peerId,
    apiPath: '/v1/group/probe',
    nonce: sharedNonce,
  });
  const replay = await probe(hub, v2Sent.headers, v2Sent.plain);
  assert.equal(replay.status, 401);
  assert.equal(replay.json.error, 'replay');

  // 反向：v2 用过的 nonce，v1 再发也必须 replay（同一张表两个方向都拦）
  const v2First = v2Headers({
    cert: registered.cert,
    privateKey: registered.keypair.privateKey,
    groupId,
    senderId: MEMBER_A.peerId,
    apiPath: '/v1/group/probe',
  });
  assert.equal((await probe(hub, v2First.headers, v2First.plain)).status, 200);
  const v1Replay = v1Headers({
    groupKey, groupId, senderId: MEMBER_A.peerId, apiPath: '/v1/group/probe', nonce: v2First.nonce,
  });
  const second = await probe(hub, v1Replay.headers, v1Replay.plain);
  assert.equal(second.status, 401);
  assert.equal(second.json.error, 'replay');
});

test('第7步：签名不是证书里那把私钥签的 → 401 bad-signature', async (t) => {
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER_A.peerId, MEMBER_A.name);
  const registered = await register(hub, MEMBER_A);
  const other = createKeypair();
  const sent = v2Headers({
    cert: registered.cert,
    privateKey: other.privateKey, // 别人的钥匙
    groupId: groupIdOf(hub),
    senderId: MEMBER_A.peerId,
    apiPath: '/v1/group/probe',
  });
  const res = await probe(hub, sent.headers, sent.plain);
  assert.equal(res.status, 401);
  assert.equal(res.json.error, 'bad-signature');
});

test('第8步：证书合法但不在成员表 → 401 not-a-member', async (t) => {
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER_A.peerId, MEMBER_A.name);
  await register(hub, MEMBER_A);
  const ghost = createKeypair();
  const now = Date.now();
  const ghostCert = signCertificate(loadOrCreateHubCa(dirOf(hub)).privateKey, {
    peerId: 'peer-v2-ghost',
    pubKey: ghost.publicKeyDer,
    groupId: groupIdOf(hub),
    issuedAt: now,
    expiresAt: now + DEFAULT_ROTATE_AFTER_MS,
    hubEpoch: 0,
  });
  const sent = v2Headers({
    cert: ghostCert,
    privateKey: ghost.privateKey,
    groupId: groupIdOf(hub),
    senderId: 'peer-v2-ghost',
    apiPath: '/v1/group/probe',
  });
  const res = await probe(hub, sent.headers, sent.plain);
  assert.equal(res.status, 401);
  assert.equal(res.json.error, 'not-a-member');
});

// ---------------------------------------------------------------------------
// 核心收益：握有 groupKey、拿不到私钥 → 冒充不了别人
// ---------------------------------------------------------------------------

test('核心负例：持 groupKey  impersonate 别人 —— 重登记被拒 + v2 冒充被拒', async (t) => {
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER_A.peerId, MEMBER_A.name);
  hub.server.group.addMember(MEMBER_B.peerId, MEMBER_B.name);
  const victim = await register(hub, MEMBER_A);
  assert.equal(victim.status, 200);
  const attackerKeys = createKeypair();
  const groupKey = groupKeyOf(hub);
  const groupId = groupIdOf(hub);
  const registerPath = '/v1/group/identity/register';

  // ① 攻击者握有 groupKey，能用 A 的 peerId 发合法的 v1 请求（这是既有限制，契约 §6 保留）
  const asASigned = v1Headers({
    groupKey, groupId, senderId: MEMBER_A.peerId, apiPath: '/v1/group/probe',
  });
  const v1Ok = await probe(hub, asASigned.headers, asASigned.plain);
  assert.equal(v1Ok.status, 200, 'v1 仍按 groupKey 放行（双模式过渡期的既有限制）');

  // ② 但想用 A 的 peerId 给自己登记一把新公钥 —— 契约 §8.2 之后连门都进不来：
  //    A 在 peers.json 里有配对记录，却没有 A 的 pairSecret → 403 pair-proof-required
  //    （比原来更严：不给「走到 cert-exists 那一步」的机会）
  const hijackBody = { peerId: MEMBER_A.peerId, pubKey: attackerKeys.publicKeyDer, groupId };
  const hijack = v1Headers({
    groupKey, groupId, senderId: MEMBER_A.peerId, method: 'POST', apiPath: registerPath, body: hijackBody,
  });
  const hijackRes = await sendGroup(hub.baseUrl, {
    groupKey, headers: hijack.headers, method: 'POST', apiPath: registerPath, plain: hijack.plain,
  });
  assert.equal(hijackRes.status, 403, hijackRes.text);
  assert.equal(hijackRes.json.error, 'pair-proof-required');
  assert.equal(ledger(hub).members[MEMBER_A.peerId].current.pubKey, victim.keypair.publicKeyDer);

  // ②' 真正的 A（配对密钥在手）重登记 → 409 cert-exists：换钥只能走 v2 的 rotate
  const reRegister = await register(hub, MEMBER_A);
  assert.equal(reRegister.status, 409, reRegister.text);
  assert.equal(reRegister.json.error, 'cert-exists');

  // ③ v2 里自称 A 但拿不出 A 的私钥：用自己的证书 → cert-peer-mismatch
  const attackerRegistered = await register(hub, { ...MEMBER_B, keypair: attackerKeys });
  assert.equal(attackerRegistered.status, 200, attackerRegistered.text);
  const masquerade = v2Headers({
    cert: attackerRegistered.cert,
    privateKey: attackerKeys.privateKey,
    groupId,
    senderId: MEMBER_A.peerId,
    apiPath: '/v1/group/probe',
  });
  const masqueradeRes = await probe(hub, masquerade.headers, masquerade.plain);
  assert.equal(masqueradeRes.status, 401);
  assert.equal(masqueradeRes.json.error, 'cert-peer-mismatch');

  // ④ 拿 A 的证书（线上可见）+ 自己的私钥签名 → bad-signature
  const forged = v2Headers({
    cert: victim.cert,
    privateKey: attackerKeys.privateKey,
    groupId,
    senderId: MEMBER_A.peerId,
    apiPath: '/v1/group/probe',
  });
  const forgedRes = await probe(hub, forged.headers, forged.plain);
  assert.equal(forgedRes.status, 401);
  assert.equal(forgedRes.json.error, 'bad-signature');
});

// ---------------------------------------------------------------------------
// v1 兼容：行为不变 + legacy 告警
// ---------------------------------------------------------------------------

test('v1 头仍然工作，并记一行 legacy 告警（同 peer 60 秒内只一条）', async (t) => {
  const lines = [];
  const hub = await startHub(t, { logger: (line) => lines.push(String(line)) });
  hub.server.group.addMember(MEMBER_A.peerId, MEMBER_A.name);
  hub.server.group.addMember(MEMBER_B.peerId, MEMBER_B.name);
  const groupKey = groupKeyOf(hub);
  const groupId = groupIdOf(hub);
  const legacyLines = () => lines.filter((line) => line.startsWith('[group] legacy-auth '));

  for (let i = 0; i < 3; i += 1) {
    const sent = v1Headers({ groupKey, groupId, senderId: MEMBER_A.peerId, apiPath: '/v1/group/probe' });
    const res = await probe(hub, sent.headers, sent.plain);
    assert.equal(res.status, 200, res.text);
  }
  assert.equal(legacyLines().length, 1, '同一 peer 60 秒内只记一条');
  assert.equal(legacyLines()[0], `[group] legacy-auth peer=${MEMBER_A.peerId.slice(0, 8)}`);

  const other = v1Headers({ groupKey, groupId, senderId: MEMBER_B.peerId, apiPath: '/v1/group/probe' });
  assert.equal((await probe(hub, other.headers, other.plain)).status, 200);
  assert.equal(legacyLines().length, 2, '不同 peer 各自一条');
  // 隐私铁律：告警里只有前 8 位，没有完整 peerId
  assert.equal(legacyLines().some((line) => line.includes(MEMBER_A.peerId)), false);
});

test('allowLegacyGroupAuth=false：v1 头 → 401 legacy-auth-disabled，v2 头照常 200', async (t) => {
  const hub = await startHub(t, { allowLegacyGroupAuth: false });
  hub.server.group.addMember(MEMBER_A.peerId, MEMBER_A.name);
  const groupKey = groupKeyOf(hub);
  const groupId = groupIdOf(hub);
  const legacy = v1Headers({ groupKey, groupId, senderId: MEMBER_A.peerId, apiPath: '/v1/group/probe' });
  const legacyRes = await probe(hub, legacy.headers, legacy.plain);
  assert.equal(legacyRes.status, 401);
  assert.equal(legacyRes.json.error, 'legacy-auth-disabled');

  // v2 不依赖 v1：直接拿 hub CA 私钥签一张证书就能用
  const keypair = createKeypair();
  const now = Date.now();
  const cert = signCertificate(loadOrCreateHubCa(dirOf(hub)).privateKey, {
    peerId: MEMBER_A.peerId,
    pubKey: keypair.publicKeyDer,
    groupId,
    issuedAt: now,
    expiresAt: now + DEFAULT_ROTATE_AFTER_MS,
    hubEpoch: 0,
  });
  const sent = v2Headers({
    cert, privateKey: keypair.privateKey, groupId, senderId: MEMBER_A.peerId, apiPath: '/v1/group/probe',
  });
  const v2Res = await probe(hub, sent.headers, sent.plain);
  assert.equal(v2Res.status, 200, v2Res.text);
});

test('默认 allowLegacyGroupAuth=true（不传该开关时 v1 照常放行）', async (t) => {
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER_A.peerId, MEMBER_A.name);
  const sent = v1Headers({
    groupKey: groupKeyOf(hub), groupId: groupIdOf(hub), senderId: MEMBER_A.peerId, apiPath: '/v1/group/probe',
  });
  const res = await probe(hub, sent.headers, sent.plain);
  assert.equal(res.status, 200, res.text);
});

// ---------------------------------------------------------------------------
// 身份端点
// ---------------------------------------------------------------------------

test('rotate：用 v2 头鉴权，签新证书并把旧证书降为 previous（graceUntil = oldExpiresAt + 7 天）', async (t) => {
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER_A.peerId, MEMBER_A.name);
  const registered = await register(hub, MEMBER_A);
  const oldCert = registered.cert;
  const nextKeys = createKeypair();
  const groupId = groupIdOf(hub);
  const apiPath = '/v1/group/identity/rotate';
  const body = { peerId: MEMBER_A.peerId, newPubKey: nextKeys.publicKeyDer, groupId };
  const sent = v2Headers({
    cert: oldCert,
    privateKey: registered.keypair.privateKey,
    groupId,
    senderId: MEMBER_A.peerId,
    method: 'POST',
    apiPath,
    body,
  });
  const res = await sendGroup(hub.baseUrl, {
    groupKey: groupKeyOf(hub), headers: sent.headers, method: 'POST', apiPath, plain: sent.plain,
  });
  assert.equal(res.status, 200, res.text);
  assert.equal(res.json.cert.pubKey, nextKeys.publicKeyDer);
  assert.equal(res.json.cert.expiresAt, res.json.cert.issuedAt + DEFAULT_ROTATE_AFTER_MS);
  assert.equal(res.json.hubEpoch, epochOf(hub));

  const record = ledger(hub).members[MEMBER_A.peerId];
  assert.equal(record.current.pubKey, nextKeys.publicKeyDer);
  assert.equal(record.previous.sig, oldCert.sig);
  assert.equal(record.previous.graceUntil, Number(oldCert.expiresAt) + DEFAULT_GRACE_MS);

  // 新证书立刻可用（旧私钥换成了新私钥）
  const after = v2Headers({
    cert: res.json.cert, privateKey: nextKeys.privateKey, groupId, senderId: MEMBER_A.peerId, apiPath: '/v1/group/probe',
  });
  assert.equal((await probe(hub, after.headers, after.plain)).status, 200);
});

test('rotate：body.peerId 与鉴权身份不符 → 403 peer-mismatch（不能替别人换钥）', async (t) => {
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER_A.peerId, MEMBER_A.name);
  hub.server.group.addMember(MEMBER_B.peerId, MEMBER_B.name);
  const registered = await register(hub, MEMBER_A);
  const nextKeys = createKeypair();
  const groupId = groupIdOf(hub);
  const apiPath = '/v1/group/identity/rotate';
  const body = { peerId: MEMBER_B.peerId, newPubKey: nextKeys.publicKeyDer, groupId };
  const sent = v2Headers({
    cert: registered.cert,
    privateKey: registered.keypair.privateKey,
    groupId,
    senderId: MEMBER_A.peerId,
    method: 'POST',
    apiPath,
    body,
  });
  const res = await sendGroup(hub.baseUrl, {
    groupKey: groupKeyOf(hub), headers: sent.headers, method: 'POST', apiPath, plain: sent.plain,
  });
  assert.equal(res.status, 403);
  assert.equal(res.json.error, 'peer-mismatch');
});

test('rotate：从没注册过 → 409 cert-missing', async (t) => {
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER_A.peerId, MEMBER_A.name);
  const registered = await register(hub, MEMBER_A);
  // 抹掉台账（模拟丢文件），rotate 就没有 previous 可降级
  fs.rmSync(memberCertsPath(dirOf(hub)));
  const nextKeys = createKeypair();
  const groupId = groupIdOf(hub);
  const apiPath = '/v1/group/identity/rotate';
  const sent = v2Headers({
    cert: registered.cert,
    privateKey: registered.keypair.privateKey,
    groupId,
    senderId: MEMBER_A.peerId,
    method: 'POST',
    apiPath,
    body: { peerId: MEMBER_A.peerId, newPubKey: nextKeys.publicKeyDer, groupId },
  });
  const res = await sendGroup(hub.baseUrl, {
    groupKey: groupKeyOf(hub), headers: sent.headers, method: 'POST', apiPath, plain: sent.plain,
  });
  assert.equal(res.status, 409);
  assert.equal(res.json.error, 'cert-missing');
});

test('register 在成员节点上 → 404 not-leader（判据与既有 not-leader 一致）', async (t) => {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [MEMBER_A, MEMBER_B]);
  const hubStateDir = makeTempStateDir();
  seedPeers(hubStateDir, [MEMBER_A, MEMBER_B]);
  const hub = await startHub(t, { stateDir: hubStateDir });
  hub.server.group.addMember(MEMBER_A.peerId, MEMBER_A.name);
  hub.server.group.addMember(MEMBER_B.peerId, MEMBER_B.name);
  const groupKey = groupKeyOf(hub);
  const groupId = groupIdOf(hub);

  // 成员节点：group.hub 指向 hub 名字 → groupRole='member'，但手里有真 groupKey
  const member = await startServer(t, {
    stateDir,
    allowRemotePrompts: true,
    group: { enabled: true, name: 'default', hub: 'some-hub', autoJoin: false, quorum: 'none' },
  });
  writeGroupKeyFile(stateDir, {
    groupId,
    groupName: 'default',
    key: groupKey,
    epoch: epochOf(hub),
    leaderPeerId: hub.server.group.state().leaderPeerId,
    members: {
      [MEMBER_A.peerId]: { name: MEMBER_A.name, baseUrl: '' },
      [MEMBER_B.peerId]: { name: MEMBER_B.name, baseUrl: '' },
    },
    hub: { peerId: '', baseUrl: '' },
  });

  const apiPath = '/v1/group/identity/register';
  const keypair = createKeypair();
  const sent = v1Headers({
    groupKey,
    groupId,
    senderId: MEMBER_A.peerId,
    method: 'POST',
    apiPath,
    body: { peerId: MEMBER_A.peerId, pubKey: keypair.publicKeyDer, groupId },
  });
  const res = await sendGroup(member.baseUrl, {
    groupKey, headers: sent.headers, method: 'POST', apiPath, plain: sent.plain,
  });
  assert.equal(res.status, 404, res.text);
  assert.equal(res.json.error, 'not-leader');
  assert.equal(fs.existsSync(path.join(stateDir, 'group', 'member-certs.json')), false);
});

test('白名单门禁没放宽：group-v2 打到非群路径 → 401 group-auth-scope', async (t) => {
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER_A.peerId, MEMBER_A.name);
  const registered = await register(hub, MEMBER_A);
  const sent = v2Headers({
    cert: registered.cert,
    privateKey: registered.keypair.privateKey,
    groupId: groupIdOf(hub),
    senderId: MEMBER_A.peerId,
    apiPath: '/v1/peers',
  });
  const res = await sendGroup(hub.baseUrl, {
    groupKey: groupKeyOf(hub), headers: sent.headers, method: 'GET', apiPath: '/v1/peers', plain: sent.plain,
  });
  assert.equal(res.status, 401);
  assert.equal(res.json.error, 'group-auth-scope');
});

test('群关闭时两条身份端点 → 404 not-found（不暴露半成品能力）', async (t) => {
  const hub = await startHub(t, { group: { enabled: false } });
  const keypair = createKeypair();
  const apiPath = '/v1/group/identity/register';
  const sent = v1Headers({
    groupKey: randomBytes(32).toString('base64url'),
    groupId: 'whatever',
    senderId: MEMBER_A.peerId,
    method: 'POST',
    apiPath,
    body: { peerId: MEMBER_A.peerId, pubKey: keypair.publicKeyDer, groupId: 'whatever' },
  });
  const res = await sendGroup(hub.baseUrl, {
    groupKey: randomBytes(32).toString('base64url'),
    headers: sent.headers,
    method: 'POST',
    apiPath,
    plain: sent.plain,
  });
  assert.equal(res.status, 404, res.text);
  assert.equal(res.json.error, 'not-found');
});

test('第8步：v2 也走 GROUP_SELF_HEAL_PATHS 的 allowUnknownSender 分支（成员侧）', async (t) => {
  const lines = [];
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER_A.peerId, MEMBER_A.name);
  hub.server.group.addMember(MEMBER_B.peerId, MEMBER_B.name);
  const groupKey = groupKeyOf(hub);
  const groupId = groupIdOf(hub);
  const hubCa = loadOrCreateHubCa(dirOf(hub));

  // 成员节点：只认识 A，不认识 ghost；信任根是注册时记下的那份 hub CA 公钥
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [MEMBER_A]);
  const member = await startServer(t, {
    stateDir,
    allowRemotePrompts: true,
    logger: (line) => lines.push(String(line)),
    group: { enabled: true, name: 'default', hub: 'some-hub', autoJoin: false, quorum: 'none' },
  });
  writeGroupKeyFile(stateDir, {
    groupId,
    groupName: 'default',
    key: groupKey,
    epoch: epochOf(hub),
    leaderPeerId: hub.server.group.state().leaderPeerId,
    members: { [MEMBER_A.peerId]: { name: MEMBER_A.name, baseUrl: '' } },
    hub: { peerId: '', baseUrl: '' },
  });
  const identityDir = path.join(stateDir, 'group');
  fs.mkdirSync(identityDir, { recursive: true });
  fs.writeFileSync(
    path.join(identityDir, 'trusted-hub-ca.json'),
    JSON.stringify({ hubCaPubKey: hubCa.pubKey, hubEpoch: epochOf(hub), at: Date.now(), source: 'register' }),
    { mode: 0o600 },
  );

  const ghostKeys = createKeypair();
  const now = Date.now();
  const ghostCert = signCertificate(hubCa.privateKey, {
    peerId: 'peer-v2-ghost',
    pubKey: ghostKeys.publicKeyDer,
    groupId,
    issuedAt: now,
    expiresAt: now + DEFAULT_ROTATE_AFTER_MS,
    hubEpoch: 0,
  });
  const call = async (apiPath) => {
    const sent = v2Headers({
      cert: ghostCert, privateKey: ghostKeys.privateKey, groupId, senderId: 'peer-v2-ghost', apiPath,
    });
    return sendGroup(member.baseUrl, {
      groupKey, headers: sent.headers, method: 'GET', apiPath, plain: sent.plain,
    });
  };

  // 非自愈路径：直接 not-a-member，且不记 self-heal 行
  const probeRes = await call('/v1/group/probe');
  assert.equal(probeRes.status, 401, probeRes.text);
  assert.equal(probeRes.json.error, 'not-a-member');
  assert.equal(lines.some((line) => line.includes('self-heal refused')), false);

  // 自愈路径：允许未知发送者进来，但权威快照里没有它 → 仍然 not-a-member（并留下拒绝行）
  const leaderRes = await call('/v1/group/leader');
  assert.equal(leaderRes.status, 401, leaderRes.text);
  assert.equal(leaderRes.json.error, 'not-a-member');
  assert.equal(
    lines.some((line) => line === '[group] self-heal refused peer=peer-v2-'),
    true,
    `self-heal 分支必须被执行到：${lines.filter((line) => line.includes('self-heal')).join('|')}`,
  );
});

test('双模式端点 /v1/group/post：v2 头等价于 v1 头（作者仍取签名身份）', async (t) => {
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER_A.peerId, MEMBER_A.name);
  const registered = await register(hub, MEMBER_A);
  const groupId = groupIdOf(hub);
  const apiPath = '/v1/group/post';
  const body = {
    kind: 'chat',
    text: 'hello via group-v2',
    // 刻意伪造：v1 与 v2 都必须忽略 body 里的作者
    from: { peerId: MEMBER_B.peerId, name: 'forged' },
    peerId: MEMBER_B.peerId,
  };
  const sent = v2Headers({
    cert: registered.cert,
    privateKey: registered.keypair.privateKey,
    groupId,
    senderId: MEMBER_A.peerId,
    method: 'POST',
    apiPath,
    body,
  });
  const res = await sendGroup(hub.baseUrl, {
    groupKey: groupKeyOf(hub), headers: sent.headers, method: 'POST', apiPath, plain: sent.plain,
  });
  assert.equal(res.status, 201, res.text);
  const [message] = hub.server.group.history({ sinceSeq: 0 });
  assert.equal(message.text, 'hello via group-v2');
  assert.equal(message.from.peerId, MEMBER_A.peerId, '作者 = 证书身份，不取 body');
});

// ---------------------------------------------------------------------------
// §8.1 r2：轮换即刻吊销旧钥（九步之后插入的 8.5 步台账检查）
// ---------------------------------------------------------------------------

test('8.5 步：台账里有该 peerId 但证书不是 current → 401 cert-revoked', async (t) => {
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER_A.peerId, MEMBER_A.name);
  await register(hub, MEMBER_A);
  // 同一 peerId、另一把公钥、同一个 hub CA 签、且没过期：前八步全过，只有 8.5 能拦它
  const stray = createKeypair();
  const now = Date.now();
  const cert = craftCert(hub, {
    peerId: MEMBER_A.peerId,
    pubKey: stray.publicKeyDer,
    issuedAt: now,
    expiresAt: now + DEFAULT_ROTATE_AFTER_MS,
  });
  const sent = v2Headers({
    cert,
    privateKey: stray.privateKey,
    groupId: groupIdOf(hub),
    senderId: MEMBER_A.peerId,
    apiPath: '/v1/group/probe',
  });
  const res = await probe(hub, sent.headers, sent.plain);
  assert.equal(res.status, 401, res.text);
  assert.equal(res.json.error, 'cert-revoked');
});

test('8.5 步：台账里没有该 peerId → 跳过检查（首注册成员立刻可用）', async (t) => {
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER_A.peerId, MEMBER_A.name);
  // 完全没注册过：连台账文件都不存在
  assert.equal(fs.existsSync(memberCertsPath(dirOf(hub))), false);
  const keypair = createKeypair();
  const now = Date.now();
  const cert = craftCert(hub, {
    peerId: MEMBER_A.peerId,
    pubKey: keypair.publicKeyDer,
    issuedAt: now,
    expiresAt: now + DEFAULT_ROTATE_AFTER_MS,
  });
  const sent = v2Headers({
    cert,
    privateKey: keypair.privateKey,
    groupId: groupIdOf(hub),
    senderId: MEMBER_A.peerId,
    apiPath: '/v1/group/probe',
  });
  const res = await probe(hub, sent.headers, sent.plain);
  assert.equal(res.status, 200, res.text);
});

test('8.1 r2：rotate 之后旧证书立刻 401 cert-revoked，新证书同一毫秒窗口内立刻可用', async (t) => {
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER_A.peerId, MEMBER_A.name);
  const registered = await register(hub, MEMBER_A);
  const oldCert = registered.cert;
  const nextKeys = createKeypair();
  const groupId = groupIdOf(hub);
  const apiPath = '/v1/group/identity/rotate';
  const body = { peerId: MEMBER_A.peerId, newPubKey: nextKeys.publicKeyDer, groupId };

  const before = Date.now();
  const rotateSent = v2Headers({
    cert: oldCert,
    privateKey: registered.keypair.privateKey,
    groupId,
    senderId: MEMBER_A.peerId,
    method: 'POST',
    apiPath,
    body,
  });
  const rotated = await sendGroup(hub.baseUrl, {
    groupKey: groupKeyOf(hub), headers: rotateSent.headers, method: 'POST', apiPath, plain: rotateSent.plain,
  });
  assert.equal(rotated.status, 200, rotated.text);

  // 旧证书：不发一分钱宽限，立刻失效（宽限只管「证书自身过期」）
  const oldSent = v2Headers({
    cert: oldCert,
    privateKey: registered.keypair.privateKey,
    groupId,
    senderId: MEMBER_A.peerId,
    apiPath: '/v1/group/probe',
  });
  const oldRes = await probe(hub, oldSent.headers, oldSent.plain);
  assert.equal(oldRes.status, 401, oldRes.text);
  assert.equal(oldRes.json.error, 'cert-revoked');

  // previous 是审计记录、不是备选凭证：台账里带 revokedAt，且仍在 graceUntil 之内也不接受
  const record = ledger(hub).members[MEMBER_A.peerId];
  assert.equal(record.previous.sig, oldCert.sig);
  assert.equal(record.previous.graceUntil, Number(oldCert.expiresAt) + DEFAULT_GRACE_MS);
  assert.ok(record.previous.revokedAt >= before && record.previous.revokedAt <= Date.now());

  // 新证书立刻可用
  const newSent = v2Headers({
    cert: rotated.json.cert,
    privateKey: nextKeys.privateKey,
    groupId,
    senderId: MEMBER_A.peerId,
    apiPath: '/v1/group/probe',
  });
  const newRes = await probe(hub, newSent.headers, newSent.plain);
  assert.equal(newRes.status, 200, newRes.text);
});

// ---------------------------------------------------------------------------
// §8.2 r2：注册要求 per-peer 签名（收窄 TOFU）
// ---------------------------------------------------------------------------

test('§8.2：已配对的 peerId 缺 pairProof → 403 pair-proof-required（且不落台账）', async (t) => {
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER_A.peerId, MEMBER_A.name);
  const res = await register(hub, MEMBER_A, { omitProof: true });
  assert.equal(res.status, 403, res.text);
  assert.equal(res.json.error, 'pair-proof-required');
  assert.equal(fs.existsSync(memberCertsPath(dirOf(hub))), false, '拒绝时不签发、不落盘');
});

test('§8.2：pairProof 验不过 → 401 bad-pair-proof（签名错 / 时钟偏 / nonce 重放）', async (t) => {
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER_A.peerId, MEMBER_A.name);
  const groupId = groupIdOf(hub);
  const keypair = createKeypair();
  const proofBody = { peerId: MEMBER_A.peerId, pubKey: keypair.publicKeyDer, groupId };

  const badSig = await register(hub, { ...MEMBER_A, keypair }, {
    proof: pairProofFor(MEMBER_A, proofBody, { sig: 'not-a-real-signature' }),
  });
  assert.equal(badSig.status, 401, badSig.text);
  assert.equal(badSig.json.error, 'bad-pair-proof');

  const skewed = await register(hub, { ...MEMBER_A, keypair }, {
    proof: pairProofFor(MEMBER_A, proofBody, { ts: Date.now() - 120_000 }),
  });
  assert.equal(skewed.status, 401, skewed.text);
  assert.equal(skewed.json.error, 'bad-pair-proof');

  // 同一个 nonce 用两次：第一次签发成功，第二次判重放（pairProof 检查在 cert-exists 之前）
  const once = pairProofFor(MEMBER_A, proofBody);
  const first = await register(hub, { ...MEMBER_A, keypair }, { proof: once });
  assert.equal(first.status, 200, first.text);
  assert.equal(ledger(hub).members[MEMBER_A.peerId].current.sig, first.json.cert.sig, '签名对 → 台账落盘');
  const replay = await register(hub, { ...MEMBER_A, keypair }, { proof: once });
  assert.equal(replay.status, 401, replay.text);
  assert.equal(replay.json.error, 'bad-pair-proof');
});

test('§8.2：未配对成员（靠群名入群）不带 pairProof → 200，只留一行 tofu 审计（前 8 位）', async (t) => {
  const lines = [];
  const hub = await startHub(t, { logger: (line) => lines.push(String(line)) });
  hub.server.group.addMember(UNPAIRED.peerId, UNPAIRED.name);
  const registered = await register(hub, UNPAIRED, { omitProof: true });
  assert.equal(registered.status, 200, registered.text);

  const registerLines = lines.filter((line) => line.startsWith('[group] identity register peer='));
  assert.equal(registerLines.length, 1, `恰好一行：${registerLines.join('|')}`);
  assert.equal(registerLines[0], `[group] identity register peer=${UNPAIRED.peerId.slice(0, 8)} tofu`);
  // 隐私铁律：行里只有前 8 位，没有完整 peerId
  assert.equal(registerLines[0].includes(UNPAIRED.peerId), false);

  // 台账落盘 + 该证书立刻可用（8.5 步按 current 放行）
  assert.equal(ledger(hub).members[UNPAIRED.peerId].current.sig, registered.json.cert.sig);
  const sent = v2Headers({
    cert: registered.json.cert,
    privateKey: registered.keypair.privateKey,
    groupId: groupIdOf(hub),
    senderId: UNPAIRED.peerId,
    apiPath: '/v1/group/probe',
  });
  assert.equal((await probe(hub, sent.headers, sent.plain)).status, 200);
});

// ---------------------------------------------------------------------------
// §8.3：服务端出站接线（identity 透传 + 60 秒缓存）
// ---------------------------------------------------------------------------

/** hub 先 claim 成 leader（此刻成员表为空 → 不产生任何出站请求），再放进一个带地址的成员 */
async function startLeaderHub(t, overrides = {}) {
  const hub = await startHub(t, overrides);
  const claim = await hub.server.group.claim();
  assert.equal(claim.ok, true, JSON.stringify(claim));
  hub.server.group.addMember(MEMBER_A.peerId, MEMBER_A.name);
  return hub;
}

/** 拦截出站 fetch 并记录请求头：这些用例只验「线上带什么头」，绝不真出网 */
async function captureOutbound(fn) {
  const original = globalThis.fetch;
  const seen = [];
  globalThis.fetch = async (url, init) => {
    seen.push({ url: String(url), headers: { ...(init?.headers ?? {}) } });
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };
  try {
    await fn();
  } finally {
    globalThis.fetch = original;
  }
  return seen;
}

test('§8.3：本地身份可用 → 出站带 v2 头 + X-Peer-Cert，且 60 秒 TTL 内只读一次身份', async (t) => {
  let loads = 0;
  let identity = null;
  const hub = await startLeaderHub(t, {
    groupIdentityLoader: () => {
      loads += 1;
      return identity ?? { ok: false, code: 'identity-missing' };
    },
  });
  const groupId = groupIdOf(hub);
  const keys = createKeypair();
  const now = Date.now();
  identity = {
    ok: true,
    cert: {
      peerId: hub.server.store.instanceId,
      pubKey: keys.publicKeyDer,
      groupId,
      issuedAt: now,
      expiresAt: now + DEFAULT_ROTATE_AFTER_MS,
      hubEpoch: 0,
      alg: 'ed25519',
      sig: 'stub',
    },
    keypair: keys,
    trustedHubCa: { hubCaPubKey: 'stub', hubEpoch: 0, at: now, source: 'register' },
  };

  const seen = await captureOutbound(async () => {
    assert.equal((await hub.server.group.heartbeat()).ok, true);
    assert.equal((await hub.server.group.heartbeat()).ok, true);
  });
  assert.equal(loads, 1, '同一 TTL 窗口内只解封私钥 + 验证书一次');
  assert.ok(seen.length >= 2, `两次心跳至少两条出站请求，实际 ${seen.length}`);
  for (const req of seen) {
    assert.equal(req.headers[GROUP_AUTH_HEADER], AUTH_V2);
    assert.equal(typeof req.headers[CERT_HEADER], 'string');
    assert.ok(req.headers[CERT_HEADER].length > 0);
  }
});

test('§8.3：本地身份读不到 → 出站仍是 v1 头（无 X-Peer-Cert），且不报错', async (t) => {
  let loads = 0;
  const hub = await startLeaderHub(t, {
    groupIdentityLoader: () => {
      loads += 1;
      return { ok: false, code: 'identity-unavailable' };
    },
  });
  const seen = await captureOutbound(async () => {
    assert.equal((await hub.server.group.heartbeat()).ok, true);
  });
  assert.equal(loads, 1);
  assert.ok(seen.length >= 1, `至少要有一条出站请求，实际 ${seen.length}`);
  for (const req of seen) {
    assert.equal(req.headers[GROUP_AUTH_HEADER], GROUP_AUTH_VALUE);
    assert.equal(req.headers[CERT_HEADER], undefined);
    assert.equal(req.headers['x-peer-cert'], undefined);
  }
});

test('§8.3：TTL 可注入 —— 窗口过后必须重读身份（轮换/吊销才能及时生效）', async (t) => {
  let loads = 0;
  const hub = await startLeaderHub(t, {
    groupIdentityCacheMs: 5,
    // 读不到 = 否定结果，走的是它自己的短窗口（默认 5 秒），这里一起压到 5ms
    groupIdentityNegativeCacheMs: 5,
    groupIdentityLoader: () => {
      loads += 1;
      return { ok: false, code: 'identity-missing' };
    },
  });
  await captureOutbound(async () => { await hub.server.group.heartbeat(); });
  assert.equal(loads, 1);
  await sleep(20);
  await captureOutbound(async () => { await hub.server.group.heartbeat(); });
  assert.equal(loads, 2, '窗口过后重新读一次');
});
