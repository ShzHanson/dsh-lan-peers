/**
 * 群身份 P2（0.9.0-α）· **端到端**验收（真端口 / 真 HTTP / 真落盘 stateDir）
 *
 * 与 group-v2-auth.test.mjs（服务端单测：手搓头 + 手搓信封）的分工：
 *   这里一条头都不手搓 —— 成员侧一律走 **产品里的客户端函数**
 *   （registerGroupIdentity / rotateGroupIdentity / groupCall({identity}) / groupCallV2），
 *   私钥与证书一律落真 stateDir 再用 loadGroupIdentity 读回来。
 *   两个真实 server 实例（hub + 一个成员）各自监听 127.0.0.1 的随机端口。
 *
 * 线格式契约（唯一权威）：internal-docs/group-v2-wire-contract.md
 *   §1 头分流 / §2 v2 头集合 / §3 九步 / §8.1 吊销 / §8.2 pairProof / §8.3 接线
 *
 * 每条断言都指向契约里的一句话；日志断言只出现 peerId **前 8 位**（日志隐私铁律）。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {
  groupCall,
  groupCallV2,
  loadGroupIdentity,
  memberCertPath,
  probeGroupPeer,
  readMemberCertFile,
  readTrustedHubCaFile,
  registerGroupIdentity,
  rotateGroupIdentity,
  trustedHubCaPath,
  writeGroupKeyFile,
  writeMemberCertFile,
  writeTrustedHubCaFile,
} from '../../lib/group-client.mjs';
import {
  DEFAULT_GRACE_MS,
  createKeypair,
  saveKeypair,
  signCertificate,
} from '../../lib/group-identity.mjs';
import {
  issueMemberCertificate,
  ledgerAcceptsCertificate,
  loadOrCreateHubCa,
  readMemberCerts,
} from '../../lib/group-ca.mjs';
import { makeTempStateDir, peerFixture, seedPeers, startServer } from './helpers.mjs';

const DAY = 24 * 60 * 60 * 1000;

/** 本文件内部的配对密钥（hub 侧 inboundSecret 与成员侧 secret 用同一把，见 peerFixture） */
const PAIR_SECRET = 'e2e-shared-pair-secret';

const MEMBER_ID = 'peer-e2e-member-0001';
const ATK_ID = 'peer-e2e-attacker-01';
const GHOST_GRACE_ID = 'peer-e2e-ghost-grace';
const GHOST_EXPIRED_ID = 'peer-e2e-ghost-expired';
const PROOF_NONE_ID = 'peer-e2e-proof-none';
const PROOF_BAD_ID = 'peer-e2e-proof-bad';
const PROOF_OK_ID = 'peer-e2e-proof-ok';

/** 日志口径：契约 §8 的日志只留前 8 位 */
const shortOf = (peerId) => String(peerId ?? '').slice(0, 8);
const MEMBER_SHORT = shortOf(MEMBER_ID);

/** 群级测试基线：quorum:none 是既有群测试的惯例（假 peerId 成员没法 ack） */
const GROUP_BASE = { enabled: true, name: 'default', autoJoin: false, retentionDays: 7, quorum: 'none' };

const pairedFixture = (peerId, extra = {}) => peerFixture(peerId, {
  secret: PAIR_SECRET,
  inboundSecret: PAIR_SECRET,
  ...extra,
});

/** hub 实例：真端口 + 真 stateDir + 把日志收进数组（断言日志用） */
async function startHub(t, options = {}) {
  const stateDir = options.stateDir ?? makeTempStateDir();
  seedPeers(stateDir, options.peers ?? [pairedFixture(MEMBER_ID)]);
  const lines = [];
  const started = await startServer(t, {
    stateDir,
    allowRemotePrompts: true,
    ...(options.server ?? {}),
    logger: (line) => lines.push(String(line)),
    group: { ...GROUP_BASE, ...(options.group ?? {}) },
  });
  return { ...started, lines, peerId: started.server.store.instanceId };
}

/**
 * 成员实例：真端口 + 真 stateDir。
 * 私钥先落盘（<stateDir>/group/member-key.json，0600 设备绑定），群密钥用 writeGroupKeyFile
 * 抄一份 hub 的 —— 这样成员侧 identity/群上下文全部来自**磁盘**，不是用例里的内存变量。
 */
async function startMember(t, hub, options = {}) {
  const stateDir = makeTempStateDir();
  const keypair = createKeypair();
  saveKeypair(stateDir, keypair, { peerId: MEMBER_ID });
  const ctx = hubGroupContext(hub);
  writeGroupKeyFile(stateDir, {
    groupId: ctx.groupId,
    keyVersion: ctx.epoch,
    key: ctx.groupKey,
    name: 'default',
    hub: { peerId: hub.peerId, name: 'hub', baseUrl: hub.baseUrl },
    members: {
      [hub.peerId]: { name: 'hub', baseUrl: hub.baseUrl },
      [MEMBER_ID]: { name: 'member', baseUrl: '' },
    },
  });
  seedPeers(stateDir, [pairedFixture(hub.peerId, { name: 'hub', baseUrl: hub.baseUrl })]);
  const lines = [];
  const started = await startServer(t, {
    stateDir,
    allowRemotePrompts: true,
    logger: (line) => lines.push(String(line)),
    ...(options.server ?? {}),
    // 拉取间隔拉长：这条用例集只关心请求/响应，不想让后台轮询往日志里灌噪声
    group: { ...GROUP_BASE, hub: hub.peerId, replicaPullMs: 60_000 },
  });
  return {
    ...started, lines, keypair, peerId: MEMBER_ID, groupId: ctx.groupId, groupKey: ctx.groupKey, epoch: ctx.epoch,
  };
}

/** hub 侧的群上下文（groupKey 只有 includeKey 才下发） */
function hubGroupContext(hub) {
  const state = hub.server.group.state({ includeKey: true });
  return { groupId: state.groupId, groupKey: state.groupKey, epoch: state.epoch ?? 0 };
}

/** 契约 §5：用 v1 头 + pairProof 注册，证书落成员盘（registerGroupIdentity 自己写两份文件） */
async function registerMember(hub, member) {
  const registered = await registerGroupIdentity({
    stateDir: member.stateDir,
    baseUrl: hub.baseUrl,
    groupKey: member.groupKey,
    groupId: member.groupId,
    peerId: member.peerId,
    pairSecret: PAIR_SECRET,
  });
  assert.equal(registered.ok, true, '契约 §5：register 必须返回证书（拿不到时 groupCall 会抛）');
  return registered;
}

/** 统一的"HTTP 请求应该被拒"取值器：groupCall/groupCallV2 用 error.status/error.code 表达 */
const rejectionOf = (promise) => promise.then(() => null, (error) => error);

// ---------------------------------------------------------------------------
// 1 注册链路
// ---------------------------------------------------------------------------

test('E2E1 注册链路：v1 头 + pairProof → 200，member-cert.json 与 trusted-hub-ca.json 落盘且能读回', async (t) => {
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER_ID, 'member');
  const member = await startMember(t, hub);

  const registered = await registerMember(hub, member);
  assert.equal(registered.cert.peerId, MEMBER_ID, '契约 §5：签回来的证书属于申请者本人');
  assert.equal(registered.cert.groupId, member.groupId, '契约 §5：证书绑定本群');

  // 落盘：<stateDir>/group/member-cert.json + <stateDir>/group/trusted-hub-ca.json（契约 §4）
  assert.equal(fs.existsSync(memberCertPath(member.stateDir)), true, '契约 §4：成员证书必须落盘');
  assert.equal(fs.existsSync(trustedHubCaPath(member.stateDir)), true, '契约 §4：信任根必须落盘');

  const certRead = readMemberCertFile(member.stateDir);
  assert.equal(certRead.ok, true, '契约 §4：落盘的 member-cert.json 必须能被产品读回');
  assert.equal(certRead.cert.sig, registered.cert.sig, '读回的必须是 hub 刚签的那份');

  const trustRead = readTrustedHubCaFile(member.stateDir);
  assert.equal(trustRead.ok, true, '契约 §4：落盘的 trusted-hub-ca.json 必须能被产品读回');
  assert.equal(trustRead.trust.hubCaPubKey, loadOrCreateHubCa(hub.stateDir).pubKey, '契约 §4：信任根 = hub CA 公钥');
  assert.equal(trustRead.trust.source, 'register', '契约 §4：来源记 register');

  // hub 台账：{v, members:{<peerId>:{current, ...}}}（契约 §4/§8.1）
  const ledger = readMemberCerts(hub.stateDir);
  assert.equal(ledger.members[MEMBER_ID]?.current?.sig, registered.cert.sig, '契约 §4：hub 台账 current = 刚签的证书');

  // 一条龙：证书 + 配对私钥 + 信任根齐备 → loadGroupIdentity ok（契约 §8.3 的入参形状）
  const identity = loadGroupIdentity(member.stateDir);
  assert.equal(identity.ok, true, '契约 §8.3：注册后成员侧 identity 必须可用');
});

// ---------------------------------------------------------------------------
// 2 v2 正路
// ---------------------------------------------------------------------------

test('E2E2 v2 正路：groupCall({identity}) 打 probe → 200，hub 日志 mode=group-v2 且本次请求零 legacy 告警', async (t) => {
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER_ID, 'member');
  const member = await startMember(t, hub);
  await registerMember(hub, member);

  const identity = loadGroupIdentity(member.stateDir);
  assert.equal(identity.ok, true, '契约 §8.3：identity?.ok === true 才走 v2');

  // 注册本身走 v1（契约 §5 的鸡生蛋），所以只数「这次 probe 之后新增」的行
  const mark = hub.lines.length;
  const probed = await groupCall({
    baseUrl: hub.baseUrl,
    groupKey: member.groupKey,
    groupId: member.groupId,
    senderId: member.peerId,
    method: 'GET',
    apiPath: '/v1/group/probe',
    identity,
  });
  assert.equal(probed.ok, true, '契约 §3：九步全过才 200');
  assert.equal(probed.groupId, member.groupId, '响应来自本群');

  const fresh = hub.lines.slice(mark);
  const v2Lines = fresh.filter((line) => line.startsWith(`[group] probe from=${MEMBER_SHORT} mode=group-v2 `));
  assert.equal(v2Lines.length, 1, '契约 §1：v2 头必须被分流成 group-v2（日志恰好一行 probe）');
  assert.equal(
    fresh.filter((line) => line.startsWith(`[group] probe from=${MEMBER_SHORT} mode=group `)).length,
    0,
    '契约 §1：v2 请求绝不能被当成 v1',
  );
  assert.equal(
    fresh.filter((line) => line.includes('[group] legacy-auth ')).length,
    0,
    '契约 §1：走 v2 的请求不得产生 legacy 告警行',
  );
});

// ---------------------------------------------------------------------------
// 3 legacy 告警
// ---------------------------------------------------------------------------

test('E2E3 legacy 告警：不带 identity 打 probe → 200，hub 恰好一行 legacy-auth 且只含 peerId 前 8 位', async (t) => {
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER_ID, 'member');
  const member = await startMember(t, hub);
  // 刻意不注册：这条只验 v1 通道（契约 §1/§6，allowLegacyGroupAuth 默认 true）

  const probed = await probeGroupPeer({
    baseUrl: hub.baseUrl,
    groupKey: member.groupKey,
    groupId: member.groupId,
    senderId: member.peerId,
  });
  assert.equal(probed.ok, true, '契约 §6：v1 头默认仍然放行');

  const legacyLines = hub.lines.filter((line) => line.includes('[group] legacy-auth '));
  assert.equal(legacyLines.length, 1, '契约 §1：v1 群请求恰好记一行 legacy 告警');
  assert.equal(legacyLines[0], `[group] legacy-auth peer=${MEMBER_SHORT}`, '契约 §1：告警行只留 peerId 前 8 位');
  assert.equal(legacyLines[0].includes(MEMBER_ID), false, '日志隐私铁律：整行不得出现完整 peerId');
});

// ---------------------------------------------------------------------------
// 4 冒充三连
// ---------------------------------------------------------------------------

test('E2E4 冒充三连：只有 groupKey 的攻击者 —— (a) v1 冒充 200（已知限制）(b) v2 用自己的证书 401 cert-peer-mismatch (c) v2 用受害者证书 + 自己私钥 401 bad-signature', async (t) => {
  const hub = await startHub(t, { peers: [pairedFixture(MEMBER_ID), pairedFixture(ATK_ID)] });
  hub.server.group.addMember(MEMBER_ID, 'victim');
  hub.server.group.addMember(ATK_ID, 'attacker');
  const member = await startMember(t, hub);
  const victim = await registerMember(hub, member);

  // 攻击者：手里有一份**真证书**（hub CA 签的，覆盖它自己的 peerId）和自己的私钥，
  // 另外还有一把群密钥（groupKey 是群成员都能拿到的），就是没有受害者的私钥。
  const ca = loadOrCreateHubCa(hub.stateDir);
  assert.equal(ca.ok, true);
  const attackerKeypair = createKeypair();
  const attackerIssued = issueMemberCertificate({
    stateDir: hub.stateDir,
    caPrivateKey: ca.privateKey,
    peerId: ATK_ID,
    pubKey: attackerKeypair.publicKeyDer,
    groupId: member.groupId,
    hubEpoch: 0,
    now: Date.now(),
  });
  assert.equal(attackerIssued.ok, true, '攻击者自己的证书必须是真的（否则这条测的就不是冒充）');

  // a) v1 头 + 受害者的 peerId：过渡期已知限制，如实断言 200（契约 §6：v1 行为一字不变）
  const a = await probeGroupPeer({
    baseUrl: hub.baseUrl,
    groupKey: member.groupKey,
    groupId: member.groupId,
    senderId: MEMBER_ID,
  });
  assert.equal(a.ok, true, '已知限制（契约 §6/§8.2）：握有 groupKey 就能用别人的 peerId 走 v1 —— 本阶段不修');

  // b) v2 头 + 受害者的 peerId + 攻击者自己的证书 → 第 4 步 cert-peer-mismatch（契约 §3）
  const b = await rejectionOf(groupCallV2({
    baseUrl: hub.baseUrl,
    groupKey: member.groupKey,
    groupId: member.groupId,
    senderId: MEMBER_ID,
    cert: attackerIssued.cert,
    privateKey: attackerKeypair.privateKey,
    method: 'GET',
    apiPath: '/v1/group/probe',
  }));
  assert.equal(b?.status, 401, '契约 §3 第 4 步：证书的 peerId 与 X-Peer-Id 不一致必须 401');
  assert.equal(b?.code, 'cert-peer-mismatch', '契约 §3 第 4 步：错误码固定 cert-peer-mismatch');

  // c) v2 头 + 受害者证书（公开可拿）+ 攻击者自己的私钥签名 → 第 7 步 bad-signature（契约 §3）
  const c = await rejectionOf(groupCallV2({
    baseUrl: hub.baseUrl,
    groupKey: member.groupKey,
    groupId: member.groupId,
    senderId: MEMBER_ID,
    cert: victim.cert,
    privateKey: attackerKeypair.privateKey,
    method: 'GET',
    apiPath: '/v1/group/probe',
  }));
  assert.equal(c?.status, 401, '契约 §3 第 7 步：公钥取自证书，冒充者的私钥签不过');
  assert.equal(c?.code, 'bad-signature', '契约 §3 第 7 步：验签失败固定 bad-signature');
});

// ---------------------------------------------------------------------------
// 5 rotate 即刻吊销
// ---------------------------------------------------------------------------

test('E2E5 rotate 即刻吊销：旧证书 401 cert-revoked，新证书同一时间窗内立刻 200', async (t) => {
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER_ID, 'member');
  const member = await startMember(t, hub);
  const registered = await registerMember(hub, member);

  const oldCert = registered.cert;
  const oldKeypair = member.keypair;

  // 基线：rotate 之前旧证书确实能用（否则「吊销」这条断言没有意义）
  const before = await groupCallV2({
    baseUrl: hub.baseUrl,
    groupKey: member.groupKey,
    groupId: member.groupId,
    senderId: member.peerId,
    cert: oldCert,
    privateKey: oldKeypair.privateKey,
    method: 'GET',
    apiPath: '/v1/group/probe',
  });
  assert.equal(before.ok, true, '基线：rotate 前旧证书 v2 请求应 200');

  // 可控 now：needsRotation 的门槛是 issuedAt+30d，实盘时间不可能等到；
  // 这里只影响「该不该轮换」的判定，线上请求的 ts 仍是真时钟（服务端 ±60s 窗口照旧生效）。
  const rotated = await rotateGroupIdentity({
    stateDir: member.stateDir,
    baseUrl: hub.baseUrl,
    groupKey: member.groupKey,
    groupId: member.groupId,
    peerId: member.peerId,
    newKeypair: createKeypair(),
    identity: loadGroupIdentity(member.stateDir),
    now: Number(oldCert.expiresAt),
  });
  assert.equal(rotated.ok, true, '契约 §5：rotate 用旧证书 + 旧私钥鉴权并返回新证书');
  assert.notEqual(rotated.cert.sig, oldCert.sig, '契约 §5：rotate 必须签出新证书');

  // 契约 §8.1：previous 是审计记录、不是备选凭证 —— 旧证书**立刻**失效
  const ledger = readMemberCerts(hub.stateDir);
  assert.equal(ledger.members[MEMBER_ID].current.sig, rotated.cert.sig, '契约 §8.1：台账 current 换成新证书');
  assert.equal(ledger.members[MEMBER_ID].previous.sig, oldCert.sig, '契约 §8.1：旧证书降为 previous');
  assert.ok(Number(ledger.members[MEMBER_ID].previous.revokedAt) > 0, '契约 §8.1：previous 必须记 revokedAt');
  assert.equal(ledgerAcceptsCertificate(hub.stateDir, MEMBER_ID, oldCert).ok, false, '契约 §8.1：台账只认 current');

  const stale = await rejectionOf(groupCallV2({
    baseUrl: hub.baseUrl,
    groupKey: member.groupKey,
    groupId: member.groupId,
    senderId: member.peerId,
    cert: oldCert,
    privateKey: oldKeypair.privateKey,
    method: 'GET',
    apiPath: '/v1/group/probe',
  }));
  assert.equal(stale?.status, 401, '契约 §8.1：旧证书立刻失效');
  assert.equal(stale?.code, 'cert-revoked', '契约 §8.1：吊销用独立错误码 cert-revoked');

  // 同一个时间窗内，新身份立刻可用（没有 sleep：靠台账而不是靠等）
  const freshIdentity = loadGroupIdentity(member.stateDir);
  assert.equal(freshIdentity.ok, true, '契约 §5：rotate 先落新私钥再落新证书，读回来必须配对');
  const renewed = await groupCall({
    baseUrl: hub.baseUrl,
    groupKey: member.groupKey,
    groupId: member.groupId,
    senderId: member.peerId,
    method: 'GET',
    apiPath: '/v1/group/probe',
    identity: freshIdentity,
  });
  assert.equal(renewed.ok, true, '契约 §8.1：新证书必须立刻可用');
});

// ---------------------------------------------------------------------------
// 6 宽限边界
// ---------------------------------------------------------------------------

test('E2E6 宽限边界：台账无记录的 peerId，超期 1 天 → 200（宽限内），超期 8 天 → 401 cert-expired', async (t) => {
  // 契约 §8.1 的 8.5 步会先按台账拦「旧钥」，所以这里必须用**台账里没有记录**的 peerId，
  // 否则测到的是 cert-revoked 而不是 cert-expired。
  const hub = await startHub(t);
  hub.server.group.addMember(GHOST_GRACE_ID, 'ghost-grace');
  hub.server.group.addMember(GHOST_EXPIRED_ID, 'ghost-expired');
  const member = await startMember(t, hub);

  assert.equal(DEFAULT_GRACE_MS, 7 * DAY, '契约 §3 第 3 步：宽限是 7 天（本用例的 1 天 / 8 天就是照它取的边界）');
  const ca = loadOrCreateHubCa(hub.stateDir);
  assert.equal(ca.ok, true);
  const now = Date.now();

  const craft = (peerId, issuedAt, expiresAt) => {
    const keypair = createKeypair();
    const cert = signCertificate(ca.privateKey, {
      peerId,
      pubKey: keypair.publicKeyDer,
      groupId: member.groupId,
      issuedAt,
      expiresAt,
      hubEpoch: 0,
    });
    return { cert, keypair };
  };
  // 超期 1 天：在 7 天宽限内
  const graced = craft(GHOST_GRACE_ID, now - 31 * DAY, now - 1 * DAY);
  // 超期 8 天：超出宽限
  const expired = craft(GHOST_EXPIRED_ID, now - 38 * DAY, now - 8 * DAY);

  assert.equal(
    ledgerAcceptsCertificate(hub.stateDir, GHOST_GRACE_ID, graced.cert).checked,
    false,
    '契约 §8.1：台账没有该 peerId 的记录 → 8.5 步跳过（否则这里测不到宽限边界）',
  );

  const inGrace = await groupCallV2({
    baseUrl: hub.baseUrl,
    groupKey: member.groupKey,
    groupId: member.groupId,
    senderId: GHOST_GRACE_ID,
    cert: graced.cert,
    privateKey: graced.keypair.privateKey,
    method: 'GET',
    apiPath: '/v1/group/probe',
  });
  assert.equal(inGrace.ok, true, '契约 §3 第 3 步：过期 1 天仍在 7 天宽限内 → 200');

  const tooLate = await rejectionOf(groupCallV2({
    baseUrl: hub.baseUrl,
    groupKey: member.groupKey,
    groupId: member.groupId,
    senderId: GHOST_EXPIRED_ID,
    cert: expired.cert,
    privateKey: expired.keypair.privateKey,
    method: 'GET',
    apiPath: '/v1/group/probe',
  }));
  assert.equal(tooLate?.status, 401, '契约 §3 第 3 步：过期超宽限必须 401');
  assert.equal(tooLate?.code, 'cert-expired', '契约 §3 第 3 步：过期超宽限用 cert-expired（不复用 untrusted-ca）');
});

// ---------------------------------------------------------------------------
// 7 pairProof 三态
// ---------------------------------------------------------------------------

test('E2E7 pairProof 三态：缺 → 403 pair-proof-required，sig 错 → 401 bad-pair-proof，对 → 200 且台账写入', async (t) => {
  const hub = await startHub(t, { peers: [PROOF_NONE_ID, PROOF_BAD_ID, PROOF_OK_ID].map((id) => pairedFixture(id)) });
  for (const id of [PROOF_NONE_ID, PROOF_BAD_ID, PROOF_OK_ID]) hub.server.group.addMember(id, 'member');
  const member = await startMember(t, hub);
  const register = (peerId, extra = {}) => registerGroupIdentity({
    baseUrl: hub.baseUrl,
    groupKey: member.groupKey,
    groupId: member.groupId,
    peerId,
    keypair: createKeypair(),
    persist: false,
    ...extra,
  });

  // 契约 §8.2：peers.json 里有该 peerId 的配对记录，却不肯出证明 → 403
  const missing = await rejectionOf(register(PROOF_NONE_ID));
  assert.equal(missing?.status, 403, '契约 §8.2：已配对的 peerId 缺 pairProof 必须拒');
  assert.equal(missing?.code, 'pair-proof-required', '契约 §8.2：错误码固定 pair-proof-required');

  // 契约 §8.2：证明用错了密钥 → 401
  const wrong = await rejectionOf(register(PROOF_BAD_ID, { pairSecret: 'not-the-paired-secret' }));
  assert.equal(wrong?.status, 401, '契约 §8.2：pairProof 验不过必须拒');
  assert.equal(wrong?.code, 'bad-pair-proof', '契约 §8.2：错误码固定 bad-pair-proof');

  // 正例：正确的配对密钥 → 200，并在 hub 台账落一条
  const good = await register(PROOF_OK_ID, { pairSecret: PAIR_SECRET });
  assert.equal(good.ok, true, '契约 §8.2：正确 pairProof 必须签发证书');
  assert.equal(good.cert.peerId, PROOF_OK_ID);
  const ledger = readMemberCerts(hub.stateDir);
  assert.equal(ledger.members[PROOF_OK_ID]?.current?.sig, good.cert.sig, '契约 §4：签发即入台账');
  assert.equal(ledger.members[PROOF_NONE_ID], undefined, '契约 §8.2：被拒的注册绝不入台账');
  assert.equal(ledger.members[PROOF_BAD_ID], undefined, '契约 §8.2：被拒的注册绝不入台账');
});

// ---------------------------------------------------------------------------
// 8 allowLegacyGroupAuth:false
// ---------------------------------------------------------------------------

test('E2E8 allowLegacyGroupAuth:false：v1 头 401 legacy-auth-disabled，同一节点 v2 仍 200', async (t) => {
  const hub = await startHub(t, { server: { allowLegacyGroupAuth: false } });
  hub.server.group.addMember(MEMBER_ID, 'member');
  const member = await startMember(t, hub);

  // v1 注册在这台 hub 上会被 §6 的门禁挡掉，所以证书直接由 hub CA 签发并装到成员盘上
  // （走的是产品里的 issueMemberCertificate / writeMemberCertFile，不是手搓 JSON）
  const ca = loadOrCreateHubCa(hub.stateDir);
  assert.equal(ca.ok, true);
  const issued = issueMemberCertificate({
    stateDir: hub.stateDir,
    caPrivateKey: ca.privateKey,
    peerId: MEMBER_ID,
    pubKey: member.keypair.publicKeyDer,
    groupId: member.groupId,
    hubEpoch: member.epoch,
    now: Date.now(),
  });
  assert.equal(issued.ok, true, '预置：hub CA 签发成员证书');
  writeMemberCertFile(member.stateDir, issued.cert);
  writeTrustedHubCaFile(member.stateDir, { hubCaPubKey: ca.pubKey, hubEpoch: member.epoch, source: 'register' });

  // v1 头 → 契约 §6 的开关生效
  const legacy = await rejectionOf(probeGroupPeer({
    baseUrl: hub.baseUrl,
    groupKey: member.groupKey,
    groupId: member.groupId,
    senderId: member.peerId,
  }));
  assert.equal(legacy?.status, 401, '契约 §6：关掉 v1 后 v1 头必须拒');
  assert.equal(legacy?.code, 'legacy-auth-disabled', '契约 §6：错误码固定 legacy-auth-disabled');

  // 同一节点同一时间，v2 头照常放行 —— 证明这条开关只关 v1，没有误伤 v2
  const identity = loadGroupIdentity(member.stateDir);
  assert.equal(identity.ok, true);
  const v2 = await probeGroupPeer({
    baseUrl: hub.baseUrl,
    groupKey: member.groupKey,
    groupId: member.groupId,
    senderId: member.peerId,
    identity,
  });
  assert.equal(v2.ok, true, '契约 §6：allowLegacyGroupAuth:false 不影响 v2');
});

// ---------------------------------------------------------------------------
// 9 门禁没放宽
// ---------------------------------------------------------------------------

test('E2E9 门禁没放宽：v2 头打非群路径 /v1/peers → 401 group-auth-scope', async (t) => {
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER_ID, 'member');
  const member = await startMember(t, hub);
  await registerMember(hub, member);
  const identity = loadGroupIdentity(member.stateDir);
  assert.equal(identity.ok, true);

  const err = await rejectionOf(groupCall({
    baseUrl: hub.baseUrl,
    groupKey: member.groupKey,
    groupId: member.groupId,
    senderId: member.peerId,
    method: 'GET',
    apiPath: '/v1/peers',
    identity,
  }));
  assert.equal(err?.status, 401, '契约 §3：v2 头只在群鉴权白名单路径上有效');
  assert.equal(err?.code, 'group-auth-scope', '契约 §3：非群路径带群头一律 401 group-auth-scope');
});
