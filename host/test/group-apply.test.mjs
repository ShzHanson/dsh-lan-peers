/**
 * v0.8.0 按名申请入群（契约 group-v08-contract.md §4/§5/§7/§9/§10）。
 *
 * 拓扑（真监听、真签名、真加密）：A = hub，B = A 的成员，C 只与 B 配对。
 * 覆盖：申请转交（C → B → A）、待批幂等、批准后 C 拿到 grant 并成为成员、
 *      autoJoin 自动批准、blocked 一律 rejected 且不落 applications、
 *      applications 的 24 小时 TTL 与 100 条上限、
 *      grant 两跳加密（hub→介绍人走群密钥信封，介绍人→申请者走 per-peer 信封）。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createPeerServer, GroupStore } from '../server.mjs';
import {
  GROUP_APPLICATION_LIMIT,
  applyGroupGrant,
  applyToGroup,
  decryptGroupJson,
  deriveGroupKeys,
  encryptGroupBody,
  groupAuthHeaders,
  groupCall,
  lookupGroupName,
  pollApplication,
  readGroupKeyFile,
} from '../../lib/group-client.mjs';
import { listenOnRandomPort, makeTempStateDir, request, writeJson0600 } from './helpers.mjs';
import { secretOf, startCluster } from './group-cluster.mjs';

const DAY = 86_400_000;
const HOUR = 3_600_000;

const C = { peerId: 'peer-apply-c', name: 'charlie' };
const STRANGER = { peerId: 'peer-apply-d', name: 'dave' };

/**
 * 起 A(hub) + B(成员)，再造一个只与 B 配对的申请者 C。
 * C 只需要 state-dir 与一把 per-peer 密钥：申请/轮询都是客户端调用（与 CLI 同路径）。
 */
async function startChain(t, { autoJoin = false } = {}) {
  const logs = [];
  const cluster = await startCluster(t, {
    count: 2,
    ids: ['peer-apply-a', 'peer-apply-b'],
    autoJoin,
    logger: (line) => logs.push(String(line)),
  });
  const [hub, introducer] = cluster.nodes;
  // B 的 peers.json 里补上 C 与陌生人 D（只有 C 会来申请）
  for (const peer of [C, STRANGER]) {
    introducer.server.store.upsertPeer(peer.peerId, {
      name: peer.name,
      baseUrl: 'http://127.0.0.1:1',
      // B 发出去用自己的密钥，收进来用对端的（与 group-cluster 同口径）
      secret: secretOf(introducer.peerId),
      inboundSecret: secretOf(peer.peerId),
    });
  }
  const applicantDir = makeTempStateDir('dsh-lan-peers-apply-');
  t.after(() => fs.rmSync(applicantDir, { recursive: true, force: true }));
  writeJson0600(path.join(applicantDir, 'state.json'), {
    instanceId: C.peerId,
    name: C.name,
    createdAt: new Date().toISOString(),
  });
  return {
    hub,
    introducer,
    logs,
    applicantDir,
    groupId: cluster.groupId,
    groupKey: cluster.groupKey,
    applicant: { peerId: C.peerId, name: C.name, baseUrl: 'http://127.0.0.1:1' },
  };
}

const applyFrom = (chain, senderId, groupId = chain.groupId) => applyToGroup({
  baseUrl: chain.introducer.baseUrl,
  secret: secretOf(senderId),
  senderId,
  groupId,
  applicant: { peerId: senderId, name: 'applicant', baseUrl: 'http://127.0.0.1:1' },
});

const pollFrom = (chain, senderId, groupId = chain.groupId) => pollApplication({
  baseUrl: chain.introducer.baseUrl,
  secret: secretOf(senderId),
  senderId,
  groupId,
});

// ---------------------------------------------------------------------------
// §4 申请与转交
// ---------------------------------------------------------------------------

test('v0.8.0 §4 申请转交：C → B（介绍人）→ A（hub）待批，重复申请幂等', async (t) => {
  const chain = await startChain(t);

  const applied = await applyFrom(chain, C.peerId);
  assert.deepEqual(applied, { status: 'pending' }, JSON.stringify(applied));

  const pending = chain.hub.server.group.applications();
  assert.equal(pending.length, 1);
  assert.equal(pending[0].peerId, C.peerId);
  assert.equal(pending[0].status, 'pending');
  // 视图里介绍人是 { peerId, name }（面板要名字），落盘仍是 peerId 字符串（下一段验证）
  assert.equal(pending[0].introducedBy.peerId, chain.introducer.peerId, 'introducer = 转交的那台成员');
  assert.equal(pending[0].introducedByName.length > 0, true, '介绍人名字不能是空串');
  assert.equal(typeof pending[0].at, 'number');
  assert.equal(pending[0].decidedAt, null);
  // 待批阶段没有成员身份，也没有授权
  assert.equal(chain.hub.server.group.state().members[C.peerId], undefined);

  // 幂等：同一个申请者再申请一次只刷新 at，不新增条目
  await new Promise((resolve) => setTimeout(resolve, 5));
  const again = await applyFrom(chain, C.peerId);
  assert.equal(again.status, 'pending');
  const after = chain.hub.server.group.applications();
  assert.equal(after.length, 1);
  assert.ok(after[0].at >= pending[0].at);

  // hub 侧落盘：group.json 里 applications 是 0600 的直接子字段
  const raw = JSON.parse(fs.readFileSync(path.join(chain.hub.dir, 'group.json'), 'utf8'));
  assert.equal(raw.applications[C.peerId].introducedBy, chain.introducer.peerId);

  // 申请者轮询：还没批 → pending
  assert.deepEqual(await pollFrom(chain, C.peerId), { status: 'pending' });

  // 陌生人对同一条申请查不到东西（各查各的）
  assert.deepEqual(await pollFrom(chain, STRANGER.peerId), { status: 'unknown' });
});

test('v0.8.0 §4 介绍人只转交自己所属群的申请；不能替别人申请', async (t) => {
  const chain = await startChain(t);

  const wrongGroup = await applyFrom(chain, C.peerId, 'not-my-group').catch((error) => ({ error }));
  assert.ok(wrongGroup.error, '群不匹配必须拒绝');
  assert.match(String(wrongGroup.error.message), /404/);

  const impersonate = await applyToGroup({
    baseUrl: chain.introducer.baseUrl,
    secret: secretOf(C.peerId),
    senderId: C.peerId,
    groupId: chain.groupId,
    applicant: { peerId: STRANGER.peerId, name: 'dave', baseUrl: 'http://127.0.0.1:1' },
  }).catch((error) => ({ error }));
  assert.ok(impersonate.error, '替别人申请必须拒绝');
  assert.match(String(impersonate.error.message), /400/);
  assert.deepEqual(chain.hub.server.group.applications(), []);
});

// ---------------------------------------------------------------------------
// §5 授权（grant）
// ---------------------------------------------------------------------------

test('v0.8.0 §5 批准后 C 轮询拿到 grant → 写 group-key.json → 群级签名读 history 成功', async (t) => {
  const chain = await startChain(t);
  await applyFrom(chain, C.peerId);

  const approved = chain.hub.server.group.approveApplication(C.peerId);
  assert.deepEqual(approved, { ok: true, status: 'approved', reason: null });
  assert.ok(chain.hub.server.group.state().members[C.peerId], '批准即入成员表');

  const polled = await pollFrom(chain, C.peerId);
  assert.equal(polled.status, 'approved');
  const grant = polled.grant;
  assert.ok(grant, 'approved 必须带 grant');
  assert.equal(grant.groupId, chain.groupId);
  assert.equal(grant.name, 's3');
  assert.equal(grant.keyVersion, 1);
  assert.equal(grant.key, chain.groupKey, 'grant 带的就是群密钥');
  assert.deepEqual(grant.hub, {
    peerId: chain.hub.peerId,
    // 群身份里的名字走 config.name（群集群默认就是 hostname，这里按实际值断言）
    name: chain.hub.server.config.name,
    baseUrl: chain.hub.baseUrl,
  });
  assert.ok(grant.members.some((member) => member.peerId === C.peerId), '成员表含申请者自己');
  assert.ok(grant.members.some((member) => member.peerId === chain.introducer.peerId));

  // 申请者落盘 group-key.json（0600），此后是成员
  const written = applyGroupGrant(chain.applicantDir, grant);
  assert.equal(written.groupId, chain.groupId);
  assert.equal(written.key, chain.groupKey);
  assert.equal(written.leaderPeerId, chain.hub.peerId);
  assert.equal(written.groupName, 's3');
  if (process.platform !== 'win32') {
    assert.equal(fs.statSync(path.join(chain.applicantDir, 'group-key.json')).mode & 0o777, 0o600);
  }
  assert.equal(readGroupKeyFile(chain.applicantDir).key, chain.groupKey);

  // 成为成员后，群级签名直连 hub 成功：/v1/group/pull 在白名单里（history 仍走 per-peer）
  const pull = await groupCall({
    baseUrl: chain.hub.baseUrl,
    groupKey: chain.groupKey,
    groupId: chain.groupId,
    senderId: C.peerId,
    method: 'GET',
    apiPath: '/v1/group/pull?sinceSeq=0&limit=10',
  });
  assert.equal(pull.groupId, chain.groupId);
  assert.ok(Array.isArray(pull.messages));
  assert.ok(pull.memberIds.includes(C.peerId), '成员表里有自己');

  // 读群日志：C 只与 B 配对，hub 上没有它的 per-peer 记录 —— 授权后它只能靠群级签名，
  // 这正是 grant 的意义（/v1/group/history 不在群级白名单，所以读日志走 pull）。
  chain.hub.server.group.post({ peerId: chain.introducer.peerId, name: 'node-b', kind: 'chat', text: 'hi' });
  const afterPost = await groupCall({
    baseUrl: chain.hub.baseUrl,
    groupKey: readGroupKeyFile(chain.applicantDir).key,
    groupId: readGroupKeyFile(chain.applicantDir).groupId,
    senderId: C.peerId,
    method: 'GET',
    apiPath: '/v1/group/pull?sinceSeq=0&limit=10',
  });
  assert.equal(afterPost.messages.length, 1, '新成员能读到群日志');
  assert.equal(afterPost.messages[0].text, 'hi');

  // 没有 per-peer 记录的节点拿到 401 unknown-peer：授权是它读群的唯一通道
  const perPeer = await request(chain.hub.baseUrl, {
    path: '/v1/group/history?sinceSeq=0&limit=10',
    peerId: C.peerId,
    secret: secretOf(C.peerId),
  });
  assert.equal(perPeer.status, 401);
  assert.equal(perPeer.json.error, 'unknown-peer');

  // 再轮询一次仍然是 approved（幂等），不会因为没有待批而变成 unknown
  assert.equal((await pollFrom(chain, C.peerId)).status, 'approved');
});

test('v0.8.0 §4.2 autoJoin：无需人工，申请后直接 approved 并拿到 grant', async (t) => {
  const chain = await startChain(t, { autoJoin: true });

  const applied = await applyFrom(chain, C.peerId);
  assert.deepEqual(applied, { status: 'approved' });
  assert.ok(chain.hub.server.group.state().members[C.peerId], 'autoJoin 直接入成员表');
  assert.equal(chain.hub.server.group.applications()[0].status, 'approved');
  assert.ok(chain.hub.server.group.applications()[0].decidedAt, 'approved 必须有 decidedAt');

  const polled = await pollFrom(chain, C.peerId);
  assert.equal(polled.status, 'approved');
  assert.equal(polled.grant.key, chain.groupKey);
});

// ---------------------------------------------------------------------------
// §9 安全约束
// ---------------------------------------------------------------------------

test('v0.8.0 §9.1 被移除者（blocked）申请 → rejected，且不落 applications', async (t) => {
  const chain = await startChain(t, { autoJoin: true });
  await applyFrom(chain, C.peerId);
  assert.ok(chain.hub.server.group.state().members[C.peerId]);

  // 踢人 = 移除 + 记住 blocked + 密钥轮换
  assert.equal(chain.hub.server.group.removeMember(C.peerId), true);
  assert.equal(chain.hub.server.group.applications().length, 0, '移除后申请记录一起作废');

  let rejected;
  try {
    rejected = await applyFrom(chain, C.peerId);
  } catch (error) {
    // 失败时把两台节点的日志带上：这条链路跨了「密钥轮换 → 群级换钥 → 重试」
    assert.fail('再次申请失败: ' + String(error?.message ?? error)
      + ' / logs=' + JSON.stringify(chain.logs.slice(-12)));
  }
  assert.deepEqual(rejected, { status: 'rejected', reason: 'blocked' });
  assert.deepEqual(chain.hub.server.group.applications(), [], '被移除者不写 applications');
  assert.equal(chain.hub.server.group.state().members[C.peerId], undefined);

  // 轮询只能得到 unknown（没有申请记录，也就没有授权）
  assert.deepEqual(await pollFrom(chain, C.peerId), { status: 'unknown' });
});

test('v0.8.0 §5.1 grant 两跳加密：hub→介绍人走群信封，介绍人→申请者走 per-peer 信封', async (t) => {
  const chain = await startChain(t);
  await applyFrom(chain, C.peerId);
  chain.hub.server.group.approveApplication(C.peerId);

  // 第一跳：hub 的响应被群密钥派生的 bodyKey 加密（介绍人才能解开）
  const { bodyKey } = deriveGroupKeys(chain.groupKey);
  const { headers, plain } = groupAuthHeaders({
    groupKey: chain.groupKey,
    groupId: chain.groupId,
    senderId: chain.introducer.peerId,
    method: 'POST',
    apiPath: '/v1/group/apply-query',
    body: { applicantPeerId: C.peerId },
  });
  const hop1 = await fetch(new URL('/v1/group/apply-query', chain.hub.baseUrl), {
    method: 'POST',
    headers: { ...headers, 'x-peer-enc': 'v1' },
    body: Buffer.from(encryptGroupBody(bodyKey, plain), 'utf8'),
  });
  const hop1Raw = await hop1.json();
  assert.equal(hop1.status, 200);
  assert.equal(hop1Raw.enc, 'v1', 'hub 的 grant 响应必须是群信封');
  const hop1Body = decryptGroupJson(bodyKey, hop1Raw.data);
  assert.equal(hop1Body.status, 'approved');
  assert.equal(hop1Body.grant.key, chain.groupKey);

  // 第二跳：介绍人把 grant 转发给申请者时，响应被申请者的 per-peer 密钥加密
  const hop2 = await request(chain.introducer.baseUrl, {
    method: 'POST',
    path: '/v1/group/apply-status',
    peerId: C.peerId,
    secret: secretOf(C.peerId),
    body: { groupId: chain.groupId },
    encrypt: true,
  });
  assert.equal(hop2.status, 200, hop2.text);
  assert.match(hop2.text, /^\{"enc":"v1"/, '介绍人 → 申请者必须是 per-peer 信封');
  assert.equal(hop2.json.status, 'approved');
  assert.equal(hop2.json.grant.key, chain.groupKey, '两跳之后 grant 仍然完整');

  // 只有申请者自己的密钥解得开：换成别人的密钥拿到的不是明文
  const eavesdrop = await request(chain.introducer.baseUrl, {
    method: 'POST',
    path: '/v1/group/apply-status',
    peerId: STRANGER.peerId,
    secret: secretOf(STRANGER.peerId),
    body: { groupId: chain.groupId },
    encrypt: true,
  });
  assert.equal(eavesdrop.json.status, 'unknown');
  assert.equal(eavesdrop.json.grant, undefined, '别人的申请查不到 grant');
});

// ---------------------------------------------------------------------------
// §3 + §4 端到端：按名发现后申请（这条链路是面板/CLI 的实际路径）
// ---------------------------------------------------------------------------

test('v0.8.0 §3/§4 只与成员配对也能按群名发现并申请（B broadcast → C lookup → C apply）', async (t) => {
  const chain = await startChain(t);
  const applicant = await startApplicantNode(t, chain);

  // B 把群名广播给非成员伙伴 C（手动路径，与面板按钮同一函数）
  const broadcast = await chain.introducer.server.group.broadcast('manual');
  assert.equal(broadcast.ok, true);
  assert.deepEqual(broadcast.sent.map((entry) => entry.peerId), [C.peerId]);

  // C 先查本地 known-groups 命中
  const known = readGroupKeyFile(applicant.dir); // 还没入群：null
  assert.equal(known, null);
  const localKnown = JSON.parse(fs.readFileSync(path.join(applicant.dir, 'known-groups.json'), 'utf8'));
  assert.equal(localKnown.groups[chain.groupId].name, 's3');

  // 再向伙伴 lookup（这里 C 只与 B 配对）
  const looked = await lookupGroupName({
    baseUrl: chain.introducer.baseUrl,
    secret: secretOf(C.peerId),
    senderId: C.peerId,
    name: 'S3',
  });
  assert.equal(looked.matches.length, 1);
  assert.equal(looked.matches[0].groupId, chain.groupId);
  assert.deepEqual(looked.matches[0].via, {
    peerId: chain.introducer.peerId,
    name: chain.introducer.server.config.name,
  });

  // 用查到的 groupId 申请 → 待批 → 批准 → 拿授权
  const applied = await applyToGroup({
    baseUrl: chain.introducer.baseUrl,
    secret: secretOf(C.peerId),
    senderId: C.peerId,
    groupId: looked.matches[0].groupId,
    applicant: { peerId: C.peerId, name: C.name, baseUrl: 'http://127.0.0.1:1' },
  });
  assert.equal(applied.status, 'pending');
  chain.hub.server.group.approveApplication(C.peerId);
  const polled = await pollFrom(chain, C.peerId);
  assert.equal(polled.status, 'approved');
  assert.ok(polled.grant.keyVersion >= 1);
});

/** 申请者节点：一个不带群的普通节点，只与 B 配对（用来验 known-groups 落盘与 lookup） */
async function startApplicantNode(t, chain) {
  const dir = makeTempStateDir('dsh-lan-peers-appnode-');
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  writeJson0600(path.join(dir, 'state.json'), {
    instanceId: C.peerId,
    name: C.name,
    createdAt: new Date().toISOString(),
  });
  writeJson0600(path.join(dir, 'peers.json'), {
    peers: {
      [chain.introducer.peerId]: {
        name: chain.introducer.name,
        baseUrl: chain.introducer.baseUrl,
        secret: secretOf(C.peerId),
        inboundSecret: secretOf(chain.introducer.peerId),
        addedAt: new Date().toISOString(),
        lastSeen: null,
      },
    },
  });
  const server = createPeerServer({
    listenHost: '127.0.0.1',
    stateDir: dir,
    name: C.name,
    requireEncryption: false,
    allowRemotePrompts: true,
  });
  const info = await listenOnRandomPort(server);
  t.after(async () => { await server.close(); });
  // B 侧要知道 C 的可达地址（广播是 B → C 方向）
  chain.introducer.server.store.upsertPeer(C.peerId, {
    name: C.name,
    baseUrl: info.url,
    secret: secretOf(chain.introducer.peerId),
    inboundSecret: secretOf(C.peerId),
  });
  return { dir, server, baseUrl: info.url };
}

// ---------------------------------------------------------------------------
// §7 存储：24 小时 TTL 与 100 条上限
// ---------------------------------------------------------------------------

test('v0.8.0 §7 applications：上限 100 条、24 小时 TTL、幂等刷新 at', async (t) => {
  const dir = makeTempStateDir('dsh-lan-peers-apps-');
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  let clock = Date.now();
  const owner = { peerId: 'hub-peer', name: 'hub' };
  const store = new GroupStore({ stateDir: dir, now: () => clock, owner });

  for (let index = 0; index < GROUP_APPLICATION_LIMIT + 5; index += 1) {
    store.upsertApplication({
      peerId: 'applicant-' + index,
      name: 'name-' + index,
      baseUrl: 'http://10.0.0.9:7788',
      introducedBy: 'intro',
      now: clock + index,
    });
  }
  assert.equal(store.applications().length, GROUP_APPLICATION_LIMIT, '上限 100 条');

  // 幂等：同一个申请者再申请只刷新 at，不新增
  const target = store.applications()[0].peerId;
  const refreshed = store.upsertApplication({ peerId: target, now: clock + 500_000 });
  assert.equal(refreshed.at, clock + 500_000);
  assert.equal(store.applications().length, GROUP_APPLICATION_LIMIT);

  // 24 小时 TTL：时钟推过 24h 后读盘（新的 GroupStore 重新加载）→ 全部过期
  clock += 24 * HOUR + 60_000;
  const reopened = new GroupStore({ stateDir: dir, now: () => clock, owner });
  assert.deepEqual(
    reopened.applications().map((entry) => entry.peerId),
    [target],
    '超过 24 小时的申请被清理，只剩刚被刷新过的那条',
  );

  // 再推 2 小时：连它一起过期
  clock += 2 * HOUR;
  const expired = new GroupStore({ stateDir: dir, now: () => clock, owner });
  assert.deepEqual(expired.applications(), [], 'TTL 之后一条都不留');
  assert.equal(expired.application(target), null);

  // 边界：刚好在 TTL 内的一条要留下
  const fresh = new GroupStore({ stateDir: dir, now: () => clock, owner });
  fresh.upsertApplication({ peerId: 'late', name: 'late', now: clock - DAY + 60_000 });
  assert.deepEqual(fresh.applications().map((entry) => entry.peerId), ['late']);
});
