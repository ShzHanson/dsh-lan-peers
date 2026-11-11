/**
 * v0.6.0 S2 · 日志复制（契约 group-s1s2-contract.md §S2）。
 *
 * 覆盖：成员副本的形状/0600/保留策略/5000 上限/seq 单调不回退、
 *      replicate 按 seq 去重（重复投递幂等）、epoch 更高才换 leader、
 *      pull 补齐（把 replica 的 lastSeq 改小后仍能补回）、
 *      post 写本地即提交（复制失败不影响 201）、hub 停掉后副本仍在、重启后 seq 不回退不重复。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { listenOnRandomPort } from '../../test-support/ports.mjs';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { createPeerServer, GroupReplicaStore, sanitizeGroupMeta } from '../server.mjs';
import { deriveGroupKeys, decryptGroupJson, encryptGroupBody, groupAuthHeaders } from '../../lib/group-client.mjs';
import { fileMode, makeTempStateDir, peerFixture, readJson, request, seedPeers, writeJson0600 } from './helpers.mjs';
// 0.10.0-α slice 4a：纪要的群级 HTTP 读口/写口 + 真集群脚手架
import { fetchGroupNotes, groupCall, postGroupNote } from '../../lib/group-client.mjs';
import { startCluster, waitFor } from './group-cluster.mjs';

const MEMBER = peerFixture('peer-replica-1');
const MEMBER2 = peerFixture('peer-replica-2');

const DAY = 86_400_000;

/** hub：stateDir 由调用方持有，便于「杀掉再重启」 */
async function startHub(t, { stateDir = makeTempStateDir(), group = {}, runner, name, logger, voteRoundMs } = {}) {
  seedPeers(stateDir, [MEMBER, MEMBER2]);
  const server = createPeerServer({
    listenHost: '127.0.0.1',
    stateDir,
    requireEncryption: false,
    allowRemotePrompts: true,
    // S3 起 majority 会把 post 变成 propose→commit（复制失败就不再是 201）；
    // 这个文件测的是 S2 的复制语义，固定 quorum:「none」= 写本地即提交。
    group: { enabled: true, name: 'default', autoJoin: true, retentionDays: 7, quorum: 'none', ...group },
    // 片 3b：hub 自己也要答题（Q&A 的参与者），测试必须能喂它一个假 runner
    ...(runner ? { runner } : {}),
    ...(name ? { name } : {}),
    ...(logger ? { logger } : {}),
    // 0.10.0-α slice 4b-1：表决轮的时长（生产固定 10 分钟；测试缩短，别真等）
    ...(voteRoundMs ? { groupVote: { roundMs: voteRoundMs } } : {}),
  });
  const info = await listenOnRandomPort(server);
  t.after(async () => { await server.close(); });
  return { server, baseUrl: info.url, stateDir };
}

/** 成员 state-dir：identity + 一条到 hub 的配对记录（secret = hub 验证我们用的那把） */
function memberStateDir(t, { hubBaseUrl, hubInstanceId, identity = MEMBER, hubName = 'hub' }) {
  const dir = makeTempStateDir('dsh-lan-peers-replica-');
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  writeJson0600(path.join(dir, 'state.json'), {
    instanceId: identity.peerId,
    name: identity.name,
    createdAt: new Date().toISOString(),
  });
  writeJson0600(path.join(dir, 'peers.json'), {
    peers: {
      [hubInstanceId]: {
        name: hubName,
        baseUrl: hubBaseUrl,
        secret: identity.inboundSecret,
        inboundSecret: 'unused-outbound',
        addedAt: new Date().toISOString(),
        lastSeen: null,
      },
    },
  });
  return dir;
}

async function startMember(t, { hubBaseUrl, hubInstanceId, identity = MEMBER, group = {}, stateDir, runner, logger, name }) {
  const dir = stateDir ?? memberStateDir(t, { hubBaseUrl, hubInstanceId, identity });
  const server = createPeerServer({
    listenHost: '127.0.0.1',
    stateDir: dir,
    requireEncryption: false,
    // autoJoin：成员 bootstrap 被 hub 回 403 not-a-member 时自助加入一次（S2 的正常上线路径）
    group: { enabled: true, hub: 'hub', autoJoin: true, ...group },
    // 测试自己驱动补差，不让后台定时器插进来
    groupReplica: { pullIntervalMs: 600_000 },
    // 0.10.0-α slice 3a：@ 必答要用喂进来的假 runner（默认的 MemoryRunner 会答成 "OK …"）
    ...(runner ? { runner } : {}),
    ...(logger ? { logger } : {}),
    // slice 3a：本机显示名（@ 判定按名字命中时用得上；config.name 默认是 os.hostname()）
    ...(name ? { name } : {}),
  });
  const info = await listenOnRandomPort(server);
  // 回环地址做「成员自报地址」：否则 hub 推到探测出的私网 IP，测试机上打不通
  server.config.group.advertiseBaseUrl = info.url;
  t.after(async () => { await server.close(); });
  return { server, baseUrl: info.url, stateDir: dir };
}

const replicaFileOf = (dir) => path.join(dir, 'group-replica.json');

/** 后台首轮 tick 可能正占着 memberInFlight，这里等到真正跑完一轮 */
async function pullNow(member, attempts = 40) {
  for (let i = 0; i < attempts; i += 1) {
    const out = await member.server.group.pull();
    if (out?.reason !== 'skipped') return out;
    await sleep(25);
  }
  throw new Error('member pull kept being skipped');
}

const postAs = (hub, identity, text, kind = 'chat') => request(hub.baseUrl, {
  method: 'POST',
  path: '/v1/group/post',
  peerId: identity.peerId,
  secret: identity.inboundSecret,
  body: { kind, text },
});

/** 群级请求（向成员端点投递副本 / 拉取） */
async function groupRequest(baseUrl, {
  groupKey,
  groupId,
  senderId,
  method = 'GET',
  path: apiPath,
  body,
  extraHeaders = {},
}) {
  const { headers, plain } = groupAuthHeaders({ groupKey, groupId, senderId, method, apiPath, body });
  const { bodyKey } = deriveGroupKeys(groupKey);
  const wire = plain.length && method === 'POST' ? Buffer.from(encryptGroupBody(bodyKey, plain), 'utf8') : Buffer.alloc(0);
  const res = await fetch(new URL(apiPath, baseUrl), {
    method,
    headers: { ...headers, ...extraHeaders, 'x-peer-enc': 'v1' },
    body: wire.length ? wire : undefined,
  });
  const text = await res.text();
  let json = null;
  try {
    const parsed = JSON.parse(text);
    json = parsed && parsed.enc === 'v1' ? decryptGroupJson(bodyKey, parsed.data) : parsed;
  } catch {}
  return { status: res.status, json, text };
}

const message = (seq, text = 'm' + seq, ts = Date.now()) => ({
  seq,
  ts,
  from: { peerId: MEMBER.peerId, name: MEMBER.name },
  kind: 'chat',
  text,
  meta: {},
});

// ---------------------------------------------------------------------------
// GroupReplicaStore 单元
// ---------------------------------------------------------------------------

test('S2 副本文件：形状固定、0600、按 seq 去重、lastSeq 单调不回退', (t) => {
  const stateDir = makeTempStateDir();
  t.after(() => fs.rmSync(stateDir, { recursive: true, force: true }));
  const store = new GroupReplicaStore({ stateDir, retentionDays: 7 });
  const groupId = 'aaaaaaaa-1111-4111-8111-111111111111';

  const first = store.append({ groupId, epoch: 1, leaderPeerId: 'hub-1', messages: [message(1), message(2), message(3)] });
  assert.equal(first.ok, true);
  assert.equal(first.added, 3);
  assert.equal(first.lastSeq, 3);

  // 重复投递：同 seq 不再追加
  const again = store.append({ groupId, epoch: 1, leaderPeerId: 'hub-1', messages: [message(2), message(3), message(4)] });
  assert.equal(again.added, 1);
  assert.equal(again.lastSeq, 4);

  // seq 比本地小的补发：不入库，lastSeq 不减
  const stale = store.append({ groupId, epoch: 1, leaderPeerId: 'hub-1', messages: [message(2), message(3)] });
  assert.equal(stale.added, 0);
  assert.equal(stale.lastSeq, 4);

  const file = store.replicaPath;
  // Windows 上 chmod 只切只读位，mode 恒为 0666（与既有用例同口径）
  if (process.platform !== 'win32') assert.equal(fileMode(file), 0o600);
  const raw = readJson(file);
  assert.deepEqual(Object.keys(raw).sort(), ['epoch', 'groupId', 'lastSeq', 'leaderPeerId', 'messages']);
  assert.equal(raw.groupId, groupId);
  assert.deepEqual(raw.messages.map((m) => m.seq), [1, 2, 3, 4]);
  assert.equal(store.state().messageCount, 4);
});

test('S2 副本 epoch：更高 epoch 更新本地 epoch/leaderPeerId，低 epoch 补发整批丢弃', (t) => {
  const stateDir = makeTempStateDir();
  t.after(() => fs.rmSync(stateDir, { recursive: true, force: true }));
  const store = new GroupReplicaStore({ stateDir, retentionDays: 7 });
  const groupId = 'bbbbbbbb-1111-4111-8111-111111111111';

  store.append({ groupId, epoch: 1, leaderPeerId: 'hub-1', messages: [message(1)] });
  assert.equal(store.state().leaderPeerId, 'hub-1');

  // 新 leader（更高 epoch）：换人并收下它的消息
  const promoted = store.append({ groupId, epoch: 2, leaderPeerId: 'hub-2', messages: [message(2)] });
  assert.equal(promoted.added, 1);
  assert.equal(store.state().epoch, 2);
  assert.equal(store.state().leaderPeerId, 'hub-2');

  // 旧 leader 的补发：整批丢弃（否则接任后的记录会倒退）
  const late = store.append({ groupId, epoch: 1, leaderPeerId: 'hub-1', messages: [message(3)] });
  assert.equal(late.added, 0);
  assert.equal(late.stale, true);
  assert.equal(store.state().epoch, 2);
  assert.equal(store.state().leaderPeerId, 'hub-2');

  // 不同 groupId：拒绝落盘
  const foreign = store.append({ groupId: 'cccccccc-1111-4111-8111-111111111111', epoch: 2, messages: [message(9)] });
  assert.equal(foreign.ok, false);
  assert.equal(foreign.error, 'group-mismatch');
  assert.equal(store.state().lastSeq, 2);
});

test('S2 副本保留策略与 hub 相同：retentionDays 过期清理 + 5000 条硬上限', (t) => {
  const stateDir = makeTempStateDir();
  t.after(() => fs.rmSync(stateDir, { recursive: true, force: true }));
  let clock = Date.parse('2026-01-10T00:00:00.000Z');
  const store = new GroupReplicaStore({ stateDir, retentionDays: 1, now: () => clock });
  const groupId = 'dddddddd-1111-4111-8111-111111111111';

  // 过期消息读写都清（与 hub 的 group.json 同一策略）：3 天前的直接不入库
  store.append({ groupId, epoch: 1, messages: [message(1, 'old', clock - 3 * DAY), message(2, 'fresh', clock)] });
  assert.equal(store.state().messageCount, 1);
  assert.equal(store.state().lastSeq, 2);
  // 再过两天：剩下那条也过期了，但 lastSeq 仍是 2（号不回收）
  clock += 2 * DAY;
  assert.equal(store.state().messageCount, 0);
  assert.equal(store.state().lastSeq, 2);

  // 硬上限：超过 5000 条只留最新的一批
  const bulk = new GroupReplicaStore({ stateDir: makeTempStateDir(), retentionDays: 7, now: () => clock });
  const many = Array.from({ length: 5005 }, (_, index) => message(index + 1, 'x', clock));
  bulk.append({ groupId, epoch: 1, messages: many });
  const kept = bulk.state();
  assert.equal(kept.messageCount, 5000);
  assert.equal(kept.lastSeq, 5005);
  assert.equal(bulk.messages({ sinceSeq: 0, limit: 1 })[0].seq, 5005);
  fs.rmSync(path.dirname(bulk.replicaPath), { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// hub ↔ 成员 端到端
// ---------------------------------------------------------------------------

test('S2 成员 bootstrap：从 hub 群状态取 groupId/groupKey，落盘 group-key.json 与副本头', async (t) => {
  const hub = await startHub(t);
  const member = await startMember(t, { hubBaseUrl: hub.baseUrl, hubInstanceId: hub.server.store.instanceId });

  const out = await pullNow(member);
  assert.equal(out.ok, true, JSON.stringify(out));

  const key = readJson(path.join(member.stateDir, 'group-key.json'));
  const state = hub.server.group.state({ includeKey: true });
  assert.equal(key.groupId, state.groupId);
  assert.equal(key.key, state.groupKey, '成员拿到的就是 hub 的群密钥');
  assert.equal(key.leaderPeerId, hub.server.store.instanceId);

  const replica = readJson(replicaFileOf(member.stateDir));
  assert.equal(replica.groupId, state.groupId);
  assert.equal(replica.leaderPeerId, hub.server.store.instanceId);
  assert.equal(replica.lastSeq, 0);
  assert.deepEqual(replica.messages, []);
  if (process.platform !== 'win32') assert.equal(fileMode(path.join(member.stateDir, 'group-key.json')), 0o600);
});

test('S2 hub post → 成员副本 ≤2s 收到；重复投递幂等；pull 补齐落后', async (t) => {
  const hub = await startHub(t);
  const member = await startMember(t, { hubBaseUrl: hub.baseUrl, hubInstanceId: hub.server.store.instanceId });
  await pullNow(member); // bootstrap + 自报地址，hub 才知道往哪推

  const posted = await postAs(hub, MEMBER, '第一条');
  assert.equal(posted.status, 201, posted.text);

  // 复制是 best-effort，不阻塞 post：这里等它落地（契约要求 ≤2s）
  const deadline = Date.now() + 2000;
  let replica = readJson(replicaFileOf(member.stateDir));
  while (replica.messages.length === 0 && Date.now() < deadline) {
    await sleep(20);
    replica = readJson(replicaFileOf(member.stateDir));
  }
  assert.equal(replica.messages.length, 1, '成员副本没在 2s 内收到');
  assert.equal(replica.messages[0].text, '第一条');
  assert.equal(replica.lastSeq, 1);

  // 同一批再投一次：按 seq 去重，不重复入库
  const state = hub.server.group.state({ includeKey: true });
  const dup = await groupRequest(member.baseUrl, {
    groupKey: state.groupKey,
    groupId: state.groupId,
    senderId: hub.server.store.instanceId,
    method: 'POST',
    path: '/v1/group/replicate',
    body: { groupId: state.groupId, epoch: 1, leaderPeerId: hub.server.store.instanceId, messages: replica.messages },
  });
  assert.equal(dup.status, 200, dup.text);
  assert.equal(dup.json.added, 0);
  assert.equal(dup.json.lastSeq, 1);

  // 落后场景：本地副本被删到只剩第 1 条且 lastSeq=1（模拟丢盘/落后），pull 补齐
  const hubMessages = [2, 3, 4].map((seq) => hub.server.group.post({ peerId: MEMBER.peerId, name: MEMBER.name, kind: 'chat', text: 'h' + seq }));
  assert.deepEqual(hubMessages.map((m) => m.seq), [2, 3, 4]);
  assert.equal(hub.server.group.state().lastSeq, 4);
  writeJson0600(replicaFileOf(member.stateDir), {
    groupId: state.groupId,
    epoch: 1,
    leaderPeerId: hub.server.store.instanceId,
    lastSeq: 1,
    messages: [{ ...message(1, 'h1') }],
  });
  // 进程内 store 有缓存，重建一个成员实例读盘（等价于重启）
  // 不 listen：没有后台 tick 抢跑，这一轮补差完全由显式 pull 驱动
  const fresh = createPeerServer({
    listenHost: '127.0.0.1',
    stateDir: member.stateDir,
    requireEncryption: false,
    group: { enabled: true, hub: 'hub' },
  });
  t.after(async () => { await fresh.close(); });
  const out = await fresh.group.pull();
  assert.equal(out.ok, true, JSON.stringify(out));
  assert.equal(out.added, 3, '缺的 2、3、4 应被补齐');
  const caughtUp = readJson(replicaFileOf(member.stateDir));
  assert.deepEqual(caughtUp.messages.map((m) => m.seq), [1, 2, 3, 4]);
  assert.equal(caughtUp.lastSeq, 4);
});

test('S2 提交语义：复制失败不影响 post 成功；hub 停掉后成员副本仍含全部消息', async (t) => {
  const hub = await startHub(t);
  const member = await startMember(t, { hubBaseUrl: hub.baseUrl, hubInstanceId: hub.server.store.instanceId });
  await pullNow(member);

  // 指向一个打不通的地址：复制必然失败，post 仍要 201
  hub.server.group.state().members[MEMBER.peerId].baseUrl = 'http://127.0.0.1:1';
  const posted = await postAs(hub, MEMBER, '提交语义');
  assert.equal(posted.status, 201, posted.text);
  assert.equal(posted.json.seq, 1);
  await sleep(60);
  const pending = hub.server.group.pendingReplication();
  assert.ok(pending.some((item) => item.peerId === MEMBER.peerId), '失败的复制应留在重试队列里');

  // 恢复地址后重试成功
  hub.server.group.state().members[MEMBER.peerId].baseUrl = member.baseUrl;
  await hub.server.group.flushReplicate();
  await sleep(20);
  const replica = readJson(replicaFileOf(member.stateDir));
  assert.deepEqual(replica.messages.map((m) => m.text), ['提交语义']);

  // 再发两条，然后杀掉 hub：副本必须仍含全部消息
  await hub.server.group.state();
  const second = await postAs(hub, MEMBER, '第二条');
  assert.equal(second.status, 201);
  const deadline = Date.now() + 2000;
  while (readJson(replicaFileOf(member.stateDir)).messages.length < 2 && Date.now() < deadline) await sleep(20);
  assert.equal(readJson(replicaFileOf(member.stateDir)).messages.length, 2);

  const hubId = hub.server.store.instanceId;
  await hub.server.close();
  const surviving = readJson(replicaFileOf(member.stateDir));
  assert.deepEqual(surviving.messages.map((m) => m.text), ['提交语义', '第二条']);
  assert.equal(surviving.lastSeq, 2);
  // hub 不在了也不影响成员自己回答 probe
  const probe = await groupRequest(member.baseUrl, {
    groupKey: readJson(path.join(member.stateDir, 'group-key.json')).key,
    groupId: surviving.groupId,
    senderId: hubId,
    path: '/v1/group/probe',
  });
  assert.equal(probe.status, 200, probe.text);
  assert.equal(probe.json.lastSeq, 2);
});

test('S2 重启 hub：seq 不回退、成员不重复收（复用同一个 stateDir）', async (t) => {
  const stateDir = makeTempStateDir();
  t.after(() => fs.rmSync(stateDir, { recursive: true, force: true }));
  const hub = await startHub(t, { stateDir });
  const member = await startMember(t, { hubBaseUrl: hub.baseUrl, hubInstanceId: hub.server.store.instanceId });
  await pullNow(member);

  assert.equal((await postAs(hub, MEMBER, 'a')).json.seq, 1);
  assert.equal((await postAs(hub, MEMBER, 'b')).json.seq, 2);
  const deadline = Date.now() + 2000;
  while (readJson(replicaFileOf(member.stateDir)).messages.length < 2 && Date.now() < deadline) await sleep(20);
  assert.equal(readJson(replicaFileOf(member.stateDir)).lastSeq, 2);

  await hub.server.close();
  // 同一个 stateDir 重启：group.json 里的 lastSeq 接着走
  const restarted = createPeerServer({
    listenHost: '127.0.0.1',
    stateDir,
    requireEncryption: false,
    allowRemotePrompts: true,
    group: { enabled: true, name: 'default', autoJoin: true, retentionDays: 7 },
  });
  const info = await listenOnRandomPort(restarted);
  t.after(async () => { await restarted.close(); });
  const hub2 = { server: restarted, baseUrl: info.url, stateDir };
  // 成员重新指向新地址（端口变了）
  member.server.config.group.hub = 'hub';
  writeJson0600(path.join(member.stateDir, 'peers.json'), {
    peers: {
      [restarted.store.instanceId]: {
        name: 'hub',
        baseUrl: hub2.baseUrl,
        secret: MEMBER.inboundSecret,
        inboundSecret: 'unused-outbound',
        addedAt: new Date().toISOString(),
        lastSeen: null,
      },
    },
  });
  const third = await postAs(hub2, MEMBER, 'c');
  assert.equal(third.json.seq, 3, 'seq 不回退也不重复');
  const out = await pullNow(member);
  assert.equal(out.ok, true, JSON.stringify(out));
  const replica = readJson(replicaFileOf(member.stateDir));
  assert.deepEqual(replica.messages.map((m) => m.seq), [1, 2, 3]);
  assert.equal(replica.lastSeq, 3);
});

test('S2 hub members().lastSeq：成员 probe 自报的进度会更新到成员视图', async (t) => {
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER.peerId, MEMBER.name);
  const state = hub.server.group.state({ includeKey: true });
  const probe = (lastSeq) => groupRequest(hub.baseUrl, {
    groupKey: state.groupKey,
    groupId: state.groupId,
    senderId: MEMBER.peerId,
    path: '/v1/group/probe',
    extraHeaders: { 'X-Peer-LastSeq': String(lastSeq) },
  });

  assert.equal((await probe(7)).status, 200);
  const after7 = hub.server.group.members().find((m) => m.peerId === MEMBER.peerId);
  assert.equal(after7.lastSeq, 7, 'hub 应记下成员自报的 lastSeq');
  assert.equal(hub.server.group.state().members[MEMBER.peerId].lastSeq, undefined, '不写 group.json（避免写放大）');

  assert.equal((await probe(9)).status, 200);
  assert.equal(hub.server.group.members().find((m) => m.peerId === MEMBER.peerId).lastSeq, 9);
});

test('S2 hub members().lastSeq：从未 probe/pull 的成员是 null，自己那条取群日志 lastSeq', async (t) => {
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER.peerId, MEMBER.name);
  hub.server.group.addMember(MEMBER2.peerId, MEMBER2.name);

  // 从没上报过进度的成员：null（面板据此显示「—」而不是「落后 0 条」）
  const view = hub.server.group.members();
  assert.equal(view.find((m) => m.peerId === MEMBER.peerId).lastSeq, null);
  assert.equal(view.find((m) => m.peerId === MEMBER2.peerId).lastSeq, null);
  // hub 自己是 leader：lastSeq 就是群日志的 lastSeq
  hub.server.group.post({ peerId: MEMBER.peerId, name: MEMBER.name, kind: 'chat', text: 'x' });
  const self = hub.server.group.members().find((m) => m.peerId === hub.server.store.instanceId);
  assert.equal(self.lastSeq, hub.server.group.state().lastSeq);
  assert.equal(self.lastSeq, 1);

  // 成员真正 pull 一轮之后：hub 看到的就是它副本的进度
  const member = await startMember(t, { hubBaseUrl: hub.baseUrl, hubInstanceId: hub.server.store.instanceId });
  await pullNow(member); // bootstrap + 补差：这一轮自报的是 0
  await pullNow(member); // 再报一次：此时本地副本已经追到 1
  const reported = hub.server.group.members().find((m) => m.peerId === MEMBER.peerId).lastSeq;
  assert.equal(reported, 1, '成员 pull 时会自报 lastSeq');
  assert.equal(member.server.group.replica.state().lastSeq, 1);
});


// ---------------------------------------------------------------------------
// 0.10.0-α slice 3a · 群内 @ 必答（常驻会话 + 引用 + 单飞）
//
// 假 runner 记录 ask/done 的先后：events 就是 A3 的顺序断言，asks 就是 A4 的次数断言。
// ---------------------------------------------------------------------------

function answerRunner({ reply = '答：磁盘还剩 42G', fail = false, delayMs = 0, now = Date.now } = {}) {
  const sessions = new Map();
  const events = [];
  const asks = [];
  const state = { reply, fail, delayMs };
  let created = 0;
  let turns = 0;
  return {
    events,
    asks,
    sessions,
    state,
    async ask(prompt, options = undefined) {
      const wanted = typeof options?.sessionId === 'string' ? options.sessionId.trim() : '';
      const live = wanted !== '' && sessions.has(wanted);
      const sessionId = live ? wanted : 'rs-' + (++created);
      turns += 1;
      asks.push({ prompt, wanted, sessionId, reused: live, turn: turns });
      events.push('ask:' + turns);
      sessions.set(sessionId, { turn: turns, completesAt: now() + state.delayMs, reported: false });
      return { sessionId, reused: live };
    },
    async poll(sessionId) {
      const session = sessions.get(sessionId);
      if (!session) return { status: 'error', error: 'session-not-found' };
      // 片 3b B5：把某台节点「卡在答题中」，好让别的节点的答案先行落地
      if (state.hold) return { status: 'running' };
      if (now() < session.completesAt) return { status: 'running' };
      if (!session.reported) {
        session.reported = true;
        events.push('done:' + session.turn);
      }
      if (state.fail) return { status: 'error', error: 'runner-error' };
      return { status: 'done', reply: state.reply };
    },
  };
}

/** hub 群日志（落盘视图，带 sanitize 后的 meta）：答复到底进没进群，看这里 */
const hubMessages = (hub) => readJson(path.join(hub.stateDir, 'group.json')).messages;

/** 关掉 hub → 成员的推送：只留「成员自己 pull」这一条触发路径，用例才确定 */
function disablePush(hub) {
  hub.server.group.state().members[MEMBER.peerId].baseUrl = 'http://127.0.0.1:1';
}

const askFromHub = (hub, text) => hub.server.group.post({
  peerId: hub.server.store.instanceId,
  name: 'hub',
  kind: 'chat',
  text,
});

const answersOf = (list) => list.filter((m) => m.from.peerId === MEMBER.peerId && m.kind === 'chat');

test('3a A4 群内 @ 到我 → 一条 chat 答复 + meta.quote（seq 对得上、摘要 ≤80、正文=runner 答复）', async (t) => {
  const hub = await startHub(t);
  const runner = answerRunner({ reply: '磁盘还剩 42G' });
  const member = await startMember(t, {
    hubBaseUrl: hub.baseUrl, hubInstanceId: hub.server.store.instanceId, runner, name: 'nas-box',
  });
  await pullNow(member); // bootstrap
  disablePush(hub);

  const question = askFromHub(hub, '@nas-box 磁盘还剩多少');
  assert.equal(question.seq, 1);
  const out = await pullNow(member);
  assert.equal(out.ok, true, JSON.stringify(out));
  await member.server.group.waitAnswers();

  assert.equal(runner.asks.length, 1, '@ 到我 → 恰好一次 runner 调用');
  assert.equal(runner.asks[0].wanted, '', '第一次提问要新建常驻会话（没有记录）');
  assert.match(runner.asks[0].prompt, /【群内提问 · 致本机】/, '提示词必须带群内提问前言');
  assert.match(runner.asks[0].prompt, /@nas-box 磁盘还剩多少/, '原文要进提示词');

  const messages = hubMessages(hub);
  const answers = answersOf(messages);
  assert.equal(answers.length, 1, '必须恰好一条答复消息');
  assert.equal(answers[0].text, '磁盘还剩 42G', '答复正文 = runner 回复');
  assert.equal(answers[0].meta.quote.seq, 1, 'quote.seq 必须是被回答那条的 seq');
  assert.equal(answers[0].meta.quote.from, 'hub');
  assert.equal(answers[0].meta.quote.excerpt, '@nas-box 磁盘还剩多少');
  assert.ok(answers[0].meta.quote.excerpt.length <= 80);

  // 常驻会话落盘了：<stateDir>/group-resident.json 里就是这个群的这条会话
  const resident = readJson(path.join(member.stateDir, 'group-resident.json'));
  const key = Object.keys(resident.groups)[0];
  assert.equal(resident.groups[key].sessionId, runner.asks[0].sessionId);
  assert.ok(resident.groups[key].lastUsedAt > 0);
});

test('3a A3 单飞：两条 @ 同时在飞 → 串行、顺序= 到达顺序、第二问复用同一条常驻会话', async (t) => {
  const hub = await startHub(t);
  const runner = answerRunner({ reply: '收到', delayMs: 20 });
  const member = await startMember(t, {
    hubBaseUrl: hub.baseUrl, hubInstanceId: hub.server.store.instanceId, runner, name: 'nas-box',
  });
  await pullNow(member);
  disablePush(hub);

  askFromHub(hub, '@nas-box 第一问');
  askFromHub(hub, '@nas-box 第二问');
  await pullNow(member);
  await member.server.group.waitAnswers();

  assert.equal(runner.asks.length, 2, '两条 @ 各一次 runner 调用');
  assert.deepEqual(runner.events, ['ask:1', 'done:1', 'ask:2', 'done:2'],
    'A8 非空断言：没有单飞守卫时这里会是 ask:1, ask:2, done:1, done:2');
  assert.equal(runner.asks[1].wanted, runner.asks[0].sessionId, '第二问必须复用同一个常驻会话');
  assert.equal(runner.asks[1].reused, true, 'runner 确认续上');

  const answers = answersOf(hubMessages(hub));
  assert.deepEqual(answers.map((m) => m.meta.quote.seq), [1, 2], '两条答复按顺序引用各自的问题');
  assert.deepEqual(answers.map((m) => m.text), ['收到', '收到']);
});

test('3a A5 空/错答案：不发帖、只记一行、日志不带正文、常驻会话之后仍可用', async (t) => {
  const hub = await startHub(t);
  const logs = [];
  const runner = answerRunner({ fail: true });
  const member = await startMember(t, {
    hubBaseUrl: hub.baseUrl,
    hubInstanceId: hub.server.store.instanceId,
    runner,
    name: 'nas-box',
    logger: (line) => logs.push(String(line)),
  });
  await pullNow(member);
  disablePush(hub);

  askFromHub(hub, '@nas-box 第一问');
  await pullNow(member);
  await member.server.group.waitAnswers();

  assert.equal(answersOf(hubMessages(hub)).length, 0, 'runner 报错 → 一条消息都不发');
  const skipped = logs.filter((line) => line.includes('[group] answer skipped'));
  assert.equal(skipped.length, 1, '失败只记一行');
  assert.match(skipped[0], /seq=\d+ reason=empty-reply/, '一行里只有 seq 与稳定 reason');
  assert.equal(skipped[0].includes('第一问'), false, '日志绝不带正文');

  // 常驻会话没有写坏：换成会答的 runner，再问一次 → 复用同一条会话并正常发帖
  runner.state.fail = false;
  runner.state.reply = '这次答了';
  askFromHub(hub, '@nas-box 第二问');
  await pullNow(member);
  await member.server.group.waitAnswers();

  assert.equal(runner.asks.length, 2);
  assert.equal(runner.asks[1].wanted, runner.asks[0].sessionId, '失败不改变常驻会话记录');
  const answers = answersOf(hubMessages(hub));
  assert.equal(answers.length, 1, '第二次有答案 → 一条答复');
  assert.equal(answers[0].meta.quote.seq, 2);
  assert.equal(answers[0].text, '这次答了');
});

test('3a A6 meta 白名单：quote 收下并收窄，未知键照旧丢掉（静默过滤，无错误码）', async (t) => {
  // 纯函数层：quote 是唯一的结构化例外，其余仍是标量白名单
  assert.deepEqual(
    sanitizeGroupMeta({ quote: { seq: 3, from: 'hub-box', excerpt: 'x'.repeat(120) }, peer: 'p' }),
    { quote: { seq: 3, from: 'hub-box', excerpt: 'x'.repeat(79) + '…' }, peer: 'p' },
  );
  assert.deepEqual(sanitizeGroupMeta({ evil: 'x' }), {}, '不在 GROUP_META_FIELDS 里的键直接丢弃');
  assert.deepEqual(sanitizeGroupMeta({ quote: { seq: 0, excerpt: 'y' } }), {}, 'seq 非正整数 = 非法 quote');

  // 线层：带 quote 的帖子必须被接收（老对端会拒 —— 0.10.0 的既定破坏性变更）
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER.peerId, MEMBER.name);
  const posted = await postAs(hub, MEMBER, '带引用', 'chat');
  assert.equal(posted.status, 201, posted.text);
  const withQuote = await request(hub.baseUrl, {
    method: 'POST',
    path: '/v1/group/post',
    peerId: MEMBER.peerId,
    secret: MEMBER.inboundSecret,
    body: { kind: 'chat', text: '带引用', meta: { quote: { seq: 1, from: 'x', excerpt: 'y' }, evil: 'z' } },
  });
  assert.equal(withQuote.status, 201, withQuote.text);
  const stored = hubMessages(hub).at(-1);
  assert.deepEqual(stored.meta, { quote: { seq: 1, from: 'x', excerpt: 'y' } }, 'quote 收下、evil 丢掉');
});

// ---------------------------------------------------------------------------
// 0.10.0-α slice 3b · hub 侧触发 / 多 @ / 无 @ 首答胜 / 抢答塌陷
//
// 共同前提：hub 与成员都喂假 runner（默认 MemoryRunner 会答成 "OK …"，断言就不确定了）。
// 每条用例都先 killPush：只留「自己 pull」这一条触发路径，去重才可断言。
// ---------------------------------------------------------------------------

const HUB_NAME = 'hub-box';

function killPush(hub, peerId) {
  const members = hub.server.group.state().members;
  if (members[peerId]) members[peerId].baseUrl = 'http://127.0.0.1:1';
}

const hubAuthored = (hub, text) => hub.server.group.post({
  peerId: hub.server.store.instanceId,
  name: HUB_NAME,
  kind: 'chat',
  text,
});

/** 群里引用了 seq 的那些 chat（= 答案） */
const quoting = (messages, seq) => messages.filter(
  (m) => m.kind === 'chat' && Number(m.meta?.quote?.seq) === Number(seq),
);

test('3b B1 hub 触发：成员发帖 @ 到 hub → hub 恰好一条带 quote 的答复（不许发两次）', async (t) => {
  const hubRunner = answerRunner({ reply: 'hub 答：还剩 42G' });
  const hub = await startHub(t, { runner: hubRunner, name: HUB_NAME });
  hub.server.group.addMember(MEMBER.peerId, MEMBER.name);

  const posted = await postAs(hub, MEMBER, '@hub-box 磁盘还剩多少');
  assert.equal(posted.status, 201, posted.text);
  await hub.server.group.waitAnswers();

  assert.equal(hubRunner.asks.length, 1, '@ 到 hub → 恰好一次 runner 调用');
  const answers = quoting(hubMessages(hub), 1);
  assert.equal(answers.length, 1, 'hub 只发一条答复（post 缝与复制缝不许各发一条）');
  assert.equal(answers[0].from.peerId, hub.server.store.instanceId, '作者必须是 hub 自己（不是空 peerId）');
  assert.equal(answers[0].text, 'hub 答：还剩 42G');
  assert.equal(answers[0].meta.quote.excerpt, '@hub-box 磁盘还剩多少');
});

test('3b B2 seq 幂等：同一条消息从复制缝投两遍 → 只答一次、只发一条', async (t) => {
  // hub 拒绝收副本（409 not-a-replica，hub 就是 leader），所以双投递在成员侧复现：
  // 同一个 seq 走两遍 /v1/group/replicate —— 第二遍连派发都不该进（副本按 seq 去重），
  // 就算进了也有「群:seq」认领兜住（见 lib/group-resident.test.mjs 的认领用例）。
  const hub = await startHub(t, { runner: answerRunner({ fail: true }), name: HUB_NAME });
  hub.server.group.addMember(MEMBER.peerId, MEMBER.name);
  const runner = answerRunner({ reply: '答：42G' });
  const member = await startMember(t, {
    hubBaseUrl: hub.baseUrl, hubInstanceId: hub.server.store.instanceId, runner, name: 'nas-box',
  });
  await pullNow(member);
  killPush(hub, MEMBER.peerId);

  const state = hub.server.group.state({ includeKey: true });
  const question = hubAuthored(hub, '@nas-box 磁盘还剩多少');
  const body = {
    groupId: state.groupId,
    epoch: 1,
    leaderPeerId: hub.server.store.instanceId,
    messages: [question],
  };
  const deliver = () => groupRequest(member.baseUrl, {
    groupKey: state.groupKey,
    groupId: state.groupId,
    senderId: hub.server.store.instanceId,
    method: 'POST',
    path: '/v1/group/replicate',
    body,
  });
  const first = await deliver();
  assert.equal(first.status, 200, first.text);
  assert.equal(first.json.added, 1);
  await member.server.group.waitAnswers();
  assert.equal(runner.asks.length, 1, '第一次投递 → 一问一答');

  const second = await deliver();
  assert.equal(second.status, 200, second.text);
  assert.equal(second.json.added, 0, '同一个 seq 不许二次入库');
  await member.server.group.waitAnswers();
  assert.equal(runner.asks.length, 1, '第二次投递不再触发答题');
  const memberAnswers = hubMessages(hub).filter((m) => m.from.peerId === MEMBER.peerId);
  assert.equal(memberAnswers.length, 1, '答复只发一条');
  assert.equal(memberAnswers[0].meta.quote.seq, question.seq);
});

test('3b B3 多 @：一条消息 @ 两台成员机 → 两条答复，引用同一个 seq', async (t) => {
  const hub = await startHub(t, { runner: answerRunner({ fail: true }), name: HUB_NAME });
  hub.server.group.addMember(MEMBER.peerId, MEMBER.name);
  hub.server.group.addMember(MEMBER2.peerId, MEMBER2.name);
  const runnerA = answerRunner({ reply: 'A 在' });
  const runnerB = answerRunner({ reply: 'B 在' });
  const a = await startMember(t, {
    hubBaseUrl: hub.baseUrl, hubInstanceId: hub.server.store.instanceId, identity: MEMBER, runner: runnerA, name: 'nas-box',
  });
  const b = await startMember(t, {
    hubBaseUrl: hub.baseUrl, hubInstanceId: hub.server.store.instanceId, identity: MEMBER2, runner: runnerB, name: 'nas-box2',
  });
  await pullNow(a);
  await pullNow(b);
  killPush(hub, MEMBER.peerId);
  killPush(hub, MEMBER2.peerId);

  const question = hubAuthored(hub, '@nas-box @nas-box2 谁在');
  await pullNow(a);
  await pullNow(b);
  await a.server.group.waitAnswers();
  await b.server.group.waitAnswers();

  assert.equal(runnerA.asks.length, 1, '被点名的第一台答一次');
  assert.equal(runnerB.asks.length, 1, '被点名的第二台也答一次（不是只答第一个）');
  const answers = quoting(hubMessages(hub), question.seq);
  assert.equal(answers.length, 2, '两台被点名的机器各一条答复');
  assert.deepEqual(
    answers.map((m) => m.from.peerId).sort(),
    [MEMBER.peerId, MEMBER2.peerId].sort(),
    '两条答复来自两台不同的机器',
  );
});

test('3b B4 无 @：没人答过 → 一台答一条；已经有人答过 → 后来者一条都不发', async (t) => {
  const hub = await startHub(t, { runner: answerRunner({ fail: true }), name: HUB_NAME });
  hub.server.group.addMember(MEMBER.peerId, MEMBER.name);
  hub.server.group.addMember(MEMBER2.peerId, MEMBER2.name);
  const runnerA = answerRunner({ reply: '答：还剩 42G' });
  const runnerB = answerRunner({ reply: '我也来答' });
  const a = await startMember(t, {
    hubBaseUrl: hub.baseUrl, hubInstanceId: hub.server.store.instanceId, identity: MEMBER, runner: runnerA, name: 'nas-box',
  });
  await pullNow(a);
  killPush(hub, MEMBER.peerId);

  const question = hubAuthored(hub, '磁盘还剩多少');
  await pullNow(a);
  await a.server.group.waitAnswers();

  assert.equal(runnerA.asks.length, 1, '没人答过 → 这台答一次');
  const first = quoting(hubMessages(hub), question.seq);
  assert.equal(first.length, 1, '群里一条答复');
  assert.equal(first[0].from.peerId, MEMBER.peerId);
  assert.equal(first[0].text, '答：还剩 42G');

  // 后来才上线的第二台：bootstrap + 补差时这条已经被答过了 → 零调用零发帖
  const b = await startMember(t, {
    hubBaseUrl: hub.baseUrl, hubInstanceId: hub.server.store.instanceId, identity: MEMBER2, runner: runnerB, name: 'nas-box2',
  });
  await pullNow(b);
  await b.server.group.waitAnswers();
  assert.equal(runnerB.asks.length, 0, 'B9 哨兵：拆掉第 (a) 道复查后这里会变成 1');
  assert.equal(
    hubMessages(hub).filter((m) => m.from.peerId === MEMBER2.peerId).length, 0,
    '一条都不许发',
  );
});

test('3b B5 抢答塌陷：两个节点都过了资格检查，先答的落地后，后者的发帖前复查必须丢掉它', async (t) => {
  const logsB = [];
  const hub = await startHub(t, { runner: answerRunner({ fail: true }), name: HUB_NAME });
  hub.server.group.addMember(MEMBER.peerId, MEMBER.name);
  hub.server.group.addMember(MEMBER2.peerId, MEMBER2.name);
  const runnerA = answerRunner({ reply: 'A 先答' });
  const runnerB = answerRunner({ reply: 'B 后答' });
  const a = await startMember(t, {
    hubBaseUrl: hub.baseUrl, hubInstanceId: hub.server.store.instanceId, identity: MEMBER, runner: runnerA, name: 'nas-box',
  });
  const b = await startMember(t, {
    hubBaseUrl: hub.baseUrl,
    hubInstanceId: hub.server.store.instanceId,
    identity: MEMBER2,
    runner: runnerB,
    name: 'nas-box2',
    logger: (line) => logsB.push(String(line)),
  });
  await pullNow(a);
  await pullNow(b);
  killPush(hub, MEMBER.peerId);
  killPush(hub, MEMBER2.peerId);

  const question = hubAuthored(hub, '磁盘还剩多少');

  // 两个节点都通过 check (a)：B 先起跑并卡在「答题中」，A 随后答完发帖
  runnerB.state.hold = true;
  await pullNow(b);
  await sleep(400); // 让 B 走完抖动 + check (a)，进入 runner 等待
  await pullNow(a);
  await a.server.group.waitAnswers();
  assert.equal(quoting(hubMessages(hub), question.seq).length, 1, 'A 的答案已经落地');
  assert.equal(runnerB.asks.length, 1, 'B 也已经过了 check (a) 并开始答题');

  // B 现在拿得到 A 的答案（本地已知消息的唯一来源），再放行它的 runner
  await pullNow(b);
  runnerB.state.hold = false;
  await b.server.group.waitAnswers();

  const answers = quoting(hubMessages(hub), question.seq);
  assert.equal(answers.length, 1, 'B9 哨兵：拆掉发帖前复查后这里会变成 2');
  assert.equal(answers[0].from.peerId, MEMBER.peerId, '留下的是先答的那条');
  const drops = logsB.filter((line) => line.includes('[group] answer dropped'));
  assert.equal(drops.length, 1, '丢掉一次，只记一行');
  assert.match(drops[0], /seq=\d+ reason=answered-first/);
  assert.equal(drops[0].includes('磁盘'), false, '日志绝不带正文');
});


// ---------------------------------------------------------------------------
// 0.10.0-α slice 4a：群纪要（hub 单写、成员只读同步）
//
// N4：hub 从**管理接口**追加 → GET group 回 rev+1；成员 POST 被 403 notes-hub-only。
// N5：纪要搭同一次 pull 同步到成员副本；成员没有写路径（管理接口拒 + 群里拒 + 不落 hub 那份文件）。
// ---------------------------------------------------------------------------

/** 管理接口的最小请求/应答桩（与 lib/admin-group.test.mjs 同款，只留必需的头） */
function adminRequest(admin, method, url, body) {
  const chunks = body === undefined ? [] : [Buffer.from(JSON.stringify(body))];
  const req = {
    method,
    url,
    socket: { remoteAddress: '127.0.0.1', setNoDelay() {} },
    headers: {
      host: '127.0.0.1:7788',
      'content-type': 'application/json',
      'content-length': String(chunks[0]?.length ?? 0),
      'x-lan-peers-token': String(admin.token ?? ''),
    },
    on() { return req; },
    once() { return req; },
    async *[Symbol.asyncIterator]() { for (const chunk of chunks) yield chunk; },
  };
  const res = {
    status: 0, headers: {}, body: '',
    setHeader(k, v) { this.headers[k] = v; },
    writeHead(status, headers) { this.status = status; Object.assign(this.headers, headers || {}); },
    write(chunk) { this.body += chunk; return true; },
    end(chunk) { if (chunk) this.body += chunk; if (!this.status) this.status = 200; },
    once() {}, on() {},
  };
  return { req, res };
}

async function hitAdmin(admin, method, apiPath, body) {
  const { req, res } = adminRequest(admin, method, apiPath, body);
  await admin.handle(req, res, new URL('http://127.0.0.1' + apiPath));
  return { status: res.status, json: (() => { try { return JSON.parse(res.body); } catch { return null; } })() };
}

test('4a N4：hub 从管理接口追加纪要 → GET group 回 rev+1；成员 POST 被 403 notes-hub-only', async (t) => {
  const { createAdmin } = await import('../../lib/admin.mjs');
  const cluster = await startCluster(t, { count: 2 });
  const [hub, member] = cluster.nodes;
  const hubAdmin = createAdmin({ server: hub.server });

  // 1) hub 运维者在面板/CLI 上追加一条 → 200 + rev
  const first = await hitAdmin(hubAdmin, 'POST', '/api/lan-peers/group/notes', { text: '十月计划：先做纪要' });
  assert.equal(first.status, 200, JSON.stringify(first.json));
  assert.equal(first.json.rev, 1);
  assert.equal(first.json.note.text, '十月计划：先做纪要');

  // 2) 群状态那条 GET 带着纪要回来（面板的 2s 节拍不新增请求）
  const state = await hitAdmin(hubAdmin, 'GET', '/api/lan-peers/group?sinceSeq=0');
  assert.equal(state.json.notes.rev, 1);
  assert.deepEqual(state.json.notes.notes.map((entry) => entry.text), ['十月计划：先做纪要']);
  assert.deepEqual(state.json.notesSummary, { count: 1, rev: 1, lastAt: state.json.notes.notes[0].createdAt });

  // 3) 群级 HTTP：成员 GET 拿得到（成员允许），rev/正文一致
  const got = await fetchGroupNotes({
    baseUrl: hub.baseUrl, groupKey: cluster.groupKey, groupId: cluster.groupId, senderId: member.peerId,
  });
  assert.equal(got.rev, 1);
  assert.equal(got.notes[0].text, '十月计划：先做纪要');

  // 4) 群级 HTTP：成员 POST → 403 notes-hub-only（门在 handler，不在白名单）
  await assert.rejects(
    () => postGroupNote({
      baseUrl: hub.baseUrl, groupKey: cluster.groupKey, groupId: cluster.groupId,
      senderId: member.peerId, text: '成员想写一条',
    }),
    (error) => {
      assert.equal(error.status, 403, '成员写纪要必须 403，实测 ' + String(error.message));
      assert.equal(error.code, 'notes-hub-only');
      return true;
    },
  );
  assert.equal(hub.server.group.notes().notes.length, 1, '被拒的那次一个字都没落盘');
});

test('4a N5：纪要随 pull 同步到成员副本；成员没有任何写路径', async (t) => {
  const { createAdmin } = await import('../../lib/admin.mjs');
  const cluster = await startCluster(t, { count: 2 });
  const [hub, member] = cluster.nodes;
  const hubNotesFile = path.join(hub.dir, 'group-notes.json');
  const memberNotesFile = path.join(member.dir, 'group-notes.json');

  assert.equal(hub.server.group.appendNote({ text: '第一条纪要' }).ok, true);
  const second = hub.server.group.appendNote({ text: '第二条纪要' });
  assert.equal(second.rev, 2);
  assert.equal(fs.existsSync(hubNotesFile), true, 'hub 有自己的纪要文件');

  // 成员靠**既有的** pull 拿到纪要（没有新轮询）
  assert.equal(member.server.group.notes().rev, 0, '同步前成员什么都还没有');
  const pulled = await pullNow(member);
  assert.equal(pulled?.ok, true, '成员这一轮 pull 必须真跑起来：' + JSON.stringify(pulled));
  const synced = member.server.group.notes();
  assert.equal(synced.rev, 2);
  assert.deepEqual(synced.notes.map((entry) => entry.text), ['第一条纪要', '第二条纪要']);

  // 成员那份落在**副本文件**里，绝不写 hub 的 group-notes.json
  assert.equal(fs.existsSync(memberNotesFile), false, '成员不许写纪要文件（那本是 hub 的）');
  const replica = readJson(path.join(member.dir, 'group-replica.json'));
  assert.equal(replica.notes.rev, 2, '纪要存在成员自己的副本里');

  // 写路径：管理接口按 isHub 先拒
  const memberAdmin = createAdmin({ server: member.server });
  const refused = await hitAdmin(memberAdmin, 'POST', '/api/lan-peers/group/notes', { text: '成员要写' });
  assert.equal(refused.status, 403);
  assert.deepEqual(refused.json, { error: 'notes-hub-only' });
  // 门面这一侧也一样（面板/CLI 走的是同一条门面）
  assert.deepEqual(member.server.group.appendNote({ text: '成员要写' }), { ok: false, error: 'notes-hub-only' });
  assert.equal(fs.existsSync(memberNotesFile), false, '成员侧没有任何写纪要文件的代码路径');
});


// ---------------------------------------------------------------------------
// 0.10.0-α slice 4b-1：群表决平面（hub 单写、成员只读同步）
//
// V7：成员能**提交**提案/投票（输入），但开轮/推进/结算只有 hub 能叫（403 votes-hub-only）；
//     权威文件只有 hub 有，成员那份只是 pull 同步来的副本。
// V8：一轮恰好一个定时器；关轮与 close() 都清掉（进程能自己退出，不吊住句柄）。
// ---------------------------------------------------------------------------

/** 群级调用：一律走 lib/group-client 的 groupCall（与 CLI/成员侧同一套签名） */
const groupCallTo = (cluster, senderId, apiPath, body, method = 'POST') => groupCall({
  baseUrl: cluster.hub.baseUrl,
  groupKey: cluster.groupKey,
  groupId: cluster.groupId,
  senderId,
  apiPath,
  method,
  ...(body === undefined ? {} : { body }),
});

test('4b-1 V7：成员可提交提案/投票，开轮与推进一律 403 votes-hub-only；权威文件只在 hub', async (t) => {
  const cluster = await startCluster(t, { count: 2 });
  const [hub, member] = cluster.nodes;
  const hubVotesFile = path.join(hub.dir, 'group-votes.json');
  const memberVotesFile = path.join(member.dir, 'group-votes.json');
  // 「轮内新来的人」那一侧：它是**群成员**（群签名有效），但 peers.json 里根本没有它
  // → lastSeen 永远是 null → 永远在冻结名单之外。用它证明「上线晚的人进不了本轮」。
  const ghost = { peerId: 'peer-ghost', name: 'ghost' };
  hub.server.group.addMember(ghost.peerId, ghost.name);

  // 1) 成员提交「补充」：入库 + 默认采纳（没有异议就不开票）
  const supplement = await groupCallTo(cluster, member.peerId, '/v1/group/proposal', {
    // body 里自称的作者一律不认：作者永远是**签名者**
    kind: 'supplement', target: { type: 'body', id: 'n1' }, text: '十月计划再补一条', author: '有人冒名',
  });
  assert.equal(supplement.ok, true);
  assert.equal(supplement.proposal.kind, 'supplement');
  assert.equal(supplement.status, 'adopted', '补充默认采纳：不该为它开票');
  assert.equal(supplement.vote, null);
  assert.equal(fs.existsSync(hubVotesFile), true, 'hub 有自己的表决平面文件');
  assert.equal(fs.existsSync(memberVotesFile), false, '成员侧根本没有写权威文件的路径');
  if (process.platform !== 'win32') assert.equal(fileMode(hubVotesFile), 0o600, '表决平面必须 0600');

  // 2) 成员提交「反对」→ **自动开票**（第 1 轮，名单在这一刻冻结）
  const objection = await groupCallTo(cluster, member.peerId, '/v1/group/proposal', {
    kind: 'objection', target: { type: 'supplement', id: supplement.proposal.id }, text: '这条我不认同',
  });
  assert.equal(objection.status, 'open', '反对一到就开票');
  assert.equal(objection.vote.round, 1);
  const voteId = objection.proposal.id;
  const opened = hub.server.group.votes().votes[voteId];
  assert.equal(opened.status, 'open');
  assert.equal(hub.server.group.voteTimers(), 1, '开着一轮就恰好挂一个定时器');

  // 3) 成员读：提案列表与单轮台账都允许（只读同步的那一半）
  const listed = await groupCallTo(cluster, member.peerId, '/v1/group/proposals', undefined, 'GET');
  assert.equal(listed.proposals.length, 2);
  assert.deepEqual(listed.shelved, []);
  assert.deepEqual(listed.summary.proposals, 2);
  // 「默认采纳」的前提是没人反对：被反对指着的那条补充不能再自称 adopted
  assert.equal(listed.proposals.find((entry) => entry.id === supplement.proposal.id).status, 'contested');
  assert.equal(listed.proposals.find((entry) => entry.id === voteId).status, 'open');
  const ledger = await groupCallTo(cluster, member.peerId, '/v1/group/vote?proposalId=' + voteId, undefined, 'GET');
  assert.equal(ledger.vote.proposalId, voteId);
  assert.deepEqual(ledger.roster, opened.roster, '台账里的冻结名单就是开轮那一刻的那份');

  // 4) 冻结名单：从没上线的第 3 台成员投不了（原因写进返回值）
  const rejected = await groupCallTo(cluster, ghost.peerId, '/v1/group/vote', { proposalId: voteId, ballot: 'yes' });
  assert.equal(rejected.accepted, false);
  assert.equal(rejected.reason, 'vote-not-eligible', '名单外的人不许投票：' + JSON.stringify(rejected));
  assert.deepEqual(hub.server.group.votes().votes[voteId].ballots, {}, '被拒的票一个字都没落盘');

  // 5) 成员**不能**开轮/推进/结算（Z3 的拒绝码 votes-hub-only）
  for (const apiPath of ['/v1/group/vote/open', '/v1/group/vote/advance']) {
    await assert.rejects(
      () => groupCallTo(cluster, member.peerId, apiPath, { proposalId: voteId }),
      (error) => {
        assert.equal(error.status, 403, apiPath + ' 必须 403，实测 ' + String(error.message));
        assert.equal(error.code, 'votes-hub-only');
        return true;
      },
    );
  }
  // 成员门面同样没有写路径（不是「还没实现」，是成员永远没有）
  assert.deepEqual(
    member.server.group.submitProposal({ kind: 'supplement', target: { type: 'body', id: 'n1' }, text: 'x' }),
    { ok: false, error: 'votes-hub-only' },
  );
  assert.deepEqual(member.server.group.closeVote(voteId), { ok: false, error: 'votes-hub-only' });
  assert.equal(member.server.group.voteTimers(), 0);

  // 6) 名单上的人全投 yes → 够票立刻关（passed），定时器随之清掉
  for (const peerId of opened.roster) {
    const cast = hub.server.group.castVote({ proposalId: voteId, peerId, ballot: 'yes' });
    assert.equal(cast.accepted, true, peerId + ' 的票必须被收下：' + cast.reason);
  }
  const settled = hub.server.group.votes().votes[voteId];
  assert.equal(settled.status, 'passed', opened.roster.length + ' 人名单全 yes 必须通过');
  assert.equal(hub.server.group.voteTimers(), 0, '关轮必须清掉定时器');

  // 7) 幂等：hub 自己再推进一次 = no-op（不许双推进）
  const advanced = await groupCallTo(cluster, hub.peerId, '/v1/group/vote/advance', { proposalId: voteId });
  assert.equal(advanced.already, true, '已结算的轮重复推进必须 no-op');
  assert.equal(advanced.vote.round, 1, '不许把 passed 推成下一轮');
  assert.equal(advanced.vote.status, 'passed');

  // 8) 成员只读同步：搭同一次 pull 回来，落进**副本**（权威文件在成员侧始终不存在）
  const hubPlaneNow = hub.server.group.votes();
  const pulled = await pullNow(member);
  assert.equal(pulled?.ok, true, '成员这一轮 pull 必须真跑起来：' + JSON.stringify(pulled));
  const replicaPlane = member.server.group.votes();
  assert.ok(replicaPlane.rev >= 1, '表决平面必须搭同一次 pull 回来');
  assert.equal(replicaPlane.rev, hubPlaneNow.rev, '成员副本停在与 hub 同一份 rev 上');
  assert.deepEqual(replicaPlane.proposals.map((entry) => entry.id), ['p1', voteId]);
  assert.equal(replicaPlane.votes[voteId].status, 'passed');
  assert.equal(readJson(replicaFileOf(member.dir)).votes.votes[voteId].status, 'passed', '平面存在成员自己的副本里');
  assert.equal(fs.existsSync(memberVotesFile), false, '成员不许写权威文件（那本是 hub 的）');
  // hub 那份仍是唯一权威：成员提交的那两条都在，作者是成员名
  const hubPlane = readJson(hubVotesFile);
  assert.equal(hubPlane.proposals.length, 2);
  const author = hubPlane.proposals[0].author;
  const hubMemberName = hub.server.group.members().find((entry) => entry.peerId === member.peerId)?.name ?? '';
  assert.equal(author === '有人冒名', false, 'body 里自称的作者必须被忽略');
  assert.ok(author.length > 0, '作者口径必须来自 hub 记的成员名，不能为空');
  assert.ok(
    hubMemberName.startsWith(author) || author.startsWith(hubMemberName),
    `作者应是 hub 记的那个成员（同名时带短 id 后缀）：${author} vs ${hubMemberName}`,
  );
});

test('4b-1 V8：一轮一个定时器；关轮与 close() 都清掉（进程能自己退出）', async (t) => {
  const lines = [];
  // 轮时长压到 400ms：既不真等 10 分钟，又给同步断言留足余量（不会和定时器抢跑）
  const hub = await startHub(t, { voteRoundMs: 400, logger: (line) => lines.push(String(line)) });
  const g = hub.server.group;
  assert.equal(g.voteTimers(), 0, '一开始没有表决定时器');

  const opened = g.submitProposal({ kind: 'objection', target: { type: 'body', id: 'n1' }, text: '这条要表决', author: 'hub-box' });
  assert.equal(opened.ok, true, JSON.stringify(opened));
  const voteId = opened.proposal.id;
  assert.equal(g.voteTimers(), 1, '开一轮 → 恰好一个定时器');
  assert.equal(g.votes().votes[voteId].round, 1);

  // 到点自己关（**没有流量也要关**）：第 1 轮 failed，第 2 轮用新冻结的名单重开
  const secondRound = await waitFor(() => (g.votes().votes[voteId].round === 2 ? g.votes().votes[voteId] : null));
  assert.ok(secondRound, '到点必须自己关轮：' + JSON.stringify(g.votes().votes[voteId]));
  assert.equal(secondRound.status, 'open');
  assert.equal(g.voteTimers(), 1, '换轮不叠加定时器：仍然只有一个');

  // 第 2 轮：名单上唯一的成员投 no → 剩下的人全 yes 也够不到 → **提前关**（不等 closesAt）
  const roster = g.votes().votes[voteId].roster;
  assert.equal(roster.length, 1, 'startHub 的群成员只有 hub 自己');
  const no = g.castVote({ proposalId: voteId, peerId: roster[0], ballot: 'no' });
  assert.equal(no.accepted, true, '名单上的票必须被收下：' + no.reason);
  assert.equal(no.closed, true, '没救了就该立刻关：' + JSON.stringify(no));
  assert.equal(g.votes().votes[voteId].round, 3, '第 2 轮失败 → 第 3 轮（不是被推两轮）');
  assert.equal(g.voteTimers(), 1, '第 3 轮重新挂定时器');

  // 第 3 轮也过不了 → shelved、进 shelved 集、不再开第 4 轮、不留定时器
  const third = g.castVote({ proposalId: voteId, peerId: roster[0], ballot: 'no' });
  assert.equal(third.closed, true);
  assert.equal(g.votes().votes[voteId].status, 'shelved');
  assert.deepEqual(g.shelved().map((entry) => entry.proposalId), [voteId], 'shelved 集里必须有它（交人裁决）');
  assert.equal(g.shelved()[0].rounds, 3);
  assert.equal(g.voteTimers(), 0, 'shelved 之后不许再留定时器');
  const againCall = g.closeVote(voteId);
  assert.equal(againCall.already, true, '已结算/已 shelved 的轮重复推进必须 no-op');
  assert.equal(g.votes().votes[voteId].round, 3, '绝不开第 4 轮');

  // 日志口径：每条状态迁移一行，id ≤8 字符，且**绝不带提案正文**
  const voteLines = lines.filter((line) => line.startsWith('[group] vote ') || line.startsWith('[group] proposal '));
  assert.ok(voteLines.some((line) => /^\[group\] vote open id=\S{1,8} round=1 roster=\d+$/.test(line)), voteLines.join('\n'));
  assert.ok(voteLines.some((line) => /^\[group\] vote close id=\S{1,8} round=1 yes=0 no=0 outcome=failed$/.test(line)), voteLines.join('\n'));
  assert.ok(voteLines.some((line) => /^\[group\] vote close id=\S{1,8} round=2 yes=0 no=1 outcome=failed$/.test(line)), voteLines.join('\n'));
  assert.ok(voteLines.some((line) => /^\[group\] vote shelved id=\S{1,8} rounds=3$/.test(line)), voteLines.join('\n'));
  assert.equal(lines.some((line) => line.includes('这条要表决')), false, '日志里绝不许出现提案正文');

  // 再开一轮，然后 close()：定时器必须被清掉（上一片的吊死就是这里漏了）
  const another = g.submitProposal({ kind: 'objection', target: { type: 'body', id: 'n2' }, text: '再开一轮', author: 'hub-box' });
  assert.equal(another.status, 'open');
  assert.equal(g.voteTimers(), 1);
  await hub.server.close();
  assert.equal(g.voteTimers(), 0, 'close() 必须清掉表决定时器（否则进程吊死）');
});
