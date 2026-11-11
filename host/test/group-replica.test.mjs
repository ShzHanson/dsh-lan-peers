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

const MEMBER = peerFixture('peer-replica-1');
const MEMBER2 = peerFixture('peer-replica-2');

const DAY = 86_400_000;

/** hub：stateDir 由调用方持有，便于「杀掉再重启」 */
async function startHub(t, { stateDir = makeTempStateDir(), group = {}, runner, name, logger } = {}) {
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

