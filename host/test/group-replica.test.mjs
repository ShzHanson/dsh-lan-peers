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
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { createPeerServer, GroupReplicaStore } from '../server.mjs';
import { deriveGroupKeys, decryptGroupJson, encryptGroupBody, groupAuthHeaders } from '../../lib/group-client.mjs';
import { fileMode, makeTempStateDir, peerFixture, readJson, request, seedPeers, writeJson0600 } from './helpers.mjs';

const MEMBER = peerFixture('peer-replica-1');
const MEMBER2 = peerFixture('peer-replica-2');

const DAY = 86_400_000;

/** hub：stateDir 由调用方持有，便于「杀掉再重启」 */
async function startHub(t, { stateDir = makeTempStateDir(), group = {} } = {}) {
  seedPeers(stateDir, [MEMBER, MEMBER2]);
  const server = createPeerServer({
    listenHost: '127.0.0.1',
    stateDir,
    requireEncryption: false,
    allowRemotePrompts: true,
    // S3 起 majority 会把 post 变成 propose→commit（复制失败就不再是 201）；
    // 这个文件测的是 S2 的复制语义，固定 quorum:「none」= 写本地即提交。
    group: { enabled: true, name: 'default', autoJoin: true, retentionDays: 7, quorum: 'none', ...group },
  });
  const info = await server.listen(0, '127.0.0.1');
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

async function startMember(t, { hubBaseUrl, hubInstanceId, identity = MEMBER, group = {}, stateDir }) {
  const dir = stateDir ?? memberStateDir(t, { hubBaseUrl, hubInstanceId, identity });
  const server = createPeerServer({
    listenHost: '127.0.0.1',
    stateDir: dir,
    requireEncryption: false,
    // autoJoin：成员 bootstrap 被 hub 回 403 not-a-member 时自助加入一次（S2 的正常上线路径）
    group: { enabled: true, hub: 'hub', autoJoin: true, ...group },
    // 测试自己驱动补差，不让后台定时器插进来
    groupReplica: { pullIntervalMs: 600_000 },
  });
  const info = await server.listen(0, '127.0.0.1');
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
  const info = await restarted.listen(0, '127.0.0.1');
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

