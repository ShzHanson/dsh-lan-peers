/**
 * hub 侧提交语义回归（「群协议核心不一致」那一刀）。
 *
 * 两个目标：
 *   1. hub 自己的发言（面板 `server.group.post` 的直写分支、派单回执）必须是**提交完备**的：
 *      写权威日志 → 同步推进 commitSeq → 入复制队列。修前只做第一件事：真机 NAS 上
 *      `seq=74 kind=chat "测试效果"` commitSeq 永远停在 73，pending 里也没有条目。
 *   2. 已经卡住的历史尾巴由**启动期对账**修平：区间里的 seq 确实都在 messages 里才推进，
 *      有缺口一条都不动并记一行告警；对账幂等（重启不重复写、不重复记日志）。
 *
 * 全程真两实例（真监听 / 真签名 / 真群密钥），不拿桩冒充成员。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import { createPeerServer } from '../server.mjs';
import { listenOnRandomPort } from '../../test-support/ports.mjs';
import { makeTempStateDir, peerFixture, readJson, seedPeers, writeJson0600 } from './helpers.mjs';
import { startCluster } from './group-cluster.mjs';

const HUB = peerFixture('peer-hubc-1', { name: 'hub' });
const MEMBER = peerFixture('peer-hubc-2', { name: 'memberc' });

async function waitFor(check, { timeoutMs = 6_000, intervalMs = 20 } = {}) {
  const deadline = Date.now() + timeoutMs;
  let last;
  while (Date.now() < deadline) {
    last = await check();
    if (last) return last;
    await sleep(intervalMs);
  }
  return last;
}

const replicaFileOf = (dir) => path.join(dir, 'group-replica.json');

/** 后台首轮 tick 可能正占着 memberInFlight，pull() 只会回 skipped —— 等到真跑完一轮 */
async function pullNow(member, attempts = 40) {
  for (let index = 0; index < attempts; index += 1) {
    const out = await member.server.group.pull();
    if (out?.reason !== 'skipped') return out;
    await sleep(25);
  }
  throw new Error('pull 一直被后台那一轮占着（reason=skipped）');
}

/**
 * 两个真实例：hub（hub 角色 = 初始 leader）+ 成员。
 * hub 的复制重试节奏由用例决定：600s = 推送完全不参与（纯 pull 用例）；
 * 120ms = 推送在毫秒级落地（纯复制用例）。
 */
async function startTwoInstances(t, { hubReplica }) {
  const hubDir = makeTempStateDir('dsh-lan-peers-hubcommit-');
  const memberDir = makeTempStateDir('dsh-lan-peers-hubcommit-');
  t.after(() => {
    fs.rmSync(hubDir, { recursive: true, force: true });
    fs.rmSync(memberDir, { recursive: true, force: true });
  });
  seedPeers(hubDir, [MEMBER]);
  writeJson0600(path.join(hubDir, 'state.json'), {
    instanceId: HUB.peerId,
    name: HUB.name,
    createdAt: new Date().toISOString(),
  });

  const hubLogs = [];
  const hub = createPeerServer({
    listenHost: '127.0.0.1',
    stateDir: hubDir,
    requireEncryption: false,
    logger: (line) => hubLogs.push(String(line)),
    group: { enabled: true, name: 'default', autoJoin: true, retentionDays: 7 },
    groupReplica: hubReplica,
    // 心跳拉长到 30s：心跳会顺带触发成员补差（契约 §5），那就分不清「推送」与「pull」了
    groupElection: { heartbeatMs: 30_000, jitterMs: 0 },
  });
  const hubInfo = await listenOnRandomPort(hub);
  hub.config.group.advertiseBaseUrl = hubInfo.url;
  t.after(async () => { await hub.close(); });

  writeJson0600(path.join(memberDir, 'state.json'), {
    instanceId: MEMBER.peerId,
    name: MEMBER.name,
    createdAt: new Date().toISOString(),
  });
  writeJson0600(path.join(memberDir, 'peers.json'), {
    peers: {
      [HUB.peerId]: {
        name: HUB.name,
        baseUrl: hubInfo.url,
        secret: MEMBER.inboundSecret,
        inboundSecret: 'unused-outbound',
        addedAt: new Date().toISOString(),
        lastSeen: null,
      },
    },
  });
  const member = createPeerServer({
    listenHost: '127.0.0.1',
    stateDir: memberDir,
    requireEncryption: false,
    group: { enabled: true, hub: HUB.name, autoJoin: true },
    // 成员侧后台补差关掉：这一条用例只观察 hub 主动推送
    groupReplica: { pullIntervalMs: 600_000 },
    groupElection: { heartbeatMs: 30_000, jitterMs: 0 },
  });
  const memberInfo = await listenOnRandomPort(member);
  member.config.group.advertiseBaseUrl = memberInfo.url;
  t.after(async () => { await member.close(); });

  // bootstrap + 自报地址：hub 之后才知道往哪推
  await pullNow({ server: member });
  // 地址写死成回环（与 group-cluster 同一口径）：否则 hub 学到的是探测出的私网 IP，
  // 「推送失败 → 成员自己 pull 兜上来」会冒充复制成功，这条用例就失去了意义
  member.config.group.advertiseBaseUrl = memberInfo.url;
  const memberRow = hub.group.state().members[MEMBER.peerId];
  if (memberRow) memberRow.baseUrl = memberInfo.url;
  return { hub: { server: hub, dir: hubDir, logs: hubLogs }, member: { server: member, dir: memberDir } };
}

// ---------------------------------------------------------------------------
// 1. hub 单机发言：commitSeq 与 lastSeq 同步推进（AC1 / AC3）
// ---------------------------------------------------------------------------

test('AC1/AC3 hub 单机发言：commitSeq 与 lastSeq 同步推进，消息进权威日志、pending 无残留', async (t) => {
  const cluster = await startCluster(t, { count: 1 });
  const hub = cluster.nodes[0];
  assert.equal(hub.server.group.role().role, 'leader', '单机 hub 必须自己就是 leader（quorum 只有自己）');

  const posted = hub.server.group.post({ kind: 'chat', text: 'hub 单机发言' });
  assert.equal(Number(posted?.seq), 1, '门面仍同步返回带 seq 的那条消息');

  const after = hub.server.group.role();
  assert.equal(hub.server.group.lastSeq(), 1);
  assert.equal(after.commitSeq, 1, 'commitSeq 必须跟着推进（修前在这里停在 0）');
  assert.equal(after.commitSeq, hub.server.group.lastSeq(), 'commitSeq === lastSeq');
  assert.equal(after.pendingCount, 0, '直写不是提案，pending 里不该有残留');
  assert.equal(hub.server.group.state().pendingCount, 0);

  const history = hub.server.group.history({ sinceSeq: 0 });
  assert.deepEqual(history.map((m) => m.seq), [1], '消息确实在权威日志 messages 里');
  assert.equal(history[0].text, 'hub 单机发言');

  // 连发两条：seq 连续、水位继续同步（没有成员也不能卡住/报错）
  const second = hub.server.group.post({ kind: 'chat', text: '第二条' });
  assert.equal(Number(second?.seq), 2);
  const third = hub.server.group.role();
  assert.equal(third.commitSeq, second.seq);
  assert.equal(third.commitSeq, hub.server.group.lastSeq());
});

// ---------------------------------------------------------------------------
// 2. 有成员在线：hub 发言 → 成员通过既有 pull / 复制收到（AC2）
// ---------------------------------------------------------------------------

test('AC2a hub 发言 → 成员靠既有 pull 收到（真两实例，推送被关掉）', async (t) => {
  const rig = await startTwoInstances(t, { hubReplica: { retryMs: 600_000 } });
  // 与面板同一个形状：作者写本机（不带 peerId 的写法作者为空，成员侧 H2 会按 unknown-author 丢弃）
  const posted = rig.hub.server.group.post({
    peerId: HUB.peerId,
    name: HUB.name,
    kind: 'chat',
    text: 'pull 目标',
  });
  assert.equal(Number(posted?.seq), 1);
  assert.equal(rig.hub.server.group.role().commitSeq, 1, 'hub 侧先自洽');

  const pulled = await pullNow(rig.member);
  assert.equal(pulled.ok, true, JSON.stringify(pulled));
  assert.equal(pulled.added, 1, '成员这一轮就该补到 1 条');

  const replica = readJson(replicaFileOf(rig.member.dir));
  assert.equal(replica.lastSeq, 1);
  assert.deepEqual(replica.messages.map((m) => m.text), ['pull 目标']);
  assert.equal(
    rig.hub.logs.some((line) => line.includes('[group] replicate peer=')),
    false,
    '推送被关掉时应答话的是 pull，不是复制',
  );
});

test('AC2b hub 发言 → 成员靠复制队列收到（真两实例，用例不显式 pull）', async (t) => {
  const rig = await startTwoInstances(t, { hubReplica: { retryMs: 120 } });
  const posted = rig.hub.server.group.post({
    peerId: HUB.peerId,
    name: HUB.name,
    kind: 'chat',
    text: '复制目标',
  });
  assert.equal(Number(posted?.seq), 1);

  // 成员侧后台补差是关的（pullIntervalMs=600s），心跳是 30s 一轮：
  // 1.5s 内到货只可能来自 hub 的复制队列
  const arrived = await waitFor(() => Number(readJson(replicaFileOf(rig.member.dir)).lastSeq ?? 0) === 1, {
    timeoutMs: 1_500,
  });
  assert.ok(arrived, '成员副本没在 1.5s 内收到');
  const replica = readJson(replicaFileOf(rig.member.dir));
  assert.deepEqual(replica.messages.map((m) => m.text), ['复制目标']);
  // hub 的日志行在 HTTP 响应之后才写，所以和到货之间还差一个 tick —— 一起等
  const logged = await waitFor(
    () => rig.hub.logs.some((line) => line.includes('[group] replicate peer=')),
    { timeoutMs: 1_500 },
  );
  assert.ok(logged, '这是复制队列推的那一条（日志里必须有 replicate 行）：' + rig.hub.logs.join(' | '));
});

// ---------------------------------------------------------------------------
// 3. 启动期对账（AC4 / AC5）：治存量 lastSeq=74 / commitSeq=73
// ---------------------------------------------------------------------------

const RECON_ID = 'peer-recon-1';
const RECON_GROUP = 'aaaaaaaa-1111-4111-8111-111111111111';

function messageOf(seq, ts) {
  return {
    seq,
    ts,
    from: { peerId: RECON_ID, name: 'recon' },
    kind: 'chat',
    text: 'm' + seq,
    meta: {},
  };
}

/** 落一份「hub 历史状态」：group.json（权威日志）+ group-role.json（提交水位） */
function seedHubState(t, { lastSeq, commitSeq, messageSeqs }) {
  const dir = makeTempStateDir('dsh-lan-peers-recon-');
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const now = Date.now();
  writeJson0600(path.join(dir, 'state.json'), {
    instanceId: RECON_ID,
    name: 'recon',
    createdAt: new Date(now).toISOString(),
  });
  writeJson0600(path.join(dir, 'group.json'), {
    groupId: RECON_GROUP,
    name: 'default',
    createdAt: new Date(now).toISOString(),
    key: randomBytes(32).toString('base64url'),
    keyVersion: 1,
    members: { [RECON_ID]: { name: 'recon', addedAt: new Date(now).toISOString() } },
    messages: messageSeqs.map((seq) => messageOf(seq, now - 1_000)),
    pending: [],
    lastSeq,
  });
  writeJson0600(path.join(dir, 'group-role.json'), {
    role: 'leader',
    epoch: 1,
    leaderPeerId: RECON_ID,
    leaseUntil: now + 60_000,
    commitSeq,
    votedFor: null,
    groupId: RECON_GROUP,
  });
  return dir;
}

/** 起一台只用加载期逻辑的 hub（不 listen：对账发生在构造时） */
async function bootHub(t, dir, logs) {
  const server = createPeerServer({
    listenHost: '127.0.0.1',
    stateDir: dir,
    requireEncryption: false,
    logger: (line) => logs.push(String(line)),
    group: { enabled: true, name: 'default', retentionDays: 7 },
  });
  t.after(async () => { await server.close(); });
  return server;
}

test('AC4 对账：lastSeq>commitSeq 且日志完整 → 推到 lastSeq，恰好一行 reconciled', async (t) => {
  const dir = seedHubState(t, { lastSeq: 3, commitSeq: 2, messageSeqs: [1, 2, 3] });
  const logs = [];
  const hub = await bootHub(t, dir, logs);

  assert.equal(hub.group.role().commitSeq, 3, 'commitSeq 必须被对账推到 lastSeq');
  assert.equal(hub.group.lastSeq(), 3);
  assert.equal(hub.group.state().pendingCount, 0, '对账不制造 pending');
  const lines = logs.filter((line) => line.includes('commitSeq reconciled'));
  assert.equal(lines.length, 1, '恰好一行：' + lines.join(' | '));
  assert.match(lines[0], /^\[group\] commitSeq reconciled from=2 to=3$/);
  // 隐私：只有 seq 数字，没有正文/路径
  assert.equal(lines[0].includes(dir), false);
  assert.equal(lines[0].includes('m1'), false);
});

test('AC4 对账：区间里有缺口 → 一条都不推进，记一行 gap 告警', async (t) => {
  // messages 缺 seq 2（构造缺口），lastSeq 仍是 3
  const dir = seedHubState(t, { lastSeq: 3, commitSeq: 1, messageSeqs: [1, 3] });
  const logs = [];
  const hub = await bootHub(t, dir, logs);

  assert.equal(hub.group.role().commitSeq, 1, '有缺口时必须保持原状');
  assert.equal(hub.group.lastSeq(), 3);
  const gaps = logs.filter((line) => line.includes('commitSeq gap'));
  assert.equal(gaps.length, 1, '恰好一行告警：' + gaps.join(' | '));
  assert.match(gaps[0], /^\[group\] commitSeq gap seq=2$/);
  assert.equal(logs.some((line) => line.includes('commitSeq reconciled')), false, '不许把缺口蒙过去');
});

test('AC5 对账幂等：连续两次启动不重复写、不重复记日志', async (t) => {
  const dir = seedHubState(t, { lastSeq: 3, commitSeq: 2, messageSeqs: [1, 2, 3] });
  const first = [];
  const one = await bootHub(t, dir, first);
  assert.equal(one.group.role().commitSeq, 3);
  assert.equal(first.filter((line) => line.includes('commitSeq reconciled')).length, 1);
  await one.close();

  const second = [];
  const two = await bootHub(t, dir, second);
  assert.equal(two.group.role().commitSeq, 3, '水位不回退');
  assert.equal(
    second.filter((line) => line.includes('commitSeq reconciled')).length,
    0,
    '第二次启动没有可对账的东西，不该再记一行：' + second.join(' | '),
  );
  assert.equal(second.filter((line) => line.includes('commitSeq gap')).length, 0);

  // 落盘也对得上（不是只改了内存）
  assert.equal(Number(readJson(path.join(dir, 'group-role.json')).commitSeq), 3);
});
