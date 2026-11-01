/**
 * v0.8.0-β §A · epoch 膨胀缺陷的三道修复（真机：3 天 495 次失败选举把 epoch 从 5 推到 500）。
 *
 * 覆盖：
 *   §A1 失败选举指数退避（假时钟：60s 内失败次数 ≤ 2，且不会永久卡死）；
 *   §A2 周期优先级纠偏（低优先级 leader 在位时 5 分钟后触发一次，之后不重复触发）；
 *   §A3 单次 epoch 涨幅 > 50 记一行告警。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { makeTempStateDir, peerFixture, request, seedPeers, writeJson0600 } from './helpers.mjs';
import { GROUP_PRIORITY_CORRECTION_MAX, GROUP_PRIORITY_CORRECTION_MS, createPeerServer } from '../server.mjs';
import { roleOf, startCluster, waitFor } from './group-cluster.mjs';

const GHOST = peerFixture('peer-ghost-1', { baseUrl: 'http://127.0.0.1:1' });

/**
 * 造一台「孤立的 hub 角色节点」：成员表里有自己 + 一台永远不可达的对端，
 * 角色是 follower（leader 指向那台幽灵）、租约已过期 —— 于是每次选举都只有自己一票。
 */
async function startIsolatedHub(t, { groupElection = {}, logger = null, heartbeatMs = 300, now = null } = {}) {
  const stateDir = makeTempStateDir('dsh-lan-peers-epoch-');
  t.after(() => fs.rmSync(stateDir, { recursive: true, force: true }));
  writeJson0600(path.join(stateDir, 'state.json'), {
    instanceId: 'peer-self-a',
    name: 'node-self',
    createdAt: new Date().toISOString(),
  });
  seedPeers(stateDir, [{ ...GHOST, secret: 'sec-ghost', inboundSecret: 'sec-ghost' }]);
  writeJson0600(path.join(stateDir, 'group.json'), {
    groupId: 'group-epoch-fixture',
    name: 'epoch',
    createdAt: new Date().toISOString(),
    key: randomBytes(32).toString('base64url'),
    keyVersion: 1,
    lastSeq: 0,
    members: { [GHOST.peerId]: { name: GHOST.name, baseUrl: GHOST.baseUrl } },
    messages: [],
    pending: [],
  });
  // 扮演「已经被高 epoch 的别人接管、但自己租约早就过期」的节点
  writeJson0600(path.join(stateDir, 'group-role.json'), {
    role: 'follower',
    epoch: 5,
    leaderPeerId: GHOST.peerId,
    leaseUntil: 0,
    commitSeq: 0,
    votedFor: null,
    groupId: 'group-epoch-fixture',
  });
  const server = createPeerServer({
    listenHost: '127.0.0.1',
    stateDir,
    requireEncryption: false,
    allowRemotePrompts: true,
    logger,
    ...(now ? { now } : {}),
    group: {
      enabled: true,
      name: 'epoch',
      autoJoin: false,
      retentionDays: 7,
      quorum: 'majority',
      heartbeatMs,
      hubPriority: 0,
    },
    groupElection: {
      heartbeatMs,
      tickMs: 600_000, // 关掉自动 tick：这个用例自己驱动 roleTick，才数得准次数
      jitterMs: 0,
      peerTimeoutMs: 120,
      ...groupElection,
    },
  });
  const info = await server.listen(0, '127.0.0.1');
  t.after(async () => { await server.close(); });
  return { server, stateDir, baseUrl: info.url };
}

test('§A1 失败选举指数退避：假时钟推进 60s，失败次数 ≤ 2 且不会永久卡死', async (t) => {
  const lines = [];
  let fake = 1_760_000_000_000;
  const clock = () => fake;
  const { server } = await startIsolatedHub(t, { logger: (line) => lines.push(String(line)), now: clock });
  const tick = async (stepMs) => {
    fake += stepMs;
    return server.group.tick();
  };

  // 第一次选举：只有自己一票，quorum 需要 2 → 落败
  const first = await tick(1);
  assert.equal(first.reason, 'quorum-unavailable', '幽灵对端不可能投票，必然落败');
  assert.equal(server.group.elections().failures, 1);
  const backoffAfterFirst = server.group.elections().backoffMs;
  assert.ok(backoffAfterFirst > 0, '失败后必须进入退避');
  assert.match(
    lines.join('\n'),
    /\[group\] election backoff failures=1 retryIn=\d+ms reason=lease-expired/,
    '退避要留一行日志（不含密钥/正文）',
  );

  // 60 秒内一共只允许 2 次失败选举（真机事故是几百次）；推进到 59s，别踩 60s 窗口边界
  for (let step = 0; step < 118; step += 1) await tick(500);
  const within60s = server.group.elections().failures;
  assert.ok(within60s <= 2, '60s 内失败选举次数必须 ≤ 2，实际 ' + within60s);
  assert.ok(within60s >= 2, '该有第二次尝试（退避不是「一次就放弃」），实际 ' + within60s);
  const attemptsWithin60s = server.group.elections().attempts;
  assert.equal(attemptsWithin60s, within60s, '没有成功也没有别的选举时，尝试数=失败数');

  // 退避不是死锁：把时钟推出 60s 窗口之后还能再试一次
  await tick(90_000);
  const later = server.group.elections().failures;
  assert.ok(later > within60s, '越过后应重新获得一次尝试机会，实际 ' + later);
  assert.ok(
    lines.filter((line) => line.startsWith('[group] election backoff')).length >= 2,
    '每次失败都要记一行退避日志',
  );
});

test('§A1 退避清零：收到合法 leader 的心跳后，失败计数与退避都归零', async (t) => {
  let fake = 1_760_000_000_000;
  const { server, baseUrl } = await startIsolatedHub(t, { now: () => fake });
  const roleOfServer = () => server.group.role();
  fake += 1;
  assert.equal((await server.group.tick()).reason, 'quorum-unavailable');
  assert.equal(server.group.elections().failures, 1);
  assert.ok(server.group.elections().backoffMs > 0);

  // 幽灵对端「回来了」：它用**同一个 epoch** 发心跳（S2 之后心跳不得推进 epoch，
  // 只能在同 epoch 下给自己续租），本机 acceptLeader（租约重新有效）。
  // 注：失败选举本身会先把本机 epoch 抬一格，所以这里取当前值而不是写死 5。
  const epochNow = server.group.role().epoch;
  const beat = await request(baseUrl, {
    method: 'POST',
    path: '/v1/group/leader',
    peerId: GHOST.peerId,
    secret: 'sec-ghost',
    body: { epoch: epochNow, leaderPeerId: GHOST.peerId, commitSeq: 0, priority: 0 },
    now: () => fake,
  });
  assert.equal(beat.status, 200, beat.text);
  assert.equal(roleOfServer().epoch, epochNow, '心跳不抬 epoch');
  assert.equal(server.group.elections().failures, 0, '跟上了合法 leader，失败计数清零');
  assert.equal(server.group.elections().backoffMs, 0, '退避清零：下一轮选举可立刻发起');
  assert.equal(server.group.role().role, 'follower');
});

test('§A2 周期优先级纠偏：低优先级 leader 在位时按周期夺回一次，之后不再重复', async (t) => {
  // 默认节奏是 5 分钟（DESIGN §A2）；这里把节奏压到 3s 假时钟来验机制
  assert.equal(GROUP_PRIORITY_CORRECTION_MS, 300_000, '默认周期必须是 5 分钟');
  assert.equal(GROUP_PRIORITY_CORRECTION_MAX, 5, '必须有累计上限，避免循环夺权');

  let fake = Date.now();
  const clock = () => fake;
  // 假时钟按 1.6×真实时间走：心跳（400ms 真实）之间只前进 640ms，
  // 小于租约 3×400=1200ms，所以 leader 的租约在假时钟里一直是有效的。
  const driver = setInterval(() => { fake += 40; }, 25);
  t.after(() => clearInterval(driver));
  const lines = [];
  const cluster = await startCluster(t, {
    count: 2,
    hubRoles: [0, 1],
    // 低优先（10）当 leader，高优先（0）以 follower 起步
    priorities: [10, 0],
    followerOf: { 1: 0 },
    heartbeatMs: 400,
    tickMs: 40,
    now: clock,
    logger: (line) => lines.push(String(line)),
    // 关掉「启动期一次性接管」，把周期纠偏单独隔离出来测
    electionExtra: { priorityStartup: false, priorityCorrectionMs: 3_000, priorityCorrectionMax: 5 },
  });
  const [low, high] = cluster.nodes;
  const takeoverOf = (node) => node.server.group.takeover();

  // 让低优先 leader 的心跳把 leaderPriority 教给 high。
  // 注意：第一次纠偏**不设冷却**（稳定期 2×heartbeat 一过就可能触发），所以这里不能
  // 用固定 sleep 去赌「还没开始纠偏」—— 机器忙时会正好撞在选举中途（实测偶发红）。
  const started = await waitFor(() => {
    const role = roleOf(high);
    return role.role === 'follower' && role.leaderPeerId === low.peerId ? role : null;
  }, { timeoutMs: 5_000, intervalMs: 5 });
  assert.ok(started, 'high 必须以 follower 起步并认 low 为 leader');
  assert.equal(
    takeoverOf(high).periodic.attempts <= 1,
    true,
    '纠偏最多已经触发一次（首次不设冷却，不能断言恰好 0）',
  );
  assert.equal(takeoverOf(high).attempts, 0, '启动期一次性接管已被关掉');

  // 过了纠偏节奏 → 周期纠偏触发一次并夺回 leadership
  await waitFor(() => takeoverOf(high).periodic.attempts === 1, { timeoutMs: 20_000 });
  await waitFor(() => roleOf(high).role === 'leader', { timeoutMs: 10_000 });
  await waitFor(() => roleOf(low).leaderPeerId === high.peerId, { timeoutMs: 10_000 });
  assert.equal(roleOf(high).epoch, 2, '纠偏必须抬 epoch');
  assert.equal(takeoverOf(high).periodic.attempts, 1);

  const text = lines.join('\n');
  assert.match(text, /\[group\] takeover periodic attempt epoch=2 priority=0 leaderPriority=10/);
  assert.match(text, /\[group\] takeover periodic won epoch=2 votes=2\/2/);
  assert.ok(!text.includes('[group] takeover attempt epoch='), '启动期一次性接管不该在这个用例里发生');

  // 再等两个纠偏周期：已经是 leader，条件不成立 → 不重复触发
  await sleep(5_000);
  assert.equal(takeoverOf(high).periodic.attempts, 1, '已是 leader，不应再纠偏');
  assert.equal(takeoverOf(high).periodic.max, 5);
  assert.equal(roleOf(high).role, 'leader');
  assert.equal(roleOf(high).leaderPeerId, high.peerId);
});

test('§A3 epoch 跳变告警：一次涨幅 499 记一行 suspicious（不含密钥）', async (t) => {
  const lines = [];
  const stateDir = makeTempStateDir('dsh-lan-peers-jump-');
  t.after(() => fs.rmSync(stateDir, { recursive: true, force: true }));
  const member = peerFixture('peer-jump-1');
  seedPeers(stateDir, [member]);
  writeJson0600(path.join(stateDir, 'group.json'), {
    groupId: 'group-jump-fixture',
    name: 'jump',
    createdAt: new Date().toISOString(),
    key: randomBytes(32).toString('base64url'),
    keyVersion: 1,
    lastSeq: 0,
    members: { [member.peerId]: { name: member.name, baseUrl: 'http://127.0.0.1:1' } },
    messages: [],
    pending: [],
  });
  const server = createPeerServer({
    listenHost: '127.0.0.1',
    stateDir,
    requireEncryption: false,
    logger: (line) => lines.push(String(line)),
    group: { enabled: true, name: 'jump', autoJoin: false, retentionDays: 7, quorum: 'majority' },
    groupElection: { heartbeatMs: 5_000, tickMs: 600_000, jitterMs: 0 },
  });
  const info = await server.listen(0, '127.0.0.1');
  t.after(async () => { await server.close(); });
  const before = server.group.role();
  assert.equal(before.epoch, 1, 'hub 首次即 leader，epoch 取 keyVersion');

  // 一台声称 epoch=500 的「leader」发心跳（真机事故里就是这么被降级的）。
  // S2 之后心跳不能推进 epoch：一律 409 stale-epoch，但**告警照留**（§A3 的监控目的不变）。
  const beat = await request(info.url, {
    method: 'POST',
    path: '/v1/group/leader',
    peerId: member.peerId,
    secret: member.inboundSecret,
    body: { epoch: 500, leaderPeerId: member.peerId, commitSeq: 0, priority: 0 },
  });
  assert.equal(beat.status, 409, beat.text);
  assert.equal(beat.json.error, 'stale-epoch');
  const after = server.group.role();
  assert.equal(after.epoch, 1, '心跳不得推进 epoch');
  assert.equal(after.role, 'leader', '本机不会被一条心跳降级');

  const jump = lines.filter((line) => line.startsWith('[group] epoch jump suspicious'));
  assert.equal(jump.length, 1, '一次大跳变尝试只留一行告警: ' + JSON.stringify(lines));
  assert.match(jump[0], /^\[group\] epoch jump suspicious from=1 to=500 reason=heartbeat-rejected$/);

  // 原地再被抬一次：还是一行告警（涨幅按**本机 epoch** 算，因为它一直没动）
  const small = await request(info.url, {
    method: 'POST',
    path: '/v1/group/leader',
    peerId: member.peerId,
    secret: member.inboundSecret,
    body: { epoch: 501, leaderPeerId: member.peerId, commitSeq: 0, priority: 0 },
  });
  assert.equal(small.status, 409);
  assert.equal(
    lines.filter((line) => line.startsWith('[group] epoch jump suspicious')).length,
    2,
    '每一次被抬都留一行（本机 epoch 始终是 1，涨幅依旧 > 50）',
  );
  assert.equal(server.group.role().epoch, 1);
  // 告警行不含任何密钥
  for (const line of lines) {
    assert.ok(!line.includes(member.inboundSecret));
    assert.ok(!line.includes(server.group.state({ includeKey: true }).groupKey));
  }
});
