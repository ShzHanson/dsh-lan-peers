/**
 * v0.7.0 S3 · 选举 / 心跳 / 租约 / 冲突裁决（契约 group-s3-contract.md §1–§4）。
 *
 * 覆盖：心跳推进与租约刷新、租约过期自动选举（epoch+1、只有一台成为 leader）、
 *      少数派拿不到多数票、同 epoch 冲突按 priority → peerId 裁决、更高 epoch 一律服从、
 *      votedFor 落盘后同一个 epoch 不投第二个人。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { setTimeout as sleep } from 'node:timers/promises';
import {
  fetchGroupLease,
  pullGroupMessages,
  readGroupKeyFile,
  requestGroupVote,
  sendGroupHeartbeat,
  writeGroupKeyFile,
} from '../../lib/group-client.mjs';
import { fileMode, makeTempStateDir } from './helpers.mjs';
import { postAs, readRoleFile, roleOf, startCluster, waitFor } from './group-cluster.mjs';

const groupArgs = (cluster, senderId) => ({
  groupKey: cluster.groupKey,
  groupId: cluster.groupId,
  senderId,
});

// ---------------------------------------------------------------------------
// §2 心跳与租约
// ---------------------------------------------------------------------------

test('S3 心跳：leader 广播后 follower 的 epoch/leader/租约同步推进，角色文件 0600', async (t) => {
  const cluster = await startCluster(t, { count: 3 });
  const [a, b, c] = cluster.nodes;

  // hub 角色首次初始化即 leader（延续 S2 语义），epoch 从群的 keyVersion 起步
  const initial = roleOf(a);
  assert.equal(initial.role, 'leader');
  assert.equal(initial.leaderPeerId, a.peerId);
  assert.equal(initial.epoch, 1);

  const sent = await a.server.group.heartbeat();
  assert.equal(sent.ok, true, JSON.stringify(sent));
  assert.equal(sent.delivered, 2, '两台 follower 都要收到心跳');

  for (const node of [b, c]) {
    await waitFor(() => roleOf(node).leaderPeerId === a.peerId);
    const role = roleOf(node);
    assert.equal(role.role, 'follower');
    assert.equal(role.epoch, 1);
    // 租约 = now + 3 × heartbeatMs（测试里 heartbeatMs=60 → 180ms 上下）
    const remaining = role.leaseUntil - Date.now();
    assert.ok(remaining > 0 && remaining <= 3 * 60 + 200, '租约剩余 ' + remaining + 'ms');
    // 角色文件落盘且 0600（Windows 不支持权限位，与既有断言同一套跳法）
    const onDisk = readRoleFile(node);
    assert.equal(onDisk.leaderPeerId, a.peerId);
    assert.equal(onDisk.epoch, 1);
    if (process.platform !== 'win32') assert.equal(fileMode(node.dir + '/group-role.json'), 0o600);
  }

  // 群级只读快照与角色文件一致（CLI `group leader --peer` 走这条）
  const lease = await fetchGroupLease({
    baseUrl: b.baseUrl,
    ...groupArgs(cluster, a.peerId),
  });
  assert.equal(lease.ok, true);
  assert.equal(lease.role, 'follower');
  assert.equal(lease.leaderPeerId, a.peerId);
  assert.equal(lease.quorum, 'majority');
  assert.equal(lease.pendingCount, 0);
  assert.equal(lease.degraded, false);
});

test('S3 租约过期：leader 被杀的 ≤3 个租约内自动接任，epoch+1 且只有一台 leader', async (t) => {
  const cluster = await startCluster(t, { count: 3, heartbeatMs: 60, tickMs: 25, jitterMs: 0 });
  const [a, b, c] = cluster.nodes;
  await waitFor(() => roleOf(b).leaderPeerId === a.peerId && roleOf(c).leaderPeerId === a.peerId);

  await a.server.close();
  const survivors = [b, c];
  const winner = await waitFor(() => survivors.find((node) => roleOf(node).role === 'leader'), {
    timeoutMs: 8_000,
    intervalMs: 10,
  });
  assert.ok(winner, '杀掉 leader 后必须有一台接任');
  const won = roleOf(winner);
  // 一次就选出来时是原 epoch + 1；抖动让两台落败者重试时会再抬一格，
  // 所以这里断言「严格变高、且仍是唯一 leader」（claim 用例单独断言严格的 +1）。
  assert.ok(won.epoch >= 2, '接任 epoch 必须严格变大，实际 ' + won.epoch);
  assert.equal(won.leaderPeerId, winner.peerId);
  const loser = survivors.find((node) => node !== winner);
  await waitFor(() => roleOf(loser).leaderPeerId === winner.peerId);
  assert.equal(roleOf(loser).role, 'follower');
  assert.equal(roleOf(loser).epoch, won.epoch);
  // 稳定：不再出现第二个 leader
  await sleep(120);
  assert.equal(survivors.filter((node) => roleOf(node).role === 'leader').length, 1);
});

test('S3 少数派：三成员只剩一台时选举拿不到多数票，角色停在 follower', async (t) => {
  const cluster = await startCluster(t, { count: 3, heartbeatMs: 60, tickMs: 25, jitterMs: 0 });
  const [a, b, c] = cluster.nodes;
  await waitFor(() => roleOf(b).leaderPeerId === a.peerId);
  await a.server.close();
  await c.server.close();

  const out = await b.server.group.elect({ reason: 'test-minority' });
  assert.equal(out.ok, false);
  assert.equal(out.reason, 'quorum-unavailable');
  assert.equal(out.votes, 1, '只有自己那一票');
  assert.equal(out.needed, 2, '三成员群 majority = floor(3/2)+1 = 2');
  assert.equal(roleOf(b).role, 'follower');
  assert.equal(roleOf(b).leaderPeerId, '');
});

// ---------------------------------------------------------------------------
// §4 冲突裁决
// ---------------------------------------------------------------------------

test('S3 同 epoch：心跳改不了领导权；priority/peerId 裁决只发生在投票端', async (t) => {
  // 心跳设长、租约检查设到很远：这个用例只裁决冲突，不让后台选举插进来
  const cluster = await startCluster(t, {
    count: 3,
    ids: ['peer-m0', 'peer-b0', 'peer-z0'],
    priorities: [0, 0, -5],
    heartbeatMs: 5_000,
    tickMs: 60_000,
  });
  const [incumbent, follower, lowPriority] = cluster.nodes;
  assert.equal(roleOf(follower).leaderPeerId, incumbent.peerId);

  const heartbeat = (fromId, extra = {}) => sendGroupHeartbeat({
    baseUrl: follower.baseUrl,
    ...groupArgs(cluster, fromId),
    epoch: 1,
    leaderPeerId: fromId,
    lastSeq: 0,
    commitSeq: 0,
    ...extra,
  });

  // ① S2：同 epoch 里「优先级更小者的心跳就能夺权」是漏洞形状，现在一律 409，
  //    且本机记录的 leader 一个字都不变 —— 领导权只能由 election 的票数推进
  await assert.rejects(
    () => heartbeat(lowPriority.peerId, { priority: -5 }),
    (error) => {
      assert.equal(error.status, 409);
      assert.equal(error.code, 'leader-conflict');
      assert.equal(error.body.leaderPeerId, incumbent.peerId, '心跳绝不能改认别人当 leader');
      return true;
    },
  );
  assert.equal(roleOf(follower).leaderPeerId, incumbent.peerId);
  assert.equal(roleOf(follower).epoch, 1, '冲突不改 epoch');

  // ② 合法的旧 leader 用自己 id 再自称一次 → 200（续租不受影响，优先级同时被学到）
  const renewed = await heartbeat(incumbent.peerId, { priority: 0 });
  assert.equal(renewed.ok, true, JSON.stringify(renewed));

  // ③ 裁决语义保留在投票端：priority 更小者（-5 < 0）照样能拿到票
  const taken = await requestGroupVote({
    baseUrl: follower.baseUrl,
    ...groupArgs(cluster, lowPriority.peerId),
    epoch: 1,
    candidate: lowPriority.peerId,
    priority: -5,
  });
  assert.equal(taken.vote, true, JSON.stringify(taken));
  await waitFor(() => roleOf(follower).leaderPeerId === lowPriority.peerId);
  assert.equal(roleOf(follower).epoch, 1, '同 epoch 裁决不抬 epoch');

  // ④ 反向：优先级更大的候选在同 epoch 里拿不到票
  const refused = await requestGroupVote({
    baseUrl: follower.baseUrl,
    ...groupArgs(cluster, incumbent.peerId),
    epoch: 1,
    candidate: incumbent.peerId,
    priority: 0,
  });
  assert.equal(refused.vote, false);
  assert.equal(refused.reason, 'lower-priority');
  assert.equal(roleOf(follower).leaderPeerId, lowPriority.peerId);

  // ⑤ priority 相同 → peerId 字典序小者胜：'peer-b0' < 'peer-m0'（同样在投票端）
  const cluster2 = await startCluster(t, {
    count: 3,
    ids: ['peer-m0', 'peer-b0', 'peer-z0'],
    heartbeatMs: 5_000,
    tickMs: 60_000,
  });
  const [incumbent2, follower2, voter2] = cluster2.nodes;
  // 投票端是 incumbent2（peer-m0 自己），候选是 peer-b0：心跳那个形状先被拒
  await assert.rejects(
    () => sendGroupHeartbeat({
      baseUrl: follower2.baseUrl,
      ...groupArgs(cluster2, 'peer-b0'),
      epoch: 1,
      leaderPeerId: 'peer-b0',
      priority: 0,
    }),
    (error) => {
      assert.equal(error.code, 'leader-conflict');
      assert.equal(error.body.leaderPeerId, incumbent2.peerId);
      return true;
    },
  );
  // 同优先级下 peerId 字典序小者（'peer-b0' < 'peer-m0'）能拿到票（第三台当投票人）
  const smaller = await requestGroupVote({
    baseUrl: voter2.baseUrl,
    ...groupArgs(cluster2, 'peer-b0'),
    epoch: 1,
    candidate: 'peer-b0',
    priority: 0,
  });
  assert.equal(smaller.vote, true, JSON.stringify(smaller));
  await waitFor(() => roleOf(voter2).leaderPeerId === 'peer-b0');
  assert.equal(roleOf(voter2).epoch, 1, '同 epoch 裁决不抬 epoch');
  // 反向（字典序更大者）拿不到票
  const reverse = await requestGroupVote({
    baseUrl: voter2.baseUrl,
    ...groupArgs(cluster2, incumbent2.peerId),
    epoch: 1,
    candidate: incumbent2.peerId,
    priority: 0,
  });
  assert.equal(reverse.vote, false);
  assert.equal(reverse.reason, 'lower-priority');
});

test('S3 更高 epoch 一律服从（走票数）；心跳不得抬 epoch', async (t) => {
  const cluster = await startCluster(t, { count: 3, heartbeatMs: 5_000, tickMs: 60_000 });
  const [a, b, c] = cluster.nodes;
  assert.equal(roleOf(a).role, 'leader');

  // S2：C 用一条 epoch=5 的心跳宣告自己是 leader —— 漏洞形状，现在 409 stale-epoch，
  // A 既不被降级、也不抬 epoch（epoch 只能由 election 的票数推进）
  await assert.rejects(
    () => sendGroupHeartbeat({
      baseUrl: a.baseUrl,
      ...groupArgs(cluster, c.peerId),
      epoch: 5,
      leaderPeerId: c.peerId,
      lastSeq: 0,
      commitSeq: 0,
    }),
    (error) => {
      assert.equal(error.status, 409);
      assert.equal(error.code, 'stale-epoch');
      assert.equal(error.body.epoch, 1, '本机 epoch 不能被子虚的告警心跳改写');
      return true;
    },
  );
  const kept = roleOf(a);
  assert.equal(kept.role, 'leader');
  assert.equal(kept.epoch, 1);
  assert.equal(kept.leaderPeerId, a.peerId);
  assert.equal(readRoleFile(a).epoch, 1);

  // C 改走正路：拉票（epoch 5 更高，一律服从）→ A 投票并降级
  const granted = await requestGroupVote({
    baseUrl: a.baseUrl,
    ...groupArgs(cluster, c.peerId),
    epoch: 5,
    candidate: c.peerId,
  });
  assert.equal(granted.vote, true, JSON.stringify(granted));
  const demoted = roleOf(a);
  assert.equal(demoted.role, 'follower');
  assert.equal(demoted.epoch, 5);
  assert.equal(demoted.leaderPeerId, c.peerId);
  // 状态要落盘（重启后不会又自称 leader）
  assert.equal(readRoleFile(a).epoch, 5);
  assert.equal(readRoleFile(a).role, 'follower');

  // 低 epoch 的心跳 → 409 stale-epoch，并带回本地 epoch
  await assert.rejects(
    () => sendGroupHeartbeat({
      baseUrl: a.baseUrl,
      ...groupArgs(cluster, b.peerId),
      epoch: 1,
      leaderPeerId: b.peerId,
    }),
    (error) => {
      assert.equal(error.status, 409);
      assert.equal(error.code, 'stale-epoch');
      assert.equal(error.body.epoch, 5);
      return true;
    },
  );
  // 低 epoch 的投票请求同样被拒，且不改本机 epoch
  const stale = await requestGroupVote({
    baseUrl: a.baseUrl,
    ...groupArgs(cluster, c.peerId),
    epoch: 2,
    candidate: c.peerId,
  });
  assert.equal(stale.vote, false);
  assert.equal(stale.reason, 'stale-epoch');
  assert.equal(stale.epoch, 5);
});

test('S3 votedFor 落盘：同一个 epoch 不投第二个人', async (t) => {
  const cluster = await startCluster(t, { count: 3, heartbeatMs: 5_000, tickMs: 60_000 });
  const [a, b, c] = cluster.nodes;

  const granted = await requestGroupVote({
    baseUrl: c.baseUrl,
    ...groupArgs(cluster, b.peerId),
    epoch: 2,
    candidate: b.peerId,
  });
  assert.equal(granted.vote, true, JSON.stringify(granted));
  assert.equal(granted.epoch, 2);
  const onDisk = readRoleFile(c);
  assert.deepEqual(onDisk.votedFor, { epoch: 2, peerId: b.peerId }, 'votedFor 必须落盘');
  assert.equal(roleOf(c).leaderPeerId, b.peerId);

  // 同一个 epoch 想改投 A：拒绝，并且文件里的记录不变
  const refused = await requestGroupVote({
    baseUrl: c.baseUrl,
    ...groupArgs(cluster, a.peerId),
    epoch: 2,
    candidate: a.peerId,
  });
  assert.equal(refused.vote, false);
  assert.equal(refused.reason, 'already-voted');
  assert.deepEqual(readRoleFile(c).votedFor, { epoch: 2, peerId: b.peerId });

  // 不在成员表里的候选一律不投
  const outsider = await requestGroupVote({
    baseUrl: c.baseUrl,
    ...groupArgs(cluster, a.peerId),
    epoch: 9,
    candidate: 'peer-not-in-group',
  });
  assert.equal(outsider.vote, false);
  assert.equal(outsider.reason, 'unknown-candidate');
});

test('S3 claim：follower 手动接管后原 leader 降级，epoch+1', async (t) => {
  const cluster = await startCluster(t, { count: 3, heartbeatMs: 5_000, tickMs: 60_000 });
  const [a, b] = cluster.nodes;
  assert.equal(roleOf(a).role, 'leader');

  const claim = await b.server.group.claim();
  assert.equal(claim.ok, true, JSON.stringify(claim));
  assert.equal(claim.role, 'leader');
  assert.equal(claim.epoch, 2);
  assert.equal(roleOf(b).leaderPeerId, b.peerId);

  await waitFor(() => roleOf(a).role === 'follower');
  assert.equal(roleOf(a).leaderPeerId, b.peerId);
  assert.equal(roleOf(a).epoch, 2);
});

test('S3 角色文件：缺失时 hub 起步为 leader、成员起步为 follower', async (t) => {
  const dir = makeTempStateDir();
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const cluster = await startCluster(t, { count: 2, heartbeatMs: 5_000, tickMs: 60_000 });
  const [hubNode, memberNode] = cluster.nodes;
  assert.equal(roleOf(hubNode).role, 'leader');
  assert.equal(roleOf(memberNode).role, 'follower');
  assert.equal(roleOf(memberNode).leaderPeerId, hubNode.peerId);
  assert.equal(roleOf(memberNode).epoch, 1);
  assert.equal(roleOf(hubNode).quorum, 'majority');
  assert.equal(roleOf(memberNode).degraded, false);
});


test('S3 同 epoch 分裂投票：自投的候选让位给裁决更合法的一方（避免卡死同一个 epoch）', async (t) => {
  const cluster = await startCluster(t, { count: 3, heartbeatMs: 5_000, tickMs: 60_000 });
  const [a, b, c] = cluster.nodes;
  // C 先宣布候选并自投（epoch 2）
  const selfVote = await requestGroupVote({
    baseUrl: c.baseUrl,
    ...groupArgs(cluster, c.peerId),
    epoch: 2,
    candidate: c.peerId,
  });
  assert.equal(selfVote.vote, true);
  // 同 epoch、peerId 更小的 A 来拉票：C 必须让位（契约 §4 的裁决顺序）
  const switched = await requestGroupVote({
    baseUrl: c.baseUrl,
    ...groupArgs(cluster, a.peerId),
    epoch: 2,
    candidate: a.peerId,
  });
  assert.equal(switched.vote, true, JSON.stringify(switched));
  assert.deepEqual(readRoleFile(c).votedFor, { epoch: 2, peerId: a.peerId });
  // 让位之后锁死：同 epoch 再来一个 peerId 更大的候选不再改投
  const refused = await requestGroupVote({
    baseUrl: c.baseUrl,
    ...groupArgs(cluster, b.peerId),
    epoch: 2,
    candidate: b.peerId,
  });
  assert.equal(refused.vote, false);
  assert.equal(refused.reason, 'lower-priority');
  assert.deepEqual(readRoleFile(c).votedFor, { epoch: 2, peerId: a.peerId });
});
// ---------------------------------------------------------------------------
// §3 quorum 分母（安全不变量：分母是成员表全集，不是「知道地址的成员」）
// ---------------------------------------------------------------------------

test('S3 quorum 分母 = 成员表全集：没有任何地址的成员也计入，且能真的挡住写入', async (t) => {
  const cluster = await startCluster(t, { count: 3, heartbeatMs: 5_000, tickMs: 60_000 });
  const [a, b] = cluster.nodes;
  const lease = (node) => fetchGroupLease({ baseUrl: node.baseUrl, ...groupArgs(cluster, b.peerId) });

  const baseline = await lease(a);
  assert.equal(baseline.memberCount, 3, 'hub 成员表 = 自己 + 两台');
  assert.equal(baseline.quorumNeeded, 2);

  // 三个只存在于成员表、从来没有地址也从不在线的成员：分母必须跟着变大
  a.server.group.addMember('peer-ghost-1', 'ghost-1');
  a.server.group.addMember('peer-ghost-2', 'ghost-2');
  a.server.group.addMember('peer-ghost-3', 'ghost-3');
  const grown = await lease(a);
  assert.equal(grown.memberCount, 6, '分母等于成员表条数（含 3 个无地址成员）');
  assert.equal(grown.quorumNeeded, 4, 'floor(6/2)+1');

  // 分母变大后，三台可达只凑得出 3 票 → 503（幽灵成员没有地址也必须算进多数派）
  const blocked = await postAs(a.baseUrl, b.peerId, { kind: 'chat', text: 'ghost-blocked' });
  assert.equal(blocked.status, 503, blocked.text);
  assert.equal(blocked.json.error, 'quorum-unavailable');
  assert.deepEqual(a.server.group.history({ sinceSeq: 0 }), []);

  // 清掉幽灵成员后恢复可写（票数 3 ≥ 3）
  for (const id of ['peer-ghost-1', 'peer-ghost-2', 'peer-ghost-3']) a.server.group.removeMember(id);
  const ok = await postAs(a.baseUrl, b.peerId, { kind: 'chat', text: 'ghost-gone' });
  assert.equal(ok.status, 201, ok.text);
  // 移除成员会轮换群密钥（keyVersion+1）：旧钥必须被拒，新钥照常
  const rotated = a.server.group.state({ includeKey: true });
  assert.ok(rotated.keyVersion > 1, 'removeMember 必须轮换 keyVersion');
  assert.notEqual(rotated.groupKey, cluster.groupKey, '轮换后 groupKey 必须变化');
  await assert.rejects(
    () => fetchGroupLease({ baseUrl: a.baseUrl, groupKey: cluster.groupKey, groupId: cluster.groupId, senderId: b.peerId }),
    (error) => {
      assert.equal(error.status, 401);
      assert.equal(error.code, 'bad-signature');
      return true;
    },
  );
  const after = await fetchGroupLease({
    baseUrl: a.baseUrl,
    groupKey: rotated.groupKey,
    groupId: cluster.groupId,
    senderId: b.peerId,
  });
  assert.equal(after.quorumNeeded, 2);
  assert.equal(after.keyVersion, rotated.keyVersion, 'lease 必须暴露 keyVersion');
});

test('S3 单节点自立为 leader 必败：N=2 且另一台不可达 → quorum-unavailable', async (t) => {
  // 这一条锁死真机事故：桌面节点曾经在 NAS 不可达时 epoch=2 自立为 leader
  const cluster = await startCluster(t, { count: 2, heartbeatMs: 5_000, tickMs: 60_000 });
  const [a, b] = cluster.nodes;
  await a.server.close();

  const out = await b.server.group.elect({ reason: 'test-lonely' });
  assert.equal(out.ok, false, JSON.stringify(out));
  assert.equal(out.reason, 'quorum-unavailable');
  assert.equal(out.votes, 1, '只有自己那一票');
  assert.equal(out.needed, 2, 'N=2 → floor(2/2)+1 = 2');
  assert.equal(roleOf(b).role, 'follower', '绝不能自立为 leader');
  assert.equal(roleOf(b).leaderPeerId, '');
});

test('S3 N=3：两台可达能当选（2 ≥ 2），只剩一台不能（1 < 2）', async (t) => {
  const cluster = await startCluster(t, { count: 3, heartbeatMs: 5_000, tickMs: 60_000 });
  const [a, b, c] = cluster.nodes;
  await a.server.close();

  const won = await b.server.group.elect({ reason: 'test-two-alive' });
  assert.equal(won.ok, true, JSON.stringify(won));
  assert.equal(won.votes, 2);
  assert.equal(won.needed, 2);
  assert.equal(roleOf(b).role, 'leader');

  await b.server.close();
  const lonely = await c.server.group.elect({ reason: 'test-one-alive' });
  assert.equal(lonely.ok, false, JSON.stringify(lonely));
  assert.equal(lonely.reason, 'quorum-unavailable');
  assert.equal(lonely.votes, 1);
  assert.equal(lonely.needed, 2);
  assert.notEqual(roleOf(c).role, 'leader');
});
test('S3 成员表未同步时：选举/心跳自愈入表（真机 not-a-member 的回归）', async (t) => {
  const cluster = await startCluster(t, { count: 3, heartbeatMs: 5_000, tickMs: 60_000 });
  const [a, b, c] = cluster.nodes;
  // H3 之后自愈只认「最近一次权威快照」：先让 c 真的 pull 一轮，拿到 hub 的 memberIds
  // （快照里 b 在群里）—— 这一步就是真机上成员启动后的第一轮 pull。
  let pulled = null;
  for (let attempt = 0; attempt < 40; attempt += 1) {
    pulled = await c.server.group.pull();
    if (pulled?.reason !== 'skipped') break;
    await sleep(25);
  }
  assert.equal(pulled.ok, true, JSON.stringify(pulled));
  // 造「c 的成员表来自一份不完整的快照」：把 b 从 c 的 group-key.json 里删掉
  const keyFile = readGroupKeyFile(c.dir);
  delete keyFile.members[b.peerId];
  writeGroupKeyFile(c.dir, keyFile);
  const stale = readGroupKeyFile(c.dir);
  assert.equal(Boolean(stale.members[b.peerId]), false, '前提：c 不认识 b');

  // b 拉票：原来会 401 not-a-member（对端永远投不进来 → 群选不出 leader）
  const vote = await requestGroupVote({
    baseUrl: c.baseUrl,
    ...groupArgs(cluster, b.peerId),
    epoch: 3,
    candidate: b.peerId,
  });
  assert.equal(vote.vote, true, JSON.stringify(vote));
  assert.equal(vote.epoch, 3);
  // 自愈：c 把 b 补回成员表（并落盘）
  const healed = readGroupKeyFile(c.dir);
  assert.ok(healed.members[b.peerId], 'c 必须把 b 补回成员表并落盘');
  // 第二次直接投，不再走自愈分支
  const again = await requestGroupVote({
    baseUrl: c.baseUrl,
    ...groupArgs(cluster, b.peerId),
    epoch: 4,
    candidate: b.peerId,
  });
  assert.equal(again.vote, true);

  // 非领导权路径仍然严格：成员表没有的发送方打 pull 仍 401 not-a-member（不自愈）
  await assert.rejects(
    () => pullGroupMessages({ baseUrl: c.baseUrl, ...groupArgs(cluster, 'peer-not-in-group') }),
    (error) => {
      assert.equal(error.status, 401);
      assert.equal(error.code, 'not-a-member');
      return true;
    },
  );
});
// 说明：post 走 per-peer 签名，这里顺带确认 leader 真的能收（详情见 group-commit.test.mjs）
test('S3 leader 就绪：hub leader 的 post 通道可用（202/201 由 commit 测试覆盖）', async (t) => {
  const cluster = await startCluster(t, { count: 2, quorum: 'none' });
  const [a, b] = cluster.nodes;
  const posted = await postAs(a.baseUrl, b.peerId, { kind: 'chat', text: 'ping' });
  assert.equal(posted.status, 201, posted.text);
  assert.equal(posted.json.seq, 1);
});

