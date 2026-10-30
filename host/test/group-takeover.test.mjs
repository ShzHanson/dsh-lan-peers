/**
 * v0.7.0 S3 补充 · 受限的启动竞选（priority-takeover）。
 *
 * 契约 §4 是「epoch 高者胜，同 epoch 才比 priority」——优先级不能跨 epoch 夺权，
 * 于是优先节点重启期间被别人抢到更高 epoch 后会永久当 follower。这里给它一次有边界的重试权：
 * 配置上没有 group.hub 的本机，启动稳定 2×heartbeatMs 后、优先级**严格更高**时尝试一次。
 *
 * 覆盖：①一次成功接管（epoch+1，原 leader 降级）②priority 相等不触发
 *      ③接管失败后推进 30s 也不重试 ④配了 group.hub 的成员不触发
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as sleep } from 'node:timers/promises';
import { roleOf, startCluster, waitFor } from './group-cluster.mjs';

const takeoverOf = (node) => node.server.group.takeover();

const electionLines = (lines, kind) => lines
  .filter((line) => line.includes('[group] election ' + kind) && line.includes('reason=priority-takeover'));

test('S3 启动接管：高优先节点一次接管成功（epoch+1），原 leader 降级', async (t) => {
  const lines = [];
  const cluster = await startCluster(t, {
    count: 2,
    // 两台都是 hub 角色（配置上没有 group.hub），才有接管资格
    hubRoles: [0, 1],
    // 低优先（10）先当 leader；高优先（0）以 follower 起步
    priorities: [10, 0],
    followerOf: { 1: 0 },
    logger: (line) => lines.push(String(line)),
  });
  const [low, high] = cluster.nodes;
  assert.equal(roleOf(low).role, 'leader');
  assert.equal(roleOf(high).role, 'follower');
  assert.equal(roleOf(high).leaderPeerId, low.peerId);
  assert.equal(takeoverOf(high).attempts, 0, '刚开始还不该动手');

  await waitFor(() => takeoverOf(high).attempts === 1, { timeoutMs: 5_000 });
  await waitFor(() => roleOf(high).role === 'leader', { timeoutMs: 5_000 });
  await waitFor(() => roleOf(low).leaderPeerId === high.peerId, { timeoutMs: 5_000 });

  assert.equal(roleOf(high).epoch, 2, '接管必须抬 epoch');
  assert.equal(roleOf(low).role, 'follower');
  assert.equal(roleOf(low).epoch, 2);
  assert.equal(takeoverOf(high).attempts, 1);
  assert.equal(takeoverOf(high).attempted, true);

  const text = lines.join('\n');
  assert.match(text, /\[group\] takeover attempt epoch=2 priority=0 leaderPriority=10/);
  assert.equal(electionLines(lines, 'won').length, 1, '一次成功接管要留一行带票数的日志');
  assert.match(text, /\[group\] takeover won epoch=2 votes=2\/2/);

  // 稳定后不再重试：推进到远超过稳定期，attempts 仍然是 1
  await sleep(400);
  assert.equal(takeoverOf(high).attempts, 1);
  assert.equal(electionLines(lines, 'won').length, 1);
});

test('S3 启动接管：priority 相等时一律不触发', async (t) => {
  const cluster = await startCluster(t, {
    count: 2,
    hubRoles: [0, 1],
    priorities: [0, 0],
    followerOf: { 1: 0 },
  });
  const [low, high] = cluster.nodes;
  // 等过稳定期（2×heartbeat=240ms）再多等几轮 tick
  await sleep(700);
  assert.equal(takeoverOf(high).attempts, 0, '优先级相等不得夺权');
  assert.equal(takeoverOf(high).attempted, false);
  assert.equal(roleOf(high).role, 'follower');
  assert.equal(roleOf(high).leaderPeerId, low.peerId);
  assert.equal(roleOf(low).role, 'leader');
});

test('S3 启动接管：失败一次后不再重试（假时钟推进 30s，接管仍只有 1 次）', async (t) => {
  let fake = Date.now();
  const clock = () => fake;
  const lines = [];
  const cluster = await startCluster(t, {
    count: 2,
    hubRoles: [0, 1],
    priorities: [10, 0],
    followerOf: { 1: 0 },
    // 心跳放慢，好让「稳定期」在假时钟里可控（租约 = 3×400 = 1200ms）
    heartbeatMs: 400,
    tickMs: 25,
    now: clock,
    logger: (line) => lines.push(String(line)),
  });
  const [low, high] = cluster.nodes;
  // 让 low 的心跳把「leader 优先级=10」教给 high（假时钟下真实时间照样走几轮）
  await sleep(600);
  assert.equal(takeoverOf(high).attempts, 0, '还没到稳定期（2×400=800ms）');

  // 把 leader 打死，再跨过稳定期：这一枪注定落空
  await low.server.close();
  fake += 900;
  await waitFor(() => takeoverOf(high).attempts === 1, { timeoutMs: 3_000 });
  assert.equal(roleOf(high).role, 'follower', '失败后不得成为 leader');
  assert.equal(electionLines(lines, 'lost').length, 1);
  assert.match(lines.join('\n'), /\[group\] takeover lost epoch=2 votes=1\/2/);

  // 推进 30s：普通租约过期选举可以重试，但**接管**必须一次就停
  fake += 30_000;
  await sleep(400);
  assert.equal(takeoverOf(high).attempts, 1, '接管每进程只允许一次');
  assert.equal(electionLines(lines, 'lost').length, 1);
  assert.equal(electionLines(lines, 'won').length, 0);
});

test('S3 启动接管：配了 group.hub 的成员节点不触发（即使优先级更高）', async (t) => {
  const cluster = await startCluster(t, { count: 2, priorities: [10, 0] });
  const [low, member] = cluster.nodes;
  assert.equal(low.server.group.isHub, true);
  assert.equal(member.server.group.isHub, false);
  await sleep(700);
  assert.equal(takeoverOf(member).attempts, 0, '成员节点（配置了 group.hub）不得夺权');
  assert.equal(roleOf(member).role, 'follower');
  assert.equal(roleOf(low).role, 'leader');
});

