/**
 * Lane A · 协议层四个洞的回归用例（S2 / H1 / H2 / H3）。
 *
 * 每条用例都写成**攻击形状**：改动前一定红，改动后必须绿。
 *   S2 心跳改写领导权   → 403 not-self-leader / 409 stale-epoch，角色文件不动
 *   H1 commit 无 leader 校验 → 409 not-leader；正文只认 pending；seq 不能自己抬
 *   H2 replicate 无发送方校验 → 409 not-leader；作者不在成员表的条目被丢弃
 *   H3 自愈落盘任意 id  → 快照里没有的 id 仍然 401，且绝不写进 group-key.json
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as sleep } from 'node:timers/promises';
import {
  commitGroupMessage,
  fetchGroupLease,
  proposeGroupMessage,
  readGroupKeyFile,
  replicateGroupMessages,
  requestGroupVote,
  sendGroupHeartbeat,
  writeGroupKeyFile,
} from '../../lib/group-client.mjs';
import { readRoleFile, roleOf, startCluster, waitFor } from './group-cluster.mjs';

const groupArgs = (cluster, senderId) => ({
  groupKey: cluster.groupKey,
  groupId: cluster.groupId,
  senderId,
});

const message = (seq, text, author) => ({
  seq,
  ts: Date.now(),
  from: { peerId: author, name: 'n-' + author },
  kind: 'chat',
  text,
  meta: {},
});

/** 后台首轮 tick 可能正占着 memberInFlight：等到真正跑完一轮（与 group-replica 同一套等法） */
async function pullNow(node, attempts = 40) {
  for (let i = 0; i < attempts; i += 1) {
    const out = await node.server.group.pull();
    if (out?.reason !== 'skipped') return out;
    await sleep(25);
  }
  throw new Error('member pull kept being skipped');
}

// ---------------------------------------------------------------------------
// S2 · 心跳不得改写领导权
// ---------------------------------------------------------------------------

test('S2 伪造心跳：leaderPeerId 不是发送方自己 → 403 not-self-leader，领导权不动', async (t) => {
  const cluster = await startCluster(t, { count: 3, heartbeatMs: 5_000, tickMs: 60_000 });
  const [a, b] = cluster.nodes;
  await waitFor(() => roleOf(b).leaderPeerId === a.peerId);
  const epoch = roleOf(a).epoch;

  // 攻击形状：合法 leader a 发心跳，但把 leaderPeerId 指向任意 id。
  // 修复前：这一条就让 b 把 leader 指针改写成 peer-ghost-leader（实测可复现）。
  await assert.rejects(
    () => sendGroupHeartbeat({
      baseUrl: b.baseUrl,
      ...groupArgs(cluster, a.peerId),
      epoch,
      leaderPeerId: 'peer-ghost-leader',
      lastSeq: 0,
      commitSeq: 0,
    }),
    (error) => {
      assert.equal(error.status, 403);
      assert.equal(error.code, 'not-self-leader');
      return true;
    },
  );

  const after = roleOf(b);
  assert.equal(after.leaderPeerId, a.peerId, 'leader 指针绝不能被心跳改写');
  assert.equal(after.role, 'follower');
  assert.equal(after.epoch, epoch, '被拒的心跳不能改 epoch');
  assert.equal(readRoleFile(b).leaderPeerId, a.peerId, '落盘的角色文件同理');
});

test('S2 心跳不得推进 epoch：epoch 更高 → 409 stale-epoch，本机停在原 epoch', async (t) => {
  const cluster = await startCluster(t, { count: 3, heartbeatMs: 5_000, tickMs: 60_000 });
  const [a, b, c] = cluster.nodes;
  await waitFor(() => roleOf(b).leaderPeerId === a.peerId);
  const epoch = roleOf(b).epoch;

  // 攻击形状：C 用一条 epoch+50 的心跳宣告自己是 leader。
  // 修复前：B 被降级、epoch 直接被抬到 51（真机 epoch 膨胀的同一条路）。
  await assert.rejects(
    () => sendGroupHeartbeat({
      baseUrl: b.baseUrl,
      ...groupArgs(cluster, c.peerId),
      epoch: epoch + 50,
      leaderPeerId: c.peerId,
      lastSeq: 0,
      commitSeq: 0,
    }),
    (error) => {
      assert.equal(error.status, 409);
      assert.equal(error.code, 'stale-epoch');
      assert.equal(error.body.epoch, epoch, '响应里带回的本机 epoch 必须没变');
      return true;
    },
  );

  const after = roleOf(b);
  assert.equal(after.epoch, epoch, 'epoch 只能由 election 的票数推进');
  assert.equal(after.leaderPeerId, a.peerId);
  assert.equal(after.role, 'follower');
  assert.equal(readRoleFile(b).epoch, epoch, '落盘的 epoch 同样不动');
});

// ---------------------------------------------------------------------------
// H1 · commit 必须有 leader 校验，且只认本机 pending
// ---------------------------------------------------------------------------

test('H1 commit：非 leader 被拒、正文只认 pending、seq 不能由客户端抬高', async (t) => {
  const cluster = await startCluster(t, { count: 3, heartbeatMs: 5_000, tickMs: 60_000 });
  const [a, b, c] = cluster.nodes;
  await waitFor(() => roleOf(b).leaderPeerId === a.peerId && roleOf(c).leaderPeerId === a.peerId);
  const epoch = roleOf(a).epoch;

  // ① 非 leader（C）想把一条自己发明的消息「转正」到 B 的副本里
  await assert.rejects(
    () => commitGroupMessage({
      baseUrl: b.baseUrl,
      ...groupArgs(cluster, c.peerId),
      epoch,
      seq: 1,
      message: message(1, 'forged-by-non-leader', c.peerId),
    }),
    (error) => {
      assert.equal(error.status, 409);
      assert.equal(error.code, 'not-leader');
      return true;
    },
  );
  assert.deepEqual(b.server.group.replica.messages(), [], '非 leader 的 commit 不能落任何正文');
  assert.equal(roleOf(b).commitSeq, 0, 'commitSeq 不能被非 leader 推进');

  // ② leader 提案（进 B 的 pending），commit 时带一份**不同的正文**：只认 pending 那份
  const staged = { ...message(1, 'pending-text', a.peerId), seq: 1 };
  const proposed = await proposeGroupMessage({
    baseUrl: b.baseUrl,
    ...groupArgs(cluster, a.peerId),
    epoch,
    seq: 1,
    message: staged,
  });
  assert.equal(proposed.ok, true, JSON.stringify(proposed));
  const committed = await commitGroupMessage({
    baseUrl: b.baseUrl,
    ...groupArgs(cluster, a.peerId),
    epoch,
    seq: 1,
    message: { ...staged, text: 'forged-body-text' },
  });
  assert.equal(committed.ok, true, JSON.stringify(committed));
  assert.deepEqual(
    b.server.group.replica.messages().map((m) => m.text),
    ['pending-text'],
    'body.message 不得覆盖 pending 里那条',
  );

  // ③ 没提案过的 seq 用来抬高 commitSeq → 409 unknown-seq，号不动
  await assert.rejects(
    () => commitGroupMessage({
      baseUrl: b.baseUrl,
      ...groupArgs(cluster, a.peerId),
      epoch,
      seq: 99,
      message: message(99, 'inflate-commit-seq', a.peerId),
    }),
    (error) => {
      assert.equal(error.status, 409);
      assert.equal(error.code, 'unknown-seq');
      return true;
    },
  );
  assert.equal(roleOf(b).commitSeq, 1, 'commitSeq 只能跟着真提交的号走');
  assert.deepEqual(b.server.group.replica.messages().map((m) => m.seq), [1]);
});

// ---------------------------------------------------------------------------
// H2 · replicate 必须校验发送方，并逐条校验作者
// ---------------------------------------------------------------------------

test('H2 replicate：非 leader 推送被拒；作者不在成员表的条目被丢弃', async (t) => {
  const logs = [];
  const cluster = await startCluster(t, {
    count: 3,
    heartbeatMs: 5_000,
    tickMs: 60_000,
    logger: (line) => logs.push(String(line)),
  });
  const [a, b, c] = cluster.nodes;
  await waitFor(() => roleOf(b).leaderPeerId === a.peerId && roleOf(c).leaderPeerId === a.peerId);
  const epoch = roleOf(a).epoch;

  // ① 非 leader（C）往 B 的副本里推历史（第二作者）
  await assert.rejects(
    () => replicateGroupMessages({
      baseUrl: b.baseUrl,
      ...groupArgs(cluster, c.peerId),
      epoch,
      leaderPeerId: c.peerId,
      messages: [message(1, 'forged-replica', c.peerId)],
    }),
    (error) => {
      assert.equal(error.status, 409);
      assert.equal(error.code, 'not-leader');
      return true;
    },
  );
  assert.deepEqual(b.server.group.replica.messages(), [], '非 leader 推来的日志一条都不能落');

  // ② 合法 leader 推两条，其中一条的作者是幽灵 id：丢弃那一条（不整批拒）
  const applied = await replicateGroupMessages({
    baseUrl: b.baseUrl,
    ...groupArgs(cluster, a.peerId),
    epoch,
    leaderPeerId: a.peerId,
    messages: [message(1, 'legit', a.peerId), message(2, 'ghost-author', 'ghost-author-0001')],
  });
  assert.equal(applied.ok, true, JSON.stringify(applied));
  assert.equal(applied.added, 1, '只落作者合法的条目');
  assert.deepEqual(b.server.group.replica.messages().map((m) => m.text), ['legit']);
  assert.match(logs.join(' '), /\[group\] replicate dropped n=1/, '丢弃要留一行日志');
});

// ---------------------------------------------------------------------------
// H3 · 自愈不得把任意 id 写进 group-key.json
// ---------------------------------------------------------------------------

test('H3 自愈：权威快照里没有的 id 仍然 401，且绝不落盘', async (t) => {
  const logs = [];
  const cluster = await startCluster(t, { count: 3, logger: (line) => logs.push(String(line)) });
  const [a, b, c] = cluster.nodes;
  // 真机上成员启动后第一轮 pull 就拿到了权威快照（C 这里是成员节点）
  const pulled = await pullNow(c);
  assert.equal(pulled.ok, true, JSON.stringify(pulled));

  const ghost = 'ghost-member-0001';
  await assert.rejects(
    () => requestGroupVote({
      baseUrl: c.baseUrl,
      ...groupArgs(cluster, ghost),
      epoch: 1,
      candidate: ghost,
    }),
    (error) => {
      assert.equal(error.status, 401);
      assert.equal(error.code, 'not-a-member');
      return true;
    },
  );
  assert.equal(readGroupKeyFile(c.dir).members[ghost], undefined, '幽灵 id 绝不能被写进成员表');
  assert.match(logs.join(' '), /\[group\] self-heal refused peer=/, '拒绝要留一行日志');

  // quorum 分母不因为一次自愈尝试而变大（以前 ghost 会进成员表并被计入分母）
  const lease = await fetchGroupLease({ baseUrl: c.baseUrl, ...groupArgs(cluster, b.peerId) });
  assert.equal(lease.memberCount, 3);

  // 对照组：快照里出现过的 id 仍能自愈入表（真机 not-a-member 那条回归不能丢）
  const keyFile = readGroupKeyFile(c.dir);
  delete keyFile.members[b.peerId];
  writeGroupKeyFile(c.dir, keyFile);
  assert.equal(readGroupKeyFile(c.dir).members[b.peerId], undefined, '前提：C 的成员表里没有 B');
  const vote = await requestGroupVote({
    baseUrl: c.baseUrl,
    ...groupArgs(cluster, b.peerId),
    epoch: roleOf(c).epoch + 2,
    candidate: b.peerId,
  });
  assert.equal(vote.vote, true, JSON.stringify(vote));
  assert.ok(readGroupKeyFile(c.dir).members[b.peerId], '快照里的成员仍必须能自愈入表');
});
