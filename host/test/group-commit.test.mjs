/**
 * v0.7.0 S3 · 两阶段提交（契约 group-s3-contract.md §5）。
 *
 * 覆盖：majority 下 propose→commit 全链路、ack 不足超时 → 503 且消息不可见、
 *      成员 pending 不暴露（pull/lease 都看不到）、commit 后可见、
 *      quorum:none 直接提交、失败的提案不消耗 seq（连续无重复）、
 *      成员当 leader 也能完成两阶段提交。
 *
 * ⚠ 造「不可达」只能靠**真实连接失败**（cluster.makeUnreachable → 关停监听）。
 *   不要再改成员的 baseUrl 假装失联：寻址有三层回退（群成员表 → 学到的地址缓存 → peers.json），
 *   而且心跳/探活会用 X-Peer-Base 把成员自报的地址**写回**成员表 —— 改完一个心跳就被学回来，
 *   提案照样送达、quorum 满足，于是拿到 201（那是产品的正确行为，红的是测试假设）。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { listenOnRandomPort } from '../../test-support/ports.mjs';
import net from 'node:net';
import {
  commitGroupMessage,
  fetchGroupLease,
  proposeGroupMessage,
  pullGroupMessages,
} from '../../lib/group-client.mjs';
import { postAs, postAsEncrypted, roleOf, startCluster, waitFor } from './group-cluster.mjs';

const groupArgs = (cluster, senderId) => ({
  groupKey: cluster.groupKey,
  groupId: cluster.groupId,
  senderId,
});

// ---------------------------------------------------------------------------
// §5 majority：propose → commit
// ---------------------------------------------------------------------------

test('S3 majority：propose→commit 全链路，三台都可见且 commitSeq 前进', async (t) => {
  const lines = [];
  const cluster = await startCluster(t, { count: 3, logger: (line) => lines.push(String(line)) });
  const [a, b, c] = cluster.nodes;
  assert.equal(roleOf(a).role, 'leader');

  const posted = await postAs(a.baseUrl, b.peerId, { kind: 'chat', text: 'hello-quorum' });
  assert.equal(posted.status, 201, posted.text);
  assert.equal(posted.json.seq, 1);
  assert.equal(typeof posted.json.ts, 'number');

  // leader 的消息表立即可见（提交后才进 messages）
  assert.deepEqual(a.server.group.history({ sinceSeq: 0 }).map((m) => m.text), ['hello-quorum']);
  // 成员靠 commit 广播转正（propose 阶段的 pending 不算）
  await waitFor(() => b.server.group.replica.state().lastSeq === 1);
  await waitFor(() => c.server.group.replica.state().lastSeq === 1);
  assert.deepEqual(b.server.group.replica.messages().map((m) => m.text), ['hello-quorum']);
  assert.deepEqual(c.server.group.replica.messages().map((m) => m.text), ['hello-quorum']);
  assert.equal(roleOf(a).commitSeq, 1);
  assert.equal(a.server.group.state().pendingCount, 0, '提交后 pending 必须清空');

  // 日志：一行 post、一行 commit、至少一次心跳；不含正文/密钥
  // 心跳按 heartbeatMs（默认 120ms）广播，用例本身只要 ~200ms —— 必须**等事件**，不能靠时序。
  await waitFor(() => lines.some((line) => line.startsWith('[group] heartbeat ')), { timeoutMs: 3_000 });
  const logText = lines.join('\n');
  assert.match(logText, /\[group\] post kind=chat seq=1 /);
  assert.match(logText, /\[group\] commit seq=1 /);
  assert.match(logText, /\[group\] heartbeat /);
  assert.equal(logText.includes('hello-quorum'), false, '日志绝不能出现消息正文');
  assert.equal(logText.includes(cluster.groupKey), false, '日志绝不能出现 groupKey');
});

test('S3 ack 不足：成员全部下线 → 503、消息不可见、seq 不被消耗、pending 归零', async (t) => {
  const lines = [];
  const cluster = await startCluster(t, { count: 3, logger: (line) => lines.push(String(line)) });
  const [a, b, c] = cluster.nodes;
  // 两台成员直接下线：leader 还在，但只能拿到自己那一票
  await b.server.close();
  await c.server.close();

  // 连不上（ECONNREFUSED）时 ack 立刻不足 → 立即 503，不必等满超时
  const startedAt = Date.now();
  const posted = await postAs(a.baseUrl, b.peerId, { kind: 'chat', text: 'must-not-be-visible' });
  const elapsedMs = Date.now() - startedAt;
  assert.equal(posted.status, 503, posted.text);
  assert.equal(posted.json.error, 'quorum-unavailable');
  assert.equal(posted.json.epoch, roleOf(a).epoch);
  assert.ok(elapsedMs < 1_000, '连不上就该快速失败，实际 ' + elapsedMs + 'ms');

  // 未提交的消息任何地方都看不到
  assert.deepEqual(a.server.group.history({ sinceSeq: 0 }), []);
  assert.equal(a.server.group.state().lastSeq, 0, '失败的提案不消耗 seq');
  assert.equal(a.server.group.state().pendingCount, 0, 'pending 必须被丢弃');
  assert.equal(roleOf(a).commitSeq, 0);
  const pulled = await pullGroupMessages({ baseUrl: a.baseUrl, ...groupArgs(cluster, b.peerId) });
  assert.deepEqual(pulled.messages, [], 'pull 也看不到未提交的消息');
  assert.equal(pulled.lastSeq, 0);
  assert.match(lines.join('\n'), /\[group\] propose dropped seq=1 /);
});

test('S3 提交超时：对端接受连接但不响应 → 等到 commitTimeoutMs 才 503，消息仍不可见', async (t) => {
  const cluster = await startCluster(t, { count: 3, commitTimeoutMs: 200 });
  const [a, b, c] = cluster.nodes;
  // 黑洞：TCP 握手成功但永不回 HTTP 响应（模拟半死节点，和 ECONNREFUSED 区分开）
  const sockets = new Set();
  const blackhole = net.createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => sockets.delete(socket));
  });
  await listenOnRandomPort(blackhole);
  t.after(() => {
    for (const socket of sockets) socket.destroy();
    blackhole.close();
  });
  blackhole.unref();
  const holeUrl = `http://127.0.0.1:${blackhole.address().port}`;
  const members = a.server.group.state().members;
  members[b.peerId].baseUrl = holeUrl;
  members[c.peerId].baseUrl = holeUrl;

  const startedAt = Date.now();
  const posted = await postAs(a.baseUrl, b.peerId, { kind: 'chat', text: 'never-committed' });
  const elapsedMs = Date.now() - startedAt;
  assert.equal(posted.status, 503, posted.text);
  assert.equal(posted.json.error, 'quorum-unavailable');
  assert.ok(elapsedMs >= 150, '半死节点要等满 commitTimeoutMs(200ms)，实际 ' + elapsedMs + 'ms');
  assert.deepEqual(a.server.group.history({ sinceSeq: 0 }), []);
  assert.equal(a.server.group.state().pendingCount, 0);
  assert.equal(a.server.group.state().lastSeq, 0);
});
test('S3 成员 pending 不暴露：propose 后 pull 看不到，commit 后立刻可见', async (t) => {
  const cluster = await startCluster(t, { count: 3 });
  const [a, b, c] = cluster.nodes;
  const message = {
    seq: 1,
    ts: Date.now(),
    from: { peerId: b.peerId, name: b.name },
    kind: 'chat',
    text: 'pending-only',
    meta: {},
  };

  const proposed = await proposeGroupMessage({
    baseUrl: c.baseUrl,
    ...groupArgs(cluster, a.peerId),
    epoch: roleOf(a).epoch,
    seq: 1,
    message,
  });
  assert.equal(proposed.ok, true, JSON.stringify(proposed));
  assert.equal(proposed.accepted, true);

  // 不可见：副本 lastSeq、副本消息、pull、history 都不该有它
  assert.equal(c.server.group.replica.state().lastSeq, 0);
  assert.deepEqual(c.server.group.replica.messages(), []);
  const pulled = await pullGroupMessages({ baseUrl: c.baseUrl, ...groupArgs(cluster, b.peerId) });
  assert.deepEqual(pulled.messages, []);
  const leasePending = await fetchGroupLease({ baseUrl: c.baseUrl, ...groupArgs(cluster, a.peerId) });
  assert.equal(leasePending.pendingCount, 1, 'pending 条数要能看到，但正文不可见');
  assert.equal(leasePending.commitSeq, 0);

  const committed = await commitGroupMessage({
    baseUrl: c.baseUrl,
    ...groupArgs(cluster, a.peerId),
    epoch: roleOf(a).epoch,
    seq: 1,
    message,
  });
  assert.equal(committed.ok, true, JSON.stringify(committed));
  assert.equal(committed.commitSeq, 1);
  assert.deepEqual(c.server.group.replica.messages().map((m) => m.text), ['pending-only']);
  const leaseAfter = await fetchGroupLease({ baseUrl: c.baseUrl, ...groupArgs(cluster, a.peerId) });
  assert.equal(leaseAfter.pendingCount, 0);
  assert.equal(leaseAfter.commitSeq, 1);
  // epoch 不符的 commit 一律 409（防止旧 leader 回灌）
  await assert.rejects(() => commitGroupMessage({
    baseUrl: c.baseUrl,
    ...groupArgs(cluster, a.peerId),
    epoch: roleOf(a).epoch + 7,
    seq: 2,
    message: { ...message, seq: 2, text: 'ghost' },
  }), (error) => {
    assert.equal(error.status, 409);
    assert.equal(error.code, 'epoch-mismatch');
    return true;
  });
});

test('S3 quorum:none：跳过 propose/commit 直接提交（两成员群可写）', async (t) => {
  const lines = [];
  const cluster = await startCluster(t, {
    count: 2,
    quorum: 'none',
    logger: (line) => lines.push(String(line)),
  });
  const [a, b] = cluster.nodes;
  assert.equal(roleOf(a).quorum, 'none');
  // 另一台下线也不影响可写：none 就是可用性优先
  await b.server.close();

  const posted = await postAs(a.baseUrl, b.peerId, { kind: 'chat', text: 'best-effort' });
  assert.equal(posted.status, 201, posted.text);
  assert.equal(posted.json.seq, 1);
  assert.equal(a.server.group.state().pendingCount, 0, 'quorum:none 不产生 pending');
  assert.equal(a.server.group.state().lastSeq, 1);
  assert.equal(roleOf(a).commitSeq, 1, '直接提交也要推进 commitSeq');
  assert.match(lines.join('\n'), /\[group\] post kind=chat seq=1 .*quorum=none/);
});

test('S3 seq 连续无重复：失败的提案不消耗号，恢复后重试拿到下一个号', async (t) => {
  // 心跳拉长到 1s ⇒ 租约 3s：整条用例（关停 → 503 → 恢复 → 201）都跑在同一个租约窗口里，
  // leader 不会中途因租约过期而换届。否则恢复回来的成员会接连发起选举、epoch 反超 leader，
  // 低 epoch 的提案被 409 stale-epoch 拒掉 —— 那是另一条语义，会把这个用例污染成假红。
  const logs = [];
  const cluster = await startCluster(t, {
    count: 3,
    heartbeatMs: 1_000,
    commitTimeoutMs: 1_500,
    logger: (line) => logs.push(String(line)),
  });
  const [a, b, c] = cluster.nodes;
  assert.equal(roleOf(a).role, 'leader');

  const first = await postAs(a.baseUrl, b.peerId, { kind: 'chat', text: 'first' });
  assert.equal(first.status, 201);
  assert.equal(first.json.seq, 1);

  // 真不可达：关掉两台成员的监听 → 提案连接被真正拒绝，只拿得到自己一票 → 503。
  // 成员表与 quorum 分母（3 人 → 需要 2 票）保持不变，这正是本条要证的东西。
  await cluster.makeUnreachable(b);
  await cluster.makeUnreachable(c);
  const failed = await postAs(a.baseUrl, b.peerId, { kind: 'chat', text: 'ghost' });
  assert.equal(failed.status, 503, failed.text);
  assert.equal(failed.json.error, 'quorum-unavailable');
  assert.equal(a.server.group.state().lastSeq, 1, '失败的提案不能推进 lastSeq');
  assert.equal(a.server.group.state().pendingCount, 0, '丢弃的提案不留在未提交区');

  // 恢复一台就够（self + 1 = 2 票）：抢回原端口，成员表里的地址本来就没变，无需重新学习。
  const c2 = await cluster.restore(c);
  assert.equal(c2.baseUrl, c.baseUrl, '恢复应抢回原端口，成员表里的寻址保持不变');
  assert.equal(roleOf(a).role, 'leader', '整个窗口都在租约内，leader 不该换届');
  // 心跳里的 X-Peer-Base 会把「发送方自己」的地址记到成员表（等事件，不靠时序）
  await waitFor(() => a.server.group.state().members[c2.peerId]?.baseUrl === c2.baseUrl, { timeoutMs: 5_000 });

  // 恢复后重试：必须是 2（不复用 1、也不跳号）
  logs.length = 0;
  const retried = await postAs(a.baseUrl, b.peerId, { kind: 'chat', text: 'second' });
  assert.equal(
    retried.status,
    201,
    retried.text + ' role=' + roleOf(a).role + '@' + roleOf(a).epoch
      + ' logs=' + JSON.stringify(logs.slice(-10)),
  );
  assert.equal(retried.json.seq, 2);

  // leader 的权威视图：seq 连续、不重复、正文按序
  const logOf = (node) => (node.server.group.isHub
    ? node.server.group.history({ sinceSeq: 0 })
    : node.server.group.replica.messages({ sinceSeq: 0 }));
  const leaderLog = logOf(a);
  assert.deepEqual(leaderLog.map((m) => m.seq), [1, 2], '已提交的 seq 连续且不重复');
  assert.equal(new Set(leaderLog.map((m) => m.seq)).size, leaderLog.length);
  assert.deepEqual(leaderLog.map((m) => m.text), ['first', 'second']);
  assert.ok(Number(roleOf(a).commitSeq) >= 2, 'commitSeq 不倒退');

  // 其它节点最终都看到两条（commit 广播 + 补差）
  // 恢复的那台靠 commit 广播把两条都收下；b 一直关着，不参与断言
  await waitFor(() => {
    const log = logOf(c2);
    return log.length >= 2 && log.at(-1).seq === 2;
  }, { timeoutMs: 8_000 });
  assert.deepEqual(logOf(c2).map((m) => m.seq), [1, 2], '恢复的成员日志必须连续无重复');
  assert.deepEqual(logOf(c2).map((m) => m.text), ['first', 'second']);
  assert.equal(logOf(a).map((m) => m.seq).join(','), '1,2', 'leader 的日志连续无重复');
});

test('S3 成员当 leader 也能完成两阶段提交（failover 后的写路径）', async (t) => {
  const cluster = await startCluster(t, { count: 3 });
  const [a, b, c] = cluster.nodes;
  assert.equal(roleOf(a).role, 'leader');

  const claim = await b.server.group.claim();
  assert.equal(claim.ok, true, JSON.stringify(claim));
  assert.equal(claim.role, 'leader');
  await waitFor(() => roleOf(a).role === 'follower' && roleOf(c).leaderPeerId === b.peerId);

  // 成员 leader 收 post：propose 给 A、C，ack 够了再落到它自己的副本
  const posted = await postAs(b.baseUrl, a.peerId, { kind: 'chat', text: 'written-by-member-leader' });
  assert.equal(posted.status, 201, posted.text);
  assert.equal(posted.json.seq, 1);
  assert.deepEqual(b.server.group.replica.messages().map((m) => m.text), ['written-by-member-leader']);

  // hub 已降级为 follower：它靠 commit 把消息转正进 group.json
  await waitFor(() => a.server.group.history({ sinceSeq: 0 }).length === 1);
  assert.deepEqual(a.server.group.history({ sinceSeq: 0 }).map((m) => m.text), ['written-by-member-leader']);
  assert.equal(a.server.group.state().lastSeq, 1);
  await waitFor(() => c.server.group.replica.state().lastSeq === 1);
  assert.equal(roleOf(b).commitSeq, 1);
});

test('S3 成员当 leader 且要求加密时：post 走 X-Peer-Enc 也能两阶段提交（真机 401 的回归）', async (t) => {
  const cluster = await startCluster(t, { count: 3, requireEncryption: true });
  const [a, b, c] = cluster.nodes;
  const claim = await b.server.group.claim();
  assert.equal(claim.ok, true, JSON.stringify(claim));
  await waitFor(() => roleOf(a).role === 'follower');
  const posted = await postAsEncrypted(b.baseUrl, a.peerId, { kind: 'chat', text: 'encrypted-to-member-leader' });
  assert.equal(posted.status, 201, posted.text);
  assert.equal(posted.json.seq, 1);
  assert.deepEqual(b.server.group.replica.messages().map((m) => m.text), ['encrypted-to-member-leader']);
  // hub 侧靠 commit 转正（加密通道同理）
  await waitFor(() => a.server.group.history({ sinceSeq: 0 }).length === 1);
});
test('S3 取号闸门：pending 占着的号不会被单阶段写（面板/管理接口）复用', async (t) => {
  const cluster = await startCluster(t, { count: 3, commitTimeoutMs: 2_000 });
  const [a, b, c] = cluster.nodes;
  // 黑洞：提案会一直挂在 pending 里，直到 commitTimeoutMs 才丢弃
  const sockets = new Set();
  const blackhole = net.createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => sockets.delete(socket));
  });
  await listenOnRandomPort(blackhole);
  t.after(() => {
    for (const socket of sockets) socket.destroy();
    blackhole.close();
  });
  blackhole.unref();
  const holeUrl = `http://127.0.0.1:${blackhole.address().port}`;
  const members = a.server.group.state().members;
  members[b.peerId].baseUrl = holeUrl;
  members[c.peerId].baseUrl = holeUrl;

  const inflight = postAs(a.baseUrl, b.peerId, { kind: 'chat', text: 'slow-proposal' });
  await waitFor(() => a.server.group.state().pendingCount === 1, { timeoutMs: 1_500 });
  const pendingSeq = a.server.group.state().lastSeq + 1;
  assert.equal(a.server.group.state().lastSeq, 0, '提案未提交，lastSeq 不推进');

  // 面板/管理接口走单阶段写（server.group.post → GroupStore.append）：必须避开 pending 占的号
  const panel = a.server.group.post({ peerId: 'peer-panel', name: 'panel', kind: 'chat', text: 'panel-msg' });
  assert.equal(panel.seq, pendingSeq + 1, '单阶段写不得复用 pending 占着的 seq');

  const failed = await inflight;
  assert.equal(failed.status, 503, failed.text);
  assert.equal(a.server.group.state().pendingCount, 0, '超时后 pending 必须清空');

  // 恢复可达后继续写：号必须继续往前走，且任何两条消息不共用 seq
  members[b.peerId].baseUrl = b.baseUrl;
  members[c.peerId].baseUrl = c.baseUrl;
  const next = await postAs(a.baseUrl, b.peerId, { kind: 'chat', text: 'after-drop' });
  assert.equal(next.status, 201, next.text);
  assert.equal(next.json.seq, panel.seq + 1);
  const seqs = a.server.group.history({ sinceSeq: 0 }).map((m) => m.seq);
  assert.deepEqual(seqs, [panel.seq, panel.seq + 1]);
  assert.equal(new Set(seqs).size, seqs.length, 'seq 不得重复（客户端按 seq 去重）');
});

// 片 3b 回归（0.10.0-α）：抢答只对**群成员**生效。
//
// 起因：3b 把「群问答」挂到了 hub 的本地单阶段写这条缝上，而这条缝的作者是调用方给的
// （面板/管理接口没有作者身份 = `from.peerId === ''`）。于是 hub 会抢答**自己刚写下的**
// 那条面板消息，答出来的那条消息再占走下一个群 seq —— 单阶段写的取号从此不连续。
// 拆掉 answerDecision 的 memberAuthor 闸门（server 侧 groupAnswerVerdict），这个用例的
// `history().length === 1` 会先变 2，`next.seq === panel.seq + 1` 会变 panel.seq + 2。
test('S3 回归（片 3b）：未知作者的单阶段写不触发抢答，所以不额外占号', async (t) => {
  const cluster = await startCluster(t, { count: 2 });
  const [a] = cluster.nodes;
  const panel = a.server.group.post({ peerId: 'peer-panel', name: 'panel', kind: 'chat', text: 'panel-msg' });
  assert.equal(panel.seq, 1);
  assert.equal(a.server.group.state().pendingCount, 0, '单阶段写不产生 pending');

  // 等过一个完整的抢答窗口（抖动 ≤300ms + 一次 runner 调用 + 一次 250ms 轮询）
  await new Promise((resolve) => setTimeout(resolve, 1_500));

  assert.equal(a.server.group.history({ sinceSeq: 0 }).length, 1, '未知作者的消息不许被抢答（不许自己答自己）');
  assert.equal(a.server.group.state().pendingCount, 0, 'pending 基线仍是 0');

  const next = a.server.group.post({ peerId: 'peer-panel', name: 'panel', kind: 'chat', text: 'panel-2' });
  assert.equal(next.seq, panel.seq + 1, '答题不许占走下一个单阶段写的 seq');
  assert.deepEqual(
    a.server.group.history({ sinceSeq: 0 }).map((m) => m.seq),
    [panel.seq, panel.seq + 1],
    'seq 连续、无空号',
  );
  assert.equal(a.server.group.state().pendingCount, 0);
});
test('S3 提交串行化：连续多条 post 的 seq 严格连续（并发下也不撞号）', async (t) => {
  const cluster = await startCluster(t, { count: 3 });
  const [a, b] = cluster.nodes;
  const posted = await Promise.all([
    postAs(a.baseUrl, b.peerId, { kind: 'chat', text: 'p1' }),
    postAs(a.baseUrl, b.peerId, { kind: 'chat', text: 'p2' }),
    postAs(a.baseUrl, b.peerId, { kind: 'chat', text: 'p3' }),
  ]);
  for (const res of posted) assert.equal(res.status, 201, res.text);
  const seqs = a.server.group.history({ sinceSeq: 0 }).map((m) => m.seq);
  assert.deepEqual(seqs, [1, 2, 3]);
  assert.equal(new Set(seqs).size, 3);
  assert.equal(a.server.group.state().pendingCount, 0);
});

