/**
 * 真机回归 pin（2026-11-09 诊断「seq 74 卡在未提交」）。
 *
 * 真机两条并存的现象：
 *   A. hub 自己的门面直写（面板发言 / 派单回执）绕过 propose→commit，
 *      只推进 lastSeq，不推进 commitSeq → 日志里有一条「永远未提交」的消息，
 *      pending 里也没有它（pendingCount=0），任何补偿都无从下手。
 *      **这一条已修（hub 侧走提交完备写）**，所以用例反转成「两者同步推进」；
 *      历史遗留（真机 73/74）由启动期对账兜底，见 group-hub-commit.test.mjs。
 *   B. 成员副本的 epoch 同时被两个平面写入（角色平面 roleState().epoch 与
 *      群平面 keyVersion），一旦角色的 epoch 更大，此后所有 pull 批次都被
 *      「旧 leader 的补发」整批丢弃（added=0/stale=true），拉取永远成功、永远拉不到。
 *      **本机已修（memberTick 传下去的是两个平面里更大的那个）**，所以这一条反转成
 *      「修复后的正确行为」；同时补一条反向保护：真正的旧 leader 补发仍必须丢弃。
 *
 * 真机数据：hub lastSeq=74 / commitSeq=73 / 可见消息最大 seq=73；
 * 本机 group-role.json epoch=2135，group-replica.json epoch=2133，
 * hub pull 响应 epoch=3（=keyVersion），于是每 10s 的 pull 都是 got=0。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as sleep } from 'node:timers/promises';
import { startCluster } from './group-cluster.mjs';

/** 等一个条件成立（选举/心跳是异步的，不给固定 sleep 猜时间）。 */
async function waitFor(check, ms = 3000) {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    if (check()) return true;
    await sleep(20);
  }
  return Boolean(check());
}

/**
 * 显式补差一轮：后台那一轮（成员 listen 时的首发 pull）可能正在飞，
 * 撞上了 memberTick 会如实回 reason=skipped —— 那不是被测行为，重试即可。
 */
async function pullNow(member) {
  for (let attempt = 0; attempt < 40; attempt += 1) {
    const out = await member.server.group.pull();
    if (out?.reason !== 'skipped') return out;
    await sleep(25);
  }
  throw new Error('pull 一直被后台那一轮占着（reason=skipped）');
}

test('DEFECT-A：hub 门面直写也必须走提交完备写（commitSeq 跟着 lastSeq 走，且不留 pending）', async (t) => {
  const cluster = await startCluster(t, { count: 2 });
  const hub = cluster.nodes[0];
  const before = hub.server.group.role();
  assert.equal(before.role, 'leader', '集群里 node0 必须是 leader，否则本用例不成立');

  const posted = hub.server.group.post({ kind: 'chat', text: '直写路径自检' });
  assert.equal(Number(posted?.seq), 1, '门面直写应同步返回带 seq 的那条消息');

  const after = hub.server.group.role();
  assert.equal(hub.server.group.lastSeq(), posted.seq, 'lastSeq 是推进了的（真机 74）');
  // 反转：修好之后 commitSeq 与 lastSeq 同步推进（修前 commitSeq 停在旧值 = 真机 73）
  assert.equal(after.commitSeq, posted.seq, 'commitSeq 必须与 lastSeq 同步推进（真机停在 73 的那个洞）');
  assert.equal(after.commitSeq, hub.server.group.lastSeq(), '两者相等 = 没有「永远未提交」的尾巴');
  assert.equal(after.pendingCount, 0, '它走的是提交完备写，不是提案 —— pending 里不该有残留');
  assert.equal(hub.server.group.state().pendingCount, 0);

  // 同一条消息对 pull 是可见的：消息确实进了权威日志
  const history = hub.server.group.history({ sinceSeq: 0 });
  assert.ok(Array.isArray(history) && history.length >= 1, 'hub 权威日志里能看到这条');
  assert.deepEqual(history.map((m) => m.seq), [posted.seq]);
});

test('FIXED-B：副本 epoch 被角色平面抬高后，群平面的补差仍然收得下（真机 73 → 74）', async (t) => {
  const cluster = await startCluster(t, { count: 2 });
  const hub = cluster.nodes[0];
  const member = cluster.nodes[1];
  assert.equal(hub.server.group.role().role, 'leader', 'node0 必须是 leader');
  assert.ok(member.server.group.replica, '成员节点必须有副本存储');

  // 群平面 epoch = pull 响应里的 epoch（= keyVersion，真机 3）
  const pageEpoch = Number(hub.server.group.state({ includeKey: true }).epoch);
  assert.ok(pageEpoch > 0, 'hub 的群平面 epoch 必须有值，否则本用例不成立');

  // 角色平面 epoch 抬上去（真机 2133 的来路）：leader 一次 claim 换 epoch，
  // 成员在拉票/心跳里接受更高 epoch —— 两个平面就此错开。
  await hub.server.group.claim();
  const raised = await waitFor(() => Number(member.server.group.role().epoch) > pageEpoch);
  const roleEpoch = Number(member.server.group.role().epoch);
  assert.ok(raised, '成员角色平面 epoch 必须高于群平面，实际 ' + roleEpoch + ' vs ' + pageEpoch);

  // 缺陷现场：副本 epoch 被角色平面写成 roleEpoch（applyCommitted 的口径），
  // 而 hub 的 pull 响应带的是群平面 pageEpoch —— 修复前 pageEpoch < roleEpoch
  // 恒成立，每一批补差都被当成「旧 leader 的补发」整批丢掉。
  const seeded = member.server.group.replica.append({ epoch: roleEpoch, messages: [] });
  assert.equal(seeded.epoch, roleEpoch, '副本 epoch = 角色平面值（真机 2133）');
  assert.equal(member.server.group.replica.state().lastSeq, 0, '副本还没收到任何一条');

  // hub 直写一条：真机 seq 74 走的就是这条路径（可读、未提交、pull 拉得到）
  const posted = hub.server.group.post({ kind: 'chat', text: '补差目标' });
  const seq = Number(posted?.seq);
  assert.ok(seq > 0);

  const pulled = await pullNow(member);
  assert.equal(pulled.ok, true);
  const arrived = await waitFor(() => member.server.group.replica.state().lastSeq === seq);
  assert.ok(
    arrived,
    'seq 必须被收下（真机 73 → 74），实际 lastSeq=' + member.server.group.replica.state().lastSeq,
  );
  assert.equal(member.server.group.replica.messages({ sinceSeq: 0 }).length, 1, '消息条数 53 → 54');
  assert.equal(member.server.group.replica.state().epoch, roleEpoch, '副本 epoch 不被拉低');
});

test('反向保护：副本 epoch 高于两个平面时，真正的旧 leader 补发仍被整批丢弃', async (t) => {
  const cluster = await startCluster(t, { count: 2 });
  const hub = cluster.nodes[0];
  const member = cluster.nodes[1];

  // 角色平面 epoch = 2（一次 claim），群平面 = 1
  await hub.server.group.claim();
  await waitFor(() => Number(member.server.group.role().epoch) > 1);

  // 副本已经被 epoch 9 的「新 leader」写过：它显然比当前两个平面都新
  const newer = 9;
  const seeded = member.server.group.replica.append({
    epoch: newer,
    messages: [{ seq: 1, ts: Date.now(), from: { peerId: cluster.ids[1], name: 'member' }, kind: 'chat', text: '新' }],
  });
  assert.equal(seeded.epoch, newer);

  // 落后 leader 的两条补发（seq 1 重复、seq 2 是本机没有的）
  hub.server.group.post({ kind: 'chat', text: '旧-1' });
  const second = hub.server.group.post({ kind: 'chat', text: '旧-2' });
  assert.equal(Number(second?.seq), 2);

  const pulled = await pullNow(member);
  assert.equal(pulled.ok, true, '拉取本身还是成功的');
  assert.equal(pulled.added, 0, '安全阀：整批仍被丢弃，一条都不收');
  assert.equal(member.server.group.replica.state().lastSeq, 1, 'lastSeq 不动（还停在副本自己的 1）');
  assert.equal(member.server.group.replica.state().epoch, newer, 'epoch 不被拉回');
  assert.equal(member.server.group.replica.messages({ sinceSeq: 1 }).length, 0, 'seq 2 没有补进来');
});
