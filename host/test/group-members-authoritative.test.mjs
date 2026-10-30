/**
 * v0.8.1 · 成员表「权威替换」回归（真机：移除不传播 → quorum 分母虚高）。
 *
 * 现场：NAS(hub/leader) 把两个测试成员 remove 掉（keyVersion 1→3），NAS 侧成员表变 2 人，
 * 但桌面成员 12 秒后仍是 4 人 —— 因为 v0.7.x 为了修 401 死锁把成员表刷新改成了并集（只增不减）。
 * 后果：桌面一旦当 leader 就以为 N=4、需要 3 票，而实际只有 2 台能投票 → 永远选不出 / 写不进去。
 *
 * 现在区分两种写入语义：
 *   · 权威快照（hub 的 state / pull 的 memberIds / grant）→ 整体替换（允许删除）；
 *   · 自愈入表（对端用 election/heartbeat 证明握着群密钥）→ 仍并集（upsertGroupMember）。
 * 并且 quorum 分母以「最近一次权威快照」为准，日志里带 source=authoritative|stale。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { applyToGroup, readGroupKeyFile, writeGroupKeyFile } from '../../lib/group-client.mjs';
import { postAs, roleOf, startCluster, waitFor } from './group-cluster.mjs';

const memberIdsOf = (node) => Object.keys(node.server.group.state().members ?? {}).sort();
const keyMembersOf = (dir) => Object.keys(readGroupKeyFile(dir).members ?? {}).sort();

/**
 * 驱动一次「真的跑完」的 pull。
 * 启动那轮 memberTick 可能还在飞（memberInFlight），此时 pull() 只会回 skipped —— 所以要等它 ok。
 */
async function pullOnce(node) {
  const done = await waitFor(async () => {
    const out = await node.server.group.pull();
    return out?.ok === true ? out : null;
  }, { timeoutMs: 8_000 });
  assert.ok(done, 'pull 没能跑完（node=' + node.peerId + '）');
  return done;
}

test('v0.8.1 ① 一次 pull 周期内成员表按权威快照收缩（不是并集保留）', async (t) => {
  const cluster = await startCluster(t, { count: 4 });
  const [a, b, c, d] = cluster.nodes;
  assert.equal(memberIdsOf(a).length, 4);

  // 移除两台（等价于面板上踢人：key 轮换 + blocked）。
  // 真机上被踢的机器随后就下线了，所以这里也真的关掉它们的监听 ——
  // 否则它们的心跳仍会走「自愈入表」把条目加回来（那条路径是刻意保留的，见 ③）。
  a.server.group.removeMember(c.peerId);
  a.server.group.removeMember(d.peerId);
  await cluster.makeUnreachable(c);
  await cluster.makeUnreachable(d);
  assert.equal(memberIdsOf(a).length, 2, 'hub 侧权威表已经是 2 人');

  assert.equal(keyMembersOf(b.dir).length, 4, '前提：成员本地还留着 4 条（旧语义下的并集）');

  await pullOnce(b);
  assert.deepEqual(keyMembersOf(b.dir), [a.peerId, b.peerId].sort(), '一次 pull 后必须与 hub 一致（2 人）');
  assert.equal(readGroupKeyFile(b.dir).members[c.peerId], undefined, '被移除的成员条目必须真的删掉');
  const keyFile = readGroupKeyFile(b.dir);
  assert.equal(keyFile.keyVersion, keyFile.epoch, 'keyVersion 与兼容别名 epoch 同值');
  assert.ok(keyFile.keyVersion >= 2, '踢人会轮换密钥');
});

test('v0.8.1 ② 收缩后该成员当 leader：分母 2、需要 2 票，能选出来并写进去', async (t) => {
  const logs = [];
  const cluster = await startCluster(t, { count: 4, logger: (line) => logs.push(String(line)) });
  const [a, b, c, d] = cluster.nodes;

  a.server.group.removeMember(c.peerId);
  a.server.group.removeMember(d.peerId);
  await cluster.makeUnreachable(c);
  await cluster.makeUnreachable(d);
  await pullOnce(b);
  assert.equal(keyMembersOf(b.dir).length, 2);

  // b 在 epoch 最高值上接管（force claim 不受退避闸门限制）
  const claimed = await b.server.group.claim({ epoch: Math.max(roleOf(a).epoch, roleOf(b).epoch) + 1 });
  assert.equal(claimed.ok, true, JSON.stringify(claimed));
  assert.equal(claimed.needed, 2, '分母是 2 人 → 只需要 2 票（旧语义下会是 3 票，永远凑不齐）');
  assert.equal(roleOf(b).role, 'leader');

  // 新 leader 写一条：a 一票 + 自己 = 2 → 201
  const posted = await postAs(b.baseUrl, a.peerId, { kind: 'chat', text: '新 leader 的第一条' });
  assert.equal(posted.status, 201, posted.text);
  assert.equal(posted.json.seq, 1);
  assert.match(logs.join('\n'), /\[group\] quorum members=2 need=2 source=authoritative/);
});

test('v0.8.1 ③ 自愈入表仍是并集：不在表里的对端发心跳仍能被补进来', async (t) => {
  const cluster = await startCluster(t, { count: 3 });
  const [, b, c] = cluster.nodes;

  const keyFile = readGroupKeyFile(b.dir);
  const trimmed = { ...keyFile.members };
  delete trimmed[c.peerId];
  writeGroupKeyFile(b.dir, { ...keyFile, members: trimmed });
  assert.equal(keyMembersOf(b.dir).includes(c.peerId), false);

  // c 用群级签名发心跳（证明它握着群密钥）→ b 必须把它补回成员表（自愈路径只增不减）
  await c.server.group.heartbeat();
  const healed = await waitFor(() => keyMembersOf(b.dir).includes(c.peerId), { timeoutMs: 5_000 });
  assert.equal(healed, true, '自愈入表必须仍然有效（权威替换不能把这条路径一起砍掉）');
});

test('v0.8.1 ④ 移除后 blocked 语义不变：被移除者 post / apply 仍被拒', async (t) => {
  const cluster = await startCluster(t, { count: 3, autoJoin: false });
  const [a, b, c] = cluster.nodes;
  a.server.group.removeMember(c.peerId);
  await pullOnce(b);

  assert.equal(a.server.group.isBlocked(c.peerId), true, 'hub 侧记着 blocked');
  const posted = await postAs(a.baseUrl, c.peerId, { kind: 'chat', text: '被踢之后还想说' });
  assert.equal(posted.status, 403, posted.text);
  assert.equal(posted.json.error, 'not-a-member');

  const applied = await applyToGroup({
    baseUrl: b.baseUrl,
    secret: 'sec-' + c.peerId,
    senderId: c.peerId,
    groupId: cluster.groupId,
    applicant: { peerId: c.peerId, name: 'kicked', baseUrl: 'http://127.0.0.1:1' },
  });
  assert.deepEqual(applied, { status: 'rejected', reason: 'blocked' });
  assert.deepEqual(a.server.group.applications(), []);
});
