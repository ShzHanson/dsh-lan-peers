/**
 * v0.7.3 安全硬化 · 移除成员即轮换群密钥 + 成员侧换钥自愈（契约补充）。
 *
 * 两个洞的回归：
 *  ① hub 收到「不在成员表但握着有效 groupKey」的心跳时必须拒绝，且**不得**把它写回成员表
 *  ② removeMember 必须轮换 keyVersion；被移除者的旧钥一律 401 bad-signature
 * 另外两条保护：③成员侧换钥后自动重试一次 ④成员侧（副本）自愈仍然有效
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { listenOnRandomPort } from '../../test-support/ports.mjs';
import { setTimeout as sleep } from 'node:timers/promises';
import {
  fetchGroupLease,
  readGroupKeyFile,
  requestGroupVote,
  sendGroupHeartbeat,
  writeGroupKeyFile,
} from '../../lib/group-client.mjs';
import { postAs, roleOf, startCluster, waitFor } from './group-cluster.mjs';

const groupArgs = (cluster, senderId) => ({
  groupKey: cluster.groupKey,
  groupId: cluster.groupId,
  senderId,
});

test('① hub 永不自愈：持有有效 groupKey 但不在成员表 → 401 not-a-member，且不写回成员表', async (t) => {
  const cluster = await startCluster(t, { count: 2, heartbeatMs: 5_000, tickMs: 60_000 });
  const [hub] = cluster.nodes;
  const before = Object.keys(hub.server.group.state().members).sort();
  const outsider = 'peer-not-invited-9f3a';

  const heartbeat = await assert.rejects(
    () => sendGroupHeartbeat({
      baseUrl: hub.baseUrl,
      ...groupArgs(cluster, outsider),
      epoch: 1,
      leaderPeerId: outsider,
    }),
    (error) => {
      assert.equal(error.status, 401);
      assert.equal(error.code, 'not-a-member');
      return true;
    },
  );
  assert.equal(heartbeat, undefined);
  // 投票端点同样是领导权协议，但 hub 侧也不得自愈
  await assert.rejects(
    () => requestGroupVote({
      baseUrl: hub.baseUrl,
      ...groupArgs(cluster, outsider),
      epoch: 2,
      candidate: outsider,
    }),
    (error) => {
      assert.equal(error.status, 401);
      assert.equal(error.code, 'not-a-member');
      return true;
    },
  );
  assert.deepEqual(Object.keys(hub.server.group.state().members).sort(), before, 'group.json 的成员表不得被自愈写入');
  assert.equal(readGroupKeyFile(hub.dir), null, 'hub 不写 group-key.json');
});

test('② 移除成员即轮换密钥：keyVersion+1，被移除者用旧钥打 election/leader → 401 bad-signature', async (t) => {
  const lines = [];
  const cluster = await startCluster(t, { count: 3, heartbeatMs: 5_000, tickMs: 60_000, logger: (line) => lines.push(String(line)) });
  const [hub, , removed] = cluster.nodes;
  const before = hub.server.group.state({ includeKey: true });
  assert.equal(before.keyVersion, 1);

  assert.equal(hub.server.group.removeMember(removed.peerId), true);
  const after = hub.server.group.state({ includeKey: true });
  assert.equal(after.keyVersion, before.keyVersion + 1, '移除成员必须抬 keyVersion');
  assert.notEqual(after.groupKey, before.groupKey, '必须换一把新 groupKey');
  assert.equal(after.members[removed.peerId], undefined, '成员表里不能再有它');
  // 日志：一行摘要，且绝不打印密钥本身
  const rotatedLine = lines.find((line) => line.startsWith('[group] key rotated '));
  assert.ok(rotatedLine, '必须有 [group] key rotated 日志');
  assert.match(rotatedLine, new RegExp(`keyVersion=${after.keyVersion} reason=member-removed`));
  assert.equal(rotatedLine.includes(after.groupKey), false, '日志不得打印密钥');
  assert.equal(rotatedLine.includes(before.groupKey), false, '日志不得打印旧密钥');
  if (process.platform !== 'win32') {
    const mode = (await import('node:fs')).statSync(hub.server.group.state ? hub.dir + '/group.json' : '').mode & 0o777;
    assert.equal(mode, 0o600, 'group.json 仍必须 0600');
  }

  // 被移除者仍握着旧钥（它的 group-key.json 没变）→ 一律拒绝，且**不是** not-a-member。
  // 有 body 的请求（心跳/投票）在信封层就先炸：400 bad-encryption；
  // 无 body 的请求（GET /v1/group/lease）能走到验签：401 bad-signature。两者都证明旧钥已失效。
  const rejectedWithOldKey = (error) => {
    assert.equal(error.status === 401 || error.status === 400, true, '状态必须是 401/400，实际 ' + error.status);
    assert.equal(['bad-signature', 'bad-encryption'].includes(String(error.code)), true, '错误码 ' + error.code);
    assert.notEqual(String(error.code), 'not-a-member', '不能只是 not-a-member —— 说明密钥没轮换');
    return true;
  };
  await assert.rejects(
    () => sendGroupHeartbeat({
      baseUrl: hub.baseUrl,
      ...groupArgs(cluster, removed.peerId),
      epoch: 2,
      leaderPeerId: removed.peerId,
    }),
    rejectedWithOldKey,
  );
  await assert.rejects(
    () => requestGroupVote({
      baseUrl: hub.baseUrl,
      ...groupArgs(cluster, removed.peerId),
      epoch: 2,
      candidate: removed.peerId,
    }),
    rejectedWithOldKey,
  );
  // 无 body 的那条给出精确的 401 bad-signature（验签先于成员表检查）
  await assert.rejects(
    () => fetchGroupLease({
      baseUrl: hub.baseUrl,
      ...groupArgs(cluster, removed.peerId),
    }),
    (error) => {
      assert.equal(error.status, 401);
      assert.equal(error.code, 'bad-signature');
      return true;
    },
  );
  // hub 侧不再把它算进多数派分母
  const lease = await fetchGroupLease({
    baseUrl: hub.baseUrl,
    groupKey: after.groupKey,
    groupId: cluster.groupId,
    senderId: cluster.nodes[1].peerId,
  });
  assert.equal(lease.memberCount, 2);
  assert.equal(lease.keyVersion, after.keyVersion);
});

test('②b 被移除的成员不能靠自助 join 回来（同一个洞的另一扇门）', async (t) => {
  const cluster = await startCluster(t, { count: 2, heartbeatMs: 5_000, tickMs: 60_000 });
  const [hub, member] = cluster.nodes;
  assert.equal(hub.server.group.state().members[member.peerId] !== undefined, true);
  hub.server.group.removeMember(member.peerId);
  // 成员用 per-peer 签名打 /v1/group/join（autoJoin 是开的）——原来会被加回成员表
  const res = await postAs(hub.baseUrl, member.peerId, { name: 'sneak-back' }, { path: '/v1/group/join' });
  assert.equal(res.status, 403, res.text);
  assert.equal(res.json.error, 'not-a-member');
  assert.equal(hub.server.group.state().members[member.peerId], undefined, '成员表不得被 join 写回');
  // 运维显式重新邀请（addMember）会解除 blocked，之后 join 也恢复正常语义
  hub.server.group.addMember(member.peerId, 'node-b');
  assert.equal(hub.server.group.state().members[member.peerId] !== undefined, true);
});
test('③ 成员换钥：hub 轮换后首次请求被拒 → 自动 refetch state → 重试一次成功', async (t) => {
  const cluster = await startCluster(t, { count: 2, heartbeatMs: 5_000, tickMs: 60_000 });
  const [hub, member] = cluster.nodes;
  // 让 hub 轮换密钥，但 member 仍在成员表里（模拟「踢掉第三台」后的换钥）
  hub.server.group.addMember('peer-ghost-1', 'ghost');
  hub.server.group.removeMember('peer-ghost-1');
  const rotated = hub.server.group.state({ includeKey: true });
  assert.ok(rotated.keyVersion > 1);
  assert.notEqual(readGroupKeyFile(member.dir)?.key, rotated.groupKey, '前提：成员手里还是旧钥');
  assert.equal(hub.server.group.members().some((entry) => entry.peerId === member.peerId), true);

  // 成员的下一次出站群请求（拉补差）会先撞 401 bad-signature → 换钥 → 重试一次
  let out = await member.server.group.pull();
  for (let attempt = 0; attempt < 40 && out?.reason === 'skipped'; attempt += 1) {
    await sleep(25);
    out = await member.server.group.pull();
  }
  assert.equal(out.ok, true, JSON.stringify(out));
  const refreshed = readGroupKeyFile(member.dir);
  assert.equal(refreshed.key, rotated.groupKey, '成员必须把新钥落进 group-key.json');
  assert.equal(roleOf(member).keyVersion, rotated.keyVersion, 'role() 必须暴露新 keyVersion');
  // 只重试一次：再拉一次应当直接成功
  const second = await member.server.group.pull();
  assert.equal(second.ok, true);
});

test('④ 成员侧（副本）自愈仍然有效：表未同步但未移除的成员，election 仍被接受并补表', async (t) => {
  const cluster = await startCluster(t, { count: 3, heartbeatMs: 5_000, tickMs: 60_000 });
  const [, b, c] = cluster.nodes;
  // H3 之后自愈只认「最近一次权威快照」：先让 c 真的 pull 一轮拿到 hub 的 memberIds
  // （b 在快照里、只是本地表不全 —— 这正是这条用例要证明的场景）
  let pulled = null;
  for (let attempt = 0; attempt < 40; attempt += 1) {
    pulled = await c.server.group.pull();
    if (pulled?.reason !== 'skipped') break;
    await sleep(25);
  }
  assert.equal(pulled.ok, true, JSON.stringify(pulled));
  // 造「c 的成员表来自不完整快照」：把 b 从 c 的 group-key.json 里删掉
  const keyFile = readGroupKeyFile(c.dir);
  delete keyFile.members[b.peerId];
  writeGroupKeyFile(c.dir, keyFile);
  assert.equal(Boolean(readGroupKeyFile(c.dir).members[b.peerId]), false);

  const vote = await requestGroupVote({
    baseUrl: c.baseUrl,
    ...groupArgs(cluster, b.peerId),
    epoch: 3,
    candidate: b.peerId,
  });
  assert.equal(vote.vote, true, JSON.stringify(vote));
  assert.ok(readGroupKeyFile(c.dir).members[b.peerId], '成员侧必须把对端补回成员表');
});

test('⑥ 轮换后 epoch 不回退：重启（新的 server 实例读同一份状态）时角色 epoch 不小于 keyVersion', async (t) => {
  const cluster = await startCluster(t, { count: 2, heartbeatMs: 5_000, tickMs: 60_000 });
  const [hub] = cluster.nodes;
  hub.server.group.addMember('peer-ghost-2', 'ghost');
  hub.server.group.removeMember('peer-ghost-2');
  const keyVersion = hub.server.group.state().keyVersion;
  assert.ok(keyVersion >= 2);
  // 同一份 stateDir 再起一个实例（等价于重启）：角色 epoch 必须 ≥ keyVersion
  const { createPeerServer } = await import('../server.mjs');
  const restarted = createPeerServer({
    listenHost: '127.0.0.1',
    stateDir: hub.dir,
    requireEncryption: false,
    group: { enabled: true, name: 's3', quorum: 'none', heartbeatMs: 5_000 },
    groupElection: { heartbeatMs: 5_000, tickMs: 60_000, peerTimeoutMs: 200 },
  });
  t.after(async () => { await restarted.close(); });
  const info = await listenOnRandomPort(restarted);
  assert.equal(info.port > 0, true);
  const role = restarted.group.role();
  assert.ok(role.epoch >= keyVersion, '角色 epoch 不得小于 keyVersion，实际 ' + role.epoch + ' vs ' + keyVersion);
});

