// dsh-lan-peers · 0.13.0-alpha（决定 C）远端摘要器：**线上**那一段（真节点、真 per-peer 签名、真信封）。
//
//   W1 在线：hub 把同一批派给被指定那一位 → 确定性一条 + agent-remote 一条（by/窗口/新会话）
//   W2 离线（用户的硬要求）：被指定那一位打不通 → 摘要与"没配"逐字节一致、有界、恰好一行 skipped
//
// 冷却/信任裁决/接收端预算那一层由 lib/group-summarizer.test.mjs 的 S1-S7 钉住。
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';

import { startCluster, waitFor } from './group-cluster.mjs';
import { isFetchBlockedPort } from './helpers.mjs';

const postHub = (hub, text) => hub.server.group.post({
  peerId: hub.peerId,
  name: hub.name,
  kind: 'chat',
  text,
});

const digestFileOf = (node) => JSON.parse(fs.readFileSync(path.join(node.dir, 'group-digests.json'), 'utf8'));

/** 比较用：at 是墙钟（两个群不共享时钟），其余字段必须逐字节相同 */
const contentOf = (entries) => JSON.stringify((entries ?? []).map((entry) => ({ ...entry, at: 0 })));

/** 一个立刻 ECONNREFUSED 的地址：先占一个 fetch 不拒绝的空闲端口，再关掉它 */
async function deadUrl() {
  for (let attempt = 0; attempt < 10; attempt += 1) {
    const port = await new Promise((resolve, reject) => {
      const probe = net.createServer();
      probe.once('error', reject);
      probe.listen(0, '127.0.0.1', () => {
        const found = probe.address().port;
        probe.close(() => resolve(found));
      });
    });
    if (!isFetchBlockedPort(port)) return 'http://127.0.0.1:' + port;
  }
  throw new Error('no dead port');
}

async function pullNow(member, attempts = 40) {
  for (let index = 0; index < attempts; index += 1) {
    const out = await member.server.group.pull();
    if (out?.reason !== 'skipped') return out;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error('member pull kept being skipped');
}

test('W1 在线：hub 派给被指定那一位 → 确定性一条 + agent-remote 一条（新会话/窗口/by）', async (t) => {
  const lines = [];
  const cluster = await startCluster(t, {
    count: 2,
    logger: (line) => lines.push(line),
    groupExtra: { digestSummarizer: 'node-b' },
  });
  const [hub, member] = cluster.nodes;
  // 接收端挂上摘要会话通道（生产路径是 lib/index.js 注入的 createSessionPrompt）
  const seen = [];
  member.server.config.digestPrompt = async (sessionId, prompt) => {
    seen.push({ sessionId, prompt });
    return { sessionId: sessionId || 's-remote', reused: false, reply: '模型摘要：验收由 alice 负责。' };
  };
  // 脚手架先写占位地址、listen 之后才写真实地址；hub 的 store 在启动时就缓存过那份占位表，
  // 这里重读一次盘（生产里 peers.json 在配对时就写好了，没有这一步）
  hub.server.store.reloadPeers();
  // 名字必须解析成 peerId（走既有配对记录，不引入第二本名册）
  assert.equal(hub.server.group.digest.remote().peerId, member.peerId);

  for (let index = 1; index <= 39; index += 1) postHub(hub, '第 ' + index + ' 条：进度同步');
  assert.equal(hub.server.group.digest.count(), 0, '39 条还不该触发');
  postHub(hub, '第 40 条：压测报告我来写');
  assert.equal(await waitFor(() => hub.server.group.digest.count() >= 2), true, '两条摘要都要落盘');

  const entries = digestFileOf(hub).digests;
  assert.equal(entries.length, 2);
  assert.equal(entries[0].source, 'fallback');
  assert.equal(entries[0].digestId, 'd-1-40');
  assert.equal(entries[1].source, 'agent-remote');
  assert.equal(entries[1].digestId, 'd-1-40-remote');
  assert.equal(entries[1].by, member.peerId.slice(0, 8), 'by = 被指定那一位的短 id（前 8 位）');
  assert.deepEqual([entries[1].fromSeq, entries[1].toSeq], [1, 40]);
  assert.equal(entries[1].text, '模型摘要：验收由 alice 负责。');

  assert.equal(seen.length, 1, '接收端一个 job 只跑一次提示');
  assert.equal(seen[0].sessionId, '', '新会话（空 sessionId），绝不复用历史');
  assert.match(seen[0].prompt, /seq 1-40/);

  // 成员 pull 回来的镜像里，模型摘要的 source/by 也得认得出来（不是被悄悄降级成 agent）
  await pullNow(member);
  const mirror = member.server.group.digest.plane();
  assert.equal(mirror.digests[0].source, 'agent-remote');
  assert.equal(mirror.digests[0].by, member.peerId.slice(0, 8));
  assert.equal(mirror.digests[1].source, 'fallback');
});

test('W2 离线（硬要求）：被指定那一位打不通 → 摘要与"没配"逐字节一致、有界、恰好一行 skipped', async (t) => {
  // 基线：完全没配远端摘要器
  const baseLines = [];
  const baseline = await startCluster(t, { count: 2, logger: (line) => baseLines.push(line) });
  const [baseHub] = baseline.nodes;
  for (let index = 1; index <= 40; index += 1) postHub(baseHub, '第 ' + index + ' 条：进度同步');
  assert.equal(await waitFor(() => baseHub.server.group.digest.count() === 1), true);
  const expected = contentOf(digestFileOf(baseHub).digests);
  assert.equal(baseLines.some((line) => line.includes('summary skipped')), false, '没配 = 一行 skip 都不该有');

  // 同一场景，摘要器指到一台已经关掉的地址
  const deadLines = [];
  const cluster = await startCluster(t, {
    count: 2,
    logger: (line) => deadLines.push(line),
    groupExtra: { digestSummarizer: 'node-b' },
  });
  const [hub, member] = cluster.nodes;
  const peersFile = path.join(hub.dir, 'peers.json');
  const peers = JSON.parse(fs.readFileSync(peersFile, 'utf8'));
  peers.peers[member.peerId].baseUrl = await deadUrl();
  fs.writeFileSync(peersFile, JSON.stringify(peers, null, 2), { mode: 0o600 });
  hub.server.store.reloadPeers();

  const startedAt = Date.now();
  for (let index = 1; index <= 40; index += 1) postHub(hub, '第 ' + index + ' 条：进度同步');
  assert.equal(await waitFor(() => hub.server.group.digest.count() === 1), true, '确定性摘要照常产出');
  const elapsedMs = Date.now() - startedAt;

  assert.equal(contentOf(digestFileOf(hub).digests), expected, '离线时摘要与"没配"逐字节一致');
  assert.equal(elapsedMs < 4_000, true, '这一趟必须有界（实测 ' + elapsedMs + 'ms）');
  const skipped = deadLines.filter((line) => line === '[digest] summary skipped reason=offline');
  assert.equal(skipped.length, 1, '一个窗口恰好一行 skipped reason=offline');
  assert.equal(hub.server.group.digest.remote().cooling, true, '失败之后进冷却');
  assert.equal(hub.server.group.digest.remote().dispatches, 1);
});
