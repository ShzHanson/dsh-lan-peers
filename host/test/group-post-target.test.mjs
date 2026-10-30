/**
 * v0.8.0 真机回归 · CLI 发言必须打给 **leader**（不是「随便一个配对伙伴」）。
 *
 * 现场（NAS=leader、桌面=成员、C3=按名入群且只与桌面配对）：
 *   C3 上 group post → 404 not-leader；桌面日志 [group] post refused reason=not-leader；
 *   NAS 那边根本没收到这次 post —— 因为 CLI 只要能把「某个伙伴」解析出来就走 per-peer。
 *
 * 现在的优先级（client/cli.mjs resolveGroupChannel）：
 *   显式 --peer → 听用户的；否则 本机持有 leader 的 per-peer 密钥 → per-peer 打 leader；
 *   否则 群级签名打 leader 的 baseUrl（leader 未知回落 hub.baseUrl）；没有 group-key 才回到旧逻辑。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readGroupKeyFile, writeGroupKeyFile } from '../../lib/group-client.mjs';
import { makeTempStateDir, writeJson0600 } from './helpers.mjs';
import { secretOf, startCluster } from './group-cluster.mjs';

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'client', 'cli.mjs');

const runCli = (args) => new Promise((resolve) => {
  execFile(process.execPath, [CLI, ...args], { encoding: 'utf8' },
    (error, stdout, stderr) => resolve({ status: error ? error.code : 0, stdout, stderr }));
});

/** 只保留某些伙伴的 peers.json（模拟「只与某台配对」的现场形状） */
function keepOnlyPeers(dir, keepPeerIds) {
  const file = path.join(dir, 'peers.json');
  const store = JSON.parse(fs.readFileSync(file, 'utf8'));
  const peers = {};
  for (const [peerId, peer] of Object.entries(store.peers ?? {})) {
    if (keepPeerIds.includes(peerId)) peers[peerId] = peer;
  }
  writeJson0600(file, { peers });
  return peers;
}

/** 让某台「按名入群」的节点只有群密钥、没有 leader 的配对记录 */
function makeJoinerDir(t, { instanceId, groupKeyFile, hubBaseUrl, leaderPeerId }) {
  const dir = makeTempStateDir('dsh-lan-peers-post-target-');
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  writeJson0600(path.join(dir, 'state.json'), {
    // 群级签名要求 senderPeerId 在成员表内：这里用集群里真实的成员身份
    instanceId,
    name: 'third-box',
    createdAt: new Date().toISOString(),
  });
  writeJson0600(path.join(dir, 'peers.json'), { peers: {} });
  writeGroupKeyFile(dir, {
    ...groupKeyFile,
    leaderPeerId,
    hub: { peerId: '', name: 'nas-box', baseUrl: hubBaseUrl },
  });
  return dir;
}

test('v0.8.0 CLI post 打 leader：只与「非 leader 的成员」配对也能发言，且不会打到那台成员', async (t) => {
  const logs = [];
  const cluster = await startCluster(t, { count: 3, logger: (line) => logs.push(String(line)) });
  const [a, b, c] = cluster.nodes;
  // 现场形状：C3（c）只与桌面（b）配对，leader（a）没有配对记录
  keepOnlyPeers(c.dir, [b.peerId]);
  const keyFile = readGroupKeyFile(c.dir);
  assert.equal(keyFile.leaderPeerId, a.peerId, '前提：group-key.json 记着 leader 是 NAS');

  logs.length = 0;
  const text = '来自第三台（群级签名）';
  const out = await runCli(['group', 'post', '--text', text, '--state-dir', c.dir]);
  assert.equal(out.status, 0, out.stderr || out.stdout);
  assert.match(out.stdout, /已发送 seq=/);
  assert.match(out.stdout, /群级签名直连/, '没有 leader 的 per-peer 密钥时必须走群级签名');
  assert.ok(out.stdout.includes(a.baseUrl), '目标必须是 leader 的地址：' + out.stdout);

  // 真的落在 leader 上
  assert.deepEqual(a.server.group.history({ sinceSeq: 0 }).map((m) => m.text), [text]);
  // 而且**没有任何请求打到那台非 leader 成员**
  assert.equal(
    logs.some((line) => line.includes('post refused reason=not-leader')),
    false,
    '不该再打给非 leader 成员: ' + JSON.stringify(logs.slice(-6)),
  );
});

test('v0.8.0 CLI post：本机持有 leader 的 per-peer 密钥时仍走 per-peer（既有行为不变）', async (t) => {
  const cluster = await startCluster(t, { count: 3 });
  const [a, b, c] = cluster.nodes;
  // c 与 b、a 都配对（现场里成员通常与 hub 配对）
  keepOnlyPeers(c.dir, [b.peerId, a.peerId]);

  const out = await runCli(['group', 'post', '--text', '走 per-peer', '--state-dir', c.dir]);
  assert.equal(out.status, 0, out.stderr || out.stdout);
  assert.doesNotMatch(out.stdout, /群级签名直连/, '有 leader 的 per-peer 密钥就该走 per-peer');
  assert.deepEqual(a.server.group.history({ sinceSeq: 0 }).map((m) => m.text), ['走 per-peer']);
});

test('v0.8.0 CLI post：leader 未知（group-key 没有 leaderPeerId）→ 回落 hub.baseUrl', async (t) => {
  const logs = [];
  const cluster = await startCluster(t, { count: 3, logger: (line) => logs.push(String(line)) });
  const [a, b, c] = cluster.nodes;
  const snapshot = readGroupKeyFile(c.dir);
  const dir = makeJoinerDir(t, {
    instanceId: c.peerId,
    groupKeyFile: { ...snapshot, leaderPeerId: '' },
    hubBaseUrl: a.baseUrl,
    leaderPeerId: '',
  });
  assert.equal(readGroupKeyFile(dir).leaderPeerId, '');
  assert.equal(readGroupKeyFile(dir).hub.baseUrl, a.baseUrl);

  const out = await runCli(['group', 'post', '--text', 'leader 未知也能发', '--state-dir', dir]);
  assert.equal(out.status, 0, out.stderr || out.stdout);
  assert.match(out.stdout, /群级签名直连/);
  assert.ok(out.stdout.includes(a.baseUrl), '应回落 hub.baseUrl：' + out.stdout);
  assert.deepEqual(a.server.group.history({ sinceSeq: 0 }).map((m) => m.text), ['leader 未知也能发']);
  // 没有任何请求打到非 leader 成员（成员收到的是 commit 复制，不是这次 post 请求）
  assert.equal(
    logs.some((line) => line.includes('post refused reason=not-leader')),
    false,
    JSON.stringify(logs.slice(-6)),
  );
  assert.equal(b.server.group.replica.state().lastSeq, 1, '成员只会通过 commit 复制收到这条');
});

test('v0.8.0 CLI post：显式 --peer 保持旧行为（按用户指定的目标发）', async (t) => {
  const cluster = await startCluster(t, { count: 3 });
  const [a, b, c] = cluster.nodes;
  keepOnlyPeers(c.dir, [b.peerId]);
  // b 不是 leader：把写请求发过去，按契约回 404 not-leader，CLI 给 exit 2
  const out = await runCli(['group', 'post', '--text', '我说了打这台', '--peer', b.name, '--state-dir', c.dir]);
  assert.equal(out.status, 2, out.stdout + out.stderr);
  assert.match(out.stderr, /404/);
  assert.match(out.stderr, /not-leader/);
  assert.equal(a.server.group.history({ sinceSeq: 0 }).length, 0, 'leader 不该收到这次 post');
});

test('v0.8.0 CLI 读路径同样认 leader：history 不会打给非 leader 成员', async (t) => {
  const logs = [];
  const cluster = await startCluster(t, { count: 3, logger: (line) => logs.push(String(line)) });
  const [a, b, c] = cluster.nodes;
  await new Promise((resolve) => setTimeout(resolve, 50));
  a.server.group.post({ peerId: a.peerId, name: a.name, kind: 'chat', text: 'hello' });
  keepOnlyPeers(c.dir, [b.peerId]);

  const out = await runCli(['group', 'history', '--state-dir', c.dir]);
  assert.equal(out.status, 0, out.stderr || out.stdout);
  assert.match(out.stdout, /hello/);
  assert.match(out.stderr, /群级签名直连/, '读路径也必须打 leader：' + out.stderr);
  assert.ok(out.stderr.includes(a.baseUrl), out.stderr);
  assert.equal(
    logs.some((line) => line.includes('not-leader')),
    false,
    JSON.stringify(logs.slice(-6)),
  );
});

