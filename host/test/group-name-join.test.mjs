/**
 * v0.8.0 真机回归 · 按名入群的节点必须真的能同步（契约 §5.1）。
 *
 * 现场：C 只与桌面配对、**没有任何群配置**，靠 advertise→find→apply→grant 入群。
 * 结果 grant 落盘时 hub 是 null、group-key.json 没有 hub 地址，于是：
 *   · C 的 group-replica.json 根本没生成，日志里没有任何 pull；
 *   · CLI group history 直接打 usage（它没有 hub 的 peer 记录）。
 * 本文件钉三件事：
 *   ① grant 落盘带 hub（peerId/name/baseUrl）+ keyVersion；
 *   ② 运行中的节点拿到授权后自动提升为成员，hub post 后副本 lastSeq 前进、history 看得到；
 *   ③ CLI 只靠 group-key.json 的 hub 也能 group state / history（不再 usage）。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { createPeerServer } from '../server.mjs';
import {
  applyGroupGrant,
  groupCall,
  readGroupKeyFile,
  writeGroupKeyFile,
} from '../../lib/group-client.mjs';
import { listenOnRandomPort, makeTempStateDir, writeJson0600 } from './helpers.mjs';

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'client', 'cli.mjs');
const HUB = { peerId: 'peer-nj-hub', name: 'nas-box' };
const JOINER = { peerId: 'peer-nj-joiner', name: 'third-box' };
const GROUP_NAME = 'team';

const secretOf = (peerId) => 'sec-' + peerId;

const waitFor = async (check, timeoutMs = 10_000) => {
  const deadline = Date.now() + timeoutMs;
  let last;
  while (Date.now() < deadline) {
    last = await check();
    if (last) return last;
    await sleep(50);
  }
  return last;
};

/** hub：真 host，群名 team；只认与它配对的节点 */
async function startHub(t, groupOverrides = {}) {
  const stateDir = makeTempStateDir('dsh-lan-peers-nj-hub-');
  t.after(() => fs.rmSync(stateDir, { recursive: true, force: true }));
  writeJson0600(path.join(stateDir, 'state.json'), {
    instanceId: HUB.peerId, name: HUB.name, createdAt: new Date().toISOString(),
  });
  const logs = [];
  const server = createPeerServer({
    listenHost: '127.0.0.1',
    stateDir,
    name: HUB.name,
    requireEncryption: false,
    allowRemotePrompts: true,
    logger: (line) => logs.push(String(line)),
    group: { enabled: true, name: GROUP_NAME, autoJoin: true, quorum: 'none', ...groupOverrides },
    groupReplica: { pullIntervalMs: 200, retryMs: 200 },
  });
  const info = await listenOnRandomPort(server);
  server.config.group.advertiseBaseUrl = info.url;
  t.after(async () => { await server.close(); });
  return { server, baseUrl: info.url, stateDir, logs };
}

/**
 * 申请者节点：**完全没有任何群配置**（既没有 group.enabled 也没有 group.hub），
 * 只与桌面那台配对（这里为了简化直接用 hub 生成 grant）。拉取间隔压到 200ms。
 */
async function startJoiner(t) {
  const stateDir = makeTempStateDir('dsh-lan-peers-nj-joiner-');
  t.after(() => fs.rmSync(stateDir, { recursive: true, force: true }));
  writeJson0600(path.join(stateDir, 'state.json'), {
    instanceId: JOINER.peerId, name: JOINER.name, createdAt: new Date().toISOString(),
  });
  writeJson0600(path.join(stateDir, 'peers.json'), { peers: {} });
  const logs = [];
  const server = createPeerServer({
    listenHost: '127.0.0.1',
    stateDir,
    name: JOINER.name,
    requireEncryption: false,
    allowRemotePrompts: true,
    logger: (line) => logs.push(String(line)),
    // 故意不传 group：现场就是「无 group.hub 配置」
    groupReplica: { pullIntervalMs: 200, retryMs: 200 },
  });
  const info = await listenOnRandomPort(server);
  t.after(async () => { await server.close(); });
  return { server, baseUrl: info.url, stateDir, logs };
}

/** hub 侧的 grant（与 /v1/group/apply-status 下发的是同一份形状） */
const grantOf = (hub) => {
  const data = hub.server.group.state({ includeKey: true });
  return {
    groupId: data.groupId,
    name: data.name,
    epoch: data.epoch,
    keyVersion: data.keyVersion,
    key: data.groupKey,
    hub: { peerId: HUB.peerId, name: HUB.name, baseUrl: hub.baseUrl },
    members: Object.entries(data.members).map(([peerId, member]) => ({
      peerId,
      name: String(member?.name ?? ''),
      baseUrl: String(member?.baseUrl ?? ''),
    })),
  };
};

test('v0.8.0 §5.1 grant 落盘带 hub（peerId/name/baseUrl）与 keyVersion', async (t) => {
  const hub = await startHub(t);
  const joiner = await startJoiner(t);
  const grant = grantOf(hub);

  const written = applyGroupGrant(joiner.stateDir, grant);
  assert.deepEqual(written.hub, { peerId: HUB.peerId, name: HUB.name, baseUrl: hub.baseUrl }, 'hub 必须落盘');
  assert.equal(written.leaderPeerId, HUB.peerId);
  assert.equal(written.epoch, grant.keyVersion);

  // 从盘上再读一次：形状稳定（重启后还能靠它 bootstrap）
  const reloaded = readGroupKeyFile(joiner.stateDir);
  assert.deepEqual(reloaded.hub, { peerId: HUB.peerId, name: HUB.name, baseUrl: hub.baseUrl });
  assert.equal(reloaded.groupName, GROUP_NAME, 'grant 里的群名也一起落盘');
  // 成员表里 hub 那条也带地址
  assert.equal(reloaded.members[HUB.peerId].baseUrl, hub.baseUrl);
});

test('v0.8.0 真机复现：无群配置的节点拿到授权后自动 pull，hub 发言 ≤10s 进副本', async (t) => {
  const hub = await startHub(t);
  const joiner = await startJoiner(t);

  // 入群前：没有副本、也不是成员
  assert.equal(fs.existsSync(path.join(joiner.stateDir, 'group-replica.json')), false);
  assert.equal(joiner.server.group.local(), null);

  // hub 侧批准（autoJoin 效果的等价：把申请者写进成员表）+ 下发 grant
  hub.server.group.addMember(JOINER.peerId, JOINER.name);
  hub.server.group.state().members[JOINER.peerId].baseUrl = joiner.baseUrl;
  applyGroupGrant(joiner.stateDir, grantOf(hub));

  // 观察器把它提升成成员并开始 pull（不需要重启，也不需要任何群配置）
  const promoted = await waitFor(() => joiner.server.group.local() !== null);
  assert.equal(promoted, true, '拿到授权后必须自动成为成员（logs=' + JSON.stringify(joiner.logs.slice(-6)) + '）');

  // hub 发一条：副本 lastSeq 要跟着前进
  const message = hub.server.group.post({
    peerId: HUB.peerId, name: HUB.name, kind: 'chat', text: 'hello from nas',
  });
  const advanced = await waitFor(() => joiner.server.group.replica
    && joiner.server.group.replica.state().lastSeq >= message.seq, 10_000);
  assert.equal(advanced, true, 'hub 发言后 ≤10s 副本要前进（logs=' + JSON.stringify(joiner.logs.slice(-8)) + '）');
  const replica = joiner.server.group.replica.state();
  assert.equal(replica.groupId, hub.server.group.state().groupId);
  const replicated = joiner.server.group.replica.messages({ sinceSeq: 0, limit: 10 });
  assert.equal(replicated.at(-1).text, 'hello from nas');

  // 群级签名直连 hub 读日志同样可用（成员身份的证据）
  const keyFile = readGroupKeyFile(joiner.stateDir);
  const pulled = await groupCall({
    baseUrl: hub.baseUrl,
    groupKey: keyFile.key,
    groupId: keyFile.groupId,
    senderId: JOINER.peerId,
    method: 'GET',
    apiPath: '/v1/group/pull?sinceSeq=0&limit=10',
  });
  assert.equal(pulled.messages.length, 1);
  assert.equal(pulled.messages[0].text, 'hello from nas');
});

test('v0.8.0 真机复现：CLI 只靠 group-key.json 的 hub 也能 state / history（不再 usage）', async (t) => {
  const hub = await startHub(t);
  const joiner = await startJoiner(t);
  hub.server.group.addMember(JOINER.peerId, JOINER.name);
  applyGroupGrant(joiner.stateDir, grantOf(hub));
  hub.server.group.post({ peerId: HUB.peerId, name: HUB.name, kind: 'chat', text: 'hello from nas' });

  // CLEAN CASE：本机 peers.json 是空的（没有 hub 的配对记录），--peer 也没给
  const runCli = (args) => new Promise((resolve) => {
    execFile(process.execPath, [CLI, ...args], { encoding: 'utf8' },
      (error, stdout, stderr) => resolve({ status: error ? error.code : 0, stdout, stderr }));
  });

  const history = await runCli(['group', 'history', '--state-dir', joiner.stateDir]);
  assert.equal(history.status, 0, history.stderr || history.stdout);
  assert.doesNotMatch(history.stderr + history.stdout, /用法:/, '不能再打 usage');
  assert.match(history.stdout, /hello from nas/);
  assert.match(history.stderr, /群级签名直连/);

  const state = await runCli(['group', 'state', '--state-dir', joiner.stateDir]);
  assert.equal(state.status, 0, state.stderr || state.stdout);
  assert.doesNotMatch(state.stderr + state.stdout, /用法:/);
  assert.match(state.stdout, new RegExp(GROUP_NAME));
  assert.match(state.stdout, new RegExp(JOINER.peerId));
  assert.match(state.stdout, /groupKey: 已在 group-key.json/);

  // v0.8.0 新增鉴权模式：只有群密钥也能发言（group 白名单里的 /v1/group/post）
  const post = await runCli(['group', 'post', '--text', 'hi from cli', '--state-dir', joiner.stateDir]);
  assert.equal(post.status, 0, post.stderr || post.stdout);
  assert.doesNotMatch(post.stderr + post.stdout, /用法:/);
  assert.match(post.stdout, /已发送 seq=/);
  assert.match(post.stdout, /群级签名直连/);
  const messages = hub.server.group.history({ sinceSeq: 0 });
  assert.equal(messages.at(-1).text, 'hi from cli');
  assert.equal(messages.at(-1).from.peerId, JOINER.peerId, '作者就是这台只有群密钥的节点');
});

test('v0.8.0 提升只在拿到 hub 地址时发生（老 group-key.json 不动）', async (t) => {
  const joiner = await startJoiner(t);
  // 只有群密钥、没有 hub：不该被当成成员（否则会对着空地址反复 pull）
  writeGroupKeyFile(joiner.stateDir, {
    groupId: 'g-legacy',
    key: 'k-legacy',
    epoch: 1,
    leaderPeerId: '',
    name: JOINER.name,
    groupName: GROUP_NAME,
    members: { [JOINER.peerId]: { name: JOINER.name, baseUrl: '' } },
  });
  await sleep(400);
  assert.equal(joiner.server.group.local(), null, '没有 hub 地址时不提升');
  assert.equal(fs.existsSync(path.join(joiner.stateDir, 'group-replica.json')), false);
});
