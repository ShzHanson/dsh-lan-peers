// dsh-lan-peers · CLI group 子命令（v0.5.0 Phase1）。
//
// 真进程跑 cli.mjs，状态全在临时 state-dir；hub 在本进程里起（所以子进程必须异步跑，
// 同步 execFileSync 会卡住本进程的事件循环，hub 就没法应答）。
import test from 'node:test';
import assert from 'node:assert/strict';
import { listenOnRandomPort } from '../test-support/ports.mjs';
import { execFile, execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as sleep } from 'node:timers/promises';
import { createPeerServer } from '../host/server.mjs';
import { makeTempStateDir, peerFixture, seedPeers, writeJson0600 } from '../host/test/helpers.mjs';

process.env.DSH_LAN_PEERS_LANG = 'zh';   // 语言钉死：断言写的是中文文案，不随机器 locale 漂移

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), 'cli.mjs');
const MEMBER = peerFixture('peer-cli-group');

function run(args) {
  return execFileSync(process.execPath, [CLI, ...args], { encoding: 'utf8' });
}

function runAsync(args) {
  return new Promise((resolve) => {
    execFile(process.execPath, [CLI, ...args], { encoding: 'utf8' }, (error, stdout, stderr) => {
      resolve({ status: error ? error.code : 0, stdout, stderr });
    });
  });
}

function runFailing(args) {
  try {
    execFileSync(process.execPath, [CLI, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (error) {
    return { status: error.status, stdout: String(error.stdout ?? ''), stderr: String(error.stderr ?? '') };
  }
  throw new Error('expected a non-zero exit: ' + args.join(' '));
}

/** 起一个 hub（默认 autoJoin，方便 CLI 自助加入） */
async function startHub(t, overrides = {}) {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, overrides.peers ?? [MEMBER]);
  const server = createPeerServer({
    listenHost: '127.0.0.1',
    stateDir,
    // S3：majority 现在真的走 propose/commit（假成员没有投票端点会 503）；
    // 这个文件测的是 v0.5 的 CLI 行为，固定 quorum:none = 写本地即提交。
    group: { enabled: true, autoJoin: true, quorum: 'none' },
    ...overrides,
  });
  const info = await listenOnRandomPort(server);
  t.after(async () => {
    await server.close();
    fs.rmSync(stateDir, { recursive: true, force: true });
  });
  return { server, baseUrl: info.url, stateDir };
}

/** 成员侧 state-dir：identity + 一条到 hub 的配对记录 */
function memberStateDir(t, { baseUrl, hubInstanceId, peerName = 'hub', identity = MEMBER, extraPeers = {} }) {
  const dir = makeTempStateDir('dsh-lan-peers-cli-group-');
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  writeJson0600(path.join(dir, 'state.json'), {
    instanceId: identity.peerId,
    name: identity.name,
    createdAt: new Date().toISOString(),
  });
  writeJson0600(path.join(dir, 'peers.json'), {
    peers: {
      [hubInstanceId]: {
        name: peerName,
        baseUrl,
        secret: identity.inboundSecret,
        inboundSecret: 'unused-outbound',
        addedAt: new Date().toISOString(),
        lastSeen: null,
      },
      ...extraPeers,
    },
  });
  return dir;
}

test('group --help 列出五个子命令与 --peer/--state-dir', () => {
  const out = run(['group', '--help']);
  assert.match(out, /group <子命令>/);
  for (const sub of ['state', 'post', 'history', 'tail', 'join']) assert.match(out, new RegExp(sub));
  assert.match(out, /--peer/);
  assert.match(out, /--state-dir/);
  assert.match(run(['--help']), /group/);
  // 无子命令时打用法而不是报错
  assert.match(run(['group']), /group <子命令>/);
});

test('group state 打印群信息与成员表，但绝不打印 groupKey 内容', async (t) => {
  const hub = await startHub(t);
  const dir = memberStateDir(t, { baseUrl: hub.baseUrl, hubInstanceId: hub.server.store.instanceId });

  const joined = await runAsync(['group', 'join', '--peer', 'hub', '--state-dir', dir]);
  assert.equal(joined.status, 0, joined.stderr);
  assert.match(joined.stdout, /已加入群 [0-9a-f-]{36} epoch=1/);

  const out = await runAsync(['group', 'state', '--peer', 'hub', '--state-dir', dir]);
  assert.equal(out.status, 0, out.stderr);
  assert.match(out.stdout, /^群组: default \([0-9a-f-]{36}\)  epoch=1 keyVersion=1 成员=2$/m);
  // 成员表一行一个：名字 	 peerId 	 online/offline 	 joinedAt
  assert.match(out.stdout, new RegExp('  ' + MEMBER.name + '\\t' + MEMBER.peerId + '\\t(online|offline)\\tjoinedAt='));
  assert.match(out.stdout, new RegExp('  ' + MEMBER.name + '\\t' + MEMBER.peerId + '\\tonline'));
  assert.match(out.stdout, /groupKey: 已收到（32B，不显示）/);

  // 真密钥一个字节都不许出现在输出里
  const key = hub.server.group.state({ includeKey: true }).groupKey;
  assert.equal(String(key).length, 43);
  assert.ok(!out.stdout.includes(key) && !out.stderr.includes(key), 'groupKey 不许被打印');
});

test('group post 发消息、group history 取回来（--since / --limit 生效）', async (t) => {
  const hub = await startHub(t);
  const dir = memberStateDir(t, { baseUrl: hub.baseUrl, hubInstanceId: hub.server.store.instanceId });
  hub.server.group.addMember(MEMBER.peerId, MEMBER.name);

  const first = await runAsync(['group', 'post', '--text', '第一条 CLI 消息', '--peer', 'hub', '--state-dir', dir]);
  assert.equal(first.status, 0, first.stderr);
  assert.match(first.stdout, /^已发送 seq=1 ts=\d{4}-\d{2}-\d{2}T/m);

  const second = await runAsync(['group', 'post', '--text', '第二条', '--kind', 'progress', '--peer', 'hub', '--state-dir', dir]);
  assert.equal(second.status, 0, second.stderr);
  assert.match(second.stdout, /已发送 seq=2/);

  const history = await runAsync(['group', 'history', '--peer', 'hub', '--state-dir', dir]);
  assert.equal(history.status, 0, history.stderr);
  assert.match(history.stdout, /^#1 \d{4}-\d{2}-\d{2}T[\d:.]+Z .+ \[chat\] 第一条 CLI 消息$/m);
  assert.match(history.stdout, /\[progress\] 第二条/);
  assert.match(history.stderr, /2 条 · lastSeq=2/);

  const since = await runAsync(['group', 'history', '--since', '1', '--peer', 'hub', '--state-dir', dir]);
  assert.ok(!since.stdout.includes('第一条 CLI 消息'), '--since 1 之后不该再出现第 1 条');
  assert.match(since.stdout, /#2 /);
  assert.match(since.stderr, /1 条 · lastSeq=2/);

  // hub 侧落盘一致
  const messages = hub.server.group.history({ sinceSeq: 0, limit: 10 });
  assert.deepEqual(messages.map((message) => message.seq), [1, 2]);
  assert.equal(messages[0].text, '第一条 CLI 消息');
  assert.deepEqual(messages[0].from, { peerId: MEMBER.peerId, name: MEMBER.name });
});

test('group tail 跟随事件流并逐条打印（期间别人发的消息也收到）', async (t) => {
  const hub = await startHub(t, { groupStream: { pollIntervalMs: 50 } });
  const dir = memberStateDir(t, { baseUrl: hub.baseUrl, hubInstanceId: hub.server.store.instanceId });
  hub.server.group.addMember(MEMBER.peerId, MEMBER.name);

  const tailing = runAsync(['group', 'tail', '--since', '0', '--duration', '3', '--peer', 'hub', '--state-dir', dir]);
  await sleep(400);
  const posted = await runAsync(['group', 'post', '--text', '边看边发', '--peer', 'hub', '--state-dir', dir]);
  assert.equal(posted.status, 0, posted.stderr);

  const out = await tailing;
  assert.equal(out.status, 0, out.stderr);
  assert.match(out.stderr, /订阅群事件 sinceSeq=0/);
  assert.match(out.stdout, /#1 \d{4}-\d{2}-\d{2}T.+\[chat\] 边看边发/);
  assert.match(out.stderr, /订阅结束 lastSeq=1/);
});

test('group join 在 hub 未开 autoJoin 时 exit 2 并说明原因', async (t) => {
  const hub = await startHub(t, { group: { enabled: true, autoJoin: false, quorum: 'none' } });
  const dir = memberStateDir(t, { baseUrl: hub.baseUrl, hubInstanceId: hub.server.store.instanceId });

  const out = await runAsync(['group', 'join', '--peer', 'hub', '--state-dir', dir]);
  assert.equal(out.status, 2);
  assert.match(out.stderr, /403 not-a-member/);
  assert.match(out.stderr, /hub 未允许自助加入/);

  // 同一个 hub 上：join 之外的群操作被拒绝也是 exit 2，且原因写清楚
  const state = await runAsync(['group', 'state', '--peer', 'hub', '--state-dir', dir]);
  assert.equal(state.status, 2);
  assert.match(state.stderr, /群操作被拒绝: 403 not-a-member/);
});

test('group join --name 只改自己；两个同名节点在 state / history 里可区分', async (t) => {
  const peerB = peerFixture('bbbbbbbb-2222-4ccc-8ddd-000000000002', { name: 'node-b' });
  const hub = await startHub(t, { peers: [MEMBER, peerB] });
  const hubId = hub.server.store.instanceId;
  const dirA = memberStateDir(t, { baseUrl: hub.baseUrl, hubInstanceId: hubId, identity: MEMBER });
  const dirB = memberStateDir(t, { baseUrl: hub.baseUrl, hubInstanceId: hubId, identity: peerB });

  // 两台机器的默认主机名相同（真机现场就是这个现象）
  const joinedA = await runAsync(['group', 'join', '--name', 'desk-alpha', '--peer', 'hub', '--state-dir', dirA]);
  assert.equal(joinedA.status, 0, joinedA.stderr);
  assert.match(joinedA.stdout, /显示名=desk-alpha/);
  const joinedB = await runAsync(['group', 'join', '--name', 'desk-alpha', '--peer', 'hub', '--state-dir', dirB]);
  assert.equal(joinedB.status, 0, joinedB.stderr);

  // 不传 --name 再 join 不会把名字抹掉
  const again = await runAsync(['group', 'join', '--peer', 'hub', '--state-dir', dirA]);
  assert.equal(again.status, 0, again.stderr);

  const state = await runAsync(['group', 'state', '--peer', 'hub', '--state-dir', dirA]);
  assert.equal(state.status, 0, state.stderr);
  assert.match(state.stdout, /desk-alpha \(peer-cli\)/, '同名成员要带短 id 后缀');
  assert.match(state.stdout, /desk-alpha \(bbbbbbbb\)/);

  await runAsync(['group', 'post', '--text', 'A 说的', '--peer', 'hub', '--state-dir', dirA]);
  await runAsync(['group', 'post', '--text', 'B 说的', '--peer', 'hub', '--state-dir', dirB]);
  const history = await runAsync(['group', 'history', '--peer', 'hub', '--state-dir', dirA]);
  assert.equal(history.status, 0, history.stderr);
  assert.match(history.stdout, /desk-alpha \(peer-cli\) \[chat\] A 说的/, 'history 的 from.name 也要能区分');
  assert.match(history.stdout, /desk-alpha \(bbbbbbbb\) \[chat\] B 说的/);

  // hub 侧存的仍是原始 name（渲染层才加后缀）
  const raw = JSON.parse(fs.readFileSync(path.join(hub.stateDir, 'group.json'), 'utf8'));
  assert.equal(raw.members[MEMBER.peerId].name, 'desk-alpha');
  assert.equal(raw.members[peerB.peerId].name, 'desk-alpha');

  // 空 --name 直接拒绝
  const empty = await runAsync(['group', 'join', '--name', '', '--peer', 'hub', '--state-dir', dirA]);
  assert.equal(empty.status, 1);
  assert.match(empty.stderr, /--name 不能为空/);
});

test('group 参数与配置错误：缺 --peer、未知对端、超长 text、非法 kind', async (t) => {
  const hub = await startHub(t);
  const dir = memberStateDir(t, {
    baseUrl: hub.baseUrl,
    hubInstanceId: hub.server.store.instanceId,
    peerName: 'hub',
    extraPeers: {
      'peer-a': { name: 'old-host', baseUrl: 'http://127.0.0.1:1', secret: 'S', inboundSecret: 'T' },
    },
  });

  const noPeer = await runAsync(['group', 'state', '--state-dir', dir]);
  assert.equal(noPeer.status, 1);
  assert.match(noPeer.stderr, /需要一个 --peer/);
  assert.match(noPeer.stderr, /候选: hub \/ old-host/);

  const unknown = await runAsync(['group', 'state', '--peer', 'nobody', '--state-dir', dir]);
  assert.equal(unknown.status, 1);
  assert.match(unknown.stderr, /未知对端: nobody/);

  const tooLong = await runAsync(['group', 'post', '--text', 'x'.repeat(4001), '--peer', 'hub', '--state-dir', dir]);
  assert.equal(tooLong.status, 1);
  assert.match(tooLong.stderr, /text 超过 4000 字符上限/);

  const badKind = await runAsync(['group', 'post', '--text', 'hi', '--kind', 'shout', '--peer', 'hub', '--state-dir', dir]);
  assert.equal(badKind.status, 1);
  assert.match(badKind.stderr, /--kind 必须是 chat \/ progress \/ result \/ system/);

  const badSub = runFailing(['group', 'nope', '--state-dir', dir]);
  assert.equal(badSub.status, 1);
  assert.match(badSub.stderr, /未知 group 子命令: nope/);
});

test('group probe 打印 peerId/epoch/lastSeq/地址（per-peer 通道）', async (t) => {
  const hub = await startHub(t);
  const dir = memberStateDir(t, { baseUrl: hub.baseUrl, hubInstanceId: hub.server.store.instanceId });
  hub.server.group.addMember(MEMBER.peerId, MEMBER.name);
  const hubId = hub.server.store.instanceId;

  const out = await runAsync(['group', 'probe', '--peer', 'hub', '--state-dir', dir]);
  assert.equal(out.status, 0, out.stderr);
  assert.match(out.stdout, new RegExp('^探测: .+ peerId=' + hubId + ' epoch=1 lastSeq=0$', 'm'));
  assert.match(out.stdout, /^ {2}地址: /m);
  assert.match(out.stdout, new RegExp('^ {2}groupId=' + hub.server.group.state().groupId + ' leader=' + hubId + '$', 'm'));
});

test('group probe 有本地群密钥时走群级签名（成功）', async (t) => {
  const hub = await startHub(t);
  const dir = memberStateDir(t, { baseUrl: hub.baseUrl, hubInstanceId: hub.server.store.instanceId });
  hub.server.group.addMember(MEMBER.peerId, MEMBER.name);
  const state = hub.server.group.state({ includeKey: true });
  writeJson0600(path.join(dir, 'group-key.json'), {
    groupId: state.groupId,
    epoch: state.epoch,
    leaderPeerId: hub.server.store.instanceId,
    key: state.groupKey,
    name: MEMBER.name,
    members: {
      [hub.server.store.instanceId]: { name: 'hub' },
      [MEMBER.peerId]: { name: MEMBER.name },
    },
  });

  const out = await runAsync(['group', 'probe', '--peer', 'hub', '--state-dir', dir]);
  assert.equal(out.status, 0, out.stderr);
  assert.match(out.stdout, /peerId=/);
  assert.match(out.stdout, /lastSeq=0/);
  // 群密钥一个字节都不许出现在输出里
  assert.ok(!out.stdout.includes(state.groupKey) && !out.stderr.includes(state.groupKey));
});

test('group probe 非成员 exit 2 并说明原因', async (t) => {
  const hub = await startHub(t);
  const dir = memberStateDir(t, { baseUrl: hub.baseUrl, hubInstanceId: hub.server.store.instanceId });
  const out = await runAsync(['group', 'probe', '--peer', 'hub', '--state-dir', dir]);
  assert.equal(out.status, 2);
  assert.match(out.stderr, /群操作被拒绝: 403 not-a-member/);
});

test('group replica 打印本地副本；没有副本时给一句说明', async (t) => {
  const dir = memberStateDir(t, { baseUrl: 'http://127.0.0.1:1', hubInstanceId: 'peer-hub-x' });

  const missing = await runAsync(['group', 'replica', '--state-dir', dir]);
  assert.equal(missing.status, 0, missing.stderr);
  assert.match(missing.stdout, /本地没有群副本/);

  writeJson0600(path.join(dir, 'group-replica.json'), {
    groupId: 'aaaaaaaa-1111-4111-8111-111111111111',
    epoch: 2,
    leaderPeerId: 'peer-hub-x',
    lastSeq: 5,
    messages: [
      { seq: 4, ts: Date.now(), from: { peerId: 'p', name: 'p' }, kind: 'chat', text: 'a', meta: {} },
      { seq: 5, ts: Date.now(), from: { peerId: 'p', name: 'p' }, kind: 'chat', text: 'b', meta: {} },
    ],
  });
  const shown = await runAsync(['group', 'replica', '--state-dir', dir]);
  assert.equal(shown.status, 0, shown.stderr);
  assert.match(shown.stdout, /^副本: groupId=aaaaaaaa-1111-4111-8111-111111111111 epoch=2 leader=peer-hub-x lastSeq=5 条数=2$/m);
  assert.match(shown.stdout, /group-replica\.json/);
});

test('group --help 列出 probe 与 replica', () => {
  const out = run(['group', '--help']);
  assert.match(out, /probe \[--peer/);
  assert.match(out, /replica +打印本地群副本/);
  assert.match(run(['--help']), /state \/ post \/ history \/ tail \/ join \/ probe \/ replica/);
});

