// dsh-lan-peers · CLI group 子命令（v0.5.0 Phase1）。
//
// 真进程跑 cli.mjs，状态全在临时 state-dir；hub 在本进程里起（所以子进程必须异步跑，
// 同步 execFileSync 会卡住本进程的事件循环，hub 就没法应答）。
import test from 'node:test';
import assert from 'node:assert/strict';
import { listenOnRandomPort } from '../test-support/ports.mjs';
import { execFile, execFileSync } from 'node:child_process';
import http from 'node:http';
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

function runAsync(args, opts = {}) {
  return new Promise((resolve) => {
    // 有 timeout：跟随循环要是退不出去，这里给 ETIMEDOUT 而不是把整个测试文件挂死。
    execFile(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 8000, ...opts }, (error, stdout, stderr) => {
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

  const second = await runAsync(['group', 'post', '--text', '第二条', '--kind', 'system', '--peer', 'hub', '--state-dir', dir]);
  assert.equal(second.status, 0, second.stderr);
  assert.match(second.stdout, /已发送 seq=2/);

  const history = await runAsync(['group', 'history', '--peer', 'hub', '--state-dir', dir]);
  assert.equal(history.status, 0, history.stderr);
  assert.match(history.stdout, /^#1 \d{4}-\d{2}-\d{2}T[\d:.]+Z .+ \[chat\] 第一条 CLI 消息$/m);
  assert.match(history.stdout, /\[system\] 第二条/);
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
  // 片 3a/3b 之后：hub 会对成员这条 chat 抢答（无 @ 抢答），答出来的是一条**新的**群消息
  // （kind:'chat' + meta.quote.seq=1，作者是 hub 自己），所以事件流是 2 条而不是 1 条。
  assert.equal(
    out.stdout.split('\n').filter((line) => line.startsWith('#')).length,
    2,
    '两条事件：#1 成员提问 + #2 hub 抢答（两条不同 seq 的消息，不是同一条重放）',
  );
  assert.match(out.stderr, /订阅结束 lastSeq=2/);
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
  assert.match(badKind.stderr, /--kind 必须是 chat \/ system/);

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

// ---------------------------------------------------------------------------
// v0.12.1 回归：hub 自己 `group post`（真机 NAS 上是 404 not-leader）
//
// 真机形状：NAS hub 没有 group-key.json（它不需要加入自己的群），于是 resolveGroupChannel
// 落到「唯一的伙伴」兜底，把写请求中继给某个**成员**，被 404 not-leader 挡下。
//
// 这里用两个 node:http 桩把这个形状钉死：admin 桩记下每次调用的 method/path/body/token，
// peer 桩记下每次中继请求 —— 「本地模式 = 零 peer 调用」这条断言才立得住（不是靠推断）。
//
// C6 非空性（谁挂了就说明分支真的在起作用）：
//   · 删掉 resolvePostChannel 的 local 分支 → C1「admin.calls.length === 1」与
//     C2「admin.calls.length === 1/2」红（请求会跑去 peer 桩，peer.calls 变成 1）。
//   · 把 local 分支放宽到成员（例如去掉 isLocalGroupLeader、见文件即本地）→
//     C3「admin.calls.length === 0」与 C4「--peer 时不许走本地 admin」红。
//   · 用「没有 group-key.json」当 leader 判据 → C5「角色未知就不打本机 admin」红。
// ---------------------------------------------------------------------------

const HUB = peerFixture('peer-nas-hub', { name: 'nas-hub' });
const HUB_TOKEN = 'cli-group-hub-token';

/** 记录请求的桩：JSON 回包。peer 桩收到的是加密二进制，解析不了就留个长度标记。 */
async function startRecorder(t, reply) {
  const calls = [];
  const server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (chunk) => { raw += chunk; });
    req.on('end', () => {
      let body = null;
      try {
        body = raw === '' ? null : JSON.parse(raw);
      } catch {
        body = '[binary ' + raw.length + ']';
      }
      calls.push({ method: req.method, path: req.url, token: req.headers['x-lan-peers-token'] ?? '', body });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(typeof reply === 'function' ? reply(calls.length) : reply));
    });
  });
  const info = await listenOnRandomPort(server);
  t.after(() => new Promise((resolve) => { server.close(() => resolve()); }));
  return { calls, baseUrl: info.url };
}

/**
 * 一个节点的 state-dir。role 传：
 *   {role:'leader',...} / {role:'follower', leaderPeerId:...} / 'corrupt'（坏 JSON）/ null（没有这个文件）
 * admin 给了才写 admin-url + admin-token（成员节点也要给，才能证明「根本没被碰」）。
 */
function nodeDir(t, { instanceId = HUB.peerId, role = null, admin = null, peers = [] } = {}) {
  const dir = makeTempStateDir('dsh-lan-peers-cli-hub-');
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  writeJson0600(path.join(dir, 'state.json'), {
    instanceId,
    name: instanceId === HUB.peerId ? HUB.name : 'member-node',
    createdAt: new Date().toISOString(),
  });
  if (role === 'corrupt') {
    fs.writeFileSync(path.join(dir, 'group-role.json'), '{ 这不是 JSON', { mode: 0o600 });
  } else if (role) {
    writeJson0600(path.join(dir, 'group-role.json'), {
      epoch: 4, leaseUntil: Date.now() + 9000, commitSeq: 3, groupId: 'g-1', ...role,
    });
  }
  if (admin) {
    fs.writeFileSync(path.join(dir, 'admin-url'), admin.baseUrl + '\n', { mode: 0o600 });
    fs.writeFileSync(path.join(dir, 'admin-token'), HUB_TOKEN + '\n', { mode: 0o600 });
  }
  if (peers.length > 0) seedPeers(dir, peers);
  return dir;
}

const HUB_TS = 1_760_000_000_000;

test('C1 hub 本地模式：group-role 说本机是 leader → 打本机 admin/group/post，零 peer 调用', async (t) => {
  const admin = await startRecorder(t, { ok: true, seq: 7, ts: HUB_TS });
  const peer = await startRecorder(t, { ok: true, seq: 1, ts: Date.now() });
  const dir = nodeDir(t, {
    role: { role: 'leader', leaderPeerId: HUB.peerId },
    admin,
    peers: [{ ...MEMBER, baseUrl: peer.baseUrl }],
  });

  const out = await runAsync(['group', 'post', 'hi', '--state-dir', dir]);
  assert.equal(out.status, 0, out.stderr);
  assert.match(out.stdout, /^已发送 seq=7 ts=\d{4}-\d{2}-\d{2}T/m);

  assert.equal(admin.calls.length, 1, '整条命令只该有一次本机 admin 调用');
  assert.equal(admin.calls[0].method, 'POST');
  assert.equal(admin.calls[0].path, '/api/lan-peers/group/post');
  assert.deepEqual(admin.calls[0].body, { kind: 'chat', text: 'hi' }, 'method+path+body 三条一起钉死');
  assert.equal(admin.calls[0].token, HUB_TOKEN, 'token 仍走 <stateDir>/admin-token');
  assert.equal(peer.calls.length, 0, '本地模式绝不给任何伙伴发写请求（真机 404 not-leader 的根因）');
});

test('C2 leaderPeerId === 本机 instanceId 也算 leader（role 缺失或不一致都一样）', async (t) => {
  const admin = await startRecorder(t, { ok: true, seq: 8, ts: HUB_TS });
  const peer = await startRecorder(t, { ok: true, seq: 1, ts: Date.now() });
  const peers = [{ ...MEMBER, baseUrl: peer.baseUrl }];

  // role 字段在、但写成 follower：leaderPeerId 才是权威
  const followerShaped = nodeDir(t, {
    role: { role: 'follower', leaderPeerId: HUB.peerId }, admin, peers,
  });
  const first = await runAsync(['group', 'post', 'hi', '--state-dir', followerShaped]);
  assert.equal(first.status, 0, first.stderr);
  assert.equal(admin.calls.length, 1, 'role=follower 但 leaderPeerId 指向自己 → 仍然本地');

  // role 字段整个缺席
  const roleAbsent = nodeDir(t, { role: { leaderPeerId: HUB.peerId }, admin, peers });
  const second = await runAsync(['group', 'post', 'hi', '--state-dir', roleAbsent]);
  assert.equal(second.status, 0, second.stderr);
  assert.equal(admin.calls.length, 2, '没有 role 字段时按 leaderPeerId 判');
  assert.equal(peer.calls.length, 0, '两种情况都零中继');
});

test('C3 成员节点：照旧中继给 leader，绝不碰本机 admin', async (t) => {
  const admin = await startRecorder(t, { ok: true, seq: 9, ts: HUB_TS });
  const peer = await startRecorder(t, { ok: true, seq: 2, ts: Date.now() });
  const dir = nodeDir(t, {
    instanceId: MEMBER.peerId,
    role: { role: 'follower', leaderPeerId: HUB.peerId },
    admin,
    peers: [{ ...HUB, baseUrl: peer.baseUrl }],
  });
  writeJson0600(path.join(dir, 'group-key.json'), {
    groupId: 'g-1',
    epoch: 4,
    leaderPeerId: HUB.peerId,
    key: 'k'.repeat(43),
    name: MEMBER.name,
    hub: { peerId: HUB.peerId, baseUrl: peer.baseUrl },
    members: { [HUB.peerId]: { name: HUB.name, baseUrl: peer.baseUrl }, [MEMBER.peerId]: { name: MEMBER.name } },
  });

  const out = await runAsync(['group', 'post', 'hi', '--state-dir', dir]);
  assert.equal(out.status, 0, out.stderr);
  assert.equal(peer.calls.length, 1, '成员必须中继给 leader');
  assert.equal(peer.calls[0].method, 'POST');
  assert.equal(peer.calls[0].path, '/v1/group/post');
  assert.equal(admin.calls.length, 0, '成员节点的本机 admin 一个字都不该收（否则又是 v0.8.0 那个坑）');
});

test('C4 --peer 在 hub 上仍然强制走 per-peer 老路径', async (t) => {
  const admin = await startRecorder(t, { ok: true, seq: 9, ts: HUB_TS });
  const peer = await startRecorder(t, { ok: true, seq: 3, ts: Date.now() });
  const dir = nodeDir(t, {
    role: { role: 'leader', leaderPeerId: HUB.peerId },
    admin,
    peers: [{ ...HUB, baseUrl: peer.baseUrl }],
  });

  const out = await runAsync(['group', 'post', 'hi', '--peer', HUB.name, '--state-dir', dir]);
  assert.equal(out.status, 0, out.stderr);
  assert.equal(peer.calls.length, 1, '显式 --peer = 用户点名，老语义不变');
  assert.equal(peer.calls[0].path, '/v1/group/post');
  assert.equal(admin.calls.length, 0, '--peer 时不许走本地 admin');
});

test('C5 group-role.json 坏掉或不存在 → 回落今天的解析，不崩', async (t) => {
  const admin = await startRecorder(t, { ok: true, seq: 9, ts: HUB_TS });
  const peer = await startRecorder(t, { ok: true, seq: 4, ts: Date.now() });
  const peers = [{ ...MEMBER, baseUrl: peer.baseUrl }];

  const corrupt = nodeDir(t, { role: 'corrupt', admin, peers });
  const first = await runAsync(['group', 'post', 'hi', '--state-dir', corrupt]);
  assert.equal(first.status, 0, first.stderr);

  const missing = nodeDir(t, { role: null, admin, peers });
  const second = await runAsync(['group', 'post', 'hi', '--state-dir', missing]);
  assert.equal(second.status, 0, second.stderr);

  assert.equal(peer.calls.length, 2, '没有可信角色文件时仍按旧规则解析（这里是唯一伙伴）');
  assert.equal(admin.calls.length, 0, '角色未知就绝不擅自打本机 admin');
});

// ---------------------------------------------------------------------------
// v0.12.3 回归：hub 自己的**读**动词（真机 NAS 上 group state/history 答的是某个成员的副本）
//
// 形状与 C1–C5 是同一套桩：admin 桩 = 本机回环管理接口 GET group，peer 桩 = 那个「唯一的伙伴」。
// 管理桩按 sinceSeq **真的切片** —— 这样「游标真的被用上了」才是可断言的，而不是只看 URL。
//
// R7 非空性（谁挂了就说明分支真的在起作用）：
//   · 删掉 cmdGroupHistory 的 wantsLocalGroupRead 分支 → R2 的
//     「?sinceSeq= 请求序列」与「--since 2 不许再给 #1」同时红（请求跑去 peer 桩，peer.calls 变 1）。
//   · 把本地分支放宽到成员（去掉 isLocalGroupLeader）→ R6 的
//     「成员节点的本机 admin 一个字都不该收」红。
//   · 删掉 cmdGroupProbe 的本地分支 → R4 的「probe 一个字节都不许出站」红。
//   · 把 groupTailLocal 退回「一次 GET 的快照」（删掉 for 循环）→ R3 的
//     「cursors.length >= 2」+「≥2 个不同 sinceSeq」+「seqs 末尾 > 3」同时红（T4 的非空性断言），
//     R3b 的「轮询次数 >= 2」也红。
// ---------------------------------------------------------------------------

const GROUP_ID = '11111111-2222-3333-4444-555555555555';
const KEY_43 = 'k'.repeat(43);   // 43 个 base64url 字符 = 32 字节

function groupMessage(seq, text) {
  return { seq, ts: HUB_TS + seq * 1000, from: { peerId: HUB.peerId, name: HUB.name }, kind: 'chat', text };
}

/** 管理接口桩：GET /api/lan-peers/group[?sinceSeq=N]，按游标真的切片（与 hub 侧同口径） */
async function startGroupAdmin(t, overrides = {}) {
  const calls = [];
  const messages = overrides.messages ?? [groupMessage(1, 'first'), groupMessage(2, 'second'), groupMessage(3, 'third')];
  const members = overrides.members ?? [
    { peerId: HUB.peerId, name: HUB.name, online: true, joinedAt: '2026-01-01T00:00:00.000Z' },
    { peerId: MEMBER.peerId, name: MEMBER.name, online: false, joinedAt: '2026-01-02T00:00:00.000Z' },
  ];
  // grow:true = 每次轮询都在尾部追加一条新消息（真 hub 在 tail 期间就是这么长出来的）：
  // 跟随式实现每轮都能拿到一条新的，快照式实现只能拿到第一轮那批。
  const grow = overrides.grow === true;
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://stub.invalid');
    calls.push({ method: req.method, path: req.url, token: req.headers['x-lan-peers-token'] ?? '' });
    const since = Number(url.searchParams.get('sinceSeq') ?? 0) || 0;
    if (grow) messages.push(groupMessage(messages.length + 1, 'live-' + (messages.length + 1)));
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      enabled: true,
      isHub: true,
      group: { groupId: GROUP_ID, name: 'default', members },
      messages: messages.filter((message) => message.seq > since),
      lastSeq: messages.length === 0 ? 0 : messages[messages.length - 1].seq,
      leader: { peerId: HUB.peerId, name: HUB.name, epoch: 1 },
      advertiseBaseUrl: overrides.advertiseBaseUrl ?? 'http://10.0.0.1:7788',
    }));
  });
  const info = await listenOnRandomPort(server);
  t.after(() => new Promise((resolve) => { server.close(() => resolve()); }));
  return { calls, baseUrl: info.url };
}

/**
 * hub 节点：group-role 说本机是 leader + group.json（hub 的群密钥与 keyVersion 都在这里，
 * hub 没有 group-key.json —— 那正是它落进「唯一伙伴」兜底、读请求打到成员身上的原因）。
 * 给了 peer 就配一个成员当那个「唯一的伙伴」：本地分支缺席时请求就会跑到它那里。
 */
function hubNodeDir(t, { admin, peer, keyVersion = 1 } = {}) {
  const dir = nodeDir(t, {
    role: { role: 'leader', leaderPeerId: HUB.peerId },
    peers: peer ? [{ ...MEMBER, baseUrl: peer.baseUrl }] : [],
    admin,
  });
  writeJson0600(path.join(dir, 'group.json'), {
    groupId: GROUP_ID,
    name: 'default',
    keyVersion,
    key: KEY_43,
    members: { [HUB.peerId]: { name: HUB.name }, [MEMBER.peerId]: { name: MEMBER.name } },
    messages: [],
    lastSeq: 0,
  });
  return dir;
}

test('R1 hub 本地 state：一次本机 admin GET group、零 peer 调用，输出与成员路径逐字一致', async (t) => {
  const admin = await startGroupAdmin(t);
  const peer = await startRecorder(t, {});
  const dir = hubNodeDir(t, { admin, peer });

  const out = await runAsync(['group', 'state', '--state-dir', dir]);
  assert.equal(out.status, 0, out.stderr);
  // 与成员路径**同一个渲染口**（printGroupStatePeerLike）：四行逐字钉死
  assert.deepEqual(out.stdout.trimEnd().split('\n'), [
    '群组: default (' + GROUP_ID + ')  epoch=1 keyVersion=1 成员=2',
    '  ' + HUB.name + '\t' + HUB.peerId + '\tonline\tjoinedAt=2026-01-01T00:00:00.000Z',
    '  ' + MEMBER.name + '\t' + MEMBER.peerId + '\toffline\tjoinedAt=2026-01-02T00:00:00.000Z',
    'groupKey: 已收到（32B，不显示）',
  ]);
  assert.equal(admin.calls.length, 1, '整条命令只该有一次本机 admin 调用');
  assert.equal(admin.calls[0].method, 'GET');
  assert.equal(admin.calls[0].path, '/api/lan-peers/group');
  assert.equal(admin.calls[0].token, HUB_TOKEN, 'token 仍走 <stateDir>/admin-token');
  assert.equal(peer.calls.length, 0, 'hub 本地读绝不给任何成员发请求（真机就是这条坏了）');
  assert.ok(!out.stdout.includes(KEY_43), '群密钥一个字节都不许出现在输出里');
});

test('R2 hub 本地 history：sinceSeq 游标真的进到管理接口，且是同一套「保留最新」口径', async (t) => {
  const admin = await startGroupAdmin(t);
  const peer = await startRecorder(t, {});
  const dir = hubNodeDir(t, { admin, peer });
  const line = (seq, text) => '#' + seq + ' ' + new Date(HUB_TS + seq * 1000).toISOString() + ' ' + HUB.name + ' [chat] ' + text;

  const all = await runAsync(['group', 'history', '--state-dir', dir]);
  assert.equal(all.status, 0, all.stderr);
  assert.deepEqual(all.stdout.trimEnd().split('\n'), [line(1, 'first'), line(2, 'second'), line(3, 'third')]);
  assert.ok(all.stderr.includes('群 ' + GROUP_ID + ' · 3 条 · lastSeq=3'), all.stderr);

  const paged = await runAsync(['group', 'history', '--since', '2', '--state-dir', dir]);
  assert.equal(paged.status, 0, paged.stderr);
  assert.deepEqual(paged.stdout.trimEnd().split('\n'), [line(3, 'third')], '--since 2 只该给 #3');
  assert.ok(paged.stderr.includes('· 1 条 · lastSeq=3'), paged.stderr);

  const capped = await runAsync(['group', 'history', '--limit', '2', '--state-dir', dir]);
  assert.deepEqual(capped.stdout.trimEnd().split('\n'), [line(2, 'second'), line(3, 'third')], '--limit 保留最新的一批');

  // 三次都是本机管理接口，且 sinceSeq 就是 CLI 那三个游标（顺序一起钉死）
  assert.deepEqual(admin.calls.map((call) => call.path), [
    '/api/lan-peers/group?sinceSeq=0',
    '/api/lan-peers/group?sinceSeq=2',
    '/api/lan-peers/group?sinceSeq=0',
  ]);
  assert.equal(peer.calls.length, 0, 'history 一次都不许打给成员');
});

test('R3 hub 本地 tail 跟随而不是快照：按 200ms 节拍推进 sinceSeq，逐批打印，零 peer 调用', async (t) => {
  // 桩在每次轮询时追加一条新消息：跟随式实现每轮拿到一条新的，快照式实现只能拿第一轮那批。
  const admin = await startGroupAdmin(t, { grow: true });
  const peer = await startRecorder(t, {});
  const dir = hubNodeDir(t, { admin, peer });

  const out = await runAsync(['group', 'tail', '--duration', '1', '--since', '1', '--state-dir', dir]);
  assert.equal(out.status, 0, out.stderr);
  assert.ok(out.stderr.includes('订阅群事件 sinceSeq=1 (1s)'), out.stderr);

  // T1-a：多轮请求，且 sinceSeq 真的在前进（钉死在一个游标上就是快照）
  const cursors = admin.calls.map((call) => Number(new URL(call.path, 'http://stub.invalid').searchParams.get('sinceSeq')));
  assert.ok(cursors.length >= 2, 'T1：跟随必须多轮请求，实测 ' + cursors.length + ' 轮');
  assert.ok(new Set(cursors).size >= 2, 'T1：≥2 个不同的 sinceSeq，实测 ' + JSON.stringify(cursors));
  assert.equal(cursors[0], 1, 'T1：首轮用的是 --since');
  for (let i = 1; i < cursors.length; i += 1) {
    assert.ok(cursors[i] >= cursors[i - 1], 'T1：游标只许单调前进：' + JSON.stringify(cursors));
  }

  // T1-b：后到的消息也被打印出来（不止首轮那个窗口）
  const seqs = out.stdout.split('\n').filter((line) => line.startsWith('#')).map((line) => Number(line.slice(1).split(' ')[0]));
  assert.ok(seqs.length >= 2, 'T1：至少两批/两条新消息被打印，实测 ' + JSON.stringify(seqs));
  assert.equal(new Set(seqs).size, seqs.length, 'T1：同一条消息不许打印两次：' + JSON.stringify(seqs));
  assert.deepEqual(seqs, [...seqs].sort((a, b) => a - b), 'T1：seq 递增，不许回放旧的');
  assert.ok(seqs[seqs.length - 1] > 3, 'T1：末尾必须是首轮窗口（--since 1 → #2/#3）之后才长出来的新消息：' + JSON.stringify(seqs));
  // 消息格式与成员路径同一个渲染口（formatGroupMessage），一行一条
  const line = (seq, text) => '#' + seq + ' ' + new Date(HUB_TS + seq * 1000).toISOString() + ' ' + HUB.name + ' [chat] ' + text;
  const lastSeq = seqs[seqs.length - 1];
  assert.equal(out.stdout.trimEnd().split('\n')[0], line(2, 'second'), 'T1：首条是第一轮的 #2（格式逐字一致）');
  assert.ok(out.stdout.includes(line(lastSeq, 'live-' + lastSeq)), 'T1：末尾那条也是同一个格式打印的');
  // lastSeq 只随真收到的消息前进，与成员路径的 out.lastSeq 同源
  assert.ok(out.stderr.includes('订阅结束 lastSeq=' + seqs[seqs.length - 1]), out.stderr);
  assert.equal(peer.calls.length, 0, 'tail 也不许给成员发请求');
});

test('R3b hub 本地 tail 到点即停：轮询次数有界、进程自己退出、不留循环/计时器', async (t) => {
  const admin = await startGroupAdmin(t, { grow: true });
  const peer = await startRecorder(t, {});
  const dir = hubNodeDir(t, { admin, peer });

  const startedAt = Date.now();
  const out = await runAsync(['group', 'tail', '--duration', '1', '--state-dir', dir]);
  const elapsed = Date.now() - startedAt;
  assert.equal(out.status, 0, out.stderr);

  // T2：1s / 200ms 节拍 ≈ 5 轮，给 +2 抖动余量；退不出去的循环会一路涨上来
  assert.ok(admin.calls.length >= 2, 'T2：必须先真的轮询，实测 ' + admin.calls.length + ' 次');
  assert.ok(admin.calls.length <= 8, 'T2：轮询次数必须有界（--duration 1），实测 ' + admin.calls.length + ' 次');
  // duration 既是下界也是上界：提前收 = 没跟随；拖过 3s = 计时器/循环没退干净
  assert.ok(elapsed >= 950, 'T2：--duration 1 不许提前结束，实测 ' + elapsed + 'ms');
  assert.ok(elapsed < 3000, 'T2：进程必须自己走到点并退出，实测 ' + elapsed + 'ms');
  // 两行 stderr 各只一次：退出路径唯一，没有第二次订阅/第二条结束行
  assert.equal(out.stderr.split('\n').filter((l) => l.includes('订阅结束')).length, 1, out.stderr);
  assert.equal(out.stderr.split('\n').filter((l) => l.includes('订阅群事件')).length, 1, out.stderr);
  assert.ok(/订阅结束 lastSeq=\d+/.test(out.stderr), out.stderr);
});

test('R4 hub 本地 probe：零出站请求，报的就是本机（leader 即自己）', async (t) => {
  const admin = await startGroupAdmin(t);
  const peer = await startRecorder(t, {});
  const dir = hubNodeDir(t, { admin, peer });

  const out = await runAsync(['group', 'probe', '--state-dir', dir]);
  assert.equal(out.status, 0, out.stderr);
  assert.deepEqual(out.stdout.trimEnd().split('\n'), [
    '探测: ' + HUB.name + ' peerId=' + HUB.peerId + ' epoch=1 lastSeq=3',
    '  地址: http://10.0.0.1:7788',
    '  groupId=' + GROUP_ID + ' leader=' + HUB.peerId,
  ]);
  assert.equal(peer.calls.length, 0, 'hub 的 probe 一个字节都不许出站（真机上是打给成员的）');
  assert.equal(admin.calls.length, 1);
  assert.equal(admin.calls[0].path, '/api/lan-peers/group');
});

test('R5 hub 本地 join：说清「本机是群 hub」并 exit 0，绝不把 join 发出去', async (t) => {
  const admin = await startGroupAdmin(t);
  const peer = await startRecorder(t, {});
  const dir = hubNodeDir(t, { admin, peer });

  const out = await runAsync(['group', 'join', '--state-dir', dir]);
  assert.equal(out.status, 0, out.stderr);
  assert.ok(out.stdout.includes('本机是群 hub，无需加入'), out.stdout);
  assert.equal(peer.calls.length, 0, 'hub 绝不把自己的 join 发给成员');
  assert.equal(admin.calls.length, 0, 'join 连本机 admin 都不用打');
});

test('R6 成员节点：五个读动词照旧走 leader/群密钥路径，本机 admin 一个字都不收', async (t) => {
  const admin = await startGroupAdmin(t);
  const peer = await startRecorder(t, {});
  const dir = nodeDir(t, {
    instanceId: MEMBER.peerId,
    role: { role: 'follower', leaderPeerId: HUB.peerId },
    admin,
    peers: [{ ...HUB, baseUrl: peer.baseUrl }],
  });
  writeJson0600(path.join(dir, 'group-key.json'), {
    groupId: 'g-1',
    epoch: 4,
    leaderPeerId: HUB.peerId,
    key: 'k'.repeat(43),
    name: MEMBER.name,
    hub: { peerId: HUB.peerId, baseUrl: peer.baseUrl },
    members: { [HUB.peerId]: { name: HUB.name, baseUrl: peer.baseUrl }, [MEMBER.peerId]: { name: MEMBER.name } },
  });

  const verbs = [['state'], ['history'], ['tail', '--duration', '1'], ['probe'], ['join']];
  for (const verb of verbs) {
    const before = peer.calls.length;
    await runAsync(['group', ...verb, '--state-dir', dir]);
    assert.equal(peer.calls.length, before + 1, 'group ' + verb[0] + '：成员节点照旧打 leader 一次');
    assert.equal(admin.calls.length, 0, 'group ' + verb[0] + '：成员节点的本机 admin 一个字都不该收');
  }
  // 五条全部指向 leader stub 的 /v1/group/*，没有一条走本地：本地分支只对 leader 开
  assert.deepEqual(peer.calls.map((call) => String(call.path).split('?')[0]), [
    '/v1/group/state',
    '/v1/group/history',
    '/v1/group/events',
    '/v1/group/probe',
    '/v1/group/join',
  ]);
});



