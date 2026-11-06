// dsh-lan-peers · CLI 的群内派单可见面（v0.8.2-α，契约 §1/§4/§5）。
//
// 真进程跑 cli.mjs：hub 在本进程里起（所以子进程必须异步跑），本机 host 的管理接口
// 用一个小 HTTP 桩代替 —— 派单执行在 host 里（Lane X），CLI 只负责「发完消息再去触发」。
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createPeerServer } from '../host/server.mjs';
import { makeTempStateDir, peerFixture, seedPeers, writeJson0600 } from '../host/test/helpers.mjs';

process.env.DSH_LAN_PEERS_LANG = 'zh';   // 语言钉死：断言写的是中文文案，不随机器 locale 漂移

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), 'cli.mjs');
const MEMBER = peerFixture('peer-cli-dispatch');

function runAsync(args) {
  return new Promise((resolve) => {
    execFile(process.execPath, [CLI, ...args], { encoding: 'utf8' }, (error, stdout, stderr) => {
      resolve({ status: error ? error.code : 0, stdout, stderr });
    });
  });
}

async function startHub(t, overrides = {}) {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, overrides.peers ?? [MEMBER]);
  const server = createPeerServer({
    listenHost: '127.0.0.1',
    stateDir,
    // 这个文件测的是 CLI 行为：quorum:none = 写本地即提交，不牵扯选举投票。
    group: { enabled: true, autoJoin: true, quorum: 'none' },
    ...overrides,
  });
  const info = await server.listen(0, '127.0.0.1');
  t.after(async () => {
    await server.close();
    fs.rmSync(stateDir, { recursive: true, force: true });
  });
  return { server, baseUrl: info.url, stateDir };
}

function memberStateDir(t, { baseUrl, hubInstanceId, identity = MEMBER, peerName = 'hub' }) {
  const dir = makeTempStateDir('dsh-lan-peers-cli-dispatch-');
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
    },
  });
  return dir;
}

/** 本机 host 的管理接口桩：只实现 group/dispatch 与 group/accept，记录每一次请求。 */
async function startAdminStub(t, handler) {
  const requests = [];
  const server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (chunk) => { raw += chunk; });
    req.on('end', () => {
      const payload = raw === '' ? null : JSON.parse(raw);
      requests.push({ method: req.method, url: String(req.url), payload });
      let answer = {};
      try {
        answer = handler({ url: String(req.url), payload }) || {};
      } catch (error) {
        answer = { status: 500, json: { error: String(error.message || error) } };
      }
      res.writeHead(Number(answer.status) || 200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(answer.json ?? {}));
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  return { requests, url: 'http://127.0.0.1:' + server.address().port };
}

/** 一条到 hub 的、已入群的成员 state-dir */
async function joinedMember(t) {
  const hub = await startHub(t);
  const dir = memberStateDir(t, { baseUrl: hub.baseUrl, hubInstanceId: hub.server.store.instanceId });
  const joined = await runAsync(['group', 'join', '--peer', 'hub', '--state-dir', dir]);
  assert.equal(joined.status, 0, joined.stderr);
  return { hub, dir };
}

const DONE = {
  ok: true,
  dispatch: { target: 'nas-box', targetName: 'nas-box', status: 'done', reason: '', elapsedMs: 1234, replyChars: 56 },
};

test('group --help 列出 dispatch 与 accept 两个新子命令', async () => {
  const out = await runAsync(['group', '--help']);
  assert.match(out.stdout, /dispatch <目标> <任务\.\.\.>/);
  assert.match(out.stdout, /accept on\|off/);
  assert.match(out.stdout, /@!名字 时作者侧自动派单/);
});

test('group dispatch <目标> <任务>：等价发一条 @!目标 任务，再触发本机派单并打印摘要', async (t) => {
  const { hub, dir } = await joinedMember(t);
  const admin = await startAdminStub(t, ({ url }) => (url.includes('/group/dispatch') ? { json: DONE } : { json: { ok: true } }));

  const out = await runAsync([
    'group', 'dispatch', 'nas-box', '跑', '回归', '--peer', 'hub', '--state-dir', dir, '--url', admin.url,
  ]);
  assert.equal(out.status, 0, out.stderr);
  assert.match(out.stdout, /已发送 seq=\d+/);
  assert.match(out.stdout, /派单 → nas-box：done（1234ms \/ 56字）/);

  const dispatched = admin.requests.filter((request) => request.url === '/api/lan-peers/group/dispatch');
  assert.equal(dispatched.length, 1);
  assert.deepEqual(dispatched[0].payload, { target: 'nas-box', task: '跑 回归', extraTargets: 0 });

  // 群消息先入库，且内容就是 "@!目标 任务"
  const history = await runAsync(['group', 'history', '--peer', 'hub', '--state-dir', dir]);
  assert.equal(history.status, 0, history.stderr);
  assert.match(history.stdout, /@!nas-box 跑 回归/);
  assert.ok(hub.server, 'hub 必须还活着');
});

test('group post --text "@!X 任务"：自动派单；普通消息一次都不打派单接口', async (t) => {
  const { dir } = await joinedMember(t);
  const admin = await startAdminStub(t, ({ url }) => (url.includes('/group/dispatch') ? { json: DONE } : { json: { ok: true } }));

  const withBang = await runAsync([
    'group', 'post', '--text', '@!nas-box 修 CI', '--peer', 'hub', '--state-dir', dir, '--url', admin.url,
  ]);
  assert.equal(withBang.status, 0, withBang.stderr);
  assert.match(withBang.stdout, /派单 → nas-box：done/);
  assert.equal(admin.requests.length, 1);
  assert.deepEqual(admin.requests[0].payload, { target: 'nas-box', task: '修 CI', extraTargets: 0 });

  const plain = await runAsync([
    'group', 'post', '--text', '@nas-box 只是提及', '--peer', 'hub', '--state-dir', dir, '--url', admin.url,
  ]);
  assert.equal(plain.status, 0, plain.stderr);
  assert.equal(admin.requests.length, 1, '没有 @! 就一次派单请求都不发');
});

test('本机没有 host：消息照发，但派单未触发要如实报错 exit 2（不静默当普通消息）', async (t) => {
  const { dir } = await joinedMember(t);
  // 默认 --url 指向 127.0.0.1:7788：本测试里那里没有 host
  const out = await runAsync([
    'group', 'post', '--text', '@!nas-box 跑回归', '--peer', 'hub', '--state-dir', dir,
    '--url', 'http://127.0.0.1:1',
  ]);
  assert.equal(out.status, 2);
  assert.match(out.stdout, /已发送 seq=\d+/, '群消息确实发出去了');
  assert.match(out.stderr, /派单未触发/);
  assert.match(out.stderr, /本机 host 未响应/);
});

test('skipped（没有 @! 目标）显示未派单，不算完成也不算失败', async (t) => {
  const { dir } = await joinedMember(t);
  const admin = await startAdminStub(t, () => ({ json: { ok: false, dispatch: { status: 'skipped', reason: 'no-target' } } }));
  const out = await runAsync([
    'group', 'dispatch', 'nas-box', '任务', '--peer', 'hub', '--state-dir', dir, '--url', admin.url,
  ]);
  assert.equal(out.status, 0, '零动作不是失败');
  assert.match(out.stdout, /未派单（消息里没有 @! 目标）: no-target/);
});

test('派单失败（failed）打印 reason 并 exit 1', async (t) => {
  const { dir } = await joinedMember(t);
  const admin = await startAdminStub(t, () => ({
    json: { ok: false, dispatch: { target: 'nas-box', status: 'failed', reason: 'not-accepting', elapsedMs: 12 } },
  }));
  const out = await runAsync([
    'group', 'dispatch', 'nas-box', '任务', '--peer', 'hub', '--state-dir', dir, '--url', admin.url,
  ]);
  assert.equal(out.status, 1);
  assert.match(out.stdout, /派单 → nas-box：failed（not-accepting \/ 12ms）/);
});

test('group accept off：打本机管理接口并打印新状态', async (t) => {
  const { dir } = await joinedMember(t);
  const admin = await startAdminStub(t, ({ payload }) => ({
    json: { ok: true, acceptDispatch: payload.acceptDispatch, persisted: true },
  }));
  const off = await runAsync(['group', 'accept', 'off', '--state-dir', dir, '--url', admin.url]);
  assert.equal(off.status, 0, off.stderr);
  assert.match(off.stdout, /本机接单：已关闭/);
  assert.deepEqual(admin.requests[0].payload, { acceptDispatch: false });

  const on = await runAsync(['group', 'accept', 'on', '--state-dir', dir, '--url', admin.url]);
  assert.equal(on.status, 0, on.stderr);
  assert.match(on.stdout, /本机接单：接单中/);
  assert.deepEqual(admin.requests[1].payload, { acceptDispatch: true });
});

test('group accept：host 未接线（501）→ exit 2 且说清原因', async (t) => {
  const { dir } = await joinedMember(t);
  const admin = await startAdminStub(t, () => ({ status: 501, json: { error: 'accept-toggle-unsupported' } }));
  const out = await runAsync(['group', 'accept', 'off', '--state-dir', dir, '--url', admin.url]);
  assert.equal(out.status, 2);
  assert.match(out.stderr, /切换接单失败/);
  assert.match(out.stderr, /accept-toggle-unsupported/);
});

test('group accept 参数必须是 on|off；persisted=false 要如实说「重启后回原值」', async (t) => {
  const { dir } = await joinedMember(t);
  const admin = await startAdminStub(t, ({ payload }) => ({
    json: { ok: true, acceptDispatch: payload.acceptDispatch, persisted: false },
  }));
  const bad = await runAsync(['group', 'accept', 'toggle', '--state-dir', dir, '--url', admin.url]);
  assert.equal(bad.status, 1);
  assert.match(bad.stderr, /group accept on\|off/);
  assert.equal(admin.requests.length, 0, '参数不对时一个请求都不发');

  const ok = await runAsync(['group', 'accept', 'off', '--state-dir', dir, '--url', admin.url]);
  assert.equal(ok.status, 0, ok.stderr);
  assert.match(ok.stdout, /重启后回到配置值/);
});
