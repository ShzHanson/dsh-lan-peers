/**
 * 0.10.0 真机回归：turnOutline 从 `session/projections` 读，不从 `session/list` 读。
 *
 * 真机证据（246 次 poll 采样，不是照文档猜的）：
 *   - `session/list` 的 itemKeys = sessionId|updatedAt|agentAvailable|formatStatus|running|
 *     blank|cwd|projections —— **turnOutline 从不在其中**（它的 schema 是「读所有可见 Session
 *     行、不 resume Agent」，唯一参数是 cursor，没有地方能点名要投影）；
 *   - `item.running` 确实在开轮后约 4.5 s 翻 false（活性没问题）；
 *   - 投影真值在 `session/projections`：@Remote('projections') projections(request:{sessionId},
 *     signal) → null | {asOfSeq, values}，失败那一刻该会话的 turnOutline 行是
 *     {ver:2,seq:28,val:{turns:[{turn,seq,prompt,response}],draft:''}}，真实答复就在里面。
 * 于是两个 runner 的 poll 在「已停下 + 列表里读不到轮次」时必须追问一次投影。
 *
 * 非空断言（T7）：删掉投影兜底 → T1 的 deepEqual({status:'done'}) 变成 {status:'running'}；
 * 把节流闸门反过来（先追问再判 running）→ T7 的 `calls === 0` 变成 2。
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

/** runner-ctx 的 debug() 每次调用时读环境变量；指到临时目录，别写进仓库的 .tmp */
const DEBUG_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'lan-peers-proj-debug-'));
process.env.LAN_PEERS_DEBUG = path.join(DEBUG_DIR, 'lan-peers-debug.log');

const { createCtxRunner } = await import('./runner-ctx.mjs');
const { createDshRunner } = await import('./runner-dsh.mjs');

const SESSION_ID = 'session-9efc4183-c86e-4224-8048-9382f6edaead';

/** 真机 conversation 缓存里的三行（permissions / workingDirectory 原样，response 是真机字符串） */
const LIVE_WORKING_DIRECTORY_VAL = 'D:/DS-Harness/lan-peers-workspace';
const LIVE_PERMISSIONS = { ver: 2, seq: 28, val: { preset: 'workspace-write', sandbox: 'workspace-write', approval: 'ask', seeded: false } };
const LIVE_WORKING_DIRECTORY = { ver: 1, seq: 28, val: LIVE_WORKING_DIRECTORY_VAL };

/** 真机 session/projections 的返回值：{asOfSeq, values}，turnOutline 是 {ver,seq,val} 三层 */
const LIVE_PROJECTIONS = {
  asOfSeq: 28,
  values: {
    turnOutline: {
      ver: 2,
      seq: 28,
      val: {
        turns: [{ turn: 1, seq: 2, prompt: 'p', response: '桌面在线' }],
        draft: '',
      },
    },
  },
};

const withReply = (response) => ({
  asOfSeq: 28,
  values: { turnOutline: { ver: 2, seq: 28, val: { turns: [{ turn: 1, seq: 2, prompt: 'p', response }], draft: '' } } },
});

/**
 * 真机 session/list 的行：itemKeys 全带上，projections.values 只带摘要投影
 * —— turnOutline **不在其中**（这就是失败现场）。legacy 才是「列表里居然带 outline」的旧形状。
 */
function listRow({ running = false, turnOutline } = {}) {
  const values = { permissions: LIVE_PERMISSIONS, workingDirectory: LIVE_WORKING_DIRECTORY };
  if (turnOutline !== undefined) values.turnOutline = turnOutline;
  return {
    sessionId: SESSION_ID,
    updatedAt: 1_764_000_000_000,
    agentAvailable: true,
    formatStatus: 'idle',
    running,
    blank: false,
    cwd: LIVE_WORKING_DIRECTORY_VAL,
    projections: { values },
  };
}

function makeTempDir(prefix = 'lan-peers-proj-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

/**
 * 照真机造的 sessionController：list() 回真机摘要行；projections 按用例给
 * （函数 / 常量 / 缺席='absent' 模拟老 host）。
 */
function ctxController({ running = false, turnOutline, projections = 'absent' } = {}) {
  const calls = [];
  const sessions = new Map();
  const controller = {
    calls,
    async create() {
      sessions.set(SESSION_ID, { turns: [] });
      return { sessionId: SESSION_ID };
    },
    async prompt() {
      return {};
    },
    async list() {
      return { items: [listRow({ running, turnOutline })] };
    },
  };
  if (projections !== 'absent') {
    // 函数 = 逐次决定（抛错/先坏后好）；其它值（含 null）= 每次都回这一份
    controller.projections = async (request, signal) => {
      calls.push({ request, signal });
      if (typeof projections === 'function') return projections(request, signal);
      return projections;
    };
  }
  return controller;
}

async function ctxPoll(controller, options = {}) {
  const dir = makeTempDir();
  const clock = { t: 1_000 };
  const runner = createCtxRunner(controller, { workspace: dir, now: () => clock.t, ...options });
  const out = await runner.ask('群内提问');
  const sessionId = typeof out === 'string' ? out : out.sessionId;
  return { runner, sessionId, clock, dir };
}

// ---------------------------------------------------------------------------
// T1 —— 列表行没有 turnOutline + projections 给真机值 → done/reply 就是那句真答复
// ---------------------------------------------------------------------------
test('T1 投影兜底：列表无 turnOutline，projections 回真机行 → done + reply', async () => {
  const controller = ctxController({ projections: LIVE_PROJECTIONS });
  const { runner, sessionId, dir } = await ctxPoll(controller);

  assert.deepEqual(await runner.poll(sessionId), { status: 'done', reply: '桌面在线' });
  assert.equal(controller.calls.length, 1, '一个字面轮次只追问一次投影');
  assert.deepEqual(controller.calls[0].request, { sessionId }, 'request 形状就是 {sessionId}');
  assert.ok(controller.calls[0].signal instanceof AbortSignal, '必须带一个 AbortSignal');
  fs.rmSync(dir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// T2/T3 —— 投影读不到（null / 抛错）→ running，绝不崩、绝不猜 done
// ---------------------------------------------------------------------------
test('T2 projections 回 null → running（不抛）', async () => {
  const controller = ctxController({ projections: null });
  const { runner, sessionId, dir } = await ctxPoll(controller);

  assert.deepEqual(await runner.poll(sessionId), { status: 'running' });
  assert.deepEqual(await runner.poll(sessionId), { status: 'running' });
  assert.equal(controller.calls.length, 2, '每轮一次追问（已停下、列表仍无轮次）');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('T3 projections 抛错 → running；随后成功仍能 done', async () => {
  let attempt = 0;
  const controller = ctxController({
    projections: async () => {
      attempt += 1;
      if (attempt === 1) throw new Error('projections unavailable');
      return LIVE_PROJECTIONS;
    },
  });
  const { runner, sessionId, dir } = await ctxPoll(controller);

  assert.deepEqual(await runner.poll(sessionId), { status: 'running' }, '抛错不许冒泡，也不许判 done');
  assert.deepEqual(await runner.poll(sessionId), { status: 'done', reply: '桌面在线' }, '下一次成功照常 done');
  fs.rmSync(dir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// T4 —— 老 host 没有 controller.projections：逐字维持今天的行为（running → deadline），不崩
// ---------------------------------------------------------------------------
test('T4 老 host 无 projections → 行为与今天一致：恒 running，不崩', async () => {
  const controller = ctxController({ projections: 'absent' });
  assert.equal(typeof controller.projections, 'undefined');
  const { runner, sessionId, dir } = await ctxPoll(controller);

  for (let i = 0; i < 3; i += 1) {
    assert.deepEqual(await runner.poll(sessionId), { status: 'running' }, '没有任何投影来源 → 还在跑');
  }
  fs.rmSync(dir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// T5 —— 列表里就有 outline（legacy host）：照旧直接用它，**一次追问都不发**
// ---------------------------------------------------------------------------
test('T5 列表自带 outline → 用它，且 projections 一次都不调用', async () => {
  const legacy = { ver: 2, seq: 41, val: { turns: [{ turn: 1, seq: 5, prompt: 'p', response: '收到' }], draft: '' } };
  const controller = ctxController({ turnOutline: legacy, projections: LIVE_PROJECTIONS });
  const { runner, sessionId, dir } = await ctxPoll(controller);

  assert.deepEqual(await runner.poll(sessionId), { status: 'done', reply: '收到' }, '列表侧优先，reply 不是投影里的那句');
  assert.equal(controller.calls.length, 0, '有轮次就不追问');
  fs.rmSync(dir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// T6 —— 空答复：投影确实给了这一轮但 response 是空 → 仍是宽限窗 → empty-reply（不变）
// ---------------------------------------------------------------------------
test('T6 投影里的 response 为空 → 450 ms 宽限后仍 empty-reply', async () => {
  const controller = ctxController({ projections: withReply('') });
  const { runner, sessionId, clock, dir } = await ctxPoll(controller);

  assert.deepEqual(await runner.poll(sessionId), { status: 'running' }, '首次观测在窗内');
  clock.t += 449;
  assert.deepEqual(await runner.poll(sessionId), { status: 'running' }, '窗内（449 < 450）');
  clock.t += 1;
  assert.deepEqual(await runner.poll(sessionId), { status: 'error', error: 'empty-reply', sessionId });
  fs.rmSync(dir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// T7 —— 节流：跑着的那一轮 **0 次**追问（把闸门反过来，这里立刻变成 2）
// ---------------------------------------------------------------------------
test('T7 节流闸门：item.running=true 时投影追问 0 次', async () => {
  const controller = ctxController({ running: true, projections: LIVE_PROJECTIONS });
  const { runner, sessionId, dir } = await ctxPoll(controller);

  assert.deepEqual(await runner.poll(sessionId), { status: 'running' });
  assert.deepEqual(await runner.poll(sessionId), { status: 'running' });
  assert.equal(controller.calls.length, 0, '还在跑 → 投影追问必须是 0 次（150 ms × N 的节奏会把它变成每轮一支 RPC）');
  fs.rmSync(dir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// T8 —— RPC 路径（runner-dsh）：同一组三种情形，且必须打 session/projections
// ---------------------------------------------------------------------------
function tokenFileIn(dir) {
  const file = path.join(dir, 'dsh-web.token');
  fs.writeFileSync(file, 'token-abc\n', { mode: 0o600 });
  return file;
}

/**
 * 假 DSH：list 回**真机摘要行**（无 turnOutline）；session/projections 按用例给。
 * mode: 'ok' 回真机值 / 'null' 回 null / 'error' 回 RPC 错误 / 'legacy' 让 list 自带 outline。
 */
function fakeDsh({ mode = 'ok', reply = '桌面在线', running = false } = {}) {
  const calls = [];
  let attempts = 0;
  const json = (value) => new Response(JSON.stringify(value), { status: 200, headers: { 'content-type': 'application/json' } });
  const ok = (value) => json({ result: { ok: true, value } });
  const fetchImpl = async (url, init = {}) => {
    const target = new URL(String(url));
    if (target.pathname === '/' && target.searchParams.has('token')) {
      return new Response('', { status: 200, headers: { 'set-cookie': 'dsh=token-abc; Path=/' } });
    }
    const rpc = JSON.parse(String(init.body ?? '{}'));
    const args = rpc.payload?.args ?? {};
    calls.push({ method: rpc.method, args });
    if (rpc.method === 'session/create') return ok({ sessionId: SESSION_ID });
    if (rpc.method === 'session/prompt') return ok({ accepted: true });
    if (rpc.method === 'session/list') {
      const legacy = mode === 'legacy'
        ? { ver: 2, seq: 41, val: { turns: [{ turn: 1, seq: 5, prompt: 'p', response: '收到' }], draft: '' } }
        : undefined;
      return ok({ items: [listRow({ running, turnOutline: legacy })] });
    }
    if (rpc.method === 'session/projections') {
      attempts += 1;
      if (mode === 'error') return json({ result: { ok: false, error: { code: 'internal', message: 'no projections' } } });
      if (mode === 'null') return ok(null);
      return ok(withReply(reply));
    }
    return json({ result: { ok: false, error: { code: 'unsupported', message: rpc.method } } });
  };
  return { calls, fetchImpl, attempts: () => attempts };
}

async function dshPoll({ mode, reply, running, clock = { t: 1_000 } } = {}) {
  const dir = makeTempDir();
  const fake = fakeDsh({ mode, reply, running });
  const runner = createDshRunner({
    baseUrl: 'http://127.0.0.1:1',
    tokenFile: tokenFileIn(dir),
    workspace: makeTempDir('lan-peers-proj-ws-'),
    fetchImpl: fake.fetchImpl,
    now: () => clock.t,
  });
  const out = await runner.ask('群内提问');
  return { runner, fake, sessionId: out.sessionId, clock, dir };
}

test('T8a dsh：列表无 turnOutline → 打 session/projections（形状 {request:{sessionId}}）→ done', async () => {
  const { runner, fake, sessionId, dir } = await dshPoll();

  assert.deepEqual(await runner.poll(sessionId), { status: 'done', reply: '桌面在线' });
  const projections = fake.calls.filter((call) => call.method === 'session/projections');
  assert.equal(projections.length, 1, '一次追问');
  assert.deepEqual(projections[0].args, { request: { sessionId } }, 'RPC 参数必须是 {request:{sessionId}}');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('T8b dsh：session/projections 回 null → running（不抛）', async () => {
  const { runner, fake, sessionId, dir } = await dshPoll({ mode: 'null' });

  assert.deepEqual(await runner.poll(sessionId), { status: 'running' });
  assert.equal(fake.attempts(), 1);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('T8c dsh：session/projections 报 RPC 错 → running；随后成功仍能 done', async () => {
  const dir = makeTempDir();
  let fail = true;
  const base = fakeDsh();
  const tokenFile = tokenFileIn(dir);
  // 第一次 error，之后回真机值：同一个 fake 的两副面孔
  const fetchImpl = async (url, init = {}) => {
    const target = new URL(String(url));
    if (target.pathname === '/') return base.fetchImpl(url, init);
    const rpc = JSON.parse(String(init.body ?? '{}'));
    if (rpc.method === 'session/projections' && fail) {
      fail = false;
      return new Response(JSON.stringify({ result: { ok: false, error: { code: 'internal', message: 'no projections' } } }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return base.fetchImpl(url, init);
  };
  const runner = createDshRunner({
    baseUrl: 'http://127.0.0.1:1',
    tokenFile,
    workspace: makeTempDir('lan-peers-proj-ws-'),
    fetchImpl,
    now: () => 1_000,
  });
  const out = await runner.ask('群内提问');

  assert.deepEqual(await runner.poll(out.sessionId), { status: 'running' }, 'RPC 错不许冒泡');
  assert.deepEqual(await runner.poll(out.sessionId), { status: 'done', reply: '桌面在线' });
  fs.rmSync(dir, { recursive: true, force: true });
});

test('T8d dsh：列表自带 outline（legacy）→ 用它，session/projections 一次都不打', async () => {
  const { runner, fake, sessionId, dir } = await dshPoll({ mode: 'legacy' });

  assert.deepEqual(await runner.poll(sessionId), { status: 'done', reply: '收到' });
  assert.equal(fake.calls.filter((call) => call.method === 'session/projections').length, 0);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('T8e dsh：item.running=true → 投影追问 0 次（节流同口径）', async () => {
  const { runner, fake, sessionId, dir } = await dshPoll({ running: true });

  assert.deepEqual(await runner.poll(sessionId), { status: 'running' });
  assert.equal(fake.attempts(), 0, '还在跑 → 0 次追问');
  fs.rmSync(dir, { recursive: true, force: true });
});
