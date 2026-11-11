/**
 * 0.8.5-α 执行侧：runner 的 ask(prompt, { workspace, permission })
 *
 * 铁律断言：
 *   - workspace 只认已存在的绝对目录；不合法 → 抛错，且**一个 RPC 都不发**（绝不静默回退）；
 *   - 不传这两个字段时，返回形状与会话行为与以前逐字一致；
 *   - 权限如实降级：appliedPermission 是读回的真实生效值，permissionHonored 只在实际
 *     生效值等于请求值时为 true，未生效时日志里有一行 reason；
 *   - path 绝不进日志（错误信息也不带）。
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createDshRunner } from './runner-dsh.mjs';

function makeTempDir(prefix = 'lan-peers-ws-') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  return dir;
}

function tokenFileIn(dir) {
  const file = path.join(dir, 'dsh-web.token');
  fs.writeFileSync(file, 'token-abc\n', { mode: 0o600 });
  return file;
}

/**
 * 假 DSH：只实现 runner 用到的四个方法，并记录每一次 RPC 与每次 session/create 的 cwd。
 * 会话自己带着 cwd 与权限（真 DSH 里也是会话自己的事实），list 把它们当投影回出来。
 */
function fakeDsh({ replyOf } = {}) {
  const calls = [];
  const creates = [];
  const sessions = new Map();
  let sequence = 0;
  // 最后一条助手消息的正文由用例决定（默认回显）；空答复与空白答复都要能造出来
  const responseOf = typeof replyOf === 'function'
    ? replyOf
    : (session) => 'ECHO ' + (session.turns[session.turns.length - 1] ?? '');
  const jsonResponse = (value) => new Response(JSON.stringify(value), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
  const fetchImpl = async (url, init = {}) => {
    const target = new URL(String(url));
    if (target.pathname === '/' && target.searchParams.has('token')) {
      return new Response('', { status: 200, headers: { 'set-cookie': 'dsh=token-abc; Path=/' } });
    }
    const rpc = JSON.parse(String(init.body ?? '{}'));
    calls.push(rpc.method);
    const args = rpc.payload?.args ?? {};
    if (rpc.method === 'session/create') {
      sequence += 1;
      const sessionId = 'dsh-' + sequence;
      creates.push(args.request?.cwd);
      sessions.set(sessionId, { cwd: args.request?.cwd, turns: [], parts: [], permission: 'read-only' });
      return jsonResponse({ result: { ok: true, value: { sessionId } } });
    }
    if (rpc.method === 'session/prompt') {
      const session = sessions.get(args.request?.sessionId);
      if (!session) {
        return jsonResponse({
          result: { ok: false, error: { code: 'session-not-found', message: 'no such session' } },
        });
      }
      session.turns.push(args.request.content?.[0]?.text ?? '');
      // 整轮 content（不只第一个文本块）：答复契约是第二个块，只能从这里断言
      session.parts.push(args.request.content ?? []);
      return jsonResponse({ result: { ok: true, value: { accepted: true } } });
    }
    if (rpc.method === 'session/list') {
      return jsonResponse({
        result: {
          ok: true,
          value: {
            items: [...sessions.entries()].map(([sessionId, session]) => ({
              sessionId,
              running: false,
              projections: {
                values: {
                  workingDirectory: session.cwd,
                  permissions: { currentValue: session.permission },
                  turnOutline: [{ response: responseOf(session) }],
                },
              },
            })),
          },
        },
      });
    }
    return jsonResponse({ result: { ok: false, error: { code: 'unsupported', message: rpc.method } } });
  };
  return { calls, creates, sessions, fetchImpl };
}

function dshRunner({ fake, stateDir, workspace, log, now }) {
  return createDshRunner({
    baseUrl: 'http://127.0.0.1:1',
    tokenFile: tokenFileIn(stateDir),
    workspace,
    fetchImpl: fake.fetchImpl,
    now: now ?? (() => 1),
    ...(log ? { log } : {}),
  });
}

/** 可推的时钟：空答复的宽限窗靠它推进，不靠 sleep */
const at = (clock) => () => clock.t;

// ---------------------------------------------------------------------------
// §2 真机 runner（loopback HTTP）：workspace 真的成为该会话的 cwd
// ---------------------------------------------------------------------------

test('§2 runner-dsh：点名 workspace → session/create 的 cwd 就是它（可区分的另一个目录）', async () => {
  const stateDir = makeTempDir();
  const projectDir = makeTempDir('lan-peers-project-');
  const namedDir = makeTempDir('lan-peers-named-');
  const fake = fakeDsh();
  const runner = dshRunner({ fake, stateDir, workspace: projectDir });

  const out = await runner.ask('在点名的工作区里跑', { workspace: namedDir });

  assert.deepEqual(out, { sessionId: 'dsh-1', reused: false }, '没点名权限时返回形状不变');
  assert.deepEqual(fake.creates, [namedDir], 'cwd 必须是点名的那一个，而不是 config.workspace');
  assert.deepEqual(fake.sessions.get('dsh-1').turns, ['在点名的工作区里跑']);

  // 不点名（只给 sessionId）时仍落在 config.workspace —— 零行为变化
  const plain = await runner.ask('默认工作区里的第二轮', { sessionId: 'dsh-1' });
  assert.deepEqual(plain, { sessionId: 'dsh-1', reused: true });

  fs.rmSync(stateDir, { recursive: true, force: true });
  fs.rmSync(projectDir, { recursive: true, force: true });
  fs.rmSync(namedDir, { recursive: true, force: true });
});

test('§2 runner-dsh：相对路径 workspace → 抛错，不发任何 RPC，绝不静默回退', async () => {
  const stateDir = makeTempDir();
  const projectDir = makeTempDir('lan-peers-project-');
  const fake = fakeDsh();
  const runner = dshRunner({ fake, stateDir, workspace: projectDir });

  await assert.rejects(
    () => runner.ask('相对路径', { workspace: 'relative/nested/dir' }),
    (error) => error.code === 'workspace-not-absolute',
  );
  assert.deepEqual(fake.calls, [], '非法 workspace 不能产生任何 RPC');
  assert.equal(fake.creates.length, 0);

  fs.rmSync(stateDir, { recursive: true, force: true });
  fs.rmSync(projectDir, { recursive: true, force: true });
});

test('§2 runner-dsh：不存在的绝对目录 → 抛错，不发任何 RPC（DSH 会 mkdir，不能交给它兜底）', async () => {
  const stateDir = makeTempDir();
  const missingDir = path.join(makeTempDir(), 'no-such-workspace');
  const fake = fakeDsh();
  const runner = dshRunner({ fake, stateDir, workspace: stateDir });

  await assert.rejects(
    () => runner.ask('不存在的目录', { workspace: missingDir }),
    (error) => error.code === 'workspace-missing' && !String(error.message).includes(missingDir),
  );
  assert.deepEqual(fake.calls, []);
  // 也拒绝「存在但是个文件」的同名输入
  const filePath = tokenFileIn(stateDir);
  await assert.rejects(
    () => runner.ask('指向文件', { workspace: filePath }),
    (error) => error.code === 'workspace-missing',
  );
  assert.deepEqual(fake.calls, []);

  fs.rmSync(stateDir, { recursive: true, force: true });
});

test('§2 runner-dsh：permission 未生效时如实回报（appliedPermission + permissionHonored:false + 一行 reason）', async () => {
  const stateDir = makeTempDir();
  const projectDir = makeTempDir('lan-peers-project-');
  const lines = [];
  const fake = fakeDsh();
  const runner = dshRunner({ fake, stateDir, workspace: projectDir, log: (line) => lines.push(line) });

  const out = await runner.ask('要高权限', { permission: 'danger-full-access' });

  // 会话真实权限是 read-only：绝不假装生效
  assert.equal(out.appliedPermission, 'read-only');
  assert.equal(out.permissionHonored, false);
  assert.equal(lines.length, 1);
  assert.match(lines[0], /reason=session-permission-unsupported/);
  assert.ok(!lines[0].includes(projectDir), 'path 绝不进日志');

  // 请求值恰好等于真实生效值时，honored 才是 true
  const match = await runner.ask('本来就是这个档', { permission: 'read-only' });
  assert.equal(match.appliedPermission, 'read-only');
  assert.equal(match.permissionHonored, true);
  assert.match(lines[1], /reason=matched-effective/);

  fs.rmSync(stateDir, { recursive: true, force: true });
  fs.rmSync(projectDir, { recursive: true, force: true });
});

test('§2 runner-dsh：续聊时 cwd 不漂移 —— 同一工作区不新建会话，换了工作区则不假装续聊', async () => {
  const stateDir = makeTempDir();
  const dirA = makeTempDir('lan-peers-a-');
  const dirB = makeTempDir('lan-peers-b-');
  const fake = fakeDsh();
  const runner = dshRunner({ fake, stateDir, workspace: dirA });

  const first = await runner.ask('第一轮', { workspace: dirA });
  assert.deepEqual(fake.creates, [dirA]);

  const same = await runner.ask('第二轮：同一个工作区', { sessionId: first.sessionId, workspace: dirA });
  assert.deepEqual(same, { sessionId: first.sessionId, reused: true });
  assert.deepEqual(fake.creates, [dirA], '同一工作区的续聊不能另起会话');

  const moved = await runner.ask('第三轮：换到 B', { sessionId: first.sessionId, workspace: dirB });
  assert.equal(moved.reused, false);
  assert.notEqual(moved.sessionId, first.sessionId);
  assert.deepEqual(fake.creates, [dirA, dirB], 'cwd 不同的旧会话不能被当成续聊');

  fs.rmSync(stateDir, { recursive: true, force: true });
  fs.rmSync(dirA, { recursive: true, force: true });
  fs.rmSync(dirB, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// §2 桌面 runner（in-process sessionController）：同一套语义
// ---------------------------------------------------------------------------

/**
 * runner-ctx 在模块加载时把 LAN_PEERS_DEBUG 冻成常量，所以整份测试文件共用一个日志文件：
 * 早在任何 import 之前就定好，需要断言的用例先清空再读。
 */
const CTX_DEBUG_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'lan-peers-ctx-debug-'));
const CTX_DEBUG_FILE = path.join(CTX_DEBUG_DIR, 'lan-peers-debug.log');
process.env.LAN_PEERS_DEBUG = CTX_DEBUG_FILE;

async function loadCtxRunner() {
  const mod = await import('./runner-ctx.mjs');
  return mod.createCtxRunner;
}

function fakeController({ replyOf } = {}) {
  const creates = [];
  const sessions = new Map();
  let sequence = 0;
  const responseOf = typeof replyOf === 'function'
    ? replyOf
    : (session) => 'ECHO ' + (session.turns[session.turns.length - 1] ?? '');
  return {
    creates,
    sessions,
    async create(request) {
      creates.push(request);
      sequence += 1;
      const sessionId = 'ctx-' + sequence;
      sessions.set(sessionId, { cwd: request.cwd, turns: [], parts: [], permission: 'read-only' });
      return { sessionId };
    },
    async prompt(request) {
      const session = sessions.get(request.sessionId);
      if (!session) throw new Error('session-not-found');
      session.turns.push(request.content?.[0]?.text ?? '');
      session.parts.push(request.content ?? []);
    },
    async list() {
      return {
        items: [...sessions.entries()].map(([sessionId, session]) => ({
          sessionId,
          running: false,
          projections: {
            values: {
              workingDirectory: session.cwd,
              permissions: { currentValue: session.permission },
              turnOutline: [{ response: responseOf(session) }],
            },
          },
        })),
      };
    },
  };
}

test('§2 runner-ctx：点名 workspace → controller.create 的 cwd 就是它；不点名时仍是 config.workspace', async () => {
  const dir = makeTempDir('lan-peers-ctx-');
  const namedDir = makeTempDir('lan-peers-ctx-named-');
  const createCtxRunner = await loadCtxRunner(dir);
  const controller = fakeController();
  const runner = createCtxRunner(controller, { workspace: dir });

  const scoped = await runner.ask('点名工作区', { workspace: namedDir });
  assert.deepEqual(scoped, { sessionId: 'ctx-1', reused: false });
  assert.equal(controller.creates[0].cwd, namedDir);

  // 旧调用形状：不带 options 仍返回裸 sessionId，cwd 仍是 config.workspace
  const bare = await runner.ask('默认工作区');
  assert.equal(typeof bare, 'string');
  assert.equal(controller.creates[1].cwd, dir);

  fs.rmSync(dir, { recursive: true, force: true });
  fs.rmSync(namedDir, { recursive: true, force: true });
});

test('§2 runner-ctx：非法 workspace 抛错且不回退（create 一次都不调用）', async () => {
  const dir = makeTempDir('lan-peers-ctx-');
  const createCtxRunner = await loadCtxRunner(dir);
  const controller = fakeController();
  const runner = createCtxRunner(controller, { workspace: dir });

  await assert.rejects(
    () => runner.ask('相对路径', { workspace: 'relative' }),
    (error) => error.code === 'workspace-not-absolute',
  );
  await assert.rejects(
    () => runner.ask('不存在', { workspace: path.join(dir, 'nope') }),
    (error) => error.code === 'workspace-missing' && !String(error.message).includes(path.join(dir, 'nope')),
  );
  assert.equal(controller.creates.length, 0, '非法 workspace 不许静默回退到默认工作区');

  fs.rmSync(dir, { recursive: true, force: true });
});

test('§2 runner-ctx：权限如实降级（读回真实值 + 日志一行 reason，且日志里没有 path）', async () => {
  const dir = makeTempDir('lan-peers-ctx-');
  const namedDir = makeTempDir('lan-peers-ctx-named-');
  const createCtxRunner = await loadCtxRunner(dir);
  const controller = fakeController();
  const runner = createCtxRunner(controller, { workspace: dir });

  fs.writeFileSync(CTX_DEBUG_FILE, '');
  const out = await runner.ask('要高权限', { workspace: namedDir, permission: 'danger-full-access' });
  assert.equal(out.appliedPermission, 'read-only');
  assert.equal(out.permissionHonored, false);

  const log = fs.readFileSync(CTX_DEBUG_FILE, 'utf8');
  assert.match(log, /reason=session-permission-unsupported/);
  assert.ok(!log.includes(namedDir), 'path 绝不进日志');

  fs.rmSync(dir, { recursive: true, force: true });
  fs.rmSync(namedDir, { recursive: true, force: true });
});

test('§2 runner-ctx：续聊 cwd 不漂移（同一工作区不新建，换了工作区不假装续聊）', async () => {
  const dir = makeTempDir('lan-peers-ctx-');
  const dirB = makeTempDir('lan-peers-ctx-b-');
  const createCtxRunner = await loadCtxRunner(dir);
  const controller = fakeController();
  const runner = createCtxRunner(controller, { workspace: dir });

  const first = await runner.ask('第一轮', { workspace: dir });
  const same = await runner.ask('第二轮：同一个工作区', { sessionId: first.sessionId, workspace: dir });
  assert.deepEqual(same, { sessionId: first.sessionId, reused: true });
  assert.equal(controller.creates.length, 1);

  const moved = await runner.ask('第三轮：换到 B', { sessionId: first.sessionId, workspace: dirB });
  assert.equal(moved.reused, false);
  assert.equal(controller.creates.length, 2);
  assert.equal(controller.creates[1].cwd, dirB);

  fs.rmSync(dir, { recursive: true, force: true });
  fs.rmSync(dirB, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// §3 桌面 runner 的权限写路径：注入 permissionPresets 后**真的去设**会话权限
//
// 真机事实（dsh-permission-presets 0.2.1-rc.5，见 README/Config）：
//   - 出厂预设表只有 workspace-write / danger-full-access，**没有 read-only**；
//   - set(session, presetName) / current(session) 收的是**会话对象**，不是 sessionId；
//   - set 是 host 侧写路径（typert 只导出 catalog），RPC 到不了，插件进程内够得着。
// 所以「read-only」这一档只能走 sandbox/mode + approval/policy 两条 canonical 事件。
// ---------------------------------------------------------------------------

const DEFAULT_PRESET_TABLE = {
  'workspace-write': { sandbox: 'workspace-write', approval: 'ask' },
  'danger-full-access': { sandbox: 'danger-full-access', approval: 'never' },
};

/**
 * 假权限服务三件套。会话对象自己带事件日志，readback 一律从**日志折叠**出来，
 * 不抄入参 —— 这样「写没写进去」才是真的被验证，而不是把请求值复述一遍。
 */
function fakeAuthority({
  presetTable = DEFAULT_PRESET_TABLE,
  failSet = false,
  appendFails = false,
  defaultMode = 'danger-full-access',
  seedPreset = 'workspace-write',
} = {}) {
  const trace = [];
  const store = new Map();
  const setCalls = [];

  const lastOf = (session, type) => session.events.filter((event) => event.type === type).at(-1)?.data;

  const permissionPresets = {
    get names() {
      return Object.keys(presetTable);
    },
    resolve(name) {
      const spec = presetTable[name];
      if (spec === undefined) throw new Error('permission: unknown preset ' + name);
      return spec;
    },
    set(session, name) {
      setCalls.push({ sessionId: session.id, name });
      if (failSet) throw new Error('permission: set refused');
      const spec = this.resolve(name);
      trace.push('set');
      session.append('permission/preset', { preset: name });
      session.append('sandbox/mode', { mode: spec.sandbox });
      session.append('approval/policy', { policy: spec.approval });
    },
    current(session) {
      const sandbox = lastOf(session, 'sandbox/mode')?.mode ?? null;
      const approval = lastOf(session, 'approval/policy')?.policy ?? null;
      const chosen = lastOf(session, 'permission/preset')?.preset;
      if (chosen !== undefined) {
        const spec = presetTable[chosen];
        if (spec !== undefined && spec.sandbox === sandbox && spec.approval === approval) return chosen;
      }
      for (const [name, spec] of Object.entries(presetTable)) {
        if (spec.sandbox === sandbox && spec.approval === approval) return name;
      }
      return 'custom';
    },
  };

  const sandboxPolicy = {
    resolve({ session }) {
      const mode = session !== undefined ? lastOf(session, 'sandbox/mode')?.mode : undefined;
      return { mode: mode ?? defaultMode };
    },
  };

  const newSession = (id, cwd) => {
    const session = {
      id,
      header: { cwd },
      events: [],
      turns: [],
      append(type, data) {
        if (appendFails) throw new Error('session append refused');
        trace.push('append:' + type);
        session.events.push({ type, data });
      },
    };
    const seed = presetTable[seedPreset];
    if (seed !== undefined) {
      session.events.push({ type: 'permission/preset', data: { preset: seedPreset } });
      session.events.push({ type: 'sandbox/mode', data: { mode: seed.sandbox } });
      session.events.push({ type: 'approval/policy', data: { policy: seed.approval } });
    }
    return session;
  };

  return {
    trace,
    setCalls,
    store,
    newSession,
    permissionPresets,
    sessions: { get: (id) => store.get(id) ?? undefined },
    sandboxPolicy,
  };
}

function authorityController(authority) {
  let sequence = 0;
  const prompts = [];
  const controller = {
    prompts,
    async create(request) {
      sequence += 1;
      const sessionId = 'auth-' + sequence;
      authority.store.set(sessionId, authority.newSession(sessionId, request.cwd));
      return { sessionId };
    },
    async prompt(request) {
      prompts.push(request.sessionId);
      authority.trace.push('prompt');
      const session = authority.store.get(request.sessionId);
      if (!session) throw new Error('session-not-found');
      session.turns.push(request.content?.[0]?.text ?? '');
    },
    async list() {
      return {
        items: [...authority.store.entries()].map(([sessionId, session]) => ({
          sessionId,
          running: false,
          projections: {
            values: {
              workingDirectory: session.header.cwd,
              permissions: { currentValue: authority.permissionPresets.current(session) },
              turnOutline: [{ response: 'ECHO' }],
            },
          },
        })),
      };
    },
  };
  return controller;
}

function bridge(authority) {
  return {
    permissionPresets: authority.permissionPresets,
    sessions: authority.sessions,
    sandboxPolicy: authority.sandboxPolicy,
  };
}

test('§3 runner-ctx：注入 permissionPresets → 按预设写路径落盘，读回一致才报 honored:true（且先设再跑）', async () => {
  const dir = makeTempDir('lan-peers-ctx-auth-');
  const createCtxRunner = await loadCtxRunner();
  const authority = fakeAuthority({ seedPreset: 'workspace-write' });
  const controller = authorityController(authority);
  const runner = createCtxRunner(controller, { workspace: dir, ...bridge(authority) });

  fs.writeFileSync(CTX_DEBUG_FILE, '');
  const out = await runner.ask('要全权', { permission: 'danger-full-access' });

  assert.equal(authority.setCalls.length, 1, '预设名存在时必须走 permissionPresets.set');
  assert.deepEqual(authority.setCalls[0], { sessionId: 'auth-1', name: 'danger-full-access' });
  assert.equal(out.appliedPermission, 'danger-full-access');
  assert.equal(out.permissionHonored, true, '读回一致才允许 true');
  assert.equal(out.permissionReason, 'matched-effective');
  assert.equal(out.reused, false);
  // 先设权限、再打这一轮：反过来等于用错的档位跑了一轮
  const promptAt = authority.trace.indexOf('prompt');
  assert.ok(promptAt > -1, authority.trace.join(','));
  assert.equal(
    authority.trace.slice(0, promptAt).filter((step) => step !== 'set' && !step.startsWith('append:')).length,
    0,
    'prompt 之前只允许出现权限写入：' + authority.trace.join(','),
  );
  // 会话事件真的落在会话日志上（这是客户端 permissions 投影的来源）
  const events = authority.store.get('auth-1').events.map((event) => event.type + ':' + JSON.stringify(event.data));
  assert.ok(events.includes('sandbox/mode:{"mode":"danger-full-access"}'), events.join(' | '));
  assert.ok(events.includes('approval/policy:{"policy":"never"}'), events.join(' | '));

  const log = fs.readFileSync(CTX_DEBUG_FILE, 'utf8');
  assert.ok(!log.includes(dir), 'path 绝不进日志');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('§3 runner-ctx：部署没配 read-only 预设时退到档位事件，读回执行档位仍等于请求值 → honored:true', async () => {
  const dir = makeTempDir('lan-peers-ctx-auth-');
  const createCtxRunner = await loadCtxRunner();
  const authority = fakeAuthority({ seedPreset: 'danger-full-access' });
  const controller = authorityController(authority);
  const runner = createCtxRunner(controller, { workspace: dir, ...bridge(authority) });

  const out = await runner.ask('只读跑一下', { permission: 'read-only' });

  assert.equal(authority.setCalls.length, 0, 'read-only 不是配置里的预设名，不能拿它去调 set');
  assert.equal(out.appliedPermission, 'read-only');
  assert.equal(out.permissionHonored, true);
  const session = authority.store.get('auth-1');
  assert.equal(authority.permissionPresets.current(session), 'custom', '预设投影是 custom：read-only 不在预设表里');
  assert.equal(authority.sandboxPolicy.resolve({ session }).mode, 'read-only', '但真正的执行档位是 read-only');
  assert.ok(session.events.some((event) => event.type === 'approval/policy' && event.data.policy === 'ask'));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('§3 runner-ctx：set 抛错 → honored:false（绝不谎报），且升高失败就按低档照跑', async () => {
  const dir = makeTempDir('lan-peers-ctx-auth-');
  const createCtxRunner = await loadCtxRunner();
  const authority = fakeAuthority({ seedPreset: 'workspace-write', failSet: true });
  const controller = authorityController(authority);
  const runner = createCtxRunner(controller, { workspace: dir, ...bridge(authority) });

  fs.writeFileSync(CTX_DEBUG_FILE, '');
  const out = await runner.ask('要全权（但服务坏了）', { permission: 'danger-full-access' });

  assert.equal(authority.setCalls.length, 1, '确实尝试过写');
  assert.equal(out.permissionHonored, false, '没生效就必须 false');
  assert.equal(out.appliedPermission, 'workspace-write', 'appliedPermission 是读回的真实值，不是请求值');
  assert.equal(out.permissionReason, 'permission-set-failed');
  assert.equal(controller.prompts.length, 1, '升高失败不拦这一单：按低档继续跑');
  assert.equal(authority.sandboxPolicy.resolve({ session: authority.store.get('auth-1') }).mode, 'workspace-write');

  const log = fs.readFileSync(CTX_DEBUG_FILE, 'utf8');
  assert.match(log, /reason=permission-set-failed/);
  assert.ok(!log.includes(dir), 'path 绝不进日志');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('§3 runner-ctx：降低权限失败 → 拒绝执行这一轮（绝不反而跑成更高档）', async () => {
  const dir = makeTempDir('lan-peers-ctx-auth-');
  const createCtxRunner = await loadCtxRunner();
  // 会话本身是 danger-full-access，read-only 写不进去（append 被拒）
  const authority = fakeAuthority({ seedPreset: 'danger-full-access', appendFails: true });
  const controller = authorityController(authority);
  const runner = createCtxRunner(controller, { workspace: dir, ...bridge(authority) });

  await assert.rejects(
    () => runner.ask('只读，但写不进去', { permission: 'read-only' }),
    (error) => error.code === 'permission-above-request' && !String(error.message).includes(dir),
  );
  assert.equal(controller.prompts.length, 0, '一步都不许用 danger-full-access 跑');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('§3 runner-ctx：服务缺席（显式 null）→ 维持旧行为，一个写操作都不做', async () => {
  const dir = makeTempDir('lan-peers-ctx-auth-');
  const createCtxRunner = await loadCtxRunner();
  const controller = fakeController();
  const runner = createCtxRunner(controller, {
    workspace: dir,
    permissionPresets: null,
    sessions: null,
    sandboxPolicy: null,
  });

  fs.writeFileSync(CTX_DEBUG_FILE, '');
  const out = await runner.ask('远程 RPC 那条路', { permission: 'danger-full-access' });

  assert.equal(out.appliedPermission, 'read-only', '假 controller 的会话真实档位是 read-only');
  assert.equal(out.permissionHonored, false);
  assert.equal(out.permissionReason, 'session-permission-unsupported');
  // 降级路径不下安全闸门（维持 0.8.5 之前的行为：如实 false 但不拦单）
  assert.equal(controller.sessions.get('ctx-1').turns.length, 1);

  const log = fs.readFileSync(CTX_DEBUG_FILE, 'utf8');
  assert.match(log, /via=none/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('§3 runner-ctx：请求值既不是预设也不是档位 → 不写、不谎报，也不因为档位比较误拦', async () => {
  const dir = makeTempDir('lan-peers-ctx-auth-');
  const createCtxRunner = await loadCtxRunner();
  // 会话处于 danger-full-access：非三档的请求值不能被当成"更宽"而去拦单
  const authority = fakeAuthority({ seedPreset: 'danger-full-access' });
  const controller = authorityController(authority);
  const runner = createCtxRunner(controller, { workspace: dir, ...bridge(authority) });

  const out = await runner.ask('一个不认识的值', { permission: 'yolo' });

  assert.equal(authority.setCalls.length, 0);
  assert.deepEqual(authority.trace, ['prompt'], '不认识的请求值一个事件都不写');
  assert.equal(out.permissionHonored, false);
  assert.equal(out.appliedPermission, 'danger-full-access', 'appliedPermission 仍是读回的真实值');
  assert.equal(out.permissionReason, 'unknown-permission');
  assert.equal(controller.prompts.length, 1);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('§3 runner-ctx：不点名 permission → 返回形状与写操作都不变（新字段不出现）', async () => {
  const dir = makeTempDir('lan-peers-ctx-auth-');
  const createCtxRunner = await loadCtxRunner();
  const authority = fakeAuthority();
  const controller = authorityController(authority);
  const runner = createCtxRunner(controller, { workspace: dir, ...bridge(authority) });

  const out = await runner.ask('不点名权限', { workspace: dir });

  assert.deepEqual(out, { sessionId: 'auth-1', reused: false }, '不点名时不多一个键');
  assert.equal(authority.setCalls.length, 0);
  assert.deepEqual(authority.trace, ['prompt'], '只有那一轮，没有任何权限写入');
  fs.rmSync(dir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// §4 答复契约（PART A）+ 空答复（PART B）
//
// 提问方拿到的答复就是**最后一条助手消息的正文**，对端模型不知道这件事 —— 契约要明说；
// 会话停下却没正文时，必须是一个显式失败，而不是「还在跑」或成功。
// ---------------------------------------------------------------------------

const CONTRACT_MARKS = [
  '最后一条消息的正文会原样返回给提问方',
  '作为这次提问的答复',
  '不要以提问或「我这就去做」收尾',
  '如果需要中途澄清',
];

test('§4 runner-dsh：契约是提问后的第二个文本块，提问正文一个字节都不改', async () => {
  const stateDir = makeTempDir();
  const fake = fakeDsh();
  const runner = dshRunner({ fake, stateDir, workspace: makeTempDir('lan-peers-project-') });

  await runner.ask('把日志收一下，然后告诉我改了哪几行');

  const content = fake.sessions.get('dsh-1').parts[0];
  assert.equal(content.length, 2, '两个文本块：提问 + 契约');
  assert.equal(content[0].text, '把日志收一下，然后告诉我改了哪几行', '提问正文原样');
  const contract = String(content[1].text ?? '');
  for (const mark of CONTRACT_MARKS) assert.ok(contract.includes(mark), '契约缺：' + mark + '\n' + contract);
  assert.ok(contract.split('\n').length <= 3, '契约不超过 3 行：' + contract);
});

test('§4 runner-ctx：契约同样落在提问之后（第二个文本块，正文原样）', async () => {
  const dir = makeTempDir('lan-peers-ctx-');
  const createCtxRunner = await loadCtxRunner(dir);
  const controller = fakeController();
  const runner = createCtxRunner(controller, { workspace: dir });

  await runner.ask('查一下磁盘');

  const content = controller.sessions.get('ctx-1').parts[0];
  assert.equal(content.length, 2);
  assert.equal(content[0].text, '查一下磁盘');
  for (const mark of CONTRACT_MARKS) assert.ok(String(content[1].text).includes(mark), '契约缺：' + mark);
  fs.rmSync(dir, { recursive: true, force: true });
});

// 宽限窗（PART B 的收口）：会话停下后正文可能还差一次投影写入才出现。窗内继续
// running 让调用方接着轮询，窗外仍为空才是「跑完了没答案」。下面四例把窗的两侧都钉住。

const GRACE_TARGET_RAWS = ['', '   ', '\n\t '];

test('§5 G1 停下 + 空答复：首次观测落在宽限窗内 → running（不是 error，也不是 done）', async () => {
  for (const raw of GRACE_TARGET_RAWS) {
    const clock = { t: 1_000 };
    const fake = fakeDsh({ replyOf: () => raw });
    const runner = dshRunner({ fake, stateDir: makeTempDir(), workspace: makeTempDir('lan-peers-project-'), now: at(clock) });
    const out = await runner.ask('照做完了但什么都没回');

    assert.deepEqual(await runner.poll(out.sessionId), { status: 'running' }, '空白答复 ' + JSON.stringify(raw) + ' 首轮不许判失败');
    clock.t += 400;
    assert.deepEqual(await runner.poll(out.sessionId), { status: 'running' }, '窗内（400 < 450）仍是 running');
  }
});

test('§5 G2 空答复持续到窗口边界之后 → error/empty-reply 且带 sessionId', async () => {
  for (const raw of GRACE_TARGET_RAWS) {
    const clock = { t: 1_000 };
    const fake = fakeDsh({ replyOf: () => raw });
    const runner = dshRunner({ fake, stateDir: makeTempDir(), workspace: makeTempDir('lan-peers-project-'), now: at(clock) });
    const out = await runner.ask('一直空着');

    assert.equal((await runner.poll(out.sessionId)).status, 'running');
    clock.t += 450;
    const polled = await runner.poll(out.sessionId);
    assert.deepEqual(polled, { status: 'error', error: 'empty-reply', sessionId: out.sessionId }, JSON.stringify(raw));
    assert.notEqual(polled.status, 'done');
  }
});

test('§5 G2 runner-ctx 同口径：窗内 running，窗外 error/empty-reply', async () => {
  const dir = makeTempDir('lan-peers-ctx-');
  const createCtxRunner = await loadCtxRunner(dir);
  const clock = { t: 1_000 };
  const controller = fakeController({ replyOf: () => '  ' });
  const runner = createCtxRunner(controller, { workspace: dir, now: at(clock) });
  const out = await runner.ask('空答复', {});

  assert.deepEqual(await runner.poll(out.sessionId), { status: 'running' });
  clock.t += 449;
  assert.deepEqual(await runner.poll(out.sessionId), { status: 'running' });
  clock.t += 1;
  assert.deepEqual(await runner.poll(out.sessionId), { status: 'error', error: 'empty-reply', sessionId: out.sessionId });
  fs.rmSync(dir, { recursive: true, force: true });
});

test('§5 G3 先空后到：正文在窗内到达 → done（宽限窗不吞迟到的答复）', async () => {
  const clock = { t: 0 };
  let text = '';
  const fake = fakeDsh({ replyOf: () => text });
  const runner = dshRunner({ fake, stateDir: makeTempDir(), workspace: makeTempDir('lan-peers-project-'), now: at(clock) });
  const out = await runner.ask('慢半拍的答复');

  assert.deepEqual(await runner.poll(out.sessionId), { status: 'running' });
  text = '正文到了，这才是答复';
  clock.t += 300;
  assert.deepEqual(await runner.poll(out.sessionId), { status: 'done', reply: '正文到了，这才是答复' });
  // 清掉计时：同一会话再被观测也不会因为上面那次空观测立刻失败
  assert.deepEqual(await runner.poll(out.sessionId), { status: 'done', reply: '正文到了，这才是答复' });
});

test('§5 G4 同一会话重新提问 → 宽限重新计时（旧计时不提前开火）', async () => {
  const clock = { t: 0 };
  const fake = fakeDsh({ replyOf: () => '' });
  const runner = dshRunner({ fake, stateDir: makeTempDir(), workspace: makeTempDir('lan-peers-project-'), now: at(clock) });
  const first = await runner.ask('第一问');
  assert.equal((await runner.poll(first.sessionId)).status, 'running');
  clock.t += 600;
  assert.equal((await runner.poll(first.sessionId)).error, 'empty-reply', '窗外这一轮确实是空答复');

  const second = await runner.ask('同一会话第二问', { sessionId: first.sessionId });
  assert.equal(second.reused, true, '续聊同一会话');
  // 旧计时（t=0）若没被清掉，t=600 立刻就会开火；重新提问必须从 600 重新计时
  assert.deepEqual(await runner.poll(second.sessionId), { status: 'running' }, '重新提问后第一个观测点');
  clock.t += 440;
  assert.deepEqual(await runner.poll(second.sessionId), { status: 'running' }, '旧计时不许提前开火（440 < 450）');
  clock.t += 10;
  assert.equal((await runner.poll(second.sessionId)).error, 'empty-reply', '新窗口到头，才判失败');
});

test('§4 非空答复：done 仍是「status + reply」两个键，内容逐字不变', async () => {
  const stateDir = makeTempDir();
  const fake = fakeDsh();
  const runner = dshRunner({ fake, stateDir, workspace: makeTempDir('lan-peers-project-') });
  const out = await runner.ask('正常一问');

  const polled = await runner.poll(out.sessionId);
  assert.deepEqual(polled, { status: 'done', reply: 'ECHO 正常一问' });
  assert.deepEqual(Object.keys(polled), ['status', 'reply'], '成功形状一个键都不多');
  // 首尾带空白的正文是**正文**，不许被当成空答复
  const blankish = fakeDsh({ replyOf: () => '  有正文  ' });
  const runner2 = dshRunner({ fake: blankish, stateDir: makeTempDir(), workspace: makeTempDir('lan-peers-project-') });
  const out2 = await runner2.ask('带空白的答复');
  assert.deepEqual(await runner2.poll(out2.sessionId), { status: 'done', reply: '  有正文  ' });
});
