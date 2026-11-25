/**
 * 0.13.0-α 收尾硬化：插件停用（close()）之后**每一个子系统都停手**。
 *
 * 六个区（审计表见 HANDOVER W1）：
 *   1 lib/group-digest.mjs   10 分钟节拍 / 机会式远端升级 / 迟到的结果（已硬化，这里复证）
 *   2 lib/participant.mjs    30s 批次窗 / 汇报触发 / 在飞的会话提示 / 环路暂停钟（无定时器）
 *   3 log-rotate + index     轮转节拍（节拍在 host/server.mjs；log-rotate 模块本身没有定时器）
 *   4 host/server.mjs        拉取 / 心跳+选举 / 表决轮+shelved 提醒 / 两种清扫 / 广播 / 摘要器
 *   5 lib/identity.mjs       证明：一个定时器都没有
 *   6 lib/admin.mjs          上传临时区清扫节拍
 *
 * 断言口径：
 *   Z1 每个区都跑「活着 → close() → 把时钟推过所有间隔」：之后**零日志、零出站调用、零文件改动**。
 *   Z2 close() 之后才解出来的在飞 promise（远端摘要 / 会话提示 / 群拉取）不写、最多一行 dropped。
 *   Z3 close() 两次、arm 之前 close()、close() 之后 arm()：都安全。
 *   Z4 变异证明（哪一行被删、哪条断言红）写在 HANDOVER W3，本文件提供那几条断言。
 *   Z5 两把尺子量「还挂着几个定时器」：
 *      · lib 三区（可注入）用假时钟的 entries 表：close() 之后 pending() 必须是 0；
 *      · host 区（不可注入）用**穿透式登记表**（真的 setTimeout/setInterval，只是记账）：
 *        close() 之后 live.size 必须回到装表那一刻的基线。
 *      两把尺子都不依赖「进程能不能退出」—— 插件自己的定时器全是 unref 的，unref 不吊住进程，
 *      所以「进程没吊住」根本证明不了它们被清了。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import { listenOnRandomPort } from '../../test-support/ports.mjs';
import { makeTempStateDir, peerFixture, seedPeers, writeJson0600 } from './helpers.mjs';
import { createParticipant } from '../../lib/participant.mjs';
import { createHubSummarizer } from '../../lib/group-digest.mjs';
import { applyPendingIdentityReset, createPeerResetNotifier } from '../../lib/identity.mjs';
import { createAdmin } from '../../lib/admin.mjs';
import { createPeerServer } from '../server.mjs';
import { waitFor } from './group-cluster.mjs';

// ---------------------------------------------------------------------------
// 尺子 1：假时钟 + 假定时器（与 lib/group-digest.test.mjs 同一副形状）
// ---------------------------------------------------------------------------

/** advance() 只让到期的条目触发；repeating 条目自己续命；返回的是可 unref 的假 handle。 */
function fakeClock(startMs = 1_000_000) {
  const entries = new Map();
  let seq = 0;
  const clock = {
    nowMs: startMs,
    fired: 0,
    setTimeoutFn(fn, ms) {
      const id = (seq += 1);
      const handle = { id, unref() { return handle; } };
      const delay = Math.max(0, Number(ms) || 0);
      entries.set(id, { fn, due: clock.nowMs + delay, every: 0 });
      return handle;
    },
    setIntervalFn(fn, ms) {
      const id = (seq += 1);
      const handle = { id, unref() { return handle; } };
      const every = Math.max(1, Number(ms) || 1);
      entries.set(id, { fn, due: clock.nowMs + every, every });
      return handle;
    },
    clearTimeoutFn(handle) {
      if (handle && handle.id) entries.delete(handle.id);
    },
    clearIntervalFn(handle) {
      if (handle && handle.id) entries.delete(handle.id);
    },
    advance(ms) {
      const target = clock.nowMs + Math.max(0, Number(ms) || 0);
      for (let guard = 0; guard < 200000; guard += 1) {
        let nextId = 0;
        let next = null;
        for (const [id, entry] of entries) {
          if (entry.due > target) continue;
          if (!next || entry.due < next.due) { next = entry; nextId = id; }
        }
        if (!next) break;
        clock.nowMs = next.due;
        if (next.every > 0) next.due += next.every;
        else entries.delete(nextId);
        clock.fired += 1;
        next.fn();
      }
      clock.nowMs = target;
    },
    pending() {
      return entries.size;
    },
  };
  clock.clearTimeout = clock.clearTimeoutFn;
  clock.clearInterval = clock.clearIntervalFn;
  return clock;
}

/** 假时钟/假登记表装到全局上，返回卸载函数（用在只认全局定时器的区：admin） */
function installGlobalTimers(clock) {
  const real = {
    setTimeout: globalThis.setTimeout,
    clearTimeout: globalThis.clearTimeout,
    setInterval: globalThis.setInterval,
    clearInterval: globalThis.clearInterval,
  };
  globalThis.setTimeout = clock.setTimeoutFn;
  globalThis.clearTimeout = clock.clearTimeoutFn;
  globalThis.setInterval = clock.setIntervalFn;
  globalThis.clearInterval = clock.clearIntervalFn;
  return () => {
    globalThis.setTimeout = real.setTimeout;
    globalThis.clearTimeout = real.clearTimeout;
    globalThis.setInterval = real.setInterval;
    globalThis.clearInterval = real.clearInterval;
  };
}

// ---------------------------------------------------------------------------
// 尺子 2：穿透式定时器登记表（给不可注入的 host 区用）
//
// 真的 set/clear，只是记账：返回的仍是真 handle（.unref() 照常可用）。
// 这样「close() 之后还挂着几个定时器」变成可观测的整数 —— 插件的定时器全是 unref 的，
// 光看「进程能不能退出」永远看不见它们。
// ---------------------------------------------------------------------------

function installTimerRegistry() {
  const live = new Map();
  /**
   * 只记账**本仓库**发起的定时器：undici 连接池自己那枚 refreshTimeout（以及 node:internal
   * 的任何节拍）不是插件的，close() 也没义务清它 —— 混进来只会让断言变成噪声。
   * 返回 null = 不是我们的，不记账；否则返回调用点（排障用）。
   */
  const siteOf = () => {
    const stack = String(new Error().stack ?? '');
    if (stack.includes('undici') || !stack.includes('lan-peers')) return null;
    const line = stack.split('\n').slice(3, 4)[0] ?? '';
    return line.trim().replace(/^at\s+/, '').slice(0, 160);
  };
  const real = {
    setTimeout: globalThis.setTimeout,
    clearTimeout: globalThis.clearTimeout,
    setInterval: globalThis.setInterval,
    clearInterval: globalThis.clearInterval,
  };
  globalThis.setTimeout = (fn, ms, ...args) => {
    let handle = null;
    const wrapped = (...callArgs) => {
      if (handle) live.delete(handle);
      return fn(...callArgs);
    };
    const site = siteOf();
    handle = real.setTimeout(wrapped, ms, ...args);
    if (site !== null) live.set(handle, { kind: 'timeout', site });
    return handle;
  };
  globalThis.setInterval = (fn, ms, ...args) => {
    const site = siteOf();
    const handle = real.setInterval(fn, ms, ...args);
    if (site !== null) live.set(handle, { kind: 'interval', site });
    return handle;
  };
  globalThis.clearTimeout = (handle) => {
    if (handle) live.delete(handle);
    return real.clearTimeout(handle);
  };
  globalThis.clearInterval = (handle) => {
    if (handle) live.delete(handle);
    return real.clearInterval(handle);
  };
  return {
    live,
    armed: () => live.size,
    dump: () => [...live.values()].map((entry) => entry.kind + ' @ ' + entry.site),
    restore: () => {
      globalThis.setTimeout = real.setTimeout;
      globalThis.clearTimeout = real.clearTimeout;
      globalThis.setInterval = real.setInterval;
      globalThis.clearInterval = real.clearInterval;
    },
  };
}

// ---------------------------------------------------------------------------
// 盘上快照 + 出站调用记账
// ---------------------------------------------------------------------------

function snapshotTree(dir) {
  const out = new Map();
  const walk = (current) => {
    let entries = [];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        out.set(full, 'dir');
        walk(full);
        continue;
      }
      try {
        const bytes = fs.readFileSync(full);
        out.set(full, createHash('sha256').update(bytes).digest('hex') + ':' + bytes.length);
      } catch {
        out.set(full, 'unreadable');
      }
    }
  };
  walk(dir);
  return out;
}

function treeDiff(before, after) {
  const changed = [];
  for (const [file, sig] of after) if (before.get(file) !== sig) changed.push(path.basename(file));
  for (const file of before.keys()) if (!after.has(file)) changed.push('-' + path.basename(file));
  return changed;
}

function makeDeferred() {
  let resolve = null;
  const promise = new Promise((r) => { resolve = r; });
  return { promise, resolve };
}

const settle = () => sleep(15);

// ---------------------------------------------------------------------------
// Z1/Z2/Z3 · 区 2：常驻参与者
// ---------------------------------------------------------------------------

function makeParticipant({ dir, clock, lines, prompts, promptSession }) {
  return createParticipant({
    stateDir: dir,
    config: { batchMs: 30_000, reportEveryMs: 60_000, reportEveryMessages: 5 },
    promptSession,
    askSummary: async (sessionId) => ({ sessionId, reused: true, reply: 'summary' }),
    log: (line) => lines.push(String(line)),
    now: () => clock.nowMs,
    setTimeoutFn: clock.setTimeoutFn,
    clearTimeoutFn: clock.clearTimeoutFn,
  });
}

test('Z1/Z3 · participant：批次窗与汇报节拍在 close() 之后一律不响', async (t) => {
  const dir = makeTempStateDir('shutdown-participant-');
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const clock = fakeClock();
  const lines = [];
  const prompts = [];
  const participant = makeParticipant({
    dir,
    clock,
    lines,
    prompts,
    promptSession: async (sessionId, prompt) => {
      prompts.push({ sessionId, prompt });
      return { sessionId: 'sess-1', reused: true };
    },
  });

  participant.arm();
  participant.push({
    kind: 'group',
    messages: [{ seq: 1, from: { peerId: 'peer-aaaa', name: 'a' }, text: 'hello', kind: 'chat' }],
  });
  assert.ok(clock.pending() > 0, '活着：批一次窗口至少挂一个定时器');
  clock.advance(30_000);
  await settle();
  assert.equal(prompts.length, 1, '活着：批次窗到点真的打了一次会话');
  assert.ok(lines.some((line) => line.includes('wake kind=group')), '活着：wake 日志在');

  // 让 close() 面对**真的挂着的**定时器：再来一批 → 批次窗重新挂上。
  // 没有这一步，「不清定时器」这个变异根本打不红（close 时表是空的，clear 是空转）。
  participant.push({
    kind: 'group',
    messages: [{ seq: 2, from: { peerId: 'peer-aaaa', name: 'a' }, text: 'still-pending', kind: 'chat' }],
  });
  await settle();
  assert.ok(clock.pending() >= 1, 'close() 之前还有挂着的定时器（这样「清」才是被测的行为）：' + clock.pending());
  const promptsBeforeClose = prompts.length;

  participant.close();
  const atClose = snapshotTree(dir);
  const linesAtClose = lines.length;
  const promptsAtClose = prompts.length;
  assert.equal(promptsAtClose, promptsBeforeClose, 'close() 自己不许多打一次会话');
  // 「推时钟」之前先量：清没清是 close() 当场的事，不能被后面那次 advance 的触发掩盖
  assert.equal(clock.pending(), 0, 'Z1/Z5：close() 当场必须一个定时器都不留');

  clock.advance(2 * 60 * 60 * 1000);
  await settle();

  assert.equal(prompts.length, promptsAtClose, 'Z1：close() 之后一次会话都不许打');
  assert.equal(lines.length, linesAtClose, 'Z1：close() 之后一行日志都不许出');
  assert.deepEqual(treeDiff(atClose, snapshotTree(dir)), [], 'Z1：close() 之后盘上一个字节都不许动');
  assert.equal(clock.pending(), 0, 'Z1/Z5：close() 之后一个定时器都不许留');

  // Z3：幂等 + close() 之后 arm() 不许把闸重新打开（index.js 的 listen().then(arm) 竞态）
  assert.doesNotThrow(() => participant.close(), 'Z3：第二次 close() 不许抛');
  participant.arm();
  assert.equal(clock.pending(), 0, 'Z3：close() 之后 arm() 不许再挂定时器');
  participant.push({
    kind: 'group',
    messages: [{ seq: 2, from: { peerId: 'peer-aaaa', name: 'a' }, text: 'after-close', kind: 'chat' }],
  });
  clock.advance(2 * 60 * 60 * 1000);
  await settle();
  assert.equal(prompts.length, promptsAtClose, 'Z3：close() 之后 arm()+push 也不许唤醒');
  assert.equal(lines.length, linesAtClose, 'Z3：close() 之后 arm()+push 也不许出日志');
});

test('Z2 · participant：close() 之后才解出来的会话提示不落盘、不记 session-recreated', async (t) => {
  const dir = makeTempStateDir('shutdown-participant-late-');
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const clock = fakeClock();
  const lines = [];
  const gate = makeDeferred();
  const participant = makeParticipant({
    dir,
    clock,
    lines: lines,
    prompts: [],
    promptSession: async () => gate.promise,
  });

  participant.arm();
  participant.push({
    kind: 'group',
    messages: [{ seq: 1, from: { peerId: 'peer-bbbb', name: 'b' }, text: 'hello', kind: 'chat' }],
  });
  clock.advance(30_000);
  await settle(); // deliver 已经在等 gate
  participant.close();
  const atClose = snapshotTree(dir);
  const linesAtClose = lines.length;

  // 迟到的结果：新建了一个会话（reused:false）→ 旧形状会落盘 + 记 session-recreated
  gate.resolve({ sessionId: 'sess-late', reused: false });
  await settle();

  assert.deepEqual(treeDiff(atClose, snapshotTree(dir)), [], 'Z2：迟到的会话 id 不许落盘');
  assert.equal(lines.length, linesAtClose, 'Z2：连一行 session-recreated 都不许记');
  assert.equal(participant.state().channels.group.sessionId, '', 'Z2：迟到的 id 不许被采纳');
});

// ---------------------------------------------------------------------------
// Z1/Z2 · 区 1：群摘要器的 10 分钟节拍与迟到的远端结果
// ---------------------------------------------------------------------------

function makeDigestStore() {
  const digests = [];
  return {
    appends: 0,
    newest: () => (digests.length > 0 ? digests[digests.length - 1] : null),
    appendMany(chunks) {
      this.appends += 1;
      const made = (Array.isArray(chunks) ? chunks : []).map((chunk) => ({ at: 0, ...chunk }));
      digests.push(...made);
      return { ok: true, digests: made, digest: made[made.length - 1] ?? null, rev: digests.length };
    },
    count: () => digests.length,
    rev: 0,
  };
}

test('Z1/Z2 · digest：节拍停下来，迟到的远端摘要一个字节都不追加', async (t) => {
  const dir = makeTempStateDir('shutdown-digest-');
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const clock = fakeClock();
  const lines = [];
  const store = makeDigestStore();
  const gate = makeDeferred();
  let remoteCalls = 0;

  const summarizer = createHubSummarizer({
    isHub: true,
    store,
    messages: () => [
      { seq: 1, from: { peerId: 'p-a', name: 'a' }, text: 'm1' },
      { seq: 2, from: { peerId: 'p-b', name: 'b' }, text: 'm2' },
    ],
    promptSession: async () => { throw Object.assign(new Error('no-session'), { code: 'no-session' }); },
    stateDir: dir,
    modelSummary: false,
    everyMs: 600_000,
    pauseWhenAlone: false,
    now: () => clock.nowMs,
    setIntervalFn: clock.setIntervalFn,
    clearIntervalFn: clock.clearIntervalFn,
    setTimeoutFn: clock.setTimeoutFn,
    clearTimeoutFn: clock.clearTimeoutFn,
    remoteSummary: {
      summary: async () => { remoteCalls += 1; return gate.promise; },
    },
    log: (line) => lines.push(String(line)),
  });

  summarizer.start();
  assert.equal(clock.pending(), 1, '活着：一个 10 分钟节拍');
  clock.advance(600_000);
  await settle();
  assert.equal(store.appends, 1, '活着：这一趟真的写下了一条确定性条目');
  assert.ok(lines.length > 0, '活着：摘要日志在');
  assert.equal(remoteCalls, 1, '活着：机会式远端升级已经派出（在飞）');

  summarizer.close();
  assert.equal(clock.pending(), 0, 'Z1：close() 当场清掉节拍');
  const linesAtClose = lines.length;
  const appendsAtClose = store.appends;

  clock.advance(2 * 60 * 60 * 1000);
  await settle();
  assert.equal(store.appends, appendsAtClose, 'Z1：推进 2 小时，一条都不许再写');
  assert.equal(lines.length, linesAtClose, 'Z1：推进 2 小时，一行日志都不许再出');
  assert.equal(remoteCalls, 1, 'Z1：推进 2 小时，一次远端派发都不许再发');

  gate.resolve({ ok: true, text: 'REMOTE-SUMMARY', by: 'peer-remote' });
  await settle();
  assert.equal(store.appends, appendsAtClose, 'Z2：迟到的远端结果一个字节都不追加');
  assert.equal(lines.length - linesAtClose, 1, 'Z2：最多一行 dropped');
  assert.match(lines[lines.length - 1], /dropped reason=closed/, 'Z2：那一行是 dropped 而不是写入');
  assert.equal(clock.pending(), 0, 'Z2：迟到结果收下之后仍然一个定时器都没有');
});

// ---------------------------------------------------------------------------
// Z1 · 区 5：identity 一个定时器都没有（动态 + 静态两条证据）
// ---------------------------------------------------------------------------

test('Z1 · identity：模块不排任何定时器（假表 + 源码两条证据）', async (t) => {
  const dir = makeTempStateDir('shutdown-identity-');
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const clock = fakeClock();
  const uninstall = installGlobalTimers(clock);
  let fetchCalls = 0;
  const realFetch = globalThis.fetch;
  globalThis.fetch = (...args) => { fetchCalls += 1; return realFetch(...args); };
  t.after(() => {
    globalThis.fetch = realFetch;
    uninstall();
  });

  const notifier = createPeerResetNotifier({ callPeer: async () => ({ ok: true }) });
  await notifier({ baseUrl: 'http://127.0.0.1:1', secret: 's' }, { resetAt: 'now', reason: 'test', senderId: 'me' });
  const applied = await applyPendingIdentityReset({ stateDir: dir, log: () => {} });

  assert.equal(applied.applied, false, '没有 marker 时如实回报 no-marker');
  assert.equal(clock.pending(), 0, 'Z1：identity 一个定时器都不许排');
  assert.equal(fetchCalls, 0, 'Z1：identity 自己一条网络都不发（通知走注入的 callPeer）');

  const source = fs.readFileSync(new URL('../../lib/identity.mjs', import.meta.url), 'utf8');
  assert.equal(/set(?:Timeout|Interval)\s*\(/.test(source), false, 'Z1：源码里没有 set{Timeout,Interval}(');
});

// ---------------------------------------------------------------------------
// Z1 · 区 6：admin 上传临时区清扫节拍
// ---------------------------------------------------------------------------

function adminResponse() {
  return {
    status: 0,
    headers: {},
    body: '',
    setHeader(name, value) { this.headers[name] = value; },
    writeHead(status, headers) { this.status = status; Object.assign(this.headers, headers || {}); },
    write(chunk) { this.body += chunk; return true; },
    end(chunk) { if (chunk) this.body += chunk; if (!this.status) this.status = 200; },
    once() {},
    on() {},
  };
}

function adminRequest(method, url, body, admin) {
  const chunks = body === undefined ? [] : [Buffer.from(JSON.stringify(body))];
  return {
    method,
    url,
    socket: { remoteAddress: '127.0.0.1', setNoDelay() {} },
    headers: {
      host: '127.0.0.1:7788',
      'content-type': 'application/json',
      'content-length': String(chunks[0]?.length ?? 0),
      ...(typeof admin.token === 'string' && admin.token !== '' ? { 'x-lan-peers-token': admin.token } : {}),
    },
    on() { return this; },
    once() { return this; },
    async *[Symbol.asyncIterator]() { for (const chunk of chunks) yield chunk; },
  };
}

async function adminHit(admin, method, apiPath, body) {
  const res = adminResponse();
  await admin.handle(adminRequest(method, apiPath, body, admin), res, new URL('http://127.0.0.1' + apiPath));
  return res;
}

test('Z1 · admin：清扫节拍在 close() 之后既不清也不许被请求重新点亮', async (t) => {
  const dir = makeTempStateDir('shutdown-admin-');
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const clock = fakeClock();
  const uninstall = installGlobalTimers(clock);
  const lines = [];
  const server = createPeerServer({
    listenHost: '127.0.0.1',
    stateDir: dir,
    logger: (line) => lines.push(String(line)),
  });
  t.after(async () => { await server.close(); uninstall(); });

  const admin = createAdmin({
    server,
    nameOf: () => server.config.name,
    rename: (next) => next,
    pairing: { mode: 'auto' },
  });

  assert.equal(admin.uploadSweepArmed(), false, '还没人上传时不该挂着清理节拍');
  const init = await adminHit(admin, 'POST', '/api/lan-peers/files/upload/init', { name: 'a.bin', bytes: 4 });
  assert.equal(init.status, 200, '活着：init 成功（' + init.body + '）');
  assert.equal(admin.uploadSweepArmed(), true, '活着：第一次 init 点亮清理节拍');
  const sweepsAtArm = lines.filter((line) => line.includes('upload sweep')).length;

  admin.close();
  assert.equal(admin.uploadSweepArmed(), false, 'Z1：close() 当场清掉清理节拍');
  assert.equal(clock.pending() - 1, 0, 'Z1：假表里只剩 server 的待批准定时器（下面 close() 清掉）');

  // close() 之后再来一次 init：功能与插件一起关 —— 不许重新点亮、不许写日志
  const linesAtClose = lines.length;
  const late = await adminHit(admin, 'POST', '/api/lan-peers/files/upload/init', { name: 'b.bin', bytes: 4 });
  assert.equal(late.status, 503, 'Z1：停用之后 init 一律 503（不留半截上传）');
  assert.equal(admin.uploadSweepArmed(), false, 'Z1：停用之后一次在飞请求不许把它重新点亮');
  assert.equal(lines.length, linesAtClose, 'Z1：停用之后不许再出一行日志');
  assert.equal(lines.filter((line) => line.includes('upload sweep')).length, sweepsAtArm, 'Z1：一次清扫都不许再跑');

  clock.advance(2 * 60 * 60 * 1000);
  await server.close();
  assert.equal(clock.pending(), 0, 'Z1/Z5：admin + server 都关掉之后假表里一个定时器都不许剩');
});

// ---------------------------------------------------------------------------
// Z1/Z2/Z5 · 区 3（轮转节拍）+ 区 4（拉取/心跳/选举/表决/shelved/清扫/广播）
//
// host 的节拍**不可注入**（createPeerServer 没有 setIntervalFn 口子），所以这里用两把尺子代替
// 「把假时钟推 2 小时」：
//   · 活着的证明 = 每类定时器真的挂上了（登记表 armed() / voteTimers() / shelvedReminders() /
//     logRotation.armed()）且拉取真的发出了一次出站调用；
//   · 停手的证明 = close() 之后登记表回到装表时的基线、各类计数器归零，再**真等 600 ms**
//     （>5×心跳 120 ms、>24×选举 tick 25 ms）：期间零出站调用、零日志、零文件改动。
// ---------------------------------------------------------------------------

const MEMBER_ID = peerFixture('peer-shutdown-1');

async function startShutdownHub(t, { logger } = {}) {
  const stateDir = makeTempStateDir('shutdown-hub-');
  t.after(() => fs.rmSync(stateDir, { recursive: true, force: true }));
  seedPeers(stateDir, [MEMBER_ID]);
  const server = createPeerServer({
    listenHost: '127.0.0.1',
    stateDir,
    requireEncryption: false,
    // quorum:none = 写本地即提交：这里测的是收尾，不是两阶段提交
    group: { enabled: true, name: 'default', autoJoin: true, retentionDays: 7, quorum: 'none' },
    // 表决轮 4s / 重提醒 30s：本用例只断言「挂着」与「清掉」，不真等它们到点
    groupVote: { roundMs: 4_000, reminderMs: 30_000 },
    ...(logger ? { logger } : {}),
  });
  const info = await listenOnRandomPort(server);
  return { server, stateDir, baseUrl: info.url };
}

async function startShutdownMember(t, { hubBaseUrl, hubInstanceId, logger } = {}) {
  const dir = makeTempStateDir('shutdown-member-');
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  writeJson0600(path.join(dir, 'state.json'), {
    instanceId: MEMBER_ID.peerId,
    name: MEMBER_ID.name,
    createdAt: new Date().toISOString(),
  });
  writeJson0600(path.join(dir, 'peers.json'), {
    peers: {
      [hubInstanceId]: {
        name: 'hub',
        baseUrl: hubBaseUrl,
        secret: MEMBER_ID.inboundSecret,
        inboundSecret: 'unused-outbound',
        addedAt: new Date().toISOString(),
        lastSeen: null,
      },
    },
  });
  const server = createPeerServer({
    listenHost: '127.0.0.1',
    stateDir: dir,
    requireEncryption: false,
    group: { enabled: true, hub: 'hub', autoJoin: true },
    // 测试自己驱动补差，不让 600s 的后台节拍插进来
    groupReplica: { pullIntervalMs: 600_000 },
    ...(logger ? { logger } : {}),
  });
  const info = await listenOnRandomPort(server);
  server.config.group.advertiseBaseUrl = info.url;
  return { server, dir, baseUrl: info.url };
}

/** 后台首轮 tick 可能正占着 memberInFlight：等到真正跑完一轮 */
async function pullNow(server, attempts = 60) {
  for (let index = 0; index < attempts; index += 1) {
    const out = await server.group.pull();
    if (out?.reason !== 'skipped') return out;
    await sleep(25);
  }
  throw new Error('member pull kept being skipped');
}

test('Z1/Z2/Z5 · host/server：close() 之后节拍器与在飞的群拉取都停手', async (t) => {
  const registry = installTimerRegistry();
  const realFetch = globalThis.fetch;
  const calls = [];
  /**
   * Z2：让一次真实拉取的响应**在 close() 之后**才交回调用方。
   * body 先整段读完再扣住 —— 这样「调用已经在 close() 之前发出」与「结果在 close() 之后落地」
   * 才是两件分开的事（否则测的只是 close() 掐断了连接）。
   */
  const hold = { armed: false, release: null };
  globalThis.fetch = async (url, init) => {
    calls.push(String(url));
    const res = await realFetch(url, init);
    if (hold.armed && String(url).includes('/v1/group/pull')) {
      const body = Buffer.from(await res.arrayBuffer());
      await new Promise((resolve) => { hold.release = resolve; });
      return new Response(body, { status: res.status, headers: res.headers });
    }
    return res;
  };
  t.after(() => {
    globalThis.fetch = realFetch;
    registry.restore();
  });
  const baseline = registry.armed();
  const lines = [];
  const logger = (line) => lines.push(String(line));

  const hub = await startShutdownHub(t, { logger });
  const member = await startShutdownMember(t, {
    hubBaseUrl: hub.baseUrl,
    hubInstanceId: hub.server.store.instanceId,
    logger,
  });
  t.after(async () => {
    await hub.server.close();
    await member.server.close();
  });

  // ---- 活着的证明：区 4 的拉取 + 各节拍器真的挂上了 ----------------------
  const firstPull = await pullNow(member.server);
  assert.equal(firstPull.ok, true, '活着：成员真的补差了一轮：' + JSON.stringify(firstPull));
  assert.ok(calls.some((url) => url.includes('/v1/group/pull')),
    '活着：拉取真的发出了出站调用 | calls=' + calls.join(' ; ') + ' | pull=' + JSON.stringify(firstPull));
  assert.ok(registry.armed() > baseline, '活着：host 的定时器真的挂上了（登记表 > 基线）');
  assert.equal(hub.server.logRotation.armed(), true, '活着：区 3 轮转节拍挂上了');

  const submitted = hub.server.group.submitProposal({
    kind: 'objection',
    target: { type: 'body', id: 'body-1' },
    text: 'SHUTDOWN-PROPOSAL-BODY',
    author: 'alice',
  });
  assert.equal(submitted.ok, true, '提案要能入库：' + JSON.stringify(submitted));
  const proposalId = submitted.proposal.id;
  assert.equal(hub.server.group.voteTimers(), 1, '活着：开着的轮挂着一个表决定时器');

  // 每一轮全体投 no → impossible → 下一轮；轮数到顶就 shelved
  for (let round = 1; round <= 6; round += 1) {
    const vote = hub.server.group.votes().votes[proposalId];
    if (vote.status !== 'open') break;
    for (const peerId of vote.roster) {
      hub.server.group.castVote({ proposalId, peerId, ballot: 'no' });
    }
  }
  assert.equal(hub.server.group.votes().votes[proposalId].status, 'shelved', '全是 no 之后必须 shelved');
  assert.equal(hub.server.group.voteTimers(), 0, '关轮之后表决定时器归零');
  assert.equal(hub.server.group.shelvedReminders(), 1, '活着：shelved 重提醒挂着一个');

  // ---- Z2：一次在飞的群拉取（响应被扣住） --------------------------------
  hold.armed = true;
  const pulling = member.server.group.pull();
  await waitFor(() => typeof hold.release === 'function', { timeoutMs: 5_000, intervalMs: 20 });
  assert.equal(typeof hold.release, 'function', '在飞的拉取确实被扣住了');

  // ---- close()：停用 ------------------------------------------------------
  await hub.server.close();
  await member.server.close();
  await settle();

  const callsAtClose = calls.length;
  const linesAtClose = lines.length;
  const hubAtClose = snapshotTree(hub.stateDir);
  const memberAtClose = snapshotTree(member.dir);

  assert.equal(hub.server.group.voteTimers(), 0, 'Z1：close() 之后表决定时器为 0');
  assert.equal(hub.server.group.shelvedReminders(), 0, 'Z1：close() 之后 shelved 重提醒为 0');
  assert.equal(hub.server.logRotation.armed(), false, 'Z1：close() 之后轮转节拍为 false');
  assert.equal(registry.armed(), baseline,
    'Z1/Z5：close() 之后登记表回到基线（一条定时器都不留）| 还活着：' + registry.dump().join(' | '));

  // ---- Z2：迟到的拉取结果 ------------------------------------------------
  hold.release();
  const pulled = await pulling;
  await settle();
  assert.equal(pulled?.reason, 'closed', 'Z2：迟到的拉取如实回报 closed：' + JSON.stringify(pulled));
  assert.deepEqual(treeDiff(memberAtClose, snapshotTree(member.dir)), [],
    'Z2：迟到拉取不许改成员副本（replicaStore.append / setNotes / rememberPeerBaseUrl 都在闸后）');
  assert.equal(lines.length, linesAtClose, 'Z2：迟到拉取连一行 pull failed 都不许记');

  // ---- Z1：真等 600 ms（>5×心跳、>24×选举 tick）：零活动 ------------------
  await sleep(600);
  assert.equal(calls.length, callsAtClose, 'Z1：close() 之后一次出站调用都不许发');
  assert.equal(lines.length, linesAtClose, 'Z1：close() 之后一行日志都不许出');
  assert.deepEqual(treeDiff(hubAtClose, snapshotTree(hub.stateDir)), [], 'Z1：hub 的 stateDir 一个字节都不许动');
  assert.deepEqual(treeDiff(memberAtClose, snapshotTree(member.dir)), [], 'Z1：成员的 stateDir 一个字节都不许动');
  assert.equal(registry.armed(), baseline, 'Z1/Z5：等待期间也没有任何定时器复活');
});