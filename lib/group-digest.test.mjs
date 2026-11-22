// dsh-lan-peers · 0.12.8-alpha（slice H）群摘要：D1-D9
//
// 每个用例一个临时 stateDir（真落盘、真 0600 原子写），会话与时钟全部可注入 ——
// 没有一个用例真的等 10 分钟，也没有一个用例真的叫模型。
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  DIGEST_FALLBACK_CHARS,
  DIGEST_FALLBACK_LINE_MAX,
  DIGEST_KEEP,
  DIGEST_OUT_FILE,
  DIGEST_PLANE_LIMIT,
  DIGEST_PROMPT_TIMEOUT_MS,
  DIGEST_SESSION_FILE,
  DIGEST_TEXT_MAX,
  DIGEST_TRIGGER_MS,
  DIGEST_TRUNC_NOTE,
  GroupDigestStore,
  createHubSummarizer,
  createSessionPrompt,
  fallbackChunkText,
  fallbackDigestText,
  resolveModelSummary,
  splitFallbackChunks,
} from './group-digest.mjs';
import { resolveConfig } from '../host/server.mjs';

/** hub 侧 handoff 文件（正文走文件，回复只写 DONE） */
const outPathOf = (dir) => path.join(dir, DIGEST_OUT_FILE);

const CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/;

function tempDir(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-digest-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

/** 假权威日志：seq 从 1 起，push(n) 追 n 条 */
function fakeLog() {
  const rows = [];
  return {
    rows,
    push(count, text = (seq) => '第 ' + seq + ' 条消息', name = 'alice') {
      for (let index = 0; index < count; index += 1) {
        const seq = rows.length + 1;
        rows.push({ seq, from: { peerId: 'peer-a', name }, text: text(seq) });
      }
      return rows.length;
    },
    read(fromSeq) {
      return rows.filter((row) => row.seq > Number(fromSeq || 0));
    },
  };
}

const alwaysAgent = (reply = '群里定了两件事。') => async (sessionId) => ({
  sessionId: sessionId || 's-1',
  reused: sessionId !== '',
  reply,
});

// modelSummary 缺省 true：既有 D/C/T/Q/N 用例测的就是**模型那条路**（决定 A 只是把生产默认翻成关）
function setup(t, { isHub = true, promptSession = null, staleSession = null, modelSummary = true, ...rest } = {}) {
  const dir = tempDir(t);
  // staleSession：**构造之前**就在 stateDir 里放一份旧会话文件（复活防线要测的就是它）
  if (staleSession !== null) {
    fs.writeFileSync(path.join(dir, DIGEST_SESSION_FILE), JSON.stringify({ sessionId: staleSession }), { mode: 0o600 });
  }
  const log = fakeLog();
  const lines = [];
  const store = new GroupDigestStore({
    stateDir: dir,
    hubId: isHub ? 'peer-hub' : '',
    now: () => 1_000,
    logger: (line) => lines.push(line),
  });
  const summarizer = createHubSummarizer({
    isHub,
    store,
    messages: (fromSeq) => log.read(fromSeq),
    promptSession,
    modelSummary,
    stateDir: dir,
    log: (line) => lines.push(line),
    now: () => 1_700_000_000_000,
    ...rest,
  });
  t.after(() => summarizer.close());
  return { dir, store, log, summarizer, lines };
}

const fileOf = (dir) => JSON.parse(fs.readFileSync(path.join(dir, 'group-digests.json'), 'utf8'));

async function waitFor(check, { timeoutMs = 3_000, intervalMs = 10 } = {}) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = await check();
    if (value) return value;
    if (Date.now() >= deadline) return value;
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
}

// ---------------------------------------------------------------------------
// D1 计数触发
// ---------------------------------------------------------------------------

test('D1 40 条新消息 → 恰好一条摘要，窗口正好覆盖这 40 条；没新消息的第二次什么都不写', async (t) => {
  const { store, log, summarizer, dir } = setup(t, { promptSession: alwaysAgent() });
  log.push(39);
  const early = await summarizer.maybeSummarize('count');
  assert.equal(early.ok, false);
  assert.equal(early.error, 'below-threshold');
  assert.equal(store.count(), 0);

  log.push(1);
  const first = await summarizer.maybeSummarize('count');
  assert.equal(first.ok, true);
  assert.equal(first.trigger, 'count');
  assert.equal(store.count(), 1);
  const only = store.list()[0];
  assert.equal(only.digestId, 'd-1-40');
  assert.equal(only.fromSeq, 1);
  assert.equal(only.toSeq, 40);
  assert.equal(only.source, 'agent');
  assert.equal(only.text, '群里定了两件事。');
  assert.equal(store.rev, 40);
  assert.equal(fileOf(dir).digests.length, 1);

  const again = await summarizer.maybeSummarize('count');
  assert.equal(again.ok, false);
  assert.equal(again.error, 'no-new');
  assert.equal(store.count(), 1, '没有新消息就不该有第二条摘要');
});

test('D1b noteNew 是计数触发的落点：39 条不叫模型，第 40 条才叫一次', async (t) => {
  let calls = 0;
  const prompt = async () => {
    calls += 1;
    return { sessionId: 's-1', reused: true, reply: '摘要正文' };
  };
  const { store, log, summarizer } = setup(t, { promptSession: prompt });
  log.push(39);
  const quiet = summarizer.noteNew();
  assert.equal(quiet.ok, true);
  assert.equal(quiet.pending, 39);
  assert.equal(quiet.fired, null);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(calls, 0);
  assert.equal(store.count(), 0);

  log.push(1);
  const fired = summarizer.noteNew();
  assert.equal(fired.fired, 'count');
  await fired.done;
  assert.equal(calls, 1);
  assert.equal(store.count(), 1);
  assert.equal(store.list()[0].toSeq, 40);
});

// ---------------------------------------------------------------------------
// D2 时间触发
// ---------------------------------------------------------------------------

test('D2 时间触发：不足 40 条也写一条（窗口只含这一批）', async (t) => {
  const { store, log, summarizer } = setup(t, { promptSession: alwaysAgent('七条消息的摘要。') });
  log.push(7);
  const out = await summarizer.maybeSummarize('timer');
  assert.equal(out.ok, true);
  assert.equal(out.trigger, 'timer');
  assert.equal(store.count(), 1);
  const only = store.list()[0];
  assert.equal(only.fromSeq, 1);
  assert.equal(only.toSeq, 7);
  assert.equal(only.source, 'agent');
});

test('D2b count + timer 同时 fire → 只写一条（并发的第二次是 no-op）', async (t) => {
  let calls = 0;
  let release = () => {};
  const gate = new Promise((resolve) => { release = resolve; });
  const prompt = async () => {
    calls += 1;
    await gate;
    return { sessionId: 's-1', reused: true, reply: '同一批只摘要一次。' };
  };
  const { store, log, summarizer } = setup(t, { promptSession: prompt });
  log.push(40);
  const first = summarizer.maybeSummarize('count');
  const second = summarizer.maybeSummarize('timer');
  release();
  const results = await Promise.all([first, second]);
  assert.equal(store.count(), 1, '两路并发只能有一条摘要');
  assert.equal(calls, 1, '模型只该被叫一次');
  const errors = results.filter((row) => row.ok !== true).map((row) => row.error);
  assert.deepEqual(errors, ['in-flight']);
});

test('D2c 10 分钟节拍：unref、close 清掉、到点真的走一趟', async (t) => {
  const clock = { armed: null, cleared: 0, unref: 0 };
  const { store, log, summarizer } = setup(t, {
    promptSession: alwaysAgent('到点摘要。'),
    setIntervalFn: (fn, ms) => {
      clock.armed = { fn, ms };
      return { unref() { clock.unref += 1; } };
    },
    clearIntervalFn: () => { clock.cleared += 1; },
  });
  const armed = summarizer.start();
  assert.equal(armed.ok, true);
  assert.equal(armed.armed, true);
  assert.equal(clock.armed.ms, DIGEST_TRIGGER_MS);
  assert.equal(clock.unref, 1, '节拍必须 unref（不吊住进程）');
  assert.equal(summarizer.start().armed, false, '重复 arm 不叠第二个定时器');

  log.push(3);
  clock.armed.fn();
  const wrote = await waitFor(() => store.count() === 1);
  assert.equal(wrote, true);
  assert.equal(store.list()[0].toSeq, 3);

  summarizer.close();
  assert.equal(clock.cleared, 1);
  assert.equal(summarizer.state().armed, false);
  assert.equal((await summarizer.maybeSummarize('timer')).error, 'closed');
});

// ---------------------------------------------------------------------------
// D3 fallback
// ---------------------------------------------------------------------------

test('D3 fallback：会话抛错 → source:fallback、有表头、有界、rev 照样前进、日志有一行', async (t) => {
  const { store, log, summarizer, lines } = setup(t, {
    promptSession: async () => {
      throw new Error('model down');
    },
  });
  log.push(40, (seq) => '第 ' + seq + ' 条：把周报发群里');
  const out = await summarizer.maybeSummarize('count');
  assert.equal(out.ok, true);
  const only = store.list()[0];
  assert.equal(only.source, 'fallback');
  assert.match(only.text, /^\[digest\] 40 条群消息（seq 1-40/);
  assert.ok(Array.from(only.text).length <= DIGEST_TEXT_MAX);
  assert.ok(only.text.includes('seq=1 '), '兜底摘要里要带原文开头');
  assert.ok(store.value().rev >= 40, '平面照常前进');
  assert.ok(lines.some((line) => line.startsWith('[digest] fallback reason=')));
  assert.ok(lines.some((line) => line.startsWith('[digest] append id=d-1-40 source=fallback')));
});

test('D3b fallback：摘要会话根本不存在（没注入）也不卡住平面', async (t) => {
  const { store, log, summarizer, lines } = setup(t, { promptSession: null });
  log.push(41);
  const out = await summarizer.maybeSummarize('count');
  assert.equal(out.ok, true);
  assert.equal(store.count(), 1);
  assert.equal(store.list()[0].source, 'fallback');
  assert.ok(lines.some((line) => line === '[digest] fallback reason=no-summarizer'));
});

test('D3c fallback：提示超时（注入的时钟）也走兜底，不会挂着不动', async (t) => {
  const { store, log, summarizer, lines } = setup(t, {
    promptSession: () => new Promise(() => {}),
    promptTimeoutMs: 5,
  });
  log.push(40);
  const out = await summarizer.maybeSummarize('count');
  assert.equal(out.ok, true);
  assert.equal(store.list()[0].source, 'fallback');
  assert.ok(lines.some((line) => line === '[digest] fallback reason=timeout'));
});

// ---------------------------------------------------------------------------
// D4 上限
// ---------------------------------------------------------------------------

test('D4 25 条摘要 → 盘上留最新 20；平面只给 5 条、新的在前', async (t) => {
  const { store, dir, log } = setup(t);
  log.push(25 * 40);
  for (let index = 0; index < 25; index += 1) {
    const out = store.append({
      fromSeq: index * 40 + 1,
      toSeq: (index + 1) * 40,
      at: 1_000 + index,
      source: index % 5 === 0 ? 'fallback' : 'agent',
      text: '第 ' + (index + 1) + ' 份摘要',
    });
    assert.equal(out.ok, true);
  }
  assert.equal(store.count(), DIGEST_KEEP);
  const file = fileOf(dir);
  assert.equal(file.version, 1);
  assert.equal(file.digests.length, DIGEST_KEEP);
  assert.equal(file.digests[file.digests.length - 1].digestId, 'd-961-1000', '最新那条必须在');
  assert.equal(file.digests[0].digestId, 'd-201-240', '最旧的 5 条被丢掉');

  const plane = store.value();
  assert.equal(plane.digests.length, DIGEST_PLANE_LIMIT);
  assert.deepEqual(plane.digests.map((row) => row.toSeq), [1000, 960, 920, 880, 840]);
  assert.equal(plane.rev, 1000);
  assert.equal(plane.hubId, 'peer-hub');
});

// ---------------------------------------------------------------------------
// D5 清洗
// ---------------------------------------------------------------------------

test('D5 清洗：控制字符与超长行 → 有界、无控制字符（agent 与 fallback 两条路）', async (t) => {
  const nasty = '好的\u0000\u0007\u001b[31m红字\u001b[0m ' + 'X'.repeat(5_000);
  const { store, log, summarizer } = setup(t, {
    promptSession: async () => ({ sessionId: 's-1', reused: true, reply: nasty }),
  });
  log.push(40, () => nasty);
  await summarizer.maybeSummarize('count');
  const agent = store.list()[0];
  assert.equal(agent.source, 'agent');
  assert.ok(Array.from(agent.text).length <= DIGEST_TEXT_MAX);
  assert.equal(CONTROL.test(agent.text), false);
  assert.equal(agent.text.endsWith('…'), true, '超长要被截断并留可见的省略号');

  const fallback = setup(t, {
    promptSession: async () => {
      throw new Error('nope');
    },
  });
  fallback.log.push(40, () => nasty);
  await fallback.summarizer.maybeSummarize('count');
  const row = fallback.store.list()[0];
  assert.equal(row.source, 'fallback');
  assert.ok(Array.from(row.text).length <= DIGEST_TEXT_MAX);
  assert.equal(CONTROL.test(row.text), false);
});

// ---------------------------------------------------------------------------
// D6 成员采纳 / 非 hub 作者忽略
// ---------------------------------------------------------------------------

test('D6 成员采纳 hub 摘要；非 hub 作者（哪怕 rev 更大）被忽略，盘上不动', async (t) => {
  const hubDir = tempDir(t);
  const memberDir = tempDir(t);
  const hub = new GroupDigestStore({ stateDir: hubDir, hubId: 'peer-hub', now: () => 5 });
  hub.append({ fromSeq: 1, toSeq: 40, at: 100, source: 'agent', text: 'hub 写的摘要' });
  const plane = hub.value();
  assert.deepEqual(Object.keys(plane).sort(), ['digests', 'hubId', 'rev']);
  assert.equal(plane.rev, 40);
  assert.equal(plane.hubId, 'peer-hub');

  const member = new GroupDigestStore({ stateDir: memberDir, hubId: '', now: () => 5 });
  const applied = member.setReplica(plane, { hubId: 'peer-hub' });
  assert.equal(applied.adopted, true);
  assert.equal(applied.rev, 40);
  assert.equal(member.count(), 1);
  assert.equal(member.list()[0].text, 'hub 写的摘要');
  const before = JSON.stringify(member.list());

  const forged = {
    rev: 9_999,
    hubId: 'peer-evil',
    digests: [{ digestId: 'd-41-80', fromSeq: 41, toSeq: 80, at: 200, source: 'agent', text: '伪造摘要' }],
  };
  const ignored = member.setReplica(forged, { hubId: 'peer-hub' });
  assert.equal(ignored.adopted, false);
  assert.equal(ignored.error, 'not-hub-authored');
  assert.equal(JSON.stringify(member.list()), before, '非 hub 作者的摘要一个字节都不落盘');
  assert.equal(fileOf(memberDir).digests.length, 1);

  // 同一份平面再来一次（rev 没变）= 不采纳，也不重写
  const repeat = member.setReplica(plane, { hubId: 'peer-hub' });
  assert.equal(repeat.adopted, false);
});

// ---------------------------------------------------------------------------
// D7 成员节点不建摘要会话
// ---------------------------------------------------------------------------

test('D7 成员节点绝不建摘要会话：零次 create 调用、盘上一条都没有', async (t) => {
  let creates = 0;
  const lines = [];
  const dir = tempDir(t);
  const store = new GroupDigestStore({ stateDir: dir, hubId: '', now: () => 1 });
  const log = fakeLog();
  log.push(200);
  const summarizer = createHubSummarizer({
    isHub: false,
    store,
    messages: (fromSeq) => log.read(fromSeq),
    promptSession: async () => {
      creates += 1;
      return { sessionId: 's-1', reused: false, reply: '不该出现' };
    },
    stateDir: dir,
    log: (line) => lines.push(line),
  });
  assert.equal(summarizer.isHub, false);
  assert.equal(summarizer.noteNew().error, 'hub-only');
  assert.equal(summarizer.tick().error, 'hub-only');
  assert.equal((await summarizer.maybeSummarize('timer')).error, 'hub-only');
  assert.equal((await summarizer.maybeSummarize('count')).error, 'hub-only');
  assert.equal(summarizer.start().error, 'hub-only');
  assert.equal(creates, 0, '成员节点一次都不该建摘要会话');
  assert.equal(store.count(), 0);
  assert.equal(fs.existsSync(path.join(dir, 'group-digest-session.json')), false);
  assert.ok(lines.includes('[digest] summarizer disabled role=member'));
});

test('D7b hub 侧会话造一次、用到底（同一个 sessionId 反复用）', async (t) => {
  const seen = [];
  const prompt = async (sessionId) => {
    seen.push(sessionId);
    return { sessionId: 's-digest', reused: sessionId !== '', reply: '摘要' };
  };
  const { store, log, summarizer, dir } = setup(t, { promptSession: prompt, sessionMode: 'reuse' });
  log.push(40);
  await summarizer.maybeSummarize('count');
  log.push(40);
  await summarizer.maybeSummarize('count');
  assert.deepEqual(seen, ['', 's-digest']);
  assert.equal(store.count(), 2);
  assert.equal(summarizer.sessionId, 's-digest');
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(dir, 'group-digest-session.json'), 'utf8')), {
    sessionId: 's-digest',
  });
});

// ---------------------------------------------------------------------------
// D8 坏文件
// ---------------------------------------------------------------------------

test('D8 group-digests.json 坏掉 → 读成空、不抛错，下一次写成功', async (t) => {
  const dir = tempDir(t);
  fs.writeFileSync(path.join(dir, 'group-digests.json'), '{ 这不是 JSON', { mode: 0o600 });
  const store = new GroupDigestStore({ stateDir: dir, hubId: 'peer-hub', now: () => 9 });
  assert.deepEqual(store.list(), []);
  assert.equal(store.count(), 0);
  assert.equal(store.rev, 0);
  assert.deepEqual(store.value(), { rev: 0, hubId: 'peer-hub', digests: [] });

  const out = store.append({ fromSeq: 1, toSeq: 5, at: 1, source: 'fallback', text: '兜底摘要' });
  assert.equal(out.ok, true);
  assert.equal(store.count(), 1);
  const file = JSON.parse(fs.readFileSync(path.join(dir, 'group-digests.json'), 'utf8'));
  assert.equal(file.version, 1);
  assert.equal(file.digests.length, 1);
});

// ---------------------------------------------------------------------------
// D9 非空性：哪条断言会在「窗口从全部消息算」/「删掉 fallback」时变红
// ---------------------------------------------------------------------------

test('D9 非空性：窗口只算新消息 / fallback 必须存在', async (t) => {
  // 变异 A：若窗口从**全部**消息起算（而不是上一条摘要之后），
  //   第二条摘要的 fromSeq 会是 1 而不是 81 —— 下面这一条就是会红的那个断言。
  const { store, log, summarizer } = setup(t, {
    promptSession: async (sessionId) => ({ sessionId: sessionId || 's-1', reused: true, reply: '摘要' }),
  });
  log.push(80);
  await summarizer.maybeSummarize('count');
  assert.equal(store.count(), 1);
  assert.equal(store.list()[0].fromSeq, 1);
  log.push(5);
  await summarizer.maybeSummarize('timer');
  assert.equal(store.count(), 2);
  assert.equal(store.list()[1].fromSeq, 81, 'A: 窗口必须从上次摘要之后起算');
  assert.equal(store.list()[1].toSeq, 85);
  // 变异 A 的第二个红点：没有新消息时窗口若从 0 起算，这里会多出一条 d-1-80
  const empty = await summarizer.maybeSummarize('timer');
  assert.equal(empty.error, 'no-new', 'A: 没有新消息就只能是 no-new');
  assert.equal(store.count(), 2);

  // 变异 B：若删掉 fallback 这条路，会话抛错时**一条摘要都不会落盘** ——
  //   下面 count===1 与 source==='fallback' 两条断言就是会红的那些。
  const broken = setup(t, {
    promptSession: async () => {
      throw new Error('model down');
    },
  });
  broken.log.push(40);
  const out = await broken.summarizer.maybeSummarize('count');
  assert.equal(out.ok, true, 'B: 会话挂了也要有摘要');
  assert.equal(broken.store.count(), 1, 'B: 删掉 fallback 这里会是 0');
  assert.equal(broken.store.list()[0].source, 'fallback', 'B: 兜底摘要必须标 fallback');
});

// ---------------------------------------------------------------------------
// 提问通道的两种返回形状（真机事故回归：新建分支曾读 asked?.sessionId → 永远空串）
// ---------------------------------------------------------------------------

test('S1 createSessionPrompt：新建会话拿到「裸 sessionId 字符串」，不能因为读错形状而放弃', async () => {
  const asked = [];
  const runner = {
    async ask(prompt, options) {
      asked.push({ prompt, options });
      return 's-new-1'; // ← 裸字符串，不是对象
    },
    async poll() { return { status: 'done', reply: '摘要正文' }; },
  };
  const prompt = createSessionPrompt({ runner });
  const out = await prompt('', '总结这一段');
  assert.equal(out.sessionId, 's-new-1');
  assert.equal(out.reply, '摘要正文');
  assert.equal(out.reused, false);
  assert.equal(asked.length, 1);
  assert.equal(asked[0].options, undefined, '新建分支不许传 options（形状契约的另一半）');
});

test('S2 createSessionPrompt：续聊拿到对象形状并如实回报 reused', async () => {
  const asked = [];
  const runner = {
    async ask(prompt, options) { asked.push(options); return { sessionId: 's-old-9', reused: true }; },
    async poll() { return { status: 'done', reply: 'ok' }; },
  };
  const out = await createSessionPrompt({ runner })('s-old-9', '继续');
  assert.equal(out.sessionId, 's-old-9');
  assert.equal(out.reused, true);
  assert.deepEqual(asked, [{ sessionId: 's-old-9' }]);
});

test('S3 createSessionPrompt：拿不到 sessionId 就抛 no-session（让调用方走确定性兜底）', async () => {
  const runner = { async ask() { return ''; }, async poll() { return { status: 'done', reply: 'x' }; } };
  await assert.rejects(() => createSessionPrompt({ runner })('', 'p'), /no-session/);
});

test('S4 createSessionPrompt：poll 报错向上抛，超时抛 timeout（带 code）', async () => {
  const errRunner = { async ask() { return 's1'; }, async poll() { return { status: 'error', error: 'boom' }; } };
  await assert.rejects(() => createSessionPrompt({ runner: errRunner })('', 'p'), /boom/);
  let tick = 0;
  const slow = { async ask() { return 's1'; }, async poll() { return { status: 'running' }; } };
  await assert.rejects(
    () => createSessionPrompt({ runner: slow, waitMs: 5, now: () => (tick += 10) })('', 'p'),
    (error) => error.code === 'timeout',
  );
});

test('S5 createSessionPrompt：没有 runner / runner 缺 poll 时返回 null（不假装能提问）', () => {
  assert.equal(createSessionPrompt({}), null);
  assert.equal(createSessionPrompt({ runner: { ask: async () => 'x' } }), null);
});

// ---------------------------------------------------------------------------
// T1-T6 正文 handoff：摘要正文从文件读，轮询回来的 reply 只当兜底
//
// 真机事故：两条摘要的 text 都恰好 120 字并以 "…" 收尾，导致整条消息被吞掉。
// 修法不是去猜 poll 那条路为什么截断，而是**不再依赖它**：提示让会话把正文写进
// <stateDir>/digest-out.txt，读完即删；文件缺席才退回 reply。
// ---------------------------------------------------------------------------

test('T1 文件优先：写 700 字文件、回复只有 120 字截断 → 落盘的是文件那份', async (t) => {
  let dir = '';
  // 700 code points，带一个只有文件里才有的开头标记（回复里没有）
  const fileBody = '摘要起点-' + '摘'.repeat(695);
  // 真机那条形状：119 字 + "…" = 恰好 120
  const truncated = '回'.repeat(119) + '…';
  const ctx = setup(t, {
    promptSession: async (sessionId) => {
      fs.writeFileSync(outPathOf(dir), fileBody, 'utf8');
      return { sessionId: sessionId || 's-1', reused: sessionId !== '', reply: truncated };
    },
  });
  dir = ctx.dir;
  ctx.log.push(40);
  const out = await ctx.summarizer.maybeSummarize('count');
  assert.equal(out.ok, true);
  assert.equal(Array.from(fileBody).length, 700);
  assert.equal(Array.from(truncated).length, 120);
  const only = ctx.store.list()[0];
  assert.equal(only.source, 'agent');
  assert.equal(only.text, fileBody, 'T6-A1：先读回复的变异下这条变红');
  assert.equal(only.text.startsWith('摘要起点-'), true, 'T6-A2：正文必须来自文件');
  assert.ok(ctx.lines.includes('[digest] source=file chars=700'));
  assert.equal(ctx.lines.some((line) => line.startsWith('[digest] source=reply')), false);
});

test('T2 文件缺席就退回回复：本趟没写文件、回复 300 字照样能用', async (t) => {
  const reply = '群'.repeat(300);
  const ctx = setup(t, {
    promptSession: async (sessionId) => ({ sessionId: sessionId || 's-1', reused: true, reply }),
  });
  ctx.log.push(40);
  await ctx.summarizer.maybeSummarize('count');
  const only = ctx.store.list()[0];
  assert.equal(only.source, 'agent');
  assert.equal(only.text, reply);
  assert.ok(ctx.lines.includes('[digest] source=reply chars=300'));
  assert.equal(ctx.lines.some((line) => line.startsWith('[digest] source=file')), false);
});

test('T3 陈旧文件不得冒充新摘要：上一趟留下的 digest-out.txt + 空回复 → 确定性兜底', async (t) => {
  const stale = '上一趟的陈旧摘要-一个字都不许出现';
  const ctx = setup(t, {
    promptSession: async (sessionId) => ({ sessionId: sessionId || 's-1', reused: true, reply: '' }),
  });
  fs.writeFileSync(outPathOf(ctx.dir), stale, 'utf8');
  ctx.log.push(40);
  const out = await ctx.summarizer.maybeSummarize('count');
  assert.equal(out.ok, true);
  const only = ctx.store.list()[0];
  assert.equal(only.source, 'fallback', 'T6-B1：提示前不删文件的变异下这条变红');
  assert.equal(only.text.includes(stale), false, 'T6-B2：陈旧正文不许进摘要');
  assert.match(only.text, /^\[digest\] 40 条群消息（seq 1-40/);
  assert.equal(fs.existsSync(outPathOf(ctx.dir)), false, 'T6-B3：兜底之后也要删干净');
});

test('T4 handoff 文件读完就删：成功之后与失败之后 stateDir 都不留文件', async (t) => {
  let dir = '';
  const good = setup(t, {
    promptSession: async (sessionId) => {
      fs.writeFileSync(outPathOf(dir), '写完就该被删掉的摘要', 'utf8');
      return { sessionId: sessionId || 's-1', reused: true, reply: '' };
    },
  });
  dir = good.dir;
  good.log.push(40);
  await good.summarizer.maybeSummarize('count');
  assert.equal(good.store.list()[0].text, '写完就该被删掉的摘要');
  assert.equal(fs.existsSync(outPathOf(dir)), false, '成功路径：读完即删');

  let dir2 = '';
  const bad = setup(t, {
    promptSession: async () => {
      fs.writeFileSync(outPathOf(dir2), '失败前的半成品', 'utf8');
      throw new Error('model down');
    },
  });
  dir2 = bad.dir;
  bad.log.push(40);
  const out = await bad.summarizer.maybeSummarize('count');
  assert.equal(out.ok, true);
  assert.equal(bad.store.list()[0].source, 'fallback');
  assert.equal(fs.existsSync(outPathOf(dir2)), false, '失败路径：也不许留下 agent 写的文件');
});

test('T5 文件里塞 5000 字 + 控制字符 → 收到 DIGEST_TEXT_MAX、控制字符抹掉、回复不使用', async (t) => {
  let dir = '';
  const huge = '好\u0000\u0007\u001b[31m红字 ' + 'X'.repeat(5_000);
  const ctx = setup(t, {
    promptSession: async (sessionId) => {
      fs.writeFileSync(outPathOf(dir), huge, 'utf8');
      return { sessionId: sessionId || 's-1', reused: true, reply: '不该用到的回复' };
    },
  });
  dir = ctx.dir;
  ctx.log.push(40);
  await ctx.summarizer.maybeSummarize('count');
  const only = ctx.store.list()[0];
  assert.equal(only.source, 'agent');
  assert.ok(Array.from(only.text).length <= DIGEST_TEXT_MAX, '文件正文同样受 DIGEST_TEXT_MAX 约束');
  assert.equal(only.text.endsWith('…'), true, '超长要以省略号收尾');
  assert.equal(CONTROL.test(only.text), false, '控制字符一律抹掉');
  assert.equal(only.text.includes('不该用到的回复'), false, '有文件就不看回复');
});

test('T6 非空性：哪条断言会在「先读回复」/「提示前不删文件」两种变异下变红', async (t) => {
  // 变异 A = compose() 先读回复（只有回复为空才看文件）：
  //   T1 的 assert.equal(only.text, fileBody) 与 startsWith('摘要起点-') 立刻变红 ——
  //   120 字的预览会盖掉 700 字的文件。同样的形状在这里再钉一次优先级。
  let dir = '';
  const fileBody = '文件正本-' + 'A'.repeat(695);
  const ctx = setup(t, {
    promptSession: async (sessionId) => {
      fs.writeFileSync(outPathOf(dir), fileBody, 'utf8');
      return { sessionId: sessionId || 's-1', reused: true, reply: 'B'.repeat(119) + '…' };
    },
  });
  dir = ctx.dir;
  ctx.log.push(40);
  await ctx.summarizer.maybeSummarize('count');
  assert.equal(ctx.store.list()[0].text, fileBody, 'A1：文件永远赢过回复（= T1 的那条断言）');
  assert.equal(Array.from(ctx.store.list()[0].text).length, 700, 'A2：长度也是文件那份');

  // 变异 B = 去掉提示前的 unlink：
  //   T3 的 source==='fallback' 与 includes(stale)===false 变红（上一趟的正文会被当成本趟摘要）。
  //   这里把陈旧文件摆在同一位置、本趟什么都不写，确认它不被采纳。
  const stale = '陈旧摘要-请勿采纳';
  const guard = setup(t, {
    promptSession: async (sessionId) => ({ sessionId: sessionId || 's-1', reused: true, reply: '' }),
  });
  fs.writeFileSync(outPathOf(guard.dir), stale, 'utf8');
  guard.log.push(40);
  await guard.summarizer.maybeSummarize('count');
  const guarded = guard.store.list()[0];
  assert.equal(guarded.source, 'fallback', 'B1：提示前必须删文件（= T3 的那条断言）');
  assert.equal(guarded.text.includes(stale), false, 'B2：陈旧正文不许入摘要');
});

// ---------------------------------------------------------------------------
// N1-N5 兜底必须交代自己没列出的消息 / 摘要那一趟必须有 180 s
//
// 真机事故两件（2026-11-22 hub）：
//   ① 换成交接文件之后四次摘要**全** fallback reason=timeout、source=file 一次没执行过
//      —— 提示多了一趟工具往返，60 s 不够；
//   ② d-198-227 那 21 条消息只渲染出 seq 198-200，剩下 18 条无声消失（兜底正文 800 字硬帽）。
// ---------------------------------------------------------------------------

/** 省略标记（必须是最后一行）：`…（还有 N 条未列出，可在群里按 seq 查看）` */
const OMIT_MARK = /…（还有 (\d+) 条未列出，可在群里按 seq 查看）/;

/** 从产出的正文里数真正列出来的消息条数（省略标记那一行不算） */
const listedCount = (text) => text.split('\n').filter((line) => /^- seq=\d+ /.test(line)).length;

const batchOf = (count, filler) => Array.from({ length: count }, (_, index) => ({
  seq: index + 1,
  name: 'alice',
  text: filler(index + 1),
}));

test('N1 25 条消息：装下的条数比 800 字预算时更多，并带**精确**的省略标记（N 按正文算）', async () => {
  const batch = batchOf(25, (seq) => '第 ' + seq + ' 条：' + '进'.repeat(90));
  const text = fallbackDigestText(batch);
  const older = fallbackDigestText(batch, { chars: 800 });
  const listed = listedCount(text);
  const listedBefore = listedCount(older);

  assert.ok(listed > listedBefore,
    '更宽的预算必须装更多条：现在 ' + listed + ' 条，800 字时只有 ' + listedBefore + ' 条');
  const found = text.match(OMIT_MARK);
  assert.ok(found, 'N1：漏了消息却没有省略标记 —— 标记失踪时变红的就是这一条');
  assert.equal(Number(found[1]), 25 - listed, 'N 必须等于「25 减去实际列出的条数」（从正文算，不写死）');
  assert.equal(text.endsWith(found[0]), true, '省略标记必须是最后一行');
  assert.ok(Array.from(text).length <= DIGEST_TEXT_MAX, '标记算在清洗后的有界正文内');
  assert.match(text, /^\[digest\] 25 条群消息（seq 1-25/, '表头保持原样');

  // 每行原文按 ~120 字截断：一条长消息不再独自吃掉整个预算
  const clipped = fallbackDigestText([{ seq: 1, name: 'bob', text: 'x'.repeat(400) }]);
  const firstLine = clipped.split('\n')[1];
  assert.ok(Array.from(firstLine.slice(firstLine.indexOf(': ') + 2)).length <= DIGEST_FALLBACK_LINE_MAX,
    '单条原文一行最多 ' + DIGEST_FALLBACK_LINE_MAX + ' 字');
});

test('N2 小批次全部装得下：**没有**省略标记', async () => {
  const batch = batchOf(3, (seq) => '第 ' + seq + ' 条：短消息');
  const text = fallbackDigestText(batch);
  assert.equal(listedCount(text), 3, '三条都要列出来');
  assert.equal(OMIT_MARK.test(text), false, 'N2：全列出来了就一个标记都不许有');
  assert.equal(text.includes('未列出'), false);
  assert.equal(text.endsWith('）'), false, '末行是一条消息，不是标记');
});

/** 假时钟 + 假定时器：advance() 只让到期的守卫触发 —— 真机上等价于「跑过了多少秒」 */
function fakeClock() {
  const state = { t: 0, armed: [] };
  return {
    state,
    setTimeoutFn: (fn, ms) => {
      const handle = { at: state.t + ms, fn, done: false };
      state.armed.push(handle);
      return handle;
    },
    clearTimeoutFn: (handle) => { if (handle) handle.done = true; },
    advance(ms) {
      state.t += ms;
      for (const handle of state.armed) {
        if (!handle.done && handle.at <= state.t) {
          handle.done = true;
          handle.fn();
        }
      }
    },
  };
}

test('N3 预算 180 s：提示在假时钟走到 90 s（>60 s 且 <180 s）才回话 → 仍然 source=file', async (t) => {
  const clock = fakeClock();
  let dir = '';
  let release = () => {};
  const ctx = setup(t, {
    setTimeoutFn: clock.setTimeoutFn,
    clearTimeoutFn: clock.clearTimeoutFn,
    now: () => 1_700_000_000_000 + clock.state.t,
    promptSession: (sessionId) => new Promise((resolve) => {
      release = () => {
        fs.writeFileSync(outPathOf(dir), '九十秒才写完的摘要', 'utf8');
        resolve({ sessionId: sessionId || 's-1', reused: true, reply: 'DONE' });
      };
    }),
  });
  dir = ctx.dir;
  ctx.log.push(40);
  const turn = ctx.summarizer.maybeSummarize('count');
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(clock.state.armed.length, 1, '超时守卫必须真的被 arm 起来');
  assert.equal(clock.state.armed[0].at, 180_000, 'N3：预算退回 60 s 时这条先红（守卫会挂在 60_000）');
  clock.advance(90_000); // 真机上这就是「这一趟跑了 90 秒」
  release(); // 90 s 那一刻提示回话、交接文件写好
  const out = await turn;

  assert.equal(out.ok, true);
  const only = ctx.store.list()[0];
  assert.equal(only.source, 'agent', 'N3：预算仍是 60 s 时 90 s 这一趟已经超时 → 这里会是 fallback');
  assert.equal(only.text, '九十秒才写完的摘要', 'N3：超时变异下正文会变成兜底表头');
  assert.ok(ctx.lines.some((line) => line === '[digest] turn ms=90000 source=file'),
    'turn 日志要同时给出耗时与来源');
});

test('N4 超时失败也留一行 turn 日志：[digest] turn ms=<n> source=fallback（ms 是数字）', async (t) => {
  let clock = 1_700_000_000_000;
  const ctx = setup(t, {
    now: () => (clock += 5_000),
    promptSession: async () => {
      throw Object.assign(new Error('timeout'), { code: 'timeout' });
    },
  });
  ctx.log.push(40);
  const out = await ctx.summarizer.maybeSummarize('count');
  assert.equal(out.ok, true);
  assert.equal(ctx.store.list()[0].source, 'fallback');
  const line = ctx.lines.find((row) => /^\[digest\] turn ms=\d+ source=fallback$/.test(row));
  assert.ok(line, 'N4：失败那一趟也必须留下 turn ms=… source=fallback');
  const ms = Number(line.match(/ms=(\d+)/)[1]);
  assert.ok(Number.isFinite(ms) && ms > 0, 'ms 必须是真数字（不是 <n>、不是空）');
  assert.ok(ctx.lines.includes('[digest] fallback reason=timeout'), '失败原因照旧单独一行');
});

test('N5 非空性：标记失踪时红的是哪条断言；预算退回 60 s 时红的是哪条', async () => {
  // 变异 A = 兜底不再写省略标记（悄悄少给消息）：
  //   N1 的 assert.ok(found) 立刻红 —— 找不到「…（还有 N 条未列出…」；
  //   紧接着 assert.equal(Number(found[1]), 25 - listed) 也会红。
  //   也就是「N1 里的 found 断言」是钉住标记的那条。
  const batch = batchOf(25, (seq) => '第 ' + seq + ' 条：' + '进'.repeat(90));
  const text = fallbackDigestText(batch);
  assert.ok(25 - listedCount(text) > 0, 'A：这一批必须真的装不下（否则标记无从谈起）');
  assert.match(text, OMIT_MARK, 'A：有消息没列出就必须有标记');
  // 变异 A2 = 兜底预算回到 800：N1 的 listed > listedBefore 与
  //   assert.equal(DIGEST_FALLBACK_CHARS, DIGEST_TEXT_MAX) 会红。
  assert.equal(DIGEST_FALLBACK_CHARS, DIGEST_TEXT_MAX, 'A2：兜底预算必须等于 DIGEST_TEXT_MAX');

  // 变异 B = DIGEST_PROMPT_TIMEOUT_MS 退回 60_000：
  //   N3 的 assert.equal(clock.state.armed[0].at, 180_000) 先红；
  //   就算只把守卫留在 60 s，N3 的 assert.equal(only.source, 'agent') 也会红（90 s 已超时 → fallback）。
  assert.equal(DIGEST_PROMPT_TIMEOUT_MS, 180_000, 'B：摘要那一趟的预算必须是 180 s');
});

// ---------------------------------------------------------------------------
// Q 摘要会话模式：per-batch（默认，一趟新会话） vs reuse（造一次用到底）
// ---------------------------------------------------------------------------

test("Q1 per-batch 默认：两趟摘要都新建会话（见 ['', '']），盘上不落会话文件", async (t) => {
  const seen = [];
  const prompt = async (sessionId) => {
    seen.push(sessionId);
    return { sessionId: 's-' + seen.length, reused: sessionId !== '', reply: '第 ' + seen.length + ' 批摘要。' };
  };
  const { store, log, summarizer, dir } = setup(t, { promptSession: prompt });
  log.push(40);
  assert.equal((await summarizer.maybeSummarize('count')).ok, true);
  log.push(40);
  assert.equal((await summarizer.maybeSummarize('count')).ok, true);
  assert.equal(store.count(), 2, '两批各自成一条摘要，谁也没丢');
  assert.deepEqual(seen, ['', ''], 'per-batch：第二趟也**不许**带 sessionId —— 这就是「不再复用」本身');
  assert.equal(summarizer.sessionId, '', 'per-batch 连内存里都不记会话');
  assert.equal(fs.existsSync(path.join(dir, DIGEST_SESSION_FILE)), false, 'per-batch 一个字节都不落会话文件');
  assert.equal(summarizer.state().sessionMode, 'per-batch');
});

test("Q2 sessionMode:'reuse'：第二趟带着第一趟返回的 sessionId（见 ['', 'session-x']）", async (t) => {
  const seen = [];
  const prompt = async (sessionId) => {
    seen.push(sessionId);
    return { sessionId: 'session-x', reused: sessionId !== '', reply: '摘要' };
  };
  const { store, log, summarizer, dir } = setup(t, { promptSession: prompt, sessionMode: 'reuse' });
  log.push(40);
  await summarizer.maybeSummarize('count');
  log.push(40);
  await summarizer.maybeSummarize('count');
  assert.equal(store.count(), 2);
  assert.deepEqual(seen, ['', 'session-x'], 'reuse：第二趟必须复用第一趟的会话');
  assert.equal(summarizer.sessionId, 'session-x');
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(dir, DIGEST_SESSION_FILE), 'utf8')), {
    sessionId: 'session-x',
  }, 'reuse 照旧落盘（回退这条路必须还能走）');
});

test('Q3 陈旧 group-digest-session.json：per-batch 照样空 sessionId，session-file-ignored 只记一次', async (t) => {
  const seen = [];
  const prompt = async (sessionId) => {
    seen.push(sessionId);
    return { sessionId: 's-fresh-' + seen.length, reused: sessionId !== '', reply: '摘要' };
  };
  const { log, summarizer, dir, lines } = setup(t, { promptSession: prompt, staleSession: 'session-stale' });
  const ignored = () => lines.filter((line) => line === '[digest] session-file-ignored').length;
  assert.equal(fs.existsSync(path.join(dir, DIGEST_SESSION_FILE)), false, '构造时就删掉陈旧文件');
  assert.equal(ignored(), 1, '恰好一行，不是每趟一行');
  log.push(40);
  await summarizer.maybeSummarize('count');
  log.push(40);
  await summarizer.maybeSummarize('count');
  assert.deepEqual(seen, ['', ''], '盘上有那份文件也**不许**带 id：硬忽略');
  assert.equal(ignored(), 1, '摘要跑完也不再多记');
  assert.equal(fs.existsSync(path.join(dir, DIGEST_SESSION_FILE)), false, '跑完也不许把它重建回来');
});

test('Q4 每趟摘要一行 session mode=：两种模式各两趟、值各自正确', async (t) => {
  const prompt = async (sessionId) => ({ sessionId: 's-1', reused: sessionId !== '', reply: '摘要' });
  const modeLines = async (ctx) => {
    ctx.log.push(40);
    await ctx.summarizer.maybeSummarize('count');
    ctx.log.push(40);
    await ctx.summarizer.maybeSummarize('count');
    return ctx.lines.filter((line) => line.startsWith('[digest] session mode='));
  };
  assert.deepEqual(await modeLines(setup(t, { promptSession: prompt })), [
    '[digest] session mode=per-batch',
    '[digest] session mode=per-batch',
  ], '默认模式：一趟一行、值必须是 per-batch');
  assert.deepEqual(await modeLines(setup(t, { promptSession: prompt, sessionMode: 'reuse' })), [
    '[digest] session mode=reuse',
    '[digest] session mode=reuse',
  ], 'reuse 模式同样一趟一行、值必须是 reuse');
});

test('Q5 非空性：模式退回 reuse 时红的是 Q1 的 seen 断言；陈旧文件被认时红的是 Q3 的两条', async (t) => {
  // 同一个探针，两种模式必须给出**不同**的 seen —— 否则 Q1/Q2 的断言是空转。
  const perBatchSeen = [];
  const perBatch = setup(t, {
    promptSession: async (sessionId) => {
      perBatchSeen.push(sessionId);
      return { sessionId: 's-pb', reused: sessionId !== '', reply: '摘要' };
    },
  });
  perBatch.log.push(40);
  await perBatch.summarizer.maybeSummarize('count');
  perBatch.log.push(40);
  await perBatch.summarizer.maybeSummarize('count');

  const reuseSeen = [];
  const reuse = setup(t, {
    sessionMode: 'reuse',
    promptSession: async (sessionId) => {
      reuseSeen.push(sessionId);
      return { sessionId: 's-ru', reused: sessionId !== '', reply: '摘要' };
    },
  });
  reuse.log.push(40);
  await reuse.summarizer.maybeSummarize('count');
  reuse.log.push(40);
  await reuse.summarizer.maybeSummarize('count');

  // 变异 A（默认换成 reuse）：Q1 的 deepEqual(seen, ['', '']) 立刻红 ⇒ 它就是钉「per-batch」的那条。
  assert.deepEqual(perBatchSeen, ['', ''], 'A：per-batch 两趟都空');
  assert.deepEqual(reuseSeen, ['', 's-ru'], 'A：reuse 第二趟必带 id');
  assert.notDeepEqual(perBatchSeen, reuseSeen, 'A：两种模式必须可分辨（Q1 的断言因此不空转）');
  // 变异 B（陈旧文件被认作会话，即构造时读它并带上 id）：Q3 的 deepEqual(seen, ['', '']) 与
  //   existsSync(...) === false 会红 ⇒ 前者钉「硬忽略」，后者钉「构造时删掉」。
  assert.equal(
    fs.existsSync(path.join(perBatch.dir, DIGEST_SESSION_FILE)),
    false,
    'B：per-batch 的 stateDir 里不许有会话文件（Q3 的 existsSync 断言就是这条）',
  );
});

// ---------------------------------------------------------------------------
// C1-C6 兜底切块：一块装不下整批就写**多条**摘要，一条消息都不许丢
//
// 真机事故（hub 当晚）：模型那一趟从来完不成，兜底是唯一输出，而一块正文（1500 字）
// 在 120 字/行时只装得下 11~14 条 —— d-266-291 有 14 条、d-292-311 有 9 条只剩
// 一枚「还有 N 条未列出」的标记，内容真的没了，成员也没法按 seq 翻回原文。
// 修法两条：行宽收到 48（一块装得下 3~4 倍）+ 一块装不下就按 seq 切块，每条各自成摘要。
// ---------------------------------------------------------------------------

/** 正文里列出来的 seq（按出现顺序；行内截断那条也算已列出） */
const seqsOf = (text) => String(text)
  .split('\n')
  .map((line) => /^- seq=(\d+) /.exec(line))
  .filter(Boolean)
  .map((found) => Number(found[1]));

/** 一行里「: 」之后那一截正文 */
const bodyOf = (line) => line.slice(line.indexOf(': ') + 2);

const rangeOf = (count) => Array.from({ length: count }, (_, index) => index + 1);

/** 一定走兜底那一趟（真机上模型永远完不成，这就是生产现状） */
const deadSession = async () => {
  throw new Error('model saturated by its own participant');
};

test('C1 · 40 条装不进一块 → 多条摘要，列出的 seq 集合与批次**完全相等**（不多不少）', async (t) => {
  const { store, log, summarizer, lines } = setup(t, { promptSession: deadSession });
  log.push(40, (seq) => '第 ' + seq + ' 条：' + '进'.repeat(60));
  const out = await summarizer.maybeSummarize('count');
  assert.equal(out.ok, true);

  const entries = store.list();
  assert.ok(entries.length > 1, 'C1：退回单块时这条先红（40 条一块装不下）');
  assert.equal(out.digests.length, entries.length, '返回的清单 = 这一批写下的全部条目');

  const listed = entries.flatMap((entry) => seqsOf(entry.text));
  assert.deepEqual([...new Set(listed)].sort((left, right) => left - right), rangeOf(40),
    'C1：漏一条或多一条这里就红 —— 覆盖必须与批次 seq 集合**集合相等**');
  assert.equal(listed.length, new Set(listed).size, 'C1：同一个 seq 不许在两块里各出现一次');
  assert.equal(listed.length, 40);

  // 块与块首尾相接：无空洞、无重叠
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    const own = seqsOf(entry.text);
    assert.equal(entry.fromSeq, own[0], 'fromSeq 必须等于这一块列出的第一条');
    assert.equal(entry.toSeq, own[own.length - 1], 'toSeq 必须等于这一块列出的最后一条');
    if (index > 0) assert.equal(entry.fromSeq, entries[index - 1].toSeq + 1, 'C1：块必须首尾相接');
  }
  assert.equal(entries[0].fromSeq, 1);
  assert.equal(entries[entries.length - 1].toSeq, 40);

  for (const entry of entries) {
    assert.equal(entry.source, 'fallback');
    assert.equal(entry.text.includes('未列出'), false, 'C1：新的兜底里没有省略标记');
    assert.ok(Array.from(entry.text).length <= DIGEST_TEXT_MAX, 'C1：每一块都必须 ≤ DIGEST_TEXT_MAX');
    for (const line of entry.text.split('\n').filter((row) => row.startsWith('- seq='))) {
      assert.ok(Array.from(bodyOf(line)).length <= DIGEST_FALLBACK_LINE_MAX,
        'C1：每行正文 ≤ ' + DIGEST_FALLBACK_LINE_MAX + ' 字（行宽退回 120 时这条先红）');
    }
  }
  assert.ok(lines.some((line) => line === '[digest] chunked n=' + entries.length + ' cover=1-40'),
    'C1：切块要留一行日志（n 与覆盖区间）');
});

test('C2 · 5 条小批次 → 恰好一条摘要、无标记、5 条全列出', async (t) => {
  const { store, log, summarizer } = setup(t, { promptSession: deadSession });
  log.push(5, (seq) => '第 ' + seq + ' 条：短消息');
  const out = await summarizer.maybeSummarize('timer');
  assert.equal(out.ok, true);
  assert.equal(out.digests.length, 1, 'C2：装得下就只写一条，不许拆');
  assert.equal(store.count(), 1);
  const only = store.list()[0];
  assert.equal(only.fromSeq, 1);
  assert.equal(only.toSeq, 5);
  assert.deepEqual(seqsOf(only.text), [1, 2, 3, 4, 5]);
  assert.equal(OMIT_MARK.test(only.text), false, 'C2：全列出来了就没有省略标记');
  assert.equal(only.text.includes('未列出'), false);
  assert.equal(only.text.includes(DIGEST_TRUNC_NOTE), false, 'C2：短消息不该带任何截断备注');
});

test('C3 · 盘上已经满 20 条（DIGEST_KEEP）也不许把当前这批挤掉：从盘上读回来每块都在', async (t) => {
  const dir = tempDir(t);
  const log = fakeLog();
  log.push(60, (seq) => '第 ' + seq + ' 条：' + '进'.repeat(50));
  const store = new GroupDigestStore({ stateDir: dir, hubId: 'peer-hub', now: () => 1_000 });
  for (let index = 1; index <= DIGEST_KEEP; index += 1) {
    const older = store.append({
      fromSeq: index, toSeq: index, at: 1, source: 'agent', text: '旧摘要 ' + index,
    });
    assert.equal(older.ok, true);
  }
  assert.equal(store.count(), DIGEST_KEEP, '前提：盘上已经有 20 条以前的摘要');
  const summarizer = createHubSummarizer({
    isHub: true,
    store,
    messages: (fromSeq) => log.read(fromSeq),
    promptSession: deadSession,
    stateDir: dir,
    now: () => 1_700_000_000_000,
  });
  t.after(() => summarizer.close());

  const out = await summarizer.maybeSummarize('timer');
  assert.equal(out.ok, true);
  const current = out.digests.map((entry) => entry.digestId);
  assert.ok(current.length > 1, 'C3：这一批必须真的切成多块（否则这条用例空转）');

  // 不信返回值：重新从盘上读一份权威
  const reloaded = new GroupDigestStore({ stateDir: dir, hubId: 'peer-hub', now: () => 1 });
  const ids = reloaded.list().map((entry) => entry.digestId);
  for (const id of current) {
    assert.ok(ids.includes(id), 'C3：上限只对以前的批次生效 —— 按 20 硬裁就会把这一批的头几块挤掉');
  }
  assert.ok(fileOf(dir).digests.length >= current.length, '盘上也得留得住这一整批');
  const covered = reloaded.list()
    .filter((entry) => current.includes(entry.digestId))
    .flatMap((entry) => seqsOf(entry.text));
  assert.deepEqual([...new Set(covered)].sort((left, right) => left - right), rangeOf(40).map((n) => n + 20),
    'C3：读回来的这一批仍然覆盖 21-60 的每一条');
  assert.equal(covered.length, 40);
  assert.equal(reloaded.rev, 60, 'rev 照旧前进到最后一条');
});

test('C4 · 单条 5000 字：那一行按剩余预算截断并注明「本条已截断」，别的消息不受影响', async (t) => {
  const big = 7;
  const { store, log, summarizer } = setup(t, { promptSession: deadSession });
  log.push(10, (seq) => (seq === big ? '长文：' + 'X'.repeat(5_000) : '第 ' + seq + ' 条：短消息'));
  const out = await summarizer.maybeSummarize('timer');
  assert.equal(out.ok, true);
  const entries = store.list();
  const holder = entries.filter((entry) => seqsOf(entry.text).includes(big));
  assert.equal(holder.length, 1, '这一条只出现在一块里');
  const line = holder[0].text.split('\n').find((row) => row.startsWith('- seq=' + big + ' '));
  assert.equal(line.endsWith(DIGEST_TRUNC_NOTE), true,
    'C4：独自塞不进一整块时按剩余预算截断并**行内**注明');
  assert.ok(Array.from(holder[0].text).length <= DIGEST_TEXT_MAX);
  assert.equal(holder[0].text.includes('未列出'), false, 'C4：截断不是省略，标记不许出现');
  assert.ok(Array.from(bodyOf(line)).length > DIGEST_FALLBACK_LINE_MAX,
    'C4：被截断的那条按剩余预算铺开，比 48 字的一行给得多');

  for (const entry of entries) {
    if (entry === holder[0]) continue;
    assert.equal(entry.text.includes(DIGEST_TRUNC_NOTE), false, 'C4：别的消息一个都不许被截断');
  }
  const all = entries.flatMap((entry) => seqsOf(entry.text));
  assert.deepEqual([...new Set(all)].sort((left, right) => left - right), rangeOf(10));
  assert.equal(all.length, 10, 'C4：截断那一条照样算已列出，谁也不重复');
});

test('C5 · 多块输出里**没有**省略标记：没有任何一条消息「未列出」', async (t) => {
  const { store, log, summarizer } = setup(t, { promptSession: deadSession });
  log.push(40, (seq) => '第 ' + seq + ' 条：' + '进'.repeat(60));
  await summarizer.maybeSummarize('count');
  const entries = store.list();
  assert.ok(entries.length > 1, 'C5：前提是多块（否则这条用例空转）');
  for (const entry of entries) {
    assert.equal(OMIT_MARK.test(entry.text), false, 'C5：切块之后没有任何一条需要省略标记');
    assert.equal(entry.text.includes('未列出'), false);
    assert.equal(entry.text.includes('省略'), false);
  }
});

test('C6 · 非空性：删掉切块 / 行宽退回 120 时，红的是 C1 的哪几条断言', async () => {
  const batch = batchOf(40, (seq) => '第 ' + seq + ' 条：' + '进'.repeat(60));

  // 变异 A = 退回「一块装下整批」（compose 用单块渲染）：
  //   C1 的 assert.ok(entries.length > 1) 与 seq 集合相等先红 —— 单块只列出这一小部分，
  //   还留一枚省略标记（而 C5 要求新输出里没有它）。
  const single = fallbackDigestText(batch);
  const singleSeqs = seqsOf(single);
  assert.ok(singleSeqs.length < 40, 'A：单块确实装不下 40 条（非空性的前提）');
  assert.match(single, OMIT_MARK, 'A：单块只能留省略标记 —— C1 的集合相等因此会红');
  assert.ok(splitFallbackChunks(batch).length > 1,
    'A：切成多块才覆盖得住（C1 的 entries.length > 1 就是这条）');

  // 变异 B = 行宽退回 120：一块装得下的条数变少（块数变多），C1 里
  //   「每行正文 ≤ DIGEST_FALLBACK_LINE_MAX」与下面这两条对比会红。
  const wide = splitFallbackChunks(batch, { lineMax: 120 });
  const narrow = splitFallbackChunks(batch);
  assert.ok(wide.length > narrow.length, 'B：120 字/行时块数必须更多（48 才装得下更多条）');
  assert.equal(DIGEST_FALLBACK_LINE_MAX, 48, 'B：行宽退回 120 时这条先红');
  assert.ok(seqsOf(fallbackDigestText(batch, { lineMax: 120 })).length < singleSeqs.length,
    'B：120 字/行时一块装下的条数更少（48 与 120 的顺序）');
  assert.equal(
    Array.from(bodyOf(fallbackDigestText(batch).split('\n')[1])).length <= DIGEST_FALLBACK_LINE_MAX,
    true,
    'B：新行宽下一行正文 ≤ 48 字（C1 的逐行断言就是这条）',
  );
  // 切块的渲染与切块本身必须同一口径：每块渲染后都 ≤ 预算（否则 sanitize 会替我们吞掉正文）
  for (const chunk of splitFallbackChunks(batch)) {
    assert.ok(Array.from(fallbackChunkText(chunk)).length <= DIGEST_TEXT_MAX);
  }
});

// ---------------------------------------------------------------------------
// U1-U5 决定 A：摘要不再叫模型（modelSummary=false 是生产默认）
//
// 真机（当晚）：hub 的摘要会话被自家参与者占着同一个 agent —— 一次唤醒 ~45 s、回话又长，
// 每一趟都烧满预算（turn ms≈175000 source=fallback），那 175 s 里还跟参与者抢同一个 agent。
// 而确定性那一趟现在**按构造就是全的**（80/80 条、0 重复、0 空洞），所以模型那条路纯属浪费。
// 开关留着（modelSummary=true 一切照旧），但默认关。
// ---------------------------------------------------------------------------

const DETERMINISTIC = /^\[digest\] deterministic chunks=(\d+) cover=(\d+)-(\d+)$/;

test('U1 modelSummary=false（默认）：零次 promptSession、无 turn/fallback 日志、只留一行 deterministic', async (t) => {
  let calls = 0;
  const { store, log, summarizer, lines } = setup(t, {
    modelSummary: false,
    promptSession: async () => {
      calls += 1;
      return { sessionId: 's-1', reused: false, reply: '模型摘要（不该出现）' };
    },
  });
  log.push(40, (seq) => '第 ' + seq + ' 条：' + '进'.repeat(60));
  const out = await summarizer.maybeSummarize('count');
  assert.equal(out.ok, true);

  assert.equal(calls, 0, 'U1/M2：off 态只要叫过一次 promptSession，这条先红');
  const entries = store.list();
  assert.equal(entries.length, 2, 'U1：这一批正好两块（40 条装不进一块）');
  assert.equal(entries[0].fromSeq, 1);
  assert.equal(entries[1].toSeq, 40);
  assert.equal(entries[1].fromSeq, entries[0].toSeq + 1, 'U1：块与块首尾相接（无空洞、无重叠）');
  assert.equal(out.digests.length, 2, '返回清单 = 这一批写下的全部条目');

  assert.equal(lines.some((line) => line.includes('turn ms=')), false, 'U1：没有 turn 就不许有 turn ms=');
  assert.equal(lines.some((line) => line.includes('fallback reason=')), false, 'U1：没有失败就没有 fallback reason=');
  const deterministic = lines.filter((line) => line.startsWith('[digest] deterministic '));
  assert.deepEqual(deterministic, ['[digest] deterministic chunks=2 cover=1-40'],
    'U1/M3：确定性日志缺失（或一批写了不止一行）这里先红');
  assert.equal(DETERMINISTIC.test(deterministic[0]), true, 'U1：日志形状 chunks=<n> cover=<from>-<to>');

  for (const entry of entries) {
    assert.equal(entry.source, 'fallback');
    assert.equal(entry.text.includes('未列出'), false, 'U1：off 态也一条不漏');
  }
  const listed = entries.flatMap((entry) => seqsOf(entry.text));
  assert.deepEqual(listed, rangeOf(40), 'U1：覆盖仍是 1..40、无重复');
});

test('U2 modelSummary=true：与今天逐字节一致（一次会话、读 handoff 文件、turn ms= 与 source=file）', async (t) => {
  const seen = [];
  let dirRef = '';
  const ctx = setup(t, {
    modelSummary: true,
    promptSession: async (sessionId, prompt) => {
      seen.push({ sessionId, prompt });
      fs.writeFileSync(path.join(dirRef, DIGEST_OUT_FILE), '文件摘要：周四上线。');
      return { sessionId: 's-1', reused: false, reply: 'DONE' };
    },
  });
  dirRef = ctx.dir;
  ctx.log.push(40, (seq) => '第 ' + seq + ' 条：进度同步');

  const out = await ctx.summarizer.maybeSummarize('count');
  assert.equal(out.ok, true);
  assert.equal(seen.length, 1, 'U2：一趟就是一次提问');
  assert.equal(seen[0].sessionId, '', 'U2：per-batch 下提示不带 sessionId');
  assert.ok(seen[0].prompt.includes('seq=1 '), 'U2：提示里仍有群消息正文');
  assert.ok(seen[0].prompt.includes('路径：'), 'U2：提示里仍给 handoff 文件路径');

  const only = ctx.store.list()[0];
  assert.equal(ctx.store.list().length, 1, 'U2：模型那一趟永远一块');
  assert.equal(only.source, 'agent');
  assert.equal(only.fromSeq, 1);
  assert.equal(only.toSeq, 40);
  assert.equal(only.text, '文件摘要：周四上线。', 'U2：文件优先、回复只当 DONE');

  assert.ok(ctx.lines.includes('[digest] session mode=per-batch'), 'U2：模式行照旧');
  assert.equal(ctx.lines.some((line) => /^\[digest\] source=file chars=\d+$/.test(line)), true,
    'U2：source=file 行照旧');
  assert.equal(ctx.lines.some((line) => /^\[digest\] turn ms=\d+ source=file$/.test(line)), true,
    'U2：turn ms= 行照旧（开着才有 turn）');
  assert.equal(ctx.lines.some((line) => line.startsWith('[digest] deterministic ')), false,
    'U2：开着模型时不写 deterministic 行');
  assert.equal(fs.existsSync(outPathOf(ctx.dir)), false, 'U2：handoff 文件读完就删');
});

test('U3 默认解析：默认关、只有字面量 true 才开（摘要器与插件配置同一条规则）', (t) => {
  assert.equal(createHubSummarizer({}).state().modelSummary, false, 'U3：默认必须是关');
  assert.equal(createHubSummarizer({ isHub: true }).state().modelSummary, false);
  assert.equal(createHubSummarizer({ modelSummary: 'true' }).state().modelSummary, false,
    "U3：字符串 'true' 不许被当成开");
  assert.equal(createHubSummarizer({ modelSummary: 1 }).state().modelSummary, false);
  assert.equal(createHubSummarizer({ modelSummary: true }).state().modelSummary, true);
  assert.equal(resolveModelSummary(undefined), false);

  const dir = tempDir(t);
  assert.equal(resolveConfig({ stateDir: dir }).digestModel, false, 'U3：config.digestModel 缺省 = 关');
  assert.equal(resolveConfig({ stateDir: dir, digestModel: true }).digestModel, true);
  assert.equal(resolveConfig({ stateDir: dir, digestModel: 'true' }).digestModel, false,
    'U3：配置写成字符串不许悄悄打开模型');
});

test('U4 开关不影响覆盖：同一批 40 条，off 与 on（模型必失败）两边 seq 集合相等', async (t) => {
  const filler = (seq) => '第 ' + seq + ' 条：' + '进'.repeat(60);
  const off = setup(t, { modelSummary: false });
  off.log.push(40, filler);
  assert.equal((await off.summarizer.maybeSummarize('count')).ok, true);

  const on = setup(t, { modelSummary: true, promptSession: deadSession });
  on.log.push(40, filler);
  assert.equal((await on.summarizer.maybeSummarize('count')).ok, true);

  const entriesOff = off.store.list();
  const seqsOff = entriesOff.flatMap((entry) => seqsOf(entry.text));
  const seqsOn = on.store.list().flatMap((entry) => seqsOf(entry.text));
  assert.ok(entriesOff.length > 1, 'U4 前提：这一批确实不止一块（单块下集合相等是白给的）');
  assert.deepEqual([...new Set(seqsOff)].sort((left, right) => left - right),
    [...new Set(seqsOn)].sort((left, right) => left - right),
    'U4：关掉模型不许悄悄缩小覆盖（集合相等）');
  assert.deepEqual(seqsOff, seqsOn, 'U4：连列出顺序都一致');
  assert.deepEqual(entriesOff.map((entry) => [entry.fromSeq, entry.toSeq]),
    on.store.list().map((entry) => [entry.fromSeq, entry.toSeq]), 'U4：块边界也一致');
});

test('U5 非空性：off 态还叫模型 → U1 的 calls 断言先红；确定性日志没写 → U1 的 deepEqual 先红', async (t) => {
  const counter = { calls: 0 };
  const session = async (sessionId) => {
    counter.calls += 1;
    return { sessionId: sessionId || 's-1', reused: false, reply: '模型摘要' };
  };
  const filler = (seq) => '第 ' + seq + ' 条：' + '进'.repeat(60);

  // 变异 A（开关被忽略、off 态照旧叫模型）：U1 的 assert.equal(calls, 0) 立刻红；
  //   模型一成功就走 agentChunks（单块）→ U1 的 entries.length===2 与 deterministic 行也连带红。
  const off = setup(t, { modelSummary: false, promptSession: session });
  off.log.push(40, filler);
  await off.summarizer.maybeSummarize('count');
  const detOff = off.lines.filter((line) => line.startsWith('[digest] deterministic '));
  assert.equal(counter.calls, 0, 'A：off 态零次模型调用（U1 的 calls===0 就是这条）');
  assert.equal(off.store.list().length, 2, 'A：off 态两块（U1 的 entries.length 就是这条）');
  assert.equal(detOff.length, 1, 'B：确定性日志恰好一行（U1 的 deepEqual 就是这条）');

  // 对照：同一份注入、同一批消息，只翻开关 —— 所以 U1 的两条断言不是空转
  counter.calls = 0;
  const on = setup(t, { modelSummary: true, promptSession: session });
  on.log.push(40, filler);
  await on.summarizer.maybeSummarize('count');
  assert.equal(counter.calls, 1, '对照：开着就**一定**叫一次（calls===0 会因此变红）');
  assert.equal(on.store.list().length, 1, '对照：开着就是单块');
  assert.equal(on.lines.some((line) => line.startsWith('[digest] deterministic ')), false,
    '对照：开着不写 deterministic 行（deepEqual 因此会变红）');
});


