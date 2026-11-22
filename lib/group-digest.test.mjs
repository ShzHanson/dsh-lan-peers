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
  DIGEST_TEXT_MAX,
  DIGEST_TRIGGER_MS,
  GroupDigestStore,
  createHubSummarizer,
  createSessionPrompt,
  fallbackDigestText,
} from './group-digest.mjs';

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

function setup(t, { isHub = true, promptSession = null, ...rest } = {}) {
  const dir = tempDir(t);
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
  const { store, log, summarizer, dir } = setup(t, { promptSession: prompt });
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

