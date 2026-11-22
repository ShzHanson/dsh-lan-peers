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
  DIGEST_KEEP,
  DIGEST_PLANE_LIMIT,
  DIGEST_TEXT_MAX,
  DIGEST_TRIGGER_MS,
  GroupDigestStore,
  createHubSummarizer,
  createSessionPrompt,
} from './group-digest.mjs';

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
