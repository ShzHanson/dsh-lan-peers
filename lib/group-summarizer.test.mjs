// dsh-lan-peers · 0.13.0-alpha（决定 C）远端摘要器：S1-S7
//
// 用户的硬要求是「那台机器突然下线，摘要仍必须准时产出」，所以这一组用例的重心
// 不是"模型摘要好不好"，而是"远端那一趟失败时，确定性摘要**逐字节**还是今天那份"。
//
// 全部零网络、零真模型：通道(call/verify)与时钟都注入，没有一个用例真的等 30 分钟。
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { DIGEST_OUT_FILE, DIGEST_TEXT_MAX, GroupDigestStore, createHubSummarizer } from './group-digest.mjs';
import { normalizeGroupConfig } from './group-client.mjs';
import {
  DIGEST_SUMMARY_PATH,
  SUMMARY_BUDGET_MS,
  SUMMARY_HANDLER_BUDGET_MS,
  SUMMARY_COOLDOWN_MS,
  SUMMARY_COOLDOWN_WINDOWS,
  createRemoteSummaryDispatcher,
  createRemoteSummaryHandler,
  resolveSummaryPeer,
  signSummaryReply,
  verifySummaryReply,
} from './group-summarizer.mjs';

const CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/;
/** 被指定的那一位（hub 的 peers.json 里 peerId = DESIGNATED，名字 = NAME） */
const DESIGNATED = 'peer-desk-1';
const DESIGNATED_NAME = 'desk-alpha';
const SECRET = 'sec-designated';
/** 同一本 peers.json 里的另一台：它的密钥签的东西一律不认 */
const FOREIGN = 'peer-other-2';
const SKIP_OFFLINE = '[digest] summary skipped reason=offline';

function tempDir(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-summary-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

/** 假权威日志：seq 从 1 起，push(n) 追 n 条 */
function fakeLog() {
  const rows = [];
  return {
    rows,
    push(count, name = 'alice') {
      for (let index = 0; index < count; index += 1) {
        const seq = rows.length + 1;
        rows.push({ seq, from: { peerId: 'peer-a', name }, text: '第 ' + seq + ' 条消息' });
      }
      return rows.length;
    },
    read(fromSeq) {
      return rows.filter((row) => row.seq > Number(fromSeq || 0));
    },
  };
}

/** 可推进的假时钟：用例自己决定"过了多久" */
function fakeClock(start = 1_700_000_000_000) {
  let value = start;
  return {
    now: () => value,
    advance(ms) {
      value += ms;
      return value;
    },
  };
}

const PEERS = [
  { peerId: DESIGNATED, name: DESIGNATED_NAME, baseUrl: 'http://127.0.0.1:1' },
  { peerId: FOREIGN, name: 'other-beta', baseUrl: 'http://127.0.0.1:2' },
];

/** 确定性那一趟（modelSummary:false）+ 可选的远端派发器 */
function setup(t, { remote = null } = {}) {
  const dir = tempDir(t);
  const log = fakeLog();
  const lines = [];
  const store = new GroupDigestStore({
    stateDir: dir,
    hubId: 'peer-hub',
    now: () => 1_000,
    logger: (line) => lines.push(line),
  });
  const summarizer = createHubSummarizer({
    isHub: true,
    store,
    messages: (fromSeq) => log.read(fromSeq),
    modelSummary: false,
    stateDir: dir,
    now: () => 1_700_000_000_000,
    log: (line) => lines.push(line),
    remoteSummary: remote,
  });
  t.after(() => summarizer.close());
  return { dir, store, log, summarizer, lines };
}

/**
 * 决定 D（0.13.0-alpha）之后的用例纪律：远端那一趟**不再被 await**（fire-and-forget），
 * 所以"它落地了没有"必须由用例显式等 —— 等一个条件成立，绝不靠固定 sleep。
 */
async function waitFor(check, { timeoutMs = 2_000, intervalMs = 5 } = {}) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = await check();
    if (value) return value;
    if (Date.now() >= deadline) return value;
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
}

/** 等派发器把在飞的几趟全部结算（冷却/日志断言都必须落在这个点之后） */
const settleDispatches = (dispatcher) => waitFor(() => dispatcher.state().inFlight === 0);

/** hub 侧验签用的对端记录：inboundSecret 就是那一位的密钥（§4 的顺序） */
const peerRecord = () => ({ peerId: DESIGNATED, inboundSecret: SECRET, secret: 'sec-hub-self' });

/** 一条"合法"的回复：由被指定那一位用自己的密钥签 */
const signedBy = (job, text, clock, { secret = SECRET, by = DESIGNATED } = {}) => (
  signSummaryReply({ secret, by, job, text, now: clock.now })
);

const onlineDispatcher = (clock, logs, { calls = null, text = '群里定了两件事。', signWith = null } = {}) => (
  createRemoteSummaryDispatcher({
    configured: true,
    peerId: DESIGNATED,
    groupId: () => 'group-1',
    call: async (job) => {
      if (calls) calls.push(job);
      return (signWith ?? ((made) => signedBy(made, text, clock)))(job);
    },
    verify: (reply, job) => verifySummaryReply({ peer: peerRecord(), reply, job, now: clock.now }),
    now: clock.now,
    log: (line) => logs.push(line),
  })
);

// ---------------------------------------------------------------------------
// S1 离线（用户的硬要求）
// ---------------------------------------------------------------------------

test('S1 配了但打不通：确定性摘要逐字节一致、有界、恰好一行 skipped reason=offline', async (t) => {
  // 基线：**没配**远端摘要器
  const baseline = setup(t);
  baseline.log.push(40);
  const baselineOut = await baseline.summarizer.maybeSummarize('count');
  assert.equal(baselineOut.ok, true);
  const expected = JSON.stringify(baseline.store.list());
  assert.equal(baseline.lines.some((line) => line.includes('summary skipped')), false,
    '没配 = 一行 skip 都不该有（与 S6 同一把尺子）');

  const clock = fakeClock();
  const logs = [];
  let dispatches = 0;
  const offline = createRemoteSummaryDispatcher({
    configured: true,
    peerId: DESIGNATED,
    groupId: () => 'group-1',
    call: async () => {
      dispatches += 1;
      throw Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:1'), { code: 'ECONNREFUSED' });
    },
    verify: () => ({ ok: false, error: 'never-called' }),
    now: clock.now,
    log: (line) => logs.push(line),
  });

  const run = setup(t, { remote: offline });
  run.log.push(40);
  const startedAt = Date.now();
  const out = await run.summarizer.maybeSummarize('count');
  const elapsedMs = Date.now() - startedAt;
  // 决定 D：远端那一趟不再被 await —— 显式等它失败结算，再断言"失败也只留一行、不进盘"
  await settleDispatches(offline);

  assert.equal(out.ok, true, '窗口本身必须成功');
  assert.equal(out.remote, null, '返回那一刻远端还没有结果（唯一诚实的值）');
  assert.equal(run.store.list().some((entry) => entry.source === 'agent-remote'), false,
    '离线时不许有远端条目');
  assert.equal(JSON.stringify(run.store.list()), expected, '离线时摘要与"没配"逐字节一致');
  assert.equal(run.store.count(), baseline.store.count());
  assert.equal(dispatches, 1, '一个窗口只探一次');
  assert.equal(elapsedMs <= 800, true, '离线这一趟必须立刻回来（实测 ' + elapsedMs + 'ms）');
  assert.equal(offline.state().inFlight, 0, '结算完就没有在飞的了');
  // 注入的预算就是上界：派发器自己不会等超过 SUMMARY_BUDGET_MS
  assert.equal(offline.state().budgetMs, SUMMARY_BUDGET_MS);
  // 早先这里断言"一两秒"，等于把 bug 当规格：hub 只等 2 秒，而接收侧预算比它大得多，
  // 结果无论对端是否就绪都必然 timeout。正确口径是"比接收侧处理预算大"，见 S9。
  assert.equal(offline.state().budgetMs > SUMMARY_HANDLER_BUDGET_MS, true, '预算必须大于接收侧处理预算');
  assert.deepEqual(logs, [SKIP_OFFLINE], '一个窗口恰好一行 skip');
  assert.equal(offline.state().cooling, true, '失败之后必须进冷却');
});

test('S1b 远端挂在半空也不挡下一个窗口：闸在确定性写入结束时就放开', async (t) => {
  const clock = fakeClock();
  const slow = createRemoteSummaryDispatcher({
    configured: true,
    peerId: DESIGNATED,
    groupId: () => 'group-1',
    call: async () => {
      // 一趟慢慢失败的远端：150 ms 之后才报离线
      await new Promise((resolve) => setTimeout(resolve, 150));
      throw Object.assign(new Error('slow boom'), { code: 'ECONNREFUSED' });
    },
    verify: () => ({ ok: false, error: 'never' }),
    now: clock.now,
    budgetMs: 5_000,
    log: () => {},
  });
  const run = setup(t, { remote: slow });
  run.log.push(40);
  const first = run.summarizer.maybeSummarize('count');
  await new Promise((resolve) => setTimeout(resolve, 30));
  assert.equal(run.store.count(), 1, '第一个窗口的确定性摘要已经落盘');

  run.log.push(40);
  const second = run.summarizer.maybeSummarize('count');
  await new Promise((resolve) => setTimeout(resolve, 30));
  // 非空性：若 busy 闸把远端那一趟也罩住，这里第二个窗口会拿到 in-flight、条数停在 1
  assert.equal(run.store.count(), 2, '第二个窗口的确定性条目在远端那趟还在飞时就已经落盘');
  const [a, b] = await Promise.all([first, second]);
  assert.equal(a.ok, true);
  assert.equal(b.ok, true);
  assert.equal(b.trigger, 'count');
});

// ---------------------------------------------------------------------------
// S2 在线
// ---------------------------------------------------------------------------

test('S2 在线：确定性条目索引不变 + 恰好追加一条 agent-remote（窗口/by/上限/控制字符）', async (t) => {
  const clock = fakeClock();
  const logs = [];
  const calls = [];
  let store = null;
  let snapshotAtDispatch = null;
  const longText = '模型摘要：' + 'x'.repeat(2_000) + '\u0007尾巴';
  const online = onlineDispatcher(clock, logs, {
    calls,
    signWith: (job) => {
      snapshotAtDispatch = JSON.stringify(store.list());
      return signedBy(job, longText, clock);
    },
  });
  const run = setup(t, { remote: online });
  store = run.store;
  run.log.push(40);
  const out = await run.summarizer.maybeSummarize('count');

  assert.equal(calls.length, 1, '一个窗口派发一次');
  assert.equal(JSON.parse(snapshotAtDispatch).length, 1, '派发那一刻确定性条目已经落盘');
  assert.equal(out.ok, true);
  assert.equal(out.digests.length, 1, '返回的 digests 仍是确定性那一批');
  assert.equal(out.remote, null, '决定 D：返回那一刻远端那一趟还没结果');
  // 不 await 它，但必须显式等它落地：落盘之后恰好一条 agent-remote（append-only）
  assert.equal(await waitFor(() => run.store.count() === 2), true, '远端那一趟最终必须落地');

  const list = run.store.list();
  assert.equal(list.length, 2, '确定性一条 + 模型摘要一条');
  assert.equal(list[0].source, 'fallback');
  assert.equal(list[0].digestId, 'd-1-40');
  // append-only：既有条目一个字节都没被改（索引 0 不变）
  assert.equal(JSON.stringify(list.slice(0, 1)), snapshotAtDispatch);

  const remote = list[1];
  assert.equal(remote.source, 'agent-remote');
  assert.equal(remote.digestId, 'd-1-40-remote', '同一个窗口的第二条，id 必须分得开');
  assert.equal(remote.by, DESIGNATED.slice(0, 8), 'by = 被指定那一位的短 id（前 8 位）');
  assert.equal(remote.fromSeq, 1);
  assert.equal(remote.toSeq, 40);
  assert.equal(CONTROL.test(remote.text), false, '控制字符一律抹掉');
  assert.equal(Array.from(remote.text).length, DIGEST_TEXT_MAX, '正文上限就是 DIGEST_TEXT_MAX');
  assert.equal(Array.from(remote.text).slice(-1)[0], '…', '超限按省略号收口');
  assert.equal(remote.text.startsWith('模型摘要：'), true);

  // 平面：新的在前，rev 仍是 40（远端那条不新增水位）
  const plane = run.store.value();
  assert.equal(plane.rev, 40);
  assert.equal(plane.digests[0].source, 'agent-remote');
  assert.equal(plane.digests[1].source, 'fallback');
  // 冷却：成功之后不再冷却
  assert.equal(online.state().cooling, false);
  assert.equal(online.state().dispatches, 1);
});

// ---------------------------------------------------------------------------
// S3 冷却
// ---------------------------------------------------------------------------

test('S3 冷却：三个失败窗口只派发一次；成功清冷却；时间到也重新派发', async (t) => {
  const clock = fakeClock();
  const logs = [];
  let dispatches = 0;
  let healthy = false;
  const dispatcher = createRemoteSummaryDispatcher({
    configured: true,
    peerId: DESIGNATED,
    groupId: () => 'group-1',
    call: async (job) => {
      dispatches += 1;
      if (!healthy) throw Object.assign(new Error('boom'), { code: 'ECONNREFUSED' });
      return signedBy(job, '模型摘要回来了', clock);
    },
    verify: (reply, job) => verifySummaryReply({ peer: peerRecord(), reply, job, now: clock.now }),
    now: clock.now,
    log: (line) => logs.push(line),
  });
  const run = setup(t, { remote: dispatcher });

  // 窗口 1/2/3：连续三个窗口都要产出确定性摘要，但只许派发一次
  for (let window = 1; window <= SUMMARY_COOLDOWN_WINDOWS; window += 1) {
    run.log.push(40);
    const out = await run.summarizer.maybeSummarize('count');
    assert.equal(out.ok, true, '第 ' + window + ' 个窗口的确定性摘要必须照常');
    // 决定 D：冷却只由**已结算**的失败推进 —— 每个窗口都等它落地，冷却语义才可数
    await settleDispatches(dispatcher);
    assert.equal(run.store.list().some((entry) => entry.source === 'agent-remote'), false,
      '第 ' + window + ' 个窗口：失败窗口一条远端条目都不许有');
  }
  assert.equal(dispatches, 1, '三个失败窗口只派发一次');
  assert.equal(logs.filter((line) => line === SKIP_OFFLINE).length, 3, '一个窗口恰好一行 skip');
  assert.equal(run.store.count(), 3, '三个窗口三条确定性摘要，一条都不少');

  // 窗口 4：窗口数到 3 → 解除冷却；这一趟成功 → 冷却清零
  healthy = true;
  run.log.push(40);
  const forth = await run.summarizer.maybeSummarize('count');
  assert.equal(dispatches, 2, '冷却按窗口数解除');
  assert.equal(await waitFor(() => run.store.list().some((entry) => entry.source === 'agent-remote')),
    true, '成功那一趟必须追加一条 agent-remote');
  await settleDispatches(dispatcher);
  assert.equal(dispatcher.state().cooling, false);

  // 窗口 5：冷却已清 → 立刻再派发（不必等 30 分钟）
  run.log.push(40);
  await run.summarizer.maybeSummarize('count');
  assert.equal(dispatches, 3, '成功之后下一个窗口立刻派发');

  // 时间规则：再失败一次，推进 30 分钟 → 不看窗口数也重新派发
  healthy = false;
  run.log.push(40);
  await run.summarizer.maybeSummarize('count');
  assert.equal(dispatches, 4);
  await settleDispatches(dispatcher);
  clock.advance(SUMMARY_COOLDOWN_MS + 1_000);
  run.log.push(40);
  await run.summarizer.maybeSummarize('count');
  assert.equal(dispatches, 5, '冷却到期（30 分钟）后重新派发');
  await settleDispatches(dispatcher);
  // 刚刚失败过：下一个窗口（时间没走）必须再次静默
  run.log.push(40);
  await run.summarizer.maybeSummarize('count');
  assert.equal(dispatches, 5, '冷却期内不再派发');
});

// ---------------------------------------------------------------------------
// S4 信任
// ---------------------------------------------------------------------------

test('S4 信任：非指定对端签名 / by 不符 / 没签 —— 一律拒绝，平面一个字节都不动', async (t) => {
  const clock = fakeClock();
  const job = { groupId: 'group-1', lines: [{ seq: 1, name: 'alice', text: 'a' }, { seq: 2, name: 'bob', text: 'b' }] };
  const verify = (reply, made) => verifySummaryReply({ peer: peerRecord(), reply, job: made, now: clock.now });

  // (a) by 自称是别人（签名本身合法）→ 先被 by 闸挡住
  const foreignBy = createRemoteSummaryDispatcher({
    configured: true, peerId: DESIGNATED, groupId: () => 'group-1',
    call: async (made) => signedBy(made, '外来摘要', clock, { secret: 'sec-foreign', by: FOREIGN }),
    verify, now: clock.now, log: () => {},
  });
  const a = await foreignBy.summary(job.lines);
  assert.equal(a.ok, false);
  assert.equal(a.reason, 'error');
  assert.equal(a.error, 'wrong-peer', 'by 不是被指定那一位 → 稳定错误');

  // (b) by 冒充被指定那一位，但用的是别人的密钥 → 验签失败
  const forged = createRemoteSummaryDispatcher({
    configured: true, peerId: DESIGNATED, groupId: () => 'group-1',
    call: async (made) => signedBy(made, '伪造摘要', clock, { secret: 'sec-foreign', by: DESIGNATED }),
    verify, now: clock.now, log: () => {},
  });
  const b = await forged.summary(job.lines);
  assert.equal(b.ok, false);
  assert.equal(b.error, 'bad-signature');

  // (c) 干脆没签
  const unsigned = createRemoteSummaryDispatcher({
    configured: true, peerId: DESIGNATED, groupId: () => 'group-1',
    call: async () => ({ ok: true, by: DESIGNATED, text: '裸回复' }),
    verify, now: clock.now, log: () => {},
  });
  const c = await unsigned.summary(job.lines);
  assert.equal(c.ok, false);
  assert.equal(c.error, 'bad-signature');

  // (d) 窗口被掉包（用同一个密钥签了别人的窗口）
  const shifted = createRemoteSummaryDispatcher({
    configured: true, peerId: DESIGNATED, groupId: () => 'group-1',
    call: async () => signedBy({ groupId: 'group-1', lines: [{ seq: 5, name: 'x', text: 'y' }] }, '别人的窗口', clock),
    verify, now: clock.now, log: () => {},
  });
  const d = await shifted.summary(job.lines);
  assert.equal(d.ok, false);
  assert.equal(d.error, 'window-mismatch');

  // 端到端：三种伪造都不许进平面（与"没配远端"逐字节一致）
  const baseline = setup(t);
  baseline.log.push(40);
  await baseline.summarizer.maybeSummarize('count');
  const expected = JSON.stringify(baseline.store.list());

  for (const [name, raw] of [
    ['外来 by', (made) => signedBy(made, '外来摘要', clock, { secret: 'sec-foreign', by: FOREIGN })],
    ['伪造签名', (made) => signedBy(made, '伪造摘要', clock, { secret: 'sec-foreign', by: DESIGNATED })],
    ['裸回复', () => ({ ok: true, by: DESIGNATED, text: '裸回复' })],
  ]) {
    const logs = [];
    const dispatcher = createRemoteSummaryDispatcher({
      configured: true, peerId: DESIGNATED, groupId: () => 'group-1',
      call: async (made) => raw(made),
      verify: (reply, made) => verifySummaryReply({ peer: peerRecord(), reply, job: made, now: clock.now }),
      now: clock.now, log: (line) => logs.push(line),
    });
    const run = setup(t, { remote: dispatcher });
    run.log.push(40);
    const out = await run.summarizer.maybeSummarize('count');
    // 决定 D：远端那一趟不再被 await —— 等它结算，才能断言"结算了也不许进平面"
    await waitFor(() => logs.length === 1);
    assert.equal(out.ok, true, name + '：确定性摘要照常');
    assert.equal(run.store.list().some((entry) => entry.source === 'agent-remote'), false,
      name + '：一条远端条目都不许发布');
    assert.equal(JSON.stringify(run.store.list()), expected, name + '：平面一个字节都不动');
    assert.deepEqual(logs, ['[digest] summary skipped reason=error'], name + '：一行稳定的 skip');
  }
});

// ---------------------------------------------------------------------------
// S5 接收端
// ---------------------------------------------------------------------------

test('S5 接收端：一个 job 一个新会话、尊重预算、没通道就是 no-agent 且绝不抛', async (t) => {
  const seen = [];
  const handler = createRemoteSummaryHandler({
    promptSession: async (sessionId, prompt) => {
      seen.push({ sessionId, prompt });
      return { sessionId: 's-new-' + seen.length, reused: false, reply: '摘要正文' };
    },
  });
  const job = {
    groupId: 'group-1',
    fromSeq: 7,
    toSeq: 9,
    lines: [{ seq: 7, name: 'alice', text: 'a' }, { seq: 8, name: 'bob', text: 'b' }, { seq: 9, name: 'carol', text: 'c' }],
  };
  const first = await handler(job);
  const second = await handler(job);
  assert.equal(first.ok, true);
  assert.equal(second.ok, true);
  assert.equal(seen.length, 2, '一个 job 恰好一次提示');
  assert.deepEqual(seen.map((item) => item.sessionId), ['', ''], '每次都是新会话（空 sessionId）');
  assert.match(seen[0].prompt, /本批 3 条（seq 7-9）/);
  assert.match(seen[0].prompt, /- seq=7 alice: a/);

  // 预算：通道挂着不回来 → 到点返回 timeout（绝不把 hub 吊在那儿）
  const stuck = createRemoteSummaryHandler({ promptSession: () => new Promise(() => {}), budgetMs: 30 });
  const startedAt = Date.now();
  const timed = await stuck(job);
  assert.equal(timed.ok, false);
  assert.equal(timed.error, 'timeout');
  assert.equal(Date.now() - startedAt < 1_000, true, '预算到点必须回来');

  // 没有通道：no-agent，且不抛
  const none = createRemoteSummaryHandler({ promptSession: null });
  assert.deepEqual(await none(job), { ok: false, error: 'no-agent' });
  // 通道自己抛：只回报，不冒泡
  const boom = createRemoteSummaryHandler({
    promptSession: async () => {
      throw new Error('no-session');
    },
  });
  assert.equal((await boom(job)).ok, false);
  // 空批次不叫模型
  let called = 0;
  const empty = createRemoteSummaryHandler({ promptSession: async () => { called += 1; return { reply: 'x' }; } });
  assert.deepEqual(await empty({ groupId: 'g', lines: [] }), { ok: false, error: 'empty-job' });
  assert.equal(called, 0);
});

// ---------------------------------------------------------------------------
// S5b 接收端 handoff：正文走文件、reply 只当兜底
//
// 真机事故：hub 收到的远端正文正好 120 字、结尾 '…' —— DSH 的 turnOutline.response 是
// **投影预览**，截断就发生在那里。hub 侧早就用 <stateDir>/digest-out.txt 绕开了它，接收端没有。
//
// 非空性（R6）：这两条断言各自钉住一个变异
//   · 「reply 优先于文件」→ R1 的 700 字长度断言必挂（会拿到 120 字）
//   · 「提示前不删」      → R3 的 empty-reply 断言必挂（会拿到上一趟的残文）
// ---------------------------------------------------------------------------

const TAIL = '尾部指纹-tail-9f3c';
/** 一个 job 的最小形状（seq 递增、正文无所谓） */
const aJob = () => ({
  groupId: 'group-1',
  lines: [{ seq: 7, name: 'alice', text: 'a' }, { seq: 8, name: 'bob', text: 'b' }],
});
const escapeRe = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

test('R1 文件优先：文件里 700 字、reply 只有 120 字截断 → 返回文件那一份', async (t) => {
  const dir = tempDir(t);
  const outFile = path.join(dir, DIGEST_OUT_FILE);
  const body = '甲'.repeat(700 - TAIL.length) + TAIL;
  const truncated = '乙'.repeat(119) + '…';
  const handler = createRemoteSummaryHandler({
    stateDir: dir,
    promptSession: async (sessionId, prompt) => {
      assert.equal(sessionId, '', '仍然是新会话');
      assert.match(prompt, new RegExp(escapeRe(outFile)), '提示里必须给出绝对的 handoff 路径');
      assert.match(prompt, /只写一个词：DONE/);
      assert.match(prompt, /不要标题、不要 Markdown/, '长度与"只有正文"的要求原样保留');
      fs.writeFileSync(outFile, body, 'utf8');
      return { sessionId: 's-r1', reply: truncated };
    },
  });
  const out = await handler(aJob());
  assert.equal(out.ok, true);
  assert.equal(Array.from(out.text).length, 700, '返回 700 字（文件），不是 120 字（reply 预览）');
  assert.equal(out.text.includes(TAIL), true, '文件独有的尾指纹必须在结果里');
  assert.equal(out.text.includes('乙'), false, 'reply 的字一个都不许进来');
});

test('R2 reply 兜底：什么都不写 → 300 字 reply 原样返回', async (t) => {
  const dir = tempDir(t);
  const reply = ('丙'.repeat(300));
  const handler = createRemoteSummaryHandler({
    stateDir: dir,
    promptSession: async () => ({ sessionId: 's-r2', reply }),
  });
  const out = await handler(aJob());
  assert.equal(out.ok, true);
  assert.equal(out.text, reply, '没有文件时 reply 就是正文（老路径不退化）');
});

test('R3 残文守卫：上一趟留下的 handoff + 空 reply → empty-reply，绝不返回残文', async (t) => {
  const dir = tempDir(t);
  const outFile = path.join(dir, DIGEST_OUT_FILE);
  // 上一趟崩在半路留下的手稿（真实成因：会话被超时打断，文件没被读完就没了下文）
  fs.writeFileSync(outFile, '上一趟的残文' + TAIL, 'utf8');
  const handler = createRemoteSummaryHandler({
    stateDir: dir,
    promptSession: async () => ({ sessionId: 's-r3', reply: '' }),
  });
  const out = await handler(aJob());
  assert.deepEqual(out, { ok: false, error: 'empty-reply' }, '提示前不删就会把残文当成本趟摘要');
  assert.equal(fs.existsSync(outFile), false, '残文也必须被清掉');
});

test('R4 两种结局都删文件：成功删、失败（抛 + 超时）也删', async (t) => {
  const dir = tempDir(t);
  const outFile = path.join(dir, DIGEST_OUT_FILE);
  const ok = createRemoteSummaryHandler({
    stateDir: dir,
    promptSession: async () => {
      fs.writeFileSync(outFile, '成功的正文', 'utf8');
      return { sessionId: 's', reply: 'DONE' };
    },
  });
  assert.equal((await ok(aJob())).ok, true);
  assert.equal(fs.existsSync(outFile), false, '成功后文件必须不在（stateDir 里绝不留手稿）');

  const boom = createRemoteSummaryHandler({
    stateDir: dir,
    promptSession: async () => {
      fs.writeFileSync(outFile, '半路崩掉的正文', 'utf8');
      throw new Error('no-session');
    },
  });
  assert.equal((await boom(aJob())).ok, false);
  assert.equal(fs.existsSync(outFile), false, '失败后同样不许留');

  const stuck = createRemoteSummaryHandler({
    stateDir: dir,
    budgetMs: 30,
    promptSession: async () => {
      fs.writeFileSync(outFile, '超时前的正文', 'utf8');
      return new Promise(() => {});
    },
  });
  assert.equal((await stuck(aJob())).error, 'timeout');
  assert.equal(fs.existsSync(outFile), false, '超时后同样不许留');
});

test('R5 超长 + 控制字符：按 hub 侧同一个上限裁、控制字符抹掉', async (t) => {
  const dir = tempDir(t);
  const outFile = path.join(dir, DIGEST_OUT_FILE);
  const dirty = '丁'.repeat(1000) + '\u0000\u0007\u001b' + '戊'.repeat(3997);
  const handler = createRemoteSummaryHandler({
    stateDir: dir,
    promptSession: async () => {
      fs.writeFileSync(outFile, dirty, 'utf8');
      return { sessionId: 's-r5', reply: '120 字的预览' };
    },
  });
  const out = await handler(aJob());
  assert.equal(out.ok, true);
  assert.equal(Array.from(dirty).length, 5000);
  assert.equal(Array.from(out.text).length, DIGEST_TEXT_MAX, '与 hub 侧同一个上限（DIGEST_TEXT_MAX=' + DIGEST_TEXT_MAX + '）');
  assert.equal(out.text.endsWith('…'), true, '裁口看得见');
  assert.equal(CONTROL.test(out.text), false, '控制字符一个都不许留');
});

test('R6 非空性：两个变异各自被哪一条断言打红', async (t) => {
  const dir = tempDir(t);
  const outFile = path.join(dir, DIGEST_OUT_FILE);
  // 变异 A「reply 优先于文件」→ 这里必挂：文件 700 字、reply 300 字，结果必须是 700
  const body = '己'.repeat(700 - TAIL.length) + TAIL;
  const prefersFile = createRemoteSummaryHandler({
    stateDir: dir,
    promptSession: async () => {
      fs.writeFileSync(outFile, body, 'utf8');
      return { sessionId: 's', reply: '庚'.repeat(300) };
    },
  });
  const fileWins = await prefersFile(aJob());
  assert.equal(Array.from(fileWins.text).length, 700, '变异 A 打红点：文件优先');
  assert.equal(fileWins.text.includes(TAIL), true);

  // 变异 B「提示前不删」→ 这里必挂：残文 40 字、reply 300 字，结果必须是那 300 字
  fs.writeFileSync(outFile, '上一趟的残文' + TAIL, 'utf8');
  const replyOnly = '辛'.repeat(300);
  const prefersReply = createRemoteSummaryHandler({
    stateDir: dir,
    promptSession: async () => ({ sessionId: 's', reply: replyOnly }),
  });
  const replyWins = await prefersReply(aJob());
  assert.equal(replyWins.text, replyOnly, '变异 B 打红点：残文绝不能冒充这一趟');
  assert.equal(replyWins.text.includes(TAIL), false);
});

// ---------------------------------------------------------------------------
// S6 默认：没配就什么都不做
// ---------------------------------------------------------------------------

test('S6 默认（空配置）：不派发、不记 skipped；名字解析不出来才是配置错误', async (t) => {
  const run = setup(t);
  run.log.push(40);
  const out = await run.summarizer.maybeSummarize('count');
  assert.equal(out.ok, true);
  assert.equal(out.remote, null);
  assert.equal(run.store.count(), 1);
  assert.equal(run.lines.filter((line) => line.includes('summary skipped')).length, 0, '沉默才是对的');
  assert.equal(run.summarizer.state().remoteSummary, false);

  // 派发器 configured:false 同样一个字都不做
  const logs = [];
  let calls = 0;
  const quiet = createRemoteSummaryDispatcher({
    configured: false, peerId: '', call: async () => { calls += 1; }, log: (line) => logs.push(line),
  });
  assert.deepEqual(await quiet.summary([{ seq: 1, name: 'a', text: 'x' }]), { ok: false, reason: 'not-configured', silent: true });
  assert.equal(calls, 0);
  assert.deepEqual(logs, []);

  // 名字 → peerId 只走既有配对记录
  assert.deepEqual(resolveSummaryPeer('', { peers: PEERS }), { configured: false, peerId: '', name: '', unknown: false });
  assert.equal(resolveSummaryPeer(DESIGNATED_NAME, { peers: PEERS }).peerId, DESIGNATED, '名字解析成 peerId');
  assert.equal(resolveSummaryPeer(DESIGNATED, { peers: PEERS }).peerId, DESIGNATED);
  const unknown = resolveSummaryPeer('没有这台', { peers: PEERS });
  assert.equal(unknown.unknown, true);
  assert.equal(unknown.peerId, '');

  // 配了但解析不出来 → 每个窗口一行 not-configured（一行，不是两行）
  const unresolvedLogs = [];
  let unresolvedCalls = 0;
  const unresolved = createRemoteSummaryDispatcher({
    configured: true, peerId: '', call: async () => { unresolvedCalls += 1; }, log: (line) => unresolvedLogs.push(line),
  });
  await unresolved.summary([{ seq: 1, name: 'a', text: 'x' }]);
  assert.equal(unresolvedCalls, 0);
  assert.deepEqual(unresolvedLogs, ['[digest] summary skipped reason=not-configured']);
  assert.equal(resolveSummaryPeer(DESIGNATED_NAME, { peers: PEERS }).peerId, DESIGNATED);
  assert.equal(DIGEST_SUMMARY_PATH, '/v1/group/digest-summary');
});

// ---------------------------------------------------------------------------
// S7 非空性：这两处变异必须被上面的断言打红
// ---------------------------------------------------------------------------

test('S7 非空性：确定性写入被摘住 / 外来 by 被放行 —— 分别由哪一条断言打红', async (t) => {
  // 变异 1：把确定性写入挂在"远端能跑通"后面（或让远端这一趟抛出）。
  // → S1/S2 的「逐字节一致 / 索引 0 不变 / 条数」断言会红：这里必须仍然是 1 条。
  const exploding = {
    peerId: DESIGNATED,
    summary: async () => {
      throw new Error('远端炸了');
    },
  };
  const broken = setup(t, { remote: exploding });
  broken.log.push(40);
  const out = await broken.summarizer.maybeSummarize('count');
  assert.equal(out.ok, true);
  assert.equal(broken.store.count(), 1, '非空性 1：确定性条目一条都不许少（门控在远端上 → 这里会是 0）');
  assert.equal(broken.store.list()[0].source, 'fallback');
  await waitFor(() => broken.lines.some((line) => line === '[digest] summary skipped reason=error'));
  assert.equal(broken.lines.filter((line) => line === '[digest] summary skipped reason=error').length, 1,
    '远端抛错也只留一行（不许把异常冒到窗口上）');
  assert.equal(broken.store.count(), 1, '抛错的远端一个字节都不许落盘');

  // 变异 2：把"验签"这道闸拆掉（verify 永远放行）→ by 闸仍然必须拦住外来那个 by。
  const clock = fakeClock();
  const logs = [];
  const permissive = createRemoteSummaryDispatcher({
    configured: true, peerId: DESIGNATED, groupId: () => 'group-1',
    call: async (made) => signedBy(made, '外来摘要', clock, { secret: 'sec-foreign', by: FOREIGN }),
    verify: () => ({ ok: true, text: '外来摘要' }),
    now: clock.now, log: (line) => logs.push(line),
  });
  const run = setup(t, { remote: permissive });
  run.log.push(40);
  const outForeign = await run.summarizer.maybeSummarize('count');
  await waitFor(() => logs.length === 1);
  assert.equal(outForeign.remote, null, '决定 D：返回那一刻远端还没有结果');
  assert.equal(run.store.list().some((entry) => entry.source === 'agent-remote'), false,
    '非空性 2：by 不符一律不发布（S4 的"平面不动"断言就死在这里）');
  assert.equal(run.store.count(), 1);
  assert.equal(JSON.parse(fs.readFileSync(path.join(run.dir, 'group-digests.json'), 'utf8')).digests.length, 1);
  assert.deepEqual(logs, ['[digest] summary skipped reason=error']);

  // 反面：by 正确 + 验签放行 → 必须真的发布（证明这道闸不是"永远拒绝"）
  const accepted = createRemoteSummaryDispatcher({
    configured: true, peerId: DESIGNATED, groupId: () => 'group-1',
    call: async (made) => signedBy(made, '真摘要', clock),
    verify: () => ({ ok: true, text: '真摘要' }),
    now: clock.now, log: () => {},
  });
  const good = setup(t, { remote: accepted });
  good.log.push(40);
  await good.summarizer.maybeSummarize('count');
  assert.equal(await waitFor(() => good.store.count() === 2), true,
    'by 正确 + 验签放行 → 必须真的发布（证明这道闸不是"永远拒绝"）');
  assert.equal(good.store.list()[1].source, 'agent-remote');
  assert.equal(good.store.list()[1].by, DESIGNATED.slice(0, 8));
});

test('S8 生产路径：group-client 的归一化必须保留 digestSummarizer', () => {
  // 真机事故：配置写进了 YAML，但 normalizeGroupConfig 不认识这个键就把它丢掉，
  // host 于是读到空串 → 派发器为 null → 行为与"未配置"完全相同，且一条日志都不留。
  // 用例若直接往工厂注入 groupExtra，会绕过这条路，把问题藏起来。
  const normalized = normalizeGroupConfig({ digestSummarizer: ' dsh-desktop ' });
  assert.equal(normalized.digestSummarizer, 'dsh-desktop', '归一化丢了它，生产里配置就是死的');
  assert.equal(normalizeGroupConfig({}).digestSummarizer, '', '未配置必须是空串（不是 undefined）');
  assert.equal(normalizeGroupConfig({ digestSummarizer: 'x'.repeat(200) }).digestSummarizer.length, 128, '上限 128');
  assert.equal(normalizeGroupConfig({ digestSummarizer: '  ' }).digestSummarizer, '', '纯空白等于未配置');
});

test('S9 预算关系：hub 的等待预算必须大于接收侧处理预算（否则必然超时）', () => {
  // 真机事故：2_000 vs 180_000，永远是 timeout，看起来像对端没路由，实际是调用方不肯等。
  assert.ok(
    SUMMARY_BUDGET_MS > SUMMARY_HANDLER_BUDGET_MS,
    'SUMMARY_BUDGET_MS(' + SUMMARY_BUDGET_MS + ') 必须 > SUMMARY_HANDLER_BUDGET_MS(' + SUMMARY_HANDLER_BUDGET_MS + ')',
  );
  const gap = SUMMARY_BUDGET_MS - SUMMARY_HANDLER_BUDGET_MS;
  assert.ok(gap <= 60_000, '余量不该大到让一个死对端把节拍拖过一分钟以上（实际 ' + gap + '）');
  assert.ok(gap >= 20_000, '余量至少 20 s：hub 还要跑完传输与验签（实际 ' + gap + '）');
  // 数值本身不写死在这里：只有关系是规格，具体毫秒由 S10 的用例从行为上钉住。
  assert.ok(SUMMARY_HANDLER_BUDGET_MS >= 250_000, '接收侧预算必须容得下真机那 168 s 的排队（实际 ' + SUMMARY_HANDLER_BUDGET_MS + '）');
});

// ---------------------------------------------------------------------------
// S10 接收端预算：真机那 168 s 的摘要必须**收下**，过了 300 s 才是 timeout
//
// 真机事故（桌面节点）：15:09:46 派发 → 15:12:34 记 remote summary failed error=timeout
// （168 s），而 stateDir 里躺着一份 1135 B 的完整摘要 —— 那台 agent 只是排在自己群的
// 参与者后面。按 deadline 丢弃 = 把一份**已经写完**的成果扔掉。这一条给那个余量上锁。
//
// 非空性：预算退回 180_000 时，下面 250 s 那一条先红 —— 虚拟计时器会在 180 s 先开火，
// 结局从 ok:true 变成 {ok:false,error:'timeout'}，assert.equal(short.out.ok, true) 必挂。
// ---------------------------------------------------------------------------
/** 只记不动手的虚拟计时器：用例自己决定何时开火 */
function virtualTimer() {
  let armed = null;
  let lastMs = 0;
  return {
    lastMs: () => lastMs,
    fire: () => {
      const pending = armed;
      armed = null;
      if (pending) pending.fn();
    },
    setTimeoutFn: (fn, ms) => {
      armed = { fn, ms };
      lastMs = ms;
      return { unref() {} };
    },
    clearTimeoutFn: () => { armed = null; },
  };
}

test('S10 预算：虚拟时间 250 s 的摘要仍被收下（取文件正文）；超过 handler 预算才是 timeout', async (t) => {
  const dir = tempDir(t);
  const outFile = path.join(dir, DIGEST_OUT_FILE);
  const body = '辛'.repeat(1135 - TAIL.length) + TAIL;
  const preview = '壬'.repeat(119) + '…';

  /** 跑一趟"耗时 elapsedMs"的摘要：文件先落盘，谁先到（预算 or 摘要）由虚拟时钟裁决 */
  const runFor = async (elapsedMs) => {
    const timer = virtualTimer();
    let settle = () => {};
    const handler = createRemoteSummaryHandler({
      stateDir: dir,
      setTimeoutFn: timer.setTimeoutFn,
      clearTimeoutFn: timer.clearTimeoutFn,
      promptSession: () => new Promise((resolve) => {
        fs.writeFileSync(outFile, body, 'utf8');
        settle = () => resolve({ sessionId: 's', reply: preview });
      }),
    });
    const pending = handler(aJob());
    const armed = timer.lastMs();
    if (armed <= elapsedMs) timer.fire(); // 预算先到点：guard 让这一趟收 timeout
    else settle();                        // 摘要在预算之内写完：走文件正文
    const out = await pending;
    settle();                             // 收到超时之后模型才跑完（真机就是这个顺序）
    return { out, armedMs: armed, writtenBytes: Array.from(body).length };
  };

  // 1) 250 s：真机 168 s + 余量。夹具按 SUMMARY_HANDLER_BUDGET_MS 计时，
  //    所以预算一退回 180_000，这一条立刻从 ok:true 翻成 timeout。
  const short = await runFor(250_000);
  assert.equal(short.armedMs, SUMMARY_HANDLER_BUDGET_MS, '计时器必须按 SUMMARY_HANDLER_BUDGET_MS 起跑');
  assert.equal(short.out.ok, true, '250 s 的摘要必须被收下（否则 handoff 里那份写完的正文被白丢）');
  assert.equal(Array.from(short.out.text).length, 1135, '拿到的是文件正文（1135 B），不是 120 字预览');
  assert.equal(short.out.text.includes(TAIL), true, '文件尾指纹必须在');

  // 2) 超过 300 s：预算到点 → 稳定 timeout（不是 failed、不是空正文）
  const over = await runFor(SUMMARY_HANDLER_BUDGET_MS + 1);
  assert.deepEqual(over.out, { ok: false, error: 'timeout' });
  assert.equal(fs.existsSync(outFile), false, '超时同样不许留手稿');
});

test('S11 三层预算必须递增：promptSession 内层 < 接收侧 handler < hub 派发', async () => {
  // 同一个坑踩过三次：2s vs 180s、180s handler vs 175s 内层、以及每次都想只调一层。
  // 远端摘要这条路穿三层预算，任何一层更小都会把已完成的活丢掉。
  const { DIGEST_PROMPT_TIMEOUT_MS } = await import('./group-digest.mjs');
  const inner = DIGEST_PROMPT_TIMEOUT_MS - 5_000;
  assert.ok(inner < SUMMARY_HANDLER_BUDGET_MS, '内层(' + inner + ') 必须 < handler(' + SUMMARY_HANDLER_BUDGET_MS + ')');
  assert.ok(SUMMARY_HANDLER_BUDGET_MS < SUMMARY_BUDGET_MS, 'handler(' + SUMMARY_HANDLER_BUDGET_MS + ') 必须 < hub 派发(' + SUMMARY_BUDGET_MS + ')');
  assert.ok(inner >= 240_000, '内层至少要容得下实测的 168 秒并留余量');
  // A5（决定 D 之后的新数值）：关系是规格，具体毫秒在这一条上锁。
  // 远端已经不再占住节拍，三层所以整体抬到分钟级 —— 边界仍按"外层 > 内层"排成一条链：
  //   promptSession 内层 595s < 接收侧 handler 600s < hub 派发 620s
  assert.equal(inner, 595_000, '内层截止必须是 595 s（' + DIGEST_PROMPT_TIMEOUT_MS + ' - 5 s）');
  assert.equal(SUMMARY_HANDLER_BUDGET_MS, 600_000, '接收侧 handler 预算必须是 600 s');
  assert.equal(SUMMARY_BUDGET_MS, 620_000, 'hub 派发预算必须是 620 s');
  assert.ok(SUMMARY_HANDLER_BUDGET_MS >= 600_000, '接收侧预算必须到分钟级（真机那趟 294 s 要装得下）');
});
