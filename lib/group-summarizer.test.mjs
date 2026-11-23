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

import { DIGEST_TEXT_MAX, GroupDigestStore, createHubSummarizer } from './group-digest.mjs';
import {
  DIGEST_SUMMARY_PATH,
  SUMMARY_BUDGET_MS,
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

  assert.equal(out.ok, true, '窗口本身必须成功');
  assert.equal(out.remote, null, '离线时不许有远端条目');
  assert.equal(JSON.stringify(run.store.list()), expected, '离线时摘要与"没配"逐字节一致');
  assert.equal(run.store.count(), baseline.store.count());
  assert.equal(dispatches, 1, '一个窗口只探一次');
  assert.equal(elapsedMs <= 800, true, '离线这一趟必须立刻回来（实测 ' + elapsedMs + 'ms）');
  // 注入的预算就是上界：派发器自己不会等超过 SUMMARY_BUDGET_MS
  assert.equal(offline.state().budgetMs, SUMMARY_BUDGET_MS);
  assert.equal(offline.state().budgetMs <= 2_000, true, '预算是"一两秒"级别');
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
  assert.equal(out.remote.source, 'agent-remote');

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
    assert.equal(out.remote, null);
  }
  assert.equal(dispatches, 1, '三个失败窗口只派发一次');
  assert.equal(logs.filter((line) => line === SKIP_OFFLINE).length, 3, '一个窗口恰好一行 skip');
  assert.equal(run.store.count(), 3, '三个窗口三条确定性摘要，一条都不少');

  // 窗口 4：窗口数到 3 → 解除冷却；这一趟成功 → 冷却清零
  healthy = true;
  run.log.push(40);
  const forth = await run.summarizer.maybeSummarize('count');
  assert.equal(dispatches, 2, '冷却按窗口数解除');
  assert.equal(forth.remote.source, 'agent-remote');
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
  clock.advance(SUMMARY_COOLDOWN_MS + 1_000);
  run.log.push(40);
  await run.summarizer.maybeSummarize('count');
  assert.equal(dispatches, 5, '冷却到期（30 分钟）后重新派发');
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
    assert.equal(out.ok, true, name + '：确定性摘要照常');
    assert.equal(out.remote, null, name + '：一条远端条目都不许发布');
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
  assert.equal(broken.lines.filter((line) => line === '[digest] summary skipped reason=error').length, 1,
    '远端抛错也只留一行（不许把异常冒到窗口上）');

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
  assert.equal(outForeign.remote, null, '非空性 2：by 不符一律不发布（S4 的"平面不动"断言就死在这里）');
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
  const outGood = await good.summarizer.maybeSummarize('count');
  assert.equal(outGood.remote.source, 'agent-remote');
  assert.equal(good.store.count(), 2);
});
