// dsh-lan-peers · awaitPeerAnswer 预算切分 / 风暴护栏回归测试。
//
// 现场（2026-11-09，7/7）：SSE 拿走了整个预算，流一断就正好到 deadline，
// 长轮询一次都没跑，答案明明可取却没人再问。2026-11-06 更狠：400
// encryption-required 被当成可重试，6 分钟打了 29255 次 /v1/answer。
// 这里全部用注入的 fetchImpl，不起端口、不 sleep 到真实预算。
import test from 'node:test';
import assert from 'node:assert/strict';
import { awaitPeerAnswer, STREAM_CAP_MS, STREAM_RESERVE_MS } from './peer-call.mjs';

const SECRET = 'budget-test-secret-0123456789';
const SENDER = 'peer-a';

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

/** 一条永远不产出、也不关闭的 SSE 流：只有 abort 能把它拆掉。 */
function hangingSse(signal, onAbort) {
  const body = new ReadableStream({
    start(controller) {
      const kill = () => {
        try { controller.error(new Error('stream-aborted')); } catch {}
        onAbort?.(Date.now());
      };
      if (signal?.aborted) kill();
      else signal?.addEventListener?.('abort', kill, { once: true });
    },
  });
  return new Response(body, { status: 200, headers: { 'content-type': 'text/event-stream' } });
}

/** 路由 + 计数 + 时间戳；handler 自己决定每个请求怎么回。 */
function recorder(handler) {
  const calls = { events: 0, answer: 0, answers: [], eventsAt: [], answerAt: [], abortedAt: [] };
  const fetchImpl = async (url, init = {}) => {
    const path = new URL(String(url)).pathname;
    if (path === '/v1/events') {
      calls.events += 1;
      calls.eventsAt.push(Date.now());
      return handler({ kind: 'events', signal: init?.signal, calls });
    }
    calls.answer += 1;
    calls.answerAt.push(Date.now());
    calls.answers.push(String(url));
    return handler({ kind: 'answer', init, calls });
  };
  return { fetchImpl, calls };
}

const base = {
  baseUrl: 'http://127.0.0.1:1',
  secret: SECRET,
  senderId: SENDER,
  sessionId: 'sess-budget',
};

test('T1 流阶段严格受限，之后至少问一次 /v1/answer', async () => {
  // 收窄保留/上限（生产默认为 STREAM_RESERVE_MS / STREAM_CAP_MS），否则要等 31s。
  const reserve = 1000;
  const cap = 1000;
  const budget = 6000; // > 2*reserve，流允许；流只拿 min(6000-1000, 1000)=1000ms
  const startedAt = Date.now();
  const { fetchImpl, calls } = recorder(({ kind, signal, calls: c }) => {
    if (kind === 'events') return hangingSse(signal, () => c.abortedAt.push(Date.now()));
    return json({ status: 'done', reply: 'polled-after-stream', elapsedMs: 5 });
  });

  const out = await awaitPeerAnswer({
    ...base,
    timeoutMs: budget,
    mode: 'auto',
    pollIntervalMs: 10,
    fetchImpl,
    streamReserveMs: reserve,
    streamCapMs: cap,
  });

  assert.equal(calls.events, 1, '流应当被开一次');
  assert.equal(calls.abortedAt.length, 1, '流必须被 abort（否则 socket 泄漏）');
  const streamMs = calls.abortedAt[0] - startedAt;
  assert.ok(streamMs < budget, `流在 ${streamMs}ms 就被掐断，必须远早于 ${budget}ms 的预算`);
  assert.ok(streamMs <= cap + 400, `流阶段 ${streamMs}ms 不得超过上限 ${cap}ms`);
  assert.ok(calls.answer >= 1, `流没给确定答案时必须至少问一次 /v1/answer，实际 ${calls.answer}`);
  assert.equal(calls.events, 1, '流只开一次，不回退重开');
  assert.equal(out.status, 'done');
  assert.equal(out.reply, 'polled-after-stream');
});

test('T2 预算 <= 2*保留时长：完全跳过流，直接轮询', async () => {
  const { fetchImpl, calls } = recorder(({ kind, signal }) =>
    // 也把 signal 接上：万一实现真的开了流，它会按 abort 退出，而不是把测试挂死。
    kind === 'events' ? hangingSse(signal) : json({ status: 'done', reply: 'no-stream', elapsedMs: 3 }),
  );

  const out = await awaitPeerAnswer({
    ...base,
    timeoutMs: 1000, // 生产常量下 1000 <= 2*STREAM_RESERVE_MS(30000)
    mode: 'auto',
    pollIntervalMs: 10,
    fetchImpl,
  });

  assert.equal(calls.events, 0, '小预算下不得开流');
  assert.ok(calls.answer >= 1, `必须直接轮询 /v1/answer，实际 ${calls.answer}`);
  assert.equal(out.status, 'done');
  assert.equal(out.reply, 'no-stream');
});

test('T3 轮询拿到的确定答案原样返回（逐字段）', async () => {
  const { fetchImpl, calls } = recorder(() => json({ status: 'done', reply: 'same-shape', elapsedMs: 42 }));

  const out = await awaitPeerAnswer({ ...base, timeoutMs: 5000, mode: 'poll', pollIntervalMs: 10, fetchImpl });

  assert.equal(calls.answer, 1);
  assert.deepEqual(Object.keys(out).sort(), ['elapsedMs', 'reply', 'status', 'transport'], '公共返回形状不得新增字段');
  assert.equal(out.status, 'done');
  assert.equal(out.reply, 'same-shape');
  assert.equal(out.transport, 'long-poll');
  assert.equal(typeof out.elapsedMs, 'number');
});

test('T4 到期仍在跑：timeout 且带上 sessionId', async () => {
  const { fetchImpl, calls } = recorder(() => json({ status: 'running', elapsedMs: 10 }));

  const out = await awaitPeerAnswer({
    ...base,
    sessionId: 'sess-resume-me',
    timeoutMs: 1200,
    mode: 'poll',
    pollIntervalMs: 50,
    fetchImpl,
  });

  assert.equal(out.status, 'timeout');
  assert.equal(out.error, 'timeout');
  assert.ok(calls.answer >= 1, '至少问过一次');
  assert.equal(out.sessionId, 'sess-resume-me', 'timeout 结果必须带 sessionId 以便续问');
});

test('T5 400 encryption-required 立即终止：只发一次请求', async () => {
  const { fetchImpl, calls } = recorder(() => json({ error: 'encryption-required' }, 400));

  const out = await awaitPeerAnswer({ ...base, timeoutMs: 60_000, mode: 'poll', pollIntervalMs: 10, fetchImpl });

  assert.equal(calls.answer, 1, `永久性 4xx 不得重试，实际发了 ${calls.answer} 次`);
  assert.equal(calls.events, 0);
  assert.equal(out.status, 'error');
  assert.match(out.error, /encryption-required/, '错误结果必须点名 encryption-required');
  assert.equal(out.httpStatus, 400);
  assert.equal(out.terminal, true);
});

test('T6 可重试失败（429）指数退避且封顶', async () => {
  const { fetchImpl, calls } = recorder(() => json({ error: 'rate-limited' }, 429));

  const out = await awaitPeerAnswer({ ...base, timeoutMs: 12_000, mode: 'poll', pollIntervalMs: 10, fetchImpl });

  const at = calls.answerAt;
  assert.ok(at.length >= 4, `退避期间仍应重试若干次，实际 ${at.length}`);
  const gaps = at.slice(1).map((t, i) => t - at[i]);
  // 500,1000,2000,4000(封顶),...：前几档必须递增
  for (let i = 0; i < Math.min(3, gaps.length - 1); i += 1) {
    assert.ok(gaps[i + 1] > gaps[i] * 1.5, `第 ${i + 1} 档退避 ${gaps[i + 1]}ms 应明显大于 ${gaps[i]}ms`);
  }
  const capped = gaps.filter((g) => g >= 3_000);
  assert.ok(capped.length >= 1, '必须出现封顶后的退避');
  assert.ok(Math.max(...gaps) <= 4_000 + 400, `退避不得超过封顶 4000ms，实际 ${Math.max(...gaps)}ms`);
  assert.equal(out.status, 'error');
  assert.match(out.error, /429/);
});

test('T7 常量与不变量自检（供 B1 引用）', () => {
  assert.equal(STREAM_RESERVE_MS, 30_000);
  assert.equal(STREAM_CAP_MS, 300_000);
});

// ---- 掉线回归：确定性失败连续 N 次就收手，别拿整份预算陪死对端 ----

/** 仿 undici：TypeError('fetch failed', { cause: <errno> })。 */
const offlineError = (code = 'ECONNREFUSED') => {
  const inner = Object.assign(new Error(`connect ${code} 127.0.0.1:1`), { code });
  return Object.assign(new TypeError('fetch failed'), { cause: inner });
};

test('E1 确定性掉线连续 N 次即报错，远早于 deadline', async () => {
  const budget = 8000; // 若没有 N 上限，这里会被退避耗到 deadline
  const startedAt = Date.now();
  const { fetchImpl, calls } = recorder(() => {
    throw offlineError('ECONNREFUSED');
  });

  const out = await awaitPeerAnswer({ ...base, timeoutMs: budget, mode: 'poll', pollIntervalMs: 10, fetchImpl });
  const elapsed = Date.now() - startedAt;

  assert.equal(calls.answer, 2, `连续掉线只准试 N=2 次，实际 ${calls.answer}`); // E6-a
  assert.equal(out.attempts, 2);
  assert.equal(out.status, 'error');
  assert.match(out.error, /ECONNREFUSED/, '错误必须点名底层 errno');
  assert.equal(out.offline, true);
  assert.equal(out.sessionId, 'sess-budget');
  assert.ok(elapsed < 3000, `掉线必须在 ~1s 内报错，实际 ${elapsed}ms（预算 ${budget}ms）`);
});

test('E2 单次掉线后恢复：不算掉线，正常返回', async () => {
  let n = 0;
  const { fetchImpl, calls } = recorder(() => {
    n += 1;
    if (n === 1) throw offlineError('ECONNREFUSED');
    return json({ status: 'done', reply: 'back-alive', elapsedMs: 1 });
  });

  const out = await awaitPeerAnswer({ ...base, timeoutMs: 8000, mode: 'poll', pollIntervalMs: 10, fetchImpl });

  assert.equal(calls.answer, 2, '一次失败之后必须还有下一枪');
  assert.equal(out.status, 'done', '单次掉线不得触发掉线判定');
  assert.equal(out.reply, 'back-alive');
  assert.deepEqual(Object.keys(out).sort(), ['elapsedMs', 'reply', 'status', 'transport']);
});

test('E3 成功后掉线：计数已清零，仍享有完整 N 次重试', async () => {
  // 序列：掉线 → running（成功，清零）→ 掉线 → 掉线（第 2 次才收手）
  const plan = ['offline', 'running', 'offline', 'offline'];
  let n = 0;
  const { fetchImpl, calls } = recorder(() => {
    const step = plan[n] ?? 'offline';
    n += 1;
    if (step === 'running') return json({ status: 'running', elapsedMs: 5 });
    throw offlineError('ECONNREFUSED');
  });

  const out = await awaitPeerAnswer({ ...base, timeoutMs: 8000, mode: 'poll', pollIntervalMs: 10, fetchImpl });

  assert.equal(calls.answer, 4, `成功后应从 0 重新计数（1+1+N=4），实际 ${calls.answer}`); // E6-b
  assert.equal(out.status, 'error');
  assert.equal(out.attempts, 4);
});

test('E4 瞬态失败（503）仍然退避重试到 deadline', async () => {
  const { fetchImpl, calls } = recorder(() => json({ error: 'unavailable' }, 503));

  const out = await awaitPeerAnswer({ ...base, timeoutMs: 6000, mode: 'poll', pollIntervalMs: 10, fetchImpl });

  assert.ok(calls.answer > 2, `瞬态 5xx 必须继续重试（> N=2），实际 ${calls.answer}`);
  assert.equal(out.status, 'error');
  assert.equal(out.offline, undefined, '5xx 不属于掉线类');
});
