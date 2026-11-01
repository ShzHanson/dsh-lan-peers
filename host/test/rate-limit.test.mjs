/**
 * host/test/rate-limit.test.mjs
 *
 * 安全审计剩下两条的验收用例：
 *   S1  /v1/pair 与 /v1/pair/confirm 按来源 IP 失败计数 + 指数退避
 *       （6 位码 10^6、TTL 10 分钟，没有计数就能在 TTL 内穷举穿）
 *   H4  /v1/ask 按 peerId 令牌桶 + 全局在跑会话上限；pruneSessions 显式取消 runner 会话
 *
 * 时间一律用注入的假时钟推进：退避 1s/30s、锁定 30s 都是可断言的确定值，
 * 不用真等 30 秒。helpers.mjs 默认把两个开关关掉，这里逐个用例显式打开。
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  ASK_BUSY_RETRY_MS,
  DEFAULT_ASK_RATE_PER_MIN,
  DEFAULT_MAX_CONCURRENT_SESSIONS,
  MAX_PAIR_RATE_ENTRIES,
  PAIR_FAIL_LOCK_MS,
  PAIR_FAIL_LOCK_THRESHOLD,
  PAIR_FAIL_INVALIDATE_THRESHOLD,
  PAIR_FAIL_BACKOFF_MAX_MS,
  PAIR_FAIL_BACKOFF_BASE_MS,
  createRunner,
  resolveConfig,
} from '../server.mjs';

import {
  makeTempStateDir,
  peerFixture,
  pollAnswer,
  request,
  seedPeers,
  startServer,
} from './helpers.mjs';

const PEER = peerFixture('peer-a');

/** MAX_SESSIONS = 500：造到第 502 个会话时淘汰必然发生过两次 */
const MAX_PRUNE_PROBE = 502;

/** 只用于测试的「另一枚 6 位码」：保证和真码不同，且格式合法 */
function otherCode(code) {
  const numeric = Number(code);
  return String((numeric + 1) % 1_000_000).padStart(6, '0');
}

function pairBody(code, overrides = {}) {
  return { code, peerId: 'peer-attacker', peerName: 'A', secret: 'S-a', ...overrides };
}

function post(baseUrl, path, body) {
  return request(baseUrl, { method: 'POST', path, signed: false, body });
}

function askBody(requestId, overrides = {}) {
  return { requestId, prompt: 'hello from the LAN peer', ...overrides };
}

function ask(baseUrl, requestId, overrides = {}) {
  return request(baseUrl, {
    method: 'POST',
    path: '/v1/ask',
    peerId: PEER.peerId,
    secret: PEER.inboundSecret,
    body: askBody(requestId, overrides),
  });
}

// ---------------------------------------------------------------------------
// S1 · 配对码穷举
// ---------------------------------------------------------------------------

test('S1 攻击形状：50 并发错误码之后该来源被拒，第 51 次 429 且锁定期内正确码也不接受', async (t) => {
  // 假时钟从真实时间起步：签名的时间戳用的是真实 Date.now，偏差必须留在 CLOCK_SKEW_MS 内
  const clock = { now: Date.now() };
  const stateDir = makeTempStateDir();
  const { server, baseUrl } = await startServer(t, {
    stateDir,
    now: () => clock.now,
    pairRateLimit: true,
  });
  const issued = server.issuePairingCode();
  const wrong = otherCode(issued.code);

  const burst = await Promise.all(
    Array.from({ length: 50 }, () => post(baseUrl, '/v1/pair', pairBody(wrong))),
  );
  const guesses = burst.filter((res) => res.status === 401);
  const throttled = burst.filter((res) => res.status === 429);
  assert.equal(guesses.length + throttled.length, 50, '只允许 401（真猜了）或 429（被退避挡住）');
  assert.ok(guesses.length >= 1, '第一次请求必须真的走到码比较');
  assert.ok(throttled.length >= 49, `并发burst 应当只剩极少数漏过去，实际 429=${throttled.length}`);
  assert.ok(throttled.every((res) => res.json.error === 'rate-limited' && res.json.retryAfterMs > 0));

  // 第 51 次：直接拒绝，不比较码、不动 store、不起任何握手
  const fiftyFirst = await post(baseUrl, '/v1/pair', pairBody(wrong));
  assert.equal(fiftyFirst.status, 429);
  assert.equal(fiftyFirst.json.error, 'rate-limited');
  assert.ok(fiftyFirst.json.retryAfterMs > 0, 'retryAfterMs 必须 > 0，客户端才有依据退避');

  // 锁定期内正确码同样不被接受（否则退避只挡「错码」等于没挡）
  const correctDuringLock = await post(baseUrl, '/v1/pair', pairBody(issued.code));
  assert.equal(correctDuringLock.status, 429);
  assert.equal(correctDuringLock.json.error, 'rate-limited');

  // 等过退避/锁定窗口，正确码照常可用：不能把正常流程一起挡死
  clock.now += PAIR_FAIL_LOCK_MS + 1_000;
  const afterLock = await post(baseUrl, '/v1/pair', pairBody(issued.code));
  assert.equal(afterLock.status, 200, afterLock.text);
  assert.match(afterLock.json.secret, /^[A-Za-z0-9_-]{43}$/);
});

test('S1 累计 5 次失败 → 该来源锁 30s（退避之外的硬锁），锁过期后恢复', async (t) => {
  // 假时钟从真实时间起步：签名的时间戳用的是真实 Date.now，偏差必须留在 CLOCK_SKEW_MS 内
  const clock = { now: Date.now() };
  const stateDir = makeTempStateDir();
  const { server, baseUrl } = await startServer(t, {
    stateDir,
    now: () => clock.now,
    pairRateLimit: true,
  });
  const issued = server.issuePairingCode();
  const wrong = otherCode(issued.code);

  // 每次失败前把时钟推过退避/锁定窗口，让 5 次都是「真猜」，累计到锁定阈值
  for (let index = 0; index < PAIR_FAIL_LOCK_THRESHOLD; index += 1) {
    if (index > 0) clock.now += PAIR_FAIL_BACKOFF_MAX_MS + 1_000;
    const res = await post(baseUrl, '/v1/pair', pairBody(wrong));
    assert.equal(res.status, 401, `第 ${index + 1} 次失败应当是 401，实际 ${res.status}`);
  }

  // 只推 29s：指数退避（16s）已过，锁（30s）还在 —— 挡住请求的必须是硬锁
  clock.now += 29_000;
  const locked = await post(baseUrl, '/v1/pair', pairBody(issued.code));
  assert.equal(locked.status, 429);
  assert.ok(locked.json.retryAfterMs > 0);
  assert.ok(locked.json.retryAfterMs <= PAIR_FAIL_LOCK_MS);

  // 推过 30s：放行，且码没被这 5 次失败作废（401 = 走到了码比较，不是 429）
  clock.now += 2_000;
  const allowed = await post(baseUrl, '/v1/pair', pairBody(wrong));
  assert.equal(allowed.status, 401, `锁过期后应当重新比较码，实际 ${allowed.status}`);
  assert.equal(allowed.json.error, 'invalid-code');
});

test('S1 累计 20 次失败 → 当前码作废：旧码正确也配不上，换新码才恢复', async (t) => {
  // 假时钟从真实时间起步：签名的时间戳用的是真实 Date.now，偏差必须留在 CLOCK_SKEW_MS 内
  const clock = { now: Date.now() };
  const stateDir = makeTempStateDir();
  const { server, baseUrl } = await startServer(t, {
    stateDir,
    now: () => clock.now,
    pairRateLimit: true,
  });
  const issued = server.issuePairingCode();
  const wrong = otherCode(issued.code);

  const statuses = [];
  for (let index = 0; index < PAIR_FAIL_INVALIDATE_THRESHOLD; index += 1) {
    const res = await post(baseUrl, '/v1/pair', pairBody(wrong));
    statuses.push(res.status);
    // 越过退避 + 锁定，保证每一次都真的做了一次码比较（否则累计不上去）
    clock.now += PAIR_FAIL_LOCK_MS + PAIR_FAIL_BACKOFF_MAX_MS + 1_000;
  }
  assert.deepEqual(statuses, Array(PAIR_FAIL_INVALIDATE_THRESHOLD).fill(401));

  // 原码作废：即使拿对了码也配不上，且不是被锁（401 invalid-code 而不是 429）
  const stale = await post(baseUrl, '/v1/pair', pairBody(issued.code));
  assert.equal(stale.status, 401);
  assert.equal(stale.json.error, 'invalid-code', '旧码应当在累计失败阈值处被作废');

  // 换一枚新码立刻可用：证明作废的是「那枚码」，不是把这台机器关死
  // （stale 那次本身也是一次失败，先把 1s 退避走过去）
  clock.now += PAIR_FAIL_BACKOFF_BASE_MS + 1_000;
  const fresh = server.issuePairingCode();
  const paired = await post(baseUrl, '/v1/pair', pairBody(fresh.code));
  assert.equal(paired.status, 200, paired.text);
});

test('S1 关闭开关（pairRateLimit=false）：回到不限流，失败不作废码', async (t) => {
  const stateDir = makeTempStateDir();
  const { server, baseUrl } = await startServer(t, { stateDir, pairRateLimit: false });
  const issued = server.issuePairingCode();
  const wrong = otherCode(issued.code);

  const statuses = [];
  for (let index = 0; index < 30; index += 1) {
    const res = await post(baseUrl, '/v1/pair', pairBody(wrong));
    statuses.push(res.status);
  }
  assert.deepEqual(statuses, Array(30).fill(401), '关掉限流后一次 429 都不该出现');

  const paired = await post(baseUrl, '/v1/pair', pairBody(issued.code));
  assert.equal(paired.status, 200, '关掉限流时 30 次失败也不能作废码');
});

test('S1 退避与锁定日志只记计数与状态，不带配对码、不带 IP 明文', async (t) => {
  // 假时钟从真实时间起步：签名的时间戳用的是真实 Date.now，偏差必须留在 CLOCK_SKEW_MS 内
  const clock = { now: Date.now() };
  const stateDir = makeTempStateDir();
  const lines = [];
  const { server, baseUrl } = await startServer(t, {
    stateDir,
    now: () => clock.now,
    pairRateLimit: true,
    logger: (line) => lines.push(String(line)),
  });
  const issued = server.issuePairingCode();
  const wrong = otherCode(issued.code);

  for (let index = 0; index < PAIR_FAIL_LOCK_THRESHOLD; index += 1) {
    if (index > 0) clock.now += PAIR_FAIL_BACKOFF_MAX_MS + 1_000;
    await post(baseUrl, '/v1/pair', pairBody(wrong));
  }
  await post(baseUrl, '/v1/pair', pairBody(issued.code)); // 触发一次 429 日志

  assert.ok(lines.some((line) => line.startsWith('pair: rate-limited')), lines.join('|'));
  assert.ok(lines.some((line) => line.includes('source locked')), '锁定要有可 grep 的一行');
  for (const line of lines) {
    assert.equal(line.includes(issued.code), false, `日志里出现了配对码：${line}`);
    assert.equal(line.includes(wrong), false, `日志里出现了配对码：${line}`);
    assert.equal(line.includes('127.0.0.1'), false, `日志里出现了来源 IP 明文：${line}`);
  }
});

// ---------------------------------------------------------------------------
// H4 · /v1/ask 频率 + 并发
// ---------------------------------------------------------------------------

test('H4 同一 peerId 的令牌桶：默认额度内放行，超一次 429 且 retryAfterMs>0', async (t) => {
  // 假时钟从真实时间起步：签名的时间戳用的是真实 Date.now，偏差必须留在 CLOCK_SKEW_MS 内
  const clock = { now: Date.now() };
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [PEER]);
  const { baseUrl } = await startServer(t, {
    stateDir,
    now: () => clock.now,
    allowRemotePrompts: true,
    runner: createRunner({ delayMs: 60_000 }),
    askRateLimit: true,
  });

  for (let index = 0; index < DEFAULT_ASK_RATE_PER_MIN; index += 1) {
    const res = await ask(baseUrl, `req-${index}`);
    assert.equal(res.status, 202, `第 ${index + 1} 次 ask 应当放行，实际 ${res.status} ${res.text}`);
  }

  const seventh = await ask(baseUrl, 'req-over');
  assert.equal(seventh.status, 429);
  assert.equal(seventh.json.error, 'rate-limited');
  assert.ok(seventh.json.retryAfterMs > 0, '必须告诉客户端等多久');
  assert.equal(seventh.json.sessionId, undefined, '被拒的请求不能建会话');

  // 令牌桶按时间补充：过一分钟重新有额度
  clock.now += 60_000;
  const refilled = await ask(baseUrl, 'req-after-window');
  assert.equal(refilled.status, 202, refilled.text);
});

test('H4 同一 requestId 重放不扣配额（幂等语义优先于限流）', async (t) => {
  // 假时钟从真实时间起步：签名的时间戳用的是真实 Date.now，偏差必须留在 CLOCK_SKEW_MS 内
  const clock = { now: Date.now() };
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [PEER]);
  const { baseUrl } = await startServer(t, {
    stateDir,
    now: () => clock.now,
    allowRemotePrompts: true,
    runner: createRunner({ delayMs: 60_000 }),
    askRateLimit: true,
    askRatePerMin: 2,
  });

  const first = await ask(baseUrl, 'req-same');
  assert.equal(first.status, 202);
  for (let index = 0; index < 4; index += 1) {
    const replay = await ask(baseUrl, 'req-same');
    assert.equal(replay.status, 202, '重复 requestId 不建新会话，也不该被 429');
    assert.equal(replay.json.sessionId, first.json.sessionId);
  }

  assert.equal((await ask(baseUrl, 'req-second')).status, 202);
  const over = await ask(baseUrl, 'req-third');
  assert.equal(over.status, 429, '两个不同请求已经用完 askRatePerMin=2 的额度');
  assert.ok(over.json.retryAfterMs > 0);
});

test('H4 全局在跑会话上限：占满后新请求 429，会话结算后立刻让位', async (t) => {
  // 假时钟从真实时间起步：签名的时间戳用的是真实 Date.now，偏差必须留在 CLOCK_SKEW_MS 内
  const clock = { now: Date.now() };
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [PEER]);
  const runner = createRunner({ delayMs: 0 });
  const { baseUrl } = await startServer(t, {
    stateDir,
    now: () => clock.now,
    allowRemotePrompts: true,
    runner,
    askRateLimit: true,
    askRatePerMin: 100,
    maxConcurrentSessions: 2,
  });

  const one = await ask(baseUrl, 'req-1');
  const two = await ask(baseUrl, 'req-2');
  assert.equal(one.status, 202);
  assert.equal(two.status, 202);

  const saturated = await ask(baseUrl, 'req-3');
  assert.equal(saturated.status, 429, '名额占满时新请求必须被拒，而不是继续起会话');
  assert.equal(saturated.json.error, 'rate-limited');
  assert.ok(saturated.json.retryAfterMs > 0);
  assert.equal(runner.sessions.size, 2, '被拒的请求不能落到 runner');

  // 结算第一个会话（poll 到 done）→ 名额释放 → 新请求放行
  const settled = await pollAnswer(baseUrl, {
    sessionId: one.json.sessionId,
    peerId: PEER.peerId,
    secret: PEER.inboundSecret,
    now: () => clock.now,
  });
  assert.equal(settled.status, 'done');

  const afterRelease = await ask(baseUrl, 'req-4');
  assert.equal(afterRelease.status, 202, afterRelease.text);
});

test('H4 关闭开关（askRateLimit=false）：回到不限流，连发 12 次全部放行', async (t) => {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [PEER]);
  const { baseUrl } = await startServer(t, {
    stateDir,
    allowRemotePrompts: true,
    runner: createRunner({ delayMs: 60_000 }),
    askRateLimit: false,
    maxConcurrentSessions: 2,
  });

  for (let index = 0; index < 12; index += 1) {
    const res = await ask(baseUrl, `req-${index}`);
    assert.equal(res.status, 202, `关掉限流后第 ${index + 1} 次也应当放行，实际 ${res.status}`);
  }
});

test('H4 pruneSessions 淘汰会话时显式取消 runner 会话（提供 cancel 就调用）', async (t) => {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [PEER]);
  const cancelled = [];
  const runner = createRunner({ delayMs: 60_000 });
  runner.cancel = (runnerSessionId) => { cancelled.push(runnerSessionId); };
  const { baseUrl } = await startServer(t, {
    stateDir,
    allowRemotePrompts: true,
    runner,
    askRateLimit: false,
  });

  const oldestRunnerIds = [];
  for (let index = 0; index < MAX_PRUNE_PROBE; index += 1) {
    const res = await ask(baseUrl, `req-prune-${index}`);
    assert.equal(res.status, 202, res.text);
    if (index < 2) oldestRunnerIds.push([...runner.sessions.keys()][index]);
  }
  // 最老的会话被淘汰时必须显式取消，且传的是 runner 侧的会话 id
  assert.deepEqual(cancelled.slice(0, 2), oldestRunnerIds);
  assert.ok(cancelled.every((runnerSessionId) => String(runnerSessionId).startsWith('mem-')));
});

// ---------------------------------------------------------------------------
// 配置归一化（默认开着，显式 false 才关）
// ---------------------------------------------------------------------------

test('S1/H4 配置默认值：两条限流默认开启，旋钮可覆盖、非法值回落默认', () => {
  const defaults = resolveConfig({ stateDir: makeTempStateDir() });
  assert.equal(defaults.pairRateLimit, true);
  assert.equal(defaults.askRateLimit, true);
  assert.equal(defaults.askRatePerMin, DEFAULT_ASK_RATE_PER_MIN);
  assert.equal(defaults.maxConcurrentSessions, DEFAULT_MAX_CONCURRENT_SESSIONS);

  const tuned = resolveConfig({
    stateDir: makeTempStateDir(),
    pairRateLimit: false,
    askRateLimit: false,
    askRatePerMin: 30,
    maxConcurrentSessions: 64,
  });
  assert.equal(tuned.pairRateLimit, false);
  assert.equal(tuned.askRateLimit, false);
  assert.equal(tuned.askRatePerMin, 30);
  assert.equal(tuned.maxConcurrentSessions, 64);

  const junk = resolveConfig({
    stateDir: makeTempStateDir(),
    askRatePerMin: 'abc',
    maxConcurrentSessions: -3,
  });
  assert.equal(junk.askRatePerMin, DEFAULT_ASK_RATE_PER_MIN);
  assert.equal(junk.maxConcurrentSessions, DEFAULT_MAX_CONCURRENT_SESSIONS);

  assert.equal(PAIR_FAIL_BACKOFF_BASE_MS, 1_000);
  assert.equal(PAIR_FAIL_BACKOFF_MAX_MS, 30_000);
  assert.ok(PAIR_FAIL_LOCK_THRESHOLD >= 1);
  assert.ok(MAX_PAIR_RATE_ENTRIES >= 1_000);
  assert.ok(ASK_BUSY_RETRY_MS > 0);
});
