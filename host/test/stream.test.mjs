/**
 * v0.4.0 · /v1/answer 长轮询（§端点 4）+ /v1/events SSE（§端点 5）。
 *
 * 覆盖：无 waitMs 立即返回（0.3.1 语义）、waitMs 在 done 时提前返回带 elapsedMs、
 *      answerWaitMs 裁剪 hold 上限、未知 sessionId 的错误码、
 *      SSE 每条事件可独立解密、终态后断流、非 200 回退路径、断开不影响会话。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import { makeTempStateDir, peerFixture, seedPeers, request, startServer } from './helpers.mjs';
import { createRunner } from '../server.mjs';
import { decryptBytes } from '../../lib/wire-crypto.mjs';

const PEER = peerFixture('peer-stream-1');

async function startStreamServer(t, overrides = {}) {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [PEER]);
  return startServer(t, { stateDir, allowRemotePrompts: true, ...overrides });
}

async function askSession(baseUrl, prompt = 'stream me', { timeoutSec = 30, encrypt = false } = {}) {
  const res = await request(baseUrl, {
    method: 'POST',
    path: '/v1/ask',
    peerId: PEER.peerId,
    secret: PEER.inboundSecret,
    body: { requestId: `req-${randomUUID()}`, prompt, timeoutSec },
    encrypt,
  });
  assert.equal(res.status, 202, res.text);
  return res.json.sessionId;
}

/** GET 的签名：canonical 的 body = sha256("") */
function signedGet(secret, requestPath, extraHeaders = {}) {
  const ts = String(Date.now());
  const nonce = randomBytes(16).toString('hex');
  const canonical = [
    'GET',
    requestPath,
    ts,
    nonce,
    createHash('sha256').update(Buffer.alloc(0)).digest('hex'),
  ].join('\n');
  const signature = createHmac('sha256', Buffer.from(String(secret), 'utf8'))
    .update(canonical, 'utf8')
    .digest('base64url');
  return {
    'x-peer-id': PEER.peerId,
    'x-peer-ts': ts,
    'x-peer-nonce': nonce,
    'x-peer-sign': signature,
    ...extraHeaders,
  };
}

function parseSseBlock(block, secret) {
  let event = null;
  let dataRaw = null;
  for (const line of block.split('\n')) {
    if (line.startsWith('event:')) event = line.slice(6).trim();
    else if (line.startsWith('data:')) dataRaw = line.slice(5).trim();
  }
  if (!event || dataRaw == null) return null;
  const envelope = JSON.parse(dataRaw);
  assert.equal(envelope.enc, 'v1', '每条事件都必须是加密信封');
  // 解密失败会 throw：这正是「每条事件可被解密」的断言
  return { event, data: JSON.parse(decryptBytes(secret, envelope.data).toString('utf8')) };
}

async function readStream(response, secret, { timeoutMs = 15_000 } = {}) {
  assert.equal(response.status, 200, 'SSE 应 200');
  assert.match(response.headers.get('content-type') ?? '', /text\/event-stream/);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  const events = [];
  let buffer = '';
  let streamEnded = false;
  try {
    for (;;) {
      const { value, done } = await Promise.race([
        reader.read(),
        new Promise((_, reject) => {
          controller.signal.addEventListener('abort', () => reject(new Error('sse-read-timeout')), { once: true });
        }),
      ]);
      if (done) {
        streamEnded = true;
        break;
      }
      buffer += decoder.decode(value, { stream: true });
      let cut;
      while ((cut = buffer.indexOf('\n\n')) >= 0) {
        const block = buffer.slice(0, cut);
        buffer = buffer.slice(cut + 2);
        const parsed = parseSseBlock(block, secret);
        if (parsed) events.push(parsed);
      }
    }
  } finally {
    clearTimeout(timer);
  }
  return { events, streamEnded };
}

// ---------------------------------------------------------------------------
// §4 /v1/answer 长轮询
// ---------------------------------------------------------------------------

test('§4 旧客户端不带 waitMs → 立即返回 running（0.3.1 语义不变）', async (t) => {
  const runner = createRunner({ delayMs: 60_000 });
  const { baseUrl } = await startStreamServer(t, { runner });
  const sessionId = await askSession(baseUrl);

  const startedAt = Date.now();
  const res = await request(baseUrl, {
    path: `/v1/answer?sessionId=${encodeURIComponent(sessionId)}`,
    peerId: PEER.peerId,
    secret: PEER.inboundSecret,
  });
  const waited = Date.now() - startedAt;
  assert.equal(res.status, 200, res.text);
  assert.equal(res.json.status, 'running');
  assert.equal(typeof res.json.elapsedMs, 'number');
  assert.ok(waited < 1_000, `不带 waitMs 必须立即返回，实等 ${waited}ms`);
});

test('§4 waitMs 在 done 时提前返回，带 reply 与 elapsedMs', async (t) => {
  const runner = createRunner({ delayMs: 400 });
  const { baseUrl } = await startStreamServer(t, { runner });
  const sessionId = await askSession(baseUrl, '长轮询回归');

  const startedAt = Date.now();
  const res = await request(baseUrl, {
    path: `/v1/answer?sessionId=${encodeURIComponent(sessionId)}&waitMs=8000`,
    peerId: PEER.peerId,
    secret: PEER.inboundSecret,
  });
  const waited = Date.now() - startedAt;
  assert.equal(res.status, 200, res.text);
  assert.equal(res.json.status, 'done');
  assert.match(res.json.reply, /^OK 长轮询回归/);
  assert.ok(res.json.elapsedMs >= 300, `elapsedMs=${res.json.elapsedMs} 应覆盖等待时间`);
  assert.ok(waited < 5_000, `应在 done 时提前返回，实等 ${waited}ms，而不是 hold 满 8000ms`);
});

test('§4 waitMs 到期仍 running 就返回；hold 上限受 answerWaitMs 裁剪', async (t) => {
  const runner = createRunner({ delayMs: 60_000 });
  const { baseUrl } = await startStreamServer(t, { runner, answerWaitMs: 300 });
  const sessionId = await askSession(baseUrl);

  const startedAt = Date.now();
  const res = await request(baseUrl, {
    // 客户端要 20s，服务端只允许 hold 300ms
    path: `/v1/answer?sessionId=${encodeURIComponent(sessionId)}&waitMs=20000`,
    peerId: PEER.peerId,
    secret: PEER.inboundSecret,
  });
  const waited = Date.now() - startedAt;
  assert.equal(res.status, 200, res.text);
  assert.equal(res.json.status, 'running');
  assert.ok(res.json.elapsedMs >= 250, `elapsedMs=${res.json.elapsedMs}`);
  assert.ok(waited < 3_000, `应被 answerWaitMs=300 裁剪，实等 ${waited}ms`);
});

test('§4/§5 未知 sessionId → 404 unknown-session（长轮询同样不发呆）', async (t) => {
  const { baseUrl } = await startStreamServer(t, {});
  const missing = randomUUID();

  const startedAt = Date.now();
  const res = await request(baseUrl, {
    path: `/v1/answer?sessionId=${encodeURIComponent(missing)}&waitMs=5000`,
    peerId: PEER.peerId,
    secret: PEER.inboundSecret,
  });
  assert.equal(res.status, 404);
  assert.equal(res.json.error, 'unknown-session');
  assert.ok(Date.now() - startedAt < 1_000, '未知会话不该 hold');

  const eventsRes = await fetch(
    new URL(`/v1/events?sessionId=${encodeURIComponent(missing)}`, baseUrl),
    { headers: signedGet(PEER.inboundSecret, `/v1/events?sessionId=${encodeURIComponent(missing)}`) },
  );
  assert.equal(eventsRes.status, 404, '客户端据此回退长轮询');
  assert.equal((await eventsRes.json()).error, 'unknown-session');
});

// ---------------------------------------------------------------------------
// §5 /v1/events SSE
// ---------------------------------------------------------------------------

test('§5 SSE：status → done，每条事件可独立解密，终态后服务端断流', async (t) => {
  const runner = createRunner({ delayMs: 700 });
  // requireEncryption:true 也不影响 SSE（GET 无请求体，事件载荷本身始终加密）
  const { baseUrl } = await startStreamServer(t, { runner, requireEncryption: true });
  const sessionId = await askSession(baseUrl, '流式回归', { encrypt: true });
  const requestPath = `/v1/events?sessionId=${encodeURIComponent(sessionId)}`;

  const response = await fetch(new URL(requestPath, baseUrl), {
    headers: signedGet(PEER.inboundSecret, requestPath, { accept: 'text/event-stream' }),
  });
  const { events, streamEnded } = await readStream(response, PEER.inboundSecret);

  assert.ok(events.length >= 2, `至少要有 status + done，实得 ${JSON.stringify(events)}`);
  assert.equal(events[0].event, 'status');
  assert.equal(events[0].data.status, 'running');
  assert.equal(typeof events[0].data.elapsedMs, 'number');

  const terminal = events.at(-1);
  assert.equal(terminal.event, 'done');
  assert.equal(terminal.data.status, 'done');
  assert.match(terminal.data.reply, /^OK 流式回归/);
  assert.equal(typeof terminal.data.elapsedMs, 'number');
  assert.equal(streamEnded, true, '终态事件之后必须主动 end 流');
});

test('§5 SSE 无签名 → 401；别人的会话 → 404（两条都是回退长轮询的信号）', async (t) => {
  const stateDir = makeTempStateDir();
  const other = peerFixture('peer-other');
  seedPeers(stateDir, [PEER, other]);
  const runner = createRunner({ delayMs: 60_000 });
  const { baseUrl } = await startStreamServer(t, { runner, stateDir });
  const sessionId = await askSession(baseUrl);

  const unsigned = await fetch(new URL(`/v1/events?sessionId=${encodeURIComponent(sessionId)}`, baseUrl));
  assert.equal(unsigned.status, 401);
  assert.equal((await unsigned.json()).error, 'bad-signature');

  const foreignPath = `/v1/events?sessionId=${encodeURIComponent(sessionId)}`;
  const foreign = await fetch(new URL(foreignPath, baseUrl), {
    headers: {
      ...signedGet(other.inboundSecret, foreignPath),
      'x-peer-id': other.peerId,
    },
  });
  assert.equal(foreign.status, 404);
});

test('§5 SSE 客户端中途断开：流结束、会话不受影响，可用 waitMs 长轮询续上', async (t) => {
  const runner = createRunner({ delayMs: 900 });
  const { baseUrl } = await startStreamServer(t, { runner });
  const sessionId = await askSession(baseUrl, '断开续传');
  const requestPath = `/v1/events?sessionId=${encodeURIComponent(sessionId)}`;

  const controller = new AbortController();
  const response = await fetch(new URL(requestPath, baseUrl), {
    headers: signedGet(PEER.inboundSecret, requestPath),
    signal: controller.signal,
  });
  assert.equal(response.status, 200);
  const reader = response.body.getReader();
  const first = await reader.read();  // 至少收到一条 status
  assert.equal(first.done, false);
  await reader.cancel().catch(() => {});
  controller.abort();
  await sleep(50);

  const resumed = await request(baseUrl, {
    path: `/v1/answer?sessionId=${encodeURIComponent(sessionId)}&waitMs=5000`,
    peerId: PEER.peerId,
    secret: PEER.inboundSecret,
  });
  assert.equal(resumed.status, 200, resumed.text);
  assert.equal(resumed.json.status, 'done', '断开 SSE 不影响会话继续执行');
  assert.match(resumed.json.reply, /^OK 断开续传/);
});

test('§5 SSE error 终态：会话超时后事件是 error，随后断流', async (t) => {
  const clock = { now: Date.now() };
  const runner = createRunner({ delayMs: 60_000 });
  const { baseUrl } = await startStreamServer(t, { runner, now: () => clock.now });
  // timeoutSec=1 → 会话 deadline 很快过去，answerFor 会返回 error:timeout
  const sessionId = await askSession(baseUrl, 'stream me', { timeoutSec: 1 });
  const requestPath = `/v1/events?sessionId=${encodeURIComponent(sessionId)}`;
  const response = await fetch(new URL(requestPath, baseUrl), {
    headers: signedGet(PEER.inboundSecret, requestPath),
  });
  assert.equal(response.status, 200);

  // 先把时钟推过 deadline，再读流
  clock.now += 5_000;
  const { events, streamEnded } = await readStream(response, PEER.inboundSecret);
  const terminal = events.at(-1);
  assert.equal(terminal.event, 'error');
  assert.equal(terminal.data.status, 'error');
  assert.equal(terminal.data.error, 'timeout');
  assert.equal(streamEnded, true);
});
