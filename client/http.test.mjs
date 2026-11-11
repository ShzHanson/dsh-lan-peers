// dsh-lan-peers · real-fetch regression tests (no fetchImpl stubs).
//
// A stub fetch cannot reproduce undici's request rules, and one of them bit us:
// `fetch(url, { method: 'GET', body: Buffer.alloc(0) })` throws
// "Request with GET/HEAD method cannot have body", which broke every signed GET
// (/v1/answer, /v1/events, /v1/peers) while the injected-fetch unit tests stayed
// green. Everything here runs the global fetch against a real node:http server.
import test from 'node:test';
import assert from 'node:assert/strict';
import { listenOnRandomPort } from '../test-support/ports.mjs';
import http from 'node:http';
import { ENC_VERSION, decryptJson, encryptJson } from '../lib/wire-crypto.mjs';
import { canonical, sameSignature, sign } from './protocol.mjs';
import { awaitPeerAnswer, callPeer, probePeer } from './peer-call.mjs';
import { readPeerEvents } from './sse.mjs';

const SECRET = 'http-test-secret-0123456789';
const SENDER = 'peer-a';

async function startPeer(handler) {
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const raw = Buffer.concat(chunks);
    const url = new URL(req.url, 'http://127.0.0.1');
    await handler({ req, res, url, raw });
  });
  await listenOnRandomPort(server);
  const { port } = server.address();
  return {
    baseUrl: 'http://127.0.0.1:' + port,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

const replyEnc = (res, status, value) => {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ enc: ENC_VERSION, data: encryptJson(SECRET, value) }));
};

/** Host-side check: the signature covers the *plaintext* body, GET = sha256(""). */
function signatureOk(record, plain) {
  const expected = sign(
    SECRET,
    canonical(
      record.method,
      record.path,
      Number(record.headers['x-peer-ts']),
      record.headers['x-peer-nonce'],
      plain,
    ),
  );
  return sameSignature(expected, String(record.headers['x-peer-sign'] ?? ''));
}

const capture = (req, raw) => ({
  method: String(req.method).toUpperCase(),
  path: req.url,
  headers: req.headers,
  raw,
});

test('a signed GET sends no body at all and undici accepts it', async () => {
  const seen = [];
  const peer = await startPeer(({ req, res, raw }) => {
    seen.push(capture(req, raw));
    replyEnc(res, 200, { status: 'done', reply: 'ok', elapsedMs: 3 });
  });
  try {
    const inits = [];
    const recording = (url, init) => {
      inits.push(init);
      return fetch(url, init);
    };
    const out = await callPeer({
      baseUrl: peer.baseUrl,
      secret: SECRET,
      senderId: SENDER,
      method: 'GET',
      apiPath: '/v1/answer?sessionId=s1',
      fetchImpl: recording,
    });
    assert.equal(out.status, 'done');
    assert.equal(inits.length, 1);
    // Buffer.alloc(0) or null would both make undici throw; the field must be absent.
    assert.equal(inits[0].body, undefined);
    assert.equal(seen.length, 1);
    assert.equal(seen[0].method, 'GET');
    assert.equal(seen[0].raw.length, 0);
  } finally {
    await peer.close();
  }
});

test('a GET is signed over sha256("") exactly as 0.3.1 did', async () => {
  const seen = [];
  const peer = await startPeer(({ req, res, raw }) => {
    seen.push(capture(req, raw));
    replyEnc(res, 200, { status: 'running' });
  });
  try {
    await callPeer({ baseUrl: peer.baseUrl, secret: SECRET, senderId: SENDER, method: 'GET', apiPath: '/v1/answer?sessionId=s1&waitMs=25000' });
    const record = seen[0];
    assert.equal(signatureOk(record, Buffer.alloc(0)), true);
    assert.equal(record.headers['x-peer-enc'], ENC_VERSION);
    assert.equal(record.headers['x-peer-id'], SENDER);
  } finally {
    await peer.close();
  }
});

test('a POST carries ciphertext and the encrypted reply is decrypted', async () => {
  const seen = [];
  const peer = await startPeer(({ req, res, raw }) => {
    const record = capture(req, raw);
    seen.push(record);
    const plain = Buffer.from(JSON.stringify(decryptJson(SECRET, raw.toString('utf8'))));
    record.plain = plain;
    replyEnc(res, 200, { accepted: true });
  });
  try {
    const out = await callPeer({
      baseUrl: peer.baseUrl,
      secret: SECRET,
      senderId: SENDER,
      method: 'POST',
      apiPath: '/v1/ask',
      body: { prompt: 'hi', timeoutSec: 30 },
    });
    assert.deepEqual(out, { accepted: true });
    const record = seen[0];
    assert.equal(record.method, 'POST');
    assert.ok(record.raw.length > 0);
    assert.notEqual(record.raw.toString('utf8'), JSON.stringify({ prompt: 'hi', timeoutSec: 30 }));
    assert.equal(signatureOk(record, record.plain), true);
  } finally {
    await peer.close();
  }
});

test('null is not a legal GET body either, so the field stays absent', async () => {
  const peer = await startPeer(({ res }) => replyEnc(res, 200, { ok: true }));
  try {
    // The trap, documented: this is what Buffer.alloc(0) used to trigger.
    await assert.rejects(
      fetch(peer.baseUrl + '/v1/answer', { method: 'GET', body: Buffer.alloc(0) }),
      /cannot have body/i,
    );
    const out = await callPeer({ baseUrl: peer.baseUrl, secret: SECRET, senderId: SENDER, apiPath: '/v1/answer' });
    assert.deepEqual(out, { ok: true });
  } finally {
    await peer.close();
  }
});

test('an unsigned health probe reads capabilities over real fetch', async () => {
  const peer = await startPeer(({ req, res }) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ name: 'nas', version: '0.4.0', capability: ['ask', 'pair', 'pair-ecdh', 'stream'], peers: 1 }));
  });
  try {
    const health = await probePeer({ baseUrl: peer.baseUrl, fresh: true });
    assert.equal(health.online, true);
    assert.deepEqual(health.capability, ['ask', 'pair', 'pair-ecdh', 'stream']);
  } finally {
    await peer.close();
  }
});

test('long-polling /v1/answer asks for waitMs and finishes', async () => {
  const seen = [];
  const peer = await startPeer(async ({ req, res, raw, url }) => {
    seen.push(capture(req, raw));
    const first = seen.length === 1;
    // Hold briefly to look like a capable peer, then report running, then done.
    await new Promise((resolve) => setTimeout(resolve, first ? 250 : 0));
    replyEnc(res, 200, first ? { status: 'running', elapsedMs: 250 } : { status: 'done', reply: 'done-reply', elapsedMs: 400 });
  });
  try {
    const out = await awaitPeerAnswer({
      baseUrl: peer.baseUrl,
      secret: SECRET,
      senderId: SENDER,
      sessionId: 'sess-lp',
      timeoutMs: 60_000,
      mode: 'poll',
      pollIntervalMs: 10,
    });
    assert.equal(out.status, 'done');
    assert.equal(out.reply, 'done-reply');
    assert.equal(out.transport, 'long-poll');
    assert.equal(seen.length, 2);
    assert.match(seen[0].path, /^\/v1\/answer\?sessionId=sess-lp&waitMs=25000$/);
    for (const record of seen) {
      assert.equal(record.method, 'GET');
      assert.equal(record.raw.length, 0);
      assert.equal(signatureOk(record, Buffer.alloc(0)), true);
    }
  } finally {
    await peer.close();
  }
});

test('a single hold never exceeds the remaining budget', async () => {
  const seen = [];
  const peer = await startPeer(({ req, res, raw }) => {
    seen.push(capture(req, raw));
    replyEnc(res, 200, seen.length < 2 ? { status: 'running' } : { status: 'done', reply: 'short-budget' });
  });
  try {
    const out = await awaitPeerAnswer({
      baseUrl: peer.baseUrl,
      secret: SECRET,
      senderId: SENDER,
      sessionId: 'sess-cap',
      timeoutMs: 1500,
      waitMs: 25_000,
      mode: 'poll',
      pollIntervalMs: 10,
    });
    assert.equal(out.status, 'done');
    for (const record of seen) {
      const waitMs = Number(new URL('http://x' + record.path).searchParams.get('waitMs'));
      assert.ok(Number.isFinite(waitMs), 'waitMs must be present');
      assert.ok(waitMs <= 1500, 'waitMs ' + waitMs + ' must not exceed the 1.5s budget');
    }
  } finally {
    await peer.close();
  }
});

test('legacy mode never sends waitMs (0.3.1 peer semantics)', async () => {
  const seen = [];
  const peer = await startPeer(({ req, res, raw }) => {
    seen.push(capture(req, raw));
    if (seen.length < 2) replyEnc(res, 200, { status: 'running' });
    else replyEnc(res, 200, { status: 'done', reply: 'legacy-ok' });
  });
  try {
    const out = await awaitPeerAnswer({
      baseUrl: peer.baseUrl,
      secret: SECRET,
      senderId: SENDER,
      sessionId: 'sess-legacy',
      timeoutMs: 10_000,
      mode: 'legacy',
      pollIntervalMs: 20,
    });
    assert.equal(out.status, 'done');
    assert.equal(out.reply, 'legacy-ok');
    assert.equal(out.transport, 'legacy-poll');
    for (const record of seen) assert.equal(record.path, '/v1/answer?sessionId=sess-legacy');
  } finally {
    await peer.close();
  }
});

test('the SSE reader works over real fetch', async () => {
  const evt = (name, value) =>
    'event: ' + name + '\ndata: ' + JSON.stringify({ enc: ENC_VERSION, data: encryptJson(SECRET, value) }) + '\n\n';
  const peer = await startPeer(async ({ req, res, raw, url }) => {
    assert.equal(String(req.method).toUpperCase(), 'GET');
    assert.equal(raw.length, 0);
    assert.equal(signatureOk(capture(req, raw), Buffer.alloc(0)), true);
    assert.match(url.search, /sessionId=sess-sse/);
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache' });
    res.write(evt('status', { status: 'running', elapsedMs: 10 }));
    res.write('event: ping\ndata: ' + JSON.stringify({ enc: ENC_VERSION, data: encryptJson(SECRET, { t: 1 }) }) + '\n\n');
    setTimeout(() => {
      res.write(evt('done', { status: 'done', reply: 'stream-reply', elapsedMs: 40 }));
      res.end();
    }, 30);
  });
  try {
    const out = await readPeerEvents({
      baseUrl: peer.baseUrl,
      secret: SECRET,
      senderId: SENDER,
      sessionId: 'sess-sse',
      timeoutMs: 5000,
    });
    assert.equal(out.ok, true);
    assert.equal(out.reply, 'stream-reply');
  } finally {
    await peer.close();
  }
});

test('a peer without /v1/events falls back to long-polling in auto mode', async () => {
  const paths = [];
  const peer = await startPeer(({ req, res, raw, url }) => {
    paths.push(url.pathname);
    if (url.pathname === '/v1/events') {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end('{"error":"not-found"}');
      return;
    }
    replyEnc(res, 200, { status: 'done', reply: 'polled', elapsedMs: 5 });
  });
  try {
    const out = await awaitPeerAnswer({
      baseUrl: peer.baseUrl,
      secret: SECRET,
      senderId: SENDER,
      sessionId: 'sess-fallback',
      // 预算必须大于 2×STREAM_RESERVE_MS(30s)，否则 awaitPeerAnswer 按设计直接跳过流、
      // 直奔长轮询（2026-11-09 的缺陷正是流吃掉整个预算）。这里要验的是
      // 「流断了就回退」，所以给足预算；404 秒回，测试不会真的等。
      timeoutMs: 70_000,
      mode: 'auto',
      pollIntervalMs: 10,
    });
    assert.equal(out.status, 'done');
    assert.equal(out.reply, 'polled');
    assert.equal(out.transport, 'long-poll');
    assert.deepEqual(paths, ['/v1/events', '/v1/answer']);
  } finally {
    await peer.close();
  }
});
