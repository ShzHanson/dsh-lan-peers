// dsh-lan-peers · client SSE reader tests.
//
// Covers the hand-written text/event-stream parser (multi-event, CRLF, chunk
// boundaries mid-line, comments, multi-line data, ping) and the per-event
// encrypted envelope, plus every fallback shape the caller relies on.
import test from 'node:test';
import assert from 'node:assert/strict';
import { encryptJson } from '../lib/wire-crypto.mjs';
import { decryptSseEvent, parseSseStream, readPeerEvents } from './sse.mjs';

const SECRET = 'sse-test-secret-0123456789';
const encoder = new TextEncoder();

function streamOf(chunks) {
  return new ReadableStream({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(encoder.encode(chunk));
      controller.close();
    },
  });
}

/** An SSE body carrying one encrypted event of the given plaintext object. */
function eventBlock(name, value, { arrayBuffers = false } = {}) {
  return 'event: ' + name + '\ndata: ' + JSON.stringify({ enc: 'v1', data: encryptJson(SECRET, value) }) + '\n\n';
}

async function collect(body) {
  const out = [];
  for await (const record of parseSseStream(body)) out.push(record);
  return out;
}

function fakeFetch(impl) {
  const calls = [];
  const spy = async (url, init) => {
    calls.push({ url, init });
    return impl(url, init);
  };
  spy.calls = calls;
  return spy;
}

const sseResponse = (chunks, status = 200) =>
  new Response(streamOf(chunks), { status, headers: { 'content-type': 'text/event-stream' } });

test('parses several events, CRLF line endings and field spacing', async () => {
  const body = streamOf([
    'event: status\r\ndata: {"n":1}\r\n\r\n',
    'event: done\r\ndata: {"n":2}\r\n\r\n',
  ]);
  assert.deepEqual(await collect(body), [
    { event: 'status', data: '{"n":1}' },
    { event: 'done', data: '{"n":2}' },
  ]);
});

test('a line split across chunk boundaries is reassembled', async () => {
  const body = streamOf([
    'event: sta',
    'tus\ndata: {"half":',
    'true}\n',
    '\nevent: done\ndata: {}\n\n',
  ]);
  assert.deepEqual(await collect(body), [
    { event: 'status', data: '{"half":true}' },
    { event: 'done', data: '{}' },
  ]);
});

test('ignores comments and id/retry, joins multiple data lines', async () => {
  const body = streamOf([': keep-alive\nid: 7\nretry: 500\nevent: status\ndata: one\ndata: two\n\n']);
  assert.deepEqual(await collect(body), [{ event: 'status', data: 'one\ntwo' }]);
});

test('an event without a trailing blank line is still delivered', async () => {
  const body = streamOf(['event: done\ndata: {"x":1}']);
  assert.deepEqual(await collect(body), [{ event: 'done', data: '{"x":1}' }]);
});

test('decrypts an encrypted event envelope', () => {
  const data = JSON.stringify({ enc: 'v1', data: encryptJson(SECRET, { status: 'done', reply: 'hi' }) });
  assert.deepEqual(decryptSseEvent(SECRET, data), { status: 'done', reply: 'hi' });
});

test('rejects a plaintext / wrong-version payload instead of trusting it', () => {
  assert.throws(() => decryptSseEvent(SECRET, JSON.stringify({ status: 'done', reply: 'raw' })), /unencrypted-event-payload/);
  assert.throws(() => decryptSseEvent(SECRET, 'not json'), /bad-event-payload/);
  assert.throws(() => decryptSseEvent(SECRET, ''), /empty-event-payload/);
});

test('readPeerEvents decrypts per-event envelopes and stops on done', async () => {
  const fetchImpl = fakeFetch(async () =>
    sseResponse([
      eventBlock('status', { status: 'running', elapsedMs: 12 }),
      eventBlock('ping', { t: 1 }),
      eventBlock('status', { status: 'running', elapsedMs: 900 }),
      eventBlock('done', { status: 'done', reply: 'final answer', elapsedMs: 950 }),
    ]),
  );
  const seen = [];
  const out = await readPeerEvents({
    baseUrl: 'http://peer.invalid:7788',
    secret: SECRET,
    senderId: 'peer-a',
    sessionId: 'sess-1',
    timeoutMs: 5000,
    fetchImpl,
    onEvent: (info) => seen.push(info.type),
  });
  assert.equal(out.ok, true);
  assert.equal(out.status, 'done');
  assert.equal(out.reply, 'final answer');
  assert.deepEqual(seen, ['status', 'ping', 'status', 'done']);

  const [{ url, init }] = fetchImpl.calls;
  assert.match(url, /\/v1\/events\?sessionId=sess-1$/);
  assert.equal(init.headers.Accept, 'text/event-stream');
  // The whole reason EventSource is unusable: these headers must be sent.
  assert.equal(init.headers['X-Peer-Id'], 'peer-a');
  assert.ok(init.headers['X-Peer-Sign']);
  assert.ok(init.headers['X-Peer-Nonce']);
  assert.equal(init.headers['X-Peer-Enc'], 'v1');
});

test('the done event terminates the read even if the stream stays open', async () => {
  let controllerRef = null;
  const body = new ReadableStream({
    start(controller) {
      controllerRef = controller;
      controller.enqueue(encoder.encode(eventBlock('done', { status: 'done', reply: 'x' })));
      // Deliberately never closed: a server that forgets to end the stream must
      // not hang the caller.
    },
  });
  const out = await readPeerEvents({
    baseUrl: 'http://peer.invalid:7788',
    secret: SECRET,
    senderId: 'peer-a',
    sessionId: 'sess-2',
    timeoutMs: 5000,
    fetchImpl: fakeFetch(async () => new Response(body, { headers: { 'content-type': 'text/event-stream' } })),
  });
  assert.equal(out.ok, true);
  assert.equal(out.reply, 'x');
  try { controllerRef.close(); } catch {}
});

test('an error event is terminal and carries the reason', async () => {
  const out = await readPeerEvents({
    baseUrl: 'http://peer.invalid:7788',
    secret: SECRET,
    senderId: 'peer-a',
    sessionId: 'sess-3',
    timeoutMs: 5000,
    fetchImpl: fakeFetch(async () => sseResponse([eventBlock('error', { status: 'error', error: 'runner-error', elapsedMs: 5 })])),
  });
  assert.equal(out.ok, true);
  assert.equal(out.status, 'error');
  assert.equal(out.error, 'runner-error');
});

test('non-200 falls back (no throw) so the caller can long-poll', async () => {
  const out = await readPeerEvents({
    baseUrl: 'http://peer.invalid:7788',
    secret: SECRET,
    senderId: 'peer-a',
    sessionId: 'sess-4',
    timeoutMs: 5000,
    fetchImpl: fakeFetch(async () => new Response('{"error":"not-found"}', { status: 404, headers: { 'content-type': 'application/json' } })),
  });
  assert.deepEqual(out, { ok: false, reason: 'http-404' });
});

test('a 200 that is not an event stream falls back', async () => {
  const out = await readPeerEvents({
    baseUrl: 'http://peer.invalid:7788',
    secret: SECRET,
    senderId: 'peer-a',
    sessionId: 'sess-5',
    timeoutMs: 5000,
    fetchImpl: fakeFetch(async () => new Response('{"ok":true}', { headers: { 'content-type': 'application/json' } })),
  });
  assert.deepEqual(out, { ok: false, reason: 'not-event-stream' });
});

test('a stream that ends while still running falls back', async () => {
  const out = await readPeerEvents({
    baseUrl: 'http://peer.invalid:7788',
    secret: SECRET,
    senderId: 'peer-a',
    sessionId: 'sess-6',
    timeoutMs: 5000,
    fetchImpl: fakeFetch(async () => sseResponse([eventBlock('status', { status: 'running', elapsedMs: 30 })])),
  });
  assert.equal(out.ok, false);
  assert.equal(out.reason, 'stream-ended');
});

test('a tampered envelope falls back instead of being trusted', async () => {
  const good = encryptJson(SECRET, { status: 'done', reply: 'x' });
  const tampered = Buffer.from(good, 'base64url');
  tampered[tampered.length - 1] ^= 0xff;
  const out = await readPeerEvents({
    baseUrl: 'http://peer.invalid:7788',
    secret: SECRET,
    senderId: 'peer-a',
    sessionId: 'sess-7',
    timeoutMs: 5000,
    fetchImpl: fakeFetch(async () =>
      sseResponse(['event: done\ndata: ' + JSON.stringify({ enc: 'v1', data: tampered.toString('base64url') }) + '\n\n']),
    ),
  });
  assert.equal(out.ok, false);
  assert.match(out.reason, /^bad-event:/);
});

test('a transport failure falls back rather than throwing', async () => {
  const out = await readPeerEvents({
    baseUrl: 'http://peer.invalid:7788',
    secret: SECRET,
    senderId: 'peer-a',
    sessionId: 'sess-8',
    timeoutMs: 5000,
    fetchImpl: fakeFetch(async () => {
      throw new Error('ECONNREFUSED');
    }),
  });
  assert.equal(out.ok, false);
  assert.match(out.reason, /stream-error: ECONNREFUSED/);
});
