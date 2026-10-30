// dsh-lan-peers · peer progress stream (SSE), client half — v0.4.0.
//
// EventSource cannot be used against a peer: every /v1/* request must carry the
// per-peer HMAC signature headers and EventSource does not let a caller set
// headers. The stream is read by hand from fetch()'s ReadableStream instead, and
// each `data:` payload is a v1-encrypted envelope decrypted event by event (a
// fresh nonce per event, same key as /v1/answer).
//
// Failure of any kind is reported as `{ok: false, reason}` — never thrown — so
// the caller can continue the same session over /v1/answer long-polling without
// replaying events it already saw.
import { ENC_VERSION, decryptJson } from '../lib/wire-crypto.mjs';
import { authHeaders } from './protocol.mjs';

export const SSE_ACCEPT = 'text/event-stream';

const reason = (error) => String(error?.message ?? error);

/**
 * Parse an SSE byte stream into `{event, data}` records.
 *
 * Handles CRLF, per-field leading spaces, comment/keep-alive lines (`:`), several
 * `data:` lines per event, and lines split across chunk boundaries. `id`/`retry`
 * are parsed away: this stream has no resumption semantics.
 */
export async function* parseSseStream(body) {
  if (!body || typeof body.getReader !== 'function') throw new Error('parseSseStream needs a ReadableStream');
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let event = '';
  let data = [];
  let hasData = false;
  const out = [];

  const feed = (line) => {
    if (line === '') {
      if (hasData) out.push({ event: event || 'message', data: data.join('\n') });
      event = '';
      data = [];
      hasData = false;
      return;
    }
    if (line.startsWith(':')) return;
    const colon = line.indexOf(':');
    const field = colon === -1 ? line : line.slice(0, colon);
    let value = colon === -1 ? '' : line.slice(colon + 1);
    if (value.startsWith(' ')) value = value.slice(1);
    if (field === 'event') event = value;
    else if (field === 'data') {
      data.push(value);
      hasData = true;
    }
  };

  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let index;
      while ((index = buffer.indexOf('\n')) !== -1) {
        let line = buffer.slice(0, index);
        buffer = buffer.slice(index + 1);
        if (line.endsWith('\r')) line = line.slice(0, -1);
        feed(line);
        while (out.length) yield out.shift();
      }
    }
    buffer += decoder.decode();
    if (buffer.length) {
      let line = buffer;
      if (line.endsWith('\r')) line = line.slice(0, -1);
      feed(line);
    }
    // A stream cut mid-event still delivers what it received.
    feed('');
    while (out.length) yield out.shift();
  } finally {
    try { await reader.cancel(); } catch {}
    try { reader.releaseLock(); } catch {}
  }
}

/** Decrypt one event payload: the wire form is `{"enc":"v1","data":"<b64url>"}`. */
export function decryptSseEvent(secret, data) {
  const text = String(data ?? '').trim();
  if (!text) throw new Error('empty-event-payload');
  let envelope;
  try {
    envelope = JSON.parse(text);
  } catch {
    throw new Error('bad-event-payload');
  }
  if (!envelope || envelope.enc !== ENC_VERSION || typeof envelope.data !== 'string') {
    throw new Error('unencrypted-event-payload');
  }
  return decryptJson(secret, envelope.data);
}

/**
 * Subscribe to a peer's /v1/events stream and return the first terminal状态.
 *
 * Returns `{ok: true, status: 'done'|'error', ...}` on a terminal event, or
 * `{ok: false, reason}` when the caller must fall back to long-polling (non-200,
 * wrong content type, broken/decryption-failing stream, or a stream that ended
 * while the session was still running).
 */
export async function readPeerEvents({
  baseUrl,
  secret,
  senderId,
  sessionId,
  signal,
  timeoutMs = 60_000,
  onEvent,
  fetchImpl = fetch,
}) {
  const apiPath = `/v1/events?sessionId=${encodeURIComponent(String(sessionId ?? ''))}`;
  const { headers } = authHeaders({ secret, senderId, method: 'GET', apiPath });
  const url = new URL(apiPath, String(baseUrl)).toString();
  const controller = new AbortController();
  const timer = setTimeout(
    () => controller.abort(new Error('stream-timeout')),
    Math.max(1000, Number(timeoutMs) || 60_000),
  );
  const forwardAbort = () => controller.abort(signal?.reason);
  if (signal) {
    if (signal.aborted) controller.abort(signal.reason);
    else signal.addEventListener('abort', forwardAbort, { once: true });
  }

  try {
    let res;
    try {
      res = await fetchImpl(url, {
        method: 'GET',
        headers: { ...headers, Accept: SSE_ACCEPT, 'X-Peer-Enc': ENC_VERSION },
        signal: controller.signal,
      });
    } catch (error) {
      return { ok: false, reason: `stream-error: ${reason(error)}` };
    }
    if (res.status !== 200) {
      try { await res.body?.cancel?.(); } catch {}
      return { ok: false, reason: `http-${res.status}` };
    }
    const contentType = String(res.headers?.get?.('content-type') ?? '');
    if (!contentType.includes(SSE_ACCEPT)) {
      try { await res.body?.cancel?.(); } catch {}
      return { ok: false, reason: 'not-event-stream' };
    }

    let events = 0;
    try {
      for await (const record of parseSseStream(res.body)) {
        const name = String(record.event || 'message');
        if (name === 'ping') {
          onEvent?.({ type: 'ping', transport: 'sse' });
          continue;
        }
        let payload;
        try {
          payload = decryptSseEvent(secret, record.data);
        } catch (error) {
          return { ok: false, reason: `bad-event: ${reason(error)}` };
        }
        events += 1;
        const status = String(
          payload?.status ?? (name === 'done' ? 'done' : name === 'error' ? 'error' : 'running'),
        );
        onEvent?.({
          type: name,
          transport: 'sse',
          status,
          elapsedMs: payload?.elapsedMs,
          reply: payload?.reply,
          error: payload?.error,
        });
        if (status === 'done') {
          return { ok: true, status: 'done', reply: String(payload?.reply ?? ''), elapsedMs: payload?.elapsedMs };
        }
        if (status === 'error') {
          return { ok: true, status: 'error', error: String(payload?.error ?? 'peer-error'), elapsedMs: payload?.elapsedMs };
        }
      }
    } catch (error) {
      return { ok: false, reason: `stream-error: ${reason(error)}` };
    }
    return { ok: false, reason: events ? 'stream-ended' : 'stream-empty' };
  } finally {
    clearTimeout(timer);
    try { signal?.removeEventListener?.('abort', forwardAbort); } catch {}
  }
}
