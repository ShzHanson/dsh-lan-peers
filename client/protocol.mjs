// dsh-lan-peers — wire protocol helpers (client half).
// The contract lives in DESIGN.md §4: a five-line canonical string signed with
// HMAC-SHA256 over a per-peer secret, base64url encoded.
import crypto from 'node:crypto';

export const MAX_SKEW_MS = 60_000;
export const NONCE_TTL_MS = 120_000;

export const sha256Hex = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

/** Canonical string: METHOD \n PATH \n TS \n NONCE \n sha256hex(body). */
export function canonical(method, path, ts, nonce, body) {
  return [method.toUpperCase(), path, String(ts), nonce, sha256Hex(body ?? Buffer.alloc(0))].join('\n');
}

/** HMAC-SHA256(secret, canonical) as base64url. The host half keys with the
 * secret's UTF-8 bytes by default (DESIGN §4 + server config
 * `secretKeyEncoding`), so the client must do the same. */
export function sign(secret, canonicalString) {
  return crypto
    .createHmac('sha256', Buffer.from(secret, 'utf8'))
    .update(canonicalString, 'utf8')
    .digest('base64url');
}

export function newSecret() {
  return crypto.randomBytes(32).toString('base64url');
}

export function newNonce() {
  return crypto.randomBytes(16).toString('hex');
}

/**
 * Build the four signing headers of one request (DESIGN §4). Shared by the plain
 * request path and by the SSE reader, which cannot use EventSource precisely
 * because EventSource refuses to send custom headers.
 */
export function authHeaders({ secret, senderId, method = 'GET', apiPath, body }) {
  const plain = body === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(body));
  const ts = Date.now();
  const nonce = newNonce();
  return {
    plain,
    headers: {
      'X-Peer-Id': senderId,
      'X-Peer-Ts': String(ts),
      'X-Peer-Nonce': nonce,
      'X-Peer-Sign': sign(secret, canonical(method, apiPath, ts, nonce, plain)),
    },
  };
}

/** Constant-time comparison of two base64url signatures. */
export function sameSignature(a, b) {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

/**
 * Verify an inbound request the way the host half must. Returns null when the
 * request is valid, otherwise a short reason code.
 */
export function verifyRequest({ method, path, ts, nonce, body, signature, secret, seenNonces = new Map(), now = Date.now() }) {
  const stamp = Number(ts);
  if (!Number.isFinite(stamp) || Math.abs(now - stamp) > MAX_SKEW_MS) return 'clock-skew';
  if (typeof nonce !== 'string' || nonce.length < 8) return 'bad-nonce';
  const seenAt = seenNonces.get(nonce);
  if (seenAt !== undefined && now - seenAt <= NONCE_TTL_MS) return 'replay';
  const expected = sign(secret, canonical(method, path, stamp, nonce, body));
  if (!sameSignature(expected, signature ?? '')) return 'bad-signature';
  seenNonces.set(nonce, now);
  for (const [key, at] of seenNonces) if (now - at > NONCE_TTL_MS) seenNonces.delete(key);
  return null;
}
