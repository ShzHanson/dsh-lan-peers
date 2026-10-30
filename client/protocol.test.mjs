import test from 'node:test';
import assert from 'node:assert/strict';
import { canonical, newNonce, newSecret, sign, verifyRequest } from './protocol.mjs';

const secret = newSecret();

test('signature round-trips', () => {
  const ts = Date.now();
  const nonce = newNonce();
  const body = Buffer.from(JSON.stringify({ hello: 'world' }));
  const sig = sign(secret, canonical('POST', '/v1/ask', ts, nonce, body));
  assert.equal(
    verifyRequest({ method: 'POST', path: '/v1/ask', ts, nonce, body, signature: sig, secret }),
    null,
  );
});

test('body tampering breaks the signature', () => {
  const ts = Date.now();
  const nonce = newNonce();
  const body = Buffer.from('{"amount":1}');
  const sig = sign(secret, canonical('POST', '/v1/ask', ts, nonce, body));
  const tampered = Buffer.from('{"amount":9}');
  assert.equal(
    verifyRequest({ method: 'POST', path: '/v1/ask', ts, nonce, body: tampered, signature: sig, secret }),
    'bad-signature',
  );
});

test('stale timestamp is rejected', () => {
  const ts = Date.now() - 5 * 60_000;
  const nonce = newNonce();
  const sig = sign(secret, canonical('GET', '/v1/peers', ts, nonce, Buffer.alloc(0)));
  assert.equal(
    verifyRequest({ method: 'GET', path: '/v1/peers', ts, nonce, body: Buffer.alloc(0), signature: sig, secret }),
    'clock-skew',
  );
});

test('replayed nonce is rejected', () => {
  const ts = Date.now();
  const nonce = newNonce();
  const sig = sign(secret, canonical('GET', '/v1/peers', ts, nonce, Buffer.alloc(0)));
  const seen = new Map();
  const args = { method: 'GET', path: '/v1/peers', ts, nonce, body: Buffer.alloc(0), signature: sig, secret, seenNonces: seen };
  assert.equal(verifyRequest(args), null);
  assert.equal(verifyRequest(args), 'replay');
});

test('wrong secret fails', () => {
  const ts = Date.now();
  const nonce = newNonce();
  const sig = sign(newSecret(), canonical('GET', '/v1/health', ts, nonce, Buffer.alloc(0)));
  assert.equal(
    verifyRequest({ method: 'GET', path: '/v1/health', ts, nonce, body: Buffer.alloc(0), signature: sig, secret }),
    'bad-signature',
  );
});
