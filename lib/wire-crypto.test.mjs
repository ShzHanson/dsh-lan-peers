import test from 'node:test';
import assert from 'node:assert/strict';
import { decryptBytes, decryptJson, deriveContentKey, encryptBytes, encryptJson } from './wire-crypto.mjs';

const secret = 'test-secret-0123456789abcdefghijklmnopqrstuvwxyz';

test('round-trips bytes', () => {
  const payload = Buffer.from('局域网协同：prompt 与 reply');
  const wire = encryptBytes(secret, payload);
  assert.ok(!wire.includes('prompt'));
  assert.equal(decryptBytes(secret, wire).toString('utf8'), payload.toString('utf8'));
});

test('round-trips JSON', () => {
  const value = { reply: '测试通过', nested: { n: 1 } };
  assert.deepEqual(decryptJson(secret, encryptJson(secret, value)), value);
});

test('ciphertext is non-deterministic', () => {
  const a = encryptBytes(secret, Buffer.from('same'));
  const b = encryptBytes(secret, Buffer.from('same'));
  assert.notEqual(a, b);
});

test('tampering fails authentication', () => {
  const wire = encryptBytes(secret, Buffer.from('hello'));
  const raw = Buffer.from(wire, 'base64url');
  raw[raw.length - 1] ^= 0xff;
  assert.throws(() => decryptBytes(secret, raw.toString('base64url')));
});

test('a different secret cannot decrypt', () => {
  const wire = encryptBytes(secret, Buffer.from('hello'));
  assert.throws(() => decryptBytes('another-secret', wire));
});

test('keys are 32 bytes and stable per secret', () => {
  assert.equal(deriveContentKey(secret).length, 32);
  assert.deepEqual(deriveContentKey(secret), deriveContentKey(secret));
  assert.notDeepEqual(deriveContentKey(secret), deriveContentKey(secret + 'x'));
});
