// dsh-lan-peers · body encryption for peer traffic (v1).
//
// The request signature already proves who sent a body and that it was not
// modified, but it leaves the prompt and the reply readable on the wire. This
// module encrypts those bodies with AES-256-GCM under a key derived from the
// same per-direction secret both sides already share.
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';

export const ENC_HEADER = 'x-peer-enc';
export const ENC_VERSION = 'v1';
const KEY_INFO = 'dsh-lan-peers/body-encryption/v1';
const NONCE_BYTES = 12;
const TAG_BYTES = 16;

/** Derive the 32-byte content key for one direction. */
export function deriveContentKey(secret) {
  const key = hkdfSync('sha256', Buffer.from(String(secret), 'utf8'), 'dsh-lan-peers/v1', KEY_INFO, 32);
  return Buffer.from(key);
}

/** Encrypt bytes → base64url(nonce || ciphertext || tag). */
export function encryptBytes(secret, plaintext) {
  const key = deriveContentKey(secret);
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
  return Buffer.concat([nonce, ciphertext, cipher.getAuthTag()]).toString('base64url');
}

/** Decrypt base64url(nonce || ciphertext || tag); throws on tampering. */
export function decryptBytes(secret, payload) {
  const raw = Buffer.from(String(payload), 'base64url');
  if (raw.length < NONCE_BYTES + TAG_BYTES) throw new Error('bad-encrypted-body');
  const key = deriveContentKey(secret);
  const nonce = raw.subarray(0, NONCE_BYTES);
  const tag = raw.subarray(raw.length - TAG_BYTES);
  const ciphertext = raw.subarray(NONCE_BYTES, raw.length - TAG_BYTES);
  const decipher = createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/** Encrypt a JSON value; returns the wire string. */
export function encryptJson(secret, value) {
  return encryptBytes(secret, Buffer.from(JSON.stringify(value), 'utf8'));
}

/** Decrypt a wire string back into a JSON value. */
export function decryptJson(secret, payload) {
  return JSON.parse(decryptBytes(secret, payload).toString('utf8'));
}
