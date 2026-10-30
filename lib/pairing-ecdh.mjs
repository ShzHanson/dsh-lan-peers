// dsh-lan-peers · ECDH (P-256) secret wrapping for the two-round pairing (v0.4.0).
//
// Round 1 of /v1/pair carries no secret any more: each side only publishes an
// ephemeral public key. Both derive the same 32-byte wrap key from the ECDH
// shared secret and AES-256-GCM wrap the real peer secrets with it, so the
// plaintext secret never touches the wire.
//
// The four exported functions are a frozen cross-half interface (client half
// imports them unchanged); everything else here is additive.
import {
  createCipheriv,
  createDecipheriv,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
} from 'node:crypto';

export const PAIR_CURVE = 'P-256';
export const PAIR_PROTOCOL_VERSION = 1;
export const WRAP_KEY_BYTES = 32;

/** §2 冻结派生参数：W = HKDF-SHA256(Z, salt, info, 32) */
const HKDF_SALT = Buffer.from('dsh-lan-peers/pair/v1', 'utf8');
const HKDF_INFO = Buffer.from('dsh-lan-peers/pair/wrap/v1', 'utf8');
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const POINT_BYTES = 65;

/**
 * P-256 SubjectPublicKeyInfo prefix. Node only exports public keys as SPKI DER,
 * while the wire format is the raw 65-byte uncompressed point, so the 26-byte
 * prefix is stripped on export and prepended on import.
 */
const SPKI_PREFIX = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');

/** Export a P-256 public KeyObject as base64url(65-byte uncompressed point). */
export function exportPublicKeyB64url(publicKey) {
  const der = Buffer.from(publicKey.export({ type: 'spki', format: 'der' }));
  if (der.length !== SPKI_PREFIX.length + POINT_BYTES || !der.subarray(0, SPKI_PREFIX.length).equals(SPKI_PREFIX)) {
    throw new TypeError('public key must be a P-256 key');
  }
  return der.subarray(SPKI_PREFIX.length).toString('base64url');
}

/** Parse base64url(65-byte P-256 point) into a public KeyObject; throws when malformed. */
export function importPublicKey(publicKeyB64url) {
  if (typeof publicKeyB64url !== 'string' || publicKeyB64url === '') {
    throw new TypeError('public key must be a base64url string');
  }
  const raw = Buffer.from(publicKeyB64url, 'base64url');
  if (raw.length !== POINT_BYTES || raw[0] !== 0x04) {
    throw new TypeError('public key must be a 65-byte uncompressed P-256 point');
  }
  try {
    return createPublicKey({
      key: Buffer.concat([SPKI_PREFIX, raw]),
      format: 'der',
      type: 'spki',
    });
  } catch (err) {
    throw new TypeError(`invalid P-256 public key: ${err?.message ?? err}`);
  }
}

/** Shape check used by the host to answer 400 bad-request before any crypto runs. */
export function isValidPublicKeyB64url(value) {
  try {
    importPublicKey(value);
    return true;
  } catch {
    return false;
  }
}

/** Generate one ephemeral P-256 key pair; publicKeyB64url is the wire form. */
export function generateKeyPair() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return { privateKey, publicKeyB64url: exportPublicKeyB64url(publicKey) };
}

/** W = HKDF-SHA256(ECDH(myPriv, peerPub), salt, info, 32) — 32 bytes. */
export function deriveWrapKey(privateKey, peerPublicKeyB64url) {
  const publicKey = importPublicKey(peerPublicKeyB64url);
  let shared;
  try {
    shared = diffieHellman({ privateKey, publicKey });
  } catch (err) {
    throw new TypeError(`ECDH failed: ${err?.message ?? err}`);
  }
  if (shared.length !== 32) throw new Error('ECDH shared secret must be 32 bytes (P-256 X coordinate)');
  return Buffer.from(hkdfSync('sha256', shared, HKDF_SALT, HKDF_INFO, WRAP_KEY_BYTES));
}

function assertWrapKey(wrapKey) {
  if (!Buffer.isBuffer(wrapKey) || wrapKey.length !== WRAP_KEY_BYTES) {
    throw new TypeError('wrap key must be a 32-byte Buffer');
  }
}

/** AES-256-GCM(W) over JSON.stringify(value) -> base64url(nonce || ciphertext || tag). */
export function wrapSecret(wrapKey, plainObject) {
  assertWrapKey(wrapKey);
  if (plainObject === null || typeof plainObject !== 'object' || Array.isArray(plainObject)) {
    throw new TypeError('wrapped value must be a plain object');
  }
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv('aes-256-gcm', wrapKey, nonce);
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(JSON.stringify(plainObject), 'utf8')),
    cipher.final(),
  ]);
  return Buffer.concat([nonce, ciphertext, cipher.getAuthTag()]).toString('base64url');
}

/** Reverse of wrapSecret; throws on tampering, wrong key, or a non-object payload. */
export function unwrapSecret(wrapKey, wrappedB64url) {
  assertWrapKey(wrapKey);
  if (typeof wrappedB64url !== 'string') throw new TypeError('wrapped secret must be a base64url string');
  const raw = Buffer.from(wrappedB64url, 'base64url');
  if (raw.length < NONCE_BYTES + TAG_BYTES) throw new Error('bad-wrapped-secret');
  const nonce = raw.subarray(0, NONCE_BYTES);
  const tag = raw.subarray(raw.length - TAG_BYTES);
  const ciphertext = raw.subarray(NONCE_BYTES, raw.length - TAG_BYTES);
  const decipher = createDecipheriv('aes-256-gcm', wrapKey, nonce);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  let parsed;
  try {
    parsed = JSON.parse(plaintext);
  } catch {
    throw new Error('wrapped secret is not valid JSON');
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('wrapped secret must decode to an object');
  }
  return parsed;
}
