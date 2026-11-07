/**
 * 测试共享工具：临时 stateDir、配对码/peers 种子、签名请求、轮询 /v1/answer。
 * 不依赖第三方包。测试只在临时目录里造状态，不碰 ~/.dsh。
 */

import { createHash, createHmac, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { createPeerServer } from '../server.mjs';
import { ENC_VERSION, decryptBytes, encryptBytes } from '../../lib/wire-crypto.mjs';
import { listenOnRandomPort } from '../../test-support/ports.mjs';

/** 每次调用都新建一个独立的临时 stateDir */
export function makeTempStateDir(prefix = 'dsh-lan-peers-test-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

export function writeJson0600(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

export function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

export function fileMode(file) {
  return fs.statSync(file).mode & 0o777;
}

export function sha256Hex(value) {
  return createHash('sha256').update(value ?? Buffer.alloc(0)).digest('hex');
}

/** 造一个对端条目：inboundSecret 是「它发来的请求该用哪把密钥签名」= §3 的 T */
export function peerFixture(peerId, overrides = {}) {
  return {
    peerId,
    name: overrides.name ?? `name-${peerId}`,
    secret: overrides.secret ?? `secret-${peerId}-outbound`,
    inboundSecret: overrides.inboundSecret ?? `secret-${peerId}-inbound`,
    baseUrl: overrides.baseUrl ?? `http://192.168.1.${peerId.length + 10}:7788`,
  };
}

/** 直接写 peers.json（0600），跳过配对流程，便于认证类用例 */
export function seedPeers(stateDir, peers) {
  const addedAt = new Date().toISOString();
  const map = {};
  for (const peer of peers) {
    map[peer.peerId] = {
      name: peer.name,
      baseUrl: peer.baseUrl ?? null,
      secret: peer.secret,
      inboundSecret: peer.inboundSecret ?? null,
      addedAt,
      lastSeen: null,
    };
  }
  writeJson0600(path.join(stateDir, 'peers.json'), { peers: map });
}

// 端口助手已搬到 test-support/ports.mjs（client / lib / host/test 三处共用同一份实现）。
// 这里 re-export，是为了既有的 import { listenOnRandomPort } from './helpers.mjs' 不破。
export {
  FETCH_BLOCKED_PORTS, fetchRejectsPort, isFetchBlockedPort, listenOnRandomPort,
} from '../../test-support/ports.mjs';

/**
 * 起一个只在 127.0.0.1 上监听的测试服务，结束后自动 close + 删临时目录。
 * @returns {Promise<{server: object, stateDir: string, baseUrl: string, info: object}>}
 */
export async function startServer(t, overrides = {}) {
  const stateDir = overrides.stateDir ?? makeTempStateDir();
  const server = createPeerServer({
    listenHost: '127.0.0.1',
    // 这组用例验证签名/时钟/重放语义；加密路径见 encryption.test.mjs
    requireEncryption: false,
    // 安全审计 S1/H4 的限流默认开启，但这批用例验证的是功能语义，
    // 不是限流语义：同一回环 IP 会做多次失败配对、同一 peerId 会连发多次 ask，
    // 开着限流会把「一次性配对码」「ask→answer」这类断言变成 429。
    // 限流本身由 rate-limit.test.mjs 显式打开开关覆盖；调用方可以按需覆盖回去。
    pairRateLimit: false,
    askRateLimit: false,
    ...overrides,
    stateDir,
  });
  const info = await listenOnRandomPort(server, '127.0.0.1');
  t.after(async () => {
    await server.close();
    fs.rmSync(stateDir, { recursive: true, force: true });
  });
  return { server, stateDir, baseUrl: info.url, info };
}

function toRawBody(value) {
  if (value == null) return Buffer.alloc(0);
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (typeof value === 'string') return Buffer.from(value, 'utf8');
  return Buffer.from(JSON.stringify(value), 'utf8');
}

/**
 * 发一个请求（默认签名）。可以故意造坏签名 / 重放 / 篡改 body / 篡改 path。
 *
 * @param {object} options
 *   path          实际请求的 path（含 query）
 *   signPath      参与签名的 path（默认同 path，用于测试路径篡改）
 *   body          参与签名并发送的 body（对象自动 JSON.stringify）
 *   overrideBody  只改发送的 body，签名仍按 body（测试 body 篡改）
 *   ts / nonce    固定时间戳 / nonce（重放、时钟偏移）
 *   signature     覆盖签名（测试 bad-signature）
 *   keyEncoding   'utf8' | 'base64url'
 *   now           取时间戳的函数（配合假时钟）
 */
export async function request(baseUrl, options = {}) {
  const {
    method = 'GET',
    path: requestPath = '/v1/health',
    signPath,
    body,
    overrideBody,
    signed = true,
    peerId,
    secret,
    ts,
    nonce = randomBytes(16).toString('hex'),
    keyEncoding = 'utf8',
    encrypt = false,
    signature,
    headers: extraHeaders = {},
    now,
  } = options;

  const nowFn = typeof now === 'function' ? now : Date.now;
  const effectiveTs = ts ?? nowFn();
  const signedBody = toRawBody(body);
  const sentBody = overrideBody === undefined ? signedBody : toRawBody(overrideBody);
  const canonicalPath = signPath ?? requestPath;
  const headers = { ...extraHeaders };
  let canonical = null;

  if (signed) {
    canonical = [
      method.toUpperCase(),
      canonicalPath,
      String(effectiveTs),
      nonce,
      sha256Hex(signedBody),
    ].join('\n');
    const key = keyEncoding === 'base64url'
      ? Buffer.from(String(secret ?? ''), 'base64url')
      : Buffer.from(String(secret ?? ''), 'utf8');
    headers['x-peer-id'] = String(peerId ?? '');
    headers['x-peer-ts'] = String(effectiveTs);
    headers['x-peer-nonce'] = nonce;
    headers['x-peer-sign'] = createHmac('sha256', key).update(canonical, 'utf8').digest('base64url');
    if (signature != null) headers['x-peer-sign'] = signature;
  }

  // 加密信封：签名仍是明文，线上传密文（与 client/peer-call.mjs 一致）。
  // overrideBody 会原样替换线上内容，用于模拟"密文被篡改"。
  let wireBody = sentBody;
  if (encrypt) {
    headers['x-peer-enc'] = ENC_VERSION;
    wireBody = signedBody.length ? Buffer.from(encryptBytes(secret, signedBody), 'utf8') : Buffer.alloc(0);
    if (overrideBody !== undefined) wireBody = toRawBody(overrideBody);
  }

  const target = new URL(requestPath, baseUrl).toString();
  let response;
  try {
    response = await fetch(target, {
      method,
      headers,
      body: method === 'GET' || method === 'HEAD' ? undefined : wireBody,
    });
  } catch (error) {
    // 带着目标 URL 重抛：并发跑全量时偶发「bad port」要能一眼看出是哪个端口
    throw new Error('fetch ' + method + ' ' + target + ' failed: ' + (error?.cause?.message ?? error?.message ?? error));
  }
  const text = await response.text();
  let json = null;
  try {
    const parsed = JSON.parse(text);
    json = parsed && parsed.enc === ENC_VERSION && typeof parsed.data === 'string'
      ? JSON.parse(decryptBytes(secret, parsed.data).toString('utf8'))
      : parsed;
  } catch {
    /* 非 JSON 响应（或解密失败）留给调用方看 text */
  }
  return {
    status: response.status,
    json,
    text,
    responseHeaders: response.headers,
    canonical,
    signature: headers['x-peer-sign'],
    nonce,
    ts: effectiveTs,
    sentPath: requestPath,
  };
}

/** 轮询 /v1/answer 直到不是 running */
export async function pollAnswer(baseUrl, {
  sessionId,
  peerId,
  secret,
  now,
  timeoutMs = 5000,
  intervalMs = 25,
  requestOptions = {},
}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const res = await request(baseUrl, {
      path: `/v1/answer?sessionId=${encodeURIComponent(sessionId)}`,
      peerId,
      secret,
      now,
      ...requestOptions,
    });
    if (res.status !== 200) throw new Error(`answer failed: ${res.status} ${res.text}`);
    if (res.json?.status !== 'running') return res.json;
    await sleep(intervalMs);
  }
  throw new Error(`answer did not settle within ${timeoutMs}ms`);
}
