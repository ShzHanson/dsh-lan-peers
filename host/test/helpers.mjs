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

/**
 * fetch（undici）拒绝的端口 —— WHATWG 的 bad port 列表。
 * listen(0) 由操作系统发临时端口，偶尔会撞上其中一个（实测撞到 10080），
 * 那时所有 fetch 直接抛 "bad port"，测试就不明不白飘红。这里显式避开。
 */
export const FETCH_BLOCKED_PORTS = new Set([
  1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 77, 79, 87, 95,
  101, 102, 103, 104, 109, 110, 111, 113, 115, 117, 119, 123, 135, 137, 139, 143, 161, 179,
  389, 427, 465, 512, 513, 514, 515, 526, 530, 531, 532, 540, 548, 554, 556, 563, 587, 601,
  636, 989, 990, 993, 995, 1719, 1720, 1723, 2049, 3659, 4045, 5060, 5061, 6000, 6566,
  4190, 6665, 6666, 6667, 6668, 6669, 6679, 6697, 10080,
]);

export function isFetchBlockedPort(port) {
  return FETCH_BLOCKED_PORTS.has(Number(port));
}

/**
 * 这条端口能不能被 undici fetch？只关心 "bad port"，其它错误（连接拒绝等）都算可用。
 * 为什么不用静态列表兜底：手抄 WHATWG 列表会漏项（实测漏过 6679、4190），
 * 一旦漏项就是"不明原因的飘红"。这里直接问一次 fetch，免疫列表漂移。
 */
async function fetchRejectsPort(host, port) {
  try {
    await fetch('http://' + host + ':' + port + '/v1/health', { signal: AbortSignal.timeout(2000) });
    return false;
  } catch (error) {
    const text = String(error?.cause?.message ?? error?.message ?? error);
    return /bad port/i.test(text);
  }
}

/** listen(0) + 避开 fetch 黑名单端口：静态表快筛 + 真 fetch 自证，撞上就换一个（最多 5 次） */
export async function listenOnRandomPort(server, host = '127.0.0.1', attempts = 5) {
  let info = null;
  for (let index = 0; index < attempts; index += 1) {
    info = await server.listen(0, host);
    if (!isFetchBlockedPort(info.port) && !(await fetchRejectsPort(host, info.port))) return info;
    await server.close();
  }
  throw new Error('no fetch-safe ephemeral port after ' + attempts + ' attempts (last=' + info?.port + ')');
}

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
