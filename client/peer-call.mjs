// dsh-lan-peers · peer calls, client half.
//
// The signature covers the *plaintext* JSON body (so the host can verify after
// decrypting), while the wire carries only AES-256-GCM ciphertext. Replay and
// clock checks still ride on the ts/nonce inside the canonical string.
//
// Three call shapes live here, in increasing order of patience:
//   callPeer         one signed + encrypted request/response
//                    (GET/HEAD carry no body at all — undici rejects
//                    `fetch(url, {method:'GET', body})` with "Request with GET/HEAD
//                    method cannot have body"; only POST/PUT send ciphertext)
//   awaitPeerAnswer  wait for a session's final state: SSE when the peer
//                    advertises "stream", otherwise /v1/answer (v0.4.0 long-poll,
//                    or the exact 0.3.1 1.5s cadence against an old peer)
//   pairPeer         one-time pairing: ECDH two-round when both sides can, plaintext
//                    legacy otherwise
import os from 'node:os';
import { ENC_VERSION, decryptJson, encryptBytes } from '../lib/wire-crypto.mjs';
import { authHeaders, newSecret } from './protocol.mjs';
import { readPeerEvents } from './sse.mjs';

export const DEFAULT_ANSWER_WAIT_MS = 25_000;
export const MAX_ANSWER_WAIT_MS = 25_000;
/** 0.3.1 cadence: how long to sleep between polls when the peer cannot hold. */
export const LEGACY_POLL_MS = 1_500;
/** A peer that answers `running` faster than this did not hold the request. */
const FAST_ANSWER_MS = 500;
/**
 * SSE 阶段只准花掉预算的一小块，必须给长轮询留出保底时间。
 * 2026-11-09 实测：7/7 次 ask 都把整个预算花在 /v1/events 上，流一断就正好到期，
 * `while (Date.now() < deadline)` 一次都不执行，答案明明可取却没人再去问一次。
 * 保留时长 = 一次满额 hold（MAX_ANSWER_WAIT_MS 25s）再加 5s 余量。
 */
export const STREAM_RESERVE_MS = 30_000;
/** SSE 自身也设上限：再长也只是白等，答案早已可由 /v1/answer 取回。 */
export const STREAM_CAP_MS = 300_000;
/** 预算 <= 2×保留时长时流拿不到有意义的窗口，直接轮询（见下方 streamBudget 判断）。 */
/** 可重试失败的指数退避：500ms 起，封顶 4s。 */
const POLL_BACKOFF_BASE_MS = 500;
const POLL_BACKOFF_CAP_MS = 4_000;
/** 4xx 里仍然可重试的：408 超时说话不算话，429 就是让你退避重试。 */
const RETRYABLE_4XX = new Set([408, 429]);
/**
 * 「对端现在就不在」这一类：重试不会变好，只会把 1s 的报错拖成 5~15 分钟的假死，
 * 用户看到的就是「lan_peer 卡住了」。连续这么多次就收手：第一次吸收毛刺
 * （对端刚重启、一次丢包），第二次还拒就连共识都算不上——它就是不在了。
 */
const DEAD_PEER_STREAK = 2;
const OFFLINE_CODES = new Set([
  'ECONNREFUSED',
  'ECONNRESET',
  'EPIPE',
  'ENOTFOUND',
  'EAI_AGAIN',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'ENETDOWN',
  'EADDRNOTAVAIL',
]);

/**
 * 传输层分类：返回让这次失败「确定性」的那个 errno，没有就返回 null（= 值得重试）。
 * 只被 callPeer 抛出的错误调用；带 status 的已经是 HTTP 层，交给 fatal 分支。
 */
function offlineCodeOf(error) {
  if (Number(error?.status)) return null;
  const codes = [];
  for (let e = error, hop = 0; e && hop < 4; e = e.cause, hop += 1) {
    if (e.code) codes.push(String(e.code));
    // happy-eyeballs 失败时 cause 是 AggregateError，每个地址一个 code
    if (Array.isArray(e.errors)) for (const inner of e.errors.slice(0, 4)) if (inner?.code) codes.push(String(inner.code));
  }
  return (
    codes.find(
      (code) => OFFLINE_CODES.has(code) || /^(ERR_TLS_|CERT_|UNABLE_TO_|ERR_SSL_|EPROTO)/.test(code),
    ) ?? null
  );
}
const PROBE_TTL_MS = 30_000;
const probeCache = new Map();

const message = (error) => String(error?.message ?? error);

function sleep(ms, signal) {
  if (!(ms > 0)) return Promise.resolve();
  return new Promise((resolve) => {
    const timer = setTimeout(done, ms);
    function done() {
      clearTimeout(timer);
      try { signal?.removeEventListener?.('abort', done); } catch {}
      resolve();
    }
    try { signal?.addEventListener?.('abort', done, { once: true }); } catch {}
  });
}

export async function callPeer({
  baseUrl,
  secret,
  senderId,
  method = 'GET',
  apiPath,
  body,
  timeoutMs = 30_000,
  signal,
  fetchImpl = fetch,
}) {
  const { headers, plain } = authHeaders({ secret, senderId, method, apiPath, body });
  const wire = plain.length ? Buffer.from(encryptBytes(secret, plain), 'utf8') : Buffer.alloc(0);
  const budget = AbortSignal.timeout(Math.max(1000, Number(timeoutMs) || 30_000));
  const composed = signal ? AbortSignal.any([signal, budget]) : budget;

  const res = await fetchImpl(new URL(apiPath, baseUrl).toString(), {
    method,
    headers: {
      ...headers,
      'Content-Type': plain.length ? 'application/octet-stream' : 'application/json',
      'X-Peer-Enc': ENC_VERSION,
    },
    // Undici hard-rejects any body on GET/HEAD (`Request with GET/HEAD method
    // cannot have body`), empty Buffer included, so the field must be absent.
    body: wire.length && method !== 'GET' && method !== 'HEAD' ? wire : undefined,
    signal: composed,
  });

  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    throw new Error(`HTTP ${res.status}: ${text.slice(0, 120)}`);
  }
  if (json && json.enc === ENC_VERSION && typeof json.data === 'string') {
    json = decryptJson(secret, json.data);
  }
  if (!res.ok) {
    // 消息文案保持不变；把状态码和错误码挂在 Error 上，让调用方能区分
    // 「永久拒绝」（400 encryption-required）和「可重试」（429 / 传输故障）。
    const error = new Error(`${res.status} ${json?.error || ''}`.trim());
    error.status = res.status;
    error.code = json?.error == null ? null : String(json.error);
    throw error;
  }
  return json;
}

export function capabilityOf(health) {
  return Array.isArray(health?.capability) ? health.capability.map(String) : [];
}

/** Unauthenticated /v1/health probe; successes are cached briefly. */
export async function probePeer({ baseUrl, timeoutMs = 2000, fetchImpl = fetch, fresh = false } = {}) {
  const key = String(baseUrl ?? '').replace(/\/+$/, '');
  const cached = probeCache.get(key);
  if (!fresh && cached && Date.now() - cached.at < PROBE_TTL_MS) return cached.value;
  let value;
  try {
    const res = await fetchImpl(`${key}/v1/health`, {
      signal: AbortSignal.timeout(Math.max(500, Number(timeoutMs) || 2000)),
    });
    const body = await res.json().catch(() => ({}));
    value = res.ok
      ? {
          online: true,
          name: body?.name ?? null,
          instanceId: body?.instanceId ?? null,
          version: body?.version ?? null,
          capability: capabilityOf(body),
          peers: body?.peers ?? 0,
        }
      : { online: false, status: res.status, capability: [] };
  } catch (error) {
    value = { online: false, error: message(error), capability: [] };
  }
  if (value.online) probeCache.set(key, { at: Date.now(), value });
  else probeCache.delete(key);
  return value;
}

export function resetProbeCache() {
  probeCache.clear();
}

/**
 * Wait for a session to reach a terminal state.
 *
 * mode 'auto'   — SSE when the peer advertised "stream", long-poll as fallback
 * mode 'stream' — SSE only, long-poll only after the stream breaks
 * mode 'poll'   — /v1/answer with waitMs (the v0.4.0 hold), no SSE
 * mode 'legacy' — exact 0.3.1 behaviour: no waitMs, poll every pollIntervalMs
 *
 * Never throws: transport failures come back as status 'error' so a model turn is
 * not interrupted. Total wall clock is bounded by timeoutMs.
 */
export async function awaitPeerAnswer({
  baseUrl,
  secret,
  senderId,
  sessionId,
  timeoutMs = 300_000,
  waitMs = DEFAULT_ANSWER_WAIT_MS,
  mode = 'auto',
  pollIntervalMs = LEGACY_POLL_MS,
  onProgress,
  signal,
  fetchImpl = fetch,
  // 预算切分的默认值就是上面两个常量；仅在测试里收窄，生产不要传。
  streamReserveMs = STREAM_RESERVE_MS,
  streamCapMs = STREAM_CAP_MS,
}) {
  const startedAt = Date.now();
  const budget = Math.max(1000, Number(timeoutMs) || 300_000);
  const deadline = startedAt + budget;
  const hold = Math.min(Math.max(1000, Number(waitMs) || DEFAULT_ANSWER_WAIT_MS), MAX_ANSWER_WAIT_MS);
  const useWaitMs = mode !== 'legacy';
  const transport = useWaitMs ? 'long-poll' : 'legacy-poll';
  const reserve = Math.max(1000, Number(streamReserveMs) || STREAM_RESERVE_MS);
  const streamCap = Math.max(1000, Number(streamCapMs) || STREAM_CAP_MS);

  // 预算切分：流最多花 min(预算 - 保留, 上限)，剩下的留给长轮询。
  // 预算太小（<= 2*保留）时流拿不到有意义的窗口，直接跳过。
  const streamBudget = Math.min(budget - reserve, streamCap);
  if ((mode === 'auto' || mode === 'stream') && budget > reserve * 2 && streamBudget >= 1000) {
    const streamAbort = new AbortController();
    const forwardAbort = () => streamAbort.abort(signal?.reason);
    if (signal) {
      if (signal.aborted) streamAbort.abort(signal.reason);
      else signal.addEventListener('abort', forwardAbort, { once: true });
    }
    let streamed;
    try {
      streamed = await readPeerEvents({
        baseUrl,
        secret,
        senderId,
        sessionId,
        signal: streamAbort.signal,
        timeoutMs: streamBudget,
        fetchImpl,
        onEvent: (info) => {
          if (info.type === 'ping') return;
          onProgress?.({ transport: 'sse', status: info.status, elapsedMs: info.elapsedMs });
        },
      });
    } finally {
      // 任何出口路径都拆掉流：监听器、socket 都不留。
      try { signal?.removeEventListener?.('abort', forwardAbort); } catch {}
      try { streamAbort.abort(new Error('stream-phase-over')); } catch {}
    }
    if (streamed?.ok) {
      return {
        status: streamed.status,
        reply: streamed.reply,
        error: streamed.error,
        elapsedMs: Number(streamed.elapsedMs) || Date.now() - startedAt,
        transport: 'sse',
      };
    }
    // Contract: a broken stream is continued with waitMs long-polling. Events are
    // not replayed; /v1/answer reports the session's current state on its own.
    // 此时预算还剩 >= 保留时长（或流提前结束），轮询至少能问一次。
  }

  const base = `/v1/answer?sessionId=${encodeURIComponent(String(sessionId ?? ''))}`;
  let attempts = 0;
  let lastError = null;
  let sawRunning = false;
  let offlineStreak = 0;
  let backoffMs = 0;
  // first 保证：流没给出确定答案时，即使已经过了 deadline 也务必问一次 /v1/answer。
  for (let first = true; first || Date.now() < deadline; first = false) {
    const remaining = Math.max(1000, deadline - Date.now());
    const holdMs = Math.min(hold, remaining);
    const apiPath = useWaitMs ? `${base}&waitMs=${holdMs}` : base;
    const startedCall = Date.now();
    attempts += 1;
    let answer;
    try {
      answer = await callPeer({
        baseUrl,
        secret,
        senderId,
        method: 'GET',
        apiPath,
        timeoutMs: (useWaitMs ? holdMs : 30_000) + 10_000,
        signal,
        fetchImpl,
      });
    } catch (error) {
      const status = Number(error?.status);
      const fatal = status >= 400 && status < 500 && !RETRYABLE_4XX.has(status);
      if (fatal) {
        // 永久性协议拒绝（2026-11-06 的 29255 次 400 encryption-required 就是这里被打成可重试）：
        // 立刻收手，不再问第二次。
        return {
          status: 'error',
          error: message(error) || `http-${status}`,
          elapsedMs: Date.now() - startedAt,
          transport,
          sessionId,
          httpStatus: status,
          terminal: true,
        };
      }
      // 确定性掉线（ECONNREFUSED / DNS / 主机不可达 / TLS）：连续 DEAD_PEER_STREAK
      // 次就认定对端不在，立刻报错，不要拿整份预算陪它耗。
      const offlineCode = offlineCodeOf(error);
      if (offlineCode) {
        offlineStreak += 1;
        if (offlineStreak >= DEAD_PEER_STREAK) {
          return {
            status: 'error',
            error: `${message(error) || 'peer-offline'} (${offlineCode})`,
            elapsedMs: Date.now() - startedAt,
            transport,
            sessionId,
            attempts,
            offline: true,
          };
        }
      }
      // 只有传输层故障和 408/429 走重试；退避封顶，快失败的服务端也打不穿。
      lastError = message(error);
      backoffMs = backoffMs ? Math.min(backoffMs * 2, POLL_BACKOFF_CAP_MS) : POLL_BACKOFF_BASE_MS;
      const left = deadline - Date.now();
      if (left <= 0) break;
      onProgress?.({ transport, status: 'retry', elapsedMs: Date.now() - startedAt });
      await sleep(Math.min(backoffMs, left), signal);
      continue;
    }
    // 拿到任何一次真实响应就说明对端活着：掉线计数清零（中途掉线照样享有完整重试）。
    offlineStreak = 0;
    const took = Date.now() - startedCall;
    const elapsedMs = Number(answer?.elapsedMs) || Date.now() - startedAt;
    if (answer?.status === 'done') {
      return { status: 'done', reply: String(answer.reply ?? ''), elapsedMs, transport };
    }
    if (answer?.status === 'error') {
      return { status: 'error', error: String(answer.error ?? 'peer-error'), elapsedMs, transport };
    }
    backoffMs = 0;
    sawRunning = true;
    onProgress?.({ transport, status: 'running', elapsedMs });
    // A peer that answers "running" without holding ignores waitMs (a 0.3.1 host
    // does exactly that), so keep the old cadence instead of spinning on it.
    if (took < FAST_ANSWER_MS && Date.now() < deadline) {
      await sleep(Math.min(pollIntervalMs, Math.max(0, deadline - Date.now())), signal);
    }
  }
  const elapsedMs = Date.now() - startedAt;
  // 预算耗尽仍在跑：带上 sessionId，调用方可以据此续问，不必整轮重来。
  // 一次都没问到状态、且最后一次是可重试失败：报 error 比报 timeout 诚实。
  if (lastError && !sawRunning) {
    return { status: 'error', error: lastError, elapsedMs, transport, sessionId };
  }
  return { status: 'timeout', error: 'timeout', elapsedMs, transport, sessionId, attempts };
}

// ---- pairing --------------------------------------------------------------

let ecdhModulePromise = null;

async function loadPairingEcdh() {
  if (!ecdhModulePromise) {
    ecdhModulePromise = import('../lib/pairing-ecdh.mjs').catch(() => null);
  }
  return ecdhModulePromise;
}

export async function pairingEcdhAvailable() {
  return (await loadPairingEcdh()) !== null;
}

async function postJson(url, body, { timeoutMs = 15_000, fetchImpl = fetch, action = 'pair' } = {}) {
  const res = await fetchImpl(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(Math.max(1000, Number(timeoutMs) || 15_000)),
  });
  const payload = await res.json().catch(() => ({}));
  if (!res.ok) {
    const error = new Error(action + ': ' + res.status + ' ' + (payload?.error || 'request-failed'));
    error.status = res.status;
    error.code = payload?.error;
    throw error;
  }
  return payload;
}

function trimBase(url) {
  const raw = String(url ?? '').trim().replace(/\/+$/, '');
  if (!/^https?:\/\//i.test(raw)) throw new Error('peer url must be http(s)://host:port');
  return raw;
}

// ---- 本机对外可达地址（配对时自报，v0.8.0 真机回归） ----------------------
//
// 与 host/server.mjs 的 S1 探测同口径：只要 RFC1918 私有 IPv4、跳过 internal 与
// 虚拟网卡。端口默认取插件默认监听端口（7788）；显式 selfBaseUrl 优先，其次环境变量。

const VIRTUAL_IFACE_PATTERN = /^(docker|veth|br-|virbr|vmnet|vbox|vethernet|hyper-v|virtualbox|vmware|loopback|lo\b|zt|tailscale|utun|tun|tap|wg|ham|npcap)/i;
const DEFAULT_LISTEN_PORT = 7788;

function trimBaseSafe(value) {
  const raw = String(value ?? '').trim().replace(/\/+$/, '');
  return /^https?:\/\//i.test(raw) ? raw : '';
}

function isPrivateIpv4(value) {
  const parts = String(value ?? '').trim().split('.');
  if (parts.length !== 4) return false;
  const octets = parts.map(Number);
  if (octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) return false;
  const [a, b] = octets;
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  return false;
}

/** 192.168 优先，其次 10/8，最后 172.16/12；同档按网卡名与地址排序（结果稳定可测） */
function privateAddressRank(address) {
  const [a] = String(address).split('.').map(Number);
  if (a === 192) return 0;
  if (a === 10) return 1;
  return 2;
}

/**
 * 本机优先公布的地址：显式 selfBaseUrl > DSH_LAN_PEERS_ADVERTISE_BASE_URL >
 * 「首选私有 IPv4 + 端口（默认 7788）」。拿不到私有地址时返回 ''。
 *
 * 为什么配对要带它：接收方把 baseUrl 存进 peers.json；缺了它，「配进来的伙伴」
 * 在广播/派单时就只剩 no-base-url（真机上表现为群名广播推不到第三台）。
 */
export function detectSelfBaseUrl({
  selfBaseUrl = '',
  port = DEFAULT_LISTEN_PORT,
  interfaces = null,
  env = null,
} = {}) {
  const explicit = trimBaseSafe(selfBaseUrl);
  if (explicit !== '') return explicit;
  const source = env ?? (typeof process !== 'undefined' && process.env ? process.env : {});
  const fromEnv = trimBaseSafe(source.DSH_LAN_PEERS_ADVERTISE_BASE_URL);
  if (fromEnv !== '') return fromEnv;
  const envPort = Number(source.DSH_LAN_PEERS_PORT);
  const wanted = Number(port);
  const listenPort = Number.isFinite(wanted) && wanted > 0
    ? Math.floor(wanted)
    : (Number.isFinite(envPort) && envPort > 0 ? Math.floor(envPort) : DEFAULT_LISTEN_PORT);
  const table = interfaces ?? os.networkInterfaces();
  const found = [];
  for (const name of Object.keys(table ?? {}).sort()) {
    if (VIRTUAL_IFACE_PATTERN.test(String(name))) continue;
    for (const entry of table[name] ?? []) {
      if (!entry) continue;
      if (entry.family !== 'IPv4' && entry.family !== 4) continue;
      if (entry.internal === true) continue;
      const address = String(entry.address ?? '');
      if (!isPrivateIpv4(address)) continue;
      found.push({ name: String(name), address, rank: privateAddressRank(address) });
    }
  }
  found.sort((left, right) => (left.rank - right.rank)
    || left.name.localeCompare(right.name)
    || left.address.localeCompare(right.address));
  return found.length > 0 ? 'http://' + found[0].address + ':' + listenPort : '';
}

async function pairPeerEcdh({ baseUrl, code, peerId, peerName, timeoutMs, fetchImpl, ecdh, selfBaseUrl = '' }) {
  const keyPair = ecdh.generateKeyPair();
  // 第一轮就把自己的可达地址带上：hub 存 peer 记录时才有 baseUrl（v0.8.0 真机回归）
  const self = trimBaseSafe(selfBaseUrl);
  const opened = await postJson(
    baseUrl + '/v1/pair',
    {
      code,
      peerId,
      peerName,
      ...(self === '' ? {} : { baseUrl: self }),
      ecdh: { v: 1, curve: 'P-256', publicKey: keyPair.publicKeyB64url },
    },
    { timeoutMs, fetchImpl, action: 'pair' },
  );
  const serverPublicKey = opened?.ecdh?.publicKey;
  if (typeof serverPublicKey !== 'string' || serverPublicKey === '') {
    throw new Error('pair: peer did not return an ECDH public key');
  }
  const wrapKey = ecdh.deriveWrapKey(keyPair.privateKey, serverPublicKey);
  const inboundSecret = newSecret();
  const wrapped = ecdh.wrapSecret(wrapKey, { secret: inboundSecret });
  const confirmed = await postJson(
    baseUrl + '/v1/pair/confirm',
    { code, peerId, peerName, wrapped },
    { timeoutMs, fetchImpl, action: 'pair/confirm' },
  );
  if (typeof confirmed?.wrapped !== 'string' || confirmed.wrapped === '') {
    throw new Error('pair/confirm: peer did not return a wrapped secret');
  }
  const issued = ecdh.unwrapSecret(wrapKey, confirmed.wrapped);
  const secret = String(issued?.secret ?? '');
  if (!secret) throw new Error('pair/confirm: peer returned an empty secret');
  return {
    peerId: confirmed.peerId,
    peerName: confirmed.peerName,
    secret,
    inboundSecret,
    baseUrl,
    transport: 'ecdh',
    pairingTtlMs: opened.pairingTtlMs ?? null,
  };
}

async function pairPeerLegacy({ baseUrl, code, peerId, peerName, timeoutMs, fetchImpl, selfBaseUrl = '' }) {
  const inboundSecret = newSecret();
  const self = trimBaseSafe(selfBaseUrl);
  const payload = await postJson(
    baseUrl + '/v1/pair',
    { code, peerId, peerName, ...(self === '' ? {} : { baseUrl: self }), secret: inboundSecret },
    { timeoutMs, fetchImpl, action: 'pair' },
  );
  if (!payload?.peerId || !payload?.secret) throw new Error('pair: peer response is missing peerId/secret');
  return {
    peerId: payload.peerId,
    peerName: payload.peerName,
    secret: payload.secret,
    inboundSecret,
    baseUrl,
    transport: 'legacy',
    pairingTtlMs: null,
  };
}

/**
 * Pair with a peer.
 *
 * mode 'auto'   — ECDH when the peer advertises "pair-ecdh" and
 *                 lib/pairing-ecdh.mjs is present; plaintext legacy otherwise
 * mode 'ecdh'   — ECDH only; a peer (or build) that cannot do it is an error
 * mode 'legacy' — plaintext only (as --legacy-pair does)
 *
 * A plaintext downgrade after a *rejected* ECDH exchange is deliberately not
 * attempted: the pairing code may already be consumed. Only an absent endpoint
 * (404/405) or an absent local module downgrades.
 */
export async function pairPeer({
  url,
  code,
  peerId,
  peerName,
  mode = 'auto',
  timeoutMs = 15_000,
  fetchImpl = fetch,
  ecdhModule,
  // 本机对外可达地址：不传则按 S1 口径自动探测（私有 IPv4 + 默认端口），
  // 探测不到就不带这个字段（老行为：接收方 baseUrl=null）。
  selfBaseUrl = null,
  selfPort = DEFAULT_LISTEN_PORT,
}) {
  const baseUrl = trimBase(url);
  const options = {
    baseUrl,
    code: String(code ?? '').trim(),
    peerId: String(peerId ?? ''),
    peerName: String(peerName ?? ''),
    timeoutMs,
    fetchImpl,
    selfBaseUrl: detectSelfBaseUrl({ selfBaseUrl: selfBaseUrl ?? '', port: selfPort }),
  };
  if (mode === 'legacy') return pairPeerLegacy(options);

  // undefined = discover the installed module; null = explicitly unavailable.
  const ecdh = ecdhModule === undefined ? await loadPairingEcdh() : ecdhModule;
  if (!ecdh) {
    if (mode === 'ecdh') {
      throw new Error('pairing-ecdh-unavailable: lib/pairing-ecdh.mjs is missing in this build');
    }
    return pairPeerLegacy(options);
  }

  const health = await probePeer({ baseUrl, fetchImpl, timeoutMs: Math.min(5000, timeoutMs) });
  const supported = capabilityOf(health).includes('pair-ecdh');
  if (!supported) {
    if (mode === 'ecdh') {
      throw new Error('pairing-ecdh-unsupported: peer /v1/health capability has no pair-ecdh');
    }
    return pairPeerLegacy(options);
  }

  try {
    return await pairPeerEcdh({ ...options, ecdh });
  } catch (error) {
    const endpointMissing = error?.status === 404 || error?.status === 405;
    if (mode === 'ecdh' || !endpointMissing) throw error;
    return pairPeerLegacy(options);
  }
}
