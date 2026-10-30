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
  if (!res.ok) throw new Error(`${res.status} ${json?.error || ''}`.trim());
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
}) {
  const startedAt = Date.now();
  const budget = Math.max(1000, Number(timeoutMs) || 300_000);
  const deadline = startedAt + budget;
  const hold = Math.min(Math.max(1000, Number(waitMs) || DEFAULT_ANSWER_WAIT_MS), MAX_ANSWER_WAIT_MS);
  const useWaitMs = mode !== 'legacy';
  const transport = useWaitMs ? 'long-poll' : 'legacy-poll';

  if (mode === 'auto' || mode === 'stream') {
    const streamed = await readPeerEvents({
      baseUrl,
      secret,
      senderId,
      sessionId,
      signal,
      timeoutMs: budget,
      fetchImpl,
      onEvent: (info) => {
        if (info.type === 'ping') return;
        onProgress?.({ transport: 'sse', status: info.status, elapsedMs: info.elapsedMs });
      },
    });
    if (streamed.ok) {
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
  }

  const base = `/v1/answer?sessionId=${encodeURIComponent(String(sessionId ?? ''))}`;
  while (Date.now() < deadline) {
    const remaining = Math.max(1000, deadline - Date.now());
    const holdMs = Math.min(hold, remaining);
    const apiPath = useWaitMs ? `${base}&waitMs=${holdMs}` : base;
    const startedCall = Date.now();
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
      return { status: 'error', error: message(error), elapsedMs: Date.now() - startedAt, transport };
    }
    const took = Date.now() - startedCall;
    const elapsedMs = Number(answer?.elapsedMs) || Date.now() - startedAt;
    if (answer?.status === 'done') {
      return { status: 'done', reply: String(answer.reply ?? ''), elapsedMs, transport };
    }
    if (answer?.status === 'error') {
      return { status: 'error', error: String(answer.error ?? 'peer-error'), elapsedMs, transport };
    }
    onProgress?.({ transport, status: 'running', elapsedMs });
    // A peer that answers "running" without holding ignores waitMs (a 0.3.1 host
    // does exactly that), so keep the old cadence instead of spinning on it.
    if (took < FAST_ANSWER_MS) {
      await sleep(Math.min(pollIntervalMs, Math.max(0, deadline - Date.now())), signal);
    }
  }
  return { status: 'timeout', error: 'timeout', elapsedMs: Date.now() - startedAt, transport };
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
