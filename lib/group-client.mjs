// dsh-lan-peers · 群聊客户端助手（成员侧与 hub 侧共用，v0.5.0 Phase1）。
//
// 这里不造 HTTP：请求走 client/peer-call.mjs 的 callPeer（签名 + AES-GCM 请求体），
// 事件流走 client/sse.mjs 的 parseSseStream + decryptSseEvent（逐帧新 nonce）。
// 供 lib/tools.mjs（进度镜像）、lib/admin.mjs（管理接口）与 client/cli.mjs 复用。
//
// groupKey 只出现在 /v1/group/state 的成员响应里，本模块也不打印它。
import { createCipheriv, createDecipheriv, createHash, createHmac, hkdfSync, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { ENC_HEADER, ENC_VERSION } from './wire-crypto.mjs';
// P2：v2 通道只**复用** P1 的原语（签名/验签/证书/密钥文件），不自己拼 canonical。
import {
  CERT_ALG,
  DEFAULT_GRACE_MS,
  DEFAULT_ROTATE_AFTER_MS,
  IDENTITY_MISSING,
  IDENTITY_UNAVAILABLE,
  buildGroupCanonicalV2,
  createKeypair,
  loadKeypair,
  needsRotation,
  publicKeyFromText,
  saveKeypair,
  signMessage,
  verifyCertificate,
} from './group-identity.mjs';
// §8.2：注册的 per-peer 证明复用契约 §4 的五行 canonical + HMAC，不自造格式
import { authHeaders, canonical as perPeerCanonical, sign as perPeerSign } from '../client/protocol.mjs';
import {
  awaitPeerAnswer,
  callPeer,
  capabilityOf,
  probePeer,
} from '../client/peer-call.mjs';
import { SSE_ACCEPT, decryptSseEvent, parseSseStream } from '../client/sse.mjs';

/**
 * §3 kind 白名单。
 * 0.10.0-α 起群内派单已移除：progress / result 不再被接受（新帖一律 400 bad-request），
 * 但老群历史与归档里仍有这两种行 —— 读路径（history/pull/面板）必须照旧能渲染它们。
 */
export const GROUP_KINDS = Object.freeze(['chat', 'system']);

/**
 * §3 meta 白名单（hub 侧仍会再过滤一次，这里是发送前的自检）。
 * 0.10.0-α 起派单已移除：target/by/reason 与工作区三键（workspaceId/workspaceName/
 * permission）不再收新值。phase/status/transport/elapsedMs/replyChars 保留 ——
 * 老群历史里的 progress/result 行仍带这些字段，读路径要能照旧显示它们。
 */
export const GROUP_META_FIELDS = Object.freeze([
  'peer',
  'sessionId',
  'phase',
  'status',
  'transport',
  'elapsedMs',
  'replyChars',
]);

/** §3 text 上限 */
export const GROUP_TEXT_MAX_CHARS = 4000;

/** §2 retentionDays 默认值 */
export const GROUP_DEFAULT_RETENTION_DAYS = 7;

// ---------------------------------------------------------------------------
// S1 v0.6.0 群级鉴权常量（host/server.mjs 与 client 共用这一份）
// ---------------------------------------------------------------------------

/** 带这个头 = 群级签名；不带 = 现有 per-peer 签名（v0.5.0 行为完全不变） */
export const GROUP_AUTH_HEADER = 'X-Peer-Auth';
export const GROUP_AUTH_VALUE = 'group';
/** 群级 canonical 里的 groupId 只能从 header 拿：GET 没有 body */
export const GROUP_ID_HEADER = 'X-Peer-Group';
/** 成员自报的可达地址（hub 据此填 members[].baseUrl） */
export const GROUP_BASE_HEADER = 'X-Peer-Base';
/** 成员自报的复制进度（hub 据此显示「落后 leader 多少条」；从未上报 = null） */
export const GROUP_LASTSEQ_HEADER = 'X-Peer-LastSeq';


export const GROUP_AUTH_SALT = 'dsh-lan-peers/group-auth/v1';
export const GROUP_SIGN_INFO = 'dsh-lan-peers/group-sign/v1';
export const GROUP_BODY_INFO = 'dsh-lan-peers/group-body/v1';
export const GROUP_AUTH_CLOCK_SKEW_MS = 60_000;
export const GROUP_AUTH_NONCE_WINDOW_MS = 120_000;

/**
 * 群级鉴权白名单（v0.8.0 起 11 条）：S1 的四条 + S3 选举/两阶段提交的四条 +
 * v0.8.0 的两条入群转交（介绍人→hub 的 apply-intake / apply-query，契约 §4.2/§5.1）+
 * /v1/group/post（**新增鉴权模式**：按名入群的成员没有 hub 的 per-peer 密钥，
 * 只认 per-peer 就只能读不能发言）。
 *
 * 心跳与查询共用 /v1/group/leader：GET 查 leader（S1），POST 心跳（S3）。
 * 注意：/v1/group/post 是**双模式**端点 —— per-peer 行为一字不变，群级只是多一条通道；
 * 它不进 groupAuthDispatch（那条通路的 404/405 语义不同），由 groupDispatch 单独分派。
 */
export const GROUP_AUTH_PATHS = Object.freeze([
  '/v1/group/probe',
  '/v1/group/replicate',
  '/v1/group/pull',
  '/v1/group/leader',
  '/v1/group/election',
  '/v1/group/propose',
  '/v1/group/commit',
  '/v1/group/lease',
  '/v1/group/apply-intake',
  '/v1/group/apply-query',
  '/v1/group/post',
]);

/** 成员侧文件（都在 <stateDir> 下，0600） */
export const GROUP_KEY_FILE = 'group-key.json';
export const GROUP_REPLICA_FILE = 'group-replica.json';
export const GROUP_ROLE_FILE = 'group-role.json';
export const GROUP_DEFAULT_REPLICA_PULL_MS = 10_000;

// ---------------------------------------------------------------------------
// S3 v0.7.0 选举 / 租约 / 两阶段提交常量（host 与 client 共用这一份）
// ---------------------------------------------------------------------------

/** 角色取值（与契约 §1 一致） */
export const GROUP_ROLES = Object.freeze(['leader', 'follower', 'candidate']);

/** leader 心跳间隔默认值（契约 §2/§8） */
export const GROUP_DEFAULT_HEARTBEAT_MS = 3_000;

/** 租约 = 3 × 心跳间隔（契约 §2） */
export const GROUP_LEASE_FACTOR = 3;

/** propose→commit 超时默认值（契约 §5/§8） */
export const GROUP_DEFAULT_COMMIT_TIMEOUT_MS = 3_000;

/** 同 epoch 冲突裁决的默认优先级：数值小者优先，同值按 peerId 字典序（契约 §4/§8） */
export const GROUP_DEFAULT_HUB_PRIORITY = 0;

/** 候选抖动的上限（契约 §2：随机抖动 0–500ms） */
export const GROUP_ELECTION_JITTER_MS = 500;

// ---------------------------------------------------------------------------
// 本机接单开关（wire 上的 members[].acceptDispatch）。
// 0.10.0-α 起派单能力已移除，这两条常量只为老对端的报文字段与既有落盘形状保留。
// ---------------------------------------------------------------------------

/** §4：本机是否接单（config group.acceptDispatch）；老对端缺字段 = true */
export const GROUP_DEFAULT_ACCEPT_DISPATCH = true;

/** 成员自报接单开关（GET 无 body，只能走 header；与 X-Peer-Base/LastSeq 同一套路） */
export const GROUP_ACCEPT_HEADER = 'X-Peer-Accept';


/**
 * 多数派：floor(N/2)+1（N = 成员总数含自己）；quorum=none 时一律 1（契约 §3）。
 * 这个函数 host 与 client 共用，避免两边算出不同的票数门槛。
 */
export function quorumSize(memberCount, mode = 'majority') {
  if (String(mode) === 'none') return 1;
  const total = Number(memberCount);
  const n = Number.isFinite(total) && total > 0 ? Math.floor(total) : 1;
  return Math.floor(n / 2) + 1;
}

const asNumber = (value, fallback = 0) => {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : fallback;
};

const asSeq = (value) => {
  const numeric = asNumber(value, 0);
  return numeric > 0 ? Math.floor(numeric) : 0;
};

const reason = (error) => String(error?.message ?? error);

const trimBase = (baseUrl) => String(baseUrl ?? '').trim().replace(/\/+$/, '');

/**
 * §2 group 配置归一化：全部有默认值，不填 = 关闭。
 * hub 留空 = 本机就是 hub；填名字或 peerId = 本机是成员。
 */
export function normalizeGroupConfig(raw) {
  const value = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  const days = Number(value.retentionDays);
  const pullMs = Number(value.replicaPullMs);
  const heartbeatMs = Number(value.heartbeatMs);
  const commitMs = Number(value.commitTimeoutMs);
  const priority = Number(value.hubPriority);
  return {
    enabled: value.enabled === true,
    hub: String(value.hub ?? '').trim(),
    name: String(value.name ?? '').trim() || 'default',
    autoJoin: value.autoJoin === true,
    retentionDays: Number.isFinite(days) && days >= 0 ? Math.floor(days) : GROUP_DEFAULT_RETENTION_DAYS,
    // S1 成员可达地址：空 = 自动探测首选私有 IPv4
    advertiseBaseUrl: String(value.advertiseBaseUrl ?? '').trim().replace(/\/+$/, ''),
    // S3：quorum 真正生效（majority = 两阶段提交，none = 可用性优先，直接提交）
    quorum: String(value.quorum ?? '').trim() === 'none' ? 'none' : 'majority',
    // S2 成员拉取间隔
    replicaPullMs: Number.isFinite(pullMs) && pullMs >= 50
      ? Math.floor(pullMs)
      : GROUP_DEFAULT_REPLICA_PULL_MS,
    // S3 §8：leader 心跳间隔（租约 = 3×）、propose→commit 超时、冲突裁决优先级
    heartbeatMs: Number.isFinite(heartbeatMs) && heartbeatMs >= 250
      ? Math.floor(heartbeatMs)
      : GROUP_DEFAULT_HEARTBEAT_MS,
    commitTimeoutMs: Number.isFinite(commitMs) && commitMs >= 100
      ? Math.floor(commitMs)
      : GROUP_DEFAULT_COMMIT_TIMEOUT_MS,
    hubPriority: Number.isFinite(priority) ? Math.floor(priority) : GROUP_DEFAULT_HUB_PRIORITY,
    // v0.8.2-α §4：本机是否接群内派单。缺省 true（老配置/老对端都按接单处理）
    acceptDispatch: value.acceptDispatch !== false,
  };
}

/** §4：老对端没有 acceptDispatch 字段 ⇒ 视为接单（向后兼容） */
export function acceptDispatchOf(member) {
  return member?.acceptDispatch !== false;
}

/**
 * §4：成员自报的接单开关归一化。'1'/'true'/true → true，'0'/'false'/false → false，
 * 其余（缺失/垃圾）→ null（= 不知道，调用方按 true 处理）。
 */
export function parseAcceptFlag(raw) {
  if (raw === true) return true;
  if (raw === false) return false;
  const value = String(raw ?? '').trim().toLowerCase();
  if (value === '1' || value === 'true' || value === 'yes') return true;
  if (value === '0' || value === 'false' || value === 'no') return false;
  return null;
}

/**
 * 把 group.hub（名字或 peerId）解析成 peers.json 里的一条记录。
 * 解析放在使用侧做，因为 peers.json 会随配对/解绑变化。
 */
export function resolveGroupHub(peers, hub) {
  const wanted = String(hub ?? '').trim();
  if (wanted === '') return null;
  const list = Array.isArray(peers) ? peers : [];
  const byId = list.find((peer) => String(peer?.peerId ?? '') === wanted);
  if (byId) return byId;
  return list.find((peer) => String(peer?.name ?? '') === wanted) ?? null;
}

/** 只保留白名单字段，值必须是 JSON 标量 */
export function sanitizeGroupMeta(meta) {
  const out = {};
  if (!meta || typeof meta !== 'object' || Array.isArray(meta)) return out;
  for (const field of GROUP_META_FIELDS) {
    const value = meta[field];
    if (value == null) continue;
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') out[field] = value;
  }
  return out;
}

/** 单行文本摘要：msg → "from	#seq ..." 由各调用方自己排版，这里只规范化字段 */
export function groupMessageSummary(message) {
  return {
    seq: asSeq(message?.seq),
    ts: asNumber(message?.ts, 0),
    from: {
      peerId: String(message?.from?.peerId ?? ''),
      name: String(message?.from?.name ?? ''),
    },
    kind: String(message?.kind ?? ''),
    text: String(message?.text ?? ''),
    meta: sanitizeGroupMeta(message?.meta),
  };
}

// ---------------------------------------------------------------------------
// 端点封装（全部走 callPeer：签名 + 加密请求体，响应按对端密钥解密）
// ---------------------------------------------------------------------------

/** GET /v1/group/state —— 成员拿到 {groupId,name,epoch,keyVersion,members,groupKey} */
export async function fetchGroupState({
  baseUrl,
  secret,
  senderId,
  timeoutMs = 10_000,
  fetchImpl = fetch,
} = {}) {
  const state = await callPeer({
    baseUrl: trimBase(baseUrl),
    secret,
    senderId,
    method: 'GET',
    apiPath: '/v1/group/state',
    timeoutMs,
    fetchImpl,
  });
  return {
    ...state,
    members: Array.isArray(state?.members) ? state.members : [],
    epoch: asNumber(state?.epoch, 0),
    keyVersion: asNumber(state?.keyVersion, 0),
  };
}

/**
 * POST /v1/group/join —— 自助加入；hub 没开 autoJoin 时对端回 403 not-a-member。
 *
 * 可选 `name` 是**本机自己的显示名**（hub 只写 senderId 那一条记录）：
 * 一台机器上跑多个 CLI 节点时，配对上报的 peerName 都是同一个 hostname，
 * 传这个名字才能让群成员表区分开。
 */
export async function joinGroup({
  baseUrl,
  secret,
  senderId,
  name = null,
  timeoutMs = 10_000,
  fetchImpl = fetch,
} = {}) {
  const body = {};
  const trimmed = typeof name === 'string' ? name.trim() : '';
  if (trimmed !== '') body.name = trimmed.slice(0, 64);
  return callPeer({
    baseUrl: trimBase(baseUrl),
    secret,
    senderId,
    method: 'POST',
    apiPath: '/v1/group/join',
    body,
    timeoutMs,
    fetchImpl,
  });
}

/**
 * POST /v1/group/post —— 发一条消息。
 * 只有白名单 meta 会被送出（hub 侧还会再过滤一次），text 超长由 hub 回 413。
 */
export async function postGroup({
  baseUrl,
  secret,
  senderId,
  kind = 'chat',
  text = '',
  meta = null,
  timeoutMs = 10_000,
  fetchImpl = fetch,
} = {}) {
  const payload = { kind: String(kind) };
  if (typeof text === 'string' && text !== '') payload.text = text;
  const cleanMeta = sanitizeGroupMeta(meta);
  if (Object.keys(cleanMeta).length > 0) payload.meta = cleanMeta;
  return callPeer({
    baseUrl: trimBase(baseUrl),
    secret,
    senderId,
    method: 'POST',
    apiPath: '/v1/group/post',
    body: payload,
    timeoutMs,
    fetchImpl,
  });
}

/** GET /v1/group/history —— {groupId, epoch, lastSeq, messages} */
export async function fetchGroupHistory({
  baseUrl,
  secret,
  senderId,
  sinceSeq = 0,
  limit = 200,
  timeoutMs = 10_000,
  fetchImpl = fetch,
} = {}) {
  const cap = Math.min(Math.max(1, Math.floor(asNumber(limit, 200))), 200);
  const apiPath = `/v1/group/history?sinceSeq=${asSeq(sinceSeq)}&limit=${cap}`;
  const page = await callPeer({
    baseUrl: trimBase(baseUrl),
    secret,
    senderId,
    method: 'GET',
    apiPath,
    timeoutMs,
    fetchImpl,
  });
  return {
    ...page,
    epoch: asNumber(page?.epoch, 0),
    lastSeq: asSeq(page?.lastSeq),
    messages: Array.isArray(page?.messages) ? page.messages : [],
  };
}

/**
 * GET /v1/group/events（SSE）：按 seq 递增去重后逐条回调 onMessage。
 *
 * 永不抛：断流/超时/坏帧都回报 {ok:false, reason}，供调用方用 sinceSeq 续传。
 * 调用方的 signal abort 会以 {ok:false, aborted:true} 收尾（CLI 的 --duration 走这条）。
 * untilSeq 给定时，收到该 seq 即正常结束（{ok:true}）。
 */
export async function readGroupEvents({
  baseUrl,
  secret,
  senderId,
  sinceSeq = 0,
  onMessage,
  onPing,
  untilSeq,
  signal,
  timeoutMs = 60_000,
  fetchImpl = fetch,
} = {}) {
  const startSeq = asSeq(sinceSeq);
  const stopAt = untilSeq == null ? null : asSeq(untilSeq);
  const apiPath = `/v1/group/events?sinceSeq=${startSeq}`;
  const { headers } = authHeaders({ secret, senderId, method: 'GET', apiPath });
  const controller = new AbortController();
  const timer = setTimeout(
    () => controller.abort(new Error('stream-timeout')),
    Math.max(1000, asNumber(timeoutMs, 60_000)),
  );
  const forward = () => controller.abort(signal?.reason);
  if (signal) {
    if (signal.aborted) controller.abort(signal.reason);
    else signal.addEventListener('abort', forward, { once: true });
  }

  let lastSeq = startSeq;
  const messages = [];
  try {
    let res;
    try {
      res = await fetchImpl(new URL(apiPath, trimBase(baseUrl) + '/').toString(), {
        method: 'GET',
        headers: { ...headers, Accept: SSE_ACCEPT, 'X-Peer-Enc': ENC_VERSION },
        signal: controller.signal,
      });
    } catch (error) {
      return { ok: false, reason: `stream-error: ${reason(error)}`, aborted: controller.signal.aborted, lastSeq, messages };
    }
    if (res.status !== 200) {
      try { await res.body?.cancel?.(); } catch {}
      let detail = '';
      try {
        const body = await res.json();
        detail = String(body?.error ?? '');
      } catch {}
      return { ok: false, reason: `http-${res.status}${detail ? ' ' + detail : ''}`, lastSeq, messages };
    }
    const contentType = String(res.headers?.get?.('content-type') ?? '');
    if (!contentType.includes(SSE_ACCEPT)) {
      try { await res.body?.cancel?.(); } catch {}
      return { ok: false, reason: 'not-event-stream', lastSeq, messages };
    }

    try {
      for await (const record of parseSseStream(res.body)) {
        const name = String(record.event || 'message');
        let payload;
        try {
          payload = decryptSseEvent(secret, record.data);
        } catch (error) {
          return { ok: false, reason: `bad-event: ${reason(error)}`, lastSeq, messages };
        }
        if (name === 'ping') {
          onPing?.(payload);
          continue;
        }
        const message = groupMessageSummary(payload);
        // seq 递增才收：断流续传/重复补发都靠这一条去重
        if (message.seq <= lastSeq) continue;
        lastSeq = message.seq;
        messages.push(message);
        onMessage?.(message);
        if (stopAt !== null && lastSeq >= stopAt) return { ok: true, lastSeq, messages };
      }
    } catch (error) {
      return {
        ok: false,
        reason: controller.signal.aborted ? 'aborted' : `stream-error: ${reason(error)}`,
        aborted: controller.signal.aborted,
        lastSeq,
        messages,
      };
    }
    return { ok: false, reason: 'stream-ended', lastSeq, messages };
  } finally {
    clearTimeout(timer);
    try { signal?.removeEventListener?.('abort', forward); } catch {}
  }
}

// ---------------------------------------------------------------------------
// S1 v0.6.0 群级鉴权：独立 canonical + HKDF(groupKey) 双密钥 + 端点封装
// ---------------------------------------------------------------------------

const emptyBuffer = () => Buffer.alloc(0);

const sha256HexBytes = (value) => createHash('sha256')
  .update(value == null ? emptyBuffer() : Buffer.from(value))
  .digest('hex');

const trimBaseUrl = (baseUrl) => String(baseUrl ?? '').trim().replace(/\/+$/, '');

/**
 * groupKey 是 group.json 里那把 32 字节 base64url 密钥；HKDF 的 ikm 用解码后的原始字节。
 * 这里不造新原语：HKDF-SHA256 派生签名/信封两把子密钥，HMAC 与 AES-256-GCM 都是既有用法。
 */
export function groupKeyBytes(groupKey) {
  const raw = Buffer.from(String(groupKey ?? ''), 'base64url');
  if (raw.length === 0) throw new Error('group-key-missing');
  return raw;
}

export function deriveGroupKeys(groupKey) {
  const ikm = groupKeyBytes(groupKey);
  return {
    signKey: Buffer.from(hkdfSync('sha256', ikm, GROUP_AUTH_SALT, GROUP_SIGN_INFO, 32)),
    bodyKey: Buffer.from(hkdfSync('sha256', ikm, GROUP_AUTH_SALT, GROUP_BODY_INFO, 32)),
  };
}

/**
 * 群级 canonical：独立于 §4 的五行的另一种格式，\n 连接、无尾随换行。
 *   GROUP / METHOD / path(含 query) / ts / nonce / groupId / senderPeerId / sha256(body)
 * GET 没有 body，最后一行就是 sha256("")。
 */
export function buildGroupCanonical({ method, path: requestPath, ts, nonce, groupId, senderPeerId, rawBody }) {
  return [
    'GROUP',
    String(method ?? '').toUpperCase(),
    String(requestPath ?? ''),
    String(ts ?? ''),
    String(nonce ?? ''),
    String(groupId ?? ''),
    String(senderPeerId ?? ''),
    sha256HexBytes(rawBody),
  ].join('\n');
}

/** HMAC-SHA256(signKey, canonical) -> base64url */
export function signGroupCanonical({ signKey, canonical }) {
  return createHmac('sha256', signKey).update(String(canonical), 'utf8').digest('base64url');
}

/** 群信封：与 wire-crypto 同一布局 base64url(nonce || ciphertext || tag)，密钥换成 HKDF 派生的 bodyKey */
export function encryptGroupBody(bodyKey, plaintext) {
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', bodyKey, nonce);
  const bytes = typeof plaintext === 'string' ? Buffer.from(plaintext, 'utf8') : Buffer.from(plaintext ?? emptyBuffer());
  const ciphertext = Buffer.concat([cipher.update(bytes), cipher.final()]);
  return Buffer.concat([nonce, ciphertext, cipher.getAuthTag()]).toString('base64url');
}

export function decryptGroupBody(bodyKey, payload) {
  const raw = Buffer.from(String(payload ?? ''), 'base64url');
  if (raw.length < 28) throw new Error('bad-group-encrypted-body');
  const nonce = raw.subarray(0, 12);
  const tag = raw.subarray(raw.length - 16);
  const ciphertext = raw.subarray(12, raw.length - 16);
  const decipher = createDecipheriv('aes-256-gcm', bodyKey, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

export const encryptGroupJson = (bodyKey, value) => encryptGroupBody(bodyKey, Buffer.from(JSON.stringify(value), 'utf8'));

export const decryptGroupJson = (bodyKey, payload) => JSON.parse(decryptGroupBody(bodyKey, payload).toString('utf8'));

/** 造一组群级签名头（测试与 groupCall 共用；负例可以覆盖 ts/nonce/groupId/signature） */
export function groupAuthHeaders({
  groupKey,
  groupId,
  senderId,
  method = 'GET',
  apiPath,
  body,
  selfBaseUrl = '',
  lastSeq,
  acceptDispatch,
  ts,
  nonce,
  signature,
}) {
  const { signKey } = deriveGroupKeys(groupKey);
  const plain = body === undefined ? emptyBuffer() : Buffer.from(JSON.stringify(body), 'utf8');
  const stamp = ts ?? Date.now();
  const freshNonce = nonce ?? randomBytes(16).toString('hex');
  const canonical = buildGroupCanonical({
    method,
    path: apiPath,
    ts: stamp,
    nonce: freshNonce,
    groupId,
    senderPeerId: senderId,
    rawBody: plain,
  });
  const headers = {
    [GROUP_AUTH_HEADER]: GROUP_AUTH_VALUE,
    'X-Peer-Id': String(senderId ?? ''),
    [GROUP_ID_HEADER]: String(groupId ?? ''),
    'X-Peer-Ts': String(stamp),
    'X-Peer-Nonce': freshNonce,
    'X-Peer-Sign': signature ?? signGroupCanonical({ signKey, canonical }),
  };
  const self = trimBaseUrl(selfBaseUrl);
  if (self !== '') headers[GROUP_BASE_HEADER] = self;
  const seq = Number(lastSeq);
  if (Number.isFinite(seq) && seq >= 0) headers[GROUP_LASTSEQ_HEADER] = String(Math.floor(seq));
  // v0.8.2-α §4：本机接单开关。GET 没有 body，只能靠 header 自报；
  // 不传就不带头（老端不认识，hub 侧缺失按 true）
  if (acceptDispatch === true || acceptDispatch === false) {
    headers[GROUP_ACCEPT_HEADER] = acceptDispatch ? '1' : '0';
  }
  return { plain, canonical, headers };
}

/** 群级签名的请求/响应（与 callPeer 同一套语义：签名覆盖明文，线上走群信封） */
export async function groupCall({
  baseUrl,
  groupKey,
  groupId,
  senderId,
  method = 'GET',
  apiPath,
  body,
  selfBaseUrl = '',
  lastSeq,
  acceptDispatch,
  identity,
  timeoutMs = 10_000,
  fetchImpl = fetch,
}) {
  const { bodyKey } = deriveGroupKeys(groupKey);
  // §8.3 生产接线：identity 生效才走 v2 头（多 X-Peer-Cert），否则**逐字节**走既有 v1。
  // 两个分支用的是同两个既有函数，v1 那条路径的输入与改动前完全相同。
  const headerArgs = { groupKey, groupId, senderId, method, apiPath, body, selfBaseUrl, lastSeq, acceptDispatch };
  const { headers, plain } = identity?.ok === true
    ? groupAuthHeadersWithIdentity({ identity, ...headerArgs })
    : groupAuthHeaders(headerArgs);
  const wire = plain.length ? Buffer.from(encryptGroupBody(bodyKey, plain), 'utf8') : emptyBuffer();
  const res = await fetchImpl(new URL(apiPath, trimBaseUrl(baseUrl) + '/').toString(), {
    method,
    headers: { ...headers, [ENC_HEADER]: ENC_VERSION },
    body: wire.length && method !== 'GET' && method !== 'HEAD' ? wire : undefined,
    signal: AbortSignal.timeout(Math.max(1000, Number(timeoutMs) || 10_000)),
  });
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    throw new Error(`HTTP ${res.status}: ${text.slice(0, 120)}`);
  }
  if (json && json.enc === ENC_VERSION && typeof json.data === 'string') {
    json = decryptGroupJson(bodyKey, json.data);
  }
  if (!res.ok) {
    // 失败也把对端的结构化 body 带出来：S3 的心跳/投票要靠它读 epoch（stale-epoch /
    // leader-conflict 的裁决依据）。message 格式保持原样，老调用方不受影响。
    const error = new Error(`${res.status} ${json?.error || ''}`.trim());
    error.status = res.status;
    error.code = String(json?.error ?? '');
    error.body = json;
    throw error;
  }
  return json;
}

// ---------------------------------------------------------------------------
// P2 · v2 通道（证书 + ed25519）：`.tmp/group-v2-wire-contract.md` §2/§4/§5/§6
//
// 与上面的 v1 通道**并列**，v1 那几行一个字都不动（两端真机在跑，是既成事实）。
// 域分离靠 `X-Peer-Auth: group-v2` + 证书 + 算法（HMAC vs ed25519），**不靠 canonical**：
// buildGroupCanonicalV2 与 buildGroupCanonical 逐字节相同（HANDOVER §0.7h-2）。
// 共用字面量按契约 §7 各侧本地定义，这里不 import 服务端任何文件。
// ---------------------------------------------------------------------------

/** §1：v2 走证书 + ed25519（v1 的值是 GROUP_AUTH_VALUE='group'） */
export const GROUP_AUTH_VALUE_V2 = 'group-v2';

/** §2：v2 头集合只比 v1 多这一个 —— base64url(UTF8(JSON.stringify(cert))) */
export const GROUP_CERT_HEADER = 'X-Peer-Cert';

/** §5：两条身份端点（字面量；服务端侧另有自己的本地集合，本数组不进 GROUP_AUTH_PATHS） */
export const GROUP_IDENTITY_REGISTER_PATH = '/v1/group/identity/register';
export const GROUP_IDENTITY_ROTATE_PATH = '/v1/group/identity/rotate';
export const GROUP_IDENTITY_PATHS = Object.freeze([
  GROUP_IDENTITY_REGISTER_PATH,
  GROUP_IDENTITY_ROTATE_PATH,
]);

/** §4：成员侧身份文件都在 <stateDir>/group/ 下（与 member-key.json 同目录） */
export const GROUP_IDENTITY_DIR = 'group';
export const GROUP_MEMBER_CERT_FILE = 'member-cert.json';
export const GROUP_TRUSTED_HUB_CA_FILE = 'trusted-hub-ca.json';

/** 可识别的稳定错误码（证书与私钥对不上：本地文件被换/被改） */
export const GROUP_CERT_KEY_MISMATCH = 'cert-key-mismatch';

const identityError = (code, detail) => {
  const err = new Error(detail ? `${code}: ${detail}` : code);
  err.code = code;
  return err;
};

const identityFail = (code, extra) => ({ ok: false, code, ...(extra ?? {}) });

/** 成员证书路径：<stateDir>/group/member-cert.json */
export function memberCertPath(stateDir) {
  return path.join(String(stateDir ?? ''), GROUP_IDENTITY_DIR, GROUP_MEMBER_CERT_FILE);
}

/** 信任根路径：<stateDir>/group/trusted-hub-ca.json */
export function trustedHubCaPath(stateDir) {
  return path.join(String(stateDir ?? ''), GROUP_IDENTITY_DIR, GROUP_TRUSTED_HUB_CA_FILE);
}

/** 同目录临时文件 + fsync + rename：崩在中间不会留下半个身份文件（目录 0700 / 文件 0600） */
function writeIdentityJson0600(file, value) {
  const dir = path.dirname(file);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tmp = path.join(dir, `.${path.basename(file)}.${randomBytes(6).toString('hex')}.tmp`);
  let fd;
  try {
    fd = fs.openSync(tmp, 'wx', 0o600);
    fs.writeFileSync(fd, `${JSON.stringify(value, null, 2)}\n`);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(tmp, file);
  } catch (err) {
    if (fd !== undefined) { try { fs.closeSync(fd); } catch {} }
    try { fs.unlinkSync(tmp); } catch {}
    throw err;
  }
  try { fs.chmodSync(file, 0o600); } catch {}
}

/**
 * 安静读一个 JSON 文件：**绝不抛错**，缺失与损坏都变成可识别 code。
 * 缺失 = IDENTITY_MISSING（调用方可以先 register），损坏 = IDENTITY_UNAVAILABLE。
 */
function readIdentityJson(stateDir, file, noStateDirReason) {
  const dir = String(stateDir ?? '').trim();
  if (dir === '') return identityFail(IDENTITY_MISSING, { reason: noStateDirReason });
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (err) {
    const missing = err && err.code === 'ENOENT';
    return identityFail(missing ? IDENTITY_MISSING : IDENTITY_UNAVAILABLE, {
      reason: missing ? 'missing' : 'read-failed',
    });
  }
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch {
    return identityFail(IDENTITY_UNAVAILABLE, { reason: 'malformed-json' });
  }
}

const isNonEmptyText = (value) => typeof value === 'string' && value !== '';

/**
 * 读 <stateDir>/group/member-cert.json（契约 §4）。
 * 返回 { ok:true, cert } 或 { ok:false, code, reason } —— **不抛未捕获异常**。
 */
export function readMemberCertFile(stateDir) {
  const read = readIdentityJson(stateDir, memberCertPath(stateDir), 'no-state-dir');
  if (!read.ok) return read;
  const cert = read.value;
  const bad = () => identityFail(IDENTITY_UNAVAILABLE, { reason: 'malformed-cert' });
  if (!cert || typeof cert !== 'object' || Array.isArray(cert)) return bad();
  if (!isNonEmptyText(cert.peerId) || !isNonEmptyText(cert.pubKey) || !isNonEmptyText(cert.groupId)) return bad();
  if (cert.alg !== CERT_ALG) return bad();
  if (!isNonEmptyText(cert.sig)) return bad();
  if (!Number.isFinite(Number(cert.issuedAt)) || !Number.isFinite(Number(cert.expiresAt))) return bad();
  return { ok: true, cert };
}

/** 写 <stateDir>/group/member-cert.json（0600、原子写）。失败照常抛（磁盘满不该被吞） */
export function writeMemberCertFile(stateDir, cert) {
  const dir = String(stateDir ?? '').trim();
  if (dir === '') throw identityError(IDENTITY_UNAVAILABLE, 'state-dir-required');
  if (!cert || typeof cert !== 'object' || Array.isArray(cert)) {
    throw identityError(IDENTITY_UNAVAILABLE, 'cert-required');
  }
  const file = memberCertPath(dir);
  writeIdentityJson0600(file, cert);
  return { path: file, bytes: Buffer.byteLength(JSON.stringify(cert), 'utf8') };
}

/** 读 <stateDir>/group/trusted-hub-ca.json：{hubCaPubKey, hubEpoch, at, source} */
export function readTrustedHubCaFile(stateDir) {
  const read = readIdentityJson(stateDir, trustedHubCaPath(stateDir), 'no-state-dir');
  if (!read.ok) return read;
  const raw = read.value;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return identityFail(IDENTITY_UNAVAILABLE, { reason: 'malformed-trusted-hub-ca' });
  }
  if (!isNonEmptyText(raw.hubCaPubKey)) {
    return identityFail(IDENTITY_UNAVAILABLE, { reason: 'malformed-trusted-hub-ca' });
  }
  const hubEpoch = Number(raw.hubEpoch);
  const at = Number(raw.at);
  return {
    ok: true,
    trust: {
      hubCaPubKey: raw.hubCaPubKey,
      hubEpoch: Number.isFinite(hubEpoch) ? Math.trunc(hubEpoch) : 0,
      at: Number.isFinite(at) ? Math.trunc(at) : 0,
      source: String(raw.source ?? ''),
    },
  };
}

/** 写 <stateDir>/group/trusted-hub-ca.json（字段序按契约 §4，0600、原子写） */
export function writeTrustedHubCaFile(stateDir, trust, options = {}) {
  const dir = String(stateDir ?? '').trim();
  if (dir === '') throw identityError(IDENTITY_UNAVAILABLE, 'state-dir-required');
  const entry = {
    hubCaPubKey: String(trust?.hubCaPubKey ?? ''),
    hubEpoch: Number.isFinite(Number(trust?.hubEpoch)) ? Math.trunc(Number(trust.hubEpoch)) : 0,
    at: Number.isFinite(Number(trust?.at)) ? Math.trunc(Number(trust.at)) : Math.trunc(Number(options.now ?? Date.now())),
    source: String(trust?.source ?? 'register'),
  };
  if (entry.hubCaPubKey === '') throw identityError(IDENTITY_UNAVAILABLE, 'hub-ca-pubkey-required');
  const file = trustedHubCaPath(dir);
  writeIdentityJson0600(file, entry);
  return { path: file, trust: entry };
}

/**
 * 一次性判定「本地能不能走 v2」：证书 + 与证书配对的私钥 + 可信 hub CA，三者齐备且证书验得过才 ok。
 * **绝不抛错**（读盘/解析/验签全部兜住）：调用方据此在 v1/v2 之间二选一。
 * 返回 { ok:true, cert, keypair, trustedHubCa, grace } 或 { ok:false, code, reason }。
 */
export function loadGroupIdentity(stateDir, options = {}) {
  const now = Number(options.now ?? Date.now());
  const graceMs = Number(options.graceMs ?? DEFAULT_GRACE_MS);
  const certRead = readMemberCertFile(stateDir);
  if (!certRead.ok) return certRead;
  const cert = certRead.cert;
  let keypair;
  try {
    keypair = loadKeypair(stateDir, { fingerprint: options.fingerprint });
  } catch (err) {
    return identityFail(String(err?.code ?? IDENTITY_UNAVAILABLE), { reason: 'keypair-unavailable', cert });
  }
  // 证书里的 pubKey 必须是这把私钥的对应公钥，否则「有证书有私钥却签不过」是最难排查的一类
  if (String(cert.pubKey) !== String(keypair.publicKeyDer)) {
    return identityFail(GROUP_CERT_KEY_MISMATCH, { reason: 'pubkey-mismatch', cert });
  }
  const trustRead = readTrustedHubCaFile(stateDir);
  if (!trustRead.ok) return identityFail(trustRead.code, { reason: 'trusted-hub-ca-unavailable', cert });
  let verdict;
  try {
    verdict = verifyCertificate(publicKeyFromText(trustRead.trust.hubCaPubKey), cert, { now, graceMs });
  } catch {
    return identityFail('untrusted-ca', { reason: 'bad-ca-public-key', cert });
  }
  if (!verdict || verdict.ok !== true) {
    return identityFail('untrusted-ca', { reason: String(verdict?.reason ?? 'unknown'), cert });
  }
  return { ok: true, cert, keypair, trustedHubCa: trustRead.trust, grace: verdict.grace === true };
}

/** 证书上线格式（契约 §2）：base64url(UTF8(JSON.stringify(cert))) */
export function encodeGroupCertHeader(cert) {
  return Buffer.from(JSON.stringify(cert ?? null), 'utf8').toString('base64url');
}

/** X-Peer-Cert → 证书对象；解析不了返回 null（**不抛错**，服务端按 401 bad-certificate 处理） */
export function decodeGroupCertHeader(value) {
  try {
    const parsed = JSON.parse(Buffer.from(String(value ?? ''), 'base64url').toString('utf8'));
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

/**
 * 造一组 v2 头（契约 §2）：字段名与 v1 完全一致，只多 X-Peer-Cert。
 * 签名字节 = buildGroupCanonicalV2(...) 的 UTF-8，算法 ed25519（复用 P1 的 signMessage）。
 * 签名覆盖**明文 body**（与 v1 相同；加密信封在更外层）。
 */
export function groupAuthHeadersV2({
  cert,
  privateKey,
  groupId,
  senderId,
  method = 'GET',
  apiPath,
  body,
  selfBaseUrl = '',
  lastSeq,
  acceptDispatch,
  ts,
  nonce,
  signature,
}) {
  if (!cert || typeof cert !== 'object' || Array.isArray(cert)) {
    throw identityError(IDENTITY_UNAVAILABLE, 'cert-required');
  }
  if (!privateKey) throw identityError(IDENTITY_UNAVAILABLE, 'private-key-required');
  const plain = body === undefined ? emptyBuffer() : Buffer.from(JSON.stringify(body), 'utf8');
  const stamp = ts ?? Date.now();
  const freshNonce = nonce ?? randomBytes(16).toString('hex');
  const peerId = String(senderId ?? cert.peerId ?? '');
  const group = String(groupId ?? cert.groupId ?? '');
  const canonical = buildGroupCanonicalV2({
    method,
    path: apiPath,
    ts: stamp,
    nonce: freshNonce,
    groupId: group,
    senderPeerId: peerId,
    rawBody: plain,
  });
  const headers = {
    [GROUP_AUTH_HEADER]: GROUP_AUTH_VALUE_V2,
    'X-Peer-Id': peerId,
    [GROUP_ID_HEADER]: group,
    'X-Peer-Ts': String(stamp),
    'X-Peer-Nonce': freshNonce,
    'X-Peer-Sign': signature ?? signMessage(privateKey, canonical),
    [GROUP_CERT_HEADER]: encodeGroupCertHeader(cert),
  };
  const self = trimBaseUrl(selfBaseUrl);
  if (self !== '') headers[GROUP_BASE_HEADER] = self;
  const seq = Number(lastSeq);
  if (Number.isFinite(seq) && seq >= 0) headers[GROUP_LASTSEQ_HEADER] = String(Math.floor(seq));
  if (acceptDispatch === true || acceptDispatch === false) {
    headers[GROUP_ACCEPT_HEADER] = acceptDispatch ? '1' : '0';
  }
  return { plain, canonical, headers };
}

/**
 * **回落**（契约 §6）：本地身份可用才走 v2，否则一律 v1 —— **不得报错中断**。
 * v1 分支的输出与 groupAuthHeaders 逐字段相同（同一个函数算出来的），既有行为一字不变。
 * identity 可注入（{ok,cert,keypair,...}），省掉测试时读真机指纹。
 */
export function groupAuthHeadersWithIdentity({
  stateDir,
  identity,
  fingerprint,
  now,
  graceMs,
  ...rest
}) {
  const v1 = groupAuthHeaders(rest);
  const resolved = identity === undefined ? loadGroupIdentity(stateDir, { fingerprint, now, graceMs }) : identity;
  if (!resolved || resolved.ok !== true) {
    return { version: 'v1', reason: String(resolved?.code ?? 'identity-unavailable'), ...v1 };
  }
  const { cert, keypair } = resolved;
  const peerId = rest.senderId === undefined ? cert.peerId : rest.senderId;
  const group = rest.groupId === undefined ? cert.groupId : rest.groupId;
  // 证书与这次请求的身份/群不一致时不要签：签了也会被 401，白跑一趟网络
  if (String(cert.peerId) !== String(peerId)) {
    return { version: 'v1', reason: 'cert-peer-mismatch', ...v1 };
  }
  if (String(cert.groupId) !== String(group)) {
    return { version: 'v1', reason: 'cert-group-mismatch', ...v1 };
  }
  const v2 = groupAuthHeadersV2({
    ...rest,
    cert,
    privateKey: keypair.privateKey,
    senderId: peerId,
    groupId: group,
  });
  return { version: 'v2', cert, identity: resolved, ...v2 };
}

/** v2 版的群级请求（与 groupCall 同一套语义：签名覆盖明文，线上走群信封） */
export async function groupCallV2({
  baseUrl,
  groupKey,
  groupId,
  senderId,
  cert,
  privateKey,
  method = 'GET',
  apiPath,
  body,
  selfBaseUrl = '',
  lastSeq,
  acceptDispatch,
  timeoutMs = 10_000,
  fetchImpl = fetch,
}) {
  const { bodyKey } = deriveGroupKeys(groupKey);
  const { headers, plain } = groupAuthHeadersV2({
    cert,
    privateKey,
    groupId,
    senderId,
    method,
    apiPath,
    body,
    selfBaseUrl,
    lastSeq,
    acceptDispatch,
  });
  const wire = plain.length ? Buffer.from(encryptGroupBody(bodyKey, plain), 'utf8') : emptyBuffer();
  const res = await fetchImpl(new URL(apiPath, trimBaseUrl(baseUrl) + '/').toString(), {
    method,
    headers: { ...headers, [ENC_HEADER]: ENC_VERSION },
    body: wire.length && method !== 'GET' && method !== 'HEAD' ? wire : undefined,
    signal: AbortSignal.timeout(Math.max(1000, Number(timeoutMs) || 10_000)),
  });
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    throw new Error(`HTTP ${res.status}: ${text.slice(0, 120)}`);
  }
  if (json && json.enc === ENC_VERSION && typeof json.data === 'string') {
    json = decryptGroupJson(bodyKey, json.data);
  }
  if (!res.ok) {
    const error = new Error(`${res.status} ${json?.error || ''}`.trim());
    error.status = res.status;
    error.code = String(json?.error ?? '');
    error.body = json;
    throw error;
  }
  return json;
}

/**
 * POST /v1/group/identity/register —— 用 **v1 头**（证明握有 groupKey = 群成员，鸡生蛋只能这么解）。
 * body 明文（群信封内）{peerId, pubKey, groupId}；响应 {cert, hubCaPubKey, hubEpoch}。
 * 拿到就落盘 member-cert.json + trusted-hub-ca.json；没有私钥则**不发请求**（回落 v1）。
 * 私钥归调用方：register 只写 hub 返回的那两份文件（自己 saveKeypair 过的才不会「有证书没钥匙」）。
 */
export async function registerGroupIdentity({
  stateDir,
  baseUrl,
  groupKey,
  groupId,
  peerId,
  keypair,
  pairSecret,
  persist = true,
  timeoutMs,
  fetchImpl,
} = {}) {
  let pair = keypair;
  if (!pair) {
    try {
      pair = loadKeypair(stateDir);
    } catch (err) {
      return { skipped: true, reason: String(err?.code ?? IDENTITY_MISSING) };
    }
  }
  if (!pair || !pair.publicKeyDer) return { skipped: true, reason: IDENTITY_MISSING };
  const body = { peerId: String(peerId ?? ''), pubKey: String(pair.publicKeyDer), groupId: String(groupId ?? '') };
  // §8.2：hub 有该 peerId 的配对记录时 register 必须带 per-peer 证明。
  // 给了 pairSecret 才带（键都不出现）；证明覆盖的 body 固定三字段、固定顺序，**不含** pairProof 自身。
  if (pairSecret !== undefined && pairSecret !== null && String(pairSecret) !== '') {
    const ts = Date.now();
    const nonce = randomBytes(16).toString('hex');
    const bodyForProof = Buffer.from(
      JSON.stringify({ peerId: body.peerId, pubKey: body.pubKey, groupId: body.groupId }),
      'utf8',
    );
    body.pairProof = {
      ts,
      nonce,
      sig: perPeerSign(String(pairSecret), perPeerCanonical('POST', GROUP_IDENTITY_REGISTER_PATH, ts, nonce, bodyForProof)),
    };
  }
  const answer = await groupCall({
    baseUrl,
    groupKey,
    groupId,
    senderId: body.peerId,
    method: 'POST',
    apiPath: GROUP_IDENTITY_REGISTER_PATH,
    body,
    timeoutMs,
    fetchImpl,
  });
  const cert = answer?.cert ?? null;
  const saved = {};
  if (persist && stateDir && cert) {
    saved.memberCert = writeMemberCertFile(stateDir, cert).path;
    saved.trustedHubCa = writeTrustedHubCaFile(stateDir, {
      hubCaPubKey: answer?.hubCaPubKey,
      hubEpoch: answer?.hubEpoch,
      source: 'register',
    }).path;
  }
  return { ok: true, cert, hubCaPubKey: String(answer?.hubCaPubKey ?? ''), hubEpoch: Number(answer?.hubEpoch ?? 0), saved };
}

/**
 * POST /v1/group/identity/rotate —— 用 **v2 头**（旧证书 + 旧私钥证明身份）。
 * body {peerId, newPubKey, groupId}；响应同 register。
 * 本地证书还没到轮换时刻就**不发请求**（省一次往返）；身份不可用同样不发请求（继续走 v1）。
 */
export async function rotateGroupIdentity({
  stateDir,
  baseUrl,
  groupKey,
  groupId,
  peerId,
  newKeypair,
  identity,
  persist = true,
  fingerprint,
  now = Date.now(),
  timeoutMs,
  fetchImpl,
} = {}) {
  const current = identity === undefined ? loadGroupIdentity(stateDir, { fingerprint, now }) : identity;
  if (!current || current.ok !== true) {
    return { skipped: true, reason: String(current?.code ?? IDENTITY_UNAVAILABLE) };
  }
  if (!needsRotation(current.cert, { now, rotateAfterMs: DEFAULT_ROTATE_AFTER_MS })) {
    return { skipped: true, reason: 'not-due', cert: current.cert };
  }
  const next = newKeypair ?? createKeypair();
  const body = {
    peerId: String(peerId ?? current.cert.peerId ?? ''),
    newPubKey: String(next.publicKeyDer ?? ''),
    groupId: String(groupId ?? current.cert.groupId ?? ''),
  };
  const answer = await groupCallV2({
    baseUrl,
    groupKey,
    groupId: body.groupId,
    senderId: body.peerId,
    cert: current.cert,
    privateKey: current.keypair.privateKey,
    method: 'POST',
    apiPath: GROUP_IDENTITY_ROTATE_PATH,
    body,
    timeoutMs,
    fetchImpl,
  });
  const cert = answer?.cert ?? null;
  const saved = {};
  if (persist && stateDir && cert) {
    // 顺序：先落新私钥再落新证书。任何一步失败都不会把「新证书 + 旧私钥」留在盘上
    saved.memberKey = saveKeypair(stateDir, next, { fingerprint, peerId: body.peerId }).path;
    saved.memberCert = writeMemberCertFile(stateDir, cert).path;
    saved.trustedHubCa = writeTrustedHubCaFile(stateDir, {
      hubCaPubKey: answer?.hubCaPubKey,
      hubEpoch: answer?.hubEpoch,
      source: 'rotate',
    }).path;
  }
  return {
    ok: true,
    cert,
    keypair: next,
    hubCaPubKey: String(answer?.hubCaPubKey ?? ''),
    hubEpoch: Number(answer?.hubEpoch ?? 0),
    saved,
  };
}

/** GET /v1/group/probe —— {ok, peerId, name, groupId, epoch, leaderPeerId, lastSeq, advertiseBaseUrl} */
export function probeGroupPeer({
  baseUrl,
  groupKey,
  groupId,
  senderId,
  selfBaseUrl = '',
  lastSeq,
  acceptDispatch,
  identity,
  timeoutMs,
  fetchImpl,
} = {}) {
  return groupCall({
    baseUrl, groupKey, groupId, senderId, selfBaseUrl, lastSeq, acceptDispatch, identity, timeoutMs, fetchImpl,
    method: 'GET',
    apiPath: '/v1/group/probe',
  });
}

/** GET /v1/group/pull?sinceSeq&limit —— 补差 */
export function pullGroupMessages({
  baseUrl,
  groupKey,
  groupId,
  senderId,
  sinceSeq = 0,
  limit = 200,
  selfBaseUrl = '',
  lastSeq,
  acceptDispatch,
  identity,
  timeoutMs,
  fetchImpl,
} = {}) {
  const since = Math.max(0, Math.floor(asNumber(sinceSeq, 0)));
  const cap = Math.min(Math.max(1, Math.floor(asNumber(limit, 200))), 200);
  return groupCall({
    baseUrl, groupKey, groupId, senderId, selfBaseUrl, lastSeq, acceptDispatch, identity, timeoutMs, fetchImpl,
    method: 'GET',
    apiPath: `/v1/group/pull?sinceSeq=${since}&limit=${cap}`,
  });
}

/** POST /v1/group/replicate —— leader 写本地后推给成员；返回 {ok, lastSeq} */
export function replicateGroupMessages({
  baseUrl,
  groupKey,
  groupId,
  senderId,
  epoch = 0,
  leaderPeerId = '',
  messages = [],
  selfBaseUrl = '',
  identity,
  timeoutMs,
  fetchImpl,
} = {}) {
  return groupCall({
    baseUrl, groupKey, groupId, senderId, selfBaseUrl, identity, timeoutMs, fetchImpl,
    method: 'POST',
    apiPath: '/v1/group/replicate',
    body: { groupId, epoch, leaderPeerId, messages },
  });
}

/** GET /v1/group/leader */
export function fetchGroupLeader({ baseUrl, groupKey, groupId, senderId, selfBaseUrl = '', identity, timeoutMs, fetchImpl } = {}) {
  return groupCall({
    baseUrl, groupKey, groupId, senderId, selfBaseUrl, identity, timeoutMs, fetchImpl,
    method: 'GET',
    apiPath: '/v1/group/leader',
  });
}

// ---------------------------------------------------------------------------
// S3 v0.7.0：心跳 / 拉票 / 提案 / 提交四个原语（全部复用 groupCall 的签名与信封）
// ---------------------------------------------------------------------------

/**
 * POST /v1/group/leader —— leader 心跳（与 GET 同路径共存：GET 查询 / POST 心跳）。
 * 返回 {ok, epoch, commitSeq}；对端 epoch 更高、或合法 leader 是别人时会抛 409。
 */
export function sendGroupHeartbeat({
  baseUrl,
  groupKey,
  groupId,
  senderId,
  epoch = 0,
  leaderPeerId = '',
  lastSeq = 0,
  commitSeq = 0,
  priority = GROUP_DEFAULT_HUB_PRIORITY,
  selfBaseUrl = '',
  acceptDispatch,
  identity,
  timeoutMs,
  fetchImpl,
} = {}) {
  const body = {
    epoch: Math.max(0, Math.floor(asNumber(epoch, 0))),
    leaderPeerId: String(leaderPeerId ?? ''),
    lastSeq: asSeq(lastSeq),
    commitSeq: asSeq(commitSeq),
    // 追加字段：同 epoch 冲突要用它按 priority → peerId 裁决（契约 §4），老对端忽略即可
    priority: Math.floor(asNumber(priority, GROUP_DEFAULT_HUB_PRIORITY)),
  };
  // v0.8.2-α §4：接单开关随心跳自报（hub 落进 group.json.members[].acceptDispatch）
  if (acceptDispatch === true || acceptDispatch === false) body.acceptDispatch = acceptDispatch;
  return groupCall({
    baseUrl, groupKey, groupId, senderId, selfBaseUrl, identity, timeoutMs, fetchImpl,
    method: 'POST',
    apiPath: '/v1/group/leader',
    body,
  });
}

/** POST /v1/group/election —— 拉票：{epoch, candidate, priority} → {vote, reason?, epoch} */
export function requestGroupVote({
  baseUrl,
  groupKey,
  groupId,
  senderId,
  epoch = 0,
  candidate = '',
  priority = GROUP_DEFAULT_HUB_PRIORITY,
  selfBaseUrl = '',
  acceptDispatch,
  identity,
  timeoutMs,
  fetchImpl,
} = {}) {
  const body = {
    epoch: Math.max(0, Math.floor(asNumber(epoch, 0))),
    candidate: String(candidate ?? ''),
    priority: Math.floor(asNumber(priority, GROUP_DEFAULT_HUB_PRIORITY)),
  };
  // v0.8.2-α §4：拉票顺带自报接单开关（发送方 = auth.peerId）
  if (acceptDispatch === true || acceptDispatch === false) body.acceptDispatch = acceptDispatch;
  return groupCall({
    baseUrl, groupKey, groupId, senderId, selfBaseUrl, identity, timeoutMs, fetchImpl,
    method: 'POST',
    apiPath: '/v1/group/election',
    body,
  });
}

/** POST /v1/group/propose —— 提案：{epoch, seq, message} → {ok, accepted} */
export function proposeGroupMessage({
  baseUrl,
  groupKey,
  groupId,
  senderId,
  epoch = 0,
  seq = 0,
  message,
  selfBaseUrl = '',
  identity,
  timeoutMs,
  fetchImpl,
} = {}) {
  return groupCall({
    baseUrl, groupKey, groupId, senderId, selfBaseUrl, identity, timeoutMs, fetchImpl,
    method: 'POST',
    apiPath: '/v1/group/propose',
    body: { epoch: Math.max(0, Math.floor(asNumber(epoch, 0))), seq: asSeq(seq), message },
  });
}

/**
 * POST /v1/group/commit —— 提交确认：{epoch, seq} → {ok, commitSeq}。
 * 契约只要求 {epoch, seq}；同时带上 message 是**追加字段**：
 * propose 丢包时成员靠它把消息转正，避免「同一个 seq 上一次被丢弃的提案被这条 commit 误转正」。
 */
export function commitGroupMessage({
  baseUrl,
  groupKey,
  groupId,
  senderId,
  epoch = 0,
  seq = 0,
  message,
  selfBaseUrl = '',
  identity,
  timeoutMs,
  fetchImpl,
} = {}) {
  const body = { epoch: Math.max(0, Math.floor(asNumber(epoch, 0))), seq: asSeq(seq) };
  if (message && typeof message === 'object') body.message = message;
  return groupCall({
    baseUrl, groupKey, groupId, senderId, selfBaseUrl, identity, timeoutMs, fetchImpl,
    method: 'POST',
    apiPath: '/v1/group/commit',
    body,
  });
}

/** GET /v1/group/lease —— 本机角色/epoch/租约（排障与 CLI 用，只读） */
export function fetchGroupLease({ baseUrl, groupKey, groupId, senderId, selfBaseUrl = '', identity, timeoutMs, fetchImpl } = {}) {
  return groupCall({
    baseUrl, groupKey, groupId, senderId, selfBaseUrl, identity, timeoutMs, fetchImpl,
    method: 'GET',
    apiPath: '/v1/group/lease',
  });
}

// ---------------------------------------------------------------------------
// 成员侧本地密钥文件：group-key.json（0600，与 group-replica.json 同目录）
// ---------------------------------------------------------------------------

function writeJson0600File(file, value) {
  const dir = path.dirname(file);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tmp = `${file}.tmp-${process.pid}-${randomBytes(4).toString('hex')}`;
  fs.writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  try {
    fs.chmodSync(tmp, 0o600);
  } catch {}
  fs.renameSync(tmp, file);
  try {
    fs.chmodSync(file, 0o600);
  } catch {}
}

/** 读 <stateDir>/group-key.json；缺失/无效返回 null（不是成员或还没 bootstrap） */
export function readGroupKeyFile(stateDir) {
  const dir = String(stateDir ?? '').trim();
  if (dir === '') return null;
  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(path.join(dir, GROUP_KEY_FILE), 'utf8'));
  } catch {
    return null;
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const groupId = String(raw.groupId ?? '');
  const key = String(raw.key ?? '');
  if (groupId === '' || key === '') return null;
  // v0.8.1：字段改叫 keyVersion（它存的一直是群密钥世代，叫 epoch 容易与角色 epoch 混）；老文件 epoch 仍可读
  const keyVersionRaw = Number(raw.keyVersion ?? raw.epoch);
  const members = {};
  if (raw.members && typeof raw.members === 'object' && !Array.isArray(raw.members)) {
    for (const [peerId, member] of Object.entries(raw.members)) {
      // S3：baseUrl 是「这个成员在网络上自报过地址」的证据（决定 quorum 集合）
      members[peerId] = {
        name: String(member?.name ?? ''),
        baseUrl: String(member?.baseUrl ?? '').trim().replace(/\/+$/, ''),
        // v0.8.2-α §4：成员表里的接单开关（hub 的 state 里带下来；缺失 = true）
        acceptDispatch: acceptDispatchOf(member),
      };
    }
  }
  return {
    groupId,
    key,
    keyVersion: Number.isFinite(keyVersionRaw) && keyVersionRaw > 0 ? Math.floor(keyVersionRaw) : 0,
    // 兼容别名：内部还有读 epoch 的调用点，语义就是 keyVersion
    epoch: Number.isFinite(keyVersionRaw) && keyVersionRaw > 0 ? Math.floor(keyVersionRaw) : 0,
    leaderPeerId: String(raw.leaderPeerId ?? ''),
    name: String(raw.name ?? ''),
    // v0.8.0：群名（成员侧广播/查重要用；老文件没有就是空串，调用方回落到配置）
    groupName: String(raw.groupName ?? ''),
    // v0.8.0（契约 §5.1）：hub 是谁、在哪 —— 按名入群的节点没有 group.hub 配置，
    // 全靠这一条才能 bootstrap/pull/参与选举。老文件没有就是 null。
    hub: readGroupKeyHub(raw.hub),
    members,
  };
}

/** group-key.json 里的 hub 三元组（peerId/name/baseUrl），缺的字段给空串；整段缺失返回 null */
function readGroupKeyHub(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const hub = {
    peerId: String(raw.peerId ?? '').trim(),
    name: String(raw.name ?? '').trim(),
    baseUrl: String(raw.baseUrl ?? '').trim().replace(/\/+$/, ''),
  };
  return hub.peerId === '' && hub.name === '' && hub.baseUrl === '' ? null : hub;
}

export function writeGroupKeyFile(stateDir, value) {
  const dir = String(stateDir ?? '').trim();
  if (dir === '') throw new Error('state-dir-missing');
  // 入参两种写法都收（keyVersion 优先），落盘统一写 keyVersion
  const keyVersion = Number(value?.keyVersion ?? value?.epoch);
  const members = {};
  if (value?.members && typeof value.members === 'object' && !Array.isArray(value.members)) {
    for (const [peerId, member] of Object.entries(value.members)) {
      const baseUrl = String(member?.baseUrl ?? '').trim().replace(/\/+$/, '');
      members[String(peerId)] = {
        name: String(member?.name ?? ''),
        baseUrl,
        acceptDispatch: acceptDispatchOf(member),
      };
    }
  }
  const normalizedVersion = Number.isFinite(keyVersion) && keyVersion > 0 ? Math.floor(keyVersion) : 0;
  const next = {
    groupId: String(value?.groupId ?? ''),
    // v0.8.1：字段名从 epoch 改成 keyVersion（值不变，仍是群密钥世代）。
    // 暂留 epoch 作为**同值别名**：管理接口/测试/外部脚本可能还在读老字段，
    // 等下一次大版本再删（读侧已经优先 keyVersion）。
    keyVersion: normalizedVersion,
    epoch: normalizedVersion,
    leaderPeerId: String(value?.leaderPeerId ?? ''),
    name: String(value?.name ?? ''),
    // v0.8.0：群名（成员侧广播/查重）；不传就是空串，日志里也不打印
    groupName: normalizeGroupName(value?.groupName),
    // v0.8.0（契约 §5.1）：grants 带来的 hub 地址必须跟着密钥一起落盘，
    // 否则按名入群的节点既不知道往哪 pull，也起不了副本/选举。
    hub: readGroupKeyHub(value?.hub),
    key: String(value?.key ?? ''),
    members,
  };
  writeJson0600File(path.join(dir, GROUP_KEY_FILE), next);
  return next;
}


// ---------------------------------------------------------------------------
// S3 v0.7.0：本机角色文件 group-role.json（0600，与 group-key.json 同目录）
// ---------------------------------------------------------------------------

/**
 * 读 <stateDir>/group-role.json；缺失/无效返回 null。
 * 形状见契约 §1：{role, epoch, leaderPeerId, leaseUntil, commitSeq, votedFor}
 */
export function readGroupRoleFile(stateDir) {
  const dir = String(stateDir ?? '').trim();
  if (dir === '') return null;
  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(path.join(dir, GROUP_ROLE_FILE), 'utf8'));
  } catch {
    return null;
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const role = GROUP_ROLES.includes(String(raw.role ?? '')) ? String(raw.role) : 'follower';
  const epoch = Number(raw.epoch);
  const leaseUntil = Number(raw.leaseUntil);
  const commitSeq = Number(raw.commitSeq);
  const votedEpoch = Number(raw.votedFor?.epoch);
  return {
    role,
    epoch: Number.isFinite(epoch) && epoch > 0 ? Math.floor(epoch) : 0,
    leaderPeerId: String(raw.leaderPeerId ?? ''),
    leaseUntil: Number.isFinite(leaseUntil) && leaseUntil > 0 ? Math.floor(leaseUntil) : 0,
    commitSeq: Number.isFinite(commitSeq) && commitSeq > 0 ? Math.floor(commitSeq) : 0,
    votedFor: Number.isFinite(votedEpoch) && votedEpoch > 0 && String(raw.votedFor?.peerId ?? '') !== ''
      ? { epoch: Math.floor(votedEpoch), peerId: String(raw.votedFor.peerId) }
      : null,
    groupId: String(raw.groupId ?? ''),
  };
}

export function writeGroupRoleFile(stateDir, value) {
  const dir = String(stateDir ?? '').trim();
  if (dir === '') throw new Error('state-dir-missing');
  const epoch = Number(value?.epoch);
  const leaseUntil = Number(value?.leaseUntil);
  const commitSeq = Number(value?.commitSeq);
  const votedEpoch = Number(value?.votedFor?.epoch);
  const next = {
    role: GROUP_ROLES.includes(String(value?.role ?? '')) ? String(value.role) : 'follower',
    epoch: Number.isFinite(epoch) && epoch > 0 ? Math.floor(epoch) : 0,
    leaderPeerId: String(value?.leaderPeerId ?? ''),
    leaseUntil: Number.isFinite(leaseUntil) && leaseUntil > 0 ? Math.floor(leaseUntil) : 0,
    commitSeq: Number.isFinite(commitSeq) && commitSeq > 0 ? Math.floor(commitSeq) : 0,
    votedFor: Number.isFinite(votedEpoch) && votedEpoch > 0 && String(value?.votedFor?.peerId ?? '') !== ''
      ? { epoch: Math.floor(votedEpoch), peerId: String(value.votedFor.peerId) }
      : null,
    groupId: String(value?.groupId ?? ''),
  };
  writeJson0600File(path.join(dir, GROUP_ROLE_FILE), next);
  return next;
}

/**
 * 本机的群密钥：hub 在 group.json 的 key 里，成员在 group-key.json 里。
 * 只读、只在同一个 stateDir 内使用（CLI 排障命令用），任何日志都不打印它。
 */
export function readLocalGroupKey(stateDir) {
  const member = readGroupKeyFile(stateDir);
  if (member) return { groupId: member.groupId, key: member.key, members: member.members, epoch: member.epoch };
  const dir = String(stateDir ?? '').trim();
  if (dir === '') return null;
  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(path.join(dir, 'group.json'), 'utf8'));
  } catch {
    return null;
  }
  if (!raw || typeof raw !== 'object') return null;
  const groupId = String(raw.groupId ?? '');
  const key = String(raw.key ?? '');
  if (groupId === '' || key === '') return null;
  const members = {};
  for (const [peerId, member] of Object.entries(raw.members && typeof raw.members === 'object' ? raw.members : {})) {
    members[peerId] = { name: String(member?.name ?? '') };
  }
  return { groupId, key, members, epoch: Number(raw.keyVersion) || 0 };
}
// ---------------------------------------------------------------------------
// v0.8.0 群名广播 / 按名查找 / 按名申请（契约 §2–§7）
// ---------------------------------------------------------------------------

/** 每节点的两份新文件（都在 <stateDir> 下，0600） */
export const GROUP_KNOWN_GROUPS_FILE = 'known-groups.json';
export const GROUP_ADVERTISE_STATE_FILE = 'advertise-state.json';

/** 契约 §7：已知群上限 50 条 / TTL 30 天；广播按伙伴节流 6 小时；申请 TTL 24 小时 / 上限 100 条 */
export const GROUP_KNOWN_GROUPS_LIMIT = 50;
export const GROUP_KNOWN_GROUPS_TTL_MS = 30 * 86_400_000;
export const GROUP_ADVERTISEMENT_THROTTLE_MS = 6 * 60 * 60 * 1000;
export const GROUP_APPLICATION_LIMIT = 100;
export const GROUP_APPLICATION_TTL_MS = 24 * 60 * 60 * 1000;

/** 契约 §3 / §5.2：查找 2 秒；申请轮询 5 秒一次、最长 10 分钟 */
export const GROUP_LOOKUP_TIMEOUT_MS = 2_000;
export const GROUP_APPLY_POLL_INTERVAL_MS = 5_000;
export const GROUP_APPLY_POLL_TIMEOUT_MS = 10 * 60 * 1000;

/** 群名上限（名字不是正文，与 GROUP_TEXT_MAX_CHARS 无关） */
export const GROUP_NAME_MAX_CHARS = 64;

/** 申请状态取值（契约 §5.1；unknown = hub 上没有这条申请） */
export const GROUP_APPLICATION_STATUSES = Object.freeze(['pending', 'approved', 'rejected', 'unknown']);

/** 群名归一化：折叠空白、去首尾、按 code point 截到 64 字（中文不拆半字） */
export function normalizeGroupName(value) {
  const text = String(value ?? '').replace(/\s+/g, ' ').trim();
  return Array.from(text).slice(0, GROUP_NAME_MAX_CHARS).join('');
}

/** 契约 §3：名字比较 = 去空白后大小写不敏感精确匹配 */
export function sameGroupName(left, right) {
  const key = (value) => normalizeGroupName(value).replace(/\s+/g, '').toLowerCase();
  const wanted = key(right);
  return wanted !== '' && key(left) === wanted;
}

function emptyKnownGroups() {
  return { groups: {} };
}

/**
 * 已知群归一化：TTL 30 天（按 lastSeen）+ 上限 50 条（超出时保留最近见到的）。
 * 形状见契约 §7：{ groups: { groupId: { name, hub, source, firstSeen, lastSeen } } }
 */
export function normalizeKnownGroups(raw, { now = Date.now } = {}) {
  const source = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  const map = source.groups && typeof source.groups === 'object' && !Array.isArray(source.groups)
    ? source.groups
    : {};
  const nowMs = typeof now === 'function' ? Number(now()) : Number(now) || Date.now();
  const cutoff = nowMs - GROUP_KNOWN_GROUPS_TTL_MS;
  const entries = [];
  for (const [groupId, entry] of Object.entries(map)) {
    const id = String(groupId ?? '').trim();
    if (id === '' || !entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
    const lastRaw = Number(entry.lastSeen);
    const firstRaw = Number(entry.firstSeen);
    const lastSeen = Number.isFinite(lastRaw) && lastRaw > 0 ? Math.floor(lastRaw) : 0;
    // 没有 lastSeen 的老条目无从判断年龄：按过期处理（宁可重新广播一次）
    if (lastSeen === 0 || lastSeen < cutoff) continue;
    entries.push([id, {
      name: normalizeGroupName(entry.name),
      hub: {
        peerId: String(entry.hub?.peerId ?? ''),
        name: String(entry.hub?.name ?? ''),
        baseUrl: trimBase(entry.hub?.baseUrl),
      },
      source: {
        peerId: String(entry.source?.peerId ?? ''),
        name: String(entry.source?.name ?? ''),
      },
      firstSeen: Number.isFinite(firstRaw) && firstRaw > 0 ? Math.floor(firstRaw) : lastSeen,
      lastSeen,
    }]);
  }
  entries.sort((left, right) => right[1].lastSeen - left[1].lastSeen);
  const groups = {};
  for (const [id, entry] of entries.slice(0, GROUP_KNOWN_GROUPS_LIMIT)) groups[id] = entry;
  return { groups };
}

/** 读 <stateDir>/known-groups.json（缺失/坏 JSON = 空表，读时不写盘） */
export function readKnownGroups(stateDir) {
  const dir = String(stateDir ?? '').trim();
  if (dir === '') return emptyKnownGroups();
  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(path.join(dir, GROUP_KNOWN_GROUPS_FILE), 'utf8'));
  } catch {
    return emptyKnownGroups();
  }
  return normalizeKnownGroups(raw);
}

export function writeKnownGroups(stateDir, data) {
  const dir = String(stateDir ?? '').trim();
  if (dir === '') throw new Error('state-dir-missing');
  const next = normalizeKnownGroups(data);
  writeJson0600File(path.join(dir, GROUP_KNOWN_GROUPS_FILE), next);
  return next;
}

/** 记住一个广播来的群：按 groupId 去重，firstSeen 保留最早一次 */
export function rememberKnownGroup({ stateDir, groupId, name, hub = null, source = null, now = Date.now } = {}) {
  const id = String(groupId ?? '').trim();
  if (id === '') throw new Error('groupId-missing');
  const nowMs = typeof now === 'function' ? Number(now()) : Number(now);
  const data = readKnownGroups(stateDir);
  const existing = data.groups[id] ?? null;
  const entry = {
    name: normalizeGroupName(name) || String(existing?.name ?? ''),
    hub: {
      peerId: String(hub?.peerId ?? '') || String(existing?.hub?.peerId ?? ''),
      name: String(hub?.name ?? '') || String(existing?.hub?.name ?? ''),
      baseUrl: trimBase(hub?.baseUrl) || String(existing?.hub?.baseUrl ?? ''),
    },
    source: {
      peerId: String(source?.peerId ?? ''),
      name: String(source?.name ?? ''),
    },
    firstSeen: Number(existing?.firstSeen) > 0 ? Math.floor(Number(existing.firstSeen)) : nowMs,
    lastSeen: nowMs,
  };
  data.groups[id] = entry;
  writeKnownGroups(stateDir, data);
  return { group: entry, created: existing === null };
}

/** 广播节流表：{ [peerId]: lastAdvertisedAtMs } */
export function readAdvertiseState(stateDir) {
  const dir = String(stateDir ?? '').trim();
  if (dir === '') return {};
  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(path.join(dir, GROUP_ADVERTISE_STATE_FILE), 'utf8'));
  } catch {
    return {};
  }
  const out = {};
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return out;
  for (const [peerId, value] of Object.entries(raw)) {
    const id = String(peerId ?? '').trim();
    const ms = Number(value);
    if (id === '' || !Number.isFinite(ms) || ms <= 0) continue;
    out[id] = Math.floor(ms);
  }
  return out;
}

export function writeAdvertiseState(stateDir, data) {
  const dir = String(stateDir ?? '').trim();
  if (dir === '') throw new Error('state-dir-missing');
  const next = {};
  if (data && typeof data === 'object' && !Array.isArray(data)) {
    for (const [peerId, value] of Object.entries(data)) {
      const id = String(peerId ?? '').trim();
      const ms = Number(value);
      if (id === '' || !Number.isFinite(ms) || ms <= 0) continue;
      next[id] = Math.floor(ms);
    }
  }
  writeJson0600File(path.join(dir, GROUP_ADVERTISE_STATE_FILE), next);
  return next;
}

/** POST /v1/group/advertise —— per-peer 签名，接收方不必是成员 */
export async function advertiseGroup({
  baseUrl,
  secret,
  senderId,
  groupId,
  name,
  hub = null,
  member = null,
  timeoutMs = GROUP_LOOKUP_TIMEOUT_MS,
  fetchImpl = fetch,
} = {}) {
  const reply = await callPeer({
    baseUrl: trimBase(baseUrl),
    secret,
    senderId,
    method: 'POST',
    apiPath: '/v1/group/advertise',
    body: {
      groupId: String(groupId ?? ''),
      name: normalizeGroupName(name),
      hub: {
        peerId: String(hub?.peerId ?? ''),
        name: String(hub?.name ?? ''),
        baseUrl: trimBase(hub?.baseUrl),
      },
      member: {
        peerId: String(member?.peerId ?? ''),
        name: String(member?.name ?? ''),
      },
      at: Date.now(),
    },
    timeoutMs,
    fetchImpl,
  });
  return { ok: reply?.ok === true };
}

/** POST /v1/group/lookup —— 按名查找，返回 { matches: [{groupId,name,hub,via}] } */
export async function lookupGroupName({
  baseUrl,
  secret,
  senderId,
  name,
  timeoutMs = GROUP_LOOKUP_TIMEOUT_MS,
  fetchImpl = fetch,
} = {}) {
  const reply = await callPeer({
    baseUrl: trimBase(baseUrl),
    secret,
    senderId,
    method: 'POST',
    apiPath: '/v1/group/lookup',
    body: { name: normalizeGroupName(name) },
    timeoutMs,
    fetchImpl,
  });
  const matches = Array.isArray(reply?.matches)
    ? reply.matches.filter((entry) => entry && typeof entry === 'object' && String(entry.groupId ?? '') !== '')
    : [];
  return { matches };
}

/** 并发问所有伙伴（契约 §3：每个 2 秒超时，失败只记一行） */
export async function lookupGroupNameEverywhere({
  peers = [],
  name,
  timeoutMs = GROUP_LOOKUP_TIMEOUT_MS,
  fetchImpl = fetch,
} = {}) {
  const wanted = normalizeGroupName(name);
  if (wanted === '') throw new Error('name-missing');
  const list = (Array.isArray(peers) ? peers : []).filter((peer) => String(peer?.baseUrl ?? '') !== '');
  const results = await Promise.all(list.map(async (peer) => {
    const peerId = String(peer?.peerId ?? '');
    try {
      const { matches } = await lookupGroupName({
        baseUrl: peer?.baseUrl,
        secret: peer?.secret,
        senderId: peer?.senderId,
        name: wanted,
        timeoutMs,
        fetchImpl,
      });
      return { peerId, peer, matches, ok: true };
    } catch (error) {
      return { peerId, peer, matches: [], ok: false, reason: String(error?.message ?? error) };
    }
  }));
  const matches = [];
  const seen = new Set();
  const failed = [];
  for (const result of results) {
    if (!result.ok) {
      failed.push({ peerId: result.peerId, name: String(result.peer?.name ?? ''), reason: result.reason });
      continue;
    }
    for (const match of result.matches) {
      if (!sameGroupName(match.name, wanted)) continue;
      const groupId = String(match.groupId ?? '');
      if (seen.has(groupId)) continue;
      seen.add(groupId);
      matches.push({
        groupId,
        name: normalizeGroupName(match.name),
        hub: {
          peerId: String(match.hub?.peerId ?? ''),
          name: String(match.hub?.name ?? ''),
          baseUrl: trimBase(match.hub?.baseUrl),
        },
        via: {
          peerId: String(match.via?.peerId ?? result.peerId),
          name: String(match.via?.name ?? result.peer?.name ?? ''),
        },
      });
    }
  }
  return { matches, failed };
}

/** POST /v1/group/apply —— 申请者 → 介绍人（介绍人再转给 hub） */
export async function applyToGroup({
  baseUrl,
  secret,
  senderId,
  groupId,
  applicant = null,
  timeoutMs = 10_000,
  fetchImpl = fetch,
} = {}) {
  const applicantBody = {
    peerId: String(applicant?.peerId ?? senderId ?? ''),
    name: String(applicant?.name ?? ''),
    baseUrl: trimBase(applicant?.baseUrl),
  };
  const reply = await callPeer({
    baseUrl: trimBase(baseUrl),
    secret,
    senderId,
    method: 'POST',
    apiPath: '/v1/group/apply',
    body: { groupId: String(groupId ?? ''), applicant: applicantBody },
    timeoutMs,
    fetchImpl,
  });
  const out = { status: String(reply?.status ?? 'unknown') };
  if (reply?.reason != null) out.reason = String(reply.reason);
  return out;
}

/** POST /v1/group/apply-status —— 申请者 → 介绍人轮询（approved 时带 grant） */
export async function pollApplication({
  baseUrl,
  secret,
  senderId,
  groupId,
  timeoutMs = 10_000,
  fetchImpl = fetch,
} = {}) {
  const reply = await callPeer({
    baseUrl: trimBase(baseUrl),
    secret,
    senderId,
    method: 'POST',
    apiPath: '/v1/group/apply-status',
    body: { groupId: String(groupId ?? '') },
    timeoutMs,
    fetchImpl,
  });
  const out = { status: String(reply?.status ?? 'unknown') };
  if (reply?.reason != null) out.reason = String(reply.reason);
  if (reply?.grant && typeof reply.grant === 'object') out.grant = reply.grant;
  return out;
}

/**
 * 收到 grant 后落 group-key.json（申请者的最后一步）：
 * 只接受 { groupId, key, ... } 齐全的授权，别的一律抛错，避免把半份授权写成「已入群」。
 * 本机原来的显示名/成员地址保留，不被 grant 覆盖。
 */
export function applyGroupGrant(stateDir, grant) {
  const groupId = String(grant?.groupId ?? '');
  const key = String(grant?.key ?? '');
  if (groupId === '' || key === '') throw new Error('grant-incomplete');
  const existing = readGroupKeyFile(stateDir);
  // v0.8.1：grant 的成员表是**权威快照** —— 整体替换，不是并集。
  // 并集会让「已被 hub 移除」的成员永远留在本机表里，quorum 分母虚高（成员当 leader 时永远选不出）。
  const previous = existing?.members ?? {};
  const members = {};
  for (const member of Array.isArray(grant?.members) ? grant.members : []) {
    const peerId = String(member?.peerId ?? '');
    if (peerId === '') continue;
    members[peerId] = {
      name: String(member?.name ?? '') || String(previous[peerId]?.name ?? ''),
      baseUrl: trimBase(member?.baseUrl) || trimBase(previous[peerId]?.baseUrl),
    };
  }
  const hub = grant?.hub ?? {};
  const hubPeerId = String(hub.peerId ?? '');
  if (hubPeerId !== '') {
    members[hubPeerId] = {
      name: String(hub.name ?? '') || String(members[hubPeerId]?.name ?? ''),
      baseUrl: trimBase(hub.baseUrl) || String(members[hubPeerId]?.baseUrl ?? ''),
    };
  }
  // 契约 §5.1：grant 里的 hub 地址必须跟着密钥落盘 —— 按名入群的节点没有 group.hub 配置，
  // 只有靠这里记下的 hub 才知道往哪 pull、把副本建起来（真机：hub 为 null 时该节点是「名义成员」）。
  const hubEntry = readGroupKeyHub({
    peerId: hubPeerId || String(existing?.hub?.peerId ?? ''),
    name: String(hub.name ?? '') || String(existing?.hub?.name ?? ''),
    baseUrl: trimBase(hub.baseUrl) || String(existing?.hub?.baseUrl ?? ''),
  });
  const keyVersion = Number(grant?.keyVersion ?? grant?.epoch);
  return writeGroupKeyFile(stateDir, {
    groupId,
    key,
    keyVersion: Number.isFinite(keyVersion) && keyVersion > 0 ? Math.floor(keyVersion) : 0,
    leaderPeerId: hubPeerId || String(existing?.leaderPeerId ?? ''),
    name: String(existing?.name ?? ''),
    groupName: normalizeGroupName(grant?.name),
    hub: hubEntry,
    members,
  });
}

/**
 * 群名广播的统一入口（自动与手动共用）：只发给**非成员**伙伴，按伙伴维度节流。
 * manual = true 跳过节流（面板按钮 / CLI group advertise）。
 * 返回发过与跳过的清单（契约 §2b 要求手动广播返回对象清单）。
 */
export async function broadcastGroupAdvertisement({
  peers = [],
  self = null,
  group = null,
  secretOf = null,
  manual = false,
  stateDir = '',
  now = Date.now,
  timeoutMs = GROUP_LOOKUP_TIMEOUT_MS,
  fetchImpl = fetch,
} = {}) {
  const groupId = String(group?.groupId ?? '');
  const name = normalizeGroupName(group?.name);
  if (groupId === '' || name === '') return { ok: false, reason: 'no-group', sent: [], skipped: [] };
  const members = new Set(Array.isArray(group?.members) ? group.members.map((id) => String(id ?? '')) : []);
  const nowMs = typeof now === 'function' ? Number(now()) : Number(now);
  const throttle = stateDir === '' ? {} : readAdvertiseState(stateDir);
  const sent = [];
  const skipped = [];
  const tasks = [];
  for (const peer of Array.isArray(peers) ? peers : []) {
    const peerId = String(peer?.peerId ?? '');
    if (peerId === '' || peerId === String(self?.peerId ?? '')) continue;
    if (members.has(peerId)) {
      skipped.push({ peerId, name: String(peer?.name ?? ''), reason: 'member' });
      continue;
    }
    const baseUrl = trimBase(peer?.baseUrl);
    if (baseUrl === '') {
      skipped.push({ peerId, name: String(peer?.name ?? ''), reason: 'no-base-url' });
      continue;
    }
    const last = Number(throttle[peerId] ?? 0);
    if (!manual && Number.isFinite(last) && nowMs - last < GROUP_ADVERTISEMENT_THROTTLE_MS) {
      skipped.push({ peerId, name: String(peer?.name ?? ''), reason: 'throttled' });
      continue;
    }
    const secret = typeof secretOf === 'function' ? secretOf(peer) : peer?.secret;
    tasks.push((async () => {
      try {
        await advertiseGroup({
          baseUrl,
          secret,
          senderId: self?.peerId,
          groupId,
          name,
          hub: group?.hub ?? null,
          member: { peerId: String(self?.peerId ?? ''), name: String(self?.name ?? '') },
          timeoutMs,
          fetchImpl,
        });
        if (stateDir !== '') throttle[peerId] = nowMs;
        sent.push({ peerId, name: String(peer?.name ?? ''), baseUrl });
        return true;
      } catch (error) {
        skipped.push({
          peerId,
          name: String(peer?.name ?? ''),
          reason: String(error?.message ?? error).slice(0, 80),
        });
        return false;
      }
    })());
  }
  const results = await Promise.all(tasks);
  if (stateDir !== '' && results.some(Boolean)) writeAdvertiseState(stateDir, throttle);
  return { ok: true, groupId, name, sent, skipped };
}


// ---------------------------------------------------------------------------
// 群名归属：成员侧不许拿配置默认值冒充真群名（0.8.0 真机回归）
// ---------------------------------------------------------------------------

/**
 * 把 hub 状态里的**权威群名**落进 group-key.json 的 groupName（有变化才写）。
 *
 * 为什么需要：0.7.x 时代写的 group-key.json 没有 groupName 字段，而 0.8.0 的广播/查找
 * 从本地文件取群名；没有回写就会一路回落成配置默认值（'default'），对外广播错误群名。
 * 返回写入后的群名（拿不到就返回空串，绝不回写空值）。
 */
export function rememberGroupNameFromState(stateDir, state) {
  const name = normalizeGroupName(state?.name);
  if (name === '') return '';
  const dir = String(stateDir ?? '').trim();
  if (dir === '') return name;
  const existing = readGroupKeyFile(dir);
  // 还没有群密钥文件 = 本机不是成员：没什么可回写的，交给调用方按需处理
  if (!existing) return name;
  if (normalizeGroupName(existing.groupName) === name) return name;
  writeGroupKeyFile(dir, { ...existing, groupName: name });
  return name;
}

/**
 * 解析本机所属群的群名（契约 §2/§3）。
 *
 * 顺序：显式 state（刚取到的 hub 状态）→ 本地 group-key.json 的 groupName →
 * 向 hub 现取一次 state（per-peer 签名，5 秒）→ 都没有就是 source:'none'。
 *
 * 关键不变量：**没有名字就返回空串**，调用方必须报 unknown 并跳过广播，
 * 不允许拿 config.group.name 的默认值冒充真群名（真机上会把 'default' 广播给伙伴）。
 */
export async function resolveGroupName({
  stateDir,
  known = '',
  state = null,
  hub = null,
  senderId = '',
  timeoutMs = 5_000,
  fetchImpl = fetch,
} = {}) {
  const dir = String(stateDir ?? '').trim();
  const fromFile = () => normalizeGroupName(known) || normalizeGroupName(readGroupKeyFile(dir)?.groupName);

  if (state && normalizeGroupName(state.name) !== '') {
    const name = rememberGroupNameFromState(dir, state);
    return { name, source: 'state' };
  }
  const local = fromFile();
  if (local !== '') return { name: local, source: 'file' };

  // 老文件没有 groupName：向 hub 取一次权威名字（只读，不推进任何世代）
  if (hub && String(hub.baseUrl ?? '') !== '' && String(hub.secret ?? '') !== '') {
    try {
      const fetched = await fetchGroupState({
        baseUrl: trimBase(hub.baseUrl),
        secret: hub.secret,
        senderId,
        timeoutMs,
        fetchImpl,
      });
      const name = normalizeGroupName(fetched?.name);
      if (name !== '') {
        rememberGroupNameFromState(dir, fetched);
        return { name, source: 'hub' };
      }
    } catch {
      /* 取不到就按未知处理，调用方报 unknown */
    }
  }
  return { name: '', source: 'none' };
}


/**
 * POST /v1/group/post —— **群级签名**通道（v0.8.0 新增鉴权模式）。
 *
 * 与 postGroup（per-peer）同一端点、同一正文口径；区别只在鉴权：
 * 只有群密钥、没有 hub per-peer 密钥的成员（按名入群）用它才能发言。
 * body 里绝不带 from/peerId：服务端一律以签名里的 senderPeerId 为准。
 */
export async function postGroupWithGroupKey({
  baseUrl,
  groupKey,
  groupId,
  senderId,
  kind = 'chat',
  text = '',
  meta = null,
  selfBaseUrl = '',
  identity,
  timeoutMs = 10_000,
  fetchImpl = fetch,
} = {}) {
  const payload = { kind: String(kind) };
  if (typeof text === 'string' && text !== '') payload.text = text;
  const cleanMeta = sanitizeGroupMeta(meta);
  if (Object.keys(cleanMeta).length > 0) payload.meta = cleanMeta;
  return groupCall({
    baseUrl,
    groupKey,
    groupId,
    senderId,
    selfBaseUrl,
    identity,
    method: 'POST',
    apiPath: '/v1/group/post',
    body: payload,
    timeoutMs,
    fetchImpl,
  });
}

