#!/usr/bin/env node
/**
 * dsh-lan-peers · host half
 * =========================
 *
 * 纯 Node ESM，无第三方依赖，无需 TS 构建。实现 DESIGN.md v0.1 §4 签名规范与 §5 端点表：
 *
 *   GET  /v1/health                          无认证（capability: ask/pair/pair-ecdh/stream）
 *   POST /v1/pair                            配对码（无 ecdh = 0.3.1 明文路径；有 ecdh = ECDH 第一轮，不消费码）
 *   POST /v1/pair/confirm                    配对码消费 + ECDH 第二轮（wrapped 交换双方密钥）
 *   POST /v1/ask                             签名 + allowRemotePrompts
 *   GET  /v1/answer?sessionId=<id>[&waitMs=] 签名（waitMs>0 时服务端 hold 成长轮询）
 *   GET  /v1/events?sessionId=<id>           签名 + SSE（每条事件独立加密）
 *   GET  /v1/peers                           签名
 *
 * 执行侧（DSH 会话）与协议完全解耦：本文件只依赖一个 runner 接口
 *
 *   createRunner({ workspace, preset, permission })
 *     -> { ask(prompt) -> sessionId | Promise<sessionId>, poll(sessionId) -> { status, reply?, error? } }
 *
 * 本轮提供内存假实现 MemoryRunner（1 秒后完成，回复 "OK <prompt 前 20 字>"）。
 * 下一轮接真 DSH 适配器时，只需替换 createRunner，server 其余部分不动。
 *
 * 单独运行：
 *   node host/server.mjs                       # 0.0.0.0:7788，allowRemotePrompts=false
 *   node host/server.mjs --allow-remote-prompts
 *   node host/server.mjs --code                # 打印一次性配对码（写 state.json）
 *
 * 安全：secret / 签名原文不写日志；state.json、peers.json 均为 0600。
 */

import { createServer as createHttpServer } from 'node:http';
import {
  createHash,
  createHmac,
  randomBytes,
  randomInt,
  randomUUID,
  timingSafeEqual,
} from 'node:crypto';
import fs from 'node:fs';
import { ENC_HEADER, ENC_VERSION, decryptBytes, encryptBytes } from '../lib/wire-crypto.mjs';
import {
  PAIR_CURVE,
  PAIR_PROTOCOL_VERSION,
  deriveWrapKey,
  generateKeyPair,
  isValidPublicKeyB64url,
  unwrapSecret,
  wrapSecret,
} from '../lib/pairing-ecdh.mjs';
import {
  GROUP_APPLICATION_LIMIT,
  GROUP_APPLICATION_STATUSES,
  GROUP_APPLICATION_TTL_MS,
  GROUP_AUTH_CLOCK_SKEW_MS,
  GROUP_AUTH_HEADER,
  GROUP_ACCEPT_HEADER,
  GROUP_AUTH_NONCE_WINDOW_MS,
  GROUP_AUTH_PATHS,
  GROUP_AUTH_VALUE,
  GROUP_BASE_HEADER,
  GROUP_DEFAULT_ACCEPT_DISPATCH,
  GROUP_DEFAULT_COMMIT_TIMEOUT_MS,
  GROUP_DEFAULT_DISPATCH_RATE_MS,
  GROUP_DEFAULT_HEARTBEAT_MS,
  GROUP_DEFAULT_HUB_PRIORITY,
  GROUP_DEFAULT_REPLICA_PULL_MS,
  GROUP_ELECTION_JITTER_MS,
  GROUP_ID_HEADER,
  GROUP_LASTSEQ_HEADER,
  GROUP_LEASE_FACTOR,
  GROUP_NAME_MAX_CHARS,
  GROUP_REPLICA_FILE,
  GROUP_ROLE_FILE,
  GROUP_ROLES,
  broadcastGroupAdvertisement,
  buildGroupCanonical,
  commitGroupMessage,
  createGroupDispatcher,
  decryptGroupBody,
  deriveGroupKeys,
  encryptGroupBody,
  fetchGroupState,
  groupCall,
  groupDispatchSummary,
  joinGroup,
  normalizeGroupName,
  parseAcceptFlag,
  postGroup,
  postGroupWithGroupKey,
  proposeGroupMessage,
  pullGroupMessages,
  quorumSize,
  readAdvertiseState,
  readGroupKeyFile,
  readKnownGroups,
  rememberGroupNameFromState,
  rememberKnownGroup,
  resolveGroupName,
  replicateGroupMessages,
  requestGroupVote,
  resolveGroupHub,
  sameGroupName,
  sendGroupHeartbeat,
  signGroupCanonical,
  writeAdvertiseState,
  writeGroupKeyFile,
} from '../lib/group-client.mjs';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';

// ---------------------------------------------------------------------------
// 常量（与 DESIGN.md 对齐）
// ---------------------------------------------------------------------------

/** 插件版本，用于 /v1/health.version */
export const PLUGIN_VERSION = '0.8.3';

/** §4.1 允许的时钟偏移 */
export const CLOCK_SKEW_MS = 60_000;

/** §4.2 nonce 重放窗口 */
export const NONCE_WINDOW_MS = 120_000;

/** §2 配对码有效期 10 分钟 */
export const PAIRING_CODE_TTL_MS = 10 * 60_000;

/** §2 ECDH 两轮握手：第一轮留下的 pending 状态有效期（只在内存，不落盘） */
export const PAIRING_ECDH_TTL_MS = 120_000;

/** §2 同时挂起的 ECDH 握手上限；超出时丢最早过期的那条，避免被刷爆内存 */
export const MAX_PENDING_PAIRS = 200;

/** §4 answer 长轮询：hold 上限默认值与硬上限（毫秒） */
export const ANSWER_WAIT_DEFAULT_MS = 25_000;
export const ANSWER_WAIT_MAX_MS = 25_000;

/** §4 长轮询期间内部 poll 间隔 */
export const ANSWER_POLL_INTERVAL_MS = 150;

/** §5 SSE：running 状态事件间隔 / ping 心跳间隔 */
export const EVENTS_STATUS_INTERVAL_MS = 1_000;
export const EVENTS_PING_INTERVAL_MS = 10_000;

/**
 * §1 能力表：v0.4.0 的 ask/pair 保留 + pair-ecdh/stream，v0.4.1 追加 unpair，
 * v0.5.0 追加 group，v0.8.0 追加 group-advertise（群名广播/按名查找，契约 §9.5）。
 * 老对端不认识某个能力位就忽略（运行时按 /v1/health 探测）。
 */
export const CAPABILITIES = Object.freeze([
  'ask',
  'pair',
  'pair-ecdh',
  'stream',
  'unpair',
  'group',
  'group-advertise',
]);

/**
 * §3 v0.5.0 群端点：只有 hub 提供。
 * group.enabled 为假、或本机是成员（配了 group.hub）时，这些路径一律 404 ——
 * 未启用群不该在局域网上暴露半成品能力。
 */
export const GROUP_V1_PATHS = Object.freeze([
  '/v1/group/state',
  '/v1/group/join',
  '/v1/group/post',
  '/v1/group/history',
  '/v1/group/events',
]);

/**
 * v0.8.0（契约 §2/§3/§4.1/§5.1）per-peer 路径：**与群开关无关**，
 * 未启用群的节点也要能答 lookup/advertise（成员与 hub 都可能被问）。
 * 这四条不需要群密钥，只要求「已配对」——签名用的就是配对时互换的那把密钥。
 */
export const GROUP_PEER_V1_PATHS = Object.freeze([
  '/v1/group/advertise',
  '/v1/group/lookup',
  '/v1/group/apply',
  '/v1/group/apply-status',
]);

/** 已知 /v1 路径（用错方法 → 405，而不是 404） */
const KNOWN_V1_PATHS = Object.freeze([
  '/v1/health',
  '/v1/pair',
  '/v1/pair/confirm',
  '/v1/ask',
  '/v1/answer',
  '/v1/events',
  '/v1/peers',
  '/v1/unpair',
  ...GROUP_V1_PATHS,
]);

/** §5 ask 默认超时（秒） */
export const DEFAULT_TIMEOUT_SEC = 300;

/** §5 ask 超时上限（秒） */
export const MAX_TIMEOUT_SEC = 900;

/** 请求体上限，防止内存打爆 */
export const MAX_BODY_BYTES = 1024 * 1024;

/** sha256("")，GET 请求的 body 摘要 */
export const EMPTY_BODY_SHA256 = createHash('sha256').update(Buffer.alloc(0)).digest('hex');

const STATE_FILE = 'state.json';
const PEERS_FILE = 'peers.json';

/** 默认 LAN 网段（未显式配置 trustedCidrs 时使用；显式配置则严格按配置） */
export const DEFAULT_TRUSTED_CIDRS = Object.freeze([
  '127.0.0.0/8',
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '169.254.0.0/16',
  '100.64.0.0/10',
  '::1/128',
  'fc00::/7',
  'fe80::/10',
]);

const MAX_SESSIONS = 500;

const GROUP_FILE = 'group.json';

/** 尾部斜杠（地址归一化共用；写成常量是为了别在正则字面量里反复转义） */
const TRAILING_SLASHES = /\/+$/;

/** §3 kind 白名单 */
export const GROUP_KINDS = Object.freeze(['chat', 'progress', 'result', 'system']);

/**
 * §3 meta 白名单：不在表里的字段在落盘前丢弃。
 * v0.8.2-α 追加 target/by/reason —— 群内派单的 progress/result 靠它们说明
 * 「谁派给谁、为什么没派成」；正文永远不进 meta。
 */
export const GROUP_META_FIELDS = Object.freeze([
  'peer',
  'sessionId',
  'phase',
  'status',
  'transport',
  'elapsedMs',
  'replyChars',
  'target',
  'by',
  'reason',
]);

/** meta 里的字符串字段上限（防止有人用 meta 夹带大块数据） */
export const GROUP_META_STRING_MAX = 200;

/** §3 text 上限（按 Unicode code point 计，中文不会被拆半个字） */
export const GROUP_TEXT_MAX_CHARS = 4000;

/** §3 history limit 的默认值与硬上限 */
export const GROUP_HISTORY_DEFAULT_LIMIT = 200;
export const GROUP_HISTORY_MAX_LIMIT = 200;

/** §4 消息硬上限（v0.8.0-β §18 起：超了**归档**，不丢） */
export const GROUP_MESSAGE_LIMIT = 5000;

/** §18：活跃区（group.json 的 messages）序列化后的体积上限；超了归档 */
export const GROUP_ARCHIVE_BYTES_LIMIT = 20 * 1024 * 1024;

/** §18：归档索引上限（超过只告警，绝不自动删文件 —— 删归档是人工决定） */
export const GROUP_ARCHIVE_INDEX_LIMIT = 200;

/** §18：归档目录名（<stateDir>/group-archive） */
export const GROUP_ARCHIVE_DIR = 'group-archive';

/**
 * v0.8.2-α §4：本机接单开关的运行期落盘文件（<stateDir>/group-dispatch-prefs.json）。
 * 刻意与 DSH profile 配置分开：profile 是用户手改过的文件，插件不回写。
 */
export const GROUP_DISPATCH_PREFS_FILE = 'group-dispatch-prefs.json';

/** v0.8.0-β §A1：失败选举的指数退避 base / 上限 / 抖动 */
export const GROUP_ELECTION_BACKOFF_BASE_MS = 5_000;
export const GROUP_ELECTION_BACKOFF_CAP_MS = 60_000;
export const GROUP_ELECTION_BACKOFF_JITTER_MS = 500;

/** §A1/A4：60s 窗口内最多允许 2 次失败选举（真机事故：3 天 495 次、每次 +1 epoch） */
export const GROUP_ELECTION_FAIL_WINDOW_MS = 60_000;
export const GROUP_ELECTION_FAIL_WINDOW_MAX = 2;

/** §A2：周期优先级纠偏的节奏与上限（上限防止无限循环夺权） */
export const GROUP_PRIORITY_CORRECTION_MS = 300_000;
export const GROUP_PRIORITY_CORRECTION_MAX = 5;

/** §A3：单次 epoch 涨幅超过这个值就记一行告警 */
export const GROUP_EPOCH_JUMP_THRESHOLD = 50;

/** §2 retentionDays 默认 7 天 */
export const GROUP_DEFAULT_RETENTION_DAYS = 7;

/** §3 SSE 轮询群存储的间隔与 ping 心跳间隔 */
export const GROUP_POLL_INTERVAL_MS = 200;
export const GROUP_EVENTS_PING_INTERVAL_MS = 10_000;

/** 成员 online 的判定窗口：peers.json 的 lastSeen 在窗口内算在线 */
export const GROUP_ONLINE_WINDOW_MS = 90_000;

/**
 * S1 v0.6.0：群级鉴权白名单（与 lib/group-client.mjs 同一份常量）。
 * 只有这四条路径认 X-Peer-Auth: group；其它路径带该头一律 401 group-auth-scope。
 */
export const GROUP_AUTH_ALLOWED_PATHS = GROUP_AUTH_PATHS;

/** S2：成员副本的重试节奏与默认拉取间隔（配置项 group.replicaPullMs 覆盖后者） */
export const GROUP_REPLICA_RETRY_MS = 2_000;
export const GROUP_GROUP_DEFAULT_REPLICA_PULL_MS = GROUP_DEFAULT_REPLICA_PULL_MS;

/** S3 v0.7.0：角色文件、角色取值与未提交区的 TTL（与 lib/group-client.mjs 同一份常量） */
export const GROUP_ROLE_KINDS = GROUP_ROLES;
export const GROUP_ROLE_STORE_FILE = GROUP_ROLE_FILE;
/** hub 落盘 pending 的兜底寿命：崩溃留下的 pending 超过这个时间就不再参与提交 */
export const GROUP_PENDING_TTL_MS = 300_000;
/** 成员侧内存 pending 的条数上限（防止被 proposal 刷爆） */
export const GROUP_PENDING_MAX = 256;
/** 心跳/投票请求的超时上限：单个对端卡住不能拖住整个 tick */
export const GROUP_S3_PEER_TIMEOUT_MS = 1_000;

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

function toBuffer(value) {
  if (value == null) return Buffer.alloc(0);
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (typeof value === 'string') return Buffer.from(value, 'utf8');
  return Buffer.from(String(value), 'utf8');
}

/** sha256 hex */
export function sha256Hex(value) {
  return createHash('sha256').update(toBuffer(value)).digest('hex');
}

/** §4 canonical 第 5 行：sha256(body) 的 hex */
export function bodyHash(rawBody) {
  return sha256Hex(rawBody);
}

/**
 * §4 canonical：五行，`\n` 连接，无尾随换行。
 *   METHOD 大写 / path（含 query，不含 host）/ X-Peer-Ts / X-Peer-Nonce / sha256(body) hex
 */
export function buildCanonical({ method, path: requestPath, ts, nonce, rawBody }) {
  return [
    String(method ?? '').toUpperCase(),
    String(requestPath ?? ''),
    String(ts ?? ''),
    String(nonce ?? ''),
    bodyHash(rawBody),
  ].join('\n');
}

/**
 * HMAC-SHA256(secret, canonical) -> base64url。
 *
 * keyEncoding 决定 secret 如何变成 HMAC key：
 *   'utf8'      —— secret 字符串本身（DESIGN.md 字面读法，默认）
 *   'base64url' —— 先把 secret 按 base64url 解码成 32 字节原始 key
 */
export function signCanonical({ secret, canonical, keyEncoding = 'utf8' }) {
  const key = keyEncoding === 'base64url'
    ? Buffer.from(String(secret ?? ''), 'base64url')
    : Buffer.from(String(secret ?? ''), 'utf8');
  return createHmac('sha256', key).update(String(canonical), 'utf8').digest('base64url');
}

/** 组合 helper：直接返回 {canonical, signature} */
export function signRequest({ method, path: requestPath, ts, nonce, rawBody, secret, keyEncoding = 'utf8' }) {
  const canonical = buildCanonical({ method, path: requestPath, ts, nonce, rawBody });
  return { canonical, signature: signCanonical({ secret, canonical, keyEncoding }) };
}

/** 定长时间比较（长度不同直接 false，避免 timingSafeEqual 抛错） */
export function timingSafeStringEqual(a, b) {
  const left = Buffer.from(String(a ?? ''), 'utf8');
  const right = Buffer.from(String(b ?? ''), 'utf8');
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

export function expandHome(input) {
  const value = String(input ?? '');
  if (value === '~') return os.homedir();
  if (value.startsWith('~/') || value.startsWith('~\\')) {
    return path.join(os.homedir(), value.slice(2));
  }
  return value;
}

export function defaultStateDir() {
  return path.join(os.homedir(), '.dsh', 'lan-peers');
}

function nowIso(ms) {
  return new Date(ms).toISOString();
}

function headerValue(req, name) {
  const value = req.headers[name];
  if (Array.isArray(value)) return value[0] ?? '';
  return typeof value === 'string' ? value : '';
}

export function randomSecret() {
  // 32 字节随机，base64url（43 字符）
  return randomBytes(32).toString('base64url');
}

/** 前 n 个「字」（按 Unicode code point，中文不会被截半个字） */
export function firstChars(value, n) {
  return Array.from(String(value ?? '')).slice(0, n).join('');
}

// ---------------------------------------------------------------------------
// 配置（DESIGN.md §7 的映射，传入的是 cordis config 的 config 段）
// ---------------------------------------------------------------------------

const PAIRING_MODES = Object.freeze(['auto', 'ecdh', 'legacy']);

/** §6 pairingMode：非法值回落到 auto（旧行为：两种配对都接受） */
function normalizePairingMode(value) {
  const mode = String(value ?? 'auto');
  return PAIRING_MODES.includes(mode) ? mode : 'auto';
}

/**
 * §2 v0.5.0 group 配置：全部有默认值，不填 = 关闭。
 * hub 留空 = 本机就是 hub；填对端的名字或 peerId = 本机是成员
 * （字符串 → peer 记录的解析放在使用侧做，因为 peers.json 随时会变）。
 */
export function normalizeGroupConfig(raw) {
  const value = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  const days = Number(value.retentionDays);
  const pullMs = Number(value.replicaPullMs);
  const heartbeatMs = Number(value.heartbeatMs);
  const commitMs = Number(value.commitTimeoutMs);
  const priority = Number(value.hubPriority);
  // v0.8.2-α §2/§4：群内派单的两个旋钮（与 lib/group-client.mjs 的同名归一化保持一致）
  const dispatchRateMs = Number(value.dispatchRateMs);
  return {
    enabled: value.enabled === true,
    hub: String(value.hub ?? '').trim(),
    name: String(value.name ?? '').trim() || 'default',
    autoJoin: value.autoJoin === true,
    retentionDays: Number.isFinite(days) && days >= 0 ? Math.floor(days) : GROUP_DEFAULT_RETENTION_DAYS,
    // S1：本机对外可达地址；空 = 自动探测首选私有 IPv4（见 pickPrivateIpv4）
    advertiseBaseUrl: String(value.advertiseBaseUrl ?? '').trim().replace(/\/+$/, ''),
    // S3：quorum 真正生效 —— majority 走 propose/commit 两阶段，none 直接提交（可用性优先）
    quorum: String(value.quorum ?? '').trim() === 'none' ? 'none' : 'majority',
    // S2：成员向 leader 补差的间隔
    replicaPullMs: Number.isFinite(pullMs) && pullMs >= 50
      ? Math.floor(pullMs)
      : GROUP_DEFAULT_REPLICA_PULL_MS,
    // S3 §8：心跳间隔（租约 = 3×）、propose→commit 超时、同 epoch 冲突裁决优先级
    heartbeatMs: Number.isFinite(heartbeatMs) && heartbeatMs >= 250
      ? Math.floor(heartbeatMs)
      : GROUP_DEFAULT_HEARTBEAT_MS,
    commitTimeoutMs: Number.isFinite(commitMs) && commitMs >= 100
      ? Math.floor(commitMs)
      : GROUP_DEFAULT_COMMIT_TIMEOUT_MS,
    hubPriority: Number.isFinite(priority) ? Math.floor(priority) : GROUP_DEFAULT_HUB_PRIORITY,
    // 本机是否接群内派单（缺省 true：老配置与老对端都按接单处理）
    acceptDispatch: value.acceptDispatch !== false,
    // 同一目标的最小派单间隔；0 = 关闭限流（只允许显式配置成 0）
    dispatchRateMs: Number.isFinite(dispatchRateMs) && dispatchRateMs >= 0
      ? Math.floor(dispatchRateMs)
      : GROUP_DEFAULT_DISPATCH_RATE_MS,
  };
}

/** §6 answerWaitMs：缺省 25000，负数/非数字回落默认，硬上限 25000 */
function normalizeAnswerWaitMs(value) {
  if (value == null) return ANSWER_WAIT_DEFAULT_MS;
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric < 0) return ANSWER_WAIT_DEFAULT_MS;
  return Math.min(Math.floor(numeric), ANSWER_WAIT_MAX_MS);
}

export function resolveConfig(overrides = {}) {
  const stateDir = expandHome(overrides.stateDir ?? defaultStateDir());
  const name = String(overrides.name ?? os.hostname());
  const listenPort = overrides.listenPort == null ? 7788 : Number(overrides.listenPort);
  if (!Number.isInteger(listenPort) || listenPort < 0 || listenPort > 65_535) {
    throw new RangeError(`listenPort must be an integer in 0..65535, got ${String(overrides.listenPort)}`);
  }
  let trustedCidrs = null;
  if (overrides.trustedCidrs != null) {
    const list = Array.isArray(overrides.trustedCidrs) ? overrides.trustedCidrs : [overrides.trustedCidrs];
    trustedCidrs = list.map((item) => String(item));
  }
  const workspace = expandHome(overrides.workspace ?? path.join(stateDir, 'workspace'));

  return {
    name,
    listenHost: String(overrides.listenHost ?? '0.0.0.0'),
    listenPort,
    stateDir,
    workspace,
    // §9 安全默认：装完不会自动被别人驱动
    allowRemotePrompts: overrides.allowRemotePrompts === true,
    requireEncryption: overrides.requireEncryption !== false,
    agentPreset: String(overrides.agentPreset ?? 'standard'),
    permission: String(overrides.permission ?? 'read-only'),
    // null = 使用 DEFAULT_TRUSTED_CIDRS（仅回环 + 私网）；显式数组 = 严格按数组
    trustedCidrs,
    now: typeof overrides.now === 'function' ? overrides.now : Date.now,
    logger: typeof overrides.logger === 'function' ? overrides.logger : null,
    // §4 未写明 secret 是「字符串」还是「base64url 解码后的字节」，默认按字符串
    secretKeyEncoding: overrides.secretKeyEncoding === 'base64url' ? 'base64url' : 'utf8',
    // 兼容 §3/§8 冲突：验签时除 inboundSecret 外，也接受 peers.json 里的 secret
    acceptSecretFallback: overrides.acceptSecretFallback !== false,
    // §6 v0.4.0：配对模式（auto 同时接受 ECDH 与旧明文）与长轮询 hold 上限
    pairingMode: normalizePairingMode(overrides.pairingMode),
    answerWaitMs: normalizeAnswerWaitMs(overrides.answerWaitMs),
    // §2 v0.5.0 群：默认关闭，hub 留空表示本机是 hub
    group: normalizeGroupConfig(overrides.group),
  };
}

// ---------------------------------------------------------------------------
// IP / CIDR 白名单（§9 只监听局域网网段）
// ---------------------------------------------------------------------------

function parseIpv4(input) {
  const parts = String(input).trim().split('.');
  if (parts.length !== 4) return null;
  let value = 0n;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    value = (value << 8n) | BigInt(octet);
  }
  return { bits: 32, value };
}

function parseIpv6(input) {
  const text = String(input).trim().split('%')[0];
  if (!text.includes(':')) return null;

  const parseGroups = (part) => {
    if (part === '') return [];
    const out = [];
    for (const group of part.split(':')) {
      if (group === '') return null;
      if (group.includes('.')) {
        const v4 = parseIpv4(group);
        if (!v4) return null;
        out.push(Number((v4.value >> 16n) & 0xffffn), Number(v4.value & 0xffffn));
      } else {
        if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null;
        out.push(Number.parseInt(group, 16));
      }
    }
    return out;
  };

  const halves = text.split('::');
  if (halves.length > 2) return null;
  let groups;
  if (halves.length === 2) {
    const left = parseGroups(halves[0]);
    const right = parseGroups(halves[1]);
    if (!left || !right) return null;
    const missing = 8 - left.length - right.length;
    if (missing < 0) return null;
    groups = [...left, ...new Array(missing).fill(0), ...right];
  } else {
    groups = parseGroups(text);
    if (!groups || groups.length !== 8) return null;
  }
  let value = 0n;
  for (const group of groups) value = (value << 16n) | BigInt(group);
  return { bits: 128, value };
}

/** 解析 IP；IPv4-mapped IPv6（::ffff:a.b.c.d）归一化为 IPv4 */
export function parseIp(input) {
  const text = String(input ?? '').trim();
  if (text === '') return null;
  const lower = text.toLowerCase();
  if (lower.startsWith('::ffff:') && lower.includes('.')) return parseIpv4(text.slice(7));
  if (text.includes(':')) return parseIpv6(text);
  return parseIpv4(text);
}

export function parseCidr(input) {
  const match = /^(.+)\/(\d{1,3})$/.exec(String(input ?? '').trim());
  if (!match) return null;
  const address = parseIp(match[1]);
  if (!address) return null;
  const prefix = Number(match[2]);
  if (prefix > address.bits) return null;
  const allOnes = (1n << BigInt(address.bits)) - 1n;
  const hostBits = BigInt(address.bits - prefix);
  const mask = allOnes ^ ((1n << hostBits) - 1n);
  return { bits: address.bits, mask, network: address.value & mask };
}

export function isIpInCidr(ip, cidr) {
  const address = parseIp(ip);
  const range = parseCidr(cidr);
  if (!address || !range || address.bits !== range.bits) return false;
  return (address.value & range.mask) === range.network;
}

/**
 * 远端地址是否允许访问。
 * cidrs 为 null/空 -> 默认私网 + 回环；显式配置 -> 严格按配置（回环也要自己写进去）。
 */
export function isAllowedRemote(ip, cidrs = null) {
  const list = cidrs && cidrs.length > 0 ? cidrs : DEFAULT_TRUSTED_CIDRS;
  return list.some((cidr) => isIpInCidr(ip, cidr));
}

// ---------------------------------------------------------------------------
// S1 成员可达地址：首选私有 IPv4（排除回环/容器/虚拟网卡）
// ---------------------------------------------------------------------------

/** 虚拟网卡名（docker/vEthernet/Hyper-V/VirtualBox/容器网桥/VPN 一律不当作对外地址） */
const VIRTUAL_IFACE_PATTERN = /^(docker|veth|br-|virbr|vmnet|vbox|vethernet|hyper-v|virtualbox|vmware|loopback|lo\b|zt|tailscale|utun|tun|tap|wg|ham|npcap)/i;

/** RFC1918 私有 IPv4 */
export function isPrivateIpv4(value) {
  const parsed = parseIpv4(String(value ?? ''));
  if (!parsed) return false;
  const octets = String(value).trim().split('.').map(Number);
  const [a, b] = octets;
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  return false;
}

/** 192.168 优先，其次 10/8，最后 172.16/12（同档按网卡名排序，结果稳定可测） */
function privateAddressRank(address) {
  const [a] = String(address).split('.').map(Number);
  if (a === 192) return 0;
  if (a === 10) return 1;
  return 2;
}

/**
 * 从 os.networkInterfaces() 的形状里挑一个私有 IPv4：跳过 internal、跳过虚拟网卡名、
 * 只保留 RFC1918，按 rank + 网卡名排序取第一个。没有则返回 null（调用方回落到配置值）。
 */
export function pickPrivateIpv4(interfaces = os.networkInterfaces()) {
  const found = [];
  const names = Object.keys(interfaces ?? {}).sort();
  for (const name of names) {
    if (VIRTUAL_IFACE_PATTERN.test(String(name))) continue;
    for (const entry of interfaces[name] ?? []) {
      if (!entry) continue;
      const family = entry.family === 'IPv4' || entry.family === 4;
      if (!family || entry.internal === true) continue;
      const address = String(entry.address ?? '');
      if (!isPrivateIpv4(address)) continue;
      found.push({ name: String(name), address, rank: privateAddressRank(address) });
    }
  }
  found.sort((left, right) => (left.rank - right.rank) || left.name.localeCompare(right.name) || left.address.localeCompare(right.address));
  return found.length > 0 ? found[0].address : null;
}

/** 本机自动探测到的地址（拿不到私有 IPv4 时返回 null） */
export function detectPrivateIpv4() {
  try {
    return pickPrivateIpv4();
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// 磁盘状态：state.json / peers.json（0600，原子写）
// ---------------------------------------------------------------------------

function writeJson0600(file, value) {
  const dir = path.dirname(file);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  try {
    fs.chmodSync(dir, 0o700);
  } catch {
    /* 目录权限尽力而为，不阻塞主流程 */
  }
  const tmp = `${file}.tmp-${process.pid}-${randomBytes(4).toString('hex')}`;
  fs.writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  try {
    fs.chmodSync(tmp, 0o600);
  } catch {
    /* ignore */
  }
  fs.renameSync(tmp, file);
  try {
    fs.chmodSync(file, 0o600);
  } catch {
    /* ignore */
  }
}

function readJsonFile(file) {
  let raw;
  try {
    raw = fs.readFileSync(file, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw err;
  }
  try {
    return JSON.parse(raw);
  } catch (err) {
    throw new Error(`${file} is not valid JSON: ${err.message}`);
  }
}

/**
 * state.json / peers.json 的读写封装。
 *
 * 关键点：配对码与 peers 都可能被同机另一个进程（client half 的 CLI）改动，
 * 所以读配对码 / 查未知 peer / 列 peers 时会重新读盘，避免 daemon 内存缓存过期。
 */
export class StateStore {
  #stateDir;

  #name;

  #now;

  #state = null;

  /** M6：配对码只活在本进程内存里（不落盘、不经文件被别的进程植入，重启即失效） */
  #pairingCode = null;

  #peers = null;

  #lastTouchPersist = new Map();

  constructor({ stateDir, name, now = Date.now }) {
    this.#stateDir = expandHome(stateDir);
    this.#name = String(name);
    this.#now = now;
    fs.mkdirSync(this.#stateDir, { recursive: true, mode: 0o700 });
    try {
      fs.chmodSync(this.#stateDir, 0o700);
    } catch {
      /* ignore */
    }
    // §8：实例身份首次启动即落盘（不等第一个请求）
    this.#state = this.#readState();
  }

  get stateDir() {
    return this.#stateDir;
  }

  get statePath() {
    return path.join(this.#stateDir, STATE_FILE);
  }

  get peersPath() {
    return path.join(this.#stateDir, PEERS_FILE);
  }

  #readState() {
    const loaded = readJsonFile(this.statePath);
    if (!loaded) {
      const fresh = {
        instanceId: randomUUID(),
        name: this.#name,
        createdAt: nowIso(this.#now()),
      };
      const state = fresh;
      writeJson0600(this.statePath, state);
      return state;
    }
    if (typeof loaded !== 'object' || loaded === null || Array.isArray(loaded)) {
      throw new Error(`${this.statePath} must contain a JSON object`);
    }
    const state = loaded;
    let dirty = false;
    if (typeof state.instanceId !== 'string' || state.instanceId === '') {
      state.instanceId = randomUUID();
      dirty = true;
    }
    if (state.name !== this.#name) {
      state.name = this.#name;
      dirty = true;
    }
    if (typeof state.createdAt !== 'string') {
      state.createdAt = nowIso(this.#now());
      dirty = true;
    }
    // M6：配对码不再落盘。老版本留下的字段读回时一律清掉（迁移即焚）
    if (Object.prototype.hasOwnProperty.call(state, 'pairingCode')) {
      delete state.pairingCode;
      dirty = true;
    }
    if (dirty) writeJson0600(this.statePath, state);
    return state;
  }

  get state() {
    if (!this.#state) this.#state = this.#readState();
    return this.#state;
  }

  get instanceId() {
    return this.state.instanceId;
  }

  /** 运行时改名：同时更新内存里的名字来源和 state.json（health 读 config.name） */
  rename(nextName) {
    const name = String(nextName ?? '').trim();
    if (name.length === 0) throw new Error('device name must not be empty');
    if (name.length > 64) throw new Error('device name must be at most 64 characters');
    this.#name = name;
    const state = this.state;
    state.name = name;
    writeJson0600(this.statePath, state);
    return name;
  }

  /**
   * 生成配对码：6 位数字、10 分钟、覆盖旧码（一次性由 consume 保证）。
   * M6：码**只存进程内存** —— state.json 里不再有它，进程重启即失效，
   * 同机另一个进程（或拿到文件写权限的人）也无法预置一枚可用的码。
   */
  issuePairingCode() {
    this.#state = this.#readState();
    const code = String(randomInt(0, 1_000_000)).padStart(6, '0');
    const expiresAt = this.#now() + PAIRING_CODE_TTL_MS;
    this.#pairingCode = { code, expiresAt };
    return { code, expiresAt };
  }

  /** 消费配对码：不存在 / 过期 / 不匹配 -> 失败；成功即焚 */
  consumePairingCode(candidate) {
    const pair = this.#pairingCode;
    if (!pair || typeof pair.code !== 'string') return { ok: false, reason: 'invalid' };
    if (this.#now() >= Number(pair.expiresAt ?? 0)) {
      this.#pairingCode = null;
      return { ok: false, reason: 'expired' };
    }
    if (!timingSafeStringEqual(pair.code, String(candidate ?? ''))) return { ok: false, reason: 'invalid' };
    this.#pairingCode = null;
    return { ok: true };
  }

  /**
   * 校验配对码但不消费（ECDH 第一轮用）：
   * 握手失败、篡改、超时都不该把码烧掉，只有 confirm 成功才 consume。
   */
  peekPairingCode(candidate) {
    const pair = this.#pairingCode;
    if (!pair || typeof pair.code !== 'string') return { ok: false, reason: 'invalid' };
    if (this.#now() >= Number(pair.expiresAt ?? 0)) {
      this.#pairingCode = null;
      return { ok: false, reason: 'expired' };
    }
    if (!timingSafeStringEqual(pair.code, String(candidate ?? ''))) return { ok: false, reason: 'invalid' };
    return { ok: true, expiresAt: Number(pair.expiresAt ?? 0) };
  }

  #readPeers() {
    const loaded = readJsonFile(this.peersPath);
    if (!loaded) return { peers: {} };
    if (typeof loaded !== 'object' || loaded === null || Array.isArray(loaded)) {
      throw new Error(`${this.peersPath} must contain a JSON object`);
    }
    if (typeof loaded.peers !== 'object' || loaded.peers === null || Array.isArray(loaded.peers)) {
      loaded.peers = {};
    }
    return loaded;
  }

  get peers() {
    if (!this.#peers) this.#peers = this.#readPeers();
    return this.#peers;
  }

  reloadPeers() {
    this.#peers = this.#readPeers();
    return this.#peers;
  }

  getPeer(peerId) {
    const local = this.peers.peers[peerId];
    if (local) return local;
    // 可能是同机 CLI 刚写入的；读一次盘再决定
    const reloaded = this.reloadPeers().peers[peerId];
    return reloaded ?? null;
  }

  listPeers() {
    const loaded = this.reloadPeers();
    return Object.entries(loaded.peers).map(([peerId, peer]) => ({
      peerId,
      name: peer?.name ?? '',
      baseUrl: peer?.baseUrl ?? null,
    }));
  }

  getPeerCount() {
    return this.listPeers().length;
  }

  /**
   * 写入/覆盖一个对端。
   * secret       —— 本端「发给该对端」时用的密钥（§3：B 存 A 给的 S，用于 B→A）
   * inboundSecret —— 校验该对端「发来」请求时用的密钥（§3 step 5：A→B 用 B 生成的 T）
   * 注：§8 只画了单个 secret 字段，双向不同密钥实际需要两把，见报告。
   */
  upsertPeer(peerId, { name, baseUrl = null, secret, inboundSecret = null }) {
    const loaded = this.reloadPeers();
    const previous = loaded.peers[peerId];
    loaded.peers[peerId] = {
      name: String(name ?? previous?.name ?? ''),
      // Two directions share one record: never drop the outbound target or the
      // peer-issued secret when this write only knows the inbound half.
      baseUrl: baseUrl == null ? (previous?.baseUrl ?? null) : String(baseUrl),
      secret: secret == null || secret === '' ? (previous?.secret ?? null) : String(secret),
      inboundSecret: inboundSecret == null ? (previous?.inboundSecret ?? null) : String(inboundSecret),
      addedAt: previous?.addedAt ?? nowIso(this.#now()),
      lastSeen: previous?.lastSeen ?? null,
    };
    writeJson0600(this.peersPath, loaded);
    return loaded.peers[peerId];
  }

  /**
   * 删除一个对端并 0600 落盘。幂等：本来就不存在时返回 false，不抛错。
   * 与 getPeer/listPeers 一样先读盘，避免把同机 CLI 刚写入的变更覆盖掉。
   */
  removePeer(peerId) {
    const id = String(peerId ?? '');
    if (id === '') return false;
    const loaded = this.reloadPeers();
    if (!Object.prototype.hasOwnProperty.call(loaded.peers, id)) return false;
    delete loaded.peers[id];
    // 该 peer 的写盘节流记录也要清掉，否则重新配对后 first touch 会被旧时间戳吃掉
    this.#lastTouchPersist.delete(id);
    writeJson0600(this.peersPath, loaded);
    return true;
  }

  /** 更新 lastSeen（内存每次更新，磁盘最多每 30s 写一次，避免每请求写盘） */
  touchPeer(peerId, atMs = this.#now()) {
    const peer = this.peers.peers[peerId];
    if (!peer) return;
    peer.lastSeen = nowIso(atMs);
    const lastPersist = this.#lastTouchPersist.get(peerId) ?? 0;
    if (atMs - lastPersist < 30_000) return;
    this.#lastTouchPersist.set(peerId, atMs);
    try {
      // Re-read first: the pairing CLI may have written baseUrl/secret since
      // this process loaded the file.
      this.reloadPeers();
      this.peers.peers[peerId] = peer;
      writeJson0600(this.peersPath, this.peers);
    } catch {
      // lastSeen 落盘失败不应让请求失败
    }
  }
}

// ---------------------------------------------------------------------------
// §3/§4 v0.5.0 群消息 meta 白名单
// ---------------------------------------------------------------------------

/** 只保留契约列出的字段；值限定 JSON 标量，字符串再卡一道长度 */
export function sanitizeGroupMeta(meta) {
  const out = {};
  if (!meta || typeof meta !== 'object' || Array.isArray(meta)) return out;
  for (const field of GROUP_META_FIELDS) {
    const value = meta[field];
    if (value == null) continue;
    if (typeof value === 'string') out[field] = value.slice(0, GROUP_META_STRING_MAX);
    else if (typeof value === 'number' || typeof value === 'boolean') out[field] = value;
  }
  return out;
}

// ---------------------------------------------------------------------------
// §4 v0.5.0 hub 侧群存储：<stateDir>/group.json（0600，只有 hub 落盘）
// ---------------------------------------------------------------------------

/** v0.8.0 契约 §7：一条入群申请的规范化视图（status 只有 pending/approved/rejected） */
function normalizeApplicationEntry(entry) {
  const raw = String(entry?.status ?? '');
  const status = GROUP_APPLICATION_STATUSES.includes(raw) && raw !== 'unknown' ? raw : 'pending';
  const at = Number(entry?.at);
  return {
    name: String(entry?.name ?? ''),
    baseUrl: String(entry?.baseUrl ?? ''),
    introducedBy: String(entry?.introducedBy ?? ''),
    at: Number.isFinite(at) && at > 0 ? Math.floor(at) : 0,
    status,
    decidedAt: typeof entry?.decidedAt === 'string' && entry.decidedAt !== '' ? entry.decidedAt : null,
  };
}

/**
 * 群状态。三条不变量：
 *
 * 1. **读写都 prune**：先删 ts < now - retentionDays 的消息，再按 5000 条硬上限丢最旧；
 * 2. **seq 单调不回退**：seq = ++lastSeq，lastSeq 落盘后即使消息被删也不减 ——
 *    客户端靠 seq 去重/续传，已删的号不能复用；
 * 3. **密钥不下盘以外的地方**：key（32B base64url）只经「已被该成员密钥加密」的
 *    成员响应下发（§3），本模块默认不对外暴露。
 */
export class GroupStore {
  #stateDir;

  #now;

  #name;

  #retentionDays;

  #owner;

  #archiveBytes;

  #logger;

  #data = null;

  constructor({
    stateDir,
    name = 'default',
    retentionDays = GROUP_DEFAULT_RETENTION_DAYS,
    owner = null,
    now = Date.now,
    archiveBytes = GROUP_ARCHIVE_BYTES_LIMIT,
    logger = null,
  }) {
    this.#stateDir = expandHome(stateDir);
    this.#now = typeof now === 'function' ? now : Date.now;
    this.#name = String(name ?? '').trim() || 'default';
    const days = Number(retentionDays);
    this.#retentionDays = Number.isFinite(days) && days >= 0 ? Math.floor(days) : GROUP_DEFAULT_RETENTION_DAYS;
    this.#owner = owner && owner.peerId
      ? { peerId: String(owner.peerId), name: String(owner.name ?? '') }
      : null;
    const bytes = Number(archiveBytes);
    this.#archiveBytes = Number.isFinite(bytes) && bytes > 0 ? Math.floor(bytes) : GROUP_ARCHIVE_BYTES_LIMIT;
    this.#logger = typeof logger === 'function' ? logger : null;
  }

  get groupPath() {
    return path.join(this.#stateDir, GROUP_FILE);
  }

  /** §18：归档目录（<stateDir>/group-archive） */
  get archiveDir() {
    return path.join(this.#stateDir, GROUP_ARCHIVE_DIR);
  }

  #log(line) {
    if (this.#logger) this.#logger(line);
  }

  /** 序列化体积：§18 的「活跃区体积」口径 */
  #messagesBytes(messages) {
    if (!Array.isArray(messages) || messages.length === 0) return 0;
    return Buffer.byteLength(JSON.stringify(messages), 'utf8');
  }

  /** 单条消息的体积（含数组里那一字节分隔符，量级足够用） */
  #messageBytes(message) {
    return Buffer.byteLength(JSON.stringify(message ?? null), 'utf8') + 1;
  }

  #archives(data) {
    if (!Array.isArray(data.archives)) data.archives = [];
    return data.archives;
  }

  /**
   * §18：算出「该搬进归档」的最旧前缀条数。
   * 三个触发条件取最靠后的那个切点：
   *   ① retentionDays 到期（不再丢弃，改为归档）；
   *   ② 5000 条硬上限（保留原有条数语义，但同样是归档而不是丢）；
   *   ③ 活跃区序列化体积 > 20 MB（§18 的主口径）。
   */
  #archiveCut(data, nowMs) {
    const messages = data.messages;
    if (!Array.isArray(messages) || messages.length === 0) return 0;
    const cutoff = nowMs - this.#retentionDays * 86_400_000;
    let cut = 0;
    while (cut < messages.length && Number(messages[cut]?.ts ?? 0) < cutoff) cut += 1;
    if (messages.length - cut > GROUP_MESSAGE_LIMIT) cut = messages.length - GROUP_MESSAGE_LIMIT;
    let bytes = this.#messagesBytes(messages);
    if (bytes > this.#archiveBytes) {
      // 从最旧的开始搬，直到剩下的部分不再超限（至少留一条，避免一次搬空）
      let index = 0;
      while (index < messages.length - 1 && bytes > this.#archiveBytes) {
        bytes -= this.#messageBytes(messages[index]);
        index += 1;
      }
      if (index > cut) cut = index;
    }
    return cut;
  }

  /**
   * §18：把一段最早的消息写成归档块并登记索引。
   * 写盘失败只告警、返回 null —— 调用方据此**不删**活跃区（宁可超限也不丢）。
   */
  #writeArchive(data, block) {
    if (!Array.isArray(block) || block.length === 0) return null;
    const fromSeq = Math.floor(Number(block[0]?.seq) || 0);
    const toSeq = Math.floor(Number(block[block.length - 1]?.seq) || 0);
    if (fromSeq < 1 || toSeq < fromSeq) return null;
    const file = `${fromSeq}-${toSeq}.json`;
    const bytes = this.#messagesBytes(block);
    const createdAt = nowIso(this.#now());
    try {
      writeJson0600(path.join(this.archiveDir, file), {
        groupId: data.groupId,
        fromSeq,
        toSeq,
        count: block.length,
        bytes,
        createdAt,
        messages: block,
      });
    } catch (error) {
      this.#log(`[group] archive failed file=${file} reason=${String(error?.code ?? error?.message ?? 'unknown')}`);
      return null;
    }
    const index = this.#archives(data);
    index.push({ file, fromSeq, toSeq, count: block.length, bytes, createdAt });
    if (index.length > GROUP_ARCHIVE_INDEX_LIMIT) {
      // §18：索引满了只提示，不自动删文件（删归档必须人工）
      this.#log(`[group] archive index full n=${index.length} max=${GROUP_ARCHIVE_INDEX_LIMIT} file=${file}`);
    }
    this.#log(`[group] archive wrote file=${file} from=${fromSeq} to=${toSeq} count=${block.length} bytes=${bytes}`);
    return file;
  }

  /** 过期/超限消息归档 + applications/pending 的 TTL；返回是否有改动（读和写都走这一步） */
  #prune(data, nowMs) {
    let changed = false;
    // §18：保留策略与体积上限都不再「丢弃」——搬进 group-archive 归档块
    const cut = this.#archiveCut(data, nowMs);
    if (cut > 0 && this.#writeArchive(data, data.messages.slice(0, cut))) {
      data.messages = data.messages.slice(cut);
      changed = true;
    }
    // v0.8.0 契约 §7：入群申请保留 24 小时，上限 100 条（超出时留最近申请的那批）
    const applications = data.applications && typeof data.applications === 'object' && !Array.isArray(data.applications)
      ? data.applications
      : {};
    const appCutoff = nowMs - GROUP_APPLICATION_TTL_MS;
    const appEntries = Object.entries(applications)
      .filter(([, entry]) => Number(entry?.at ?? 0) >= appCutoff)
      .sort((left, right) => Number(right[1]?.at ?? 0) - Number(left[1]?.at ?? 0));
    const keptApplications = {};
    for (const [peerId, entry] of appEntries.slice(0, GROUP_APPLICATION_LIMIT)) keptApplications[peerId] = entry;
    if (Object.keys(keptApplications).length !== Object.keys(applications).length) {
      data.applications = keptApplications;
      changed = true;
    }
    // S3：崩溃留下的 pending 不会永远挡住同一个 seq —— 超过 TTL 就当没提过
    const staleAfter = nowMs - GROUP_PENDING_TTL_MS;
    const pendingKept = (Array.isArray(data.pending) ? data.pending : [])
      .filter((entry) => Number(entry?.ts ?? 0) >= staleAfter);
    if (pendingKept.length !== (data.pending?.length ?? 0)) {
      data.pending = pendingKept;
      changed = true;
    }
    return changed;
  }

  #normalize(raw) {
    const data = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
    if (typeof data.groupId !== 'string' || data.groupId === '') data.groupId = randomUUID();
    if (typeof data.name !== 'string' || data.name === '') data.name = this.#name;
    if (typeof data.createdAt !== 'string') data.createdAt = nowIso(this.#now());
    if (typeof data.key !== 'string' || data.key === '') data.key = randomBytes(32).toString('base64url');
    const keyVersion = Number(data.keyVersion);
    data.keyVersion = Number.isInteger(keyVersion) && keyVersion >= 1 ? keyVersion : 1;
    if (!Array.isArray(data.messages)) data.messages = [];
    // S3 §5：未提交区。与 messages 分开存，读写都不进 history/pull/events。
    if (!Array.isArray(data.pending)) data.pending = [];
    // 被移除的成员：记住它，防止它用「自助 join」把自己加回来（踢人要真的踢掉）。
    // 只有运维显式 addMember 会把这条记录清掉（等价于重新邀请）。
    if (typeof data.blocked !== 'object' || data.blocked === null || Array.isArray(data.blocked)) data.blocked = {};
    // v0.8.0 契约 §7：入群申请 { [applicantPeerId]: { name, baseUrl, introducedBy, at, status, decidedAt } }
    if (typeof data.applications !== 'object' || data.applications === null || Array.isArray(data.applications)) {
      data.applications = {};
    }
    data.pending = data.pending.filter((entry) => entry && typeof entry === 'object'
      && Number.isFinite(Number(entry.seq)) && Number(entry.seq) > 0);
    if (typeof data.members !== 'object' || data.members === null || Array.isArray(data.members)) data.members = {};
    // v0.8.2-α §4：成员的接单开关。读写都只认「显式 false = 关闭」，
    // 缺失/垃圾值一律按 true（老 group.json 与老对端都是这个口径）。
    for (const member of Object.values(data.members)) {
      if (!member || typeof member !== 'object') continue;
      if (member.acceptDispatch !== undefined) member.acceptDispatch = member.acceptDispatch !== false;
    }
    // §18：归档索引 [{ file, fromSeq, toSeq, count, bytes, createdAt }]
    data.archives = (Array.isArray(data.archives) ? data.archives : [])
      .filter((entry) => entry && typeof entry === 'object'
        && typeof entry.file === 'string' && /^\d+-\d+\.json$/.test(entry.file))
      .map((entry) => ({
        file: String(entry.file),
        fromSeq: Math.max(0, Math.floor(Number(entry.fromSeq) || 0)),
        toSeq: Math.max(0, Math.floor(Number(entry.toSeq) || 0)),
        count: Math.max(0, Math.floor(Number(entry.count) || 0)),
        bytes: Math.max(0, Math.floor(Number(entry.bytes) || 0)),
        createdAt: typeof entry.createdAt === 'string' ? entry.createdAt : nowIso(this.#now()),
      }));
    // seq 单调：落盘的 lastSeq 不得小于任何仍存消息的 seq
    const highest = data.messages.reduce((max, message) => Math.max(max, Number(message?.seq ?? 0)), 0);
    const lastSeq = Number(data.lastSeq);
    data.lastSeq = Math.max(Number.isInteger(lastSeq) && lastSeq >= 0 ? lastSeq : 0, highest);
    return data;
  }

  #save(data) {
    this.#prune(data, this.#now());
    writeJson0600(this.groupPath, data);
    return data;
  }

  #load() {
    const nowMs = this.#now();
    if (this.#data) {
      if (this.#prune(this.#data, nowMs)) this.#save(this.#data);
      return this.#data;
    }
    const raw = readJsonFile(this.groupPath);
    const data = this.#normalize(raw);
    let dirty = raw === null;
    // hub 自己也是成员，首次初始化即入表（否则 hub 没有任何成员可读它的状态）
    if (this.#owner && !data.members[this.#owner.peerId]) {
      data.members[this.#owner.peerId] = { name: this.#owner.name, addedAt: nowIso(nowMs) };
      dirty = true;
    }
    if (this.#prune(data, nowMs)) dirty = true;
    if (dirty) this.#save(data);
    this.#data = data;
    return data;
  }

  /** 公开视图：groupKey 只在 includeKey 时给出（hub 自己的成员响应才需要） */
  state({ includeKey = false } = {}) {
    const data = this.#load();
    const view = {
      groupId: data.groupId,
      name: data.name,
      createdAt: data.createdAt,
      epoch: data.keyVersion,
      keyVersion: data.keyVersion,
      lastSeq: data.lastSeq,
      members: data.members,
      // S3 §5：未提交条数（pending 不进 messages，但要让面板/管理接口看得见）
      pendingCount: data.pending.length,
    };
    if (includeKey) view.groupKey = data.key;
    return view;
  }

  addMember(peerId, name = '') {
    const id = String(peerId ?? '').trim();
    if (id === '') throw new Error('member peerId must not be empty');
    const data = this.#load();
    // 运维显式加人 = 重新邀请：解除「被移除」记录
    if (Object.prototype.hasOwnProperty.call(data.blocked ?? {}, id)) {
      delete data.blocked[id];
      this.#save(data);
    }
    const existing = data.members[id];
    if (!existing) {
      data.members[id] = { name: String(name ?? ''), addedAt: nowIso(this.#now()) };
      this.#save(data);
    } else if (name && existing.name !== String(name)) {
      existing.name = String(name);
      this.#save(data);
    }
    return data.members[id];
  }

  /**
   * v0.8.2-α §4：记下某个成员自报的接单开关（hub 侧权威落盘）。
   * 只在该值真的变化时写盘 —— 心跳/拉取是 3s/10s 一次的周期性请求，静默期必须零写入。
   * 返回是否发生了变更。
   */
  setMemberAcceptDispatch(peerId, accept) {
    const id = String(peerId ?? '');
    const data = this.#load();
    const member = data.members[id];
    if (!member || typeof member !== 'object') return false;
    const next = accept !== false;
    // 字段缺失时也写一次：让 group.json 里每个人都有**实数**（运维/面板要看得见）。
    // 写一次之后值不变就不再落盘 —— 心跳 3s、pull 10s 一级的周期上报不会造成写放大。
    if (member.acceptDispatch !== undefined && member.acceptDispatch !== false === next) return false;
    member.acceptDispatch = next;
    this.#save(data);
    return true;
  }

  /** 这个 peerId 是否被运维移除过（自助 join 必须拒绝） */
  isBlocked(peerId) {
    const data = this.#load();
    return Object.prototype.hasOwnProperty.call(data.blocked ?? {}, String(peerId ?? ''));
  }

  removeMember(peerId) {
    const data = this.#load();
    const id = String(peerId ?? '');
    if (!Object.prototype.hasOwnProperty.call(data.members, id)) return false;
    delete data.members[id];
    // 记住「被移除」：否则它还能用 per-peer 签名走 /v1/group/join（autoJoin）把自己加回来
    data.blocked[id] = nowIso(this.#now());
    // v0.8.0：申请记录跟着成员身份一起作废（否则「被移除者申请 → rejected 且不写 applications」
    // 会被一条陈旧的 approved 条目顶掉）
    if (Object.prototype.hasOwnProperty.call(data.applications ?? {}, id)) delete data.applications[id];
    // 移除成员 = 它可能还握着旧 groupKey：必须立刻轮换密钥，否则「踢人」形同虚设
    // （被移除者只要还能用旧钥签名，就能把自己的心跳送进来）。
    data.key = randomBytes(32).toString('base64url');
    const version = Number(data.keyVersion);
    data.keyVersion = (Number.isInteger(version) && version >= 1 ? version : 1) + 1;
    this.#save(data);
    return true;
  }

  renameGroup(nextName) {
    const name = String(nextName ?? '').trim();
    if (name === '') throw new Error('group name must not be empty');
    if (name.length > 64) throw new Error('group name must be at most 64 characters');
    const data = this.#load();
    data.name = name;
    this.#save(data);
    return name;
  }

  /**
   * 追加一条消息（**单阶段写**：quorum:none、以及管理接口/面板的直写路径）。
   * 取号必须避开 pending 已预留的空号：两阶段提交的提案先占住 lastSeq+1，
   * 此时若再来一条直写也取 lastSeq+1，两条消息就会共用同一个 seq ——
   * 客户端按 seq 去重，后一条会被静默丢弃。
   */
  append({ peerId, name, kind, text = '', meta = {} }) {
    const data = this.#load();
    const reserved = data.pending.reduce((max, entry) => Math.max(max, Number(entry?.seq) || 0), 0);
    const seq = Math.max(Number(data.lastSeq) || 0, reserved) + 1;
    data.lastSeq = seq;
    const message = {
      seq,
      ts: this.#now(),
      from: { peerId: String(peerId ?? ''), name: String(name ?? '') },
      kind: String(kind ?? 'chat'),
      text: String(text ?? ''),
      meta: sanitizeGroupMeta(meta),
    };
    data.messages.push(message);
    this.#save(data);
    return message;
  }

  /**
   * S3 §5：把一条消息放进未提交区（pending），返回待提交的那条。
   * seq 取 lastSeq+1 但**不推进 lastSeq** —— 提案被丢弃时号可以复用，
   * 客户端看到的 seq 才连续（契约 §9.2「seq 连续、无重复」）。
   */
  stagePending({ peerId, name, kind, text = '', meta = {} }) {
    const data = this.#load();
    const seq = Number(data.lastSeq) + 1;
    const message = {
      seq,
      ts: this.#now(),
      from: { peerId: String(peerId ?? ''), name: String(name ?? '') },
      kind: String(kind ?? 'chat'),
      text: String(text ?? ''),
      meta: sanitizeGroupMeta(meta),
    };
    data.pending.push(message);
    this.#save(data);
    return message;
  }

  /**
   * S3 §5：把一条消息转正（提交）。优先用本机 pending 里的那条（ts/from 保持原样），
   * 也接受 commit 携带的正文；已存在的同一个 seq 幂等返回。
   */
  commitMessage(message) {
    const data = this.#load();
    const seq = Math.floor(Number(message?.seq) || 0);
    if (seq < 1) return null;
    const existing = data.messages.find((entry) => Number(entry?.seq) === seq);
    if (existing) {
      data.pending = data.pending.filter((entry) => Number(entry?.seq) !== seq);
      this.#save(data);
      return existing;
    }
    const staged = data.pending.find((entry) => Number(entry?.seq) === seq) ?? null;
    const source = staged ?? message;
    const ts = Number(source?.ts);
    const value = {
      seq,
      ts: Number.isFinite(ts) && ts > 0 ? Math.floor(ts) : this.#now(),
      from: {
        peerId: String(source?.from?.peerId ?? ''),
        name: String(source?.from?.name ?? ''),
      },
      kind: String(source?.kind ?? 'chat'),
      text: String(source?.text ?? ''),
      meta: sanitizeGroupMeta(source?.meta),
    };
    data.pending = data.pending.filter((entry) => Number(entry?.seq) !== seq);
    data.messages.push(value);
    data.messages.sort((left, right) => Number(left.seq) - Number(right.seq));
    // seq 单调不回退：提交是唯一的推进方式（丢弃的提案不推进）
    if (seq > data.lastSeq) data.lastSeq = seq;
    this.#save(data);
    return value;
  }

  /** S3：丢弃一条未提交提案（quorum 不足 / 超时）；号不推进，可被下一条复用 */
  dropPending(seq) {
    const data = this.#load();
    const id = Math.floor(Number(seq) || 0);
    const before = data.pending.length;
    data.pending = data.pending.filter((entry) => Number(entry?.seq) !== id);
    if (data.pending.length === before) return false;
    this.#save(data);
    return true;
  }

  pendingCount() {
    return this.#load().pending.length;
  }

  /** 未提交区的某一条正文（H1：commit 只认这条，不再采信 body 里的 message） */
  pendingMessage(seq) {
    const data = this.#load();
    const id = Math.floor(Number(seq) || 0);
    const found = data.pending.find((entry) => Number(entry?.seq) === id);
    return found ? { ...found, from: { ...found.from }, meta: { ...found.meta } } : null;
  }

  /** 未提交区的 seq 列表（只给门面/测试看，不携带正文） */
  pendingSeqs() {
    return this.#load().pending.map((entry) => Number(entry?.seq)).filter((seq) => seq > 0);
  }

  /**
   * §18：归档索引（管理接口/面板/CLI 用）。
   * 顺手剔除「文件已经不在」的条目 —— 人工/CLI 直接删文件后索引能自愈，不会留死条目。
   */
  archives() {
    const data = this.#load();
    const index = this.#archives(data);
    const kept = index.filter((entry) => {
      try {
        return fs.existsSync(path.join(this.archiveDir, String(entry.file)));
      } catch {
        return false;
      }
    });
    if (kept.length !== index.length) {
      data.archives = kept;
      this.#save(data);
    }
    return kept.map((entry) => ({ ...entry }));
  }

  /**
   * §18：人工删除一个归档文件并从索引移除（必须显式调用；返回值不含正文）。
   * 形状定稿（管理接口/面板按它接线）：{ ok, removedBytes } / { ok:false, reason:'unknown-archive' }。
   */
  deleteArchive(file) {
    const name = path.basename(String(file ?? '').trim());
    if (!/^\d+-\d+\.json$/.test(name)) return { ok: false, reason: 'bad-file' };
    const data = this.#load();
    const index = this.#archives(data);
    const at = index.findIndex((entry) => String(entry?.file ?? '') === name);
    let removedBytes = at >= 0 ? Math.max(0, Math.floor(Number(index[at]?.bytes) || 0)) : 0;
    let removedFile = false;
    try {
      removedFile = true;
      if (at < 0) {
        const stat = fs.statSync(path.join(this.archiveDir, name));
        removedBytes = Math.max(0, Math.floor(Number(stat?.size) || 0));
      }
      fs.unlinkSync(path.join(this.archiveDir, name));
    } catch (error) {
      if (error?.code !== 'ENOENT') return { ok: false, reason: String(error?.code ?? 'unlink-failed') };
      removedFile = false;
    }
    if (at < 0 && !removedFile) return { ok: false, reason: 'unknown-archive' };
    if (at >= 0) index.splice(at, 1);
    this.#save(data);
    this.#log(`[group] archive deleted file=${name} bytes=${removedBytes} index=${at >= 0 ? 'removed' : 'absent'}`);
    return { ok: true, file: name, removedBytes, removedFromIndex: at >= 0 };
  }

  /**
   * §18：sinceSeq 之后**下一条**落在哪个已归档区间。
   * history 用它回 { archived: true, archiveFrom, archiveTo } 而不是静默空结果。
   */
  archivedRangeFor(sinceSeq = 0) {
    const data = this.#load();
    const next = Math.floor(Number(sinceSeq) || 0) + 1;
    const hit = this.#archives(data).find((entry) => {
      const from = Number(entry?.fromSeq);
      const to = Number(entry?.toSeq);
      return Number.isFinite(from) && Number.isFinite(to) && next >= from && next <= to;
    });
    return hit
      ? { file: String(hit.file), fromSeq: Number(hit.fromSeq), toSeq: Number(hit.toSeq) }
      : null;
  }

  /** sinceSeq 之后的消息；limit 超过时保留**最新**的那批（客户端用 lastSeq 续传） */
  messages({ sinceSeq = 0, limit = GROUP_HISTORY_DEFAULT_LIMIT } = {}) {
    const data = this.#load();
    const since = Number(sinceSeq);
    const from = Number.isFinite(since) && since > 0 ? Math.floor(since) : 0;
    const requested = Number(limit);
    const cap = Number.isFinite(requested) && requested > 0
      ? Math.min(Math.floor(requested), GROUP_HISTORY_MAX_LIMIT)
      : GROUP_HISTORY_DEFAULT_LIMIT;
    const fresh = data.messages.filter((message) => Number(message?.seq ?? 0) > from);
    return fresh.length > cap ? fresh.slice(fresh.length - cap) : fresh;
  }

  // ---- v0.8.0 入群申请（契约 §4.2/§5/§7） ----------------------------------

  /** 一条申请（不存在返回 null）；只给 hub 侧用 */
  application(peerId) {
    const data = this.#load();
    const id = String(peerId ?? '');
    const entry = data.applications[id];
    if (!entry) return null;
    return { peerId: id, ...normalizeApplicationEntry(entry) };
  }

  /** 申请清单（新的在前）；管理接口/面板据此显示「待批准」区块 */
  applications() {
    const data = this.#load();
    return Object.entries(data.applications)
      .map(([peerId, entry]) => ({ peerId, ...normalizeApplicationEntry(entry) }))
      .sort((left, right) => right.at - left.at);
  }

  /**
   * 幂等登记一条申请：同一个 applicantPeerId 重复申请**只刷新 at**，不新增条目（契约 §4.2）。
   * 已经是 approved 的不会被打回 pending（否则批准后对方再点一次申请就丢授权）。
   */
  upsertApplication({ peerId, name = '', baseUrl = '', introducedBy = '', status = 'pending', now } = {}) {
    const id = String(peerId ?? '').trim();
    if (id === '') throw new Error('applicant peerId must not be empty');
    const data = this.#load();
    const at = Number(now);
    const stamp = Number.isFinite(at) && at > 0 ? Math.floor(at) : this.#now();
    const wanted = String(status ?? '');
    const nextStatus = wanted === 'approved' || wanted === 'rejected' ? wanted : 'pending';
    const existing = data.applications[id] ?? null;
    const keepApproved = existing?.status === 'approved' && nextStatus !== 'rejected';
    const effective = keepApproved ? 'approved' : nextStatus;
    data.applications[id] = {
      name: String(name ?? '').trim().slice(0, GROUP_NAME_MAX_CHARS) || String(existing?.name ?? ''),
      baseUrl: String(baseUrl ?? '').trim().replace(/\/+$/, '') || String(existing?.baseUrl ?? ''),
      introducedBy: String(introducedBy ?? '') || String(existing?.introducedBy ?? ''),
      at: stamp,
      status: effective,
      decidedAt: effective === 'pending'
        ? null
        : (keepApproved ? (existing?.decidedAt ?? nowIso(stamp)) : nowIso(stamp)),
    };
    this.#save(data);
    return { peerId: id, ...normalizeApplicationEntry(data.applications[id]) };
  }

  /**
   * 人工决定（面板/管理接口）：approved 会同时入成员表。
   * 被移除者（blocked）不能靠「批准」回来 —— 契约 §9.1 对所有权入群路径生效，
   * 重新邀请要走显式 addMember（等价于运维重新发邀请）。
   */
  decideApplication(peerId, status, { now } = {}) {
    const id = String(peerId ?? '').trim();
    const wanted = String(status ?? '');
    if (wanted !== 'approved' && wanted !== 'rejected') {
      throw new Error('status must be approved or rejected');
    }
    const data = this.#load();
    const existing = data.applications[id] ?? null;
    if (!existing) return null;
    const stampRaw = Number(now);
    const stamp = Number.isFinite(stampRaw) && stampRaw > 0 ? Math.floor(stampRaw) : this.#now();
    const blocked = Object.prototype.hasOwnProperty.call(data.blocked ?? {}, id);
    const effective = wanted === 'approved' && blocked ? 'rejected' : wanted;
    existing.status = effective;
    existing.decidedAt = nowIso(stamp);
    existing.at = stamp;
    this.#save(data);
    if (effective === 'approved') this.addMember(id, existing.name);
    return {
      peerId: id,
      ...normalizeApplicationEntry(existing),
      reason: effective !== wanted ? 'blocked' : null,
    };
  }

  /** S1：成员自报的可达地址（advertiseBaseUrl 或自动探测结果）写回群状态 */
  setMemberBaseUrl(peerId, baseUrl) {
    const data = this.#load();
    const id = String(peerId ?? '');
    const member = data.members[id];
    const next = String(baseUrl ?? '').trim().replace(/\/+$/, '');
    if (!member || next === '' || member.baseUrl === next) return member ?? null;
    member.baseUrl = next;
    this.#save(data);
    return member;
  }
}

// ---------------------------------------------------------------------------
// S2 v0.6.0 成员副本：<stateDir>/group-replica.json（0600）
// ---------------------------------------------------------------------------

/**
 * 成员侧日志副本。形状固定 {groupId, epoch, leaderPeerId, lastSeq, messages[]}，
 * 保留策略与 hub 的 group.json 完全一致（retentionDays / 5000 条 / seq 单调不回退）：
 *
 * 1. 读写都 prune（按 ts 过期 + 硬上限丢最旧）；
 * 2. 按 seq 去重后追加，lastSeq 只增不减（即使消息被保留策略删掉也不回收号）；
 * 3. epoch 更高才认新 leader；更低 epoch 的补发整批丢弃，避免旧 leader 回灌。
 */
export class GroupReplicaStore {
  #stateDir;

  #now;

  #retentionDays;

  #data = null;

  constructor({
    stateDir,
    retentionDays = GROUP_DEFAULT_RETENTION_DAYS,
    now = Date.now,
  }) {
    this.#stateDir = expandHome(stateDir);
    this.#now = typeof now === 'function' ? now : Date.now;
    const days = Number(retentionDays);
    this.#retentionDays = Number.isFinite(days) && days >= 0 ? Math.floor(days) : GROUP_DEFAULT_RETENTION_DAYS;
  }

  get replicaPath() {
    return path.join(this.#stateDir, GROUP_REPLICA_FILE);
  }

  #prune(data, nowMs) {
    let changed = false;
    const cutoff = nowMs - this.#retentionDays * 86_400_000;
    const kept = data.messages.filter((message) => Number(message?.ts ?? 0) >= cutoff);
    if (kept.length !== data.messages.length) {
      data.messages = kept;
      changed = true;
    }
    if (data.messages.length > GROUP_MESSAGE_LIMIT) {
      data.messages = data.messages.slice(data.messages.length - GROUP_MESSAGE_LIMIT);
      changed = true;
    }
    return changed;
  }

  #normalize(raw) {
    const data = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
    data.groupId = typeof data.groupId === 'string' ? data.groupId : '';
    const epoch = Number(data.epoch);
    data.epoch = Number.isFinite(epoch) && epoch > 0 ? Math.floor(epoch) : 0;
    data.leaderPeerId = typeof data.leaderPeerId === 'string' ? data.leaderPeerId : '';
    const seen = new Set();
    const messages = [];
    for (const message of Array.isArray(data.messages) ? data.messages : []) {
      const seq = Number(message?.seq);
      if (!Number.isFinite(seq) || seq <= 0) continue;
      const id = Math.floor(seq);
      if (seen.has(id)) continue;
      seen.add(id);
      messages.push({ ...message, seq: id });
    }
    messages.sort((left, right) => left.seq - right.seq);
    data.messages = messages;
    const highest = messages.length > 0 ? messages[messages.length - 1].seq : 0;
    const lastSeq = Number(data.lastSeq);
    data.lastSeq = Math.max(
      Number.isFinite(lastSeq) && lastSeq > 0 ? Math.floor(lastSeq) : 0,
      highest,
    );
    return data;
  }

  #save(data) {
    this.#prune(data, this.#now());
    writeJson0600(this.replicaPath, data);
    return data;
  }

  #load() {
    if (this.#data) {
      if (this.#prune(this.#data, this.#now())) this.#save(this.#data);
      return this.#data;
    }
    const raw = readJsonFile(this.replicaPath);
    const data = this.#normalize(raw);
    let dirty = raw === null;
    if (this.#prune(data, this.#now())) dirty = true;
    if (dirty) this.#save(data);
    this.#data = data;
    return data;
  }

  /** 只读摘要（CLI / 日志用，不含消息正文） */
  state() {
    const data = this.#load();
    return {
      groupId: data.groupId,
      epoch: data.epoch,
      leaderPeerId: data.leaderPeerId,
      lastSeq: data.lastSeq,
      messageCount: data.messages.length,
    };
  }

  /** 与 GroupStore.messages 同口径：sinceSeq 之后，超过 limit 时保留最新的一批 */
  messages({ sinceSeq = 0, limit = GROUP_HISTORY_DEFAULT_LIMIT } = {}) {
    const data = this.#load();
    const since = Number(sinceSeq);
    const from = Number.isFinite(since) && since > 0 ? Math.floor(since) : 0;
    const requested = Number(limit);
    const cap = Number.isFinite(requested) && requested > 0
      ? Math.min(Math.floor(requested), GROUP_HISTORY_MAX_LIMIT)
      : GROUP_HISTORY_DEFAULT_LIMIT;
    const fresh = data.messages.filter((message) => Number(message?.seq ?? 0) > from);
    return fresh.length > cap ? fresh.slice(fresh.length - cap) : fresh;
  }

  /** bootstrap 时写入/校正头部字段（groupId/epoch/leader），不动消息与 lastSeq */
  ensureHeader({ groupId = '', epoch = 0, leaderPeerId = '', lastSeq = 0 } = {}) {
    const data = this.#load();
    let changed = false;
    const nextGroupId = String(groupId ?? '');
    if (nextGroupId !== '' && data.groupId !== nextGroupId) {
      data.groupId = nextGroupId;
      changed = true;
    }
    const nextEpoch = Number(epoch);
    if (Number.isFinite(nextEpoch) && nextEpoch > data.epoch) {
      data.epoch = Math.floor(nextEpoch);
      changed = true;
    }
    const nextLeader = String(leaderPeerId ?? '');
    if (nextLeader !== '' && data.leaderPeerId !== nextLeader) {
      data.leaderPeerId = nextLeader;
      changed = true;
    }
    const nextLast = Number(lastSeq);
    if (Number.isFinite(nextLast) && nextLast > data.lastSeq) {
      data.lastSeq = Math.floor(nextLast);
      changed = true;
    }
    if (changed) this.#save(data);
    return this.state();
  }

  /**
   * 收下一批消息（replicate / pull 共用）：校验 groupId、按 seq 去重、epoch 更高则换 leader。
   * 返回 {ok, added, lastSeq, epoch, leaderPeerId}；groupId 不一致时不落盘。
   */
  append({ groupId = '', epoch = 0, leaderPeerId = '', messages = [] } = {}) {
    const data = this.#load();
    const incomingGroup = String(groupId ?? '');
    if (incomingGroup !== '' && data.groupId !== '' && incomingGroup !== data.groupId) {
      return { ok: false, error: 'group-mismatch', added: 0, lastSeq: data.lastSeq, epoch: data.epoch, leaderPeerId: data.leaderPeerId };
    }
    let changed = false;
    if (data.groupId === '' && incomingGroup !== '') {
      data.groupId = incomingGroup;
      changed = true;
    }
    const incomingEpoch = Number(epoch);
    const epochValue = Number.isFinite(incomingEpoch) && incomingEpoch > 0 ? Math.floor(incomingEpoch) : 0;
    if (epochValue > data.epoch) {
      data.epoch = epochValue;
      changed = true;
      if (String(leaderPeerId ?? '') !== '') {
        data.leaderPeerId = String(leaderPeerId);
      }
    } else if (epochValue > 0 && epochValue < data.epoch) {
      // 旧 leader 的补发：整批丢弃（epoch 回退会让接任后的记录倒退）
      if (changed) this.#save(data);
      return { ok: true, added: 0, stale: true, lastSeq: data.lastSeq, epoch: data.epoch, leaderPeerId: data.leaderPeerId };
    } else if (String(leaderPeerId ?? '') !== '' && data.leaderPeerId !== String(leaderPeerId)) {
      data.leaderPeerId = String(leaderPeerId);
      changed = true;
    }

    const seen = new Set(data.messages.map((message) => Number(message.seq)));
    let added = 0;
    for (const message of Array.isArray(messages) ? messages : []) {
      const seq = Number(message?.seq);
      if (!Number.isFinite(seq) || seq <= 0) continue;
      const id = Math.floor(seq);
      if (seen.has(id)) continue;
      seen.add(id);
      const ts = Number(message?.ts);
      data.messages.push({
        seq: id,
        ts: Number.isFinite(ts) && ts > 0 ? Math.floor(ts) : this.#now(),
        from: {
          peerId: String(message?.from?.peerId ?? ''),
          name: String(message?.from?.name ?? ''),
        },
        kind: String(message?.kind ?? 'chat'),
        text: String(message?.text ?? ''),
        meta: sanitizeGroupMeta(message?.meta),
      });
      added += 1;
    }
    if (added > 0) {
      data.messages.sort((left, right) => left.seq - right.seq);
      const highest = data.messages[data.messages.length - 1].seq;
      // seq 单调不回退：即使中间的消息被保留策略删掉，lastSeq 也不减
      if (highest > data.lastSeq) data.lastSeq = highest;
      changed = true;
    }
    if (changed) this.#save(data);
    return { ok: true, added, lastSeq: data.lastSeq, epoch: data.epoch, leaderPeerId: data.leaderPeerId };
  }
}

// ---------------------------------------------------------------------------
// S3 v0.7.0 角色/租约：<stateDir>/group-role.json（0600）
// ---------------------------------------------------------------------------

/**
 * 本机角色状态（契约 §1）。形状冻结：
 *   {role, epoch, leaderPeerId, leaseUntil, commitSeq, votedFor, groupId}
 * votedFor 必须落盘 —— 它是「同一个 epoch 不投两次」的唯一依据（契约 §3）。
 */
export class GroupRoleStore {
  #stateDir;

  #now;

  #data = null;

  constructor({ stateDir, now = Date.now }) {
    this.#stateDir = expandHome(stateDir);
    this.#now = typeof now === 'function' ? now : Date.now;
  }

  get rolePath() {
    return path.join(this.#stateDir, GROUP_ROLE_FILE);
  }

  #normalize(raw) {
    const data = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
    data.role = GROUP_ROLES.includes(String(data.role ?? '')) ? String(data.role) : 'follower';
    const epoch = Number(data.epoch);
    data.epoch = Number.isFinite(epoch) && epoch > 0 ? Math.floor(epoch) : 0;
    data.leaderPeerId = typeof data.leaderPeerId === 'string' ? data.leaderPeerId : '';
    const leaseUntil = Number(data.leaseUntil);
    data.leaseUntil = Number.isFinite(leaseUntil) && leaseUntil > 0 ? Math.floor(leaseUntil) : 0;
    const commitSeq = Number(data.commitSeq);
    data.commitSeq = Number.isFinite(commitSeq) && commitSeq > 0 ? Math.floor(commitSeq) : 0;
    const votedEpoch = Number(data.votedFor?.epoch);
    data.votedFor = Number.isFinite(votedEpoch) && votedEpoch > 0 && String(data.votedFor?.peerId ?? '') !== ''
      ? { epoch: Math.floor(votedEpoch), peerId: String(data.votedFor.peerId) }
      : null;
    data.groupId = typeof data.groupId === 'string' ? data.groupId : '';
    return data;
  }

  #save(data) {
    writeJson0600(this.rolePath, data);
    return data;
  }

  #load() {
    if (this.#data) return this.#data;
    this.#data = this.#normalize(readJsonFile(this.rolePath));
    return this.#data;
  }

  state() {
    const data = this.#load();
    return {
      role: data.role,
      epoch: data.epoch,
      leaderPeerId: data.leaderPeerId,
      leaseUntil: data.leaseUntil,
      commitSeq: data.commitSeq,
      votedFor: data.votedFor ? { ...data.votedFor } : null,
      groupId: data.groupId,
    };
  }

  /** 只更新给出的字段（其余保持），落盘后返回新状态 */
  update(patch = {}) {
    const data = this.#load();
    if (patch.role !== undefined) data.role = patch.role;
    if (patch.epoch !== undefined) data.epoch = patch.epoch;
    if (patch.leaderPeerId !== undefined) data.leaderPeerId = patch.leaderPeerId;
    if (patch.leaseUntil !== undefined) data.leaseUntil = patch.leaseUntil;
    if (patch.commitSeq !== undefined) data.commitSeq = patch.commitSeq;
    if (patch.votedFor !== undefined) data.votedFor = patch.votedFor;
    if (patch.groupId !== undefined) data.groupId = patch.groupId;
    const normalized = this.#normalize(data);
    this.#data = normalized;
    return this.#save(normalized) && this.state();
  }
}

/** 独立使用的配对码生成入口（给 CLI / client half 复用） */
export function issuePairingCode(options = {}) {
  const config = resolveConfig(options);
  const store = new StateStore({ stateDir: config.stateDir, name: config.name, now: config.now });
  const { code, expiresAt } = store.issuePairingCode();
  return { code, expiresAt, instanceId: store.instanceId, stateDir: config.stateDir };
}

// ---------------------------------------------------------------------------
// Runner：/v1/ask 的执行侧接口（与 DSH 的耦合点）
// ---------------------------------------------------------------------------

/**
 * 内存假实现：
 *   - ask(prompt)     立刻返回 sessionId，1 秒后「完成」
 *   - poll(sessionId) running / done（reply = "OK " + prompt 前 20 字）
 *
 * 下一轮的真 DSH 适配器实现同一个接口即可，server 不需要改。
 * 注意：poll 返回 {status:'done'} 时 reply 必须是最终回复文本；
 *      {status:'error'} 时带 error 字符串。
 */
export class MemoryRunner {
  constructor({ workspace, preset, permission, delayMs = 1000, now = Date.now } = {}) {
    this.workspace = workspace;
    this.preset = preset;
    this.permission = permission;
    this.delayMs = delayMs;
    this.now = now;
    this.sessions = new Map();
    this.sequence = 0;
  }

  async ask(prompt) {
    this.sequence += 1;
    const sessionId = `mem-${this.sequence}-${randomBytes(4).toString('hex')}`;
    const startedAt = this.now();
    this.sessions.set(sessionId, {
      prompt: String(prompt),
      startedAt,
      completesAt: startedAt + this.delayMs,
      reply: `OK ${firstChars(prompt, 20)}`,
    });
    return sessionId;
  }

  poll(sessionId) {
    const session = this.sessions.get(sessionId);
    if (!session) return { status: 'error', error: 'unknown-session' };
    if (this.now() >= session.completesAt) {
      return { status: 'done', reply: session.reply };
    }
    return { status: 'running' };
  }
}

/** 真 DSH 适配器的插入点 */
export function createRunner(options = {}) {
  return new MemoryRunner(options);
}

// ---------------------------------------------------------------------------
// HTTP 服务
// ---------------------------------------------------------------------------

/**
 * The peer record this request claims, used to pick the inbound content key
 * before the signature is verified. The signature still guards the ciphertext,
 * so a wrong id only fails closed.
 */
function peerForRequest(store, req) {
  const peerId = String(req.headers['x-peer-id'] ?? '');
  if (peerId === '') return null;
  try {
    // getPeer() carries the secrets; listPeers() is the redacted view for /v1/peers.
    if (typeof store.getPeer === 'function') return store.getPeer(peerId) ?? null;
    return store.listPeers().find((peer) => peer.peerId === peerId) ?? null;
  } catch {
    return null;
  }
}

/**
 * Decrypt a request body when it advertises our envelope. Returns the plaintext
 * bytes, or throws `bad-encryption` so the caller can answer 400.
 */
function decryptInbound(secret, rawBody, encHeader) {
  if (String(encHeader ?? '') !== ENC_VERSION) return rawBody;
  if (rawBody.length === 0) return rawBody;
  return decryptBytes(secret, rawBody.toString('utf8'));
}

/** Wrap one response body in the encrypted envelope. */
function encryptOutbound(secret, body) {
  return { enc: ENC_VERSION, data: encryptBytes(secret, Buffer.from(JSON.stringify(body), 'utf8')) };
}

function sendJson(res, status, payload) {
  const body = Buffer.from(JSON.stringify(payload));
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': String(body.length),
    'cache-control': 'no-store',
  });
  res.end(body);
}

function readRequestBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let tooLarge = false;
    req.on('data', (chunk) => {
      if (tooLarge) return;
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        tooLarge = true;
        chunks.length = 0;
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (tooLarge) {
        const err = new Error('payload too large');
        err.code = 'payload-too-large';
        reject(err);
        return;
      }
      resolve(Buffer.concat(chunks));
    });
    req.on('error', reject);
  });
}

function parseJsonBody(rawBody) {
  if (!rawBody || rawBody.length === 0) return {};
  let parsed;
  try {
    parsed = JSON.parse(rawBody.toString('utf8'));
  } catch {
    const err = new Error('invalid JSON body');
    err.code = 'bad-json';
    throw err;
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    const err = new Error('JSON body must be an object');
    err.code = 'bad-json';
    throw err;
  }
  return parsed;
}

function nonEmptyString(value, maxLength = 4096) {
  return typeof value === 'string' && value.trim() !== '' && value.length <= maxLength;
}

/**
 * 创建 host 服务实例（不自动 listen）。
 *
 * @param {object} overrides 见 resolveConfig；另外：
 *   runner   —— 注入 runner（默认 createRunner(...)）
 *   stateDir —— 状态目录（测试用临时目录）
 * @returns {{
 *   config: object, store: StateStore, runner: object,
 *   issuePairingCode: () => {code: string, expiresAt: number},
 *   listen: (port?: number, host?: string) => Promise<{host: string, port: number, url: string}>,
 *   close: () => Promise<void>,
 *   url: () => string | null, httpServer: import('node:http').Server,
 * }}
 */
export function createPeerServer(overrides = {}) {
  const config = resolveConfig(overrides);
  const store = new StateStore({ stateDir: config.stateDir, name: config.name, now: config.now });
  const runner = overrides.runner ?? createRunner({
    workspace: config.workspace,
    preset: config.agentPreset,
    permission: config.permission,
    now: config.now,
  });
  if (!runner || typeof runner.ask !== 'function' || typeof runner.poll !== 'function') {
    throw new TypeError('runner must implement ask(prompt) and poll(sessionId)');
  }

  /** sessionId -> 会话记录 */
  /**
   * §3 群事件流的节奏：默认 200ms 轮询 / 10s ping。
   * 测试需要在一个用例里看到 ping 帧，用 overrides.groupStream 覆盖（只影响本进程）。
   */
  const groupPollIntervalMs = Number.isFinite(Number(overrides.groupStream?.pollIntervalMs))
    ? Math.max(20, Math.floor(Number(overrides.groupStream.pollIntervalMs)))
    : GROUP_POLL_INTERVAL_MS;
  const groupPingIntervalMs = Number.isFinite(Number(overrides.groupStream?.pingIntervalMs))
    ? Math.max(20, Math.floor(Number(overrides.groupStream.pingIntervalMs)))
    : GROUP_EVENTS_PING_INTERVAL_MS;

  const sessions = new Map();
  /** `${peerId}\0${requestId}` -> sessionId（幂等） */
  const requestIds = new Map();
  /** nonce -> 过期时间 */
  const nonces = new Map();
  let lastNoncePrune = 0;

  /**
   * §2 ECDH 第一轮挂起状态：code -> { privateKey, clientPublicKey, peerId, peerName, baseUrl, expiresAt }。
   * 只在内存、不落盘；120s TTL，confirm 成功或过期即删。私钥用完即弃，服务端不持久化。
   */
  const pendingPairs = new Map();
  const pendingPairTimer = setInterval(() => prunePendingPairs(config.now()), 30_000);
  pendingPairTimer.unref?.();

  function prunePendingPairs(nowMs) {
    for (const [code, pending] of pendingPairs) {
      if (pending.expiresAt <= nowMs) pendingPairs.delete(code);
    }
  }

  /**
   * §4 v0.5.0：只有 hub 落盘群状态。
   *   group.enabled 且没配 group.hub          -> hub（本机自建群）
   *   group.enabled 且配了 group.hub（成员侧） -> member
   * v0.8.0（契约 §5.1）：**没在配置里启用群**，但 group-key.json 记着 hub（按名入群拿到的授权）
   *   -> member：无需任何 group.hub 配置就能 pull、建副本、参加选举。
   *   其余 -> off（没有群服务，端点 404）
   */
  function resolveGroupRole() {
    if (config.group.enabled) return config.group.hub === '' ? 'hub' : 'member';
    const keyHub = readGroupKeyFile(config.stateDir)?.hub ?? null;
    const known = keyHub && (String(keyHub.baseUrl ?? '') !== '' || String(keyHub.peerId ?? '') !== '');
    return known ? 'member' : 'off';
  }

  // v0.8.0：role 可以被**运行期提升**（按名入群拿到 grant 后原地变成员），所以是 let
  let groupRole = resolveGroupRole();

  // -------------------------------------------------------------------------
  // v0.8.2-α §4：本机「接单」开关（热生效）
  //
  // 配置 group.acceptDispatch 是**默认值来源**；运行期切换（面板/CLI 调
  // server.group.setAcceptDispatch）落 <stateDir>/group-dispatch-prefs.json，启动时覆盖配置。
  // 刻意不回写 DSH profile：那是用户手改过的文件，插件写坏一次就要人工修。
  // -------------------------------------------------------------------------
  const groupPrefsPath = path.join(config.stateDir, GROUP_DISPATCH_PREFS_FILE);

  function readAcceptDispatchPref() {
    try {
      const raw = JSON.parse(fs.readFileSync(groupPrefsPath, 'utf8'));
      return parseAcceptFlag(raw?.acceptDispatch);
    } catch {
      return null;
    }
  }

  let localAcceptDispatch = (() => {
    const pref = readAcceptDispatchPref();
    if (pref !== null) return pref;
    return config.group.acceptDispatch === false ? false : GROUP_DEFAULT_ACCEPT_DISPATCH;
  })();

  /** 本机接单开关（所有自报点与群状态视图都读这里，切换后立刻生效） */
  const acceptDispatchNow = () => localAcceptDispatch === true;

  /** §18：归档触发体积（默认 20 MB；overrides.groupArchive.bytes 只给测试压缩用） */
  const archiveBytesLimit = Number.isFinite(Number(overrides.groupArchive?.bytes))
    ? Math.max(1, Math.floor(Number(overrides.groupArchive.bytes)))
    : GROUP_ARCHIVE_BYTES_LIMIT;

  const groupStore = groupRole === 'hub'
    ? new GroupStore({
        stateDir: config.stateDir,
        name: config.group.name,
        retentionDays: config.group.retentionDays,
        // hub 自己也是成员，首次初始化即入表
        owner: { peerId: store.instanceId, name: config.name },
        now: config.now,
        archiveBytes: archiveBytesLimit,
        logger: config.logger,
      })
    : null;

  // v0.8.2-α §4：hub 自己那条成员的接单开关必须**落成实数**。
  // 它收不到自己的心跳，若不在这里写，group.json 里就永远是 undefined；作者侧读到
  // undefined 会按向后兼容当 true → not-accepting 永远触发不了（2026-11-01 真机复现）。
  if (groupStore) groupStore.setMemberAcceptDispatch(store.instanceId, localAcceptDispatch);

  /**
   * S2：只有成员落盘副本；hub 的权威日志仍是 group.json。
   * 副本与 group.json 同保留策略（retentionDays / 5000 条 / seq 单调不回退）。
   */
  function createReplicaStore() {
    return new GroupReplicaStore({
      stateDir: config.stateDir,
      retentionDays: config.group.retentionDays,
      now: config.now,
    });
  }

  let replicaStore = groupRole === 'member' ? createReplicaStore() : null;

  /** 真实监听端口（listen 时才知道）；S1 的地址探测要用 */
  let boundAddress = null;

  /** 本机对外的可达地址：group.advertiseBaseUrl 优先，否则「首选私有 IPv4 + 实际端口」 */
  function localAdvertiseBaseUrl() {
    const configured = String(config.group.advertiseBaseUrl ?? '').trim().replace(/\/+$/, '');
    if (configured !== '') return configured;
    const ip = detectPrivateIpv4();
    if (!ip) return '';
    const port = boundAddress?.port ?? config.listenPort;
    return `http://${ip}:${port}`;
  }

  /**
   * 本机的群视图：hub 读 group.json，成员读 group-key.json + group-replica.json。
   * 返回 null 表示本机还没有群上下文（群关闭，或成员还没 bootstrap）。
   */
  function localGroupContext() {
    if (groupStore) {
      const data = groupStore.state({ includeKey: true });
      return {
        node: 'hub',
        groupId: data.groupId,
        epoch: data.epoch,
        leaderPeerId: store.instanceId,
        // 群密钥只经「已被成员密钥加密」的响应下发；服务端内部用它派生群级密钥
        groupKey: data.groupKey,
        lastSeq: data.lastSeq,
        members: data.members,
      };
    }
    if (groupRole !== 'member') return null;
    const keyFile = readGroupKeyFile(config.stateDir);
    if (!keyFile) return null;
    const replica = replicaStore.state();
    const members = { ...keyFile.members };
    // 自己那一行永远用本机实时开关（group-key.json 是从 hub 抄来的副本，可能是旧的）
    members[store.instanceId] = {
      ...(members[store.instanceId] ?? { name: config.name }),
      name: members[store.instanceId]?.name || config.name,
      acceptDispatch: acceptDispatchNow(),
    };
    return {
      node: 'member',
      groupId: keyFile.groupId,
      epoch: Math.max(keyFile.epoch, replica.epoch),
      leaderPeerId: replica.leaderPeerId || keyFile.leaderPeerId || '',
      groupKey: keyFile.key,
      lastSeq: replica.lastSeq,
      members,
    };
  }

  /** 群级 nonce 表独立于 per-peer：两套 canonical 的 nonce 命名空间不共享 */
  const groupNonces = new Map();
  let lastGroupNoncePrune = 0;

  function rememberGroupNonce(nonce, nowMs) {
    if (nowMs - lastGroupNoncePrune > 30_000) {
      for (const [key, expiresAt] of groupNonces) {
        if (expiresAt <= nowMs) groupNonces.delete(key);
      }
      lastGroupNoncePrune = nowMs;
    }
    groupNonces.set(nonce, nowMs + GROUP_AUTH_NONCE_WINDOW_MS);
  }

  /**
   * S1 群级签名校验（独立 canonical，与 §4 的五行的完全分开）：
   * groupId 一致、senderPeerId 在成员表、ts ±60s、nonce 120s 去重。
   * 返回 {ok:true, senderId, ctx} 或 {ok:false, status, error}。
   */
  function verifyGroupAuth(req, rawBody, { allowUnknownSender = false } = {}) {
    const senderId = headerValue(req, 'x-peer-id');
    const groupId = headerValue(req, GROUP_ID_HEADER.toLowerCase());
    const tsRaw = headerValue(req, 'x-peer-ts');
    const nonce = headerValue(req, 'x-peer-nonce');
    const signature = headerValue(req, 'x-peer-sign');
    if (!senderId || !tsRaw || !nonce || !signature) return { ok: false, status: 401, error: 'bad-signature' };
    const ts = Number(tsRaw);
    if (!Number.isFinite(ts)) return { ok: false, status: 401, error: 'bad-signature' };
    const nowMs = config.now();
    if (Math.abs(nowMs - ts) > GROUP_AUTH_CLOCK_SKEW_MS) return { ok: false, status: 401, error: 'clock-skew' };
    if ((groupNonces.get(nonce) ?? 0) > nowMs) return { ok: false, status: 401, error: 'replay' };
    const ctx = localGroupContext();
    if (!ctx || !ctx.groupKey) return { ok: false, status: 401, error: 'group-auth-unavailable' };
    if (String(groupId) !== String(ctx.groupId)) return { ok: false, status: 401, error: 'group-mismatch' };
    // 先验签、再查成员表：被移除的成员拿着**旧群密钥**打进来应当是 bad-signature（密钥世代不对），
    // 而不是 not-a-member —— 这样「移除成员即轮换密钥」才有可验证的信号。
    const canonical = buildGroupCanonical({
      method: req.method,
      path: req.url,
      ts: tsRaw,
      nonce,
      groupId,
      senderPeerId: senderId,
      rawBody,
    });
    const { signKey } = deriveGroupKeys(ctx.groupKey);
    const expected = signGroupCanonical({ signKey, canonical });
    if (!timingSafeStringEqual(expected, signature)) return { ok: false, status: 401, error: 'bad-signature' };
    if (senderId !== store.instanceId && !Object.prototype.hasOwnProperty.call(ctx.members, senderId)) {
      // hub 是权威成员表：不认识就是不属于群，一律拒绝（自愈只给成员侧的副本用）
      if (!allowUnknownSender || groupStore) return { ok: false, status: 401, error: 'not-a-member' };
      // H3：自愈不能再「凭签名把任意 id 写进 group-key.json」。
      // 只允许**最近一次权威快照**（hub 的 state / pull 的 memberIds）里出现过的 id：
      // 快照说这个人在群里、只是本机表还停在旧版本 → 补进来；
      // 快照里根本没有的 id → 仍然 not-a-member（否则一个幽灵 id 就能把自己写进成员表）。
      if (!authoritativeMemberIds.has(senderId)) {
        if (config.logger) config.logger(`[group] self-heal refused peer=${shortPeerId(senderId)}`);
        return { ok: false, status: 401, error: 'not-a-member' };
      }
      // 自愈（真机 not-a-member 回归）：群密钥签名已经证明对端握有群密钥，只是本机成员表
      // 还停在一份不完整的快照上（成员在 bootstrap 之后才加入）。选举/心跳是领导权协议，
      // 先把它补进成员表，否则对端永远投不进来、整个群选不出 leader。
      upsertGroupMember(senderId);
      if (config.logger) config.logger(`[group] member healed peer=${shortPeerId(senderId)}`);
    }
    // 只有签名通过的 nonce 才登记（同 per-peer 路径）
    rememberGroupNonce(nonce, nowMs);
    return { ok: true, senderId, ctx };
  }

  /** 响应加密用的密钥（与 http 层的规则一致：inboundSecret 优先，兼容 secret 回落） */
  function responseKeyFor(peer) {
    if (peer?.inboundSecret) return peer.inboundSecret;
    if (config.acceptSecretFallback && peer?.secret) return peer.secret;
    return null;
  }

  // ---- 签名校验（§4） -----------------------------------------------------

  function pruneNonces(nowMs) {
    for (const [nonce, expiresAt] of nonces) {
      if (expiresAt <= nowMs) nonces.delete(nonce);
    }
    lastNoncePrune = nowMs;
  }

  function rememberNonce(nonce, nowMs) {
    if (nowMs - lastNoncePrune > 30_000) pruneNonces(nowMs);
    nonces.set(nonce, nowMs + NONCE_WINDOW_MS);
  }

  function verifyPeerSignature(peer, canonical, providedSign) {
    const secrets = [];
    if (peer?.inboundSecret) secrets.push(peer.inboundSecret);
    if (config.acceptSecretFallback && peer?.secret && !secrets.includes(peer.secret)) {
      secrets.push(peer.secret);
    }
    for (const secret of secrets) {
      const expected = signCanonical({ secret, canonical, keyEncoding: config.secretKeyEncoding });
      if (timingSafeStringEqual(expected, providedSign)) return true;
    }
    return false;
  }

  /** 返回 {ok:true, peerId, peer} 或 {ok:false, status, error} */
  function authenticate(req, rawBody) {
    const peerId = headerValue(req, 'x-peer-id');
    const tsRaw = headerValue(req, 'x-peer-ts');
    const nonce = headerValue(req, 'x-peer-nonce');
    const signature = headerValue(req, 'x-peer-sign');
    if (!peerId || !tsRaw || !nonce || !signature) {
      return { ok: false, status: 401, error: 'bad-signature' };
    }
    const ts = Number(tsRaw);
    if (!Number.isFinite(ts)) return { ok: false, status: 401, error: 'bad-signature' };

    const nowMs = config.now();
    // 1) 时钟窗
    if (Math.abs(nowMs - ts) > CLOCK_SKEW_MS) return { ok: false, status: 401, error: 'clock-skew' };
    // 2) 重放（nonce 在窗口内出现过）
    if (nonces.has(nonce) && (nonces.get(nonce) ?? 0) > nowMs) {
      return { ok: false, status: 401, error: 'replay' };
    }
    // 3) 找到对端、比对签名
    const peer = store.getPeer(peerId);
    if (!peer) return { ok: false, status: 401, error: 'unknown-peer' };
    const canonical = buildCanonical({
      method: req.method,
      path: req.url,
      ts: tsRaw,
      nonce,
      rawBody,
    });
    if (!verifyPeerSignature(peer, canonical, signature)) {
      return { ok: false, status: 401, error: 'bad-signature' };
    }
    // 只有签名通过的 nonce 才登记，避免坏人用坏请求把 nonce 占掉
    rememberNonce(nonce, nowMs);
    store.touchPeer(peerId, nowMs);
    return { ok: true, peerId, peer };
  }

  // ---- /v1/ask 的会话与超时 ----------------------------------------------

  function normalizeTimeoutSec(value) {
    if (value === undefined || value === null) return DEFAULT_TIMEOUT_SEC;
    const numeric = Number(value);
    if (!Number.isFinite(numeric) || numeric <= 0) return null;
    return Math.min(Math.ceil(numeric), MAX_TIMEOUT_SEC);
  }

  function pruneSessions() {
    if (sessions.size <= MAX_SESSIONS) return;
    const oldestFirst = [...sessions.values()].sort((a, b) => a.startedAt - b.startedAt);
    while (sessions.size > MAX_SESSIONS && oldestFirst.length > 0) {
      const session = oldestFirst.shift();
      sessions.delete(session.sessionId);
      requestIds.delete(`${session.peerId}\u0000${session.requestId}`);
    }
  }

  async function createAskSession({ peerId, requestId, prompt, timeoutSec }) {
    const key = `${peerId}\u0000${requestId}`;
    const existingId = requestIds.get(key);
    if (existingId && sessions.has(existingId)) {
      return { sessionId: existingId, reused: true };
    }
    // 真 DSH 适配器可能是异步的，这里 await 兼容 string 与 Promise
    const runnerSessionId = await runner.ask(prompt);
    const sessionId = randomUUID();
    const startedAt = config.now();
    sessions.set(sessionId, {
      sessionId,
      peerId,
      requestId,
      prompt,
      runnerSessionId,
      startedAt,
      timeoutSec,
      deadline: startedAt + timeoutSec * 1000,
    });
    requestIds.set(key, sessionId);
    pruneSessions();
    return { sessionId, reused: false };
  }

  async function answerFor(session) {
    let result;
    try {
      // 真 DSH 适配器的 poll 是异步的（读本地 session 列表），必须 await，
      // 否则拿到的是 Promise，status 恒为 running，直到 deadline 误报 timeout。
      result = await runner.poll(session.runnerSessionId);
    } catch {
      return { status: 'error', error: 'runner-error' };
    }
    result = result ?? {};
    if (result.status === 'done') {
      return { status: 'done', reply: String(result.reply ?? '') };
    }
    if (result.status === 'error') {
      return { status: 'error', error: String(result.error ?? 'runner-error') };
    }
    // 会话已完成就不算超时；只有还在跑且过了 deadline 才算 timeout
    if (config.now() >= session.deadline) return { status: 'error', error: 'timeout' };
    return { status: 'running' };
  }

  // ---- 路由 --------------------------------------------------------------

  /** §1：legacy 模式下不宣告 pair-ecdh，新客户端因此自动回退旧明文配对（兼容矩阵第 2 行） */
  function capabilityList() {
    if (config.pairingMode === 'legacy') return CAPABILITIES.filter((item) => item !== 'pair-ecdh');
    return [...CAPABILITIES];
  }

  function health() {
    return {
      status: 200,
      body: {
        name: config.name,
        instanceId: store.instanceId,
        version: PLUGIN_VERSION,
        capability: capabilityList(),
        peers: store.getPeerCount(),
      },
    };
  }

  function pair(rawBody) {
    let body;
    try {
      body = parseJsonBody(rawBody);
    } catch {
      return { status: 400, body: { error: 'bad-request' } };
    }
    // §2 v0.4.0：带 ecdh 走两轮握手（不消费码）；不带则一字不改地保留 0.3.1 明文路径
    if (body.ecdh !== undefined && body.ecdh !== null) return pairEcdhRound1(body);
    if (config.pairingMode === 'ecdh') return { status: 400, body: { error: 'ecdh-required' } };
    const { code, peerId, peerName, secret } = body;
    if (!nonEmptyString(peerId, 200) || !nonEmptyString(peerName, 200) || !nonEmptyString(secret, 512)) {
      return { status: 400, body: { error: 'bad-request' } };
    }
    if (code == null || !/^\d{6}$/.test(String(code))) {
      return { status: 401, body: { error: 'invalid-code' } };
    }
    const consumed = store.consumePairingCode(String(code));
    if (!consumed.ok) return { status: 401, body: { error: 'invalid-code' } };

    // §3 step 3：B 保存 A 给的 S（B→A 用），并生成给 A 的 T（A→B 用）
    const inboundSecret = randomSecret();
    store.upsertPeer(peerId, {
      name: peerName,
      baseUrl: typeof body.baseUrl === 'string' ? body.baseUrl : null,
      secret,
      inboundSecret,
    });
    // 兼容矩阵第 1 行：行为不变，但每次走明文都留一行弃用告警（不含 secret）
    warnLegacyPairing(peerId);
    return {
      status: 200,
      body: {
        peerId: store.instanceId,
        peerName: config.name,
        secret: inboundSecret,
      },
    };
  }

  /** 旧明文配对路径的弃用告警：一行、可 grep、不带密钥 */
  function warnLegacyPairing(peerId) {
    if (config.logger) config.logger(`pair: legacy plaintext path used by ${peerId}`);
  }

  /** §2 ECDH 第一轮：只发服务端临时公钥，**不消费**配对码 */
  function pairEcdhRound1(body) {
    if (config.pairingMode === 'legacy') return { status: 400, body: { error: 'bad-request' } };
    const { code, peerId, peerName, ecdh } = body;
    if (!nonEmptyString(peerId, 200) || !nonEmptyString(peerName, 200)) {
      return { status: 400, body: { error: 'bad-request' } };
    }
    if (ecdh === null || typeof ecdh !== 'object' || Array.isArray(ecdh)) {
      return { status: 400, body: { error: 'bad-request' } };
    }
    if (Number(ecdh.v) !== PAIR_PROTOCOL_VERSION || String(ecdh.curve ?? '') !== PAIR_CURVE) {
      return { status: 400, body: { error: 'bad-request' } };
    }
    if (!isValidPublicKeyB64url(ecdh.publicKey)) {
      return { status: 400, body: { error: 'bad-request' } };
    }
    if (code == null || !/^\d{6}$/.test(String(code))) {
      return { status: 401, body: { error: 'invalid-code' } };
    }
    // 只校验不消费：否则第一轮失败一次就把码废了
    if (!store.peekPairingCode(String(code)).ok) {
      return { status: 401, body: { error: 'invalid-code' } };
    }
    const nowMs = config.now();
    prunePendingPairs(nowMs);
    const ephemeral = generateKeyPair();
    pendingPairs.delete(String(code));
    pendingPairs.set(String(code), {
      privateKey: ephemeral.privateKey,
      clientPublicKey: ecdh.publicKey,
      peerId,
      // 契约要求 pending 里留档；confirm 以 body 里的 peerName 为准
      peerName,
      baseUrl: typeof body.baseUrl === 'string' ? body.baseUrl : null,
      expiresAt: nowMs + PAIRING_ECDH_TTL_MS,
    });
    while (pendingPairs.size > MAX_PENDING_PAIRS) {
      const oldest = [...pendingPairs.entries()].sort((a, b) => a[1].expiresAt - b[1].expiresAt)[0];
      if (!oldest) break;
      pendingPairs.delete(oldest[0]);
    }
    return {
      status: 200,
      body: {
        ecdh: { v: PAIR_PROTOCOL_VERSION, curve: PAIR_CURVE, publicKey: ephemeral.publicKeyB64url },
        pairingTtlMs: PAIRING_ECDH_TTL_MS,
      },
    };
  }

  /**
   * §2 ECDH 第二轮：W = HKDF(ECDH(serverPriv, clientPub))，解 wrapped 里的 S，
   * 成功才消费配对码、写 peer，再用同一把 W 回 wrapped({secret: T})。
   */
  function pairConfirm(rawBody) {
    let body;
    try {
      body = parseJsonBody(rawBody);
    } catch {
      return { status: 400, body: { error: 'bad-request' } };
    }
    const { code, peerId, peerName, wrapped } = body;
    if (!nonEmptyString(peerId, 200) || !nonEmptyString(peerName, 200) || !nonEmptyString(wrapped, 8192)) {
      return { status: 400, body: { error: 'bad-request' } };
    }
    if (code == null || !/^\d{6}$/.test(String(code))) {
      return { status: 401, body: { error: 'invalid-code' } };
    }
    prunePendingPairs(config.now());
    const pending = pendingPairs.get(String(code));
    if (!pending) {
      // 码还在但没有挂起的握手 → pairing-expired；码本身不对/已被用掉 → invalid-code
      const known = store.peekPairingCode(String(code)).ok;
      return { status: 401, body: { error: known ? 'pairing-expired' : 'invalid-code' } };
    }
    if (pending.peerId !== peerId) return { status: 400, body: { error: 'bad-request' } };
    let wrapKey;
    try {
      wrapKey = deriveWrapKey(pending.privateKey, pending.clientPublicKey);
    } catch {
      return { status: 400, body: { error: 'bad-request' } };
    }
    let payload;
    try {
      payload = unwrapSecret(wrapKey, wrapped);
    } catch {
      // 篡改或错密钥：码与 pending 都不动，允许用正确 wrapped 重试
      return { status: 400, body: { error: 'bad-encryption' } };
    }
    if (!nonEmptyString(payload.secret, 512)) return { status: 400, body: { error: 'bad-encryption' } };

    const consumed = store.consumePairingCode(String(code));
    pendingPairs.delete(String(code));
    if (!consumed.ok) return { status: 401, body: { error: 'pairing-expired' } };

    // 与明文路径同一语义：存对端给的 S（我→对端），生成 T（对端→我）
    const inboundSecret = randomSecret();
    store.upsertPeer(peerId, {
      name: peerName,
      baseUrl: pending.baseUrl ?? null,
      secret: payload.secret,
      inboundSecret,
    });
    return {
      status: 200,
      body: {
        peerId: store.instanceId,
        peerName: config.name,
        // 每次新随机 nonce，同一把 W 只在本轮有效
        wrapped: wrapSecret(wrapKey, { secret: inboundSecret }),
      },
    };
  }

  async function ask(req, rawBody) {
    const auth = authenticate(req, rawBody);
    if (!auth.ok) return { status: auth.status, body: { error: auth.error }, peerId: null };
    // 先认证再暴露配置：未配对的人看不到 disabled
    if (!config.allowRemotePrompts) {
      return { status: 403, body: { error: 'disabled' }, peerId: auth.peerId };
    }
    let body;
    try {
      body = parseJsonBody(rawBody);
    } catch (err) {
      return { status: 400, body: { error: 'bad-request' }, peerId: auth.peerId };
    }
    const { requestId, prompt } = body;
    if (!nonEmptyString(requestId, 200) || !nonEmptyString(prompt, MAX_BODY_BYTES)) {
      return { status: 400, body: { error: 'bad-request' }, peerId: auth.peerId };
    }
    const timeoutSec = normalizeTimeoutSec(body.timeoutSec);
    if (timeoutSec == null) {
      return { status: 400, body: { error: 'bad-request' }, peerId: auth.peerId };
    }
    let created;
    try {
      created = await createAskSession({ peerId: auth.peerId, requestId, prompt, timeoutSec });
    } catch {
      return { status: 500, body: { error: 'runner-error' }, peerId: auth.peerId };
    }
    return { status: 202, body: { sessionId: created.sessionId }, peerId: auth.peerId };
  }

  /** §4：没有 waitMs（或 <=0）→ 0，立即返回，语义与 0.3.1 完全一致 */
  function readWaitMs(url) {
    const raw = url.searchParams.get('waitMs');
    if (raw == null || raw === '') return 0;
    const numeric = Number(raw);
    if (!Number.isFinite(numeric) || numeric <= 0) return 0;
    return Math.min(Math.floor(numeric), config.answerWaitMs);
  }

  async function answer(req, rawBody, url, res) {
    const hrStart = process.hrtime.bigint();
    // hold 时长用真实时钟量（假时钟注入下也不会空转），与 http 日志的耗时口径一致
    const elapsedMs = () => Number(process.hrtime.bigint() - hrStart) / 1e6;
    const auth = authenticate(req, rawBody);
    if (!auth.ok) return { status: auth.status, body: { error: auth.error }, peerId: null };
    const sessionId = url.searchParams.get('sessionId');
    if (!nonEmptyString(sessionId, 200)) {
      return { status: 400, body: { error: 'bad-request' }, peerId: auth.peerId };
    }
    const session = sessions.get(sessionId);
    // 只允许发起者本人读取，避免已配对的对端互看结果
    if (!session || session.peerId !== auth.peerId) {
      return { status: 404, body: { error: 'unknown-session' }, peerId: auth.peerId };
    }
    const waitMs = readWaitMs(url);
    let disconnected = false;
    if (res && typeof res.once === 'function') {
      // 客户端走了就别再空转轮询；会话本身不受影响
      res.once('close', () => { disconnected = true; });
    }
    let outcome = await answerFor(session);
    while (waitMs > 0 && outcome.status === 'running' && !disconnected) {
      const remaining = waitMs - elapsedMs();
      if (remaining <= 0) break;
      await sleep(Math.min(ANSWER_POLL_INTERVAL_MS, remaining));
      if (disconnected) break;
      outcome = await answerFor(session);
    }
    return {
      status: 200,
      body: { ...outcome, elapsedMs: Math.round(elapsedMs()) },
      peerId: auth.peerId,
    };
  }

  // ---- §5 SSE：/v1/events -------------------------------------------------

  /** 一条事件 = 独立 GCM 帧（逐条新 nonce），载荷仍是 {enc:'v1', data} */
  function sseFrame(event, payload, key) {
    const data = encryptBytes(key, Buffer.from(JSON.stringify(payload), 'utf8'));
    return `event: ${event}\ndata: ${JSON.stringify({ enc: ENC_VERSION, data })}\n\n`;
  }

  /**
   * §5：签名与其它端点相同（canonical 的 body = sha256("")）。
   * GET 没有请求体，所以不强制 X-Peer-Enc；流内每一条事件始终加密。
   * 终态事件（done/error）之后主动 end；客户端断开只结束流，不停会话。
   */
  async function events(req, rawBody, url, res) {
    const hrStart = process.hrtime.bigint();
    const elapsedMs = () => Number(process.hrtime.bigint() - hrStart) / 1e6;
    const auth = authenticate(req, rawBody);
    if (!auth.ok) return { status: auth.status, body: { error: auth.error }, peerId: null };
    const sessionId = url.searchParams.get('sessionId');
    if (!nonEmptyString(sessionId, 200)) {
      return { status: 400, body: { error: 'bad-request' }, peerId: auth.peerId };
    }
    const session = sessions.get(sessionId);
    // 与 /v1/answer 同样的归属校验：非发起者一律 404（客户端据此回退长轮询）
    if (!session || session.peerId !== auth.peerId) {
      return { status: 404, body: { error: 'unknown-session' }, peerId: auth.peerId };
    }
    const streamKey = responseKeyFor(auth.peer);
    if (!streamKey) {
      return { status: 400, body: { error: 'encryption-required' }, peerId: auth.peerId };
    }

    res.writeHead(200, {
      'content-type': 'text/event-stream; charset=utf-8',
      'cache-control': 'no-store',
      connection: 'keep-alive',
      'x-accel-buffering': 'no',
    });
    res.flushHeaders?.();
    req.socket?.setNoDelay?.(true);

    let closed = false;
    const onClose = () => { closed = true; };
    res.once('close', onClose);
    const write = (event, payload) => {
      if (closed || res.writableEnded) return false;
      try {
        res.write(sseFrame(event, payload, streamKey));
        return true;
      } catch {
        closed = true;
        return false;
      }
    };

    let lastStatusAt = -Infinity;
    let lastPingAt = 0;
    let outcome;
    try {
      outcome = await answerFor(session);
      while (!closed && !res.writableEnded) {
        const nowMs = Math.round(elapsedMs());
        if (outcome.status === 'running') {
          if (nowMs - lastStatusAt >= EVENTS_STATUS_INTERVAL_MS) {
            if (!write('status', { status: 'running', elapsedMs: nowMs })) break;
            lastStatusAt = nowMs;
          }
          if (nowMs - lastPingAt >= EVENTS_PING_INTERVAL_MS) {
            if (!write('ping', { t: config.now() })) break;
            lastPingAt = nowMs;
          }
          await sleep(ANSWER_POLL_INTERVAL_MS);
          if (closed) break;
          outcome = await answerFor(session);
          continue;
        }
        if (outcome.status === 'done') {
          write('done', { status: 'done', reply: outcome.reply ?? '', elapsedMs: nowMs });
        } else {
          write('error', { status: 'error', error: outcome.error ?? 'runner-error', elapsedMs: nowMs });
        }
        break;
      }
    } finally {
      res.removeListener('close', onClose);
      if (!res.writableEnded && !res.destroyed) {
        try {
          res.end();
        } catch {
          /* 客户端已经走了 */
        }
      }
    }
    return {
      status: 200,
      body: { status: outcome?.status ?? 'running', elapsedMs: Math.round(elapsedMs()) },
      peerId: auth.peerId,
    };
  }

  function peers(req, rawBody) {
    const auth = authenticate(req, rawBody);
    if (!auth.ok) return { status: auth.status, body: { error: auth.error }, peerId: null };
    return {
      status: 200,
      body: { peers: store.listPeers().map(({ peerId, name, baseUrl }) => ({ peerId, name, baseUrl })) },
      peerId: auth.peerId,
    };
  }

  /**
   * /v1/unpair（签名+加密）：请求方要求本端把它删掉。
   * 只认 auth.peerId —— body 一律忽略，请求方不能指定别删哪个 peerId；
   * 无 body 也合法（canonical 的 body 摘要就是 sha256("")）。
   */
  function unpair(req, rawBody) {
    const auth = authenticate(req, rawBody);
    if (!auth.ok) return { status: auth.status, body: { error: auth.error }, peerId: null };
    const removed = store.removePeer(auth.peerId);
    // 该 peer 挂起的 ECDH 握手一并作废，免得删掉之后还能被 confirm 写回来
    for (const [code, pending] of pendingPairs) {
      if (pending.peerId === auth.peerId) pendingPairs.delete(code);
    }
    return {
      status: 200,
      body: { ok: true, removed, peers: store.getPeerCount() },
      peerId: auth.peerId,
    };
  }

  // ---- §3 v0.5.0 群（hub 侧；成员侧用 lib/group-client.mjs 走网络） --------

  /** 短 id：peerId 前 8 位（与 [admin] 日志里的 id8 口径一致） */
  function shortPeerId(peerId) {
    return String(peerId ?? '').slice(0, 8);
  }

  /**
   * 展示用名字：**同名成员加短 id 后缀**（"desk-alpha (3c389892)"）。
   *
   * 为什么在渲染层做而不是写回 group.json：一台机器上跑两个 CLI 节点、或两台同型号
   * 机器都会上报同一个 hostname；读的时候统一加后缀，历史消息也能一并纠正，
   * 而原始 name 保持不动（契约 §4 的 members[peerId].name 仍是本人上报的那份）。
   */
  function groupDisplayNames(members) {
    const raw = new Map();
    const counts = new Map();
    for (const [peerId, member] of Object.entries(members)) {
      const name = member?.name || shortPeerId(peerId);
      raw.set(peerId, name);
      counts.set(name, (counts.get(name) ?? 0) + 1);
    }
    const display = new Map();
    for (const [peerId, name] of raw) {
      display.set(peerId, (counts.get(name) ?? 0) > 1 ? `${name} (${shortPeerId(peerId)})` : name);
    }
    return display;
  }

  /** 只改渲染值：from.name 换成去重后的展示名，其它字段原样 */
  function withDisplayName(message, displayNames) {
    const peerId = String(message?.from?.peerId ?? '');
    const shown = displayNames.get(peerId);
    if (shown === undefined || shown === message?.from?.name) return message;
    return { ...message, from: { ...message.from, name: shown } };
  }

  function decoratedMessages(options) {
    const displayNames = groupDisplayNames(groupStore.state().members);
    return groupStore.messages(options).map((message) => withDisplayName(message, displayNames));
  }

  /** 成员表 + 在线状态：自己永远在线，其他成员看 peers.json 的 lastSeen */
  function groupMembersView() {
    const data = groupStore.state();
    const displayNames = groupDisplayNames(data.members);
    const nowMs = config.now();
    return Object.entries(data.members).map(([peerId, member]) => {
      const isSelf = peerId === store.instanceId;
      const peer = isSelf ? null : store.getPeer(peerId);
      const lastSeen = isSelf ? nowIso(nowMs) : (peer?.lastSeen ?? null);
      const seenAt = lastSeen ? Date.parse(lastSeen) : Number.NaN;
      return {
        peerId,
        name: displayNames.get(peerId) ?? member?.name ?? '',
        // 渲染值与原始值分开：group.json 里存的是后者
        rawName: member?.name ?? '',
        online: isSelf || (Number.isFinite(seenAt) && nowMs - seenAt <= GROUP_ONLINE_WINDOW_MS),
        lastSeen,
        joinedAt: member?.addedAt ?? null,
        // S1「我看到的你的地址」：成员自报的优先，其次 peers.json 里配对时的地址
        baseUrl: member?.baseUrl ?? (isSelf ? localAdvertiseBaseUrl() : (peer?.baseUrl ?? '')) ?? '',
        // S2 复制进度：自己就是 leader（取群日志的 lastSeq）；成员取它自报的值，
        // 从未 probe/pull 过的成员是 null —— 不要填 0 冒充「已同步 0 条」。
        lastSeq: isSelf
          ? groupStore.state().lastSeq
          : (memberProgress.get(peerId)?.lastSeq ?? null),
        // v0.8.2-α §4：接单开关（老对端缺字段 = true）。自己那一行读本机实时值。
        acceptDispatch: isSelf ? acceptDispatchNow() : member?.acceptDispatch !== false,
      };
    });
  }

  /** 成员表：hub 读 group.json；成员节点（S3 里也可能当 leader）读群上下文 */
  function groupMembersMap() {
    if (groupStore) return groupStore.state().members;
    return localGroupContext()?.members ?? {};
  }

  function groupMemberOf(peerId) {
    const members = groupMembersMap();
    return Object.prototype.hasOwnProperty.call(members, peerId) ? members[peerId] : null;
  }

  function groupState(req, rawBody) {
    const auth = authenticate(req, rawBody);
    if (!auth.ok) return { status: auth.status, body: { error: auth.error }, peerId: null };
    const member = groupMemberOf(auth.peerId);
    if (!member) return { status: 403, body: { error: 'not-a-member' }, peerId: auth.peerId };
    const data = groupStore.state({ includeKey: true });
    return {
      status: 200,
      body: {
        groupId: data.groupId,
        name: data.name,
        epoch: data.epoch,
        keyVersion: data.keyVersion,
        members: groupMembersView(),
        // §3：只给成员；响应本身已被该成员的密钥加密（ENC_HEADER 门控）
        groupKey: data.groupKey,
      },
      peerId: auth.peerId,
    };
  }

  /**
   * §3：autoJoin 为真才允许已配对成员自助加入；否则一律 not-a-member。
   *
   * body 里可选 `name` 是**请求方自己的显示名**：只写 auth.peerId 这一条，
   * 没有办法改别人的名字（body 里的 peerId 之类一律忽略）。
   */
  function groupJoin(req, rawBody) {
    const auth = authenticate(req, rawBody);
    if (!auth.ok) return { status: auth.status, body: { error: auth.error }, peerId: null };
    let body;
    try {
      body = parseJsonBody(rawBody);
    } catch {
      return { status: 400, body: { error: 'bad-request' }, peerId: auth.peerId };
    }
    let requestedName = null;
    if (body.name != null) {
      const trimmed = typeof body.name === 'string' ? body.name.trim() : '';
      if (trimmed === '' || trimmed.length > 64) {
        return { status: 400, body: { error: 'bad-request' }, peerId: auth.peerId };
      }
      requestedName = trimmed;
    }
    const existing = groupMemberOf(auth.peerId);
    if (!existing) {
      if (!config.group.autoJoin) return { status: 403, body: { error: 'not-a-member' }, peerId: auth.peerId };
      // 被移除过的成员：自助 join 不生效（必须有运维显式 addMember 重新邀请）
      if (groupStore.isBlocked(auth.peerId)) {
        if (config.logger) config.logger(`[group] join refused peer=${shortPeerId(auth.peerId)} reason=removed`);
        return { status: 403, body: { error: 'not-a-member' }, peerId: auth.peerId };
      }
      groupStore.addMember(auth.peerId, requestedName ?? auth.peer?.name ?? '');
      if (config.logger) config.logger(`[group] join ${auth.peerId}`);
      // 契约 §2a：入群成功后广播一次（非成员伙伴、按伙伴节流 6 小时）
      void broadcastGroupName({ reason: 'join' }).catch(() => {});
    } else if (requestedName && requestedName !== existing.name) {
      // 已经是成员时再 join 一次 = 本人改自己的显示名
      groupStore.addMember(auth.peerId, requestedName);
      if (config.logger) config.logger(`[group] join ${auth.peerId} (rename)`);
    }
    const data = groupStore.state();
    return {
      status: 200,
      body: { groupId: data.groupId, epoch: data.epoch, name: data.members[auth.peerId]?.name ?? '' },
      peerId: auth.peerId,
    };
  }

  /**
   * 正文校验（两种鉴权共用同一口径）：kind 白名单、text 必须是字符串且不超长。
   * 超长直接拒绝（不截断）：截断会悄悄改写别人的话。
   */
  function readPostBody(rawBody, peerId) {
    let body;
    try {
      body = parseJsonBody(rawBody);
    } catch {
      return { status: 400, body: { error: 'bad-request' }, peerId };
    }
    const kind = String(body.kind ?? '');
    if (!GROUP_KINDS.includes(kind)) return { status: 400, body: { error: 'bad-request' }, peerId };
    if (body.text != null && typeof body.text !== 'string') {
      return { status: 400, body: { error: 'bad-request' }, peerId };
    }
    const text = typeof body.text === 'string' ? body.text : '';
    if (Array.from(text).length > GROUP_TEXT_MAX_CHARS) {
      return { status: 413, body: { error: 'payload-too-large' }, peerId };
    }
    return { body: { kind, text, meta: body.meta } };
  }

  /** S3 §5：写路径串行化（两种鉴权共用）—— 一次只让一条消息走 propose→commit */
  function enqueuePost(input) {
    const task = postChain.then(() => deliverPost(input));
    postChain = task.then(() => {}, () => {});
    return task;
  }

  function groupPost(req, rawBody) {
    const auth = authenticate(req, rawBody);
    if (!auth.ok) return { status: auth.status, body: { error: auth.error }, peerId: null };
    const member = groupMemberOf(auth.peerId);
    if (!member) return { status: 403, body: { error: 'not-a-member' }, peerId: auth.peerId };
    const parsed = readPostBody(rawBody, auth.peerId);
    if (parsed.status) return parsed;
    return enqueuePost({
      peerId: auth.peerId,
      name: member.name || auth.peer?.name || '',
      kind: parsed.body.kind,
      text: parsed.body.text,
      meta: parsed.body.meta,
    });
  }

  /**
   * POST /v1/group/post —— **群级签名**通道（v0.8.0 新增鉴权模式，per-peer 路径一字不变）。
   *
   * 为什么需要：按名入群的成员只有 group-key.json 里的群密钥，没有与 hub 的 per-peer 密钥，
   * 只认 per-peer 就等于「只能读不能发言」—— 与群聊目的不符。
   *
   * 三条硬约束（契约 §9）：
   *   1. canonical 里的 senderPeerId 必须在成员表内；
   *   2. 该 sender 不在 blocked（被移除者不能借群密钥继续发言）；
   *   3. body 里的 from/peerId 一律忽略 —— 作者永远以签名为准。
   * blocked 名单只有 hub 有权威数据，所以这条通道只在 hub 上生效（成员节点回 409 not-a-hub）。
   */
  function groupPostWithGroupAuth(req, rawBody) {
    if (groupRole === 'off') return { status: 404, body: { error: 'not-found' }, peerId: null };
    if (!groupStore) return { status: 409, body: { error: 'not-a-hub' }, peerId: null };
    const checked = verifyGroupAuth(req, rawBody, { allowUnknownSender: false });
    if (!checked.ok) return { status: checked.status, body: { error: checked.error }, peerId: null };
    const sender = String(checked.senderId ?? '');
    const member = Object.prototype.hasOwnProperty.call(checked.ctx.members ?? {}, sender)
      ? checked.ctx.members[sender]
      : null;
    if (!member) return { status: 403, body: { error: 'not-a-member' }, peerId: sender };
    if (groupStore.isBlocked(sender)) {
      if (config.logger) config.logger('[group] post refused peer=' + shortPeerId(sender) + ' reason=blocked');
      return { status: 403, body: { error: 'blocked' }, peerId: sender };
    }
    const parsed = readPostBody(rawBody, sender);
    if (parsed.status) return parsed;
    // 作者取自签名与成员表，body 里的 from/peerId 连读都不读
    return enqueuePost({
      peerId: sender,
      name: String(member.name ?? '') || groupMemberName(sender),
      kind: parsed.body.kind,
      text: parsed.body.text,
      meta: parsed.body.meta,
    });
  }

  function readGroupSinceSeq(url) {
    const raw = url.searchParams.get('sinceSeq');
    if (raw == null || raw === '') return 0;
    const numeric = Number(raw);
    return Number.isFinite(numeric) && numeric > 0 ? Math.floor(numeric) : 0;
  }

  function readGroupLimit(url) {
    const raw = url.searchParams.get('limit');
    if (raw == null || raw === '') return GROUP_HISTORY_DEFAULT_LIMIT;
    const numeric = Number(raw);
    if (!Number.isFinite(numeric) || numeric < 1) return GROUP_HISTORY_DEFAULT_LIMIT;
    return Math.min(Math.floor(numeric), GROUP_HISTORY_MAX_LIMIT);
  }

  function groupHistory(req, rawBody, url) {
    const auth = authenticate(req, rawBody);
    if (!auth.ok) return { status: auth.status, body: { error: auth.error }, peerId: null };
    if (!groupMemberOf(auth.peerId)) return { status: 403, body: { error: 'not-a-member' }, peerId: auth.peerId };
    const data = groupStore.state();
    const sinceSeq = readGroupSinceSeq(url);
    // §18：游标落在已归档区间 → 明确回 archived 标记，不静默给空结果
    const archived = groupStore.archivedRangeFor(sinceSeq);
    if (archived) {
      return {
        status: 200,
        body: {
          groupId: data.groupId,
          epoch: data.epoch,
          lastSeq: data.lastSeq,
          archived: true,
          archiveFrom: archived.fromSeq,
          archiveTo: archived.toSeq,
          messages: [],
        },
        peerId: auth.peerId,
      };
    }
    return {
      status: 200,
      body: {
        groupId: data.groupId,
        epoch: data.epoch,
        lastSeq: data.lastSeq,
        messages: decoratedMessages({ sinceSeq, limit: readGroupLimit(url) }),
      },
      peerId: auth.peerId,
    };
  }

  /**
   * §3 /v1/group/events（SSE）：每帧一条 sseFrame（逐帧新 nonce，可逐帧解密），
   * 先用 sinceSeq 补发历史，再按 200ms 轮询群存储；event: ping 每 10s。
   * 流本身没有终态 —— 客户端断开（或 CLI 的 --duration 到点）才结束。
   */
  async function groupEvents(req, rawBody, url, res) {
    const auth = authenticate(req, rawBody);
    if (!auth.ok) return { status: auth.status, body: { error: auth.error }, peerId: null };
    if (!groupMemberOf(auth.peerId)) return { status: 403, body: { error: 'not-a-member' }, peerId: auth.peerId };
    const streamKey = responseKeyFor(auth.peer);
    if (!streamKey) {
      return { status: 400, body: { error: 'encryption-required' }, peerId: auth.peerId };
    }

    res.writeHead(200, {
      'content-type': 'text/event-stream; charset=utf-8',
      'cache-control': 'no-store',
      connection: 'keep-alive',
      'x-accel-buffering': 'no',
    });
    res.flushHeaders?.();
    req.socket?.setNoDelay?.(true);

    let closed = false;
    const onClose = () => { closed = true; };
    res.once('close', onClose);
    const write = (event, payload) => {
      if (closed || res.writableEnded) return false;
      try {
        res.write(sseFrame(event, payload, streamKey));
        return true;
      } catch {
        closed = true;
        return false;
      }
    };

    let sinceSeq = readGroupSinceSeq(url);
    const hrStart = process.hrtime.bigint();
    let lastPingAt = 0;
    try {
      for (;;) {
        for (const message of decoratedMessages({ sinceSeq, limit: GROUP_HISTORY_MAX_LIMIT })) {
          if (!write('message', message)) break;
          sinceSeq = Number(message.seq) || sinceSeq;
        }
        if (closed || res.writableEnded) break;
        const nowMs = Number(process.hrtime.bigint() - hrStart) / 1e6;
        if (nowMs - lastPingAt >= groupPingIntervalMs) {
          if (!write('ping', { t: config.now() })) break;
          lastPingAt = nowMs;
        }
        await sleep(groupPollIntervalMs);
      }
    } finally {
      res.removeListener('close', onClose);
      if (!res.writableEnded && !res.destroyed) {
        try {
          res.end();
        } catch {
          /* 客户端已经走了 */
        }
      }
    }
    return { status: 200, body: { status: 'ok', lastSeq: sinceSeq }, peerId: auth.peerId };
  }


  // ---- v0.8.0 群名广播 / 按名查找 / 按名申请（契约 §2–§5） -----------------

  /** 启动后广播的延迟：等 listen 完成（地址才知道），且不阻塞启动 */
  const ADVERTISE_STARTUP_DELAY_MS = 1_200;

  /**
   * 本机的群身份（hub 与成员都适用）：广播与查重要用的 groupId / 群名 / hub 三元组。
   * 群名来源：hub 读 group.json 的 name；成员读 group-key.json 的 groupName。
   * 成员侧**不回落配置**（配置默认值会把 'default' 当群名广播出去）。
   * 本地为空时由 resolveGroupIdentity() 向 hub 现取并回写。
   */
  function localGroupIdentity() {
    const ctx = localGroupContext();
    if (!ctx || String(ctx.groupId ?? '') === '') return null;
    const selfId = store.instanceId;
    const members = ctx.members ?? {};
    const keyFile = groupStore ? null : readGroupKeyFile(config.stateDir);
    // hub 节点自己就是 hub；成员节点信 leaderPeerId（群密钥与权威日志在它那边）
    const hubPeerId = groupStore ? selfId : String(ctx.leaderPeerId || keyFile?.leaderPeerId || '');
    const hubMember = hubPeerId === '' ? null : (members[hubPeerId] ?? null);
    return {
      groupId: String(ctx.groupId),
      // 成员侧的群名**只认本地文件里的 groupName**（0.7.x 老文件为空 → 交给
      // resolveGroupIdentity() 向 hub 现取一次；取不到就是 unknown）。
      // 绝不回落到 config.group.name：那会把配置默认值 'default' 当成真群名广播出去。
      name: groupStore
        ? String(groupStore.state().name)
        : normalizeGroupName(keyFile?.groupName),
      hub: {
        peerId: hubPeerId,
        name: String(hubMember?.name ?? '') || (hubPeerId === selfId ? config.name : ''),
        baseUrl: hubPeerId === selfId
          ? localAdvertiseBaseUrl()
          : String(hubMember?.baseUrl ?? '').trim().replace(/\/+$/, ''),
      },
      member: { peerId: selfId, name: groupMemberName(selfId) || config.name },
    };
  }

  /**
   * 群身份（带群名自愈）：本地 groupName 为空（0.7.x 老文件）时向 hub 现取一次权威群名，
   * 取到即回写 group-key.json。仍然拿不到就保持空串 —— 调用方必须报 unknown。
   */
  async function resolveGroupIdentity() {
    const identity = localGroupIdentity();
    if (!identity || identity.name !== '') return identity;
    const hub = groupHubPeer();
    const resolved = await resolveGroupName({
      stateDir: config.stateDir,
      hub: hub ? { baseUrl: hub.baseUrl, secret: hub.secret } : null,
      senderId: store.instanceId,
    }).catch(() => ({ name: '' }));
    if (resolved.name === '') return identity;
    if (config.logger) {
      config.logger('[group] group-name resolved source=' + resolved.source + ' name=' + resolved.name);
    }
    return { ...identity, name: resolved.name };
  }

  /** 广播目标：已配对但**不在本群**的伙伴（secret 走 getPeer —— listPeers 是脱敏视图） */
  function nonMemberPeers() {
    const members = groupMembersMap();
    const out = [];
    for (const visible of store.listPeers()) {
      const peerId = String(visible?.peerId ?? '');
      if (peerId === '' || Object.prototype.hasOwnProperty.call(members, peerId)) continue;
      const full = store.getPeer(peerId) ?? visible;
      out.push({
        peerId,
        name: String(full?.name ?? ''),
        baseUrl: String(full?.baseUrl ?? '').trim().replace(/\/+$/, ''),
        secret: full?.secret,
      });
    }
    return out;
  }

  let advertiseTimer = null;
  let memberJoinAdvertised = false;

  /**
   * 契约 §2：把本机群名广播给非成员伙伴。
   * manual（面板按钮 / CLI）不节流；自动触发按伙伴维度 6 小时节流（advertise-state.json）。
   * 从不抛：失败只记一行日志，返回发过与跳过的清单。
   */
  async function broadcastGroupName({ manual = false, reason = 'manual' } = {}) {
    const identity = await resolveGroupIdentity();
    if (!identity) return { ok: false, reason: 'no-group', sent: [], skipped: [] };
    if (identity.name === '') {
      // 群名未知就不广播（宁可什么都不发，也不把 'default' 当成真群名发给伙伴）
      if (config.logger) {
        config.logger('[group] advertise skipped reason=group-name-unknown group=' + shortPeerId(identity.groupId));
      }
      return { ok: false, reason: 'group-name-unknown', sent: [], skipped: [] };
    }
    const peers = nonMemberPeers();
    if (peers.length === 0) {
      return { ok: true, groupId: identity.groupId, name: identity.name, sent: [], skipped: [] };
    }
    let out;
    try {
      out = await broadcastGroupAdvertisement({
        peers,
        self: identity.member,
        group: {
          groupId: identity.groupId,
          name: identity.name,
          hub: identity.hub,
          members: Object.keys(groupMembersMap()),
        },
        stateDir: config.stateDir,
        manual,
        now: () => config.now(),
      });
    } catch (error) {
      if (config.logger) {
        config.logger('[group] advertise failed reason=' + String(error?.message ?? error).slice(0, 60));
      }
      return { ok: false, reason: 'advertise-failed', sent: [], skipped: [] };
    }
    if (config.logger) {
      config.logger(
        '[group] advertise reason=' + reason
        + ' group=' + shortPeerId(identity.groupId)
        + ' sent=' + out.sent.length
        + ' skipped=' + out.skipped.length,
      );
    }
    return out;
  }

  /** 启动后一次（契约 §2a）：延迟到 listen 之后，定时器 unref 且 close() 会清掉 */
  function scheduleStartupAdvertise() {
    if (advertiseTimer) return;
    advertiseTimer = setTimeout(() => {
      advertiseTimer = null;
      void broadcastGroupName({ reason: 'startup' }).catch(() => {});
    }, ADVERTISE_STARTUP_DELAY_MS);
    advertiseTimer.unref?.();
  }

  /** per-peer 请求的 JSON body（坏 JSON 返回 null，调用方回 400） */
  function readPeerJsonBody(rawBody) {
    try {
      const parsed = parseJsonBody(rawBody);
      return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
    } catch {
      return null;
    }
  }

  /** hub 侧 grant（契约 §5.1）：群密钥 + 成员表 + hub 地址；外发时由传输层自适应加密 */
  function groupGrant() {
    const data = groupStore.state({ includeKey: true });
    return {
      groupId: data.groupId,
      name: data.name,
      epoch: data.epoch,
      keyVersion: data.keyVersion,
      key: data.groupKey,
      hub: { peerId: store.instanceId, name: config.name, baseUrl: localAdvertiseBaseUrl() },
      members: Object.entries(data.members).map(([peerId, member]) => ({
        peerId,
        name: String(member?.name ?? ''),
        baseUrl: String(member?.baseUrl ?? '').trim().replace(/\/+$/, ''),
      })),
    };
  }

  /**
   * 契约 §4.2：hub 侧入账（本地与远程都走这一份）。
   * blocked 一律 rejected 且**不落 applications**（§9.1）；autoJoin 直接 approved。
   */
  function intakeApplication({ applicant, introducer } = {}) {
    if (!groupStore) return { status: 'unknown', reason: 'not-a-hub' };
    const peerId = String(applicant?.peerId ?? '').trim();
    if (peerId === '') return { status: 'unknown', reason: 'bad-request' };
    if (groupStore.isBlocked(peerId)) {
      if (config.logger) {
        config.logger('[group] apply rejected peer=' + shortPeerId(peerId) + ' reason=blocked');
      }
      return { status: 'rejected', reason: 'blocked' };
    }
    // 已经是成员：既有成员身份本身就够，不必再落一条申请
    if (Object.prototype.hasOwnProperty.call(groupMembersMap(), peerId)) {
      return { status: 'approved', reason: 'already-member' };
    }
    const name = String(applicant?.name ?? '').trim().slice(0, GROUP_NAME_MAX_CHARS);
    const baseUrl = String(applicant?.baseUrl ?? '').trim().replace(/\/+$/, '');
    const autoApprove = config.group.autoJoin === true;
    const entry = groupStore.upsertApplication({
      peerId,
      name,
      baseUrl,
      introducedBy: String(introducer?.peerId ?? ''),
      status: autoApprove ? 'approved' : 'pending',
      now: config.now(),
    });
    if (entry.status === 'approved' && !Object.prototype.hasOwnProperty.call(groupMembersMap(), peerId)) {
      groupStore.addMember(peerId, name);
      if (baseUrl !== '') groupStore.setMemberBaseUrl(peerId, baseUrl);
    }
    if (config.logger) {
      config.logger(
        '[group] apply peer=' + shortPeerId(peerId)
        + ' by=' + shortPeerId(String(introducer?.peerId ?? ''))
        + ' status=' + entry.status,
      );
    }
    if (entry.status === 'approved') void broadcastGroupName({ reason: 'join' }).catch(() => {});
    return { status: entry.status };
  }

  /** 契约 §5.1：hub 侧查一条申请；approved 时连 grant 一起给 */
  function queryApplication(applicantPeerId) {
    if (!groupStore) return { status: 'unknown', reason: 'not-a-hub' };
    const peerId = String(applicantPeerId ?? '').trim();
    const entry = peerId === '' ? null : groupStore.application(peerId);
    if (!entry) return { status: 'unknown' };
    if (entry.status === 'approved') {
      // 状态是 approved 但成员表里没有（人工改过文件/崩溃残留）：补进去再下发，
      // 否则对方拿着群密钥进来会被判 not-a-member。
      if (!Object.prototype.hasOwnProperty.call(groupMembersMap(), peerId)) {
        groupStore.addMember(peerId, entry.name);
      }
      return { status: 'approved', grant: groupGrant() };
    }
    if (entry.status === 'rejected') return { status: 'rejected' };
    return { status: 'pending' };
  }

  /**
   * 介绍人 → hub：群级鉴权转交（本机就是 hub 时走本地，不发 HTTP）。
   *
   * 这两条路径都是**可重放**的（apply-intake 按 §4.2 幂等、apply-query 是纯读），
   * 所以网络抖动/超时重试一次：忙碌的 hub 不该让成员的申请凭空失败。
   * 带密钥的 401/400 由 withGroupKey 自己换钥重试，这里只管传输层的偶发失败。
   */
  async function callHubGroup(apiPath, body, { attempts = 2, timeoutMs = 8_000 } = {}) {
    const hub = groupHubPeer();
    if (!hub) throw new Error('hub-not-paired');
    const ctx = localGroupContext();
    if (!ctx?.groupKey) throw new Error('group-key-missing');
    let lastError = null;
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      try {
        return await withGroupKey((keyCtx) => groupCall({
          baseUrl: String(hub.baseUrl ?? '').trim().replace(/\/+$/, ''),
          groupKey: keyCtx.groupKey,
          groupId: String(keyCtx.groupId),
          senderId: store.instanceId,
          selfBaseUrl: localAdvertiseBaseUrl(),
          method: 'POST',
          apiPath,
          body,
          timeoutMs,
        }));
      } catch (error) {
        lastError = error;
        const status = Number(error?.status);
        const transient = status >= 500 || !Number.isFinite(status)
          || /timeout|timed out|fetch failed|ECONN|aborted|socket/i.test(String(error?.message ?? ''));
        if (attempt + 1 >= attempts || !transient) throw error;
        await sleep(250);
      }
    }
    throw lastError;
  }

  /** POST /v1/group/advertise —— per-peer；只接受已配对对端（authenticate 就是那道门） */
  function groupAdvertise(req, rawBody) {
    const auth = authenticate(req, rawBody);
    if (!auth.ok) return { status: auth.status, body: { error: auth.error }, peerId: null };
    const body = readPeerJsonBody(rawBody);
    if (!body) return { status: 400, body: { error: 'bad-request' }, peerId: auth.peerId };
    const groupId = String(body.groupId ?? '').trim();
    const name = normalizeGroupName(body.name);
    const hubPeerId = String(body.hub?.peerId ?? '').trim();
    if (groupId === '' || name === '' || hubPeerId === '') {
      return { status: 400, body: { error: 'bad-request' }, peerId: auth.peerId };
    }
    // §9.3：自己的群信息不进 known-groups，别让对端的快照覆盖本机事实
    const own = localGroupContext();
    if (own && String(own.groupId) === groupId) {
      if (config.logger) {
        config.logger(
          '[group] advertise ignored group=' + shortPeerId(groupId)
          + ' from=' + shortPeerId(auth.peerId) + ' reason=own-group',
        );
      }
      return { status: 200, body: { ok: true, ignored: 'own-group' }, peerId: auth.peerId };
    }
    const remembered = rememberKnownGroup({
      stateDir: config.stateDir,
      groupId,
      name,
      hub: {
        peerId: hubPeerId,
        name: String(body.hub?.name ?? ''),
        baseUrl: String(body.hub?.baseUrl ?? ''),
      },
      source: {
        peerId: auth.peerId,
        name: String(auth.peer?.name ?? '') || String(body.member?.name ?? ''),
      },
      now: config.now(),
    });
    if (config.logger) {
      // §9.4：只记 groupId/peerId 前 8 位与状态（群名本身可以记，正文不行）
      config.logger(
        '[group] advertise from=' + shortPeerId(auth.peerId)
        + ' group=' + shortPeerId(groupId)
        + ' name=' + name
        + ' ' + (remembered.created ? 'new' : 'refresh'),
      );
    }
    return { status: 200, body: { ok: true }, peerId: auth.peerId };
  }

  /** POST /v1/group/lookup —— per-peer；§9.2 只回答本机所属群 + 本机 known-groups */
  async function groupLookup(req, rawBody) {
    const auth = authenticate(req, rawBody);
    if (!auth.ok) return { status: auth.status, body: { error: auth.error }, peerId: null };
    const body = readPeerJsonBody(rawBody);
    if (!body) return { status: 400, body: { error: 'bad-request' }, peerId: auth.peerId };
    const wanted = normalizeGroupName(body.name);
    if (wanted === '') return { status: 400, body: { error: 'bad-request' }, peerId: auth.peerId };
    const matches = [];
    const seen = new Set();
    // 群名未知时先向 hub 现取一次（老 group-key.json 没有 groupName）
    const identity = await resolveGroupIdentity();
    if (identity && sameGroupName(identity.name, wanted)) {
      seen.add(identity.groupId);
      matches.push({
        groupId: identity.groupId,
        name: identity.name,
        hub: identity.hub,
        via: { peerId: store.instanceId, name: config.name },
      });
    }
    for (const [groupId, entry] of Object.entries(readKnownGroups(config.stateDir).groups)) {
      if (seen.has(groupId) || !sameGroupName(entry.name, wanted)) continue;
      seen.add(groupId);
      matches.push({
        groupId,
        name: entry.name,
        hub: entry.hub,
        via: {
          peerId: String(entry.source?.peerId ?? '') || store.instanceId,
          name: String(entry.source?.name ?? '') || config.name,
        },
      });
    }
    if (config.logger) {
      config.logger('[group] lookup from=' + shortPeerId(auth.peerId) + ' matches=' + matches.length);
    }
    return { status: 200, body: { matches }, peerId: auth.peerId };
  }

  /** POST /v1/group/apply —— 申请者 → 介绍人；介绍人转交 hub（自己就是 hub 时本地入账） */
  async function groupApply(req, rawBody) {
    const auth = authenticate(req, rawBody);
    if (!auth.ok) return { status: auth.status, body: { error: auth.error }, peerId: null };
    const body = readPeerJsonBody(rawBody);
    if (!body) return { status: 400, body: { error: 'bad-request' }, peerId: auth.peerId };
    const ctx = localGroupContext();
    if (!ctx) return { status: 404, body: { error: 'not-in-group' }, peerId: auth.peerId };
    const groupId = String(body.groupId ?? '').trim();
    // 介绍人只转交自己所属群的申请
    if (groupId !== '' && groupId !== String(ctx.groupId)) {
      return { status: 404, body: { error: 'not-in-group' }, peerId: auth.peerId };
    }
    // 已经是成员也照样转交：介绍人只做「成员/群匹配」两项校验（契约 §4.1），
    // 「是不是已经被踢（blocked）」只有 hub 知道 —— 本机成员表可能是旧的。
    const claimed = String(body.applicant?.peerId ?? '').trim();
    // 只能替自己申请：签名证明的就是 auth.peerId，不替别人背书
    if (claimed !== '' && claimed !== auth.peerId) {
      return { status: 400, body: { error: 'bad-request' }, peerId: auth.peerId };
    }
    const applicant = {
      peerId: auth.peerId,
      name: String(body.applicant?.name ?? '').trim().slice(0, GROUP_NAME_MAX_CHARS)
        || String(auth.peer?.name ?? ''),
      baseUrl: String(body.applicant?.baseUrl ?? '').trim().replace(/\/+$/, '')
        || String(auth.peer?.baseUrl ?? '').trim().replace(/\/+$/, ''),
    };
    const introducer = { peerId: store.instanceId, name: config.name };
    let answer;
    try {
      answer = groupStore
        ? intakeApplication({ applicant, introducer })
        : await callHubGroup('/v1/group/apply-intake', {
          groupId: String(ctx.groupId),
          applicant,
          introducer,
        });
    } catch (error) {
      if (config.logger) {
        config.logger(
          '[group] apply forward failed peer=' + shortPeerId(auth.peerId)
          + ' reason=' + String(error?.message ?? error).slice(0, 60),
        );
      }
      return { status: 502, body: { error: 'hub-unavailable' }, peerId: auth.peerId };
    }
    const out = { status: String(answer?.status ?? 'unknown') };
    if (answer?.reason != null) out.reason = String(answer.reason);
    if (config.logger) {
      config.logger('[group] apply from=' + shortPeerId(auth.peerId) + ' status=' + out.status);
    }
    return { status: 200, body: out, peerId: auth.peerId };
  }

  /** POST /v1/group/apply-status —— 申请者轮询介绍人；approved 时带 grant（per-peer 加密转发） */
  async function groupApplyStatus(req, rawBody) {
    const auth = authenticate(req, rawBody);
    if (!auth.ok) return { status: auth.status, body: { error: auth.error }, peerId: null };
    const body = readPeerJsonBody(rawBody);
    if (!body) return { status: 400, body: { error: 'bad-request' }, peerId: auth.peerId };
    const ctx = localGroupContext();
    if (!ctx) return { status: 404, body: { error: 'not-in-group' }, peerId: auth.peerId };
    const groupId = String(body.groupId ?? '').trim();
    if (groupId !== '' && groupId !== String(ctx.groupId)) {
      return { status: 404, body: { error: 'not-in-group' }, peerId: auth.peerId };
    }
    let answer;
    try {
      answer = groupStore
        ? queryApplication(auth.peerId)
        : await callHubGroup('/v1/group/apply-query', {
          applicantPeerId: auth.peerId,
          groupId: String(ctx.groupId),
        });
    } catch (error) {
      if (config.logger) {
        config.logger(
          '[group] apply-status failed peer=' + shortPeerId(auth.peerId)
          + ' reason=' + String(error?.message ?? error).slice(0, 60),
        );
      }
      return { status: 502, body: { error: 'hub-unavailable' }, peerId: auth.peerId };
    }
    const out = { status: String(answer?.status ?? 'unknown') };
    if (answer?.reason != null) out.reason = String(answer.reason);
    if (answer?.grant && typeof answer.grant === 'object') out.grant = answer.grant;
    if (config.logger) {
      config.logger('[group] apply-status peer=' + shortPeerId(auth.peerId) + ' status=' + out.status);
    }
    return { status: 200, body: out, peerId: auth.peerId };
  }

  /** POST /v1/group/apply-intake —— 群级鉴权，介绍人 → hub（契约 §4.2） */
  function groupApplyIntake(req, rawBody, url, auth) {
    if (!groupStore) return { status: 409, body: { error: 'not-a-hub' }, peerId: auth.peerId };
    const body = readPeerJsonBody(rawBody);
    if (!body) return { status: 400, body: { error: 'bad-request' }, peerId: auth.peerId };
    const groupId = String(body.groupId ?? '').trim();
    if (groupId !== '' && groupId !== String(auth.ctx.groupId)) {
      return { status: 400, body: { error: 'group-mismatch' }, peerId: auth.peerId };
    }
    const out = intakeApplication({ applicant: body.applicant, introducer: body.introducer });
    return {
      status: 200,
      body: out.reason == null ? { status: out.status } : { status: out.status, reason: out.reason },
      peerId: auth.peerId,
    };
  }

  /** POST /v1/group/apply-query —— 群级鉴权，介绍人代申请者查 hub（契约 §5.1） */
  function groupApplyQuery(req, rawBody, url, auth) {
    if (!groupStore) return { status: 409, body: { error: 'not-a-hub' }, peerId: auth.peerId };
    const body = readPeerJsonBody(rawBody);
    if (!body) return { status: 400, body: { error: 'bad-request' }, peerId: auth.peerId };
    const applicantPeerId = String(body.applicantPeerId ?? '').trim();
    if (applicantPeerId === '') {
      return { status: 400, body: { error: 'bad-request' }, peerId: auth.peerId };
    }
    return { status: 200, body: queryApplication(applicantPeerId), peerId: auth.peerId };
  }

  // ---- S1/S2 v0.6.0 成员互访（群级鉴权；hub 与成员都提供） -------------------

  /** 成员自报的可达地址写进群状态（只写它自己那条；hub 侧才有成员表） */
  function rememberMemberBaseUrl(peerId, baseUrl) {
    if (!groupStore) return;
    const id = String(peerId ?? '');
    if (id === '' || id === store.instanceId) return;
    const clean = String(baseUrl ?? '').trim().replace(/\/+$/, '');
    if (!/^https?:\/\//i.test(clean)) return;
    groupStore.setMemberBaseUrl(id, clean);
  }

  /**
   * v0.8.2-α §4：成员自报的接单开关（心跳 body / probe·pull 的 X-Peer-Accept）。
   * hub 侧权威落盘进 group.json.members[].acceptDispatch；值缺失/垃圾一律忽略
   * （「没报」≠「关闭」，也绝不把老对端当成不接单）。
   */
  function rememberMemberAcceptDispatch(peerId, raw) {
    const value = parseAcceptFlag(raw);
    if (value === null) return false;
    const id = String(peerId ?? '');
    if (id === '' || id === store.instanceId) return false;
    if (!groupStore) return false;
    const changed = groupStore.setMemberAcceptDispatch(id, value);
    if (changed && config.logger) {
      config.logger('[group] accept-dispatch from=' + shortPeerId(id) + ' value=' + (value ? 'on' : 'off'));
    }
    return changed;
  }

  /**
   * S2 成员复制进度（内存，不落盘）：peerId -> {lastSeq, at}。
   * 成员在 probe/pull 的 X-Peer-LastSeq 里自报，hub 只用来算「落后 leader 多少条」。
   * 刻意不写 group.json：每 10s 一次 pull 的写放大不值当，重启后重新上报即可。
   */
  const memberProgress = new Map();

  function rememberMemberProgress(peerId, rawLastSeq) {
    if (!groupStore) return;
    const id = String(peerId ?? '');
    if (id === '' || id === store.instanceId) return;
    const raw = String(rawLastSeq ?? '').trim();
    if (raw === '') return;
    const seq = Number(raw);
    if (!Number.isFinite(seq) || seq < 0) return;
    memberProgress.set(id, { lastSeq: Math.floor(seq), at: config.now() });
  }

  /** 把对端补进本机成员表（自愈用）：hub 写 group.json，成员写 group-key.json */
  /** 群密钥世代（hub 读 group.json 的 keyVersion，成员读 group-key.json 的 epoch） */
  function groupKeyVersion() {
    const ctx = localGroupContext();
    return Number(ctx?.epoch) || 0;
  }

  /**
   * 成员侧换钥：hub 轮换 groupKey（例如移除成员）后，老密钥的请求会变成 401 bad-signature。
   * 用 per-peer 签名重取 GET /v1/group/state（响应加密、含 groupKey/keyVersion），
   * 更新本地 group-key.json 后由调用方重试一次。
   */
  let lastKeyRefreshAt = 0;
  /** 在途的换钥请求：并发请求**合并**到同一次刷新上，而不是把后来者判成 throttled */
  let keyRefreshInFlight = null;

  /**
   * 成员侧换钥（对外）。
   *
   * 三态：
   *   1. 有在途刷新 → 等它（同一秒里多个请求同时 401 是常态：一次轮换会让所有在飞的请求
   *      同时坏掉。判成 throttled 会让后来者拿到旧钥重试，然后再失败一次 —— 真机复现为
   *      「移除成员后申请入群 502」）。
   *   2. 已经成功刷新过（<1s）→ throttled（脏请求打不爆 hub）。
   *   3. 其余 → 真的去拉一次 state。
   */
  async function refreshGroupKeyFromHub() {
    if (groupRole !== 'member') return { ok: false, reason: 'not-member' };
    if (keyRefreshInFlight) return keyRefreshInFlight;
    if (config.now() - lastKeyRefreshAt < 1_000) {
      if (config.logger) config.logger('[group] key refresh throttled reason=within-1s');
      return { ok: false, reason: 'throttled' };
    }
    lastKeyRefreshAt = config.now();
    keyRefreshInFlight = refreshGroupKeyNow().finally(() => {
      keyRefreshInFlight = null;
    });
    return keyRefreshInFlight;
  }

  async function refreshGroupKeyNow() {
    const hub = groupHubPeer();
    if (!hub) return { ok: false, reason: 'hub-not-paired' };
    // 只有群密钥的节点（按名入群、没和 hub 配对过）换不了钥：
    // /v1/group/state 走的是 per-peer 签名，需要配对时互换的那把密钥。
    if (!hub.secret) return { ok: false, reason: 'hub-not-paired' };
    try {
      const state = await fetchGroupState({
        baseUrl: hub.baseUrl,
        secret: hub.secret,
        senderId: store.instanceId,
        timeoutMs: 5_000,
      });
      if (!state?.groupId || !state?.groupKey) return { ok: false, reason: 'group-state-incomplete' };
      const existing = readGroupKeyFile(config.stateDir) ?? { members: {} };
      const keyVersion = Number(state.keyVersion) || Number(state.epoch) || 0;
      // v0.8.1：换钥顺带拿到权威成员表 —— 整体替换（并集会让人数虚高、quorum 永不可达）
      const previous = existing.members ?? {};
      const members = {};
      for (const member of Array.isArray(state.members) ? state.members : []) {
        const peerId = String(member?.peerId ?? '');
        if (peerId === '') continue;
        members[peerId] = {
          name: String(member?.name ?? '') || String(previous[peerId]?.name ?? ''),
          baseUrl: String(member?.baseUrl ?? '') || String(previous[peerId]?.baseUrl ?? ''),
          acceptDispatch: member?.acceptDispatch !== false,
        };
      }
      if (Object.keys(members).length === 0) Object.assign(members, previous);
      if (!members[store.instanceId]) members[store.instanceId] = { name: config.name, baseUrl: '' };
      rememberAuthoritativeMembers(Object.keys(members), 'state');
      writeGroupKeyFile(config.stateDir, {
        ...existing,
        groupId: String(state.groupId),
        key: String(state.groupKey),
        // 只增不减：轮换后这里跟着 keyVersion 走，角色初始化再用 max() 兜一次
        keyVersion: Math.max(Number(existing.keyVersion) || 0, keyVersion),
        leaderPeerId: String(existing.leaderPeerId ?? ''),
        name: config.name,
        // 换钥顺带刷新权威群名（hub 改名后成员侧也能跟上）
        groupName: normalizeGroupName(state.name) || normalizeGroupName(existing.groupName),
        // hub 三元组：地址以本次解析到的为准，名字/peerId 保留既有值兜底
        hub: {
          peerId: String(hub.peerId ?? '') || String(existing?.hub?.peerId ?? ''),
          name: String(hub.name ?? '') || String(existing?.hub?.name ?? ''),
          baseUrl: String(hub.baseUrl ?? '').replace(TRAILING_SLASHES, '')
            || String(existing?.hub?.baseUrl ?? ''),
        },
        members,
      });
      replicaStore?.ensureHeader?.({ groupId: String(state.groupId) });
      if (config.logger) config.logger(`[group] key refreshed keyVersion=${keyVersion}`);
      return { ok: true, keyVersion };
    } catch (error) {
      if (config.logger) {
        config.logger(`[group] key refresh failed reason=${String(error?.message ?? error).slice(0, 60)}`);
      }
      return { ok: false, reason: 'refresh-failed' };
    }
  }

  /**
   * 群级请求的统一入口：正常发一次；成员侧遇到 401 bad-signature 就换钥再发**一次**。
   * callFn 拿到的 ctx（groupKey/groupId）在重试时是重新读盘得到的，保证用的是新钥。
   */
  async function withGroupKey(callFn) {
    const ctx = localGroupContext();
    if (!ctx?.groupKey) throw new Error('group-key-missing');
    try {
      return await callFn(ctx);
    } catch (error) {
      const code = String(error?.code ?? '');
      const status = Number(error?.status);
      const retryable = groupRole === 'member'
        && ((status === 401 && code === 'bad-signature')
          || (status === 400 && code === 'bad-encryption'));
      if (!retryable) throw error;
      const refreshed = await refreshGroupKeyFromHub();
      if (refreshed.ok !== true) {
        // 换钥被节流（同一秒内已经刷过一次）：那次刷新很可能已经把新钥落盘了，
        // 只是本进程刚读到的还是旧上下文。重读一次，只有**确实变了**才重试，
        // 否则把原始错误抛出去（不要因为节流把一次正常请求变成 502）。
        if (String(refreshed.reason ?? '') === 'throttled') {
          const reread = localGroupContext();
          if (reread?.groupKey && reread.groupKey !== ctx.groupKey) return callFn(reread);
        }
        throw error;
      }
      const fresh = localGroupContext();
      if (!fresh?.groupKey) throw error;
      return callFn(fresh);
    }
  }

  function upsertGroupMember(peerId) {
    const id = String(peerId ?? '');
    if (id === '') return;
    if (groupStore) {
      groupStore.addMember(id, '');
      return;
    }
    const existing = readGroupKeyFile(config.stateDir);
    if (!existing || existing.members?.[id]) return;
    const members = { ...existing.members, [id]: { name: '', baseUrl: '' } };
    writeGroupKeyFile(config.stateDir, { ...existing, members });
  }

  function groupMemberName(peerId) {
    const ctx = localGroupContext();
    return String(ctx?.members?.[peerId]?.name ?? '') || config.name;
  }

  /**
   * 两条通道都认这四个路径：
   *   1) X-Peer-Auth: group —— 群级签名（成员之间、成员→hub 的复制/补差）；
   *   2) 现有 per-peer 签名 —— CLI 排障用（仍要过成员门控，与 state/history 同口径）。
   */
  /** 领导权协议：允许「成员表未同步」的对端自愈进来（其余路径仍严格按成员表 401） */
  const GROUP_SELF_HEAL_PATHS = new Set(['/v1/group/election', '/v1/group/leader']);

  function authorizeGroupRequest(req, rawBody, url = null) {
    if (headerValue(req, GROUP_AUTH_HEADER.toLowerCase()) === GROUP_AUTH_VALUE) {
      const allowUnknownSender = Boolean(url && GROUP_SELF_HEAL_PATHS.has(url.pathname));
      const checked = verifyGroupAuth(req, rawBody, { allowUnknownSender });
      if (!checked.ok) return checked;
      return { ok: true, mode: 'group', peerId: checked.senderId, ctx: checked.ctx };
    }
    const checked = authenticate(req, rawBody);
    if (!checked.ok) return checked;
    const ctx = localGroupContext();
    if (!ctx) return { ok: false, status: 404, error: 'not-found' };
    if (!Object.prototype.hasOwnProperty.call(ctx.members, checked.peerId)) {
      return { ok: false, status: 403, error: 'not-a-member' };
    }
    return { ok: true, mode: 'peer', peerId: checked.peerId, ctx };
  }

  function groupProbe(req, rawBody, url, auth) {
    const ctx = auth.ctx;
    rememberMemberBaseUrl(auth.peerId, headerValue(req, GROUP_BASE_HEADER.toLowerCase()));
    rememberMemberProgress(auth.peerId, headerValue(req, GROUP_LASTSEQ_HEADER.toLowerCase()));
    rememberMemberAcceptDispatch(auth.peerId, headerValue(req, GROUP_ACCEPT_HEADER.toLowerCase()));
    const advertiseBaseUrl = localAdvertiseBaseUrl();
    if (config.logger) {
      config.logger(
        `[group] probe from=${shortPeerId(auth.peerId)} mode=${auth.mode} lastSeq=${ctx.lastSeq}`,
      );
    }
    return {
      status: 200,
      body: {
        ok: true,
        peerId: store.instanceId,
        name: groupMemberName(store.instanceId),
        groupId: ctx.groupId,
        epoch: ctx.epoch,
        leaderPeerId: ctx.leaderPeerId,
        lastSeq: ctx.lastSeq,
        advertiseBaseUrl,
        // v0.8.2-α §4：本机接单开关（对端据此判断能不能往我这派单）
        acceptDispatch: acceptDispatchNow(),
      },
      peerId: auth.peerId,
    };
  }

  function groupLeader(req, rawBody, url, auth) {
    const ctx = auth.ctx;
    return {
      status: 200,
      body: {
        ok: true,
        groupId: ctx.groupId,
        epoch: ctx.epoch,
        leaderPeerId: ctx.leaderPeerId,
        lastSeq: ctx.lastSeq,
        advertiseBaseUrl: localAdvertiseBaseUrl(),
        acceptDispatch: acceptDispatchNow(),
      },
      peerId: auth.peerId,
    };
  }

  /** v0.8.2-α §4：成员接单开关掩码（自己那一行用本机实时值，其余读成员表） */
  function groupMemberAcceptMask(ctx) {
    const mask = {};
    for (const [peerId, member] of Object.entries(ctx?.members ?? {})) {
      mask[peerId] = peerId === store.instanceId ? acceptDispatchNow() : member?.acceptDispatch !== false;
    }
    return mask;
  }

  function groupPull(req, rawBody, url, auth) {
    const ctx = auth.ctx;
    rememberMemberBaseUrl(auth.peerId, headerValue(req, GROUP_BASE_HEADER.toLowerCase()));
    rememberMemberProgress(auth.peerId, headerValue(req, GROUP_LASTSEQ_HEADER.toLowerCase()));
    // follower 不心跳（心跳只由 leader 发），它唯一的周期自报渠道就是 pull：
    // 接单开关也随这里上报，否则「关掉接单」要等下一次选举才传得到 hub。
    rememberMemberAcceptDispatch(auth.peerId, headerValue(req, GROUP_ACCEPT_HEADER.toLowerCase()));
    const sinceSeq = readGroupSinceSeq(url);
    const limit = readGroupLimit(url);
    // hub 读权威日志，成员读本地副本（成员之间也能互相补差）
    const messages = groupStore
      ? groupStore.messages({ sinceSeq, limit })
      : replicaStore.messages({ sinceSeq, limit });
    if (config.logger) {
      config.logger(
        `[group] pull from=${shortPeerId(auth.peerId)} since=${sinceSeq} n=${messages.length} lastSeq=${ctx.lastSeq}`,
      );
    }
    return {
      status: 200,
      body: {
        ok: true,
        groupId: ctx.groupId,
        epoch: ctx.epoch,
        leaderPeerId: ctx.leaderPeerId,
        lastSeq: ctx.lastSeq,
        messages,
        // 成员靠它把成员表刷新到最新（新成员加进来后不会一直判 not-a-member）
        memberIds: Object.keys(ctx.members),
        memberAcceptDispatch: groupMemberAcceptMask(ctx),
        // v0.8.2-α §4：接单开关随 pull 下发（只多这一张 id→bool 的小表）。
        // 少了它，成员本地表永远停在默认值 true —— 作者侧前置检查读到旧值，
        // 「hub 关单后成员派单」就照常执行（真机现象）。老端忽略该字段。
      },
      peerId: auth.peerId,
    };
  }

  function groupReplicate(req, rawBody, url, auth) {
    // 只有成员接收副本：hub 自己就是 leader，收别人推来的日志等于让日志出现第二作者
    if (!replicaStore || groupStore) {
      return { status: 409, body: { error: 'not-a-replica' }, peerId: auth.peerId };
    }
    let body;
    try {
      body = parseJsonBody(rawBody);
    } catch {
      return { status: 400, body: { error: 'bad-request' }, peerId: auth.peerId };
    }
    const groupId = String(body.groupId ?? '');
    if (groupId !== String(auth.ctx.groupId)) {
      return { status: 409, body: { error: 'group-mismatch' }, peerId: auth.peerId };
    }
    const epoch = Number(body.epoch);
    if (!Number.isFinite(epoch) || epoch < 0) {
      return { status: 400, body: { error: 'bad-request' }, peerId: auth.peerId };
    }
    // H2：副本只接「本机认定的 leader」推来的日志。
    // 少了这道校验，任何握着群密钥的成员都能往别人的副本里写任意历史（第二作者）。
    const recordedLeader = String(
      ensureRole()?.leaderPeerId ?? '',
    ) || String(replicaStore.state().leaderPeerId ?? '');
    if (recordedLeader === '') {
      return { status: 409, body: { error: 'no-leader' }, peerId: auth.peerId };
    }
    if (auth.peerId !== recordedLeader) {
      if (config.logger) {
        config.logger(
          `[group] replicate refused not-leader from=${shortPeerId(auth.peerId)} leader=${shortPeerId(recordedLeader)}`,
        );
      }
      return { status: 409, body: { error: 'not-leader', leaderPeerId: recordedLeader }, peerId: auth.peerId };
    }
    // H2：逐条校验作者在成员表里；不合规的那条丢弃并记一行（不整批拒，避免一条脏数据
    // 把整次复制卡死 —— 复制是 best-effort 的追赶通道，不是权威写路径）
    const knownAuthors = new Set(Object.keys(auth.ctx?.members ?? {}));
    knownAuthors.add(store.instanceId);
    const incoming = Array.isArray(body.messages) ? body.messages : [];
    const messages = [];
    let dropped = 0;
    for (const message of incoming) {
      const author = String(message?.from?.peerId ?? '');
      if (author === '' || !knownAuthors.has(author)) {
        dropped += 1;
        continue;
      }
      messages.push(message);
    }
    if (dropped > 0 && config.logger) {
      config.logger(
        `[group] replicate dropped n=${dropped} from=${shortPeerId(auth.peerId)} reason=unknown-author`,
      );
    }
    const applied = replicaStore.append({
      groupId,
      epoch: Math.floor(epoch),
      leaderPeerId: String(body.leaderPeerId ?? ''),
      messages,
    });
    if (config.logger) {
      config.logger(
        `[group] replicate from=${shortPeerId(auth.peerId)} n=${applied.added} lastSeq=${applied.lastSeq}`,
      );
    }
    return { status: 200, body: { ok: true, lastSeq: applied.lastSeq, added: applied.added }, peerId: auth.peerId };
  }

  // ---- S3 v0.7.0 选举 / 租约 / 两阶段提交（hub 与成员都参与） ----------------

  /** overrides.groupElection 只给测试用：把心跳/超时/抖动压缩到毫秒级 */
  const electionOverrides = overrides.groupElection && typeof overrides.groupElection === 'object'
    ? overrides.groupElection
    : {};
  const heartbeatMs = Number.isFinite(Number(electionOverrides.heartbeatMs))
    ? Math.max(50, Math.floor(Number(electionOverrides.heartbeatMs)))
    : config.group.heartbeatMs;
  /** §2：租约 = 3 × 心跳间隔 */
  const leaseMs = heartbeatMs * GROUP_LEASE_FACTOR;
  const commitTimeoutMs = Number.isFinite(Number(electionOverrides.commitTimeoutMs))
    ? Math.max(50, Math.floor(Number(electionOverrides.commitTimeoutMs)))
    : config.group.commitTimeoutMs;
  const hubPriority = config.group.hubPriority;
  const jitterMaxMs = Number.isFinite(Number(electionOverrides.jitterMs))
    ? Math.max(0, Math.floor(Number(electionOverrides.jitterMs)))
    : Math.min(heartbeatMs, GROUP_ELECTION_JITTER_MS);
  /** 租约检查节奏：远密于心跳，保证「杀 leader ≤10s」在 3s 心跳/9s 租约下仍成立 */
  const roleTickMs = Number.isFinite(Number(electionOverrides.tickMs))
    ? Math.max(20, Math.floor(Number(electionOverrides.tickMs)))
    // 200ms 上限：租约 9s（3×3s）到点后 200ms 内必定被检查到，加抖动仍 < 10s（契约 §9.2）
    : Math.max(50, Math.min(200, Math.round(heartbeatMs / 3)));
  const peerTimeoutMs = Number.isFinite(Number(electionOverrides.peerTimeoutMs))
    ? Math.max(50, Math.floor(Number(electionOverrides.peerTimeoutMs)))
    : Math.min(heartbeatMs, GROUP_S3_PEER_TIMEOUT_MS);
  const quorumMode = config.group.quorum;
  /** §A1：失败选举的指数退避（base × 2^n，上限 60s，0–500ms 抖动） */
  const backoffBaseMs = Number.isFinite(Number(electionOverrides.backoffBaseMs))
    ? Math.max(1, Math.floor(Number(electionOverrides.backoffBaseMs)))
    : GROUP_ELECTION_BACKOFF_BASE_MS;
  const backoffCapMs = Number.isFinite(Number(electionOverrides.backoffCapMs))
    ? Math.max(1, Math.floor(Number(electionOverrides.backoffCapMs)))
    : GROUP_ELECTION_BACKOFF_CAP_MS;
  const backoffJitterMs = Number.isFinite(Number(electionOverrides.backoffJitterMs))
    ? Math.max(0, Math.floor(Number(electionOverrides.backoffJitterMs)))
    : GROUP_ELECTION_BACKOFF_JITTER_MS;
  /** §A1/A4：窗口配额（默认 60s 内最多 2 次失败选举） */
  const failWindowMs = Number.isFinite(Number(electionOverrides.failWindowMs))
    ? Math.max(1, Math.floor(Number(electionOverrides.failWindowMs)))
    : GROUP_ELECTION_FAIL_WINDOW_MS;
  const failWindowMax = Number.isFinite(Number(electionOverrides.failWindowMax))
    ? Math.max(1, Math.floor(Number(electionOverrides.failWindowMax)))
    : GROUP_ELECTION_FAIL_WINDOW_MAX;
  /** §A2：周期优先级纠偏（默认 5 分钟一次，累计最多 5 次） */
  const priorityCorrectionMs = Number.isFinite(Number(electionOverrides.priorityCorrectionMs))
    ? Math.max(1, Math.floor(Number(electionOverrides.priorityCorrectionMs)))
    : GROUP_PRIORITY_CORRECTION_MS;
  const priorityCorrectionMax = Number.isFinite(Number(electionOverrides.priorityCorrectionMax))
    ? Math.max(0, Math.floor(Number(electionOverrides.priorityCorrectionMax)))
    : GROUP_PRIORITY_CORRECTION_MAX;
  /** 启动期一次性接管可以单独关掉（只给测试隔离周期纠偏用） */
  const priorityStartupEnabled = electionOverrides.priorityStartup !== false;

  let roleStore = groupRole === 'off'
    ? null
    : new GroupRoleStore({ stateDir: config.stateDir, now: config.now });
  /** 学到的对端优先级（选举/心跳 body 里带），同 epoch 冲突裁决用（契约 §4） */
  const peerPriorities = new Map();
  /** 学到的对端可达地址（X-Peer-Base / 投票回执），成员侧没有 group.json 时靠它 */
  const peerBaseUrls = new Map();
  /** 成员侧待提交提案（内存；leader 不发 commit 就等于没发生，重启即丢是正确的） */
  const pendingProposals = new Map();
  let electionInFlight = false;
  let roleTimer = null;
  let heartbeatTimer = null;
  let roleSeeded = false;
  /** 本进程启动时刻（受限启动竞选的「稳定期」起点） */
  const processStartedAtMs = config.now();
  /** 契约补充：启动期按优先级接管（每个进程生命周期最多一次） */
  let takeoverAttempted = false;
  let takeoverAttempts = 0;
  const takeoverStableMs = heartbeatMs * 2;
  /** §A2：周期优先级纠偏的计数与节奏 */
  let correctionAttempts = 0;
  let lastCorrectionAtMs = 0;
  /** §A1：失败选举退避状态（连续失败次数 / 退避到期时刻 / 窗口内的失败时刻） */
  let electionFailures = 0;
  let electionBackoffUntilMs = 0;
  let electionFailWindow = [];
  /** 只给门面/测试看的计数 */
  let electionAttempts = 0;
  /** 提交串行化：一次只让一条消息走 propose→commit，seq 才连续、pending 区才不撞号 */
  let postChain = Promise.resolve();

  function roleState() {
    return roleStore ? roleStore.state() : null;
  }

  /**
   * 首次初始化（契约 §1）：hub（不配 group.hub）即初始 leader，延续 S2 的语义；
   * 成员从 follower 起步，leaderPeerId 取 group-key.json 里记的那个（bootstrap 时写入）。
   * 已有 group-role.json 时一律沿用 —— 重启不该把降级过的节点重新抬成 leader。
   */
  function ensureRole() {
    if (!roleStore) return null;
    const st = roleStore.state();
    if (roleSeeded) return st;
    const ctx = localGroupContext();
    // 成员还没 bootstrap（没有群密钥/成员表）时不落盘：等拿到群上下文再定角色，
    // 否则会写下一份「没有 leader」的角色文件，重启后又要靠心跳纠正。
    if (!ctx?.groupKey || String(ctx.groupId ?? '') === '') return st;
    roleSeeded = true;
    const baseEpoch = Math.max(1, Number(ctx?.epoch) || 1, st.epoch);
    const initialLeader = groupRole === 'hub'
      ? store.instanceId
      : String(ctx?.leaderPeerId ?? st.leaderPeerId ?? '');
    if (st.epoch === 0 || st.leaderPeerId === '') {
      return roleStore.update({
        role: initialLeader === store.instanceId ? 'leader' : 'follower',
        epoch: baseEpoch,
        leaderPeerId: initialLeader,
        leaseUntil: config.now() + leaseMs,
        commitSeq: st.commitSeq,
        votedFor: st.votedFor,
        groupId: String(ctx?.groupId ?? st.groupId ?? ''),
      });
    }
    if (st.groupId === '' && ctx?.groupId) {
      return roleStore.update({ groupId: String(ctx.groupId) });
    }
    // 密钥轮换（keyVersion 变大）后角色 epoch 至少跟上：epoch 只升不降，
    // 否则重启后会以更低的 epoch 参与裁决（契约 §4 里 epoch 低就是服从）。
    if (st.epoch < baseEpoch) return roleStore.update({ epoch: baseEpoch });
    return st;
  }

  function isLocalLeader() {
    const st = roleState();
    if (!st) return groupRole === 'hub';
    return st.role === 'leader'
      && st.leaderPeerId === store.instanceId
      && config.now() <= st.leaseUntil;
  }

  /** 契约 §7 的 degraded：没有 leader，或租约已过期 */
  function isDegraded() {
    const st = ensureRole();
    if (!st) return true;
    return st.leaderPeerId === '' || config.now() > st.leaseUntil;
  }

  function groupMemberIds() {
    const ctx = localGroupContext();
    const ids = new Set(Object.keys(ctx?.members ?? {}));
    ids.add(store.instanceId);
    return [...ids];
  }

  function rememberPeerBaseUrl(peerId, baseUrl) {
    const id = String(peerId ?? '');
    const clean = String(baseUrl ?? '').trim().replace(/\/+$/, '');
    if (id === '' || id === store.instanceId) return;
    if (!/^https?:\/\//i.test(clean)) return;
    peerBaseUrls.set(id, clean);
    persistMemberAddress(id, clean);
  }

  /**
   * 成员侧把学到的地址写回 group-key.json（hub 的写路径本来就是 group.json）。
   * 只在值变化时写：心跳每 3s 一次，静默期零写入。
   */
  function persistMemberAddress(peerId, baseUrl) {
    if (groupRole !== 'member') return;
    const existing = readGroupKeyFile(config.stateDir);
    if (!existing) return;
    const current = String(existing.members?.[peerId]?.baseUrl ?? '');
    const selfCurrent = String(existing.members?.[store.instanceId]?.baseUrl ?? '');
    const selfBaseUrl = localAdvertiseBaseUrl();
    if (current === baseUrl && (selfCurrent !== '' || selfBaseUrl === '')) return;
    const members = { ...existing.members };
    members[peerId] = { ...(members[peerId] ?? {}), baseUrl };
    if (selfBaseUrl !== '') members[store.instanceId] = { ...(members[store.instanceId] ?? {}), baseUrl: selfBaseUrl };
    writeGroupKeyFile(config.stateDir, { ...existing, members });
  }

  /**
   * 对端可达地址：学到的 > 群成员表（group.json / group-key.json，读盘即最新）> peers.json。
   * 群成员表必须排在 peers.json 前面：成员节点被 bootstrap 之前，peers.json 里可能是旧地址。
   */
  function baseUrlOf(peerId) {
    const id = String(peerId ?? '');
    if (id === '') return '';
    if (id === store.instanceId) return localAdvertiseBaseUrl();
    // 按名入群：group-key.json 里记的 hub 地址就是权威（成员表可能还没学到）
    if (groupRole === 'member') {
      const keyHub = readGroupKeyFile(config.stateDir)?.hub ?? null;
      const hubUrl = String(keyHub?.baseUrl ?? '').trim().replace(TRAILING_SLASHES, '');
      if (hubUrl !== '' && (String(keyHub?.peerId ?? '') === id || id === '')) return hubUrl;
    }
    // 群成员表优先：它同样是成员自报的地址（hub 写 group.json / 成员写 group-key.json），
    // 但它是**持久化且运维可见可覆盖**的那一份；学到的缓存只做兜底（两者来源相同，顺序不影响线上）。
    const fromGroup = String(localGroupContext()?.members?.[id]?.baseUrl ?? '')
      .trim().replace(/\/+$/, '');
    if (fromGroup !== '') return fromGroup;
    const learned = String(peerBaseUrls.get(id) ?? '').trim().replace(/\/+$/, '');
    if (learned !== '') return learned;
    const recorded = String(groupStore ? groupStore.state().members[id]?.baseUrl ?? '' : '')
      .trim().replace(/\/+$/, '');
    if (recorded !== '') return recorded;
    const peer = store.getPeer(id);
    return String(peer?.baseUrl ?? '').trim().replace(/\/+$/, '');
  }

  /**
   * 成员**自报**过的地址（不是 peers.json 里配对时那条）：只有它才算「群成员真的在网络上」。
   * hub 记在 group.json 的 members[].baseUrl，成员记在 group-key.json / 本进程学到的表里。
   */
  function knownMemberAddress(peerId) {
    const id = String(peerId ?? '');
    if (id === '' || id === store.instanceId) return '';
    const learned = String(peerBaseUrls.get(id) ?? '').trim().replace(/\/+$/, '');
    if (learned !== '') return learned;
    const ctx = localGroupContext();
    return String(ctx?.members?.[id]?.baseUrl ?? '').trim().replace(/\/+$/, '');
  }

  /** 心跳/选举的目标：除自己以外、地址已知（含 peers.json 兜底）的成员 */
  function peerTargets() {
    return groupMemberIds().filter((id) => id !== store.instanceId && baseUrlOf(id) !== '');
  }

  /**
   * 承诺集合 = **成员表全集**（含自己，去重）。
   * 分母绝不能按「知道地址」过滤：那会让刚启动/还没学到地址的节点把分母压到 1，
   * 于是自投即当选（2026-10-27 真机事故：桌面节点在两节点群里 epoch=2 自立为 leader）。
   * 地址只决定「提案/拉票发给谁」，不决定多数派的分母（契约 §3：N = 成员总数含自己）。
   */
  /**
   * 最近一次**权威**成员快照（v0.8.1）：hub 的 state/pull/grant 说了算。
   * quorum 分母必须用它，而不是「本机表 ∪ 自愈补进来的」那份 —— 后者正是真机上
   * 「移除的人还在表里 → 分母虚高 → 成员当 leader 永远选不出」的来源。
   */
  let authoritativeMemberIds = new Set();
  let lastAuthoritativeAt = 0;
  let lastQuorumLogKey = '';

  function rememberAuthoritativeMembers(ids, source = 'state') {
    const next = new Set();
    for (const raw of Array.isArray(ids) ? ids : []) {
      const id = String(raw ?? '');
      if (id !== '') next.add(id);
    }
    next.add(store.instanceId);
    const changed = next.size !== authoritativeMemberIds.size
      || [...next].some((id) => !authoritativeMemberIds.has(id));
    authoritativeMemberIds = next;
    lastAuthoritativeAt = config.now();
    if (changed && config.logger) {
      config.logger(
        '[group] members authoritative n=' + next.size + ' source=' + source,
      );
    }
    logQuorumIfChanged();
    return next;
  }

  /** quorum 分母的来源：hub 的 group.json 恒权威；成员用最近一次权威快照；都没有才退回本机表 */
  function quorumSnapshot() {
    if (groupStore) {
      const ids = new Set(Object.keys(groupStore.state().members));
      ids.add(store.instanceId);
      return { ids, source: 'authoritative' };
    }
    if (authoritativeMemberIds.size > 0) {
      return { ids: new Set(authoritativeMemberIds), source: 'authoritative' };
    }
    const ids = new Set(groupMemberIds());
    ids.add(store.instanceId);
    return { ids, source: 'stale' };
  }

  function quorumMembers() {
    return [...quorumSnapshot().ids];
  }

  /** 只在数量/门槛/来源变化时打一行（心跳 3s 一次，不能刷屏） */
  function logQuorumIfChanged() {
    if (!config.logger) return;
    const snapshot = quorumSnapshot();
    const need = quorumSize(snapshot.ids.size, quorumMode);
    const key = snapshot.ids.size + ':' + need + ':' + snapshot.source;
    if (key === lastQuorumLogKey) return;
    lastQuorumLogKey = key;
    config.logger(
      '[group] quorum members=' + snapshot.ids.size + ' need=' + need + ' source=' + snapshot.source,
    );
  }

  /** 提案目标 = 除自己以外、地址已知（含 peers.json 兜底）的成员；地址缺失只影响投递 */
  function proposeTargets() {
    return peerTargets();
  }

  /** 契约 §3：majority = floor(N/2)+1（N 含自己），none = 1 */
  function quorumNeeded() {
    return quorumSize(quorumMembers().length, quorumMode);
  }

  function priorityOf(peerId) {
    const id = String(peerId ?? '');
    if (id === store.instanceId) return hubPriority;
    const known = peerPriorities.get(id);
    return Number.isFinite(known) ? known : GROUP_DEFAULT_HUB_PRIORITY;
  }

  /** 契约 §4：数值小的优先级高；同优先级按 peerId 字典序 */
  function leaderWins(challenger, incumbent) {
    const left = Number.isFinite(challenger?.priority) ? challenger.priority : GROUP_DEFAULT_HUB_PRIORITY;
    const right = Number.isFinite(incumbent?.priority) ? incumbent.priority : GROUP_DEFAULT_HUB_PRIORITY;
    if (left !== right) return left < right;
    return String(challenger?.peerId ?? '') < String(incumbent?.peerId ?? '');
  }

  /** 权威日志：hub 读 group.json，成员（含当 leader 的成员）读本地副本 */
  function ledgerLastSeq() {
    if (groupStore) return groupStore.state().lastSeq;
    return replicaStore ? replicaStore.state().lastSeq : 0;
  }

  function pendingCount() {
    return groupStore ? groupStore.pendingCount() : pendingProposals.size;
  }

  function buildGroupMessage({ seq, peerId, name, kind, text = '', meta = {} }) {
    return {
      seq: Math.max(1, Math.floor(Number(seq) || 1)),
      ts: config.now(),
      from: { peerId: String(peerId ?? ''), name: String(name ?? '') },
      kind: String(kind ?? 'chat'),
      text: String(text ?? ''),
      meta: sanitizeGroupMeta(meta),
    };
  }

  /** 只保留契约字段：propose/commit 来的正文一律过一遍，防止夹带 */
  function normalizeIncomingMessage(message, seq) {
    const ts = Number(message?.ts);
    return {
      seq: Math.max(1, Math.floor(Number(seq) || 0)),
      ts: Number.isFinite(ts) && ts > 0 ? Math.floor(ts) : config.now(),
      from: {
        peerId: String(message?.from?.peerId ?? ''),
        name: String(message?.from?.name ?? ''),
      },
      kind: String(message?.kind ?? 'chat'),
      text: String(message?.text ?? ''),
      meta: sanitizeGroupMeta(message?.meta),
    };
  }

  function prunePendingProposals() {
    const staleAfter = config.now() - Math.max(commitTimeoutMs * 3, 10_000);
    for (const [seq, entry] of pendingProposals) {
      if (Number(entry?.at ?? 0) < staleAfter) pendingProposals.delete(seq);
    }
    while (pendingProposals.size > GROUP_PENDING_MAX) {
      const oldest = pendingProposals.keys().next();
      if (oldest.done) break;
      pendingProposals.delete(oldest.value);
    }
  }

  /** quorum:none 的直接提交（可用性优先）：hub 进 group.json，成员 leader 进本地副本 */
  function ledgerAppend(input) {
    if (groupStore) return groupStore.append(input);
    const ctx = localGroupContext();
    const seq = ledgerLastSeq() + 1;
    const message = buildGroupMessage({ seq, ...input });
    replicaStore.append({
      groupId: String(ctx?.groupId ?? ''),
      epoch: roleState()?.epoch ?? 0,
      leaderPeerId: store.instanceId,
      messages: [message],
    });
    return message;
  }

  function stagePending(input) {
    if (groupStore) return groupStore.stagePending(input);
    const seq = ledgerLastSeq() + 1;
    const message = buildGroupMessage({ seq, ...input });
    pendingProposals.set(seq, { message, at: config.now() });
    prunePendingProposals();
    return message;
  }

  function commitStaged(message) {
    if (groupStore) return groupStore.commitMessage(message);
    pendingProposals.delete(message.seq);
    const ctx = localGroupContext();
    replicaStore.append({
      groupId: String(ctx?.groupId ?? ''),
      epoch: roleState()?.epoch ?? 0,
      leaderPeerId: store.instanceId,
      messages: [message],
    });
    return message;
  }

  function dropStaged(seq) {
    if (groupStore) return groupStore.dropPending(seq);
    return pendingProposals.delete(seq);
  }

  /** 收下一条已提交消息（commit 广播 / 本机自己 commit 后转正） */
  function applyCommitted(message) {
    const value = normalizeIncomingMessage(message, message?.seq);
    if (groupStore) return Boolean(groupStore.commitMessage(value));
    const ctx = localGroupContext();
    const applied = replicaStore.append({
      groupId: String(ctx?.groupId ?? ''),
      epoch: roleState()?.epoch ?? 0,
      leaderPeerId: roleState()?.leaderPeerId ?? '',
      messages: [value],
    });
    return applied.added > 0;
  }

  async function settleWithin(tasks, ms) {
    if (tasks.length === 0) return [];
    let timer = null;
    const timeout = new Promise((resolve) => {
      timer = setTimeout(() => resolve(null), Math.max(1, Math.floor(ms)));
      timer.unref?.();
    });
    const result = await Promise.race([Promise.all(tasks), timeout]);
    if (timer) clearTimeout(timer);
    return Array.isArray(result) ? result : [];
  }

  /** 心跳：续租约 + 广播；对端说「你非法」就降级，说「我 epoch 更高」就服从 */
  async function broadcastHeartbeat() {
    const st = ensureRole();
    if (!st || st.role !== 'leader') return { ok: false, reason: 'not-leader' };
    const ctx = localGroupContext();
    if (!ctx?.groupKey || String(ctx.groupId ?? '') === '') return { ok: false, reason: 'no-group-key' };
    const nowMs = config.now();
    const renewed = roleStore.update({ leaseUntil: nowMs + leaseMs });
    const lastSeq = ledgerLastSeq();
    const targets = peerTargets();
    const base = {
      groupKey: ctx.groupKey,
      groupId: String(ctx.groupId),
      senderId: store.instanceId,
      epoch: renewed.epoch,
      leaderPeerId: store.instanceId,
      lastSeq,
      commitSeq: renewed.commitSeq,
      priority: hubPriority,
      selfBaseUrl: localAdvertiseBaseUrl(),
      // v0.8.2-α §4：接单开关随心跳自报
      acceptDispatch: acceptDispatchNow(),
      timeoutMs: peerTimeoutMs,
    };
    const results = await Promise.allSettled(targets.map((peerId) => withGroupKey((keyCtx) => sendGroupHeartbeat({
      ...base,
      groupKey: keyCtx.groupKey,
      groupId: String(keyCtx.groupId),
      baseUrl: baseUrlOf(peerId),
    }))));
    let conflictWith = '';
    let ahead = null;
    for (const result of results) {
      if (result.status !== 'rejected') continue;
      const body = result.reason?.body;
      const code = String(body?.error ?? '');
      if (code === 'leader-conflict') conflictWith = String(body?.leaderPeerId ?? '');
      else if (code === 'stale-epoch') ahead = body;
    }
    if (ahead) {
      acceptLeader({
        epoch: Number(ahead.epoch) || renewed.epoch,
        leaderPeerId: String(ahead.leaderPeerId ?? ''),
        commitSeq: Number(ahead.commitSeq) || 0,
      });
      if (config.logger) {
        config.logger(`[group] heartbeat superseded epoch=${Number(ahead.epoch) || renewed.epoch} role=follower`);
      }
      return { ok: false, reason: 'stale-epoch' };
    }
    if (conflictWith !== '') {
      roleStore.update({ role: 'follower', leaseUntil: config.now() + leaseMs });
      if (config.logger) {
        config.logger(`[group] heartbeat conflict epoch=${renewed.epoch} winner=${shortPeerId(conflictWith)} role=follower`);
      }
      return { ok: false, reason: 'leader-conflict' };
    }
    const okCount = results.filter((entry) => entry.status === 'fulfilled').length;
    if (config.logger) {
      config.logger(
        `[group] heartbeat epoch=${renewed.epoch} commitSeq=${renewed.commitSeq} lastSeq=${lastSeq} n=${okCount}/${targets.length}`,
      );
    }
    return { ok: true, epoch: renewed.epoch, commitSeq: renewed.commitSeq, delivered: okCount };
  }

  async function broadcastCommit(epoch, seq, message) {
    const ctx = localGroupContext();
    if (!ctx?.groupKey) return { ok: false, reason: 'no-group-key' };
    const base = {
      groupKey: ctx.groupKey,
      groupId: String(ctx.groupId),
      senderId: store.instanceId,
      epoch,
      seq,
      message,
      selfBaseUrl: localAdvertiseBaseUrl(),
      timeoutMs: peerTimeoutMs,
    };
    const targets = peerTargets();
    const results = await Promise.allSettled(targets.map((peerId) => withGroupKey((keyCtx) => commitGroupMessage({
      ...base,
      groupKey: keyCtx.groupKey,
      groupId: String(keyCtx.groupId),
      baseUrl: baseUrlOf(peerId),
    }))));
    return { ok: true, delivered: results.filter((entry) => entry.status === 'fulfilled').length, total: targets.length };
  }

  /** §A3：单次 epoch 涨幅过大就记一行告警（真机事故 epoch 5→500 毫无痕迹） */
  function noteEpochJump(fromEpoch, toEpoch, reason) {
    const from = Math.max(0, Math.floor(Number(fromEpoch) || 0));
    const to = Math.max(0, Math.floor(Number(toEpoch) || 0));
    if (to - from <= GROUP_EPOCH_JUMP_THRESHOLD) return;
    if (config.logger) {
      config.logger(`[group] epoch jump suspicious from=${from} to=${to} reason=${String(reason)}`);
    }
  }

  /** §A1 退出条件：收到更高 epoch 的心跳 / 自己成为 leader / 租约重新有效 → 退避清零 */
  function resetElectionBackoff() {
    if (electionFailures === 0 && electionBackoffUntilMs === 0 && electionFailWindow.length === 0) return;
    electionFailures = 0;
    electionBackoffUntilMs = 0;
    electionFailWindow = [];
  }

  /**
   * §A1：失败选举退避闸门，返回「下一次允许发起选举的时刻」。
   * 两道闸取较晚者：① 指数退避（base × 2^n，上限 60s，加抖动）；② 窗口配额（默认 60s 内最多 2 次）。
   */
  function electionAllowedAt() {
    const nowMs = config.now();
    while (electionFailWindow.length > 0 && nowMs - electionFailWindow[0] >= failWindowMs) electionFailWindow.shift();
    let until = electionBackoffUntilMs;
    if (electionFailWindow.length >= failWindowMax) {
      until = Math.max(until, electionFailWindow[0] + failWindowMs);
    }
    return until;
  }

  /** 记一次失败选举：指数退避 + 窗口计数（真机事故的根因：失败一次 +1 epoch 且立刻重来） */
  function noteElectionFailure(reason) {
    electionFailures += 1;
    const nowMs = config.now();
    const wait = Math.min(backoffCapMs, backoffBaseMs * 2 ** (electionFailures - 1))
      + (backoffJitterMs > 0 ? Math.floor(Math.random() * backoffJitterMs) : 0);
    electionBackoffUntilMs = nowMs + wait;
    electionFailWindow.push(nowMs);
    if (config.logger) {
      config.logger(`[group] election backoff failures=${electionFailures} retryIn=${wait}ms reason=${String(reason)}`);
    }
  }

  /** 接受/服从一个 leader（契约 §4：epoch 更高一律服从；同 epoch 已由调用方裁决） */
  function acceptLeader({ epoch, leaderPeerId, commitSeq }) {
    const st = ensureRole();
    const nowMs = config.now();
    const nextEpoch = Math.max(st.epoch, Math.floor(Number(epoch) || 0));
    noteEpochJump(st.epoch, nextEpoch, 'heartbeat');
    // 跟上了合法 leader（租约被续）= §A1 的退出条件之一
    resetElectionBackoff();
    const isSelf = String(leaderPeerId) === store.instanceId;
    const next = roleStore.update({
      role: isSelf ? 'leader' : 'follower',
      epoch: nextEpoch,
      leaderPeerId: String(leaderPeerId ?? ''),
      leaseUntil: nowMs + leaseMs,
      commitSeq: Math.max(st.commitSeq, Math.floor(Number(commitSeq) || 0)),
      votedFor: st.votedFor,
      groupId: st.groupId,
    });
    return next;
  }

  /**
   * 契约 §3：拉票。票数 ≥ quorum 才成为 leader；落败回到 follower 并更新 epoch，
   * 同时把租约推后一个窗口，避免多台机器在同一个瞬间反复抢票。
   */
  async function runElection({ reason = 'lease-expired', forcedEpoch = null, force = false } = {}) {
    if (!roleStore) return { ok: false, reason: 'group-disabled' };
    if (electionInFlight) return { ok: false, reason: 'election-in-flight' };
    // §A1：退避期内不起新选举。运维显式 claim / 接管（force）不受闸门限制。
    if (!force) {
      const until = electionAllowedAt();
      if (config.now() < until) {
        return { ok: false, reason: 'election-backoff', retryAt: until, backoffMs: until - config.now() };
      }
    }
    electionInFlight = true;
    electionAttempts += 1;
    try {
      // 契约 §2 的 0–500ms 抖动必须在「宣布候选」之前：先抖再抢，
      // 否则两台会在同一个 epoch 里各投自己一票，谁都过不了半（真实集群里表现为多绕一轮）。
      if (jitterMaxMs > 0) await sleep(Math.floor(Math.random() * jitterMaxMs));
      const st = ensureRole();
      const epoch = Math.max(1, Math.floor(Number(forcedEpoch) || 0), st.epoch + 1);
      roleStore.update({
        role: 'candidate',
        epoch,
        leaderPeerId: '',
        leaseUntil: 0,
        votedFor: { epoch, peerId: store.instanceId },
        commitSeq: st.commitSeq,
        groupId: st.groupId,
      });
      const ctx = localGroupContext();
      if (!ctx?.groupKey || String(ctx.groupId ?? '') === '') {
        roleStore.update({ role: 'follower', epoch, leaseUntil: config.now() + leaseMs });
        noteElectionFailure('no-group-key');
        return { ok: false, reason: 'no-group-key' };
      }
      const targets = peerTargets();
      // 成员表里有、但地址未知/不可达的成员：它们不可能投票，票数自然不足
      const unreachableBase = Math.max(0, quorumMembers().length - 1 - targets.length);
      let votes = 1;
      let ahead = null;
      let unreachable = unreachableBase;
      const tasks = targets.map(async (peerId) => {
        try {
          const reply = await withGroupKey((keyCtx) => requestGroupVote({
            baseUrl: baseUrlOf(peerId),
            groupKey: keyCtx.groupKey,
            groupId: String(keyCtx.groupId),
            senderId: store.instanceId,
            epoch,
            candidate: store.instanceId,
            priority: hubPriority,
            selfBaseUrl: localAdvertiseBaseUrl(),
            acceptDispatch: acceptDispatchNow(),
            timeoutMs: peerTimeoutMs,
          }));
          if (Number(reply?.epoch) > epoch && String(reply?.leaderPeerId ?? '') !== '') ahead = reply;
          if (typeof reply?.advertiseBaseUrl === 'string') rememberPeerBaseUrl(peerId, reply.advertiseBaseUrl);
          return reply?.vote === true;
        } catch (error) {
          const body = error?.body;
          if (Number(body?.epoch) > epoch) ahead = body;
          // 不可达成员只计数（lost 那行日志里有 unreachable=N），不逐条刷日志
          unreachable += 1;
          return false;
        }
      });
      const granted = await settleWithin(tasks, Math.max(peerTimeoutMs * 2, 500));
      votes += granted.filter(Boolean).length;
      const needed = quorumNeeded();
      if (ahead) {
        acceptLeader({
          epoch: Number(ahead.epoch) || epoch,
          leaderPeerId: String(ahead.leaderPeerId ?? ''),
          commitSeq: Number(ahead.commitSeq) || 0,
        });
        if (config.logger) config.logger(`[group] election abandon epoch=${epoch} reason=higher-epoch`);
        // 已经服从了更高的 epoch：跟上了合法 leader，退避清零（不是「失败」）
        resetElectionBackoff();
        return { ok: false, reason: 'higher-epoch', epoch: Number(ahead.epoch) || epoch };
      }
      if (votes >= needed) {
        const won = roleStore.update({
          role: 'leader',
          epoch,
          leaderPeerId: store.instanceId,
          leaseUntil: config.now() + leaseMs,
          votedFor: { epoch, peerId: store.instanceId },
          groupId: String(ctx.groupId),
        });
        noteEpochJump(st.epoch, won.epoch, 'election');
        // 自己当上 leader = §A1 的退出条件
        resetElectionBackoff();
        if (config.logger) {
          config.logger(`[group] election won epoch=${epoch} votes=${votes}/${needed} reason=${reason}`);
        }
        void broadcastHeartbeat().catch(() => {});
        return { ok: true, role: 'leader', epoch: won.epoch, votes, needed };
      }
      roleStore.update({
        role: 'follower',
        epoch,
        // 这一轮没人过半：撤掉自投票，别让「废票」把同一个 epoch 里的后续拉票也堵死
        // （契约 §3 的「未投过别人」保护的是真投出去的票，轮次作废即撤回）。
        votedFor: null,
        // 重试窗口带抖动：两台落败者不会在同一毫秒又同时宣布候选
        leaseUntil: config.now() + leaseMs + Math.floor(Math.random() * leaseMs),
      });
      noteElectionFailure(reason);
      if (config.logger) {
        config.logger(
          `[group] election lost epoch=${epoch} votes=${votes}/${needed} unreachable=${unreachable} reason=${reason}`,
        );
      }
      return { ok: false, reason: 'quorum-unavailable', epoch, votes, needed, unreachable };
    } finally {
      electionInFlight = false;
    }
  }

  /**
   * §A2 的公共前置条件：配置上是 hub（无 group.hub）、本机是 follower、当前有一个租约有效的
   * leader、且 leader 的 priority **严格**更大（数值更大 = 优先级更低），才轮到「按优先级夺权」。
   * 相等一律不动（避免同优先级互抢）。
   */
  function priorityTakeoverEligibility() {
    if (!roleStore) return { ok: false, reason: 'group-disabled' };
    if (String(config.group.hub ?? '') !== '') return { ok: false, reason: 'member-role' };
    const st = ensureRole();
    if (!st || st.role !== 'follower') return { ok: false, reason: 'not-follower' };
    // 只在「跟得好好的」时候动手：没有 leader 或租约已过期，交给正常的 lease-expired 选举
    if (st.leaderPeerId === '' || config.now() > st.leaseUntil) {
      return { ok: false, reason: 'no-stable-leader' };
    }
    if (config.now() - processStartedAtMs < takeoverStableMs) {
      return { ok: false, reason: 'not-stable-yet' };
    }
    const leaderPriority = priorityOf(st.leaderPeerId);
    if (!(hubPriority < leaderPriority)) return { ok: false, reason: 'not-higher-priority' };
    return { ok: true, st, leaderPriority };
  }

  /**
   * 受限的「启动后按优先级接管」（每进程最多一次）。
   *
   * 背景：契约 §4 是「epoch 高者胜，同 epoch 才比 priority」，所以优先级**不能跨 epoch** 夺权。
   * 真机事故形态：优先节点（NAS，hubPriority=0）重启期间备份节点抢到 epoch=4 当了 leader，
   * NAS 回来只能一直当 follower —— priority 永远等不到生效的机会。
   *
   * 因此给「配置上没有 group.hub 的本机」（即配置上的 hub）一次**有边界**的重试权：
   * 进程启动稳定 2×heartbeatMs、当前有一个租约有效的 leader、且本机优先级严格更高时，
   * 发起一次 epoch+1 的选举。赢则收回 leadership，输则本进程内永久放弃（不循环重试）。
   * 成员节点（配了 group.hub）不参与：运维的接线意图是「以 hub 为准」。
   */
  async function maybePriorityTakeover() {
    if (!priorityStartupEnabled) return { attempted: false, reason: 'startup-takeover-off' };
    if (!roleStore || takeoverAttempted) return { attempted: false, reason: 'already-done-or-off' };
    const gate = priorityTakeoverEligibility();
    if (!gate.ok) return { attempted: false, reason: gate.reason };
    const st = gate.st;
    const leaderPriority = gate.leaderPriority;
    takeoverAttempted = true;
    takeoverAttempts += 1;
    const epoch = st.epoch + 1;
    if (config.logger) {
      config.logger(`[group] takeover attempt epoch=${epoch} priority=${hubPriority} leaderPriority=${leaderPriority}`);
    }
    const out = await runElection({ reason: 'priority-takeover', forcedEpoch: epoch });
    if (config.logger) {
      if (out?.ok === true) {
        config.logger(`[group] takeover won epoch=${out.epoch} votes=${out.votes}/${out.needed}`);
      } else {
        config.logger(
          `[group] takeover lost epoch=${out?.epoch ?? epoch} votes=${out?.votes ?? 1}/${out?.needed ?? quorumNeeded()}`
            + ` reason=${out?.reason ?? 'unknown'}`,
        );
      }
    }
    return { attempted: true, result: out };
  }

  /**
   * §A2：**周期性**优先级纠偏。
   *
   * 背景（真机）：NAS（hubPriority=0）离线期间备份节点抢到高 epoch 当 leader；NAS 回来只能当
   * follower，而启动期一次性接管早在进程启动 2×heartbeat 内就用掉了 —— 之后没有任何机会把
   * leadership 收回来。「epoch 高者胜」这条裁决规则本身不改，改为周期性检查：
   * 每 priorityCorrectionMs（默认 5 分钟）最多尝试一次 epoch+1 的选举；累计 priorityCorrectionMax
   * 次（默认 5）后彻底放弃，避免两台机器互相夺权形成循环。
   */
  async function maybePeriodicPriorityTakeover() {
    if (priorityCorrectionMax === 0) return { attempted: false, reason: 'correction-off' };
    if (correctionAttempts >= priorityCorrectionMax) return { attempted: false, reason: 'correction-exhausted' };
    const nowMs = config.now();
    // 第一次不设冷却（等价于「启动稳定期之后随时可纠偏一次」）
    if (lastCorrectionAtMs !== 0 && nowMs - lastCorrectionAtMs < priorityCorrectionMs) {
      return { attempted: false, reason: 'correction-cooldown' };
    }
    const gate = priorityTakeoverEligibility();
    if (!gate.ok) return { attempted: false, reason: gate.reason };
    const epoch = gate.st.epoch + 1;
    lastCorrectionAtMs = nowMs;
    correctionAttempts += 1;
    if (config.logger) {
      config.logger(
        `[group] takeover periodic attempt epoch=${epoch} priority=${hubPriority}`
          + ` leaderPriority=${gate.leaderPriority} n=${correctionAttempts}/${priorityCorrectionMax}`,
      );
    }
    const out = await runElection({ reason: 'priority-correction', forcedEpoch: epoch, force: true });
    if (config.logger) {
      if (out?.ok === true) {
        config.logger(`[group] takeover periodic won epoch=${out.epoch} votes=${out.votes}/${out.needed}`);
      } else {
        config.logger(
          `[group] takeover periodic lost epoch=${out?.epoch ?? epoch} votes=${out?.votes ?? 1}/${out?.needed ?? quorumNeeded()}`
            + ` reason=${out?.reason ?? 'unknown'}`,
        );
      }
    }
    return { attempted: true, result: out };
  }

  /** 租约检查：非 leader 且租约过期 → 进入候选并发起选举（抖动在 runElection 里） */
  async function roleTick() {
    // 每轮顺手对一下 quorum 口径（只在实际变化时打一行，心跳 3s 一次也不刷屏）
    logQuorumIfChanged();
    const st = ensureRole();
    if (!st || st.role === 'leader') return { ok: false, reason: 'leader-or-off' };
    if (electionInFlight) return { ok: false, reason: 'election-in-flight' };
    // ① 受限的启动竞选（每进程最多一次；不满足条件时什么也不做）
    const takeover = await maybePriorityTakeover();
    if (takeover.attempted) return takeover.result ?? { ok: false, reason: 'takeover-attempted' };
    // ② §A2 周期优先级纠偏（每 priorityCorrectionMs 最多一次，有累计上限）
    const correction = await maybePeriodicPriorityTakeover();
    if (correction.attempted) return correction.result ?? { ok: false, reason: 'correction-attempted' };
    // ③ 租约过期 → 正常选举；§A1 的退避期里不起新选举
    if (config.now() <= st.leaseUntil) return { ok: false, reason: 'lease-valid' };
    const until = electionAllowedAt();
    if (config.now() < until) {
      return { ok: false, reason: 'election-backoff', retryAt: until, backoffMs: until - config.now() };
    }
    if (peerTargets().length === 0) return { ok: false, reason: 'no-peers-with-address' };
    return runElection({ reason: 'lease-expired' });
  }

  async function heartbeatTick() {
    const st = ensureRole();
    if (!st || st.role !== 'leader') return { ok: false, reason: 'not-leader' };
    return broadcastHeartbeat();
  }

  function startRoleTimers() {
    if (!roleStore) return;
    ensureRole();
    if (!heartbeatTimer) {
      heartbeatTimer = setInterval(() => {
        void heartbeatTick().catch(() => {});
      }, heartbeatMs);
      heartbeatTimer.unref?.();
    }
    if (!roleTimer) {
      roleTimer = setInterval(() => {
        void roleTick().catch(() => {});
      }, roleTickMs);
      roleTimer.unref?.();
    }
  }

  function stopRoleTimers() {
    if (heartbeatTimer) {
      clearInterval(heartbeatTimer);
      heartbeatTimer = null;
    }
    if (roleTimer) {
      clearInterval(roleTimer);
      roleTimer = null;
    }
  }

  /** 契约 §3：投票三个条件都要满足，否则 {vote:false, reason} */
  function voteDecision({ epoch, candidate, priority, st }) {
    const ctx = localGroupContext();
    const members = ctx?.members ?? {};
    if (!Object.prototype.hasOwnProperty.call(members, candidate)) {
      return { vote: false, reason: 'unknown-candidate' };
    }
    if (epoch < st.epoch) return { vote: false, reason: 'stale-epoch' };
    if (epoch === st.epoch) {
      const incumbent = st.leaderPeerId !== '' && st.leaderPeerId !== candidate
        ? { peerId: st.leaderPeerId, priority: priorityOf(st.leaderPeerId) }
        : null;
      if (incumbent && !leaderWins({ peerId: candidate, priority }, incumbent)) {
        return { vote: false, reason: 'lower-priority' };
      }
    }
    if (st.votedFor && st.votedFor.epoch === epoch && st.votedFor.peerId !== candidate) {
      // 投给别人之后就锁死（不双投）；但「自己那一票」可以改投给同 epoch 里
      // 按 §4 裁决顺序更合法的候选 —— 否则两台同时宣布候选会把同一个 epoch 卡死。
      const canSwitch = st.votedFor.peerId === store.instanceId
        && leaderWins(
          { peerId: candidate, priority },
          { peerId: store.instanceId, priority: hubPriority },
        );
      if (!canSwitch) return { vote: false, reason: 'already-voted' };
    }
    return { vote: true };
  }
  // ---- S3 端点：心跳 / 拉票 / 提案 / 提交 / 角色查询（全部群级鉴权） ----------

  function parseS3Body(rawBody) {
    try {
      const body = parseJsonBody(rawBody);
      return body && typeof body === 'object' && !Array.isArray(body) ? body : null;
    } catch {
      return null;
    }
  }

  /** GET /v1/group/lease —— 只读角色快照（排障/CLI 用；不含密钥、不含正文） */
  function groupLease(req, rawBody, url, auth) {
    const st = ensureRole();
    return {
      status: 200,
      body: {
        ok: true,
        peerId: store.instanceId,
        role: st.role,
        epoch: st.epoch,
        leaderPeerId: st.leaderPeerId,
        leaseUntil: st.leaseUntil,
        commitSeq: st.commitSeq,
        pendingCount: pendingCount(),
        quorum: quorumMode,
        // 分母与门槛：成员表全集（含没有地址的成员），地址只影响投递
        memberCount: quorumMembers().length,
        quorumNeeded: quorumNeeded(),
        // 群密钥世代（只给世代，不给密钥）：轮换后可从这里看出来
        keyVersion: groupKeyVersion(),
        degraded: isDegraded(),
        advertiseBaseUrl: localAdvertiseBaseUrl(),
        // v0.8.2-α §4：本机接单开关（排障用，与心跳/probe 同一口径）
        acceptDispatch: acceptDispatchNow(),
      },
      peerId: auth.peerId,
    };
  }

  /**
   * POST /v1/group/leader —— 心跳（与 GET 同路径：GET 查询 / POST 心跳）。
   * epoch 更低 → 409 stale-epoch；同 epoch 但合法 leader 是别人 → 409 leader-conflict。
   */
  function groupHeartbeat(req, rawBody, url, auth) {
    const body = parseS3Body(rawBody);
    if (!body) return { status: 400, body: { error: 'bad-request' }, peerId: auth.peerId };
    const epoch = Math.floor(Number(body.epoch) || 0);
    const leaderPeerId = String(body.leaderPeerId ?? '');
    if (epoch < 1 || leaderPeerId === '') {
      return { status: 400, body: { error: 'bad-request' }, peerId: auth.peerId };
    }
    const commitSeq = Math.max(0, Math.floor(Number(body.commitSeq) || 0));
    const senderBaseUrl = headerValue(req, GROUP_BASE_HEADER.toLowerCase());
    // v0.8.0：心跳里 X-Peer-Base 是**发送方自己**的地址 —— 只记到发送方名下。
    // 少了这一笔，成员重启换端口后只有下一次 pull（测试里 600s 一次）才会纠正地址，
    // 期间 leader 的提案会打到旧地址上（表现：post 503 quorum-unavailable，而成员明明在线）。
    rememberMemberBaseUrl(auth.peerId, senderBaseUrl);
    rememberMemberAcceptDispatch(auth.peerId, body.acceptDispatch);
    const st = ensureRole();
    if (!st) return { status: 404, body: { error: 'not-found' }, peerId: auth.peerId };
    // S2：心跳只能为**自己**续租。少了这条，任何握着群密钥的成员发一条心跳就能把
    // 对端的 leaderPeerId 改写成任意 id（实测：一句话让对面变 follower、leader 指向别人）。
    if (leaderPeerId !== auth.peerId) {
      if (config.logger) {
        config.logger(
          `[group] heartbeat refused not-self-leader from=${shortPeerId(auth.peerId)} claim=${shortPeerId(leaderPeerId)} epoch=${epoch}`,
        );
      }
      return { status: 403, body: { error: 'not-self-leader', epoch: st.epoch }, peerId: auth.peerId };
    }
    // 地址与优先级也只许写在自己名下（以前 key 用的是 body 里的 leaderPeerId = 别人的 id）
    rememberPeerBaseUrl(auth.peerId, senderBaseUrl);
    if (Number.isFinite(Number(body.priority))) peerPriorities.set(auth.peerId, Math.floor(Number(body.priority)));
    // S2：心跳不得推进 epoch —— epoch 只能由 /v1/group/election 的票数推进。
    // 心跳带更高的 epoch 就是「靠一句话篡位」，按 stale-epoch 拒，并留一行告警。
    if (epoch > st.epoch) {
      noteEpochJump(st.epoch, epoch, 'heartbeat-rejected');
      if (config.logger) {
        config.logger(
          `[group] heartbeat refused epoch-advance from=${shortPeerId(auth.peerId)} epoch=${epoch} keep=${st.epoch}`,
        );
      }
      return {
        status: 409,
        body: { error: 'stale-epoch', epoch: st.epoch, leaderPeerId: st.leaderPeerId, commitSeq: st.commitSeq },
        peerId: auth.peerId,
      };
    }
    if (epoch < st.epoch) {
      return {
        status: 409,
        body: { error: 'stale-epoch', epoch: st.epoch, leaderPeerId: st.leaderPeerId, commitSeq: st.commitSeq },
        peerId: auth.peerId,
      };
    }
    // 同 epoch：只有本机记录的 leader 自己来才续租；领导权变更一律走 election 的票数。
    // （st.leaderPeerId === '' = 本机还没有 leader 记录，这是成员的 bootstrap 路径：
    //  此时接受发送方自报的 leader，等于把 group-key.json 里已知的那个 leader 学进角色表。）
    if (st.leaderPeerId !== '' && st.leaderPeerId !== leaderPeerId) {
      if (config.logger) {
        config.logger(
          `[group] heartbeat conflict from=${shortPeerId(leaderPeerId)} epoch=${epoch} keep=${shortPeerId(st.leaderPeerId)}`,
        );
      }
      return {
        status: 409,
        body: { error: 'leader-conflict', epoch: st.epoch, leaderPeerId: st.leaderPeerId, commitSeq: st.commitSeq },
        peerId: auth.peerId,
      };
    }
    const before = st.commitSeq;
    const accepted = acceptLeader({ epoch, leaderPeerId, commitSeq });
    if (config.logger) {
      config.logger(
        `[group] heartbeat from=${shortPeerId(leaderPeerId)} epoch=${epoch} commitSeq=${commitSeq} role=${accepted.role}`,
      );
    }
    // 契约 §5：心跳里的 commitSeq 更高说明本机漏了提交，用 pull 补齐（成员侧）
    if (groupRole === 'member' && commitSeq > before) void memberTick().catch(() => {});
    return {
      status: 200,
      body: {
        ok: true,
        epoch: accepted.epoch,
        commitSeq: accepted.commitSeq,
        // v0.8.2-α §4：本机接单开关（心跳是对端周期性学到它的渠道）
        acceptDispatch: acceptDispatchNow(),
      },
      peerId: auth.peerId,
    };
  }

  /**
   * POST /v1/group/election —— 拉票。
   * candidate === 本机 instanceId 是**本机自称候选**（CLI `group claim` 从回环打过来）：
   * 由本机自己发起选举，返回本机结果；否则按契约 §3 的三个条件投票。
   */
  async function groupElection(req, rawBody, url, auth) {
    const body = parseS3Body(rawBody);
    if (!body) return { status: 400, body: { error: 'bad-request' }, peerId: auth.peerId };
    const epoch = Math.floor(Number(body.epoch) || 0);
    const candidate = String(body.candidate ?? '');
    const priority = Number.isFinite(Number(body.priority))
      ? Math.floor(Number(body.priority))
      : GROUP_DEFAULT_HUB_PRIORITY;
    if (epoch < 1 || candidate === '') {
      return { status: 400, body: { error: 'bad-request' }, peerId: auth.peerId };
    }
    rememberPeerBaseUrl(auth.peerId, headerValue(req, GROUP_BASE_HEADER.toLowerCase()));
    rememberMemberAcceptDispatch(auth.peerId, body.acceptDispatch);
    peerPriorities.set(candidate, priority);
    const st = ensureRole();
    if (!st) return { status: 404, body: { error: 'not-found' }, peerId: auth.peerId };
    if (candidate === store.instanceId) {
      const out = await runElection({ reason: 'claim', forcedEpoch: Math.max(epoch, st.epoch + 1) });
      const after = ensureRole();
      return {
        status: 200,
        body: {
          vote: out?.ok === true,
          reason: out?.reason ?? null,
          epoch: after.epoch,
          role: after.role,
          leaderPeerId: after.leaderPeerId,
          // 运维要能看出「差几票」：分母是成员表全集，不是可达成员数
          votes: out?.votes ?? null,
          needed: out?.needed ?? null,
          memberCount: quorumMembers().length,
        },
        peerId: auth.peerId,
      };
    }
    const decision = voteDecision({ epoch, candidate, priority, st });
    if (decision.vote) {
      roleStore.update({
        role: 'follower',
        epoch: Math.max(st.epoch, epoch),
        leaderPeerId: candidate,
        leaseUntil: config.now() + leaseMs,
        votedFor: { epoch, peerId: candidate },
        commitSeq: st.commitSeq,
        groupId: st.groupId,
      });
    }
    const after = ensureRole();
    if (config.logger) {
      config.logger(
        `[group] election vote candidate=${shortPeerId(candidate)} epoch=${epoch} grant=${decision.vote}`
          + `${decision.reason ? ` reason=${decision.reason}` : ''}`,
      );
    }
    return {
      status: 200,
      body: {
        vote: decision.vote,
        reason: decision.reason ?? null,
        epoch: after.epoch,
        leaderPeerId: after.leaderPeerId,
        // 自报可达地址：成员当 leader 时靠它把对端加进承诺集合
        advertiseBaseUrl: localAdvertiseBaseUrl(),
      },
      peerId: auth.peerId,
    };
  }

  /** POST /v1/group/propose —— 把提案放进本地 pending（**不对外可见**，契约 §5） */
  function groupPropose(req, rawBody, url, auth) {
    const body = parseS3Body(rawBody);
    if (!body) return { status: 400, body: { error: 'bad-request' }, peerId: auth.peerId };
    const epoch = Math.floor(Number(body.epoch) || 0);
    const seq = Math.floor(Number(body.seq) || 0);
    const raw = body.message;
    if (epoch < 1 || seq < 1 || !raw || typeof raw !== 'object' || Array.isArray(raw)) {
      return { status: 400, body: { error: 'bad-request' }, peerId: auth.peerId };
    }
    const st = ensureRole();
    if (!st) return { status: 404, body: { error: 'not-found' }, peerId: auth.peerId };
    if (epoch !== st.epoch) {
      return {
        status: 409,
        body: { error: epoch < st.epoch ? 'stale-epoch' : 'epoch-mismatch', epoch: st.epoch },
        peerId: auth.peerId,
      };
    }
    if (st.leaderPeerId !== '' && auth.peerId !== st.leaderPeerId) {
      return { status: 409, body: { error: 'not-leader', epoch: st.epoch }, peerId: auth.peerId };
    }
    pendingProposals.set(seq, { message: normalizeIncomingMessage(raw, seq), at: config.now() });
    prunePendingProposals();
    if (config.logger) {
      config.logger(`[group] propose from=${shortPeerId(auth.peerId)} epoch=${epoch} seq=${seq}`);
    }
    return { status: 200, body: { ok: true, accepted: true, epoch: st.epoch }, peerId: auth.peerId };
  }

  /**
   * 本机未提交区里那一条。两条存放路径都要看：
   *   · propose 收到的提案 → pendingProposals（内存，hub 与成员都走这里）；
   *   · 本机自己 stage 的（leader 的 post 路径）→ hub 落 group.json.pending，成员落内存表。
   */
  function stagedProposal(seq) {
    const inMemory = pendingProposals.get(seq)?.message ?? null;
    if (inMemory) return inMemory;
    return groupStore ? groupStore.pendingMessage(seq) : null;
  }

  /** POST /v1/group/commit —— 提交确认：pending 转正并推进 commitSeq（契约 §5） */
  function groupCommit(req, rawBody, url, auth) {
    const body = parseS3Body(rawBody);
    if (!body) return { status: 400, body: { error: 'bad-request' }, peerId: auth.peerId };
    const epoch = Math.floor(Number(body.epoch) || 0);
    const seq = Math.floor(Number(body.seq) || 0);
    if (epoch < 1 || seq < 1) return { status: 400, body: { error: 'bad-request' }, peerId: auth.peerId };
    const st = ensureRole();
    if (!st) return { status: 404, body: { error: 'not-found' }, peerId: auth.peerId };
    if (epoch !== st.epoch) {
      return {
        status: 409,
        body: { error: epoch < st.epoch ? 'stale-epoch' : 'epoch-mismatch', epoch: st.epoch },
        peerId: auth.peerId,
      };
    }
    // H1：与 propose 同口径 —— 只有 leader 能提交。少了这条，任何成员都能把
    // 自己发明的消息「转正」进别人的日志（并顺手把 commitSeq 抬到任意值）。
    if (st.leaderPeerId !== '' && auth.peerId !== st.leaderPeerId) {
      if (config.logger) {
        config.logger(
          `[group] commit refused not-leader from=${shortPeerId(auth.peerId)} seq=${seq} epoch=${epoch}`,
        );
      }
      return { status: 409, body: { error: 'not-leader', epoch: st.epoch, commitSeq: st.commitSeq }, peerId: auth.peerId };
    }
    // H1：正文只认本机 pending 里那一条 —— body.message 不再被采信，
    // 客户端也无法用一个没提案过的 seq 抬高 commitSeq。
    const staged = stagedProposal(seq);
    if (!staged) {
      if (seq <= st.commitSeq) {
        // 幂等：这条早就转正过了（广播重投），不重复应用、不推进号
        return { status: 200, body: { ok: true, commitSeq: st.commitSeq, applied: false }, peerId: auth.peerId };
      }
      if (config.logger) {
        config.logger(`[group] commit refused unknown-seq from=${shortPeerId(auth.peerId)} seq=${seq} epoch=${epoch}`);
      }
      return { status: 409, body: { error: 'unknown-seq', epoch: st.epoch, commitSeq: st.commitSeq }, peerId: auth.peerId };
    }
    const applied = applyCommitted(normalizeIncomingMessage(staged, seq));
    pendingProposals.delete(seq);
    const next = roleStore.update({
      commitSeq: Math.max(st.commitSeq, seq),
      role: st.role,
      epoch: st.epoch,
      leaderPeerId: st.leaderPeerId,
      leaseUntil: st.leaseUntil,
      votedFor: st.votedFor,
      groupId: st.groupId,
    });
    if (config.logger) {
      config.logger(
        `[group] commit from=${shortPeerId(auth.peerId)} epoch=${epoch} seq=${seq} applied=${applied} commitSeq=${next.commitSeq}`,
      );
    }
    return { status: 200, body: { ok: true, commitSeq: next.commitSeq, applied }, peerId: auth.peerId };
  }

  /**
   * S3 §5：leader 的写路径。quorum=majority 走 propose→commit，ack 不足/超时一律丢弃 pending
   * 并回 503 —— **未提交的消息任何时刻都不对外可见**。
   */
  async function deliverPost(input) {
    if (quorumMode === 'none') {
      const message = ledgerAppend(input);
      const st0 = ensureRole();
      if (st0) roleStore.update({ commitSeq: Math.max(st0.commitSeq, message.seq) });
      if (config.logger) {
        config.logger(
          `[group] post kind=${message.kind} seq=${message.seq} peer=${shortPeerId(input.peerId)} quorum=none`,
        );
      }
      if (groupStore) enqueueReplication(message);
      return { status: 201, body: { seq: message.seq, ts: message.ts }, peerId: input.peerId };
    }
    const st = ensureRole();
    if (!st || st.role !== 'leader' || st.leaderPeerId !== store.instanceId || config.now() > st.leaseUntil) {
      if (config.logger) {
        config.logger(`[group] propose denied reason=not-leader epoch=${st?.epoch ?? 0}`);
      }
      return {
        status: 503,
        body: { error: 'quorum-unavailable', epoch: st?.epoch ?? 0 },
        peerId: input.peerId,
      };
    }
    const ctx = localGroupContext();
    if (!ctx?.groupKey || String(ctx.groupId ?? '') === '') {
      return { status: 503, body: { error: 'quorum-unavailable', epoch: st.epoch }, peerId: input.peerId };
    }
    const message = stagePending(input);
    const seq = message.seq;
    if (config.logger) {
      config.logger(
        `[group] post kind=${message.kind} seq=${seq} peer=${shortPeerId(input.peerId)} quorum=${quorumMode}`,
      );
    }
    const needed = quorumNeeded();
    const targets = proposeTargets();
    const base = {
      groupKey: ctx.groupKey,
      groupId: String(ctx.groupId),
      senderId: store.instanceId,
      epoch: st.epoch,
      seq,
      message,
      selfBaseUrl: localAdvertiseBaseUrl(),
      timeoutMs: commitTimeoutMs,
    };
    const tasks = targets.map(async (peerId) => {
      try {
        const reply = await withGroupKey((keyCtx) => proposeGroupMessage({
          ...base,
          groupKey: keyCtx.groupKey,
          groupId: String(keyCtx.groupId),
          baseUrl: baseUrlOf(peerId),
        }));
        return reply?.ok === true;
      } catch {
        return false;
      }
    });
    const granted = await settleWithin(tasks, commitTimeoutMs);
    const acks = 1 + granted.filter(Boolean).length;
    if (acks >= needed) {
      commitStaged(message);
      roleStore.update({ commitSeq: Math.max(st.commitSeq, seq) });
      if (config.logger) {
        config.logger(`[group] commit seq=${seq} epoch=${st.epoch} acks=${acks}/${needed}`);
      }
      void broadcastCommit(st.epoch, seq, message).catch(() => {});
      if (groupStore) enqueueReplication(message);
      return { status: 201, body: { seq, ts: message.ts }, peerId: input.peerId };
    }
    dropStaged(seq);
    if (config.logger) {
      config.logger(
        `[group] propose dropped seq=${seq} epoch=${st.epoch} acks=${acks}/${needed} reason=quorum-unavailable`,
      );
    }
    return { status: 503, body: { error: 'quorum-unavailable', epoch: st.epoch }, peerId: input.peerId };
  }
  async function groupAuthDispatch(req, rawBody, url) {
    if (groupRole === 'off') return { status: 404, body: { error: 'not-found' } };
    const method = String(req.method ?? 'GET').toUpperCase();
    const handlers = {
      'GET /v1/group/probe': groupProbe,
      'GET /v1/group/pull': groupPull,
      // S1 查询 leader（GET）/ S3 心跳（POST）共用这一条路径，方法区分
      'GET /v1/group/leader': groupLeader,
      'POST /v1/group/leader': groupHeartbeat,
      'POST /v1/group/replicate': groupReplicate,
      'POST /v1/group/election': groupElection,
      'POST /v1/group/propose': groupPropose,
      'POST /v1/group/commit': groupCommit,
      'GET /v1/group/lease': groupLease,
      // v0.8.0（契约 §4.2/§5.1）：介绍人 → hub 的入群转交与代查（只有 hub 真的处理）
      'POST /v1/group/apply-intake': groupApplyIntake,
      'POST /v1/group/apply-query': groupApplyQuery,
    };
    const handler = handlers[`${method} ${url.pathname}`];
    if (!handler) return { status: 405, body: { error: 'method-not-allowed' } };
    let auth = authorizeGroupRequest(req, rawBody, url);
    if (!auth.ok && groupRole === 'member' && String(auth.error) === 'bad-signature') {
      // hub 轮换密钥后，成员手里的旧钥会让**入站**请求也变成 bad-signature；
      // 这里先按 per-peer 换钥，再验一次（只重试一次），避免「谁也没法先动」的死锁。
      const refreshed = await refreshGroupKeyFromHub();
      if (refreshed.ok === true) auth = authorizeGroupRequest(req, rawBody, url);
    }
    if (!auth.ok) return { status: auth.status, body: { error: auth.error }, peerId: null };
    return handler(req, rawBody, url, auth);
  }

  async function groupDispatch(req, rawBody, url, res) {
    const method = String(req.method ?? 'GET').toUpperCase();
    // POST /v1/group/post 是**双模式**端点（v0.8.0）：群级签名在 hub 上走单独分派，
    // per-peer 仍走下面的老路径（404 not-leader / 403 not-a-member 语义一字不变）。
    const groupAuthPost = method === 'POST' && url.pathname === '/v1/group/post'
      && headerValue(req, GROUP_AUTH_HEADER.toLowerCase()) === GROUP_AUTH_VALUE;
    if (groupAuthPost) return groupPostWithGroupAuth(req, rawBody);
    // S1/S2/S3 的八条 + v0.8.0 的两条：群级鉴权的路径 hub 与成员都提供（不经 hub 直连）。
    // post 是双模式端点，例外地留在下面的 groupDispatch 里（per-peer 语义一字不变）。
    if (GROUP_AUTH_PATHS.includes(url.pathname) && url.pathname !== '/v1/group/post') {
      return groupAuthDispatch(req, rawBody, url);
    }
    // v0.8.0：per-peer 的发现/申请四条与群开关无关 —— 没启用群的节点也要能答
    // advertise/lookup（否则「只与某成员配对」的申请者永远发现不了群）。
    if (GROUP_PEER_V1_PATHS.includes(url.pathname)) {
      if (method !== 'POST') return { status: 405, body: { error: 'method-not-allowed' } };
      if (url.pathname === '/v1/group/advertise') return groupAdvertise(req, rawBody);
      if (url.pathname === '/v1/group/lookup') return groupLookup(req, rawBody);
      if (url.pathname === '/v1/group/apply') return groupApply(req, rawBody);
      return groupApplyStatus(req, rawBody);
    }
    // S3：成员节点只有当上 leader 才收 post（否则这些路径仍当作不存在，v0.5.0 语义不变）
    const leaderPost = !groupStore && method === 'POST' && url.pathname === '/v1/group/post' && isLocalLeader();
    if (!groupStore && !leaderPost) {
      // 成员节点上「post 打到非 leader」与「群没启用」要能分辨：状态码保持 404（v0.5 语义不变），
      // 但正文与日志点明原因，免得和「leader 拿不到多数派 503」混在一起。
      if (groupRole !== 'off' && method === 'POST' && url.pathname === '/v1/group/post') {
        if (config.logger) {
          config.logger(`[group] post refused reason=not-leader epoch=${roleState()?.epoch ?? 0}`);
        }
        return { status: 404, body: { error: 'not-leader' }, peerId: null };
      }
      return { status: 404, body: { error: 'not-found' } };
    }
    if (!GROUP_V1_PATHS.includes(url.pathname)) return { status: 404, body: { error: 'not-found' } };
    if (method === 'GET' && url.pathname === '/v1/group/state') return groupState(req, rawBody);
    if (method === 'POST' && url.pathname === '/v1/group/join') return groupJoin(req, rawBody);
    if (method === 'POST' && url.pathname === '/v1/group/post') return groupPost(req, rawBody);
    if (method === 'GET' && url.pathname === '/v1/group/history') return groupHistory(req, rawBody, url);
    if (method === 'GET' && url.pathname === '/v1/group/events') return groupEvents(req, rawBody, url, res);
    return { status: 405, body: { error: 'method-not-allowed' } };
  }

  // ---- S2 v0.6.0 复制：hub 推送队列 + 成员拉取循环 -------------------------

  const replicaRetryMs = Number.isFinite(Number(overrides.groupReplica?.retryMs))
    ? Math.max(100, Math.floor(Number(overrides.groupReplica.retryMs)))
    : GROUP_REPLICA_RETRY_MS;
  const replicaPullMs = Number.isFinite(Number(overrides.groupReplica?.pullIntervalMs))
    ? Math.max(50, Math.floor(Number(overrides.groupReplica.pullIntervalMs)))
    : config.group.replicaPullMs;

  /**
   * v0.8.0：role=off 的节点每隔这么久看一眼「有没有按名入群拿到的授权」。
   * 取 min(1s, 拉取间隔)：真机上 CLI 拿到 grant 后 ≤1s 就开始 pull，测试里跟着 pullIntervalMs 走。
   */
  const grantWatchEveryMs = Number.isFinite(Number(overrides.groupReplica?.pullIntervalMs))
    ? Math.max(50, Math.floor(Number(overrides.groupReplica.pullIntervalMs)))
    : Math.min(1_000, config.group.replicaPullMs);

  /** peerId -> {messages: [], lastError} ：推送失败只留在这里重试，不阻塞 post */
  const replicaQueue = new Map();
  let replicaRetryTimer = null;

  /** 推送目标：群状态里记的地址优先，其次 peers.json 里配对时的地址 */
  function replicaTarget(peerId) {
    const member = groupStore ? groupStore.state().members[peerId] : null;
    const recorded = String(member?.baseUrl ?? '').trim().replace(/\/+$/, '');
    if (recorded !== '') return recorded;
    const peer = store.getPeer(String(peerId));
    return String(peer?.baseUrl ?? '').trim().replace(/\/+$/, '');
  }

  function ensureReplicaTimer() {
    if (replicaRetryTimer) return;
    replicaRetryTimer = setInterval(() => {
      void flushReplication().catch(() => {});
    }, replicaRetryMs);
    replicaRetryTimer.unref?.();
  }

  /**
   * leader 写本地后调这里：把消息排进每个成员的队列并立刻尝试一次。
   * 不 await、不抛 —— S2 的提交语义就是「写本地即提交」，复制失败只重试。
   */
  function enqueueReplication(message) {
    if (!groupStore) return;
    const ctx = localGroupContext();
    if (!ctx?.groupKey) return;
    for (const peerId of Object.keys(ctx.members)) {
      if (peerId === store.instanceId) continue;
      const entry = replicaQueue.get(peerId) ?? { messages: [], lastError: '' };
      entry.messages.push(message);
      if (entry.messages.length > GROUP_MESSAGE_LIMIT) {
        entry.messages.splice(0, entry.messages.length - GROUP_MESSAGE_LIMIT);
      }
      replicaQueue.set(peerId, entry);
    }
    if (replicaQueue.size === 0) return;
    ensureReplicaTimer();
    void flushReplication().catch(() => {});
  }

  async function flushReplication() {
    if (replicaQueue.size === 0) {
      if (replicaRetryTimer) {
        clearInterval(replicaRetryTimer);
        replicaRetryTimer = null;
      }
      return;
    }
    const ctx = localGroupContext();
    if (!ctx?.groupKey) return;
    for (const [peerId, entry] of [...replicaQueue]) {
      if (entry.messages.length === 0) {
        replicaQueue.delete(peerId);
        continue;
      }
      const baseUrl = replicaTarget(peerId);
      if (baseUrl === '') {
        if (entry.lastError !== 'no-base-url') {
          entry.lastError = 'no-base-url';
          if (config.logger) {
            config.logger(`[group] replicate pending peer=${shortPeerId(peerId)} reason=no-base-url`);
          }
        }
        continue;
      }
      const batch = entry.messages.slice();
      try {
        const sent = await replicateGroupMessages({
          baseUrl,
          groupKey: ctx.groupKey,
          groupId: ctx.groupId,
          senderId: store.instanceId,
          epoch: ctx.epoch,
          leaderPeerId: ctx.leaderPeerId,
          messages: batch,
          selfBaseUrl: localAdvertiseBaseUrl(),
          timeoutMs: Math.max(500, replicaRetryMs),
        });
        entry.messages = entry.messages.slice(batch.length);
        entry.lastError = '';
        if (entry.messages.length === 0) replicaQueue.delete(peerId);
        else replicaQueue.set(peerId, entry);
        if (config.logger) {
          config.logger(
            `[group] replicate peer=${shortPeerId(peerId)} n=${batch.length} lastSeq=${sent?.lastSeq ?? '-'}`,
          );
        }
      } catch (error) {
        entry.lastError = String(error?.message ?? error);
        if (config.logger) {
          config.logger(
            `[group] replicate retry peer=${shortPeerId(peerId)} pending=${entry.messages.length} reason=${entry.lastError}`,
          );
        }
      }
    }
    if (replicaQueue.size === 0 && replicaRetryTimer) {
      clearInterval(replicaRetryTimer);
      replicaRetryTimer = null;
    }
  }

  /**
   * 成员侧的 hub：地址与（可能有的）对端密钥。
   *
   * 解析顺序（v0.8.0 真机回归）：
   *   1. config.group.hub（名字或 peerId）→ peers.json 里那条（带 per-peer 密钥）
   *   2. group-key.json 的 hub.peerId  → peers.json 里那条（如果碰巧配对过）
   *   3. group-key.json 的 hub.baseUrl → 直接用（**没有** per-peer 密钥，只能走群级鉴权）
   *
   * 第 3 条是「按名入群」的主路径：那台机器与 hub 之间没有配对记录，但它握着群密钥，
   * pull / 心跳 / 选举都是群级签名，够了（不需要 per-peer）。
   */
  function groupHubPeer() {
    if (groupRole !== 'member') return null;
    const peers = Object.entries(store.reloadPeers().peers)
      .map(([peerId, peer]) => ({ peerId, ...peer }));
    const keyHub = readGroupKeyFile(config.stateDir)?.hub ?? null;
    const keyHubId = String(keyHub?.peerId ?? '').trim();
    const keyHubUrl = String(keyHub?.baseUrl ?? '').trim().replace(TRAILING_SLASHES, '');
    let hub = String(config.group.hub ?? '').trim() !== ''
      ? resolveGroupHub(peers, config.group.hub)
      : null;
    if (!hub && keyHubId !== '') {
      hub = peers.find((peer) => String(peer.peerId ?? '') === keyHubId) ?? null;
    }
    if (!hub && keyHubUrl !== '') {
      hub = peers.find((peer) => String(peer.baseUrl ?? '').trim().replace(TRAILING_SLASHES, '') === keyHubUrl)
        ?? null;
    }
    if (!hub && keyHubUrl !== '') {
      // 没配对过：只有地址与（可能的）名字。secret=null 表示不能签 per-peer 请求。
      hub = { peerId: keyHubId, name: String(keyHub?.name ?? ''), baseUrl: keyHubUrl, secret: null };
    }
    if (!hub) return null;
    const baseUrl = String(hub.baseUrl ?? '').trim().replace(TRAILING_SLASHES, '');
    if (baseUrl === '') return null;
    return {
      peerId: String(hub.peerId ?? ''),
      name: String(hub.name ?? ''),
      baseUrl,
      // secret=null = 只有群密钥（按名入群）：只能走群级鉴权的端点
      secret: hub.secret ? String(hub.secret) : null,
    };
  }

  /**
   * **权威替换**成员侧成员表（v0.8.1）。
   *
   * v0.7.x 为了修「401 not-a-member 死锁」把这里改成了并集（只增不减）。并集解决了
   * 「快照不完整时误删」，代价是**权威移除永远传不到成员**：removed 的人留在本机表里，
   * quorum 分母虚高（真机：NAS 侧 2 人、桌面侧 12 秒后仍是 4 人 → 桌面当 leader 时
   * 以为需要 3 票，而实际只有 2 台能投票，于是永远选不出、永远写不进去）。
   *
   * 现在区分两种写入语义：
   *   · 权威快照（hub 的 /v1/group/state、pull 的 memberIds、grant）→ 整体替换（本函数）；
   *   · 自愈入表（对端用 election/heartbeat 证明自己握着群密钥）→ upsertGroupMember 并集。
   *
   * 名字与地址仍尽量沿用本地已知值（快照里通常没有），但**条目本身以权威快照为准**。
   */
  function replaceGroupMembers(members, names = {}, accepts = null) {
    const existing = readGroupKeyFile(config.stateDir);
    if (!existing) return null;
    const previous = existing.members ?? {};
    const next = {};
    const acceptOf = (id) => {
      // v0.8.2-α §4：pull 带来的掩码是权威值；掩码没提这个成员就沿用本地已知值。
      // 少了这一笔，每轮 pull 都会把成员的接单开关重置回默认 true（真机上就是
      // 「hub 关了单、成员还在照派」）。
      if (accepts && Object.prototype.hasOwnProperty.call(accepts, id)) return accepts[id] !== false;
      return previous[id]?.acceptDispatch !== false;
    };
    for (const peerId of members) {
      const id = String(peerId ?? '');
      if (id === '') continue;
      if (next[id]) continue;
      // baseUrl 是承诺集合的依据：学到的优先，其次文件里原有的（快照里一般没有地址）
      const baseUrl = knownMemberAddress(id) || String(previous[id]?.baseUrl ?? '');
      next[id] = {
        name: String(names[id]?.name ?? previous[id]?.name ?? ''),
        baseUrl,
        acceptDispatch: acceptOf(id),
      };
    }
    if (Object.keys(next).length === 0) return null;
    if (!next[store.instanceId]) {
      next[store.instanceId] = {
        name: config.name,
        baseUrl: String(previous[store.instanceId]?.baseUrl ?? '') || localAdvertiseBaseUrl(),
        acceptDispatch: acceptDispatchNow(),
      };
    }
    rememberAuthoritativeMembers(Object.keys(next), 'pull');
    writeGroupKeyFile(config.stateDir, { ...existing, members: next });
    return next;
  }

  /** 成员 bootstrap：用 per-peer 密钥取群状态（groupId + groupKey），失败只记一行 */
  async function bootstrapMember(hub) {
    try {
      let state;
      try {
        state = await fetchGroupState({ baseUrl: hub.baseUrl, secret: hub.secret, senderId: store.instanceId, timeoutMs: 5000 });
      } catch (error) {
        const text = String(error?.message ?? error);
        // hub 开了 autoJoin 时自助加入一次再取状态（与 CLI group join 同一语义）
        if (!/^403\b/.test(text) || !config.group.autoJoin) throw error;
        await joinGroup({ baseUrl: hub.baseUrl, secret: hub.secret, senderId: store.instanceId, name: config.name });
        state = await fetchGroupState({ baseUrl: hub.baseUrl, secret: hub.secret, senderId: store.instanceId, timeoutMs: 5000 });
      }
      if (!state?.groupId || !state?.groupKey) throw new Error('group-state-incomplete');
      // v0.8.1：hub 的 state.members 是权威快照 —— 整体替换（允许删除已移除的成员）
      const members = {};
      for (const member of Array.isArray(state.members) ? state.members : []) {
        const peerId = String(member?.peerId ?? '');
        if (peerId === '') continue;
        members[peerId] = {
          name: String(member?.name ?? ''),
          baseUrl: String(member?.baseUrl ?? ''),
          // v0.8.2-α §4：hub 的 state.members[].acceptDispatch 是权威值
          acceptDispatch: member?.acceptDispatch !== false,
        };
      }
      if (!members[hub.peerId]) members[hub.peerId] = { name: hub.name, baseUrl: hub.baseUrl };
      if (!members[store.instanceId]) members[store.instanceId] = { name: config.name, baseUrl: '' };
      rememberAuthoritativeMembers(Object.keys(members), 'state');
      writeGroupKeyFile(config.stateDir, {
        groupId: String(state.groupId),
        key: String(state.groupKey),
        keyVersion: Number(state.keyVersion) || Number(state.epoch) || 0,
        leaderPeerId: hub.peerId,
        name: config.name,
        // hub 是群名的权威来源：bootstrap 时把真名落盘（广播/查找都靠它）
        groupName: String(state.name ?? ''),
        // hub 三元组：之后重启也能靠它继续 pull（不依赖 group.hub 配置）
        hub: { peerId: hub.peerId, name: hub.name, baseUrl: hub.baseUrl },
        members,
      });
      replicaStore.ensureHeader({
        groupId: String(state.groupId),
        epoch: Number(state.epoch) || 0,
        leaderPeerId: hub.peerId,
      });
      if (config.logger) {
        config.logger(`[group] bootstrap hub=${shortPeerId(hub.peerId)} epoch=${Number(state.epoch) || 0}`);
      }
      // 契约 §2a：成员「入群成功后一次」广播（进程内只做一次；节流仍按伙伴维度生效）
      if (!memberJoinAdvertised) {
        memberJoinAdvertised = true;
        void broadcastGroupName({ reason: 'member-join' }).catch(() => {});
      }
      return { ok: true };
    } catch (error) {
      const reason = String(error?.message ?? error);
      if (memberLastError !== reason) {
        memberLastError = reason;
        if (config.logger) config.logger(`[group] bootstrap failed reason=${reason}`);
      }
      return { ok: false, reason };
    }
  }

  let memberTimer = null;
  let memberInFlight = false;
  let memberLastError = '';
  /** v0.8.0：role=off 时的授权观察器（拿到 grant 就是成员，不必重启） */
  let grantWatchTimer = null;

  /**
   * v0.8.0 真机回归：运行期「按名入群」提升。
   *
   * 进程启动时既没有群配置也没有授权 → role=off；之后 CLI 用 grant 写了 group-key.json，
   * 这里把本进程原地提升成成员：建副本、起拉取循环、参与选举。只提升一次。
   */
  function promoteToMember() {
    if (groupRole !== 'off') return false;
    const keyHub = readGroupKeyFile(config.stateDir)?.hub ?? null;
    const known = keyHub && (String(keyHub.baseUrl ?? '') !== '' || String(keyHub.peerId ?? '') !== '');
    if (!known) return false;
    groupRole = 'member';
    if (!replicaStore) replicaStore = createReplicaStore();
    if (!roleStore) roleStore = new GroupRoleStore({ stateDir: config.stateDir, now: config.now });
    if (!memberTimer) {
      void memberTick().catch(() => {});
      memberTimer = setInterval(() => {
        void memberTick().catch(() => {});
      }, replicaPullMs);
      memberTimer.unref?.();
    }
    startRoleTimers();
    if (config.logger) {
      config.logger(
        '[group] promoted to member reason=grant hub=' + shortPeerId(String(keyHub?.peerId ?? ''))
        + ' base=' + String(keyHub?.baseUrl ?? ''),
      );
    }
    return true;
  }

  /** 观察授权文件：只在 role=off 时运行，提升成功即停表 */
  function startGrantWatcher() {
    if (groupRole !== 'off' || grantWatchTimer) return;
    grantWatchTimer = setInterval(() => {
      if (promoteToMember() && grantWatchTimer) {
        clearInterval(grantWatchTimer);
        grantWatchTimer = null;
      }
    }, grantWatchEveryMs);
    grantWatchTimer.unref?.();
  }

  /** 成员每一轮：确保有密钥 → 向 leader 补差 → 收下并去重 */
  async function memberTick() {
    if (groupRole !== 'member' || memberInFlight) return { ok: false, reason: 'skipped' };
    // S3：自己已经当上 leader 时，本机就是顺序源，不该再去向（可能已死的）原 hub 补差
    if (isLocalLeader()) return { ok: false, reason: 'is-leader' };
    memberInFlight = true;
    try {
      const hub = groupHubPeer();
      if (!hub) {
        if (memberLastError !== 'hub-not-paired') {
          memberLastError = 'hub-not-paired';
          if (config.logger) config.logger('[group] pull skipped reason=hub-not-paired');
        }
        return { ok: false, reason: 'hub-not-paired' };
      }
      let ctx = localGroupContext();
      if (!ctx?.groupKey) {
        // 按名入群的节点手里已经有群密钥（grant 落盘），走不到这里；
        // 真走到这里又没有 per-peer 密钥，就无从 bootstrap（只能等授权）。
        if (!hub.secret) {
          if (memberLastError !== 'no-group-key') {
            memberLastError = 'no-group-key';
            if (config.logger) config.logger('[group] pull skipped reason=no-group-key');
          }
          return { ok: false, reason: 'no-group-key' };
        }
        const boot = await bootstrapMember(hub);
        if (!boot.ok) return boot;
        ctx = localGroupContext();
      }
      if (!ctx?.groupKey) return { ok: false, reason: 'no-group-key' };
      const sinceSeq = replicaStore.state().lastSeq;
      const page = await withGroupKey((keyCtx) => pullGroupMessages({
        baseUrl: hub.baseUrl,
        groupKey: keyCtx.groupKey,
        groupId: keyCtx.groupId,
        senderId: store.instanceId,
        sinceSeq,
        limit: GROUP_HISTORY_MAX_LIMIT,
        selfBaseUrl: localAdvertiseBaseUrl(),
        // 自报复制进度：hub 的面板据此显示「落后 leader 多少条」
        lastSeq: sinceSeq,
        // v0.8.2-α §4：follower 的周期自报渠道就是 pull（心跳只由 leader 发）
        acceptDispatch: acceptDispatchNow(),
        timeoutMs: Math.max(1000, replicaPullMs),
      }));
      if (String(page?.groupId ?? '') !== String(ctx.groupId)) {
        throw new Error('group-mismatch');
      }
      const applied = replicaStore.append({
        groupId: String(page.groupId),
        epoch: Number(page.epoch) || 0,
        leaderPeerId: String(page.leaderPeerId ?? ''),
        messages: Array.isArray(page.messages) ? page.messages : [],
      });
      if (Array.isArray(page.memberIds) && page.memberIds.length > 0) {
        replaceGroupMembers(page.memberIds, ctx.members, page.memberAcceptDispatch ?? null);
      }
      memberLastError = '';
      // hub 在 pull 响应里自报地址（X-Peer-Base 同一口径）：按名入群的节点本地没有 hub 的
      // 配对记录，靠这一条把地址写进 group-key.json 的成员表（选举/提案要用）。
      rememberPeerBaseUrl(hub.peerId, page?.advertiseBaseUrl ?? '');
      // 契约 §2/§3：群名只有 hub 是权威。0.7.x 的老 group-key.json 没有 groupName 字段，
      // 这里在它为空时补取一次 hub 状态并回写（之后为空才再取，不引入每轮 pull 的额外请求）。
      if (normalizeGroupName(readGroupKeyFile(config.stateDir)?.groupName) === '') {
        const named = await resolveGroupName({
          stateDir: config.stateDir,
          hub: { baseUrl: hub.baseUrl, secret: hub.secret },
          senderId: store.instanceId,
          timeoutMs: 5_000,
        }).catch(() => ({ name: '' }));
        if (named.name !== '' && config.logger) {
          config.logger('[group] group-name learned source=' + named.source + ' name=' + named.name);
        }
      }
      if (config.logger) {
        config.logger(`[group] pull since=${sinceSeq} got=${applied.added} lastSeq=${applied.lastSeq}`);
      }
      return { ok: true, added: applied.added, lastSeq: applied.lastSeq };
    } catch (error) {
      const reason = String(error?.message ?? error);
      if (memberLastError !== reason) {
        memberLastError = reason;
        if (config.logger) config.logger(`[group] pull failed reason=${reason}`);
      }
      return { ok: false, reason };
    } finally {
      memberInFlight = false;
    }
  }

  /** hub 把自己那条成员的地址也写进群状态（面板要显示「我看到的你的地址」） */
  function refreshSelfBaseUrl() {
    if (!groupStore) return;
    const baseUrl = localAdvertiseBaseUrl();
    if (baseUrl !== '') groupStore.setMemberBaseUrl(store.instanceId, baseUrl);
  }

  async function dispatch(req, rawBody, url, res) {
    const method = String(req.method ?? 'GET').toUpperCase();
    // S1 路径白名单：群级鉴权只允许四条成员互访路径，其它路径一律 401 group-auth-scope
    if (headerValue(req, 'x-peer-auth') === GROUP_AUTH_VALUE && !GROUP_AUTH_PATHS.includes(url.pathname)) {
      return { status: 401, body: { error: 'group-auth-scope' } };
    }
    if (method === 'GET' && url.pathname === '/v1/health') return health();
    if (method === 'POST' && url.pathname === '/v1/pair') return pair(rawBody);
    if (method === 'POST' && url.pathname === '/v1/pair/confirm') return pairConfirm(rawBody);
    if (method === 'POST' && url.pathname === '/v1/ask') return ask(req, rawBody);
    if (method === 'GET' && url.pathname === '/v1/answer') return answer(req, rawBody, url, res);
    if (method === 'GET' && url.pathname === '/v1/events') return events(req, rawBody, url, res);
    if (method === 'GET' && url.pathname === '/v1/peers') return peers(req, rawBody);
    if (method === 'POST' && url.pathname === '/v1/unpair') return unpair(req, rawBody);
    // v0.5.0 群：未知的 /v1/group/* 也走这里（404 而不是落到通用 405）
    if (url.pathname.startsWith('/v1/group/')) return groupDispatch(req, rawBody, url, res);
    if (KNOWN_V1_PATHS.includes(url.pathname)) {
      return { status: 405, body: { error: 'method-not-allowed' } };
    }
    return { status: 404, body: { error: 'not-found' } };
  }

  const httpServer = createHttpServer(async (req, res) => {
    const startedAt = process.hrtime.bigint();
    let url;
    try {
      url = new URL(req.url ?? '/', 'http://lan-peer.invalid');
    } catch {
      sendJson(res, 400, { error: 'bad-request' });
      return;
    }
    const remoteAddress = req.socket?.remoteAddress ?? '';
    let result;
    let rawBody = Buffer.alloc(0);
    let responseSecret = null;
    /** S1：群级请求的响应信封密钥（HKDF(groupKey) 的 body key） */
    let groupResponseKey = null;
    try {
      if (!isAllowedRemote(remoteAddress, config.trustedCidrs)) {
        result = { status: 403, body: { error: 'forbidden-network' } };
      } else {
        rawBody = await readRequestBody(req);
        const groupAuthRequest = headerValue(req, 'x-peer-auth') === GROUP_AUTH_VALUE;
        // /v1/events 不在列表里：GET 没有请求体，加密信封无从谈起；
        // 它的签名在 handler 内验，事件载荷始终逐条加密（见 events()）。
        // 群级请求不参与 per-peer 门控：它用 HKDF(groupKey) 的信封，签名覆盖明文 body。
        const authenticated = !groupAuthRequest
          && (['/v1/ask', '/v1/answer', '/v1/peers', '/v1/unpair'].includes(url.pathname)
            // 群端点只有 hub 提供；未启用群时不做门控，直接由 dispatch 回 404
            || (groupStore !== null && GROUP_V1_PATHS.includes(url.pathname))
            // v0.8.0（契约 §2/§3/§4.1/§5.1）：发现与申请四条是 per-peer 路径，
            // **与群开关无关** —— 任何已配对节点都要先按对端密钥解信封再验签。
            || GROUP_PEER_V1_PATHS.includes(url.pathname)
            // S3：成员当上 leader 时也收 post，同样要先按发送方密钥解密/验签
            || (groupStore === null && url.pathname === '/v1/group/post' && isLocalLeader()));
        if (groupAuthRequest) {
          const groupCtx = localGroupContext();
          if (groupCtx?.groupKey) {
            let bodyKey = deriveGroupKeys(groupCtx.groupKey).bodyKey;
            groupResponseKey = bodyKey;
            const encrypted = String(req.headers[ENC_HEADER] ?? '') === ENC_VERSION;
            if (encrypted && rawBody.length > 0) {
              let decrypted = false;
              try {
                rawBody = decryptGroupBody(bodyKey, rawBody.toString('utf8'));
                decrypted = true;
              } catch {
                decrypted = false;
              }
              if (!decrypted) {
                // hub 轮换了群密钥：成员侧先按 per-peer 换钥再解一次（只一次）
                const healed = groupRole === 'member' ? await refreshGroupKeyFromHub() : { ok: false };
                if (healed.ok === true) {
                  const freshCtx = localGroupContext();
                  if (freshCtx?.groupKey) {
                    bodyKey = deriveGroupKeys(freshCtx.groupKey).bodyKey;
                    groupResponseKey = bodyKey;
                    try {
                      rawBody = decryptGroupBody(bodyKey, rawBody.toString('utf8'));
                      decrypted = true;
                    } catch {
                      decrypted = false;
                    }
                  }
                }
              }
              if (!decrypted) {
                // 对端拿的可能仍是旧钥：错误体走**明文**，否则它连信封都解不开
                result = { status: 400, body: { error: 'bad-encryption' } };
                groupResponseKey = null;
              }
            }
          }
        }
        if (authenticated) {
          const peer = peerForRequest(store, req);
          const inboundSecret = peer?.inboundSecret
            ?? (config.acceptSecretFallback ? peer?.secret : undefined);
          const encrypted = String(req.headers[ENC_HEADER] ?? '') === ENC_VERSION;
          if (!encrypted && config.requireEncryption) {
            result = { status: 400, body: { error: 'encryption-required' } };
          } else if (encrypted) {
            if (!inboundSecret) {
              result = { status: 401, body: { error: 'bad-signature' } };
            } else {
              try {
                rawBody = decryptInbound(inboundSecret, rawBody, ENC_VERSION);
                responseSecret = inboundSecret;
              } catch {
                result = { status: 400, body: { error: 'bad-encryption' } };
              }
            }
          }
        }
        if (result === undefined) result = await dispatch(req, rawBody, url, res);
      }
    } catch (err) {
      if (err?.code === 'payload-too-large') {
        result = { status: 413, body: { error: 'payload-too-large' } };
      } else if (err?.code === 'bad-json') {
        result = { status: 400, body: { error: 'bad-request' } };
      } else {
        if (config.logger) config.logger(`internal error: ${err?.message ?? err}`);
        result = { status: 500, body: { error: 'internal' } };
      }
    }

    if (!res.headersSent) {
      try {
        // 错误体一律明文：群级请求失败时对端可能拿着旧钥（密钥刚轮换），加密过去它连错误码都读不到，
        // 也就无法据此换钥重试。错误体只有 {error, epoch, ...} 之类的码，不含任何密钥。
        const body = (groupResponseKey && result.status < 400)
          ? {
              enc: ENC_VERSION,
              data: encryptGroupBody(groupResponseKey, Buffer.from(JSON.stringify(result.body), 'utf8')),
            }
          : (responseSecret ? encryptOutbound(responseSecret, result.body) : result.body);
        sendJson(res, result.status, body);
      } catch {
        res.destroy();
      }
    }
    if (config.logger) {
      const elapsedMs = Number(process.hrtime.bigint() - startedAt) / 1e6;
      // 只记录方法、路径、状态、耗时、peerId、错误码（4xx/5xx 时才带，便于排障）；
      // 绝不记录 header / secret / 签名原文
      const errorCode = result.status >= 400 ? String(result.body?.error ?? '') : '';
      config.logger(
        `${nowIso(Date.now())} ${String(req.method).toUpperCase()} ${url.pathname} `
        + `${result.status} ${elapsedMs.toFixed(1)}ms peer=${result.peerId ?? '-'}`
        + `${errorCode === '' ? '' : ` err=${errorCode}`}`,
      );
    }
  });

  /**
   * S3 门面：角色/租约/未提交条数/手动接管。hub 与成员两种形状都带上同一份，
   * 管理接口（契约 §7）与管理面板只需要读 role() 的字段、调 claim()。
   */
  const s3Facade = {
    role: () => {
      const st = ensureRole();
      if (!st) return { role: 'follower', epoch: 0, leaderPeerId: '', leaseUntil: 0, commitSeq: 0, pendingCount: 0 };
      return {
        role: st.role,
        epoch: st.epoch,
        leaderPeerId: st.leaderPeerId,
        leaseUntil: st.leaseUntil,
        commitSeq: st.commitSeq,
        pendingCount: pendingCount(),
        votedFor: st.votedFor,
        groupId: st.groupId,
        degraded: isDegraded(),
        quorum: quorumMode,
        keyVersion: groupKeyVersion(),
      };
    },
    /** 契约 §7：POST /api/lan-peers/group/leader {action:claim} 的落点 */
    claim: async (options = {}) => {
      if (!roleStore) return { ok: false, reason: 'group-disabled' };
      const st = ensureRole();
      const epoch = Number.isFinite(Number(options.epoch)) ? Math.floor(Number(options.epoch)) : st.epoch + 1;
      const out = await runElection({ reason: 'claim', forcedEpoch: Math.max(epoch, st.epoch + 1), force: true });
      const after = ensureRole();
      return {
        ok: after.role === 'leader',
        role: after.role,
        epoch: after.epoch,
        leaderPeerId: after.leaderPeerId,
        reason: out?.ok ? null : (out?.reason ?? 'claim-failed'),
        votes: out?.votes ?? null,
        needed: out?.needed ?? null,
      };
    },
    elect: (options = {}) => runElection(options),
    tick: () => roleTick(),
    heartbeat: () => broadcastHeartbeat(),
    quorumMode: () => quorumMode,
    pendingCount: () => pendingCount(),
    /**
     * 按优先级夺权的状态：attempted 只在本进程尝试过启动期接管后为 true（attempts 恒 ≤ 1）；
     * periodic 是 §A2 周期纠偏的计数与节奏（attempts 累计不超过 max）。
     */
    takeover: () => ({
      attempted: takeoverAttempted,
      attempts: takeoverAttempts,
      stableMs: takeoverStableMs,
      sinceStartMs: config.now() - processStartedAtMs,
      priority: hubPriority,
      leaderPriority: roleState()?.leaderPeerId ? priorityOf(roleState().leaderPeerId) : null,
      periodic: {
        enabled: priorityCorrectionMax > 0,
        attempts: correctionAttempts,
        max: priorityCorrectionMax,
        everyMs: priorityCorrectionMs,
        lastAt: lastCorrectionAtMs,
      },
    }),
    /** §A1：失败选举退避的实时状态（排障/测试用；不含任何密钥或正文） */
    elections: () => {
      const nextAllowedAt = electionAllowedAt();
      return {
        attempts: electionAttempts,
        failures: electionFailures,
        backoffUntil: electionBackoffUntilMs,
        windowCount: electionFailWindow.length,
        nextAllowedAt,
        backoffMs: Math.max(0, nextAllowedAt - config.now()),
      };
    },
    degraded: () => isDegraded(),
    roleFile: roleStore ? roleStore.rolePath : null,
  };
  /**
   * v0.8.0 门面（管理接口/面板/测试共用，不经 HTTP）：
   * 广播、待批准清单与批准/拒绝、本机群身份、已知群只读视图。
   * 成员节点也带一份（广播与 identity 与 hub 同口径；applications 恒为空）。
   */
  function decideApplication(peerId, status) {
    if (!groupStore) return { ok: false, reason: 'not-a-hub' };
    const decided = groupStore.decideApplication(peerId, status);
    if (!decided) return { ok: false, reason: 'unknown-application' };
    if (config.logger) {
      config.logger(
        '[group] application peer=' + shortPeerId(peerId)
        + ' status=' + decided.status
        + (decided.reason == null ? '' : ' reason=' + decided.reason),
      );
    }
    if (decided.status === 'approved') void broadcastGroupName({ reason: 'approve' }).catch(() => {});
    return { ok: true, status: decided.status, reason: decided.reason ?? null };
  }

  /**
   * 待批准清单（契约 §8）：管理接口/面板直接吃这个形状 ——
   * peerId / name / introducedBy / introducedByName / at / status / decidedAt。
   * introducedByName 是渲染用的（介绍人可能已经不在成员表里，那就给空串）。
   */
  function applicationViews() {
    if (!groupStore) return [];
    const members = groupMembersMap();
    const displayNames = groupDisplayNames(members);
    return groupStore.applications().map((entry) => {
      const introducer = members[entry.introducedBy] ? entry.introducedBy : '';
      const introducedByName = introducer === ''
        ? ''
        : (displayNames.get(introducer) ?? String(members[introducer]?.name ?? ''));
      return {
        ...entry,
        // 落盘的是 peerId 字符串（契约 §7）；这里给视图两种形态：
        //   introducedBy        —— { peerId, name }：admin 的 normalizeApplications 只从
        //                          对象形态取介绍人名字（字符串形态它会退化成空串）
        //   introducedByPeerId  —— 纯 peerId，便于脚本直接比对
        //   introducedByName    —— 渲染用名字（成员表里没有介绍人时为空串）
        introducedBy: { peerId: String(entry.introducedBy ?? ''), name: introducedByName },
        introducedByPeerId: String(entry.introducedBy ?? ''),
        introducedByName,
      };
    });
  }

  /** 管理接口的 action 取值归一化：approve/approved/reject/rejected（大小写不敏感） */
  function applicationStatusOf(action) {
    const wanted = String(action ?? '').trim().toLowerCase();
    if (wanted === 'approve' || wanted === 'approved') return 'approved';
    if (wanted === 'reject' || wanted === 'rejected') return 'rejected';
    return '';
  }

  // -------------------------------------------------------------------------
  // v0.8.2-α §1–§3 群内派单：作者侧门面（单例）+ 摘要投影
  //
  // 为什么门面在 host 里：派单的执行侧是「本机作为作者发一次 1:1 ask」，
  // 而回执要写进群。面板/CLI/工具都经这里，避免解析与前置检查写三遍。
  // -------------------------------------------------------------------------

  /** peers.json 的**完整**记录（带 secret）：派单要真签名，脱敏视图不够用 */
  function groupPeersFull() {
    const loaded = store.reloadPeers();
    return Object.entries(loaded.peers ?? {}).map(([peerId, peer]) => ({ peerId, ...peer }));
  }

  /**
   * 群级签名的回执通道（v0.8.0 §18.5 已有能力）：只有群密钥、没和 hub 配对的成员
   * （按名入群）靠它把进度写进群。目标按「leader → hub」顺序试：
   * /v1/group/post 的群级通道只在 hub 上生效，正常情况下 leader 就是 hub 角色。
   */
  async function postGroupReceiptWithGroupKey({ kind, text = '', meta = null }) {
    const ctx = localGroupContext();
    if (!ctx?.groupKey || String(ctx.groupId ?? '') === '') throw new Error('group-key-unavailable');
    const targets = [];
    const leaderId = String(ctx.leaderPeerId ?? '');
    if (leaderId !== '' && leaderId !== store.instanceId) {
      const leaderUrl = baseUrlOf(leaderId);
      if (leaderUrl !== '') targets.push(leaderUrl);
    }
    const hubUrl = String(groupHubPeer()?.baseUrl ?? '').trim().replace(TRAILING_SLASHES, '');
    if (hubUrl !== '' && !targets.includes(hubUrl)) targets.push(hubUrl);
    if (targets.length === 0) throw new Error('group-post-unreachable');
    let lastError = null;
    for (const baseUrl of targets) {
      try {
        const sent = await withGroupKey((keyCtx) => postGroupWithGroupKey({
          baseUrl,
          groupKey: keyCtx.groupKey,
          groupId: String(keyCtx.groupId),
          senderId: store.instanceId,
          kind,
          text,
          meta,
          selfBaseUrl: localAdvertiseBaseUrl(),
          timeoutMs: 5_000,
        }));
        return { ok: true, seq: sent?.seq ?? null };
      } catch (error) {
        lastError = error;
      }
    }
    throw lastError ?? new Error('group-post-failed');
  }

  /**
   * 往群里投一条派单回执（progress/result）。三条通道，按可用性依次降级：
   *   1. hub（有 groupStore）→ 直写 group.json，自己当 leader 时顺手入复制队列；
   *   2. 有 hub 的 per-peer 密钥 → 既有 per-peer 通道打 hub（与 §14 进度镜像同一条路）；
   *   3. 只有群密钥（按名入群）→ 群级签名通道打 leader，leader 未知回落 hub。
   * 只有 2/3 都失败才抛（派单器记 group.error + 一行日志）；回执成败绝不影响派单本身。
   */
  async function postGroupReceipt({ kind, text = '', meta = null }) {
    if (groupStore) {
      const message = groupStore.append({
        peerId: store.instanceId,
        name: config.name,
        kind,
        text,
        meta,
      });
      if (isLocalLeader()) enqueueReplication(message);
      return { ok: true, seq: message?.seq ?? null };
    }
    const hub = groupHubPeer();
    let peerError = null;
    if (hub && hub.secret && hub.baseUrl) {
      try {
        const sent = await postGroup({
          baseUrl: hub.baseUrl,
          secret: hub.secret,
          senderId: store.instanceId,
          kind,
          text,
          meta,
          timeoutMs: 5_000,
        });
        return { ok: true, seq: sent?.seq ?? null };
      } catch (error) {
        peerError = error;
      }
    }
    try {
      return await postGroupReceiptWithGroupKey({ kind, text, meta });
    } catch (error) {
      throw peerError ?? error;
    }
  }

  let groupDispatcher = null;

  /** 派单器单例：限流表与 dispatchState 必须全进程一份 */
  function dispatcher() {
    if (!groupDispatcher) {
      groupDispatcher = createGroupDispatcher({
        config,
        peers: () => groupPeersFull(),
        self: () => ({ instanceId: store.instanceId, name: config.name }),
        post: (payload) => postGroupReceipt(payload),
        memberView: () => groupMembersMap(),
        log: config.logger,
        now: () => config.now(),
      });
    }
    return groupDispatcher;
  }

  /** 本机群功能是否可用（关闭时派单直接回 group-disabled，而不是静默什么都不做） */
  function dispatchFacadeOff() {
    return {
      status: 'failed',
      reason: 'group-disabled',
      target: null,
      targetName: null,
      elapsedMs: 0,
      replyChars: 0,
    };
  }

  /**
   * v0.8.2-α §4：切换本机接单开关（热生效）。
   * 落 <stateDir>/group-dispatch-prefs.json —— 写成功即 persisted=true；
   * 写不了也必须在**本进程**立刻生效，并如实回 persisted=false。
   */
  function setAcceptDispatch(value) {
    const next = value === true || value === 1 || String(value).trim().toLowerCase() === 'true';
    localAcceptDispatch = next;
    config.group.acceptDispatch = next;
    if (groupStore) groupStore.setMemberAcceptDispatch(store.instanceId, next);
    // hub 自己也是成员：本机切换必须立刻落进自己那条 members[]，
    // 否则别的节点（经 pull 掩码 / 群状态）永远读不到这次关闭。
    let persisted = false;
    try {
      writeJson0600(groupPrefsPath, { acceptDispatch: next, updatedAt: new Date(config.now()).toISOString() });
      persisted = true;
    } catch (error) {
      if (config.logger) {
        config.logger('[group] accept-dispatch persist failed: ' + String(error?.message ?? error));
      }
    }
    if (config.logger) {
      config.logger('[group] accept-dispatch local=' + (next ? 'on' : 'off') + ' persisted=' + persisted);
    }
    return { acceptDispatch: next, persisted };
  }

  const dispatchFacade = {
    /**
     * **冻结签名**（Lane Y 的面板/CLI 消费）：
     * dispatch({ target, task }) 或 dispatch({ text })（作者侧解析 @!）
     *   → { status: 'done'|'failed'|'skipped', reason, target, targetName, elapsedMs, replyChars }
     * **只返回摘要**：reply 正文在这里被剥掉，群历史里也只有摘要。
     */
    dispatch: async (input = {}) => {
      if (groupRole === 'off') return dispatchFacadeOff();
      return groupDispatchSummary(await dispatcher().dispatch(input ?? {}));
    },
    /**
     * 内部入口：返回**含 reply** 的完整结果。
     * 只允许 lan_group_ask 工具使用 —— 不得经由任何管理接口或 HTTP 路由暴露；
     * 面板与 CLI 只能拿到 dispatch() 的摘要（契约 §3：正文只回发起方）。
     */
    dispatchWithReply: async (input = {}) => {
      if (groupRole === 'off') {
        return {
          dispatched: false,
          ok: false,
          status: 'failed',
          reason: 'group-disabled',
          target: null,
          targetName: null,
          sessionId: '',
          reply: '',
          replyChars: 0,
          elapsedMs: 0,
          multiTarget: false,
          unknownTarget: false,
          group: { progressSeq: null, resultSeq: null, error: 'group-disabled' },
        };
      }
      return dispatcher().dispatch(input ?? {});
    },
    /** 冻结签名：{ lastTarget, lastAt, inFlight }（只读；群关闭时是空快照） */
    dispatchState: () => (groupRole === 'off'
      ? { lastTarget: null, lastAt: 0, inFlight: false }
      : dispatcher().state()),
    setAcceptDispatch: (value) => setAcceptDispatch(value),
    /** 本机接单开关（面板/群状态同一口径） */
    acceptDispatch: () => acceptDispatchNow(),
  };

  const discoveryFacade = {
    broadcast: (reason = 'manual') => broadcastGroupName({ manual: true, reason }),
    identity: () => localGroupIdentity(),
    knownGroups: () => readKnownGroups(config.stateDir),
    advertiseState: () => readAdvertiseState(config.stateDir),
    nonMemberPeers: () => nonMemberPeers().map(({ peerId, name, baseUrl }) => ({ peerId, name, baseUrl })),
    applications: () => applicationViews(),
    /**
     * 契约 §8 的唯一入口（lib/admin.mjs 的 POST /api/lan-peers/group/applications 走这里）：
     * 入参 { peerId, action }，出参 { ok, status, reason? }。
     */
    decideApplication: ({ peerId, action } = {}) => {
      const status = applicationStatusOf(action);
      if (status === '') return { ok: false, status: '', reason: 'bad-action' };
      if (!groupStore) return { ok: false, status: '', reason: 'not-a-hub' };
      return decideApplication(peerId, status);
    },
    // 便捷别名（测试与脚本用；语义与上面完全一致）
    approveApplication: (peerId) => decideApplication(peerId, 'approved'),
    rejectApplication: (peerId) => decideApplication(peerId, 'rejected'),
  };

  return {
    config,
    store,
    runner,
    httpServer,
    get sessions() {
      return sessions;
    },
    /**
     * v0.5.0 群操作入口（给管理接口 / 面板 / 测试复用，不经 HTTP）：
     * state() 默认脱敏 —— groupKey 只经「成员响应」下发，管理接口不该拿到它。
     * 没有群服务时 enabled=false，调用方据此返回 {enabled:false} 而不是报错。
     */
    group: groupStore
      ? {
          enabled: true,
          isHub: true,
          ...s3Facade,
          ...discoveryFacade,
          ...dispatchFacade,
          state: (options = {}) => groupStore.state(options),
          members: () => groupMembersView(),
          addMember: (peerId, name) => groupStore.addMember(peerId, name),
          /** 被移除名单（只读）：管理接口/测试用它解释「为什么这个 peer 进不来」 */
          isBlocked: (peerId) => groupStore.isBlocked(peerId),
          removeMember: (peerId) => {
            const removed = groupStore.removeMember(peerId);
            if (!removed) return removed;
            const id = String(peerId ?? '');
            memberProgress.delete(id);
            peerBaseUrls.delete(id);
            peerPriorities.delete(id);
            if (config.logger) {
              config.logger(`[group] key rotated keyVersion=${groupStore.state().keyVersion} reason=member-removed`);
            }
            return removed;
          },
          rename: (nextName) => groupStore.renameGroup(nextName),
          post: (input) => groupStore.append(input),
          // 与 /v1/group/history 同一个渲染口径：同名成员在这里就已经带上短 id 后缀
          history: (options = {}) => decoratedMessages(options),
          // §18：归档索引 / 人工删除 / 游标落在归档区间的判定（管理接口与面板走这里）
          archives: () => groupStore.archives(),
          deleteArchive: (file) => groupStore.deleteArchive(file),
          archivedRange: (sinceSeq = 0) => groupStore.archivedRangeFor(sinceSeq),
          archiveDir: () => groupStore.archiveDir,
          lastSeq: () => groupStore.state().lastSeq,
          // S1/S2：地址探测 + 复制队列（测试/CLI 可以直接驱动，不必等定时器）
          advertiseBaseUrl: () => localAdvertiseBaseUrl(),
          local: () => localGroupContext(),
          replica: null,
          flushReplicate: () => flushReplication(),
          pendingReplication: () => [...replicaQueue].map(([peerId, entry]) => ({
            peerId,
            pending: entry.messages.length,
            lastError: entry.lastError,
          })),
        }
      : {
          enabled: false,
          isHub: false,
          ...s3Facade,
          ...discoveryFacade,
          ...dispatchFacade,
          // S2 成员侧：本地副本 + 拉取/推送入口（hub 端点仍在 hub 那边）。
          // v0.8.0：副本可能因「按名入群」在运行期才出现（role 从 off 提升成 member），
          // 所以这里必须是 getter —— 否则门面永远拿到初始化那一刻的 null。
          get replica() {
            if (!replicaStore) return null;
            return {
              state: () => replicaStore.state(),
              messages: (options = {}) => replicaStore.messages(options),
              append: (payload) => replicaStore.append(payload),
              ensureHeader: (payload) => replicaStore.ensureHeader(payload),
              file: replicaStore.replicaPath,
            };
          },
          pull: () => memberTick(),
          advertiseBaseUrl: () => localAdvertiseBaseUrl(),
          local: () => localGroupContext(),
          // §18.3：成员副本是可重建缓存，只剪枝不归档 —— 归档是 hub 侧权威日志的事
          archives: () => [],
          deleteArchive: () => ({ ok: false, reason: 'not-a-hub' }),
          archivedRange: () => null,
        },
    issuePairingCode() {
      return store.issuePairingCode();
    },
    async listen(port = config.listenPort, host = config.listenHost) {
      await new Promise((resolve, reject) => {
        const onError = (err) => {
          httpServer.removeListener('listening', onListening);
          reject(err);
        };
        const onListening = () => {
          httpServer.removeListener('error', onError);
          resolve();
        };
        httpServer.once('error', onError);
        httpServer.once('listening', onListening);
        httpServer.listen(port, host);
      });
      const address = httpServer.address();
      boundAddress = typeof address === 'object' && address ? address : null;
      const actualPort = boundAddress?.port ?? port;
      // S1/S2 都要真实端口：绑定后才探测地址、才启动成员拉取
      refreshSelfBaseUrl();
      if (groupRole === 'member' && !memberTimer) {
        void memberTick();
        memberTimer = setInterval(() => {
          void memberTick();
        }, replicaPullMs);
        memberTimer.unref?.();
      }
      // §18：启动时做一次体积检查 —— 历史遗留的超大 group.json（没有经过本版写入路径）
      // 也要在启动时就归档，否则它会一直拖慢每一次读写。
      if (groupStore) groupStore.state();
      // S3：心跳 / 租约检查。两个定时器都 unref()，close() 里清掉（热重载不留定时器）
      startRoleTimers();
      // v0.8.0 契约 §2a：已入群节点启动后广播一次（延迟到地址已知；节流在广播里生效）
      scheduleStartupAdvertise();
      // v0.8.0：role=off 的节点观察「按名入群」的授权文件（拿到就原地变成员）
      startGrantWatcher();
      return {
        host: boundAddress?.address ?? host,
        port: actualPort,
        url: `http://127.0.0.1:${actualPort}`,
      };
    },
    async close() {
      clearInterval(pendingPairTimer);
      stopRoleTimers();
      if (advertiseTimer) {
        clearTimeout(advertiseTimer);
        advertiseTimer = null;
      }
      if (grantWatchTimer) {
        clearInterval(grantWatchTimer);
        grantWatchTimer = null;
      }
      if (memberTimer) {
        clearInterval(memberTimer);
        memberTimer = null;
      }
      if (replicaRetryTimer) {
        clearInterval(replicaRetryTimer);
        replicaRetryTimer = null;
      }
      if (!httpServer.listening) return;
      const closed = new Promise((resolve) => httpServer.close(resolve));
      httpServer.closeAllConnections?.();
      await closed;
      boundAddress = null;
    },
    url() {
      if (!boundAddress) return null;
      return `http://127.0.0.1:${boundAddress.port}`;
    },
  };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function printUsage() {
  process.stdout.write(`dsh-lan-peers host

Usage:
  node host/server.mjs [options]

Options:
  --name <name>               本机显示名（默认 os.hostname()）
  --host <address>            监听地址（默认 0.0.0.0）
  --port <port>               监听端口（默认 7788）
  --state-dir <dir>           状态目录（默认 ~/.dsh/lan-peers）
  --workspace <dir>           远端会话工作区（默认 <state-dir>/workspace）
  --preset <name>             会话预设（默认 standard）
  --permission <name>         权限预设（默认 read-only）
  --allow-remote-prompts      允许远端派单（默认关闭）
  --trusted-cidr <cidr>       允许的来源网段，可重复；不给则仅回环 + 私网
  --pairing-mode <mode>       配对模式 auto|ecdh|legacy（默认 auto）
  --answer-wait-ms <ms>       /v1/answer 长轮询 hold 上限（默认 25000，上限 25000）
  --group                     启用群聊（本机作为 hub；默认关闭）
  --group-hub <名字|peerId>   成员侧：hub 的名字或 peerId（留空 = 本机就是 hub）
  --group-name <name>         群名（默认 default）
  --group-auto-join           允许已配对成员自助加入（默认关闭）
  --group-retention-days <n>  历史保留天数（默认 7，0 = 读到时立即清旧）
  --group-advertise-base-url <url>  本机对外可达地址（默认自动探测私有 IPv4）
  --group-quorum <mode>       majority|none（S3：majority = propose/commit 两阶段）
  --group-heartbeat-ms <ms>   leader 心跳间隔（默认 3000；租约 = 3×）
  --group-commit-timeout-ms <ms>  propose→commit 超时（默认 3000）
  --group-hub-priority <n>    同 epoch 裁决优先级（数值小者优先，默认 0）
  --group-replica-pull-ms <ms>  成员向 leader 补差间隔（默认 10000）
  --code                      只生成并打印一次性配对码，然后退出
  -h, --help                  显示帮助
`);
}

async function main(argv) {
  const { values } = parseArgs({
    args: argv,
    allowPositionals: false,
    options: {
      name: { type: 'string' },
      host: { type: 'string' },
      port: { type: 'string' },
      'state-dir': { type: 'string' },
      workspace: { type: 'string' },
      preset: { type: 'string' },
      permission: { type: 'string' },
      'allow-remote-prompts': { type: 'boolean', default: false },
      'trusted-cidr': { type: 'string', multiple: true },
      'pairing-mode': { type: 'string' },
      'answer-wait-ms': { type: 'string' },
      group: { type: 'boolean', default: false },
      'group-hub': { type: 'string' },
      'group-name': { type: 'string' },
      'group-auto-join': { type: 'boolean', default: false },
      'group-retention-days': { type: 'string' },
      'group-advertise-base-url': { type: 'string' },
      'group-quorum': { type: 'string' },
      'group-heartbeat-ms': { type: 'string' },
      'group-commit-timeout-ms': { type: 'string' },
      'group-hub-priority': { type: 'string' },
      'group-replica-pull-ms': { type: 'string' },
      code: { type: 'boolean', default: false },
      help: { type: 'boolean', short: 'h', default: false },
    },
  });

  if (values.help) {
    printUsage();
    return;
  }

  const overrides = {
    name: values.name,
    listenHost: values.host,
    listenPort: values.port == null ? undefined : Number(values.port),
    stateDir: values['state-dir'],
    workspace: values.workspace,
    agentPreset: values.preset,
    permission: values.permission,
    allowRemotePrompts: values['allow-remote-prompts'] === true,
    trustedCidrs: values['trusted-cidr'],
    pairingMode: values['pairing-mode'],
    answerWaitMs: values['answer-wait-ms'] == null ? undefined : Number(values['answer-wait-ms']),
    // 群：给了任何 --group* 才覆盖 group 配置，否则保持默认（关闭）
    group: (values.group || values['group-hub'] != null || values['group-name'] != null
      || values['group-auto-join'] || values['group-retention-days'] != null
      || values['group-advertise-base-url'] != null || values['group-quorum'] != null
      || values['group-heartbeat-ms'] != null || values['group-commit-timeout-ms'] != null
      || values['group-hub-priority'] != null
      || values['group-replica-pull-ms'] != null)
      ? {
          enabled: values.group === true,
          hub: typeof values['group-hub'] === 'string' ? values['group-hub'] : undefined,
          name: values['group-name'],
          autoJoin: values['group-auto-join'] === true,
          retentionDays: values['group-retention-days'] == null
            ? undefined
            : Number(values['group-retention-days']),
          advertiseBaseUrl: values['group-advertise-base-url'],
          quorum: values['group-quorum'],
          heartbeatMs: values['group-heartbeat-ms'] == null
            ? undefined
            : Number(values['group-heartbeat-ms']),
          commitTimeoutMs: values['group-commit-timeout-ms'] == null
            ? undefined
            : Number(values['group-commit-timeout-ms']),
          hubPriority: values['group-hub-priority'] == null
            ? undefined
            : Number(values['group-hub-priority']),
          replicaPullMs: values['group-replica-pull-ms'] == null
            ? undefined
            : Number(values['group-replica-pull-ms']),
        }
      : undefined,
  };
  // 未显式给出的项保持 undefined，交给 resolveConfig 走默认值
  for (const key of Object.keys(overrides)) {
    if (overrides[key] === undefined) delete overrides[key];
  }

  if (values.code) {
    const { code, expiresAt } = issuePairingCode(overrides);
    process.stdout.write(
      `lan-peers pairing code: ${code}  (valid until ${nowIso(expiresAt)}, single use)\n`,
    );
    return;
  }

  const server = createPeerServer({ ...overrides, logger: (line) => process.stdout.write(`${line}\n`) });
  const info = await server.listen();
  process.stdout.write(
    `dsh-lan-peers host listening on http://${info.host}:${info.port}  `
    + `name=${server.config.name}  instance=${server.store.instanceId}  `
    + `allowRemotePrompts=${server.config.allowRemotePrompts}\n`,
  );

  const shutdown = async () => {
    await server.close();
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

const isMain = process.argv[1] != null && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  main(process.argv.slice(2)).catch((err) => {
    process.stderr.write(`${err?.stack ?? err}\n`);
    process.exitCode = 1;
  });
}
