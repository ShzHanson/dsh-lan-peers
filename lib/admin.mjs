// dsh-lan-peers · loopback admin API + the self-contained settings panel.
//
// All routes live under /lan-peers/ and require BOTH a loopback Host header and
// the per-process admin token (see ADMIN_TOKEN below), so a LAN browser — or a
// page on any site that reaches 127.0.0.1 — cannot rename this device or mint
// pairing codes. Two routes stay token-free: panel.js (the token is inside it,
// requiring one would deadlock) and client-log (append-only diagnostics).
import { randomBytes, timingSafeEqual } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { callPeer, capabilityOf, pairPeer, probePeer } from '../client/peer-call.mjs';
// v0.5.0 群：配置归一化 + 成员侧端点封装（服务端/客户端共用同一套常量与白名单）。
import {
  GROUP_KINDS, GROUP_REPLICA_FILE, GROUP_TEXT_MAX_CHARS, fetchGroupHistory, fetchGroupState, joinGroup,
  normalizeGroupConfig, postGroup, resolveGroupHub, sanitizeGroupMeta,
} from './group-client.mjs';
// v0.8.0（契约 §2/§3 §4/§5，Lane P 冻结签名）：lookupGroupName / advertiseGroup /
// applyToGroup / pollApplication / readKnownGroups 按命名空间探测 —— 命名导入在函数
// 落地前会让整个模块链接失败，命名空间做不到的事只有一件：静态检查，而这里不需要。
import * as groupClientModule from './group-client.mjs';

const PREFIX = '/api/lan-peers/';

// S3：管理接口的进程级会话 token。模块加载即进程启动，一次生成（32 字节随机），
// 只存在于三个地方：本进程、PANEL_SCRIPT 字面量、<stateDir>/admin-token（0600，给
// CLI/管理脚本）。绝不写进 state.json、URL、日志或错误体。
const ADMIN_TOKEN = randomBytes(32).toString('hex');
const ADMIN_TOKEN_HEADER = 'x-lan-peers-token';
const ADMIN_TOKEN_FILE = 'admin-token';
/** 同进程出口（测试/CLI 复用）；跨进程请读 <stateDir>/admin-token。 */
export const adminToken = () => ADMIN_TOKEN;

// 免 token 的两条路由：panel.js 是静态脚本且 token 就在它里面（要求 token 才能取
// token 是死锁）；client-log 只写审计日志、没有敏感读，老面板还得能上报。
// 两条之外一律要 token —— 只读接口也不例外。
const TOKEN_FREE_ROUTES = new Set(['panel.js', 'client-log']);
const READ_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function isLoopbackHostname(hostname) {
  return hostname === 'localhost' || hostname === '::1' || hostname === '[::1]'
    || /^127(\.\d{1,3}){3}$/.test(hostname);
}

function hostHeader(req) {
  const raw = req && req.headers ? req.headers.host : undefined;
  return typeof raw === 'string' ? raw.trim() : '';
}

/** Host 头必须是回环 authority。缺失不再是放行理由（那正是绕过门禁的形状）。 */
function hostIsLoopback(req) {
  const raw = hostHeader(req);
  if (raw === '') return false;
  let hostname;
  try {
    hostname = new URL(`http://${raw}`).hostname;
  } catch {
    return false;
  }
  return isLoopbackHostname(hostname);
}

/** CSRF：浏览器才带 Origin；带了就必须是回环，'null'（沙箱/文件页）同样拒绝。 */
function originIsLoopback(req) {
  const raw = req && req.headers ? req.headers.origin : undefined;
  const origin = Array.isArray(raw) ? raw[0] : raw;
  if (typeof origin !== 'string' || origin.trim() === '') return true;
  let hostname;
  try {
    hostname = new URL(origin.trim()).hostname;
  } catch {
    return false;
  }
  return isLoopbackHostname(hostname);
}

/** 写操作只收 JSON：text/plain 这类「简单请求」正是跨站表单发得出来的形状。 */
function isJsonContentType(req) {
  const raw = req && req.headers ? req.headers['content-type'] : undefined;
  const value = Array.isArray(raw) ? raw[0] : raw;
  return typeof value === 'string' && /^application\/json\b/i.test(value.trim());
}

/**
 * M6：GET state 的配对视图 —— 只回「有没有码、还剩几秒」，码本身绝不回显。
 * 码只出现在 POST code 那一次响应里（一次性提示），刷面板也拿不回来。
 */
function pairingView(state) {
  const pair = state && typeof state === 'object' ? state.pairingCode : null;
  if (!pair || typeof pair.code !== 'string') return { active: false, expiresInSec: 0 };
  const left = Math.round((Number(pair.expiresAt ?? 0) - Date.now()) / 1000);
  if (!(left > 0)) return { active: false, expiresInSec: 0 };
  return { active: true, expiresInSec: left };
}

function tokenMatches(req) {
  const raw = req && req.headers ? req.headers[ADMIN_TOKEN_HEADER] : undefined;
  const given = Array.isArray(raw) ? raw[0] : raw;
  if (typeof given !== 'string' || given === '') return false;
  const a = Buffer.from(given, 'utf8');
  const b = Buffer.from(ADMIN_TOKEN, 'utf8');
  return a.length === b.length && timingSafeEqual(a, b);
}

function sendJson(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(body));
}

async function readJson(req, limit = 64 * 1024) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) throw new Error('payload too large');
    chunks.push(chunk);
  }
  if (size === 0) return {};
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

function normalizeUrl(input) {
  const raw = String(input ?? '').trim();
  if (raw === '') throw new Error('peer address is required');
  const url = new URL(/^https?:\/\//i.test(raw) ? raw : `http://${raw}`);
  if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new Error('peer address must be http(s)');
  return url.origin;
}

// ---------------------------------------------------------------------------
// v0.5.0 · 群聊（Phase2：只读管理接口 + 面板「群组」页）
//
// 总原则同 DESIGN §5：浏览器永不直连对端。任何 hub 往返都在插件进程里用 hub
// peer 的 secret 完成（lib/group-client.mjs 的 callPeer 封装），浏览器只认回环上
// 的 /api/lan-peers/group*，也拿不到 groupKey。
//
// 两侧来源：
//   hub    → host/server.mjs 暴露的 server.group（本地 group.json，不经 HTTP）
//   成员侧 → lib/group-client.mjs 的 fetchGroupState / fetchGroupHistory /
//            postGroup / joinGroup（hub peer 的 secret 签名 + 加密）
// 启停取自 host 归一化后的 server.config.group（enabled 缺省 false = 关闭）。
const GROUP_NAME_MAX = 64;
const GROUP_HISTORY_LIMIT = 200;
const GROUP_DISABLED_STATE = Object.freeze({
  enabled: false, isHub: false, group: null, messages: [], lastSeq: 0,
});
// v0.7.0 S3（契约 §1/§7）：成员角色三态，其它值一律当「不知道」。
const GROUP_ROLES = Object.freeze(['leader', 'follower', 'candidate']);

// ---- v0.8.0（契约 §3/§5/§6/§7）：群名发现、按名申请、改名查重 ----
// 查重/查找/广播的超时：契约 §3/§6 写死 2 秒，超时即「这个伙伴这次没话说」，绝不算冲突。
const GROUP_DISCOVERY_TIMEOUT_MS = 2000;
// 待批准申请的保留口径（契约 §7）：TTL 24 小时、上限 100 条 —— hub 侧存的与面板看到的一致。
const APPLICATION_TTL_MS = 24 * 3600 * 1000;
const APPLICATIONS_LIMIT = 100;
// 申请状态的三种结果（契约 §5.1）；其它值一律当 unknown（面板据此不写状态行）。
const APPLICATION_STATUSES = Object.freeze(['pending', 'approved', 'rejected']);

/**
 * 群名比较口径（契约 §3）：去空白后大小写不敏感精确匹配。
 * 群名是人类可读标签而不是 id，所以「家里」与「 家里 」是同一个名字。
 */
function groupNameKey(value) {
  return String(value ?? '').replace(/\s+/g, '').toLowerCase();
}

/** 日志里的 id 截断（契约 §9.4：只记前 8 位）。 */
function shortId(value) {
  const id = String(value ?? '');
  return id === '' ? '(empty)' : id.slice(0, 8);
}

/**
 * 时间归一化：数值（毫秒）与 ISO 字符串都收，其余一律 0。
 * 现状：host 落盘的 at 是毫秒数、decidedAt 按契约 §7 是 ISO 字符串（nowIso），
 * 两种形态都会流到这里，所以统一收一遍；这是防御性归一，不是对某个已知 bug 的修补。
 */
function toMillis(value) {
  if (value == null) return 0;
  const numeric = Number(value);
  if (Number.isFinite(numeric) && numeric > 0) return Math.floor(numeric);
  const parsed = Date.parse(String(value));
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
}

/**
 * 待批准申请的视图归一化（契约 §7/§8）。
 * 存储里是 { [applicantPeerId]: { name, baseUrl, introducedBy, at, status, decidedAt } }，
 * 介绍人可能是 peerId 字符串，也可能是 { peerId, name }；两种都归一成同一形状，
 * 面板只认这一个形状。TTL 24 小时与 100 条上限在这里统一裁掉。
 */
function normalizeApplications(raw, nowMs = Date.now()) {
  const list = [];
  const take = (peerId, entry) => {
    if (!entry || typeof entry !== 'object') return;
    // at 现状是毫秒数（host/server.mjs 落盘即归一成 ms）；ISO 也接受，纯属防御
    const stamp = toMillis(entry.at);
    if (stamp > 0 && nowMs - stamp > APPLICATION_TTL_MS) return;
    const by = entry.introducedBy;
    const introducedBy = String((by && typeof by === 'object' ? by.peerId : by) ?? '');
    // 三元表达式在字符串形态下返回 ''（不是 nullish），所以这里只能串 ||：
    // 对象形态优先 by.name，其次宿主另给的 introducedByName/introducerName。
    const introducedByName = String(
      (by && typeof by === 'object' ? by.name : '') || entry.introducedByName || entry.introducerName || '',
    );
    const status = APPLICATION_STATUSES.includes(String(entry.status ?? '')) ? String(entry.status) : 'pending';
    list.push({
      peerId: String(peerId),
      name: String(entry.name ?? ''),
      introducedBy,
      introducedByName,
      at: stamp,
      status,
      // decidedAt 契约 §7 落的是 ISO 字符串：归一成毫秒，缺失/不可解析才是 null
      decidedAt: toMillis(entry.decidedAt) || null,
    });
  };
  if (Array.isArray(raw)) {
    for (const entry of raw) take(String(entry?.peerId ?? ''), entry);
  } else if (raw && typeof raw === 'object') {
    for (const [peerId, entry] of Object.entries(raw)) take(peerId, entry);
  }
  return list
    .filter((entry) => entry.peerId !== '')
    .sort((a, b) => b.at - a.at)
    .slice(0, APPLICATIONS_LIMIT);
}

/**
 * 归档索引归一化（DESIGN §18.1/§18.2）：host 写的是
 * { file, fromSeq, toSeq, count, bytes, createdAt }，面板/CLI/接口只认这一种形状。
 * 缺 file 的条目直接丢掉（没有文件名就删不掉，也没法描述）；数字字段不可解析时给 null，
 * 不把 NaN 写进 JSON（面板会显示成 NaN）。
 */
function normalizeArchives(raw) {
  const list = [];
  for (const entry of Array.isArray(raw) ? raw : []) {
    if (!entry || typeof entry !== 'object') continue;
    const file = String(entry.file ?? '').trim();
    if (file === '') continue;
    const num = (value) => {
      // Number(null) 是 0、Number('') 也是 0：缺值要先认出来，否则「没给」会显示成 0。
      if (value == null || value === '') return null;
      const numeric = Number(value);
      return Number.isFinite(numeric) && numeric >= 0 ? Math.floor(numeric) : null;
    };
    list.push({
      file,
      fromSeq: num(entry.fromSeq),
      toSeq: num(entry.toSeq),
      count: num(entry.count),
      bytes: num(entry.bytes) ?? 0,
      createdAt: toMillis(entry.createdAt) || null,
    });
  }
  // 新的在前：最近归档的更可能是用户想删的那个
  return list.sort((a, b) => (b.fromSeq ?? 0) - (a.fromSeq ?? 0));
}

function parseSinceSeq(raw) {
  const value = Number(String(raw ?? '').trim());
  if (!Number.isFinite(value) || value < 0) return 0;
  return Math.floor(value);
}

/** seq/epoch 的三态取值：缺失或非法一律 null（面板据此区分「0」和「不知道」）。 */
function asSeqOrNull(value) {
  if (value == null) return null;
  const numeric = Number(value);
  return Number.isFinite(numeric) && numeric >= 0 ? Math.floor(numeric) : null;
}

/**
 * 成员副本读取器（host 外壳没有 replica 入口时的兜底）：
 * 只服务面板显示，缺文件/坏 JSON 一律当作「没有副本」（null）。
 * 用 mtime+size 命中缓存，避免 2s 轮询反复反序列化 5000 条消息。
 */
function createReplicaReader(stateDirOf) {
  let cached = { stamp: '', value: null };
  return () => {
    const dir = String(stateDirOf() ?? '').trim();
    if (dir === '') return null;
    const file = path.join(dir, GROUP_REPLICA_FILE);
    let stat;
    try {
      stat = fs.statSync(file);
    } catch {
      return null;
    }
    const stamp = String(stat.mtimeMs) + ':' + String(stat.size);
    if (cached.stamp === stamp) return cached.value;
    let value = null;
    try {
      const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
        // 面板只用得到「副本已经到第几条」；细节以 host 的 ReplicaStore 为准
        value = { lastSeq: asSeqOrNull(raw.lastSeq) ?? 0 };
      }
    } catch {
      value = null;
    }
    cached = { stamp, value };
    return value;
  };
}

function errorStatus(error, fallback) {
  const status = Number(error?.status);
  if (Number.isInteger(status) && status >= 400 && status <= 599) return status;
  // group-client 的 callPeer 抛的是 `${status} ${error}` 形式的 Error（没有 status 字段）
  const match = /^(\d{3})\b/.exec(String(error?.message ?? ''));
  const parsed = match ? Number(match[1]) : Number.NaN;
  return Number.isInteger(parsed) && parsed >= 400 && parsed <= 599 ? parsed : fallback;
}

/**
 * 成员视图 = 契约 §3 的五个字段（hub 的 members() 已按此形状给出）
 * + v0.6.0 S1/S2 追加的 baseUrl / lastSeq / lag（后端没给就是 ''/null，老消费者不受影响）。
 */
function memberView(member) {
  return {
    peerId: String(member?.peerId ?? ''),
    name: String(member?.name ?? ''),
    online: member?.online === true,
    lastSeen: member?.lastSeen ?? null,
    joinedAt: member?.joinedAt ?? null,
    // baseUrl 是「别人看到的本机地址」（S1 的 probe 记录），lastSeq 是该成员的复制进度（S2）
    baseUrl: typeof member?.baseUrl === 'string' ? member.baseUrl : '',
    lastSeq: asSeqOrNull(member?.lastSeq),
    lag: asSeqOrNull(member?.lag),
    // v0.8.2-α（契约 §4）：该成员是否接单。老对端没有这个字段 = 接单（向后兼容），
    // 只有明确的 false 才算「已关闭」—— 缺字段绝不能被读成「关闭」。
    acceptDispatch: member?.acceptDispatch !== false,
  };
}

/**
 * 派单回执的三种终态（契约 §3，0.8.2-α 修订版）：只认这三个值，其它一律按 failed 处理。
 * skipped = 这条消息根本没有 @! 目标（reason=no-target）：零消息写入，绝不算「完成」，
 * 更不能显示成 done —— 让用户以为派了一单而其实什么都没发生，就是谎报。
 */
const DISPATCH_STATUSES = Object.freeze(['done', 'failed', 'skipped']);

/**
 * 契约 §1（作者侧语法）：`@!<名字>` = 派单，`@<名字>` = 纯提及（零动作）。
 *
 * 只取第一个 `@!`；名字 = `@!` 之后第一段非空白（名字里含空格时用短 id / peerId 前 8 位），
 * 任务 = 整条 text 去掉这一段后的 trim（可以为空串 —— 是否拒绝由 host 按 reason=empty 判定）。
 * 多出来的 `@!` 不整条拒绝，只回一个 extraTargets 计数让 host 记 reason=multi-target-ignored。
 *
 * 面板（管理接口的 group/post）与 CLI（group dispatch）共用这一份解析，避免两套口径。
 */
export function parseGroupDispatchCommand(text) {
  const body = typeof text === 'string' ? text : String(text ?? '');
  const matches = [...body.matchAll(/@!([^\s]+)/gu)];
  if (matches.length === 0) return null;
  const first = matches[0];
  const at = Number(first.index ?? 0);
  const before = body.slice(0, at).trimEnd();
  const after = body.slice(at + first[0].length).trimStart();
  return {
    target: first[1],
    // 接缝处补一个空格（"顺手看看 @!nas 日志" → "顺手看看 日志"），其余空白原样保留。
    task: (before === '' || after === '' ? before + after : before + ' ' + after).trim(),
    extraTargets: matches.length - 1,
  };
}

/**
 * 派单回执归一化（契约 §3）：只保留摘要字段，正文与任何多余字段在这里就被丢掉，
 * 所以管理接口与面板也不可能拿到「回复全文」。
 */
function normalizeDispatchOutcome(out, target) {
  const data = out && typeof out === 'object' ? out : {};
  const status = DISPATCH_STATUSES.includes(String(data.status ?? '')) ? String(data.status) : 'failed';
  const elapsed = Number(data.elapsedMs);
  const chars = Number(data.replyChars);
  const given = data.reason == null ? '' : String(data.reason).slice(0, 40);
  // 缺省 reason 按终态补齐：failed 是 error、skipped 是 no-target（面板文案依赖它，不能是空串）。
  const reason = given !== '' ? given : (status === 'failed' ? 'error' : (status === 'skipped' ? 'no-target' : ''));
  return {
    target: String(data.target ?? target ?? ''),
    targetName: data.targetName == null ? '' : String(data.targetName).slice(0, 64),
    status,
    reason,
    elapsedMs: Number.isFinite(elapsed) && elapsed >= 0 ? Math.round(elapsed) : null,
    replyChars: Number.isFinite(chars) && chars >= 0 ? Math.round(chars) : null,
  };
}

/**
 * In-memory feed of lan_peer_ask dispatches, so the panel can show a live
 * running/done view (: elapsed time included) without exposing peer secrets or
 * prompt text. Entries are pruned keepMs after they settle.
 */
export function createDispatchFeed({ now = () => Date.now(), keepMs = 5 * 60_000 } = {}) {
  const entries = new Map();
  let counter = 0;

  const prune = () => {
    for (const [id, entry] of entries) {
      if (entry.finishedAt && now() - entry.finishedAt > keepMs) entries.delete(id);
    }
  };

  return {
    begin(info = {}) {
      prune();
      counter += 1;
      const id = 'dsp-' + now().toString(36) + '-' + counter;
      entries.set(id, {
        id,
        peer: '',
        peerId: '',
        sessionId: '',
        status: 'running',
        transport: '',
        timeoutSec: 0,
        startedAt: now(),
        updatedAt: now(),
        ...info,
      });
      return id;
    },
    update(id, patch = {}) {
      const entry = entries.get(id);
      if (!entry) return;
      Object.assign(entry, patch, { updatedAt: now() });
    },
    finish(id, patch = {}) {
      const entry = entries.get(id);
      if (!entry) return;
      Object.assign(entry, patch, { updatedAt: now(), finishedAt: now() });
    },
    list() {
      prune();
      return [...entries.values()]
        .map((entry) => ({ ...entry, elapsedMs: (entry.finishedAt ?? now()) - entry.startedAt }))
        .sort((left, right) => right.startedAt - left.startedAt);
    },
  };
}

/**
 * Ask a peer to delete its record of us ("you have been unpaired").
 *
 * Best effort by contract: every failure path returns a reason instead of
 * throwing, because the local delete must happen no matter what the peer says.
 * The capability gate keeps a 0.3.1 peer from being asked for an endpoint it
 * does not have.
 */
async function notifyPeerUnpair({ peer, senderId, probeMs = 2000, callMs = 5000 }) {
  const baseUrl = String(peer?.baseUrl ?? '').trim().replace(/\/+$/, '');
  if (baseUrl === '') return { notified: false, reason: 'no-address' };
  if (!peer?.secret) return { notified: false, reason: 'no-secret' };
  const health = await probePeer({ baseUrl, timeoutMs: probeMs, fresh: true });
  if (!health?.online) return { notified: false, reason: 'unreachable' };
  if (!capabilityOf(health).includes('unpair')) return { notified: false, reason: 'unsupported' };
  try {
    await callPeer({
      baseUrl,
      secret: peer.secret,
      senderId,
      method: 'POST',
      apiPath: '/v1/unpair',
      timeoutMs: callMs,
    });
    return { notified: true };
  } catch (error) {
    return { notified: false, reason: String(error?.message ?? error) };
  }
}

export function createAdmin({
  server, nameOf, rename, feed = null, pairing = {},
  // v0.5.0：group 覆盖 cordis 配置（测试/显式接线），groupApi 整块替换群后端。
  group = null, groupApi = null,
  // v0.8.0：Lane P 的发现/申请五个函数按冻结签名注入（测试桩 / host 显式接线）；
  // 不注入时退回 group-client.mjs 的命名空间导出，P 落地后自动生效。
  // applyGrant(grant) 是「收到 grant 后写 group-key.json」的接线点（host 侧负责），
  // 缺席时群密钥只会被丢弃，绝不进浏览器或日志。
  groupNet = null, applyGrant = null,
}) {
  // The desktop window has no reachable devtools, so client-side failures are
  // invisible there; the client half reports them here and they land in the
  // plugin log next to the server lines.
  const clientLog = typeof server?.config?.logger === 'function'
    ? server.config.logger
    : () => {};
  const store = server.store;
  const pairingMode = ['auto', 'ecdh', 'legacy'].includes(pairing.mode) ? pairing.mode : 'auto';

  // ---- v0.5.0 群聊：hub 读本地存储，成员侧用 hub peer 的 secret 走 /v1/group/* ----
  const groupOverride = group;
  const groupApiOverride = groupApi;

  const groupSettings = () => normalizeGroupConfig(
    groupOverride ?? (server && server.config ? server.config.group : null),
  );

  // host 侧的群外壳：hub 有存储，成员侧有本地副本（enabled=false 但 replica/advertiseBaseUrl 可用）。
  const groupFacade = () => (server && server.group && typeof server.group === 'object' ? server.group : null);
  const hubFacade = () => {
    const facade = groupFacade();
    return facade && facade.enabled === true ? facade : null;
  };

  /** S1：优先用 host 的地址探测（知道真实监听端口），拿不到再退回本文件的口径。 */
  const coreAdvertise = () => {
    const facade = groupFacade();
    if (!facade || typeof facade.advertiseBaseUrl !== 'function') return '';
    try {
      const value = facade.advertiseBaseUrl();
      return typeof value === 'string' ? value.trim().replace(/\/+$/, '') : '';
    } catch {
      return '';
    }
  };

  /** 本机群上下文（host 门面口径）：null = 本机还没有群（未启用，或成员还没 bootstrap）。 */
  const coreLocal = () => {
    const facade = groupFacade();
    if (!facade || typeof facade.local !== 'function') return null;
    try {
      const ctx = facade.local();
      return ctx && typeof ctx === 'object' ? ctx : null;
    } catch {
      return null;
    }
  };

  /** S2：成员副本优先用 host 的 ReplicaStore，老版本（无此入口）才自己读文件。 */
  const coreReplica = () => {
    const facade = groupFacade();
    const replica = facade ? facade.replica : null;
    if (!replica || typeof replica.state !== 'function') return null;
    try {
      const state = replica.state();
      return state && typeof state === 'object' ? state : null;
    } catch {
      return null;
    }
  };

  /**
   * 把 group.hub（名字或 peerId）解析成 peers.json 里的**完整**记录。
   *
   * 必须两步：listPeers() 是给 /v1/peers 的脱敏视图（只有 peerId/name/baseUrl，
   * **没有 secret**），只够认出「是谁」；拿到 peerId 后要用 getPeer() 取带
   * secret/baseUrl 的记录，否则组不出签名请求（真机表现为
   * 「hub peer has no address/secret」）。
   */
  const groupHubPeer = (settings) => {
    const hub = String(settings?.hub ?? '').trim();
    if (hub === '') return null;
    const list = typeof store?.listPeers === 'function' ? store.listPeers() : [];
    // 第一步：脱敏视图按 peerId 或名字匹配
    const found = resolveGroupHub(Array.isArray(list) ? list : [], hub) ?? null;
    if (typeof store?.getPeer !== 'function') return found;
    // 第二步：完整记录（found 为空时也试一次：hub 可能直接写的是 peerId）
    const full = store.getPeer(String(found?.peerId ?? hub));
    return full ? { ...found, ...full } : found;
  };

  const rawGroupConfig = () => {
    const raw = groupOverride ?? (server && server.config ? server.config.group : null);
    return raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  };

  /**
   * 契约 S1 的 advertiseBaseUrl 来源判定。
   * 归一化后的配置（group-client 的 normalizeGroupConfig）与原始配置都读一遍：
   * 前者是当前口径，后者保证归一化还没带上该字段时配置同样生效。
   */
  const configuredAdvertise = () => {
    const value = groupSettings().advertiseBaseUrl ?? rawGroupConfig().advertiseBaseUrl;
    return typeof value === 'string' ? value.trim().replace(/\/+$/, '') : '';
  };

  /**
   * 生效的对外地址：config 优先，否则就用 host 的探测结果（它知道真实监听端口，
   * 也是写进群状态 members[].baseUrl 的同一个值 —— 面板据此判断「别人看到的对不对」）。
   * 这里绝不另起一套探测口径，否则两个口径一旦不一致就会误报地址提示。
   */
  const advertiseAddress = () => {
    const configured = configuredAdvertise();
    if (configured !== '') return { baseUrl: configured, source: 'config' };
    const detected = coreAdvertise();
    return { baseUrl: detected, source: detected === '' ? 'none' : 'auto' };
  };

  /** 本机 state 目录：group.json / group-replica.json / known-groups.json 都住在这里。 */
  const stateDirOf = () => {
    const fromStore = typeof store?.stateDir === 'string' ? store.stateDir : '';
    if (fromStore !== '') return fromStore;
    const fromConfig = server?.config?.stateDir;
    return typeof fromConfig === 'string' ? fromConfig : '';
  };

  /**
   * S3：把进程 token 落到 <stateDir>/admin-token（0600），CLI/管理脚本从这里读。
   * 写不进去不影响本进程的校验（只是 CLI 拿不到 token，会看到 401 token-required），
   * 所以这里绝不抛错、也绝不把 token 写进日志。
   */
  let adminTokenFile = '';
  const writeAdminTokenFile = () => {
    if (adminTokenFile !== '') return adminTokenFile;
    const dir = stateDirOf();
    if (dir === '') return '';
    try {
      fs.mkdirSync(dir, { recursive: true });
      const file = path.join(dir, ADMIN_TOKEN_FILE);
      fs.writeFileSync(file, ADMIN_TOKEN + '\n', { mode: 0o600 });
      // 已存在的文件 mode 不会因 writeFileSync 改变，显式补一次 0600。
      fs.chmodSync(file, 0o600);
      adminTokenFile = file;
      return file;
    } catch {
      return '';
    }
  };
  writeAdminTokenFile();

  const readReplica = createReplicaReader(stateDirOf);

  /**
   * v0.8.0：Lane P 冻结签名的解析器。注入优先（测试桩 / host 显式接线），
   * 其次 group-client.mjs 的命名空间导出（P 落地后同名自动生效），两者都没有就是 null，
   * 调用方据此降级（查重跳过、广播/查找回 501），既有路由行为不受影响。
   */
  const netFn = (name) => {
    // 注入里**显式**给了这个名字就以它为准：函数=用，null=本轮关掉这项能力
    // （测试要跑「P 未接线」的降级分支，接线方也可能只想开一部分）。
    if (groupNet && Object.prototype.hasOwnProperty.call(groupNet, name)) {
      return typeof groupNet[name] === 'function' ? groupNet[name] : null;
    }
    const fromModule = groupClientModule[name];
    return typeof fromModule === 'function' ? fromModule : null;
  };

  /**
   * 收到 grant 后写 group-key.json 的落盘口（契约 §5：申请者的最后一步）。
   * 优先注入（host 有自己的存储口径时用它），否则用 group-client 的 applyGroupGrant
   * 写本机 stateDir —— 没有 stateDir 就没有落盘口，grant 只能被丢弃（绝不进浏览器）。
   */
  const grantWriter = () => {
    if (typeof applyGrant === 'function') return applyGrant;
    const dir = stateDirOf();
    if (dir === '' || typeof groupClientModule.applyGroupGrant !== 'function') return null;
    return (grant) => groupClientModule.applyGroupGrant(dir, grant);
  };

  /**
   * 已配对且「能签名」的伙伴（peers.json 的脱敏视图没有 secret，必须再取完整记录）。
   * 查重/查找/广播都只走这一条路径：没有地址或没有密钥的伙伴不是可达邻域。
   */
  const signablePeers = () => {
    const list = typeof store?.listPeers === 'function' ? store.listPeers() : [];
    const out = [];
    for (const summary of Array.isArray(list) ? list : []) {
      const peerId = String(summary?.peerId ?? '');
      if (peerId === '') continue;
      const full = typeof store?.getPeer === 'function' ? store.getPeer(peerId) : null;
      const peer = full ? { ...summary, ...full } : summary;
      if (!peer.baseUrl || !peer.secret) continue;
      out.push({ peerId, name: String(peer.name ?? ''), baseUrl: String(peer.baseUrl), secret: peer.secret });
    }
    return out;
  };

  const selfIdentity = () => ({
    peerId: String(store?.instanceId ?? ''),
    name: String(typeof nameOf === 'function' ? nameOf() : ''),
  });

  /**
   * 契约 §3/§6：向所有已配对伙伴并发 lookup，2 秒超时。
   * 任何一路失败都只记一行日志（不抛、不聚合），因为查重范围是「可达邻域」而不是权威注册表：
   * 一个伙伴掉线不该让用户永远改不了群名。命中按 groupId 去重，后到的只补 via。
   */
  const lookupEveryPeer = async ({ name, timeoutMs = GROUP_DISCOVERY_TIMEOUT_MS }) => {
    const lookup = netFn('lookupGroupName');
    const peers = signablePeers();
    if (!lookup) return { matches: [], failed: 0, checked: peers.length, unsupported: true };
    const senderId = String(store?.instanceId ?? '');
    const settled = await Promise.all(peers.map(async (peer) => {
      try {
        const out = await lookup({ baseUrl: peer.baseUrl, secret: peer.secret, senderId, name, timeoutMs });
        return { peer, matches: Array.isArray(out?.matches) ? out.matches : [], error: '' };
      } catch (error) {
        clientLog('[admin] group lookup peer=' + shortId(peer.peerId) + ' failed: '
          + String(error?.message ?? error).slice(0, 80));
        return { peer, matches: [], error: String(error?.message ?? error) };
      }
    }));
    const seen = new Map();
    let failed = 0;
    for (const item of settled) {
      if (item.error !== '') { failed += 1; continue; }
      for (const match of item.matches) {
        if (!match || typeof match !== 'object') continue;
        const groupId = String(match.groupId ?? '');
        if (groupId === '' || seen.has(groupId)) continue;
        seen.set(groupId, {
          groupId,
          name: String(match.name ?? ''),
          hub: match.hub && typeof match.hub === 'object' ? match.hub : null,
          via: { peerId: item.peer.peerId, name: item.peer.name },
        });
      }
    }
    return { matches: [...seen.values()], failed, checked: peers.length, unsupported: false };
  };

  /**
   * 契约 §2(a)/§6.4：把群名广播给「已配对但不在群里」的伙伴。
   * 成员集合由调用方从群状态快照给出（hub 与注入后端同一口径），所以这里只做发送与计数。
   */
  const broadcastGroupName = async ({ memberIds, groupId, name }) => {
    const advertise = netFn('advertiseGroup');
    const self = selfIdentity();
    const targets = signablePeers().filter((peer) => !memberIds.has(String(peer.peerId)));
    if (!advertise) return { targets: targets.length, sent: 0, unsupported: true };
    const hub = { peerId: self.peerId, name: self.name, baseUrl: advertiseAddress().baseUrl };
    const member = { peerId: self.peerId, name: self.name };
    let sent = 0;
    await Promise.all(targets.map(async (peer) => {
      try {
        await advertise({ baseUrl: peer.baseUrl, secret: peer.secret, senderId: self.peerId, groupId, name, hub, member });
        sent += 1;
      } catch (error) {
        clientLog('[admin] group advertise peer=' + shortId(peer.peerId) + ' failed: '
          + String(error?.message ?? error).slice(0, 80));
      }
    }));
    return { targets: targets.length, sent, unsupported: false };
  };

  /** 群状态快照里的成员 id 集合（广播对象 = 伙伴 - 成员）。 */
  const memberIdsOf = (snapshot) => new Set(
    (Array.isArray(snapshot?.members) ? snapshot.members : []).map((member) => String(member?.peerId ?? '')),
  );

  /** 本机 known-groups（契约 §3：先查本地，未命中再问伙伴）；Lane P 缺席或无文件时是空表。 */
  const localKnownGroups = async () => {
    const read = netFn('readKnownGroups');
    if (!read) return [];
    try {
      const out = await read(stateDirOf());
      const groups = out && typeof out === 'object' ? (out.groups ?? {}) : {};
      if (!groups || typeof groups !== 'object') return [];
      return Object.entries(groups).map(([groupId, entry]) => ({
        groupId,
        name: String(entry?.name ?? ''),
        hub: entry?.hub && typeof entry.hub === 'object' ? entry.hub : null,
        source: entry?.source && typeof entry.source === 'object' ? entry.source : null,
      }));
    } catch (error) {
      clientLog('[admin] group known-groups read failed: ' + String(error?.message ?? error).slice(0, 80));
      return [];
    }
  };

  /** 群状态成员表里的名字（找不到就是空串）：给「真 leader 不是本机」时用。 */
  const memberNameOf = (snapshot, peerId) => {
    if (peerId === '') return '';
    const list = Array.isArray(snapshot?.members) ? snapshot.members : [];
    const found = list.find((member) => String(member?.peerId ?? '') === peerId);
    return String(found?.name ?? '');
  };

  /**
   * S1：leader —— 没有选举信息时，hub 侧就是本机，成员侧就是 group.hub 指向的那个 peer。
   *
   * S3：角色门面说了算的两个字段：
   *   - `epoch` 取选举世代（群元数据那份是 group.json 的 keyVersion 世代，真机上出现
   *     过「leader.epoch=1 而状态行 epoch=3」的打架）；
   *   - `leaderPeerId` 取真 leader（配置上是 hub 的机器可能输掉选举，那时 selfRole 仍是
   *     hub、role 是 follower，leader 必须是赢家，而不是本机）。
   * 门面缺席（老 host / 未接线）时两者都回退到 S1 的旧口径，行为不变。
   */
  const leaderOf = (snapshot, resolved, face = null) => {
    const epoch = asSeqOrNull(face?.epoch) ?? asSeqOrNull(snapshot?.epoch);
    const declared = face && typeof face === 'object' ? face.leaderPeerId : undefined;
    const declaredId = declared == null ? '' : String(declared);
    if (declaredId !== '') {
      const fromMembers = memberNameOf(snapshot, declaredId);
      // 成员表里查不到时：若声明的 leader 就是本机，仍用本机名称（别把 peerId 当名字显示）；
      // 是别的机器就退到 peerId（面板会原样显示，不会编名字）。
      const name = fromMembers !== ''
        ? fromMembers
        : (declaredId === String(store?.instanceId ?? '')
          ? String(typeof nameOf === 'function' ? nameOf() : '')
          : declaredId);
      return { peerId: declaredId, name, epoch };
    }
    if (resolved.isHub === true) {
      return {
        peerId: String(store?.instanceId ?? ''),
        name: String(typeof nameOf === 'function' ? nameOf() : ''),
        epoch,
      };
    }
    let peer = null;
    try {
      peer = groupHubPeer(resolved.settings ?? groupSettings());
    } catch {
      peer = null;
    }
    return {
      peerId: String(peer?.peerId ?? snapshot?.leaderPeerId ?? ''),
      name: String(peer?.name ?? ''),
      epoch,
    };
  };

  /** S2：本机副本落后 leader 多少条（副本不存在时一律 null，不假装同步）。 */
  const replicaView = (record, leaderLastSeq) => {
    const lastSeq = record ? record.lastSeq : null;
    return {
      lastSeq,
      leaderLastSeq,
      lag: lastSeq == null ? null : Math.max(0, leaderLastSeq - lastSeq),
    };
  };

  /**
   * S3：host 的角色门面。契约 §7 要求「字段来源优先 host 的 server.group 门面」，
   * 兼容两种接线：`role()` 函数（与 advertiseBaseUrl/local 同款）或带 `state()`
   * 的对象。host 还没接线时返回 null（面板/接口按契约形状降级，不报错）。
   */
  const roleFace = () => {
    const facade = groupFacade();
    if (!facade) return null;
    try {
      const raw = typeof facade.role === 'function'
        ? facade.role()
        : (facade.role && typeof facade.role.state === 'function' ? facade.role.state() : null);
      return raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : null;
    } catch {
      return null;
    }
  };

  /**
   * S3（契约 §7）：role / leaseUntil / quorum / commitSeq / pendingCount / degraded。
   * 来源优先级：host 门面 > 群状态快照 > 本文件兜底（hub=leader，成员=follower）。
   * 缺字段时给保守值而不是编造报警：只有「明确没有 leader」或「租约已过期」才算 degraded。
   */
  const roleView = ({ isHub, settings, snapshot = null, leader = null, lastSeq = null, state = null }) => {
    const face = state ?? roleFace() ?? {};
    const snap = snapshot && typeof snapshot === 'object' ? snapshot : {};
    const known = [face.role, snap.role].find((value) => GROUP_ROLES.includes(String(value ?? '')));
    const leaseUntil = asSeqOrNull(face.leaseUntil) ?? asSeqOrNull(snap.leaseUntil);
    // 可见的 lastSeq 就是已提交序号：未提交消息不进 messages/history/pull（契约 §5）
    const commitSeq = asSeqOrNull(face.commitSeq) ?? asSeqOrNull(snap.commitSeq) ?? asSeqOrNull(lastSeq);
    const pendingCount = asSeqOrNull(face.pendingCount) ?? asSeqOrNull(snap.pendingCount) ?? 0;
    const quorum = String(settings?.quorum ?? '') === 'none' ? 'none' : 'majority';
    // 只有门面**明确**给出 leaderPeerId 才以它为准；否则沿用 S1 的 leader 口径，
    // 免得把「老 hub 不报 leaderPeerId」误判成「当前没有 leader」。
    const declared = Object.prototype.hasOwnProperty.call(face, 'leaderPeerId') ? face.leaderPeerId : undefined;
    const leaderId = declared === undefined ? String(leader?.peerId ?? '') : String(declared ?? '');
    const degraded = leaderId === '' || (leaseUntil !== null && Date.now() > leaseUntil);
    return {
      role: known === undefined ? (isHub ? 'leader' : 'follower') : String(known),
      leaseUntil,
      quorum,
      commitSeq,
      pendingCount,
      degraded,
    };
  };

  /** S3：host 侧手动接管入口（契约 §7 的 POST /api/lan-peers/group/leader）。 */
  const coreClaim = () => {
    const facade = groupFacade();
    if (!facade || typeof facade.claim !== 'function') {
      const error = new Error('claim-unsupported');
      error.status = 501;
      throw error;
    }
    return facade.claim();
  };

  /**
   * 契约 §4（本机接单开关）：「热生效 + 写 profile 配置」是 host 的事（只有它知道配置怎么落盘），
   * 管理接口与面板只转发这一个动作。门面没接线时如实回 501 —— 绝不在本文件里改内存配置冒充成功：
   * 那会变成「面板说已关闭、重启后又悄悄打开」的假成功。
   */
  const coreSetAcceptDispatch = (value) => {
    const facade = groupFacade();
    if (!facade || typeof facade.setAcceptDispatch !== 'function') {
      const error = new Error('accept-toggle-unsupported');
      error.status = 501;
      throw error;
    }
    const out = facade.setAcceptDispatch(value);
    const raw = out && typeof out === 'object' ? out.acceptDispatch : out;
    return {
      acceptDispatch: raw !== false,
      persisted: out !== null && typeof out === 'object' && out.persisted === true,
    };
  };

  /**
   * 本机接单开关的当前值。优先问 host 门面（它知道运行期热切换与落盘覆盖），
   * 门面没有这个读口时退回原始配置 —— 缺字段 = 接单中，绝不读成「已关闭」。
   */
  const coreAcceptDispatch = () => {
    const facade = groupFacade();
    if (facade && typeof facade.acceptDispatch === 'function') {
      try {
        const value = facade.acceptDispatch();
        if (typeof value === 'boolean') return value;
      } catch {
        // 门面读失败就退回配置口径，面板不至于因为一次读取异常显示错状态
      }
    }
    return rawGroupConfig().acceptDispatch !== false;
  };

  /** 契约 §5：本机派单实时状态（面板状态行）。门面没有这个入口就返回 null，不编造。 */
  const coreDispatchState = () => {
    const facade = groupFacade();
    if (!facade || typeof facade.dispatchState !== 'function') return null;
    try {
      const out = facade.dispatchState();
      return out && typeof out === 'object' ? out : null;
    } catch {
      return null;
    }
  };

  /**
   * 契约 §3：作者侧派单。正文只回 1:1 发起方，**不会**出现在这里的返回值里，
   * 因此管理接口与面板从结构上就拿不到正文。
   */
  const coreDispatch = async ({ target, task, extraTargets = 0 }) => {
    const facade = groupFacade();
    if (!facade || typeof facade.dispatch !== 'function') {
      const error = new Error('dispatch-unsupported');
      error.status = 501;
      throw error;
    }
    const out = await facade.dispatch({ target, task, extraTargets });
    return normalizeDispatchOutcome(out, target);
  };

  /**
   * 派单失败不连带已经发出的那条群消息：异常在这里压成 failed 摘要（reason 只留一句话），
   * 调用方据此决定是回 dispatch 字段还是只写日志。
   */
  const settledDispatch = async (command) => {
    try {
      const outcome = await coreDispatch(command);
      clientLog('[admin] group dispatch target=' + shortId(command.target) + ' status=' + outcome.status
        + ' reason=' + (outcome.reason === '' ? '-' : outcome.reason)
        + ' elapsed=' + (outcome.elapsedMs === null ? '?' : outcome.elapsedMs + 'ms'));
      return outcome;
    } catch (error) {
      const reason = String(error?.message ?? error).replace(/\s+/g, ' ').slice(0, 40);
      clientLog('[admin] group dispatch failed target=' + shortId(command.target) + ' err=' + reason);
      return {
        target: String(command.target),
        targetName: '',
        status: 'failed',
        reason,
        elapsedMs: null,
        replyChars: null,
      };
    }
  };

  const hubMembers = (hub) => {
    if (typeof hub.members === 'function') return hub.members().map(memberView);
    const data = hub.state();
    return Object.entries(data.members || {}).map(([peerId, member]) => memberView({
      peerId,
      name: member?.name ?? '',
      online: peerId === store.instanceId,
      lastSeen: null,
      joinedAt: member?.addedAt ?? null,
    }));
  };

  /**
   * v0.8.0（契约 §7/§8）：host 门面还没提供 applications 入口时的只读兜底。
   * 只读 group.json 的 applications 字段（面板先能看见申请人），批准/拒绝仍要等 host 接线 ——
   * 那里才拿得到群密钥去生成 grant，管理接口自己造一个 grant 是错的。
   */
  const localApplications = () => {
    const dir = stateDirOf();
    if (dir === '') return [];
    try {
      const raw = JSON.parse(fs.readFileSync(path.join(dir, 'group.json'), 'utf8'));
      return normalizeApplications(raw?.applications);
    } catch {
      return [];
    }
  };

  /**
   * v0.8.0-β（DESIGN §18.2）：host 门面还没提供 archives() 时的只读兜底。
   * 只读 group.json 的 archives 索引 —— 面板先能看见归档，删除仍要等 host 接线
   * （只有 host 知道归档文件在 stateDir 下怎么落、怎么删）。
   */
  const localArchives = () => {
    const dir = stateDirOf();
    if (dir === '') return [];
    try {
      const raw = JSON.parse(fs.readFileSync(path.join(dir, 'group.json'), 'utf8'));
      return normalizeArchives(raw?.archives);
    } catch {
      return [];
    }
  };

  /** hub 侧：直接读写本地 group.json（不经 HTTP，也不把 groupKey 交出去）。 */
  const hubGroupApi = (hub) => ({
    enabled: true,
    isHub: true,
    state({ sinceSeq = 0 } = {}) {
      const data = hub.state();
      return {
        groupId: data.groupId,
        name: data.name,
        // S1：epoch = 群密钥世代（GroupStore.state() 的 epoch/keyVersion 同一口径）
        epoch: data.epoch ?? data.keyVersion ?? null,
        members: hubMembers(hub),
        messages: hub.history({ sinceSeq, limit: GROUP_HISTORY_LIMIT }),
        lastSeq: data.lastSeq,
      };
    },
    post({ kind, text, meta }) {
      const message = hub.post({ peerId: store.instanceId, name: nameOf(), kind, text, meta });
      return { seq: message?.seq ?? null, ts: message?.ts ?? null };
    },
    member({ peerId, action }) {
      if (action === 'add') {
        const peer = typeof store?.getPeer === 'function' ? store.getPeer(peerId) : null;
        hub.addMember(peerId, String(peer?.name ?? ''));
      } else if (!hub.removeMember(peerId)) {
        const error = new Error('unknown-member');
        error.status = 404;
        throw error;
      }
      return { members: hubMembers(hub) };
    },
    setName({ name }) {
      return { name: hub.rename(name) };
    },
    join() {
      const error = new Error('hub-cannot-join');
      error.status = 409;
      throw error;
    },
    // S3：选举在 host 里跑，这里只转发并归一化 {ok, role, epoch} / {ok:false, reason}
    claim() {
      return coreClaim();
    },
    // v0.8.0（契约 §8）：待批准申请。host 门面负责落盘/生成 grant，这里只读它的结果；
    // 门面未接线时退回 group.json 的只读视图（面板不至于一片空白）。
    async applications() {
      if (typeof hub.applications === 'function') {
        const out = await hub.applications();
        return { applications: normalizeApplications(Array.isArray(out) ? out : out?.applications) };
      }
      return { applications: localApplications() };
    },
    async decideApplication({ peerId, action }) {
      if (typeof hub.decideApplication !== 'function') {
        const error = new Error('applications-unsupported');
        error.status = 501;
        throw error;
      }
      const out = await hub.decideApplication({ peerId, action });
      const status = APPLICATION_STATUSES.includes(String(out?.status ?? ''))
        ? String(out.status)
        : (action === 'approve' ? 'approved' : 'rejected');
      return { status };
    },
    // v0.8.0-β（DESIGN §18.2）：归档只归档、不自动删除，删不删由人决定。
    // 门面未接线时退回 group.json 的只读索引（和 applications 同款降级）。
    async archives() {
      if (typeof hub.archives === 'function') {
        const out = await hub.archives();
        return { archives: normalizeArchives(Array.isArray(out) ? out : out?.archives) };
      }
      return { archives: localArchives() };
    },
    async deleteArchive(file) {
      if (typeof hub.deleteArchive !== 'function') {
        const error = new Error('archives-unsupported');
        error.status = 501;
        throw error;
      }
      return await hub.deleteArchive(file);
    },
  });

  /** 成员侧：每次调用先解析 hub peer（peers.json 会随配对/解绑变化）。 */
  const memberGroupApi = (settings) => {
    const link = () => {
      const peer = groupHubPeer(settings);
      if (!peer) {
        const error = new Error('hub peer not paired: ' + settings.hub);
        error.status = 409;
        throw error;
      }
      if (!peer.baseUrl || !peer.secret) {
        const error = new Error('hub peer has no address/secret: ' + settings.hub);
        error.status = 409;
        throw error;
      }
      return { baseUrl: peer.baseUrl, secret: peer.secret, senderId: store.instanceId };
    };
    const hubOnly = (name) => {
      const error = new Error('hub-only');
      error.status = 403;
      error.action = name;
      return error;
    };
    return {
      enabled: true,
      isHub: false,
      async state({ sinceSeq = 0 } = {}) {
        const binding = link();
        const current = await fetchGroupState(binding);
        const history = await fetchGroupHistory({ ...binding, sinceSeq, limit: GROUP_HISTORY_LIMIT });
        // groupKey 只随成员响应下发：管理接口与面板都不转发（契约 §3）。
        return {
          groupId: current.groupId,
          name: current.name,
          epoch: current.epoch ?? current.keyVersion ?? null,
          leaderPeerId: current.leaderPeerId ?? null,
          // 成员表原样返回：地址/进度的归一化只在路由层做一次
          members: current.members,
          messages: history.messages,
          lastSeq: history.lastSeq,
        };
      },
      async post({ kind, text, meta }) {
        const out = await postGroup({ ...link(), kind, text, meta });
        return { seq: out?.seq ?? null, ts: out?.ts ?? null };
      },
      member() { throw hubOnly('member'); },
      setName() { throw hubOnly('setName'); },
      async join() {
        const out = await joinGroup(link());
        return { groupId: out?.groupId ?? null, epoch: out?.epoch ?? null };
      },
      // S3 手动接管：成员侧同样由本机 host 的选举状态机执行（不经过 hub HTTP）
      async claim() {
        return coreClaim();
      },
    };
  };

  /**
   * v0.8.0（按名入群）：「群功能对本机是否有效」的判定 —— 不再只等于 config.group.enabled。
   *
   * 成员身份可以在运行期长出来（拿到 grant → 写 group-key.json），而 config.group 可能一直是关的。
   * 只认配置的话，刚入群的节点在面板里仍然是「群组未启用」，这条链路在界面上等于没通。
   *   config.group.enabled === true   → 有效，来源 config
   *   host 门面 local() 有 groupId / role().groupId 非空 → 本机已是成员，来源 membership
   *   两者都不成立                     → 未启用（对外形状保持 v0.7.4，一个字段都不加）
   * 判定字段是**探测**来的（host/server.mjs：localGroupContext() 与 s3Facade.role()），
   * role() 不会返回 'off'，所以这里不看 role 的名字，只看它认不认得出 groupId。
   */
  const groupActivation = () => {
    const settings = groupSettings();
    if (settings.enabled) return { enabled: true, source: 'config', settings, local: null };
    const local = coreLocal();
    const localGroupId = String(local?.groupId ?? '').trim();
    const roleGroupId = String(roleFace()?.groupId ?? '').trim();
    const groupId = localGroupId !== '' ? localGroupId : roleGroupId;
    if (groupId === '') return { enabled: false, source: 'none', settings, local: null };
    // 成员身份自带 hub 线索：local.leaderPeerId（hub 永远是自己的 leader，副本也记当前 leader）。
    // config.group.hub 写好了就以配置为准 —— 配置是人手的意图，比推断可靠。
    const configuredHub = String(settings.hub ?? '').trim();
    const hub = configuredHub !== '' ? configuredHub : String(local?.leaderPeerId ?? '').trim();
    return { enabled: true, source: 'membership', settings: { ...settings, enabled: true, hub }, local, groupId };
  };

  // status: 'disabled'（未启用，按契约不报错）| 'error'（配置说启用但起不来）| 'ok'
  const resolveGroup = async () => {
    if (groupApiOverride) {
      const api = typeof groupApiOverride === 'function' ? await groupApiOverride() : groupApiOverride;
      if (!api || api.enabled !== true) return { status: 'disabled' };
      return { status: 'ok', api, isHub: api.isHub === true, enabledSource: 'config' };
    }
    const activation = groupActivation();
    if (!activation.enabled) return { status: 'disabled', settings: activation.settings };
    const settings = activation.settings;
    const hub = hubFacade();
    if (hub) {
      return { status: 'ok', api: hubGroupApi(hub), isHub: true, settings, enabledSource: activation.source };
    }
    if (settings.hub === '') {
      // 有群却没 hub 线索：config 写了「本机是 hub」但 host 没起群存储（例如 stateDir 不可写），
      // 或者成员身份里连 leader 都还不知道。两种情况都如实报错，不假装空群。
      const reason = activation.source === 'membership' ? 'hub-unknown' : 'group-store-unavailable';
      return { status: 'error', reason, isHub: activation.source === 'config', settings, enabledSource: activation.source };
    }
    return {
      status: 'ok',
      api: memberGroupApi(settings),
      isHub: false,
      settings,
      enabledSource: activation.source,
    };
  };


  return {
    prefix: PREFIX,
    // S3：同进程只读出口（测试/CLI 接线用）。跨进程请读 <stateDir>/admin-token。
    token: ADMIN_TOKEN,
    async handle(req, res, url) {
      if (!url.pathname.startsWith(PREFIX)) return false;
      const route = url.pathname.slice(PREFIX.length);
      const method = String(req.method || 'GET').toUpperCase();
      const write = !READ_METHODS.has(method);
      // panel.js / client-log 免 token，但 client-log 仍只收 JSON（它不是浏览器表单能
      // 造出来的形状）；其余路由下面三道门全过才进业务，只读接口也不例外。
      const open = TOKEN_FREE_ROUTES.has(route);
      if (!open) {
        if (hostHeader(req) === '') {
          // Host 缺失（老 Electron IPC 桥的形状）不再默认放行：必须带对 token。
          // 顺序也是语义 —— 先 Host/Origin（403 不泄露 token 对不对），再 token（401）。
          if (!tokenMatches(req)) {
            sendJson(res, 403, { error: 'forbidden: host-header-required' });
            return true;
          }
        } else if (!hostIsLoopback(req)) {
          sendJson(res, 403, { error: 'forbidden: loopback-only' });
          return true;
        }
        if (write && !originIsLoopback(req)) {
          sendJson(res, 403, { error: 'forbidden: cross-origin' });
          return true;
        }
        if (write && !isJsonContentType(req)) {
          sendJson(res, 415, { error: 'content-type-json-required' });
          return true;
        }
        if (!tokenMatches(req)) {
          sendJson(res, 401, { error: 'token-required' });
          return true;
        }
      } else if (write && !isJsonContentType(req)) {
        sendJson(res, 415, { error: 'content-type-json-required' });
        return true;
      }
      try {
        if (route === 'state' && method === 'GET') {
          const state = store.state;
          sendJson(res, 200, {
            name: nameOf(),
            instanceId: store.instanceId,
            peers: store.listPeers().map(({ peerId, name, baseUrl, lastSeen }) => ({
              peerId, name, baseUrl, lastSeen: lastSeen ?? null,
            })),
            // M6：配对码不回显（只有 active/expiresInSec），码只在生成那次响应里出现。
            pairing: pairingView(state),
          });
          return true;
        }

        if (route === 'name' && method === 'POST') {
          const body = await readJson(req);
          const name = rename(String(body.name ?? ''));
          clientLog('[admin] rename -> ' + name);
          sendJson(res, 200, { ok: true, name });
          return true;
        }

        if (route === 'code' && method === 'POST') {
          const issued = store.issuePairingCode();
          // Never log the code itself — it is a one-time credential.
          clientLog('[admin] pairing code issued ttl=' + Math.round((issued.expiresAt - Date.now()) / 1000) + 's');
          sendJson(res, 200, { ok: true, code: issued.code, expiresAt: issued.expiresAt });
          return true;
        }

        if (route === 'pair' && method === 'POST') {
          const body = await readJson(req);
          const peerUrl = normalizeUrl(body.url);
          const code = String(body.code ?? '').trim();
          if (!/^\d{6}$/.test(code)) {
            sendJson(res, 400, { error: '配对码必须是 6 位数字' });
            return true;
          }
          const plainName = String(body.peerName ?? '').trim();
          // pairPeer negotiates: ECDH two-round when the peer advertises
          // "pair-ecdh", plaintext legacy otherwise (see client/peer-call.mjs).
          let paired;
          try {
            paired = await pairPeer({
              url: peerUrl,
              code,
              peerId: store.instanceId,
              peerName: nameOf(),
              mode: pairingMode,
              timeoutMs: 15_000,
            });
          } catch (error) {
            const status = Number(error?.status) || 0;
            const reason = String(error?.message ?? error);
            if (status === 401 || status === 400) {
              sendJson(res, 400, { error: '配对码无效或已过期' });
            } else if (/fetch failed|ECONN|ENOTFOUND|timeout|abort/i.test(reason)) {
              sendJson(res, 502, { error: '连不上对端: ' + reason });
            } else {
              sendJson(res, 502, { error: '配对失败: ' + reason });
            }
            return true;
          }
          const stored = store.upsertPeer(paired.peerId, {
            name: plainName || paired.peerName || paired.peerId,
            baseUrl: peerUrl,
            secret: paired.secret,
            inboundSecret: paired.inboundSecret,
          });
          clientLog('[admin] pair -> ' + stored.name + ' (' + String(paired.peerId).slice(0, 8) + ') transport=' + paired.transport);
          sendJson(res, 200, {
            ok: true,
            transport: paired.transport,
            peer: { peerId: paired.peerId, name: stored.name, baseUrl: peerUrl },
          });
          return true;
        }

        if (route === 'dispatch' && method === 'GET') {
          // Live view of the model tool's dispatches: status, transport and how
          // long each one has been running. Prompt text is never recorded here.
          sendJson(res, 200, { dispatches: feed ? feed.list() : [] });
          return true;
        }

        if (route === 'client-log' && method === 'POST') {
          const body = await readJson(req);
          const event = String(body.event ?? '').slice(0, 120) || 'client-log';
          const detail = body.detail == null ? '' : ' ' + String(body.detail).slice(0, 600);
          clientLog('[client] ' + event + detail);
          sendJson(res, 200, { ok: true });
          return true;
        }

        if (route === 'unpair' && method === 'POST') {
          const body = await readJson(req);
          const peerId = String(body.peerId ?? '').trim();
          const peer = peerId === '' ? null : store.getPeer(peerId);
          if (!peer) {
            clientLog('[admin] unpair ' + (peerId || '(empty)') + ' -> unknown-peer (nothing changed)');
            sendJson(res, 404, { error: 'unknown-peer' });
            return true;
          }
          // Tell the peer before dropping it: the local record still holds the
          // address and the secret the notification needs.
          const remote = await notifyPeerUnpair({ peer, senderId: store.instanceId });
          const removed = store.removePeer(peerId);
          // Admin actions were previously invisible: a peer disappearing could
          // not be traced to a human clicking 解除. Log it (never the secrets).
          clientLog('[admin] unpair ' + String(peerId).slice(0, 8) + ' name=' + String(peer.name ?? '')
            + ' removed=' + removed + ' remote=' + (remote.notified ? 'notified' : 'local-only:' + (remote.reason ?? 'unknown')));
          sendJson(res, 200, {
            ok: true,
            peer: { peerId, name: String(peer.name ?? '') },
            remote,
          });
          return true;
        }

        // ---- v0.5.0 群聊管理接口（只读为主，全部只经回环） ----
        // 浏览器拿到的只是本机回环结果：成员侧的 hub 往返在这里用 hub peer 的
        // secret 完成（lib/group-client.mjs），对端名字/正文一律只作数据回传。
        if (route === 'group' && method === 'GET') {
          const sinceSeq = parseSinceSeq(url.searchParams.get('sinceSeq'));
          const resolved = await resolveGroup();
          if (resolved.status === 'disabled') {
            if (sinceSeq === 0) clientLog('[admin] group state -> disabled');
            // 未启用群：形状与 v0.5.0 完全一致（老面板/外部脚本继续可用）。
            sendJson(res, 200, { ...GROUP_DISABLED_STATE });
            return true;
          }
          const isHub = resolved.isHub === true;
          // v0.6.0 S1/S2 的可见性字段：只加不改，未启用分支保持旧形状。
          const selfRole = isHub ? 'hub' : 'member';
          const advertise = advertiseAddress();
          // S3：一次请求只读一次角色门面 —— leader.epoch 与状态行的 epoch 必须同源，
          // 否则两次读取之间换 leader 就会在同一条响应里自相矛盾。
          const roleState = roleFace();
          // v0.7.0 S3（契约 §7）：角色/租约/quorum/提交进度只加不改；失败分支也带上，
          // 面板据此显示 degraded，而不是留一片空白。
          const extras = (leader, replica, selfBaseUrl, snapshot = null, lastSeq = null) => ({
            leader,
            selfRole,
            replica,
            advertiseBaseUrl: advertise.baseUrl,
            advertiseSource: advertise.source,
            selfBaseUrl,
            // v0.8.2-α（契约 §5）：本机接单开关的当前值（面板据此渲染开关）+ 派单实时状态。
            // acceptDispatch 缺省 true（老配置没有这个字段 = 接单）；门面没接线时 dispatch 是 null。
            acceptDispatch: coreAcceptDispatch(),
            dispatch: coreDispatchState(),
            // v0.8.0：enabled 的语义是「群功能对本机是否有效」，这里说明它凭什么有效
            // （config 打开 / 本机已按名入群）。排障时一眼能看出「配置关着但人在群里」。
            enabledSource: resolved.enabledSource ?? 'config',
            ...roleView({
              isHub,
              snapshot,
              leader,
              lastSeq,
              state: roleState,
              settings: resolved.settings ?? groupSettings(),
            }),
          });
          if (resolved.status === 'error') {
            clientLog('[admin] group state failed: ' + resolved.reason);
            sendJson(res, 200, {
              enabled: true,
              isHub,
              group: null,
              messages: [],
              lastSeq: sinceSeq,
              error: resolved.reason,
              ...extras(null, null, ''),
            });
            return true;
          }
          try {
            const snapshot = (await resolved.api.state({ sinceSeq })) ?? {};
            const rawMembers = Array.isArray(snapshot.members) ? snapshot.members : [];
            const messages = Array.isArray(snapshot.messages) ? snapshot.messages : [];
            const rawLast = Number(snapshot.lastSeq);
            const lastSeq = Number.isFinite(rawLast) ? rawLast : sinceSeq;
            // 成员的「落后条数」= leader 的 lastSeq - 该成员上报的 lastSeq（没上报就是 null）
            const members = rawMembers.map((member) => {
              const view = memberView(member);
              return { ...view, lag: view.lastSeq == null ? null : Math.max(0, lastSeq - view.lastSeq) };
            });
            const leader = leaderOf(snapshot, resolved, roleState);
            const replica = isHub
              ? { lastSeq, leaderLastSeq: lastSeq, lag: 0 }
              : replicaView(coreReplica() ?? readReplica(), lastSeq);
            // hub 的成员表里也记着自己：「别人看到的你的地址」就是自己那条的 baseUrl。
            const selfPeerId = String(store?.instanceId ?? '');
            const selfMember = selfPeerId === ''
              ? null
              : members.find((member) => member.peerId === selfPeerId) ?? null;
            // 面板每 2s 拉一次：只在首次、有新消息或失败时留痕，否则日志会被轮询刷爆。
            if (sinceSeq === 0 || messages.length > 0) {
              clientLog('[admin] group state isHub=' + isHub + ' sinceSeq=' + sinceSeq
                + ' new=' + messages.length + ' lastSeq=' + lastSeq + ' members=' + members.length);
            }
            // v0.8.0（契约 §8）：hub 侧的待批准申请随群状态一起下发 —— 面板的 2s 节拍仍然
            // 只打这一条请求（多一条后台 GET 就会把「一个节拍一个请求」的既有口径打散）；
            // 独立的 GET group/applications 保留给 CLI/外部脚本。
            let applications = null;
            if (isHub && typeof resolved.api.applications === 'function') {
              try {
                const listed = (await resolved.api.applications()) ?? {};
                applications = Array.isArray(listed.applications) ? listed.applications : [];
              } catch (error) {
                // 读不到申请不影响群状态本身：把失败留在日志里，面板照旧显示群。
                clientLog('[admin] group applications failed err=' + String(error?.message ?? error).slice(0, 80));
              }
            }
            sendJson(res, 200, {
              enabled: true,
              isHub,
              group: { groupId: snapshot.groupId ?? null, name: snapshot.name ?? '', members },
              messages,
              lastSeq,
              ...extras(leader, replica, selfMember ? selfMember.baseUrl : '', snapshot, lastSeq),
              ...(isHub ? { applications } : {}),
            });
          } catch (error) {
            const reason = String(error?.message ?? error);
            clientLog('[admin] group state failed: ' + reason);
            sendJson(res, 200, {
              enabled: true,
              isHub,
              group: null,
              messages: [],
              lastSeq: sinceSeq,
              error: reason,
              ...extras(null, null, ''),
            });
          }
          return true;
        }

        // S3 契约 §7：运维手动接管（POST /v1/group/leader 是心跳，这里不是同一个东西）
        if (route === 'group/leader' && method === 'POST') {
          const body = await readJson(req);
          const action = String(body.action ?? '').trim();
          if (action !== 'claim') {
            clientLog('[admin] group claim refused action=' + action.slice(0, 16) + ' (bad action)');
            // 失败也按契约 §7 的形状回 {ok:false, reason}，面板只把这句写进 msg 区
            sendJson(res, 200, { ok: false, reason: 'bad-action' });
            return true;
          }
          const resolved = await resolveGroup();
          if (resolved.status !== 'ok') {
            const reason = resolved.status === 'error' ? resolved.reason : 'group-disabled';
            clientLog('[admin] group claim refused err=' + reason);
            sendJson(res, 200, { ok: false, reason });
            return true;
          }
          if (typeof resolved.api.claim !== 'function') {
            clientLog('[admin] group claim unsupported (backend has no claim)');
            sendJson(res, 200, { ok: false, reason: 'claim-unsupported' });
            return true;
          }
          try {
            const out = (await resolved.api.claim({})) ?? {};
            if (out.ok === true) {
              // 只记角色/世代：接管不涉及任何密钥或正文。
              const role = GROUP_ROLES.includes(String(out.role ?? '')) ? String(out.role) : 'leader';
              const epoch = asSeqOrNull(out.epoch);
              clientLog('[admin] group claim ok role=' + role + ' epoch=' + (epoch ?? '?'));
              sendJson(res, 200, { ok: true, role, epoch });
            } else {
              const reason = String(out.reason ?? 'claim-refused');
              clientLog('[admin] group claim refused reason=' + reason);
              sendJson(res, 200, { ok: false, reason });
            }
          } catch (error) {
            const reason = String(error?.message ?? error);
            clientLog('[admin] group claim failed err=' + reason);
            sendJson(res, 200, { ok: false, reason });
          }
          return true;
        }

        if (route === 'group/post' && method === 'POST') {
          const body = await readJson(req);
          const kind = String(body.kind ?? 'chat').trim() || 'chat';
          if (!GROUP_KINDS.includes(kind)) {
            clientLog('[admin] group post rejected kind=' + kind.slice(0, 24) + ' (kind not allowed)');
            sendJson(res, 400, { error: 'bad-kind' });
            return true;
          }
          const text = body.text == null ? '' : String(body.text);
          if (text.length > GROUP_TEXT_MAX_CHARS) {
            clientLog('[admin] group post rejected kind=' + kind + ' textLen=' + text.length + ' (too large)');
            sendJson(res, 413, { error: 'payload-too-large' });
            return true;
          }
          const meta = sanitizeGroupMeta(body.meta);
          const resolved = await resolveGroup();
          if (resolved.status !== 'ok') {
            const reason = resolved.status === 'error' ? resolved.reason : 'group-disabled';
            clientLog('[admin] group post refused kind=' + kind + ' textLen=' + text.length + ' err=' + reason);
            sendJson(res, resolved.status === 'error' ? 502 : 409, { error: reason });
            return true;
          }
          try {
            const out = (await resolved.api.post({ kind, text, meta })) ?? {};
            // 只记长度/字段数/序号：群消息正文（可能含回复全文）绝不进日志。
            clientLog('[admin] group post kind=' + kind + ' textLen=' + text.length
              + ' meta=' + Object.keys(meta).length + ' seq=' + (out.seq ?? '?'));
            // 契约 §1/§5：chat 正文里带 @!X 时作者侧自动触发一次派单。消息已经发出，
            // 所以派单失败既不回滚也不改 HTTP 状态 —— 结果只作为 dispatch 摘要回给调用方；
            // 群历史里的 progress/result 由 host 按契约 §3 写（正文永不入群）。
            const command = kind === 'chat' ? parseGroupDispatchCommand(text) : null;
            const dispatch = command ? await settledDispatch(command) : null;
            sendJson(res, 200, {
              ok: true,
              seq: out.seq ?? null,
              ts: out.ts ?? null,
              ...(dispatch ? { dispatch } : {}),
            });
          } catch (error) {
            const reason = String(error?.message ?? error);
            clientLog('[admin] group post failed kind=' + kind + ' textLen=' + text.length + ' err=' + reason);
            sendJson(res, errorStatus(error, 502), { error: reason });
          }
          return true;
        }

        // ---- v0.8.2-α（契约 §4）：本机接单开关 ----
        // 只有 host 知道配置怎么落盘，所以这里只转发；失败原样回 reason，不在面板上猜。
        if (route === 'group/accept' && method === 'POST') {
          const body = await readJson(req);
          if (typeof body.acceptDispatch !== 'boolean') {
            clientLog('[admin] group accept rejected (acceptDispatch must be boolean)');
            sendJson(res, 400, { error: 'bad-accept' });
            return true;
          }
          const resolved = await resolveGroup();
          if (resolved.status !== 'ok') {
            const reason = resolved.status === 'error' ? resolved.reason : 'group-disabled';
            clientLog('[admin] group accept refused err=' + reason);
            sendJson(res, resolved.status === 'error' ? 502 : 409, { error: reason });
            return true;
          }
          try {
            const out = coreSetAcceptDispatch(body.acceptDispatch);
            clientLog('[admin] group accept -> ' + (out.acceptDispatch ? 'on' : 'off')
              + ' persisted=' + out.persisted);
            sendJson(res, 200, { ok: true, acceptDispatch: out.acceptDispatch, persisted: out.persisted });
          } catch (error) {
            const reason = String(error?.message ?? error);
            clientLog('[admin] group accept failed err=' + reason);
            sendJson(res, errorStatus(error, 502), { error: reason });
          }
          return true;
        }

        // ---- v0.8.2-α（契约 §3/§5）：作者侧派单入口 ----
        // CLI（本机直连 hub 发完消息后）与显式 group dispatch 都打这一条：派单执行在 host 里，
        // 这里只做参数校验、转发与摘要归一化 —— 回复正文一律不经过本接口。
        if (route === 'group/dispatch' && method === 'POST') {
          const body = await readJson(req);
          const target = String(body.target ?? '').trim();
          const task = body.task == null ? '' : String(body.task);
          if (target === '') {
            clientLog('[admin] group dispatch rejected (target required)');
            sendJson(res, 400, { error: 'bad-target' });
            return true;
          }
          if (task.length > GROUP_TEXT_MAX_CHARS) {
            clientLog('[admin] group dispatch rejected target=' + shortId(target) + ' taskLen=' + task.length);
            sendJson(res, 413, { error: 'payload-too-large' });
            return true;
          }
          const resolved = await resolveGroup();
          if (resolved.status !== 'ok') {
            const reason = resolved.status === 'error' ? resolved.reason : 'group-disabled';
            clientLog('[admin] group dispatch refused target=' + shortId(target) + ' err=' + reason);
            sendJson(res, resolved.status === 'error' ? 502 : 409, { error: reason });
            return true;
          }
          const extra = Number(body.extraTargets);
          const outcome = await settledDispatch({
            target,
            task,
            extraTargets: Number.isFinite(extra) && extra > 0 ? Math.floor(extra) : 0,
          });
          // 派单本身失败（not-accepting/offline/busy/...）仍是 200：那是业务结果，不是接口错误。
          sendJson(res, 200, { ok: outcome.status === 'done', dispatch: outcome });
          return true;
        }

        if (route === 'group/member' && method === 'POST') {
          const body = await readJson(req);
          const peerId = String(body.peerId ?? '').trim();
          const action = String(body.action ?? 'add').trim() || 'add';
          const shortId = peerId === '' ? '(empty)' : peerId.slice(0, 8);
          if (action !== 'add' && action !== 'remove') {
            clientLog('[admin] group member rejected peer=' + shortId + ' action=' + action.slice(0, 16) + ' (bad action)');
            sendJson(res, 400, { error: 'bad-action' });
            return true;
          }
          if (peerId === '') {
            clientLog('[admin] group member rejected action=' + action + ' (peerId required)');
            sendJson(res, 400, { error: 'peerId-required' });
            return true;
          }
          const resolved = await resolveGroup();
          if (resolved.status !== 'ok') {
            const reason = resolved.status === 'error' ? resolved.reason : 'group-disabled';
            clientLog('[admin] group member refused peer=' + shortId + ' action=' + action + ' err=' + reason);
            sendJson(res, resolved.status === 'error' ? 502 : 409, { error: reason });
            return true;
          }
          if (resolved.isHub !== true) {
            clientLog('[admin] group member refused peer=' + shortId + ' action=' + action + ' (hub only)');
            sendJson(res, 403, { error: 'hub-only' });
            return true;
          }
          if (action === 'add') {
            // hub 只能把「已配对的 peer」拉进群：没配对的 id 既验不了签也加不进。
            const known = typeof store?.getPeer === 'function' ? store.getPeer(peerId) : null;
            if (!known) {
              clientLog('[admin] group member refused peer=' + shortId + ' action=add (unknown peer)');
              sendJson(res, 404, { error: 'unknown-peer' });
              return true;
            }
          }
          try {
            const out = (await resolved.api.member({ peerId, action })) ?? {};
            clientLog('[admin] group member action=' + action + ' peer=' + shortId
              + ' members=' + (Array.isArray(out.members) ? out.members.length : '?'));
            sendJson(res, 200, { ok: true, action, peerId, members: out.members ?? null });
          } catch (error) {
            const reason = String(error?.message ?? error);
            clientLog('[admin] group member failed action=' + action + ' peer=' + shortId + ' err=' + reason);
            sendJson(res, errorStatus(error, 502), { error: reason });
          }
          return true;
        }

        // ---- v0.8.0（契约 §8）：hub 侧待批准申请 ----
        if (route === 'group/applications' && method === 'GET') {
          const resolved = await resolveGroup();
          if (resolved.status !== 'ok') {
            const reason = resolved.status === 'error' ? resolved.reason : 'group-disabled';
            clientLog('[admin] group applications refused err=' + reason);
            sendJson(res, resolved.status === 'error' ? 502 : 409, { error: reason });
            return true;
          }
          if (resolved.isHub !== true) {
            clientLog('[admin] group applications refused (hub only)');
            sendJson(res, 403, { error: 'hub-only' });
            return true;
          }
          try {
            const out = (await resolved.api.applications()) ?? {};
            const list = Array.isArray(out.applications) ? out.applications : [];
            clientLog('[admin] group applications pending=' + list.filter((item) => item.status === 'pending').length
              + ' total=' + list.length);
            sendJson(res, 200, { applications: list });
          } catch (error) {
            const reason = String(error?.message ?? error);
            clientLog('[admin] group applications failed err=' + reason);
            sendJson(res, errorStatus(error, 502), { error: reason });
          }
          return true;
        }

        if (route === 'group/applications' && method === 'POST') {
          const body = await readJson(req);
          const peerId = String(body.peerId ?? '').trim();
          const action = String(body.action ?? '').trim();
          if (action !== 'approve' && action !== 'reject') {
            clientLog('[admin] group application rejected action=' + action.slice(0, 16) + ' (bad action)');
            sendJson(res, 400, { error: 'bad-action' });
            return true;
          }
          if (peerId === '') {
            clientLog('[admin] group application rejected action=' + action + ' (peerId required)');
            sendJson(res, 400, { error: 'peerId-required' });
            return true;
          }
          const resolved = await resolveGroup();
          if (resolved.status !== 'ok') {
            const reason = resolved.status === 'error' ? resolved.reason : 'group-disabled';
            clientLog('[admin] group application refused peer=' + shortId(peerId) + ' err=' + reason);
            sendJson(res, resolved.status === 'error' ? 502 : 409, { error: reason });
            return true;
          }
          if (resolved.isHub !== true) {
            clientLog('[admin] group application refused peer=' + shortId(peerId) + ' (hub only)');
            sendJson(res, 403, { error: 'hub-only' });
            return true;
          }
          if (typeof resolved.api.decideApplication !== 'function') {
            clientLog('[admin] group application unsupported peer=' + shortId(peerId));
            sendJson(res, 501, { error: 'applications-unsupported' });
            return true;
          }
          try {
            const out = (await resolved.api.decideApplication({ peerId, action })) ?? {};
            const status = APPLICATION_STATUSES.includes(String(out.status ?? ''))
              ? String(out.status)
              : (action === 'approve' ? 'approved' : 'rejected');
            clientLog('[admin] group application peer=' + shortId(peerId) + ' action=' + action + ' status=' + status);
            sendJson(res, 200, { ok: true, status });
          } catch (error) {
            const reason = String(error?.message ?? error);
            clientLog('[admin] group application failed peer=' + shortId(peerId) + ' action=' + action + ' err=' + reason);
            sendJson(res, errorStatus(error, 502), { error: reason });
          }
          return true;
        }

        // ---- v0.8.0-β（DESIGN §18.2）：hub 侧归档列表 / 人工删除归档 ----
        // 归档只归档、不自动删除：删不删、删哪个由人决定，所以这里只有「列」和「删」两个动作。
        if (route === 'group/archives' && method === 'GET') {
          const resolved = await resolveGroup();
          if (resolved.status !== 'ok') {
            const reason = resolved.status === 'error' ? resolved.reason : 'group-disabled';
            clientLog('[admin] group archives refused err=' + reason);
            sendJson(res, resolved.status === 'error' ? 502 : 409, { error: reason });
            return true;
          }
          if (resolved.isHub !== true) {
            clientLog('[admin] group archives refused (hub only)');
            sendJson(res, 403, { error: 'hub-only' });
            return true;
          }
          if (typeof resolved.api.archives !== 'function') {
            clientLog('[admin] group archives unsupported');
            sendJson(res, 501, { error: 'archives-unsupported' });
            return true;
          }
          try {
            const out = (await resolved.api.archives()) ?? {};
            const list = normalizeArchives(Array.isArray(out) ? out : out.archives);
            const totalBytes = list.reduce((sum, item) => sum + item.bytes, 0);
            clientLog('[admin] group archives listed count=' + list.length + ' bytes=' + totalBytes);
            sendJson(res, 200, { archives: list, totalBytes });
          } catch (error) {
            const reason = String(error?.message ?? error);
            clientLog('[admin] group archives failed err=' + reason);
            sendJson(res, errorStatus(error, 502), { error: reason });
          }
          return true;
        }

        if (route === 'group/archives' && method === 'POST') {
          const body = await readJson(req);
          const file = String(body.file ?? '').trim();
          const action = String(body.action ?? '').trim();
          if (action !== 'delete') {
            clientLog('[admin] group archive rejected action=' + action.slice(0, 16) + ' (bad action)');
            sendJson(res, 400, { error: 'bad-action' });
            return true;
          }
          // 契约里 file 是「文件名」：带路径成分的一律不收，免得门面被引到归档目录之外。
          if (file === '' || file === '.' || file === '..' || path.basename(file) !== file) {
            clientLog('[admin] group archive rejected (bad file)');
            sendJson(res, 400, { error: 'bad-file' });
            return true;
          }
          const resolved = await resolveGroup();
          if (resolved.status !== 'ok') {
            const reason = resolved.status === 'error' ? resolved.reason : 'group-disabled';
            clientLog('[admin] group archive refused err=' + reason);
            sendJson(res, resolved.status === 'error' ? 502 : 409, { error: reason });
            return true;
          }
          if (resolved.isHub !== true) {
            clientLog('[admin] group archive refused (hub only)');
            sendJson(res, 403, { error: 'hub-only' });
            return true;
          }
          if (typeof resolved.api.deleteArchive !== 'function') {
            clientLog('[admin] group archive unsupported');
            sendJson(res, 501, { error: 'archives-unsupported' });
            return true;
          }
          try {
            const out = (await resolved.api.deleteArchive(file)) ?? {};
            if (out.ok === false) {
              // 契约 §18.2：未知归档文件如实报 404，其余失败按上游/未知处理。
              const reason = String(out.reason ?? 'delete-failed');
              clientLog('[admin] group archive delete refused file=' + file.slice(0, 64) + ' err=' + reason);
              sendJson(res, reason === 'unknown-archive' ? 404 : 502, { error: reason });
              return true;
            }
            const removed = Number(out.removedBytes);
            const removedBytes = Number.isFinite(removed) && removed > 0 ? Math.floor(removed) : 0;
            clientLog('[admin] group archive delete file=' + file.slice(0, 64) + ' bytes=' + removedBytes);
            sendJson(res, 200, { ok: true, removedBytes });
          } catch (error) {
            const reason = String(error?.message ?? error);
            clientLog('[admin] group archive delete failed file=' + file.slice(0, 64) + ' err=' + reason);
            sendJson(res, errorStatus(error, reason === 'unknown-archive' ? 404 : 502), { error: reason });
          }
          return true;
        }

        if (route === 'group/config' && method === 'POST') {
          const body = await readJson(req);
          const name = String(body.name ?? '').trim();
          if (name === '' || name.length > GROUP_NAME_MAX) {
            clientLog('[admin] group config rejected nameLen=' + name.length + ' (invalid)');
            sendJson(res, 400, { error: 'bad-name' });
            return true;
          }
          const resolved = await resolveGroup();
          if (resolved.status !== 'ok') {
            const reason = resolved.status === 'error' ? resolved.reason : 'group-disabled';
            clientLog('[admin] group config refused err=' + reason);
            sendJson(res, resolved.status === 'error' ? 502 : 409, { error: reason });
            return true;
          }
          if (resolved.isHub !== true) {
            clientLog('[admin] group config refused (hub only)');
            sendJson(res, 403, { error: 'hub-only' });
            return true;
          }
          // 契约 §6：改名先查重（可达邻域：已配对伙伴 + 它们的已知群）。
          // 自己的 groupId 不参与判定（同名不同 groupId 才算冲突）。
          let snapshot = {};
          try {
            snapshot = (await resolved.api.state({ sinceSeq: 0 })) ?? {};
          } catch {
            snapshot = {};   // 拿不到自己的快照就不排除自己：宁可多报一条冲突，也不放同名群进来
          }
          const ownGroupId = String(snapshot.groupId ?? '');
          const check = await lookupEveryPeer({ name });
          const conflicts = check.matches
            .filter((match) => groupNameKey(match.name) === groupNameKey(name)
              && String(match.groupId) !== ownGroupId)
            .map((match) => ({
              peerId: String(match.via?.peerId ?? ''),
              peerName: String(match.via?.name ?? ''),
              groupId: String(match.groupId),
              name: String(match.name),
            }));
          if (check.unsupported) {
            // Lane P 未接线：跳过查重而不是拒绝改名（既有行为不变），但要在日志里说清楚。
            clientLog('[admin] group name check skipped (lookup-unavailable)');
          } else if (check.failed > 0) {
            clientLog('[admin] group name check unreachable=' + check.failed + '/' + check.checked);
          }
          if (conflicts.length > 0) {
            clientLog('[admin] group name taken nameLen=' + name.length + ' conflicts=' + conflicts.length
              + ' groupId=' + shortId(conflicts[0].groupId));
            sendJson(res, 409, { error: 'name-taken', conflicts });
            return true;
          }
          try {
            const out = (await resolved.api.setName({ name })) ?? {};
            const applied = String(out.name ?? name);
            clientLog('[admin] group name -> ' + applied);
            // 契约 §6.4：改名成功后（尽力）重新广播新名；广播失败不影响改名结果。
            const broadcast = await broadcastGroupName({
              memberIds: memberIdsOf(snapshot),
              groupId: ownGroupId,
              name: applied,
            });
            if (broadcast.unsupported) {
              clientLog('[admin] group advertise skipped (advertise-unavailable)');
            } else {
              clientLog('[admin] group advertise targets=' + broadcast.targets + ' sent=' + broadcast.sent);
            }
            // 响应形状维持 v0.7.4（{ok,name}）：广播计数只进日志，
            // 老面板/外部脚本的比较不会因为多一个字段而挂掉。
            sendJson(res, 200, { ok: true, name: applied });
          } catch (error) {
            const reason = String(error?.message ?? error);
            clientLog('[admin] group config failed err=' + reason);
            sendJson(res, errorStatus(error, 502), { error: reason });
          }
          return true;
        }

        if (route === 'group/join' && method === 'POST') {
          const resolved = await resolveGroup();
          if (resolved.status !== 'ok') {
            const reason = resolved.status === 'error' ? resolved.reason : 'group-disabled';
            clientLog('[admin] group join refused err=' + reason);
            sendJson(res, resolved.status === 'error' ? 502 : 409, { error: reason });
            return true;
          }
          if (resolved.isHub === true) {
            clientLog('[admin] group join refused (this device is the hub)');
            sendJson(res, 409, { error: 'hub-cannot-join' });
            return true;
          }
          try {
            const out = (await resolved.api.join({})) ?? {};
            // groupKey 属于群密钥：只记录 message 级别的结果，绝不打出来。
            clientLog('[admin] group join ok groupId=' + String(out.groupId ?? '?').slice(0, 12)
              + ' epoch=' + (out.epoch ?? '?'));
            sendJson(res, 200, { ok: true, groupId: out.groupId ?? null, epoch: out.epoch ?? null });
          } catch (error) {
            const reason = String(error?.message ?? error);
            clientLog('[admin] group join failed err=' + reason);
            sendJson(res, errorStatus(error, 502), { error: reason });
          }
          return true;
        }

        // ---- v0.8.0（契约 §2/§3/§4/§5）：按名查找 / 申请 / 状态 / 手动广播 ----
        // 这几条是面板「按名入群」的唯一通道：浏览器只认回环接口，per-peer 签名与
        // 两跳转交都在插件进程里完成（Lane P 的 group-client 函数，按冻结签名调用）。
        if (route === 'group/lookup' && method === 'POST') {
          const body = await readJson(req);
          const name = String(body.name ?? '').trim();
          if (name === '' || name.length > GROUP_NAME_MAX) {
            clientLog('[admin] group lookup rejected nameLen=' + name.length + ' (invalid)');
            sendJson(res, 400, { error: 'bad-name' });
            return true;
          }
          // 契约 §3 的查找顺序：先本地 known-groups，未命中再问伙伴。
          const key = groupNameKey(name);
          const known = await localKnownGroups();
          const local = known
            .filter((entry) => groupNameKey(entry.name) === key)
            .map((entry) => ({
              groupId: entry.groupId,
              name: entry.name,
              hub: entry.hub,
              via: entry.source ? { peerId: String(entry.source.peerId ?? ''), name: String(entry.source.name ?? '') } : null,
              source: 'local',
            }));
          if (local.length > 0) {
            clientLog('[admin] group lookup local hits=' + local.length);
            sendJson(res, 200, { matches: local, source: 'local' });
            return true;
          }
          const found = await lookupEveryPeer({ name });
          if (found.unsupported) {
            clientLog('[admin] group lookup unsupported (lookup-unavailable)');
            sendJson(res, 501, { error: 'lookup-unsupported', matches: [] });
            return true;
          }
          clientLog('[admin] group lookup peers=' + found.checked + ' hits=' + found.matches.length + ' failed=' + found.failed);
          sendJson(res, 200, { matches: found.matches, source: 'peers', checked: found.checked });
          return true;
        }

        if (route === 'group/apply' && method === 'POST') {
          const body = await readJson(req);
          const groupId = String(body.groupId ?? '').trim();
          const introducerId = String(body.introducer ?? '').trim();
          if (groupId === '' || introducerId === '') {
            clientLog('[admin] group apply rejected (groupId/introducer required)');
            sendJson(res, 400, { error: 'bad-request' });
            return true;
          }
          // 介绍人必须是已配对的伙伴：per-peer 签名要它的 secret，没配对就无从谈起。
          const peer = typeof store?.getPeer === 'function' ? store.getPeer(introducerId) : null;
          if (!peer) {
            clientLog('[admin] group apply refused introducer=' + shortId(introducerId) + ' (unknown peer)');
            sendJson(res, 404, { error: 'unknown-peer' });
            return true;
          }
          if (!peer.baseUrl || !peer.secret) {
            clientLog('[admin] group apply refused introducer=' + shortId(introducerId) + ' (no address/secret)');
            sendJson(res, 409, { error: 'introducer-unreachable' });
            return true;
          }
          const apply = netFn('applyToGroup');
          if (!apply) {
            clientLog('[admin] group apply unsupported (apply-unavailable)');
            sendJson(res, 501, { error: 'apply-unsupported' });
            return true;
          }
          const self = selfIdentity();
          const applicant = { peerId: self.peerId, name: self.name, baseUrl: advertiseAddress().baseUrl };
          try {
            const out = (await apply({
              baseUrl: String(peer.baseUrl),
              secret: peer.secret,
              senderId: self.peerId,
              groupId,
              applicant,
            })) ?? {};
            const status = APPLICATION_STATUSES.includes(String(out.status ?? '')) ? String(out.status) : 'pending';
            // 只记状态与 groupId 前 8 位：申请链路里没有任何需要落日志的正文。
            clientLog('[admin] group apply groupId=' + shortId(groupId) + ' status=' + status);
            sendJson(res, 200, { ok: true, status, reason: out.reason == null ? null : String(out.reason) });
          } catch (error) {
            const reason = String(error?.message ?? error);
            clientLog('[admin] group apply failed groupId=' + shortId(groupId) + ' err=' + reason.slice(0, 80));
            sendJson(res, errorStatus(error, 502), { error: reason });
          }
          return true;
        }

        if (route === 'group/apply-status' && method === 'GET') {
          const groupId = String(url.searchParams.get('groupId') ?? '').trim();
          const introducerId = String(url.searchParams.get('introducer') ?? '').trim();
          if (groupId === '' || introducerId === '') {
            sendJson(res, 400, { error: 'bad-request' });
            return true;
          }
          const peer = typeof store?.getPeer === 'function' ? store.getPeer(introducerId) : null;
          if (!peer || !peer.baseUrl || !peer.secret) {
            clientLog('[admin] group apply-status refused introducer=' + shortId(introducerId) + ' (unknown peer)');
            sendJson(res, 404, { error: 'unknown-peer' });
            return true;
          }
          const poll = netFn('pollApplication');
          if (!poll) {
            clientLog('[admin] group apply-status unsupported (poll-unavailable)');
            sendJson(res, 501, { error: 'apply-status-unsupported' });
            return true;
          }
          const self = selfIdentity();
          try {
            const out = (await poll({
              baseUrl: String(peer.baseUrl),
              secret: peer.secret,
              senderId: self.peerId,
              groupId,
            })) ?? {};
            const status = APPLICATION_STATUSES.includes(String(out.status ?? '')) ? String(out.status) : 'unknown';
            // 群密钥绝不进浏览器：grant 只交给接线点落盘（group-key.json 是 host 的地盘），
            // 日志也只用世代与成员数说话。
            const writeGrant = out.grant ? grantWriter() : null;
            if (out.grant && writeGrant) {
              try {
                await writeGrant(out.grant);
                clientLog('[admin] group grant applied groupId=' + shortId(groupId)
                  + ' keyVersion=' + (out.grant.keyVersion ?? '?')
                  + ' members=' + (Array.isArray(out.grant.members) ? out.grant.members.length : '?'));
              } catch (error) {
                clientLog('[admin] group grant apply failed groupId=' + shortId(groupId)
                  + ' err=' + String(error?.message ?? error).slice(0, 80));
              }
            } else if (out.grant) {
              clientLog('[admin] group grant dropped groupId=' + shortId(groupId) + ' (no writer: applyGrant/stateDir missing)');
            }
            clientLog('[admin] group apply-status groupId=' + shortId(groupId) + ' status=' + status);
            sendJson(res, 200, { status, reason: out.reason == null ? null : String(out.reason) });
          } catch (error) {
            const reason = String(error?.message ?? error);
            clientLog('[admin] group apply-status failed groupId=' + shortId(groupId) + ' err=' + reason.slice(0, 80));
            sendJson(res, errorStatus(error, 502), { error: reason });
          }
          return true;
        }

        if (route === 'group/advertise' && method === 'POST') {
          const resolved = await resolveGroup();
          if (resolved.status !== 'ok') {
            const reason = resolved.status === 'error' ? resolved.reason : 'group-disabled';
            clientLog('[admin] group advertise refused err=' + reason);
            sendJson(res, resolved.status === 'error' ? 502 : 409, { error: reason });
            return true;
          }
          if (resolved.isHub !== true) {
            clientLog('[admin] group advertise refused (hub only)');
            sendJson(res, 403, { error: 'hub-only' });
            return true;
          }
          let snapshot = {};
          try {
            snapshot = (await resolved.api.state({ sinceSeq: 0 })) ?? {};
          } catch (error) {
            const reason = String(error?.message ?? error);
            clientLog('[admin] group advertise failed err=' + reason);
            sendJson(res, errorStatus(error, 502), { error: reason });
            return true;
          }
          const groupId = String(snapshot.groupId ?? '');
          const groupName = String(snapshot.name ?? '');
          if (groupId === '' || groupName === '') {
            clientLog('[admin] group advertise refused (group not ready)');
            sendJson(res, 409, { error: 'group-not-ready' });
            return true;
          }
          // 契约 §2(b)：手动广播无节流，返回广播对象数量（面板显示的就是这个数）。
          const out = await broadcastGroupName({ memberIds: memberIdsOf(snapshot), groupId, name: groupName });
          if (out.unsupported) {
            clientLog('[admin] group advertise unsupported (advertise-unavailable) targets=' + out.targets);
            sendJson(res, 501, { error: 'advertise-unsupported', targets: out.targets, sent: 0 });
            return true;
          }
          clientLog('[admin] group advertise groupId=' + shortId(groupId)
            + ' targets=' + out.targets + ' sent=' + out.sent);
          sendJson(res, 200, { ok: true, targets: out.targets, sent: out.sent });
          return true;
        }

        sendJson(res, 404, { error: 'not-found' });
        return true;
      } catch (error) {
        sendJson(res, 400, { error: String(error?.message ?? error) });
        return true;
      }
    },
  };
}

/** The browser half: a floating panel injected into the DSH index page. */
export const PANEL_SCRIPT = `
(() => {
  if (window.__dshLanPeersPanel) return;
  window.__dshLanPeersPanel = true;
  // S3：管理接口的会话 token。它只活在「本机回环 host 直出的这份脚本」和
  // <stateDir>/admin-token 里 —— 绝不进 URL、日志、错误消息。React 半
  // （lib/client.js）从这里设的全局读同一个值，读不到就降级成不发请求。
  const T = '${ADMIN_TOKEN}';
  window.__lanPeersToken = T;
  // 失败时把 body/status 挂到 Error 上（v0.8.0 改名查重要读 409 的 conflicts 清单），
  // Error.message 仍是原来的 error 字符串 —— 既有调用点看到的行为不变。
  const api = (path, init) => {
    const options = Object.assign({}, init);
    const headers = Object.assign({}, options.headers);
    headers['X-Lan-Peers-Token'] = T;
    // 写操作服务端只收 JSON（text/plain 这类简单请求一律 415），这里统一补上。
    const verb = String(options.method || 'GET').toUpperCase();
    if (verb !== 'GET' && verb !== 'HEAD' && !headers['Content-Type']) {
      headers['Content-Type'] = 'application/json';
    }
    options.headers = headers;
    return fetch('/api/lan-peers/' + path, options).then(async (r) => {
      const body = await r.json().catch(() => ({}));
      if (!r.ok) {
        const error = new Error(body.error || ('HTTP ' + r.status));
        error.status = r.status;
        error.body = body;
        throw error;
      }
      return body;
    });
  };

  const style = document.createElement('style');
  style.textContent = \`
    #dshLpBtn{position:fixed;z-index:2147483000;border:1px solid #3f6ae0;background:#1b2333;color:#dfe7ff;border-radius:999px;padding:8px 14px;font:13px/1.2 system-ui;cursor:grab;box-shadow:0 6px 20px rgba(0,0,0,.35);touch-action:none;user-select:none;white-space:nowrap}
    #dshLpPanel{position:fixed;width:320px;z-index:2147483000;background:#161b22;color:#e6edf3;border:1px solid #30363d;border-radius:12px;padding:14px;font:13px/1.5 system-ui;box-shadow:0 12px 40px rgba(0,0,0,.5);display:none;max-height:70vh;overflow:auto;box-sizing:border-box}
    #dshLpPanel h4{margin:0 0 8px;font-size:13px;color:#9ecbff}
    #dshLpPanel label{display:block;margin:8px 0 4px;color:#8b949e;font-size:12px}
    #dshLpPanel input{width:100%;box-sizing:border-box;background:#0d1117;border:1px solid #30363d;color:#e6edf3;border-radius:6px;padding:6px 8px;font:12px system-ui}
    #dshLpPanel button{margin-top:8px;background:#1f6feb;border:0;color:#fff;border-radius:6px;padding:6px 10px;font:12px system-ui;cursor:pointer}
    #dshLpPanel button.ghost{background:#21262d;border:1px solid #30363d}
    #dshLpPanel .code{font:20px/1.3 ui-monospace,monospace;letter-spacing:2px;color:#7ee787;margin-top:6px}
    #dshLpPanel .hint{color:#8b949e;font-size:11px;margin-top:4px}
    #dshLpPanel .peer{border-top:1px solid #21262d;padding:6px 0;font-size:12px;color:#c9d1d9}
    #dshLpPanel .job{display:flex;gap:6px;justify-content:space-between;border-top:1px solid #21262d;padding:5px 0;font-size:12px;color:#c9d1d9}
    #dshLpPanel .job .st{color:#7ee787;white-space:nowrap}
    #dshLpPanel .job .st.run{color:#f0883e}
    #dshLpPanel .job .st.bad{color:#f85149}
    #dshLpMsg{margin-top:8px;font-size:12px;min-height:16px;color:#f0883e}
    #dshLpPanel .tabs{display:flex;gap:6px;margin:0 0 8px}
    #dshLpPanel .tabs button{margin-top:0;flex:1}
    #dshLpPanel .tabs button.on{background:#1f6feb;border:1px solid #1f6feb;color:#fff}
    #dshLpPanel .member{display:flex;gap:6px;align-items:center;border-top:1px solid #21262d;padding:5px 0;font-size:12px;color:#c9d1d9}
    #dshLpPanel .member .dot{color:#484f58;font-size:10px}
    #dshLpPanel .member .dot.on{color:#3fb950}
    #dshLpPanel .member .gname{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    #dshLpPanel .member .gtime{color:#8b949e;font-size:11px;white-space:nowrap}
    #dshLpPanel .member button{margin-top:0}
    #dshLpPanel .member.gmem{flex-wrap:wrap}
    #dshLpPanel .member.gmem .gsub{flex-basis:100%;display:flex;gap:6px;font-size:11px;color:#8b949e;max-width:100%}
    #dshLpPanel .member.gmem .gsub .gaddr{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    #dshLpPanel .member.gmem .gsub .glag{white-space:nowrap}
    #dshLpPanel .member.gmem .gsub .glag.hot{color:#f85149;font-weight:600}
    #dshLpPanel #dshLpGroupLeader,#dshLpPanel #dshLpGroupRole,#dshLpPanel #dshLpGroupReplica{margin-top:2px}
    #dshLpPanel #dshLpGroupAddrWarn{color:#d29922;margin-top:2px}
    #dshLpPanel #dshLpGroupStatus{margin-top:2px;color:#c9d1d9}
    #dshLpPanel #dshLpGroupDegraded{color:#f85149;font-weight:600;margin-top:4px}
    #dshLpPanel #dshLpGroupMsgs{max-height:180px;overflow:auto;border-top:1px solid #21262d;padding-top:4px}
    #dshLpPanel #dshLpArchiveHead{margin-top:2px;color:#8b949e}
    #dshLpPanel #dshLpGroupArchives{max-height:140px;overflow:auto;border-top:1px solid #21262d;padding-top:4px}
    #dshLpPanel .gmsg{font-size:12px;color:#c9d1d9;border-bottom:1px solid #161b22;padding:3px 0;word-break:break-word}
    #dshLpPanel .gmsg .gk{color:#79c0ff}
  \`;
  document.head.appendChild(style);

  const btn = document.createElement('button');
  btn.id = 'dshLpBtn';
  btn.textContent = '🔗 伙伴';
  const panel = document.createElement('div');
  panel.id = 'dshLpPanel';
  // 静态骨架：只有本文件写死的标签与 id，任何来自对端的内容都走 textContent。
  panel.innerHTML = \`
    <div class="tabs">
      <button class="ghost tab on" id="dshLpTabPeers">伙伴</button>
      <button class="ghost tab" id="dshLpTabGroup">群组</button>
    </div>
    <div id="dshLpPagePeers">
      <label>设备名称</label>
      <input id="dshLpName" maxlength="64" />
      <button class="ghost" id="dshLpSaveName">保存名称</button>
      <label>临时配对码</label>
      <button class="ghost" id="dshLpCode">生成配对码</button>
      <div class="code" id="dshLpCodeText">------</div>
      <div class="hint" id="dshLpCodeHint">生成后只显示一次，请立刻抄下（10 分钟内有效、只能使用一次）</div>
      <label>添加伙伴（对方地址 + 配对码）</label>
      <input id="dshLpUrl" placeholder="192.168.1.10:7788" />
      <input id="dshLpPeerName" placeholder="对方名称（可选）" style="margin-top:6px" />
      <input id="dshLpPairCode" placeholder="六位配对码" style="margin-top:6px" />
      <button id="dshLpPair">建立伙伴关系</button>
      <div id="dshLpPeers"></div>
      <label>派单实时状态</label>
      <div id="dshLpJobs"></div>
    </div>
    <div id="dshLpPageGroup" style="display:none">
      <div class="hint" id="dshLpGroupHead">群组未启用</div>
      <div class="hint" id="dshLpGroupStatus"></div>
      <div class="hint" id="dshLpGroupDegraded" style="display:none"></div>
      <div class="hint" id="dshLpGroupLeader">当前 leader: —</div>
      <div class="hint" id="dshLpGroupRole">我的角色: —</div>
      <div class="hint" id="dshLpGroupReplica"></div>
      <div class="hint" id="dshLpGroupAddrWarn" style="display:none"></div>
      <div id="dshLpGroupMembers"></div>
      <label>群消息（2 秒轮询）</label>
      <div id="dshLpGroupMsgs"></div>
      <input id="dshLpGroupText" maxlength="4000" placeholder="发一条群消息" style="margin-top:6px" />
      <button id="dshLpGroupSend">发送</button>
      <div class="hint" id="dshLpGroupSyntax">@!名字 任务 = 派单给该成员 · @名字 = 提及（不派单）</div>
      <div class="hint" id="dshLpGroupDispatchState"></div>
      <button class="ghost" id="dshLpAccept">本机接单：接单中</button>
      <div class="hint" id="dshLpAcceptHint">关闭后别人 @! 本机会收到 not-accepting</div>
      <div id="dshLpGroupHub" style="display:none">
        <label>群名</label>
        <input id="dshLpGroupName" maxlength="64" />
        <button class="ghost" id="dshLpGroupSaveName">保存群名</button>
        <div class="hint" id="dshLpGroupNameConflicts"></div>
        <button class="ghost" id="dshLpGroupAdvertise">把群名广播给我的伙伴</button>
        <div class="hint" id="dshLpAdvertiseHint"></div>
        <label>待批准</label>
        <div id="dshLpGroupPending"></div>
        <label>归档（只归档、不自动删除）</label>
        <div class="hint" id="dshLpArchiveHead">归档 0 个 · 共 0 B</div>
        <div id="dshLpGroupArchives"></div>
        <label>添加成员（已配对的 peerId）</label>
        <input id="dshLpGroupAddId" placeholder="peerId" />
        <button class="ghost" id="dshLpGroupAdd">添加成员</button>
        <div class="hint">成员行右侧的「移除」按钮可移除该成员</div>
        <button class="ghost" id="dshLpGroupClaim">接管为 leader</button>
        <div class="hint">接管会立即发起一次选举（epoch+1），原 leader 降级为 follower</div>
      </div>
      <div id="dshLpGroupJoinBox" style="display:none">
        <button class="ghost" id="dshLpGroupJoin">加入群组</button>
        <label>按群名加入</label>
        <input id="dshLpGroupFindName" maxlength="64" placeholder="群名" />
        <button class="ghost" id="dshLpGroupFind">查找</button>
        <div class="hint" id="dshLpFindHint">查重范围：已配对伙伴及其已知群</div>
        <div id="dshLpGroupFindResult"></div>
        <div class="hint" id="dshLpApplyStatus"></div>
      </div>
    </div>
    <div id="dshLpMsg"></div>
  \`;
  document.body.appendChild(btn);
  document.body.appendChild(panel);

  // Draggable launcher. Default is the bottom-right corner so it never covers
  // the app's own settings entry; the last drag position is remembered.
  const POS_KEY = 'dsh-lan-peers:launcher:v1';
  const EDGE = 8;
  const clampTo = (v, lo, hi) => Math.min(Math.max(v, lo), Math.max(lo, hi));
  const readPos = () => {
    try {
      const saved = JSON.parse(localStorage.getItem(POS_KEY) || 'null');
      if (saved && typeof saved.x === 'number' && typeof saved.y === 'number') return saved;
    } catch (error) {}
    return null;
  };
  const writePos = (p) => { try { localStorage.setItem(POS_KEY, JSON.stringify(p)); } catch (error) {} };
  const fitPos = (x, y, w, h) => ({
    x: clampTo(x, EDGE, window.innerWidth - w - EDGE),
    y: clampTo(y, EDGE, window.innerHeight - h - EDGE),
  });
  const btnBox = () => ({ w: btn.offsetWidth || 96, h: btn.offsetHeight || 36 });
  let pos = readPos();
  if (!pos) { const box0 = btnBox(); pos = { x: window.innerWidth - box0.w - 16, y: window.innerHeight - box0.h - 16 }; }
  const applyPos = () => {
    const box = btnBox();
    pos = fitPos(pos.x, pos.y, box.w, box.h);
    btn.style.left = pos.x + 'px';
    btn.style.top = pos.y + 'px';
  };
  const placePanel = () => {
    const box = btnBox();
    const width = Math.min(320, window.innerWidth - 2 * EDGE);
    panel.style.width = width + 'px';
    panel.style.left = clampTo(pos.x, EDGE, window.innerWidth - width - EDGE) + 'px';
    if (pos.y + box.h / 2 > window.innerHeight / 2) {
      panel.style.top = 'auto';
      panel.style.bottom = Math.max(EDGE, window.innerHeight - pos.y + 8) + 'px';
    } else {
      panel.style.bottom = 'auto';
      panel.style.top = (pos.y + box.h + 8) + 'px';
    }
  };
  applyPos();
  window.addEventListener('resize', () => {
    applyPos();
    if (panel.style.display === 'block') placePanel();
  });

  let drag = null;
  let skipClick = false;
  btn.addEventListener('pointerdown', (event) => {
    if (event.button !== 0) return;
    // A drag that ends off-button may never emit click; never leave the swallow
    // flag armed, or the next real click would be ignored.
    skipClick = false;
    const rect = btn.getBoundingClientRect();
    drag = { id: event.pointerId, dx: event.clientX - rect.left, dy: event.clientY - rect.top, x0: event.clientX, y0: event.clientY, w: rect.width, h: rect.height, moved: false };
    if (btn.setPointerCapture) btn.setPointerCapture(event.pointerId);
  });
  btn.addEventListener('pointermove', (event) => {
    if (!drag || drag.id !== event.pointerId) return;
    // 4px threshold: below it this is still a click, not a drag.
    if (!drag.moved && Math.abs(event.clientX - drag.x0) + Math.abs(event.clientY - drag.y0) < 4) return;
    drag.moved = true;
    btn.style.cursor = 'grabbing';
    pos = fitPos(event.clientX - drag.dx, event.clientY - drag.dy, drag.w, drag.h);
    applyPos();
    if (panel.style.display === 'block') placePanel();
  });
  const endDrag = (event) => {
    if (!drag || drag.id !== event.pointerId) return;
    const moved = drag.moved;
    drag = null;
    btn.style.cursor = 'grab';
    if (btn.releasePointerCapture) btn.releasePointerCapture(event.pointerId);
    if (moved) { skipClick = true; writePos(pos); }
  };
  btn.addEventListener('pointerup', endDrag);
  btn.addEventListener('pointercancel', endDrag);
  btn.addEventListener('keydown', (event) => {
    const step = event.shiftKey ? 24 : 8;
    const delta = { ArrowLeft: [-step, 0], ArrowRight: [step, 0], ArrowUp: [0, -step], ArrowDown: [0, step] }[event.key];
    if (!delta) return;
    event.preventDefault();
    const box = btnBox();
    pos = fitPos(pos.x + delta[0], pos.y + delta[1], box.w, box.h);
    applyPos();
    if (panel.style.display === 'block') placePanel();
    writePos(pos);
  });

  const $ = (id) => panel.querySelector('#' + id);
  let timer = null;
  // M6：手上这一份码（只在「生成」那一次的响应里有）的过期时刻；state 不再回显码，
  // 所以刷新面板时它决定是继续显示码还是只说「已生成，剩余 N 秒」。
  let shownCodeExpiresAt = 0;
  const msg = (text) => { $('dshLpMsg').textContent = text || ''; };

  function renderPeers(peers, dropPeer) {
    const box = $('dshLpPeers');
    box.innerHTML = '';
    if (!peers.length) { box.innerHTML = '<div class="peer">还没有伙伴</div>'; return; }
    for (const p of peers) {
      const row = document.createElement('div');
      row.className = 'peer';
      row.style.display = 'flex';
      row.style.gap = '6px';
      row.style.alignItems = 'center';
      row.style.justifyContent = 'space-between';
      const label = document.createElement('span');
      // textContent, never innerHTML: the peer name comes from the other machine.
      label.textContent = p.name + ' · ' + (p.baseUrl || '(仅入站)');
      const drop = document.createElement('button');
      drop.className = 'ghost';
      drop.textContent = '解除';
      drop.style.marginTop = '0';
      drop.style.whiteSpace = 'nowrap';
      drop.onclick = () => dropPeer(p, drop);
      row.appendChild(label);
      row.appendChild(drop);
      box.appendChild(row);
    }
  }

  // Unpair: the host deletes its record and, when the peer is online and
  // unpair-capable, asks the peer to delete its record too.
  async function dropPeer(p, button) {
    if (!window.confirm('解除与 ' + p.name + ' 的配对？对端在线时会同步删除。')) return;
    if (button) button.disabled = true;
    msg('解除中…');
    try {
      const out = await api('unpair', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ peerId: p.peerId }),
      });
      const synced = !!(out.remote && out.remote.notified);
      const name = (out.peer && out.peer.name) || p.name;
      msg('已解除与 ' + name + ' 的配对' + (synced ? '（对端已同步删除）' : '（仅本地）'));
      await refresh();
    } catch (error) {
      msg(String(error.message || error));
    } finally {
      if (button) button.disabled = false;
    }
  }

  function renderJobs(jobs) {
    const box = $('dshLpJobs');
    box.innerHTML = '';
    if (!jobs.length) { box.innerHTML = '<div class="job"><span>暂无派单记录</span></div>'; return; }
    for (const job of jobs) {
      const row = document.createElement('div');
      row.className = 'job';
      const label = document.createElement('span');
      label.textContent = job.peer + ' · ' + job.status + ' · ' + Math.round((job.elapsedMs || 0) / 1000) + 's';
      const badge = document.createElement('span');
      const ok = job.status === 'done';
      const bad = job.status === 'error' || job.status === 'timeout';
      badge.className = 'st' + (ok ? '' : bad ? ' bad' : ' run');
      badge.textContent = job.transport || '';
      row.appendChild(label);
      row.appendChild(badge);
      box.appendChild(row);
    }
  }

  function startCountdown(expiresAt) {
    clearInterval(timer);
    const tick = () => {
      const left = Math.max(0, Math.floor((expiresAt - Date.now()) / 1000));
      const m = String(Math.floor(left / 60)).padStart(2, '0');
      const s = String(left % 60).padStart(2, '0');
      $('dshLpCodeHint').textContent = left > 0
        ? ('已生成，剩余 ' + left + ' 秒（' + m + ':' + s + '）· 码只显示这一次，请现在抄下')
        : '已过期，请重新生成';
      if (left <= 0) clearInterval(timer);
    };
    tick();
    timer = setInterval(tick, 1000);
  }

  async function refresh() {
    try {
      const st = await api('state');
      $('dshLpName').value = st.name;
      renderPeers(st.peers || [], dropPeer);
      // M6：state 只回 {active, expiresInSec}，码本身不回显。手上还留着「生成」那次
      // 拿到的码就继续显示它，否则只报状态 —— 抄不下来就只能重新生成。
      if (st.pairing && st.pairing.active) {
        const left = Number(st.pairing.expiresInSec);
        const seconds = Number.isFinite(left) && left > 0 ? left : 0;
        if (shownCodeExpiresAt <= Date.now()) {
          $('dshLpCodeText').textContent = '已生成（码不回显）';
          startCountdown(Date.now() + seconds * 1000);
        }
      } else {
        shownCodeExpiresAt = 0;
      }
    } catch (error) {
      msg(String(error.message || error));
    }
    pollJobs();
  }

  // Elapsed time has to tick locally: the peer only reports on transitions.
  let jobsTimer = null;
  const pollJobs = () => {
    api('dispatch')
      .then((out) => renderJobs(out.dispatches || []))
      .catch(() => {});
  };

// ---- 群组页（v0.5.0：2s 增量轮询，全部用户内容走 textContent）----
  // 面板只读本机回环接口；对端名字/正文一律不可信，禁止参与 innerHTML 拼接。
  const GROUP_POLL_MS = 2000;
  let groupSeq = 0;        // 请求游标：GET group?sinceSeq=<groupSeq>
  let groupShown = 0;      // 已渲染的最大 seq（断流/重复帧去重）
  let groupTimer = null;
  let groupTabOpen = false;
  let groupIsHub = false;
  let groupKnown = false;   // 是否拉过群状态：未知时配对成功后要先拉一次再决定问不问
  let groupEnabled = false; // 最近一次 GET group 的 enabled，缺省按未启用处理
  // v0.8.2-α（契约 §4/§5）：本机接单开关的当前值（面板据此翻转）+ 成员 id→名字（派单摘要要显示目标名）
  let acceptOn = true;
  let groupNames = {};
  // v0.8.0（契约 §5.2）：申请中的上下文（有它才轮询状态），最长 10 分钟。
  const APPLY_MAX_WAIT_MS = 600000;
  let applyCtx = null;
  // 已决定的申请在「待批准」区块下带一行决定时间（契约 §7 的 decidedAt 落盘是 ISO，
  // 面板只负责显示）；列表可能很长，只留最近几条。
  const DECIDED_SHOWN_MAX = 5;
  // v0.8.0-β（DESIGN §18.2）：归档列表每次进群组页只拉一次（另有删除后主动刷新），
  // 不挂在 2s 节拍上 —— 归档不会自己变，反复拉只会白读磁盘。
  let archivesLoaded = false;

  // 时间戳可能是毫秒数（群消息 ts）或 ISO 字符串（hub 的成员 lastSeen/joinedAt）
  function toMs(value) {
    const numeric = Number(value);
    if (Number.isFinite(numeric) && numeric > 0) return numeric;
    const parsed = Date.parse(String(value == null ? '' : value));
    return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
  }

  function clockText(ts) {
    const value = toMs(ts);
    const date = new Date(value > 0 ? value : Date.now());
    const pad = (n) => (n < 10 ? '0' + n : String(n));
    return pad(date.getHours()) + ':' + pad(date.getMinutes()) + ':' + pad(date.getSeconds());
  }

  function agoText(ts) {
    const value = toMs(ts);
    if (value <= 0) return '未活动';
    const delta = Math.max(0, Date.now() - value);
    if (delta < 60000) return Math.round(delta / 1000) + 's前';
    if (delta < 3600000) return Math.round(delta / 60000) + 'm前';
    return Math.round(delta / 3600000) + 'h前';
  }

  // meta 摘要只列白名单字段（DESIGN §3），未知字段不渲染。
  function metaText(meta) {
    if (!meta || typeof meta !== 'object') return '';
    const parts = [];
    if (meta.phase) parts.push(String(meta.phase));
    if (meta.status) parts.push(String(meta.status));
    if (meta.transport) parts.push(String(meta.transport));
    if (meta.elapsedMs != null && Number.isFinite(Number(meta.elapsedMs))) parts.push(Math.round(Number(meta.elapsedMs)) + 'ms');
    if (meta.replyChars != null && Number.isFinite(Number(meta.replyChars))) parts.push(Number(meta.replyChars) + '字');
    return parts.join('/');
  }

  function clearBox(id) {
    const box = $(id);
    box.innerHTML = '';
    return box;
  }

  function stopGroupPoll() {
    if (groupTimer) { clearInterval(groupTimer); groupTimer = null; }
  }

  function startGroupPoll() {
    stopGroupPoll();
    groupTimer = setInterval(pollGroup, GROUP_POLL_MS);
  }

  function renderMembers(members) {
    const box = clearBox('dshLpGroupMembers');
    if (!members.length) {
      const none = document.createElement('div');
      none.className = 'member';
      none.textContent = '还没有成员';
      box.appendChild(none);
      return;
    }
    for (const member of members) {
      const row = document.createElement('div');
      row.className = 'member gmem';
      const dot = document.createElement('span');
      dot.className = 'dot' + (member && member.online ? ' on' : '');
      dot.textContent = member && member.online ? '●' : '○';
      const label = document.createElement('span');
      label.className = 'gname';
      // 名字来自对端：只赋值 textContent，永不拼 innerHTML。
      label.textContent = String((member && (member.name || member.peerId)) || '(未命名)');
      const seen = document.createElement('span');
      seen.className = 'gtime';
      seen.textContent = agoText(member && member.lastSeen);
      row.appendChild(dot);
      row.appendChild(label);
      row.appendChild(seen);
      if (groupIsHub && member && member.peerId) {
        const remove = document.createElement('button');
        remove.className = 'ghost';
        remove.textContent = '移除';
        remove.style.marginTop = '0';
        remove.onclick = () => removeMember(member, remove);
        row.appendChild(remove);
      }
      row.appendChild(memberMeta(member));
      box.appendChild(row);
    }
  }

  /** 成员副行：别人看到的该成员地址（没有就 —）+ 落后 leader 多少条（>0 醒目）。 */
  function memberMeta(member) {
    const sub = document.createElement('div');
    sub.className = 'gsub';
    const addr = document.createElement('span');
    addr.className = 'gaddr';
    // 地址来自对端上报的群状态：只赋值 textContent，永不拼 innerHTML。
    const base = member && typeof member.baseUrl === 'string' ? member.baseUrl : '';
    addr.textContent = base === '' ? '—' : base;
    sub.appendChild(addr);
    const lag = seqOrNull(member ? member.lag : null);
    if (lag !== null) {
      const lagSpan = document.createElement('span');
      lagSpan.className = 'glag' + (lag > 0 ? ' hot' : '');
      lagSpan.textContent = '落后 ' + lag + ' 条';
      sub.appendChild(lagSpan);
    }
    // 契约 §5：成员行的接单状态。字段缺省 = 接单中（老对端没有这个字段，绝不能显示成「已关闭」）。
    const accepts = member ? member.acceptDispatch !== false : true;
    const acceptSpan = document.createElement('span');
    acceptSpan.className = 'gaccept' + (accepts ? '' : ' off');
    acceptSpan.textContent = accepts ? '接单中' : '已关闭';
    sub.appendChild(acceptSpan);
    return sub;
  }

  // -------------------------------------------------------------------------
  // v0.8.0（契约 §3/§5/§8）：按群名查找 · 申请入群 · hub 待批准 · 群名广播
  // 申请人/介绍人/群名都来自对端，一律 textContent；群密钥与 grant 永不上屏。
  // -------------------------------------------------------------------------

  /** groupId 前 8 位：面板只显示前缀，完整 id 留给日志。 */
  function shortIdText(value) {
    const id = String(value == null ? '' : value);
    return id === '' ? '—' : id.slice(0, 8);
  }

  /** 体积文案：B 不带小数，KB/MB 一位小数（归档总体积与每行共用同一口径）。 */
  function sizeText(bytes) {
    const value = Math.max(0, Math.round(Number(bytes) || 0));
    if (value < 1024) return value + ' B';
    if (value < 1048576) return (value / 1024).toFixed(1) + ' KB';
    return (value / 1048576).toFixed(1) + ' MB';
  }

  /**
   * hub 侧「归档」区块（DESIGN §18.2）：顶行「归档 N 个 · 共 X」，每行
   * 文件名 / seq 区间 / 条数 / 体积 / 时间 / 删除。
   * 文件名来自 hub 落盘的索引：只进 textContent 与 confirm 文案。
   */
  function renderArchives(out) {
    const box = clearBox('dshLpGroupArchives');
    const data = out && typeof out === 'object' ? out : {};
    const list = Array.isArray(data.archives) ? data.archives : [];
    const declared = Number(data.totalBytes);
    const total = Number.isFinite(declared) && declared >= 0
      ? declared
      : list.reduce((sum, item) => sum + (Number(item && item.bytes) || 0), 0);
    $('dshLpArchiveHead').textContent = '归档 ' + list.length + ' 个 · 共 ' + sizeText(total);
    if (!list.length) {
      const none = document.createElement('div');
      none.className = 'peer';
      none.textContent = '还没有归档（超过 20 MB 或超过保留天数才归档，不会自动删除）';
      box.appendChild(none);
      return;
    }
    for (const item of list) {
      const file = String((item && item.file) || '');
      if (file === '') continue;
      const row = document.createElement('div');
      row.className = 'member garchive';
      const name = document.createElement('span');
      name.className = 'gname';
      name.textContent = file;
      const remove = document.createElement('button');
      remove.className = 'ghost';
      remove.textContent = '删除';
      remove.onclick = () => deleteArchive(item, remove);
      const meta = document.createElement('div');
      meta.className = 'gsub';
      const from = seqOrNull(item.fromSeq);
      const to = seqOrNull(item.toSeq);
      const count = seqOrNull(item.count);
      const created = toMs(item.createdAt);
      meta.textContent = 'seq ' + (from === null ? '—' : from) + '–' + (to === null ? '—' : to)
        + ' · ' + (count === null ? '—' : count) + ' 条'
        + ' · ' + sizeText(item.bytes)
        + ' · ' + (created > 0 ? agoText(created) : '时间未知');
      row.appendChild(name);
      row.appendChild(remove);
      row.appendChild(meta);
      box.appendChild(row);
    }
  }

  /** 拉一次归档列表并渲染；失败只写 msg 区（并记住已试过，免得 2s 节拍反复撞同一个错误）。 */
  async function loadArchives() {
    archivesLoaded = true;
    try {
      renderArchives(await api('group/archives'));
    } catch (error) {
      msg('归档：' + String(error && error.message ? error.message : error));
    }
  }

  /** 删除单个归档：二次确认 → POST → 刷新列表并提示释放了多少空间。 */
  async function deleteArchive(item, button) {
    const file = String((item && item.file) || '');
    if (file === '') return;
    if (!window.confirm('删除归档 ' + file + '？删除后无法恢复（seq 号不会复用）')) return;
    if (button) button.disabled = true;
    msg('');
    try {
      const out = await api('group/archives', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ file: file, action: 'delete' }),
      });
      const removed = Number(out && out.removedBytes);
      msg('已删除归档 ' + file
        + (Number.isFinite(removed) && removed > 0 ? '，释放 ' + sizeText(removed) : ''));
      await loadArchives();
    } catch (error) {
      msg('删除归档失败：' + String(error && error.message ? error.message : error));
      if (button) button.disabled = false;
    }
  }

  /** hub 侧「待批准」区块：申请人 + 介绍人 + 提交时间 + 批准/拒绝，末尾附最近的决定。 */
  function renderPendingApplications(list) {
    const box = clearBox('dshLpGroupPending');
    // 明确读到失败（null）与「老 hub 没这个字段」（undefined）要分开说：
    // 前者是异常，后者只是没有待批准可言。
    const unreadable = list === null;
    const all = Array.isArray(list) ? list : [];
    const pending = all.filter((item) => item && item.status === 'pending');
    const decided = all
      .filter((item) => item && (item.status === 'approved' || item.status === 'rejected'))
      .slice(0, DECIDED_SHOWN_MAX);
    if (!pending.length) {
      const none = document.createElement('div');
      none.className = 'peer';
      none.textContent = unreadable ? '申请列表暂不可读' : '没有待批准的申请';
      box.appendChild(none);
      if (!unreadable) renderDecidedApplications(box, decided);
      return;
    }
    for (const item of pending) {
      const row = document.createElement('div');
      row.className = 'member gpending';
      const label = document.createElement('span');
      label.className = 'gname';
      label.textContent = String(item.name || item.peerId || '(未知)');
      const approve = document.createElement('button');
      approve.className = 'ghost';
      approve.textContent = '批准';
      approve.onclick = () => decideApplication(item, 'approve', approve);
      const reject = document.createElement('button');
      reject.className = 'ghost';
      reject.textContent = '拒绝';
      reject.onclick = () => decideApplication(item, 'reject', reject);
      const meta = document.createElement('div');
      meta.className = 'gsub';
      const by = String(item.introducedByName || '') || shortIdText(item.introducedBy);
      meta.textContent = '介绍人 ' + by + ' · ' + agoText(item.at);
      row.appendChild(label);
      row.appendChild(approve);
      row.appendChild(reject);
      row.appendChild(meta);
      box.appendChild(row);
    }
    renderDecidedApplications(box, decided);
  }

  /**
   * 已决定申请的一行摘要：状态 + 申请人 + 决定时间（decidedAt 缺失时如实写「未知」，
   * 不拿提交时间冒充决定时间）。host 落盘是 ISO，这里用 toMs 统一吃下。
   */
  function renderDecidedApplications(box, decided) {
    for (const item of decided) {
      const row = document.createElement('div');
      row.className = 'gsub gdecided';
      const stamp = toMs(item.decidedAt);
      const label = item.status === 'approved' ? '已批准' : '已拒绝';
      row.textContent = label + ' · ' + String(item.name || item.peerId || '(未知)')
        + ' · ' + (stamp > 0 ? '决定于 ' + agoText(stamp) : '决定时间未知');
      box.appendChild(row);
    }
  }

  /** 成员侧查找结果：群名 · hub 名 · 介绍人 + 「申请加入」。 */
  function renderFindResults(matches) {
    const box = clearBox('dshLpGroupFindResult');
    if (!matches.length) return;
    for (const match of matches) {
      const row = document.createElement('div');
      row.className = 'member gfind';
      const label = document.createElement('span');
      label.className = 'gname';
      label.textContent = String(match.name || '(未命名群)');
      const apply = document.createElement('button');
      apply.className = 'ghost';
      apply.textContent = '申请加入';
      apply.onclick = () => applyForMatch(match, apply);
      const meta = document.createElement('div');
      meta.className = 'gsub';
      const hub = match.hub ? String(match.hub.name || match.hub.peerId || '') : '';
      const via = match.via ? String(match.via.name || match.via.peerId || '') : '';
      meta.textContent = 'hub ' + (hub === '' ? '—' : hub)
        + ' · 介绍人 ' + (via === '' ? '—' : via)
        + ' · ' + shortIdText(match.groupId);
      row.appendChild(label);
      row.appendChild(apply);
      row.appendChild(meta);
      box.appendChild(row);
    }
  }

  /** 申请状态三态：待批准 / 已加入 / 被拒（未知不写，免得把「没问到」显示成结论）。 */
  function renderApplyStatus(status, reason) {
    const labels = { pending: '待批准', approved: '已加入', rejected: '被拒' };
    const label = labels[String(status || '')] || '';
    const box = $('dshLpApplyStatus');
    if (label === '') { box.textContent = ''; return; }
    box.textContent = '申请状态：' + label + (reason ? '（' + String(reason) + '）' : '');
  }

  /** 改名冲突清单：伙伴名 + 群名 + groupId 前 8 位（契约 §8）。 */
  function renderNameConflicts(conflicts) {
    const box = $('dshLpGroupNameConflicts');
    const list = Array.isArray(conflicts) ? conflicts : [];
    if (!list.length) { box.textContent = ''; return; }
    const lines = [];
    for (const item of list) {
      const peer = String(item.peerName || '') || shortIdText(item.peerId);
      lines.push(peer + ' · ' + String(item.name || '(未命名群)') + ' · ' + shortIdText(item.groupId));
    }
    box.textContent = '群名已被占用（未改名）：' + lines.join('；');
  }

  /** 申请者的状态轮询（契约 §5.2）：最长 10 分钟，超时就停并提示「仍待批准」。 */
  function pollApplyStatus() {
    const ctx = applyCtx;
    if (!ctx) return;
    if (Date.now() - ctx.startedAt > APPLY_MAX_WAIT_MS) {
      applyCtx = null;
      renderApplyStatus('pending');
      msg('仍在待批准，可稍后再试');
      return;
    }
    api('group/apply-status?groupId=' + encodeURIComponent(ctx.groupId)
      + '&introducer=' + encodeURIComponent(ctx.introducer))
      .then((out) => {
        const status = String((out && out.status) || 'unknown');
        renderApplyStatus(status, out && out.reason);
        if (status === 'approved') {
          applyCtx = null;
          msg('已加入群组');
        } else if (status === 'rejected') {
          applyCtx = null;
          msg('申请被拒：' + String((out && out.reason) || '未说明原因'));
        }
      })
      .catch(() => {});
  }

  async function applyForMatch(match, button) {
    const groupId = String((match && match.groupId) || '');
    const introducer = match && match.via ? String(match.via.peerId || '') : '';
    if (groupId === '' || introducer === '') { msg('这条命中缺少介绍人信息，无法申请'); return; }
    if (button) button.disabled = true;
    msg('申请中…');
    try {
      const out = await groupAction('group/apply', { groupId: groupId, introducer: introducer }, '');
      const status = String((out && out.status) || 'pending');
      renderApplyStatus(status, out && out.reason);
      msg(status === 'approved' ? '已加入群组' : (status === 'rejected' ? '申请被拒' : '申请已发出，等待批准'));
      // 待批准才需要轮询；已加入/被拒是一次性的结论。
      applyCtx = status === 'pending' ? { groupId: groupId, introducer: introducer, startedAt: Date.now() } : null;
    } catch (error) {
      msg('申请失败：' + String(error.message || error));
    } finally {
      if (button) button.disabled = false;
    }
  }

  async function decideApplication(item, action, button) {
    const peerId = String((item && item.peerId) || '');
    if (peerId === '') return;
    if (button) button.disabled = true;
    try {
      await groupAction('group/applications', { peerId: peerId, action: action },
        action === 'approve' ? '已批准' : '已拒绝');
      // 决定之后立刻重拉一次群状态：待批准区块与成员表一起更新，不用等下一个 2s 节拍。
      pollGroup();
    } catch (error) {
      msg(String(error.message || error));
    } finally {
      if (button) button.disabled = false;
    }
  }

  /** 面板侧的三态 seq：缺失/非法返回 null，让「0」和「不知道」显示成不同样子。 */
  function seqOrNull(value) {
    if (value === null || value === undefined) return null;
    const numeric = Number(value);
    return isFinite(numeric) && numeric >= 0 ? Math.floor(numeric) : null;
  }

  /** 成员 id → 名字（查不到就显示 peerId 前 8 位，绝不编一个名字出来）。 */
  function memberLabel(peerId) {
    const id = String(peerId == null ? '' : peerId);
    if (id === '') return '—';
    return groupNames[id] || shortIdText(id);
  }

  /**
   * 契约 §3 的派单摘要口径：派单 → 目标：done/failed（reason / 耗时 / 字数）。
   * 只吃 status/reason/elapsedMs/replyChars —— 正文根本不在这个函数能看到的字段里。
   */
  function dispatchSummaryText(outcome) {
    const data = outcome && typeof outcome === 'object' ? outcome : {};
    const raw = String(data.status || '');
    const status = raw === 'done' || raw === 'skipped' ? raw : 'failed';
    // 三态各说各话：skipped 是「这条消息没有 @! 目标」，绝不能显示成完成或失败。
    if (status === 'skipped') return '未派单（消息里没有 @! 目标）';
    // M1：同名歧义是用户的选择问题，不是网络故障 —— 直接给可操作的下一步。
    if (status === 'failed' && String(data.reason || '') === 'ambiguous') {
      return '派单 → ' + memberLabel(data.target) + '：有多个同名成员，请用 @!名字 (短id) 重发';
    }
    const parts = [];
    // reason 不只在 failed 上有意义：done 也可能带 multi-target-ignored（契约 §1 不整条拒绝）。
    if (data.reason != null && String(data.reason) !== '') parts.push(String(data.reason));
    const elapsed = Number(data.elapsedMs);
    if (Number.isFinite(elapsed) && elapsed >= 0) parts.push(Math.round(elapsed) + 'ms');
    const chars = Number(data.replyChars);
    if (Number.isFinite(chars) && chars >= 0) parts.push(Math.round(chars) + '字');
    return '派单 → ' + memberLabel(data.target) + '：' + status
      + (parts.length ? '（' + parts.join(' / ') + '）' : '');
  }

  /** 群消息里的派单行：dispatch-start = 进行中，dispatch-end = 摘要；其它消息返回空串。 */
  function dispatchLine(item) {
    const meta = item && item.meta && typeof item.meta === 'object' ? item.meta : null;
    const phase = meta ? String(meta.phase || '') : '';
    if (phase !== 'dispatch-start' && phase !== 'dispatch-end') return '';
    if (phase === 'dispatch-start') return '派单 → ' + memberLabel(meta.target) + '：进行中';
    return dispatchSummaryText(meta);
  }

  /**
   * 本机接单开关 + 派单状态行（契约 §4/§5）。开关值来自 GET group 的 acceptDispatch
   * （缺省 true：老配置没有这个字段就是接单中）；dispatchState 未接线时后端给 null，
   * 状态行留空 —— 宁可不显示，也不编一个进度出来。
   */
  function renderAccept(data) {
    const accept = !(data && data.acceptDispatch === false);
    acceptOn = accept;
    const button = $('dshLpAccept');
    button.textContent = '本机接单：' + (accept ? '接单中' : '已关闭');
    button.style.display = 'block';
    const state = data && data.dispatch && typeof data.dispatch === 'object' ? data.dispatch : null;
    const target = state && state.lastTarget != null ? String(state.lastTarget) : '';
    const line = $('dshLpGroupDispatchState');
    if (state && state.inFlight === true) {
      line.textContent = '派单中 → ' + memberLabel(target) + '（等回复）';
    } else if (target !== '') {
      line.textContent = '上次派单 → ' + memberLabel(target) + ' · ' + agoText(state.lastAt);
    } else {
      line.textContent = '';
    }
  }

  function appendMessages(list) {
    if (!list.length) return;
    const box = $('dshLpGroupMsgs');
    let added = 0;
    for (const item of list) {
      if (!item) continue;
      const seq = Number(item.seq);
      if (Number.isFinite(seq)) {
        if (seq <= groupShown) continue;              // 同一 seq 只渲染一次
        groupShown = seq;
        if (seq > groupSeq) groupSeq = seq;
      }
      if (box.children.length > 500) box.innerHTML = '';   // 长会话不无限增长
      const from = item.from || {};
      const who = String(from.name || from.peerId || '系统');
      const kind = String(item.kind || 'chat');
      const text = typeof item.text === 'string' ? item.text : '';
      // 契约 §5：派单回执只渲染摘要；item.text 在派单消息上**一律不显示** ——
      // 万一上游把正文写进了群消息，面板也不会把它摊在屏幕上。
      const dispatch = dispatchLine(item);
      let body = dispatch !== '' ? dispatch : text;
      if (dispatch === '' && body === '' && item.meta) body = metaText(item.meta);
      if (body.length > 200) body = body.slice(0, 200) + '…';
      const row = document.createElement('div');
      row.className = 'gmsg';
      row.textContent = clockText(item.ts) + ' · ' + who + ' · ' + kind + (body === '' ? '' : ' · ' + body);
      box.appendChild(row);
      added += 1;
    }
    if (added > 0) {
      box.scrollTop = box.scrollHeight;      // 自动滚到底
    }
  }

  function renderGroup(out) {
    const data = out || {};
    // 配对后的入群询问以「最近一次 GET group」为准：这里记下状态供其判断。
    groupKnown = true;
    groupEnabled = data.enabled === true;
    const head = $('dshLpGroupHead');
    if (data.enabled !== true) {
      groupIsHub = false;
      // 未启用就没有群状态可轮询：停掉定时器，等下次打开页面再试。
      // 例外是有申请在飞的时候 —— 那时的 2s 节拍只服务申请状态（契约 §5.2）。
      if (!applyCtx) stopGroupPoll();
      head.textContent = '群组未启用（config group.enabled=false）';
      $('dshLpGroupLeader').textContent = '当前 leader: —';
      $('dshLpGroupRole').textContent = '我的角色: —';
      $('dshLpGroupReplica').textContent = '';
      $('dshLpGroupStatus').textContent = '';
      $('dshLpGroupDegraded').textContent = '';
      $('dshLpGroupDegraded').style.display = 'none';
      $('dshLpGroupAddrWarn').textContent = '';
      $('dshLpGroupAddrWarn').style.display = 'none';
      $('dshLpGroupHub').style.display = 'none';
      // 还没入群（甚至没配 group.hub）的节点恰恰最需要「按群名加入」，所以这一块留着；
      // 自助「加入群组」按钮由回环接口如实回 group-disabled，不在这里假装可用。
      $('dshLpGroupJoinBox').style.display = 'block';
      clearBox('dshLpGroupMembers');
      clearBox('dshLpGroupMsgs');
      // v0.8.0 的四个区块同样清掉：停用的群不该留着上次的待批准/申请状态。
      clearBox('dshLpGroupPending');
      clearBox('dshLpGroupArchives');
      $('dshLpArchiveHead').textContent = '归档 0 个 · 共 0 B';
      archivesLoaded = false;
      $('dshLpGroupNameConflicts').textContent = '';
      $('dshLpAdvertiseHint').textContent = '';
      // 未启用时没有群可接单：开关与派单状态行一起收起来，别留一个点了会报错的按钮。
      $('dshLpAccept').style.display = 'none';
      $('dshLpGroupDispatchState').textContent = '';
      // 申请上下文与查找结果不在这里清：未入群的节点本来就没有群状态，
      // 一进来就抹掉「刚找到的群 / 正在等的申请」等于让用户从头再来。
      if (!applyCtx) $('dshLpApplyStatus').textContent = '';
      return;
    }
    if (data.isHub === true) groupIsHub = true; else groupIsHub = false;
    const group = data.group || null;
    const members = group && Array.isArray(group.members) ? group.members : [];
    // 派单摘要要用目标的名字：成员表先归一成 id→名字，appendMessages 才有名字可用。
    groupNames = {};
    for (const member of members) {
      const id = member && member.peerId ? String(member.peerId) : '';
      if (id !== '') groupNames[id] = String(member.name || id);
    }
    const title = group && group.name ? String(group.name) : '(未命名)';
    // v0.8.0：config 关着、但本机已按名入群时，群功能是有效的 —— 这里如实说是怎么来的，
    // 免得用户看着「群组」页却以为自己的群没启用。
    const label = data.enabledSource === 'membership' ? '群组（按名加入）' : '群组';
    head.textContent = label + ' ' + title + (groupIsHub ? ' · 本机 hub' : ' · 成员视角') + ' · ' + members.length + ' 人';
    if (data.error) msg('群组：' + String(data.error));
    renderLeader(data, groupIsHub);
    renderMembers(members);
    renderAccept(data);
    // v0.8.0（契约 §8）：待批准申请跟着同一个 2s 节拍到（hub 侧才有这个字段）。
    // 归档（§18.2）不挂节拍：进页面拉一次、删除成功后再拉一次（归档不会自己变）。
    if (groupIsHub) {
      renderPendingApplications(data.applications);
      if (!archivesLoaded) loadArchives();
    } else {
      clearBox('dshLpGroupPending');
      clearBox('dshLpGroupArchives');
      $('dshLpArchiveHead').textContent = '归档只在 hub 侧可见';
    }
    appendMessages(Array.isArray(data.messages) ? data.messages : []);
    const last = Number(data.lastSeq);
    if (Number.isFinite(last) && last > groupSeq) groupSeq = last;
    $('dshLpGroupHub').style.display = groupIsHub ? 'block' : 'none';
    $('dshLpGroupJoinBox').style.display = groupIsHub ? 'none' : 'block';
    if (groupIsHub && document.activeElement !== $('dshLpGroupName')) {
      $('dshLpGroupName').value = title;
    }
  }

  /** 顶部：当前 leader + epoch、我的角色、本机副本进度、地址提示（全部 textContent）。 */
  function renderLeader(data, isHub) {
    const leader = data.leader && typeof data.leader === 'object' ? data.leader : null;
    const leaderName = leader ? String(leader.name || leader.peerId || '') : '';
    const epoch = seqOrNull(leader ? leader.epoch : null);
    $('dshLpGroupLeader').textContent = '当前 leader: ' + (leaderName === '' ? '—' : leaderName)
      + (epoch === null ? '' : ' (epoch ' + epoch + ')');
    const role = data.selfRole === 'hub' ? 'hub' : (data.selfRole === 'member' ? '成员' : '');
    $('dshLpGroupRole').textContent = '我的角色: ' + (role === '' ? (isHub ? 'hub' : '成员') : role);

    const replica = data.replica && typeof data.replica === 'object' ? data.replica : null;
    const replLast = seqOrNull(replica ? replica.lastSeq : null);
    const replLag = seqOrNull(replica ? replica.lag : null);
    let line = '';
    if (replLast !== null) {
      line = '本地副本: 已到 ' + replLast + ' 条';
      if (replLag === null) line += ' · leader 进度未知';
      else if (replLag > 0) line += ' · 落后 leader ' + replLag + ' 条';
      else line += ' · 已同步';
    }
    $('dshLpGroupReplica').textContent = line;

    // 配置里没写 advertiseBaseUrl 时本机靠自动探测，别人看到的地址若不同就得让用户去改配置
    const advertises = typeof data.advertiseBaseUrl === 'string' ? data.advertiseBaseUrl : '';
    const seenByOthers = typeof data.selfBaseUrl === 'string' ? data.selfBaseUrl : '';
    const source = typeof data.advertiseSource === 'string' ? data.advertiseSource : '';
    const warn = $('dshLpGroupAddrWarn');
    if (source !== 'config' && seenByOthers !== '' && seenByOthers !== advertises) {
      warn.textContent = '别人看到的你的地址是 ' + seenByOthers + '，如不对请在 config 里设 group.advertiseBaseUrl';
      warn.style.display = 'block';
    } else {
      warn.textContent = '';
      warn.style.display = 'none';
    }
    renderRoleStatus(data, leaderName, epoch);
  }

  /**
   * v0.7.0 S3（契约 §7）：顶部状态行 = 角色 / epoch / leader / quorum 模式 / 未提交条数，
   * degraded（无 leader 或租约过期）时另起一行醒目提示。字段缺失降级成 —，不写 NaN。
   */
  function renderRoleStatus(data, leaderName, epoch) {
    const role = typeof data.role === 'string' && data.role !== '' ? data.role : '—';
    const quorum = data.quorum === 'none' || data.quorum === 'majority' ? data.quorum : '—';
    const pending = seqOrNull(data.pendingCount);
    $('dshLpGroupStatus').textContent = '角色 ' + role
      + ' · epoch ' + (epoch === null ? '—' : epoch)
      + ' · leader ' + (leaderName === '' ? '—' : leaderName)
      + ' · quorum 模式 ' + quorum
      + ' · 未提交 ' + (pending === null ? '—' : pending) + ' 条';
    const degraded = $('dshLpGroupDegraded');
    if (data.degraded === true) {
      degraded.textContent = '当前无 leader，请稍候或手动接管';
      degraded.style.display = 'block';
    } else {
      degraded.textContent = '';
      degraded.style.display = 'none';
    }
  }

  function pollGroup() {
    if (!groupTabOpen) return;
    // 页面隐藏时不轮询（省电、也不在后台刷对端）：待批准列表与申请状态都挂在这一个节拍上，
    // 所以 document.hidden 一为真，v0.8.0 的新请求也一并停。
    if (document.hidden === true) return;
    api('group?sinceSeq=' + groupSeq)
      .then((out) => {
        renderGroup(out);
        if (applyCtx) pollApplyStatus();
      })
      .catch((error) => { msg('群组：' + String(error.message || error)); });
  }

  function setTab(which) {
    const isGroup = which === 'group';
    groupTabOpen = isGroup;
    $('dshLpPagePeers').style.display = isGroup ? 'none' : 'block';
    $('dshLpPageGroup').style.display = isGroup ? 'block' : 'none';
    $('dshLpTabPeers').className = isGroup ? 'ghost tab' : 'ghost tab on';
    $('dshLpTabGroup').className = isGroup ? 'ghost tab on' : 'ghost tab';
    stopGroupPoll();
    if (!isGroup) return;
    groupSeq = 0;
    groupShown = 0;
    // 每次进群组页重新拉归档（别的地方也可能归档过）
    archivesLoaded = false;
    clearBox('dshLpGroupMsgs');
    pollGroup();
    startGroupPoll();
  }

  async function groupAction(path, payload, okText) {
    msg('');
    const out = await api(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (okText) msg(okText);
    return out;
  }

  /**
   * 配对成功后问一次「要不要进群」。群成员身份是信任边界，所以只做一次点击确认，
   * 绝不自动入群；取消就一个请求都不发。
   * hub 侧把刚配对的 peer 拉进本机群（group/member add），成员侧自助 join。
   * 群功能未启用时静默跳过；群状态还没拉过就先 GET 一次再决定，不能把「没拉过」当成「未启用」。
   * 名字来自对端自报，只用于 confirm 文案与 msg，永远不进 innerHTML。
   */
  async function askJoinGroup(peer) {
    const peerId = String((peer && peer.peerId) || '');
    const reported = String((peer && peer.name) || '').trim();
    const name = reported !== '' ? reported : peerId.slice(0, 8);
    if (!groupKnown) {
      try {
        const out = await api('group?sinceSeq=0');
        groupKnown = true;
        groupEnabled = !!(out && out.enabled === true);
        groupIsHub = !!(out && out.isHub === true);
      } catch (error) {
        return;   // 状态都拿不到就不弹框；groupKnown 仍为 false，下次配对再试
      }
    }
    if (!groupEnabled) return;
    const isHub = groupIsHub === true;
    const question = isHub
      ? '把刚配对的「' + name + '」加入群组吗？'
      : '要加入「' + name + ' 的群组」吗？';
    if (typeof window.confirm === 'function' && window.confirm(question) !== true) return;
    try {
      if (isHub) {
        await groupAction('group/member', { peerId: peerId, action: 'add' }, '已把 ' + name + ' 加入群组');
      } else {
        const out = await groupAction('group/join', {}, '');
        const epoch = seqOrNull(out && out.epoch);
        msg(epoch === null ? '已加入群组' : '已加入群组（epoch ' + epoch + '）');
      }
      if (groupTabOpen) pollGroup();
    } catch (error) {
      const reason = String((error && error.message) || error);
      if (isHub) {
        msg('加入群组失败：' + reason);
      } else {
        msg('加入群组失败：' + reason
          + (/not-a-member|403/.test(reason) ? '（对端未开 autoJoin，请 hub 侧在面板「添加成员」）' : ''));
      }
    }
  }

  async function removeMember(member, button) {
    const label = String((member && (member.name || member.peerId)) || '');
    if (typeof window.confirm === 'function' && !window.confirm('把 ' + label + ' 移出群组？')) return;
    if (button) button.disabled = true;
    try {
      await groupAction('group/member', { peerId: member.peerId, action: 'remove' }, '已移除 ' + label);
      pollGroup();
    } catch (error) {
      msg(String(error.message || error));
    } finally {
      if (button) button.disabled = false;
    }
  }
  /**
   * v0.7.0 S3（契约 §7）：手动接管为 leader。二次确认 → POST group/leader，
   * 请求期间禁用按钮；失败（含 {ok:false, reason} 与网络错误）只写 msg 区，不弹异常。
   */
  async function claimLeader() {
    const button = $('dshLpGroupClaim');
    if (typeof window.confirm === 'function'
      && !window.confirm('立即接管为 leader？会触发一次选举（epoch+1），原 leader 降级为 follower。')) return;
    if (button) button.disabled = true;
    try {
      const out = await groupAction('group/leader', { action: 'claim' });
      if (out && out.ok === true) {
        const epoch = seqOrNull(out.epoch);
        msg('已接管为 ' + String(out.role || 'leader') + (epoch === null ? '' : '（epoch ' + epoch + '）'));
        pollGroup();
      } else {
        msg('接管失败：' + String((out && out.reason) || '未知原因'));
      }
    } catch (error) {
      msg(String(error.message || error));
    } finally {
      if (button) button.disabled = false;
    }
  }

  btn.onclick = () => {
    if (skipClick) { skipClick = false; return; }
    const open = panel.style.display === 'block';
    panel.style.display = open ? 'none' : 'block';
    clearInterval(jobsTimer);
    stopGroupPoll();
    if (!open) {
      placePanel();
      refresh();
      jobsTimer = setInterval(pollJobs, 1000);
      if (groupTabOpen) {
        pollGroup();
        startGroupPoll();
      }
    }
  };
  $('dshLpSaveName').onclick = async () => {
    msg('');
    try {
      await api('name', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: $('dshLpName').value }) });
      msg('名称已保存');
    } catch (error) { msg(String(error.message || error)); }
  };
  $('dshLpCode').onclick = async () => {
    msg('');
    try {
      const out = await api('code', { method: 'POST' });
      // 一次性提示：码只在这一刻出现，之后任何接口都不会再回显它。
      $('dshLpCodeText').textContent = out.code;
      shownCodeExpiresAt = Number(out.expiresAt) || 0;
      startCountdown(out.expiresAt);
      msg('已生成配对码，请现在抄下（面板刷新后不再显示）');
    } catch (error) { msg(String(error.message || error)); }
  };
  $('dshLpPair').onclick = async () => {
    msg('配对中…');
    try {
      const out = await api('pair', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: $('dshLpUrl').value, peerName: $('dshLpPeerName').value, code: $('dshLpPairCode').value }),
      });
      msg('已与 ' + out.peer.name + ' 建立伙伴关系');
      $('dshLpUrl').value = ''; $('dshLpPeerName').value = ''; $('dshLpPairCode').value = '';
      refresh();
      await askJoinGroup(out.peer);
    } catch (error) { msg(String(error.message || error)); }
  };

  $('dshLpTabPeers').onclick = () => setTab('peers');
  $('dshLpTabGroup').onclick = () => setTab('group');
  $('dshLpGroupSend').onclick = async () => {
    const input = $('dshLpGroupText');
    const text = String(input.value || '');
    if (text.trim() === '') { msg('消息不能为空'); return; }
    msg('发送中…');
    try {
      const out = await groupAction('group/post', { kind: 'chat', text: text }, '已发送');
      input.value = '';
      // 契约 §1/§5：正文带 @!X 时作者侧已自动派单，摘要只写 msg 区（群历史里由 host 写状态摘要）。
      // skipped 表示这条消息没有派单目标 —— 说成「已派单」就是谎报，所以按三态分开说。
      const dispatch = out && out.dispatch && typeof out.dispatch === 'object' ? out.dispatch : null;
      if (dispatch && dispatch.status !== 'skipped') msg('已发送 · ' + dispatchSummaryText(dispatch));
      pollGroup();
    } catch (error) { msg(String(error.message || error)); }
  };
  /**
   * 契约 §4：本机接单开关。成功后立刻刷新群状态（开关与成员行同源），
   * 失败只写 msg 区 —— 面板绝不在这里假装改成功，也不自己改内存配置。
   */
  $('dshLpAccept').onclick = async () => {
    const next = !acceptOn;
    try {
      const out = await groupAction('group/accept', { acceptDispatch: next }, '');
      const applied = !(out && out.acceptDispatch === false);
      acceptOn = applied;
      msg('本机接单：' + (applied ? '接单中' : '已关闭')
        + (out && out.persisted === false ? '（仅本进程生效，重启后回到配置值）' : ''));
      pollGroup();
    } catch (error) {
      msg('切换接单失败：' + String(error.message || error));
    }
  };
  $('dshLpGroupAdd').onclick = async () => {
    const input = $('dshLpGroupAddId');
    const peerId = String(input.value || '').trim();
    if (peerId === '') { msg('请填写 peerId'); return; }
    try {
      await groupAction('group/member', { peerId: peerId, action: 'add' }, '已添加成员');
      input.value = '';
      pollGroup();
    } catch (error) { msg(String(error.message || error)); }
  };
  $('dshLpGroupSaveName').onclick = async () => {
    const name = String($('dshLpGroupName').value || '').trim();
    if (name === '') { msg('群名不能为空'); return; }
    renderNameConflicts([]);
    try {
      await groupAction('group/config', { name: name }, '群名已更新');
      pollGroup();
    } catch (error) {
      // 契约 §6：409 name-taken 时群名不变，把冲突清单摊开给用户看（伙伴名 + 群名 + id 前缀）。
      const body = error && error.body ? error.body : null;
      if (error && error.status === 409 && body && body.error === 'name-taken') {
        renderNameConflicts(body.conflicts);
        msg('群名已被占用，未改名');
        return;
      }
      msg(String(error.message || error));
    }
  };
  $('dshLpGroupFind').onclick = async () => {
    const name = String($('dshLpGroupFindName').value || '').trim();
    if (name === '') { msg('请输入群名'); return; }
    msg('查找中…');
    try {
      const out = await api('group/lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name }),
      });
      const matches = Array.isArray(out && out.matches) ? out.matches : [];
      renderFindResults(matches);
      if (matches.length === 0) msg('未发现该群（查重范围：已配对伙伴及其已知群）');
      else if (matches.length > 1) msg('发现 ' + matches.length + ' 个同名群，请选择要加入的那个');
      else msg('');
    } catch (error) { msg('查找失败：' + String(error.message || error)); }
  };
  $('dshLpGroupAdvertise').onclick = async () => {
    const hint = $('dshLpAdvertiseHint');
    hint.textContent = '';
    msg('');
    try {
      const out = await api('group/advertise', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      const targets = Number(out && out.targets);
      const sent = Number(out && out.sent);
      hint.textContent = '广播对象 ' + (isFinite(targets) ? targets : 0) + ' 个 · 已发出 '
        + (isFinite(sent) ? sent : 0) + ' 个';
      msg('群名广播已发出');
    } catch (error) { msg('广播失败：' + String(error.message || error)); }
  };
  $('dshLpGroupClaim').onclick = () => claimLeader();
  $('dshLpGroupJoin').onclick = async () => {
    try {
      await groupAction('group/join', {}, '已加入群组');
      pollGroup();
    } catch (error) { msg(String(error.message || error)); }
  };
  window.addEventListener('visibilitychange', () => {
    if (document.hidden === true) { stopGroupPoll(); return; }
    if (groupTabOpen) {
      pollGroup();
      startGroupPoll();
    }
  });
})();
`;
