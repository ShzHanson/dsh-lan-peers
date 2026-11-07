// dsh-lan-peers · loopback admin API + the self-contained settings panel.
//
// All routes live under /lan-peers/ and require BOTH a loopback Host header and
// the instance admin token (createAdmin resolves it from <stateDir>/admin-token),
// so a LAN browser — or a page on any site that reaches 127.0.0.1 — cannot rename
// this device or mint pairing codes. Two routes stay token-free: panel.js (the
// token is inside it, requiring one would deadlock) and client-log (append-only
// diagnostics).
import { randomBytes, timingSafeEqual } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { callPeer, capabilityOf, pairPeer, probePeer } from '../client/peer-call.mjs';
// v0.8.5-α（契约 §6）：新增的设置页与私聊派单弹层文案不硬编码 —— 词表只有 lib/i18n.mjs
// 一份，面板是直出脚本不能 import，所以下面用 t(lang, key) 为两种语言各取一份字面量嵌进
// 脚本（见 PANEL_TEXT）。这样面板里没有第二份文案，也不会出现「只补中文格」的漏项。
import { DEFAULT_LANG, LANGS, keys, resolveLang, t } from './i18n.mjs';
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

// S3：管理接口的会话 token。它是**实例级**的（createAdmin 里以 <stateDir>/admin-token
// 为准解析，见该函数里的真机修复注释），只存在于三个地方：本进程、直出的 panel.js、
// <stateDir>/admin-token（0600，给 CLI/管理脚本）。绝不写进 state.json、URL、日志或错误体。
const ADMIN_TOKEN_HEADER = 'x-lan-peers-token';
const ADMIN_TOKEN_FILE = 'admin-token';
// v0.8.5-α：面板语言开关落在 <stateDir>/config.json 的 lang 上（与 client/cli.mjs 读同一份文件）。
// 界面里显式点选的值比部署期 YAML 更具体，所以它在 resolveLang(config) **之前**生效。
const UI_CONFIG_FILE = 'config.json';
const UI_LANG_VALUES = Object.freeze(['zh', 'en', 'auto']);
// 合法 token 的形状：32 字节随机数的十六进制（小写）。文件内容不匹配即「损坏」。
const ADMIN_TOKEN_PATTERN = /^[0-9a-f]{64}$/;
// 进程级兜底 token，**只在拿不到 stateDir 时**用（测试桩、没有 stateDir 的只读组合）：
// 那时无处落盘，也就无从「以文件为准」。有 stateDir 的实例一律不用它。
const PROCESS_ADMIN_TOKEN = randomBytes(32).toString('hex');
// adminToken() 的出口值：当前实例的那一枚（createAdmin 解析后写这里）。
let currentAdminToken = PROCESS_ADMIN_TOKEN;
// 真机缺陷修复：管理接口挂在 **DSH web 端口**（NAS 3080、桌面每次重启还会变），peer 端口
// 7788 上只有 peer 服务器 —— CLI 默认打 7788 必然 404。所以回环 Host 的管理请求会把
// 自己的地址记进这个文件，CLI 从这里解析。**它不是安全边界**（token 才是唯一凭证），
// 内容也绝不进日志。
const ADMIN_URL_FILE = 'admin-url';
/** 同进程出口（测试/CLI 复用）：返回**当前实例**的 token；跨进程请读 <stateDir>/admin-token。 */
export const adminToken = () => currentAdminToken;

// 版本号从 package.json 读（本模块也被 CLI 直接 import，走 host/server.mjs 的
// PLUGIN_VERSION 会把整个 HTTP 服务器拖进 CLI 进程，所以宁可自己读一次文件）。
const PLUGIN_VERSION = (() => {
  try {
    const raw = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
    return typeof raw.version === 'string' && raw.version !== '' ? raw.version : '0.0.0';
  } catch {
    return '0.0.0';
  }
})();

// 免 token 的两条路由：panel.js 是静态脚本且 token 就在它里面（要求 token 才能取
// token 是死锁）；client-log 只写审计日志、没有敏感读，老面板还得能上报。
// 两条之外一律要 token —— 只读接口也不例外。
const TOKEN_FREE_ROUTES = new Set(['panel.js', 'client-log']);
const READ_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

// 契约 §1：权限三档，顺序即档位高低。它们是协议字段，任何语言下都保持英文原样。
const DISPATCH_PERMISSIONS = ['read-only', 'workspace-write', 'danger-full-access'];
const DISPATCH_APPROVAL_STATES = ['pending', 'approved', 'rejected', 'expired'];

const dispatchPermRank = (value) => DISPATCH_PERMISSIONS.indexOf(String(value ?? '').trim());

/**
 * 契约 §0/§1：本机视角的 prefs（**含 path**）。只在回环管理面回，绝不进协议。
 * 缺省按契约 §1：defaultWorkspaceId 落在第一个存在的 id，maxPermission 落回 workspace-write。
 */
function dispatchPrefsView(raw) {
  const src = raw && typeof raw === 'object' ? raw : {};
  const workspaces = [];
  for (const item of Array.isArray(src.workspaces) ? src.workspaces : []) {
    if (!item || typeof item !== 'object') continue;
    const id = String(item.id ?? '').trim();
    if (id === '') continue;
    workspaces.push({ id, name: String(item.name ?? ''), path: String(item.path ?? '') });
  }
  const ids = new Set(workspaces.map((ws) => ws.id));
  const wanted = String(src.defaultWorkspaceId ?? '').trim();
  const rank = dispatchPermRank(src.maxPermission);
  return {
    defaultWorkspaceId: ids.has(wanted) ? wanted : (workspaces[0]?.id ?? ''),
    maxPermission: rank < 0 ? DISPATCH_PERMISSIONS[1] : DISPATCH_PERMISSIONS[rank],
    workspaces,
  };
}

/**
 * 契约 §2：对外视图 —— **只有 id 与 name**。对端就算违约把 path 带回来，也在这一层被丢掉，
 * 所以「options 响应不含 path」是结构性保证，不是某处判断的结果。
 * 上限缺省/非法时按最低一档算：发送方永远拿不到比它该有的更多权限。
 */
function dispatchOptionsView(raw) {
  const src = raw && typeof raw === 'object' ? raw : {};
  const workspaces = [];
  for (const item of Array.isArray(src.workspaces) ? src.workspaces : []) {
    if (!item || typeof item !== 'object') continue;
    const id = String(item.id ?? '').trim();
    if (id === '') continue;
    workspaces.push({ id, name: String(item.name ?? '') });
  }
  const ids = new Set(workspaces.map((ws) => ws.id));
  const wanted = String(src.defaultWorkspaceId ?? '').trim();
  const rank = dispatchPermRank(src.maxPermission);
  return {
    defaultWorkspaceId: ids.has(wanted) ? wanted : (workspaces[0]?.id ?? ''),
    maxPermission: rank < 0 ? DISPATCH_PERMISSIONS[0] : DISPATCH_PERMISSIONS[rank],
    workspaces,
  };
}

/** 契约 §3：待批准条目**只有这些字段** —— 正文与 path 都不在其中。 */
function dispatchPendingView(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const approvalId = String(raw.approvalId ?? '').trim();
  if (approvalId === '') return null;
  const stamp = (value) => (Number.isFinite(Number(value)) ? Number(value) : 0);
  return {
    approvalId,
    from: String(raw.from ?? ''),
    workspaceId: String(raw.workspaceId ?? ''),
    workspaceName: String(raw.workspaceName ?? ''),
    permission: String(raw.permission ?? ''),
    promptBytes: Math.max(0, Math.floor(stamp(raw.promptBytes))),
    at: stamp(raw.at),
    expiresAt: stamp(raw.expiresAt),
  };
}

/** 契约 §2：审批状态只回 state（+ 已批准时的 sessionId），其余一律不转述。 */
function dispatchApprovalView(raw) {
  const src = raw && typeof raw === 'object' ? raw : {};
  const state = String(src.state ?? '');
  const out = { state: DISPATCH_APPROVAL_STATES.includes(state) ? state : 'pending' };
  const sessionId = String(src.sessionId ?? '');
  if (sessionId !== '') out.sessionId = sessionId;
  return out;
}

function isLoopbackHostname(hostname) {
  return hostname === 'localhost' || hostname === '::1' || hostname === '[::1]'
    || /^127(\.\d{1,3}){3}$/.test(hostname);
}

function hostHeader(req) {
  const raw = req && req.headers ? req.headers.host : undefined;
  return typeof raw === 'string' ? raw.trim() : '';
}

/** 任意请求头的字符串视图（数组形态取第一个；没有就是空串）。 */
function headerOf(req, name) {
  const raw = req && req.headers ? req.headers[name] : undefined;
  const value = Array.isArray(raw) ? raw[0] : raw;
  return typeof value === 'string' ? value.trim() : '';
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

/** 常量时间比较：给的是**本实例**的那枚 token（实例级，不再是模块级常量）。 */
function tokenMatches(req, token) {
  const raw = req && req.headers ? req.headers[ADMIN_TOKEN_HEADER] : undefined;
  const given = Array.isArray(raw) ? raw[0] : raw;
  if (typeof given !== 'string' || given === '') return false;
  const a = Buffer.from(given, 'utf8');
  const b = Buffer.from(String(token ?? ''), 'utf8');
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

/**
 * v0.8.5-α（契约 §3）：文件互传门面 list() 的条目归一。
 * id 是唯一必需字段 —— 没有 id 的条目在面板上既不能接受也不能拒收；其余字段补默认值，
 * 数字统一按 Number 收。from 只透出 peerId/name：对端地址与密钥不在这条视图里。
 */
function normalizeFileEntry(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const id = String(raw.id ?? '').trim();
  if (id === '') return null;
  const from = raw.from && typeof raw.from === 'object'
    ? { peerId: String(raw.from.peerId ?? ''), name: String(raw.from.name ?? '') }
    : { peerId: '', name: String(raw.from ?? '') };
  const at = toMillis(raw.at);
  return {
    id,
    name: String(raw.name ?? ''),
    size: Number.isFinite(Number(raw.size)) ? Number(raw.size) : 0,
    sha256: String(raw.sha256 ?? ''),
    from,
    at: at > 0 ? at : null,
    state: String(raw.state ?? 'pending'),
    // 只有传输中的条目带 received：其它状态的形状与以前逐字一致。
    ...(Number.isFinite(Number(raw.received)) ? { received: Number(raw.received) } : {}),
  };
}

/**
 * v0.8.5-α（契约 §2/§5）：私聊条目归一。id 是唯一必需字段（面板按 id 去重、按 id 对齐
 * 两端历史都没法在缺 id 的行上工作），缺了就整行丢掉。text 原样回给调用方 —— 这一层
 * 不改写也不截断正文，渲染侧（面板）负责 textContent。
 */
function normalizeDmMessage(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const id = String(raw.id ?? '').trim();
  if (id === '') return null;
  const ts = toMillis(raw.ts);
  return {
    id,
    ts: ts > 0 ? ts : 0,
    from: raw.from === 'peer' ? 'peer' : 'self',
    text: String(raw.text ?? ''),
    sessionId: String(raw.sessionId ?? ''),
    state: String(raw.state ?? ''),
  };
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
// v0.8.5-α（契约 §2）：pending-approval = 目标回 202 待批准 —— **不是失败**。回执与面板
// 都要能原样把它带到屏幕上（批准后 hub 会再写一条 done），所以它是第四种合法终态。
const DISPATCH_STATUSES = Object.freeze(['done', 'failed', 'skipped', 'pending-approval']);

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
  return withDispatchScope({
    target: String(data.target ?? target ?? ''),
    targetName: data.targetName == null ? '' : String(data.targetName).slice(0, 64),
    status,
    reason,
    elapsedMs: Number.isFinite(elapsed) && elapsed >= 0 ? Math.round(elapsed) : null,
    replyChars: Number.isFinite(chars) && chars >= 0 ? Math.round(chars) : null,
  }, data);
}

/**
 * 契约 §3：回执里的工作区**只有 id 与 name**。path 不在这两个字段里 —— 所以「群回执不含
 * 任何 path」是结构性保证，不依赖某处判断：目标就算违约把 path 带回来，也在这里被丢掉。
 */
function dispatchWorkspaceView(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const id = String(raw.id ?? '').trim();
  const name = String(raw.name ?? '').trim();
  if (id === '' && name === '') return null;
  return { id, name };
}

/**
 * 契约 §4：目标回告的 workspace/permission/permissionHonored 一律可选 ——
 * 一个字段都没有时**一个都不加**（不带新字段的路径与 0.8.4 逐字一致）。
 */
function withDispatchScope(view, raw) {
  const src = raw && typeof raw === 'object' ? raw : {};
  const workspace = dispatchWorkspaceView(src.workspace);
  if (workspace) view.workspace = workspace;
  const permission = String(src.permission ?? '').trim();
  if (DISPATCH_PERMISSIONS.includes(permission)) view.permission = permission;
  if (typeof src.permissionHonored === 'boolean') view.permissionHonored = src.permissionHonored;
  return view;
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
  // v0.8.5-α（契约 §3/§4）：文件互传门面。默认读 server.files（host 侧挂载），
  // 测试/显式接线可用 files 整块替换；缺席时四条管理路由一律回 501，不假装空列表。
  files = null,
  // v0.8.5-α（契约 §4/§5）：私聊门面 list/send/sync。默认读 server.dm（G1 在 host 侧挂载，
  // index.js 无需改动即可接上）；缺席时三条 dm 路由同样回 501，不假装空对话。
  dm = null,
  // v0.8.5-α（契约 §4/§5）：派单工作区/权限门面 prefs/savePrefs/options/pending/approve/reject。
  // 默认读 server.dispatch（H1 在 host 侧挂载）；缺席时五条路由回 501，不假装空设置。
  dispatch = null,
  // 对端两个只读端点的接线点（测试桩）：{ options(peer), approval(peer, id) }。
  // 不注入时走 client/peer-call 的签名调用 —— 契约 §2 的两条 /v1/dispatch/* 端点。
  dispatchNet = null,
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

  /**
   * 文件门面（契约 §3：list/accept/reject/send/progress）。
   * 每次请求现取一次，所以 host 在 createPeerServer 之后才挂上 server.files 也不会漏
   * —— F1 落地前这里就是空的，缺了如实回 501（可见面的诚实口径与 group 一致）。
   */
  const filesOverride = files;
  const filesFacade = () => {
    if (filesOverride) return filesOverride;
    const facade = server && server.files && typeof server.files === 'object' ? server.files : null;
    return facade;
  };

  /**
   * 私聊门面（契约 §4：list/send/sync）。取用口径与文件门面一致：注入优先，其次现读
   * server.dm —— host 在本进程起来之后才挂上行也不会漏，G1 落地前这里就是空的。
   */
  const dmOverride = dm;
  const dmFacade = () => {
    if (dmOverride) return dmOverride;
    const facade = server && server.dm && typeof server.dm === 'object' ? server.dm : null;
    return facade;
  };

  // 派单门面（契约 §4：prefs/savePrefs/options/pending/approve/reject）。
  // 取用口径与 files/dm 一致：注入优先，其次现读 server.dispatch —— H1 在 host 侧挂上
  // 之前这里就是空的，缺了如实回 501（不假装「没有待批准」）。
  const dispatchOverride = dispatch;
  const dispatchFacade = () => {
    if (dispatchOverride) return dispatchOverride;
    const facade = server && server.dispatch && typeof server.dispatch === 'object' ? server.dispatch : null;
    return facade;
  };
  const dispatchFn = (name) => {
    const facade = dispatchFacade();
    return facade && typeof facade[name] === 'function' ? facade[name].bind(facade) : null;
  };

  // 对端 /v1/dispatch/options 的代理（契约 §2/§5/§6：派单弹层要按对端能力渲染下拉）。
  // 复用既有 per-peer 签名通道，没有新信任面；返回值再被 dispatchOptionsView 洗一遍 ——
  // path 在这一层第二次丢掉（不信任对端）。
  const peerDispatchCall = async (peer, apiPath) => {
    const baseUrl = String(peer?.baseUrl ?? '').trim().replace(/\/+$/, '');
    if (baseUrl === '') {
      const error = new Error('peer-unreachable');
      error.status = 409;
      throw error;
    }
    if (!peer?.secret) {
      const error = new Error('peer-unpaired');
      error.status = 409;
      throw error;
    }
    return callPeer({
      baseUrl,
      secret: peer.secret,
      senderId: store.instanceId,
      method: 'GET',
      apiPath,
      timeoutMs: 10_000,
    });
  };

  // 注入优先（测试桩），否则真打契约 §2 的两条端点。
  const fetchPeerOptions = async (peer) => {
    if (dispatchNet && typeof dispatchNet.options === 'function') return dispatchNet.options(peer);
    return peerDispatchCall(peer, '/v1/dispatch/options');
  };
  const fetchPeerApproval = async (peer, approvalId) => {
    if (dispatchNet && typeof dispatchNet.approval === 'function') return dispatchNet.approval(peer, approvalId);
    return peerDispatchCall(peer, '/v1/dispatch/approval?id=' + encodeURIComponent(approvalId));
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

  // ---- v0.8.5-α：界面语言（<stateDir>/config.json 的 lang）----
  // 生效优先级：stateDir/config.json 的 lang > cordis config.lang > 环境变量 > locale > zh。
  // 文件不存在 / 坏 JSON / 非法值一律当「没点选过」回落到 resolveLang —— 绝不抛错、
  // 也绝不因为一个坏文件让插件起不来。
  const normalizeUiLang = (raw) => {
    const value = typeof raw === 'string' ? raw.trim().toLowerCase() : '';
    return UI_LANG_VALUES.includes(value) ? value : '';
  };
  // 面板轮询很密（1-2s 一次）：先比 mtime+size，文件没动就不重读、不重解析。
  let uiLangCache = { file: '', stamp: '', lang: '' };
  const readUiLang = () => {
    const dir = stateDirOf();
    if (dir === '') return '';
    const file = path.join(dir, UI_CONFIG_FILE);
    let stamp = '';
    try {
      const stat = fs.statSync(file);
      stamp = String(stat.mtimeMs) + ':' + String(stat.size);
      if (uiLangCache.file === file && uiLangCache.stamp === stamp) return uiLangCache.lang;
    } catch {
      uiLangCache = { file, stamp: '', lang: '' };
      return '';
    }
    let lang = '';
    try {
      const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) lang = normalizeUiLang(parsed.lang);
    } catch { lang = ''; }
    uiLangCache = { file, stamp, lang };
    return lang;
  };
  /** 面板当前该用哪一格：点选 zh/en 就听它的；auto/没点选/非法值都交回 resolveLang。 */
  const panelLang = () => {
    const picked = readUiLang();
    if (picked === 'zh' || picked === 'en') return picked;
    return resolveLang(server && server.config ? server.config : {});
  };
  // 原子写（同目录临时文件 + rename，与 admin-token 同一手法），0600，**保留文件里其它键**。
  // 写不进去返回 false，由路由回 500；绝不抛错。
  const writeUiLang = (value) => {
    const dir = stateDirOf();
    if (dir === '') return false;
    const file = path.join(dir, UI_CONFIG_FILE);
    let config = {};
    try {
      const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) config = parsed;
    } catch { config = {}; }
    config.lang = value;
    const tmp = file + '.tmp-' + process.pid + '-' + randomBytes(4).toString('hex');
    try {
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(tmp, JSON.stringify(config, null, 2) + '\n', { mode: 0o600 });
      fs.chmodSync(tmp, 0o600);
      fs.renameSync(tmp, file);
      fs.chmodSync(file, 0o600);
      uiLangCache = { file: '', stamp: '', lang: '' };
      return true;
    } catch {
      try { fs.unlinkSync(tmp); } catch { /* 临时文件也没落下来 */ }
      return false;
    }
  };

  /**
   * S3 · v0.8.5-α 真机修复：管理 token **以文件为准**（<stateDir>/admin-token）。
   *
   * 旧实现是模块加载时 randomBytes(32) 生成一枚、文件只是它的副本 —— 于是每次进程/插件
   * 重启都换一枚：已打开的窗口（桌面窗口不加载 panel.js，手里那枚来自 bootstrap）之后
   * 每个管理请求都 401 且永不恢复，只能手动 Ctrl+R。
   *
   * 威胁模型：token 防的是跨站/CSRF，不是防本机进程（本机进程本来就能读这个文件）。
   * 「每次重启换一枚」因此没有任何安全收益，只让每个已打开页面失效。改成沿用文件之后，
   * 重启不再影响已打开页面。文件损坏/不可读时仍然照旧生成新值 —— 插件不能因此起不来。
   */
  // 读到合法值就沿用；文件不存在、内容不是 64 位小写 hex、或读不出来都回空串，由调用方
  // 重新生成。日志只说「读不到、已重生成」，**绝不带 token**。
  const readTokenFile = (file) => {
    let raw;
    try {
      raw = fs.readFileSync(file, 'utf8');
    } catch (error) {
      // 首次启动（ENOENT）是正常路径，不是「损坏」，不打日志。
      if (error?.code !== 'ENOENT') clientLog('[admin] token file unreadable, regenerated');
      return '';
    }
    const token = raw.trim();
    if (!ADMIN_TOKEN_PATTERN.test(token)) {
      clientLog('[admin] token file unreadable, regenerated');
      return '';
    }
    // 旧文件权限可能比 0600 宽：读到就修正一次。Windows 的 mode 是合成值，chmod 只是尽力
    // 而为 —— 失败也不影响沿用（mode 是加固，不是判据）。
    try {
      if ((fs.statSync(file).mode & 0o777) !== 0o600) fs.chmodSync(file, 0o600);
    } catch { /* 权限修正失败：不影响沿用这枚 token */ }
    return token;
  };

  // 原子写：同目录临时文件 + rename，于是下一个进程绝不会读到写了一半的文件。
  // 写不进去不抛错（只是 CLI 拿不到 token，会看到 401 token-required），也绝不记 token。
  const writeTokenFile = (dir, token) => {
    const file = path.join(dir, ADMIN_TOKEN_FILE);
    const tmp = file + '.tmp-' + process.pid + '-' + randomBytes(4).toString('hex');
    try {
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(tmp, token + '\n', { mode: 0o600 });
      fs.chmodSync(tmp, 0o600);
      fs.renameSync(tmp, file);
      // rename 带来的就是上面那份 0600；这里补一次是为了对付「已存在文件 mode 不会被
      // 覆盖」这条老经验不被任何平台破坏。
      fs.chmodSync(file, 0o600);
      return file;
    } catch {
      try { fs.unlinkSync(tmp); } catch { /* 临时文件也没落下来 */ }
      return '';
    }
  };

  /** 本实例的 token：有 stateDir 就以文件为准，没有就退回进程级那一枚（无处落盘）。 */
  const sessionToken = (() => {
    const dir = stateDirOf();
    if (dir === '') return PROCESS_ADMIN_TOKEN;
    const existing = readTokenFile(path.join(dir, ADMIN_TOKEN_FILE));
    if (existing !== '') return existing;
    const fresh = randomBytes(32).toString('hex');
    writeTokenFile(dir, fresh);
    return fresh;
  })();
  // 四个出口指向同一枚实例 token：adminToken()、直出的 panel.js、bootstrap、请求校验。
  currentAdminToken = sessionToken;
  // 面板语言：按当前生效语言渲一次，并记住「渲进去的是哪一格」——
  // /lang 存了新值、或 config.json 被外部改过时，只有这个值真的变了才重渲（整份脚本 ~200KB）。
  let renderedLang = panelLang();
  const refreshPanelScript = (force = false) => {
    const next = panelLang();
    if (!force && next === renderedLang) return renderedLang;
    renderedLang = next;
    PANEL_SCRIPT = renderPanelScript(sessionToken, next);
    return next;
  };
  PANEL_SCRIPT = renderPanelScript(sessionToken, renderedLang);

  /**
   * 把「本进程的管理接口地址」记到 <stateDir>/admin-url（0600）。
   * 触发条件是**任一**回环 Host 的管理请求（面板一打开就会打 state 等接口）。
   * 内容没变就不重写：面板会持续轮询，别为了同样的字符串反复写盘。
   * 写不进去只是 CLI 少了便利信息，绝不因此拒绝请求，也绝不写日志（地址与文件名都不进日志）。
   */
  let adminUrlFile = '';
  const rememberAdminUrl = (req) => {
    if (!hostIsLoopback(req)) return;
    const host = hostHeader(req);
    if (host === '') return;
    const dir = stateDirOf();
    if (dir === '') return;
    const value = 'http://' + host;
    const file = adminUrlFile !== '' ? adminUrlFile : path.join(dir, ADMIN_URL_FILE);
    try {
      if (fs.readFileSync(file, 'utf8').trim() === value) {
        adminUrlFile = file;
        return;
      }
    } catch { /* 还没这个文件，往下写 */ }
    try {
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(file, value + '\n', { mode: 0o600 });
      // 已存在的文件 mode 不会因 writeFileSync 改变，显式补一次 0600。
      fs.chmodSync(file, 0o600);
      adminUrlFile = file;
    } catch { /* 只读 stateDir / 配额满：静默放弃 */ }
  };

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
  const coreDispatch = async ({ target, task, extraTargets = 0, workspaceId = '', permission = '' }) => {
    const facade = groupFacade();
    if (!facade || typeof facade.dispatch !== 'function') {
      const error = new Error('dispatch-unsupported');
      error.status = 501;
      throw error;
    }
    // 契约 §1/§2：新字段只在真的有值时才进请求体 —— 老 host 收到的形状与 0.8.4 逐字一致。
    const request = { target, task, extraTargets };
    if (String(workspaceId) !== '') request.workspaceId = String(workspaceId);
    if (String(permission) !== '') request.permission = String(permission);
    const out = await facade.dispatch(request);
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
    post({ kind, text, meta, target, workspaceId, permission }) {
      // 契约 §1：dispatch 帖的三件新字段原样交给 host 存进群历史（只有 id/名字，没有 path）。
      // 一个都没带时不往请求里加键：老 host 收到的形状与 0.8.4 逐字一致。
      const extra = {};
      if (target != null && String(target) !== '') extra.target = String(target);
      if (workspaceId != null && String(workspaceId) !== '') extra.workspaceId = String(workspaceId);
      if (permission != null && String(permission) !== '') extra.permission = String(permission);
      const message = hub.post({ peerId: store.instanceId, name: nameOf(), kind, text, meta, ...extra });
      return withDispatchScope({ seq: message?.seq ?? null, ts: message?.ts ?? null }, message);
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
      async post({ kind, text, meta, target, workspaceId, permission }) {
        const extra = {};
        if (target != null && String(target) !== '') extra.target = String(target);
        if (workspaceId != null && String(workspaceId) !== '') extra.workspaceId = String(workspaceId);
        if (permission != null && String(permission) !== '') extra.permission = String(permission);
        const out = await postGroup({ ...link(), kind, text, meta, ...extra });
        return withDispatchScope({ seq: out?.seq ?? null, ts: out?.ts ?? null }, out);
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
    // S3：同一枚实例 token（panel.js / bootstrap / 这里校验的都指向它）。
    token: sessionToken,
    async handle(req, res, url) {
      if (!url.pathname.startsWith(PREFIX)) return false;
      // 先记地址再走门禁：面板第一次打开（哪怕 token 还没用上）也足以把地址落下来。
      rememberAdminUrl(req);
      // 语言可能被别处改过（手改 config.json、另一个进程）：每次管理请求先对一次，
      // 变了就重渲活绑定 —— 这就是「改完刷新页面即生效、不用重载插件」的那一步。
      refreshPanelScript();
      const route = url.pathname.slice(PREFIX.length);
      const method = String(req.method || 'GET').toUpperCase();

      // 0.8.5-α 真机修复：桌面（Electron/React 半）不加载 panel.js，也就永远拿不到
      // window.__lanPeersToken —— 面板自 0.8.3 起一直是空的。所以补一条**免 token** 的
      // bootstrap，把本进程这枚 token 交给同源页面。门禁是严格的：
      //   1) Host 必须是回环 authority（缺失也拒）—— LAN 上的机器根本连不到这条；
      //   2) 带 Sec-Fetch-Site 时只接受 same-origin / none，跨站页面一律 403 cross-origin
      //      （浏览器不允许页面伪造这个头）；
      //   3) 响应没有 CORS 头，跨站 JS 即使发出请求也读不到响应体。
      // token 的威胁模型是防跨站/CSRF，不是防本机进程（本机进程本来就能读 admin-token）。
      // 日志只记 ok/denied 与该头的值，绝不记 token。
      if (route === 'bootstrap') {
        if (method !== 'GET') {
          sendJson(res, 405, { error: 'method-not-allowed' });
          return true;
        }
        if (hostHeader(req) === '' || !hostIsLoopback(req)) {
          clientLog('[admin] bootstrap denied reason=non-loopback');
          sendJson(res, 403, { error: 'forbidden: loopback-only' });
          return true;
        }
        const site = headerOf(req, 'sec-fetch-site');
        if (site !== '' && site !== 'same-origin' && site !== 'none') {
          clientLog('[admin] bootstrap denied reason=cross-origin site=' + site.slice(0, 24));
          sendJson(res, 403, { error: 'cross-origin' });
          return true;
        }
        clientLog('[admin] bootstrap ok');
        sendJson(res, 200, { token: sessionToken, name: nameOf(), version: PLUGIN_VERSION });
        return true;
      }

      const write = !READ_METHODS.has(method);
      // panel.js / client-log 免 token，但 client-log 仍只收 JSON（它不是浏览器表单能
      // 造出来的形状）；其余路由下面三道门全过才进业务，只读接口也不例外。
      const open = TOKEN_FREE_ROUTES.has(route);
      if (!open) {
        if (hostHeader(req) === '') {
          // Host 缺失（老 Electron IPC 桥的形状）不再默认放行：必须带对 token。
          // 顺序也是语义 —— 先 Host/Origin（403 不泄露 token 对不对），再 token（401）。
          if (!tokenMatches(req, sessionToken)) {
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
        if (!tokenMatches(req, sessionToken)) {
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

        // ---- v0.8.5-α：界面语言开关（契约 §6）----
        // 门禁沿用上面四道（回环 Host + 会话 token；写操作另加 JSON + 同源），这里不再重复。
        if (route === 'lang' && method === 'GET') {
          const picked = readUiLang();
          sendJson(res, 200, { lang: picked === '' ? 'auto' : picked, effective: panelLang() });
          return true;
        }

        if (route === 'lang' && method === 'POST') {
          const body = await readJson(req);
          const wanted = normalizeUiLang(body && body.lang);
          if (wanted === '') {
            sendJson(res, 400, { error: 'bad-lang' });
            return true;
          }
          if (stateDirOf() === '') {
            sendJson(res, 501, { error: 'no-state-dir' });
            return true;
          }
          if (!writeUiLang(wanted)) {
            sendJson(res, 500, { error: 'lang-write-failed' });
            return true;
          }
          // 日志只记这一格的值本身：不记路径、不记 token、不记旧值。
          clientLog('[admin] lang=' + wanted);
          refreshPanelScript(true);
          sendJson(res, 200, { ok: true, lang: wanted, effective: panelLang() });
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

        // ---- v0.8.5-α 文件互传管理接口（契约 §3/§4，Lane F2） ----
        // 四条路由全部只经回环 + token（写操作另加 JSON + 同源，走上面那三道门）。
        // 文件本体永远不经过这里的响应：这里只调门面的 list/accept/reject/send。
        // 日志口径（契约 §0）：只记 size、sha256 前 8 位与状态 —— 文件名、落盘路径
        // 与文件内容一律不进日志。
        if (route === 'files' && method === 'GET') {
          const facade = filesFacade();
          if (!facade || typeof facade.list !== 'function') {
            clientLog('[admin] files list unsupported (no files facade)');
            sendJson(res, 501, { error: 'files-unsupported' });
            return true;
          }
          const listed = await facade.list();
          const rows = (Array.isArray(listed) ? listed : []).map(normalizeFileEntry).filter(Boolean);
          // 三个桶：待确认（pending）、已入 inbox（done）、传输中（incoming）。
          // incoming 自成第三桶，**不混进** pending/done —— 它没有「可接受/已收下」这两个状态，
          // 混进去会让 accept/reject 与「已收」计数都变成假的。已拒收（rejected）仍不露面。
          const pending = rows.filter((row) => row.state === 'pending');
          const inbox = rows.filter((row) => row.state === 'done');
          const incoming = rows.filter((row) => row.state === 'incoming');
          clientLog('[admin] files list pending=' + pending.length + ' inbox=' + inbox.length
            + ' incoming=' + incoming.length);
          sendJson(res, 200, { pending, inbox, incoming });
          return true;
        }

        if (route === 'files/progress' && method === 'GET') {
          // 契约 §4（只读）：CLI/面板轮询一条传输的进度，走同一道 token 门禁。
          // 这条路由每 500ms 会被打一次，所以**成功时不写日志**（写一次就淹掉整个日志）；
          // 只在「id 不认识」这种罕见分支留一行，便于事后解释「为什么没有进度」。
          const id = String(url.searchParams.get('id') ?? '').trim();
          if (id === '') {
            sendJson(res, 400, { error: 'id-required' });
            return true;
          }
          const facade = filesFacade();
          if (!facade || typeof facade.progress !== 'function') {
            sendJson(res, 501, { error: 'files-unsupported' });
            return true;
          }
          let out;
          try {
            out = await facade.progress(id);
          } catch (error) {
            const reason = String(error?.message ?? error);
            clientLog('[admin] files progress id=' + shortId(id) + ' state=error reason=' + reason.slice(0, 48));
            sendJson(res, errorStatus(error, 502), { error: reason });
            return true;
          }
          const state = String(out?.state ?? '');
          // 门面的「查不到」口径是 state:'unknown'（不抛错）：未知 id 一律 404。
          if (state === '' || state === 'unknown') {
            clientLog('[admin] files progress id=' + shortId(id) + ' state=unknown');
            sendJson(res, 404, { error: 'unknown-id' });
            return true;
          }
          const received = Number.isFinite(Number(out?.received)) ? Number(out.received) : 0;
          const size = Number.isFinite(Number(out?.size)) ? Number(out.size) : 0;
          sendJson(res, 200, { received, size, state });
          return true;
        }

        if (route === 'files/outbound' && method === 'GET') {
          // 出站进度（只读）：CLI 在 send 期间轮询「这一趟已经发出去多少字节」。
          // 同 files/progress：这条路由每 500ms 打一次，成功时不写日志。
          // 返回体**不含 path**：文件路径只在「本机选文件」那一刻用过，绝不回显。
          const facade = filesFacade();
          if (!facade || typeof facade.outbound !== 'function') {
            sendJson(res, 501, { error: 'files-unsupported' });
            return true;
          }
          let rows;
          try {
            rows = await facade.outbound();
          } catch (error) {
            const reason = String(error?.message ?? error);
            sendJson(res, errorStatus(error, 502), { error: reason });
            return true;
          }
          const out = (Array.isArray(rows) ? rows : []).map((row) => ({
            transferId: String(row?.transferId ?? ''),
            peerId: String(row?.peerId ?? ''),
            name: String(row?.name ?? ''),
            size: Number.isFinite(Number(row?.size)) ? Number(row.size) : 0,
            sent: Number.isFinite(Number(row?.sent)) ? Number(row.sent) : 0,
          })).filter((row) => row.transferId !== '');
          sendJson(res, 200, out);
          return true;
        }

        if ((route === 'files/accept' || route === 'files/reject') && method === 'POST') {
          const action = route === 'files/accept' ? 'accept' : 'reject';
          const body = await readJson(req);
          const id = String(body.id ?? '').trim();
          if (id === '') {
            sendJson(res, 400, { error: 'id-required' });
            return true;
          }
          const facade = filesFacade();
          if (!facade || typeof facade[action] !== 'function') {
            clientLog('[admin] files ' + action + ' unsupported id=' + shortId(id));
            sendJson(res, 501, { error: 'files-unsupported' });
            return true;
          }
          let out;
          try {
            out = await facade[action](id);
          } catch (error) {
            const reason = String(error?.message ?? error);
            clientLog('[admin] files ' + action + ' id=' + shortId(id) + ' state=error reason=' + reason.slice(0, 48));
            sendJson(res, errorStatus(error, 502), { error: reason });
            return true;
          }
          if (!out || out.ok !== true) {
            // 未知 id / 已过期（10 分钟未确认自动拒收，契约 §2）都落到这里。
            const reason = String(out?.reason ?? 'unknown-id');
            clientLog('[admin] files ' + action + ' id=' + shortId(id) + ' state=rejected reason=' + reason.slice(0, 32));
            sendJson(res, 404, { error: reason });
            return true;
          }
          clientLog('[admin] files ' + action + ' id=' + shortId(id) + ' state=ok');
          // 落盘路径含文件名：只回给发起这次操作的调用方，绝不写日志。
          sendJson(res, 200, action === 'accept'
            ? { ok: true, path: typeof out.path === 'string' ? out.path : '' }
            : { ok: true });
          return true;
        }

        if (route === 'files/send' && method === 'POST') {
          // 这里是**本机**选定的文件路径（用户在面板/CLI 里点的那个），
          // 与「绝不接受对端指定路径」（契约 §0）不是同一条线上的东西。
          const body = await readJson(req);
          const peerId = String(body.peerId ?? '').trim();
          const target = String(body.path ?? '').trim();
          if (peerId === '') {
            sendJson(res, 400, { error: 'peerId-required' });
            return true;
          }
          if (target === '') {
            sendJson(res, 400, { error: 'path-required' });
            return true;
          }
          const facade = filesFacade();
          if (!facade || typeof facade.send !== 'function') {
            clientLog('[admin] files send unsupported peer=' + shortId(peerId));
            sendJson(res, 501, { error: 'files-unsupported' });
            return true;
          }
          let out;
          try {
            out = await facade.send({ peerId, path: target });
          } catch (error) {
            const reason = String(error?.message ?? error);
            clientLog('[admin] files send peer=' + shortId(peerId) + ' state=error reason=' + reason.slice(0, 48));
            sendJson(res, errorStatus(error, 502), { error: reason });
            return true;
          }
          if (!out || out.ok !== true) {
            const reason = String(out?.reason ?? 'send-failed');
            clientLog('[admin] files send peer=' + shortId(peerId) + ' state=rejected reason=' + reason.slice(0, 32));
            sendJson(res, 409, { error: reason });
            return true;
          }
          const transferId = String(out.id ?? '');
          const bytes = Number(out.bytes) || 0;
          const sha256 = String(out.sha256 ?? '');
          const ms = Number.isFinite(Number(out.ms)) ? Number(out.ms) : 0;
          clientLog('[admin] files send peer=' + shortId(peerId) + ' id=' + shortId(transferId)
            + ' bytes=' + bytes + ' sha=' + sha256.slice(0, 8) + ' state=ok ms=' + ms);
          sendJson(res, 200, { ok: true, id: transferId, bytes, sha256, ms });
          return true;
        }

        // ---- v0.8.5-α 私聊管理接口（契约 §5，Lane G2） ----
        // 三条路由只经回环 + token（写操作另加 JSON + 同源，走上面那三道门）。
        // 铁律（契约 §0）：私聊与群完全隔离 —— 正文不进群历史、不进群日志。日志只记
        // peer 前 8 位、正文字节数与状态；reply 只回给发起这次调用的那一方。
        if (route === 'dm' && method === 'GET') {
          const peerId = String(url.searchParams.get('peer') ?? '').trim();
          if (peerId === '') {
            sendJson(res, 400, { error: 'peer-required' });
            return true;
          }
          const facade = dmFacade();
          if (!facade || typeof facade.list !== 'function') {
            clientLog('[admin] dm list unsupported (no dm facade)');
            sendJson(res, 501, { error: 'dm-unsupported' });
            return true;
          }
          let listed;
          try {
            listed = await facade.list(peerId);
          } catch (error) {
            const reason = String(error?.message ?? error);
            clientLog('[admin] dm list peer=' + shortId(peerId) + ' state=error reason=' + reason.slice(0, 48));
            sendJson(res, errorStatus(error, 502), { error: reason });
            return true;
          }
          const messages = (Array.isArray(listed) ? listed : []).map(normalizeDmMessage).filter(Boolean);
          // 名字取自 peers.json（对端自报）；查不到就空串，面板退回显示 id 前缀。
          const known = typeof store?.getPeer === 'function' ? store.getPeer(peerId) : null;
          clientLog('[admin] dm list peer=' + shortId(peerId) + ' count=' + messages.length);
          sendJson(res, 200, { peer: { peerId, name: String(known?.name ?? '') }, messages });
          return true;
        }

        if (route === 'dm/send' && method === 'POST') {
          const body = await readJson(req);
          const peerId = String(body.peerId ?? '').trim();
          const text = String(body.text ?? '');
          if (peerId === '') {
            sendJson(res, 400, { error: 'peerId-required' });
            return true;
          }
          // 空正文不发：对端那边会得到一条无意义的会话轮次，也很容易是误触。
          if (text.trim() === '') {
            sendJson(res, 400, { error: 'text-required' });
            return true;
          }
          const facade = dmFacade();
          if (!facade || typeof facade.send !== 'function') {
            clientLog('[admin] dm send unsupported peer=' + shortId(peerId));
            sendJson(res, 501, { error: 'dm-unsupported' });
            return true;
          }
          const bytes = Buffer.byteLength(text, 'utf8');
          // 契约 §2：两个可选字段都不传时，请求体与现在完全一致（旧对端不受影响）。
          const workspaceId = String(body.workspaceId ?? '').trim();
          const permission = String(body.permission ?? '').trim();
          const scoped = workspaceId !== '' || permission !== '';
          let out;
          try {
            out = await facade.send({
              peerId,
              text,
              ...(workspaceId === '' ? {} : { workspaceId }),
              ...(permission === '' ? {} : { permission }),
            });
          } catch (error) {
            const reason = String(error?.message ?? error);
            clientLog('[admin] dm send peer=' + shortId(peerId) + ' bytes=' + bytes
              + ' state=error reason=' + reason.slice(0, 48));
            sendJson(res, errorStatus(error, 502), { error: reason });
            return true;
          }
          if (!out || out.ok !== true) {
            // 目标离线 / 未配对 / 对端拒绝：reason 是给调用方的，不是给日志的正文。
            const reason = String(out?.reason ?? 'dm-send-failed');
            clientLog('[admin] dm send peer=' + shortId(peerId) + ' bytes=' + bytes
              + ' state=rejected reason=' + reason.slice(0, 32));
            sendJson(res, 409, { error: reason });
            return true;
          }
          // 契约 §2/§4：超对方默认档时不执行 —— 回 202 + approvalId，正文留在对端内存里，
          // 本机这条私聊继续是 pending（面板据此显示「等待对方确认…」并开始轮询）。
          if (out.pendingApproval === true) {
            const approvalId = String(out.approvalId ?? '');
            const expiresAt = Number.isFinite(Number(out.expiresAt)) ? Number(out.expiresAt) : 0;
            clientLog('[admin] dm send peer=' + shortId(peerId) + ' bytes=' + bytes
              + ' ws=' + (workspaceId === '' ? 'default' : workspaceId)
              + ' perm=' + (permission === '' ? 'default' : permission)
              + ' id=' + shortId(approvalId) + ' state=pending-approval');
            sendJson(res, 202, { ok: true, pendingApproval: true, approvalId, expiresAt });
            return true;
          }
          const id = String(out.id ?? '');
          const sessionId = String(out.sessionId ?? '');
          const reply = String(out.reply ?? '');
          const elapsedMs = Number.isFinite(Number(out.elapsedMs)) ? Number(out.elapsedMs) : 0;
          const reused = out.reused === true;
          // 点名的派单把对端回告的「实际生效」那组带回去（只有 id 与名字，没有 path）。
          const workspace = scoped && out.workspace && typeof out.workspace === 'object'
            ? { id: String(out.workspace.id ?? ''), name: String(out.workspace.name ?? '') }
            : null;
          const appliedPerm = scoped && typeof out.permission === 'string' ? out.permission : '';
          clientLog('[admin] dm send peer=' + shortId(peerId) + ' id=' + shortId(id)
            + ' bytes=' + bytes + ' replyBytes=' + Buffer.byteLength(reply, 'utf8')
            + ' reused=' + reused + ' state=ok ms=' + elapsedMs
            + (scoped ? ' ws=' + (workspaceId === '' ? 'default' : workspaceId)
              + ' perm=' + (appliedPerm === '' ? (permission === '' ? 'default' : permission) : appliedPerm) : ''));
          sendJson(res, 200, {
            ok: true, id, sessionId, reply, elapsedMs, reused,
            ...(workspace ? { workspace } : {}),
            ...(scoped ? { permission: appliedPerm === '' ? (permission === '' ? 'default' : permission) : appliedPerm } : {}),
          });
          return true;
        }

        if (route === 'dm/sync' && method === 'POST') {
          const body = await readJson(req);
          const peerId = String(body.peerId ?? '').trim();
          if (peerId === '') {
            sendJson(res, 400, { error: 'peerId-required' });
            return true;
          }
          const facade = dmFacade();
          if (!facade || typeof facade.sync !== 'function') {
            clientLog('[admin] dm sync unsupported peer=' + shortId(peerId));
            sendJson(res, 501, { error: 'dm-unsupported' });
            return true;
          }
          let out;
          try {
            out = await facade.sync(peerId);
          } catch (error) {
            const reason = String(error?.message ?? error);
            clientLog('[admin] dm sync peer=' + shortId(peerId) + ' state=error reason=' + reason.slice(0, 48));
            sendJson(res, errorStatus(error, 502), { error: reason });
            return true;
          }
          if (!out || out.ok !== true) {
            const reason = String(out?.reason ?? 'dm-sync-failed');
            clientLog('[admin] dm sync peer=' + shortId(peerId) + ' state=rejected reason=' + reason.slice(0, 32));
            sendJson(res, 409, { error: reason });
            return true;
          }
          const added = Number.isFinite(Number(out.added)) ? Number(out.added) : 0;
          const total = Number.isFinite(Number(out.total)) ? Number(out.total) : 0;
          clientLog('[admin] dm sync peer=' + shortId(peerId) + ' added=' + added + ' total=' + total);
          sendJson(res, 200, { ok: true, added, total });
          return true;
        }

        // ---- v0.8.5-α 派单设置管理接口（契约 §5/§6，Lane H2）----
        // 门禁沿用既有三道（回环 Host + 会话 token；写操作另加 JSON + 同源），这里不再重复。
        // 铁律（契约 §0）：path 只出现在 settings 这一份**本机**响应里（那是本机自己的配置）；
        // 跨机的 options 只有 id 与 name。日志只记 id 前 8 位、权限档、工作区 id、字节数。
        if (route === 'dispatch/settings' && method === 'GET') {
          const prefs = dispatchFn('prefs');
          if (!prefs) {
            clientLog('[admin] dispatch settings unsupported');
            sendJson(res, 501, { error: 'dispatch-unsupported' });
            return true;
          }
          let raw;
          try {
            raw = await prefs();
          } catch (error) {
            const reason = String(error?.message ?? error);
            clientLog('[admin] dispatch settings read state=error reason=' + reason.slice(0, 48));
            sendJson(res, errorStatus(error, 502), { error: reason });
            return true;
          }
          const view = dispatchPrefsView(raw);
          clientLog('[admin] dispatch settings read default=' + view.defaultWorkspaceId
            + ' max=' + view.maxPermission + ' ws=' + view.workspaces.length);
          sendJson(res, 200, view);
          return true;
        }

        // 契约 §5：GET dispatch/options?peer= 代理对端 options（无 path）。
        // 不带 peer 时回本机对外视图（同样无 path）—— 面板「我这台能给别人什么」的预览。
        if (route === 'dispatch/options' && method === 'GET') {
          const peerId = String(url.searchParams.get('peer') ?? '').trim();
          if (peerId === '') {
            const options = dispatchFn('options');
            if (!options) {
              clientLog('[admin] dispatch options unsupported');
              sendJson(res, 501, { error: 'dispatch-unsupported' });
              return true;
            }
            let raw;
            try {
              raw = await options();
            } catch (error) {
              const reason = String(error?.message ?? error);
              clientLog('[admin] dispatch options read state=error reason=' + reason.slice(0, 48));
              sendJson(res, errorStatus(error, 502), { error: reason });
              return true;
            }
            sendJson(res, 200, dispatchOptionsView(raw));
            return true;
          }
          const peer = typeof store?.getPeer === 'function' ? store.getPeer(peerId) : null;
          if (!peer) {
            clientLog('[admin] dispatch options peer=' + shortId(peerId) + ' state=unknown-peer');
            sendJson(res, 404, { error: 'unknown-peer' });
            return true;
          }
          let raw;
          try {
            raw = await fetchPeerOptions(peer);
          } catch (error) {
            // 对端没升级（404）与不可达都归「现在做不了」，不把对端地址写进 reason。
            const reason = String(error?.message ?? error);
            clientLog('[admin] dispatch options peer=' + shortId(peerId) + ' state=error reason=' + reason.slice(0, 32));
            sendJson(res, errorStatus(error, 502), { error: reason.startsWith('404') ? 'options-unsupported' : reason });
            return true;
          }
          const view = dispatchOptionsView(raw);
          clientLog('[admin] dispatch options peer=' + shortId(peerId)
            + ' ws=' + view.workspaces.length + ' max=' + view.maxPermission + ' state=ok');
          sendJson(res, 200, view);
          return true;
        }

        // 契约 §5：POST dispatch/{approve,reject} { id } —— 只是转发门面结论，不自己拍板。
        if ((route === 'dispatch/approve' || route === 'dispatch/reject') && method === 'POST') {
          const action = route === 'dispatch/approve' ? 'approve' : 'reject';
          const body = await readJson(req);
          const approvalId = String(body.id ?? '').trim();
          if (approvalId === '') {
            sendJson(res, 400, { error: 'id-required' });
            return true;
          }
          const decide = dispatchFn(action);
          if (!decide) {
            clientLog('[admin] dispatch ' + action + ' unsupported');
            sendJson(res, 501, { error: 'dispatch-unsupported' });
            return true;
          }
          let out;
          try {
            out = await decide(approvalId);
          } catch (error) {
            const reason = String(error?.message ?? error);
            clientLog('[admin] dispatch ' + action + ' id=' + shortId(approvalId)
              + ' state=error reason=' + reason.slice(0, 32));
            sendJson(res, errorStatus(error, 502), { error: reason });
            return true;
          }
          if (!out || out.ok !== true) {
            const reason = String(out?.reason ?? out?.state ?? 'unknown-approval');
            clientLog('[admin] dispatch ' + action + ' id=' + shortId(approvalId)
              + ' state=rejected reason=' + reason.slice(0, 32));
            sendJson(res, 404, { error: reason });
            return true;
          }
          const state = String(out.state ?? (action === 'approve' ? 'approved' : 'rejected'));
          clientLog('[admin] dispatch ' + action + ' id=' + shortId(approvalId) + ' state=' + state);
          sendJson(res, 200, { ok: true, state });
          return true;
        }

        // 契约 §6 需要「发送方轮询审批状态」，§5 的清单里没有对应条目（§2 只把这条端点
        // 定义在对端）：这里补一条只读代理，回的就是 §2 的四态，只多一个 sessionId。
        if (route === 'dispatch/approval' && method === 'GET') {
          const approvalId = String(url.searchParams.get('id') ?? '').trim();
          const peerId = String(url.searchParams.get('peer') ?? '').trim();
          if (approvalId === '') {
            sendJson(res, 400, { error: 'id-required' });
            return true;
          }
          if (peerId === '') {
            sendJson(res, 400, { error: 'peer-required' });
            return true;
          }
          const peer = typeof store?.getPeer === 'function' ? store.getPeer(peerId) : null;
          if (!peer) {
            clientLog('[admin] dispatch approval peer=' + shortId(peerId) + ' state=unknown-peer');
            sendJson(res, 404, { error: 'unknown-peer' });
            return true;
          }
          let raw;
          try {
            raw = await fetchPeerApproval(peer, approvalId);
          } catch (error) {
            const reason = String(error?.message ?? error);
            clientLog('[admin] dispatch approval peer=' + shortId(peerId) + ' id=' + shortId(approvalId)
              + ' state=error reason=' + reason.slice(0, 32));
            sendJson(res, errorStatus(error, 502), { error: reason.startsWith('404') ? 'unknown-approval' : reason });
            return true;
          }
          const view = dispatchApprovalView(raw);
          sendJson(res, 200, view);
          return true;
        }

        if (route === 'dispatch/pending' && method === 'GET') {
          const pending = dispatchFn('pending');
          if (!pending) {
            clientLog('[admin] dispatch pending unsupported');
            sendJson(res, 501, { error: 'dispatch-unsupported' });
            return true;
          }
          let raw;
          try {
            raw = await pending();
          } catch (error) {
            const reason = String(error?.message ?? error);
            clientLog('[admin] dispatch pending state=error reason=' + reason.slice(0, 48));
            sendJson(res, errorStatus(error, 502), { error: reason });
            return true;
          }
          const items = (Array.isArray(raw) ? raw : []).map(dispatchPendingView).filter(Boolean);
          // 来源名字取自 peers.json（对端自报，只用于显示）；查不到就留空，面板退回 id 前 8 位。
          for (const item of items) {
            const known = typeof store?.getPeer === 'function' ? store.getPeer(item.from) : null;
            item.fromName = String(known?.name ?? '');
          }
          clientLog('[admin] dispatch pending count=' + items.length);
          sendJson(res, 200, { items });
          return true;
        }

        if (route === 'dispatch/settings' && method === 'POST') {
          const save = dispatchFn('savePrefs');
          if (!save) {
            clientLog('[admin] dispatch settings save unsupported');
            sendJson(res, 501, { error: 'dispatch-unsupported' });
            return true;
          }
          const body = await readJson(req);
          const has = (key) => Object.prototype.hasOwnProperty.call(body, key);
          const patch = {};
          if (has('defaultWorkspaceId')) patch.defaultWorkspaceId = String(body.defaultWorkspaceId ?? '');
          if (has('maxPermission')) {
            const wanted = String(body.maxPermission ?? '');
            if (!DISPATCH_PERMISSIONS.includes(wanted)) {
              clientLog('[admin] dispatch settings save state=rejected reason=bad-permission');
              sendJson(res, 400, { error: 'bad-permission' });
              return true;
            }
            patch.maxPermission = wanted;
          }
          if (has('workspaces')) {
            if (!Array.isArray(body.workspaces)) {
              clientLog('[admin] dispatch settings save state=rejected reason=bad-workspaces');
              sendJson(res, 400, { error: 'bad-workspaces' });
              return true;
            }
            patch.workspaces = body.workspaces
              .filter((item) => item && typeof item === 'object' && !Array.isArray(item))
              .map((item) => ({
                id: String(item.id ?? ''),
                name: String(item.name ?? ''),
                path: String(item.path ?? ''),
              }));
          }
          let saved;
          try {
            saved = await save(patch);
          } catch (error) {
            const reason = String(error?.message ?? error);
            clientLog('[admin] dispatch settings save state=error reason=' + reason.slice(0, 48));
            sendJson(res, errorStatus(error, 502), { error: reason });
            return true;
          }
          // 契约 §1：校验失败不写盘，回稳定 reason + 当前仍然有效的值（面板据此原地纠正）。
          if (saved && saved.ok === false) {
            const reason = String(saved.reason ?? 'bad-prefs');
            clientLog('[admin] dispatch settings save state=rejected reason=' + reason.slice(0, 32));
            sendJson(res, 400, { error: reason, ...dispatchPrefsView(saved) });
            return true;
          }
          const view = dispatchPrefsView(saved);
          clientLog('[admin] dispatch settings save default=' + view.defaultWorkspaceId
            + ' max=' + view.maxPermission + ' ws=' + view.workspaces.length + ' state=ok');
          sendJson(res, 200, view);
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

        // ---- v0.8.5-α（契约 §3/§4）：群派单的目标 options 代理 ----
        // 群派单的可选工作区来自**目标成员**，本机只能代理一次（复用既有 per-peer 签名通道）。
        // 回给面板的永远只有 id 与 name：dispatchOptionsView 再洗一遍，path 在这里第二次丢掉。
        if (route === 'group/dispatch-options' && method === 'GET') {
          const peerId = String(url.searchParams.get('peer') ?? '').trim();
          if (peerId === '') {
            clientLog('[admin] group dispatch-options rejected (peer required)');
            sendJson(res, 400, { error: 'bad-peer' });
            return true;
          }
          const facade = groupFacade();
          const readOptions = facade && typeof facade.dispatchOptions === 'function'
            ? facade.dispatchOptions.bind(facade) : null;
          if (!readOptions) {
            clientLog('[admin] group dispatch-options refused (facade not wired)');
            sendJson(res, 501, { error: 'dispatch-options-unsupported' });
            return true;
          }
          try {
            const raw = await readOptions(peerId);
            // 门面有两种如实降级的方式：抛错，或回 { ok:false, error }（host 侧门面就是后者）。
            // 两种都当成「取不到」—— 面板据此置灰，绝不把一次失败画成「对方没有工作区」。
            if (raw && typeof raw === 'object' && raw.ok === false) {
              clientLog('[admin] group dispatch-options peer=' + shortId(peerId)
                + ' state=unavailable reason=' + String(raw.error ?? '-').slice(0, 40));
              sendJson(res, 502, { error: 'options-unavailable' });
              return true;
            }
            const view = dispatchOptionsView(raw);
            clientLog('[admin] group dispatch-options peer=' + shortId(peerId)
              + ' ws=' + view.workspaces.length + ' max=' + view.maxPermission);
            sendJson(res, 200, view);
          } catch (error) {
            // 群是多人可见的：目标侧的原始 message 可能带地址/目录，所以只回一个稳定 reason。
            clientLog('[admin] group dispatch-options failed peer=' + shortId(peerId)
              + ' err=' + String(error?.message ?? error).replace(/\s+/g, ' ').slice(0, 60));
            sendJson(res, errorStatus(error, 502), { error: 'options-unavailable' });
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
          // 契约 §1/§3：dispatch 帖的三个可选字段（target / workspaceId / permission）。
          // 一个都不带时下面的请求体与 0.8.4 逐字一致 —— 不是「带了空串」，是一个键都没有。
          const target = String(body.target ?? '').trim();
          const workspaceId = String(body.workspaceId ?? '').trim();
          const permission = String(body.permission ?? '').trim();
          if (permission !== '' && !DISPATCH_PERMISSIONS.includes(permission)) {
            clientLog('[admin] group post rejected kind=' + kind + ' (permission not allowed)');
            sendJson(res, 400, { error: 'bad-permission' });
            return true;
          }
          const scope = {};
          if (target !== '') scope.target = target;
          if (workspaceId !== '') scope.workspaceId = workspaceId;
          if (permission !== '') scope.permission = permission;
          const scoped = Object.keys(scope).length > 0;
          const resolved = await resolveGroup();
          if (resolved.status !== 'ok') {
            const reason = resolved.status === 'error' ? resolved.reason : 'group-disabled';
            clientLog('[admin] group post refused kind=' + kind + ' textLen=' + text.length + ' err=' + reason);
            sendJson(res, resolved.status === 'error' ? 502 : 409, { error: reason });
            return true;
          }
          try {
            const out = (await resolved.api.post({ kind, text, meta, ...scope })) ?? {};
            // 只记长度/字段数/序号：群消息正文（可能含回复全文）绝不进日志。工作区只记 id，
            // 名字与路径都不进日志（路径本来就不该到 hub 这一层）。
            clientLog('[admin] group post kind=' + kind + ' textLen=' + text.length
              + ' meta=' + Object.keys(meta).length + ' seq=' + (out.seq ?? '?')
              + (scoped ? ' scoped=1 target=' + shortId(target === '' ? '-' : target)
                + ' ws=' + (workspaceId === '' ? 'default' : workspaceId)
                + ' perm=' + (permission === '' ? 'default' : permission) : ''));
            // 契约 §1/§3/§5：派单目标 = 显式 target（弹层显式化）**或** 正文里的 @!X（纯文本语法）。
            // 两者都在时以显式 target 为准，任务正文仍取去掉 @!X 之后那段（绝不把语法当任务发出去）。
            // 消息已经发出，所以派单失败既不回滚也不改 HTTP 状态 —— 结果只作为 dispatch 摘要回给调用方；
            // 群历史里的 progress/result 由 host 按契约 §3 写（正文永不入群）。
            // 契约 §4：带新字段时门面（server.group.post）自己发帖**并**派单，回执就是它的返回值；
            // 这时绝不再派一次 —— 重复派单会让目标侧把同一个任务跑两遍。
            // 门面还没接线（返回值里没有派单状态）时，退回本机派生这条老路。
            const embedded = scoped
              && typeof out.status === 'string' && DISPATCH_STATUSES.includes(String(out.status))
              ? out : null;
            const parsed = kind === 'chat' ? parseGroupDispatchCommand(text) : null;
            let command = null;
            if (target !== '') {
              command = {
                target,
                task: parsed ? parsed.task : text.trim(),
                extraTargets: parsed ? parsed.extraTargets : 0,
              };
            } else if (parsed) {
              command = parsed;
            }
            if (command && workspaceId !== '') command.workspaceId = workspaceId;
            if (command && permission !== '') command.permission = permission;
            const dispatch = embedded
              ? normalizeDispatchOutcome(embedded, target)
              : (command ? await settledDispatch(command) : null);
            sendJson(res, 200, {
              ok: true,
              seq: out.seq ?? null,
              ts: out.ts ?? null,
              ...(dispatch ? { dispatch } : {}),
              // 契约 §4：目标回告的作用域（可选；没有就一个键都不加，响应与 0.8.4 逐字一致）。
              ...withDispatchScope({}, out),
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

// 契约 §6：设置页与私聊派单弹层的文案清单。面板是直出脚本（不能 import lib/i18n.mjs），
// 所以下面在模块加载时用 t(lang, key) 为两种语言各取一份字面量、嵌进脚本里的 PANEL_I18N。
// 词表仍只有 lib/i18n.mjs 一份：漏补某一格会在这里就露出来（zh 兜底），而不是到真机上。
// 面板段整份接线（0.8.5-α i18n 第二批）：注入的 key 清单直接从词表里取所有 panel.* 项，
// 不再手抄一份清单 —— 手抄的那份会随着面板接线漂移，而面板里任何一笔漏 key 都会在
// 运行时静默回落成 key 名本身。漏 key 由测试（lib/panel-i18n.test.mjs）在源码层兜住。
const PANEL_TEXT_KEYS = Object.freeze(keys(DEFAULT_LANG).filter((key) => key.startsWith('panel.')));

const PANEL_I18N_JSON = (() => {
  const table = {};
  for (const lang of LANGS) {
    const cell = {};
    for (const key of PANEL_TEXT_KEYS) cell[key] = t(lang, key);
    table[lang] = cell;
  }
  return JSON.stringify(table);
})();

/**
 * The browser half: a floating panel injected into the DSH index page.
 *
 * 按实例渲染：token 是实例级（以 <stateDir>/admin-token 为准），所以这里做成渲染函数，
 * 而 PANEL_SCRIPT 是**活绑定** —— createAdmin 解析出实例 token 之后重渲染一次。
 * lib/index.js 在 exact 路由的响应里读的正是这个绑定，于是直出的 panel.js 与管理接口
 * 永远用同一枚 token；进程内只有一块面板，重复加载也只会渲染出同一个 stateDir 的那一枚。
 * 模块加载时那份用进程级兜底 token：createAdmin 之前不可能有请求，它只是让这个绑定在
 * 任何时刻都是一个能独立解析的脚本。
 */
export const renderPanelScript = (token, lang = DEFAULT_LANG) => `
(() => {
  if (window.__dshLanPeersPanel) return;
  window.__dshLanPeersPanel = true;
  // S3：管理接口的会话 token。它只活在「本机回环 host 直出的这份脚本」和
  // <stateDir>/admin-token 里 —— 绝不进 URL、日志、错误消息。React 半
  // （lib/client.js）从这里设的全局读同一个值，读不到就降级成不发请求。
  const T = '${token}';
  window.__lanPeersToken = T;
  // 文案：本脚本不能 import lib/i18n.mjs，所以这份表是 admin.mjs 加载时用 t(lang, key)
  // 为两种语言各取好的字面量（整份都注入，浏览器侧不再二次猜语言）。
  // 用哪一格由**渲染时传进来的 lang** 决定 —— 它来自 resolveLang(config)，不是写死的。
  const I18N = ${PANEL_I18N_JSON};
  const I18N_LANG = '${resolveLang(lang)}';
  // 缺 key 的回落链：本语言格 → 英文档 → key 本身。绝不返回 undefined。
  const LT = (key, params) => {
    const table = I18N[I18N_LANG] || I18N.en;
    let text = table ? table[key] : undefined;
    if (text === undefined && I18N.en) text = I18N.en[key];
    if (text === undefined) return String(key);
    let out = String(text);
    if (params && typeof params === 'object') {
      for (const name of Object.keys(params)) {
        const value = params[name] == null ? '' : String(params[name]);
        out = out.split('{' + name + '}').join(value);
      }
    }
    return out;
  };
  // 0.8.5-α 真机 bug：插件每次重启都重新生成 token，而这份页面可能是上一个进程里加载的 ——
  // 手里那枚旧 token 会让之后每个管理请求都 401，且**永不恢复**（只能手动刷新）。
  // 所以发请求读 tok 这个可更新的副本，只在 401 时去 bootstrap 换一枚新的再重放一次。
  // 0.8.5-α 规格调整：闸门从「每会话一次」改成「每次连续 401 失败最多自愈一次（成功后重置）
  // + 每会话上限 3 次」。开发期频繁热重启，只救第一次等于没救；有上限所以不会打成死循环 ——
  // 连续失败期间 burst 不复位，只有一次成功之后才有下一次机会。
  let tok = T;
  let burstHealed = false;
  let healCount = 0;
  const HEAL_MAX_PER_SESSION = 3;
  // 埋点走既有 client-log（免 token、只收 JSON）；**绝不含 token 本身**。
  const note = (event) => {
    try {
      fetch('/api/lan-peers/client-log', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ event: event, detail: null }),
      }).catch(() => {});
    } catch (e) {}
  };
  const refreshToken = () => fetch('/api/lan-peers/bootstrap', { method: 'GET' })
    .then((res) => (res.ok ? res.json() : null))
    .then((body) => {
      const fresh = body && typeof body.token === 'string' ? body.token : '';
      if (fresh === '') throw new Error('bootstrap returned no token');
      tok = fresh;
      window.__lanPeersToken = fresh;
      return fresh;
    });
  // 失败时把 body/status 挂到 Error 上（v0.8.0 改名查重要读 409 的 conflicts 清单），
  // Error.message 仍是原来的 error 字符串 —— 既有调用点看到的行为不变。
  const send = (path, init, token) => {
    const options = Object.assign({}, init);
    const headers = Object.assign({}, options.headers);
    headers['X-Lan-Peers-Token'] = token;
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
      // 一次成功就把 burst 闸门复位：之后的 401 属于新的一段故障，值得再救一次
      // （每会话 3 次的硬上限不变，所以复位不会变成死循环）。
      burstHealed = false;
      return body;
    });
  };
  const api = (path, init) => send(path, init, tok).catch((error) => {
    // 只有 401 可能是 token 轮换。403/415/409 是有意义的业务答复，重试没有意义。
    if (!error || error.status !== 401) throw error;
    // 连续失败段里最多救一次；每会话累计 3 次封顶。
    if (burstHealed || healCount >= HEAL_MAX_PER_SESSION) throw error;
    burstHealed = true;
    healCount += 1;
    return refreshToken().then(
      (fresh) => send(path, init, fresh).then((body) => { note('token-refreshed'); return body; }),
      // 拿不到新 token：仍然把最初那次 401 交给既有 msg 区（不额外造文案）。
      () => { throw error; },
    );
  });

  const style = document.createElement('style');
  style.textContent = \`
    #dshLpBtn{position:fixed;z-index:2147483000;border:1px solid #3f6ae0;background:#1b2333;color:#dfe7ff;border-radius:999px;padding:8px 14px;font:13px/1.2 system-ui;cursor:grab;box-shadow:0 6px 20px rgba(0,0,0,.35);touch-action:none;user-select:none;white-space:nowrap}
    #dshLpPanel{position:fixed;width:320px;z-index:2147483000;background:#161b22;color:#e6edf3;border:1px solid #30363d;border-radius:12px;padding:14px;font:13px/1.5 system-ui;box-shadow:0 12px 40px rgba(0,0,0,.5);display:none;max-height:70vh;overflow:auto;box-sizing:border-box}
    #dshLpPanel h4{margin:0 0 8px;font-size:13px;color:#9ecbff}
    #dshLpPanel label{display:block;margin:8px 0 4px;color:#8b949e;font-size:12px}
    #dshLpPanel input{width:100%;box-sizing:border-box;background:#0d1117;border:1px solid #30363d;color:#e6edf3;border-radius:6px;padding:6px 8px;font:12px system-ui}
    #dshLpPanel select{width:100%;box-sizing:border-box;background:#0d1117;border:1px solid #30363d;color:#e6edf3;border-radius:6px;padding:6px 8px;font:12px system-ui}
    #dshLpPanel select option:disabled{color:#484f58}
    #dshLpPanel .wsrow,#dshLpPanel .pending{display:flex;gap:6px;align-items:center;border-top:1px solid #21262d;padding:5px 0;font-size:12px;color:#c9d1d9;flex-wrap:wrap}
    #dshLpPanel .wsrow .wsid{font:11px ui-monospace,monospace;color:#7ee787;min-width:44px}
    #dshLpPanel .wsrow input{flex:1;min-width:80px}
    #dshLpPanel .pending .pleft{color:#f0883e;white-space:nowrap}
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
    #dshLpPanel .member .dot,#dshLpPanel .dmrow .dot{color:#484f58;font-size:10px}
    #dshLpPanel .member .dot.on,#dshLpPanel .dmrow .dot.on{color:#3fb950}
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
    #dshLpPanel #dshLpGroupMsgs{max-height:200px;overflow:auto;border-top:1px solid #21262d;padding-top:4px}
    #dshLpPanel #dshLpArchiveHead{margin-top:2px;color:#8b949e}
    #dshLpPanel #dshLpGroupArchives{max-height:140px;overflow:auto;border-top:1px solid #21262d;padding-top:4px}
    #dshLpPanel .gsys{display:flex;justify-content:center;margin:4px 0;font-size:10px;color:#8b949e;text-align:center;word-break:break-word}
    #dshLpPanel .gsys.pending{color:#d29922}
    #dshLpPanel #dshLpDmList{display:flex;flex-direction:column;max-height:120px;overflow:auto;border-top:1px solid #21262d}
    #dshLpPanel .dmrow{display:flex;gap:6px;align-items:center;padding:4px 2px;font-size:12px;color:#c9d1d9;cursor:pointer;border-bottom:1px solid #161b22}
    #dshLpPanel .dmrow.on{background:#1b2333;border-radius:6px}
    #dshLpPanel .dmrow .dmname{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    #dshLpPanel .dmrow .dmtime{color:#8b949e;font-size:11px;white-space:nowrap}
    #dshLpPanel #dshLpDmMsgs{max-height:200px;overflow:auto;border-top:1px solid #21262d;padding-top:4px}
    #dshLpPanel .dmmsg{display:flex;margin:3px 0}
    #dshLpPanel .dmmsg.self{justify-content:flex-end}
    #dshLpPanel .dmmsg .bubble{max-width:78%;border-radius:10px;padding:4px 8px;font-size:12px;word-break:break-word;white-space:pre-wrap}
    #dshLpPanel .dmmsg.self .bubble{background:#1f6feb;color:#fff}
    #dshLpPanel .dmmsg.peer .bubble{background:#21262d;color:#e6edf3}
    #dshLpPanel .dmmsg .bubble .st{display:block;font-size:10px;color:#9ecbff;margin-top:2px}
  \`;
  document.head.appendChild(style);

  const btn = document.createElement('button');
  btn.id = 'dshLpBtn';
  btn.textContent = LT('panel.launcher');
  const panel = document.createElement('div');
  panel.id = 'dshLpPanel';
  // 静态骨架：只有本文件写死的标签与 id，任何来自对端的内容都走 textContent。
  panel.innerHTML = \`
    <div class="tabs">
      <button class="ghost tab on" id="dshLpTabPeers"></button>
      <button class="ghost tab" id="dshLpTabGroup"></button>
      <button class="ghost tab" id="dshLpTabDm"></button>
      <button class="ghost tab" id="dshLpTabSettings"></button>
    </div>
    <div id="dshLpPagePeers">
      <label id="dshLpNameLabel"></label>
      <input id="dshLpName" maxlength="64" />
      <button class="ghost" id="dshLpSaveName"></button>
      <label id="dshLpCodeLabel"></label>
      <button class="ghost" id="dshLpCode"></button>
      <div class="code" id="dshLpCodeText">------</div>
      <div class="hint" id="dshLpCodeHint"></div>
      <label id="dshLpAddLabel"></label>
      <input id="dshLpUrl" placeholder="192.168.1.10:7788" />
      <input id="dshLpPeerName" style="margin-top:6px" />
      <input id="dshLpPairCode" style="margin-top:6px" />
      <button id="dshLpPair"></button>
      <div id="dshLpPeers"></div>
      <label id="dshLpJobsLabel"></label>
      <div id="dshLpJobs"></div>
      <div class="hint" id="dshLpIncoming"></div>
    </div>
    <div id="dshLpPageGroup" style="display:none">
      <div class="hint" id="dshLpGroupHead"></div>
      <div class="hint" id="dshLpGroupStatus"></div>
      <div class="hint" id="dshLpGroupDegraded" style="display:none"></div>
      <div class="hint" id="dshLpGroupLeader"></div>
      <div class="hint" id="dshLpGroupRole"></div>
      <div class="hint" id="dshLpGroupReplica"></div>
      <div class="hint" id="dshLpGroupAddrWarn" style="display:none"></div>
      <div id="dshLpGroupMembers"></div>
      <label id="dshLpGroupMsgsLabel"></label>
      <div id="dshLpGroupMsgs"></div>
      <div class="hint" id="dshLpGroupSyntax"></div>
      <input id="dshLpGroupText" maxlength="4000" style="margin-top:6px" />
      <button id="dshLpGroupSend"></button>
      <button class="ghost" id="dshLpGroupDispatchBtn"></button>
      <div id="dshLpGroupDispatchBox" style="display:none">
        <div class="hint" id="dshLpGroupDispatchTitle"></div>
        <label id="dshLpGroupTargetLabel"></label>
        <select id="dshLpGroupTarget"></select>
        <label id="dshLpGroupWsLabel"></label>
        <select id="dshLpGroupWs"></select>
        <label id="dshLpGroupPermLabel"></label>
        <select id="dshLpGroupPerm"></select>
        <div class="hint" id="dshLpGroupDispatchHint"></div>
        <button class="ghost" id="dshLpGroupDispatchClose"></button>
      </div>
      <div class="hint" id="dshLpGroupDispatchState"></div>
      <button class="ghost" id="dshLpAccept"></button>
      <div class="hint" id="dshLpAcceptHint"></div>
      <div id="dshLpGroupHub" style="display:none">
        <label id="dshLpGroupNameLabel"></label>
        <input id="dshLpGroupName" maxlength="64" />
        <button class="ghost" id="dshLpGroupSaveName"></button>
        <div class="hint" id="dshLpGroupNameConflicts"></div>
        <button class="ghost" id="dshLpGroupAdvertise"></button>
        <div class="hint" id="dshLpAdvertiseHint"></div>
        <label id="dshLpPendingLabel"></label>
        <div id="dshLpGroupPending"></div>
        <label id="dshLpArchivesLabel"></label>
        <div class="hint" id="dshLpArchiveHead"></div>
        <div id="dshLpGroupArchives"></div>
        <label id="dshLpGroupAddLabel"></label>
        <input id="dshLpGroupAddId" placeholder="peerId" />
        <button class="ghost" id="dshLpGroupAdd"></button>
        <div class="hint" id="dshLpRemoveHint"></div>
        <button class="ghost" id="dshLpGroupClaim"></button>
        <div class="hint" id="dshLpClaimHint"></div>
      </div>
      <div id="dshLpGroupJoinBox" style="display:none">
        <button class="ghost" id="dshLpGroupJoin"></button>
        <label id="dshLpJoinByNameLabel"></label>
        <input id="dshLpGroupFindName" maxlength="64" />
        <button class="ghost" id="dshLpGroupFind"></button>
        <div class="hint" id="dshLpFindHint"></div>
        <div id="dshLpGroupFindResult"></div>
        <div class="hint" id="dshLpApplyStatus"></div>
      </div>
    </div>
    <div id="dshLpMsg"></div>
  \`;
  document.body.appendChild(btn);
  document.body.appendChild(panel);
  // 静态骨架里一个字都不写死：上面的标签、按钮、提示全部留空，执行时按注入表填回去。
  // 一律 textContent/placeholder（骨架只由本文件写死的 id 组成，没有任何对端内容）。
  // 用 panel.querySelector 而不是 $ ：$ 定义在这段之后，这里还不能用。
  const SKEL_TEXT = {
    dshLpTabPeers: 'panel.tab.peers',
    dshLpTabGroup: 'panel.tab.group',
    dshLpTabDm: 'panel.tab.dm',
    dshLpTabSettings: 'panel.tab.settings',
    dshLpNameLabel: 'panel.peers.labelName',
    dshLpSaveName: 'panel.peers.saveName',
    dshLpCodeLabel: 'panel.peers.labelCode',
    dshLpCode: 'panel.peers.makeCode',
    dshLpCodeHint: 'panel.peers.codeHint',
    dshLpAddLabel: 'panel.peers.labelAdd',
    dshLpPair: 'panel.peers.actionPair',
    dshLpJobsLabel: 'panel.peers.labelJobs',
    dshLpGroupMsgsLabel: 'panel.group.labelMsgs',
    dshLpGroupSyntax: 'panel.group.syntaxHint',
    dshLpGroupSend: 'panel.common.send',
    dshLpAcceptHint: 'panel.group.acceptHint',
    dshLpGroupNameLabel: 'panel.group.labelName',
    dshLpGroupSaveName: 'panel.group.saveName',
    dshLpGroupAdvertise: 'panel.group.advertise',
    dshLpPendingLabel: 'panel.group.labelPending',
    dshLpArchivesLabel: 'panel.group.labelArchives',
    dshLpGroupAddLabel: 'panel.group.labelAddMember',
    dshLpGroupAdd: 'panel.group.addMember',
    dshLpRemoveHint: 'panel.group.removeHint',
    dshLpGroupClaim: 'panel.group.claim',
    dshLpClaimHint: 'panel.group.claimHint',
    dshLpGroupJoin: 'panel.group.join',
    dshLpJoinByNameLabel: 'panel.group.labelJoinByName',
    dshLpGroupFind: 'panel.group.find',
    dshLpFindHint: 'panel.group.findHint',
  };
  const SKEL_PLACEHOLDER = {
    dshLpPeerName: 'panel.peers.placeholderName',
    dshLpPairCode: 'panel.peers.placeholderCode',
    dshLpGroupText: 'panel.group.placeholderText',
    dshLpGroupFindName: 'panel.group.placeholderFind',
  };
  for (const id of Object.keys(SKEL_TEXT)) {
    const node = panel.querySelector('#' + id);
    if (node) node.textContent = LT(SKEL_TEXT[id]);
  }
  for (const id of Object.keys(SKEL_PLACEHOLDER)) {
    const node = panel.querySelector('#' + id);
    if (node) node.placeholder = LT(SKEL_PLACEHOLDER[id]);
  }

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
    if (!peers.length) {
      const empty = document.createElement('div');
      empty.className = 'peer';
      empty.textContent = LT('panel.peers.emptyRow');
      box.appendChild(empty);
      return;
    }
    for (const p of peers) {
      const row = document.createElement('div');
      row.className = 'peer';
      row.style.display = 'flex';
      row.style.gap = '6px';
      row.style.alignItems = 'center';
      row.style.justifyContent = 'space-between';
      const label = document.createElement('span');
      // textContent, never innerHTML: the peer name comes from the other machine.
      label.textContent = p.name + ' · ' + (p.baseUrl || LT('panel.peers.inboundOnly'));
      const drop = document.createElement('button');
      drop.className = 'ghost';
      drop.textContent = LT('panel.peers.actionUnpair');
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
    if (!window.confirm(LT('panel.peers.unpairConfirm', { name: p.name }))) return;
    if (button) button.disabled = true;
    msg(LT('panel.peers.unpairing'));
    try {
      const out = await api('unpair', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ peerId: p.peerId }),
      });
      const synced = !!(out.remote && out.remote.notified);
      const name = (out.peer && out.peer.name) || p.name;
      msg(LT('panel.peers.unpaired', { name: name })
        + (synced ? LT('panel.peers.unpairedSynced') : LT('panel.peers.unpairedLocal')));
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
    if (!jobs.length) {
      const empty = document.createElement('div');
      empty.className = 'job';
      const emptyText = document.createElement('span');
      emptyText.textContent = LT('panel.peers.emptyJobs');
      empty.appendChild(emptyText);
      box.appendChild(empty);
      return;
    }
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
        ? LT('panel.peers.codeCountdown', { sec: left, mm: m, ss: s })
        : LT('panel.peers.codeExpired');
      if (left <= 0) clearInterval(timer);
    };
    tick();
    timer = setInterval(tick, 1000);
  }

  // 本机 peerId（GET state 的 instanceId）：群气泡靠右/靠左的判据，refresh 每次打开都刷新。
  let selfPeerId = '';

  async function refresh() {
    try {
      const st = await api('state');
      // 本机 peerId 只从 GET state 的 instanceId 拿：GET group 不回自述，
      // 气泡靠左还是靠右全靠它（拿不到就一律当别人，不猜）。
      selfPeerId = String((st && st.instanceId) || '');
      $('dshLpName').value = st.name;
      renderPeers(st.peers || [], dropPeer);
      // M6：state 只回 {active, expiresInSec}，码本身不回显。手上还留着「生成」那次
      // 拿到的码就继续显示它，否则只报状态 —— 抄不下来就只能重新生成。
      if (st.pairing && st.pairing.active) {
        const left = Number(st.pairing.expiresInSec);
        const seconds = Number.isFinite(left) && left > 0 ? left : 0;
        if (shownCodeExpiresAt <= Date.now()) {
          $('dshLpCodeText').textContent = LT('panel.peers.codeHidden');
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

  // -------------------------------------------------------------------------
  // v0.8.5-α 群组页「⚙ 派单设置」弹层（契约 §3，Lane G-B）
  // 目标成员 = 群成员表；工作区/权限的可选值来自**选中目标**（GET group/dispatch-options?peer=…，
  // 只有 id 与 name），切目标就重拉一次。取不到就只显示默认值并置灰 —— 绝不给一份
  // 「选了会报错」的清单。铁律：这里绝不显示任何 path（目标不给，本机也不问）；
  // 全部动态内容只走 textContent，本段零反引号。
  // -------------------------------------------------------------------------
  let groupMembers = [];
  let groupDispatchTarget = '';
  let groupTargetOptions = null;
  let groupOkScope = false;
  let groupDispatchOpen = false;

  const groupDispatchBtn = $('dshLpGroupDispatchBtn');
  const groupDispatchBox = $('dshLpGroupDispatchBox');
  const groupTarget = $('dshLpGroupTarget');
  const groupWs = $('dshLpGroupWs');
  const groupPerm = $('dshLpGroupPerm');
  const groupDispatchHint = $('dshLpGroupDispatchHint');
  const groupDispatchClose = $('dshLpGroupDispatchClose');
  // 骨架里只放 id，一句文案都不写死：全部按渲染时的 lang（resolveLang(config)）从注入表取。
  groupDispatchBtn.textContent = LT('panel.group.dispatchButton');
  $('dshLpGroupDispatchTitle').textContent = LT('panel.group.dispatchTitle');
  $('dshLpGroupTargetLabel').textContent = LT('panel.group.target');
  $('dshLpGroupWsLabel').textContent = LT('panel.group.workspace');
  $('dshLpGroupPermLabel').textContent = LT('panel.group.permission');
  groupDispatchClose.textContent = LT('panel.group.close');
  groupDispatchHint.textContent = LT('panel.group.hint');
  // 与私聊弹层同款：打开前先收起（骨架里的 style 只是脚本执行前的兜底）。
  groupDispatchBox.style.display = 'none';

  /** 权限档位高低：协议值原样比，不翻译（与设置页同一份 PERMS 顺序）。 */
  function groupPermRankOf(level) {
    return PERMS.indexOf(String(level == null ? '' : level));
  }

  /** 目标成员下拉：群成员表（每次 renderGroup 刷新；选中的还在就保留，不打断用户）。 */
  function paintGroupTargets() {
    const wanted = groupDispatchTarget;
    groupTarget.innerHTML = '';
    for (const member of groupMembers) {
      const opt = document.createElement('option');
      opt.value = member.peerId;
      opt.textContent = member.name;
      groupTarget.appendChild(opt);
    }
    if (groupMembers.length === 0) {
      const opt = document.createElement('option');
      opt.value = '';
      opt.textContent = LT('panel.group.noMembers');
      groupTarget.appendChild(opt);
      groupDispatchTarget = '';
      groupTarget.value = '';
      return;
    }
    const keep = groupMembers.some((member) => member.peerId === wanted)
      ? wanted : groupMembers[0].peerId;
    groupDispatchTarget = keep;
    groupTarget.value = keep;
  }

  /** 「只显示默认值并置灰」：拿不到目标 options 时，一个可能被拒的选项都不画。 */
  function paintGroupScopeUnavailable() {
    groupWs.innerHTML = '';
    const wsOpt = document.createElement('option');
    wsOpt.value = '';
    wsOpt.textContent = LT('panel.group.noWorkspace');
    groupWs.appendChild(wsOpt);
    groupWs.value = '';
    groupWs.disabled = true;
    groupPerm.innerHTML = '';
    const permOpt = document.createElement('option');
    // 协议默认档原样显示：这就是「不带字段时目标会用的那一档」。
    permOpt.value = '';
    permOpt.textContent = 'workspace-write';
    groupPerm.appendChild(permOpt);
    groupPerm.value = '';
    groupPerm.disabled = true;
    groupDispatchHint.textContent = LT('panel.group.noWorkspace');
  }

  /** 弹层：工作区下拉（目标 options）+ 权限三档（超目标上限的置灰并写明原因）。 */
  function renderGroupDispatch() {
    const opts = groupTargetOptions && typeof groupTargetOptions === 'object' ? groupTargetOptions : null;
    const workspaces = opts && Array.isArray(opts.workspaces) ? opts.workspaces : [];
    groupOkScope = workspaces.length > 0;
    if (!groupOkScope) {
      paintGroupScopeUnavailable();
      return;
    }
    groupWs.disabled = false;
    groupWs.innerHTML = '';
    for (const ws of workspaces) {
      const opt = document.createElement('option');
      opt.value = String(ws && ws.id ? ws.id : '');
      opt.textContent = String((ws && ws.name) || (ws && ws.id) || '');
      groupWs.appendChild(opt);
    }
    const wanted = String(opts.defaultWorkspaceId || '');
    groupWs.value = wanted !== '' ? wanted : String(workspaces[0] && workspaces[0].id ? workspaces[0].id : '');
    const maxLevel = PERMS.indexOf(String(opts.maxPermission)) >= 0 ? String(opts.maxPermission) : PERMS[0];
    const maxRank = groupPermRankOf(maxLevel);
    groupPerm.disabled = false;
    groupPerm.innerHTML = '';
    for (const level of PERMS) {
      const over = groupPermRankOf(level) > maxRank;
      const opt = document.createElement('option');
      opt.value = level;
      // 协议值原样在前；超上限的补一句原因并 disabled（点了也选不中）。
      opt.textContent = over ? level + ' · ' + LT('panel.group.overLimit', { max: maxLevel }) : level;
      opt.disabled = over;
      groupPerm.appendChild(opt);
    }
    // 默认 workspace-write；它超过目标上限时退到上限那一档（不越权默认）。
    groupPerm.value = groupPermRankOf('workspace-write') <= maxRank ? 'workspace-write' : maxLevel;
    groupDispatchHint.textContent = LT('panel.group.hint');
  }

  /** 换目标就重拉一次：迟到的旧响应按目标 id 丢掉，绝不画成别人的清单。 */
  async function loadGroupTargetOptions() {
    const target = groupDispatchTarget;
    groupTargetOptions = null;
    if (target === '') {
      renderGroupDispatch();
      return;
    }
    try {
      const out = await api('group/dispatch-options?peer=' + encodeURIComponent(target));
      if (groupDispatchTarget !== target) return;
      groupTargetOptions = out && typeof out === 'object' ? out : null;
    } catch (error) {
      if (groupDispatchTarget !== target) return;
      groupTargetOptions = null;
      msg(LT('panel.group.loadFailed', { text: String((error && error.message) || error) }));
    }
    renderGroupDispatch();
  }

  /**
   * 这次发送点名的作用域。弹层没开 / 没有目标 / 目标没给可选工作区 → 只带 target
   * （契约 §0/§2 的退回口径：由目标用自己的默认工作区与默认档）。
   */
  function groupScopeNow() {
    if (!groupDispatchOpen) return null;
    const target = groupDispatchTarget !== '' ? groupDispatchTarget : String(groupTarget.value || '');
    if (target === '') return null;
    if (!groupOkScope) return { target };
    const workspaceId = String(groupWs.value == null ? '' : groupWs.value).trim();
    const permission = String(groupPerm.value == null ? '' : groupPerm.value).trim();
    const scope = { target };
    if (workspaceId !== '') scope.workspaceId = workspaceId;
    if (permission !== '') scope.permission = permission;
    return scope;
  }

  groupDispatchBtn.onclick = async () => {
    if (groupDispatchOpen) {
      groupDispatchOpen = false;
      groupDispatchBox.style.display = 'none';
      return;
    }
    msg('');
    paintGroupTargets();
    groupDispatchOpen = true;
    groupDispatchBox.style.display = 'block';
    await loadGroupTargetOptions();
  };

  groupDispatchClose.onclick = () => {
    groupDispatchOpen = false;
    groupDispatchBox.style.display = 'none';
    groupTargetOptions = null;
    groupOkScope = false;
  };

  groupTarget.onchange = () => {
    groupDispatchTarget = String(groupTarget.value || '');
    loadGroupTargetOptions();
  };

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
    if (value <= 0) return LT('panel.common.inactive');
    const delta = Math.max(0, Date.now() - value);
    if (delta < 60000) return LT('panel.common.agoSecs', { n: Math.round(delta / 1000) });
    if (delta < 3600000) return LT('panel.common.agoMinutes', { n: Math.round(delta / 60000) });
    return LT('panel.common.agoHours', { n: Math.round(delta / 3600000) });
  }

  // meta 摘要只列白名单字段（DESIGN §3），未知字段不渲染。
  function metaText(meta) {
    if (!meta || typeof meta !== 'object') return '';
    const parts = [];
    if (meta.phase) parts.push(String(meta.phase));
    if (meta.status) parts.push(String(meta.status));
    if (meta.transport) parts.push(String(meta.transport));
    if (meta.elapsedMs != null && Number.isFinite(Number(meta.elapsedMs))) parts.push(Math.round(Number(meta.elapsedMs)) + 'ms');
    if (meta.replyChars != null && Number.isFinite(Number(meta.replyChars))) parts.push(LT('panel.common.chars', { n: Number(meta.replyChars) }));
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
      none.textContent = LT('panel.group.emptyMembers');
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
      label.textContent = String((member && (member.name || member.peerId)) || LT('panel.common.unnamedParen'));
      const seen = document.createElement('span');
      seen.className = 'gtime';
      seen.textContent = agoText(member && member.lastSeen);
      row.appendChild(dot);
      row.appendChild(label);
      row.appendChild(seen);
      if (groupIsHub && member && member.peerId) {
        const remove = document.createElement('button');
        remove.className = 'ghost';
        remove.textContent = LT('panel.group.remove');
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
      lagSpan.textContent = LT('panel.group.lag', { n: lag });
      sub.appendChild(lagSpan);
    }
    // 契约 §5：成员行的接单状态。字段缺省 = 接单中（老对端没有这个字段，绝不能显示成「已关闭」）。
    const accepts = member ? member.acceptDispatch !== false : true;
    const acceptSpan = document.createElement('span');
    acceptSpan.className = 'gaccept' + (accepts ? '' : ' off');
    acceptSpan.textContent = accepts ? LT('panel.group.acceptOn') : LT('panel.group.acceptOff');
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
    $('dshLpArchiveHead').textContent = LT('panel.group.archivesHead', { count: list.length, bytes: sizeText(total) });
    if (!list.length) {
      const none = document.createElement('div');
      none.className = 'peer';
      none.textContent = LT('panel.group.archivesEmpty');
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
      remove.textContent = LT('panel.group.delete');
      remove.onclick = () => deleteArchive(item, remove);
      const meta = document.createElement('div');
      meta.className = 'gsub';
      const from = seqOrNull(item.fromSeq);
      const to = seqOrNull(item.toSeq);
      const count = seqOrNull(item.count);
      const created = toMs(item.createdAt);
      meta.textContent = 'seq ' + (from === null ? '—' : from) + '–' + (to === null ? '—' : to)
        + ' · ' + (count === null ? '—' : LT('panel.common.count', { count: count }))
        + ' · ' + sizeText(item.bytes)
        + ' · ' + (created > 0 ? agoText(created) : LT('panel.group.timeUnknown'));
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
      msg(LT('panel.group.archivesLoadFailed', { text: String(error && error.message ? error.message : error) }));
    }
  }

  /** 删除单个归档：二次确认 → POST → 刷新列表并提示释放了多少空间。 */
  async function deleteArchive(item, button) {
    const file = String((item && item.file) || '');
    if (file === '') return;
    if (!window.confirm(LT('panel.group.archiveConfirm', { file: file }))) return;
    if (button) button.disabled = true;
    msg('');
    try {
      const out = await api('group/archives', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ file: file, action: 'delete' }),
      });
      const removed = Number(out && out.removedBytes);
      msg(LT('panel.group.archiveDeleted', { file: file })
        + (Number.isFinite(removed) && removed > 0 ? LT('panel.group.archiveFreed', { size: sizeText(removed) }) : ''));
      await loadArchives();
    } catch (error) {
      msg(LT('panel.group.archiveDeleteFailed', { text: String(error && error.message ? error.message : error) }));
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
      none.textContent = unreadable ? LT('panel.group.pendingUnreadable') : LT('panel.group.pendingEmpty');
      box.appendChild(none);
      if (!unreadable) renderDecidedApplications(box, decided);
      return;
    }
    for (const item of pending) {
      const row = document.createElement('div');
      row.className = 'member gpending';
      const label = document.createElement('span');
      label.className = 'gname';
      label.textContent = String(item.name || item.peerId || LT('panel.common.unknownParen'));
      const approve = document.createElement('button');
      approve.className = 'ghost';
      approve.textContent = LT('panel.group.approve');
      approve.onclick = () => decideApplication(item, 'approve', approve);
      const reject = document.createElement('button');
      reject.className = 'ghost';
      reject.textContent = LT('panel.group.reject');
      reject.onclick = () => decideApplication(item, 'reject', reject);
      const meta = document.createElement('div');
      meta.className = 'gsub';
      const by = String(item.introducedByName || '') || shortIdText(item.introducedBy);
      meta.textContent = LT('panel.group.pendingMeta', { by: by, ago: agoText(item.at) });
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
      const label = item.status === 'approved' ? LT('panel.settings.approved') : LT('panel.settings.rejected');
      row.textContent = label + ' · ' + String(item.name || item.peerId || LT('panel.common.unknownParen'))
        + ' · ' + (stamp > 0 ? LT('panel.group.decidedAt', { ago: agoText(stamp) }) : LT('panel.group.decidedUnknown'));
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
      label.textContent = String(match.name || LT('panel.group.unnamedGroupParen'));
      const apply = document.createElement('button');
      apply.className = 'ghost';
      apply.textContent = LT('panel.group.applyJoin');
      apply.onclick = () => applyForMatch(match, apply);
      const meta = document.createElement('div');
      meta.className = 'gsub';
      const hub = match.hub ? String(match.hub.name || match.hub.peerId || '') : '';
      const via = match.via ? String(match.via.name || match.via.peerId || '') : '';
      meta.textContent = LT('panel.group.findMeta', {
        hub: hub === '' ? '—' : hub,
        via: via === '' ? '—' : via,
        gid: shortIdText(match.groupId),
      });
      row.appendChild(label);
      row.appendChild(apply);
      row.appendChild(meta);
      box.appendChild(row);
    }
  }

  /** 申请状态三态：待批准 / 已加入 / 被拒（未知不写，免得把「没问到」显示成结论）。 */
  function renderApplyStatus(status, reason) {
    const labels = {
      pending: LT('panel.group.applyPending'),
      approved: LT('panel.group.applyJoined'),
      rejected: LT('panel.group.applyRejectedShort'),
    };
    const label = labels[String(status || '')] || '';
    const box = $('dshLpApplyStatus');
    if (label === '') { box.textContent = ''; return; }
    box.textContent = LT('panel.group.applyStatus', { label: label })
      + (reason ? LT('panel.group.reasonParen', { reason: String(reason) }) : '');
  }

  /** 改名冲突清单：伙伴名 + 群名 + groupId 前 8 位（契约 §8）。 */
  function renderNameConflicts(conflicts) {
    const box = $('dshLpGroupNameConflicts');
    const list = Array.isArray(conflicts) ? conflicts : [];
    if (!list.length) { box.textContent = ''; return; }
    const lines = [];
    for (const item of list) {
      const peer = String(item.peerName || '') || shortIdText(item.peerId);
      lines.push(peer + ' · ' + String(item.name || LT('panel.group.unnamedGroupParen')) + ' · ' + shortIdText(item.groupId));
    }
    box.textContent = LT('panel.group.nameConflict', { list: lines.join(LT('panel.common.listSep')) });
  }

  /** 申请者的状态轮询（契约 §5.2）：最长 10 分钟，超时就停并提示「仍待批准」。 */
  function pollApplyStatus() {
    const ctx = applyCtx;
    if (!ctx) return;
    if (Date.now() - ctx.startedAt > APPLY_MAX_WAIT_MS) {
      applyCtx = null;
      renderApplyStatus('pending');
      msg(LT('panel.group.stillPending'));
      return;
    }
    api('group/apply-status?groupId=' + encodeURIComponent(ctx.groupId)
      + '&introducer=' + encodeURIComponent(ctx.introducer))
      .then((out) => {
        const status = String((out && out.status) || 'unknown');
        renderApplyStatus(status, out && out.reason);
        if (status === 'approved') {
          applyCtx = null;
          msg(LT('panel.group.joined'));
        } else if (status === 'rejected') {
          applyCtx = null;
          msg(LT('panel.group.applyRejectedMsg', { reason: String((out && out.reason) || LT('panel.common.noReason')) }));
        }
      })
      .catch(() => {});
  }

  async function applyForMatch(match, button) {
    const groupId = String((match && match.groupId) || '');
    const introducer = match && match.via ? String(match.via.peerId || '') : '';
    if (groupId === '' || introducer === '') { msg(LT('panel.group.applyMissingIntroducer')); return; }
    if (button) button.disabled = true;
    msg(LT('panel.group.applying'));
    try {
      const out = await groupAction('group/apply', { groupId: groupId, introducer: introducer }, '');
      const status = String((out && out.status) || 'pending');
      renderApplyStatus(status, out && out.reason);
      msg(status === 'approved' ? LT('panel.group.joined')
        : (status === 'rejected' ? LT('panel.group.applyRejected') : LT('panel.group.applySent')));
      // 待批准才需要轮询；已加入/被拒是一次性的结论。
      applyCtx = status === 'pending' ? { groupId: groupId, introducer: introducer, startedAt: Date.now() } : null;
    } catch (error) {
      msg(LT('panel.group.applyFailed', { text: String(error.message || error) }));
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
        action === 'approve' ? LT('panel.settings.approved') : LT('panel.settings.rejected'));
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
  /**
   * 回执的作用域：只写「工作区名 · 权限档」。读的字段只有 workspace.name / workspace.id /
   * workspaceName / workspaceId / permission —— path 不在这份名单里，所以它进不了这句话。
   * 一个字段都没有时返回空串（0.8.4 的行文本一个字都不变）。
   */
  function receiptScopeText(source) {
    const data = source && typeof source === 'object' ? source : {};
    const meta = data.meta && typeof data.meta === 'object' ? data.meta : data;
    const ws = meta.workspace && typeof meta.workspace === 'object' ? meta.workspace : null;
    const name = String((ws && (ws.name || ws.id)) || meta.workspaceName || meta.workspaceId || '');
    const perm = String(meta.permission || '');
    if (name === '' && perm === '') return '';
    return ' · ' + LT('panel.group.receiptScope', {
      workspace: name === '' ? '—' : name,
      permission: perm === '' ? '—' : perm,
    });
  }

  /** 这条回执是不是「等目标点头」（契约 §2）：只影响样式，不影响文案里的状态。 */
  function dispatchPending(item) {
    const meta = item && item.meta && typeof item.meta === 'object' ? item.meta : null;
    return meta !== null && String(meta.status || '') === 'pending-approval';
  }

  function dispatchSummaryText(outcome) {
    const data = outcome && typeof outcome === 'object' ? outcome : {};
    const raw = String(data.status || '');
    // 契约 §2：pending-approval 是第四种终态（等目标人工批准），绝不并进 failed。
    const status = raw === 'done' || raw === 'skipped' || raw === 'pending-approval' ? raw : 'failed';
    // 三态各说各话：skipped 是「这条消息没有 @! 目标」，绝不能显示成完成或失败。
    if (status === 'skipped') return LT('panel.group.receiptSkipped');
    if (status === 'pending-approval') {
      return LT('panel.group.receipt', { target: memberLabel(data.target), status: LT('panel.group.pendingApproval') })
        + receiptScopeText(data);
    }
    // M1：同名歧义是用户的选择问题，不是网络故障 —— 直接给可操作的下一步。
    if (status === 'failed' && String(data.reason || '') === 'ambiguous') {
      return LT('panel.group.receipt', { target: memberLabel(data.target), status: LT('panel.group.ambiguous') });
    }
    const parts = [];
    // reason 不只在 failed 上有意义：done 也可能带 multi-target-ignored（契约 §1 不整条拒绝）。
    if (data.reason != null && String(data.reason) !== '') parts.push(String(data.reason));
    const elapsed = Number(data.elapsedMs);
    if (Number.isFinite(elapsed) && elapsed >= 0) parts.push(Math.round(elapsed) + 'ms');
    const chars = Number(data.replyChars);
    if (Number.isFinite(chars) && chars >= 0) parts.push(LT('panel.common.chars', { n: Math.round(chars) }));
    return LT('panel.group.receipt', { target: memberLabel(data.target), status: status })
      + (parts.length ? LT('panel.group.receiptDetail', { detail: parts.join(' / ') }) : '')
      + receiptScopeText(data);
  }

  /** 群消息里的派单行：dispatch-start = 进行中，dispatch-end = 摘要；其它消息返回空串。 */
  function dispatchLine(item) {
    const meta = item && item.meta && typeof item.meta === 'object' ? item.meta : null;
    const phase = meta ? String(meta.phase || '') : '';
    if (phase !== 'dispatch-start' && phase !== 'dispatch-end') return '';
    if (phase === 'dispatch-start') {
      return LT('panel.group.receipt', { target: memberLabel(meta.target), status: LT('panel.group.inFlight') }) + receiptScopeText(meta);
    }
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
    button.textContent = LT('panel.group.acceptButton', {
      state: accept ? LT('panel.group.acceptOn') : LT('panel.group.acceptOff'),
    });
    button.style.display = 'block';
    const state = data && data.dispatch && typeof data.dispatch === 'object' ? data.dispatch : null;
    const target = state && state.lastTarget != null ? String(state.lastTarget) : '';
    const line = $('dshLpGroupDispatchState');
    if (state && state.inFlight === true) {
      line.textContent = LT('panel.group.dispatchInFlight', { target: memberLabel(target) });
    } else if (target !== '') {
      line.textContent = LT('panel.group.lastDispatch', { target: memberLabel(target), ago: agoText(state.lastAt) });
    } else {
      line.textContent = '';
    }
  }

  /** 是否本机发的：只认 GET state 的 instanceId，拿不到就不认（宁可当别人，也不猜）。 */
  function messageFromSelf(from) {
    const id = from && from.peerId ? String(from.peerId) : '';
    return id !== '' && id === selfPeerId;
  }

  /**
   * 群消息行（v0.8.5-α 视觉语言对齐私聊页）：正文直接复用 .dmmsg.self/.peer + .bubble + .st
   * 这一套既有规则（自己靠右蓝底、别人靠左深灰），元信息走 .st 小字。
   * 派单回执（progress/result 与 dispatch-start/end）不进气泡，渲染成居中的 .gsys 系统行，
   * 屏幕上要一眼分清「谁在说话」和「系统消息」。动态内容一律 textContent。
   */
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
      const from = item.from && typeof item.from === 'object' ? item.from : {};
      const who = String(from.name || from.peerId || LT('panel.group.senderSystem'));
      const kind = String(item.kind || 'chat');
      const text = typeof item.text === 'string' ? item.text : '';
      const meta = metaText(item.meta);
      // 时间 + seq 的元信息：每条消息都要能被对上群历史里的一行。
      const stamp = clockText(item.ts) + (Number.isFinite(seq) ? ' · #' + seq : '');
      // 契约 §5：派单回执只渲染摘要；item.text 在派单消息上**一律不显示** ——
      // 万一上游把正文写进了群消息，面板也不会把它摊在屏幕上。
      const dispatch = dispatchLine(item);
      if (dispatch !== '' || kind === 'progress' || kind === 'result') {
        const sys = document.createElement('div');
        // 契约 §2/§3：pending-approval 是「等目标点头」，不是失败 —— 单独一条中性样式
        // （.gsys.pending，琥珀色），不用告警红。
        sys.className = dispatchPending(item) ? 'gsys pending' : 'gsys';
        const detail = meta !== '' ? meta : text;
        sys.textContent = (dispatch !== '' ? dispatch : LT('panel.group.sysLine', { kind: kind })
          + (detail === '' ? '' : ' · ' + detail))
          + ' · ' + stamp;
        box.appendChild(sys);
        added += 1;
        continue;
      }
      let body = text;
      if (body === '' && meta !== '') body = meta;
      if (body.length > 200) body = body.slice(0, 200) + '…';
      const row = document.createElement('div');
      row.className = 'dmmsg ' + (messageFromSelf(from) ? 'self' : 'peer');
      const bubble = document.createElement('div');
      bubble.className = 'bubble';
      const bodySpan = document.createElement('span');
      // 对端正文只进 textContent：绝不拼 HTML，也不进日志。
      bodySpan.textContent = body;
      const metaSpan = document.createElement('span');
      metaSpan.className = 'st';
      metaSpan.textContent = who + ' · ' + stamp;
      bubble.appendChild(bodySpan);
      bubble.appendChild(metaSpan);
      row.appendChild(bubble);
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
      head.textContent = LT('panel.group.headDisabled');
      $('dshLpGroupLeader').textContent = LT('panel.group.leaderLine', { name: '—' });
      $('dshLpGroupRole').textContent = LT('panel.group.roleLine', { role: '—' });
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
      $('dshLpArchiveHead').textContent = LT('panel.group.archivesHead', { count: 0, bytes: '0 B' });
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
    // 契约 §3：派单弹层的目标下拉与成员表同源（名字来自成员自报，只进 textContent）。
    groupMembers = [];
    for (const member of members) {
      const id = member && member.peerId ? String(member.peerId) : '';
      if (id === '') continue;
      groupMembers.push({ peerId: id, name: String(member.name || id) });
    }
    if (groupDispatchOpen) {
      const beforeTarget = groupDispatchTarget;
      paintGroupTargets();
      // 选中的人已经不在群里：清单必须跟着换，不能留着一份别人的工作区。
      if (groupDispatchTarget !== beforeTarget) loadGroupTargetOptions();
    }
    const title = group && group.name ? String(group.name) : LT('panel.common.unnamedParen');
    // v0.8.0：config 关着、但本机已按名入群时，群功能是有效的 —— 这里如实说是怎么来的，
    // 免得用户看着「群组」页却以为自己的群没启用。
    const label = data.enabledSource === 'membership' ? LT('panel.group.labelByName') : LT('panel.group.labelPlain');
    head.textContent = LT('panel.group.headName', {
      label: label,
      title: title,
      scope: groupIsHub ? LT('panel.group.scopeHub') : LT('panel.group.scopeMember'),
      count: members.length,
    });
    if (data.error) msg(LT('panel.group.err', { text: String(data.error) }));
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
      $('dshLpArchiveHead').textContent = LT('panel.group.archivesHubOnly');
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
    $('dshLpGroupLeader').textContent = LT('panel.group.leaderLine', {
      name: (leaderName === '' ? '—' : leaderName) + (epoch === null ? '' : ' (epoch ' + epoch + ')'),
    });
    const role = data.selfRole === 'hub' ? 'hub' : (data.selfRole === 'member' ? LT('panel.group.roleMember') : '');
    $('dshLpGroupRole').textContent = LT('panel.group.roleLine', {
      role: role === '' ? (isHub ? 'hub' : LT('panel.group.roleMember')) : role,
    });

    const replica = data.replica && typeof data.replica === 'object' ? data.replica : null;
    const replLast = seqOrNull(replica ? replica.lastSeq : null);
    const replLag = seqOrNull(replica ? replica.lag : null);
    let line = '';
    if (replLast !== null) {
      line = LT('panel.group.replicaArrived', { n: replLast });
      if (replLag === null) line += LT('panel.group.replicaUnknown');
      else if (replLag > 0) line += LT('panel.group.replicaLag', { n: replLag });
      else line += LT('panel.group.replicaSynced');
    }
    $('dshLpGroupReplica').textContent = line;

    // 配置里没写 advertiseBaseUrl 时本机靠自动探测，别人看到的地址若不同就得让用户去改配置
    const advertises = typeof data.advertiseBaseUrl === 'string' ? data.advertiseBaseUrl : '';
    const seenByOthers = typeof data.selfBaseUrl === 'string' ? data.selfBaseUrl : '';
    const source = typeof data.advertiseSource === 'string' ? data.advertiseSource : '';
    const warn = $('dshLpGroupAddrWarn');
    if (source !== 'config' && seenByOthers !== '' && seenByOthers !== advertises) {
      warn.textContent = LT('panel.group.addrWarn', { addr: seenByOthers });
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
    $('dshLpGroupStatus').textContent = LT('panel.group.statusLine', {
      role: role,
      epoch: epoch === null ? '—' : epoch,
      leader: leaderName === '' ? '—' : leaderName,
      quorum: quorum,
      pending: pending === null ? '—' : pending,
    });
    const degraded = $('dshLpGroupDegraded');
    if (data.degraded === true) {
      degraded.textContent = LT('panel.group.degraded');
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
      .catch((error) => { msg(LT('panel.group.err', { text: String(error.message || error) })); });
  }

  // -------------------------------------------------------------------------
  // v0.8.5-α 私聊页（契约 §6，Lane G2）
  // 铁律：动态内容一律 textContent；这一段实现里**没有任何反引号模板字符串** ——
  // 整页用 createElement 拼（静态骨架里也不写私聊标记），所以对端正文永远不会
  // 参与 HTML 解析。轮询 1s 且 document.hidden 一为真就停，与群组的 2s 节拍互不影响。
  // -------------------------------------------------------------------------
  const DM_POLL_MS = 1000;
  // state 只带 lastSeen（没有 online 字段）：60s 内有活动就算在线，与成员行的口径分开说明。
  const DM_ONLINE_MS = 60000;
  const DM_PAGE_MAX_ROWS = 200;   // 一屏气泡最多渲染这么多条（历史可以 2000 条，面板不全渲染）
  let dmTabOpen = false;
  let dmPeerId = '';
  let dmPeerName = '';
  let dmTimer = null;
  let dmRows = [];                // 服务端权威列表（GET dm?peer=）
  const dmLocal = new Map();      // 还没进服务端列表的条目：发送中 / 刚发完的回复
  let dmPeers = [];               // GET state 的伙伴列表（在线状态 + 名称）
  const dmLastAt = {};            // peerId -> 最近一条私聊时间（毫秒），只用于列表行

  const dmPage = document.createElement('div');
  dmPage.id = 'dshLpPageDm';
  dmPage.style.display = 'none';
  const dmHead = document.createElement('div');
  dmHead.id = 'dshLpDmHead';
  dmHead.className = 'hint';
  dmHead.textContent = LT('panel.dm.head');
  const dmListBox = document.createElement('div');
  dmListBox.id = 'dshLpDmList';
  const dmPeerLine = document.createElement('div');
  dmPeerLine.id = 'dshLpDmPeer';
  dmPeerLine.className = 'hint';
  dmPeerLine.textContent = LT('panel.dm.noPeerSelected');
  const dmMsgs = document.createElement('div');
  dmMsgs.id = 'dshLpDmMsgs';
  const dmInput = document.createElement('input');
  dmInput.id = 'dshLpDmText';
  dmInput.maxLength = 4000;
  dmInput.placeholder = LT('panel.dm.placeholder');
  dmInput.style.marginTop = '6px';
  const dmSendBtn = document.createElement('button');
  dmSendBtn.id = 'dshLpDmSend';
  dmSendBtn.textContent = LT('panel.common.send');
  dmPage.appendChild(dmHead);
  dmPage.appendChild(dmListBox);
  dmPage.appendChild(dmPeerLine);
  dmPage.appendChild(dmMsgs);
  dmPage.appendChild(dmInput);
  dmPage.appendChild(dmSendBtn);
  panel.appendChild(dmPage);

  /** 在线判定：state 的 lastSeen 在 60s 内（老记录没有 lastSeen 就算离线）。 */
  function dmOnline(peer) {
    const seen = toMs(peer && peer.lastSeen);
    return seen > 0 && (Date.now() - seen) < DM_ONLINE_MS;
  }

  /** 同一条消息的「同一性」：先按 id，再按 (方向, 正文) —— 服务端列表为准。 */
  function dmKeyOf(row) {
    return JSON.stringify([String(row && row.from), String(row && row.text)]);
  }

  /** 服务端列表 + 本地覆盖层；id 或 (方向,正文) 已经出现过就不再重复渲染。 */
  function mergeDmRows(rows) {
    const ids = new Set();
    const keys = new Set();
    const out = [];
    for (const row of rows) {
      ids.add(String(row.id));
      keys.add(dmKeyOf(row));
      out.push(row);
    }
    for (const row of dmLocal.values()) {
      if (ids.has(String(row.id))) continue;
      if (keys.has(dmKeyOf(row))) continue;
      out.push(row);
    }
    out.sort((a, b) => (Number(a.ts) || 0) - (Number(b.ts) || 0));
    return out;
  }

  /** 气泡区：自己靠右、对方靠左；state=sending 的那条显示「发送中」。 */
  function renderDmMessages() {
    dmMsgs.innerHTML = '';
    const all = mergeDmRows(dmRows);
    if (all.length === 0) {
      const none = document.createElement('div');
      none.className = 'hint';
      none.textContent = dmPeerId === '' ? LT('panel.dm.emptyNoPeer') : LT('panel.dm.emptyNoHistory');
      dmMsgs.appendChild(none);
      return;
    }
    // 只渲染最近 DM_PAGE_MAX_ROWS 条：历史 2000 条也不该把面板一次性铺满。
    const rows = all.length > DM_PAGE_MAX_ROWS ? all.slice(all.length - DM_PAGE_MAX_ROWS) : all;
    for (const row of rows) {
      const wrap = document.createElement('div');
      wrap.className = 'dmmsg ' + (row.from === 'peer' ? 'peer' : 'self');
      const bubble = document.createElement('div');
      bubble.className = 'bubble';
      const body = document.createElement('span');
      // 对端正文只进 textContent：绝不拼 HTML，也不进日志。
      body.textContent = String(row.text == null ? '' : row.text);
      bubble.appendChild(body);
      const stamp = document.createElement('span');
      stamp.className = 'st';
      // 特殊态（发送中 / 等待对方确认 / 已批准 / 已拒绝 / 超时）走文案，其余显示时刻。
      const special = row.state === 'sending' || row.state === 'pending-approval'
        || row.state === 'approval-approved' || row.state === 'approval-rejected'
        || row.state === 'approval-expired';
      stamp.textContent = special ? dmStampText(row) : clockText(row.ts);
      if (special) wrap.className = wrap.className + ' pending';
      bubble.appendChild(stamp);
      wrap.appendChild(bubble);
      dmMsgs.appendChild(wrap);
    }
    dmMsgs.scrollTop = dmMsgs.scrollHeight;
  }

  /** 左侧伙伴列表：在线点 + 名字 + 最近一条私聊时间（没聊过就用 lastSeen）。 */
  function renderDmPeers() {
    dmListBox.innerHTML = '';
    if (dmPeers.length === 0) {
      const none = document.createElement('div');
      none.className = 'hint';
      none.textContent = LT('panel.peers.empty');
      dmListBox.appendChild(none);
      return;
    }
    for (const peer of dmPeers) {
      const peerId = String(peer && peer.peerId ? peer.peerId : '');
      if (peerId === '') continue;
      const row = document.createElement('div');
      row.className = 'dmrow' + (peerId === dmPeerId ? ' on' : '');
      const dot = document.createElement('span');
      dot.className = 'dot' + (dmOnline(peer) ? ' on' : '');
      dot.textContent = dmOnline(peer) ? '●' : '○';
      const name = document.createElement('span');
      name.className = 'dmname';
      name.textContent = String(peer.name || peerId.slice(0, 8));
      const when = document.createElement('span');
      when.className = 'dmtime';
      const last = Number(dmLastAt[peerId]);
      when.textContent = Number.isFinite(last) && last > 0
        ? LT('panel.dm.recent', { time: clockText(last) })
        : agoText(peer.lastSeen);
      row.appendChild(dot);
      row.appendChild(name);
      row.appendChild(when);
      row.onclick = () => { selectDmPeer(peerId); };
      dmListBox.appendChild(row);
    }
  }

  /** 把 GET dm?peer= 的响应贴到面板上（服务端是权威；本地覆盖层在 merge 里合并）。 */
  function applyDmView(out) {
    const data = out && typeof out === 'object' ? out : {};
    const peer = data.peer && typeof data.peer === 'object' ? data.peer : {};
    dmPeerName = String(peer.name || '') || dmPeerId.slice(0, 8);
    dmPeerLine.textContent = LT('panel.dm.withPeer', { name: dmPeerName, id: shortIdText(dmPeerId) });
    const rows = [];
    const list = Array.isArray(data.messages) ? data.messages : [];
    for (const raw of list) {
      if (!raw || typeof raw !== 'object') continue;
      const id = String(raw.id == null ? '' : raw.id);
      if (id === '') continue;
      rows.push({
        id,
        ts: toMs(raw.ts),
        from: raw.from === 'peer' ? 'peer' : 'self',
        text: String(raw.text == null ? '' : raw.text),
        state: String(raw.state == null ? '' : raw.state),
      });
    }
    dmRows = rows;
    let newest = 0;
    for (const row of rows) if (row.ts > newest) newest = row.ts;
    if (newest > 0) dmLastAt[dmPeerId] = newest;
    renderDmPeers();
    renderDmMessages();
  }

  async function loadDmMessages() {
    if (dmPeerId === '') return;
    try {
      applyDmView(await api('dm?peer=' + encodeURIComponent(dmPeerId)));
    } catch (error) {
      msg(LT('panel.dm.readFailed', { text: String((error && error.message) || error) }));
    }
  }

  /** 打开某个伙伴：先 sync 一次（契约 §6），再拉本地历史渲染。sync 失败不阻塞历史。 */
  async function selectDmPeer(peerId) {
    const next = String(peerId == null ? '' : peerId);
    if (next === '') return;
    dmPeerId = next;
    dmRows = [];
    dmLocal.clear();
    // 换伙伴：派单弹层与待确认轮询都属于上一个伙伴，一并收起（绝不错问另一个 peer）。
    dmDispatchOpen = false;
    dmDialog.style.display = 'none';
    dmPeerOptions = null;
    stopApprovalPoll();
    dmApproval = null;
    dmPeerLine.textContent = LT('panel.dm.syncing');
    renderDmPeers();
    renderDmMessages();
    msg('');
    try {
      const synced = await api('dm/sync', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ peerId: dmPeerId }),
      });
      const added = Number(synced && synced.added);
      const total = Number(synced && synced.total);
      dmHead.textContent = LT('panel.dm.synced', {
        added: Number.isFinite(added) ? added : 0,
        total: Number.isFinite(total) ? total : 0,
      });
    } catch (error) {
      msg(LT('panel.dm.syncFailed', { text: String((error && error.message) || error) }));
    }
    await loadDmMessages();
  }

  /** 进私聊页：先拿伙伴列表（在线状态 + 名字），默认选中第一个。 */
  async function openDmPage() {
    msg('');
    try {
      const st = await api('state');
      dmPeers = Array.isArray(st && st.peers) ? st.peers : [];
    } catch (error) {
      msg(LT('panel.dm.peersFailed', { text: String((error && error.message) || error) }));
    }
    renderDmPeers();
    if (dmPeerId === '' && dmPeers.length > 0) {
      const first = String(dmPeers[0] && dmPeers[0].peerId ? dmPeers[0].peerId : '');
      if (first !== '') dmPeerId = first;
    }
    if (dmPeerId !== '') {
      await selectDmPeer(dmPeerId);
    } else {
      dmPeerLine.textContent = LT('panel.peers.empty');
      renderDmMessages();
    }
    startDmPoll();
  }

  function pollDm() {
    if (!dmTabOpen) return;
    if (document.hidden === true) return;
    if (dmPeerId === '') return;
    api('dm?peer=' + encodeURIComponent(dmPeerId))
      .then((out) => { applyDmView(out); })
      .catch((error) => { msg(LT('panel.dm.err', { text: String((error && error.message) || error) })); });
  }

  function stopDmPoll() {
    if (dmTimer) { clearInterval(dmTimer); dmTimer = null; }
  }

  function startDmPoll() {
    stopDmPoll();
    dmTimer = setInterval(pollDm, DM_POLL_MS);
  }

  /**
   * 发一条私聊：先上屏「发送中」，成功拿回复后替换成自己一条 + 对方一条；
   * 失败只写 msg 区，正文放回输入框（绝不把用户刚打的字吞掉），也不抛错。
   */
  async function sendDm() {
    if (dmPeerId === '') { msg(LT('panel.dm.pickFirst')); return; }
    const text = String(dmInput.value == null ? '' : dmInput.value);
    if (text.trim() === '') { msg(LT('panel.dm.emptyText')); return; }
    msg('');
    dmInput.value = '';
    const pendingId = 'pending-' + String(Date.now()) + '-' + String(Math.round(Math.random() * 1e6));
    dmLocal.set(pendingId, { id: pendingId, ts: Date.now(), from: 'self', text: text, state: 'sending' });
    renderDmMessages();
    // 契约 §2：弹层没打开时这两个字段一个都不带 —— 不发 = 对端用自己的默认工作区与默认档。
    const scope = dmScopeNow();
    let out;
    try {
      out = await api('dm/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          peerId: dmPeerId,
          text: text,
          ...(scope && scope.workspaceId !== '' ? { workspaceId: scope.workspaceId } : {}),
          ...(scope && scope.permission !== '' ? { permission: scope.permission } : {}),
        }),
      });
    } catch (error) {
      dmLocal.delete(pendingId);
      dmInput.value = text;
      renderDmMessages();
      msg(LT('panel.dm.sendFailed', { text: String((error && error.message) || error) }));
      return;
    }
    dmLocal.delete(pendingId);
    const sentId = String((out && out.id) || pendingId);
    const now = Date.now();
    // 契约 §2/§6：超过对端默认档 = 还没执行。气泡停在「等待对方确认…」并开始轮询审批状态，
    // 绝不假装成功，也不自己编一条回复。
    if (out && out.pendingApproval === true) {
      dmLocal.set(sentId, { id: sentId, ts: now, from: 'self', text: text, state: 'pending-approval' });
      dmApproval = {
        approvalId: String(out.approvalId || ''),
        expiresAt: Number(out.expiresAt) || 0,
        peerId: dmPeerId,
        rowId: sentId,
      };
      dmLastAt[dmPeerId] = now;
      renderDmPeers();
      renderDmMessages();
      if (dmApproval.approvalId !== '') startApprovalPoll();
      return;
    }
    dmLocal.set(sentId, {
      id: sentId, ts: now, from: 'self', text: text, state: String((out && out.state) || 'sent'),
    });
    const reply = String(out && out.reply != null ? out.reply : '');
    if (reply !== '') {
      // 回复先挂在这条发送下面；主循环下一次 GET 若已带回它，merge 会按 (方向,正文) 去重。
      dmLocal.set(sentId + '-reply', { id: sentId + '-reply', ts: now + 1, from: 'peer', text: reply, state: 'sent' });
    }
    dmLastAt[dmPeerId] = now;
    renderDmPeers();
    renderDmMessages();
  }

  // -------------------------------------------------------------------------
  // v0.8.5-α 第四个页签「设置」（契约 §5/§6，Lane H2）
  // 铁律：动态内容一律 textContent；本段没有反引号模板字符串（清空只赋空串）。
  // 设置页**可以**显示 path —— 那是本机自己的配置，从不跨机（跨机只有 id 与 name）。
  // -------------------------------------------------------------------------
  const SETTINGS_POLL_MS = 2000;
  // 权限三档是协议值，不翻译；这份清单从 admin.mjs 的 DISPATCH_PERMISSIONS 嵌进来。
  const PERMS = ${JSON.stringify(DISPATCH_PERMISSIONS)};
  const secondsOf = (ms) => Math.max(0, Math.ceil((Number(ms) || 0) / 1000));
  let settingsTabOpen = false;
  let settingsTimer = null;
  let settingsRows = [];

  function mkEl(tag, id, className) {
    const el = document.createElement(tag);
    if (id) el.id = id;
    if (className) el.className = className;
    return el;
  }
  function mkInput(id, placeholder) {
    const el = mkEl('input', id, '');
    el.placeholder = placeholder;
    el.maxLength = 260;
    return el;
  }
  function mkButton(id, text, ghost) {
    const el = mkEl('button', id, ghost ? 'ghost' : '');
    el.textContent = text;
    return el;
  }
  function mkHint(id, text) {
    const el = mkEl('div', id, 'hint');
    el.textContent = text;
    return el;
  }

  const settingsPage = mkEl('div', 'dshLpPageSettings', '');
  settingsPage.style.display = 'none';
  const setHead = mkHint('dshLpSetHead', LT('panel.settings.head'));
  // 界面语言：三个选项的文字**本身就是语言名**（中文 / English / 自动），所以它们可以硬编码；
  // 标签与提示仍全部走词表。
  const LANG_OPTIONS = [['zh', '中文'], ['en', 'English'], ['auto', '自动 / Auto']];
  const setLangLabel = mkEl('label', '', '');
  setLangLabel.textContent = LT('panel.settings.uiLang');
  const setLang = mkEl('select', 'dshLpSetLang', '');
  for (const pair of LANG_OPTIONS) {
    const opt = document.createElement('option');
    opt.value = pair[0];
    opt.textContent = pair[1];
    setLang.appendChild(opt);
  }
  setLang.value = 'auto';
  const setDefaultLabel = mkEl('label', '', '');
  setDefaultLabel.textContent = LT('panel.settings.defaultWorkspace');
  const setDefault = mkEl('select', 'dshLpSetDefault', '');
  const setMaxLabel = mkEl('label', '', '');
  setMaxLabel.textContent = LT('panel.settings.maxPermission');
  const setMax = mkEl('select', 'dshLpSetMaxPerm', '');
  const setWsLabel = mkEl('label', '', '');
  setWsLabel.textContent = LT('panel.settings.workspaces');
  const setList = mkEl('div', 'dshLpSetList', '');
  const setNewLabel = mkEl('label', '', '');
  setNewLabel.textContent = LT('panel.settings.newWorkspace');
  const setNewId = mkInput('dshLpSetNewId', LT('panel.settings.idPlaceholder'));
  const setNewName = mkInput('dshLpSetNewName', LT('panel.settings.namePlaceholder'));
  const setNewPath = mkInput('dshLpSetNewPath', LT('panel.settings.pathPlaceholder'));
  const setAdd = mkButton('dshLpSetAdd', LT('panel.settings.add'), true);
  const setSave = mkButton('dshLpSetSave', LT('panel.settings.save'), false);
  const setPendingLabel = mkEl('label', '', '');
  setPendingLabel.textContent = LT('panel.settings.pending');
  const setPending = mkEl('div', 'dshLpSetPending', '');
  settingsPage.appendChild(setHead);
  settingsPage.appendChild(setLangLabel);
  settingsPage.appendChild(setLang);
  settingsPage.appendChild(setDefaultLabel);
  settingsPage.appendChild(setDefault);
  settingsPage.appendChild(setMaxLabel);
  settingsPage.appendChild(setMax);
  settingsPage.appendChild(setWsLabel);
  settingsPage.appendChild(setList);
  settingsPage.appendChild(setNewLabel);
  settingsPage.appendChild(setNewId);
  settingsPage.appendChild(setNewName);
  settingsPage.appendChild(setNewPath);
  settingsPage.appendChild(setAdd);
  settingsPage.appendChild(setSave);
  settingsPage.appendChild(setPendingLabel);
  settingsPage.appendChild(setPending);
  panel.appendChild(settingsPage);

  const permRankOf = (level) => PERMS.indexOf(String(level == null ? '' : level));

  function paintDefaultSelect(current) {
    setDefault.innerHTML = '';
    for (const row of settingsRows) {
      const opt = document.createElement('option');
      opt.value = row.id;
      opt.textContent = row.name || row.id;
      setDefault.appendChild(opt);
    }
    const wanted = current == null ? String(setDefault.value || '') : String(current);
    const picked = settingsRows.some((row) => row.id === wanted)
      ? wanted
      : (settingsRows.length ? settingsRows[0].id : '');
    setDefault.value = picked;
  }

  function syncRowValues() {
    for (const row of settingsRows) {
      if (row.nameInput) row.name = String(row.nameInput.value == null ? '' : row.nameInput.value);
      if (row.pathInput) row.path = String(row.pathInput.value == null ? '' : row.pathInput.value);
    }
  }

  function paintRows() {
    const current = String(setDefault.value || '');
    setList.innerHTML = '';
    if (settingsRows.length === 0) {
      setList.appendChild(mkHint('', LT('panel.settings.empty')));
      paintDefaultSelect('');
      return;
    }
    for (const row of settingsRows) {
      const line = mkEl('div', 'dshLpWs-' + row.id, 'wsrow');
      const idText = mkEl('span', '', 'wsid');
      // id 是协议里的标识，原样显示；改名不改 id（改 id 等于换掉一个工作区）。
      idText.textContent = row.id;
      const nameInput = mkInput('', LT('panel.settings.namePlaceholder'));
      nameInput.value = row.name;
      const pathInput = mkInput('', LT('panel.settings.pathPlaceholder'));
      pathInput.value = row.path;
      row.nameInput = nameInput;
      row.pathInput = pathInput;
      const del = mkButton('', LT('panel.settings.remove'), true);
      del.onclick = () => {
        syncRowValues();
        settingsRows = settingsRows.filter((item) => item !== row);
        paintRows();
      };
      line.appendChild(idText);
      line.appendChild(nameInput);
      line.appendChild(pathInput);
      line.appendChild(del);
      setList.appendChild(line);
    }
    paintDefaultSelect(current);
  }

  function renderSettings(view) {
    const prefs = view && typeof view === 'object' ? view : {};
    const list = Array.isArray(prefs.workspaces) ? prefs.workspaces : [];
    settingsRows = list.map((ws) => ({
      id: String(ws && ws.id ? ws.id : ''),
      name: String(ws && ws.name ? ws.name : ''),
      path: String(ws && ws.path ? ws.path : ''),
      nameInput: null,
      pathInput: null,
    }));
    const level = permRankOf(prefs.maxPermission) < 0 ? 'workspace-write' : String(prefs.maxPermission);
    setMax.innerHTML = '';
    for (const one of PERMS) {
      const opt = document.createElement('option');
      opt.value = one;
      opt.textContent = one;
      setMax.appendChild(opt);
    }
    setMax.value = level;
    paintRows();
    const wanted = String(prefs.defaultWorkspaceId || '');
    if (wanted !== '' && settingsRows.some((row) => row.id === wanted)) setDefault.value = wanted;
  }

  setAdd.onclick = () => {
    msg('');
    const id = String(setNewId.value == null ? '' : setNewId.value).trim();
    const name = String(setNewName.value == null ? '' : setNewName.value).trim();
    const dir = String(setNewPath.value == null ? '' : setNewPath.value).trim();
    if (id === '') { msg(LT('panel.settings.badId')); return; }
    if (dir === '') { msg(LT('panel.settings.badPath')); return; }
    syncRowValues();
    const wanted = String(setDefault.value || '');
    settingsRows.push({ id, name: name === '' ? id : name, path: dir, nameInput: null, pathInput: null });
    setNewId.value = '';
    setNewName.value = '';
    setNewPath.value = '';
    paintRows();
    paintDefaultSelect(wanted);
  };

  async function saveSettings() {
    msg('');
    syncRowValues();
    let out;
    try {
      out = await api('dispatch/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          defaultWorkspaceId: String(setDefault.value || ''),
          maxPermission: String(setMax.value || ''),
          workspaces: settingsRows.map((row) => ({ id: row.id, name: row.name, path: row.path })),
        }),
      });
    } catch (error) {
      // 校验失败回 400 + 稳定 reason（正文给用户看，不自己改配置）；带上当前有效值时重画。
      msg(String((error && error.message) || error));
      const body = error && error.body ? error.body : null;
      if (body && Array.isArray(body.workspaces)) renderSettings(body);
      return;
    }
    renderSettings(out);
    msg(LT('panel.settings.saved'));
  }
  setSave.onclick = () => { saveSettings(); };

  /** 语言下拉：选完就落盘（POST lang），成功再提示 + 刷新；失败如实回显，不改选中项。 */
  async function saveLang() {
    msg('');
    const wanted = String(setLang.value || 'auto');
    try {
      const out = await api('lang', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ lang: wanted }),
      });
      if (!out || out.ok !== true) {
        msg(LT('panel.settings.langFailed', { text: String((out && out.error) || 'unknown') }));
        return;
      }
      // 已落盘：先说一句，再自动刷新一次（桌面窗口里没有 location 时只是不刷新，不报错）。
      msg(LT('panel.settings.langSaved'));
      setTimeout(() => {
        try {
          if (typeof location !== 'undefined' && location && typeof location.reload === 'function') location.reload();
        } catch (error) { /* 没有 location 的宿主：留给用户手动刷新 */ }
      }, 400);
    } catch (error) {
      msg(LT('panel.settings.langFailed', { text: String((error && error.message) || error) }));
    }
  }
  setLang.onchange = () => { saveLang(); };

  /** 打开设置页时把当前点选值读回来；读不到就保持默认 auto（这是偏好，不是必须成功的读取）。 */
  async function loadLang() {
    try {
      const out = await api('lang');
      const picked = String((out && out.lang) || 'auto');
      if (LANG_OPTIONS.some((pair) => pair[0] === picked)) setLang.value = picked;
    } catch (error) { /* 拿不到就保持当前选中项 */ }
  }

  function renderPending(items) {
    setPending.innerHTML = '';
    const list = Array.isArray(items) ? items : [];
    if (list.length === 0) {
      setPending.appendChild(mkHint('', LT('panel.settings.pendingEmpty')));
      return;
    }
    for (const item of list) {
      const approvalId = String((item && item.approvalId) || '');
      const row = mkEl('div', 'dshLpPend-' + approvalId, 'pending');
      const who = mkEl('span', '', 'pfrom');
      // 来源优先用 peers.json 里的名字（管理接口查好的 fromName）；没有就退回 peerId 前 8 位。
      // 任何情况下都不显示路径 —— 待批准记录里本来就没有 path。
      const fromName = String((item && item.fromName) || '');
      who.textContent = LT('panel.settings.from', {
        name: fromName !== '' ? fromName : String((item && item.from) || '').slice(0, 8),
      });
      const what = mkEl('span', '', 'pwhat');
      what.textContent = String((item && item.workspaceName) || (item && item.workspaceId) || '')
        + ' · ' + String((item && item.permission) || '');
      const left = mkEl('span', '', 'pleft');
      left.textContent = LT('panel.settings.remaining', {
        sec: secondsOf(Number(item && item.expiresAt) - Date.now()),
      });
      const ok = mkButton('', LT('panel.settings.approve'), false);
      ok.onclick = () => { decidePending('approve', approvalId); };
      const no = mkButton('', LT('panel.settings.reject'), true);
      no.onclick = () => { decidePending('reject', approvalId); };
      row.appendChild(who);
      row.appendChild(what);
      row.appendChild(left);
      row.appendChild(ok);
      row.appendChild(no);
      setPending.appendChild(row);
    }
  }

  async function decidePending(action, approvalId) {
    if (approvalId === '') return;
    msg('');
    try {
      const out = await api('dispatch/' + action, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: approvalId }),
      });
      const state = String((out && out.state) || '');
      const key = action === 'approve' ? 'panel.settings.approved' : 'panel.settings.rejected';
      msg(LT(key) + (state === '' ? '' : ' ' + state));
    } catch (error) {
      msg(String((error && error.message) || error));
    }
    loadPending();
  }

  async function loadPending() {
    try {
      const out = await api('dispatch/pending');
      renderPending(out && Array.isArray(out.items) ? out.items : []);
    } catch (error) {
      if (!(error && error.status === 501)) msg(String((error && error.message) || error));
    }
  }

  async function loadSettings() {
    await loadLang();
    try {
      renderSettings(await api('dispatch/settings'));
    } catch (error) {
      // 门面未接线（待 H1）时如实说明，而不是画一个空清单骗人。
      if (error && error.status === 501) msg(LT('panel.settings.unsupported'));
      else msg(String((error && error.message) || error));
    }
    await loadPending();
  }

  function stopSettingsPoll() {
    if (settingsTimer) { clearInterval(settingsTimer); settingsTimer = null; }
  }
  function startSettingsPoll() {
    stopSettingsPoll();
    settingsTimer = setInterval(pollSettings, SETTINGS_POLL_MS);
  }
  function pollSettings() {
    if (!settingsTabOpen) return;
    if (document.hidden === true) return;
    loadPending();
  }
  async function openSettingsPage() {
    msg('');
    await loadSettings();
    startSettingsPoll();
  }

  // -------------------------------------------------------------------------
  // v0.8.5-α 私聊「⚙ 派单设置」弹层（契约 §6，Lane H2）
  // 工作区来自对端 options（只有 id 与 name）；权限三档里超过对端上限的**置灰并写明原因**
  // （不允许「选了才报错」）。默认 = 对端 defaultWorkspaceId + workspace-write。
  // 铁律：这里绝不显示 path（对端不会给，本机也不问）。
  // -------------------------------------------------------------------------
  const APPROVAL_POLL_MS = 1000;
  let dmDispatchOpen = false;
  let dmPeerOptions = null;
  let dmApproval = null;
  let dmApprovalTimer = null;

  const dmDispatchBtn = mkButton('dshLpDmDispatch', LT('panel.dispatch.button'), true);
  const dmDialog = mkEl('div', 'dshLpDmDialog', '');
  dmDialog.style.display = 'none';
  const dmDialogTitle = mkHint('dshLpDmDialogTitle', LT('panel.dispatch.title'));
  const dmWsLabel = mkEl('label', '', '');
  dmWsLabel.textContent = LT('panel.dispatch.workspace');
  const dmWs = mkEl('select', 'dshLpDmWs', '');
  const dmPermLabel = mkEl('label', '', '');
  dmPermLabel.textContent = LT('panel.dispatch.permission');
  const dmPerm = mkEl('select', 'dshLpDmPerm', '');
  const dmDialogHint = mkHint('dshLpDmDialogHint', LT('panel.dispatch.hint'));
  const dmDialogClose = mkButton('dshLpDmDialogClose', LT('panel.dispatch.close'), true);
  dmDialog.appendChild(dmDialogTitle);
  dmDialog.appendChild(dmWsLabel);
  dmDialog.appendChild(dmWs);
  dmDialog.appendChild(dmPermLabel);
  dmDialog.appendChild(dmPerm);
  dmDialog.appendChild(dmDialogHint);
  dmDialog.appendChild(dmDialogClose);
  dmPage.appendChild(dmDispatchBtn);
  dmPage.appendChild(dmDialog);

  /** 弹层：工作区下拉（对端 options）+ 权限三档（超上限置灰）。 */
  function renderDispatchDialog() {
    const opts = dmPeerOptions && typeof dmPeerOptions === 'object' ? dmPeerOptions : null;
    const workspaces = opts && Array.isArray(opts.workspaces) ? opts.workspaces : [];
    const maxLevel = opts && PERMS.indexOf(String(opts.maxPermission)) >= 0 ? String(opts.maxPermission) : PERMS[0];
    const maxRank = permRankOf(maxLevel);
    dmWs.innerHTML = '';
    if (workspaces.length === 0) {
      const opt = document.createElement('option');
      opt.value = '';
      opt.textContent = LT('panel.dispatch.noWorkspace');
      dmWs.appendChild(opt);
      dmWs.value = '';
    } else {
      for (const ws of workspaces) {
        const opt = document.createElement('option');
        opt.value = String(ws && ws.id ? ws.id : '');
        opt.textContent = String((ws && ws.name) || (ws && ws.id) || '');
        dmWs.appendChild(opt);
      }
      const wanted = String(opts.defaultWorkspaceId || '');
      dmWs.value = wanted !== '' ? wanted : String(workspaces[0] && workspaces[0].id ? workspaces[0].id : '');
    }
    dmPerm.innerHTML = '';
    for (const level of PERMS) {
      const over = permRankOf(level) > maxRank;
      const opt = document.createElement('option');
      opt.value = level;
      // 协议值原样在前；超上限的补一句原因，并 disabled（点了也选不中）。
      opt.textContent = over ? level + ' · ' + LT('panel.dispatch.overLimit', { max: maxLevel }) : level;
      opt.disabled = over;
      dmPerm.appendChild(opt);
    }
    // 契约 §6：默认 workspace-write；它超过对端上限时退到上限那一档（不越权默认）。
    dmPerm.value = permRankOf('workspace-write') <= maxRank ? 'workspace-write' : maxLevel;
  }

  dmDialogClose.onclick = () => {
    dmDispatchOpen = false;
    dmDialog.style.display = 'none';
  };

  dmDispatchBtn.onclick = async () => {
    if (dmDispatchOpen) {
      dmDispatchOpen = false;
      dmDialog.style.display = 'none';
      return;
    }
    if (dmPeerId === '') { msg(LT('panel.dm.pickFirst')); return; }
    msg('');
    try {
      dmPeerOptions = await api('dispatch/options?peer=' + encodeURIComponent(dmPeerId));
    } catch (error) {
      dmPeerOptions = null;
      dmDialog.style.display = 'none';
      dmDispatchOpen = false;
      msg(LT('panel.dispatch.loadFailed', { text: String((error && error.message) || error) }));
      return;
    }
    dmDispatchOpen = true;
    dmDialog.style.display = 'block';
    renderDispatchDialog();
  };

  /** 这次发送点名的工作区与权限：没打开弹层就一个字段都不带（契约 §2 的「都不传」）。 */
  function dmScopeNow() {
    if (!dmDispatchOpen) return null;
    const workspaceId = String(dmWs.value == null ? '' : dmWs.value).trim();
    const permission = String(dmPerm.value == null ? '' : dmPerm.value).trim();
    if (workspaceId === '' && permission === '') return null;
    return { workspaceId, permission };
  }

  function dmStampText(row) {
    if (row.state === 'sending') return LT('panel.dm.sending');
    if (row.state === 'pending-approval') return LT('panel.dm.waitingApproval');
    if (row.state === 'approval-approved') return LT('panel.dm.approvalApproved');
    if (row.state === 'approval-rejected') return LT('panel.dm.approvalRejected');
    if (row.state === 'approval-expired') return LT('panel.dm.approvalExpired');
    return clockText(row.ts);
  }

  function stopApprovalPoll() {
    if (dmApprovalTimer) { clearInterval(dmApprovalTimer); dmApprovalTimer = null; }
  }
  function startApprovalPoll() {
    stopApprovalPoll();
    dmApprovalTimer = setInterval(pollApproval, APPROVAL_POLL_MS);
  }

  /** 把这条气泡钉到一个终态：停轮询、改 stamp、重画（正文永远来自用户自己打的那条）。 */
  function settleApproval(rowId, state) {
    stopApprovalPoll();
    dmApproval = null;
    const row = dmLocal.get(rowId) || dmRows.filter((item) => item.id === rowId)[0];
    if (row) row.state = state;
    renderDmMessages();
  }

  /** 批准之后回复要等对端跑完：先 sync 一次再拉历史，气泡区自然长出那条回复。 */
  function syncDmAfterApproval() {
    if (dmPeerId === '') return;
    api('dm/sync', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ peerId: dmPeerId }),
    }).then(() => loadDmMessages()).catch(() => {});
  }

  async function pollApproval() {
    if (!dmApproval) { stopApprovalPoll(); return; }
    if (document.hidden === true) return;
    const rowId = dmApproval.rowId;
    const expiresAt = Number(dmApproval.expiresAt);
    // 本地兜底：对端 10 分钟没处理就是 expired（不靠对端一定回话）。
    if (expiresAt > 0 && Date.now() > expiresAt) {
      settleApproval(rowId, 'approval-expired');
      return;
    }
    let out;
    try {
      out = await api('dispatch/approval?id=' + encodeURIComponent(dmApproval.approvalId)
        + '&peer=' + encodeURIComponent(dmApproval.peerId));
    } catch (error) {
      msg(String((error && error.message) || error));
      return;
    }
    const state = String((out && out.state) || 'pending');
    if (state === 'approved') { settleApproval(rowId, 'approval-approved'); syncDmAfterApproval(); return; }
    if (state === 'rejected') { settleApproval(rowId, 'approval-rejected'); return; }
    if (state === 'expired') { settleApproval(rowId, 'approval-expired'); }
  }

  function setTab(which) {
    const isGroup = which === 'group';
    const isDm = which === 'dm';
    const isSettings = which === 'settings';
    groupTabOpen = isGroup;
    dmTabOpen = isDm;
    settingsTabOpen = isSettings;
    $('dshLpPagePeers').style.display = isGroup || isDm || isSettings ? 'none' : 'block';
    $('dshLpPageGroup').style.display = isGroup ? 'block' : 'none';
    dmPage.style.display = isDm ? 'block' : 'none';
    settingsPage.style.display = isSettings ? 'block' : 'none';
    $('dshLpTabPeers').className = isGroup || isDm || isSettings ? 'ghost tab' : 'ghost tab on';
    $('dshLpTabGroup').className = isGroup ? 'ghost tab on' : 'ghost tab';
    $('dshLpTabDm').className = isDm ? 'ghost tab on' : 'ghost tab';
    $('dshLpTabSettings').className = isSettings ? 'ghost tab on' : 'ghost tab';
    stopGroupPoll();
    // 私聊有自己的 1s 节拍：切页先把它停掉，只有私聊页才重新起。
    stopDmPoll();
    stopSettingsPoll();
    if (isSettings) {
      openSettingsPage();
      return;
    }
    if (isDm) {
      openDmPage();
      return;
    }
    if (!isGroup) return;
    // 气泡靠右全靠本机 peerId：万一面板打开时那次 state 还没回来，进页面补一次
    // （一次性，不开新节拍；群组的 2s 节拍仍只打 GET group）。
    if (selfPeerId === '') refresh();
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
      ? LT('panel.group.joinAskHub', { name: name })
      : LT('panel.group.joinAskSelf', { name: name });
    if (typeof window.confirm === 'function' && window.confirm(question) !== true) return;
    try {
      if (isHub) {
        await groupAction('group/member', { peerId: peerId, action: 'add' }, LT('panel.group.addedToGroup', { name: name }));
      } else {
        const out = await groupAction('group/join', {}, '');
        const epoch = seqOrNull(out && out.epoch);
        msg(epoch === null ? LT('panel.group.joined') : LT('panel.group.joinedWithEpoch', { epoch: epoch }));
      }
      if (groupTabOpen) pollGroup();
    } catch (error) {
      const reason = String((error && error.message) || error);
      if (isHub) {
        msg(LT('panel.group.joinFailedWith', { reason: reason }));
      } else {
        msg(LT('panel.group.joinFailedWith', { reason: reason })
          + (/not-a-member|403/.test(reason) ? LT('panel.group.joinAutoJoinHint') : ''));
      }
    }
  }

  async function removeMember(member, button) {
    const label = String((member && (member.name || member.peerId)) || '');
    if (typeof window.confirm === 'function' && !window.confirm(LT('panel.group.removeConfirm', { label: label }))) return;
    if (button) button.disabled = true;
    try {
      await groupAction('group/member', { peerId: member.peerId, action: 'remove' }, LT('panel.group.removed', { label: label }));
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
      && !window.confirm(LT('panel.group.claimConfirm'))) return;
    if (button) button.disabled = true;
    try {
      const out = await groupAction('group/leader', { action: 'claim' });
      if (out && out.ok === true) {
        const epoch = seqOrNull(out.epoch);
        msg(LT('panel.group.claimed', { role: String(out.role || 'leader') })
          + (epoch === null ? '' : LT('panel.group.epochSuffix', { epoch: epoch })));
        pollGroup();
      } else {
        msg(LT('panel.group.claimFailed', { reason: String((out && out.reason) || LT('panel.common.unknownReason')) }));
      }
    } catch (error) {
      msg(String(error.message || error));
    } finally {
      if (button) button.disabled = false;
    }
  }

  // -------------------------------------------------------------------------
  // 接收侧进度：GET files 的 incoming 桶（传输中的 .part 实际大小）。
  // 面板打开期间每 1s 打一次（与 dispatch 作业同一个节拍）；拿不到就保持上一行，不打扰。
  // 铁律：只有 textContent，没有任何 innerHTML/反引号；文件名来自对端，绝不拼进 DOM 结构。
  // -------------------------------------------------------------------------
  let filesTimer = null;
  function renderIncoming(rows) {
    const box = $('dshLpIncoming');
    const list = Array.isArray(rows) ? rows : [];
    if (list.length === 0) { box.textContent = ''; return; }
    const row = list[0];
    const size = Number(row.size) || 0;
    const received = Number(row.received) || 0;
    const pct = size > 0 ? Math.max(0, Math.min(100, Math.round((received / size) * 100))) : 0;
    box.textContent = LT('panel.files.incoming', {
      received: sizeText(received),
      size: sizeText(size),
      pct,
    }) + (list.length > 1 ? '  +' + (list.length - 1) : '');
  }
  async function pollIncoming() {
    if (document.hidden === true) return;
    try {
      const out = await api('files');
      renderIncoming(out && Array.isArray(out.incoming) ? out.incoming : []);
    } catch (error) {
      // 门面未接线（501）或暂时读不到：不清空上一行，也不报错。
    }
  }

  btn.onclick = () => {
    if (skipClick) { skipClick = false; return; }
    const open = panel.style.display === 'block';
    panel.style.display = open ? 'none' : 'block';
    clearInterval(jobsTimer);
    clearInterval(filesTimer);
    stopGroupPoll();
    stopDmPoll();
    stopSettingsPoll();
    if (!open) {
      placePanel();
      refresh();
      jobsTimer = setInterval(pollJobs, 1000);
      pollIncoming();
      filesTimer = setInterval(pollIncoming, 1000);
      if (groupTabOpen) {
        pollGroup();
        startGroupPoll();
      }
      if (dmTabOpen) {
        pollDm();
        startDmPoll();
      }
      if (settingsTabOpen) {
        pollSettings();
        startSettingsPoll();
      }
    }
  };
  $('dshLpSaveName').onclick = async () => {
    msg('');
    try {
      await api('name', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: $('dshLpName').value }) });
      msg(LT('panel.peers.nameSaved'));
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
      msg(LT('panel.peers.codeShown'));
    } catch (error) { msg(String(error.message || error)); }
  };
  $('dshLpPair').onclick = async () => {
    msg(LT('panel.peers.pairing'));
    try {
      const out = await api('pair', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: $('dshLpUrl').value, peerName: $('dshLpPeerName').value, code: $('dshLpPairCode').value }),
      });
      msg(LT('panel.peers.paired', { name: out.peer.name }));
      $('dshLpUrl').value = ''; $('dshLpPeerName').value = ''; $('dshLpPairCode').value = '';
      refresh();
      await askJoinGroup(out.peer);
    } catch (error) { msg(String(error.message || error)); }
  };

  $('dshLpTabPeers').onclick = () => setTab('peers');
  $('dshLpTabGroup').onclick = () => setTab('group');
  $('dshLpTabDm').onclick = () => setTab('dm');
  $('dshLpTabSettings').onclick = () => setTab('settings');
  dmSendBtn.onclick = () => sendDm();
  dmInput.addEventListener('keydown', (ev) => {
    if (ev && ev.key === 'Enter' && ev.shiftKey !== true) sendDm();
  });
  async function sendGroupMessage() {
    const input = $('dshLpGroupText');
    const text = String(input.value || '');
    if (text.trim() === '') { msg(LT('panel.group.msgEmpty')); return; }
    msg(LT('panel.group.sending'));
    // 契约 §3：弹层里显式选定了目标才带这三个字段；弹层没开就是一个键都不带
    // （纯文本 @!目标 任务 语法照旧，请求体与 0.8.4 逐字一致）。
    const scope = groupScopeNow();
    try {
      const out = await groupAction('group/post', {
        kind: 'chat',
        text: text,
        ...(scope ? scope : {}),
      }, LT('panel.group.sent'));
      input.value = '';
      // 契约 §1/§5：正文带 @!X 时作者侧已自动派单，摘要只写 msg 区（群历史里由 host 写状态摘要）。
      // skipped 表示这条消息没有派单目标 —— 说成「已派单」就是谎报，所以按三态分开说。
      const dispatch = out && out.dispatch && typeof out.dispatch === 'object' ? out.dispatch : null;
      if (dispatch && dispatch.status !== 'skipped') msg(LT('panel.group.sentWith', { text: dispatchSummaryText(dispatch) }));
      pollGroup();
    } catch (error) { msg(String(error.message || error)); }
  }
  // 输入框 + 发送按钮的口径与私聊页一致：回车发送、Shift+Enter 换行。
  $('dshLpGroupSend').onclick = () => { sendGroupMessage(); };
  $('dshLpGroupText').addEventListener('keydown', (ev) => {
    if (ev && ev.key === 'Enter' && ev.shiftKey !== true) sendGroupMessage();
  });
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
      msg(LT('panel.group.acceptButton', {
        state: applied ? LT('panel.group.acceptOn') : LT('panel.group.acceptOff'),
      }) + (out && out.persisted === false ? LT('panel.group.acceptLocalOnly') : ''));
      pollGroup();
    } catch (error) {
      msg(LT('panel.group.acceptFailed', { text: String(error.message || error) }));
    }
  };
  $('dshLpGroupAdd').onclick = async () => {
    const input = $('dshLpGroupAddId');
    const peerId = String(input.value || '').trim();
    if (peerId === '') { msg(LT('panel.group.addMemberMissingId')); return; }
    try {
      await groupAction('group/member', { peerId: peerId, action: 'add' }, LT('panel.group.memberAdded'));
      input.value = '';
      pollGroup();
    } catch (error) { msg(String(error.message || error)); }
  };
  $('dshLpGroupSaveName').onclick = async () => {
    const name = String($('dshLpGroupName').value || '').trim();
    if (name === '') { msg(LT('panel.group.nameEmpty')); return; }
    renderNameConflicts([]);
    try {
      await groupAction('group/config', { name: name }, LT('panel.group.nameSaved'));
      pollGroup();
    } catch (error) {
      // 契约 §6：409 name-taken 时群名不变，把冲突清单摊开给用户看（伙伴名 + 群名 + id 前缀）。
      const body = error && error.body ? error.body : null;
      if (error && error.status === 409 && body && body.error === 'name-taken') {
        renderNameConflicts(body.conflicts);
        msg(LT('panel.group.nameTaken'));
        return;
      }
      msg(String(error.message || error));
    }
  };
  $('dshLpGroupFind').onclick = async () => {
    const name = String($('dshLpGroupFindName').value || '').trim();
    if (name === '') { msg(LT('panel.group.findNeedName')); return; }
    msg(LT('panel.group.finding'));
    try {
      const out = await api('group/lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name }),
      });
      const matches = Array.isArray(out && out.matches) ? out.matches : [];
      renderFindResults(matches);
      if (matches.length === 0) msg(LT('panel.group.findNone'));
      else if (matches.length > 1) msg(LT('panel.group.findMulti', { count: matches.length }));
      else msg('');
    } catch (error) { msg(LT('panel.group.findFailed', { text: String(error.message || error) })); }
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
      hint.textContent = LT('panel.group.advertiseResult', {
        targets: isFinite(targets) ? targets : 0,
        sent: isFinite(sent) ? sent : 0,
      });
      msg(LT('panel.group.advertiseSent'));
    } catch (error) { msg(LT('panel.group.advertiseFailed', { text: String(error.message || error) })); }
  };
  $('dshLpGroupClaim').onclick = () => claimLeader();
  $('dshLpGroupJoin').onclick = async () => {
    try {
      await groupAction('group/join', {}, LT('panel.group.joined'));
      pollGroup();
    } catch (error) { msg(String(error.message || error)); }
  };
  window.addEventListener('visibilitychange', () => {
    if (document.hidden === true) { stopGroupPoll(); stopDmPoll(); stopSettingsPoll(); return; }
    if (groupTabOpen) {
      pollGroup();
      startGroupPoll();
    }
    if (dmTabOpen) {
      pollDm();
      startDmPoll();
    }
    if (settingsTabOpen) {
      pollSettings();
      startSettingsPoll();
    }
  });
})();
`;

// 活绑定：createAdmin 解析出实例 token 后会重渲染（见那里的注释）。
export let PANEL_SCRIPT = renderPanelScript(PROCESS_ADMIN_TOKEN);
