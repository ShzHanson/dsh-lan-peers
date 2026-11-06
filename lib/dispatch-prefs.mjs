/**
 * dsh-lan-peers · 派单设置与待批准队列（0.8.5-α 契约 §1/§3）
 * =====================================================
 * 两个本地文件，零依赖：
 *
 *   <stateDir>/dispatch-prefs.json    接收方设置（id/名字/本机路径/上限）—— **永不外发路径**
 *   <stateDir>/dispatch-pending.json  待批准队列（**绝不存正文**，只存字节数）
 *
 * 铁律（契约 §0）：
 *   - 工作区只以 id + name 对外标识；path 只在本机视图（prefs()）里出现；
 *   - 权限三档只降不升：请求档 > maxPermission 直接拒，请求档 > 默认档但 ≤ 上限才进确认流程。
 *
 * 这两个文件都是 0600 原子写（先写 .tmp 再 rename），与 state.json / peers.json 同一套写法。
 */
import { randomBytes, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

/** 权限三档：顺序即档位高低（契约 §1） */
export const PERMISSION_LEVELS = Object.freeze(['read-only', 'workspace-write', 'danger-full-access']);

export const DISPATCH_PREFS_FILE = 'dispatch-prefs.json';
export const DISPATCH_PENDING_FILE = 'dispatch-pending.json';

/** 缺省值（契约 §1）：没有 dispatch-prefs.json 时生效 */
export const DISPATCH_DEFAULT_WORKSPACE_ID = 'main';
export const DISPATCH_DEFAULT_WORKSPACE_NAME = '主工作区';
export const DISPATCH_DEFAULT_MAX_PERMISSION = 'workspace-write';

/** 待批准 TTL（契约 §3：10 分钟） */
export const DISPATCH_PENDING_TTL_MS = 10 * 60 * 1000;

/** 队列条数上限：一批对端狂发也不该把内存/文件堆爆（超了丢最早的已决条目） */
export const DISPATCH_PENDING_MAX_RECORDS = 200;

/** 定时清理间隔（与 fileStore 的定时器同一量级） */
export const DISPATCH_PENDING_PRUNE_MS = 30_000;

/** id / name 的长度与字符上限（id 会进协议与文件名，先压住可用字符） */
const ID_MAX = 64;
const NAME_MAX = 64;
const BAD_ID_CHARS = /[\u0000-\u001f/\\]/;

/** 档位序号；非法值一律 -1（调用方据此判 400/403，不靠抛错） */
export function permissionRank(value) {
  return PERMISSION_LEVELS.indexOf(String(value ?? ''));
}

export function isPermission(value) {
  return permissionRank(value) >= 0;
}

/** ~ 展开（与 host/server.mjs 的 expandHome 同口径，不引依赖） */
function expandHome(value) {
  const text = String(value ?? '');
  if (text === '~') return process.env.HOME || process.env.USERPROFILE || text;
  if (text.startsWith('~/') || text.startsWith('~\\')) {
    const home = process.env.HOME || process.env.USERPROFILE;
    return home ? path.join(home, text.slice(2)) : text;
  }
  return text;
}

/** 0600 原子写（与 state.json 同一套：目录 0700，文件 0600） */
function writeJson0600(file, value) {
  const dir = path.dirname(file);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  try {
    fs.chmodSync(dir, 0o700);
  } catch {
    /* 目录权限尽力而为，不阻塞主流程 */
  }
  const tmp = `${file}.tmp-${process.pid}-${randomBytes(4).toString('hex')}`;
  fs.writeFileSync(tmp, `${JSON.stringify(value, null, 2)}
`, { mode: 0o600 });
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
    return null;
  }
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// 设置：<stateDir>/dispatch-prefs.json
// ---------------------------------------------------------------------------

export class DispatchPrefs {
  #stateDir;
  #workspace;
  #now;
  #logger;

  /**
   * @param {object} options
   *   stateDir  —— 状态目录（必填）
   *   workspace —— 缺省工作区路径（默认 <stateDir>/workspace，与 config.workspace 同源）
   *   now       —— 取时函数（测试注入假时钟）
   *   logger    —— 可选日志（只记非法输入的种类，不记 path）
   */
  constructor({ stateDir, workspace, now = Date.now, logger = null } = {}) {
    const dir = expandHome(stateDir);
    if (typeof dir !== 'string' || dir === '') throw new TypeError('DispatchPrefs needs stateDir');
    this.#stateDir = path.resolve(dir);
    const ws = expandHome(workspace);
    this.#workspace = typeof ws === 'string' && ws !== '' ? path.resolve(ws) : path.join(this.#stateDir, 'workspace');
    this.#now = typeof now === 'function' ? now : Date.now;
    this.#logger = typeof logger === 'function' ? logger : null;
  }

  get stateDir() {
    return this.#stateDir;
  }

  /** 设置文件绝对路径（测试与排障用） */
  get file() {
    return path.join(this.#stateDir, DISPATCH_PREFS_FILE);
  }

  /** 缺省工作区路径（本机视角，永不外发） */
  get workspace() {
    return this.#workspace;
  }

  /** 契约 §1 缺省值：id=main / 名字=主工作区 / 上限=workspace-write */
  defaults() {
    return {
      defaultWorkspaceId: DISPATCH_DEFAULT_WORKSPACE_ID,
      maxPermission: DISPATCH_DEFAULT_MAX_PERMISSION,
      workspaces: [{
        id: DISPATCH_DEFAULT_WORKSPACE_ID,
        name: DISPATCH_DEFAULT_WORKSPACE_NAME,
        path: this.#workspace,
      }],
    };
  }

  /** 本机视图（含 path）：契约 §4 的 server.dispatch.prefs() */
  get() {
    const stored = readJsonFile(this.file);
    if (stored === null) return this.defaults();
    const normalized = this.#normalize(stored);
    if (normalized.ok !== true) {
      // 文件被手改坏：回落缺省值，不抛错（否则热重载会直接起不来）
      if (this.#logger) this.#logger('[dispatch] prefs invalid reason=' + normalized.reason + ' fallback=defaults');
      return this.defaults();
    }
    return normalized.value;
  }

  /** 对外视图（只有 id/name）：契约 §2 的 GET /v1/dispatch/options */
  options() {
    const prefs = this.get();
    return {
      defaultWorkspaceId: prefs.defaultWorkspaceId,
      maxPermission: prefs.maxPermission,
      workspaces: prefs.workspaces.map((entry) => ({ id: entry.id, name: entry.name })),
    };
  }

  /** id -> 设置条目（含 path）；未知 id 返回 null */
  workspace(workspaceId) {
    const id = String(workspaceId ?? '');
    return this.get().workspaces.find((entry) => entry.id === id) ?? null;
  }

  /**
   * 保存（契约 §4：savePrefs(patch) → 同形状）。
   * 校验：id 唯一、path 存在且是目录、maxPermission 合法、defaultWorkspaceId 指向存在的 id。
   * 非法输入**不写盘**：返回 { ok:false, reason, ...当前有效值 }，调用方据此回 400。
   */
  save(patch) {
    const current = this.get();
    const next = {
      defaultWorkspaceId: current.defaultWorkspaceId,
      maxPermission: current.maxPermission,
      workspaces: current.workspaces.map((entry) => ({ ...entry })),
    };
    if (patch != null && typeof patch === 'object' && !Array.isArray(patch)) {
      if (patch.workspaces !== undefined) next.workspaces = patch.workspaces;
      if (patch.maxPermission !== undefined) next.maxPermission = patch.maxPermission;
      if (patch.defaultWorkspaceId !== undefined) next.defaultWorkspaceId = patch.defaultWorkspaceId;
    }
    // 缺省工作区目录按需创建：<stateDir>/workspace 在首次保存前可能还不存在
    // （面板只改一个 maxPermission 也要能存下去，而不是被"路径不存在"挡回来）。
    try {
      fs.mkdirSync(this.#workspace, { recursive: true, mode: 0o700 });
    } catch {
      /* 建不出来就让下面的校验如实回 path-missing */
    }
    const checked = this.#normalize(next);
    if (checked.ok !== true) {
      if (this.#logger) this.#logger('[dispatch] prefs rejected reason=' + checked.reason);
      return { ok: false, reason: checked.reason, ...current };
    }
    writeJson0600(this.file, checked.value);
    if (this.#logger) {
      this.#logger(
        '[dispatch] prefs saved workspaces=' + checked.value.workspaces.length
        + ' max=' + checked.value.maxPermission
        + ' default=' + checked.value.defaultWorkspaceId,
      );
    }
    return checked.value;
  }

  /**
   * 归一并校验。path 只在这里落地：绝对化 + 存在性 + 必须是目录。
   * @returns {{ok:true, value:object} | {ok:false, reason:string}}
   */
  #normalize(value) {
    if (value == null || typeof value !== 'object' || Array.isArray(value)) return { ok: false, reason: 'bad-prefs' };
    const rows = Array.isArray(value.workspaces) ? value.workspaces : null;
    if (!rows || rows.length === 0) return { ok: false, reason: 'bad-workspaces' };
    if (rows.length > DISPATCH_PENDING_MAX_RECORDS) return { ok: false, reason: 'bad-workspaces' };
    const workspaces = [];
    const ids = new Set();
    for (const row of rows) {
      if (row == null || typeof row !== 'object' || Array.isArray(row)) return { ok: false, reason: 'bad-workspaces' };
      const id = typeof row.id === 'string' ? row.id.trim() : '';
      if (id === '' || id.length > ID_MAX || BAD_ID_CHARS.test(id)) return { ok: false, reason: 'bad-id' };
      if (ids.has(id)) return { ok: false, reason: 'duplicate-id' };
      ids.add(id);
      const rawName = typeof row.name === 'string' ? row.name.trim() : '';
      if (rawName.length > NAME_MAX) return { ok: false, reason: 'bad-name' };
      const rawPath = typeof row.path === 'string' ? row.path.trim() : '';
      if (rawPath === '') return { ok: false, reason: 'path-missing' };
      const absolute = path.resolve(expandHome(rawPath));
      let stat;
      try {
        stat = fs.statSync(absolute);
      } catch {
        return { ok: false, reason: 'path-missing' };
      }
      if (!stat.isDirectory()) return { ok: false, reason: 'path-not-dir' };
      workspaces.push({ id, name: rawName === '' ? id : rawName, path: absolute });
    }
    const maxPermission = String(value.maxPermission ?? '');
    if (!isPermission(maxPermission)) return { ok: false, reason: 'bad-permission' };
    const defaultWorkspaceId = typeof value.defaultWorkspaceId === 'string' ? value.defaultWorkspaceId.trim() : '';
    if (!ids.has(defaultWorkspaceId)) return { ok: false, reason: 'bad-default-workspace' };
    return { ok: true, value: { defaultWorkspaceId, maxPermission, workspaces } };
  }
}

// ---------------------------------------------------------------------------
// 待批准队列：<stateDir>/dispatch-pending.json
// ---------------------------------------------------------------------------

/**
 * 一条待批准记录**只有这些字段**（契约 §3）：正文永不落盘，只有 promptBytes。
 * state / sessionId / decidedAt 是决策结果，用于 GET /v1/dispatch/approval 跨重启回答。
 */
const PENDING_FIELDS = Object.freeze([
  'approvalId',
  'from',
  'workspaceId',
  'workspaceName',
  'permission',
  'promptBytes',
  'at',
  'expiresAt',
]);

export class DispatchPending {
  #stateDir;
  #now;
  #ttlMs;
  #logger;
  #timer = null;

  constructor({ stateDir, now = Date.now, ttlMs = DISPATCH_PENDING_TTL_MS, logger = null } = {}) {
    const dir = expandHome(stateDir);
    if (typeof dir !== 'string' || dir === '') throw new TypeError('DispatchPending needs stateDir');
    this.#stateDir = path.resolve(dir);
    this.#now = typeof now === 'function' ? now : Date.now;
    const ttl = Math.floor(Number(ttlMs));
    this.#ttlMs = Number.isFinite(ttl) && ttl > 0 ? ttl : DISPATCH_PENDING_TTL_MS;
    this.#logger = typeof logger === 'function' ? logger : null;
  }

  get file() {
    return path.join(this.#stateDir, DISPATCH_PENDING_FILE);
  }

  get ttlMs() {
    return this.#ttlMs;
  }

  /** 契约 §3：创建一条待批准记录（**不收正文**，只收字节数） */
  create({ from, workspaceId, workspaceName, permission, promptBytes } = {}) {
    const nowMs = this.#now();
    const record = {
      approvalId: randomUUID(),
      from: String(from ?? ''),
      workspaceId: String(workspaceId ?? ''),
      workspaceName: String(workspaceName ?? ''),
      permission: String(permission ?? ''),
      promptBytes: Number.isFinite(Number(promptBytes)) ? Math.max(0, Math.floor(Number(promptBytes))) : 0,
      at: nowMs,
      expiresAt: nowMs + this.#ttlMs,
      state: 'pending',
    };
    const records = this.#load();
    records.push(record);
    this.#store(records);
    return { ...record };
  }

  /** 待批准列表（契约 §4 的 pending()）：只回 state=pending 的，过期的当场清掉 */
  list() {
    const nowMs = this.#now();
    const records = this.#load();
    const { kept, changed } = this.#expire(records, nowMs);
    if (changed) this.#store(kept);
    return kept
      .filter((record) => record.state === 'pending')
      .sort((left, right) => left.at - right.at)
      .map((record) => ({ ...record }));
  }

  /** 全部记录（含已决；面板排障用，不属于冻结面） */
  all() {
    const nowMs = this.#now();
    const records = this.#load();
    const { kept, changed } = this.#expire(records, nowMs);
    if (changed) this.#store(kept);
    return kept.map((record) => ({ ...record }));
  }

  /**
   * 读一条并把 TTL 结算掉：过期即落盘成 expired（契约 §3「超时 → expired 并清理」）。
   * @returns {object|null} 记录（state 已是最新）；未知 id 返回 null
   */
  peek(approvalId) {
    const id = String(approvalId ?? '');
    if (id === '') return null;
    const nowMs = this.#now();
    const records = this.#load();
    const { kept, changed } = this.#expire(records, nowMs);
    if (changed) this.#store(kept);
    const found = kept.find((record) => record.approvalId === id);
    return found ? { ...found } : null;
  }

  /** 'pending' | 'approved' | 'rejected' | 'expired' | 'unknown' */
  state(approvalId) {
    return this.peek(approvalId)?.state ?? 'unknown';
  }

  /** 落地决策；批准时把 sessionId 写回记录（契约 §3 最后一条） */
  settle(approvalId, state, { sessionId } = {}) {
    const id = String(approvalId ?? '');
    const records = this.#load();
    const found = records.find((record) => record.approvalId === id);
    if (!found) return null;
    found.state = String(state ?? '');
    found.decidedAt = this.#now();
    if (typeof sessionId === 'string' && sessionId !== '') found.sessionId = sessionId;
    this.#store(records);
    return { ...found };
  }

  /** 定时清理：过期置 expired，已决且超过一个 TTL 的整条删掉（保留期只为回答 approval 查询） */
  prune() {
    const nowMs = this.#now();
    const records = this.#load();
    const { kept, changed } = this.#expire(records, nowMs);
    const survivors = kept.filter((record) => {
      if (record.state === 'pending') return true;
      return nowMs - (record.decidedAt ?? record.at) < this.#ttlMs;
    });
    if (changed || survivors.length !== records.length) this.#store(survivors);
    return survivors.length;
  }

  /** 起定时器（unref：不吊住进程）——listen() 里调用 */
  start(intervalMs = DISPATCH_PENDING_PRUNE_MS) {
    if (this.#timer !== null) return;
    this.#timer = setInterval(() => {
      try {
        this.prune();
      } catch {
        /* 清理失败不影响服务 */
      }
    }, Math.max(1000, Math.floor(Number(intervalMs) || DISPATCH_PENDING_PRUNE_MS)));
    this.#timer.unref?.();
  }

  /** close() 里显式清掉（热重载不留定时器） */
  close() {
    if (this.#timer !== null) {
      clearInterval(this.#timer);
      this.#timer = null;
    }
  }

  #expire(records, nowMs) {
    let changed = false;
    const kept = records.map((record) => {
      if (record.state === 'pending' && nowMs >= record.expiresAt) {
        changed = true;
        return { ...record, state: 'expired', decidedAt: nowMs };
      }
      return record;
    });
    if (changed && this.#logger) this.#logger('[dispatch] pending expired');
    return { kept, changed };
  }

  #load() {
    const raw = readJsonFile(this.file);
    const rows = Array.isArray(raw?.pending) ? raw.pending : [];
    return rows.map((row) => normalizePendingRecord(row)).filter(Boolean).slice(-DISPATCH_PENDING_MAX_RECORDS);
  }

  #store(records) {
    writeJson0600(this.file, { pending: records.slice(-DISPATCH_PENDING_MAX_RECORDS) });
  }
}

/** 只认契约字段（对端给什么都不能进本机文件）：多余键在落盘前丢掉 */
function normalizePendingRecord(row) {
  if (row == null || typeof row !== 'object' || Array.isArray(row)) return null;
  const approvalId = typeof row.approvalId === 'string' ? row.approvalId : '';
  if (approvalId === '') return null;
  const record = {};
  for (const field of PENDING_FIELDS) {
    if (field === 'at' || field === 'expiresAt' || field === 'promptBytes') {
      record[field] = Number.isFinite(Number(row[field])) ? Math.floor(Number(row[field])) : 0;
    } else {
      record[field] = typeof row[field] === 'string' ? row[field] : '';
    }
  }
  const state = ['pending', 'approved', 'rejected', 'expired'].includes(row.state) ? row.state : 'pending';
  record.state = state;
  if (typeof row.sessionId === 'string' && row.sessionId !== '') record.sessionId = row.sessionId;
  if (Number.isFinite(Number(row.decidedAt))) record.decidedAt = Math.floor(Number(row.decidedAt));
  return record;
}
