// dsh-lan-peers · 私聊存储（0.8.5-α 契约 §2）。
//
// 一对伙伴一个文件：<stateDir>/dm/<peerId>.jsonl（0600，追加写）。
// 每行一条 { id, ts, from, text, sessionId, state }：
//   id        发送方生成的 UUID —— 两端对齐的唯一锚点
//   from      self | peer（**相对本机视角**；收到对端的条目要翻面，见 flipSide）
//   sessionId 该轮所属的 DSH 连续会话 id（契约 §1），没有则为 null
//   state     pending（已收下、等回复）| sent（本轮闭环）| failed（发送失败）
//
// 三条硬约束：
//   1. 按 id 去重（merge 与 append 都过这一关）；
//   2. 每对上限 2000 条 / 7 天，超出按最旧丢弃 —— 只在真的裁掉时才重写文件，
//      常态路径永远是纯追加；
//   3. 正文只落盘、进日志的只有 peerId 前 8 位与条目数（§0 铁律）。
//
// 修订（state 从 pending 变 sent）也走追加：同一 id 再写一行，读取时后出现的
// 那行是权威 —— 这样「append-only」与「状态可变」不用二选一。
import { createHash, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const DM_ROOT_DIR = 'dm';
export const DM_FILE_EXT = '.jsonl';
/** 每对上限（契约 §2） */
export const DM_MAX_PER_PAIR = 2000;
/** TTL：7 天（契约 §2） */
export const DM_TTL_MS = 7 * 24 * 60 * 60 * 1000;
/** 单条正文上限：进 /v1/dm/sync 的 body 上限是 1MiB，这里留足批量余量 */
export const DM_TEXT_MAX_BYTES = 8 * 1024;
/** 单轮对齐最多交换多少条（超出由下次打开面板时补齐） */
export const DM_SYNC_MAX_ITEMS = 500;
export const DM_ID_MAX_CHARS = 200;
export const DM_SESSION_MAX_CHARS = 200;

export const DM_STATES = Object.freeze(['pending', 'sent', 'failed']);
export const DM_SIDES = Object.freeze(['self', 'peer']);

/** from 是「相对本机」的，跨机器传输时必须翻面（否则对方看到的是自己的消息在左边） */
export function flipSide(from) {
  if (from === 'self') return 'peer';
  if (from === 'peer') return 'self';
  return null;
}

/** 日志口径：只暴露前 8 位 */
export function shortPeer(peerId) {
  return String(peerId ?? '').slice(0, 8);
}

/** peerId -> 文件名。UUID 原样用，意外字符一律折叠成稳定摘要（不进路径） */
export function dmFileName(peerId) {
  const raw = String(peerId ?? '');
  if (/^[A-Za-z0-9_-]{1,128}$/.test(raw)) return raw + DM_FILE_EXT;
  return 'p-' + createHash('sha256').update(raw, 'utf8').digest('hex').slice(0, 32) + DM_FILE_EXT;
}

/** 校验 + 归一化；不合法返回 null（调用方跳过，绝不半条落盘） */
export function normalizeDmEntry(input) {
  if (!input || typeof input !== 'object') return null;
  const id = typeof input.id === 'string' ? input.id.trim() : '';
  if (id === '' || id.length > DM_ID_MAX_CHARS) return null;
  const ts = Number(input.ts);
  if (!Number.isFinite(ts) || ts < 0) return null;
  if (!DM_SIDES.includes(input.from)) return null;
  const text = typeof input.text === 'string' ? input.text : '';
  if (Buffer.byteLength(text, 'utf8') > DM_TEXT_MAX_BYTES) return null;
  const sessionId = typeof input.sessionId === 'string' && input.sessionId !== ''
    ? input.sessionId.slice(0, DM_SESSION_MAX_CHARS)
    : null;
  const state = DM_STATES.includes(input.state) ? input.state : 'pending';
  return { id, ts, from: input.from, text, sessionId, state };
}

export class DmStore {
  #dir;
  #now;
  #max;
  #ttl;
  #logger;
  /** peerId -> Map<id, entry>（同一 id 的后一行覆盖前一行） */
  #cache = new Map();

  constructor({
    stateDir,
    now = Date.now,
    maxPerPeer = DM_MAX_PER_PAIR,
    ttlMs = DM_TTL_MS,
    logger = null,
  } = {}) {
    this.#dir = path.join(String(stateDir ?? '.'), DM_ROOT_DIR);
    this.#now = typeof now === 'function' ? now : Date.now;
    const max = Math.floor(Number(maxPerPeer));
    this.#max = Number.isFinite(max) && max > 0 ? max : DM_MAX_PER_PAIR;
    const ttl = Math.floor(Number(ttlMs));
    this.#ttl = Number.isFinite(ttl) && ttl > 0 ? ttl : DM_TTL_MS;
    this.#logger = typeof logger === 'function' ? logger : null;
    fs.mkdirSync(this.#dir, { recursive: true, mode: 0o700 });
  }

  get dir() {
    return this.#dir;
  }

  file(peerId) {
    return path.join(this.#dir, dmFileName(peerId));
  }

  #log(line) {
    if (this.#logger) this.#logger(line);
  }

  #load(peerId) {
    const cached = this.#cache.get(peerId);
    if (cached) return cached;
    const map = new Map();
    let raw = '';
    try {
      raw = fs.readFileSync(this.file(peerId), 'utf8');
    } catch {
      raw = '';
    }
    for (const line of raw.split('\n')) {
      if (line.trim() === '') continue;
      let parsed;
      try {
        parsed = JSON.parse(line);
      } catch {
        continue; // 半行（进程被杀）不该让整份历史报废
      }
      const entry = normalizeDmEntry(parsed);
      if (!entry) continue;
      // 同一 id 的后一行覆盖前一行；**不删再插**——Map 对已存在的 key 原地赋值即保序，
      // 这条顺序就是同毫秒消息的先后（气泡不能把回复排到提问前面）
      map.set(entry.id, entry);
    }
    const state = { map };
    this.#cache.set(peerId, state);
    return state;
  }

  /**
   * 当前可见视图：丢掉过期条目、按 ts 升序、超出上限时保最新的一段。
   * 只按 ts 排序并依赖 Array#sort 的稳定性 —— 同毫秒的两条（提问与回复很可能同毫秒）
   * 因此保持落盘先后，不会被 id 的字典序打乱。
   */
  #live(state) {
    const cutoff = this.#now() - this.#ttl;
    const kept = [...state.map.values()].filter((entry) => entry.ts >= cutoff);
    kept.sort((left, right) => left.ts - right.ts);
    return kept.length > this.#max ? kept.slice(kept.length - this.#max) : kept;
  }

  #appendLine(peerId, entry) {
    const file = this.file(peerId);
    try {
      fs.mkdirSync(this.#dir, { recursive: true, mode: 0o700 });
      const created = !fs.existsSync(file);
      fs.appendFileSync(file, JSON.stringify(entry) + '\n', { mode: 0o600 });
      if (created) {
        try {
          fs.chmodSync(file, 0o600);
        } catch {
          /* Windows 上 chmod 只影响只读位，忽略即可 */
        }
      }
      return true;
    } catch (error) {
      this.#log('[dm] write failed peer=' + shortPeer(peerId) + ' code=' + String(error?.code ?? 'unknown'));
      return false;
    }
  }

  /** 真裁掉了才重写（常态路径纯追加，不产生 O(n) 写入） */
  #compact(peerId, state) {
    const live = this.#live(state);
    if (live.length === state.map.size) return 0;
    const dropped = state.map.size - live.length;
    const file = this.file(peerId);
    const tmp = file + '.tmp-' + process.pid + '-' + randomUUID().slice(0, 8);
    try {
      fs.writeFileSync(tmp, live.map((entry) => JSON.stringify(entry) + '\n').join(''), { mode: 0o600 });
      fs.renameSync(tmp, file);
    } catch (error) {
      try {
        fs.rmSync(tmp, { force: true });
      } catch {
        /* 清理失败不影响主流程 */
      }
      this.#log('[dm] compact failed peer=' + shortPeer(peerId) + ' code=' + String(error?.code ?? 'unknown'));
      return 0;
    }
    this.#cache.set(peerId, { map: new Map(live.map((entry) => [entry.id, entry])) });
    this.#log('[dm] compact peer=' + shortPeer(peerId) + ' dropped=' + dropped + ' kept=' + live.length);
    return dropped;
  }

  /** 新条目；同 id 已存在时不动（去重，契约 §2） */
  append(peerId, input) {
    const key = String(peerId ?? '');
    if (key === '') return { added: false, reason: 'bad-peer', entry: null };
    const entry = normalizeDmEntry(input);
    if (!entry) return { added: false, reason: 'bad-entry', entry: null };
    const state = this.#load(key);
    if (state.map.has(entry.id)) return { added: false, reason: 'duplicate', entry: state.map.get(entry.id) };
    if (!this.#appendLine(key, entry)) return { added: false, reason: 'write-failed', entry: null };
    state.map.set(entry.id, entry);
    const dropped = this.#compact(key, state);
    return { added: true, entry, dropped };
  }

  /** 修订一条已有条目（追加同 id 的一行；ts 不动，排序锚点稳定） */
  update(peerId, id, patch = {}) {
    const key = String(peerId ?? '');
    const state = this.#load(key);
    const current = state.map.get(String(id ?? ''));
    if (!current) return { ok: false, reason: 'unknown-id' };
    const next = normalizeDmEntry({ ...current, ...patch, id: current.id, ts: current.ts });
    if (!next) return { ok: false, reason: 'bad-entry' };
    if (!this.#appendLine(key, next)) return { ok: false, reason: 'write-failed' };
    state.map.set(current.id, next);
    return { ok: true, entry: next };
  }

  /**
   * 收下对端的一批条目（/v1/dm/sync 与门面 sync 共用）：
   * from 先翻面（对方的 self 是本机的 peer），再按 id 去重落盘。
   */
  merge(peerId, messages) {
    const key = String(peerId ?? '');
    if (key === '') return { added: 0, skipped: 0, total: 0 };
    let added = 0;
    let skipped = 0;
    for (const raw of Array.isArray(messages) ? messages : []) {
      const entry = normalizeDmEntry({ ...(raw ?? {}), from: flipSide(raw?.from) });
      if (!entry) {
        skipped += 1;
        continue;
      }
      const out = this.append(key, entry);
      if (out.added) added += 1;
      else if (out.reason === 'write-failed') skipped += 1;
    }
    return { added, skipped, total: this.list(key).length };
  }

  /** 按 ts 升序（契约 §2）；返回浅拷贝，调用方改不到缓存 */
  list(peerId) {
    const key = String(peerId ?? '');
    if (key === '') return [];
    return this.#live(this.#load(key)).map((entry) => ({ ...entry }));
  }

  count(peerId) {
    return this.list(peerId).length;
  }

  ids(peerId) {
    return new Set(this.list(peerId).map((entry) => entry.id));
  }

  /** 该伙伴最近一条带 sessionId 的条目 —— 下一轮 ask 要带上它（契约 §1） */
  lastSessionId(peerId) {
    const live = this.list(peerId);
    for (let index = live.length - 1; index >= 0; index -= 1) {
      const sessionId = live[index].sessionId;
      if (typeof sessionId === 'string' && sessionId !== '') return sessionId;
    }
    return '';
  }

  /** 本机视角下最新一条的时间（对齐响应的 have 字段） */
  newestTs(peerId) {
    const live = this.list(peerId);
    return live.length > 0 ? live[live.length - 1].ts : 0;
  }
}
