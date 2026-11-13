// dsh-lan-peers · 0.12.0-α（S1）文件面：单发 offer/pull 模型的存储层。
//
// 模型（用户决议，不再协商）：发送方只发一份**报价**（metadata，零字节），字节留在
// 自己的 outbox 里等对端来拉。三块区域，全部在 <stateDir> 下面：
//
//   outbox/<fileId>/         发送方keeper拷贝（data + meta.json）—— 等对端 pull
//   offers/<fileId>/meta.json 接收方的待下载条目（**只有 metadata，没有 data**）
//   file-trust.json            per-peer 信任标记（面板「信任此人」写的就是它）
//
// 铁律沿用 lib/file-store.mjs：对端只给「文件名 + 字节 + sha256」，路径只由本机 id 拼；
// 名字先过 sanitizeFileName()；日志只记 size / sha256 前 8 位 / 状态。
//
// 本模块不碰 HTTP：路由（host/server.mjs）只调它的方法，单测直接驱动它。
import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import {
  FILE_CHUNK_HARD_MAX,
  hashFile,
  isFileId,
  sanitizeFileName,
} from './file-store.mjs';

export const OUTBOX_DIR = 'outbox';
export const OFFERS_DIR = 'offers';
export const OUTBOX_GONE_FILE = '.gone.json';
export const FILE_TRUST_FILE = 'file-trust.json';

/** 缺省配额 5 GiB；环境变量优先（运维不必改代码就能压一压盘） */
export const FILE_OUTBOX_QUOTA_BYTES = 5 * 1024 ** 3;
/** 空闲多久算过期：7 天（从 max(createdAt, lastPullAt) 起算） */
export const FILE_OUTBOX_TTL_MS = 7 * 24 * 60 * 60 * 1000;
/** 待下载条目上限：只存 metadata，几条也只是个数字，但别让它无界 */
export const FILE_OFFER_LIMIT = 512;
/** 墓碑上限：刚被逐出的 id 记在这里，pull 才能如实回 409 file-gone 而不是 404 */
export const FILE_GONE_LIMIT = 512;
export const FILE_TRUST_VERSION = 1;

/** 只有服务端生成的 uuid 才能拼路径；对端给的一律先过这关。 */
export function parseFileId(raw) {
  return isFileId(raw) ? String(raw) : '';
}

/** offer 的名字与收件箱走同一份清洗（唯一实现仍在 file-store）。 */
export function sanitizeOfferName(raw) {
  return sanitizeFileName(raw);
}

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = file + '.tmp-' + process.pid + '-' + randomUUID().slice(0, 8);
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmp, file);
}

function positiveInt(value, fallback) {
  const numeric = Math.floor(Number(value));
  if (!Number.isFinite(numeric) || numeric < 1) return fallback;
  return numeric;
}

function isSha256(value) {
  return /^[0-9a-f]{64}$/.test(String(value ?? '').toLowerCase());
}

function quotaFromEnv() {
  const raw = process.env.FILE_OUTBOX_QUOTA_BYTES;
  if (raw == null || String(raw).trim() === '') return FILE_OUTBOX_QUOTA_BYTES;
  return positiveInt(raw, FILE_OUTBOX_QUOTA_BYTES);
}

/**
 * 发送方的 keeper 拷贝。
 *
 * 逐出规则（两段，T2/T3 钉的就是这两段）：
 *   1) TTL —— now - max(createdAt, lastPullAt) >= ttlMs 的条目先走；
 *      刚被拉过的条目 createdAt 再老也不走（它还活着）。
 *   2) 配额 —— 仍超 quotaBytes 时按 lastPullAt 升序（最久没被拉的先走）逐个删除，
 *      同 lastPullAt 按 createdAt、再按 fileId 定序（确定性，用例可复现）。
 * 逐出即删目录，并在 .gone.json 里留一条墓碑：之后对端的 pull 得到 409 file-gone
 * （而不是 404 unknown-file —— 「不知道」和「知道但没了」是两件事）。
 */
export class FileOutbox {
  constructor(options = {}) {
    const stateDir = String(options.stateDir ?? process.cwd());
    this.root = path.join(stateDir, OUTBOX_DIR);
    this.gonePath = path.join(this.root, OUTBOX_GONE_FILE);
    this.now = typeof options.now === 'function' ? options.now : Date.now;
    this.quotaBytes = positiveInt(
      options.quotaBytes ?? quotaFromEnv(),
      FILE_OUTBOX_QUOTA_BYTES,
    );
    this.ttlMs = positiveInt(options.ttlMs, FILE_OUTBOX_TTL_MS);
    this.logger = typeof options.logger === 'function' ? options.logger : null;
    /** fileId -> { fileId, name, size, sha256, to, createdAt, lastPullAt } */
    this.entries = new Map();
    /** fileId -> 逐出时间（墓碑，只为区分 404 / 409） */
    this.gone = new Map();
    this.timer = null;
    fs.mkdirSync(this.root, { recursive: true, mode: 0o700 });
    this.load();
  }

  log(text) {
    if (this.logger) this.logger('[file] ' + text);
  }

  entryDir(fileId) {
    return path.join(this.root, fileId);
  }

  dataPath(fileId) {
    return path.join(this.entryDir(fileId), 'data');
  }

  metaPath(fileId) {
    return path.join(this.entryDir(fileId), 'meta.json');
  }

  load() {
    let names = [];
    try {
      names = fs.readdirSync(this.root);
    } catch {
      names = [];
    }
    for (const name of names) {
      if (!isFileId(name)) continue;
      const meta = readJson(this.metaPath(name));
      if (!meta || typeof meta !== 'object') continue;
      let stat;
      try {
        stat = fs.statSync(this.dataPath(name));
      } catch {
        // meta 在、data 不在：半路写坏，收掉这一条
        this.drop(name, 'broken', { gone: false });
        continue;
      }
      this.entries.set(name, {
        fileId: name,
        name: String(meta.name ?? ''),
        size: stat.size,
        sha256: String(meta.sha256 ?? '').toLowerCase(),
        to: String(meta.to ?? ''),
        createdAt: Number(meta.createdAt) || 0,
        lastPullAt: Number(meta.lastPullAt) || Number(meta.createdAt) || 0,
        persistedAt: 0,
      });
    }
    const raw = readJson(this.gonePath);
    const gone = raw && typeof raw.gone === 'object' && raw.gone ? raw.gone : {};
    for (const [fileId, at] of Object.entries(gone)) {
      if (isFileId(fileId)) this.gone.set(fileId, Number(at) || 0);
    }
  }

  saveGone() {
    try {
      writeJson(this.gonePath, { gone: Object.fromEntries(this.gone) });
    } catch (error) {
      this.log('gone-write-failed err=' + String(error?.message ?? error).slice(0, 48));
    }
  }

  noteGone(fileId) {
    if (!isFileId(fileId)) return;
    this.gone.set(fileId, this.now());
    while (this.gone.size > FILE_GONE_LIMIT) {
      const oldest = this.gone.keys().next().value;
      if (oldest === undefined) break;
      this.gone.delete(oldest);
    }
    this.saveGone();
  }

  /** 已用字节（只算 outbox 里仍然存在的 keeper 拷贝） */
  get used() {
    let total = 0;
    for (const entry of this.entries.values()) total += Number(entry.size) || 0;
    return total;
  }

  /** 配额（不是已用）—— 用例与面板都按这两个名字读 */
  get total() {
    return this.quotaBytes;
  }

  get count() {
    return this.entries.size;
  }

  writeMeta(entry) {
    try {
      writeJson(this.metaPath(entry.fileId), {
        fileId: entry.fileId,
        name: entry.name,
        size: entry.size,
        sha256: entry.sha256,
        to: entry.to,
        createdAt: entry.createdAt,
        lastPullAt: entry.lastPullAt,
      });
      entry.persistedAt = this.now();
    } catch (error) {
      this.log('meta-write-failed id=' + String(entry.fileId).slice(0, 8)
        + ' err=' + String(error?.message ?? error).slice(0, 48));
    }
  }

  /**
   * 收下一份 keeper 拷贝。size/sha256 以**盘上真实字节**为准（stat + hashFile）：
   * 调用方给的值只当声明，不一致时按盘的来。
   * @returns {{ok:true, fileId:string, name:string, size:number, sha256:string}
   *          | {ok:false, reason:'bad-name'|'not-found'|'not-a-file'|'copy-failed'}}
   */
  async put(input = {}) {
    const fileId = parseFileId(input.fileId) || randomUUID();
    const name = sanitizeOfferName(input.name);
    if (name === '') return { ok: false, reason: 'bad-name' };
    const sourcePath = String(input.sourcePath ?? '');
    let stat;
    try {
      stat = fs.statSync(sourcePath);
    } catch {
      return { ok: false, reason: 'not-found' };
    }
    if (!stat.isFile()) return { ok: false, reason: 'not-a-file' };
    const size = stat.size;
    const at = this.now();
    const declared = String(input.sha256 ?? '').toLowerCase();
    const sha256 = isSha256(declared) ? declared : await hashFile(sourcePath);
    fs.mkdirSync(this.entryDir(fileId), { recursive: true, mode: 0o700 });
    const dataPath = this.dataPath(fileId);
    const tmp = dataPath + '.tmp-' + process.pid + '-' + randomUUID().slice(0, 8);
    try {
      fs.copyFileSync(sourcePath, tmp);
      fs.renameSync(tmp, dataPath);
    } catch (error) {
      try { fs.rmSync(tmp, { force: true }); } catch { /* 已经不在 */ }
      this.drop(fileId, 'copy-failed', { gone: false });
      this.log('put id=' + fileId.slice(0, 8) + ' state=rejected reason=copy-failed');
      return { ok: false, reason: 'copy-failed' };
    }
    const entry = {
      fileId,
      name,
      size,
      sha256,
      to: String(input.to ?? ''),
      createdAt: at,
      lastPullAt: at,
      persistedAt: 0,
    };
    this.entries.set(fileId, entry);
    // 刚进来的这一条一定是盘上最新的，先把 meta 落住再收配额
    this.writeMeta(entry);
    const swept = this.sweep(at);
    this.log('put id=' + fileId.slice(0, 8) + ' bytes=' + size + ' sha=' + sha256.slice(0, 8)
      + ' evicted=' + swept.removed);
    return { ok: true, fileId, name, size, sha256 };
  }

  /** 查一条：未知给 unknown-file，逐出过给 file-gone（两者都是「不能拉」，但原因不同） */
  get(fileId) {
    const id = parseFileId(fileId);
    if (id === '') return { ok: false, reason: 'unknown-file' };
    const entry = this.entries.get(id);
    if (entry) return { ok: true, entry };
    return { ok: false, reason: this.gone.has(id) ? 'file-gone' : 'unknown-file' };
  }

  /**
   * 读一块。offset 是**绝对偏移**，length 默认按 FILE_CHUNK_HARD_MAX（单响应硬上限）。
   * @returns {{data:Buffer, offset:number, size:number, eof:boolean}
   *          | {error:'unknown-file'|'file-gone'|'bad-offset'|'read-failed', size?:number}}
   */
  open(fileId, offset, length) {
    const found = this.get(fileId);
    if (!found.ok) return { error: found.reason };
    const entry = found.entry;
    const at = Number(offset);
    if (!Number.isInteger(at) || at < 0 || at > entry.size) {
      return { error: 'bad-offset', size: entry.size };
    }
    const want = Math.min(
      Math.max(1, Number.isFinite(Number(length)) ? Math.floor(Number(length)) : FILE_CHUNK_HARD_MAX),
      FILE_CHUNK_HARD_MAX,
    );
    const room = Math.max(0, entry.size - at);
    const take = Math.min(want, room);
    let data = Buffer.alloc(0);
    if (take > 0) {
      try {
        const handle = fs.openSync(this.dataPath(entry.fileId), 'r');
        try {
          const buffer = Buffer.allocUnsafe(take);
          const read = fs.readSync(handle, buffer, 0, take, at);
          data = buffer.subarray(0, read);
        } finally {
          fs.closeSync(handle);
        }
      } catch {
        return { error: 'read-failed' };
      }
    }
    entry.lastPullAt = this.now();
    // meta 只在「距上次落盘 ≥30s」时重写：大文件一块 512KiB，逐块落盘纯属自找 IO
    if (!entry.persistedAt || entry.lastPullAt - entry.persistedAt >= 30_000) this.writeMeta(entry);
    return { data, offset: at, size: entry.size, eof: at + data.length >= entry.size };
  }

  /** 删一条（目录 + 内存 + 墓碑）。gone=false 只删不立碑（半路写坏那种）。 */
  drop(fileId, reason = 'drop', { gone = true } = {}) {
    const id = parseFileId(fileId);
    if (id === '') return false;
    const entry = this.entries.get(id);
    this.entries.delete(id);
    try {
      fs.rmSync(this.entryDir(id), { recursive: true, force: true });
    } catch { /* 已经不在 */ }
    if (gone) this.noteGone(id);
    if (entry) this.log('evict id=' + id.slice(0, 8) + ' bytes=' + entry.size + ' reason=' + reason);
    return entry !== undefined;
  }

  /** TTL + 配额两段清扫；返回本趟逐出的 id，便于用例断言「谁被赶走了」 */
  sweep(nowMs = this.now()) {
    const at = Number.isFinite(Number(nowMs)) ? Number(nowMs) : this.now();
    const evicted = [];
    for (const entry of [...this.entries.values()]) {
      const alive = Math.max(Number(entry.createdAt) || 0, Number(entry.lastPullAt) || 0);
      if (at - alive < this.ttlMs) continue;
      this.drop(entry.fileId, 'ttl');
      evicted.push(entry.fileId);
    }
    let used = this.used;
    while (used > this.quotaBytes && this.entries.size > 0) {
      const victim = [...this.entries.values()].sort((left, right) => (
        (left.lastPullAt - right.lastPullAt)
        || (left.createdAt - right.createdAt)
        || String(left.fileId).localeCompare(String(right.fileId))
      ))[0];
      if (!victim) break;
      used -= Number(victim.size) || 0;
      this.drop(victim.fileId, 'quota');
      evicted.push(victim.fileId);
    }
    return { evicted, removed: evicted.length, used: this.used };
  }

  /** 定时清扫：unref（不吊住进程）+ close() 里清（热重载不留定时器） */
  start() {
    if (this.timer) return;
    this.timer = setInterval(() => {
      try {
        this.sweep();
      } catch (error) {
        this.log('sweep-failed err=' + String(error?.message ?? error).slice(0, 48));
      }
    }, 60_000);
    this.timer.unref?.();
  }

  close() {
    if (!this.timer) return;
    clearInterval(this.timer);
    this.timer = null;
  }
}

/**
 * 接收方「待下载」条目（metadata only：这里**从来没有 data 文件**）。
 * 一个目录一条，删条目就是删目录 —— 与 outbox 同一副形状，运维一眼能对上。
 */
export class FileOffers {
  constructor(options = {}) {
    const stateDir = String(options.stateDir ?? process.cwd());
    this.root = path.join(stateDir, OFFERS_DIR);
    this.now = typeof options.now === 'function' ? options.now : Date.now;
    this.ttlMs = positiveInt(options.ttlMs, FILE_OUTBOX_TTL_MS);
    this.limit = positiveInt(options.limit, FILE_OFFER_LIMIT);
    this.logger = typeof options.logger === 'function' ? options.logger : null;
    /** fileId -> { id, name, size, sha256, from:{peerId,name}, at } */
    this.entries = new Map();
    fs.mkdirSync(this.root, { recursive: true, mode: 0o700 });
    this.load();
  }

  log(text) {
    if (this.logger) this.logger('[file] ' + text);
  }

  metaPath(fileId) {
    return path.join(this.root, fileId, 'meta.json');
  }

  load() {
    let names = [];
    try {
      names = fs.readdirSync(this.root);
    } catch {
      names = [];
    }
    for (const name of names) {
      if (!isFileId(name)) continue;
      const meta = readJson(this.metaPath(name));
      if (!meta || typeof meta !== 'object') {
        try { fs.rmSync(path.join(this.root, name), { recursive: true, force: true }); } catch { /* 已经不在 */ }
        continue;
      }
      this.entries.set(name, {
        id: name,
        name: String(meta.name ?? ''),
        size: Number(meta.size) || 0,
        sha256: String(meta.sha256 ?? '').toLowerCase(),
        from: meta.from && typeof meta.from === 'object'
          ? { peerId: String(meta.from.peerId ?? ''), name: String(meta.from.name ?? '') }
          : { peerId: '', name: '' },
        at: Number(meta.at) || 0,
      });
    }
  }

  writeMeta(offer) {
    try {
      writeJson(this.metaPath(offer.id), {
        id: offer.id,
        name: offer.name,
        size: offer.size,
        sha256: offer.sha256,
        from: offer.from,
        at: offer.at,
      });
    } catch (error) {
      this.log('offer-meta-failed id=' + String(offer.id).slice(0, 8)
        + ' err=' + String(error?.message ?? error).slice(0, 48));
    }
  }

  /**
   * 记一条待下载。同一个 fileId 重复到达 = 幂等重发（保留原来的 at）。
   * @returns {{ok:true, offer:object} | {ok:false, reason:'bad-name'|'bad-request'}}
   */
  add(input = {}) {
    const id = parseFileId(input.fileId);
    if (id === '') return { ok: false, reason: 'bad-request' };
    const name = sanitizeOfferName(input.name);
    if (name === '') return { ok: false, reason: 'bad-name' };
    const size = Number(input.size);
    if (!Number.isInteger(size) || size < 0) return { ok: false, reason: 'bad-request' };
    const sha256 = String(input.sha256 ?? '').toLowerCase();
    if (!isSha256(sha256)) return { ok: false, reason: 'bad-request' };
    const from = input.from && typeof input.from === 'object'
      ? { peerId: String(input.from.peerId ?? ''), name: String(input.from.name ?? '') }
      : { peerId: '', name: '' };
    const previous = this.entries.get(id);
    const offer = {
      id,
      name,
      size,
      sha256,
      from,
      at: previous ? previous.at : this.now(),
    };
    this.entries.set(id, offer);
    this.writeMeta(offer);
    while (this.entries.size > this.limit) {
      const oldest = [...this.entries.values()]
        .sort((left, right) => (Number(left.at) - Number(right.at)))[0];
      if (!oldest) break;
      this.remove(oldest.id);
    }
    return { ok: true, offer };
  }

  get(fileId) {
    const id = parseFileId(fileId);
    if (id === '') return null;
    return this.entries.get(id) ?? null;
  }

  list() {
    return [...this.entries.values()].sort((left, right) => Number(right.at) - Number(left.at));
  }

  remove(fileId) {
    const id = parseFileId(fileId);
    if (id === '') return false;
    const had = this.entries.delete(id);
    try {
      fs.rmSync(path.join(this.root, id), { recursive: true, force: true });
    } catch { /* 已经不在 */ }
    return had;
  }

  sweep(nowMs = this.now()) {
    const at = Number.isFinite(Number(nowMs)) ? Number(nowMs) : this.now();
    let removed = 0;
    for (const offer of [...this.entries.values()]) {
      if (at - Number(offer.at) < this.ttlMs) continue;
      this.remove(offer.id);
      removed += 1;
    }
    return removed;
  }
}

/**
 * per-peer 信任标记（<stateDir>/file-trust.json，#0600，原子写）。
 * 坏文件 = 「谁都不信任」，绝不抛：面板不能因为一个坏 JSON 就打不开。
 */
export class FileTrust {
  constructor(options = {}) {
    const stateDir = String(options.stateDir ?? process.cwd());
    this.file = path.join(stateDir, FILE_TRUST_FILE);
    this.now = typeof options.now === 'function' ? options.now : Date.now;
    this.logger = typeof options.logger === 'function' ? options.logger : null;
    /** peerId -> { trusted:true, updatedAt } */
    this.peers = new Map();
    this.load();
  }

  load() {
    const raw = readJson(this.file);
    const peers = raw && typeof raw === 'object' && raw.peers && typeof raw.peers === 'object'
      ? raw.peers
      : null;
    if (!peers || Number(raw.version) !== FILE_TRUST_VERSION) return;
    for (const [peerId, entry] of Object.entries(peers)) {
      if (String(peerId) === '' || !entry || typeof entry !== 'object') continue;
      if (entry.trusted !== true) continue;
      this.peers.set(String(peerId), {
        trusted: true,
        updatedAt: Number(entry.updatedAt) || 0,
      });
    }
  }

  save() {
    writeJson(this.file, {
      version: FILE_TRUST_VERSION,
      peers: Object.fromEntries(this.peers),
    });
  }

  isTrusted(peerId) {
    const id = String(peerId ?? '');
    if (id === '') return false;
    return this.peers.get(id)?.trusted === true;
  }

  /** 写一枚标记；trusted=false 是**删条目**（缺席即不信任，不留 false 的坟头） */
  set(peerId, trusted) {
    const id = String(peerId ?? '').trim();
    if (id === '') return { ok: false, reason: 'bad-peer' };
    const yes = trusted === true;
    const updatedAt = this.now();
    if (yes) this.peers.set(id, { trusted: true, updatedAt });
    else this.peers.delete(id);
    try {
      this.save();
    } catch (error) {
      if (this.logger) {
        this.logger('[file] trust-write-failed peer=' + id.slice(0, 8)
          + ' err=' + String(error?.message ?? error).slice(0, 48));
      }
      return { ok: false, reason: 'write-failed' };
    }
    return { ok: true, peerId: id, trusted: yes, updatedAt };
  }

  list() {
    return [...this.peers.entries()].map(([peerId, entry]) => ({
      peerId,
      trusted: true,
      updatedAt: entry.updatedAt,
    }));
  }
}
