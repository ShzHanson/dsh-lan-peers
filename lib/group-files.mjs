/**
 * dsh-lan-peers · 0.12.0-α（S2）群文件：**hub 侧**的一份拷贝 + 一个公告平面
 * ==========================================================================
 *
 * 模型（用户决议，与 S1 的私发不同）：
 *   DM    —— 发送方留着字节，收件方去**发送方**那里拉；
 *   GROUP —— 发送方只往 **hub** 传一份，会员按需到 hub 拉。targets:'all' 与
 *            targets:[peerId] 走**同一条**上传路径：哪怕只发一个人，也落在 hub 上，
 *            发送方下线之后这份文件照样在（这是这条路径唯一的意义）。
 *
 * 三块落盘，全部在 <stateDir> 下面：
 *
 *   group-files/<fileId>/meta.json   一条上传的记录（声明值 + LRU 时间戳 + 是否已收完）
 *   group-files/<fileId>/data        真实字节（只有 hub 有）
 *   group-files.json                 公告平面 {rev, files:[...]}（hub 权威、成员只读镜像）
 *   group-downloads.json             本机**已下载**过的群文件（成员侧，只为面板显示 downloaded）
 *
 * 与 S1 同一套铁律：
 *   · 路径只由本机拼（fileId 必须是 UUID 形状），文件名先过 sanitizeFileName()；
 *   · 日志只记 size / sha256 前 8 位 / 状态 —— 文件名、路径、内容一律不落日志；
 *   · 零依赖、不碰 HTTP：路由只调这里的方法，单测直接驱动它。
 *
 * 逐出与墓碑（用户选的是「配额 + LRU」，**没有** TTL 删除）：
 *   · 总量 GROUP_FILES_QUOTA_BYTES（20 GiB）；
 *   · 超了就按 lastAccessAt 升序逐出（list / pull / finish / append 都 touch），
 *     同 lastAccessAt 按 createdAt、再按 fileId 定序（确定性，用例可复现）；
 *   · 逐出**不删公告**：条目翻成 gone:true 留在平面里，成员看到「已失效」而不是静默 404；
 *   · 单文件比整份配额还大 → 直接拒（too-large），**一个字节都不逐出** ——
 *     「装不下的东西」不该以清空别人的文件为代价。
 *
 * 并发：同时只允许 GROUP_FILES_MAX_UPLOADS 条在传的上传。否则一个客户端开几十条
 * 半截上传就能把盘占满（声明 size 很小、实际一直往里写）。半截上传（没收完）由
 * 60 秒的空闲清扫器收掉（与 admin 上传通道同一个习惯：unref + close() 里清）。
 */
import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { FILE_CHUNK_HARD_MAX, hashFile, isFileId, sanitizeFileName } from './file-store.mjs';

export const GROUP_FILES_DIR = 'group-files';
export const GROUP_FILES_PLANE_FILE = 'group-files.json';
export const GROUP_FILES_DOWNLOADS_FILE = 'group-downloads.json';

/** 群文件总量配额：20 GiB（用户选的「配额 + LRU」，不是 TTL 删除） */
export const GROUP_FILES_QUOTA_BYTES = 20 * 1024 ** 3;

/**
 * 单块原始字节上限：512 KiB（与 S1 的 FILE_CHUNK_HARD_MAX 同一个数）。
 * 为什么不能再大：base64 后 JSON 700 KB，再过群信封 base64url 约 933 KB，
 * 必须留在 MAX_BODY_BYTES(1 MiB) 里 —— 这条线上限决定了块大小，不是审美。
 */
export const GROUP_FILE_CHUNK_MAX = FILE_CHUNK_HARD_MAX;

/** 同时在传的上传条数上限：4 条（超了 409 too-many-uploads） */
export const GROUP_FILES_MAX_UPLOADS = 4;

/** 半截上传空闲多久算放弃：10 分钟（清扫器 60 秒一趟） */
export const GROUP_FILES_UPLOAD_IDLE_MS = 10 * 60 * 1000;
export const GROUP_FILES_SWEEP_MS = 60_000;

/** 公告平面最多留多少条（逐出的墓碑也在里面，所以给它一个上限，只丢最旧的） */
export const GROUP_FILES_LIMIT = 1024;

const TRAILING_SLASHES = /\/+$/;
const PLAIN_TEXT_MAX = 200;

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

function nonNegativeInt(value) {
  const numeric = Math.floor(Number(value));
  if (!Number.isFinite(numeric) || numeric < 0) return -1;
  return numeric;
}

const asText = (value) => (typeof value === 'string' ? value : '');

export function isSha256Hex(value) {
  return /^[0-9a-f]{64}$/.test(asText(value).toLowerCase());
}

/** 对端给的一律先过这关：只有服务端生成的 uuid 才能拼路径 */
export function parseGroupFileId(raw) {
  return isFileId(raw) ? String(raw) : '';
}

/** 群文件的名字走与收件箱同一份清洗（唯一实现仍在 lib/file-store.mjs） */
export function sanitizeGroupFileName(raw) {
  return sanitizeFileName(raw);
}

/**
 * targets 归一化：'all' | [peerId...]（去重、去空白、上限 64 个 id）。
 * 空数组 / 坏形状一律当 'all'：**看得更多**不会让谁「看不见自己的文件」，
 * 而把一张空目标表当成「谁都不给」才是真的丢数据。
 */
export function normalizeTargets(raw) {
  if (raw == null) return 'all';
  if (typeof raw === 'string') {
    const one = raw.trim();
    if (one === '' || one === 'all') return 'all';
    return [one];
  }
  if (!Array.isArray(raw)) return 'all';
  const ids = [];
  for (const entry of raw) {
    const id = asText(entry).trim();
    if (id === '' || id === 'all') continue;
    if (ids.includes(id)) continue;
    if (ids.length >= 64) break;
    ids.push(id);
  }
  return ids.length === 0 ? 'all' : ids;
}

/** 这个 target 表允许哪个 peer 看/拉（targets:'all' 谁都允许） */
export function targetAllows(targets, peerId) {
  const normalized = normalizeTargets(targets);
  if (normalized === 'all') return true;
  const id = asText(peerId).trim();
  if (id === '') return false;
  return normalized.includes(id);
}

/** 平面里的一条：形状固定，坏数据一律返回 null（调用方直接丢掉这一条） */
export function makePlaneEntry(raw) {
  const source = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  const fileId = parseGroupFileId(source.fileId);
  if (fileId === '') return null;
  const name = sanitizeGroupFileName(source.name);
  if (name === '') return null;
  const size = nonNegativeInt(source.size);
  if (size < 0) return null;
  const sha256 = asText(source.sha256).toLowerCase();
  if (!isSha256Hex(sha256)) return null;
  const from = source.from && typeof source.from === 'object' ? source.from : {};
  const at = Number(source.at);
  return {
    fileId,
    name,
    size,
    sha256,
    from: {
      peerId: asText(from.peerId).slice(0, PLAIN_TEXT_MAX),
      name: asText(from.name).slice(0, PLAIN_TEXT_MAX),
    },
    targets: normalizeTargets(source.targets),
    at: Number.isFinite(at) && at > 0 ? Math.floor(at) : 0,
    gone: source.gone === true,
  };
}

/** 平面归一化：坏文件/缺字段的老数据都收敛成 {rev, files}，绝不抛错 */
export function normalizeFilesPlane(raw) {
  const source = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  const rev = Number(source.rev);
  const seen = new Set();
  const files = [];
  for (const entry of Array.isArray(source.files) ? source.files : []) {
    const made = makePlaneEntry(entry);
    if (!made || seen.has(made.fileId)) continue;
    seen.add(made.fileId);
    files.push(made);
  }
  return { rev: Number.isFinite(rev) && rev > 0 ? Math.floor(rev) : 0, files };
}

/** 成员侧合并（只读镜像）：**remote.rev 更大才采纳**，否则原样留住本地视图 */
export function mergeFilesPlane(local, remote) {
  const mine = normalizeFilesPlane(local);
  const theirs = normalizeFilesPlane(remote);
  if (theirs.rev > mine.rev) return theirs;
  return mine;
}

/**
 * 可见性：hub 看全部；成员只看到 targets:'all' 与点名给自己的那些。
 * **只有这一个实现** —— pull 响应、管理接口、平面读口全走它，绝不各写一套。
 */
export function visibleFiles(value, { peerId = '', isHub = false } = {}) {
  const base = normalizeFilesPlane(value);
  if (isHub === true) return base.files;
  const id = asText(peerId);
  return base.files.filter((entry) => targetAllows(entry.targets, id));
}

/** 状态行用的便宜摘要（面板/日志：条数 / rev / 失效条数） */
export function filesPlaneSummary(value) {
  const base = normalizeFilesPlane(value);
  return {
    rev: base.rev,
    count: base.files.length,
    gone: base.files.filter((entry) => entry.gone === true).length,
  };
}

function quotaFromEnv() {
  const raw = process.env.GROUP_FILES_QUOTA_BYTES;
  if (raw == null || String(raw).trim() === '') return GROUP_FILES_QUOTA_BYTES;
  return positiveInt(raw, GROUP_FILES_QUOTA_BYTES);
}

/**
 * hub 侧的字节存储。
 *
 * 一条记录 = 一个目录（meta.json + data）。**received 不落盘**：它永远是 data 的真实
 * 长度（stat）。落一份「已收多少」的冗余数字，断线/崩溃之后只会骗自己。
 */
export class GroupFileStore {
  constructor(options = {}) {
    const stateDir = String(options.stateDir ?? process.cwd());
    this.root = path.join(stateDir, GROUP_FILES_DIR);
    this.now = typeof options.now === 'function' ? options.now : Date.now;
    this.quotaBytes = positiveInt(options.quotaBytes ?? quotaFromEnv(), GROUP_FILES_QUOTA_BYTES);
    this.maxUploads = positiveInt(options.maxUploads, GROUP_FILES_MAX_UPLOADS);
    this.uploadIdleMs = positiveInt(options.uploadIdleMs, GROUP_FILES_UPLOAD_IDLE_MS);
    this.logger = typeof options.logger === 'function' ? options.logger : null;
    /** 逐出回调：让公告平面翻 gone:true（不传就只有墓碑，平面不知情） */
    this.onEvict = typeof options.onEvict === 'function' ? options.onEvict : null;
    /** fileId -> { fileId, name, size, sha256, from, targets, createdAt, lastAccessAt, complete } */
    this.entries = new Map();
    /** fileId -> 逐出/收回时间（墓碑：只为把 404 unknown-file 与 409 file-gone 分开） */
    this.gone = new Map();
    this.timer = null;
    fs.mkdirSync(this.root, { recursive: true, mode: 0o700 });
    this.load();
  }

  log(text) {
    if (this.logger) this.logger('[group-files] ' + text);
  }

  entryDir(fileId) {
    return path.join(this.root, fileId);
  }

  dataPath(fileId) {
    return path.join(this.root, fileId, 'data');
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
        this.drop(name, 'broken', { tombstone: false });
        continue;
      }
      let stat;
      try {
        stat = fs.statSync(this.dataPath(name));
      } catch {
        // meta 在、data 不在：半路写坏，收掉（不立碑 —— 它从来没被公告过）
        this.drop(name, 'broken', { tombstone: false });
        continue;
      }
      this.entries.set(name, {
        fileId: name,
        name: sanitizeGroupFileName(meta.name),
        size: nonNegativeInt(meta.size),
        sha256: asText(meta.sha256).toLowerCase(),
        from: {
          peerId: asText(meta.from?.peerId),
          name: asText(meta.from?.name),
        },
        targets: normalizeTargets(meta.targets),
        createdAt: Number(meta.createdAt) || 0,
        lastAccessAt: Number(meta.lastAccessAt) || Number(meta.createdAt) || 0,
        complete: meta.complete === true,
        bytes: stat.size,
      });
    }
  }

  writeMeta(entry) {
    try {
      writeJson(this.metaPath(entry.fileId), {
        fileId: entry.fileId,
        name: entry.name,
        size: entry.size,
        sha256: entry.sha256,
        from: entry.from,
        targets: entry.targets,
        createdAt: entry.createdAt,
        lastAccessAt: entry.lastAccessAt,
        complete: entry.complete === true,
      });
    } catch (error) {
      this.log('meta-write-failed id=' + String(entry.fileId).slice(0, 8)
        + ' err=' + String(error?.message ?? error).slice(0, 48));
    }
  }

  /** 已收字节（只统计**已收完**的条目：半截上传不算「文件」） */
  get used() {
    let total = 0;
    for (const entry of this.entries.values()) {
      if (entry.complete !== true) continue;
      total += Number(entry.size) || 0;
    }
    return total;
  }

  /** 配额（不是已用）—— 用例与面板都按这两个名字读 */
  get total() {
    return this.quotaBytes;
  }

  get count() {
    return this.entries.size;
  }

  /** 在传的上传条数（并发上限只看这一个数） */
  get inFlight() {
    let pending = 0;
    for (const entry of this.entries.values()) if (entry.complete !== true) pending += 1;
    return pending;
  }

  received(fileId) {
    try {
      return fs.statSync(this.dataPath(fileId)).size;
    } catch {
      return 0;
    }
  }

  /** 查一条：未知给 unknown-file，逐出/收回过给 file-gone（两者都是「不能拉」，原因不同） */
  get(fileId) {
    const id = parseGroupFileId(fileId);
    if (id === '') return { ok: false, reason: 'unknown-file' };
    const entry = this.entries.get(id);
    if (entry) return { ok: true, entry };
    return { ok: false, reason: this.gone.has(id) ? 'file-gone' : 'unknown-file' };
  }

  noteGone(fileId) {
    const id = parseGroupFileId(fileId);
    if (id === '') return;
    this.gone.set(id, this.now());
  }

  /**
   * 开一条上传（第一条 chunk 之前）。
   * @returns {{ok:true, fileId, received, replay:boolean}
   *          | {ok:false, error:'bad-request'|'too-large'|'too-many-uploads'|'already-exists'}}
   */
  begin(input = {}) {
    const source = input && typeof input === 'object' ? input : {};
    const fileId = parseGroupFileId(source.fileId);
    if (fileId === '') return { ok: false, error: 'bad-request' };
    const name = sanitizeGroupFileName(source.name);
    if (name === '') return { ok: false, error: 'bad-request' };
    const size = nonNegativeInt(source.size);
    if (size < 0) return { ok: false, error: 'bad-request' };
    const sha256 = asText(source.sha256).toLowerCase();
    if (!isSha256Hex(sha256)) return { ok: false, error: 'bad-request' };
    const from = {
      peerId: asText(source.from?.peerId).slice(0, PLAIN_TEXT_MAX),
      name: asText(source.from?.name).slice(0, PLAIN_TEXT_MAX),
    };
    if (from.peerId === '') return { ok: false, error: 'bad-request' };
    const targets = normalizeTargets(source.targets);

    const existing = this.entries.get(fileId);
    if (existing) {
      // 幂等：同一条重放（网络重试/进程重启后重来）原样接受，字节不重写
      const same = existing.size === size && existing.sha256 === sha256 && existing.name === name;
      if (same && existing.complete !== true) {
        return { ok: true, fileId, received: this.received(fileId), replay: true };
      }
      if (same && existing.complete === true) {
        return { ok: true, fileId, received: existing.size, replay: true };
      }
      return { ok: false, error: 'already-exists' };
    }

    // 装不下的东西当场拒：**先判这一条**，绝不为了给它腾地方而清空别人的文件
    if (size > this.quotaBytes) return { ok: false, error: 'too-large' };
    if (this.inFlight >= this.maxUploads) return { ok: false, error: 'too-many-uploads' };

    // 够不够放：先按 LRU 逐出（逐出即墓碑 + 通知平面），腾不出就拒
    const evicted = this.sweepQuota(this.now(), size);
    if (this.used + size > this.quotaBytes) {
      return { ok: false, error: 'too-large', evicted };
    }

    const at = this.now();
    const entry = {
      fileId,
      name,
      size,
      sha256,
      from,
      targets,
      createdAt: at,
      lastAccessAt: at,
      complete: false,
      bytes: 0,
    };
    try {
      fs.mkdirSync(this.entryDir(fileId), { recursive: true, mode: 0o700 });
      fs.writeFileSync(this.dataPath(fileId), Buffer.alloc(0), { mode: 0o600 });
    } catch (error) {
      this.drop(fileId, 'begin-failed', { tombstone: false });
      this.log('begin-failed id=' + fileId.slice(0, 8) + ' err=' + String(error?.message ?? error).slice(0, 48));
      return { ok: false, error: 'write-failed' };
    }
    this.entries.set(fileId, entry);
    this.writeMeta(entry);
    this.log('begin id=' + fileId.slice(0, 8) + ' bytes=' + size + ' sha=' + sha256.slice(0, 8)
      + ' targets=' + (targets === 'all' ? 'all' : String(targets.length)));
    return { ok: true, fileId, received: 0, replay: false, evicted };
  }

  /**
   * 追加一块。offset 必须正好接在已收字节后面：
   *   · offset === received        → 写入；
   *   · 块完全落在已收范围内       → 200 replay（**绝不重写**，重放不产生重复字节）；
   *   · 其它（前跳/空洞/跨界搭接） → 409 offset-mismatch，并把 received 报回去。
   */
  append(fileId, offset, bytes) {
    const id = parseGroupFileId(fileId);
    const entry = this.entries.get(id);
    if (!entry) return { ok: false, error: this.gone.has(id) ? 'file-gone' : 'unknown-file' };
    if (entry.complete === true) return { ok: false, error: 'already-complete', received: entry.size };
    const data = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes ?? []);
    if (data.length === 0) return { ok: false, error: 'bad-request', received: this.received(id) };
    const at = nonNegativeInt(offset);
    const received = this.received(id);
    if (at < 0) return { ok: false, error: 'offset-mismatch', received };
    if (at < received) {
      // 重放：整块都在已收范围内才算重放（搭接一半的是错的客户端，不是重试）
      if (at + data.length > received) return { ok: false, error: 'offset-mismatch', received };
      let seen;
      try {
        const handle = fs.openSync(this.dataPath(id), 'r');
        try {
          const buffer = Buffer.allocUnsafe(data.length);
          const read = fs.readSync(handle, buffer, 0, data.length, at);
          seen = buffer.subarray(0, read);
        } finally {
          fs.closeSync(handle);
        }
      } catch {
        return { ok: false, error: 'read-failed', received };
      }
      // 同一段重放必须**逐字节相同**：不同就说明"同一 offset 两套内容"，当场拒
      if (seen.length !== data.length || !seen.equals(data)) {
        return { ok: false, error: 'offset-mismatch', received };
      }
      entry.lastAccessAt = this.now();
      this.writeMeta(entry);
      return { ok: true, replay: true, received, offset: at };
    }
    if (at > received) return { ok: false, error: 'offset-mismatch', received };
    if (received + data.length > entry.size) {
      return { ok: false, error: 'size-exceeded', received, size: entry.size };
    }
    try {
      const handle = fs.openSync(this.dataPath(id), 'a');
      try {
        fs.writeSync(handle, data);
      } finally {
        fs.closeSync(handle);
      }
    } catch (error) {
      this.log('append-failed id=' + id.slice(0, 8) + ' err=' + String(error?.message ?? error).slice(0, 48));
      return { ok: false, error: 'write-failed', received };
    }
    entry.bytes = received + data.length;
    entry.lastAccessAt = this.now();
    this.writeMeta(entry);
    return { ok: true, replay: false, received: entry.bytes, offset: at };
  }

  /**
   * 收完：按**盘上真实字节**验 size + sha256（声明值只当声明）。
   * 对不上就把半截删掉（不立碑：它从来没被公告过），返回 integrity-failed。
   * @returns {{ok:true, entry, evicted:string[]} | {ok:false, error:string}}
   */
  async finish(fileId) {
    const id = parseGroupFileId(fileId);
    const entry = this.entries.get(id);
    if (!entry) return { ok: false, error: this.gone.has(id) ? 'file-gone' : 'unknown-file' };
    if (entry.complete === true) return { ok: true, entry: { ...entry }, evicted: [] };
    const size = this.received(id);
    if (size !== entry.size) {
      this.drop(id, 'integrity-size', { tombstone: false });
      return { ok: false, error: 'integrity-failed', size, expected: entry.size };
    }
    let sha256 = '';
    try {
      sha256 = await hashFile(this.dataPath(id));
    } catch {
      this.drop(id, 'integrity-read', { tombstone: false });
      return { ok: false, error: 'integrity-failed', size };
    }
    if (sha256 !== entry.sha256) {
      this.drop(id, 'integrity-sha', { tombstone: false });
      this.log('integrity-failed id=' + id.slice(0, 8) + ' got=' + sha256.slice(0, 8)
        + ' want=' + entry.sha256.slice(0, 8));
      return { ok: false, error: 'integrity-failed', size, sha256 };
    }
    entry.complete = true;
    entry.lastAccessAt = this.now();
    entry.bytes = size;
    this.writeMeta(entry);
    // 收完才占配额：先落住这一条（它是最新的），再按 LRU 收
    const evicted = this.sweepQuota(this.now(), 0);
    this.log('finish id=' + id.slice(0, 8) + ' bytes=' + size + ' sha=' + sha256.slice(0, 8)
      + ' evicted=' + evicted.length);
    return { ok: true, entry: { ...entry }, evicted };
  }

  /**
   * 读一块。offset 是**绝对偏移**，length 默认 GROUP_FILE_CHUNK_MAX（单响应硬上限）。
   * touch：被拉的条目 lastAccessAt 前进（LRU 的「刚用过」就是这一下）。
   */
  open(fileId, offset, length) {
    const found = this.get(fileId);
    if (!found.ok) return { error: found.reason };
    const entry = found.entry;
    if (entry.complete !== true) return { error: 'incomplete', size: entry.size };
    const at = Number(offset);
    if (!Number.isInteger(at) || at < 0 || at > entry.size) return { error: 'bad-offset', size: entry.size };
    const want = Math.min(
      Math.max(1, Number.isFinite(Number(length)) ? Math.floor(Number(length)) : GROUP_FILE_CHUNK_MAX),
      GROUP_FILE_CHUNK_MAX,
    );
    const take = Math.min(want, Math.max(0, entry.size - at));
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
    entry.lastAccessAt = this.now();
    this.writeMeta(entry);
    return { data, offset: at, size: entry.size, eof: at + data.length >= entry.size };
  }

  /** 列表（hub 视图）：**这一下也 touch** —— 面板上看过一眼就是「刚用过」 */
  list() {
    const at = this.now();
    const rows = [];
    for (const entry of this.entries.values()) {
      if (entry.complete !== true) continue;
      entry.lastAccessAt = at;
      this.writeMeta(entry);
      rows.push({ ...entry });
    }
    rows.sort((left, right) => (right.lastAccessAt - left.lastAccessAt)
      || (right.createdAt - left.createdAt)
      || String(left.fileId).localeCompare(String(right.fileId)));
    return rows;
  }

  /** 删一条（目录 + 内存 + 墓碑）。tombstone=false 只删不立碑（半路坏掉那种）。 */
  drop(fileId, reason = 'drop', { tombstone = true } = {}) {
    const id = parseGroupFileId(fileId);
    if (id === '') return false;
    const entry = this.entries.get(id);
    this.entries.delete(id);
    try {
      fs.rmSync(this.entryDir(id), { recursive: true, force: true });
    } catch { /* 已经不在 */ }
    if (tombstone) {
      this.noteGone(id);
      if (this.onEvict) {
        try {
          this.onEvict(id, reason);
        } catch (error) {
          this.log('evict-hook-failed id=' + id.slice(0, 8) + ' err=' + String(error?.message ?? error).slice(0, 48));
        }
      }
    }
    if (entry) {
      this.log('drop id=' + id.slice(0, 8) + ' bytes=' + entry.size + ' reason=' + reason
        + ' tombstone=' + (tombstone ? 'yes' : 'no'));
    }
    return entry !== undefined;
  }

  /** 条目级删除（路由的 withdraw / 用例）：字节没了，**公告留着翻 gone** */
  remove(fileId) {
    const id = parseGroupFileId(fileId);
    if (id === '') return { ok: false, error: 'unknown-file' };
    const existed = this.entries.has(id) || this.gone.has(id);
    if (!existed) return { ok: false, error: 'unknown-file' };
    this.drop(id, 'removed', { tombstone: true });
    return { ok: true, removed: true };
  }

  /** 配额清扫：逐出到「已用 + reserve <= 配额」为止，返回本趟逐出的 id */
  sweepQuota(nowMs = this.now(), reserve = 0) {
    const at = Number.isFinite(Number(nowMs)) ? Number(nowMs) : this.now();
    const room = Math.max(0, positiveInt(reserve, 0));
    const evicted = [];
    let used = this.used;
    while (used + room > this.quotaBytes) {
      const victim = [...this.entries.values()]
        .filter((entry) => entry.complete === true)
        .sort((left, right) => (
          (left.lastAccessAt - right.lastAccessAt)
          || (left.createdAt - right.createdAt)
          || String(left.fileId).localeCompare(String(right.fileId))
        ))[0];
      if (!victim) break;
      used -= Number(victim.size) || 0;
      this.drop(victim.fileId, 'quota', { tombstone: true });
      evicted.push(victim.fileId);
    }
    if (evicted.length > 0) this.log('quota-evict n=' + evicted.length + ' used=' + this.used + ' at=' + at);
    return evicted;
  }

  /** 半截上传清扫：空闲超过 uploadIdleMs 的（永不碰已收完的文件） */
  sweepUploads(nowMs = this.now()) {
    const at = Number.isFinite(Number(nowMs)) ? Number(nowMs) : this.now();
    const dropped = [];
    for (const entry of [...this.entries.values()]) {
      if (entry.complete === true) continue;
      const idle = at - (Number(entry.lastAccessAt) || 0);
      if (idle < this.uploadIdleMs) continue;
      this.drop(entry.fileId, 'abandoned', { tombstone: false });
      dropped.push(entry.fileId);
    }
    if (dropped.length > 0) this.log('upload-sweep n=' + dropped.length);
    return dropped;
  }

  /** 一趟清扫（半截 + 配额），返回 {uploads, evicted} */
  sweep(nowMs = this.now()) {
    const uploads = this.sweepUploads(nowMs);
    const evicted = this.sweepQuota(nowMs, 0);
    return { uploads, evicted, used: this.used };
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
    }, GROUP_FILES_SWEEP_MS);
    this.timer.unref?.();
  }

  close() {
    if (!this.timer) return;
    clearInterval(this.timer);
    this.timer = null;
  }
}

/**
 * 公告平面（hub 权威、成员只读镜像）：<stateDir>/group-files.json，形状 {rev, files}。
 *
 * 为什么复用「notes/votePlane 那种平面」而不新加一个群消息 kind：
 * 老 peer 收到不认识的 kind 会 400 整条消息 —— 加一个 kind 等于把公告变成
 * 「要么升级所有节点、要么谁都收不到」。平面是搭同一次 pull 回来的，rev 门控。
 */
export class GroupFilesPlane {
  constructor(options = {}) {
    const stateDir = String(options.stateDir ?? process.cwd());
    this.path = path.join(stateDir, GROUP_FILES_PLANE_FILE);
    this.now = typeof options.now === 'function' ? options.now : Date.now;
    this.limit = positiveInt(options.limit, GROUP_FILES_LIMIT);
    this.logger = typeof options.logger === 'function' ? options.logger : null;
    this.data = normalizeFilesPlane(readJson(this.path));
  }

  log(text) {
    if (this.logger) this.logger('[group-files] ' + text);
  }

  value() {
    return normalizeFilesPlane(this.data);
  }

  save() {
    try {
      writeJson(this.path, this.data);
    } catch (error) {
      this.log('plane-write-failed err=' + String(error?.message ?? error).slice(0, 48));
    }
  }

  trim() {
    if (this.data.files.length <= this.limit) return;
    // 只丢最旧的；墓碑优先丢（活着的那条还没人看完）
    const keep = [...this.data.files];
    while (keep.length > this.limit) {
      const index = keep.findIndex((entry) => entry.gone === true);
      keep.splice(index >= 0 ? index : 0, 1);
    }
    this.data.files = keep;
  }

  /** 公告一条（幂等：内容一样的重放不动 rev） */
  announce(raw) {
    const entry = makePlaneEntry(raw);
    if (!entry) return { ok: false, error: 'bad-request', rev: this.data.rev };
    const at = this.now();
    const next = { ...entry, at: entry.at > 0 ? entry.at : at, gone: false };
    const index = this.data.files.findIndex((row) => row.fileId === next.fileId);
    if (index >= 0) {
      const current = this.data.files[index];
      const same = current.name === next.name && current.size === next.size
        && current.sha256 === next.sha256 && current.gone === false
        && JSON.stringify(current.targets) === JSON.stringify(next.targets);
      if (same) return { ok: true, rev: this.data.rev, changed: false, fileId: next.fileId };
      const files = [...this.data.files];
      files[index] = next;
      this.data = { rev: this.data.rev + 1, files };
    } else {
      this.data = { rev: this.data.rev + 1, files: [...this.data.files, next] };
    }
    this.trim();
    this.save();
    this.log('announce id=' + next.fileId.slice(0, 8) + ' rev=' + this.data.rev + ' bytes=' + next.size);
    return { ok: true, rev: this.data.rev, changed: true, fileId: next.fileId };
  }

  /**
   * 翻成 gone（逐出/收回）：条目**留在平面里**。
   * 删掉它才是错的 —— 成员会看到「凭空消失」，一句「已失效」都没得说。
   */
  markGone(fileIds) {
    const ids = (Array.isArray(fileIds) ? fileIds : [fileIds]).map((id) => parseGroupFileId(id));
    let changed = false;
    const files = this.data.files.map((entry) => {
      if (entry.gone === true) return entry;
      if (!ids.includes(entry.fileId)) return entry;
      changed = true;
      return { ...entry, gone: true };
    });
    if (!changed) return { rev: this.data.rev, changed: false };
    this.data = { rev: this.data.rev + 1, files };
    this.save();
    this.log('gone n=' + ids.length + ' rev=' + this.data.rev);
    return { rev: this.data.rev, changed: true };
  }

  /** 成员侧合并（只读镜像）：rev 更大才采纳 */
  setReplica(raw) {
    const current = this.value();
    const merged = mergeFilesPlane(current, raw);
    const adopted = merged.rev !== current.rev;
    if (adopted) {
      this.data = merged;
      this.save();
    }
    return { rev: merged.rev, count: merged.files.length, adopted };
  }
}

/**
 * 本机**已下载**的群文件（成员侧小台账，只为面板把 downloaded 显示成真的）。
 * 不存名字不存路径：只记 fileId → {size, sha256, at}。
 */
export class GroupFileDownloads {
  constructor(options = {}) {
    const stateDir = String(options.stateDir ?? process.cwd());
    this.path = path.join(stateDir, GROUP_FILES_DOWNLOADS_FILE);
    this.now = typeof options.now === 'function' ? options.now : Date.now;
    this.data = readJson(this.path);
    this.entries = new Map();
    const raw = this.data && typeof this.data === 'object' && this.data.files && typeof this.data.files === 'object'
      ? this.data.files
      : {};
    for (const [fileId, row] of Object.entries(raw)) {
      const id = parseGroupFileId(fileId);
      if (id === '') continue;
      this.entries.set(id, {
        fileId: id,
        size: nonNegativeInt(row?.size),
        sha256: asText(row?.sha256).toLowerCase(),
        at: Number(row?.at) || 0,
      });
    }
  }

  save() {
    writeJson(this.path, { files: Object.fromEntries(this.entries) });
  }

  has(fileId) {
    return this.entries.has(parseGroupFileId(fileId));
  }

  get(fileId) {
    return this.entries.get(parseGroupFileId(fileId)) ?? null;
  }

  add(fileId, input = {}) {
    const id = parseGroupFileId(fileId);
    if (id === '') return { ok: false, error: 'bad-request' };
    this.entries.set(id, {
      fileId: id,
      size: nonNegativeInt(input.size),
      sha256: asText(input.sha256).toLowerCase(),
      at: this.now(),
    });
    this.save();
    return { ok: true, fileId: id };
  }

  remove(fileId) {
    const id = parseGroupFileId(fileId);
    if (!this.entries.delete(id)) return { ok: false, removed: false };
    this.save();
    return { ok: true, removed: true };
  }

  list() {
    return [...this.entries.values()];
  }
}

/**
 * 把三块拼在一起（server 与单测都走这里，逐出 → 平面翻 gone 只在这一处接线）。
 * close() 清掉清扫定时器。
 */
export function createGroupFiles(options = {}) {
  const logger = typeof options.logger === 'function' ? options.logger : null;
  const plane = new GroupFilesPlane({ stateDir: options.stateDir, now: options.now, limit: options.limit, logger });
  const store = new GroupFileStore({
    stateDir: options.stateDir,
    now: options.now,
    quotaBytes: options.quotaBytes,
    maxUploads: options.maxUploads,
    uploadIdleMs: options.uploadIdleMs,
    logger,
    onEvict: (fileId) => plane.markGone([fileId]),
  });
  const downloads = new GroupFileDownloads({ stateDir: options.stateDir, now: options.now });
  if (options.start !== false) store.start();
  return {
    store,
    plane,
    downloads,
    /** 平面路径（运维/用例要能指着它） */
    planePath: plane.path,
    sweep: (nowMs) => {
      const out = store.sweep(nowMs);
      return out;
    },
    close: () => store.close(),
  };
}
