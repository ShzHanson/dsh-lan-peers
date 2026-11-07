// dsh-lan-peers · 入站文件存储（0.8.5-α 契约 §2）。
//
// 三块区域，全部在 <stateDir>/inbox/ 下面，**落盘路径只由本模块拼**：
//   inbox/                      最终文件（<id>__<清洗后文件名>）
//   inbox/.pending/<id>/        待确认（data + meta.json）
//   inbox/.incoming/<id>.part   传输中（顺序追加；断点续传的锚点）
//
// 铁律：对端只能给「名字」和「字节」，不能给路径。名字先过 sanitizeFileName()，
// 任何目录成分在那一步就被丢掉；路径只由服务端生成的 id 拼出来。
// 日志只记 size / sha256 前 8 位 / 状态，绝不记文件名与内容。
import { createHash, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const FILE_ROOT_DIR = 'inbox';
export const FILE_PENDING_DIR = '.pending';
export const FILE_INCOMING_DIR = '.incoming';
export const FILE_INDEX_FILE = '.index.json';
export const FILE_META_FILE = 'meta.json';
export const FILE_DATA_FILE = 'data';

/** 文件名长度上限（含扩展名） */
export const FILE_NAME_MAX_CHARS = 128;
/** 并发传输上限（契约 §2） */
export const FILE_MAX_CONCURRENT = 2;
/** 单块硬上限：与 host 的 MAX_BODY_BYTES(1MiB) 留足 base64 + JSON 余量 */
export const FILE_CHUNK_HARD_MAX = 512 * 1024;

export const FILE_DEFAULT_MAX_BYTES = 512 * 1024 * 1024;
export const FILE_DEFAULT_INBOX_BYTES = 2 * 1024 * 1024 * 1024;
export const FILE_DEFAULT_CHUNK_BYTES = 512 * 1024;
export const FILE_DEFAULT_PENDING_TTL_MS = 600_000;

/** 服务端生成的 id（randomUUID）；任何外部传入的 id 都要先过这关才能拼路径 */
const ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
/** transferId 只存在于内存索引，不进路径，但也别让它无界 */
const TRANSFER_LIMIT = 512;

const RESERVED_NAMES = new Set([
  'CON', 'PRN', 'AUX', 'NUL',
  ...Array.from({ length: 9 }, (_, index) => 'COM' + (index + 1)),
  ...Array.from({ length: 9 }, (_, index) => 'LPT' + (index + 1)),
]);

/** 不可见字符：C0/C1 控制符、零宽、行/段分隔符、BOM */
const CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028\u2029\ufeff]/g;
const PATH_SEPARATORS = /[\\/]+/;
const FORBIDDEN_CHARS = /[:\\/]/g;
const TRAILING_DOTS_SPACES = /[. ]+$/;

/** Windows 保留设备名（按扩展名前的躯干判定，大小写无关） */
export function isReservedFileName(raw) {
  const stem = String(raw ?? '').split('.').shift().trim().toUpperCase();
  return RESERVED_NAMES.has(stem);
}

/**
 * 清洗对端给的文件名：返回可落盘的名字；无法安全使用时返回 ''（调用方据此 bad-name）。
 *   ../x         -> x        （目录成分被丢掉）
 *   a/b          -> b
 *   C:\tmp\x.exe -> x.exe
 *   CON / con.txt-> ''       （保留设备名直接拒收）
 *   控制符/零宽   -> 删除
 *   尾部点/空格   -> 删除（Windows 落盘会吃掉它们，留着会出现两个不同名字同一文件）
 *   超长          -> 截躯干、保扩展名，总长 ≤128
 */
export function sanitizeFileName(raw) {
  const source = String(raw ?? '');
  const tail = source.split(PATH_SEPARATORS).filter((part) => part !== '').pop() ?? '';
  const name = tail
    .replace(FORBIDDEN_CHARS, '_')
    .replace(CONTROL_CHARS, '')
    .trim()
    .replace(TRAILING_DOTS_SPACES, '');
  if (name === '' || name === '.' || name === '..') return '';
  const dot = name.lastIndexOf('.');
  const hasExtension = dot > 0 && dot < name.length - 1;
  const stem = hasExtension ? name.slice(0, dot) : name;
  let extension = hasExtension ? name.slice(dot) : '';
  if (isReservedFileName(stem)) return '';
  if (stem.trim() === '') return '';
  // 扩展名自己就超长（或把躯干挤没了）时丢掉它，宁可少个后缀也不能超长
  if (extension.length >= FILE_NAME_MAX_CHARS) extension = '';
  const budget = Math.max(1, FILE_NAME_MAX_CHARS - extension.length);
  return stem.slice(0, budget) + extension;
}

/** 流式 sha256：512MB 的文件不能整体读进内存 */
export async function hashFile(filePath) {
  const hash = createHash('sha256');
  const stream = fs.createReadStream(filePath);
  for await (const chunk of stream) hash.update(chunk);
  return hash.digest('hex');
}

/** 日志用：只暴露前 8 位 */
export function shortSha(sha256) {
  return String(sha256 ?? '').slice(0, 8);
}

function writeJsonFile0600(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = file + '.tmp-' + process.pid + '-' + randomUUID().slice(0, 8);
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmp, file);
}

function readJsonFile(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

function positiveInt(value, fallback, { min = 1, max = Number.MAX_SAFE_INTEGER } = {}) {
  const numeric = Math.floor(Number(value));
  if (!Number.isFinite(numeric) || numeric < min) return fallback;
  return Math.min(numeric, max);
}

/**
 * 入站文件存储。所有时间来自注入的 now()，用例可以用假时钟驱动 TTL。
 *
 * 状态机（一个 transferId 走完一遍）：
 *   offer    -> 新建/复用 .incoming/<id>.part，返回 resumeFrom
 *   chunk    -> 顺序追加（offset != 已收字节 一律 409）
 *   complete -> sha256 校验通过后搬进 .pending/<id>/，autoAccept 时直接进 inbox
 */
export class FileStore {
  constructor(options = {}) {
    const stateDir = String(options.stateDir ?? process.cwd());
    this.inboxDir = path.join(stateDir, FILE_ROOT_DIR);
    this.pendingDir = path.join(this.inboxDir, FILE_PENDING_DIR);
    this.incomingDir = path.join(this.inboxDir, FILE_INCOMING_DIR);
    this.indexPath = path.join(this.inboxDir, FILE_INDEX_FILE);
    this.now = typeof options.now === 'function' ? options.now : Date.now;
    this.maxFileBytes = positiveInt(options.maxBytes, FILE_DEFAULT_MAX_BYTES);
    this.inboxLimitBytes = positiveInt(options.inboxBytes, FILE_DEFAULT_INBOX_BYTES);
    this.defaultChunkBytes = positiveInt(options.chunkBytes, FILE_DEFAULT_CHUNK_BYTES, {
      min: 1,
      max: FILE_CHUNK_HARD_MAX,
    });
    this.ttlMs = positiveInt(options.pendingTtlMs, FILE_DEFAULT_PENDING_TTL_MS, { min: 1 });
    this.autoAccept = options.autoAccept === true;
    this.logger = typeof options.logger === 'function' ? options.logger : null;
    this.timer = null;

    /** sha256 -> part(传输中) */
    this.parts = new Map();
    /** transferId -> { sha256, id, size, state, received, from, at } */
    this.transfers = new Map();
    /** id -> meta.json */
    this.pending = new Map();
    /** sha256 -> { id, name, size, file, from, at } */
    this.index = new Map();

    this.ensureDirs();
    this.loadIndex();
    this.loadPending();
    this.loadIncoming();
  }

  // ---- 目录与索引 ---------------------------------------------------------

  ensureDirs() {
    fs.mkdirSync(this.inboxDir, { recursive: true, mode: 0o700 });
    fs.mkdirSync(this.pendingDir, { recursive: true, mode: 0o700 });
    fs.mkdirSync(this.incomingDir, { recursive: true, mode: 0o700 });
  }

  loadIndex() {
    const raw = readJsonFile(this.indexPath);
    const files = raw && typeof raw.files === 'object' && raw.files ? raw.files : {};
    for (const [sha256, entry] of Object.entries(files)) {
      if (!entry || typeof entry !== 'object') continue;
      const file = String(entry.file ?? '');
      if (!ID_PATTERN.test(String(entry.id ?? '')) || file === '') continue;
      if (!fs.existsSync(path.join(this.inboxDir, file))) continue;
      this.index.set(String(sha256), {
        id: String(entry.id),
        name: String(entry.name ?? ''),
        size: Number(entry.size) || 0,
        file,
        sha256: String(sha256),
        from: entry.from && typeof entry.from === 'object'
          ? { peerId: String(entry.from.peerId ?? ''), name: String(entry.from.name ?? '') }
          : { peerId: '', name: '' },
        at: Number(entry.at) || 0,
      });
    }
  }

  saveIndex() {
    const files = {};
    for (const [sha256, entry] of this.index) {
      files[sha256] = {
        id: entry.id,
        name: entry.name,
        size: entry.size,
        file: entry.file,
        from: entry.from,
        at: entry.at,
      };
    }
    writeJsonFile0600(this.indexPath, { files });
  }

  loadPending() {
    let entries = [];
    try {
      entries = fs.readdirSync(this.pendingDir, { withFileTypes: true });
    } catch {
      entries = [];
    }
    for (const entry of entries) {
      if (!entry.isDirectory() || !ID_PATTERN.test(entry.name)) continue;
      const dir = path.join(this.pendingDir, entry.name);
      const meta = readJsonFile(path.join(dir, FILE_META_FILE));
      if (!meta || !fs.existsSync(path.join(dir, FILE_DATA_FILE))) {
        // 半路写坏（掉电/进程被杀）的待确认条目直接清掉，别让它占着配额
        try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* 已经不在 */ }
        continue;
      }
      this.pending.set(entry.name, {
        id: entry.name,
        name: String(meta.name ?? ''),
        size: Number(meta.size) || 0,
        sha256: String(meta.sha256 ?? ''),
        from: meta.from && typeof meta.from === 'object'
          ? { peerId: String(meta.from.peerId ?? ''), name: String(meta.from.name ?? '') }
          : { peerId: '', name: '' },
        at: Number(meta.at) || 0,
      });
    }
  }

  loadIncoming() {
    let entries = [];
    try {
      entries = fs.readdirSync(this.incomingDir, { withFileTypes: true });
    } catch {
      entries = [];
    }
    for (const entry of entries) {
      if (!entry.isFile() || !entry.name.endsWith('.part')) continue;
      const id = entry.name.slice(0, -'.part'.length);
      if (!ID_PATTERN.test(id)) continue;
      const metaPath = path.join(this.incomingDir, id + '.json');
      const meta = readJsonFile(metaPath);
      const full = path.join(this.incomingDir, entry.name);
      if (!meta || typeof meta.sha256 !== 'string' || meta.sha256 === '') {
        try { fs.rmSync(full, { force: true }); } catch { /* 已经不在 */ }
        continue;
      }
      const part = {
        id,
        name: String(meta.name ?? ''),
        size: Number(meta.size) || 0,
        sha256: String(meta.sha256),
        from: meta.from && typeof meta.from === 'object'
          ? { peerId: String(meta.from.peerId ?? ''), name: String(meta.from.name ?? '') }
          : { peerId: '', name: '' },
        path: full,
        received: this.partSize(full),
        updatedAt: Number(meta.updatedAt) || this.now(),
      };
      this.parts.set(part.sha256, part);
    }
  }

  // ---- 内部工具 -----------------------------------------------------------

  log(text) {
    if (this.logger) this.logger('[file] ' + text);
  }

  partSize(file) {
    try {
      return fs.statSync(file).size;
    } catch {
      return 0;
    }
  }

  safeId(rawId) {
    const id = String(rawId ?? '');
    return ID_PATTERN.test(id) ? id : '';
  }

  activeIncoming() {
    return this.parts.size;
  }

  usedBytes() {
    let total = 0;
    for (const entry of this.index.values()) total += entry.size;
    for (const meta of this.pending.values()) total += meta.size;
    for (const part of this.parts.values()) total += part.size;
    return total;
  }

  registerTransfer(transferId, record) {
    const id = String(transferId ?? '');
    if (id === '') return;
    if (this.transfers.size >= TRANSFER_LIMIT && !this.transfers.has(id)) {
      const oldest = this.transfers.keys().next().value;
      if (oldest !== undefined) this.transfers.delete(oldest);
    }
    this.transfers.set(id, record);
  }

  writePartMeta(part) {
    try {
      writeJsonFile0600(path.join(this.incomingDir, part.id + '.json'), {
        id: part.id,
        name: part.name,
        size: part.size,
        sha256: part.sha256,
        from: part.from,
        updatedAt: part.updatedAt,
      });
    } catch (error) {
      this.log('meta-failed sha=' + shortSha(part.sha256) + ' err=' + String(error?.message ?? error));
    }
  }

  createPart({ name, size, sha256, from }) {
    const id = randomUUID();
    const part = {
      id,
      name,
      size,
      sha256,
      from,
      path: path.join(this.incomingDir, id + '.part'),
      received: 0,
      updatedAt: this.now(),
    };
    fs.writeFileSync(part.path, Buffer.alloc(0), { mode: 0o600 });
    this.parts.set(sha256, part);
    this.writePartMeta(part);
    return part;
  }

  dropPart(part) {
    if (!part) return;
    this.parts.delete(part.sha256);
    try { fs.rmSync(part.path, { force: true }); } catch { /* 已经不在 */ }
    try { fs.rmSync(path.join(this.incomingDir, part.id + '.json'), { force: true }); } catch { /* 已经不在 */ }
  }

  // ---- 协议三步 -----------------------------------------------------------

  /**
   * 契约 §1 offer。返回 { accept:true, resumeFrom, dedupe } 或 { accept:false, reason }。
   * reason ∈ too-large | inbox-full | busy | bad-name | duplicate-pending
   * （bad-request 只可能出现在字段本身不合法时；HTTP 层已先校验，正常对端碰不到）
   */
  offer(input = {}) {
    const transferId = String(input.transferId ?? '');
    const size = Number(input.size);
    const sha256 = String(input.sha256 ?? '').toLowerCase();
    const from = {
      peerId: String(input.from?.peerId ?? ''),
      name: String(input.from?.name ?? ''),
    };
    if (!Number.isFinite(size) || size < 0 || Math.floor(size) !== size || !/^[0-9a-f]{64}$/.test(sha256)) {
      return { accept: false, reason: 'bad-request' };
    }
    const name = sanitizeFileName(input.name);
    if (name === '') return { accept: false, reason: 'bad-name' };

    const wanted = Math.floor(Number(input.chunkBytes));
    const chunkBytes = Number.isFinite(wanted) && wanted > 0
      ? Math.min(wanted, FILE_CHUNK_HARD_MAX)
      : this.defaultChunkBytes;

    // 1) 去重：同一个 sha256 已经在盘上 → 不重传
    const known = this.index.get(sha256);
    if (known) {
      this.registerTransfer(transferId, {
        sha256, id: known.id, size: known.size, state: 'done', received: known.size, from, at: this.now(),
      });
      this.log('offer size=' + size + ' sha=' + shortSha(sha256) + ' accept=1 dedupe=1');
      return { accept: true, resumeFrom: size, dedupe: true };
    }
    // 2) 待确认区里有同一份 → 让先来的那份走完流程，别在 inbox 里堆两份
    for (const meta of this.pending.values()) {
      if (meta.sha256 === sha256) return { accept: false, reason: 'duplicate-pending' };
    }
    // 3) 单文件限额
    if (size > this.maxFileBytes) {
      this.log('offer size=' + size + ' sha=' + shortSha(sha256) + ' accept=0 reason=too-large');
      return { accept: false, reason: 'too-large' };
    }

    let part = this.parts.get(sha256) ?? null;
    if (part && part.size !== size) {
      // 同名不同长 = 换了内容，旧分片作废（sha256 相同就不可能有这个分支，防御性）
      this.dropPart(part);
      part = null;
    }
    if (!part) {
      if (this.activeIncoming() >= FILE_MAX_CONCURRENT) {
        this.log('offer size=' + size + ' sha=' + shortSha(sha256) + ' accept=0 reason=busy');
        return { accept: false, reason: 'busy' };
      }
      if (this.usedBytes() + size > this.inboxLimitBytes) {
        this.log('offer size=' + size + ' sha=' + shortSha(sha256) + ' accept=0 reason=inbox-full');
        return { accept: false, reason: 'inbox-full' };
      }
      part = this.createPart({ name, size, sha256, from });
    }

    // 4) resumeFrom 以磁盘为准：发送端被 kill 过就是这样接上的
    part.received = this.partSize(part.path);
    if (part.received > size) {
      fs.truncateSync(part.path, size);
      part.received = size;
    }
    part.updatedAt = this.now();
    if (part.name !== name) part.name = name;
    this.registerTransfer(transferId, {
      sha256, id: part.id, size, state: 'incoming', received: part.received, from, at: this.now(),
    });
    this.writePartMeta(part);
    this.log('offer size=' + size + ' sha=' + shortSha(sha256) + ' accept=1 resume=' + part.received + ' chunk=' + chunkBytes);
    return { accept: true, resumeFrom: part.received, dedupe: false };
  }

  /**
   * 契约 §1 chunk：offset 必须等于已收字节（顺序追加，没有空洞可填）。
   * 返回 { received } 或 { error: bad-offset, expected } / { error: unknown-transfer | too-large }
   */
  writeChunk(input = {}) {
    const transferId = String(input.transferId ?? '');
    const transfer = this.transfers.get(transferId);
    if (!transfer) return { error: 'unknown-transfer' };
    const part = this.parts.get(transfer.sha256);
    if (!part) {
      // 已经 complete（或已被清理）：重复推送同一批块时如实回报累计值
      if (transfer.state === 'done' || transfer.state === 'pending') return { received: transfer.size };
      return { error: 'unknown-transfer' };
    }
    const offset = Number(input.offset);
    if (!Number.isFinite(offset) || Math.floor(offset) !== offset) return { error: 'bad-offset', expected: part.received };
    if (offset !== part.received) return { error: 'bad-offset', expected: part.received };
    const bytes = Buffer.isBuffer(input.data) ? input.data : Buffer.from(input.data ?? Buffer.alloc(0));
    if (bytes.length === 0) return { received: part.received };
    if (bytes.length > FILE_CHUNK_HARD_MAX) return { error: 'too-large' };
    if (part.received + bytes.length > part.size) return { error: 'too-large' };
    try {
      fs.appendFileSync(part.path, bytes);
    } catch (error) {
      this.log('chunk-failed sha=' + shortSha(part.sha256) + ' err=' + String(error?.message ?? error));
      return { error: 'write-failed' };
    }
    part.received += bytes.length;
    part.updatedAt = this.now();
    transfer.received = part.received;
    return { received: part.received };
  }

  /** 契约 §1 complete：整体 sha256 对齐后才搬进待确认区 */
  async complete(input = {}) {
    const transferId = String(input.transferId ?? '');
    const transfer = this.transfers.get(transferId);
    if (!transfer) return { error: 'unknown-transfer' };
    if (transfer.state === 'done') return { ok: true, id: transfer.id, needConfirm: false };
    if (transfer.state === 'pending') return { ok: true, id: transfer.id, needConfirm: true };
    const part = this.parts.get(transfer.sha256);
    if (!part) return { error: 'unknown-transfer' };

    part.received = this.partSize(part.path);
    if (part.received !== part.size) return { error: 'incomplete', received: part.received };

    const digest = await hashFile(part.path);
    if (digest.toLowerCase() !== part.sha256) {
      this.dropPart(part);
      for (const other of this.transfers.values()) {
        if (other.sha256 === transfer.sha256 && other.state === 'incoming') other.state = 'rejected';
      }
      this.log('complete size=' + part.size + ' sha=' + shortSha(part.sha256) + ' got=' + shortSha(digest) + ' state=rejected reason=checksum-mismatch');
      return { error: 'checksum-mismatch' };
    }

    const id = part.id;
    const dir = path.join(this.pendingDir, id);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    try {
      fs.renameSync(part.path, path.join(dir, FILE_DATA_FILE));
    } catch (error) {
      this.log('complete size=' + part.size + ' sha=' + shortSha(part.sha256) + ' state=rejected reason=move-failed');
      return { error: 'move-failed', detail: String(error?.message ?? error) };
    }
    this.parts.delete(part.sha256);
    try { fs.rmSync(path.join(this.incomingDir, part.id + '.json'), { force: true }); } catch { /* 已经不在 */ }

    const meta = { id, name: part.name, size: part.size, sha256: part.sha256, from: part.from, at: this.now() };
    writeJsonFile0600(path.join(dir, FILE_META_FILE), meta);
    this.pending.set(id, { id, name: meta.name, size: meta.size, sha256: meta.sha256, from: meta.from, at: meta.at });
    for (const other of this.transfers.values()) {
      if (other.sha256 === meta.sha256) {
        other.id = id;
        other.state = this.autoAccept ? 'done' : 'pending';
      }
    }
    this.log('complete size=' + meta.size + ' sha=' + shortSha(meta.sha256) + ' state=pending autoAccept=' + (this.autoAccept ? 1 : 0));

    if (this.autoAccept) {
      const accepted = this.accept(id);
      if (accepted.ok) return { ok: true, id, needConfirm: false, path: accepted.path };
      // 自动确认失败也绝不丢文件：退回到「等人工确认」
      for (const other of this.transfers.values()) {
        if (other.sha256 === meta.sha256) other.state = 'pending';
      }
    }
    return { ok: true, id, needConfirm: true };
  }

  /** GET /v1/file/status；未知 transferId 返回 null（HTTP 层据此 404） */
  status(transferId) {
    const transfer = this.transfers.get(String(transferId ?? ''));
    if (!transfer) return null;
    if (transfer.state === 'done') {
      return { received: transfer.size, size: transfer.size, state: 'done' };
    }
    if (transfer.state === 'pending') {
      return { received: transfer.size, size: transfer.size, state: 'pending' };
    }
    if (transfer.state === 'rejected') {
      return { received: transfer.received ?? 0, size: transfer.size, state: 'rejected' };
    }
    const part = this.parts.get(transfer.sha256);
    const received = part ? part.received : 0;
    return { received, size: transfer.size, state: 'incoming' };
  }

  // ---- 门面（契约 §3） ----------------------------------------------------

  /**
   * 传输中的条目（接收侧进度）：`.incoming/<id>.json` 的元数据 + `.part` 的**实际**字节数。
   * received 现取现 stat，不走内存里的缓存值 —— 面板/CLI 要的就是「现在到了多少」。
   */
  listIncoming() {
    const out = [];
    for (const part of this.parts.values()) {
      out.push({
        id: part.id,
        name: part.name,
        size: part.size,
        received: this.partSize(part.path),
        from: { peerId: part.from?.peerId ?? '', name: part.from?.name ?? '' },
        at: part.updatedAt,
        state: 'incoming',
      });
    }
    return out;
  }

  list() {
    const out = [];
    for (const meta of this.pending.values()) {
      out.push({
        id: meta.id,
        name: meta.name,
        size: meta.size,
        sha256: meta.sha256,
        from: { peerId: meta.from.peerId, name: meta.from.name },
        at: meta.at,
        state: 'pending',
      });
    }
    for (const entry of this.index.values()) {
      out.push({
        id: entry.id,
        name: entry.name,
        size: entry.size,
        sha256: entry.sha256,
        from: { peerId: entry.from.peerId, name: entry.from.name },
        at: entry.at,
        state: 'done',
      });
    }
    // 传输中的条目自成第三桶：state:'incoming'。调用方（管理接口/面板/CLI）按 state 分桶，
    // 所以它们不会被误当成 pending（可 accept/reject）或 done。
    out.push(...this.listIncoming());
    out.sort((left, right) => Number(right.at) - Number(left.at));
    return out;
  }

  accept(rawId) {
    const id = this.safeId(rawId);
    if (id === '') return { ok: false, reason: 'unknown-id' };
    const meta = this.pending.get(id);
    if (!meta) return { ok: false, reason: 'not-pending' };
    const dir = path.join(this.pendingDir, id);
    const source = path.join(dir, FILE_DATA_FILE);
    // 最终名：服务端 id 前缀 + 已清洗的名字。两者都不是对端可控的路径成分。
    const file = id + '__' + meta.name;
    const target = path.join(this.inboxDir, file);
    try {
      if (!fs.existsSync(source)) throw new Error('missing-data');
      fs.renameSync(source, target);
    } catch (error) {
      this.log('accept state=failed sha=' + shortSha(meta.sha256) + ' err=' + String(error?.message ?? error));
      return { ok: false, reason: 'move-failed' };
    }
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* 已经不在 */ }
    this.pending.delete(id);
    this.index.set(meta.sha256, {
      id,
      name: meta.name,
      size: meta.size,
      file,
      sha256: meta.sha256,
      from: meta.from,
      at: meta.at,
    });
    try {
      this.saveIndex();
    } catch (error) {
      this.log('accept state=done sha=' + shortSha(meta.sha256) + ' index-write-failed=' + String(error?.message ?? error));
    }
    for (const other of this.transfers.values()) {
      if (other.sha256 === meta.sha256) other.state = 'done';
    }
    this.log('accept size=' + meta.size + ' sha=' + shortSha(meta.sha256) + ' state=done');
    return { ok: true, id, path: target };
  }

  reject(rawId) {
    const id = this.safeId(rawId);
    if (id === '') return { ok: false, reason: 'unknown-id' };
    const meta = this.pending.get(id);
    if (!meta) return { ok: false, reason: 'not-pending' };
    try { fs.rmSync(path.join(this.pendingDir, id), { recursive: true, force: true }); } catch { /* 已经不在 */ }
    this.pending.delete(id);
    for (const other of this.transfers.values()) {
      if (other.sha256 === meta.sha256) other.state = 'rejected';
    }
    this.log('reject size=' + meta.size + ' sha=' + shortSha(meta.sha256) + ' state=rejected');
    return { ok: true, id };
  }

  progress(rawId) {
    const id = this.safeId(rawId);
    if (id === '') return { received: 0, size: 0, state: 'unknown' };
    const meta = this.pending.get(id);
    if (meta) return { received: meta.size, size: meta.size, state: 'pending' };
    const done = this.index.get([...this.index.keys()].find((key) => this.index.get(key).id === id));
    if (done) return { received: done.size, size: done.size, state: 'done' };
    for (const part of this.parts.values()) {
      if (part.id === id) return { received: part.received, size: part.size, state: 'incoming' };
    }
    return { received: 0, size: 0, state: 'unknown' };
  }

  // ---- TTL 清理 -----------------------------------------------------------

  /** 未确认超过 ttl 的一律自动拒收删除；顺带清掉「发送端被 kill」留下的僵尸分片 */
  sweep(nowMs = this.now()) {
    const at = Number.isFinite(Number(nowMs)) ? Number(nowMs) : this.now();
    let removed = 0;
    for (const meta of [...this.pending.values()]) {
      if (at - Number(meta.at) < this.ttlMs) continue;
      this.reject(meta.id);
      removed += 1;
    }
    for (const part of [...this.parts.values()]) {
      if (at - Number(part.updatedAt) < this.ttlMs) continue;
      this.dropPart(part);
      for (const other of this.transfers.values()) {
        if (other.sha256 === part.sha256 && other.state === 'incoming') other.state = 'rejected';
      }
      this.log('sweep size=' + part.size + ' sha=' + shortSha(part.sha256) + ' state=rejected reason=ttl');
      removed += 1;
    }
    return removed;
  }

  /** 定时清理：unref（不吊住进程）+ close() 里清（热重载不留定时器） */
  start() {
    if (this.timer) return;
    const intervalMs = Math.max(1000, Math.min(60_000, Math.floor(this.ttlMs / 4)));
    this.timer = setInterval(() => {
      try {
        this.sweep();
      } catch (error) {
        this.log('sweep-failed err=' + String(error?.message ?? error));
      }
    }, intervalMs);
    this.timer.unref?.();
  }

  close() {
    if (!this.timer) return;
    clearInterval(this.timer);
    this.timer = null;
  }
}
