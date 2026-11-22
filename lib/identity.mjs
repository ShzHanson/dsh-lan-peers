// dsh-lan-peers · 身份密钥重置（危险区）：排定 → 备份 → 下次启动生效。
//
// 为什么不是「点一下立刻换身份」：instanceId 已经绑进签名与寻址（peers.json 的配对记录、
// 群成员的 peerId、对端手里的白名单），正在跑的进程里换掉它 = 所有在线链路立刻变哑，
// 且没有任何一条通知来得及发出去。所以动作拆成两段：
//   arm（管理接口，显式 confirm:'RESET'）—— 先整份备份身份material，再落一枚 pending 标记；
//   apply（启动时、监听之前）—— 先用**旧**密钥把「我要重置」通知给每个已配对伙伴，
//                                再重生 instanceId / 清空 peers.json / 删群身分文件 / 换 admin-token。
// 数据不是身份：消息历史、摘要、offers/outbox、dm、成员记录一律不碰（这里连路径都不知道）。
//
// 本模块无网络、无定时器：通知是注入进来的（notify），真实实现见 createPeerResetNotifier。
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';

/** pending 标记：存在即「已排定，下次启动生效」。 */
export const IDENTITY_MARKER_FILE = 'identity-reset-pending.json';
/** 备份目录前缀（目录名 = 前缀 + UTC 时间戳，人眼可读、可手抄）。 */
export const IDENTITY_BACKUP_PREFIX = 'identity-backup-';
/** 上次重置的结果（面板要能说清「通知了几个、失败几个」）。 */
export const IDENTITY_LAST_RESET_FILE = 'identity-last-reset.json';

/** 备份哪些文件：**身份material**，顺序即 README 里的顺序。 */
export const IDENTITY_BACKUP_FILES = Object.freeze([
  'state.json',
  'peers.json',
  'group-key.json',
  'group-role.json',
  'admin-token',
]);

/** 重置时要删掉的群身份文件（成员侧）。 */
export const IDENTITY_GROUP_FILES = Object.freeze(['group-key.json', 'group-role.json']);

const ADMIN_TOKEN_FILE = 'admin-token';
const STATE_FILE = 'state.json';
const PEERS_FILE = 'peers.json';

const TEMP_MARK = () => '.tmp-' + process.pid + '-' + randomBytes(4).toString('hex');

/** now 可注入：函数、毫秒数或 Date 三种形状都收。 */
function nowMs(now) {
  if (typeof now === 'function') return Number(now());
  if (now instanceof Date) return now.getTime();
  if (typeof now === 'number' && Number.isFinite(now)) return now;
  return Date.now();
}

/** UTC 时间戳：20260101T120000Z（不含冒号，任何文件系统都能用）。 */
export function utcStamp(now = Date.now) {
  const date = new Date(nowMs(now));
  const pad = (value) => String(value).padStart(2, '0');
  return String(date.getUTCFullYear())
    + pad(date.getUTCMonth() + 1)
    + pad(date.getUTCDate())
    + 'T'
    + pad(date.getUTCHours())
    + pad(date.getUTCMinutes())
    + pad(date.getUTCSeconds())
    + 'Z';
}

const isoOf = (now) => new Date(nowMs(now)).toISOString();

function dirOf(stateDir) {
  return String(stateDir ?? '').trim();
}

function readJsonOrNull(file) {
  let raw;
  try {
    raw = fs.readFileSync(file, 'utf8');
  } catch {
    return null;
  }
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

/** 0600 原子写（同目录临时文件 + rename，与 state.json / admin-token 同一手法）。 */
function writeFile0600(file, text) {
  const dir = path.dirname(file);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tmp = file + TEMP_MARK();
  fs.writeFileSync(tmp, text, { mode: 0o600 });
  try { fs.chmodSync(tmp, 0o600); } catch { /* Windows 上是尽力而为 */ }
  fs.renameSync(tmp, file);
  try { fs.chmodSync(file, 0o600); } catch { /* 同上 */ }
  return file;
}

const shortIdOf = (value) => String(value ?? '').slice(0, 8);

/** peers.json → [{ peerId, name, baseUrl, secret }]（读不出来就是空表：绝不因此崩）。 */
function readPeerRecords(stateDir) {
  const loaded = readJsonOrNull(path.join(stateDir, PEERS_FILE));
  const map = loaded && typeof loaded === 'object' && !Array.isArray(loaded) && loaded.peers
    && typeof loaded.peers === 'object' && !Array.isArray(loaded.peers)
    ? loaded.peers
    : {};
  const out = [];
  for (const peerId of Object.keys(map)) {
    const record = map[peerId] ?? {};
    out.push({
      peerId: String(peerId),
      name: String(record.name ?? ''),
      baseUrl: String(record.baseUrl ?? ''),
      secret: String(record.secret ?? ''),
    });
  }
  return out;
}

/** 最新的备份目录名（没有就空串）：只认前缀 + 干净的名字，绝不向外给路径。 */
function latestBackupName(stateDir) {
  let names;
  try {
    names = fs.readdirSync(stateDir);
  } catch {
    return '';
  }
  const backups = names.filter((name) => name.startsWith(IDENTITY_BACKUP_PREFIX)).sort();
  return backups.length === 0 ? '' : backups[backups.length - 1];
}

/**
 * 只读视图（GET identity 的数据源）：**没有密钥、没有路径**，只有状态与备份目录名。
 * 标记损坏时 resetPending=false（本机没有可执行的排定），resetAt 为空串。
 */
export function readIdentityState({ stateDir } = {}) {
  const dir = dirOf(stateDir);
  const view = {
    stateDir: dir,
    instanceIdShort: '',
    peerCount: 0,
    hasGroup: false,
    resetPending: false,
    resetAt: '',
    lastBackup: '',
    lastResetNotified: null,
  };
  if (dir === '') return view;
  const state = readJsonOrNull(path.join(dir, STATE_FILE));
  if (state && typeof state === 'object' && !Array.isArray(state)) {
    view.instanceIdShort = shortIdOf(state.instanceId);
  }
  view.peerCount = readPeerRecords(dir).length;
  view.hasGroup = IDENTITY_GROUP_FILES.some((name) => fs.existsSync(path.join(dir, name)));
  view.lastBackup = latestBackupName(dir);
  const marker = readJsonOrNull(path.join(dir, IDENTITY_MARKER_FILE));
  if (marker && typeof marker === 'object' && !Array.isArray(marker)) {
    view.resetPending = true;
    view.resetAt = String(marker.resetAt ?? '');
  }
  const last = readJsonOrNull(path.join(dir, IDENTITY_LAST_RESET_FILE));
  if (last && typeof last === 'object' && !Array.isArray(last)
    && (Number.isFinite(last.notified) || Number.isFinite(last.failed))) {
    view.lastResetNotified = {
      notified: Number.isFinite(Number(last.notified)) ? Number(last.notified) : 0,
      failed: Number.isFinite(Number(last.failed)) ? Number(last.failed) : 0,
    };
  }
  return view;
}

const README_LINES = Object.freeze([
  'dsh-lan-peers identity backup',
  '',
  'What this is: a byte-for-byte copy of this node identity material, taken',
  'right before a pending "reset identity keys" was armed. The reset applies',
  'on the NEXT START (arming itself changed nothing but this copy + a marker).',
  '',
  'Files (only the ones that existed at backup time are here):',
  '  state.json       instance id + device name   (identity)',
  '  peers.json       every pairing + secrets     (identity)',
  '  group-key.json   group membership key        (identity)',
  '  group-role.json  this node group role        (identity)',
  '  admin-token      admin API token             (identity)',
  '',
  'Not backed up on purpose (they are data, not identity, and the reset',
  'never touches them): message history, digests, offers/outbox, dm stores,',
  'participant and report state.',
  '',
  'How to restore by hand:',
  '  1. stop dsh-lan-peers (nothing may be running on this state dir);',
  '  2. delete identity-reset-pending.json in the state dir if it is still',
  '     there -- otherwise the next start applies the reset again;',
  '  3. copy every file from this directory back into the state dir',
  '     (overwrite what is there);',
  '  4. permissions: files 0600, directory 0700;',
  '  5. start dsh-lan-peers and check GET /api/lan-peers/identity.',
  '',
  'Peers that already received the "identity reset" notice may have dropped',
  'this node: pair with them again (a fresh pairing code) after restoring.',
  '',
  'This file contains no secrets: the secrets live in the copied files.',
]);

function writeReadme(backupDir, { at, reason, files }) {
  const lines = README_LINES.slice();
  const extra = ['', 'Backup taken at: ' + at];
  if (reason !== '') extra.push('Reason reported to peers: ' + reason);
  extra.push('Files in this backup: ' + (files.length === 0 ? '(none existed)' : files.join(', ')));
  writeFile0600(path.join(backupDir, 'README.txt'), extra.concat(lines).join('\n') + '\n');
}

/**
 * 备份身份material（只复制**存在**的那几个文件，逐个 0600，目录 0700），再落 pending 标记。
 * 调用方已经过了 confirm 闸：这里不再问第二遍。
 * @returns {{ok:true, backup:string, resetAt:string, files:string[]} | {ok:false, reason:string}}
 */
export function armIdentityReset({ stateDir, now = Date.now, reason = '' } = {}) {
  const dir = dirOf(stateDir);
  if (dir === '') return { ok: false, reason: 'no-state-dir' };
  const markerPath = path.join(dir, IDENTITY_MARKER_FILE);
  // 已排定就不再备份第二次：重复的备份只会让人分不清哪一份是「重置前」。
  if (fs.existsSync(markerPath)) return { ok: false, reason: 'already-pending' };

  const at = isoOf(now);
  const stamp = utcStamp(now);
  const cleanReason = String(reason ?? '').replace(/\s+/g, ' ').trim().slice(0, 32);
  let name = IDENTITY_BACKUP_PREFIX + stamp;
  let backupDir = path.join(dir, name);
  try {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    if (fs.existsSync(backupDir)) name = IDENTITY_BACKUP_PREFIX + stamp + '-' + randomBytes(2).toString('hex');
    backupDir = path.join(dir, name);
    fs.mkdirSync(backupDir, { recursive: true, mode: 0o700 });
    try { fs.chmodSync(backupDir, 0o700); } catch { /* 目录权限尽力而为 */ }
  } catch {
    return { ok: false, reason: 'backup-failed' };
  }

  const copied = [];
  try {
    for (const fileName of IDENTITY_BACKUP_FILES) {
      const source = path.join(dir, fileName);
      let bytes;
      try {
        bytes = fs.readFileSync(source);
      } catch (error) {
        if (error && error.code === 'ENOENT') continue;
        throw error;
      }
      const target = path.join(backupDir, fileName);
      fs.writeFileSync(target, bytes, { mode: 0o600 });
      try { fs.chmodSync(target, 0o600); } catch { /* 同上 */ }
      copied.push(fileName);
    }
    writeReadme(backupDir, { at, reason: cleanReason, files: copied });
  } catch {
    // 备份不完整就不落标记：宁可让这次排定失败，也不给一份靠不住的还原点。
    try { fs.rmSync(backupDir, { recursive: true, force: true }); } catch { /* 清不掉就留着 */ }
    return { ok: false, reason: 'backup-failed' };
  }

  const marker = {
    resetAt: at,
    reason: cleanReason,
    backup: name,
    instanceIdShort: shortIdOf(readJsonOrNull(path.join(dir, STATE_FILE))?.instanceId),
    requestedBy: 'admin',
  };
  try {
    writeFile0600(markerPath, JSON.stringify(marker, null, 2) + '\n');
  } catch {
    return { ok: false, reason: 'marker-failed' };
  }
  return { ok: true, backup: name, resetAt: at, files: copied };
}

/** 撤掉 pending 标记（重启前随时可撤）；没有标记时就是一次 no-op。 */
export function cancelIdentityReset({ stateDir } = {}) {
  const dir = dirOf(stateDir);
  if (dir === '') return { ok: false, reason: 'no-state-dir', removed: false };
  try {
    fs.unlinkSync(path.join(dir, IDENTITY_MARKER_FILE));
    return { ok: true, removed: true };
  } catch (error) {
    if (error && error.code === 'ENOENT') return { ok: true, removed: false };
    return { ok: false, reason: 'cancel-failed', removed: false };
  }
}

/** 备份目录名只认这种形状（纯 basename）：标记被手改过也绝不拼出状态目录之外的路径。 */
const SAFE_BACKUP_NAME = /^[A-Za-z0-9._-]+$/;

function ignore(log, reason) {
  if (typeof log === 'function') log('[identity] reset ignored reason=' + String(reason).slice(0, 32));
  return { applied: false, reason };
}

/**
 * 启动时的执行者：**监听之前**调用。
 *
 * 顺序是安全属性本身：先通知（此时旧密钥还在盘上，所以通知是「被旧身份签名的」），
 * 再重生。任何一次通知失败都只记一行、绝不阻断重置 —— 一台关机的伙伴不能让人永远换不了身份。
 * 标记损坏/不可读 → 一行 reset ignored 后照常启动（插件绝不因此起不来）。
 *
 * @returns {Promise<{applied:boolean, notified?:number, failed?:number, backup?:string, reason?:string}>}
 */
export async function applyPendingIdentityReset({ stateDir, now = Date.now, log = null, notify = null } = {}) {
  const dir = dirOf(stateDir);
  if (dir === '') return ignore(log, 'no-state-dir');
  const markerPath = path.join(dir, IDENTITY_MARKER_FILE);
  let raw;
  try {
    raw = fs.readFileSync(markerPath, 'utf8');
  } catch (error) {
    if (error && error.code === 'ENOENT') return { applied: false, reason: 'no-marker' };
    return ignore(log, 'unreadable');
  }
  let marker;
  try {
    marker = JSON.parse(raw);
  } catch {
    return ignore(log, 'malformed');
  }
  if (!marker || typeof marker !== 'object' || Array.isArray(marker)) return ignore(log, 'malformed');
  const backupName = String(marker.backup ?? '');
  if (!SAFE_BACKUP_NAME.test(backupName)) return ignore(log, 'bad-backup');
  // 没有可验证的备份就不重置：还原点是这个动作存在的理由之一。
  let backupOk = false;
  try {
    backupOk = fs.statSync(path.join(dir, backupName)).isDirectory();
  } catch {
    backupOk = false;
  }
  if (!backupOk) return ignore(log, 'no-backup');

  const peers = readPeerRecords(dir);
  const oldState = readJsonOrNull(path.join(dir, STATE_FILE));
  const resetAt = typeof marker.resetAt === 'string' && marker.resetAt !== '' ? marker.resetAt : isoOf(now);
  const reason = String(marker.reason ?? '').replace(/\s+/g, ' ').trim().slice(0, 32);
  const notice = { resetAt, reason, senderId: String(oldState?.instanceId ?? '') };

  // 1) 通知（best effort，一次一个，不重试）。旧密钥此刻仍在盘上。
  let notified = 0;
  let failed = 0;
  if (typeof notify === 'function') {
    for (const peer of peers) {
      try {
        await notify(peer, notice);
        notified += 1;
      } catch {
        failed += 1;
        if (typeof log === 'function') {
          log('[identity] reset-notice failed peer=' + shortIdOf(peer.peerId));
        }
      }
    }
  }

  // 2) 重生：instanceId 换新的，其余非身份字段（name/createdAt）保持原样。
  const nextState = (oldState && typeof oldState === 'object' && !Array.isArray(oldState))
    ? { ...oldState }
    : { name: '', createdAt: isoOf(now) };
  nextState.instanceId = randomUUID();
  writeFile0600(path.join(dir, STATE_FILE), JSON.stringify(nextState, null, 2) + '\n');
  // 所有配对作废：对端还留着旧 instanceId，留着这些记录只会让它们一直 401。
  writeFile0600(path.join(dir, PEERS_FILE), JSON.stringify({ peers: {} }, null, 2) + '\n');
  // 群身份（成员侧）：重新入群要新邀请，密钥不留在盘上。
  for (const fileName of IDENTITY_GROUP_FILES) {
    try { fs.unlinkSync(path.join(dir, fileName)); } catch { /* 本来就没有 */ }
  }
  // 管理 token 换新的：旧 token 代表的那个身份已经不存在了。
  writeFile0600(path.join(dir, ADMIN_TOKEN_FILE), randomBytes(32).toString('hex') + '\n');

  if (typeof log === 'function') {
    log('[identity] reset applied backup=' + backupName + ' peers-cleared=1 group=cleared');
  }
  // 结果落一份（面板读它）：与标记同一位置，同样不含密钥。
  try {
    writeFile0600(path.join(dir, IDENTITY_LAST_RESET_FILE), JSON.stringify({
      at: isoOf(now),
      backup: backupName,
      reason,
      notified,
      failed,
    }, null, 2) + '\n');
  } catch { /* 写不进去只是面板少一行，不影响重置已经发生 */ }
  try { fs.unlinkSync(markerPath); } catch { /* 已经没了 */ }
  return { applied: true, notified, failed, backup: backupName };
}

/**
 * 真实的通知实现：签名 + 加密信封复用既有的 callPeer（**绝不在这里重写签名**）。
 * 调用方把它注进 applyPendingIdentityReset({ notify })。
 */
export function createPeerResetNotifier({ callPeer, timeoutMs = 5000 } = {}) {
  if (typeof callPeer !== 'function') throw new Error('createPeerResetNotifier requires callPeer');
  return async function notify(peer, notice = {}) {
    const body = {
      resetAt: String(notice?.resetAt ?? ''),
      reason: String(notice?.reason ?? '').replace(/\s+/g, ' ').trim().slice(0, 32),
    };
    return callPeer({
      baseUrl: String(peer?.baseUrl ?? ''),
      secret: String(peer?.secret ?? ''),
      senderId: String(notice?.senderId ?? ''),
      method: 'POST',
      apiPath: '/v1/peer/reset-notice',
      body,
      timeoutMs,
    });
  };
}
