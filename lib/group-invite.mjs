// dsh-lan-peers · 0.12.5-alpha（slice A）入群邀请的落盘层。
//
// 两份文件，形状固定，都是「读失败等于空」——邀请是**可再来一次**的东西，
// 一个坏文件不该让面板的 GET 变成 500，也不该让收邀请的节点起不来。
//   <stateDir>/group-invites.json     接收方：{ version:1, invites: { [groupId]: grant+from+receivedAt } }
//   <stateDir>/group-invites-out.json 邀请方（hub）：{ [peerId]: { at, state } }
//
// 这里只有 I/O，没有任何网络与鉴权：走线在 host/server.mjs，路由门在 lib/admin.mjs。
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';

export const GROUP_INVITES_FILE = 'group-invites.json';
export const GROUP_INVITES_OUT_FILE = 'group-invites-out.json';
export const GROUP_INVITE_VERSION = 1;
/** 待接受邀请的上限（每个 groupId 只留一条，所以这是「同时能挂几个群」的上限） */
export const GROUP_INVITE_LIMIT = 20;
/**
 * 邀请方账本的状态取值：除这几种之外一律不写（面板据此选按钮）。
 *   0.12.5-alpha slice B 追加两种 —— 它们由**被邀请方**的 ack 写进来：
 *   joined（对方接受了，本机 joinState 立刻变 joined）/ declined（对方拒绝了，可以重新邀请）。
 */
export const GROUP_INVITE_STATES = Object.freeze([
  'invited', 'unreachable', 'already-member', 'joined', 'declined',
]);

/** 容错读：文件不存在、读不出、不是对象、JSON 坏 —— 一律当「没有」 */
function readJsonTolerant(file) {
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

/** 原子写（同目录临时文件 + rename，0600）：写不进去返回 false，绝不抛 */
function writeJsonAtomic(file, value) {
  const tmp = file + '.tmp-' + process.pid + '-' + randomBytes(4).toString('hex');
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(tmp, JSON.stringify(value, null, 2) + '\n', { mode: 0o600 });
    fs.chmodSync(tmp, 0o600);
    fs.renameSync(tmp, file);
    fs.chmodSync(file, 0o600);
    return true;
  } catch {
    try { fs.unlinkSync(tmp); } catch { /* 临时文件也没落下来 */ }
    return false;
  }
}

const stamp = (now) => (Number.isFinite(Number(now)) ? Number(now) : Date.now());

/** 接收方：{ version, invites } —— 任何时候都返回可写形状，缺字段就补 */
export function readGroupInvites(stateDir) {
  const raw = stateDir ? readJsonTolerant(path.join(stateDir, GROUP_INVITES_FILE)) : null;
  const invites = raw?.invites && typeof raw.invites === 'object' && !Array.isArray(raw.invites)
    ? raw.invites
    : {};
  const clean = {};
  for (const [groupId, entry] of Object.entries(invites)) {
    if (String(groupId) === '' || !entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
    clean[String(groupId)] = entry;
  }
  return { version: GROUP_INVITE_VERSION, invites: clean };
}

export function writeGroupInvites(stateDir, data) {
  if (!stateDir) return false;
  const invites = data?.invites && typeof data.invites === 'object' ? data.invites : {};
  // 上限：按 receivedAt 留最新的若干条（groupId 已经是键，天然一条一个群）
  const trimmed = Object.entries(invites)
    .sort((a, b) => Number(b[1]?.receivedAt ?? 0) - Number(a[1]?.receivedAt ?? 0))
    .slice(0, GROUP_INVITE_LIMIT);
  return writeJsonAtomic(path.join(stateDir, GROUP_INVITES_FILE), {
    version: GROUP_INVITE_VERSION,
    invites: Object.fromEntries(trimmed),
  });
}

/**
 * 面板可见的那一份：**绝不含 key**。
 * 面板要按钮就够（群名/来处/时间/人数），群密钥留在这台机器的 group-key.json 里。
 */
export function inviteView(groupId, entry) {
  const members = Array.isArray(entry?.members) ? entry.members : [];
  const from = entry?.from && typeof entry.from === 'object' ? entry.from : {};
  return {
    groupId: String(groupId ?? entry?.groupId ?? ''),
    name: String(entry?.name ?? ''),
    from: { peerId: String(from.peerId ?? ''), name: String(from.name ?? '') },
    receivedAt: stamp(entry?.receivedAt),
    memberCount: members.length,
  };
}

/** 接收方的待处理清单（新的在前）：GET group/invite 的唯一数据源 */
export function listInvites(stateDir) {
  const { invites } = readGroupInvites(stateDir);
  return Object.entries(invites)
    .map(([groupId, entry]) => inviteView(groupId, entry))
    .sort((a, b) => b.receivedAt - a.receivedAt);
}

/**
 * 存一条邀请。同一个 groupId 再收到一次就是**覆盖**（hub 换钥后重发是正常路径），
 * 所以「邀请两次只有一条」不是特判，是键的形状。
 */
export function putGroupInvite(stateDir, { grant, from = null, now = Date.now() } = {}) {
  const groupId = String(grant?.groupId ?? '');
  if (!stateDir || groupId === '') return { stored: false, invite: null };
  const data = readGroupInvites(stateDir);
  data.invites[groupId] = {
    ...grant,
    groupId,
    from: { peerId: String(from?.peerId ?? ''), name: String(from?.name ?? '') },
    receivedAt: stamp(now),
  };
  const stored = writeGroupInvites(stateDir, data);
  return { stored, invite: data.invites[groupId] };
}

/** 取一条（不删）：accept 必须先验后删 —— 半份授权不该先把邀请吃掉 */
export function readGroupInvite(stateDir, groupId) {
  const id = String(groupId ?? '');
  if (id === '') return null;
  const { invites } = readGroupInvites(stateDir);
  return invites[id] ?? null;
}

export function dropGroupInvite(stateDir, groupId) {
  const id = String(groupId ?? '');
  if (!stateDir || id === '') return false;
  const data = readGroupInvites(stateDir);
  if (!Object.prototype.hasOwnProperty.call(data.invites, id)) return false;
  delete data.invites[id];
  return writeGroupInvites(stateDir, data);
}

/** 邀请方账本：{ [peerId]: { at, state } } —— 与接收方那份是两回事，互不覆盖 */
export function readInviteLedger(stateDir) {
  const raw = stateDir ? readJsonTolerant(path.join(stateDir, GROUP_INVITES_OUT_FILE)) : null;
  const out = {};
  for (const [peerId, entry] of Object.entries(raw ?? {})) {
    if (String(peerId) === '' || !entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
    const state = GROUP_INVITE_STATES.includes(String(entry.state ?? '')) ? String(entry.state) : 'unreachable';
    out[String(peerId)] = { at: stamp(entry.at), state };
  }
  return out;
}

export function recordInviteAttempt(stateDir, peerId, state, now = Date.now()) {
  const id = String(peerId ?? '');
  const value = String(state ?? '');
  if (!stateDir || id === '' || !GROUP_INVITE_STATES.includes(value)) return readInviteLedger(stateDir);
  const ledger = readInviteLedger(stateDir);
  ledger[id] = { at: stamp(now), state: value };
  writeJsonAtomic(path.join(stateDir, GROUP_INVITES_OUT_FILE), ledger);
  return ledger;
}

/**
 * 名单成员的入群态（面板据此选按钮）：
 *   joined（已在群里）/ invited（已发邀请、还没接受）/ not-invited（两者都不是）
 * hub 唯一的「已入群」信号由 host 提供（见 host/server.mjs 的 joinedMemberIds），
 * 这里只做三态归一 —— 两个平面都有事实时以 joined 为准。
 */
export function joinStateOf(peerId, { joined = null, ledger = null } = {}) {
  const id = String(peerId ?? '');
  const isJoined = joined instanceof Set ? joined.has(id) : (Array.isArray(joined) ? joined.includes(id) : false);
  if (isJoined) return 'joined';
  const entry = ledger && typeof ledger === 'object' ? ledger[id] : null;
  // 账本说 joined = 对方自己 ack 过「我进了」（memberProgress 要等它下一次 pull 才更新，
  // 这中间的空窗期不能让面板把「已经入群的人」画成「邀请入群」）。
  if (entry?.state === 'joined') return 'joined';
  // declined / unreachable / already-member 都退回 not-invited：按钮必须能再点一次。
  return entry?.state === 'invited' ? 'invited' : 'not-invited';
}
