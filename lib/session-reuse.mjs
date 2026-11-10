/**
 * dsh-lan-peers · 会话复用决策（0.9.0-α 核心层）
 * ==============================================
 * **纯函数模块**：没有 fs、没有网络、没有时钟依赖 —— 用假时钟就能把整张真值表测完。
 * 决策只有三种动作：复用（reuse）/ 新建（new）/ 走既有的待批准队列（approval）。
 *
 * 复用的键是**三元**：peerId + 归一化工作区 + 权限档。三者全等才可能复用 ——
 * 权限档不是 session/create 的字段，它是会话事件折出来的投影（见 lib/runner-dsh.mjs 的
 * permissionReport 注释），所以「档位不同 = 另一个会话」，绝不允许跨档复用。
 *
 * 窗口是**滑动**的：锚点是 lastUsedAt（最后一次使用），不是创建时间。
 *   0 < gap < reuseTtl                                     → reuse
 *   gap ≥ reuseTtl 且 gap ≤ approvalWindow                 → approval（人点头才建）
 *   gap > approvalWindow                                   → new（静默建）
 *
 * 双方都有话语权：发送方可以要新会话（requestedNew），接收方可以拒绝这个请求
 * （requestAllowed=false）—— 被拒时回落到 TTL 判断，能复用就复用。
 *
 * reason 是**稳定词表**（日志与用例都按它断言，不按自然语言）。
 */
import path from 'node:path';

export const SESSION_ACTION_REUSE = 'reuse';
export const SESSION_ACTION_NEW = 'new';
export const SESSION_ACTION_APPROVAL = 'approval';

/** 稳定 reason 词表：一条决策一个词，日志/用例/排障都按它对齐 */
export const SESSION_REUSE_REASONS = Object.freeze({
  /** 账本里没有这个三元的会话 */
  NO_SESSION: 'no-session',
  /** 有会话，但不是同一个对端/工作区/权限档 */
  TRIPLE_MISMATCH: 'triple-mismatch',
  /** 复用窗口内：接着用 */
  TTL_FRESH: 'ttl-fresh',
  /** 复用窗口已过 */
  TTL_EXPIRED: 'ttl-expired',
  /** sessionReuseTtlMs = 0：永不复用 */
  TTL_DISABLED: 'ttl-disabled',
  /** 发送方要求新会话，接收方接受 */
  REQUESTED: 'requested',
  /** 发送方要求新会话，接收方拒绝 → 回落复用 */
  REQUEST_DENIED: 'request-denied',
  /** 窗口内新建：要人点头 */
  WITHIN_WINDOW: 'within-window',
  /** 批准被拒/过期后回落到复用（由调用方强制，不在纯函数里产生） */
  FALLBACK_REUSE: 'fallback-reuse',
});

/**
 * 归一化工作区标识：绝对化 + win32 忽略大小写（与 lib/runner-dsh.mjs 的 sameDir 同口径）。
 * 空串保持空串 —— 绝不把 "" 解析成当前目录，那会让两个不同工作区撞成同一个三元。
 */
export function normalizeWorkspaceKey(value) {
  const text = typeof value === 'string' ? value.trim() : '';
  if (text === '') return '';
  const resolved = path.resolve(text);
  return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
}

/** 三元键（Map/日志用）：三段拼起来，空段也占位，避免拼接歧义 */
export function sessionTripleKey(triple) {
  const row = triple !== null && typeof triple === 'object' ? triple : {};
  return [
    String(row.peerId ?? ''),
    normalizeWorkspaceKey(row.workspace),
    String(row.permission ?? ''),
  ].join('\u0000');
}

/** 两个三元是否全等（缺一段就不算匹配） */
export function sameSessionTriple(left, right) {
  if (left === null || typeof left !== 'object' || right === null || typeof right !== 'object') return false;
  return String(left.peerId ?? '') === String(right.peerId ?? '')
    && normalizeWorkspaceKey(left.workspace) === normalizeWorkspaceKey(right.workspace)
    && String(left.permission ?? '') === String(right.permission ?? '');
}

/**
 * 决策。
 *
 * @param {object} input
 *   now             —— 现在（毫秒）
 *   existing        —— 账本里的会话 { lastUsedAt, triple:{peerId,workspace,permission} } 或 null
 *   reuseTtlMs      —— 复用窗口（0 = 永不复用）
 *   approvalWindowMs—— 新建会话的批准窗口（0 = 永不要求批准）
 *   requestAllowed  —— 接收方是否接受发送方的「要新会话」请求
 *   requestedNew    —— 发送方是否要求新会话
 *   triple          —— 本次请求的三元
 * @returns {{action:'reuse'|'new'|'approval', reason:string, gapMs:number}}
 *   gapMs = now - lastUsedAt（没有会话时为 -1，读不到时间戳时为 Infinity 的整数值化用 -1）
 */
export function decideSessionAction({
  now,
  existing = null,
  reuseTtlMs,
  approvalWindowMs,
  requestAllowed = true,
  requestedNew = false,
  triple = null,
} = {}) {
  const nowMs = Number.isFinite(Number(now)) ? Number(now) : Date.now();
  // 1. 账本里没有会话：压根没有 gap，谈不上窗口 —— 静默建
  if (existing === null || typeof existing !== 'object' || Array.isArray(existing)) {
    return { action: SESSION_ACTION_NEW, reason: SESSION_REUSE_REASONS.NO_SESSION, gapMs: -1 };
  }
  // 2. 三元必须全等：对端、归一化工作区、权限档，缺一不可（跨档复用 = 提权）
  if (triple !== null && !sameSessionTriple(existing.triple, triple)) {
    return { action: SESSION_ACTION_NEW, reason: SESSION_REUSE_REASONS.TRIPLE_MISMATCH, gapMs: -1 };
  }
  // 3. gap：读不到 lastUsedAt 就当作「无限久以前」（核对不了就按过期办，宁可新建）
  const last = Number(existing.lastUsedAt);
  const gapMs = Number.isFinite(last) ? Math.max(0, nowMs - last) : -1;
  // 4. TTL = 0：永不复用（0 是「关掉复用」的显式语义，不是「立刻过期」的巧合）
  const ttl = Number(reuseTtlMs);
  if (!Number.isFinite(ttl) || ttl <= 0) {
    return { action: SESSION_ACTION_NEW, reason: SESSION_REUSE_REASONS.TTL_DISABLED, gapMs };
  }
  const wantsNew = requestedNew === true && requestAllowed !== false;
  const requestDenied = requestedNew === true && requestAllowed === false;
  // 5. 没人要新会话、且还在窗口内 → 复用（被拒的请求也走这里：回落复用）
  if (!wantsNew && gapMs >= 0 && gapMs < ttl) {
    return {
      action: SESSION_ACTION_REUSE,
      reason: requestDenied ? SESSION_REUSE_REASONS.REQUEST_DENIED : SESSION_REUSE_REASONS.TTL_FRESH,
      gapMs,
    };
  }
  // 6. 需要新会话：批准窗口内要人点头，窗口外（或窗口关掉）静默建
  const reason = wantsNew ? SESSION_REUSE_REASONS.REQUESTED : SESSION_REUSE_REASONS.TTL_EXPIRED;
  const windowMs = Number(approvalWindowMs);
  if (!Number.isFinite(windowMs) || windowMs <= 0) return { action: SESSION_ACTION_NEW, reason, gapMs };
  if (gapMs < 0 || gapMs > windowMs) return { action: SESSION_ACTION_NEW, reason, gapMs };
  return {
    action: SESSION_ACTION_APPROVAL,
    reason: wantsNew ? SESSION_REUSE_REASONS.REQUESTED : SESSION_REUSE_REASONS.WITHIN_WINDOW,
    gapMs,
  };
}
