/**
 * dsh-lan-peers · 会话复用策略设置（0.9.0-α）
 * ============================================
 * 三个键落在 <stateDir>/config.json —— 与 lang / panelScale / dispatchApprovalTtlMs
 * 同一份文件、同一套写法：**只读不写**（由人手工改，或由 batch 2 的面板写），
 * 每次现读现用，手工改完不必重启。
 *
 *   sessionReuseTtlMs            复用窗口（滑动，锚点 lastUsedAt），默认 24h；0 = 永不复用
 *   sessionNewApprovalWindowMs   新建会话的人工批准窗口，默认 7d；0 = 永不要求批准
 *   sessionNewRequestAllowed     接收方是否接受发送方的「要新会话」请求，默认 true
 *
 * 归一化口径（契约）：
 *   - 毫秒键只认**有限整数**；越界夹到 0 … 30d（夹，不回落 —— 夹是「按最接近的合法值办」）；
 *   - 坏值（非数字 / NaN / 空串 / 布尔 / 小数）静默回落默认值：**永不抛错、永不退出**。
 *     一个被手改坏的键不能让派单流程起不来，也不能让复用策略悄悄变成「永不复用」。
 */
import fs from 'node:fs';
import path from 'node:path';

export const SESSION_REUSE_CONFIG_FILE = 'config.json';

export const SESSION_REUSE_TTL_KEY = 'sessionReuseTtlMs';
export const SESSION_NEW_APPROVAL_WINDOW_KEY = 'sessionNewApprovalWindowMs';
export const SESSION_NEW_REQUEST_ALLOWED_KEY = 'sessionNewRequestAllowed';

/** 24 小时：一次「最近用过」的会话一天之内还能接着聊 */
export const SESSION_REUSE_TTL_DEFAULT_MS = 86_400_000;
/** 7 天：超过一周没动过的会话，新建一次已经不奇怪了，静默建 */
export const SESSION_NEW_APPROVAL_WINDOW_DEFAULT_MS = 604_800_000;
/** 发送方的请求默认可被接受；接收方可以用配置关掉 */
export const SESSION_NEW_REQUEST_ALLOWED_DEFAULT = true;

/** 两个毫秒键的共同区间（30 天上限，超过就没有「复用」和「批准」的意义了） */
export const SESSION_REUSE_MS_MIN = 0;
export const SESSION_REUSE_MS_MAX = 2_592_000_000;

/** 默认值三元组（读不到文件时的形状，也是 readSessionReusePrefs 的返回形状） */
export function sessionReuseDefaults() {
  return {
    [SESSION_REUSE_TTL_KEY]: SESSION_REUSE_TTL_DEFAULT_MS,
    [SESSION_NEW_APPROVAL_WINDOW_KEY]: SESSION_NEW_APPROVAL_WINDOW_DEFAULT_MS,
    [SESSION_NEW_REQUEST_ALLOWED_KEY]: SESSION_NEW_REQUEST_ALLOWED_DEFAULT,
  };
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

/**
 * 毫秒键归一：缺键 / 坏值 → fallback；越界 → 夹到 [MIN, MAX]。
 * 只认有限整数（"86400000" 这种字符串数字照收，1.5 / true / "" 一律算坏值）。
 */
export function normalizeSessionReuseMs(value, fallback) {
  if (value === null || value === undefined || value === '' || typeof value === 'boolean') return fallback;
  const text = typeof value === 'number' ? value : String(value).trim();
  if (text === '') return fallback;
  const numeric = typeof text === 'number' ? text : Number(text);
  if (!Number.isFinite(numeric) || !Number.isInteger(numeric)) return fallback;
  if (numeric <= SESSION_REUSE_MS_MIN) return SESSION_REUSE_MS_MIN;
  if (numeric >= SESSION_REUSE_MS_MAX) return SESSION_REUSE_MS_MAX;
  return numeric;
}

/** 复用窗口：默认 24h；0 = 永不复用 */
export function normalizeSessionReuseTtlMs(value) {
  return normalizeSessionReuseMs(value, SESSION_REUSE_TTL_DEFAULT_MS);
}

/** 新建会话的批准窗口：默认 7d；0 = 永不要求批准 */
export function normalizeSessionNewApprovalWindowMs(value) {
  return normalizeSessionReuseMs(value, SESSION_NEW_APPROVAL_WINDOW_DEFAULT_MS);
}

/** 「要新会话」是否被接受：只认布尔；其余（含 "false"）回落默认 true */
export function normalizeSessionNewRequestAllowed(value) {
  if (value === true) return true;
  if (value === false) return false;
  return SESSION_NEW_REQUEST_ALLOWED_DEFAULT;
}

/**
 * 把一个 config.json 对象（可能是 null / 数组 / 字符串）归一成三元组。
 * 这一层永不抛错：任何形状都得到一个可用的三元组。
 */
export function normalizeSessionReusePrefs(raw) {
  const source = raw !== null && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  return {
    [SESSION_REUSE_TTL_KEY]: normalizeSessionReuseTtlMs(source[SESSION_REUSE_TTL_KEY]),
    [SESSION_NEW_APPROVAL_WINDOW_KEY]: normalizeSessionNewApprovalWindowMs(source[SESSION_NEW_APPROVAL_WINDOW_KEY]),
    [SESSION_NEW_REQUEST_ALLOWED_KEY]: normalizeSessionNewRequestAllowed(source[SESSION_NEW_REQUEST_ALLOWED_KEY]),
  };
}

/**
 * 从 <stateDir>/config.json 读三个键（只读，不写）。
 * 文件不存在 / 坏 JSON / 不是对象 / 非法值统统回默认 —— 绝不抛错。
 */
export function readSessionReusePrefs(stateDir) {
  const dir = expandHome(stateDir);
  if (typeof dir !== 'string' || dir === '') return sessionReuseDefaults();
  let raw = null;
  try {
    raw = JSON.parse(fs.readFileSync(path.join(path.resolve(dir), SESSION_REUSE_CONFIG_FILE), 'utf8'));
  } catch {
    raw = null;
  }
  return normalizeSessionReusePrefs(raw);
}
