/**
 * 0.9.0-α 契约 §1/§2：会话复用决策（纯函数）+ 三个设置键的归一化
 *
 * 两层都**不碰 server**：
 *   1. lib/session-reuse.mjs —— 真值表（复用的三元 + 滑动窗口 + 双方话语权）；
 *   2. lib/session-reuse-prefs.mjs —— 缺省 / 夹取 / 坏值回落，三种情形每个键都过一遍。
 *
 * 铁律：坏值永不抛错；0 是「关闭」的显式语义（TTL=0 永不复用，窗口=0 永不要求批准）。
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  SESSION_ACTION_APPROVAL,
  SESSION_ACTION_NEW,
  SESSION_ACTION_REUSE,
  SESSION_REUSE_REASONS,
  decideSessionAction,
  normalizeWorkspaceKey,
  sameSessionTriple,
  sessionTripleKey,
} from './session-reuse.mjs';
import {
  SESSION_NEW_APPROVAL_WINDOW_DEFAULT_MS,
  SESSION_NEW_APPROVAL_WINDOW_KEY,
  SESSION_NEW_REQUEST_ALLOWED_DEFAULT,
  SESSION_NEW_REQUEST_ALLOWED_KEY,
  SESSION_REUSE_CONFIG_FILE,
  SESSION_REUSE_MS_MAX,
  SESSION_REUSE_TTL_DEFAULT_MS,
  SESSION_REUSE_TTL_KEY,
  normalizeSessionNewApprovalWindowMs,
  normalizeSessionNewRequestAllowed,
  normalizeSessionReusePrefs,
  normalizeSessionReuseTtlMs,
  readSessionReusePrefs,
} from './session-reuse-prefs.mjs';

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
/** 三个键的契约默认值：TTL 24h / 批准窗口 7d / 请求可接受 */
const DEFAULTS = { reuseTtlMs: 86_400_000, approvalWindowMs: 604_800_000, requestAllowed: true };
const TRIPLE = { peerId: 'peer-a', workspace: '/srv/ws/main', permission: 'workspace-write' };

/** 账本里的一条会话：三元全等，lastUsedAt = now - gap */
function ledgerEntry(gapMs, triple = TRIPLE) {
  return { lastUsedAt: 1_700_000_000_000 - gapMs, triple: { ...triple } };
}

function decide(gapMs, overrides = {}) {
  const now = 1_700_000_000_000;
  return decideSessionAction({
    now,
    existing: gapMs === null ? null : ledgerEntry(gapMs),
    ...DEFAULTS,
    ...overrides,
    triple: overrides.triple ?? TRIPLE,
  });
}

// ---------------------------------------------------------------------------
// 真值表（S1 a–h）
// ---------------------------------------------------------------------------

test('§1 (a) 三元全等且 gap 1h（窗口 24h）→ reuse', () => {
  const out = decide(HOUR);
  assert.equal(out.action, SESSION_ACTION_REUSE);
  assert.equal(out.reason, SESSION_REUSE_REASONS.TTL_FRESH);
  assert.equal(out.gapMs, HOUR);
});

test('§1 (b) gap 25h（超过 24h TTL）但批准窗口 7d → approval', () => {
  const out = decide(25 * HOUR);
  assert.equal(out.action, SESSION_ACTION_APPROVAL);
  assert.equal(out.reason, SESSION_REUSE_REASONS.WITHIN_WINDOW);
  assert.equal(out.gapMs, 25 * HOUR);
});

test('§1 (c) gap 8d（超过 7d 窗口）→ 静默 new，reason=ttl-expired', () => {
  const out = decide(8 * DAY);
  assert.equal(out.action, SESSION_ACTION_NEW);
  assert.equal(out.reason, SESSION_REUSE_REASONS.TTL_EXPIRED);
});

test('§1 (d) 账本里没有会话 → new，reason=no-session（gap_ms=-1）', () => {
  const out = decide(null);
  assert.equal(out.action, SESSION_ACTION_NEW);
  assert.equal(out.reason, SESSION_REUSE_REASONS.NO_SESSION);
  assert.equal(out.gapMs, -1);
});

test('§1 (e) 三元不匹配 → new，reason=triple-mismatch（gap 再小也不复用）', () => {
  for (const mismatched of [
    { ...TRIPLE, peerId: 'peer-b' },
    { ...TRIPLE, workspace: '/srv/ws/docs' },
    { ...TRIPLE, permission: 'danger-full-access' },
    { ...TRIPLE, permission: 'read-only' },
  ]) {
    const out = decide(60_000, { triple: mismatched });
    assert.equal(out.action, SESSION_ACTION_NEW, JSON.stringify(mismatched));
    assert.equal(out.reason, SESSION_REUSE_REASONS.TRIPLE_MISMATCH);
  }
});

test('§1 (f) 发送方要新会话 + 接收方允许 + gap 2h → approval，reason=requested', () => {
  const out = decide(2 * HOUR, { requestedNew: true, requestAllowed: true });
  assert.equal(out.action, SESSION_ACTION_APPROVAL);
  assert.equal(out.reason, SESSION_REUSE_REASONS.REQUESTED);
});

test('§1 (g) 发送方要新会话但接收方拒绝 → 回落 reuse，reason=request-denied', () => {
  const out = decide(2 * HOUR, { requestedNew: true, requestAllowed: false });
  assert.equal(out.action, SESSION_ACTION_REUSE);
  assert.equal(out.reason, SESSION_REUSE_REASONS.REQUEST_DENIED);
});

test('§1 (h) reuseTtlMs=0 → 永不复用（窗口内也不复用，reason=ttl-disabled）', () => {
  for (const gap of [0, 60_000, HOUR, 25 * HOUR, 8 * DAY]) {
    const out = decide(gap, { reuseTtlMs: 0 });
    assert.equal(out.action, SESSION_ACTION_NEW, 'gap=' + gap);
    assert.notEqual(out.reason, SESSION_REUSE_REASONS.TTL_FRESH);
  }
  // 0 是「关闭复用」，与「马上就要过期」不是一回事：连批准流程都不该被拉出来
  assert.equal(decide(60_000, { reuseTtlMs: 0 }).reason, SESSION_REUSE_REASONS.TTL_DISABLED);
});

test('§1 边界：窗口关掉（0 = 永不要求批准）→ 需要新会话时静默建', () => {
  assert.equal(decide(25 * HOUR, { approvalWindowMs: 0 }).action, SESSION_ACTION_NEW);
  assert.equal(decide(25 * HOUR, { approvalWindowMs: 0 }).reason, SESSION_REUSE_REASONS.TTL_EXPIRED);
  // 恰好落在窗口边界上仍算「窗口内」→ 要批准（GREATER 才静默建）
  assert.equal(decide(7 * DAY, { approvalWindowMs: 7 * DAY }).action, SESSION_ACTION_APPROVAL);
  assert.equal(decide(7 * DAY + 1, { approvalWindowMs: 7 * DAY }).action, SESSION_ACTION_NEW);
});

test('§1 读不到 lastUsedAt 时按过期办（核对不了就新建，不赌）', () => {
  const out = decideSessionAction({
    now: 1_700_000_000_000,
    existing: { lastUsedAt: undefined, triple: { ...TRIPLE } },
    ...DEFAULTS,
    triple: TRIPLE,
  });
  assert.equal(out.action, SESSION_ACTION_NEW);
});

test('§1 三元键：工作区归一化（win32 忽略大小写）+ 拼接不歧义', () => {
  const left = sessionTripleKey({ ...TRIPLE, workspace: '/srv/ws/main' });
  const right = sessionTripleKey({ ...TRIPLE, workspace: '/srv/ws/main/' });
  assert.equal(left, right, '同一目录的不同写法必须是同一个键');
  assert.equal(normalizeWorkspaceKey(''), '', '空串不许被解析成当前目录');
  assert.equal(sameSessionTriple(TRIPLE, { ...TRIPLE }), true);
  assert.equal(sameSessionTriple(TRIPLE, null), false);
  assert.equal(
    sessionTripleKey({ peerId: 'a\u0000b', workspace: '', permission: '' }),
    'a\u0000b\u0000\u0000',
    '空段也占位，避免 peerId 里带分隔符时拼接歧义',
  );
});

// ---------------------------------------------------------------------------
// S2 设置：缺省 / 夹取 / 坏值回落（每个键三种情形）
// ---------------------------------------------------------------------------

test('S2 三个键缺省：文件不存在时读默认值，且不落盘', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-session-reuse-prefs-'));
  const prefs = readSessionReusePrefs(dir);
  assert.equal(prefs[SESSION_REUSE_TTL_KEY], SESSION_REUSE_TTL_DEFAULT_MS);
  assert.equal(prefs[SESSION_REUSE_TTL_KEY], 86_400_000);
  assert.equal(prefs[SESSION_NEW_APPROVAL_WINDOW_KEY], SESSION_NEW_APPROVAL_WINDOW_DEFAULT_MS);
  assert.equal(prefs[SESSION_NEW_APPROVAL_WINDOW_KEY], 604_800_000);
  assert.equal(prefs[SESSION_NEW_REQUEST_ALLOWED_KEY], SESSION_NEW_REQUEST_ALLOWED_DEFAULT);
  assert.equal(prefs[SESSION_NEW_REQUEST_ALLOWED_KEY], true);
  assert.equal(fs.existsSync(path.join(dir, SESSION_REUSE_CONFIG_FILE)), false, '只读不该建文件');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('S2 三个键越界：夹到 0 … 30d（夹不是回落）', () => {
  assert.equal(normalizeSessionReuseTtlMs(-1), 0);
  assert.equal(normalizeSessionReuseTtlMs(9e15), SESSION_REUSE_MS_MAX);
  assert.equal(normalizeSessionNewApprovalWindowMs(-86_400_000), 0);
  assert.equal(normalizeSessionNewApprovalWindowMs(SESSION_REUSE_MS_MAX + 1), SESSION_REUSE_MS_MAX);
  // 布尔不是档位：只认真假，不看真假值像不像数字
  assert.equal(normalizeSessionNewRequestAllowed(0), SESSION_NEW_REQUEST_ALLOWED_DEFAULT);
  assert.equal(normalizeSessionNewRequestAllowed('false'), SESSION_NEW_REQUEST_ALLOWED_DEFAULT);
});

test('S2 三个键坏值：静默回落默认（永不抛错）', () => {
  for (const bad of ['abc', null, undefined, '', true, Number.NaN, Number.POSITIVE_INFINITY, 1.5, {}]) {
    assert.equal(normalizeSessionReuseTtlMs(bad), SESSION_REUSE_TTL_DEFAULT_MS, 'bad=' + String(bad));
    assert.equal(normalizeSessionNewApprovalWindowMs(bad), SESSION_NEW_APPROVAL_WINDOW_DEFAULT_MS, 'bad=' + String(bad));
  }
  // 故意不是对象 / 坏 JSON：整份回落，绝不抛
  assert.deepEqual(normalizeSessionReusePrefs(null), normalizeSessionReusePrefs({}));
  assert.deepEqual(normalizeSessionReusePrefs([1, 2, 3]), normalizeSessionReusePrefs({}));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-session-reuse-prefs-bad-'));
  fs.writeFileSync(path.join(dir, SESSION_REUSE_CONFIG_FILE), '{ not json', 'utf8');
  assert.equal(readSessionReusePrefs(dir)[SESSION_REUSE_TTL_KEY], SESSION_REUSE_TTL_DEFAULT_MS);
  // stateDir 不是字符串也不抛
  assert.equal(readSessionReusePrefs(null)[SESSION_REUSE_TTL_KEY], SESSION_REUSE_TTL_DEFAULT_MS);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('S2 三个键合法值：真读到（含字符串数字与显式 0 / false）', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-session-reuse-prefs-ok-'));
  fs.writeFileSync(
    path.join(dir, SESSION_REUSE_CONFIG_FILE),
    JSON.stringify({
      lang: 'zh',
      [SESSION_REUSE_TTL_KEY]: '3600000',
      [SESSION_NEW_APPROVAL_WINDOW_KEY]: 0,
      [SESSION_NEW_REQUEST_ALLOWED_KEY]: false,
    }),
    'utf8',
  );
  const prefs = readSessionReusePrefs(dir);
  assert.deepEqual(prefs, {
    [SESSION_REUSE_TTL_KEY]: HOUR,
    [SESSION_NEW_APPROVAL_WINDOW_KEY]: 0,
    [SESSION_NEW_REQUEST_ALLOWED_KEY]: false,
  });
  // 显式 0 与 false 是**有效值**，不能被回落成默认（否则「关掉」这个动作没有出口）
  assert.notEqual(prefs[SESSION_NEW_APPROVAL_WINDOW_KEY], SESSION_NEW_APPROVAL_WINDOW_DEFAULT_MS);
  fs.rmSync(dir, { recursive: true, force: true });
});
