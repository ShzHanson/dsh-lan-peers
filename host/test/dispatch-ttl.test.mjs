/**
 * 0.9.x · 待批准 TTL 可配置（dispatchApprovalTtlMs）
 *
 * 真人协作里踩到的坑：`DISPATCH_PENDING_TTL_MS` 原来是硬编码 10 分钟，派单发过来、对端
 * 回了 pending-approval，人十分钟后回到面板，记录已经自己过期清掉了 —— 看起来像「这个功能
 * 根本没生效」。这里钉死四件事：
 *
 *   1. 默认值不变：DISPATCH_PENDING_TTL_MS = 600000，缺键就是它；
 *   2. 允许范围 60000 – 3600000（1 分钟 – 1 小时），非法值（0 / -1 / 'abc' / 越界）回落默认；
 *   3. 配置落在 <stateDir>/config.json 的 dispatchApprovalTtlMs（与 lang / panelScale 同一份
 *      文件，手工可改），新建待批准记录的 expiresAt 按它现算（±2s），改完不必重启；
 *   4. 显式注入的 dispatchPendingTtlMs 仍然是硬钉（既有旋钮与既有用例的口径一字不动）。
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';

import { createAdmin } from '../../lib/admin.mjs';
import {
  DISPATCH_APPROVAL_TTL_KEY,
  DISPATCH_APPROVAL_TTL_MAX_MS,
  DISPATCH_APPROVAL_TTL_MIN_MS,
  DISPATCH_PENDING_TTL_MS,
  normalizeDispatchApprovalTtlMs,
  readDispatchApprovalTtlMs,
} from '../../lib/dispatch-prefs.mjs';
import {
  makeTempStateDir,
  peerFixture,
  request,
  seedPeers,
  startServer,
  writeJson0600,
} from './helpers.mjs';

const A_ID = 'peer-ttl-0001';
const A_SECRET = 'k-ttl-inbound';
const A_OUTBOUND = 'k-ttl-outbound';
const CONFIG_FILE = 'config.json';

/** 在临时 stateDir 里造一份 config.json（可只写一个键），再起服务 */
function configDir(extra = {}, base = {}) {
  const stateDir = makeTempStateDir();
  writeJson0600(path.join(stateDir, CONFIG_FILE), { ...base, ...extra });
  return stateDir;
}

/** 以 A 的身份向 b 发一条「超过默认档、不超上限」的派单 → 必然进待批准队列 */
function askNeedingApproval(b, requestId = 'r-ttl-1') {
  return request(b.baseUrl, {
    method: 'POST',
    path: '/v1/ask',
    peerId: A_ID,
    secret: A_SECRET,
    encrypt: true,
    body: { requestId, prompt: '把构建跑一遍', workspaceId: 'main', permission: 'workspace-write' },
  });
}

async function startPeer(t, stateDir, overrides = {}) {
  const b = await startServer(t, { stateDir, allowRemotePrompts: true, ...overrides });
  seedPeers(stateDir, [peerFixture(A_ID, { name: 'A', secret: A_OUTBOUND, inboundSecret: A_SECRET })]);
  return b;
}

const ttlOfPending = (b) => {
  const [record] = b.server.dispatch.pending();
  assert.ok(record, '待批准队列里必须有那一条记录');
  return record.expiresAt - record.at;
};

// ---------------------------------------------------------------------------
// ① 默认值 / 范围 / 非法值
// ---------------------------------------------------------------------------
test('默认常量不变：DISPATCH_PENDING_TTL_MS 仍是 10 分钟', () => {
  assert.equal(DISPATCH_PENDING_TTL_MS, 10 * 60 * 1000);
  assert.equal(DISPATCH_PENDING_TTL_MS, 600_000);
});

test('归一：缺键 / 非法值 / 越界一律回落 600000，合法值原样返回', () => {
  const bad = [undefined, null, '', 'abc', 'NaN', 0, -1, -600_000, 7200000, 3600001, 59999, NaN, Infinity, -Infinity, {}, []];
  for (const value of bad) {
    assert.equal(normalizeDispatchApprovalTtlMs(value), DISPATCH_PENDING_TTL_MS,
      '非法值必须回落默认：' + String(value));
  }
  // 边界与合法值（含数字字符串：config.json 是手改的，写 "120000" 也得认）
  assert.equal(normalizeDispatchApprovalTtlMs(DISPATCH_APPROVAL_TTL_MIN_MS), 60_000);
  assert.equal(normalizeDispatchApprovalTtlMs(DISPATCH_APPROVAL_TTL_MAX_MS), 3_600_000);
  assert.equal(normalizeDispatchApprovalTtlMs(120_000), 120_000);
  assert.equal(normalizeDispatchApprovalTtlMs('120000'), 120_000);
  assert.equal(normalizeDispatchApprovalTtlMs(120_000.7), 120_000, '小数向下取整，不产生半毫秒');
});

test('读盘：文件不存在 / 坏 JSON / 不是对象 → 默认；有该键 → 生效', () => {
  const empty = makeTempStateDir();
  assert.equal(readDispatchApprovalTtlMs(empty), DISPATCH_PENDING_TTL_MS, '没有 config.json 就是默认值');

  const broken = makeTempStateDir();
  fs.writeFileSync(path.join(broken, CONFIG_FILE), '{ not json', { mode: 0o600 });
  assert.equal(readDispatchApprovalTtlMs(broken), DISPATCH_PENDING_TTL_MS, '坏 JSON 不许抛错');

  const arrayish = makeTempStateDir();
  fs.writeFileSync(path.join(arrayish, CONFIG_FILE), '[1,2,3]', { mode: 0o600 });
  assert.equal(readDispatchApprovalTtlMs(arrayish), DISPATCH_PENDING_TTL_MS, '顶层不是对象就当没有');

  const good = configDir({ [DISPATCH_APPROVAL_TTL_KEY]: 120_000 }, { lang: 'en' });
  assert.equal(readDispatchApprovalTtlMs(good), 120_000);
  assert.equal(readDispatchApprovalTtlMs(''), DISPATCH_PENDING_TTL_MS, '空 stateDir 一律默认');
});

// ---------------------------------------------------------------------------
// ② 端到端：config.json 的 dispatchApprovalTtlMs 决定 expiresAt
// ---------------------------------------------------------------------------
test('config.json 写 120000 → 新建待批准记录 expiresAt - now ≈ 120000（±2s）', async (t) => {
  const stateDir = configDir({ [DISPATCH_APPROVAL_TTL_KEY]: 120_000 }, { lang: 'zh', panelScale: 1.2 });
  const b = await startPeer(t, stateDir);

  const before = Date.now();
  const res = await askNeedingApproval(b);
  const after = Date.now();

  assert.equal(res.status, 202);
  assert.equal(res.json.state, 'pending-approval');
  const expiresAt = Number(res.json.expiresAt);
  assert.ok(Number.isFinite(expiresAt) && expiresAt > 0, '必须回一个真实 expiresAt');
  assert.ok(Math.abs(expiresAt - Date.now() - 120_000) <= 2000,
    '202 回执里的 expiresAt 必须按配置算，实际偏移 ' + (expiresAt - Date.now()));

  const record = b.server.dispatch.pending()[0];
  assert.equal(record.approvalId, res.json.approvalId);
  assert.equal(record.expiresAt - record.at, 120_000, '落盘记录的 TTL 必须正好是配置值');
  assert.ok(record.at >= before && record.at <= after, 'at 是创建那一刻');

  // 与 lang / panelScale 同文件：那两个键必须还在（读路不写，这里顺带确认没被冲掉）
  const stored = JSON.parse(fs.readFileSync(path.join(stateDir, CONFIG_FILE), 'utf8'));
  assert.equal(stored.lang, 'zh');
  assert.equal(stored.panelScale, 1.2);
  assert.equal(stored[DISPATCH_APPROVAL_TTL_KEY], 120_000);
});

test('config.json 写非法值（7200000 / 0 / -1 / "abc"）→ 回落 600000', async (t) => {
  const cases = [7200000, 0, -1, 'abc'];
  for (let index = 0; index < cases.length; index += 1) {
    const bad = cases[index];
    const stateDir = configDir({ [DISPATCH_APPROVAL_TTL_KEY]: bad });
    const b = await startPeer(t, stateDir);
    const res = await askNeedingApproval(b, 'r-bad-' + index);
    assert.equal(res.status, 202, '非法 TTL 不能挡住派单流程：' + String(bad));
    assert.equal(ttlOfPending(b), 600_000, '非法值必须回落默认：' + String(bad));
    assert.ok(Math.abs(Number(res.json.expiresAt) - Date.now() - 600_000) <= 2000);
  }
});

test('改完不必重启：起服务后再写 config.json，下一条记录立刻用新值', async (t) => {
  const stateDir = configDir({});
  const b = await startPeer(t, stateDir);

  const first = await askNeedingApproval(b, 'r-before');
  assert.equal(first.status, 202);
  assert.equal(ttlOfPending(b), 600_000, '没有该键时是默认值');

  writeJson0600(path.join(stateDir, CONFIG_FILE), { [DISPATCH_APPROVAL_TTL_KEY]: 300_000 });
  const second = await askNeedingApproval(b, 'r-after');
  assert.equal(second.status, 202);
  const fresh = b.server.dispatch.pending().find((row) => row.approvalId === second.json.approvalId);
  assert.ok(fresh, '第二条记录必须进了待批准队列');
  assert.equal(fresh.expiresAt - fresh.at, 300_000, '重读 config.json，无需重启');
});

// ---------------------------------------------------------------------------
// ③ 既有旋钮不被改写：显式注入 dispatchPendingTtlMs 仍然是硬钉
// ---------------------------------------------------------------------------
test('显式 dispatchPendingTtlMs 优先于 config.json（既有旋钮口径不变）', async (t) => {
  const stateDir = configDir({ [DISPATCH_APPROVAL_TTL_KEY]: 120_000 });
  const b = await startPeer(t, stateDir, { dispatchPendingTtlMs: 300 });
  const res = await askNeedingApproval(b);
  assert.equal(res.status, 202);
  assert.equal(ttlOfPending(b), 300, '显式注入的值必须原样生效（不被 60000 下限改写）');
});

test('没有 config.json 时行为与改造前一致：10 分钟', async (t) => {
  const stateDir = makeTempStateDir();
  const b = await startPeer(t, stateDir);
  const res = await askNeedingApproval(b);
  assert.equal(res.status, 202);
  assert.equal(ttlOfPending(b), DISPATCH_PENDING_TTL_MS);
});

// ---------------------------------------------------------------------------
// ④ 同一个文件里的键互不踩踏：面板改外观/语言之后，手写的 TTL 还在
// ---------------------------------------------------------------------------
function adminResponse() {
  return {
    status: 0, headers: {}, body: '',
    setHeader(key, value) { this.headers[key] = value; },
    writeHead(status, headers) { this.status = status; Object.assign(this.headers, headers || {}); },
    write(chunk) { this.body += chunk; return true; },
    end(chunk) { if (chunk) this.body += chunk; if (!this.status) this.status = 200; },
    once() {}, on() {},
  };
}

/** 打一次回环管理接口（面板外观 POST 就够用：它走 config.json 的读改写） */
async function hitAdmin(admin, method, apiPath, body) {
  const payload = body === undefined ? '' : JSON.stringify(body);
  const req = {
    method,
    url: apiPath,
    socket: { remoteAddress: '127.0.0.1', setNoDelay() {} },
    headers: {
      host: '127.0.0.1:7788',
      origin: 'http://127.0.0.1:7788',
      'content-type': 'application/json',
      'content-length': String(Buffer.byteLength(payload)),
      'x-lan-peers-token': admin.token,
    },
    on() { return req; },
    once() { return req; },
    async *[Symbol.asyncIterator]() { if (payload !== '') yield Buffer.from(payload); },
  };
  const res = adminResponse();
  await admin.handle(req, res, new URL('http://127.0.0.1' + apiPath));
  return { status: res.status, json: (() => { try { return JSON.parse(res.body); } catch { return null; } })() };
}

test('手写的 dispatchApprovalTtlMs 不被面板写配置冲掉（同一份 config.json，原子写保留其它键）', async () => {
  const stateDir = configDir({ [DISPATCH_APPROVAL_TTL_KEY]: 120_000 }, { lang: 'zh', panelScale: 1 });
  const admin = createAdmin({
    server: { store: { stateDir }, config: { stateDir } },
    nameOf: () => 'me',
    rename: () => {},
  });

  const out = await hitAdmin(admin, 'POST', '/api/lan-peers/panel-ui', { scale: 1.3 });
  assert.equal(out.status, 200);
  const stored = JSON.parse(fs.readFileSync(path.join(stateDir, CONFIG_FILE), 'utf8'));
  assert.equal(stored.panelScale, 1.3, '外观确实写进去了');
  assert.equal(stored.lang, 'zh', '没点名的键保持原值');
  assert.equal(stored[DISPATCH_APPROVAL_TTL_KEY], 120_000, '手写的 TTL 必须还在（否则会被悄悄打回 10 分钟）');
  assert.equal(readDispatchApprovalTtlMs(stateDir), 120_000);
});
