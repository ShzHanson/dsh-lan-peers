/**
 * 真机事故回归：**「说了等批准」必须查得到记录**。
 *
 * 现场（2026-11-09 14:26Z）：对端 NAS 的 POST /v1/ask 回了 202，但
 *   - <stateDir>/dispatch-pending.json 不存在（不只是 desktop 目录，整台机器都没有）
 *   - GET /api/lan-peers/dispatch/pending → {"items":[]}
 *   - 全量日志里 [dispatch] pending from= 一次都没出现
 * 结论见 host/server.mjs 的 [dispatch] executed / pending 分叉：那次 202 是**真的开跑了**，
 * 不是待批准。教训是两条，本文件各钉一层：
 *
 *   1. 写盘不等于写成 —— create() 回读校验，读不到就抛 pending-store-failed；
 *      /v1/ask 于是回 500 approval-persist-failed，绝不回一个指向不存在记录的 202；
 *   2. /v1/ask 的三种 202（执行 / 新排队 / 重放）必须在日志里可区分，
 *      否则下一次事故仍然只能靠猜（本次就猜错了一整天）。
 *
 * 同时把「同一个 DispatchPending 实例 / 同一个 stateDir」钉死：/v1/ask 写进去的那条，
 * 必须能被管理接口的 GET dispatch/pending 看见、被 POST dispatch/approve 批准并真正执行。
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';

import { createAdmin } from '../../lib/admin.mjs';
import { DISPATCH_PENDING_FILE } from '../../lib/dispatch-prefs.mjs';
import { createRunner } from '../server.mjs';
import { peerFixture, pollAnswer, request, seedPeers, startServer } from './helpers.mjs';

/** 一个固定身份的对端（只有它签得动本机 B） */
const PEER = { peerId: 'peer-nas-0001', name: 'example-nas', secret: 'nas-secret' };

function makeResponse() {
  return {
    status: 0, headers: {}, body: '',
    setHeader(k, v) { this.headers[k] = v; },
    writeHead(status, headers) { this.status = status; Object.assign(this.headers, headers || {}); },
    write(chunk) { this.body += chunk; return true; },
    end(chunk) { if (chunk) this.body += chunk; if (!this.status) this.status = 200; },
    once() {}, on() {},
  };
}

function makeRequest(method, url, body, admin) {
  const chunks = body === undefined ? [] : [Buffer.from(JSON.stringify(body))];
  const token = admin && typeof admin.token === 'string' ? admin.token : '';
  const req = {
    method,
    url,
    socket: { remoteAddress: '127.0.0.1', setNoDelay() {} },
    headers: {
      host: '127.0.0.1:7788',
      'content-type': 'application/json',
      'content-length': String(chunks[0]?.length ?? 0),
      ...(token === '' ? {} : { 'x-lan-peers-token': token }),
    },
    on() { return req; },
    once() { return req; },
    async *[Symbol.asyncIterator]() { for (const chunk of chunks) yield chunk; },
  };
  return req;
}

async function hit(admin, method, apiPath, body) {
  const res = makeResponse();
  const handled = await admin.handle(
    makeRequest(method, apiPath, body, admin),
    res,
    new URL('http://127.0.0.1' + apiPath),
  );
  return { handled, res, json: (() => { try { return JSON.parse(res.body); } catch { return null; } })() };
}

function ask(baseUrl, { requestId, prompt, workspaceId, permission }) {
  return request(baseUrl, {
    method: 'POST',
    path: '/v1/ask',
    peerId: PEER.peerId,
    secret: PEER.secret,
    body: {
      requestId,
      prompt,
      ...(workspaceId === undefined ? {} : { workspaceId }),
      ...(permission === undefined ? {} : { permission }),
    },
  });
}

/** 起 B，把 PEER 种进 peers.json，挂上真实管理接口（与 lib/index.js 同一套装配）。 */
async function bootB(t, overrides = {}) {
  const logs = [];
  const runner = overrides.runner ?? createRunner({ delayMs: 5 });
  const b = await startServer(t, {
    allowRemotePrompts: true,
    permission: 'read-only',
    logger: (line) => logs.push(String(line)),
    runner,
    ...overrides,
  });
  seedPeers(b.stateDir, [peerFixture(PEER.peerId, { name: PEER.name, secret: PEER.secret })]);
  const admin = createAdmin({ server: b.server, nameOf: () => 'self', rename: (n) => n, feed: null, pairing: { mode: 'auto' } });
  return { b, admin, logs, runner };
}

function pendingFileOf(b) {
  return path.join(b.stateDir, DISPATCH_PENDING_FILE);
}

test('AC1/AC2：超默认档未超上限 → 202；记录落盘且管理接口看得见，可批准并真正执行', async (t) => {
  const { b, admin, logs } = await bootB(t);
  // 上限抬到 danger-full-access，默认档仍是 read-only（config 默认）→ workspace-write 必须人工确认
  assert.equal(b.server.dispatch.savePrefs({ maxPermission: 'danger-full-access' }).maxPermission, 'danger-full-access');

  const marker = 'MARKER-VISIBLE-' + Math.random().toString(36).slice(2, 10);
  const accepted = await ask(b.baseUrl, { requestId: 'r-vis', prompt: marker, workspaceId: 'main', permission: 'workspace-write' });
  assert.equal(accepted.status, 202, accepted.text);
  assert.equal(accepted.json.state, 'pending-approval');
  assert.equal(typeof accepted.json.approvalId, 'string');

  // 1) 落盘：文件当场就存在，且不含正文
  const file = pendingFileOf(b);
  assert.ok(fs.existsSync(file), '说了「等批准」就必须有 dispatch-pending.json');
  assert.equal(fs.readFileSync(file, 'utf8').includes(marker), false, '待批准文件里不得有正文');

  // 2) 管理接口看得见（同一个 DispatchPending / 同一个 stateDir，不是两套门面）
  const list = await hit(admin, 'GET', '/api/lan-peers/dispatch/pending');
  assert.equal(list.res.status, 200);
  assert.equal(list.json.items.length, 1, '管理接口必须看见 /v1/ask 刚写进去的那条');
  const item = list.json.items[0];
  assert.equal(item.approvalId, accepted.json.approvalId);
  assert.equal(item.from, PEER.peerId);
  assert.equal(item.fromName, PEER.name);
  assert.equal(item.workspaceId, 'main');
  assert.equal(item.workspaceName, '主工作区');
  assert.equal(item.permission, 'workspace-write');
  assert.equal(item.promptBytes, Buffer.byteLength(marker, 'utf8'));
  const remainingSec = Math.round((item.expiresAt - Date.now()) / 1000);
  assert.ok(remainingSec > 540 && remainingSec <= 600, '剩余秒数由 expiresAt 算（默认 TTL 10 分钟）: ' + remainingSec);

  // 3) 待批准期间绝不执行
  assert.equal(b.server.sessions.size, 0);

  // 4) 管理接口批准 → 真正执行
  const ok = await hit(admin, 'POST', '/api/lan-peers/dispatch/approve', { id: item.approvalId });
  assert.equal(ok.res.status, 200, ok.res.body);
  assert.deepEqual(ok.json, { ok: true, state: 'approved' });
  assert.equal(b.server.sessions.size, 1, '批准后必须开跑');
  const stored = JSON.parse(fs.readFileSync(file, 'utf8')).pending[0];
  assert.equal(stored.state, 'approved');
  assert.equal(typeof stored.sessionId, 'string');

  // 5) 执行结果可按 /v1/answer 取回；待批准列表清空
  const answered = await pollAnswer(b.baseUrl, { sessionId: stored.sessionId, peerId: PEER.peerId, secret: PEER.secret });
  assert.equal(answered.status, 'done');
  const after = await hit(admin, 'GET', '/api/lan-peers/dispatch/pending');
  assert.deepEqual(after.json.items, []);

  // 6) 三种 202 在日志里必须分得开：这条走的是 pending，不是 executed
  assert.equal(logs.some((line) => line.startsWith('[dispatch] pending from=')), true, logs.join('\n'));
  assert.equal(logs.some((line) => line.startsWith('[dispatch] pending failed')), false);
});

test('AC2：同一条记录可以拒绝；拒绝不执行、不进会话表', async (t) => {
  const { b, admin } = await bootB(t);
  assert.equal(b.server.dispatch.savePrefs({ maxPermission: 'danger-full-access' }).maxPermission, 'danger-full-access');

  const accepted = await ask(b.baseUrl, { requestId: 'r-reject', prompt: '这条要拒', workspaceId: 'main', permission: 'workspace-write' });
  assert.equal(accepted.json.state, 'pending-approval');

  const no = await hit(admin, 'POST', '/api/lan-peers/dispatch/reject', { id: accepted.json.approvalId });
  assert.equal(no.res.status, 200, no.res.body);
  assert.deepEqual(no.json, { ok: true, state: 'rejected' });
  assert.equal(b.server.sessions.size, 0, '拒绝绝不能执行');
  assert.equal(b.server.dispatch.state(accepted.json.approvalId), 'rejected');
  const after = await hit(admin, 'GET', '/api/lan-peers/dispatch/pending');
  assert.deepEqual(after.json.items, []);
});

test('AC3：超上限 → 403 permission-denied，且一条待批准记录都不产生', async (t) => {
  const { b, admin, logs } = await bootB(t);
  // 上限保持缺省 workspace-write
  const denied = await ask(b.baseUrl, { requestId: 'r-over', prompt: '超上限', workspaceId: 'main', permission: 'danger-full-access' });
  assert.equal(denied.status, 403);
  assert.equal(denied.json.error, 'permission-denied');
  assert.equal(fs.existsSync(pendingFileOf(b)), false, '403 不得落盘任何待批准记录');
  const list = await hit(admin, 'GET', '/api/lan-peers/dispatch/pending');
  assert.deepEqual(list.json.items, []);
  assert.equal(b.server.sessions.size, 0);
  // 拒的那一步也要留一条可读的痕：现场就是靠这个判断「403 还是 202」
  assert.equal(logs.some((line) => line.startsWith('[dispatch] denied from=') && line.includes('reason=permission-denied')), true, logs.join('\n'));
});

test('AC4：同一 requestId 重发 → 同一个 approvalId，不排第二条', async (t) => {
  const { b, admin } = await bootB(t);
  assert.equal(b.server.dispatch.savePrefs({ maxPermission: 'danger-full-access' }).maxPermission, 'danger-full-access');

  const first = await ask(b.baseUrl, { requestId: 'r-replay', prompt: '重发', workspaceId: 'main', permission: 'workspace-write' });
  const again = await ask(b.baseUrl, { requestId: 'r-replay', prompt: '重发', workspaceId: 'main', permission: 'workspace-write' });
  assert.equal(again.status, 202);
  assert.equal(again.json.state, 'pending-approval');
  assert.equal(again.json.approvalId, first.json.approvalId);
  const list = await hit(admin, 'GET', '/api/lan-peers/dispatch/pending');
  assert.equal(list.json.items.length, 1, '重放不得排第二条');
});

test('落盘失败 → 500 approval-persist-failed，绝不回一个查不到的 202', async (t) => {
  const { b, admin, logs } = await bootB(t);
  assert.equal(b.server.dispatch.savePrefs({ maxPermission: 'danger-full-access' }).maxPermission, 'danger-full-access');
  // 把 dispatch-pending.json 顶成一个目录：原子写的 rename 必然失败，而 peers.json 照常可读
  // （鉴权不受影响，请求能走到派单这一段）。
  const file = pendingFileOf(b);
  fs.mkdirSync(file);
  t.after(() => fs.rmSync(file, { recursive: true, force: true }));

  const res = await ask(b.baseUrl, { requestId: 'r-store-fail', prompt: '写不进去', workspaceId: 'main', permission: 'workspace-write' });
  assert.equal(res.status, 500, '写不进队列就不能说「等批准」: ' + res.text);
  assert.equal(res.json.error, 'approval-persist-failed');
  assert.equal(res.json.state, undefined, '不得回 pending-approval / approvalId');
  assert.equal(res.json.approvalId, undefined);
  // 队列里也真的没有：管理接口看的和 /v1/ask 写的是同一份
  const list = await hit(admin, 'GET', '/api/lan-peers/dispatch/pending');
  assert.deepEqual(list.json.items, []);
  assert.equal(logs.some((line) => line.startsWith('[dispatch] pending failed')), true, logs.join('\n'));
});
