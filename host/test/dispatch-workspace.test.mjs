/**
 * 0.8.5-α 契约 §1–§4：派单工作区与权限（协议 + 待批准队列 + 门面）
 *
 * 三层覆盖：
 *   1. lib/dispatch-prefs.mjs —— 设置校验与待批准队列（纯本地，无 HTTP）；
 *   2. /v1/dispatch/* 与 /v1/ask 的协议语义（真监听、真签名、真信封）；
 *   3. 门面 server.dispatch.* / server.dm.send 端到端，含两个真进程的演示。
 *
 * 铁律断言：options 响应不含任何绝对路径；待批准文件不含正文；日志里既没有正文也没有路径。
 */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { pathToFileURL } from 'node:url';
import { setTimeout as sleep } from 'node:timers/promises';

import {
  DISPATCH_PENDING_FILE,
  DISPATCH_PENDING_TTL_MS,
  DISPATCH_PREFS_FILE,
  DispatchPending,
  DispatchPrefs,
} from '../../lib/dispatch-prefs.mjs';
import { createRunner } from '../server.mjs';
import {
  fileMode,
  makeTempStateDir,
  peerFixture,
  pollAnswer,
  request,
  seedPeers,
  startServer,
} from './helpers.mjs';

/** 两个节点互相成为对端（跳过配对流程）；返回两条方向的签名密钥 */
function linkPair(a, b) {
  const aId = a.server.store.instanceId;
  const bId = b.server.store.instanceId;
  const aToB = 'k-' + aId.slice(0, 6) + '-to-' + bId.slice(0, 6);
  const bToA = 'k-' + bId.slice(0, 6) + '-to-' + aId.slice(0, 6);
  seedPeers(a.stateDir, [peerFixture(bId, { name: 'B', secret: aToB, inboundSecret: bToA, baseUrl: b.baseUrl })]);
  seedPeers(b.stateDir, [peerFixture(aId, { name: 'A', secret: bToA, inboundSecret: aToB, baseUrl: a.baseUrl })]);
  return { aId, bId, aToB, bToA };
}

/** A 以签名 + 信封的身份向 B 发一条 /v1/ask */
function askAs(baseUrl, { peerId, secret, requestId, prompt, workspaceId, permission }) {
  return request(baseUrl, {
    method: 'POST',
    path: '/v1/ask',
    peerId,
    secret,
    encrypt: true,
    body: {
      requestId,
      prompt,
      ...(workspaceId === undefined ? {} : { workspaceId }),
      ...(permission === undefined ? {} : { permission }),
    },
  });
}

/** 一个能记账的假执行侧：每个会话记住实际生效的 workspace / permission */
function trackingRunner() {
  const runner = createRunner({ delayMs: 5 });
  const seen = [];
  const ask = runner.ask.bind(runner);
  runner.ask = async (prompt, options) => {
    seen.push({ prompt: String(prompt), workspace: options?.workspace ?? null, permission: options?.permission ?? null });
    return ask(prompt, options);
  };
  return { runner, seen };
}

// ---------------------------------------------------------------------------
// §1 设置：缺省值 / 校验 / 0600
// ---------------------------------------------------------------------------

test('§1 prefs 缺省值：id=main、上限 workspace-write、本机 workspace 路径；读不到文件时不落盘', () => {
  const dir = makeTempStateDir('dsh-dispatch-prefs-');
  const workspace = path.join(dir, 'workspace');
  const prefs = new DispatchPrefs({ stateDir: dir, workspace });

  const current = prefs.get();
  assert.equal(current.defaultWorkspaceId, 'main');
  assert.equal(current.maxPermission, 'workspace-write');
  assert.equal(current.workspaces.length, 1);
  assert.equal(current.workspaces[0].id, 'main');
  assert.equal(current.workspaces[0].name, '主工作区');
  assert.equal(current.workspaces[0].path, path.resolve(workspace));
  // 只是读，不该凭空建文件
  assert.equal(fs.existsSync(path.join(dir, DISPATCH_PREFS_FILE)), false);

  // 对外视图只有 id + name
  const options = prefs.options();
  assert.deepEqual(Object.keys(options).sort(), ['defaultWorkspaceId', 'maxPermission', 'workspaces']);
  assert.deepEqual(options.workspaces, [{ id: 'main', name: '主工作区' }]);
  assert.equal(JSON.stringify(options).includes(path.resolve(workspace)), false);

  const saved = prefs.save({ maxPermission: 'danger-full-access' });
  assert.equal(saved.maxPermission, 'danger-full-access');
  assert.equal(fs.existsSync(prefs.file), true);
  if (process.platform !== 'win32') assert.equal(fileMode(prefs.file), 0o600, 'dispatch-prefs.json 必须 0600');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('§1 savePrefs 校验：重复 id / 路径不存在 / 不是目录 / 上限非法 / 默认指向未知 id 一律拒绝且不写盘', () => {
  const dir = makeTempStateDir('dsh-dispatch-prefs-bad-');
  const workspace = path.join(dir, 'workspace');
  const file = path.join(dir, 'plain.txt');
  fs.mkdirSync(workspace, { recursive: true });
  fs.writeFileSync(file, 'not a directory\n', 'utf8');
  const prefs = new DispatchPrefs({ stateDir: dir, workspace });

  const baseline = prefs.save({ maxPermission: 'danger-full-access' });
  assert.equal(baseline.maxPermission, 'danger-full-access');
  const before = fs.readFileSync(prefs.file, 'utf8');

  const cases = [
    { patch: { workspaces: [{ id: 'a', name: 'A', path: workspace }, { id: 'a', name: 'A2', path: workspace }] }, reason: 'duplicate-id' },
    { patch: { workspaces: [{ id: 'a', name: 'A', path: path.join(dir, 'nope') }] }, reason: 'path-missing' },
    { patch: { workspaces: [{ id: 'a', name: 'A', path: file }] }, reason: 'path-not-dir' },
    { patch: { maxPermission: 'root' }, reason: 'bad-permission' },
    { patch: { defaultWorkspaceId: 'ghost' }, reason: 'bad-default-workspace' },
    { patch: { workspaces: [] }, reason: 'bad-workspaces' },
    { patch: { workspaces: [{ id: 'a b/c', name: 'A', path: workspace }] }, reason: 'bad-id' },
  ];
  for (const item of cases) {
    const out = prefs.save(item.patch);
    assert.equal(out.ok, false, JSON.stringify(item.patch) + ' 必须被拒');
    assert.equal(out.reason, item.reason);
    // 被拒时回的是「当前有效值」，且盘上内容一字不改
    assert.equal(out.maxPermission, 'danger-full-access');
    assert.equal(fs.readFileSync(prefs.file, 'utf8'), before, '非法输入不得写盘');
  }
  fs.rmSync(dir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// §3 待批准队列（纯本地）
// ---------------------------------------------------------------------------

test('§3 待批准队列：只存契约字段（无正文）、TTL 到期自动 expired、已决条目保留 sessionId', () => {
  const dir = makeTempStateDir('dsh-dispatch-pending-');
  let nowMs = 1_000;
  const pending = new DispatchPending({ stateDir: dir, now: () => nowMs, ttlMs: DISPATCH_PENDING_TTL_MS });

  const record = pending.create({
    from: 'peer-1',
    workspaceId: 'main',
    workspaceName: '主工作区',
    permission: 'danger-full-access',
    promptBytes: 42,
  });
  assert.equal(record.state, 'pending');
  assert.equal(record.expiresAt - record.at, DISPATCH_PENDING_TTL_MS);
  assert.equal(pending.list().length, 1);
  if (process.platform !== 'win32') assert.equal(fileMode(pending.file), 0o600, 'dispatch-pending.json 必须 0600');

  const raw = fs.readFileSync(pending.file, 'utf8');
  const stored = JSON.parse(raw).pending[0];
  assert.deepEqual(
    Object.keys(stored).sort(),
    ['approvalId', 'at', 'expiresAt', 'from', 'permission', 'promptBytes', 'state', 'workspaceId', 'workspaceName'],
    '待批准记录只认契约字段',
  );
  assert.equal(raw.includes('danger-full-access'), true);

  // 10 分钟到点：状态变 expired，队列清空
  nowMs = record.expiresAt + 1;
  assert.equal(pending.state(record.approvalId), 'expired');
  assert.equal(pending.list().length, 0);

  // 已决条目：批准带 sessionId 写回，过了保留期才被 prune 掉
  const second = pending.create({ from: 'peer-2', workspaceId: 'main', workspaceName: '主工作区', permission: 'workspace-write', promptBytes: 7 });
  pending.settle(second.approvalId, 'approved', { sessionId: 'sess-42' });
  assert.equal(pending.peek(second.approvalId).sessionId, 'sess-42');
  nowMs += DISPATCH_PENDING_TTL_MS + 10_000;
  pending.prune();
  assert.equal(pending.peek(second.approvalId), null, '保留期过后整条清掉');
  pending.close();
  fs.rmSync(dir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// §2 GET /v1/dispatch/options
// ---------------------------------------------------------------------------

test('§2 options 响应只有 id/name：JSON 里不含任何绝对路径，未配对 401，拒单节点 403', async (t) => {
  const a = await startServer(t, { allowRemotePrompts: true });
  const b = await startServer(t, { allowRemotePrompts: true });
  const { aId, aToB } = linkPair(a, b);

  const res = await request(b.baseUrl, {
    path: '/v1/dispatch/options',
    peerId: aId,
    secret: aToB,
    encrypt: true,
  });
  assert.equal(res.status, 200, res.text);
  // 贴出实际响应（验收第 3 条：不含绝对路径）
  console.log('options 实际响应:', JSON.stringify(res.json));

  assert.deepEqual(Object.keys(res.json).sort(), ['defaultWorkspaceId', 'maxPermission', 'workspaces']);
  assert.equal(res.json.defaultWorkspaceId, 'main');
  assert.equal(res.json.maxPermission, 'workspace-write');
  assert.deepEqual(res.json.workspaces, [{ id: 'main', name: '主工作区' }]);

  const text = JSON.stringify(res.json);
  assert.equal(text.includes('path'), false, 'options 响应不得出现 path 键');
  assert.equal(text.includes(b.stateDir), false, 'options 响应不得出现 stateDir');
  assert.equal(text.includes(path.resolve(b.server.config.workspace)), false, 'options 响应不得出现工作区绝对路径');
  assert.equal(/(^|[^a-z])[A-Za-z]:\\/.test(text), false, '响应里不能有盘符路径');
  assert.equal(text.includes('/'), false, '响应里不能有以 / 开头的路径');

  // 未签名 → 401（per-peer 路径，与 ask 同一道门）
  const anonymous = await request(b.baseUrl, { path: '/v1/dispatch/options' });
  assert.equal(anonymous.status, 401);

  // 拒绝接单的节点不交出工作区清单
  const c = await startServer(t, { allowRemotePrompts: false });
  seedPeers(c.stateDir, [peerFixture(aId, { name: 'A', secret: 'k-c', inboundSecret: 'k-c' })]);
  const disabled = await request(c.baseUrl, { path: '/v1/dispatch/options', peerId: aId, secret: 'k-c', encrypt: true });
  assert.equal(disabled.status, 403);
  assert.equal(disabled.json.error, 'disabled');
});

test('§2 未知 /v1/dispatch/* → 404，已知路径用错方法 → 405', async (t) => {
  const a = await startServer(t, { allowRemotePrompts: true });
  const b = await startServer(t, { allowRemotePrompts: true });
  const { aId, aToB } = linkPair(a, b);

  const unknown = await request(b.baseUrl, { path: '/v1/dispatch/nope', peerId: aId, secret: aToB, encrypt: true });
  assert.equal(unknown.status, 404);
  assert.equal(unknown.json.error, 'not-found');

  const wrongMethod = await request(b.baseUrl, {
    method: 'POST',
    path: '/v1/dispatch/options',
    peerId: aId,
    secret: aToB,
    encrypt: true,
    body: {},
  });
  assert.equal(wrongMethod.status, 405);
  assert.equal(wrongMethod.json.error, 'method-not-allowed');
});

// ---------------------------------------------------------------------------
// §2 POST /v1/ask 的派单校验
// ---------------------------------------------------------------------------

test('§2 ask 校验顺序：未知 workspaceId 409 → 非法 permission 400 → 超上限 403', async (t) => {
  const a = await startServer(t, { allowRemotePrompts: true });
  const b = await startServer(t, { allowRemotePrompts: true, runner: createRunner({ delayMs: 5 }) });
  const { aId, aToB } = linkPair(a, b);

  // 未知工作区 + 非法权限：先命中 409（顺序不能反）
  const both = await askAs(b.baseUrl, { peerId: aId, secret: aToB, requestId: 'r-1', prompt: '顺序', workspaceId: 'ghost', permission: 'root' });
  assert.equal(both.status, 409);
  assert.equal(both.json.error, 'unknown-workspace');

  const unknownWorkspace = await askAs(b.baseUrl, { peerId: aId, secret: aToB, requestId: 'r-2', prompt: '未知工作区', workspaceId: 'ghost' });
  assert.equal(unknownWorkspace.status, 409);
  assert.equal(unknownWorkspace.json.error, 'unknown-workspace');

  const badPermission = await askAs(b.baseUrl, { peerId: aId, secret: aToB, requestId: 'r-3', prompt: '非法权限', workspaceId: 'main', permission: 'root' });
  assert.equal(badPermission.status, 400);
  assert.equal(badPermission.json.error, 'bad-permission');

  // 默认上限 workspace-write：请求 danger-full-access 直接 403，不进确认流程
  const denied = await askAs(b.baseUrl, { peerId: aId, secret: aToB, requestId: 'r-4', prompt: '超上限', workspaceId: 'main', permission: 'danger-full-access' });
  assert.equal(denied.status, 403);
  assert.equal(denied.json.error, 'permission-denied');
  assert.equal(b.server.dispatch.pending().length, 0, '403 不得留下待批准记录');
  assert.equal(b.server.runner.sessions.size, 0, '被拒的请求不得执行');
});

test('§2 请求档 ≤ 默认档 → 直接执行：对端收到 read-only 与点名的工作区', async (t) => {
  const a = await startServer(t, { allowRemotePrompts: true, logger: () => {} });
  const { runner, seen } = trackingRunner();
  const b = await startServer(t, { allowRemotePrompts: true, runner });
  const { aId, aToB } = linkPair(a, b);

  const accepted = await askAs(b.baseUrl, {
    peerId: aId,
    secret: aToB,
    requestId: 'r-direct',
    prompt: '只读跑一下',
    workspaceId: 'main',
    permission: 'read-only',
  });
  assert.equal(accepted.status, 202, accepted.text);
  assert.deepEqual(accepted.json.workspace, { id: 'main', name: '主工作区' }, '回包里只有 id + 名字');
  assert.equal(accepted.json.permission, 'read-only');
  assert.equal(JSON.stringify(accepted.json).includes(path.resolve(b.server.config.workspace)), false);

  // 执行侧确实拿到了那一组（runner 记录 + 会话记录两处都对得上）
  assert.equal(seen.length, 1);
  assert.equal(seen[0].permission, 'read-only');
  assert.equal(seen[0].workspace, path.resolve(b.server.config.workspace));
  const session = b.server.sessions.get(accepted.json.sessionId);
  assert.equal(session.workspaceId, 'main');
  assert.equal(session.workspaceName, '主工作区');
  assert.equal(session.permission, 'read-only');
  assert.equal(JSON.stringify(session).includes(path.resolve(b.server.config.workspace)), false, '会话记录里不存路径');

  const answered = await pollAnswer(b.baseUrl, { sessionId: accepted.json.sessionId, peerId: aId, secret: aToB, encrypt: true });
  assert.equal(answered.status, 'done');
});

test('§2 请求档 > 默认档但 ≤ 上限 → 202 pending-approval：不执行、正文不落盘、同 requestId 幂等', async (t) => {
  const marker = 'MARKER-PENDING-' + Math.random().toString(36).slice(2, 10);
  const a = await startServer(t, { allowRemotePrompts: true });
  const { runner, seen } = trackingRunner();
  const b = await startServer(t, { allowRemotePrompts: true, runner });
  const { aId, aToB } = linkPair(a, b);

  // 上限维持 workspace-write，默认档仍是 read-only → workspace-write 必须人工确认
  const accepted = await askAs(b.baseUrl, {
    peerId: aId,
    secret: aToB,
    requestId: 'r-pending',
    prompt: marker,
    workspaceId: 'main',
    permission: 'workspace-write',
  });
  assert.equal(accepted.status, 202, accepted.text);
  assert.deepEqual(Object.keys(accepted.json).sort(), ['approvalId', 'expiresAt', 'state']);
  assert.equal(accepted.json.state, 'pending-approval');
  assert.equal(typeof accepted.json.approvalId, 'string');
  assert.ok(accepted.json.expiresAt > Date.now());

  // 没执行：runner 一次都没被调用，也没有协议会话
  assert.equal(seen.length, 0, '待批准期间绝不能执行');
  assert.equal(b.server.sessions.size, 0);

  // 队列里有且只有一条；正文绝不落盘
  const list = b.server.dispatch.pending();
  assert.equal(list.length, 1);
  assert.equal(list[0].from, aId);
  assert.equal(list[0].workspaceId, 'main');
  assert.equal(list[0].workspaceName, '主工作区');
  assert.equal(list[0].permission, 'workspace-write');
  assert.equal(list[0].promptBytes, Buffer.byteLength(marker, 'utf8'));
  const pendingFile = path.join(b.stateDir, DISPATCH_PENDING_FILE);
  const raw = fs.readFileSync(pendingFile, 'utf8');
  assert.equal(raw.includes(marker), false, '待批准文件里不得有正文');
  assert.equal(raw.includes(path.resolve(b.server.config.workspace)), false, '待批准文件里不得有路径');
  if (process.platform !== 'win32') assert.equal(fileMode(pendingFile), 0o600);

  // 同一 requestId 重发：复用同一条（不排第二条队，也不执行）
  const replay = await askAs(b.baseUrl, {
    peerId: aId,
    secret: aToB,
    requestId: 'r-pending',
    prompt: marker,
    workspaceId: 'main',
    permission: 'workspace-write',
  });
  assert.equal(replay.status, 202);
  assert.equal(replay.json.approvalId, accepted.json.approvalId);
  assert.equal(b.server.dispatch.pending().length, 1);
});

test('§2/§4 批准后按请求的工作区与权限真正执行，sessionId 写回记录；只有发起方能读状态', async (t) => {
  const a = await startServer(t, { allowRemotePrompts: true });
  const c = await startServer(t, { allowRemotePrompts: true });
  const { runner, seen } = trackingRunner();
  const b = await startServer(t, { allowRemotePrompts: true, runner });
  const aId = a.server.store.instanceId;
  const bId = b.server.store.instanceId;
  const cId = c.server.store.instanceId;
  const aToB = 'k-ab-' + aId.slice(0, 4);
  const bToA = 'k-ba-' + bId.slice(0, 4);
  const cToB = 'k-cb-' + cId.slice(0, 4);
  const bToC = 'k-bc-' + bId.slice(0, 4);
  // B 同时认识 A 与 C：C 也是合法对端，但没资格读 A 的那条批准
  seedPeers(a.stateDir, [peerFixture(bId, { name: 'B', secret: aToB, inboundSecret: bToA, baseUrl: b.baseUrl })]);
  seedPeers(b.stateDir, [
    peerFixture(aId, { name: 'A', secret: bToA, inboundSecret: aToB, baseUrl: a.baseUrl }),
    peerFixture(cId, { name: 'C', secret: bToC, inboundSecret: cToB, baseUrl: c.baseUrl }),
  ]);
  seedPeers(c.stateDir, [peerFixture(bId, { name: 'B', secret: cToB, inboundSecret: bToC, baseUrl: b.baseUrl })]);

  const accepted = await askAs(b.baseUrl, {
    peerId: aId,
    secret: aToB,
    requestId: 'r-approve',
    prompt: '完全权限跑一下',
    workspaceId: 'main',
    permission: 'danger-full-access',
  });
  // 上限是 workspace-write → 直接 403（这里顺手证明「上限优先于确认流程」）
  assert.equal(accepted.status, 403);
  assert.equal(accepted.json.error, 'permission-denied');

  // 放开上限后重新请求：进入确认流程
  const saved = b.server.dispatch.savePrefs({ maxPermission: 'danger-full-access' });
  assert.equal(saved.maxPermission, 'danger-full-access');
  const pendingRes = await askAs(b.baseUrl, {
    peerId: aId,
    secret: aToB,
    requestId: 'r-approve-2',
    prompt: '完全权限跑一下',
    workspaceId: 'main',
    permission: 'danger-full-access',
  });
  assert.equal(pendingRes.status, 202);
  assert.equal(pendingRes.json.state, 'pending-approval');
  const approvalId = pendingRes.json.approvalId;

  // 状态查询：pending；别的对端读 → 404
  const peeked = await request(b.baseUrl, {
    path: '/v1/dispatch/approval?id=' + encodeURIComponent(approvalId),
    peerId: aId,
    secret: aToB,
    encrypt: true,
  });
  assert.equal(peeked.status, 200);
  assert.deepEqual(peeked.json, { state: 'pending' });

  const stranger = await request(b.baseUrl, {
    path: '/v1/dispatch/approval?id=' + encodeURIComponent(approvalId),
    peerId: cId,
    secret: cToB,
    encrypt: true,
  });
  assert.equal(stranger.status, 404);
  assert.equal(stranger.json.error, 'unknown-approval');

  const unknownId = await request(b.baseUrl, {
    path: '/v1/dispatch/approval?id=not-a-real-id',
    peerId: aId,
    secret: aToB,
    encrypt: true,
  });
  assert.equal(unknownId.status, 404);

  // 批准：真正执行，且按点名的 danger-full-access
  const approved = await b.server.dispatch.approve(approvalId);
  assert.equal(approved.ok, true, JSON.stringify(approved));
  assert.equal(approved.state, 'approved');
  assert.equal(typeof approved.sessionId, 'string');
  assert.equal(seen.length, 1);
  assert.equal(seen[0].permission, 'danger-full-access');
  assert.equal(seen[0].workspace, path.resolve(b.server.config.workspace));
  const session = b.server.sessions.get(approved.sessionId);
  assert.equal(session.permission, 'danger-full-access');
  assert.equal(b.server.dispatch.pending().length, 0);

  // sessionId 写回记录：文件里有，HTTP 也能读到
  const stored = JSON.parse(fs.readFileSync(path.join(b.stateDir, DISPATCH_PENDING_FILE), 'utf8')).pending[0];
  assert.equal(stored.state, 'approved');
  assert.equal(stored.sessionId, approved.sessionId);
  const readBack = await request(b.baseUrl, {
    path: '/v1/dispatch/approval?id=' + encodeURIComponent(approvalId),
    peerId: aId,
    secret: aToB,
    encrypt: true,
  });
  assert.deepEqual(readBack.json, { state: 'approved', sessionId: approved.sessionId });

  // 批准是幂等的：再点一次不会开第二个会话
  const again = await b.server.dispatch.approve(approvalId);
  assert.equal(again.ok, true);
  assert.equal(again.sessionId, approved.sessionId);
  assert.equal(seen.length, 1);

  // 发送方拿 sessionId 就能取回复
  const answered = await pollAnswer(b.baseUrl, { sessionId: approved.sessionId, peerId: aId, secret: aToB, encrypt: true });
  assert.equal(answered.status, 'done');
});

test('§4 拒绝不执行；未知 approvalId 一律 ok:false；TTL 到期变 expired', async (t) => {
  const a = await startServer(t, { allowRemotePrompts: true });
  const { runner, seen } = trackingRunner();
  const b = await startServer(t, { allowRemotePrompts: true, runner, dispatchPendingTtlMs: 300 });
  const { aId, aToB } = linkPair(a, b);

  const pendingRes = await askAs(b.baseUrl, {
    peerId: aId,
    secret: aToB,
    requestId: 'r-reject',
    prompt: '不该被执行',
    workspaceId: 'main',
    permission: 'workspace-write',
  });
  assert.equal(pendingRes.status, 202);
  const approvalId = pendingRes.json.approvalId;

  const rejected = b.server.dispatch.reject(approvalId);
  assert.deepEqual(rejected, { ok: true, state: 'rejected' });
  assert.equal(seen.length, 0, '拒绝后不得执行');
  assert.equal(b.server.sessions.size, 0);
  const readBack = await request(b.baseUrl, {
    path: '/v1/dispatch/approval?id=' + encodeURIComponent(approvalId),
    peerId: aId,
    secret: aToB,
    encrypt: true,
  });
  assert.deepEqual(readBack.json, { state: 'rejected' });

  // 拒绝之后不能再批准
  const approveRejected = await b.server.dispatch.approve(approvalId);
  assert.equal(approveRejected.ok, false);
  assert.equal(approveRejected.state, 'rejected');
  assert.equal(seen.length, 0);

  // 未知 id
  assert.equal((await b.server.dispatch.approve('nope')).ok, false);
  assert.equal(b.server.dispatch.reject('nope').state, 'unknown');
  assert.equal((await b.server.dispatch.approve('')).state, 'unknown');

  // TTL：第二个请求放着不管，300ms 后自己变 expired
  const expiring = await askAs(b.baseUrl, {
    peerId: aId,
    secret: aToB,
    requestId: 'r-expire',
    prompt: '十分钟也没人管',
    workspaceId: 'main',
    permission: 'workspace-write',
  });
  const expiringId = expiring.json.approvalId;
  await sleep(500);
  const expiredState = await request(b.baseUrl, {
    path: '/v1/dispatch/approval?id=' + encodeURIComponent(expiringId),
    peerId: aId,
    secret: aToB,
    encrypt: true,
  });
  assert.deepEqual(expiredState.json, { state: 'expired' });
  assert.equal(b.server.dispatch.pending().length, 0, '过期条目不再出现在待批准列表');
  const lateApprove = await b.server.dispatch.approve(expiringId);
  assert.equal(lateApprove.ok, false);
  assert.equal(lateApprove.state, 'expired');
  assert.equal(seen.length, 0, '过期后批准也不得执行');
});

// ---------------------------------------------------------------------------
// §4 门面：不传新字段时行为完全不变
// ---------------------------------------------------------------------------

test('§4 不传 workspaceId/permission 时 ask 与 dm.send 的回包一字不差（旧客户端不受影响）', async (t) => {
  const a = await startServer(t, { allowRemotePrompts: true });
  const b = await startServer(t, { allowRemotePrompts: true, runner: createRunner({ delayMs: 5 }) });
  const { aId, aToB, bId } = linkPair(a, b);

  const legacy = await askAs(b.baseUrl, { peerId: aId, secret: aToB, requestId: 'r-legacy', prompt: '老客户端' });
  assert.equal(legacy.status, 202);
  assert.deepEqual(Object.keys(legacy.json).sort(), ['dmSessionId', 'reused', 'sessionId'], '旧请求的回包不得多出字段');
  const legacySession = b.server.sessions.get(legacy.json.sessionId);
  assert.equal(legacySession.workspaceId, '', '没点名的会话不留派单标识');
  assert.equal(legacySession.permission, '');

  const sent = await a.server.dm.send({ peerId: bId, text: '老面板发一条' });
  assert.equal(sent.ok, true, JSON.stringify(sent));
  assert.deepEqual(
    Object.keys(sent).sort(),
    ['elapsedMs', 'id', 'ok', 'reply', 'reused', 'sessionId'],
    '不点名时 dm.send 的回包键集合与以前一致',
  );
  assert.equal(sent.reply, 'OK 老面板发一条');

  // 失败面同样是老形状
  assert.deepEqual(await a.server.dm.send({ peerId: '', text: 'x' }), { ok: false, reason: 'bad-peer' });
  assert.deepEqual(await a.server.dm.send({ peerId: 'peer-1', text: 'x' }), { ok: false, reason: 'unpaired' });

  // 没有待批准、没有 prefs 写盘副作用（除了 savePrefs 自己）
  assert.equal(b.server.dispatch.pending().length, 0);
  assert.equal(fs.existsSync(path.join(a.stateDir, DISPATCH_PREFS_FILE)), false);
});

// ---------------------------------------------------------------------------
// §4 门面：dm.send 点名工作区/权限
// ---------------------------------------------------------------------------

test('§4 dm.send 点名 read-only + 默认工作区：成功回包带 workspace/permission，对端按只读执行', async (t) => {
  const a = await startServer(t, { allowRemotePrompts: true, logger: () => {} });
  const { runner, seen } = trackingRunner();
  const b = await startServer(t, { allowRemotePrompts: true, runner, logger: () => {} });
  const { bId } = linkPair(a, b);

  const sent = await a.server.dm.send({ peerId: bId, text: '只读点名', workspaceId: 'main', permission: 'read-only' });
  assert.equal(sent.ok, true, JSON.stringify(sent));
  assert.deepEqual(sent.workspace, { id: 'main', name: '主工作区' });
  assert.equal(sent.permission, 'read-only');
  assert.equal(sent.reply, 'OK 只读点名');
  assert.equal(seen.length, 1);
  assert.equal(seen[0].permission, 'read-only');
  assert.equal(seen[0].workspace, path.resolve(b.server.config.workspace));
  // 本地正文与对端工作区路径都没有进日志（对端 A 的日志里更不该有别人的目录）
  assert.equal(JSON.stringify(sent).includes(path.resolve(b.server.config.workspace)), false);
});

test('§4 dm.send 超默认档 → 待批准形状；批准后按完全权限执行（A 的本地记录仍是 pending）', async (t) => {
  const a = await startServer(t, { allowRemotePrompts: true, logger: () => {} });
  const { runner, seen } = trackingRunner();
  const b = await startServer(t, { allowRemotePrompts: true, runner, logger: () => {} });
  const { aId, aToB, bId } = linkPair(a, b);
  assert.equal(b.server.dispatch.savePrefs({ maxPermission: 'danger-full-access' }).maxPermission, 'danger-full-access');

  const sent = await a.server.dm.send({ peerId: bId, text: '完全权限点名', workspaceId: 'main', permission: 'danger-full-access' });
  assert.deepEqual(
    Object.keys(sent).sort(),
    ['approvalId', 'expiresAt', 'ok', 'pendingApproval'],
    '待批准回包是冻结形状',
  );
  assert.equal(sent.ok, true);
  assert.equal(sent.pendingApproval, true);
  assert.equal(typeof sent.approvalId, 'string');
  assert.ok(sent.expiresAt > Date.now());
  assert.equal(seen.length, 0, '待批准期间不得执行');
  assert.equal(a.server.dm.list(bId)[0].state, 'pending', '发送方本地那条继续是 pending');

  const approved = await b.server.dispatch.approve(sent.approvalId);
  assert.equal(approved.ok, true);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].permission, 'danger-full-access');

  // 批准后发送方可以照常接上 /v1/answer
  const answered = await pollAnswer(b.baseUrl, { sessionId: approved.sessionId, peerId: aId, secret: aToB, encrypt: true });
  assert.equal(answered.status, 'done');
  assert.equal(answered.reply, 'OK 完全权限点名');
});

// ---------------------------------------------------------------------------
// §6 正文与路径都不进日志
// ---------------------------------------------------------------------------

test('§6 日志只有 peer 前缀 / 工作区 id / 权限 / 字节数：正文与任何绝对路径都不出现', async (t) => {
  const marker = 'MARKER-DISPATCH-' + Math.random().toString(36).slice(2, 10);
  const logs = [];
  const logger = (line) => logs.push(String(line));
  const a = await startServer(t, { allowRemotePrompts: true, logger });
  const b = await startServer(t, { allowRemotePrompts: true, logger, runner: createRunner({ delayMs: 5 }) });
  const { aId, aToB } = linkPair(a, b);
  const workspacePath = path.resolve(b.server.config.workspace);

  await askAs(b.baseUrl, { peerId: aId, secret: aToB, requestId: 'r-log-1', prompt: marker, workspaceId: 'main', permission: 'read-only' });
  const pendingRes = await askAs(b.baseUrl, { peerId: aId, secret: aToB, requestId: 'r-log-2', prompt: marker + '-2', workspaceId: 'main', permission: 'workspace-write' });
  await b.server.dispatch.approve(pendingRes.json.approvalId);
  await request(b.baseUrl, { path: '/v1/dispatch/options', peerId: aId, secret: aToB, encrypt: true });

  assert.ok(logs.some((line) => line.startsWith('[dispatch] pending')), '至少有 pending 日志行');
  assert.ok(logs.some((line) => line.startsWith('[dispatch] approve')), '至少有 approve 日志行');
  assert.ok(logs.some((line) => line.includes('ws=main')), '日志里只有工作区 id');
  for (const line of logs) {
    assert.equal(line.includes(marker), false, '登录里不得出现正文: ' + line);
    assert.equal(line.includes(workspacePath), false, '日志里不得出现工作区绝对路径: ' + line);
    assert.equal(line.includes(b.stateDir), false, '日志里不得出现 stateDir: ' + line);
  }
});

// ---------------------------------------------------------------------------
// §3 close()：定时器与内存正文一起收尾
// ---------------------------------------------------------------------------

test('§3 close() 收尾：待批准正文随内存丢掉，之后批准如实回 prompt-lost（不编造执行）', async (t) => {
  const a = await startServer(t, { allowRemotePrompts: true, logger: () => {} });
  const b = await startServer(t, { allowRemotePrompts: true, logger: () => {}, runner: createRunner({ delayMs: 5 }) });
  const { aId, aToB } = linkPair(a, b);

  const res = await askAs(b.baseUrl, { peerId: aId, secret: aToB, requestId: 'r-close', prompt: '关掉再批准', workspaceId: 'main', permission: 'workspace-write' });
  assert.equal(res.status, 202);
  const approvalId = res.json.approvalId;
  await b.server.close();

  const out = await b.server.dispatch.approve(approvalId);
  assert.equal(out.ok, false);
  assert.equal(out.state, 'expired');
  assert.equal(out.reason, 'prompt-lost');
  assert.equal(b.server.runner.sessions.size, 0);
});

// ---------------------------------------------------------------------------
// §1/§7 设置改完立即生效：新增工作区马上就能被点名
// ---------------------------------------------------------------------------

test('§1 新增工作区后立即生效（无需重启）：点名新 id 就在那个目录里执行', async (t) => {
  const a = await startServer(t, { allowRemotePrompts: true, logger: () => {} });
  const { runner, seen } = trackingRunner();
  const b = await startServer(t, { allowRemotePrompts: true, runner, logger: () => {} });
  const { aId, aToB } = linkPair(a, b);
  const secondDir = path.join(b.stateDir, 'second-workspace');
  fs.mkdirSync(secondDir, { recursive: true });

  const saved = b.server.dispatch.savePrefs({
    workspaces: [
      { id: 'main', name: '主工作区', path: path.resolve(b.server.config.workspace) },
      { id: 'second', name: '第二个', path: secondDir },
    ],
  });
  assert.equal(saved.workspaces.length, 2);
  // 本机视图有 path，对外视图没有
  assert.equal(b.server.dispatch.prefs().workspaces[1].path, path.resolve(secondDir));
  assert.deepEqual(b.server.dispatch.options().workspaces, [
    { id: 'main', name: '主工作区' },
    { id: 'second', name: '第二个' },
  ]);

  const accepted = await askAs(b.baseUrl, {
    peerId: aId,
    secret: aToB,
    requestId: 'r-second',
    prompt: '在第二个工作区跑',
    workspaceId: 'second',
    permission: 'read-only',
  });
  assert.equal(accepted.status, 202, accepted.text);
  assert.deepEqual(accepted.json.workspace, { id: 'second', name: '第二个' });
  assert.equal(seen.length, 1);
  assert.equal(seen[0].workspace, path.resolve(secondDir), '必须真的落到点名的那个目录');

  // 默认工作区还是 main：不点名时仍用本机默认路径（旧行为）
  const legacy = await askAs(b.baseUrl, { peerId: aId, secret: aToB, requestId: 'r-second-legacy', prompt: '不点名' });
  assert.equal(legacy.status, 202);
  assert.equal(seen.length, 2);
  // 不点名 = 连 options 都不传给 runner（旧调用形状），工作区由执行侧自己的默认值决定
  assert.equal(seen[1].workspace, null);
  assert.equal(seen[1].permission, null);
});

// ---------------------------------------------------------------------------
// §2/§3/§4 两个真进程：A 点名 read-only 直接执行；点名完全权限 → B 202 → 批准后执行
// ---------------------------------------------------------------------------

const CHILD_SCRIPT = String.raw`import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { ENC_VERSION, decryptBytes } from __WIRE_URL__;
import { createPeerServer } from __SERVER_URL__;

const NL = String.fromCharCode(10);
const [role, stateDir, selfName, selfId, peerId, peerUrl, peerName, keyOut, keyIn] = process.argv.slice(2);
fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
fs.writeFileSync(
  path.join(stateDir, 'state.json'),
  JSON.stringify({ instanceId: selfId, name: selfName, createdAt: new Date().toISOString() }, null, 2),
  { mode: 0o600 },
);
if (peerId && peerId !== '-') {
  const entry = {
    name: peerName,
    baseUrl: peerUrl === '-' ? null : peerUrl,
    secret: keyOut,
    inboundSecret: keyIn,
    addedAt: new Date().toISOString(),
    lastSeen: null,
  };
  const peers = {};
  peers[peerId] = entry;
  fs.writeFileSync(path.join(stateDir, 'peers.json'), JSON.stringify({ peers }, null, 2), { mode: 0o600 });
}

// 剧本执行侧：每个会话记住实际生效的权限与工作区（只打印是否存在，不打印路径）
const sessions = new Map();
const runner = {
  async ask(prompt, options = {}) {
    const id = 'dsh-' + (sessions.size + 1);
    const ws = typeof options.workspace === 'string' ? options.workspace : '';
    let wsExists = false;
    try {
      wsExists = ws !== '' && fs.statSync(ws).isDirectory();
    } catch {
      wsExists = false;
    }
    sessions.set(id, { prompt: String(prompt), permission: String(options.permission ?? ''), wsExists });
    process.stdout.write('RUN ' + id + ' perm=' + String(options.permission ?? '-') + ' wsExists=' + wsExists + NL);
    // 契约 §2 的权限回报：这个剧本执行侧真的按点名的档位跑，所以实际生效 = 请求值
    const stated = String(options.permission ?? '');
    return { sessionId: id, reused: false, ...(stated === '' ? {} : { appliedPermission: stated, permissionHonored: true }) };
  },
  poll(sessionId) {
    const session = sessions.get(sessionId);
    if (!session) return { status: 'error', error: 'session-not-found' };
    return { status: 'done', reply: 'REPLY[' + session.permission + '] ' + session.prompt.slice(0, 30) };
  },
};

const server = createPeerServer({
  stateDir,
  name: selfName,
  listenHost: '127.0.0.1',
  allowRemotePrompts: true,
  runner,
  logger: (line) => process.stdout.write('LOG ' + line + NL),
});
const info = await server.listen(0, '127.0.0.1');
process.stdout.write('READY ' + info.port + NL);

async function signedGet(apiPath) {
  const ts = Date.now();
  const nonce = crypto.randomBytes(16).toString('hex');
  const digest = crypto.createHash('sha256').update(Buffer.alloc(0)).digest('hex');
  const canonical = ['GET', apiPath, String(ts), nonce, digest].join(String.fromCharCode(10));
  const signature = crypto.createHmac('sha256', Buffer.from(keyOut, 'utf8')).update(canonical, 'utf8').digest('base64url');
  const res = await fetch(peerUrl + apiPath, {
    headers: {
      'x-peer-id': selfId,
      'x-peer-ts': String(ts),
      'x-peer-nonce': nonce,
      'x-peer-sign': signature,
      'x-peer-enc': ENC_VERSION,
    },
  });
  const text = await res.text();
  let json = null;
  try {
    const parsed = JSON.parse(text);
    json = parsed && parsed.enc === ENC_VERSION && typeof parsed.data === 'string'
      ? JSON.parse(decryptBytes(keyOut, parsed.data).toString('utf8'))
      : parsed;
  } catch {
    json = null;
  }
  return { status: res.status, json };
}

if (role === 'B') {
  const saved = server.dispatch.savePrefs({ maxPermission: 'danger-full-access' });
  process.stdout.write('PREFS ' + JSON.stringify({ maxPermission: saved.maxPermission, defaultWorkspaceId: saved.defaultWorkspaceId }) + NL);
  process.stdout.write('OPTIONS ' + JSON.stringify(server.dispatch.options()) + NL);
  let busy = false;
  setInterval(async () => {
    if (busy) return;
    const items = server.dispatch.pending();
    if (items.length === 0) return;
    busy = true;
    try {
      for (const item of items) {
        const out = await server.dispatch.approve(item.approvalId);
        process.stdout.write('APPROVED ' + JSON.stringify({ id: item.approvalId, ok: out.ok, state: out.state, sessionId: out.sessionId ?? null }) + NL);
      }
    } finally {
      busy = false;
    }
  }, 100).unref();
  process.on('SIGTERM', () => { server.close().finally(() => process.exit(0)); });
  setInterval(() => {}, 1000);
} else {
  const first = await server.dm.send({ peerId, text: 'READONLY-CHECK', workspaceId: 'main', permission: 'read-only' });
  process.stdout.write('A1 ' + JSON.stringify({
    ok: first.ok,
    workspace: first.workspace ?? null,
    permission: first.permission ?? null,
    reply: first.reply ?? null,
    reason: first.reason ?? null,
  }) + NL);
  const second = await server.dm.send({ peerId, text: 'APPROVAL-CHECK', workspaceId: 'main', permission: 'danger-full-access' });
  process.stdout.write('A2 ' + JSON.stringify({
    ok: second.ok,
    pendingApproval: second.pendingApproval === true,
    approvalId: second.approvalId ?? null,
    expiresAt: second.expiresAt ?? null,
  }) + NL);
  let approval = null;
  for (let round = 0; round < 100; round += 1) {
    const out = await signedGet('/v1/dispatch/approval?id=' + encodeURIComponent(second.approvalId));
    if (out.status === 200 && out.json && out.json.state !== 'pending') {
      approval = out.json;
      break;
    }
    await sleep(100);
  }
  process.stdout.write('A3 ' + JSON.stringify(approval ?? { state: 'timeout' }) + NL);
  if (approval && approval.sessionId) {
    const answer = await signedGet('/v1/answer?sessionId=' + encodeURIComponent(approval.sessionId) + '&waitMs=5000');
    process.stdout.write('A4 ' + JSON.stringify({ status: answer.status, body: answer.json }) + NL);
  }
  await server.close();
  process.exit(0);
}
`;

/** 按行读子进程输出（A1/A2 可能同一次 chunk 到齐，所以是队列不是一次性监听） */
function lineReader(child) {
  const lines = [];
  const waiters = new Set();
  let pending = '';
  const push = (line) => {
    lines.push(line);
    for (const waiter of [...waiters]) {
      if (waiter.predicate(line)) waiter.settle(line);
    }
  };
  child.stdout.on('data', (data) => {
    pending += String(data);
    const parts = pending.split(String.fromCharCode(10));
    pending = parts.pop();
    for (const part of parts) push(part);
  });
  child.stderr.on('data', (data) => push('STDERR ' + String(data).trim()));
  return {
    lines,
    waitFor(predicate, timeoutMs = 30_000) {
      const existing = lines.find(predicate);
      if (existing !== undefined) return Promise.resolve(existing);
      return new Promise((resolve, reject) => {
        let timer = null;
        const waiter = {
          predicate,
          settle(line) {
            clearTimeout(timer);
            waiters.delete(waiter);
            resolve(line);
          },
        };
        timer = setTimeout(() => {
          waiters.delete(waiter);
          reject(new Error('timeout waiting for child line; got: ' + lines.slice(-8).join(' | ')));
        }, timeoutMs);
        waiters.add(waiter);
      });
    },
  };
}

test('§2/§3/§4 两个真进程：A 点名只读直接执行；点名完全权限 → B 202 待批准 → 批准后按完全权限执行', async (t) => {
  const root = makeTempStateDir('dsh-dispatch-two-proc-');
  const scriptPath = path.join(root, 'demo-node.mjs');
  const serverUrl = pathToFileURL(path.join(process.cwd(), 'host', 'server.mjs')).href;
  const wireUrl = pathToFileURL(path.join(process.cwd(), 'lib', 'wire-crypto.mjs')).href;
  fs.writeFileSync(
    scriptPath,
    CHILD_SCRIPT.replace('__SERVER_URL__', JSON.stringify(serverUrl)).replace('__WIRE_URL__', JSON.stringify(wireUrl)),
  );

  const aDir = path.join(root, 'A');
  const bDir = path.join(root, 'B');
  fs.mkdirSync(aDir, { recursive: true });
  fs.mkdirSync(bDir, { recursive: true });
  const aId = 'peer-A-' + Math.random().toString(36).slice(2, 8);
  const bId = 'peer-B-' + Math.random().toString(36).slice(2, 8);
  const keyAToB = 'kab-' + Math.random().toString(36).slice(2, 10);
  const keyBToA = 'kba-' + Math.random().toString(36).slice(2, 10);

  const b = spawn(process.execPath, [scriptPath, 'B', bDir, 'B', bId, aId, '-', 'A', keyBToA, keyAToB], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  t.after(() => { try { b.kill('SIGTERM'); } catch {} });
  const bLines = lineReader(b);
  const ready = await bLines.waitFor((line) => line.startsWith('READY '));
  const bPort = Number(ready.slice('READY '.length).trim());
  assert.ok(bPort > 0, 'B 必须在真端口上监听');
  const bUrl = 'http://127.0.0.1:' + bPort;
  const prefsLine = await bLines.waitFor((line) => line.startsWith('PREFS '));
  assert.equal(JSON.parse(prefsLine.slice('PREFS '.length)).maxPermission, 'danger-full-access');
  // 验收第 3 条：options 响应里没有任何路径（B 自己打出来的那一份）
  const optionsLine = await bLines.waitFor((line) => line.startsWith('OPTIONS '));
  const optionsJson = JSON.stringify(JSON.parse(optionsLine.slice('OPTIONS '.length)));
  console.log('B 的 options 响应:', optionsJson);
  assert.equal(optionsJson.includes('path'), false, 'options 不得有 path 键');
  assert.equal(optionsJson.includes(bDir), false, 'options 不得有 stateDir');
  assert.equal(optionsJson.includes(path.sep + 'B' + path.sep), false, 'options 不得有工作区绝对路径');

  const a = spawn(process.execPath, [scriptPath, 'A', aDir, 'A', aId, bId, bUrl, 'B', keyAToB, keyBToA], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  t.after(() => { try { a.kill('SIGTERM'); } catch {} });
  const aLines = lineReader(a);
  const a1 = JSON.parse((await aLines.waitFor((line) => line.startsWith('A1 '))).slice(3));
  const a2 = JSON.parse((await aLines.waitFor((line) => line.startsWith('A2 '))).slice(3));
  const a3 = JSON.parse((await aLines.waitFor((line) => line.startsWith('A3 '))).slice(3));
  const a4 = JSON.parse((await aLines.waitFor((line) => line.startsWith('A4 '))).slice(3));

  // 演示流水（两个真进程，A 与 B 各自的 stdout 拼出来的）
  console.log('A1 (read-only)      :', JSON.stringify(a1));
  console.log('A2 (full-access)    :', JSON.stringify(a2));
  console.log('A3 (approval)       :', JSON.stringify(a3));
  console.log('A4 (answer)         :', JSON.stringify(a4));

  // 1) 只读：直接执行，B 拿到 read-only
  assert.equal(a1.ok, true, JSON.stringify(a1));
  assert.deepEqual(a1.workspace, { id: 'main', name: '主工作区' });
  assert.equal(a1.permission, 'read-only');
  assert.equal(a1.reply, 'REPLY[read-only] READONLY-CHECK');
  const run1 = await bLines.waitFor((line) => line.startsWith('RUN ') && line.includes('perm=read-only'));
  assert.equal(run1.includes('wsExists=true'), true, 'B 必须在点名的那个目录里执行');

  // 2) 完全权限：B 回 202，A 拿到 approvalId
  assert.equal(a2.ok, true, JSON.stringify(a2));
  assert.equal(a2.pendingApproval, true);
  assert.equal(typeof a2.approvalId, 'string');

  // 3) B 人工批准后真的执行了，A 通过 approval 端点拿到 sessionId 与回复
  assert.equal(a3.state, 'approved', JSON.stringify(a3));
  assert.equal(typeof a3.sessionId, 'string');
  const run2 = await bLines.waitFor((line) => line.startsWith('RUN ') && line.includes('perm=danger-full-access'));
  assert.equal(run2.includes('wsExists=true'), true);
  assert.equal(a4.status, 200, JSON.stringify(a4));
  assert.equal(a4.body.status, 'done');
  assert.equal(a4.body.reply, 'REPLY[danger-full-access] APPROVAL-CHECK');
  const approvedLine = await bLines.waitFor((line) => line.startsWith('APPROVED '));
  assert.equal(JSON.parse(approvedLine.slice('APPROVED '.length)).state, 'approved');

  // 4) 两个进程的日志里既没有正文也没有路径
  const allLogs = [...aLines.lines, ...bLines.lines].filter((line) => line.startsWith('LOG '));
  assert.ok(allLogs.some((line) => line.includes('[dispatch] pending')), 'B 应当有 pending 日志');
  for (const line of allLogs) {
    assert.equal(line.includes('READONLY-CHECK') || line.includes('APPROVAL-CHECK'), false, '日志里不得出现正文: ' + line);
    assert.equal(line.includes(bDir) || line.includes(aDir), false, '日志里不得出现 stateDir: ' + line);
  }

  // 5) 落盘证据：B 的待批准文件里没有正文，只有字节数
  const pendingRaw = fs.readFileSync(path.join(bDir, DISPATCH_PENDING_FILE), 'utf8');
  assert.equal(pendingRaw.includes('APPROVAL-CHECK'), false);
  assert.equal(JSON.parse(pendingRaw).pending.length, 1);
  fs.rmSync(root, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// §2 权限如实回报：回包里的 permission 必须是「实际生效」而不是「请求值」
// ---------------------------------------------------------------------------

/**
 * 一个如实回报的桩执行侧：distinct 于 MemoryRunner —— 它能假装「点了 X、实际跑的是 Y」，
 * 也就是真实 runner 在对端 RPC 层写不了会话级权限时的样子。
 */
function reportingRunner({ appliedPermission, permissionHonored, permissionReason, omitReport = false }) {
  const inner = createRunner({ delayMs: 5 });
  const runner = {
    async ask(prompt, options) {
      const base = await inner.ask(prompt, options);
      const sessionId = typeof base === 'string' ? base : base.sessionId;
      if (omitReport) return { sessionId, reused: base.reused === true };
      return {
        sessionId,
        reused: base.reused === true,
        appliedPermission,
        permissionHonored,
        ...(permissionReason === undefined ? {} : { permissionReason }),
      };
    },
    poll: (sessionId) => inner.poll(sessionId),
  };
  return runner;
}

test('§2 honored:true：permission 是实际档，requestedPermission 是请求档（假 runner 真的按档执行）', async (t) => {
  const a = await startServer(t, { allowRemotePrompts: true, logger: () => {} });
  const { runner } = trackingRunner();
  const b = await startServer(t, { allowRemotePrompts: true, runner, logger: () => {} });
  const { aId, aToB } = linkPair(a, b);

  const accepted = await askAs(b.baseUrl, {
    peerId: aId, secret: aToB, requestId: 'r-honored', prompt: '只读点名', workspaceId: 'main', permission: 'read-only',
  });
  assert.equal(accepted.status, 202, accepted.text);
  assert.equal(accepted.json.permission, 'read-only', '实际生效档');
  assert.equal(accepted.json.requestedPermission, 'read-only');
  assert.equal(accepted.json.permissionHonored, true);
});

test('§2 honored:false：permission 只报实际档，请求档走 requestedPermission（界面不再谎称生效）', async (t) => {
  const a = await startServer(t, { allowRemotePrompts: true, logger: () => {} });
  // 默认档抬到 workspace-write：点名 workspace-write 不需要人工确认，直接执行
  const runner = reportingRunner({
    appliedPermission: 'read-only',
    permissionHonored: false,
    permissionReason: 'session-permission-unsupported',
  });
  const b = await startServer(t, { allowRemotePrompts: true, permission: 'workspace-write', runner, logger: () => {} });
  const { aId, aToB, bId } = linkPair(a, b);

  const accepted = await askAs(b.baseUrl, {
    peerId: aId, secret: aToB, requestId: 'r-demoted', prompt: '点写实际只读', workspaceId: 'main', permission: 'workspace-write',
  });
  assert.equal(accepted.status, 202, accepted.text);
  assert.equal(accepted.json.permission, 'read-only', 'permission 必须是实际生效值，不是请求值');
  assert.equal(accepted.json.requestedPermission, 'workspace-write');
  assert.equal(accepted.json.permissionHonored, false);
  assert.equal(JSON.stringify(accepted.json).includes(path.resolve(b.server.config.workspace)), false);
  console.log('honored:false 的 /v1/ask 完整响应:', JSON.stringify(accepted.json));

  // 门面同名透传：dm.send 拿到的是同一组实值
  const sent = await a.server.dm.send({ peerId: bId, text: '降级点名', workspaceId: 'main', permission: 'workspace-write' });
  assert.equal(sent.ok, true, JSON.stringify(sent));
  assert.equal(sent.permission, 'read-only');
  assert.equal(sent.requestedPermission, 'workspace-write');
  assert.equal(sent.permissionHonored, false);
});

test('§2 runner 不回报权限三键：回落空串/false，不抛错也不臆造 honored', async (t) => {
  const logs = [];
  const a = await startServer(t, { allowRemotePrompts: true, logger: () => {} });
  const runner = reportingRunner({ omitReport: true });
  const b = await startServer(t, {
    allowRemotePrompts: true, runner, logger: (line) => logs.push(String(line)),
  });
  const { aId, aToB } = linkPair(a, b);

  const accepted = await askAs(b.baseUrl, {
    peerId: aId, secret: aToB, requestId: 'r-silent', prompt: '老 runner 不回报', workspaceId: 'main', permission: 'read-only',
  });
  assert.equal(accepted.status, 202, accepted.text);
  assert.equal(accepted.json.permission, '', '读不到实际档就是空串，不许回填请求值');
  assert.equal(accepted.json.requestedPermission, 'read-only');
  assert.equal(accepted.json.permissionHonored, false, '缺失不得读成 true');
  // 日志同样是空值出空值
  assert.ok(
    logs.some((line) => line === 'perm requested=read-only applied= honored=false reason='),
    logs.join(' | '),
  );
});

test('§6 权限日志只有 requested/applied/honored/reason：没有 path、没有 stateDir、没有正文', async (t) => {
  const marker = 'MARKER-PERM-' + Math.random().toString(36).slice(2, 10);
  const logs = [];
  const a = await startServer(t, { allowRemotePrompts: true, logger: () => {} });
  const runner = reportingRunner({
    appliedPermission: 'workspace-write',
    permissionHonored: true,
    permissionReason: 'matched-effective',
  });
  const b = await startServer(t, {
    allowRemotePrompts: true, permission: 'workspace-write', runner, logger: (line) => logs.push(String(line)),
  });
  const { aId, aToB } = linkPair(a, b);

  await askAs(b.baseUrl, {
    peerId: aId, secret: aToB, requestId: 'r-perm-log', prompt: marker, workspaceId: 'main', permission: 'workspace-write',
  });
  const permLines = logs.filter((line) => line.startsWith('perm '));
  assert.equal(permLines.length, 1, permLines.join(' | '));
  assert.equal(permLines[0], 'perm requested=workspace-write applied=workspace-write honored=true reason=matched-effective');
  for (const line of logs) {
    assert.equal(line.includes(marker), false, '权限日志里不得出现正文: ' + line);
    assert.equal(line.includes(b.stateDir), false, '权限日志里不得出现 stateDir: ' + line);
    assert.equal(line.includes(path.resolve(b.server.config.workspace)), false, '权限日志里不得出现工作区绝对路径: ' + line);
  }
});

