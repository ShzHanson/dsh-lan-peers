/**
 * 0.9.0-α 契约 §1–§5：会话复用策略的**接线**行为（真监听、真签名、真 202）
 *
 * 覆盖：
 *   - TTL 内复用同一个 DSH 会话（不是「每次都新建」，也不是「一直复用」）；
 *   - 超过批准窗口 → 静默新建；窗口内 → 走**既有**待批准 202（三键形状不变）；
 *   - 拒绝 / 过期 → 回落复用（标 reused:true），而不是让这一问失败；
 *   - 权限档 / 工作区不同 → 三元不匹配 → 不复用（跨档复用 = 跨权限复用）；
 *   - 接收方用 sessionNewRequestAllowed=false 拒绝发送方的「要新会话」请求；
 *   - 别的对端拿着我的 dmSessionId 仍然只能新建（owner 检查没有被放宽）。
 *
 * 时间用**改账本锚点**的方式拨动（不改 config.now）：签名/重放窗口走的是真时钟，
 * 假时钟会把 ts 校验一起拨坏，测出来的东西就不是生产形状了。
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { setTimeout as sleep } from 'node:timers/promises';

import { SESSION_REUSE_CONFIG_FILE, SESSION_NEW_REQUEST_ALLOWED_KEY } from '../../lib/session-reuse-prefs.mjs';
import { createRunner } from '../server.mjs';
import { makeTempStateDir, peerFixture, pollAnswer, request, seedPeers, startServer } from './helpers.mjs';

const HOUR = 3_600_000;
const DAY = 24 * HOUR;

const PEER = peerFixture('peer-reuse-a');

/** 两个节点互认（跳过配对），返回四条签名材料 */
function linkPair(a, b) {
  const aId = a.server.store.instanceId;
  const bId = b.server.store.instanceId;
  const aToB = 'k-' + aId.slice(0, 6) + '-to-' + bId.slice(0, 6);
  const bToA = 'k-' + bId.slice(0, 6) + '-to-' + aId.slice(0, 6);
  seedPeers(a.stateDir, [peerFixture(bId, { name: 'B', secret: aToB, inboundSecret: bToA, baseUrl: b.baseUrl })]);
  seedPeers(b.stateDir, [peerFixture(aId, { name: 'A', secret: bToA, inboundSecret: aToB, baseUrl: a.baseUrl })]);
  return { aId, bId, aToB, bToA };
}

/** 以签名 + 信封身份向 /v1/ask 发一条 */
function askAs(baseUrl, { peerId, secret, requestId, prompt, ...extra }) {
  return request(baseUrl, {
    method: 'POST',
    path: '/v1/ask',
    peerId,
    secret,
    encrypt: true,
    body: { requestId, prompt, ...extra },
  });
}

function approvalAs(baseUrl, { peerId, secret, approvalId }) {
  return request(baseUrl, {
    path: '/v1/dispatch/approval?id=' + encodeURIComponent(approvalId),
    peerId,
    secret,
    encrypt: true,
  });
}

/** 把账本里所有会话的「最近使用」往前拨 ms —— 这是唯一的「时间旅行」入口 */
function ageSessions(server, ms) {
  let count = 0;
  for (const session of server.sessions.values()) {
    session.lastUsedAt = (Number.isFinite(session.lastUsedAt) ? session.lastUsedAt : Date.now()) - ms;
    count += 1;
  }
  return count;
}

function decisions(lines) {
  return lines.filter((line) => String(line).startsWith('[dispatch] session reuse='));
}

// ---------------------------------------------------------------------------
// S3：TTL 内复用 / 窗口外静默新建 / 窗口内待批准
// ---------------------------------------------------------------------------

test('S3 同一 peer+workspace+permission、TTL 内第二次 ask → 复用同一个 DSH 会话', async (t) => {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [PEER]);
  const runner = createRunner({ delayMs: 5 });
  const { baseUrl } = await startServer(t, { stateDir, runner, allowRemotePrompts: true });
  const auth = { peerId: PEER.peerId, secret: PEER.inboundSecret };

  const first = await askAs(baseUrl, { ...auth, requestId: 'r1', prompt: '第一轮' });
  assert.equal(first.status, 202);
  assert.equal(first.json.reused, false);

  const second = await askAs(baseUrl, { ...auth, requestId: 'r2', prompt: '第二轮' });
  assert.equal(second.status, 202);
  assert.equal(second.json.reused, true, '同一个三元、TTL 内必须复用');
  assert.equal(second.json.dmSessionId, first.json.dmSessionId, '复用 = 同一个 DSH 会话 id');
  assert.notEqual(second.json.sessionId, first.json.sessionId, '协议会话每次仍是新的');
  assert.equal(runner.sessions.size, 1, '复用不该在 runner 侧新建会话');
  assert.equal(runner.sessions.get(first.json.dmSessionId).turns, 2);
  // 复用也要真的打进去：第二轮的回答来自同一个会话
  const done = await pollAnswer(baseUrl, { ...auth, sessionId: second.json.sessionId });
  assert.equal(done.status, 'done');
  assert.equal(done.reply, 'OK 第二轮');
});

test('S3 gap 超过批准窗口（8d）→ 静默新建（不排队），reason=ttl-expired', async (t) => {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [PEER]);
  const lines = [];
  const runner = createRunner({ delayMs: 5 });
  const { baseUrl, server } = await startServer(t, {
    stateDir, runner, allowRemotePrompts: true, logger: (line) => lines.push(line),
  });
  const auth = { peerId: PEER.peerId, secret: PEER.inboundSecret };

  const first = await askAs(baseUrl, { ...auth, requestId: 'r1', prompt: '很久以前' });
  assert.equal(ageSessions(server, 8 * DAY), 1, '账本里应有一条会话可拨');

  const second = await askAs(baseUrl, { ...auth, requestId: 'r2', prompt: '现在' });
  assert.equal(second.status, 202);
  assert.equal(second.json.state, undefined, '窗口外是静默新建，不是待批准');
  assert.notEqual(second.json.dmSessionId, first.json.dmSessionId);
  assert.equal(second.json.reused, false);
  assert.equal(runner.sessions.size, 2);
  assert.equal(server.dispatch.pending().length, 0, '静默新建不产生待批准记录');
  const last = decisions(lines).at(-1);
  assert.match(last, /^\[dispatch\] session reuse=new reason=ttl-expired gap_ms=\d+$/);
});

test('S3 gap 在批准窗口内（25h）→ 既有 202 待批准三键形状，且这一问没有执行', async (t) => {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [PEER]);
  const lines = [];
  const runner = createRunner({ delayMs: 5 });
  const { baseUrl, server } = await startServer(t, {
    stateDir, runner, allowRemotePrompts: true, logger: (line) => lines.push(line),
  });
  const auth = { peerId: PEER.peerId, secret: PEER.inboundSecret };

  await askAs(baseUrl, { ...auth, requestId: 'r1', prompt: '一天以前' });
  ageSessions(server, 25 * HOUR);

  const pendingAsk = await askAs(baseUrl, { ...auth, requestId: 'r2', prompt: '要新会话吗' });
  assert.equal(pendingAsk.status, 202);
  assert.deepEqual(
    Object.keys(pendingAsk.json).sort(),
    ['approvalId', 'expiresAt', 'state'],
    '复用策略的 202 必须与既有待批准 202 同一个键集合',
  );
  assert.equal(pendingAsk.json.state, 'pending-approval');
  assert.equal(runner.sessions.size, 1, '等批准期间不得执行');
  assert.equal(server.dispatch.pending().length, 1);
  assert.match(decisions(lines).at(-1), /reuse=approval reason=within-window gap_ms=\d+/);

  // 同一个 requestId 再发一次是**重放**（既有的 pending replay 分支），不排第二条
  const replay = await askAs(baseUrl, { ...auth, requestId: 'r2', prompt: '要新会话吗' });
  assert.equal(replay.json.approvalId, pendingAsk.json.approvalId);
  assert.equal(server.dispatch.pending().length, 1);
});

test('S3 批准 → 按人点的那件事执行：新建会话（不是复用）', async (t) => {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [PEER]);
  const runner = createRunner({ delayMs: 5 });
  const { baseUrl, server } = await startServer(t, { stateDir, runner, allowRemotePrompts: true });
  const auth = { peerId: PEER.peerId, secret: PEER.inboundSecret };

  const first = await askAs(baseUrl, { ...auth, requestId: 'r1', prompt: '旧会话' });
  ageSessions(server, 25 * HOUR);
  const pendingAsk = await askAs(baseUrl, { ...auth, requestId: 'r2', prompt: '新会话' });

  const approved = await server.dispatch.approve(pendingAsk.json.approvalId);
  assert.equal(approved.ok, true, JSON.stringify(approved));
  assert.equal(approved.state, 'approved');
  assert.equal(typeof approved.sessionId, 'string');
  assert.equal(runner.sessions.size, 2, '人批准的是「新建」，就必须真新建');
  const created = server.sessions.get(approved.sessionId);
  assert.notEqual(created.dmSessionId, first.json.dmSessionId);
  const state = await approvalAs(baseUrl, { ...auth, approvalId: pendingAsk.json.approvalId });
  assert.deepEqual(state.json, { state: 'approved', sessionId: approved.sessionId });
});

test('S3 拒绝 → 回落复用：GET 回 rejected+reused+sessionId，且这一问真的执行了', async (t) => {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [PEER]);
  const runner = createRunner({ delayMs: 5 });
  const { baseUrl, server } = await startServer(t, { stateDir, runner, allowRemotePrompts: true });
  const auth = { peerId: PEER.peerId, secret: PEER.inboundSecret };

  const first = await askAs(baseUrl, { ...auth, requestId: 'r1', prompt: '旧会话' });
  ageSessions(server, 25 * HOUR);
  const pendingAsk = await askAs(baseUrl, { ...auth, requestId: 'r2', prompt: '被拒的一问' });

  const rejected = await server.dispatch.reject(pendingAsk.json.approvalId);
  assert.deepEqual(rejected, { ok: true, state: 'rejected' });

  const state = await approvalAs(baseUrl, { ...auth, approvalId: pendingAsk.json.approvalId });
  assert.equal(state.status, 200);
  assert.equal(state.json.state, 'rejected', '状态如实是 rejected');
  assert.equal(state.json.reused, true, '但结论是回落复用，不是失败');
  const sessionId = state.json.sessionId;
  assert.equal(typeof sessionId, 'string');
  assert.equal(runner.sessions.size, 1, '回落复用不许新建 runner 会话');
  assert.equal(server.sessions.get(sessionId).dmSessionId, first.json.dmSessionId);
  const done = await pollAnswer(baseUrl, { ...auth, sessionId });
  assert.equal(done.status, 'done');
  assert.equal(done.reply, 'OK 被拒的一问');
});

test('S3 过期 → 同样回落复用（待批准 TTL 300ms）', async (t) => {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [PEER]);
  const runner = createRunner({ delayMs: 5 });
  const { baseUrl, server } = await startServer(t, {
    stateDir, runner, allowRemotePrompts: true, dispatchPendingTtlMs: 300,
  });
  const auth = { peerId: PEER.peerId, secret: PEER.inboundSecret };

  const first = await askAs(baseUrl, { ...auth, requestId: 'r1', prompt: '旧会话' });
  ageSessions(server, 25 * HOUR);
  const pendingAsk = await askAs(baseUrl, { ...auth, requestId: 'r2', prompt: '没人管的一问' });
  assert.equal(pendingAsk.json.state, 'pending-approval');
  await sleep(500);

  const state = await approvalAs(baseUrl, { ...auth, approvalId: pendingAsk.json.approvalId });
  assert.equal(state.json.state, 'expired');
  assert.equal(state.json.reused, true);
  assert.equal(runner.sessions.size, 1);
  assert.equal(server.sessions.get(state.json.sessionId).dmSessionId, first.json.dmSessionId);
});

// ---------------------------------------------------------------------------
// S4：权限档 / 工作区不同 → 三元不匹配 → 不复用
// ---------------------------------------------------------------------------

test('S4 低档不能复用高档会话，高档也不能复用低档会话', async (t) => {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [PEER]);
  const runner = createRunner({ delayMs: 5 });
  // 默认执行档抬到 workspace-write：read-only / workspace-write 都不触发权限批准，
  // 这样走的才是**复用策略**这条分支（权限批准是另一条路）。
  const { baseUrl } = await startServer(t, { stateDir, runner, allowRemotePrompts: true, permission: 'workspace-write' });
  const auth = { peerId: PEER.peerId, secret: PEER.inboundSecret };

  const low = await askAs(baseUrl, { ...auth, requestId: 'r1', prompt: '只读的', permission: 'read-only' });
  assert.equal(low.status, 202);
  const high = await askAs(baseUrl, { ...auth, requestId: 'r2', prompt: '可写的', permission: 'workspace-write' });
  assert.equal(high.status, 202);
  assert.notEqual(high.json.dmSessionId, low.json.dmSessionId, '权限档不同 = 不同会话');
  assert.equal(high.json.reused, false);
  assert.equal(runner.sessions.size, 2);

  // 反向：拿低档去撞刚才的会话，也必须新建（回到 read-only 那一档就是复用它的老会话）
  const lowAgain = await askAs(baseUrl, { ...auth, requestId: 'r3', prompt: '又是只读', permission: 'read-only' });
  assert.equal(lowAgain.json.dmSessionId, low.json.dmSessionId, '同档同三元 → 复用 read-only 那条');
  assert.equal(lowAgain.json.reused, true);
  const highAgain = await askAs(baseUrl, { ...auth, requestId: 'r4', prompt: '又可写', permission: 'workspace-write' });
  assert.equal(highAgain.json.dmSessionId, high.json.dmSessionId, '同档同三元 → 复用 workspace-write 那条');
  assert.equal(runner.sessions.size, 2, '四条请求只该有两条 runner 会话');
});

test('S4 工作区不同 → 不复用（同工作区回来仍然复用）', async (t) => {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [PEER]);
  const runner = createRunner({ delayMs: 5 });
  const { baseUrl, server } = await startServer(t, { stateDir, runner, allowRemotePrompts: true });
  const mainDir = path.join(stateDir, 'ws-main');
  const docsDir = path.join(stateDir, 'ws-docs');
  fs.mkdirSync(mainDir, { recursive: true });
  fs.mkdirSync(docsDir, { recursive: true });
  const saved = server.dispatch.savePrefs({
    maxPermission: 'read-only',
    workspaces: [
      { id: 'main', name: '主工作区', path: mainDir },
      { id: 'docs', name: '文档', path: docsDir },
    ],
  });
  assert.deepEqual(saved.workspaces.map((row) => row.id), ['main', 'docs']);
  const auth = { peerId: PEER.peerId, secret: PEER.inboundSecret };

  const inMain = await askAs(baseUrl, { ...auth, requestId: 'r1', prompt: '主工作区', workspaceId: 'main' });
  const inDocs = await askAs(baseUrl, { ...auth, requestId: 'r2', prompt: '文档区', workspaceId: 'docs' });
  assert.equal(inMain.status, 202);
  assert.equal(inDocs.status, 202);
  assert.notEqual(inDocs.json.dmSessionId, inMain.json.dmSessionId, '工作区不同 = 不同会话');
  assert.equal(runner.sessions.size, 2);
  const backToMain = await askAs(baseUrl, { ...auth, requestId: 'r3', prompt: '回主工作区', workspaceId: 'main' });
  assert.equal(backToMain.json.dmSessionId, inMain.json.dmSessionId);
  assert.equal(backToMain.json.reused, true);
  assert.equal(runner.sessions.size, 2);
});

// ---------------------------------------------------------------------------
// S3：接收方对「发送方要新会话」的话语权
// ---------------------------------------------------------------------------

test('S3 发送方要新会话 + 默认允许（gap 2h）→ 待批准；接收方关掉后同一请求只复用', async (t) => {
  const allowDir = makeTempStateDir();
  seedPeers(allowDir, [PEER]);
  const allowRunner = createRunner({ delayMs: 5 });
  const allow = await startServer(t, { stateDir: allowDir, runner: allowRunner, allowRemotePrompts: true });
  const auth = { peerId: PEER.peerId, secret: PEER.inboundSecret };

  const first = await askAs(allow.baseUrl, { ...auth, requestId: 'r1', prompt: '先聊一句' });
  ageSessions(allow.server, 2 * HOUR);
  const requested = await askAs(allow.baseUrl, { ...auth, requestId: 'r2', prompt: '我要新会话', requestNewSession: true });
  assert.equal(requested.json.state, 'pending-approval', '窗口内要新会话 → 要人点头');
  assert.equal(allowRunner.sessions.size, 1);

  // 同一个「要新会话」的请求，接收方在 config.json 里关掉之后 → 请求被拒 → 复用旧会话
  const denyDir = makeTempStateDir();
  seedPeers(denyDir, [PEER]);
  const denyRunner = createRunner({ delayMs: 5 });
  const deny = await startServer(t, { stateDir: denyDir, runner: denyRunner, allowRemotePrompts: true });
  fs.writeFileSync(
    path.join(denyDir, SESSION_REUSE_CONFIG_FILE),
    JSON.stringify({ [SESSION_NEW_REQUEST_ALLOWED_KEY]: false }),
    'utf8',
  );
  const mine = await askAs(deny.baseUrl, { ...auth, requestId: 'r1', prompt: '先聊一句' });
  ageSessions(deny.server, 2 * HOUR);
  const ignored = await askAs(deny.baseUrl, { ...auth, requestId: 'r2', prompt: '我要新会话', requestNewSession: true });
  assert.equal(ignored.status, 202);
  assert.equal(ignored.json.state, undefined, '被拒的请求不该拉出待批准');
  assert.equal(ignored.json.reused, true);
  assert.equal(ignored.json.dmSessionId, mine.json.dmSessionId, '接收方说了算：仍然复用');
  assert.equal(denyRunner.sessions.size, 1);
  assert.equal(deny.server.dispatch.pending().length, 0);
});

// ---------------------------------------------------------------------------
// 幂等 / owner 检查 / 日志形状
// ---------------------------------------------------------------------------

test('S1 复用策略不削弱 owner 检查：别的对端拿我的 dmSessionId 仍然只能新建', async (t) => {
  const stateDir = makeTempStateDir();
  const other = peerFixture('peer-reuse-other');
  seedPeers(stateDir, [PEER, other]);
  const runner = createRunner({ delayMs: 5 });
  const { baseUrl } = await startServer(t, { stateDir, runner, allowRemotePrompts: true });

  const mine = await askAs(baseUrl, { peerId: PEER.peerId, secret: PEER.inboundSecret, requestId: 'r1', prompt: '我的会话' });
  const stolen = await askAs(baseUrl, {
    peerId: other.peerId,
    secret: other.inboundSecret,
    requestId: 'r2',
    prompt: '借你的会话',
    sessionId: mine.json.dmSessionId,
  });
  assert.equal(stolen.status, 202);
  assert.equal(stolen.json.reused, false, '跨 peer 的锚点一律不复用');
  assert.notEqual(stolen.json.dmSessionId, mine.json.dmSessionId);
  assert.equal(runner.sessions.size, 2, '每个对端各一条会话');
});

test('S5 决策日志：一行一决策、形状稳定、不含正文与绝对路径', async (t) => {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [PEER]);
  const lines = [];
  const runner = createRunner({ delayMs: 5 });
  const { baseUrl, server } = await startServer(t, {
    stateDir, runner, allowRemotePrompts: true, logger: (line) => lines.push(String(line)),
  });
  const auth = { peerId: PEER.peerId, secret: PEER.inboundSecret };
  const workspace = path.resolve(server.config.workspace);
  const PROMPT = '别把我写进日志-marker-9917';

  await askAs(baseUrl, { ...auth, requestId: 'r1', prompt: PROMPT });
  await askAs(baseUrl, { ...auth, requestId: 'r2', prompt: PROMPT });
  ageSessions(server, 25 * HOUR);
  const pending = await askAs(baseUrl, { ...auth, requestId: 'r3', prompt: PROMPT });
  // 同一个 requestId 再发一次：既有 pending replay 那条线必须还在（并复用同一条记录）
  const replay = await askAs(baseUrl, { ...auth, requestId: 'r3', prompt: PROMPT });
  assert.equal(replay.json.approvalId, pending.json.approvalId);

  const seen = decisions(lines);
  assert.equal(seen.length, 4, '每个决策恰好一行');
  for (const line of seen) {
    assert.match(line, /^\[dispatch\] session reuse=(reuse|new|approval) reason=[a-z-]+ gap_ms=-?\d+$/);
    assert.equal(line.includes(PROMPT), false, '日志不许带正文');
    assert.equal(line.includes(workspace), false, '日志不许带绝对路径');
  }
  assert.deepEqual(
    seen.map((line) => line.split(' ')[2]),
    ['reuse=new', 'reuse=reuse', 'reuse=approval', 'reuse=approval'],
  );
  // 既有三条 202 语义线（executed / pending / pending replay）一条都没丢
  assert.ok(lines.some((line) => line.startsWith('[dispatch] executed')));
  assert.ok(lines.some((line) => line.startsWith('[dispatch] pending from=')));
  assert.ok(lines.some((line) => line.startsWith('[dispatch] pending replay')));
  t.diagnostic(seen.join(' | '));
});
