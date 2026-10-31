// dsh-lan-peers · v0.8.2-α 群内派单的可见面（管理接口层：契约 §1/§3/§4/§5）。
//
// 三件事在这里钉死：
//   1. @! 的解析口径（作者侧，POST 之后）；
//   2. 派单回执只回摘要 —— 正文既不出现在响应里，也不出现在日志里；
//   3. 门面（server.group.dispatch / setAcceptDispatch / dispatchState）缺失时如实降级，
//      绝不静默假装成功（Lane X 未接线时这是唯一能救场的降级面）。
import test from 'node:test';
import assert from 'node:assert/strict';
import { createAdmin, parseGroupDispatchCommand } from './admin.mjs';

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

function makeRequest(method, url, body) {
  const chunks = body === undefined ? [] : [Buffer.from(JSON.stringify(body))];
  const req = {
    method,
    url,
    socket: { remoteAddress: '127.0.0.1', setNoDelay() {} },
    headers: { 'content-type': 'application/json', 'content-length': String(chunks[0]?.length ?? 0) },
    on() { return req; },
    once() { return req; },
    async *[Symbol.asyncIterator]() { for (const chunk of chunks) yield chunk; },
  };
  return req;
}

async function hit(admin, method, apiPath, body) {
  const res = makeResponse();
  const handled = await admin.handle(makeRequest(method, apiPath, body), res, new URL('http://127.0.0.1' + apiPath));
  return { handled, res, json: (() => { try { return JSON.parse(res.body); } catch { return null; } })() };
}

const MEMBERS = [
  { peerId: 'peer-hub', name: 'hub-box', online: true, lastSeen: 1_700_000_000_000, joinedAt: 1, acceptDispatch: true },
  { peerId: 'peer-nas', name: 'nas-box', online: true, lastSeen: 1_700_000_500_000, joinedAt: 2, acceptDispatch: false },
  // 老对端：完全没有 acceptDispatch 字段 —— 必须显示成「接单中」
  { peerId: 'peer-old', name: 'old-box', online: false, lastSeen: null, joinedAt: 3 },
];

/** 记录后端调用的桩（route 层）。 */
function makeApi() {
  const calls = [];
  return {
    calls,
    enabled: true,
    isHub: true,
    state({ sinceSeq = 0 } = {}) {
      calls.push({ method: 'state', sinceSeq });
      return { groupId: 'g-1', name: 'default', members: MEMBERS, messages: [], lastSeq: 4 };
    },
    post(args) {
      calls.push({ method: 'post', ...args });
      return { seq: 5, ts: 1_700_000_800_000 };
    },
    member(args) { calls.push({ method: 'member', args }); return { members: MEMBERS }; },
    setName(args) { calls.push({ method: 'setName', args }); return { name: args.name }; },
    join() { calls.push({ method: 'join' }); return { groupId: 'g-1', epoch: 1 }; },
    claim() { calls.push({ method: 'claim' }); return { ok: true, role: 'leader', epoch: 1 }; },
  };
}

/**
 * facade = server.group。给了就是「host 已接线」，不给就是「Lane X 还没落地」。
 * 派单桩故意在返回值里塞一个正文标记：它必须被适配层丢掉。
 */
function makeFacade(overrides = {}) {
  const calls = [];
  const facade = {
    enabled: true,
    // host 侧（Lane X）真实接线时的读口：面板开关的权威值
    acceptDispatch() {
      calls.push({ method: 'acceptDispatch' });
      return true;
    },
    setAcceptDispatch(value) {
      calls.push({ method: 'setAcceptDispatch', value });
      return { acceptDispatch: value, persisted: true };
    },
    dispatchState() {
      calls.push({ method: 'dispatchState' });
      return { lastTarget: 'peer-nas', lastAt: 1_700_000_900_000, inFlight: false };
    },
    async dispatch(request) {
      calls.push({ method: 'dispatch', ...request });
      return {
        status: 'done',
        target: request.target,
        targetName: 'nas-box',
        elapsedMs: 1234,
        replyChars: 56,
        reply: 'REPLY-BODY-MUST-NOT-LEAK',
      };
    },
    ...overrides,
  };
  return { facade, calls };
}

function stubAdmin({ group = { enabled: true, hub: '', acceptDispatch: true }, facade = undefined } = {}) {
  const lines = [];
  const api = makeApi();
  const store = { instanceId: 'inst-self', stateDir: '', listPeers: () => [], getPeer: () => null };
  const admin = createAdmin({
    server: { config: { logger: (line) => lines.push(line), listenPort: 0, group }, store, group: facade },
    nameOf: () => 'self',
    rename: (n) => n,
    feed: null,
    pairing: { mode: 'auto' },
    group,
    // 未启用时不给后端桩：走真实判定（group.enabled=false → disabled），否则桩会盖掉配置。
    groupApi: group.enabled === true ? api : null,
  });
  return { admin, lines, api };
}

// ---------------------------------------------------------------------------
// 契约 §1：@! 的解析
// ---------------------------------------------------------------------------

test('@!名字 任务 → 派单；@名字 → 纯提及（零动作）', () => {
  assert.deepEqual(parseGroupDispatchCommand('@!nas-box 修一下 CI'), {
    target: 'nas-box', task: '修一下 CI', extraTargets: 0,
  });
  assert.equal(parseGroupDispatchCommand('@nas-box 只是提及'), null);
  assert.equal(parseGroupDispatchCommand('就是聊天'), null);
  assert.equal(parseGroupDispatchCommand(''), null);
});

test('只有 @! 没有任务：task 是空串（是否拒绝由 host 按 reason=empty 判定）', () => {
  assert.deepEqual(parseGroupDispatchCommand('@!nas-box'), { target: 'nas-box', task: '', extraTargets: 0 });
  assert.deepEqual(parseGroupDispatchCommand('@!nas-box   '), { target: 'nas-box', task: '', extraTargets: 0 });
});

test('一条消息里多个 @!：只取第一个，其余只回计数（multi-target-ignored 不整条拒绝）', () => {
  const parsed = parseGroupDispatchCommand('@!nas 第一单 @!hub 第二单');
  assert.equal(parsed.target, 'nas');
  assert.equal(parsed.extraTargets, 1);
  assert.match(parsed.task, /^第一单/);
});

test('任务文本 = 整条 text 去掉第一个 @!X 片段后 trim（前缀也保留）', () => {
  assert.deepEqual(parseGroupDispatchCommand('顺手看看 @!nas 日志'), {
    target: 'nas', task: '顺手看看 日志', extraTargets: 0,
  });
});

// ---------------------------------------------------------------------------
// 成员接单状态（契约 §4：老对端缺字段 = 接单中）
// ---------------------------------------------------------------------------

test('GET group：成员行带 acceptDispatch，缺字段按 true（老对端绝不显示成已关闭）', async () => {
  const { facade } = makeFacade();
  const { admin } = stubAdmin({ facade });
  const out = await hit(admin, 'GET', '/api/lan-peers/group?sinceSeq=0');
  assert.equal(out.res.status, 200);
  const members = out.json.group.members;
  assert.equal(members[0].acceptDispatch, true);
  assert.equal(members[1].acceptDispatch, false);
  assert.equal(members[2].acceptDispatch, true, '缺字段 = 接单中');
});

test('GET group：带出本机开关与派单状态；门面没接线时 dispatch 为 null', async () => {
  const { facade } = makeFacade();
  const wired = stubAdmin({ facade });
  const out = await hit(wired.admin, 'GET', '/api/lan-peers/group?sinceSeq=0');
  assert.equal(out.json.acceptDispatch, true, '配置里没写 acceptDispatch = 接单中');
  assert.deepEqual(out.json.dispatch, { lastTarget: 'peer-nas', lastAt: 1_700_000_900_000, inFlight: false });

  const { admin } = stubAdmin({ group: { enabled: true, hub: '', acceptDispatch: false } });
  const off = await hit(admin, 'GET', '/api/lan-peers/group?sinceSeq=0');
  assert.equal(off.json.acceptDispatch, false);
  assert.equal(off.json.dispatch, null, '门面没有 dispatchState 时不编造状态');

  // 门面同时给了 acceptDispatch() 读口时以它为准（那是运行期热切换后的值，
  // 配置可能还是启动时那份）：host 读口说「接单中」，就不该按配置显示「已关闭」。
  const hot = stubAdmin({ group: { enabled: true, hub: '', acceptDispatch: false }, facade });
  const wiredOut = await hit(hot.admin, 'GET', '/api/lan-peers/group?sinceSeq=0');
  assert.equal(wiredOut.json.acceptDispatch, true, '以 host 的运行期读口为准');
});

// ---------------------------------------------------------------------------
// 契约 §4：本机接单开关
// ---------------------------------------------------------------------------

test('POST group/accept：转发给 host 门面并回显新状态（persisted 如实透传）', async () => {
  const { facade, calls } = makeFacade();
  const { admin, lines } = stubAdmin({ facade });
  const out = await hit(admin, 'POST', '/api/lan-peers/group/accept', { acceptDispatch: false });
  assert.equal(out.res.status, 200);
  assert.deepEqual(out.json, { ok: true, acceptDispatch: false, persisted: true });
  assert.deepEqual(calls[0], { method: 'setAcceptDispatch', value: false });
  assert.match(lines.join('\n'), /\[admin\] group accept -> off persisted=true/);

  const back = await hit(admin, 'POST', '/api/lan-peers/group/accept', { acceptDispatch: true });
  assert.equal(back.json.acceptDispatch, true);
});

test('POST group/accept：非布尔的 acceptDispatch → 400，一个门面调用都不发生', async () => {
  const { facade, calls } = makeFacade();
  const { admin } = stubAdmin({ facade });
  for (const bad of [undefined, null, 'off', 0, 1]) {
    const out = await hit(admin, 'POST', '/api/lan-peers/group/accept', { acceptDispatch: bad });
    assert.equal(out.res.status, 400, 'acceptDispatch=' + JSON.stringify(bad));
    assert.equal(out.json.error, 'bad-accept');
  }
  assert.deepEqual(calls, []);
});

test('POST group/accept：门面没接线 → 501 accept-toggle-unsupported（不假装已切）', async () => {
  const { admin, lines } = stubAdmin({});
  const out = await hit(admin, 'POST', '/api/lan-peers/group/accept', { acceptDispatch: false });
  assert.equal(out.res.status, 501);
  assert.equal(out.json.error, 'accept-toggle-unsupported');
  assert.match(lines.join('\n'), /group accept failed/);
});

test('POST group/accept：群未启用 → 409 group-disabled', async () => {
  const { admin } = stubAdmin({ group: { enabled: false } });
  const out = await hit(admin, 'POST', '/api/lan-peers/group/accept', { acceptDispatch: false });
  assert.equal(out.res.status, 409);
  assert.equal(out.json.error, 'group-disabled');
});

// ---------------------------------------------------------------------------
// 契约 §3：作者侧派单入口（POST group/dispatch）
// ---------------------------------------------------------------------------

test('POST group/dispatch：done → 只回摘要字段，正文不进响应也不进日志', async () => {
  const { facade, calls } = makeFacade();
  const { admin, lines } = stubAdmin({ facade });
  const out = await hit(admin, 'POST', '/api/lan-peers/group/dispatch', {
    target: 'nas-box', task: 'TASK-TEXT-MUST-NOT-LEAK',
  });
  assert.equal(out.res.status, 200);
  assert.equal(out.json.ok, true);
  assert.deepEqual(out.json.dispatch, {
    target: 'nas-box', targetName: 'nas-box', status: 'done', reason: '', elapsedMs: 1234, replyChars: 56,
  });
  assert.equal('reply' in out.json.dispatch, false, '正文不得出现在管理接口');
  assert.doesNotMatch(out.res.body, /REPLY-BODY-MUST-NOT-LEAK/);
  assert.doesNotMatch(lines.join('\n'), /TASK-TEXT-MUST-NOT-LEAK|REPLY-BODY-MUST-NOT-LEAK/,
    '任务文本与回复正文都不许进日志');
  assert.deepEqual(calls.find((c) => c.method === 'dispatch'), {
    method: 'dispatch', target: 'nas-box', task: 'TASK-TEXT-MUST-NOT-LEAK', extraTargets: 0,
  });
});

test('POST group/dispatch：failed 带 reason（not-accepting/offline/busy…）仍是 200', async () => {
  const { facade } = makeFacade({
    dispatch: async (request) => ({ status: 'failed', target: request.target, reason: 'not-accepting' }),
  });
  const { admin } = stubAdmin({ facade });
  const out = await hit(admin, 'POST', '/api/lan-peers/group/dispatch', { target: 'nas', task: 'x' });
  assert.equal(out.res.status, 200);
  assert.equal(out.json.ok, false, '业务失败不是接口错误，但 ok 必须为 false');
  assert.equal(out.json.dispatch.status, 'failed');
  assert.equal(out.json.dispatch.reason, 'not-accepting');
  assert.equal(out.json.dispatch.elapsedMs, null);
});

test('POST group/dispatch：skipped（没有 @! 目标）原样透传，不折算成 done/failed', async () => {
  const { facade } = makeFacade({
    dispatch: async () => ({ status: 'skipped', reason: 'no-target' }),
  });
  const { admin } = stubAdmin({ facade });
  const out = await hit(admin, 'POST', '/api/lan-peers/group/dispatch', { target: 'nas', task: '' });
  assert.equal(out.json.dispatch.status, 'skipped');
  assert.equal(out.json.dispatch.reason, 'no-target');
  assert.equal(out.json.ok, false);
});

test('POST group/dispatch：未知 status 一律按 failed + reason=error（绝不猜成完成）', async () => {
  const { facade } = makeFacade({ dispatch: async () => ({ status: 'weird' }) });
  const { admin } = stubAdmin({ facade });
  const out = await hit(admin, 'POST', '/api/lan-peers/group/dispatch', { target: 'nas', task: 'x' });
  assert.equal(out.json.dispatch.status, 'failed');
  assert.equal(out.json.dispatch.reason, 'error');
});

test('POST group/dispatch：参数校验 400 bad-target / 413 payload-too-large', async () => {
  const { facade, calls } = makeFacade();
  const { admin } = stubAdmin({ facade });
  const empty = await hit(admin, 'POST', '/api/lan-peers/group/dispatch', { target: '  ', task: 'x' });
  assert.equal(empty.res.status, 400);
  assert.equal(empty.json.error, 'bad-target');

  const huge = await hit(admin, 'POST', '/api/lan-peers/group/dispatch', {
    target: 'nas', task: 'x'.repeat(4001),
  });
  assert.equal(huge.res.status, 413);
  assert.equal(huge.json.error, 'payload-too-large');
  assert.deepEqual(calls, []);
});

test('POST group/dispatch：门面没接线 → 501 dispatch-unsupported', async () => {
  const { admin, lines } = stubAdmin({});
  const out = await hit(admin, 'POST', '/api/lan-peers/group/dispatch', { target: 'nas', task: 'x' });
  assert.equal(out.res.status, 200, '派单失败是业务结果：接口仍 200，但 dispatch.status=failed');
  assert.equal(out.json.dispatch.status, 'failed');
  assert.equal(out.json.dispatch.reason, 'dispatch-unsupported');
  assert.match(lines.join('\n'), /group dispatch failed/);
});

// ---------------------------------------------------------------------------
// 契约 §1/§5：panel 路径（POST group/post 内含 @!）的作者侧自动触发
// ---------------------------------------------------------------------------

test('POST group/post：正文带 @!X → 消息先入库，再派单一单（只一单），响应带摘要', async () => {
  const { facade, calls } = makeFacade();
  const { admin, api } = stubAdmin({ facade });
  const out = await hit(admin, 'POST', '/api/lan-peers/group/post', {
    kind: 'chat', text: '@!nas-box 跑一下回归',
  });
  assert.equal(out.res.status, 200);
  assert.equal(out.json.seq, 5);
  assert.equal(out.json.dispatch.status, 'done');
  const dispatches = calls.filter((c) => c.method === 'dispatch');
  assert.equal(dispatches.length, 1, '一条消息最多解析一个 @!，也最多派一单');
  assert.equal(dispatches[0].task, '跑一下回归');
  assert.equal(api.calls.filter((c) => c.method === 'post').length, 1, '群消息只写一次');
  assert.equal(api.calls.find((c) => c.method === 'post').kind, 'chat');
});

test('POST group/post：普通 @名字（无感叹号）→ 零派单、零 dispatch 字段', async () => {
  const { facade, calls } = makeFacade();
  const { admin } = stubAdmin({ facade });
  const out = await hit(admin, 'POST', '/api/lan-peers/group/post', { kind: 'chat', text: '@nas-box 只是提及' });
  assert.equal(out.res.status, 200);
  assert.equal('dispatch' in out.json, false);
  assert.equal(calls.filter((c) => c.method === 'dispatch').length, 0);
});

test('POST group/post：progress/result 回执里出现 @! 也不触发派单（回执不是命令）', async () => {
  const { facade, calls } = makeFacade();
  const { admin } = stubAdmin({ facade });
  await hit(admin, 'POST', '/api/lan-peers/group/post', { kind: 'result', text: '@!nas 别派我' });
  assert.equal(calls.filter((c) => c.method === 'dispatch').length, 0);
});

test('POST group/post：派单失败不回滚已发出的消息（seq 照旧、HTTP 仍 200）', async () => {
  const { admin, api } = stubAdmin({});
  const out = await hit(admin, 'POST', '/api/lan-peers/group/post', { kind: 'chat', text: '@!nas 跑一下' });
  assert.equal(out.res.status, 200);
  assert.equal(out.json.seq, 5, '消息已经发出去了，不能因为派单失败就假装没发');
  assert.equal(out.json.dispatch.status, 'failed');
  assert.equal(out.json.dispatch.reason, 'dispatch-unsupported');
  assert.equal(api.calls.filter((c) => c.method === 'post').length, 1);
});
