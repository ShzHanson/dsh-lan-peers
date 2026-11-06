// dsh-lan-peers · v0.8.5-α 群派单的可见面（管理接口层：契约 §3/§4）。
//
// 四件事在这里钉死：
//   1. GET group/dispatch-options?peer= 代理目标 options，回给面板的**只有 id 与 name**
//      （目标就算违约把 path 带回来，也在 dispatchOptionsView 这一层丢掉）；
//   2. POST group/post 透传 target/workspaceId/permission，一个都不带时请求体与 0.8.4 逐字一致；
//   3. pending-approval 是第四种终态，绝不并进 failed；
//   4. 门面没接线时如实回 501，出错只回稳定 reason（群是多人可见的，错误体不带目标侧路径）。
import test from 'node:test';
import assert from 'node:assert/strict';
import { createAdmin } from './admin.mjs';

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
  const handled = await admin.handle(makeRequest(method, apiPath, body, admin), res, new URL('http://127.0.0.1' + apiPath));
  return { handled, res, json: (() => { try { return JSON.parse(res.body); } catch { return null; } })() };
}

const MEMBERS = [
  { peerId: 'peer-hub', name: 'hub-box', online: true, lastSeen: 1, joinedAt: 1, acceptDispatch: true },
  { peerId: 'peer-nas', name: 'nas-box', online: true, lastSeen: 2, joinedAt: 2, acceptDispatch: true },
];

/** 目标侧 options（带 path：它必须在这一层被丢掉）。 */
const PEER_OPTIONS = {
  defaultWorkspaceId: 'main',
  maxPermission: 'workspace-write',
  workspaces: [
    { id: 'main', name: '主工作区', path: 'D:/work/main' },
    { id: 'docs', name: '文档', path: 'D:/work/docs' },
  ],
};

/** route 层后端桩：记录 group/post 收到的请求体。 */
function makeApi(reply = null) {
  const posts = [];
  return {
    posts,
    enabled: true,
    isHub: true,
    state() {
      return { groupId: 'g-1', name: '家里', members: MEMBERS, messages: [], lastSeq: 4 };
    },
    post(args) {
      posts.push(args);
      return reply === null ? { seq: 5, ts: 1_700_000_800_000 } : reply;
    },
    member() { return { members: MEMBERS }; },
    setName(args) { return { name: args.name }; },
    join() { return { groupId: 'g-1', epoch: 1 }; },
    claim() { return { ok: true, role: 'leader', epoch: 1 }; },
  };
}

/** facade = server.group：dispatchOptions（G-A 门面）+ dispatch（既有派单口）。 */
function makeFacade(overrides = {}) {
  const dispatched = [];
  const optionsAsked = [];
  // overrides 只改行为；记录永远发生在包装层（否则「透传给门面」这类断言会被 override 吞掉）。
  const innerOptions = overrides.dispatchOptions || (async () => PEER_OPTIONS);
  const innerDispatch = overrides.dispatch || (async (request) => ({
    status: 'done',
    target: request.target,
    targetName: 'nas-box',
    elapsedMs: 12,
    replyChars: 3,
    reply: 'REPLY-BODY-MUST-NOT-LEAK',
  }));
  const facade = {
    ...overrides,
    enabled: true,
    async dispatchOptions(peerId) {
      optionsAsked.push(peerId);
      return innerOptions(peerId);
    },
    async dispatch(request) {
      dispatched.push(request);
      return innerDispatch(request);
    },
  };
  return { facade, dispatched, optionsAsked };
}

function stubAdmin({ facade, postReply = null } = {}) {
  const lines = [];
  const api = makeApi(postReply);
  const store = { instanceId: 'inst-self', stateDir: '', listPeers: () => [], getPeer: () => null };
  const group = { enabled: true, hub: '', acceptDispatch: true };
  const admin = createAdmin({
    server: { config: { logger: (line) => lines.push(line), listenPort: 0, group }, store, group: facade },
    nameOf: () => 'self',
    rename: (n) => n,
    feed: null,
    pairing: { mode: 'auto' },
    group,
    groupApi: api,
  });
  return { admin, lines, api };
}

// ---------------------------------------------------------------------------
// GET /api/lan-peers/group/dispatch-options?peer=
// ---------------------------------------------------------------------------

test('GET group/dispatch-options：代理目标 options，只回 id 与 name（path 结构性丢掉）', async () => {
  const { facade, optionsAsked } = makeFacade();
  const { admin } = stubAdmin({ facade });
  const out = await hit(admin, 'GET', '/api/lan-peers/group/dispatch-options?peer=peer-nas');
  assert.equal(out.res.status, 200);
  assert.deepEqual(optionsAsked, ['peer-nas'], '按目标 peerId 代理一次');
  assert.deepEqual(out.json, {
    defaultWorkspaceId: 'main',
    maxPermission: 'workspace-write',
    workspaces: [{ id: 'main', name: '主工作区' }, { id: 'docs', name: '文档' }],
  });
  assert.equal(out.res.body.includes('D:/'), false, '目标侧的 path 一个字节都不许出现在响应里');
  assert.equal(Object.prototype.hasOwnProperty.call(out.json.workspaces[0], 'path'), false);
});

test('GET group/dispatch-options：缺 peer → 400 bad-peer，不碰门面', async () => {
  const { facade, optionsAsked } = makeFacade();
  const { admin } = stubAdmin({ facade });
  const out = await hit(admin, 'GET', '/api/lan-peers/group/dispatch-options');
  assert.equal(out.res.status, 400);
  assert.deepEqual(out.json, { error: 'bad-peer' });
  assert.deepEqual(optionsAsked, []);
});

test('GET group/dispatch-options：门面没接线 → 501（不假装「对方没有工作区」）', async () => {
  const { admin } = stubAdmin({ facade: { enabled: true } });
  const out = await hit(admin, 'GET', '/api/lan-peers/group/dispatch-options?peer=peer-nas');
  assert.equal(out.res.status, 501);
  assert.deepEqual(out.json, { error: 'dispatch-options-unsupported' });
});

test('GET group/dispatch-options：目标报错只回稳定 reason（错误体不带目标侧路径）', async () => {
  const { facade } = makeFacade({
    async dispatchOptions() {
      const error = new Error('read failed: D:/work/secret');
      throw error;
    },
  });
  const { admin, lines } = stubAdmin({ facade });
  const out = await hit(admin, 'GET', '/api/lan-peers/group/dispatch-options?peer=peer-nas');
  assert.equal(out.res.status, 502);
  assert.deepEqual(out.json, { error: 'options-unavailable' });
  assert.equal(out.res.body.includes('D:/'), false, '群是多人可见的：错误体不含目标侧路径');
  assert.match(lines.join('\n'), /group dispatch-options failed/);
});

// ---------------------------------------------------------------------------
// POST /api/lan-peers/group/post —— 新字段透传
// ---------------------------------------------------------------------------

test('POST group/post 带 target/workspaceId/permission：透传给发帖与派单，回执只有工作区名与权限档', async () => {
  const { facade, dispatched } = makeFacade({
    async dispatch(request) {
      return {
        status: 'done',
        target: request.target,
        targetName: 'nas-box',
        elapsedMs: 12,
        replyChars: 3,
        workspace: { id: 'main', name: '主工作区', path: 'D:/work/main' },
        permission: 'read-only',
        permissionHonored: true,
      };
    },
  });
  const { admin, api } = stubAdmin({ facade });
  const out = await hit(admin, 'POST', '/api/lan-peers/group/post', {
    kind: 'chat', text: '把构建跑一遍', target: 'peer-nas', workspaceId: 'main', permission: 'read-only',
  });
  assert.equal(out.res.status, 200);
  assert.deepEqual(api.posts, [{
    kind: 'chat', text: '把构建跑一遍', meta: {},
    target: 'peer-nas', workspaceId: 'main', permission: 'read-only',
  }], '三个新字段原样进发帖请求（hub 负责存进群历史）');
  assert.deepEqual(dispatched, [{
    target: 'peer-nas', task: '把构建跑一遍', extraTargets: 0, workspaceId: 'main', permission: 'read-only',
  }], '同一组字段透传给派单门面');
  assert.equal(out.json.dispatch.status, 'done');
  assert.deepEqual(out.json.dispatch.workspace, { id: 'main', name: '主工作区' },
    '回执里的工作区只有 id 与 name');
  assert.equal(out.json.dispatch.permission, 'read-only');
  assert.equal(out.json.dispatch.permissionHonored, true);
  assert.equal(out.res.body.includes('D:/'), false, '回执里绝无 path');
  assert.equal(out.res.body.includes('REPLY-BODY'), false, '回复正文永不进管理接口');
});

test('POST group/post 不带新字段：请求体与派单参数与 0.8.4 逐字一致（没有空串键）', async () => {
  const { facade, dispatched } = makeFacade();
  const { admin, api } = stubAdmin({ facade });
  const out = await hit(admin, 'POST', '/api/lan-peers/group/post', { kind: 'chat', text: '@!peer-nas 跑一下' });
  assert.equal(out.res.status, 200);
  assert.deepEqual(api.posts, [{ kind: 'chat', text: '@!peer-nas 跑一下', meta: {} }]);
  assert.deepEqual(dispatched, [{ target: 'peer-nas', task: '跑一下', extraTargets: 0 }]);
  assert.deepEqual(Object.keys(out.json).sort(), ['dispatch', 'ok', 'seq', 'ts'],
    '响应形状与 0.8.4 一致：不多一个 workspace/permission 键');
  assert.equal(out.json.dispatch.workspace, undefined);
});

test('POST group/post：纯文本 @!目标 任务 语法仍然可用（弹层只是显式化）', async () => {
  const { facade, dispatched } = makeFacade();
  const { admin } = stubAdmin({ facade });
  await hit(admin, 'POST', '/api/lan-peers/group/post', { kind: 'chat', text: '顺手看看 @!nas-box 日志' });
  assert.deepEqual(dispatched, [{ target: 'nas-box', task: '顺手看看 日志', extraTargets: 0 }],
    '@! 解析口径一个字都没变');
});

test('POST group/post：非法 permission → 400 bad-permission（既不发帖也不派单）', async () => {
  const { facade, dispatched } = makeFacade();
  const { admin, api } = stubAdmin({ facade });
  const out = await hit(admin, 'POST', '/api/lan-peers/group/post', {
    kind: 'chat', text: '跑一下', target: 'peer-nas', permission: 'root',
  });
  assert.equal(out.res.status, 400);
  assert.deepEqual(out.json, { error: 'bad-permission' });
  assert.deepEqual(api.posts, []);
  assert.deepEqual(dispatched, []);
});

test('POST group/post：pending-approval 是第四种终态，不并进 failed', async () => {
  const { facade } = makeFacade({
    async dispatch(request) {
      return {
        status: 'pending-approval',
        target: request.target,
        targetName: 'nas-box',
        workspace: { id: 'main', name: '主工作区' },
        permission: 'danger-full-access',
      };
    },
  });
  const { admin } = stubAdmin({ facade });
  const out = await hit(admin, 'POST', '/api/lan-peers/group/post', {
    kind: 'chat', text: '跑一下', target: 'peer-nas', permission: 'danger-full-access',
  });
  assert.equal(out.res.status, 200);
  assert.equal(out.json.dispatch.status, 'pending-approval', '「等目标点头」不许被写成失败');
  assert.equal(out.json.dispatch.reason, '');
  assert.deepEqual(out.json.dispatch.workspace, { id: 'main', name: '主工作区' });
  assert.equal(out.json.dispatch.permission, 'danger-full-access');
});

test('门面已经派过单（server.group.post 回派单摘要）→ 管理接口绝不再派第二次', async () => {
  const { facade, dispatched } = makeFacade();
  const { admin, api } = stubAdmin({
    facade,
    // host 侧真门面（G-A）带 token 时的形状：发帖 + 派单一次做完，回执就是派单摘要。
    postReply: {
      seq: 7,
      status: 'pending-approval',
      reason: null,
      target: 'peer-nas',
      targetName: 'nas-box',
      elapsedMs: 0,
      replyChars: 0,
      workspace: { id: 'main', name: '主工作区' },
      permission: 'danger-full-access',
      appliedPermission: null,
      permissionHonored: false,
      approvalId: 'ap-g-1',
    },
  });
  const out = await hit(admin, 'POST', '/api/lan-peers/group/post', {
    kind: 'chat', text: '跑一下', target: 'peer-nas', workspaceId: 'main', permission: 'danger-full-access',
  });
  assert.equal(out.res.status, 200);
  assert.equal(api.posts.length, 1);
  assert.deepEqual(dispatched, [], '同一个任务只许派一次（重派会让目标跑两遍）');
  assert.equal(out.json.seq, 7);
  assert.equal(out.json.dispatch.status, 'pending-approval');
  assert.deepEqual(out.json.dispatch.workspace, { id: 'main', name: '主工作区' });
  assert.equal(out.json.dispatch.permission, 'danger-full-access');
  assert.equal(out.json.dispatch.permissionHonored, false);
});

test('门面回 { ok:false, error } → 502 options-unavailable（不把失败画成「对方没有工作区」）', async () => {
  const { facade } = makeFacade({
    async dispatchOptions() {
      return { ok: false, error: 'unknown-peer', workspaces: [], defaultWorkspaceId: '', maxPermission: '' };
    },
  });
  const { admin } = stubAdmin({ facade });
  const out = await hit(admin, 'GET', '/api/lan-peers/group/dispatch-options?peer=peer-nas');
  assert.equal(out.res.status, 502);
  assert.deepEqual(out.json, { error: 'options-unavailable' });
});

// ---------------------------------------------------------------------------
// 门禁
// ---------------------------------------------------------------------------

test('两条群派单路由都沿用 token 门禁（无 token → 401）', async () => {
  const { facade, optionsAsked, dispatched } = makeFacade();
  const { admin } = stubAdmin({ facade });
  const noToken = { token: '' };
  const options = await hit({ ...admin, token: '' }, 'GET', '/api/lan-peers/group/dispatch-options?peer=peer-nas');
  assert.equal(options.res.status, 401);
  const post = await hit({ ...admin, token: '' }, 'POST', '/api/lan-peers/group/post', { kind: 'chat', text: 'x' });
  assert.equal(post.res.status, 401);
  assert.deepEqual(optionsAsked, [], '门禁先于门面');
  assert.deepEqual(dispatched, []);
  assert.equal(noToken.token, '');
});
