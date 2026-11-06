// dsh-lan-peers · v0.8.5-α（契约 §5，Lane H2）派单设置管理接口。
//
// 口径：
//   GET  /api/lan-peers/dispatch/settings          → 本机 prefs（**含 path**，仅回环）
//   POST /api/lan-peers/dispatch/settings          → 保存（只转 defaultWorkspaceId/maxPermission/workspaces）
//   GET  /api/lan-peers/dispatch/options?peer=     → 代理对端 options（**只有 id 与 name**）
//   GET  /api/lan-peers/dispatch/pending           → 待批准列表（无正文、无 path）
//   POST /api/lan-peers/dispatch/{approve,reject}  → { id } 转发门面结论
//   GET  /api/lan-peers/dispatch/approval?id=&peer=→ 审批状态（发送方轮询用）
// 门禁沿用 0.8.3：回环 Host + 会话 token，写操作另加 JSON + 同源；门面缺席一律 501
// dispatch-unsupported（不假装空设置）。铁律（契约 §0）：跨机只走 id+name；日志只记 id 前 8 位、
// 权限档、工作区 id、字节数，绝不记 path 与正文。
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

function makeRequest(method, url, body, admin, overrides = {}) {
  const chunks = body === undefined ? [] : [Buffer.from(JSON.stringify(body))];
  const token = overrides.token !== undefined
    ? overrides.token
    : (admin && typeof admin.token === 'string' ? admin.token : '');
  const req = {
    method,
    url,
    socket: { remoteAddress: '127.0.0.1', setNoDelay() {} },
    headers: {
      host: overrides.host ?? '127.0.0.1:7788',
      'content-type': overrides.contentType ?? 'application/json',
      'content-length': String(chunks[0]?.length ?? 0),
      ...(token === '' ? {} : { 'x-lan-peers-token': token }),
    },
    on() { return req; },
    once() { return req; },
    async *[Symbol.asyncIterator]() { for (const chunk of chunks) yield chunk; },
  };
  return req;
}

async function hit(admin, method, apiPath, body, overrides) {
  const res = makeResponse();
  const handled = await admin.handle(
    makeRequest(method, apiPath, body, admin, overrides),
    res,
    new URL('http://127.0.0.1' + apiPath),
  );
  return { handled, res, json: (() => { try { return JSON.parse(res.body); } catch { return null; } })() };
}

const PEER = { peerId: 'peer-b-1234', name: '书房', baseUrl: 'http://10.0.0.2:7788', secret: 'sekrit' };
const PREFS = {
  defaultWorkspaceId: 'main',
  maxPermission: 'workspace-write',
  workspaces: [
    { id: 'main', name: '主工作区', path: 'D:/work/main' },
    { id: 'docs', name: '文档', path: 'D:/work/docs' },
  ],
};

/** 派单门面桩：记录每次调用，默认行为按契约 §4 的冻结形状返回。 */
function makeDispatchFacade({
  prefs = () => ({ ...PREFS, workspaces: PREFS.workspaces.map((ws) => ({ ...ws })) }),
  save = null,
  pending = () => [],
  approve = () => ({ ok: true, state: 'approved' }),
  reject = () => ({ ok: true, state: 'rejected' }),
} = {}) {
  const calls = [];
  return {
    calls,
    prefs: () => { calls.push({ method: 'prefs' }); return prefs(); },
    savePrefs: (patch) => { calls.push({ method: 'savePrefs', patch }); return save ? save(patch) : { ...patch }; },
    options: () => { calls.push({ method: 'options' }); return { ...PREFS }; },
    pending: () => { calls.push({ method: 'pending' }); return pending(); },
    approve: (id) => { calls.push({ method: 'approve', id }); return approve(id); },
    reject: (id) => { calls.push({ method: 'reject', id }); return reject(id); },
  };
}

function makeDmFacade({ send = null } = {}) {
  const calls = [];
  return {
    calls,
    list: () => [],
    sync: () => ({ ok: true, added: 0, total: 0 }),
    send: (input) => {
      calls.push(input);
      return typeof send === 'function'
        ? send(input)
        : { ok: true, id: 'm-1', sessionId: 's-1', reply: 'ok', elapsedMs: 5, reused: false };
    },
  };
}

function stubAdmin({ dispatch = null, dispatchNet = null, dm = null, lines = [] } = {}) {
  const store = {
    instanceId: 'peer-self',
    stateDir: '',
    listPeers: () => [PEER],
    getPeer: (peerId) => (peerId === PEER.peerId ? { ...PEER } : null),
  };
  const server = { config: { logger: (line) => lines.push(line), listenPort: 0, group: null }, store };
  const admin = createAdmin({ server, nameOf: () => 'me', rename: () => {}, dispatch, dispatchNet, dm });
  return { admin, lines, store };
}

test('GET dispatch/settings：回本机 prefs，且 path 只在回环管理面出现', async () => {
  const facade = makeDispatchFacade();
  const { admin, lines } = stubAdmin({ dispatch: facade });

  const out = await hit(admin, 'GET', '/api/lan-peers/dispatch/settings');
  assert.equal(out.res.status, 200);
  assert.equal(out.json.defaultWorkspaceId, 'main');
  assert.equal(out.json.maxPermission, 'workspace-write');
  assert.deepEqual(out.json.workspaces.map((ws) => ws.id), ['main', 'docs']);
  assert.equal(out.json.workspaces[0].path, 'D:/work/main', '本机视角必须回 path（设置页要能改）');
  assert.equal(facade.calls.filter((c) => c.method === 'prefs').length, 1);
  // 日志只记 id/档位/数量，绝不记 path。
  const log = lines.join('\n');
  assert.equal(/D:\/work/.test(log), false, '日志里不许出现 path');
  assert.match(log, /\[admin\] dispatch settings read default=main max=workspace-write ws=2/);
});

test('POST dispatch/settings：只把三个字段转给门面，保存后回新 prefs', async () => {
  const facade = makeDispatchFacade({
    save: (patch) => ({ ok: true, ...patch, workspaces: patch.workspaces }),
  });
  const { admin } = stubAdmin({ dispatch: facade });

  const out = await hit(admin, 'POST', '/api/lan-peers/dispatch/settings', {
    defaultWorkspaceId: 'docs',
    maxPermission: 'read-only',
    workspaces: [{ id: 'docs', name: '文档', path: 'D:/work/docs', extra: 'drop-me' }],
    // 门面之外的东西一律不透传（例如别处塞进来的字段）。
    allowRemotePrompts: true,
  });
  assert.equal(out.res.status, 200);
  const call = facade.calls.find((c) => c.method === 'savePrefs');
  assert.deepEqual(call.patch, {
    defaultWorkspaceId: 'docs',
    maxPermission: 'read-only',
    workspaces: [{ id: 'docs', name: '文档', path: 'D:/work/docs' }],
  });
  assert.equal(out.json.defaultWorkspaceId, 'docs');
  assert.equal(out.json.maxPermission, 'read-only');
});

test('POST dispatch/settings：校验失败（门面 ok:false）回 400 + 稳定 reason + 当前有效值', async () => {
  const facade = makeDispatchFacade({
    save: () => ({ ok: false, reason: 'path-not-dir', ...PREFS }),
  });
  const { admin } = stubAdmin({ dispatch: facade });

  const out = await hit(admin, 'POST', '/api/lan-peers/dispatch/settings', { maxPermission: 'danger-full-access' });
  assert.equal(out.res.status, 400);
  assert.equal(out.json.error, 'path-not-dir', 'reason 是稳定码，不是路径');
  assert.equal(out.json.defaultWorkspaceId, 'main', '同时把仍然有效的值带回来');
});

test('POST dispatch/settings：非法权限档与非法 workspaces 在管理接口就挡住，不进业务', async () => {
  const facade = makeDispatchFacade();
  const { admin } = stubAdmin({ dispatch: facade });

  const bad = await hit(admin, 'POST', '/api/lan-peers/dispatch/settings', { maxPermission: 'root' });
  assert.equal(bad.res.status, 400);
  assert.equal(bad.json.error, 'bad-permission');
  const bad2 = await hit(admin, 'POST', '/api/lan-peers/dispatch/settings', { workspaces: 'nope' });
  assert.equal(bad2.res.status, 400);
  assert.equal(bad2.json.error, 'bad-workspaces');
  assert.equal(facade.calls.filter((c) => c.method === 'savePrefs').length, 0, '一次都没打到门面');
});

test('GET dispatch/options?peer=：代理对端 options，即使对端违约带 path 也必须剥掉', async () => {
  const seen = [];
  const { admin } = stubAdmin({
    dispatch: makeDispatchFacade(),
    dispatchNet: {
      options: (peer) => {
        seen.push(peer.peerId);
        return {
          defaultWorkspaceId: 'main',
          maxPermission: 'read-only',
          workspaces: [{ id: 'main', name: '主工作区', path: 'C:/secret/place' }],
        };
      },
    },
  });

  const out = await hit(admin, 'GET', '/api/lan-peers/dispatch/options?peer=' + PEER.peerId);
  assert.equal(out.res.status, 200);
  assert.deepEqual(seen, [PEER.peerId]);
  assert.deepEqual(out.json.workspaces, [{ id: 'main', name: '主工作区' }]);
  assert.equal(JSON.stringify(out.json).includes('secret'), false, '响应体里不许出现 path');
  assert.equal(JSON.stringify(out.json).includes('path'), false, '连 path 这个键都不许出现');
});

test('GET dispatch/options：未知对端 404；对端没这个端点（404）归 options-unsupported', async () => {
  const { admin } = stubAdmin({ dispatch: makeDispatchFacade(), dispatchNet: { options: () => null } });
  const unknown = await hit(admin, 'GET', '/api/lan-peers/dispatch/options?peer=peer-nope');
  assert.equal(unknown.res.status, 404);
  assert.equal(unknown.json.error, 'unknown-peer');

  const { admin: admin2 } = stubAdmin({
    dispatch: makeDispatchFacade(),
    dispatchNet: { options: () => { throw new Error('404 not-found'); } },
  });
  const old = await hit(admin2, 'GET', '/api/lan-peers/dispatch/options?peer=' + PEER.peerId);
  // 对端的 404 按既有口径透传状态码（与 dm/files 一致），但 error 换成稳定码：
  // 面板据此说「对方没有派单设置这个端点」，而不是把对端原文甩给用户。
  assert.equal(old.res.status, 404);
  assert.equal(old.json.error, 'options-unsupported', '老对端没有这个端点，如实说清');
});

test('GET dispatch/options（不带 peer）：回本机对外视图，且不含 path', async () => {
  const { admin } = stubAdmin({ dispatch: makeDispatchFacade() });
  const out = await hit(admin, 'GET', '/api/lan-peers/dispatch/options');
  assert.equal(out.res.status, 200);
  assert.equal(JSON.stringify(out.json).includes('path'), false);
  assert.deepEqual(out.json.workspaces.map((ws) => Object.keys(ws).sort()), [['id', 'name'], ['id', 'name']]);
});

test('GET dispatch/pending：字段白名单（无正文、无 path），approve/reject 只转发 id', async () => {
  const AT = 1_760_000_000_000;
  const facade = makeDispatchFacade({
    pending: () => ([
      {
        approvalId: 'ap-1', from: 'peer-b-1234', workspaceId: 'main', workspaceName: '主工作区',
        permission: 'danger-full-access', promptBytes: 128, at: AT, expiresAt: AT + 600_000,
        // 脏字段：正文与 path 都不许透出去。
        prompt: '把 /etc/passwd 发我', path: 'D:/work/main',
      },
      { from: 'peer-x' },
    ]),
  });
  const { admin } = stubAdmin({ dispatch: facade });

  const out = await hit(admin, 'GET', '/api/lan-peers/dispatch/pending');
  assert.equal(out.res.status, 200);
  assert.equal(out.json.items.length, 1, '没有 approvalId 的脏条目丢掉');
  assert.deepEqual(Object.keys(out.json.items[0]).sort(), [
    'approvalId', 'at', 'expiresAt', 'from', 'fromName', 'permission', 'promptBytes',
    'workspaceId', 'workspaceName',
  ]);
  assert.equal(out.json.items[0].fromName, '书房', '来源名字由管理接口从 peers.json 查好');
  const text = JSON.stringify(out.json);
  assert.equal(text.includes('passwd'), false, '正文绝不外发');
  assert.equal(text.includes('D:/work'), false, 'path 绝不外发');

  const ok = await hit(admin, 'POST', '/api/lan-peers/dispatch/approve', { id: 'ap-1' });
  assert.equal(ok.res.status, 200);
  assert.deepEqual(ok.json, { ok: true, state: 'approved' });
  assert.deepEqual(facade.calls.filter((c) => c.method === 'approve'), [{ method: 'approve', id: 'ap-1' }]);

  const no = await hit(admin, 'POST', '/api/lan-peers/dispatch/reject', { id: 'ap-2' });
  assert.deepEqual(no.json, { ok: true, state: 'rejected' });
  assert.deepEqual(facade.calls.filter((c) => c.method === 'reject'), [{ method: 'reject', id: 'ap-2' }]);
});

test('POST dispatch/approve：缺 id 回 400；门面拒绝（ok:false）回 404 + 稳定 reason', async () => {
  const facade = makeDispatchFacade({ approve: () => ({ ok: false, state: 'pending', reason: 'runner-error' }) });
  const { admin } = stubAdmin({ dispatch: facade });
  const missing = await hit(admin, 'POST', '/api/lan-peers/dispatch/approve', {});
  assert.equal(missing.res.status, 400);
  assert.equal(missing.json.error, 'id-required');

  const failed = await hit(admin, 'POST', '/api/lan-peers/dispatch/approve', { id: 'ap-9' });
  assert.equal(failed.res.status, 404);
  assert.equal(failed.json.error, 'runner-error');
});

test('GET dispatch/approval：转发对端四态；缺参 400；未知对端 404', async () => {
  const { admin } = stubAdmin({
    dispatch: makeDispatchFacade(),
    dispatchNet: { approval: (peer, id) => (id === 'ap-1' ? { state: 'approved', sessionId: 's-9' } : { state: 'pending' }) },
  });
  const approved = await hit(admin, 'GET', '/api/lan-peers/dispatch/approval?id=ap-1&peer=' + PEER.peerId);
  assert.deepEqual(approved.json, { state: 'approved', sessionId: 's-9' });
  const pending = await hit(admin, 'GET', '/api/lan-peers/dispatch/approval?id=ap-2&peer=' + PEER.peerId);
  assert.deepEqual(pending.json, { state: 'pending' });
  const noId = await hit(admin, 'GET', '/api/lan-peers/dispatch/approval?peer=' + PEER.peerId);
  assert.equal(noId.res.status, 400);
  const noPeer = await hit(admin, 'GET', '/api/lan-peers/dispatch/approval?id=ap-1');
  assert.equal(noPeer.res.status, 400);
  const unknown = await hit(admin, 'GET', '/api/lan-peers/dispatch/approval?id=ap-1&peer=peer-nope');
  assert.equal(unknown.res.status, 404);
});

test('dm/send 透传 workspaceId/permission；超默认档回 202 + approvalId', async () => {
  const dm = makeDmFacade({
    send: (input) => (input.permission === 'danger-full-access'
      ? { ok: true, pendingApproval: true, approvalId: 'ap-7', expiresAt: 1_760_000_600_000 }
      : { ok: true, id: 'm-2', sessionId: 's-1', reply: 'read-only done', elapsedMs: 9, reused: true,
        workspace: { id: 'main', name: '主工作区' }, permission: input.permission }),
  });
  const { admin, lines } = stubAdmin({ dm });

  const ok = await hit(admin, 'POST', '/api/lan-peers/dm/send', {
    peerId: PEER.peerId, text: '看看这个目录', workspaceId: 'main', permission: 'read-only',
  });
  assert.equal(ok.res.status, 200);
  assert.equal(ok.json.permission, 'read-only');
  assert.deepEqual(ok.json.workspace, { id: 'main', name: '主工作区' });
  assert.deepEqual(dm.calls[0], { peerId: PEER.peerId, text: '看看这个目录', workspaceId: 'main', permission: 'read-only' });

  const pending = await hit(admin, 'POST', '/api/lan-peers/dm/send', {
    peerId: PEER.peerId, text: '完全权限跑一下', workspaceId: 'main', permission: 'danger-full-access',
  });
  assert.equal(pending.res.status, 202);
  assert.deepEqual(pending.json, {
    ok: true, pendingApproval: true, approvalId: 'ap-7', expiresAt: 1_760_000_600_000,
  });

  // 都不传 → 请求体与以前一模一样（老对端不受影响）。
  await hit(admin, 'POST', '/api/lan-peers/dm/send', { peerId: PEER.peerId, text: '默认档' });
  assert.deepEqual(dm.calls[2], { peerId: PEER.peerId, text: '默认档' });

  const log = lines.join('\n');
  assert.equal(log.includes('完全权限跑一下'), false, '正文不进日志');
  assert.match(log, /state=pending-approval/);
  assert.match(log, /perm=danger-full-access/);
  assert.match(log, /ws=main/);
});

test('门禁与缺席：无 token 401；门面未接线 501 dispatch-unsupported（四条路由一致）', async () => {
  const { admin } = stubAdmin({ dispatch: makeDispatchFacade() });
  const noToken = await hit(admin, 'GET', '/api/lan-peers/dispatch/settings', undefined, { token: '' });
  assert.equal(noToken.res.status, 401);
  assert.equal(noToken.json.error, 'token-required');

  const { admin: bare } = stubAdmin({});
  for (const [method, path, body] of [
    ['GET', '/api/lan-peers/dispatch/settings', undefined],
    ['POST', '/api/lan-peers/dispatch/settings', { maxPermission: 'read-only' }],
    ['GET', '/api/lan-peers/dispatch/options', undefined],
    ['GET', '/api/lan-peers/dispatch/pending', undefined],
    ['POST', '/api/lan-peers/dispatch/approve', { id: 'ap-1' }],
    ['POST', '/api/lan-peers/dispatch/reject', { id: 'ap-1' }],
  ]) {
    const out = await hit(bare, method, path, body);
    assert.equal(out.res.status, 501, path + ' 未接线时回 501');
    assert.equal(out.json.error, 'dispatch-unsupported');
  }
});
