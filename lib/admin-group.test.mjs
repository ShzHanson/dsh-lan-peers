// dsh-lan-peers · v0.5.0 群聊管理接口（GET/POST /api/lan-peers/group*）。
//
// 契约 §5：浏览器永不直连对端。hub 侧读本地 group.json，成员侧由插件进程用
// hub peer 的 secret 走 /v1/group/*；两种形态都在这里跑真行为（真实 host 服务
// 或注入的群后端桩），并钉住「日志与响应里绝不出现群密钥/正文」。
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createAdmin } from './admin.mjs';
import { makeTempStateDir, seedPeers, startServer } from '../host/test/helpers.mjs';

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

// S3：管理接口已有两道门 —— 回环 Host 头 + 进程会话 token。测试桩按真实面板的形状
// 补齐这两个头（token 取同进程 admin 实例的那一份），业务断言全部保持原样。
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
  { peerId: 'peer-hub', name: 'hub-box', online: true, lastSeen: 1_700_000_000_000, joinedAt: 1 },
  { peerId: 'peer-nas', name: 'nas-box', online: false, lastSeen: 1_700_000_500_000, joinedAt: 2 },
];

const MESSAGES = [
  { seq: 7, ts: 1_700_000_600_000, from: { peerId: 'peer-nas', name: 'nas-box' }, kind: 'chat', text: 'hello' },
  { seq: 8, ts: 1_700_000_700_000, from: { peerId: 'peer-hub', name: 'hub-box' }, kind: 'progress', text: '', meta: { phase: 'start', status: 'running', peer: 'nas-box' } },
];

/** 记录所有后端调用的桩（route 层用；真实 hub/成员链路见下方两组）。 */
function makeApi({ failOn = null } = {}) {
  const calls = [];
  const guard = (name) => {
    if (failOn === name) {
      const error = new Error('hub unreachable');
      error.status = 502;
      throw error;
    }
  };
  return {
    calls,
    enabled: true,
    isHub: true,
    state({ sinceSeq = 0 } = {}) {
      calls.push({ method: 'state', sinceSeq });
      guard('state');
      return { groupId: 'g-1', name: 'default', members: MEMBERS, messages: MESSAGES, lastSeq: 8 };
    },
    post(args) {
      calls.push({ method: 'post', ...args });
      guard('post');
      return { seq: 9, ts: 1_700_000_800_000 };
    },
    member(args) {
      calls.push({ method: 'member', args });
      guard('member');
      return { members: MEMBERS };
    },
    setName(args) {
      calls.push({ method: 'setName', args });
      guard('setName');
      return { name: args.name };
    },
    join() {
      calls.push({ method: 'join' });
      guard('join');
      return { groupId: 'g-1', epoch: 3 };
    },
    // v0.7.0 S3：手动接管入口
    claim(args) {
      calls.push({ method: 'claim', args });
      guard('claim');
      return { ok: true, role: 'leader', epoch: 5 };
    },
  };
}

function stubAdmin({
  peers = [], group = null, api = undefined,
  // v0.6.0：地址探测与成员副本读取的接线（默认 0 端口 / 临时目录都取不到 → 'none'/null）
  listenPort = 0, stateDir = '', facade = null,
} = {}) {
  const lines = [];
  // 未启用时不给后端桩：走真实判定（group.enabled=false → disabled），否则桩会盖掉配置。
  const enabled = group !== null && group.enabled === true;
  const groupApi = api !== undefined ? api : (enabled ? { ...makeApi(), isHub: group.hub === '' } : null);
  const store = {
    instanceId: 'inst-self',
    stateDir,
    listPeers: () => peers,
    getPeer: (id) => peers.find((p) => p.peerId === id) || null,
  };
  const admin = createAdmin({
    server: { config: { logger: (line) => lines.push(line), listenPort }, store, group: facade },
    nameOf: () => 'self',
    rename: (n) => n,
    feed: null,
    pairing: { mode: 'auto' },
    group,
    groupApi,
  });
  return { admin, lines, api: groupApi };
}

// ---------------------------------------------------------------------------
// 路由层（注入群后端桩）
// ---------------------------------------------------------------------------

test('group.enabled=false → 返回 enabled:false 的空形状，且完全不打后端', async () => {
  const { admin, lines, api } = stubAdmin({ group: { enabled: false } });
  const out = await hit(admin, 'GET', '/api/lan-peers/group');
  assert.equal(out.res.status, 200);
  assert.deepEqual(out.json, { enabled: false, isHub: false, group: null, messages: [], lastSeq: 0 });
  assert.deepEqual(
    Object.keys(out.json).sort(),
    ['enabled', 'group', 'isHub', 'lastSeq', 'messages'],
    '未启用时形状与 v0.5.0 完全一致（v0.6.0 的新字段一个都不加）',
  );
  assert.equal(api, null, '未启用时后端桩根本不会被注入/调用');
  assert.ok(lines.some((l) => l.includes('[admin] group state')), '未启用也留一条日志');
});

test('hub 侧 GET：透传 group/members/messages/lastSeq，sinceSeq 原样交给后端', async () => {
  const { admin, lines, api } = stubAdmin({ group: { enabled: true, hub: '' } });
  const out = await hit(admin, 'GET', '/api/lan-peers/group?sinceSeq=6');
  assert.equal(out.res.status, 200);
  assert.equal(out.json.enabled, true);
  assert.equal(out.json.isHub, true);
  // v0.6.0 追加 baseUrl/lastSeq/lag（缺省 ''/null），旧五字段原样；
  // v0.8.2-α 追加 acceptDispatch（契约 §4：缺字段 = 接单中，绝不显示成已关闭）
  assert.deepEqual(out.json.group, {
    groupId: 'g-1',
    name: 'default',
    members: MEMBERS.map((member) => ({
      ...member, baseUrl: '', lastSeq: null, lag: null, acceptDispatch: true,
    })),
  });
  assert.deepEqual(out.json.messages, MESSAGES);
  assert.equal(out.json.lastSeq, 8);
  assert.equal(out.json.error, undefined, '成功路径不带 error 字段');
  assert.deepEqual(api.calls[0], { method: 'state', sinceSeq: 6 });
  const line = lines.find((l) => l.includes('[admin] group state'));
  assert.match(line, /isHub=true/);
  assert.match(line, /sinceSeq=6/);
  assert.match(line, /new=2/);
});

test('成员侧 GET：isHub=false，增量游标透传，非法 sinceSeq 归零', async () => {
  const { admin, api } = stubAdmin({ group: { enabled: true, hub: 'nas' } });
  const out = await hit(admin, 'GET', '/api/lan-peers/group?sinceSeq=0');
  assert.equal(out.json.isHub, false);
  assert.equal(out.json.messages.length, 2);
  await hit(admin, 'GET', '/api/lan-peers/group?sinceSeq=abc');
  await hit(admin, 'GET', '/api/lan-peers/group?sinceSeq=-5');
  await hit(admin, 'GET', '/api/lan-peers/group?sinceSeq=12');
  assert.deepEqual(api.calls.map((c) => c.sinceSeq), [0, 0, 0, 12]);
});

test('后端不可用（hub 不可达）→ 200 带 error 字段，不把异常抛给浏览器', async () => {
  const { admin, lines } = stubAdmin({ group: { enabled: true, hub: 'nas' }, api: makeApi({ failOn: 'state' }) });
  const out = await hit(admin, 'GET', '/api/lan-peers/group?sinceSeq=4');
  assert.equal(out.res.status, 200);
  assert.equal(out.json.enabled, true);
  assert.equal(out.json.group, null);
  assert.deepEqual(out.json.messages, []);
  assert.equal(out.json.lastSeq, 4);
  assert.match(out.json.error, /hub unreachable/);
  assert.ok(lines.some((l) => l.includes('[admin] group state failed')), '失败必须留痕');
});

test('post：kind 白名单与 text 长度校验（400 / 413），正文绝不进日志', async () => {
  const { admin, lines, api } = stubAdmin({ group: { enabled: true, hub: '' } });
  const badKind = await hit(admin, 'POST', '/api/lan-peers/group/post', { kind: 'evil', text: 'x' });
  assert.equal(badKind.res.status, 400);
  assert.deepEqual(badKind.json, { error: 'bad-kind' });

  const tooLong = await hit(admin, 'POST', '/api/lan-peers/group/post', { kind: 'chat', text: 'x'.repeat(4001) });
  assert.equal(tooLong.res.status, 413);
  assert.deepEqual(tooLong.json, { error: 'payload-too-large' });
  assert.equal(api.calls.length, 0, '校验失败不得下发到后端');

  const ok = await hit(admin, 'POST', '/api/lan-peers/group/post', { kind: 'chat', text: 'SSS-SECRET-TEXT' });
  assert.equal(ok.res.status, 200);
  assert.deepEqual(ok.json, { ok: true, seq: 9, ts: 1_700_000_800_000 });
  assert.deepEqual(api.calls[0], { method: 'post', kind: 'chat', text: 'SSS-SECRET-TEXT', meta: {} });

  const log = lines.filter((l) => l.includes('[admin] group post')).join('\n');
  assert.match(log, /textLen=15/);
  assert.doesNotMatch(log, /SSS-SECRET-TEXT/, '群消息正文不进日志');
});

test('post：meta 只保留白名单字段（DESIGN §3）', async () => {
  const { admin, api } = stubAdmin({ group: { enabled: true, hub: '' } });
  await hit(admin, 'POST', '/api/lan-peers/group/post', {
    kind: 'chat',
    text: 'done/1227ms/142字',
    meta: { peer: 'nas-box', sessionId: 's-1', phase: 'end', status: 'done', transport: 'sse', elapsedMs: 1227, replyChars: 142, prompt: 'DROP ME', reply: 'DROP ME TOO' },
  });
  const post = api.calls.find((c) => c.method === 'post');
  assert.deepEqual(Object.keys(post.meta).sort(), ['elapsedMs', 'peer', 'phase', 'replyChars', 'sessionId', 'status', 'transport']);
  assert.equal(post.meta.prompt, undefined);
  assert.equal(post.meta.reply, undefined);
});

test('post：群未启用 → 409 group-disabled；后端出错 → 透传状态码', async () => {
  const disabled = await hit(stubAdmin({ group: { enabled: false } }).admin, 'POST', '/api/lan-peers/group/post', { kind: 'chat', text: 'hi' });
  assert.equal(disabled.res.status, 409);
  assert.deepEqual(disabled.json, { error: 'group-disabled' });

  const failing = stubAdmin({ group: { enabled: true, hub: '' }, api: makeApi({ failOn: 'post' }) });
  const out = await hit(failing.admin, 'POST', '/api/lan-peers/group/post', { kind: 'chat', text: 'hi' });
  assert.equal(out.res.status, 502);
  assert.match(out.json.error, /hub unreachable/);
});

test('member：仅 hub 可用；未知 peer 不能加；action/peerId 校验', async () => {
  const memberSide = stubAdmin({ group: { enabled: true, hub: 'nas' }, api: { ...makeApi(), isHub: false } });
  const forbidden = await hit(memberSide.admin, 'POST', '/api/lan-peers/group/member', { peerId: 'peer-x', action: 'add' });
  assert.equal(forbidden.res.status, 403);
  assert.deepEqual(forbidden.json, { error: 'hub-only' });

  const hub = stubAdmin({ group: { enabled: true, hub: '' }, peers: [{ peerId: 'peer-nas', name: 'nas-box' }] });
  const ghost = await hit(hub.admin, 'POST', '/api/lan-peers/group/member', { peerId: 'nobody', action: 'add' });
  assert.equal(ghost.res.status, 404);
  assert.deepEqual(ghost.json, { error: 'unknown-peer' });

  const badAction = await hit(hub.admin, 'POST', '/api/lan-peers/group/member', { peerId: 'peer-nas', action: 'nuke' });
  assert.equal(badAction.res.status, 400);
  assert.deepEqual(badAction.json, { error: 'bad-action' });

  const empty = await hit(hub.admin, 'POST', '/api/lan-peers/group/member', { peerId: '  ', action: 'add' });
  assert.equal(empty.res.status, 400);
  assert.deepEqual(empty.json, { error: 'peerId-required' });
  assert.equal(hub.api.calls.length, 0, '校验失败不得下发');
});

test('member：hub 添加/移除成员都下发后端并留痕（不含 secret）', async () => {
  const { admin, lines, api } = stubAdmin({ group: { enabled: true, hub: '' }, peers: [{ peerId: 'peer-nas', name: 'nas-box' }] });
  const added = await hit(admin, 'POST', '/api/lan-peers/group/member', { peerId: 'peer-nas', action: 'add' });
  assert.equal(added.res.status, 200);
  assert.equal(added.json.ok, true);
  assert.equal(added.json.action, 'add');
  const removed = await hit(admin, 'POST', '/api/lan-peers/group/member', { peerId: 'peer-nas', action: 'remove' });
  assert.equal(removed.res.status, 200);
  assert.deepEqual(api.calls.filter((c) => c.method === 'member').map((c) => c.args.action), ['add', 'remove']);
  const log = lines.filter((l) => l.includes('[admin] group member')).join('\n');
  assert.match(log, /action=add/);
  assert.match(log, /action=remove/);
  assert.doesNotMatch(log, /secret/i, '日志里不得出现密钥');
});

test('config：仅 hub 改群名，空名/超长被拒', async () => {
  const memberSide = stubAdmin({ group: { enabled: true, hub: 'nas' }, api: { ...makeApi(), isHub: false } });
  const forbidden = await hit(memberSide.admin, 'POST', '/api/lan-peers/group/config', { name: '新群名' });
  assert.equal(forbidden.res.status, 403);
  assert.deepEqual(forbidden.json, { error: 'hub-only' });

  const hub = stubAdmin({ group: { enabled: true, hub: '' } });
  const empty = await hit(hub.admin, 'POST', '/api/lan-peers/group/config', { name: '   ' });
  assert.equal(empty.res.status, 400);
  assert.deepEqual(empty.json, { error: 'bad-name' });
  const tooLong = await hit(hub.admin, 'POST', '/api/lan-peers/group/config', { name: 'n'.repeat(65) });
  assert.equal(tooLong.res.status, 400);

  const ok = await hit(hub.admin, 'POST', '/api/lan-peers/group/config', { name: '  家里  ' });
  assert.equal(ok.res.status, 200);
  assert.deepEqual(ok.json, { ok: true, name: '家里' });
  assert.deepEqual(hub.api.calls.find((c) => c.method === 'setName').args, { name: '家里' });
  assert.ok(hub.lines.some((l) => l.includes('[admin] group name -> 家里')));
});

test('join：成员侧可用，hub 侧 409，未启用 409', async () => {
  const memberSide = stubAdmin({ group: { enabled: true, hub: 'nas' }, api: { ...makeApi(), isHub: false } });
  const ok = await hit(memberSide.admin, 'POST', '/api/lan-peers/group/join');
  assert.equal(ok.res.status, 200);
  assert.deepEqual(ok.json, { ok: true, groupId: 'g-1', epoch: 3 });
  assert.ok(memberSide.lines.some((l) => l.includes('[admin] group join ok')), '加入动作要留痕');
  assert.doesNotMatch(memberSide.lines.join('\n'), /groupKey/, '群密钥绝不进日志');

  const hubSide = stubAdmin({ group: { enabled: true, hub: '' } });
  const nope = await hit(hubSide.admin, 'POST', '/api/lan-peers/group/join');
  assert.equal(nope.res.status, 409);
  assert.deepEqual(nope.json, { error: 'hub-cannot-join' });

  const off = await hit(stubAdmin({ group: { enabled: false } }).admin, 'POST', '/api/lan-peers/group/join');
  assert.equal(off.res.status, 409);
  assert.deepEqual(off.json, { error: 'group-disabled' });
});

test('join：后端抛 403 not-a-member 时状态码透传（成员未加入群）', async () => {
  const api = makeApi();
  api.isHub = false;
  api.join = () => {
    const error = new Error('not-a-member');
    error.status = 403;
    throw error;
  };
  const out = await hit(stubAdmin({ group: { enabled: true, hub: 'nas' }, api }).admin, 'POST', '/api/lan-peers/group/join');
  assert.equal(out.res.status, 403);
  assert.deepEqual(out.json, { error: 'not-a-member' });
});

test('未知群路由仍是 404（不吞掉其它路径）', async () => {
  const out = await hit(stubAdmin({ group: { enabled: true, hub: '' } }).admin, 'GET', '/api/lan-peers/group/nope');
  assert.equal(out.res.status, 404);
  assert.deepEqual(out.json, { error: 'not-found' });
});

// ---------------------------------------------------------------------------
// hub 侧：真 host 服务 + 本地 group.json
// ---------------------------------------------------------------------------

test('hub 侧：GET 读本地群状态，post 落盘并返回 seq，成员可增删、群名可改', async (t) => {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [{ peerId: 'peer-nas', name: 'nas-box', secret: 'S-a', inboundSecret: 'T-a', baseUrl: 'http://127.0.0.1:1' }]);
  const lines = [];
  const hub = await startServer(t, {
    stateDir,
    name: 'hub-box',
    logger: (line) => lines.push(line),
    group: { enabled: true, hub: '', name: '家里', retentionDays: 7 },
  });
  const admin = createAdmin({ server: hub.server, nameOf: () => hub.server.config.name, rename: (n) => n });

  const empty = await hit(admin, 'GET', '/api/lan-peers/group?sinceSeq=0');
  assert.equal(empty.res.status, 200);
  assert.equal(empty.json.enabled, true);
  assert.equal(empty.json.isHub, true);
  assert.equal(empty.json.group.name, '家里');
  assert.equal(empty.json.group.members.length, 1, 'hub 自己首次初始化即入表');
  assert.deepEqual(empty.json.messages, []);
  assert.equal(JSON.stringify(empty.json).includes('groupKey'), false, '管理接口不下发群密钥');

  // v0.6.0 S1/S2：真 host 外壳给出的 leader/地址/副本字段
  assert.equal(empty.json.selfRole, 'hub');
  assert.equal(empty.json.leader.peerId, hub.server.store.instanceId);
  assert.equal(empty.json.leader.name, 'hub-box');
  assert.equal(typeof empty.json.leader.epoch, 'number');
  assert.deepEqual(
    { lastSeq: empty.json.replica.lastSeq, lag: empty.json.replica.lag },
    { lastSeq: empty.json.lastSeq, lag: 0 },
    'hub 就是 leader：副本永远与 leader 同进度',
  );
  const selfMember = empty.json.group.members.find((member) => member.peerId === hub.server.store.instanceId);
  assert.equal(typeof selfMember.baseUrl, 'string', '真 host 会给成员表带上「我看到的地址」');
  if (empty.json.advertiseBaseUrl !== '') {
    assert.match(empty.json.advertiseBaseUrl, /^http:\/\/\d+\.\d+\.\d+\.\d+:\d+$/, '私有 IPv4 + 真实端口');
    assert.equal(empty.json.selfBaseUrl, empty.json.advertiseBaseUrl, '别人看到的我的地址 = 我自报的地址');
    assert.equal(empty.json.advertiseSource, 'auto');
  }

  const posted = await hit(admin, 'POST', '/api/lan-peers/group/post', { kind: 'chat', text: 'hi there' });
  assert.equal(posted.res.status, 200);
  assert.equal(posted.json.seq, 1);
  assert.equal(typeof posted.json.ts, 'number');

  const after = await hit(admin, 'GET', '/api/lan-peers/group?sinceSeq=0');
  assert.equal(after.json.messages.length, 1);
  assert.equal(after.json.messages[0].text, 'hi there');
  assert.equal(after.json.messages[0].from.name, 'hub-box');
  assert.equal(after.json.lastSeq, 1);
  const incremental = await hit(admin, 'GET', '/api/lan-peers/group?sinceSeq=1');
  assert.deepEqual(incremental.json.messages, [], 'sinceSeq 之后没有新消息');

  const added = await hit(admin, 'POST', '/api/lan-peers/group/member', { peerId: 'peer-nas', action: 'add' });
  assert.equal(added.res.status, 200);
  assert.equal(added.json.members.length, 2);
  assert.ok(added.json.members.some((m) => m.peerId === 'peer-nas' && m.name === 'nas-box'));
  const removed = await hit(admin, 'POST', '/api/lan-peers/group/member', { peerId: 'peer-nas', action: 'remove' });
  assert.equal(removed.json.members.length, 1);

  const renamed = await hit(admin, 'POST', '/api/lan-peers/group/config', { name: '客厅' });
  assert.deepEqual(renamed.json, { ok: true, name: '客厅' });
  const named = await hit(admin, 'GET', '/api/lan-peers/group?sinceSeq=1');
  assert.equal(named.json.group.name, '客厅');

  const log = lines.filter((l) => l.includes('[admin] group')).join('\n');
  assert.match(log, /\[admin\] group post kind=chat textLen=8/);
  assert.doesNotMatch(log, /hi there/, '正文不进日志');
});

test('hub 侧：未启用群的 host 一律回 enabled:false（契约 §7.3）', async (t) => {
  const hub = await startServer(t, { name: 'plain', group: { enabled: false } });
  const admin = createAdmin({ server: hub.server, nameOf: () => hub.server.config.name, rename: (n) => n });
  const out = await hit(admin, 'GET', '/api/lan-peers/group');
  assert.equal(out.res.status, 200);
  assert.deepEqual(out.json, { enabled: false, isHub: false, group: null, messages: [], lastSeq: 0 });
  const post = await hit(admin, 'POST', '/api/lan-peers/group/post', { kind: 'chat', text: 'x' });
  assert.equal(post.res.status, 409);
});

// ---------------------------------------------------------------------------
// 成员侧：真 hub 服务 + group-client 的签名/加密往返
// ---------------------------------------------------------------------------

test('成员侧：GET/post 由插件进程代理到 hub（含 groupKey 剥离），浏览器不直连对端', async (t) => {
  const hubDir = makeTempStateDir();
  seedPeers(hubDir, [{ peerId: 'member-inst', name: 'me', secret: 'H2M', inboundSecret: 'M2H', baseUrl: 'http://127.0.0.1:1' }]);
  // S3 起 majority 两阶段提交生效：本夹具里成员没有起真实服务器（baseUrl 打不通），
  // 拿不到 ack → hub 按契约 §5/§9.3 回 503 是正确行为，而这条测试考的是「管理接口
  // 代理 + groupKey 剥离」，所以固定 quorum:none（可写优先）以隔离该路径。
  const hub = await startServer(t, {
    stateDir: hubDir,
    name: 'hub-box',
    group: { enabled: true, hub: '', name: '家里', autoJoin: true, quorum: 'none' },
  });
  hub.server.group.addMember('member-inst', 'me');

  const lines = [];
  const memberStore = {
    instanceId: 'member-inst',
    listPeers: () => [{ peerId: hub.server.store.instanceId, name: 'hub-box', baseUrl: hub.baseUrl, secret: 'M2H' }],
    getPeer: () => null,
  };
  const admin = createAdmin({
    server: {
      config: { group: { enabled: true, hub: 'hub-box' }, logger: (line) => lines.push(line) },
      store: memberStore,
    },
    nameOf: () => 'me',
    rename: (n) => n,
  });

  const state = await hit(admin, 'GET', '/api/lan-peers/group?sinceSeq=0');
  assert.equal(state.res.status, 200);
  assert.equal(state.json.isHub, false, '成员侧必须自报 isHub=false');
  assert.equal(state.json.group.name, '家里');
  assert.equal(state.json.group.members.length, 2, 'hub + 本成员');
  assert.equal(JSON.stringify(state.json).includes('groupKey'), false, 'groupKey 不得转给面板');
  assert.doesNotMatch(lines.join('\n'), /groupKey/, '日志也不得出现群密钥');

  const posted = await hit(admin, 'POST', '/api/lan-peers/group/post', {
    kind: 'chat',
    text: '代理到 hub 的一条',
    meta: { peer: 'nas-box', sessionId: 's-9', phase: 'start', status: 'running' },
  });
  assert.equal(posted.res.status, 200);
  assert.equal(posted.json.seq, 1);

  const seen = await hit(admin, 'GET', '/api/lan-peers/group?sinceSeq=0');
  assert.equal(seen.json.messages.length, 1);
  assert.equal(seen.json.messages[0].kind, 'chat');
  assert.equal(seen.json.messages[0].text, '代理到 hub 的一条');
  assert.equal(seen.json.messages[0].meta.phase, 'start');
  assert.equal(seen.json.lastSeq, 1);
});

test('成员侧：hub 未配对 → GET 报 error 而不是 500/异常', async () => {
  const lines = [];
  const admin = createAdmin({
    server: {
      config: { group: { enabled: true, hub: 'ghost-hub' }, logger: (line) => lines.push(line) },
      store: { instanceId: 'member-inst', listPeers: () => [], getPeer: () => null },
    },
    nameOf: () => 'me',
    rename: (n) => n,
  });
  const out = await hit(admin, 'GET', '/api/lan-peers/group');
  assert.equal(out.res.status, 200);
  assert.equal(out.json.enabled, true);
  assert.equal(out.json.isHub, false);
  assert.match(out.json.error, /hub peer not paired/);
});
// ---------------------------------------------------------------------------
// v0.6.0 S1/S2：leader / epoch / 落后条数 / 成员地址（只加字段，不改旧形状）
// ---------------------------------------------------------------------------

/** 后端桩：可控的成员表（带 baseUrl/lastSeq）、lastSeq 与 epoch。 */
function apiWith({ members = MEMBERS, lastSeq = 8, epoch = 4, isHub = true } = {}) {
  const api = makeApi();
  api.isHub = isHub;
  api.state = () => ({
    groupId: 'g-1', name: 'default', epoch, leaderPeerId: 'inst-self', members, messages: MESSAGES, lastSeq,
  });
  return api;
}

test('hub 侧：GET 追加 leader/selfRole/replica/members 地址与 lag，旧字段一个不动', async () => {
  const members = [
    { peerId: 'inst-self', name: 'self', online: true, lastSeen: null, joinedAt: 1, baseUrl: 'http://192.168.1.20:7788', lastSeq: 8 },
    { peerId: 'peer-nas', name: 'nas-box', online: false, lastSeen: null, joinedAt: 2, baseUrl: 'http://192.168.1.51:7788', lastSeq: 3 },
    { peerId: 'peer-quiet', name: 'quiet', online: false, lastSeen: null, joinedAt: 3 },
  ];
  const { admin } = stubAdmin({ group: { enabled: true, hub: '' }, api: apiWith({ members }) });
  const out = await hit(admin, 'GET', '/api/lan-peers/group?sinceSeq=0');
  assert.equal(out.res.status, 200);

  // 旧形状：一个字段都没改
  assert.equal(out.json.enabled, true);
  assert.equal(out.json.isHub, true);
  assert.equal(out.json.group.groupId, 'g-1');
  assert.equal(out.json.group.name, 'default');
  assert.deepEqual(out.json.messages, MESSAGES);
  assert.equal(out.json.lastSeq, 8);
  assert.equal(out.json.error, undefined);

  // 新字段
  assert.deepEqual(out.json.leader, { peerId: 'inst-self', name: 'self', epoch: 4 });
  assert.equal(out.json.selfRole, 'hub');
  assert.deepEqual(out.json.replica, { lastSeq: 8, leaderLastSeq: 8, lag: 0 });
  assert.equal(out.json.advertiseBaseUrl, '');
  assert.equal(out.json.advertiseSource, 'none');
  assert.equal(out.json.selfBaseUrl, 'http://192.168.1.20:7788', '别人看到的我的地址 = 群状态里自己那条');

  const [self, nas, quiet] = out.json.group.members;
  assert.deepEqual([self.lag, nas.lag, quiet.lag], [0, 5, null], 'lag = leader lastSeq - 成员 lastSeq；没上报就是 null');
  assert.equal(nas.baseUrl, 'http://192.168.1.51:7788');
  assert.equal(quiet.baseUrl, '', '后端没给地址就是空串（面板显示 —）');
  assert.equal(quiet.lastSeq, null);
});

test('advertiseBaseUrl：config 优先；未配置时用 host 的探测结果；都没有就是空串', async () => {
  const configured = await hit(
    stubAdmin({ group: { enabled: true, hub: '', advertiseBaseUrl: 'http://192.168.1.20:7788/' } }).admin,
    'GET', '/api/lan-peers/group',
  );
  assert.equal(configured.json.advertiseBaseUrl, 'http://192.168.1.20:7788', '去尾部斜杠');
  assert.equal(configured.json.advertiseSource, 'config');

  const wrapper = (advertise) => ({
    enabled: false, isHub: false, advertiseBaseUrl: () => advertise, replica: null,
  });
  const detected = await hit(stubAdmin({
    group: { enabled: true, hub: '' }, facade: wrapper('http://192.168.1.211:3180'),
  }).admin, 'GET', '/api/lan-peers/group');
  assert.equal(detected.json.advertiseBaseUrl, 'http://192.168.1.211:3180');
  assert.equal(detected.json.advertiseSource, 'auto');

  // host 也探测不到（没网卡/端口未知）→ 不编一个 URL 出来
  const none = await hit(stubAdmin({ group: { enabled: true, hub: '' }, facade: wrapper('') }).admin, 'GET', '/api/lan-peers/group');
  assert.equal(none.json.advertiseBaseUrl, '');
  assert.equal(none.json.advertiseSource, 'none');

  // 没有 host 外壳（极简接线）时同样降级，不抛错
  const bare = await hit(stubAdmin({ group: { enabled: true, hub: '' } }).admin, 'GET', '/api/lan-peers/group');
  assert.equal(bare.json.advertiseBaseUrl, '');
  assert.equal(bare.json.advertiseSource, 'none');
});

test('成员侧：leader 是 group.hub peer，replica 读本地 group-replica.json 并算出 lag', async () => {
  const stateDir = makeTempStateDir();
  fs.writeFileSync(path.join(stateDir, 'group-replica.json'), JSON.stringify({
    groupId: 'g-1', epoch: 4, leaderPeerId: 'peer-hub', lastSeq: 5, messages: [],
  }));
  const peers = [{ peerId: 'peer-hub', name: 'hub-box', baseUrl: 'http://127.0.0.1:1', secret: 's' }];
  const out = await hit(stubAdmin({
    group: { enabled: true, hub: 'hub-box' },
    api: apiWith({ isHub: false, lastSeq: 8 }),
    peers, stateDir,
  }).admin, 'GET', '/api/lan-peers/group?sinceSeq=0');

  assert.equal(out.json.selfRole, 'member');
  assert.deepEqual(out.json.leader, { peerId: 'peer-hub', name: 'hub-box', epoch: 4 });
  assert.deepEqual(out.json.replica, { lastSeq: 5, leaderLastSeq: 8, lag: 3 });

  // 没有副本文件：不假装同步（lastSeq/lag 都是 null）
  const missing = await hit(stubAdmin({
    group: { enabled: true, hub: 'hub-box' },
    api: apiWith({ isHub: false, lastSeq: 8 }),
    peers, stateDir: makeTempStateDir(),
  }).admin, 'GET', '/api/lan-peers/group');
  assert.deepEqual(missing.json.replica, { lastSeq: null, leaderLastSeq: 8, lag: null });

  // 坏 JSON 同样降级成「没有副本」，不抛错
  const brokenDir = makeTempStateDir();
  fs.writeFileSync(path.join(brokenDir, 'group-replica.json'), '{ not json');
  const broken = await hit(stubAdmin({
    group: { enabled: true, hub: 'hub-box' },
    api: apiWith({ isHub: false, lastSeq: 8 }),
    peers, stateDir: brokenDir,
  }).admin, 'GET', '/api/lan-peers/group');
  assert.equal(broken.res.status, 200);
  assert.deepEqual(broken.json.replica, { lastSeq: null, leaderLastSeq: 8, lag: null });
});

test('后端不可用：新字段降级成 null/空串，旧 error 形状不变', async () => {
  const api = { ...makeApi({ failOn: 'state' }), isHub: false };
  const { admin, lines } = stubAdmin({ group: { enabled: true, hub: 'nas' }, api });
  const out = await hit(admin, 'GET', '/api/lan-peers/group?sinceSeq=4');
  assert.equal(out.res.status, 200);
  assert.equal(out.json.enabled, true);
  assert.equal(out.json.isHub, false);
  assert.equal(out.json.group, null);
  assert.deepEqual(out.json.messages, []);
  assert.equal(out.json.lastSeq, 4);
  assert.match(out.json.error, /hub unreachable/);
  assert.equal(out.json.leader, null);
  assert.equal(out.json.selfRole, 'member');
  assert.equal(out.json.replica, null);
  assert.equal(out.json.selfBaseUrl, '');
  assert.ok(lines.some((line) => line.includes('[admin] group state failed')));
});
test('优先采用 host 外壳的探测地址与成员副本（本文件的口径只是兜底）', async () => {
  const facade = {
    enabled: false,
    isHub: false,
    advertiseBaseUrl: () => 'http://10.0.0.5:7788',
    replica: { state: () => ({ groupId: 'g-1', epoch: 4, leaderPeerId: 'peer-hub', lastSeq: 7 }) },
  };
  const peers = [{ peerId: 'peer-hub', name: 'hub-box', baseUrl: 'http://127.0.0.1:1', secret: 's' }];
  const out = await hit(stubAdmin({
    group: { enabled: true, hub: 'hub-box' },
    api: apiWith({ isHub: false, lastSeq: 8 }),
    peers, facade,
  }).admin, 'GET', '/api/lan-peers/group');

  assert.equal(out.json.advertiseBaseUrl, 'http://10.0.0.5:7788', 'host 知道真实监听端口，优先用它');
  assert.equal(out.json.advertiseSource, 'auto');
  assert.deepEqual(out.json.replica, { lastSeq: 7, leaderLastSeq: 8, lag: 1 });

  // config 仍然压过 host 的探测值
  const configured = await hit(stubAdmin({
    group: { enabled: true, hub: 'hub-box', advertiseBaseUrl: 'http://192.168.1.20:7788' },
    api: apiWith({ isHub: false, lastSeq: 8 }),
    peers, facade,
  }).admin, 'GET', '/api/lan-peers/group');
  assert.equal(configured.json.advertiseBaseUrl, 'http://192.168.1.20:7788');
  assert.equal(configured.json.advertiseSource, 'config');
});
// ---------------------------------------------------------------------------
// 真机回归：store.listPeers() 是脱敏视图（没有 secret），解析 hub 必须用 getPeer
// ---------------------------------------------------------------------------

test('成员侧：listPeers 脱敏也要能出 leader，secret 必须从 getPeer 取（真机回归）', async (t) => {
  const hubDir = makeTempStateDir();
  seedPeers(hubDir, [{ peerId: 'member-inst', name: 'me', secret: 'H2M', inboundSecret: 'M2H', baseUrl: 'http://127.0.0.1:1' }]);
  const hub = await startServer(t, {
    stateDir: hubDir,
    name: 'nas-box',
    group: { enabled: true, hub: '', name: '家里', autoJoin: true },
  });
  hub.server.group.addMember('member-inst', 'me');
  const hubPeerId = hub.server.store.instanceId;

  const lines = [];
  const memberStore = {
    instanceId: 'member-inst',
    // 与真 StateStore 一致：listPeers() 只有 peerId/name/baseUrl，**没有 secret**
    listPeers: () => [{ peerId: hubPeerId, name: 'nas-box', baseUrl: hub.baseUrl, lastSeen: new Date().toISOString() }],
    getPeer: (id) => (id === hubPeerId
      ? { peerId: hubPeerId, name: 'nas-box', baseUrl: hub.baseUrl, secret: 'M2H' }
      : null),
  };
  const admin = createAdmin({
    server: { config: { group: { enabled: true, hub: 'nas-box' }, logger: (line) => lines.push(line) }, store: memberStore },
    nameOf: () => 'me',
    rename: (n) => n,
  });

  const out = await hit(admin, 'GET', '/api/lan-peers/group?sinceSeq=0');
  assert.equal(out.res.status, 200);
  assert.equal(out.json.error, undefined, '脱敏视图不该让成员侧报 no address/secret');
  assert.equal(out.json.isHub, false);
  assert.equal(out.json.selfRole, 'member');
  assert.equal(out.json.leader.peerId, hubPeerId);
  assert.equal(out.json.leader.name, 'nas-box', 'leader 名字来自 getPeer 的完整记录');
  assert.equal(typeof out.json.leader.epoch, 'number');
  assert.equal(out.json.group.name, '家里');
  assert.equal(out.json.group.members.length, 2, 'hub + 本成员');
  assert.equal(out.json.replica.lastSeq, null, '没有副本入口时如实报 null');
  assert.doesNotMatch(lines.join('\n'), /M2H/, 'secret 绝不进日志');
});

test('成员侧：只有脱敏记录且 getPeer 取不到时，才报 no address/secret', async () => {
  const lines = [];
  const admin = createAdmin({
    server: {
      config: { group: { enabled: true, hub: 'nas-box' }, logger: (line) => lines.push(line) },
      store: {
        instanceId: 'member-inst',
        listPeers: () => [{ peerId: 'peer-hub-id', name: 'nas-box', baseUrl: 'http://10.0.0.9:7788' }],
        getPeer: () => null,
      },
    },
    nameOf: () => 'me',
    rename: (n) => n,
  });
  const out = await hit(admin, 'GET', '/api/lan-peers/group');
  assert.equal(out.res.status, 200);
  assert.match(out.json.error, /hub peer has no address\/secret: nas-box/, '错误文案保留');
  assert.equal(out.json.leader, null);
  assert.equal(out.json.selfRole, 'member');
  assert.equal(out.json.group, null);
  assert.ok(lines.some((line) => line.includes('[admin] group state failed')));
});

test('成员侧：group.hub 直接写 peerId 时同样走 getPeer（脱敏视图为空也能解析）', async () => {
  const admin = createAdmin({
    server: {
      config: { group: { enabled: true, hub: 'peer-hub-id' }, logger: () => {} },
      store: {
        instanceId: 'member-inst',
        listPeers: () => [],
        getPeer: (id) => (id === 'peer-hub-id'
          ? { peerId: 'peer-hub-id', name: 'nas-box', baseUrl: 'http://10.0.0.9:7788', secret: 'M2H' }
          : null),
      },
    },
    nameOf: () => 'me',
    rename: (n) => n,
  });
  const out = await hit(admin, 'GET', '/api/lan-peers/group');
  // 解析成功 → 不再是 no address/secret（这里 hub 不可达，因此是网络错误）
  assert.doesNotMatch(String(out.json.error), /no address\/secret/);
  assert.equal(out.json.isHub, false);
});

// ---------------------------------------------------------------------------
// v0.7.0 S3（契约 §7）：角色 / 租约 / quorum / 提交进度 / 手动接管
// ---------------------------------------------------------------------------

const HUB_PEERS = [{ peerId: 'peer-hub', name: 'hub-box', baseUrl: 'http://127.0.0.1:1', secret: 's' }];

/** host 门面桩（server.group）：S3 认 role()、role.state() 与 claim()。 */
const roleFacade = (state) => ({ enabled: false, isHub: false, role: () => state });

test('S3 · GET 追加 role/leaseUntil/quorum/commitSeq/pendingCount/degraded：host 门面优先', async () => {
  const leaseUntil = Date.now() + 9000;
  const out = await hit(stubAdmin({
    group: { enabled: true, hub: 'hub-box' },
    api: apiWith({ isHub: false, lastSeq: 8 }),
    peers: HUB_PEERS,
    facade: roleFacade({
      role: 'follower', epoch: 9, leaderPeerId: 'peer-hub', leaseUntil, commitSeq: 12, pendingCount: 2,
    }),
  }).admin, 'GET', '/api/lan-peers/group?sinceSeq=0');

  assert.equal(out.res.status, 200);
  assert.equal(out.json.role, 'follower', '选举角色来自门面，不是 selfRole');
  assert.equal(out.json.leaseUntil, leaseUntil);
  assert.equal(out.json.quorum, 'majority');
  assert.equal(out.json.commitSeq, 12, '已提交序号来自门面');
  assert.equal(out.json.pendingCount, 2, '未提交条数来自门面');
  assert.equal(out.json.degraded, false, '有 leader 且租约未过期');

  // 旧字段的取法不变，但 epoch 改为以角色门面为准（这里是 9，群元数据是 4）
  assert.deepEqual(out.json.leader, { peerId: 'peer-hub', name: 'hub-box', epoch: 9 });
  assert.equal(out.json.selfRole, 'member');
  assert.equal(out.json.lastSeq, 8);
  assert.deepEqual(out.json.messages, MESSAGES);
  assert.equal(out.json.group.groupId, 'g-1');
  assert.equal(out.json.error, undefined);

  // 门面若是「对象 + state()」形态同样认
  const objectShape = await hit(stubAdmin({
    group: { enabled: true, hub: '' },
    facade: {
      enabled: true, isHub: true,
      role: { state: () => ({ role: 'candidate', leaseUntil, commitSeq: 3, pendingCount: 1 }) },
    },
  }).admin, 'GET', '/api/lan-peers/group');
  assert.equal(objectShape.json.role, 'candidate');
  assert.equal(objectShape.json.commitSeq, 3);
  assert.equal(objectShape.json.pendingCount, 1);

  // 门的 role() 抛错就当没接线（面板降级，不 500）
  const throwing = await hit(stubAdmin({
    group: { enabled: true, hub: '' },
    facade: { enabled: true, isHub: true, role: () => { throw new Error('boom'); } },
  }).admin, 'GET', '/api/lan-peers/group');
  assert.equal(throwing.res.status, 200);
  assert.equal(throwing.json.role, 'leader');
});

test('S3 · degraded：租约过期 / 门面明确没有 leader 才报警，缺字段不报', async () => {
  const expired = await hit(stubAdmin({
    group: { enabled: true, hub: 'hub-box' },
    api: apiWith({ isHub: false, lastSeq: 8 }),
    peers: HUB_PEERS,
    facade: roleFacade({ role: 'follower', leaderPeerId: 'peer-hub', leaseUntil: Date.now() - 1 }),
  }).admin, 'GET', '/api/lan-peers/group');
  assert.equal(expired.json.degraded, true, '租约过期 = degraded');

  const leaderless = await hit(stubAdmin({
    group: { enabled: true, hub: 'hub-box' },
    api: apiWith({ isHub: false, lastSeq: 8 }),
    peers: HUB_PEERS,
    facade: roleFacade({ role: 'candidate', leaderPeerId: null, leaseUntil: Date.now() + 9000 }),
  }).admin, 'GET', '/api/lan-peers/group');
  assert.equal(leaderless.json.degraded, true, '门面明确 leaderPeerId=null = degraded');

  // host 还没接线（没有 role 门面）：按 S1 口径 hub 就是 leader，不编造报警
  const unwired = await hit(stubAdmin({
    group: { enabled: true, hub: '' },
    api: apiWith({ isHub: true, lastSeq: 8 }),
  }).admin, 'GET', '/api/lan-peers/group');
  assert.equal(unwired.json.degraded, false);
  assert.equal(unwired.json.role, 'leader', 'hub 兜底角色 = leader');
  assert.equal(unwired.json.leaseUntil, null, '租约未知就是 null（面板显示 —）');
  assert.equal(unwired.json.commitSeq, 8, '可见的 lastSeq 就是已提交序号');
  assert.equal(unwired.json.pendingCount, 0);
  assert.equal(unwired.json.quorum, 'majority', '默认 majority');

  const memberFallback = await hit(stubAdmin({
    group: { enabled: true, hub: 'hub-box' },
    api: apiWith({ isHub: false, lastSeq: 8 }),
    peers: HUB_PEERS,
  }).admin, 'GET', '/api/lan-peers/group');
  assert.equal(memberFallback.json.role, 'follower', '成员兜底角色 = follower');
  assert.equal(memberFallback.json.degraded, false, '老 hub 不报 leaderPeerId 不等于没有 leader');

  const none = await hit(stubAdmin({
    group: { enabled: true, hub: '', quorum: 'none' },
    api: apiWith({ isHub: true, lastSeq: 8 }),
  }).admin, 'GET', '/api/lan-peers/group');
  assert.equal(none.json.quorum, 'none', 'group.quorum=none 如实透给面板');
});

test('S3 · leader.epoch 以角色门面为准：角色 3 / 群元数据 1 → 3；门面缺席回退旧值', async () => {
  // 真机（NAS 0.7.0）现象：group.json 的 keyVersion 世代是 1，角色文件已经是 3。
  const metadataEpochOne = () => ({
    groupId: 'g-1', name: 'default', epoch: 1, members: MEMBERS, messages: MESSAGES, lastSeq: 8,
  });
  const roleEpochThree = () => ({
    role: 'leader', epoch: 3, leaderPeerId: 'inst-self', leaseUntil: Date.now() + 9000,
    commitSeq: 8, pendingCount: 0,
  });

  const hubSide = await hit(stubAdmin({
    group: { enabled: true, hub: '' },
    api: { ...makeApi(), isHub: true, state: metadataEpochOne },
    facade: { enabled: true, isHub: true, role: roleEpochThree },
  }).admin, 'GET', '/api/lan-peers/group');
  assert.equal(hubSide.json.leader.epoch, 3, 'leader.epoch 必须是选举世代，不是 group.json 的 keyVersion');
  assert.equal(hubSide.json.leader.peerId, 'inst-self', 'peerId 取法不变');
  assert.equal(hubSide.json.leader.name, 'self', 'name 取法不变');
  assert.equal(hubSide.json.role, 'leader');

  const memberSide = await hit(stubAdmin({
    group: { enabled: true, hub: 'hub-box' },
    api: { ...makeApi(), isHub: false, state: metadataEpochOne },
    peers: HUB_PEERS,
    facade: { enabled: false, isHub: false, role: () => ({ role: 'follower', epoch: 3, leaderPeerId: 'peer-hub' }) },
  }).admin, 'GET', '/api/lan-peers/group');
  assert.equal(memberSide.json.leader.epoch, 3, '成员侧同样以角色世代为准');
  assert.equal(memberSide.json.leader.peerId, 'peer-hub', '成员侧 peerId 仍取 group.hub 指向的 peer');

  // 角色门面缺席（老 host / M 未接线）：回到原来那个值，旧行为不破
  const fallback = await hit(stubAdmin({
    group: { enabled: true, hub: '' },
    api: { ...makeApi(), isHub: true, state: metadataEpochOne },
  }).admin, 'GET', '/api/lan-peers/group');
  assert.equal(fallback.json.leader.epoch, 1, '没有角色门面时回退到群元数据的 epoch');
});

test('S3 · 成员侧 leader.peerId 同样以角色门面为准（配置的 group.hub 只是引导入口）', async () => {
  // 动态 hub 的语义：leader 可能是任何成员，group.hub 只是引导入口，不代表当前 leader。
  const members = [
    { peerId: 'peer-hub', name: 'hub-box', online: true, lastSeen: null, joinedAt: 1, baseUrl: 'http://192.168.1.51:7788', lastSeq: 8 },
    { peerId: 'peer-other', name: 'dsh-desktop', online: true, lastSeen: null, joinedAt: 2, baseUrl: 'http://192.168.1.20:7788', lastSeq: 8 },
    { peerId: 'member-inst', name: 'me', online: true, lastSeen: null, joinedAt: 3, baseUrl: '', lastSeq: null },
  ];
  const leadsAs = (leaderPeerId) => stubAdmin({
    group: { enabled: true, hub: 'hub-box' },
    api: apiWith({ isHub: false, lastSeq: 8, members }),
    peers: HUB_PEERS,
    facade: { enabled: false, isHub: false, role: () => ({ role: 'follower', epoch: 3, leaderPeerId, leaseUntil: Date.now() + 9000 }) },
  });

  const out = await hit(leadsAs('peer-other').admin, 'GET', '/api/lan-peers/group');
  assert.equal(out.json.selfRole, 'member');
  assert.equal(out.json.role, 'follower');
  assert.equal(out.json.leader.peerId, 'peer-other', '门面的 leaderPeerId 压过配置的 group.hub');
  assert.notEqual(out.json.leader.peerId, 'peer-hub');
  assert.equal(out.json.leader.name, 'dsh-desktop', '名字从群成员表查');
  assert.equal(out.json.leader.epoch, 3);

  // 本机自己当 leader：成员表里有名字就用表里的，没有就用本机名（不是 UUID）
  const named = await hit(leadsAs('member-inst').admin, 'GET', '/api/lan-peers/group');
  assert.equal(named.json.leader.peerId, 'member-inst');
  assert.equal(named.json.leader.name, 'me');
  // 成员表里没有本机那条（还没进群状态）：本机自己当 leader 时用自己的名字，不是 UUID
  const unnamed = await hit(stubAdmin({
    group: { enabled: true, hub: 'hub-box' },
    api: apiWith({ isHub: false, lastSeq: 8 }),
    peers: HUB_PEERS,
    facade: { enabled: false, isHub: false, role: () => ({ role: 'leader', epoch: 3, leaderPeerId: 'inst-self' }) },
  }).admin, 'GET', '/api/lan-peers/group');
  assert.equal(unnamed.json.leader.peerId, 'inst-self', '本机（store.instanceId）当选');
  assert.equal(unnamed.json.leader.name, 'self', '查不到时本机用自己的名字');

  // 门面缺席 / leaderPeerId 为空：回退到配置的 group.hub（旧行为不破）
  const legacy = await hit(stubAdmin({
    group: { enabled: true, hub: 'hub-box' },
    api: apiWith({ isHub: false, lastSeq: 8, members }),
    peers: HUB_PEERS,
  }).admin, 'GET', '/api/lan-peers/group');
  assert.equal(legacy.json.leader.peerId, 'peer-hub', '没有角色门面时仍认配置的 hub');
  assert.equal(legacy.json.leader.name, 'hub-box');

  const emptyLeader = await hit(leadsAs('').admin, 'GET', '/api/lan-peers/group');
  assert.equal(emptyLeader.json.leader.peerId, 'peer-hub', 'leaderPeerId 为空字符串等于没接线');
});

test('S3 · hub 且选举为 follower：leader.peerId 是真 leader（不是本机），selfRole 仍是 hub', async () => {
  // 真机（0.7.2 NAS）：配置上是 hub，但选举输给了 dsh-desktop。
  const members = [
    { peerId: 'inst-self', name: 'nas-box', online: true, lastSeen: null, joinedAt: 1, baseUrl: 'http://192.168.1.51:7788', lastSeq: 8 },
    { peerId: 'peer-desktop', name: 'dsh-desktop', online: true, lastSeen: null, joinedAt: 2, baseUrl: 'http://192.168.1.20:7788', lastSeq: 8 },
  ];
  const state = () => ({
    groupId: 'g-1', name: 'default', epoch: 4, members, messages: MESSAGES, lastSeq: 8,
  });
  const followerHub = await hit(stubAdmin({
    group: { enabled: true, hub: '' },
    api: { ...makeApi(), isHub: true, state },
    facade: { enabled: true, isHub: true, role: () => ({ role: 'follower', epoch: 4, leaderPeerId: 'peer-desktop', leaseUntil: Date.now() + 9000 }) },
  }).admin, 'GET', '/api/lan-peers/group');

  assert.equal(followerHub.json.selfRole, 'hub', 'selfRole 是「配置上的 hub」，与选举角色不是一个概念');
  assert.equal(followerHub.json.role, 'follower', '选举角色如实透出');
  assert.equal(followerHub.json.leader.peerId, 'peer-desktop', 'leader 必须是选举赢家，不能写死本机');
  assert.notEqual(followerHub.json.leader.peerId, 'inst-self');
  assert.equal(followerHub.json.leader.name, 'dsh-desktop', '名字从成员表里查');
  assert.equal(followerHub.json.leader.epoch, 4);

  // 成员表里查不到那个 peerId：名字退回 peerId（不编名字，也不回退本机）
  const ghost = await hit(stubAdmin({
    group: { enabled: true, hub: '' },
    api: { ...makeApi(), isHub: true, state },
    facade: { enabled: true, isHub: true, role: () => ({ role: 'follower', epoch: 4, leaderPeerId: 'peer-ghost' }) },
  }).admin, 'GET', '/api/lan-peers/group');
  assert.equal(ghost.json.leader.peerId, 'peer-ghost');
  assert.equal(ghost.json.leader.name, 'peer-ghost', '查不到名字就用 peerId');

  // 角色门面缺席（老 host / 未接线）：回退到「hub 就是本机」的旧行为
  const legacy = await hit(stubAdmin({
    group: { enabled: true, hub: '' },
    api: { ...makeApi(), isHub: true, state },
  }).admin, 'GET', '/api/lan-peers/group');
  assert.equal(legacy.json.leader.peerId, 'inst-self', '没有角色门面时回退本机');
  assert.equal(legacy.json.leader.name, 'self');
});

test('S3 · 群状态快照里的角色字段是第二来源（门面缺席时也能显示）', async () => {
  const leaseUntil = Date.now() + 9000;
  const api = apiWith({ isHub: true, lastSeq: 8 });
  api.state = () => ({
    groupId: 'g-1', name: 'default', members: MEMBERS, messages: MESSAGES, lastSeq: 8,
    role: 'candidate', leaseUntil, commitSeq: 6, pendingCount: 1,
  });
  const out = await hit(stubAdmin({ group: { enabled: true, hub: '' }, api }).admin, 'GET', '/api/lan-peers/group');
  assert.equal(out.json.role, 'candidate');
  assert.equal(out.json.leaseUntil, leaseUntil);
  assert.equal(out.json.commitSeq, 6);
  assert.equal(out.json.pendingCount, 1);
});

test('S3 · 后端失败分支同样带六个新字段（degraded=true），旧 error 形状不变', async () => {
  const { admin } = stubAdmin({ group: { enabled: true, hub: 'nas' }, api: { ...makeApi({ failOn: 'state' }), isHub: false } });
  const out = await hit(admin, 'GET', '/api/lan-peers/group?sinceSeq=4');
  assert.equal(out.res.status, 200);
  assert.match(out.json.error, /hub unreachable/);
  assert.equal(out.json.group, null);
  assert.equal(out.json.role, 'follower');
  assert.equal(out.json.leaseUntil, null);
  assert.equal(out.json.commitSeq, null);
  assert.equal(out.json.pendingCount, 0);
  assert.equal(out.json.quorum, 'majority');
  assert.equal(out.json.degraded, true, '看不到 leader 就是 degraded');
});

test('S3 · claim 三态：成功 / 后端拒绝 / 后端抛错，全部 200 且日志不留密钥', async () => {
  const ok = await hit(stubAdmin({ group: { enabled: true, hub: '' } }).admin,
    'POST', '/api/lan-peers/group/leader', { action: 'claim' });
  assert.equal(ok.res.status, 200);
  assert.deepEqual(ok.json, { ok: true, role: 'leader', epoch: 5 });

  const refusedApi = makeApi();
  refusedApi.claim = () => ({ ok: false, reason: 'quorum-unavailable' });
  const refused = await hit(stubAdmin({ group: { enabled: true, hub: '' }, api: refusedApi }).admin,
    'POST', '/api/lan-peers/group/leader', { action: 'claim' });
  assert.equal(refused.res.status, 200);
  assert.deepEqual(refused.json, { ok: false, reason: 'quorum-unavailable' }, '拒绝也按契约形状回，不抛 5xx');

  const broken = stubAdmin({ group: { enabled: true, hub: '' }, api: makeApi({ failOn: 'claim' }) });
  const failed = await hit(broken.admin, 'POST', '/api/lan-peers/group/leader', { action: 'claim' });
  assert.equal(failed.res.status, 200);
  assert.deepEqual(failed.json, { ok: false, reason: 'hub unreachable' });

  const log = broken.lines.filter((line) => line.includes('[admin] group claim')).join('\n');
  assert.match(log, /\[admin\] group claim failed err=hub unreachable/);
  assert.doesNotMatch(log, /secret/i, '接管日志不得出现密钥');
});

test('S3 · claim 前置拒绝：action 校验 / 未启用 / 后端没有接管入口', async () => {
  const bad = stubAdmin({ group: { enabled: true, hub: '' } });
  const badAction = await hit(bad.admin, 'POST', '/api/lan-peers/group/leader', { action: 'nuke' });
  assert.equal(badAction.res.status, 200);
  assert.deepEqual(badAction.json, { ok: false, reason: 'bad-action' });
  assert.equal(bad.api.calls.length, 0, '校验失败不得下发到后端');

  const disabled = await hit(stubAdmin({ group: { enabled: false } }).admin,
    'POST', '/api/lan-peers/group/leader', { action: 'claim' });
  assert.deepEqual(disabled.json, { ok: false, reason: 'group-disabled' });

  const noClaim = await hit(stubAdmin({ group: { enabled: true, hub: '' }, api: { ...makeApi(), claim: undefined } }).admin,
    'POST', '/api/lan-peers/group/leader', { action: 'claim' });
  assert.deepEqual(noClaim.json, { ok: false, reason: 'claim-unsupported' });
});

test('S3 · claim 走真 host 门面（server.group.claim）：转发成功，缺失时如实报 claim-unsupported', async () => {
  const wired = stubAdmin({
    group: { enabled: true, hub: '' },
    api: null,
    facade: { enabled: true, isHub: true, claim: () => ({ ok: true, role: 'leader', epoch: 7 }) },
  });
  const out = await hit(wired.admin, 'POST', '/api/lan-peers/group/leader', { action: 'claim' });
  assert.equal(out.res.status, 200);
  assert.deepEqual(out.json, { ok: true, role: 'leader', epoch: 7 });
  assert.ok(wired.lines.some((line) => line.includes('[admin] group claim ok role=leader epoch=7')));

  const unwired = await hit(stubAdmin({
    group: { enabled: true, hub: '' },
    api: null,
    facade: { enabled: true, isHub: true },
  }).admin, 'POST', '/api/lan-peers/group/leader', { action: 'claim' });
  assert.deepEqual(unwired.json, { ok: false, reason: 'claim-unsupported' }, 'M 未接线时如实报，面板只写 msg');
});

test('S3 · 未启用群的形状完全不变（六个新字段一个都不加）', async () => {
  const out = await hit(stubAdmin({ group: { enabled: false } }).admin, 'GET', '/api/lan-peers/group');
  assert.deepEqual(out.json, { enabled: false, isHub: false, group: null, messages: [], lastSeq: 0 });
  for (const key of ['role', 'leaseUntil', 'quorum', 'commitSeq', 'pendingCount', 'degraded']) {
    assert.equal(key in out.json, false, '未启用分支不得出现 ' + key);
  }
});

