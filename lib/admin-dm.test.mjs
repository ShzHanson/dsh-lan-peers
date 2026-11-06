// dsh-lan-peers · v0.8.5-α（契约 §5，Lane G2）私聊管理接口。
//
// 口径：
//   GET  /api/lan-peers/dm?peer=<peerId>        → { peer:{peerId,name}, messages:[...] }
//   POST /api/lan-peers/dm/send { peerId, text } → { ok, id, sessionId, reply, elapsedMs, reused }
//   POST /api/lan-peers/dm/sync { peerId }       → { ok, added, total }
// 门禁沿用 0.8.3：回环 Host + 会话 token，写操作另加 JSON + 同源；门面缺席一律 501
// dm-unsupported（不假装空对话）。铁律（契约 §0）：私聊与群完全隔离 —— 正文不进群、
// 不进日志，日志只记 peer 前 8 位、字节数与状态。
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

/** 真实面板的形状：回环 Host 头 + token（这里可整体覆盖，用于测门禁本身）。 */
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
      ...(overrides.extraHeaders ?? {}),
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

const AT = 1_760_000_000_000;
const PEER = { peerId: 'peer-b-1234', name: '书房' };
const MESSAGES = [
  { id: 'm-1', ts: AT, from: 'self', text: '我叫你小助手', sessionId: 's-1', state: 'sent' },
  { id: 'm-2', ts: AT + 900, from: 'peer', text: '好的，记住了', sessionId: 's-1', state: 'sent' },
  // 脏条目：没有 id 的行没法按 id 去重/对齐，整行丢掉。
  { ts: AT + 1200, from: 'peer', text: '没有 id' },
  null,
];

function makeDmFacade({
  messages = MESSAGES,
  sendResult = { ok: true, id: 'm-3', sessionId: 's-1', reply: '还记得，你让我叫小助手', elapsedMs: 1227, reused: true },
  syncResult = { ok: true, added: 2, total: 2 },
  throwOn = '',
} = {}) {
  const calls = [];
  const guard = (name) => {
    if (throwOn !== name) return;
    const error = new Error('dm unavailable');
    error.status = 500;
    throw error;
  };
  return {
    calls,
    async list(peerId) { calls.push({ method: 'list', peerId }); guard('list'); return messages; },
    async send(input) {
      calls.push({ method: 'send', ...input });
      guard('send');
      return typeof sendResult === 'function' ? sendResult(input) : sendResult;
    },
    async sync(peerId) {
      calls.push({ method: 'sync', peerId });
      guard('sync');
      return typeof syncResult === 'function' ? syncResult(peerId) : syncResult;
    },
  };
}

/** 群门面探测器：私聊的任何一条路由都不许碰它（契约 §0 的隔离断言）。 */
function makeGroupSpy() {
  const calls = [];
  const note = (name) => (...args) => { calls.push({ name, args }); return null; };
  return { calls, post: note('post'), history: note('history'), dispatchWithReply: note('dispatch') };
}

function stubAdmin({ dm = null, dmMounted = false, serverDm = null, stateDir = '' } = {}) {
  const lines = [];
  const store = {
    instanceId: 'peer-self',
    stateDir,
    listPeers: () => [PEER],
    getPeer: (peerId) => (peerId === PEER.peerId ? { ...PEER } : null),
  };
  const group = makeGroupSpy();
  const server = { config: { logger: (line) => lines.push(line), listenPort: 0, group: null }, store, group };
  // dmMounted：模拟 G1 在 host 上把门面挂到 server.dm 的形状（默认接线就是这样读的）。
  if (dmMounted && dmMounted !== true) server.dm = dmMounted;
  if (dmMounted === true && dm) server.dm = dm;
  if (serverDm) server.dm = serverDm;
  const admin = createAdmin({
    server,
    nameOf: () => 'self-box',
    rename: (n) => n,
    feed: null,
    pairing: { mode: 'auto' },
    dm: dmMounted === true || serverDm ? null : dm,
  });
  return { admin, lines, group };
}

const dmLines = (lines) => lines.filter((line) => line.includes('[admin] dm'));

// ---------------------------------------------------------------------------
// 门禁
// ---------------------------------------------------------------------------

test('私聊接口门禁：没有 token 一律 401，写操作非 JSON 415 —— 只读接口也不例外', async () => {
  const facade = makeDmFacade();
  const { admin } = stubAdmin({ dm: facade });

  const read = await hit(admin, 'GET', '/api/lan-peers/dm?peer=' + PEER.peerId, undefined, { token: '' });
  assert.equal(read.res.status, 401);
  assert.deepEqual(read.json, { error: 'token-required' });

  const send = await hit(admin, 'POST', '/api/lan-peers/dm/send', { peerId: PEER.peerId, text: '你好' }, { token: '' });
  assert.equal(send.res.status, 401);

  const sync = await hit(admin, 'POST', '/api/lan-peers/dm/sync', { peerId: PEER.peerId }, { token: '' });
  assert.equal(sync.res.status, 401);

  const wrongType = await hit(
    admin, 'POST', '/api/lan-peers/dm/send', { peerId: PEER.peerId, text: '你好' }, { contentType: 'text/plain' },
  );
  assert.equal(wrongType.res.status, 415);
  assert.deepEqual(wrongType.json, { error: 'content-type-json-required' });

  assert.equal(facade.calls.length, 0, '门禁拦住的请求不能碰到门面');
});

// ---------------------------------------------------------------------------
// GET /api/lan-peers/dm
// ---------------------------------------------------------------------------

test('GET dm：按契约 §5 回 { peer, messages }，脏条目被丢弃、正文原样回传', async () => {
  const facade = makeDmFacade();
  const { admin, lines, group } = stubAdmin({ dm: facade });

  const out = await hit(admin, 'GET', '/api/lan-peers/dm?peer=' + PEER.peerId);
  assert.equal(out.res.status, 200);
  assert.deepEqual(facade.calls, [{ method: 'list', peerId: PEER.peerId }]);
  assert.deepEqual(out.json.peer, { peerId: PEER.peerId, name: '书房' });
  assert.equal(out.json.messages.length, 2, '没有 id 的行整行丢掉');
  assert.deepEqual(out.json.messages[0], {
    id: 'm-1', ts: AT, from: 'self', text: '我叫你小助手', sessionId: 's-1', state: 'sent',
  });
  assert.equal(out.json.messages[1].from, 'peer');

  // 日志口径：只记 peer 前 8 位与条数，正文一个字都不进日志。
  const dm = dmLines(lines);
  assert.equal(dm.length, 1);
  assert.match(dm[0], /dm list peer=peer-b-1 count=2/);
  assert.doesNotMatch(lines.join('\n'), /小助手/, '私聊正文不得进日志');
  assert.equal(group.calls.length, 0, '私聊请求不得触碰群门面（契约 §0）');
});

test('GET dm：缺 peer 400，门面缺席 501，list 抛错按 status 回（默认 502）', async () => {
  const { admin } = stubAdmin({ dm: makeDmFacade() });

  const missing = await hit(admin, 'GET', '/api/lan-peers/dm');
  assert.equal(missing.res.status, 400);
  assert.deepEqual(missing.json, { error: 'peer-required' });

  const unwired = await hit(stubAdmin({ dm: null }).admin, 'GET', '/api/lan-peers/dm?peer=' + PEER.peerId);
  assert.equal(unwired.res.status, 501);
  assert.deepEqual(unwired.json, { error: 'dm-unsupported' });

  const broken = await hit(stubAdmin({ dm: makeDmFacade({ throwOn: 'list' }) }).admin,
    'GET', '/api/lan-peers/dm?peer=' + PEER.peerId);
  assert.equal(broken.res.status, 500);
  assert.deepEqual(broken.json, { error: 'dm unavailable' });
});

// ---------------------------------------------------------------------------
// POST /api/lan-peers/dm/send
// ---------------------------------------------------------------------------

test('POST dm/send：门面收到 { peerId, text }，响应形状与契约 §5 一致', async () => {
  const facade = makeDmFacade();
  const { admin, lines, group } = stubAdmin({ dm: facade });

  const out = await hit(admin, 'POST', '/api/lan-peers/dm/send', { peerId: PEER.peerId, text: '我刚才让你叫什么？' });
  assert.equal(out.res.status, 200);
  assert.deepEqual(facade.calls, [{ method: 'send', peerId: PEER.peerId, text: '我刚才让你叫什么？' }]);
  assert.deepEqual(out.json, {
    ok: true, id: 'm-3', sessionId: 's-1', reply: '还记得，你让我叫小助手', elapsedMs: 1227, reused: true,
  });

  const dm = dmLines(lines);
  assert.equal(dm.length, 1);
  assert.match(dm[0], /dm send peer=peer-b-1 id=m-3 bytes=27 replyBytes=33 reused=true state=ok ms=1227/);
  assert.doesNotMatch(lines.join('\n'), /小助手/, '正文与回复都不得进日志');
  assert.doesNotMatch(lines.join('\n'), /我刚才让你叫/, '正文不得进日志');
  assert.equal(group.calls.length, 0, '私聊回复只回调用方，绝不入群');
});

test('POST dm/send：缺 peerId / 空正文 400，门面缺席 501，目标离线 409 带明确 reason', async () => {
  const { admin } = stubAdmin({ dm: makeDmFacade() });

  const noPeer = await hit(admin, 'POST', '/api/lan-peers/dm/send', { text: '在吗' });
  assert.equal(noPeer.res.status, 400);
  assert.deepEqual(noPeer.json, { error: 'peerId-required' });

  const noText = await hit(admin, 'POST', '/api/lan-peers/dm/send', { peerId: PEER.peerId, text: '   ' });
  assert.equal(noText.res.status, 400);
  assert.deepEqual(noText.json, { error: 'text-required' });

  const unwired = await hit(stubAdmin({ dm: null }).admin, 'POST', '/api/lan-peers/dm/send',
    { peerId: PEER.peerId, text: '在吗' });
  assert.equal(unwired.res.status, 501);
  assert.deepEqual(unwired.json, { error: 'dm-unsupported' });

  const offline = await hit(
    stubAdmin({ dm: makeDmFacade({ sendResult: { ok: false, reason: 'peer-offline' } }) }).admin,
    'POST', '/api/lan-peers/dm/send', { peerId: PEER.peerId, text: '在吗' },
  );
  assert.equal(offline.res.status, 409);
  assert.deepEqual(offline.json, { error: 'peer-offline' }, '离线要给明确 reason，不能编一个 ok');
});

// ---------------------------------------------------------------------------
// POST /api/lan-peers/dm/sync
// ---------------------------------------------------------------------------

test('POST dm/sync：门面收到 peerId，回 { ok, added, total }', async () => {
  const facade = makeDmFacade();
  const { admin, lines } = stubAdmin({ dm: facade });

  const out = await hit(admin, 'POST', '/api/lan-peers/dm/sync', { peerId: PEER.peerId });
  assert.equal(out.res.status, 200);
  assert.deepEqual(out.json, { ok: true, added: 2, total: 2 });
  assert.deepEqual(facade.calls, [{ method: 'sync', peerId: PEER.peerId }]);
  assert.match(dmLines(lines)[0], /dm sync peer=peer-b-1 added=2 total=2/);
});

test('POST dm/sync：缺 peerId 400，门面缺席 501，对端离线 409，抛错 502', async () => {
  const { admin } = stubAdmin({ dm: makeDmFacade() });

  const missing = await hit(admin, 'POST', '/api/lan-peers/dm/sync', {});
  assert.equal(missing.res.status, 400);
  assert.deepEqual(missing.json, { error: 'peerId-required' });

  const unwired = await hit(stubAdmin({ dm: null }).admin, 'POST', '/api/lan-peers/dm/sync', { peerId: PEER.peerId });
  assert.equal(unwired.res.status, 501);

  const offline = await hit(
    stubAdmin({ dm: makeDmFacade({ syncResult: { ok: false, reason: 'peer-offline' } }) }).admin,
    'POST', '/api/lan-peers/dm/sync', { peerId: PEER.peerId },
  );
  assert.equal(offline.res.status, 409);
  assert.deepEqual(offline.json, { error: 'peer-offline' });

  const broken = await hit(stubAdmin({ dm: makeDmFacade({ throwOn: 'sync' }) }).admin,
    'POST', '/api/lan-peers/dm/sync', { peerId: PEER.peerId });
  assert.equal(broken.res.status, 500);
});

// ---------------------------------------------------------------------------
// 接线形态
// ---------------------------------------------------------------------------

test('接线：createAdmin 之后才挂上的 server.dm 也能用（G1 落地无需改本文件）', async () => {
  const facade = makeDmFacade();
  const { admin } = stubAdmin({ serverDm: facade });

  const read = await hit(admin, 'GET', '/api/lan-peers/dm?peer=' + PEER.peerId);
  assert.equal(read.res.status, 200);
  assert.equal(read.json.messages.length, 2);

  const send = await hit(admin, 'POST', '/api/lan-peers/dm/send', { peerId: PEER.peerId, text: '早' });
  assert.equal(send.res.status, 200);
  assert.equal(send.json.reused, true);
  assert.deepEqual(facade.calls.map((call) => call.method), ['list', 'send']);
});
