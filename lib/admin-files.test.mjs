// dsh-lan-peers · v0.8.5-α（契约 §3/§4，Lane F2）文件互传管理接口 + 发送工具。
//
// 口径：
//   GET  /api/lan-peers/files                        → { pending, inbox }
//   POST /api/lan-peers/files/accept { id }          → { ok, path }
//   POST /api/lan-peers/files/reject { id }          → { ok }
//   POST /api/lan-peers/files/send { peerId, path }  → { ok, id, bytes, sha256, ms }
// 门禁沿用 0.8.3：回环 Host + 会话 token，写操作另加 JSON + 同源；门面缺席一律
// 501 files-unsupported（不假装空列表）。日志只记 size / sha256 前 8 位 / 状态 ——
// 文件名、落盘路径与文件内容都不进日志（契约 §0）。
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createAdmin } from './admin.mjs';
import { createLanPeerTools } from './tools.mjs';
import { makeTempStateDir, writeJson0600 } from '../host/test/helpers.mjs';

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

const SHA_A = 'a'.repeat(64);
const SHA_B = 'b'.repeat(64);
const AT = 1_760_000_000_000;
const ENTRIES = [
  { id: 'id-pending-1', name: '报告.pdf', size: 4096, sha256: SHA_A, from: { peerId: 'peer-b', name: '书房' }, at: AT, state: 'pending' },
  { id: 'id-done-1', name: 'photo.jpg', size: 2048, sha256: SHA_B, from: { peerId: 'peer-b', name: '书房' }, at: AT - 1000, state: 'done' },
  // 传输中与已拒收都不进这两个桶（契约 §4 只有 pending / inbox）。
  { id: 'id-incoming-1', name: 'big.bin', size: 10, sha256: '', from: { peerId: 'peer-b', name: '书房' }, at: AT, state: 'incoming' },
  { id: 'id-rejected-1', name: 'old.bin', size: 10, sha256: '', from: { peerId: 'peer-b', name: '书房' }, at: AT, state: 'rejected' },
];

const SENT_PATH = '/home/u/secret-name.bin';

function makeFilesFacade({
  entries = ENTRIES,
  acceptResult = { ok: true, path: '/state/inbox/id-pending-1__report.pdf' },
  rejectResult = { ok: true },
  sendResult = { ok: true, id: 'tx-7f3a91', bytes: 4096, sha256: SHA_A, ms: 37 },
  progressResult = { received: 8192, size: 16384, state: 'incoming' },
  throwOn = '',
} = {}) {
  const calls = [];
  const guard = (name) => {
    if (throwOn !== name) return;
    const error = new Error('inbox unavailable');
    error.status = 500;
    throw error;
  };
  return {
    calls,
    async list() { calls.push({ method: 'list' }); guard('list'); return entries; },
    async accept(id) {
      calls.push({ method: 'accept', id });
      guard('accept');
      return typeof acceptResult === 'function' ? acceptResult(id) : acceptResult;
    },
    async reject(id) { calls.push({ method: 'reject', id }); guard('reject'); return rejectResult; },
    async send(input) { calls.push({ method: 'send', ...input }); guard('send'); return sendResult; },
    async progress(id) {
      calls.push({ method: 'progress', id });
      guard('progress');
      return typeof progressResult === 'function' ? progressResult(id) : progressResult;
    },
  };
}

function stubAdmin({ files = null, mounted = false, stateDir = '' } = {}) {
  const lines = [];
  const store = { instanceId: 'peer-self', stateDir, listPeers: () => [], getPeer: () => null };
  const server = { config: { logger: (line) => lines.push(line), listenPort: 0 }, store };
  // mounted：模拟 F1 在 host 上把门面挂到 server.files 的形状（默认接线就是这样读的）。
  if (mounted && files) server.files = files;
  const admin = createAdmin({
    server,
    nameOf: () => 'self-box',
    rename: (n) => n,
    feed: null,
    pairing: { mode: 'auto' },
    files: mounted ? null : files,
  });
  return { admin, lines };
}

const filesLines = (lines) => lines.filter((line) => line.includes('[admin] files'));

// ---------------------------------------------------------------------------
// 门禁：token / JSON
// ---------------------------------------------------------------------------

test('文件接口门禁：没有 token 一律 401，写操作非 JSON 415 —— 只读接口也不例外', async () => {
  const facade = makeFilesFacade();
  const { admin } = stubAdmin({ files: facade });

  const read = await hit(admin, 'GET', '/api/lan-peers/files', undefined, { token: '' });
  assert.equal(read.res.status, 401);
  assert.deepEqual(read.json, { error: 'token-required' });

  const accept = await hit(admin, 'POST', '/api/lan-peers/files/accept', { id: 'id-pending-1' }, { token: '' });
  assert.equal(accept.res.status, 401);

  const send = await hit(admin, 'POST', '/api/lan-peers/files/send', { peerId: 'peer-b', path: SENT_PATH }, { token: '' });
  assert.equal(send.res.status, 401);

  const wrongType = await hit(
    admin, 'POST', '/api/lan-peers/files/reject', { id: 'id-pending-1' }, { contentType: 'text/plain' },
  );
  assert.equal(wrongType.res.status, 415);
  assert.deepEqual(wrongType.json, { error: 'content-type-json-required' });

  assert.equal(facade.calls.length, 0, '门禁拦住的请求不能碰到门面');
});

// ---------------------------------------------------------------------------
// GET /api/lan-peers/files
// ---------------------------------------------------------------------------

test('GET files：按 state 分成 pending / inbox 两桶，脏条目被归一或丢掉', async () => {
  const dirty = [
    ...ENTRIES,
    { name: '没有 id.bin', size: 1, state: 'pending' },
    { id: '  id-spaced  ', name: null, size: '8192', sha256: null, from: 'peer-c', at: '2026-01-02T03:04:05.000Z', state: 'done' },
    null,
  ];
  const facade = makeFilesFacade({ entries: dirty });
  const { admin, lines } = stubAdmin({ files: facade });
  const out = await hit(admin, 'GET', '/api/lan-peers/files');

  assert.equal(out.handled, true);
  assert.equal(out.res.status, 200);
  assert.equal(out.json.pending.length, 1, 'pending 桶 = state pending（没有 id 的条目已丢掉）');
  assert.equal(out.json.inbox.length, 2, 'inbox 桶 = state done');
  assert.deepEqual(out.json.pending[0], {
    id: 'id-pending-1', name: '报告.pdf', size: 4096, sha256: SHA_A,
    from: { peerId: 'peer-b', name: '书房' }, at: AT, state: 'pending',
  });
  const spaced = out.json.inbox.find((row) => row.id === 'id-spaced');
  assert.equal(spaced.size, 8192, '字符串体积收成数字');
  assert.equal(spaced.sha256, '', '缺 sha256 给空串，不回 null');
  assert.deepEqual(spaced.from, { peerId: '', name: 'peer-c' }, 'from 是字符串时也能读出来');
  assert.equal(spaced.at, Date.parse('2026-01-02T03:04:05.000Z'), 'ISO 时间收成毫秒');
  assert.equal(out.json.pending.concat(out.json.inbox).some((row) => row.state !== 'pending' && row.state !== 'done'), false);

  const line = filesLines(lines).find((item) => item.includes('files list'));
  assert.match(line, /pending=1 inbox=2/, '日志只记条数');
  assert.equal(line.includes('报告.pdf'), false, '日志不写文件名');
});

test('GET files：门面缺席（F1 未接线）如实 501，不返回空列表充数', async () => {
  const { admin, lines } = stubAdmin({ files: null });
  const out = await hit(admin, 'GET', '/api/lan-peers/files');
  assert.equal(out.res.status, 501);
  assert.deepEqual(out.json, { error: 'files-unsupported' });
  assert.match(filesLines(lines)[0], /unsupported/);
});

test('GET files：默认接线读 server.files（F1 挂载后无需改 createAdmin）', async () => {
  const facade = makeFilesFacade();
  const { admin } = stubAdmin({ files: facade, mounted: true });
  const out = await hit(admin, 'GET', '/api/lan-peers/files');
  assert.equal(out.res.status, 200);
  assert.equal(out.json.pending.length, 1);
  assert.equal(facade.calls[0].method, 'list');
});

// ---------------------------------------------------------------------------
// POST files/accept · files/reject
// ---------------------------------------------------------------------------

test('POST files/accept：回 { ok, path }，日志记 id 与状态但不记落盘路径（含文件名）', async () => {
  const facade = makeFilesFacade();
  const { admin, lines } = stubAdmin({ files: facade });
  const out = await hit(admin, 'POST', '/api/lan-peers/files/accept', { id: 'id-pending-1' });

  assert.equal(out.res.status, 200);
  assert.deepEqual(out.json, { ok: true, path: '/state/inbox/id-pending-1__report.pdf' });
  assert.deepEqual(facade.calls, [{ method: 'accept', id: 'id-pending-1' }]);

  const line = filesLines(lines).find((item) => item.includes('files accept'));
  assert.match(line, /id=id-pendi/);
  assert.match(line, /state=ok/);
  assert.equal(line.includes('report.pdf'), false, '落盘路径（含文件名）绝不进日志');
  assert.equal(line.includes('/state/inbox'), false);
});

test('POST files/reject：回 { ok:true }；未知 id 404；缺 id 400；门面抛错按其 status 回', async () => {
  const facade = makeFilesFacade();
  const { admin, lines } = stubAdmin({ files: facade });

  const ok = await hit(admin, 'POST', '/api/lan-peers/files/reject', { id: 'id-pending-1' });
  assert.equal(ok.res.status, 200);
  assert.deepEqual(ok.json, { ok: true });

  const unknownFacade = makeFilesFacade({ rejectResult: { ok: false, reason: 'unknown-id' } });
  const unknown = await hit(stubAdmin({ files: unknownFacade }).admin, 'POST', '/api/lan-peers/files/reject', { id: 'nope' });
  assert.equal(unknown.res.status, 404);
  assert.deepEqual(unknown.json, { error: 'unknown-id' });

  const missing = await hit(admin, 'POST', '/api/lan-peers/files/accept', {});
  assert.equal(missing.res.status, 400);
  assert.deepEqual(missing.json, { error: 'id-required' });

  const exploding = await hit(
    stubAdmin({ files: makeFilesFacade({ throwOn: 'accept' }) }).admin,
    'POST', '/api/lan-peers/files/accept', { id: 'id-pending-1' },
  );
  assert.equal(exploding.res.status, 500);
  assert.deepEqual(exploding.json, { error: 'inbox unavailable' });

  assert.match(filesLines(lines).find((item) => item.includes('files reject')) ?? '', /state=ok/);
});

// ---------------------------------------------------------------------------
// POST files/send
// ---------------------------------------------------------------------------

test('POST files/send：透传 { peerId, path } 并回 { ok,id,bytes,sha256,ms }，日志只记字节与 sha 前 8 位', async () => {
  const facade = makeFilesFacade();
  const { admin, lines } = stubAdmin({ files: facade });
  const out = await hit(admin, 'POST', '/api/lan-peers/files/send', { peerId: 'peer-b', path: SENT_PATH });

  assert.equal(out.res.status, 200);
  assert.deepEqual(out.json, { ok: true, id: 'tx-7f3a91', bytes: 4096, sha256: SHA_A, ms: 37 });
  assert.deepEqual(facade.calls, [{ method: 'send', peerId: 'peer-b', path: SENT_PATH }]);

  const line = filesLines(lines).find((item) => item.includes('files send'));
  assert.match(line, /bytes=4096/);
  assert.match(line, /sha=aaaaaaaa/, 'sha256 只记前 8 位');
  assert.equal(line.includes('aaaaaaaaaaaa'), false, '不写完整 sha256');
  assert.equal(line.includes('secret-name'), false, '日志不写文件名');
  assert.equal(line.includes(SENT_PATH), false, '日志不写本地路径');
});

test('POST files/send：缺 peerId/path 400；对端拒绝 409；门面抛错 502', async () => {
  const { admin } = stubAdmin({ files: makeFilesFacade() });

  const noPeer = await hit(admin, 'POST', '/api/lan-peers/files/send', { path: SENT_PATH });
  assert.equal(noPeer.res.status, 400);
  assert.deepEqual(noPeer.json, { error: 'peerId-required' });

  const noPath = await hit(admin, 'POST', '/api/lan-peers/files/send', { peerId: 'peer-b' });
  assert.equal(noPath.res.status, 400);
  assert.deepEqual(noPath.json, { error: 'path-required' });

  const refused = await hit(
    stubAdmin({ files: makeFilesFacade({ sendResult: { ok: false, reason: 'too-large' } }) }).admin,
    'POST', '/api/lan-peers/files/send', { peerId: 'peer-b', path: SENT_PATH },
  );
  assert.equal(refused.res.status, 409);
  assert.deepEqual(refused.json, { error: 'too-large' });

  const thrown = await hit(
    stubAdmin({ files: makeFilesFacade({ throwOn: 'send' }) }).admin,
    'POST', '/api/lan-peers/files/send', { peerId: 'peer-b', path: SENT_PATH },
  );
  assert.equal(thrown.res.status, 500);

  const unsupported = await hit(
    stubAdmin({ files: null }).admin, 'POST', '/api/lan-peers/files/send', { peerId: 'peer-b', path: SENT_PATH },
  );
  assert.equal(unsupported.res.status, 501);
});

// ---------------------------------------------------------------------------
// GET /api/lan-peers/bootstrap（免 token，但严格门禁）—— 桌面面板拿不到 token 的真机修复
// ---------------------------------------------------------------------------

test('GET bootstrap：回环 Host + same-origin → 200，token 就是本进程那一枚，日志不含 token', async () => {
  const { admin, lines } = stubAdmin({ files: makeFilesFacade() });
  const out = await hit(admin, 'GET', '/api/lan-peers/bootstrap', undefined, {
    extraHeaders: { 'sec-fetch-site': 'same-origin' },
  });

  assert.equal(out.res.status, 200);
  assert.equal(out.json.token, admin.token, '交出去的就是本进程这枚 token');
  assert.equal(typeof out.json.name, 'string');
  assert.match(out.json.version, /^\d+\.\d+\.\d+/, '版本号来自 package.json');

  const log = lines.join('\n');
  assert.match(log, /\[admin\] bootstrap ok/);
  assert.equal(log.includes(admin.token), false, 'token 绝不进日志');
  assert.equal(log.includes(admin.token.slice(0, 8)), false, '连前缀也不行');

  // 不带 Sec-Fetch-Site（curl / Electron 原生请求）与 'none'（地址栏直开）同样放行。
  for (const extraHeaders of [undefined, { 'sec-fetch-site': 'none' }]) {
    const again = await hit(admin, 'GET', '/api/lan-peers/bootstrap', undefined, { extraHeaders });
    assert.equal(again.res.status, 200, '缺省 / none 都必须能用：' + JSON.stringify(extraHeaders));
    assert.equal(again.json.token, admin.token);
  }
});

test('GET bootstrap：跨站（cross-site / same-site）一律 403 cross-origin，且日志不泄露 token', async () => {
  const { admin, lines } = stubAdmin({ files: makeFilesFacade() });
  for (const site of ['cross-site', 'same-site']) {
    const out = await hit(admin, 'GET', '/api/lan-peers/bootstrap', undefined, { extraHeaders: { 'sec-fetch-site': site } });
    assert.equal(out.res.status, 403, site + ' 必须被拒');
    assert.deepEqual(out.json, { error: 'cross-origin' });
    assert.equal(Object.prototype.hasOwnProperty.call(out.json, 'token'), false);
  }
  const log = lines.join('\n');
  assert.match(log, /bootstrap denied reason=cross-origin/);
  assert.equal(log.includes(admin.token), false);
});

test('GET bootstrap：非回环 Host / Host 缺失 403，且非 GET 405（LAN 上根本拿不到 token）', async () => {
  const { admin } = stubAdmin({ files: makeFilesFacade() });

  const lan = await hit(admin, 'GET', '/api/lan-peers/bootstrap', undefined, { host: '203.0.113.7:3080' });
  assert.equal(lan.res.status, 403);
  assert.deepEqual(lan.json, { error: 'forbidden: loopback-only' });

  const missing = await hit(admin, 'GET', '/api/lan-peers/bootstrap', undefined, { host: '' });
  assert.equal(missing.res.status, 403, 'Host 缺失不是放行理由');

  const post = await hit(admin, 'POST', '/api/lan-peers/bootstrap', {});
  assert.equal(post.res.status, 405);
});

// ---------------------------------------------------------------------------
// <stateDir>/admin-url（真机缺陷：管理接口在 DSH web 端口，不是 peer 端口 7788）
// ---------------------------------------------------------------------------

test('管理接口把回环 Host 记进 <stateDir>/admin-url（0600），Host 变了才重写，且不进日志', async (t) => {
  const dir = makeTempStateDir('dsh-lan-peers-admin-url-');
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const { admin, lines } = stubAdmin({ files: makeFilesFacade(), stateDir: dir });
  const file = path.join(dir, 'admin-url');

  const first = await hit(admin, 'GET', '/api/lan-peers/files', undefined, { host: '127.0.0.1:3080' });
  assert.equal(first.res.status, 200);
  assert.equal(fs.readFileSync(file, 'utf8').trim(), 'http://127.0.0.1:3080');
  // Windows 上 chmod 只翻只读位，0600 无从验证（既有用例同一口径）。
  if (process.platform !== 'win32') assert.equal(fs.statSync(file).mode & 0o777, 0o600, 'admin-url 必须 0600');

  // 同一地址不重写（面板会持续轮询，别为了同一串字符反复写盘）
  const stamp = fs.statSync(file).mtimeMs;
  await new Promise((resolve) => setTimeout(resolve, 20));
  await hit(admin, 'GET', '/api/lan-peers/files', undefined, { host: '127.0.0.1:3080' });
  assert.equal(fs.statSync(file).mtimeMs, stamp, '地址没变就不该重写');

  // 桌面每次重启 web 端口都会变：Host 变了要跟着更新
  await hit(admin, 'GET', '/api/lan-peers/files', undefined, { host: '127.0.0.1:10591' });
  assert.equal(fs.readFileSync(file, 'utf8').trim(), 'http://127.0.0.1:10591');

  // 非回环 Host（LAN 上别人打过来）不能覆盖本机地址
  await hit(admin, 'GET', '/api/lan-peers/files', undefined, { host: '203.0.113.7:3080' });
  assert.equal(fs.readFileSync(file, 'utf8').trim(), 'http://127.0.0.1:10591');

  // 地址与文件名都不进日志
  assert.equal(/admin-url|127\.0\.0\.1:10591/.test(lines.join('\n')), false);
});

test('没有 token 的第一次访问也落地址（先记地址再走门禁），但仍按门禁回 401', async (t) => {
  const dir = makeTempStateDir('dsh-lan-peers-admin-url-noauth-');
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const { admin } = stubAdmin({ files: makeFilesFacade(), stateDir: dir });

  const out = await hit(admin, 'GET', '/api/lan-peers/files', undefined, { token: '', host: 'localhost:3080' });
  assert.equal(out.res.status, 401, '地址便利文件不改变门禁');
  assert.equal(fs.readFileSync(path.join(dir, 'admin-url'), 'utf8').trim(), 'http://localhost:3080');
});

// ---------------------------------------------------------------------------
// GET /api/lan-peers/files/progress（契约 §4 只读进度，Lane F2 补）
// ---------------------------------------------------------------------------

test('GET files/progress：只读返回 { received, size, state }，成功时不写日志（每 500ms 一次的轮询不能淹日志）', async () => {
  const facade = makeFilesFacade({ progressResult: { received: 8192, size: 16384, state: 'incoming' } });
  const { admin, lines } = stubAdmin({ files: facade });
  const out = await hit(admin, 'GET', '/api/lan-peers/files/progress?id=tr-1');

  assert.equal(out.handled, true);
  assert.equal(out.res.status, 200);
  assert.deepEqual(out.json, { received: 8192, size: 16384, state: 'incoming' });
  assert.deepEqual(facade.calls, [{ method: 'progress', id: 'tr-1' }], 'id 原样交给门面');
  assert.equal(filesLines(lines).length, 0, '轮询成功不写日志');

  // 脏值归一：字符串数字照收，缺 size 给 0 —— 面板/CLI 不会拿到 null。
  const dirty = makeFilesFacade({ progressResult: { received: '512', size: null, state: 'pending' } });
  const second = await hit(stubAdmin({ files: dirty }).admin, 'GET', '/api/lan-peers/files/progress?id=tr-2');
  assert.equal(second.res.status, 200);
  assert.deepEqual(second.json, { received: 512, size: 0, state: 'pending' });
});

test('GET files/progress：缺 id 400、未知 id 404、门面缺席 501、门面抛错 502', async () => {
  const unknownFacade = makeFilesFacade({ progressResult: { received: 0, size: 0, state: 'unknown' } });
  const { admin, lines } = stubAdmin({ files: unknownFacade });

  const missing = await hit(admin, 'GET', '/api/lan-peers/files/progress');
  assert.equal(missing.res.status, 400);
  assert.deepEqual(missing.json, { error: 'id-required' });

  const unknown = await hit(admin, 'GET', '/api/lan-peers/files/progress?id=nope');
  assert.equal(unknown.res.status, 404);
  assert.deepEqual(unknown.json, { error: 'unknown-id' });
  assert.match(filesLines(lines).find((item) => item.includes('files progress')) ?? '', /state=unknown/);

  const unwired = await hit(stubAdmin({ files: null }).admin, 'GET', '/api/lan-peers/files/progress?id=tr-1');
  assert.equal(unwired.res.status, 501);
  assert.deepEqual(unwired.json, { error: 'files-unsupported' });

  const thrown = await hit(
    stubAdmin({ files: makeFilesFacade({ throwOn: 'progress' }) }).admin,
    'GET', '/api/lan-peers/files/progress?id=tr-1',
  );
  assert.equal(thrown.res.status, 500);
  assert.deepEqual(thrown.json, { error: 'inbox unavailable' });
});

// ---------------------------------------------------------------------------
// 工具 lan_peer_send_file（lib/tools.mjs + lib/index.js 注入）
// ---------------------------------------------------------------------------

async function seedPeer(t) {
  const dir = makeTempStateDir('dsh-lan-peers-tool-send-');
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  writeJson0600(path.join(dir, 'peers.json'), {
    peers: { 'peer-b-1234': { name: '书房', baseUrl: 'http://10.0.0.2:7788', secret: 's', inboundSecret: 'i' } },
  });
  return dir;
}

test('工具 lan_peer_send_file：按名字解析 peerId，返回 { ok,id,bytes,sha256,ms }，日志不写路径', async (t) => {
  const dir = await seedPeer(t);
  const calls = [];
  const logs = [];
  const tools = await createLanPeerTools(
    { stateDir: dir },
    {
      defineTool: (spec) => spec,
      log: (line) => logs.push(line),
      sendFile: async (input) => {
        calls.push(input);
        return { ok: true, id: 'tx-7f3a91', bytes: 4096, sha256: SHA_A, ms: 37 };
      },
    },
  );
  const tool = tools.find((item) => item.name === 'lan_peer_send_file');
  assert.ok(tool, '工具必须注册：' + tools.map((item) => item.name).join(','));
  assert.deepEqual(Object.keys(tool.parameters).sort(), ['path', 'peer']);

  const out = await tool.execute({ peer: '书房', path: SENT_PATH });
  assert.equal(out.ok, true);
  assert.equal(out.id, 'tx-7f3a91');
  assert.equal(out.bytes, 4096);
  assert.equal(out.sha256, SHA_A);
  assert.equal(out.ms, 37);
  assert.match(out.text, /tx-7f3a91/);
  assert.deepEqual(calls, [{ peerId: 'peer-b-1234', path: SENT_PATH }], '工具传的是 peerId，不是名字');

  const line = logs.find((item) => item.includes('send-file'));
  assert.match(line, /bytes=4096/);
  assert.match(line, /sha=aaaaaaaa/);
  assert.equal(line.includes('secret-name'), false, '日志不写文件名');
  assert.equal(line.includes(SENT_PATH), false, '日志不写本地路径');
});

test('工具 lan_peer_send_file：未知伙伴与门面缺席都报错，不静默成功', async (t) => {
  const dir = await seedPeer(t);
  const tools = await createLanPeerTools(
    { stateDir: dir },
    { defineTool: (spec) => spec, log: () => {}, sendFile: async () => ({ ok: true, id: 'x', bytes: 1, sha256: '', ms: 1 }) },
  );
  const tool = tools.find((item) => item.name === 'lan_peer_send_file');
  await assert.rejects(() => tool.execute({ peer: '不存在的伙伴', path: SENT_PATH }), /unknown peer/);

  const unbound = await createLanPeerTools({ stateDir: dir }, { defineTool: (spec) => spec, log: () => {} });
  await assert.rejects(
    () => unbound.find((item) => item.name === 'lan_peer_send_file').execute({ peer: '书房', path: SENT_PATH }),
    /file transfer unavailable/,
  );
});
