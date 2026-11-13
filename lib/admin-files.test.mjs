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
// 上传通道的口径全部复用 file-store 那一份常量（硬分片上限 / 单文件缺省上限）。
import { FILE_CHUNK_HARD_MAX, FILE_DEFAULT_MAX_BYTES } from './file-store.mjs';

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

function stubAdmin({ files = null, mounted = false, stateDir = '', config = {} } = {}) {
  const lines = [];
  const store = { instanceId: 'peer-self', stateDir, listPeers: () => [], getPeer: () => null };
  // config 覆盖：上传通道要读宿主那两枚真值 —— config.fileMaxBytes（单文件上限）与
  // config.now（与宿主同一枚时钟；U7 用它把假钟往前拨）。
  const server = { config: { logger: (line) => lines.push(line), listenPort: 0, ...config }, store };
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

// ---------------------------------------------------------------------------
// 0.11.0 slice A：浏览器上传通道（init → chunk × N → finish / cancel）
//
// 面板在 sandbox:true 的 webview 里没有原生文件对话框，拿不到文件系统路径；而 send 只认
// 「本机路径」。所以字节先落 <stateDir>/.upload-tmp/<uuid>/，finish 那一刻再把这块临时
// 文件交给门面 send。目录名是 randomUUID()，客户端给的名字只经 file-store 的
// sanitizeFileName() 洗一遍后当文件名 —— 名字绝不参与拼路径。
//
// U9 非空化（拆掉哪一处、哪一条断言就会红）：
//   - 拆掉 finish 的 finally dropUpload → U1「finish 之后临时目录必须消失」与 U3/U6
//     的同一条断言直接红（不是靠「没抛错」撑着的）；
//   - 拆掉 chunk 的 offset !== received 判断 → U2 的 409 / received:8 两条断言红，
//     且 finish 交出去的内容变成 'AAAABBBBAAAABBBB'（U2 末尾那条内容断言也一起红）；
//   - 拆掉 init 的 sanitizeFileName → U4 的 'CON' 与 meta.name 三条断言红；
//   - 拆掉 TTL 清扫 → U7 里被放弃那一路的目录仍存在，chunk 回 200 而不是 404，两条都红。
// ---------------------------------------------------------------------------

const UPLOAD_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
// 上传通道的日志前缀是 '[admin] upload …'（filesLines 只收 '[admin] files …'）。
const uploadLines = (lines) => lines.filter((line) => line.includes('[admin] upload'));
const uploadDirOf = (stateDir, uploadId) => path.join(stateDir, '.upload-tmp', uploadId);
const readUploadMeta = (stateDir, uploadId) => JSON.parse(
  fs.readFileSync(path.join(uploadDirOf(stateDir, uploadId), 'meta.json'), 'utf8'),
);

function uploadStateDir(t) {
  const dir = makeTempStateDir('dsh-lan-peers-upload-');
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

/** 桩门面：取证时机就在 send 被调用那一瞬间（文件还在不在、内容是不是完整的那一份）。 */
function makeUploadFacade({ throwOnSend = false, sendId = 'tx-up-1' } = {}) {
  const calls = [];
  return {
    calls,
    async send(input) {
      let size = -1;
      let body = '';
      let existed = false;
      try {
        existed = fs.existsSync(input.path);
        size = fs.statSync(input.path).size;
        body = fs.readFileSync(input.path, 'utf8');
      } catch {
        existed = false;
      }
      calls.push({ peerId: input.peerId, path: input.path, existed, size, body });
      if (throwOnSend) throw new Error('envelope failed');
      return { ok: true, id: sendId, bytes: size, sha256: SHA_A, ms: 12 };
    },
  };
}

const uploadInit = (admin, name, bytes) => hit(admin, 'POST', '/api/lan-peers/files/upload/init', { name, bytes });
const uploadChunk = (admin, uploadId, offset, slice) => hit(
  admin, 'POST', '/api/lan-peers/files/upload/chunk',
  { uploadId, offset, dataBase64: slice.toString('base64') },
);
const uploadFinish = (admin, uploadId, peerId = 'peer-b') => hit(
  admin, 'POST', '/api/lan-peers/files/upload/finish', { uploadId, peerId },
);

/** 一片一片推上去（默认 7 字节一片：断言里能看出「多片拼起来的顺序」）。 */
async function uploadAll(admin, uploadId, payload, chunk = 7) {
  let offset = 0;
  let last = null;
  while (offset < payload.length) {
    const slice = payload.subarray(offset, Math.min(payload.length, offset + chunk));
    last = await uploadChunk(admin, uploadId, offset, slice);
    assert.equal(last.res.status, 200, '分片 offset=' + offset + ' 必须 200：' + last.res.body);
    offset += slice.length;
  }
  return last;
}

test('U1 init → chunk × N → finish：send 只调一次，调用时文件在、调用后临时目录已消失', async (t) => {
  const stateDir = uploadStateDir(t);
  const facade = makeUploadFacade();
  const { admin, lines } = stubAdmin({ files: facade, stateDir });
  const payload = Buffer.from('ABCDEFGHIJ'.repeat(30));

  const init = await uploadInit(admin, '报告.pdf', payload.length);
  assert.equal(init.res.status, 200);
  assert.match(init.json.uploadId, UPLOAD_ID_RE, '临时目录名只能是 randomUUID()');
  assert.equal(init.json.chunkBytes, FILE_CHUNK_HARD_MAX);
  const uploadId = init.json.uploadId;
  assert.equal(fs.existsSync(path.join(uploadDirOf(stateDir, uploadId), 'meta.json')), true, 'meta 必须落盘');

  const last = await uploadAll(admin, uploadId, payload);
  assert.equal(last.json.received, payload.length);
  assert.equal(last.json.bytes, payload.length);

  const finish = await uploadFinish(admin, uploadId);
  assert.equal(finish.res.status, 200);
  assert.deepEqual(Object.keys(finish.json).sort(), ['bytes', 'id', 'ms', 'ok', 'sha256', 'uploadId'],
    '返回形状与 files/send 一致，只多一枚 uploadId');
  assert.equal(finish.json.uploadId, uploadId);
  assert.equal(finish.json.id, 'tx-up-1');
  assert.equal(finish.json.bytes, payload.length);

  assert.equal(facade.calls.length, 1, 'send 只调一次');
  assert.equal(facade.calls[0].existed, true, 'send 被调用那一瞬间文件必须还在');
  assert.equal(facade.calls[0].peerId, 'peer-b');
  assert.equal(path.basename(facade.calls[0].path), '报告.pdf', '交给 send 的是洗过的原名');
  assert.equal(facade.calls[0].size, payload.length);
  assert.equal(facade.calls[0].body, payload.toString('utf8'), '多片拼装后内容必须一字不差');

  assert.equal(fs.existsSync(uploadDirOf(stateDir, uploadId)), false, 'finish 之后临时目录必须消失');
  const line = uploadLines(lines).find((item) => item.includes('upload finish'));
  assert.match(line, /state=ok/);
  assert.equal(line.includes('报告.pdf'), false, '日志不写文件名');
  assert.equal(line.includes(uploadId), false, '日志只写 id 前 8 位');
});

test('U2 乱序 offset 被稳定码拒绝，且已收的字节一个都不动', async (t) => {
  const stateDir = uploadStateDir(t);
  const facade = makeUploadFacade();
  const { admin, lines } = stubAdmin({ files: facade, stateDir });

  const init = await uploadInit(admin, 'order.txt', 16);
  const uploadId = init.json.uploadId;
  assert.equal((await uploadChunk(admin, uploadId, 0, Buffer.from('AAAABBBB'))).res.status, 200);

  for (const bad of [16, 0, 4]) {
    const out = await uploadChunk(admin, uploadId, bad, Buffer.from('CCCCDDDD'));
    assert.equal(out.res.status, 409, 'offset=' + bad + ' 必须拒收');
    assert.deepEqual(out.json, { error: 'offset-mismatch', received: 8 }, '稳定错误码 + 已收字节数');
  }
  // 负数/非整数 offset 在更前面就被挡下（与「顺序不对」不是同一个错，码也不同）。
  const negative = await uploadChunk(admin, uploadId, -8, Buffer.from('CCCCDDDD'));
  assert.deepEqual(negative.json, { error: 'bad-offset', received: 8 });
  const fractional = await uploadChunk(admin, uploadId, 1.5, Buffer.from('CCCCDDDD'));
  assert.deepEqual(fractional.json, { error: 'bad-offset', received: 8 });
  const dataPath = path.join(uploadDirOf(stateDir, uploadId), 'data');
  assert.equal(fs.statSync(dataPath).size, 8, '被拒的分片一个字节都不能落盘');
  assert.equal(fs.readFileSync(dataPath, 'utf8'), 'AAAABBBB', '已收的那一段原样保留');
  assert.equal(readUploadMeta(stateDir, uploadId).received, 8, 'meta 不能被乱序分片带偏');
  assert.equal(uploadLines(lines).some((item) => item.includes('reason=offset-mismatch')), true);

  assert.equal((await uploadChunk(admin, uploadId, 8, Buffer.from('CCCCDDDD'))).res.status, 200);
  const finish = await uploadFinish(admin, uploadId);
  assert.equal(finish.res.status, 200);
  assert.equal(facade.calls[0].body, 'AAAABBBBCCCCDDDD', '补齐之后内容才是完整的那一份');
});

test('U3 received !== bytes 时 finish 拒收，并删掉临时目录', async (t) => {
  const stateDir = uploadStateDir(t);
  const facade = makeUploadFacade();
  const { admin, lines } = stubAdmin({ files: facade, stateDir });

  const init = await uploadInit(admin, 'half.bin', 10);
  const uploadId = init.json.uploadId;
  assert.equal((await uploadChunk(admin, uploadId, 0, Buffer.from('1234'))).res.status, 200);

  const finish = await uploadFinish(admin, uploadId);
  assert.equal(finish.res.status, 409);
  assert.deepEqual(finish.json, { error: 'incomplete', received: 4 });
  assert.equal(facade.calls.length, 0, '没收齐一律不交给 send');
  assert.equal(fs.existsSync(uploadDirOf(stateDir, uploadId)), false, '拒收也要删临时目录');
  assert.equal(uploadLines(lines).some((item) => item.includes('reason=incomplete')), true);
});

test('U4 文件名走 file-store 那一份清洗：CON 拒收，路径/控制符/超长按同一规则洗', async (t) => {
  const stateDir = uploadStateDir(t);
  const facade = makeUploadFacade();
  const { admin } = stubAdmin({ files: facade, stateDir });

  // Windows 保留设备名：与 send 同一条口径 —— 直接拒收，不悄悄改名。
  const reserved = await uploadInit(admin, 'CON', 3);
  assert.equal(reserved.res.status, 400);
  assert.deepEqual(reserved.json, { error: 'bad-name' });
  assert.equal(fs.existsSync(path.join(stateDir, '.upload-tmp')), false, '拒收不许留目录');
  const reservedDot = await uploadInit(admin, 'con.txt', 3);
  assert.equal(reservedDot.json.error, 'bad-name', '带扩展名的保留名同样拒收');

  // 目录成分被丢掉：../../etc/passwd → passwd（名字只当文件名，路径由本进程拼）。
  const traversal = await uploadInit(admin, '../../etc/passwd', 3);
  assert.equal(traversal.res.status, 200);
  // 临时区结构固定：<uuid>/meta.json + <uuid>/data + <uuid>/out/（成品落 out/ 里，
  // 所以客户端把文件叫 meta.json 也撞不了车）。
  assert.equal(readUploadMeta(stateDir, traversal.json.uploadId).name, 'passwd', '名字只当文件名');
  assert.equal(fs.existsSync(path.join(stateDir, '.upload-tmp', traversal.json.uploadId, 'data')), true);
  assert.equal(fs.existsSync(path.join(stateDir, '.upload-tmp', traversal.json.uploadId, 'out')), true);
  await uploadChunk(admin, traversal.json.uploadId, 0, Buffer.from('abc'));
  const finished = await uploadFinish(admin, traversal.json.uploadId);
  assert.equal(finished.res.status, 200);
  assert.equal(path.basename(facade.calls[0].path), 'passwd', '交给 send 的就是洗过的名字');
  assert.equal(facade.calls[0].path.startsWith(path.join(stateDir, '.upload-tmp')), true,
    '落盘路径只能在本进程的临时区里');

  // 控制符被删掉（不是替换成 _）：re<NUL>port.txt → report.txt
  const control = await uploadInit(admin, 're\u0000port.txt', 3);
  assert.equal(readUploadMeta(stateDir, control.json.uploadId).name, 'report.txt');

  // 超长：躯干截断、扩展名保住、总长 ≤ 128
  const long = await uploadInit(admin, 'x'.repeat(200) + '.txt', 3);
  const longName = readUploadMeta(stateDir, long.json.uploadId).name;
  assert.equal(longName.length, 128);
  assert.equal(longName.endsWith('.txt'), true, '截断只截躯干，扩展名留着');

  // 名字正好等于临时区自己的文件名时也不会串：成品落 out/ 子目录。
  const collide = await uploadInit(admin, 'meta.json', 3);
  assert.equal(readUploadMeta(stateDir, collide.json.uploadId).name, 'meta.json');
  await uploadChunk(admin, collide.json.uploadId, 0, Buffer.from('xxx'));
  const collideFinish = await uploadFinish(admin, collide.json.uploadId);
  assert.equal(collideFinish.res.status, 200);
  assert.equal(path.basename(facade.calls[1].path), 'meta.json', '叫 meta.json 的文件也能发出去');
});

test('U5 超限一律拒收：init 的 bytes 与 chunk 的原始字节数两道闸', async (t) => {
  const stateDir = uploadStateDir(t);
  const facade = makeUploadFacade();
  // 单文件上限读宿主配置（config.fileMaxBytes），测试里钉成 1024。
  const { admin } = stubAdmin({ files: facade, stateDir, config: { fileMaxBytes: 1024 } });

  const tooBig = await uploadInit(admin, 'big.bin', 1025);
  assert.equal(tooBig.res.status, 409);
  assert.deepEqual(tooBig.json, { error: 'too-large', maxBytes: 1024 });

  for (const bad of [0, -5, 1.5, 'abc', null]) {
    const out = await uploadInit(admin, 'bad.bin', bad);
    assert.equal(out.res.status, 400, 'bytes=' + String(bad) + ' 必须是正整数');
    assert.deepEqual(out.json, { error: 'bad-bytes' });
  }

  const ok = await uploadInit(admin, 'ok.bin', 1024);
  assert.equal(ok.res.status, 200, '正好等于上限要收');
  const oversizedChunk = await uploadChunk(admin, ok.json.uploadId, 0, Buffer.alloc(FILE_CHUNK_HARD_MAX + 1, 7));
  assert.equal(oversizedChunk.res.status, 409);
  assert.deepEqual(oversizedChunk.json, { error: 'chunk-too-large', max: FILE_CHUNK_HARD_MAX });
  const overflow = await uploadChunk(admin, ok.json.uploadId, 0, Buffer.alloc(2048, 7));
  assert.equal(overflow.res.status, 409, '整块超过 init 声明的 bytes 也要拒收');
  assert.deepEqual(overflow.json, { error: 'chunk-overflow', received: 0, size: 1024 });

  // 缺省上限（没有 config.fileMaxBytes）回落到 file-store 的 512 MiB。
  const { admin: plain } = stubAdmin({ files: facade, stateDir: uploadStateDir(t) });
  const defaultTooBig = await uploadInit(plain, 'huge.bin', FILE_DEFAULT_MAX_BYTES + 1);
  assert.equal(defaultTooBig.res.status, 409);
  assert.equal(defaultTooBig.json.error, 'too-large');
});

test('U6 facade.send 抛错：错误如实回给调用方，临时目录照样删掉', async (t) => {
  const stateDir = uploadStateDir(t);
  const facade = makeUploadFacade({ throwOnSend: true });
  const { admin, lines } = stubAdmin({ files: facade, stateDir });

  const init = await uploadInit(admin, 'boom.bin', 4);
  const uploadId = init.json.uploadId;
  await uploadAll(admin, uploadId, Buffer.from('wxyz'), 2);

  const finish = await uploadFinish(admin, uploadId);
  assert.equal(finish.res.status, 502);
  assert.deepEqual(finish.json, { error: 'envelope failed' });
  assert.equal(facade.calls.length, 1);
  assert.equal(fs.existsSync(uploadDirOf(stateDir, uploadId)), false, '抛错这条路也必须删临时目录');
  assert.equal(uploadLines(lines).some((item) => item.includes('upload finish') && item.includes('state=error')), true);
});

test('U7 TTL 清扫：放弃的那一路被删掉，活着的那一路不动（假钟）', async (t) => {
  const stateDir = uploadStateDir(t);
  const facade = makeUploadFacade();
  let clock = 1_760_000_000_000;
  const { admin, lines } = stubAdmin({ files: facade, stateDir, config: { now: () => clock } });

  const abandoned = await uploadInit(admin, 'abandoned.txt', 8);
  const abandonedId = abandoned.json.uploadId;
  assert.equal((await uploadChunk(admin, abandonedId, 0, Buffer.from('aabb'))).res.status, 200);
  assert.equal(admin.uploadSweepArmed(), true, 'init 之后清理节拍要点亮');

  // 拨过 TTL：下一次 init 会先扫一遍（同一条 TTL，不是第二套口径）。
  clock += FILE_DEFAULT_MAX_BYTES === 0 ? 0 : 10 * 60 * 1000 + 5_000;
  const live = await uploadInit(admin, 'live.txt', 4);
  const liveId = live.json.uploadId;

  assert.equal(fs.existsSync(uploadDirOf(stateDir, abandonedId)), false, '过期那一路必须被删');
  assert.equal(fs.existsSync(uploadDirOf(stateDir, liveId)), true, '活着那一路不许动');
  assert.equal((await uploadChunk(admin, abandonedId, 2, Buffer.from('cc'))).res.status, 404, '过期后是 unknown-upload');
  assert.equal((await uploadChunk(admin, liveId, 0, Buffer.from('dddd'))).res.status, 200, '活着那一路还能续');

  const sweepLine = uploadLines(lines).find((item) => item.includes('upload sweep'));
  assert.match(sweepLine, /reason=ttl/);
  assert.equal(sweepLine.includes('abandoned'), false, '日志不写文件名');

  // close() 之后定时器必须归零（unref 起来的那一枚，热重载/测试都不许留着）。
  admin.close();
  assert.equal(admin.uploadSweepArmed(), false, 'close() 之后清理节拍必须清掉');
  admin.close();
  assert.equal(admin.uploadSweepArmed(), false, 'close() 幂等');
});

test('U8 四条上传路由同一道门：非 JSON 415、没 token 401；非法 uploadId 不进任何路径', async (t) => {
  const stateDir = uploadStateDir(t);
  const facade = makeUploadFacade();
  const { admin } = stubAdmin({ files: facade, stateDir });
  const init = await uploadInit(admin, 'gate.bin', 8);
  const uploadId = init.json.uploadId;

  const chunkBody = { uploadId, offset: 0, dataBase64: Buffer.from('abcd').toString('base64') };
  const plain = await hit(admin, 'POST', '/api/lan-peers/files/upload/chunk', chunkBody, { contentType: 'text/plain' });
  assert.equal(plain.res.status, 415, '分片只收 JSON（§0.5 不为例外开口子）');
  assert.deepEqual(plain.json, { error: 'content-type-json-required' });
  // 真正落盘要等门禁之后：被 415 拦下的那次没有写进任何字节。
  assert.equal(fs.statSync(path.join(uploadDirOf(stateDir, uploadId), 'data')).size, 0);

  const octet = await hit(admin, 'POST', '/api/lan-peers/files/upload/chunk', chunkBody,
    { contentType: 'application/octet-stream' });
  assert.equal(octet.res.status, 415, 'octet-stream 同样拒收：没有为它开的那条路');

  for (const [pathName, body] of [
    ['/api/lan-peers/files/upload/init', { name: 'a.bin', bytes: 4 }],
    ['/api/lan-peers/files/upload/chunk', chunkBody],
    ['/api/lan-peers/files/upload/finish', { uploadId, peerId: 'peer-b' }],
    ['/api/lan-peers/files/upload/cancel', { uploadId }],
  ]) {
    const out = await hit(admin, 'POST', pathName, body, { token: '' });
    assert.equal(out.res.status, 401, pathName + ' 没有 token 必须 401');
    assert.deepEqual(out.json, { error: 'token-required' });
  }

  // uploadId 是客户端字段：不合法就根本不进 path.join（路径由本进程拼）。
  for (const evil of ['../../etc', '..', uploadId + '/../..', '', 'A'.repeat(36)]) {
    const out = await hit(admin, 'POST', '/api/lan-peers/files/upload/cancel', { uploadId: evil });
    assert.equal(out.res.status, 400, 'uploadId=' + JSON.stringify(evil) + ' 必须 400');
    assert.deepEqual(out.json, { error: 'bad-upload-id' });
  }
  assert.equal(fs.existsSync(uploadDirOf(stateDir, uploadId)), true, '非法 uploadId 碰不到真实目录');

  // cancel 幂等：删掉的那一次 removed=true，再来一次 removed=false 仍然是 200。
  const first = await hit(admin, 'POST', '/api/lan-peers/files/upload/cancel', { uploadId });
  assert.deepEqual(first.json, { ok: true, uploadId, removed: true });
  assert.equal(fs.existsSync(uploadDirOf(stateDir, uploadId)), false);
  const second = await hit(admin, 'POST', '/api/lan-peers/files/upload/cancel', { uploadId });
  assert.equal(second.res.status, 200);
  assert.deepEqual(second.json, { ok: true, uploadId, removed: false });
});

// ---------------------------------------------------------------------------
// 0.11.0 slice B（G1 / G2 / G3）：面板要能「先问进度再续传」，而一次网络抖动
// 重发的同一片不许毒掉快路径。
//
// B 组非空化（拆掉哪一处、哪一条断言就会红）：
//   - 拆掉 G1（GET files/upload）→ B1 三条断言直接 404/400，面板的「重试=续传」也就
//     只能从 0 重来（panel-files 的 V3 后半段同时红）；
//   - 拆掉 G2（init 回显 maxBytes）→ B2 的 maxBytes:4096 与 state.fileMaxBytes 两条红；
//   - 拆掉 G3 的 uploadTailMatches 分支 → B3 第一条（重放回 200）变 409，且日志里没有
//     state=replay；反过来把「字节必须相同」放宽成「offset<received 就 200」→ B3 里
//     「同位置不同字节仍 409」那条红。
// ---------------------------------------------------------------------------

const MISSING_UPLOAD_ID = '00000000-0000-4000-8000-000000000000';

test('B1 GET files/upload?id=：回活计数器（G1），未知 id 404，非法 id 400，成功不写日志', async (t) => {
  const stateDir = uploadStateDir(t);
  const { admin, lines } = stubAdmin({ files: makeUploadFacade(), stateDir });
  const init = await uploadInit(admin, 'resume.bin', 8);
  const uploadId = init.json.uploadId;
  assert.equal((await uploadChunk(admin, uploadId, 0, Buffer.from('abcd'))).res.status, 200);

  const before = uploadLines(lines).length;
  const info = await hit(admin, 'GET', '/api/lan-peers/files/upload?id=' + uploadId);
  assert.equal(info.res.status, 200);
  // 面板要的就是这五格：续传从 received 起，chunkBytes 决定下一片多大。
  assert.deepEqual(info.json, {
    uploadId,
    name: 'resume.bin',
    bytes: 8,
    received: 4,
    chunkBytes: FILE_CHUNK_HARD_MAX,
  });
  assert.equal(uploadLines(lines).length, before, '常规轮询不许写日志（写一次就淹掉日志）');

  const unknown = await hit(admin, 'GET', '/api/lan-peers/files/upload?id=' + MISSING_UPLOAD_ID);
  assert.equal(unknown.res.status, 404, '未知 uploadId 必须 404，不能回 200 + 全 0（那会让面板从 0 重传）');
  assert.deepEqual(unknown.json, { error: 'unknown-upload' });

  const bad = await hit(admin, 'GET', '/api/lan-peers/files/upload?id=../../etc');
  assert.equal(bad.res.status, 400);
  assert.deepEqual(bad.json, { error: 'bad-upload-id' });
  const none = await hit(admin, 'GET', '/api/lan-peers/files/upload');
  assert.equal(none.res.status, 400);

  // 续传之后照常收尾：G1 只是问进度，不改任何状态。
  assert.equal((await uploadChunk(admin, uploadId, 4, Buffer.from('efgh'))).res.status, 200);
  assert.equal((await hit(admin, 'GET', '/api/lan-peers/files/upload?id=' + uploadId)).json.received, 8);
  assert.equal((await uploadFinish(admin, uploadId)).res.status, 200);
  assert.equal((await hit(admin, 'GET', '/api/lan-peers/files/upload?id=' + uploadId)).res.status, 404,
    'finish 之后临时区没了，G1 也该 404');
});

test('B2 init 回显 maxBytes（G2）：与 config.fileMaxBytes 同一枚，超限 409 也带它，state 也报同一枚', async (t) => {
  const stateDir = uploadStateDir(t);
  const { admin } = stubAdmin({ files: makeUploadFacade(), stateDir, config: { fileMaxBytes: 4096 } });
  const init = await uploadInit(admin, 'a.bin', 4096);
  assert.equal(init.res.status, 200);
  assert.equal(init.json.maxBytes, 4096, 'inclusive 边界：正好等于上限要过');
  assert.equal(init.json.chunkBytes, FILE_CHUNK_HARD_MAX);

  const big = await uploadInit(admin, 'b.bin', 4097);
  assert.equal(big.res.status, 409);
  assert.deepEqual(big.json, { error: 'too-large', maxBytes: 4096 });

  // 面板要在**发 init 之前**就拦住超限文件：所以上限也从 state 报一次。
  const state = await hit(admin, 'GET', '/api/lan-peers/state');
  assert.equal(state.res.status, 200);
  assert.equal(state.json.fileMaxBytes, 4096);

  // 没配 fileMaxBytes 的宿主：回落到 file-store 的缺省值（同一份口径，不另写一套）。
  const plain = stubAdmin({ files: makeUploadFacade(), stateDir: uploadStateDir(t) });
  assert.equal((await uploadInit(plain.admin, 'c.bin', 16)).json.maxBytes, FILE_DEFAULT_MAX_BYTES);
});

test('B3 重发的同一片回 200 且不重复落盘（G3）；字节不同仍 409；向前有空洞仍 409', async (t) => {
  const stateDir = uploadStateDir(t);
  const { admin, lines } = stubAdmin({ files: makeUploadFacade(), stateDir });
  const init = await uploadInit(admin, 'replay.bin', 16);
  const uploadId = init.json.uploadId;
  const first = Buffer.from('AAAABBBB');
  const second = Buffer.from('CCCCDDDD');
  assert.equal((await uploadChunk(admin, uploadId, 0, first)).res.status, 200);
  assert.equal((await uploadChunk(admin, uploadId, 8, second)).res.status, 200);

  // 同一片重发两次：200 + received 原地不动（幂等重放）。
  for (const [offset, slice] of [[0, first], [8, second], [0, first]]) {
    const replay = await uploadChunk(admin, uploadId, offset, slice);
    assert.equal(replay.res.status, 200, 'offset=' + offset + ' 的重放必须 200：' + replay.res.body);
    assert.equal(replay.json.received, 16, '重放不许推进 received');
    assert.equal(replay.json.replay, true);
  }
  const dataPath = path.join(uploadDirOf(stateDir, uploadId), 'data');
  assert.equal(fs.statSync(dataPath).size, 16, '重放绝不能把字节再追加一份（16 而不是 32）');
  assert.equal(fs.readFileSync(dataPath).toString(), 'AAAABBBBCCCCDDDD');
  assert.equal(readUploadMeta(stateDir, uploadId).received, 16);
  assert.ok(uploadLines(lines).some((item) => item.includes('state=replay')), '重放要留一行可解释的日志');

  // 同一位置但字节不同：这不是重放，是坏片 —— 仍然 409。
  const wrong = await uploadChunk(admin, uploadId, 0, Buffer.from('XXXXBBBB'));
  assert.equal(wrong.res.status, 409);
  assert.deepEqual(wrong.json, { error: 'offset-mismatch', received: 16 });

  // 部分重叠（前半截在盘上、后半截是新的）：不做「截断重写」，仍然 409。
  const partial = await uploadChunk(admin, uploadId, 12, Buffer.from('DDDDEEEE'));
  assert.equal(partial.res.status, 409);
  assert.equal(partial.json.received, 16);

  // offset > received：前面有空洞，重发也救不回来 —— 409 不带 replay。
  const gap = await uploadChunk(admin, uploadId, 24, Buffer.from('EEEE'));
  assert.equal(gap.res.status, 409);
  assert.equal(gap.json.replay, undefined);
  assert.equal(fs.statSync(dataPath).size, 16, '被拒的分片一个字节都没写');

  // 收尾仍然交出一份完整的文件（重放没有把内容搞坏）。
  const finish = await uploadFinish(admin, uploadId);
  assert.equal(finish.res.status, 200);
});


