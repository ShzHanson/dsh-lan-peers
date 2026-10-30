// dsh-lan-peers · v0.8.0-β（DESIGN §18.2）管理接口：归档列表 / 人工删除。
//
// 口径：
//   GET  /api/lan-peers/group/archives → { archives, totalBytes }（hub only）
//   POST /api/lan-peers/group/archives { file, action:"delete" } → { ok, removedBytes }
//   非 hub 403 hub-only；未启用 409；未知 file 404；门面缺 deleteArchive 501 archives-unsupported。
// 归档只归档、不自动删除：接口里没有「自动清理」这条路，删除必须是显式的一步。
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createAdmin } from './admin.mjs';
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

const HOUR = 3600_000;
const CREATED_A = Date.now() - 3 * HOUR;
const ARCHIVES = [
  { file: '101-400.json', fromSeq: 101, toSeq: 400, count: 300, bytes: 12 * 1024 * 1024, createdAt: CREATED_A },
  { file: '1-100.json', fromSeq: 1, toSeq: 100, count: 100, bytes: 9 * 1024 * 1024, createdAt: CREATED_A - HOUR },
];

function makeHubApi({ archives = ARCHIVES, isHub = true, enabled = true, facadeDelete = null, archivesThrows = false } = {}) {
  const calls = [];
  const api = {
    calls,
    enabled,
    isHub,
    state() { return { groupId: 'g-own', name: '家里', members: [], messages: [], lastSeq: 400 }; },
  };
  if (archives !== null) {
    api.archives = async () => {
      calls.push({ method: 'archives' });
      if (archivesThrows) {
        const error = new Error('disk unavailable');
        error.status = 500;
        throw error;
      }
      return { archives };
    };
  }
  api.deleteArchive = async (file) => {
    calls.push({ method: 'deleteArchive', file });
    return facadeDelete === null
      ? { ok: true, removedBytes: 12 * 1024 * 1024 }
      : facadeDelete(file);
  };
  return api;
}

function stubAdmin({ api = null, facade = null, group = { enabled: true, hub: '' }, stateDir = '' } = {}) {
  const lines = [];
  const store = {
    instanceId: 'peer-self',
    stateDir,
    listPeers: () => [],
    getPeer: () => null,
  };
  const admin = createAdmin({
    server: { config: { logger: (line) => lines.push(line), listenPort: 0 }, store, group: facade },
    nameOf: () => 'self-box',
    rename: (n) => n,
    feed: null,
    pairing: { mode: 'auto' },
    group,
    groupApi: api,
  });
  return { admin, lines };
}

const listLine = (lines) => lines.find((line) => line.includes('[admin] group archives'));

// ---------------------------------------------------------------------------
// GET /api/lan-peers/group/archives
// ---------------------------------------------------------------------------

test('GET 归档：hub 返回索引归一后的清单与总体积，日志只记条数与字节', async () => {
  const api = makeHubApi();
  const { admin, lines } = stubAdmin({ api });
  const out = await hit(admin, 'GET', '/api/lan-peers/group/archives');
  assert.equal(out.handled, true);
  assert.equal(out.res.status, 200);
  assert.equal(out.json.archives.length, 2);
  assert.deepEqual(out.json.archives[0], ARCHIVES[0]);
  assert.equal(out.json.totalBytes, 21 * 1024 * 1024, '总体积 = 各归档体积之和');
  const line = listLine(lines);
  assert.match(line, /count=2/);
  assert.match(line, /bytes=22020096/);
  assert.equal(line.includes('101-400.json'), false, '列表日志不写文件名（正文/文件名留给删除日志）');
});

test('GET 归档：脏索引归一（缺 file 丢掉、数字不可解析给 null、createdAt 收 ISO）', async () => {
  const created = '2026-10-30T08:00:00.000Z';
  const api = makeHubApi({
    archives: [
      { file: '  7-9.json ', fromSeq: 7, toSeq: 9, count: '3', bytes: '2048', createdAt: created },
      { fromSeq: 1, toSeq: 2, count: 1, bytes: 10, createdAt: created },
      { file: '', fromSeq: 3, toSeq: 4, count: 1, bytes: 10, createdAt: created },
      { file: 'x.json', fromSeq: 'abc', toSeq: null, count: undefined, bytes: undefined, createdAt: null },
    ],
  });
  const { admin } = stubAdmin({ api });
  const out = await hit(admin, 'GET', '/api/lan-peers/group/archives');
  assert.equal(out.res.status, 200);
  const files = out.json.archives.map((item) => item.file);
  assert.deepEqual(files, ['7-9.json', 'x.json'], '没有文件名的条目丢掉，文件名去空白');
  const first = out.json.archives[0];
  assert.equal(first.count, 3);
  assert.equal(first.bytes, 2048);
  assert.equal(first.createdAt, Date.parse(created), 'ISO 时间归一成毫秒');
  const second = out.json.archives[1];
  assert.equal(second.fromSeq, null);
  assert.equal(second.toSeq, null);
  assert.equal(second.count, null);
  assert.equal(second.bytes, 0, 'bytes 缺失按 0 计（求和不出 NaN）');
  assert.equal(second.createdAt, null);
  assert.equal(out.json.totalBytes, 2048);
});

test('GET 归档：非 hub 403 hub-only，未启用 409 group-disabled', async () => {
  const memberSide = stubAdmin({ api: makeHubApi({ isHub: false }) });
  const forbidden = await hit(memberSide.admin, 'GET', '/api/lan-peers/group/archives');
  assert.equal(forbidden.res.status, 403);
  assert.deepEqual(forbidden.json, { error: 'hub-only' });

  const disabled = stubAdmin({ group: { enabled: false } });
  const off = await hit(disabled.admin, 'GET', '/api/lan-peers/group/archives');
  assert.equal(off.res.status, 409);
  assert.deepEqual(off.json, { error: 'group-disabled' });
});

test('GET 归档：门面没有 archives → 501 archives-unsupported；门面报错 → 502', async () => {
  const unsupported = stubAdmin({ api: makeHubApi({ archives: null }) });
  const missing = await hit(unsupported.admin, 'GET', '/api/lan-peers/group/archives');
  assert.equal(missing.res.status, 501);
  assert.deepEqual(missing.json, { error: 'archives-unsupported' });

  const broken = stubAdmin({ api: makeHubApi({ archivesThrows: true }) });
  const failed = await hit(broken.admin, 'GET', '/api/lan-peers/group/archives');
  assert.equal(failed.res.status, 500, '门面自带 status 时如实透出');
  assert.deepEqual(failed.json, { error: 'disk unavailable' });
});

test('GET 归档：host 门面未接线时退回 group.json 的只读索引（面板先能看见）', async () => {
  const stateDir = makeTempStateDir();
  writeJson0600(path.join(stateDir, 'group.json'), {
    groupId: 'g-own',
    name: '家里',
    archives: [{ file: '1-50.json', fromSeq: 1, toSeq: 50, count: 50, bytes: 1024, createdAt: CREATED_A }],
  });
  // host 门面只有 state()：归档入口还没接线（Lane R 待落地）
  const facade = { enabled: true, state: () => ({ groupId: 'g-own', name: '家里', members: {}, lastSeq: 50 }) };
  const { admin } = stubAdmin({ facade, group: { enabled: true, hub: '' }, stateDir });
  const out = await hit(admin, 'GET', '/api/lan-peers/group/archives');
  assert.equal(out.res.status, 200);
  assert.equal(out.json.archives.length, 1);
  assert.equal(out.json.archives[0].file, '1-50.json');
  assert.equal(out.json.totalBytes, 1024);
  fs.rmSync(stateDir, { recursive: true, force: true });
});

test('GET 归档：host 门面提供 archives() 时以门面为准', async () => {
  const stateDir = makeTempStateDir();
  writeJson0600(path.join(stateDir, 'group.json'), {
    groupId: 'g-own',
    archives: [{ file: 'stale.json', fromSeq: 1, toSeq: 1, count: 1, bytes: 1, createdAt: CREATED_A }],
  });
  const facade = {
    enabled: true,
    state: () => ({ groupId: 'g-own', name: '家里', members: {}, lastSeq: 1 }),
    archives: async () => ({ archives: ARCHIVES }),
  };
  const { admin } = stubAdmin({ facade, group: { enabled: true, hub: '' }, stateDir });
  const out = await hit(admin, 'GET', '/api/lan-peers/group/archives');
  assert.equal(out.res.status, 200);
  assert.deepEqual(out.json.archives.map((item) => item.file), ['101-400.json', '1-100.json']);
  assert.equal(out.json.totalBytes, 21 * 1024 * 1024);
  fs.rmSync(stateDir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// POST /api/lan-peers/group/archives { file, action: "delete" }
// ---------------------------------------------------------------------------

test('POST 删除归档：成功返回 { ok, removedBytes }，日志只记文件名与字节', async () => {
  const api = makeHubApi();
  const { admin, lines } = stubAdmin({ api });
  const out = await hit(admin, 'POST', '/api/lan-peers/group/archives', { file: '101-400.json', action: 'delete' });
  assert.equal(out.res.status, 200);
  assert.deepEqual(out.json, { ok: true, removedBytes: 12 * 1024 * 1024 });
  assert.deepEqual(api.calls.filter((call) => call.method === 'deleteArchive'), [{ method: 'deleteArchive', file: '101-400.json' }]);
  const line = lines.find((item) => item.includes('[admin] group archive delete file='));
  assert.match(line, /file=101-400\.json/);
  assert.match(line, /bytes=12582912/);
});

test('POST 删除归档：门面回 { ok:false, reason:"unknown-archive" } → 404 unknown-archive', async () => {
  const api = makeHubApi({ facadeDelete: () => ({ ok: false, reason: 'unknown-archive' }) });
  const { admin } = stubAdmin({ api });
  const out = await hit(admin, 'POST', '/api/lan-peers/group/archives', { file: 'nope.json', action: 'delete' });
  assert.equal(out.res.status, 404);
  assert.deepEqual(out.json, { error: 'unknown-archive' });
});

test('POST 删除归档：门面抛 404 同样按 unknown-archive 处理；其它失败 502', async () => {
  const api = makeHubApi({
    facadeDelete: (file) => {
      if (file === 'nope.json') {
        const error = new Error('unknown-archive');
        error.status = 404;
        throw error;
      }
      return { ok: false, reason: 'unlink-failed' };
    },
  });
  const { admin } = stubAdmin({ api });
  const gone = await hit(admin, 'POST', '/api/lan-peers/group/archives', { file: 'nope.json', action: 'delete' });
  assert.equal(gone.res.status, 404);
  assert.deepEqual(gone.json, { error: 'unknown-archive' });

  const other = await hit(admin, 'POST', '/api/lan-peers/group/archives', { file: 'locked.json', action: 'delete' });
  assert.equal(other.res.status, 502);
  assert.deepEqual(other.json, { error: 'unlink-failed' });
});

test('POST 删除归档：非 hub 403 hub-only，未启用 409，门面缺 deleteArchive 501', async () => {
  const memberSide = stubAdmin({ api: makeHubApi({ isHub: false }) });
  const forbidden = await hit(memberSide.admin, 'POST', '/api/lan-peers/group/archives', { file: '1.json', action: 'delete' });
  assert.equal(forbidden.res.status, 403);
  assert.deepEqual(forbidden.json, { error: 'hub-only' });

  const disabled = stubAdmin({ group: { enabled: false } });
  const off = await hit(disabled.admin, 'POST', '/api/lan-peers/group/archives', { file: '1.json', action: 'delete' });
  assert.equal(off.res.status, 409);
  assert.deepEqual(off.json, { error: 'group-disabled' });

  const noFacade = makeHubApi();
  delete noFacade.deleteArchive;
  const unsupported = stubAdmin({ api: noFacade });
  const missing = await hit(unsupported.admin, 'POST', '/api/lan-peers/group/archives', { file: '1.json', action: 'delete' });
  assert.equal(missing.res.status, 501);
  assert.deepEqual(missing.json, { error: 'archives-unsupported' });
});

test('POST 删除归档：动作只认 delete，文件名不许带路径成分', async () => {
  const api = makeHubApi();
  const { admin } = stubAdmin({ api });

  const badAction = await hit(admin, 'POST', '/api/lan-peers/group/archives', { file: '1.json', action: 'purge' });
  assert.equal(badAction.res.status, 400);
  assert.deepEqual(badAction.json, { error: 'bad-action' });

  for (const file of ['', '   ', '../group.json', 'sub/1.json', '..']) {
    const badFile = await hit(admin, 'POST', '/api/lan-peers/group/archives', { file, action: 'delete' });
    assert.equal(badFile.res.status, 400, 'file=' + JSON.stringify(file));
    assert.deepEqual(badFile.json, { error: 'bad-file' });
  }
  assert.equal(api.calls.filter((call) => call.method === 'deleteArchive').length, 0, '被拒绝的请求不得打到门面');
});

test('POST 删除归档：host 门面缺 deleteArchive 时如实 501（不假装删掉）', async () => {
  const facade = { enabled: true, state: () => ({ groupId: 'g-own', name: '家里', members: {}, lastSeq: 1 }) };
  const { admin } = stubAdmin({ facade, group: { enabled: true, hub: '' } });
  const out = await hit(admin, 'POST', '/api/lan-peers/group/archives', { file: '1-50.json', action: 'delete' });
  assert.equal(out.res.status, 501);
  assert.deepEqual(out.json, { error: 'archives-unsupported' });
});
