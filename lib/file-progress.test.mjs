// dsh-lan-peers · v0.8.5-α 两个进度显示：接收侧 incoming 桶 + 出站 outbound 表。
//
// 这里钉死六件事：
//   1. files.list() 多出 state:'incoming' 的条目，received 取 .part 的**实际**字节数；
//   2. incoming 与 pending/done 互不混桶（accept/reject 的语义不能被它污染）；
//   3. GET /files 回三个桶，GET /files/outbound 回数组且**不含 path**；
//   4. 出站表不可用时不影响任何既有返回（501 也要能优雅降级）；
//   5. 词表 zh/en 两份都补齐；
//   6. CLI：inbox list 多一行「接收中」，send-file 在能查到出站表时打印「已发 X/Y」，
//      查不到时与以前逐字一致（已用 Ns + 最终发送行）。
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { listenOnRandomPort } from '../test-support/ports.mjs';
import { FileStore } from './file-store.mjs';
import { createAdmin } from './admin.mjs';
import { keys, t } from './i18n.mjs';
import { makeTempStateDir, writeJson0600 } from '../host/test/helpers.mjs';

process.env.DSH_LAN_PEERS_LANG = 'zh';   // CLI 断言写的是中文文案，钉死语言

const SHA = 'a'.repeat(64);
const cliPath = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'client', 'cli.mjs');
const TOKEN = 'file-progress-token';

// ---------------------------------------------------------------------------
// 1) FileStore.list() 的 incoming 桶
// ---------------------------------------------------------------------------

function makeStore() {
  return new FileStore({ stateDir: makeTempStateDir('lanb-files-progress-') });
}

test('files.list() 的 incoming：received 取 .part 的实际字节数，形状齐全', () => {
  const store = makeStore();
  const part = store.createPart({
    name: 'big.bin',
    size: 5 * 1024 * 1024,
    sha256: SHA,
    from: { peerId: 'peer-a', name: '书房' },
  });
  fs.appendFileSync(part.path, Buffer.alloc(2 * 1024 * 1024, 7));

  const rows = store.list();
  const incoming = rows.filter((row) => row.state === 'incoming');
  assert.equal(incoming.length, 1, '传输中的条目必须出现在 list() 里');
  const row = incoming[0];
  assert.equal(row.id, part.id);
  assert.equal(row.name, 'big.bin');
  assert.equal(row.size, 5 * 1024 * 1024);
  assert.equal(row.received, 2 * 1024 * 1024, 'received 必须是 .part 现在的实际大小');
  assert.deepEqual(row.from, { peerId: 'peer-a', name: '书房' });
  assert.equal(typeof row.at, 'number');

  // 再涨一点：list() 每次现算，不吃缓存
  fs.appendFileSync(part.path, Buffer.alloc(1024 * 1024, 7));
  assert.equal(store.list().find((item) => item.state === 'incoming').received, 3 * 1024 * 1024);
});

test('incoming 与 pending/done 互不混桶：三个桶各自为空时都为空', () => {
  const store = makeStore();
  assert.deepEqual(store.list(), [], '空 store 的 list() 仍是空数组');
  const part = store.createPart({ name: 'x.bin', size: 10, sha256: 'b'.repeat(64), from: {} });
  fs.appendFileSync(part.path, Buffer.alloc(4));
  const rows = store.list();
  assert.equal(rows.filter((row) => row.state === 'incoming').length, 1);
  assert.equal(rows.filter((row) => row.state === 'pending').length, 0, '传输中不许算 pending');
  assert.equal(rows.filter((row) => row.state === 'done').length, 0, '传输中不许算 done');

  // 传输中从盘上消失（对端中止/清理）后，list() 不再回它
  fs.rmSync(part.path, { force: true });
  store.parts.delete('b'.repeat(64));
  assert.deepEqual(store.list(), []);
});

// ---------------------------------------------------------------------------
// 2) 管理接口：GET /files 的第三个桶 + GET /files/outbound
// ---------------------------------------------------------------------------

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

function makeRequest(method, apiPath, token) {
  const headers = { host: '127.0.0.1:7788', 'content-length': '0' };
  if (token) headers['x-lan-peers-token'] = token;
  const req = {
    method,
    url: apiPath,
    socket: { remoteAddress: '127.0.0.1', setNoDelay() {} },
    headers,
    on() { return req; },
    once() { return req; },
    async *[Symbol.asyncIterator]() {},
  };
  return req;
}

function bootAdmin(files) {
  const lines = [];
  const store = { instanceId: 'peer-self', stateDir: makeTempStateDir('lanb-files-admin-'), listPeers: () => [], getPeer: () => null };
  const admin = createAdmin({
    server: { config: { logger: (line) => lines.push(line), listenPort: 0 }, store },
    nameOf: () => 'self-box',
    rename: (n) => n,
    files,
  });
  return { admin, lines };
}

async function hit(admin, method, apiPath, token) {
  const res = makeResponse();
  const handled = await admin.handle(makeRequest(method, apiPath, token), res, new URL('http://127.0.0.1' + apiPath));
  assert.equal(handled, true, apiPath + ' 必须由 admin 接管');
  let json = null;
  try { json = JSON.parse(res.body); } catch { json = null; }
  return { status: res.status, json, raw: res.body };
}

test('GET /files 回三个桶：incoming 独立、带 received，且响应体不含 path', async () => {
  const files = {
    list: async () => [
      { id: 'p-end-1', name: 'pending.bin', size: 10, sha256: SHA, from: { peerId: 'a', name: 'A' }, at: 1, state: 'pending' },
      { id: 'd-one-01', name: 'done.bin', size: 20, sha256: SHA, from: { peerId: 'a', name: 'A' }, at: 2, state: 'done' },
      { id: 'i-nc-0001', name: 'big.bin', size: 1000, received: 250, sha256: SHA, from: { peerId: 'a', name: 'A' }, at: 3, state: 'incoming' },
      { id: 'r-ej-0001', name: 'rejected.bin', size: 30, sha256: SHA, from: { peerId: 'a', name: 'A' }, at: 4, state: 'rejected' },
    ],
  };
  const { admin } = bootAdmin(files);
  const out = await hit(admin, 'GET', '/api/lan-peers/files', admin.token);

  assert.equal(out.status, 200);
  assert.deepEqual(out.json.pending.map((row) => row.id), ['p-end-1'], 'pending 桶只装 pending');
  assert.deepEqual(out.json.inbox.map((row) => row.id), ['d-one-01'], 'inbox 桶只装 done');
  assert.deepEqual(out.json.incoming.map((row) => row.id), ['i-nc-0001'], 'incoming 自成第三桶');
  assert.equal(out.json.incoming[0].received, 250, 'received 必须透出来');
  assert.equal(out.json.incoming[0].state, 'incoming');
  assert.equal(out.raw.includes('rejected.bin'), false, '已拒收仍和以前一样不露面');
  assert.equal(out.raw.includes('"path"'), false, '响应体绝不含 path');
});

test('GET /files/outbound：数组 + 固定字段，无 path；没有出站能力时 501', async () => {
  const files = {
    list: async () => [],
    outbound: async () => [
      { transferId: 'tx-1', peerId: 'peer-b-1234', name: 'big.bin', size: 5_242_880, sent: 1_048_576, path: 'D:/secret/big.bin' },
    ],
  };
  const { admin } = bootAdmin(files);
  const out = await hit(admin, 'GET', '/api/lan-peers/files/outbound', admin.token);

  assert.equal(out.status, 200);
  assert.equal(Array.isArray(out.json), true, '回的就是数组');
  assert.deepEqual(out.json, [{ transferId: 'tx-1', peerId: 'peer-b-1234', name: 'big.bin', size: 5_242_880, sent: 1_048_576 }],
    '只透出五个字段，path 被丢掉');
  assert.equal(out.raw.includes('secret'), false, '文件路径绝不能出现在响应里');

  const bare = bootAdmin({ list: async () => [] });
  const unsupported = await hit(bare.admin, 'GET', '/api/lan-peers/files/outbound', bare.admin.token);
  assert.equal(unsupported.status, 501, '门面没挂 outbound 就如实说 501');
  assert.equal(unsupported.json.error, 'files-unsupported');
});

test('GET /files/outbound 仍需 token（与 files 同一道门禁）', async () => {
  const { admin } = bootAdmin({ list: async () => [], outbound: async () => [] });
  const denied = await hit(admin, 'GET', '/api/lan-peers/files/outbound');
  assert.equal(denied.status, 401);
  assert.equal(denied.json.error, 'token-required');
});

// ---------------------------------------------------------------------------
// 3) 词表
// ---------------------------------------------------------------------------

test('词表 zh/en 两份都补齐：panel.files.incoming 与 cli.inbox.incomingLine', () => {
  const zhKeys = new Set(keys('zh'));
  const enKeys = new Set(keys('en'));
  for (const key of ['panel.files.incoming', 'cli.inbox.incomingLine']) {
    assert.ok(zhKeys.has(key), 'zh 缺 ' + key);
    assert.ok(enKeys.has(key), 'en 缺 ' + key);
    assert.doesNotMatch(String(t('en', key)), /[\u4e00-\u9fa5]/, 'en 文案不许有中文：' + key);
  }
  assert.match(t('zh', 'panel.files.incoming'), /\{received\}.*\{size\}.*\{pct\}/, '占位符要齐');
  assert.match(t('en', 'panel.files.incoming'), /\{received\}.*\{size\}.*\{pct\}/, '占位符要齐');
  assert.match(t('zh', 'cli.inbox.incomingLine'), /\{id\}.*\{name\}.*\{received\}.*\{size\}/, '占位符要齐');
});

// ---------------------------------------------------------------------------
// 4) CLI：inbox list 的接收中一行；send-file 的出站字节进度（能查就显示、查不到就降级）
// ---------------------------------------------------------------------------

function runAsync(args, env = {}) {
  return new Promise((resolve) => {
    execFile(process.execPath, [cliPath, ...args], { encoding: 'utf8', env: { ...process.env, ...env } },
      (error, stdout, stderr) => resolve({ status: error ? error.code : 0, stdout, stderr }));
  });
}

async function startAdmin(t, handler) {
  const seen = [];
  const server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (chunk) => { raw += chunk; });
    req.on('end', () => {
      const call = {
        method: req.method,
        url: req.url,
        token: req.headers['x-lan-peers-token'] ?? '',
        body: raw === '' ? null : JSON.parse(raw),
      };
      seen.push(call);
      const reply = handler(call) ?? {};
      const send = () => {
        res.writeHead(reply.status ?? 200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(reply.body ?? {}));
      };
      if (reply.delayMs) setTimeout(send, reply.delayMs);
      else send();
    });
  });
  const { port } = await listenOnRandomPort(server);
  t.after(() => new Promise((resolve) => { server.close(() => resolve()); }));

  const dir = makeTempStateDir('dsh-lan-peers-file-progress-');
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  writeJson0600(path.join(dir, 'peers.json'), {
    peers: { 'peer-b-1234': { name: '书房', baseUrl: 'http://10.0.0.2:7788', secret: 's', inboundSecret: 'i' } },
  });
  fs.writeFileSync(path.join(dir, 'admin-token'), TOKEN + '\n', { mode: 0o600 });
  const file = path.join(dir, 'payload.bin');
  fs.writeFileSync(file, Buffer.alloc(4096, 7));
  return { seen, url: 'http://127.0.0.1:' + port, dir, file };
}

test('CLI inbox list：多一行「接收中 <id前8> <name> <received>/<size>」，摘要行不变', async (t) => {
  const admin = await startAdmin(t, () => ({
    body: {
      pending: [],
      inbox: [],
      incoming: [{ id: 'i-nc-0001abcdef', name: 'big.bin', size: 5_242_880, received: 1_048_576, from: { peerId: 'p', name: 'A' }, at: 1, state: 'incoming' }],
    },
  }));
  const out = await runAsync(['inbox', 'list', '--url', admin.url, '--state-dir', admin.dir]);
  assert.equal(out.status, 0, out.stderr);
  assert.equal(out.stdout.trim(), '接收中 i-nc-000 big.bin 1048576/5242880', 'id 只留前 8 位，其余原样');
  assert.match(out.stderr, /待确认 0 个 · 已收 0 个/, '摘要行口径不变');
});

test('CLI send-file：能查到出站表就把「已用 Ns」升级成「已发 X/Y 字节（Z%）」', async (t) => {
  const files = await startAdmin(t, (call) => {
    if (call.url.startsWith('/api/lan-peers/files/outbound')) {
      return { body: [{ transferId: 'tx-live', peerId: 'peer-b-1234', name: 'payload.bin', size: 4096, sent: 2048 }] };
    }
    return { body: { ok: true, id: 'tx-live', bytes: 4096, sha256: SHA, ms: 1500 }, delayMs: 1500 };
  });
  const out = await runAsync(['send-file', '书房', files.file, '--url', files.url, '--state-dir', files.dir],
    { DSH_LAN_PEERS_PROGRESS: '1' });

  assert.equal(out.status, 0, out.stderr);
  assert.match(out.stderr, /已发 2048\/4096 字节（50%）/, '出站表给出的 sent/size 直接上屏');
  assert.equal(out.stdout.trim(), '已发送 id=tx-live bytes=4096 sha256=' + SHA + ' ms=1500', '最终一行不变');
  assert.ok(files.seen.some((call) => call.url.startsWith('/api/lan-peers/files/outbound')), 'send 期间真的轮询了出站表');
});

test('CLI send-file：出站表不可用（501）时静默降级，输出与以前逐字一致', async (t) => {
  const files = await startAdmin(t, (call) => (call.url.startsWith('/api/lan-peers/files/outbound')
    ? { status: 501, body: { error: 'files-unsupported' } }
    : { body: { ok: true, id: 'tx-legacy', bytes: 4096, sha256: SHA, ms: 700 }, delayMs: 700 }));
  const out = await runAsync(['send-file', '书房', files.file, '--url', files.url, '--state-dir', files.dir],
    { DSH_LAN_PEERS_PROGRESS: '1' });

  assert.equal(out.status, 0, out.stderr);
  assert.match(out.stderr, /已用 \d+s/, '拿不到出站表就退回已用时长');
  assert.equal(/已发 /.test(out.stderr), false, '不许画出假的字节进度');
  assert.equal(out.stdout.trim(), '已发送 id=tx-legacy bytes=4096 sha256=' + SHA + ' ms=700');
  assert.equal(/文件操作失败/.test(out.stderr), false, '进度失败不外溢成命令失败');
});
