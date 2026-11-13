// dsh-lan-peers · 0.12.0-alpha S1：**下载路径**上的两个进度显示（incoming 桶 + 三桶视图）。
//
// 单发 offer/pull 之后，「进度」只剩一件事可看：对方来拉的时候本机收到多少字节。
// 本文件钉死这些：
//   1. files.list() 里的 state:'incoming'，received 取 .part 的**实际**字节数；
//   2. incoming 与 offers/done 互不混桶（报价没有「已收下」这件事，不能算进 inbox）；
//   3. GET /files 回 { offers, inbox, incoming } 三个桶，响应体不含 path；
//   4. 下载进行中：GET /files/progress 读到同一份已收字节，落盘后转 done；
//   5. 词表 zh/en 两份都补齐（含新的摘要行与 offer 行）；
//   6. CLI：inbox list 三桶 + 新的摘要行；send-file 在 offer 阶段只滚「已用 Ns」，
//      最终一行是「已挂出待下载」（本机字节根本没动，不许画字节进度）。
//
// 删除的一例（明知而删，理由写在文末）：「CLI send-file 能查到出站表就把已用时长升级成
// 「已发 X/Y 字节」」—— 推送模型才有出站字节表，现在门面的 outbound() 恒回空数组。
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
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
const sha256 = (buffer) => createHash('sha256').update(buffer).digest('hex');
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
  assert.equal(incoming.length, 1, '拉取中的条目必须出现在 list() 里');
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

test('incoming 与 offers/done 互不混桶：三个桶各自为空时都为空', () => {
  const store = makeStore();
  assert.deepEqual(store.list(), [], '空 store 的 list() 仍是空数组');
  const part = store.createPart({ name: 'x.bin', size: 10, sha256: 'b'.repeat(64), from: {} });
  fs.appendFileSync(part.path, Buffer.alloc(4));
  const rows = store.list();
  assert.equal(rows.filter((row) => row.state === 'incoming').length, 1);
  assert.equal(rows.filter((row) => row.state === 'offer').length, 0, '拉取中不许算成待下载');
  assert.equal(rows.filter((row) => row.state === 'done').length, 0, '拉取中不许算 done');

  // 拉取中从盘上消失（对端中止/清理）后，list() 不再回它
  fs.rmSync(part.path, { force: true });
  store.parts.delete('b'.repeat(64));
  assert.deepEqual(store.list(), []);
});

// ---------------------------------------------------------------------------
// 2) 管理接口：GET /files 的三个桶 + GET /files/progress 的下载进度
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

test('GET /files 回三个桶：待下载（offer）/ 已收（done）/ 传输中（incoming），且响应体不含 path', async () => {
  const files = {
    list: async () => [
      { id: 'o-ff-0001', name: 'offered.bin', size: 1000, sha256: SHA, from: { peerId: 'a', name: 'A' }, at: 1, state: 'offer', trusted: true },
      { id: 'd-one-01', name: 'done.bin', size: 20, sha256: SHA, from: { peerId: 'a', name: 'A' }, at: 2, state: 'done' },
      { id: 'i-nc-0001', name: 'big.bin', size: 1000, received: 250, sha256: SHA, from: { peerId: 'a', name: 'A' }, at: 3, state: 'incoming' },
      { id: 'r-ej-0001', name: 'rejected.bin', size: 30, sha256: SHA, from: { peerId: 'a', name: 'A' }, at: 4, state: 'rejected' },
    ],
  };
  const { admin } = bootAdmin(files);
  const out = await hit(admin, 'GET', '/api/lan-peers/files', admin.token);

  assert.equal(out.status, 200);
  assert.deepEqual(out.json.offers.map((row) => row.id), ['o-ff-0001'], 'offers 桶只装待下载');
  assert.equal(out.json.offers[0].trusted, true, '信任标记必须透出来（面板据此决定要不要问一句）');
  assert.deepEqual(out.json.inbox.map((row) => row.id), ['d-one-01'], 'inbox 桶只装 done：待下载没有「已收下」这件事');
  assert.deepEqual(out.json.incoming.map((row) => row.id), ['i-nc-0001'], 'incoming 自成第三桶');
  assert.equal(out.json.incoming[0].received, 250, 'received 必须透出来');
  assert.equal(out.json.incoming[0].state, 'incoming');
  assert.equal(out.json.offers.length + out.json.inbox.length + out.json.incoming.length, 3, '一条只在其中一个桶里');
  assert.equal(out.raw.includes('rejected.bin'), false, '已拒收仍和以前一样不露面');
  assert.equal(out.raw.includes('"path"'), false, '响应体绝不含 path');
});

test('下载进行中：incoming 桶带真实 received，GET /files/progress 读到同一份字节，落盘后转 done', async (t) => {
  const stateDir = makeTempStateDir('lanb-files-pulling-');
  t.after(() => fs.rmSync(stateDir, { recursive: true, force: true }));
  const store = new FileStore({ stateDir, chunkBytes: 1024 });
  const body = Buffer.alloc(4096, 9);
  const digest = sha256(body);
  // 真实 FileStore 挂成门面：这两个接口读的就是下载路径自己写的那份状态
  const { admin } = bootAdmin({ list: () => store.list(), progress: (id) => store.progress(id) });

  const opened = store.offer({
    transferId: 'tx-pull',
    name: 'pull.bin',
    size: body.length,
    sha256: digest,
    from: { peerId: 'peer-a', name: '书房' },
  });
  assert.deepEqual(opened, { accept: true, resumeFrom: 0, dedupe: false });
  assert.deepEqual(store.writeChunk({ transferId: 'tx-pull', offset: 0, data: body.subarray(0, 1024) }), { received: 1024 });

  const running = await hit(admin, 'GET', '/api/lan-peers/files', admin.token);
  assert.deepEqual(running.json.offers, [], '还没下载过的报价不该出现在这里');
  assert.deepEqual(running.json.incoming.map((row) => row.received), [1024], '拉取中：incoming 带已收字节');
  assert.deepEqual(running.json.inbox, [], '拉取中不算已收');

  const partId = running.json.incoming[0].id;
  const mid = await hit(admin, 'GET', '/api/lan-peers/files/progress?id=' + partId, admin.token);
  assert.equal(mid.status, 200);
  assert.deepEqual(mid.json, { received: 1024, size: 4096, state: 'incoming' });

  // 再拉一块：同一份状态跟着涨（路径与面板轮询的是同一条）
  assert.deepEqual(store.writeChunk({ transferId: 'tx-pull', offset: 1024, data: body.subarray(1024) }), { received: 4096 });
  const grown = await hit(admin, 'GET', '/api/lan-peers/files/progress?id=' + partId, admin.token);
  assert.deepEqual(grown.json, { received: 4096, size: 4096, state: 'incoming' });

  // 拉完 + 落盘：进度转 done，incoming 桶空出来
  const completed = await store.complete({ transferId: 'tx-pull' });
  assert.equal(completed.needConfirm, true);
  const pending = await hit(admin, 'GET', '/api/lan-peers/files/progress?id=' + partId, admin.token);
  assert.deepEqual(pending.json, { received: 4096, size: 4096, state: 'pending' });
  assert.equal(store.accept(partId).ok, true);
  const done = await hit(admin, 'GET', '/api/lan-peers/files/progress?id=' + partId, admin.token);
  assert.deepEqual(done.json, { received: 4096, size: 4096, state: 'done' });
  const settled = await hit(admin, 'GET', '/api/lan-peers/files', admin.token);
  assert.deepEqual(settled.json.incoming, [], '落盘之后不再算传输中');
  assert.deepEqual(settled.json.inbox.map((row) => row.id), [partId]);

  // 未知 id 仍然 404（下载路径没给它造出「假进度」）
  const unknown = await hit(admin, 'GET', '/api/lan-peers/files/progress?id=not-a-real-id', admin.token);
  assert.equal(unknown.status, 404);
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

test('词表 zh/en 两份都补齐：incoming 行、offer 行、新的摘要行', () => {
  const zhKeys = new Set(keys('zh'));
  const enKeys = new Set(keys('en'));
  for (const key of [
    'panel.files.incoming',
    'cli.inbox.incomingLine',
    'cli.inbox.tagOffer',
    'cli.inbox.tagOfferTrusted',
    'cli.inbox.summary',
    'cli.file.offered',
  ]) {
    assert.ok(zhKeys.has(key), 'zh 缺 ' + key);
    assert.ok(enKeys.has(key), 'en 缺 ' + key);
    assert.doesNotMatch(String(t('en', key)), /[\u4e00-\u9fa5]/, 'en 文案不许有中文：' + key);
  }
  assert.match(t('zh', 'panel.files.incoming'), /\{received\}.*\{size\}.*\{pct\}/, '占位符要齐');
  assert.match(t('en', 'panel.files.incoming'), /\{received\}.*\{size\}.*\{pct\}/, '占位符要齐');
  assert.match(t('zh', 'cli.inbox.incomingLine'), /\{id\}.*\{name\}.*\{received\}.*\{size\}/, '占位符要齐');
  // 摘要行口径换了：以前是「待确认 / 已收」，现在是「待下载 / 已收」
  assert.match(t('zh', 'cli.inbox.summary'), /\{offers\}.*\{inbox\}/, '占位符要齐');
  assert.match(t('en', 'cli.inbox.summary'), /\{offers\}.*\{inbox\}/, '占位符要齐');
  assert.match(t('zh', 'cli.file.offered'), /\{id\}.*\{bytes\}.*\{sha256\}.*\{ms\}/, '占位符要齐');
});

// ---------------------------------------------------------------------------
// 4) CLI：inbox list 的三桶 + 摘要行；send-file 在 offer 阶段只滚已用时长
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

test('CLI inbox list：待下载（含信任标记）+ 已收 + 传输中三桶，摘要行是「待下载 / 已收」', async (t) => {
  const admin = await startAdmin(t, () => ({
    body: {
      offers: [
        { id: 'o-ff-0001abcdef', name: 'offered.bin', size: 10, sha256: SHA, from: { peerId: 'p', name: '书房' }, at: 1, state: 'offer', trusted: true },
        { id: 'o-ff-0002abcdef', name: 'plain.bin', size: 20, sha256: SHA, from: { peerId: 'p', name: '书房' }, at: 2, state: 'offer', trusted: false },
      ],
      inbox: [
        { id: 'd-one-01abcdef', name: 'done.bin', size: 30, sha256: SHA, from: { peerId: 'p', name: '书房' }, at: 3, state: 'done' },
      ],
      incoming: [{ id: 'i-nc-0001abcdef', name: 'big.bin', size: 5_242_880, received: 1_048_576, from: { peerId: 'p', name: 'A' }, at: 4, state: 'incoming' }],
    },
  }));
  const out = await runAsync(['inbox', 'list', '--url', admin.url, '--state-dir', admin.dir]);
  assert.equal(out.status, 0, out.stderr);

  const lines = out.stdout.trim().split('\n');
  assert.equal(lines.length, 4, '待下载 2 + 已收 1 + 传输中 1');
  assert.match(lines[0], /^待下载\(信任\)\to-ff-0001abcdef\toffered\.bin\t10B\tsha256 a{64}\tfrom 书房\t/, lines[0]);
  assert.match(lines[1], /^待下载\to-ff-0002abcdef\tplain\.bin\t20B\t/, lines[1] + '：没信任过的不带标记');
  assert.match(lines[2], /^已收\td-one-01abcdef\tdone\.bin\t30B\t/, lines[2]);
  assert.equal(lines[3], '接收中 i-nc-000 big.bin 1048576/5242880', 'id 只留前 8 位，其余原样');
  assert.equal(out.stderr.trim(), '待下载 2 个 · 已收 1 个', '摘要行＝待下载/已收（不再是待确认）');
});

test('CLI send-file：offer 阶段只滚「已用 Ns」，最终一行是「已挂出待下载」（本机字节没动）', async (t) => {
  const files = await startAdmin(t, (call) => (call.url.startsWith('/api/lan-peers/files/outbound')
    ? { status: 501, body: { error: 'files-unsupported' } }
    : { body: { ok: true, fileId: 'tx-offer-1', bytes: 4096, sha256: SHA, ms: 700 }, delayMs: 700 }));
  const out = await runAsync(['send-file', '书房', files.file, '--url', files.url, '--state-dir', files.dir],
    { DSH_LAN_PEERS_PROGRESS: '1' });

  assert.equal(out.status, 0, out.stderr);
  assert.match(out.stderr, /已用 \d+s/, '拿不到出站表就退回已用时长');
  assert.equal(/已发 /.test(out.stderr), false, '字节留在本机等对端来拉：不许画假的字节进度');
  assert.equal(out.stdout.trim(),
    '已挂出待下载 id=tx-offer-1 bytes=4096 sha256=' + SHA + ' ms=700（对端下载时才拉字节）');
  assert.ok(files.seen.some((call) => call.url.startsWith('/api/lan-peers/files/outbound')),
    'CLI 仍然会问一次出站表（旧 host / 旧版本兼容）');
  assert.equal(/文件操作失败/.test(out.stderr), false, '进度失败不外溢成命令失败');
});

// ---------------------------------------------------------------------------
// 删除的一例（明知而删）
//
// 旧用例「CLI send-file：能查到出站表就把「已用 Ns」升级成「已发 X/Y 字节（Z%）」」
// 钉的是**推送**模型：本机把字节推出去，所以有「已发多少」。offer/pull 之后门面的
// outbound() 恒回空数组（host/server.mjs 里那一行注释写得很直），生产上不存在
// 「sent > 0」的行可用；再拿桩喂一张假表去断言「升级」只会把一段死分支锁死。
// 于是它没有对应物：删掉，而不是把断言降级成「恰好也没画」。
// 计数：本文件 9 例 → 9 例（删 1 例，新增 1 例：下载进行中的 incoming 桶 + files/progress）。
// ---------------------------------------------------------------------------
