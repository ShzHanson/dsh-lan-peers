/**
 * 0.12.0-alpha S1 契约：**单发 offer/pull** 文件面（取代 0.8.5-α 的推送模型）。
 *
 * 模型：发送方只发一份 metadata（offer），字节留在自己的 outbox 里等对端来拉；
 * 接收方只有「待下载」条目（零字节），点下载才逐块 pull、验 sha256、落 inbox。
 *
 * 两条真节点（同一进程里两个 createPeerServer，走真实 HTTP/签名/信封）覆盖端到端；
 * 纯函数与 store 级用例覆盖清洗、限额、重启重建。
 *
 * 与推送模型的一一对应（删掉的都是「推送线上才有的事」）：
 *   推送：sender 分块调度 + receiver 自动收完 / 自动确认
 *   现在：sender 只挂 outbox；receiver 不点下载就一个字节都不落盘（本文件多处钉死这件事）
 */
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import test from 'node:test';

import { decryptBytes } from '../../lib/wire-crypto.mjs';
import { createAdmin } from '../../lib/admin.mjs';
import { FileOutbox, pullStateOf } from '../../lib/file-offer.mjs';
import { FILE_V1_PATHS, resolveConfig } from '../server.mjs';
import { FileStore, isReservedFileName, sanitizeFileName } from '../../lib/file-store.mjs';
import {
  listenOnRandomPort, makeTempStateDir, peerFixture, request, seedPeers, startServer,
} from './helpers.mjs';

/** 单响应硬上限：也是 pull 的块大小 */
const CHUNK = 512 * 1024;

/** 管理接口的最小请求/应答桩（与 group-files-wire / admin-files 同一口径） */
async function adminHit(admin, method, apiPath, body) {
  const chunks = body === undefined ? [] : [Buffer.from(JSON.stringify(body))];
  const req = {
    method,
    url: apiPath,
    socket: { remoteAddress: '127.0.0.1', setNoDelay() {} },
    headers: {
      host: '127.0.0.1:7788',
      'content-type': 'application/json',
      'content-length': String(chunks[0]?.length ?? 0),
      'x-lan-peers-token': String(admin.token ?? ''),
    },
    on() { return req; },
    once() { return req; },
    async *[Symbol.asyncIterator]() { for (const chunk of chunks) yield chunk; },
  };
  const res = {
    status: 0, headers: {}, body: '',
    setHeader(k, v) { this.headers[k] = v; },
    writeHead(status, headers) { this.status = status; Object.assign(this.headers, headers || {}); },
    write(chunk) { this.body += chunk; return true; },
    end(chunk) { if (chunk) this.body += chunk; if (!this.status) this.status = 200; },
    once() {}, on() {},
  };
  await admin.handle(req, res, new URL('http://127.0.0.1' + apiPath));
  return { status: res.status, json: (() => { try { return JSON.parse(res.body); } catch { return null; } })() };
}
const sha256 = (buffer) => createHash('sha256').update(buffer).digest('hex');

/** 确定性内容（不用随机：失败时 sha256 稳定可查；seed 用来造「同长度不同内容」） */
function payloadBytes(length, seed = 31) {
  const buffer = Buffer.alloc(length);
  for (let index = 0; index < length; index += 1) buffer[index] = (index * seed + 7) & 0xff;
  return buffer;
}

/**
 * 让若干节点互相成为对端（跳过配对流程，与其它用例同一口径）。
 * 同一份 peers.json 一次写完 —— seedPeers 会整文件覆盖，分多次写会丢掉前一条。
 */
function linkAll(nodes) {
  const keyOf = (from, to) => 'key-' + from.server.store.instanceId.slice(0, 8)
    + '-' + to.server.store.instanceId.slice(0, 8);
  for (const node of nodes) {
    const peers = nodes
      .filter((other) => other !== node)
      .map((other) => peerFixture(other.server.store.instanceId, {
        name: 'node-' + other.server.store.instanceId.slice(0, 4),
        secret: keyOf(node, other),
        inboundSecret: keyOf(other, node),
        baseUrl: other.baseUrl,
      }));
    if (peers.length > 0) seedPeers(node.stateDir, peers);
  }
  return { key: (from, to) => keyOf(from, to) };
}

/** 以 sender 的身份（签名 + 信封）打 receiver */
function signedFrom(sender, receiver, secret) {
  return (apiPath, body) => request(receiver.baseUrl, {
    peerId: sender.server.store.instanceId,
    secret,
    encrypt: true,
    method: 'POST',
    path: apiPath,
    body,
  });
}

function inboxFiles(stateDir) {
  const dir = path.join(stateDir, 'inbox');
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter((name) => !name.startsWith('.'));
}

function incomingParts(stateDir) {
  const dir = path.join(stateDir, 'inbox', '.incoming');
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter((name) => name.endsWith('.part'));
}

const offersOf = (files) => files.list().filter((row) => row.state === 'offer');

/**
 * 数一数真的拉了几块、按什么顺序拉的。
 *
 * pull 的请求体是加密信封，所以这里拦一层 fetch：用同一把 secret 解出 { fileId, offset }
 * 再放行（不读 req 流 —— 那会把产品自己的请求体抢走）。onPull 在产品**处理这一块之前**
 * 回调，于是「此刻接收方已经有多少字节」这类断言也是真的。
 */
function watchPulls(secret, options = {}) {
  const original = globalThis.fetch;
  const offsets = [];
  let failures = 0;
  globalThis.fetch = async (url, init) => {
    if (String(url).includes('/v1/file/pull')) {
      let offset = NaN;
      try {
        // 请求体线上就是 base64url 密文（不是 {enc,data} 信封 —— 那个形状只用于响应）
        const plain = decryptBytes(secret, String(init?.body ?? '')).toString('utf8');
        offset = Number(JSON.parse(plain).offset);
      } catch {
        // 解不开就记 NaN：断言会红，但不许把产品请求吃掉
      }
      if (typeof options.onPull === 'function') options.onPull(offset);
      offsets.push(offset);
      if (Number.isFinite(options.failFrom) && offsets.length > options.failFrom) {
        failures += 1;
        throw new TypeError('fetch failed: simulated unreachable holder');
      }
    }
    return original(url, init);
  };
  return {
    offsets,
    get failures() { return failures; },
    restore() { globalThis.fetch = original; },
  };
}

/** 一个「刚被放掉」的端口：拿它当 baseUrl，fetch 就是真的连不上（不是假的 bad port） */
async function deadPort() {
  const server = net.createServer((socket) => socket.destroy());
  const info = await listenOnRandomPort(server, '127.0.0.1');
  await new Promise((resolve) => server.close(resolve));
  return info.port;
}

// ---------------------------------------------------------------------------
// 端到端：offer → 逐块 pull → sha256 → 落 inbox
// ---------------------------------------------------------------------------

test('§1 端到端：offer 只带 metadata（对端零字节）→ 按序拉 ceil(size/512KiB) 块 → 落 inbox', async (t) => {
  const sender = await startServer(t);
  const receiver = await startServer(t);
  const link = linkAll([sender, receiver]);

  const payload = payloadBytes(1100 * 1024 + 7);   // 512KiB × 2 + 剩余 → 正好 3 块
  const localFile = path.join(sender.stateDir, 'payload.bin');
  fs.writeFileSync(localFile, payload);
  const expected = sha256(payload);
  const expectChunks = Math.ceil(payload.length / CHUNK);
  assert.equal(expectChunks, 3);

  const offered = await sender.server.files.send({
    peerId: receiver.server.store.instanceId,
    path: localFile,
  });
  assert.equal(offered.ok, true, JSON.stringify(offered));
  assert.equal(offered.offer, 'sent');
  assert.equal(offered.bytes, payload.length);
  assert.equal(offered.sha256, expected);
  assert.match(offered.fileId, /^[0-9a-f-]{36}$/);
  assert.ok(Number.isFinite(offered.ms));

  // 发送方：keeper 拷贝在 outbox 里，字节一个不少
  assert.equal(fs.statSync(path.join(sender.stateDir, 'outbox', offered.fileId, 'data')).size, payload.length);

  // 接收方：一条待下载 + 只有 meta.json —— 一个字节都不落盘
  const rows = receiver.server.files.list();
  assert.deepEqual(rows.map((row) => row.state), ['offer']);
  assert.deepEqual(
    { id: rows[0].id, name: rows[0].name, size: rows[0].size, sha256: rows[0].sha256 },
    { id: offered.fileId, name: 'payload.bin', size: payload.length, sha256: expected },
  );
  assert.equal(rows[0].from.peerId, sender.server.store.instanceId);
  assert.equal(rows[0].trusted, false, '没信任过的 peer 默认不信任');
  assert.deepEqual(
    fs.readdirSync(path.join(receiver.stateDir, 'offers', offered.fileId)).sort(),
    ['meta.json'],
    '待下载条目只有 meta.json',
  );
  assert.deepEqual(inboxFiles(receiver.stateDir), [], '还没下载，inbox 必须空');
  assert.deepEqual(incomingParts(receiver.stateDir), [], '还没下载，没有半截分片');

  // 拉取过程中每一块的现场：此刻接收方只有前面那几块字节，inbox 仍然是空的
  const observed = [];
  const seen = watchPulls(link.key(receiver, sender), {
    onPull: (offset) => {
      const live = receiver.server.files.list().filter((row) => row.state === 'incoming');
      observed.push({
        offset,
        live: live.length,
        received: live[0]?.received ?? -1,
        inbox: inboxFiles(receiver.stateDir).length,
      });
    },
  });
  let downloaded;
  try {
    downloaded = await receiver.server.files.download(offered.fileId);
    assert.deepEqual(seen.offsets, [0, CHUNK, CHUNK * 2], '必须按 512KiB 顺序拉，块数 = ceil(size/chunk)');
  } finally {
    seen.restore();
  }
  assert.equal(downloaded.ok, true, JSON.stringify(downloaded));
  assert.equal(downloaded.bytes, payload.length);
  assert.equal(downloaded.sha256, expected);
  assert.equal(downloaded.pulled, payload.length);
  assert.deepEqual(
    observed.map((item) => [item.offset, item.received, item.live, item.inbox]),
    [[0, 0, 1, 0], [CHUNK, CHUNK, 1, 0], [CHUNK * 2, CHUNK * 2, 1, 0]],
    '逐块推进：拉第 N 块时已收 N 块，且没有任何一块提前落进 inbox',
  );

  // 落盘：inbox/<id>__<清洗后文件名>，内容 sha256 对齐
  const landed = inboxFiles(receiver.stateDir);
  assert.equal(landed.length, 1);
  assert.equal(landed[0], downloaded.id + '__payload.bin');
  assert.deepEqual([landed[0]], [downloaded.id + '__payload.bin']);
  assert.ok(downloaded.path.startsWith(path.join(receiver.stateDir, 'inbox') + path.sep), downloaded.path);
  assert.equal(sha256(fs.readFileSync(downloaded.path)), expected);
  assert.equal(fs.existsSync(path.join(receiver.stateDir, 'offers', offered.fileId)), false, '下载完待下载条目消失');
  assert.deepEqual(incomingParts(receiver.stateDir), [], '拼完就没有半截分片了');
  assert.deepEqual(receiver.server.files.list().map((row) => row.state), ['done']);
});

// ---------------------------------------------------------------------------
// T1/T2：一趟传输必须能被「客户端手上那一个 id」（offer 的 fileId）寻址
// ---------------------------------------------------------------------------

test('§1 T1 传输可寻址：下载途中按 offer 的 fileId 查 progress 读到活字节，incoming 行 id 就是它', async (t) => {
  const sender = await startServer(t);
  const receiver = await startServer(t);
  const link = linkAll([sender, receiver]);

  const payload = payloadBytes(1100 * 1024 + 7);   // 3 块
  const localFile = path.join(sender.stateDir, 'addressable.bin');
  fs.writeFileSync(localFile, payload);
  const offered = await sender.server.files.send({ peerId: receiver.server.store.instanceId, path: localFile });
  assert.equal(offered.ok, true, JSON.stringify(offered));

  // onPull 在产品处理这一块**之前**回调：此刻「已收字节」就是前面那几块的累计
  const samples = [];
  const seen = watchPulls(link.key(receiver, sender), {
    onPull: (offset) => {
      const rows = receiver.server.files.list().filter((row) => row.state === 'incoming');
      samples.push({
        offset,
        incomingId: rows[0]?.id ?? '',
        incomingReceived: rows[0]?.received ?? -1,
        // 客户端（CLI/面板）手上只有 offer 的 fileId，没有别的 id 可查
        progress: receiver.server.files.progress(offered.fileId),
      });
    },
  });
  let downloaded;
  try {
    downloaded = await receiver.server.files.download(offered.fileId);
    assert.deepEqual(seen.offsets, [0, CHUNK, CHUNK * 2], '按 512KiB 顺序拉满三块');
  } finally {
    seen.restore();
  }
  assert.equal(downloaded.ok, true, JSON.stringify(downloaded));

  assert.deepEqual(
    samples.map((sample) => sample.progress),
    [
      { received: 0, size: payload.length, state: 'incoming' },
      { received: CHUNK, size: payload.length, state: 'incoming' },
      { received: CHUNK * 2, size: payload.length, state: 'incoming' },
    ],
    'progress?id=<offer fileId> 途中必须报 incoming + 已收字节（先前的 404/unknown 就是这条被钉住的缺陷）',
  );
  assert.deepEqual(
    samples.map((sample) => sample.incomingId),
    [offered.fileId, offered.fileId, offered.fileId],
    'GET files 的 incoming 行 id 必须等于 offer 的 fileId：客户端只握着一个 id',
  );
  assert.deepEqual(samples.map((sample) => sample.incomingReceived), [0, CHUNK, CHUNK * 2],
    'incoming.received 与 progress.received 同源（都现算 .part 的实际字节）');
});

test('§1 T2 终态：同一个 id 下载完成后报 done（字节数齐全），只有本机没见过的 id 才 404', async (t) => {
  const sender = await startServer(t);
  const receiver = await startServer(t);
  const link = linkAll([sender, receiver]);

  const payload = payloadBytes(600 * 1024);        // 2 块
  const localFile = path.join(sender.stateDir, 'terminal.bin');
  fs.writeFileSync(localFile, payload);
  const expected = sha256(payload);
  const offered = await sender.server.files.send({ peerId: receiver.server.store.instanceId, path: localFile });
  assert.equal(offered.ok, true, JSON.stringify(offered));

  const seen = watchPulls(link.key(receiver, sender));
  let downloaded;
  try {
    downloaded = await receiver.server.files.download(offered.fileId);
  } finally {
    seen.restore();
  }
  assert.equal(downloaded.ok, true, JSON.stringify(downloaded));

  // 文档化口径（本断言就是这条口径的钉子）：完成之后
  //   GET files/progress?id=<offer fileId> → 200 { received:size, size, state:'done' }
  // 不是 404。admin 路由（lib/admin.mjs）原样转发这三字段，所以门面形状 = HTTP 形状。
  // sha256 不在这条响应里（要加得动 admin 路由，超出本次边界），它仍在 GET files 上。
  assert.deepEqual(
    receiver.server.files.progress(offered.fileId),
    { received: payload.length, size: payload.length, state: 'done' },
  );
  const idle = receiver.server.files.progress('00000000-0000-4000-8000-000000000000');
  assert.deepEqual(idle, { received: 0, size: 0, state: 'unknown' }, '本机没见过的 id 才是 unknown（HTTP 404）');

  const rows = receiver.server.files.list();
  assert.deepEqual(rows.map((row) => row.state), ['done']);
  assert.equal(rows[0].id, offered.fileId, '收件箱行也用同一个 id 对账');
  assert.equal(rows[0].sha256, expected);
  assert.equal(rows[0].received, undefined, 'done 行不带 received：字节数由 size 表达');
});

// ---------------------------------------------------------------------------
// T3：download 回的 locator 在 fileAutoAccept 两种取值下都真实可用
// ---------------------------------------------------------------------------

test('§3 T3 locator：fileAutoAccept 两种取值下 download 都回一个真实存在的落盘路径', async (t) => {
  for (const autoAccept of [false, true]) {
    const label = 'fileAutoAccept=' + autoAccept;
    const sender = await startServer(t);
    const receiver = await startServer(t, { fileAutoAccept: autoAccept });
    const link = linkAll([sender, receiver]);

    const payload = payloadBytes(9000, 11);
    const localFile = path.join(sender.stateDir, 'locator.bin');
    fs.writeFileSync(localFile, payload);
    const expected = sha256(payload);
    const offered = await sender.server.files.send({ peerId: receiver.server.store.instanceId, path: localFile });
    assert.equal(offered.ok, true, label + ' ' + JSON.stringify(offered));

    const seen = watchPulls(link.key(receiver, sender));
    let downloaded;
    try {
      downloaded = await receiver.server.files.download(offered.fileId);
    } finally {
      seen.restore();
    }
    assert.equal(downloaded.ok, true, label + ' ' + JSON.stringify(downloaded));
    assert.equal(typeof downloaded.path, 'string', label + '：locator 必须是字符串');
    assert.notEqual(downloaded.path, '', label + '：locator 不能是空串（autoAccept 分支曾用空串盖掉落盘路径）');
    assert.equal(fs.existsSync(downloaded.path), true, label + '：locator 必须真的在盘上：' + downloaded.path);
    assert.equal(path.dirname(downloaded.path), path.join(receiver.stateDir, 'inbox'), label + '：必须落在 inbox');
    assert.equal(path.basename(downloaded.path), downloaded.id + '__locator.bin', label + '：id 与文件名都出自服务端');
    assert.equal(sha256(fs.readFileSync(downloaded.path)), expected, label + '：locator 指向的就是那份字节');
  }
});

test('§2 断线重试：拉到一半 holder 失联 → 已收字节留在 .part，重试从 resumeFrom 续，不从头再来', async (t) => {
  const sender = await startServer(t);
  const receiver = await startServer(t);
  const link = linkAll([sender, receiver]);

  const payload = payloadBytes(700 * 1024);   // 2 块
  const localFile = path.join(sender.stateDir, 'resume.bin');
  fs.writeFileSync(localFile, payload);
  const expected = sha256(payload);

  const offered = await sender.server.files.send({
    peerId: receiver.server.store.instanceId,
    path: localFile,
  });
  assert.equal(offered.ok, true, JSON.stringify(offered));

  // 第 2 块开始就连不上 holder
  const broken = watchPulls(link.key(receiver, sender), { failFrom: 1 });
  let first;
  try {
    first = await receiver.server.files.download(offered.fileId);
    assert.deepEqual(broken.offsets, [0, CHUNK], '第 2 块发出去了，但没等到回包');
    assert.equal(broken.failures, 1);
  } finally {
    broken.restore();
  }
  assert.equal(first.ok, false);
  assert.equal(first.reason, 'holder-offline');
  assert.equal(first.received, CHUNK, '已经拉下来的那一块如实回报');
  assert.equal(first.bytes, payload.length);
  assert.deepEqual(inboxFiles(receiver.stateDir), [], '断了也不许有文件落地');
  assert.deepEqual(incomingParts(receiver.stateDir).length, 1, '半截分片留着等重试');
  const mid = receiver.server.files.list().filter((row) => row.state === 'incoming');
  assert.deepEqual([mid.length, mid[0].received, mid[0].size], [1, CHUNK, payload.length]);
  assert.deepEqual(offersOf(receiver.server.files).map((row) => row.id), [offered.fileId], '待下载条目还在，能重试');

  // 重试：只拉剩下的那一块
  const resumed = watchPulls(link.key(receiver, sender));
  let second;
  try {
    second = await receiver.server.files.download(offered.fileId);
    assert.deepEqual(resumed.offsets, [CHUNK], '必须从 resumeFrom 续，不许从 0 重拉');
  } finally {
    resumed.restore();
  }
  assert.equal(second.ok, true, JSON.stringify(second));
  const landed = inboxFiles(receiver.stateDir);
  assert.equal(landed.length, 1);
  assert.equal(sha256(fs.readFileSync(path.join(receiver.stateDir, 'inbox', landed[0]))), expected);
  assert.deepEqual(incomingParts(receiver.stateDir), []);
  assert.deepEqual(offersOf(receiver.server.files), []);
});

test('§1 空文件（size=0）：报价 → 下载 0 块 → 落一个 0 字节文件，sha256 = e3b0c442…', async (t) => {
  const sender = await startServer(t);
  const receiver = await startServer(t);
  const link = linkAll([sender, receiver]);
  const empty = path.join(sender.stateDir, 'empty.bin');
  fs.writeFileSync(empty, Buffer.alloc(0));

  const offered = await sender.server.files.send({ peerId: receiver.server.store.instanceId, path: empty });
  assert.equal(offered.ok, true, JSON.stringify(offered));
  assert.equal(offered.bytes, 0);
  assert.equal(offered.sha256, sha256(Buffer.alloc(0)));

  const seen = watchPulls(link.key(receiver, sender));
  let downloaded;
  try {
    downloaded = await receiver.server.files.download(offered.fileId);
    assert.deepEqual(seen.offsets, [], '0 字节没有块可拉');
  } finally {
    seen.restore();
  }
  assert.equal(downloaded.ok, true, JSON.stringify(downloaded));
  assert.equal(downloaded.bytes, 0);
  assert.equal(fs.statSync(downloaded.path).size, 0);
  assert.equal(path.basename(downloaded.path), downloaded.id + '__empty.bin');
});

test('§2 同内容二次报价 → 第二次下载是 dedupe（0 块、inbox 不堆第二份）', async (t) => {
  const sender = await startServer(t);
  const receiver = await startServer(t);
  const link = linkAll([sender, receiver]);

  const payload = payloadBytes(150 * 1024);
  const localFile = path.join(sender.stateDir, 'once.bin');
  fs.writeFileSync(localFile, payload);
  const expected = sha256(payload);

  const first = await sender.server.files.send({ peerId: receiver.server.store.instanceId, path: localFile });
  assert.equal(first.ok, true, JSON.stringify(first));
  const firstPull = watchPulls(link.key(receiver, sender));
  let one;
  try {
    one = await receiver.server.files.download(first.fileId);
  } finally {
    firstPull.restore();
  }
  assert.equal(one.ok, true, JSON.stringify(one));
  assert.deepEqual(firstPull.offsets, [0]);
  assert.equal(inboxFiles(receiver.stateDir).length, 1);

  // 同内容再报价一条：新的 fileId、新的待下载条目
  const second = await sender.server.files.send({ peerId: receiver.server.store.instanceId, path: localFile });
  assert.equal(second.ok, true, JSON.stringify(second));
  assert.notEqual(second.fileId, first.fileId);
  assert.equal(offersOf(receiver.server.files).length, 1, '第二次报价同样是一条待下载');
  assert.equal(second.sha256, expected);

  const secondPull = watchPulls(link.key(receiver, sender));
  let two;
  try {
    two = await receiver.server.files.download(second.fileId);
    assert.deepEqual(secondPull.offsets, [], '内容已在盘上：一块都不用拉');
  } finally {
    secondPull.restore();
  }
  assert.equal(two.ok, true, JSON.stringify(two));
  assert.equal(two.pulled, 0);
  assert.equal(two.bytes, payload.length);
  assert.equal(inboxFiles(receiver.stateDir).length, 1, 'inbox 里不许堆两份相同内容');
  assert.deepEqual(receiver.server.files.list().map((row) => row.state), ['done']);
  assert.deepEqual(offersOf(receiver.server.files), [], '两条待下载条目都被消费掉');
});

// ---------------------------------------------------------------------------
// 路径穿越 / 保留名
// ---------------------------------------------------------------------------

test('§6.5 路径穿越与 Windows 保留名：清洗或拒收，绝不落到 inbox 之外', async (t) => {
  // 纯函数口径
  assert.equal(sanitizeFileName('../x'), 'x');
  assert.equal(sanitizeFileName('a/b'), 'b');
  assert.equal(sanitizeFileName('../../etc/passwd'), 'passwd');
  assert.equal(sanitizeFileName('C:\\Windows\\System32\\evil.dll'), 'evil.dll');
  assert.equal(sanitizeFileName('/abs/path/x.txt'), 'x.txt');
  assert.equal(sanitizeFileName('..'), '');
  assert.equal(sanitizeFileName(''), '');
  assert.equal(sanitizeFileName('a\u0000b\u200b.txt'), 'ab.txt');
  assert.equal(sanitizeFileName('trailing...'), 'trailing');
  for (const reserved of ['CON', 'con.txt', 'AUX.log', 'NUL', 'COM1', 'com7.dat', 'LPT9.dat', 'lpt1']) {
    assert.equal(sanitizeFileName(reserved), '', reserved + ' 必须拒收');
    assert.equal(isReservedFileName(reserved), true, reserved);
  }
  assert.equal(isReservedFileName('console.txt'), false);
  const longName = sanitizeFileName('a'.repeat(300) + '.tar.gz');
  assert.ok(longName.length <= 128, String(longName.length));
  assert.ok(longName.endsWith('.gz'));

  // 协议口径：对端在 offer 里塞穿越名 —— 条目里的名字被清洗，落盘仍在 inbox 之内
  const sender = await startServer(t);
  const receiver = await startServer(t);
  const link = linkAll([sender, receiver]);
  const api = signedFrom(sender, receiver, link.key(sender, receiver));
  const body = Buffer.from('traversal');
  const localFile = path.join(sender.stateDir, 'payload.bin');
  fs.writeFileSync(localFile, body);
  const sent = await sender.server.files.send({
    peerId: receiver.server.store.instanceId,
    path: localFile,
  });
  assert.equal(sent.ok, true, JSON.stringify(sent));

  // 同一个 fileId 重发一条带穿越名的 offer（metadata 与 keeper 一致，所以能拉成功）
  const forged = await api('/v1/file/offer', {
    fileId: sent.fileId,
    name: '../../../../etc/passwd',
    size: body.length,
    sha256: sha256(body),
  });
  assert.equal(forged.status, 200, forged.text);
  assert.deepEqual(forged.json, { ok: true });
  const entry = offersOf(receiver.server.files)[0];
  assert.equal(entry.id, sent.fileId);
  assert.equal(entry.name, 'passwd', '目录成分必须被丢掉');
  assert.equal(fs.existsSync(path.join(receiver.stateDir, 'etc')), false);

  const downloaded = await receiver.server.files.download(sent.fileId);
  assert.equal(downloaded.ok, true, JSON.stringify(downloaded));
  assert.equal(path.basename(downloaded.path), downloaded.id + '__passwd');
  assert.ok(downloaded.path.startsWith(path.join(receiver.stateDir, 'inbox') + path.sep), downloaded.path);
  assert.equal(fs.readFileSync(downloaded.path).toString(), 'traversal');
  assert.equal(fs.existsSync(path.join(path.dirname(receiver.stateDir), 'passwd')), false, '绝不落到 stateDir 之外');

  // 保留名直接拒收：400 bad-name，且不留条目
  for (const reserved of ['CON', 'con.txt', 'COM1', 'LPT9.dat']) {
    const rejected = await api('/v1/file/offer', {
      fileId: randomUUID(),
      name: reserved,
      size: 4,
      sha256: 'f'.repeat(64),
    });
    assert.equal(rejected.status, 400, reserved + ' ' + rejected.text);
    assert.deepEqual(rejected.json, { error: 'bad-name' });
  }
  assert.deepEqual(offersOf(receiver.server.files), [], '被拒的报价不留条目');
  assert.deepEqual(incomingParts(receiver.stateDir), []);
  assert.deepEqual(inboxFiles(receiver.stateDir), [downloaded.id + '__passwd']);
});

// ---------------------------------------------------------------------------
// 限额
// ---------------------------------------------------------------------------

test('§6.6 限额：超 fileMaxBytes 在**报价时**就拒；inbox 满与并发 2 在下载时给出明确 reason', async (t) => {
  const sender = await startServer(t);
  const tight = await startServer(t, { fileMaxBytes: 1024, fileInboxBytes: 1000 });
  const roomy = await startServer(t);   // 默认限额：只用来测并发
  const link = linkAll([sender, tight, roomy]);
  const api = signedFrom(sender, tight, link.key(sender, tight));

  // 1) 报价阶段就拒：tight 的 fileMaxBytes 是 1024，一条 2048 的报价得不到条目
  const tooLarge = await api('/v1/file/offer', {
    fileId: randomUUID(),
    name: 'big.bin',
    size: 2048,
    sha256: 'a'.repeat(64),
  });
  assert.equal(tooLarge.status, 413, tooLarge.text);
  assert.deepEqual(tooLarge.json, { error: 'too-large' });
  assert.deepEqual(offersOf(tight.server.files), [], '被拒的报价一个条目都不留');

  // 2) inbox 满：900 字节在限额内，第二条 900 字节就会超 1000 的总量
  const bodies = [payloadBytes(900, 3), payloadBytes(900, 5)];
  const sent = [];
  for (let index = 0; index < bodies.length; index += 1) {
    const file = path.join(sender.stateDir, 'fit-' + index + '.bin');
    fs.writeFileSync(file, bodies[index]);
    const out = await sender.server.files.send({ peerId: tight.server.store.instanceId, path: file });
    assert.equal(out.ok, true, JSON.stringify(out));
    sent.push(out);
  }
  assert.equal(offersOf(tight.server.files).length, 2);
  const firstDown = await tight.server.files.download(sent[0].fileId);
  assert.equal(firstDown.ok, true, JSON.stringify(firstDown));
  const full = await tight.server.files.download(sent[1].fileId);
  assert.equal(full.ok, false, JSON.stringify(full));
  assert.equal(full.reason, 'inbox-full');
  assert.deepEqual(inboxFiles(tight.stateDir), [firstDown.id + '__fit-0.bin'], '超限的那条一个字节都不落');
  assert.deepEqual(offersOf(tight.server.files).map((row) => row.id), [sent[1].fileId], '待下载条目留着，清盘后还能下');

  // 3) 并发 ≤2：三个下载同时在跑，第三个 offer() 当场 busy
  const busy = [payloadBytes(64, 7), payloadBytes(63, 7), payloadBytes(62, 7)];
  const busySent = [];
  for (let index = 0; index < busy.length; index += 1) {
    const file = path.join(sender.stateDir, 'busy-' + index + '.bin');
    fs.writeFileSync(file, busy[index]);
    const out = await sender.server.files.send({ peerId: roomy.server.store.instanceId, path: file });
    assert.equal(out.ok, true, JSON.stringify(out));
    busySent.push(out);
  }
  const results = await Promise.all(busySent.map((out) => roomy.server.files.download(out.fileId)));
  assert.equal(results.filter((out) => out.ok === true).length, 2, JSON.stringify(results.map((out) => out.reason ?? 'ok')));
  const refused = results.filter((out) => out.ok !== true);
  assert.equal(refused.length, 1);
  assert.equal(refused[0].reason, 'busy');
  assert.equal(inboxFiles(roomy.stateDir).length, 2, '被 busy 拒的那条不许留下半截文件');
  assert.deepEqual(incomingParts(roomy.stateDir), []);
});

// ---------------------------------------------------------------------------
// TTL / 失败不落地
// ---------------------------------------------------------------------------

test('§6.3 TTL：没人下载的报价到期被清掉，之后下载如实说 unknown-file', async (t) => {
  let clock = Date.now();
  const receiver = await startServer(t, { now: () => clock });
  const sender = await startServer(t, { now: () => clock });
  linkAll([sender, receiver]);

  const localFile = path.join(sender.stateDir, 'ttl.bin');
  fs.writeFileSync(localFile, Buffer.from('ttl-body'));
  const offered = await sender.server.files.send({
    peerId: receiver.server.store.instanceId,
    path: localFile,
  });
  assert.equal(offered.ok, true, JSON.stringify(offered));
  assert.equal(offersOf(receiver.server.files).length, 1);

  // 时钟跳过 TTL（7 天），驱动一次清理（不 sleep）
  clock += 8 * 24 * 60 * 60 * 1000;
  const removed = receiver.server.files.sweep();
  const evicted = sender.server.files.sweep();
  assert.ok(removed >= 1, 'const removed=' + removed);
  assert.ok(evicted >= 1, 'const evicted=' + evicted);
  assert.deepEqual(receiver.server.files.list(), []);
  assert.equal(fs.existsSync(path.join(receiver.stateDir, 'offers', offered.fileId)), false, '到期删目录');
  assert.equal(fs.existsSync(path.join(sender.stateDir, 'outbox', offered.fileId)), false, '发送方的 keeper 也按 TTL 逐出');
  assert.deepEqual(inboxFiles(receiver.stateDir), []);

  const after = await receiver.server.files.download(offered.fileId);
  assert.equal(after.ok, false);
  assert.equal(after.reason, 'unknown-file', '清掉之后连拉都拉不了：这就是「没人下载」的代价');
  assert.deepEqual(inboxFiles(receiver.stateDir), []);
});

test('§5 接收方 fileAutoAccept=true 也**不会**因为一条 offer 自动落地：下载才是同意', async (t) => {
  const sender = await startServer(t);
  const receiver = await startServer(t, { fileAutoAccept: true });
  const link = linkAll([sender, receiver]);
  const payload = payloadBytes(9 * 1024);
  const localFile = path.join(sender.stateDir, 'auto.bin');
  fs.writeFileSync(localFile, payload);

  const offered = await sender.server.files.send({ peerId: receiver.server.store.instanceId, path: localFile });
  assert.equal(offered.ok, true, JSON.stringify(offered));
  // 推送模型里 autoAccept 是「对端推完就自动收」；现在 offer 之后什么都没发生
  assert.deepEqual(inboxFiles(receiver.stateDir), [], 'offer 不落字节');
  assert.deepEqual(incomingParts(receiver.stateDir), []);
  assert.deepEqual(receiver.server.files.list().map((row) => row.state), ['offer']);

  const seen = watchPulls(link.key(receiver, sender));
  let downloaded;
  try {
    downloaded = await receiver.server.files.download(offered.fileId);
    assert.deepEqual(seen.offsets, [0]);
  } finally {
    seen.restore();
  }
  assert.equal(downloaded.ok, true, JSON.stringify(downloaded));
  // autoAccept 时 complete() 自己就搬进 inbox：门面回的 path 就是那份落盘路径（T3 钉住）
  const landed = inboxFiles(receiver.stateDir);
  assert.deepEqual(landed, [downloaded.id + '__auto.bin']);
  assert.equal(sha256(fs.readFileSync(path.join(receiver.stateDir, 'inbox', landed[0]))), sha256(payload));
  assert.deepEqual(receiver.server.files.list().map((row) => row.state), ['done']);
});

test('§1 完整性：holder 回来的字节被改过 → integrity-failed，半截删掉，什么都不落', async (t) => {
  const sender = await startServer(t);
  const receiver = await startServer(t);
  linkAll([sender, receiver]);

  const payload = payloadBytes(600 * 1024);
  const localFile = path.join(sender.stateDir, 'payload.bin');
  fs.writeFileSync(localFile, payload);
  const offered = await sender.server.files.send({
    peerId: receiver.server.store.instanceId,
    path: localFile,
  });
  assert.equal(offered.ok, true, JSON.stringify(offered));

  // 把 keeper 拷贝里第一个字节改掉：offer 里的 sha256 仍是原文件的
  const kept = path.join(sender.stateDir, 'outbox', offered.fileId, 'data');
  const corrupted = Buffer.from(fs.readFileSync(kept));
  corrupted[0] = corrupted[0] ^ 0xff;
  fs.writeFileSync(kept, corrupted);

  const downloaded = await receiver.server.files.download(offered.fileId);
  assert.equal(downloaded.ok, false);
  assert.equal(downloaded.reason, 'integrity-failed');
  assert.deepEqual(inboxFiles(receiver.stateDir), [], '校验不过就不许有文件落地');
  assert.deepEqual(incomingParts(receiver.stateDir), [], '半截分片必须被删掉');
  assert.deepEqual(offersOf(receiver.server.files), [], '这条待下载作废，别再让人点第二次');
  assert.equal(fs.existsSync(kept), true, '发送方的 keeper 不动：坏的是它自己的字节');
});

test('§1 holder 连不上 → holder-offline，一个字节都不落，条目留着等重试', async (t) => {
  const ghostId = randomUUID();
  const port = await deadPort();
  const stateDir = makeTempStateDir('dsh-file-offline-');
  seedPeers(stateDir, [
    peerFixture(ghostId, {
      name: 'ghost',
      // 夹具值的形状照 leak-check 的豁免口径写（<标识>-secret），不然会被当成真凭据
      secret: 'ghost-outbound-secret',
      inboundSecret: 'ghost-inbound-secret',
      baseUrl: 'http://127.0.0.1:' + port,
    }),
  ]);
  const receiver = await startServer(t, { stateDir });

  const fileId = randomUUID();
  const body = Buffer.from('ghost');
  const offered = await request(receiver.baseUrl, {
    peerId: ghostId,
    secret: 'ghost-inbound-secret',
    encrypt: true,
    method: 'POST',
    path: '/v1/file/offer',
    body: { fileId, name: 'ghost.bin', size: body.length, sha256: sha256(body) },
  });
  assert.equal(offered.status, 200, offered.text);
  assert.equal(offersOf(receiver.server.files).length, 1);

  const downloaded = await receiver.server.files.download(fileId);
  assert.equal(downloaded.ok, false, JSON.stringify(downloaded));
  assert.equal(downloaded.reason, 'holder-offline');
  assert.equal(downloaded.received, 0, '一块都没拉到');
  assert.equal(downloaded.bytes, body.length);
  assert.deepEqual(inboxFiles(receiver.stateDir), []);
  assert.deepEqual(offersOf(receiver.server.files).map((row) => row.id), [fileId], '条目留着，holder 回来还能下');
});

// ---------------------------------------------------------------------------
// 收回 / 错误码 / 鉴权
// ---------------------------------------------------------------------------

test('§1 收回：sender withdraw → 待下载条目消失，再下载如实说 unknown-file（重复收回幂等）', async (t) => {
  const sender = await startServer(t);
  const receiver = await startServer(t);
  const link = linkAll([sender, receiver]);
  const api = signedFrom(sender, receiver, link.key(sender, receiver));

  const localFile = path.join(sender.stateDir, 'payload.bin');
  fs.writeFileSync(localFile, payloadBytes(32));
  const offered = await sender.server.files.send({
    peerId: receiver.server.store.instanceId,
    path: localFile,
  });
  assert.equal(offered.ok, true, JSON.stringify(offered));
  assert.equal(offersOf(receiver.server.files).length, 1);

  const withdraw = await api('/v1/file/withdraw', { fileId: offered.fileId });
  assert.equal(withdraw.status, 200, withdraw.text);
  assert.deepEqual(withdraw.json, { ok: true, removed: true });
  assert.deepEqual(offersOf(receiver.server.files), [], '收到 withdraw 就把待下载条目删掉');
  assert.equal(fs.existsSync(path.join(receiver.stateDir, 'offers', offered.fileId)), false);

  const after = await receiver.server.files.download(offered.fileId);
  assert.equal(after.ok, false);
  assert.equal(after.reason, 'unknown-file');
  assert.deepEqual(inboxFiles(receiver.stateDir), [], '收回之后也许诺不了字节');

  const again = await api('/v1/file/withdraw', { fileId: offered.fileId });
  assert.equal(again.status, 200, again.text);
  assert.deepEqual(again.json, { ok: true, removed: false }, '重复收回只是 removed:false，不是错误');
});

test('§1 pull 的错误码：403 forbidden / 404 unknown-file / 409 file-gone / 400 bad-offset / 405 / 404', async (t) => {
  const sender = await startServer(t);
  const receiver = await startServer(t);
  const eve = await startServer(t);
  const link = linkAll([sender, receiver, eve]);
  const from = (node) => signedFrom(node, sender, link.key(node, sender));

  const localFile = path.join(sender.stateDir, 'payload.bin');
  fs.writeFileSync(localFile, payloadBytes(1024));
  const offered = await sender.server.files.send({
    peerId: receiver.server.store.instanceId,
    path: localFile,
  });
  assert.equal(offered.ok, true, JSON.stringify(offered));

  // 1) eve 也是合法对端（签名过得去），但这份 keeper 不是给它的 → 403，且身体里没有字节
  const stolen = await from(eve)('/v1/file/pull', { fileId: offered.fileId, offset: 0 });
  assert.equal(stolen.status, 403, stolen.text);
  assert.deepEqual(stolen.json, { error: 'forbidden' });
  assert.equal(stolen.text.includes('dataBase64'), false, '403 的身体里绝不能夹带字节');

  // 2) 不认识的 id → 404 unknown-file
  const unknown = await from(receiver)('/v1/file/pull', { fileId: randomUUID(), offset: 0 });
  assert.equal(unknown.status, 404, unknown.text);
  assert.deepEqual(unknown.json, { error: 'unknown-file' });

  // 3) 越界偏移 → 400 bad-offset（带真实 size）
  const badOffset = await from(receiver)('/v1/file/pull', { fileId: offered.fileId, offset: 4096 });
  assert.equal(badOffset.status, 400, badOffset.text);
  assert.deepEqual(badOffset.json, { error: 'bad-offset', size: 1024 });

  // 4) 正常那块：base64 + offset/eof
  const ok = await from(receiver)('/v1/file/pull', { fileId: offered.fileId, offset: 0 });
  assert.equal(ok.status, 200, ok.text);
  assert.equal(ok.json.offset, 0);
  assert.equal(ok.json.eof, true, '1024 字节一次就到底');
  assert.equal(Buffer.from(ok.json.dataBase64, 'base64').length, 1024);

  // 5) 被逐出（TTL 到点）→ 409 file-gone（「有过，但没了」），下载侧翻成 file-gone
  sender.server.files.sweep(Date.now() + 8 * 24 * 60 * 60 * 1000);
  const gone = await from(receiver)('/v1/file/pull', { fileId: offered.fileId, offset: 0 });
  assert.equal(gone.status, 409, gone.text);
  assert.deepEqual(gone.json, { error: 'file-gone' });
  assert.equal(fs.existsSync(path.join(sender.stateDir, 'outbox', offered.fileId)), false, '逐出删目录');
  const downloadGone = await receiver.server.files.download(offered.fileId);
  assert.equal(downloadGone.ok, false);
  assert.equal(downloadGone.reason, 'file-gone');
  assert.deepEqual(offersOf(receiver.server.files), [], 'file-gone 的条目当场作废，别再让人点');

  // 6) 已知路径用错方法 405；未知 /v1/file/* 404
  const wrongMethod = await request(sender.baseUrl, {
    peerId: receiver.server.store.instanceId,
    secret: link.key(receiver, sender),
    encrypt: true,
    method: 'GET',
    path: '/v1/file/offer',
  });
  assert.equal(wrongMethod.status, 405, wrongMethod.text);
  assert.equal(wrongMethod.json.error, 'method-not-allowed');
  const notFound = await from(receiver)('/v1/file/nope', {});
  assert.equal(notFound.status, 404, notFound.text);
  assert.deepEqual([...FILE_V1_PATHS].sort(), [
    '/v1/file/offer',
    '/v1/file/pull',
    '/v1/file/withdraw',
  ]);
});

test('§0/§6.7 未配对对端 → 401；缺加密信封 → 400 encryption-required', async (t) => {
  const lax = await startServer(t);
  const strict = await startServer(t, { requireEncryption: true });
  const sender = await startServer(t);
  const laxLink = linkAll([sender, lax]);
  const strictLink = linkAll([sender, strict]);
  const offerBody = {
    fileId: randomUUID(),
    name: 'auth.bin',
    size: 4,
    sha256: 'a'.repeat(64),
  };

  // 没有签名头 → 401
  const unsigned = await request(lax.baseUrl, {
    method: 'POST',
    path: '/v1/file/offer',
    signed: false,
    body: offerBody,
  });
  assert.equal(unsigned.status, 401, unsigned.text);

  // 签名了但不在 peers.json → 401
  const stranger = await request(lax.baseUrl, {
    method: 'POST',
    path: '/v1/file/offer',
    peerId: 'not-paired-peer',
    secret: 'whatever',
    encrypt: true,
    body: offerBody,
  });
  assert.equal(stranger.status, 401, stranger.text);

  // 配对过、但不带 X-Peer-Enc（严格节点）→ 400 encryption-required
  const plaintext = await request(strict.baseUrl, {
    method: 'POST',
    path: '/v1/file/offer',
    peerId: sender.server.store.instanceId,
    secret: strictLink.key(sender, strict),
    encrypt: false,
    body: offerBody,
  });
  assert.equal(plaintext.status, 400, plaintext.text);
  assert.equal(plaintext.json.error, 'encryption-required');

  // 带上信封就通了（签名 + 加密体，走既有鉴权）
  const ok = await signedFrom(sender, strict, strictLink.key(sender, strict))('/v1/file/offer', offerBody);
  assert.equal(ok.status, 200, ok.text);
  assert.deepEqual(ok.json, { ok: true });
  assert.deepEqual(offersOf(strict.server.files).map((row) => row.id), [offerBody.fileId]);

  // lax 也通（续用 laxLink，避免「先 seed 后覆盖」把对端弄丢）
  const okLax = await signedFrom(sender, lax, laxLink.key(sender, lax))('/v1/file/offer', offerBody);
  assert.equal(okLax.status, 200, okLax.text);
  assert.deepEqual(offersOf(lax.server.files).map((row) => row.id), [offerBody.fileId]);
});

// ---------------------------------------------------------------------------
// 门面签名 / 配置 / store 级单元（与推送模型无关，原样保留）
// ---------------------------------------------------------------------------

test('§3 门面签名：send 失败只回 { ok:false, reason }，不抛', async (t) => {
  const sender = await startServer(t);
  const tiny = await startServer(t, { fileMaxBytes: 8 });
  linkAll([sender, tiny]);

  assert.deepEqual(
    await pick(await sender.server.files.send({ peerId: tiny.server.store.instanceId, path: '/no/such/file.bin' })),
    { ok: false, reason: 'not-found' },
  );
  assert.deepEqual(
    await pick(await sender.server.files.send({ peerId: 'ghost', path: '/tmp/x' })),
    { ok: false, reason: 'unknown-peer' },
  );

  const smallFile = path.join(sender.stateDir, 'small.bin');
  fs.writeFileSync(smallFile, payloadBytes(64));
  assert.deepEqual(
    await pick(await sender.server.files.send({ peerId: tiny.server.store.instanceId, path: smallFile })),
    { ok: false, reason: 'too-large' },
  );
  assert.deepEqual(inboxFiles(tiny.stateDir), []);
  assert.deepEqual(incomingParts(tiny.stateDir), []);
  assert.deepEqual(offersOf(tiny.server.files), []);
});

function pick(result) {
  return { ok: result.ok, reason: result.reason };
}

test('§5 配置旋钮默认值就是契约值', () => {
  const config = resolveConfig({ stateDir: makeTempStateDir('dsh-file-config-') });
  assert.equal(config.fileAutoAccept, false);
  assert.equal(config.fileMaxBytes, 512 * 1024 * 1024);
  assert.equal(config.fileInboxBytes, 2 * 1024 * 1024 * 1024);
  assert.equal(config.fileChunkBytes, 512 * 1024);
  assert.equal(config.filePendingTtlMs, 600_000);
  // 非法值回落默认；块大小硬上限 512KiB（base64 + JSON 后必须留在 1MiB body 限制内）
  const clamped = resolveConfig({
    stateDir: config.stateDir,
    fileAutoAccept: 'yes',
    fileMaxBytes: -1,
    fileInboxBytes: 'nope',
    fileChunkBytes: 8 * 1024 * 1024,
    filePendingTtlMs: 0,
  });
  assert.equal(clamped.fileAutoAccept, false);
  assert.equal(clamped.fileMaxBytes, 512 * 1024 * 1024);
  assert.equal(clamped.fileInboxBytes, 2 * 1024 * 1024 * 1024);
  assert.equal(clamped.fileChunkBytes, 512 * 1024);
  assert.equal(clamped.filePendingTtlMs, 600_000);
});

test('§2 store：重启重建、坏 meta 自愈、越界 id 拒绝', async (t) => {
  const stateDir = makeTempStateDir('dsh-file-store-');
  t.after(() => fs.rmSync(stateDir, { recursive: true, force: true }));
  const store = new FileStore({ stateDir, chunkBytes: 1024 });
  const body = Buffer.from('store-level');
  const hash = sha256(body);

  const offered = store.offer({
    transferId: 's-1',
    name: 'store.bin',
    size: body.length,
    sha256: hash,
    from: { peerId: 'peer-1', name: 'node-1' },
  });
  assert.deepEqual(offered, { accept: true, resumeFrom: 0, dedupe: false });
  assert.deepEqual(store.writeChunk({ transferId: 's-1', offset: 0, data: body }), { received: body.length });
  const done = await store.complete({ transferId: 's-1' });
  assert.equal(done.ok, true);
  assert.equal(done.needConfirm, true);

  // 门面 id 只认服务端生成的 UUID：'../' 这类一律拒绝，绝不拼进路径
  assert.deepEqual(store.accept('../' + done.id), { ok: false, reason: 'unknown-id' });
  assert.deepEqual(store.reject('../../etc'), { ok: false, reason: 'unknown-id' });
  assert.deepEqual(store.progress('nope'), { received: 0, size: 0, state: 'unknown' });

  // 重新打开：「待确认」与「已落盘」都能从磁盘重建（掉电重启）
  const reopened = new FileStore({ stateDir });
  assert.deepEqual(reopened.list().map((entry) => [entry.state, entry.name]), [['pending', 'store.bin']]);
  assert.equal(reopened.accept(done.id).ok, true);
  const afterRestart = new FileStore({ stateDir });
  assert.deepEqual(afterRestart.list().map((entry) => entry.state), ['done']);
  assert.equal(afterRestart.progress(done.id).state, 'done');

  // 半路写坏的待确认目录（只有 meta、没有 data）启动时被清掉
  const brokenId = '11111111-1111-4111-8111-111111111111';
  fs.mkdirSync(path.join(stateDir, 'inbox', '.pending', brokenId), { recursive: true });
  fs.writeFileSync(
    path.join(stateDir, 'inbox', '.pending', brokenId, 'meta.json'),
    JSON.stringify({ id: brokenId, name: 'x', size: 1, sha256: 'a'.repeat(64) }),
  );
  const healed = new FileStore({ stateDir });
  assert.equal(healed.list().length, 1);
  assert.equal(fs.existsSync(path.join(stateDir, 'inbox', '.pending', brokenId)), false);
});

// ---------------------------------------------------------------------------
// S3b：发送方那一半也要看得见（GET files 的 outbox 桶）
//
// 非空化：把 FileOutbox.open() 里的高水位记账拆掉 → 本用例的 pulling / pulled
// 与 pulledBytes 三条断言红；把 admin 的 outbox 白名单换成原样透传 → Q2 的路径断言红。
// ---------------------------------------------------------------------------

test('Q1 发送方看得见自己发出去的那一份：outbox 从 waiting → pulling → pulled（真两块 + 断线）', async (t) => {
  const sender = await startServer(t);
  const receiver = await startServer(t);
  const link = linkAll([sender, receiver]);
  const admin = createAdmin({ server: sender.server });

  const payload = payloadBytes(CHUNK * 2 + 7);   // 3 块
  const localFile = path.join(sender.stateDir, 'outbox-demo.bin');
  fs.writeFileSync(localFile, payload);

  const before = await adminHit(admin, 'GET', '/api/lan-peers/files');
  assert.equal(before.status, 200);
  assert.deepEqual(before.json.outbox, [], '还没发过东西：这一桶是空数组（字段本身必须在）');

  const sent = await adminHit(admin, 'POST', '/api/lan-peers/files/send', {
    peerId: receiver.server.store.instanceId,
    path: localFile,
  });
  assert.equal(sent.status, 200, JSON.stringify(sent.json));

  const waiting = await adminHit(admin, 'GET', '/api/lan-peers/files');
  const row = waiting.json.outbox.find((item) => item.fileId === sent.json.fileId);
  assert.ok(row, '发完之后发送方的 outbox 里必须有这一行');
  assert.equal(row.state, 'waiting', '对方还没拉：waiting');
  assert.equal(row.pulledBytes, 0);
  assert.equal(row.size, payload.length);
  assert.equal(row.sha256, sha256(payload));
  assert.equal(row.name, 'outbox-demo.bin', '名字是清洗过的那一份');
  assert.equal(row.to.peerId, receiver.server.store.instanceId, '这一格就是「送给谁」');
  assert.match(String(row.to.name), /^node-/, 'to.name 取自本机 peers.json（不是对端给的）');
  assert.ok(row.at > 0);

  // Q2：metadata only —— 发送方的落盘布局一个字都不许上线
  assert.deepEqual(Object.keys(row).sort(),
    ['at', 'fileId', 'name', 'pulledBytes', 'sha256', 'size', 'state', 'to']);
  const wire = JSON.stringify(waiting.json);
  assert.equal(wire.includes(sender.stateDir), false, '不许带发送方的 stateDir');
  assert.equal(wire.includes('outbox/'), false, '不许带 keeper 拷贝的落盘路径');
  assert.equal(wire.includes('"path"'), false, '没有 path 这一格');

  // 只服务一块就断：pulling + pulledBytes 在 0 与 size 之间
  const seen = watchPulls(link.key(receiver, sender), { failFrom: 1 });
  let first;
  try {
    first = await receiver.server.files.download(sent.json.fileId);
    assert.deepEqual(seen.offsets, [0, CHUNK], '第 2 块发出去了但没等到回包');
  } finally {
    seen.restore();
  }
  assert.equal(first.ok, false, '这一趟必须失败（否则没有「拉到一半」这件事）');
  const pulling = await adminHit(admin, 'GET', '/api/lan-peers/files');
  const mid = pulling.json.outbox.find((item) => item.fileId === sent.json.fileId);
  assert.equal(mid.state, 'pulling', '拉了一部分就是 pulling');
  assert.equal(mid.pulledBytes, CHUNK, '高水位 = 真被服务出去的那一块');
  assert.ok(mid.pulledBytes > 0 && mid.pulledBytes < payload.length);

  // 续传拉完：pulled，高水位 = size，仍是同一行（不新开一条）
  const second = await receiver.server.files.download(sent.json.fileId);
  assert.equal(second.ok, true, JSON.stringify(second));
  const pulled = await adminHit(admin, 'GET', '/api/lan-peers/files');
  const done = pulled.json.outbox.find((item) => item.fileId === sent.json.fileId);
  assert.equal(done.state, 'pulled', '整份被服务过一次就是 pulled');
  assert.equal(done.pulledBytes, payload.length);
  assert.equal(pulled.json.outbox.length, 1, '一条 keeper 拷贝只占一行');
  assert.equal(sha256(fs.readFileSync(second.path)), sha256(payload), '字节真的被对端拉全了');
});

test('T4 高水位：list() 三态 waiting → pulling → pulled，只增不减，且落在 meta.json 里（重启后还在）', async (t) => {
  const stateDir = makeTempStateDir('dsh-lan-peers-outbox-');
  t.after(() => fs.rmSync(stateDir, { recursive: true, force: true }));
  const bytes = payloadBytes(1000);
  const source = path.join(stateDir, 'src.bin');
  fs.writeFileSync(source, bytes);

  const outbox = new FileOutbox({ stateDir, now: () => 1_000_000 });
  const put = await outbox.put({ name: '报告.pdf', sourcePath: source, to: 'peer-b' });
  assert.equal(put.ok, true, JSON.stringify(put));

  const fresh = outbox.list();
  assert.equal(fresh.length, 1);
  assert.deepEqual(Object.keys(fresh[0]).sort(),
    ['at', 'fileId', 'name', 'pulledBytes', 'sha256', 'size', 'state', 'to'],
    '八格 metadata：没有 path、没有 bytes');
  assert.equal(fresh[0].state, 'waiting', '一个字节都没被拉过');
  assert.equal(fresh[0].pulledBytes, 0);
  assert.equal(fresh[0].to, 'peer-b', 'FileOutbox 里 to 还是裸 peerId（补名字的是 server 门面）');

  outbox.open(put.fileId, 0, 400);
  assert.equal(outbox.list()[0].state, 'pulling');
  assert.equal(outbox.list()[0].pulledBytes, 400, '高水位 = 服务出去的最远偏移');

  // 重发同一片（回到 0）不许把高水位往回拨
  outbox.open(put.fileId, 0, 400);
  assert.equal(outbox.list()[0].pulledBytes, 400, '只增不减');

  outbox.open(put.fileId, 400, 600);
  assert.equal(outbox.list()[0].state, 'pulled', '整份被服务过一次就是 pulled');

  // 拉完那一趟必须落一次盘：重启之后不能退回 pulling
  const reopened = new FileOutbox({ stateDir, now: () => 1_000_000 });
  assert.equal(reopened.list()[0].pulledBytes, 1000, '高水位落在 outbox/<fileId>/meta.json 里');
  assert.equal(reopened.list()[0].state, 'pulled');

  // 三态只有一处实现
  assert.equal(pullStateOf({ size: 10, servedBytes: 0 }), 'waiting');
  assert.equal(pullStateOf({ size: 10, servedBytes: 3 }), 'pulling');
  assert.equal(pullStateOf({ size: 10, servedBytes: 10 }), 'pulled');

  // 逐出之后这一行就没了（墓碑不外露）
  outbox.drop(put.fileId, 'test');
  assert.deepEqual(outbox.list(), []);
});
