/**
 * 0.8.5-α 契约 §1–§3 / §5 / §6：文件互传协议 + 落盘 + 门面。
 *
 * 两条真节点（同一进程里两个 createPeerServer，走真实 HTTP）覆盖端到端；
 * 纯函数与 store 级用例覆盖清洗、限额、TTL、重启重建。
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';

import { FILE_V1_PATHS, resolveConfig } from '../server.mjs';
import { FileStore, isReservedFileName, sanitizeFileName } from '../../lib/file-store.mjs';
import { makeTempStateDir, peerFixture, request, seedPeers, startServer } from './helpers.mjs';

const sha256 = (buffer) => createHash('sha256').update(buffer).digest('hex');

/** 确定性内容（不用随机：失败时 sha256 稳定可查） */
function payloadBytes(length) {
  const buffer = Buffer.alloc(length);
  for (let index = 0; index < length; index += 1) buffer[index] = (index * 31 + 7) & 0xff;
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

/** 以 sender 的身份对 receiver 发签名 + 加密请求 */
function peerFrom(sender, receiver, secret) {
  const peerId = sender.server.store.instanceId;
  const base = { peerId, secret, encrypt: true };
  return {
    post: (apiPath, body) => request(receiver.baseUrl, { ...base, method: 'POST', path: apiPath, body }),
    get: (apiPath) => request(receiver.baseUrl, { ...base, method: 'GET', path: apiPath }),
  };
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

// ---------------------------------------------------------------------------
// §1 端到端
// ---------------------------------------------------------------------------

test('§1/§6.1 端到端：offer → chunk → complete → 待确认 → accept 落盘，两端 sha256 一致', async (t) => {
  const sender = await startServer(t, { fileChunkBytes: 256 * 1024 });
  const receiver = await startServer(t, { fileChunkBytes: 256 * 1024 });
  linkAll([sender, receiver]);

  const payload = payloadBytes(700 * 1024 + 123);
  const localFile = path.join(sender.stateDir, 'payload.bin');
  fs.writeFileSync(localFile, payload);
  const expected = sha256(payload);

  const sent = await sender.server.files.send({
    peerId: receiver.server.store.instanceId,
    path: localFile,
  });
  assert.equal(sent.ok, true, JSON.stringify(sent));
  assert.equal(sent.bytes, payload.length);
  assert.equal(sent.sha256, expected);
  assert.equal(sent.resumeFrom, 0);
  assert.equal(sent.needConfirm, true);
  assert.ok(Number.isFinite(sent.ms));

  // 接收端：待确认区里恰好一条，meta 逐字段对齐契约 §2
  const pending = receiver.server.files.list();
  assert.equal(pending.length, 1);
  assert.equal(pending[0].id, sent.id);
  assert.equal(pending[0].name, 'payload.bin');
  assert.equal(pending[0].size, payload.length);
  assert.equal(pending[0].sha256, expected);
  assert.equal(pending[0].state, 'pending');
  assert.equal(pending[0].from.peerId, sender.server.store.instanceId);
  assert.ok(Number.isFinite(pending[0].at));
  assert.ok(fs.existsSync(path.join(receiver.stateDir, 'inbox', '.pending', sent.id, 'meta.json')));
  assert.deepEqual(
    receiver.server.files.progress(sent.id),
    { received: payload.length, size: payload.length, state: 'pending' },
  );

  // 确认 → 落盘 inbox/<id>__<清洗后文件名>
  const accepted = receiver.server.files.accept(sent.id);
  assert.equal(accepted.ok, true, JSON.stringify(accepted));
  assert.ok(accepted.path.startsWith(path.join(receiver.stateDir, 'inbox') + path.sep), accepted.path);
  assert.equal(path.basename(accepted.path), sent.id + '__payload.bin');
  assert.equal(sha256(fs.readFileSync(accepted.path)), expected);
  assert.deepEqual(receiver.server.files.list().map((entry) => entry.state), ['done']);
  assert.deepEqual(
    receiver.server.files.progress(sent.id),
    { received: payload.length, size: payload.length, state: 'done' },
  );
  assert.equal(receiver.server.files.reject('00000000-0000-4000-8000-000000000000').ok, false);
});

test('§2/§6.2 中途断开 → 重新 send 同一文件 → 从 resumeFrom 续传', async (t) => {
  const sender = await startServer(t, { fileChunkBytes: 64 * 1024 });
  const receiver = await startServer(t, { fileChunkBytes: 64 * 1024 });
  const link = linkAll([sender, receiver]);
  const api = peerFrom(sender, receiver, link.key(sender, receiver));

  const payload = payloadBytes(200 * 1024);
  const localFile = path.join(sender.stateDir, 'resume.bin');
  fs.writeFileSync(localFile, payload);
  const expected = sha256(payload);
  const chunkBytes = 64 * 1024;
  const completedBytes = chunkBytes * 3;

  // 发送端只推到第 3 块就被「kill」：没有 complete，.part 留在 .incoming
  const transferId = 'abandoned-but-resumable';
  const offered = await api.post('/v1/file/offer', {
    transferId,
    name: 'resume.bin',
    size: payload.length,
    sha256: expected,
    chunkBytes,
  });
  assert.equal(offered.status, 200, offered.text);
  assert.deepEqual(offered.json, { accept: true, resumeFrom: 0, dedupe: false });

  for (let offset = 0; offset < completedBytes; offset += chunkBytes) {
    const slice = payload.subarray(offset, offset + chunkBytes);
    const chunk = await api.post('/v1/file/chunk', { transferId, offset, data: slice.toString('base64') });
    assert.equal(chunk.status, 200, chunk.text);
    assert.equal(chunk.json.received, offset + chunkBytes);
  }
  assert.equal(incomingParts(receiver.stateDir).length, 1);

  // 换一条新 send（新 transferId）：offer 必须报 resumeFrom = 已收字节
  const resumed = await sender.server.files.send({
    peerId: receiver.server.store.instanceId,
    path: localFile,
  });
  assert.equal(resumed.ok, true, JSON.stringify(resumed));
  assert.equal(resumed.resumeFrom, completedBytes);
  assert.equal(resumed.sha256, expected);
  assert.equal(resumed.bytes, payload.length);

  const accepted = receiver.server.files.accept(resumed.id);
  assert.equal(accepted.ok, true, JSON.stringify(accepted));
  assert.equal(sha256(fs.readFileSync(accepted.path)), expected);
});

test('§1 空文件（size=0）也能走完 offer → complete，sha256 = e3b0c442…', async (t) => {
  const sender = await startServer(t);
  const receiver = await startServer(t);
  linkAll([sender, receiver]);
  const empty = path.join(sender.stateDir, 'empty.bin');
  fs.writeFileSync(empty, Buffer.alloc(0));

  const sent = await sender.server.files.send({ peerId: receiver.server.store.instanceId, path: empty });
  assert.equal(sent.ok, true, JSON.stringify(sent));
  assert.equal(sent.bytes, 0);
  assert.equal(sent.sha256, sha256(Buffer.alloc(0)));
  const accepted = receiver.server.files.accept(sent.id);
  assert.equal(accepted.ok, true, JSON.stringify(accepted));
  assert.equal(fs.statSync(accepted.path).size, 0);
});

test('§2/§6.4 同内容二次发送 → dedupe:true 且不写新文件', async (t) => {
  const sender = await startServer(t, { fileChunkBytes: 64 * 1024 });
  const receiver = await startServer(t, { fileChunkBytes: 64 * 1024 });
  linkAll([sender, receiver]);

  const payload = payloadBytes(150 * 1024);
  const localFile = path.join(sender.stateDir, 'once.bin');
  fs.writeFileSync(localFile, payload);

  const first = await sender.server.files.send({ peerId: receiver.server.store.instanceId, path: localFile });
  assert.equal(first.ok, true, JSON.stringify(first));
  assert.equal(receiver.server.files.accept(first.id).ok, true);
  assert.equal(inboxFiles(receiver.stateDir).length, 1);

  const second = await sender.server.files.send({ peerId: receiver.server.store.instanceId, path: localFile });
  assert.equal(second.ok, true, JSON.stringify(second));
  assert.equal(second.dedupe, true);
  assert.equal(second.sent, 0);
  assert.equal(second.sha256, first.sha256);
  assert.equal(inboxFiles(receiver.stateDir).length, 1);
  assert.deepEqual(receiver.server.files.list().map((entry) => entry.state), ['done']);

  // 还在待确认区的同一份内容再传 → duplicate-pending（inbox 里不堆两份）
  const other = await startServer(t, { fileChunkBytes: 64 * 1024 });
  linkAll([sender, other]);
  const dupFirst = await sender.server.files.send({ peerId: other.server.store.instanceId, path: localFile });
  assert.equal(dupFirst.ok, true, JSON.stringify(dupFirst));
  const dupSecond = await sender.server.files.send({ peerId: other.server.store.instanceId, path: localFile });
  assert.equal(dupSecond.ok, false);
  assert.equal(dupSecond.reason, 'duplicate-pending');
});

// ---------------------------------------------------------------------------
// §6.5 路径穿越 / 保留名
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

  // 协议口径：目录成分丢掉，落盘路径仍在 inbox 之内
  const receiver = await startServer(t);
  const sender = await startServer(t);
  const link = linkAll([sender, receiver]);
  const api = peerFrom(sender, receiver, link.key(sender, receiver));
  const body = Buffer.from('traversal');

  const offered = await api.post('/v1/file/offer', {
    transferId: 'traversal-1',
    name: '../../../../etc/passwd',
    size: body.length,
    sha256: sha256(body),
    chunkBytes: 1024,
  });
  assert.equal(offered.status, 200, offered.text);
  assert.equal(offered.json.accept, true);
  const chunk = await api.post('/v1/file/chunk', {
    transferId: 'traversal-1',
    offset: 0,
    data: body.toString('base64'),
  });
  assert.equal(chunk.status, 200, chunk.text);
  const completed = await api.post('/v1/file/complete', { transferId: 'traversal-1' });
  assert.equal(completed.status, 200, completed.text);
  const accepted = receiver.server.files.accept(completed.json.id);
  assert.equal(accepted.ok, true, JSON.stringify(accepted));
  assert.equal(path.basename(accepted.path), completed.json.id + '__passwd');
  assert.ok(accepted.path.startsWith(path.join(receiver.stateDir, 'inbox') + path.sep));
  assert.equal(fs.readFileSync(accepted.path).toString(), 'traversal');
  assert.equal(fs.existsSync(path.join(receiver.stateDir, 'etc')), false);
  assert.equal(fs.existsSync(path.join(path.dirname(receiver.stateDir), 'passwd')), false);

  // 保留名直接拒收，盘上不留分片
  for (const reserved of ['CON', 'con.txt', 'COM1', 'LPT9.dat']) {
    const rejected = await api.post('/v1/file/offer', {
      transferId: 'reserved-' + reserved,
      name: reserved,
      size: 4,
      sha256: 'f'.repeat(64),
      chunkBytes: 1024,
    });
    assert.equal(rejected.status, 400, reserved + ' ' + rejected.text);
    assert.deepEqual(rejected.json, { accept: false, reason: 'bad-name' });
  }
  assert.deepEqual(incomingParts(receiver.stateDir), []);
});

// ---------------------------------------------------------------------------
// §6.6 限额
// ---------------------------------------------------------------------------

test('§6.6 超 fileMaxBytes / inbox 满 / 并发超 2 → 明确 reason，不落盘', async (t) => {
  const receiver = await startServer(t, { fileMaxBytes: 1024, fileInboxBytes: 1000 });
  const sender = await startServer(t);
  const link = linkAll([sender, receiver]);
  const api = peerFrom(sender, receiver, link.key(sender, receiver));

  const tooLarge = await api.post('/v1/file/offer', {
    transferId: 'big',
    name: 'big.bin',
    size: 2048,
    sha256: 'a'.repeat(64),
    chunkBytes: 1024,
  });
  assert.equal(tooLarge.status, 413, tooLarge.text);
  assert.deepEqual(tooLarge.json, { accept: false, reason: 'too-large' });

  // 600 字节收下（还没 complete）→ 再来 600 字节就超 inbox 总量
  const first = await api.post('/v1/file/offer', {
    transferId: 'fit-1',
    name: 'one.bin',
    size: 600,
    sha256: 'b'.repeat(64),
    chunkBytes: 600,
  });
  assert.equal(first.status, 200, first.text);
  const full = await api.post('/v1/file/offer', {
    transferId: 'fit-2',
    name: 'two.bin',
    size: 600,
    sha256: 'c'.repeat(64),
    chunkBytes: 600,
  });
  assert.equal(full.status, 409, full.text);
  assert.deepEqual(full.json, { accept: false, reason: 'inbox-full' });

  // 并发 ≤2：此刻在跑的是 fit-1，再开一个就满了
  const second = await api.post('/v1/file/offer', {
    transferId: 'fit-3',
    name: 'three.bin',
    size: 400,
    sha256: 'd'.repeat(64),
    chunkBytes: 400,
  });
  assert.equal(second.status, 200, second.text);
  const third = await api.post('/v1/file/offer', {
    transferId: 'fit-4',
    name: 'four.bin',
    size: 100,
    sha256: 'e'.repeat(64),
    chunkBytes: 100,
  });
  assert.equal(third.status, 429, third.text);
  assert.deepEqual(third.json, { accept: false, reason: 'busy' });

  // 被拒的请求一个字节都没落盘
  assert.equal(incomingParts(receiver.stateDir).length, 2);
  assert.deepEqual(inboxFiles(receiver.stateDir), []);
});

// ---------------------------------------------------------------------------
// §6.3 TTL
// ---------------------------------------------------------------------------

test('§6.3 未确认超过 filePendingTtlMs → 自动拒收删除，inbox 干净', async (t) => {
  let clock = Date.now();
  const receiver = await startServer(t, { now: () => clock, filePendingTtlMs: 1000 });
  const sender = await startServer(t, { now: () => clock });
  const link = linkAll([sender, receiver]);
  const api = peerFrom(sender, receiver, link.key(sender, receiver));

  const body = Buffer.from('ttl-body');
  const offered = await api.post('/v1/file/offer', {
    transferId: 'ttl-1',
    name: 'ttl.bin',
    size: body.length,
    sha256: sha256(body),
    chunkBytes: 1024,
  });
  assert.equal(offered.status, 200, offered.text);
  await api.post('/v1/file/chunk', { transferId: 'ttl-1', offset: 0, data: body.toString('base64') });
  const completed = await api.post('/v1/file/complete', { transferId: 'ttl-1' });
  assert.equal(completed.status, 200, completed.text);
  assert.equal(completed.json.needConfirm, true);
  assert.equal(receiver.server.files.list().length, 1);

  // 时钟跳过 TTL，驱动一次定时清理（不 sleep）
  clock += 1001;
  assert.equal(receiver.server.files.sweep(), 1);
  assert.deepEqual(receiver.server.files.list(), []);
  assert.deepEqual(inboxFiles(receiver.stateDir), []);
  assert.equal(fs.existsSync(path.join(receiver.stateDir, 'inbox', '.pending', completed.json.id)), false);
  assert.deepEqual(
    (await api.get('/v1/file/status?transferId=ttl-1')).json,
    { received: body.length, size: body.length, state: 'rejected' },
  );
  assert.equal(receiver.server.files.accept(completed.json.id).ok, false);
});

test('§5 fileAutoAccept=true → complete 直接进 inbox，needConfirm:false', async (t) => {
  const receiver = await startServer(t, { fileAutoAccept: true });
  const sender = await startServer(t);
  linkAll([sender, receiver]);
  const payload = payloadBytes(9 * 1024);
  const localFile = path.join(sender.stateDir, 'auto.bin');
  fs.writeFileSync(localFile, payload);

  const sent = await sender.server.files.send({ peerId: receiver.server.store.instanceId, path: localFile });
  assert.equal(sent.ok, true, JSON.stringify(sent));
  assert.equal(sent.needConfirm, false);
  const acceptedPath = path.join(receiver.stateDir, 'inbox', sent.id + '__auto.bin');
  assert.equal(fs.existsSync(acceptedPath), true);
  assert.equal(sha256(fs.readFileSync(acceptedPath)), sha256(payload));
  assert.deepEqual(receiver.server.files.list().map((entry) => entry.state), ['done']);
});

// ---------------------------------------------------------------------------
// §1 错误码 / 鉴权
// ---------------------------------------------------------------------------

test('§1 bad-offset → 409{expected}；unknown-transfer → 404；checksum-mismatch → 422', async (t) => {
  const receiver = await startServer(t);
  const sender = await startServer(t);
  const link = linkAll([sender, receiver]);
  const api = peerFrom(sender, receiver, link.key(sender, receiver));
  const body = Buffer.from('abcdefgh');

  const offered = await api.post('/v1/file/offer', {
    transferId: 'errs-1',
    name: 'errs.bin',
    size: body.length,
    sha256: '0'.repeat(64), // 故意的假摘要：complete 必然不匹配
    chunkBytes: 4,
  });
  assert.equal(offered.status, 200, offered.text);
  assert.deepEqual(offered.json, { accept: true, resumeFrom: 0, dedupe: false });

  const badOffset = await api.post('/v1/file/chunk', { transferId: 'errs-1', offset: 99, data: body.toString('base64') });
  assert.equal(badOffset.status, 409, badOffset.text);
  assert.deepEqual(badOffset.json, { error: 'bad-offset', expected: 0 });

  const okChunk = await api.post('/v1/file/chunk', { transferId: 'errs-1', offset: 0, data: body.toString('base64') });
  assert.equal(okChunk.status, 200, okChunk.text);
  assert.deepEqual(okChunk.json, { received: body.length });

  const mismatch = await api.post('/v1/file/complete', { transferId: 'errs-1' });
  assert.equal(mismatch.status, 422, mismatch.text);
  assert.deepEqual(mismatch.json, { error: 'checksum-mismatch' });
  assert.deepEqual(incomingParts(receiver.stateDir), []);

  const unknown = await api.post('/v1/file/chunk', { transferId: 'never-offered', offset: 0, data: body.toString('base64') });
  assert.equal(unknown.status, 404, unknown.text);
  assert.deepEqual(unknown.json, { error: 'unknown-transfer' });
  assert.equal((await api.get('/v1/file/status?transferId=never-offered')).status, 404);

  // 已知路径用错方法 405；未知 /v1/file/* 404
  const wrongMethod = await api.get('/v1/file/offer');
  assert.equal(wrongMethod.status, 405, wrongMethod.text);
  assert.equal(wrongMethod.json.error, 'method-not-allowed');
  const notFound = await api.post('/v1/file/nope', {});
  assert.equal(notFound.status, 404, notFound.text);
  assert.deepEqual([...FILE_V1_PATHS].sort(), [
    '/v1/file/chunk',
    '/v1/file/complete',
    '/v1/file/offer',
    '/v1/file/status',
  ]);
});

test('§0/§6.7 未配对对端 → 401；缺加密信封 → 400 encryption-required', async (t) => {
  const lax = await startServer(t);
  const strict = await startServer(t, { requireEncryption: true });
  const sender = await startServer(t);
  const laxLink = linkAll([sender, lax]);
  const strictLink = linkAll([sender, strict]);
  const offerBody = {
    transferId: 'auth-1',
    name: 'auth.bin',
    size: 4,
    sha256: 'a'.repeat(64),
    chunkBytes: 1024,
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
  const ok = await peerFrom(sender, strict, strictLink.key(sender, strict)).post('/v1/file/offer', offerBody);
  assert.equal(ok.status, 200, ok.text);
  assert.equal(ok.json.accept, true);

  // lax 也通（续用 laxLink，避免「先 seed 后覆盖」把对端弄丢）
  const okLax = await peerFrom(sender, lax, laxLink.key(sender, lax)).post('/v1/file/offer', offerBody);
  assert.equal(okLax.status, 200, okLax.text);
});

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
});

function pick(result) {
  return { ok: result.ok, reason: result.reason };
}

// ---------------------------------------------------------------------------
// §5 配置 + store 级单元
// ---------------------------------------------------------------------------

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
