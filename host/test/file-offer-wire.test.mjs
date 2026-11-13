// dsh-lan-peers · 0.12.0-alpha（S1）单发 offer/pull 模型：真节点端到端。
//
// 两条真 createPeerServer（真实 HTTP、真实签名/信封）覆盖：
//   T4 offer（只有 metadata）→ 逐块 pull → sha256 对齐 → 落 inbox
//   T5 holder 返回被改过的字节 → integrity-failed，半截文件删掉，什么都没有落地
//   T6 授权：别人拉 403 / 未知 404 unknown-file / 逐出 409 file-gone
//   T7 信任：默认 false，files/trust 翻转后 GET files 的 offer 带 trusted
//   T8 收回：withdraw 之后对方那条待下载消失
//   T9 非空性：见文末注释（哪条断言会因为去掉 sha 校验 / 授权而变红）
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';

import { FileTrust } from '../../lib/file-offer.mjs';
import { peerFixture, request, seedPeers, startServer } from './helpers.mjs';

const sha256 = (buffer) => createHash('sha256').update(buffer).digest('hex');

/** 确定性内容（不用随机：失败时 sha256 稳定可查） */
function payloadBytes(length) {
  const buffer = Buffer.alloc(length);
  for (let index = 0; index < length; index += 1) buffer[index] = (index * 37 + 11) & 0xff;
  return buffer;
}

/** 让若干节点互相成为对端（跳过配对流程，与其他用例同一口径） */
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

// ---------------------------------------------------------------------------
// T4
// ---------------------------------------------------------------------------

test('T4 offer→pull 全程：对端零字节、逐块拉 3 次、sha256 对齐、条目移入 inbox', async (t) => {
  const sender = await startServer(t);
  const receiver = await startServer(t);
  linkAll([sender, receiver]);

  const payload = payloadBytes(1100 * 1024 + 7);   // 512KiB × 2 + 剩余 → 正好 3 块
  const localFile = path.join(sender.stateDir, 'payload.bin');
  fs.writeFileSync(localFile, payload);
  const expected = sha256(payload);

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
  const kept = path.join(sender.stateDir, 'outbox', offered.fileId, 'data');
  assert.equal(fs.statSync(kept).size, payload.length);

  // 接收方：只有一条待下载 + 只有 meta.json —— 一个字节都不落盘
  const offers = offersOf(receiver.server.files);
  assert.equal(offers.length, 1);
  assert.deepEqual(
    { id: offers[0].id, name: offers[0].name, size: offers[0].size, sha256: offers[0].sha256 },
    { id: offered.fileId, name: 'payload.bin', size: payload.length, sha256: expected },
  );
  assert.equal(offers[0].from.peerId, sender.server.store.instanceId);
  assert.equal(offers[0].trusted, false, '没信任过的 peer 默认不信任');
  assert.deepEqual(
    fs.readdirSync(path.join(receiver.stateDir, 'offers', offered.fileId)).sort(),
    ['meta.json'],
    '待下载条目只有 meta.json',
  );
  assert.deepEqual(inboxFiles(receiver.stateDir), [], '还没下载，inbox 必须空');
  assert.deepEqual(incomingParts(receiver.stateDir), [], '还没下载，没有半截分片');

  // 数一数真的拉了几块：pull 是逐块的，不是一次性整个文件
  let pulls = 0;
  sender.server.httpServer.on('request', (req) => {
    if (String(req.url ?? '') === '/v1/file/pull') pulls += 1;
  });

  const downloaded = await receiver.server.files.download(offered.fileId);
  assert.equal(downloaded.ok, true, JSON.stringify(downloaded));
  assert.equal(downloaded.bytes, payload.length);
  assert.equal(downloaded.sha256, expected);
  assert.equal(pulls, 3, '1100KiB+7 字节按 512KiB 一块 → 恰好 3 次 pull');

  const landed = inboxFiles(receiver.stateDir);
  assert.equal(landed.length, 1);
  assert.equal(sha256(fs.readFileSync(path.join(receiver.stateDir, 'inbox', landed[0]))), expected);
  assert.equal(offersOf(receiver.server.files).length, 0, '下载完那条待下载条目消失');
  assert.deepEqual(incomingParts(receiver.stateDir), [], '拼完就没有半截分片了');
  assert.equal(receiver.server.files.list().filter((row) => row.state === 'done').length, 1);
});

// ---------------------------------------------------------------------------
// T5
// ---------------------------------------------------------------------------

test('T5 完整性：holder 回来的字节被改过 → integrity-failed，半截文件删掉，什么都不落', async (t) => {
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
  assert.equal(offersOf(receiver.server.files).length, 0, '这条待下载作废，别再让人点第二次');
});

// ---------------------------------------------------------------------------
// T6
// ---------------------------------------------------------------------------

test('T6 授权：别人的 id 拉 403 / 未知 404 unknown-file / 逐出 409 file-gone', async (t) => {
  const sender = await startServer(t);
  const receiver = await startServer(t);
  const eve = await startServer(t);
  const link = linkAll([sender, receiver, eve]);

  const localFile = path.join(sender.stateDir, 'payload.bin');
  fs.writeFileSync(localFile, payloadBytes(1024));
  const offered = await sender.server.files.send({
    peerId: receiver.server.store.instanceId,
    path: localFile,
  });
  assert.equal(offered.ok, true, JSON.stringify(offered));

  // 1) eve 也是 sender 的合法对端（签名过得去），但这份 offer 不是给它的
  const eavesdrop = await signedFrom(eve, sender, link.key(eve, sender))('/v1/file/pull', {
    fileId: offered.fileId,
    offset: 0,
  });
  assert.equal(eavesdrop.status, 403);
  assert.deepEqual(eavesdrop.json, { error: 'forbidden' });
  assert.equal(eavesdrop.text.includes('dataBase64'), false, '403 的身体里绝不能夹带字节');

  // 2) 不认识的 id → 404 unknown-file（「没有过」）
  const unknown = await signedFrom(receiver, sender, link.key(receiver, sender))('/v1/file/pull', {
    fileId: randomUUID(),
    offset: 0,
  });
  assert.equal(unknown.status, 404);
  assert.deepEqual(unknown.json, { error: 'unknown-file' });

  // 3) 被逐出（TTL 到点）→ 409 file-gone（「有过，但没了」）
  sender.server.files.sweep(Date.now() + 8 * 24 * 60 * 60 * 1000);
  const gone = await signedFrom(receiver, sender, link.key(receiver, sender))('/v1/file/pull', {
    fileId: offered.fileId,
    offset: 0,
  });
  assert.equal(gone.status, 409);
  assert.deepEqual(gone.json, { error: 'file-gone' });
  assert.equal(fs.existsSync(path.join(sender.stateDir, 'outbox', offered.fileId)), false, '逐出删目录');

  // 4) 越界偏移 → 400 bad-offset（重新挂一份来测，因为上一条已被逐出）
  const second = await sender.server.files.send({
    peerId: receiver.server.store.instanceId,
    path: localFile,
  });
  const badOffset = await signedFrom(receiver, sender, link.key(receiver, sender))('/v1/file/pull', {
    fileId: second.fileId,
    offset: 4096,
  });
  assert.equal(badOffset.status, 400);
  assert.equal(badOffset.json.error, 'bad-offset');

  // 5) 正常那一块是 base64 明文，且 offset/eof 如实回报
  const ok = await signedFrom(receiver, sender, link.key(receiver, sender))('/v1/file/pull', {
    fileId: second.fileId,
    offset: 0,
  });
  assert.equal(ok.status, 200);
  assert.equal(ok.json.offset, 0);
  assert.equal(ok.json.eof, true, '1024 字节一次就到底');
  assert.equal(Buffer.from(ok.json.dataBase64, 'base64').length, 1024);
});

// ---------------------------------------------------------------------------
// T7
// ---------------------------------------------------------------------------

test('T7 信任：默认 false → files/trust 翻 true → GET files 的 offer 带 trusted', async (t) => {
  const sender = await startServer(t);
  const receiver = await startServer(t);
  linkAll([sender, receiver]);

  const localFile = path.join(sender.stateDir, 'payload.bin');
  fs.writeFileSync(localFile, payloadBytes(64));
  const offered = await sender.server.files.send({
    peerId: receiver.server.store.instanceId,
    path: localFile,
  });
  assert.equal(offered.ok, true, JSON.stringify(offered));

  const senderId = sender.server.store.instanceId;
  assert.equal(offersOf(receiver.server.files)[0].trusted, false, '默认不信任');
  assert.equal(receiver.server.files.isTrusted(senderId), false);

  const set = await receiver.server.files.setTrust(senderId, true);
  assert.equal(set.ok, true);
  assert.equal(receiver.server.files.isTrusted(senderId), true);
  assert.equal(offersOf(receiver.server.files)[0].trusted, true, '信任标记必须出现在 offer 视图里');

  await receiver.server.files.setTrust(senderId, false);
  assert.equal(offersOf(receiver.server.files)[0].trusted, false);

  // 坏 file-trust.json = 谁都不信任，且不抛（面板不能因为一个坏 JSON 就打不开）
  fs.writeFileSync(path.join(receiver.stateDir, 'file-trust.json'), 'not json at all');
  const broken = new FileTrust({ stateDir: receiver.stateDir });
  assert.equal(broken.isTrusted(senderId), false);
  assert.deepEqual(broken.list(), []);
});

// ---------------------------------------------------------------------------
// T8
// ---------------------------------------------------------------------------

test('T8 收回：sender withdraw 之后，接收方那条待下载消失（重复收回幂等）', async (t) => {
  const sender = await startServer(t);
  const receiver = await startServer(t);
  const link = linkAll([sender, receiver]);

  const localFile = path.join(sender.stateDir, 'payload.bin');
  fs.writeFileSync(localFile, payloadBytes(32));
  const offered = await sender.server.files.send({
    peerId: receiver.server.store.instanceId,
    path: localFile,
  });
  assert.equal(offersOf(receiver.server.files).length, 1);

  const withdraw = await signedFrom(sender, receiver, link.key(sender, receiver))('/v1/file/withdraw', {
    fileId: offered.fileId,
  });
  assert.equal(withdraw.status, 200);
  assert.deepEqual(withdraw.json, { ok: true, removed: true });
  assert.equal(offersOf(receiver.server.files).length, 0, '收到 withdraw 就把待下载条目删掉');
  assert.equal(fs.existsSync(path.join(receiver.stateDir, 'offers', offered.fileId)), false);

  // 幂等：再收一次只是 removed:false，不是错误
  const again = await signedFrom(sender, receiver, link.key(sender, receiver))('/v1/file/withdraw', {
    fileId: offered.fileId,
  });
  assert.equal(again.status, 200);
  assert.deepEqual(again.json, { ok: true, removed: false });
});

// ---------------------------------------------------------------------------
// T9 非空性（反向证明：这两条断言不是摆设）
//
// - 去掉 sha256 校验（fileStore.complete 里那句 digest !== part.sha256）：T5 的
//   assert.equal(downloaded.reason, 'integrity-failed') 立刻变红 —— 改过的字节会被
//   当成好文件收下，inbox 里会多出一份内容与声明不符的文件，紧接着
//   assert.deepEqual(inboxFiles(receiver.stateDir), []) 也会红。
// - 去掉 pull 授权（filePull 里 found.entry.to !== auth.peerId 那一段）：T6 的第一条
//   assert.equal(eavesdrop.status, 403) 变红（会变成 200 + 真字节），而
//   assert.equal(eavesdrop.text.includes('dataBase64'), false) 会跟着红 —— 一个没被
//   offer 的 peer 也把文件拉走了。
// ---------------------------------------------------------------------------
