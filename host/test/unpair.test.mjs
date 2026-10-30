/**
 * v0.4.1 · 手动取消配对（unpair）。
 *
 * 覆盖：StateStore.removePeer 的落盘/幂等/不清别人；POST /v1/unpair 只删请求方、
 *      未签名 401、删完再请求 401 unknown-peer、GET 405、加密门控与 /v1/ask 一致、
 *      删掉后该 peer 挂起的 ECDH 握手一并作废。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { StateStore } from '../server.mjs';
import { fileMode, makeTempStateDir, peerFixture, readJson, request, seedPeers, startServer } from './helpers.mjs';
import { generateKeyPair } from '../../lib/pairing-ecdh.mjs';

const A = { peerId: 'peer-a', secret: peerFixture('peer-a').secret, inboundSecret: peerFixture('peer-a').inboundSecret };
const B = { peerId: 'peer-b', secret: peerFixture('peer-b').secret, inboundSecret: peerFixture('peer-b').inboundSecret };

// ---------------------------------------------------------------------------
// StateStore.removePeer
// ---------------------------------------------------------------------------

test('removePeer 删条目并 0600 落盘，重复删除返回 false 且不抛错', (t) => {
  const stateDir = makeTempStateDir();
  t.after(() => fs.rmSync(stateDir, { recursive: true, force: true }));
  seedPeers(stateDir, [peerFixture('peer-a'), peerFixture('peer-b')]);
  const store = new StateStore({ stateDir, name: 'me' });

  assert.equal(store.removePeer('peer-a'), true);
  const onDisk = readJson(path.join(stateDir, 'peers.json'));
  assert.equal(Object.keys(onDisk.peers).length, 1, '只剩一个 peer');
  assert.equal(onDisk.peers['peer-a'], undefined, '被删的 peer 必须从磁盘消失');
  assert.ok(onDisk.peers['peer-b'], '别人的条目不能被牵连');
  if (process.platform !== 'win32') assert.equal(fileMode(path.join(stateDir, 'peers.json')), 0o600);

  // 幂等：第二次、以及从未见过的 peerId 都只返回 false
  assert.equal(store.removePeer('peer-a'), false);
  assert.equal(store.removePeer('peer-never'), false);
  assert.equal(store.removePeer(''), false);
  assert.equal(Object.keys(readJson(path.join(stateDir, 'peers.json')).peers).length, 1);
});

test('removePeer 先读盘：不覆盖同机 CLI 刚写入的对端', (t) => {
  const stateDir = makeTempStateDir();
  t.after(() => fs.rmSync(stateDir, { recursive: true, force: true }));
  seedPeers(stateDir, [peerFixture('peer-a')]);
  const store = new StateStore({ stateDir, name: 'me' });
  assert.equal(store.listPeers().length, 1);

  // 另一个进程（CLI）在 server 内存不变的情况下加了一条
  seedPeers(stateDir, [peerFixture('peer-a'), peerFixture('peer-b')]);
  assert.equal(store.removePeer('peer-a'), true);
  const onDisk = readJson(path.join(stateDir, 'peers.json'));
  assert.ok(onDisk.peers['peer-b'], 'CLI 刚写的 peer-b 必须保留');
  assert.equal(onDisk.peers['peer-a'], undefined);
});

test('removePeer 清掉写盘节流记录：重新配对的 peer 第一次 touch 立刻落盘', (t) => {
  const stateDir = makeTempStateDir();
  t.after(() => fs.rmSync(stateDir, { recursive: true, force: true }));
  seedPeers(stateDir, []);
  const store = new StateStore({ stateDir, name: 'me', now: () => 1_000_000 });

  store.upsertPeer('peer-a', { name: 'a', secret: 's', inboundSecret: 't' });
  store.touchPeer('peer-a', 1_000_000);        // 超过 30s 阈值 → 记账并落盘
  assert.ok(readJson(path.join(stateDir, 'peers.json')).peers['peer-a'].lastSeen);

  assert.equal(store.removePeer('peer-a'), true);
  assert.equal(readJson(path.join(stateDir, 'peers.json')).peers['peer-a'], undefined);

  // 重新配对后 5s 内 touch：若节流记录没被清掉，这次写盘会被 30s 阈值吃掉
  store.upsertPeer('peer-a', { name: 'a2', secret: 's', inboundSecret: 't' });
  store.touchPeer('peer-a', 1_005_000);
  const after = readJson(path.join(stateDir, 'peers.json')).peers['peer-a'];
  assert.ok(after, '重新配对的 peer 应存在');
  assert.ok(after.lastSeen, 'first touch 必须落盘（节流记录已随删除清掉）');
});

// ---------------------------------------------------------------------------
// POST /v1/unpair
// ---------------------------------------------------------------------------

test('/v1/unpair 签名成功只删请求方，剩余数量正确，删完再请求 401 unknown-peer', async (t) => {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [peerFixture('peer-a'), peerFixture('peer-b')]);
  const { baseUrl } = await startServer(t, { stateDir });

  // 无 body 也应合法（canonical 的 body 摘要 = sha256("")）
  const removed = await request(baseUrl, {
    method: 'POST',
    path: '/v1/unpair',
    peerId: A.peerId,
    secret: A.inboundSecret,
  });
  assert.equal(removed.status, 200, removed.text);
  assert.deepEqual(removed.json, { ok: true, removed: true, peers: 1 });

  const onDisk = readJson(path.join(stateDir, 'peers.json'));
  assert.deepEqual(Object.keys(onDisk.peers), [B.peerId], '只删请求方，另一个 peer 不动');

  const again = await request(baseUrl, {
    method: 'POST',
    path: '/v1/unpair',
    peerId: A.peerId,
    secret: A.inboundSecret,
  });
  assert.equal(again.status, 401);
  assert.equal(again.json.error, 'unknown-peer');

  // 其它端点同样认为它已不存在（认证层一致）
  const peers = await request(baseUrl, { path: '/v1/peers', peerId: A.peerId, secret: A.inboundSecret });
  assert.equal(peers.status, 401);
  assert.equal(peers.json.error, 'unknown-peer');

  // 剩下那个 peer 仍可正常使用
  const stillThere = await request(baseUrl, { path: '/v1/peers', peerId: B.peerId, secret: B.inboundSecret });
  assert.equal(stillThere.status, 200);
  assert.deepEqual(stillThere.json.peers.map((p) => p.peerId), [B.peerId]);
});

test('/v1/unpair 未签名 → 401（与 /v1/ask /v1/peers 同一条认证）', async (t) => {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [peerFixture('peer-a')]);
  const { baseUrl } = await startServer(t, { stateDir });

  const unsigned = await request(baseUrl, { method: 'POST', path: '/v1/unpair', signed: false });
  assert.equal(unsigned.status, 401);
  assert.equal(unsigned.json.error, 'bad-signature');

  // 签名头齐全但密钥不对，同样不许删
  const wrongKey = await request(baseUrl, {
    method: 'POST',
    path: '/v1/unpair',
    peerId: A.peerId,
    secret: 'not-the-secret',
  });
  assert.equal(wrongKey.status, 401);
  assert.equal(wrongKey.json.error, 'bad-signature');
  assert.ok(readJson(path.join(stateDir, 'peers.json')).peers['peer-a'], '认证失败绝不能删条目');
});

test('/v1/unpair 忽略 body：请求方塞别人的 peerId 也只删自己', async (t) => {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [peerFixture('peer-a'), peerFixture('peer-b')]);
  const { baseUrl } = await startServer(t, { stateDir });

  const res = await request(baseUrl, {
    method: 'POST',
    path: '/v1/unpair',
    peerId: A.peerId,
    secret: A.inboundSecret,
    body: { peerId: B.peerId },
  });
  assert.equal(res.status, 200, res.text);
  assert.equal(res.json.ok, true);
  const onDisk = readJson(path.join(stateDir, 'peers.json'));
  assert.deepEqual(Object.keys(onDisk.peers), [B.peerId], 'B 不能被别人指定删掉');
});

test('/v1/unpair 的加密门控与 /v1/ask 一致：缺 X-Peer-Enc → 400，带了但未配对 → 401', async (t) => {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [peerFixture('peer-a')]);
  const { baseUrl } = await startServer(t, { stateDir, requireEncryption: true });

  const plain = await request(baseUrl, { method: 'POST', path: '/v1/unpair', peerId: A.peerId, secret: A.inboundSecret });
  assert.equal(plain.status, 400);
  assert.equal(plain.json.error, 'encryption-required');
  assert.ok(readJson(path.join(stateDir, 'peers.json')).peers['peer-a'], '未加密的请求不能删条目');

  const stranger = await request(baseUrl, {
    method: 'POST',
    path: '/v1/unpair',
    peerId: 'peer-unknown',
    secret: 'whatever',
    encrypt: true,
  });
  assert.equal(stranger.status, 401);
  assert.equal(stranger.json.error, 'bad-signature');

  const ok = await request(baseUrl, {
    method: 'POST',
    path: '/v1/unpair',
    peerId: A.peerId,
    secret: A.inboundSecret,
    encrypt: true,
  });
  assert.equal(ok.status, 200, ok.text);
  assert.equal(ok.json.removed, true);
  assert.equal(readJson(path.join(stateDir, 'peers.json')).peers['peer-a'], undefined);
});

test('/v1/unpair 用错方法 → 405（已登记路径，不是 404）', async (t) => {
  const { baseUrl } = await startServer(t);
  const res = await request(baseUrl, { path: '/v1/unpair', signed: false });
  assert.equal(res.status, 405);
  assert.equal(res.json.error, 'method-not-allowed');
});

test('unpair 会作废该 peer 挂起的 ECDH 握手（confirm 得到 pairing-expired）', async (t) => {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [peerFixture('peer-a')]);
  const { server, baseUrl } = await startServer(t, { stateDir });

  const { code } = server.issuePairingCode();
  const client = generateKeyPair();
  const first = await request(baseUrl, {
    method: 'POST',
    path: '/v1/pair',
    signed: false,
    body: {
      code,
      peerId: A.peerId,
      peerName: 'A 的显示名',
      baseUrl: 'http://192.168.1.21:7788',
      ecdh: { v: 1, curve: 'P-256', publicKey: client.publicKeyB64url },
    },
  });
  assert.equal(first.status, 200, first.text);

  const removed = await request(baseUrl, {
    method: 'POST',
    path: '/v1/unpair',
    peerId: A.peerId,
    secret: A.inboundSecret,
  });
  assert.equal(removed.status, 200, removed.text);

  const confirm = await request(baseUrl, {
    method: 'POST',
    path: '/v1/pair/confirm',
    signed: false,
    body: { code, peerId: A.peerId, peerName: 'A 的显示名', wrapped: 'AAAA' },
  });
  assert.equal(confirm.status, 401);
  assert.equal(confirm.json.error, 'pairing-expired', '挂起的握手已被 unpair 清掉');
  assert.equal(readJson(path.join(stateDir, 'peers.json')).peers[A.peerId], undefined);
});
