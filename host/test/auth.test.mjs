/**
 * host/test/auth.test.mjs
 *
 * 覆盖 DESIGN.md §11 验收用例 1、2（health / 坏签名 / 重放 / 时钟偏移），
 * 外加 §4 canonical 定义、§3 配对码生命周期、§8 存储权限、§9 网段白名单。
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import {
  CLOCK_SKEW_MS,
  EMPTY_BODY_SHA256,
  PAIRING_CODE_TTL_MS,
  buildCanonical,
  createPeerServer,
  isAllowedRemote,
  issuePairingCode,
  parseCidr,
  signCanonical,
} from '../server.mjs';

import {
  fileMode,
  makeTempStateDir,
  peerFixture,
  readJson,
  request,
  seedPeers,
  startServer,
} from './helpers.mjs';

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// ---------------------------------------------------------------------------
// §4 canonical / 签名工具
// ---------------------------------------------------------------------------

test('§4 canonical 是五行、\\n 连接、无尾随换行', () => {
  const rawBody = Buffer.from('{"prompt":"hi"}');
  const canonical = buildCanonical({
    method: 'post',
    path: '/v1/ask?x=1',
    ts: 1_700_000_000_000,
    nonce: 'a'.repeat(32),
    rawBody,
  });

  const lines = canonical.split('\n');
  assert.equal(lines.length, 5);
  assert.equal(lines[0], 'POST', 'METHOD 必须大写');
  assert.equal(lines[1], '/v1/ask?x=1', 'path 必须含 query');
  assert.equal(lines[2], '1700000000000');
  assert.equal(lines[3], 'a'.repeat(32));
  assert.equal(lines[4], createHash('sha256').update(rawBody).digest('hex'));
  assert.equal(canonical.endsWith('\n'), false, '不能有尾随换行');
});

test('§4 GET 的 body 摘要固定是 sha256("")，签名是 base64url(HMAC-SHA256(secret, canonical))', () => {
  assert.equal(
    EMPTY_BODY_SHA256,
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  );
  const canonical = buildCanonical({ method: 'GET', path: '/v1/health', ts: 1, nonce: 'n', rawBody: undefined });
  assert.equal(canonical.split('\n')[4], EMPTY_BODY_SHA256);

  const expected = createHmac('sha256', Buffer.from('sekret', 'utf8'))
    .update(canonical, 'utf8')
    .digest('base64url');
  assert.equal(signCanonical({ secret: 'sekret', canonical }), expected);
  // base64url 字符集：不含 + / =
  assert.match(expected, /^[A-Za-z0-9_-]+$/);
});

// ---------------------------------------------------------------------------
// §11.1 health
// ---------------------------------------------------------------------------

test('§11.1 GET /v1/health 无认证 200，peers 计数正确', async (t) => {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [peerFixture('peer-a'), peerFixture('peer-b')]);
  const { server, baseUrl } = await startServer(t, { stateDir, name: 'nas-box' });

  const health = await request(baseUrl, { path: '/v1/health', signed: false });
  assert.equal(health.status, 200);
  assert.equal(health.json.name, 'nas-box');
  assert.match(health.json.instanceId, UUID_V4);
  assert.equal(health.json.instanceId, server.store.instanceId);
  // 版本号跟随实现，发版不需要改测试
  assert.match(health.json.version, /^\d+\.\d+\.\d+/);
  // v0.4.0 · capability per DESIGN §12.2（旧的 ask/pair 保留）；v0.4.1 追加 unpair；
  // v0.5.0 追加 group；v0.8.0 追加 group-advertise（契约 §9.5：三处记账同步，保持 deepEqual）
  assert.deepEqual(health.json.capability, [
    'ask', 'pair', 'pair-ecdh', 'stream', 'unpair', 'group', 'group-advertise',
  ]);
  assert.equal(health.json.peers, 2);

  // 完全不带头也 200
  const bare = await fetch(new URL('/v1/health', baseUrl));
  assert.equal(bare.status, 200);

  // state.json 已落盘且 0600
  const statePath = path.join(stateDir, 'state.json');
  if (process.platform !== 'win32') assert.equal(fileMode(statePath), 0o600);
  assert.equal(readJson(statePath).instanceId, server.store.instanceId);
});

test('§8 state.json 的 instanceId/createdAt 跨重启保持不变', async (t) => {
  const stateDir = makeTempStateDir();
  t.after(() => fs.rmSync(stateDir, { recursive: true, force: true }));

  const first = createPeerServer({ stateDir, listenHost: '127.0.0.1', name: 'nas-box' });
  let initial;
  try {
    await first.listen(0, '127.0.0.1');
    initial = readJson(path.join(stateDir, 'state.json'));
  } finally {
    await first.close();
  }

  const second = createPeerServer({ stateDir, listenHost: '127.0.0.1', name: 'nas-box' });
  let reloaded;
  try {
    await second.listen(0, '127.0.0.1');
    reloaded = readJson(path.join(stateDir, 'state.json'));
  } finally {
    await second.close();
  }

  assert.equal(reloaded.instanceId, initial.instanceId);
  assert.equal(reloaded.createdAt, initial.createdAt);
  assert.equal(reloaded.name, 'nas-box');
  if (process.platform !== 'win32') assert.equal(fileMode(path.join(stateDir, 'state.json')), 0o600);
});

// ---------------------------------------------------------------------------
// §11.2 签名校验：坏签名 / 重放 / 时钟偏移
// ---------------------------------------------------------------------------

test('合法签名通过；GET /v1/peers 不泄露 secret', async (t) => {
  const stateDir = makeTempStateDir();
  const peer = peerFixture('peer-a');
  seedPeers(stateDir, [peer]);
  const { baseUrl } = await startServer(t, { stateDir });

  const res = await request(baseUrl, {
    path: '/v1/peers',
    peerId: peer.peerId,
    secret: peer.inboundSecret,
  });
  assert.equal(res.status, 200);
  assert.equal(res.json.peers.length, 1);
  assert.deepEqual(Object.keys(res.json.peers[0]).sort(), ['baseUrl', 'name', 'peerId']);
  assert.equal(res.json.peers[0].peerId, 'peer-a');
  assert.equal(res.text.includes(peer.inboundSecret), false);
  assert.equal(res.text.includes(peer.secret), false);
  if (process.platform !== 'win32') assert.equal(fileMode(path.join(stateDir, 'peers.json')), 0o600);
});

test('§11.2 错误签名 → 401 bad-signature（错密钥 / 改签名 / 缺头）', async (t) => {
  const stateDir = makeTempStateDir();
  const peer = peerFixture('peer-a');
  seedPeers(stateDir, [peer]);
  const { baseUrl } = await startServer(t, { stateDir });

  const wrongSecret = await request(baseUrl, {
    path: '/v1/peers',
    peerId: peer.peerId,
    secret: 'not-the-paired-secret',
  });
  assert.equal(wrongSecret.status, 401);
  assert.equal(wrongSecret.json.error, 'bad-signature');

  const mangledSign = await request(baseUrl, {
    path: '/v1/peers',
    peerId: peer.peerId,
    secret: peer.inboundSecret,
    signature: 'A'.repeat(43),
  });
  assert.equal(mangledSign.status, 401);
  assert.equal(mangledSign.json.error, 'bad-signature');

  const noHeaders = await request(baseUrl, { path: '/v1/peers', signed: false });
  assert.equal(noHeaders.status, 401);
  assert.equal(noHeaders.json.error, 'bad-signature');

  // 未配对的对端
  const unknownPeer = await request(baseUrl, {
    path: '/v1/peers',
    peerId: 'peer-never-paired',
    secret: peer.inboundSecret,
  });
  assert.equal(unknownPeer.status, 401);
  assert.equal(unknownPeer.json.error, 'unknown-peer');
});

test('§11.2 重放同一 nonce → 401 replay（换 nonce 即可用）', async (t) => {
  const stateDir = makeTempStateDir();
  const peer = peerFixture('peer-a');
  seedPeers(stateDir, [peer]);
  const { baseUrl } = await startServer(t, { stateDir });

  const nonce = randomBytes(16).toString('hex');
  const ts = Date.now();
  const options = { path: '/v1/peers', peerId: peer.peerId, secret: peer.inboundSecret, nonce, ts };

  const first = await request(baseUrl, options);
  assert.equal(first.status, 200);

  const replayed = await request(baseUrl, options);
  assert.equal(replayed.status, 401);
  assert.equal(replayed.json.error, 'replay');

  const fresh = await request(baseUrl, {
    ...options,
    nonce: randomBytes(16).toString('hex'),
  });
  assert.equal(fresh.status, 200);
});

test('§11.2 时间戳偏移 ±5 分钟 → 401 clock-skew，且先于签名错误', async (t) => {
  const stateDir = makeTempStateDir();
  const peer = peerFixture('peer-a');
  seedPeers(stateDir, [peer]);
  const { baseUrl } = await startServer(t, { stateDir });

  for (const offset of [-5 * 60_000, 5 * 60_000]) {
    const res = await request(baseUrl, {
      path: '/v1/peers',
      peerId: peer.peerId,
      secret: peer.inboundSecret,
      ts: Date.now() + offset,
    });
    assert.equal(res.status, 401, `offset ${offset} 应被拒绝`);
    assert.equal(res.json.error, 'clock-skew');
  }

  // 契约 §4 的校验顺序：先时钟窗，再 nonce，再签名
  const skewedAndBadSign = await request(baseUrl, {
    path: '/v1/peers',
    peerId: peer.peerId,
    secret: peer.inboundSecret,
    ts: Date.now() - (CLOCK_SKEW_MS + 1_000),
    signature: 'B'.repeat(43),
  });
  assert.equal(skewedAndBadSign.json.error, 'clock-skew');

  // 边界内（±59s）仍然可用
  const nearly = await request(baseUrl, {
    path: '/v1/peers',
    peerId: peer.peerId,
    secret: peer.inboundSecret,
    ts: Date.now() - 59_000,
  });
  assert.equal(nearly.status, 200);
});

test('§4 body 被篡改 → 401 bad-signature', async (t) => {
  const stateDir = makeTempStateDir();
  const peer = peerFixture('peer-a');
  seedPeers(stateDir, [peer]);
  const { baseUrl } = await startServer(t, { stateDir });

  const res = await request(baseUrl, {
    method: 'POST',
    path: '/v1/ask',
    peerId: peer.peerId,
    secret: peer.inboundSecret,
    body: { requestId: 'req-1', prompt: 'hello' },
    overrideBody: { requestId: 'req-1', prompt: 'evil' },
  });
  // 签名对不上 → 401；如果实现先看 allowRemotePrompts 会错成 403
  assert.equal(res.status, 401);
  assert.equal(res.json.error, 'bad-signature');
});

test('§4 path/query 被篡改 → 401 bad-signature', async (t) => {
  const stateDir = makeTempStateDir();
  const peer = peerFixture('peer-a');
  seedPeers(stateDir, [peer]);
  const { baseUrl } = await startServer(t, { stateDir });

  const res = await request(baseUrl, {
    path: '/v1/answer?sessionId=bbb',
    signPath: '/v1/answer?sessionId=aaa',
    peerId: peer.peerId,
    secret: peer.inboundSecret,
  });
  assert.equal(res.status, 401);
  assert.equal(res.json.error, 'bad-signature');
});

test('§4 验签接受 inboundSecret；默认也兼容存量的 secret（兼容开关可关）', async (t) => {
  const peer = peerFixture('peer-a');

  const lenientDir = makeTempStateDir();
  seedPeers(lenientDir, [peer]);
  const lenient = await startServer(t, { stateDir: lenientDir });

  const viaInbound = await request(lenient.baseUrl, {
    path: '/v1/peers',
    peerId: peer.peerId,
    secret: peer.inboundSecret,
  });
  assert.equal(viaInbound.status, 200);

  // §3 step 3 与 step 5 对「存哪把密钥」的表述互相矛盾；默认宽容地也接受 secret
  const viaLegacySecret = await request(lenient.baseUrl, {
    path: '/v1/peers',
    peerId: peer.peerId,
    secret: peer.secret,
  });
  assert.equal(viaLegacySecret.status, 200);

  const strictDir = makeTempStateDir();
  seedPeers(strictDir, [peer]);
  const strict = await startServer(t, { stateDir: strictDir, acceptSecretFallback: false });

  const strictLegacy = await request(strict.baseUrl, {
    path: '/v1/peers',
    peerId: peer.peerId,
    secret: peer.secret,
  });
  assert.equal(strictLegacy.status, 401);
  assert.equal(strictLegacy.json.error, 'bad-signature');

  const strictInbound = await request(strict.baseUrl, {
    path: '/v1/peers',
    peerId: peer.peerId,
    secret: peer.inboundSecret,
  });
  assert.equal(strictInbound.status, 200);
});

// ---------------------------------------------------------------------------
// §3 配对
// ---------------------------------------------------------------------------

test('§3/§2 配对码：6 位数字、10 分钟、一次性；成功后写入 peers.json（0600）', async (t) => {
  const stateDir = makeTempStateDir();
  const { server, baseUrl } = await startServer(t, { stateDir, name: 'nas-box' });

  const issued = server.issuePairingCode();
  assert.match(issued.code, /^\d{6}$/);
  const ttl = issued.expiresAt - Date.now();
  assert.ok(ttl > PAIRING_CODE_TTL_MS - 5_000 && ttl <= PAIRING_CODE_TTL_MS, `ttl=${ttl}`);

  const statePath = path.join(stateDir, 'state.json');
  if (process.platform !== 'win32') assert.equal(fileMode(statePath), 0o600);
  assert.equal(readJson(statePath).pairingCode.code, issued.code);

  const pairBody = {
    code: issued.code,
    peerId: 'peer-a',
    peerName: 'A 的显示名',
    secret: 'S-created-by-A',
    baseUrl: 'http://192.168.1.21:7788',
  };
  const paired = await request(baseUrl, { method: 'POST', path: '/v1/pair', signed: false, body: pairBody });
  assert.equal(paired.status, 200);
  assert.equal(paired.json.peerId, server.store.instanceId);
  assert.equal(paired.json.peerName, 'nas-box');
  assert.match(paired.json.secret, /^[A-Za-z0-9_-]{43}$/, '32 字节 base64url 应为 43 字符');
  assert.notEqual(paired.json.secret, 'S-created-by-A', '两把密钥必须不同');

  const peersPath = path.join(stateDir, 'peers.json');
  if (process.platform !== 'win32') assert.equal(fileMode(peersPath), 0o600);
  const stored = readJson(peersPath).peers['peer-a'];
  assert.equal(stored.name, 'A 的显示名');
  assert.equal(stored.secret, 'S-created-by-A');
  assert.equal(stored.inboundSecret, paired.json.secret);
  assert.equal(stored.baseUrl, 'http://192.168.1.21:7788');
  assert.equal(readJson(statePath).pairingCode, undefined, '配对码用后即焚');

  const health = await request(baseUrl, { path: '/v1/health', signed: false });
  assert.equal(health.json.peers, 1);

  // 返回给 A 的 T 就是 A→B 的签名密钥（§3 step 5）；用它能过认证，落到 403 disabled
  const askWithT = await request(baseUrl, {
    method: 'POST',
    path: '/v1/ask',
    peerId: 'peer-a',
    secret: paired.json.secret,
    body: { requestId: 'r-1', prompt: 'ping' },
  });
  assert.equal(askWithT.status, 403);
  assert.equal(askWithT.json.error, 'disabled');

  // 一次性：同一码再用一次 → 401 invalid-code
  const reused = await request(baseUrl, {
    method: 'POST',
    path: '/v1/pair',
    signed: false,
    body: { code: issued.code, peerId: 'peer-b', peerName: 'B', secret: 'S-b' },
  });
  assert.equal(reused.status, 401);
  assert.equal(reused.json.error, 'invalid-code');
  assert.equal(readJson(peersPath).peers['peer-b'], undefined);
});

test('§3 配对码 10 分钟后过期，且过期码被清掉', async (t) => {
  const clock = { now: Date.now() };
  const stateDir = makeTempStateDir();
  const { server, baseUrl } = await startServer(t, { stateDir, now: () => clock.now });

  const { code, expiresAt } = server.issuePairingCode();
  assert.equal(expiresAt - clock.now, PAIRING_CODE_TTL_MS);

  clock.now = expiresAt + 1;
  const res = await request(baseUrl, {
    method: 'POST',
    path: '/v1/pair',
    signed: false,
    body: { code, peerId: 'peer-late', peerName: 'Late', secret: 's' },
  });
  assert.equal(res.status, 401);
  assert.equal(res.json.error, 'invalid-code');
  assert.equal(readJson(path.join(stateDir, 'state.json')).pairingCode, undefined);
});

test('§3 配对 body 缺字段 → 400；码格式不对 / 没发码 → 401 invalid-code', async (t) => {
  const stateDir = makeTempStateDir();
  const { baseUrl } = await startServer(t, { stateDir });

  const missingSecret = await request(baseUrl, {
    method: 'POST',
    path: '/v1/pair',
    signed: false,
    body: { code: '123456', peerId: 'peer-a', peerName: 'A' },
  });
  assert.equal(missingSecret.status, 400);
  assert.equal(missingSecret.json.error, 'bad-request');

  const noCodeIssued = await request(baseUrl, {
    method: 'POST',
    path: '/v1/pair',
    signed: false,
    body: { code: '123456', peerId: 'peer-a', peerName: 'A', secret: 's' },
  });
  assert.equal(noCodeIssued.status, 401);
  assert.equal(noCodeIssued.json.error, 'invalid-code');

  const badFormat = await request(baseUrl, {
    method: 'POST',
    path: '/v1/pair',
    signed: false,
    body: { code: 'abcdef', peerId: 'peer-a', peerName: 'A', secret: 's' },
  });
  assert.equal(badFormat.status, 401);
  assert.equal(badFormat.json.error, 'invalid-code');
});

test('配对码由另一个进程（CLI）写入时，正在运行的 server 也能看到', async (t) => {
  const stateDir = makeTempStateDir();
  const { baseUrl } = await startServer(t, { stateDir, name: 'nas-box' });

  // 模拟 `lan-peers code` 在另一个进程里写 state.json
  const { code } = issuePairingCode({ stateDir, name: 'nas-box' });

  const paired = await request(baseUrl, {
    method: 'POST',
    path: '/v1/pair',
    signed: false,
    body: { code, peerId: 'peer-cli', peerName: 'CLI', secret: 's-cli' },
  });
  assert.equal(paired.status, 200);
  assert.equal(readJson(path.join(stateDir, 'state.json')).pairingCode, undefined);
});

// ---------------------------------------------------------------------------
// §9 网络层白名单
// ---------------------------------------------------------------------------

test('§9 显式 trustedCidrs 会拒绝非白名单来源（403 forbidden-network）', async (t) => {
  const stateDir = makeTempStateDir();
  const { baseUrl } = await startServer(t, { stateDir, trustedCidrs: ['10.0.0.0/8'] });

  const res = await request(baseUrl, { path: '/v1/health', signed: false });
  assert.equal(res.status, 403);
  assert.equal(res.json.error, 'forbidden-network');
});

test('§9 默认白名单允许回环/私网，拒绝公网；CIDR 解析正确', async (t) => {
  const stateDir = makeTempStateDir();
  const { baseUrl } = await startServer(t, { stateDir });
  const health = await request(baseUrl, { path: '/v1/health', signed: false });
  assert.equal(health.status, 200, '默认应允许 127.0.0.1');

  assert.equal(isAllowedRemote('192.168.1.44', null), true);
  assert.equal(isAllowedRemote('10.9.8.7', null), true);
  assert.equal(isAllowedRemote('127.0.0.1', null), true);
  assert.equal(isAllowedRemote('8.8.8.8', null), false, '公网必须拒绝');
  assert.equal(isAllowedRemote('::1', null), true);
  assert.equal(isAllowedRemote('fe80::1', null), true);
  assert.equal(isAllowedRemote('2606:4700:4700::1111', null), false);

  // 显式配置是严格模式：回环不在列表里就不许
  assert.equal(isAllowedRemote('127.0.0.1', ['192.168.1.0/24']), false);
  assert.equal(isAllowedRemote('192.168.1.4', ['192.168.1.0/24']), true);
  assert.equal(isAllowedRemote('::ffff:192.168.1.4', ['192.168.1.0/24']), true);
  assert.equal(isAllowedRemote('10.2.3.4', ['10.0.0.0/8']), true);
  assert.equal(isAllowedRemote('11.2.3.4', ['10.0.0.0/8']), false);

  assert.deepEqual(parseCidr('192.168.1.0/24')?.bits, 32);
  assert.equal(parseCidr('not-a-cidr'), null);
});

// ---------------------------------------------------------------------------
// §9 日志不泄露 secret / 签名
// ---------------------------------------------------------------------------

test('§9 请求日志不打印 secret、签名原文', async (t) => {
  const lines = [];
  const stateDir = makeTempStateDir();
  const peer = peerFixture('peer-a');
  seedPeers(stateDir, [peer]);
  const { baseUrl } = await startServer(t, { stateDir, logger: (line) => lines.push(line) });

  const ok = await request(baseUrl, {
    path: '/v1/peers',
    peerId: peer.peerId,
    secret: peer.inboundSecret,
  });
  assert.equal(ok.status, 200);

  const bad = await request(baseUrl, {
    path: '/v1/peers',
    peerId: peer.peerId,
    secret: 'wrong-secret-value',
  });
  assert.equal(bad.status, 401);

  const joined = lines.join('\n');
  assert.ok(lines.length >= 2, '应有请求日志');
  assert.equal(joined.includes(peer.inboundSecret), false, '日志不得含 secret');
  assert.equal(joined.includes(ok.signature), false, '日志不得含签名原文');
  assert.equal(joined.includes(bad.signature), false, '日志不得含签名原文');
  assert.ok(joined.includes('/v1/peers'));
  assert.ok(joined.includes('200'));
  assert.ok(joined.includes('401'));
  assert.ok(joined.includes('peer=peer-a'));
});
