/**
 * 报文加密（DESIGN §4.1）的端点级用例。
 *
 * 签名层仍由 auth.test.mjs / api.test.mjs 覆盖（那些服务端 requireEncryption:false）；
 * 这里专门验证：蜜文往返、明文被拒、密文被篡改被拒、响应确实是信封格式。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { makeTempStateDir, peerFixture, seedPeers, request, startServer, pollAnswer } from './helpers.mjs';

const PEER = peerFixture('peer-enc-1');

function askBody(overrides = {}) {
  return {
    requestId: `req-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    prompt: 'encrypted hello',
    timeoutSec: 30,
    ...overrides,
  };
}

test('§4.1 加密的 ask → answer 全链路（响应为 {enc,data} 信封）', async (t) => {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [PEER]);
  const { baseUrl } = await startServer(t, {
    stateDir,
    allowRemotePrompts: true,
    requireEncryption: true,
  });

  const ask = await request(baseUrl, {
    method: 'POST',
    path: '/v1/ask',
    peerId: PEER.peerId,
    secret: PEER.inboundSecret,
    body: askBody({ prompt: 'encrypted round trip' }),
    encrypt: true,
  });
  assert.equal(ask.status, 202, ask.text);
  assert.equal(typeof ask.json.sessionId, 'string');

  // 原始响应体必须是信封，而不是明文 JSON
  assert.match(ask.text, /"enc":"v1"/);

  const answer = await pollAnswer(baseUrl, {
    sessionId: ask.json.sessionId,
    peerId: PEER.peerId,
    secret: PEER.inboundSecret,
    requestOptions: { encrypt: true },
  });
  assert.equal(answer.status, 'done');
  assert.ok(answer.reply.length > 0);
});

test('§4.1 requireEncryption 时明文请求被拒（400 encryption-required）', async (t) => {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [PEER]);
  const { baseUrl } = await startServer(t, { stateDir, requireEncryption: true });

  const res = await request(baseUrl, {
    path: '/v1/peers',
    peerId: PEER.peerId,
    secret: PEER.inboundSecret,
  });
  assert.equal(res.status, 400);
  assert.equal(res.json.error, 'encryption-required');
});

test('§4.1 密文被篡改 → 400 bad-encryption，且不进入签名校验', async (t) => {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [PEER]);
  const { baseUrl } = await startServer(t, { stateDir, requireEncryption: true });

  // overrideBody 只改发送内容、签名仍按明文：密文被改，GCM 认证失败
  const res = await request(baseUrl, {
    method: 'POST',
    path: '/v1/ask',
    peerId: PEER.peerId,
    secret: PEER.inboundSecret,
    body: askBody(),
    overrideBody: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    encrypt: true,
  });
  assert.equal(res.status, 400);
  assert.equal(res.json.error, 'bad-encryption');
});

test('§4.1 requireEncryption 关闭时明文仍然可用（向后兼容开关）', async (t) => {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [PEER]);
  const { baseUrl } = await startServer(t, { stateDir, requireEncryption: false });

  const res = await request(baseUrl, {
    path: '/v1/peers',
    peerId: PEER.peerId,
    secret: PEER.inboundSecret,
  });
  assert.equal(res.status, 200);
  assert.ok(Array.isArray(res.json.peers));
});
