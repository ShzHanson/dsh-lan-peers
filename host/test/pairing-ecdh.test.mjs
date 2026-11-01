/**
 * v0.4.0 · ECDH 两轮配对（契约 §端点 2/3）+ 兼容矩阵第 1 行。
 *
 * 覆盖：两轮成功握手、wrapped 篡改、pending 过期、配对码一次性、
 *      第一轮不消费码、旧明文路径仍 200 且有弃用告警、非法 publicKey、
 *      capability 与 pairingMode 的联动。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { makeTempStateDir, readJson, request, startServer } from './helpers.mjs';
import { PAIRING_ECDH_TTL_MS, resolveConfig } from '../server.mjs';
import { deriveWrapKey, generateKeyPair, unwrapSecret, wrapSecret } from '../../lib/pairing-ecdh.mjs';

const CLIENT = { peerId: 'peer-ecdh', peerName: 'A 的显示名', baseUrl: 'http://192.168.1.21:7788' };

function round1Body(code, client, overrides = {}) {
  return {
    code,
    peerId: CLIENT.peerId,
    peerName: CLIENT.peerName,
    baseUrl: CLIENT.baseUrl,
    ecdh: { v: 1, curve: 'P-256', publicKey: client.publicKeyB64url },
    ...overrides,
  };
}

function confirmBody(code, wrapped, overrides = {}) {
  return { code, peerId: CLIENT.peerId, peerName: CLIENT.peerName, wrapped, ...overrides };
}

function post(baseUrl, requestPath, body) {
  return request(baseUrl, { method: 'POST', path: requestPath, signed: false, body });
}

/** 自己和自己做 ECDH，只为造一个形状合法的 wrapped 乱码/密钥 */
function selfWrapKey(client) {
  return deriveWrapKey(client.privateKey, client.publicKeyB64url);
}

test('§2/§3 ECDH 两轮握手成功：第一轮不消费码，confirm 返回可解的 T 并落盘', async (t) => {
  const stateDir = makeTempStateDir();
  const logs = [];
  const { server, baseUrl } = await startServer(t, {
    stateDir,
    name: 'B-host',
    logger: (line) => logs.push(line),
  });
  const { code } = server.issuePairingCode();
  const client = generateKeyPair();

  const first = await post(baseUrl, '/v1/pair', round1Body(code, client));
  assert.equal(first.status, 200, first.text);
  assert.deepEqual(first.json.ecdh, {
    v: 1,
    curve: 'P-256',
    publicKey: first.json.ecdh.publicKey,
  });
  assert.equal(Buffer.from(first.json.ecdh.publicKey, 'base64url').length, 65, '未压缩 P-256 点为 65 字节');
  assert.equal(Buffer.from(first.json.ecdh.publicKey, 'base64url')[0], 0x04);
  assert.equal(first.json.pairingTtlMs, 120_000);

  // 第一轮不消费配对码（M6：码只活在本进程内存里，state.json 里不再有它）
  assert.equal(readJson(path.join(stateDir, 'state.json')).pairingCode, undefined, 'M6：配对码不落盘');
  assert.equal(fs.existsSync(path.join(stateDir, 'peers.json')), false);

  const wrapKey = deriveWrapKey(client.privateKey, first.json.ecdh.publicKey);
  assert.equal(wrapKey.length, 32, 'W 必须是 32 字节');

  const second = await post(baseUrl, '/v1/pair/confirm', confirmBody(code, wrapSecret(wrapKey, { secret: 'S-from-client' })));
  assert.equal(second.status, 200, second.text);
  assert.equal(second.json.peerId, server.store.instanceId);
  assert.equal(second.json.peerName, 'B-host');

  const issued = unwrapSecret(wrapKey, second.json.wrapped);
  assert.match(issued.secret, /^[A-Za-z0-9_-]{43}$/, 'T 是 32 字节 base64url');

  const stored = readJson(path.join(stateDir, 'peers.json')).peers[CLIENT.peerId];
  assert.equal(stored.name, CLIENT.peerName);
  assert.equal(stored.secret, 'S-from-client');
  assert.equal(stored.inboundSecret, issued.secret);
  assert.equal(stored.baseUrl, CLIENT.baseUrl);
  assert.equal(readJson(path.join(stateDir, 'state.json')).pairingCode, undefined, 'M6：码从不落盘');

  // 全程没有走过明文路径，因此不该出现弃用告警
  assert.equal(logs.some((line) => line.includes('legacy plaintext path used')), false);

  // 拿 T 就能认证（落到 403 disabled，说明签名已通过）
  const ask = await request(baseUrl, {
    method: 'POST',
    path: '/v1/ask',
    peerId: CLIENT.peerId,
    secret: issued.secret,
    body: { requestId: 'ecdh-e2e', prompt: 'ping' },
  });
  assert.equal(ask.status, 403);
  assert.equal(ask.json.error, 'disabled');
});

test('§2 wrapped 被篡改 → 400 bad-encryption，配对码与 pending 都不动，可用正确 wrapped 重试', async (t) => {
  const stateDir = makeTempStateDir();
  const { server, baseUrl } = await startServer(t, { stateDir });
  const { code } = server.issuePairingCode();
  const client = generateKeyPair();

  const first = await post(baseUrl, '/v1/pair', round1Body(code, client));
  assert.equal(first.status, 200, first.text);
  const wrapKey = deriveWrapKey(client.privateKey, first.json.ecdh.publicKey);
  const wrapped = wrapSecret(wrapKey, { secret: 'S-from-client' });

  const raw = Buffer.from(wrapped, 'base64url');
  raw[raw.length - 1] ^= 0xff;
  const tampered = await post(baseUrl, '/v1/pair/confirm', confirmBody(code, raw.toString('base64url')));
  assert.equal(tampered.status, 400, tampered.text);
  assert.equal(tampered.json.error, 'bad-encryption');
  assert.equal(readJson(path.join(stateDir, 'state.json')).pairingCode, undefined, 'M6：配对码不落盘');

  // 用别的密钥包裹同样解不开
  const strangerKey = selfWrapKey(generateKeyPair());
  const wrongKey = await post(baseUrl, '/v1/pair/confirm', confirmBody(code, wrapSecret(strangerKey, { secret: 'S' })));
  assert.equal(wrongKey.status, 400);
  assert.equal(wrongKey.json.error, 'bad-encryption');

  const retry = await post(baseUrl, '/v1/pair/confirm', confirmBody(code, wrapped));
  assert.equal(retry.status, 200, retry.text);
  assert.ok(unwrapSecret(wrapKey, retry.json.wrapped).secret.length > 0);
});

test('§2 握手 pending 超过 120s → 401 pairing-expired；配对码本身仍有效可重来', async (t) => {
  const clock = { now: Date.now() };
  const stateDir = makeTempStateDir();
  const { server, baseUrl } = await startServer(t, { stateDir, now: () => clock.now });
  const { code } = server.issuePairingCode();
  const client = generateKeyPair();

  const first = await post(baseUrl, '/v1/pair', round1Body(code, client));
  assert.equal(first.status, 200, first.text);
  const wrapKey = deriveWrapKey(client.privateKey, first.json.ecdh.publicKey);
  const wrapped = wrapSecret(wrapKey, { secret: 'S' });

  clock.now += PAIRING_ECDH_TTL_MS + 1;
  const expired = await post(baseUrl, '/v1/pair/confirm', confirmBody(code, wrapped));
  assert.equal(expired.status, 401, expired.text);
  assert.equal(expired.json.error, 'pairing-expired');

  // 配对码 TTL 是 10 分钟，没被握手超时连累：还能重新走一轮
  const again = await post(baseUrl, '/v1/pair', round1Body(code, client));
  assert.equal(again.status, 200, again.text);
});

test('§2 配对码一次性：confirm 成功后重放 confirm / 重放第一轮 → 401 invalid-code', async (t) => {
  const stateDir = makeTempStateDir();
  const { server, baseUrl } = await startServer(t, { stateDir });
  const { code } = server.issuePairingCode();
  const client = generateKeyPair();

  const first = await post(baseUrl, '/v1/pair', round1Body(code, client));
  const wrapKey = deriveWrapKey(client.privateKey, first.json.ecdh.publicKey);
  const wrapped = wrapSecret(wrapKey, { secret: 'S' });
  const ok = await post(baseUrl, '/v1/pair/confirm', confirmBody(code, wrapped));
  assert.equal(ok.status, 200, ok.text);

  const replayConfirm = await post(baseUrl, '/v1/pair/confirm', confirmBody(code, wrapped));
  assert.equal(replayConfirm.status, 401);
  assert.equal(replayConfirm.json.error, 'invalid-code');

  const replayRound1 = await post(baseUrl, '/v1/pair', round1Body(code, client));
  assert.equal(replayRound1.status, 401);
  assert.equal(replayRound1.json.error, 'invalid-code');

  // 旧明文路径也不能再用这个码
  const legacyReplay = await post(baseUrl, '/v1/pair', { code, peerId: 'peer-x', peerName: 'X', secret: 'S-x' });
  assert.equal(legacyReplay.status, 401);
  assert.equal(legacyReplay.json.error, 'invalid-code');
});

test('兼容矩阵① 旧客户端（body 无 ecdh）→ 新服务端：明文配对仍 200 + 一行弃用告警', async (t) => {
  const stateDir = makeTempStateDir();
  const logs = [];
  const { server, baseUrl } = await startServer(t, {
    stateDir,
    name: 'B-host',
    logger: (line) => logs.push(line),
  });
  const { code } = server.issuePairingCode();

  const paired = await post(baseUrl, '/v1/pair', {
    code,
    peerId: 'peer-legacy',
    peerName: 'Old client',
    secret: 'S-old',
    baseUrl: 'http://192.168.1.9:7788',
  });
  assert.equal(paired.status, 200, paired.text);
  assert.equal(paired.json.peerId, server.store.instanceId);
  assert.equal(paired.json.peerName, 'B-host');
  assert.match(paired.json.secret, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(paired.json.ecdh, undefined, '旧响应形状里没有 ecdh 字段');

  const warnings = logs.filter((line) => line === 'pair: legacy plaintext path used by peer-legacy');
  assert.equal(warnings.length, 1, `警告行必须恰好一行，实得 ${JSON.stringify(logs)}`);

  const stored = readJson(path.join(stateDir, 'peers.json')).peers['peer-legacy'];
  assert.equal(stored.secret, 'S-old');
  assert.equal(stored.inboundSecret, paired.json.secret);
  assert.equal(readJson(path.join(stateDir, 'state.json')).pairingCode, undefined);
});

test('§2 publicKey / ecdh 信封非法 → 400 bad-request（码不消费，随后正常握手仍可用）', async (t) => {
  const stateDir = makeTempStateDir();
  const { server, baseUrl } = await startServer(t, { stateDir });
  const { code } = server.issuePairingCode();
  const client = generateKeyPair();
  const goodPoint = client.publicKeyB64url;

  const cases = [
    { ecdh: 'not-an-object' },
    { ecdh: { v: 2, curve: 'P-256', publicKey: goodPoint } },
    { ecdh: { v: 1, curve: 'X25519', publicKey: goodPoint } },
    { ecdh: { v: 1, curve: 'P-256', publicKey: 'not-base64url-!!!' } },
    { ecdh: { v: 1, curve: 'P-256', publicKey: Buffer.alloc(65, 4).toString('base64url') } },
    { ecdh: { v: 1, curve: 'P-256', publicKey: Buffer.from(goodPoint, 'base64url').subarray(1).toString('base64url') } },
    { ecdh: { v: 1, curve: 'P-256' } },
  ];
  for (const override of cases) {
    const res = await post(baseUrl, '/v1/pair', round1Body(code, client, override));
    assert.equal(res.status, 400, `${JSON.stringify(override)} -> ${res.status} ${res.text}`);
    assert.equal(res.json.error, 'bad-request');
  }
  assert.equal(readJson(path.join(stateDir, 'state.json')).pairingCode, undefined, 'M6：配对码不落盘');

  // 非法的第一轮不得烧码：同一个码随后仍能正常握手（行为断言取代过去的落盘断言）
  const ok = await post(baseUrl, '/v1/pair', round1Body(code, client));
  assert.equal(ok.status, 200, ok.text);
});

test('§2 confirm 未做第一轮 → 401 pairing-expired；码不对 → 401 invalid-code', async (t) => {
  const stateDir = makeTempStateDir();
  const { server, baseUrl } = await startServer(t, { stateDir });
  const { code } = server.issuePairingCode();
  const garbage = wrapSecret(selfWrapKey(generateKeyPair()), { secret: 'S' });

  const noPending = await post(baseUrl, '/v1/pair/confirm', confirmBody(code, garbage));
  assert.equal(noPending.status, 401, noPending.text);
  assert.equal(noPending.json.error, 'pairing-expired');

  const otherCode = code === '000000' ? '000001' : '000000';
  const wrongCode = await post(baseUrl, '/v1/pair/confirm', confirmBody(otherCode, garbage));
  assert.equal(wrongCode.status, 401, wrongCode.text);
  assert.equal(wrongCode.json.error, 'invalid-code');

  const missingWrapped = await post(baseUrl, '/v1/pair/confirm', { code, peerId: CLIENT.peerId, peerName: CLIENT.peerName });
  assert.equal(missingWrapped.status, 400);
  assert.equal(missingWrapped.json.error, 'bad-request');
});

test('§1/§6 capability 与 pairingMode：legacy 不宣告 pair-ecdh 且拒绝 ECDH；ecdh 拒绝旧明文', async (t) => {
  const legacy = await startServer(t, { stateDir: makeTempStateDir(), pairingMode: 'legacy' });
  const legacyHealth = await request(legacy.baseUrl, { path: '/v1/health', signed: false });
  // v0.4.0 · capability per DESIGN §12.2；v0.4.1 追加 unpair；v0.5.0 追加 group；
  // v0.8.0 追加 group-advertise（老对端不认识就忽略）
  assert.deepEqual(legacyHealth.json.capability, [
    'ask', 'pair', 'stream', 'unpair', 'group', 'group-advertise',
  ]);
  const { code } = legacy.server.issuePairingCode();
  const ecdhAttempt = await post(legacy.baseUrl, '/v1/pair', round1Body(code, generateKeyPair()));
  assert.equal(ecdhAttempt.status, 400);
  assert.equal(ecdhAttempt.json.error, 'bad-request');

  const strict = await startServer(t, { stateDir: makeTempStateDir(), pairingMode: 'ecdh' });
  const strictHealth = await request(strict.baseUrl, { path: '/v1/health', signed: false });
  assert.deepEqual(strictHealth.json.capability, [
    'ask', 'pair', 'pair-ecdh', 'stream', 'unpair', 'group', 'group-advertise',
  ]);
  const legacyPair = await post(strict.baseUrl, '/v1/pair', {
    code: '123456',
    peerId: 'peer-legacy',
    peerName: 'Old',
    secret: 'S-old',
  });
  assert.equal(legacyPair.status, 400);
  assert.equal(legacyPair.json.error, 'ecdh-required');
});

test('§6 配置：pairingMode 非法值回落 auto；answerWaitMs 默认 25000 且硬上限 25000', () => {
  assert.equal(resolveConfig({}).pairingMode, 'auto');
  assert.equal(resolveConfig({ pairingMode: 'nope' }).pairingMode, 'auto');
  assert.equal(resolveConfig({ pairingMode: 'ecdh' }).pairingMode, 'ecdh');
  assert.equal(resolveConfig({}).answerWaitMs, 25_000);
  assert.equal(resolveConfig({ answerWaitMs: 500 }).answerWaitMs, 500);
  assert.equal(resolveConfig({ answerWaitMs: 999_999 }).answerWaitMs, 25_000);
  assert.equal(resolveConfig({ answerWaitMs: -1 }).answerWaitMs, 25_000);
});
