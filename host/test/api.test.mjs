/**
 * host/test/api.test.mjs
 *
 * 覆盖 DESIGN.md §11 验收用例 3、4（disabled / ask→answer 完整流程），
 * 外加 §5 的幂等、超时（默认 300s、上限 900s）、会话归属、配对后直接可问。
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';

import { createRunner } from '../server.mjs';

import {
  makeTempStateDir,
  peerFixture,
  pollAnswer,
  readJson,
  request,
  seedPeers,
  startServer,
} from './helpers.mjs';

const PEER = peerFixture('peer-a');

function askBody(overrides = {}) {
  return { requestId: 'req-1', prompt: 'hello from the LAN peer', ...overrides };
}

// ---------------------------------------------------------------------------
// §11.3 allowRemotePrompts 默认 false
// ---------------------------------------------------------------------------

test('§11.3 默认 allowRemotePrompts=false：签名合法的 /v1/ask → 403 disabled，且不建会话', async (t) => {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [PEER]);
  const runner = createRunner({ delayMs: 5 });
  const { baseUrl } = await startServer(t, { stateDir, runner });

  const res = await request(baseUrl, {
    method: 'POST',
    path: '/v1/ask',
    peerId: PEER.peerId,
    secret: PEER.inboundSecret,
    body: askBody(),
  });
  assert.equal(res.status, 403);
  assert.equal(res.json.error, 'disabled');
  assert.equal(runner.sessions.size, 0, 'disabled 时不应创建任何会话');
  assert.equal(res.json.sessionId, undefined);

  // health 不受开关影响，也不泄露开关状态
  const health = await request(baseUrl, { path: '/v1/health', signed: false });
  assert.equal(health.status, 200);
  assert.equal(health.json.peers, 1);
});

test('§5 先认证后看开关：allowRemotePrompts=true 但签名错 → 401，不建会话', async (t) => {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [PEER]);
  const runner = createRunner({ delayMs: 5 });
  const { baseUrl } = await startServer(t, { stateDir, runner, allowRemotePrompts: true });

  const res = await request(baseUrl, {
    method: 'POST',
    path: '/v1/ask',
    peerId: PEER.peerId,
    secret: 'wrong-secret',
    body: askBody(),
  });
  assert.equal(res.status, 401);
  assert.equal(res.json.error, 'bad-signature');
  assert.equal(runner.sessions.size, 0);

  const anonymous = await request(baseUrl, {
    method: 'POST',
    path: '/v1/ask',
    signed: false,
    body: askBody(),
  });
  assert.equal(anonymous.status, 401);
});

// ---------------------------------------------------------------------------
// §11.4 ask → answer
// ---------------------------------------------------------------------------

test('§11.4 打开开关后 ask → 202，answer running → done，reply 非空', async (t) => {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [PEER]);
  const { baseUrl } = await startServer(t, { stateDir, allowRemotePrompts: true });

  const prompt = 'hello from the LAN peer'; // 23 字符，回复应截到前 20
  const ask = await request(baseUrl, {
    method: 'POST',
    path: '/v1/ask',
    peerId: PEER.peerId,
    secret: PEER.inboundSecret,
    body: askBody({ prompt }),
  });
  assert.equal(ask.status, 202);
  assert.equal(typeof ask.json.sessionId, 'string');
  assert.ok(ask.json.sessionId.length > 0);

  const first = await request(baseUrl, {
    path: `/v1/answer?sessionId=${encodeURIComponent(ask.json.sessionId)}`,
    peerId: PEER.peerId,
    secret: PEER.inboundSecret,
  });
  assert.equal(first.status, 200);
  assert.equal(first.json.status, 'running');

  const done = await pollAnswer(baseUrl, {
    sessionId: ask.json.sessionId,
    peerId: PEER.peerId,
    secret: PEER.inboundSecret,
    timeoutMs: 5_000,
    intervalMs: 50,
  });
  assert.equal(done.status, 'done');
  assert.equal(done.reply, 'OK hello from the LAN p');
  assert.ok(done.reply.length > 0);
});

test('§5 同一 requestId 幂等：重复提交返回同一 sessionId，只执行一次', async (t) => {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [PEER]);
  const inner = createRunner({ delayMs: 20 });
  let askCalls = 0;
  const runner = {
    ask(prompt) {
      askCalls += 1;
      return inner.ask(prompt);
    },
    poll(sessionId) {
      return inner.poll(sessionId);
    },
  };
  const { baseUrl } = await startServer(t, { stateDir, runner, allowRemotePrompts: true });

  const first = await request(baseUrl, {
    method: 'POST',
    path: '/v1/ask',
    peerId: PEER.peerId,
    secret: PEER.inboundSecret,
    body: askBody({ requestId: 'same-request', prompt: '第一次' }),
  });
  const second = await request(baseUrl, {
    method: 'POST',
    path: '/v1/ask',
    peerId: PEER.peerId,
    secret: PEER.inboundSecret,
    body: askBody({ requestId: 'same-request', prompt: '第二次（应被忽略）' }),
  });
  assert.equal(first.status, 202);
  assert.equal(second.status, 202);
  assert.equal(second.json.sessionId, first.json.sessionId);
  assert.equal(askCalls, 1, '同一 requestId 只应触发一次 runner.ask');

  // 不同 requestId 是新会话
  const other = await request(baseUrl, {
    method: 'POST',
    path: '/v1/ask',
    peerId: PEER.peerId,
    secret: PEER.inboundSecret,
    body: askBody({ requestId: 'another-request', prompt: '另一件事' }),
  });
  assert.equal(other.status, 202);
  assert.notEqual(other.json.sessionId, first.json.sessionId);
  assert.equal(askCalls, 2);
});

test('§5 超时：默认 300s；timeoutSec 上限 900s；到期后 answer 返回 error:"timeout"', async (t) => {
  const clock = { now: Date.now() };
  const now = () => clock.now;
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [PEER]);
  // 1 小时后才完成的 runner，保证「超时」先于「完成」
  const runner = createRunner({ delayMs: 60 * 60 * 1000, now });
  const { baseUrl } = await startServer(t, {
    stateDir,
    runner,
    allowRemotePrompts: true,
    now,
  });

  const answer = (sessionId) => request(baseUrl, {
    path: `/v1/answer?sessionId=${encodeURIComponent(sessionId)}`,
    peerId: PEER.peerId,
    secret: PEER.inboundSecret,
    now,
  });
  const ask = (body) => request(baseUrl, {
    method: 'POST',
    path: '/v1/ask',
    peerId: PEER.peerId,
    secret: PEER.inboundSecret,
    body,
    now,
  });

  // 默认 timeoutSec = 300
  const defaulted = await ask(askBody({ requestId: 'default-timeout' }));
  assert.equal(defaulted.status, 202);

  clock.now += 299_000;
  let res = await answer(defaulted.json.sessionId);
  assert.equal(res.json.status, 'running');

  clock.now += 2_000; // 301s
  res = await answer(defaulted.json.sessionId);
  assert.equal(res.json.status, 'error');
  assert.equal(res.json.error, 'timeout');

  // timeoutSec=100000 被夹到 900
  const capped = await ask(askBody({ requestId: 'capped-timeout', timeoutSec: 100_000 }));
  assert.equal(capped.status, 202);

  clock.now += 899_000;
  res = await answer(capped.json.sessionId);
  assert.equal(res.json.status, 'running', '900s 上限内不应超时');

  clock.now += 2_000;
  res = await answer(capped.json.sessionId);
  assert.equal(res.json.status, 'error');
  assert.equal(res.json.error, 'timeout');
});

test('§5 ask 参数非法 → 400 bad-request；answer 缺 sessionId → 400', async (t) => {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [PEER]);
  const { baseUrl } = await startServer(t, { stateDir, allowRemotePrompts: true });

  const signedAsk = (body) => request(baseUrl, {
    method: 'POST',
    path: '/v1/ask',
    peerId: PEER.peerId,
    secret: PEER.inboundSecret,
    body,
  });

  for (const body of [
    { prompt: 'no requestId' },
    { requestId: 'r1' },
    { requestId: 'r2', prompt: '   ' },
    { requestId: 'r3', prompt: 'p', timeoutSec: 'abc' },
    { requestId: 'r4', prompt: 'p', timeoutSec: 0 },
    { requestId: 'r5', prompt: 'p', timeoutSec: -5 },
  ]) {
    const res = await signedAsk(body);
    assert.equal(res.status, 400, `body=${JSON.stringify(body)}`);
    assert.equal(res.json.error, 'bad-request');
  }

  const noSession = await request(baseUrl, {
    path: '/v1/answer',
    peerId: PEER.peerId,
    secret: PEER.inboundSecret,
  });
  assert.equal(noSession.status, 400);
  assert.equal(noSession.json.error, 'bad-request');
});

test('§5 会话归属：未配对/别的对端不能读，未知 sessionId → 404', async (t) => {
  const stateDir = makeTempStateDir();
  const peerA = peerFixture('peer-a');
  const peerB = peerFixture('peer-b');
  seedPeers(stateDir, [peerA, peerB]);
  const { baseUrl } = await startServer(t, { stateDir, allowRemotePrompts: true });

  const ask = await request(baseUrl, {
    method: 'POST',
    path: '/v1/ask',
    peerId: peerA.peerId,
    secret: peerA.inboundSecret,
    body: askBody({ requestId: 'owned-by-a' }),
  });
  assert.equal(ask.status, 202);

  const byOwner = await request(baseUrl, {
    path: `/v1/answer?sessionId=${encodeURIComponent(ask.json.sessionId)}`,
    peerId: peerA.peerId,
    secret: peerA.inboundSecret,
  });
  assert.equal(byOwner.status, 200);

  const byOtherPeer = await request(baseUrl, {
    path: `/v1/answer?sessionId=${encodeURIComponent(ask.json.sessionId)}`,
    peerId: peerB.peerId,
    secret: peerB.inboundSecret,
  });
  assert.equal(byOtherPeer.status, 404);
  assert.equal(byOtherPeer.json.error, 'unknown-session');

  const unknown = await request(baseUrl, {
    path: `/v1/answer?sessionId=${randomUUID()}`,
    peerId: peerA.peerId,
    secret: peerA.inboundSecret,
  });
  assert.equal(unknown.status, 404);
  assert.equal(unknown.json.error, 'unknown-session');
});

test('§3+§5 完整链路：配对 → 用返回的密钥 ask → answer done', async (t) => {
  const stateDir = makeTempStateDir();
  const runner = createRunner({ delayMs: 20 });
  const { server, baseUrl } = await startServer(t, {
    stateDir,
    runner,
    allowRemotePrompts: true,
    name: 'B',
  });

  const { code } = server.issuePairingCode();
  const paired = await request(baseUrl, {
    method: 'POST',
    path: '/v1/pair',
    signed: false,
    body: { code, peerId: 'peer-remote', peerName: 'A', secret: 'S-from-A' },
  });
  assert.equal(paired.status, 200);
  const peerSecret = paired.json.secret;

  const prompt = '请总结今天的所有构建日志，给出三条要点';
  const ask = await request(baseUrl, {
    method: 'POST',
    path: '/v1/ask',
    peerId: 'peer-remote',
    secret: peerSecret,
    body: { requestId: 'e2e-1', prompt },
  });
  assert.equal(ask.status, 202);

  const done = await pollAnswer(baseUrl, {
    sessionId: ask.json.sessionId,
    peerId: 'peer-remote',
    secret: peerSecret,
    timeoutMs: 5_000,
  });
  assert.equal(done.status, 'done');
  const expected = `OK ${[...prompt].slice(0, 20).join('')}`;
  assert.equal(done.reply, expected, '中文按 code point 截 20 字，不能截半个字');

  // 对端视角能看到刚配上的 A，但看不到 secret
  const peers = await request(baseUrl, {
    path: '/v1/peers',
    peerId: 'peer-remote',
    secret: peerSecret,
  });
  assert.equal(peers.status, 200);
  assert.deepEqual(peers.json.peers, [
    { peerId: 'peer-remote', name: 'A', baseUrl: null },
  ]);
  assert.equal(peers.text.includes(peerSecret), false);

  // state.json 里没有残留配对码
  assert.equal(readJson(`${stateDir}/state.json`).pairingCode, undefined);
});

// ---------------------------------------------------------------------------
// runner 接口 + 路由兜底
// ---------------------------------------------------------------------------

test('MemoryRunner：默认 1000ms 完成，reply = "OK <prompt 前 20 字>"', async () => {
  const clock = { now: 1_000 };
  const runner = createRunner({ now: () => clock.now });

  const sessionId = await runner.ask('1234567890123456789012345');
  assert.equal(typeof sessionId, 'string');

  clock.now += 999;
  assert.deepEqual(runner.poll(sessionId), { status: 'running' });

  clock.now += 1;
  assert.deepEqual(runner.poll(sessionId), {
    status: 'done',
    reply: 'OK 12345678901234567890',
  });

  assert.deepEqual(runner.poll('missing-session'), {
    status: 'error',
    error: 'unknown-session',
  });
});

test('未知路由 404；已知路由用错方法 405', async (t) => {
  const stateDir = makeTempStateDir();
  const { baseUrl } = await startServer(t, { stateDir });

  const unknown = await request(baseUrl, { path: '/v1/nope', signed: false });
  assert.equal(unknown.status, 404);
  assert.equal(unknown.json.error, 'not-found');

  const wrongMethod = await request(baseUrl, { method: 'POST', path: '/v1/health', signed: false });
  assert.equal(wrongMethod.status, 405);
  assert.equal(wrongMethod.json.error, 'method-not-allowed');

  const getAsk = await request(baseUrl, { path: '/v1/ask', signed: false });
  assert.equal(getAsk.status, 405);
});
