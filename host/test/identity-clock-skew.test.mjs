/**
 * 真机验收挖出来的缺口（2026-01 · NAS hub 时钟快 250–325ms）：
 *
 *   AC1 证书「未来签发」的前向时钟容差（DEFAULT_CERT_CLOCK_SKEW_MS = 60 秒，clockSkewMs 可覆盖/可关）；
 *   AC2 过期语义一字不动（1 天仍在 7 天宽限内，8 天 expired）；
 *   AC3 cachedGroupIdentity 的**否定结果**只缓存 5 秒（可用身份仍是 60 秒）；
 *   AC4 降级可见：[group] identity unavailable / available 各一行，状态切换才记，且不含路径/密钥。
 *
 * 时钟一律注入（config.now），不真等 60 秒/5 秒。出站 fetch 全拦，绝不真出网。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import {
  DEFAULT_CERT_CLOCK_SKEW_MS,
  DEFAULT_GRACE_MS,
  createKeypair,
  signCertificate,
  verifyCertificate,
} from '../../lib/group-identity.mjs';
import {
  GROUP_IDENTITY_CACHE_MS,
  GROUP_IDENTITY_NEGATIVE_CACHE_MS,
} from '../server.mjs';
import { makeTempStateDir, peerFixture, seedPeers, startServer } from './helpers.mjs';

const DAY = 24 * 60 * 60 * 1000;
const MEMBER_A = peerFixture('peer-clock-alpha');

function makeCa() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return { caPublicKey: publicKey, caPrivateKey: privateKey };
}

function makeCert(caPrivateKey, overrides = {}) {
  const now = Date.now();
  return signCertificate(caPrivateKey, {
    peerId: 'peer-a',
    pubKey: createKeypair().publicKeyDer,
    groupId: 'group-1',
    issuedAt: now - DAY,
    expiresAt: now + 29 * DAY,
    hubEpoch: 7,
    ...overrides,
  });
}

// ---------------------------------------------------------------------------
// AC1 · 前向时钟容差
// ---------------------------------------------------------------------------

test('AC1：not-yet-valid 给 60 秒前向容差，clockSkewMs:0 恢复零容忍', () => {
  assert.equal(DEFAULT_CERT_CLOCK_SKEW_MS, 60_000, '容差口径 = 群鉴权时钟窗 60 秒');
  const { caPublicKey, caPrivateKey } = makeCa();
  const issuedAt = Date.now();
  const cert = makeCert(caPrivateKey, { issuedAt, expiresAt: issuedAt + 30 * DAY });

  // 本机时钟「正好/略慢」都算有效
  assert.deepEqual(verifyCertificate(caPublicKey, cert, { now: issuedAt + 1 }), { ok: true });
  assert.deepEqual(verifyCertificate(caPublicKey, cert, { now: issuedAt }), { ok: true });
  assert.deepEqual(verifyCertificate(caPublicKey, cert, { now: issuedAt - 59_999 }), { ok: true });
  assert.deepEqual(verifyCertificate(caPublicKey, cert, { now: issuedAt - 60_000 }), { ok: true });

  // 越过容差 → 仍是既有的 not-yet-valid（不新造错误码）
  assert.deepEqual(
    verifyCertificate(caPublicKey, cert, { now: issuedAt - 60_001 }),
    { ok: false, reason: 'not-yet-valid' },
  );

  // 0 = 关掉容差（老行为，供测试钉边界）
  assert.deepEqual(
    verifyCertificate(caPublicKey, cert, { now: issuedAt - 1, clockSkewMs: 0 }),
    { ok: false, reason: 'not-yet-valid' },
  );
  // 覆盖值生效：容差 2 秒时 1.5 秒前仍接受，2.5 秒前拒绝
  assert.deepEqual(verifyCertificate(caPublicKey, cert, { now: issuedAt - 1_500, clockSkewMs: 2_000 }), { ok: true });
  assert.deepEqual(
    verifyCertificate(caPublicKey, cert, { now: issuedAt - 2_500, clockSkewMs: 2_000 }),
    { ok: false, reason: 'not-yet-valid' },
  );
  // 容差只对「未来签发」，不是「未来都放行」
  const farFuture = makeCert(caPrivateKey, { issuedAt: issuedAt + DAY, expiresAt: issuedAt + 30 * DAY });
  assert.deepEqual(
    verifyCertificate(caPublicKey, farFuture, { now: issuedAt }),
    { ok: false, reason: 'not-yet-valid' },
  );
});

// ---------------------------------------------------------------------------
// AC2 · 过期宽限语义不变
// ---------------------------------------------------------------------------

test('AC2：过期语义不被前向容差影响（+1 天 ok+grace，+8 天 expired）', () => {
  assert.equal(DEFAULT_GRACE_MS, 7 * DAY);
  const { caPublicKey, caPrivateKey } = makeCa();
  const now = Date.now();
  const expiredOneDay = makeCert(caPrivateKey, { issuedAt: now - 40 * DAY, expiresAt: now - DAY });
  assert.deepEqual(verifyCertificate(caPublicKey, expiredOneDay, { now }), { ok: true, grace: true });
  const expiredEightDays = makeCert(caPrivateKey, { issuedAt: now - 40 * DAY, expiresAt: now - 8 * DAY });
  assert.deepEqual(verifyCertificate(caPublicKey, expiredEightDays, { now }), { ok: false, reason: 'expired' });
});

// ---------------------------------------------------------------------------
// AC3 / AC4 · 出站 identity 的双窗口缓存 + 降级可见
// ---------------------------------------------------------------------------

const groupIdOf = (hub) => hub.server.group.state().groupId;

/** hub 先 claim 成 leader（此刻成员表为空 → 不出网），再放进一个带地址的成员 */
async function startLeaderHub(t, overrides = {}) {
  const stateDir = overrides.stateDir ?? makeTempStateDir();
  seedPeers(stateDir, [MEMBER_A]);
  const group = { enabled: true, name: 'default', autoJoin: false, retentionDays: 7, quorum: 'none' };
  const started = await startServer(t, {
    stateDir,
    allowRemotePrompts: true,
    ...overrides,
    group: { ...group, ...(overrides.group ?? {}) },
  });
  const claim = await started.server.group.claim();
  assert.equal(claim.ok, true, JSON.stringify(claim));
  started.server.group.addMember(MEMBER_A.peerId, MEMBER_A.name);
  return started;
}

/** 拦截出站 fetch：只验「读了几次身份 / 记了什么日志」，绝不真出网 */
async function captureOutbound(fn) {
  const original = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
  try {
    return await fn();
  } finally {
    globalThis.fetch = original;
  }
}

test('AC3：否定结果只缓存 5 秒（可用身份仍是 60 秒）', async (t) => {
  assert.equal(GROUP_IDENTITY_NEGATIVE_CACHE_MS, 5_000);
  let clock = Date.now();
  let loads = 0;
  const hub = await startLeaderHub(t, {
    now: () => clock,
    groupIdentityLoader: () => {
      loads += 1;
      return { ok: false, code: 'identity-missing' };
    },
  });
  const read = () => captureOutbound(() => hub.server.group.heartbeat());

  await read();
  assert.equal(loads, 1);
  clock += 4_999;
  await read();
  assert.equal(loads, 1, '5 秒窗口内不重读（300ms 抖动不会变成每分钟重读，但也不能无限重读）');
  clock += 2;
  await read();
  assert.equal(loads, 2, '越过 5 秒必须重读：时钟追赶/证书刚签发要秒级自愈');
  clock += 5_000;
  await read();
  assert.equal(loads, 3, '否定窗口每次过期都重读');
});

test('AC3：groupIdentityNegativeCacheMs:0 → 每次出站都重读身份', async (t) => {
  let loads = 0;
  const hub = await startLeaderHub(t, {
    groupIdentityNegativeCacheMs: 0,
    groupIdentityLoader: () => {
      loads += 1;
      return { ok: false, code: 'identity-missing' };
    },
  });
  await captureOutbound(() => hub.server.group.heartbeat());
  const first = loads;
  assert.ok(first >= 1);
  await captureOutbound(() => hub.server.group.heartbeat());
  assert.ok(loads > first, `0 = 不缓存否定结果，实际 ${first} → ${loads}`);
});

test('AC3：读到可用身份仍按 60 秒缓存（窗口内 loader 只调一次）', async (t) => {
  assert.equal(GROUP_IDENTITY_CACHE_MS, 60_000);
  let clock = Date.now();
  let loads = 0;
  let current = null;
  const hub = await startLeaderHub(t, {
    now: () => clock,
    groupIdentityLoader: () => {
      loads += 1;
      return current;
    },
  });
  const keys = createKeypair();
  const groupId = groupIdOf(hub);
  const issuedAt = Date.now();
  current = {
    ok: true,
    cert: {
      peerId: hub.server.store.instanceId,
      pubKey: keys.publicKeyDer,
      groupId,
      issuedAt,
      expiresAt: issuedAt + 30 * DAY,
      hubEpoch: 0,
      alg: 'ed25519',
      sig: 'stub',
    },
    keypair: keys,
    trustedHubCa: { hubCaPubKey: 'stub', hubEpoch: 0, at: issuedAt, source: 'register' },
  };

  await captureOutbound(() => hub.server.group.heartbeat());
  assert.equal(loads, 1);
  clock += 30_000;
  await captureOutbound(() => hub.server.group.heartbeat());
  assert.equal(loads, 1, '60 秒窗口内不再解封私钥/验证书');
  clock += 31_000;
  await captureOutbound(() => hub.server.group.heartbeat());
  assert.equal(loads, 2, '窗口过后重读');
});

test('AC4：降级可见 —— 连续不可用只记一行、恢复记一行、内容不含路径/密钥', async (t) => {
  const logs = [];
  let phase = 'missing';
  let stub = null;
  const hub = await startLeaderHub(t, {
    // 两个窗口都压成 0：每个出站请求都真读一次身份，这样才能证明「读了很多次，只记一行」
    groupIdentityCacheMs: 0,
    groupIdentityNegativeCacheMs: 0,
    logger: (line) => logs.push(line),
    groupIdentityLoader: () => {
      if (phase === 'ok') return stub;
      if (phase === 'hostile') return { ok: false, reason: 'C:/Users/secret/cert.json?token=abcdef' };
      return { ok: false, code: 'identity-missing' };
    },
  });
  const identityLines = () => logs.filter((line) => /\[group\] identity (un)?available/.test(line));
  const cycle = () => captureOutbound(() => hub.server.group.heartbeat());

  const keys = createKeypair();
  const groupId = groupIdOf(hub);
  const issuedAt = Date.now();
  stub = {
    ok: true,
    cert: {
      peerId: hub.server.store.instanceId,
      pubKey: keys.publicKeyDer,
      groupId,
      issuedAt,
      expiresAt: issuedAt + 30 * DAY,
      hubEpoch: 0,
      alg: 'ed25519',
      sig: 'stub',
    },
    keypair: keys,
    trustedHubCa: { hubCaPubKey: 'stub', hubEpoch: 0, at: issuedAt, source: 'register' },
  };

  await cycle();
  await cycle();
  await cycle();
  assert.deepEqual(identityLines(), ['[group] identity unavailable reason=identity-missing']);

  phase = 'ok';
  await cycle();
  assert.deepEqual(identityLines().slice(1), ['[group] identity available']);
  await cycle();
  assert.equal(identityLines().length, 2, '持续可用不再刷屏');

  // 再次降级：先重读一次失败（否定窗口 0）→ 又切换成不可用，再记一行
  phase = 'missing';
  await cycle();
  assert.equal(identityLines().length, 3);
  assert.equal(identityLines()[2], '[group] identity unavailable reason=identity-missing');

  // 诚实测试：reason 里塞路径/查询串/大写混排也漏不出去。
  // 先恢复一次再降级：否则「不可用 → 不可用」不是状态切换，本来就不该记第二行。
  phase = 'ok';
  await cycle();
  phase = 'hostile';
  await cycle();
  const hostileLine = identityLines()[4];
  assert.ok(typeof hostileLine === 'string', `期望第 5 行存在，实际 ${JSON.stringify(identityLines())}`);
  assert.equal(hostileLine, '[group] identity unavailable reason=unknown');


  for (const line of identityLines()) {
    assert.ok(line.length <= 120, `日志行过长：${line}`);
    assert.equal(/[\\/]/.test(line), false, `日志行含路径分隔符：${line}`);
  }
});
