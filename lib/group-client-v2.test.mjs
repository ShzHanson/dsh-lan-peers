// dsh-lan-peers · P2 v2 通道（证书 + ed25519）成员侧的钉子。
//
// 这里钉死九件事（都是"改坏了会静默失效"的那种）：
//   1. §2 头集合逐字段一致：字段名与 v1 相同，只多 X-Peer-Cert = base64url(UTF8(JSON))；
//   2. 签名字节 = buildGroupCanonicalV2(...)，能被 P1 的 verifyMessage 验过（正面断言）；
//   3. 负例：改 ts/nonce/groupId/senderPeerId/body 任一项 → 验签失败；cert 被篡改 → 证书验不过；
//   4. 身份文件 0600 + 原子写（不留临时文件）；损坏内容读取**不抛未捕获异常**，报 identity-unavailable；
//   5. 回落：没有身份 / 身份不可用 → 既有 v1 头逐字段不变（groupCall 仍发 X-Peer-Auth: group）；
//   6. rotate 未到轮换时刻**不发请求**；
//   7. register 用 v1 头（证明握有 groupKey），rotate 用 v2 头（旧证书 + 旧私钥）；
//   8. §8.2 pairProof：给了 pairSecret 才带（三字段固定顺序、不含 pairProof 自身），
//      用 client/protocol.mjs 的 canonical + sign 对拍；没给 → 请求体里连键都不存在；
//   9. §8.3 identity 透传：groupCall 与 10 个包装器给了 identity 走 v2、不给逐字节仍走 v1。
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { generateKeyPairSync } from 'node:crypto';
import { makeTempStateDir } from '../host/test/helpers.mjs';
import { ENC_HEADER, ENC_VERSION } from './wire-crypto.mjs';
import { canonical as perPeerCanonical, sign as perPeerSign } from '../client/protocol.mjs';
import {
  GROUP_AUTH_VALUE,
  GROUP_CERT_HEADER,
  GROUP_AUTH_VALUE_V2,
  GROUP_IDENTITY_ROTATE_PATH,
  GROUP_MEMBER_CERT_FILE,
  GROUP_TRUSTED_HUB_CA_FILE,
  buildGroupCanonical,
  decryptGroupJson,
  deriveGroupKeys,
  encodeGroupCertHeader,
  encryptGroupJson,
  groupAuthHeaders,
  groupAuthHeadersV2,
  groupAuthHeadersWithIdentity,
  groupCall,
  groupCallV2,
  loadGroupIdentity,
  memberCertPath,
  readMemberCertFile,
  readTrustedHubCaFile,
  registerGroupIdentity,
  rotateGroupIdentity,
  trustedHubCaPath,
  writeMemberCertFile,
  writeTrustedHubCaFile,
  // §8.3：10 个 groupCall 包装器（identity 必透传）
  probeGroupPeer,
  pullGroupMessages,
  replicateGroupMessages,
  fetchGroupLeader,
  sendGroupHeartbeat,
  requestGroupVote,
  proposeGroupMessage,
  commitGroupMessage,
  fetchGroupLease,
  postGroupWithGroupKey,
} from './group-client.mjs';
import {
  IDENTITY_UNAVAILABLE,
  createKeypair,
  saveKeypair,
  signCertificate,
  verifyCertificate,
  verifyMessage,
} from './group-identity.mjs';

const DAY = 24 * 60 * 60 * 1000;
const GROUP_ID = 'group-v2-fixture';
const PEER_ID = 'peer-member-a';
const GROUP_KEY = Buffer.alloc(32, 3).toString('base64url');
/** 注入固定指纹：测试不碰真机 MachineGuid，也不需要真实设备绑定 */
const FP = Buffer.alloc(32, 7);

const withTempDir = (fn) => {
  const dir = makeTempStateDir('dsh-group-client-v2-');
  try {
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
};

/** node:test 里 await 临时目录清理的薄封装（避免 withTempDir 里忘记 await 导致目录泄漏） */
async function withTempDirAsync(fn) {
  const dir = makeTempStateDir('dsh-group-client-v2-');
  try {
    return await fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/** hub 侧 CA（只在这里当夹具用：签证书是 hub 的活） */
function makeCa() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicKey,
    privateKey,
    pubKeyText: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
  };
}

/** 一张成员证书（时间可覆盖） */
function makeCert(ca, { peerId = PEER_ID, groupId = GROUP_ID, pubKey, issuedAt, expiresAt } = {}) {
  const now = Date.now();
  return signCertificate(ca.privateKey, {
    peerId,
    pubKey,
    groupId,
    issuedAt: issuedAt ?? now,
    expiresAt: expiresAt ?? now + 30 * DAY,
    hubEpoch: 3,
  });
}

/** 一套完整的成员侧身份（member-key.json + member-cert.json + trusted-hub-ca.json） */
function setupIdentity(stateDir, options = {}) {
  const ca = options.ca ?? makeCa();
  const keypair = options.keypair ?? createKeypair();
  saveKeypair(stateDir, keypair, { fingerprint: FP, peerId: PEER_ID });
  const cert = makeCert(ca, {
    pubKey: keypair.publicKeyDer,
    issuedAt: options.issuedAt,
    expiresAt: options.expiresAt,
  });
  writeMemberCertFile(stateDir, cert);
  writeTrustedHubCaFile(stateDir, { hubCaPubKey: ca.pubKeyText, hubEpoch: 3, source: 'register' });
  return { ca, keypair, cert };
}

/** 假 fetch：把 answer 装成群信封返回，并记录请求（不碰网络、不占端口） */
function stubFetch(answer) {
  const calls = [];
  const { bodyKey } = deriveGroupKeys(GROUP_KEY);
  const impl = async (url, init) => {
    calls.push({ url: String(url), init });
    const data = JSON.stringify({ enc: ENC_VERSION, data: encryptGroupJson(bodyKey, answer) });
    return { ok: true, status: 200, text: async () => data };
  };
  impl.calls = calls;
  return impl;
}

const baseHeaderArgs = {
  groupKey: GROUP_KEY,
  groupId: GROUP_ID,
  senderId: PEER_ID,
  method: 'POST',
  apiPath: '/v1/group/post',
  body: { kind: 'chat', text: 'hello' },
  ts: 1_700_000_000_000,
  nonce: 'a1b2c3d4e5f60718',
};

// ---------------------------------------------------------------------------
// 1. §2 头集合
// ---------------------------------------------------------------------------

test('v2 头：字段名与 v1 完全一致，只多 X-Peer-Cert，值按 §2', () => {
  const ca = makeCa();
  const keypair = createKeypair();
  const cert = makeCert(ca, { pubKey: keypair.publicKeyDer });
  const { headers, plain } = groupAuthHeadersV2({ cert, privateKey: keypair.privateKey, ...baseHeaderArgs });

  assert.deepEqual(Object.keys(headers).sort(), [
    'X-Peer-Auth',
    'X-Peer-Cert',
    'X-Peer-Group',
    'X-Peer-Id',
    'X-Peer-Nonce',
    'X-Peer-Sign',
    'X-Peer-Ts',
  ]);
  assert.equal(headers['X-Peer-Auth'], GROUP_AUTH_VALUE_V2);
  assert.equal(GROUP_AUTH_VALUE_V2, 'group-v2');
  assert.equal(GROUP_CERT_HEADER, 'X-Peer-Cert');
  assert.equal(headers['X-Peer-Id'], PEER_ID);
  assert.equal(headers['X-Peer-Group'], GROUP_ID);
  assert.equal(headers['X-Peer-Ts'], String(baseHeaderArgs.ts));
  assert.equal(headers['X-Peer-Nonce'], baseHeaderArgs.nonce);
  assert.equal(headers[GROUP_CERT_HEADER], encodeGroupCertHeader(cert));
  assert.equal(headers[GROUP_CERT_HEADER], Buffer.from(JSON.stringify(cert), 'utf8').toString('base64url'));
  assert.equal(
    JSON.parse(Buffer.from(headers[GROUP_CERT_HEADER], 'base64url').toString('utf8')).peerId,
    PEER_ID,
  );
  // 签名覆盖明文 body（与 v1 相同口径）
  assert.equal(plain.toString('utf8'), JSON.stringify(baseHeaderArgs.body));
});

test('v2 canonical 与 v1 逐字节相同，且签名能被 P1 的 verifyMessage 验过', () => {
  const ca = makeCa();
  const keypair = createKeypair();
  const cert = makeCert(ca, { pubKey: keypair.publicKeyDer });
  const v2 = groupAuthHeadersV2({ cert, privateKey: keypair.privateKey, ...baseHeaderArgs });
  const v1Canonical = buildGroupCanonical({
    method: baseHeaderArgs.method,
    path: baseHeaderArgs.apiPath,
    ts: baseHeaderArgs.ts,
    nonce: baseHeaderArgs.nonce,
    groupId: GROUP_ID,
    senderPeerId: PEER_ID,
    rawBody: v2.plain,
  });
  assert.equal(v2.canonical, v1Canonical, 'v2 与 v1 必须同一套 canonical（域分离靠头，不靠字符串）');

  const sign = v2.headers['X-Peer-Sign'];
  assert.equal(verifyMessage(keypair.publicKey, v2.canonical, sign), true, '字符串形态可验');
  assert.equal(verifyMessage(keypair.publicKey, {
    method: baseHeaderArgs.method,
    path: baseHeaderArgs.apiPath,
    ts: baseHeaderArgs.ts,
    nonce: baseHeaderArgs.nonce,
    groupId: GROUP_ID,
    senderPeerId: PEER_ID,
    rawBody: v2.plain,
  }, sign), true, '对象形态可验（协议层两种传法都要过）');
  assert.equal(verifyMessage(ca.publicKey, v2.canonical, sign), false, '换个公钥就验不过');
});

test('v2 负例：改 ts/nonce/groupId/senderPeerId/body 任一字节 → 验签失败', () => {
  const ca = makeCa();
  const keypair = createKeypair();
  const cert = makeCert(ca, { pubKey: keypair.publicKeyDer });
  const { headers, canonical } = groupAuthHeadersV2({ cert, privateKey: keypair.privateKey, ...baseHeaderArgs });
  const sign = headers['X-Peer-Sign'];
  assert.equal(verifyMessage(keypair.publicKey, canonical, sign), true);

  const mutations = {
    ts: canonical.replace('1700000000000', '1700000000001'),
    nonce: canonical.replace('a1b2c3d4e5f60718', 'a1b2c3d4e5f60719'),
    groupId: canonical.replace(GROUP_ID, `${GROUP_ID}x`),
    senderPeerId: canonical.replace(PEER_ID, `${PEER_ID}x`),
    body: canonical.replace(/(\n[0-9a-f]{64})$/, `\n${'0'.repeat(64)}`),
  };
  for (const [field, mutated] of Object.entries(mutations)) {
    assert.notEqual(mutated, canonical, `${field} 必须真的被改到`);
    assert.equal(verifyMessage(keypair.publicKey, mutated, sign), false, `${field} 被改后必须验签失败`);
  }
  // 头里的签名被换一个字符同样过不去
  const first = sign[0] === 'A' ? 'B' : 'A';
  assert.equal(verifyMessage(keypair.publicKey, canonical, first + sign.slice(1)), false);
});

test('v2 负例：cert 被篡改 → verifyCertificate 失败，且签出来的头带上的是篡改后的证书', () => {
  const ca = makeCa();
  const keypair = createKeypair();
  const cert = makeCert(ca, { pubKey: keypair.publicKeyDer });
  assert.equal(verifyCertificate(ca.publicKey, cert).ok, true, '原证书必须验得过');

  const tampered = { ...cert, peerId: 'peer-someone-else' };
  const verdict = verifyCertificate(ca.publicKey, tampered);
  assert.equal(verdict.ok, false);
  assert.equal(verdict.reason, 'bad-signature');

  const { headers } = groupAuthHeadersV2({ cert: tampered, privateKey: keypair.privateKey, ...baseHeaderArgs });
  const carried = JSON.parse(Buffer.from(headers[GROUP_CERT_HEADER], 'base64url').toString('utf8'));
  assert.equal(carried.peerId, 'peer-someone-else', '头里带的就是篡改后的证书（服务端必须自己验）');
  assert.equal(verifyCertificate(ca.publicKey, carried).ok, false);
});

// ---------------------------------------------------------------------------
// 2. 身份文件读写
// ---------------------------------------------------------------------------

test('身份文件：0600、原子写、不留临时文件，读回逐字段一致', () => {
  withTempDir((stateDir) => {
    const ca = makeCa();
    const keypair = createKeypair();
    const cert = makeCert(ca, { pubKey: keypair.publicKeyDer });
    writeMemberCertFile(stateDir, cert);
    writeTrustedHubCaFile(stateDir, { hubCaPubKey: ca.pubKeyText, hubEpoch: 3, at: 1_700_000_000_000 });

    assert.equal(memberCertPath(stateDir), path.join(stateDir, 'group', GROUP_MEMBER_CERT_FILE));
    assert.equal(trustedHubCaPath(stateDir), path.join(stateDir, 'group', GROUP_TRUSTED_HUB_CA_FILE));

    const certRead = readMemberCertFile(stateDir);
    assert.equal(certRead.ok, true);
    assert.deepEqual(certRead.cert, cert);

    const trustRead = readTrustedHubCaFile(stateDir);
    assert.equal(trustRead.ok, true);
    assert.equal(trustRead.trust.hubCaPubKey, ca.pubKeyText);
    assert.equal(trustRead.trust.hubEpoch, 3);
    assert.equal(trustRead.trust.at, 1_700_000_000_000);
    assert.equal(trustRead.trust.source, 'register', '缺省 source 按契约 §4 写成 register');
    assert.deepEqual(Object.keys(JSON.parse(fs.readFileSync(trustedHubCaPath(stateDir), 'utf8'))), [
      'hubCaPubKey', 'hubEpoch', 'at', 'source',
    ], '字段序按契约 §4');

    // 原子写：目录里只剩两个身份文件，没有 .tmp 残留
    const leftovers = fs.readdirSync(path.join(stateDir, 'group')).filter((name) => name.endsWith('.tmp'));
    assert.deepEqual(leftovers, [], '不许留临时文件');
    if (process.platform !== 'win32') {
      for (const file of [memberCertPath(stateDir), trustedHubCaPath(stateDir)]) {
        assert.equal(fs.statSync(file).mode & 0o777, 0o600, `${file} 必须是 0600`);
      }
    }
  });
});

test('身份文件：损坏/缺失内容读取不抛未捕获异常，报 identity-unavailable / identity-missing', () => {
  withTempDir((stateDir) => {
    // 全缺失
    assert.equal(readMemberCertFile(stateDir).ok, false);
    assert.equal(readMemberCertFile(stateDir).code, 'identity-missing');
    assert.equal(readTrustedHubCaFile(stateDir).ok, false);
    assert.equal(readTrustedHubCaFile(stateDir).code, 'identity-missing');
    const empty = loadGroupIdentity(stateDir);
    assert.equal(empty.ok, false, '没有身份 → 回落，不抛错');

    // 坏 JSON
    fs.mkdirSync(path.join(stateDir, 'group'), { recursive: true });
    fs.writeFileSync(memberCertPath(stateDir), '{ not json ', { mode: 0o600 });
    const broken = readMemberCertFile(stateDir);
    assert.equal(broken.ok, false);
    assert.equal(broken.code, IDENTITY_UNAVAILABLE);
    assert.equal(broken.reason, 'malformed-json');

    // 合法 JSON 但形状不对
    fs.writeFileSync(memberCertPath(stateDir), JSON.stringify({ peerId: PEER_ID }), { mode: 0o600 });
    const shape = readMemberCertFile(stateDir);
    assert.equal(shape.ok, false);
    assert.equal(shape.code, IDENTITY_UNAVAILABLE);
    assert.equal(shape.reason, 'malformed-cert');

    // 信任根缺公钥
    fs.writeFileSync(trustedHubCaPath(stateDir), JSON.stringify({ hubEpoch: 1 }), { mode: 0o600 });
    const trust = readTrustedHubCaFile(stateDir);
    assert.equal(trust.ok, false);
    assert.equal(trust.reason, 'malformed-trusted-hub-ca');

    // 整条链兜住：loadGroupIdentity 对烂文件也不抛
    assert.equal(loadGroupIdentity(stateDir).ok, false);
  });
});

test('loadGroupIdentity：证书与私钥不配对 → cert-key-mismatch（不静默用错密钥）', () => {
  withTempDir((stateDir) => {
    const ca = makeCa();
    const mine = createKeypair();
    const other = createKeypair();
    saveKeypair(stateDir, mine, { fingerprint: FP, peerId: PEER_ID });
    // 证书里写的是别人的公钥
    writeMemberCertFile(stateDir, makeCert(ca, { pubKey: other.publicKeyDer }));
    writeTrustedHubCaFile(stateDir, { hubCaPubKey: ca.pubKeyText, hubEpoch: 3 });
    const loaded = loadGroupIdentity(stateDir, { fingerprint: FP });
    assert.equal(loaded.ok, false);
    assert.equal(loaded.code, 'cert-key-mismatch');
  });
});

// ---------------------------------------------------------------------------
// 3. 回落（契约 §6）：没有证书 / 身份不可用 → 一律 v1，不报错中断
// ---------------------------------------------------------------------------

test('回落：没有任何身份文件 → 自动通道输出与 groupAuthHeaders 逐字段相同（v1 头照旧）', () => {
  withTempDir((stateDir) => {
    const v1 = groupAuthHeaders(baseHeaderArgs);
    const auto = groupAuthHeadersWithIdentity({ stateDir, ...baseHeaderArgs });
    assert.equal(auto.version, 'v1');
    assert.deepEqual(auto.headers, v1.headers);
    assert.equal(auto.canonical, v1.canonical);
    assert.equal(auto.plain.toString('utf8'), v1.plain.toString('utf8'));
    assert.equal(auto.headers['X-Peer-Auth'], GROUP_AUTH_VALUE);
    assert.equal(auto.headers[GROUP_CERT_HEADER], undefined, 'v1 头里不会凭空多出证书头');
  });
});

test('回落：有证书但没有 member-key.json / 信任根损坏 → 仍是 v1，且给出可识别原因', () => {
  withTempDir((stateDir) => {
    const ca = makeCa();
    const keypair = createKeypair();
    writeMemberCertFile(stateDir, makeCert(ca, { pubKey: keypair.publicKeyDer }));

    // 只有证书，没有私钥
    const noKey = groupAuthHeadersWithIdentity({ stateDir, ...baseHeaderArgs });
    assert.equal(noKey.version, 'v1');
    assert.equal(noKey.reason, 'identity-missing');
    assert.equal(noKey.headers[GROUP_CERT_HEADER], undefined);

    // 私钥有了，信任根是垃圾
    saveKeypair(stateDir, keypair, { fingerprint: FP, peerId: PEER_ID });
    fs.writeFileSync(trustedHubCaPath(stateDir), '{ nope', { mode: 0o600 });
    const noTrust = groupAuthHeadersWithIdentity({ stateDir, ...baseHeaderArgs });
    assert.equal(noTrust.version, 'v1');
    assert.equal(noTrust.reason, IDENTITY_UNAVAILABLE);
  });
});

test('回落：既有 groupCall 行为不变 —— 仍发 X-Peer-Auth: group，且没有 X-Peer-Cert', async () => {
  const seen = [];
  const { bodyKey } = deriveGroupKeys(GROUP_KEY);
  const fetchImpl = async (url, init) => {
    seen.push({ url: String(url), headers: init.headers, body: init.body });
    return {
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ enc: ENC_VERSION, data: encryptGroupJson(bodyKey, { ok: true }) }),
    };
  };
  const answer = await groupCall({
    baseUrl: 'http://127.0.0.1:7788',
    groupKey: GROUP_KEY,
    groupId: GROUP_ID,
    senderId: PEER_ID,
    method: 'POST',
    apiPath: '/v1/group/post',
    body: { kind: 'chat', text: 'hi' },
    fetchImpl,
  });
  assert.deepEqual(answer, { ok: true });
  assert.equal(seen.length, 1);
  assert.equal(seen[0].headers['X-Peer-Auth'], 'group');
  assert.equal(seen[0].headers[GROUP_CERT_HEADER], undefined);
  assert.deepEqual(
    Object.keys(seen[0].headers).sort(),
    ['X-Peer-Auth', 'X-Peer-Group', 'X-Peer-Id', 'X-Peer-Nonce', 'X-Peer-Sign', 'X-Peer-Ts', ENC_HEADER].sort(),
    'v1 头集合一字不多一字不少（只多群信封版本头）',
  );
});

test('身份齐备时自动通道走 v2，签名可用 member 公钥验过', () => {
  withTempDir((stateDir) => {
    const { keypair } = setupIdentity(stateDir);
    const auto = groupAuthHeadersWithIdentity({ stateDir, fingerprint: FP, ...baseHeaderArgs });
    assert.equal(auto.version, 'v2');
    assert.equal(auto.headers['X-Peer-Auth'], GROUP_AUTH_VALUE_V2);
    assert.ok(auto.headers[GROUP_CERT_HEADER]);
    assert.equal(verifyMessage(keypair.publicKey, auto.canonical, auto.headers['X-Peer-Sign']), true);
  });
});

// ---------------------------------------------------------------------------
// 4. 注册 / 轮换（契约 §5）
// ---------------------------------------------------------------------------

test('register 用 v1 头（证明握有 groupKey），成功后落盘证书与信任根', async () => {
  await withTempDirAsync(async (stateDir) => {
    const ca = makeCa();
    const keypair = createKeypair();
    const cert = makeCert(ca, { pubKey: keypair.publicKeyDer });
    const fetchImpl = stubFetch({ cert, hubCaPubKey: ca.pubKeyText, hubEpoch: 3 });

    const result = await registerGroupIdentity({
      stateDir,
      baseUrl: 'http://127.0.0.1:7788',
      groupKey: GROUP_KEY,
      groupId: GROUP_ID,
      peerId: PEER_ID,
      keypair,
      fetchImpl,
    });

    assert.equal(result.ok, true);
    assert.deepEqual(result.cert, cert);
    assert.equal(result.hubCaPubKey, ca.pubKeyText);
    assert.equal(fetchImpl.calls.length, 1);
    assert.match(fetchImpl.calls[0].url, /\/v1\/group\/identity\/register$/);
    assert.equal(fetchImpl.calls[0].init.method, 'POST');
    assert.equal(fetchImpl.calls[0].init.headers['X-Peer-Auth'], 'group', 'register 必须走 v1 头');
    assert.equal(fetchImpl.calls[0].init.headers[GROUP_CERT_HEADER], undefined);

    // 请求体是群信封，解开看明文
    const { bodyKey } = deriveGroupKeys(GROUP_KEY);
    const sent = decryptGroupJson(bodyKey, fetchImpl.calls[0].init.body.toString('utf8'));
    assert.deepEqual(sent, { peerId: PEER_ID, pubKey: keypair.publicKeyDer, groupId: GROUP_ID });

    // 落盘
    const certRead = readMemberCertFile(stateDir);
    assert.equal(certRead.ok, true);
    assert.equal(certRead.cert.pubKey, keypair.publicKeyDer);
    assert.equal(readTrustedHubCaFile(stateDir).trust.hubCaPubKey, ca.pubKeyText);
  });
});

test('register：本地没有私钥 → 不发请求（回落 v1，不报错中断）', async () => {
  await withTempDirAsync(async (stateDir) => {
    const fetchImpl = stubFetch({});
    const result = await registerGroupIdentity({
      stateDir,
      baseUrl: 'http://127.0.0.1:7788',
      groupKey: GROUP_KEY,
      groupId: GROUP_ID,
      peerId: PEER_ID,
      fetchImpl,
    });
    assert.equal(result.skipped, true);
    assert.equal(result.reason, 'identity-missing');
    assert.equal(fetchImpl.calls.length, 0);
  });
});

test('rotate：本地证书未到轮换时刻 → 不发请求', async () => {
  await withTempDirAsync(async (stateDir) => {
    setupIdentity(stateDir); // issuedAt = now → 30 天后才该换
    const fetchImpl = stubFetch({});
    const result = await rotateGroupIdentity({
      stateDir,
      baseUrl: 'http://127.0.0.1:7788',
      groupKey: GROUP_KEY,
      groupId: GROUP_ID,
      fingerprint: FP,
      fetchImpl,
    });
    assert.equal(result.skipped, true);
    assert.equal(result.reason, 'not-due');
    assert.equal(fetchImpl.calls.length, 0, '未到期必须省掉这次网络往返');
  });
});

test('rotate：到期时用 v2 头（旧证书 + 旧私钥）发一次请求，并落盘新私钥/新证书', async () => {
  await withTempDirAsync(async (stateDir) => {
    const now = Date.now();
    // 31 天前签发、1 天前过期（仍在 7 天宽限内）→ 必须轮换
    const { ca, keypair: oldPair, cert: oldCert } = setupIdentity(stateDir, {
      issuedAt: now - 31 * DAY,
      expiresAt: now - 1 * DAY,
    });
    const next = createKeypair();
    const nextCert = makeCert(ca, { pubKey: next.publicKeyDer });
    const fetchImpl = stubFetch({ cert: nextCert, hubCaPubKey: ca.pubKeyText, hubEpoch: 4 });

    const result = await rotateGroupIdentity({
      stateDir,
      baseUrl: 'http://127.0.0.1:7788',
      groupKey: GROUP_KEY,
      groupId: GROUP_ID,
      peerId: PEER_ID,
      newKeypair: next,
      fingerprint: FP,
      now,
      fetchImpl,
    });

    assert.equal(result.ok, true);
    assert.deepEqual(result.cert, nextCert);
    assert.equal(result.hubCaPubKey, ca.pubKeyText);
    assert.equal(result.hubEpoch, 4);
    assert.equal(fetchImpl.calls.length, 1);
    assert.match(fetchImpl.calls[0].url, new RegExp(`${GROUP_IDENTITY_ROTATE_PATH}$`));

    const headers = fetchImpl.calls[0].init.headers;
    assert.equal(headers['X-Peer-Auth'], GROUP_AUTH_VALUE_V2, 'rotate 必须走 v2 头');
    assert.equal(headers[GROUP_CERT_HEADER], encodeGroupCertHeader(oldCert), '带的是**旧**证书');
    // 旧私钥签的，能被旧证书里的公钥验过
    const { bodyKey } = deriveGroupKeys(GROUP_KEY);
    const sent = decryptGroupJson(bodyKey, fetchImpl.calls[0].init.body.toString('utf8'));
    assert.deepEqual(sent, { peerId: PEER_ID, newPubKey: next.publicKeyDer, groupId: GROUP_ID });
    assert.equal(verifyMessage(
      oldPair.publicKey,
      buildGroupCanonical({
        method: 'POST',
        path: GROUP_IDENTITY_ROTATE_PATH,
        ts: headers['X-Peer-Ts'],
        nonce: headers['X-Peer-Nonce'],
        groupId: GROUP_ID,
        senderPeerId: PEER_ID,
        rawBody: Buffer.from(JSON.stringify(sent), 'utf8'),
      }),
      headers['X-Peer-Sign'],
    ), true, 'rotate 的签名覆盖明文 body');

    // 新证书 + 新私钥一起落盘，且重新 load 得到新身份
    assert.equal(readMemberCertFile(stateDir).cert.pubKey, next.publicKeyDer);
    const reloaded = loadGroupIdentity(stateDir, { fingerprint: FP });
    assert.equal(reloaded.ok, true);
    assert.equal(reloaded.keypair.publicKeyDer, next.publicKeyDer);
    assert.equal(reloaded.cert.peerId, PEER_ID);
  });
});

test('rotate：身份不可用（没有证书）→ 不发请求，回落到 v1', async () => {
  await withTempDirAsync(async (stateDir) => {
    const fetchImpl = stubFetch({});
    const result = await rotateGroupIdentity({
      stateDir,
      baseUrl: 'http://127.0.0.1:7788',
      groupKey: GROUP_KEY,
      groupId: GROUP_ID,
      fingerprint: FP,
      fetchImpl,
    });
    assert.equal(result.skipped, true);
    assert.equal(result.reason, 'identity-missing');
    assert.equal(fetchImpl.calls.length, 0);
  });
});

test('groupCallV2：线上是群信封 + v2 头，响应解密后返回', async () => {
  withTempDir((stateDir) => {
    const { ca, keypair, cert } = setupIdentity(stateDir);
    const calls = [];
    const { bodyKey } = deriveGroupKeys(GROUP_KEY);
    const fetchImpl = async (url, init) => {
      calls.push({ url: String(url), init });
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({
          enc: ENC_VERSION,
          data: encryptGroupJson(bodyKey, { pong: true }),
        }),
      };
    };
    return groupCallV2({
      baseUrl: 'http://127.0.0.1:7788',
      groupKey: GROUP_KEY,
      groupId: GROUP_ID,
      senderId: PEER_ID,
      cert,
      privateKey: keypair.privateKey,
      method: 'POST',
      apiPath: '/v1/group/identity/rotate',
      body: { probe: 1 },
      fetchImpl,
    }).then((answer) => {
      assert.deepEqual(answer, { pong: true });
      const headers = calls[0].init.headers;
      assert.equal(headers['X-Peer-Auth'], GROUP_AUTH_VALUE_V2);
      assert.equal(headers[GROUP_CERT_HEADER], encodeGroupCertHeader(cert));
      assert.equal(verifyCertificate(ca.publicKey, cert).ok, true);
    });
  });
});

// ---------------------------------------------------------------------------
// 5. §8.3 生产接线：groupCall 的 identity 分支
// ---------------------------------------------------------------------------

test('§8.3 groupCall：identity 生效 → v2 头 + X-Peer-Cert + X-Peer-Enc，签名能被证书公钥验过', async () => {
  await withTempDirAsync(async (stateDir) => {
    const { keypair } = setupIdentity(stateDir);
    const identity = loadGroupIdentity(stateDir, { fingerprint: FP });
    assert.equal(identity.ok, true, '夹具身份必须可用');
    const body = { kind: 'chat', text: 'hello' };
    const fetchImpl = stubFetch({ ok: true });

    const answer = await groupCall({
      baseUrl: 'http://127.0.0.1:7788',
      groupKey: GROUP_KEY,
      groupId: GROUP_ID,
      senderId: PEER_ID,
      method: 'POST',
      apiPath: '/v1/group/post',
      body,
      identity,
      fetchImpl,
    });
    assert.deepEqual(answer, { ok: true });

    const headers = fetchImpl.calls[0].init.headers;
    assert.equal(headers['X-Peer-Auth'], GROUP_AUTH_VALUE_V2);
    assert.equal(headers[GROUP_CERT_HEADER], encodeGroupCertHeader(identity.cert));
    assert.equal(headers[ENC_HEADER], ENC_VERSION, 'v2 请求必须同时带群信封头，否则服务端加密门禁 400');

    const plain = Buffer.from(JSON.stringify(body), 'utf8');
    const canonical = buildGroupCanonical({
      method: 'POST',
      path: '/v1/group/post',
      ts: Number(headers['X-Peer-Ts']),
      nonce: headers['X-Peer-Nonce'],
      groupId: GROUP_ID,
      senderPeerId: PEER_ID,
      rawBody: plain,
    });
    assert.equal(verifyMessage(keypair.publicKey, canonical, headers['X-Peer-Sign']), true,
      'P1 的 verifyMessage(cert.pubKey, canonical, sig) 必须验得过');

    const { bodyKey } = deriveGroupKeys(GROUP_KEY);
    assert.deepEqual(decryptGroupJson(bodyKey, fetchImpl.calls[0].init.body.toString('utf8')), body,
      '线上仍是群信封，签名覆盖的是明文 body');
  });
});

test('§8.3 groupCall：不传 identity / identity.ok !== true → 与改动前逐字段相同，且无 X-Peer-Cert 键', async () => {
  const body = { kind: 'chat', text: 'hi' };
  const wireArgs = {
    baseUrl: 'http://127.0.0.1:7788',
    groupKey: GROUP_KEY,
    groupId: GROUP_ID,
    senderId: PEER_ID,
    method: 'POST',
    apiPath: '/v1/group/post',
    body,
  };
  const cases = [
    ['缺省 identity', {}],
    ['identity.ok=false', { identity: { ok: false, code: IDENTITY_UNAVAILABLE } }],
    ['identity 无 ok 字段', { identity: { cert: null } }],
  ];
  for (const [label, extra] of cases) {
    const fetchImpl = stubFetch({ ok: true });
    await groupCall({ ...wireArgs, ...extra, fetchImpl });
    const headers = fetchImpl.calls[0].init.headers;

    assert.equal(headers['X-Peer-Auth'], GROUP_AUTH_VALUE, `${label}：必须仍是 v1`);
    assert.equal(Object.prototype.hasOwnProperty.call(headers, GROUP_CERT_HEADER), false,
      `${label}：v1 头里不许出现 X-Peer-Cert 键`);

    const { [ENC_HEADER]: enc, ...signed } = headers;
    assert.equal(enc, ENC_VERSION);
    const ts = Number(headers['X-Peer-Ts']);
    const nonce = headers['X-Peer-Nonce'];
    const expected = groupAuthHeaders({
      groupKey: GROUP_KEY,
      groupId: GROUP_ID,
      senderId: PEER_ID,
      method: 'POST',
      apiPath: '/v1/group/post',
      body,
      ts,
      nonce,
    });
    assert.deepEqual(signed, expected.headers, `${label}：v1 头与 groupAuthHeaders 逐字段相同`);
    assert.equal(
      buildGroupCanonical({
        method: 'POST',
        path: '/v1/group/post',
        ts,
        nonce,
        groupId: GROUP_ID,
        senderPeerId: PEER_ID,
        rawBody: Buffer.from(JSON.stringify(body), 'utf8'),
      }),
      expected.canonical,
      `${label}：canonical 逐字节相同`,
    );
  }
});

test('§8.3 包装器透传：10 个 groupCall 包装器给 identity 走 v2、不给仍走 v1', async () => {
  await withTempDirAsync(async (stateDir) => {
    setupIdentity(stateDir);
    const identity = loadGroupIdentity(stateDir, { fingerprint: FP });
    assert.equal(identity.ok, true, '夹具身份必须可用');

    const common = { baseUrl: 'http://127.0.0.1:7788', groupKey: GROUP_KEY, groupId: GROUP_ID, senderId: PEER_ID };
    const table = [
      ['probeGroupPeer', (extra) => probeGroupPeer({ ...common, ...extra })],
      ['pullGroupMessages', (extra) => pullGroupMessages({ ...common, ...extra })],
      ['replicateGroupMessages', (extra) => replicateGroupMessages({ ...common, messages: [], ...extra })],
      ['fetchGroupLeader', (extra) => fetchGroupLeader({ ...common, ...extra })],
      ['sendGroupHeartbeat', (extra) => sendGroupHeartbeat({ ...common, ...extra })],
      ['requestGroupVote', (extra) => requestGroupVote({ ...common, ...extra })],
      ['proposeGroupMessage', (extra) => proposeGroupMessage({ ...common, message: { seq: 1, kind: 'chat', text: 'x' }, ...extra })],
      ['commitGroupMessage', (extra) => commitGroupMessage({ ...common, seq: 1, ...extra })],
      ['fetchGroupLease', (extra) => fetchGroupLease({ ...common, ...extra })],
      ['postGroupWithGroupKey', (extra) => postGroupWithGroupKey({ ...common, kind: 'chat', text: 'hi', ...extra })],
    ];
    assert.equal(table.length, 10, '10 个包装器一个都不能少');

    for (const [name, call] of table) {
      const withId = stubFetch({ ok: true });
      await call({ identity, fetchImpl: withId });
      const v2Headers = withId.calls[0].init.headers;
      assert.equal(v2Headers['X-Peer-Auth'], GROUP_AUTH_VALUE_V2, `${name}：identity 没有透传（仍走 v1）`);
      assert.equal(v2Headers[GROUP_CERT_HEADER], encodeGroupCertHeader(identity.cert), `${name}：v2 必须带证书头`);
      assert.equal(v2Headers[ENC_HEADER], ENC_VERSION, `${name}：v2 必须带群信封头`);

      const noId = stubFetch({ ok: true });
      await call({ fetchImpl: noId });
      const v1Headers = noId.calls[0].init.headers;
      assert.equal(v1Headers['X-Peer-Auth'], GROUP_AUTH_VALUE, `${name}：不给 identity 必须仍是 v1`);
      assert.equal(Object.prototype.hasOwnProperty.call(v1Headers, GROUP_CERT_HEADER), false,
        `${name}：v1 头里不许出现 X-Peer-Cert 键`);
    }
  });
});

// ---------------------------------------------------------------------------
// 6. §8.2 注册的 per-peer 证明（pairProof）
// ---------------------------------------------------------------------------

const PAIR_SECRET = 'pair-secret-fixture-8f3a';
const registerArgs = (stateDir, keypair, fetchImpl, extra = {}) => ({
  stateDir,
  baseUrl: 'http://127.0.0.1:7788',
  groupKey: GROUP_KEY,
  groupId: GROUP_ID,
  peerId: PEER_ID,
  keypair,
  fetchImpl,
  ...extra,
});

test('§8.2 register：给了 pairSecret → 请求体带 pairProof{ts,nonce,sig}，用 protocol 的 canonical+sign 对拍通过', async () => {
  await withTempDirAsync(async (stateDir) => {
    const ca = makeCa();
    const keypair = createKeypair();
    const cert = makeCert(ca, { pubKey: keypair.publicKeyDer });
    const fetchImpl = stubFetch({ cert, hubCaPubKey: ca.pubKeyText, hubEpoch: 3 });

    const before = Date.now();
    const result = await registerGroupIdentity(registerArgs(stateDir, keypair, fetchImpl, { pairSecret: PAIR_SECRET }));
    const after = Date.now();
    assert.equal(result.ok, true);

    const { bodyKey } = deriveGroupKeys(GROUP_KEY);
    const sent = decryptGroupJson(bodyKey, fetchImpl.calls[0].init.body.toString('utf8'));

    assert.deepEqual(Object.keys(sent), ['peerId', 'pubKey', 'groupId', 'pairProof'], '三字段 + pairProof');
    assert.deepEqual(Object.keys(sent.pairProof), ['ts', 'nonce', 'sig']);
    assert.ok(Number.isFinite(sent.pairProof.ts) && sent.pairProof.ts >= before - 1000 && sent.pairProof.ts <= after + 1000);
    assert.match(sent.pairProof.nonce, /^[0-9a-f]{32}$/);

    // 正面断言：hub 侧用同一套五行 canonical + HMAC 必须算得出同一个 sig
    const bodyForProof = Buffer.from(
      JSON.stringify({ peerId: PEER_ID, pubKey: keypair.publicKeyDer, groupId: GROUP_ID }),
      'utf8',
    );
    const expected = perPeerSign(
      PAIR_SECRET,
      perPeerCanonical('POST', '/v1/group/identity/register', sent.pairProof.ts, sent.pairProof.nonce, bodyForProof),
    );
    assert.equal(sent.pairProof.sig, expected);
    assert.notEqual(
      perPeerSign('wrong-secret', perPeerCanonical('POST', '/v1/group/identity/register', sent.pairProof.ts, sent.pairProof.nonce, bodyForProof)),
      expected,
      '换一把 pairSecret 必须算不出同一个 sig',
    );
    // 证明不覆盖 pairProof 自身：把 pairProof 塞进 body 后的 canonical 会算出别的值
    const withProof = Buffer.from(JSON.stringify(sent), 'utf8');
    assert.notEqual(
      perPeerSign(PAIR_SECRET, perPeerCanonical('POST', '/v1/group/identity/register', sent.pairProof.ts, sent.pairProof.nonce, withProof)),
      expected,
    );

    assert.equal(fetchImpl.calls[0].init.headers['X-Peer-Auth'], GROUP_AUTH_VALUE, 'register 仍然走 v1 头');
  });
});

test('§8.2 register：没给 pairSecret → 请求体里连 pairProof 键都不存在', async () => {
  await withTempDirAsync(async (stateDir) => {
    const ca = makeCa();
    const keypair = createKeypair();
    const cert = makeCert(ca, { pubKey: keypair.publicKeyDer });
    const fetchImpl = stubFetch({ cert, hubCaPubKey: ca.pubKeyText, hubEpoch: 3 });

    await registerGroupIdentity(registerArgs(stateDir, keypair, fetchImpl));

    const { bodyKey } = deriveGroupKeys(GROUP_KEY);
    const sent = decryptGroupJson(bodyKey, fetchImpl.calls[0].init.body.toString('utf8'));
    assert.equal(Object.prototype.hasOwnProperty.call(sent, 'pairProof'), false, '键必须不存在，不是 undefined');
    assert.deepEqual(Object.keys(sent), ['peerId', 'pubKey', 'groupId']);
    assert.deepEqual(sent, { peerId: PEER_ID, pubKey: keypair.publicKeyDer, groupId: GROUP_ID });
  });
});
