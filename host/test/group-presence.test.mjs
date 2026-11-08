/**
 * 伙伴在线态 × 群级通道：群级鉴权成功后也要刷新 peers.json 的 lastSeen。
 *
 * 背景（真机实测）：成员的日常流量（心跳/拉取/复制/群派单）全走 X-Peer-Auth 群级通道，
 * 不过 per-peer 验签；lastSeen 只在 per-peer 鉴权成功时刷新，于是对端的「伙伴」列表
 * 停在最后一次 per-peer 交互上，几小时后把本机判成掉线 —— 而群视图同一时刻是 online=true。
 *
 * 覆盖：
 *   1) v1（groupKey HMAC）成功 → lastSeen 推到本次请求的 nowMs（精确到毫秒）；
 *   2) v2（证书 + ed25519）成功 → 同上；
 *   3) 坏签名 401 → lastSeen 不变（坏请求不刷新在线态）；
 *   4) 未配对的群成员 → 请求照既有语义通过，但 peers.json 里不会多出该条目；
 *   5) 自己（store.instanceId）→ peers.json 不会多出本机条目。
 *
 * 时钟用注入的 config.now（startServer 的 now 覆盖），所以断言的是「这一次请求算出来的
 * 那一毫秒」，不是「大概刚刚」。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {
  GROUP_ID_HEADER,
  decryptGroupJson,
  deriveGroupKeys,
  groupAuthHeaders,
  groupAuthHeadersV2,
  signGroupCanonical,
} from '../../lib/group-client.mjs';
import { DEFAULT_ROTATE_AFTER_MS, createKeypair, signCertificate } from '../../lib/group-identity.mjs';
import { loadOrCreateHubCa } from '../../lib/group-ca.mjs';
import { makeTempStateDir, peerFixture, readJson, seedPeers, startServer } from './helpers.mjs';

const PROBE = '/v1/group/probe';
const PEERS_FILE = 'peers.json';

// 两个已配对成员（各自单独一个用例，互不干扰）+ 一个只入群、未配对的成员
const MEMBER_V1 = peerFixture('peer-presence-v1');
const MEMBER_V2 = peerFixture('peer-presence-v2');
const UNPAIRED = peerFixture('peer-presence-unpaired');

const iso = (ms) => new Date(ms).toISOString();

/** 起一个开了群的 hub；时钟由用例注入，日志静音（本用例不关心日志行） */
async function startHub(t, peerIds = [MEMBER_V1, MEMBER_V2]) {
  const clock = { now: Date.now() };
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, peerIds);
  const started = await startServer(t, {
    stateDir,
    now: () => clock.now,
    logger: () => {},
    allowRemotePrompts: true,
    group: { enabled: true, name: 'default', autoJoin: false, retentionDays: 7, quorum: 'none' },
  });
  const { server } = started;
  const groupKey = server.group.state({ includeKey: true }).groupKey;
  const groupId = server.group.state().groupId;
  const peers = () => readJson(path.join(stateDir, PEERS_FILE)).peers;
  return { ...started, clock, groupKey, groupId, peers, instanceId: server.store.instanceId };
}

/**
 * 发一个群级 GET（v1 或 v2 头由是否传 cert 决定）。签名/信封都用客户端同一套原语，
 * 只有 signature 可覆盖 —— 「坏签名」负例必须只坏在签名上。
 */
async function sendGroup(baseUrl, { groupKey, groupId, senderId, cert, privateKey, ts, signature }) {
  const { bodyKey } = deriveGroupKeys(groupKey);
  const built = cert
    ? groupAuthHeadersV2({ cert, privateKey, groupId, senderId, method: 'GET', apiPath: PROBE, ts, signature })
    : groupAuthHeaders({ groupKey, groupId, senderId, method: 'GET', apiPath: PROBE, ts, signature });
  const res = await fetch(new URL(PROBE, baseUrl), {
    method: 'GET',
    headers: { ...built.headers, 'x-peer-enc': 'v1' },
  });
  const text = await res.text();
  let json = null;
  try {
    const parsed = JSON.parse(text);
    json = parsed && parsed.enc === 'v1' && typeof parsed.data === 'string'
      ? decryptGroupJson(bodyKey, parsed.data)
      : parsed;
  } catch {
    /* 非 JSON / 解不开（坏签名时线上是密文）留给调用方看 status */
  }
  return { status: res.status, json, text };
}

/** hub CA 现场签一张成员证书（不落台账 → 服务端跳过台账检查，只验证书链与成员表） */
function craftCert(hub, peerId) {
  const ca = loadOrCreateHubCa(hub.stateDir);
  assert.equal(ca.ok, true);
  const keypair = createKeypair();
  const cert = signCertificate(ca.privateKey, {
    peerId,
    pubKey: keypair.publicKeyDer,
    groupId: hub.groupId,
    issuedAt: hub.clock.now,
    expiresAt: hub.clock.now + DEFAULT_ROTATE_AFTER_MS,
    hubEpoch: 0,
  });
  return { cert, keypair };
}

test('AC1：v1 群级请求成功后 lastSeen 推到该请求的 nowMs（前后各比一次）', async (t) => {
  const hub = await startHub(t, [MEMBER_V1]);
  hub.server.group.addMember(MEMBER_V1.peerId, MEMBER_V1.name);

  assert.equal(hub.peers()[MEMBER_V1.peerId].lastSeen, null, '前置：种子 peers.json 里没有 lastSeen');

  const first = hub.clock.now;
  const r1 = await sendGroup(hub.baseUrl, {
    groupKey: hub.groupKey, groupId: hub.groupId, senderId: MEMBER_V1.peerId, ts: first,
  });
  assert.equal(r1.status, 200, r1.text);
  assert.equal(hub.peers()[MEMBER_V1.peerId].lastSeen, iso(first), 'v1 成功 → lastSeen = 本次 nowMs');

  // 第二次：跳过 30s 落盘节流，验证是「每次请求都推进」，不是「只写一次」
  hub.clock.now = first + 60_000;
  const second = hub.clock.now;
  const r2 = await sendGroup(hub.baseUrl, {
    groupKey: hub.groupKey, groupId: hub.groupId, senderId: MEMBER_V1.peerId, ts: second,
  });
  assert.equal(r2.status, 200, r2.text);
  assert.equal(hub.peers()[MEMBER_V1.peerId].lastSeen, iso(second));
});

test('AC2：v2 群级请求（证书 + ed25519）同样更新 lastSeen', async (t) => {
  const hub = await startHub(t, [MEMBER_V2]);
  hub.server.group.addMember(MEMBER_V2.peerId, MEMBER_V2.name);
  const { cert, keypair } = craftCert(hub, MEMBER_V2.peerId);

  assert.equal(hub.peers()[MEMBER_V2.peerId].lastSeen, null);

  const first = hub.clock.now;
  const r1 = await sendGroup(hub.baseUrl, {
    groupKey: hub.groupKey,
    groupId: hub.groupId,
    senderId: MEMBER_V2.peerId,
    cert,
    privateKey: keypair.privateKey,
    ts: first,
  });
  assert.equal(r1.status, 200, r1.text);
  assert.equal(hub.peers()[MEMBER_V2.peerId].lastSeen, iso(first));

  hub.clock.now = first + 60_000;
  const second = hub.clock.now;
  const r2 = await sendGroup(hub.baseUrl, {
    groupKey: hub.groupKey,
    groupId: hub.groupId,
    senderId: MEMBER_V2.peerId,
    cert,
    privateKey: keypair.privateKey,
    ts: second,
  });
  assert.equal(r2.status, 200, r2.text);
  assert.equal(hub.peers()[MEMBER_V2.peerId].lastSeen, iso(second));
});

test('AC3：坏签名 401 → lastSeen 不变（坏请求不刷新在线态）', async (t) => {
  const hub = await startHub(t, [MEMBER_V1]);
  hub.server.group.addMember(MEMBER_V1.peerId, MEMBER_V1.name);

  const good = hub.clock.now;
  const ok = await sendGroup(hub.baseUrl, {
    groupKey: hub.groupKey, groupId: hub.groupId, senderId: MEMBER_V1.peerId, ts: good,
  });
  assert.equal(ok.status, 200, ok.text);
  assert.equal(hub.peers()[MEMBER_V1.peerId].lastSeen, iso(good));

  // 只有签名坏：其余头全部合法、时钟也在窗口内
  hub.clock.now = good + 60_000;
  const bad = await sendGroup(hub.baseUrl, {
    groupKey: hub.groupKey,
    groupId: hub.groupId,
    senderId: MEMBER_V1.peerId,
    ts: hub.clock.now,
    signature: signGroupCanonical({ signKey: Buffer.alloc(32, 7), canonical: 'GROUP\nx' }),
  });
  assert.equal(bad.status, 401, bad.text);
  assert.equal(bad.json?.error, 'bad-signature');
  assert.equal(hub.peers()[MEMBER_V1.peerId].lastSeen, iso(good), '401 之后 lastSeen 必须停在原值');
});

test('AC4：未配对的群成员按既有语义通过，但 peers.json 不会新增该条目', async (t) => {
  const hub = await startHub(t, [MEMBER_V1]);
  hub.server.group.addMember(MEMBER_V1.peerId, MEMBER_V1.name);
  // 只入群、没配对：成员表里有它，peers.json 里没有
  hub.server.group.addMember(UNPAIRED.peerId, UNPAIRED.name);
  assert.equal(hub.peers()[UNPAIRED.peerId], undefined);

  const res = await sendGroup(hub.baseUrl, {
    groupKey: hub.groupKey, groupId: hub.groupId, senderId: UNPAIRED.peerId, ts: hub.clock.now,
  });
  assert.equal(res.status, 200, res.text);
  const after = hub.peers();
  assert.equal(after[UNPAIRED.peerId], undefined, 'touchPeer 只更新已配对条目，不能凭空造 peer');
  assert.deepEqual(Object.keys(after), [MEMBER_V1.peerId]);
});

test('AC5：自己发起的群级请求不会把 store.instanceId 写进 peers.json', async (t) => {
  const hub = await startHub(t, [MEMBER_V1]);
  hub.server.group.addMember(MEMBER_V1.peerId, MEMBER_V1.name);
  assert.equal(typeof hub.instanceId, 'string');

  const res = await sendGroup(hub.baseUrl, {
    groupKey: hub.groupKey, groupId: hub.groupId, senderId: hub.instanceId, ts: hub.clock.now,
  });
  assert.equal(res.status, 200, res.text);
  const after = hub.peers();
  assert.equal(after[hub.instanceId], undefined);
  assert.deepEqual(Object.keys(after), [MEMBER_V1.peerId]);
});

test('AC1+：只更新签名身份对应的条目，不波及别的 peer', async (t) => {
  const hub = await startHub(t, [MEMBER_V1, MEMBER_V2]);
  hub.server.group.addMember(MEMBER_V1.peerId, MEMBER_V1.name);
  hub.server.group.addMember(MEMBER_V2.peerId, MEMBER_V2.name);

  const nowMs = hub.clock.now;
  const res = await sendGroup(hub.baseUrl, {
    groupKey: hub.groupKey, groupId: hub.groupId, senderId: MEMBER_V1.peerId, ts: nowMs,
  });
  assert.equal(res.status, 200, res.text);
  const after = hub.peers();
  assert.equal(after[MEMBER_V1.peerId].lastSeen, iso(nowMs));
  assert.equal(after[MEMBER_V2.peerId].lastSeen, null, '没发请求的 peer 不该被刷新');
});

test('AC4+：同机 CLI 刚解绑的 peer 不会被群级请求写回 peers.json（不复活）', async (t) => {
  const hub = await startHub(t, [MEMBER_V1, MEMBER_V2]);
  hub.server.group.addMember(MEMBER_V1.peerId, MEMBER_V1.name);
  // 模拟另一个进程（CLI unpair）在服务运行期间改了 peers.json：
  // 进程内存里还有 MEMBER_V1，文件里已经没有了。
  const file = path.join(hub.stateDir, PEERS_FILE);
  const kept = JSON.parse(fs.readFileSync(file, 'utf8'));
  delete kept.peers[MEMBER_V1.peerId];
  fs.writeFileSync(file, JSON.stringify(kept));

  const res = await sendGroup(hub.baseUrl, {
    groupKey: hub.groupKey, groupId: hub.groupId, senderId: MEMBER_V1.peerId, ts: hub.clock.now,
  });
  assert.equal(res.status, 200, res.text);
  assert.deepEqual(Object.keys(hub.peers()), [MEMBER_V2.peerId], '解绑过的 peer 不能被 touchPeer 写回文件');
});

// GROUP_ID_HEADER 仅用于说明头部口径与客户端一致（不参与签名之外的判断）
test('口径：群级请求带的是 X-Peer-Auth 群级头，不是 per-peer 签名', async (t) => {
  const hub = await startHub(t, [MEMBER_V1]);
  hub.server.group.addMember(MEMBER_V1.peerId, MEMBER_V1.name);
  const { headers } = groupAuthHeaders({
    groupKey: hub.groupKey, groupId: hub.groupId, senderId: MEMBER_V1.peerId, apiPath: PROBE,
  });
  assert.equal(headers['X-Peer-Auth'], 'group');
  assert.equal(headers[GROUP_ID_HEADER], String(hub.groupId));
  // 这条通道历史上从不触碰 lastSeen，正是掉线的成因；本用例存在的意义是记录口径
});
