/**
 * v0.6.0 S1 · 群级鉴权（契约 group-s1s2-contract.md §S1）。
 *
 * 覆盖：群级签名成功/失败、路径白名单（401 group-auth-scope）、非成员 401、
 *      nonce 重放、时钟偏移、groupId 不一致、群关闭时 404、成员服务器也提供四个端点、
 *      地址探测（排除回环/虚拟网卡，192.168 优先）与 advertiseBaseUrl 优先级。
 *
 * 群级请求走 lib/group-client.mjs 的同一套原语（签名覆盖明文，线上走 HKDF 信封），
 * 所以这里的正例也顺带验证了客户端与 host 的 canonical 一致性。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { listenOnRandomPort } from '../../test-support/ports.mjs';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import {
  GROUP_AUTH_HEADER,
  GROUP_AUTH_PATHS,
  GROUP_AUTH_VALUE,
  GROUP_ID_HEADER,
  GROUP_BASE_HEADER,
  decryptGroupJson,
  deriveGroupKeys,
  encryptGroupBody,
  groupAuthHeaders,
} from '../../lib/group-client.mjs';
import { createPeerServer, pickPrivateIpv4 } from '../server.mjs';
import { makeTempStateDir, peerFixture, request, seedPeers, startServer, writeJson0600 } from './helpers.mjs';

const MEMBER = peerFixture('peer-group-auth-1');
const OUTSIDER = peerFixture('peer-group-auth-2');

/** 起一个开了群的 hub；peers.json 里预置两个已配对、但只有 MEMBER 入群 */
async function startHub(t, overrides = {}) {
  const stateDir = overrides.stateDir ?? makeTempStateDir();
  seedPeers(stateDir, [MEMBER, OUTSIDER]);
  // S3：与 group.test.mjs 同理 —— 假 peerId 成员无法 ack，固定 quorum:none。
  const group = { enabled: true, name: 'default', autoJoin: false, retentionDays: 7, quorum: 'none' };
  const started = await startServer(t, {
    stateDir,
    allowRemotePrompts: true,
    ...overrides,
    group: { ...group, ...(overrides.group ?? {}) },
  });
  return started;
}

const groupKeyOf = (hub) => hub.server.group.state({ includeKey: true }).groupKey;
const groupIdOf = (hub) => hub.server.group.state().groupId;

/**
 * 发一个群级签名请求。ts/nonce/groupId/signature/extraHeaders 都可覆盖（负例用）。
 * 返回值里的 json 已按群信封解密。
 */
async function groupRequest(baseUrl, options = {}) {
  const {
    groupKey,
    groupId,
    senderId,
    method = 'GET',
    path: apiPath,
    body,
    ts,
    nonce,
    signature,
    groupIdHeader,
    selfBaseUrl = '',
    extraHeaders = {},
  } = options;
  const { headers, plain } = groupAuthHeaders({
    groupKey,
    groupId,
    senderId,
    method,
    apiPath,
    body,
    selfBaseUrl,
    ts,
    nonce,
    signature,
  });
  if (groupIdHeader !== undefined) headers[GROUP_ID_HEADER] = groupIdHeader;
  const { bodyKey } = deriveGroupKeys(groupKey);
  const wire = plain.length && method !== 'GET' && method !== 'HEAD'
    ? Buffer.from(encryptGroupBody(bodyKey, plain), 'utf8')
    : Buffer.alloc(0);
  const res = await fetch(new URL(apiPath, baseUrl), {
    method,
    headers: { ...headers, ...extraHeaders, 'x-peer-enc': 'v1' },
    body: wire.length ? wire : undefined,
  });
  const text = await res.text();
  let json = null;
  try {
    const parsed = JSON.parse(text);
    json = parsed && parsed.enc === 'v1' && typeof parsed.data === 'string'
      ? decryptGroupJson(bodyKey, parsed.data)
      : parsed;
  } catch {
    /* 非 JSON / 解密失败留给 text */
  }
  return { status: res.status, json, text, headers };
}

// ---------------------------------------------------------------------------
// 正例
// ---------------------------------------------------------------------------

test('S1 群级签名成功：GET /v1/group/probe 返回契约字段', async (t) => {
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER.peerId, MEMBER.name);
  const groupKey = groupKeyOf(hub);
  const groupId = groupIdOf(hub);

  const res = await groupRequest(hub.baseUrl, {
    groupKey,
    groupId,
    senderId: MEMBER.peerId,
    path: '/v1/group/probe',
  });
  assert.equal(res.status, 200, res.text);
  const body = res.json;
  assert.equal(body.ok, true);
  assert.equal(body.peerId, hub.server.store.instanceId);
  assert.equal(body.groupId, groupId);
  assert.equal(body.epoch, 1);
  assert.equal(body.leaderPeerId, hub.server.store.instanceId, 'hub 自己就是 leader');
  assert.equal(body.lastSeq, 0);
  assert.equal(typeof body.advertiseBaseUrl, 'string');
  assert.equal(typeof body.name, 'string');

  // leader / pull 同样可用
  const leader = await groupRequest(hub.baseUrl, {
    groupKey, groupId, senderId: MEMBER.peerId, path: '/v1/group/leader',
  });
  assert.equal(leader.status, 200, leader.text);
  assert.equal(leader.json.leaderPeerId, hub.server.store.instanceId);

  const pull = await groupRequest(hub.baseUrl, {
    groupKey, groupId, senderId: MEMBER.peerId, path: '/v1/group/pull?sinceSeq=0&limit=10',
  });
  assert.equal(pull.status, 200, pull.text);
  assert.deepEqual(pull.json.messages, []);
  assert.ok(Array.isArray(pull.json.memberIds));
  assert.ok(pull.json.memberIds.includes(MEMBER.peerId));
});

test('S1 白名单：只有群级白名单里的路径认群级头，其它一律 401 group-auth-scope', async (t) => {
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER.peerId, MEMBER.name);
  const groupKey = groupKeyOf(hub);
  const groupId = groupIdOf(hub);

  // v0.8.0 起白名单十一条：S3 的八条 + 入群转交的两条（§4.2/§5.1）+ post 的群级通道
  // （按名入群的成员没有 hub 的 per-peer 密钥，只认 per-peer 就等于只能读不能发言）
  const allowed = GROUP_AUTH_PATHS;
  assert.deepEqual([...allowed], [
    '/v1/group/probe',
    '/v1/group/replicate',
    '/v1/group/pull',
    '/v1/group/leader',
    '/v1/group/election',
    '/v1/group/propose',
    '/v1/group/commit',
    '/v1/group/lease',
    '/v1/group/apply-intake',
    '/v1/group/apply-query',
    '/v1/group/post',
  ]);

  const forbidden = [
    ['GET', '/v1/group/state'],
    ['GET', '/v1/group/history'],
    ['GET', '/v1/group/events'],
    ['POST', '/v1/ask'],
    ['GET', '/v1/answer?sessionId=x'],
    ['GET', '/v1/peers'],
    ['POST', '/v1/unpair'],
    ['GET', '/v1/health'],
    ['GET', '/v1/group/probe2'],
  ];
  for (const [method, apiPath] of forbidden) {
    const res = await groupRequest(hub.baseUrl, {
      groupKey,
      groupId,
      senderId: MEMBER.peerId,
      method,
      path: apiPath,
      body: method === 'POST' ? { requestId: 'r1', prompt: 'x' } : undefined,
    });
    assert.equal(res.status, 401, method + ' ' + apiPath);
    assert.equal(res.json?.error, 'group-auth-scope', method + ' ' + apiPath);
  }
  // 群密钥没有把 /v1/ask 变成可用：会话数不变
  assert.equal(hub.server.sessions.size, 0);
});

test('S1 接受条件：非成员 401 / 坏签名 401 / groupId 不符 401 / 时钟偏移 401 / nonce 重放 401', async (t) => {
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER.peerId, MEMBER.name);
  const groupKey = groupKeyOf(hub);
  const groupId = groupIdOf(hub);
  const probe = (extra = {}) => groupRequest(hub.baseUrl, {
    groupKey, groupId, senderId: MEMBER.peerId, path: '/v1/group/probe', ...extra,
  });

  // 已配对但不在成员表
  const outsider = await groupRequest(hub.baseUrl, {
    groupKey, groupId, senderId: OUTSIDER.peerId, path: '/v1/group/probe',
  });
  assert.equal(outsider.status, 401);
  assert.equal(outsider.json.error, 'not-a-member');

  // 签名不对
  const badSign = await probe({ signature: 'A'.repeat(43) });
  assert.equal(badSign.status, 401);
  assert.equal(badSign.json.error, 'bad-signature');

  // groupId 与对端不一致（header 与 canonical 一致，但都不是本群的 id）
  const otherGroup = '00000000-0000-4000-8000-000000000000';
  const mismatch = await groupRequest(hub.baseUrl, {
    groupKey, groupId: otherGroup, senderId: MEMBER.peerId, path: '/v1/group/probe',
  });
  assert.equal(mismatch.status, 401);
  assert.equal(mismatch.json.error, 'group-mismatch');

  // 时钟偏移 ±60s
  const skewed = await probe({ ts: Date.now() - 120_000 });
  assert.equal(skewed.status, 401);
  assert.equal(skewed.json.error, 'clock-skew');

  // nonce 重放：同一 nonce 第二次被拒
  const nonce = randomBytes(16).toString('hex');
  const first = await probe({ nonce });
  assert.equal(first.status, 200, first.text);
  const replay = await probe({ nonce, ts: Date.now() });
  assert.equal(replay.status, 401);
  assert.equal(replay.json.error, 'replay');
});

test('S1 群关闭时群级端点 404（不暴露半成品能力）', async (t) => {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [MEMBER]);
  const { baseUrl } = await startServer(t, { stateDir, group: { enabled: false } });
  const res = await groupRequest(baseUrl, {
    groupKey: randomBytes(32).toString('base64url'),
    groupId: 'any',
    senderId: MEMBER.peerId,
    path: '/v1/group/probe',
  });
  assert.equal(res.status, 404);
  assert.equal(res.json.error, 'not-found');
});

test('S1 per-peer 签名仍可访问四个端点（CLI 排障路径），非成员 403 not-a-member', async (t) => {
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER.peerId, MEMBER.name);

  const asMember = await request(hub.baseUrl, {
    path: '/v1/group/probe',
    peerId: MEMBER.peerId,
    secret: MEMBER.inboundSecret,
  });
  assert.equal(asMember.status, 200, asMember.text);
  assert.equal(asMember.json.groupId, groupIdOf(hub));

  const asOutsider = await request(hub.baseUrl, {
    path: '/v1/group/probe',
    peerId: OUTSIDER.peerId,
    secret: OUTSIDER.inboundSecret,
  });
  assert.equal(asOutsider.status, 403);
  assert.equal(asOutsider.json.error, 'not-a-member');
});

// ---------------------------------------------------------------------------
// 成员侧端点（不经过 hub 也能互访）
// ---------------------------------------------------------------------------

test('S1 成员服务器自己也提供 probe/pull/leader，数据来自 group-replica.json', async (t) => {
  const groupKey = randomBytes(32).toString('base64url');
  const groupId = '11111111-2222-4333-8444-555555555555';
  const HUB = peerFixture('peer-group-auth-hub');
  const PEER2 = peerFixture('peer-group-auth-peer2');
  const stateDir = makeTempStateDir();
  writeJson0600(path.join(stateDir, 'state.json'), {
    instanceId: PEER2.peerId,
    name: PEER2.name,
    createdAt: new Date().toISOString(),
  });
  seedPeers(stateDir, [HUB]);
  writeJson0600(path.join(stateDir, 'group-key.json'), {
    groupId,
    epoch: 2,
    leaderPeerId: HUB.peerId,
    key: groupKey,
    name: PEER2.name,
    members: { [HUB.peerId]: { name: HUB.name }, [PEER2.peerId]: { name: PEER2.name } },
  });
  writeJson0600(path.join(stateDir, 'group-replica.json'), {
    groupId,
    epoch: 2,
    leaderPeerId: HUB.peerId,
    lastSeq: 2,
    messages: [
      { seq: 1, ts: Date.now(), from: { peerId: 'a', name: 'a' }, kind: 'chat', text: 'one', meta: {} },
      { seq: 2, ts: Date.now(), from: { peerId: 'a', name: 'a' }, kind: 'chat', text: 'two', meta: {} },
    ],
  });
  const server = createPeerServer({
    listenHost: '127.0.0.1',
    stateDir,
    requireEncryption: false,
    group: { enabled: true, hub: 'hub' },
  });
  const info = await listenOnRandomPort(server);
  t.after(async () => {
    await server.close();
    fs.rmSync(stateDir, { recursive: true, force: true });
  });

  const probe = await groupRequest(info.url, {
    groupKey, groupId, senderId: HUB.peerId, path: '/v1/group/probe',
  });
  assert.equal(probe.status, 200, probe.text);
  assert.equal(probe.json.peerId, PEER2.peerId);
  assert.equal(probe.json.epoch, 2);
  assert.equal(probe.json.leaderPeerId, HUB.peerId);
  assert.equal(probe.json.lastSeq, 2);

  const pull = await groupRequest(info.url, {
    groupKey, groupId, senderId: HUB.peerId, path: '/v1/group/pull?sinceSeq=1&limit=200',
  });
  assert.equal(pull.status, 200, pull.text);
  assert.equal(pull.json.messages.length, 1);
  assert.equal(pull.json.messages[0].text, 'two');

  // 非成员（签名有效但不在成员表）一样被拒
  const outsider = await groupRequest(info.url, {
    groupKey, groupId, senderId: 'not-in-group', path: '/v1/group/probe',
  });
  assert.equal(outsider.status, 401);
  assert.equal(outsider.json.error, 'not-a-member');
});

// ---------------------------------------------------------------------------
// 成员可达地址
// ---------------------------------------------------------------------------

test('S1 地址探测：排除回环/虚拟网卡，192.168 优先，无私有地址返回 null', () => {
  const sample = {
    lo: [{ address: '127.0.0.1', family: 'IPv4', internal: true }],
    'vEthernet (WSL)': [{ address: '172.20.0.1', family: 'IPv4', internal: false }],
    docker0: [{ address: '172.17.0.1', family: 'IPv4', internal: false }],
    'VirtualBox Host-Only Network': [{ address: '192.168.56.1', family: 'IPv4', internal: false }],
    eth0: [{ address: '10.1.2.3', family: 'IPv4', internal: false }],
    wlan0: [{ address: '192.168.1.20', family: 'IPv4', internal: false }],
    'Tailscale': [{ address: '100.64.0.1', family: 'IPv4', internal: false }],
  };
  assert.equal(pickPrivateIpv4(sample), '192.168.1.20');
  // 只有虚拟网卡挂着的私网地址时：一个都不选
  assert.equal(pickPrivateIpv4({
    docker0: [{ address: '172.17.0.1', family: 'IPv4', internal: false }],
    lo: [{ address: '127.0.0.1', family: 'IPv4', internal: true }],
  }), null);
  // 公网地址不算
  assert.equal(pickPrivateIpv4({ eth0: [{ address: '8.8.8.8', family: 'IPv4', internal: false }] }), null);
  // 真实网卡列表：要么拿到私有 IPv4，要么 null（CI/容器里允许没有）
  const detected = pickPrivateIpv4();
  assert.ok(detected === null || /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(detected));
});

test('S1 advertiseBaseUrl 配置优先：写进 probe 与群状态 members[].baseUrl', async (t) => {
  const hub = await startHub(t, { group: { enabled: true, advertiseBaseUrl: 'http://10.1.2.3:7788' } });
  hub.server.group.addMember(MEMBER.peerId, MEMBER.name);
  const groupKey = groupKeyOf(hub);
  const groupId = groupIdOf(hub);

  const probe = await groupRequest(hub.baseUrl, {
    groupKey, groupId, senderId: MEMBER.peerId, path: '/v1/group/probe',
  });
  assert.equal(probe.status, 200, probe.text);
  assert.equal(probe.json.advertiseBaseUrl, 'http://10.1.2.3:7788');

  const state = hub.server.group.state();
  assert.equal(state.members[hub.server.store.instanceId].baseUrl, 'http://10.1.2.3:7788');
  const view = hub.server.group.members().find((m) => m.peerId === hub.server.store.instanceId);
  assert.equal(view.baseUrl, 'http://10.1.2.3:7788');
});

test('S1 未配置 advertiseBaseUrl：探测私有 IPv4 + 实际端口；成员自报地址写进群状态', async (t) => {
  const hub = await startHub(t);
  hub.server.group.addMember(MEMBER.peerId, MEMBER.name);
  const groupKey = groupKeyOf(hub);
  const groupId = groupIdOf(hub);

  const probe = await groupRequest(hub.baseUrl, {
    groupKey, groupId, senderId: MEMBER.peerId, path: '/v1/group/probe',
  });
  assert.equal(probe.status, 200, probe.text);
  const advertised = probe.json.advertiseBaseUrl;
  assert.equal(typeof advertised, 'string');
  if (advertised !== '') {
    assert.match(advertised, /^http:\/\/\d+\.\d+\.\d+\.\d+:\d+$/);
  }

  // 成员在群级请求里带 X-Peer-Base：hub 记下「我看到的你的地址」
  const announced = 'http://192.168.1.21:7788';
  const second = await groupRequest(hub.baseUrl, {
    groupKey, groupId, senderId: MEMBER.peerId,
    path: '/v1/group/probe',
    selfBaseUrl: announced,
    extraHeaders: { [GROUP_BASE_HEADER]: announced },
  });
  assert.equal(second.status, 200, second.text);
  await sleep(10);
  assert.equal(hub.server.group.state().members[MEMBER.peerId].baseUrl, announced);
  const memberView = hub.server.group.members().find((m) => m.peerId === MEMBER.peerId);
  assert.equal(memberView.baseUrl, announced);
});

test('S1 群级鉴权头常量与契约一致（头部名字写死在契约里）', () => {
  assert.equal(GROUP_AUTH_HEADER, 'X-Peer-Auth');
  assert.equal(GROUP_AUTH_VALUE, 'group');
  assert.equal(GROUP_ID_HEADER, 'X-Peer-Group');
});
