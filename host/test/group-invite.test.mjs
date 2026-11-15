// dsh-lan-peers · 0.12.5-alpha（slice A）入群邀请：推送式授权的端到端用例。
//
// 现场还原的是**真洞**：hub 把 peer 加进 roster，peer 却没有群密钥 —— 它没有 config.group.hub，
// 所以按名申请那条路对它不存在。这里造的就是这台机器（group.enabled=false、无 group-key.json）。
//
// 判据全部落在盘上/HTTP 上，不看实现内部：
//   I1 推送到达并落盘（面板那份不含 key）   I2 接受 → group-key.json + 群上下文变活
//   I3 拒绝 → 不落盘                          I4 半份授权 → 409 且不写 key
//   I5 已入群 → already-member 且一个字节都不发 I6 不可达 → unreachable 且可重试
//   I7 成员节点打 hub-only 路由 → 403          I8 重复邀请 → 一条邀请 / 一条账本
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createPeerServer } from '../server.mjs';
import { createAdmin } from '../../lib/admin.mjs';
import { readGroupKeyFile } from '../../lib/group-client.mjs';
import net from 'node:net';
import { isFetchBlockedPort } from '../../test-support/ports.mjs';
import { makeTempStateDir, request, writeJson0600 } from './helpers.mjs';
import { waitFor } from './group-cluster.mjs';

const HUB = { peerId: 'peer-hub0001', name: 'hub-box' };
const PEER = { peerId: 'peer-node001', name: 'node-one' };
const GROUP_NAME = '家里';
// 声明里对不上的东西：先算出来，断言里直接用（避免「写完再读」自证）
const secretOf = (peerId) => 'sec-' + peerId;

function writePeers(stateDir, self, other, otherUrl) {
  writeJson0600(path.join(stateDir, 'peers.json'), {
    peers: {
      [other.peerId]: {
        name: other.name,
        baseUrl: otherUrl,
        secret: secretOf(self.peerId),
        inboundSecret: secretOf(other.peerId),
        addedAt: new Date().toISOString(),
        lastSeen: null,
      },
    },
  });
}

function seedIdentity(dir, peer) {
  writeJson0600(path.join(dir, 'state.json'), {
    instanceId: peer.peerId,
    name: peer.name,
    createdAt: new Date().toISOString(),
  });
}

/** 静音角色定时器：这两条用例关心的是邀请的落盘与门禁，不是选举 */
const quietElection = {
  heartbeatMs: 60_000,
  commitTimeoutMs: 60_000,
  tickMs: 60_000,
  jitterMs: 0,
  peerTimeoutMs: 250,
};

/**
 * 造一对节点：hub（group 启用、roster 里有 PEER）与 peer（**没有群**：enabled=false 且无 key）。
 * 这就是「roster 里有人、对方永远 group-disabled」的那台机器。
 */
async function startPair(t) {
  const peerLogs = [];
  const hubDir = makeTempStateDir('dsh-lan-peers-invite-hub-');
  const peerDir = makeTempStateDir('dsh-lan-peers-invite-peer-');
  t.after(() => fs.rmSync(hubDir, { recursive: true, force: true }));
  t.after(() => fs.rmSync(peerDir, { recursive: true, force: true }));
  seedIdentity(hubDir, HUB);
  seedIdentity(peerDir, PEER);
  writePeers(hubDir, HUB, PEER, 'http://127.0.0.1:1');
  writePeers(peerDir, PEER, HUB, 'http://127.0.0.1:1');

  // 端口必须**先**确定：peers.json 是启动时读进内存的，事后改文件不会改 store.getPeer()，
  // 而 hub 推邀请时用的正是 peers.json 里的那条地址（事后改会推到占位地址上 → 假 unreachable）。
  const hubPort = await pickFreePort();
  const peerPort = await pickFreePort();
  const hubUrl = 'http://127.0.0.1:' + hubPort;
  const peerUrl = 'http://127.0.0.1:' + peerPort;
  writePeers(hubDir, HUB, PEER, peerUrl);
  writePeers(peerDir, PEER, HUB, hubUrl);

  const hubServer = createPeerServer({
    listenHost: '127.0.0.1',
    listenPort: hubPort,
    stateDir: hubDir,
    name: HUB.name,
    logger: () => {},
    group: { enabled: true, name: GROUP_NAME, autoJoin: false, heartbeatMs: 60_000 },
    groupReplica: { pullIntervalMs: 600_000, retryMs: 600_000 },
    groupElection: quietElection,
  });
  const peerServer = createPeerServer({
    listenHost: '127.0.0.1',
    listenPort: peerPort,
    stateDir: peerDir,
    name: PEER.name,
    // slice B：ack 是 best-effort，成功/失败都只留一行日志 —— 所以把这两行收起来给断言用
    logger: (line) => { peerLogs.push(String(line)); },
    // 关键：没有 group.hub，也没有 group-key.json —— role 是 off
    group: { enabled: false },
    groupReplica: { pullIntervalMs: 600_000, retryMs: 600_000 },
    groupElection: quietElection,
  });
  t.after(async () => { await hubServer.close(); });
  t.after(async () => { await peerServer.close(); });
  // 自报地址必须在 listen **之前**写进配置（否则前几轮 pull 会报探测出来的私网 IP）
  hubServer.config.group.advertiseBaseUrl = hubUrl;
  peerServer.config.group.advertiseBaseUrl = peerUrl;
  await hubServer.listen(hubPort, '127.0.0.1');
  await peerServer.listen(peerPort, '127.0.0.1');

  // roster 里加上这个成员（live 的「面板加了人」那一步）
  hubServer.group.addMember(PEER.peerId, PEER.name);
  hubServer.group.state().members[PEER.peerId].baseUrl = peerUrl;

  const hubAdmin = createAdmin({
    server: hubServer,
    nameOf: () => HUB.name,
    rename: async () => true,
    pairing: { mode: 'auto' },
  });
  const peerAdmin = createAdmin({
    server: peerServer,
    nameOf: () => PEER.name,
    rename: async () => true,
    pairing: { mode: 'auto' },
  });
  return {
    hub: { ...HUB, server: hubServer, dir: hubDir, url: hubUrl, admin: hubAdmin },
    peer: { ...PEER, server: peerServer, dir: peerDir, url: peerUrl, admin: peerAdmin, logs: peerLogs },
  };
}

function makeResponse() {
  return {
    status: 0, headers: {}, body: '',
    setHeader(k, v) { this.headers[k] = v; },
    writeHead(status, headers) { this.status = status; Object.assign(this.headers, headers || {}); },
    write(chunk) { this.body += chunk; return true; },
    end(chunk) { if (chunk) this.body += chunk; if (!this.status) this.status = 200; },
    once() {}, on() {},
  };
}

/** 面板那一侧的形状：回环 Host + 进程 token */
async function hit(node, method, apiPath, body) {
  const chunks = body === undefined ? [] : [Buffer.from(JSON.stringify(body))];
  const token = typeof node.admin.token === 'string' ? node.admin.token : '';
  const req = {
    method,
    url: apiPath,
    socket: { remoteAddress: '127.0.0.1', setNoDelay() {} },
    headers: {
      host: '127.0.0.1:7788',
      'content-type': 'application/json',
      'content-length': String(chunks[0]?.length ?? 0),
      ...(token === '' ? {} : { 'x-lan-peers-token': token }),
    },
    on() { return req; },
    once() { return req; },
    async *[Symbol.asyncIterator]() { for (const chunk of chunks) yield chunk; },
  };
  const res = makeResponse();
  await node.admin.handle(req, res, new URL('http://127.0.0.1' + apiPath));
  const parsed = (() => { try { return JSON.parse(res.body); } catch { return null; } })();
  return { status: res.status, body: parsed, raw: res.body };
}

/** 先挑一个「fetch 不拒绝」的空闲端口（与 group-cluster 同一套） */
async function pickFreePort() {
  for (let attempt = 0; attempt < 10; attempt += 1) {
    const port = await new Promise((resolve, reject) => {
      const probe = net.createServer();
      probe.unref();
      probe.once('error', reject);
      probe.listen(0, '127.0.0.1', () => {
        const found = probe.address().port;
        probe.close(() => resolve(found));
      });
    });
    if (!isFetchBlockedPort(port)) return port;
  }
  throw new Error('no fetch-safe free port');
}

const inviteFiles = (dir) => path.join(dir, 'group-invites.json');
const ledgerFile = (dir) => path.join(dir, 'group-invites-out.json');
const inviteStore = (dir) => (fs.existsSync(inviteFiles(dir)) ? JSON.parse(fs.readFileSync(inviteFiles(dir), 'utf8')) : { invites: {} });

// ---------------------------------------------------------------------------

test('I1 推送到达：peer 落盘一条邀请，面板那份不含 key', async (t) => {
  const pair = await startPair(t);
  const out = await hit(pair.hub, 'POST', '/api/lan-peers/group/invite', { peerId: PEER.peerId });
  assert.equal(out.status, 200);
  assert.deepEqual(out.body, { ok: true, peerId: PEER.peerId, state: 'invited' });

  // 盘上：接收方那一份
  const stored = inviteStore(pair.peer.dir);
  const keys = Object.keys(stored.invites);
  assert.equal(keys.length, 1);
  const groupId = keys[0];
  const hubState = pair.hub.server.group.state({ includeKey: true });
  assert.equal(groupId, hubState.groupId);
  assert.equal(stored.invites[groupId].key, hubState.groupKey);
  assert.equal(stored.invites[groupId].from.peerId, HUB.peerId);

  // 面板：只有面板需要的那几项，**没有 key**
  const listed = await hit(pair.peer, 'GET', '/api/lan-peers/group/invite');
  assert.equal(listed.status, 200);
  assert.equal(listed.body.invites.length, 1);
  const view = listed.body.invites[0];
  assert.deepEqual(Object.keys(view).sort(), ['from', 'groupId', 'memberCount', 'name', 'receivedAt']);
  assert.equal(view.groupId, groupId);
  assert.equal(view.name, GROUP_NAME);
  assert.deepEqual(view.from, { peerId: HUB.peerId, name: HUB.name });
  assert.ok(!('key' in view) && !('groupKey' in view));
  assert.equal(view.memberCount, 2); // hub + 被邀成员
  assert.ok(!listed.raw.includes(hubState.groupKey), 'key 绝不能出现在面板响应里');
});

test('I2 接受：写 group-key.json、邀请消失、群上下文变活', async (t) => {
  const pair = await startPair(t);
  const before = await hit(pair.peer, 'GET', '/api/lan-peers/group');
  assert.equal(before.body.enabled, false, '未接受前是 group-disabled（这是 live 的现状）');

  await hit(pair.hub, 'POST', '/api/lan-peers/group/invite', { peerId: PEER.peerId });
  const groupId = Object.keys(inviteStore(pair.peer.dir).invites)[0];
  const hubState = pair.hub.server.group.state({ includeKey: true });

  const accepted = await hit(pair.peer, 'POST', '/api/lan-peers/group/invite/accept', { groupId });
  assert.equal(accepted.status, 200);
  assert.deepEqual(accepted.body, { ok: true, groupId });

  // ① 授权真的落到 group-key.json（跳过 applyGroupGrant 时这一条就红）
  const keyFile = readGroupKeyFile(pair.peer.dir);
  assert.equal(keyFile.groupId, hubState.groupId);
  assert.equal(keyFile.key, hubState.groupKey);
  assert.equal(keyFile.keyVersion, hubState.keyVersion);
  assert.equal(keyFile.hub.peerId, HUB.peerId);

  // ② 邀请消失
  const listed = await hit(pair.peer, 'GET', '/api/lan-peers/group/invite');
  assert.deepEqual(listed.body.invites, []);

  // ③ 群上下文变活：既有提升（promoteToMember）跑过 —— 判据就是面板用的那一个 probe
  const local = pair.peer.server.group.local();
  assert.equal(local?.groupId, hubState.groupId, 'local() 认得出这个群（promoteToMember 生效）');
  assert.equal(local?.groupKey, hubState.groupKey);
  const after = await hit(pair.peer, 'GET', '/api/lan-peers/group');
  assert.equal(after.body.enabled, true, '接受后不再是 group-disabled');
  assert.equal(after.body.isHub, false);
});

test('I3 拒绝：丢掉邀请、仍然未入群', async (t) => {
  const pair = await startPair(t);
  await hit(pair.hub, 'POST', '/api/lan-peers/group/invite', { peerId: PEER.peerId });
  const groupId = Object.keys(inviteStore(pair.peer.dir).invites)[0];

  const declined = await hit(pair.peer, 'POST', '/api/lan-peers/group/invite/decline', { groupId });
  assert.equal(declined.status, 200);
  assert.deepEqual(declined.body, { ok: true });
  assert.deepEqual(inviteStore(pair.peer.dir).invites, {});
  assert.equal(readGroupKeyFile(pair.peer.dir), null, '拒绝不得写 group-key.json');
  const state = await hit(pair.peer, 'GET', '/api/lan-peers/group');
  assert.equal(state.body.enabled, false);

  // 再拒绝一次：404（幂等失败面稳定，不是 500）
  const again = await hit(pair.peer, 'POST', '/api/lan-peers/group/invite/decline', { groupId });
  assert.equal(again.status, 404);
  assert.equal(again.body.error, 'invite-not-found');
});

test('I4 半份授权：accept → 409 grant-incomplete，且不写 group-key.json', async (t) => {
  const pair = await startPair(t);
  await hit(pair.hub, 'POST', '/api/lan-peers/group/invite', { peerId: PEER.peerId });
  const file = inviteFiles(pair.peer.dir);
  const stored = JSON.parse(fs.readFileSync(file, 'utf8'));
  const groupId = Object.keys(stored.invites)[0];
  // 篡改：把 key 抹掉（等价于一个半份授权）
  delete stored.invites[groupId].key;
  fs.writeFileSync(file, JSON.stringify(stored, null, 2));

  const out = await hit(pair.peer, 'POST', '/api/lan-peers/group/invite/accept', { groupId });
  assert.equal(out.status, 409);
  assert.equal(out.body.error, 'grant-incomplete');
  assert.equal(readGroupKeyFile(pair.peer.dir), null, '半份授权绝不能写成「已入群」');
  // 邀请还在：修好以后还能再来一次
  assert.equal(Object.keys(inviteStore(pair.peer.dir).invites).length, 1);

  // 未知 groupId 走 404（与 409 分得开）
  const missing = await hit(pair.peer, 'POST', '/api/lan-peers/group/invite/accept', { groupId: 'g-nope' });
  assert.equal(missing.status, 404);
  assert.equal(missing.body.error, 'invite-not-found');
});

test('I5 已入群：already-member、一个字节都不发（对端已关停）', async (t) => {
  const pair = await startPair(t);
  await hit(pair.hub, 'POST', '/api/lan-peers/group/invite', { peerId: PEER.peerId });
  const groupId = Object.keys(inviteStore(pair.peer.dir).invites)[0];
  await hit(pair.peer, 'POST', '/api/lan-peers/group/invite/accept', { groupId });

  // 让 hub 真的知道「它入群了」：成员自己 pull 一次（X-Peer-LastSeq 那条上报）
  await pair.peer.server.group.pull();
  const known = await waitFor(() => pair.hub.server.group.joinedMemberIds().includes(PEER.peerId), { timeoutMs: 6_000 });
  assert.equal(known, true, 'hub 的 joined 判据 = 它真的来过（pull/probe 上报）');

  // 造**真不可达**：关掉 peer 的监听。这时任何真正发出的推送都会变成 unreachable，
  // 所以拿到 already-member 就证明「判据在推送之前」（推到已入群成员时这一条必红）。
  await pair.peer.server.close();
  const out = await hit(pair.hub, 'POST', '/api/lan-peers/group/invite', { peerId: PEER.peerId });
  assert.equal(out.status, 200);
  assert.equal(out.body.state, 'already-member');
  assert.equal(out.body.ok, true);

  // 账本照实记；接收方那份没有被新邀请污染（还是刚才那一份、且已被接受删除）
  const ledger = JSON.parse(fs.readFileSync(ledgerFile(pair.hub.dir), 'utf8'));
  assert.equal(ledger[PEER.peerId].state, 'already-member');
  assert.deepEqual(inviteStore(pair.peer.dir).invites, {});
});

test('I6 不可达：unreachable 记账，重试稳定不崩', async (t) => {
  const pair = await startPair(t);
  await pair.peer.server.close();
  const first = await hit(pair.hub, 'POST', '/api/lan-peers/group/invite', { peerId: PEER.peerId });
  assert.equal(first.status, 200);
  assert.deepEqual(first.body, { ok: false, peerId: PEER.peerId, state: 'unreachable', error: 'unreachable' });
  const second = await hit(pair.hub, 'POST', '/api/lan-peers/group/invite', { peerId: PEER.peerId });
  assert.equal(second.status, 200);
  assert.deepEqual(second.body, first.body, '重试的码必须一致（稳定）');
  const ledger = JSON.parse(fs.readFileSync(ledgerFile(pair.hub.dir), 'utf8'));
  assert.equal(ledger[PEER.peerId].state, 'unreachable');
  assert.equal(Object.keys(ledger).length, 1, '同一个 peer 只留一条账本');
});

test('I7 成员节点打 hub-only 路由 → 403 hub-only', async (t) => {
  const pair = await startPair(t);
  await hit(pair.hub, 'POST', '/api/lan-peers/group/invite', { peerId: PEER.peerId });
  const groupId = Object.keys(inviteStore(pair.peer.dir).invites)[0];
  await hit(pair.peer, 'POST', '/api/lan-peers/group/invite/accept', { groupId });

  // 接受之后 peer 是**成员**（resolveGroup 的 isHub=false）：这条路由必须 403
  const out = await hit(pair.peer, 'POST', '/api/lan-peers/group/invite', { peerId: HUB.peerId });
  assert.equal(out.status, 403);
  assert.equal(out.body.error, 'hub-only');

  // 反过来 hub 自己打这条路由是正常的（同一个路由两面）
  const ok = await hit(pair.hub, 'POST', '/api/lan-peers/group/invite', { peerId: PEER.peerId });
  assert.equal(ok.status, 200);
});

test('I8 重复邀请：接收方一条、账本一条，面板 joinState 正确', async (t) => {
  const pair = await startPair(t);
  const first = await hit(pair.hub, 'POST', '/api/lan-peers/group/invite', { peerId: PEER.peerId });
  const second = await hit(pair.hub, 'POST', '/api/lan-peers/group/invite', { peerId: PEER.peerId });
  assert.equal(first.body.state, 'invited');
  assert.equal(second.body.state, 'invited');
  const stored = inviteStore(pair.peer.dir).invites;
  assert.equal(Object.keys(stored).length, 1, '同一个 groupId 只留一条邀请');
  const ledger = JSON.parse(fs.readFileSync(ledgerFile(pair.hub.dir), 'utf8'));
  assert.equal(Object.keys(ledger).length, 1, '同一个 peer 只留一条账本');
  assert.equal(ledger[PEER.peerId].state, 'invited');

  // 面板：GET group 带 joinState（invisible → invited），这就是 slice B 选按钮的依据
  const state = await hit(pair.hub, 'GET', '/api/lan-peers/group');
  assert.equal(state.status, 200);
  const member = state.body.group.members.find((entry) => entry.peerId === PEER.peerId);
  assert.equal(member.joinState, 'invited');
  assert.equal(state.body.invites.joinStates[PEER.peerId], 'invited');
  const selfMember = state.body.group.members.find((entry) => entry.peerId === HUB.peerId);
  assert.equal(selfMember.joinState, 'joined');
});

test('V3 非配对调用方打 /v1/group/invite → 401（per-peer 门禁确实盖到了新路由）', async (t) => {
  const pair = await startPair(t);
  // 不带签名头、不带信封：与其它 per-peer 路径同一条拒绝面
  // 与其它 per-peer 路径同一条拒绝面：这台机器上 requireEncryption 是默认开的，
  // 所以「未配对」先表现为没带信封的 400 encryption-required；带上信封（伪造的陌生密钥）
  // 才走到验签那一步 —— 那一步的 401 才是「这条路由确实在 per-peer 白名单里」的证据。
  const plain = await request(pair.peer.url, {
    method: 'POST',
    path: '/v1/group/invite',
    body: { groupId: 'g-x', key: 'k-x', members: [] },
  });
  assert.equal(plain.status, 400);
  assert.equal(plain.json.error, 'encryption-required');
  const stranger = await request(pair.peer.url, {
    method: 'POST',
    path: '/v1/group/invite',
    peerId: 'peer-stranger',
    secret: 'not-the-paired-secret',
    encrypt: true,
    body: { groupId: 'g-x', key: 'k-x', members: [] },
  });
  assert.equal(stranger.status, 401);
  assert.equal(stranger.json.error, 'bad-signature');
  assert.deepEqual(inviteStore(pair.peer.dir).invites, {}, '未鉴权的推送不得落盘');
});
// ---------------------------------------------------------------------------
// slice B · P1：未入群节点的 GET group 必须**自己**带上待接受邀请
//
// 面板「一个节拍一条请求」的硬前提：disabled 形状里没有 invites，面板就只能每 2s 再打
// 一条 GET group/invite。这条用例同时钉住两件事 —— 有/没有两种情况下 invites 都在，
// 而且老字段（enabled/isHub/group/messages/lastSeq）一个值都没动。
// ---------------------------------------------------------------------------
test('B1 disabled 形状带 invites（空与非空），其余五个字段一字不改', async (t) => {
  const pair = await startPair(t);
  const empty = await hit(pair.peer, 'GET', '/api/lan-peers/group');
  assert.equal(empty.status, 200);
  // 空的那一份：老形状 + invites: []，key 集合恰好是这六个
  assert.deepEqual(empty.body, {
    enabled: false, isHub: false, group: null, messages: [], lastSeq: 0, invites: [],
  });

  await hit(pair.hub, 'POST', '/api/lan-peers/group/invite', { peerId: PEER.peerId });
  const groupId = Object.keys(inviteStore(pair.peer.dir).invites)[0];
  const withOne = await hit(pair.peer, 'GET', '/api/lan-peers/group');
  assert.deepEqual(Object.keys(withOne.body).sort(),
    ['enabled', 'group', 'invites', 'isHub', 'lastSeq', 'messages']);
  // 老字段逐个对照：不是「还在」，是逐个值相同
  for (const key of ['enabled', 'isHub', 'group', 'messages', 'lastSeq']) {
    assert.deepEqual(withOne.body[key], empty.body[key], '老字段被改动了：' + key);
  }
  assert.equal(withOne.body.invites.length, 1);
  const view = withOne.body.invites[0];
  assert.deepEqual(Object.keys(view).sort(), ['from', 'groupId', 'memberCount', 'name', 'receivedAt']);
  assert.equal(view.groupId, groupId);
  assert.equal(view.name, GROUP_NAME);
  assert.deepEqual(view.from, { peerId: HUB.peerId, name: HUB.name });
  assert.equal(view.memberCount, 2);
  const hubKey = pair.hub.server.group.state({ includeKey: true }).groupKey;
  assert.ok(!withOne.raw.includes(hubKey), '群密钥绝不能进面板响应');
});

// ---------------------------------------------------------------------------
// slice B · P4：ack —— 被邀请方的接受/拒绝回头写进邀请方账本
// ---------------------------------------------------------------------------
test('B4a 接受之后 hub 账本从 invited 翻成 joined', async (t) => {
  const pair = await startPair(t);
  await hit(pair.hub, 'POST', '/api/lan-peers/group/invite', { peerId: PEER.peerId });
  const groupId = Object.keys(inviteStore(pair.peer.dir).invites)[0];
  assert.equal(JSON.parse(fs.readFileSync(ledgerFile(pair.hub.dir), 'utf8'))[PEER.peerId].state, 'invited');

  const accepted = await hit(pair.peer, 'POST', '/api/lan-peers/group/invite/accept', { groupId });
  assert.equal(accepted.status, 200);
  // accept 里 await 了这条 ack（上界 3s），所以这里读到的一定是 ack 之后的状态
  const ledger = JSON.parse(fs.readFileSync(ledgerFile(pair.hub.dir), 'utf8'));
  assert.equal(ledger[PEER.peerId].state, 'joined', 'hub 账本必须从 invited 变成 joined');
  assert.ok(pair.peer.logs.some((line) => line.includes('[group] invite ack sent gid=')), 'ack 成功要留一行日志');

  // 面板的三态也跟着变：此时 memberProgress 还没更新，joined 只可能来自账本
  const state = await hit(pair.hub, 'GET', '/api/lan-peers/group');
  const member = state.body.group.members.find((entry) => entry.peerId === PEER.peerId);
  assert.equal(member.joinState, 'joined');
});

test('B4b 拒绝之后 hub 账本翻成 declined，joinState 回到 not-invited（可再邀请）', async (t) => {
  const pair = await startPair(t);
  await hit(pair.hub, 'POST', '/api/lan-peers/group/invite', { peerId: PEER.peerId });
  const groupId = Object.keys(inviteStore(pair.peer.dir).invites)[0];

  const declined = await hit(pair.peer, 'POST', '/api/lan-peers/group/invite/decline', { groupId });
  assert.equal(declined.status, 200);
  const ledger = JSON.parse(fs.readFileSync(ledgerFile(pair.hub.dir), 'utf8'));
  assert.equal(ledger[PEER.peerId].state, 'declined');

  const state = await hit(pair.hub, 'GET', '/api/lan-peers/group');
  const member = state.body.group.members.find((entry) => entry.peerId === PEER.peerId);
  assert.equal(member.joinState, 'not-invited', '拒绝是「还能再邀一次」，不是终态');
});

test('B4c hub 不可达时 ack 失败：accept 照样成功，账本之外的一切都不受影响', async (t) => {
  const pair = await startPair(t);
  await hit(pair.hub, 'POST', '/api/lan-peers/group/invite', { peerId: PEER.peerId });
  const groupId = Object.keys(inviteStore(pair.peer.dir).invites)[0];
  const hubState = pair.hub.server.group.state({ includeKey: true });
  // 邀请方真的掉线：这条 ack 必然失败
  await pair.hub.server.close();

  const accepted = await hit(pair.peer, 'POST', '/api/lan-peers/group/invite/accept', { groupId });
  assert.equal(accepted.status, 200, 'ack 失败绝不能把入群变成失败');
  assert.deepEqual(accepted.body, { ok: true, groupId });
  // 入群的三个判据一个不少：key 落盘、邀请消失、群上下文变活
  const keyFile = readGroupKeyFile(pair.peer.dir);
  assert.equal(keyFile.groupId, hubState.groupId);
  assert.equal(keyFile.key, hubState.groupKey);
  assert.deepEqual(inviteStore(pair.peer.dir).invites, {});
  assert.equal((await hit(pair.peer, 'GET', '/api/lan-peers/group')).body.enabled, true);
  // 失败只留一行：gid 前 8 位，没有 body、没有密钥
  const failed = pair.peer.logs.filter((line) => line.includes('[group] invite ack failed gid='));
  assert.equal(failed.length, 1, '一次失败一行日志');
  assert.match(failed[0], /^\[group\] invite ack failed gid=[0-9a-zA-Z]{1,8}$/);
});

test('B4d ack 路由的门：未加密 400、群对不上 409、答过的不能再改账本', async (t) => {
  const pair = await startPair(t);
  await hit(pair.hub, 'POST', '/api/lan-peers/group/invite', { peerId: PEER.peerId });
  const groupId = Object.keys(inviteStore(pair.peer.dir).invites)[0];

  const plain = await request(pair.hub.url, {
    method: 'POST', path: '/v1/group/invite/ack', body: { groupId, decision: 'decline' },
  });
  assert.equal(plain.status, 400);
  assert.equal(plain.json.error, 'encryption-required');

  // 被邀请方自己签名（per-peer 门）：这条 ack 真的能写账本
  const ack = (decision, gid) => request(pair.hub.url, {
    method: 'POST',
    path: '/v1/group/invite/ack',
    peerId: PEER.peerId,
    secret: secretOf(PEER.peerId),
    encrypt: true,
    body: { groupId: gid, decision },
  });
  const declined = await ack('decline', groupId);
  assert.equal(declined.status, 200);
  assert.deepEqual(declined.json, { ok: true, groupId, state: 'declined' });

  // 群对不上：ack 只对「邀请里那个群」有意义
  const wrong = await ack('accept', 'g-other');
  assert.equal(wrong.status, 409);
  assert.equal(wrong.json.error, 'group-mismatch');

  // 已经答过的人再 ack：403 not-invited，且既成事实不被覆盖
  const again = await ack('accept', groupId);
  assert.equal(again.status, 403);
  assert.equal(again.json.error, 'not-invited');
  assert.equal(JSON.parse(fs.readFileSync(ledgerFile(pair.hub.dir), 'utf8'))[PEER.peerId].state, 'declined');
});
