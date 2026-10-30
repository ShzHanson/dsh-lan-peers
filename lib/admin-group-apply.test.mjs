// dsh-lan-peers · v0.8.0（契约 §8）管理接口：待批准申请 / 改名查重 / 按名查找 / 申请链路。
//
// 契约口径：
//   §6 改名先查重（可达邻域=已配对伙伴及其已知群），同名不同 groupId → 409 name-taken 且不改名；
//   §8 GET/POST group/applications 只给 hub；面板的查找/申请/状态/广播各自一条回环路由。
// Lane P 的五个函数按冻结签名注入（groupNet），本文件既验证接线参数，也验证「P 未落地时降级」。
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createAdmin } from './admin.mjs';
import { makeTempStateDir, writeJson0600 } from '../host/test/helpers.mjs';

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

function makeRequest(method, url, body) {
  const chunks = body === undefined ? [] : [Buffer.from(JSON.stringify(body))];
  const req = {
    method,
    url,
    socket: { remoteAddress: '127.0.0.1', setNoDelay() {} },
    headers: { 'content-type': 'application/json', 'content-length': String(chunks[0]?.length ?? 0) },
    on() { return req; },
    once() { return req; },
    async *[Symbol.asyncIterator]() { for (const chunk of chunks) yield chunk; },
  };
  return req;
}

async function hit(admin, method, apiPath, body) {
  const res = makeResponse();
  const handled = await admin.handle(makeRequest(method, apiPath, body), res, new URL('http://127.0.0.1' + apiPath));
  return { handled, res, json: (() => { try { return JSON.parse(res.body); } catch { return null; } })() };
}

const MEMBERS = [
  { peerId: 'peer-self', name: 'self-box', online: true, lastSeen: 1_700_000_000_000, joinedAt: 1 },
  { peerId: 'peer-nas', name: 'nas-box', online: true, lastSeen: 1_700_000_500_000, joinedAt: 2 },
];

/** 已配对伙伴（peers.json 视图无 secret，getPeer 才有 —— 路由必须走 getPeer）。 */
const PEERS = [
  { peerId: 'peer-a', name: 'nas-a', baseUrl: 'http://10.0.0.2:7788', secret: 'sec-a' },
  { peerId: 'peer-b', name: 'nas-b', baseUrl: 'http://10.0.0.3:7788', secret: 'sec-b' },
];

function makeHubApi({
  groupId = 'g-own', groupName = '家里', members = MEMBERS,
  applications = [], failOn = null,
} = {}) {
  const calls = [];
  const guard = (name) => {
    if (failOn === name) {
      const error = new Error('hub unavailable');
      error.status = 502;
      throw error;
    }
  };
  return {
    calls,
    enabled: true,
    isHub: true,
    state() {
      calls.push({ method: 'state' });
      guard('state');
      return { groupId, name: groupName, members, messages: [], lastSeq: 3 };
    },
    async applications() {
      calls.push({ method: 'applications' });
      guard('applications');
      return { applications };
    },
    async decideApplication({ peerId, action }) {
      calls.push({ method: 'decideApplication', peerId, action });
      guard('decideApplication');
      if (peerId === 'peer-ghost') {
        const error = new Error('unknown-application');
        error.status = 404;
        throw error;
      }
      return { status: action === 'approve' ? 'approved' : 'rejected' };
    },
    setName({ name }) {
      calls.push({ method: 'setName', name });
      guard('setName');
      return { name };
    },
  };
}

function stubAdmin({
  peers = PEERS, group = { enabled: true, hub: '' }, api = null, facade = null,
  groupNet = null, applyGrant = null, stateDir = '',
} = {}) {
  const lines = [];
  const store = {
    instanceId: 'peer-self',
    stateDir,
    listPeers: () => peers.map(({ peerId, name, baseUrl }) => ({ peerId, name, baseUrl })),
    getPeer: (id) => peers.find((peer) => peer.peerId === id) || null,
  };
  const admin = createAdmin({
    server: { config: { logger: (line) => lines.push(line), listenPort: 0 }, store, group: facade },
    nameOf: () => 'self-box',
    rename: (n) => n,
    feed: null,
    pairing: { mode: 'auto' },
    group,
    groupApi: api,
    groupNet,
    applyGrant,
  });
  return { admin, lines };
}

/** Lane P 的五个冻结签名，按需覆盖/失败。 */
function makeNet({ matches = [], advertiseThrows = false, lookupThrows = [], poll = null, apply = null, knownGroups = null } = {}) {
  const calls = { lookup: [], advertise: [], apply: [], poll: [], known: 0 };
  const net = {
    calls,
    async lookupGroupName(args) {
      calls.lookup.push(args);
      if (lookupThrows.includes(args.baseUrl)) throw new Error('connect ECONNREFUSED');
      return { matches: typeof matches === 'function' ? matches(args) : matches };
    },
    async advertiseGroup(args) {
      calls.advertise.push(args);
      if (advertiseThrows) throw new Error('advertise failed');
      return { ok: true };
    },
    async applyToGroup(args) {
      calls.apply.push(args);
      if (typeof apply === 'function') return apply(args);
      return { status: 'pending' };
    },
    async pollApplication(args) {
      calls.poll.push(args);
      if (typeof poll === 'function') return poll(args);
      return { status: 'pending' };
    },
    readKnownGroups(dir) {
      calls.known += 1;
      if (typeof knownGroups === 'function') return knownGroups(dir);
      return { groups: knownGroups || {} };
    },
  };
  return net;
}

// ---------------------------------------------------------------------------
// 契约 §8：GET / POST group/applications
// ---------------------------------------------------------------------------

const APPLICATIONS = [
  { peerId: 'peer-a', name: 'nas-a', introducedBy: 'peer-nas', introducedByName: 'nas-box', at: Date.now() - 1000, status: 'pending', decidedAt: null },
  { peerId: 'peer-b', name: 'nas-b', introducedBy: 'peer-nas', introducedByName: 'nas-box', at: Date.now() - 2000, status: 'approved', decidedAt: Date.now() - 1500 },
];

test('GET group/applications：hub 返回申请清单，日志只记条数', async () => {
  const api = makeHubApi({ applications: APPLICATIONS });
  const { admin, lines } = stubAdmin({ api });
  const out = await hit(admin, 'GET', '/api/lan-peers/group/applications');
  assert.equal(out.res.status, 200);
  assert.deepEqual(out.json.applications, APPLICATIONS);
  const line = lines.find((l) => l.includes('[admin] group applications'));
  assert.match(line, /pending=1/);
  assert.match(line, /total=2/);
});

test('GET group/applications：成员侧 403 hub-only，未启用 409 group-disabled', async () => {
  const memberSide = stubAdmin({ api: { ...makeHubApi(), isHub: false } });
  const forbidden = await hit(memberSide.admin, 'GET', '/api/lan-peers/group/applications');
  assert.equal(forbidden.res.status, 403);
  assert.deepEqual(forbidden.json, { error: 'hub-only' });

  const disabled = stubAdmin({ group: { enabled: false } });
  const off = await hit(disabled.admin, 'GET', '/api/lan-peers/group/applications');
  assert.equal(off.res.status, 409);
  assert.deepEqual(off.json, { error: 'group-disabled' });
});

test('申请视图归一化：ISO 时间两态、字符串介绍人 + introducedByName、decidedAt 三态', async () => {
  const stateDir = makeTempStateDir();
  const now = Date.now();
  const isoAt = new Date(now - 60_000).toISOString();
  const isoDecided = new Date(now - 30_000).toISOString();
  const oldIso = new Date(now - 25 * 3600 * 1000).toISOString();
  writeJson0600(path.join(stateDir, 'group.json'), {
    groupId: 'g-own',
    name: '家里',
    members: {},
    messages: [],
    lastSeq: 0,
    applications: {
      // 契约 §7 落盘形态：introducedBy 是 peerId 字符串、decidedAt 是 ISO；at 换成 ISO 也要能吃
      'peer-iso': { name: 'nas-iso', introducedBy: 'peer-nas', introducedByName: 'nas-box', at: isoAt, status: 'approved', decidedAt: isoDecided },
      // 宿主视图形态：introducedBy 是对象，at / decidedAt 是毫秒
      'peer-ms': { name: 'nas-ms', introducedBy: { peerId: 'peer-nas', name: 'nas-box' }, at: now - 120_000, status: 'approved', decidedAt: now - 90_000 },
      // 没有介绍人、没有 decidedAt
      'peer-none': { name: 'nas-none', introducedBy: '', at: now - 180_000, status: 'pending' },
      // ISO 形态的 at 也必须参与 24h TTL（否则过期申请永远挂着）
      'peer-old': { name: 'nas-old', introducedBy: 'peer-nas', at: oldIso, status: 'pending' },
    },
  });
  const facade = {
    enabled: true,
    isHub: true,
    state: () => ({ groupId: 'g-own', name: '家里', members: [], messages: [], lastSeq: 0 }),
    members: () => [],
    history: () => [],
  };
  const { admin } = stubAdmin({ facade, stateDir });
  const out = await hit(admin, 'GET', '/api/lan-peers/group/applications');
  assert.equal(out.res.status, 200);
  const byId = Object.fromEntries(out.json.applications.map((item) => [item.peerId, item]));
  assert.deepEqual(Object.keys(byId).sort(), ['peer-iso', 'peer-ms', 'peer-none'], 'ISO 形态的 at 也要被 TTL 裁掉');
  assert.deepEqual(out.json.applications.map((item) => item.peerId), ['peer-iso', 'peer-ms', 'peer-none'], '新的在前');

  assert.equal(byId['peer-iso'].at, Date.parse(isoAt));
  assert.equal(byId['peer-iso'].decidedAt, Date.parse(isoDecided), 'ISO 的 decidedAt 归一成毫秒');
  assert.equal(byId['peer-iso'].introducedBy, 'peer-nas');
  assert.equal(byId['peer-iso'].introducedByName, 'nas-box', '字符串形态介绍人 + introducedByName 时名字必须保留');
  assert.equal(byId['peer-ms'].decidedAt, now - 90_000, '毫秒形态的 decidedAt 原样保留');
  assert.equal(byId['peer-ms'].introducedByName, 'nas-box', '对象形态介绍人取 by.name');
  assert.equal(byId['peer-none'].decidedAt, null, '缺失即 null');
  assert.equal(byId['peer-none'].introducedByName, '');
});

test('GET group/applications：后端出错 → 透传状态码并留痕', async () => {
  const { admin, lines } = stubAdmin({ api: makeHubApi({ failOn: 'applications' }) });
  const out = await hit(admin, 'GET', '/api/lan-peers/group/applications');
  assert.equal(out.res.status, 502);
  assert.match(out.json.error, /hub unavailable/);
  assert.ok(lines.some((l) => l.includes('[admin] group applications failed')));
});

test('GET group/applications：host 门面未接线时退回只读 group.json（TTL 24h + 介绍人归一化）', async () => {
  const stateDir = makeTempStateDir();
  const now = Date.now();
  writeJson0600(path.join(stateDir, 'group.json'), {
    groupId: 'g-own',
    name: '家里',
    members: {},
    messages: [],
    lastSeq: 0,
    applications: {
      'peer-a': { name: 'nas-a', baseUrl: 'http://10.0.0.2:7788', introducedBy: { peerId: 'peer-nas', name: 'nas-box' }, at: now - 1000, status: 'pending' },
      'peer-b': { name: 'nas-b', introducedBy: 'peer-nas', at: now - 2000, status: 'rejected', decidedAt: now - 1500 },
      // 25 小时前的申请已经过期（契约 §7 TTL 24 小时）：面板不该再看见它
      'peer-old': { name: 'old', introducedBy: 'peer-nas', at: now - 25 * 3600 * 1000, status: 'pending' },
    },
  });
  const facade = {
    enabled: true,
    isHub: true,
    state: () => ({ groupId: 'g-own', name: '家里', members: [], messages: [], lastSeq: 0 }),
    members: () => [],
    history: () => [],
  };
  const { admin } = stubAdmin({ api: null, facade, stateDir });
  const out = await hit(admin, 'GET', '/api/lan-peers/group/applications');
  assert.equal(out.res.status, 200);
  assert.deepEqual(out.json.applications.map((item) => item.peerId), ['peer-a', 'peer-b'], '过期条目被 TTL 裁掉，新的在前');
  assert.equal(out.json.applications[0].introducedByName, 'nas-box', '介绍人是对象形状时名字取出来');
  assert.equal(out.json.applications[1].introducedBy, 'peer-nas', '介绍人是字符串形状时照抄 peerId');
});

test('POST group/applications：approve / reject 只转发给 hub 后端', async () => {
  const api = makeHubApi();
  const { admin, lines } = stubAdmin({ api });
  const approve = await hit(admin, 'POST', '/api/lan-peers/group/applications', { peerId: 'peer-a', action: 'approve' });
  assert.equal(approve.res.status, 200);
  assert.deepEqual(approve.json, { ok: true, status: 'approved' });
  const reject = await hit(admin, 'POST', '/api/lan-peers/group/applications', { peerId: 'peer-b', action: 'reject' });
  assert.deepEqual(reject.json, { ok: true, status: 'rejected' });
  assert.deepEqual(api.calls.filter((c) => c.method === 'decideApplication'), [
    { method: 'decideApplication', peerId: 'peer-a', action: 'approve' },
    { method: 'decideApplication', peerId: 'peer-b', action: 'reject' },
  ]);
  assert.ok(lines.some((l) => l.includes('peer=peer-a action=approve status=approved')));
});

test('POST group/applications：action/peerId 校验、成员侧 403、未知申请 404', async () => {
  const api = makeHubApi();
  const { admin } = stubAdmin({ api });
  const badAction = await hit(admin, 'POST', '/api/lan-peers/group/applications', { peerId: 'peer-a', action: 'drop' });
  assert.equal(badAction.res.status, 400);
  assert.deepEqual(badAction.json, { error: 'bad-action' });
  const noPeer = await hit(admin, 'POST', '/api/lan-peers/group/applications', { action: 'approve' });
  assert.equal(noPeer.res.status, 400);
  assert.deepEqual(noPeer.json, { error: 'peerId-required' });
  assert.equal(api.calls.length, 0, '校验失败不得下发到后端');

  const memberSide = stubAdmin({ api: { ...makeHubApi(), isHub: false } });
  const forbidden = await hit(memberSide.admin, 'POST', '/api/lan-peers/group/applications', { peerId: 'peer-a', action: 'approve' });
  assert.equal(forbidden.res.status, 403);

  const ghost = await hit(admin, 'POST', '/api/lan-peers/group/applications', { peerId: 'peer-ghost', action: 'approve' });
  assert.equal(ghost.res.status, 404);
  assert.deepEqual(ghost.json, { error: 'unknown-application' });
});

test('POST group/applications：host 门面没有决定入口 → 501（批准要它才生得出 grant）', async () => {
  const facade = {
    enabled: true,
    isHub: true,
    state: () => ({ groupId: 'g-own', name: '家里', members: [], messages: [], lastSeq: 0 }),
    members: () => [],
    history: () => [],
  };
  const { admin, lines } = stubAdmin({ facade });
  const out = await hit(admin, 'POST', '/api/lan-peers/group/applications', { peerId: 'peer-a', action: 'approve' });
  assert.equal(out.res.status, 501);
  assert.deepEqual(out.json, { error: 'applications-unsupported' });
  assert.ok(lines.some((l) => l.includes('[admin] group application failed')), '拒绝也要留痕');
});

// ---------------------------------------------------------------------------
// 契约 §6：改名查重
// ---------------------------------------------------------------------------

test('改名查重：同名不同 groupId → 409 name-taken，群名不变', async () => {
  const api = makeHubApi();
  const net = makeNet({
    matches: (args) => (args.baseUrl === 'http://10.0.0.2:7788'
      ? [{ groupId: 'g-other', name: '家里', hub: { peerId: 'peer-hub', name: 'hub-box', baseUrl: 'http://10.0.0.9:7788' } }]
      : []),
  });
  const { admin, lines } = stubAdmin({ api, groupNet: net });
  const out = await hit(admin, 'POST', '/api/lan-peers/group/config', { name: '家里' });
  assert.equal(out.res.status, 409);
  assert.equal(out.json.error, 'name-taken');
  assert.deepEqual(out.json.conflicts, [{
    peerId: 'peer-a', peerName: 'nas-a', groupId: 'g-other', name: '家里',
  }]);
  assert.equal(api.calls.some((call) => call.method === 'setName'), false, '冲突时绝不能改名');
  assert.ok(lines.some((l) => l.includes('[admin] group name taken')));
  assert.equal(net.calls.lookup.length, 2, '所有已配对伙伴都要问一遍（并发）');
  assert.equal(net.calls.lookup[0].timeoutMs, 2000, '契约 §6：2 秒超时');
  assert.equal(net.calls.lookup[0].senderId, 'peer-self');
  assert.equal(net.calls.lookup[0].secret, 'sec-a', '必须用 getPeer 的完整记录（脱敏视图没有 secret）');
});

test('改名查重：没有冲突就改名，并向非成员伙伴广播新名', async () => {
  const api = makeHubApi();
  const net = makeNet();
  const { admin, lines } = stubAdmin({ api, groupNet: net });
  const out = await hit(admin, 'POST', '/api/lan-peers/group/config', { name: '新家' });
  assert.equal(out.res.status, 200);
  assert.deepEqual(out.json, { ok: true, name: '新家' }, '响应形状维持 v0.7.4');
  assert.ok(api.calls.some((call) => call.method === 'setName' && call.name === '新家'));
  // peer-a / peer-b 都不在成员表里（MEMBERS 只有 peer-self / peer-nas）
  assert.equal(net.calls.advertise.length, 2, '广播对象 = 已配对但不在群里的伙伴');
  assert.deepEqual(net.calls.advertise[0].member, { peerId: 'peer-self', name: 'self-box' });
  assert.equal(net.calls.advertise[0].name, '新家');
  assert.equal(net.calls.advertise[0].groupId, 'g-own');
  assert.ok(lines.some((l) => l.includes('[admin] group advertise targets=2 sent=2')));
});

test('改名查重：同名但是自己这个群（同 groupId）不算冲突', async () => {
  const api = makeHubApi({ groupId: 'g-own', groupName: '家里' });
  const net = makeNet({ matches: [{ groupId: 'g-own', name: '家里' }] });
  const { admin } = stubAdmin({ api, groupNet: net });
  const out = await hit(admin, 'POST', '/api/lan-peers/group/config', { name: '家里' });
  assert.equal(out.res.status, 200);
  assert.ok(api.calls.some((call) => call.method === 'setName'));
});

test('改名查重：去空白 + 大小写不敏感（契约 §3 的比较口径）', async () => {
  const api = makeHubApi();
  const net = makeNet({ matches: [{ groupId: 'g-other', name: ' Family Room ' }] });
  const { admin } = stubAdmin({ api, groupNet: net });
  const conflict = await hit(admin, 'POST', '/api/lan-peers/group/config', { name: 'familyroom' });
  assert.equal(conflict.res.status, 409);
  assert.equal(conflict.json.error, 'name-taken');

  const clear = stubAdmin({ api: makeHubApi(), groupNet: makeNet({ matches: [{ groupId: 'g-other', name: '别的群' }] }) });
  const ok = await hit(clear.admin, 'POST', '/api/lan-peers/group/config', { name: 'familyroom' });
  assert.equal(ok.res.status, 200);
});

test('改名查重：某个伙伴查不动就跳过它（失败忽略 + 一行日志），不阻塞改名', async () => {
  const api = makeHubApi();
  const net = makeNet({ lookupThrows: ['http://10.0.0.2:7788'] });
  const { admin, lines } = stubAdmin({ api, groupNet: net });
  const out = await hit(admin, 'POST', '/api/lan-peers/group/config', { name: '新家' });
  assert.equal(out.res.status, 200);
  assert.ok(lines.some((l) => l.includes('[admin] group lookup peer=peer-a failed')), '失败一路一行日志');
  assert.ok(lines.some((l) => l.includes('group name check unreachable=1/2')));
});

test('改名查重：Lane P 未接线时跳过查重（既有改名行为不变）', async () => {
  const api = makeHubApi();
  const { admin, lines } = stubAdmin({ api, groupNet: { lookupGroupName: null, advertiseGroup: null } });
  const out = await hit(admin, 'POST', '/api/lan-peers/group/config', { name: '新家' });
  assert.equal(out.res.status, 200);
  assert.deepEqual(out.json, { ok: true, name: '新家' });
  assert.ok(lines.some((l) => l.includes('[admin] group name check skipped (lookup-unavailable)')));
  assert.ok(lines.some((l) => l.includes('[admin] group advertise skipped (advertise-unavailable)')));
});

test('改名查重：成员侧仍然 403 hub-only，坏名字 400', async () => {
  const memberSide = stubAdmin({ api: { ...makeHubApi(), isHub: false } });
  const forbidden = await hit(memberSide.admin, 'POST', '/api/lan-peers/group/config', { name: '家里' });
  assert.equal(forbidden.res.status, 403);
  assert.deepEqual(forbidden.json, { error: 'hub-only' });

  const hub = stubAdmin({ api: makeHubApi(), groupNet: makeNet() });
  const blank = await hit(hub.admin, 'POST', '/api/lan-peers/group/config', { name: '   ' });
  assert.equal(blank.res.status, 400);
  assert.deepEqual(blank.json, { error: 'bad-name' });
});

// ---------------------------------------------------------------------------
// 契约 §2(b)：手动广播按钮
// ---------------------------------------------------------------------------

test('POST group/advertise：只发给非成员伙伴，返回广播对象数量', async () => {
  const api = makeHubApi();
  const net = makeNet();
  const { admin, lines } = stubAdmin({ api, groupNet: net });
  const out = await hit(admin, 'POST', '/api/lan-peers/group/advertise', {});
  assert.equal(out.res.status, 200);
  assert.deepEqual(out.json, { ok: true, targets: 2, sent: 2 });
  assert.equal(net.calls.advertise.length, 2);
  assert.equal(net.calls.advertise[0].hub.peerId, 'peer-self');
  assert.ok(lines.some((l) => l.includes('group advertise groupId=g-own targets=2 sent=2')));
});

test('POST group/advertise：成员对象里的伙伴不重复广播', async () => {
  const api = makeHubApi({ members: [...MEMBERS, { peerId: 'peer-a', name: 'nas-a' }] });
  const net = makeNet();
  const { admin } = stubAdmin({ api, groupNet: net });
  const out = await hit(admin, 'POST', '/api/lan-peers/group/advertise', {});
  assert.deepEqual(out.json, { ok: true, targets: 1, sent: 1 });
  assert.deepEqual(net.calls.advertise.map((call) => call.baseUrl), ['http://10.0.0.3:7788']);
});

test('POST group/advertise：非 hub 403、Lane P 缺席 501、群没准备好 409', async () => {
  const memberSide = stubAdmin({ api: { ...makeHubApi(), isHub: false } });
  const forbidden = await hit(memberSide.admin, 'POST', '/api/lan-peers/group/advertise', {});
  assert.equal(forbidden.res.status, 403);

  const unsupported = stubAdmin({ api: makeHubApi(), groupNet: { advertiseGroup: null } });
  const missing = await hit(unsupported.admin, 'POST', '/api/lan-peers/group/advertise', {});
  assert.equal(missing.res.status, 501);
  assert.equal(missing.json.error, 'advertise-unsupported');
  assert.equal(missing.json.targets, 2, '接口不可用也要如实报广播对象数量');

  const notReady = stubAdmin({ api: makeHubApi({ groupId: '', groupName: '' }), groupNet: makeNet() });
  const empty = await hit(notReady.admin, 'POST', '/api/lan-peers/group/advertise', {});
  assert.equal(empty.res.status, 409);
  assert.deepEqual(empty.json, { error: 'group-not-ready' });
});

// ---------------------------------------------------------------------------
// 契约 §3：按名查找（先本地 known-groups，未命中问伙伴）
// ---------------------------------------------------------------------------

test('POST group/lookup：本地 known-groups 命中就不再打扰伙伴', async () => {
  const net = makeNet({ knownGroups: { 'g-known': { name: '家里', hub: { peerId: 'peer-hub', name: 'hub-box' }, source: { peerId: 'peer-nas', name: 'nas-box' } } } });
  const { admin } = stubAdmin({ group: { enabled: false }, groupNet: net });
  const out = await hit(admin, 'POST', '/api/lan-peers/group/lookup', { name: ' 家里 ' });
  assert.equal(out.res.status, 200);
  assert.equal(out.json.source, 'local');
  assert.deepEqual(out.json.matches[0], {
    groupId: 'g-known',
    name: '家里',
    hub: { peerId: 'peer-hub', name: 'hub-box' },
    via: { peerId: 'peer-nas', name: 'nas-box' },
    source: 'local',
  });
  assert.equal(net.calls.lookup.length, 0, '本地命中后不必再查伙伴');
});

test('POST group/lookup：本地没命中就并发问伙伴，命中带 via，按 groupId 去重', async () => {
  const net = makeNet({
    matches: (args) => [
      { groupId: 'g-other', name: '家里', hub: { peerId: 'peer-hub', name: 'hub-box' } },
      ...(args.baseUrl === 'http://10.0.0.3:7788' ? [{ groupId: 'g-other', name: '家里' }, { groupId: 'g-2', name: '家里' }] : []),
    ],
    lookupThrows: ['http://10.0.0.3:7788'].length ? [] : [],
  });
  const { admin, lines } = stubAdmin({ groupNet: net });
  const out = await hit(admin, 'POST', '/api/lan-peers/group/lookup', { name: '家里' });
  assert.equal(out.res.status, 200);
  assert.equal(out.json.source, 'peers');
  assert.deepEqual(out.json.matches.map((m) => m.groupId), ['g-other', 'g-2'], '同一 groupId 只留一条');
  assert.deepEqual(out.json.matches[0].via, { peerId: 'peer-a', name: 'nas-a' });
  assert.equal(out.json.checked, 2);
  assert.ok(lines.some((l) => l.includes('[admin] group lookup peers=2 hits=2')));
});

test('POST group/lookup：一路伙伴失败只记日志，其余命中照常返回', async () => {
  const net = makeNet({
    matches: [{ groupId: 'g-other', name: '家里' }],
    lookupThrows: ['http://10.0.0.3:7788'],
  });
  const { admin, lines } = stubAdmin({ groupNet: net });
  const out = await hit(admin, 'POST', '/api/lan-peers/group/lookup', { name: '家里' });
  assert.equal(out.json.matches.length, 1);
  assert.equal(out.json.checked, 2);
  assert.ok(lines.some((l) => l.includes('[admin] group lookup peer=peer-b failed')));
});

test('POST group/lookup：坏名字 400；Lane P 缺席 501', async () => {
  const { admin } = stubAdmin({ groupNet: makeNet() });
  const blank = await hit(admin, 'POST', '/api/lan-peers/group/lookup', { name: '' });
  assert.equal(blank.res.status, 400);
  assert.deepEqual(blank.json, { error: 'bad-name' });

  const unsupported = stubAdmin({ groupNet: { lookupGroupName: null, readKnownGroups: null } });
  const missing = await hit(unsupported.admin, 'POST', '/api/lan-peers/group/lookup', { name: '家里' });
  assert.equal(missing.res.status, 501);
  assert.equal(missing.json.error, 'lookup-unsupported');
});

// ---------------------------------------------------------------------------
// 契约 §4/§5：申请与状态（grant 绝不进浏览器）
// ---------------------------------------------------------------------------

test('POST group/apply：按冻结签名调 applyToGroup，申请者信息来自本机', async () => {
  const net = makeNet({ apply: () => ({ status: 'pending' }) });
  const { admin, lines } = stubAdmin({ groupNet: net });
  const out = await hit(admin, 'POST', '/api/lan-peers/group/apply', { groupId: 'g-other', introducer: 'peer-a' });
  assert.equal(out.res.status, 200);
  assert.deepEqual(out.json, { ok: true, status: 'pending', reason: null });
  assert.deepEqual(net.calls.apply, [{
    baseUrl: 'http://10.0.0.2:7788',
    secret: 'sec-a',
    senderId: 'peer-self',
    groupId: 'g-other',
    applicant: { peerId: 'peer-self', name: 'self-box', baseUrl: '' },
  }]);
  assert.ok(lines.some((l) => l.includes('[admin] group apply groupId=g-other status=pending')));
});

test('POST group/apply：缺参 400、介绍人未配对 404、Lane P 缺席 501、后端拒绝透传', async () => {
  const { admin } = stubAdmin({ groupNet: makeNet() });
  const missing = await hit(admin, 'POST', '/api/lan-peers/group/apply', { groupId: 'g-other' });
  assert.equal(missing.res.status, 400);

  const ghost = await hit(admin, 'POST', '/api/lan-peers/group/apply', { groupId: 'g-other', introducer: 'peer-ghost' });
  assert.equal(ghost.res.status, 404);

  const unsupported = stubAdmin({ groupNet: { applyToGroup: null } });
  const off = await hit(unsupported.admin, 'POST', '/api/lan-peers/group/apply', { groupId: 'g-other', introducer: 'peer-a' });
  assert.equal(off.res.status, 501, 'Lane P 缺席时如实回 501（而不是伪造一个申请）');

  const refusing = makeNet({
    apply: () => {
      const error = new Error('429 too many requests');
      throw error;
    },
  });
  const failed = await hit(stubAdmin({ groupNet: refusing }).admin, 'POST', '/api/lan-peers/group/apply', { groupId: 'g-other', introducer: 'peer-a' });
  assert.equal(failed.res.status, 429, 'callPeer 的 "429 ..." 形式要解析成状态码');
});

test('GET group/apply-status：只回状态，grant 交给接线点落盘且绝不上日志', async () => {
  const grant = {
    groupId: 'g-other',
    name: '家里',
    epoch: 3,
    keyVersion: 7,
    key: 'SECRET-GROUP-KEY-MUST-NOT-LEAK',
    hub: { peerId: 'peer-hub', name: 'hub-box', baseUrl: 'http://10.0.0.9:7788' },
    members: [{ peerId: 'peer-hub', name: 'hub-box' }, { peerId: 'peer-self', name: 'self-box' }],
  };
  const net = makeNet({ poll: () => ({ status: 'approved', grant }) });
  const applied = [];
  const { admin, lines } = stubAdmin({ groupNet: net, applyGrant: (g) => { applied.push(g); } });
  const out = await hit(admin, 'GET', '/api/lan-peers/group/apply-status?groupId=g-other&introducer=peer-a');
  assert.equal(out.res.status, 200);
  assert.deepEqual(out.json, { status: 'approved', reason: null });
  assert.equal(JSON.stringify(out.json).includes('SECRET-GROUP-KEY'), false, '群密钥绝不进浏览器');
  assert.equal(applied.length, 1, 'grant 交给接线点写 group-key.json');
  const log = lines.join('\n');
  assert.match(log, /group grant applied groupId=g-other keyVersion=7 members=2/);
  assert.doesNotMatch(log, /SECRET-GROUP-KEY/, '群密钥绝不进日志');
  assert.deepEqual(net.calls.poll, [{
    baseUrl: 'http://10.0.0.2:7788', secret: 'sec-a', senderId: 'peer-self', groupId: 'g-other',
  }]);
});

test('GET group/apply-status：没有注入也不带 stateDir 时 grant 直接丢弃（只留一行日志）', async () => {
  const net = makeNet({ poll: () => ({ status: 'approved', grant: { keyVersion: 2, key: 'SECRET-GROUP-KEY', members: [] } }) });
  const { admin, lines } = stubAdmin({ groupNet: net });
  const out = await hit(admin, 'GET', '/api/lan-peers/group/apply-status?groupId=g-other&introducer=peer-a');
  assert.deepEqual(out.json, { status: 'approved', reason: null });
  assert.ok(lines.some((l) => l.includes('group grant dropped groupId=g-other')));
  assert.doesNotMatch(lines.join('\n'), /SECRET-GROUP-KEY/);
});

test('GET group/apply-status：默认落盘口把 grant 写进 group-key.json（0600），响应里仍然没有群密钥', async () => {
  const stateDir = makeTempStateDir();
  const net = makeNet({
    poll: () => ({
      status: 'approved',
      grant: {
        groupId: 'g-other',
        name: '老家的群',
        keyVersion: 4,
        key: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        hub: { peerId: 'peer-a', name: 'nas-a', baseUrl: 'http://10.0.0.2:7788' },
        members: [{ peerId: 'peer-a', name: 'nas-a' }, { peerId: 'peer-self', name: 'self-box' }],
      },
    }),
  });
  const { admin, lines } = stubAdmin({ groupNet: net, stateDir });
  const out = await hit(admin, 'GET', '/api/lan-peers/group/apply-status?groupId=g-other&introducer=peer-a');
  assert.deepEqual(out.json, { status: 'approved', reason: null });
  assert.equal(JSON.stringify(out.json).includes('AAAAAAAAAAAAAAAAAAAA'), false, '群密钥绝不进浏览器');
  const keyFile = JSON.parse(fs.readFileSync(path.join(stateDir, 'group-key.json'), 'utf8'));
  assert.equal(keyFile.groupId, 'g-other');
  assert.equal(keyFile.epoch, 4);
  assert.deepEqual(Object.keys(keyFile.members).sort(), ['peer-a', 'peer-self']);
  assert.ok(lines.some((l) => l.includes('group grant applied groupId=g-other keyVersion=4 members=2')));
  assert.doesNotMatch(lines.join('\n'), /AAAAAA/);
});

test('GET group/apply-status：缺参 400、介绍人未配对 404、Lane P 缺席 501、rejected 带原因', async () => {
  const { admin } = stubAdmin({ groupNet: makeNet() });
  const missing = await hit(admin, 'GET', '/api/lan-peers/group/apply-status?groupId=g-other');
  assert.equal(missing.res.status, 400);
  const ghost = await hit(admin, 'GET', '/api/lan-peers/group/apply-status?groupId=g-other&introducer=peer-ghost');
  assert.equal(ghost.res.status, 404);
  const off = await hit(stubAdmin({ groupNet: { pollApplication: null } }).admin, 'GET', '/api/lan-peers/group/apply-status?groupId=g-other&introducer=peer-a');
  assert.equal(off.res.status, 501);

  const rejected = makeNet({ poll: () => ({ status: 'rejected', reason: 'blocked' }) });
  const out = await hit(stubAdmin({ groupNet: rejected }).admin, 'GET', '/api/lan-peers/group/apply-status?groupId=g-other&introducer=peer-a');
  assert.deepEqual(out.json, { status: 'rejected', reason: 'blocked' });
});

// ---------------------------------------------------------------------------
// 与面板同一口径：GET group 的 hub 形状带上 applications
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 契约 §8 + 按名入群：enabled 的语义 = 「群功能对本机是否有效」
// ---------------------------------------------------------------------------

test('config 关着但本机已按名入群（门面 local() 有 groupId）→ enabled:true + enabledSource:membership', async () => {
  const facade = {
    enabled: false,
    isHub: false,
    local: () => ({ node: 'member', groupId: 'g-key', leaderPeerId: 'peer-hub', members: {} }),
  };
  const { admin } = stubAdmin({ group: { enabled: false, hub: '' }, facade, api: null });
  const out = await hit(admin, 'GET', '/api/lan-peers/group?sinceSeq=0');
  assert.equal(out.res.status, 200);
  assert.equal(out.json.enabled, true, '成员身份让群功能对本机有效');
  assert.equal(out.json.enabledSource, 'membership');
  assert.equal(out.json.isHub, false);
  // hub 没配对：如实报错而不是假装没入群（启用判定已经成立这件事不变）
  assert.match(String(out.json.error), /hub peer not paired: peer-hub/);
});

test('成员身份只体现在 role().groupId 上也算数（host 两种口径都收）', async () => {
  const facade = {
    enabled: false,
    isHub: false,
    role: () => ({ role: 'follower', groupId: 'g-key', leaderPeerId: 'peer-hub' }),
  };
  const { admin } = stubAdmin({ group: { enabled: false, hub: '' }, facade, api: null });
  const out = await hit(admin, 'GET', '/api/lan-peers/group?sinceSeq=0');
  assert.equal(out.json.enabled, true);
  assert.equal(out.json.enabledSource, 'membership');
});

test('门面说有效但没有 hub 线索 → 200 + error:hub-unknown，不装作空群', async () => {
  const facade = { enabled: false, isHub: false, local: () => ({ node: 'member', groupId: 'g-key' }) };
  const { admin } = stubAdmin({ group: { enabled: false, hub: '' }, facade, api: null });
  const out = await hit(admin, 'GET', '/api/lan-peers/group?sinceSeq=0');
  assert.equal(out.json.enabled, true);
  assert.equal(out.json.enabledSource, 'membership');
  assert.equal(out.json.error, 'hub-unknown');
  assert.equal(out.json.group, null);
});

test('config 关着且门面认不出成员 → enabled:false，形状与 v0.7.4 一字不差', async () => {
  const facade = { enabled: false, isHub: false };
  const { admin } = stubAdmin({ group: { enabled: false, hub: '' }, facade, api: null });
  const out = await hit(admin, 'GET', '/api/lan-peers/group?sinceSeq=0');
  assert.equal(out.res.status, 200);
  assert.deepEqual(out.json, { enabled: false, isHub: false, group: null, messages: [], lastSeq: 0 });
  assert.deepEqual(Object.keys(out.json).sort(), ['enabled', 'group', 'isHub', 'lastSeq', 'messages'], '未启用分支不加新字段');
});

test('config 开着 → enabledSource:config（hub 与成员两侧都有）', async () => {
  const hubSide = await hit(stubAdmin({ api: makeHubApi() }).admin, 'GET', '/api/lan-peers/group?sinceSeq=0');
  assert.equal(hubSide.json.enabledSource, 'config');
  const memberSide = await hit(
    stubAdmin({ api: { ...makeHubApi(), isHub: false } }).admin,
    'GET',
    '/api/lan-peers/group?sinceSeq=0',
  );
  assert.equal(memberSide.json.enabledSource, 'config');
});

test('GET group（hub）：随群状态下发待批准申请，成员侧不带这个字段', async () => {
  const api = makeHubApi({ applications: APPLICATIONS });
  const { admin } = stubAdmin({ api });
  const hub = await hit(admin, 'GET', '/api/lan-peers/group?sinceSeq=0');
  assert.deepEqual(hub.json.applications, APPLICATIONS);

  const memberSide = stubAdmin({ api: { ...makeHubApi(), isHub: false } });
  const member = await hit(memberSide.admin, 'GET', '/api/lan-peers/group?sinceSeq=0');
  assert.equal('applications' in member.json, false, '成员侧形状不变');
});
