/**
 * v0.5.0 Phase1 · 群聊 hub 端点（契约 §1/§3/§4/§6）。
 *
 * 覆盖：未启用群 404、已配对但非成员 403 not-a-member、autoJoin 开关、
 *      post 的 kind/text/meta 校验与 413、seq 单调 + history sinceSeq/limit、
 *      逐帧加密门控、group.json 0600、保留策略与 5000 硬上限（假时钟）、
 *      /v1/group/events 逐帧可解密 + ping 帧、lib/group-client 端到端、§6 进度镜像。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { makeTempStateDir, peerFixture, request, seedPeers, startServer, writeJson0600 } from './helpers.mjs';
import { GroupStore } from '../server.mjs';
import { decryptBytes } from '../../lib/wire-crypto.mjs';
import {
  createGroupMirror,
  fetchGroupHistory,
  fetchGroupState,
  joinGroup,
  postGroup,
  readGroupEvents,
} from '../../lib/group-client.mjs';

const MEMBER = peerFixture('peer-group-1');
const OUTSIDER = peerFixture('peer-group-2');

/** 起一个开了群的 hub；peers.json 里预置一对「已配对」的伙伴 */
async function startHub(t, overrides = {}) {
  const stateDir = overrides.stateDir ?? makeTempStateDir();
  seedPeers(stateDir, [MEMBER, OUTSIDER]);
  // S3：majority 下 post 走 propose→commit，假 peerId 成员没有投票端点必然 503；
  // 这个文件测的是 v0.5 端点语义，固定 quorum:none（写本地即提交）。
  const group = { enabled: true, name: 'default', autoJoin: false, retentionDays: 7, quorum: 'none' };
  const started = await startServer(t, {
    stateDir,
    allowRemotePrompts: true,
    ...overrides,
    // overrides.group 只覆盖给出的字段，别把 quorum:none 顶掉
    group: { ...group, ...(overrides.group ?? {}) },
  });
  return started;
}

const asMember = (baseUrl, options = {}) => request(baseUrl, {
  peerId: MEMBER.peerId,
  secret: MEMBER.inboundSecret,
  ...options,
});

const postMessage = (baseUrl, body) => asMember(baseUrl, {
  method: 'POST',
  path: '/v1/group/post',
  body,
});

// ---------------------------------------------------------------------------
// §3 端点存在性 / 成员门控
// ---------------------------------------------------------------------------

test('§3 未启用群：/v1/group/* 五个端点一律 404（不暴露半成品能力）', async (t) => {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [MEMBER]);
  const { baseUrl } = await startServer(t, { stateDir, group: { enabled: false } });

  const attempts = [
    ['GET', '/v1/group/state'],
    ['POST', '/v1/group/join'],
    ['POST', '/v1/group/post'],
    ['GET', '/v1/group/history'],
    ['GET', '/v1/group/events'],
  ];
  for (const [method, apiPath] of attempts) {
    const res = await request(baseUrl, {
      method,
      path: apiPath,
      signed: false,
      body: method === 'POST' ? {} : undefined,
    });
    assert.equal(res.status, 404, method + ' ' + apiPath);
    assert.equal(res.json?.error, 'not-found');
  }
});

test('§3 已配对但不在群里：state/post/history/events 全部 403 not-a-member', async (t) => {
  const { baseUrl } = await startHub(t);

  const state = await request(baseUrl, { path: '/v1/group/state', peerId: OUTSIDER.peerId, secret: OUTSIDER.inboundSecret });
  assert.equal(state.status, 403);
  assert.equal(state.json.error, 'not-a-member');

  const posted = await request(baseUrl, {
    method: 'POST',
    path: '/v1/group/post',
    peerId: OUTSIDER.peerId,
    secret: OUTSIDER.inboundSecret,
    body: { kind: 'chat', text: 'sneak in' },
  });
  assert.equal(posted.status, 403);
  assert.equal(posted.json.error, 'not-a-member');

  const history = await request(baseUrl, { path: '/v1/group/history', peerId: OUTSIDER.peerId, secret: OUTSIDER.inboundSecret });
  assert.equal(history.status, 403);

  const events = await request(baseUrl, { path: '/v1/group/events', peerId: OUTSIDER.peerId, secret: OUTSIDER.inboundSecret });
  assert.equal(events.status, 403);
  assert.equal(events.json.error, 'not-a-member');
});

test('§3 join：autoJoin=false 一律 403；autoJoin=true 自助加入并下发 32B groupKey', async (t) => {
  const closed = await startHub(t);
  const refused = await asMember(closed.baseUrl, { method: 'POST', path: '/v1/group/join', body: {} });
  assert.equal(refused.status, 403);
  assert.equal(refused.json.error, 'not-a-member');
  // 被拒绝的 join 不该把任何人写进成员表（成员表里只有 hub 自己）
  assert.deepEqual(
    Object.keys(closed.server.group.state().members),
    [closed.server.store.instanceId],
    '拒绝 join 后成员表只该有 hub 自己',
  );

  const open = await startHub(t, {
    group: { enabled: true, name: 'default', autoJoin: true, retentionDays: 7 },
  });
  const joined = await asMember(open.baseUrl, { method: 'POST', path: '/v1/group/join', body: {} });
  assert.equal(joined.status, 200, joined.text);
  assert.match(joined.json.groupId, /^[0-9a-f-]{36}$/);
  assert.equal(joined.json.epoch, 1);
  // 幂等：再 join 一次仍是 200，成员表不重复
  const again = await asMember(open.baseUrl, { method: 'POST', path: '/v1/group/join', body: {} });
  assert.equal(again.status, 200);
  assert.equal(again.json.groupId, joined.json.groupId);

  const state = await asMember(open.baseUrl, { path: '/v1/group/state' });
  assert.equal(state.status, 200);
  assert.equal(state.json.epoch, state.json.keyVersion);
  assert.equal(Buffer.from(state.json.groupKey, 'base64url').length, 32, 'groupKey 必须是 32 字节');
  const ids = state.json.members.map((member) => member.peerId);
  assert.ok(ids.includes(MEMBER.peerId), '成员表里有自己');
  assert.ok(ids.includes(open.server.store.instanceId), 'hub 自己也是成员');
  const mine = state.json.members.find((member) => member.peerId === MEMBER.peerId);
  assert.equal(mine.online, true, '刚认证过的成员算在线');
  assert.equal(mine.name, MEMBER.name);
  assert.match(String(mine.joinedAt), /^\d{4}-\d{2}-\d{2}T/);
});

// ---------------------------------------------------------------------------
// §3 post / history
// ---------------------------------------------------------------------------

test('§3 post → 201 {seq,ts} 且 seq 单调；history 按 sinceSeq/limit 取最新一批', async (t) => {
  const { baseUrl, server } = await startHub(t, { group: { enabled: true, autoJoin: true } });
  await asMember(baseUrl, { method: 'POST', path: '/v1/group/join', body: {} });

  const first = await postMessage(baseUrl, { kind: 'chat', text: '第一条' });
  assert.equal(first.status, 201, first.text);
  assert.equal(first.json.seq, 1);
  assert.equal(typeof first.json.ts, 'number');

  const second = await postMessage(baseUrl, { kind: 'chat', text: '第二条' });
  assert.equal(second.json.seq, 2);
  const third = await postMessage(baseUrl, { kind: 'system', text: '第三条' });
  assert.equal(third.json.seq, 3);

  const all = await asMember(baseUrl, { path: '/v1/group/history' });
  assert.equal(all.status, 200);
  assert.equal(all.json.lastSeq, 3);
  assert.equal(all.json.epoch, 1);
  assert.deepEqual(all.json.messages.map((message) => message.seq), [1, 2, 3]);
  assert.deepEqual(all.json.messages[0].from, { peerId: MEMBER.peerId, name: MEMBER.name });
  assert.equal(all.json.messages[0].text, '第一条');

  const since = await asMember(baseUrl, { path: '/v1/group/history?sinceSeq=1' });
  assert.deepEqual(since.json.messages.map((message) => message.seq), [2, 3]);

  // limit 超过上限时保留最新的一批（客户端用 lastSeq 续传）
  const capped = await asMember(baseUrl, { path: '/v1/group/history?sinceSeq=0&limit=2' });
  assert.deepEqual(capped.json.messages.map((message) => message.seq), [2, 3]);
  const clampedHigh = await asMember(baseUrl, { path: '/v1/group/history?limit=99999' });
  assert.equal(clampedHigh.status, 200);
  assert.equal(clampedHigh.json.messages.length, 3);

  // 落盘形状：seq 不回退的来源是 lastSeq
  assert.equal(server.group.state().lastSeq, 3);
});

test('§3 post 校验：非法 kind 400、text 超 4000 → 413、meta 只留白名单字段', async (t) => {
  const { baseUrl } = await startHub(t, { group: { enabled: true, autoJoin: true } });
  await asMember(baseUrl, { method: 'POST', path: '/v1/group/join', body: {} });

  const badKind = await postMessage(baseUrl, { kind: 'shout', text: 'x' });
  assert.equal(badKind.status, 400);
  assert.equal(badKind.json.error, 'bad-request');

  const missingKind = await postMessage(baseUrl, { text: 'x' });
  assert.equal(missingKind.status, 400);

  const tooLong = await postMessage(baseUrl, { kind: 'chat', text: 'x'.repeat(4001) });
  assert.equal(tooLong.status, 413);
  assert.equal(tooLong.json.error, 'payload-too-large');
  // 超长不落盘（不截断、不静默改写）
  assert.equal((await asMember(baseUrl, { path: '/v1/group/history' })).json.messages.length, 0);

  const exact = await postMessage(baseUrl, { kind: 'chat', text: '中'.repeat(4000) });
  assert.equal(exact.status, 201, '正好 4000 字符必须放行');

  const meta = await postMessage(baseUrl, {
    kind: 'result',
    text: 'done/12ms/3字',
    meta: {
      peer: 'nas-box',
      sessionId: 's-1',
      phase: 'end',
      status: 'done',
      transport: 'sse',
      elapsedMs: 12,
      replyChars: 3,
      // 白名单外的一律丢弃
      prompt: '把这段原文偷偷存进群里',
      reply: '回复全文也不许留',
      nested: { a: 1 },
    },
  });
  assert.equal(meta.status, 201);
  const stored = (await asMember(baseUrl, { path: '/v1/group/history?sinceSeq=1' })).json.messages[0];
  assert.deepEqual(Object.keys(stored.meta).sort(), [
    'elapsedMs', 'peer', 'phase', 'replyChars', 'sessionId', 'status', 'transport',
  ]);
  assert.equal(stored.meta.elapsedMs, 12);
  assert.deepEqual(Object.keys(stored).sort(), ['from', 'kind', 'meta', 'seq', 'text', 'ts']);
});

test('§3 加密门控：未带 X-Peer-Enc → 400；带了 → 成员响应是 enc 信封且可解密', async (t) => {
  const { baseUrl } = await startHub(t, {
    requireEncryption: true,
    group: { enabled: true, autoJoin: true },
  });
  await asMember(baseUrl, { method: 'POST', path: '/v1/group/join', body: {}, encrypt: true });

  const plain = await asMember(baseUrl, { path: '/v1/group/state' });
  assert.equal(plain.status, 400);
  assert.equal(plain.json.error, 'encryption-required');

  const encrypted = await asMember(baseUrl, { path: '/v1/group/state', encrypt: true });
  assert.equal(encrypted.status, 200);
  // helpers 会自动解密：能读到 groupKey 就说明响应确实走了 enc 信封
  assert.match(encrypted.text, /^\{"enc":"v1","data":/);
  assert.equal(Buffer.from(encrypted.json.groupKey, 'base64url').length, 32);

  const posted = await asMember(baseUrl, {
    method: 'POST',
    path: '/v1/group/post',
    body: { kind: 'chat', text: '加密发帖' },
    encrypt: true,
  });
  assert.equal(posted.status, 201);
  assert.match(posted.text, /^\{"enc":"v1","data":/);
});

// ---------------------------------------------------------------------------
// §4 存储
// ---------------------------------------------------------------------------

test('§4 hub 首次初始化：group.json 0600、hub 自己是成员、管理视图不吐 groupKey', async (t) => {
  const lines = [];
  const { baseUrl, server, stateDir } = await startHub(t, {
    logger: (line) => lines.push(String(line)),
    group: { enabled: true, autoJoin: true, name: 'team' },
  });
  await asMember(baseUrl, { method: 'POST', path: '/v1/group/join', body: {} });
  await postMessage(baseUrl, { kind: 'chat', text: 'hi' });

  const groupFile = path.join(stateDir, 'group.json');
  // Windows 不支持 Unix 权限位（与既有 state.json/peers.json 断言同一套跳法）
  if (process.platform !== 'win32') assert.equal(fs.statSync(groupFile).mode & 0o777, 0o600, 'group.json 必须 0600');
  const raw = JSON.parse(fs.readFileSync(groupFile, 'utf8'));
  // S3 §5：group.json 追加 pending（未提交区，与 messages 分开存）
  // v0.8.0 契约 §7：追加 applications（入群申请，24 小时 TTL / 上限 100）
  // v0.8.0-β DESIGN §18：追加 archives（归档索引，上限 200 条；超限只告警不自动删）
  assert.deepEqual(Object.keys(raw).sort(), [
    // blocked：被移除的成员（自助 join 不得把 ta 加回来）
    'applications', 'archives', 'blocked', 'createdAt', 'groupId', 'key', 'keyVersion', 'lastSeq',
    'members', 'messages', 'name', 'pending',
  ]);
  assert.deepEqual(raw.archives, [], '没有任何归档时索引是空数组');
  assert.equal(Buffer.from(raw.key, 'base64url').length, 32);
  assert.equal(raw.name, 'team');
  assert.equal(raw.lastSeq, 1);

  // 管理/面板视图默认脱敏：groupKey 只经成员响应下发
  const view = server.group.state();
  assert.equal(view.groupKey, undefined);
  assert.equal(view.groupId, raw.groupId);
  assert.ok(server.group.members().some((member) => member.peerId === server.store.instanceId));

  // 日志：有 [group] 行，但绝不出现 groupKey / 任何密钥
  assert.ok(lines.some((line) => line.startsWith('[group] post kind=chat')), '群操作要留一行日志');
  for (const line of lines) {
    assert.ok(!line.includes(raw.key), '日志里不许出现 groupKey: ' + line);
    assert.ok(!line.includes(MEMBER.inboundSecret), '日志里不许出现 secret: ' + line);
  }
});

test('§4 seq 单调不回退 + retentionDays=0 清旧 + 5000 条硬上限（假时钟）', (t) => {
  const dir = makeTempStateDir();
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  let nowMs = 1_760_000_000_000;
  const clock = () => nowMs;

  // retentionDays=0：now 一前进，旧消息就该被 prune；seq 不回退也不复用
  const store = new GroupStore({ stateDir: dir, name: 'g', retentionDays: 0, owner: { peerId: 'hub', name: 'hub' }, now: clock });
  assert.equal(store.append({ peerId: 'p1', name: 'P1', kind: 'chat', text: 'a' }).seq, 1);
  nowMs += 1_000;
  assert.equal(store.append({ peerId: 'p1', name: 'P1', kind: 'chat', text: 'b' }).seq, 2);
  nowMs += 1_000;
  // 读的时候也 prune：两条都过期了
  assert.equal(store.messages({ sinceSeq: 0 }).length, 0);
  const state = store.state();
  assert.equal(state.lastSeq, 2, '删旧消息不回退 lastSeq');
  assert.equal(state.messages, undefined);
  // 新消息继续用更大的号（绝不复用已删的 1/2）
  assert.equal(store.append({ peerId: 'p1', name: 'P1', kind: 'chat', text: 'c' }).seq, 3);

  // 正常保留期：1 天内不删，超过 1 天删
  const dir7 = makeTempStateDir();
  t.after(() => fs.rmSync(dir7, { recursive: true, force: true }));
  let now7 = 1_760_000_000_000;
  const store7 = new GroupStore({ stateDir: dir7, name: 'g', retentionDays: 1, now: () => now7 });
  store7.append({ peerId: 'p1', name: 'P1', kind: 'chat', text: 'keep' });
  now7 += 23 * 3600 * 1000;
  assert.equal(store7.messages({}).length, 1, '1 天内保留');
  now7 += 2 * 3600 * 1000;
  assert.equal(store7.messages({}).length, 0, '超过 1 天清掉');
  assert.equal(store7.state().lastSeq, 1);

  // 5000 条硬上限：直接造 5000 条再追加，丢最旧、号继续递增
  const dirCap = makeTempStateDir();
  t.after(() => fs.rmSync(dirCap, { recursive: true, force: true }));
  const capNow = 1_760_000_000_000;
  const messages = Array.from({ length: 5000 }, (_, index) => ({
    seq: index + 1,
    ts: capNow,
    from: { peerId: 'p1', name: 'P1' },
    kind: 'chat',
    text: 'm' + (index + 1),
    meta: {},
  }));
  writeJson0600(path.join(dirCap, 'group.json'), {
    groupId: 'g-cap',
    name: 'g',
    createdAt: new Date(capNow).toISOString(),
    keyVersion: 1,
    key: randomBytes(32).toString('base64url'),
    lastSeq: 5000,
    members: {},
    messages,
  });
  const capStore = new GroupStore({ stateDir: dirCap, name: 'g', retentionDays: 7, now: () => capNow });
  assert.equal(capStore.messages({ sinceSeq: 0, limit: 200 }).length, 200);
  assert.equal(capStore.messages({ sinceSeq: 0, limit: 200 }).at(-1).seq, 5000);
  const appended = capStore.append({ peerId: 'p1', name: 'P1', kind: 'chat', text: 'm5001' });
  assert.equal(appended.seq, 5001, 'seq 继续递增');
  const kept = JSON.parse(fs.readFileSync(path.join(dirCap, 'group.json'), 'utf8')).messages;
  assert.equal(kept.length, 5000, '硬上限 5000 条');
  assert.equal(kept[0].seq, 2, '丢最旧的那条');
  assert.equal(kept.at(-1).seq, 5001);
});

// ---------------------------------------------------------------------------
// 显示名：同机/同型号撞名时，渲染层加短 id 后缀（group.json 原始 name 不动）
// ---------------------------------------------------------------------------

// 两个同型号机器的默认主机名，短 id 用 peerId 前 8 位
const SAME_1 = peerFixture('3c389892-1111-4a1b-8c2d-000000000001', { name: 'desk-alpha' });
const SAME_2 = peerFixture('aaaaaaaa-bbbb-4ccc-8ddd-000000000002', { name: 'desk-alpha' });

test('同名成员在 state / history / admin 门面里都能区分（渲染层加短 id，不改 group.json）', async (t) => {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [SAME_1, SAME_2]);
  const { baseUrl, server } = await startServer(t, {
    stateDir,
    allowRemotePrompts: true,
    // S3：假 peerId 成员没有投票端点 → 固定 quorum:none（与 startHub 同一口径）
    group: { enabled: true, autoJoin: true, quorum: 'none' },
  });

  const join = (peer) => request(baseUrl, {
    method: 'POST',
    path: '/v1/group/join',
    peerId: peer.peerId,
    secret: peer.inboundSecret,
    body: { name: 'desk-alpha' },
  });
  assert.equal((await join(SAME_1)).status, 200);
  assert.equal((await join(SAME_2)).status, 200);

  const post = (peer, text) => request(baseUrl, {
    method: 'POST',
    path: '/v1/group/post',
    peerId: peer.peerId,
    secret: peer.inboundSecret,
    body: { kind: 'chat', text },
  });
  assert.equal((await post(SAME_1, 'from-1')).status, 201);
  assert.equal((await post(SAME_2, 'from-2')).status, 201);

  // ① /v1/group/state 的成员表：两条同名 → 各自带自己的短 id
  const view = await request(baseUrl, {
    path: '/v1/group/state',
    peerId: SAME_1.peerId,
    secret: SAME_1.inboundSecret,
  });
  assert.equal(view.status, 200);
  const names = new Map(view.json.members.map((member) => [member.peerId, member.name]));
  assert.equal(names.get(SAME_1.peerId), 'desk-alpha (3c389892)');
  assert.equal(names.get(SAME_2.peerId), 'desk-alpha (aaaaaaaa)');
  // 展示名两两不同（hub 自己也可能就是同一个默认主机名，所以整体比较）
  const all = view.json.members.map((member) => member.name);
  assert.equal(new Set(all).size, all.length, '成员表里不该有无法区分的同名行');
  // 原始名单独留一份，面板可据此说明「这是同名的谁」
  assert.deepEqual(
    view.json.members
      .filter((member) => member.peerId === SAME_1.peerId || member.peerId === SAME_2.peerId)
      .map((member) => member.rawName),
    ['desk-alpha', 'desk-alpha'],
  );

  // ② history 的 from.name 同样是去重后的展示名
  const history = await request(baseUrl, {
    path: '/v1/group/history',
    peerId: SAME_1.peerId,
    secret: SAME_1.inboundSecret,
  });
  assert.deepEqual(history.json.messages.map((message) => message.from.name), [
    'desk-alpha (3c389892)',
    'desk-alpha (aaaaaaaa)',
  ]);
  assert.deepEqual(history.json.messages.map((message) => message.from.peerId), [SAME_1.peerId, SAME_2.peerId]);

  // ③ 面板/管理接口那条路径（server.group 门面）也是同一口径
  assert.deepEqual(
    server.group.history({ sinceSeq: 0, limit: 10 }).map((message) => message.from.name),
    ['desk-alpha (3c389892)', 'desk-alpha (aaaaaaaa)'],
  );
  assert.equal(
    server.group.members().find((member) => member.peerId === SAME_2.peerId).name,
    'desk-alpha (aaaaaaaa)',
  );

  // ④ 落盘的原始 name 没有被改写
  const raw = JSON.parse(fs.readFileSync(path.join(stateDir, 'group.json'), 'utf8'));
  assert.equal(raw.members[SAME_1.peerId].name, 'desk-alpha');
  assert.equal(raw.members[SAME_2.peerId].name, 'desk-alpha');
  assert.equal(raw.messages[0].from.name, 'desk-alpha');
});

test('join 的可选 name：只写自己那一条，重复 join = 本人改名；别人改不了', async (t) => {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [MEMBER, OUTSIDER]);
  const { baseUrl } = await startServer(t, {
    stateDir,
    allowRemotePrompts: true,
    group: { enabled: true, autoJoin: true },
  });
  const join = (peer, body) => request(baseUrl, {
    method: 'POST',
    path: '/v1/group/join',
    peerId: peer.peerId,
    secret: peer.inboundSecret,
    body,
  });

  const first = await join(MEMBER, { name: '同机节点A' });
  assert.equal(first.status, 200);
  assert.equal(first.json.name, '同机节点A');

  // 再 join 一次带新名字 = 改自己的显示名
  const renamed = await join(MEMBER, { name: '同机节点A2' });
  assert.equal(renamed.status, 200);
  assert.equal(renamed.json.name, '同机节点A2');

  // 不带 name 的 join 不会把已有名字抹掉
  assert.equal((await join(MEMBER, {})).json.name, '同机节点A2');

  // 试图用 body 里的 peerId 改别人：hub 只认 x-peer-id
  const spoof = await join(OUTSIDER, { name: '想改别人', peerId: MEMBER.peerId });
  assert.equal(spoof.status, 200);
  assert.equal(spoof.json.name, '想改别人');

  const state = await request(baseUrl, {
    path: '/v1/group/state',
    peerId: MEMBER.peerId,
    secret: MEMBER.inboundSecret,
  });
  const names = new Map(state.json.members.map((member) => [member.peerId, member.name]));
  assert.equal(names.get(MEMBER.peerId), '同机节点A2', '别人的 join 不能改到本机');
  assert.equal(names.get(OUTSIDER.peerId), '想改别人');

  // name 合法性：空串 / 超 64 / 非字符串 → 400
  assert.equal((await join(MEMBER, { name: '   ' })).status, 400);
  assert.equal((await join(MEMBER, { name: 'x'.repeat(65) })).status, 400);
  assert.equal((await join(MEMBER, { name: 123 })).status, 400);
});

// ---------------------------------------------------------------------------
// §3 SSE /v1/group/events
// ---------------------------------------------------------------------------

function signedGetHeaders(secret, peerId, apiPath) {
  const ts = String(Date.now());
  const nonce = randomBytes(16).toString('hex');
  const canonical = [
    'GET',
    apiPath,
    ts,
    nonce,
    createHash('sha256').update(Buffer.alloc(0)).digest('hex'),
  ].join('\n');
  return {
    'x-peer-id': peerId,
    'x-peer-ts': ts,
    'x-peer-nonce': nonce,
    'x-peer-sign': createHmac('sha256', Buffer.from(String(secret), 'utf8')).update(canonical, 'utf8').digest('base64url'),
  };
}

function parseFrame(block, secret) {
  let event = null;
  let raw = null;
  for (const line of block.split('\n')) {
    if (line.startsWith('event:')) event = line.slice(6).trim();
    else if (line.startsWith('data:')) raw = line.slice(5).trim();
  }
  if (!event || raw == null) return null;
  const envelope = JSON.parse(raw);
  assert.equal(envelope.enc, 'v1', '每一帧都必须是加密信封');
  // 解密失败会 throw —— 这行就是「逐帧可独立解密」的断言
  return { event, data: JSON.parse(decryptBytes(secret, envelope.data).toString('utf8')) };
}

async function readFrames(res, secret, { wantPing = false, timeoutMs = 4000 } = {}) {
  assert.equal(res.status, 200, 'SSE 应 200');
  assert.match(res.headers.get('content-type') ?? '', /text\/event-stream/);
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  const frames = [];
  let buffer = '';
  const deadline = Date.now() + timeoutMs;
  try {
    while (Date.now() < deadline) {
      const { value, done } = await Promise.race([
        reader.read(),
        sleep(Math.max(1, deadline - Date.now())).then(() => ({ done: true })),
      ]);
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let cut;
      while ((cut = buffer.indexOf('\n\n')) >= 0) {
        const parsed = parseFrame(buffer.slice(0, cut), secret);
        buffer = buffer.slice(cut + 2);
        if (parsed) frames.push(parsed);
      }
      if (wantPing && frames.some((frame) => frame.event === 'ping')) break;
    }
  } finally {
    try { await reader.cancel(); } catch {}
  }
  return frames;
}

test('§3 /v1/group/events：逐帧可解密、seq 递增、每 10s 有 ping 帧', async (t) => {
  const { baseUrl } = await startHub(t, {
    group: { enabled: true, autoJoin: true },
    // 只为本用例把节奏调快：默认 200ms 轮询 / 10s ping
    groupStream: { pollIntervalMs: 50, pingIntervalMs: 100 },
  });
  await asMember(baseUrl, { method: 'POST', path: '/v1/group/join', body: {} });
  await postMessage(baseUrl, { kind: 'chat', text: '历史里的旧消息' });

  const controller = new AbortController();
  t.after(() => controller.abort());
  const apiPath = '/v1/group/events?sinceSeq=0';
  const res = await fetch(new URL(apiPath, baseUrl), {
    headers: signedGetHeaders(MEMBER.inboundSecret, MEMBER.peerId, apiPath),
    signal: controller.signal,
  });

  // 流开着的时候再发一条：既验证「先补发历史」，也验证「轮询追加」
  const live = await postMessage(baseUrl, { kind: 'progress', meta: { phase: 'start', status: 'running' } });
  assert.equal(live.status, 201, live.text);

  const frames = await readFrames(res, MEMBER.inboundSecret, { wantPing: true });
  const messages = frames.filter((frame) => frame.event === 'message').map((frame) => frame.data);
  assert.ok(messages.length >= 2, '历史 + 新消息都要出现');
  assert.deepEqual(messages.map((message) => message.seq), messages.map((message) => message.seq).slice().sort((a, b) => a - b));
  assert.equal(messages[0].text, '历史里的旧消息');
  assert.equal(messages.at(-1).kind, 'progress');
  assert.ok(frames.some((frame) => frame.event === 'ping'), '要有 ping 心跳帧（带加密载荷）');

  // 断流后用 sinceSeq 续传：只补没见过的
  const tail = await fetch(new URL('/v1/group/events?sinceSeq=' + messages.at(-1).seq, baseUrl), {
    headers: signedGetHeaders(MEMBER.inboundSecret, MEMBER.peerId, '/v1/group/events?sinceSeq=' + messages.at(-1).seq),
    signal: controller.signal,
  });
  const resumed = await readFrames(tail, MEMBER.inboundSecret, { wantPing: true });
  assert.equal(resumed.filter((frame) => frame.event === 'message').length, 0, 'sinceSeq 之后没有新消息就该静默');
});

// ---------------------------------------------------------------------------
// lib/group-client.mjs（成员侧助手）
// ---------------------------------------------------------------------------

test('§3 lib/group-client：state/post/history/readGroupEvents 端到端（真 fetch）', async (t) => {
  const { baseUrl } = await startHub(t, {
    group: { enabled: true, autoJoin: true },
    groupStream: { pollIntervalMs: 50 },
  });
  const target = { baseUrl, secret: MEMBER.inboundSecret, senderId: MEMBER.peerId };

  const joined = await joinGroup(target);
  assert.equal(joined.epoch, 1);

  const state = await fetchGroupState(target);
  assert.equal(state.name, 'default');
  assert.equal(Buffer.from(state.groupKey, 'base64url').length, 32);
  assert.ok(state.members.some((member) => member.peerId === MEMBER.peerId));

  const sent = await postGroup({ ...target, kind: 'chat', text: '客户端发的' });
  assert.equal(sent.seq, 1);

  const page = await fetchGroupHistory({ ...target, sinceSeq: 0, limit: 10 });
  assert.equal(page.lastSeq, 1);
  assert.equal(page.messages[0].text, '客户端发的');

  // 先订阅再发：覆盖轮询追加路径（不是只吃补发的历史）
  const controller = new AbortController();
  const seen = [];
  const pending = readGroupEvents({
    ...target,
    sinceSeq: 1,
    signal: controller.signal,
    timeoutMs: 5000,
    onMessage: (message) => seen.push(message),
    onPing: () => {},
  });
  await sleep(120);
  const live = await postGroup({ ...target, kind: 'system', text: '边跑边发' });
  await sleep(400);
  controller.abort();
  const out = await pending;
  assert.equal(out.aborted, true);
  assert.deepEqual(seen.map((message) => message.seq), [live.seq]);
  assert.equal(out.lastSeq, live.seq);

  // untilSeq：拿到目标 seq 就正常收尾
  await postGroup({ ...target, kind: 'chat', text: 'stop-here' });
  const bounded = await readGroupEvents({ ...target, sinceSeq: live.seq, untilSeq: live.seq + 1, timeoutMs: 3000 });
  assert.equal(bounded.ok, true);
  assert.equal(bounded.lastSeq, live.seq + 1);
});

// ---------------------------------------------------------------------------
// §6 进度镜像
// ---------------------------------------------------------------------------

test('§6 进度镜像：start/finish 两条落进群，且不含 prompt 原文与回复全文', async (t) => {
  const hubState = makeTempStateDir();
  seedPeers(hubState, [MEMBER]);
  const { baseUrl: hubUrl, server: hub } = await startServer(t, {
    stateDir: hubState,
    allowRemotePrompts: true,
    // S3：镜像用例同样固定 quorum:none（写本地即提交，与 v0.5 语义一致）
    group: { enabled: true, autoJoin: true, quorum: 'none' },
  });
  hub.group.addMember(MEMBER.peerId, MEMBER.name);

  // 成员侧 state-dir：identity + 到 hub 的配对记录（hub 用 MEMBER.inboundSecret 验签）
  const memberDir = makeTempStateDir();
  t.after(() => fs.rmSync(memberDir, { recursive: true, force: true }));
  writeJson0600(path.join(memberDir, 'state.json'), {
    instanceId: MEMBER.peerId,
    name: MEMBER.name,
    createdAt: new Date().toISOString(),
  });
  writeJson0600(path.join(memberDir, 'peers.json'), {
    peers: {
      [hub.store.instanceId]: {
        name: 'hub',
        baseUrl: hubUrl,
        secret: MEMBER.inboundSecret,
        inboundSecret: 'unused',
        addedAt: new Date().toISOString(),
        lastSeen: null,
      },
    },
  });

  const logged = [];
  const mirror = createGroupMirror({
    config: { stateDir: memberDir, group: { enabled: true, hub: 'hub' } },
    peers: [{ peerId: hub.store.instanceId, name: 'hub', baseUrl: hubUrl, secret: MEMBER.inboundSecret }],
    self: { instanceId: MEMBER.peerId, name: MEMBER.name },
    log: (line) => logged.push(String(line)),
  });
  assert.equal(mirror.enabled, true, 'group.enabled 且配了 hub 才启用镜像');
  assert.equal(mirror.hub.name, 'hub');

  const started = await mirror.start({ peer: 'nas-box', sessionId: 'session-1' });
  assert.equal(started.ok, true);
  const finished = await mirror.finish({
    peer: 'nas-box',
    sessionId: 'session-1',
    status: 'done',
    transport: 'sse',
    elapsedMs: 1227,
    replyChars: 142,
  });
  assert.equal(finished.ok, true);

  const messages = hub.group.history({ sinceSeq: 0, limit: 10 });
  assert.deepEqual(messages.map((message) => message.kind), ['progress', 'result']);
  assert.deepEqual(messages[0].meta, { peer: 'nas-box', sessionId: 'session-1', phase: 'start', status: 'running' });
  assert.equal(messages[0].text, '', '开始那条不带 text');
  assert.equal(messages[1].text, 'done/1227ms/142字');
  assert.deepEqual(messages[1].meta, {
    peer: 'nas-box',
    sessionId: 'session-1',
    status: 'done',
    transport: 'sse',
    elapsedMs: 1227,
    replyChars: 142,
  });
  // 契约 §6：绝不发 prompt 原文与回复全文 —— 两条消息的正文里都没有它们
  const serialized = JSON.stringify(messages);
  assert.ok(!serialized.includes('把这段原文'), '不能出现 prompt 原文');
  assert.equal(logged.length, 0, '成功时不该有失败日志');

  // 投递失败只记日志，不抛：未知 hub → 不启用；不可达 hub → {ok:false} + 一行日志
  const unconfigured = createGroupMirror({
    config: { group: { enabled: true, hub: 'nobody' } },
    peers: [],
    self: { instanceId: MEMBER.peerId },
    log: (line) => logged.push(String(line)),
  });
  assert.equal(unconfigured.enabled, false);
  assert.equal((await unconfigured.start({ peer: 'x', sessionId: 'y' })).ok, false);
  assert.equal((await unconfigured.finish({ peer: 'x', sessionId: 'y', status: 'done', elapsedMs: 1 })).ok, false);

  const failing = createGroupMirror({
    config: { group: { enabled: true, hub: 'dead' } },
    peers: [{ peerId: 'dead', name: 'dead', baseUrl: 'http://127.0.0.1:1', secret: 'S' }],
    self: { instanceId: MEMBER.peerId },
    log: (line) => logged.push(String(line)),
    timeoutMs: 500,
  });
  assert.equal(failing.enabled, true);
  const failed = await failing.finish({ peer: 'x', sessionId: 'y', status: 'error', elapsedMs: 5, replyChars: 0 });
  assert.equal(failed.ok, false);
  assert.equal(logged.length, 1, '失败只记一行日志');
  assert.match(logged[0], /^\[group\] mirror failed kind=result: /);
});

// ---------------------------------------------------------------------------
// 路由细节
// ---------------------------------------------------------------------------

test('§3 未知的 /v1/group/* → 404；已知路径用错方法 → 405', async (t) => {
  const { baseUrl } = await startHub(t);

  const unknown = await asMember(baseUrl, { path: '/v1/group/nope' });
  assert.equal(unknown.status, 404);
  assert.equal(unknown.json.error, 'not-found');

  const wrongMethod = await asMember(baseUrl, { method: 'POST', path: '/v1/group/state', body: {} });
  assert.equal(wrongMethod.status, 405);
  assert.equal(wrongMethod.json.error, 'method-not-allowed');

  const getPost = await asMember(baseUrl, { path: '/v1/group/post' });
  assert.equal(getPost.status, 405);

  // /v1/health 宣告 group（老对端忽略）
  const health = await request(baseUrl, { path: '/v1/health', signed: false });
  assert.ok(health.json.capability.includes('group'));
});
