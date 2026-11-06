/**
 * 0.8.5-α 契约 §1–§4：连续会话 + 私聊存储 + 两端对齐 + 门面。
 *
 * 覆盖三层：
 *   1. runner（lib/runner-dsh.mjs）的 sessionId 续聊/回退 —— 注入 fetch，不起 DSH；
 *   2. /v1/ask 与 /v1/dm/sync 的 HTTP 语义（真监听、真签名、真信封）；
 *   3. 门面 server.dm.*（list / send / sync）端到端，含「两个真进程」的连续会话演示。
 *
 * 铁律断言：私聊正文不进日志、不进群历史（marker 口径）。
 */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { pathToFileURL } from 'node:url';

import { DmStore, DM_MAX_PER_PAIR, DM_TTL_MS, dmFileName, flipSide } from '../../lib/dm-store.mjs';
import { createDshRunner } from '../../lib/runner-dsh.mjs';
import { createRunner } from '../server.mjs';
import {
  makeTempStateDir,
  peerFixture,
  pollAnswer,
  request,
  seedPeers,
  startServer,
} from './helpers.mjs';

const PEER = peerFixture('peer-1');

/** 同一进程里若干节点互相成为对端（跳过配对；seedPeers 整文件覆盖，故一次写完） */
function linkAll(nodes) {
  const keyOf = (from, to) => 'key-' + from.server.store.instanceId.slice(0, 8)
    + '-' + to.server.store.instanceId.slice(0, 8);
  for (const node of nodes) {
    const peers = nodes
      .filter((other) => other !== node)
      .map((other) => peerFixture(other.server.store.instanceId, {
        name: 'node-' + other.server.store.instanceId.slice(0, 4),
        secret: keyOf(node, other),
        inboundSecret: keyOf(other, node),
        baseUrl: other.baseUrl,
      }));
    if (peers.length > 0) seedPeers(node.stateDir, peers);
  }
  return { key: (from, to) => keyOf(from, to) };
}

function dmDir(stateDir) {
  return path.join(stateDir, 'dm');
}

// ---------------------------------------------------------------------------
// §1 runner：给了 sessionId 就续聊，失效就回退新建
// ---------------------------------------------------------------------------

/** 假 DSH：只实现本 runner 用到的那几个方法，并记录每一次 RPC */
function fakeDsh() {
  const calls = [];
  const sessions = new Map();
  let sequence = 0;
  const jsonResponse = (value) => new Response(JSON.stringify(value), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
  const fetchImpl = async (url, init = {}) => {
    const target = new URL(String(url));
    if (target.pathname === '/' && target.searchParams.has('token')) {
      return new Response('', { status: 200, headers: { 'set-cookie': 'dsh=token-abc; Path=/' } });
    }
    const rpc = JSON.parse(String(init.body ?? '{}'));
    calls.push(rpc.method);
    const requestBody = rpc.payload?.args?.request ?? {};
    if (rpc.method === 'session/create') {
      sequence += 1;
      const sessionId = 'dsh-' + sequence;
      sessions.set(sessionId, []);
      return jsonResponse({ result: { ok: true, value: { sessionId } } });
    }
    if (rpc.method === 'session/prompt') {
      const turns = sessions.get(requestBody.sessionId);
      if (!turns) {
        return jsonResponse({
          result: { ok: false, error: { code: 'session-not-found', message: 'no such session' } },
        });
      }
      turns.push(requestBody.content?.[0]?.text ?? '');
      return jsonResponse({ result: { ok: true, value: { accepted: true } } });
    }
    return jsonResponse({ result: { ok: false, error: { code: 'unsupported', message: rpc.method } } });
  };
  return { calls, sessions, fetchImpl };
}

function tokenFileIn(dir) {
  const file = path.join(dir, 'dsh-web.token');
  fs.writeFileSync(file, 'token-abc\n', { mode: 0o600 });
  return file;
}

test('§1 runner：给了 sessionId 在既有会话上续聊（reused:true），不新建会话', async () => {
  const dir = makeTempStateDir();
  const dsh = fakeDsh();
  const runner = createDshRunner({
    baseUrl: 'http://127.0.0.1:1',
    tokenFile: tokenFileIn(dir),
    workspace: dir,
    fetchImpl: dsh.fetchImpl,
    now: () => 1,
  });

  const first = await runner.ask('第一轮：我叫你小助手');
  assert.deepEqual(first, { sessionId: 'dsh-1', reused: false });
  const second = await runner.ask('第二轮：我刚才让你叫什么？', { sessionId: first.sessionId });
  assert.deepEqual(second, { sessionId: 'dsh-1', reused: true });
  // 两轮都落在同一个 DSH 会话里
  assert.deepEqual(dsh.sessions.get('dsh-1'), ['第一轮：我叫你小助手', '第二轮：我刚才让你叫什么？']);
  assert.equal(dsh.calls.filter((method) => method === 'session/create').length, 1);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('§1 runner：sessionId 失效 → 回退新建并标 reused:false', async () => {
  const dir = makeTempStateDir();
  const dsh = fakeDsh();
  const runner = createDshRunner({
    baseUrl: 'http://127.0.0.1:1',
    tokenFile: tokenFileIn(dir),
    workspace: dir,
    fetchImpl: dsh.fetchImpl,
    now: () => 1,
  });

  const out = await runner.ask('用已经被删掉的会话', { sessionId: 'dsh-deleted' });
  assert.equal(out.reused, false);
  assert.notEqual(out.sessionId, 'dsh-deleted');
  assert.equal(dsh.calls.filter((method) => method === 'session/create').length, 1);
  fs.rmSync(dir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// §1 /v1/ask：sessionId 可选，旧客户端行为不变
// ---------------------------------------------------------------------------

test('§1 /v1/ask 不带 sessionId（旧客户端）：每次新会话，响应多出 reused:false 与 dmSessionId', async (t) => {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [PEER]);
  const runner = createRunner({ delayMs: 5 });
  const { baseUrl } = await startServer(t, { stateDir, runner, allowRemotePrompts: true });

  const res = await request(baseUrl, {
    method: 'POST',
    path: '/v1/ask',
    peerId: PEER.peerId,
    secret: PEER.inboundSecret,
    body: { requestId: 'r1', prompt: 'hello' },
  });
  assert.equal(res.status, 202);
  assert.equal(res.json.reused, false);
  // sessionId 仍是 /v1/answer 的协议会话 id：旧客户端的取答复路径一个字都不用改
  assert.equal(typeof res.json.sessionId, 'string');
  assert.ok(res.json.sessionId.length > 0);
  assert.ok(String(res.json.dmSessionId).startsWith('mem-'));

  const done = await pollAnswer(baseUrl, {
    sessionId: res.json.sessionId,
    peerId: PEER.peerId,
    secret: PEER.inboundSecret,
  });
  assert.equal(done.status, 'done');
  assert.equal(done.reply, 'OK hello');
  assert.equal(runner.sessions.size, 1);
});

test('§1 /v1/ask 带 sessionId：续聊同一 DSH 会话（reused:true、dmSessionId 不变、协议会话仍是新的）', async (t) => {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [PEER]);
  const runner = createRunner({ delayMs: 5 });
  const { baseUrl } = await startServer(t, { stateDir, runner, allowRemotePrompts: true });
  const ask = (requestId, prompt, sessionId) => request(baseUrl, {
    method: 'POST',
    path: '/v1/ask',
    peerId: PEER.peerId,
    secret: PEER.inboundSecret,
    body: { requestId, prompt, ...(sessionId === undefined ? {} : { sessionId }) },
  });

  const first = await ask('r1', '我叫你小助手');
  assert.equal(first.status, 202);
  const second = await ask('r2', '我刚才让你叫什么？', first.json.dmSessionId);
  assert.equal(second.status, 202);
  assert.equal(second.json.reused, true);
  assert.equal(second.json.dmSessionId, first.json.dmSessionId, '两轮必须落在同一个 DSH 会话');
  assert.notEqual(second.json.sessionId, first.json.sessionId, '协议会话每次都是新的');
  // 续聊不新建 DSH 会话
  assert.equal(runner.sessions.size, 1);
  assert.equal(runner.sessions.get(first.json.dmSessionId).turns, 2);

  const done = await pollAnswer(baseUrl, {
    sessionId: second.json.sessionId,
    peerId: PEER.peerId,
    secret: PEER.inboundSecret,
  });
  assert.equal(done.status, 'done');
  assert.equal(done.reply, 'OK 我刚才让你叫什么？');
});

test('§1 /v1/ask 带失效 sessionId：回退新建，reused:false 且 dmSessionId 换新', async (t) => {
  const stateDir = makeTempStateDir();
  seedPeers(stateDir, [PEER]);
  const runner = createRunner({ delayMs: 5 });
  const { baseUrl } = await startServer(t, { stateDir, runner, allowRemotePrompts: true });

  const res = await request(baseUrl, {
    method: 'POST',
    path: '/v1/ask',
    peerId: PEER.peerId,
    secret: PEER.inboundSecret,
    body: { requestId: 'r1', prompt: 'hi', sessionId: 'mem-999-does-not-exist' },
  });
  assert.equal(res.status, 202);
  assert.equal(res.json.reused, false);
  assert.notEqual(res.json.dmSessionId, 'mem-999-does-not-exist');
  assert.equal(runner.sessions.size, 1);
});

test('§1 别的对端不能续聊不属于它的 DSH 会话（按失效处理）', async (t) => {
  const stateDir = makeTempStateDir();
  const other = peerFixture('peer-2');
  seedPeers(stateDir, [PEER, other]);
  const runner = createRunner({ delayMs: 5 });
  const { baseUrl } = await startServer(t, { stateDir, runner, allowRemotePrompts: true });

  const mine = await request(baseUrl, {
    method: 'POST',
    path: '/v1/ask',
    peerId: PEER.peerId,
    secret: PEER.inboundSecret,
    body: { requestId: 'r1', prompt: '我的会话' },
  });
  const stolen = await request(baseUrl, {
    method: 'POST',
    path: '/v1/ask',
    peerId: other.peerId,
    secret: other.inboundSecret,
    body: { requestId: 'r2', prompt: '续别人的会话', sessionId: mine.json.dmSessionId },
  });
  assert.equal(stolen.status, 202);
  assert.equal(stolen.json.reused, false, '跨 peer 的 sessionId 一律回退新建');
  assert.notEqual(stolen.json.dmSessionId, mine.json.dmSessionId);
  assert.equal(runner.sessions.size, 2);
});

// ---------------------------------------------------------------------------
// §2 dm-store：去重 / 上限 / TTL / 升序 / 0600
// ---------------------------------------------------------------------------

test('§2 dm-store：同 id 只留一条（去重），update 走追加但读取取最后一行', () => {
  const stateDir = makeTempStateDir();
  const store = new DmStore({ stateDir, now: () => 1_000 });
  const entry = { id: 'm-1', ts: 10, from: 'self', text: '你好', sessionId: 's-1', state: 'pending' };

  assert.equal(store.append('peer-1', entry).added, true);
  const again = store.append('peer-1', entry);
  assert.equal(again.added, false);
  assert.equal(again.reason, 'duplicate');
  assert.equal(store.count('peer-1'), 1);

  assert.equal(store.update('peer-1', 'm-1', { state: 'sent' }).ok, true);
  const list = store.list('peer-1');
  assert.equal(list.length, 1);
  assert.equal(list[0].state, 'sent');
  assert.equal(list[0].text, '你好');

  // 重启后仍是同一个视图（去重语义落在文件行上，不是内存里）
  const reopened = new DmStore({ stateDir, now: () => 1_000 });
  assert.deepEqual(reopened.list('peer-1'), store.list('peer-1'));
  assert.equal(fs.readFileSync(store.file('peer-1'), 'utf8').trim().split('\n').length, 2);
  fs.rmSync(stateDir, { recursive: true, force: true });
});

test('§2 dm-store：每对 2000 条上限（可注入更小值验证裁剪保留最新）', () => {
  const stateDir = makeTempStateDir();
  const store = new DmStore({ stateDir, now: () => 1_000, maxPerPeer: 5 });
  for (let index = 0; index < 10; index += 1) {
    store.append('peer-1', { id: 'm-' + index, ts: index + 1, from: 'self', text: '第 ' + index + ' 条' });
  }
  const list = store.list('peer-1');
  assert.equal(list.length, 5);
  assert.deepEqual(list.map((entry) => entry.id), ['m-5', 'm-6', 'm-7', 'm-8', 'm-9']);
  // 文件也真裁了，不是只在读的时候截断
  const lines = fs.readFileSync(store.file('peer-1'), 'utf8').trim().split('\n');
  assert.equal(lines.length, 5);
  assert.equal(DM_MAX_PER_PAIR, 2000);
  fs.rmSync(stateDir, { recursive: true, force: true });
});

test('§2 dm-store：7 天 TTL —— 过期条目读不到，下次写入时从文件里裁掉', () => {
  const stateDir = makeTempStateDir();
  const clock = { now: 1_000_000 };
  const store = new DmStore({ stateDir, now: () => clock.now });
  store.append('peer-1', { id: 'old', ts: clock.now, from: 'self', text: '七天前的' });
  clock.now += DM_TTL_MS - 1;
  store.append('peer-1', { id: 'fresh', ts: clock.now, from: 'self', text: '新的' });
  assert.deepEqual(store.list('peer-1').map((entry) => entry.id), ['old', 'fresh']);

  clock.now += 2; // 越过 TTL
  assert.deepEqual(store.list('peer-1').map((entry) => entry.id), ['fresh']);
  store.append('peer-1', { id: 'newer', ts: clock.now, from: 'self', text: '更新的' });
  const lines = fs.readFileSync(store.file('peer-1'), 'utf8').trim().split('\n');
  assert.equal(lines.length, 2, '过期条目在写路径被裁掉');
  fs.rmSync(stateDir, { recursive: true, force: true });
});

test('§2 dm-store：乱序写入仍按 ts 升序返回；merge 会翻面 from 并跳过坏条目', () => {
  const stateDir = makeTempStateDir();
  const store = new DmStore({ stateDir, now: () => 10_000_000 });
  store.append('peer-9', { id: 'c', ts: 300, from: 'self', text: '3' });
  store.append('peer-9', { id: 'a', ts: 100, from: 'self', text: '1' });
  store.append('peer-9', { id: 'b', ts: 200, from: 'peer', text: '2' });
  assert.deepEqual(store.list('peer-9').map((entry) => entry.id), ['a', 'b', 'c']);

  const merged = store.merge('peer-9', [
    // 对端的 self 在本机是 peer —— 不翻面的话气泡会左右颠倒
    { id: 'd', ts: 400, from: 'self', text: '对面说的' },
    { id: 'e', ts: 500, from: 'peer', text: '对面记的我的话' },
    { id: 'a', ts: 100, from: 'self', text: '重复 id' },
    { id: '', ts: 600, from: 'self', text: '坏条目' },
    { id: 'f', ts: Number.NaN, from: 'self', text: '坏 ts' },
  ]);
  assert.equal(merged.added, 2);
  assert.equal(merged.skipped, 2);
  const list = store.list('peer-9');
  assert.equal(list.find((entry) => entry.id === 'd').from, 'peer');
  assert.equal(list.find((entry) => entry.id === 'e').from, 'self');
  assert.equal(list.find((entry) => entry.id === 'a').text, '1', '重复 id 不覆盖已有条目');
  assert.equal(flipSide('self'), 'peer');
  assert.equal(flipSide('peer'), 'self');
  fs.rmSync(stateDir, { recursive: true, force: true });
});

test('§2 dm-store：文件 0600、目录 dm/、peerId 不进路径（非安全字符走摘要名）', () => {
  const stateDir = makeTempStateDir();
  const store = new DmStore({ stateDir, now: () => 1_000 });
  store.append('peer-1', { id: 'm-1', ts: 1, from: 'self', text: 'x' });
  assert.equal(path.dirname(store.file('peer-1')), dmDir(stateDir));
  assert.equal(path.basename(store.file('peer-1')), 'peer-1.jsonl');
  if (process.platform !== 'win32') {
    assert.equal(fs.statSync(store.file('peer-1')).mode & 0o777, 0o600, '私聊文件必须 0600');
  }
  // 带路径分隔符/上跳的 peerId 不能拼出目录成分
  const nasty = '../../etc/passwd';
  assert.equal(dmFileName(nasty).includes('/'), false);
  store.append(nasty, { id: 'm-2', ts: 1, from: 'self', text: 'y' });
  assert.equal(path.dirname(store.file(nasty)), dmDir(stateDir));
  fs.rmSync(stateDir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// §3 /v1/dm/sync
// ---------------------------------------------------------------------------

test('§3 /v1/dm/sync 未配对：无签名与未知对端一律 401，且不落任何文件', async (t) => {
  const { baseUrl, stateDir } = await startServer(t);

  const anonymous = await request(baseUrl, {
    method: 'POST',
    path: '/v1/dm/sync',
    signed: false,
    body: { messages: [] },
  });
  assert.equal(anonymous.status, 401);

  const stranger = await request(baseUrl, {
    method: 'POST',
    path: '/v1/dm/sync',
    peerId: 'peer-x',
    secret: 'whatever',
    encrypt: true,
    body: { messages: [{ id: 'm-1', ts: 1, from: 'self', text: 'hi' }] },
  });
  assert.equal(stranger.status, 401);
  const files = fs.existsSync(path.join(stateDir, 'dm')) ? fs.readdirSync(path.join(stateDir, 'dm')) : [];
  assert.deepEqual(files, [], '未配对的请求不落盘');

  // 已知路径用错方法 → 405（不是 404）
  const wrongMethod = await request(baseUrl, { path: '/v1/dm/sync', signed: false });
  assert.equal(wrongMethod.status, 405);
});

test('§3 /v1/dm/sync 双向补齐：一次往返两端 id 集合完全一致，重复同步是幂等的', async (t) => {
  const a = await startServer(t);
  const b = await startServer(t);
  const keys = linkAll([a, b]);
  const aId = a.server.store.instanceId;
  const bId = b.server.store.instanceId;

  // ts 用真实时钟：DmStore 的 7 天 TTL 会立刻裁掉 1970 年的假时间戳
  const now = Date.now();
  a.server.dm.store().append(bId, { id: 'a-1', ts: now, from: 'self', text: 'A 的第一条' });
  b.server.dm.store().append(aId, { id: 'b-1', ts: now + 1, from: 'self', text: 'B 的第一条' });

  const synced = await a.server.dm.sync(bId);
  assert.deepEqual(synced, { ok: true, added: 1, total: 2 });
  assert.deepEqual(a.server.dm.list(bId).map((entry) => entry.id), ['a-1', 'b-1']);
  // 一次往返就把两边都补齐了（A 发出自己的，收回 B 缺的；B 在服务端已经 merge）
  assert.deepEqual(b.server.dm.list(aId).map((entry) => entry.id), ['a-1', 'b-1']);
  assert.deepEqual(
    new Set(a.server.dm.list(bId).map((entry) => entry.id)),
    new Set(b.server.dm.list(aId).map((entry) => entry.id)),
  );
  // 翻面证据：A 眼里 b-1 是对端说的
  assert.equal(a.server.dm.list(bId).find((entry) => entry.id === 'b-1').from, 'peer');

  // 再来一次：没有任何新增
  assert.deepEqual(await a.server.dm.sync(bId), { ok: true, added: 0, total: 2 });

  // 底层端点：响应带 have（本机视角最新 ts）与「对方缺的那部分」
  const raw = await request(b.baseUrl, {
    method: 'POST',
    path: '/v1/dm/sync',
    peerId: aId,
    secret: keys.key(a, b),
    encrypt: true,
    body: { peerId: aId, messages: [{ id: 'a-2', ts: now + 2, from: 'self', text: 'A 的第二条' }] },
  });
  assert.equal(raw.status, 200);
  assert.equal(raw.json.ok, true);
  assert.equal(raw.json.have, now + 2);
  assert.deepEqual(raw.json.messages.map((entry) => entry.id).sort(), ['a-1', 'b-1']);
});

// ---------------------------------------------------------------------------
// §4 门面：list / send / sync
// ---------------------------------------------------------------------------

test('§4 dm.send 端到端：写入本地 → 1:1 ask → 回复落盘；第二轮续聊同一 DSH 会话', async (t) => {
  const a = await startServer(t, { allowRemotePrompts: true });
  const b = await startServer(t, { allowRemotePrompts: true, runner: createRunner({ delayMs: 5 }) });
  linkAll([a, b]);
  const bId = b.server.store.instanceId;

  const first = await a.server.dm.send({ peerId: bId, text: '我叫你小助手' });
  assert.equal(first.ok, true, JSON.stringify(first));
  assert.equal(first.reused, false);
  assert.equal(first.reply, 'OK 我叫你小助手');
  assert.ok(Number.isFinite(first.elapsedMs));
  assert.ok(String(first.sessionId).startsWith('mem-'));

  const second = await a.server.dm.send({ peerId: bId, text: '我刚才让你叫什么？' });
  assert.equal(second.ok, true, JSON.stringify(second));
  assert.equal(second.reused, true, '第二轮必须续上第一轮的 DSH 会话');
  assert.equal(second.sessionId, first.sessionId);
  assert.equal(second.reply, 'OK 我刚才让你叫什么？');

  // 本地四条：自己/对方交替，按 ts 升序，且都挂在同一个连续会话上
  const list = a.server.dm.list(bId);
  assert.equal(list.length, 4);
  assert.deepEqual(list.map((entry) => entry.from), ['self', 'peer', 'self', 'peer']);
  assert.deepEqual(list.map((entry) => entry.state), ['sent', 'sent', 'sent', 'sent']);
  assert.deepEqual(list.map((entry) => entry.text), [
    '我叫你小助手',
    'OK 我叫你小助手',
    '我刚才让你叫什么？',
    'OK 我刚才让你叫什么？',
  ]);
  for (const entry of list) assert.equal(entry.sessionId, first.sessionId);
  for (let index = 1; index < list.length; index += 1) assert.ok(list[index].ts >= list[index - 1].ts);

  // 对端本地本来只有它自己的这条路径产生的记录？—— 没有：对端不写私聊存储，
  // 它的副本来自 /v1/dm/sync（契约 §2「两端各存一份，按 id 对齐」）
  assert.equal(b.server.dm.list(a.server.store.instanceId).length, 0);
  const synced = await a.server.dm.sync(bId);
  assert.equal(synced.ok, true);
  assert.equal(synced.total, 4);
  assert.deepEqual(
    b.server.dm.list(a.server.store.instanceId).map((entry) => entry.id),
    a.server.dm.list(bId).map((entry) => entry.id),
  );
  // 翻面证据：A 说的两轮，在 B 眼里都是 from:'peer'
  assert.deepEqual(
    b.server.dm.list(a.server.store.instanceId).map((entry) => entry.from),
    ['peer', 'self', 'peer', 'self'],
  );
});

test('§4 dm.send 失败面：未配对 / 空正文 / 目标不可达 —— 只回 { ok:false, reason }，本地留痕', async (t) => {
  const a = await startServer(t);
  assert.deepEqual(await a.server.dm.send({ peerId: '', text: 'x' }), { ok: false, reason: 'bad-peer' });
  assert.deepEqual(await a.server.dm.send({ peerId: 'peer-1', text: 'x' }), { ok: false, reason: 'unpaired' });

  const b = await startServer(t);
  // 配对但地址不可达（127.0.0.1:9 是 fetch 的坏端口之一，必然连不上）
  seedPeers(a.stateDir, [peerFixture(b.server.store.instanceId, { baseUrl: 'http://127.0.0.1:9' })]);
  seedPeers(b.stateDir, [peerFixture(a.server.store.instanceId, { baseUrl: 'http://127.0.0.1:9' })]);
  const unreachable = await a.server.dm.send({ peerId: b.server.store.instanceId, text: '发不出去' });
  assert.equal(unreachable.ok, false);
  assert.equal(unreachable.reason, 'unreachable');
  assert.equal(a.server.dm.list(b.server.store.instanceId)[0].state, 'failed');
});

test('§4 私聊正文不进日志、不进群历史（marker 断言）', async (t) => {
  const marker = 'MARKER-DM-' + Math.random().toString(36).slice(2, 10);
  const logs = [];
  const a = await startServer(t, {
    allowRemotePrompts: true,
    logger: (line) => logs.push(String(line)),
    // 群开着才谈得上「不进群历史」
    group: { enabled: true, autoJoin: true },
  });
  const b = await startServer(t, {
    allowRemotePrompts: true,
    runner: createRunner({ delayMs: 5 }),
    group: { enabled: true, autoJoin: true },
  });
  linkAll([a, b]);

  const sent = await a.server.dm.send({ peerId: b.server.store.instanceId, text: marker });
  assert.equal(sent.ok, true, JSON.stringify(sent));
  assert.ok(sent.reply.includes(marker), '回复里应当带着正文（证明只是「不进日志」）');
  assert.equal(a.server.group.enabled, true);

  // 日志里只有 [dm] peer 前 8 位 / 字节数 / 状态：正文一次都不能出现
  assert.ok(logs.some((line) => line.startsWith('[dm] send')), '至少有 [dm] 日志行');
  assert.equal(logs.some((line) => line.includes(marker)), false, '私聊正文不得进日志');

  // 群历史里也没有（私聊与群完全隔离）
  assert.equal(JSON.stringify(a.server.group.history()).includes(marker), false);
  assert.equal(JSON.stringify(b.server.group.history()).includes(marker), false);
});

// ---------------------------------------------------------------------------
// §1/§2/§4 两个真进程：连续会话 + 落盘 + 对齐
// ---------------------------------------------------------------------------

const CHILD_SCRIPT = [
  "import crypto from 'node:crypto';",
  "import fs from 'node:fs';",
  "import path from 'node:path';",
  "import { createPeerServer } from __SERVER_URL__;",
  '',
  'const [role, stateDir, selfName, selfId, peerId, peerUrl, peerName, keyOut, keyIn] = process.argv.slice(2);',
  "fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });",
  '// 本机身份写死：两端要能互相对上 peerId（真机上由首次启动生成，这里为了脚本确定性）',
  "if (selfId && selfId !== '-') {",
  "  fs.writeFileSync(",
  "    path.join(stateDir, 'state.json'),",
  "    JSON.stringify({ instanceId: selfId, name: selfName, createdAt: new Date().toISOString() }, null, 2),",
  '    { mode: 0o600 },',
  '  );',
  '}',
  "if (peerId && peerId !== '-') {",
  "  fs.writeFileSync(",
  "    path.join(stateDir, 'peers.json'),",
  '    JSON.stringify({',
  '      peers: {',
  '        [peerId]: {',
  '          name: peerName,',
  "          baseUrl: peerUrl === '-' ? null : peerUrl,",
  '          secret: keyOut,',
  '          inboundSecret: keyIn,',
  '          addedAt: new Date().toISOString(),',
  '          lastSeen: null,',
  '        },',
  '      },',
  '    }, null, 2),',
  '    { mode: 0o600 },',
  '  );',
  '}',
  '',
  // 换行统一走 fromCharCode：这个字符串要再被写进一个文件，转义层数越少越不容易出错
  'const NL = String.fromCharCode(10);',
  '',
  '// 剧本 DSH：只认「同一个会话」—— 换了会话就记不住上一轮说过什么，',
  '// 于是「你让我叫你 X」这句话本身就是连续会话生效的证据。',
  'const sessions = new Map();',
  'const runner = {',
  '  async ask(prompt, options = {}) {',
  "    const wanted = typeof options?.sessionId === 'string' ? options.sessionId : '';",
  '    if (wanted && sessions.has(wanted)) {',
  '      sessions.get(wanted).turns.push(String(prompt));',
  '      return { sessionId: wanted, reused: true };',
  '    }',
  "    const id = 'dsh-' + (sessions.size + 1) + '-' + crypto.randomBytes(3).toString('hex');",
  '    sessions.set(id, { turns: [String(prompt)] });',
  '    return { sessionId: id, reused: false };',
  '  },',
  '  poll(sessionId) {',
  '    const session = sessions.get(sessionId);',
  "    if (!session) return { status: 'error', error: 'session-not-found' };",
  '    const last = session.turns[session.turns.length - 1];',
  '    const named = /我叫你(.+)$/.exec(session.turns[0] ?? "");',
  '    const reply = /我刚才让你叫什么/.test(last)',
  "      ? (session.turns.length >= 2 && named ? '你让我叫你' + named[1] : '我不知道你让我叫什么')",
  "      : (named ? '好的，记住了：' + named[1] : '收到');",
  "    return { status: 'done', reply };",
  '  },',
  '};',
  '',
  'const server = createPeerServer({',
  '  stateDir,',
  '  name: selfName,',
  "  listenHost: '127.0.0.1',",
  '  allowRemotePrompts: true,',
  '  runner,',
  "  logger: (line) => process.stdout.write('LOG ' + line + NL),",
  '});',
  "const info = await server.listen(0, '127.0.0.1');",
  "process.stdout.write('READY ' + info.port + NL);",
  '',
  "if (role === 'A') {",
  "  const first = await server.dm.send({ peerId, text: '我叫你小助手' });",
  "  process.stdout.write('A1 ' + JSON.stringify({",
  '    ok: first.ok, sessionId: first.sessionId, reused: first.reused, reply: first.reply, reason: first.reason ?? null,',
  "  }) + NL);",
  "  const second = await server.dm.send({ peerId, text: '我刚才让你叫什么？' });",
  "  process.stdout.write('A2 ' + JSON.stringify({",
  '    ok: second.ok, sessionId: second.sessionId, reused: second.reused, reply: second.reply, reason: second.reason ?? null,',
  "  }) + NL);",
  '  const synced = await server.dm.sync(peerId);',
  "  process.stdout.write('A3 ' + JSON.stringify(synced) + NL);",
  "  process.stdout.write('A4 ' + JSON.stringify(server.dm.list(peerId)) + NL);",
  '  await server.close();',
  '  process.exit(0);',
  '} else {',
  '  process.on("SIGTERM", () => { server.close().finally(() => process.exit(0)); });',
  '  setInterval(() => {}, 1000);',
  '}',
].join('\n');

/** 按行读子进程输出（A1/A2 可能同一次 chunk 里到齐，所以是队列不是一次性监听） */
function lineReader(child) {
  const lines = [];
  const waiters = new Set();
  let pending = '';
  const push = (line) => {
    lines.push(line);
    for (const waiter of [...waiters]) {
      if (waiter.predicate(line)) waiter.settle(line);
    }
  };
  child.stdout.on('data', (data) => {
    pending += String(data);
    const parts = pending.split('\n');
    pending = parts.pop();
    for (const line of parts) push(line);
  });
  child.stderr.on('data', (data) => push('STDERR ' + String(data).trim()));
  return {
    lines,
    waitFor(predicate, timeoutMs = 30_000) {
      const existing = lines.find(predicate);
      if (existing !== undefined) return Promise.resolve(existing);
      return new Promise((resolve, reject) => {
        let timer = null;
        const waiter = {
          predicate,
          settle(line) {
            clearTimeout(timer);
            waiters.delete(waiter);
            resolve(line);
          },
        };
        timer = setTimeout(() => {
          waiters.delete(waiter);
          reject(new Error('timeout waiting for child line; got: ' + lines.slice(-8).join(' | ')));
        }, timeoutMs);
        waiters.add(waiter);
      });
    },
  };
}

test('§1/§2/§4 两个真进程：A 让 B 记住「小助手」，第二轮 B 答出来（sessionId 相同、reused:true）', async (t) => {
  const root = makeTempStateDir('dsh-dm-two-proc-');
  const scriptPath = path.join(root, 'demo-node.mjs');
  const serverUrl = pathToFileURL(path.join(process.cwd(), 'host', 'server.mjs')).href;
  fs.writeFileSync(scriptPath, CHILD_SCRIPT.replace('__SERVER_URL__', JSON.stringify(serverUrl)));
  const aDir = path.join(root, 'A');
  const bDir = path.join(root, 'B');
  fs.mkdirSync(aDir, { recursive: true });
  fs.mkdirSync(bDir, { recursive: true });
  const aId = 'peer-A-' + Math.random().toString(36).slice(2, 8);
  const bId = 'peer-B-' + Math.random().toString(36).slice(2, 8);
  const keyAToB = 'kab-' + Math.random().toString(36).slice(2, 10);
  const keyBToA = 'kba-' + Math.random().toString(36).slice(2, 10);

  const b = spawn(process.execPath, [scriptPath, 'B', bDir, 'B', bId, aId, '-', 'A', keyBToA, keyAToB], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  t.after(() => { try { b.kill('SIGTERM'); } catch {} });
  const bLines = lineReader(b);
  const ready = await bLines.waitFor((line) => line.startsWith('READY '));
  const bPort = Number(ready.slice('READY '.length).trim());
  assert.ok(bPort > 0, 'B 必须在真端口上监听');
  const bUrl = 'http://127.0.0.1:' + bPort;

  const a = spawn(process.execPath, [scriptPath, 'A', aDir, 'A', aId, bId, bUrl, 'B', keyAToB, keyBToA], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  t.after(() => { try { a.kill('SIGTERM'); } catch {} });
  const aLines = lineReader(a);
  const a1Line = await aLines.waitFor((line) => line.startsWith('A1 '));
  const a2Line = await aLines.waitFor((line) => line.startsWith('A2 '));
  const a3Line = await aLines.waitFor((line) => line.startsWith('A3 '));
  const a4Line = await aLines.waitFor((line) => line.startsWith('A4 '));
  const first = JSON.parse(a1Line.slice(3));
  const second = JSON.parse(a2Line.slice(3));

  assert.equal(first.ok, true, JSON.stringify(first));
  assert.equal(first.reused, false);
  assert.equal(first.reply, '好的，记住了：小助手');
  assert.equal(second.ok, true, JSON.stringify(second));
  assert.equal(second.reused, true, '第二个进程必须续上同一个 DSH 会话');
  assert.equal(second.reply, '你让我叫你小助手', '只有真的续上会话才可能记住上一轮');
  assert.equal(second.sessionId, first.sessionId, '两轮打印的 sessionId 必须相同');
  assert.equal(JSON.parse(a3Line.slice(3)).ok, true);
  const persisted = JSON.parse(a4Line.slice(3));
  assert.deepEqual(persisted.map((entry) => entry.from), ['self', 'peer', 'self', 'peer']);

  // 落盘证据：A 的私聊文件里四条，且重启后仍读得回来
  const aFile = path.join(aDir, 'dm', bId + '.jsonl');
  assert.equal(fs.existsSync(aFile), true);
  // 追加写：4 条消息 + 2 条状态修订（pending -> sent 也走追加，读取时后一行权威）
  assert.equal(fs.readFileSync(aFile, 'utf8').trim().split('\n').length, 6);
  const reopened = new DmStore({ stateDir: aDir });
  assert.equal(reopened.list(bId).length, 4);
  assert.deepEqual(reopened.list(bId).map((entry) => entry.id), persisted.map((entry) => entry.id));

  // 日志里没有正文
  assert.equal(aLines.lines.some((line) => line.startsWith('LOG ') && line.includes('小助手')), false);
  fs.rmSync(root, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// §1 桌面端 runner（in-process sessionController）：连续会话同样成立
//
// Electron 里没有 web token，只有这条 runner 能用；它不认 { sessionId } 的话
// 「桌面作为回答方」就永远续不上会话 —— 这两条用例守的就是桌面端不退化。
// ---------------------------------------------------------------------------

/** 假 sessionController：create/prompt/list 三件套。prompt 打到不存在的会话会抛。 */
function fakeController() {
  const sessions = new Map();
  let sequence = 0;
  return {
    sessions,
    async create() {
      sequence += 1;
      const sessionId = 'ctx-' + sequence;
      sessions.set(sessionId, { turns: [] });
      return { sessionId };
    },
    async prompt(request) {
      const session = sessions.get(request.sessionId);
      if (!session) throw new Error('session-not-found: ' + request.sessionId);
      session.turns.push(request.content?.[0]?.text ?? '');
      return { ok: true };
    },
    async list() {
      return {
        items: [...sessions.entries()].map(([sessionId, session]) => ({
          sessionId,
          running: false,
          projections: {
            values: { turnOutline: [{ response: 'ECHO ' + (session.turns[session.turns.length - 1] ?? '') }] },
          },
        })),
      };
    },
  };
}

/** runner-ctx 在模块加载时读 LAN_PEERS_DEBUG，先把它指到临时目录再动态导入 */
async function loadCtxRunner(dir) {
  process.env.LAN_PEERS_DEBUG = path.join(dir, 'lan-peers-debug.log');
  const mod = await import('../../lib/runner-ctx.mjs');
  return mod.createCtxRunner;
}

test('§1 桌面 runner（in-process）：同一 sessionId 连续两次 → reused:true，且打在同一个 controller 会话上', async () => {
  const dir = makeTempStateDir('dsh-ctx-runner-');
  const createCtxRunner = await loadCtxRunner(dir);
  const controller = fakeController();
  const runner = createCtxRunner(controller, { workspace: dir });

  // 旧形状：不带 options 仍返回裸 sessionId（旧调用方与既有断言依赖）
  const first = await runner.ask('我叫你小助手');
  assert.equal(typeof first, 'string');
  const second = await runner.ask('我刚才让你叫什么？', { sessionId: first });
  assert.deepEqual(second, { sessionId: first, reused: true });
  assert.equal(controller.sessions.size, 1, '第二轮不能另起会话');
  assert.deepEqual(controller.sessions.get(first).turns, ['我叫你小助手', '我刚才让你叫什么？']);

  // 续聊出来的会话，poll 读到的就是这一轮的回复
  const done = await runner.poll(first);
  assert.equal(done.status, 'done');
  assert.equal(done.reply, 'ECHO 我刚才让你叫什么？');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('§1 桌面 runner（in-process）：sessionId 不存在 → 回退新建 reused:false，且不抛错', async () => {
  const dir = makeTempStateDir('dsh-ctx-runner-');
  const createCtxRunner = await loadCtxRunner(dir);
  const controller = fakeController();
  const runner = createCtxRunner(controller, { workspace: dir });

  const out = await runner.ask('续一个已经不存在的会话', { sessionId: 'ctx-missing' });
  assert.equal(out.reused, false);
  assert.notEqual(out.sessionId, 'ctx-missing');
  assert.equal(controller.sessions.size, 1);
  assert.deepEqual(controller.sessions.get(out.sessionId).turns, ['续一个已经不存在的会话']);

  // 没有 list 的 controller（老 sessionController）：靠 prompt 的报错回退，同样不抛
  const bare = {
    async create() { return { sessionId: 'bare-1' }; },
    async prompt(request) { if (request.sessionId !== 'bare-1') throw new Error('session-not-found'); },
  };
  const bareRunner = createCtxRunner(bare, { workspace: dir });
  const fallback = await bareRunner.ask('再来一次', { sessionId: 'bare-missing' });
  assert.deepEqual(fallback, { sessionId: 'bare-1', reused: false });
  fs.rmSync(dir, { recursive: true, force: true });
});
