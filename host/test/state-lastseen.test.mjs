/**
 * 读视图 × 伙伴在线态：`GET /api/lan-peers/state` 的 lastSeen 必须反映「当前内存态」。
 *
 * 真机现象（2026-11-08T06:09:45Z 热重载后）：群心跳每 3 秒一次，磁盘 peers.json 里
 * d3e962ec… 的 lastSeen 已经是 06:09:47.066Z，但同一时刻 /api/lan-peers/state 回的是
 * lastSeen: null —— 面板「伙伴」行 60 秒在线判定吃这个值，于是永远显示离线。
 *
 * 这里钉死四件事（时钟全部注入，不 sleep）：
 *   1) touchPeer 之后 state.peers[].lastSeen 立刻变新，**不等** 30s 写盘节流；
 *   2) 节流窗口内（磁盘还是旧值）读视图仍然取内存里的最新值；
 *   3) unpair 之后该 peer 不在 state.peers 里，内存里那点新鲜值也不能把它复活；
 *   4) touchPeer 的 30 秒写盘节流仍然存在：窗口内多次 touch 只写一次盘。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { StateStore } from '../server.mjs';
import { createAdmin } from '../../lib/admin.mjs';
import { makeTempStateDir, peerFixture, readJson, seedPeers } from './helpers.mjs';

const PEERS_FILE = 'peers.json';
const iso = (ms) => new Date(ms).toISOString();

/** 与真面板同形状的 req/res：回环 Host 头 + 会话 token 头 */
function makeResponse() {
  return {
    status: 0,
    headers: {},
    body: '',
    setHeader(k, v) { this.headers[k] = v; },
    writeHead(status, headers) { this.status = status; Object.assign(this.headers, headers || {}); },
    write(chunk) { this.body += chunk; return true; },
    end(chunk) { if (chunk) this.body += chunk; if (!this.status) this.status = 200; },
    once() {},
    on() {},
  };
}

function makeRequest(apiPath, token) {
  const req = {
    method: 'GET',
    url: apiPath,
    socket: { remoteAddress: '127.0.0.1', setNoDelay() {} },
    headers: { host: '127.0.0.1:7788', 'content-length': '0', 'x-lan-peers-token': token },
    on() { return req; },
    once() { return req; },
    async *[Symbol.asyncIterator]() {},
  };
  return req;
}

/** 起一个真 StateStore + 真 admin；返回读 state 的便捷函数 */
function boot(t, peerIds = []) {
  const clock = { now: Date.parse('2026-11-08T06:00:00.000Z') };
  const stateDir = makeTempStateDir('dsh-lan-peers-lastseen-');
  t.after(() => fs.rmSync(stateDir, { recursive: true, force: true }));
  seedPeers(stateDir, peerIds);
  const store = new StateStore({ stateDir, name: 'me', now: () => clock.now });
  const server = { config: { logger: () => {}, listenPort: 0 }, store };
  const admin = createAdmin({ server, nameOf: () => 'me', rename: (n) => n });
  const disk = () => readJson(path.join(stateDir, PEERS_FILE)).peers;
  const getState = async () => {
    const res = makeResponse();
    const handled = await admin.handle(
      makeRequest('/api/lan-peers/state', admin.token),
      res,
      new URL('http://127.0.0.1/api/lan-peers/state'),
    );
    assert.equal(handled, true, 'state 必须由 admin 接管');
    assert.equal(res.status, 200, 'state 必须 200：' + res.body);
    return JSON.parse(res.body);
  };
  return { clock, stateDir, store, admin, disk, getState };
}

test('touchPeer 之后 state.lastSeen 立刻变新（不等 30s 写盘节流）', async (t) => {
  const PEER = peerFixture('peer-lastseen-a');
  const hud = boot(t, [PEER]);
  const t0 = hud.clock.now;

  const before = await hud.getState();
  assert.equal(before.peers.length, 1);
  assert.equal(before.peers[0].lastSeen, null, '初始没有 lastSeen');

  // 第一次 touch：超出节流窗口 → 记账并落盘
  hud.store.touchPeer(PEER.peerId, t0);
  const first = await hud.getState();
  assert.equal(first.peers[0].lastSeen, iso(t0), '第一次 touch 后读视图就该有新值');

  // 第二次 touch：只过 5 秒 → 内存更新、磁盘按设计不动
  const t1 = t0 + 5_000;
  hud.store.touchPeer(PEER.peerId, t1);
  const after = await hud.getState();
  assert.equal(hud.disk()[PEER.peerId].lastSeen, iso(t0), '节流窗口内磁盘仍是旧值（设计如此）');
  assert.equal(after.peers[0].lastSeen, iso(t1), '读视图必须取内存最新值，不能停在磁盘旧值');

  // 再读一次（会再次 reloadPeers）也不能把内存里那点新鲜值冲掉
  const again = await hud.getState();
  assert.equal(again.peers[0].lastSeen, iso(t1), '反复读 state 不应回退到磁盘旧值');
});

test('unpair 之后 state.peers 不含该 peer，内存新鲜值也不能复活它', async (t) => {
  const PEER = peerFixture('peer-lastseen-b');
  const hud = boot(t, [PEER]);
  const t0 = hud.clock.now;

  hud.store.touchPeer(PEER.peerId, t0);
  assert.equal((await hud.getState()).peers.length, 1);

  assert.equal(hud.store.removePeer(PEER.peerId), true);
  assert.deepEqual((await hud.getState()).peers, [], '解绑后读视图不能还留着它');

  // 解绑后还有群级流量进来：state 与磁盘都不许把它写回来
  hud.store.touchPeer(PEER.peerId, t0 + 2_000);
  assert.deepEqual((await hud.getState()).peers, [], 'touch 不能把已解绑的 peer 复活到读视图');
  assert.equal(hud.disk()[PEER.peerId], undefined, 'touch 不能把已解绑的 peer 写回磁盘');
});

test('touchPeer 的 30 秒写盘节流仍在：窗口内多次 touch 只写一次盘', async (t) => {
  const PEER = peerFixture('peer-lastseen-c');
  const hud = boot(t, [PEER]);
  const t0 = hud.clock.now;

  hud.store.touchPeer(PEER.peerId, t0);                 // 记账 + 落盘
  assert.equal(hud.disk()[PEER.peerId].lastSeen, iso(t0));
  const mtimeAfterFirst = fs.statSync(path.join(hud.stateDir, PEERS_FILE)).mtimeMs;

  for (const delta of [1_000, 5_000, 29_999]) hud.store.touchPeer(PEER.peerId, t0 + delta);
  assert.equal(
    hud.disk()[PEER.peerId].lastSeen,
    iso(t0),
    '30 秒窗口内多次 touch 不许再写盘（节流是性能设计）',
  );
  assert.equal(
    fs.statSync(path.join(hud.stateDir, PEERS_FILE)).mtimeMs,
    mtimeAfterFirst,
    '窗口内文件 mtime 都不该变',
  );

  // 越过 30 秒阈值 → 下一次 touch 必须落盘，且读视图跟着走
  hud.store.touchPeer(PEER.peerId, t0 + 30_000);
  assert.equal(hud.disk()[PEER.peerId].lastSeen, iso(t0 + 30_000), '越过阈值后必须落盘');
  assert.equal((await hud.getState()).peers[0].lastSeen, iso(t0 + 30_000));
});
