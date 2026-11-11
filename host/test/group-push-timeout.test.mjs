/**
 * 片 3b 缺陷回归：出站推送（fan-out）必须有界，关停必须 abort 在飞推送。
 *
 * 缺陷原样：一次打向「不可达成员」的推送没有上界 —— undici 的 ConnectWrap 挂在事件
 * 循环上，发送方被永久吊住（生产 = 每个离线成员攒一条悬挂推送；测试 = 断言全过、
 * 进程永不退出）。三条用例分别钉住：
 *   P1 打向「黑孔」对端（TCP 连得上、HTTP 永不回）的推送在上界内失败，并记 push-timeout；
 *   P2 推送在飞时 close()：立刻以 push-shutdown 落地，不等上界、不吊住关停；
 *   P3 正常路径零回归：打向活着的对端仍然成功，且远快于上界。
 *
 * 非空性（H5）：把 GROUP_PUSH_TIMEOUT_MS 去掉（或调大到调用方自带的 60s 之上）→ P1 的
 * `elapsed < 6s` 断言失败（实测变成 ~60s）；把 close() 里的 pushGate.abort 去掉 → P2 的
 * 「关停后 1.5s 内落地」断言失败（那条推送要等满上界才结束）。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { setTimeout as sleep } from 'node:timers/promises';
import { listenOnRandomPort } from '../../test-support/ports.mjs';
import { GROUP_PUSH_TIMEOUT_MS, createPeerServer } from '../server.mjs';
import { makeTempStateDir, peerFixture, seedPeers } from './helpers.mjs';

const PEER = peerFixture('peer-push-1');

/** 每次重试都 60s：让「调用方自带的上界」远大于统一上界，P1 的界才只可能是新常量给的 */
const SLOW_RETRY_MS = 60_000;

/**
 * P1 的绝对上界（不写成 GROUP_PUSH_TIMEOUT_MS 的倍数：那会跟着常量一起放大，
 * 常量被调虚就等于没断言）。数值只受「统一上界 + 一次调度抖动」约束。
 */
const PUSH_BOUND_MS = 6_000;

/** 黑孔：收下 TCP 连接后什么都不回（= 对端在线但 HTTP 层卡死 / 首包丢失） */
async function startBlackhole(t) {
  const sockets = new Set();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on('error', () => {});
    socket.on('close', () => sockets.delete(socket));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => {
    for (const socket of sockets) socket.destroy();
    server.close();
  });
  return `http://127.0.0.1:${server.address().port}`;
}

/** 一个 hub（quorum:none，写本地即提交）：成员表里只留 PEER，地址由调用方指定 */
async function startHub(t, { memberBaseUrl }) {
  const stateDir = makeTempStateDir('dsh-lan-peers-push-');
  seedPeers(stateDir, [PEER]);
  const server = createPeerServer({
    listenHost: '127.0.0.1',
    stateDir,
    requireEncryption: false,
    group: { enabled: true, name: 'default', autoJoin: true, retentionDays: 7, quorum: 'none' },
    groupReplica: { retryMs: SLOW_RETRY_MS },
  });
  const info = await listenOnRandomPort(server);
  t.after(async () => { await server.close(); });
  server.group.addMember(PEER.peerId, PEER.name);
  server.group.state().members[PEER.peerId].baseUrl = memberBaseUrl;
  return server;
}

/** 发一条消息进复制队列（走 flush:false：队列里留着，由测试自己驱动一次 flush） */
function queueOneMessage(server) {
  server.group.post({
    peerId: server.store.instanceId,
    name: 'hub-box',
    kind: 'chat',
    text: '待推送',
  });
  assert.equal(server.group.pendingReplication()[0]?.pending, 1, '消息已排进复制队列');
}

const entryOf = (server) => server.group.pendingReplication().find((e) => e.peerId === PEER.peerId);

test('P1 不可达对端：推送在上界内失败、记 push-timeout、消息留在队列里重试', async (t) => {
  const blackhole = await startBlackhole(t);
  const hub = await startHub(t, { memberBaseUrl: blackhole });
  queueOneMessage(hub);

  const startedAt = Date.now();
  await hub.group.flushReplicate();
  const elapsed = Date.now() - startedAt;

  assert.equal(entryOf(hub)?.lastError, 'push-timeout', '失败原因必须是新上界给的 push-timeout');
  assert.ok(
    elapsed < PUSH_BOUND_MS,
    `推送必须在有界时间内失败（实测 ${elapsed}ms，统一上界 ${GROUP_PUSH_TIMEOUT_MS}ms，调用方自带 60s）`,
  );
  assert.ok(elapsed > 500, `确实是「连上但不回」而不是瞬时 ECONNREFUSED（实测 ${elapsed}ms）`);
  assert.equal(entryOf(hub)?.pending, 1, '有界失败不丢消息：留在队列里等重试');
});

test('P2 关停：在飞推送立刻 push-shutdown 落地，close() 不被吊住', async (t) => {
  const blackhole = await startBlackhole(t);
  const hub = await startHub(t, { memberBaseUrl: blackhole });
  queueOneMessage(hub);

  const inFlight = hub.group.flushReplicate();
  await sleep(150);
  assert.equal(entryOf(hub)?.lastError, '', '此刻推送确实在飞（还没落地）');

  const startedAt = Date.now();
  await hub.close();
  const closeMs = Date.now() - startedAt;
  assert.ok(closeMs < 1_000, `close() 不能被在飞推送拖住（实测 ${closeMs}ms）`);

  // 关停后 1s 内必须落地：这条推送自带的上界是 3s，所以「1s 就结束」只能是关停闸给的
  const settled = await Promise.race([
    inFlight.then(() => 'settled'),
    sleep(1_000).then(() => 'still-pending'),
  ]);
  assert.equal(settled, 'settled', '关停必须 abort 在飞推送，而不是等满上界');
  assert.equal(entryOf(hub)?.lastError, 'push-shutdown', '原因记 push-shutdown');
});

test('P3 正常路径：活着的对端照旧成功，且远快于上界', async (t) => {
  const received = [];
  const live = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      received.push(req.url);
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, lastSeq: 1 }));
    });
  });
  await new Promise((resolve) => live.listen(0, '127.0.0.1', resolve));
  t.after(() => live.close());
  const hub = await startHub(t, { memberBaseUrl: `http://127.0.0.1:${live.address().port}` });
  queueOneMessage(hub);

  const startedAt = Date.now();
  await hub.group.flushReplicate();
  const elapsed = Date.now() - startedAt;

  assert.deepEqual(received, ['/v1/group/replicate'], '线上形状不变：还是同一个端点');
  assert.equal(entryOf(hub)?.pending ?? 0, 0, '推送成功 → 队列清空（没有改错误码/线格式）');
  assert.ok(elapsed < GROUP_PUSH_TIMEOUT_MS, `正常路径远快于上界（实测 ${elapsed}ms）`);
});
