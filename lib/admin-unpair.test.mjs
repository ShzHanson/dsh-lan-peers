/**
 * v0.4.1 · 手动取消配对的管理接口 POST /api/lan-peers/unpair。
 *
 * 走真实 HTTP + 真实 fetch：admin.handle 只挂在回环地址上，路由层的
 * Host 校验、body 解析和"尽力通知对端"都是真行为，不是注入桩。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { createAdmin } from './admin.mjs';
import { StateStore, createPeerServer } from '../host/server.mjs';
import { makeTempStateDir, readJson, seedPeers } from '../host/test/helpers.mjs';

// S3：管理接口要会话 token。本文件走真 HTTP，所以 token 取同进程 admin 实例那一份，
// 由 post() 放到 X-Lan-Peers-Token 头里（路由层的 Host/Origin/JSON 门禁都是真行为）。
let adminToken = '';

async function startAdmin(t, store) {
  const admin = createAdmin({ server: { store }, nameOf: () => 'me', rename: () => 'me' });
  adminToken = admin.token;
  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://lan-peer.invalid');
    Promise.resolve(admin.handle(req, res, url)).then((handled) => {
      if (!handled) {
        res.writeHead(404, { 'content-type': 'application/json' });
        res.end('{"error":"not-found"}');
      }
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  return 'http://127.0.0.1:' + server.address().port;
}

function post(baseUrl, body, headers = {}) {
  return fetch(baseUrl + '/api/lan-peers/unpair', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-lan-peers-token': adminToken, ...headers },
    body: JSON.stringify(body),
  }).then(async (res) => ({ status: res.status, json: await res.json().catch(() => null) }));
}

test('admin unpair：peerId 缺失或未知 → 404 unknown-peer，且不删任何条目', async (t) => {
  const stateDir = makeTempStateDir();
  t.after(() => fs.rmSync(stateDir, { recursive: true, force: true }));
  seedPeers(stateDir, [{ peerId: 'peer-a', name: 'a', secret: 's', inboundSecret: 't', baseUrl: 'http://127.0.0.1:1' }]);
  const store = new StateStore({ stateDir, name: 'me' });
  const baseUrl = await startAdmin(t, store);

  for (const body of [{}, { peerId: '' }, { peerId: 'nobody' }]) {
    const res = await post(baseUrl, body);
    assert.equal(res.status, 404, JSON.stringify(body));
    assert.deepEqual(res.json, { error: 'unknown-peer' });
  }
  assert.ok(readJson(path.join(stateDir, 'peers.json')).peers['peer-a'], '未知 id 不能删掉别人');
});

test('admin unpair：对端不可达时本地照样删除，remote.notified=false 且带原因', async (t) => {
  const stateDir = makeTempStateDir();
  t.after(() => fs.rmSync(stateDir, { recursive: true, force: true }));
  // 端口 1 上没有东西在听
  seedPeers(stateDir, [
    { peerId: 'peer-a', name: 'nas-box', secret: 's', inboundSecret: 't', baseUrl: 'http://127.0.0.1:1' },
    { peerId: 'peer-b', name: 'keep-me', secret: 's2', inboundSecret: 't2', baseUrl: null },
  ]);
  const store = new StateStore({ stateDir, name: 'me' });
  const baseUrl = await startAdmin(t, store);

  const res = await post(baseUrl, { peerId: 'peer-a' });
  assert.equal(res.status, 200, JSON.stringify(res.json));
  assert.deepEqual(res.json.peer, { peerId: 'peer-a', name: 'nas-box' });
  assert.equal(res.json.remote.notified, false);
  assert.equal(res.json.remote.reason, 'unreachable');

  const onDisk = readJson(path.join(stateDir, 'peers.json'));
  assert.deepEqual(Object.keys(onDisk.peers), ['peer-b'], '本地一定删除，且不牵连别的 peer');
});

test('admin unpair：只有入站记录（无 baseUrl）时不去探活，只删本地', async (t) => {
  const stateDir = makeTempStateDir();
  t.after(() => fs.rmSync(stateDir, { recursive: true, force: true }));
  seedPeers(stateDir, [{ peerId: 'peer-in', name: 'inbound-only', secret: 's', inboundSecret: 't', baseUrl: null }]);
  const store = new StateStore({ stateDir, name: 'me' });
  const baseUrl = await startAdmin(t, store);

  const res = await post(baseUrl, { peerId: 'peer-in' });
  assert.equal(res.status, 200, JSON.stringify(res.json));
  assert.deepEqual(res.json.remote, { notified: false, reason: 'no-address' });
  assert.equal(readJson(path.join(stateDir, 'peers.json')).peers['peer-in'], undefined);
});

test('admin unpair：对端在线且声明 unpair 时双向删除', async (t) => {
  const dirA = makeTempStateDir();
  const storeA = new StateStore({ stateDir: dirA, name: 'me' });
  const meId = storeA.instanceId;

  const dirB = makeTempStateDir();
  seedPeers(dirB, [{ peerId: meId, name: 'me', secret: 'test-B-nothing', inboundSecret: 'S' }]);
  const peer = createPeerServer({ stateDir: dirB, name: 'peer-host', listenHost: '127.0.0.1' });
  const info = await peer.listen(0, '127.0.0.1');
  t.after(async () => {
    await peer.close();
    fs.rmSync(dirA, { recursive: true, force: true });
    fs.rmSync(dirB, { recursive: true, force: true });
  });

  storeA.upsertPeer(peer.store.instanceId, {
    name: 'peer-host',
    baseUrl: info.url,
    secret: 'S',            // 对端用 inboundSecret=S 验签
    inboundSecret: 'T',
  });

  const baseUrl = await startAdmin(t, storeA);
  const res = await post(baseUrl, { peerId: peer.store.instanceId });
  assert.equal(res.status, 200, JSON.stringify(res.json));
  assert.equal(res.json.remote.notified, true, JSON.stringify(res.json.remote));
  assert.deepEqual(res.json.peer, { peerId: peer.store.instanceId, name: 'peer-host' });

  assert.equal(readJson(path.join(dirA, 'peers.json')).peers[peer.store.instanceId], undefined, '本端已删');
  assert.equal(
    readJson(path.join(dirB, 'peers.json')).peers[meId],
    undefined,
    '对端也被通知删除本端记录',
  );
  assert.equal(peer.store.getPeerCount(), 0);
});

test('admin unpair：对端在线但不声明 unpair（0.3.1 形态）→ 不发请求，reason=unsupported', async (t) => {
  // 冒充 0.3.1：health 只有 ask/pair，且没有任何 /v1/unpair 处理
  const seen = [];
  const old = http.createServer((req, res) => {
    seen.push(req.method + ' ' + req.url);
    if (req.url === '/v1/health') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ name: 'old-host', instanceId: 'old-id', version: '0.3.1', capability: ['ask', 'pair'], peers: 0 }));
      return;
    }
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end('{"error":"not-found"}');
  });
  await new Promise((resolve) => old.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => old.close(resolve)));

  const dirA = makeTempStateDir();
  const storeA = new StateStore({ stateDir: dirA, name: 'me' });
  storeA.upsertPeer('old-id', {
    name: 'old-host',
    baseUrl: 'http://127.0.0.1:' + old.address().port,
    secret: 'S',
    inboundSecret: 'T',
  });
  t.after(() => fs.rmSync(dirA, { recursive: true, force: true }));

  const baseUrl = await startAdmin(t, storeA);
  const res = await post(baseUrl, { peerId: 'old-id' });
  assert.equal(res.status, 200, JSON.stringify(res.json));
  assert.deepEqual(res.json.remote, { notified: false, reason: 'unsupported' });
  assert.deepEqual(seen, ['GET /v1/health'], '旧对端不该收到 unpair 请求');
  assert.equal(readJson(path.join(dirA, 'peers.json')).peers['old-id'], undefined, '本地照样删除');
});
