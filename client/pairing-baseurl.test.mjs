/**
 * v0.8.0 真机回归 · 配对必须带上自己的可达地址（缺陷 2）。
 *
 * 现场：桌面 peers.json 里 C 的记录 baseUrl=null → 群名广播对 C 直接算 no-base-url，
 * 于是「配进来的伙伴」永远收不到广播/派单。
 * 本文件钉三件事：
 *   ① pairPeer 发出的配对请求体里带 baseUrl（ECDH 第一轮与旧明文都带），接收方一并入库；
 *   ② 不显式指定时按 S1 口径自动探测（私有 IPv4 + 端口），探测不到就不带（老行为）；
 *   ③ CLI pair --base-url 走同一条路径（面板/管理接口也复用 pairPeer）。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createPeerServer } from '../host/server.mjs';
import { detectSelfBaseUrl, pairPeer } from './peer-call.mjs';
import { listenOnRandomPort, makeTempStateDir } from '../host/test/helpers.mjs';

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), 'cli.mjs');

async function startHost(t, overrides = {}) {
  const stateDir = overrides.stateDir ?? makeTempStateDir();
  const server = createPeerServer({
    listenHost: '127.0.0.1',
    stateDir,
    requireEncryption: false,
    allowRemotePrompts: false,
    ...overrides,
  });
  const info = await listenOnRandomPort(server);
  t.after(async () => {
    await server.close();
    fs.rmSync(stateDir, { recursive: true, force: true });
  });
  return { server, baseUrl: info.url, stateDir };
}

const runCli = (args) => new Promise((resolve) => {
  execFile(process.execPath, [CLI, ...args], { encoding: 'utf8' }, (error, stdout, stderr) => {
    resolve({ status: error ? error.code : 0, stdout, stderr });
  });
});

test('v0.8.0 缺陷2：ECDH 配对把发起方的 baseUrl 存进接收方 peers.json', async (t) => {
  const host = await startHost(t);
  const { code } = host.server.issuePairingCode();
  const selfBaseUrl = 'http://192.168.1.77:7788';

  const paired = await pairPeer({
    url: host.baseUrl,
    code,
    peerId: 'peer-init-ecdh',
    peerName: 'initiator',
    mode: 'ecdh',
    selfBaseUrl,
  });
  assert.equal(paired.transport, 'ecdh');

  const stored = host.server.store.getPeer('peer-init-ecdh');
  assert.ok(stored, '接收方必须落一条 peer 记录');
  assert.equal(stored.baseUrl, selfBaseUrl, '配对时自报的地址必须入库（不再是 null）');
});

test('v0.8.0 缺陷2：旧明文配对同样带 baseUrl（0.3.1 路径不退化）', async (t) => {
  const host = await startHost(t);
  const { code } = host.server.issuePairingCode();
  const selfBaseUrl = 'http://192.168.1.78:7788';
  const paired = await pairPeer({
    url: host.baseUrl,
    code,
    peerId: 'peer-init-legacy',
    peerName: 'initiator-legacy',
    mode: 'legacy',
    selfBaseUrl,
  });
  assert.equal(paired.transport, 'legacy');
  assert.equal(host.server.store.getPeer('peer-init-legacy').baseUrl, selfBaseUrl);
});

test('v0.8.0 缺陷2：不显式指定时按 S1 口径自动探测；探测不到就不写（老行为）', async (t) => {
  const host = await startHost(t);
  const detected = detectSelfBaseUrl();
  const { code } = host.server.issuePairingCode();
  await pairPeer({
    url: host.baseUrl,
    code,
    peerId: 'peer-init-auto',
    peerName: 'initiator-auto',
    mode: 'ecdh',
  });
  const stored = host.server.store.getPeer('peer-init-auto');
  if (detected === '') {
    assert.equal(stored.baseUrl, null, '没有可用私有地址时不带 baseUrl');
  } else {
    assert.equal(stored.baseUrl, detected, '默认就带自动探测到的地址');
  }
});

test('v0.8.0 缺陷2：探测口径（私有 IPv4 优先 192.168、跳过虚拟/回环/公网；非法值被忽略）', () => {
  const interfaces = {
    'vEthernet (WSL)': [{ family: 'IPv4', address: '172.28.0.1', internal: false }],
    'Wi-Fi': [
      { family: 'IPv6', address: 'fe80::1', internal: false },
      { family: 'IPv4', address: '192.168.1.211', internal: false },
    ],
    '以太网': [{ family: 'IPv4', address: '10.0.0.7', internal: false }],
    Loopback: [{ family: 'IPv4', address: '127.0.0.1', internal: true }],
    公网: [{ family: 'IPv4', address: '8.8.8.8', internal: false }],
  };
  assert.equal(detectSelfBaseUrl({ interfaces }), 'http://192.168.1.211:7788');
  assert.equal(detectSelfBaseUrl({ interfaces, port: 8123 }), 'http://192.168.1.211:8123');
  // 显式值优先，且会去掉尾部斜杠；非 http(s) 一律忽略
  assert.equal(
    detectSelfBaseUrl({ interfaces, selfBaseUrl: 'http://10.9.9.9:7788/' }),
    'http://10.9.9.9:7788',
  );
  assert.equal(detectSelfBaseUrl({ interfaces, selfBaseUrl: 'ftp://10.9.9.9' }), 'http://192.168.1.211:7788');
  // 环境变量优先于探测（部署里给不出私有地址时的手动兜底）
  assert.equal(
    detectSelfBaseUrl({ interfaces, env: { DSH_LAN_PEERS_ADVERTISE_BASE_URL: 'http://192.168.1.30:7788' } }),
    'http://192.168.1.30:7788',
  );
  // 完全没有私有地址 → 空串（调用方不会发空 baseUrl）
  assert.equal(
    detectSelfBaseUrl({ interfaces: { 公网: [{ family: 'IPv4', address: '8.8.8.8', internal: false }] } }),
    '',
  );
});

test('v0.8.0 缺陷2：CLI pair --base-url 走同一条路径（真进程 + 真 host）', async (t) => {
  const host = await startHost(t);
  const stateDir = makeTempStateDir('dsh-lan-peers-pair-cli-');
  t.after(() => fs.rmSync(stateDir, { recursive: true, force: true }));
  const { code } = host.server.issuePairingCode();
  const selfBaseUrl = 'http://192.168.1.79:7788';

  const out = await runCli([
    'pair', '--url', host.baseUrl, '--code', code,
    '--name', 'cli-initiator', '--peer-name', 'hub-box',
    '--base-url', selfBaseUrl, '--state-dir', stateDir,
  ]);
  assert.equal(out.status, 0, out.stderr);
  assert.match(out.stdout, /已配对/, out.stdout);

  const stored = Object.values(host.server.store.listPeers());
  assert.equal(stored.length, 1);
  assert.equal(stored[0].baseUrl, selfBaseUrl, 'CLI 把自己的地址一起发给了对端');
  // CLI 本地也记住了对端地址（既有行为不变）
  const local = JSON.parse(fs.readFileSync(path.join(stateDir, 'peers.json'), 'utf8'));
  assert.equal(local.peers[host.server.store.instanceId].baseUrl, host.baseUrl);
});
