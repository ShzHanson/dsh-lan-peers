// dsh-lan-peers · 端口助手的回归钉：同一个坏端口不许被发第二次
//
// 背景（本仓库的假红 #4）：test-support/ports.mjs 原先只靠 listen( 0 ) 反复重试。
// Linux/Windows 内核会把刚释放的临时端口优先再发一次，于是每次重试都可能落回
// 同一个 WHATWG bad port（6665-6669 等），5 次耗尽 -> "no fetch-safe ephemeral port
// after 5 attempts (last=6669)"。这条文件用假 server 把那个场景钉成确定性的。
//
// F5（非空性）—— 每个断言各自负责什么：
//   · "distinct ports"（F1 的 asked 无重复 + 逐个是显式端口）：把 pickCandidatePort
//     里的 asked 去重去掉（或退回每次 listen(0)），这一条立刻红 —— 假 server 会一直
//     回答 6669，asked 变成 [0,0,0,0,0]/[0,c,c,...]，重复与"耗尽"两处断言同时炸。
//   · "happy path 只问一次"（F2 的 asked 深等于 [0]，F2 的 live 分支同款）：把
//     listen(0) 改成一上来就挑显式候选，或让它多走一次重试，这一条立刻红。
import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import http from 'node:http';

import { isFetchBlockedPort, listenOnRandomPort } from '../../test-support/ports.mjs';

const BLOCKED = 6669; // 6669 在 FETCH_BLOCKED_PORTS 里（WHATWG bad port，IRCS）

/**
 * 假 server：有 address()，所以 needsLiveProbe 为 false —— 一次网络都不发，
 * 端口完全由 report(请求的端口) 决定。这正是「操作系统把同一个号再发一次」的模型。
 */
function fakeServer(report) {
  const asked = [];
  const state = { port: 0 };
  const server = {
    listening: false,
    listen(port) {
      asked.push(port);
      this.listening = true;
      state.port = report(port);
      return undefined;
    },
    address() {
      return state.port > 0 ? { address: '127.0.0.1', family: 'IPv4', port: state.port } : null;
    },
    close(callback) {
      this.listening = false;
      if (typeof callback === 'function') callback();
      return undefined;
    },
  };
  return { server, asked };
}

test('F1 · listen(0) 老落回同一个坏端口时，改用显式端口成功，且每次问的端口都不同', async () => {
  // listen(0) 永远报 6669（内核复用同一号）；显式端口则如实回报。
  const { server, asked } = fakeServer((port) => (port === 0 ? BLOCKED : port));

  const info = await listenOnRandomPort(server, '127.0.0.1');

  assert.equal(isFetchBlockedPort(info.port), false, '返回的端口不能还是 fetch 黑名单里的：' + info.port);
  assert.equal(asked[0], 0, '第 1 发必须仍是 listen(0)（happy path 语义不变）');
  assert.equal(asked.length, 2, '第 2 发就该用显式端口命中，实际问过：' + asked.join(','));
  assert.ok(asked[1] > 0, '第 2 发必须是显式端口，实际：' + asked[1]);
  assert.equal(new Set(asked).size, asked.length, '同一个端口不许被问第二次，实际：' + asked.join(','));
  assert.equal(info.port, asked[1], '返回值必须是真正绑上的那个端口');
});

test('F2 · happy path 不变：第一次 listen(0) 拿到干净端口就返回，只问一次', async () => {
  const clean = 51234; // 既不在黑名单，也不需要重试
  const { server, asked } = fakeServer(() => clean);

  const info = await listenOnRandomPort(server, '127.0.0.1');

  assert.deepEqual(asked, [0], '干净端口必须在第 1 发直接返回，实际问过：' + asked.join(','));
  assert.equal(info.port, clean);
  assert.equal(info.url, 'http://127.0.0.1:' + clean, 'url 形状不变');
});

test('F2b · needsLiveProbe 分支也只在第 1 发命中时才返回（真 server + 真 fetch 自证）', async () => {
  // 先绑一个真实的、非黑名单端口的 http server（极小概率落到黑名单就换一个，保证确定性）。
  let real = null;
  let realPort = 0;
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const candidate = http.createServer((req, res) => { res.writeHead(200); res.end('ok'); });
    await new Promise((resolve, reject) => {
      candidate.once('error', reject);
      candidate.listen({ host: '127.0.0.1', port: 0 }, resolve);
    });
    realPort = candidate.address().port;
    if (!isFetchBlockedPort(realPort)) { real = candidate; break; }
    await new Promise((resolve) => candidate.close(resolve));
  }
  assert.ok(real, '需要先绑到一个非黑名单端口');

  // 产品 peer server 的形状：没有 address()，listen() 返回 thenable。
  const asked = [];
  const liveServer = {
    config: {},
    listen(port) {
      asked.push(port);
      return Promise.resolve({ port: realPort, url: 'http://127.0.0.1:' + realPort });
    },
    close() { return Promise.resolve(); },
  };
  try {
    const info = await listenOnRandomPort(liveServer, '127.0.0.1');
    assert.equal(info.port, realPort, '真打 /v1/health 通过后原样返回');
    assert.deepEqual(asked, [0], 'live 分支也必须第 1 发就命中，实际问过：' + asked.join(','));
  } finally {
    await new Promise((resolve) => real.close(resolve));
  }
});

test('F3 · 每个候选都不可用时仍然报错（确定性，无真 socket）', async () => {
  // 不论问什么端口，这个假 server 都回答 6669：等价于「候选段整段被屏蔽」。
  const { server, asked } = fakeServer(() => BLOCKED);

  await assert.rejects(
    () => listenOnRandomPort(server, '127.0.0.1'),
    (error) => {
      assert.ok(error instanceof Error, '必须是 Error');
      assert.match(error.message, /no fetch-safe port after 5 distinct ports tried/,
        '失败文案必须点名「试了几个、且互不相同」，实际：' + error.message);
      assert.match(error.message, /last=6669/, '失败文案仍要带 last=，实际：' + error.message);
      return true;
    },
  );
  assert.equal(asked.length, 5, 'attempts=5 就是 5 个端口，实际：' + asked.join(','));
  assert.equal(new Set(asked).size, asked.length, '耗尽路径上问过的端口也必须互不相同：' + asked.join(','));
});

test('F4 · 真 server：listenOnRandomPort 给出可用端口，且能干净关掉', async () => {
  const server = net.createServer((socket) => socket.end('ok'));
  const info = await listenOnRandomPort(server, '127.0.0.1');
  try {
    assert.ok(info.port > 0, '必须拿到真端口');
    assert.equal(isFetchBlockedPort(info.port), false, '真端口不能落在 fetch 黑名单：' + info.port);
    assert.equal(info.url, 'http://127.0.0.1:' + info.port);

    const echoed = await new Promise((resolve, reject) => {
      const socket = net.connect(info.port, '127.0.0.1');
      socket.once('data', (chunk) => { socket.end(); resolve(String(chunk)); });
      socket.once('error', reject);
    });
    assert.equal(echoed, 'ok', '这个端口必须真的能连上');
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
  assert.equal(server.listening, false, '关闭后不许还挂着监听');
});
