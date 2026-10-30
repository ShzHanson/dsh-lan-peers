// dsh-lan-peers · CLI unpair（v0.4.1）。
//
// 真进程跑 cli.mjs，状态全在临时 state-dir 里；通知路径用一个临时 host 当对端，
// 断言两端 peers.json 各少一条。
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile, execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createPeerServer } from '../host/server.mjs';
import { makeTempStateDir, readJson, writeJson0600 } from '../host/test/helpers.mjs';

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), 'cli.mjs');

function run(args) {
  return execFileSync(process.execPath, [CLI, ...args], { encoding: 'utf8' });
}

/** 异步跑 CLI：对端 host 就在本进程里，同步子进程会把事件循环卡住 */
function runAsync(args) {
  return new Promise((resolve) => {
    execFile(process.execPath, [CLI, ...args], { encoding: 'utf8' }, (error, stdout, stderr) => {
      resolve({ status: error ? error.code : 0, stdout, stderr });
    });
  });
}

function runFailing(args) {
  try {
    execFileSync(process.execPath, [CLI, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (error) {
    return { status: error.status, stdout: String(error.stdout ?? ''), stderr: String(error.stderr ?? '') };
  }
  throw new Error('expected a non-zero exit: ' + args.join(' '));
}

const peersFile = (dir) => path.join(dir, 'peers.json');
const peerIds = (dir) => Object.keys(readJson(peersFile(dir)).peers);

test('unpair --help 列出子命令选项', () => {
  const out = run(['unpair', '--help']);
  assert.match(out, /--peer/);
  assert.match(out, /--local-only/);
  assert.match(out, /--timeout/);
  assert.match(out, /v1\/unpair/);
  // 根帮助也要能看到这个子命令
  assert.match(run(['--help']), /unpair/);
});

test('unpair 在临时 state-dir 上删条目并 exit 0（对端不可达也照样删）', (t) => {
  const dir = makeTempStateDir();
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  writeJson0600(peersFile(dir), {
    peers: {
      'peer-a': { name: 'old-host', baseUrl: 'http://127.0.0.1:1', secret: 'S', inboundSecret: 'T', addedAt: 'then', lastSeen: null },
      'peer-b': { name: 'keep-me', baseUrl: null, secret: 'S2', inboundSecret: 'T2', addedAt: 'then', lastSeen: null },
    },
  });

  const out = run(['unpair', '--peer', 'old-host', '--state-dir', dir, '--timeout', '1']);
  assert.match(out, /^已解除与 old-host 的配对（仅本地；原因：对端不可达）$/m);
  assert.deepEqual(peerIds(dir), ['peer-b'], '只删目标，另一个 peer 保留');
  assert.equal(readJson(peersFile(dir)).peers['peer-b'].name, 'keep-me');
});

test('unpair --local-only 跳过通知并说明原因', (t) => {
  const dir = makeTempStateDir();
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  writeJson0600(peersFile(dir), {
    peers: { 'peer-a': { name: 'old-host', baseUrl: 'http://127.0.0.1:1', secret: 'S', inboundSecret: 'T' } },
  });

  const out = run(['unpair', '--peer', 'old-host', '--local-only', '--state-dir', dir]);
  assert.match(out, /仅本地；原因：已跳过对端通知（--local-only）/);
  assert.deepEqual(peerIds(dir), []);
});

test('找不到对端 → exit 2 且给出用法提示，peers.json 不动', (t) => {
  const dir = makeTempStateDir();
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  writeJson0600(peersFile(dir), {
    peers: { 'peer-a': { name: 'old-host', baseUrl: null, secret: 'S', inboundSecret: 'T' } },
  });

  const failed = runFailing(['unpair', '--peer', 'nobody', '--state-dir', dir]);
  assert.equal(failed.status, 2);
  assert.match(failed.stderr, /未知对端: nobody/);
  assert.match(failed.stderr, /用法: dsh-lan-peers unpair --peer/);
  assert.deepEqual(peerIds(dir), ['peer-a']);
});

test('同名多个匹配 → exit 2、报歧义并列出候选', (t) => {
  const dir = makeTempStateDir();
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  writeJson0600(peersFile(dir), {
    peers: {
      'peer-a': { name: 'dup', baseUrl: 'http://127.0.0.1:1', secret: 'S', inboundSecret: 'T' },
      'peer-b': { name: 'dup', baseUrl: 'http://127.0.0.1:2', secret: 'S', inboundSecret: 'T' },
    },
  });

  const failed = runFailing(['unpair', '--peer', 'dup', '--state-dir', dir]);
  assert.equal(failed.status, 2);
  assert.match(failed.stderr, /歧义/);
  assert.match(failed.stderr, /peer-a/);
  assert.match(failed.stderr, /peer-b/);
  assert.deepEqual(peerIds(dir).sort(), ['peer-a', 'peer-b']);

  // 用 peerId 就能精确解除
  run(['unpair', '--peer', 'peer-a', '--state-dir', dir, '--local-only']);
  assert.deepEqual(peerIds(dir), ['peer-b']);
});

test('端到端：通知临时 host 后，对端 peers.json 也少一条', async (t) => {
  const dirMe = makeTempStateDir();
  const dirPeer = makeTempStateDir();
  const meState = { instanceId: 'me-instance-id', name: 'me', createdAt: new Date().toISOString() };
  writeJson0600(path.join(dirMe, 'state.json'), meState);

  const peer = createPeerServer({ stateDir: dirPeer, name: 'peer-host', listenHost: '127.0.0.1' });
  const info = await peer.listen(0, '127.0.0.1');
  t.after(async () => {
    await peer.close();
    fs.rmSync(dirMe, { recursive: true, force: true });
    fs.rmSync(dirPeer, { recursive: true, force: true });
  });

  const peerId = peer.store.instanceId;
  writeJson0600(peersFile(dirPeer), {
    peers: {
      [meState.instanceId]: { name: 'me', baseUrl: null, secret: 'unused', inboundSecret: 'S', addedAt: 'then', lastSeen: null },
    },
  });
  writeJson0600(peersFile(dirMe), {
    peers: {
      [peerId]: { name: 'peer-host', baseUrl: info.url, secret: 'S', inboundSecret: 'T', addedAt: 'then', lastSeen: null },
      'peer-other': { name: 'other', baseUrl: null, secret: 'x', inboundSecret: 'y', addedAt: 'then', lastSeen: null },
    },
  });

  const { status, stdout, stderr } = await runAsync(['unpair', '--peer', 'peer-host', '--state-dir', dirMe, '--timeout', '5']);
  assert.equal(status, 0, stderr);
  assert.match(stdout, /^已解除与 peer-host 的配对（对端已同步删除）$/m);
  assert.deepEqual(peerIds(dirMe), ['peer-other'], '本端删掉目标，别的保留');
  assert.deepEqual(Object.keys(readJson(peersFile(dirPeer)).peers), [], '对端被通知后也删掉了本端');
  assert.equal(peer.store.getPeerCount(), 0);
});
