// dsh-lan-peers · CLI surface tests (help is part of the contract).
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import http from 'node:http';
import fs from 'node:fs';
import { listenOnRandomPort } from '../test-support/ports.mjs';
import { ENC_VERSION, decryptJson, encryptJson } from '../lib/wire-crypto.mjs';
import { keys, t } from '../lib/i18n.mjs';
import { makeTempStateDir, writeJson0600 } from '../host/test/helpers.mjs';

process.env.DSH_LAN_PEERS_LANG = 'zh';   // 语言钉死：断言写的是中文文案，不随机器 locale 漂移

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), 'cli.mjs');

function run(args) {
  return execFileSync(process.execPath, [CLI, ...args], { encoding: 'utf8' });
}

test('root --help lists every subcommand', () => {
  const out = run(['--help']);
  for (const command of ['code', 'pair', 'peers', 'ask', 'events', 'help']) {
    assert.match(out, new RegExp('\\b' + command + '\\b'));
  }
  assert.match(out, /--state-dir/);
});

test('pair --help documents the two-round flow and the forced legacy switch', () => {
  const out = run(['pair', '--help']);
  assert.match(out, /--url/);
  assert.match(out, /--code/);
  assert.match(out, /--legacy-pair/);
  assert.match(out, /--ecdh-pair/);
  assert.match(out, /confirm/);
});

test('events --help documents the subscription options', () => {
  const out = run(['events', '--help']);
  assert.match(out, /--peer/);
  assert.match(out, /--session/);
  assert.match(out, /--duration/);
  assert.match(out, /events/);
});

test('an unknown subcommand fails with usage on stderr', () => {
  assert.throws(
    () => execFileSync(process.execPath, [CLI, 'nope'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }),
    (error) => error.status === 1 && /未知子命令/.test(String(error.stderr)),
  );
});

test('events without --session fails with usage instead of hanging', () => {
  assert.throws(
    () => execFileSync(process.execPath, [CLI, 'events', '--peer', 'x'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }),
    (error) => error.status === 1 && /--session/.test(String(error.message) + String(error.stderr)),
  );
});

// ---------------------------------------------------------------------------
// ask --perm：ask 不携带权限档 —— 必须当场拒绝，不能静默发出去
// ---------------------------------------------------------------------------

const SECRET = 'cli-ask-test-secret-0123456789';
const PEER_ID = 'peer-ask-1';
const CJK = /[\u4e00-\u9fff]/;

function runAsync(args) {
  return new Promise((resolve) => {
    execFile(process.execPath, [CLI, ...args], { encoding: 'utf8' }, (error, stdout, stderr) => {
      resolve({ status: error ? error.code : 0, stdout, stderr });
    });
  });
}

/** 只实现 /v1/health、/v1/ask、/v1/answer 的加密对端桩；每条请求的明文都记进 seen。 */
async function startAskPeer(t) {
  const seen = [];
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const raw = Buffer.concat(chunks);
    if (req.url === '/v1/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ name: 'stub', version: '0.3.1', capability: ['ask'], peers: 1 }));
      return;
    }
    const plain = raw.length ? decryptJson(SECRET, raw.toString('utf8')) : null;
    seen.push({ method: req.method, url: req.url, plain });
    const value = req.url === '/v1/ask' ? { sessionId: 'sess-ask-1' } : { status: 'done', reply: 'stub-reply', elapsedMs: 5 };
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ enc: ENC_VERSION, data: encryptJson(SECRET, value) }));
  });
  const { port } = await listenOnRandomPort(server);
  t.after(() => new Promise((resolve) => { server.close(() => resolve()); }));
  const dir = makeTempStateDir('dsh-lan-peers-cli-ask-');
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  writeJson0600(path.join(dir, 'peers.json'), {
    peers: { [PEER_ID]: { name: 'stub', baseUrl: 'http://127.0.0.1:' + port, secret: SECRET } },
  });
  return { seen, dir };
}

test('ask --perm <档>：当场拒绝，一个请求都不发，并指到 dm 的路径', async (t) => {
  const peer = await startAskPeer(t);
  for (const argv of [['--perm', 'danger-full-access'], ['--perm']]) {
    const out = await runAsync(['ask', '--peer', 'stub', '你好', ...argv, '--state-dir', peer.dir]);
    assert.notEqual(out.status, 0, 'ask 带 ' + argv.join(' ') + ' 必须失败');
    assert.match(out.stderr, /ask 不携带权限档：--perm 在 ask 上无效/);
    assert.match(out.stderr, /dm <peer> <正文> --perm <read-only\|workspace-write\|danger-full-access>/);
    assert.doesNotMatch(out.stdout, /stub-reply/);
  }
  assert.equal(peer.seen.length, 0, '被拒绝的 ask 不得发出任何请求');
});

test('ask 不带 --perm 照旧：/v1/ask 报文仍是 {requestId,prompt,timeoutSec} 且真的发出去了', async (t) => {
  const peer = await startAskPeer(t);
  const out = await runAsync(['ask', '--peer', 'stub', '你好', '--timeout', '5', '--state-dir', peer.dir]);

  assert.equal(out.status, 0, out.stderr);
  assert.match(out.stdout, /stub-reply/);
  const ask = peer.seen.find((call) => call.url === '/v1/ask');
  assert.ok(ask, '请求必须真的发出去');
  assert.equal(ask.method, 'POST');
  assert.deepEqual(Object.keys(ask.plain).sort(), ['prompt', 'requestId', 'timeoutSec']);
  assert.equal(ask.plain.prompt, '你好');
  assert.equal(ask.plain.timeoutSec, 5);
  assert.match(ask.plain.requestId, /^req-/);
});

test('cli.ask.noPerm：zh/en 两格都在，英文格没有汉字', () => {
  for (const lang of ['zh', 'en']) assert.ok(keys(lang).includes('cli.ask.noPerm'), lang + ' 缺 cli.ask.noPerm');
  const en = t('en', 'cli.ask.noPerm');
  const zh = t('zh', 'cli.ask.noPerm');
  assert.doesNotMatch(en, CJK);
  assert.match(zh, CJK);
  for (const text of [en, zh]) {
    assert.match(text, /--perm/);
    assert.match(text, /dm <peer>/);
  }
});
