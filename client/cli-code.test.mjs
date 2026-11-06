// dsh-lan-peers · M6 之后 `lan-peers code` 必须请本机 host 发码。
//
// 审计/产品口径：配对码只在 daemon 进程内存里，CLI 是独立进程 —— 它自己造的码对正在跑的
// host 无效，用户抄走的是废码。所以 code 子命令改成打本机管理接口（带 token），
// 本机没 host / 拿不到 token 时 exit 2 并说清怎么起 host，绝不本地造一个码。
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createAdmin } from '../lib/admin.mjs';
import { makeTempStateDir } from '../host/test/helpers.mjs';

process.env.DSH_LAN_PEERS_LANG = 'zh';   // 语言钉死：断言写的是中文文案，不随机器 locale 漂移

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), 'cli.mjs');

const run = (args) => new Promise((resolve) => {
  execFile(process.execPath, [CLI, ...args], { encoding: 'utf8' }, (error, stdout, stderr) => {
    resolve({ code: error ? error.code : 0, stdout: String(stdout || ''), stderr: String(stderr || '') });
  });
});

/** 真 admin 挂在真 HTTP 上：token 文件由它启动时写进这个 stateDir（CLI 读同一份）。 */
async function startAdmin(t, { dir, code = '246810' } = {}) {
  const state = { instanceId: 'inst-self', name: 'self' };
  const store = {
    instanceId: 'inst-self',
    stateDir: dir,
    state,
    listPeers: () => [],
    getPeer: () => null,
    issuePairingCode: () => {
      const issued = { code, expiresAt: Date.now() + 600_000 };
      state.pairingCode = issued;
      return issued;
    },
  };
  const admin = createAdmin({
    server: { config: { logger: () => {} }, store },
    nameOf: () => 'self',
    rename: (n) => n,
  });
  const calls = [];
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      calls.push({ url: String(req.url || ''), method: String(req.method || 'GET'), headers: req.headers });
      const url = new URL(String(req.url || '/'), 'http://127.0.0.1');
      Promise.resolve(admin.handle(req, res, url)).then((handled) => {
        if (!handled) {
          res.writeHead(404, { 'content-type': 'application/json' });
          res.end('{"error":"not-found"}');
        }
      }).catch((error) => {
        res.writeHead(500, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: String(error && error.message ? error.message : error) }));
      });
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  return { admin, calls, state, url: 'http://127.0.0.1:' + server.address().port };
}

test('code：请本机 host 发码并原样打印（与 admin 手里的码一致）', async (t) => {
  const dir = makeTempStateDir('lanb-cli-code-');
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const rig = await startAdmin(t, { dir, code: '246810' });

  const out = await run(['code', '--state-dir', dir, '--url', rig.url]);
  assert.equal(out.code, 0, out.stderr);
  assert.match(out.stdout, /配对码: 246810/);
  assert.doesNotMatch(out.stdout + out.stderr, /token/, '不能把 token 字样漏到界面上');

  const issued = rig.calls.find((call) => call.url === '/api/lan-peers/code');
  assert.ok(issued, '必须打 POST /api/lan-peers/code: ' + JSON.stringify(rig.calls.map((c) => c.url)));
  assert.equal(issued.method, 'POST');
  assert.equal(issued.headers['x-lan-peers-token'], rig.admin.token, 'token 从 <stateDir>/admin-token 读，只走请求头');

  // 打印出来的码就是 host 手里的那一个：GET state 说「已生成」。
  const state = await fetch(rig.url + '/api/lan-peers/state', { headers: { 'x-lan-peers-token': rig.admin.token } });
  const body = await state.json();
  assert.equal(body.pairing.active, true, 'CLI 打印的码必须是本机 host 活着的那一个');
  assert.equal(JSON.stringify(body).includes('246810'), false, 'GET state 仍不回显码');
});

test('code：本机没有 host / 拿不到 token → exit 2，且绝不本地造码打印', async (t) => {
  const dir = makeTempStateDir('lanb-cli-code-');
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const rig = await startAdmin(t, { dir, code: '246810' });
  // 拿掉 token 文件：等价于「本机 host 没起 / 不是同一个进程」。
  fs.rmSync(path.join(dir, 'admin-token'));

  const out = await run(['code', '--state-dir', dir, '--url', rig.url]);
  assert.equal(out.code, 2, '拿不到码就是 exit 2: ' + out.stdout + out.stderr);
  assert.match(out.stderr, /请先启动本机 host/);
  assert.match(out.stderr, /token-required/, '失败原因要如实转述');
  assert.doesNotMatch(out.stdout, /\d{6}/, '失败时不能在 stdout 吐出任何 6 位数字（那会被当成码）');
  assert.equal(fs.existsSync(path.join(dir, 'admin-token')), false, 'CLI 不该自己去造 token');
});

test('code --help 说明「请本机 host 发码」，不再声称写 state.json', async (t) => {
  const out = await run(['code', '--help']);
  assert.match(out.stdout, /请本机 host 生成一次性配对码/);
  assert.doesNotMatch(out.stdout, /同时写入 state\.json/, 'M6 之后 state.json 不再存码');
});
