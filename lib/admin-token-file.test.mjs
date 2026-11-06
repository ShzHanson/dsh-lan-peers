// dsh-lan-peers · v0.8.5-α 真机修复：管理 token **以文件为准**
//
// 现场：<stateDir>/admin-token 只是模块加载时那枚随机 token 的副本，于是每次插件/进程
// 重启都换一枚；已打开的窗口（桌面窗口不加载 panel.js，手里那枚来自 bootstrap）之后每个
// 管理请求都 401，且永不恢复，只能手动 Ctrl+R。
//
// 这里钉死四件事：
//   1. 文件里有合法值（^[0-9a-f]{64}$）→ **沿用**它，bootstrap / adminToken() / 请求校验
//      都指向这一枚；
//   2. 文件不存在 → 生成一枚并原子落盘（0600），不抛错；
//   3. 文件损坏（空 / 非 hex / 大写 / 长度不对）→ 重新生成并覆盖，日志恰好一行
//      「[admin] token file unreadable, regenerated」，且不含 token；
//   4. 同一 stateDir 的两次 createAdmin（= 一次重启）→ 同一枚 token，旧窗口仍然能用。
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { adminToken, createAdmin } from './admin.mjs';
import { makeTempStateDir } from '../host/test/helpers.mjs';

const TOKEN_FILE = 'admin-token';
const HEX64 = /^[0-9a-f]{64}$/;
const REGEN_LINE = '[admin] token file unreadable, regenerated';

const tokenFileOf = (dir) => path.join(dir, TOKEN_FILE);
const readTokenFile = (dir) => fs.readFileSync(tokenFileOf(dir), 'utf8').trim();

function makeResponse() {
  return {
    status: 0, headers: {}, body: '',
    setHeader(k, v) { this.headers[k] = v; },
    writeHead(status, headers) { this.status = status; Object.assign(this.headers, headers || {}); },
    write(chunk) { this.body += chunk; return true; },
    end(chunk) { if (chunk) this.body += chunk; if (!this.status) this.status = 200; },
    once() {}, on() {},
  };
}

/** 与真实面板同形状的请求：回环 Host 头 + token 头（headers 一律小写）。 */
function makeRequest(method, apiPath, token) {
  const req = {
    method,
    url: apiPath,
    socket: { remoteAddress: '127.0.0.1', setNoDelay() {} },
    headers: {
      host: '127.0.0.1:7788',
      'content-length': '0',
      ...(token === '' ? {} : { 'x-lan-peers-token': token }),
    },
    on() { return req; },
    once() { return req; },
    async *[Symbol.asyncIterator]() {},
  };
  return req;
}

async function hit(admin, method, apiPath, token = '') {
  const res = makeResponse();
  const handled = await admin.handle(makeRequest(method, apiPath, token), res, new URL('http://127.0.0.1' + apiPath));
  assert.equal(handled, true, apiPath + ' 必须由 admin 接管');
  let json = null;
  try { json = JSON.parse(res.body); } catch { json = null; }
  return { status: res.status, json };
}

function bootAdmin(stateDir) {
  const lines = [];
  const store = {
    instanceId: 'inst-self',
    stateDir,
    state: { instanceId: 'inst-self', name: 'me', createdAt: '2026-01-01T00:00:00.000Z' },
    listPeers: () => [],
    getPeer: () => null,
  };
  const server = { config: { logger: (line) => lines.push(line), listenPort: 0 }, store };
  const admin = createAdmin({ server, nameOf: () => 'me', rename: (n) => n });
  return { admin, lines };
}

test('① 文件里已有合法 token → 沿用：bootstrap 与 adminToken() 都回这一枚，state 200', async () => {
  const dir = makeTempStateDir();
  const seeded = 'b0'.repeat(32);
  fs.writeFileSync(tokenFileOf(dir), seeded + '\n', { mode: 0o600 });

  const { admin, lines } = bootAdmin(dir);
  assert.equal(admin.token, seeded, '必须沿用文件里的值，不能重新生成');
  assert.equal(adminToken(), seeded, 'adminToken() 出口指向同一枚实例 token');
  assert.equal(readTokenFile(dir), seeded, '沿用路径不得改写文件');

  const boot = await hit(admin, 'GET', '/api/lan-peers/bootstrap');
  assert.equal(boot.status, 200);
  assert.equal(boot.json.token, seeded, 'bootstrap 交出去的也是这一枚');

  const state = await hit(admin, 'GET', '/api/lan-peers/state', seeded);
  assert.equal(state.status, 200, '用文件里的 token 打管理接口必须 200');
  assert.equal(lines.includes(REGEN_LINE), false, '沿用不是「损坏重生成」，不该打那行日志');
});

test('② 文件不存在 → 生成 64 位 hex 并落盘 0600，同一枚就是本实例 token', async () => {
  const dir = makeTempStateDir();
  assert.equal(fs.existsSync(tokenFileOf(dir)), false, '前提：临时 stateDir 里还没有 token 文件');

  const { admin, lines } = bootAdmin(dir);
  const written = readTokenFile(dir);
  assert.match(written, HEX64, '落盘的必须是 64 位小写 hex');
  assert.equal(written, admin.token, '文件内容与本实例 token 必须一致');
  assert.equal(adminToken(), written);
  // Windows 的 mode 是合成值：按既有惯例跳过 mode 断言（同 admin-files 的 admin-url 用例）。
  if (process.platform !== 'win32') {
    assert.equal(fs.statSync(tokenFileOf(dir)).mode & 0o777, 0o600, '落盘必须 0600');
  }
  assert.deepEqual(
    fs.readdirSync(dir).filter((name) => name.startsWith(TOKEN_FILE + '.')),
    [],
    '原子写的临时文件必须已经被 rename 走掉',
  );
  assert.equal(lines.includes(REGEN_LINE), false, '首次创建不是「损坏」，不该打那行日志');

  const state = await hit(admin, 'GET', '/api/lan-peers/state', admin.token);
  assert.equal(state.status, 200);
});

test('③ 文件损坏（空 / 非 hex / 大写 hex / 长度不对）→ 重新生成并覆盖，不抛错，日志一行且不含 token', async () => {
  const brokenCases = ['', 'not-a-token', 'A'.repeat(64), '0'.repeat(63)];
  for (const broken of brokenCases) {
    const dir = makeTempStateDir();
    fs.writeFileSync(tokenFileOf(dir), broken + '\n', { mode: 0o600 });

    let lines = [];
    let admin = null;
    assert.doesNotThrow(() => { const booted = bootAdmin(dir); admin = booted.admin; lines = booted.lines; },
      '损坏的 token 文件绝不能让插件起不来：' + JSON.stringify(broken.slice(0, 12)));

    assert.match(admin.token, HEX64, '必须换成一枚合法 token');
    if (broken !== '') assert.notEqual(admin.token, broken, '损坏的值不能被沿用');
    assert.equal(readTokenFile(dir), admin.token, '必须覆盖落盘');

    const regenerated = lines.filter((line) => line === REGEN_LINE);
    assert.equal(regenerated.length, 1, '恰好一行 [admin] token file unreadable, regenerated');
    const log = lines.join('\n');
    assert.equal(log.includes(admin.token), false, 'token 绝不进日志');
    assert.equal(log.includes(admin.token.slice(0, 8)), false, '连前缀也不行');

    const state = await hit(admin, 'GET', '/api/lan-peers/state', admin.token);
    assert.equal(state.status, 200, '重生成之后本进程自己必须认这一枚');
  }
});

test('④ 同一 stateDir 的两次 createAdmin（模拟重启）→ 同一枚 token，旧窗口仍然 200', async () => {
  const dir = makeTempStateDir();
  const first = bootAdmin(dir).admin;
  const second = bootAdmin(dir).admin;

  assert.equal(second.token, first.token, '重启后必须沿用文件里那一枚');
  assert.equal(adminToken(), first.token, '出口指向当前实例，值不变');
  assert.equal(readTokenFile(dir), first.token, '两次加载都不该改写文件');

  const state = await hit(second, 'GET', '/api/lan-peers/state', first.token);
  assert.equal(state.status, 200, '重启前打开的窗口拿旧 token 必须继续能用');
});
