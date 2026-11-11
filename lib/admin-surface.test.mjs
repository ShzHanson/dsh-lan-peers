// dsh-lan-peers · 管理接口与可见面：S3（凭证 + CSRF 门禁）、M6（配对码不回显）、
// M1（派单歧义的可见面）。攻击形状用真 admin.handle 跑，正常路径用真面板脚本桥接过去。
//
// 审计事实（0.8.2）：/api/lan-peers/* 唯一门禁是「Host 头是回环」，而 Host 缺失时
// 该函数直接 return true —— 任何能打到这条端口的进程都能改名、发配对码。这里把
// 修好之后的三道门钉死：回环 Host + 进程 token + （写操作）JSON/同源。
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { PANEL_SCRIPT, adminToken, createAdmin } from './admin.mjs';
import { createPeerServer } from '../host/server.mjs';
import { makeTempStateDir, peerFixture, seedPeers, writeJson0600 } from '../host/test/helpers.mjs';


const TOKEN = adminToken();

function makeResponse() {
  return {
    status: 0,
    headers: {},
    body: '',
    writeHead(status, headers) { this.status = status; Object.assign(this.headers, headers || {}); },
    setHeader(k, v) { this.headers[k] = v; },
    write(chunk) { this.body += chunk; return true; },
    end(chunk) { if (chunk) this.body += chunk; if (!this.status) this.status = 200; },
    once() {},
    on() {},
  };
}

/** 与真实面板同形状的请求：headers 一律小写（Node 收进来的就是这个形状）。 */
function makeReq({ method = 'GET', path: apiPath, headers = {}, body } = {}) {
  const chunks = body === undefined ? [] : [Buffer.from(body)];
  const req = {
    method,
    url: apiPath,
    socket: { remoteAddress: '127.0.0.1', setNoDelay() {} },
    headers: {
      host: '127.0.0.1:7788',
      ...headers,
      'content-length': String(chunks[0]?.length ?? 0),
    },
    on() { return req; },
    once() { return req; },
    async *[Symbol.asyncIterator]() { for (const chunk of chunks) yield chunk; },
  };
  return req;
}

const jsonOf = (res) => {
  try { return JSON.parse(res.body); } catch { return null; }
};

/** 一块真 admin：群后端用 groupApi 整块替换（只统计 post 调用，不碰网络）。 */
function bootAdmin({ stateDir = '' } = {}) {
  const posts = [];
  const logged = [];
  const store = {
    instanceId: 'inst-self',
    stateDir,
    state: { instanceId: 'inst-self', name: 'me', createdAt: '2026-01-01T00:00:00.000Z' },
    listPeers: () => [],
    getPeer: () => null,
    // M6：码只在生成那一次的响应里，state.json 落不落盘已不归管理面管，这里只模拟内存码。
    issuePairingCode: () => {
      const issued = { code: '654321', expiresAt: Date.now() + 600_000 };
      store.state.pairingCode = issued;
      return issued;
    },
  };
  const server = {
    config: { logger: (line) => logged.push(line) },
    store,
  };
  const admin = createAdmin({
    server,
    nameOf: () => 'me',
    rename: (n) => n,
    feed: null,
    pairing: { mode: 'auto' },
    groupApi: {
      enabled: true,
      isHub: true,
      post: async (message) => { posts.push(message); return { seq: 7, ts: 1_700_000_000_000 }; },
      state: () => ({ groupId: 'g-1', name: '家里', members: {} }),
      history: () => ({ messages: [], lastSeq: 0 }),
    },
  });
  return { admin, posts, logged };
}

async function hit(admin, options) {
  const res = makeResponse();
  const req = makeReq(options);
  const handled = await admin.handle(req, res, new URL('http://127.0.0.1' + req.url));
  return { handled, status: res.status, json: jsonOf(res), raw: res.body };
}

// ---------------------------------------------------------------------------
// 攻击形状：每一条都对应一种真实可发的请求
// ---------------------------------------------------------------------------

test('无 token 的只读请求 → 401 token-required（只读接口也不例外）', async () => {
  const { admin } = bootAdmin();
  const out = await hit(admin, { path: '/api/lan-peers/state' });
  assert.equal(out.status, 401);
  assert.equal(out.json.error, 'token-required');
});

test('错误 token → 401（长度不同也不炸 timingSafeEqual）', async () => {
  const { admin } = bootAdmin();
  for (const bad of ['0'.repeat(64), 'short', TOKEN.slice(0, 63) + (TOKEN.endsWith('a') ? 'b' : 'a')]) {
    const out = await hit(admin, { path: '/api/lan-peers/state', headers: { 'x-lan-peers-token': bad } });
    assert.equal(out.status, 401, bad.slice(0, 8));
    assert.equal(out.json.error, 'token-required');
  }
});

test('text/plain 的 POST → 415（跨站表单能发的正是这种简单请求），业务不执行', async () => {
  const { admin, posts } = bootAdmin();
  const out = await hit(admin, {
    method: 'POST',
    path: '/api/lan-peers/group/post',
    headers: { 'x-lan-peers-token': TOKEN, 'content-type': 'text/plain' },
    body: JSON.stringify({ kind: 'chat', text: '被注入的消息' }),
  });
  assert.equal(out.status, 415);
  assert.equal(out.json.error, 'content-type-json-required');
  assert.equal(posts.length, 0, '被拒的请求绝不能落到群后端');
});

test('带跨站 Origin 的写请求 → 403 forbidden: cross-origin', async () => {
  const { admin, posts } = bootAdmin();
  for (const origin of ['https://evil.example', 'http://192.168.1.9:7788', 'null']) {
    const out = await hit(admin, {
      method: 'POST',
      path: '/api/lan-peers/group/post',
      headers: { 'x-lan-peers-token': TOKEN, origin, 'content-type': 'application/json' },
      body: JSON.stringify({ kind: 'chat', text: 'x' }),
    });
    assert.equal(out.status, 403, origin);
    assert.equal(out.json.error, 'forbidden: cross-origin');
  }
  assert.equal(posts.length, 0);
});

test('Host 头缺失且无 token → 403 host-header-required（0.8.2 的绕过形状）', async () => {
  const { admin } = bootAdmin();
  const out = await hit(admin, { path: '/api/lan-peers/state', headers: { host: '' } });
  assert.equal(out.status, 403);
  assert.equal(out.json.error, 'forbidden: host-header-required');
});

test('Host 缺失但 token 对（Electron IPC 桥）→ 放行：token 才是真正的门', async () => {
  const { admin } = bootAdmin();
  const out = await hit(admin, { path: '/api/lan-peers/state', headers: { host: '', 'x-lan-peers-token': TOKEN } });
  assert.equal(out.status, 200, JSON.stringify(out.json));
  assert.equal(out.json.name, 'me');
});

test('非回环 Host（LAN 地址 / 元数据地址）→ 403 loopback-only', async () => {
  const { admin } = bootAdmin();
  for (const host of ['192.168.1.9:7788', '169.254.169.254', 'evil.example:7788']) {
    const out = await hit(admin, { path: '/api/lan-peers/state', headers: { host, 'x-lan-peers-token': TOKEN } });
    assert.equal(out.status, 403, host);
    assert.equal(out.json.error, 'forbidden: loopback-only');
  }
});

test('panel.js 免 token：宿主直出，token 门禁不会把它一起挡住', async () => {
  const { admin } = bootAdmin();
  const out = await hit(admin, { path: '/api/lan-peers/panel.js' });
  // 真机上 lib/index.js 用 exact 路由先接走 panel.js；哪怕落到 admin 的 prefix，
  // 它也只能是 404（本模块不管这个路径），绝不能是 401 —— 那会让面板连脚本都拉不到。
  assert.notEqual(out.status, 401, 'panel.js 不能因为缺 token 被挡：token 就在脚本里');
  assert.notEqual(out.status, 403, 'panel.js 不受 Host/Origin 门禁影响');
  assert.equal(out.status, 404, 'admin 不接管 panel.js（宿主直出）');
});

test('client-log 免 token（老面板兼容），但仍只收 JSON', async () => {
  const { admin } = bootAdmin();
  const ok = await hit(admin, {
    method: 'POST',
    path: '/api/lan-peers/client-log',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ event: 'module-loaded' }),
  });
  assert.equal(ok.status, 200, ok.raw);
  const notJson = await hit(admin, {
    method: 'POST',
    path: '/api/lan-peers/client-log',
    headers: { 'content-type': 'text/plain' },
    body: 'x',
  });
  assert.equal(notJson.status, 415);
});

test('token 不进 URL、不进日志、不进错误体', async () => {
  const { admin, logged } = bootAdmin();
  const out = await hit(admin, { path: '/api/lan-peers/state' });
  assert.doesNotMatch(out.raw, new RegExp(TOKEN), '错误体不得回显 token');
  assert.doesNotMatch(String(admin.prefix), new RegExp(TOKEN));
  const accepted = await hit(admin, { path: '/api/lan-peers/state', headers: { 'x-lan-peers-token': TOKEN } });
  assert.equal(accepted.status, 200);
  assert.equal(logged.some((line) => String(line).includes(TOKEN)), false, '日志里不得出现 token');
});

test('<stateDir>/admin-token 由 admin 启动时写入，内容就是进程 token', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-lan-peers-admin-token-'));
  try {
    const { admin } = bootAdmin({ stateDir: dir });
    const file = path.join(dir, 'admin-token');
    assert.equal(fs.existsSync(file), true, 'CLI 要读的那个文件必须存在');
    assert.equal(fs.readFileSync(file, 'utf8').trim(), admin.token, '文件内容就是同一个 token');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// 正常路径：真面板脚本 → 真 admin.handle（桥接器只搬运，不伪造安全判断）
// ---------------------------------------------------------------------------

function makeElement(tag) {
  const cache = new Map();
  const el = {
    tagName: String(tag).toUpperCase(),
    id: '',
    className: '',
    textContent: '',
    value: '',
    style: {},
    disabled: false,
    children: [],
    listeners: new Map(),
    offsetWidth: 96,
    offsetHeight: 36,
    onclick: null,
    appendChild(child) { this.children.push(child); return child; },
    addEventListener(type, fn) {
      if (!this.listeners.has(type)) this.listeners.set(type, []);
      this.listeners.get(type).push(fn);
    },
    removeEventListener() {},
    setPointerCapture() {},
    releasePointerCapture() {},
    getBoundingClientRect() { return { left: 0, top: 0, width: this.offsetWidth, height: this.offsetHeight }; },
    querySelector(selector) {
      const id = String(selector).replace(/^#/, '');
      if (!cache.has(id)) cache.set(id, makeElement('div'));
      return cache.get(id);
    },
  };
  let html = '';
  Object.defineProperty(el, 'innerHTML', {
    get: () => html,
    set: (value) => { html = value; if (value === '') el.children.length = 0; },
  });
  return el;
}

const flush = async (rounds = 20) => {
  for (let i = 0; i < rounds; i += 1) await new Promise((resolve) => setTimeout(resolve, 1));
};

/** 面板脚本 → 真 handler：只把 fetch 的 init 搬成 Node 的 req，安全判断全在 admin 里。 */
function bootPanel(admin) {
  const calls = [];
  const document = {
    head: makeElement('head'),
    body: makeElement('body'),
    hidden: false,
    createElement: (tag) => makeElement(tag),
  };
  const fetchStub = async (url, init = {}) => {
    const apiPath = String(url).replace('/api/lan-peers/', '');
    const method = String(init.method || 'GET').toUpperCase();
    const sentHeaders = Object.assign({}, init.headers || {});
    const loweredHeaders = {};
    for (const [key, value] of Object.entries(sentHeaders)) loweredHeaders[String(key).toLowerCase()] = String(value);
    calls.push({ path: apiPath, method, headers: loweredHeaders });
    const res = makeResponse();
    const req = makeReq({ method, path: '/api/lan-peers/' + apiPath, headers: loweredHeaders, body: init.body });
    await admin.handle(req, res, new URL('http://127.0.0.1' + req.url));
    return {
      ok: res.status >= 200 && res.status < 300,
      status: res.status,
      json: async () => jsonOf(res) || {},
    };
  };
  const window = {
    innerWidth: 1000,
    innerHeight: 800,
    addEventListener() {},
    confirm: () => true,
    localStorage: { getItem: () => null, setItem: () => {} },
  };
  vm.runInNewContext(PANEL_SCRIPT, {
    window,
    document,
    localStorage: window.localStorage,
    fetch: fetchStub,
    setInterval: () => 0,
    clearInterval: () => {},
    setTimeout: () => 0,
    clearTimeout: () => {},
    JSON, Math, console,
  });
  const btn = document.body.children.find((el) => el.id === 'dshLpBtn');
  const panel = document.body.children.find((el) => el.id === 'dshLpPanel');
  return { btn, panel, window, calls };
}

test('面板脚本自带 token（并设 React 半读的那个全局），且与 admin 是同一份', async () => {
  assert.match(PANEL_SCRIPT, /const T = '[0-9a-f]{64}';/, 'token 必须是面板脚本里的字面量');
  const { admin } = bootAdmin();
  const page = bootPanel(admin);
  assert.equal(page.window.__lanPeersToken, admin.token, 'panel.js 加载即设置 window.__lanPeersToken');
});

test('正常路径：面板用自带 token 完成一次 GET state，渲染出伙伴', async () => {
  const { admin } = bootAdmin();
  const page = bootPanel(admin);
  page.btn.onclick();
  await flush();
  const stateCall = page.calls.find((call) => call.path === 'state');
  assert.ok(stateCall, '打开面板必须 GET state');
  assert.equal(stateCall.headers['x-lan-peers-token'], admin.token, 'token 只走请求头');
  assert.equal(page.calls.some((call) => call.path.includes(admin.token)), false, 'token 绝不能进 URL');
  assert.match(page.panel.querySelector('#dshLpMsg').textContent, /^$/, '正常路径不写错误文案');
});

test('正常路径：面板用自带 token 完成一次 POST group/post（JSON + 200）', async () => {
  const { admin, posts } = bootAdmin();
  const page = bootPanel(admin);
  page.btn.onclick();
  await flush();
  page.panel.querySelector('#dshLpGroupText').value = '晚上好';
  page.panel.querySelector('#dshLpGroupSend').onclick();
  await flush();
  const posted = page.calls.find((call) => call.path === 'group/post');
  assert.ok(posted, '必须发出 POST group/post');
  assert.equal(posted.method, 'POST');
  assert.equal(posted.headers['x-lan-peers-token'], admin.token);
  assert.equal(posted.headers['content-type'], 'application/json', '面板自己也补齐 JSON 头');
  assert.deepEqual(posts, [{ kind: 'chat', text: '晚上好', meta: {} }], '请求真的落到了群后端');
  assert.equal(page.panel.querySelector('#dshLpMsg').textContent, '已发送');
});
// ---------------------------------------------------------------------------
// M6：配对码不再回显（只有生成那一次的响应里有）
// ---------------------------------------------------------------------------

test('M6 · 发码只回一次：POST code 带码，GET state 只回 active/expiresInSec', async () => {
  const { admin } = bootAdmin();
  const issued = await hit(admin, {
    method: 'POST',
    path: '/api/lan-peers/code',
    headers: { 'x-lan-peers-token': TOKEN, 'content-type': 'application/json' },
    body: '{}',
  });
  assert.equal(issued.status, 200, issued.raw);
  assert.equal(issued.json.code, '654321', '一次性提示里必须有码，否则用户永远拿不到');

  const state = await hit(admin, { path: '/api/lan-peers/state', headers: { 'x-lan-peers-token': TOKEN } });
  assert.equal(state.status, 200);
  assert.equal(state.json.pairing.active, true);
  assert.equal(typeof state.json.pairing.expiresInSec, 'number');
  assert.ok(state.json.pairing.expiresInSec > 0 && state.json.pairing.expiresInSec <= 600, '剩余秒数要如实给出');
  assert.equal(JSON.stringify(state.json).includes('654321'), false, 'GET state 绝不回显配对码');
});

test('M6 · 没有码时 GET state 回 active:false（形状固定，面板不用猜）', async () => {
  const { admin } = bootAdmin();
  const state = await hit(admin, { path: '/api/lan-peers/state', headers: { 'x-lan-peers-token': TOKEN } });
  assert.deepEqual(state.json.pairing, { active: false, expiresInSec: 0 });
});
