// dsh-lan-peers · v0.8.5-α（契约 §6）面板语言开关：<stateDir>/config.json 的 lang。
//
// 生效优先级（本文件逐条钉死）：stateDir/config.json 的 lang > cordis config.lang
// > 环境变量 DSH_LAN_PEERS_LANG > locale > zh。面板脚本不再用 createAdmin 那一次的结果，
// 而是跟着「当前生效语言」重渲 —— 所以改完语言刷新页面就生效，不用重载插件。
//
// 铁律：坏文件/缺 stateDir 一律回落，绝不抛错、绝不让插件起不来。
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { PANEL_SCRIPT, createAdmin } from './admin.mjs';
import { makeTempStateDir } from '../host/test/helpers.mjs';

const CONFIG_FILE = 'config.json';
const configFileOf = (dir) => path.join(dir, CONFIG_FILE);
const readConfig = (dir) => JSON.parse(fs.readFileSync(configFileOf(dir), 'utf8'));
const langOf = (script) => (String(script).match(/const I18N_LANG = '([a-z]+)';/) || [])[1] || '';

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

/** 与真实面板同形状的请求：回环 Host + token 头；写操作带 JSON content-type。 */
function makeRequest(method, apiPath, options) {
  const opts = options || {};
  const payload = opts.body === undefined ? '' : JSON.stringify(opts.body);
  const headers = {
    host: '127.0.0.1:7788',
    'content-length': String(Buffer.byteLength(payload)),
  };
  if (opts.token) headers['x-lan-peers-token'] = opts.token;
  if (payload !== '') headers['content-type'] = 'application/json';
  const req = {
    method,
    url: apiPath,
    socket: { remoteAddress: '127.0.0.1', setNoDelay() {} },
    headers,
    on() { return req; },
    once() { return req; },
    async *[Symbol.asyncIterator]() {
      if (payload !== '') yield Buffer.from(payload, 'utf8');
    },
  };
  return req;
}

async function hit(admin, method, apiPath, options) {
  const res = makeResponse();
  const handled = await admin.handle(
    makeRequest(method, apiPath, options),
    res,
    new URL('http://127.0.0.1' + apiPath),
  );
  assert.equal(handled, true, apiPath + ' 必须由 admin 接管');
  let json = null;
  try { json = JSON.parse(res.body); } catch { json = null; }
  return { status: res.status, json };
}

function bootAdmin(stateDir, options) {
  const opts = options || {};
  if (opts.env === undefined) delete process.env.DSH_LAN_PEERS_LANG;
  else process.env.DSH_LAN_PEERS_LANG = opts.env;
  const lines = [];
  const store = {
    instanceId: 'inst-self',
    stateDir,
    state: { instanceId: 'inst-self', name: 'me', createdAt: '2026-01-01T00:00:00.000Z' },
    listPeers: () => [],
    getPeer: () => null,
  };
  const config = { logger: (line) => lines.push(line), listenPort: 0 };
  if (opts.lang !== undefined) config.lang = opts.lang;
  const server = { config, store };
  const admin = createAdmin({ server, nameOf: () => 'me', rename: (n) => n });
  return { admin, lines };
}

test('① GET lang：无 token 401；有 token 回 { lang: auto, effective: <生效格> }', async () => {
  const dir = makeTempStateDir();
  const { admin } = bootAdmin(dir, { env: 'zh' });

  const denied = await hit(admin, 'GET', '/api/lan-peers/lang', {});
  assert.equal(denied.status, 401, '没有 token 必须 401');
  assert.equal(denied.json.error, 'token-required');

  const ok = await hit(admin, 'GET', '/api/lan-peers/lang', { token: admin.token });
  assert.equal(ok.status, 200);
  assert.equal(ok.json.lang, 'auto', '没点选过就是 auto');
  assert.equal(ok.json.effective, 'zh', 'env=zh 时生效格是 zh');
  assert.equal(fs.existsSync(configFileOf(dir)), false, '只读接口不该顺手写文件');
});

test('② POST lang=en：落盘 0600、保留文件里其它键、回 ok 并立刻改生效格', async () => {
  const dir = makeTempStateDir();
  fs.writeFileSync(configFileOf(dir), JSON.stringify({ listenPort: 7788, name: 'keep-me' }, null, 2) + '\n');
  const { admin, lines } = bootAdmin(dir, { env: 'zh' });

  const saved = await hit(admin, 'POST', '/api/lan-peers/lang', { token: admin.token, body: { lang: 'en' } });
  assert.equal(saved.status, 200);
  assert.deepEqual(
    { ok: saved.json.ok, lang: saved.json.lang, effective: saved.json.effective },
    { ok: true, lang: 'en', effective: 'en' },
  );

  const config = readConfig(dir);
  assert.equal(config.lang, 'en', 'lang 必须写进去');
  assert.equal(config.listenPort, 7788, '文件里其它键必须原样保留');
  assert.equal(config.name, 'keep-me', '文件里其它键必须原样保留');
  if (process.platform !== 'win32') {
    assert.equal(fs.statSync(configFileOf(dir)).mode & 0o777, 0o600, '配置文件必须 0600');
  }
  assert.deepEqual(
    fs.readdirSync(dir).filter((name) => name.startsWith(CONFIG_FILE + '.')),
    [],
    '原子写的临时文件必须已经被 rename 走掉',
  );
  assert.deepEqual(lines.filter((line) => line.includes('lang=')), ['[admin] lang=en'], '日志只记这一格的值');
  assert.equal(lines.join('\n').includes(dir), false, '日志不许出现 stateDir 路径');
});

test('③ POST 非法值 → 400 bad-lang，且一个字节都不写盘', async () => {
  const dir = makeTempStateDir();
  fs.writeFileSync(configFileOf(dir), JSON.stringify({ lang: 'zh', keep: 1 }) + '\n');
  const before = fs.readFileSync(configFileOf(dir), 'utf8');
  const { admin } = bootAdmin(dir, { env: 'zh' });

  for (const bad of ['fr', 'ZH_cn', '', 'en-US', 42, null]) {
    const out = await hit(admin, 'POST', '/api/lan-peers/lang', { token: admin.token, body: { lang: bad } });
    assert.equal(out.status, 400, '非法值必须 400：' + JSON.stringify(bad));
    assert.equal(out.json.error, 'bad-lang');
  }
  assert.equal(fs.readFileSync(configFileOf(dir), 'utf8'), before, '400 不许改文件');
});

test('④ 优先级：config.json > cordis config.lang > env > 默认，五种组合逐个核', async () => {
  // 文件点选 en，cordis 写 zh → 听文件的（界面点选比部署期 YAML 更具体）
  let dir = makeTempStateDir();
  fs.writeFileSync(configFileOf(dir), JSON.stringify({ lang: 'en' }));
  let booted = bootAdmin(dir, { lang: 'zh', env: 'zh' });
  let got = await hit(booted.admin, 'GET', '/api/lan-peers/lang', { token: booted.admin.token });
  assert.deepEqual({ lang: got.json.lang, effective: got.json.effective }, { lang: 'en', effective: 'en' });

  // 文件是 auto → 交给后续层：cordis config.lang=en 胜出
  dir = makeTempStateDir();
  fs.writeFileSync(configFileOf(dir), JSON.stringify({ lang: 'auto' }));
  booted = bootAdmin(dir, { lang: 'en', env: 'zh' });
  got = await hit(booted.admin, 'GET', '/api/lan-peers/lang', { token: booted.admin.token });
  assert.deepEqual({ lang: got.json.lang, effective: got.json.effective }, { lang: 'auto', effective: 'en' });

  // 文件里的值非法 → 等于没点选：cordis config.lang=zh 胜出
  dir = makeTempStateDir();
  fs.writeFileSync(configFileOf(dir), JSON.stringify({ lang: 'bogus' }));
  booted = bootAdmin(dir, { lang: 'zh', env: 'en' });
  got = await hit(booted.admin, 'GET', '/api/lan-peers/lang', { token: booted.admin.token });
  assert.deepEqual({ lang: got.json.lang, effective: got.json.effective }, { lang: 'auto', effective: 'zh' });

  // 没有文件、cordis 也没写 → env 胜出
  dir = makeTempStateDir();
  booted = bootAdmin(dir, { env: 'en' });
  got = await hit(booted.admin, 'GET', '/api/lan-peers/lang', { token: booted.admin.token });
  assert.deepEqual({ lang: got.json.lang, effective: got.json.effective }, { lang: 'auto', effective: 'en' });

  // 什么都没有 → zh
  dir = makeTempStateDir();
  booted = bootAdmin(dir, { env: 'zh' });
  got = await hit(booted.admin, 'GET', '/api/lan-peers/lang', { token: booted.admin.token });
  assert.deepEqual({ lang: got.json.lang, effective: got.json.effective }, { lang: 'auto', effective: 'zh' });
});

test('⑤ 面板脚本跟着当前语言走：改完不重载插件，活绑定 PANEL_SCRIPT 立刻换格', async () => {
  const dir = makeTempStateDir();
  const { admin } = bootAdmin(dir, { env: 'zh' });
  assert.equal(langOf(PANEL_SCRIPT), 'zh', '初始按 env=zh 渲');

  const saved = await hit(admin, 'POST', '/api/lan-peers/lang', { token: admin.token, body: { lang: 'en' } });
  assert.equal(saved.status, 200);
  assert.equal(langOf(PANEL_SCRIPT), 'en', '不重建 admin、不重载插件，绑定就要换到 en');
  assert.ok(PANEL_SCRIPT.includes('"panel.tab.settings":"Settings"'), 'en 格内容也要跟着换');

  await hit(admin, 'POST', '/api/lan-peers/lang', { token: admin.token, body: { lang: 'auto' } });
  assert.equal(langOf(PANEL_SCRIPT), 'zh', '设回 auto 后回到 env=zh');
  assert.equal(readConfig(dir).lang, 'auto', 'auto 本身就是合法值，要原样落盘');
});

test('⑥ 坏 config.json 不让插件起不来：get 回落 auto，post 照样能写回来', async () => {
  const dir = makeTempStateDir();
  fs.writeFileSync(configFileOf(dir), '{ this is not json ,,,');
  let booted = null;
  assert.doesNotThrow(() => { booted = bootAdmin(dir, { env: 'zh' }); }, '坏文件绝不能让 createAdmin 抛错');
  const { admin } = booted;

  const got = await hit(admin, 'GET', '/api/lan-peers/lang', { token: admin.token });
  assert.equal(got.status, 200);
  assert.deepEqual({ lang: got.json.lang, effective: got.json.effective }, { lang: 'auto', effective: 'zh' });

  const saved = await hit(admin, 'POST', '/api/lan-peers/lang', { token: admin.token, body: { lang: 'en' } });
  assert.equal(saved.status, 200);
  assert.deepEqual(readConfig(dir), { lang: 'en' }, '坏文件按空对象重建，不把坏内容抄进去');
});

test('⑦ 没有 stateDir：GET 仍可用（auto），POST 回 501 而不是抛错', async () => {
  process.env.DSH_LAN_PEERS_LANG = 'zh';
  const lines = [];
  const store = {
    instanceId: 'inst-self',
    state: { instanceId: 'inst-self', name: 'me', createdAt: '2026-01-01T00:00:00.000Z' },
    listPeers: () => [],
    getPeer: () => null,
  };
  const admin = createAdmin({
    server: { config: { logger: (line) => lines.push(line), listenPort: 0 }, store },
    nameOf: () => 'me',
    rename: (n) => n,
  });

  const got = await hit(admin, 'GET', '/api/lan-peers/lang', { token: admin.token });
  assert.equal(got.status, 200);
  assert.deepEqual({ lang: got.json.lang, effective: got.json.effective }, { lang: 'auto', effective: 'zh' });

  const saved = await hit(admin, 'POST', '/api/lan-peers/lang', { token: admin.token, body: { lang: 'en' } });
  assert.equal(saved.status, 501, '没有落盘口就如实说，而不是假装存了');
  assert.equal(saved.json.error, 'no-state-dir');
});
// ---------------------------------------------------------------------------
// ⑧ 面板「设置」页那个下拉：三个选项就是语言名、选完就 POST、成功后在 msg 区说一句。
// ---------------------------------------------------------------------------
function makeElement(tag) {
  const cache = new Map();
  const el = {
    tagName: String(tag).toUpperCase(),
    id: '', className: '', textContent: '', value: '', placeholder: '', maxLength: 0,
    style: {}, disabled: false, selected: false, children: [], listeners: new Map(),
    offsetWidth: 96, offsetHeight: 36, onclick: null,
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

async function bootPanel(langScript) {
  const created = [];
  const calls = [];
  const document = {
    head: makeElement('head'),
    body: makeElement('body'),
    hidden: false,
    createElement: (tag) => { const el = makeElement(tag); created.push(el); return el; },
  };
  const json = (body) => ({ ok: true, status: 200, json: async () => body });
  const fetchStub = async (url, init) => {
    const apiPath = String(url).replace('/api/lan-peers/', '');
    const body = init && init.body ? JSON.parse(init.body) : null;
    calls.push({ path: apiPath, method: (init && init.method) || 'GET', body });
    if (apiPath === 'state') return json({ name: 'me', instanceId: 'me-id', peers: [], pairing: null });
    if (apiPath === 'lang' && (init && init.method) === 'POST') return json({ ok: true, lang: body.lang, effective: 'en' });
    if (apiPath === 'lang') return json({ lang: 'zh', effective: 'zh' });
    if (apiPath === 'dispatch/settings') return json({ defaultWorkspaceId: '', maxPermission: 'workspace-write', workspaces: [] });
    if (apiPath === 'dispatch/pending') return json({ items: [] });
    return json({});
  };
  const window = {
    innerWidth: 1000, innerHeight: 800, addEventListener() {}, confirm: () => true,
    localStorage: { getItem: () => null, setItem: () => {} },
  };
  vm.runInNewContext(langScript, {
    window, document, localStorage: window.localStorage, fetch: fetchStub,
    setInterval: () => 1, clearInterval: () => {}, setTimeout: () => 0, clearTimeout: () => {},
    JSON, Math, Promise, console,
  });
  const panel = document.body.children.find((el) => el.id === 'dshLpPanel');
  const btn = document.body.children.find((el) => el.id === 'dshLpBtn');
  const byId = (id) => created.find((el) => el.id === id);
  return { panel, btn, calls, byId, msgBox: panel.querySelector('#dshLpMsg') };
}

const flush = async (rounds) => {
  for (let i = 0; i < (rounds || 40); i += 1) await new Promise((resolve) => setTimeout(resolve, 1));
};

test('⑧ 设置页下拉：三个选项是语言名，选完 POST lang，成功后 msg 区提示并触发刷新', async () => {
  const app = await bootPanel(PANEL_SCRIPT);
  app.btn.onclick();
  await flush();
  app.panel.querySelector('#dshLpTabSettings').onclick();
  await flush();

  const select = app.byId('dshLpSetLang');
  assert.ok(select, '设置页必须有语言下拉');
  assert.deepEqual(select.children.map((opt) => opt.value), ['zh', 'en', 'auto']);
  assert.deepEqual(select.children.map((opt) => opt.textContent), ['中文', 'English', '自动 / Auto']);
  assert.equal(select.value, 'zh', '打开设置页要回读当前点选值');

  select.value = 'en';
  select.onchange();
  await flush();
  const posted = app.calls.filter((call) => call.path === 'lang' && call.method === 'POST');
  assert.equal(posted.length, 1, '选完就要发一次 POST');
  assert.deepEqual(posted[0].body, { lang: 'en' });
  assert.equal(app.msgBox.textContent, '已保存，正在刷新…', '成功要在 msg 区说清楚');
  assert.equal(app.byId('dshLpSetLang').value, 'en', '选中项保持用户刚选的那一格');
});
