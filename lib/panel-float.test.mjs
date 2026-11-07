// dsh-lan-peers · v0.9.0 面板悬浮卡：标题栏拖动 + Ctrl+滚轮缩放 + 界面字号。
//
// 面板是直出脚本（浏览器 JS），不能 import：这里用与 lib/panel-drag.test.mjs 同一套
// 最小 DOM 桩 + node:vm 跑真 PANEL_SCRIPT，断言拖动/缩放/字号的行为与落盘，
// 再用 createAdmin 跑真路由断言 config.json 的读写与非法值 400。
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import { PANEL_SCRIPT, createAdmin, renderPanelScript } from './admin.mjs';
import { keys, t } from './i18n.mjs';

const VIEW = { w: 1000, h: 800 };
const POS_KEY = 'dsh-lan-peers:panel-pos:v1';
const px = (value) => Number.parseFloat(String(value));

// ---------------------------------------------------------------------------
// 最小 DOM 桩：与 panel-drag.test.mjs 同款，额外支持 style.setProperty 两种形态
// （真实浏览器的 CSSStyleDeclaration 有它；纯对象桩没有，脚本两条路都得走通）。
// ---------------------------------------------------------------------------
function makeStyle(withSetProperty) {
  const bag = {};
  if (withSetProperty) bag.setProperty = (name, value) => { bag[name] = value; };
  return bag;
}

function makeElement(tag, options) {
  const opts = options || {};
  const cache = new Map();
  const el = {
    tagName: String(tag).toUpperCase(),
    id: '',
    className: '',
    textContent: '',
    innerHTML: '',
    value: '',
    placeholder: '',
    disabled: false,
    type: '',
    min: '',
    max: '',
    step: '',
    title: '',
    style: makeStyle(opts.styleSetProperty === true),
    children: [],
    listeners: new Map(),
    offsetWidth: 96,
    offsetHeight: 36,
    onclick: null,
    onchange: null,
    oninput: null,
    appendChild(child) { this.children.push(child); return child; },
    addEventListener(type, fn) {
      if (!this.listeners.has(type)) this.listeners.set(type, []);
      this.listeners.get(type).push(fn);
    },
    removeEventListener() {},
    setPointerCapture() {},
    releasePointerCapture() {},
    getBoundingClientRect() {
      const num = (raw) => Number.parseFloat(String(raw)) || 0;
      const top = String(this.style.top == null ? 'auto' : this.style.top) === 'auto'
        ? VIEW.h - num(this.style.bottom) - (this.offsetHeight || 0)
        : num(this.style.top);
      return { left: num(this.style.left), top, width: this.offsetWidth, height: this.offsetHeight };
    },
    querySelector(selector) {
      const id = String(selector).replace(/^#/, '');
      if (!cache.has(id)) cache.set(id, makeElement('div'));
      return cache.get(id);
    },
    fire(type, event) {
      for (const fn of this.listeners.get(type) || []) fn(event);
    },
  };
  let html = '';
  Object.defineProperty(el, 'innerHTML', {
    get: () => html,
    set: (value) => { html = value; if (value === '') el.children.length = 0; },
  });
  return el;
}

/**
 * 跑一份面板脚本：fetch 记录每一次调用，setTimeout 进可手动 flush 的队列（去抖要验），
 * window.resize 也能手动派发。boot 出来的东西足够断言拖动/缩放/字号三条链路。
 */
function boot(script, options) {
  const opts = options || {};
  const store = new Map(opts.store ? Array.from(opts.store) : []);
  const calls = [];
  const timers = [];
  const created = [];
  const windowListeners = new Map();
  const document = {
    head: makeElement('head'),
    body: makeElement('body'),
    hidden: false,
    createElement: (tag) => {
      const el = makeElement(tag, { styleSetProperty: opts.styleSetProperty === true });
      created.push(el);
      return el;
    },
  };
  const json = (body) => ({ ok: true, status: 200, json: async () => body });
  const fetchStub = async (url, init) => {
    const apiPath = String(url).replace('/api/lan-peers/', '');
    const body = init && init.body ? JSON.parse(init.body) : null;
    calls.push({ path: apiPath, method: (init && init.method) || 'GET', body });
    if (apiPath === 'state') return json({ name: 'me', instanceId: 'me-id', peers: [], pairing: null });
    if (apiPath === 'panel-ui') return json({ ok: true, scale: body && body.scale, fontPx: body && body.fontPx });
    if (apiPath === 'dispatch/settings') {
      return json({ defaultWorkspaceId: '', maxPermission: 'workspace-write', workspaces: [] });
    }
    if (apiPath === 'dispatch/pending') return json({ items: [] });
    if (apiPath === 'lang') return json({ lang: 'zh', effective: 'zh' });
    return json({});
  };
  const window = {
    innerWidth: VIEW.w,
    innerHeight: VIEW.h,
    addEventListener(type, fn) {
      if (!windowListeners.has(type)) windowListeners.set(type, []);
      windowListeners.get(type).push(fn);
    },
    confirm: () => true,
    localStorage: {
      getItem: (key) => (store.has(key) ? store.get(key) : null),
      setItem: (key, value) => store.set(key, String(value)),
    },
  };
  const sandbox = {
    window,
    document,
    localStorage: window.localStorage,
    fetch: fetchStub,
    setInterval: () => 0,
    clearInterval: () => {},
    setTimeout: (fn) => { timers.push(fn); return timers.length; },
    clearTimeout: (id) => { if (id) timers[id - 1] = null; },
    JSON,
    Math,
    Promise,
    console,
  };
  vm.runInNewContext(script, sandbox);
  const panel = document.body.children.find((el) => el.id === 'dshLpPanel');
  const btn = document.body.children.find((el) => el.id === 'dshLpBtn');
  assert.ok(btn, '启动按钮必须挂进 document.body');
  assert.ok(panel, '面板必须挂进 document.body');
  const head = panel.querySelector('#dshLpPanelHead');
  return {
    panel,
    btn,
    head,
    store,
    calls,
    json,
    window,
    byId: (id) => created.find((el) => el.id === id),
    flushTimers: () => {
      const pending = timers.splice(0, timers.length).filter(Boolean);
      for (const fn of pending) fn();
      return pending.length;
    },
    resizeTo: (w, h) => {
      window.innerWidth = w;
      window.innerHeight = h;
      for (const fn of windowListeners.get('resize') || []) fn({});
    },
  };
}

const flush = async (rounds) => {
  for (let i = 0; i < (rounds || 40); i += 1) await new Promise((resolve) => setTimeout(resolve, 1));
};

/** 打开面板（真实用法就是点一下启动按钮），返回面板节点。 */
async function open(app) {
  app.btn.onclick();
  await flush();
  assert.equal(app.panel.style.display, 'block', '面板必须已打开');
  return app.panel;
}

const uiPosts = (calls) => calls.filter((call) => call.path === 'panel-ui' && call.method === 'POST');

// ---------------------------------------------------------------------------
// ① 默认外观与改造前完全一致：scale(1) / 16px
// ---------------------------------------------------------------------------
test('默认外观与改造前一致：transform=scale(1)、--lp-font-px=16px（浏览器 setProperty 那条路）', () => {
  const app = boot(PANEL_SCRIPT);
  assert.equal(app.panel.style.transform, 'scale(1)');
  assert.equal(app.panel.style.transformOrigin, '0 0', '缩放原点取左上，拖动仍是一比一');
  assert.equal(app.panel.style['--lp-font-px'], '16px');
  assert.equal(px(app.panel.style.width), 320, 'scale=1 时 CSS 宽度仍是 320px');
  const real = boot(PANEL_SCRIPT, { styleSetProperty: true });
  assert.equal(real.panel.style['--lp-font-px'], '16px', 'CSSStyleDeclaration 上也写得进去');
});

test('注入值来自服务端：renderPanelScript(token, lang, ui) 把 scale/fontPx 放进 PANEL_UI', () => {
  const script = renderPanelScript('tok', 'zh', { scale: 1.6, fontPx: 20 });
  assert.match(script, /const PANEL_UI = \{"scale":1.6,"fontPx":20\};/);
  const app = boot(script);
  assert.equal(app.panel.style.transform, 'scale(1.6)');
  assert.equal(app.panel.style['--lp-font-px'], '20px');
  assert.equal(px(app.panel.style.width), 200, '320 / 1.6：视觉宽度不变，只放大内容');
  // 越界的注入值由 panelUiOf 兜回默认，绝不把 NaN 或 9 放大到屏幕上。
  const bad = renderPanelScript('tok', 'zh', { scale: 9, fontPx: -3 });
  assert.match(bad, /const PANEL_UI = \{"scale":1,"fontPx":16\};/);
});

// ---------------------------------------------------------------------------
// ② 拖动：4px 阈值 / 跟随 / 松手落盘 / 边界钳制 / resize 重新钳制
// ---------------------------------------------------------------------------
test('标题栏拖动：≥4px 才跟随，松手写 dsh-lan-peers:panel-pos:v1', async () => {
  const app = boot(PANEL_SCRIPT);
  const panel = await open(app);
  const startLeft = px(panel.style.left);
  const startTop = px(panel.style.top) || panel.getBoundingClientRect().top;

  app.head.fire('pointerdown', { button: 0, pointerId: 1, clientX: 700, clientY: 400 });
  app.head.fire('pointermove', { pointerId: 1, clientX: 750, clientY: 410 });
  app.head.fire('pointerup', { pointerId: 1, clientX: 750, clientY: 410 });

  assert.equal(px(panel.style.left), startLeft + 50, '拖动 1:1 跟手');
  assert.equal(px(panel.style.top), startTop + 10);
  assert.equal(panel.style.bottom, 'auto', '拖过之后不再用 bottom 定位');
  assert.deepEqual(JSON.parse(app.store.get(POS_KEY)), { x: startLeft + 50, y: startTop + 10 });
});

test('位移 <4px 不算拖动：位置不变、localStorage 不写', async () => {
  const app = boot(PANEL_SCRIPT);
  const panel = await open(app);
  const startLeft = px(panel.style.left);

  app.head.fire('pointerdown', { button: 0, pointerId: 2, clientX: 700, clientY: 400 });
  app.head.fire('pointermove', { pointerId: 2, clientX: 702, clientY: 401 });
  app.head.fire('pointerup', { pointerId: 2, clientX: 702, clientY: 401 });

  assert.equal(px(panel.style.left), startLeft, '3px 抖动不许挪卡片');
  assert.equal(app.store.has(POS_KEY), false, '没真拖动就不该写位置');
});

test('拖出视口会被钳制：标题栏至少留 80px 可见', async () => {
  const app = boot(PANEL_SCRIPT);
  const panel = await open(app);

  app.head.fire('pointerdown', { button: 0, pointerId: 3, clientX: 700, clientY: 400 });
  app.head.fire('pointermove', { pointerId: 3, clientX: 9000, clientY: 9000 });
  app.head.fire('pointerup', { pointerId: 3, clientX: 9000, clientY: 9000 });
  assert.equal(px(panel.style.left), VIEW.w - 80, '右侧最多只剩 80px 在视口里');
  assert.equal(px(panel.style.top), VIEW.h - 80, '底部同理');

  app.head.fire('pointerdown', { button: 0, pointerId: 4, clientX: 700, clientY: 400 });
  app.head.fire('pointermove', { pointerId: 4, clientX: -9000, clientY: -9000 });
  app.head.fire('pointerup', { pointerId: 4, clientX: -9000, clientY: -9000 });
  const saved = JSON.parse(app.store.get(POS_KEY));
  assert.equal(px(panel.style.left), 80 - 320, '左侧最多移出 (宽度-80)');
  assert.equal(px(panel.style.top), 0);
  assert.deepEqual(saved, { x: 80 - 320, y: 0 }, '钳制之后的值才是落盘的值');
});

test('resize 之后仍然在界内（缩窗口会把卡片拉回来）', async () => {
  const app = boot(PANEL_SCRIPT);
  const panel = await open(app);
  app.head.fire('pointerdown', { button: 0, pointerId: 5, clientX: 700, clientY: 400 });
  app.head.fire('pointermove', { pointerId: 5, clientX: 9000, clientY: 3000 });
  app.head.fire('pointerup', { pointerId: 5, clientX: 9000, clientY: 3000 });
  assert.equal(px(panel.style.left), VIEW.w - 80);

  app.resizeTo(400, 300);
  const left = px(panel.style.left);
  const top = px(panel.style.top);
  assert.ok(left <= 400 - 80, '右边的 80px 还得在视口里，实际 left=' + left);
  assert.ok(left + 320 >= 80, '左边的 80px 也得在视口里，实际 left=' + left);
  assert.ok(top >= 0 && top <= 300 - 80, '标题栏纵向也要留住，实际 top=' + top);
});

test('存档的面板位置下次打开被采用', async () => {
  const store = new Map([[POS_KEY, JSON.stringify({ x: 120, y: 140 })]]);
  const app = boot(PANEL_SCRIPT, { store });
  const panel = await open(app);
  assert.equal(px(panel.style.left), 120);
  assert.equal(px(panel.style.top), 140);
});

// ---------------------------------------------------------------------------
// ③ Ctrl+滚轮缩放：步进 0.1 / 钳制 0.8-2.0 / 400ms 去抖后 POST / 普通滚轮不动
// ---------------------------------------------------------------------------
test('Ctrl+滚轮每步 0.1，钳制在 0.8-2.0，去抖 400ms 后 POST panel-ui', async () => {
  const app = boot(PANEL_SCRIPT);
  const panel = await open(app);
  const before = uiPosts(app.calls).length;

  app.panel.fire('wheel', { ctrlKey: true, deltaY: -120, preventDefault() {} });
  assert.equal(panel.style.transform, 'scale(1.1)', '向上滚一格 = +0.1');
  assert.equal(app.byId('dshLpSetScale').value, '1.1', '设置页滑块要跟着走');

  // 去抖：连着滚三格只落盘一次，且是最后那一个值。
  app.panel.fire('wheel', { ctrlKey: true, deltaY: -120, preventDefault() {} });
  app.panel.fire('wheel', { ctrlKey: true, deltaY: -120, preventDefault() {} });
  assert.equal(panel.style.transform, 'scale(1.3)');
  assert.equal(uiPosts(app.calls).length, before, '去抖期间不许发请求');

  app.flushTimers();
  await flush();
  const posts = uiPosts(app.calls);
  assert.equal(posts.length, before + 1, '400ms 到了只发一次 POST');
  assert.deepEqual(posts[posts.length - 1].body, { scale: 1.3, fontPx: 16 }, '载荷字段名与设计一致');

  // 上界 / 下界。
  for (let i = 0; i < 20; i += 1) app.panel.fire('wheel', { ctrlKey: true, deltaY: -120, preventDefault() {} });
  assert.equal(panel.style.transform, 'scale(2)');
  for (let i = 0; i < 40; i += 1) app.panel.fire('wheel', { ctrlKey: true, deltaY: 120, preventDefault() {} });
  assert.equal(panel.style.transform, 'scale(0.8)');
});

test('普通滚轮不改变缩放（消息列表还要靠它滚）', async () => {
  const app = boot(PANEL_SCRIPT);
  const panel = await open(app);
  const before = uiPosts(app.calls).length;
  let prevented = 0;

  app.panel.fire('wheel', { ctrlKey: false, deltaY: -300, preventDefault() { prevented += 1; } });
  app.panel.fire('wheel', { deltaY: 300, preventDefault() { prevented += 1; } });
  app.flushTimers();
  await flush();

  assert.equal(panel.style.transform, 'scale(1)', '普通滚轮一格都不许动缩放');
  assert.equal(prevented, 0, '普通滚轮不许 preventDefault（否则列表滚不动）');
  assert.equal(uiPosts(app.calls).length, before, '普通滚轮不该发 panel-ui 请求');
});

// ---------------------------------------------------------------------------
// ④ 设置页两行：界面字号下拉 + 面板缩放滑块（含重置）
// ---------------------------------------------------------------------------
test('设置页字号下拉：12/14/16/18/20，改完根节点变量变化并 POST', async () => {
  const app = boot(PANEL_SCRIPT);
  await open(app);
  app.panel.querySelector('#dshLpTabSettings').onclick();
  await flush();

  const select = app.byId('dshLpSetFont');
  assert.ok(select, '设置页必须有界面字号下拉');
  assert.deepEqual(select.children.map((opt) => opt.value), ['12', '14', '16', '18', '20']);
  assert.equal(select.value, '16', '打开设置页要回读当前字号');

  select.value = '20';
  select.onchange();
  assert.equal(app.panel.style['--lp-font-px'], '20px', '根节点 CSS 变量立刻跟着变');
  await flush();
  const posts = uiPosts(app.calls);
  assert.equal(posts.length, 1);
  assert.deepEqual(posts[0].body, { scale: 1, fontPx: 20 });
  assert.equal(app.panel.style.transform, 'scale(1)', '改字号不该动缩放');
});

test('设置页缩放滑块：0.8-2.0 步进 0.1，拖动先本地生效、去抖后落盘；重置回 1.0/16', async () => {
  const app = boot(PANEL_SCRIPT);
  await open(app);
  app.panel.querySelector('#dshLpTabSettings').onclick();
  await flush();

  const slider = app.byId('dshLpSetScale');
  assert.ok(slider, '设置页必须有面板缩放滑块');
  assert.equal(slider.min, '0.8');
  assert.equal(slider.max, '2');
  assert.equal(slider.step, '0.1');
  assert.equal(slider.value, '1');

  slider.value = '1.5';
  slider.oninput();
  assert.equal(app.panel.style.transform, 'scale(1.5)', '拖滑块要实时生效');
  assert.equal(app.byId('dshLpSetScaleValue').textContent, '1.5x');
  assert.equal(uiPosts(app.calls).length, 0, '拖动期间只去抖，不发请求');
  app.flushTimers();
  await flush();
  assert.deepEqual(uiPosts(app.calls)[0].body, { scale: 1.5, fontPx: 16 });

  app.byId('dshLpSetUiReset').onclick();
  await flush();
  assert.equal(app.panel.style.transform, 'scale(1)');
  assert.equal(app.panel.style['--lp-font-px'], '16px');
  assert.equal(app.byId('dshLpSetScaleValue').textContent, '1.0x');
  const posts = uiPosts(app.calls);
  assert.deepEqual(posts[posts.length - 1].body, { scale: 1, fontPx: 16 }, '重置也要落盘');
});

// ---------------------------------------------------------------------------
// ⑤ 服务端：GET/POST /api/lan-peers/panel-ui（同一个 config.json，保留其它键）
// ---------------------------------------------------------------------------
const CONFIG_FILE = 'config.json';
const configFileOf = (dir) => path.join(dir, CONFIG_FILE);
const readConfig = (dir) => JSON.parse(fs.readFileSync(configFileOf(dir), 'utf8'));
const makeTempStateDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'lan-peers-float-'));

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

function makeRequest(method, apiPath, options) {
  const opts = options || {};
  const payload = opts.body === undefined ? '' : JSON.stringify(opts.body);
  const headers = { host: '127.0.0.1:7788', 'content-length': String(Buffer.byteLength(payload)) };
  if (opts.token) headers['x-lan-peers-token'] = opts.token;
  if (payload !== '') headers['content-type'] = 'application/json';
  const req = {
    method,
    url: apiPath,
    socket: { remoteAddress: '127.0.0.1', setNoDelay() {} },
    headers,
    on() { return req; },
    once() { return req; },
    async *[Symbol.asyncIterator]() { if (payload !== '') yield Buffer.from(payload, 'utf8'); },
  };
  return req;
}

async function hit(admin, method, apiPath, options) {
  const res = makeResponse();
  const handled = await admin.handle(makeRequest(method, apiPath, options), res, new URL('http://127.0.0.1' + apiPath));
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
  return { admin: createAdmin({ server, nameOf: () => 'me', rename: (n) => n }), lines };
}

test('GET panel-ui：默认 { scale: 1, fontPx: 16 }，且只读接口不写文件', async () => {
  const dir = makeTempStateDir();
  const { admin } = bootAdmin(dir);
  const got = await hit(admin, 'GET', '/api/lan-peers/panel-ui', { token: admin.token });
  assert.equal(got.status, 200);
  assert.deepEqual(got.json, { scale: 1, fontPx: 16 });
  assert.equal(fs.existsSync(configFileOf(dir)), false, '只读接口不该顺手写文件');
});

test('POST panel-ui：落盘 0600、保留 lang 等其它键、重渲面板脚本带上新值', async () => {
  const dir = makeTempStateDir();
  fs.writeFileSync(configFileOf(dir), JSON.stringify({ lang: 'en', listenPort: 7788, keep: 'me' }, null, 2) + '\n');
  const { admin, lines } = bootAdmin(dir);

  const saved = await hit(admin, 'POST', '/api/lan-peers/panel-ui', {
    token: admin.token,
    body: { scale: 1.4, fontPx: 18 },
  });
  assert.equal(saved.status, 200);
  assert.deepEqual(saved.json, { ok: true, scale: 1.4, fontPx: 18 });

  const config = readConfig(dir);
  assert.equal(config.panelScale, 1.4);
  assert.equal(config.panelFontPx, 18);
  assert.equal(config.lang, 'en', '同一个文件里的 lang 必须原样保留');
  assert.equal(config.listenPort, 7788, '其它键同样保留');
  assert.equal(config.keep, 'me');
  if (process.platform !== 'win32') {
    assert.equal(fs.statSync(configFileOf(dir)).mode & 0o777, 0o600, '配置文件必须 0600');
  }
  assert.deepEqual(
    fs.readdirSync(dir).filter((name) => name.startsWith(CONFIG_FILE + '.')),
    [],
    '原子写的临时文件必须已经被 rename 走掉',
  );
  assert.deepEqual(lines.filter((line) => line.includes('panel-ui')), ['[admin] panel-ui scale=1.4 fontPx=18']);

  // 重渲：活绑定里真的带上新值（刷新页面即生效，不用重载插件）。
  assert.match(PANEL_SCRIPT, /const PANEL_UI = \{"scale":1.4,"fontPx":18\};/);

  const got = await hit(admin, 'GET', '/api/lan-peers/panel-ui', { token: admin.token });
  assert.deepEqual(got.json, { scale: 1.4, fontPx: 18 });
});

test('POST panel-ui 非法值 → 400 bad-panel-ui，一个字节都不写盘', async () => {
  const dir = makeTempStateDir();
  fs.writeFileSync(configFileOf(dir), JSON.stringify({ panelScale: 1.2, panelFontPx: 14 }) + '\n');
  const before = fs.readFileSync(configFileOf(dir), 'utf8');
  const { admin } = bootAdmin(dir);

  const bads = [
    { scale: 0.5, fontPx: 16 },
    { scale: 2.1, fontPx: 16 },
    { scale: 'abc', fontPx: 16 },
    { scale: null, fontPx: 16 },
    { scale: 1.2, fontPx: 25 },
    { scale: 1.2, fontPx: 11 },
    { scale: 1.2, fontPx: 15.5 },
    { scale: 1.2, fontPx: 'abc' },
  ];
  for (const body of bads) {
    const out = await hit(admin, 'POST', '/api/lan-peers/panel-ui', { token: admin.token, body });
    assert.equal(out.status, 400, '非法值必须 400：' + JSON.stringify(body));
    assert.equal(out.json.error, 'bad-panel-ui');
  }
  assert.equal(fs.readFileSync(configFileOf(dir), 'utf8'), before, '400 不许改文件');
});

test('panel-ui 只发一个字段时另一格保持原值；坏 config.json 回落默认', async () => {
  const dir = makeTempStateDir();
  fs.writeFileSync(configFileOf(dir), JSON.stringify({ panelScale: 1.5, panelFontPx: 18 }) + '\n');
  const { admin } = bootAdmin(dir);
  const out = await hit(admin, 'POST', '/api/lan-peers/panel-ui', { token: admin.token, body: { fontPx: 12 } });
  assert.equal(out.status, 200);
  assert.deepEqual(out.json, { ok: true, scale: 1.5, fontPx: 12 });
  assert.equal(readConfig(dir).panelScale, 1.5, '没点名的字段保持原值');

  const broken = makeTempStateDir();
  fs.writeFileSync(configFileOf(broken), '{ this is not json ,,,');
  const booted = bootAdmin(broken);
  const got = await hit(booted.admin, 'GET', '/api/lan-peers/panel-ui', { token: booted.admin.token });
  assert.deepEqual(got.json, { scale: 1, fontPx: 16 }, '坏文件按默认值读，绝不让插件起不来');
});

// ---------------------------------------------------------------------------
// ⑥ 铁律：新增段零反引号、无 console.error、innerHTML 只赋空串、词条两格齐备
// ---------------------------------------------------------------------------
const NEW_KEYS = [
  'panel.settings.fontSize',
  'panel.settings.panelScale',
  'panel.settings.reset',
  'panel.settings.uiSaved',
  'panel.settings.uiFailed',
  'panel.frame.dragHint',
];

test('铁律：新增段零反引号、整段脚本无 console.error、innerHTML 只赋空串', () => {
  const BT = String.fromCharCode(96);
  const script = PANEL_SCRIPT;
  const start = script.indexOf('v0.9.0：面板外观');
  const end = script.indexOf('const $ = (id) =>');
  assert.ok(start > 0 && end > start, '新增段的切片标记必须都在脚本里');
  assert.equal(script.slice(start, end).split(BT).length - 1, 0, '新增段不许出现反引号');
  assert.equal((script.match(/console[.]error/g) || []).length, 0, '面板段不许新增 console 错误调用');
  const lines = script.split('\n').filter((line) => /innerHTML\s*=/.test(line));
  assert.ok(lines.length >= 5);
  for (const line of lines) {
    assert.ok(/innerHTML\s*=\s*(?:''|[\u0060])/.test(line.trim()), 'innerHTML 只允许赋空串或静态骨架：' + line.trim());
  }
});

test('新增词条 zh / en 两格都存在且非空（缺一边视为未完成）', () => {
  const zh = keys('zh');
  const en = keys('en');
  for (const key of NEW_KEYS) {
    assert.ok(zh.includes(key), 'zh 表缺 ' + key);
    assert.ok(en.includes(key), 'en 表缺 ' + key);
    assert.notEqual(String(t('zh', key)).trim(), '', 'zh 值不能为空：' + key);
    assert.notEqual(String(t('en', key)).trim(), '', 'en 值不能为空：' + key);
    assert.doesNotMatch(String(t('en', key)), /[\u4e00-\u9fa5]/, 'en 值不许是中文：' + key);
    assert.notEqual(String(t('en', key)), String(t('zh', key)), 'en 与 zh 一字不差等于没译：' + key);
  }
  // 脚本里真的用到了它们（不是只往词表里加了几行）。
  const script = PANEL_SCRIPT;
  for (const key of NEW_KEYS) assert.ok(script.includes("'" + key + "'"), '面板脚本没用上 ' + key);
});
