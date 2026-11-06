// dsh-lan-peers · 401 自愈（0.8.5-α 真机：插件重启换了 token，已打开的面板永不恢复）
//
// 现场：日志里 listening on 已 80 次 —— 每次重启 ADMIN_TOKEN 都重新生成。页面如果是在
// 重启**之前**加载的，手里那枚旧 token 会让之后每个管理请求都 401，而且永远不恢复，
// 除非用户手动刷新。这里钉死五件事：
//   1. 401 → GET bootstrap 取当前 token → 更新内存与 window → **重放一次**原请求；
//   2. 闸门 = 每次连续 401 失败最多自愈一次（成功后重置）+ 每会话上限 3 次：
//      连续失败段里不重复救，成功一次之后才有下一次机会，整页生命周期封顶 3 次；
//   3. 403 不是 token 问题：一律不重试；
//   4. 自愈对用户无感（不弹提示），只在既有 client-log 里留一条 token-refreshed，且不含 token；
//   5. 自愈段（含 0.8.5-α 新加的文案表 LT）零反引号、无 console.error。
import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { PANEL_SCRIPT } from './admin.mjs';

const STALE = 'stale-token-from-previous-process';
const FRESH = 'fresh-token-from-bootstrap';
const VIEW = { w: 1000, h: 800 };

// 真机上这份脚本由**上一个进程**直出：它内嵌的是那时那一枚 token。
const STALE_PANEL = PANEL_SCRIPT.replace(/const T = '[0-9a-f]{64}';/, "const T = '" + STALE + "';");
assert.notEqual(STALE_PANEL, PANEL_SCRIPT, '替换必须命中 token 字面量（否则这组用例测不到轮换）');

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

const flush = async (rounds = 30) => {
  for (let i = 0; i < rounds; i += 1) await new Promise((resolve) => setTimeout(resolve, 1));
};

/**
 * respond(path, token) → { status, body }：测试直接决定某个 token 能不能过。
 * bootstrapToken 可以是字符串，也可以是每次调用取下一个的函数（模拟「又重启了一次」）。
 */
function boot({ respond, bootstrapToken = FRESH } = {}) {
  const calls = [];
  const timers = [];
  const document = {
    head: makeElement('head'),
    body: makeElement('body'),
    hidden: false,
    createElement: (tag) => makeElement(tag),
  };
  const res = (status, body) => ({ ok: status >= 200 && status < 300, status, json: async () => body });
  const fetchStub = async (url, init) => {
    const path = String(url).replace('/api/lan-peers/', '');
    const token = init && init.headers ? init.headers['X-Lan-Peers-Token'] : undefined;
    calls.push({ path, token, body: init && init.body ? JSON.parse(init.body) : null });
    if (path === 'bootstrap') {
      const fresh = typeof bootstrapToken === 'function' ? bootstrapToken() : bootstrapToken;
      return res(200, { token: fresh, name: 'me', version: '0.8.5-α' });
    }
    if (path === 'client-log') return res(200, { ok: true });
    const out = respond(path, token);
    return res(out.status, out.body);
  };
  const window = {
    innerWidth: VIEW.w,
    innerHeight: VIEW.h,
    addEventListener() {},
    confirm: () => true,
    localStorage: { getItem: () => null, setItem: () => {} },
  };
  vm.runInNewContext(STALE_PANEL, {
    window,
    document,
    localStorage: window.localStorage,
    fetch: fetchStub,
    setInterval: (fn, ms) => { timers.push({ fn, ms }); return timers.length; },
    clearInterval: () => {},
    setTimeout: () => 0,
    clearTimeout: () => {},
    JSON, Math, console,
  });
  const btn = document.body.children.find((el) => el.id === 'dshLpBtn');
  const panel = document.body.children.find((el) => el.id === 'dshLpPanel');
  const count = (path) => calls.filter((c) => c.path === path).length;
  return {
    btn, panel, calls, timers, window, count,
    msgBox: () => panel.querySelector('#dshLpMsg'),
    peersBox: () => panel.querySelector('#dshLpPeers'),
    logs: () => calls.filter((c) => c.path === 'client-log').map((c) => c.body),
  };
}

const PEERS = [{ peerId: 'p1', name: 'nas-box', baseUrl: 'http://192.168.1.51:7788' }];
const stateOk = () => ({ status: 200, body: { name: 'me', instanceId: 'me-id', peers: PEERS, pairing: null } });

test('401 → bootstrap 取新 token → 重放一次成功，且用户完全看不出来', async () => {
  const app = boot({
    respond: (path, token) => {
      // 旧 token 一律 401：这就是重启后的真实行为。
      if (token === STALE) return { status: 401, body: { error: 'unauthorized' } };
      if (path === 'state') return stateOk();
      return { status: 200, body: { dispatches: [] } };
    },
  });

  app.btn.onclick();
  await flush();

  assert.equal(app.count('bootstrap'), 1, '401 之后去取一次当前 token');
  assert.equal(app.window.__lanPeersToken, FRESH, '内存里的 token 与 window 同步更新');
  const stateCalls = app.calls.filter((c) => c.path === 'state');
  assert.equal(stateCalls.length, 2, '原请求被重放了一次');
  assert.equal(stateCalls[0].token, STALE, '第一次带的是页面里的旧 token');
  assert.equal(stateCalls[1].token, FRESH, '重放带的是刚取到的新 token');
  assert.equal(app.peersBox().children.length, 1, '自愈后首屏照常渲染出伙伴');
  assert.equal(app.msgBox().textContent, '', '自愈成功不弹任何提示');

  const logs = app.logs();
  assert.equal(logs.filter((b) => b.event === 'token-refreshed').length, 1, 'client-log 里留一条 token-refreshed');
  for (const log of logs) {
    const text = JSON.stringify(log);
    assert.equal(text.includes(STALE), false, '日志里不能有 token');
    assert.equal(text.includes(FRESH), false, '日志里不能有新 token');
  }
  for (const call of app.calls) assert.equal(call.path.includes(FRESH), false, 'token 不进 URL');
});

test('burst 闸门：一段连续 401 里只自愈一次，不循环、不刷屏', async () => {
  const app = boot({
    respond: () => ({ status: 401, body: { error: 'unauthorized' } }),
  });

  app.btn.onclick();          // 开面板：state + dispatch 都 401
  await flush();
  assert.equal(app.count('bootstrap'), 1, '第一次 401 自愈一次');
  assert.equal(app.count('state'), 2, 'state：原请求 + 一次重放');

  const afterFirst = app.calls.length;
  app.btn.onclick();          // 关
  app.btn.onclick();          // 再开：又一批管理请求，但这一段里一次成功都没有
  await flush();

  assert.equal(app.count('bootstrap'), 1, '连续失败段里不许第二次取 token');
  assert.ok(app.calls.length > afterFirst, '确实又发了管理请求');
  assert.equal(app.count('state'), 3, '每个原请求最多被重放一次');
  assert.equal(app.msgBox().textContent, 'unauthorized', '放弃时把服务端错误交给既有 msg 区');
  assert.equal(app.msgBox().textContent.includes(STALE), false);
});

// 0.8.5-α 规格调整（旧用例在这里是「每会话最多一次」，所以旧断言会红）：
// 「每会话一次」在开发期等于没救 —— 热重启之后第一次救回来了，第二次重启又只能手动刷新。
// 新口径：一次成功之后 burst 复位，可以再救；整页生命周期仍然封顶 3 次。
test('成功后复位：第二段 401 还能再自愈一次（旧口径在这里会红）', async () => {
  let valid = FRESH;
  const tokens = [FRESH, 'fresh-token-second-restart'];
  const app = boot({
    bootstrapToken: () => (tokens.length ? tokens.shift() : 'fresh-token-second-restart'),
    respond: (path, token) => {
      if (token !== valid) return { status: 401, body: { error: 'unauthorized' } };
      if (path === 'state') return stateOk();
      return { status: 200, body: { dispatches: [] } };
    },
  });

  app.btn.onclick();          // 第一段：旧 token → 401 → 自愈到 FRESH → 成功
  await flush();
  assert.equal(app.count('bootstrap'), 1, '第一段救一次');
  assert.equal(app.window.__lanPeersToken, FRESH);

  // 第二次重启：服务端只认新的一枚，手里这枚又成了旧货。
  valid = 'fresh-token-second-restart';
  app.btn.onclick();          // 关
  app.btn.onclick();          // 开 → 又 401；但中间那次成功已经把 burst 复位
  await flush();

  assert.equal(app.count('bootstrap'), 2, '成功之后允许再自愈一次（旧口径：仍是 1）');
  assert.equal(app.window.__lanPeersToken, 'fresh-token-second-restart', 'window 里换成第二枚新 token');
  assert.equal(app.msgBox().textContent, '', '第二次自愈同样对用户无感');
});

test('硬上限：每会话最多 3 次自愈，第 4 段失败只报错不再取 token', async () => {
  const tokens = ['v1', 'v2', 'v3', 'v4'];
  let valid = 'v1';
  const app = boot({
    bootstrapToken: () => (tokens.length ? tokens.shift() : 'v-out'),
    respond: (path, token) => {
      if (token !== valid) return { status: 401, body: { error: 'unauthorized' } };
      if (path === 'state') return stateOk();
      return { status: 200, body: { dispatches: [] } };
    },
  });

  for (const next of ['v1', 'v2', 'v3']) {
    valid = next;
    app.btn.onclick();        // 开
    await flush();
    if (next !== 'v3') app.btn.onclick();   // 关，进入下一段
  }
  assert.equal(app.count('bootstrap'), 3, '三段各救一次 = 3 次');

  valid = 'v4';
  if (app.panel.style.display === 'block') app.btn.onclick();   // 先关掉
  app.btn.onclick();          // 第 4 段：预算已用完
  await flush();
  assert.equal(app.count('bootstrap'), 3, '第 4 段不再自愈（每会话上限 3 次）');
  assert.equal(app.msgBox().textContent, 'unauthorized');
});

test('403 不是 token 问题：不取 token、不重放，只把业务错误写进 msg 区', async () => {
  const app = boot({
    respond: () => ({ status: 403, body: { error: 'forbidden-host' } }),
  });

  app.btn.onclick();
  await flush();

  assert.equal(app.count('bootstrap'), 0, '403 一律不触发自愈');
  assert.equal(app.count('state'), 1, '不重放');
  assert.equal(app.msgBox().textContent, 'forbidden-host', '业务错误照原样显示');
});

test('自愈段零反引号：新增行不引入模板字符串', () => {
  const start = PANEL_SCRIPT.indexOf('0.8.5-α 真机 bug');
  const end = PANEL_SCRIPT.indexOf("const style = document.createElement('style')");
  assert.ok(start > 0 && end > start, '自愈段必须在面板脚本里');
  const block = PANEL_SCRIPT.slice(start, end);
  assert.equal((block.match(/`/g) || []).length, 0, '面板段新增行零反引号');
  assert.equal(/console\.error/.test(block), false, '不新增 console.error');
});
