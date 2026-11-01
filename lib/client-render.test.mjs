// dsh-lan-peers · React panel renders without a browser.
//
// The desktop window exposes no devtools, so a render-time exception shows up as
// "the button is missing" and nothing else. This harness runs the real client
// module against a minimal React hook runtime, so such a throw fails a test
// instead of silently eating the launcher.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SOURCE = fs.readFileSync(path.join(HERE, 'client.js'), 'utf8');

const el = (type, props, ...children) => ({ type, props: props || {}, children: children.flat(Infinity).filter((c) => c != null) });
const textOf = (node) => {
  if (node == null) return '';
  if (typeof node === 'string' || typeof node === 'number') return String(node);
  if (Array.isArray(node)) return node.map(textOf).join(' ');
  return textOf(node.children);
};

function boot(peerCount, options = {}) {
  const calls = [];
  const timers = [];
  const appended = [];
  const store = new Map();
  const hooks = { states: [], effects: [], index: 0, setters: [] };

  const React = {
    createElement: el,
    useState(init) {
      const k = hooks.index++;
      if (!(k in hooks.states)) hooks.states[k] = typeof init === 'function' ? init() : init;
      if (!hooks.setters[k]) hooks.setters[k] = (v) => { hooks.states[k] = typeof v === 'function' ? v(hooks.states[k]) : v; };
      return [hooks.states[k], hooks.setters[k]];
    },
    useEffect(fn) { hooks.effects.push(fn); hooks.index++; },
    useRef(init) { const k = hooks.index++; if (!(k in hooks.states)) hooks.states[k] = { current: init }; return hooks.states[k]; },
    useCallback(fn) { hooks.index++; return fn; },
  };

  const peers = Array.from({ length: peerCount }, (_, i) => ({ peerId: 'p' + i, name: 'nas-box', baseUrl: 'http://192.168.1.51:7788' }));
  const sandbox = {
    console,
    JSON, Math, Date, String, Number, Object, Array, Promise,
    setTimeout: (fn) => { timers.push(fn); return timers.length; },
    clearTimeout: () => {}, clearInterval: () => {}, setInterval: () => 0,
    fetch: async (url) => {
      calls.push(String(url));
      const body = String(url).endsWith('/state')
        ? { name: 'dsh-desktop', peers, pairing: null }
        : String(url).endsWith('/dispatch') ? { dispatches: [] } : { ok: true };
      if (options.fetchFail && String(url).endsWith('/panel.js')) {
        return { ok: false, status: 500, json: async () => ({}), text: async () => '' };
      }
      return { ok: true, json: async () => body, text: async () => (String(url).endsWith('/panel.js') ? 'window.__dshLanPeersPanel=true;' : '') };
    },
    localStorage: {
      getItem: (k) => (store.has(k) ? store.get(k) : null),
      setItem: (k, v) => store.set(k, String(v)),
    },
  };
  const launcherNode = options.existingLauncher
    ? {
        nodeName: 'BUTTON',
        style: {},
        // options.launcherHidden models the real failure we hit: the node exists
        // but an ancestor's transform/overflow makes it zero-sized or clipped.
        getBoundingClientRect: () => (options.launcherHidden
          ? { left: 0, top: 0, right: 0, bottom: 0, width: 0, height: 0 }
          : { left: 900, top: 700, right: 962, bottom: 736, width: 62, height: 36 }),
      }
    : null;
  sandbox.document = {
    createElement: (tag) => ({ tagName: String(tag).toUpperCase(), src: '' }),
    querySelector: () => launcherNode,
    querySelectorAll: () => (launcherNode ? [launcherNode] : []),
    elementFromPoint: () => (options.covered ? { tagName: 'DIV', className: 'overlay', contains: () => false } : launcherNode),
    body: { appendChild: (node) => { appended.push(node); return node; } },
  };
  const winListeners = new Map();
  sandbox.window = {
    innerWidth: 1000, innerHeight: 800,
    addEventListener(type, fn) { winListeners.set(type, fn); },
    removeEventListener(type) { winListeners.delete(type); },
    dispatchEvent(event) { const fn = winListeners.get(event && event.type); if (fn) fn(event); return true; },
    localStorage: sandbox.localStorage,
    confirm: () => true,
    // S3：管理接口要会话 token。真实环境里它由 panel.js 设到 window 上；测试桩不校验
    // header，所以这里放一个占位值即可（options.token === false 用来模拟「还没注入」）。
    __lanPeersToken: options.token === false ? undefined : 'test-token',
  };
  sandbox.window.__ModuleLoader__ = { load: (spec) => { sandbox.__spec = spec; } };
  sandbox.__ModuleLoader__ = sandbox.window.__ModuleLoader__;

  vm.runInNewContext(SOURCE, sandbox, { filename: 'client.js' });
  assert.ok(sandbox.__spec && typeof sandbox.__spec.factory === 'function', 'module must call __ModuleLoader__.load with a factory');

  const mod = sandbox.__spec.factory((name) => {
    if (name === 'react') return React;
    throw new Error('unexpected require: ' + name);
  });
  assert.ok(mod && typeof mod.apply === 'function', 'factory must return an apply()');

  let Component = null;
  const slots = {
    inject: (_name, fn) => fn(),
    register: (_meta, component) => { Component = component; },
  };
  mod.apply({ slots });
  assert.ok(Component, 'apply() must register the panel component');

  const render = () => {
    hooks.index = 0;
    hooks.effects = [];
    return Component();
  };
  const flush = async () => { for (let i = 0; i < 20; i++) await Promise.resolve(); };

  return {
    render, flush, hooks, calls, appended, timers, launcherNode, window: sandbox.window,
    fire: (type) => sandbox.window.dispatchEvent({ type }),
    runTimers: () => { const queued = timers.splice(0); for (const fn of queued) fn(); },
  };
}

test('启动器不存在时，自动注入独立面板脚本兜底', async () => {
  const { runTimers, appended, flush } = boot(1);
  runTimers();
  await flush();
  const injected = appended.find((node) => node && node.tagName === 'SCRIPT');
  assert.ok(injected, '应当注入一个 script');
  assert.match(String(injected.textContent), /__dshLanPeersPanel/);
});

test('两个定时器都到点时只注入一次', async () => {
  const { runTimers, appended, flush } = boot(1, { existingLauncher: true });
  runTimers();                 // 1.5s 与 4s 两个定时器一起触发
  await flush();
  assert.equal(appended.filter((n) => n && n.tagName === 'SCRIPT').length, 1, '必须幂等');
});

test('启动器矩形正常但被别的元素盖住时，仍注入兜底', async () => {
  const { runTimers, appended, flush } = boot(1, { existingLauncher: true, covered: true });
  runTimers();
  await flush();
  const injected = appended.filter((node) => node && node.tagName === 'SCRIPT');
  assert.equal(injected.length, 1, '被盖住时必须注入且只注入一次');
  assert.match(String(injected[0].textContent), /__dshLanPeersPanel/);
});

test('注入成功后隐藏槽位浮层，保证界面上只有一个按钮', async () => {
  const { runTimers, appended, flush, launcherNode } = boot(1, { existingLauncher: true });
  runTimers();
  await flush();
  assert.equal(appended.filter((n) => n && n.tagName === 'SCRIPT').length, 1);
  assert.equal(launcherNode.style.display, 'none', 'body 级面板接管后，槽位浮层应被隐藏');
});

test('panel.js 取不到时保留槽位浮层（不退化成「没有按钮」）', async () => {
  const { runTimers, appended, flush, launcherNode } = boot(1, { existingLauncher: true, fetchFail: true });
  runTimers();
  await flush();
  assert.equal(appended.filter((n) => n && n.tagName === 'SCRIPT').length, 0, '取不到就不注入空脚本');
  assert.notEqual(launcherNode.style.display, 'none', '失败时必须保留 React 那个按钮');
});

test('启动器在 DOM 但不可见（被祖先 transform/overflow 裁掉）时，仍注入兜底', async () => {
  const { runTimers, appended, flush } = boot(1, { existingLauncher: true, launcherHidden: true });
  runTimers();
  await flush();
  const injected = appended.filter((node) => node && node.tagName === 'SCRIPT');
  assert.equal(injected.length, 1, '不可见时必须注入且只注入一次');
  assert.match(String(injected[0].textContent), /__dshLanPeersPanel/, '注入的是从 /panel.js 取回并内联的面板脚本');
});

test('body 级面板接管后 React 面板整体退场（界面上只剩一个按钮）', () => {
  const { render, hooks, fire } = boot(1);
  const before = render();
  assert.match(textOf(before), /伙伴/, '退场前是有按钮的');
  for (const fn of hooks.effects.slice(0)) fn();   // 挂载副作用：注册退场监听
  fire('dsh-lan-peers:standdown');
  assert.equal(textOf(render()), '', '退场后不应再渲染任何东西');
});

test('React 面板能渲染出「伙伴」按钮（渲染期不抛异常）', () => {
  const { render } = boot(1);
  const tree = render();
  assert.match(textOf(tree), /伙伴/);
});

function clickLauncher(tree) {
  let clicked = false;
  const walk = (node) => {
    if (!node || typeof node !== 'object') return;
    if (Array.isArray(node)) return node.forEach(walk);
    const isLauncher = node.props && typeof node.props.onClick === 'function' && /伙伴/.test(textOf(node));
    if (isLauncher && !clicked) { clicked = true; node.props.onClick(); return; }
    walk(node.children);
  };
  walk(tree);
  assert.ok(clicked, 'launcher button with onClick must exist');
}

/** Render, open the panel, let the effects settle, render again. */
async function openPanel(boot_) {
  const { render, flush, hooks } = boot_;
  clickLauncher(render());
  render();                                  // panel is open now
  for (const fn of hooks.effects.slice(0)) fn();
  await flush();
  return render();
}

test('有一个伙伴时，面板里渲染出「解除」', async () => {
  const text = textOf(await openPanel(boot(1)));
  assert.match(text, /局域网伙伴/);
  assert.match(text, /解除/);
});

test('没有伙伴时渲染占位行且不出现「解除」', async () => {
  const text = textOf(await openPanel(boot(0)));
  assert.match(text, /还没有伙伴/);
  assert.doesNotMatch(text, /解除/);
});

test('首屏拿不到 token 时不发管理请求，token 到位后补一次并渲染出 state', async () => {
  // panel.js 是 defer 注入的：首屏第一次 GET state 可能比它先到。S3 之后没有 token
  // 就不发请求（否则只会换回一条用户看不懂的 401），但必须安排一次重试。
  const app = boot(1, { token: false });
  const first = textOf(await openPanel(app));
  assert.equal(app.calls.filter((u) => u.includes('/api/lan-peers/state')).length, 0, '没有 token 就不发管理请求');
  assert.doesNotMatch(first, /解除/);
  assert.doesNotMatch(first, /token/, '这是用户看不懂的内部状态，不能变成面板错误文案');

  app.window.__lanPeersToken = 'test-token';   // panel.js 注入完成
  app.runTimers();                             // 800ms 的那一次重试
  await app.flush();

  const second = textOf(app.render());
  assert.equal(app.calls.filter((u) => u.includes('/api/lan-peers/state')).length, 1, '重试只补一次');
  assert.match(second, /解除/, '首屏数据在 token 到位后正常渲染');
  assert.doesNotMatch(second, /token/, '成功路径也不该出现 token 字样');
});
