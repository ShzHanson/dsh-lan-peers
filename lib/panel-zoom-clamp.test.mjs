// dsh-lan-peers · v0.9.1 面板放大不再遮挡窗口内容：封顶 + 自动选边 + 按视觉尺寸重钳制。
//
// 面板是直出脚本（浏览器 JS），不能 import：这里沿用 lib/panel-float.test.mjs 的最小 DOM 桩
// + node:vm 跑真 PANEL_SCRIPT，只断言「放大之后整块还在视口里」这一件事的五条：
//   ① 样式表封顶：max-width / max-height 都按 1/--lp-scale 反向补偿；
//   ② 自动选边：下半屏取 bottom（向上长）、右半屏取 right（向左长）；
//   ③ 放大后 left + offsetWidth*scale / top + offsetHeight*scale 都不出视口；
//   ④ resize / fontPx 变化同样触发重钳制；
//   ⑤ 拖动仍然 1:1 跟手（不被 scale 放大）；外加桩兼容：量不到尺寸不抛错。
import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { PANEL_SCRIPT } from './admin.mjs';

const VIEW = { w: 1000, h: 800 };
const POS_KEY = 'dsh-lan-peers:panel-pos:v1';
const EDGE = 8;
const px = (value) => Number.parseFloat(String(value));

// ---------------------------------------------------------------------------
// 最小 DOM 桩：与 panel-float.test.mjs 同款；noMetrics 时连 offset*/rect 都不给，
// 用来验证「量不到尺寸就退化成老行为，且绝不抛错」。
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
    querySelector(selector) {
      const id = String(selector).replace(/^#/, '');
      if (!cache.has(id)) cache.set(id, makeElement('div', opts));
      return cache.get(id);
    },
    fire(type, event) {
      for (const fn of this.listeners.get(type) || []) fn(event);
    },
  };
  if (opts.noMetrics !== true) {
    el.offsetWidth = 96;
    el.offsetHeight = 36;
    el.getBoundingClientRect = function getRect() {
      const num = (raw) => Number.parseFloat(String(raw)) || 0;
      const top = String(this.style.top == null ? 'auto' : this.style.top) === 'auto'
        ? VIEW.h - num(this.style.bottom) - (this.offsetHeight || 0)
        : num(this.style.top);
      return { left: num(this.style.left), top, width: this.offsetWidth, height: this.offsetHeight };
    };
  }
  let html = '';
  Object.defineProperty(el, 'innerHTML', {
    get: () => html,
    set: (value) => { html = value; if (value === '') el.children.length = 0; },
  });
  return el;
}

function boot(options) {
  const opts = options || {};
  const store = new Map(opts.store ? Array.from(opts.store) : []);
  const created = [];
  const timers = [];
  const windowListeners = new Map();
  const elOpts = { styleSetProperty: true, noMetrics: opts.noMetrics === true };
  const document = {
    head: makeElement('head', elOpts),
    body: makeElement('body', elOpts),
    hidden: false,
    createElement: (tag) => {
      const el = makeElement(tag, elOpts);
      created.push(el);
      return el;
    },
  };
  const json = (body) => ({ ok: true, status: 200, json: async () => body });
  const fetchStub = async (url, init) => {
    const apiPath = String(url).replace('/api/lan-peers/', '');
    if (apiPath === 'state') return json({ name: 'me', instanceId: 'me-id', peers: [], pairing: null });
    if (apiPath === 'panel-ui') return json({ ok: true });
    if (apiPath === 'dispatch/settings') {
      return json({ defaultWorkspaceId: '', maxPermission: 'workspace-write', workspaces: [] });
    }
    if (apiPath === 'dispatch/pending') return json({ items: [] });
    if (apiPath === 'lang') return json({ lang: 'zh', effective: 'zh' });
    if (init && init.body) JSON.parse(init.body);
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
  vm.runInNewContext(PANEL_SCRIPT, sandbox);
  const panel = document.body.children.find((el) => el.id === 'dshLpPanel');
  const btn = document.body.children.find((el) => el.id === 'dshLpBtn');
  assert.ok(btn, '启动按钮必须挂进 document.body');
  assert.ok(panel, '面板必须挂进 document.body');
  return {
    panel,
    btn,
    head: panel.querySelector('#dshLpPanelHead'),
    store,
    byId: (id) => created.find((el) => el.id === id),
    flush: async () => {
      const pending = timers.splice(0, timers.length).filter(Boolean);
      for (const fn of pending) fn();
      for (let i = 0; i < 40; i += 1) await new Promise((resolve) => setTimeout(resolve, 1));
    },
    resizeTo: (w, h) => {
      window.innerWidth = w;
      window.innerHeight = h;
      for (const fn of windowListeners.get('resize') || []) fn({});
    },
    zoom: (steps) => {
      for (let i = 0; i < (steps || 1); i += 1) {
        panel.fire('wheel', { ctrlKey: true, deltaY: -120, preventDefault() {} });
      }
    },
  };
}

/** 打开面板（真实用法就是点一下启动按钮），并接受一个已存档的面板位置。 */
const openAt = (pos, options) => {
  const app = boot(Object.assign({}, options, {
    store: new Map([[POS_KEY, JSON.stringify(pos)]]),
  }));
  app.btn.onclick();
  assert.equal(app.panel.style.display, 'block', '面板必须已打开');
  return app;
};

// ---------------------------------------------------------------------------
// ① AC1：样式表封顶 —— 宽高上限都除以 --lp-scale，视觉尺寸不可能超出视口
// ---------------------------------------------------------------------------
test('AC1 封顶：max-width / max-height 按 1/--lp-scale 反向补偿，scale=2 时上限约等于半个视口', () => {
  const rule = /#dshLpPanel\{([^}]*)\}/.exec(PANEL_SCRIPT);
  assert.ok(rule, '#dshLpPanel 规则必须存在');
  const body = rule[1];
  assert.ok(
    body.includes('max-width:calc((100vw - 16px) / var(--lp-scale))'),
    '缺 max-width 封顶：' + body,
  );
  assert.ok(
    body.includes('max-height:calc((100vh - 16px) / var(--lp-scale))'),
    '缺 max-height 封顶：' + body,
  );
  assert.doesNotMatch(body, /max-height:70vh/, '旧的 70vh 硬上限必须换掉（放大会被一起放大）');

  // scale=2：(1000-16)/2 = 492 ≈ 半个视口，且 492×2 ≤ 1000-16。
  const cap = (VIEW.w - 16) / 2;
  assert.ok(Math.abs(cap - VIEW.w / 2) <= EDGE, 'scale=2 的上限应当约为视口一半，实际 ' + cap);
  assert.ok(cap * 2 <= VIEW.w - 16, '宽度×scale 必须 ≤ 100vw-16');

  // 内联 max-height 会盖掉样式表的封顶：不许再写。
  const app = boot({});
  assert.equal(app.panel.style.maxHeight, undefined, '不许用内联 max-height 覆盖封顶');
});

// ---------------------------------------------------------------------------
// ② AC2：自动选边 —— 下半屏向上长（bottom），右半屏向左长（right）
// ---------------------------------------------------------------------------
test('AC2 自动选边：面板在哪半屏，transform-origin 就取哪条边（缩放时重选）', () => {
  const cases = [
    { pos: { x: 720, y: 90 }, want: 'right top', label: '右上' },
    { pos: { x: 720, y: 700 }, want: 'right bottom', label: '右下' },
    { pos: { x: 60, y: 90 }, want: 'left top', label: '左上' },
    { pos: { x: 60, y: 700 }, want: 'left bottom', label: '左下' },
  ];
  for (const item of cases) {
    const app = openAt(item.pos);
    assert.equal(app.panel.style.transformOrigin, item.want, item.label + '：打开时就该选好边');
    app.zoom(1);
    assert.equal(app.panel.style.transformOrigin, item.want, item.label + '：缩放一次仍是 ' + item.want);
  }
  // 语义上的两半：下半屏 → bottom（向上长），上半屏 → top。
  const lower = openAt({ x: 400, y: 700 });
  assert.equal(lower.panel.style.transformOrigin.split(' ')[1], 'bottom', '下半屏必须 bottom');
  const upper = openAt({ x: 400, y: 40 });
  assert.equal(upper.panel.style.transformOrigin.split(' ')[1], 'top', '上半屏必须 top');
  const right = openAt({ x: 780, y: 400 });
  assert.equal(right.panel.style.transformOrigin.split(' ')[0], 'right', '右半屏必须 right');
  const left = openAt({ x: 40, y: 400 });
  assert.equal(left.panel.style.transformOrigin.split(' ')[0], 'left', '左半屏必须 left');
});

// ---------------------------------------------------------------------------
// ③ AC3：贴右下角放大到 scale=2，整块（含标题栏）仍在视口内
// ---------------------------------------------------------------------------
test('AC3 放大后整块在视口内：left + offsetWidth*2 ≤ innerWidth，top + offsetHeight*2 ≤ innerHeight', () => {
  const app = openAt({ x: 880, y: 700 });
  const panel = app.panel;
  assert.equal(panel.style.transform, 'scale(1)');
  app.zoom(10);
  assert.equal(panel.style.transform, 'scale(2)', '用例前提：确实放大到 2 倍');

  const left = px(panel.style.left);
  const top = px(panel.style.top);
  const visW = panel.offsetWidth * 2;
  const visH = panel.offsetHeight * 2;
  assert.ok(left + visW <= VIEW.w, 'left(' + left + ') + ' + visW + ' 必须 ≤ ' + VIEW.w + '，实际 ' + (left + visW));
  assert.ok(top + visH <= VIEW.h, 'top(' + top + ') + ' + visH + ' 必须 ≤ ' + VIEW.h + '，实际 ' + (top + visH));
  assert.ok(left >= EDGE, '也不能被推出左边界：left=' + left);
  assert.ok(top >= EDGE, '也不能被推出上边界：top=' + top);
});

// ---------------------------------------------------------------------------
// ④ AC4：resize 与 fontPx 变化同样触发重钳制
// ---------------------------------------------------------------------------
test('AC4 resize：视口变小后按视觉尺寸重新钳制', () => {
  const app = openAt({ x: 880, y: 700 });
  app.resizeTo(400, 300);
  const left = px(app.panel.style.left);
  const top = px(app.panel.style.top);
  assert.ok(left + app.panel.offsetWidth <= 400, 'left(' + left + ') + 96 必须 ≤ 400，实际 ' + (left + 96));
  assert.ok(top + app.panel.offsetHeight <= 300, 'top(' + top + ') + 36 必须 ≤ 300，实际 ' + (top + 36));
});

test('AC4 界面字号：fontPx 变化（内容变高）后按视觉尺寸重新钳制', async () => {
  const app = openAt({ x: 880, y: 700 });
  app.panel.querySelector('#dshLpTabSettings').onclick();
  await app.flush();
  const select = app.byId('dshLpSetFont');
  assert.ok(select, '设置页必须有界面字号下拉');

  // 桩不排版：字号变大就手动把「量到的高度」抬高，模拟内容长高。
  app.panel.offsetHeight = 400;
  select.value = '20';
  select.onchange();
  assert.equal(app.panel.style['--lp-font-px'], '20px', '用例前提：字号确实改了');

  const top = px(app.panel.style.top);
  assert.ok(top < 700, '旧位置会顶出视口，必须往上挪：top=' + top);
  assert.ok(top + 400 <= VIEW.h, 'top(' + top + ') + 视觉高 400 必须 ≤ ' + VIEW.h + '，实际 ' + (top + 400));
});

// ---------------------------------------------------------------------------
// ⑤ AC5：缩放 2.0 时拖动仍 1:1 跟手（不被 scale 放大/缩小）
// ---------------------------------------------------------------------------
test('AC5 缩放 2.0 时拖动：拖 100px，style.left 的位移也正好 100px', () => {
  const app = openAt({ x: 300, y: 300 });
  app.zoom(10);
  assert.equal(app.panel.style.transform, 'scale(2)', '用例前提：面板在 2 倍缩放下');
  const startLeft = px(app.panel.style.left);
  const startTop = px(app.panel.style.top);

  app.head.fire('pointerdown', { button: 0, pointerId: 7, clientX: 400, clientY: 400 });
  app.head.fire('pointermove', { pointerId: 7, clientX: 500, clientY: 400 });
  app.head.fire('pointerup', { pointerId: 7, clientX: 500, clientY: 400 });

  assert.equal(px(app.panel.style.left) - startLeft, 100, '位移必须正好 100px（不是 200 / 50）');
  assert.equal(px(app.panel.style.top), startTop, '没拖 y 就不许挪 y');
});

// ---------------------------------------------------------------------------
// ⑥ 桩兼容：量不到 offset*/rect 时不抛错，也不乱猜高度（纵向钳制直接跳过）
// ---------------------------------------------------------------------------
test('桩兼容：没有 offsetWidth/offsetHeight/getBoundingClientRect 时不抛错，位置仍在视口内', async () => {
  const app = boot({ noMetrics: true, store: new Map([[POS_KEY, JSON.stringify({ x: 700, y: 650 })]]) });
  app.btn.onclick();
  assert.equal(app.panel.style.display, 'block');
  assert.ok(Number.isFinite(px(app.panel.style.left)), 'left 必须是数字');

  app.zoom(1);
  app.panel.querySelector('#dshLpTabSettings').onclick();
  await app.flush();
  app.resizeTo(700, 500);

  const left = px(app.panel.style.left);
  assert.ok(left >= EDGE, 'left=' + left + ' 不许跑到左边界外');
  assert.ok(left + 320 <= 700, '横向仍按 320 的视觉宽留在视口内：left=' + left);
});
