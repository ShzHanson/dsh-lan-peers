// dsh-lan-peers · injected panel launcher behaviour (drag + persistence).
//
// The panel script is plain browser JS served from /api/lan-peers/panel.js, so
// it cannot be imported: it runs against a minimal DOM stub instead. This is the
// only way to test the drag contract without a browser or an app restart.
import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { PANEL_SCRIPT } from './admin.mjs';

const VIEW = { w: 1000, h: 800 };

function makeElement(tag) {
  const cache = new Map();
  const el = {
    tagName: String(tag).toUpperCase(),
    id: '',
    className: '',
    textContent: '',
    innerHTML: '',
    value: '',
    style: {},
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
    getBoundingClientRect() {
      return {
        left: Number.parseFloat(this.style.left || '0') || 0,
        top: Number.parseFloat(this.style.top || '0') || 0,
        width: this.offsetWidth,
        height: this.offsetHeight,
      };
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
  return el;
}

function boot() {
  const store = new Map();
  const document = {
    head: makeElement('head'),
    body: makeElement('body'),
    createElement: (tag) => makeElement(tag),
  };
  const window = {
    innerWidth: VIEW.w,
    innerHeight: VIEW.h,
    addEventListener() {},
    localStorage: {
      getItem: (key) => (store.has(key) ? store.get(key) : null),
      setItem: (key, value) => store.set(key, String(value)),
    },
  };
  const sandbox = {
    window,
    document,
    localStorage: window.localStorage,
    fetch: async () => ({ ok: true, json: async () => ({ name: 'dev', peers: [], pairing: null, dispatches: [] }) }),
    setInterval: () => 0,
    clearInterval: () => {},
    setTimeout: () => 0,
    clearTimeout: () => {},
    JSON,
    Math,
    console,
  };
  vm.runInNewContext(PANEL_SCRIPT, sandbox);
  const btn = document.body.children.find((el) => el.id === 'dshLpBtn');
  const panel = document.body.children.find((el) => el.id === 'dshLpPanel');
  assert.ok(btn, 'launcher button must be appended');
  assert.ok(panel, 'panel must be appended');
  return { btn, panel, store };
}

const px = (v) => Number.parseFloat(String(v));

test('默认落在右下角，不压左下角的设置入口', () => {
  const { btn } = boot();
  assert.equal(px(btn.style.left), VIEW.w - 96 - 16);
  assert.equal(px(btn.style.top), VIEW.h - 36 - 16);
  assert.equal(btn.style.bottom, undefined);
  assert.equal(btn.style.cursor, undefined, 'cursor 由 CSS grab 提供');
});

test('拖动改变位置并写入 localStorage', () => {
  const { btn, store } = boot();
  btn.fire('pointerdown', { button: 0, pointerId: 1, clientX: 900, clientY: 760 });
  btn.fire('pointermove', { pointerId: 1, clientX: 700, clientY: 600 });
  btn.fire('pointerup', { pointerId: 1, clientX: 700, clientY: 600 });

  const saved = JSON.parse(store.get('dsh-lan-peers:launcher:v1'));
  assert.equal(saved.x, 700 - 12);
  assert.equal(saved.y, 600 - 12);
  assert.equal(px(btn.style.left), 688);
  assert.equal(px(btn.style.top), 588);
  assert.equal(btn.style.cursor, 'grab');
});

test('小于 4px 的抖动不算拖动（仍可当点击）', () => {
  const { btn, store } = boot();
  btn.fire('pointerdown', { button: 0, pointerId: 2, clientX: 900, clientY: 760 });
  btn.fire('pointermove', { pointerId: 2, clientX: 902, clientY: 761 });
  btn.fire('pointerup', { pointerId: 2, clientX: 902, clientY: 761 });
  assert.equal(store.has('dsh-lan-peers:launcher:v1'), false, '未拖动不应写位置');
  assert.equal(btn.style.cursor, 'grab', '松手后光标复位（无论是否真拖动）');
  btn.onclick();
});

test('拖完松手不误触发面板开关；普通点击才开关', () => {
  const { btn, panel } = boot();
  btn.fire('pointerdown', { button: 0, pointerId: 3, clientX: 900, clientY: 760 });
  btn.fire('pointermove', { pointerId: 3, clientX: 800, clientY: 700 });
  btn.fire('pointerup', { pointerId: 3, clientX: 800, clientY: 700 });
  btn.onclick();                                    // the click that follows a drag
  assert.notEqual(panel.style.display, 'block', '拖后紧跟的 click 必须被吞掉');

  btn.onclick();                                    // a real click
  assert.equal(panel.style.display, 'block');
  assert.ok(px(panel.style.left) >= 8, '面板横向必须在视口内');
  assert.ok(panel.style.top === 'auto' || px(panel.style.top) > 0);
  assert.ok(panel.style.bottom === 'auto' || px(panel.style.bottom) >= 8);
});

test('拖完在按钮外松手（无 click 派发）也不会吞掉下一次点击', () => {
  const { btn, panel } = boot();
  btn.fire('pointerdown', { button: 0, pointerId: 9, clientX: 900, clientY: 760 });
  btn.fire('pointermove', { pointerId: 9, clientX: 700, clientY: 600 });
  btn.fire('pointerup', { pointerId: 9, clientX: 2000, clientY: 2000 });   // ends far away, browser emits no click
  btn.fire('pointerdown', { button: 0, pointerId: 10, clientX: 700, clientY: 600 });
  btn.fire('pointerup', { pointerId: 10, clientX: 700, clientY: 600 });   // plain click gesture
  btn.onclick();
  assert.equal(panel.style.display, 'block', '上一次拖动残留的 swallow 标记必须被清除');
});

test('拖出视口会被夹回边界内', () => {
  const { btn } = boot();
  btn.fire('pointerdown', { button: 0, pointerId: 4, clientX: 900, clientY: 760 });
  btn.fire('pointermove', { pointerId: 4, clientX: 5000, clientY: 5000 });
  btn.fire('pointerup', { pointerId: 4, clientX: 5000, clientY: 5000 });
  assert.equal(px(btn.style.left), VIEW.w - 96 - 8);
  assert.equal(px(btn.style.top), VIEW.h - 36 - 8);

  btn.fire('pointerdown', { button: 0, pointerId: 5, clientX: 890, clientY: 750 });
  btn.fire('pointermove', { pointerId: 5, clientX: -500, clientY: -500 });
  btn.fire('pointerup', { pointerId: 5, clientX: -500, clientY: -500 });
  assert.equal(px(btn.style.left), 8);
  assert.equal(px(btn.style.top), 8);
});

test('存档位置越界时加载即夹回视口内（按钮不会「消失」在屏幕外）', () => {
  const fakeStore = new Map([['dsh-lan-peers:launcher:v1', JSON.stringify({ x: 5000, y: 5000 })]]);
  const document = {
    head: makeElement('head'),
    body: makeElement('body'),
    createElement: (tag) => makeElement(tag),
  };
  const window = {
    innerWidth: VIEW.w, innerHeight: VIEW.h, addEventListener() {},
    localStorage: { getItem: (k) => (fakeStore.has(k) ? fakeStore.get(k) : null), setItem: (k, v) => fakeStore.set(k, String(v)) },
  };
  vm.runInNewContext(PANEL_SCRIPT, {
    window, document, localStorage: window.localStorage,
    fetch: async () => ({ ok: true, json: async () => ({}) }),
    setInterval: () => 0, clearInterval: () => {}, setTimeout: () => 0, clearTimeout: () => {}, JSON, Math, console,
  });
  const btn = document.body.children.find((el) => el.id === 'dshLpBtn');
  assert.equal(px(btn.style.left), VIEW.w - 96 - 8);
  assert.equal(px(btn.style.top), VIEW.h - 36 - 8);
});

test('存档的位置在下次加载时被采用', () => {
  const fakeStore = new Map([['dsh-lan-peers:launcher:v1', JSON.stringify({ x: 120, y: 140 })]]);
  const document = {
    head: makeElement('head'),
    body: makeElement('body'),
    createElement: (tag) => makeElement(tag),
  };
  const window = {
    innerWidth: VIEW.w, innerHeight: VIEW.h, addEventListener() {},
    localStorage: { getItem: (k) => (fakeStore.has(k) ? fakeStore.get(k) : null), setItem: (k, v) => fakeStore.set(k, String(v)) },
  };
  vm.runInNewContext(PANEL_SCRIPT, {
    window, document, localStorage: window.localStorage,
    fetch: async () => ({ ok: true, json: async () => ({}) }),
    setInterval: () => 0, clearInterval: () => {}, setTimeout: () => 0, clearTimeout: () => {}, JSON, Math, console,
  });
  const btn = document.body.children.find((el) => el.id === 'dshLpBtn');
  assert.equal(px(btn.style.left), 120);
  assert.equal(px(btn.style.top), 140);
});
