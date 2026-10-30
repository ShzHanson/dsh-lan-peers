// dsh-lan-peers · 注入面板里的「解除」入口（v0.4.1）。
//
// PANEL_SCRIPT 是浏览器脚本，无法 import：用最小 DOM 桩执行它，再点一次真实
// 按钮，断言 confirm 文案、POST 载荷、按钮禁用与结果提示。桩与
// lib/panel-drag.test.mjs 同款，额外记录 fetch 调用与创建过的标签名。
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
    getBoundingClientRect() {
      return { left: 0, top: 0, width: this.offsetWidth, height: this.offsetHeight };
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
  // innerHTML = '' is how renderPeers clears the list; model that on children.
  let html = '';
  Object.defineProperty(el, 'innerHTML', {
    get: () => html,
    set: (value) => { html = value; if (value === '') el.children.length = 0; },
  });
  return el;
}

/** 执行 PANEL_SCRIPT 并返回可操作的句柄：面板、按钮、fetch 记录、confirm 记录 */
function boot({ peers = [], unpair = null, confirmAnswer = true } = {}) {
  const created = [];
  const calls = [];
  const confirms = [];
  const document = {
    head: makeElement('head'),
    body: makeElement('body'),
    createElement: (tag) => { const el = makeElement(tag); created.push(el); return el; },
  };
  const jsonResponse = (body) => ({ ok: true, status: 200, json: async () => body });
  const fetchStub = async (url, init) => {
    const path = String(url).replace('/api/lan-peers/', '');
    calls.push({ path, init });
    if (path === 'state') return jsonResponse({ name: 'me', instanceId: 'me-id', peers, pairing: null });
    if (path === 'dispatch') return jsonResponse({ dispatches: [] });
    if (path === 'unpair') return jsonResponse(unpair ?? { ok: true, peer: {}, remote: { notified: false, reason: 'unreachable' } });
    return jsonResponse({});
  };
  const window = {
    innerWidth: VIEW.w,
    innerHeight: VIEW.h,
    addEventListener() {},
    confirm: (text) => { confirms.push(text); return confirmAnswer; },
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
    JSON,
    Math,
    console,
  });
  const btn = document.body.children.find((el) => el.id === 'dshLpBtn');
  const panel = document.body.children.find((el) => el.id === 'dshLpPanel');
  return { btn, panel, calls, confirms, created };
}

const flush = async (rounds = 20) => {
  for (let i = 0; i < rounds; i += 1) await new Promise((resolve) => setTimeout(resolve, 1));
};

const PEERS = [{ peerId: 'nas-box-id', name: 'nas-box', baseUrl: 'http://192.168.1.51:7788' }];

async function openPanel(options) {
  const booted = boot(options);
  booted.btn.onclick();
  await flush();
  const box = booted.panel.querySelector('#dshLpPeers');
  return { ...booted, box };
}

test('伙伴行右侧有「解除」按钮，点击先 confirm 对端在线会同步删除', async () => {
  const { box, confirms, calls } = await openPanel({ peers: PEERS });
  assert.equal(box.children.length, 1);
  const [label, drop] = box.children[0].children;
  assert.equal(label.textContent, 'nas-box · http://192.168.1.51:7788');
  assert.equal(drop.tagName, 'BUTTON');
  assert.equal(drop.textContent, '解除');
  assert.equal(calls.filter((call) => call.path === 'unpair').length, 0, '点亮按钮前不发请求');

  drop.onclick();
  assert.deepEqual(confirms, ['解除与 nas-box 的配对？对端在线时会同步删除。']);
});

test('确认后 POST /api/lan-peers/unpair 带正确 peerId；请求期间按钮禁用', async () => {
  const { box, calls } = await openPanel({
    peers: PEERS,
    unpair: { ok: true, peer: { peerId: 'nas-box-id', name: 'nas-box' }, remote: { notified: true } },
  });
  const [, drop] = box.children[0].children;

  drop.onclick();
  assert.equal(drop.disabled, true, '请求期间必须禁用，避免重复提交');

  await flush();
  const posted = calls.filter((call) => call.path === 'unpair');
  assert.equal(posted.length, 1);
  assert.equal(posted[0].init.method, 'POST');
  assert.equal(posted[0].init.headers['Content-Type'], 'application/json');
  assert.deepEqual(JSON.parse(posted[0].init.body), { peerId: 'nas-box-id' });
  assert.equal(drop.disabled, false, '请求结束后恢复可点');
  const unpairAt = calls.findIndex((call) => call.path === 'unpair');
  assert.ok(calls.slice(unpairAt + 1).some((call) => call.path === 'state'), '成功后刷新列表');
});

test('对端已同步删除时提示写「对端已同步删除」', async () => {
  const { box, panel } = await openPanel({
    peers: PEERS,
    unpair: { ok: true, peer: { peerId: 'nas-box-id', name: 'nas-box' }, remote: { notified: true } },
  });
  box.children[0].children[1].onclick();
  await flush();
  assert.equal(panel.querySelector('#dshLpMsg').textContent, '已解除与 nas-box 的配对（对端已同步删除）');
});

test('对端未同步时提示写「仅本地」', async () => {
  const { box, panel } = await openPanel({
    peers: PEERS,
    unpair: { ok: true, peer: { peerId: 'nas-box-id', name: 'nas-box' }, remote: { notified: false, reason: 'unreachable' } },
  });
  box.children[0].children[1].onclick();
  await flush();
  assert.equal(panel.querySelector('#dshLpMsg').textContent, '已解除与 nas-box 的配对（仅本地）');
});

test('取消 confirm 后不发请求、不删任何东西', async () => {
  const { box, panel, calls } = await openPanel({ peers: PEERS, confirmAnswer: false });
  box.children[0].children[1].onclick();
  await flush();
  assert.equal(calls.filter((call) => call.path === 'unpair').length, 0);
  assert.equal(panel.querySelector('#dshLpMsg').textContent, '');
});

test('对端名字里的 HTML 只当文本，不参与 innerHTML 拼接', async () => {
  const evil = '<img src=x onerror=alert(1)>';
  const { box, created } = await openPanel({ peers: [{ peerId: 'p1', name: evil, baseUrl: '' }] });
  const label = box.children[0].children[0];
  assert.equal(label.textContent, evil + ' · (仅入站)');
  assert.equal(created.some((el) => el.tagName === 'IMG'), false, '不得因为名字而创建标签');
});
