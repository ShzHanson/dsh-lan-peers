// dsh-lan-peers · 面板「建立伙伴关系」成功后的一次性入群询问。
//
// PANEL_SCRIPT 是浏览器脚本，无法 import：沿用 panel-group / panel-unpair 的最小 DOM 桩执行它，
// 断言这条新交互的全部边界——hub 侧 add / 成员侧 join、取消零请求、群未启用静默跳过、
// 群状态未知先拉一次再决定、对端名字为空退回 peerId 前 8 位。
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

/** GET group 的最小响应：enabled / isHub 决定配对后问不问、问哪一句。 */
function groupState({ enabled = true, isHub = true } = {}) {
  return {
    enabled,
    isHub,
    group: { groupId: 'g-1', name: '家里', members: [] },
    messages: [],
    lastSeq: 0,
    leader: { peerId: 'peer-hub', name: 'hub-box', epoch: 3 },
    selfRole: isHub ? 'hub' : 'member',
  };
}

function boot({
  group = () => groupState(),
  pair = { peerId: 'peer-new', name: 'nas-new' },
  confirmAnswer = true,
  joinError = null,
} = {}) {
  const calls = [];
  const confirms = [];
  const document = {
    head: makeElement('head'),
    body: makeElement('body'),
    hidden: false,
    createElement: (tag) => makeElement(tag),
  };
  const jsonResponse = (body) => ({ ok: true, status: 200, json: async () => body });
  const fetchStub = async (url, init) => {
    const path = String(url).replace('/api/lan-peers/', '');
    calls.push({ path, init });
    if (path === 'state') return jsonResponse({ name: 'me', instanceId: 'me-id', peers: [], pairing: null });
    if (path === 'dispatch') return jsonResponse({ dispatches: [] });
    if (path === 'pair') return jsonResponse({ ok: true, transport: 'plain', peer: pair });
    if (path.startsWith('group?sinceSeq=')) {
      const sinceSeq = Number(path.split('=')[1]);
      return jsonResponse(group({ sinceSeq }));
    }
    if (path === 'group/join') {
      if (joinError) return { ok: false, status: 403, json: async () => ({ error: joinError }) };
      return jsonResponse({ ok: true, groupId: 'g-1', epoch: 3 });
    }
    if (path === 'group/member') return jsonResponse({ ok: true, peerId: pair.peerId, members: [] });
    return jsonResponse({});
  };
  const window = {
    innerWidth: VIEW.w,
    innerHeight: VIEW.h,
    addEventListener() {},
    confirm: (text) => {
      confirms.push(text);
      return typeof confirmAnswer === 'function' ? confirmAnswer(text) : confirmAnswer;
    },
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
  return { btn, panel, calls, confirms };
}

/** 打开面板（真机上的第一步） */
async function openPanel(options) {
  const booted = boot(options);
  booted.btn.onclick();
  await flush();
  return booted;
}

/** 先把群状态拉过一遍，再回到「伙伴」页（正常使用时的顺序） */
async function learnGroupState(booted) {
  booted.panel.querySelector('#dshLpTabGroup').onclick();
  await flush();
  booted.panel.querySelector('#dshLpTabPeers').onclick();
}

const pairNow = async (booted) => {
  booted.panel.querySelector('#dshLpPair').onclick();
  await flush();
};

// v0.8.0-β：打开群组页会顺带拉一次只读的归档列表（group/archives），那是页面渲染，
// 不属于配对流程 —— 下面的断言只统计配对可能触发的群操作请求。
const groupPosts = (calls) => calls
  .filter((call) => call.path.startsWith('group/') && call.path !== 'group/archives');

test('hub 侧确认 → POST group/member 带 {peerId, action:"add"}，成功写 msg', async () => {
  const b = await openPanel({ group: () => groupState({ enabled: true, isHub: true }) });
  await learnGroupState(b);
  await pairNow(b);
  assert.equal(b.confirms.length, 1);
  assert.equal(b.confirms[0], '把刚配对的「nas-new」加入群组吗？');
  const posts = b.calls.filter((call) => call.path === 'group/member');
  assert.equal(posts.length, 1);
  assert.equal(posts[0].init.method, 'POST');
  assert.deepEqual(JSON.parse(posts[0].init.body), { peerId: 'peer-new', action: 'add' });
  assert.equal(b.panel.querySelector('#dshLpMsg').textContent, '已把 nas-new 加入群组');
  // 配对主流程不变：成功提示 + 清空输入 + 刷新列表
  assert.equal(b.panel.querySelector('#dshLpUrl').value, '');
  assert.ok(b.calls.some((call) => call.path === 'state'), '配对后仍刷新伙伴列表');
});

test('hub 侧取消 → 一个群请求都不发', async () => {
  const b = await openPanel({ group: () => groupState({ enabled: true, isHub: true }), confirmAnswer: false });
  await learnGroupState(b);
  await pairNow(b);
  assert.equal(b.confirms.length, 1);
  assert.equal(groupPosts(b.calls).length, 0, '取消后不发任何群请求');
  assert.match(b.panel.querySelector('#dshLpMsg').textContent, /建立伙伴关系/);
});

test('成员侧确认 → POST group/join，成功后 msg 带 epoch', async () => {
  const b = await openPanel({ group: () => groupState({ enabled: true, isHub: false }) });
  await learnGroupState(b);
  await pairNow(b);
  assert.equal(b.confirms.length, 1);
  assert.equal(b.confirms[0], '要加入「nas-new 的群组」吗？');
  const posts = b.calls.filter((call) => call.path === 'group/join');
  assert.equal(posts.length, 1);
  assert.equal(posts[0].init.method, 'POST');
  assert.deepEqual(JSON.parse(posts[0].init.body), {});
  assert.equal(b.panel.querySelector('#dshLpMsg').textContent, '已加入群组（epoch 3）');
});

test('群未启用 → 不弹确认框，也不发群请求', async () => {
  const b = await openPanel({ group: () => groupState({ enabled: false }) });
  await learnGroupState(b);
  const before = b.calls.filter((call) => call.path.startsWith('group')).length;
  await pairNow(b);
  assert.equal(b.confirms.length, 0, 'enabled!==true 静默跳过');
  assert.equal(b.calls.filter((call) => call.path.startsWith('group')).length, before);
  assert.equal(groupPosts(b.calls).length, 0);
  assert.match(b.panel.querySelector('#dshLpMsg').textContent, /建立伙伴关系/, '配对本身仍然成功');
});

test('群状态未知 → 先 GET group?sinceSeq=0 一次再决定是否询问', async () => {
  const b = await openPanel({ group: () => groupState({ enabled: true, isHub: true }) });
  assert.equal(b.calls.some((call) => call.path.startsWith('group')), false, '配对前没拉过群状态');
  await pairNow(b);
  const getAt = b.calls.findIndex((call) => call.path === 'group?sinceSeq=0');
  const postAt = b.calls.findIndex((call) => call.path === 'group/member');
  assert.ok(getAt >= 0, '配对完成后先拉一次群状态');
  assert.ok(postAt > getAt, '拉取之后才决定询问并提交');
  assert.equal(b.confirms.length, 1);
});

test('群状态未知且未启用 → 仍先拉一次，然后静默跳过', async () => {
  const b = await openPanel({ group: () => groupState({ enabled: false }) });
  await pairNow(b);
  assert.equal(b.calls.filter((call) => call.path === 'group?sinceSeq=0').length, 1);
  assert.equal(b.confirms.length, 0);
  assert.equal(groupPosts(b.calls).length, 0);
});

test('对端名字为空 → 用 peerId 前 8 位', async () => {
  const b = await openPanel({
    group: () => groupState({ enabled: true, isHub: true }),
    pair: { peerId: 'abcdef1234567890', name: '' },
  });
  await learnGroupState(b);
  await pairNow(b);
  assert.equal(b.confirms.length, 1);
  assert.equal(b.confirms[0], '把刚配对的「abcdef12」加入群组吗？');
});

test('群状态拉取失败 → 不弹框也不发请求（groupKnown 仍未知，下次再试）', async () => {
  const b = await openPanel({ group: () => { throw new Error('boom'); } });
  await pairNow(b);
  assert.equal(b.confirms.length, 0);
  assert.equal(groupPosts(b.calls).length, 0);
  assert.match(b.panel.querySelector('#dshLpMsg').textContent, /建立伙伴关系/);
});

test('入群失败只写 msg 区：成员侧 not-a-member 提示去 hub 面板添加成员', async () => {
  const b = await openPanel({
    group: () => groupState({ enabled: true, isHub: false }),
    joinError: 'not-a-member',
  });
  await learnGroupState(b);
  await pairNow(b);
  assert.equal(b.confirms.length, 1, '失败前仍先问过一次');
  const line = b.panel.querySelector('#dshLpMsg').textContent;
  assert.match(line, /not-a-member/);
  assert.match(line, /请 hub 侧在面板「添加成员」/);
});
