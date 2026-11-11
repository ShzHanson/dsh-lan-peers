// dsh-lan-peers · 面板「群组」页里 0.10.0-α 之后仍然成立的几条口径。
//
// 群内派单已在 0.10.0-α 移除，本文件只剩三件事（派单相关的用例随能力一起删掉）：
//   1. 成员行照旧显示 members[].acceptDispatch 这条 wire 字段（老对端缺字段 = 接单中）；
//   2. 普通 chat 消息走气泡：正文 + 元信息（发送者 · 时间 · seq）；
//   3. 群组页 2s 轮询与 document.hidden 的既有口径不变。
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

// 正文标记：任何一处上屏都算泄漏（契约 §0：群历史只放状态摘要）
const REPLY_BODY = 'REPLY-BODY-MUST-NOT-SHOW-9f3a';

const MEMBERS = [
  { peerId: 'peer-hub', name: 'hub-box', online: true, lastSeen: Date.now(), joinedAt: 1, baseUrl: 'http://192.168.1.20:7788', lastSeq: 9, lag: 0, acceptDispatch: true },
  { peerId: 'peer-nas', name: 'nas-box', online: true, lastSeen: Date.now(), joinedAt: 2, baseUrl: 'http://192.168.1.51:7788', lastSeq: 9, lag: 0, acceptDispatch: false },
  // 老对端：没有 acceptDispatch 字段
  { peerId: 'peer-old', name: 'old-box', online: false, lastSeen: Date.now() - 5000, joinedAt: 3, baseUrl: '', lastSeq: 4, lag: 5 },
];

const MESSAGES = [
  { seq: 1, ts: 1_700_000_600_000, from: { peerId: 'peer-hub', name: 'hub-box' }, kind: 'chat', text: '早' },
  {
    seq: 2, ts: 1_700_000_700_000, from: { peerId: 'peer-hub', name: 'hub-box' },
    kind: 'progress', text: '', meta: { phase: 'dispatch-start', target: 'peer-nas', by: 'peer-hub', status: 'running' },
  },
  {
    seq: 3, ts: 1_700_000_800_000, from: { peerId: 'peer-hub', name: 'hub-box' },
    kind: 'result', text: '', meta: { phase: 'dispatch-end', status: 'done', target: 'peer-nas', elapsedMs: 1227, replyChars: 142 },
  },
  {
    seq: 4, ts: 1_700_000_900_000, from: { peerId: 'peer-hub', name: 'hub-box' },
    // 故意把正文塞进 text：面板必须只渲染摘要，一个字都不能显示
    kind: 'result', text: REPLY_BODY,
    meta: { phase: 'dispatch-end', status: 'failed', target: 'peer-nas', reason: 'not-accepting', elapsedMs: 80, replyChars: 0 },
  },
];

function groupState(overrides = {}) {
  return {
    enabled: true,
    isHub: true,
    group: { groupId: 'g-1', name: '家里', members: MEMBERS },
    messages: MESSAGES,
    lastSeq: 4,
    leader: { peerId: 'peer-hub', name: 'hub-box', epoch: 3 },
    selfRole: 'hub',
    replica: { lastSeq: 4, leaderLastSeq: 4, lag: 0 },
    advertiseBaseUrl: 'http://192.168.1.20:7788',
    advertiseSource: 'config',
    selfBaseUrl: 'http://192.168.1.20:7788',
    role: 'leader',
    leaseUntil: Date.now() + 9000,
    quorum: 'majority',
    commitSeq: 4,
    pendingCount: 0,
    degraded: false,
    // v0.8.2-α：members[].acceptDispatch 这条 wire 字段（面板成员行照旧显示它）
    acceptDispatch: true,
    ...overrides,
  };
}

function boot({ group = groupState } = {}) {
  const calls = [];
  const timers = [];
  const document = {
    head: makeElement('head'),
    body: makeElement('body'),
    hidden: false,
    createElement: (tag) => makeElement(tag),
  };
  const jsonResponse = (body) => ({ ok: true, status: 200, json: async () => body });
  const fetchStub = async (url, init) => {
    const path = String(url).replace('/api/lan-peers/', '');
    calls.push({ path, init, body: init && init.body ? JSON.parse(init.body) : null });
    if (path === 'state') return jsonResponse({ name: 'me', instanceId: 'me-id', peers: [], pairing: null });
    if (path === 'dispatch') return jsonResponse({ dispatches: [] });
    if (path.startsWith('group?sinceSeq=')) {
      const sinceSeq = Number(path.split('=')[1]);
      return jsonResponse(typeof group === 'function' ? group({ sinceSeq }) : group);
    }
    if (path.startsWith('group/')) return jsonResponse({ ok: true });
    return jsonResponse({});
  };
  const window = {
    innerWidth: VIEW.w,
    innerHeight: VIEW.h,
    addEventListener() {},
    confirm: () => true,
    localStorage: { getItem: () => null, setItem: () => {} },
  };
  vm.runInNewContext(PANEL_SCRIPT, {
    window,
    document,
    localStorage: window.localStorage,
    fetch: fetchStub,
    setInterval: (fn, ms) => { timers.push({ fn, ms }); return timers.length; },
    clearInterval: () => {},
    setTimeout: () => 0,
    clearTimeout: () => {},
    JSON,
    Math,
    console,
  });
  const btn = document.body.children.find((el) => el.id === 'dshLpBtn');
  const panel = document.body.children.find((el) => el.id === 'dshLpPanel');
  return { btn, panel, document, calls, timers };
}

/** 打开面板并切到「群组」页（真机上的两步操作） */
async function openGroupPage(options) {
  const booted = boot(options);
  booted.btn.onclick();
  await flush();
  booted.panel.querySelector('#dshLpTabGroup').onclick();
  await flush();
  return {
    ...booted,
    members: booted.panel.querySelector('#dshLpGroupMembers'),
    messages: booted.panel.querySelector('#dshLpGroupMsgs'),
    msgBox: booted.panel.querySelector('#dshLpMsg'),
    textInput: booted.panel.querySelector('#dshLpGroupText'),
    sendButton: booted.panel.querySelector('#dshLpGroupSend'),
  };
}

const subRowOf = (row) => row.children.find((child) => String(child.className).includes('gsub'));

test('成员行显示接单状态：接单中 / 已关闭，老对端缺字段按「接单中」', async () => {
  const { members } = await openGroupPage();
  const [hubRow, nasRow, oldRow] = members.children;
  const hubAccept = subRowOf(hubRow).children.find((child) => String(child.className).startsWith('gaccept'));
  const nasAccept = subRowOf(nasRow).children.find((child) => String(child.className).startsWith('gaccept'));
  const oldAccept = subRowOf(oldRow).children.find((child) => String(child.className).startsWith('gaccept'));
  assert.equal(hubAccept.textContent, '接单中');
  assert.match(nasAccept.textContent, /已关闭/);
  assert.match(nasAccept.className, /\boff\b/);
  assert.equal(oldAccept.textContent, '接单中', '缺字段的老对端不能被显示成已关闭');
});

test('普通 chat 消息走气泡：正文 + 元信息（发送者 · 时间 · seq）', async () => {
  const { messages } = await openGroupPage();
  const bubble = messages.children[0].children[0];
  assert.match(bubble.className, /\bbubble\b/);
  assert.equal(bubble.children[0].textContent, '早', '正文原样进气泡');
  assert.match(bubble.children[1].textContent, /^hub-box · \d{2}:\d{2}:\d{2} · #1$/, '元信息：发送者 · 时间 · seq');
});

test('群组页仍然 2s 轮询，页面隐藏时停止（v0.8.2-α 没有改动这个口径）', async () => {
  const { calls, timers, document } = await openGroupPage();
  const interval = timers.find((timer) => timer.ms === 2000);
  assert.ok(interval, '2s 轮询必须还在');
  const before = calls.filter((call) => call.path.startsWith('group?sinceSeq=')).length;
  document.hidden = true;
  interval.fn();
  await flush();
  assert.equal(calls.filter((call) => call.path.startsWith('group?sinceSeq=')).length, before);
});
