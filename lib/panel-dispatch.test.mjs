// dsh-lan-peers · 面板「群组」页的派单可见面（v0.8.2-α，契约 §4/§5）。
//
// 钉死四件事：
//   1. 成员行显示接单状态（老对端缺字段 = 接单中）；
//   2. 派单回执只渲染摘要，item.text 一律不上屏（正文永不入群，也不该在面板上复活）；
//   3. 本机接单开关：点一下打 group/accept，失败只写 msg 区；
//   4. 发消息框旁有 @! 语法提示，2s 轮询与 document.hidden 的既有口径不变。
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
    // v0.8.2-α：本机开关 + 派单实时状态
    acceptDispatch: true,
    dispatch: { lastTarget: 'peer-nas', lastAt: Date.now() - 120_000, inFlight: false },
    ...overrides,
  };
}

function boot({ group = groupState, acceptAnswer = { ok: true, acceptDispatch: false, persisted: true }, acceptError = null, postAnswer = { ok: true, seq: 5, ts: 1_700_001_000_000 } } = {}) {
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
    if (path === 'group/accept') {
      if (acceptError) throw new Error(acceptError);
      return jsonResponse(typeof acceptAnswer === 'function' ? acceptAnswer(init) : acceptAnswer);
    }
    if (path === 'group/post') {
      return jsonResponse(typeof postAnswer === 'function' ? postAnswer(init) : postAnswer);
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
    acceptButton: booted.panel.querySelector('#dshLpAccept'),
    syntaxHints: booted.panel.querySelector('#dshLpGroupSyntax'),
    dispatchLine: booted.panel.querySelector('#dshLpGroupDispatchState'),
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

test('派单回执只渲染摘要：派单 → 目标：done（耗时 / 字数）', async () => {
  const { messages } = await openGroupPage();
  // seq2 = dispatch-start，seq3 = dispatch-end(done)，seq4 = dispatch-end(failed)
  // v0.8.5-α：派单回执是居中的系统行（.gsys，一行小字），不再和正文挤在同一行。
  assert.match(messages.children[1].textContent, /^派单 → nas-box：进行中 · \d{2}:\d{2}:\d{2} · #2$/);
  assert.match(messages.children[1].className, /\bgsys\b/);
  assert.match(messages.children[2].textContent, /派单 → nas-box：done（1227ms \/ 142字）/);
  assert.match(messages.children[3].textContent, /派单 → nas-box：failed（not-accepting \/ 80ms \/ 0字）/);
});

test('派单消息里的 item.text 绝不上屏（正文永不入群，也不在面板复活）', async () => {
  const { messages, panel } = await openGroupPage();
  for (const row of messages.children) {
    assert.doesNotMatch(row.textContent, new RegExp(REPLY_BODY), '正文不得出现在群消息行');
  }
  assert.doesNotMatch(panel.querySelector('#dshLpMsg').textContent, new RegExp(REPLY_BODY));
  assert.doesNotMatch(PANEL_SCRIPT, new RegExp(REPLY_BODY));
});

test('普通 chat 消息走气泡：正文 + 元信息（发送者 · 时间 · seq）', async () => {
  const { messages } = await openGroupPage();
  const bubble = messages.children[0].children[0];
  assert.match(bubble.className, /\bbubble\b/);
  assert.equal(bubble.children[0].textContent, '早', '正文原样进气泡');
  assert.match(bubble.children[1].textContent, /^hub-box · \d{2}:\d{2}:\d{2} · #1$/, '元信息：发送者 · 时间 · seq');
});

test('发消息框旁提示两种语法：@!名字 任务 = 派单，@名字 = 提及', async () => {
  // 骨架是 PANEL_SCRIPT 里的静态字符串（DOM 桩不解析 innerHTML），所以断言源码里的那段文案。
  assert.match(PANEL_SCRIPT, /id="dshLpGroupSyntax">@!名字 任务 = 派单给该成员 · @名字 = 提及（不派单）</);
  const { syntaxHints } = await openGroupPage();
  assert.ok(syntaxHints, '语法提示的元素 id 必须在骨架里');
});

test('本机接单开关：文案跟着群状态的 acceptDispatch 走', async () => {
  const on = await openGroupPage();
  assert.equal(on.acceptButton.textContent, '本机接单：接单中');
  const off = await openGroupPage({ group: () => groupState({ acceptDispatch: false }) });
  assert.equal(off.acceptButton.textContent, '本机接单：已关闭');
});

test('点开关 → POST group/accept（取反）→ 文案与 msg 都更新', async () => {
  // 真机上 host 改完会立刻回显新值：桩里也让群状态跟着变，才能验证「刷新后文案一致」。
  let accept = true;
  const { acceptButton, calls, msgBox } = await openGroupPage({
    group: () => groupState({ acceptDispatch: accept }),
    acceptAnswer: (init) => {
      accept = JSON.parse(init.body).acceptDispatch;
      return { ok: true, acceptDispatch: accept, persisted: true };
    },
  });
  await acceptButton.onclick();
  await flush();
  const posted = calls.find((call) => call.path === 'group/accept');
  assert.deepEqual(posted.body, { acceptDispatch: false }, '当前是接单中，点一下应关闭');
  assert.equal(acceptButton.textContent, '本机接单：已关闭');
  assert.match(msgBox.textContent, /本机接单：已关闭/);
});

test('开关失败只写 msg 区（不弹异常、文案不乱改）', async () => {
  const { acceptButton, msgBox } = await openGroupPage({ acceptError: 'accept-toggle-unsupported' });
  await acceptButton.onclick();
  await flush();
  assert.match(msgBox.textContent, /切换接单失败：accept-toggle-unsupported/);
  assert.equal(acceptButton.textContent, '本机接单：接单中', '失败时不能假装已经切过去');
});

test('persisted=false 时如实说明「重启后回到配置值」', async () => {
  const { acceptButton, msgBox } = await openGroupPage({
    acceptAnswer: { ok: true, acceptDispatch: false, persisted: false },
  });
  await acceptButton.onclick();
  await flush();
  assert.match(msgBox.textContent, /重启后回到配置值/);
});

test('派单状态行：inFlight 时显示「等回复」，否则显示上次派单与时间', async () => {
  const busy = await openGroupPage({
    group: () => groupState({ dispatch: { lastTarget: 'peer-nas', lastAt: Date.now(), inFlight: true } }),
  });
  assert.match(busy.dispatchLine.textContent, /派单中 → nas-box（等回复）/);

  const idle = await openGroupPage();
  assert.match(idle.dispatchLine.textContent, /上次派单 → nas-box · .*前/);

  const unknown = await openGroupPage({ group: () => groupState({ dispatch: null }) });
  assert.equal(unknown.dispatchLine.textContent, '', '门面没接线时状态行留空，不编造');
});

test('发送带 @! 的消息：群消息照发，msg 区显示派单摘要', async () => {
  const { textInput, sendButton, calls, msgBox } = await openGroupPage({
    postAnswer: {
      ok: true, seq: 5, ts: 1_700_001_000_000,
      dispatch: { target: 'peer-nas', status: 'done', reason: '', elapsedMs: 1200, replyChars: 12 },
    },
  });
  textInput.value = '@!nas-box 跑回归';
  await sendButton.onclick();
  await flush();
  const posted = calls.find((call) => call.path === 'group/post');
  assert.deepEqual(posted.body, { kind: 'chat', text: '@!nas-box 跑回归' });
  assert.match(msgBox.textContent, /已发送 · 派单 → nas-box：done（1200ms \/ 12字）/);
});

test('派单失败时的发送：msg 区显示 failed 与 reason', async () => {
  const { textInput, sendButton, msgBox } = await openGroupPage({
    postAnswer: {
      ok: true, seq: 5, ts: 1,
      dispatch: { target: 'peer-nas', status: 'failed', reason: 'offline', elapsedMs: 20, replyChars: null },
    },
  });
  textInput.value = '@!nas-box 跑回归';
  await sendButton.onclick();
  await flush();
  assert.match(msgBox.textContent, /派单 → nas-box：failed（offline \/ 20ms \/ 0字）/);
});

test('skipped（没有 @! 目标）不算派单：只报已发送，不显示「派单完成」', async () => {
  const { textInput, sendButton, msgBox } = await openGroupPage({
    postAnswer: { ok: true, seq: 5, ts: 1, dispatch: { target: '', status: 'skipped', reason: 'no-target' } },
  });
  textInput.value = '普通消息';
  await sendButton.onclick();
  await flush();
  assert.match(msgBox.textContent, /^已发送$/);
  assert.doesNotMatch(msgBox.textContent, /派单/);
});

test('群未启用：接单开关收起，不显示派单状态', async () => {
  const { acceptButton, dispatchLine } = await openGroupPage({
    group: () => ({ enabled: false, isHub: false, group: null, messages: [], lastSeq: 0 }),
  });
  assert.equal(acceptButton.style.display, 'none');
  assert.equal(dispatchLine.textContent, '');
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
