// dsh-lan-peers · v0.8.5-α（契约 §6，Lane G2）注入面板的「私聊」页。
//
// PANEL_SCRIPT 是浏览器脚本，无法 import：用与 panel-group/panel-drag 同款的
// 最小 DOM 桩执行它，再断言伙伴列表 / 气泡对话 / 发送中替换 / 1s 轮询 + hidden 停，
// 以及「正文只走 textContent、私聊段零反引号、无 console.error」三条铁律。
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

const PEER_B = { peerId: 'peer-b-1234', name: '书房', baseUrl: 'http://10.0.0.2:7788', lastSeen: new Date().toISOString() };
const PEER_C = { peerId: 'peer-c-5678', name: 'nas-box', baseUrl: 'http://10.0.0.3:7788', lastSeen: Date.now() - 7 * 60 * 1000 };
const AT = 1_760_000_000_000;

function dmMessages() {
  return [
    { id: 'm-1', ts: AT, from: 'self', text: '我叫你小助手', sessionId: 's-1', state: 'sent' },
    { id: 'm-2', ts: AT + 900, from: 'peer', text: '好的，记住了', sessionId: 's-1', state: 'sent' },
  ];
}

function boot({
  peers = [PEER_B, PEER_C],
  messages = dmMessages,
  sync = { ok: true, added: 2, total: 2 },
  send = { ok: true, id: 'm-3', sessionId: 's-1', reply: '还记得，你让我叫小助手', elapsedMs: 1227, reused: true },
  sendError = null,
  hidden = false,
} = {}) {
  const created = [];
  const calls = [];
  const timers = [];
  const document = {
    head: makeElement('head'),
    body: makeElement('body'),
    hidden,
    createElement: (tag) => { const el = makeElement(tag); created.push(el); return el; },
  };
  const jsonResponse = (body) => ({ ok: true, status: 200, json: async () => body });
  const fetchStub = async (url, init) => {
    const path = String(url).replace('/api/lan-peers/', '');
    calls.push({ path, init });
    if (path === 'state') return jsonResponse({ name: 'me', instanceId: 'me-id', peers, pairing: null });
    if (path === 'dispatch') return jsonResponse({ dispatches: [] });
    if (path === 'dm/sync') return jsonResponse(sync);
    if (path === 'dm/send') {
      if (sendError) throw new Error(sendError);
      return jsonResponse(send);
    }
    if (path.startsWith('dm?peer=')) {
      return jsonResponse({
        peer: { peerId: decodeURIComponent(path.slice('dm?peer='.length)), name: '书房' },
        messages: typeof messages === 'function' ? messages() : messages,
      });
    }
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
  const byId = (id) => created.find((el) => el.id === id);
  return { btn, panel, document, calls, created, timers, byId };
}

/** 打开面板并切到「私聊」页（真机上的两步操作）；dmTimer 只认切页之后新起的 1000ms 计时器。 */
async function openDmPage(options) {
  const booted = boot(options);
  booted.btn.onclick();
  await flush();
  const before = booted.timers.length;
  booted.panel.querySelector('#dshLpTabDm').onclick();
  await flush();
  return {
    ...booted,
    page: booted.byId('dshLpPageDm'),
    listBox: booted.byId('dshLpDmList'),
    msgs: booted.byId('dshLpDmMsgs'),
    input: booted.byId('dshLpDmText'),
    sendBtn: booted.byId('dshLpDmSend'),
    peerLine: booted.byId('dshLpDmPeer'),
    head: booted.byId('dshLpDmHead'),
    msgBox: booted.panel.querySelector('#dshLpMsg'),
    dmTimer: booted.timers.slice(before).find((timer) => timer.ms === 1000),
  };
}

const dmCalls = (calls) => calls.filter((call) => call.path.startsWith('dm'));

test('「私聊」是第三个并列页签：点击切换显示并高亮', async () => {
  const { panel, page } = await openDmPage();
  assert.equal(page.style.display, 'block');
  assert.equal(panel.querySelector('#dshLpPagePeers').style.display, 'none');
  assert.equal(panel.querySelector('#dshLpPageGroup').style.display, 'none');
  assert.match(panel.querySelector('#dshLpTabDm').className, /on/);
  assert.doesNotMatch(panel.querySelector('#dshLpTabGroup').className, /on\b/);

  panel.querySelector('#dshLpTabPeers').onclick();
  assert.equal(page.style.display, 'none', '切回伙伴页要把私聊页藏起来');
  assert.equal(panel.querySelector('#dshLpPagePeers').style.display, 'block');
});

test('打开私聊：先 POST dm/sync 再 GET dm?peer=，伙伴列表带在线点 + 名字 + 最近时间', async () => {
  const { calls, listBox, page, head, peerLine } = await openDmPage();

  const dm = dmCalls(calls);
  const syncIndex = dm.findIndex((call) => call.path === 'dm/sync');
  const listIndex = dm.findIndex((call) => call.path.startsWith('dm?peer='));
  assert.ok(syncIndex >= 0 && listIndex >= 0, '打开私聊必须 sync 一次并拉历史');
  assert.ok(syncIndex < listIndex, '契约 §6：先 sync 后渲染');
  assert.deepEqual(JSON.parse(dm[syncIndex].init.body), { peerId: 'peer-b-1234' });
  assert.equal(dm[syncIndex].init.method, 'POST');
  assert.equal(dm[listIndex].path, 'dm?peer=peer-b-1234');

  assert.equal(page.style.display, 'block');
  assert.match(head.textContent, /已对齐 2 条（本地共 2 条）/);
  assert.match(peerLine.textContent, /与 书房 私聊/);

  assert.equal(listBox.children.length, 2, '两个伙伴各一行');
  const [first, second] = listBox.children;
  assert.equal(first.children[0].textContent, '●');
  assert.match(first.children[0].className, /\bon\b/);
  assert.equal(first.children[1].textContent, '书房');
  assert.match(first.children[2].textContent, /^(最近 \d{2}:\d{2}:\d{2}|\d+s前|\d+m前)$/);
  assert.equal(second.children[0].textContent, '○');
  assert.doesNotMatch(second.children[0].className, /\bon\b/);
  assert.equal(second.children[1].textContent, 'nas-box');
});

test('气泡对话：自己靠右、对方靠左，正文只进 textContent', async () => {
  const evil = '<img src=x onerror=alert(1)>';
  const { msgs, created } = await openDmPage({
    messages: () => ([
      { id: 'm-1', ts: AT, from: 'self', text: '我叫你小助手', sessionId: 's-1', state: 'sent' },
      { id: 'm-2', ts: AT + 900, from: 'peer', text: evil, sessionId: 's-1', state: 'sent' },
    ]),
  });

  assert.equal(msgs.children.length, 2);
  const [mine, theirs] = msgs.children;
  assert.match(mine.className, /\bself\b/);
  assert.match(theirs.className, /\bpeer\b/);
  assert.equal(mine.children[0].children[0].textContent, '我叫你小助手');
  assert.equal(theirs.children[0].children[0].textContent, evil, '对端正文原样落进 textContent');
  assert.equal(created.some((el) => el.tagName === 'IMG'), false, '不得因为正文而创建标签');
});

test('发送：先上屏「发送中」，成功后替换为对方气泡', async () => {
  const { msgs, input, sendBtn, calls } = await openDmPage();

  input.value = '我刚才让你叫什么？';
  sendBtn.onclick();
  // 不等 promise：这一刻必须已经有一条「发送中」在屏幕上。
  assert.equal(msgs.children.length, 3);
  const pending = msgs.children[2];
  assert.match(pending.className, /\bself\b/);
  assert.equal(pending.children[0].children[0].textContent, '我刚才让你叫什么？');
  assert.equal(pending.children[0].children[1].textContent, '发送中');

  await flush();
  const posted = calls.find((call) => call.path === 'dm/send');
  assert.ok(posted, '必须 POST dm/send');
  assert.equal(posted.init.method, 'POST');
  assert.deepEqual(JSON.parse(posted.init.body), { peerId: 'peer-b-1234', text: '我刚才让你叫什么？' });
  assert.equal(input.value, '', '发送成功后清空输入框');

  // 成功后：「发送中」消失，换成自己一条 + 对方一条（回复替换成对方气泡）。
  assert.equal(msgs.children.length, 4);
  assert.equal(msgs.children.every((row) => !/发送中/.test(row.textContent)), true);
  const last = msgs.children[3];
  assert.match(last.className, /\bpeer\b/);
  assert.equal(last.children[0].children[0].textContent, '还记得，你让我叫小助手');
});

test('发送失败：只写 msg 区，正文放回输入框，不抛错也不留「发送中」', async () => {
  const { msgs, input, sendBtn, msgBox } = await openDmPage({ sendError: '409 peer-offline' });

  input.value = '在吗';
  sendBtn.onclick();
  await flush();

  assert.match(msgBox.textContent, /私聊发送失败：409 peer-offline/);
  assert.equal(input.value, '在吗', '失败不吞用户正文');
  assert.equal(msgs.children.length, 2, '「发送中」气泡要撤掉，不能留着骗人');
  assert.equal(msgs.children.some((row) => /发送中/.test(row.textContent)), false);
});

test('私聊用 1s 轮询，document.hidden 时停；群组 2s 节拍不碰私聊', async () => {
  const { calls, document, dmTimer } = await openDmPage();
  assert.ok(dmTimer, '私聊必须有自己 1s 的计时器');
  assert.equal(calls.some((call) => call.path.startsWith('group')), false, '私聊页不发群请求（2s 节拍不参与）');

  const before = dmCalls(calls).length;
  document.hidden = true;
  dmTimer.fn();
  await flush();
  assert.equal(dmCalls(calls).length, before, '页面隐藏时不得轮询私聊');

  document.hidden = false;
  dmTimer.fn();
  await flush();
  assert.equal(dmCalls(calls).length, before + 1, '重新可见后恢复');
  assert.match(dmCalls(calls)[dmCalls(calls).length - 1].path, /^dm\?peer=peer-b-1234$/);
});

test('私聊段零反引号模板字符串、无 console.error，正文不进群', async () => {
  const start = PANEL_SCRIPT.indexOf('v0.8.5-α 私聊页');
  const end = PANEL_SCRIPT.indexOf('function setTab(', start);
  assert.ok(start > 0 && end > start, '私聊段必须能被定位到');
  const section = PANEL_SCRIPT.slice(start, end);
  assert.equal(section.includes('\u0060'), false, '私聊段不得出现反引号');
  assert.equal(/\$\{/.test(section), false, '私聊段不得出现模板插值');
  assert.equal(PANEL_SCRIPT.includes('console.error'), false, '面板不得用 console.error');

  const { calls } = await openDmPage();
  const input = calls.find((call) => call.path === 'state');
  assert.ok(input, '私聊页复用 GET state 拿伙伴列表');
  assert.equal(calls.some((call) => call.path === 'group/post'), false, '私聊正文不得进群');
});
