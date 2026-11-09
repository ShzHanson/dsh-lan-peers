// dsh-lan-peers · 「粘底」回归（bug：用户向上翻看历史时，轮询把人拽回最下方）。
// 前半段是私聊页（renderDmMessages，1s 节拍）；后半段是群聊页（appendMessages，2s 节拍，增量追加）。
//
// PANEL_SCRIPT 是浏览器脚本、无法 import：与 panel-dm / panel-wechat-ui 同款最小 DOM 桩执行它，
// 再断言两个视图各自的滚动语义。桩只在三处照抄真实浏览器：
//   ① 子节点数决定 scrollHeight（每行 ROW_H），② innerHTML='' 清子节点并把 scrollTop 归零，
//   ③ scrollTop 永远被夹在 [0, scrollHeight - clientHeight]。
// 于是「轮询把用户拽回底部」这类失败是真失败，不是桩里 scrollTop 恰好没被重置的假通过。
import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { PANEL_SCRIPT } from './admin.mjs';

const ROW_H = 30;        // 一条气泡 30px
const CLIENT_H = 200;    // 可视高 200px：20 条 = 600px 内容，可滚 400px
const AT = 1_760_000_000_000;

function makeElement(tag) {
  const cache = new Map();
  let top = 0;
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
    clientHeight: CLIENT_H,
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
  Object.defineProperty(el, 'scrollHeight', { get: () => el.children.length * ROW_H });
  Object.defineProperty(el, 'scrollTop', {
    get: () => top,
    set: (value) => {
      const max = Math.max(0, el.children.length * ROW_H - CLIENT_H);
      const n = Number(value);
      top = Number.isFinite(n) ? Math.min(Math.max(0, n), max) : 0;
    },
  });
  let html = '';
  Object.defineProperty(el, 'innerHTML', {
    get: () => html,
    set: (value) => {
      html = value;
      if (value === '') {
        el.children.length = 0;
        top = 0;                       // 清空内容，浏览器就是这么把 scrollTop 归零的
      }
    },
  });
  return el;
}

const flush = async (rounds = 20) => {
  for (let i = 0; i < rounds; i += 1) await new Promise((resolve) => setTimeout(resolve, 1));
};

const CTX_COUNT = 20;

function dmMessages(count) {
  const out = [];
  for (let i = 0; i < count; i += 1) {
    out.push({
      id: 'm-' + String(i + 1),
      ts: AT + i * 1000,
      from: i % 2 === 0 ? 'self' : 'peer',
      text: '第 ' + String(i + 1) + ' 条',
      sessionId: 's-1',
      state: 'sent',
    });
  }
  return out;
}

/** 起面板、开私聊页；messages 可变，用来模拟轮询期间对手又发了一条。 */
function boot() {
  const state = { messages: dmMessages(CTX_COUNT) };
  const created = [];
  const timers = [];
  const document = {
    head: makeElement('head'),
    body: makeElement('body'),
    hidden: false,
    createElement: (tag) => { const el = makeElement(tag); created.push(el); return el; },
  };
  const jsonResponse = (body) => ({ ok: true, status: 200, json: async () => body });
  const fetchStub = async (url) => {
    const path = String(url).replace('/api/lan-peers/', '');
    if (path === 'state') {
      return jsonResponse({
        name: 'me',
        instanceId: 'me-id',
        peers: [{ peerId: 'peer-b-1234', name: '书房', lastSeen: new Date().toISOString() }],
        pairing: null,
      });
    }
    if (path === 'dispatch') return jsonResponse({ dispatches: [] });
    if (path === 'dm/sync') return jsonResponse({ ok: true, added: CTX_COUNT, total: CTX_COUNT });
    if (path.startsWith('dm?peer=')) {
      return jsonResponse({
        peer: { peerId: 'peer-b-1234', name: '书房' },
        messages: state.messages.slice(),
      });
    }
    return jsonResponse({});
  };
  const window = {
    innerWidth: 1000,
    innerHeight: 800,
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
  return { btn, panel, document, state, created, timers };
}

/** 打开面板 -> 切到私聊页 -> 按 1s 节拍跑一次 pollDm（真机上浏览器每秒做的事）。 */
async function openAndPoll() {
  const app = boot();
  app.btn.onclick();
  await flush();
  const before = app.timers.length;
  app.panel.querySelector('#dshLpTabDm').onclick();
  await flush();
  const msgs = app.created.find((el) => el.id === 'dshLpDmMsgs');
  const dmTimer = app.timers.slice(before).find((timer) => timer.ms === 1000);
  assert.ok(msgs, '私聊气泡容器必须存在');
  assert.ok(dmTimer, '私聊必须有自己的 1s 计时器');
  // 一次真实的轮询：pollDm -> GET dm?peer= -> applyDmView -> renderDmMessages。
  const poll = async () => { dmTimer.fn(); await flush(); };
  return { ...app, msgs, poll };
}

test('停在底部：首屏渲染后贴在最新一条上', async () => {
  const { msgs } = await openAndPoll();
  assert.equal(msgs.children.length, CTX_COUNT);
  assert.equal(msgs.scrollHeight, CTX_COUNT * ROW_H);
  assert.equal(msgs.scrollTop, CTX_COUNT * ROW_H - CLIENT_H, '首次进来应当直接看到最新一条');
});

test('翻上去看历史：轮询重新渲染后 scrollTop 一格都不动', async () => {
  const { msgs, poll } = await openAndPoll();
  const maxScroll = CTX_COUNT * ROW_H - CLIENT_H;
  msgs.scrollTop = 100;                      // 用户往上翻，停在距底 300px 处
  assert.equal(msgs.scrollTop, 100);
  assert.ok(maxScroll - msgs.scrollTop > 24, '前提：用户确实不在底部附近');

  await poll();                              // 1s 节拍照常拉一次 dm?peer=
  assert.equal(msgs.scrollTop, 100, '轮询不得改变用户当前的阅读位置');

  await poll();                              // 再来一次，确认不是只有第一次不动
  assert.equal(msgs.scrollTop, 100, '第二次轮询同样不得拽回底部');
  assert.equal(msgs.children.length, CTX_COUNT, '内容没变，渲染照旧');
});

test('停在底部：轮询带来新消息时跟着最新一条走', async () => {
  const { msgs, poll, state } = await openAndPoll();
  assert.equal(msgs.scrollTop, CTX_COUNT * ROW_H - CLIENT_H, '前提：用户停在新消息处');

  state.messages = dmMessages(CTX_COUNT + 1);
  await poll();
  assert.equal(msgs.children.length, CTX_COUNT + 1);
  assert.equal(msgs.scrollTop, (CTX_COUNT + 1) * ROW_H - CLIENT_H, '说好停底部的用户必须跟到最新一条');
});

test('阈值 24px：距底 20px 仍算底部（跟新消息），距底 200px 算翻看历史（原地不动）', async () => {
  const near = await openAndPoll();
  near.msgs.scrollTop = CTX_COUNT * ROW_H - CLIENT_H - 20;   // 距底 20px，阈值内
  near.state.messages = dmMessages(CTX_COUNT + 1);
  await near.poll();
  assert.equal(near.msgs.scrollTop, (CTX_COUNT + 1) * ROW_H - CLIENT_H, '阈值内的用户仍视为停在底部');

  const far = await openAndPoll();
  far.msgs.scrollTop = CTX_COUNT * ROW_H - CLIENT_H - 200;   // 距底 200px，阈值外
  far.state.messages = dmMessages(CTX_COUNT + 1);
  await far.poll();
  assert.equal(far.msgs.scrollTop, CTX_COUNT * ROW_H - CLIENT_H - 200, '阈值外的用户一根手指都不许被挪');
});

// ---------------------------------------------------------------------------
// 群聊页：appendMessages 是**增量追加**（不清空列表），所以「不动」是默认，「动」要理由：
// 本来就在底部（跟新消息），或者追加途中撞上 500 条上限清空过（读的内容已没了）。
// ---------------------------------------------------------------------------

const GROUP_MEMBERS = [
  { peerId: 'peer-hub', name: 'hub-box', online: true, lastSeen: new Date().toISOString(), joinedAt: 1, baseUrl: 'http://192.168.1.20:7788', lastSeq: 20, lag: 0 },
];

const range = (from, to) => {
  const out = [];
  for (let i = from; i <= to; i += 1) out.push(i);
  return out;
};

const groupMessages = (seqs) => seqs.map((seq) => ({
  seq,
  ts: AT + seq * 1000,
  from: { peerId: 'peer-hub', name: 'hub-box' },
  kind: 'chat',
  text: '群消息 ' + String(seq),
}));

function bootGroup(seqs) {
  // seqs = 服务端历史里的 seq 列表；raw 非 null 时原样返回（用来造「非空但全是重复 seq」的一帧）。
  const state = { seqs: seqs.slice(), raw: null };
  const created = [];
  const timers = [];
  const document = {
    head: makeElement('head'),
    body: makeElement('body'),
    hidden: false,
    createElement: (tag) => { const el = makeElement(tag); created.push(el); return el; },
  };
  const jsonResponse = (body) => ({ ok: true, status: 200, json: async () => body });
  const fetchStub = async (url) => {
    const path = String(url).replace('/api/lan-peers/', '');
    if (path === 'state') return jsonResponse({ name: 'me', instanceId: 'me-id', peers: [], pairing: null });
    if (path === 'dispatch') return jsonResponse({ dispatches: [] });
    if (path.startsWith('group?sinceSeq=')) {
      const since = Number(path.slice('group?sinceSeq='.length));
      const picked = state.raw !== null ? state.raw : state.seqs.filter((seq) => seq > since);
      return jsonResponse({
        enabled: true,
        isHub: false,
        group: { groupId: 'g-1', name: '家里', members: GROUP_MEMBERS },
        messages: groupMessages(picked),
        lastSeq: state.seqs.length ? state.seqs[state.seqs.length - 1] : 0,
        leader: { peerId: 'peer-hub', name: 'hub-box', epoch: 3 },
        selfRole: 'member',
        replica: { lastSeq: 0, leaderLastSeq: 0, lag: 0 },
        advertiseBaseUrl: 'http://192.168.1.20:7788',
        advertiseSource: 'config',
        selfBaseUrl: 'http://192.168.1.20:7788',
        role: 'follower',
        leaseUntil: Date.now() + 9000,
        quorum: 'majority',
        commitSeq: 0,
        pendingCount: 0,
        degraded: false,
      });
    }
    return jsonResponse({});
  };
  const window = {
    innerWidth: 1000,
    innerHeight: 800,
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
  return { btn, panel, created, timers, state };
}

/** 打开面板 -> 切到群组页 -> 按 2s 节拍跑一次 pollGroup（renderGroup -> appendMessages）。 */
async function openGroupAndPoll(seqs) {
  const app = bootGroup(seqs);
  app.btn.onclick();
  await flush();
  const before = app.timers.length;
  app.panel.querySelector('#dshLpTabGroup').onclick();
  await flush();
  const msgs = app.panel.querySelector('#dshLpGroupMsgs');
  const groupTimer = app.timers.slice(before).find((timer) => timer.ms === 2000);
  assert.ok(groupTimer, '群组必须有自己的 2s 计时器');
  const poll = async () => { groupTimer.fn(); await flush(40); };
  return { ...app, msgs, poll };
}

test('群聊·首屏：从空列表开始，仍然落在最新一条', async () => {
  const { msgs } = await openGroupAndPoll(range(1, 20));
  assert.equal(msgs.children.length, 20);
  assert.equal(msgs.scrollTop, 20 * ROW_H - CLIENT_H, '进页面就该看到最新一条');
});

test('群聊·翻上去看历史：新消息到达后 scrollTop 一格都不动', async () => {
  const { msgs, poll, state } = await openGroupAndPoll(range(1, 20));
  msgs.scrollTop = 100;
  assert.ok(20 * ROW_H - CLIENT_H - msgs.scrollTop > 24, '前提：用户确实不在底部附近');

  state.seqs = range(1, 22);
  await poll();
  assert.equal(msgs.children.length, 22, '前提：新消息确实被追加了');
  assert.equal(msgs.scrollTop, 100, '增量追加不得改变用户当前的阅读位置');

  state.seqs = range(1, 23);
  await poll();
  assert.equal(msgs.scrollTop, 100, '下一次节拍同样不许把人拽回底部');
});

test('群聊·停在底部：新消息到达时跟着最新一条走', async () => {
  const { msgs, poll, state } = await openGroupAndPoll(range(1, 20));
  assert.equal(msgs.scrollTop, 20 * ROW_H - CLIENT_H, '前提：用户停在最新一条');

  state.seqs = range(1, 21);
  await poll();
  assert.equal(msgs.children.length, 21);
  assert.equal(msgs.scrollTop, 21 * ROW_H - CLIENT_H, '说好停在底部的用户必须跟到最新一条');
});

test('群聊·没有新内容：added === 0 的那一帧连一个像素都不动', async () => {
  const { msgs, poll, state } = await openGroupAndPoll(range(1, 20));
  msgs.scrollTop = 100;

  await poll();                       // 服务端没有新 seq：appendMessages 直接返回
  assert.equal(msgs.scrollTop, 100, '空帧不许动');

  state.raw = [20];                   // 非空但 seq 已渲染过：去重后 added 仍是 0
  await poll();
  assert.equal(msgs.children.length, 20, '前提：重复 seq 不追加');
  assert.equal(msgs.scrollTop, 100, '去重帧同样不许动');
});

test('群聊·撞上 500 条上限被清空：读的内容已没了，规则是落回最新一条', async () => {
  const { msgs, poll, state } = await openGroupAndPoll(range(1, 20));
  msgs.scrollTop = 100;                       // 用户正在翻历史
  state.seqs = range(1, 521);                 // 一次来 501 条，追加途中必然撞上限并清空
  await poll();
  // 20 + 481 条 = 501 条时清空，剩下 20 条落在新列表里 —— 这个数字同时证明裁剪确实发生过、上限仍在。
  assert.equal(msgs.children.length, 20, '前提：500 条上限的裁剪确实触发过');
  assert.equal(msgs.scrollTop, msgs.scrollHeight - CLIENT_H, '内容已被清空重建，落到最新一条');
});

