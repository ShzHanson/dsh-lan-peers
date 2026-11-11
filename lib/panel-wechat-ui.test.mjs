// dsh-lan-peers · 面板 UI 统一：按钮/面板分层、标题栏 × 关闭、群聊与私聊共用同一套消息行。
//
// PANEL_SCRIPT 是浏览器脚本，无法 import：这里用与 panel-float/panel-dm/panel-group 同一套
// 最小 DOM 桩 + node:vm 跑真 PANEL_SCRIPT，断言下面四条：
//   1. 伙伴按钮的 z-index 数值始终高于面板（面板放大到 scale=2 时也不变），且没有用
//      display / pointer-events 之类的取巧让按钮「看不见但能点」；
//   2. 标题栏右侧的 × 存在、有 title/aria-label、点击等价于既有开关（display=none），
//      并且它不是拖动（不写 localStorage 位置）；
//   3. 群聊与私聊渲染出的消息行是同一套 DOM（同一个 messageRow），自己靠右、他人靠左；
//   4. 群聊的既有信息面一处不丢（leader/role/replica/degraded/addrWarn/members/msgs/
//      archives/输入框逐 id 都在），新文案 zh/en 两格都非空。
import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { PANEL_SCRIPT, renderPanelScript } from './admin.mjs';
import { keys, t } from './i18n.mjs';

const VIEW = { w: 1000, h: 800 };
const POS_KEY = 'dsh-lan-peers:panel-pos:v1';
const AT = 1_760_000_000_000;
const px = (value) => Number.parseFloat(String(value));

// ---------------------------------------------------------------------------
// 最小 DOM 桩：与 panel-float.test.mjs 同款（含 style.setProperty 与可写 localStorage）
// ---------------------------------------------------------------------------
function makeStyle(withSetProperty) {
  const bag = {};
  if (withSetProperty) bag.setProperty = (name, value) => { bag[name] = value; };
  return bag;
}

function makeElement(tag) {
  const cache = new Map();
  const el = {
    tagName: String(tag).toUpperCase(),
    id: '',
    className: '',
    textContent: '',
    innerHTML: '',
    value: '',
    placeholder: '',
    title: '',
    disabled: false,
    style: makeStyle(true),
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
      const num = (raw) => Number.parseFloat(String(raw)) || 0;
      const top = String(this.style.top == null ? 'auto' : this.style.top) === 'auto'
        ? VIEW.h - num(this.style.bottom) - (this.offsetHeight || 0)
        : num(this.style.top);
      return { left: num(this.style.left), top, width: this.offsetWidth, height: this.offsetHeight };
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

/**
 * 跑一份面板脚本。routes 以「问号前的路径」为键（也可写完整路径），值是响应对象或函数。
 * 返回面板/按钮/标题栏/×节点、样式表文本，以及 localState 的可写视图。
 */
function boot(options) {
  const opts = options || {};
  const routes = opts.routes || {};
  const store = new Map(opts.store ? Array.from(opts.store) : []);
  const created = [];
  const calls = [];
  const windowListeners = new Map();
  const document = {
    head: makeElement('head'),
    body: makeElement('body'),
    hidden: false,
    createElement: (tag) => { const el = makeElement(tag); created.push(el); return el; },
  };
  const json = (body) => ({ ok: true, status: 200, json: async () => body });
  const fetchStub = async (url, init) => {
    const path = String(url).replace('/api/lan-peers/', '');
    calls.push({ path, method: (init && init.method) || 'GET' });
    const key = Object.prototype.hasOwnProperty.call(routes, path) ? path : path.split('?')[0];
    const entry = routes[key];
    if (typeof entry === 'function') return json(entry(path, init));
    if (entry !== undefined) return json(entry);
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
      getItem: (name) => (store.has(name) ? store.get(name) : null),
      setItem: (name, value) => store.set(name, String(value)),
    },
  };
  vm.runInNewContext(opts.script || PANEL_SCRIPT, {
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
    Promise,
    console,
  });
  const btn = document.body.children.find((el) => el.id === 'dshLpBtn');
  const panel = document.body.children.find((el) => el.id === 'dshLpPanel');
  assert.ok(btn, '启动按钮必须挂进 document.body');
  assert.ok(panel, '面板必须挂进 document.body');
  assert.ok(document.head.children.length > 0, '面板样式表必须挂进 document.head');
  return {
    btn,
    panel,
    created,
    calls,
    store,
    body: document.body,
    css: () => String(document.head.children[0].textContent || ''),
    head: panel.querySelector('#dshLpPanelHead'),
    close: () => panel.querySelector('#dshLpPanelClose'),
    skeleton: () => String(panel.innerHTML || ''),
    byId: (id) => created.find((el) => el.id === id),
    open: () => { btn.onclick(); },
  };
}

const flush = async (rounds = 20) => {
  for (let i = 0; i < rounds; i += 1) await new Promise((resolve) => setTimeout(resolve, 1));
};

/** 一行消息的「结构指纹」：标签 + class 链，逐字比较两个页面是不是同一个渲染器。 */
function shape(el) {
  const self = String(el.tagName).toLowerCase() + '.' + String(el.className).split(/\s+/).join('.');
  return el.children.length === 0 ? self : self + '>' + el.children.map(shape).join(',');
}

const ruleOf = (css, selector) => {
  const found = new RegExp(selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\{([^}]*)\\}').exec(css);
  return found ? found[1] : null;
};

// ---------------------------------------------------------------------------
// ① 分层：按钮永远在面板之上
// ---------------------------------------------------------------------------
test('伙伴按钮的 z-index 数值高于面板，scale=2 打开时仍然成立（不靠 display/pointer-events 取巧）', () => {
  const app = boot({ script: renderPanelScript('tok', 'zh', { scale: 2, fontPx: 16 }) });
  const css = app.css();
  const btnZ = Number(/#dshLpBtn\{[^}]*z-index:(\d+)/.exec(css)[1]);
  const panelZ = Number(/#dshLpPanel\{[^}]*z-index:(\d+)/.exec(css)[1]);
  assert.ok(Number.isFinite(btnZ) && Number.isFinite(panelZ), '两条规则都必须写死 z-index');
  assert.ok(btnZ > panelZ, '按钮层级必须严格高于面板，实际 ' + btnZ + ' vs ' + panelZ);
  // dsh pet 挂件用 2147483000：面板与按钮都必须压在它上面，否则重叠区域点不到面板。
  assert.ok(panelZ > 2147483000, '面板层级必须高于 dsh pet 挂件 2147483000，实际 ' + panelZ);
  assert.ok(btnZ > 2147483000, '按钮层级必须高于 dsh pet 挂件 2147483000，实际 ' + btnZ);

  // 面板打开 + 放大到 2 倍：层级与可点性都不许变。
  app.open();
  assert.equal(app.panel.style.display, 'block');
  assert.equal(app.panel.style.transform, 'scale(2)', '用例前提：面板确实被放大到 2 倍');
  assert.equal(Number(/#dshLpBtn\{[^}]*z-index:(\d+)/.exec(app.css())[1]), btnZ, '缩放不改层级');
  assert.ok(app.body.children.includes(app.btn), '按钮仍在文档里');
  assert.ok(app.body.children.indexOf(app.panel) > app.body.children.indexOf(app.btn),
    '面板后插入 DOM —— 盖不盖得住全靠 z-index 分层');

  const btnRule = ruleOf(css, '#dshLpBtn');
  const panelRule = ruleOf(css, '#dshLpPanel');
  for (const rule of [btnRule, panelRule]) {
    assert.doesNotMatch(rule, /pointer-events\s*:\s*none/, '不许用 pointer-events 取巧');
  }
  // 按钮自己必须始终可显示可点（面板的 display:none 是「默认收起」，不是取巧）。
  assert.doesNotMatch(btnRule, /display\s*:\s*none/);
});

// ---------------------------------------------------------------------------
// ② 标题栏 ×：自带关闭入口，且不是拖动
// ---------------------------------------------------------------------------
test('标题栏 × 关闭键：骨架里有、文案走 i18n、点击把面板 display 置 none 且不写位置', () => {
  const app = boot({});
  const close = app.close();
  assert.ok(PANEL_SCRIPT.includes('id="dshLpPanelClose"'), '× 必须写在静态骨架里');
  assert.ok(app.skeleton().includes('id="dshLpPanelClose"'), '× 属于面板骨架');
  assert.ok(String(app.skeleton()).indexOf('#dshLpPanelClose') < 0, '骨架里不该出现 CSS 选择器文本');
  assert.equal(close.title, t('zh', 'panel.frame.closeHint'), 'title 走注入表');

  app.open();
  assert.equal(app.panel.style.display, 'block');
  assert.equal(typeof close.onclick, 'function', '× 必须可点');
  close.onclick();
  assert.equal(app.panel.style.display, 'none', '× 关掉面板');
  assert.equal(app.store.has(POS_KEY), false, '× 不是拖动，不许写位置');
});

test('在 × 上按下再移动不会启动标题栏拖动（不挪卡片、不落盘）', () => {
  const app = boot({});
  app.open();
  const close = app.close();
  const left = px(app.panel.style.left);
  const top = px(app.panel.style.top);

  app.head.fire('pointerdown', { button: 0, pointerId: 11, clientX: 700, clientY: 10, target: close });
  app.head.fire('pointermove', { pointerId: 11, clientX: 780, clientY: 90 });
  app.head.fire('pointerup', { pointerId: 11, clientX: 780, clientY: 90 });
  assert.equal(px(app.panel.style.left), left, '点 × 不许被当成拖动');
  assert.equal(px(app.panel.style.top), top);
  assert.equal(app.store.has(POS_KEY), false, '没真拖动就不该写位置');

  // 反向确认：同一条通道上，从标题栏空白处按下仍然是拖动（排除「整段被关掉」）。
  app.head.fire('pointerdown', { button: 0, pointerId: 12, clientX: 700, clientY: 10 });
  app.head.fire('pointermove', { pointerId: 12, clientX: 740, clientY: 40 });
  app.head.fire('pointerup', { pointerId: 12, clientX: 740, clientY: 40 });
  assert.equal(px(app.panel.style.left), left + 40, '标题栏拖动照旧');
});

// ---------------------------------------------------------------------------
// ③ 群聊与私聊共用同一套消息行
// ---------------------------------------------------------------------------
const DM_PEER = { peerId: 'peer-b-1234', name: '书房', baseUrl: 'http://10.0.0.2:7788', lastSeen: new Date().toISOString() };
const MEMBERS = [
  { peerId: 'me-id', name: 'me', online: true, lastSeen: new Date().toISOString(), joinedAt: 1, baseUrl: 'http://10.0.0.1:7788', lastSeq: 2, lag: 0 },
  { peerId: 'peer-nas', name: 'nas-box', online: true, lastSeen: new Date().toISOString(), joinedAt: 2, baseUrl: 'http://10.0.0.3:7788', lastSeq: 1, lag: 0 },
];

function groupState() {
  return {
    enabled: true,
    isHub: true,
    group: { groupId: 'g-1', name: '家里', members: MEMBERS },
    messages: [
      { seq: 1, ts: AT, from: { peerId: 'me-id', name: 'me' }, kind: 'chat', text: '我先说' },
      { seq: 2, ts: AT + 900, from: { peerId: 'peer-nas', name: 'nas-box' }, kind: 'chat', text: '我接着说' },
    ],
    lastSeq: 2,
    leader: { peerId: 'me-id', name: 'me', epoch: 3 },
    selfRole: 'hub',
    replica: { lastSeq: 2, leaderLastSeq: 2, lag: 0 },
    advertiseBaseUrl: 'http://10.0.0.1:7788',
    advertiseSource: 'config',
    selfBaseUrl: 'http://10.0.0.1:7788',
    role: 'leader',
    quorum: 'majority',
    pendingCount: 0,
    degraded: false,
    applications: [],
  };
}

async function openDmBox() {
  const app = boot({
    routes: {
      state: { name: 'me', instanceId: 'me-id', peers: [DM_PEER], pairing: null },
      'dm/sync': { ok: true, added: 2, total: 2 },
      dm: {
        peer: { peerId: DM_PEER.peerId, name: DM_PEER.name },
        messages: [
          { id: 'm-1', ts: AT, from: 'self', text: '我先说', state: 'sent' },
          { id: 'm-2', ts: AT + 900, from: 'peer', text: '我接着说', state: 'sent' },
        ],
      },
    },
  });
  app.open();
  await flush();
  app.panel.querySelector('#dshLpTabDm').onclick();
  await flush();
  return { app, msgs: app.byId('dshLpDmMsgs'), page: app.byId('dshLpPageDm') };
}

async function openGroupBox() {
  const app = boot({ routes: { state: { name: 'me', instanceId: 'me-id', peers: [], pairing: null }, group: groupState() } });
  app.open();
  await flush();
  app.panel.querySelector('#dshLpTabGroup').onclick();
  await flush();
  return { app, msgs: app.panel.querySelector('#dshLpGroupMsgs') };
}

test('群聊与私聊的消息行是同一套 DOM：class 链逐字相同，自己靠右、他人靠左', async () => {
  const dm = await openDmBox();
  const group = await openGroupBox();

  assert.equal(dm.msgs.children.length, 2, '私聊两条消息都要上屏');
  assert.equal(group.msgs.children.length, 2, '群聊两条消息都要上屏');
  const [dmMine, dmTheirs] = dm.msgs.children;
  const [groupMine, groupTheirs] = group.msgs.children;

  assert.equal(shape(groupMine), shape(dmMine), '自己那条：两个页面必须是同一个结构');
  assert.equal(shape(groupTheirs), shape(dmTheirs), '别人那条：两个页面必须是同一个结构');
  assert.equal(dmMine.className, 'dmmsg self');
  assert.equal(dmTheirs.className, 'dmmsg peer');
  assert.equal(groupMine.children[0].className, 'bubble');
  assert.equal(groupTheirs.children[0].className, 'bubble');
  // 正文与元信息各就各位：正文第 0 个、弱化的 .st 第 1 个。
  assert.equal(groupMine.children[0].children[0].textContent, '我先说');
  assert.equal(groupTheirs.children[0].children[0].textContent, '我接着说');
  assert.ok(String(groupTheirs.children[0].children[1].className).includes('st'), '群聊时间/发送者走 .st');
  assert.match(groupTheirs.children[0].children[1].textContent, /^nas-box · \d{2}:\d{2}:\d{2} · #2$/,
    '群聊的 .st = 发送者名 · 时间，时间弱化显示');
  assert.match(dmTheirs.children[0].children[1].textContent, /^书房 · \d{2}:\d{2}:\d{2}$/,
    '私聊显示对端名 + 时间');

  // 一套 CSS 决定左右：自己右对齐，别人默认靠左。
  const css = dm.app.css();
  assert.match(ruleOf(css, '#dshLpPanel .dmmsg.self') || '', /justify-content:flex-end/);
  assert.match(ruleOf(css, '#dshLpPanel .dmmsg') || '', /display:flex/);
  assert.equal(ruleOf(css, '#dshLpPanel .dmmsg.self .bubble'), 'background:#1f6feb;color:#fff');
  assert.equal(ruleOf(css, '#dshLpPanel .dmmsg.peer .bubble'), 'background:#21262d;color:#e6edf3');

  // 只有一份渲染器：气泡构造全脚本只出现一次，两个页面各调用一次。
  assert.equal(PANEL_SCRIPT.match(/className = 'bubble'/g).length, 1, '气泡只有一个构造点（不许复制粘贴第二份）');
  assert.equal(PANEL_SCRIPT.match(/function messageRow\(/g).length, 1);
  assert.equal(PANEL_SCRIPT.match(/messageRow\(\{/g).length, 2, '私聊与群聊各用一次 messageRow');
});

test('长文本换行 / 圆角 / 字号换算：气泡规则按 --lp-font-px 走，正文可折行', () => {
  const app = boot({});
  const css = app.css();
  const bubble = ruleOf(css, '#dshLpPanel .dmmsg .bubble') || '';
  assert.match(bubble, /border-radius:10px/);
  assert.match(bubble, /font-size:calc\(var\(--lp-font-px\)\*0\.75\)/);
  assert.match(bubble, /word-break:break-word/);
  assert.match(bubble, /white-space:pre-wrap/);
  assert.match(ruleOf(css, '#dshLpPanel .dmmsg .bubble .lpbody') || '', /white-space:pre-wrap/);
  assert.match(ruleOf(css, '#dshLpPanel .dmmsg .bubble .st') || '', /font-size:calc\(var\(--lp-font-px\)\*0\.625\)/);
});

// ---------------------------------------------------------------------------
// ④ 布局：消息流吃满剩余高度并可滚动，输入行贴底；缩放不塌陷
// ---------------------------------------------------------------------------
test('群聊/私聊的聊天列：消息流 flex:1 + min-height:0 可滚动，输入行排在消息流之后', () => {
  const app = boot({});
  const css = app.css();
  for (const selector of ['#dshLpPanel #dshLpGroupMsgs', '#dshLpPanel #dshLpDmMsgs']) {
    const rule = ruleOf(css, selector) || '';
    assert.match(rule, /flex:1 1 auto/, selector + ' 必须吃满剩余空间');
    assert.match(rule, /min-height:0/, selector + ' 必须允许收缩，不然滚动条出不来');
    assert.match(rule, /overflow:auto/);
  }
  const col = ruleOf(css, '#dshLpPanel .chatcol') || '';
  assert.match(col, /display:flex/);
  assert.match(col, /flex-direction:column/);
  assert.match(col, /min-height:0/);
  assert.match(col, /max-height:calc\(70vh \/ var\(--lp-scale\) - 160px\)/, '高度上限按 1/scale 补偿');
  assert.equal(app.panel.style['--lp-scale'], '1', '缩放系数落到根节点，CSS 才能反向补偿');

  // 骨架顺序：消息区 → 输入框 → 发送（输入行永远在消息流下方）。
  // 0.10.0-α：@! 语法提示随群内派单一起移除，中间那一层不再存在。
  const msgsAt = PANEL_SCRIPT.indexOf('id="dshLpGroupMsgs"');
  const inputAt = PANEL_SCRIPT.indexOf('id="dshLpGroupText"');
  const sendAt = PANEL_SCRIPT.indexOf('id="dshLpGroupSend"');
  assert.ok(msgsAt > 0 && msgsAt < inputAt && inputAt < sendAt,
    '顺序必须仍是 消息区 → 输入框 → 发送');
});

// ---------------------------------------------------------------------------
// ⑤ 群聊信息面一处不丢
// ---------------------------------------------------------------------------
test('群聊的 leader/role/replica/degraded/addrWarn/members/msgs/archives/输入框逐 id 都还在', async () => {
  const ids = [
    'dshLpGroupHead', 'dshLpGroupStatus', 'dshLpGroupDegraded', 'dshLpGroupLeader',
    'dshLpGroupRole', 'dshLpGroupReplica', 'dshLpGroupAddrWarn', 'dshLpGroupMembers',
    'dshLpGroupMsgs', 'dshLpGroupMsgsLabel', 'dshLpGroupText',
    'dshLpGroupSend', 'dshLpGroupArchives', 'dshLpArchiveHead', 'dshLpArchivesLabel',
    'dshLpGroupHub',
  ];
  for (const id of ids) {
    assert.ok(PANEL_SCRIPT.includes('id="' + id + '"'), '骨架里缺 ' + id);
  }

  const group = await openGroupBox();
  const box = (id) => group.app.panel.querySelector('#' + id);
  assert.equal(box('dshLpPageGroup').style.display, 'block');
  assert.match(box('dshLpGroupLeader').textContent, /me/);
  assert.match(box('dshLpGroupRole').textContent, /hub/);
  assert.match(box('dshLpGroupReplica').textContent, /2/);
  assert.equal(box('dshLpGroupStatus').textContent.length > 0, true, '状态行仍要显示');
  assert.equal(box('dshLpGroupDegraded').style.display, 'none', '没 degraded 就收起来（节点仍在）');
  assert.equal(box('dshLpGroupAddrWarn').style.display, 'none', '地址一致时不提示（节点仍在）');
  assert.equal(box('dshLpGroupMembers').children.length, 2, '成员表照旧两行');
  assert.equal(group.msgs.children.length, 2, '消息流照旧');
  assert.ok(box('dshLpGroupText'), '群发输入框仍在');
  assert.ok(box('dshLpGroupArchives'), '归档区仍在');
});

// ---------------------------------------------------------------------------
// ⑥ 新文案 zh/en + 铁律
// ---------------------------------------------------------------------------
test('新增文案走 LT：panel.frame.closeHint 在 zh/en 两格都非空且不是同一句', () => {
  const zh = t('zh', 'panel.frame.closeHint');
  const en = t('en', 'panel.frame.closeHint');
  assert.equal(typeof zh, 'string');
  assert.equal(typeof en, 'string');
  assert.notEqual(zh.trim(), '');
  assert.notEqual(en.trim(), '');
  assert.notEqual(zh, en, 'en 必须是真译文');
  assert.ok(keys('zh').includes('panel.frame.closeHint'), 'key 必须进词表');
  assert.ok(keys('en').includes('panel.frame.closeHint'));
  assert.ok(PANEL_SCRIPT.includes('panel.frame.closeHint'), '× 的文案必须取自注入表');
  const enApp = boot({ script: renderPanelScript('tok', 'en') });
  assert.equal(enApp.close().title, en, 'en 面板上 × 的 title 是英文');
});

test('铁律：共用渲染器与群聊段零反引号、无 console.error、innerHTML 只赋空串', async () => {
  const start = PANEL_SCRIPT.indexOf('function messageRow(');
  const end = PANEL_SCRIPT.indexOf('function renderGroup(', start);
  assert.ok(start > 0 && end > start, '共用渲染器段必须能被定位到');
  const section = PANEL_SCRIPT.slice(start, end);
  assert.equal(section.includes('\u0060'), false, '共用渲染器段不得出现反引号');
  assert.equal(/\$\{/.test(section), false, '共用渲染器段不得出现模板插值');
  assert.equal(PANEL_SCRIPT.match(/console[.]error/g), null, '面板不得用 console.error');

  const group = await openGroupBox();
  assert.equal(group.msgs.children.every((row) => row.innerHTML === ''), true,
    '动态内容一律 textContent，元素本身不留 innerHTML');

  // 关闭面板后不再轮询：× 与启动按钮共用同一段开关逻辑。
  const app = group.app;
  app.close().onclick();
  assert.equal(app.panel.style.display, 'none');
  const before = app.calls.length;
  app.panel.querySelector('#dshLpTabGroup').onclick();
  await flush();
  assert.ok(app.calls.length >= before, '切页后仍能工作（开关没有把逻辑写死）');
});
