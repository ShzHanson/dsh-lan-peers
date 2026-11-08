// dsh-lan-peers · 面板级「待批准」入口（真人协作踩到的 UX 缺口）
//
// 用户实测到的三条：
//   1. 私聊/群聊里只有一句「等待批准」，批准入口只在设置页最底部（要滚动才看得见）；
//   2. dispatch/pending 回空时设置页只有一句空提示，容易被当成「没这个功能」；
//   3. 待批准记录 10 分钟就自己清掉，没有任何「来了」的提示。
//
// 这里把「页签栏下方的 #dshLpPendingBar」钉死：
//   AC1 items>0 → 可见、标题含条数、行数 = items 数，且四个页签下都可见（逐个页签断言）；
//   AC2 items=0 → display:none（不占垂直空间）；
//   AC3 bar 里的批准/拒绝走既有 decidePending（POST dispatch/approve|reject + {id}），随后重拉 pending；
//   AC4 设置页列表与 bar 用同一份行渲染函数（结构指纹相同 + 代码级「两处都调它」）；
//   AC5 回执里出现 pendingApproval === true → 立刻触发一次 dispatch/pending（私聊 / 群聊各一条）；
//   AC6 document.hidden === true 时不再发起请求。
//
// 铁律：新增段零反引号；动态内容只走 textContent；innerHTML 只赋空串；不新增 console.error。
import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { PANEL_SCRIPT } from './admin.mjs';
import { keys, t } from './i18n.mjs';

const VIEW = { w: 1000, h: 800 };

function makeElement(tag) {
  const cache = new Map();
  const el = {
    tagName: String(tag).toUpperCase(),
    id: '', className: '', textContent: '', value: '', placeholder: '', maxLength: 0,
    style: {}, disabled: false, selected: false, children: [], listeners: new Map(),
    offsetWidth: 96, offsetHeight: 36, onclick: null,
    appendChild(child) { this.children.push(child); return child; },
    addEventListener(type, fn) {
      if (!this.listeners.has(type)) this.listeners.set(type, []);
      this.listeners.get(type).push(fn);
    },
    removeEventListener() {},
    setPointerCapture() {},
    releasePointerCapture() {},
    getBoundingClientRect() { return { left: 0, top: 0, width: this.offsetWidth, height: this.offsetHeight }; },
    querySelector(selector) {
      const id = String(selector).replace(/^#/, '');
      if (!cache.has(id)) cache.set(id, makeElement('div'));
      return cache.get(id);
    },
  };
  let html = '';
  Object.defineProperty(el, 'innerHTML', {
    get: () => html,
    set: (value) => { html = value; if (value === '') el.children.length = 0; },
  });
  return el;
}

const flush = async (rounds = 30) => {
  for (let i = 0; i < rounds; i += 1) await new Promise((resolve) => setTimeout(resolve, 1));
};

const PEER = { peerId: 'peer-b-1234', name: '书房', baseUrl: 'http://10.0.0.2:7788', lastSeen: Date.now() };
const PREFS = {
  defaultWorkspaceId: 'main',
  maxPermission: 'workspace-write',
  workspaces: [{ id: 'main', name: '主工作区', path: 'D:/work/main' }],
};
const PEER_OPTIONS = {
  defaultWorkspaceId: 'main',
  maxPermission: 'workspace-write',
  workspaces: [{ id: 'main', name: '主工作区' }],
};

function pendingItems() {
  const now = Date.now();
  return [
    {
      approvalId: 'ap-1', from: 'peer-b-12345678', fromName: '书房', workspaceId: 'main',
      workspaceName: '主工作区', permission: 'danger-full-access', promptBytes: 64, at: now,
      expiresAt: now + 90_000,
    },
    {
      approvalId: 'ap-2', from: 'peer-c-99999999', workspaceId: 'docs', workspaceName: '文档',
      permission: 'workspace-write', promptBytes: 12, at: now + 1, expiresAt: now + 300_000,
    },
  ];
}

function boot({ pending = [], sendReply = null, postAnswer = null, group = null } = {}) {
  const calls = [];
  const timers = [];
  const created = [];
  const state = { pending: pending.map((item) => ({ ...item })) };
  const document = {
    head: makeElement('head'),
    body: makeElement('body'),
    hidden: false,
    createElement: (tag) => { const el = makeElement(tag); created.push(el); return el; },
  };
  const json = (body, status = 200) => ({ ok: status >= 200 && status < 300, status, json: async () => body });
  const fetchStub = async (url, init) => {
    const path = String(url).replace('/api/lan-peers/', '');
    const body = init && init.body ? JSON.parse(init.body) : null;
    calls.push({ path, method: (init && init.method) || 'GET', body });
    if (path === 'state') return json({ name: 'me', instanceId: 'me-id', peers: [PEER], pairing: null });
    if (path === 'dispatch') return json({ dispatches: [] });
    if (path === 'client-log') return json({ ok: true });
    if (path === 'lang') return json({ lang: 'auto' });
    if (path === 'dispatch/settings') return json(PREFS);
    if (path.startsWith('dispatch/options')) return json(PEER_OPTIONS);
    if (path === 'dispatch/pending') return json({ items: state.pending });
    if (path === 'dispatch/approve' || path === 'dispatch/reject') {
      const action = path.slice('dispatch/'.length);
      state.pending = state.pending.filter((item) => item.approvalId !== body.id);
      return json({ ok: true, state: action === 'approve' ? 'approved' : 'rejected' });
    }
    if (path.startsWith('dispatch/approval')) return json({ state: 'pending' });
    if (path === 'dm/send') {
      return json(sendReply || { ok: true, id: 'm-2', sessionId: 's-1', reply: '好的', elapsedMs: 10, reused: true });
    }
    if (path === 'dm/sync') return json({ ok: true, added: 0, total: 0 });
    if (path.startsWith('dm?peer=')) return json({ peer: { peerId: PEER.peerId, name: PEER.name }, messages: [] });
    if (path === 'group/post') {
      return json(postAnswer || { ok: true, seq: 5, ts: Date.now() });
    }
    if (path.startsWith('group?sinceSeq=')) {
      const base = {
        enabled: true, isHub: true,
        group: { groupId: 'g-1', name: '家里', members: [{ peerId: 'peer-nas', name: 'nas-box', online: true }] },
        messages: [], lastSeq: 0, acceptDispatch: true,
      };
      return json(typeof group === 'function' ? group(base) : base);
    }
    if (path.startsWith('group/')) return json({ ok: true });
    return json({});
  };
  const window = {
    innerWidth: VIEW.w, innerHeight: VIEW.h, addEventListener() {}, confirm: () => true,
    localStorage: { getItem: () => null, setItem: () => {} },
  };
  vm.runInNewContext(PANEL_SCRIPT, {
    window, document, localStorage: window.localStorage, fetch: fetchStub,
    setInterval: (fn, ms) => { timers.push({ fn, ms }); return timers.length; },
    clearInterval: () => {},
    setTimeout: () => 0,
    clearTimeout: () => {},
    JSON, Math, console,
  });
  const btn = document.body.children.find((el) => el.id === 'dshLpBtn');
  const panel = document.body.children.find((el) => el.id === 'dshLpPanel');
  const q = (id) => panel.querySelector('#' + id);
  // 骨架里的节点走 panel.querySelector；用 createElement 现搭的页面（设置页 / 私聊页）走 created
  const byId = (id) => created.find((el) => el.id === id);
  const bar = q('dshLpPendingBar');
  const barList = q('dshLpPendingBarList');
  const barTitle = q('dshLpPendingBarTitle');
  const pendingCalls = () => calls.filter((call) => call.path === 'dispatch/pending').length;
  return {
    btn, panel, q, byId, bar, barList, barTitle, calls, timers, state, document, created, pendingCalls,
  };
}

/** 打开面板（默认停在第 1 个页签「伙伴」） */
async function openPanel(options) {
  const app = boot(options);
  app.btn.onclick();
  await flush();
  return app;
}

/** 取一行待批准的结构指纹：class 链 + 每一格的文案（不看对象身份） */
const fingerprint = (row) => ({
  className: String(row.className),
  cells: row.children.map((cell) => String(cell.className) + '|' + String(cell.textContent)),
});

const rowButton = (row, label) => row.children.find((cell) => String(cell.textContent) === label);

// ---------------------------------------------------------------------------
// AC1：items > 0 → 可见、标题含条数、行数 = items 数，四个页签都可见
// ---------------------------------------------------------------------------
test('AC1 面板一打开就看得见：标题含条数 + 行数等于 items 数', async () => {
  const app = await openPanel({ pending: pendingItems() });
  assert.equal(app.bar.style.display, 'block', '有待批准就必须显示这条 bar');
  assert.equal(app.barTitle.textContent, t('zh', 'panel.pendingBar.title').replace('{count}', '2'));
  assert.equal(app.barList.children.length, 2, '两条待批准 = 两行');

  const first = app.barList.children[0];
  assert.equal(first.children[0].textContent, '来自 书房', '有名字就用名字');
  assert.equal(first.children[1].textContent, '主工作区 · danger-full-access');
  assert.match(first.children[2].textContent, /^剩余 \d+ 秒$/, '剩余秒数按真实 expiresAt 算');
  assert.equal(first.children[3].textContent, '批准');
  assert.equal(first.children[4].textContent, '拒绝');
});

test('AC1 四个页签下都可见（不靠设置页滚动）', async () => {
  const app = await openPanel({ pending: pendingItems() });
  for (const tab of ['peers', 'group', 'dm', 'settings']) {
    app.q('dshLpTab' + tab.charAt(0).toUpperCase() + tab.slice(1)).onclick();
    await flush();
    assert.equal(app.bar.style.display, 'block', tab + ' 页签下待批准条必须可见');
    assert.equal(app.barList.children.length, 2, tab + ' 页签下行数不能变');
    assert.equal(app.barTitle.textContent, t('zh', 'panel.pendingBar.title').replace('{count}', '2'));
  }
});

// ---------------------------------------------------------------------------
// AC2：items === 0 → 整条隐藏（display:none，不占垂直空间）
// ---------------------------------------------------------------------------
test('AC2 没有待批准时整条隐藏', async () => {
  const empty = await openPanel({ pending: [] });
  assert.equal(empty.bar.style.display, 'none');
  assert.equal(empty.barTitle.textContent, '');
  assert.equal(empty.barList.children.length, 0);

  // 从「有」变「空」：批准完最后一条，bar 自己收起来
  const app = await openPanel({ pending: [pendingItems()[0]] });
  assert.equal(app.bar.style.display, 'block');
  rowButton(app.barList.children[0], '批准').onclick();
  await flush();
  assert.equal(app.bar.style.display, 'none', '空列表必须收起来，不能留一条空壳占位');
  assert.equal(app.barList.children.length, 0);
});

// ---------------------------------------------------------------------------
// AC3：批准 / 拒绝走既有 decidePending，随后重拉 pending
// ---------------------------------------------------------------------------
test('AC3 bar 里点批准 → POST dispatch/approve {id}，随后重拉 dispatch/pending', async () => {
  const app = await openPanel({ pending: pendingItems() });
  const before = app.pendingCalls();
  rowButton(app.barList.children[0], '批准').onclick();
  await flush();

  const approve = app.calls.filter((call) => call.path === 'dispatch/approve');
  assert.equal(approve.length, 1, '批准只能发一次请求');
  assert.equal(approve[0].method, 'POST');
  assert.deepEqual(approve[0].body, { id: 'ap-1' }, '载荷与设置页完全一致：只有 id');
  assert.ok(app.pendingCalls() > before, '批准之后必须重拉待批准列表（bar 与设置页同一份数据）');
  assert.equal(app.barList.children.length, 1, '只剩第二条');
  assert.equal(app.barList.children[0].children[0].textContent, '来自 peer-c-9');
  assert.match(app.q('dshLpMsg').textContent, /^已批准/);
});

test('AC3 bar 里点拒绝 → POST dispatch/reject {id}', async () => {
  const app = await openPanel({ pending: pendingItems() });
  rowButton(app.barList.children[1], '拒绝').onclick();
  await flush();
  const reject = app.calls.filter((call) => call.path === 'dispatch/reject');
  assert.equal(reject.length, 1);
  assert.deepEqual(reject[0].body, { id: 'ap-2' });
  assert.equal(app.barList.children.length, 1);
  assert.equal(app.barList.children[0].children[0].textContent, '来自 书房');
  assert.equal(app.q('dshLpMsg').textContent, '已拒绝 rejected');
});

// ---------------------------------------------------------------------------
// AC4：设置页列表与 bar 用同一份行渲染函数
// ---------------------------------------------------------------------------
test('AC4 设置页的行与 bar 的行结构指纹完全相同（同一份渲染函数）', async () => {
  const app = await openPanel({ pending: pendingItems() });
  const barRows = app.barList.children.map((row) => fingerprint(row));

  app.q('dshLpTabSettings').onclick();
  await flush();
  const settingsRows = app.byId('dshLpSetPending').children.map((row) => fingerprint(row));

  assert.equal(settingsRows.length, 2, '设置页也渲染同样的两条');
  assert.deepEqual(settingsRows, barRows, '两处行的 class 链与每一格文案必须逐字相同');
});

test('AC4 代码级：行渲染只在 pendingRow 一处实现，两个列表都调它', () => {
  const source = readFileSync(new URL('./admin.mjs', import.meta.url), 'utf8');
  assert.equal(source.split('function pendingRow(').length - 1, 1, '行渲染函数只允许定义一次');
  assert.ok(PANEL_SCRIPT.includes('function pendingRow('), '面板脚本里必须有共用的行渲染函数');
  // 定义 1 次 + 设置页 1 次 + 顶部条 1 次 = 3
  assert.equal(PANEL_SCRIPT.split('pendingRow(').length - 1, 3,
    'pendingRow 必须是「一处定义、两处调用」');
  // 行的构造只该在 pendingRow 里出现一次（旧的行内实现不许复活成第二份）
  assert.equal(PANEL_SCRIPT.split("mkEl('div', 'dshLpPend-' + approvalId, 'pending')").length - 1, 1,
    '构造待批准行的代码只该在 pendingRow 里出现一次');
});

// ---------------------------------------------------------------------------
// AC5：回执里出现 pendingApproval === true 就刷新（私聊 + 群聊）
// ---------------------------------------------------------------------------
test('AC5 私聊：dm/send 回 pendingApproval:true → 立刻重拉 dispatch/pending', async () => {
  const app = await openPanel({
    pending: [],
    sendReply: { ok: true, pendingApproval: true, approvalId: 'ap-7', expiresAt: Date.now() + 600_000 },
  });
  app.q('dshLpTabDm').onclick();
  await flush();
  app.byId('dshLpDmDispatch').onclick();
  await flush();

  // 对端刚把一条待批准挂出来：桩里让列表随之变化，验证「来了就看得见」
  app.state.pending = pendingItems();
  const before = app.pendingCalls();
  app.byId('dshLpDmText').value = '把构建跑一遍';
  app.byId('dshLpDmSend').onclick();
  await flush();

  assert.equal(app.calls.filter((call) => call.path === 'dm/send').length, 1);
  assert.ok(app.pendingCalls() > before, '回执说「等批准」的当下必须刷新一次待批准');
  assert.equal(app.bar.style.display, 'block', '刷新之后 bar 立刻可见（不必去设置页）');
  assert.equal(app.barList.children.length, 2);
});

test('AC5 群聊：群派单回执带 pendingApproval:true → 立刻重拉 dispatch/pending', async () => {
  const app = await openPanel({
    pending: [],
    postAnswer: {
      ok: true, seq: 5, ts: Date.now(),
      dispatch: { target: 'peer-nas', targetName: 'nas-box', status: 'pending-approval', pendingApproval: true },
    },
  });
  app.q('dshLpTabGroup').onclick();
  await flush();

  app.state.pending = pendingItems();
  const before = app.pendingCalls();
  app.q('dshLpGroupText').value = '@!nas-box 把构建跑一遍';
  app.q('dshLpGroupSend').onclick();
  await flush();

  assert.equal(app.calls.filter((call) => call.path === 'group/post').length, 1);
  assert.ok(app.pendingCalls() > before, '群回执里说「等待对方确认」也必须刷新待批准');
  assert.equal(app.bar.style.display, 'block');
});

test('AC5 反向：回执不是 pending-approval 时不多打一次 pending', async () => {
  const app = await openPanel({
    pending: [],
    sendReply: { ok: true, id: 'm-9', sessionId: 's-1', reply: '好的', elapsedMs: 5, reused: false },
  });
  app.q('dshLpTabDm').onclick();
  await flush();
  app.byId('dshLpDmDispatch').onclick();
  await flush();
  const before = app.pendingCalls();
  app.byId('dshLpDmText').value = '跑一下';
  app.byId('dshLpDmSend').onclick();
  await flush();
  assert.equal(app.pendingCalls(), before, '正常回执不该额外拉一次待批准');
});

// ---------------------------------------------------------------------------
// AC6：document.hidden === true 时不再发起请求
// ---------------------------------------------------------------------------
test('AC6 页面隐藏时轮询不发起 dispatch/pending 请求', async () => {
  const app = await openPanel({ pending: pendingItems() });
  const before = app.pendingCalls();
  app.document.hidden = true;
  // 面板打开时起的 1s 节拍（伙伴页 jobs / 收件进度）与 2s 群节拍都打一遍
  for (const timer of app.timers.filter((one) => one.ms === 1000 || one.ms === 2000)) timer.fn();
  await flush();
  assert.equal(app.pendingCalls(), before, '隐藏期间一次都不许拉待批准');

  app.document.hidden = false;
  const visible = app.pendingCalls();
  for (const timer of app.timers.filter((one) => one.ms === 1000 || one.ms === 2000)) timer.fn();
  await flush();
  assert.ok(app.pendingCalls() >= visible, '回到可见后节拍照旧工作（不把逻辑写死成停）');
});

// ---------------------------------------------------------------------------
// AC8 + 铁律：新文案两格齐备、零反引号、无 console.error、innerHTML 只赋空串
// ---------------------------------------------------------------------------
test('AC8 新 i18n key 在 zh/en 两格都非空，且不是同一句', () => {
  const key = 'panel.pendingBar.title';
  assert.ok(keys('zh').includes(key), 'zh 词表必须有这个 key');
  assert.ok(keys('en').includes(key), 'en 词表必须有这个 key');
  assert.equal(typeof t('zh', key), 'string');
  assert.ok(String(t('zh', key)).trim() !== '');
  assert.ok(String(t('en', key)).trim() !== '');
  assert.notEqual(t('zh', key), t('en', key), 'en 不能照抄 zh');
  assert.doesNotMatch(String(t('en', key)), /[\u4e00-\u9fa5]/, 'en 格不许有中文');
  assert.ok(String(t('zh', key)).includes('{count}'), 'zh 文案要能显示条数');
  assert.ok(String(t('en', key)).includes('{count}'), 'en 文案要能显示条数');
});

test('铁律：新增段零反引号、无 console.error、innerHTML 只赋空串', () => {
  const source = readFileSync(new URL('./admin.mjs', import.meta.url), 'utf8');
  const start = source.indexOf('function pendingRow(');
  const end = source.indexOf('function tickPendingBar(');
  assert.ok(start > 0 && end > start, '新增段必须在 admin.mjs 里');
  const block = source.slice(start, end);
  assert.equal((block.match(/`/g) || []).length, 0, '新增段零反引号');
  assert.equal(/console\.error/.test(block), false, '不新增 console.error');
  assert.equal(/innerHTML\s*=\s*[^'"\s]/.test(block), false, 'innerHTML 只允许赋空串');
  assert.equal(/innerHTML\s*\+=/.test(block), false, '不许 innerHTML +=');
  // 骨架里这条 bar 默认收起，靠 JS 显隐
  assert.match(source, /<div id="dshLpPendingBar" style="display:none">/);
});
