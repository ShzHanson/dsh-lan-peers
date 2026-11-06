// dsh-lan-peers · v0.8.5-α 群组页「⚙ 派单设置」弹层 + 群派单回执（契约 §3，Lane G-B）。
//
// PANEL_SCRIPT 是浏览器脚本，无法 import：用与 panel-group/panel-dm 同款的最小 DOM 桩执行它。
// 断言八件事：
//   1. 输入框旁有「⚙ 派单设置」按钮（与私聊同款 ghost），默认收起，点开拉默认目标的 options；
//   2. 弹层默认值 = 目标 defaultWorkspaceId + workspace-write，超目标上限的档位置灰并写明原因；
//   3. 切换目标就重拉 group/dispatch-options?peer=…；
//   4. 取不到 options → 工作区与权限都置灰、只显示默认值、注明「对方未提供可选工作区」；
//   5. 发帖带 { text, target, workspaceId, permission }；弹层没开时只带 { kind, text }；
//   6. 纯文本 @!目标 任务 语法仍然可用；
//   7. 回执系统行显示「工作区 <名字> · 权限 <档>」，pending-approval 用单独的中性样式；
//   8. 弹层里绝不出现任何 path（断言），新段落零反引号、无 console.error。
import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { PANEL_SCRIPT } from './admin.mjs';

const VIEW = { w: 1000, h: 800 };

function makeElement(tag) {
  const cache = new Map();
  const el = {
    tagName: String(tag).toUpperCase(),
    id: '', className: '', textContent: '', value: '', placeholder: '', maxLength: 0,
    style: {}, disabled: false, children: [], listeners: new Map(),
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

const flush = async (rounds = 25) => {
  for (let i = 0; i < rounds; i += 1) await new Promise((resolve) => setTimeout(resolve, 1));
};

const MEMBERS = [
  { peerId: 'peer-hub', name: 'hub-box', online: true, lastSeen: new Date().toISOString(), joinedAt: 1 },
  { peerId: 'peer-nas', name: 'nas-box', online: true, lastSeen: new Date().toISOString(), joinedAt: 2 },
];

// 目标侧 options：**故意带 path** —— 面板一个都不能显示（对端违约也不许漏）。
const OPTIONS = {
  'peer-hub': {
    defaultWorkspaceId: 'main',
    maxPermission: 'workspace-write',
    workspaces: [
      { id: 'main', name: '主工作区', path: 'D:/work/main' },
      { id: 'docs', name: '文档', path: 'D:/work/docs' },
    ],
  },
  'peer-nas': {
    defaultWorkspaceId: 'docs',
    maxPermission: 'read-only',
    workspaces: [{ id: 'docs', name: '文档', path: 'D:/work/docs' }],
  },
};

function groupState({ sinceSeq = 0, messages = [] } = {}) {
  return {
    enabled: true,
    isHub: true,
    group: { groupId: 'g-1', name: '家里', members: MEMBERS },
    messages: messages.filter((m) => m.seq > sinceSeq),
    lastSeq: messages.length === 0 ? 0 : messages[messages.length - 1].seq,
    leader: { peerId: 'peer-hub', name: 'hub-box', epoch: 3 },
    selfRole: 'hub',
    replica: { lastSeq: 0, lag: 0 },
    advertiseBaseUrl: 'http://192.168.1.20:7788',
    advertiseSource: 'config',
    selfBaseUrl: 'http://192.168.1.20:7788',
    role: 'leader',
    quorum: 'majority',
    pendingCount: 0,
    degraded: false,
  };
}

function boot({ messages = [], options = OPTIONS, optionsStatus = 200, postReply = null } = {}) {
  const created = [];
  const posts = [];
  const calls = [];
  const timers = [];
  const document = {
    head: makeElement('head'),
    body: makeElement('body'),
    hidden: false,
    createElement: (tag) => { const el = makeElement(tag); created.push(el); return el; },
  };
  const json = (body, status = 200) => ({ ok: status >= 200 && status < 300, status, json: async () => body });
  const fetchStub = async (url, init) => {
    const path = String(url).replace('/api/lan-peers/', '');
    calls.push({ path, init, body: init && init.body ? JSON.parse(init.body) : null });
    if (path === 'state') return json({ name: 'me', instanceId: 'me-id', peers: [], pairing: null });
    if (path === 'dispatch') return json({ dispatches: [] });
    if (path.startsWith('group?sinceSeq=')) {
      return json(groupState({ sinceSeq: Number(path.split('=')[1]), messages }));
    }
    if (path.startsWith('group/dispatch-options')) {
      const peerId = decodeURIComponent(path.split('peer=')[1] || '');
      if (optionsStatus !== 200) return json({ error: 'options-unavailable' }, optionsStatus);
      const found = options[peerId];
      if (!found) return json({ error: 'options-unavailable' }, 502);
      return json(found);
    }
    if (path === 'group/post') {
      posts.push(JSON.parse(init.body));
      return json(postReply || { ok: true, seq: 9, ts: 1_700_001_000_000 });
    }
    if (path.startsWith('group/')) return json({ ok: true, seq: 3, ts: 1_700_000_900_000 });
    return json({});
  };
  const window = {
    innerWidth: VIEW.w, innerHeight: VIEW.h, addEventListener() {},
    confirm: () => true,
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
  return { btn, panel, created, calls, posts, timers };
}

/** 打开面板 → 切到群组页（真机上的两步操作）。 */
async function openGroupPage(extra) {
  const booted = boot(extra);
  booted.btn.onclick();
  await flush();
  booted.panel.querySelector('#dshLpTabGroup').onclick();
  await flush();
  const q = (id) => booted.panel.querySelector('#' + id);
  return {
    ...booted,
    messages: q('dshLpGroupMsgs'),
    msgBox: q('dshLpMsg'),
    dispatchBtn: q('dshLpGroupDispatchBtn'),
    box: q('dshLpGroupDispatchBox'),
    target: q('dshLpGroupTarget'),
    ws: q('dshLpGroupWs'),
    perm: q('dshLpGroupPerm'),
    hint: q('dshLpGroupDispatchHint'),
    closeBtn: q('dshLpGroupDispatchClose'),
    input: q('dshLpGroupText'),
  };
}

/** 点开弹层（默认目标 = 群里第一个成员）。 */
async function openDialog(extra) {
  const app = await openGroupPage(extra);
  app.dispatchBtn.onclick();
  await flush();
  return app;
}

const optionCalls = (calls) => calls.filter((call) => call.path.startsWith('group/dispatch-options'));

// ---------------------------------------------------------------------------
// 1. 按钮与默认值
// ---------------------------------------------------------------------------

test('输入框旁有「⚙ 派单设置」（与私聊同款 ghost），默认收起；点开拉默认目标的 options', async () => {
  const app = await openGroupPage();
  assert.equal(app.dispatchBtn.textContent, '⚙ 派单设置');
  // 与私聊同款：骨架里就是 ghost 按钮（DOM 桩不解析静态 class，所以直接钉骨架）
  assert.match(PANEL_SCRIPT, /<button class="ghost" id="dshLpGroupDispatchBtn">/);
  assert.match(PANEL_SCRIPT, /<button class="ghost" id="dshLpDmDispatch">|mkButton\('dshLpDmDispatch'/);
  assert.equal(app.box.style.display, 'none', '默认收起');

  app.dispatchBtn.onclick();
  await flush();
  assert.equal(app.box.style.display, 'block');
  assert.deepEqual(optionCalls(app.calls).map((call) => call.path),
    ['group/dispatch-options?peer=peer-hub'], '默认目标是群里第一个成员');
});

test('弹层默认值 = 目标的 defaultWorkspaceId + workspace-write，超目标上限的档位置灰写明原因', async () => {
  const app = await openDialog();
  assert.deepEqual(app.target.children.map((opt) => opt.value), ['peer-hub', 'peer-nas'], '目标下拉 = 群成员');
  assert.equal(app.target.children[0].textContent, 'hub-box', '名字只走 textContent');
  assert.equal(app.ws.value, 'main', '默认工作区来自目标的 defaultWorkspaceId');
  assert.deepEqual(app.ws.children.map((opt) => opt.value), ['main', 'docs']);
  assert.equal(app.perm.value, 'workspace-write', '权限默认 workspace-write');
  assert.equal(app.perm.children[0].disabled, false, 'read-only 在上限之内');
  assert.equal(app.perm.children[1].disabled, false, 'workspace-write 正好等于上限');
  assert.equal(app.perm.children[2].disabled, true, 'danger-full-access 超过目标上限 → 置灰');
  assert.match(app.perm.children[2].textContent, /danger-full-access · 超过对方上限（workspace-write），已置灰/);
});

// ---------------------------------------------------------------------------
// 2. 联动：切换目标重拉
// ---------------------------------------------------------------------------

test('切换目标成员 → 重新拉 group/dispatch-options?peer=<新目标>，下拉换成新目标的工作区', async () => {
  const app = await openDialog();
  app.target.value = 'peer-nas';
  app.target.onchange();
  await flush();
  assert.deepEqual(optionCalls(app.calls).map((call) => call.path), [
    'group/dispatch-options?peer=peer-hub',
    'group/dispatch-options?peer=peer-nas',
  ], '切目标必须重拉一次');
  assert.deepEqual(app.ws.children.map((opt) => opt.value), ['docs']);
  assert.equal(app.ws.value, 'docs');
  assert.equal(app.perm.value, 'read-only', '默认档超上限时退到上限那一档，不越权默认');
  assert.equal(app.perm.children[0].disabled, false);
  assert.equal(app.perm.children[1].disabled, true, 'workspace-write 超过 read-only 上限 → 置灰');
});

test('取不到 options → 只显示默认值并置灰，注明「对方未提供可选工作区」', async () => {
  const app = await openDialog({ optionsStatus: 500 });
  assert.equal(app.ws.disabled, true, '工作区下拉置灰');
  assert.equal(app.ws.children.length, 1);
  assert.equal(app.ws.children[0].value, '');
  assert.equal(app.ws.children[0].textContent, '对方未提供可选工作区');
  assert.equal(app.perm.disabled, true, '权限下拉置灰');
  assert.equal(app.perm.children.length, 1, '不给一份「选了会报错」的三档清单');
  assert.equal(app.perm.children[0].textContent, 'workspace-write', '只显示协议默认档');
  assert.equal(app.hint.textContent, '对方未提供可选工作区');
  assert.match(app.msgBox.textContent, /^读取对方派单设置失败：/);

  // 取不到就一个字段都不带（由目标用自己的默认工作区与默认档，契约 §0/§2 的退回口径）。
  app.input.value = '跑一下';
  app.input.fire('keydown', { key: 'Enter' });
  await flush();
  assert.deepEqual(app.posts, [{ kind: 'chat', text: '跑一下', target: 'peer-hub' }]);
});

// ---------------------------------------------------------------------------
// 3. 发送
// ---------------------------------------------------------------------------

test('弹层确认后发帖：{ text, target, workspaceId, permission } 一起进请求体', async () => {
  const app = await openDialog();
  app.ws.value = 'docs';
  app.perm.value = 'read-only';
  app.input.value = '把构建跑一遍';
  app.input.fire('keydown', { key: 'Enter' });
  await flush();
  assert.deepEqual(app.posts, [{
    kind: 'chat', text: '把构建跑一遍',
    target: 'peer-hub', workspaceId: 'docs', permission: 'read-only',
  }]);
  assert.equal(app.msgBox.textContent, '已发送', '没有 dispatch 回执时仍是「已发送」');
});

test('纯文本 @!目标 任务 仍然可用：弹层没开 → 请求体只有 { kind, text }（与 0.8.4 逐字一致）', async () => {
  const app = await openGroupPage();
  app.input.value = '@!nas-box 跑一下';
  app.input.fire('keydown', { key: 'Enter' });
  await flush();
  assert.deepEqual(app.posts, [{ kind: 'chat', text: '@!nas-box 跑一下' }]);
  assert.equal(optionCalls(app.calls).length, 0, '没点开弹层就不去问任何目标');
});

// ---------------------------------------------------------------------------
// 4. 回执展示
// ---------------------------------------------------------------------------

test('回执系统行：气泡外显示「工作区 <名字> · 权限 <档>」，一条 path 都不出现', async () => {
  const app = await openGroupPage({
    messages: [
      {
        seq: 1, ts: 1_700_000_700_000, from: { peerId: 'peer-hub', name: 'hub-box' },
        kind: 'progress', text: '', meta: {
          phase: 'dispatch-start', target: 'peer-nas', status: 'running',
          workspace: { id: 'main', name: '主工作区', path: 'D:/work/main' }, permission: 'read-only',
        },
      },
      {
        seq: 2, ts: 1_700_001_000_000, from: { peerId: 'peer-hub', name: 'hub-box' },
        kind: 'result', text: '', meta: {
          phase: 'dispatch-end', status: 'done', target: 'peer-nas', elapsedMs: 1227, replyChars: 142,
          workspace: { id: 'main', name: '主工作区', path: 'D:/work/main' }, permission: 'read-only',
        },
      },
    ],
  });
  assert.equal(app.messages.children.length, 2);
  const [start, end] = app.messages.children;
  assert.match(start.className, /\bgsys\b/);
  assert.doesNotMatch(start.className, /\bdmmsg\b|\bbubble\b/, '回执不进气泡');
  assert.match(start.textContent, /^派单 → nas-box：进行中 · 工作区 主工作区 · 权限 read-only · \d{2}:\d{2}:\d{2} · #1$/);
  assert.match(end.textContent, /^派单 → nas-box：done（1227ms \/ 142字） · 工作区 主工作区 · 权限 read-only · \d{2}:\d{2}:\d{2} · #2$/);
  assert.equal(start.textContent.includes('D:/'), false, '群回执里绝不出现 path');
  assert.equal(end.textContent.includes('D:/'), false);
});

test('pending-approval 用单独的中性样式（不是失败红），批准后转 done', async () => {
  const app = await openGroupPage({
    messages: [
      {
        seq: 1, ts: 1_700_001_000_000, from: { peerId: 'peer-hub', name: 'hub-box' },
        kind: 'result', text: '', meta: {
          phase: 'dispatch-end', status: 'pending-approval', target: 'peer-nas',
          workspace: { id: 'main', name: '主工作区' }, permission: 'danger-full-access',
        },
      },
    ],
  });
  const row = app.messages.children[0];
  assert.match(row.className, /\bgsys\b/);
  assert.match(row.className, /\bpending\b/, 'pending-approval 有自己的类名');
  assert.doesNotMatch(row.className, /failed|error/, '不是失败样式');
  assert.match(row.textContent, /^派单 → nas-box：等待对方确认… · 工作区 主工作区 · 权限 danger-full-access/);
  assert.equal(row.textContent.includes('failed'), false, '不把「等对方点头」写成失败');
  // 样式本身：琥珀色中性提示，不是告警红（#f85149）
  assert.match(PANEL_SCRIPT, /#dshLpPanel \.gsys\.pending\{color:#d29922\}/);
  assert.equal(/#dshLpPanel \.gsys\.pending\{[^}]*#f85149/.test(PANEL_SCRIPT), false);
  // 同一批历史里再出现 done 时，样式回到普通系统行（批准后转 done 的可见证据）
  const done = await openGroupPage({
    messages: [
      {
        seq: 1, ts: 1_700_001_500_000, from: { peerId: 'peer-hub', name: 'hub-box' },
        kind: 'result', text: '', meta: {
          phase: 'dispatch-end', status: 'done', target: 'peer-nas',
          workspace: { id: 'main', name: '主工作区' }, permission: 'danger-full-access',
        },
      },
    ],
  });
  assert.equal(done.messages.children[0].className, 'gsys', 'done 不带 pending');
  assert.match(done.messages.children[0].textContent, /：done · 工作区 主工作区 · 权限 danger-full-access/);
});

// ---------------------------------------------------------------------------
// 5. 铁律：弹层里绝不出现 path
// ---------------------------------------------------------------------------

test('弹层里绝不出现任何 path（对端违约带回 path 也不显示）', async () => {
  const app = await openDialog();
  const texts = app.box.children.map((child) => child.textContent).join('|')
    + '|' + app.ws.children.map((opt) => opt.textContent).join('|')
    + '|' + app.perm.children.map((opt) => opt.textContent).join('|')
    + '|' + app.target.children.map((opt) => opt.textContent).join('|')
    + '|' + app.hint.textContent;
  assert.equal(texts.includes('D:/'), false, '一个路径都不许出现');
  assert.equal(texts.includes('path'), false);
  assert.equal(texts.includes('D:/work'), false, '连 path 的片段都不该漏');
  // 请求侧同样不带 path：options 请求只有 peer，发帖体只有四个字段
  app.input.value = '跑一下';
  app.input.fire('keydown', { key: 'Enter' });
  await flush();
  const body = app.posts[0];
  assert.deepEqual(Object.keys(body).sort(), ['kind', 'permission', 'target', 'text', 'workspaceId']);
  assert.equal(JSON.stringify(body).includes('D:/'), false);
  assert.equal(optionCalls(app.calls).every((call) => call.path.indexOf('path') === -1), true);
});

test('群派单弹层段零反引号、无 console.error：新文案全部走词表', () => {
  const start = PANEL_SCRIPT.indexOf('v0.8.5-α 群组页「⚙ 派单设置」弹层');
  const end = PANEL_SCRIPT.indexOf('function toMs(', start);
  assert.ok(start > 0 && end > start, '群派单段必须能被定位到');
  const section = PANEL_SCRIPT.slice(start, end);
  assert.equal(section.includes(String.fromCharCode(96)), false, '本段零反引号');
  assert.equal(/\$\{/.test(section), false, '本段没有模板插值');
  assert.equal(/console\.error/.test(section), false, '不新增 console.error');
  assert.equal(/innerHTML\s*=\s*[^'"\s]/.test(section), false, '动态内容一律 textContent（只允许赋空串清空）');
});
