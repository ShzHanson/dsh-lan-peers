// dsh-lan-peers · v0.8.5-α（契约 §5/§6，Lane H2）面板第四个页签「设置」+ 私聊派单弹层。
//
// PANEL_SCRIPT 是浏览器脚本，无法 import：用与 panel-dm/panel-group 同款的最小 DOM 桩执行它。
// 断言五件事：
//   1. 第四个页签并列存在，点击切换显示并高亮；
//   2. 设置页读 GET dispatch/settings（含 path，本机配置），保存走 POST 且只发三个字段；
//   3. 待批准列表渲染来源/工作区/权限/剩余时间，批准与拒绝按钮走 POST；
//   4. 私聊弹层默认值 = 对端 defaultWorkspaceId + workspace-write，超上限的档位置灰并写明原因；
//   5. 发完全权限 → 气泡「等待对方确认…」+ 轮询 approval → 批准/拒绝/超时三种明确文案。
// 铁律：动态内容只走 textContent；设置页可以显示 path，私聊对话框里绝不出现 path。
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
  workspaces: [
    { id: 'main', name: '主工作区', path: 'D:/work/main' },
    { id: 'docs', name: '文档', path: 'D:/work/docs' },
  ],
};
const PEER_OPTIONS = {
  defaultWorkspaceId: 'main',
  maxPermission: 'workspace-write',
  workspaces: [{ id: 'main', name: '主工作区' }, { id: 'docs', name: '文档' }],
};

function boot({
  prefs = PREFS,
  options = PEER_OPTIONS,
  optionsStatus = 200,
  optionsError = 'options-unsupported',
  pending = [],
  settingsStatus = 200,
  saveReply = null,
  sendReply = null,
  approval = 'pending',
  messages = [],
} = {}) {
  const created = [];
  const calls = [];
  const timers = [];
  const state = { approval, pending: pending.slice() };
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
    if (path === 'dispatch/settings') {
      if (settingsStatus !== 200) return json({ error: 'dispatch-unsupported' }, settingsStatus);
      if (body) return json(saveReply || { ...body, workspaces: body.workspaces });
      return json(prefs);
    }
    if (path.startsWith('dispatch/options')) {
      if (optionsStatus !== 200) return json({ error: optionsError }, optionsStatus);
      return json(options);
    }
    if (path === 'dispatch/pending') return json({ items: state.pending });
    if (path === 'dispatch/approve' || path === 'dispatch/reject') {
      const action = path.slice('dispatch/'.length);
      state.pending = state.pending.filter((item) => item.approvalId !== body.id);
      return json({ ok: true, state: action === 'approve' ? 'approved' : 'rejected' });
    }
    if (path.startsWith('dispatch/approval')) return json({ state: state.approval });
    if (path === 'dm/send') return json(sendReply || { ok: true, id: 'm-2', sessionId: 's-1', reply: '好的', elapsedMs: 10, reused: true });
    if (path === 'dm/sync') return json({ ok: true, added: 0, total: messages.length });
    if (path.startsWith('dm?peer=')) return json({ peer: { peerId: PEER.peerId, name: PEER.name }, messages });
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
  const byId = (id) => created.find((el) => el.id === id);
  return { btn, panel, calls, created, timers, state, byId, document };
}

async function openSettings(extra) {
  const booted = boot(extra);
  booted.btn.onclick();
  await flush();
  const before = booted.timers.length;
  booted.panel.querySelector('#dshLpTabSettings').onclick();
  await flush();
  return {
    ...booted,
    page: booted.byId('dshLpPageSettings'),
    setDefault: booted.byId('dshLpSetDefault'),
    setMax: booted.byId('dshLpSetMaxPerm'),
    list: booted.byId('dshLpSetList'),
    pendingBox: booted.byId('dshLpSetPending'),
    saveBtn: booted.byId('dshLpSetSave'),
    addBtn: booted.byId('dshLpSetAdd'),
    newId: booted.byId('dshLpSetNewId'),
    newName: booted.byId('dshLpSetNewName'),
    newPath: booted.byId('dshLpSetNewPath'),
    msgBox: booted.panel.querySelector('#dshLpMsg'),
    settingsTimer: booted.timers.slice(before).find((timer) => timer.ms === 2000),
  };
}

async function openDm(extra) {
  const booted = boot(extra);
  booted.btn.onclick();
  await flush();
  booted.panel.querySelector('#dshLpTabDm').onclick();
  await flush();
  return {
    ...booted,
    dmPage: booted.byId('dshLpPageDm'),
    dispatchBtn: booted.byId('dshLpDmDispatch'),
    dialog: booted.byId('dshLpDmDialog'),
    ws: booted.byId('dshLpDmWs'),
    perm: booted.byId('dshLpDmPerm'),
    input: booted.byId('dshLpDmText'),
    sendBtn: booted.byId('dshLpDmSend'),
    msgs: booted.byId('dshLpDmMsgs'),
    msgBox: booted.panel.querySelector('#dshLpMsg'),
  };
}

function stamps(msgs) {
  return msgs.children.map((wrap) => wrap.children[0].children[1].textContent);
}

test('「设置」是第四个并列页签：点击切换显示并高亮，其余页全部让位', async () => {
  const app = await openSettings();
  assert.equal(app.page.style.display, 'block');
  assert.equal(app.panel.querySelector('#dshLpPagePeers').style.display, 'none');
  assert.equal(app.panel.querySelector('#dshLpPageGroup').style.display, 'none');
  assert.match(app.panel.querySelector('#dshLpTabSettings').className, /on/);
  assert.doesNotMatch(app.panel.querySelector('#dshLpTabDm').className, /on\b/);
  assert.equal(app.panel.querySelector('#dshLpTabSettings').textContent, '设置');

  app.panel.querySelector('#dshLpTabPeers').onclick();
  assert.equal(app.page.style.display, 'none', '切回伙伴页要把设置页藏起来');
  assert.equal(app.panel.querySelector('#dshLpPagePeers').style.display, 'block');
});

test('设置页渲染：默认工作区下拉 + 三档上限 + 命名工作区清单（id/名字/路径都在）', async () => {
  const app = await openSettings();
  assert.deepEqual(app.setDefault.children.map((opt) => opt.value), ['main', 'docs']);
  assert.equal(app.setDefault.value, 'main', '默认工作区按 prefs.defaultWorkspaceId 选中');
  assert.deepEqual(app.setMax.children.map((opt) => opt.value),
    ['read-only', 'workspace-write', 'danger-full-access']);
  assert.equal(app.setMax.value, 'workspace-write');

  assert.equal(app.list.children.length, 2, '两个命名工作区各一行');
  const row = app.list.children[0];
  assert.equal(row.children[0].textContent, 'main', 'id 原样显示');
  assert.equal(row.children[1].value, '主工作区', '名字可改');
  assert.equal(row.children[2].value, 'D:/work/main', '设置页可以显示本机 path（这是本机自己的配置）');
  assert.equal(row.children[3].textContent, '删除');
});

test('设置页保存：POST dispatch/settings 只带三个字段，成功后写 msg 与最新值', async () => {
  const app = await openSettings();
  app.list.children[0].children[1].value = '主工作区（改名）';
  app.setMax.value = 'read-only';
  app.saveBtn.onclick();
  await flush();

  const post = app.calls.filter((call) => call.path === 'dispatch/settings' && call.method === 'POST');
  assert.equal(post.length, 1);
  assert.deepEqual(post[0].body, {
    defaultWorkspaceId: 'main',
    maxPermission: 'read-only',
    workspaces: [
      { id: 'main', name: '主工作区（改名）', path: 'D:/work/main' },
      { id: 'docs', name: '文档', path: 'D:/work/docs' },
    ],
  });
  assert.equal(app.msgBox.textContent, '设置已保存（立即生效）');
  assert.equal(app.setMax.value, 'read-only', '保存后用响应里的值重画');
});

test('设置页：新增工作区先进清单，空 id/空路径在本地就挡住（不发请求）', async () => {
  const app = await openSettings();
  const before = app.calls.filter((call) => call.path === 'dispatch/settings' && call.method === 'POST').length;

  app.addBtn.onclick();
  assert.equal(app.msgBox.textContent, '工作区 id 不能为空');
  app.newId.value = 'media';
  app.addBtn.onclick();
  assert.equal(app.msgBox.textContent, '路径不能为空');

  app.newPath.value = 'D:/work/media';
  app.addBtn.onclick();
  assert.equal(app.list.children.length, 3, '新增一行');
  assert.equal(app.list.children[2].children[0].textContent, 'media');
  assert.equal(app.list.children[2].children[2].value, 'D:/work/media');
  assert.equal(app.newId.value, '', '输入框清空');
  const after = app.calls.filter((call) => call.path === 'dispatch/settings' && call.method === 'POST').length;
  assert.equal(after, before, '新增只是本地编辑，保存才发请求');
});

test('待批准列表：来自谁/工作区/权限/剩余秒数 + 批准与拒绝按钮走 POST', async () => {
  const now = Date.now();
  const app = await openSettings({
    pending: [{
      approvalId: 'ap-1', from: 'peer-b-12345678', fromName: '书房', workspaceId: 'main',
      workspaceName: '主工作区', permission: 'danger-full-access', promptBytes: 64, at: now,
      expiresAt: now + 90_000,
    }],
  });
  assert.equal(app.pendingBox.children.length, 1);
  const row = app.pendingBox.children[0];
  assert.equal(row.children[0].textContent, '来自 书房', '有名字就用名字（不用 id 前缀）');
  assert.equal(row.children[1].textContent, '主工作区 · danger-full-access');
  assert.match(row.children[2].textContent, /^剩余 \d+ 秒$/);
  assert.equal(row.children[3].textContent, '批准');
  assert.equal(row.children[4].textContent, '拒绝');

  row.children[3].onclick();
  await flush();
  const approve = app.calls.filter((call) => call.path === 'dispatch/approve');
  assert.equal(approve.length, 1);
  assert.deepEqual(approve[0].body, { id: 'ap-1' });
  assert.match(app.msgBox.textContent, /^已批准/);
  assert.equal(app.pendingBox.children.length, 1, '空了之后重画成占位行');
  assert.equal(app.pendingBox.children[0].textContent, '没有待批准请求');
});

test('待批准：拒绝按钮 POST dispatch/reject；空列表给一句占位文案', async () => {
  const now = Date.now();
  const app = await openSettings({
    pending: [{
      approvalId: 'ap-2', from: 'peer-c-9999', workspaceId: 'docs', workspaceName: '文档',
      permission: 'workspace-write', promptBytes: 12, at: now, expiresAt: now + 1000,
    }],
  });
  assert.equal(app.pendingBox.children[0].children[0].textContent, '来自 peer-c-9',
    '没有名字时退回 peerId 前 8 位');
  app.pendingBox.children[0].children[4].onclick();
  await flush();
  const reject = app.calls.filter((call) => call.path === 'dispatch/reject');
  assert.equal(reject.length, 1);
  assert.deepEqual(reject[0].body, { id: 'ap-2' });
  assert.equal(app.msgBox.textContent, '已拒绝 rejected');

  const empty = await openSettings({ pending: [] });
  assert.equal(empty.pendingBox.children[0].textContent, '没有待批准请求');
});

test('门面未接线（501）：设置页如实说「本机还没有派单门面」，不画空清单', async () => {
  const app = await openSettings({ settingsStatus: 501 });
  assert.equal(app.msgBox.textContent, '本机还没有派单门面（待 H1 接线）');
});

test('私聊弹层：⚙ 按钮读对端 options，默认 = 对端 defaultWorkspaceId + workspace-write', async () => {
  const app = await openDm();
  assert.equal(app.dialog.style.display, 'none', '默认收起');
  assert.equal(app.dispatchBtn.textContent, '⚙ 派单设置');

  app.dispatchBtn.onclick();
  await flush();
  assert.equal(app.dialog.style.display, 'block');
  assert.equal(app.calls.filter((call) => call.path.startsWith('dispatch/options?peer=')).length, 1);
  assert.deepEqual(app.ws.children.map((opt) => opt.value), ['main', 'docs']);
  assert.equal(app.ws.value, 'main', '默认工作区来自对端 options');
  assert.equal(app.perm.value, 'workspace-write', '权限默认 workspace-write');
  assert.equal(app.perm.children.length, 3);
  assert.equal(app.perm.children[0].disabled, false, 'read-only 在上限之内');
  assert.equal(app.perm.children[1].disabled, false, 'workspace-write 正好等于上限，可选');
  assert.equal(app.perm.children[2].disabled, true, 'danger-full-access 超过上限 → 置灰');
});

test('私聊弹层：超过对端上限的档位置灰，并把原因写在选项上（不允许选了才报错）', async () => {
  const app = await openDm({
    options: { defaultWorkspaceId: 'docs', maxPermission: 'read-only', workspaces: PEER_OPTIONS.workspaces },
  });
  app.dispatchBtn.onclick();
  await flush();
  assert.equal(app.ws.value, 'docs');
  assert.equal(app.perm.children[0].disabled, false, 'read-only 可选');
  assert.equal(app.perm.children[1].disabled, true, 'workspace-write 超过上限 → 置灰');
  assert.equal(app.perm.children[2].disabled, true, 'danger-full-access 超过上限 → 置灰');
  assert.match(app.perm.children[2].textContent, /danger-full-access · 超过对方上限（read-only），已置灰/);
  assert.equal(app.perm.value, 'read-only', '默认档超上限时退到上限那一档，不越权默认');
});

test('私聊弹层：不显示 path（对端 options 本来就没有，本机也不问）', async () => {
  const app = await openDm();
  app.dispatchBtn.onclick();
  await flush();
  const dialog = app.dialog;
  const text = dialog.children.map((child) => child.textContent).join('|')
    + '|' + app.ws.children.map((opt) => opt.textContent).join('|')
    + '|' + app.perm.children.map((opt) => opt.textContent).join('|');
  assert.equal(text.includes('D:/'), false, '对话框里一个路径都不许出现');
  assert.equal(text.includes('path'), false);
});

test('发送完全权限：气泡写「等待对方确认…」，轮询到 approved 后显示对方回复', async () => {
  const app = await openDm({
    sendReply: { ok: true, pendingApproval: true, approvalId: 'ap-7', expiresAt: Date.now() + 600_000 },
    messages: () => [],
  });
  app.dispatchBtn.onclick();
  await flush();
  app.perm.value = 'danger-full-access';

  const before = app.timers.length;
  app.input.value = '把构建跑一遍';
  app.sendBtn.onclick();
  await flush();

  const post = app.calls.filter((call) => call.path === 'dm/send');
  assert.equal(post.length, 1);
  assert.deepEqual(post[0].body, { peerId: PEER.peerId, text: '把构建跑一遍', workspaceId: 'main', permission: 'danger-full-access' });
  assert.deepEqual(stamps(app.msgs), ['等待对方确认…'], '正文自己那条 + 等待确认的 stamp');

  const approvalTimer = app.timers.slice(before).find((timer) => timer.ms === 1000);
  assert.ok(approvalTimer, '开始 1s 轮询 approval');
  assert.equal(app.calls.filter((call) => call.path.startsWith('dispatch/approval')).length, 0, '还没到时候，先不发');

  const syncsBefore = app.calls.filter((call) => call.path === 'dm/sync').length;
  app.state.approval = 'approved';
  approvalTimer.fn();
  await flush();
  const polls = app.calls.filter((call) => call.path.startsWith('dispatch/approval'));
  assert.equal(polls.length, 1);
  assert.equal(polls[0].path, 'dispatch/approval?id=ap-7&peer=' + PEER.peerId);
  assert.deepEqual(stamps(app.msgs), ['对方已批准，正在执行…']);
  assert.equal(app.calls.filter((call) => call.path === 'dm/sync').length, syncsBefore + 1,
    '批准后立刻再 sync 一次拿回复（打开私聊时已经 sync 过一次）');
});

test('拒绝与超时：气泡给出明确文案，并且停止轮询', async () => {
  const rejected = await openDm({
    sendReply: { ok: true, pendingApproval: true, approvalId: 'ap-8', expiresAt: Date.now() + 600_000 },
  });
  rejected.dispatchBtn.onclick();
  await flush();
  const before = rejected.timers.length;
  rejected.input.value = '跑一下';
  rejected.sendBtn.onclick();
  await flush();
  const timer = rejected.timers.slice(before).find((one) => one.ms === 1000);
  rejected.state.approval = 'rejected';
  timer.fn();
  await flush();
  assert.deepEqual(stamps(rejected.msgs), ['对方拒绝了这次派单（超出其默认授权档）']);

  const expired = await openDm({
    sendReply: { ok: true, pendingApproval: true, approvalId: 'ap-9', expiresAt: Date.now() - 1 },
  });
  expired.dispatchBtn.onclick();
  await flush();
  const beforeExpired = expired.timers.length;
  expired.input.value = '跑一下';
  expired.sendBtn.onclick();
  await flush();
  const expiredTimer = expired.timers.slice(beforeExpired).find((one) => one.ms === 1000);
  expiredTimer.fn();
  await flush();
  assert.deepEqual(stamps(expired.msgs), ['等待超时，对方没有处理']);
  assert.equal(expired.calls.filter((call) => call.path.startsWith('dispatch/approval')).length, 0,
    '过期在本地就判掉，不用再问对端');
});

test('设置页/弹层段零反引号、无 console.error：新文案全部走词表', async () => {
  const start = PANEL_SCRIPT.indexOf('第四个页签');
  const end = PANEL_SCRIPT.indexOf('function setTab(');
  assert.ok(start > 0 && end > start, '设置段必须在面板脚本里');
  const block = PANEL_SCRIPT.slice(start, end);
  assert.equal((block.match(/`/g) || []).length, 0, '面板段新增行零反引号');
  assert.equal(/console\.error/.test(block), false, '不新增 console.error');
  assert.equal(/innerHTML\s*=\s*[^'"\s]/.test(block), false, '动态内容一律 textContent（只允许赋空串清空）');
});
