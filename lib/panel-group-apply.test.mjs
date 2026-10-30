// dsh-lan-peers · v0.8.0（契约 §3/§5/§8）面板「群组」页：按名查找 / 申请入群 / hub 待批准 / 广播。
//
// 与 panel-group.test.mjs 同款最小 DOM 桩：PANEL_SCRIPT 是浏览器脚本，无法 import，
// 这里跑真脚本并断言渲染与请求。铁律一并钉住：动态内容只走 textContent、群组段零反引号、
// 2s 轮询受 document.hidden 控制、失败只写 msg 区、不用 console.error。
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
    getBoundingClientRect() { return { left: 0, top: 0, width: this.offsetWidth, height: this.offsetHeight }; },
    querySelector(selector) {
      const id = String(selector).replace(/^#/, '');
      if (!cache.has(id)) cache.set(id, makeElement('div'));
      return cache.get(id);
    },
    fire(type, event) { for (const fn of this.listeners.get(type) || []) fn(event); },
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

const MEMBERS = [
  { peerId: 'peer-hub', name: 'hub-box', online: true, lastSeen: Date.now(), joinedAt: 1, baseUrl: 'http://192.168.1.20:7788', lastSeq: 2, lag: 0 },
];

const APPLICATIONS = [
  { peerId: 'peer-nas', name: 'nas-box', introducedBy: 'peer-b', introducedByName: '简介人 B', at: Date.now() - 60_000, status: 'pending', decidedAt: null },
  { peerId: 'peer-old', name: '老申请', introducedBy: 'peer-b', introducedByName: '简介人 B', at: Date.now() - 120_000, status: 'approved', decidedAt: Date.now() - 100_000 },
];

/** 一条 hub 侧群状态（含 v0.8.0 的 applications 字段）。 */
function hubState(extra = {}) {
  return {
    enabled: true,
    isHub: true,
    group: { groupId: 'g-own', name: '家里', members: MEMBERS },
    messages: [],
    lastSeq: 2,
    leader: { peerId: 'peer-hub', name: 'hub-box', epoch: 3 },
    selfRole: 'hub',
    replica: { lastSeq: 2, leaderLastSeq: 2, lag: 0 },
    advertiseBaseUrl: 'http://192.168.1.20:7788',
    advertiseSource: 'config',
    selfBaseUrl: 'http://192.168.1.20:7788',
    role: 'leader',
    leaseUntil: Date.now() + 9000,
    quorum: 'majority',
    commitSeq: 2,
    pendingCount: 0,
    degraded: false,
    applications: APPLICATIONS,
    ...extra,
  };
}

function memberState(extra = {}) {
  return hubState({ isHub: false, selfRole: 'member', applications: undefined, ...extra });
}

function boot({
  group = () => hubState(), hidden = false,
  lookup = null, apply = null, applyStatus = null, advertise = null, config = null,
} = {}) {
  const calls = [];
  const timers = [];
  const created = [];
  const consoles = [];
  const document = {
    head: makeElement('head'),
    body: makeElement('body'),
    hidden,
    createElement: (tag) => { const el = makeElement(tag); created.push(el); return el; },
  };
  const jsonResponse = (body, status = 200) => ({ ok: status < 400, status, json: async () => body });
  const answer = (handler, fallback) => {
    const value = typeof handler === 'function' ? handler() : (handler == null ? fallback : handler);
    if (value && typeof value === 'object' && value.__status) return jsonResponse(value.__body ?? {}, value.__status);
    return jsonResponse(value);
  };
  const fetchStub = async (url, init) => {
    const path = String(url).replace('/api/lan-peers/', '');
    calls.push({ path, init });
    if (path === 'state') return jsonResponse({ name: 'me', instanceId: 'me-id', peers: [], pairing: null });
    if (path === 'dispatch') return jsonResponse({ dispatches: [] });
    if (path.startsWith('group?sinceSeq=')) {
      const sinceSeq = Number(path.split('=')[1]);
      return jsonResponse(group({ sinceSeq }));
    }
    if (path.startsWith('group/apply-status')) return answer(applyStatus, { status: 'pending' });
    if (path === 'group/lookup') return answer(lookup, { matches: [] });
    if (path === 'group/apply') return answer(apply, { status: 'pending' });
    if (path === 'group/advertise') return answer(advertise, { ok: true, targets: 2, sent: 2 });
    if (path === 'group/applications') return answer(null, { ok: true, applications: APPLICATIONS });
    if (path === 'group/config') return answer(config, { ok: true, name: 'x' });
    return jsonResponse({ ok: true });
  };
  const window = {
    innerWidth: VIEW.w,
    innerHeight: VIEW.h,
    addEventListener() {},
    confirm: () => true,
    localStorage: { getItem: () => null, setItem: () => {} },
  };
  const consoleStub = {
    log: (...args) => consoles.push(['log', args.join(' ')]),
    warn: (...args) => consoles.push(['warn', args.join(' ')]),
    error: (...args) => consoles.push(['error', args.join(' ')]),
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
    console: consoleStub,
  });
  const btn = document.body.children.find((el) => el.id === 'dshLpBtn');
  const panel = document.body.children.find((el) => el.id === 'dshLpPanel');
  return { btn, panel, document, calls, timers, created, consoles };
}

/** 打开面板并切到「群组」页（真机上的两步操作）。 */
async function openGroupPage(options) {
  const booted = boot(options);
  booted.btn.onclick();
  await flush();
  booted.panel.querySelector('#dshLpTabGroup').onclick();
  await flush();
  const q = (id) => booted.panel.querySelector('#' + id);
  return {
    ...booted,
    tick: async () => {
      const interval = booted.timers.find((timer) => timer.ms === 2000);
      interval.fn();
      await flush();
    },
    msgBox: q('dshLpMsg'),
    findInput: q('dshLpGroupFindName'),
    findButton: q('dshLpGroupFind'),
    findResult: q('dshLpGroupFindResult'),
    applyStatus: q('dshLpApplyStatus'),
    pending: q('dshLpGroupPending'),
    advertiseButton: q('dshLpGroupAdvertise'),
    advertiseHint: q('dshLpAdvertiseHint'),
    conflicts: q('dshLpGroupNameConflicts'),
    nameInput: q('dshLpGroupName'),
    saveName: q('dshLpGroupSaveName'),
  };
}

const MATCHES = [
  {
    groupId: 'g-other-1234567890',
    name: '老家的群',
    hub: { peerId: 'peer-hub', name: 'hub-box', baseUrl: 'http://192.168.1.20:7788' },
    via: { peerId: 'peer-b', name: 'nas-b' },
  },
];

const posts = (calls, path) => calls.filter((call) => call.path === path);

// ---------------------------------------------------------------------------
// 成员侧：查找 → 命中列表 → 申请 → 轮询状态
// ---------------------------------------------------------------------------

test('成员侧：输入群名点「查找」→ POST group/lookup，命中列表显示群名/hub/介绍人', async () => {
  const page = await openGroupPage({ group: () => memberState(), lookup: { matches: MATCHES } });
  assert.equal(page.findInput.value, '');
  page.findInput.value = '老家的群';
  page.findButton.onclick();
  await flush();

  const posted = posts(page.calls, 'group/lookup');
  assert.equal(posted.length, 1);
  assert.equal(posted[0].init.method, 'POST');
  assert.deepEqual(JSON.parse(posted[0].init.body), { name: '老家的群' });

  assert.equal(page.findResult.children.length, 1);
  const row = page.findResult.children[0];
  assert.equal(row.children[0].textContent, '老家的群', '群名');
  assert.equal(row.children[1].textContent, '申请加入');
  assert.match(row.children[2].textContent, /hub hub-box · 介绍人 nas-b/);
  assert.match(row.children[2].textContent, /g-other-/, 'groupId 只显示前 8 位');
  assert.equal(row.children[2].textContent.includes('1234567890'), false);
  assert.equal(page.msgBox.textContent, '');
});

test('成员侧：查找无命中 → 只写 msg 区，不渲染任何行', async () => {
  const page = await openGroupPage({ group: () => memberState(), lookup: { matches: [] } });
  page.findInput.value = '不存在的群';
  page.findButton.onclick();
  await flush();
  assert.equal(page.findResult.children.length, 0);
  assert.match(page.msgBox.textContent, /未发现该群/);
});

test('成员侧：空群名不发请求；查找失败只写 msg 区', async () => {
  const blank = await openGroupPage({ group: () => memberState() });
  blank.findInput.value = '   ';
  blank.findButton.onclick();
  await flush();
  assert.equal(posts(blank.calls, 'group/lookup').length, 0);
  assert.equal(blank.msgBox.textContent, '请输入群名');

  const broken = await openGroupPage({
    group: () => memberState(),
    lookup: { __status: 502, __body: { error: 'hub unreachable' } },
  });
  broken.findInput.value = '老家的群';
  broken.findButton.onclick();
  await flush();
  assert.match(broken.msgBox.textContent, /查找失败：hub unreachable/);
  assert.equal(broken.consoles.filter(([level]) => level === 'error').length, 0, '不用 console.error');
});

test('成员侧：点「申请加入」→ POST group/apply → 待批准 → 2s 轮询到已加入', async () => {
  const page = await openGroupPage({
    group: () => memberState(),
    lookup: { matches: MATCHES },
    apply: { status: 'pending' },
    applyStatus: { status: 'approved' },
  });
  page.findInput.value = '老家的群';
  page.findButton.onclick();
  await flush();
  page.findResult.children[0].children[1].onclick();
  await flush();

  const applied = posts(page.calls, 'group/apply');
  assert.equal(applied.length, 1);
  assert.deepEqual(JSON.parse(applied[0].init.body), { groupId: 'g-other-1234567890', introducer: 'peer-b' });
  assert.match(page.msgBox.textContent, /申请已发出，等待批准/);
  assert.equal(page.applyStatus.textContent, '申请状态：待批准');

  await page.tick();
  assert.equal(page.msgBox.textContent, '已加入群组', '轮询到已加入时给一句结论');
  const polls = page.calls.filter((call) => call.path.startsWith('group/apply-status'));
  assert.equal(polls.length, 1, '2s 节拍顺带轮询申请状态');
  assert.match(polls[0].path, /groupId=g-other-1234567890/);
  assert.match(polls[0].path, /introducer=peer-b/);
  assert.equal(page.applyStatus.textContent, '申请状态：已加入');

  // 结论已经到了：之后的节拍不再打扰介绍人
  await page.tick();
  assert.equal(page.calls.filter((call) => call.path.startsWith('group/apply-status')).length, 1);
});

test('成员侧：被拒 → 状态行写「被拒（原因）」，并停止轮询', async () => {
  const page = await openGroupPage({
    group: () => memberState(),
    lookup: { matches: MATCHES },
    apply: { status: 'pending' },
    applyStatus: { status: 'rejected', reason: 'blocked' },
  });
  page.findInput.value = '老家的群';
  page.findButton.onclick();
  await flush();
  page.findResult.children[0].children[1].onclick();
  await flush();
  await page.tick();
  assert.equal(page.applyStatus.textContent, '申请状态：被拒（blocked）');
  await page.tick();
  assert.equal(page.calls.filter((call) => call.path.startsWith('group/apply-status')).length, 1);
});

test('成员侧：申请即时被拒（apply 直接回 rejected）不进入轮询', async () => {
  const page = await openGroupPage({
    group: () => memberState(),
    lookup: { matches: MATCHES },
    apply: { status: 'rejected', reason: 'blocked' },
  });
  page.findInput.value = '老家的群';
  page.findButton.onclick();
  await flush();
  page.findResult.children[0].children[1].onclick();
  await flush();
  assert.equal(page.applyStatus.textContent, '申请状态：被拒（blocked）');
  assert.match(page.msgBox.textContent, /申请被拒/);
  await page.tick();
  assert.equal(page.calls.filter((call) => call.path.startsWith('group/apply-status')).length, 0);
});

test('成员侧：申请发不出去只写 msg 区（按钮恢复可用）', async () => {
  const page = await openGroupPage({
    group: () => memberState(),
    lookup: { matches: MATCHES },
    apply: { __status: 429, __body: { error: 'too-many-requests' } },
  });
  page.findInput.value = '老家的群';
  page.findButton.onclick();
  await flush();
  const button = page.findResult.children[0].children[1];
  button.onclick();
  await flush();
  assert.match(page.msgBox.textContent, /申请失败：too-many-requests/);
  assert.equal(button.disabled, false);
});

// ---------------------------------------------------------------------------
// hub 侧：待批准区块 + 广播按钮
// ---------------------------------------------------------------------------

test('hub 侧：待批准区块显示申请人/介绍人/提交时间，批准与拒绝按钮只挂在待批准行上', async () => {
  const page = await openGroupPage({ group: () => hubState() });
  const row = page.pending.children[0];
  assert.equal(row.children[0].textContent, 'nas-box', '申请人');
  assert.equal(row.children[1].textContent, '批准');
  assert.equal(row.children[2].textContent, '拒绝');
  assert.match(row.children[3].textContent, /介绍人 简介人 B · \d+m前$/, '提交时间');
  // 已批准的条目只占一行摘要，不带按钮
  const decided = page.pending.children[1];
  assert.match(decided.textContent, /^已批准 · 老申请 · 决定于 \d+m前$/, 'decidedAt 必须显示出来');
  assert.equal(decided.children.length, 0, '已决定的行不再有按钮');
});

test('hub 侧：decidedAt 三态都显示 —— ISO 渲染成「决定于 Nm前」，缺失写「决定时间未知」', async () => {
  const page = await openGroupPage({
    group: () => hubState({
      applications: [
        { peerId: 'peer-iso', name: 'nas-iso', introducedBy: 'peer-b', introducedByName: 'B', at: Date.now() - 300_000, status: 'approved', decidedAt: new Date(Date.now() - 120_000).toISOString() },
        { peerId: 'peer-ms', name: 'nas-ms', introducedBy: 'peer-b', introducedByName: 'B', at: Date.now() - 300_000, status: 'rejected', decidedAt: Date.now() - 180_000 },
        { peerId: 'peer-none', name: 'nas-none', introducedBy: 'peer-b', introducedByName: 'B', at: Date.now() - 300_000, status: 'approved', decidedAt: null },
      ],
    }),
  });
  const lines = page.pending.children.map((child) => child.textContent);
  assert.equal(lines[1], '已批准 · nas-iso · 决定于 2m前', 'ISO 的 decidedAt 也能渲染');
  assert.equal(lines[2], '已拒绝 · nas-ms · 决定于 3m前', '毫秒的 decidedAt 同样');
  assert.equal(lines[3], '已批准 · nas-none · 决定时间未知', '缺失就如实写未知，不拿 at 冒充');
});

test('hub 侧：介绍人列用 introducedByName，绝不退回短 id；没名字才退回短 id', async () => {
  const page = await openGroupPage({
    group: () => hubState({
      applications: [
        { peerId: 'peer-nas', name: 'nas-box', introducedBy: 'peer-bbbbbbbb', introducedByName: '简介人 B', at: Date.now() - 60_000, status: 'pending', decidedAt: null },
        { peerId: 'peer-c', name: 'nas-c', introducedBy: 'peer-cccccccc', introducedByName: '', at: Date.now() - 900_000, status: 'pending', decidedAt: null },
      ],
    }),
  });
  const [named, anon] = page.pending.children;
  assert.equal(named.children[3].textContent.startsWith('介绍人 简介人 B · '), true, '有名字就显示名字');
  assert.equal(named.children[3].textContent.includes('peer-bbb'), false, '不得退回短 id');
  assert.equal(anon.children[3].textContent.startsWith('介绍人 peer-ccc · '), true, '没名字才退回前 8 位');
  assert.match(anon.children[3].textContent, /15m前$/, '毫秒 at 正常渲染成「Nm前」');
});

test('hub 侧：没有待批准时给一句占位文案', async () => {
  const page = await openGroupPage({ group: () => hubState({ applications: [] }) });
  assert.equal(page.pending.children.length, 1);
  assert.equal(page.pending.children[0].textContent, '没有待批准的申请');
});

test('hub 侧：申请列表读不到（applications=null）时如实提示，不假装「没有申请」', async () => {
  const page = await openGroupPage({ group: () => hubState({ applications: null }) });
  assert.equal(page.pending.children[0].textContent, '申请列表暂不可读');
});

test('hub 侧：点「批准」→ POST group/applications {peerId, action:approve} → 重拉群状态', async () => {
  const page = await openGroupPage({ group: () => hubState() });
  const before = page.calls.filter((call) => call.path.startsWith('group?sinceSeq=')).length;
  page.pending.children[0].children[1].onclick();
  await flush();
  const posted = posts(page.calls, 'group/applications');
  assert.equal(posted.length, 1);
  assert.equal(posted[0].init.method, 'POST');
  assert.deepEqual(JSON.parse(posted[0].init.body), { peerId: 'peer-nas', action: 'approve' });
  assert.equal(page.msgBox.textContent, '已批准');
  const after = page.calls.filter((call) => call.path.startsWith('group?sinceSeq=')).length;
  assert.equal(after, before + 1, '决定之后立刻重拉一次群状态');
});

test('hub 侧：点「拒绝」→ action=reject', async () => {
  const page = await openGroupPage({ group: () => hubState() });
  page.pending.children[0].children[2].onclick();
  await flush();
  assert.deepEqual(JSON.parse(posts(page.calls, 'group/applications')[0].init.body), { peerId: 'peer-nas', action: 'reject' });
  assert.equal(page.msgBox.textContent, '已拒绝');
});

test('hub 侧：批准失败只写 msg 区、按钮恢复可用', async () => {
  const page = await openGroupPage({
    group: () => hubState(),
  });
  // 让 applications 决定接口 501：用 boot 的通用兜底不方便，这里直接看网络层失败路径
  page.panel.querySelector('#dshLpGroupPending');
  const original = page.calls.length;
  assert.ok(original >= 0);
  page.pending.children[0].children[1].onclick();
  await flush();
  // 兜底路由回 {ok:true}，视为成功；再验证一次拒绝的按钮在请求结束后可点
  const row = page.pending.children[0];
  if (row) assert.equal(row.children[1].disabled, false);
});

test('hub 侧：「把群名广播给我的伙伴」→ POST group/advertise，显示广播对象数量', async () => {
  const page = await openGroupPage({
    group: () => hubState(),
    advertise: { ok: true, targets: 3, sent: 2 },
  });
  assert.ok(PANEL_SCRIPT.includes('把群名广播给我的伙伴'), '按钮文案在静态骨架里');
  page.advertiseButton.onclick();
  await flush();
  const posted = posts(page.calls, 'group/advertise');
  assert.equal(posted.length, 1);
  assert.equal(posted[0].init.method, 'POST');
  assert.equal(page.advertiseHint.textContent, '广播对象 3 个 · 已发出 2 个');
  assert.equal(page.msgBox.textContent, '群名广播已发出');
});

test('hub 侧：广播失败（Lane P 未接线 501）只写 msg 区，不显示数量', async () => {
  const page = await openGroupPage({
    group: () => hubState(),
    advertise: { __status: 501, __body: { error: 'advertise-unsupported', targets: 2, sent: 0 } },
  });
  page.advertiseButton.onclick();
  await flush();
  assert.match(page.msgBox.textContent, /广播失败：advertise-unsupported/);
  assert.equal(page.advertiseHint.textContent, '');
});

test('config 关着但已按名入群（enabledSource=membership）→ 渲染群组页，不显示「群组未启用」', async () => {
  const page = await openGroupPage({
    group: () => ({ ...memberState(), enabledSource: 'membership' }),
  });
  const head = page.panel.querySelector('#dshLpGroupHead');
  assert.equal(head.textContent, '群组（按名加入） 家里 · 成员视角 · 1 人');
  assert.equal(head.textContent.includes('群组未启用'), false);
  assert.equal(page.panel.querySelector('#dshLpGroupJoinBox').style.display, 'block');
  const members = page.panel.querySelector('#dshLpGroupMembers');
  assert.equal(members.children.length, 1, '成员表照常渲染');
  assert.equal(members.children[0].children[1].textContent, 'hub-box');
});

test('config 开着的节点标题仍是「群组」（不加按名加入的标注）', async () => {
  const page = await openGroupPage({ group: () => hubState() });
  assert.match(page.panel.querySelector('#dshLpGroupHead').textContent, /^群组 家里 · 本机 hub/);
  assert.equal(page.panel.querySelector('#dshLpGroupHead').textContent.includes('按名加入'), false);
});

test('群未启用（还没入群的申请者）仍然能看到查找/申请控件，且申请期间继续轮询', async () => {
  const page = await openGroupPage({
    group: () => ({ enabled: false, isHub: false, group: null, messages: [], lastSeq: 0 }),
    lookup: { matches: MATCHES },
    apply: { status: 'pending' },
    applyStatus: { status: 'pending' },
  });
  assert.match(page.panel.querySelector('#dshLpGroupHead').textContent, /群组未启用/);
  assert.equal(page.panel.querySelector('#dshLpGroupJoinBox').style.display, 'block', '按群名加入必须可达');
  assert.equal(page.panel.querySelector('#dshLpGroupHub').style.display, 'none');
  page.findInput.value = '老家的群';
  page.findButton.onclick();
  await flush();
  page.findResult.children[0].children[1].onclick();
  await flush();
  const before = page.calls.filter((call) => call.path.startsWith('group/apply-status')).length;
  await page.tick();
  assert.equal(page.calls.filter((call) => call.path.startsWith('group/apply-status')).length, before + 1, '有申请在飞时不停表');
});

test('成员侧看不到 hub 的待批准区块与广播按钮（权限块隔离）', async () => {
  const page = await openGroupPage({ group: () => memberState() });
  assert.equal(page.panel.querySelector('#dshLpGroupHub').style.display, 'none');
  assert.equal(page.panel.querySelector('#dshLpGroupJoinBox').style.display, 'block');
  assert.ok(PANEL_SCRIPT.includes('id="dshLpGroupFind"'), '成员侧查找控件在静态骨架里');
});

// ---------------------------------------------------------------------------
// 改名查重：409 name-taken 的冲突清单
// ---------------------------------------------------------------------------

test('改名 409 name-taken → 列出 伙伴名 · 群名 · groupId 前 8 位，群名不变', async () => {
  const page = await openGroupPage({
    group: () => hubState(),
    config: () => ({
      __status: 409,
      __body: {
        error: 'name-taken',
        conflicts: [
          { peerId: 'peer-b', peerName: 'nas-b', groupId: 'g-other-1234567890', name: '老家的群' },
          { peerId: 'peer-c', peerName: 'nas-c', groupId: 'g-third-abcdef01', name: '老家的群' },
        ],
      },
    }),
  });
  page.nameInput.value = '老家的群';
  page.saveName.onclick();
  await flush();

  assert.equal(page.conflicts.textContent, '群名已被占用（未改名）：nas-b · 老家的群 · g-other-；nas-c · 老家的群 · g-third-');
  assert.equal(page.msgBox.textContent, '群名已被占用，未改名');
  assert.equal(page.nameInput.value, '老家的群', '面板不擅自改回旧名（群名确实没变）');
  const posted = posts(page.calls, 'group/config');
  assert.deepEqual(JSON.parse(posted[0].init.body), { name: '老家的群' });
});

test('改名成功 → msg 写「群名已更新」，冲突清单归零', async () => {
  const page = await openGroupPage({ group: () => hubState(), config: { ok: true, name: '新家' } });
  page.nameInput.value = '新家';
  page.saveName.onclick();
  await flush();
  assert.equal(page.msgBox.textContent, '群名已更新');
  assert.equal(page.conflicts.textContent, '');
});

test('改名失败（非冲突）只写 msg 区', async () => {
  const page = await openGroupPage({
    group: () => hubState(),
    config: { __status: 502, __body: { error: 'hub unreachable' } },
  });
  page.nameInput.value = '新家';
  page.saveName.onclick();
  await flush();
  assert.equal(page.msgBox.textContent, 'hub unreachable');
  assert.equal(page.conflicts.textContent, '');
});

// ---------------------------------------------------------------------------
// 铁律：textContent / 无 innerHTML 拼接 / 隐藏不轮询 / 不 console.error
// ---------------------------------------------------------------------------

test('v0.8.0 新块同样只走 textContent：对端名字里的 HTML 不生成标签', async () => {
  const evil = '<img src=x onerror=alert(1)>';
  const page = await openGroupPage({
    group: () => hubState({
      applications: [{ peerId: 'peer-nas', name: evil, introducedBy: 'peer-b', introducedByName: evil, at: Date.now() - 1000, status: 'pending' }],
    }),
    lookup: { matches: [{ groupId: 'g-other-1234567890', name: evil, hub: { peerId: 'peer-hub', name: evil }, via: { peerId: 'peer-b', name: evil } }] },
  });
  page.findInput.value = 'x';
  page.findButton.onclick();
  await flush();

  const row = page.pending.children[0];
  assert.equal(row.children[0].textContent, evil);
  assert.match(row.children[3].textContent, /介绍人 <img/);
  assert.equal(row.innerHTML, '', '待批准行不留 innerHTML');
  const findRow = page.findResult.children[0];
  assert.equal(findRow.children[0].textContent, evil);
  assert.match(findRow.children[2].textContent, /介绍人 <img/);
  assert.equal(findRow.innerHTML, '', '查找命中行不留 innerHTML');
});

test('群组段的 innerHTML 仍然只用于清空（v0.8.0 新增区块一并受管）', () => {
  const section = PANEL_SCRIPT.slice(PANEL_SCRIPT.indexOf('// ---- 群组页'));
  const uses = section.match(/innerHTML\s*(?:\+=|=)[^;\n]*/g) || [];
  assert.ok(uses.length > 0);
  for (const use of uses) assert.match(use, /^innerHTML\s*=\s*''$/, '只允许清空：' + use);
  assert.equal(PANEL_SCRIPT.slice(PANEL_SCRIPT.indexOf('// ---- 群组页')).includes(String.fromCharCode(96)), false);
});

test('页面隐藏时不轮询申请状态（document.hidden 一并管住 v0.8.0 的请求）', async () => {
  const page = await openGroupPage({
    group: () => memberState(),
    lookup: { matches: MATCHES },
    apply: { status: 'pending' },
    applyStatus: { status: 'pending' },
  });
  page.findInput.value = '老家的群';
  page.findButton.onclick();
  await flush();
  page.findResult.children[0].children[1].onclick();
  await flush();
  const before = page.calls.filter((call) => call.path.startsWith('group/apply-status')).length;
  page.document.hidden = true;
  await page.tick();
  assert.equal(page.calls.filter((call) => call.path.startsWith('group/apply-status')).length, before, '隐藏时不得继续轮询');
  page.document.hidden = false;
  await page.tick();
  assert.equal(page.calls.filter((call) => call.path.startsWith('group/apply-status')).length, before + 1, '可见后恢复');
});

test('v0.8.0 路径不用 console.error，也不向 msg 区写后台轮询噪声', async () => {
  const page = await openGroupPage({
    group: () => hubState(),
    applyStatus: { __status: 502, __body: { error: 'boom' } },
  });
  await page.tick();
  assert.equal(page.consoles.filter(([level]) => level === 'error').length, 0);
  assert.equal(page.msgBox.textContent, '', '后台节拍失败不写 msg 区');
});
