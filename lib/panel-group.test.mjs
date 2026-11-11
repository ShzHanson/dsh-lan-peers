// dsh-lan-peers · 注入面板的「群组」页（v0.5.0）。
//
// PANEL_SCRIPT 是浏览器脚本，无法 import：用与 panel-drag/panel-unpair 同款的
// 最小 DOM 桩执行它，再断言「群组」页的渲染、2s 增量轮询、hub/成员两种控件形态，
// 以及「用户内容只走 textContent、群密钥不上屏」。
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

// DOM 桩的 textContent 不会聚合子节点：气泡里的正文/元信息挂在子节点上，
// 要按「一行文字」断言就得自己聚合（真 DOM 的 textContent 本来就是这个语义）。
const flatText = (el) => [String(el.textContent || ''), ...el.children.map((child) => flatText(child))].join('');

// v0.6.0 S1/S2：成员行还要显示「别人看到的地址」与「落后 N 条」
const MEMBERS = [
  { peerId: 'peer-hub', name: 'hub-box', online: true, lastSeen: new Date().toISOString(), joinedAt: 1, baseUrl: 'http://192.168.1.20:7788', lastSeq: 2, lag: 0 },
  { peerId: 'peer-nas', name: 'nas-box', online: false, lastSeen: Date.now() - 7000, joinedAt: 2, baseUrl: 'http://192.168.1.51:7788', lastSeq: 0, lag: 4 },
];

function groupState({ sinceSeq = 0 } = {}) {
  const all = [
    { seq: 1, ts: 1_700_000_600_000, from: { peerId: 'peer-nas', name: 'nas-box' }, kind: 'chat', text: '早' },
    { seq: 2, ts: 1_700_000_700_000, from: { peerId: 'peer-hub', name: 'hub-box' }, kind: 'progress', text: '', meta: { phase: 'start', status: 'running', peer: 'nas-box' } },
  ];
  const messages = all.filter((m) => m.seq > sinceSeq);
  return {
    enabled: true,
    isHub: true,
    group: { groupId: 'g-1', name: '家里', members: MEMBERS },
    messages,
    lastSeq: 2,
    // v0.6.0 S1/S2 的可见性字段（管理接口 GET group 的新增部分）
    leader: { peerId: 'peer-hub', name: 'hub-box', epoch: 3 },
    selfRole: 'hub',
    replica: { lastSeq: 2, leaderLastSeq: 2, lag: 0 },
    advertiseBaseUrl: 'http://192.168.1.20:7788',
    advertiseSource: 'config',
    selfBaseUrl: 'http://192.168.1.20:7788',
    // v0.7.0 S3（契约 §7）的选举可见性字段
    role: 'leader',
    leaseUntil: Date.now() + 9000,
    quorum: 'majority',
    commitSeq: 2,
    pendingCount: 0,
    degraded: false,
    groupKey: 'GROUP-KEY-MUST-NOT-SHOW',
  };
}

function boot({
  group = groupState, peers = [], hidden = false, groupError = null,
  // v0.7.0 S3：接管按钮的响应（对象或函数）、是否把响应挂住以观察请求期禁用、confirm 的答案
  claim = null, deferClaim = false, confirmAnswer = true,
} = {}) {
  const created = [];
  const calls = [];
  const timers = [];
  const confirms = [];
  let resolveClaim = null;
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
    if (path.startsWith('group?sinceSeq=')) {
      if (groupError) throw new Error(groupError);
      const sinceSeq = Number(path.split('=')[1]);
      return jsonResponse(typeof group === 'function' ? group({ sinceSeq }) : group);
    }
    if (path === 'group/leader') {
      const answer = () => (typeof claim === 'function' ? claim() : (claim || { ok: true, role: 'leader', epoch: 4 }));
      if (!deferClaim) return jsonResponse(answer());
      // 挂住不 resolve：测试据此断言「请求期按钮禁用」
      return new Promise((resolve) => { resolveClaim = () => resolve(jsonResponse(answer())); });
    }
    if (path.startsWith('group/')) return jsonResponse({ ok: true, seq: 3, ts: 1_700_000_900_000 });
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
  return {
    btn, panel, document, calls, created, timers, confirms,
    finishClaim: () => (resolveClaim ? resolveClaim() : null),
  };
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
    head: booted.panel.querySelector('#dshLpGroupHead'),
    hubBox: booted.panel.querySelector('#dshLpGroupHub'),
    joinBox: booted.panel.querySelector('#dshLpGroupJoinBox'),
    msgBox: booted.panel.querySelector('#dshLpMsg'),
    leaderLine: booted.panel.querySelector('#dshLpGroupLeader'),
    roleLine: booted.panel.querySelector('#dshLpGroupRole'),
    statusLine: booted.panel.querySelector('#dshLpGroupStatus'),
    degradedLine: booted.panel.querySelector('#dshLpGroupDegraded'),
    claimButton: booted.panel.querySelector('#dshLpGroupClaim'),
    replicaLine: booted.panel.querySelector('#dshLpGroupReplica'),
    addrWarn: booted.panel.querySelector('#dshLpGroupAddrWarn'),
  };
}

const groupCalls = (calls) => calls.filter((call) => call.path.startsWith('group'));

test('「群组」与「伙伴」是两个并列页签，点击切换显示', async () => {
  const { panel } = await openGroupPage();
  assert.equal(panel.querySelector('#dshLpPagePeers').style.display, 'none');
  assert.equal(panel.querySelector('#dshLpPageGroup').style.display, 'block');
  assert.match(panel.querySelector('#dshLpTabGroup').className, /on/);
  panel.querySelector('#dshLpTabPeers').onclick();
  assert.equal(panel.querySelector('#dshLpPagePeers').style.display, 'block');
  assert.equal(panel.querySelector('#dshLpPageGroup').style.display, 'none');
});

test('渲染群名与成员表：名字 + 在线点 + 最近活动时间', async () => {
  const { head, members } = await openGroupPage();
  assert.match(head.textContent, /群组 家里/);
  assert.match(head.textContent, /本机 hub/);
  assert.match(head.textContent, /2 人/);

  assert.equal(members.children.length, 2);
  const [hubRow, nasRow] = members.children;
  assert.equal(hubRow.children[0].textContent, '●');
  assert.match(hubRow.children[0].className, /\bon\b/);
  assert.equal(hubRow.children[1].textContent, 'hub-box');
  assert.match(hubRow.children[2].textContent, /前$/, '最近活动时间要显示成「xx前」');

  assert.equal(nasRow.children[0].textContent, '○');
  assert.doesNotMatch(nasRow.children[0].className, /\bon\b/);
  assert.equal(nasRow.children[1].textContent, 'nas-box');
  assert.match(nasRow.children[2].textContent, /^[0-9]+s前$/);
});

test('消息流按 seq 递增渲染：正文进气泡，老 progress 行进系统行', async () => {
  const { messages } = await openGroupPage();
  assert.equal(messages.children.length, 2);
  // seq1 = 别人的 chat：左侧气泡（.dmmsg.peer > .bubble），元信息在 .st 里
  const chat = messages.children[0];
  assert.match(chat.className, /\bdmmsg peer\b/);
  const bubble = chat.children[0];
  assert.match(bubble.className, /\bbubble\b/);
  assert.equal(bubble.children[0].textContent, '早');
  assert.match(bubble.children[1].className, /\bst\b/);
  assert.match(bubble.children[1].textContent, /^nas-box · \d{2}:\d{2}:\d{2} · #1$/);
  // seq2 = 老的 progress 行（0.10.0-α 前留下的数据）：一行居中系统行，不是气泡
  const sys = messages.children[1];
  assert.match(sys.className, /\bgsys\b/);
  assert.match(sys.textContent, /^hub-box · 系统 · progress · start\/running · \d{2}:\d{2}:\d{2} · #2$/);
});

test('2s 轮询：首次 sinceSeq=0，之后按 lastSeq 增量拉取且不重复渲染', async () => {
  const { panel, calls, timers, messages } = await openGroupPage({
    group: ({ sinceSeq }) => ({
      ...groupState({ sinceSeq }),
      messages: sinceSeq === 0 ? groupState().messages : [{ seq: 3, ts: 1_700_001_000_000, from: { peerId: 'peer-nas', name: 'nas-box' }, kind: 'result', text: 'done/1227ms/142字' }],
      lastSeq: sinceSeq === 0 ? 2 : 3,
    }),
  });
  // 只看轮询请求：群组页还会顺带拉一次只读的 group/archives（v0.8.0-β），不在这条断言里。
  const polled = () => calls.filter((call) => call.path.startsWith('group?sinceSeq='));
  const first = polled()[0];
  assert.equal(first.path, 'group?sinceSeq=0');
  const interval = timers.find((timer) => timer.ms === 2000);
  assert.ok(interval, '必须用 2s 间隔轮询');

  interval.fn();
  await flush();
  const second = polled()[1];
  assert.equal(second.path, 'group?sinceSeq=2', '增量游标跟上一次 lastSeq');
  assert.equal(messages.children.length, 3, '只追加新消息，不重复渲染旧帧');
  assert.match(messages.children[2].textContent, /result · done\/1227ms\/142字/);
});

test('页面隐藏（document.hidden）时停止轮询', async () => {
  const { document, calls, timers } = await openGroupPage();
  const before = groupCalls(calls).length;
  document.hidden = true;
  const interval = timers.find((timer) => timer.ms === 2000);
  interval.fn();
  await flush();
  assert.equal(groupCalls(calls).length, before, '隐藏时不得继续拉取');
  document.hidden = false;
  interval.fn();
  await flush();
  assert.equal(groupCalls(calls).length, before + 1, '重新可见后恢复');
});

test('hub 侧显示「添加成员 / 改群名」控件，成员侧只显示「加入群组」', async () => {
  const hubSide = await openGroupPage();
  assert.equal(hubSide.hubBox.style.display, 'block');
  assert.equal(hubSide.joinBox.style.display, 'none');
  assert.equal(hubSide.panel.querySelector('#dshLpGroupName').value, '家里', 'hub 侧可改群名（预填当前名）');

  const memberSide = await openGroupPage({ group: () => ({ ...groupState(), isHub: false }) });
  assert.equal(memberSide.hubBox.style.display, 'none');
  assert.equal(memberSide.joinBox.style.display, 'block');
  assert.match(PANEL_SCRIPT, /<button class="ghost" id="dshLpGroupJoin"><\/button>/, '成员侧按钮在骨架里');
  assert.ok(PANEL_SCRIPT.includes('"panel.group.join":"加入群组"'), '成员侧按钮文案来自注入表');
});

test('群未启用：显示「群组未启用」，不报错也不刷 msg', async () => {
  const { head, members, messages, msgBox } = await openGroupPage({
    group: () => ({ enabled: false, isHub: false, group: null, messages: [], lastSeq: 0 }),
  });
  assert.match(head.textContent, /群组未启用/);
  assert.equal(members.children.length, 0);
  assert.equal(messages.children.length, 0);
  assert.equal(msgBox.textContent, '', '未启用不是错误，不能写进 msg 区域');
});

test('对端名字里的 HTML 只当文本；群密钥（groupKey）永不上屏', async () => {
  const evil = '<img src=x onerror=alert(1)>';
  const { created, head, members, messages } = await openGroupPage({
    group: () => ({
      enabled: true,
      isHub: true,
      group: { groupId: 'g-1', name: evil, members: [{ peerId: 'p1', name: evil, online: true, lastSeen: null, joinedAt: null }] },
      messages: [{ seq: 1, ts: Date.now(), from: { peerId: 'p1', name: evil }, kind: 'chat', text: evil }],
      lastSeq: 1,
      groupKey: 'GROUP-KEY-MUST-NOT-SHOW',
    }),
  });
  assert.equal(members.children[0].children[1].textContent, evil);
  assert.match(flatText(messages.children[0]), new RegExp(evil.slice(0, 5)));
  assert.equal(created.some((el) => el.tagName === 'IMG'), false, '不得因为名字而创建标签');
  const rendered = [head.textContent, ...members.children.map((row) => row.textContent), ...messages.children.map((row) => flatText(row))]
    .concat(created.map((el) => el.textContent))
    .join('\n');
  assert.doesNotMatch(rendered, /GROUP-KEY-MUST-NOT-SHOW/, '群密钥不得出现在面板里');
});

test('发送消息：POST group/post 带 kind=chat，成功后清空输入并提示', async () => {
  const { panel, calls, msgBox } = await openGroupPage();
  const input = panel.querySelector('#dshLpGroupText');
  input.value = '晚上好';
  panel.querySelector('#dshLpGroupSend').onclick();
  await flush();
  const posted = calls.find((call) => call.path === 'group/post');
  assert.ok(posted, '必须发 POST group/post');
  assert.equal(posted.init.method, 'POST');
  assert.deepEqual(JSON.parse(posted.init.body), { kind: 'chat', text: '晚上好' });
  assert.equal(input.value, '');
  assert.equal(msgBox.textContent, '已发送');
});

test('空消息不发请求，错误提示写在 msg 区域', async () => {
  const { panel, calls, msgBox } = await openGroupPage();
  panel.querySelector('#dshLpGroupSend').onclick();
  await flush();
  assert.equal(calls.filter((call) => call.path === 'group/post').length, 0);
  assert.equal(msgBox.textContent, '消息不能为空');

  const failing = await openGroupPage({ groupError: 'hub unreachable' });
  assert.match(failing.msgBox.textContent, /群组：hub unreachable/, '轮询失败显示在 msg 区域');
});

test('hub 侧移除成员：行内「移除」→ 二次确认 → POST group/member remove', async () => {
  const { members, calls, confirms } = await openGroupPage();
  const dropButton = members.children[1].children.find((child) => child.tagName === 'BUTTON');
  assert.ok(dropButton, 'hub 侧每个成员行要有移除按钮');
  assert.equal(dropButton.textContent, '移除');
  dropButton.onclick();
  assert.deepEqual(confirms, ['把 nas-box 移出群组？']);
  await flush();
  const posted = calls.find((call) => call.path === 'group/member');
  assert.deepEqual(JSON.parse(posted.init.body), { peerId: 'peer-nas', action: 'remove' });
});

test('hub 侧添加成员与改群名都会打到管理接口', async () => {
  const { panel, calls } = await openGroupPage();
  panel.querySelector('#dshLpGroupAddId').value = 'peer-nas';
  panel.querySelector('#dshLpGroupAdd').onclick();
  await flush();
  panel.querySelector('#dshLpGroupName').value = '客厅';
  panel.querySelector('#dshLpGroupSaveName').onclick();
  await flush();
  // 只统计带请求体的写操作：v0.8.0-β 的 group/archives 列表是 GET（无 body）。
  const bodies = calls
    .filter((call) => call.path.startsWith('group/') && call.init && call.init.body)
    .map((call) => [call.path, JSON.parse(call.init.body)]);
  assert.deepEqual(bodies.find(([path]) => path === 'group/member')[1], { peerId: 'peer-nas', action: 'add' });
  assert.deepEqual(bodies.find(([path]) => path === 'group/config')[1], { name: '客厅' });
});

test('成员侧「加入群组」→ POST group/join', async () => {
  const { panel, calls, msgBox } = await openGroupPage({ group: () => ({ ...groupState(), isHub: false }) });
  panel.querySelector('#dshLpGroupJoin').onclick();
  await flush();
  const posted = calls.find((call) => call.path === 'group/join');
  assert.ok(posted, '必须发 POST group/join');
  assert.deepEqual(JSON.parse(posted.init.body), {});
  assert.equal(msgBox.textContent, '已加入群组');
});

test('群组页脚本不含反引号模板字符串，且整段脚本可被 vm 独立解析', () => {
  assert.doesNotThrow(() => new vm.Script(PANEL_SCRIPT), 'PANEL_SCRIPT 必须能独立解析');
  const start = PANEL_SCRIPT.indexOf('// ---- 群组页');
  assert.ok(start > 0, '群组页代码段应存在');
  assert.equal(PANEL_SCRIPT.slice(start).includes(String.fromCharCode(96)), false, '群组页代码不得使用反引号模板字符串');
});
// ---------------------------------------------------------------------------
// v0.6.0 S1/S2：leader / 角色 / 成员地址 / 落后条数 / 地址提示
// ---------------------------------------------------------------------------

const subRowOf = (row) => row.children.find((child) => String(child.className).includes('gsub'));

test('顶部显示「当前 leader: <名字> (epoch N)」与「我的角色: hub|成员」', async () => {
  const hubSide = await openGroupPage();
  assert.equal(hubSide.leaderLine.textContent, '当前 leader: hub-box (epoch 3)');
  assert.equal(hubSide.roleLine.textContent, '我的角色: hub');

  const memberSide = await openGroupPage({
    group: () => ({ ...groupState(), isHub: false, selfRole: 'member', leader: { peerId: 'peer-hub', name: 'hub-box', epoch: 7 } }),
  });
  assert.equal(memberSide.leaderLine.textContent, '当前 leader: hub-box (epoch 7)');
  assert.equal(memberSide.roleLine.textContent, '我的角色: 成员');
});

test('leader/epoch 缺失时降级成 —，不把 NaN 写进面板', async () => {
  const { leaderLine, roleLine } = await openGroupPage({
    group: () => ({ ...groupState(), leader: null, selfRole: undefined }),
  });
  assert.equal(leaderLine.textContent, '当前 leader: —');
  assert.equal(roleLine.textContent, '我的角色: hub', 'selfRole 缺失时按 isHub 兜底');
});

test('成员行显示各自的 baseUrl 与「落后 N 条」，lag>0 醒目，看不到地址显示 —', async () => {
  const { members } = await openGroupPage();
  const [hubRow, nasRow] = members.children;

  assert.equal(subRowOf(hubRow).children[0].textContent, 'http://192.168.1.20:7788');
  const hubLag = subRowOf(hubRow).children[1];
  assert.equal(hubLag.textContent, '落后 0 条');
  assert.doesNotMatch(hubLag.className, /hot/, '已同步不高亮');

  assert.equal(subRowOf(nasRow).children[0].textContent, 'http://192.168.1.51:7788');
  const nasLag = subRowOf(nasRow).children[1];
  assert.equal(nasLag.textContent, '落后 4 条');
  assert.match(nasLag.className, /hot/, 'lag>0 必须醒目');

  const quiet = await openGroupPage({
    group: () => ({
      ...groupState(),
      group: { groupId: 'g-1', name: '家里', members: [{ peerId: 'p1', name: 'quiet', online: false, lastSeen: null, joinedAt: null }] },
    }),
  });
  const quietSub = subRowOf(quiet.members.children[0]);
  assert.equal(quietSub.children[0].textContent, '—', '地址未知就显示 —');
  // v0.8.2-α：副行多了接单状态（契约 §4），所以不显示落后条数这条改成按类名找
  assert.equal(quietSub.children.filter((child) => String(child.className).includes('glag')).length, 0,
    'lag 未知时不显示落后条数');
  assert.equal(quietSub.children[1].textContent, '接单中', '接单状态紧跟地址');
});

test('本地副本行：已到 N 条 + 落后 leader M 条；副本未知时整行留空', async () => {
  const synced = await openGroupPage();
  assert.equal(synced.replicaLine.textContent, '本地副本: 已到 2 条 · 已同步');

  const behind = await openGroupPage({
    group: () => ({ ...groupState(), isHub: false, selfRole: 'member', replica: { lastSeq: 5, leaderLastSeq: 9, lag: 4 } }),
  });
  assert.equal(behind.replicaLine.textContent, '本地副本: 已到 5 条 · 落后 leader 4 条');

  const unknown = await openGroupPage({
    group: () => ({ ...groupState(), isHub: false, replica: { lastSeq: null, leaderLastSeq: 9, lag: null } }),
  });
  assert.equal(unknown.replicaLine.textContent, '');
});

test('advertiseBaseUrl 未配置且与别人看到的地址不同 → 一行提示；配好则不提示', async () => {
  const mismatch = await openGroupPage({
    group: () => ({
      ...groupState(),
      isHub: false,
      advertiseBaseUrl: 'http://192.168.1.20:7788',
      advertiseSource: 'auto',
      selfBaseUrl: 'http://192.168.1.99:7788',
    }),
  });
  assert.equal(mismatch.addrWarn.style.display, 'block');
  assert.equal(
    mismatch.addrWarn.textContent,
    '别人看到的你的地址是 http://192.168.1.99:7788，如不对请在 config 里设 group.advertiseBaseUrl',
  );

  const configured = await openGroupPage();
  assert.equal(configured.addrWarn.style.display, 'none');
  assert.equal(configured.addrWarn.textContent, '', 'config 里配了就不要提示');

  const undetected = await openGroupPage({
    group: () => ({ ...groupState(), advertiseBaseUrl: '', advertiseSource: 'none', selfBaseUrl: 'http://192.168.1.99:7788' }),
  });
  assert.equal(undetected.addrWarn.style.display, 'block', '探测不到自己的地址时必须提示');

  const nothing = await openGroupPage({ group: () => ({ ...groupState(), advertiseSource: 'auto', selfBaseUrl: '' }) });
  assert.equal(nothing.addrWarn.style.display, 'none', '别人也没看到我的地址就没什么可提示的');
});

test('新字段同样只走 textContent：地址/leader 名里的 HTML 不生成标签', async () => {
  const evil = '<img src=x onerror=alert(1)>';
  const { members, leaderLine, roleLine, replicaLine, addrWarn, created } = await openGroupPage({
    group: () => ({
      ...groupState(),
      isHub: false,
      leader: { peerId: 'p1', name: evil, epoch: 1 },
      group: { groupId: 'g-1', name: '家里', members: [{ peerId: 'p1', name: 'x', online: true, lastSeen: null, joinedAt: null, baseUrl: evil, lastSeq: 1, lag: 2 }] },
      advertiseBaseUrl: '',
      advertiseSource: 'none',
      selfBaseUrl: evil,
    }),
  });
  assert.equal(leaderLine.textContent, '当前 leader: ' + evil + ' (epoch 1)');
  const subRow = subRowOf(members.children[0]);
  assert.equal(subRow.children[0].textContent, evil);
  assert.equal(subRow.children[1].textContent, '落后 2 条');
  assert.match(addrWarn.textContent, new RegExp(evil.slice(0, 5)));
  assert.equal(created.some((el) => el.tagName === 'IMG'), false, '不得因为地址而创建标签');
  for (const el of [leaderLine, roleLine, replicaLine, addrWarn, ...subRow.children]) {
    assert.equal(el.innerHTML, '', '动态内容一律 textContent，元素本身不留 innerHTML');
  }
});

test('群组页代码里的 innerHTML 只用于清空，绝不拼接动态内容', () => {
  const section = PANEL_SCRIPT.slice(PANEL_SCRIPT.indexOf('// ---- 群组页'));
  const uses = section.match(/innerHTML\s*(?:\+=|=)[^;\n]*/g) || [];
  assert.ok(uses.length > 0, '群组页应当能找到 innerHTML 使用点');
  for (const use of uses) assert.match(use, /^innerHTML\s*=\s*''$/, '只允许清空：' + use);
});

// ---------------------------------------------------------------------------
// v0.7.0 S3（契约 §7）：顶部状态行 / degraded 提示 / 接管为 leader
// ---------------------------------------------------------------------------

test('S3 · 顶部状态行显示 角色 / epoch / leader / quorum 模式 / 未提交条数', async () => {
  const hubSide = await openGroupPage();
  assert.equal(
    hubSide.statusLine.textContent,
    '角色 leader · epoch 3 · leader hub-box · quorum 模式 majority · 未提交 0 条',
  );

  const memberSide = await openGroupPage({
    group: () => ({
      ...groupState(),
      isHub: false,
      selfRole: 'member',
      role: 'follower',
      quorum: 'none',
      pendingCount: 3,
      leader: { peerId: 'peer-hub', name: 'hub-box', epoch: 6 },
    }),
  });
  assert.equal(
    memberSide.statusLine.textContent,
    '角色 follower · epoch 6 · leader hub-box · quorum 模式 none · 未提交 3 条',
  );
});

test('S3 · 字段缺失时状态行降级成 —，不写 NaN/undefined，也不误报 degraded', async () => {
  const { statusLine, degradedLine } = await openGroupPage({
    group: () => ({
      ...groupState(),
      role: undefined,
      quorum: undefined,
      pendingCount: undefined,
      leaseUntil: undefined,
      degraded: undefined,
      leader: null,
    }),
  });
  assert.equal(statusLine.textContent, '角色 — · epoch — · leader — · quorum 模式 — · 未提交 — 条');
  assert.equal(degradedLine.style.display, 'none', '没有明确 degraded 标记就不报警');
  assert.equal(degradedLine.textContent, '');
});

test('S3 · degraded=true 时醒目提示「当前无 leader，请稍候或手动接管」，恢复后消失', async () => {
  let degraded = true;
  const { degradedLine, timers } = await openGroupPage({ group: () => ({ ...groupState(), degraded }) });
  assert.equal(degradedLine.textContent, '当前无 leader，请稍候或手动接管');
  assert.equal(degradedLine.style.display, 'block');

  degraded = false;
  const interval = timers.find((timer) => timer.ms === 2000);
  interval.fn();
  await flush();
  assert.equal(degradedLine.textContent, '', '恢复后提示必须撤掉');
  assert.equal(degradedLine.style.display, 'none');
});

test('S3 · 状态行与 degraded 提示同样只走 textContent', async () => {
  const evil = '<img src=x onerror=alert(1)>';
  const { statusLine, created } = await openGroupPage({
    group: () => ({
      ...groupState(),
      role: evil,
      leader: { peerId: 'p1', name: evil, epoch: 1 },
      pendingCount: 2,
    }),
  });
  assert.equal(statusLine.textContent, '角色 ' + evil + ' · epoch 1 · leader ' + evil + ' · quorum 模式 majority · 未提交 2 条');
  assert.equal(statusLine.innerHTML, '', '动态内容一律 textContent');
  assert.equal(created.some((el) => el.tagName === 'IMG'), false, '不得因为角色/leader 名创建标签');
});

test('S3 · 接管按钮在 hub 权限块里（成员侧看不见），文案为「接管为 leader」', () => {
  const skeleton = PANEL_SCRIPT.slice(PANEL_SCRIPT.indexOf('id="dshLpGroupHub"'), PANEL_SCRIPT.indexOf('id="dshLpGroupJoinBox"'));
  assert.match(skeleton, /<button class="ghost" id="dshLpGroupClaim"><\/button>/, '按钮必须落在 hub 权限块内');
  assert.ok(PANEL_SCRIPT.includes('"panel.group.claim":"接管为 leader"'), '按钮文案来自注入表');
});

test('S3 · 接管：二次确认 → POST group/leader {action:claim} → 成功提示，请求期禁用', async () => {
  const ok = await openGroupPage({ claim: { ok: true, role: 'leader', epoch: 4 } });
  ok.claimButton.onclick();
  await flush();
  assert.equal(ok.confirms.length, 1, '必须先 window.confirm 二次确认');
  assert.match(ok.confirms[0], /接管为 leader/);
  const posted = ok.calls.find((call) => call.path === 'group/leader');
  assert.ok(posted, '必须 POST group/leader');
  assert.equal(posted.init.method, 'POST');
  assert.deepEqual(JSON.parse(posted.init.body), { action: 'claim' });
  assert.equal(ok.msgBox.textContent, '已接管为 leader（epoch 4）');
  assert.equal(ok.claimButton.disabled, false, '完成后按钮解禁');

  const pending = await openGroupPage({ deferClaim: true });
  pending.claimButton.onclick();
  await flush();
  assert.equal(pending.claimButton.disabled, true, '请求期必须禁用按钮');
  pending.finishClaim();
  await flush();
  assert.equal(pending.claimButton.disabled, false);
  assert.equal(pending.msgBox.textContent, '已接管为 leader（epoch 4）');
});

test('S3 · 接管失败/取消只写 msg 区，不弹异常也不发多余请求', async () => {
  const refused = await openGroupPage({ claim: { ok: false, reason: 'quorum-unavailable' } });
  refused.claimButton.onclick();
  await flush();
  assert.equal(refused.msgBox.textContent, '接管失败：quorum-unavailable', '拒绝原因写进 msg 区');
  assert.equal(refused.claimButton.disabled, false);

  const broken = await openGroupPage({ claim: () => { throw new Error('boom'); } });
  broken.claimButton.onclick();
  await flush();
  assert.equal(broken.msgBox.textContent, 'boom', '网络异常同样只写 msg 区');
  assert.equal(broken.claimButton.disabled, false);

  const cancelled = await openGroupPage({ confirmAnswer: false });
  cancelled.claimButton.onclick();
  await flush();
  assert.equal(cancelled.calls.filter((call) => call.path === 'group/leader').length, 0, '取消确认就不发请求');
  assert.equal(cancelled.msgBox.textContent, '', '取消不该写 msg');
});

// ---------------------------------------------------------------------------
// v0.8.5-α：群组页 UI 改成与「私聊」页同一套视觉语言（气泡 / 系统行 / 圆点 / 输入区）。
// 功能面一条不动：发消息与 @! 派单、sinceSeq 轮询与 hidden 停、成员与在线点、归档、
// 群名 / leader、邀请与入群申请入口都在原有测试里继续生效。
// ---------------------------------------------------------------------------

test('群消息气泡照搬私聊页：自己靠右 self、别人靠左 peer，正文只进 textContent', async () => {
  const evil = '<img src=x onerror=alert(1)>';
  const { messages, created } = await openGroupPage({
    group: () => ({
      ...groupState(),
      messages: [
        { seq: 1, ts: 1_700_000_600_000, from: { peerId: 'me-id', name: 'me' }, kind: 'chat', text: '我先说' },
        { seq: 2, ts: 1_700_000_700_000, from: { peerId: 'peer-nas', name: 'nas-box' }, kind: 'chat', text: evil },
      ],
      lastSeq: 2,
    }),
  });
  assert.equal(messages.children.length, 2);
  const [mine, theirs] = messages.children;
  // 复用私聊页那套 .dmmsg.self/.peer + .bubble：自己靠右、别人靠左
  assert.equal(mine.className, 'dmmsg self');
  assert.equal(theirs.className, 'dmmsg peer');
  assert.equal(mine.children[0].className, 'bubble');
  assert.equal(mine.children[0].children[0].textContent, '我先说');
  assert.equal(theirs.children[0].children[0].textContent, evil, '对端正文原样落进 textContent');
  assert.equal(created.some((el) => el.tagName === 'IMG'), false, '不得因为正文而创建标签');
  // 视觉规则本身只有一套：气泡样式就写在 .dmmsg 上，没有第二套群专用气泡
  assert.match(PANEL_SCRIPT, /#dshLpPanel \.dmmsg\.self \.bubble\{background:#1f6feb;color:#fff\}/);
  assert.match(PANEL_SCRIPT, /#dshLpPanel \.dmmsg\.peer \.bubble\{background:#21262d;color:#e6edf3\}/);
  assert.doesNotMatch(PANEL_SCRIPT, /\.gmsg\{/, '旧的一行式消息样式已经退场');
});

test('老 progress/result 行只渲染成一行系统行（0.10.0-α 的 legacy 读路径）', async () => {
  const { messages } = await openGroupPage({
    group: () => ({
      ...groupState(),
      messages: [
        { seq: 1, ts: 1_700_000_600_000, from: { peerId: 'peer-hub', name: 'hub-box' }, kind: 'progress', text: '', meta: { phase: 'dispatch-start', target: 'peer-nas', status: 'running' } },
        { seq: 2, ts: 1_700_000_700_000, from: { peerId: 'peer-hub', name: 'hub-box' }, kind: 'result', text: '', meta: { phase: 'dispatch-end', status: 'done', target: 'peer-nas', elapsedMs: 1227, replyChars: 142 } },
      ],
      lastSeq: 2,
    }),
  });
  // 一条老的 progress + 一条老的 result：各渲染**正好一行**，读路径一个字都不抛。
  assert.equal(messages.children.length, 2);
  for (const row of messages.children) {
    assert.match(row.className, /^gsys$/, '老回执行是中性系统行（不再是 gsys pending）');
    assert.doesNotMatch(row.className, /\bdmmsg\b|\bbubble\b/);
    assert.equal(row.children.length, 0, '系统行只有一行字，不挂气泡');
  }
  assert.match(messages.children[0].textContent, /^hub-box · 系统 · progress · dispatch-start\/running · \d{2}:\d{2}:\d{2} · #1$/);
  assert.match(messages.children[1].textContent, /^hub-box · 系统 · result · dispatch-end\/done\/1227ms\/142字 · \d{2}:\d{2}:\d{2} · #2$/);
  // 只剩一条 .gsys 规则：派单受理态专用的 .gsys.pending 随能力一起删掉
  assert.match(PANEL_SCRIPT, /#dshLpPanel \.gsys\{[^}]*justify-content:center;[^}]*font-size:10px;color:#8b949e;/);
  assert.equal(/#dshLpPanel \.gsys\.pending/.test(PANEL_SCRIPT), false, '.gsys.pending 只服务派单受理态');
});

test('成员列表沿用私聊页同款 ● 在线 / ○ 离线 圆点', async () => {
  const { members } = await openGroupPage();
  const [online, offline] = members.children;
  assert.equal(online.children[0].textContent, '●');
  assert.equal(online.children[0].className, 'dot on');
  assert.equal(offline.children[0].textContent, '○');
  assert.equal(offline.children[0].className, 'dot');
  // 同一条 CSS 规则同时管群成员点和私聊列表点：不是「长得像」，是同一个
  assert.match(PANEL_SCRIPT, /#dshLpPanel \.member \.dot,#dshLpPanel \.dmrow \.dot\{color:#484f58;font-size:10px\}/);
  assert.match(PANEL_SCRIPT, /#dshLpPanel \.member \.dot\.on,#dshLpPanel \.dmrow \.dot\.on\{color:#3fb950\}/);
});

test('底部输入区与私聊页同款：消息区 → 输入框 → 发送，回车即发', async () => {
  const msgsAt = PANEL_SCRIPT.indexOf('id="dshLpGroupMsgs"');
  const inputAt = PANEL_SCRIPT.indexOf('id="dshLpGroupText"');
  const sendAt = PANEL_SCRIPT.indexOf('id="dshLpGroupSend"');
  assert.ok(msgsAt > 0 && inputAt > 0 && sendAt > 0, '三个节点都在骨架里');
  assert.ok(msgsAt < inputAt && inputAt < sendAt, '顺序：消息区 → 输入框 → 发送');
  // 0.10.0-α：@! 语法提示随群内派单一起移除，输入区不再有那一行 hint。
  assert.equal(PANEL_SCRIPT.includes('id="dshLpGroupSyntax"'), false, '派单语法提示不再出现在骨架里');
  assert.match(PANEL_SCRIPT, /id="dshLpGroupText" maxlength="4000"/);
  assert.ok(PANEL_SCRIPT.includes('"panel.group.placeholderText":"发一条群消息（回车发送）"'), '输入框占位来自注入表');

  const { panel, calls } = await openGroupPage();
  const input = panel.querySelector('#dshLpGroupText');
  input.value = '@!nas-box 跑一下';
  input.fire('keydown', { key: 'Enter' });
  await flush();
  const posted = calls.filter((call) => call.path === 'group/post');
  assert.equal(posted.length, 1, '回车必须发群消息');
  assert.deepEqual(JSON.parse(posted[0].init.body), { kind: 'chat', text: '@!nas-box 跑一下' }, '正文原样发出（不再有 target/workspace/permission 字段）');

  input.value = '换行用';
  input.fire('keydown', { key: 'Enter', shiftKey: true });
  await flush();
  assert.equal(calls.filter((call) => call.path === 'group/post').length, 1, 'Shift+Enter 不发送');
  assert.equal(input.value, '换行用', 'Shift+Enter 保留输入内容');
});

test('群气泡与系统行同样只走 textContent，且这一段零反引号模板字符串', async () => {
  const start = PANEL_SCRIPT.indexOf('群消息行（v0.8.5-α 视觉语言对齐私聊页）');
  const end = PANEL_SCRIPT.indexOf('function renderGroup(', start);
  assert.ok(start > 0 && end > start, '群气泡段必须能被定位到');
  const section = PANEL_SCRIPT.slice(start, end);
  assert.equal(section.includes('\u0060'), false, '群气泡段不得出现反引号');
  assert.equal(/\$\{/.test(section), false, '群气泡段不得出现模板插值');
  assert.equal(section.includes('innerHTML'), true, '只保留「清空」那一处兜底');

  const evil = '<b>名字</b>';
  const { messages, created } = await openGroupPage({
    group: () => ({
      ...groupState(),
      messages: [
        { seq: 1, ts: 1_700_000_600_000, from: { peerId: 'peer-nas', name: evil }, kind: 'chat', text: evil },
        { seq: 2, ts: 1_700_000_700_000, from: { peerId: 'peer-nas', name: evil }, kind: 'result', text: '', meta: { phase: 'dispatch-end', status: 'done', target: 'peer-nas' } },
      ],
      lastSeq: 2,
    }),
  });
  // 名字与正文都只当文本：不该多出 B / IMG 之类的真实标签
  assert.equal(created.some((el) => el.tagName === 'B' || el.tagName === 'IMG'), false);
  assert.match(flatText(messages.children[0]), /<b>名字<\/b>/);
  assert.match(messages.children[1].textContent, /^<b>名字<\/b> · 系统 · result/);
  assert.equal(messages.children.every((row) => row.innerHTML === ''), true, '动态内容一律 textContent，元素本身不留 innerHTML');
});

test('S3 · 群未启用：状态行与 degraded 提示一并清空', async () => {
  const { statusLine, degradedLine, claimButton } = await openGroupPage({
    group: () => ({ enabled: false, isHub: false, group: null, messages: [], lastSeq: 0, degraded: true }),
  });
  assert.equal(statusLine.textContent, '');
  assert.equal(degradedLine.textContent, '');
  assert.equal(degradedLine.style.display, 'none');
  assert.ok(claimButton, '按钮节点仍在（hub 块整体隐藏），不会因为未启用而报错');
});

// ---------------------------------------------------------------------------
// 0.10.0-α slice 3a（A7）：meta.quote 在答案气泡**上方**渲染成一行纯文本
// ---------------------------------------------------------------------------

test('3a A7 引用行：quote 走 textContent（无 innerHTML），没有 quote 的消息一个字都不变', async () => {
  const { messages, created } = await openGroupPage({
    group: () => ({
      ...groupState(),
      messages: [
        { seq: 1, ts: 1_700_000_600_000, from: { peerId: 'peer-nas', name: 'nas-box' }, kind: 'chat', text: '@hub-box 磁盘还剩多少' },
        {
          seq: 2,
          ts: 1_700_000_700_000,
          from: { peerId: 'peer-hub', name: 'hub-box' },
          kind: 'chat',
          text: '磁盘还剩 42G',
          meta: { quote: { seq: 1, from: 'nas-box', excerpt: '@hub-box 磁盘还剩多少' } },
        },
        {
          seq: 3,
          ts: 1_700_000_800_000,
          from: { peerId: 'peer-hub', name: 'hub-box' },
          kind: 'chat',
          text: '一条普通消息',
        },
      ],
      lastSeq: 3,
    }),
  });

  // 带 quote 的那条：气泡里多一个 .lpquote 文本节点，位置在正文之前（上方）
  const answerRow = messages.children[1];
  const answerBubble = answerRow.children[0];
  const quoteNode = answerBubble.children[0];
  assert.equal(quoteNode.className, 'lpquote', '引用行是气泡里的第一个节点');
  assert.equal(quoteNode.textContent, '引用 nas-box：@hub-box 磁盘还剩多少');
  assert.equal(answerBubble.children[1].className, 'lpbody', '正文仍排在引用后面');
  assert.equal(answerBubble.children[1].textContent, '磁盘还剩 42G');
  assert.equal(quoteNode.innerHTML, '', '引用行只赋值 textContent，元素本身不留 innerHTML');
  assert.equal(answerRow.innerHTML, '');

  // 没有 quote 的那条：气泡里只有正文 + 元信息（与改造前逐字一致）
  const plainBubble = messages.children[2].children[0];
  assert.deepEqual(plainBubble.children.map((child) => child.className), ['lpbody', 'st']);
  assert.equal(plainBubble.children.some((child) => child.className === 'lpquote'), false, '没有 quote 就没有引用行');
  assert.match(flatText(plainBubble), /一条普通消息/, '正文照旧渲染');

  // 引用内容里的尖括号不会被当成标签（只当文本）
  assert.equal(created.some((el) => el.tagName === 'B' || el.tagName === 'IMG'), false);
});

test('3a A7 铁律：引用行不引入 console.error / document.hidden / 反引号', () => {
  const start = PANEL_SCRIPT.indexOf('function messageRow(');
  const end = PANEL_SCRIPT.indexOf('function appendMessages(', start);
  assert.ok(start > 0 && end > start, 'messageRow 必须能被定位到');
  const section = PANEL_SCRIPT.slice(start, end);
  assert.equal(section.includes('innerHTML'), false, 'messageRow 里一处 innerHTML 都不该有');
  assert.equal(section.includes('\u0060'), false, '这一段不得出现反引号');
  assert.equal((PANEL_SCRIPT.match(/console\.error/g) || []).length, 0, '面板脚本零 console.error');
  // document.hidden 是既有闸门（全文 9 处，本轮一处都没加）；messageRow 段里一处都没有
  assert.equal((PANEL_SCRIPT.match(/document\.hidden/g) || []).length, 9,
    'document.hidden 数量与本轮之前一致（9 处，未新增）');
});

// ---------------------------------------------------------------------------
// 0.10.0-α slice 4a：纪要区（同一个「群组」页里的一块，不开新页签）
// ---------------------------------------------------------------------------

const NOTES_STATE = () => {
  const at = Date.now() - 60_000;
  const notes = [
    { id: 'n1', text: '周一发布的旧结论', author: 'hub-box', createdAt: at },
    { id: 'n2', text: '<img src=x onerror=alert(1)>', author: 'hub-box', createdAt: at + 1000 },
  ];
  return { notes: { rev: 2, notes }, notesSummary: { count: 2, rev: 2, lastAt: at + 1000 } };
};

test('4a N6：纪要区渲染在群组页里；成员视图不渲染追加行，hub 视图两者都有', async () => {
  const add = NOTES_STATE();

  // ---- hub 视图：只读列表 + 一行追加 ----
  const hubView = await openGroupPage({ group: () => ({ ...groupState(), ...add }) });
  const hubNotes = hubView.panel.querySelector('#dshLpGroupNotes');
  assert.equal(hubNotes.children.length, 2, '两条纪要都渲染');
  assert.equal(hubNotes.children.filter((row) => String(row.className).includes('lpnote')).length, 2);
  // 最新在上（追加序倒着渲染）：首行是后写的那条
  assert.match(flatText(hubNotes.children[0]), /<img src=x onerror=alert\(1\)>/, '正文原样以文本渲染');
  assert.match(flatText(hubNotes.children[1]), /周一发布的旧结论/);
  assert.match(hubView.panel.querySelector('#dshLpNotesHead').textContent, /共 2 条 · rev 2/, 'head 行给 count/rev');
  const hubWrite = hubView.panel.querySelector('#dshLpNotesWrite');
  assert.equal(hubWrite.children.length, 2, 'hub 视图恰好一个输入框 + 一个按钮');
  assert.deepEqual(hubWrite.children.map((el) => el.id), ['dshLpNoteText', 'dshLpNoteSend']);
  assert.equal(hubWrite.style.display, 'block');

  // 铁律：动态内容只走 textContent；元素本身不留 innerHTML；不得因为正文创建标签
  for (const row of hubNotes.children) {
    assert.equal(row.innerHTML, '', '纪要行只赋 textContent');
    for (const child of row.children) assert.equal(child.innerHTML, '');
  }
  assert.equal(hubView.created.some((el) => el.tagName === 'IMG'), false, '正文绝不参与 HTML 解析');

  // ---- 成员视图：同样看得到纪要，但追加行一个节点都没有 ----
  const memberView = await openGroupPage({ group: () => ({ ...groupState(), isHub: false, ...add }) });
  const memberNotes = memberView.panel.querySelector('#dshLpGroupNotes');
  assert.equal(memberNotes.children.length, 2, '成员照样看得到同步来的纪要');
  const memberWrite = memberView.panel.querySelector('#dshLpNotesWrite');
  assert.equal(memberWrite.children.length, 0, '成员视图里连输入框/按钮都不存在');
  assert.equal(memberWrite.style.display, 'none');
  const memberIds = memberView.created.map((el) => el.id);
  assert.equal(memberIds.includes('dshLpNoteText'), false, '成员侧没有追加输入框');
  assert.equal(memberIds.includes('dshLpNoteSend'), false, '成员侧没有追加按钮');
  assert.notEqual(memberView.panel.querySelector('#dshLpNotesMemberHint').textContent, '', '成员视图改说「只读」');
});

test('4a N6 铁律：纪要段零反引号、innerHTML 只赋空串、不新增 console.error / 节拍', async () => {
  const start = PANEL_SCRIPT.indexOf('function renderNotes');
  assert.ok(start > 0, '纪要是群组页里的一个函数，不是新页签');
  const end = PANEL_SCRIPT.indexOf('function renderGroup');
  const section = PANEL_SCRIPT.slice(start, end);
  assert.equal(section.includes('\u0060'), false, '纪要段不得出现反引号');
  assert.equal(section.includes('innerHTML'), false, '纪要段连 innerHTML 都不碰（清空走 clearBox）');
  assert.equal(section.includes('console.error'), false);
  assert.equal(section.includes('console.'), false);
  assert.equal(section.includes('setInterval'), false, '纪要不开新节拍：跟着群组那一个');
  assert.equal((PANEL_SCRIPT.match(/console\.error/g) || []).length, 0, '面板脚本零 console.error');
  // document.hidden 的门只有一个（pollGroup 里那一处），纪要段不许自己再加
  assert.equal(section.includes('document.hidden'), false);
  // 新增的按钮/输入框都是脚本现建的（成员侧就自然不存在）
  assert.equal(section.includes('dshLpNoteText'), true);
  assert.equal(section.includes('dshLpNoteSend'), true);
});

// ---------------------------------------------------------------------------
// 0.10.0-α slice 4b-2：表决区（同一个「群组」页里的一块；shelved 只有 hub 能裁决）
// ---------------------------------------------------------------------------

const VOTE_STATE = ({ mine = '', closed = false, shelved = 1, decided = 0 } = {}) => {
  const now = Date.now();
  return {
    votePlane: {
      rev: 3,
      proposals: [
        {
          id: 'p2', kind: 'objection', target: { type: 'body', id: 'n7' },
          text: '<b>旧结论</b>不同意，因为排期不够', author: 'nas-box', createdAt: now - 1000,
          status: 'open', decision: '',
          vote: {
            round: 2, status: 'open', eligible: 3, threshold: 2, yes: 1, no: 0,
            openedAt: now - 5000, closesAt: closed ? now - 1000 : now + 42000, mine,
          },
        },
        {
          id: 'p3', kind: 'supplement', target: { type: 'body', id: 'n9' },
          text: '补充一条已经默认采纳', author: 'hub-box', createdAt: now - 9000,
          status: 'adopted', decision: '', vote: null,
        },
        ...(decided === 0 ? [] : [{
          id: 'p5', kind: 'objection', target: { type: 'body', id: 'n3' },
          text: '刚才被 hub 裁决过的一条', author: 'hub-box', createdAt: now - 20000,
          status: 'adopted', decision: 'adopt',
          verdict: { decision: 'adopt', reason: '先按这个来', at: now - 30000, by: 'hub-box' },
          vote: {
            round: 3, status: 'shelved', eligible: 2, threshold: 2, yes: 1, no: 1,
            openedAt: now - 90000, closesAt: now - 30000, mine: 'no',
          },
        }]),
      ],
      shelved: shelved === 0 ? [] : [
        {
          proposalId: 'p1', rounds: 3, at: now - 60000, kind: 'objection',
          text: '三轮都没过的一条反对', target: { type: 'proposal', id: 'p0' },
        },
      ],
    },
    voteSummary: { rev: 3, proposals: decided === 0 ? 2 : 3, open: 1, shelved: shelved, decided: decided },
  };
};

const voteRowButtons = (view) => {
  const rows = view.panel.querySelector('#dshLpGroupVotes').children;
  const acts = rows
    .map((row) => row.children.find((child) => String(child.className) === 'lpvoteact'))
    .filter(Boolean);
  return acts.length === 0 ? [] : acts[0].children;
};

const decideButtons = (view) => view.created.filter((el) => el.tagName === 'BUTTON'
  && (el.textContent === '采纳' || el.textContent === '否决'));

test('4b-2 U2：开着的表决渲染轮次/目标/计票/需要几票/倒计时/我的票，点了就发 group/vote', async () => {
  const view = await openGroupPage({ group: () => ({ ...groupState(), ...VOTE_STATE() }) });
  const box = view.panel.querySelector('#dshLpGroupVotes');
  assert.equal(box.children.length, 1, '只渲染开着的那一条（默认采纳的补充不占投票位）');
  const row = box.children[0];
  const text = flatText(row);
  assert.match(text, /反对 · 目标 正文 n7/, '种类 + 目标（类型 + 短 id）');
  assert.match(text, /第 2\/3 轮/, '轮次 1..3');
  assert.match(text, /yes 1\/no 0 · 2\/3 → 需要 2 票/, '计票 + 需要的票数（由服务端算好）');
  assert.match(text, /剩 \d+s/, '到本轮截止的倒计时');
  assert.match(text, /我的票：未投/);
  assert.match(text, /旧结论/, '摘录以文本渲染');
  assert.equal(view.created.some((el) => el.tagName === 'B'), false, '正文里的 HTML 不参与解析');
  const buttons = voteRowButtons(view);
  assert.deepEqual(buttons.map((b) => b.textContent), ['赞成', '反对']);
  assert.deepEqual(buttons.map((b) => b.disabled), [false, false], '没投过、没过点 → 可投');

  buttons[0].onclick();
  await flush();
  const posted = view.calls.filter((call) => call.path === 'group/vote').pop();
  assert.ok(posted, '点「赞成」必须发一次 group/vote');
  assert.deepEqual(JSON.parse(posted.init.body), { proposalId: 'p2', ballot: 'yes' });
});

test('4b-2 U2：投过 / 已截止 → 两个按钮都 disabled（不是只换文案）', async () => {
  const voted = await openGroupPage({ group: () => ({ ...groupState(), ...VOTE_STATE({ mine: 'yes' }) }) });
  assert.deepEqual(voteRowButtons(voted).map((b) => b.disabled), [true, true], '已经投过这一轮 → 置灰');
  assert.match(flatText(voted.panel.querySelector('#dshLpGroupVotes')), /我的票：赞成/);

  const closed = await openGroupPage({ group: () => ({ ...groupState(), ...VOTE_STATE({ closed: true }) }) });
  assert.deepEqual(voteRowButtons(closed).map((b) => b.disabled), [true, true], '本轮已截止 → 置灰');
  assert.match(flatText(closed.panel.querySelector('#dshLpGroupVotes')), /本轮已截止/);
});

test('4b-2 U3：待裁决列表只有 hub 有「采纳/否决」；成员侧零按钮且明说谁能定', async () => {
  const hubView = await openGroupPage({ group: () => ({ ...groupState(), ...VOTE_STATE() }) });
  const hubBox = hubView.panel.querySelector('#dshLpGroupShelved');
  assert.equal(hubBox.children.length, 1);
  assert.match(flatText(hubBox.children[0]), /需要你来定：采纳还是否决/, 'hub 侧明确要求人来决定');
  assert.match(flatText(hubBox.children[0]), /3 轮均未通过/);
  assert.equal(decideButtons(hubView).length, 2, 'hub 侧恰好两个裁决按钮');
  assert.deepEqual(decideButtons(hubView).map((b) => b.textContent), ['采纳', '否决']);
  assert.equal(hubView.panel.querySelector('#dshLpShelvedMemberHint').style.display, 'none');

  decideButtons(hubView)[1].onclick();
  await flush();
  const posted = hubView.calls.filter((call) => call.path === 'group/adjudicate').pop();
  assert.ok(posted, '点「否决」必须发一次 group/adjudicate');
  assert.deepEqual(JSON.parse(posted.init.body), { proposalId: 'p1', decision: 'reject' });

  const memberView = await openGroupPage({ group: () => ({ ...groupState(), isHub: false, ...VOTE_STATE() }) });
  assert.equal(decideButtons(memberView).length, 0, '成员侧一个裁决按钮都不许建');
  const memberBox = memberView.panel.querySelector('#dshLpGroupShelved');
  assert.equal(memberBox.children.length, 1, '成员照样看得到待裁决列表（只读）');
  const hint = memberView.panel.querySelector('#dshLpShelvedMemberHint');
  assert.notEqual(hint.textContent, '', '成员侧必须说清「只有 hub 能定」');
  assert.match(hint.textContent, /只有 hub 的运维者能采纳或否决/);
  assert.equal(hint.style.display, 'block');
  assert.equal(memberView.calls.filter((call) => call.path === 'group/adjudicate').length, 0);
});

test('4b-2 U5/U6：表决段零反引号、不碰 HTML 赋值、不加 console 调用，也不开新节拍', async () => {
  // 铁律：新增的发出行里没有反引号（一个就足以把 PANEL_SCRIPT 撕开）
  const start = PANEL_SCRIPT.indexOf('function noteActionRow');
  const end = PANEL_SCRIPT.indexOf('function renderGroup');
  assert.ok(start > 0 && end > start, '表决段必须是群组页里的一段，不是新页签');
  const section = PANEL_SCRIPT.slice(start, end);
  assert.equal(section.includes('\u0060'), false, '表决段不得出现反引号');
  assert.equal(section.includes('innerHTML'), false, '表决段连 HTML 赋值都不碰（清空走 clearBox）');
  assert.equal(section.includes('console.'), false, '表决段不加任何 console 调用');
  assert.equal(section.includes('document.hidden'), false, '隐藏门只有 pollGroup 那一处');
  assert.equal(section.includes('setInterval'), false, '表决不开新节拍：跟着群组那一个 2s');
  assert.equal((PANEL_SCRIPT.match(/console\.error/g) || []).length, 0, '面板脚本零 console.error');
  assert.equal((PANEL_SCRIPT.match(/document\.hidden/g) || []).length, 9, 'document.hidden 的门一处都没多');
  assert.equal((PANEL_SCRIPT.match(/setInterval\(/g) || []).length, 7, '节拍数量必须与改造前一致');

  // 定时器清单：带上表决平面与不带，二者必须一模一样（多一个就是新节拍）
  const plain = await openGroupPage();
  const voting = await openGroupPage({ group: () => ({ ...groupState(), ...VOTE_STATE() }) });
  assert.deepEqual(voting.timers.map((timer) => timer.ms), plain.timers.map((timer) => timer.ms),
    '表决区不得新增任何定时器');
  assert.equal(voting.timers.filter((timer) => timer.ms === 2000).length, 1, '群组仍然只有那一个 2s 节拍');

  // 每条纪要上的两个小动作（补充 / 反对）同样是文本按钮，且把纪要 id 当目标
  const view = await openGroupPage({ group: () => ({ ...groupState(), ...NOTES_STATE(), ...VOTE_STATE() }) });
  const firstNote = view.panel.querySelector('#dshLpGroupNotes').children[0];
  const acts = firstNote.children.find((child) => String(child.className) === 'lpnoteact');
  assert.ok(acts, '每条纪要都带一行动作');
  assert.deepEqual(acts.children.map((b) => b.textContent), ['补充', '反对']);
  assert.equal(acts.children[0].innerHTML, '', '按钮只有文字');
  // 没有理由就不发请求：只有空白 → 只写 msg 区
  const before = view.calls.filter((call) => call.path === 'group/proposal').length;
  acts.children[0].onclick();
  await flush();
  assert.equal(view.calls.filter((call) => call.path === 'group/proposal').length, before, '空理由不发请求');
  assert.match(view.panel.querySelector('#dshLpMsg').textContent, /理由不能是空的/);
  // 写了理由 → 一次 group/proposal，目标预填成这条纪要的 id
  view.panel.querySelector('#dshLpProposalText').value = '这里补一句';
  acts.children[1].onclick();
  await flush();
  const posted = view.calls.filter((call) => call.path === 'group/proposal').pop();
  assert.ok(posted, '有理由就要发一次 group/proposal');
  assert.deepEqual(JSON.parse(posted.init.body), { kind: 'objection', target: { type: 'body', id: 'n2' }, text: '这里补一句' });
});

test('4b-2 F2：已裁决的提案显示决定本身（采纳 + 理由），零裁决按钮；hub 与成员看到同一份', async () => {
  for (const isHub of [true, false]) {
    const view = await openGroupPage({ group: () => ({ ...groupState(), isHub, ...VOTE_STATE({ decided: 1 }) }) });
    const box = view.panel.querySelector('#dshLpGroupDecided');
    assert.equal(box.children.length, 1, '已裁决区渲染一条（裁决随平面复制过来，两侧同源）');
    const text = flatText(box.children[0]);
    assert.match(text, /已裁决（采纳）/, '说的是「已裁决」，不是搁置提示');
    assert.match(text, /（先按这个来）/, '有理由就以括注显示');
    assert.equal(text.includes('搁置'), false, '已裁决的提案不许再显示搁置');
    assert.equal(view.panel.querySelector('#dshLpGroupVotes').children.length, 1, '已裁决的不占开票位');
    assert.equal(view.panel.querySelector('#dshLpGroupShelved').children.length, 1, '待裁决只剩真正未裁决的那条');
    if (isHub) {
      assert.equal(decideButtons(view).length, 2, 'hub 的按钮只留给仍未裁决的 shelved');
    } else {
      assert.equal(decideButtons(view).length, 0, '成员侧零裁决按钮（含已裁决区）');
    }
  }
});
