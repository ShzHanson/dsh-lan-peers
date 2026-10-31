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

test('消息流按 seq 递增渲染：时间 · 成员名 · kind · text/meta 摘要', async () => {
  const { messages } = await openGroupPage();
  assert.equal(messages.children.length, 2);
  const first = messages.children[0].textContent;
  assert.match(first, /^\d{2}:\d{2}:\d{2} · nas-box · chat · 早$/);
  const second = messages.children[1].textContent;
  assert.match(second, /· hub-box · progress · start\/running$/);
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
  assert.match(PANEL_SCRIPT, /<button class="ghost" id="dshLpGroupJoin">加入群组<\/button>/, '成员侧按钮文案');
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
  assert.match(messages.children[0].textContent, new RegExp(evil.slice(0, 5)));
  assert.equal(created.some((el) => el.tagName === 'IMG'), false, '不得因为名字而创建标签');
  const rendered = [head.textContent, ...members.children.map((row) => row.textContent), ...messages.children.map((row) => row.textContent)]
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
  assert.match(skeleton, /<button class="ghost" id="dshLpGroupClaim">接管为 leader<\/button>/, '按钮必须落在 hub 权限块内');
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

test('S3 · 群未启用：状态行与 degraded 提示一并清空', async () => {
  const { statusLine, degradedLine, claimButton } = await openGroupPage({
    group: () => ({ enabled: false, isHub: false, group: null, messages: [], lastSeq: 0, degraded: true }),
  });
  assert.equal(statusLine.textContent, '');
  assert.equal(degradedLine.textContent, '');
  assert.equal(degradedLine.style.display, 'none');
  assert.ok(claimButton, '按钮节点仍在（hub 块整体隐藏），不会因为未启用而报错');
});
