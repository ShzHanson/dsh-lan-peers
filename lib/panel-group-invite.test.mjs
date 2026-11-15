// dsh-lan-peers · 0.12.5-alpha（slice B）入群邀请的面板：hub 行内控件 + 成员侧横幅。
//
// 这一片的面板不是新页签，而是两处「长在既有群组页上」的东西：
//   hub 侧 —— 每个 roster 成员的入群三态与那一颗该点的按钮（joinState 由 GET group 下发）；
//   成员侧 —— 一个横幅，渲染 GET group 的 invites 数组（disabled 形状里现在就有它）。
// 铁律与其它 panel-*.test.mjs 同款：动态内容一律 textContent、不新开节拍、零 console.error。
import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { PANEL_SCRIPT } from './admin.mjs';
import { PANEL_BATCH3_KEYS, keys, t } from './i18n.mjs';

const CJK = /[\u4e00-\u9fff]/;
const SRC = readFileSync(new URL('./admin.mjs', import.meta.url), 'utf8');
const BT = String.fromCharCode(96);

// 与 panel-group / panel-i18n 同款的最小 DOM 桩：面板脚本只碰这些接口。
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

const NOW = 1_700_000_000_000;

/** hub 侧的一份 GET group：成员行带 joinState，账本平面在 invites.joinStates 上。 */
function hubState(nasJoinState) {
  return {
    enabled: true,
    isHub: true,
    group: {
      groupId: 'g-1',
      name: '家里',
      members: [
        { peerId: 'peer-hub', name: 'hub-box', online: true, lastSeen: NOW, baseUrl: '', joinState: 'joined' },
        { peerId: 'peer-nas', name: 'nas-box', online: true, lastSeen: NOW, baseUrl: '', joinState: nasJoinState },
      ],
    },
    messages: [],
    lastSeq: 0,
    leader: { peerId: 'peer-hub', name: 'hub-box', epoch: 3 },
    selfRole: 'hub',
    replica: { lastSeq: 0, leaderLastSeq: 0, lag: 0 },
    advertiseBaseUrl: '', advertiseSource: 'config', selfBaseUrl: '',
    role: 'leader', quorum: 'none', commitSeq: 0, pendingCount: 0, degraded: false,
    applications: [],
    // slice A 的账本平面（hub 才有）：joinStates 是行状态的第二来源
    invites: { byPeer: {}, joinStates: { 'peer-hub': 'joined', 'peer-nas': nasJoinState } },
  };
}

/** 成员侧的一份 GET group：还没入群，disabled 形状 + 待接受邀请。 */
function peerState(invites) {
  return { enabled: false, isHub: false, group: null, messages: [], lastSeq: 0, invites: invites };
}

const INVITE = {
  groupId: 'g-1',
  name: '家里',
  from: { peerId: 'peer-hub', name: 'hub-box' },
  receivedAt: NOW,
  memberCount: 3,
};

function boot({ group, inviteReply = null, script = PANEL_SCRIPT }) {
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
    calls.push({ path, init });
    if (path === 'state') return jsonResponse({ name: 'me', instanceId: 'me-id', peers: [], pairing: null });
    if (path === 'dispatch') return jsonResponse({ dispatches: [] });
    // 邀请路由要在 group/ 的兜底之前：它就是被断言的那一条
    if (path === 'group/invite') {
      return jsonResponse(typeof inviteReply === 'function' ? inviteReply() : (inviteReply || { ok: true }));
    }
    if (path.startsWith('group?sinceSeq=')) {
      const sinceSeq = Number(path.split('=')[1]);
      return jsonResponse(typeof group === 'function' ? group({ sinceSeq }) : group);
    }
    if (path.startsWith('group/')) return jsonResponse({ ok: true });
    return jsonResponse({});
  };
  const window = {
    innerWidth: 1000,
    innerHeight: 800,
    addEventListener() {},
    confirm: () => true,
    localStorage: { getItem: () => null, setItem: () => {} },
  };
  vm.runInNewContext(script, {
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
    Promise,
    console,
  });
  const btn = document.body.children.find((el) => el.id === 'dshLpBtn');
  const panel = document.body.children.find((el) => el.id === 'dshLpPanel');
  assert.ok(btn && panel, '缩略按钮与面板都要挂进 document.body');
  return { btn, panel, calls, timers };
}

/** 真机上的两步：点缩略按钮 → 切到「群组」页。 */
async function openGroupPage(options) {
  const booted = boot(options);
  booted.btn.onclick();
  await flush();
  booted.panel.querySelector('#dshLpTabGroup').onclick();
  await flush();
  return {
    ...booted,
    members: booted.panel.querySelector('#dshLpGroupMembers'),
    banner: booted.panel.querySelector('#dshLpInviteBanner'),
    msgBox: booted.panel.querySelector('#dshLpMsg'),
    head: booted.panel.querySelector('#dshLpGroupHead'),
  };
}

// 控件的「文案清单」= 子节点的 textContent（容器自身在桩里恒为 ''，真 DOM 会聚合子节点）
const labelsOf = (el) => el.children.map((child) => child.textContent);
const rowOf = (members, name) => members.children.find(
  (row) => row.children.some((child) => child.textContent === name),
);
const joinOf = (row) => row.children.find((child) => child.className === 'gjoin');
const posts = (calls, path) => calls.filter((call) => call.path === path);

// ---------------------------------------------------------------------------
// P2 · hub 侧：一行三态，各给一颗该点的按钮
// ---------------------------------------------------------------------------

test('P2 hub 行 not-invited：渲染「邀请入群」，点了就 POST group/invite {peerId}', async () => {
  let nas = 'not-invited';
  const page = await openGroupPage({
    group: () => hubState(nas),
    inviteReply: () => { nas = 'invited'; return { ok: true, peerId: 'peer-nas', state: 'invited' }; },
  });

  const row = rowOf(page.members, 'nas-box');
  assert.ok(row, 'nas-box 这一行必须在成员表里');
  const control = joinOf(row);
  assert.ok(control, 'hub 行必须挂一个入群控件');
  assert.deepEqual(labelsOf(control), [t('zh', 'panel.group.inviteAction')], '未邀请时只有一颗「邀请入群」');

  control.children[0].onclick();
  await flush();
  const sent = posts(page.calls, 'group/invite');
  assert.equal(sent.length, 1, '点一下只发一条邀请');
  assert.equal(sent[0].init.method, 'POST');
  assert.deepEqual(JSON.parse(sent[0].init.body), { peerId: 'peer-nas' });
  // 成功之后的那一拍：行自己换成「已邀请（待对方接受）」
  const after = joinOf(rowOf(page.members, 'nas-box'));
  assert.deepEqual(labelsOf(after),
    [t('zh', 'panel.group.invitePending'), t('zh', 'panel.group.inviteResend')]);
  assert.equal(page.msgBox.textContent, t('zh', 'panel.group.inviteSent', { name: 'nas-box' }));
});

test('P2 hub 行 invited：只有「已邀请（待对方接受）」+「重新发送」，没有「邀请入群」', async () => {
  const page = await openGroupPage({ group: () => hubState('invited') });
  const control = joinOf(rowOf(page.members, 'nas-box'));
  const labels = labelsOf(control);
  assert.deepEqual(labels, [t('zh', 'panel.group.invitePending'), t('zh', 'panel.group.inviteResend')]);
  assert.equal(labels.includes(t('zh', 'panel.group.inviteAction')), false, '已邀请的行不许再给「邀请入群」');
});

test('P2 hub 行 joined：只留一句「已入群」，一颗按钮都没有', async () => {
  const page = await openGroupPage({ group: () => hubState('joined') });
  const control = joinOf(rowOf(page.members, 'nas-box'));
  assert.deepEqual(labelsOf(control), [t('zh', 'panel.group.inviteJoined')]);
  assert.equal(control.children.filter((child) => child.tagName === 'BUTTON').length, 0);
});

test('P2 unreachable：稳定码上屏，按钮留着且可再点（重试是正常路径）', async () => {
  const page = await openGroupPage({
    group: () => hubState('not-invited'),
    inviteReply: () => ({ ok: false, peerId: 'peer-nas', state: 'unreachable', error: 'unreachable' }),
  });
  const control = joinOf(rowOf(page.members, 'nas-box'));
  const button = control.children[0];
  assert.equal(button.textContent, t('zh', 'panel.group.inviteAction'));
  button.onclick();
  await flush();
  assert.equal(button.disabled, false, 'unreachable 之后按钮必须解回可点');
  assert.equal(control.children.length, 1, '失败不换控件形态：还是那一颗「邀请入群」');
  assert.equal(page.msgBox.textContent, t('zh', 'panel.group.inviteUnreachable', { code: 'unreachable' }));
  assert.match(page.msgBox.textContent, /unreachable/, '稳定码必须原样上屏');
});

// ---------------------------------------------------------------------------
// P3 · 成员侧：横幅来自 disabled 形状里的 invites
// ---------------------------------------------------------------------------

test('P3 成员侧横幅：群名 + 人数；接受打 accept、拒绝打 decline；没有邀请就不画', async () => {
  const page = await openGroupPage({ group: () => peerState([INVITE]) });
  assert.equal(page.head.textContent, t('zh', 'panel.group.headDisabled'), '未入群时顶部照旧是「未启用」');
  assert.equal(page.banner.style.display, 'block');
  assert.equal(page.banner.children.length, 1);

  const row = page.banner.children[0];
  const expected = t('zh', 'panel.group.inviteBanner', { name: 'hub-box', group: '家里', count: 3 });
  assert.equal(row.children[0].textContent, expected);
  assert.match(row.children[0].textContent, /家里/, '群名要上屏');
  assert.match(row.children[0].textContent, /3 名成员/, '人数要上屏');
  assert.equal(row.children[1].textContent, t('zh', 'panel.group.inviteAccept'));
  assert.equal(row.children[2].textContent, t('zh', 'panel.group.inviteDecline'));

  row.children[1].onclick();
  await flush();
  const accepted = posts(page.calls, 'group/invite/accept');
  assert.equal(accepted.length, 1, '接受只打一条路由');
  assert.deepEqual(JSON.parse(accepted[0].init.body), { groupId: 'g-1' });

  row.children[2].onclick();
  await flush();
  const declined = posts(page.calls, 'group/invite/decline');
  assert.equal(declined.length, 1, '拒绝只打一条路由');
  assert.deepEqual(JSON.parse(declined[0].init.body), { groupId: 'g-1' });

  // 没有邀请：整块隐藏，一个子节点都不留
  const none = await openGroupPage({ group: () => peerState([]) });
  assert.equal(none.banner.style.display, 'none');
  assert.equal(none.banner.children.length, 0);
  assert.equal(none.head.textContent, t('zh', 'panel.group.headDisabled'));
});

test('P3 老 host（disabled 形状没有 invites 字段）：横幅不画、也不报错', async () => {
  const page = await openGroupPage({
    group: () => ({ enabled: false, isHub: false, group: null, messages: [], lastSeq: 0 }),
  });
  assert.equal(page.banner.style.display, 'none');
  assert.equal(page.banner.children.length, 0);
  assert.equal(page.msgBox.textContent, '');
});

// ---------------------------------------------------------------------------
// P5 · 铁律与文案：按源码切片计数，不靠目测
// ---------------------------------------------------------------------------

function addedBlock() {
  const start = SRC.indexOf('  function renderInviteBanner(list) {');
  const end = SRC.indexOf('  /** 顶部：当前 leader + epoch', start);
  assert.ok(start > 0, '新增面板段的起点必须在 lib/admin.mjs 里');
  assert.ok(end > start, '新增面板段的终点必须在 lib/admin.mjs 里');
  return SRC.slice(start, end);
}

test('P5 铁律：新增面板段零反引号、零 console、innerHTML 只赋空串、不新开节拍', () => {
  const seg = addedBlock();
  for (const fn of ['function renderInviteBanner(', 'function answerInvite(', 'function joinControl(', 'function inviteMember(']) {
    assert.ok(seg.includes(fn), '切片必须盖住：' + fn);
  }
  assert.equal(seg.split(BT).length - 1, 0, '新增面板段出现了反引号');
  assert.equal(seg.includes('console.error'), false, '新增面板段不许有 console.error');
  assert.equal((seg.match(/console\./g) || []).length, 0, '新增面板段一个 console 调用都不需要');
  for (const line of seg.split('\n').filter((item) => item.includes('innerHTML'))) {
    assert.equal(line.includes('+='), false, 'innerHTML 不许 +=：' + line.trim());
    assert.match(line.trim(), /innerHTML\s*=\s*''/, 'innerHTML 只允许赋空串：' + line.trim());
  }
  assert.equal(seg.includes('setInterval'), false, '邀请不许新开节拍');
  assert.equal((PANEL_SCRIPT.match(/setInterval\(/g) || []).length, 7,
    '节拍数量必须与改造前一致（HEAD 实测 7 枚，一个都没加）');
});

test('P5 i18n：14 条邀请文案 zh + en 都在，en 无中文、与 zh 不同、插值名字对齐', () => {
  assert.equal(PANEL_BATCH3_KEYS.length, 14, '这批固定 14 条');
  for (const key of PANEL_BATCH3_KEYS) {
    assert.equal(key.startsWith('panel.group.invite'), true, '归在 panel.group.invite* 下：' + key);
    assert.equal(keys('zh').includes(key), true, 'zh 缺 key：' + key);
    assert.equal(keys('en').includes(key), true, 'en 缺 key：' + key);
    assert.notEqual(String(t('zh', key)).trim(), '', 'zh 空串：' + key);
    assert.notEqual(String(t('en', key)).trim(), '', 'en 空串：' + key);
    assert.equal(CJK.test(String(t('en', key))), false, 'en 格仍是中文：' + key);
    assert.notEqual(String(t('en', key)), String(t('zh', key)), 'en 与 zh 一字不差等于没译：' + key);
    assert.equal(SRC.includes("'" + key + "'"), true, '面板没有引用：' + key);
  }
  const names = (text) => (String(text).match(/\{[a-zA-Z]+\}/g) || []).sort();
  for (const key of ['panel.group.inviteBanner', 'panel.group.inviteSent']) {
    assert.deepEqual(names(t('en', key)), names(t('zh', key)), '插值名字对不上：' + key);
  }
  assert.deepEqual(names(t('zh', 'panel.group.inviteBanner')), ['{count}', '{group}', '{name}']);
});

// ---------------------------------------------------------------------------
// P6 · 非空性：这两条断言真的会红 —— 用变异脚本证明，不是嘴上说
// ---------------------------------------------------------------------------

test('P6 变异一：抽掉 disabled 分支那行 renderInviteBanner，横幅断言立刻红', async () => {
  const anchor = 'renderInviteBanner(waiting);';
  assert.equal(PANEL_SCRIPT.includes(anchor), true, '变异锚点必须在脚本里');
  const mutated = PANEL_SCRIPT.replace(anchor, '');
  const real = await openGroupPage({ group: () => peerState([INVITE]) });
  assert.equal(real.banner.children.length, 1, '真脚本：一条邀请就画一行');
  const broken = await openGroupPage({ group: () => peerState([INVITE]), script: mutated });
  // 就是这一条会红（P3 里那句 banner.children.length === 1）
  assert.equal(broken.banner.children.length, 0, '变异后横幅消失 —— P3 的横幅条数断言因此能失败');
});

test('P6 变异二：抽掉 unreachable 之后的解禁行，按钮就永远点不动了', async () => {
  // 锚点用**调用点**而不是裸 key：裸 key 先出现在注入表那段 JSON 里
  const anchor = "LT('panel.group.inviteUnreachable'";
  const at = PANEL_SCRIPT.indexOf(anchor);
  assert.ok(at > 0, '变异锚点必须在脚本里');
  const unlock = 'if (button) button.disabled = false;';
  const cut = PANEL_SCRIPT.indexOf(unlock, at);
  assert.ok(cut > at, '紧跟其后的解禁行必须存在');
  const mutated = PANEL_SCRIPT.slice(0, cut) + PANEL_SCRIPT.slice(cut + unlock.length);

  const broken = await openGroupPage({
    group: () => hubState('not-invited'),
    inviteReply: () => ({ ok: false, peerId: 'peer-nas', state: 'unreachable', error: 'unreachable' }),
    script: mutated,
  });
  const button = joinOf(rowOf(broken.members, 'nas-box')).children[0];
  button.onclick();
  await flush();
  // 就是这一条会红（P2 unreachable 里那句 disabled === false）
  assert.equal(button.disabled, true, '变异后按钮留在禁用态 —— P2 的「可再点」断言因此能失败');
});
