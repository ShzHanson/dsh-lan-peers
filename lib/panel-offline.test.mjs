// dsh-lan-peers · 0.12.6：伙伴页只留在线伙伴；私聊列表给离线行标「离线」并弱化。
//
// PANEL_SCRIPT 是浏览器脚本、无法 import：与 panel-unpair / panel-dm 同款最小 DOM 桩执行它，
// 再断言两个列表盒里的节点。桩照抄真实浏览器的两处行为：① innerHTML='' 清子节点，
// ② querySelector('#id') 每次返回同一个节点（面板的 $() 与测试看到的是同一份）。
import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { PANEL_SCRIPT } from './admin.mjs';
import { t } from './i18n.mjs';

const VIEW = { w: 1000, h: 800 };
const CJK = /[\u4e00-\u9fa5]/;
const MIN = 60000;

// 两个伙伴：书房机在线（lastSeen 就是现在），仓库机离线（7 分钟前）。
// 名字里刻意不带「离线」二字 —— 否则「行里有没有离线字样」这条断言自己就假通过。
const ONLINE = { peerId: 'peer-on-1', name: '书房机', baseUrl: 'http://10.0.0.2:7788', lastSeen: new Date().toISOString() };
const OFFLINE = { peerId: 'peer-off-1', name: '仓库机', baseUrl: 'http://10.0.0.3:7788', lastSeen: new Date(Date.now() - 7 * MIN).toISOString() };
const OFFLINE_B = { peerId: 'peer-off-2', name: '车库机', baseUrl: 'http://192.0.2.4:7788', lastSeen: new Date(Date.now() - 30 * MIN).toISOString() };

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
  };
  let html = '';
  Object.defineProperty(el, 'innerHTML', {
    get: () => html,
    set: (value) => { html = value; if (value === '') el.children.length = 0; },
  });
  return el;
}

/** 盒子里所有非空 textContent（行是拼出来的，没有聚合的 textContent）。 */
function flatText(el) {
  const out = [];
  const walk = (node) => {
    if (!node) return;
    if (typeof node.textContent === 'string' && node.textContent !== '') out.push(node.textContent);
    for (const child of node.children || []) walk(child);
  };
  walk(el);
  return out.join(' | ');
}

const rowOf = (box, name) => box.children.find((row) => flatText(row).includes(name));

const flush = async (rounds = 20) => {
  for (let i = 0; i < rounds; i += 1) await new Promise((resolve) => setTimeout(resolve, 1));
};

/** 执行面板脚本（默认就是出货的那一份；U6 传改过的副本）。 */
function boot({ script = PANEL_SCRIPT, peers = [] } = {}) {
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
    if (path === 'state') return jsonResponse({ name: 'me', instanceId: 'me-id', peers, pairing: null });
    if (path === 'dispatch') return jsonResponse({ dispatches: [] });
    if (path === 'dm/sync') return jsonResponse({ ok: true, added: 0, total: 0 });
    if (path.startsWith('dm?peer=')) return jsonResponse({ peer: { peerId: 'x', name: 'x' }, messages: [] });
    return jsonResponse({});
  };
  const window = {
    innerWidth: VIEW.w,
    innerHeight: VIEW.h,
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
    console,
  });
  const btn = document.body.children.find((el) => el.id === 'dshLpBtn');
  const panel = document.body.children.find((el) => el.id === 'dshLpPanel');
  const byId = (id) => created.find((el) => el.id === id);
  return { btn, panel, created, timers, byId, peersBox: () => panel.querySelector('#dshLpPeers') };
}

/** 打开面板 -> 停在伙伴页（首屏 refresh 已经渲染过伙伴列表）。 */
async function openPeers(options) {
  const app = boot(options);
  app.btn.onclick();
  await flush();
  return { ...app, box: app.peersBox() };
}

/** 打开面板 -> 切到私聊页（openDmPage 会再拉一次 state 并渲染伙伴列表）。 */
async function openDm(options) {
  const app = boot(options);
  app.btn.onclick();
  await flush();
  app.panel.querySelector('#dshLpTabDm').onclick();
  await flush();
  const list = app.byId('dshLpDmList');
  assert.ok(list, '私聊伙伴列表容器必须存在');
  return { ...app, list };
}

// ---------------------------------------------------------------------------
// U1 / U2：伙伴页（#dshLpPeers）
// ---------------------------------------------------------------------------

test('U1 一在线一离线：伙伴页只渲染在线那一个，离线伙伴的名字整个盒子里都没有', async () => {
  const { box } = await openPeers({ peers: [ONLINE, OFFLINE] });
  assert.equal(box.children.length, 1, '两个伙伴只该剩在线的一行');
  assert.match(flatText(box.children[0]), /书房机/, '在线伙伴照旧有名字');
  assert.equal(box.children.length === 1, true);
  assert.equal(flatText(box).includes('仓库机'), false, '离线伙伴的名字不许出现在伙伴页');
  assert.equal(flatText(box).includes(t('zh', 'panel.peers.allOffline')), false, '还有人在线，不该出提示行');
});

test('U2 全离线：伙伴页只有一行提示（新 key），一个伙伴行都不剩', async () => {
  const { box } = await openPeers({ peers: [OFFLINE, OFFLINE_B] });
  assert.equal(box.children.length, 1, '只剩提示行');
  assert.equal(box.children[0].className, 'hint', '提示行走 hint 样式');
  assert.equal(box.children[0].textContent, t('zh', 'panel.peers.allOffline'));
  assert.equal(box.children[0].textContent, '当前没有在线伙伴，离线伙伴可在私聊里找到');
  assert.equal(box.children[0].children.length, 0, '提示行里没有按钮');
  assert.equal(flatText(box).includes('仓库机'), false, '离线伙伴一行都不许有');
  assert.equal(flatText(box).includes('车库机'), false, '离线伙伴一行都不许有');
});

test('U1b 一个伙伴都没有：仍是原来那句「还没有伙伴」，与全离线区分开', async () => {
  const { box } = await openPeers({ peers: [] });
  assert.equal(box.children.length, 1);
  assert.equal(box.children[0].textContent, t('zh', 'panel.peers.emptyRow'));
});

// ---------------------------------------------------------------------------
// U3：私聊列表（#dshLpDmList）保留离线伙伴，但带「离线」字样与 off 类
// ---------------------------------------------------------------------------

test('U3 私聊列表：离线行带「离线」字样 + off 类，在线行两者都没有', async () => {
  const { list } = await openDm({ peers: [ONLINE, OFFLINE] });
  assert.equal(list.children.length, 2, '私聊列表两个伙伴都在');
  const onRow = rowOf(list, '书房机');
  const offRow = rowOf(list, '仓库机');
  assert.ok(onRow && offRow, '两行都渲染出来了');

  const offLabel = offRow.children.filter((child) => child.className === 'dmoff');
  assert.equal(offLabel.length, 1, '离线行正好一个「离线」标签');
  assert.equal(offLabel[0].textContent, t('zh', 'panel.dm.offline'));
  assert.equal(offLabel[0].textContent, '离线');
  assert.match(offRow.className, /\boff\b/, '离线行带 off 类（样式靠类，不靠内联 opacity）');
  assert.equal(offRow.children[0].textContent, '○');

  assert.doesNotMatch(onRow.className, /\boff\b/, '在线行不许带 off 类');
  assert.equal(onRow.children.filter((child) => child.className === 'dmoff').length, 0, '在线行没有「离线」标签');
  assert.equal(onRow.children[0].textContent, '●');
  assert.equal(flatText(onRow).includes('离线'), false, '在线行整行都不出现「离线」');

  // 样式规则在面板的样式表里（与邻居同一种写法，没有内联 opacity）
  assert.match(PANEL_SCRIPT, /#dshLpPanel \.dmrow\.off\{color:#8b949e\}/);
  assert.match(PANEL_SCRIPT, /#dshLpPanel \.dmrow\.off \.dot,#dshLpPanel \.dmrow\.off \.dmoff\{order:-1\}/);
  assert.match(PANEL_SCRIPT, /#dshLpPanel \.dmrow\.off \.dmoff\{color:#484f58;/);
});

// ---------------------------------------------------------------------------
// U4：两条新 key，两格齐全
// ---------------------------------------------------------------------------

test('U4 i18n 两格齐全：中文逐字对，英文无中日韩字，两格真不同', () => {
  assert.equal(t('zh', 'panel.peers.allOffline'), '当前没有在线伙伴，离线伙伴可在私聊里找到');
  assert.equal(t('en', 'panel.peers.allOffline'), 'No peers are online. Offline peers are listed in the direct-message panel.');
  assert.equal(t('zh', 'panel.dm.offline'), '离线');
  assert.equal(t('en', 'panel.dm.offline'), 'offline');
  for (const key of ['panel.peers.allOffline', 'panel.dm.offline']) {
    const zh = String(t('zh', key));
    const en = String(t('en', key));
    assert.ok(CJK.test(zh), 'zh 格应当是中文：' + key);
    assert.equal(CJK.test(en), false, 'en 格不许有中日韩字：' + key);
    assert.notEqual(zh, en, '两格必须真的不同：' + key);
    assert.doesNotMatch(zh, /^panel[.]/, 'zh 格不许漏成 key 名：' + key);
    assert.doesNotMatch(en, /^panel[.]/, 'en 格不许漏成 key 名：' + key);
  }
});

// ---------------------------------------------------------------------------
// U5：铁律 —— 改动切片零反引号、innerHTML 只赋空串、setInterval 数量不变
// ---------------------------------------------------------------------------

const PEERS_SLICE_START = 'const PEER_ONLINE_MS = 60000;';
const PEERS_SLICE_END = 'function renderJobs(jobs) {';
const DM_SLICE_START = '/** 左侧伙伴列表：在线点 + 名字 + 最近一条私聊时间';
const DM_SLICE_END = 'function applyDmView(out) {';
const CSS_SLICE_START = '#dshLpPanel .dmrow.off{color:#8b949e}';
const CSS_SLICE_END = '#dshLpPanel #dshLpDmMsgs{';

function sliceOf(source, start, end) {
  const from = source.indexOf(start);
  const to = source.indexOf(end);
  assert.ok(from >= 0, '切片起点必须在：' + start);
  assert.ok(to > from, '切片终点必须在起点之后：' + end);
  return source.slice(from, to);
}

test('U5 铁律：三段改动切片零反引号、innerHTML 只赋空串、setInterval 仍是 7 个', () => {
  const peersSlice = sliceOf(PANEL_SCRIPT, PEERS_SLICE_START, PEERS_SLICE_END);
  const dmSlice = sliceOf(PANEL_SCRIPT, DM_SLICE_START, DM_SLICE_END);
  const cssSlice = sliceOf(PANEL_SCRIPT, CSS_SLICE_START, CSS_SLICE_END);
  const slices = { 伙伴页: peersSlice, 私聊列表: dmSlice, 样式: cssSlice };
  for (const [name, text] of Object.entries(slices)) {
    assert.equal((text.match(/\u0060/g) || []).length, 0, name + '切片里零反引号');
  }
  assert.equal((peersSlice.match(/innerHTML\s*=/g) || []).length, 1, '伙伴页只有一处 innerHTML');
  assert.equal((dmSlice.match(/innerHTML\s*=/g) || []).length, 1, '私聊列表只有一处 innerHTML');
  assert.equal((peersSlice.match(/innerHTML\s*=\s*''/g) || []).length, 1, '伙伴页只赋空串');
  assert.equal((dmSlice.match(/innerHTML\s*=\s*''/g) || []).length, 1, '私聊列表只赋空串');
  // 全脚本：除唯一的静态骨架那一处，innerHTML 只允许赋空串（与 panel-i18n 同一条口径）。
  const assigned = PANEL_SCRIPT.split('\n')
    .filter((line) => line.includes('innerHTML') && line.includes('=') && !line.trim().startsWith('//') && !line.trim().startsWith('*'));
  for (const line of assigned) {
    assert.match(line.trim(), /innerHTML\s*=\s*(''|\u0060)/, 'innerHTML 只允许空串或静态骨架：' + line.trim());
  }
  // 节拍数量：改动前后都是 7（本 slice 一个新 setInterval 都没加）
  assert.equal((PANEL_SCRIPT.match(/setInterval\(/g) || []).length, 7, 'setInterval 数量不变');
  assert.equal((PANEL_SCRIPT.match(/console[.]error/g) || []).length, 0, '不许新增 console.error');
});

// ---------------------------------------------------------------------------
// U6：非空断言 —— 把两处改动各自改坏，U1 / U3 的断言必须真的会红
// ---------------------------------------------------------------------------

test('U6 拿掉「只列在线」的过滤：U1 的「只剩一行 / 名字不出现」当场红', async () => {
  const mutated = PANEL_SCRIPT.replace('const shown = peers.filter(peerIsOnline);', 'const shown = peers;');
  assert.notEqual(mutated, PANEL_SCRIPT, '变异必须真的落到脚本上');
  const { box } = await openPeers({ script: mutated, peers: [ONLINE, OFFLINE] });
  assert.equal(box.children.length, 2, '变异后离线伙伴又回到伙伴页');
  assert.equal(flatText(box).includes('仓库机'), true, '变异后离线伙伴的名字出现 —— U1 的断言就是靠这个变红的');
});

test('U6 拿掉「离线」文案：U3 的标签断言当场红', async () => {
  const mutated = PANEL_SCRIPT.replace("off.textContent = LT('panel.dm.offline');", "off.textContent = '';");
  assert.notEqual(mutated, PANEL_SCRIPT, '变异必须真的落到脚本上');
  const { list } = await openDm({ script: mutated, peers: [ONLINE, OFFLINE] });
  const offRow = rowOf(list, '仓库机');
  assert.ok(offRow, 'off 类还在（这一条只打文案）');
  assert.deepEqual(offRow.children.filter((child) => child.className === 'dmoff').map((child) => child.textContent), [''],
    '变异后离线行没有「离线」二字 —— U3 的 textContent 断言就是靠这个变红的');
  assert.equal(flatText(offRow).includes('离线'), false);
});
