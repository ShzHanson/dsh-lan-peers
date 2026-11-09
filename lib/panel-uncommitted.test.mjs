// dsh-lan-peers · 面板「群组」页的「有未提交的尾巴」告警（真机 seq 74 卡在未提交的可见性）
//
// 真机现场：hub 的 lastSeq=74 而 commitSeq=73 —— 74 是 leader 直写进权威日志、却没走
// 提交却只在状态行里以两个裸数字出现，成员那头永远是「拉取成功、拉不到」。
// 本文件钉住新的可见性：
//   AC1 lastSeq > commitSeq → 状态条里出现告警，文案带条数（74-73=1）；
//   AC2 相等 → display:none 且内容清空（不占位、不残留旧文案）；
//   AC3 commitSeq 反而更大 / 字段缺失 → 不告警，且绝不写 NaN；
//   AC4 告警挂在既有的 .gbar 紧凑条里（#dshLpGroupStatusBar），不是新增数据源；
//   AC5 i18n：panel.group.uncommitted 两格都非空、en 格无中文残留、占位符是 {count}；
//   AC6 铁律：新增渲染代码零反引号、无 console 错误调用、innerHTML 只赋空串。
import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { PANEL_SCRIPT, renderPanelScript } from './admin.mjs';
import { keys, t } from './i18n.mjs';

const VIEW = { w: 1000, h: 800 };
const CJK = /[\u4e00-\u9fff]/;

// 与 panel-group / panel-i18n 同款的最小 DOM 桩：面板脚本只碰这些接口。
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

/** 一份最小的 hub 侧群状态：只有本用例关心的两个数字是可变的。 */
function groupState(extra = {}) {
  return {
    enabled: true,
    isHub: true,
    group: { groupId: 'g-1', name: '家里', members: [] },
    messages: [],
    lastSeq: 74,
    leader: { peerId: 'peer-hub', name: 'hub-box', epoch: 3 },
    selfRole: 'hub',
    replica: { lastSeq: 74, leaderLastSeq: 74, lag: 0 },
    advertiseBaseUrl: 'http://192.168.1.20:7788',
    advertiseSource: 'config',
    selfBaseUrl: 'http://192.168.1.20:7788',
    role: 'leader',
    leaseUntil: Date.now() + 9000,
    quorum: 'majority',
    pendingCount: 0,
    degraded: false,
    ...extra,
  };
}

/** 打开面板并切到「群组」页（真机上的两步操作）。 */
async function openGroupPage(state) {
  const document = {
    head: makeElement('head'),
    body: makeElement('body'),
    hidden: false,
    createElement: (tag) => makeElement(tag),
  };
  const jsonResponse = (body) => ({ ok: true, status: 200, json: async () => body });
  const fetchStub = async (url) => {
    const path = String(url).replace('/api/lan-peers/', '');
    if (path === 'state') return jsonResponse({ name: 'me', instanceId: 'me-id', peers: [], pairing: null });
    if (path === 'dispatch') return jsonResponse({ dispatches: [] });
    if (path.startsWith('group?sinceSeq=')) return jsonResponse(state);
    if (path.startsWith('group/')) return jsonResponse({ ok: true, seq: 3, ts: 1_700_000_900_000 });
    return jsonResponse({});
  };
  const window = {
    innerWidth: VIEW.w,
    innerHeight: VIEW.h,
    addEventListener() {},
    confirm: () => true,
    localStorage: { getItem: () => null, setItem: () => {} },
  };
  vm.runInNewContext(PANEL_SCRIPT, {
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
    console,
  });
  const btn = document.body.children.find((el) => el.id === 'dshLpBtn');
  const panel = document.body.children.find((el) => el.id === 'dshLpPanel');
  btn.onclick();
  await flush();
  panel.querySelector('#dshLpTabGroup').onclick();
  await flush();
  return { panel, tail: panel.querySelector('#dshLpGroupUncommitted') };
}

test('lastSeq > commitSeq：状态条出现未提交告警，文案带条数（真机 74 > 73）', async () => {
  const { tail } = await openGroupPage(groupState({ lastSeq: 74, commitSeq: 73 }));
  assert.equal(tail.style.display, 'block', '有未提交的尾巴时必须显式可见');
  assert.equal(tail.textContent, t('zh', 'panel.group.uncommitted', { count: 1 }));
  assert.match(tail.textContent, /1/, '文案要带条数，不是一句干告警');
  assert.match(tail.textContent, CJK, 'zh 面板下是中文文案');
});

test('lastSeq === commitSeq：告警不显示、不占空间、不残留旧文案', async () => {
  const { tail } = await openGroupPage(groupState({ lastSeq: 74, commitSeq: 74 }));
  assert.equal(tail.style.display, 'none', '相等时隐藏');
  assert.equal(tail.textContent, '', '内容也清空，不残留上一次的条数');
});

test('commitSeq 更大或字段缺失：不告警，且绝不把 NaN 写上去', async () => {
  const ahead = await openGroupPage(groupState({ lastSeq: 73, commitSeq: 74 }));
  assert.equal(ahead.tail.style.display, 'none', 'commitSeq 更大不是「未提交」');
  assert.equal(ahead.tail.textContent, '');

  const missing = groupState({ lastSeq: 74 });
  delete missing.commitSeq;
  const { tail } = await openGroupPage(missing);
  assert.equal(tail.style.display, 'none', '没有 commitSeq 就不猜');
  assert.equal(tail.textContent, '');
});

test('告警挂在既有 .gbar 紧凑条里（复用状态条，不新增数据源）', () => {
  const script = renderPanelScript('tok', 'zh');
  const bar = /id="dshLpGroupStatusBar" class="gbar">([\s\S]*?)<\/div>\s*<div id="dshLpGroupMembers">/.exec(script);
  assert.ok(bar, '群组页状态条仍是 .gbar');
  assert.match(bar[1], /id="dshLpGroupUncommitted"/, '告警是状态条里的一项');
  assert.match(bar[1], /id="dshLpGroupUncommitted" style="display:none"/, '默认不占位');
});

test('i18n：panel.group.uncommitted 两格都非空、占位符是 {count}、en 无中文残留', () => {
  assert.ok(keys('zh').includes('panel.group.uncommitted'));
  const zh = t('zh', 'panel.group.uncommitted', { count: 2 });
  const en = t('en', 'panel.group.uncommitted', { count: 2 });
  assert.notEqual(zh.trim(), '');
  assert.notEqual(en.trim(), '');
  assert.match(zh, /2/, 'zh 格替换了条数占位符');
  assert.match(en, /2/, 'en 格替换了条数占位符');
  assert.doesNotMatch(en, CJK, 'en 格不许是中文');
  assert.notEqual(zh, en, '两种语言必须真的不同');
});

test('铁律：新增渲染代码零反引号、无 console 错误调用、innerHTML 只赋空串', () => {
  assert.equal((PANEL_SCRIPT.match(/console[.]error/g) || []).length, 0, '面板段不许 console 错误调用');
  const at = PANEL_SCRIPT.indexOf("LT('panel.group.uncommitted'");
  assert.ok(at > 0, '渲染代码必须走 i18n key');
  const block = PANEL_SCRIPT.slice(at - 400, at + 400);
  assert.doesNotMatch(block, /`/, '新增渲染代码零反引号');
  assert.doesNotMatch(block, /console[.]error/, '新增渲染代码无 console 错误调用');
  assert.doesNotMatch(block, /innerHTML/, '这条告警只写 textContent');
  assert.match(PANEL_SCRIPT, /getElementById|\(id\) =>/, '面板原有取节点方式不变');
});
