// dsh-lan-peers · v0.8.0-β（DESIGN §18.2）面板「群组」页的「归档」区块。
//
// 与 panel-group.test.mjs 同款最小 DOM 桩：PANEL_SCRIPT 是浏览器脚本，无法 import，
// 这里跑真脚本并断言渲染与请求。铁律一并钉住：动态内容只走 textContent、群组段零反引号、
// 删除必须二次确认、删除成功才刷新列表、失败只写 msg 区、不用 console.error。
import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { PANEL_SCRIPT } from './admin.mjs';

const VIEW = { w: 1000, h: 800 };
const HOUR = 3600_000;
const MB = 1024 * 1024;

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

/** 两条归档：体积合计 21 MB（2 × 一个「MB」口径的整数便于断言文案）。 */
function archivesFixture() {
  const created = Date.now() - 3 * HOUR;
  return [
    { file: '101-400.json', fromSeq: 101, toSeq: 400, count: 300, bytes: 12 * MB, createdAt: created },
    { file: '1-100.json', fromSeq: 1, toSeq: 100, count: 100, bytes: 9 * MB, createdAt: created - HOUR },
  ];
}

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
    quorum: 'majority',
    pendingCount: 0,
    degraded: false,
    applications: [],
    ...extra,
  };
}

function boot({
  group = () => hubState(), hidden = false, archives = null, remove = null, confirmAnswer = true,
} = {}) {
  // 归档列表是可变状态：删除成功后 GET 要能返回「少了一条」的新列表。
  let stored = typeof archives === 'function' ? archives() : (archives || archivesFixture());
  const totalOf = (list) => list.reduce((sum, item) => sum + (Number(item.bytes) || 0), 0);
  const calls = [];
  const timers = [];
  const created = [];
  const confirms = [];
  const consoles = [];
  const document = {
    head: makeElement('head'),
    body: makeElement('body'),
    hidden,
    createElement: (tag) => { const el = makeElement(tag); created.push(el); return el; },
  };
  const jsonResponse = (body, status = 200) => ({ ok: status < 400, status, json: async () => body });
  const fetchStub = async (url, init) => {
    const path = String(url).replace('/api/lan-peers/', '');
    calls.push({ path, init });
    if (path === 'state') return jsonResponse({ name: 'me', instanceId: 'me-id', peers: [], pairing: null });
    if (path === 'dispatch') return jsonResponse({ dispatches: [] });
    if (path.startsWith('group?sinceSeq=')) {
      const sinceSeq = Number(path.split('=')[1]);
      return jsonResponse(typeof group === 'function' ? group({ sinceSeq }) : group);
    }
    if (path === 'group/archives') {
      const method = String(init && init.method ? init.method : 'GET');
      if (method === 'GET') return jsonResponse({ archives: stored, totalBytes: totalOf(stored) });
      const body = init && init.body ? JSON.parse(init.body) : {};
      const verdict = typeof remove === 'function' ? remove(body) : (remove || { ok: true, removedBytes: 12 * MB });
      if (verdict instanceof Error) throw verdict;
      if (verdict && verdict.__status) return jsonResponse(verdict.__body ?? {}, verdict.__status);
      if (verdict.ok !== false && Array.isArray(stored)) {
        stored = stored.filter((item) => item.file !== body.file);
      }
      return jsonResponse(verdict);
    }
    return jsonResponse({ ok: true });
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
  return { btn, panel, document, calls, timers, created, confirms, consoles };
}

/** 打开面板并切到「群组」页（真机上的两步操作）。 */
async function openGroupPage(options = {}) {
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
    archiveHead: q('dshLpArchiveHead'),
    archiveList: q('dshLpGroupArchives'),
    hubBox: q('dshLpGroupHub'),
  };
}

const archiveCalls = (calls, method) => calls.filter((call) => call.path === 'group/archives'
  && String(call.init && call.init.method ? call.init.method : 'GET') === method);

const subRowOf = (row) => row.children.find((child) => String(child.className).includes('gsub'));

// ---------------------------------------------------------------------------
// 渲染：顶行总体积 + 每行文件名 / seq 区间 / 条数 / 体积 / 时间 / 删除
// ---------------------------------------------------------------------------

test('hub 侧：归档区块顶行显示「归档 N 个 · 共 X」，每行五要素齐全', async () => {
  const page = await openGroupPage();
  assert.equal(page.archiveHead.textContent, '归档 2 个 · 共 21.0 MB');
  assert.equal(page.archiveList.children.length, 2);

  const first = page.archiveList.children[0];
  assert.equal(first.className, 'member garchive');
  assert.equal(first.children[0].textContent, '101-400.json', '文件名');
  assert.equal(first.children[1].textContent, '删除', '删除按钮');
  assert.match(subRowOf(first).textContent, /seq 101–400/);
  assert.match(subRowOf(first).textContent, /300 条/);
  assert.match(subRowOf(first).textContent, /12\.0 MB/);
  assert.match(subRowOf(first).textContent, /3h前/);

  const second = page.archiveList.children[1];
  assert.equal(second.children[0].textContent, '1-100.json');
  assert.match(subRowOf(second).textContent, /seq 1–100 · 100 条 · 9\.0 MB/);
  assert.equal(page.msgBox.textContent, '', '只读列表不写 msg 区');
});

test('归档区块只拉一次：2s 轮询不会重复请求（归档不挂节拍）', async () => {
  const page = await openGroupPage();
  assert.equal(archiveCalls(page.calls, 'GET').length, 1);
  await page.tick();
  await page.tick();
  assert.equal(archiveCalls(page.calls, 'GET').length, 1, '再轮询两拍也不该重拉归档');
});

test('没有归档时给出说明行，顶行仍是 0', async () => {
  const page = await openGroupPage({ archives: () => [] });
  assert.equal(page.archiveHead.textContent, '归档 0 个 · 共 0 B');
  assert.equal(page.archiveList.children.length, 1);
  assert.match(page.archiveList.children[0].textContent, /还没有归档/);
});

test('动态内容全走 textContent：归档行不留 innerHTML，也不因为文件名创建标签', async () => {
  const page = await openGroupPage({
    archives: () => [
      { file: '<img src=x onerror=alert(1)>.json', fromSeq: 1, toSeq: 2, count: 3, bytes: 1024, createdAt: Date.now() - 1000 },
    ],
  });
  const row = page.archiveList.children.find((child) => String(child.className).includes('garchive'));
  assert.equal(row.children[0].textContent, '<img src=x onerror=alert(1)>.json');
  for (const el of [row, ...row.children]) assert.equal(el.innerHTML, '', '动态内容一律 textContent');
  assert.equal(page.created.some((el) => el.tagName === 'IMG'), false, '文件名不得变成标签');
});

// ---------------------------------------------------------------------------
// 删除：二次确认 → POST → 刷新列表 + 提示释放空间
// ---------------------------------------------------------------------------

test('删除：二次确认 → POST { file, action:"delete" } → 提示释放空间并刷新列表与总体积', async () => {
  const page = await openGroupPage();
  const removeButton = page.archiveList.children[0].children[1];
  removeButton.onclick();
  await flush();

  assert.equal(page.confirms.length, 1, '必须先 window.confirm 二次确认');
  assert.match(page.confirms[0], /101-400\.json/);
  assert.match(page.confirms[0], /无法恢复/);

  const posted = archiveCalls(page.calls, 'POST');
  assert.equal(posted.length, 1);
  assert.deepEqual(JSON.parse(posted[0].init.body), { file: '101-400.json', action: 'delete' });
  assert.match(page.msgBox.textContent, /已删除归档 101-400\.json，释放 12\.0 MB/);

  assert.equal(archiveCalls(page.calls, 'GET').length, 2, '删除成功后必须重新拉一次列表');
  assert.equal(page.archiveHead.textContent, '归档 1 个 · 共 9.0 MB', '总体积跟着刷新');
  assert.equal(page.archiveList.children.length, 1);
  assert.equal(page.archiveList.children[0].children[0].textContent, '1-100.json');
});

test('删除：二次确认点「取消」就不发请求，也不写 msg 区', async () => {
  const page = await openGroupPage({ confirmAnswer: false });
  page.archiveList.children[0].children[1].onclick();
  await flush();
  assert.equal(page.confirms.length, 1, '二次确认照常弹出');
  assert.equal(archiveCalls(page.calls, 'POST').length, 0, '取消就不该有删除请求');
  assert.equal(archiveCalls(page.calls, 'GET').length, 1, '取消也不刷新列表');
  assert.equal(page.msgBox.textContent, '', '取消不该写 msg');
  assert.equal(page.archiveList.children.length, 2, '列表原样保留');
});

test('删除失败：只写 msg 区，按钮解禁，不弹异常也不用 console.error', async () => {
  const page = await openGroupPage({ remove: () => Object.assign(new Error('boom'), {}) });
  const button = page.archiveList.children[0].children[1];
  button.onclick();
  await flush();
  assert.equal(page.msgBox.textContent, '删除归档失败：boom');
  assert.equal(button.disabled, false, '失败后按钮要能再点');
  assert.equal(archiveCalls(page.calls, 'POST').length, 1);
  assert.equal(archiveCalls(page.calls, 'GET').length, 1, '失败不刷新列表');
  assert.equal(page.consoles.some(([level]) => level === 'error'), false, '面板不写 console.error');
});

test('删除被拒（501 archives-unsupported）：错误码进 msg 区，列表原样保留', async () => {
  const page = await openGroupPage({ remove: () => ({ __status: 501, __body: { error: 'archives-unsupported' } }) });
  page.archiveList.children[0].children[1].onclick();
  await flush();
  assert.match(page.msgBox.textContent, /删除归档失败：archives-unsupported/);
  assert.equal(page.archiveList.children.length, 2);
  assert.equal(page.archiveHead.textContent, '归档 2 个 · 共 21.0 MB');
});

// ---------------------------------------------------------------------------
// 成员侧 / 铁律
// ---------------------------------------------------------------------------

test('成员侧：归档区块清空并说明只在 hub 可见，且不打归档接口', async () => {
  const page = await openGroupPage({ group: () => hubState({ isHub: false, selfRole: 'member' }) });
  assert.equal(archiveCalls(page.calls, 'GET').length, 0, '成员侧不该请求 group/archives');
  assert.equal(page.archiveList.children.length, 0);
  assert.equal(page.archiveHead.textContent, '归档只在 hub 侧可见');
});

test('群未启用：归档区块一并清空', async () => {
  const page = await openGroupPage({
    group: () => ({ enabled: false, isHub: false, group: null, messages: [], lastSeq: 0 }),
  });
  assert.equal(archiveCalls(page.calls, 'GET').length, 0);
  assert.equal(page.archiveList.children.length, 0);
  assert.equal(page.archiveHead.textContent, '归档 0 个 · 共 0 B');
});

test('铁律：归档区块在 hub 权限块内、群组段无反引号、innerHTML 只用于清空', () => {
  const hubBlock = PANEL_SCRIPT.slice(PANEL_SCRIPT.indexOf('id="dshLpGroupHub"'), PANEL_SCRIPT.indexOf('id="dshLpGroupJoinBox"'));
  assert.match(hubBlock, /id="dshLpArchiveHead"/, '顶行必须在 hub 权限块内');
  assert.match(hubBlock, /id="dshLpGroupArchives"/, '列表容器必须在 hub 权限块内');

  const section = PANEL_SCRIPT.slice(PANEL_SCRIPT.indexOf('// ---- 群组页'));
  assert.equal(section.includes(String.fromCharCode(96)), false, '群组段不得使用反引号模板字符串');
  const uses = section.match(/innerHTML\s*(?:\+=|=)[^;\n]*/g) || [];
  assert.ok(uses.length > 0, '群组段应当能找到 innerHTML 使用点');
  for (const use of uses) assert.match(use, /^innerHTML\s*=\s*''$/, '只允许清空：' + use);
});
