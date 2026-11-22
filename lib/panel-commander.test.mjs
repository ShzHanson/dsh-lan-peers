// dsh-lan-peers · 0.13.0-alpha slice F：面板不再「代人说话」+ 指挥官输入框。
//
// 两半都在这里：
//   1) 面板段（PANEL_SCRIPT 直出脚本，用与 panel-dm/panel-group 同款的最小 DOM 桩跑）；
//   2) 管理接口段（真 admin.handle 跑 commander / commander/say 两条路由）。
//
// 铁律：撤掉的入口必须留一条**逐字对着 client/cli.mjs 核过**的命令行指路条；
// 指挥官盒子只认服务端那几个稳定错误串，异常正文一个字都不上屏。
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

import { PANEL_SCRIPT, adminToken, createAdmin, renderPanelScript } from './admin.mjs';
import { PANEL_BATCH4_KEYS, keys, t } from './i18n.mjs';

const TOKEN = adminToken();
const CJK = /[\u3400-\u9fff]/;
const BACKTICK = String.fromCharCode(96);
const ZH = (key, params) => t('zh', key, params);
const apiPath = '/api/lan-peers/';
const PEER_B = { peerId: 'peer-b-1234', name: '书房', baseUrl: 'http://10.0.0.2:7788', lastSeen: new Date().toISOString() };
const AT = 1_760_000_000_000;
const OFFER = {
  fileId: 'f-1', name: 'note.txt', size: 4, at: AT, trusted: true,
  from: { peerId: PEER_B.peerId, name: '书房' },
};

// ---------------------------------------------------------------------------
// 面板段：最小 DOM 桩（与 panel-dm.test.mjs 同一形状）
// ---------------------------------------------------------------------------
// 面板用 panel.querySelector('#id') 取节点：桩里先查**真**建出来的元素，再退回自动桩。
let ID_LOOKUP = () => undefined;

function makeElement(tag) {
  const cache = new Map();
  const el = {
    tagName: String(tag).toUpperCase(),
    id: '',
    className: '',
    textContent: '',
    value: '',
    disabled: false,
    style: {},
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
      const real = ID_LOOKUP(id);
      if (real) return real;
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

function boot(options = {}) {
  const {
    script = renderPanelScript('tok-zh', 'zh'),
    commander = { available: true, sessionIdShort: 'abcd1234', lastReplyAt: 0 },
    say = { ok: true, reply: '好的，先归档再回你', sessionId: 'abcd1234' },
    sayError = '',
    sayThrow = false,
    files = { offers: [OFFER], inbox: [], incoming: [] },
  } = options;
  const created = [];
  const calls = [];
  const timers = [];
  const document = {
    head: makeElement('head'),
    body: makeElement('body'),
    hidden: false,
    createElement: (tag) => { const el = makeElement(tag); created.push(el); return el; },
  };
  const jsonResponse = (body, status = 200, ok = true) => ({ ok, status, json: async () => body });
  const fetchStub = async (url, init) => {
    const path = String(url).replace(apiPath, '');
    calls.push({ path, method: String((init && init.method) || 'GET').toUpperCase(), init });
    if (path === 'state') return jsonResponse({ name: 'me', instanceId: 'me-id', peers: [PEER_B], pairing: null });
    if (path === 'dispatch') return jsonResponse({ dispatches: [] });
    if (path === 'commander') return jsonResponse(commander);
    if (path === 'commander/say') {
      if (sayThrow) throw new Error('fetch failed: ECONNRESET at /secret/path');
      if (sayError !== '') return jsonResponse({ error: sayError }, 502, false);
      return jsonResponse(say);
    }
    if (path === 'files') return jsonResponse(files);
    if (path.startsWith('files/progress')) return jsonResponse({ state: 'done', size: 4, received: 4 });
    if (path === 'files/download') return jsonResponse({ ok: true });
    if (path === 'dm/sync') return jsonResponse({ ok: true, added: 0, total: 0 });
    if (path.startsWith('dm?peer=')) return jsonResponse({ peer: { peerId: PEER_B.peerId, name: '书房' }, messages: [] });
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
    console,
  });
  const btn = document.body.children.find((el) => el.id === 'dshLpBtn');
  const panel = document.body.children.find((el) => el.id === 'dshLpPanel');
  const byId = (id) => created.find((el) => el.id === id);
  ID_LOOKUP = (id) => created.find((el) => el.id === id);
  const callsTo = (path) => calls.filter((call) => call.path === path);
  return { btn, panel, document, calls, created, timers, byId, callsTo };
}

/** 打开面板并切到「私聊」页（指挥官盒子就在这一页的页首）。 */
async function openDmPage(options) {
  const app = boot(options);
  app.btn.onclick();
  await flush();
  app.panel.querySelector('#dshLpTabDm').onclick();
  await flush();
  return {
    ...app,
    page: app.byId('dshLpPageDm'),
    text: app.byId('dshLpCommanderText'),
    send: app.byId('dshLpCommanderSend'),
    hint: app.byId('dshLpCommanderHint'),
    reply: app.byId('dshLpCommanderReply'),
  };
}

function walk(node, visit) {
  visit(node);
  for (const child of node.children || []) walk(child, visit);
}

function buttonsIn(node, text) {
  const out = [];
  walk(node, (el) => { if (el.tagName === 'BUTTON' && el.textContent === text) out.push(el); });
  return out;
}

// ---------------------------------------------------------------------------
// P1：三个入口整块消失 + 每个都留了指路条（命令名逐字对着 CLI 核过）
// ---------------------------------------------------------------------------
const REMOVED_IDS = [
  'dshLpDmText', 'dshLpDmSend', 'dshLpDmAttach', 'dshLpDmPick',
  'dshLpGroupText', 'dshLpGroupSend',
  'dshLpGroupFilesPick', 'dshLpGroupFilesSend', 'dshLpGroupFilesTo',
];
const CLI_HINTS = [
  'dsh-lan-peers dm <peer> <text>',
  'dsh-lan-peers send-file <peer> <file>',
  'dsh-lan-peers group post <text>',
  'dsh-lan-peers group-file <file>',
];

test('P1 撤掉的入口在脚本与 DOM 里都不存在，四条命令行指路条逐字在位', async () => {
  const script = renderPanelScript('tok-zh', 'zh');
  for (const id of REMOVED_IDS) {
    assert.equal(script.includes(id), false, '撤掉的入口还在直出脚本里：' + id);
  }
  for (const line of CLI_HINTS) {
    assert.ok(script.includes(line), '缺少指路条的这条命令：' + line);
  }
  const app = await openDmPage();
  for (const id of REMOVED_IDS) {
    assert.equal(app.byId(id), undefined, '撤掉的入口还在面板 DOM 里：' + id);
  }
  // 指路条自己必须是真 DOM 文本（不是注释里的一句话）
  assert.equal(app.byId('dshLpDmCliHint').textContent, ZH('panel.cli.dm'));
  assert.equal(app.byId('dshLpDmFileCliHint').textContent, ZH('panel.cli.sendFile'));
});

test('P1b 指路条里的命令名在 client/cli.mjs 里真实存在（面板不自己编命令）', () => {
  const cli = fs.readFileSync(new URL('../client/cli.mjs', import.meta.url), 'utf8');
  assert.match(cli, /dm: cmdDm,/, 'dm 子命令');
  assert.match(cli, /'group-file': cmdGroupFile,/, 'group-file 子命令');
  assert.match(cli, /'send-file': cmdSendFile,/, 'send-file 子命令');
  assert.match(cli, /post: cmdGroupPost,/, 'group post 子命令');
  // 命令名之外，CLI 自己的用法串也必须是同一形状（不是面板自己攒的字符串）
  assert.match(t('zh', 'cli.dm.sendUsage'), /dsh-lan-peers dm <peer>/);
  assert.match(t('zh', 'cli.file.sendFileUsage'), /dsh-lan-peers send-file <peer> <文件>/);
  assert.match(t('zh', 'cli.file.groupFileUsage'), /dsh-lan-peers group-file <文件>/);
  assert.match(t('en', 'cli.dm.sendUsage'), /dsh-lan-peers dm <peer> <text>/);
  assert.match(t('en', 'cli.file.sendFileUsage'), /dsh-lan-peers send-file <peer> <file>/);
});

// ---------------------------------------------------------------------------
// P2：下载没被误伤
// ---------------------------------------------------------------------------
test('P2 私聊页仍列出待下载文件，点「下载」真的 POST files/download', async () => {
  const app = await openDmPage();
  // 文件表挂在既有 1s 节拍上：这里把那个节拍的手动跑一次（选中对端之后才认得这段对话）
  for (const timer of app.timers.filter((entry) => entry.ms === 1000)) timer.fn();
  await flush();
  const box = app.byId('dshLpDmFiles');
  assert.ok(box, '私聊页的文件区必须还在');
  const downloadButtons = buttonsIn(box, ZH('panel.files.download'));
  assert.equal(downloadButtons.length, 1, '一条待下载 = 一个下载键');
  assert.equal(app.callsTo('files/download').length, 0, '只列出来，不发请求');
  downloadButtons[0].onclick();
  await flush();
  const posted = app.callsTo('files/download');
  assert.equal(posted.length, 1, '点下载必须打到 files/download');
  assert.equal(posted[0].method, 'POST');
  assert.deepEqual(JSON.parse(posted[0].init.body), { fileId: 'f-1' });
  assert.ok(app.byId('dshLpDmOutbox'), '「我发出的」表还在（撤的是人发出去，不是收回来）');
});

// ---------------------------------------------------------------------------
// P3：盒子按 GET commander 决定能不能说话；发出去 = 带上正文；回复铺在下面
// ---------------------------------------------------------------------------
test('P3 available 时盒子可用：占位带会话短 id，发送带上正文，回复渲染在框下面', async () => {
  const app = await openDmPage({
    commander: { available: true, sessionIdShort: 'abcd1234', lastReplyAt: AT },
    say: { ok: true, reply: '好的，先归档再回你', sessionId: 'abcd1234' },
  });
  assert.ok(app.text && app.send && app.reply, '盒子必须有一输入一发送一块回话区');
  assert.equal(app.text.disabled, false);
  assert.equal(app.send.disabled, false);
  assert.equal(app.text.placeholder, ZH('panel.commander.placeholderReady', { id: 'abcd1234' }));
  assert.equal(app.reply.textContent, ZH('panel.commander.replyEmpty'), '还没说话时是空态文案');

  app.text.value = '把这周的日志归一下档';
  app.send.onclick();
  await flush();

  const posted = app.callsTo('commander/say');
  assert.equal(posted.length, 1, '一次点击 = 一条 commander/say');
  assert.equal(posted[0].method, 'POST');
  assert.deepEqual(JSON.parse(posted[0].init.body), { text: '把这周的日志归一下档' });
  assert.equal(app.reply.textContent, '好的，先归档再回你', '回复必须铺在框下面');
  assert.equal(app.text.value, '', '发出去之后输入框清空');
  assert.equal(app.hint.textContent, '');
});

test('P3b available=false 时盒子只显示占位文案，两个控件都禁用', async () => {
  const app = await openDmPage({ commander: { available: false, sessionIdShort: '', lastReplyAt: 0 } });
  assert.equal(app.text.placeholder, ZH('panel.commander.placeholderOff'));
  assert.equal(app.text.disabled, true);
  assert.equal(app.send.disabled, true);
  assert.equal(app.hint.textContent, ZH('panel.commander.offHint'));
});

// ---------------------------------------------------------------------------
// P4：错误只上屏稳定文案
// ---------------------------------------------------------------------------
test('P4 bad-text / timeout / no-session / 未知码 / 抛异常 都只上屏词表里的那一句', async () => {
  const cases = [
    [{ sayError: 'bad-text' }, 'panel.commander.badText'],
    [{ sayError: 'timeout' }, 'panel.commander.timeout'],
    [{ sayError: 'no-session' }, 'panel.commander.noSession'],
    [{ sayError: 'weird-not-a-code' }, 'panel.commander.error'],
    [{ sayThrow: true }, 'panel.commander.error'],
  ];
  for (const [options, key] of cases) {
    const app = await openDmPage({ commander: { available: true, sessionIdShort: 'abcd1234', lastReplyAt: 0 }, ...options });
    app.text.value = '说句话';
    app.send.onclick();
    await flush();
    assert.equal(app.hint.textContent, ZH(key), JSON.stringify(options));
    assert.doesNotMatch(app.hint.textContent, /ECONNRESET|secret|socket hang up|fetch failed|at Object/i, '异常正文不许上屏');
    assert.equal(app.reply.textContent, ZH('panel.commander.replyEmpty'), '失败不许编一条回复出来');
  }
});

// ---------------------------------------------------------------------------
// P5：空输入一个请求都不发
// ---------------------------------------------------------------------------
test('P5 空输入（含全空格）不打 commander/say，只把「先打一句」写上屏', async () => {
  const app = await openDmPage({ commander: { available: true, sessionIdShort: 'abcd1234', lastReplyAt: 0 } });
  for (const blank of ['', '   ', '\n\t ']) {
    app.text.value = blank;
    app.send.onclick();
    await flush();
    assert.equal(app.callsTo('commander/say').length, 0, '空输入不许发请求：' + JSON.stringify(blank));
    assert.equal(app.hint.textContent, ZH('panel.commander.emptyText'));
  }
});

// ---------------------------------------------------------------------------
// P6：铁律 + 新 key 双语对齐
// ---------------------------------------------------------------------------
test('P6 铁律：零 console.error、setInterval 仍是 7、hidden 闸门一个不少、指挥官段零反引号零 innerHTML', () => {
  const script = renderPanelScript('tok-zh', 'zh');
  assert.equal((script.match(/console[.]error/g) || []).length, 0, '面板段零 console.error');
  // setInterval：切片前 7 处（tick / group / dm / settings / approval / jobs / files），切片后仍是 7 处。
  assert.equal((script.match(/setInterval[(]/g) || []).length, 7, '不许新开 setInterval');
  // document.hidden：既有 7 处一个不少，也没多出第 8 处（指挥官探问复用 pollDm 的门）。
  assert.equal((script.match(/document[.]hidden === true/g) || []).length, 7, '既有 hidden 闸门不许被删、也不许另加');
  assert.match(script, /document[.]hidden === true[\s\S]{0,120}指挥官盒子跟同一拍/, 'pollDm 的闸门原样还在');

  const start = script.indexOf('let commanderAvailable');
  const end = script.indexOf('commanderText.addEventListener');
  assert.ok(start > 0 && end > start, '指挥官段必须能在脚本里定位到');
  const slice = script.slice(start, end + 200);
  assert.equal(slice.includes(BACKTICK), false, '指挥官段零反引号');
  assert.equal(slice.includes('innerHTML'), false, '指挥官段零 innerHTML');
  assert.ok(slice.includes('commanderReply.textContent = '), '回复只走 textContent');
});

test('P6b 第四批新 key：两格都在、en 无 CJK、两格不一字不差', () => {
  assert.ok(PANEL_BATCH4_KEYS.length >= 18, '第四批规模：' + PANEL_BATCH4_KEYS.length);
  for (const key of PANEL_BATCH4_KEYS) {
    assert.ok(keys('zh').includes(key), 'zh 缺 key：' + key);
    assert.ok(keys('en').includes(key), 'en 缺 key：' + key);
    const zhText = t('zh', key);
    const enText = t('en', key);
    assert.ok(zhText !== '' && zhText !== 'undefined', 'zh 空格子：' + key);
    assert.ok(enText !== '' && enText !== 'undefined', 'en 空格子：' + key);
    assert.doesNotMatch(enText, CJK, 'en 格仍是中文：' + key);
    assert.notEqual(zhText, enText, '两格一字不差：' + key);
  }
});

// ---------------------------------------------------------------------------
// P7：非空性 —— 两处变异各让一条断言红
// ---------------------------------------------------------------------------
test('P7 非空性：把私聊输入框塞回去 → P1 红；把回复那一行拆掉 → P3 红', async () => {
  const revived = PANEL_SCRIPT.replace(
    "commanderText.id = 'dshLpCommanderText';",
    "const dmInput = document.createElement('input');\n  dmInput.id = 'dshLpDmText';\n  commanderText.id = 'dshLpCommanderText';",
  );
  assert.notEqual(revived, PANEL_SCRIPT, '变异必须真的改到脚本');
  assert.ok(revived.includes('dshLpDmText'), 'P1 的「撤掉的入口还在脚本里」会红');

  const target = "commanderReply.textContent = reply === '' ? LT('panel.commander.replyEmpty') : reply;";
  const crippled = renderPanelScript('tok-zh', 'zh').replace(target, "commanderReply.textContent = '';");
  assert.notEqual(crippled, renderPanelScript('tok-zh', 'zh'), '变异必须真的改到回复那一行');
  const app = await openDmPage({
    script: crippled,
    commander: { available: true, sessionIdShort: 'abcd1234', lastReplyAt: 0 },
    say: { ok: true, reply: '好的，先归档再回你', sessionId: 'abcd1234' },
  });
  app.text.value = '把这周的日志归一下档';
  app.send.onclick();
  await flush();
  assert.equal(app.callsTo('commander/say').length, 1, '请求照发（所以红的是回复那条断言）');
  assert.notEqual(app.reply.textContent, '好的，先归档再回你', '回复没渲染 → P3 的 assert 会红');
});

// ---------------------------------------------------------------------------
// 管理接口段：GET commander / POST commander/say
// ---------------------------------------------------------------------------
function makeResponse() {
  return {
    status: 0,
    headers: {},
    body: '',
    writeHead(status, headers) { this.status = status; Object.assign(this.headers, headers || {}); },
    setHeader(k, v) { this.headers[k] = v; },
    write(chunk) { this.body += chunk; return true; },
    end(chunk) { if (chunk) this.body += chunk; if (!this.status) this.status = 200; },
    once() {},
    on() {},
  };
}

function makeReq({ method = 'GET', path = apiPath, headers = {}, body } = {}) {
  const chunks = body === undefined ? [] : [Buffer.from(body)];
  const req = {
    method,
    url: path,
    socket: { remoteAddress: '127.0.0.1', setNoDelay() {} },
    headers: { host: '127.0.0.1:7788', ...headers, 'content-length': String(chunks[0]?.length ?? 0) },
    on() { return req; },
    once() { return req; },
    async *[Symbol.asyncIterator]() { for (const chunk of chunks) yield chunk; },
  };
  return req;
}

const jsonOf = (res) => { try { return JSON.parse(res.body); } catch { return null; } };

async function hit(admin, options) {
  const res = makeResponse();
  const req = makeReq(options);
  const handled = await admin.handle(req, res, new URL('http://127.0.0.1' + req.url));
  return { handled, status: res.status, json: jsonOf(res), raw: res.body };
}

function bootAdmin({ commanderSay = null } = {}) {
  const logged = [];
  const store = {
    instanceId: 'inst-self',
    stateDir: '',
    state: { instanceId: 'inst-self', name: 'me', createdAt: '2026-01-01T00:00:00.000Z' },
    listPeers: () => [],
    getPeer: () => null,
  };
  const admin = createAdmin({
    server: { config: { logger: (line) => logged.push(line) }, store },
    nameOf: () => 'me',
    rename: (n) => n,
    feed: null,
    pairing: { mode: 'auto' },
    commanderSay,
  });
  return { admin, logged };
}

const POST_HEADERS = { 'x-lan-peers-token': TOKEN, 'content-type': 'application/json' };
const READ_HEADERS = { 'x-lan-peers-token': TOKEN };

test('R1 GET commander：不注入时 available=false；注入后 available=true 并回报短 id 与上次回复时刻', async () => {
  const off = await hit(bootAdmin().admin, { path: apiPath + 'commander', headers: READ_HEADERS });
  assert.equal(off.status, 200);
  assert.deepEqual(off.json, { available: false, sessionIdShort: '', lastReplyAt: 0 });
  const unsupported = await hit(bootAdmin().admin, { method: 'POST', path: apiPath + 'commander/say', headers: POST_HEADERS, body: '{"text":"hi"}' });
  assert.equal(unsupported.status, 501);
  assert.equal(unsupported.json.error, 'commander-unsupported');

  const { admin } = bootAdmin({ commanderSay: async () => ({ ok: true, reply: '收到', sessionIdShort: 'abcd1234' }) });
  const say = await hit(admin, { method: 'POST', path: apiPath + 'commander/say', headers: POST_HEADERS, body: '{"text":"归一下档"}' });
  assert.equal(say.status, 200, say.raw);
  assert.deepEqual(say.json, { ok: true, reply: '收到', sessionId: 'abcd1234' });
  const state = await hit(admin, { path: apiPath + 'commander', headers: READ_HEADERS });
  assert.equal(state.json.available, true);
  assert.equal(state.json.sessionIdShort, 'abcd1234');
  assert.ok(state.json.lastReplyAt > 0, '成功一次就记下时刻');
});

test('R2 POST commander/say：正文原样交给注入的 commanderSay；失败折成稳定串 + 稳定状态码', async () => {
  const seen = [];
  const { admin } = bootAdmin({
    commanderSay: async (text) => {
      seen.push(text);
      if (text === 'ok') return { ok: true, reply: '', sessionIdShort: 'abcd1234' };
      return { ok: false, error: text };
    },
  });
  assert.equal((await hit(admin, { method: 'POST', path: apiPath + 'commander/say', headers: POST_HEADERS, body: '{"text":"ok"}' })).json.reply, '');
  assert.deepEqual(seen, ['ok'], '正文原样交给下面（接口不 trim 也不改写）');
  const cases = [['bad-text', 400], ['no-session', 503], ['timeout', 504], ['send-failed', 502], ['weird', 502]];
  for (const [code, status] of cases) {
    const out = await hit(admin, { method: 'POST', path: apiPath + 'commander/say', headers: POST_HEADERS, body: JSON.stringify({ text: code }) });
    assert.equal(out.status, status, code);
    assert.equal(out.json.error, code, code);
  }
  const broken = bootAdmin({ commanderSay: async () => { throw new Error('socket hang up at /secret/path'); } }).admin;
  const out = await hit(broken, { method: 'POST', path: apiPath + 'commander/say', headers: POST_HEADERS, body: '{"text":"x"}' });
  assert.equal(out.status, 502);
  assert.equal(out.json.error, 'error');
  assert.equal(out.raw.includes('secret'), false, '异常正文不许回流给浏览器');
});
