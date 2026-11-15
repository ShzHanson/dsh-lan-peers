// dsh-lan-peers · 0.12.4：伙伴页「本机地址」那一行（端口 + **全部**非回环 IPv4）
//
// 真机现象（用户的说法）：「在伙伴页添加一行显示自身 ip 以及端口的输出，否则连自己的
// 端口都不知道。」原来面板从不告诉你「对端该连哪里」，而一台机器常常有两条地址
// （有线 + 无线），只报一条就等于指错路。
//
// 本文件钉住四件事：
//   P1 GET state 的 own 块（端口 / 每个非回环 IPv4 / 对外声明 / 管理地址）；
//   P2 面板那一行把**每一条**地址都写出来，并把对外声明的那一枚就地标记；
//   P3 没有局域网地址时仍报端口（一行，仍然有用）；
//   P4 铁律：新增段零反引号、无 console.error、不碰 innerHTML、不加节拍不加请求；
//   P5 新文案 zh + en 两格齐备、en 无中日韩字；
//   P6 非空化：把「多条地址」压成一条、把声明标记拆掉，对应断言真的会红。
//
// 隐私口径：本文件一个真实 IP 都没有 —— 一律 10.1.2.3 / 10.1.2.4 / 203.0.113.9 这类
// 显然假的地址；真机地址只由 listPrivateIpv4s() 在运行时算，测试只与它比对。
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { PANEL_SCRIPT, createAdmin, renderPanelScript } from './admin.mjs';
import { detectPrivateIpv4, listPrivateIpv4s, pickPrivateIpv4 } from '../host/server.mjs';
import { makeTempStateDir } from '../host/test/helpers.mjs';
import { listenOnRandomPort } from '../test-support/ports.mjs';
import { createPeerServer } from '../host/server.mjs';
import { keys, t } from './i18n.mjs';

const PORT = 7788;
const IP_A = '10.1.2.3';
const IP_B = '10.1.2.4';

/** 一块假网卡表：有线 + 无线各一条私有地址，另有回环 / 虚拟网卡 / IPv6 三条必须被排除 */
const FAKE_IFACES = {
  Ethernet: [{ address: IP_A, family: 'IPv4', internal: false }],
  'Wi-Fi': [{ address: IP_B, family: 4, internal: false }],
  'vEthernet (WSL)': [{ address: '172.20.0.1', family: 'IPv4', internal: false }],
  'Loopback Pseudo-Interface 1': [{ address: '127.0.0.1', family: 'IPv4', internal: true }],
  'Ethernet 2': [{ address: 'fe80::1', family: 'IPv6', internal: false }],
};

// ---------------------------------------------------------------------------
// 真面板的最小 DOM 桩（与 panel-files / panel-dm 同款接口）
// ---------------------------------------------------------------------------
function makeElement(tag) {
  const cache = new Map();
  const el = {
    tagName: String(tag).toUpperCase(),
    id: '', className: '', textContent: '', value: '', placeholder: '', maxLength: 0,
    style: {}, disabled: false, selected: false, children: [], listeners: new Map(),
    offsetWidth: 96, offsetHeight: 36, onclick: null,
    appendChild(child) { this.children.push(child); return child; },
    click() {},
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

const flush = async (rounds = 40) => {
  for (let i = 0; i < rounds; i += 1) await new Promise((resolve) => setTimeout(resolve, 1));
};

/** 跑一份面板脚本，state 的 own 块由调用方给；返回那一行的文本与请求/节拍流水 */
function bootPanel(own, script = PANEL_SCRIPT) {
  const calls = [];
  const timers = [];
  const document = {
    head: makeElement('head'),
    body: makeElement('body'),
    hidden: false,
    createElement: (tag) => makeElement(tag),
  };
  const json = (body) => ({ ok: true, status: 200, json: async () => body });
  const fetchStub = async (url, init) => {
    const path = String(url).replace('/api/lan-peers/', '');
    calls.push({ path, method: (init && init.method) || 'GET' });
    if (path === 'state') {
      return json({ name: 'me', instanceId: 'me-id', peers: [], pairing: null, fileMaxBytes: 0, own });
    }
    if (path === 'lang') return json({ lang: 'auto' });
    return json({});
  };
  const window = {
    innerWidth: 1000, innerHeight: 800, addEventListener() {}, confirm: () => true,
    localStorage: { getItem: () => null, setItem: () => {} },
  };
  vm.runInNewContext(script, {
    window, document, localStorage: window.localStorage, fetch: fetchStub,
    setInterval: (fn, ms) => { timers.push({ fn, ms }); return timers.length; },
    clearInterval: () => {},
    setTimeout: () => 0, clearTimeout: () => {},
    JSON, Math, console,
  });
  const btn = document.body.children.find((el) => el.id === 'dshLpBtn');
  const panel = document.body.children.find((el) => el.id === 'dshLpPanel');
  return { btn, panel, calls, timers, text: (id) => panel.querySelector('#' + id).textContent };
}

/** 直接拿一份面板脚本跑一趟（refresh 由打开面板触发），读那一行的文本 */
async function openWith(own, script) {
  const app = bootPanel(own, script);
  app.btn.onclick();
  await flush();
  return app.text('dshLpOwnAddr');
}

const ownLineOf = (own, script) => openWith(own, script);

/** 真面板的一趟：打开面板（refresh 一次）后读那一行 */
async function openAndRead(own) {
  const app = bootPanel(own);
  app.btn.onclick();
  await flush();
  return app;
}

// ---------------------------------------------------------------------------
// 服务端：一块真 admin（群门面按桩接线，地址与端口由桩给）
// ---------------------------------------------------------------------------
function makeResponse() {
  return {
    status: 0, headers: {}, body: '',
    setHeader(k, v) { this.headers[k] = v; },
    writeHead(status, headers) { this.status = status; Object.assign(this.headers, headers || {}); },
    write(chunk) { this.body += chunk; return true; },
    end(chunk) { if (chunk) this.body += chunk; if (!this.status) this.status = 200; },
    once() {}, on() {},
  };
}

function makeRequest(path, token) {
  const req = {
    method: 'GET',
    url: path,
    socket: { remoteAddress: '127.0.0.1', setNoDelay() {} },
    headers: { host: '127.0.0.1:' + PORT, 'content-length': '0', 'x-lan-peers-token': token },
    on() { return req; },
    once() { return req; },
    async *[Symbol.asyncIterator]() {},
  };
  return req;
}

async function getState(admin) {
  const res = makeResponse();
  const handled = await admin.handle(makeRequest('/api/lan-peers/state', admin.token), res,
    new URL('http://127.0.0.1/api/lan-peers/state'));
  assert.equal(handled, true, 'state 必须由 admin 接管');
  assert.equal(res.status, 200, 'state 必须 200：' + res.body);
  return JSON.parse(res.body);
}

function ownServer({ ips = [IP_A, IP_B], advertise = '', groupConfig = null } = {}) {
  const store = {
    instanceId: 'inst-self', stateDir: '',
    state: { instanceId: 'inst-self', name: 'me', createdAt: '2026-01-01T00:00:00.000Z' },
    listPeers: () => [], getPeer: () => null,
  };
  return {
    config: { logger: () => {}, listenPort: PORT, group: groupConfig },
    store,
    group: {
      advertiseBaseUrl: () => advertise,
      listenPort: () => PORT,
      localAddresses: () => ips,
    },
  };
}

// ---------------------------------------------------------------------------
// P1：own 块的形状
// ---------------------------------------------------------------------------
test('P1 listPrivateIpv4s 收全部非回环 IPv4（排除回环/虚拟网卡/IPv6），pickPrivateIpv4 口径不变', () => {
  assert.deepEqual(listPrivateIpv4s(FAKE_IFACES), [IP_A, IP_B],
    '两条真网卡地址都要在，顺序按 rank + 网卡名（Ethernet 在 Wi-Fi 前）');
  assert.equal(pickPrivateIpv4(FAKE_IFACES), IP_A, '首选仍是排序后的第一条');
  assert.equal(pickPrivateIpv4(FAKE_IFACES), listPrivateIpv4s(FAKE_IFACES)[0],
    'detect 的首选必须就是列表第一条（同一份排序，不另起一套口径）');
  // 只有公网地址时：列表照收，首选仍然是 null（老行为不变）
  assert.deepEqual(listPrivateIpv4s({ Ethernet: [{ address: '203.0.113.9', family: 'IPv4', internal: false }] }),
    ['203.0.113.9']);
  assert.equal(pickPrivateIpv4({ Ethernet: [{ address: '203.0.113.9', family: 'IPv4', internal: false }] }), null);
  // 空表 / 坏表都不抛
  assert.deepEqual(listPrivateIpv4s({}), []);
  assert.deepEqual(listPrivateIpv4s(null), []);
  assert.equal(typeof detectPrivateIpv4(), 'string', 'detectPrivateIpv4 仍旧返回字符串（老调用方口径不变）');
});

test('P1 GET state 带 own 块：端口 = 配置端口，一条地址一个条目，url = http://<ip>:<port>', async () => {
  const admin = createAdmin({ server: ownServer(), nameOf: () => 'me', rename: (n) => n });
  const out = await getState(admin);
  assert.ok(out.own && typeof out.own === 'object', 'GET state 必须有 own 块');
  assert.equal(out.own.listenPort, PORT, 'listenPort 就是配置的监听端口');
  assert.deepEqual(out.own.addresses, [
    { ip: IP_A, url: 'http://' + IP_A + ':' + PORT },
    { ip: IP_B, url: 'http://' + IP_B + ':' + PORT },
  ], '两条地址各一个条目，url 由 ip + 端口拼出来');
  assert.equal(out.own.addresses.length, 2, '多数一条会静默指错网络');
  assert.equal(out.own.advertise, null, '没有对外地址时是 null（不是空字符串对象）');
  assert.equal(out.own.adminBase, 'http://127.0.0.1:' + PORT, 'adminBase 是面板此刻在打的 origin');
  // own 块里只允许数字、URL 与两个枚举词：任何一条字符串都要能落进这三类之一
  const strings = [out.own.adminBase, out.own.advertise === null ? '' : out.own.advertise.source]
    .concat(out.own.addresses.map((row) => row.url))
    .filter((value) => value !== '');
  for (const value of strings) {
    assert.match(String(value), /^(?:http:\/\/[0-9.]+:\d+|auto|config)$/,
      'own 块里只许有 IP/端口/URL（不许出现路径）：' + value);
  }
});

test('P1 own.advertise 复用 advertiseAddress()：config 优先，否则自动探测那一枚', async () => {
  const auto = createAdmin({
    server: ownServer({ advertise: 'http://' + IP_A + ':' + PORT }),
    nameOf: () => 'me', rename: (n) => n,
  });
  assert.deepEqual((await getState(auto)).own.advertise,
    { url: 'http://' + IP_A + ':' + PORT, source: 'auto' }, '自动探测 → source:auto');

  const configured = createAdmin({
    server: ownServer({ advertise: 'http://' + IP_A + ':' + PORT, groupConfig: { advertiseBaseUrl: 'http://10.9.9.9:7788/' } }),
    nameOf: () => 'me', rename: (n) => n,
  });
  assert.deepEqual((await getState(configured)).own.advertise,
    { url: 'http://10.9.9.9:7788', source: 'config' }, '配置里手写的那一枚 → source:config（末尾斜杠归一）');
});

test('P1 真 host：own 的端口就是真实监听端口，地址就是 listPrivateIpv4s() 那一份', async (t) => {
  const stateDir = makeTempStateDir('dsh-lan-peers-own-');
  const server = createPeerServer({ listenHost: '127.0.0.1', stateDir, requireEncryption: false });
  const info = await listenOnRandomPort(server, '127.0.0.1');
  t.after(async () => { await server.close(); fs.rmSync(stateDir, { recursive: true, force: true }); });
  const admin = createAdmin({ server, nameOf: () => 'me', rename: (n) => n });
  const out = await getState(admin);
  assert.equal(out.own.listenPort, info.port, 'own.listenPort 必须是真正绑上的那个端口（不是配置里的缺省值）');
  const live = listPrivateIpv4s();
  assert.deepEqual(out.own.addresses.map((row) => row.ip), live,
    'own.addresses 必须与本机全部非回环 IPv4 一一对上，一条不多一条不少');
  for (const row of out.own.addresses) {
    assert.equal(row.url, 'http://' + row.ip + ':' + info.port);
  }
  assert.equal(out.own.adminBase, 'http://127.0.0.1:' + PORT, '管理地址仍来自请求的 Host 头');
});

// ---------------------------------------------------------------------------
// P2：面板那一行
// ---------------------------------------------------------------------------
test('P2 面板一行写全两个地址，并把对外声明的那一枚就地标记', async () => {
  const app = await openAndRead({
    listenPort: PORT,
    addresses: [{ ip: IP_A, url: 'http://' + IP_A + ':' + PORT }, { ip: IP_B, url: 'http://' + IP_B + ':' + PORT }],
    advertise: { url: 'http://' + IP_A + ':' + PORT, source: 'auto' },
    adminBase: 'http://127.0.0.1:' + PORT,
  });
  const line = app.text('dshLpOwnAddr');
  const marked = IP_A + ':' + PORT + t('zh', 'panel.peers.ownAdvertised');
  const plain = IP_B + ':' + PORT;
  assert.equal(line, t('zh', 'panel.peers.ownLine').replace('{addrs}', marked + ' · ' + plain),
    '整行形状：本机 <ip:port>（对外声明） · <ip:port>');
  assert.ok(line.includes(plain), '第二条地址必须也出现（不许只报一条）');
  assert.ok(line.includes(marked), '对外声明的那一枚必须带标记');
  assert.equal(line.includes(IP_B + ':' + PORT + t('zh', 'panel.peers.ownAdvertised')), false,
    '标记只落在被声明的那一枚上');
});

test('P2 对外地址不在列表里（配置手写）时，末尾补一句声明的是哪个', async () => {
  const app = await openAndRead({
    listenPort: PORT,
    addresses: [{ ip: IP_A, url: 'http://' + IP_A + ':' + PORT }],
    advertise: { url: 'http://10.9.9.9:7788', source: 'config' },
  });
  assert.equal(app.text('dshLpOwnAddr'),
    t('zh', 'panel.peers.ownLine').replace('{addrs}', IP_A + ':' + PORT)
      + t('zh', 'panel.peers.ownAdvertiseOther').replace('{url}', 'http://10.9.9.9:7788'));
});

// ---------------------------------------------------------------------------
// P3：没有局域网地址
// ---------------------------------------------------------------------------
test('P3 零地址时那一行报「未发现局域网地址」并且仍报端口', async () => {
  const admin = createAdmin({ server: ownServer({ ips: [], advertise: '' }), nameOf: () => 'me', rename: (n) => n });
  const out = await getState(admin);
  assert.deepEqual(out.own.addresses, [], '没有非回环 IPv4 时是空数组');
  assert.equal(out.own.advertise, null);
  const app = await openAndRead(out.own);
  assert.equal(app.text('dshLpOwnAddr'), t('zh', 'panel.peers.ownNoAddr').replace('{port}', String(PORT)));
  assert.match(app.text('dshLpOwnAddr'), /7788/, '端口必须还在那一行里');
});

test('P3 老 host 没有 own 块时那一行也不炸（照样报端口）', async () => {
  const app = await openAndRead(undefined);
  assert.equal(app.text('dshLpOwnAddr'),
    t('zh', 'panel.peers.ownNoAddr').replace('{port}', '0'), '缺 own 时端口按 0 报，绝不抛错');
});

// ---------------------------------------------------------------------------
// P4：铁律（只扫新增段）
// ---------------------------------------------------------------------------
const SRC = readFileSync(new URL('./admin.mjs', import.meta.url), 'utf8');
const SECTION_START = '  // 「本机地址」那一行：端口 + **全部**';
const SECTION_END = '  function startCountdown(expiresAt) {';

function addedBlock() {
  const start = SRC.indexOf(SECTION_START);
  const end = SRC.indexOf(SECTION_END, start);
  assert.ok(start > 0 && end > start, '新增段的起止标记必须还在 lib/admin.mjs 里');
  return SRC.slice(start, end);
}

test('P4 新增段零反引号、无 console.error、不碰 innerHTML、节拍数不变', () => {
  const block = addedBlock();
  assert.equal((block.match(/`/g) || []).length, 0, '新增段零反引号（面板整份就是一个模板字符串）');
  assert.equal(/console\.error/.test(block), false, '不新增 console.error');
  assert.equal(block.includes('innerHTML'), false, '这一行只用 textContent，连 innerHTML 都不碰');
  for (const needle of ['dshLpOwnAddr', 'renderOwnAddr', 'panel.peers.ownAdvertised', 'panel.peers.ownNoAddr']) {
    assert.ok(block.includes(needle), '新增段里必须真的有：' + needle);
  }
  // 节拍与请求都不许加：面板脚本的 setInterval 仍是改造前的 7 条
  // （admin.mjs 源码里另有 1 条模块级的，不属于面板段，全文件 8 条）
  assert.equal((PANEL_SCRIPT.match(/setInterval\(/g) || []).length, 7, '不许新开节拍');
  assert.equal(PANEL_SCRIPT.includes('id="dshLpOwnAddr"'), true, '骨架里必须有那一行的节点');
  assert.equal(PANEL_SCRIPT.includes('function renderOwnAddr'), true, '渲染函数必须在面板脚本里');
});

test('P4 打开面板仍然只打一趟 GET state，那一行不另发请求', async () => {
  const app = await openAndRead({ listenPort: PORT, addresses: [{ ip: IP_A, url: 'http://' + IP_A + ':' + PORT }], advertise: null });
  assert.equal(app.calls.filter((call) => call.path === 'state').length, 1, 'state 只拉一次');
  // 面板本来就在打的四个端点：这一趟不许出现第五个（新增行只能搭既有的 state）
  const KNOWN = ['dispatch', 'dispatch/pending', 'files', 'state'];
  const unknown = app.calls.map((call) => call.path).filter((path) => !KNOWN.includes(path));
  assert.deepEqual(unknown, [], '新增行不许新开请求：多出来的端点 = ' + unknown.join(', '));
});

// ---------------------------------------------------------------------------
// P5：新文案 zh + en
// ---------------------------------------------------------------------------
const NEW_KEYS = [
  'panel.peers.ownLine',
  'panel.peers.ownAdvertised',
  'panel.peers.ownAdvertiseOther',
  'panel.peers.ownNoAddr',
];

test('P5 四条新文案 zh + en 两格都在：en 无中日韩字、与 zh 不同、插值名对得上', async () => {
  const zhKeys = keys('zh');
  const enKeys = keys('en');
  for (const key of NEW_KEYS) {
    assert.equal(zhKeys.includes(key), true, 'zh 缺 key：' + key);
    assert.equal(enKeys.includes(key), true, 'en 缺 key：' + key);
    assert.notEqual(String(t('zh', key)).trim(), '', 'zh 空串：' + key);
    assert.notEqual(String(t('en', key)).trim(), '', 'en 空串：' + key);
    assert.equal(/[\u4e00-\u9fa5]/.test(String(t('en', key))), false, 'en 格仍是中文：' + key);
    assert.notEqual(String(t('en', key)), String(t('zh', key)), 'en 与 zh 一字不差等于没译：' + key);
    const names = (value) => (String(value).match(/\{[a-zA-Z]+\}/g) || []).sort();
    assert.deepEqual(names(t('en', key)), names(t('zh', key)), '插值名字对不上：' + key);
  }
  // 面板真的按注入表渲染英文（不是只有词表里有）
  const en = await openWith({ listenPort: PORT, addresses: [{ ip: IP_A, url: 'http://' + IP_A + ':' + PORT }], advertise: null },
    renderPanelScript('tok-own-en', 'en'));
  assert.match(en, new RegExp(t('en', 'panel.peers.ownLine').split('{addrs}')[0].trim()));
  assert.equal(/[\u4e00-\u9fa5]/.test(en), false, '英文面板下那一行不许有中文');
  assert.equal(en.includes(IP_A + ':' + PORT), true);
});

// ---------------------------------------------------------------------------
// P6：非空化（脚本级变异，内存里改，磁盘不动）
// ---------------------------------------------------------------------------
test('P6 变异证明：「几条地址」压成一条 → 第二条地址的断言红；拆掉声明标记 → 标记断言红', async () => {
  const own = {
    listenPort: PORT,
    addresses: [{ ip: IP_A, url: 'http://' + IP_A + ':' + PORT }, { ip: IP_B, url: 'http://' + IP_B + ':' + PORT }],
    advertise: { url: 'http://' + IP_A + ':' + PORT, source: 'auto' },
  };
  const SCRIPT = renderPanelScript('tok-own-p6', 'zh');
  const expected = t('zh', 'panel.peers.ownLine').replace('{addrs}',
    IP_A + ':' + PORT + t('zh', 'panel.peers.ownAdvertised') + ' · ' + IP_B + ':' + PORT);
  assert.equal(await openAndRead(own).then((app) => app.text('dshLpOwnAddr')), expected, '先确认原版是对的');

  // 变异 1：只留第一条地址（「几条地址塌成一条」）
  const collapse = SCRIPT.replace("parts.join(' · ')", "parts.slice(0, 1).join(' · ')");
  assert.notEqual(collapse, SCRIPT, '变异必须真的落地');
  const collapsedText = await openWith(own, collapse);
  assert.equal(collapsedText.includes(IP_B + ':' + PORT), false, '塌成一条后第二条真的不见了');
  assert.throws(() => assert.equal(collapsedText, expected), 'P2 的第二条断言在这个变异下必须红');

  // 变异 2：拆掉「对外声明」标记
  const dropMark = SCRIPT.replace("(isAdv ? LT('panel.peers.ownAdvertised') : '')", "''");
  assert.notEqual(dropMark, SCRIPT, '变异必须真的落地');
  const unmarked = await openWith(own, dropMark);
  assert.equal(unmarked.includes(t('zh', 'panel.peers.ownAdvertised')), false, '标记真的被拆掉了');
  assert.throws(() => assert.equal(unmarked.includes(IP_A + ':' + PORT + t('zh', 'panel.peers.ownAdvertised')), true),
    'P2 的声明标记断言在这个变异下必须红');
});
