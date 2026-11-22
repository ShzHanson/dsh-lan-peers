// dsh-lan-peers · 0.13.0-α 危险区：三条管理路由 + 面板那一行 + 对端的签名通知端点。
//
// 断言（X1–X4 / X9 / Y3 / Y4 路由面 + X10 非空性）：
//   1. reset-request 必须收到**一字不差**的 {confirm:'RESET'}：小写、尾随空格、缺字段都 400 confirm-required，且一个文件都不写；
//   2. 成功时先落备份目录再落标记，GET identity 随后报 resetPending:true 与备份目录名（没有路径、没有密钥）；
//   3. 已排定再排 → 409 already-pending，备份不重复；cancel 删标记、幂等；
//   4. 面板那一行：按钮在输入 RESET 之前是禁用的，点击只发 {confirm:'RESET'}，400 落成一条稳定文案，
//      已排定时显示「已排定重置：重启后生效」+ 取消按钮；
//   5. 对端的 POST /v1/peer/reset-notice：未签名/错钥 401（与 unpair 同门）、删掉发送方、
//      hub 且对方在成员表里 → 走既有移除路径（轮换群密钥）并回 group:'cleared'。
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import { PANEL_SCRIPT, createAdmin } from './admin.mjs';
import { IDENTITY_BACKUP_FILES, IDENTITY_BACKUP_PREFIX, IDENTITY_MARKER_FILE, applyPendingIdentityReset, readIdentityState } from './identity.mjs';
import { makeTempStateDir, peerFixture, request, seedPeers, startServer, writeJson0600 } from '../host/test/helpers.mjs';

const OLD_ID = '11111111-2222-3333-4444-555555555555';
const OLD_TOKEN = 'cd'.repeat(32);
const MEMBER = peerFixture('peer-member-1');
const OTHER = peerFixture('peer-member-2');

function write(file, content) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, content, { mode: 0o600 });
}

/** 一个像真机那样的 stateDir（身份文件 + 一份数据文件，验证「数据不是身份」）。 */
function makeStateDir(t) {
  const stateDir = makeTempStateDir('dsh-lp-identity-admin-');
  t.after(() => fs.rmSync(stateDir, { recursive: true, force: true }));
  write(path.join(stateDir, 'state.json'), JSON.stringify({ instanceId: OLD_ID, name: 'me', createdAt: '2026-01-01T00:00:00.000Z' }, null, 2) + '\n');
  write(path.join(stateDir, 'peers.json'), JSON.stringify({ peers: {} }, null, 2) + '\n');
  write(path.join(stateDir, 'admin-token'), OLD_TOKEN + '\n');
  write(path.join(stateDir, 'group-key.json'), '{"groupKey":"k-old"}\n');
  write(path.join(stateDir, 'group-role.json'), '{"role":"member"}\n');
  write(path.join(stateDir, 'group-digests.json'), '{"digests":[]}\n');
  return stateDir;
}

const listBackups = (stateDir) => fs.readdirSync(stateDir).filter((n) => n.startsWith(IDENTITY_BACKUP_PREFIX)).sort();

// ---- 管理接口的最小真实骨架（与 admin-surface.test.mjs 同款） --------------

function makeResponse() {
  return {
    status: 0, headers: {}, body: '',
    writeHead(status, headers) { this.status = status; Object.assign(this.headers, headers || {}); },
    setHeader(k, v) { this.headers[k] = v; },
    write(chunk) { this.body += chunk; return true; },
    end(chunk) { if (chunk) this.body += chunk; if (!this.status) this.status = 200; },
    once() {}, on() {},
  };
}

function makeReq({ method = 'GET', url, headers = {}, body } = {}) {
  const chunks = body === undefined ? [] : [Buffer.from(body)];
  const req = {
    method, url,
    socket: { remoteAddress: '127.0.0.1', setNoDelay() {} },
    headers: { host: '127.0.0.1:7788', ...headers, 'content-length': String(chunks[0]?.length ?? 0) },
    on() { return req; }, once() { return req; },
    async *[Symbol.asyncIterator]() { for (const chunk of chunks) yield chunk; },
  };
  return req;
}

function bootAdmin({ stateDir }) {
  const logged = [];
  const store = {
    instanceId: OLD_ID,
    stateDir,
    state: { instanceId: OLD_ID, name: 'me', createdAt: '2026-01-01T00:00:00.000Z' },
    listPeers: () => [],
    getPeer: () => null,
  };
  const admin = createAdmin({
    server: { config: { logger: (line) => logged.push(String(line)) }, store },
    nameOf: () => 'me',
    rename: (n) => n,
    feed: null,
    pairing: { mode: 'auto' },
  });
  return { admin, logged, token: admin.token };
}

async function hit(admin, options) {
  const res = makeResponse();
  const req = makeReq(options);
  const handled = await admin.handle(req, res, new URL('http://127.0.0.1' + req.url));
  let json = null;
  try { json = JSON.parse(res.body); } catch { json = null; }
  return { handled, status: res.status, json, raw: res.body };
}

const post = (admin, route, body) => hit(admin, {
  method: 'POST',
  url: '/api/lan-peers/' + route,
  headers: { 'x-lan-peers-token': admin.token, 'content-type': 'application/json' },
  body: body === undefined ? undefined : JSON.stringify(body),
});

test('X1 arm：备份目录装齐当时存在的身份文件，GET identity 随后报 resetPending:true + 备份名', async (t) => {
  const stateDir = makeStateDir(t);
  const { admin } = bootAdmin({ stateDir });
  const armed = await post(admin, 'identity/reset-request', { confirm: 'RESET' });
  assert.equal(armed.status, 200, armed.raw);
  assert.equal(armed.json.ok, true);
  assert.equal(armed.json.effectiveAfter, 'restart');
  assert.match(armed.json.backup, new RegExp('^' + IDENTITY_BACKUP_PREFIX + '[0-9]{8}T[0-9]{6}Z$'));

  const backupDir = path.join(stateDir, armed.json.backup);
  assert.equal(fs.statSync(backupDir).isDirectory(), true);
  for (const name of IDENTITY_BACKUP_FILES) {
    assert.equal(fs.existsSync(path.join(backupDir, name)), true, '备份里必须有：' + name);
    assert.equal(fs.readFileSync(path.join(backupDir, name), 'utf8'), fs.readFileSync(path.join(stateDir, name), 'utf8'));
  }
  assert.ok(fs.existsSync(path.join(stateDir, IDENTITY_MARKER_FILE)), '标记必须落盘');
  assert.equal(fs.readFileSync(path.join(backupDir, README_NAME), 'utf8').length > 0, true);
  assert.equal(fs.existsSync(path.join(backupDir, 'group-digests.json')), false, '数据文件不进身份备份');

  const view = await hit(admin, { url: '/api/lan-peers/identity', headers: { 'x-lan-peers-token': admin.token } });
  assert.equal(view.status, 200, view.raw);
  assert.equal(view.json.resetPending, true);
  assert.equal(view.json.lastBackup, armed.json.backup);
  assert.equal(view.json.instanceIdShort, OLD_ID.slice(0, 8));
  assert.equal(view.json.hasGroup, true);
  assert.equal(view.json.lastResetNotified, null);
  // 只给目录名：响应体里绝不出现 stateDir 绝对路径，也没有任何密钥字段。
  assert.equal(view.raw.includes(stateDir), false, 'GET identity 不许回路径');
  for (const secret of ['k-old', OLD_TOKEN, OLD_ID]) assert.equal(view.raw.includes(secret), false, '不回密钥/旧 id');
});

const README_NAME = 'README.txt';

test('X2 confirm 闸：小写 / 尾随空格 / 缺字段一律 400 confirm-required，一个文件都不写', async (t) => {
  const stateDir = makeStateDir(t);
  const { admin } = bootAdmin({ stateDir });
  const bad = [{ confirm: 'reset' }, { confirm: 'RESET ' }, {}, { confirm: 'RESET!' }, { confirm: ['RESET'] }];
  for (const body of bad) {
    const out = await post(admin, 'identity/reset-request', body);
    assert.equal(out.status, 400, JSON.stringify(body));
    assert.equal(out.json.error, 'confirm-required');
  }
  assert.equal(fs.existsSync(path.join(stateDir, IDENTITY_MARKER_FILE)), false, '被拒的请求不许落标记');
  assert.deepEqual(listBackups(stateDir), [], '被拒的请求更不许造备份');
  const view = readIdentityState({ stateDir });
  assert.equal(view.resetPending, false);
  assert.equal(view.lastBackup, '');
});

test('X3 已排定 → 409 already-pending，备份不重复', async (t) => {
  const stateDir = makeStateDir(t);
  const { admin } = bootAdmin({ stateDir });
  const first = await post(admin, 'identity/reset-request', { confirm: 'RESET' });
  assert.equal(first.status, 200);
  const again = await post(admin, 'identity/reset-request', { confirm: 'RESET' });
  assert.equal(again.status, 409);
  assert.equal(again.json.error, 'already-pending');
  assert.deepEqual(listBackups(stateDir), [first.json.backup], '第二次不许再备份一份');
});

test('X4 cancel 删标记、GET identity 回到 resetPending:false，第二次 cancel 仍 200（no-op）', async (t) => {
  const stateDir = makeStateDir(t);
  const { admin } = bootAdmin({ stateDir });
  await post(admin, 'identity/reset-request', { confirm: 'RESET' });
  const canceled = await post(admin, 'identity/reset-cancel', {});
  assert.equal(canceled.status, 200);
  assert.deepEqual(canceled.json, { ok: true });
  assert.equal(fs.existsSync(path.join(stateDir, IDENTITY_MARKER_FILE)), false);
  const view = await hit(admin, { url: '/api/lan-peers/identity', headers: { 'x-lan-peers-token': admin.token } });
  assert.equal(view.json.resetPending, false);
  const twice = await post(admin, 'identity/reset-cancel', {});
  assert.equal(twice.status, 200, '第二次也是 200（就是一次 no-op）');
  assert.deepEqual(listBackups(stateDir).length, 1);
});

test('Y4 路由面：重置执行完之后 GET identity 报 lastResetNotified', async (t) => {
  const stateDir = makeStateDir(t);
  const { admin } = bootAdmin({ stateDir });
  seedPeers(stateDir, []) ;
  await post(admin, 'identity/reset-request', { confirm: 'RESET' });
  const applied = await applyPendingIdentityReset({
    stateDir,
    notify: async (peer) => { if (peer.peerId === 'x') throw new Error('nope'); },
  });
  assert.equal(applied.applied, true);
  const view = await hit(admin, { url: '/api/lan-peers/identity', headers: { 'x-lan-peers-token': admin.token } });
  assert.equal(view.status, 200, view.raw);
  assert.deepEqual(view.json.lastResetNotified, { notified: 0, failed: 0 });
  assert.equal(view.json.resetPending, false);
  assert.equal(view.json.lastBackup, applied.backup, '备份名字仍然报得出来');
});

// ---- 面板那一行（X9） ------------------------------------------------------

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
    removeEventListener() {}, setPointerCapture() {}, releasePointerCapture() {},
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

function bootPanel({ identity = { resetPending: false, lastBackup: '', lastResetNotified: null }, resetReply = { status: 200, body: { ok: true, backup: 'identity-backup-20260101T000000Z', effectiveAfter: 'restart' } } } = {}) {
  const created = [];
  const calls = [];
  const timers = [];
  let confirmAnswer = true;
  const document = {
    head: makeElement('head'), body: makeElement('body'), hidden: false,
    createElement: (tag) => { const el = makeElement(tag); created.push(el); return el; },
  };
  const json = (body, status = 200) => ({ ok: status >= 200 && status < 300, status, json: async () => body });
  const fetchStub = async (url, init) => {
    const route = String(url).replace('/api/lan-peers/', '');
    const body = init && init.body ? JSON.parse(init.body) : null;
    calls.push({ route, method: (init && init.method) || 'GET', body });
    if (route === 'state') return json({ name: 'me', instanceId: OLD_ID, peers: [], pairing: null });
    if (route === 'dispatch') return json({ dispatches: [] });
    if (route === 'client-log') return json({ ok: true });
    if (route === 'lang') return json({ lang: 'zh', effective: 'zh' });
    if (route === 'dispatch/settings') return json({ defaultWorkspaceId: 'main', maxPermission: 'workspace-write', workspaces: [] });
    if (route === 'dispatch/pending') return json({ items: [] });
    if (route === 'identity') return json(identity);
    if (route === 'identity/reset-request') return json(resetReply.body, resetReply.status);
    if (route === 'identity/reset-cancel') return json({ ok: true });
    return json({});
  };
  const window = {
    innerWidth: VIEW.w, innerHeight: VIEW.h, addEventListener() {},
    confirm: () => confirmAnswer,
    localStorage: { getItem: () => null, setItem: () => {} },
  };
  vm.runInNewContext(PANEL_SCRIPT, {
    window, document, localStorage: window.localStorage, fetch: fetchStub,
    setInterval: (fn, ms) => { timers.push({ fn, ms }); return timers.length; },
    clearInterval: () => {}, setTimeout: () => 0, clearTimeout: () => {},
    JSON, Math, console,
  });
  const byId = (id) => created.find((el) => el.id === id);
  return {
    document, calls, timers, byId,
    setConfirm: (value) => { confirmAnswer = value; },
    panel: document.body.children.find((el) => el.id === 'dshLpPanel'),
    btn: document.body.children.find((el) => el.id === 'dshLpBtn'),
  };
}

async function openSettings(options) {
  const app = bootPanel(options);
  app.btn.onclick();
  await flush();
  app.panel.querySelector('#dshLpTabSettings').onclick();
  await flush();
  return {
    ...app,
    input: app.byId('dshLpSetDangerInput'),
    arm: app.byId('dshLpSetDangerBtn'),
    stateBox: app.byId('dshLpSetDangerState'),
    head: app.byId('dshLpSetDangerHead'),
    explain: app.byId('dshLpSetDangerExplain'),
    restartNote: app.byId('dshLpSetDangerRestart'),
    msgBox: app.panel.querySelector('#dshLpMsg'),
  };
}

test('X9 面板：说明 + 输入框 + 禁用按钮；输入 RESET 才解禁，点击只发 {confirm:\'RESET\'}', async () => {
  const app = await openSettings();
  assert.equal(app.head.textContent, '危险区');
  assert.match(app.explain.textContent, /会失去/);
  assert.match(app.explain.textContent, /会保留/, '必须说清什么会留下');
  assert.match(app.restartNote.textContent, /重启后生效/);
  assert.match(app.restartNote.textContent, /通知每个伙伴/, '必须说明重启时会通知伙伴');
  assert.equal(app.arm.disabled, true, '没输入 RESET 之前按钮是禁用的');

  app.input.value = 'RESE';
  app.input.oninput();
  assert.equal(app.arm.disabled, true);
  app.input.value = 'RESET ';
  app.input.oninput();
  assert.equal(app.arm.disabled, true, '带空格也不解禁（与路由口径一字不差）');
  app.input.value = 'RESET';
  app.input.oninput();
  assert.equal(app.arm.disabled, false);

  app.arm.onclick();
  await flush();
  const posts = app.calls.filter((one) => one.route === 'identity/reset-request');
  assert.equal(posts.length, 1);
  assert.equal(posts[0].method, 'POST');
  assert.deepEqual(posts[0].body, { confirm: 'RESET' }, '面板只发这一个字段');

  assert.equal(app.stateBox.children.length, 2, '成功后要有「已排定」一行 + 取消按钮');
  assert.equal(app.stateBox.children[0].textContent, '已排定重置：重启后生效');
  assert.equal(app.stateBox.children[1].textContent, '取消');
  assert.equal(app.input.disabled, true, '已排定时不再让人接着敲');
});

test('X9b 面板：window.confirm 被取消就一个请求都不发', async () => {
  const app = await openSettings();
  app.setConfirm(false);
  app.input.value = 'RESET';
  app.input.oninput();
  app.arm.onclick();
  await flush();
  assert.equal(app.calls.filter((one) => one.route === 'identity/reset-request').length, 0);
});

test('X9c 面板：400 落成一条稳定文案（不是服务端原文）', async () => {
  const app = await openSettings({ resetReply: { status: 400, body: { error: 'confirm-required', detail: 'server-side text' } } });
  app.input.value = 'RESET';
  app.input.oninput();
  app.arm.onclick();
  await flush();
  assert.equal(app.msgBox.textContent, '未确认：需要原样输入 RESET（confirm-required）');
});

test('X9d 面板：已排定时直接显示「已排定重置：重启后生效」+ 取消按钮；点取消走 reset-cancel', async () => {
  const app = await openSettings({ identity: { resetPending: true, lastBackup: 'identity-backup-20260101T000000Z', resetAt: '2026-01-01T00:00:00.000Z' } });
  assert.equal(app.stateBox.children[0].textContent, '已排定重置：重启后生效');
  const cancel = app.stateBox.children[1];
  assert.equal(cancel.textContent, '取消');
  cancel.onclick();
  await flush();
  const posts = app.calls.filter((one) => one.route === 'identity/reset-cancel');
  assert.equal(posts.length, 1);
  assert.equal(posts[0].method, 'POST');
  assert.equal(app.msgBox.textContent, '已取消重置排定');
});

// ---- 对端：POST /v1/peer/reset-notice（Y3） --------------------------------

test('Y3 对端：未签名/错钥 → 401（与 unpair 同门）；GET → 405', async (t) => {
  const stateDir = makeTempStateDir('dsh-lp-identity-notice-');
  seedPeers(stateDir, [MEMBER]);
  const { baseUrl } = await startServer(t, { stateDir });
  const unsigned = await request(baseUrl, { method: 'POST', path: '/v1/peer/reset-notice', signed: false, body: { resetAt: 'x' } });
  assert.equal(unsigned.status, 401);
  assert.equal(unsigned.json.error, 'bad-signature');
  const wrongKey = await request(baseUrl, {
    method: 'POST', path: '/v1/peer/reset-notice', peerId: MEMBER.peerId, secret: 'not-the-secret', body: { resetAt: 'x' },
  });
  assert.equal(wrongKey.status, 401);
  assert.equal(wrongKey.json.error, 'bad-signature');
  assert.equal(fs.readFileSync(path.join(stateDir, 'peers.json'), 'utf8').includes(MEMBER.peerId), true, '认证失败绝不能删条目');
  const wrongMethod = await request(baseUrl, { path: '/v1/peer/reset-notice', peerId: MEMBER.peerId, secret: MEMBER.inboundSecret });
  assert.equal(wrongMethod.status, 405);
});

test('Y3 对端（hub）：合法通知删掉发送方、走既有成员移除路径（轮换群密钥）、回 group:cleared', async (t) => {
  const stateDir = makeTempStateDir('dsh-lp-identity-hub-');
  seedPeers(stateDir, [MEMBER, OTHER]);
  const logs = [];
  const hub = await startServer(t, {
    stateDir,
    allowRemotePrompts: true,
    logger: (line) => logs.push(String(line)),
    group: { enabled: true, name: 'default', autoJoin: false, retentionDays: 7, quorum: 'none' },
  });
  assert.ok(hub.server.group.addMember(MEMBER.peerId, MEMBER.name), '先把这个 peer 放进成员表');
  const keyVersionBefore = hub.server.group.state({ includeKey: true }).keyVersion;

  const notice = await request(hub.baseUrl, {
    method: 'POST',
    path: '/v1/peer/reset-notice',
    peerId: MEMBER.peerId,
    secret: MEMBER.inboundSecret,
    body: { resetAt: '2026-01-02T03:04:05.000Z', reason: 'panel-armed' },
  });
  assert.equal(notice.status, 200, notice.text);
  assert.deepEqual(notice.json, { ok: true, removed: true, group: 'cleared' });

  const onDisk = JSON.parse(fs.readFileSync(path.join(stateDir, 'peers.json'), 'utf8'));
  assert.equal(Object.prototype.hasOwnProperty.call(onDisk.peers, MEMBER.peerId), false, '发送方必须从 peers.json 消失');
  assert.ok(onDisk.peers[OTHER.peerId], '别的伙伴不许被牵连');
  const members = hub.server.group.state().members;
  assert.equal(Object.prototype.hasOwnProperty.call(members, MEMBER.peerId), false, 'hub 的成员表里也要没它');
  const keyVersionAfter = hub.server.group.state({ includeKey: true }).keyVersion;
  assert.ok(keyVersionAfter > keyVersionBefore, '移除成员必须轮换群密钥（既有路径）');
  const line = logs.find((one) => one.startsWith('[peer] reset-notice'));
  assert.equal(line, '[peer] reset-notice from=' + MEMBER.peerId.slice(0, 8) + ' removed=1');

  // 再说一次：这个 peerId 已经不在 peers.json 里 → 401 unknown-peer（与 unpair 一致）
  const again = await request(hub.baseUrl, {
    method: 'POST', path: '/v1/peer/reset-notice', peerId: MEMBER.peerId, secret: MEMBER.inboundSecret, body: {},
  });
  assert.equal(again.status, 401);
  assert.equal(again.json.error, 'unknown-peer');
});

test('Y3 对端：不是 hub → group:not-hub；是 hub 但对方不在成员表 → group:not-member', async (t) => {
  const plainDir = makeTempStateDir('dsh-lp-identity-plain-');
  seedPeers(plainDir, [MEMBER]);
  const plain = await startServer(t, { stateDir: plainDir, logger: () => {} });
  const plainNotice = await request(plain.baseUrl, {
    method: 'POST', path: '/v1/peer/reset-notice', peerId: MEMBER.peerId, secret: MEMBER.inboundSecret, body: {},
  });
  assert.equal(plainNotice.status, 200, plainNotice.text);
  assert.deepEqual(plainNotice.json, { ok: true, removed: true, group: 'not-hub' });

  const hubDir = makeTempStateDir('dsh-lp-identity-hub2-');
  seedPeers(hubDir, [MEMBER]);
  const hub = await startServer(t, {
    stateDir: hubDir,
    allowRemotePrompts: true,
    logger: () => {},
    group: { enabled: true, name: 'default', autoJoin: false, retentionDays: 7, quorum: 'none' },
  });
  const notMember = await request(hub.baseUrl, {
    method: 'POST', path: '/v1/peer/reset-notice', peerId: MEMBER.peerId, secret: MEMBER.inboundSecret, body: {},
  });
  assert.equal(notMember.status, 200, notMember.text);
  assert.deepEqual(notMember.json, { ok: true, removed: true, group: 'not-member' });
});

// ---- X10 非空性 -----------------------------------------------------------

test('X10 非空性：点明「删掉哪一处、哪条断言会红」，并对源码做同一条检查', () => {
  // ① 删掉 confirm 闸（lib/admin.mjs 的 identity/reset-request 里那行）→
  //    X2 的 assert.equal(out.status, 400)（小写 'reset' 那一档）立刻变 200，红。
  // ② 删掉备份（lib/identity.mjs armIdentityReset 里的复制循环）→
  //    X1 的 assert.equal(fs.existsSync(path.join(backupDir, name)), true) 立刻红。
  // ③ 通知挪到重生之后（Y1）→ seen[*].live === OLD_ID 那一条红。
  // ④ 通知失败改成抛出去（Y2）→ out.applied === true 那条红。
  const adminSrc = fs.readFileSync(new URL('./admin.mjs', import.meta.url), 'utf8');
  const identitySrc = fs.readFileSync(new URL('./identity.mjs', import.meta.url), 'utf8');
  assert.ok(adminSrc.includes("if (confirm !== 'RESET')"), 'confirm 闸必须在源码里（一字不差）');
  assert.ok(adminSrc.includes("typeof body.confirm === 'string'"), '闸必须卡类型（数组 String 化后也等于 RESET）');
  assert.ok(identitySrc.includes('fs.writeFileSync(target, bytes'), '备份必须是逐字节复制');
  assert.ok(identitySrc.includes('IDENTITY_BACKUP_FILES'), '备份清单只有一份');
  assert.ok(identitySrc.includes('[identity] reset-notice failed peer='), '通知失败的日志口径在源码里');
  const applyIndex = identitySrc.indexOf('await notify(peer, notice)');
  const regenIndex = identitySrc.indexOf('nextState.instanceId = randomUUID()');
  assert.ok(applyIndex > 0 && regenIndex > applyIndex, '源码顺序：先通知、后重生');
});
