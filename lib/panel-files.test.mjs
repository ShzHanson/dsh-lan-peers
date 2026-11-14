// dsh-lan-peers · 0.12.0-alpha S3：面板这一侧的「文件面」（offer / 按需下载 / 群文件）
//
// 服务端在 S1/S2 已经把模型换掉了：文件不再「推过去等批准」，而是**挂一份 metadata 当邀约**，
// 收到的人按需去持有者那边逐块拉。这一份钉住面板跟着换过来的那一半：
//   P1 三张列表（offers / inbox / incoming）与空态；
//   P2 下载 / 拒绝两条写路由 + gone 行没有下载按钮；
//   P3 下载前的确认门：未信任先问、继续才发请求、勾了信任会写 files/trust；
//   P4 群发目标（全体 = 'all'，成员 = 它的 uuid）与群列的 gone/downloaded；
//   P5 进度轮询用 offer 的 fileId，前进的是既有节拍上的进度条，不开第二个节拍；
//   P6 513 MiB 从私聊附件选也不发 init，提示里点名 CLI 与 agent 工具；
//   P7 铁律（新增段零反引号 / 无 console.error / innerHTML 只赋空串 / 节拍与隐藏门不变）；
//   P8 新文案 zh + en 两格齐备、en 无中日韩字；
//   P9 非空化：拆掉确认门 / 拆掉 gone 守卫各有一条断言真的会红（脚本级变异，跑完还原）。
//
// 隐私口径：面板文本里不出现本机绝对路径 —— 这一份的断言里也没有任何真实路径。
import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { PANEL_SCRIPT, renderPanelScript } from './admin.mjs';
import { keys, t } from './i18n.mjs';

const VIEW = { w: 1000, h: 800 };
const PEER = { peerId: 'peer-b-1234', name: '书房', baseUrl: 'http://10.0.0.2:7788', lastSeen: 0 };
const PEER_ID = PEER.peerId;
const OTHER = { peerId: 'peer-c-5678', name: '客厅', baseUrl: 'http://10.0.0.3:7788', lastSeen: 0 };
const MIB = 1024 * 1024;
const AT = 1_760_000_000_000;

function makeElement(tag, widthLog) {
  const cache = new Map();
  const style = {};
  Object.defineProperty(style, 'width', {
    get: () => style.__w || '',
    set: (value) => { style.__w = value; if (widthLog) widthLog.push(String(value)); },
  });
  const el = {
    tagName: String(tag).toUpperCase(),
    id: '', className: '', textContent: '', value: '', placeholder: '', maxLength: 0,
    style, disabled: false, selected: false, checked: false, children: [], listeners: new Map(), files: null,
    offsetWidth: 96, offsetHeight: 36, onclick: null, clicks: 0,
    appendChild(child) { this.children.push(child); return child; },
    // 真 DOM 里 input.click() 会去戳系统选择器；桩这一层只数「被点了几下」
    click() { this.clicks += 1; },
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
      if (!cache.has(id)) cache.set(id, makeElement('div', widthLog));
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

const flush = async (rounds = 60) => {
  for (let i = 0; i < rounds; i += 1) await new Promise((resolve) => setTimeout(resolve, 1));
};

/** 假 File：只实现面板真正用到的两格（size / slice().arrayBuffer()）。 */
function makeFile(name, size, content = null) {
  return {
    name,
    size,
    slice(start, end) {
      if (content === null) return { size: 0, arrayBuffer: async () => new Uint8Array(0) };
      const part = content.subarray(start, end);
      return { size: part.length, arrayBuffer: async () => part };
    },
  };
}

const emptyFiles = () => ({ offers: [], inbox: [], incoming: [] });

/** S1 的三桶 fixture：两条邀约（一条已信任、一条没信任）+ 一条已收到 + 一条传输中 */
function fixtureFiles() {
  return {
    offers: [
      {
        id: 'offer-1', name: '合同.pdf', size: 4096, sha256: 'a'.repeat(64),
        from: { peerId: PEER_ID, name: '书房' }, at: AT + 1000, trusted: false, state: 'offer',
      },
      {
        id: 'offer-2', name: '旧合同.pdf', size: 2048, sha256: 'b'.repeat(64),
        from: { peerId: PEER_ID, name: '书房' }, at: AT, trusted: true, state: 'offer',
      },
    ],
    inbox: [{
      id: 'done-1', name: '照片.jpg', size: 3000, sha256: 'c'.repeat(64),
      from: { peerId: PEER_ID, name: '书房' }, at: AT, trusted: true, state: 'done',
    }],
    incoming: [{
      id: 'in-1', name: 'big.bin', size: 8192, received: 4096,
      from: { peerId: PEER_ID, name: '书房' }, at: AT, state: 'incoming',
    }],
  };
}

/** GET group 的 fixture：S3 把 groupFiles 搭在这次响应里下发（没有第二条请求） */
function fixtureGroup() {
  return {
    enabled: true,
    isHub: false,
    selfRole: 'member',
    enabledSource: 'config',
    group: {
      groupId: 'g-1',
      name: '家里',
      members: [
        { peerId: PEER_ID, name: '书房' },
        { peerId: OTHER.peerId, name: '客厅' },
      ],
    },
    messages: [],
    lastSeq: 0,
    leader: null,
    replica: null,
    advertiseBaseUrl: '',
    selfBaseUrl: '',
    groupFiles: {
      rev: 3,
      files: [
        {
          fileId: 'gf-1', name: '群文件.zip', size: 5120, sha256: 'd'.repeat(64),
          from: { peerId: PEER_ID, name: '书房' }, targets: 'all', at: AT + 2000,
          gone: false, downloaded: false, mine: false,
        },
        {
          fileId: 'gf-2', name: '过期.log', size: 100, sha256: 'e'.repeat(64),
          from: { peerId: OTHER.peerId, name: '客厅' }, targets: 'all', at: AT,
          gone: true, downloaded: false, mine: false,
        },
        {
          fileId: 'gf-3', name: '已下.bin', size: 64, sha256: 'f'.repeat(64),
          from: { peerId: PEER_ID, name: '书房' }, targets: 'all', at: AT - 1000,
          gone: false, downloaded: true, mine: true,
        },
      ],
    },
  };
}

function boot({
  files = emptyFiles(),
  peers = [PEER, OTHER],
  fileMaxBytes = 0,
  chunkBytes = 4,
  failChunkAt = 0,
  chunkMode = 'increment',
  initMaxBytes = 1_000_000,
  group = fixtureGroup(),
  hangDownload = false,
  withdrawMode = 'ok',
  progress = [[250, 1000, 'incoming'], [700, 1000, 'incoming']],
  script = PANEL_SCRIPT,
} = {}) {
  const calls = [];
  const timers = [];
  const widths = [];
  const created = [];
  const state = { files, group, serverReceived: 0, lastInitBytes: 0, progressAt: 0 };
  const document = {
    head: makeElement('head', widths),
    body: makeElement('body', widths),
    hidden: false,
    createElement: (tag) => { const el = makeElement(tag, widths); created.push(el); return el; },
  };
  const json = (body, status = 200) => ({ ok: status >= 200 && status < 300, status, json: async () => body });
  let chunkCalls = 0;
  const fetchStub = async (url, init) => {
    const path = String(url).replace('/api/lan-peers/', '');
    const method = (init && init.method) || 'GET';
    const body = init && init.body ? JSON.parse(init.body) : null;
    calls.push({ path, method, body });
    if (path === 'state') {
      return json({ name: 'me', instanceId: 'me-id', peers, pairing: null, fileMaxBytes });
    }
    if (path === 'dispatch') return json({ dispatches: [] });
    if (path === 'dispatch/pending') return json({ items: [] });
    if (path === 'client-log') return json({ ok: true });
    if (path === 'lang') return json({ lang: 'auto' });
    if (path === 'files') return json(state.files);
    if (path === 'files/download') {
      if (hangDownload) return new Promise(() => {});
      return json({ ok: true, id: 'done-x', bytes: 4096, sha256: 'a'.repeat(64), ms: 2 });
    }
    if (path === 'files/decline') return json({ ok: true, fileId: body.fileId });
    if (path === 'files/withdraw') {
      // 撤回的三种答复：真服务端只在「对端确认过」之后才删本机那份，所以 GET files 的下一次
      // 响应里那一行本来就没了 —— 这里照着它删（不是面板自己把行抹掉）。
      if (withdrawMode === 'offline') return json({ error: 'peer-offline' }, 503);
      state.files = {
        ...state.files,
        outbox: (state.files.outbox || []).filter((row) => row.fileId !== body.fileId),
      };
      if (withdrawMode === 'unknown') return json({ error: 'unknown-file' }, 404);
      return json({ ok: true, fileId: body.fileId, removed: true, remote: 'ok' });
    }
    if (path === 'files/trust') return json({ ok: true, peerId: body.peerId, trusted: body.trusted === true });
    if (path.startsWith('files/progress?id=')) {
      const at = Math.min(state.progressAt, progress.length - 1);
      const row = progress[at];
      state.progressAt += 1;
      return json({ received: row[0], size: row[1], state: row[2] });
    }
    if (path === 'files/upload/init') {
      state.lastInitBytes = Number(body.bytes) || 0;
      return json({ uploadId: 'u-1', chunkBytes, maxBytes: initMaxBytes });
    }
    if (path === 'files/upload/chunk') {
      chunkCalls += 1;
      const landed = Buffer.from(String(body.dataBase64 || ''), 'base64').length;
      if (chunkMode === 'complete') {
        state.serverReceived = state.lastInitBytes;
        return json({ uploadId: body.uploadId, received: state.lastInitBytes, bytes: state.lastInitBytes });
      }
      state.serverReceived += landed;
      if (failChunkAt > 0 && chunkCalls === failChunkAt) {
        return json({ error: 'offset-mismatch', received: state.serverReceived }, 409);
      }
      return json({ uploadId: body.uploadId, received: state.serverReceived, bytes: state.lastInitBytes });
    }
    if (path === 'files/upload/finish') {
      return json({ ok: true, fileId: 'offer-new', bytes: state.lastInitBytes, sha256: 'a'.repeat(64), uploadId: body.uploadId });
    }
    if (path === 'files/upload/cancel') return json({ ok: true, removed: true });
    if (path.startsWith('files/upload?id=')) {
      return json({
        uploadId: path.slice('files/upload?id='.length),
        name: 'blip.bin',
        bytes: state.lastInitBytes,
        received: state.serverReceived,
        chunkBytes,
      });
    }
    if (path === 'files/send') return json({ ok: true, fileId: 'offer-via-path', bytes: 4096, sha256: 'b'.repeat(64), offer: 'sent' });
    if (path === 'group/files/send') {
      return json({ ok: true, fileId: 'gf-new', bytes: 4096, sha256: 'c'.repeat(64), targets: body.peerId, rev: 4 });
    }
    if (path === 'group/files/download') return json({ ok: true, fileId: body.fileId, bytes: 5120, sha256: 'd'.repeat(64) });
    if (path === 'group/files/withdraw') return json({ ok: true, fileId: body.fileId, removed: true, gone: true });
    if (path.startsWith('group?')) return json(state.group);
    if (path.startsWith('dm?peer=')) return json({ peer: { peerId: PEER_ID, name: '书房' }, messages: [] });
    if (path === 'dm/sync') return json({ added: 0, total: 0 });
    if (path === 'dm/send') return json({ id: 'm-1', state: 'sent', reply: '' });
    return json({});
  };
  const window = {
    innerWidth: VIEW.w, innerHeight: VIEW.h, addEventListener() {}, confirm: () => true,
    localStorage: { getItem: () => null, setItem: () => {} },
  };
  vm.runInNewContext(script, {
    window, document, localStorage: window.localStorage, fetch: fetchStub,
    setInterval: (fn, ms) => { timers.push({ fn, ms }); return timers.length; },
    clearInterval: () => {},
    setTimeout: () => 0,
    clearTimeout: () => {},
    JSON, Math, console,
  });
  const btn = document.body.children.find((el) => el.id === 'dshLpBtn');
  const panel = document.body.children.find((el) => el.id === 'dshLpPanel');
  const q = (id) => panel.querySelector('#' + id);
  const byId = (id) => created.find((el) => el.id === id);
  const callsTo = (path) => calls.filter((call) => call.path === path);
  return { btn, panel, q, byId, calls, callsTo, timers, widths, state, document, created, window };
}

async function openPanel(options) {
  const app = boot(options);
  app.btn.onclick();
  await flush();
  return app;
}

/** 走一次既有的 1s 节拍（jobs + files 两枚都在 1000ms 上） */
async function beat(app, ms = 1000) {
  for (const timer of app.timers.filter((one) => one.ms === ms)) timer.fn();
  await flush();
}

/** 点开某个页签并等它自己那一趟请求落地 */
async function openTab(app, which) {
  app.q('dshLpTab' + which).onclick();
  await flush();
  return app;
}

const labels = (el) => el.children.map((child) => child.textContent);
const findRow = (box, name) => box.children.find((row) => row.children[0] && row.children[0].textContent === name);
function clickText(row, label) {
  const button = row.children.find((child) => child.textContent === label);
  assert.ok(button, label + ' 这一格必须存在（行内按钮）');
  button.onclick();
  return button;
}

/** 私聊附件输入（按钮自己挂在 dmChat 上，所以只能按 id 找创建出来的那一枚） */
function pickDmFile(app, file) {
  const pick = app.byId('dshLpDmPick');
  assert.ok(pick, '私聊页必须有附件输入（dshLpDmPick）');
  pick.files = [file];
  const listener = pick.listeners.get('change')[0];
  assert.equal(typeof listener, 'function', '附件输入必须挂 change 监听');
  listener();
}

function pickFile(app, file) {
  const pick = app.q('dshLpFilesPick');
  pick.files = [file];
  const listener = pick.listeners.get('change')[0];
  assert.equal(typeof listener, 'function', '文件输入必须挂 change 监听：' + file.name);
  listener();
}

// ---------------------------------------------------------------------------
// P1：三张列表 + 空态
// ---------------------------------------------------------------------------
test('P1 三张列表按 {offers,inbox,incoming} 渲染，offer 带名字/体积/时间/来源', async () => {
  const app = await openPanel({ files: fixtureFiles() });

  assert.equal(app.q('dshLpFilesPendingHead').textContent,
    t('zh', 'panel.files.pendingHead').replace('{count}', '2'));
  assert.equal(app.q('dshLpFilesInboxHead').textContent,
    t('zh', 'panel.files.inboxHead').replace('{count}', '1'));
  assert.equal(app.q('dshLpFilesIncomingHead').textContent,
    t('zh', 'panel.files.incomingHead').replace('{count}', '1'));

  const offers = app.q('dshLpFilesPending');
  assert.equal(offers.children.length, 2, '两条邀约各一行');
  const newest = offers.children[0];
  assert.equal(newest.children[0].textContent, '合同.pdf', '最新的一条在上（at 大的先渲染）');
  assert.equal(newest.children[1].textContent, '4.0 KB', '只显示体积，不显示路径');
  assert.equal(newest.children[2].className, 'lpsender');
  assert.equal(newest.children[2].textContent, '书房', '来源显示对端洗过的名字');
  assert.equal(newest.children[3].className, 'lpfiletime', '第四格是相对时间');
  assert.equal(newest.children[4].textContent, t('zh', 'panel.files.download'));
  assert.equal(newest.children[5].textContent, t('zh', 'panel.files.decline'));
  assert.equal(offers.children[1].children[0].textContent, '旧合同.pdf');

  const inbox = app.q('dshLpFilesInbox');
  assert.equal(inbox.children.length, 1);
  assert.deepEqual(labels(inbox.children[0]).slice(0, 3), ['照片.jpg', '2.9 KB', '书房']);
  assert.equal(inbox.children[0].children[4].textContent, t('zh', 'panel.files.downloadedBadge'),
    '收件箱那一行是「已下载」，不是一枚下载按钮');
  assert.equal(labels(inbox.children[0]).includes(t('zh', 'panel.files.download')), false);

  const incoming = app.q('dshLpFilesIncoming');
  assert.equal(incoming.children.length, 1);
  assert.equal(incoming.children[0].children[0].textContent, t('zh', 'panel.files.incoming')
    .replace('{received}', '4.0 KB').replace('{size}', '8.0 KB').replace('{pct}', '50'));
  assert.equal(incoming.children[0].children[1].className, 'lpsender');
});

test('P1 空桶各自只渲染一行提示（不是一个空盒子）', async () => {
  const app = await openPanel({ files: emptyFiles() });
  for (const [id, key] of [
    ['dshLpFilesPending', 'panel.files.emptyPending'],
    ['dshLpFilesInbox', 'panel.files.emptyInbox'],
    ['dshLpFilesIncoming', 'panel.files.emptyIncoming'],
  ]) {
    const box = app.q(id);
    assert.equal(box.children.length, 1, id + ' 空态必须正好一行');
    assert.equal(box.children[0].className, 'hint');
    assert.equal(box.children[0].textContent, t('zh', key));
  }
  assert.equal(app.q('dshLpFilesPendingHead').textContent,
    t('zh', 'panel.files.pendingHead').replace('{count}', '0'));
});

// ---------------------------------------------------------------------------
// P2：下载 / 拒绝两条写路由；gone 行没有下载按钮
// ---------------------------------------------------------------------------
test('P2 下载 POST files/download{fileId}，拒绝 POST files/decline{fileId}，gone 行没有下载按钮', async () => {
  const files = fixtureFiles();
  files.offers.push({
    id: 'offer-gone', name: 'gone.bin', size: 10, sha256: '9'.repeat(64),
    from: { peerId: PEER_ID, name: '书房' }, at: AT, trusted: true, gone: true, state: 'offer',
  });
  const app = await openPanel({ files });

  // 已信任那一条：点了就直接拉（不带任何确认）
  clickText(findRow(app.q('dshLpFilesPending'), '旧合同.pdf'), t('zh', 'panel.files.download'));
  await flush();
  const posted = app.callsTo('files/download');
  assert.equal(posted.length, 1);
  assert.equal(posted[0].method, 'POST');
  assert.deepEqual(posted[0].body, { fileId: 'offer-2' }, '载荷是 offer 的 fileId');

  // 拒绝：只发 files/decline
  clickText(findRow(app.q('dshLpFilesPending'), '合同.pdf'), t('zh', 'panel.files.decline'));
  await flush();
  const declined = app.callsTo('files/decline');
  assert.equal(declined.length, 1);
  assert.deepEqual(declined[0].body, { fileId: 'offer-1' });
  assert.match(app.q('dshLpMsg').textContent, /^已拒绝下载：合同/);

  // gone：只有「已失效」这一格，没有下载按钮
  const gone = findRow(app.q('dshLpFilesPending'), 'gone.bin');
  assert.ok(gone, 'gone 条目仍然在列表里（墓碑留下，而不是静默消失）');
  assert.ok(labels(gone).includes(t('zh', 'panel.files.goneBadge')));
  assert.equal(labels(gone).includes(t('zh', 'panel.files.download')), false, '已失效不许有下载按钮');
  assert.equal(labels(gone).includes(t('zh', 'panel.files.decline')), false);
});

// ---------------------------------------------------------------------------
// P3：确认门 + 信任勾选
// ---------------------------------------------------------------------------
test('P3 未信任：先出确认面板、继续之前一个请求都不发；勾信任才 POST files/trust', async () => {
  const app = await openPanel({ files: fixtureFiles() });
  clickText(findRow(app.q('dshLpFilesPending'), '合同.pdf'), t('zh', 'panel.files.download'));
  await flush();

  assert.equal(app.callsTo('files/download').length, 0, '确认之前一个下载请求都不许发');
  assert.equal(app.q('dshLpFileConfirm').style.display, 'block', '确认面板必须露面');
  assert.equal(app.q('dshLpFileConfirmBody').textContent,
    t('zh', 'panel.files.confirmSize').replace('{size}', '4.0 KB'), '确认面板要写文件大小');
  assert.equal(app.q('dshLpFileFrom').textContent,
    t('zh', 'panel.files.confirmFrom').replace('{name}', '书房'), '确认面板要写来源');
  assert.equal(app.q('dshLpFileConfirmAsk').textContent, t('zh', 'panel.files.confirmAsk'));
  assert.equal(app.q('dshLpFileConfirmTrust').style.display, 'block', '私聊给「信任此人」勾选框');
  assert.equal(app.q('dshLpFileNoTrust').style.display, 'none');

  app.q('dshLpFileTrustBox').checked = true;
  app.q('dshLpFileConfirmGo').onclick();
  await flush();

  const trust = app.callsTo('files/trust');
  assert.equal(trust.length, 1, '勾了信任就要写这一格');
  assert.deepEqual(trust[0].body, { peerId: PEER_ID, trusted: true });
  const download = app.callsTo('files/download');
  assert.equal(download.length, 1);
  assert.deepEqual(download[0].body, { fileId: 'offer-1' });
  assert.equal(app.q('dshLpFileConfirm').style.display, 'none', '继续之后面板收起');
});

test('P3 已信任即刻下载；取消则一个请求都不发', async () => {
  const app = await openPanel({ files: fixtureFiles() });
  clickText(findRow(app.q('dshLpFilesPending'), '旧合同.pdf'), t('zh', 'panel.files.download'));
  await flush();
  assert.equal(app.callsTo('files/download').length, 1, 'trusted:true 不弹确认');
  assert.notEqual(app.q('dshLpFileConfirm').style.display, 'block', '已信任那一趟不许弹确认面板');
  assert.equal(app.callsTo('files/trust').length, 0, '没勾就不写信任');

  clickText(findRow(app.q('dshLpFilesPending'), '合同.pdf'), t('zh', 'panel.files.download'));
  await flush();
  assert.equal(app.q('dshLpFileConfirm').style.display, 'block');
  const before = app.callsTo('files/download').length;
  app.q('dshLpFileConfirmCancel').onclick();
  await flush();
  assert.equal(app.callsTo('files/download').length, before, '取消不发任何下载请求');
  assert.equal(app.q('dshLpFileConfirm').style.display, 'none');
});

// ---------------------------------------------------------------------------
// P4：群发目标 + 群列状态 + 群下载没有按成员信任
// ---------------------------------------------------------------------------
test('P4 群发目标：全体 = peerId:all，成员 = 它的 uuid；群列渲染 gone/downloaded', async () => {
  const app = await openPanel({ files: emptyFiles() });
  await openTab(app, 'Group');

  assert.ok(app.callsTo('group?sinceSeq=0').length >= 1, '进群页仍然只打既有那一条 GET group');
  const select = app.q('dshLpGroupFilesTo');
  assert.equal(select.children[0].value, 'all');
  assert.equal(select.children[0].textContent, t('zh', 'panel.group.filesAll'));
  const memberIds = select.children.slice(1).map((child) => child.value);
  assert.deepEqual(memberIds, [PEER_ID, OTHER.peerId], '每个成员一枚 option，值就是它的 peerId');

  const pathInput = app.q('dshLpGroupFilesPath');
  select.value = 'all';
  pathInput.value = '/tmp/group-all.zip';
  app.q('dshLpGroupFilesSend').onclick();
  await flush();
  const sent = app.callsTo('group/files/send');
  assert.equal(sent.length, 1);
  assert.deepEqual(sent[0].body, { peerId: 'all', path: '/tmp/group-all.zip' });

  select.value = OTHER.peerId;
  pathInput.value = '/tmp/group-one.zip';
  app.q('dshLpGroupFilesSend').onclick();
  await flush();
  assert.deepEqual(app.callsTo('group/files/send')[1].body,
    { peerId: OTHER.peerId, path: '/tmp/group-one.zip' }, '发给某个成员就是它的 uuid');

  // 群列：gone / downloaded 两个状态各自成一格
  const list = app.q('dshLpGroupFiles');
  const gone = findRow(list, '过期.log');
  assert.ok(gone, 'gone 条目留在列表里');
  assert.ok(labels(gone).includes(t('zh', 'panel.files.goneBadge')));
  assert.equal(labels(gone).includes(t('zh', 'panel.files.download')), false, '已失效没有下载按钮');
  const downloaded = findRow(list, '已下.bin');
  assert.ok(labels(downloaded).includes(t('zh', 'panel.files.downloadedBadge')));
  assert.ok(labels(downloaded).includes(t('zh', 'panel.group.filesMineBadge')));
  assert.equal(labels(downloaded).includes(t('zh', 'panel.files.download')), false);
  assert.equal(app.q('dshLpGroupFilesHead').textContent,
    t('zh', 'panel.group.filesHead').replace('{count}', '3'));
});

test('P4 群文件下载：后端没有按成员信任 → 只问一句、不给勾选框、不写 files/trust', async () => {
  const app = await openPanel({ files: emptyFiles() });
  await openTab(app, 'Group');

  clickText(findRow(app.q('dshLpGroupFiles'), '群文件.zip'), t('zh', 'panel.files.download'));
  await flush();
  assert.equal(app.q('dshLpFileConfirm').style.display, 'block', '群文件也先问一句');
  assert.equal(app.q('dshLpFileConfirmTrust').style.display, 'none', '没有按成员信任可存，就不给假开关');
  assert.equal(app.q('dshLpFileNoTrust').textContent, t('zh', 'panel.files.groupNoTrust'));
  assert.equal(app.callsTo('group/files/download').length, 0);

  app.q('dshLpFileConfirmGo').onclick();
  await flush();
  const posted = app.callsTo('group/files/download');
  assert.equal(posted.length, 1);
  assert.deepEqual(posted[0].body, { fileId: 'gf-1' });
  assert.equal(app.callsTo('files/trust').length, 0, '群文件那条路绝不写信任');
});

// ---------------------------------------------------------------------------
// P5：进度轮询（同一个节拍、同一个 fileId）
// ---------------------------------------------------------------------------
test('P5 进度用 offer 的 fileId 问 files/progress，进度条前进，节拍数不变', async () => {
  const files = {
    offers: [{
      id: 'offer-9', name: 'big.bin', size: 1000, sha256: 'a'.repeat(64),
      from: { peerId: PEER_ID, name: '书房' }, at: AT, trusted: true, state: 'offer',
    }],
    inbox: [],
    incoming: [],
  };
  const app = await openPanel({ files, hangDownload: true });
  const timersBefore = app.timers.length;
  const scriptIntervals = (PANEL_SCRIPT.match(/setInterval\(/g) || []).length;

  clickText(findRow(app.q('dshLpFilesPending'), 'big.bin'), t('zh', 'panel.files.download'));
  await flush();

  await beat(app);
  assert.equal(app.q('dshLpFileDlBar').style.width, '25%', '第一次回报 received=250/1000');
  const probes = app.calls.filter((call) => call.path.startsWith('files/progress?id='));
  assert.ok(probes.length >= 1, '进度必须问 files/progress');
  assert.equal(probes[0].path, 'files/progress?id=offer-9', '用的就是 offer 的 fileId');

  await beat(app);
  assert.equal(app.q('dshLpFileDlBar').style.width, '70%', '第二次回报前进到 700/1000');
  assert.equal(app.q('dshLpFileDlStatus').textContent,
    t('zh', 'panel.files.dlProgress')
      .replace('{received}', '700 B').replace('{size}', '1000 B').replace('{pct}', '70'));

  assert.equal(app.timers.length, timersBefore, '下载进度不许新开节拍');
  assert.equal((PANEL_SCRIPT.match(/setInterval\(/g) || []).length, scriptIntervals);
  assert.equal(scriptIntervals, 7, 'HEAD 就是 7 枚 setInterval：这一片不许再加');
});

// ---------------------------------------------------------------------------
// P6：私聊附件（目标固定）与 513 MiB 硬上限
// ---------------------------------------------------------------------------
test('P6 私聊附件：目标固定成这段对话的 peer，走既有 upload 链（init → chunk → finish）', async () => {
  const app = await openPanel({ files: emptyFiles() });
  await openTab(app, 'Dm');
  // 伙伴页那个下拉故意换成别人：私聊附件绝不许跟它走
  app.q('dshLpFilesPeer').value = 'peer-other-9999';
  pickDmFile(app, makeFile('note.txt', 4, Buffer.from('ABCD')));
  await flush();

  assert.equal(app.callsTo('files/upload/init').length, 1);
  assert.deepEqual(app.callsTo('files/upload/init')[0].body, { name: 'note.txt', bytes: 4 });
  const finish = app.callsTo('files/upload/finish');
  assert.equal(finish.length, 1, 'finish 只发一次');
  assert.deepEqual(finish[0].body, { uploadId: 'u-1', peerId: PEER_ID },
    '目标固定成私聊这段对话的 peer（不是伙伴页下拉里那一枚）');
  assert.equal(app.callsTo('files/send').length, 0, '浏览器选的文件不走「按路径发」');
});

test('P6 513 MiB 从私聊附件选：一次 init 都不发，提示点名 CLI 与 agent 工具', async () => {
  const app = await openPanel({ files: emptyFiles(), fileMaxBytes: 2048 * MIB });
  await openTab(app, 'Dm');
  pickDmFile(app, makeFile('huge.bin', 513 * MIB));
  await flush();

  assert.equal(app.callsTo('files/upload/init').length, 0, '513 MiB 不许发 init');
  assert.equal(app.callsTo('files/upload/chunk').length, 0);
  const status = app.q('dshLpFilesStatus').textContent;
  assert.ok(status.includes('513.0 MB'), '提示里要有真实体积：' + status);
  assert.ok(status.includes('512.0 MB'), '提示里要写清上限：' + status);
  assert.ok(status.includes('send-file'), '提示要给出命令行那一条路：' + status);
  assert.ok(status.includes('lan_peer_send_file'), '提示要给出 agent 工具那一条路：' + status);

  const hint = app.q('dshLpFilesCapHint').textContent;
  assert.equal(hint, t('zh', 'panel.files.capHint'.replace('capHint', 'panelCapHint')));
  assert.ok(hint.includes('512 MiB') && hint.includes('send-file') && hint.includes('lan_peer_send_file'));
});

test('P6 512 MiB 正好等于上限：边界包含（init 会被调用）', async () => {
  const app = await openPanel({ files: emptyFiles(), chunkMode: 'complete', initMaxBytes: 512 * MIB });
  await openTab(app, 'Dm');
  pickDmFile(app, makeFile('edge.bin', 512 * MIB));
  await flush();
  const init = app.callsTo('files/upload/init');
  assert.equal(init.length, 1, '512 MiB 是允许的（size > cap 才拒）');
  assert.equal(init[0].body.bytes, 512 * MIB);
  assert.equal(app.q('dshLpFilesStatus').textContent,
    t('zh', 'panel.files.uploadDone').replace('{name}', 'edge.bin').replace('{size}', '512.0 MB'),
    '边界那一枚真的走完了整条路（init → chunk → finish）');
});

// ---------------------------------------------------------------------------
// P7：铁律（只扫新增段）
// ---------------------------------------------------------------------------
const SECTION_START = '0.12.0-alpha S3：文件面（同一个';
const SECTION_END = "$('dshLpFilesPathSend').onclick";

function addedBlock() {
  const source = readFileSync(new URL('./admin.mjs', import.meta.url), 'utf8');
  const start = source.indexOf(SECTION_START);
  const end = source.indexOf(SECTION_END);
  assert.ok(start > 0 && end > start, '新增段的起止标记必须还在 lib/admin.mjs 里');
  return source.slice(start, end);
}

test('P7 新增段零反引号、无 console.error、innerHTML 只赋空串、隐藏门仍在', () => {
  const block = addedBlock();
  assert.equal((block.match(/`/g) || []).length, 0, '新增段零反引号（面板整份就是一个模板字符串）');
  assert.equal(/console\.error/.test(block), false, '不新增 console.error');
  for (const line of block.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed.includes('innerHTML')) continue;
    if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;
    assert.match(trimmed, /innerHTML\s*=\s*'';/, 'innerHTML 只允许赋空串：' + trimmed);
  }
  assert.equal(/document\.hidden/.test(block), true, 'pollIncoming 那道隐藏门必须还在这一段的 poll 里');
  // 非空化：这一段真的就是 S3 的新代码（否则上面几条铁律会变成对空串的检查）
  for (const needle of ['files/download', 'files/decline', 'files/trust', 'files/progress', 'group/files/send', 'dshLpFileConfirm']) {
    assert.ok(block.includes(needle), '新增段里必须真的有：' + needle);
  }
});

test('P7 节拍数与隐藏门数与 HEAD 一致（7 / 9），隐藏时三张列表都不刷新', async () => {
  assert.equal((PANEL_SCRIPT.match(/setInterval\(/g) || []).length, 7, '不许新开节拍');
  assert.equal((PANEL_SCRIPT.match(/document\.hidden/g) || []).length, 9, '隐藏门数量不变');
  const poll = PANEL_SCRIPT.slice(PANEL_SCRIPT.indexOf('async function pollIncoming'));
  assert.match(poll.slice(0, 240), /if \(document\.hidden === true\) return;/, '轮询的第一句仍是隐藏门');

  const app = await openPanel({ files: fixtureFiles() });
  const before = app.callsTo('files').length;
  app.document.hidden = true;
  await beat(app);
  assert.equal(app.callsTo('files').length, before, '隐藏期间一次都不许拉 files');
  app.document.hidden = false;
  await beat(app);
  assert.ok(app.callsTo('files').length > before, '回到可见后节拍照旧工作');
});

// ---------------------------------------------------------------------------
// P8：新文案 zh + en 两格齐备
// ---------------------------------------------------------------------------
const NEW_KEYS = [
  'panel.files.download',
  'panel.files.decline',
  'panel.files.declined',
  'panel.files.goneBadge',
  'panel.files.downloadedBadge',
  'panel.files.confirmTitle',
  'panel.files.confirmSize',
  'panel.files.confirmFrom',
  'panel.files.confirmAsk',
  'panel.files.confirmTrust',
  'panel.files.confirmGo',
  'panel.files.confirmCancel',
  'panel.files.groupNoTrust',
  'panel.files.dlStart',
  'panel.files.dlProgress',
  'panel.files.dlDone',
  'panel.files.dlFailed',
  'panel.files.trustSaved',
  'panel.files.pendingHead',
  'panel.files.inboxHead',
  'panel.files.emptyPending',
  'panel.files.uploadDone',
  'panel.dm.attach',
  'panel.dm.filesHead',
  'panel.dm.filesEmpty',
  'panel.group.filesLabel',
  'panel.group.filesHead',
  'panel.group.filesEmpty',
  'panel.group.filesNoGroup',
  'panel.group.filesToLabel',
  'panel.group.filesAll',
  'panel.group.filesPathLabel',
  'panel.group.filesPathPlaceholder',
  'panel.group.filesSend',
  'panel.group.filesPathEmpty',
  'panel.group.filesSent',
  'panel.group.filesFailed',
  'panel.group.filesWithdraw',
  'panel.group.filesWithdrawn',
  'panel.group.filesMineBadge',
];

test('P8 新文案 zh + en 两格都在、en 无中日韩字，engine 语言下渲染英文', async () => {
  const zhKeys = keys('zh');
  const enKeys = keys('en');
  for (const key of NEW_KEYS) {
    assert.ok(zhKeys.includes(key), 'zh 缺 key：' + key);
    assert.ok(enKeys.includes(key), 'en 缺 key：' + key);
    assert.ok(String(t('zh', key)).trim() !== '', 'zh 空串：' + key);
    assert.ok(String(t('en', key)).trim() !== '', 'en 空串：' + key);
    assert.doesNotMatch(String(t('en', key)), /[\u4e00-\u9fa5]/, 'en 格不许有中文：' + key);
  }
  // 面板真的按注入表渲染英文（不是只有词表里有）
  const app = await openPanel({ files: fixtureFiles(), script: renderPanelScript('tok-en-s3', 'en') });
  const row = findRow(app.q('dshLpFilesPending'), '合同.pdf');
  assert.equal(row.children[4].textContent, t('en', 'panel.files.download'));
  assert.doesNotMatch(row.children[4].textContent, /[\u4e00-\u9fa5]/);
});

// ---------------------------------------------------------------------------
// P9：非空化 —— 拆掉哪一处、哪一条断言就会红（脚本级变异，跑完还原）
// ---------------------------------------------------------------------------
test('P9 非空化：拆掉确认门 / 拆掉 gone 守卫，各有断言真的变红（之后还原）', async () => {
  // 1) 拆掉确认门：requestDownload 变成「一律直接拉」→ P3 第一条断言（确认之前一个请求都不发）会红
  const gate = 'if (kind === \'dm\' && row && row.trusted === true) {';
  assert.ok(PANEL_SCRIPT.includes(gate), '变异锚点必须还在脚本里');
  const noGate = PANEL_SCRIPT.replace(gate, 'if (true) {');
  assert.notEqual(noGate, PANEL_SCRIPT, '变异必须真的改到脚本');
  const mutated = await openPanel({ files: fixtureFiles(), script: noGate });
  clickText(findRow(mutated.q('dshLpFilesPending'), '合同.pdf'), t('zh', 'panel.files.download'));
  await flush();
  assert.equal(mutated.callsTo('files/download').length, 1, '没有确认门时下载会立刻发出去 —— 于是 P3 那条断言红');
  assert.notEqual(mutated.q('dshLpFileConfirm').style.display, 'block', '变异之后确认面板根本不会露面');

  // 2) 拆掉 gone 守卫：gone 行会长出一枚下载按钮 → P2 最后一条断言会红
  const guard = 'if (row && row.gone === true) {';
  const noGuard = PANEL_SCRIPT.split(guard).join('if (false) {');
  assert.notEqual(noGuard, PANEL_SCRIPT, '变异必须真的改到脚本');
  const files = fixtureFiles();
  files.offers.push({
    id: 'offer-gone', name: 'gone.bin', size: 10, sha256: '9'.repeat(64),
    from: { peerId: PEER_ID, name: '书房' }, at: AT, trusted: true, gone: true, state: 'offer',
  });
  const broken = await openPanel({ files, script: noGuard });
  const brokenRow = findRow(broken.q('dshLpFilesPending'), 'gone.bin');
  assert.ok(labels(brokenRow).includes(t('zh', 'panel.files.download')), '没有守卫时 gone 行会带下载按钮 —— 于是 P2 那条断言红');

  // 3) 还原：原脚本两处都还是「关着」的
  const pristine = await openPanel({ files: fixtureFiles() });
  clickText(findRow(pristine.q('dshLpFilesPending'), '合同.pdf'), t('zh', 'panel.files.download'));
  await flush();
  assert.equal(pristine.callsTo('files/download').length, 0, '还原之后确认门仍然挡着');
  assert.equal(pristine.q('dshLpFileConfirm').style.display, 'block');
});

// ---------------------------------------------------------------------------
// 既有能力不回退：分片上传 / 续传 / 相对时间
// ---------------------------------------------------------------------------
test('R1 顺序分片 + 进度只增 + finish 只一次（伙伴页下拉那一枚 peer）', async () => {
  const app = await openPanel({ files: emptyFiles() });
  app.q('dshLpFilesPeer').value = PEER_ID;
  pickFile(app, makeFile('report.bin', 12, Buffer.from('AAAABBBBCCCC')));
  await flush();
  const chunks = app.callsTo('files/upload/chunk');
  assert.deepEqual(chunks.map((call) => call.body.offset), [0, 4, 8]);
  assert.deepEqual(chunks.map((call) => Buffer.from(call.body.dataBase64, 'base64').toString()),
    ['AAAA', 'BBBB', 'CCCC']);
  const widths = app.widths.filter((value) => value.endsWith('%')).map((value) => parseInt(value, 10));
  assert.deepEqual(widths, [0, 33, 67, 100], '进度只增不减，最后一次是 100%');
  assert.deepEqual(app.callsTo('files/upload/finish')[0].body, { uploadId: 'u-1', peerId: PEER_ID });
});

test('R2 409 之后「重试 = 续传」：先 GET files/upload?id=，再从 received 继续', async () => {
  const app = await openPanel({ files: emptyFiles(), failChunkAt: 2 });
  app.q('dshLpFilesPeer').value = PEER_ID;
  pickFile(app, makeFile('blip.bin', 12, Buffer.from('AAAABBBBCCCC')));
  await flush();
  assert.equal(app.q('dshLpFilesStatus').textContent,
    t('zh', 'panel.files.uploadFailed').replace('{code}', 'offset-mismatch'));
  const chunksBefore = app.callsTo('files/upload/chunk').length;
  app.q('dshLpFilesRetry').onclick();
  await flush();
  const probes = app.calls.filter((call) => call.path.startsWith('files/upload?id='));
  assert.equal(probes.length, 1);
  const resumed = app.callsTo('files/upload/chunk').slice(chunksBefore);
  assert.deepEqual(resumed.map((call) => call.body.offset), [8], '续传绝不回到 0');
  assert.equal(app.callsTo('files/upload/init').length, 1, '续传不许重新 init');
});

// ---------------------------------------------------------------------------
// Q（S3b）：群发改用同一个文件选择器 + 「我发出的」三态
//
// 非空化：
//   - 把 finishUpload 的 payload 换回「永远 {uploadId, peerId}」→ Q6a 的
//     scope:'group' 断言红（群发会静默退回私聊那条路）；
//   - 把 renderDmOutbox 从 pollIncoming 里摘掉 → Q6b 的 waiting/pulling/pulled 三条全红。
// ---------------------------------------------------------------------------

function fixtureOutbox() {
  return [
    {
      fileId: 'o-1', name: '报告.pdf', size: 4096, sha256: 'a'.repeat(64),
      to: { peerId: PEER_ID, name: '书房' }, at: AT + 3000, pulledBytes: 0, state: 'waiting',
    },
    {
      fileId: 'o-2', name: '大图.bin', size: 8192, sha256: 'b'.repeat(64),
      to: { peerId: PEER_ID, name: '书房' }, at: AT + 2000, pulledBytes: 4096, state: 'pulling',
    },
    {
      fileId: 'o-3', name: '小文件.txt', size: 100, sha256: 'c'.repeat(64),
      to: { peerId: PEER_ID, name: '书房' }, at: AT + 1000, pulledBytes: 100, state: 'pulled',
    },
    // 发给别人的那一行不进这段对话
    {
      fileId: 'o-4', name: '别人的.bin', size: 10, sha256: 'd'.repeat(64),
      to: { peerId: OTHER.peerId, name: '客厅' }, at: AT, pulledBytes: 0, state: 'waiting',
    },
  ];
}

function pickGroupFile(app, file) {
  const pick = app.q('dshLpGroupFilesPick');
  pick.files = [file];
  const listener = pick.listeners.get('change')[0];
  assert.equal(typeof listener, 'function', '群发也要有文件选择器（dshLpGroupFilesPick）');
  listener();
}

test('Q6a 群发走同一个选择器：init → chunk → finish 带 scope:group（不再只能填绝对路径）', async () => {
  const app = await openPanel({ files: emptyFiles() });
  await openTab(app, 'Group');

  pickGroupFile(app, makeFile('群.zip', 8, Buffer.from('AAAABBBB')));
  await flush();

  assert.equal(app.callsTo('files/upload/init').length, 1, '同一条上传链：先 init');
  assert.deepEqual(app.callsTo('files/upload/init')[0].body, { name: '群.zip', bytes: 8 });
  assert.deepEqual(app.callsTo('files/upload/chunk').map((call) => call.body.offset), [0, 4],
    '顺序分片，与私聊附件同一条路');
  assert.equal(app.callsTo('group/files/send').length, 0, '不再走「按本机路径发」那条老路');
  assert.equal(app.callsTo('files/send').length, 0);
  assert.deepEqual(app.callsTo('files/upload/finish')[0].body,
    { uploadId: 'u-1', scope: 'group', targets: 'all' },
    '终点显式声明 scope:group + 目标（缺省全体）');
  assert.match(app.q('dshLpGroupFilesStatus').textContent, /^已发到群/);

  // 目标换成某个成员：同一条链，只换 targets
  app.q('dshLpGroupFilesTo').value = OTHER.peerId;
  pickGroupFile(app, makeFile('给客厅.bin', 4, Buffer.from('WXYZ')));
  await flush();
  assert.deepEqual(app.callsTo('files/upload/finish')[1].body,
    { uploadId: 'u-1', scope: 'group', targets: OTHER.peerId });
});

test('Q6b 我发出的：三态行渲染名字/体积/目标/时间/状态，撤回按钮只给还没拉完的两态', async () => {
  const app = await openPanel({ files: { ...fixtureFiles(), outbox: fixtureOutbox() } });
  await openTab(app, 'Dm');
  await beat(app);

  assert.equal(app.q('dshLpDmOutboxHead').textContent,
    t('zh', 'panel.dm.outboxHead').replace('{count}', '3'),
    '只数发给这段对话那一枚 peer 的（发给别人的不进这一块）');
  const box = app.q('dshLpDmOutbox');
  assert.equal(box.children.length, 3);
  const states = box.children.map((row) => row.children[4].textContent);
  assert.deepEqual(states, [
    t('zh', 'panel.files.outboxWaiting'),
    t('zh', 'panel.files.outboxPulling').replace('{pulled}', '4.0 KB').replace('{size}', '8.0 KB'),
    t('zh', 'panel.files.outboxPulled'),
  ], '三态各有自己那一句文案（waiting / pulling（带字节）/ pulled）');

  const newest = box.children[0];
  assert.equal(newest.children[0].textContent, '报告.pdf', '最新的在上');
  assert.equal(newest.children[1].textContent, '4.0 KB', '体积只显示大小');
  assert.equal(newest.children[2].textContent, '书房', '目标显示对端那个名字');
  assert.equal(newest.children[3].className, 'lpfiletime');
  assert.equal(newest.children.length, 6, '六格：名字/体积/目标/时间/状态 + 撤回');
  for (const row of box.children) {
    assert.equal(labels(row).some((text) => text === t('zh', 'panel.files.download')), false,
      '发送方这一块没有下载按钮（撤回不是下载）');
  }
  // S3c：撤回只长在「对端还没拉完」的两态上 —— pulled 那份字节已在对方盘上，撤回是演戏
  const withdrawLabel = t('zh', 'panel.files.withdraw');
  assert.equal(labels(box.children[0]).includes(withdrawLabel), true, 'waiting 要给撤回');
  assert.equal(labels(box.children[1]).includes(withdrawLabel), true, 'pulling 也要给撤回');
  assert.equal(labels(box.children[2]).includes(withdrawLabel), false, 'pulled 不给撤回');
  assert.equal(box.children[2].children.some((child) => child.tagName === 'BUTTON'), false,
    'pulled 那一行一个按钮都不许有（字节已经在对方盘上）');

  // 空态：没有 outbox 这一桶也不炸，只渲染一行提示
  const empty = await openPanel({ files: fixtureFiles() });
  await openTab(empty, 'Dm');
  await beat(empty);
  assert.equal(empty.q('dshLpDmOutboxHead').textContent,
    t('zh', 'panel.dm.outboxHead').replace('{count}', '0'));
  assert.equal(empty.q('dshLpDmOutbox').children.length, 1);
  assert.equal(empty.q('dshLpDmOutbox').children[0].textContent, t('zh', 'panel.dm.outboxEmpty'));
});

// ---------------------------------------------------------------------------
// W5（0.12.0-alpha S3c）：撤回按钮 —— 只给 waiting/pulling，点了就打 files/withdraw；
//   对端离线（503 peer-offline）行留着、状态格写稳定码（可重试）；
//   成功 / unknown-file 行自然消失（GET files 不再列它，不开第二个节拍）。
// W6 非空化：「pulled 不给按钮」那道判断拆掉 → 上面那条断言真的变红（跑完还原）。
// ---------------------------------------------------------------------------
const outboxPanel = () => ({ ...fixtureFiles(), outbox: fixtureOutbox() });

test('W5 撤回：waiting/pulling 有按钮、点了 POST files/withdraw、200 行消失、503 行留着带稳定码', async () => {
  const withdrawLabel = t('zh', 'panel.files.withdraw');
  const app = await openPanel({ files: outboxPanel() });
  await openTab(app, 'Dm');
  await beat(app);

  // waiting 那一行（报告.pdf）：点一下 = 一条 POST files/withdraw {fileId}
  clickText(app.q('dshLpDmOutbox').children[0], withdrawLabel);
  await flush();
  const posted = app.callsTo('files/withdraw');
  assert.equal(posted.length, 1, '点一下只发一条请求');
  assert.equal(posted[0].method, 'POST');
  assert.deepEqual(posted[0].body, { fileId: 'o-1' }, '请求体只有 {fileId}');
  // 服务端删掉之后 GET files 不再列它 → 同一拍重渲染少一行（没有新节拍）
  await beat(app);
  assert.equal(findRow(app.q('dshLpDmOutbox'), '报告.pdf'), undefined, '撤回过的那一行不见了');
  assert.equal(app.q('dshLpDmOutbox').children.length, 2);

  // pulling 那一行（大图.bin）同样能撤
  clickText(app.q('dshLpDmOutbox').children[0], withdrawLabel);
  await flush();
  await beat(app);
  assert.equal(findRow(app.q('dshLpDmOutbox'), '大图.bin'), undefined);
  assert.deepEqual(app.callsTo('files/withdraw').map((call) => call.body.fileId), ['o-1', 'o-2']);

  // pulled 那一行（小文件.txt）：没有按钮，所以谁也点不动它
  const pulledRow = app.q('dshLpDmOutbox').children[0];
  assert.equal(findRow(app.q('dshLpDmOutbox'), '小文件.txt'), pulledRow);
  assert.equal(labels(pulledRow).includes(withdrawLabel), false, 'pulled 不给撤回');
  assert.equal(app.callsTo('files/withdraw').length, 2, 'pulled 那一行没有按钮，点不出第三条请求');

  // 对端离线：行必须留着，状态格写稳定码（可重试），不吞错
  const offline = await openPanel({ files: outboxPanel(), withdrawMode: 'offline' });
  await openTab(offline, 'Dm');
  await beat(offline);
  const row = offline.q('dshLpDmOutbox').children[0];
  clickText(row, withdrawLabel);
  await flush();
  assert.equal(offline.q('dshLpDmOutbox').children.length, 3, '503 之后三行原样都在（可重试）');
  assert.equal(offline.q('dshLpDmOutbox').children[0], row, '连那一枚行元素都没被换掉');
  assert.equal(row.children[4].textContent,
    t('zh', 'panel.files.withdrawOffline').replace('{code}', 'peer-offline'),
    '状态格写的是稳定码（面板不编造「已撤回」）');
  assert.match(row.children[4].textContent, /peer-offline/, '稳定码本身要看得见');
  assert.equal(labels(row).includes(withdrawLabel), true, '还能再点一次（retryable）');

  // unknown-file：本来就不在了，刷新即可 —— 既不报成离线，也不留着一条假行
  const gone = await openPanel({ files: outboxPanel(), withdrawMode: 'unknown' });
  await openTab(gone, 'Dm');
  await beat(gone);
  clickText(gone.q('dshLpDmOutbox').children[0], withdrawLabel);
  await flush();
  await beat(gone);
  assert.equal(findRow(gone.q('dshLpDmOutbox'), '报告.pdf'), undefined, 'unknown-file 之后那一行也消失');
  assert.equal(gone.callsTo('files/withdraw').length, 1, '不因为 404 就重试成风暴');
});

test('W6 非空化：拆掉「只给 waiting/pulling」那道判断，pulled 行立刻长出撤回（之后还原）', async () => {
  const guard = "if (state === 'waiting' || state === 'pulling') {";
  assert.ok(PANEL_SCRIPT.includes(guard), '状态判断必须真的在脚本里（否则下面变异是空转）');
  const leaky = PANEL_SCRIPT.replace(guard, 'if (true) {');
  assert.notEqual(leaky, PANEL_SCRIPT, '变异必须真的改到脚本');
  const app = await openPanel({ files: outboxPanel(), script: leaky });
  await openTab(app, 'Dm');
  await beat(app);
  const box = app.q('dshLpDmOutbox');
  assert.equal(labels(box.children[2]).includes(t('zh', 'panel.files.withdraw')), true,
    '拆掉判断之后 pulled 也长按钮 —— 于是 Q6b/W5 那条「pulled 不给撤回」真的变红');

  const pristine = await openPanel({ files: outboxPanel() });
  await openTab(pristine, 'Dm');
  await beat(pristine);
  assert.equal(labels(pristine.q('dshLpDmOutbox').children[2]).includes(t('zh', 'panel.files.withdraw')), false,
    '还原：原脚本里 pulled 仍然没有按钮');
});

test('Q8 S3b 新文案 zh + en 两格都在、en 无中日韩字', async () => {
  const NEW_S3B = [
    'panel.dm.outboxHead',
    'panel.dm.outboxEmpty',
    'panel.files.outboxWaiting',
    'panel.files.outboxPulling',
    'panel.files.outboxPulled',
    'panel.files.withdraw',
    'panel.files.withdrawOffline',
    'panel.group.filesPick',
  ];
  const zhKeys = keys('zh');
  const enKeys = keys('en');
  for (const key of NEW_S3B) {
    assert.ok(zhKeys.includes(key), 'zh 缺 key：' + key);
    assert.ok(enKeys.includes(key), 'en 缺 key：' + key);
    assert.ok(String(t('zh', key)).trim() !== '', 'zh 空串：' + key);
    assert.ok(String(t('en', key)).trim() !== '', 'en 空串：' + key);
    assert.notEqual(String(t('en', key)), String(t('zh', key)), 'en 必须真译过：' + key);
    assert.doesNotMatch(String(t('en', key)), /[\u4e00-\u9fa5]/, 'en 格不许有中文：' + key);
  }
  // 面板真的按注入表渲染英文（不是只有词表里有）
  const app = await openPanel({
    files: { ...fixtureFiles(), outbox: fixtureOutbox() },
    script: renderPanelScript('tok-en-s3b', 'en'),
  });
  await openTab(app, 'Dm');
  await beat(app);
  assert.equal(app.q('dshLpDmOutboxHead').textContent, t('en', 'panel.dm.outboxHead').replace('{count}', '3'));
  assert.doesNotMatch(app.q('dshLpDmOutbox').children[0].children[4].textContent, /[\u4e00-\u9fa5]/);
});

test('R3 fileTimeAgo 边界表：0/59s/60s/59m/60m/23h/24h/6d/7d + 空值 + 时钟回拨', () => {
  const app = boot({ files: emptyFiles() });
  const ago = app.window.__lanPeersFileTimeAgo;
  assert.equal(typeof ago, 'function');
  const NOW_MS = AT;
  const SEC = 1000;
  const MIN = 60 * SEC;
  const HOUR = 60 * MIN;
  const DAY = 24 * HOUR;
  const table = [
    [NOW_MS, '刚刚'],
    [NOW_MS - 59 * SEC, '刚刚'],
    [NOW_MS - 60 * SEC, '1 分钟前'],
    [NOW_MS - 59 * MIN, '59 分钟前'],
    [NOW_MS - 60 * MIN, '1 小时前'],
    [NOW_MS - 23 * HOUR, '23 小时前'],
    [NOW_MS - 24 * HOUR, '1 天前'],
    [NOW_MS - 6 * DAY, '6 天前'],
  ];
  for (const [at, want] of table) assert.equal(ago(at, NOW_MS), want, 'at = now - ' + (NOW_MS - at) + 'ms');
  for (const bad of [null, 0, NaN, undefined]) assert.equal(ago(bad, NOW_MS), '', '空值 → 空串：' + String(bad));
  assert.equal(ago(NOW_MS + 60 * SEC, NOW_MS), '刚刚', '时钟回拨收口成刚刚');
});

// ---------------------------------------------------------------------------
// P10（0.12.0-alpha S3 修缺陷）：群发目标里**不出现自己**
//   P10 三个成员里有一个是本机 → 全体 + 另两个；只剩自己时仍然渲染（只有全体）
//   非空化：拆掉自己那一格过滤 → self 回到下拉（之后还原）
// ---------------------------------------------------------------------------
test('P10 群发目标不出自己：三个成员里一个是本机 → 全体 + 另两个；只有一个成员时只有全体', async () => {
  const SELF_ID = 'me-id'; // boot 的 GET state 就回这个 instanceId
  const group = fixtureGroup();
  group.group.members = [{ peerId: SELF_ID, name: '本机' }, ...group.group.members];
  const app = await openPanel({ files: emptyFiles(), group });
  await openTab(app, 'Group');

  const select = app.q('dshLpGroupFilesTo');
  assert.equal(select.children[0].value, 'all', '全体成员永远在第一格');
  assert.equal(select.children[0].textContent, t('zh', 'panel.group.filesAll'), '第一格文案不变');
  assert.deepEqual(select.children.slice(1).map((child) => child.value), [PEER_ID, OTHER.peerId],
    '下拉 = 另两个成员，本机那一格不许出现');
  assert.equal(select.children.some((child) => child.value === SELF_ID), false, '自己绝不能是目标');

  const solo = fixtureGroup();
  solo.group.members = [{ peerId: SELF_ID, name: '本机' }];
  const one = await openPanel({ files: emptyFiles(), group: solo });
  await openTab(one, 'Group');
  const soloSelect = one.q('dshLpGroupFilesTo');
  assert.equal(soloSelect.children.length, 1, '只有一个真实成员时下拉照样渲染（只有全体），不是空盒子');
  assert.equal(soloSelect.children[0].value, 'all');
});

test('P10 非空化：拆掉自己那一格过滤，self 会回到下拉（之后还原）', async () => {
  const anchor = 'if (isSelfPeer(peerId)) continue;';
  assert.ok(PANEL_SCRIPT.includes(anchor), '过滤锚点必须还在脚本里');
  const mutated = PANEL_SCRIPT.replace(anchor, 'if (false) continue;');
  assert.notEqual(mutated, PANEL_SCRIPT, '变异必须真的改到脚本');
  const group = fixtureGroup();
  group.group.members = [{ peerId: 'me-id', name: '本机' }, ...group.group.members];
  const broken = await openPanel({ files: emptyFiles(), group, script: mutated });
  await openTab(broken, 'Group');
  assert.equal(broken.q('dshLpGroupFilesTo').children.some((child) => child.value === 'me-id'), true,
    '没有过滤时本机回到下拉 —— 于是 P10 那条断言红');

  const pristine = await openPanel({ files: emptyFiles(), group });
  await openTab(pristine, 'Group');
  assert.equal(pristine.q('dshLpGroupFilesTo').children.some((child) => child.value === 'me-id'), false,
    '还原之后本机不再出现');
});

// ---------------------------------------------------------------------------
// F（0.12.0-alpha 修缺陷）：私聊附件按钮「附件按了没反应」
//   F1 点按钮 = 把选择器戳开（dshLpDmPick.click()），自己一个请求都不发
//   F2 change 只认第一个文件，route/body 与群发那条路一致，目标=这段对话的 peer
//   F3 没选文件就 change：一个上传请求都不发
//   F4 选完 value 清空（同一枚文件连选两次各自触发）
//   非空化：拆掉 onclick → F1 红；去掉 peer 实参 → F2 红（跑完还原）
// ---------------------------------------------------------------------------
const uploadRoute = (app) => app.calls
  .filter((call) => call.path.startsWith('files/upload/'))
  .map((call) => call.path + ' ' + call.method);

/** 走一次私聊附件选择器：真浏览器会把 value 填成假路径，这里也先填上（否则 F4 是空断言） */
function dmChange(app, files, value = 'fake-selected.txt') {
  const pick = app.byId('dshLpDmPick');
  assert.ok(pick, '私聊页必须有附件输入（dshLpDmPick）');
  pick.files = files;
  pick.value = files && files.length > 0 ? value : '';
  const listener = pick.listeners.get('change')[0];
  assert.equal(typeof listener, 'function', '附件输入必须挂 change 监听');
  listener();
  return pick;
}

test('F1 点私聊附件按钮只是把选择器戳开，自己不发明细/上传请求', async () => {
  const app = await openPanel({ files: emptyFiles() });
  await openTab(app, 'Dm');
  const attach = app.byId('dshLpDmAttach');
  const pick = app.byId('dshLpDmPick');
  assert.ok(attach && pick, '两个控件都必须真的挂上 DOM');
  assert.equal(attach.textContent, t('zh', 'panel.dm.attach'));
  assert.equal(typeof attach.onclick, 'function', '附件按钮必须绑点击事件（没绑就是「按了没反应」）');
  const before = app.calls.length;
  attach.onclick();
  await flush();
  assert.equal(pick.clicks, 1, '点一下 = 选择器被点击恰好一次');
  assert.equal(app.calls.length, before, '按钮这一下自己不发任何请求');
  assert.equal(app.callsTo('files/upload/init').length, 0, '按钮本身不许起上传链');
});

test('F2 change 只认第一个文件，route 与群发同一条链，finish 目标是这段对话的 peer', async () => {
  const app = await openPanel({ files: emptyFiles() });
  await openTab(app, 'Dm');
  // 伙伴页那个下拉故意换成别人：私聊附件绝不许跟它走
  app.q('dshLpFilesPeer').value = 'peer-other-9999';
  dmChange(app, [makeFile('note.txt', 4, Buffer.from('ABCD')), makeFile('second.bin', 8, Buffer.from('XXXXXXXX'))]);
  await flush();

  // 群发那条路（scope='group'）今天的产物，用来对照：同一条 init → chunk → finish
  const group = await openPanel({ files: emptyFiles() });
  await openTab(group, 'Group');
  pickGroupFile(group, makeFile('note.txt', 4, Buffer.from('ABCD')));
  await flush();

  assert.deepEqual(uploadRoute(app), uploadRoute(group), '私聊与群发是同一条 upload 链（路径 + 方法逐条相同）');
  assert.deepEqual(app.callsTo('files/upload/init')[0].body, { name: 'note.txt', bytes: 4 },
    'init 请求体与群发一致：{name, bytes}，且只认第一个文件');
  assert.deepEqual(app.callsTo('files/upload/chunk').map((call) => call.body.offset),
    group.callsTo('files/upload/chunk').map((call) => call.body.offset), '分片顺序一致');
  // 两条路只在终点分叉：群发声明 scope+targets，私聊带这段对话的 peerId
  assert.deepEqual(group.callsTo('files/upload/finish')[0].body, { uploadId: 'u-1', scope: 'group', targets: 'all' });
  assert.deepEqual(app.callsTo('files/upload/finish')[0].body, { uploadId: 'u-1', peerId: PEER_ID },
    'finish 的 peerId 是这段对话的 peer，不是伙伴页下拉里的 peer-other-9999');
  assert.equal(app.callsTo('files/send').length, 0, '浏览器选的文件不走「按本机路径发」那条老路');
  // 落地之后列表自己刷新：finish 之后必须还有一次 GET files（我发出的 / 收到的 / 待下载）
  const finishAt = app.calls.findIndex((call) => call.path === 'files/upload/finish');
  assert.ok(finishAt > 0, 'finish 必须真的发过');
  assert.ok(app.calls.slice(finishAt).some((call) => call.path === 'files'),
    'finish 之后必须再 GET 一次 files：offer 立刻出现在「我发出的」，不用手点');
});

test('F3 没选文件就 change：一个上传请求都不发', async () => {
  const app = await openPanel({ files: emptyFiles() });
  await openTab(app, 'Dm');
  dmChange(app, null);
  await flush();
  dmChange(app, []);
  await flush();
  assert.deepEqual(uploadRoute(app), [], '没有文件时 init / chunk / finish 一条都不许发');
  assert.equal(app.callsTo('files/send').length, 0);
});

test('F4 选完把 value 清空：同一枚文件连选两次也各自触发一次', async () => {
  const app = await openPanel({ files: emptyFiles() });
  await openTab(app, 'Dm');
  const pick = dmChange(app, [makeFile('a.txt', 4, Buffer.from('ABCD'))]);
  await flush();
  assert.equal(pick.value, '', '选完立刻清空（不清空时同一枚文件不会再触发 change）');
  assert.equal(app.callsTo('files/upload/init').length, 1, '这一趟真的走了上传链');
});

test('F5 非空化：拆掉 onclick → F1 红；去掉 peer 实参 → F2 红（之后还原）', async () => {
  const clickAnchor = 'dmAttachBtn.onclick = () => { dmPick.click(); };';
  assert.ok(PANEL_SCRIPT.includes(clickAnchor), '点击绑定必须真的在脚本里');
  const noClick = PANEL_SCRIPT.replace(clickAnchor, '');
  assert.notEqual(noClick, PANEL_SCRIPT, '变异必须真的改到脚本');
  const broken = await openPanel({ files: emptyFiles(), script: noClick });
  await openTab(broken, 'Dm');
  assert.equal(broken.byId('dshLpDmAttach').onclick, null, '撤掉绑定之后 onclick 是空的');
  assert.equal(broken.byId('dshLpDmPick').clicks, 0, '于是按钮点不动 —— F1 那条断言红');

  const peerAnchor = 'startUpload(picked, dmPeerId);';
  assert.ok(PANEL_SCRIPT.includes(peerAnchor), 'peer 实参必须真的在脚本里');
  const noPeer = PANEL_SCRIPT.replace(peerAnchor, 'startUpload(picked);');
  assert.notEqual(noPeer, PANEL_SCRIPT, '变异必须真的改到脚本');
  const drifted = await openPanel({ files: emptyFiles(), script: noPeer });
  await openTab(drifted, 'Dm');
  drifted.q('dshLpFilesPeer').value = 'peer-other-9999';
  dmChange(drifted, [makeFile('note.txt', 4, Buffer.from('ABCD'))]);
  await flush();
  assert.deepEqual(drifted.callsTo('files/upload/finish')[0].body, { uploadId: 'u-1', peerId: 'peer-other-9999' },
    '少了实参就跟伙伴页下拉走 —— 于是 F2 那条断言红');

  // 还原：原脚本仍然是「这段对话的 peer」
  const pristine = await openPanel({ files: emptyFiles() });
  await openTab(pristine, 'Dm');
  pristine.q('dshLpFilesPeer').value = 'peer-other-9999';
  dmChange(pristine, [makeFile('note.txt', 4, Buffer.from('ABCD'))]);
  await flush();
  assert.deepEqual(pristine.callsTo('files/upload/finish')[0].body, { uploadId: 'u-1', peerId: PEER_ID });
});
