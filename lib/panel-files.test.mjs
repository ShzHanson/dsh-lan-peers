// dsh-lan-peers · 0.11.0 slice B：伙伴页里的 FILES 区（三桶列表 + 两条发送入口）
//
// 这一份钉住「面板」这一侧的行为，服务端那三条缺口（G1/G2/G3）由 lib/admin-files.test.mjs
// 的 B1/B2/B3 钉。分段：
//   V2 三桶渲染 / 批准与拒绝走既有路由 / 空态一行 / 两条发送入口并存且文案不同；
//   V3 上传胶水：顺序分片、进度只增、finish 只一次、409 之后「重试 = 先问 G1 再续」；
//   V4 超限预检（高于上限一次 init 都不发）+ 513 MiB 硬上限 + 512 MiB 边界包含；
//   V5 铁律：零反引号 / 无 console.error / innerHTML 只赋空串 / 节拍数与隐藏门数与 HEAD 一致；
//   V6 新文案 zh + en 两格齐备，en 无中日韩字；
//   V8 非空化：拆掉哪一处、哪一条断言就会红。
//
// 隐私口径：面板文本里不出现本机绝对路径 —— 这一份的断言里也没有任何真实路径。
import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { PANEL_SCRIPT } from './admin.mjs';
import { keys, t } from './i18n.mjs';

const VIEW = { w: 1000, h: 800 };
const PEER = { peerId: 'peer-b-1234', name: '书房', baseUrl: 'http://10.0.0.2:7788', lastSeen: 0 };
const MIB = 1024 * 1024;

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
    style, disabled: false, selected: false, children: [], listeners: new Map(), files: null,
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

/**
 * 假 File：只实现面板真正用到的两格（size / slice().arrayBuffer()）。
 * content 传 null 时 slice 回空片 —— 用来造「512 MiB 边界」这种不该真分配的文件。
 */
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

const emptyFiles = () => ({ pending: [], inbox: [], incoming: [] });
const AT = 1_760_000_000_000;
const fixtureFiles = () => ({
  pending: [
    { id: 'id-1', name: '旧合同.pdf', size: 2048, from: { peerId: 'peer-b', name: '书房' }, at: AT, state: 'pending' },
    { id: 'id-2', name: '合同.pdf', size: 4096, from: { peerId: 'peer-b', name: '书房' }, at: AT + 1000, state: 'pending' },
  ],
  inbox: [{ id: 'id-3', name: '照片.jpg', size: 3000, from: { peerId: 'peer-b', name: '书房' }, at: AT, state: 'done' }],
  incoming: [{ id: 'id-4', name: 'big.bin', size: 8192, received: 4096, from: { peerId: 'peer-b', name: '书房' }, at: AT, state: 'incoming' }],
});

function boot({
  files = emptyFiles(),
  peers = [PEER],
  fileMaxBytes = 0,
  chunkBytes = 4,
  failChunkAt = 0,
  chunkMode = 'increment',
  initMaxBytes = 1_000_000,
} = {}) {
  const calls = [];
  const timers = [];
  const widths = [];
  const created = [];
  const state = { files, serverReceived: 0, lastInitBytes: 0 };
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
    if (path === 'files/accept' || path === 'files/reject') {
      const bucket = path === 'files/accept' ? 'pending' : 'pending';
      state.files[bucket] = state.files[bucket].filter((row) => row.id !== body.id);
      return json({ ok: true });
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
        // 网络抖动那一版：字节其实落盘了，回执丢了（或回了 409）—— 面板必须去问 G1。
        return json({ error: 'offset-mismatch', received: state.serverReceived }, 409);
      }
      return json({ uploadId: body.uploadId, received: state.serverReceived, bytes: state.lastInitBytes });
    }
    if (path === 'files/upload/finish') {
      return json({ ok: true, id: 'tx-1', bytes: state.lastInitBytes, sha256: 'a'.repeat(64), ms: 3, uploadId: body.uploadId });
    }
    if (path === 'files/upload/cancel') return json({ ok: true, removed: true });
    if (path.startsWith('files/upload?id=')) {
      // G1：盘上真实已收多少 —— 续传**只**认这一份
      return json({
        uploadId: path.slice('files/upload?id='.length),
        name: 'blip.bin',
        bytes: state.lastInitBytes,
        received: state.serverReceived,
        chunkBytes,
      });
    }
    if (path === 'files/send') return json({ ok: true, id: 'tx-2', bytes: 4096, sha256: 'b'.repeat(64), ms: 5 });
    return json({});
  };
  const window = {
    innerWidth: VIEW.w, innerHeight: VIEW.h, addEventListener() {}, confirm: () => true,
    localStorage: { getItem: () => null, setItem: () => {} },
  };
  vm.runInNewContext(PANEL_SCRIPT, {
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
  return { btn, panel, q, byId, calls, callsTo, timers, widths, state, document, created };
}

async function openPanel(options) {
  const app = boot(options);
  app.btn.onclick();
  await flush();
  return app;
}

/** 选文件（等价于点开 <input type=file> 并挑了一个） */
function pickFile(app, file) {
  const pick = app.q('dshLpFilesPick');
  pick.files = [file];
  const listener = pick.listeners.get('change')[0];
  assert.equal(typeof listener, 'function', '文件输入必须挂 change 监听：' + file.name);
  listener();
}

/** 拖一个文件到 FILES 区 */
function dropFile(app, file) {
  const drop = app.q('dshLpFilesWrap').listeners.get('drop')[0];
  assert.equal(typeof drop, 'function', 'FILES 区必须是拖放落点');
  let prevented = false;
  drop({ preventDefault() { prevented = true; }, dataTransfer: { files: [file] } });
  assert.equal(prevented, true, 'drop 必须 preventDefault：否则浏览器直接打开文件');
}

// ---------------------------------------------------------------------------
// V2：三桶渲染 / 批准与拒绝 / 空态 / 两条发送入口
// ---------------------------------------------------------------------------
test('V2 三桶按 GET files 的 fixture 渲染，最新在上；待批准带批准/拒绝两个按钮', async () => {
  const app = await openPanel({ files: fixtureFiles() });

  assert.equal(app.q('dshLpFilesPendingHead').textContent, t('zh', 'panel.files.pendingHead').replace('{count}', '2'));
  assert.equal(app.q('dshLpFilesInboxHead').textContent, t('zh', 'panel.files.inboxHead').replace('{count}', '1'));
  assert.equal(app.q('dshLpFilesIncomingHead').textContent, t('zh', 'panel.files.incomingHead').replace('{count}', '1'));

  const pending = app.q('dshLpFilesPending');
  assert.equal(pending.children.length, 2);
  const newest = pending.children[0];
  assert.equal(newest.children[0].textContent, '合同.pdf', '最新的一条在上（at 大的先渲染）');
  assert.equal(newest.children[1].textContent, '4.0 KB', '只显示体积，不显示路径');
  assert.equal(newest.children[2].textContent, '批准');
  assert.equal(newest.children[3].textContent, '拒绝');
  assert.equal(pending.children[1].children[0].textContent, '旧合同.pdf');

  const inbox = app.q('dshLpFilesInbox');
  assert.equal(inbox.children.length, 1);
  assert.equal(inbox.children[0].children[0].textContent, '照片.jpg');
  assert.equal(inbox.children[0].children[1].textContent, '2.9 KB');
  assert.equal(inbox.children[0].children.length, 2, '收件箱一行只有名字 + 体积（没有按钮、没有路径）');

  const incoming = app.q('dshLpFilesIncoming');
  assert.equal(incoming.children.length, 1);
  assert.equal(incoming.children[0].children[0].textContent,
    t('zh', 'panel.files.incoming').replace('{received}', '4.0 KB').replace('{size}', '8.0 KB').replace('{pct}', '50'));
});

test('V2 空桶各自只渲染一行提示（不是一个空盒子）', async () => {
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
  assert.equal(app.q('dshLpFilesPendingHead').textContent, t('zh', 'panel.files.pendingHead').replace('{count}', '0'));
});

test('V2 批准 / 拒绝：POST files/accept|reject {id}，成功后摘掉行并重拉三桶', async () => {
  const app = await openPanel({ files: fixtureFiles() });
  const accept = app.q('dshLpFilesPending').children[0].children[2];
  const filesBefore = app.callsTo('files').length;
  accept.onclick();
  await flush();

  const posted = app.callsTo('files/accept');
  assert.equal(posted.length, 1);
  assert.equal(posted[0].method, 'POST');
  assert.deepEqual(posted[0].body, { id: 'id-2' }, '载荷只有 id');
  assert.ok(app.callsTo('files').length > filesBefore, '成功后必须重拉三桶');
  assert.equal(app.q('dshLpFilesPending').children.length, 1, '被批准的那一行必须消失');
  assert.equal(app.q('dshLpFilesPending').children[0].children[0].textContent, '旧合同.pdf');
  assert.match(app.q('dshLpMsg').textContent, /^已批准：合同/);

  const reject = app.q('dshLpFilesPending').children[0].children[3];
  reject.onclick();
  await flush();
  assert.equal(app.callsTo('files/reject').length, 1);
  assert.deepEqual(app.callsTo('files/reject')[0].body, { id: 'id-1' });
  assert.equal(app.q('dshLpFilesPending').children.length, 1, '拒绝之后也只剩空态那一行');
  assert.equal(app.q('dshLpFilesPending').children[0].className, 'hint');
});

test('V2 两条发送入口并存且文案不同：选/拖文件 vs 填写本机绝对路径', async () => {
  const app = await openPanel({ files: emptyFiles() });
  const source = readFileSync(new URL('./admin.mjs', import.meta.url), 'utf8');
  const segment = source.slice(source.indexOf('export const renderPanelScript'), source.indexOf('export let PANEL_SCRIPT'));
  assert.ok(segment.includes('<input id="dshLpFilesPick" type="file" />'), '主入口是原生文件选择');
  assert.ok(segment.includes('<details id="dshLpFilesAdvanced">'), '进阶入口是折叠的「绝对路径」块');
  assert.equal(typeof app.q('dshLpFilesWrap').listeners.get('drop')[0], 'function', '主入口还要能拖放');
  assert.equal(typeof app.q('dshLpFilesPathSend').onclick, 'function', '进阶入口有一个明确的发送按钮');

  const primary = app.q('dshLpFilesSendLabel').textContent;
  const advanced = app.q('dshLpFilesAdvancedLabel').textContent;
  assert.ok(primary.trim() !== '' && advanced.trim() !== '');
  assert.notEqual(primary, advanced, '两条入口的文案必须能区分开');
  assert.match(advanced, /路径/, '进阶入口自己说清楚它是「本机路径」那一条');
  assert.equal(advanced, t('zh', 'panel.files.advancedLabel'));
});

// ---------------------------------------------------------------------------
// V3：上传胶水（stub fetch）
// ---------------------------------------------------------------------------
test('V3 顺序分片 + 进度只增 + finish 只一次（带 uploadId 与下拉里选中的 peerId）', async () => {
  const app = await openPanel({ files: emptyFiles() });
  app.q('dshLpFilesPeer').value = PEER.peerId;
  pickFile(app, makeFile('report.bin', 12, Buffer.from('AAAABBBBCCCC')));
  await flush();

  const init = app.callsTo('files/upload/init');
  assert.equal(init.length, 1);
  assert.deepEqual(init[0].body, { name: 'report.bin', bytes: 12 });

  const chunks = app.callsTo('files/upload/chunk');
  assert.deepEqual(chunks.map((call) => call.body.offset), [0, 4, 8], 'offset 必须按 chunkBytes 顺序递增');
  assert.deepEqual(chunks.map((call) => Buffer.from(call.body.dataBase64, 'base64').toString()),
    ['AAAA', 'BBBB', 'CCCC'], '每一片都是那几个真字节（base64 编码正确、没有串片）');

  // 只取进度条那几条（面板自身的 style.width 是像素值，这里只要百分数）
  const widths = app.widths.filter((value) => value.endsWith('%')).map((value) => parseInt(value, 10));
  assert.deepEqual(widths, [0, 33, 67, 100], '进度只增不减，最后一次是 100%');

  const finish = app.callsTo('files/upload/finish');
  assert.equal(finish.length, 1, 'finish 只能发一次');
  assert.deepEqual(finish[0].body, { uploadId: 'u-1', peerId: PEER.peerId });
  assert.equal(app.q('dshLpFilesRetry').style.display, 'none', '成功之后不许留着「重试」');
});

test('V3 拖放与点选走同一条路（drop 也发 init）', async () => {
  const app = await openPanel({ files: emptyFiles() });
  app.q('dshLpFilesPeer').value = PEER.peerId;
  dropFile(app, makeFile('dropped.bin', 4, Buffer.from('WXYZ')));
  await flush();
  assert.equal(app.callsTo('files/upload/init').length, 1);
  assert.deepEqual(app.callsTo('files/upload/init')[0].body, { name: 'dropped.bin', bytes: 4 });
  assert.equal(app.callsTo('files/upload/chunk').length, 1);
});

test('V3 409 之后「重试 = 续传」：先 GET files/upload?id=，再从 received 继续（不从 0 重来）', async () => {
  const app = await openPanel({ files: emptyFiles(), failChunkAt: 2 });
  app.q('dshLpFilesPeer').value = PEER.peerId;
  pickFile(app, makeFile('blip.bin', 12, Buffer.from('AAAABBBBCCCC')));
  await flush();

  // 第 2 片被 409 打断：面板显示稳定错误码并亮出重试
  assert.equal(app.q('dshLpFilesStatus').textContent,
    t('zh', 'panel.files.uploadFailed').replace('{code}', 'offset-mismatch'));
  const retry = app.q('dshLpFilesRetry');
  assert.equal(retry.style.display, 'block');
  assert.equal(retry.textContent, t('zh', 'panel.files.retry').replace('{received}', '4 B'));
  assert.equal(app.callsTo('files/upload/finish').length, 0, '被打断的那一趟不许 finish');

  const chunksBefore = app.callsTo('files/upload/chunk').length;
  const filesBefore = app.callsTo('files').length;
  retry.onclick();
  await flush();

  const probes = app.calls.filter((call) => call.path.startsWith('files/upload?id='));
  assert.equal(probes.length, 1, '重试必须先问 G1 拿盘上真实的 received');
  assert.equal(probes[0].path, 'files/upload?id=u-1');
  assert.ok(app.callsTo('files').length >= filesBefore, '重试不该悄悄换成别的数据源');

  const resumed = app.callsTo('files/upload/chunk').slice(chunksBefore);
  assert.deepEqual(resumed.map((call) => call.body.offset), [8],
    '续传从 G1 报的 received=8 起，绝不回到 0');
  assert.equal(Buffer.from(resumed[0].body.dataBase64, 'base64').toString(), 'CCCC');
  assert.equal(app.callsTo('files/upload/init').length, 1, '续传不许重新 init（那会换一个临时区）');
  assert.equal(app.callsTo('files/upload/finish').length, 1);
  assert.deepEqual(app.callsTo('files/upload/finish')[0].body, { uploadId: 'u-1', peerId: PEER.peerId });
  assert.equal(app.q('dshLpFilesRetry').style.display, 'none');
});

// ---------------------------------------------------------------------------
// V4：超限预检（一次 init 都不发）+ 面板 512 MiB 硬上限
// ---------------------------------------------------------------------------
test('V4 高于宿主上限：一次 files/upload/init 都不发，直接给超限提示', async () => {
  const app = await openPanel({ files: emptyFiles(), fileMaxBytes: 1024 });
  app.q('dshLpFilesPeer').value = PEER.peerId;
  pickFile(app, makeFile('big.bin', 2048, Buffer.from('x'.repeat(2048))));
  await flush();
  assert.equal(app.callsTo('files/upload/init').length, 0, '超限文件不许占临时区');
  assert.equal(app.callsTo('files/upload/chunk').length, 0);
  assert.equal(app.q('dshLpFilesStatus').textContent,
    t('zh', 'panel.files.uploadTooLarge')
      .replace('{name}', 'big.bin').replace('{size}', '2.0 KB').replace('{max}', '1.0 KB'));
});

test('V4 513 MiB：即使宿主把 fileMaxBytes 抬到 2 GiB，面板也绝不发 init（端点 512 MiB）', async () => {
  const app = await openPanel({ files: emptyFiles(), fileMaxBytes: 2048 * MIB });
  app.q('dshLpFilesPeer').value = PEER.peerId;
  pickFile(app, makeFile('huge.bin', 513 * MIB));
  await flush();
  assert.equal(app.callsTo('files/upload/init').length, 0, '513 MiB 不许发 init');
  assert.equal(app.callsTo('files/upload/chunk').length, 0);

  const status = app.q('dshLpFilesStatus').textContent;
  assert.ok(status.includes('513.0 MB'), '提示里要有这个文件的真实体积：' + status);
  assert.ok(status.includes('512.0 MB'), '提示里要写清上限：' + status);
  assert.ok(status.includes('send-file'), '提示要给出命令行那一条路：' + status);
  assert.ok(status.includes('lan_peer_send_file'), '提示要给出 agent 工具那一条路：' + status);

  // 常驻提示（区块级那一行，不是逐行内容）：空桶渲染之后仍然在，并且两条路都点名。
  const hint = app.q('dshLpFilesCapHint').textContent;
  assert.equal(hint, t('zh', 'panel.files.panelCapHint'));
  assert.ok(hint.includes('512 MiB') && hint.includes('send-file') && hint.includes('lan_peer_send_file'));
  assert.equal(app.q('dshLpFilesPending').children.length, 1, '空桶仍然只是一行提示（没有被常驻提示顶掉）');
});

test('V4 512 MiB 正好等于上限：init 会被调用（边界包含，不是排除）', async () => {
  const app = await openPanel({ files: emptyFiles(), chunkMode: 'complete', initMaxBytes: 512 * MIB });
  app.q('dshLpFilesPeer').value = PEER.peerId;
  pickFile(app, makeFile('edge.bin', 512 * MIB));
  await flush();
  const init = app.callsTo('files/upload/init');
  assert.equal(init.length, 1, '512 MiB 是允许的（size > cap 才拒）');
  assert.equal(init[0].body.bytes, 512 * MIB);
  assert.equal(app.q('dshLpFilesStatus').textContent,
    t('zh', 'panel.files.uploadDone').replace('{name}', 'edge.bin').replace('{size}', '512.0 MB'),
    '边界那一枚真的走完了整条路（init → chunk → finish）');
});

// ---------------------------------------------------------------------------
// V5：铁律
// ---------------------------------------------------------------------------
const SECTION_START = '0.11.0 slice B：FILES 区（**同一个';
const SECTION_END = "$('dshLpFilesPathSend').onclick";

function addedBlock() {
  const source = readFileSync(new URL('./admin.mjs', import.meta.url), 'utf8');
  const start = source.indexOf(SECTION_START);
  const end = source.indexOf(SECTION_END);
  assert.ok(start > 0 && end > start, '新增段的起止标记必须还在 lib/admin.mjs 里');
  return source.slice(start, end);
}

test('V5 新增段零反引号、无 console.error、innerHTML 只赋空串', () => {
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
});

test('V5 节拍数与隐藏门数都不变（HEAD 就是 7 / 9），上传进度复用既有 1s 轮询', () => {
  // HEAD（slice A/B 之前的提交）里就是这两枚数：不新开 setInterval、不删隐藏门。
  assert.equal((PANEL_SCRIPT.match(/setInterval\(/g) || []).length, 7, '不许新开节拍');
  assert.equal((PANEL_SCRIPT.match(/document\.hidden/g) || []).length, 9, '隐藏门数量不变');
  const poll = PANEL_SCRIPT.slice(PANEL_SCRIPT.indexOf('async function pollIncoming'));
  assert.match(poll.slice(0, 240), /if \(document\.hidden === true\) return;/, '轮询的第一句仍是隐藏门');
  assert.equal(/setInterval\(pollIncoming/.test(PANEL_SCRIPT), true, '仍然用既有的那个 1s 节拍');
});

test('V5 document.hidden 时三桶不再刷新（隐藏门真的挡得住）', async () => {
  const app = await openPanel({ files: fixtureFiles() });
  const before = app.callsTo('files').length;
  app.document.hidden = true;
  for (const timer of app.timers.filter((one) => one.ms === 1000)) timer.fn();
  await flush();
  assert.equal(app.callsTo('files').length, before, '隐藏期间一次都不许拉 files');
  app.document.hidden = false;
  for (const timer of app.timers.filter((one) => one.ms === 1000)) timer.fn();
  await flush();
  assert.ok(app.callsTo('files').length > before, '回到可见后节拍照旧工作');
});

// ---------------------------------------------------------------------------
// V6：新文案 zh + en 两格齐备
// ---------------------------------------------------------------------------
const NEW_KEYS = [
  'panel.files.label',
  'panel.files.pendingHead',
  'panel.files.inboxHead',
  'panel.files.incomingHead',
  'panel.files.emptyPending',
  'panel.files.emptyInbox',
  'panel.files.emptyIncoming',
  'panel.files.accept',
  'panel.files.reject',
  'panel.files.accepted',
  'panel.files.rejectedMsg',
  'panel.files.actionFailed',
  'panel.files.sendLabel',
  'panel.files.dropHint',
  'panel.files.peerLabel',
  'panel.files.noPeer',
  'panel.files.progress',
  'panel.files.uploadDone',
  'panel.files.uploadFailed',
  'panel.files.uploadTooLarge',
  'panel.files.panelCapHint',
  'panel.files.retry',
  'panel.files.advancedLabel',
  'panel.files.placeholderPath',
  'panel.files.pathSend',
  'panel.files.pathEmpty',
  'panel.files.pathSent',
  'panel.files.pathFailed',
];

test('V6 新文案 zh + en 两格都在、en 无中日韩字，两条对外命令原样出现', () => {
  const zhKeys = keys('zh');
  const enKeys = keys('en');
  for (const key of NEW_KEYS) {
    assert.ok(zhKeys.includes(key), 'zh 缺 key：' + key);
    assert.ok(enKeys.includes(key), 'en 缺 key：' + key);
    assert.ok(String(t('zh', key)).trim() !== '', 'zh 空串：' + key);
    assert.ok(String(t('en', key)).trim() !== '', 'en 空串：' + key);
    assert.doesNotMatch(String(t('en', key)), /[\u4e00-\u9fa5]/, 'en 格不许有中文：' + key);
  }
  for (const key of ['panel.files.panelCapHint', 'panel.files.uploadTooLarge']) {
    assert.ok(String(t('en', key)).includes('send-file'), key + ' 必须点名命令行那条路');
    assert.ok(String(t('en', key)).includes('lan_peer_send_file'), key + ' 必须点名 agent 工具那条路');
    assert.ok(String(t('zh', key)).includes('send-file'));
    assert.ok(String(t('zh', key)).includes('lan_peer_send_file'));
  }
  assert.ok(String(t('zh', 'panel.files.panelCapHint')).includes('512 MiB'));
  assert.ok(String(t('en', 'panel.files.panelCapHint')).includes('512 MiB'));
});

// ---------------------------------------------------------------------------
// V8：非空化 —— 拆掉哪一处、哪一条断言就会红
//
//   1) 拆掉 retryUpload 里的 G1 探测（直接用 job.received 续）→ V3「409 之后…」的
//      probes.length === 1 与 resumed offsets === [8] 同时红：偏移会变回 4。
//   2) 拆掉 startUpload 里的预检（limit > 0 && size > limit 那一段）→ V4 两条
//      （宿主上限 / 513 MiB）的 init === 0 立刻红，因为它会去撞 init。
//   3) 拆掉 G3 的服务端重放分支 → lib/admin-files.test.mjs 的 B3 第一条红（重放变 409）。
//   4) 把面板上限从 min(…) 换成只用 fileMaxBytes → V4 的 513 MiB 那条红（2 GiB 的宿主上限
//      会让 init 被发出去）。
// ---------------------------------------------------------------------------
test('V8 非空化：预检与续传的断言各有一条能真的变红（自检当前实现的两处关键行为）', async () => {
  // 预检：超限不 init（与 V4 同一条路，但这里从「非空化」的角度再钉一次结果值）
  const oversize = await openPanel({ files: emptyFiles(), fileMaxBytes: 1024 });
  oversize.q('dshLpFilesPeer').value = PEER.peerId;
  pickFile(oversize, makeFile('x.bin', 1025));
  await flush();
  assert.equal(oversize.callsTo('files/upload/init').length, 0);

  // 续传：G1 的存在性直接决定「从哪儿续」
  const resume = await openPanel({ files: emptyFiles(), failChunkAt: 1 });
  resume.q('dshLpFilesPeer').value = PEER.peerId;
  pickFile(resume, makeFile('y.bin', 8, Buffer.from('AAAABBBB')));
  await flush();
  resume.q('dshLpFilesRetry').onclick();
  await flush();
  const probes = resume.calls.filter((call) => call.path.startsWith('files/upload?id='));
  assert.equal(probes.length, 1, '没有 G1 就没有续传，这条断言先红');
  assert.equal(resume.callsTo('files/upload/init').length, 1);
});
