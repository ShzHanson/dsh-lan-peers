// dsh-lan-peers · v0.8.5-α（契约 §6）面板文案的注入、语言切换与回落。
//
// 面板是直出脚本，不能 import lib/i18n.mjs：admin.mjs 在渲染时把两种语言的
// panel.* 字面量整份嵌进脚本（PANEL_I18N_JSON），用哪一格由 resolveLang(config) 决定。
// 本文件在源码层与运行层两头兜住：
//   1. lang=zh / lang=en 各生成一份，页签与按钮文案真的跟着换（不是浏览器猜的）；
//   2. 注入表覆盖全部 panel.* key，两格都是非空字符串，绝不出现 undefined；
//   3. 回落链：本语言格 → 英文格 → key 本身（两格都缺时显示 key 名，不抛错）；
//   4. 面板段除注入表与注释外没有硬编码中文；
//   5. 铁律：零 console 错误调用；innerHTML 只赋空串或静态骨架，且永不插值。
import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { PANEL_SCRIPT, renderPanelScript } from './admin.mjs';
import { readFileSync } from 'node:fs';
import { PANEL_BATCH2_KEYS, keys, resolveLang, t } from './i18n.mjs';

const CJK = /[\u4e00-\u9fff]/;

// 与 panel-dm / panel-group 同款的最小 DOM 桩：面板脚本只碰这些接口。
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

// 执行一份渲染好的面板脚本，返回面板节点与按 id 取文案的小工具。
function runScript(script) {
  const document = {
    head: makeElement('head'),
    body: makeElement('body'),
    hidden: false,
    createElement: (tag) => makeElement(tag),
  };
  const window = {
    innerWidth: 1000, innerHeight: 800, addEventListener() {}, confirm: () => true,
    localStorage: { getItem: () => null, setItem: () => {} },
  };
  vm.runInNewContext(script, {
    window, document, localStorage: window.localStorage,
    fetch: async () => ({ ok: true, status: 200, json: async () => ({}) }),
    setInterval: () => 1, clearInterval: () => {},
    setTimeout: () => 0, clearTimeout: () => {},
    JSON, Math, Promise, console,
  });
  const panel = document.body.children.find((el) => el.id === 'dshLpPanel');
  assert.ok(panel, '面板节点必须挂进 document.body');
  return { panel, text: (id) => panel.querySelector('#' + id).textContent };
}

// 脚本里的注入表就是那一行 JSON，直接解析回来核对。
function tableOf(script) {
  const line = script.split('\n').find((item) => item.includes('const I18N = {'));
  assert.ok(line, '脚本里必须有注入表');
  return JSON.parse(line.slice(line.indexOf('{'), line.lastIndexOf('}') + 1));
}

// 改注入表再回填脚本：用来制造「缺格」，测回落链。
function withTable(script, mutate) {
  return script.split('\n').map((line) => {
    if (!line.includes('const I18N = {')) return line;
    const table = JSON.parse(line.slice(line.indexOf('{'), line.lastIndexOf('}') + 1));
    mutate(table);
    return '  const I18N = ' + JSON.stringify(table) + ';';
  }).join('\n');
}

// 剥掉注入表那一行与注释：剩下的才是「硬编码文案」的候选。
function bare(script) {
  return script.split('\n')
    .filter((line) => {
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*')) return false;
      return !line.includes('const I18N = {');
    })
    .map((line) => line.replace(/\s\/\/.*$/, '').replace(/\/\*.*?\*\//g, ''))
    .join('\n');
}

test('lang=zh：I18N_LANG 取 zh 格，页签与按钮渲染中文', () => {
  const script = renderPanelScript('tok-zh', 'zh');
  assert.match(script, /const I18N_LANG = 'zh';/);
  const app = runScript(script);
  assert.equal(app.text('dshLpTabPeers'), '伙伴');
  assert.equal(app.text('dshLpTabGroup'), '群组');
  assert.equal(app.text('dshLpTabDm'), '私聊');
  assert.equal(app.text('dshLpTabSettings'), '设置');
  assert.equal(app.text('dshLpGroupSend'), t('zh', 'panel.common.send'));
  assert.ok(CJK.test(app.text('dshLpGroupSend')), '群发按钮是中文文案，不是空按钮');
  assert.doesNotMatch(app.text('dshLpTabPeers'), /^panel\./, '文案不许漏成 key 名');
});

test('lang=en：I18N_LANG 取 en 格，同一批节点换成英文', () => {
  const script = renderPanelScript('tok-en', 'en');
  assert.match(script, /const I18N_LANG = 'en';/);
  const app = runScript(script);
  assert.equal(app.text('dshLpTabPeers'), 'Peers');
  assert.equal(app.text('dshLpTabGroup'), 'Group');
  assert.equal(app.text('dshLpTabDm'), 'DM');
  assert.equal(app.text('dshLpTabSettings'), 'Settings');
  assert.equal(app.text('dshLpGroupSend'), t('en', 'panel.common.send'));
  assert.doesNotMatch(app.text('dshLpTabSettings'), CJK, 'en 下页签不许是中文');
  const zhApp = runScript(renderPanelScript('tok-zh', 'zh'));
  assert.notEqual(app.text('dshLpTabPeers'), zhApp.text('dshLpTabPeers'), '两种语言必须真的不同');
});

test('注入表两格都齐：全部 panel.* key 都是非空字符串，绝无 undefined', () => {
  const script = renderPanelScript('tok-en', 'en');
  const table = tableOf(script);
  const panelKeys = keys('zh').filter((key) => key.startsWith('panel.'));
  assert.ok(panelKeys.length >= 200, '面板词表规模不该缩水，实际 ' + panelKeys.length);
  for (const lang of ['zh', 'en']) {
    assert.ok(table[lang] && typeof table[lang] === 'object', lang + ' 格必须存在');
    for (const key of panelKeys) {
      const value = table[lang][key];
      assert.equal(typeof value, 'string', lang + ' 缺 key：' + key);
      assert.notEqual(value, '', lang + ' 空字符串：' + key);
      assert.notEqual(value, 'undefined', lang + ' 字面 undefined：' + key);
    }
  }
  // 第一批 80 条译文合并前只有 zh 格的那些 key，现在英文格必须没有中文残留。
  const merged = [
    'panel.title', 'panel.tab.files', 'panel.common.send', 'panel.common.unknown',
    'panel.peers.columnName', 'panel.peers.empty', 'panel.dm.body', 'panel.files.pending',
    'panel.group.role', 'panel.group.unnamed', 'panel.group.leader',
  ];
  for (const key of merged) {
    assert.doesNotMatch(String(table.en[key]), CJK, 'en 格仍是中文：' + key);
  }
});

test('缺 key 回落：本语言缺格取英文，英文也缺就显示 key 名（不 undefined、不抛错）', () => {
  const english = t('en', 'panel.tab.peers');
  const dropZh = withTable(renderPanelScript('tok-zh', 'zh'), (table) => {
    delete table.zh['panel.tab.peers'];
  });
  assert.equal(runScript(dropZh).text('dshLpTabPeers'), english, 'zh 缺格要回落到英文格');
  const dropBoth = withTable(renderPanelScript('tok-en', 'en'), (table) => {
    delete table.zh['panel.tab.peers'];
    delete table.en['panel.tab.peers'];
  });
  const text = runScript(dropBoth).text('dshLpTabPeers');
  assert.equal(text, 'panel.tab.peers', '两格都缺时显示 key 本身');
  assert.doesNotMatch(String(text), /undefined/, '绝不能把 undefined 写到屏幕上');
});

// 唯一允许硬编码中文的一行：语言下拉的三个选项本身就是语言名（中文 / English / 自动）。
// 整行必须与这份名单逐字一致 —— 于是「顺手再写一句中文」仍然会红。
const LANG_OPTIONS_LINE = "const LANG_OPTIONS = [['zh', '中文'], ['en', 'English'], ['auto', '自动 / Auto']];";

test('面板段除注入表、注释与语言名选项外没有硬编码中文', () => {
  for (const lang of ['zh', 'en']) {
    const lines = bare(renderPanelScript('tok-' + lang, lang)).split('\n');
    const optionLines = lines.filter((line) => line.trim().startsWith('const LANG_OPTIONS ='));
    assert.equal(optionLines.length, 1, lang + ' 页面里语言名选项行必须唯一且存在');
    assert.equal(optionLines[0].trim(), LANG_OPTIONS_LINE, '选项文字只允许是这三个语言名');
    const hits = lines.filter((line) => line.trim() !== LANG_OPTIONS_LINE && CJK.test(line));
    assert.deepEqual(hits.slice(0, 5), [], lang + ' 面板段仍有硬编码中文');
  }
});

test('铁律扫描：零 console 错误调用，innerHTML 只赋空串或静态骨架、永不插值', () => {
  const script = renderPanelScript('tok-zh', 'zh');
  assert.equal((script.match(/console[.]error/g) || []).length, 0, '面板段不许新增 console 错误调用');
  const lines = bare(script).split('\n').filter((line) => line.includes('innerHTML'));
  assert.ok(lines.length >= 5, '面板本来就用 innerHTML 清容器');
  for (const line of lines) {
    const trimmed = line.trim();
    assert.doesNotMatch(trimmed, /innerHTML\s*\+=/, '不许 innerHTML +=：' + trimmed);
    assert.ok(!trimmed.includes('$' + '{'), 'innerHTML 不许插值：' + trimmed);
    assert.ok(/innerHTML\s*=\s*(?:''|[\u0060])/.test(trimmed), '只允许赋空串或静态骨架：' + trimmed);
  }
});

test('语言来自 resolveLang(config)：config 与 env 两条路都能换语言', () => {
  assert.equal(resolveLang({ lang: 'en' }), 'en');
  assert.equal(resolveLang({ lang: 'zh' }), 'zh');
  assert.equal(resolveLang({ lang: 'en-US' }), 'en', '带地区后缀也算命中');
  const previous = process.env.DSH_LAN_PEERS_LANG;
  process.env.DSH_LAN_PEERS_LANG = 'en';
  try {
    assert.equal(resolveLang({}), 'en');
    const script = renderPanelScript('tok-env', resolveLang({}));
    assert.match(script, /const I18N_LANG = 'en';/);
    assert.equal(runScript(script).text('dshLpTabPeers'), 'Peers');
  } finally {
    if (previous === undefined) delete process.env.DSH_LAN_PEERS_LANG;
    else process.env.DSH_LAN_PEERS_LANG = previous;
  }
  assert.match(PANEL_SCRIPT, /const I18N_LANG = 'zh';/, '模块加载时那份走默认语言');
});

// ---------------------------------------------------------------------------
// 铁律的两条量化证据（第二批补）。上面的扫描是「整段有没有」，这里按段落切片计数，
// 并把协议 token 与词表彻底分开：它们来自变量，进词表就等于把协议值翻译坏了。
// ---------------------------------------------------------------------------
const SRC = readFileSync(new URL('./admin.mjs', import.meta.url), 'utf8');
const BT = String.fromCharCode(96);

function sliceOf(startMark, endMark) {
  const start = SRC.indexOf(startMark);
  const end = SRC.indexOf(endMark, start + 1);
  assert.ok(start > 0, '切片起点必须在源码里：' + startMark);
  assert.ok(end > start, '切片终点必须在源码里：' + endMark);
  return SRC.slice(start, end);
}

const REGIONS = [
  ['注入段（I18N / I18N_LANG / LT）', '  const I18N = ', '  // 0.8.5-α 真机 bug'],
  ['骨架文案回填（SKEL_TEXT / SKEL_PLACEHOLDER）', '  const SKEL_TEXT = {', '  // Draggable launcher.'],
  ['伙伴页（renderPeers / renderJobs / 倒计时）', '  function renderPeers(', '  async function refresh('],
  ['归档 / 待批准 / 申请（renderArchives → decideApplication）', '  function renderArchives(', '  function seqOrNull('],
  ['群组页（appendMessages / renderGroup / renderLeader）', '  function appendMessages(', '  function pollGroup('],
  ['私聊页（DM 页构造 → selectDmPeer）', '  const dmPage = document.createElement', '  function stopDmPoll('],
  ['操作入口（保存 / 配对 / 发消息 / 接单 / 查找 / 广播）', "  $('dshLpSaveName').onclick", '  window.addEventListener('],
];

test('面板段零反引号：按段落切片计数（不是目测）', () => {
  const counts = {};
  for (const [name, start, end] of REGIONS) {
    counts[name] = sliceOf(start, end).split(BT).length - 1;
  }
  for (const name of Object.keys(counts)) assert.equal(counts[name], 0, name + ' 出现了反引号');
  // 整段只剩改造前就有的 6 个：外层模板字符串的开合 + CSS / 骨架那两对内层模板。
  const total = sliceOf('export const renderPanelScript = (token, lang', 'export let PANEL_SCRIPT')
    .split(BT).length - 1;
  assert.equal(total, 6, '反引号只允许改造前就有的那 6 个');
  for (const [name, start, end] of REGIONS) {
    assert.equal(sliceOf(start, end).includes('console.error'), false, name + ' 不得有 console.error');
  }
});

test('协议 token 不进词表：权限档 / @! / sha256 来自变量，不是文案', () => {
  const PROTOCOL = ['read-only', 'workspace-write', 'danger-full-access', 'auto', 'sha256', '@!', 'not-accepting'];
  for (const lang of ['zh', 'en']) {
    for (const key of keys(lang)) {
      const value = t(lang, key);
      for (const token of PROTOCOL) assert.notEqual(value, token, lang + ' 词表把协议 token 当文案了：' + key);
    }
  }
  // 权限三档照旧由 admin.mjs 的 DISPATCH_PERMISSIONS 注入，原样进脚本、原样上屏。
  assert.ok(PANEL_SCRIPT.includes('const PERMS = '), '权限档清单仍由 DISPATCH_PERMISSIONS 注入');
  assert.ok(PANEL_SCRIPT.includes('read-only'), '协议值原样出现在脚本里');
});

test('第二批 key 带统一标记，且每条都有非空 zh 值（en 先摊开同一份占位）', () => {
  assert.ok(PANEL_BATCH2_KEYS.length >= 150, '第二批 key 清单应当上百，实际 ' + PANEL_BATCH2_KEYS.length);
  const table = tableOf(renderPanelScript('tok-batch2', 'zh'));
  for (const key of PANEL_BATCH2_KEYS) {
    assert.ok(key.startsWith('panel.'), '第二批只铺面板域：' + key);
    assert.equal(typeof table.zh[key], 'string', '第二批缺 zh 值：' + key);
    assert.notEqual(table.zh[key], '', '第二批 zh 值不能是空串：' + key);
    assert.notEqual(table.en[key], '', 'en 格即使是占位也不能是空串：' + key);
  }
});

// ---------------------------------------------------------------------------
// out3 + out4 合并后的收口（0.8.5-α 第三批）：en 表里不许再有中文，也不许有
// 「看起来译过、其实与 zh 一字不差」的格子 —— 全角标点那类最容易被漏掉。
// ---------------------------------------------------------------------------
test('en 表零中文残留：正则扫 \u4e00-\u9fa5，白名单为空；英文值不得是空串', () => {
  const WHITELIST = [];
  assert.deepEqual(WHITELIST, [], '白名单必须为空：有例外就明说，不要藏在断言里');
  const hits = keys('en')
    .filter((key) => /[\u4e00-\u9fa5]/.test(String(t('en', key))))
    .filter((key) => !WHITELIST.includes(key));
  assert.deepEqual(hits, [], 'en 表仍有中文残留');
  const empty = keys('en').filter((key) => String(t('en', key)).trim() === '');
  assert.deepEqual(empty, [], 'en 表不许有空串');
});

test('第二批 165 条全部真译过：en 值不等于 zh 值（全角标点也不算译）', () => {
  // 0.10.0-α slice 4a：群纪要 10 条译文并入第二批（152 + 10），所以规模基线跟着走。
  assert.equal(PANEL_BATCH2_KEYS.length, 162, '第二批规模必须与译文对齐（152 + 10 条群纪要），实际 ' + PANEL_BATCH2_KEYS.length);
  const same = PANEL_BATCH2_KEYS.filter((key) => String(t('en', key)) === String(t('zh', key)));
  assert.deepEqual(same, [], '这些 key 的 en 与 zh 一字不差，等于没译');
  const cjk = PANEL_BATCH2_KEYS.filter((key) => /[\u4e00-\u9fa5]/.test(String(t('en', key))));
  assert.deepEqual(cjk, [], '第二批 en 格仍是中文');
});

// ---------------------------------------------------------------------------
// 第四批：面板源码里每个 LT(...) 的 key 都必须在 zh 与 en 两格里存在。
// 漏一笔不会抛错 —— LT 只是回落到 key 名本身，屏幕上就会冒出「panel.xxx.yyy」；
// 所以这条只能扫真源码（lib/admin.mjs），不许在测试里另抄一份 key 清单。
// ---------------------------------------------------------------------------
const ADMIN_SRC = readFileSync(new URL('./admin.mjs', import.meta.url), 'utf8');

function panelSegment() {
  const start = ADMIN_SRC.indexOf('export const renderPanelScript');
  const end = ADMIN_SRC.indexOf('export let PANEL_SCRIPT');
  assert.ok(start > 0 && end > start, '面板段起止标记必须还在 lib/admin.mjs 里');
  return ADMIN_SRC.slice(start, end);
}

function blockOf(text, marker) {
  const start = text.indexOf(marker);
  assert.ok(start > 0, '面板段里找不到：' + marker);
  const end = text.indexOf('};', start);
  assert.ok(end > start, '区块没有闭合：' + marker);
  return text.slice(start, end);
}

test('面板里每个 LT key 都能在 zh/en 两格取到：缺一条就点名列出', () => {
  const seg = panelSegment();
  // 字面量调用点：单引号与双引号两种写法都算。
  const literal = [
    ...[...seg.matchAll(/LT\(\s*'([^']+)'/g)].map((match) => match[1]),
    ...[...seg.matchAll(/LT\(\s*"([^"]+)"/g)].map((match) => match[1]),
  ];
  assert.ok(literal.length >= 200, '面板字面量调用点不该缩水，实际 ' + literal.length);

  // 动态拼 key 的调用点全部白名单化：不写清为什么，这条规则就能被绕过。
  const DYNAMIC_ALLOWED = {
    // 骨架回填：key 来自这两张表，表里的值由下面整表核一遍（不是在调用点硬编码）。
    SKEL_TEXT: '骨架文案表：值全部是 panel.* 字面量，下面整表核进 zh/en',
    SKEL_PLACEHOLDER: '骨架 placeholder 表：同上',
    // decidePending：上一行 const key = action === 'approve' ? '...approved' : '...rejected'，
    // 两个 key 都是字面量，这里只是透传变量；那两个值由下面那条扫描一并核。
    key: 'decidePending 的透传变量：取值行是三元字面量，由下面 const key 扫描一并核',
  };
  const dynamicHeads = [...new Set(
    [...seg.matchAll(/LT\(\s*([A-Za-z_$][A-Za-z0-9_$]*)/g)].map((match) => match[1]),
  )];
  const unknownDynamic = dynamicHeads.filter((head) => !Object.prototype.hasOwnProperty.call(DYNAMIC_ALLOWED, head));
  assert.deepEqual(unknownDynamic, [],
    '出现未白名单化的动态拼 key（先想清楚它凭什么躲得过字面量扫描）：' + unknownDynamic.join(' | '));

  // 白名单的两张骨架表：整表的值也要落进词表，否则白名单就是一条后门。
  for (const table of Object.keys(DYNAMIC_ALLOWED)) {
    if (table === 'key') continue;
    const block = blockOf(seg, 'const ' + table + ' = {');
    const tableKeys = [...block.matchAll(/:\s*'([^']+)'/g)].map((match) => match[1]);
    assert.ok(tableKeys.length >= 4, table + ' 的条目不该缩水，实际 ' + tableKeys.length);
    literal.push(...tableKeys);
  }
  // 透传变量的两个取值：只从 const key = ... 那一行里取，不手抄。
  for (const match of seg.matchAll(/const key = [^;]+;/g)) {
    // 只取像 key 的字符串：同一行里 'approve' 是 action 值，不是文案 key。
    for (const quoted of match[0].matchAll(/'([^']+)'/g)) {
      if (quoted[1].startsWith('panel.')) literal.push(quoted[1]);
    }
  }

  const used = [...new Set(literal)].sort();
  assert.ok(used.length >= 190, '扫到的 key 数量不该缩水，实际 ' + used.length);
  const zhKeys = new Set(keys('zh'));
  const enKeys = new Set(keys('en'));
  const missingZh = used.filter((key) => !zhKeys.has(key));
  const missingEn = used.filter((key) => !enKeys.has(key));
  assert.deepEqual(missingZh, [],
    '这些 key 在 zh 词表里不存在，面板会直接显示 key 名：' + missingZh.join(', '));
  assert.deepEqual(missingEn, [],
    '这些 key 在 en 词表里不存在，英文面板会直接显示 key 名：' + missingEn.join(', '));
});


// ---------------------------------------------------------------------------
// 0.10.0-α slice 4a：群纪要的文案（zh + en 各一份，en 不许有 CJK，也不许与 zh 一字不差）
// ---------------------------------------------------------------------------
test('4a N7：纪要文案 11 条在中英两格都在，en 无中文且与 zh 不同', () => {
  const NOTES_KEYS = [
    'panel.group.notesLabel',
    'panel.group.notesHead',
    'panel.group.notesEmpty',
    'panel.group.notesPlaceholder',
    'panel.group.notesAdd',
    'panel.group.notesAdded',
    'panel.group.notesAddFailed',
    'panel.group.notesEmptyInput',
    'panel.group.notesRowMeta',
    'panel.group.notesMemberHint',
  ];
  const zhKeys = keys('zh');
  const enKeys = keys('en');
  for (const key of NOTES_KEYS) {
    assert.equal(zhKeys.includes(key), true, 'zh 缺 key：' + key);
    assert.equal(enKeys.includes(key), true, 'en 缺 key：' + key);
    assert.notEqual(String(t('zh', key)).trim(), '', 'zh 空串：' + key);
    assert.notEqual(String(t('en', key)).trim(), '', 'en 空串：' + key);
    assert.equal(CJK.test(String(t('en', key))), false, 'en 格仍是中文：' + key);
  }
  // 占位符 key 必须带着同样的插值名字（否则英文界面会显示 {count} 原样）
  assert.match(String(t('zh', 'panel.group.notesHead')), /\{count\}/);
  assert.match(String(t('en', 'panel.group.notesHead')), /\{count\}/);
  assert.match(String(t('zh', 'panel.group.notesAdded')), /\{rev\}/);
  assert.match(String(t('en', 'panel.group.notesAdded')), /\{rev\}/);
  // 面板里真的用到了这几条（不是只加了词表）
  const seg = panelSegment();
  for (const key of NOTES_KEYS) {
    assert.equal(seg.includes("'" + key + "'"), true, '面板没有引用：' + key);
  }
});
