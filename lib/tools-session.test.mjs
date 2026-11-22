/**
 * 0.12.7-alpha（slice D）：本机会话的两个门面 —— lan_sessions / lan_session_ask。
 *
 * 铁律四条（与 slice B/C 同一口径）：
 *   1. 错一律走稳定短串（unknown-session / self-session / target-permission-higher /
 *      own-permission-unknown / bad-prompt / timeout / list-failed / ask-failed），
 *      绝不把 host 的异常抛给模型。
 *   2. 会话列表**绝不出现 cwd**：行里只有短 id / 最后活动时间 / 权限档。
 *   3. 短 id = 会话 id 的**尾部** 8 字符（DSH 的 id 一律 session-<n>，头部 8 字符恒为
 *      'session-'）；按前缀显示会让每一行都长一个样、按它派单必然 unknown-session。
 *   4. 权限闸默认开：目标档更高 → 拒绝；目标档读不出来按**最高档**算（fail-closed）。
 *
 * host 侧两个门面（listSessions / askSession）在这里注入成桩：本文件只验工具这一层的
 * 参数、权限闸、短 id 与日志，不碰真会话、不 sleep。
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

import { createLanPeerTools } from './tools.mjs';

/** 假 cwd：它只要出现在任何一格渲染里，S1 就失败 */
const FAKE_CWD = 'D:/work/TOP-SECRET-cwd-9f3a';
const AT = 1_800_000_000_000;
/** 真机形状：session-<n> */
const SELF = 'session-1';
const OTHER = 'session-2';
const HIGH = 'session-3';
const UNKNOWN_TIER = 'session-4';
/** 尾部 8 字符（列表与回执里显示的就是它） */
const SELF_SHORT = 'ession-1';
const OTHER_SHORT = 'ession-2';

const EXEC = { agent: { sessionId: SELF } };

/** 假会话表：每行都**故意带上** cwd 与投影 —— 工具必须一个都不往外带 */
function rows() {
  return [
    { sessionId: SELF, lastActivity: AT + 2000, permission: 'workspace-write', cwd: FAKE_CWD, workingDirectory: FAKE_CWD },
    { sessionId: OTHER, lastActivity: AT + 1000, permission: 'workspace-write', cwd: FAKE_CWD, workingDirectory: FAKE_CWD },
    { sessionId: HIGH, lastActivity: AT, permission: 'danger-full-access', cwd: FAKE_CWD, workingDirectory: FAKE_CWD },
  ];
}

/** 第四行：permissions 投影读不出来（permissionOf 回空串） */
function rowsWithUnknownTier() {
  return [...rows(), { sessionId: UNKNOWN_TIER, lastActivity: AT - 1000, permission: '', cwd: FAKE_CWD }];
}

/** 尾部 8 字符撞车的两行：短 id 必须整体加长，不能显示成同一个 */
function rowsSharingTail8() {
  return [
    { sessionId: 'AAAA-session-7', lastActivity: AT, permission: 'workspace-write', cwd: FAKE_CWD },
    { sessionId: 'BBBB-session-7', lastActivity: AT - 1000, permission: 'workspace-write', cwd: FAKE_CWD },
  ];
}

/** 共享 4 字符后缀的两行（一个 id 尾部就是另一个的尾部）：按 '1234' 匹配必须判含糊 */
function rowsSharingSuffix() {
  return [
    { sessionId: 'session-1234', lastActivity: AT, permission: 'workspace-write', cwd: FAKE_CWD },
    { sessionId: 'session-21234', lastActivity: AT - 1000, permission: 'workspace-write', cwd: FAKE_CWD },
  ];
}

async function makeTools({
  list = async () => rows(),
  ask = async () => ({ status: 'done', reply: '收到' }),
  allowHigher = () => false,
  config = {},
} = {}) {
  const sent = [];
  const lines = [];
  const tools = await createLanPeerTools(config, {
    defineTool: (spec) => spec,
    listSessions: list,
    askSession: async (input) => {
      sent.push(input);
      return ask(input);
    },
    allowHigherPermission: allowHigher,
    log: (line) => lines.push(String(line)),
  });
  const tool = (name) => {
    const found = tools.find((one) => one.name === name);
    assert.ok(found, name + ' 必须存在');
    return found;
  };
  return { sessions: tool('lan_sessions'), ask: tool('lan_session_ask'), sent, lines };
}

test('S1 lan_sessions：短 id = id 的尾部 8 字符（不是头部），行里没有 cwd', async () => {
  const { sessions } = await makeTools();
  const out = await sessions.execute({});
  assert.equal(out.error, undefined);
  assert.equal(out.sessions.length, 3);
  // 每行只有三格 —— 多一格都是泄露面
  for (const row of out.sessions) assert.deepEqual(Object.keys(row).sort(), ['id', 'lastActivity', 'permission']);
  assert.equal(out.sessions[0].id, SELF_SHORT);
  assert.equal(out.sessions[1].id, OTHER_SHORT);
  assert.equal(out.sessions[0].id, SELF.slice(-8), '短 id 必须等于尾部 8 字符（头部前缀会让每行都成 session-）');
  assert.equal(out.sessions[0].id.startsWith('session-'), false, '头部前缀那种写法一定失败');
  assert.equal(out.sessions[0].lastActivity, AT + 2000, '最后活动时间原样回（epoch ms）');
  assert.equal(out.sessions[0].permission, 'workspace-write', '权限档原样回');
  assert.equal(out.sessions[2].permission, 'danger-full-access');
  assert.match(out.text, /ession-1/);
  assert.match(out.text, /2027-01-15T08:00:00\.000Z/, '摘要里给人看的是 ISO 时间');
  // S8 的第二条钉：把 cwd 加进列表 → 下面这条断言失败
  const rendered = JSON.stringify(out);
  assert.equal(rendered.includes(FAKE_CWD), false, 'cwd 不许出现在任何一格（行、text、整体 JSON）');
  assert.equal(rendered.includes(SELF), false, '全 id 也不许出现（只回短 id）');
});

test('S1c lan_sessions：两行尾部 8 字符撞车 → 短 id 确定性加长，绝不显示成同一个', async () => {
  const { sessions } = await makeTools({ list: async () => rowsSharingTail8() });
  const out = await sessions.execute({});
  const [first, second] = out.sessions;
  assert.notEqual(first.id, second.id, '撞车的两行不许显示成同一个短 id');
  assert.ok(first.id.length > 8 && second.id.length > 8, '撞车时整体加长（9 字符）');
  assert.ok('AAAA-session-7'.endsWith(first.id) && 'BBBB-session-7'.endsWith(second.id), '加长仍取尾部');
  // 确定性：同一份名单再算一次，得到同一组短 id
  const again = await (await makeTools({ list: async () => rowsSharingTail8() })).sessions.execute({});
  assert.deepEqual(again.sessions.map((row) => row.id), out.sessions.map((row) => row.id));
});

test('S1b lan_sessions：list 抛错 → 稳定串 list-failed，绝不抛给模型', async () => {
  const broken = await makeTools({ list: async () => { throw new Error('boom'); } });
  const out = await broken.sessions.execute({});
  assert.equal(out.error, 'list-failed');
  assert.deepEqual(out.sessions, []);
  assert.match(out.text, /^list-failed/);
  // 没有注入列表门面（没有 sessionController 的组合）也是同一个稳定串
  const bare = await createLanPeerTools({}, { defineTool: (spec) => spec });
  const none = await bare.find((one) => one.name === 'lan_sessions').execute({});
  assert.equal(none.error, 'list-failed');
});

test('S2 lan_session_ask 快乐路径：一次提问打到解析出的全 id，只回最后一条助手消息，日志一行', async () => {
  const { ask, sent, lines } = await makeTools();
  const out = await ask.execute({ sessionId: OTHER_SHORT, prompt: 'please run the tests' }, EXEC);
  assert.equal(out.ok, true);
  assert.equal(out.error, '');
  assert.equal(out.reply, '收到');
  assert.equal(out.text, '收到', '返回的就是那条消息本身，不是 transcript');
  assert.equal(out.session, OTHER_SHORT, '回执带的是同一个短 id');
  assert.equal(sent.length, 1, '只发一次');
  assert.equal(sent[0].sessionId, OTHER, '短 id 已解析成全 id 再发');
  assert.equal(sent[0].prompt, 'please run the tests');
  assert.equal(sent[0].timeoutMs, 120_000, '默认等 120 s');
  const okLines = lines.filter((line) => line.startsWith('[session] ask ') && !line.includes('refused'));
  assert.equal(okLines.length, 1, '成功只记一行');
  assert.match(okLines[0], /^\[session\] ask target=ession-2 ms=\d+$/);
  assert.equal(lines.join('\n').includes('please run the tests'), false, '正文一个字都不进日志');
});

test('S3 解析规则：尾部 8 字符 / 全 id / 唯一后缀都解析；太短与含糊一律 unknown-session', async () => {
  // 列表里显示的那个短 id（尾部 8 字符）必须真的能派单 —— 旧的前缀写法在这条上失败
  const fromShort = await makeTools();
  const byShort = await fromShort.ask.execute({ sessionId: OTHER_SHORT, prompt: 'go' }, EXEC);
  assert.equal(byShort.ok, true, '尾部 8 字符必须解析得到');
  assert.equal(fromShort.sent[0].sessionId, OTHER);

  // 全 id 照收
  const byFull = await makeTools();
  assert.equal((await byFull.ask.execute({ sessionId: OTHER, prompt: 'go' }, EXEC)).ok, true);
  assert.equal(byFull.sent[0].sessionId, OTHER);

  // 更长的尾部也照收（唯一后缀）
  const byLonger = await makeTools();
  assert.equal((await byLonger.ask.execute({ sessionId: 'on-2', prompt: 'go' }, EXEC)).ok, true);
  assert.equal(byLonger.sent[0].sessionId, OTHER);

  // 太短：不猜
  const tooShort = await makeTools();
  const shortOut = await tooShort.ask.execute({ sessionId: 'n-2', prompt: 'go' }, EXEC);
  assert.equal(shortOut.error, 'unknown-session');
  assert.match(shortOut.text, /at least 4 characters/);
  assert.equal(tooShort.sent.length, 0);

  // 含糊：两个会话共享 '1234' 后缀（一个 id 的尾部就是另一个的尾部）→ 不许挑一个去发
  const fuzzy = await makeTools({ list: async () => rowsSharingSuffix() });
  const out = await fuzzy.ask.execute({ sessionId: '1234', prompt: 'go' }, EXEC);
  assert.equal(out.error, 'unknown-session');
  assert.equal(out.ok, false);
  assert.match(out.text, /2 sessions end with/);
  assert.equal(fuzzy.sent.length, 0, '含糊后缀一条都没发');
  assert.deepEqual(fuzzy.lines, ['[session] ask refused target=1234 reason=unknown-session']);
});

test('S4 派给自己 → self-session，一条都没发', async () => {
  const { ask, sent } = await makeTools();
  const out = await ask.execute({ sessionId: SELF_SHORT, prompt: 'loop' }, EXEC);
  assert.equal(out.error, 'self-session');
  assert.equal(sent.length, 0);
});

test('S5 目标档更高 → target-permission-higher；同一个工具对象把开关抬起来就成功', async () => {
  let flag = false;
  const { ask, sent } = await makeTools({ allowHigher: () => flag });
  const refused = await ask.execute({ sessionId: 'ession-3', prompt: 'do it' }, EXEC);
  assert.equal(refused.error, 'target-permission-higher', 'danger-full-access > workspace-write');
  assert.equal(refused.ok, false);
  assert.equal(sent.length, 0, '拒绝时一条都没发');

  // 同一个工具对象、同一份名单：只把开关抬起来 —— 证明闸门是每次调用现读的，不是造工具时冻住的
  flag = true;
  const ok = await ask.execute({ sessionId: 'ession-3', prompt: 'do it' }, EXEC);
  assert.equal(ok.ok, true);
  assert.equal(ok.error, '');
  assert.equal(sent.length, 1);
  assert.equal(sent[0].sessionId, HIGH);
});

test('S6 目标档读不出来 → 按最高档算（fail-closed）：闸关着就拒绝', async () => {
  const { ask, sent } = await makeTools({ list: async () => rowsWithUnknownTier(), allowHigher: () => false });
  const out = await ask.execute({ sessionId: 'ession-4', prompt: 'do it' }, EXEC);
  // 若回落成「最低档」这里会放行 —— 这条断言就是那个方向的钉子
  assert.equal(out.error, 'target-permission-higher');
  assert.equal(sent.length, 0);
});

test('S7 超时回 timeout 不抛；空 prompt 回 bad-prompt 且一条都没发', async () => {
  const stalled = await makeTools({ ask: async () => ({ status: 'timeout' }) });
  const out = await stalled.ask.execute({ sessionId: OTHER_SHORT, prompt: 'long job', timeoutSec: 3 }, EXEC);
  assert.equal(out.ok, false);
  assert.equal(out.error, 'timeout', '超时是稳定串，不是异常');
  assert.equal(stalled.sent[0].timeoutMs, 3000, 'timeoutSec 生效');
  assert.match(out.text, /may still be working/);

  const blank = await makeTools();
  const bad = await blank.ask.execute({ sessionId: OTHER_SHORT, prompt: '   ' }, EXEC);
  assert.equal(bad.error, 'bad-prompt');
  assert.equal(blank.sent.length, 0, '空 prompt 一条都没发');
});

/** 变异体：就地改一行源码、临时落在 lib/ 里（相对 import 才解析得到），用完删掉 */
async function importMutant(t, mutate) {
  const source = fs.readFileSync(new URL('./tools.mjs', import.meta.url), 'utf8');
  const mutated = mutate(source);
  assert.notEqual(mutated, source, '变异必须真的改到源码，否则这条测试是空转');
  const file = new URL('./.mutant-' + process.pid + '-' + Math.random().toString(36).slice(2, 8) + '.mjs', import.meta.url);
  fs.writeFileSync(file, mutated);
  t.after(() => {
    try { fs.unlinkSync(file); } catch { /* 已经没了就算了 */ }
  });
  return import(file.href);
}

test('S8 非空性：三处变异各自打中一条断言', async (t) => {
  // (a) 把短 id 退回「头部前缀」→ S1/S3 立刻失败（这正是本 slice 修掉的那个 bug）
  const prefixMutant = await importMutant(t, (source) => source.replace(
    "            id: shorts.get(String(row?.sessionId ?? '')) ?? '',",
    "            id: id8(String(row?.sessionId ?? '')),",
  ));
  const prefixTools = await prefixMutant.createLanPeerTools({}, { defineTool: (spec) => spec, listSessions: async () => rows() });
  const prefixed = await prefixTools.find((one) => one.name === 'lan_sessions').execute({});
  assert.equal(prefixed.sessions[0].id, 'session-', '改回前缀后每行都成 session- → S1 那条断言失败');

  // (b) 把 cwd 拼进列表行 → S1 里「渲染里找不到 FAKE_CWD」那条断言失败
  const cwdMutant = await importMutant(t, (source) => source.replace(
    "            id: shorts.get(String(row?.sessionId ?? '')) ?? '',",
    "            id: shorts.get(String(row?.sessionId ?? '')) ?? '',\n            cwd: String(row?.cwd ?? ''),",
  ));
  const leakTools = await cwdMutant.createLanPeerTools({}, { defineTool: (spec) => spec, listSessions: async () => rows() });
  const leak = await leakTools.find((one) => one.name === 'lan_sessions').execute({});
  assert.equal(JSON.stringify(leak).includes(FAKE_CWD), true, '变异体确实带出了 cwd → S1 那条断言不是空转');

  // (c) 删掉权限比较 → S5/S6 的拒绝变成放行
  const permMutant = await importMutant(t, (source) => source.replace(
    'if (sessionTierRank(targetTier) > sessionTierRank(ownTier)) {',
    'if (false) {',
  ));
  const sent = [];
  const permTools = await permMutant.createLanPeerTools({}, {
    defineTool: (spec) => spec,
    listSessions: async () => rows(),
    askSession: async (input) => { sent.push(input); return { status: 'done', reply: 'ok' }; },
    allowHigherPermission: () => false,
  });
  const out = await permTools.find((one) => one.name === 'lan_session_ask')
    .execute({ sessionId: 'ession-3', prompt: 'do it' }, EXEC);
  assert.equal(out.ok, true, '没有权限比较就放行了 → S5 的 target-permission-higher 断言不是空转');
  assert.equal(sent.length, 1);
});
