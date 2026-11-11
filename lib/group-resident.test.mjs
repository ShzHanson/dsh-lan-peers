/**
 * dsh-lan-peers · 0.10.0-α slice 3a 群内常驻会话（A1 / A2 / A3 / A8）
 *
 * 这一层全是纯逻辑 + 一个落盘 store：用假时钟与假 runner 就能把两条分支都跑到。
 * 服务器侧的 A3/A4/A5/A6 在 host/test/group-replica.test.mjs，面板侧的 A7 在
 * lib/panel-group.test.mjs。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  RESIDENT_FILE,
  RESIDENT_QUOTE_EXCERPT_MAX,
  ResidentSessionStore,
  addressedToNode,
  buildResidentPrompt,
  createAnswerQueue,
  mentionAliases,
  mentionsNode,
  quoteExcerpt,
  resolveResidentUse,
  sanitizeQuoteMeta,
} from './group-resident.mjs';

const GROUP = 'aaaaaaaa-1111-4111-8111-111111111111';

const tempDir = (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-lan-peers-resident-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
};

// ---------------------------------------------------------------------------
// A1 常驻会话存储：写 → 读往返；陈旧 sessionId 当作不可用并新建（两条分支都断言）
// ---------------------------------------------------------------------------

test('A1 常驻会话：写→读往返、0600、跨实例（重启）读回同一条记录', (t) => {
  const stateDir = tempDir(t);
  const store = new ResidentSessionStore({ stateDir, now: () => 5_000 });

  assert.equal(store.filePath, path.join(stateDir, RESIDENT_FILE));
  assert.equal(store.read(GROUP), null, '没建过就是 null，不是空对象');

  const saved = store.save({ groupId: GROUP, sessionId: 'sess-1', at: 1_700_000_000_000 });
  assert.deepEqual(saved, { groupId: GROUP, sessionId: 'sess-1', lastUsedAt: 1_700_000_000_000 });

  // 重启：新实例只靠磁盘
  const reopened = new ResidentSessionStore({ stateDir });
  assert.deepEqual(reopened.read(GROUP), {
    groupId: GROUP,
    sessionId: 'sess-1',
    lastUsedAt: 1_700_000_000_000,
  });

  const file = path.join(stateDir, RESIDENT_FILE);
  if (process.platform !== 'win32') assert.equal(fs.statSync(file).mode & 0o777, 0o600, '状态文件必须是 0600');
  assert.deepEqual(JSON.parse(fs.readFileSync(file, 'utf8')), {
    version: 1,
    groups: { [GROUP]: { sessionId: 'sess-1', lastUsedAt: 1_700_000_000_000 } },
  });

  // 覆盖写 + 清空（每次都用新实例读：一个进程里只有一块缓存，跨实例只认磁盘）
  store.save({ groupId: GROUP, sessionId: 'sess-2', at: 1_700_000_100_000 });
  assert.equal(new ResidentSessionStore({ stateDir }).read(GROUP).sessionId, 'sess-2');
  assert.equal(store.save({ groupId: GROUP, sessionId: '' }), null);
  assert.equal(new ResidentSessionStore({ stateDir }).read(GROUP), null);

  // 坏文件不制造崩溃：当作「没有记录」
  fs.writeFileSync(file, '{not json');
  assert.equal(new ResidentSessionStore({ stateDir }).read(GROUP), null);
});

test('A1 陈旧 sessionId：runner 说 reused=false → 新建；说 reused=true → 复用（两条分支）', () => {
  const record = { groupId: GROUP, sessionId: 'sess-dead', lastUsedAt: 1 };

  // 分支 1：记录已经不存在了（runner 新建了一条，reused=false，id 也变了）
  const stale = resolveResidentUse({
    record,
    asked: { sessionId: 'sess-fresh', reused: false },
  });
  assert.deepEqual(stale, { sessionId: 'sess-fresh', reuse: false, stale: true, reason: 'stale-recreated' });
  assert.notEqual(stale.sessionId, record.sessionId, '陈旧记录必须被换掉，不能再用旧 id');

  // 分支 1b：runner 没标 reused，但给回来的 id 不是原来那个 —— 同样算陈旧
  assert.equal(
    resolveResidentUse({ record, asked: { sessionId: 'sess-other' } }).reason,
    'stale-recreated',
  );

  // 分支 2：runner 确认续上同一个会话
  const reused = resolveResidentUse({ record, asked: { sessionId: 'sess-dead', reused: true } });
  assert.deepEqual(reused, { sessionId: 'sess-dead', reuse: true, stale: false, reason: 'reused' });

  // 没有记录 = 第一次为这个群建常驻会话（不是陈旧）
  assert.deepEqual(
    resolveResidentUse({ record: null, asked: { sessionId: 'sess-new', reused: false } }),
    { sessionId: 'sess-new', reuse: false, stale: false, reason: 'no-record' },
  );
  // runner 一个 id 都没给：明确放弃（不发帖）
  assert.equal(resolveResidentUse({ record, asked: { sessionId: '' } }).reason, 'no-session');
});

// ---------------------------------------------------------------------------
// A2 触发判定：@name / @name: / ＠name / peerId / 非点名 / 代码块 / /task
// ---------------------------------------------------------------------------

const ALIASES = mentionAliases({ name: 'nas-box', peerId: 'peer-replica-1', shortId: 'peer-rep' });
const ask = (text, overrides = {}) => addressedToNode({
  text,
  kind: 'chat',
  fromPeerId: 'peer-hub',
  selfPeerId: 'peer-replica-1',
  aliases: ALIASES,
  ...overrides,
});

test('A2 命中：@名字、@名字:、全角 ＠、peerId、大小写不敏感', () => {
  assert.equal(ask('@nas-box 磁盘还剩多少'), true);
  assert.equal(ask('@nas-box: 磁盘还剩多少'), true, '@name: 也容忍');
  assert.equal(ask('＠nas-box 磁盘还剩多少'), true, '全角 ＠ 必须归一');
  assert.equal(ask('@NAS-BOX 磁盘还剩多少'), true, '大小写不敏感');
  assert.equal(ask('@peer-replica-1 磁盘还剩多少'), true, 'peerId 也是名字');
  assert.equal(ask('大家看下 @nas-box 这台'), true, '不在行首也算');
  assert.equal(mentionsNode('@nas-box-1 看下', ALIASES), false, '更长的名字不该命中');
});

test('A2 不命中：没 @、别的名字、代码块里的示例、/task 命令、自己发的', () => {
  assert.equal(ask('nas-box 磁盘还剩多少'), false, '没有 @ 就不是点名');
  assert.equal(ask('@nas-box2 磁盘还剩多少'), false, '名字后缀不同不命中');
  assert.equal(ask('@hub-box 磁盘还剩多少'), false, '点的是别人');
  assert.equal(ask('看这条 `@nas-box 磁盘还剩多少` 就行'), false, '行内代码里的 @ 是示例');
  assert.equal(ask('```\n@nas-box 磁盘还剩多少\n```'), false, '代码块里的 @ 也是示例');
  assert.equal(ask('/task @nas-box 收一下日志'), false, '/task 已转私聊派单，不再当问题答');
  assert.equal(ask('@nas-box 看下', { fromPeerId: 'peer-replica-1' }), false, '自己发的不答自己');
  assert.equal(ask('@nas-box 看下', { kind: 'system' }), false, '非 chat 不触发');
  assert.equal(ask('   '), false, '空白消息不触发');
});

test('A2 引用摘要：≤80 个 code point，换行压平', () => {
  const long = '@nas-box ' + '很長'.repeat(200);
  const excerpt = quoteExcerpt(long);
  assert.ok(Array.from(excerpt).length <= RESIDENT_QUOTE_EXCERPT_MAX, 'in: ' + Array.from(excerpt).length);
  assert.ok(excerpt.endsWith('…'), '截断必须带省略号');
  assert.equal(quoteExcerpt('a\nb\tc'), 'a b c');
  assert.equal(quoteExcerpt('@nas-box 短'), '@nas-box 短', '短的原文原样');
  // meta.quote 的唯一规范化入口：seq 必须是正整数
  assert.equal(sanitizeQuoteMeta({ seq: 0, excerpt: 'x' }), null);
  assert.equal(sanitizeQuoteMeta({ seq: 7, from: 'hub-box', excerpt: 'x'.repeat(200) }).excerpt.length, 80);
});

// ---------------------------------------------------------------------------
// A3 单飞：两条同时在飞 → 一条一条来，顺序 = 到达顺序
// ---------------------------------------------------------------------------

test('A3 单飞队列：第二条必须等第一条结束（顺序与并发度一起断言）', async () => {
  const queue = createAnswerQueue();
  const events = [];
  let live = 0;
  let peak = 0;
  const job = (name, ms) => async () => {
    live += 1;
    peak = Math.max(peak, live);
    events.push('start:' + name);
    await new Promise((resolve) => setTimeout(resolve, ms));
    events.push('end:' + name);
    live -= 1;
    return name;
  };

  assert.equal(queue.pending('g'), 0);
  const first = queue.enqueue('g', job('one', 20));
  const second = queue.enqueue('g', job('two', 1));
  assert.equal(queue.pending('g'), 2, '两条都排着');

  assert.deepEqual(await Promise.all([first, second]), ['one', 'two']);
  assert.deepEqual(events, ['start:one', 'end:one', 'start:two', 'end:two'],
    'A8 非空断言：拆掉单飞守卫后会是 start:one,start:two,... —— 这条断言就是它的哨兵');
  assert.equal(peak, 1, '同一时刻只允许一个作业在飞');
  assert.equal(queue.pending('g'), 0, '链尾清空，不留无界 map');

  // 失败不会把链卡死：后一条照样跑
  const failed = queue.enqueue('g', async () => { throw new Error('boom'); });
  const after = queue.enqueue('g', job('three', 1));
  await assert.rejects(failed, /boom/);
  await after;
  assert.deepEqual(events.slice(-2), ['start:three', 'end:three']);
});

test('A3 提问提示词：前言在正文之前，原文按上限截断', () => {
  const prompt = buildResidentPrompt({ senderName: 'hub-box', text: '@nas-box ' + 'x'.repeat(5000) });
  assert.ok(prompt.startsWith('【群内提问 · 致本机】'), '前言必须是第一行');
  assert.ok(prompt.includes('原样'), '必须说明正文会原样进群（与 runner 的答复契约同口径）');
  assert.ok(prompt.includes('提问者：hub-box'));
  assert.ok(prompt.length <= 1500, 'prompt 长度 ' + prompt.length);
  assert.ok(prompt.includes('@nas-box xxx'), '原文在提示词最后');
});
