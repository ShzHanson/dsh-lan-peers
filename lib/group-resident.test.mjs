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
  RESIDENT_JITTER_MS,
  RESIDENT_TTL_MS,
  alreadyAnsweredSeq,
  answerJitterMs,
  createAnswerClaimSet,
  isAnswerMessage,
  memberMentionAliases,
  resolvedMentions,
  undirectedQuestion,
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

// ---------------------------------------------------------------------------
// 片 3b · 无 @ 抢答的资格判定 / 首答胜 / 抖动 / TTL
// ---------------------------------------------------------------------------

const GROUP_MEMBERS = {
  'peer-replica-1': { name: 'nas-box' },
  'peer-replica-2': { name: 'nas-box2' },
  'peer-hub-0001': { name: 'hub-box' },
};
const KNOWN = memberMentionAliases({
  members: GROUP_MEMBERS,
  selfPeerId: 'peer-replica-1',
  selfName: 'nas-box',
});
const undirected = (text, overrides = {}) => undirectedQuestion({
  text,
  kind: 'chat',
  fromPeerId: 'peer-hub-0001',
  selfPeerId: 'peer-replica-1',
  knownMentions: KNOWN,
  ...overrides,
});

test('B7 无 @ 资格：只答「没点名任何已知成员」的 chat（/task、自己发的、非 chat、答案都不算）', () => {
  assert.equal(undirected('磁盘还剩多少'), true, '没人被点名 → 谁都可以答');
  assert.equal(undirected('@ghost-9 磁盘还剩多少'), true, '点陌生名字 = 没点名（不构成定向）');
  assert.equal(undirected('@nas-box 磁盘还剩多少'), false, '点到了已知成员 → 走定向路径，不算抢答');
  assert.equal(undirected('@NAS-BOX2 在吗'), false, '大小写不敏感');
  assert.equal(undirected('@hub-box 在吗'), false, '点到 hub 也算点名');
  assert.equal(undirected('/task @nas-box 收日志'), false, '/task 绝不进抢答路径');
  assert.equal(undirected('/task 收日志'), false, '/task 本身也不是问题');
  assert.equal(undirected('磁盘还剩多少', { fromPeerId: 'peer-replica-1' }), false, '自己发的不答');
  assert.equal(undirected('磁盘还剩多少', { kind: 'system' }), false, '非 chat 不答');
  assert.equal(undirected('   '), false, '空白不答');
  assert.equal(undirected('看这条 `@nas-box 磁盘` 就行'), true, '行内代码里的 @ 不算点名');
  // 答案是「答案」，不是问题：防「答答案」的无限乒乓
  const answerMeta = { quote: { seq: 7, from: 'hub-box', excerpt: 'x' } };
  assert.equal(undirected('磁盘还剩多少', { meta: answerMeta }), false, '带 quote 的消息是答案');
  assert.equal(isAnswerMessage(answerMeta), true);
  assert.equal(isAnswerMessage({ quote: { seq: 0 } }), false, 'seq 非正 → 不是合法答案');
  assert.equal(isAnswerMessage({}), false);
  // 多 @：每个节点用自己的别名表问一次，各自命中（不是「只答第一个」）
  assert.deepEqual(resolvedMentions('@nas-box @nas-box2 谁在', KNOWN), ['nas-box', 'nas-box2']);
  assert.deepEqual(resolvedMentions('@nas-box 单独问', KNOWN), ['nas-box']);
});

test('B5/B2 首答胜的判据与去重键：alreadyAnsweredSeq 只看 quote.seq；claim 只放行一次', () => {
  const answer = { seq: 9, kind: 'chat', meta: { quote: { seq: 5, from: 'x', excerpt: 'y' } } };
  assert.equal(alreadyAnsweredSeq([answer], 5), true, '有人引用过这个 seq 就是答过了');
  assert.equal(alreadyAnsweredSeq([answer], 6), false);
  assert.equal(alreadyAnsweredSeq([{ seq: 9, kind: 'chat', text: '闲聊' }], 5), false, '没有 quote 的闲聊不算答过');
  assert.equal(alreadyAnsweredSeq([{ ...answer, kind: 'system' }], 5), false, '非 chat 不算答过');
  assert.equal(alreadyAnsweredSeq([], 5), false);

  const claims = createAnswerClaimSet({ capacity: 2 });
  assert.equal(claims.claim('g:1'), true);
  assert.equal(claims.claim('g:1'), false, '同一条消息从几条缝进来也只有一个答案');
  assert.equal(claims.claim('g:2'), true);
  assert.equal(claims.claim('g:3'), true);
  assert.equal(claims.size(), 2, '有界：老键被挤掉，不留无界 map');
  assert.equal(claims.claim('g:1'), true, '被挤掉的键可以重新认领（更老的消息已经不在窗口里）');
});

test('B6 抖动：由 peerId 派生、确定性、两台机器不同、落在 [0, span)', () => {
  const a = answerJitterMs('peer-replica-1');
  const b = answerJitterMs('peer-replica-2');
  assert.equal(a, answerJitterMs('peer-replica-1'), '同一台机器每次都一样');
  assert.notEqual(a, b, '两台不同机器几乎不会同时起跑');
  for (const value of [a, b, answerJitterMs(''), answerJitterMs('x'.repeat(64))]) {
    assert.ok(Number.isInteger(value), '必须是整数毫秒');
    assert.ok(value >= 0 && value < RESIDENT_JITTER_MS, '必须落在 [0, ' + RESIDENT_JITTER_MS + ')');
  }
  assert.ok(answerJitterMs('peer-1', { span: 5 }) < 5, 'span 可调（测试用）');
});

test('B8 TTL：空闲驱逐 → 记录消失 → 下次使用新建；在飞的群一律跳过', (t) => {
  const stateDir = tempDir(t);
  let clock = 1_000_000;
  const store = new ResidentSessionStore({ stateDir, now: () => clock });
  store.save({ groupId: 'g-old', sessionId: 'sess-old', at: clock });
  store.save({ groupId: 'g-busy', sessionId: 'sess-busy', at: clock });

  clock += RESIDENT_TTL_MS + 1; // 两条都过期了
  store.save({ groupId: 'g-fresh', sessionId: 'sess-fresh', at: clock });
  // 在飞的那条：即使过期也不许驱逐
  const removed = store.prune({ busy: ['g-busy'] });
  assert.deepEqual(removed, ['g-old'], '只有 g-old 被驱逐，在飞的 g-busy 留着');
  assert.equal(store.read('g-old'), null, '驱逐 = 记录消失');
  assert.equal(store.read('g-busy').sessionId, 'sess-busy', '在飞的答案不许被驱逐');
  assert.equal(store.read('g-fresh').sessionId, 'sess-fresh', '新鲜记录不动');
  assert.ok(removed.length > 0);
  // 驱逐是安全的：下次提问按「没建过」新建（不需要回滚/迁移）
  assert.equal(resolveResidentUse({ record: store.read('g-old'), asked: { sessionId: 'sess-new' } }).reason,
    'no-record');
  store.save({ groupId: 'g-old', sessionId: 'sess-new', at: clock });
  assert.equal(store.read('g-old').sessionId, 'sess-new', '驱逐之后重建成功');
  // 什么都不忙时，过期的全部清掉
  clock += RESIDENT_TTL_MS + 1;
  assert.deepEqual(store.prune().sort(), ['g-busy', 'g-fresh', 'g-old']);
  assert.deepEqual(store.state().groups, [], '空表，不留无界增长');
});
