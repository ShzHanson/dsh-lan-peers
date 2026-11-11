/**
 * 0.10.1 修复回归：hub 在 quorum=majority 下也要答群内 @（真机 seq=18 哑火）。
 *
 * 真机症状：成员答得对，hub 从来不答，且 NAS 日志里**从来没有** `[group] answer` 行。
 * 根因：leader 收到成员 post 的落盘口是 deliverPost 的 majority 分支（commitStaged），
 * 那里没有调用 dispatchGroupAnswers —— 成员侧靠 commit 广播走 applyCommitted，所以只有 hub 哑。
 * 本文件的两条用例必须**真跑 majority**（group-cluster 默认已经是 majority），
 * 用 quorum:none 的脚手架（host/test/group-replica.test.mjs 的 startHub）测不出这条缝。
 *
 * 另外三条否决用例（自己发的 / 陌生作者 / /task）锁定 0.10.0 的既有行为不许回退，
 * 并要求每一条否决都留一行 `[group] answer skip seq=<n> reason=<token>`：否决不再静默。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { postAs, startCluster } from './group-cluster.mjs';
import { answerDecision } from '../../lib/group-resident.mjs';

// 短 id 必须不同（selfMentionAliases 用 peerId 前 8 位作别名）；名字必须显式给，
// 否则两台同机节点的 config.name 都回落到 os.hostname()，@ 点名就分不清点的是谁。
const IDS = ['peer-hub-abcd1', 'peer-desk-abcd2'];
const NAMES = ['node-1', 'node-2'];

/** 假 runner：只记「被问了几次」，poll 立刻 done（与 group-replica.test.mjs 的形状一致） */
function answerRunner({ reply = '收到' } = {}) {
  const asks = [];
  const sessions = new Map();
  let created = 0;
  return {
    asks,
    async ask(prompt, options = undefined) {
      const wanted = typeof options?.sessionId === 'string' ? options.sessionId.trim() : '';
      const live = wanted !== '' && sessions.has(wanted);
      const sessionId = live ? wanted : 'rs-' + (++created);
      asks.push({ prompt, wanted, sessionId, reused: live });
      sessions.set(sessionId, { done: false });
      return { sessionId, reused: live };
    },
    async poll(sessionId) {
      const session = sessions.get(sessionId);
      if (!session) return { status: 'error', error: 'session-not-found' };
      session.done = true;
      return { status: 'done', reply };
    },
  };
}

const chatAnswers = (node) => node.server.group.history({ sinceSeq: 0 })
  .filter((m) => m.kind === 'chat' && Number(m.meta?.quote?.seq) > 0);

const skipLines = (log, seq, reason) => log.filter(
  (line) => line === '[group] answer skip seq=' + seq + ' reason=' + reason,
);

// ---------------------------------------------------------------------------
// T1 / T2：成员 @ 到 hub → hub 必须答（majority 缝）
// ---------------------------------------------------------------------------

test('T1 hub（majority）答成员的 @ 点名：一条 chat + meta.quote.seq = 问题的 seq', async (t) => {
  const hubRunner = answerRunner({ reply: '收到，hub在线' });
  const cluster = await startCluster(t, { count: 2, ids: IDS, names: NAMES, runners: [hubRunner] });
  const [hub, member] = cluster.nodes;
  assert.equal(hub.server.group.role().role, 'leader', '前提：node0 就是 leader（= hub）');

  // 判定层先用 hub 的**真实上下文**复核一次：这条 seq=18 形状的消息对它就是「点名答」。
  // （不是抢答：抢答要求「没人被点名」，而这里点名的是 hub 自己的显示名。）
  const verdict = answerDecision({
    text: '@node-1 只回一句：hub在线',
    kind: 'chat',
    fromPeerId: member.peerId,
    selfPeerId: hub.peerId,
    aliases: ['node-1', hub.peerId, hub.peerId.slice(0, 8)],
    knownMentions: ['node-1', hub.peerId, hub.peerId.slice(0, 8), 'node-2', member.peerId, member.peerId.slice(0, 8)],
    meta: null,
    memberAuthor: true,
  });
  assert.deepEqual(verdict, { intent: 'directed', reason: '' }, '点名答：判定层不许否决');

  // 与真机 seq=18 同形：kind:chat、作者是另一个成员、text 用 hub 的显示名点名
  const posted = await postAs(hub.baseUrl, member.peerId, { kind: 'chat', text: '@node-1 只回一句：hub在线' });
  assert.equal(posted.status, 201, posted.text);
  await hub.server.group.waitAnswers();

  assert.equal(hubRunner.asks.length, 1, 'hub 必须被提问恰好一次（修复前这里是 0：majority 缝没排答案）');
  const answers = chatAnswers(hub);
  assert.equal(answers.length, 1, 'hub 恰好一条带 quote 的答复');
  assert.equal(Number(answers[0].meta.quote.seq), Number(posted.json.seq), 'quote.seq 必须等于问题的 seq');
  assert.equal(answers[0].from.peerId, hub.peerId, '作者必须是 hub 自己（不是空 peerId）');
  assert.equal(answers[0].text, '收到，hub在线');
});

test('T2 全角 ＠ + peerId 短形式同样算点名', async (t) => {
  const hubRunner = answerRunner({ reply: '在' });
  const cluster = await startCluster(t, { count: 2, ids: IDS, names: NAMES, runners: [hubRunner] });
  const [hub, member] = cluster.nodes;

  const posted = await postAs(hub.baseUrl, member.peerId, { kind: 'chat', text: '＠peer-hub 只回一句：在不在' });
  assert.equal(posted.status, 201, posted.text);
  await hub.server.group.waitAnswers();

  assert.equal(hubRunner.asks.length, 1, '全角 ＠ + 短 id 也要命中');
  assert.equal(chatAnswers(hub).length, 1);
});

// ---------------------------------------------------------------------------
// T3 - T6：否决必须仍然成立，而且必须各留一行 skip（reason=token）
// ---------------------------------------------------------------------------

test('T3 自己发的（含 @ 自己）不答，且留一行 reason=self-authored', async (t) => {
  const log = [];
  const runner = answerRunner();
  const cluster = await startCluster(t, { count: 1, ids: IDS, names: NAMES, runners: [runner], logger: (line) => log.push(String(line)) });
  const hub = cluster.hub;

  const posted = hub.server.group.post({
    peerId: hub.peerId, name: 'node-1', kind: 'chat', text: '@node-1 这条是我自己发的',
  });
  await hub.server.group.waitAnswers();

  assert.equal(runner.asks.length, 0, '自己发的不许自己答（0.10.0 的回归不许回退）');
  assert.equal(chatAnswers(hub).length, 0, '群里一条答复都不许出现');
  assert.equal(skipLines(log, posted.seq, 'self-authored').length, 1, '否决必须留恰好一行 skip');
});

test('T4 陌生作者（不是群成员）不触发抢答，且留一行 reason=not-a-member-author', async (t) => {
  const log = [];
  const runner = answerRunner();
  const cluster = await startCluster(t, { count: 1, ids: IDS, names: NAMES, runners: [runner], logger: (line) => log.push(String(line)) });
  const hub = cluster.hub;

  // 面板/管理接口的单阶段写没有作者身份走到成员表里：这里显式用一个陌生 peerId
  const posted = hub.server.group.post({
    peerId: 'peer-ghost', name: 'ghost', kind: 'chat', text: '群里闲聊一句，没有任何 @',
  });
  await hub.server.group.waitAnswers();

  assert.equal(runner.asks.length, 0, '陌生作者不为它花一次 runner 调用（0.10.0 的 isGroupMemberAuthor 闸门）');
  assert.equal(chatAnswers(hub).length, 0);
  assert.equal(skipLines(log, posted.seq, 'not-a-member-author').length, 1, '否决必须留恰好一行 skip');
});

test('T5 /task 不是问题，留一行 reason=task', async (t) => {
  const log = [];
  const runner = answerRunner();
  const cluster = await startCluster(t, { count: 2, ids: IDS, names: NAMES, runners: [runner], logger: (line) => log.push(String(line)) });
  const [hub, member] = cluster.nodes;

  const posted = await postAs(hub.baseUrl, member.peerId, { kind: 'chat', text: '/task @node-1 收一下日志' });
  assert.equal(posted.status, 201, posted.text);
  await hub.server.group.waitAnswers();

  assert.equal(runner.asks.length, 0, '/task 已转私聊派单，不许重复当问题答');
  assert.equal(skipLines(log, posted.json.seq, 'task').length, 1, '否决必须留恰好一行 skip');
});

test('T6 @ 到的是别人 → 既不答也不抢答，留一行 reason=not-mention', async (t) => {
  const log = [];
  const runner = answerRunner();
  const cluster = await startCluster(t, { count: 2, ids: IDS, names: NAMES, runners: [runner], logger: (line) => log.push(String(line)) });
  const [hub, member] = cluster.nodes;

  const posted = await postAs(hub.baseUrl, member.peerId, { kind: 'chat', text: '@node-2 你来说一句' });
  assert.equal(posted.status, 201, posted.text);
  await hub.server.group.waitAnswers();

  assert.equal(runner.asks.length, 0, '点的是别人（node-2）→ hub 不答');
  assert.equal(skipLines(log, posted.json.seq, 'not-mention').length, 1, '否决必须留恰好一行 skip');
});

// ---------------------------------------------------------------------------
// T7：判定链本身（未知名字 = 没点名，不是「点我」）
// ---------------------------------------------------------------------------

test('T7 未知名字的 @ 不构成定向（intent=undirected，不是 directed）', async () => {
  // 判定链在 host/server.mjs 里只做「喂上下文」：这里直接用同一份纯函数复核两个极端。
  const base = { kind: 'chat', fromPeerId: 'peer-desk-abcd2', selfPeerId: 'peer-hub-abcd1' };
  const aliases = ['node-1', 'peer-hub-abcd1', 'peer-hub'];
  const knownMentions = ['node-1', 'peer-hub-abcd1', 'peer-hub', 'node-2', 'peer-desk-abcd2', 'peer-des'];

  assert.deepEqual(
    answerDecision({ ...base, text: '@ghost-9 只回一句', aliases, knownMentions }),
    { intent: 'undirected', reason: '' },
    '点陌生名字 = 没点名（不会变成「点我」）',
  );
  assert.deepEqual(
    answerDecision({ ...base, text: '只回一句，没有 @', aliases, knownMentions }),
    { intent: 'undirected', reason: '' },
    '完全没有 @ 也是抢答区间',
  );
  assert.deepEqual(
    answerDecision({ ...base, text: '@node-1 只回一句', aliases, knownMentions }),
    { intent: 'directed', reason: '' },
    '点到 hub 的显示名 → 点名答（T1 的判定前提）',
  );
  assert.deepEqual(
    answerDecision({ ...base, text: '@node-1 只回一句', aliases, knownMentions, meta: { quote: { seq: 3 } } }),
    { intent: '', reason: 'already-answered' },
    '带 quote 的是答案，不答答案（防乒乓）',
  );
  assert.deepEqual(
    answerDecision({ ...base, kind: 'progress', text: '@node-1 x', aliases, knownMentions }),
    { intent: '', reason: 'not-chat' },
  );
});
