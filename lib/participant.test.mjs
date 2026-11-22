/**
 * 0.12.7-alpha（slice C）：常驻参与者的唤醒队列。
 *
 * 铁律：这里**没有一个真 sleep** —— 时钟与定时器都是假的（注入的），
 * 所以「30 秒批次」在本文件里是一次 advance(30000) 就能走完的事。
 *
 * 用例编号与交接单一一对应（C1..C8、C10）；C9（lan_group_post 工具）在
 * lib/tools-group.test.mjs 里（工具那一层的错误口径与那里同源）。
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  LOOP_BREAK_MS,
  PARTICIPANT_FILE,
  PARTICIPANT_MARK,
  PARTICIPANT_REPORT_MESSAGES,
  PARTICIPANT_REPORT_MS,
  createParticipant,
  createParticipantWiring,
  decisionEvents,
  migrateParticipantState,
  normalizeParticipantConfig,
} from './participant.mjs';

const SELF = 'self-node-0001';
const PEER_A = 'peer-alpha-01';
const PEER_B = 'peer-bravo-02';

/** 假时钟 + 假定时器：advance() 把到点的回调按时间顺序跑完 */
function makeClock(start = 1_700_000_000_000) {
  let current = start;
  let sequence = 0;
  const timers = [];
  return {
    now: () => current,
    setTimeoutFn(fn, ms) {
      sequence += 1;
      const handle = { id: sequence, at: current + Math.max(0, Number(ms) || 0), fn };
      timers.push(handle);
      return handle;
    },
    clearTimeoutFn(handle) {
      const index = timers.indexOf(handle);
      if (index >= 0) timers.splice(index, 1);
    },
    advance(ms) {
      current += Math.max(0, Number(ms) || 0);
      for (;;) {
        const due = timers.filter((handle) => handle.at <= current).sort((a, b) => a.at - b.at)[0];
        if (!due) break;
        timers.splice(timers.indexOf(due), 1);
        due.fn();
      }
    },
    /** 还挂着几个定时器（泄漏检查：close() 之后必须是 0） */
    pending: () => timers.length,
  };
}

/** 让 participant 内部的 promise 链跑完（微任务 → 一个 macro tick 就够） */
const tick = () => new Promise((resolve) => setImmediate(resolve));

function stateDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'lan-peers-participant-'));
}

function message(seq, text, { from = PEER_A, name = 'alpha', kind = 'chat', meta = null } = {}) {
  return { seq, ts: 1_700_000_000_000 + seq, from: { peerId: from, name }, kind, text, meta };
}

/** 造一个被用例驱动的参与者：wakes 里是每一次真实打出去的 prompt */
function makeParticipant(overrides = {}) {
  const clock = makeClock();
  const wakes = [];
  const logs = [];
  const dir = overrides.stateDir ?? stateDir();
  const answers = overrides.answers ?? [];
  let answerIndex = 0;
  const participant = createParticipant({
    stateDir: dir,
    selfId: () => SELF,
    config: overrides.config ?? {},
    log: (line) => logs.push(String(line)),
    now: clock.now,
    setTimeoutFn: clock.setTimeoutFn,
    clearTimeoutFn: clock.clearTimeoutFn,
    proposalPlane: overrides.proposalPlane ?? (() => null),
    promptSession: async (sessionId, prompt) => {
      wakes.push({ sessionId, prompt });
      if (typeof overrides.promptSession === 'function') {
        return overrides.promptSession(sessionId, prompt, wakes.length);
      }
      const scripted = answers[answerIndex];
      answerIndex += 1;
      if (scripted instanceof Error) throw scripted;
      if (scripted !== undefined) return scripted;
      return { sessionId: sessionId === '' ? 'sess-participant' : sessionId, reused: sessionId !== '' };
    },
  });
  participant.arm();
  return { participant, clock, wakes, logs, dir };
}

const logsMatching = (logs, needle) => logs.filter((line) => line.includes(needle));

// ---------------------------------------------------------------------------
// C1：窗口内三条群消息 → 恰好**一次**唤醒，提示里三条正文都在
// ---------------------------------------------------------------------------
test('C1 三条群消息在一个窗口内只唤醒一次，提示里三条正文都在', async () => {
  const { participant, clock, wakes, logs } = makeParticipant();
  participant.push({
    kind: 'group',
    groupId: 'g1',
    messages: [message(1, '第一条：门禁的补丁'), message(2, '第二条：我投了 reject'), message(3, '第三条：等你回话')],
  });
  await tick();
  // C10 的非空性断言之一：删掉 30s 批处理（每次 push 立即 flush）这条就会红
  assert.equal(wakes.length, 0, '窗口还没到，一条都不该打出去');
  assert.equal(participant.state().pending, true, '批量窗定时器必须已经挂上');

  clock.advance(29_999);
  await tick();
  assert.equal(wakes.length, 0, '差 1ms 也还是窗口内');

  clock.advance(1);
  await tick();
  assert.equal(wakes.length, 1, '一个窗口只唤醒一次');
  const prompt = wakes[0].prompt;
  assert.match(prompt, /本批 3 条/);
  assert.ok(prompt.includes('第一条：门禁的补丁'), '第一条正文必须在提示里');
  assert.ok(prompt.includes('第二条：我投了 reject'), '第二条正文必须在提示里');
  assert.ok(prompt.includes('第三条：等你回话'), '第三条正文必须在提示里');
  assert.ok(prompt.includes('lan_group_post'), '提示必须告诉 agent 用哪个工具发言');
  assert.deepEqual(logsMatching(logs, 'wake kind=group batch=3'), ['[participant] wake kind=group batch=3']);
  assert.equal(logsMatching(logs, '第').length, 0, '日志里没有正文（只到 id 与条数）');
});

// ---------------------------------------------------------------------------
// C2：同一窗口里来一个决策事件 → 立刻多一次唤醒（共 2 次），并点出提案 + 轮次
// ---------------------------------------------------------------------------
test('C2 决策事件绕过批次窗立刻唤醒，并点出提案 id 与轮次', async () => {
  let plane = { rev: 1, proposals: [], votes: {}, shelved: [] };
  const { participant, clock, wakes, logs } = makeParticipant({ proposalPlane: () => plane });
  participant.push({ kind: 'group', groupId: 'g1', messages: [message(1, '普通的一句群聊')] });
  clock.advance(30_000);
  await tick();
  assert.equal(wakes.length, 1, '批次窗的那一次');

  // 批次窗之后才出现的一条提案：开票 = 决策事件
  plane = {
    rev: 2,
    proposals: [{ id: 'proposal-abcdef', kind: 'objection', text: 'x' }],
    votes: { 'proposal-abcdef': { round: 2, status: 'open', closesAt: 1_800_000_000_000, roster: [SELF] } },
    shelved: [],
  };
  participant.push({ kind: 'vote' });
  await tick();
  assert.equal(wakes.length, 2, '决策事件不再等 30s：一次推进就多一次唤醒');
  assert.equal(participant.state().pending, false, '决策事件走的是立即路径，不起批次窗定时器');
  assert.deepEqual(logsMatching(logs, 'wake kind=vote proposal=proposal-abcdef round=2'.slice(0, 44)), []);

  const voteLine = logs.find((line) => line.startsWith('[participant] wake kind=vote'));
  assert.equal(voteLine, '[participant] wake kind=vote proposal=proposal round=2', 'id 截到 8 位');
  const prompt = wakes[1].prompt;
  assert.match(prompt, /proposal-abcdef/);
  assert.match(prompt, /第 2 轮/);
  assert.ok(prompt.includes('lan_group_vote'), '决策唤醒必须告诉 agent 用哪个工具投票');
  assert.ok(prompt.includes('lan_group_proposals'), '决策唤醒必须让 agent 先看票数');
});

// ---------------------------------------------------------------------------
// C3：回声闸 —— 本机作者的消息零唤醒
// ---------------------------------------------------------------------------
test('C3 本机作者的消息永不唤醒（回声闸）', async () => {
  const { participant, clock, wakes } = makeParticipant();
  participant.push({ kind: 'group', groupId: 'g1', messages: [message(1, '我自己刚说的话', { from: SELF })] });
  clock.advance(120_000);
  await tick();
  // C10 的非空性断言之二：删掉回声闸，这条立刻红
  assert.equal(wakes.length, 0, '自己说的话不该叫醒自己');

  // 对照：同一个作者换成本机之外 → 立刻就能唤醒（差异只可能来自回声闸）
  participant.push({ kind: 'group', groupId: 'g1', messages: [message(2, '别人说的话', { from: PEER_A })] });
  clock.advance(30_000);
  await tick();
  assert.equal(wakes.length, 1);
});

// ---------------------------------------------------------------------------
// C4：系统行闸 —— /task 回执、搁置提醒、表决通知零唤醒
// ---------------------------------------------------------------------------
test('C4 系统行（回执/搁置提醒/表决通知）永不进唤醒队列', async () => {
  const { participant, clock, wakes } = makeParticipant();
  participant.push({
    kind: 'group',
    groupId: 'g1',
    messages: [
      message(1, '/task 回执：@alpha 已接单', { kind: 'system' }),
      message(2, '[group] vote shelved: proposal deadbeef kind=objection rounds=3 — only the hub operator can decide', { kind: 'system' }),
      // 第二道闸：即便有人把它塞进 kind=chat，系统前缀同样挡下
      message(3, '[group] vote close id=deadbeef round=2 yes=1 no=1 outcome=still-open', { kind: 'chat' }),
    ],
  });
  clock.advance(120_000);
  await tick();
  assert.equal(wakes.length, 0, '机器说的话不该叫醒人');
});

// ---------------------------------------------------------------------------
// C5：乒乓闸 —— 连续 3 条参与者消息后暂停 10 分钟，窗口过后自动恢复
// ---------------------------------------------------------------------------
test('C5 乒乓闸：第 3 条触发 loop-break，第 4 条被丢，窗口过后恢复', async () => {
  const { participant, clock, wakes, logs } = makeParticipant();
  const byParticipant = (seq, text) => message(seq, text, { from: PEER_B, meta: { transport: PARTICIPANT_MARK } });

  participant.push({ kind: 'group', groupId: 'g1', messages: [byParticipant(1, 'agent 说一'), byParticipant(2, 'agent 说二'), byParticipant(3, 'agent 说三')] });
  clock.advance(30_000);
  await tick();
  assert.equal(wakes.length, 1, '前三条本身照常进批次');
  assert.equal(logsMatching(logs, 'loop-break peer=peer-bra').length, 1, 'loop-break 只写一行');
  assert.equal(logs.find((line) => line.includes('loop-break')), '[participant] loop-break peer=peer-bra', 'peer id 截到 8 位');

  participant.push({ kind: 'group', groupId: 'g1', messages: [byParticipant(4, 'agent 说四')] });
  clock.advance(30_000);
  await tick();
  assert.equal(wakes.length, 1, '暂停窗内第 4 条被丢掉');
  assert.equal(logsMatching(logs, 'loop-break').length, 1, '暂停窗内不重复刷 loop-break');

  // 窗口过后自动恢复：不用人做任何事
  clock.advance(LOOP_BREAK_MS);
  participant.push({ kind: 'group', groupId: 'g1', messages: [byParticipant(5, 'agent 说五')] });
  clock.advance(30_000);
  await tick();
  assert.equal(wakes.length, 2, '窗口一过唤醒自动恢复');
});

// ---------------------------------------------------------------------------
// C6：私聊 —— 一次唤醒立刻发生（不等 30s），并点出对端
// ---------------------------------------------------------------------------
test('C6 私聊立刻唤醒一次，并点出对端', async () => {
  const { participant, wakes, logs } = makeParticipant();
  participant.push({ kind: 'dm', peerId: PEER_A, entries: [{ id: 'dm-1', from: 'self', text: '在吗？帮我看下门禁' }] });
  await tick();
  // 一次 macro tick 就够：完全没有 advance()，所以「等 30 秒」这条路径根本没被走过
  assert.equal(wakes.length, 1, '私聊不等批次窗');
  assert.equal(logs.find((line) => line.startsWith('[participant] wake kind=dm')), '[participant] wake kind=dm peer=peer-alp');
  assert.ok(wakes[0].prompt.includes('peer-alp'), '提示里要有对端短 id');
  assert.ok(wakes[0].prompt.includes('帮我看下门禁'), '提示里要带那条私聊正文');
  assert.ok(wakes[0].prompt.includes('lan_peer_ask'), '回复走同一条 1:1 通道');
  assert.equal(participant.state().pending, false, '私聊不挂批次窗定时器');
});

// ---------------------------------------------------------------------------
// C7：participant.group:false / dm:false 各自彻底关掉那个频道
// ---------------------------------------------------------------------------
test('C7 group:false 只关群唤醒，dm:false 只关私聊唤醒', async () => {
  const groupOff = makeParticipant({ config: { group: false, batchMs: 30_000 } });
  groupOff.participant.push({ kind: 'group', groupId: 'g1', messages: [message(1, '群消息')] });
  groupOff.clock.advance(120_000);
  await tick();
  assert.equal(groupOff.wakes.length, 0, 'group:false → 群通道零唤醒');
  assert.equal(groupOff.participant.state().pending, false, 'group:false → 连定时器都不该起');

  const dmOff = makeParticipant({ config: { dm: false, batchMs: 30_000 } });
  dmOff.participant.push({ kind: 'dm', peerId: PEER_A, entries: [{ id: 'dm-1', from: 'self', text: '私聊' }] });
  await tick();
  assert.equal(dmOff.wakes.length, 0, 'dm:false → 私聊通道零唤醒');

  // 另一半必须还活着（关一个不等于全关）
  dmOff.participant.push({ kind: 'group', groupId: 'g1', messages: [message(1, '群消息')] });
  dmOff.clock.advance(30_000);
  await tick();
  assert.equal(dmOff.wakes.length, 1, 'dm:false 时群通道照常工作');

  // 坏值回落默认（两个频道都开、汇报开、窗口 6h/200 条）
  assert.deepEqual(normalizeParticipantConfig({ group: 'nope', dm: 0, batchMs: -5, reportEveryMs: 0, reportEveryMessages: 'x' }), {
    group: true,
    dm: true,
    commander: true,
    batchMs: 30_000,
    reportEveryMs: PARTICIPANT_REPORT_MS,
    reportEveryMessages: PARTICIPANT_REPORT_MESSAGES,
  });
  assert.deepEqual(normalizeParticipantConfig({ batchMs: 1500 }), {
    group: true,
    dm: true,
    commander: true,
    batchMs: 1500,
    reportEveryMs: PARTICIPANT_REPORT_MS,
    reportEveryMessages: PARTICIPANT_REPORT_MESSAGES,
  });
  // 回滚闸只认布尔 false
  assert.equal(normalizeParticipantConfig({ commander: false }).commander, false);
  assert.equal(normalizeParticipantConfig({ commander: 0 }).commander, true);
});

// ---------------------------------------------------------------------------
// C8：会话复用 —— 两次唤醒用同一个 sessionId；失败只重建一次
// ---------------------------------------------------------------------------
test('C8 常驻会话复用，失败时只重建一次并记 session-recreated', async () => {
  const { participant, clock, wakes, logs, dir } = makeParticipant();
  participant.push({ kind: 'dm', peerId: PEER_A, entries: [{ id: 'dm-1', from: 'self', text: '第一轮' }] });
  await tick();
  participant.push({ kind: 'dm', peerId: PEER_A, entries: [{ id: 'dm-2', from: 'self', text: '第二轮' }] });
  await tick();
  assert.equal(wakes.length, 2);
  assert.equal(wakes[0].sessionId, '', '第一次是新建（空 sessionId）');
  assert.equal(wakes[1].sessionId, 'sess-participant', '第二次复用同一个常驻会话');
  const stored = JSON.parse(fs.readFileSync(path.join(dir, PARTICIPANT_FILE), 'utf8'));
  assert.equal(stored.dm.sessionId, 'sess-participant', '私聊频道有自己的常驻会话');
  assert.ok(Number(stored.dm.since) > 0, '窗口起点必须落盘');
  assert.equal(logsMatching(logs, 'session-recreated').length, 0, '没失败就不该重建');

  // 让第三次唤醒失败：旧会话没了的唯一证据就是「打不进去」
  const failing = makeParticipant({
    stateDir: dir,
    promptSession: async (sessionId, prompt, call) => {
      // 第 1 次（常驻会话）打不进去 = 那个会话没了；第 2 次走新建路径
      if (call === 1) throw new Error('session-gone');
      return { sessionId: 'sess-recreated', reused: false };
    },
  });
  failing.participant.push({ kind: 'dm', peerId: PEER_A, entries: [{ id: 'dm-9', from: 'self', text: '第三轮' }] });
  await tick();
  assert.equal(failing.wakes.length, 2, '失败 → 重打一次，不是两次');
  assert.equal(failing.wakes[0].sessionId, 'sess-participant', '先打常驻会话');
  assert.equal(failing.wakes[1].sessionId, '', '失败后用新建路径重打一次');
  assert.equal(logsMatching(failing.logs, 'session-recreated').length, 1, '只记一次 session-recreated');
  const healed = JSON.parse(fs.readFileSync(path.join(dir, PARTICIPANT_FILE), 'utf8'));
  assert.equal(healed.dm.sessionId, 'sess-recreated', '新会话写回同一个文件');
  clock.advance(0);
});

// ---------------------------------------------------------------------------
// C10：非空性 —— 指出「删掉闸门/批处理时哪条断言会红」，并把对照做实
// ---------------------------------------------------------------------------
test('C10 非空性：回声闸与 30s 批处理各自的判别断言', async () => {
  // 1) 删掉**回声闸**会红的是 C3 的 assert.equal(wakes.length, 0)：
  //    同一批消息里只差 from.peerId，本机作者那条一旦进队列，唤醒数就从 0 变 1。
  //    这里的对照把差异钉在一处：作者不是本机 → 立刻就醒。
  const control = makeParticipant();
  control.participant.push({ kind: 'group', groupId: 'g1', messages: [message(1, '同一句话', { from: SELF })] });
  control.clock.advance(30_000);
  await tick();
  assert.equal(control.wakes.length, 0);
  control.participant.push({ kind: 'group', groupId: 'g1', messages: [message(2, '同一句话', { from: PEER_A })] });
  control.clock.advance(30_000);
  await tick();
  assert.equal(control.wakes.length, 1, '唯一变量是作者：唤醒只可能被回声闸挡下');

  // 2) 删掉**30s 批处理**会红的是 C1 的 assert.equal(wakes.length, 0)（push 之后立刻查）：
  //    三条消息会变成三次唤醒而不是一次。这里的对照：立即路径（flush）一次就出一次唤醒。
  const batched = makeParticipant();
  batched.participant.push({ kind: 'group', groupId: 'g1', messages: [message(1, 'a'), message(2, 'b'), message(3, 'c')] });
  await tick();
  assert.equal(batched.wakes.length, 0, '批处理：push 之后立刻查必须是 0');
  batched.clock.advance(30_000);
  await tick();
  assert.equal(batched.wakes.length, 1, '批处理：三条合成一次');

  const immediate = makeParticipant();
  immediate.participant.push({ kind: 'group', groupId: 'g1', messages: [message(1, 'a')] });
  immediate.participant.flush();
  await tick();
  assert.equal(immediate.wakes.length, 1, '走立即路径时一次 push 就是一次唤醒');

  // 3) 决策事件的判定本身（纯函数）：开票 / 进轮 / 搁置三种，人的裁决不算
  const before = new Map([['p1', { round: 1, status: 'open' }]]);
  const events = decisionEvents(
    {
      proposals: [{ id: 'p1' }, { id: 'p2' }, { id: 'p3' }],
      votes: { p1: { round: 2, status: 'open' }, p2: { round: 1, status: 'open' }, p3: { round: 3, status: 'shelved' } },
    },
    before,
  );
  assert.deepEqual(events.map((event) => [event.proposalId, event.event, event.round]), [
    ['p1', 'round', 2],
    ['p2', 'opened', 1],
    ['p3', 'shelved', 3],
  ]);
  assert.deepEqual(decisionEvents({ proposals: [{ id: 'p1' }], votes: { p1: { round: 1, status: 'passed' } } }, before), []);
});

// ---------------------------------------------------------------------------
// 定时器纪律：close() 之后一个定时器都不留（真机回归用例正是在抓这个）
// ---------------------------------------------------------------------------
test('close() 清掉批次窗定时器，之后 push 不再唤醒', async () => {
  const { participant, clock, wakes } = makeParticipant();
  participant.push({ kind: 'group', groupId: 'g1', messages: [message(1, '还没到窗口')] });
  assert.equal(clock.pending(), 2, '批次窗 + 汇报窗各一个（都在 close() 的账上）');
  participant.close();
  assert.equal(clock.pending(), 0, 'close() 必须清掉两个定时器');
  clock.advance(120_000);
  await tick();
  assert.equal(wakes.length, 0);
});

// ---------------------------------------------------------------------------
// slice E：汇报（频道 → 指挥官会话）。假时钟/假通道，没有一个真 sleep、没有一个真会话。
// ---------------------------------------------------------------------------
const T0 = 1_700_000_000_000;
const GROUP_SESSION = 'sess-group-aaaa1111';
const DM_SESSION = 'sess-dm-bbbb2222';
const COMMANDER_SESSION = 'sess-cmd-cccc3333';

const groupMessages = (count, start = 1) => Array.from(
  { length: count },
  (_, index) => message(start + index, '群消息 ' + (start + index)),
);
const dmEntries = (count, start = 1) => Array.from(
  { length: count },
  (_, index) => ({ id: 'dm-' + (start + index), from: 'self', text: '私聊 ' + (start + index) }),
);
const readStateFile = (dir) => JSON.parse(fs.readFileSync(path.join(dir, PARTICIPANT_FILE), 'utf8'));

/** 一次 prompt 是哪一种：wake-group / wake-dm / summary-group / summary-dm / report */
function kindOfPrompt(prompt) {
  const text = String(prompt ?? '');
  if (text.includes('汇报摘要')) return 'summary-' + (/频道 (group|dm)/.exec(text)?.[1] ?? '?');
  if (text.includes('【常驻参与者 · 汇报】')) return 'report';
  if (text.includes('条私聊')) return 'wake-dm';
  return 'wake-group';
}

/** 三个假会话的宿主：记录每一次 prompt，按需让某一步失败 */
function makeReporter(overrides = {}) {
  const clock = makeClock(T0);
  const dir = overrides.stateDir ?? stateDir();
  const logs = [];
  const prompts = [];
  const sessionOf = {
    'wake-group': GROUP_SESSION,
    'summary-group': GROUP_SESSION,
    'wake-dm': DM_SESSION,
    'summary-dm': DM_SESSION,
    report: COMMANDER_SESSION,
  };
  let reportAttempts = 0;
  const record = (sessionId, prompt) => {
    const kind = kindOfPrompt(prompt);
    prompts.push({ kind, sessionId, prompt });
    return kind;
  };
  const participant = createParticipant({
    stateDir: dir,
    selfId: () => SELF,
    config: overrides.config ?? {},
    log: (line) => logs.push(String(line)),
    now: clock.now,
    setTimeoutFn: clock.setTimeoutFn,
    clearTimeoutFn: clock.clearTimeoutFn,
    proposalPlane: () => null,
    promptSession: async (sessionId, prompt) => {
      const kind = record(sessionId, prompt);
      if (kind === 'report') {
        reportAttempts += 1;
        if (overrides.reportThrows === true) throw new Error('commander-down');
        if (overrides.reportThrowsOnce === true && reportAttempts === 1) throw new Error('commander-down');
      }
      const target = sessionOf[kind] ?? COMMANDER_SESSION;
      return { sessionId: sessionId === '' ? target : sessionId, reused: sessionId !== '' };
    },
    askSummary: async (sessionId, prompt) => {
      const kind = record(sessionId, prompt);
      if (overrides.summaryThrows === true) throw new Error('summary-down');
      const target = sessionOf[kind] ?? GROUP_SESSION;
      return {
        sessionId: sessionId === '' ? target : sessionId,
        reused: sessionId !== '',
        reply: overrides.summaryThrowsEmpty === true ? '   ' : (overrides.summary ?? '摘要：本机在 ' + kind + ' 里看到的事'),
      };
    },
  });
  participant.arm();
  return { participant, clock, logs, prompts, dir };
}

// ---------------------------------------------------------------------------
// R1：群频道满 200 条 → 恰好一份汇报；计数归零
// ---------------------------------------------------------------------------
test('R1 群频道满 200 条 → 恰好一份汇报，带条数/窗口/两个短 id，之后计数归零', async () => {
  const { participant, clock, logs, prompts, dir } = makeReporter();
  clock.advance(60_000);
  // dm 频道先有一个会话：汇报里要能点名两个参与者会话
  participant.push({ kind: 'dm', peerId: PEER_A, entries: dmEntries(1) });
  await tick();
  assert.equal(prompts.filter((p) => p.kind === 'report').length, 0, 'dm 一条不触发汇报');

  participant.push({ kind: 'group', groupId: 'g1', messages: groupMessages(200) });
  await tick();
  const reports = prompts.filter((p) => p.kind === 'report');
  assert.equal(reports.length, 1, '200 条刚好触发一次，而且只有一次');
  const text = reports[0].prompt;
  assert.ok(text.includes('消息数: 200'), '汇报必须带条数');
  assert.ok(text.includes(new Date(T0).toISOString()), '窗口起点');
  assert.ok(text.includes(new Date(T0 + 60_000).toISOString()), '窗口终点');
  assert.ok(text.includes('aaaa1111') && text.includes('bbbb2222'), '两个参与者会话的短 id 都在');
  assert.equal(reports[0].sessionId, '', '指挥官会话第一次是新建');

  const stored = readStateFile(dir);
  assert.equal(stored.group.msgCount, 0, '汇报之后群频道计数归零');
  assert.equal(stored.group.reports, 1);
  assert.equal(stored.group.summarizedAt, T0 + 60_000);
  assert.equal(stored.commander.sessionId, COMMANDER_SESSION, '指挥官会话记下来了');
  assert.ok(stored.commander.createdAt > 0);
  assert.equal(stored.dm.msgCount, 1, 'dm 的计数不动');
  const summary = '摘要：本机在 summary-group 里看到的事';
  assert.deepEqual(logsMatching(logs, '[participant] report channel='), [
    '[participant] report channel=group msgs=200 chars=' + Array.from(summary).length,
  ]);
});

// ---------------------------------------------------------------------------
// R2：时间窗到点也汇报（条数很少）—— 证明不是只看条数
// ---------------------------------------------------------------------------
test('R2 时间窗到点、条数很少仍然汇报一次（不是只看条数）', async () => {
  const { participant, clock, prompts } = makeReporter();
  participant.push({ kind: 'group', groupId: 'g1', messages: groupMessages(3) });
  await tick();
  assert.equal(prompts.filter((p) => p.kind === 'report').length, 0, '3 条远不到 200，先不汇报');
  clock.advance(PARTICIPANT_REPORT_MS);
  await tick();
  const reports = prompts.filter((p) => p.kind === 'report');
  assert.equal(reports.length, 1, '时间窗到点仍然汇报一次');
  assert.ok(reports[0].prompt.includes('消息数: 3'), '汇报的是那 3 条');
});

// ---------------------------------------------------------------------------
// R3：dm / group 互相独立
// ---------------------------------------------------------------------------
test('R3 dm 与 group 各自独立：一份汇报只重置自己那个频道，并且各自点名', async () => {
  const { participant, prompts, dir } = makeReporter();
  participant.push({ kind: 'dm', peerId: PEER_A, entries: dmEntries(1) });
  await tick();
  participant.push({ kind: 'group', groupId: 'g1', messages: groupMessages(200) });
  await tick();
  let stored = readStateFile(dir);
  assert.equal(stored.group.reports, 1);
  assert.equal(stored.group.msgCount, 0);
  assert.equal(stored.dm.msgCount, 1, '群频道汇报不碰 dm 的计数');
  assert.equal(stored.dm.reports, 0);

  participant.push({ kind: 'dm', peerId: PEER_A, entries: dmEntries(200, 2) });
  await tick();
  stored = readStateFile(dir);
  assert.equal(stored.dm.reports, 1);
  assert.equal(stored.dm.msgCount, 0);
  assert.equal(stored.group.reports, 1, 'dm 的汇报不碰 group 的计数');
  assert.equal(stored.group.msgCount, 0);

  const reports = prompts.filter((p) => p.kind === 'report').map((p) => p.prompt);
  assert.equal(reports.length, 2);
  assert.ok(reports[0].includes('频道: group') && !reports[0].includes('频道: dm'), '第一份点名 group');
  assert.ok(reports[1].includes('频道: dm') && !reports[1].includes('频道: group'), '第二份点名 dm');
  assert.ok(reports[1].includes('消息数: 201'), 'dm 窗口累计的是 1 + 200');
});

// ---------------------------------------------------------------------------
// R4：指挥官打不进去 —— 不崩、一行 report-failed、计数不重置、下一个窗口再试
// ---------------------------------------------------------------------------
test('R4 指挥官 prompt 抛错：不崩、恰好一行 report-failed、计数不重置、唤醒照常', async () => {
  const { participant, logs, prompts, dir } = makeReporter({ reportThrows: true });
  participant.push({ kind: 'group', groupId: 'g1', messages: groupMessages(200) });
  await tick();
  assert.deepEqual(logsMatching(logs, 'report-failed'), ['[participant] report-failed channel=group']);
  assert.equal(logsMatching(logs, '[participant] report channel=').length, 0, '失败时绝不写成功那一行');

  let stored = readStateFile(dir);
  assert.equal(stored.group.msgCount, 200, '计数不重置（下一个窗口重试的就是这批）');
  assert.equal(stored.group.reports, 0);
  assert.equal(stored.group.summarizedAt, 0);

  // 不 spin：同一窗口里再来一条也不立刻重打
  participant.push({ kind: 'group', groupId: 'g1', messages: groupMessages(1, 201) });
  await tick();
  assert.equal(logsMatching(logs, 'report-failed').length, 1, '同一个窗口只失败一次');
  stored = readStateFile(dir);
  assert.equal(stored.group.msgCount, 201, '失败之后又攒的那一条也留着');

  // 参与者照常干活
  participant.push({ kind: 'dm', peerId: PEER_A, entries: dmEntries(1) });
  await tick();
  assert.equal(logsMatching(logs, 'wake kind=dm peer=peer-alp').length, 1, '汇报失败不影响唤醒');
  assert.ok(prompts.some((p) => p.kind === 'wake-dm'), '普通唤醒照常打出去');

  // 摘要拿不到是另一条线：同样只记一行，计数同样不动
  const noSummary = makeReporter({ summaryThrows: true });
  noSummary.participant.push({ kind: 'group', groupId: 'g1', messages: groupMessages(200) });
  await tick();
  assert.deepEqual(logsMatching(noSummary.logs, 'summary-failed'), ['[participant] summary-failed channel=group']);
  assert.equal(logsMatching(noSummary.logs, 'report-failed').length, 0, '摘要失败不算汇报失败');
  assert.equal(noSummary.prompts.filter((p) => p.kind === 'report').length, 0, '没摘要就不打了');
  assert.equal(readStateFile(noSummary.dir).group.msgCount, 200, '摘要失败也不动计数');
});

// ---------------------------------------------------------------------------
// R5：commander:false —— 回滚闸
// ---------------------------------------------------------------------------
test('R5 commander:false → 零汇报，而唤醒照旧工作', async () => {
  const { participant, clock, logs, prompts } = makeReporter({ config: { commander: false } });
  assert.equal(participant.settings.commander, false);
  participant.push({ kind: 'group', groupId: 'g1', messages: groupMessages(200) });
  await tick();
  clock.advance(PARTICIPANT_REPORT_MS);
  await tick();
  assert.equal(prompts.filter((p) => p.kind === 'report').length, 0, '回滚闸：一条汇报都不发');
  assert.equal(prompts.filter((p) => p.kind.startsWith('summary')).length, 0, '连摘要都不问');
  assert.equal(logsMatching(logs, 'wake kind=group batch=200').length, 1, '唤醒照旧工作');
  assert.equal(logsMatching(logs, '[participant] report').length, 0, '一条汇报日志都没有');
  assert.equal(logsMatching(logs, 'summary-failed').length, 0);
});

// ---------------------------------------------------------------------------
// R6：迁移（旧形状只有 sessionId）
// ---------------------------------------------------------------------------
test('R6 旧 participant.json 只带 sessionId：那个会话归 group，dm+commander 现造，重跑迁移是 no-op', async () => {
  const dir = stateDir();
  const file = path.join(dir, PARTICIPANT_FILE);
  fs.writeFileSync(file, JSON.stringify({ sessionId: 'sess-legacy-9999', createdAt: T0 }) + '\n');

  const first = makeParticipant({ stateDir: dir });
  const stored = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.deepEqual(Object.keys(stored).sort(), ['commander', 'dm', 'group'], '顶层只剩三个身份');
  assert.equal(stored.group.sessionId, 'sess-legacy-9999', '旧会话变成 group 频道的会话');
  assert.equal(stored.group.since, T0, '旧 createdAt 变成窗口起点');
  for (const key of ['sessionId', 'since', 'msgCount', 'summarizedAt', 'summary', 'reports']) {
    assert.ok(key in stored.group, '频道形状必须有 ' + key);
  }
  assert.equal(stored.dm.sessionId, '', 'dm 现造（第一次用到时再建会话）');
  assert.equal(stored.commander.sessionId, '');
  assert.deepEqual(stored, migrateParticipantState(stored, T0), '再迁一次是全等（幂等）');

  const second = makeParticipant({ stateDir: dir });
  assert.deepEqual(JSON.parse(fs.readFileSync(file, 'utf8')), stored, '重跑迁移不写坏文件（no-op）');
  second.participant.push({ kind: 'group', groupId: 'g1', messages: [message(1, '旧会话还在吗')] });
  second.clock.advance(30_000);
  await tick();
  assert.equal(second.wakes[0].sessionId, 'sess-legacy-9999', '旧形状的会话继续用来唤醒');
  assert.equal(first.participant.state().channels.group.sessionId, 'sess-legacy-9999');
});

// ---------------------------------------------------------------------------
// R7：非空性 —— 点名「删掉哪一处时哪条断言会红」
// ---------------------------------------------------------------------------
test('R7 非空性：短 id 与「失败不重置」各自的判别断言', async () => {
  // 1) 汇报漏掉参与者短 id → R1 的 assert.ok(text.includes('aaaa1111') && text.includes('bbbb2222')) 红。
  //    这里再加一条反向断言：短 id 必须真的短（整串 id 不许出现在汇报里）。
  const full = makeReporter();
  full.participant.push({ kind: 'dm', peerId: PEER_A, entries: dmEntries(1) });
  await tick();
  full.participant.push({ kind: 'group', groupId: 'g1', messages: groupMessages(200) });
  await tick();
  const text = full.prompts.find((p) => p.kind === 'report').prompt;
  assert.ok(text.includes('aaaa1111') && text.includes('bbbb2222'), '两个短 id 都在');
  assert.ok(!text.includes(GROUP_SESSION) && !text.includes(DM_SESSION), '汇报里只有短 id，没有整串 id');

  // 2) 「报告失败也重置计数」→ R4 的 assert.equal(stored.group.msgCount, 200) 红。
  //    实测：失败后的下一个窗口带着**累积**条数（200 + 1）重试一次 —— 计数真的留着。
  const retry = makeReporter({ reportThrowsOnce: true });
  retry.participant.push({ kind: 'group', groupId: 'g1', messages: groupMessages(200) });
  await tick();
  retry.participant.push({ kind: 'group', groupId: 'g1', messages: groupMessages(1, 201) });
  await tick();
  retry.clock.advance(PARTICIPANT_REPORT_MS);
  await tick();
  const reports = retry.prompts.filter((p) => p.kind === 'report');
  assert.equal(reports.length, 2, '第一个窗口失败，下一个窗口重试一次');
  assert.ok(reports[1].prompt.includes('消息数: 201'), '重试用的是没被重置的那批计数');
  const stored = readStateFile(retry.dir);
  assert.equal(stored.group.msgCount, 0, '这一次成功才归零');
  assert.equal(stored.group.reports, 1);
});

// ---------------------------------------------------------------------------
// 工厂接线（插件入口只装一行；用例直接驱动工厂，不碰 index.js）
// ---------------------------------------------------------------------------
test('工厂 createParticipantWiring：runner.ask/poll 一处驱动唤醒与汇报', async () => {
  const clock = makeClock(T0);
  const dir = stateDir();
  const logs = [];
  const calls = [];
  let created = 0;
  const runner = {
    async ask(prompt, options) {
      const wanted = typeof options?.sessionId === 'string' ? options.sessionId : '';
      created += 1;
      const id = 'sess-fact' + String(created).padStart(4, '0') + 'eeee5555';
      calls.push({ wanted, prompt, id });
      if (wanted === '') return id; // 新建：宿主返回裸 sessionId
      return { sessionId: wanted, reused: true };
    },
    async poll() {
      return { status: 'done', reply: '工厂摘要正文' };
    },
  };
  const wiring = createParticipantWiring({
    runner,
    config: { participant: { reportEveryMessages: 2 } },
    stateDir: dir,
    log: (line) => logs.push(String(line)),
    now: clock.now,
    setTimeoutFn: clock.setTimeoutFn,
    clearTimeoutFn: clock.clearTimeoutFn,
  });
  wiring.arm();
  wiring.push({ kind: 'group', groupId: 'g1', messages: [message(1, '一'), message(2, '二')] });
  await tick();

  const summary = calls.find((c) => c.prompt.includes('汇报摘要'));
  assert.ok(summary, '先向频道自己的会话要摘要');
  assert.ok(summary.prompt.includes('频道 group'));
  const report = calls.find((c) => c.prompt.includes('【常驻参与者 · 汇报】'));
  assert.ok(report, '再把汇报打进指挥官会话');
  assert.ok(report.prompt.includes('消息数: 2'));
  assert.ok(report.prompt.includes('工厂摘要正文'), '摘要正文进了汇报');
  assert.ok(report.prompt.includes('eeee5555'), '短 id 来自真实的会话 id');

  const stored = readStateFile(dir);
  assert.equal(stored.group.sessionId, summary.id, '频道会话就是 ask 新建的那个');
  assert.equal(stored.commander.sessionId, report.id, '指挥官会话记下来了');
  assert.equal(logsMatching(logs, '[participant] report channel=group msgs=2').length, 1);

  // 普通唤醒也走同一个 ask
  wiring.push({ kind: 'dm', peerId: PEER_A, entries: dmEntries(1) });
  await tick();
  assert.ok(calls.some((c) => c.prompt.includes('lan_peer_ask')), '私聊唤醒走同一条通道');
  wiring.close();
});

// ---------------------------------------------------------------------------
// slice F：面板指挥官输入框的接线（sayToCommander）
// ---------------------------------------------------------------------------
/** 一个只会 ask/poll 的假 runner：ask 新建时回裸 id，续用回 {sessionId, reused}。 */
function makeSayRunner({ reply = '指挥官回话了', status = 'done', askThrows = false, id = 'sess-commander-abcdef123456' } = {}) {
  const asked = [];
  const polled = [];
  return {
    asked,
    polled,
    runner: {
      async ask(prompt, options) {
        if (askThrows) throw new Error('runner exploded');
        const wanted = typeof options?.sessionId === 'string' ? options.sessionId : '';
        asked.push({ wanted, prompt });
        if (wanted === '') return id;
        return { sessionId: wanted, reused: true };
      },
      async poll(sessionId) {
        polled.push(sessionId);
        return { status, reply: status === 'done' ? reply : '' };
      },
    },
  };
}

function wiringFor(runner, dir, extra = {}) {
  return createParticipantWiring({
    runner,
    config: {},
    stateDir: dir,
    log: () => {},
    selfId: () => SELF,
    proposalPlane: () => null,
    summaryPollMs: 1,
    ...extra,
  });
}

test('F1 sayToCommander：第一次造指挥官会话、第二次续用同一个，回话与短 id 一起回来', async () => {
  const dir = stateDir();
  const fake = makeSayRunner();
  const wiring = wiringFor(fake.runner, dir, { commanderWaitMs: 50 });
  const first = await wiring.sayToCommander('  把日志归档  ');
  assert.deepEqual(first, { ok: true, reply: '指挥官回话了', sessionIdShort: 'ef123456' });
  assert.equal(fake.asked[0].wanted, '', '第一次没有会话：让宿主新建');
  assert.equal(fake.asked[0].prompt, '把日志归档', '正文 trim 之后原样打进去');
  const stored = readStateFile(dir);
  assert.equal(stored.commander.sessionId, 'sess-commander-abcdef123456', '指挥官会话记进 participant.json');
  assert.ok(stored.commander.createdAt > 0);

  const second = await wiring.sayToCommander('再来一句');
  assert.equal(fake.asked[1].wanted, 'sess-commander-abcdef123456', '第二次打的是同一个会话（永不轮换）');
  assert.equal(second.ok, true);
  assert.equal(fake.polled[0], 'sess-commander-abcdef123456', '读回复走的就是那条会话');
});

test('F2 sayToCommander：空正文 / 全空格 / 超长都回 bad-text，一个请求都不发', async () => {
  const dir = stateDir();
  const fake = makeSayRunner();
  const wiring = wiringFor(fake.runner, dir, { commanderWaitMs: 50 });
  for (const text of ['', '   ', '\n\t ', 'x'.repeat(4001), undefined, null, 42]) {
    assert.deepEqual(await wiring.sayToCommander(text), { ok: false, error: 'bad-text' }, String(text).slice(0, 8));
  }
  assert.equal(fake.asked.length, 0, 'bad-text 不许惊动 runner');
  assert.equal(fake.polled.length, 0);
});

test('F3 sayToCommander：没有 runner / 没有 poll 都回 no-session（绝不抛错）', async () => {
  const dir = stateDir();
  const none = createParticipantWiring({ runner: null, stateDir: dir, expandHome: (value) => value });
  assert.deepEqual(await none.sayToCommander('喂'), { ok: false, error: 'no-session' });
  const askOnly = createParticipantWiring({
    runner: { ask: async () => 'sess-x' },
    stateDir: dir,
    expandHome: (value) => value,
  });
  assert.deepEqual(await askOnly.sayToCommander('喂'), { ok: false, error: 'no-session' });
});

test('F4 sayToCommander：ask 抛错 = send-failed；poll 一直是 running = timeout（同一档超时预算）', async () => {
  const dir = stateDir();
  const boom = makeSayRunner({ askThrows: true });
  const failed = await wiringFor(boom.runner, dir, { commanderWaitMs: 20 }).sayToCommander('喂');
  assert.deepEqual(failed, { ok: false, error: 'send-failed' });

  const stuck = makeSayRunner({ status: 'running' });
  const started = Date.now();
  const timedOut = await wiringFor(stuck.runner, dir, { commanderWaitMs: 120 }).sayToCommander('喂');
  const elapsed = Date.now() - started;
  assert.deepEqual(timedOut, { ok: false, error: 'timeout' });
  assert.ok(elapsed >= 100 && elapsed < 3000, '超时窗按 commanderWaitMs 收口，实际 ' + elapsed + 'ms');
  assert.ok(stuck.polled.length > 1, '超时是轮询到点，不是一次就放弃');
});

test('F5 同一条 poller：汇报摘要与指挥官回话都只经 runner.ask/poll（没有第二条通道）', async () => {
  const clock = makeClock(T0);
  const dir = stateDir();
  const calls = [];
  let seq = 0;
  const runner = {
    async ask(prompt, options) {
      const wanted = typeof options?.sessionId === 'string' ? options.sessionId : '';
      seq += 1;
      const id = 'sess-shared' + String(seq).padStart(4, '0') + 'eeee5555';
      calls.push({ kind: 'ask', wanted, prompt });
      if (wanted === '') return id;
      return { sessionId: wanted, reused: true };
    },
    async poll() {
      calls.push({ kind: 'poll' });
      return { status: 'done', reply: '同一段回复' };
    },
  };
  const wiring = createParticipantWiring({
    runner,
    config: { participant: { reportEveryMessages: 1 } },
    stateDir: dir,
    log: () => {},
    now: clock.now,
    setTimeoutFn: clock.setTimeoutFn,
    clearTimeoutFn: clock.clearTimeoutFn,
    summaryPollMs: 1,
    commanderWaitMs: 50,
  });
  wiring.arm();
  wiring.push({ kind: 'group', groupId: 'g1', messages: [{ seq: 1, from: { peerId: PEER_A, name: 'a' }, kind: 'chat', text: '一' }] });
  await tick();
  const said = await wiring.sayToCommander('你好');
  assert.equal(said.ok, true);
  const polls = calls.filter((call) => call.kind === 'poll').length;
  assert.ok(polls >= 2, '摘要一次 + 回话一次，两次都落在同一个 poll 上，实际 ' + polls);
  wiring.close();
  assert.equal(clock.pending(), 0, 'close 之后不留定时器');
});

