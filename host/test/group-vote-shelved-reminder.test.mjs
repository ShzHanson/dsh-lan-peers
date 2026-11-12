/**
 * 0.10.0-α slice 4b-3 · shelved 的**提醒**（只提醒，不裁决）。
 *
 * 症状：提案第 3 轮还没过就 shelved，而它唯一的出口是面板的群页签 —— 从不打开那个页签的
 * 运维者永远不知道有决定在等他。这片补的是一条**声音**，状态机一个字都没动：
 *   T1 搁置当场发且只发一条 kind:'system'，正文/备注不进群历史；
 *   T2 同一窗口内重复触发不刷屏（幂等）；
 *   T2b 提醒确实由定时器发出来（不是只在搁置那一下发过一次）；
 *   T3 已裁决的提案不再提醒，定时器被清掉；
 *   T4 close() 之后两种定时器都是 0（进程因此能退出：跑完这个文件就是证据）；
 *   T5 重启后 resume 重新挂上提醒（只断言挂着，不等它到点）；
 *   T6 没有新的 console.error；日志只有 id（≤8）+ 轮数，没有正文。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { listenOnRandomPort } from '../../test-support/ports.mjs';
import { createPeerServer } from '../server.mjs';
import { makeTempStateDir, readJson } from './helpers.mjs';

const PROPOSAL_BODY = 'PROPOSAL-BODY-SECRET-7f3a';
const NOTE_BODY = 'NOTE-BODY-SECRET-9c1d';

/** hub：stateDir 由调用方持有（T5 要「杀掉再重启」同一个目录） */
async function startHub(t, { stateDir = makeTempStateDir(), logger, reminderMs } = {}) {
  const server = createPeerServer({
    listenHost: '127.0.0.1',
    stateDir,
    requireEncryption: false,
    // quorum:none = 写本地即提交：这里测的是提醒，不是复制
    group: { enabled: true, name: 'default', autoJoin: true, retentionDays: 7, quorum: 'none' },
    ...(logger ? { logger } : {}),
    ...(reminderMs ? { groupVote: { reminderMs } } : {}),
  });
  const info = await listenOnRandomPort(server);
  t.after(async () => {
    await server.close();
    fs.rmSync(stateDir, { recursive: true, force: true });
  });
  return { server, baseUrl: info.url, stateDir, group: server.group };
}

/** 群历史里的 system 消息（读权威文件，不读渲染后的视图：断言的是**落盘**的东西） */
function systemMessages(stateDir) {
  const data = readJson(path.join(stateDir, 'group.json'));
  return (data.messages ?? []).filter((message) => message.kind === 'system');
}

/**
 * 手动走完三轮把它顶到 shelved：每轮都投 no。
 * 名单只有 hub 自己（这条用例不起成员）→ 一轮立刻 impossible → failed → 下一轮，绝不用真等 10 分钟。
 */
function shelveOnce(group, { note = false } = {}) {
  if (note) group.appendNote({ text: NOTE_BODY });
  const submitted = group.submitProposal({
    kind: 'objection',
    target: { type: 'body', id: 'body-1' },
    text: PROPOSAL_BODY,
    author: 'alice',
  });
  assert.equal(submitted.ok, true, '提案要能入库：' + JSON.stringify(submitted));
  const id = submitted.proposal.id;
  for (let round = 1; round <= 3; round += 1) {
    const vote = group.votes().votes[id];
    assert.equal(vote.status, 'open', '第 ' + round + ' 轮要开着：' + JSON.stringify(vote));
    const cast = group.castVote({ proposalId: id, peerId: vote.roster[0], ballot: 'no' });
    assert.equal(cast.closed, true, 'no 票让第 ' + round + ' 轮当场结算（impossible）');
  }
  assert.equal(group.votes().votes[id].status, 'shelved');
  return id;
}

test('4b-3 T1：搁置当场只发一条 system 提醒，且正文/备注一个字都不进群历史', async (t) => {
  const lines = [];
  const hub = await startHub(t, { logger: (line) => lines.push(String(line)) });
  const id = shelveOnce(hub.group, { note: true });

  assert.deepEqual(hub.group.shelved().map((entry) => entry.proposalId), [id], 'shelved 集里有它');
  const systems = systemMessages(hub.stateDir);
  assert.equal(systems.length, 1, '恰好一条 system（不是 0 条，也不是两条）：'
    + JSON.stringify(systems.map((entry) => entry.text)));
  const text = systems[0].text;
  assert.match(text, /shelved/, '要带 shelved 标记：' + text);
  assert.match(text, /kind=objection/, '要带提案种类：' + text);
  assert.match(text, /rounds=3/, '要带轮数 3：' + text);
  assert.match(text, /hub operator/, '要说清只有 hub 运维者能裁决：' + text);
  assert.equal(text.includes(PROPOSAL_BODY), false, '提案正文不进群历史');
  assert.equal(text.includes(NOTE_BODY), false, '备注正文不进群历史');
  // 既有契约不变：轮定时器 0（shelved 之后不许再留），提醒另有一张表
  assert.equal(hub.group.voteTimers(), 0, 'shelved 之后没有轮定时器');
  assert.equal(hub.group.shelvedReminders(), 1, '挂着恰好一个重提醒');
  assert.ok(lines.length > 0);
});

test('4b-3 T2：同一窗口内重复触发不刷屏（幂等），窗口过去后一条一次', async (t) => {
  const hub = await startHub(t, { logger: () => {} });
  const id = shelveOnce(hub.group);
  const before = systemMessages(hub.stateDir);
  assert.equal(before.length, 1);

  // 1) 重放一次 closeVote（状态已不是 open）→ 不推进、不发消息
  const replay = hub.group.closeVote(id);
  assert.equal(replay.already, true, '重复结算原样返回：' + JSON.stringify(replay));
  // 2) 同一窗口内连叫两次提醒 → 都被窗口闸挡掉
  assert.equal(hub.group.remindShelved(id).emitted, false, '窗口内的第二次触发是空操作');
  assert.equal(hub.group.remindShelved(id).emitted, false, '再叫一次还是空操作');
  assert.equal(systemMessages(hub.stateDir).length, 1, '群历史里还是只有那一条');
  assert.equal(hub.group.shelvedReminders(), 1, '定时器没被叠成两个');
});

test('4b-3 T2b：提醒真的由定时器发出来（间隔可覆盖，断言两条同形）', async (t) => {
  const hub = await startHub(t, { logger: () => {}, reminderMs: 120 });
  shelveOnce(hub.group);
  const texts = [];
  for (let index = 0; index < 100 && texts.length < 2; index += 1) {
    await sleep(20);
    const systems = systemMessages(hub.stateDir);
    if (systems.length >= 2) texts.push(...systems.map((entry) => entry.text));
  }
  assert.equal(texts.length >= 2, true, '到点必须自己再发一条（这正是「不会沉默」）：' + texts.length);
  assert.equal(texts[1], texts[0], '提醒与搁置公告同形（同一条文本，不夹带新信息）');
});

test('4b-3 T3：已裁决的提案不再提醒，且定时器被清掉', async (t) => {
  const hub = await startHub(t, { logger: () => {} });
  const id = shelveOnce(hub.group);
  assert.equal(hub.group.shelvedReminders(), 1);
  const decided = hub.group.adjudicate({ proposalId: id, decision: 'reject', reason: '不用了', by: 'ops' });
  assert.equal(decided.ok, true, '裁决要能落地：' + JSON.stringify(decided));
  assert.equal(hub.group.shelvedReminders(), 0, '裁决 = 不再等任何人 → 提醒定时器清零');
  assert.equal(hub.group.remindShelved(id).emitted, false, '已裁决的提案不发提醒');
  assert.equal(systemMessages(hub.stateDir).length, 1, '只有搁置那一条，裁决不再发第二条');
});

test('4b-3 T4：close() 之后两种定时器都是 0（进程能退出）', async (t) => {
  const hub = await startHub(t, { logger: () => {}, reminderMs: 60 });
  shelveOnce(hub.group);
  assert.equal(hub.group.shelvedReminders(), 1);
  await hub.server.close();
  assert.equal(hub.group.shelvedReminders(), 0, 'close() 必须把提醒整表清掉');
  assert.equal(hub.group.voteTimers(), 0, '轮定时器同理');
});

test('4b-3 T5：重启后 resume 重新挂上提醒（不立刻补发）', async (t) => {
  const stateDir = makeTempStateDir();
  const first = await startHub(t, { stateDir, logger: () => {} });
  const id = shelveOnce(first.group);
  assert.equal(first.group.shelvedReminders(), 1);
  await first.server.close();
  assert.equal(first.group.shelvedReminders(), 0);

  const second = await startHub(t, { stateDir, logger: () => {} });
  assert.deepEqual(second.group.shelved().map((entry) => entry.proposalId), [id], '重启后 shelved 仍在');
  assert.equal(second.group.shelvedReminders(), 1, 'listen 的 resume 必须把提醒重新挂上');
  assert.equal(systemMessages(stateDir).length, 1, '重启不补发（补发会让反复重启变成刷屏）');
});

test('4b-3 T6：没有新的 console.error；日志只有 ≤8 的 id 与轮数，没有正文', async (t) => {
  const lines = [];
  const errors = [];
  const realError = console.error;
  console.error = (...args) => { errors.push(args.map((arg) => String(arg)).join(' ')); };
  t.after(() => { console.error = realError; });
  try {
    const hub = await startHub(t, { logger: (line) => lines.push(String(line)) });
    shelveOnce(hub.group, { note: true });
  } finally {
    console.error = realError;
  }
  assert.deepEqual(errors, [], '不许出现新的 console.error');
  const reminders = lines.filter((line) => line.includes('vote shelved reminder'));
  assert.equal(reminders.length, 1, '一次提醒恰好一行日志：' + JSON.stringify(reminders));
  assert.match(reminders[0], /^\[group\] vote shelved reminder id=\S{1,8} round=3$/, '格式与隐私：' + reminders[0]);
  for (const line of lines) {
    assert.equal(line.includes(PROPOSAL_BODY), false, '日志里没有提案正文：' + line);
    assert.equal(line.includes(NOTE_BODY), false, '日志里没有备注正文：' + line);
  }
});
