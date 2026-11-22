/**
 * 0.12.7-alpha（slice B）：agent 看到的两个群门面 —— lan_group_proposals / lan_group_vote。
 *
 * 铁律两条：
 *   1. 错一律走稳定短串（not-in-group / unknown-proposal / bad-decision / hub-unreachable），
 *      绝不把 host 的异常抛给模型 —— 模型能处理的只有短串，栈帧对它只是噪声。
 *   2. 每一票都必须能被人认出来源：日志里少一个 by=agent，人就分不清那一下是谁点的。
 *
 * host 侧两个函数（groupVotes / castGroupBallot）在这里注入成桩：本文件只验工具这一层
 * 的参数、错误口径与日志，不重跑 hub。
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { PARTICIPANT_MARK } from './participant.mjs';
import { createLanPeerTools } from './tools.mjs';

const SELF = 'self-peer-0001';
const OPEN_ID = 'abcdef1234567890';
const DEADLINE = 1800000000000; // 2027-01-15T08:00:00.000Z

function stateDirWithSelf() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lan-peers-group-tools-'));
  fs.writeFileSync(path.join(dir, 'state.json'), JSON.stringify({ instanceId: SELF, name: 'self' }));
  return dir;
}

async function makeTools({ group = { enabled: true }, votes = null, cast = null, post = null, log = null } = {}) {
  const stateDir = stateDirWithSelf();
  const created = await createLanPeerTools(
    { stateDir, group },
    {
      defineTool: (spec) => spec,
      ...(votes ? { groupVotes: votes } : {}),
      ...(cast ? { castGroupBallot: cast } : {}),
      ...(post ? { groupPost: post } : {}),
      ...(log ? { log } : {}),
    },
  );
  return created;
}

function toolNamed(tools, name) {
  const found = tools.find((tool) => tool.name === name);
  assert.ok(found, name + ' 必须存在');
  return found;
}

/** 一条开着的反对提案：本机已投 reject，另一个成员投了 adopt */
function openPlane() {
  return {
    rev: 3,
    proposals: [
      {
        id: OPEN_ID,
        kind: 'objection',
        text: 'remove the stale peer from the roster',
        target: { type: 'body', id: 'seq-1' },
        author: 'peer-9',
        createdAt: 1,
      },
    ],
    votes: {
      [OPEN_ID]: {
        round: 1,
        status: 'open',
        roster: [SELF, 'peer-2', 'peer-3'],
        ballots: { [SELF]: 'no', 'peer-2': 'yes' },
        openedAt: 1,
        closesAt: DEADLINE,
      },
    },
    verdicts: {},
    shelved: [],
  };
}

test('T1 lan_group_proposals：开着的提案带短 id/截止时间/本机票与计数', async () => {
  const tools = await makeTools({ votes: async () => openPlane() });
  const out = await toolNamed(tools, 'lan_group_proposals').execute({});
  assert.equal(out.error, undefined);
  assert.equal(out.proposals.length, 1);
  const row = out.proposals[0];
  assert.equal(row.id, OPEN_ID);
  assert.equal(row.id8, 'abcdef12');
  assert.equal(row.mine, 'reject', '本机那一票必须被读出来（yes→adopt / no→reject）');
  assert.equal(row.adopt, 1);
  assert.equal(row.reject, 1);
  assert.equal(row.eligible, 3);
  assert.equal(row.deadline, DEADLINE);
  assert.match(out.text, /abcdef12/, '文本里必须是短 id（≤8）');
  assert.match(out.text, /deadline=2027-01-15T08:00:00\.000Z/);
  assert.match(out.text, /mine=reject/);
  assert.match(out.text, /adopt=1 reject=1/);
});

test('T1b lan_group_proposals：没有群时是清楚的空列表，不抛', async () => {
  const noGroup = await makeTools({ group: null });
  const out = await toolNamed(noGroup, 'lan_group_proposals').execute({});
  assert.equal(out.error, 'not-in-group');
  assert.deepEqual(out.proposals, []);
  assert.match(out.text, /not in a group/);
  assert.match(out.text, /no proposals/);

  // 在群里但没有等决定的提案：也是空列表，但不是错误
  const quiet = await makeTools({ votes: async () => ({ rev: 1, proposals: [], votes: {}, verdicts: {}, shelved: [] }) });
  const empty = await toolNamed(quiet, 'lan_group_proposals').execute({});
  assert.equal(empty.error, undefined);
  assert.deepEqual(empty.proposals, []);
  assert.match(empty.text, /No open group proposals/);

  // 读平面自己炸了：仍然是短串，不抛
  const broken = await makeTools({ votes: async () => { throw new Error('boom'); } });
  const failed = await toolNamed(broken, 'lan_group_proposals').execute({});
  assert.equal(failed.error, 'hub-unreachable');
  assert.deepEqual(failed.proposals, []);
});

test('T2 lan_group_vote adopt：host 函数恰好被调一次，参数是 id + yes', async () => {
  const calls = [];
  const tools = await makeTools({
    cast: async (input) => { calls.push(input); return { ok: true, accepted: true, reason: '', vote: { yes: 2, no: 1 } }; },
  });
  const out = await toolNamed(tools, 'lan_group_vote').execute({ proposalId: OPEN_ID, decision: 'adopt' });
  assert.equal(calls.length, 1, '一次调用只能落一张票');
  assert.deepEqual(calls[0], { proposalId: OPEN_ID, ballot: 'yes' });
  assert.equal(out.ok, true);
  assert.equal(out.error, '');
  assert.match(out.text, /ballot recorded: adopt on abcdef12/);
});

test('T3 lan_group_vote reject：decision 不是写死的，票面跟着变成 no', async () => {
  const calls = [];
  const tools = await makeTools({
    cast: async (input) => { calls.push(input); return { ok: true, accepted: true, reason: '', vote: { yes: 0, no: 2 } }; },
  });
  const out = await toolNamed(tools, 'lan_group_vote').execute({ proposalId: OPEN_ID, decision: 'reject' });
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0], { proposalId: OPEN_ID, ballot: 'no' });
  assert.equal(out.ok, true);
  assert.match(out.text, /ballot recorded: reject on abcdef12/);
});

test('T4 坏参数：稳定短串，host 函数一次都不调', async () => {
  const calls = [];
  const tools = await makeTools({
    cast: async (input) => { calls.push(input); return { ok: true, accepted: true, vote: { yes: 1, no: 0 } }; },
  });
  const vote = toolNamed(tools, 'lan_group_vote');

  const bad = await vote.execute({ proposalId: OPEN_ID, decision: 'maybe' });
  assert.equal(bad.ok, false);
  assert.equal(bad.error, 'bad-decision');
  assert.match(bad.text, /^bad-decision: decision must be "adopt" or "reject"/);

  const missingDecision = await vote.execute({ proposalId: OPEN_ID });
  assert.equal(missingDecision.error, 'bad-decision');

  const missingId = await vote.execute({ decision: 'adopt' });
  assert.equal(missingId.ok, false);
  assert.equal(missingId.error, 'unknown-proposal');
  assert.match(missingId.text, /proposalId is required/);

  const blankId = await vote.execute({ proposalId: '   ', decision: 'adopt' });
  assert.equal(blankId.error, 'unknown-proposal');

  assert.deepEqual(calls, [], '参数没通过校验时，host 函数不该被叫到');
});

test('T5 写口失败：unknown-proposal / hub-unreachable 都是短串，不是异常', async () => {
  const notFound = await makeTools({ cast: async () => ({ ok: false, error: 'vote-not-found' }) });
  const a = await toolNamed(notFound, 'lan_group_vote').execute({ proposalId: OPEN_ID, decision: 'adopt' });
  assert.equal(a.ok, false);
  assert.equal(a.error, 'unknown-proposal');
  assert.match(a.text, /^unknown-proposal:/);

  const throwing = await makeTools({ cast: async () => { throw new Error('ECONNREFUSED 127.0.0.1:7401'); } });
  const b = await toolNamed(throwing, 'lan_group_vote').execute({ proposalId: OPEN_ID, decision: 'adopt' });
  assert.equal(b.ok, false);
  assert.equal(b.error, 'hub-unreachable');
  assert.match(b.text, /^hub-unreachable:/);
  assert.ok(!/ECONNREFUSED/.test(b.text), '原始异常文本不能漏给模型');

  // 轮次关了 / 本机不在名单：仍然是「这条现在不能投」
  const refused = await makeTools({ cast: async () => ({ ok: true, accepted: false, reason: 'vote-closed' }) });
  const c = await toolNamed(refused, 'lan_group_vote').execute({ proposalId: OPEN_ID, decision: 'reject' });
  assert.equal(c.ok, false);
  assert.equal(c.error, 'unknown-proposal');

  // 成员节点没有写口：本机根本不在群里
  const hubOnly = await makeTools({ cast: async () => ({ ok: false, error: 'votes-hub-only' }) });
  const d = await toolNamed(hubOnly, 'lan_group_vote').execute({ proposalId: OPEN_ID, decision: 'adopt' });
  assert.equal(d.error, 'not-in-group');

  // 群关着时连 host 函数都不该被叫
  const calls = [];
  const noGroup = await makeTools({ group: null, cast: async (input) => { calls.push(input); return { ok: true, accepted: true }; } });
  const e = await toolNamed(noGroup, 'lan_group_vote').execute({ proposalId: OPEN_ID, decision: 'adopt' });
  assert.equal(e.error, 'not-in-group');
  assert.deepEqual(calls, []);
});

test('T6 日志：一次投票恰好一行，带 by=agent 与短 id；描述说清「本机只有一票」', async () => {
  const lines = [];
  const tools = await makeTools({
    cast: async () => ({ ok: true, accepted: true, reason: '', vote: { yes: 1, no: 0 } }),
    log: (line) => lines.push(String(line)),
  });
  await toolNamed(tools, 'lan_group_vote').execute({ proposalId: OPEN_ID, decision: 'adopt' });
  const casts = lines.filter((line) => line.includes('ballot cast'));
  assert.equal(casts.length, 1, '一张票只能有一行日志');
  assert.equal(casts[0], '[group] ballot cast by=agent proposal=abcdef12 decision=adopt');
  assert.match(casts[0], /by=agent/);
  assert.match(casts[0], /proposal=abcdef12/);
  assert.ok(!/1234567890/.test(casts[0]), '日志里的 id 必须截到 8 位');

  const description = String(toolNamed(tools, 'lan_group_vote').description ?? '');
  assert.match(description, /single ballot/);
  assert.match(description, /OVERWRITES the previous ballot/i, '描述必须说明会覆盖上一张票');
  assert.match(description, /by=agent/, '描述必须说明 agent 投的票会留痕');
});

test('T7 非空性：by=agent 与 decision 都是承重的', async () => {
  // (1) 日志那条断言：把 'by=agent ' 从日志行里删掉，上面 casts[0] 的 assert.equal
  //     与 T6 的 /by=agent/ 都会失败 —— 也就是「人能看出这不是自己点的」这件事有测试兜着。
  // (2) decision 那条断言：把 decision 写死成 adopt，T3 里 calls[0].ballot === 'no' 会拿到 'yes' 而失败。
  const ballots = [];
  const logs = [];
  const tools = await makeTools({
    cast: async (input) => { ballots.push(input.ballot); return { ok: true, accepted: true, reason: '', vote: { yes: 1, no: 0 } }; },
    log: (line) => logs.push(String(line)),
  });
  const vote = toolNamed(tools, 'lan_group_vote');
  await vote.execute({ proposalId: OPEN_ID, decision: 'adopt' });
  await vote.execute({ proposalId: OPEN_ID, decision: 'reject' });

  assert.deepEqual(ballots, ['yes', 'no'], '两种裁决必须落成两种不同的票面');
  assert.deepEqual(logs, [
    '[group] ballot cast by=agent proposal=abcdef12 decision=adopt',
    '[group] ballot cast by=agent proposal=abcdef12 decision=reject',
  ], '每次投票恰好一行，且行内两处都可能被改坏：by=agent 与 decision');
});

// ---------------------------------------------------------------------------
// 0.12.7-alpha（slice C）：lan_group_post —— 群内发言
//
// 写口由 host 注入（server.group.post = 面板发言那条 commitLocalMessage），
// 所以这里只验：参数、参与者标记、一行日志、以及四条稳定拒绝口径（绝不抛错）。
// ---------------------------------------------------------------------------

function postTools(post, { enabled = true, log = null } = {}) {
  return makeTools({ group: { enabled }, post, ...(log ? { log } : {}) });
}

test('C9-1 发言：一次 host 调用，正文原样，带参与者标记', async () => {
  const calls = [];
  const logs = [];
  const tools = await postTools(async (input) => { calls.push(input); return { ok: true, seq: 42 }; }, { log: (line) => logs.push(String(line)) });
  const out = await toolNamed(tools, 'lan_group_post').execute({ text: '门禁补丁我合了，明早回归' });
  assert.equal(calls.length, 1, '一条消息只打一次 host 写口');
  assert.equal(calls[0].text, '门禁补丁我合了，明早回归');
  assert.equal(calls[0].kind, 'chat');
  assert.equal(calls[0].meta.transport, PARTICIPANT_MARK, '参与者标记必须带上（对面靠它认乒乓）');
  assert.equal(out.ok, true);
  assert.equal(out.seq, 42);
  assert.deepEqual(logs, ['[group] post by=agent seq=42 chars=12'], '一行日志，没有正文');
  assert.ok(!logs[0].includes('门禁'), '正文一个字都不进日志');
});

test('C9-2 描述必须说清「公开发给整个群」', async () => {
  const tools = await postTools(async () => ({ ok: true, seq: 1 }));
  const description = String(toolNamed(tools, 'lan_group_post').description ?? '');
  assert.match(description, /PUBLIC TO THE WHOLE GROUP/);
  assert.match(description, /lan_peer_ask/, '必须指出只对一个对端时用哪条通道');
});

test('C9-3 没有群 → 稳定拒绝串，一次 host 调用都不发', async () => {
  const calls = [];
  const tools = await postTools(async (input) => { calls.push(input); return { ok: true, seq: 1 }; }, { enabled: false });
  const out = await toolNamed(tools, 'lan_group_post').execute({ text: '有人吗' });
  assert.equal(out.ok, false);
  assert.equal(out.error, 'not-in-group');
  assert.match(out.text, /^not-in-group: /);
  assert.deepEqual(calls, []);

  // 注入缺失（host 没接这一块）同样是 not-in-group，而不是抛错
  const bare = await makeTools({ group: { enabled: true } });
  const missing = await toolNamed(bare, 'lan_group_post').execute({ text: '有人吗' });
  assert.equal(missing.error, 'not-in-group');
});

test('C9-4 空正文 → 稳定拒绝（bad-text），host 一次都不调', async () => {
  const calls = [];
  const tools = await postTools(async (input) => { calls.push(input); return { ok: true, seq: 1 }; });
  for (const value of ['', '   ', '\n\t']) {
    const out = await toolNamed(tools, 'lan_group_post').execute({ text: value });
    assert.equal(out.ok, false);
    assert.equal(out.error, 'bad-text');
    assert.match(out.text, /^bad-text: /);
  }
  assert.deepEqual(calls, []);
});

test('C9-5 host 拒绝/抛错 → 稳定串，绝不把异常抛给模型', async () => {
  const thrown = await postTools(async () => { throw new Error('group-post-unreachable'); });
  const a = await toolNamed(thrown, 'lan_group_post').execute({ text: '在吗' });
  assert.equal(a.ok, false);
  assert.equal(a.error, 'post-failed');
  assert.match(a.text, /^post-failed: /);

  const refused = await postTools(async () => ({ ok: false, error: 'not-in-group' }));
  const b = await toolNamed(refused, 'lan_group_post').execute({ text: '在吗' });
  assert.equal(b.error, 'not-in-group', 'host 说没群，就照没群报');

  const other = await postTools(async () => ({ ok: false, error: 'blocked' }));
  const c = await toolNamed(other, 'lan_group_post').execute({ text: '在吗' });
  assert.equal(c.error, 'post-failed');
  assert.match(c.text, /blocked/, '原因带出来，但仍然是稳定前缀');
});
