// dsh-lan-peers · 0.10.0-α slice 4b-1 群表决状态机（纯模块）。
//
// 覆盖 V1–V6 与 V9：阈值表、名单冻结、提前关轮、到点失败重开、三轮 shelved、幂等。
// 全部用**假时钟**（把 now 当参数传），一次真实等待都没有 —— 这是本模块保持纯函数的目的。
// hub 侧的落盘/走线/hub-only 门在 host/test/group-replica.test.mjs 的 V7/V8 里。
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  MAX_ROUNDS,
  PROPOSAL_TEXT_MAX,
  ROUND_MS,
  THRESHOLD_DEN,
  THRESHOLD_NUM,
  advance,
  castBallot,
  makeProposal,
  mergeVotesReplica,
  normalizeVote,
  normalizeVotePlane,
  openRound,
  settleRound,
  summarize,
  tally,
  votesSummary,
} from './group-vote.mjs';

const T0 = 1_700_000_000_000;

const proposal = (overrides = {}) => ({
  id: 'p1',
  kind: 'objection',
  target: { type: 'body', id: 'n3' },
  text: '这条决议再想想',
  author: 'member-a',
  createdAt: T0,
  ...overrides,
});

/** 造一份 n 人名单：peer-0 .. peer-(n-1) */
const rosterOf = (size) => Array.from({ length: size }, (_, index) => 'peer-' + index);

/** 连着投 yes 次票（每次都用上一次返回的记录，模拟真实的串行到达） */
function voteYes(vote, count, now = T0 + 1) {
  let current = vote;
  for (let index = 0; index < count; index += 1) {
    const out = castBallot({ vote: current, peerId: 'peer-' + index, ballot: 'yes', now });
    assert.equal(out.accepted, true, `peer-${index} 的票必须被收下：${out.reason}`);
    current = out.vote;
  }
  return current;
}

// ---------------------------------------------------------------------------
// V1 阈值表
// ---------------------------------------------------------------------------

test('V1 阈值表：yes*3 >= roster*2 —— 2 人需 2 票、3 人需 2 票、4 人需 3 票、5 人需 4 票（ceil）', () => {
  // [名单人数, yes 票数, 期望是否通过]
  const table = [
    [2, 1, false], [2, 2, true],
    [3, 1, false], [3, 2, true],
    [4, 2, false], [4, 3, true],
    [5, 3, false], [5, 4, true],
  ];
  for (const [size, yes, expected] of table) {
    const vote = voteYes(openRound({ proposal: proposal(), roster: rosterOf(size), now: T0 }), yes);
    const counts = tally(vote);
    assert.equal(counts.eligible, size);
    assert.equal(counts.yes, yes);
    assert.equal(counts.passed, expected, `roster=${size} yes=${yes}`);
    // 自证：判据就是这个**整数**表达式本身（不是浮点 2/3，也不是 round()）
    assert.equal(counts.passed, yes * THRESHOLD_DEN >= size * THRESHOLD_NUM);
    // threshold = ceil(eligible*2/3)：「还差几票 yes」
    assert.equal(counts.threshold, Math.ceil((size * THRESHOLD_NUM) / THRESHOLD_DEN));
  }
  // 常量钉死：2/3、10 分钟、3 轮；roster 5 的 ceil 是 4（不是 3.33 取整成 3）
  assert.deepEqual([THRESHOLD_NUM, THRESHOLD_DEN, ROUND_MS, MAX_ROUNDS], [2, 3, 600_000, 3]);
  assert.equal(tally(openRound({ proposal: proposal(), roster: rosterOf(5), now: T0 })).threshold, 4);
  // 两人群：两票必须都 yes —— 一票 yes 一票 no 直接失败（用户明说的后果）
  let pair = openRound({ proposal: proposal(), roster: ['peer-0', 'peer-1'], now: T0 });
  pair = castBallot({ vote: pair, peerId: 'peer-0', ballot: 'yes', now: T0 + 1 }).vote;
  pair = castBallot({ vote: pair, peerId: 'peer-1', ballot: 'no', now: T0 + 2 }).vote;
  assert.equal(tally(pair).passed, false);
  // 空名单不是「自动通过」：0*3 >= 0*2 会让空群凭空过，必须判 impossible
  const empty = openRound({ proposal: proposal(), roster: [], now: T0 });
  assert.equal(tally(empty).eligible, 0);
  assert.equal(tally(empty).passed, false);
  assert.equal(tally(empty).impossible, true);
});

// ---------------------------------------------------------------------------
// V2 名单冻结
// ---------------------------------------------------------------------------

test('V2 冻结名单：轮内掉线不减分母；轮内上线的人投不了（原因写进返回值）', () => {
  const roster = ['peer-a', 'peer-b', 'peer-c'];
  const vote = openRound({ proposal: proposal(), roster, now: T0 });
  const snapshot = JSON.stringify(vote);

  // peer-c 轮内掉线 —— 用「一直没投票」模拟（它还在名单里，分母不动）
  let live = castBallot({ vote, peerId: 'peer-a', ballot: 'yes', now: T0 + 1_000 }).vote;
  live = castBallot({ vote: live, peerId: 'peer-b', ballot: 'yes', now: T0 + 2_000 }).vote;
  const counts = tally(live);
  assert.equal(counts.eligible, 3, '分母是冻结值：掉线的人不许从分母里消失');
  assert.equal(counts.passed, true, '3 人名单 2 票 yes 就过：2*3 >= 3*2');

  // 第 4 个成员轮内上线：投不了，也不进本轮分母
  const late = castBallot({ vote: live, peerId: 'peer-d', ballot: 'yes', now: T0 + 3_000 });
  assert.equal(late.accepted, false);
  assert.equal(late.reason, 'vote-not-eligible', '轮内上线的人必须被拒，且原因可读');
  assert.deepEqual(late.vote, live, '被拒的票一个字都没进记录');
  assert.equal(tally(late.vote).eligible, 3);

  // 冻结名单也意味着「名单是值不是引用」：开轮后改调用方的数组不影响这一轮
  const mutable = ['peer-a', 'peer-b'];
  const frozen = openRound({ proposal: proposal(), roster: mutable, now: T0 });
  mutable.push('peer-z');
  assert.notEqual(frozen.roster, mutable, '名单必须被复制，不能是调用方那个数组');
  assert.deepEqual(frozen.roster, ['peer-a', 'peer-b']);
  assert.equal(JSON.stringify(vote), snapshot, 'openRound/castBallot/tally 都不许改输入');
});

// ---------------------------------------------------------------------------
// V3 提前关轮
// ---------------------------------------------------------------------------

test('V3 提前关轮：够票立刻关（passed）；没救也立刻关（failed）—— 都不等 closesAt', () => {
  // (a) 够票
  const enough = voteYes(openRound({ proposal: proposal(), roster: rosterOf(3), now: T0 }), 2, T0 + 1_000);
  const early = settleRound({ vote: enough, now: T0 + 1_000 });
  assert.equal(early.closed, true, '票到齐就不该等到 closesAt');
  assert.equal(early.outcome, 'passed');
  assert.equal(early.vote.closedAt, T0 + 1_000, 'closedAt 是关轮那一刻');
  assert.ok(T0 + 1_000 < enough.closesAt, '必须真的早于 closesAt 才叫提前');

  // (b) 没救：3 人名单里 2 票 no → 剩下 1 票全 yes 也够不到 2 票
  let dead = openRound({ proposal: proposal(), roster: rosterOf(3), now: T0 });
  dead = castBallot({ vote: dead, peerId: 'peer-0', ballot: 'no', now: T0 + 1_000 }).vote;
  dead = castBallot({ vote: dead, peerId: 'peer-1', ballot: 'no', now: T0 + 1_000 }).vote;
  const counts = tally(dead);
  assert.equal(counts.impossible, true, '(0+1)*3 < 3*2：剩下的人全投 yes 也不够');
  const broke = settleRound({ vote: dead, now: T0 + 1_000 });
  assert.equal(broke.closed, true, '没救了就别让人干等 10 分钟');
  assert.equal(broke.outcome, 'failed');

  // (c) 既没够也没没救 → 保持开着（不许提前关）
  const pending = voteYes(openRound({ proposal: proposal(), roster: rosterOf(3), now: T0 }), 1, T0 + 1_000);
  const wait = settleRound({ vote: pending, now: T0 + 1_000 });
  assert.equal(wait.outcome, 'still-open');
  assert.equal(wait.closed, false);
  assert.deepEqual(wait.vote, pending, '没关轮就不许改记录');
});

// ---------------------------------------------------------------------------
// V4 到点失败 + 下一轮重新冻结
// ---------------------------------------------------------------------------

test('V4 到点票不够 → 这一轮失败；advance 开第 2 轮，名单是**新冻结**的那份', () => {
  let vote = openRound({ proposal: proposal(), roster: rosterOf(3), now: T0 });
  vote = castBallot({ vote, peerId: 'peer-0', ballot: 'yes', now: T0 + 60_000 }).vote;
  assert.equal(tally(vote).passed, false);
  // 还差得远，不到点就不能关
  assert.equal(settleRound({ vote, now: vote.closesAt - 1 }).closed, false);
  const atClose = settleRound({ vote, now: vote.closesAt });
  assert.equal(atClose.outcome, 'failed');
  assert.equal(atClose.vote.closedAt, T0 + ROUND_MS, 'closedAt 记的是「该关的时刻」');
  assert.equal(ROUND_MS, 600_000, '一轮就是 10 分钟');

  const next = advance({
    proposal: proposal(),
    vote: atClose.vote,
    now: atClose.vote.closedAt,
    roster: ['peer-0', 'peer-1', 'peer-2', 'peer-3'],
  });
  assert.equal(next.outcome, 'round-open');
  assert.equal(next.vote.round, 2);
  assert.deepEqual(next.vote.roster, ['peer-0', 'peer-1', 'peer-2', 'peer-3'], '第 2 轮用新冻结的名单');
  assert.deepEqual(next.vote.ballots, {}, '上一轮的票不带进新一轮');
  assert.equal(next.vote.status, 'open');
  assert.equal(next.vote.openedAt, T0 + ROUND_MS);
  assert.equal(next.vote.closesAt, T0 + ROUND_MS * 2);
  assert.equal(tally(next.vote).threshold, 3, '4 人名单要 3 票');

  // 没给新名单就沿用上一轮 —— 绝不隐式重算分母
  const kept = advance({ proposal: proposal(), vote: atClose.vote, now: atClose.vote.closedAt });
  assert.deepEqual(kept.vote.roster, rosterOf(3));
});

// ---------------------------------------------------------------------------
// V5 三轮 shelved
// ---------------------------------------------------------------------------

test('V5 第 3 轮还不过 → shelved、进 shelved 集，且不再开第 4 轮', () => {
  let vote = openRound({ proposal: proposal(), roster: ['peer-a', 'peer-b'], now: T0 });
  const rounds = [];
  for (let index = 0; index < MAX_ROUNDS; index += 1) {
    const settled = settleRound({ vote, now: vote.closesAt });
    assert.equal(settled.outcome, 'failed', `第 ${index + 1} 轮没人投 → 失败`);
    const next = advance({ proposal: proposal(), vote: settled.vote, now: vote.closesAt + 1 });
    rounds.push({ settled, next });
    vote = next.vote;
  }
  assert.deepEqual(rounds.map((entry) => entry.settled.vote.round), [1, 2, 3]);
  assert.deepEqual(rounds.map((entry) => entry.next.outcome), ['round-open', 'round-open', 'shelved']);
  assert.equal(rounds[2].next.shelved, true);
  assert.equal(vote.status, 'shelved');

  // 不再开新轮：round 停在 3，状态停在 shelved
  const again = advance({ proposal: proposal(), vote, now: T0 + 10 * ROUND_MS });
  assert.equal(again.outcome, 'shelved');
  assert.equal(again.shelved, true);
  assert.equal(again.vote.round, MAX_ROUNDS);
  assert.equal(again.vote.status, 'shelved');
  assert.equal(advance({ proposal: proposal(), vote: again.vote, now: T0 + 11 * ROUND_MS }).vote.round, MAX_ROUNDS);

  // shelved 集（平面里的那一条）—— hub 落盘的那份由 host 用例断言，这里断形状与摘要
  const plane = normalizeVotePlane({
    rev:3,
    proposals: [proposal()],
    votes: { p1: again.vote },
    shelved: [{ proposalId: 'p1', rounds: MAX_ROUNDS, at: T0 + 3 * ROUND_MS }],
  });
  assert.deepEqual(plane.shelved, [{ proposalId: 'p1', rounds: 3, at: T0 + 3 * ROUND_MS }]);
  assert.deepEqual(votesSummary(plane), { rev: 3, proposals: 1, open: 0, shelved: 1 });
  // shelved 之后谁也不能再投
  const late = castBallot({ vote: again.vote, peerId: 'peer-a', ballot: 'yes', now: T0 + 12 * ROUND_MS });
  assert.equal(late.accepted, false);
  assert.equal(late.reason, 'vote-closed');
});

// ---------------------------------------------------------------------------
// V6 幂等 + 撞票口径
// ---------------------------------------------------------------------------

test('V6 幂等：settleRound 两次同结果（closedAt 不变）、不重复推进；关轮后迟到票被拒', () => {
  const base = openRound({ proposal: proposal(), roster: rosterOf(3), now: T0 });
  const first = settleRound({ vote: base, now: T0 + ROUND_MS });
  const second = settleRound({ vote: first.vote, now: T0 + ROUND_MS + 5_000 });
  assert.equal(first.outcome, 'failed');
  assert.equal(second.outcome, 'failed');
  assert.deepEqual(second.vote, first.vote, '第二次结算不许改写状态或 closedAt');

  // 不会双推进：从同一个失败轮算两次，出来的都是第 2 轮
  const a = advance({ proposal: proposal(), vote: first.vote, now: T0 + ROUND_MS, roster: ['peer-0', 'peer-1'] });
  const b = advance({ proposal: proposal(), vote: first.vote, now: T0 + ROUND_MS, roster: ['peer-0', 'peer-1'] });
  assert.deepEqual(a.vote, b.vote);
  assert.equal(a.vote.round, 2);
  // 第 2 轮已经开着时再 advance → still-open（不会又开一轮）
  const still = advance({ proposal: proposal(), vote: a.vote, now: T0 + ROUND_MS + 1, roster: ['peer-0'] });
  assert.equal(still.outcome, 'still-open');
  assert.equal(still.vote.round, 2);

  // 关轮后的迟到票：拒绝，且不改记录
  const late = castBallot({ vote: first.vote, peerId: 'peer-0', ballot: 'yes', now: T0 + ROUND_MS });
  assert.equal(late.accepted, false);
  assert.equal(late.reason, 'vote-closed');
  assert.deepEqual(late.vote, first.vote);

  // 撞票口径：**后投覆盖先投**（last-wins），同值重投是幂等的
  let flip = openRound({ proposal: proposal(), roster: rosterOf(2), now: T0 });
  flip = castBallot({ vote: flip, peerId: 'peer-0', ballot: 'yes', now: T0 + 1 }).vote;
  assert.equal(tally(flip).yes, 1);
  flip = castBallot({ vote: flip, peerId: 'peer-0', ballot: 'no', now: T0 + 2 }).vote;
  assert.equal(tally(flip).yes, 0, '改主意：后投的那一票生效');
  assert.equal(tally(flip).no, 1);
  const same = castBallot({ vote: flip, peerId: 'peer-0', ballot: 'no', now: T0 + 3 });
  assert.equal(same.accepted, true, '同值重投也算收下（什么都不变）');
  assert.deepEqual(same.vote, flip);
  // 坏票面 / 缺 peerId 一律拒，原因可读
  assert.equal(castBallot({ vote: flip, peerId: 'peer-0', ballot: 'maybe', now: T0 + 4 }).reason, 'vote-ballot-invalid');
  assert.equal(castBallot({ vote: flip, peerId: '  ', ballot: 'yes', now: T0 + 4 }).reason, 'vote-peer-required');
});

// ---------------------------------------------------------------------------
// 校验 / 摘要 / 副本合并（口径与 slice 4a 的纪要同一套）
// ---------------------------------------------------------------------------

test('校验与摘要：正文/种类/目标/作者都要过闸；摘要只吐计数与标量', () => {
  assert.deepEqual(makeProposal({}), { ok: false, error: 'proposal-id-required' });
  assert.equal(makeProposal({ id: 'p1', kind: 'veto', target: { type: 'body', id: 'n1' }, text: 'x', author: 'a', createdAt: 1 }).error, 'proposal-kind-invalid');
  assert.equal(makeProposal({ id: 'p1', kind: 'objection', target: { type: 'chat', id: 'n1' }, text: 'x', author: 'a', createdAt: 1 }).error, 'proposal-target-invalid');
  assert.equal(makeProposal({ id: 'p1', kind: 'objection', target: { type: 'body', id: '' }, text: 'x', author: 'a', createdAt: 1 }).error, 'proposal-target-required');
  assert.equal(makeProposal({ id: 'p1', kind: 'objection', target: { type: 'body', id: 'n1' }, text: '   ', author: 'a', createdAt: 1 }).error, 'proposal-text-empty');
  assert.equal(makeProposal({ id: 'p1', kind: 'objection', target: { type: 'body', id: 'n1' }, text: 'x'.repeat(PROPOSAL_TEXT_MAX + 1), author: 'a', createdAt: 1 }).error, 'proposal-text-too-long');
  assert.equal(makeProposal({ id: 'p1', kind: 'objection', target: { type: 'body', id: 'n1' }, text: '纪'.repeat(PROPOSAL_TEXT_MAX), author: 'a', createdAt: 1 }).ok, true, '上限本身合法，且按 code point 计');
  assert.equal(makeProposal({ id: 'p1', kind: 'objection', target: { type: 'body', id: 'n1' }, text: 'x', author: ' ', createdAt: 1 }).error, 'proposal-author-required');
  assert.equal(makeProposal({ id: 'p1', kind: 'objection', target: { type: 'body', id: 'n1' }, text: 'x', author: 'a', createdAt: 0 }).error, 'proposal-created-at-required');
  const made = makeProposal({ id: ' p7 ', kind: 'supplement', target: { type: 'supplement', id: ' p3 ' }, text: '  补一句  ', author: ' member-b ', createdAt: T0 + 0.7 });
  assert.equal(made.ok, true);
  assert.deepEqual(made.proposal.target, { type: 'supplement', id: 'p3' }, '补丁指向某条补充（不是只能反对正文）');
  assert.equal(made.proposal.text, '补一句');
  assert.equal(made.proposal.createdAt, T0);

  // 摘要：只有计数与标量，绝不带正文
  let vote = voteYes(openRound({ proposal: made.proposal, roster: rosterOf(3), now: T0 }), 2, T0 + 5);
  const summary = summarize(vote);
  assert.deepEqual(Object.keys(summary).sort(), ['closedAt', 'closesAt', 'eligible', 'no', 'openedAt', 'passed', 'proposalId', 'round', 'status', 'threshold', 'yes']);
  assert.equal(summary.yes, 2);
  assert.equal(summary.threshold, 2);
  assert.equal(summary.status, 'open');
  assert.equal(JSON.stringify(summary).includes('补一句'), false, '摘要里不许出现正文');
  // 空/坏输入也问得动（total）
  assert.equal(summarize(null).eligible, 0);
  assert.deepEqual(normalizeVote(null).ballots, {});

  // 副本合并：rev 更大才采纳（与 4a 的纪要同一套判新旧）
  const older = { rev: 2, proposals: [proposal({ id: 'p1' })], votes: { p1: vote }, shelved: [] };
  const newer = { rev: 3, proposals: [proposal({ id: 'p1' }), proposal({ id: 'p2', kind: 'supplement' })], votes: { p1: vote }, shelved: [] };
  assert.equal(mergeVotesReplica(older, newer).rev, 3);
  assert.equal(mergeVotesReplica(newer, older).rev, 3, '对端更旧时绝不回退本地视图');
  assert.equal(mergeVotesReplica(newer, { rev: 3, proposals: newer.proposals, votes: newer.votes, shelved: [] }).proposals.length, 2);
  assert.equal(mergeVotesReplica(null, null).rev, 0);
});

// ---------------------------------------------------------------------------
// V9 非空性
// ---------------------------------------------------------------------------

test('V9 非空性：把「每票重算名单」/「> 而非 >=」换成变异体，V1/V2 的断言立刻红', () => {
  // 变异体 A：分母按**实时在线**重算（掉线的人从分母里消失）—— 正被冻结规则排除的那件事。
  const frozen = openRound({ proposal: proposal(), roster: ['peer-0', 'peer-1', 'peer-2', 'peer-3'], now: T0 });
  const twoOfFour = voteYes(frozen, 2, T0 + 1);
  assert.equal(tally(twoOfFour).passed, false, 'V1 的 roster=4/yes=2 必须失败：2*3 < 4*2');
  // 只有 peer-0/peer-1 还在线（peer-2/peer-3 掉线）→ 变异体把分母缩成 2
  const liveRoster = ['peer-0', 'peer-1'];
  const recalcPerBallot = (vote) => normalizeVote({ ...vote, roster: liveRoster });
  assert.equal(
    tally(recalcPerBallot(twoOfFour)).passed,
    true,
    '变异体（分母缩水）会把 V1 那条「4 人 2 票不过」判成通过 —— 这正是 V2 冻结断言要挡的失败点',
  );
  assert.notEqual(tally(recalcPerBallot(twoOfFour)).passed, tally(twoOfFour).passed);

  // 变异体 B：写成严格大于 `yes > eligible*2/3` —— V1 的「3 人 2 票通过」当场红（2 > 2 是假）。
  const strictPass = (yes, eligible) => yes > (eligible * THRESHOLD_NUM) / THRESHOLD_DEN;
  const twoOfThree = voteYes(openRound({ proposal: proposal(), roster: rosterOf(3), now: T0 }), 2, T0 + 1);
  assert.equal(tally(twoOfThree).passed, true, '真实现：2*3 >= 3*2 通过');
  assert.equal(strictPass(2, 3), false, '变异体（严格大于）：2 > 2 不成立 —— V1 的 3 人那一行立刻红');
  assert.equal(strictPass(4, 5), true, '变异体在「刚好等于」以外的行上看不出来，所以 V1 必须包含 3 人/2 票这一行');
});
