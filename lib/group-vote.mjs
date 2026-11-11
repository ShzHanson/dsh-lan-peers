/**
 * dsh-lan-peers · 0.10.0-α slice 4b-1 群表决状态机（零 I/O 的纯模块）
 * ==================================================================
 * 用户决定（已定稿，别再改）：
 *   · 只有**群纪要/决议**这一层可表决 —— 问答与派单不是可表决对象，所以本模块不认识它们；
 *   · 成员可提「补充」或「反对」；**反对自动开票**，补充默认**直接采纳**（没有异议就不投票）；
 *   · 一轮 10 分钟；每轮开始时**冻结**名单 = 那一刻在线的成员 ——
 *     轮内掉线**不减分母**，轮内上线**不进本轮**（分母是冻结值，不是实时在线数）；
 *   · 通过口径是 2/3，写成整数形式：`yes * THRESHOLD_DEN >= eligible * THRESHOLD_NUM`
 *     （即 `yes * 3 >= roster.length * 2`）。两群人必须两票都 yes —— 这不是 bug，是用户明说的后果；
 *   · 一轮过不了就进下一轮（名单**重新冻结**），第 MAX_ROUNDS 轮还过不了 → `shelved`，
 *     交给人裁决（4b-2 的面板负责把它端到用户面前，本模块只负责把它从 `open` 里摘出来）。
 *
 * 五条不变量：
 *   1. 所有函数都**不改输入**：返回新对象，输入一个字节都不动（调用方能安心重放）；
 *   2. `now` 一律由调用方注入 —— 本模块不认时钟、不起定时器、不读盘，因此可以被假时钟逐毫秒驱动；
 *   3. 所有函数对坏输入**不抛错**（total）：坏形状收敛成空值对象，坏票被丢掉而不是让进程红；
 *   4. 表决正文只进值对象，**不进日志** —— 日志口径由调用方守（≤8 字符 id + 计数）；
 *   5. 名单是**值**不是引用：`roster` 进函数就被复制并排序（定序让两侧/重放逐字节可比）。
 */

/** 通过口径的分子（2）：`yes * DEN >= eligible * NUM` —— 整数形式，不做浮点比较 */
export const THRESHOLD_NUM = 2;
/** 通过口径的分母 */
export const THRESHOLD_DEN = 3;
/** 单轮时长：10 分钟（用户定稿；hub 只允许在测试里用 overrides 改短） */
export const ROUND_MS = 600_000;
/** 最多几轮：第 3 轮还没过 → shelved（交人裁决，绝不开第 4 轮） */
export const MAX_ROUNDS = 3;

/** 单条补充/反对正文上限（与纪要同一把尺：Unicode code point 计，中文不会被拆半个字） */
export const PROPOSAL_TEXT_MAX = 2000;
/** 作者名上限（成员表里的名字口径一致） */
export const PROPOSAL_AUTHOR_MAX = 64;
/** 各种 id 的上限：提案 id / 目标 id 都按这一把尺（日志截到 8，这里管落盘） */
export const PROPOSAL_ID_MAX = 64;
/** 表决平面最多留多少个提案：只丢最旧的（id 号不复用，成员判新旧仍正确） */
export const PROPOSAL_LIMIT = 200;

/** 提案种类：补充（默认采纳）/ 反对（自动开票） */
export const PROPOSAL_KINDS = Object.freeze(['supplement', 'objection']);
/** 反对/补充指向的目标：正文 / 某条补充 / 另一个提案 */
export const TARGET_TYPES = Object.freeze(['body', 'supplement', 'proposal']);
/** 票面只有两种：yes / no（不设弃权 —— 弃权等于没投，分母不减） */
export const BALLOT_VALUES = Object.freeze(['yes', 'no']);
/** 一轮的状态：open 只有 hub 能关；shelved 只能由 advance 产生（第 3 轮失败） */
export const VOTE_STATUSES = Object.freeze(['open', 'passed', 'failed', 'shelved']);

const asText = (value) => (typeof value === 'string' ? value : '');

const asObject = (value) => (value && typeof value === 'object' && !Array.isArray(value) ? value : {});

/** code point 长度：中文/emoji 都按一个字符算，避免把半个字切开 */
export function textLength(value) {
  return Array.from(asText(value)).length;
}

/** 时间归一化：非有限值/非正数一律当 0（坏文件里的时间戳不该让整个平面抛错） */
const toTime = (value) => {
  const at = Number(value);
  return Number.isFinite(at) && at > 0 ? Math.floor(at) : 0;
};

/** 轮次归一化：1..MAX_ROUNDS；坏值按 1 轮算（宁可少算轮次也不越界） */
const toRound = (value) => {
  const round = Number(value);
  if (!Number.isFinite(round) || round < 1) return 1;
  return Math.min(MAX_ROUNDS, Math.floor(round));
};

/**
 * 造一条提案并校验。id 必须由调用方给（hub 用 `p<序号>` 这种短号）：
 * 本函数不生成 id —— 生成就得靠随机/时钟，那就不再是纯函数，重放会得到两个不同的 id。
 *
 * 返回 {ok:true, proposal} 或 {ok:false, error}；error 是稳定的英文码（面板/日志都不翻译它）。
 */
export function makeProposal(input = {}) {
  const source = asObject(input);
  const id = asText(source.id).trim();
  if (id === '') return { ok: false, error: 'proposal-id-required' };
  if (textLength(id) > PROPOSAL_ID_MAX) return { ok: false, error: 'proposal-id-too-long' };
  const kind = asText(source.kind).trim();
  if (!PROPOSAL_KINDS.includes(kind)) return { ok: false, error: 'proposal-kind-invalid' };
  const target = asObject(source.target);
  const type = asText(target.type).trim();
  if (!TARGET_TYPES.includes(type)) return { ok: false, error: 'proposal-target-invalid' };
  const targetId = asText(target.id).trim();
  if (targetId === '') return { ok: false, error: 'proposal-target-required' };
  if (textLength(targetId) > PROPOSAL_ID_MAX) return { ok: false, error: 'proposal-target-too-long' };
  // 正文：首尾空白去掉再判空 —— 只有空白的补充等于没写
  const text = asText(source.text).trim();
  if (text === '') return { ok: false, error: 'proposal-text-empty' };
  if (textLength(text) > PROPOSAL_TEXT_MAX) return { ok: false, error: 'proposal-text-too-long' };
  const author = asText(source.author).trim();
  if (author === '') return { ok: false, error: 'proposal-author-required' };
  if (textLength(author) > PROPOSAL_AUTHOR_MAX) return { ok: false, error: 'proposal-author-too-long' };
  const at = Number(source.createdAt);
  if (!Number.isFinite(at) || at <= 0) return { ok: false, error: 'proposal-created-at-required' };
  return {
    ok: true,
    proposal: {
      id,
      kind,
      target: { type, id: targetId },
      // 正文原样保留（只去首尾空白）：改写会让两侧同一条提案对不上
      text,
      author,
      createdAt: Math.floor(at),
    },
  };
}

/** 提案归一化：坏文件/缺字段的老数据都收敛成合法提案，坏条目**丢掉**而不是抛错 */
export function normalizeProposal(raw) {
  const made = makeProposal(raw);
  return made.ok ? made.proposal : null;
}

/**
 * 投票记录归一化（一轮一份）。形状固定：
 *   { proposalId, round, roster[], ballots{peerId:'yes'|'no'}, openedAt, closesAt, status, closedAt }
 *
 * 三条硬口径：
 *   1. roster 复制 + **去重 + 排序**：定序让重放/两侧比较逐字节相同；
 *   2. ballots 里**名单外的人一律不算**（冻结口径的第二道门：hand-edit 进来的陌生票也不进分母）；
 *   3. status 不认识就按 'open'（宁可多问一次，也不把一轮投票悄悄埋掉）。
 */
export function normalizeVote(raw) {
  const source = asObject(raw);
  const proposalId = asText(source.proposalId).trim();
  const roster = [];
  const seen = new Set();
  for (const entry of Array.isArray(source.roster) ? source.roster : []) {
    const peerId = asText(entry).trim();
    if (peerId === '' || seen.has(peerId)) continue;
    seen.add(peerId);
    roster.push(peerId);
  }
  roster.sort();
  const ballots = {};
  const rawBallots = asObject(source.ballots);
  for (const [peerId, value] of Object.entries(rawBallots)) {
    if (!seen.has(peerId)) continue;
    const ballot = asText(value).trim();
    if (!BALLOT_VALUES.includes(ballot)) continue;
    ballots[peerId] = ballot;
  }
  const openedAt = toTime(source.openedAt);
  const closesAtRaw = Number(source.closesAt);
  const closesAt = Number.isFinite(closesAtRaw) && closesAtRaw >= openedAt
    ? Math.floor(closesAtRaw)
    : openedAt + ROUND_MS;
  const status = VOTE_STATUSES.includes(asText(source.status)) ? asText(source.status) : 'open';
  return {
    proposalId,
    round: toRound(source.round),
    roster,
    ballots,
    openedAt,
    closesAt,
    status,
    closedAt: toTime(source.closedAt),
  };
}

/**
 * 开一轮：名单**在这一刻冻结**（调用方只传「此刻在线的成员」，之后轮内变化与本轮无关）。
 *
 * 返回一轮 vote 记录（不返回 {ok}：本函数 total，坏输入收敛成一圈「没人能投」的空轮）。
 * 空名单不是「自动通过」：eligible=0 时 tally 一律判 impossible（`0*3 >= 0*2` 会让空群
 * 凭空通过，那是必须堵掉的洞）；hub 侧也保证名单至少含自己（hub 永远在线）。
 *
 * `round`/`roundMs` 只为 advance 重开与测试注入存在，生产路径用默认值 1 / ROUND_MS。
 */
export function openRound({ proposal, roster, now = 0, round = 1, roundMs = ROUND_MS } = {}) {
  const made = normalizeProposal(proposal);
  const at = toTime(now);
  const span = Number.isFinite(Number(roundMs)) && Number(roundMs) > 0 ? Math.floor(Number(roundMs)) : ROUND_MS;
  return normalizeVote({
    proposalId: made ? made.id : '',
    round,
    roster,
    ballots: {},
    openedAt: at,
    closesAt: at + span,
    status: 'open',
    closedAt: 0,
  });
}

/**
 * 投一票。四种拒绝（reason 是稳定英文码，调用方原样回给成员并记日志）：
 *   - `vote-closed`：这一轮已经结算，或 `now >= closesAt`（迟到票一律不算 —— 结算过的分母不许再动）；
 *   - `vote-not-eligible`：不在**冻结名单**里（轮内掉线的人还能投、轮内上线的人不能投）；
 *   - `vote-ballot-invalid`：票面不是 yes/no；
 *   - `vote-peer-required`：没给 peerId。
 *
 * 撞票口径：**后投覆盖先投（last-wins）**。理由：同一轮里成员改主意是正常操作，而 first-wins
 * 会让「点错了」无法纠正、还会逼 UI 去猜谁是最终意图；last-wins 在冻结名单下仍然安全 ——
 * 分母不动、一人一票、覆盖只影响自己的那一格。等价于幂等重投（同值再投一次等于什么都没变）。
 */
export function castBallot({ vote, peerId, ballot, now = 0 } = {}) {
  const current = normalizeVote(vote);
  const id = asText(peerId).trim();
  if (id === '') return { vote: current, accepted: false, reason: 'vote-peer-required' };
  const value = asText(ballot).trim();
  if (!BALLOT_VALUES.includes(value)) return { vote: current, accepted: false, reason: 'vote-ballot-invalid' };
  const at = toTime(now);
  if (current.status !== 'open') return { vote: current, accepted: false, reason: 'vote-closed' };
  if (at >= current.closesAt) return { vote: current, accepted: false, reason: 'vote-closed' };
  if (!current.roster.includes(id)) return { vote: current, accepted: false, reason: 'vote-not-eligible' };
  const ballots = { ...current.ballots, [id]: value };
  return { vote: { ...current, ballots }, accepted: true, reason: '' };
}

/**
 * 计票。四个口径一次算清，调用方不需要自己乘：
 *   - `threshold` = ceil(eligible * NUM / DEN) = 「还差几票 yes」（名单 5 → 4，这就是 ceil 的来历）；
 *   - `passed`    = `eligible > 0 && yes * THRESHOLD_DEN >= eligible * THRESHOLD_NUM`（即 yes*3 >= eligible*2）；
 *   - `impossible`= 没通过，且**剩下的票全投 yes 也够不到**（yes + 未投）* NUM < eligible * DEN；
 *     空名单也归到 impossible（见 openRound 的注释）。
 */
export function tally(vote) {
  const current = normalizeVote(vote);
  const eligible = current.roster.length;
  let yes = 0;
  let no = 0;
  for (const value of Object.values(current.ballots)) {
    if (value === 'yes') yes += 1;
    else if (value === 'no') no += 1;
  }
  const threshold = Math.ceil((eligible * THRESHOLD_NUM) / THRESHOLD_DEN);
  const passed = eligible > 0 && yes * THRESHOLD_DEN >= eligible * THRESHOLD_NUM;
  const remaining = Math.max(0, eligible - yes - no);
  const reachable = eligible > 0 && (yes + remaining) * THRESHOLD_DEN >= eligible * THRESHOLD_NUM;
  return { yes, no, eligible, threshold, passed, impossible: !passed && !reachable };
}

/**
 * 结算一轮。三条关轮路径（顺序就是优先级）：
 *   1. 票到齐了（passed）→ 立刻关，`closedAt = now`（不等 10 分钟）；
 *   2. 没救了（impossible）→ 立刻关，别让所有人干等到点；
 *   3. `now >= closesAt` → 按点关，`closedAt = closesAt`（记的是**该关的时刻**，不是被叫醒的时刻）。
 *
 * **幂等**：已经结算过的一轮原样返回（outcome 就是它现在的状态，closedAt 不变）。
 * 定时器重复触发、网络重试、hub 重启补结算都能安全重放 —— 不会把 closedAt 刷成新时间，也不会再往前推进一轮。
 */
export function settleRound({ vote, now = 0 } = {}) {
  const current = normalizeVote(vote);
  if (current.status !== 'open') return { vote: current, outcome: current.status, closed: true };
  const at = toTime(now);
  const counts = tally(current);
  if (counts.passed) return { vote: { ...current, status: 'passed', closedAt: at }, outcome: 'passed', closed: true };
  if (counts.impossible) {
    return { vote: { ...current, status: 'failed', closedAt: at }, outcome: 'failed', closed: true };
  }
  if (at >= current.closesAt) {
    return { vote: { ...current, status: 'failed', closedAt: current.closesAt }, outcome: 'failed', closed: true };
  }
  return { vote: current, outcome: 'still-open', closed: false };
}

/**
 * 由「上一轮的结果」算下一个状态：
 *   - `passed`     → 保持（提案生效）；
 *   - `still-open` → 还开着，什么都不做（调用方别重开）；
 *   - `round-open` → 第 round+1 轮，名单**重新冻结**（`roster` 由 hub 传最新的在线名单）；
 *   - `shelved`    → 第 MAX_ROUNDS 轮也没过，摘出 open 交人裁决（**绝不开第 4 轮**）。
 *
 * `roster` 没给就沿用上一轮的名单 —— **绝不隐式重算**：本模块不认识在线状态，
 * 「新名单」只能由 hub 冻结后传进来（认时钟/在线状态就不是纯函数了）。
 */
export function advance({ proposal, vote, now = 0, roster = null, roundMs = ROUND_MS } = {}) {
  const current = vote ? normalizeVote(vote) : null;
  if (!current || current.proposalId === '') return { outcome: 'no-vote', vote: null, shelved: false };
  if (current.status === 'passed') return { outcome: 'passed', vote: current, shelved: false };
  if (current.status === 'shelved') return { outcome: 'shelved', vote: current, shelved: true };
  if (current.status === 'open') return { outcome: 'still-open', vote: current, shelved: false };
  if (current.round < MAX_ROUNDS) {
    const frozen = roster == null ? current.roster : roster;
    const next = openRound({
      proposal: { ...asObject(proposal), id: current.proposalId },
      roster: frozen,
      now,
      round: current.round + 1,
      roundMs,
    });
    return { outcome: 'round-open', vote: next, shelved: false };
  }
  return { outcome: 'shelved', vote: { ...current, status: 'shelved' }, shelved: true };
}

/**
 * 状态行/UI 用的便宜摘要：**只有计数与标量，没有正文**（日志与面板摘要共用这一份口径）。
 * 未知/空票也能问：返回一圈 0，不抛错。
 */
export function summarize(vote) {
  const current = normalizeVote(vote);
  const counts = tally(current);
  return {
    proposalId: current.proposalId,
    round: current.round,
    status: current.status,
    eligible: counts.eligible,
    threshold: counts.threshold,
    yes: counts.yes,
    no: counts.no,
    passed: counts.passed,
    openedAt: current.openedAt,
    closesAt: current.closesAt,
    closedAt: current.closedAt,
  };
}

// ---------------------------------------------------------------------------
// 值对象：表决平面（hub 落盘 / 上网 / 成员副本都是这一个形状）
// ---------------------------------------------------------------------------

/** 一条 shelved 记录的归一化：{proposalId, rounds, at}（只留「谁、几轮、什么时候」） */
function normalizeShelvedEntry(raw) {
  const source = asObject(raw);
  const proposalId = asText(source.proposalId).trim();
  if (proposalId === '') return null;
  const rounds = Number(source.rounds);
  return {
    proposalId,
    rounds: Number.isFinite(rounds) && rounds > 0 ? Math.min(MAX_ROUNDS, Math.floor(rounds)) : MAX_ROUNDS,
    at: toTime(source.at),
  };
}

/**
 * 表决平面归一化：`{ rev, proposals[], votes{proposalId: vote}, shelved[] }`。
 *
 * `rev` 是**显式**字段，只由 hub 的写入前进，永不回退 —— 成员靠它判「谁的视图更新」
 * （与 slice 4a 的纪要同一套判新旧办法，成员侧不重写盘）。坏条目逐条丢掉，不抛错。
 */
export function normalizeVotePlane(raw) {
  const source = asObject(raw);
  const rev = Number(source.rev);
  const seen = new Set();
  const proposals = [];
  for (const entry of Array.isArray(source.proposals) ? source.proposals : []) {
    const made = normalizeProposal(entry);
    if (!made || seen.has(made.id)) continue;
    seen.add(made.id);
    proposals.push(made);
  }
  const kept = proposals.length > PROPOSAL_LIMIT ? proposals.slice(proposals.length - PROPOSAL_LIMIT) : proposals;
  const votes = {};
  const rawVotes = asObject(source.votes);
  for (const [proposalId, entry] of Object.entries(rawVotes)) {
    const vote = normalizeVote(entry);
    // 键与记录里的 proposalId 必须自洽；对不上就按**键**改名（键才是落盘的那一列）
    votes[proposalId] = { ...vote, proposalId: vote.proposalId === '' ? proposalId : vote.proposalId };
  }
  const shelved = [];
  const shelvedSeen = new Set();
  for (const entry of Array.isArray(source.shelved) ? source.shelved : []) {
    const made = normalizeShelvedEntry(entry);
    if (!made || shelvedSeen.has(made.proposalId)) continue;
    shelvedSeen.add(made.proposalId);
    shelved.push(made);
  }
  return {
    rev: Number.isFinite(rev) && rev > 0 ? Math.floor(rev) : 0,
    proposals: kept,
    votes,
    shelved,
  };
}

/**
 * 成员侧合并（只读同步）：**remote.rev 更大才采纳**，否则原样留住本地视图。
 * rev 相等保留本地对象本身（不是「内容一样」，而是「没新信息就别重写盘」）。
 */
export function mergeVotesReplica(local, remote) {
  const mine = normalizeVotePlane(local);
  const theirs = normalizeVotePlane(remote);
  if (theirs.rev > mine.rev) return theirs;
  return mine;
}

/** 状态行用的便宜摘要：rev / 提案数 / 开着的轮数 / shelved 数（没有一个字的内容） */
export function votesSummary(plane) {
  const base = normalizeVotePlane(plane);
  let open = 0;
  for (const vote of Object.values(base.votes)) if (vote.status === 'open') open += 1;
  return { rev: base.rev, proposals: base.proposals.length, open, shelved: base.shelved.length };
}
