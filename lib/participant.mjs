/**
 * dsh-lan-peers · 常驻参与者（resident participant）
 * =================================================
 * 用户决定（三条，已定稿，别再改）：
 *   1. 群里每来一条新消息都进这个参与者，一个 30s 批次只唤醒**一次**；
 *      决策事件（提案开票 / 进下一轮 / 被搁置）**立即**唤醒，不等批次窗；
 *   2. 发言**不限速**（用户明确否掉了节流）—— 本文件里没有任何速率闸；
 *   3. 私聊同一个参与者：对端来的 DM 立刻唤醒本机 agent 去讨论/回复。
 *
 * 三把锁都不是限速，是**环路保护**：
 *   · 回声闸：本机作者的消息永不唤醒（自己说的话不该叫醒自己）；
 *   · 系统行闸：/task 回执、搁置提醒、表决通知是机器行的系统消息，不进唤醒队列；
 *   · 乒乓闸：同一对端连续 3 条「参与者作者」的远程消息（中间没有人的消息）→
 *     暂停该对端 10 分钟的唤醒并写一行 [participant] loop-break peer=<8>，窗口过后自动恢复。
 *
 * 汇报（slice E，用户定稿）：每个频道（群 / 私聊）满了 6 小时**或** 200 条消息，先到先算一次 ——
 * 先问**这个频道自己的会话**要一个 ≤1200 字的紧凑摘要，再把一份汇报打进**指挥官会话**；
 * 指挥官用既有的 lan_session_ask 把活派回这两个参与者会话（不另起第二条通道）。
 * 指挥官会话造一次、用到底（永不轮换）；任何一步失败只记一行，下一个窗口再试，绝不 spin。
 *
 * 铁律：
 *   - 时钟与定时器由调用方注入（用例里没有一个真 sleep）；
 *   - 会话是**常驻**的：<stateDir>/participant.json 里的 sessionId 造一次、用到底，
 *     只有「打进去说这个会话没了」时才重建**一次**，并记 [participant] session-recreated；
 *   - 日志只到 id ≤8 与条数，正文一个字都不进日志（与群消息同一口径）。
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/** 常驻会话身份文件（与 group-resident.json / group-role.json 同一目录、同一 0600 口径） */
export const PARTICIPANT_FILE = 'participant.json';

/** 批量窗：窗口内的群消息合成一次唤醒（用户定的 30s） */
export const PARTICIPANT_BATCH_MS = 30_000;
/** 汇报窗口：6 小时（用户定的；与「200 条」先到先算） */
export const PARTICIPANT_REPORT_MS = 21_600_000;
/** 汇报窗口：200 条消息（用户定的；每个频道单独算） */
export const PARTICIPANT_REPORT_MESSAGES = 200;
/** 汇报摘要上限（code point 计；超了截断并加省略号） */
export const REPORT_SUMMARY_MAX = 1_200;
/** 频道表（顺序稳定：先 group 后 dm） */
export const PARTICIPANT_CHANNELS = Object.freeze(['group', 'dm']);
/** 汇报摘要最多等多久（宿主那边的轮询预算） */
export const SUMMARY_WAIT_MS = 20_000;
/** 汇报摘要的轮询步长 */
export const SUMMARY_POLL_MS = 200;
/** 乒乓闸：连续几条「参与者作者」的远程消息就停 */
export const LOOP_BREAK_STREAK = 3;
/** 乒乓闸的暂停窗（10 分钟；窗口过后自动恢复） */
export const LOOP_BREAK_MS = 600_000;
/** 塞进唤醒提示的正文片段上限（Unicode code point 计：中文不会被拆半个字） */
export const WAKE_ITEM_MAX = 400;
/** 记过的 DM 条目 id 上限：只为去重，超出按最旧丢弃 */
export const DM_SEEN_MAX = 200;

/**
 * 「这条帖子是本机的**参与者**发的」标记。
 *
 * 为什么借用 meta.transport：群消息的 meta 白名单（host/server.mjs 与
 * lib/group-client.mjs 各一份）只放行固定几个字段，新键会在发送前与落盘前各被丢弃一次；
 * 而 transport 是白名单里唯一的自由字符串字段（旧 progress/result 行才用它，0.10.0-α
 * 起这两种 kind 已不再产生）。改白名单要动本切片边界外的文件，所以标记走这个现成字段。
 */
export const PARTICIPANT_MARK = 'participant';

/**
 * 系统行的正文前缀（除了 kind 之外的第二道闸）：
 * 这些行即便被塞进 kind=chat，也不该叫醒任何人 —— 它们不是人在说话。
 */
export const SYSTEM_TEXT_PREFIXES = Object.freeze(['[group] vote', '[system]', '[task]']);

const asText = (value) => (typeof value === 'string' ? value : '');

/** 正文片段：按 code point 截断，绝不把半个字切开 */
export function clipText(value, max = WAKE_ITEM_MAX) {
  const chars = Array.from(asText(value).replace(/\s+/g, ' ').trim());
  if (chars.length <= max) return chars.join('');
  return chars.slice(0, max).join('') + '…';
}

/**
 * 配置归一化：两个频道默认都开（用户要求），batchMs 默认 30s，汇报窗默认 6h / 200 条。
 * 只有**布尔 false** 关频道、关汇报；坏值一律回落到默认值（不抛错）。
 * commander:false 是**回滚闸**：参与者照常醒，只是不再往指挥官会话汇报。
 */
export function normalizeParticipantConfig(value) {
  const source = value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  const batch = Number(source.batchMs);
  const reportMs = Number(source.reportEveryMs);
  const reportMessages = Number(source.reportEveryMessages);
  return {
    group: source.group === false ? false : true,
    dm: source.dm === false ? false : true,
    commander: source.commander === false ? false : true,
    batchMs: Number.isFinite(batch) && batch >= 1 ? Math.floor(batch) : PARTICIPANT_BATCH_MS,
    reportEveryMs: Number.isFinite(reportMs) && reportMs >= 1 ? Math.floor(reportMs) : PARTICIPANT_REPORT_MS,
    reportEveryMessages: Number.isFinite(reportMessages) && reportMessages >= 1
      ? Math.floor(reportMessages)
      : PARTICIPANT_REPORT_MESSAGES,
  };
}

const positiveInt = (value) => {
  const number = Number(value);
  return Number.isFinite(number) && number > 0 ? Math.floor(number) : 0;
};

/** 汇报里的会话短 id：id 的**尾部** 8 位（与 lib/tools.mjs 的 sessionTail 同一口径） */
export const shortSessionId = (value) => {
  const text = asText(value);
  return text.length <= 8 ? text : text.slice(-8);
};

/**
 * 状态文件归一 + 迁移（纯函数，可单测；**幂等**：migrate(migrate(x)) 与 migrate(x) 全等）。
 *
 * 新形状：{ commander:{sessionId,createdAt}, group:{...}, dm:{...} }
 * 频道形状：{ sessionId, since, msgCount, summarizedAt, summary, reports }
 *
 * 旧形状（slice C）顶层只有一个 sessionId：那个常驻会话就是 **group 频道**的会话，
 * dm 与 commander 现造（sessionId 空 = 第一次用到时再建）。这里只补齐记录 ——
 * 真建会话要打一次宿主，那是异步的，不属于迁移。
 */
export function migrateParticipantState(raw, nowMs = 0) {
  const clock = positiveInt(nowMs) || Date.now();
  const source = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  const entryOf = (value) => (value && typeof value === 'object' && !Array.isArray(value) ? value : null);
  const channelOf = (value, fallbackSince) => {
    const entry = entryOf(value);
    return {
      sessionId: asText(entry?.sessionId),
      since: positiveInt(entry?.since) || fallbackSince,
      msgCount: Math.max(0, Math.floor(Number(entry?.msgCount) || 0)),
      summarizedAt: positiveInt(entry?.summarizedAt),
      summary: asText(entry?.summary),
      reports: Math.max(0, Math.floor(Number(entry?.reports) || 0)),
    };
  };
  const group = channelOf(source.group, positiveInt(source.createdAt) || clock);
  // 旧形状：顶层那个常驻会话归 group 频道（不丢，继续用）
  if (group.sessionId === '') group.sessionId = asText(source.sessionId);
  const commander = entryOf(source.commander);
  return {
    commander: { sessionId: asText(commander?.sessionId), createdAt: positiveInt(commander?.createdAt) },
    group,
    dm: channelOf(source.dm, clock),
  };
}

/** 这条群消息是本机参与者发的吗（另一个节点的参与者也会带同一个标记） */
export function isParticipantAuthored(message) {
  return asText(message?.meta?.transport) === PARTICIPANT_MARK;
}

/** 系统行：kind 不是 chat，或者正文以系统前缀开头 */
export function isSystemLine(message) {
  if (asText(message?.kind) !== 'chat') return true;
  const body = asText(message?.text).trim();
  return SYSTEM_TEXT_PREFIXES.some((prefix) => body.startsWith(prefix));
}

/** 表决平面 → id -> {round, status}（决策事件的比较基准） */
export function snapshotPlane(plane) {
  const out = new Map();
  const votes = plane?.votes && typeof plane.votes === 'object' ? plane.votes : {};
  for (const entry of Array.isArray(plane?.proposals) ? plane.proposals : []) {
    const id = asText(entry?.id);
    if (id === '') continue;
    const vote = votes[id] && typeof votes[id] === 'object' ? votes[id] : null;
    out.set(id, {
      round: Math.max(1, Math.floor(Number(vote?.round ?? 1) || 1)),
      status: asText(vote?.status) || 'open',
    });
  }
  return out;
}

/**
 * 决策事件（纯函数）：开票 / 进下一轮 / 被搁置。
 * 「人已经裁决」不是决策事件 —— 那件事已经结束，没有需要本机去投的票。
 */
export function decisionEvents(plane, previous) {
  const prev = previous instanceof Map ? previous : new Map();
  const votes = plane?.votes && typeof plane.votes === 'object' ? plane.votes : {};
  const out = [];
  for (const entry of Array.isArray(plane?.proposals) ? plane.proposals : []) {
    const id = asText(entry?.id);
    if (id === '') continue;
    const vote = votes[id] && typeof votes[id] === 'object' ? votes[id] : null;
    const status = asText(vote?.status) || 'open';
    const round = Math.max(1, Math.floor(Number(vote?.round ?? 1) || 1));
    const closesAt = Number(vote?.closesAt) > 0 ? Number(vote.closesAt) : 0;
    const seen = prev.get(id) ?? null;
    // 第一次看见就已经搁置的提案，按搁置报（更急的那一格），不报「开票」
    if (!seen) out.push({ proposalId: id, round, status, closesAt, event: status === 'shelved' ? 'shelved' : 'opened' });
    else if (status === 'shelved' && seen.status !== 'shelved') out.push({ proposalId: id, round, status, closesAt, event: 'shelved' });
    else if (round > seen.round) out.push({ proposalId: id, round, status, closesAt, event: 'round' });
  }
  return out;
}

const DECISION_RANK = Object.freeze({ shelved: 3, round: 2, opened: 1 });

/** 一次唤醒只讲最急的那一个决定（搁置 > 进轮 > 开票） */
export function pickDecision(events) {
  let best = null;
  for (const event of Array.isArray(events) ? events : []) {
    if (!best || (DECISION_RANK[event.event] ?? 0) > (DECISION_RANK[best.event] ?? 0)) best = event;
  }
  return best;
}

const shortId = (value) => asText(value).slice(0, 8);

/**
 * 造一个常驻参与者。
 *
 * 注入面（全部可假）：
 *   selfId()          本机 instanceId（回声闸用）
 *   promptSession(sessionId, prompt) -> {sessionId, reused}
 *                     本机唤醒通道；sessionId 为空串 = 新建，等于 lib/runner-ctx.mjs 的 ask
 *   askSummary(sessionId, prompt) -> {sessionId, reused, reply}
 *                     汇报摘要通道：问一次并读回那条回复（不注入就用 promptSession，
 *                     它不带 reply 时摘要为空 = summary-failed）
 *   proposalPlane()   表决平面只读视图（server.group.votes()）
 *   log(line)         一行日志
 *   now / setTimeoutFn / clearTimeoutFn   时钟与定时器
 */
export function createParticipant({
  stateDir,
  selfId = () => '',
  config = {},
  promptSession = null,
  askSummary = null,
  proposalPlane = () => null,
  log = null,
  now = Date.now,
  setTimeoutFn = (fn, ms) => setTimeout(fn, ms),
  clearTimeoutFn = (handle) => clearTimeout(handle),
} = {}) {
  const settings = normalizeParticipantConfig(config);
  const dir = path.resolve(String(stateDir ?? '.'));
  const file = path.join(dir, PARTICIPANT_FILE);
  const logLine = (line) => {
    if (typeof log === 'function') log(line);
  };
  const timeOf = () => {
    const value = Number(now());
    return Number.isFinite(value) ? value : 0;
  };

  /** 群消息批次（窗口内累积；只存唤醒提示需要的那几个字段） */
  let queue = [];
  /** 私聊批次 */
  let dms = [];
  /** 待唤醒的决策事件（一次只留最急的一条） */
  let decision = null;
  /** 批量窗定时器（同一时刻至多一个；unref 过，不吊住进程） */
  let timer = null;
  let closed = false;
  let lastSeq = 0;
  let planeState = new Map();
  let chain = Promise.resolve();
  /** peerId -> {count, pausedUntil}：乒乓闸 */
  const streak = new Map();
  const seenDm = new Set();

  // ---- 常驻会话身份（三个：group 频道 / dm 频道 / 指挥官） ------------------

  /** 旧形状（顶层只有 sessionId）或缺文件：迁移之后要**立刻**按新形状落盘 */
  function needsMigration(raw) {
    if (raw === null || typeof raw !== 'object') return true;
    if (raw.sessionId !== undefined) return true;
    return !raw.group || !raw.dm || !raw.commander;
  }

  function readState() {
    let raw = null;
    let missing = true;
    try {
      raw = JSON.parse(fs.readFileSync(file, 'utf8'));
      missing = false;
    } catch {
      raw = null;
    }
    const next = migrateParticipantState(raw, timeOf());
    // 迁移是「就地」的：迁移一次之后，磁盘上就是新形状（再跑一次是 no-op）
    if (missing || needsMigration(raw)) persistState(next);
    return next;
  }

  const state = readState();
  const channels = { group: state.group, dm: state.dm };

  function snapshot() {
    const channel = (entry) => ({
      sessionId: entry.sessionId,
      since: entry.since,
      msgCount: entry.msgCount,
      summarizedAt: entry.summarizedAt,
      summary: entry.summary,
      reports: entry.reports,
    });
    return {
      commander: { sessionId: state.commander.sessionId, createdAt: state.commander.createdAt },
      group: channel(channels.group),
      dm: channel(channels.dm),
    };
  }

  function persistState(next = snapshot()) {
    try {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      const tmp = file + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify(next, null, 2) + '\n', { mode: 0o600 });
      fs.renameSync(tmp, file);
    } catch (error) {
      logLine('[participant] session write failed: ' + asText(error?.message ?? error).slice(0, 120));
    }
  }

  function adoptChannel(name, previousId, out, forced) {
    const entry = channels[name];
    const nextId = asText(out?.sessionId);
    if (nextId === '') {
      if (forced) logLine('[participant] session-recreated');
      return;
    }
    // 宿主自己回退新建过（reused=false / id 变了）= 旧会话已经不在了
    const recreated = forced || (previousId !== '' && (nextId !== previousId || out?.reused === false));
    if (previousId === nextId && !recreated) return;
    entry.sessionId = nextId;
    persistState();
    if (recreated) logLine('[participant] session-recreated');
  }

  // ---- 环路保护 -----------------------------------------------------------

  function paused(peerId) {
    const entry = peerId === '' ? null : streak.get(peerId);
    if (!entry) return false;
    if (entry.pausedUntil > timeOf()) return true;
    // 窗口过了：自动恢复（计数一起归零，下一次是全新的一串）
    if (entry.pausedUntil > 0) {
      entry.pausedUntil = 0;
      entry.count = 0;
    }
    return false;
  }

  function noteAuthored(peerId, participantAuthored) {
    if (peerId === '') return;
    const entry = streak.get(peerId) ?? { count: 0, pausedUntil: 0 };
    if (!participantAuthored) {
      // 人的消息把这一串打断
      entry.count = 0;
      streak.set(peerId, entry);
      return;
    }
    entry.count += 1;
    if (entry.count >= LOOP_BREAK_STREAK && entry.pausedUntil <= timeOf()) {
      entry.pausedUntil = timeOf() + LOOP_BREAK_MS;
      logLine('[participant] loop-break peer=' + shortId(peerId));
    }
    streak.set(peerId, entry);
  }

  // ---- 批次与唤醒 ---------------------------------------------------------

  function schedule() {
    if (closed || timer !== null) return;
    timer = setTimeoutFn(() => {
      timer = null;
      flush();
    }, settings.batchMs);
    // 定时器绝不吊住进程（真机回归用例正是在抓这个）
    if (timer && typeof timer.unref === 'function') timer.unref();
  }

  function flushNow() {
    if (timer !== null) {
      clearTimeoutFn(timer);
      timer = null;
    }
    flush();
  }

  function flush() {
    if (closed) return;
    const batch = queue;
    const dmBatch = dms;
    const vote = decision;
    queue = [];
    dms = [];
    decision = null;
    if (batch.length === 0 && dmBatch.length === 0 && vote === null) return;
    // 日志口径：只到 id ≤8 与条数，正文一个字都不进日志
    if (vote !== null) {
      logLine('[participant] wake kind=vote proposal=' + shortId(vote.proposalId) + ' round=' + vote.round);
    }
    if (dmBatch.length > 0) logLine('[participant] wake kind=dm peer=' + shortId(dmBatch[0].peerId));
    if (batch.length > 0) logLine('[participant] wake kind=group batch=' + batch.length);
    // 计数跟着这一批落盘（一条一次太吵，一批一次就够）
    persistState();
    // 每个频道打**自己**那个常驻会话：群批（+ 表决决定）走 group，私聊批走 dm
    if (batch.length > 0 || vote !== null) {
      const prompt = buildGroupPrompt({ batch, vote });
      // 串行：上一次唤醒的 prompt 还在一轮里，下一次排队（不并发打同一个会话）
      chain = chain.then(() => deliver('group', prompt)).catch(() => {});
    }
    if (dmBatch.length > 0) {
      const prompt = buildDmPrompt({ dmBatch });
      chain = chain.then(() => deliver('dm', prompt)).catch(() => {});
    }
  }

  function buildGroupPrompt({ batch, vote }) {
    const parts = [];
    if (batch.length > 0) parts.push(batch.length + ' 条群消息');
    if (vote !== null) parts.push('一个表决决定');
    const lines = ['【常驻参与者 · 唤醒】本机进入了一个新批次：' + parts.join(' + ') + '。'];
    if (batch.length > 0) {
      lines.push('群消息（本批 ' + batch.length + ' 条，按 seq 升序）：');
      for (const item of batch) {
        lines.push('- seq=' + item.seq + ' ' + (item.name === '' ? '-' : item.name)
          + '(' + shortId(item.peerId) + '): ' + clipText(item.text));
      }
      lines.push('要在这个群里说话就用 lan_group_post（参数 text）—— 这条会**公开发给整个群**，不只发给一个人。');
      lines.push('只想看看群里在说什么、或者想投票，就用 lan_group_proposals。');
    }
    if (vote !== null) {
      // 提示里给**完整**提案 id：lan_group_vote 收的就是它（日志才截到 8 位）
      lines.push('表决：提案 ' + vote.proposalId + '（' + vote.event + '）第 ' + vote.round + ' 轮'
        + '，本机还没投/还要再看一眼票数。');
      lines.push('本轮截止（UTC）= ' + (vote.closesAt > 0 ? new Date(vote.closesAt).toISOString() : 'none'));
      lines.push('先 lan_group_proposals 看票数与自己那一票，再用 lan_group_vote（参数 proposalId、decision=adopt|reject）投本机那一票；每台机器一条提案只有一票。');
    }
    return lines.join('\n');
  }

  function buildDmPrompt({ dmBatch }) {
    const lines = ['【常驻参与者 · 唤醒】本机进入了一个新批次：' + dmBatch.length + ' 条私聊。'];
    for (const item of dmBatch) {
      lines.push('- 私聊来自 peer=' + shortId(item.peerId) + ': ' + clipText(item.text));
    }
    lines.push('要回复这个对端就走同一条 1:1 通道：lan_peer_ask（参数 peer、prompt）。');
    return lines.join('\n');
  }

  /** 真发一次：那个频道的会话没了就**只**重建一次 */
  async function deliver(name, prompt) {
    if (typeof promptSession !== 'function') return;
    const current = channels[name].sessionId;
    try {
      const out = await promptSession(current, prompt);
      adoptChannel(name, current, out, false);
    } catch {
      try {
        const out = await promptSession('', prompt);
        adoptChannel(name, '', out, true);
      } catch (error) {
        logLine('[participant] wake failed: ' + asText(error?.message ?? error).slice(0, 120));
      }
    }
  }

  // ---- 汇报（频道 → 指挥官会话） ------------------------------------------

  /** channel -> 下一次尝试的时刻：只在失败后设（不 spin）。不落盘：重启后多试一次也无害 */
  const retryAt = new Map();
  /** 正在飞的那份汇报：同一频道同一时刻只有一份 */
  const reporting = new Set();
  let reportTimer = null;
  let reportChain = Promise.resolve();

  const channelOn = (name) => (name === 'group' ? settings.group : settings.dm);
  const charCount = (text) => Array.from(asText(text)).length;
  const isoOf = (ms) => (positiveInt(ms) > 0 ? new Date(positiveInt(ms)).toISOString() : 'none');

  /** 该频道下一个「该汇报」的时刻（失败过就是失败后推出来的那个窗口） */
  function windowEnd(name) {
    const gate = retryAt.get(name) ?? 0;
    if (gate > 0) return gate;
    return channels[name].since + settings.reportEveryMs;
  }

  /**
   * 到了吗：时间窗（since + reportEveryMs）**或**条数（reportEveryMessages），先到先算。
   * 失败过的频道只剩时间窗这一条路 —— 计数不动，等下一个窗口再试，而不是原地重打。
   */
  function reportDue(name, nowMs) {
    if (closed || !settings.commander || !channelOn(name)) return false;
    const entry = channels[name];
    if (!entry || entry.msgCount <= 0) return false;
    // 已经在飞的那一份，落地之后自己会重新排一次（否则会排出一个 0 延迟的自我循环）
    if (reporting.has(name)) return false;
    const gate = retryAt.get(name) ?? 0;
    if (gate > 0) return nowMs >= gate;
    return entry.msgCount >= settings.reportEveryMessages || nowMs >= entry.since + settings.reportEveryMs;
  }

  function scheduleReport() {
    if (reportTimer !== null) {
      clearTimeoutFn(reportTimer);
      reportTimer = null;
    }
    if (closed || !settings.commander) return;
    let at = 0;
    for (const name of PARTICIPANT_CHANNELS) {
      if (!channelOn(name) || channels[name].msgCount <= 0 || reporting.has(name)) continue;
      const due = windowEnd(name);
      if (at === 0 || due < at) at = due;
    }
    if (at === 0) return;
    reportTimer = setTimeoutFn(() => {
      reportTimer = null;
      pumpReports();
    }, Math.max(0, at - timeOf()));
    if (reportTimer && typeof reportTimer.unref === 'function') reportTimer.unref();
  }

  function pumpReports() {
    if (closed || !settings.commander) return;
    const nowMs = timeOf();
    for (const name of PARTICIPANT_CHANNELS) {
      if (reportDue(name, nowMs)) enqueueReport(name);
    }
    scheduleReport();
  }

  /** 消息进来时现算一次（不等定时器）：条数那一半的触发就靠这里 */
  function maybeReport() {
    if (closed || !settings.commander) return;
    const nowMs = timeOf();
    for (const name of PARTICIPANT_CHANNELS) {
      if (reportDue(name, nowMs)) enqueueReport(name);
    }
    scheduleReport();
  }

  function enqueueReport(name) {
    if (reporting.has(name)) return;
    reporting.add(name);
    reportChain = reportChain
      .then(() => runReport(name))
      .catch(() => {})
      .then(() => {
        reporting.delete(name);
        scheduleReport();
      });
  }

  /** 失败：计数一个都不动（下一个窗口重试的就是它们），只把下一次尝试推到下一个窗口 */
  function failWindow(name) {
    retryAt.set(name, timeOf() + settings.reportEveryMs);
    scheduleReport();
  }

  async function runReport(name) {
    const entry = channels[name];
    if (!entry || entry.msgCount <= 0) return;
    if (typeof promptSession !== 'function') return;
    // 先把这一批唤醒打完：同一个频道会话上不并发两条提示
    await chain;
    const from = entry.since > 0 ? entry.since : timeOf();
    const to = timeOf();
    const count = entry.msgCount;

    // (a) 问**这个频道自己的会话**要一个紧凑摘要
    let summary = '';
    try {
      summary = await summarizeChannel(name, { from, to, count });
    } catch {
      summary = '';
    }
    if (summary === '') {
      // 会话不肯答 / 出错 / 空回复：这一轮没有汇报，计数原样留着，下一个窗口再问一次
      logLine('[participant] summary-failed channel=' + name);
      failWindow(name);
      return;
    }

    // (b) 汇报打进指挥官会话
    try {
      await promptCommander(buildReportPrompt({ channel: name, from, to, count, summary }));
    } catch {
      logLine('[participant] report-failed channel=' + name);
      failWindow(name);
      return;
    }

    // (c) 只有真送到才动计数：扣掉已经汇报过的那些，窗口从 to 重新起算
    entry.msgCount = Math.max(0, entry.msgCount - count);
    entry.since = to;
    entry.summarizedAt = to;
    entry.summary = summary;
    entry.reports += 1;
    retryAt.delete(name);
    persistState();
    logLine('[participant] report channel=' + name + ' msgs=' + count + ' chars=' + charCount(summary));
  }

  /** 摘要：走注入的 askSummary（要读回回复）；没注入就退回 promptSession 并看它带不带 reply */
  async function summarizeChannel(name, { from, to, count }) {
    const ask = typeof askSummary === 'function' ? askSummary : promptSession;
    const entry = channels[name];
    const current = entry.sessionId;
    const out = await ask(current, buildSummaryPrompt({ channel: name, from, to, count }));
    adoptChannel(name, current, out, false);
    return clipText(asText(out?.reply ?? out?.summary ?? ''), REPORT_SUMMARY_MAX).trim();
  }

  /**
   * 指挥官会话：造一次（空 id → 让宿主新建）、用到底，**永不轮换**。
   * 失败就是失败（交给 runReport 记 report-failed），这一层不重打、不换会话。
   * 唯一的例外是宿主自己回退新建过（旧会话真没了）：那时新 id 就是它，记下来接着用。
   */
  async function promptCommander(prompt) {
    const current = asText(state.commander.sessionId);
    const out = await promptSession(current, prompt);
    const nextId = asText(out?.sessionId);
    if (nextId === '') {
      if (current === '') throw new Error('commander-session-missing');
      return;
    }
    if (nextId === current) return;
    if (current !== '') logLine('[participant] session-recreated');
    state.commander = {
      sessionId: nextId,
      createdAt: current === '' ? timeOf() : (positiveInt(state.commander.createdAt) || timeOf()),
    };
    persistState();
  }

  function buildSummaryPrompt({ channel, from, to, count }) {
    return [
      '【常驻参与者 · 汇报摘要】本机要把频道 ' + channel + ' 的这一段汇报给指挥官，先给一个紧凑摘要。',
      '窗口：' + isoOf(from) + ' → ' + isoOf(to) + '（' + count + ' 条消息）',
      '不超过 ' + REPORT_SUMMARY_MAX + ' 字：谁要什么、定了什么、还欠什么。只写摘要正文，不列文件、不复述原文、不反问。',
      '你这次不回或出错就没有汇报：本机什么都不改，等下一个窗口再问你一次。',
    ].join('\n');
  }

  /** 指挥官收到的汇报正文（频道 / 窗口 / 条数 / 摘要 / 两个参与者会话的短 id） */
  function buildReportPrompt({ channel, from, to, count, summary }) {
    const groupShort = shortSessionId(channels.group.sessionId) || '-';
    const dmShort = shortSessionId(channels.dm.sessionId) || '-';
    return [
      '【常驻参与者 · 汇报】频道 ' + channel + ' 的一个汇报窗口到了。',
      '频道: ' + channel,
      '窗口: ' + isoOf(from) + ' → ' + isoOf(to),
      '消息数: ' + count,
      '摘要: ' + summary,
      '本机参与者会话(短 id): group=' + groupShort + ' dm=' + dmShort,
      '要派活就用既有的 lan_session_ask {sessionId, prompt} 打回上面这两个短 id（4 位以上的唯一后缀也认）—— 这就是参与者汇报走的那一条通道，没有第二条。',
    ].join('\n');
  }

  // ---- 入口 ---------------------------------------------------------------

  function pushGroup(event) {
    if (!settings.group) return;
    const self = asText(selfId());
    const list = Array.isArray(event?.messages) ? event.messages : [];
    let added = 0;
    let highest = lastSeq;
    for (const message of list) {
      const seq = Math.floor(Number(message?.seq) || 0);
      if (seq <= 0 || seq <= lastSeq) continue;
      highest = Math.max(highest, seq);
      const author = asText(message?.from?.peerId);
      // 回声闸：本机作者的消息永远不叫醒本机
      if (self !== '' && author === self) continue;
      // 系统行闸：回执/提醒/通知不是人在说话
      if (isSystemLine(message)) continue;
      if (paused(author)) continue;
      noteAuthored(author, isParticipantAuthored(message));
      queue.push({
        seq,
        peerId: author,
        name: asText(message?.from?.name),
        text: asText(message?.text),
      });
      added += 1;
    }
    lastSeq = highest;
    if (added > 0) {
      channels.group.msgCount += added;
      persistState();
      schedule();
      maybeReport();
    }
  }

  function pushDm(event) {
    if (!settings.dm) return;
    const peerId = asText(event?.peerId);
    if (peerId === '') return;
    const entries = Array.isArray(event?.entries) ? event.entries : [];
    let added = 0;
    for (const entry of entries) {
      // 对端视角的 self = 对端写的那条（本机视角的 peer）
      if (asText(entry?.from) !== 'self') continue;
      const id = asText(entry?.id);
      if (id !== '' && seenDm.has(id)) continue;
      if (id !== '') {
        seenDm.add(id);
        if (seenDm.size > DM_SEEN_MAX) seenDm.delete(seenDm.values().next().value);
      }
      dms.push({ peerId, text: asText(entry?.text) });
      added += 1;
    }
    if (added === 0) return;
    channels.dm.msgCount += added;
    persistState();
    // 私聊不排队等窗口：立刻唤醒
    flushNow();
    maybeReport();
  }

  function pushVotes() {
    if (!settings.group) return;
    let plane = null;
    try {
      plane = proposalPlane();
    } catch {
      return;
    }
    if (!plane || typeof plane !== 'object') return;
    const events = decisionEvents(plane, planeState);
    planeState = snapshotPlane(plane);
    const picked = pickDecision(events);
    if (!picked) return;
    decision = picked;
    // 决策事件绕过批次窗：立刻唤醒
    flushNow();
  }

  return {
    file,
    settings,
    /** 常驻身份就位（listen 之后调）：补一次汇报定时器；身份缺了等第一次唤醒/摘要再建 */
    arm() {
      closed = false;
      scheduleReport();
      return {
        sessionId: channels.group.sessionId,
        group: settings.group,
        dm: settings.dm,
        commander: settings.commander,
        batchMs: settings.batchMs,
        reportEveryMs: settings.reportEveryMs,
        reportEveryMessages: settings.reportEveryMessages,
      };
    },
    push(event) {
      if (closed || !event || typeof event !== 'object') return;
      const kind = asText(event.kind);
      if (kind === 'group') pushGroup(event);
      else if (kind === 'dm') pushDm(event);
      else if (kind === 'vote') pushVotes();
    },
    /** 测试/排障：直接走一次落点（不影响批量窗语义） */
    flush: flushNow,
    /** 指挥官会话 id（空串 = 还没建过）：面板/排障只读这一格 */
    commanderSession() {
      return asText(state.commander.sessionId);
    },
    /**
     * 记下指挥官会话的新 id（造一次、用到底）。宿主自己回退新建过（id 变了）视为会话没了，
     * 记一行 session-recreated；同一个 id 反复上报是 no-op。
     */
    adoptCommander(nextId) {
      const next = asText(nextId);
      if (next === '') return '';
      const previous = asText(state.commander.sessionId);
      if (previous === next) return next;
      state.commander = {
        sessionId: next,
        createdAt: positiveInt(state.commander.createdAt) || timeOf(),
      };
      persistState();
      if (previous !== '') logLine('[participant] session-recreated');
      return next;
    },
    close() {
      closed = true;
      if (timer !== null) {
        clearTimeoutFn(timer);
        timer = null;
      }
      if (reportTimer !== null) {
        clearTimeoutFn(reportTimer);
        reportTimer = null;
      }
      queue = [];
      dms = [];
      decision = null;
      streak.clear();
      reporting.clear();
      retryAt.clear();
    },
    /** 排障可见：还挂着几个等待项、定时器起没起、三个常驻身份是谁 */
    state() {
      const channel = (entry) => ({
        sessionId: entry.sessionId,
        msgCount: entry.msgCount,
        summarizedAt: entry.summarizedAt,
        reports: entry.reports,
      });
      return {
        queued: queue.length,
        dms: dms.length,
        decision: decision === null ? null : { ...decision },
        sessionId: channels.group.sessionId,
        pending: timer !== null,
        reportPending: reportTimer !== null,
        closed,
        channels: { group: channel(channels.group), dm: channel(channels.dm) },
        commander: { sessionId: state.commander.sessionId, createdAt: state.commander.createdAt },
      };
    },
  };
}

/**
 * 把常驻参与者接到宿主上（接线就住在本文件里，插件入口只装一行）。
 *
 * 注入面：
 *   runner  {ask(prompt[,{sessionId}]), poll(sessionId)}  —— 唤醒与汇报摘要都用它，不另开通道
 *   config  插件 config（读 config.participant）        stateDir/expandHome  身份文件放哪
 *   selfId()/proposalPlane()/log()                      回声闸 / 表决平面 / 日志
 * 返回 { participant, push, arm, close, state, file, settings }：插件把这些装上即可。
 */
export function createParticipantWiring({
  runner = null,
  config = {},
  stateDir = '',
  expandHome = (value) => String(value ?? ''),
  selfId = () => '',
  proposalPlane = () => null,
  log = null,
  now = Date.now,
  setTimeoutFn = (fn, ms) => setTimeout(fn, ms),
  clearTimeoutFn = (handle) => clearTimeout(handle),
  summaryWaitMs = SUMMARY_WAIT_MS,
  summaryPollMs = SUMMARY_POLL_MS,
  // 面板指挥官输入框等回复的预算（与汇报同一档；测试把它压到几毫秒）
  commanderWaitMs = SUMMARY_WAIT_MS,
} = {}) {
  const askable = runner && typeof runner.ask === 'function' ? runner : null;
  const pollable = askable !== null && typeof askable.poll === 'function';
  const raw = typeof stateDir === 'string' ? stateDir.trim() : '';
  const dir = raw !== '' ? expandHome(raw) : path.join(os.homedir(), '.dsh', 'lan-peers');

  // 唤醒：空 sessionId = 新建；给了 id 就在那个常驻会话上接着打（宿主自己回退新建时如实回报）
  const promptSession = askable === null ? null : async (sessionId, prompt) => {
    const wanted = typeof sessionId === 'string' ? sessionId.trim() : '';
    if (wanted === '') {
      const created = await askable.ask(prompt);
      return { sessionId: String(created ?? ''), reused: false };
    }
    const out = await askable.ask(prompt, { sessionId: wanted });
    const next = String(out?.sessionId ?? '') || wanted;
    return { sessionId: next, reused: next === wanted && out?.reused !== false };
  };

  /**
   * 本文件**唯一**的轮询：问完之后等那个会话的最后一条助手消息（同一个 ask/poll 对）。
   * 汇报摘要与面板的指挥官输入框都走它 —— 没有第二条 poller，也没有第二套超时。
   * 返回值是稳定状态字符串，绝不把异常抛给调用方（调用方各自决定怎么记）。
   */
  const waitForReply = pollable !== true ? null : async (sessionId, waitMs) => {
    const deadline = Date.now() + Math.max(1000, Number(waitMs) || 0);
    for (;;) {
      let out = null;
      try {
        out = await askable.poll(sessionId);
      } catch {
        return { status: 'error', reply: '' };
      }
      const status = String(out?.status ?? '');
      if (status === 'done') return { status: 'done', reply: String(out?.reply ?? '') };
      // error / 超时 = 这一轮拿不到回复（participant 记 summary-failed，面板显示稳定错误串）
      if (status === 'error') return { status: 'error', reply: '' };
      if (Date.now() >= deadline) return { status: 'timeout', reply: '' };
      await new Promise((resolve) => setTimeout(resolve, Math.max(1, Number(summaryPollMs) || 0)));
    }
  };

  // 汇报摘要：问一次 + 读回最后一条助手消息（同一个 ask/poll 对，没有第二条通道）
  const askSummary = waitForReply === null ? null : async (sessionId, prompt) => {
    const sent = await promptSession(sessionId, prompt);
    const next = String(sent?.sessionId ?? '');
    let reply = '';
    if (next !== '') {
      const waited = await waitForReply(next, summaryWaitMs);
      if (waited.status === 'done') reply = waited.reply;
    }
    return { sessionId: next, reused: sent?.reused !== false, reply };
  };

  const participant = createParticipant({
    stateDir: dir,
    selfId,
    config: config && typeof config === 'object' ? config.participant : {},
    promptSession,
    askSummary,
    proposalPlane,
    log,
    now,
    setTimeoutFn,
    clearTimeoutFn,
  });

  /** 面板指挥官输入框的正文上限：超了就是 bad-text（截断会悄悄改掉人说的话） */
  const COMMANDER_SAY_MAX = 4000;

  /**
   * 面板上的「指挥官」输入框：等价于在本机 commander 会话里打一句话。
   * 通道与汇报**完全同一条**（promptSession 发 + waitForReply 收），所以没有第二条 poller；
   * 超时档位也与汇报同一档（summaryWaitMs / commanderWaitMs）。
   * 失败一律给稳定字符串：bad-text / no-session / send-failed / error / timeout。
   */
  const sayToCommander = async (text) => {
    const body = typeof text === 'string' ? text.trim() : '';
    if (body === '' || Array.from(body).length > COMMANDER_SAY_MAX) return { ok: false, error: 'bad-text' };
    if (promptSession === null || waitForReply === null) return { ok: false, error: 'no-session' };
    const current = participant.commanderSession();
    let sent = null;
    try {
      sent = await promptSession(current, body);
    } catch {
      return { ok: false, error: 'send-failed' };
    }
    const next = asText(sent?.sessionId) || current;
    if (next === '') return { ok: false, error: 'no-session' };
    participant.adoptCommander(next);
    const waited = await waitForReply(next, commanderWaitMs);
    if (waited.status !== 'done') return { ok: false, error: waited.status };
    return { ok: true, reply: waited.reply, sessionIdShort: shortSessionId(next) };
  };

  return {
    participant,
    sayToCommander,
    file: participant.file,
    settings: participant.settings,
    push: (event) => participant.push(event),
    arm: () => participant.arm(),
    close: () => participant.close(),
    state: () => participant.state(),
  };
}
