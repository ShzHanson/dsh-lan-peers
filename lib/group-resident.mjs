/**
 * dsh-lan-peers · 0.10.0-α slice 3a 群内常驻会话（@ 点名必答）
 * ==========================================================
 * 用户决定：**每台成员机每个群一个常驻会话**，群里的问答都在这个会话里接着聊。
 * 本模块只做四件互不耦合的事，全部可用假时钟/假 runner 测完：
 *
 *   1. ResidentSessionStore   —— <stateDir>/group-resident.json（0600 原子写）的读/写
 *   2. resolveResidentUse()   —— 复用还是新建的**纯决定**（陈旧记录 → 新建）
 *   3. addressedToNode()      —— 「这条消息是不是 @ 我问了」的纯判定
 *   4. createAnswerQueue()    —— 每群一条串行链（单飞：排队不并发）
 *
 * 会话层不是本文件发明的：真正的复用/新建仍走 lib/session-reuse.mjs 的既有机器，
 * 这里只负责「记住这个群用哪个会话 id」以及「记录里的 id 已经不在了怎么办」。
 *
 * 铁律：
 *   - 陈旧记录不猜测：ask 回来 reused=false / id 变了，就当「新建了一个常驻会话」，不报错；
 *   - 判定不做语义猜测：只认 @ + 名字/peerId，代码块里和 `/task` 命令里的 @ 一律不算；
 *   - 日志与调用方只拿短 id，正文永不进日志（截断后的引用只进群消息，不进日志）。
 */
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { parseGroupTask } from './group-task.mjs';

/** 常驻会话状态文件（与 group-role.json / group-replica.json 同一目录、同一 0600 口径） */
export const RESIDENT_FILE = 'group-resident.json';

/** 常驻会话的空闲上限：一天没再答过话就把这条记录扔掉（下次问 → 新会话） */
export const RESIDENT_TTL_MS = 86_400_000;

/** 引用摘要的硬上限（Unicode code point 计：中文不会被拆半个字） */
export const RESIDENT_QUOTE_EXCERPT_MAX = 80;

/** 塞进提问里的原文上限（再长的问题也不该把提示词撑爆） */
export const RESIDENT_PROMPT_TEXT_MAX = 1200;

/**
 * 群内提问的固定前言（中文，与 lib/runner-dsh.mjs 的答复契约同一口径）。
 * 它不是界面文案 —— 它是**发给模型的提示词**，所以不进 i18n 词表。
 */
export const RESIDENT_PROMPT_PREAMBLE = [
  '【群内提问 · 致本机】群里有人 @ 了你，请直接、简洁地回答这个问题。',
  '你最后一条消息的正文会**原样**发到群里作为答复，所以不要复述这条说明，也不要写元信息。',
].join('\n');

const AT_VARIANTS = /[\uFF20\uFE6B]/g;
const FULLWIDTH_COLON = /\uFF1A/g;

const asText = (value) => (typeof value === 'string' ? value : '');

/** 群 id 归一化：只去首尾空白（id 是 uuid，绝不改大小写） */
export function normalizeGroupId(value) {
  return asText(value).trim();
}

// ---------------------------------------------------------------------------
// 1. 常驻会话落盘
// ---------------------------------------------------------------------------

/** 原子写 0600：与 host/server.mjs 的 writeJson0600 同口径（tmp → rename → chmod） */
function writeJson0600(file, value) {
  const dir = path.dirname(file);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  try {
    fs.chmodSync(dir, 0o700);
  } catch {
    /* 目录权限尽力而为，不阻塞主流程 */
  }
  const tmp = `${file}.tmp-${process.pid}-${randomBytes(4).toString('hex')}`;
  fs.writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  try {
    fs.chmodSync(tmp, 0o600);
  } catch {
    /* ignore */
  }
  fs.renameSync(tmp, file);
  try {
    fs.chmodSync(file, 0o600);
  } catch {
    /* ignore */
  }
}

function readJsonFile(file) {
  let raw;
  try {
    raw = fs.readFileSync(file, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw err;
  }
  try {
    return JSON.parse(raw);
  } catch {
    // 坏文件不该让一台成员机再也答不上话：当作「没有任何记录」，下次落盘会覆盖它
    return null;
  }
}

/**
 * 每群一条记录：{ groupId, sessionId, lastUsedAt }。
 * 形状冻结（这就是 R1 里说的「exact fields」）：
 *   version    —— 文件格式版本，当前恒为 1
 *   groups     —— groupId → { sessionId, lastUsedAt }（lastUsedAt 是毫秒时间戳）
 */
export class ResidentSessionStore {
  #stateDir;

  #now;

  #data = null;

  constructor({ stateDir, now = Date.now }) {
    this.#stateDir = stateDir;
    this.#now = typeof now === 'function' ? now : Date.now;
  }

  get filePath() {
    return path.join(this.#stateDir, RESIDENT_FILE);
  }

  #normalize(raw) {
    const data = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
    const groups = data.groups && typeof data.groups === 'object' && !Array.isArray(data.groups)
      ? data.groups
      : {};
    const out = {};
    for (const [key, value] of Object.entries(groups)) {
      const groupId = normalizeGroupId(key);
      if (groupId === '' || !value || typeof value !== 'object') continue;
      const sessionId = asText(value.sessionId).trim();
      if (sessionId === '') continue;
      const lastUsedAt = Number(value.lastUsedAt);
      out[groupId] = {
        sessionId,
        lastUsedAt: Number.isFinite(lastUsedAt) && lastUsedAt > 0 ? Math.floor(lastUsedAt) : 0,
      };
    }
    return { version: 1, groups: out };
  }

  #load() {
    if (this.#data) return this.#data;
    this.#data = this.#normalize(readJsonFile(this.filePath));
    return this.#data;
  }

  #save(data) {
    this.#data = this.#normalize(data);
    writeJson0600(this.filePath, this.#data);
    return this.#data;
  }

  /** 读一个群的记录；没有就 null（null = 「还没建过常驻会话」） */
  read(groupId) {
    const key = normalizeGroupId(groupId);
    if (key === '') return null;
    const entry = this.#load().groups[key];
    return entry ? { groupId: key, sessionId: entry.sessionId, lastUsedAt: entry.lastUsedAt } : null;
  }

  /** 落一条（覆盖语义）：sessionId 为空则删除该群的记录，返回新记录或 null */
  save({ groupId, sessionId = '', at = null } = {}) {
    const key = normalizeGroupId(groupId);
    if (key === '') return null;
    const data = this.#load();
    const id = asText(sessionId).trim();
    if (id === '') {
      delete data.groups[key];
      this.#save(data);
      return null;
    }
    const stamp = Number(at);
    const record = { sessionId: id, lastUsedAt: Number.isFinite(stamp) && stamp > 0 ? Math.floor(stamp) : this.#now() };
    data.groups[key] = record;
    this.#save(data);
    return { groupId: key, ...record };
  }

  /**
   * 空闲驱逐（TTL）：`lastUsedAt` 早于 now-ttlMs 的记录删掉，返回被删掉的群 id。
   *
   * 两条安全约束：
   *   1. `busy` 里的群**一律不动** —— 答案还在飞的时候把记录删掉，会让这次答复
   *      之后的复用判决拿到一条不存在的记录（会话对不上号）；
   *   2. 驱逐本身是**无害**的：记录没了 = 「这个群还没建过常驻会话」，下一次提问
   *      走 reason:'no-record' 新建一条，不需要回滚、不需要迁移、不会报错。
   */
  prune({ ttlMs = RESIDENT_TTL_MS, busy = [] } = {}) {
    const ttl = Math.max(1, Math.floor(Number(ttlMs) || RESIDENT_TTL_MS));
    const busyIds = new Set(Array.from(busy ?? []).map((value) => normalizeGroupId(value)));
    const data = this.#load();
    const cutoff = this.#now() - ttl;
    const removed = [];
    for (const [groupId, entry] of Object.entries(data.groups)) {
      if (busyIds.has(groupId)) continue;
      const lastUsed = Number(entry?.lastUsedAt) || 0;
      if (lastUsed > 0 && lastUsed >= cutoff) continue;
      delete data.groups[groupId];
      removed.push(groupId);
    }
    if (removed.length > 0) this.#save(data);
    return removed;
  }

  /** 整表视图（排障/测试用；只有 id 与时间，没有任何正文） */
  state() {    const data = this.#load();
    return {
      file: this.filePath,
      groups: Object.entries(data.groups).map(([groupId, entry]) => ({ groupId, ...entry })),
    };
  }
}

// ---------------------------------------------------------------------------
// 2. 复用还是新建（纯决定）
// ---------------------------------------------------------------------------

/**
 * 把「记录」与「runner.ask 的返回」折成一个结论。
 *
 *   asked = { sessionId, reused } —— runner 的两种合法形状在这里已经收敛成一种
 *     （旧形状裸字符串 → reused 未知，按「给了 id 就是续上」处理由调用方决定；
 *      这里只看 sessionId 与 reused 两个字段）
 *
 * 返回 { sessionId, reuse, stale, reason }：
 *   reason: 'no-record'        —— 这个群还没有常驻会话 → 新建（reuse:false, stale:false）
 *   reason: 'reused'           —— 记录在、runner 确认续上 → 复用
 *   reason: 'stale-recreated'  —— 记录在但**已经用不了**（reused=false 或 id 变了）→ 新建
 *   reason: 'no-session'       —— runner 没给出 id（错误路径，调用方据此放弃）
 *
 * 陈旧判据只有两条，都不猜原因：runner 明确说 reused:false，或给回来的 id 不是原来那个。
 */
export function resolveResidentUse({ record = null, asked = null } = {}) {
  const sessionId = asText(asked?.sessionId).trim();
  if (sessionId === '') return { sessionId: '', reuse: false, stale: false, reason: 'no-session' };
  if (!record || asText(record.sessionId).trim() === '') {
    return { sessionId, reuse: false, stale: false, reason: 'no-record' };
  }
  const recorded = asText(record.sessionId).trim();
  const reused = asked?.reused === true && sessionId === recorded;
  if (reused) return { sessionId, reuse: true, stale: false, reason: 'reused' };
  return { sessionId, reuse: false, stale: true, reason: 'stale-recreated' };
}

// ---------------------------------------------------------------------------
// 3. 「这条消息是不是 @ 我」
// ---------------------------------------------------------------------------

/** 全角 ＠/﹫ → @，全角 ：→ :（只是把同一个符号的两种敲法归一，不改任何语义） */
export function normalizeMentionText(text) {
  return asText(text).replace(AT_VARIANTS, '@').replace(FULLWIDTH_COLON, ':');
}

/** 抹掉代码块/行内代码：里面的 @ 是**示例**，不是点名 */
export function stripCodeSpans(text) {
  return asText(text)
    .replace(/```[\s\S]*?```/g, ' ')
    .replace(/`[^`\n]*`/g, ' ');
}

const escapeRegExp = (value) => String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * 本机的几个可被 @ 的名字：显示名、peerId、以及面板里同名成员用的 name-短id。
 * 空串一律不进表（否则 `@` 后面接空白就成了点名）。
 */
export function mentionAliases({ name = '', peerId = '', shortId = '' } = {}) {
  const base = asText(name).trim();
  const peer = asText(peerId).trim();
  const short = asText(shortId).trim() || peer.slice(0, 8);
  const list = [];
  for (const item of [base, peer, short]) {
    if (item !== '' && !list.includes(item)) list.push(item);
  }
  if (base !== '' && short !== '') {
    const decorated = `${base}-${short}`;
    if (!list.includes(decorated)) list.push(decorated);
  }
  return list;
}

/**
 * 名字匹配的**唯一一份**边界规则：大小写不敏感，`@名字` 后面不能紧跟
 * 字母/数字/下划线/连字符（`@a` 不该命中 `@ab`）。
 * 「这条消息 @ 了谁」与「这条消息 @ 了我吗」都走这一份，边界语义不会分叉。
 */
function mentionPattern(alias) {
  const name = asText(alias).trim();
  if (name === '') return null;
  return new RegExp(`@${escapeRegExp(name)}(?![A-Za-z0-9_-])`, 'iu');
}

/** `@名字` 后面不能紧跟字母/数字/下划线/连字符（`@a` 不该命中 `@ab`） */
export function mentionsNode(text, aliases = []) {
  const plain = normalizeMentionText(stripCodeSpans(text));
  const list = Array.isArray(aliases) ? aliases : [];
  if (plain.trim() === '') return false;
  for (const alias of list) {
    const pattern = mentionPattern(alias);
    if (pattern && pattern.test(plain)) return true;
  }
  return false;
}

/**
 * 这条消息 @ 了**哪些已知名字**（去重、小写、按别名表顺序）。
 * 多 @ 不需要「第一命中」：每个节点各自用自己那份别名表问一次「有我吗」，
 * 因此一条消息 @ 了 N 台机器就会有 N 台各自命中一次（各自一条答案）。
 */
export function resolvedMentions(text, aliases = []) {
  const plain = normalizeMentionText(stripCodeSpans(text));
  const list = Array.isArray(aliases) ? aliases : [];
  if (plain.trim() === '') return [];
  const hits = [];
  for (const alias of list) {
    const pattern = mentionPattern(alias);
    if (!pattern || !pattern.test(plain)) continue;
    const key = asText(alias).trim().toLowerCase();
    if (key !== '' && !hits.includes(key)) hits.push(key);
  }
  return hits;
}

/**
 * 群里**所有**可被 @ 的名字：成员表（name / peerId / name-短id）+ 本机自己。
 * 用途只有一个：判断「这条消息到底点名了谁」—— 点的是未知名字 = 没点名。
 */
export function memberMentionAliases({ members = {}, selfPeerId = '', selfName = '' } = {}) {
  const list = [];
  const push = (value) => {
    const item = asText(value).trim();
    if (item !== '' && !list.includes(item)) list.push(item);
  };
  const table = members && typeof members === 'object' && !Array.isArray(members)
    ? Object.entries(members)
    : [];
  for (const [peerId, member] of table) {
    for (const alias of mentionAliases({ name: member?.name ?? '', peerId })) push(alias);
  }
  for (const alias of mentionAliases({ name: selfName, peerId: selfPeerId })) push(alias);
  return list;
}

/** 带合法 `meta.quote` 的消息是**答案**，不是问题：绝不「回答一个答案」（否则两个节点会无限乒乓） */
export function isAnswerMessage(meta) {
  if (!meta || typeof meta !== 'object' || Array.isArray(meta)) return false;
  const quote = meta.quote;
  if (!quote || typeof quote !== 'object') return false;
  const seq = Number(quote.seq);
  return Number.isFinite(seq) && seq > 0;
}

/**
 * 「不答」的稳定原因码（日志 token，也是 answerDecision 的判定优先级顺序）。
 *
 * 存在的理由：0.10.0 的否决是**静默**的（`if (intent === '') continue`），
 * 于是日志里「从没做过决定」与「决定不答」长得一模一样 —— 真机上 hub 一次都不答题时
 * 根本分不清是哪一道闸门挡的。现在每一道否决都必须自报家门。
 */
export const ANSWER_SKIP_REASONS = Object.freeze([
  'not-chat',
  'self-authored',
  'already-answered',
  'task',
  'not-a-member-author',
  'not-mention',
]);

/**
 * 判定链的**唯一一份实现**：这条消息要不要答、以什么身份答、不答是因为哪一条。
 *
 * 返回 { intent: '' | 'directed' | 'undirected', reason: '' | ANSWER_SKIP_REASONS 之一 }。
 * 顺序即优先级（改动顺序等于改动语义，别动）：
 *   not-chat（progress/result 是回执）→ self-authored（自己发的不答自己）→
 *   already-answered（带 quote 的是答案，不是问题）→ 空白 → task（/task 是派单）→
 *   @ 到我 → directed（点名答，不受作者身份影响）→ not-a-member-author（抢答只对成员）→
 *   not-mention（@ 里点到的是别人）→ undirected（没人被点名，谁都可以答）
 */
export function answerDecision({
  text = '',
  kind = 'chat',
  fromPeerId = '',
  selfPeerId = '',
  aliases = [],
  knownMentions = [],
  meta = null,
  memberAuthor = true,
} = {}) {
  if (String(kind || 'chat') !== 'chat') return { intent: '', reason: 'not-chat' };
  const from = asText(fromPeerId);
  const self = asText(selfPeerId);
  if (from !== '' && self !== '' && from === self) return { intent: '', reason: 'self-authored' };
  if (isAnswerMessage(meta)) return { intent: '', reason: 'already-answered' };
  const raw = asText(text);
  if (raw.trim() === '') return { intent: '', reason: 'not-mention' };
  if (parseGroupTask(raw).isTask) return { intent: '', reason: 'task' };
  if (mentionsNode(raw, aliases)) return { intent: 'directed', reason: '' };
  if (!memberAuthor) return { intent: '', reason: 'not-a-member-author' };
  if (resolvedMentions(raw, knownMentions).length > 0) return { intent: '', reason: 'not-mention' };
  return { intent: 'undirected', reason: '' };
}

/**
 * 群消息 → 要不要答（= answerDecision 的 'directed' 分支，保留给既有调用方）。
 * 三条否决：不是 kind:'chat'、是我自己发的、是 `/task` 命令（另加「带 quote 的是答案」）。
 * 通过之后才看 @。
 */
export function addressedToNode({
  text = '',
  kind = 'chat',
  fromPeerId = '',
  selfPeerId = '',
  aliases = [],
  meta = null,
} = {}) {
  return answerDecision({ text, kind, fromPeerId, selfPeerId, aliases, meta }).intent === 'directed';
}

/**
 * 「这条消息没点名，谁都可以答」的**完整资格判定**（slice 3b，= answerDecision 的 'undirected' 分支）。
 * 通过 = 本机可以答；不通过 = 不该答。四道否决 + 一道点名判定：
 *   kind 必须 chat、不是我发的、不是 `/task`、不是「答案」（带 quote）、
 *   并且 @ 里**没有一个**能落到群里的已知成员（点陌生名字 = 等于没点名）。
 * aliases 传的是**本机**的别名表：@ 到我自己就不是抢答，是点名答。
 */
export function undirectedQuestion({
  text = '',
  kind = 'chat',
  fromPeerId = '',
  selfPeerId = '',
  knownMentions = [],
  aliases = [],
  meta = null,
  memberAuthor = true,
} = {}) {
  return answerDecision({
    text, kind, fromPeerId, selfPeerId, aliases, knownMentions, meta, memberAuthor,
  }).intent === 'undirected';
}

/**
 * 已经有人答过这条了吗？（首答胜的**唯一**判据）
 *
 * 只认一个证据：本地已知消息里存在 `kind:'chat'` 且 `meta.quote.seq === seq` 的那条。
 * 不猜「谁该答」、不看时间戳、不比较正文 —— 只要有人答了，后来者就闭嘴。
 */
export function alreadyAnsweredSeq(messages, seq) {
  const target = Math.floor(Number(seq) || 0);
  if (target <= 0) return false;
  const list = Array.isArray(messages) ? messages : [];
  for (const message of list) {
    if (String(message?.kind ?? '') !== 'chat') continue;
    if (!isAnswerMessage(message?.meta)) continue;
    if (Math.floor(Number(message.meta.quote.seq)) === target) return true;
  }
  return false;
}

/**
 * 已经排过答案的 「群:seq」 集合（有界 FIFO）。
 *
 * 存在的理由：同一条消息会从多条缝进来（hub 的 post 缝 + 复制缝 + commit 广播缝），
 * 每一条缝都该触发，但一条消息只该答一次 —— 去重键就是 seq 本身。
 */
export function createAnswerClaimSet({ capacity = 1024 } = {}) {
  const cap = Math.max(1, Math.floor(Number(capacity) || 1024));
  const seen = new Set();
  return {
    /** 第一次见到这个 key 返回 true（= 由本机排这次答案） */
    claim(key) {
      const id = String(key ?? '');
      if (id === '') return false;
      if (seen.has(id)) return false;
      seen.add(id);
      while (seen.size > cap) {
        const oldest = seen.values().next();
        if (oldest.done) break;
        seen.delete(oldest.value);
      }
      return true;
    },
    /**
     * 还回一次认领（失败路径用）：`false` = 本来就没占着。
     *
     * 认领是「预留」，预留就必须有归还 —— 一次 runner 失败不该让这条消息在本机永久哑火。
     */
    release(key) {
      const id = String(key ?? '');
      if (id === '') return false;
      return seen.delete(id);
    },
    has(key) {
      return seen.has(String(key ?? ''));
    },
    size() {
      return seen.size;
    },
  };
}

/** 无 @ 时的起跑抖动上限：实际延迟落在 [0, 299] 毫秒 */
export const RESIDENT_JITTER_MS = 300;

/**
 * 由 peerId 派生的**确定性**抖动（FNV-1a → [0, span)）：同一台机器每次都一样，
 * 两台不同机器几乎不会同时起跑。它只错开**起跑**，不决定谁赢 —— 谁赢由
 * 「已经有人答过」的复查决定。
 */
export function answerJitterMs(peerId, { span = RESIDENT_JITTER_MS } = {}) {
  const cap = Math.max(1, Math.floor(Number(span) || RESIDENT_JITTER_MS));
  const id = String(peerId ?? '');
  let hash = 0x811c9dc5;
  for (let index = 0; index < id.length; index += 1) {
    hash ^= id.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash % cap;
}

// ---------------------------------------------------------------------------
// 4. 单飞队列（每群一条串行链）
// ---------------------------------------------------------------------------

/**
 * 最小的正确机制：**每群一条 Promise 链**。
 * 第二条 @ 消息进来时排在第一条后面（`chain.then(run)`），因此同一时刻只有一个
 * runner 调用在飞，且顺序 = 到达顺序；链尾清空后删除 key，不留下无界 map。
 */
export function createAnswerQueue() {
  const chains = new Map();
  const depth = new Map();
  return {
    /** 排队执行 job；返回这次 job 自己的 promise（成功/失败都原样交给调用方） */
    enqueue(key, job) {
      const name = String(key ?? '');
      const prev = chains.get(name) ?? Promise.resolve();
      const run = prev.then(() => job(), () => job());
      const tail = run.then(() => {}, () => {});
      chains.set(name, tail);
      depth.set(name, (depth.get(name) ?? 0) + 1);
      const done = run.finally(() => {
        const left = Math.max(0, (depth.get(name) ?? 1) - 1);
        if (left === 0) {
          depth.delete(name);
          if (chains.get(name) === tail) chains.delete(name);
        } else {
          depth.set(name, left);
        }
      });
      return done;
    },
    /** 这个群还排着几条（含正在跑的那条） */
    pending(key) {
      return depth.get(String(key ?? '')) ?? 0;
    },
  };
}

// ---------------------------------------------------------------------------
// 5. 提问与引用摘要
// ---------------------------------------------------------------------------

/** 一行化的引用摘要：去换行、压空白、≤max 个 code point（截断时补 …） */
export function quoteExcerpt(text, max = RESIDENT_QUOTE_EXCERPT_MAX) {
  const flat = asText(text).replace(/\s+/g, ' ').trim();
  const cap = Math.max(1, Math.floor(Number(max) || RESIDENT_QUOTE_EXCERPT_MAX));
  const chars = Array.from(flat);
  if (chars.length <= cap) return chars.join('');
  return `${chars.slice(0, cap - 1).join('')}…`;
}

/** meta.quote 的唯一规范化入口（server 与 group-client 共用这一份） */
export function sanitizeQuoteMeta(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const seq = Number(value.seq);
  if (!Number.isFinite(seq) || seq <= 0) return null;
  return {
    seq: Math.floor(seq),
    from: asText(value.from).slice(0, 64),
    excerpt: quoteExcerpt(value.excerpt),
  };
}

/**
 * 提问提示词：固定前言 + 提问者 + 原文（原文按 RESIDENT_PROMPT_TEXT_MAX 截断）。
 * 前言在**前面**、原文在**后面**：离生成最近的是被回答的那句话本身。
 */
export function buildResidentPrompt({ senderName = '', text = '', maxChars = RESIDENT_PROMPT_TEXT_MAX } = {}) {
  const cap = Math.max(1, Math.floor(Number(maxChars) || RESIDENT_PROMPT_TEXT_MAX));
  const who = Array.from(asText(senderName).trim()).slice(0, 64).join('') || '?';
  const body = Array.from(asText(text).trim()).slice(0, cap).join('');
  return [
    RESIDENT_PROMPT_PREAMBLE,
    `提问者：${who}`,
    '原始消息：',
    body,
  ].join('\n');
}
