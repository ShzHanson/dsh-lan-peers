/**
 * dsh-lan-peers · 0.12.8-alpha（slice H）群摘要：hub **一次**汇总，成员只读摘要
 * ======================================================================
 *
 * 用户决议（四条，已定稿）：
 *   1. 载体 = **群平面**（与 groupFiles 同一个形状：hub 权威、rev 门控）。
 *      摘要**不是**群消息、**不占** seq —— 加一个群消息 kind 等于「要么全网升级、
 *      要么谁都收不到」，平面是搭同一次 pull 回来的，老节点收到不认识的字段只是忽略。
 *   2. 触发（hub 侧）：新消息满 40 条**或**每 10 分钟，先到先算。
 *   3. 成员**只消费摘要**；原文照旧走既有工具（本切片不把原文喂给成员会话）。
 *   4. hub 侧还有一个全局指挥官会话（做汇总的那一个）；每台节点自己的本地指挥官是别的切片。
 *
 * 为什么成本从 N 降到 1：今天每个成员的参与者会话都在读**原始**群消息（一批 N 次模型调用）；
 * 现在只有 hub 的那一个会话读原文，其余成员读**一份**已经压缩好的摘要。
 *
 * 落盘（都在 <stateDir> 下，原子 0600、tmp→rename）：
 *
 *   group-digests.json        { version:1, digests:[{digestId,fromSeq,toSeq,at,source,text}] }
 *                             append-only，只留最新 DIGEST_KEEP(20) 条（丢更旧的）
 *   group-digest-session.json { sessionId }   摘要会话的身份（造一次、用到底，与参与者同一套策略）
 *
 * 铁律：
 *   · 摘要正文有界（≤1500 code point）且**必须**过 sanitizeDigestText()：控制字符一律抹掉
 *     （群消息正文来自别人，把它原样打进终端/日志/提示是不设防的注入面）；
 *   · 摘要会话**只**看群消息正文：批次里只有 seq / 名字 / 正文，没有 token、没有文件内容、
 *     没有任何对端机密；
 *   · **fallback 是强制的**：会话造不出来 / 提示失败 / 超时 → 写一份确定性摘要
 *     （source:'fallback'，条数表头 + 原文开头若干字，零模型调用），平面永不停摆；
 *   · 平面里的 rev 由**最新一条摘要的 toSeq** 推出（群的 seq 本身就是单调钟）：
 *     重启之后 rev 不会倒退，否则成员会永远忽略之后的摘要。
 */
import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';

export const GROUP_DIGESTS_FILE = 'group-digests.json';
export const DIGEST_SESSION_FILE = 'group-digest-session.json';

/** 盘上最多留多少条（append-only，只丢更旧的） */
export const DIGEST_KEEP = 20;
/** 平面里最多下发几条（新的在前）：成员只需要「最近发生了什么」 */
export const DIGEST_PLANE_LIMIT = 5;
/** 摘要正文上限（code point 计；超了截断并加省略号） */
export const DIGEST_TEXT_MAX = 1500;
/** 提示里每行原文的片段上限（一条群消息不该把整个提示撑满） */
export const DIGEST_LINE_MAX = 300;
/** 触发：新消息满 40 条 */
export const DIGEST_TRIGGER_MESSAGES = 40;
/** 触发：每 10 分钟 */
export const DIGEST_TRIGGER_MS = 10 * 60 * 1000;
/** fallback 摘要里摘多少字原文 */
export const DIGEST_FALLBACK_CHARS = 800;
/** 摘要会话单次回复的超时（超时就 fallback，绝不把平面挂在那儿） */
export const DIGEST_PROMPT_TIMEOUT_MS = 60_000;
export const DIGEST_SOURCES = Object.freeze(['agent', 'fallback']);

// 控制字符：C0（除 \n，\t 也一并折成空格）+ DEL + C1。正文里没有一个是正当的。
const CONTROL_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g;

const asText = (value) => (typeof value === 'string' ? value : '');

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = file + '.tmp-' + process.pid + '-' + randomUUID().slice(0, 8);
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmp, file);
}

const positiveInt = (value, fallback) => {
  const number = Math.floor(Number(value));
  return Number.isFinite(number) && number > 0 ? number : fallback;
};

/** 失败原因压成一行 ≤40 字（日志口径：永远不落正文） */
function shortReason(error, max = 40) {
  const raw = asText(error?.code) || asText(error?.message) || String(error ?? 'unknown');
  return raw.replace(/\s+/g, '-').slice(0, max) || 'unknown';
}

/** 一行原文：折空白、按 code point 截断（不切半个汉字） */
export function clipLine(value, max = DIGEST_LINE_MAX) {
  const chars = Array.from(asText(value).replace(/\s+/g, ' ').trim());
  if (chars.length <= max) return chars.join('');
  return chars.slice(0, Math.max(1, max - 1)).join('') + '…';
}

/**
 * 摘要正文的唯一清洗 + 截断口。控制字符抹成空格，行内首尾空白去掉，
 * 三连空行折成两行，最后按 code point 收到 max（超了以省略号收尾）。
 */
export function sanitizeDigestText(value, max = DIGEST_TEXT_MAX) {
  const limit = positiveInt(max, DIGEST_TEXT_MAX);
  const text = asText(value)
    .replace(/\r\n?/g, '\n')
    .replace(CONTROL_CHARS, ' ')
    .split('\n')
    .map((line) => line.replace(/^[ \t\u00A0]+|[ \t\u00A0]+$/g, ''))
    .join('\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
  const chars = Array.from(text);
  if (chars.length <= limit) return chars.join('');
  return chars.slice(0, Math.max(1, limit - 1)).join('') + '…';
}

const seqOf = (value) => {
  const number = Math.floor(Number(value));
  return Number.isFinite(number) && number > 0 ? number : 0;
};

/** digestId 由窗口决定（确定性：同一个窗口不可能写两条） */
export const digestIdOf = (fromSeq, toSeq) => 'd-' + seqOf(fromSeq) + '-' + seqOf(toSeq);

/** 一条摘要：形状固定，坏数据一律 null（调用方直接丢掉这一条） */
export function normalizeDigest(raw) {
  const source = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  const fromSeq = seqOf(source.fromSeq);
  const toSeq = seqOf(source.toSeq);
  if (fromSeq < 1 || toSeq < fromSeq) return null;
  const text = sanitizeDigestText(source.text);
  if (text === '') return null;
  const at = Number(source.at);
  const kind = asText(source.source) === 'fallback' ? 'fallback' : 'agent';
  return {
    digestId: asText(source.digestId).slice(0, 64) || digestIdOf(fromSeq, toSeq),
    fromSeq,
    toSeq,
    at: Number.isFinite(at) && at > 0 ? Math.floor(at) : 0,
    source: kind,
    text,
  };
}

/** 盘上的那份：{version:1, digests:[旧→新]}，坏数据收敛成空表（绝不抛错） */
export function normalizeDigestStore(raw) {
  const source = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  const digests = [];
  const seen = new Set();
  for (const entry of Array.isArray(source.digests) ? source.digests : []) {
    const made = normalizeDigest(entry);
    if (!made || seen.has(made.digestId)) continue;
    seen.add(made.digestId);
    digests.push(made);
  }
  return { version: 1, digests: digests.slice(-DIGEST_KEEP) };
}

/** 平面里的 rev：最新一条的 toSeq（群的 seq 是单调钟；重启不倒退） */
export function digestPlaneRev(digests) {
  const list = Array.isArray(digests) ? digests : [];
  const newest = list[list.length - 1];
  return newest ? seqOf(newest.toSeq) : 0;
}

/** 平面形状 {rev, hubId, digests}：只带最新 DIGEST_PLANE_LIMIT 条，**新的在前** */
export function normalizeDigestPlane(raw) {
  const source = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  const base = normalizeDigestStore(source);
  const digests = [...base.digests].reverse().slice(0, DIGEST_PLANE_LIMIT);
  const rev = Number(source.rev);
  return {
    rev: Number.isFinite(rev) && rev > 0 ? Math.floor(rev) : digestPlaneRev(base.digests),
    hubId: asText(source.hubId).slice(0, 64),
    digests,
  };
}

/** 成员侧合并（只读镜像）：rev 更大才采纳 */
export function mergeDigestPlane(local, remote) {
  const mine = normalizeDigestPlane(local);
  const theirs = normalizeDigestPlane(remote);
  return theirs.rev > mine.rev ? theirs : mine;
}

/**
 * fallback 摘要（**确定性**、零模型）：条数表头 + 原文开头若干字。
 * 同一个批次永远得到同一段文字 —— 用例与排障都靠得住。
 */
export function fallbackDigestText(batch, { chars = DIGEST_FALLBACK_CHARS } = {}) {
  const list = Array.isArray(batch) ? batch : [];
  const limit = positiveInt(chars, DIGEST_FALLBACK_CHARS);
  const fromSeq = seqOf(list[0]?.seq);
  const toSeq = seqOf(list[list.length - 1]?.seq);
  const lines = [
    '[digest] ' + list.length + ' 条群消息（seq ' + fromSeq + '-' + toSeq
      + '，摘要服务不可用，下面是原文开头）',
  ];
  for (const item of list) {
    lines.push('- seq=' + seqOf(item?.seq) + ' ' + (asText(item?.name) || '-')
      + ': ' + clipLine(item?.text));
    if (lines.join('\n').length >= limit) break;
  }
  return sanitizeDigestText(lines.join('\n'), limit);
}

/** 摘要提示：**只**装群消息正文（seq / 名字 / 正文），没有别的任何东西 */
export function buildDigestPrompt(batch) {
  const list = Array.isArray(batch) ? batch : [];
  const fromSeq = seqOf(list[0]?.seq);
  const toSeq = seqOf(list[list.length - 1]?.seq);
  const lines = [
    '【群摘要 · 本机是 hub】把下面这一批群消息压成一段不超过 800 字的中文摘要，给群成员直接读：',
    '谁在做什么、已经定下来的结论、还等谁办什么事。只输出摘要正文；不要标题、不要 Markdown、不要逐条复述。',
    '本批 ' + list.length + ' 条（seq ' + fromSeq + '-' + toSeq + '）：',
  ];
  for (const item of list) {
    lines.push('- seq=' + seqOf(item?.seq) + ' ' + (asText(item?.name) || '-')
      + ': ' + clipLine(item?.text));
  }
  return lines.join('\n');
}

/**
 * 摘要存储：hub 侧是权威（append），成员侧是镜像（setReplica，rev 门控、只认 hub 作者）。
 * 角色由**调用方**决定（hub 传 hubId=本机 instanceId），这里只保证形状。
 */
export class GroupDigestStore {
  constructor(options = {}) {
    const stateDir = String(options.stateDir ?? process.cwd());
    this.path = path.join(stateDir, GROUP_DIGESTS_FILE);
    this.now = typeof options.now === 'function' ? options.now : Date.now;
    this.logger = typeof options.logger === 'function' ? options.logger : null;
    /** 本机是 hub 时的作者 id：平面靠它判「这条摘要是不是 hub 写的」 */
    this.hubId = asText(options.hubId).slice(0, 64);
    this.data = normalizeDigestStore(readJson(this.path));
  }

  log(text) {
    if (this.logger) this.logger('[digest] ' + text);
  }

  list() {
    return this.data.digests.map((entry) => ({ ...entry }));
  }

  count() {
    return this.data.digests.length;
  }

  newest() {
    const size = this.data.digests.length;
    return size === 0 ? null : { ...this.data.digests[size - 1] };
  }

  /** 平面 rev = 最新一条的 toSeq */
  get rev() {
    return digestPlaneRev(this.data.digests);
  }

  /** 平面投影 {rev, hubId, digests(新的在前, ≤5)} */
  value() {
    return normalizeDigestPlane({ rev: this.rev, hubId: this.hubId, digests: this.data.digests });
  }

  save() {
    try {
      writeJson(this.path, { version: 1, digests: this.data.digests });
    } catch (error) {
      this.log('store-write-failed err=' + shortReason(error, 48));
    }
  }

  /** 追加一条（append-only，只留最新 20）：同一个窗口重放不会写第二条 */
  append(input) {
    const raw = input && typeof input === 'object' ? input : {};
    const made = normalizeDigest({
      ...raw,
      at: Number(raw.at) > 0 ? raw.at : Number(this.now()),
    });
    if (!made) return { ok: false, error: 'bad-request', rev: this.rev, count: this.count() };
    if (this.data.digests.some((entry) => entry.digestId === made.digestId)) {
      return { ok: false, error: 'duplicate', rev: this.rev, count: this.count() };
    }
    this.data.digests = [...this.data.digests, made].slice(-DIGEST_KEEP);
    this.save();
    this.log('append id=' + made.digestId + ' source=' + made.source
      + ' chars=' + Array.from(made.text).length + ' rev=' + this.rev);
    return { ok: true, digest: made, rev: this.rev, count: this.count() };
  }

  /**
   * 成员侧采纳一份 hub 写的平面：**只认 hub 作者**且 rev 更大。
   * 非 hub 的平面（哪怕 rev 更大）一个字节都不落盘 —— 摘要的作者只有 hub 一个。
   */
  setReplica(raw, { hubId = '' } = {}) {
    const current = this.value();
    const theirs = normalizeDigestPlane(raw);
    const expected = asText(hubId).slice(0, 64);
    if (expected === '' || theirs.hubId === '' || theirs.hubId !== expected) {
      return {
        rev: current.rev,
        count: this.count(),
        adopted: false,
        error: expected === '' ? 'no-hub' : 'not-hub-authored',
      };
    }
    const merged = mergeDigestPlane(current, theirs);
    const adopted = merged.rev > current.rev;
    if (!adopted) return { rev: current.rev, count: this.count(), adopted: false };
    // 平面是「新的在前」，盘上是「旧→新」：翻回来再落
    this.data.digests = normalizeDigestStore({ digests: [...merged.digests].reverse() }).digests;
    this.hubId = theirs.hubId;
    this.save();
    this.log('replica rev=' + merged.rev + ' n=' + merged.digests.length);
    return { rev: merged.rev, count: this.count(), adopted: true };
  }
}

/**
 * hub 侧的摘要器：**造一次会话、用到底**（与常驻参与者同一套策略）。
 *
 * 注入面（全部可假）：
 *   store            GroupDigestStore（权威那份）
 *   messages(fromSeq) -> [{seq, from:{name}, text}]   hub 的权威日志
 *   promptSession(sessionId, prompt) -> {sessionId, reused, reply}   空 sessionId = 新建
 *   log(line)        一行日志（'[digest] ...' 由这里给，调用方只管写出去）
 *   now / setIntervalFn / clearIntervalFn / setTimeoutFn / clearTimeoutFn   时钟与定时器全可注入
 *
 * 角色在**这里**判（不是靠调用方记得不叫）：isHub !== true 的实例什么都不做 ——
 * 不造会话、不读日志、不写平面。成员节点上跑的永远是这个禁用态。
 */
export function createHubSummarizer({
  isHub = false,
  store = null,
  messages = null,
  promptSession = null,
  stateDir = '',
  sessionFile = '',
  everyMessages = DIGEST_TRIGGER_MESSAGES,
  everyMs = DIGEST_TRIGGER_MS,
  promptTimeoutMs = DIGEST_PROMPT_TIMEOUT_MS,
  fallbackChars = DIGEST_FALLBACK_CHARS,
  now = Date.now,
  setIntervalFn = (fn, ms) => setInterval(fn, ms),
  clearIntervalFn = (handle) => clearInterval(handle),
  setTimeoutFn = (fn, ms) => setTimeout(fn, ms),
  clearTimeoutFn = (handle) => clearTimeout(handle),
  log = null,
} = {}) {
  const hubOnly = isHub !== true;
  const logLine = (line) => {
    if (typeof log === 'function') log(line);
  };
  const timeOf = () => {
    const value = Number(now());
    return Number.isFinite(value) ? value : 0;
  };
  const triggerMessages = positiveInt(everyMessages, DIGEST_TRIGGER_MESSAGES);
  const triggerMs = positiveInt(everyMs, DIGEST_TRIGGER_MS);
  const fallbackLimit = positiveInt(fallbackChars, DIGEST_FALLBACK_CHARS);
  const dir = String(stateDir ?? '').trim() === '' ? '' : path.resolve(String(stateDir));
  const sessionPath = asText(sessionFile) !== ''
    ? asText(sessionFile)
    : (dir === '' ? '' : path.join(dir, DIGEST_SESSION_FILE));

  let sessionId = '';
  let busy = false;
  let closed = false;
  let timer = null;

  if (hubOnly) logLine('[digest] summarizer disabled role=member');

  function readSession() {
    if (sessionPath === '') return '';
    const raw = readJson(sessionPath);
    return asText(raw?.sessionId).slice(0, 128);
  }

  function writeSession(next) {
    if (sessionPath === '') return;
    try {
      writeJson(sessionPath, { sessionId: next });
    } catch (error) {
      logLine('[digest] session-write-failed err=' + shortReason(error, 48));
    }
  }

  if (!hubOnly) sessionId = readSession();

  /**
   * 本批 = **上次摘要之后**新增的消息（窗口从最新一条摘要的 toSeq 起算）。
   * 这一行是「重复 fire 是空操作」的来源：窗口不是从 0 起算，而是从上一条摘要之后。
   */
  function freshBatch() {
    if (typeof messages !== 'function') return [];
    const latest = store ? store.newest() : null;
    const since = latest ? seqOf(latest.toSeq) : 0;
    const raw = messages(since);
    const out = [];
    for (const message of Array.isArray(raw) ? raw : []) {
      const seq = seqOf(message?.seq);
      if (seq <= since) continue;
      out.push({ seq, name: asText(message?.from?.name), text: asText(message?.text) });
    }
    out.sort((left, right) => left.seq - right.seq);
    return out;
  }

  function withPromptTimeout(promise) {
    const ms = positiveInt(promptTimeoutMs, DIGEST_PROMPT_TIMEOUT_MS);
    let handle = null;
    const guard = new Promise((resolve, reject) => {
      handle = setTimeoutFn(() => {
        reject(Object.assign(new Error('timeout'), { code: 'timeout' }));
      }, ms);
      if (handle && typeof handle.unref === 'function') handle.unref();
    });
    return Promise.race([Promise.resolve(promise), guard]).finally(() => {
      if (handle) clearTimeoutFn(handle);
    });
  }

  /** 一次合成的两条路：会话回话（source:agent）/ 确定性兜底（source:fallback） */
  async function compose(batch) {
    try {
      if (typeof promptSession !== 'function') {
        throw Object.assign(new Error('no-summarizer'), { code: 'no-summarizer' });
      }
      const previous = sessionId;
      const out = await withPromptTimeout(promptSession(previous, buildDigestPrompt(batch)));
      const next = asText(out?.sessionId).slice(0, 128);
      if (next !== '' && next !== previous) {
        sessionId = next;
        writeSession(next);
        if (previous !== '') logLine('[digest] session-recreated');
      }
      const text = sanitizeDigestText(out?.reply);
      if (text === '') throw Object.assign(new Error('empty-reply'), { code: 'empty-reply' });
      return { text, source: 'agent' };
    } catch (error) {
      logLine('[digest] fallback reason=' + shortReason(error));
      return { text: fallbackDigestText(batch, { chars: fallbackLimit }), source: 'fallback' };
    }
  }

  /**
   * 唯一的落点：count / timer / manual 三条路都从这里进。
   * 闸在这一行**同步**落下 —— 并发的第二次 fire 直接 in-flight（no-op），绝不双写。
   */
  async function maybeSummarize(trigger = 'manual') {
    if (hubOnly) return { ok: false, error: 'hub-only' };
    if (!store) return { ok: false, error: 'no-store' };
    if (closed) return { ok: false, error: 'closed' };
    if (busy) return { ok: false, error: 'in-flight' };
    const kind = ['count', 'timer', 'manual'].includes(String(trigger)) ? String(trigger) : 'manual';
    let batch = [];
    try {
      batch = freshBatch();
    } catch (error) {
      logLine('[digest] batch-failed err=' + shortReason(error));
      return { ok: false, error: 'batch-failed' };
    }
    if (batch.length === 0) return { ok: false, error: 'no-new' };
    if (kind === 'count' && batch.length < triggerMessages) {
      return { ok: false, error: 'below-threshold', pending: batch.length };
    }
    busy = true;
    const fromSeq = batch[0].seq;
    const toSeq = batch[batch.length - 1].seq;
    try {
      const composed = await compose(batch);
      const out = store.append({
        fromSeq,
        toSeq,
        at: timeOf(),
        source: composed.source,
        text: composed.text,
      });
      if (out.ok !== true) {
        logLine('[digest] write-failed err=' + shortReason(out.error, 32));
        return { ok: false, error: String(out.error) };
      }
      return { ok: true, trigger: kind, digest: out.digest, rev: out.rev };
    } finally {
      busy = false;
    }
  }

  /** 计数触发：够 40 条才真的跑一趟（不够只报数，绝不为 3 条消息叫一次模型） */
  function noteNew() {
    if (hubOnly) return { ok: false, error: 'hub-only' };
    if (!store) return { ok: false, error: 'no-store' };
    if (closed) return { ok: false, error: 'closed' };
    let pending = 0;
    try {
      pending = freshBatch().length;
    } catch {
      return { ok: false, error: 'batch-failed' };
    }
    if (pending < triggerMessages) return { ok: true, pending, fired: null };
    const done = maybeSummarize('count').catch(() => ({ ok: false, error: 'failed' }));
    return { ok: true, pending, fired: 'count', done };
  }

  /** 时间触发：这一趟有什么算什么（0 条 = 空操作） */
  function tick() {
    if (hubOnly) return { ok: false, error: 'hub-only' };
    const done = maybeSummarize('timer').catch(() => ({ ok: false, error: 'failed' }));
    return { ok: true, done };
  }

  return {
    isHub: !hubOnly,
    sessionPath,
    get sessionId() {
      return sessionId;
    },
    state() {
      let pending = 0;
      try {
        pending = hubOnly ? 0 : freshBatch().length;
      } catch {
        pending = 0;
      }
      return {
        isHub: !hubOnly,
        closed,
        busy,
        sessionId,
        pending,
        everyMessages: triggerMessages,
        everyMs: triggerMs,
        rev: store ? store.rev : 0,
        count: store ? store.count() : 0,
        armed: timer !== null,
      };
    },
    maybeSummarize,
    noteNew,
    tick,
    /** 10 分钟节拍：unref（不吊住进程）+ close() 里清（热重载不留定时器） */
    start() {
      if (hubOnly) return { ok: false, error: 'hub-only' };
      if (closed || timer !== null) return { ok: true, armed: false };
      timer = setIntervalFn(() => {
        try {
          tick();
        } catch (error) {
          logLine('[digest] tick-failed err=' + shortReason(error));
        }
      }, triggerMs);
      if (timer && typeof timer.unref === 'function') timer.unref();
      return { ok: true, armed: true, everyMs: triggerMs };
    },
    close() {
      closed = true;
      if (timer !== null) {
        clearIntervalFn(timer);
        timer = null;
      }
    },
  };
}

/**
 * 把「给总结会话提问并等回答」做成可测的工厂。
 *
 * 为什么单独拿出来：这段接线原先内联在插件入口里，而入口没有任何用例覆盖，
 * 于是 `runner.ask` 的两种返回形状被写成同一种读法 —— 新建会话那条永远拿到空串，
 * 真机上表现为 [digest] fallback reason=no-session，摘要平面长期只走兜底。
 *
 * 形状契约（与 lib/participant.mjs 的 promptSession 同源）：
 *   · runner.ask(prompt)                  → 裸 sessionId 字符串
 *   · runner.ask(prompt, { sessionId })   → { sessionId, reused }
 * 任何一步拿不到 sessionId 就向上抛，让调用方走确定性兜底摘要，绝不卡住摘要平面。
 */
export function createSessionPrompt({
  runner = null,
  waitMs = 55_000,
  pollMs = 150,
  now = Date.now,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
} = {}) {
  if (!runner || typeof runner.ask !== 'function' || typeof runner.poll !== 'function') {
    return null;
  }
  return async function sessionPrompt(sessionId, prompt) {
    const wanted = typeof sessionId === 'string' ? sessionId.trim() : '';
    let next = '';
    let reused = false;
    if (wanted === '') {
      const created = await runner.ask(prompt);
      next = String(created ?? '').trim();
    } else {
      const asked = await runner.ask(prompt, { sessionId: wanted });
      next = String(asked?.sessionId ?? '').trim() || wanted;
      reused = next === wanted && asked?.reused !== false;
    }
    if (next === '') throw new Error('no-session');
    const deadline = now() + waitMs;
    for (;;) {
      const polled = await runner.poll(next);
      const status = String(polled?.status ?? '');
      if (status === 'done') return { sessionId: next, reused, reply: String(polled?.reply ?? '') };
      if (status === 'error') throw new Error(String(polled?.error ?? 'ask-failed'));
      if (now() >= deadline) throw Object.assign(new Error('timeout'), { code: 'timeout' });
      await sleep(pollMs);
    }
  };
}
