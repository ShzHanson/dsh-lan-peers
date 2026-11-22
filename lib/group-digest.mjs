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
 *   group-digest-session.json { sessionId }   **只**在 sessionMode:'reuse' 下存在（造一次、用到底）；
 *                            默认 per-batch 一条摘要一个新会话，这个文件既不读也不写，构造时还会删掉旧的一份
 *   digest-out.txt            摘要会话这一趟写下的正文（**每次提示前先删、读完立删**，stateDir 里绝不留）
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
/**
 * 摘要正文的 handoff 文件名（落在 <stateDir> 下）：正文由文件承载，
 * 因为轮询回来的 reply 只是 UI 预览，真机上到 120 字就被截断。
 */
export const DIGEST_OUT_FILE = 'digest-out.txt';

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
/**
 * fallback 正文预算 = 正文上限（原先是 800：25 条消息只塞得下 3 条，
 * 剩下 18 条**悄无声息**地消失，读的人不知道自己漏了什么）。
 */
export const DIGEST_FALLBACK_CHARS = DIGEST_TEXT_MAX;
/** fallback 里每条原文的片段上限（120 字够认出一条消息，又让更多条塞得进来） */
export const DIGEST_FALLBACK_LINE_MAX = 120;
/**
 * 摘要会话单次回复的超时（超时就 fallback，绝不把平面挂在那儿）。
 * 180 s：提示现在要求会话**写一个文件**再回 DONE，多一趟工具往返 ——
 * 60 s 在真机上把这条路整体打成 timeout（四次全 fallback，source=file 一次没执行过）。
 */
export const DIGEST_PROMPT_TIMEOUT_MS = 180_000;
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

/** 省略标记（最后一行）：N = 真的没列出来的条数，一个都不许少报 */
const omitMarker = (omitted) => '…（还有 ' + omitted + ' 条未列出，可在群里按 seq 查看）';

/**
 * fallback 摘要（**确定性**、零模型）：条数表头 + 原文开头若干条 + 省略标记。
 * 同一个批次永远得到同一段文字 —— 用例与排障都靠得住。
 *
 * 装不下的消息**必须**以最后一行如实交代（`…（还有 N 条未列出，可在群里按 seq 查看）`）：
 * 悄悄漏掉 18 条比只列出 3 条更糟，因为读的人不知道自己漏了什么。
 * 标记本身也从预算里扣 —— 它算在清洗后的有界正文内，绝不能被 sanitize 截掉。
 */
export function fallbackDigestText(batch, {
  chars = DIGEST_FALLBACK_CHARS,
  lineMax = DIGEST_FALLBACK_LINE_MAX,
} = {}) {
  const list = Array.isArray(batch) ? batch : [];
  const limit = positiveInt(chars, DIGEST_FALLBACK_CHARS);
  const width = positiveInt(lineMax, DIGEST_FALLBACK_LINE_MAX);
  const fromSeq = seqOf(list[0]?.seq);
  const toSeq = seqOf(list[list.length - 1]?.seq);
  const size = (text) => Array.from(text).length;
  const header = '[digest] ' + list.length + ' 条群消息（seq ' + fromSeq + '-' + toSeq
    + '，摘要服务不可用，下面是原文开头）';
  const lines = [];
  let used = size(header);
  for (const item of list) {
    const line = '- seq=' + seqOf(item?.seq) + ' ' + (asText(item?.name) || '-')
      + ': ' + clipLine(item?.text, width);
    // 这一行之后还剩几条：标记从这一步就进预算，所以最终那份一定留得下它
    const omitted = list.length - (lines.length + 1);
    const tail = omitted > 0 ? '\n' + omitMarker(omitted) : '';
    if (used + 1 + size(line) + size(tail) > limit) break;
    lines.push(line);
    used += 1 + size(line);
  }
  const omitted = list.length - lines.length;
  if (omitted > 0) lines.push(omitMarker(omitted));
  return sanitizeDigestText([header, ...lines].join('\n'), limit);
}

/**
 * 摘要提示：**只**装群消息正文（seq / 名字 / 正文），没有别的任何东西。
 *
 * outFile 是 hub 侧 <stateDir> 下的**绝对路径**（由调用方从已解析的 stateDir 推出，绝不来自模型输出）：
 * 正文走文件、回复只写 DONE —— 轮询回来的 reply 只当兜底。outFile 为空（没给 stateDir）时
 * 不带落盘指令，仍走回复那条老路。
 */
export function buildDigestPrompt(batch, { outFile = '' } = {}) {
  const list = Array.isArray(batch) ? batch : [];
  const fromSeq = seqOf(list[0]?.seq);
  const toSeq = seqOf(list[list.length - 1]?.seq);
  const writeTo = asText(outFile);
  const lines = [
    '【群摘要 · 本机是 hub】把下面这一批群消息压成一段不超过 800 字的中文摘要，给群成员直接读：',
    '谁在做什么、已经定下来的结论、还等谁办什么事。只输出摘要正文；不要标题、不要 Markdown、不要逐条复述。',
    '超过 800 字就压短（硬上限：摘要正文不得超过 800 字）。',
  ];
  if (writeTo !== '') {
    lines.push(
      '落盘（必须做）：把摘要正文**覆盖写入**下面这个绝对路径（UTF-8，只写摘要正文，不要追加、不要写别的文件）：',
      '路径：' + writeTo,
      '写完文件后，你的回复只写一个词：DONE —— 不要在回复里重复摘要正文。',
    );
  }
  lines.push('本批 ' + list.length + ' 条（seq ' + fromSeq + '-' + toSeq + '）：');
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
 * hub 侧的摘要器。
 *
 * sessionMode 决定摘要会话怎么来：
 *   'per-batch'（默认）  一趟摘要一个**新**会话：提示时不带 sessionId（promptSession('', prompt)），
 *                        这一趟的答复用完就丢。摘要是自包含的（提示里已经有整批消息正文），
 *                        跨批记忆换不来任何东西，却让每批的 prompt+reply 一直堆在同一个会话里 ——
 *                        真机上同一会话从 93 KB 涨到 232 KB，单轮从 60 s 涨到 175 s 而彻底超预算。
 *   'reuse'              老行为：造一次、用到底，sessionId 落 group-digest-session.json。
 *                        留着它只是为了可测与可回退，默认不走。
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
  sessionMode = 'per-batch',
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

  // 只有字面量 'reuse' 走老路；别的一律 per-batch（默认），拼错也不会悄悄回到复用
  const mode = String(sessionMode ?? '') === 'reuse' ? 'reuse' : 'per-batch';

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
    if (mode !== 'reuse' || sessionPath === '') return;
    try {
      writeJson(sessionPath, { sessionId: next });
    } catch (error) {
      logLine('[digest] session-write-failed err=' + shortReason(error, 48));
    }
  }

  if (!hubOnly && mode === 'per-batch' && sessionPath !== '') {
    // 复活防线：per-batch 下这个文件既不读也不写，构造时顺手删一次 ——
    // 盘上残留一份旧会话，下一个人会以为「文件还在 = 还在复用」，进而以为轮次慢是别的原因。
    let stale = false;
    try {
      stale = fs.existsSync(sessionPath);
    } catch {
      stale = false;
    }
    if (stale) {
      try {
        fs.unlinkSync(sessionPath);
      } catch {
        // 删不掉也照旧不读它；日志只按「盘上确实有一份」记一次
      }
      logLine('[digest] session-file-ignored');
    }
  }
  if (!hubOnly && mode === 'reuse') sessionId = readSession();

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

  /** handoff 文件的绝对路径：**只**由已解析的 stateDir 推出（dir 为空时没有这条路） */
  const outFilePath = dir === '' ? '' : path.join(dir, DIGEST_OUT_FILE);

  /** 提示前与读后都要删。ENOENT 是最常见的一条（没有文件就是正常起点），不记日志。 */
  function clearOutFile() {
    if (outFilePath === '') return;
    try {
      fs.unlinkSync(outFilePath);
    } catch {
      // ENOENT / 权限：删不掉也不许打断摘要流程
    }
  }

  /** 读回 handoff 正文并**立刻删除**；任何读错误都收成空串，绝不向上抛 */
  function takeOutFile() {
    if (outFilePath === '') return '';
    let raw = '';
    try {
      raw = fs.readFileSync(outFilePath, 'utf8');
    } catch {
      raw = '';
    } finally {
      clearOutFile();
    }
    return sanitizeDigestText(raw);
  }

  /**
   * 一次合成的两条路：会话回话（source:agent）/ 确定性兜底（source:fallback）。
   *
   * 正文的**首选**是 handoff 文件：轮询回来的 reply 只是 UI 预览（真机到 120 字就截断），
   * 所以顺序是「文件 → 回复 → empty-reply → 兜底」，并且提示之前先删掉陈旧文件。
   */
  async function compose(batch) {
    // 每一趟都量耗时：'[digest] turn ms=<n> source=<file|reply|fallback>'。
    // 少了这一行，「四次全 fallback、source=file 一次没执行」只能靠现场推断才看得出来。
    const startedAt = Number(now());
    const turn = (source) => {
      const ms = Math.round(Number(now()) - startedAt);
      logLine('[digest] turn ms=' + (Number.isFinite(ms) && ms > 0 ? ms : 0) + ' source=' + source);
    };
    // 每趟摘要一行：模式是这一行唯一的变量，下一回看日志不必再从会话体积反推
    logLine('[digest] session mode=' + mode);
    try {
      if (typeof promptSession !== 'function') {
        throw Object.assign(new Error('no-summarizer'), { code: 'no-summarizer' });
      }
      clearOutFile();
      // per-batch：**永远**空 sessionId —— 空串就是「新建会话」，一个批次的答复与下一批无关
      const previous = mode === 'reuse' ? sessionId : '';
      let out = null;
      try {
        out = await withPromptTimeout(
          promptSession(previous, buildDigestPrompt(batch, { outFile: outFilePath })),
        );
      } catch (error) {
        clearOutFile();
        throw error;
      }
      const next = asText(out?.sessionId).slice(0, 128);
      if (mode === 'reuse' && next !== '' && next !== previous) {
        sessionId = next;
        writeSession(next);
        if (previous !== '') logLine('[digest] session-recreated');
      }
      const fromFile = takeOutFile();
      if (fromFile !== '') {
        logLine('[digest] source=file chars=' + Array.from(fromFile).length);
        turn('file');
        return { text: fromFile, source: 'agent' };
      }
      const text = sanitizeDigestText(out?.reply);
      if (text === '') throw Object.assign(new Error('empty-reply'), { code: 'empty-reply' });
      logLine('[digest] source=reply chars=' + Array.from(text).length);
      turn('reply');
      return { text, source: 'agent' };
    } catch (error) {
      clearOutFile();
      logLine('[digest] fallback reason=' + shortReason(error));
      const text = fallbackDigestText(batch, { chars: fallbackLimit });
      turn('fallback');
      return { text, source: 'fallback' };
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
        sessionMode: mode,
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
  // 内层轮询的截止必须**贴着外层守卫**（180 s - 5 s），否则守卫放宽到 180 s 也白搭：
  // 55 s 的内层 deadline 会先抛 timeout，真机上照样是 fallback。
  waitMs = DIGEST_PROMPT_TIMEOUT_MS - 5_000,
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
