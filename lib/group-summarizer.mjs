/**
 * dsh-lan-peers · 0.13.0-alpha（决定 C）群摘要的**远端摘要器**
 * ======================================================================
 *
 * 用户要的是「模型摘要回来」，代价是 hub 自己的参与者会话被那一趟摘要占满
 * （真机 turn ms≈175000 source=fallback）。决定 C 把它搬到**另一台机器**：
 * 桌面机或第三台节点跑模型，hub 只负责派发与采纳。
 *
 * 硬要求（用户原话）：**那台机器突然下线，摘要仍必须准时产出**。所以这里的铁律：
 *
 *   1. 确定性先行，永不改变：远端这一趟发生在确定性条目**全部落盘之后**，
 *      既不提前、也不阻塞、更不取消。窗口该有的一条都不少（决定 A 是地板）。
 *   2. 机会式升级：成功才**追加一条**（source:'agent-remote'），append-only，
 *      绝不改既有条目、绝不改 rev 的语义（同窗口 toSeq，不带新水位）。
 *   3. 下线 = 降级，不是停摆：探测/超时/错误回复最多花掉一两秒（SUMMARY_BUDGET_MS），
 *      然后进冷却（30 分钟或 3 个窗口，先到先解），冷却期内一个包都不发。
 *      每个窗口只留**一行**：[digest] summary skipped reason=<offline|timeout|error|not-configured>
 *   4. 信任：只认**被指定那一位**签名且 by 相等的回复；别的回稳定错误、记一行、绝不发布。
 *   5. 内容安全：模型输出是**数据**。上限 DIGEST_TEXT_MAX、过 sanitizeDigestText（控制字符抹掉），
 *      再打上 source/by/fromSeq/toSeq 才可能进平面。
 *
 * 为什么签名放在这里而不是 host：正文（canonical 五行 + HMAC-SHA256）与 §4 完全同形，
 * 但这几行要能被 lib 层用例直接钉住（"外来 by 一律拒"）。请求方向仍然用既有的
 * per-peer 鉴权（host/server.mjs 的 authenticate），这里只补**回复**那一个方向。
 */
import { createHash, createHmac, randomBytes } from 'node:crypto';

import { DIGEST_LINE_MAX, DIGEST_TEXT_MAX, clipLine, sanitizeDigestText } from './group-digest.mjs';

/** 接收端的路由（per-peer 签名 + 信封；与 /v1/file/*、/v1/dm/* 同一把尺子） */
export const DIGEST_SUMMARY_PATH = '/v1/group/digest-summary';
/** 回复签名的 canonical 第一行（请求方向是 HTTP 方法，回复方向没有方法可用） */
export const SUMMARY_CANON_METHOD = 'SUMMARY';
/** 冷却：时长（30 分钟）与窗口数（3 个）任一满足即解除 */
export const SUMMARY_COOLDOWN_MS = 30 * 60 * 1000;
export const SUMMARY_COOLDOWN_WINDOWS = 3;
/** 派发预算：对端不在线时这条路必须**有界**地回来（"最多一两秒"） */
/**
 * hub 派发时愿意等多久。**必须大于接收侧的处理预算**（SUMMARY_HANDLER_BUDGET_MS = 180s），
 * 否则无论对端是否就绪都必然超时。真机事故：这两个值曾是 2s vs 180s（差 90 倍），
 * 表现为每次都在 compose 后约 2 秒记 summary skipped reason=timeout，
 * 而当时对端的路由与代码其实都是好的。
 */
export const SUMMARY_BUDGET_MS = 200_000;
/** 接收端自己那一趟模型的预算（与 hub 侧 prompt 超时同量级） */
export const SUMMARY_HANDLER_BUDGET_MS = 180_000;
/** 回复签名的时间窗（与 §4 CLOCK_SKEW_MS 同口径） */
export const SUMMARY_CLOCK_SKEW_MS = 5 * 60 * 1000;
/** 一条 job 里最多几条消息（窗口本来就 40 上下；这是防呆上限） */
export const SUMMARY_MAX_LINES = 512;
/** 摘要正文上限：与确定性摘要同一个上限，平面里没有"更大的一条" */
export const SUMMARY_TEXT_MAX = DIGEST_TEXT_MAX;
/** 只允许这四个 skip 原因（日志口径是稳定字符串，排障脚本直接 grep） */
export const SUMMARY_SKIP_REASONS = Object.freeze(['offline', 'timeout', 'error', 'not-configured']);

/** 「对端现在就不在」这一类：重试不会变好，只会把一两秒拖成假死 */
const OFFLINE_CODES = new Set([
  'ECONNREFUSED',
  'ECONNRESET',
  'EPIPE',
  'ENOTFOUND',
  'EAI_AGAIN',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'ENETDOWN',
  'EADDRNOTAVAIL',
  'UND_ERR_CONNECT_TIMEOUT',
  'ERR_INVALID_URL',
]);

const asText = (value) => (typeof value === 'string' ? value : '');

const positiveInt = (value, fallback) => {
  const number = Math.floor(Number(value));
  return Number.isFinite(number) && number > 0 ? number : fallback;
};

const seqOf = (value) => {
  const number = Math.floor(Number(value));
  return Number.isFinite(number) && number > 0 ? number : 0;
};

/**
 * 配置值（peerId 或 peer 名）→ peerId。
 *
 * 空 = 没配（连一行日志都不该有，S6：沉默才是对的）。
 * 名字解析不出来 = 配置错误：调用方记一次 [digest] summarizer unknown name=...，
 * 之后按「没配」处理（每个窗口一行 reason=not-configured）。
 */
export function resolveSummaryPeer(value, { peers = [] } = {}) {
  const wanted = String(value ?? '').trim();
  if (wanted === '') return { configured: false, peerId: '', name: '', unknown: false };
  const list = Array.isArray(peers) ? peers : [];
  const byId = list.find((peer) => asText(peer?.peerId) === wanted);
  if (byId) return { configured: true, peerId: asText(byId.peerId), name: asText(byId.name), unknown: false };
  // 同名只取 peerId 最小那一个：配置里写名字不该让结果随 peers.json 顺序漂移
  const sameName = list
    .filter((peer) => asText(peer?.name) === wanted)
    .map((peer) => asText(peer?.peerId))
    .filter((id) => id !== '')
    .sort();
  if (sameName.length > 0) {
    const peerId = sameName[0];
    const record = list.find((peer) => asText(peer?.peerId) === peerId);
    return { configured: true, peerId, name: asText(record?.name), unknown: false };
  }
  return { configured: true, peerId: '', name: '', unknown: true };
}

/** 一批消息（[{seq,name,text}]）→ 一个自包含 job：只有 seq / 名字 / 正文 */
export function buildSummaryJob({ groupId = '', lines = [] } = {}) {
  const list = (Array.isArray(lines) ? lines : [])
    .filter((line) => seqOf(line?.seq) > 0)
    .slice()
    .sort((left, right) => seqOf(left?.seq) - seqOf(right?.seq))
    .slice(0, SUMMARY_MAX_LINES)
    .map((line) => ({
      seq: seqOf(line?.seq),
      name: asText(line?.name).slice(0, 64),
      text: clipLine(line?.text, DIGEST_LINE_MAX),
    }));
  return {
    groupId: asText(groupId).slice(0, 64),
    fromSeq: list.length === 0 ? 0 : seqOf(list[0].seq),
    toSeq: list.length === 0 ? 0 : seqOf(list[list.length - 1].seq),
    lines: list,
  };
}

/** 接收端那一趟提示：与 hub 侧同一口径（只装正文、只输出摘要、有界） */
export function buildSummaryPrompt(job) {
  const made = buildSummaryJob(job);
  const lines = [
    '【群摘要 · 本机是远端摘要节点】把下面这一批群消息压成一段不超过 800 字的中文摘要，给群成员直接读：',
    '谁在做什么、已经定下来的结论、还等谁办什么事。只输出摘要正文；不要标题、不要 Markdown、不要逐条复述。',
    '本批 ' + made.lines.length + ' 条（seq ' + made.fromSeq + '-' + made.toSeq + '）：',
  ];
  for (const line of made.lines) {
    lines.push('- seq=' + line.seq + ' ' + (line.name || '-') + ': ' + line.text);
  }
  return lines.join('\n');
}

/** 预算守卫：promise 与一个定时器赛跑（超时抛 code='timeout'） */
function withBudget(promise, ms, { setTimeoutFn, clearTimeoutFn } = {}) {
  const budget = positiveInt(ms, SUMMARY_BUDGET_MS);
  let handle = null;
  const guard = new Promise((resolve, reject) => {
    handle = setTimeoutFn(() => {
      reject(Object.assign(new Error('timeout'), { code: 'timeout' }));
    }, budget);
    if (handle && typeof handle.unref === 'function') handle.unref();
  });
  return Promise.race([Promise.resolve(promise), guard]).finally(() => {
    if (handle) clearTimeoutFn(handle);
  });
}

/** 失败压成三选一（offline / timeout / error）—— 日志口径只有这几种 */
export function classifySummaryFailure(error) {
  const code = asText(error?.code);
  const reason = asText(error?.message) || String(error ?? '');
  if (code === 'timeout' || /timeout/i.test(reason)) return 'timeout';
  if (OFFLINE_CODES.has(code)) return 'offline';
  const status = Number(error?.status);
  // 404/502/503 说明那个地址上没有摘要器（对端未升级/不在）——同属"现在拿不到"
  if (status === 404 || status === 502 || status === 503) return 'offline';
  // 传输层细节藏在 cause 里（undici 的 AggregateError 每个地址一个 code）
  for (let hop = 0, cursor = error?.cause; cursor && hop < 4; cursor = cursor.cause, hop += 1) {
    if (OFFLINE_CODES.has(asText(cursor.code))) return 'offline';
    if (Array.isArray(cursor.errors)) {
      for (const inner of cursor.errors.slice(0, 4)) {
        if (OFFLINE_CODES.has(asText(inner?.code))) return 'offline';
      }
    }
  }
  return 'error';
}

// ---------------------------------------------------------------------------
// 回复签名（§4 canonical 五行 + HMAC-SHA256，与 host 侧 signCanonical 同形）
// ---------------------------------------------------------------------------

const sha256Hex = (bytes) => createHash('sha256').update(bytes).digest('hex');

function replyCanonical({ by, groupId, fromSeq, toSeq, text, ts, nonce }) {
  const payload = Buffer.from(JSON.stringify({
    by: asText(by),
    groupId: asText(groupId),
    fromSeq: seqOf(fromSeq),
    toSeq: seqOf(toSeq),
    text: asText(text),
  }), 'utf8');
  return [
    SUMMARY_CANON_METHOD,
    DIGEST_SUMMARY_PATH,
    String(ts),
    String(nonce),
    sha256Hex(payload),
  ].join('\n');
}

function hmacOf(secret, canonical, keyEncoding = 'utf8') {
  const key = keyEncoding === 'base64url'
    ? Buffer.from(String(secret ?? ''), 'base64url')
    : Buffer.from(String(secret ?? ''), 'utf8');
  return createHmac('sha256', key).update(String(canonical), 'utf8').digest('base64url');
}

function timingSafeStringEqual(left, right) {
  const a = Buffer.from(String(left ?? ''), 'utf8');
  const b = Buffer.from(String(right ?? ''), 'utf8');
  if (a.length !== b.length) return false;
  if (a.length === 0) return false;
  let diff = 0;
  for (let index = 0; index < a.length; index += 1) diff |= a[index] ^ b[index];
  return diff === 0;
}

/**
 * 接收端签名自己的回复：签名覆盖「是谁 + 覆盖哪个窗口 + 正文」，
 * 所以 hub 那边一句 by 骗不过去 —— 没有自己那把密钥就凑不出这个签名。
 */
export function signSummaryReply({
  secret = '',
  keyEncoding = 'utf8',
  by = '',
  job = null,
  text = '',
  now = Date.now,
  nonce = '',
} = {}) {
  const made = buildSummaryJob(job ?? {});
  const ts = Number(now());
  const usedNonce = asText(nonce) || randomBytes(16).toString('hex');
  const body = sanitizeDigestText(text);
  const canonical = replyCanonical({
    by,
    groupId: made.groupId,
    fromSeq: made.fromSeq,
    toSeq: made.toSeq,
    text: body,
    ts,
    nonce: usedNonce,
  });
  return {
    ok: true,
    by: asText(by).slice(0, 64),
    groupId: made.groupId,
    fromSeq: made.fromSeq,
    toSeq: made.toSeq,
    text: body,
    sig: { ts, nonce: usedNonce, sign: hmacOf(secret, canonical, keyEncoding) },
  };
}

/**
 * hub 侧验回复：签名只认**被指定那一位**的密钥（inboundSecret 优先，与 §4 的
 * verifyPeerSignature 同一顺序）。任何一项过不去都是稳定错误码，绝不猜、绝不放行。
 */
export function verifySummaryReply({
  peer = null,
  reply = null,
  job = null,
  now = Date.now,
  skewMs = SUMMARY_CLOCK_SKEW_MS,
  keyEncoding = 'utf8',
} = {}) {
  const source = reply && typeof reply === 'object' ? reply : {};
  const sig = source.sig && typeof source.sig === 'object' ? source.sig : null;
  if (!sig) return { ok: false, error: 'bad-signature' };
  const ts = Number(sig.ts);
  if (!Number.isFinite(ts)) return { ok: false, error: 'bad-signature' };
  const nowMs = Number(now());
  if (!Number.isFinite(nowMs) || Math.abs(nowMs - ts) > positiveInt(skewMs, SUMMARY_CLOCK_SKEW_MS)) {
    return { ok: false, error: 'clock-skew' };
  }
  const made = buildSummaryJob(job ?? {});
  const canonical = replyCanonical({
    by: source.by,
    groupId: source.groupId,
    fromSeq: source.fromSeq,
    toSeq: source.toSeq,
    text: source.text,
    ts,
    nonce: asText(sig.nonce),
  });
  const secrets = [];
  if (asText(peer?.inboundSecret) !== '') secrets.push(peer.inboundSecret);
  if (asText(peer?.secret) !== '' && !secrets.includes(peer.secret)) secrets.push(peer.secret);
  for (const secret of secrets) {
    if (timingSafeStringEqual(hmacOf(secret, canonical, keyEncoding), asText(sig.sign))) {
      // 窗口必须对得上：一段别的窗口的摘要不能被安到这一批头上
      if (seqOf(source.fromSeq) !== made.fromSeq || seqOf(source.toSeq) !== made.toSeq) {
        return { ok: false, error: 'window-mismatch' };
      }
      const text = sanitizeDigestText(source.text);
      if (text === '') return { ok: false, error: 'empty-text' };
      return { ok: true, text };
    }
  }
  return { ok: false, error: 'bad-signature' };
}

// ---------------------------------------------------------------------------
// hub 侧派发器（冷却、一行日志、信任裁决都在这里）
// ---------------------------------------------------------------------------

/**
 * 一个窗口问一次远端摘要器；失败进冷却，成功清冷却。
 *
 * 注入面：
 *   call(job)        → 原始回复（host 侧就是 callPeer；用例里可以是假通道）
 *   verify(reply,job) → {ok,text} | {ok:false,error}（host 侧就是 verifySummaryReply）
 *   log(line)         一行日志（'[digest] ...' 由这里给全）
 *   now / setTimeoutFn / clearTimeoutFn   时钟与定时器全可注入（没有一个用例真的等 30 分钟）
 */
export function createRemoteSummaryDispatcher({
  configured = false,
  peerId = '',
  groupId = '',
  call = null,
  verify = null,
  now = Date.now,
  cooldownMs = SUMMARY_COOLDOWN_MS,
  cooldownWindows = SUMMARY_COOLDOWN_WINDOWS,
  budgetMs = SUMMARY_BUDGET_MS,
  log = null,
  setTimeoutFn = (fn, ms) => setTimeout(fn, ms),
  clearTimeoutFn = (handle) => clearTimeout(handle),
} = {}) {
  const wanted = configured === true;
  const designated = asText(peerId).slice(0, 64);
  const cooldownFor = positiveInt(cooldownMs, SUMMARY_COOLDOWN_MS);
  const windowCap = positiveInt(cooldownWindows, SUMMARY_COOLDOWN_WINDOWS);
  const budget = positiveInt(budgetMs, SUMMARY_BUDGET_MS);
  const timeOf = () => {
    const value = Number(now());
    return Number.isFinite(value) ? value : 0;
  };
  const logLine = (line) => {
    if (typeof log === 'function') log(line);
  };

  /** 冷却状态只在内存里：重启一次就重试一次（把"一台机器下线"熬过去就够） */
  let failedAt = 0;
  let windowsSinceFailure = 0;
  let lastReason = '';
  let dispatches = 0;
  let skips = 0;

  const skip = (reason) => {
    const stable = SUMMARY_SKIP_REASONS.includes(reason) ? reason : 'error';
    skips += 1;
    logLine('[digest] summary skipped reason=' + stable);
  };

  const fail = (reason, error = '') => {
    const stable = SUMMARY_SKIP_REASONS.includes(reason) ? reason : 'error';
    failedAt = timeOf();
    windowsSinceFailure = 0;
    lastReason = stable;
    skip(stable);
    return { ok: false, reason: stable, error: asText(error) };
  };

  const cooling = () => failedAt > 0
    && timeOf() - failedAt < cooldownFor
    && windowsSinceFailure < windowCap;

  const groupIdOf = () => (typeof groupId === 'function' ? asText(groupId()) : asText(groupId));

  async function summary(batch) {
    const list = Array.isArray(batch) ? batch : [];
    // 没配 = 一个字都不做、一行都不记（S6：沉默才是对的）
    if (!wanted) return { ok: false, reason: 'not-configured', silent: true };
    if (list.length === 0) return { ok: false, reason: 'not-configured', silent: true };
    // 配了但解析不出 peerId（名字打错/对端不在 peers.json）→ 按没配处理，一个窗口一行
    if (designated === '' || typeof call !== 'function') {
      skip('not-configured');
      return { ok: false, reason: 'not-configured' };
    }
    if (failedAt > 0) {
      windowsSinceFailure += 1;
      if (cooling()) {
        // 冷却期内不派发；日志照旧一个窗口一行（死掉的对端不该消失在日志里）
        skip(lastReason || 'offline');
        return { ok: false, reason: lastReason || 'offline', cooling: true };
      }
      // 时间到或窗口数到：解除冷却，这一趟重新试
      failedAt = 0;
      windowsSinceFailure = 0;
    }
    const job = buildSummaryJob({ groupId: groupIdOf(), lines: list });
    dispatches += 1;
    let raw = null;
    try {
      raw = await withBudget(call(job), budget, { setTimeoutFn, clearTimeoutFn });
    } catch (error) {
      return fail(classifySummaryFailure(error));
    }
    // 信任第一关：by 必须**就是**被指定的那一位（谁签的都白搭，先看它自报是谁）
    const by = asText(raw?.by);
    if (by === '' || by !== designated) return fail('error', 'wrong-peer');
    const verdict = typeof verify === 'function'
      ? verify(raw, job)
      : { ok: false, error: 'no-verifier' };
    if (!verdict || verdict.ok !== true) {
      return fail('error', asText(verdict?.error) || 'rejected');
    }
    const text = sanitizeDigestText(verdict.text);
    if (text === '') return fail('error', 'empty-text');
    // 成功 = 冷却清零：下一批立刻又能派发（一个死掉的对端回来时不该被旧冷却挡住）
    failedAt = 0;
    windowsSinceFailure = 0;
    lastReason = '';
    return { ok: true, text, by: designated, fromSeq: job.fromSeq, toSeq: job.toSeq };
  }

  return {
    summary,
    peerId: designated,
    state() {
      return {
        configured: wanted,
        peerId: designated,
        cooling: failedAt > 0 && cooling(),
        windowsSinceFailure,
        lastReason,
        dispatches,
        skips,
        budgetMs: budget,
        cooldownMs: cooldownFor,
        cooldownWindows: windowCap,
      };
    },
  };
}

// ---------------------------------------------------------------------------
// 接收端：一个 job 一个新会话（自包含批次，绝不复用历史 —— 那是 bloat 事故的教训）
// ---------------------------------------------------------------------------

/**
 * 远端摘要器的 job 处理器。
 *
 * promptSession 来自 group-digest.mjs 的 createSessionPrompt（真实路径），这里
 * **永远**传空 sessionId：一个批次一个新会话，答复用完就丢。没有通道时返回
 * {ok:false,error:'no-agent'}，绝不抛 —— 抛出去会让 hub 那边多等一个超时。
 */
export function createRemoteSummaryHandler({
  promptSession = null,
  budgetMs = SUMMARY_HANDLER_BUDGET_MS,
  now = Date.now,
  log = null,
  setTimeoutFn = (fn, ms) => setTimeout(fn, ms),
  clearTimeoutFn = (handle) => clearTimeout(handle),
} = {}) {
  const budget = positiveInt(budgetMs, SUMMARY_HANDLER_BUDGET_MS);
  return async function handleSummaryJob(job) {
    if (typeof promptSession !== 'function') return { ok: false, error: 'no-agent' };
    const made = buildSummaryJob(job ?? {});
    if (made.lines.length === 0) return { ok: false, error: 'empty-job' };
    let out = null;
    try {
      // '' = 新建会话；每一个 job 都是新的（自包含批次）
      out = await withBudget(promptSession('', buildSummaryPrompt(made)), budget, { setTimeoutFn, clearTimeoutFn });
    } catch (error) {
      const code = asText(error?.code) || asText(error?.message) || 'failed';
      if (typeof log === 'function') log('[digest] remote summary failed error=' + code.slice(0, 40));
      return { ok: false, error: code === 'timeout' ? 'timeout' : 'failed' };
    }
    const text = sanitizeDigestText(out?.reply);
    if (text === '') return { ok: false, error: 'empty-reply' };
    return { ok: true, text, at: Number(now()) };
  };
}
