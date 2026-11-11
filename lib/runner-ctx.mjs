// dsh-lan-peers · in-process runner.
//
// Uses the harness services directly (ctx.sessionController) instead of the
// local HTTP API, so inbound peer asks need no web token at all. This is the
// only runner that works inside the Electron app, which exposes no token.
import fs from 'node:fs';
import path from 'node:path';

const DEFAULT_DEBUG = 'D:/DS-Harness/.tmp/lan-peers-debug.log';
/**
 * 日志落点**每次调用时**读环境变量，不在模块加载时冻成常量：
 * 本模块现在也被 runner-dsh 静态 import（共用投影拆包），谁先被谁加载由导入图决定，
 * 冻在加载时就会让「先 setenv 再 import」的调用方把日志写去别处（测试和真机都一样）。
 */
function debug(line) {
  const target = process.env.LAN_PEERS_DEBUG || DEFAULT_DEBUG;
  try { fs.appendFileSync(target, new Date().toISOString() + ' ' + line + '\n'); } catch {}
}

const shortId = (value) => String(value ?? '').slice(0, 8);

/**
 * 铁律：workspace 只认**已存在的绝对目录**。不合法就抛错让上层回 runner-error，
 * 绝不静默回退到默认工作区 —— 否则界面里的「选择工作区」就是谎话。
 * 错误里绝不带 path（它会顺着 500 与日志走到对端）；只带一个稳定的 code。
 */
function workspaceError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

/** @returns {string|undefined} undefined = 没点名（保持旧行为），否则是校验通过的绝对路径 */
function resolveWorkspace(requested) {
  if (requested === undefined || requested === null) return undefined;
  if (typeof requested !== 'string') throw workspaceError('workspace-invalid');
  const value = requested.trim();
  if (value === '') return undefined;
  if (!path.isAbsolute(value)) throw workspaceError('workspace-not-absolute');
  let stat;
  try {
    stat = fs.statSync(value);
  } catch {
    throw workspaceError('workspace-missing');
  }
  if (!stat.isDirectory()) throw workspaceError('workspace-missing');
  return value;
}

/** @returns {string} 空串 = 没点名（保持旧行为，返回里一个多余键都不加） */
function resolvePermission(requested) {
  if (requested === undefined || requested === null) return '';
  if (typeof requested !== 'string') throw workspaceError('permission-invalid');
  return requested.trim();
}

/**
 * 权限三档（与 lib/dispatch-prefs.mjs 的 PERMISSION_LEVELS 同口径，顺序即档位高低）。
 * 这里不 import 那个模块：它是 host/派单侧的文件，runner 只依赖本文件自己的常量，
 * 两边同时被改时不会因为一处语法问题把执行侧一起带塌。
 */
const PERMISSION_TIERS = Object.freeze(['read-only', 'workspace-write', 'danger-full-access']);

/** 档位对应的审批策略（与 dsh-permission-presets 出厂预设 bundle 一致；read-only 收紧为 ask） */
const TIER_APPROVAL = Object.freeze({
  'read-only': 'ask',
  'workspace-write': 'ask',
  'danger-full-access': 'never',
});

/** @returns {number} 档位序号；不是三档之一一律 -1 */
function permissionRank(value) {
  return PERMISSION_TIERS.indexOf(String(value ?? ''));
}

/**
 * 安全闸门：请求档是已知档位、而读回的生效档**更宽**时，绝不执行这一轮。
 * 升高失败只是"没生效"（按低档照跑并如实 false）；降低失败则必须拒绝，
 * 否则一次 read-only 派单会静静地跑成 danger-full-access —— 那比报 false 更糟。
 */
function broaderThanRequested(requested, effective) {
  const error = new Error('permission-above-request');
  error.code = 'permission-above-request';
  error.requested = requested;
  error.effective = effective;
  return error;
}

/** 两个目录是不是同一个（Windows 大小写不敏感） */
function sameDir(left, right) {
  if (typeof left !== 'string' || left === '' || typeof right !== 'string' || right === '') return false;
  const a = path.resolve(left);
  const b = path.resolve(right);
  return process.platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b;
}

/**
 * 投影行的**线形状**（读真机 projection 缓存得到，路径见下）是真三层：
 *
 *   record.rows.turnOutline      = { ver: 2, seq: 41, val: { turns: [ { turn, seq, prompt, response } ], draft: '' } }
 *   record.rows.permissions      = { ver: 2, seq: 41, val: { preset, sandbox, approval, seeded } }
 *   record.rows.workingDirectory = { ver: 1, seq: 41, val: 'D:/DS-Harness/lan-peers-workspace' }
 *
 * 即每一行都是 `{ ver, seq, val }`：ver/seq 是版本与序号，**真值一律在 val 里**。
 * 历代客户端快照还有一层 `{ currentValue }`。所以「值」和「这一行的语义」是两件事：
 * 先剥已知包装层，再按语义读 `.turns` / `.preset`。
 *
 * 上一版（a66b570）把这些形状一个个列出来认，列漏了 `.val` 一层 —— 真机上
 * `{turns}` 永远匹配不上 `{val:{turns}}`，`outline` 恒为 []，poll 恒 running，
 * 120 s 打满判 empty-reply，会话里明明写着 response='收到' 也发不出去。
 * 这里改成剥包装 + 读字段两步，包装层有几个、按什么顺序出现都不再需要预先列举。
 */
const PROJECTION_WRAPPERS = ['val', 'currentValue'];

/** @returns {*} 剥掉所有已知包装层后的值；认不出来的形状原样返回，由调用方按语义判空 */
export function unwrapProjection(row) {
  let value = row;
  // 上限只为防自引用/病态嵌套，不表达「已知深度」
  for (let depth = 0; depth < 8; depth += 1) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) break;
    const key = PROJECTION_WRAPPERS.find((candidate) => candidate in value);
    if (key === undefined) break;
    value = value[key];
  }
  return value;
}

/**
 * turnOutline 的轮次数组。认清：裸数组 / `{turns}` / `{val:{turns}}` / `{currentValue:{turns}}` /
 * `{val:[...]}` / `{currentValue:[...]}`。认不出来的形状仍然当「没有这一轮」
 * （保持原有 running 语义，不猜）。
 */
export function turnOutlineTurns(row) {
  const value = unwrapProjection(row);
  if (Array.isArray(value)) return value;
  if (Array.isArray(value?.turns)) return value.turns;
  return [];
}

/** permissions 投影：剥包装后读 preset，读不到退 sandbox；都没有 → '' （调用方据此如实降级） */
export function permissionOf(row) {
  const value = unwrapProjection(row);
  if (typeof value === 'string') return value;
  if (typeof value?.preset === 'string' && value.preset !== 'custom') return value.preset;
  if (typeof value?.sandbox === 'string') return value.sandbox;
  return '';
}

/**
 * DSH 里 cwd 与权限都是会话自己的事实（cwd 进 session header，权限是 permissions 投影）。
 * 这里只读 list 里的投影做**核对**，据此如实回报，不猜。
 * @returns {{workingDirectory:string, permission:string}|null} null = 读不到
 */
async function sessionState(controller, sessionId) {
  if (typeof controller?.list !== 'function') return null;
  try {
    const listed = await controller.list({}, new AbortController().signal);
    const item = (listed?.items || []).find((entry) => entry?.sessionId === sessionId);
    if (!item) return null;
    const values = item.projections?.values ?? {};
    // 三个投影行都是 { ver, seq, val }（见 unwrapProjection）：workingDirectory 的真值在 .val 里，
    // 直接读 values.workingDirectory 只会拿到对象 → '' → cwd 核对永远不通过、会话永不复用
    const cwd = unwrapProjection(values.workingDirectory);
    return {
      workingDirectory: typeof cwd === 'string' ? cwd : '',
      // permissions 投影的线 view 形状见 permissionOf
      permission: permissionOf(values.permissions),
    };
  } catch {
    return null;
  }
}

/**
 * @param controller sessionController（create/prompt/list）
 * @param {object} options
 *   workspace / agentPreset —— 既有配置
 *   permissionPresets —— host 侧 dsh-permission-presets 服务（取自 lib/index.js 的
 *     ctx.get('permissionPresets')）；缺席（NAS 远程 RPC、composition 没挂）时传 null/undefined，
 *     行为与本改动之前逐字一致
 *   sessions —— host 侧会话表（ctx.get('sessions')），用来按 sessionId 拿**活会话对象**：
 *     permissionPresets.set/current 收的都是会话对象，不是 id
 *   sandboxPolicy —— host 侧 sandbox 策略（ctx.get('sandboxPolicy')），用来读回真实生效档
 */
export function createCtxRunner(controller, { workspace, agentPreset, permissionPresets, sessions, sandboxPolicy, now = Date.now } = {}) {
  debug('createCtxRunner controller=' + typeof controller + ' create=' + typeof controller?.create + ' prompt=' + typeof controller?.prompt + ' list=' + typeof controller?.list
    + ' permissionPresets=' + typeof permissionPresets + ' sessions=' + typeof sessions + ' sandboxPolicy=' + typeof sandboxPolicy);
  if (!controller || typeof controller.create !== 'function' || typeof controller.prompt !== 'function') {
    throw new TypeError('ctx runner needs sessionController.create/prompt/list');
  }

  /**
   * 空答复的宽限窗（与 lib/runner-dsh.mjs 同值同口径）：会话 running 翻成 false 的那一刻，
   * 最后一条助手消息可能还差一次投影写入才出现在 turnOutline 里（写序抖动）。所以
   * 「停下 + 没正文」先当一个**观察**，窗内继续回 running 让调用方接着轮询，窗外才是真失败。
   * 450ms = 3 × 150ms（服务端 ANSWER_POLL_INTERVAL_MS 的轮询节奏）。
   */
  const EMPTY_REPLY_GRACE_MS = 450;
  /** sessionId → 第一次看到「已停下但正文为空」的时刻；真答复或重新提问都会清掉它 */
  const emptyReplySince = new Map();

  /**
   * 答复契约（与 lib/runner-dsh.mjs 的同名常量逐字一致）：poll 读回来的是本会话
   * **最后一条助手消息的正文**，而对端模型并不知道这件事 —— 它很容易用一句
   * 「好的，我这就去做」收尾，那句话于是成了答复（甚至是空答复）。所以每一轮都把
   * 契约作为**第二个文本块**附在提问后面：提问正文一个字都不改，契约在问句之后。
   * 两个 runner 各自持有这份常量：它们互不 import（见文件头的注释），同步改动靠这条说明。
   */
  const ANSWER_CONTRACT = [
    '【对端提问 · 答复契约】你最后一条消息的正文会原样返回给提问方，作为这次提问的答复。',
    '结果、结论、改动清单都写在这条消息里，不要以提问或「我这就去做」收尾。',
    '如果需要中途澄清，也请在这条消息里给出你已完成的判断与当前可用结论。',
  ].join('\n');

  /** 往一个已有会话里发一轮（新建与续聊共用；续聊失败时调用方回退新建） */
  async function promptSession(sessionId, prompt) {
    // 重新提问 = 新的等待起点：清掉这个会话上残留的空答复计时，新的一轮自己重新计时
    emptyReplySince.delete(sessionId);
    // The RPC layer always supplies an AbortSignal; the service dereferences it,
    // so a direct in-process call must pass one too.
    await controller.prompt({
      requestId: `lan-peers-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`,
      sessionId,
      mode: 'queue',
      clientTimeZone: 'Asia/Shanghai',
      content: [
        { type: 'text', text: String(prompt) },
        { type: 'text', text: ANSWER_CONTRACT },
      ],
    }, new AbortController().signal);
  }

  /**
   * 会话还在不在：能读 list 就先问一次（省掉一次注定失败的 prompt）；
   * 读不出来（或没有 list）时返回 true，把判断交给 prompt 自己的报错。
   */
  async function sessionKnown(sessionId) {
    if (typeof controller.list !== 'function') return true;
    try {
      const listed = await controller.list({}, new AbortController().signal);
      const items = Array.isArray(listed?.items) ? listed.items : null;
      if (!items) return true;
      return items.some((entry) => entry?.sessionId === sessionId);
    } catch {
      return true;
    }
  }

  /** 按 sessionId 拿本进程里的活会话对象；拿不到返回 null（不是会话不存在） */
  function liveSession(sessionId) {
    if (!sessions || typeof sessions.get !== 'function') return null;
    try {
      return sessions.get(sessionId) ?? null;
    } catch {
      return null;
    }
  }

  /** 请求值是不是这套 composition 里真的配了的预设名（names 是公开 getter，缺失才退回 resolve 试探） */
  function knownPreset(name) {
    if (typeof permissionPresets?.set !== 'function') return false;
    try {
      if (Array.isArray(permissionPresets.names)) return permissionPresets.names.includes(name);
      if (typeof permissionPresets.resolve === 'function') {
        permissionPresets.resolve(name);
        return true;
      }
    } catch {}
    return false;
  }

  /**
   * 写入口。能当预设名走 permissionPresets.set（本包唯一倡导的写路径）；
   * 部署没配这个预设名、但它是三档之一时（出厂预设表只有 workspace-write /
   * danger-full-access，**没有 read-only**），退化为直接追加两条 canonical 事件：
   * 与 dsh-sandbox-policy 的 setSandboxMode / dsh-user-approval 的 setApprovalPolicy
   * 写的是同一对（sandbox/mode + approval/policy）日志事件，逐字一致。
   * 本插件 import 不到那两个包（DSH 的 node_modules 在 app.asar 里），所以照抄它们的
   * 事件形状而不是调用函数 —— 语义相同，来源可查。
   * @returns {string} 'preset' | 'tier' | ''（请求值既不是预设也不是档位）
   */
  function writePermission(session, requested) {
    if (knownPreset(requested)) {
      permissionPresets.set(session, requested);
      return 'preset';
    }
    if (permissionRank(requested) < 0) return '';
    if (typeof session?.append !== 'function') throw new TypeError('session has no append');
    session.append('sandbox/mode', { mode: requested });
    const policy = TIER_APPROVAL[requested];
    if (policy !== undefined) session.append('approval/policy', { policy });
    return 'tier';
  }

  /**
   * 读回真实生效值，两个独立事实各读各的：
   *   preset —— permissions 投影的派生值（= 客户端看到的 currentValue，'custom' = 不匹配任何预设）
   *   sandbox —— sandbox 策略按会话折叠出的**执行档位**（default 兜底已算进去）
   * @returns {{preset:string, sandbox:string}}
   */
  function readPermission(session) {
    const read = { preset: '', sandbox: '' };
    try {
      const preset = permissionPresets.current(session);
      if (typeof preset === 'string') read.preset = preset;
    } catch {}
    try {
      const mode = sandboxPolicy.resolve({ session })?.mode;
      if (typeof mode === 'string') read.sandbox = mode;
    } catch {}
    if (read.sandbox === '') {
      // resolve 会校验会话 cwd 是绝对路径；cwd 不合法时退到「最后一条 sandbox/mode 事件」，
      // 它正是我刚写进去的那一条，不依赖 policy 的默认档兜底
      try {
        const mode = sandboxPolicy.overrideOf?.(session);
        if (typeof mode === 'string') read.sandbox = mode;
      } catch {}
    }
    if (read.sandbox === '' && read.preset !== '' && read.preset !== 'custom') {
      // 没有 sandboxPolicy 时退一步：预设自己的 bundle 就是它要写的档位
      try {
        const spec = permissionPresets.resolve(read.preset);
        if (typeof spec?.sandbox === 'string') read.sandbox = spec.sandbox;
      } catch {}
    }
    return read;
  }

  /**
   * 权限：DSH 的会话级权限不是 session create 的字段，它是会话事件
   * （permission/preset + sandbox/mode + approval/policy）折叠出来的 permissions 投影。
   * 注入了 permissionPresets 时本 runner 才有写入口，于是先写、再读回、再跑这一轮：
   * 顺序不能倒 —— 这一轮的执行档位由会话当前状态决定，先跑再改等于用错的档位跑了一轮。
   *
   * 铁律：honored 只有在读回的生效值**真的等于**请求值时才为 true；写失败/读不回一律
   * false 并把稳定的 reason 回给上层（reason 里永远没有 path）。
   * @returns {object} 权限三键（不点名时是空对象，返回形状一个键都不多）
   */
  async function scopePermission(sessionId, requested) {
    if (requested === '') return {};

    const session = liveSession(sessionId);
    if (!permissionPresets || !session) {
      // 注入缺席（NAS 的远程 RPC / 服务没挂）或会话不在本进程：维持改动前的诚实降级，
      // 只按 session/list 的投影核对，一个写操作都不做。
      const state = await sessionState(controller, sessionId);
      const applied = state?.permission ?? '';
      const honored = applied !== '' && applied === requested;
      const reason = applied === ''
        ? 'session-permission-unreadable'
        : honored ? 'matched-effective' : 'session-permission-unsupported';
      debug('permission requested=' + requested + ' applied=' + (applied || 'unknown') + ' honored=' + honored + ' reason=' + reason + ' via=none');
      return { appliedPermission: applied, permissionHonored: honored, permissionReason: reason };
    }

    let via = '';
    let failure = '';
    try {
      via = writePermission(session, requested);
    } catch {
      failure = 'permission-set-failed';
    }
    if (via === '' && failure === '') failure = 'unknown-permission';

    const read = readPermission(session);
    const preset = read.preset === 'custom' ? '' : read.preset;
    const honored = (preset !== '' && preset === requested) || (read.sandbox !== '' && read.sandbox === requested);
    const applied = honored ? requested : (preset || read.sandbox);
    const reason = honored
      ? 'matched-effective'
      : (failure || (preset === '' && read.sandbox === '' ? 'session-permission-unreadable' : 'session-permission-unsupported'));
    debug('permission requested=' + requested + ' applied=' + (applied || 'unknown') + ' honored=' + honored
      + ' reason=' + reason + ' via=' + (via || '-'));

    if (!honored && permissionRank(requested) >= 0 && permissionRank(read.sandbox) > permissionRank(requested)) {
      // 能证明生效档比请求档更宽：宁可这一单失败，也不许用更高的档位跑
      debug('permission abort session=' + shortId(sessionId) + ' effective=' + read.sandbox);
      throw broaderThanRequested(requested, read.sandbox);
    }

    return { appliedPermission: applied, permissionHonored: honored, permissionReason: reason };
  }

  return {
    /**
     * 契约 §1：给了 sessionId 就在既有 DSH 会话上继续，否则新建；
     * 会话失效（被删/过期）则回退新建并标 reused:false。
     * 契约 §2：点名 workspace/permission 时按点名的那一组执行；都不点名时形状与行为逐字不变。
     *
     * 返回形状与 lib/runner-dsh.mjs 对齐：带 options 时 { sessionId, reused }，
     * 不带 options 时仍返回裸 sessionId —— 这是本 runner 既有的对外形状，不为了新接口改掉它。
     * 只有点名 permission 时才会多出 appliedPermission / permissionHonored / permissionReason 三个键
     * （permissionReason 是本版新增的诚实诊断码，host 侧的 normalizeRunnerAnswer 认它）。
     */
    async ask(prompt, options = undefined) {
      const statedWorkspace = resolveWorkspace(options?.workspace);
      const statedPermission = resolvePermission(options?.permission);
      const wanted = typeof options?.sessionId === 'string' ? options.sessionId.trim() : '';

      // 复用前必须核对旧会话的两件事，核对不了就不假装续聊：
      //   1. cwd —— 点名为工作区时；
      //   2. 权限档 —— 权限是会话事件折出来的投影，读回会话真实的那一档再比对；
      //      读不到也算不可复用（跨档复用就是跨权限复用，宁可新建）。
      let reuseAllowed = wanted !== '';
      // 空串 = 没点名权限（resolvePermission 的既有口径），此时不做档位比对
      const permissionStated = statedPermission !== '' && statedPermission !== undefined;
      if (reuseAllowed && (statedWorkspace !== undefined || permissionStated)) {
        const state = await sessionState(controller, wanted);
        reuseAllowed = Boolean(state)
          && (statedWorkspace === undefined || sameDir(state.workingDirectory, statedWorkspace))
          && (!permissionStated || state.permission === statedPermission);
        debug('ask reuse-cwd session=' + shortId(wanted) + ' match=' + reuseAllowed);
      }

      if (reuseAllowed && (statedWorkspace !== undefined || (await sessionKnown(wanted)))) {
        // 权限先落到这个会话上，再打这一轮（闸门拒绝会在这里抛出，不落进 fallback=create）
        const scoped = await scopePermission(wanted, statedPermission);
        try {
          await promptSession(wanted, prompt);
          debug('ask reuse session=' + shortId(wanted) + ' reused=true');
          return { sessionId: wanted, reused: true, ...scoped };
        } catch (error) {
          if (error?.code === 'permission-above-request') throw error;
          // 列得出来但打不进去（刚被删/被占）：不猜原因，回退新建
          debug('ask reuse failed session=' + shortId(wanted) + ' fallback=create');
        }
      } else if (wanted !== '') {
        debug('ask reuse miss session=' + shortId(wanted) + ' fallback=create');
      }

      // 不给 workspace 时 cwd 仍是 config.workspace —— 与以前一字不差
      const created = await controller.create({
        cwd: statedWorkspace ?? workspace,
        ...(agentPreset ? { agentPreset } : {}),
      });
      const sessionId = created?.sessionId;
      // 只记会话 id：create 的响应形状归 DSH 所有，整体打印可能把 cwd 带进日志
      debug('create session=' + shortId(sessionId) + ' workspaceNamed=' + (statedWorkspace !== undefined));
      if (!sessionId) throw new Error('sessionController.create returned no sessionId');
      const scoped = await scopePermission(sessionId, statedPermission);
      await promptSession(sessionId, prompt);
      if (options === undefined) return sessionId;
      return { sessionId, reused: false, ...scoped };
    },

    async poll(sessionId) {
      const listed = await controller.list({}, new AbortController().signal);
      debug('poll ' + sessionId + ' items=' + (listed?.items?.length ?? 'none'));
      const item = (listed?.items || []).find((entry) => entry.sessionId === sessionId);
      if (!item) return { status: 'error', error: 'session-not-found' };
      if (item.running) return { status: 'running' };
      const outline = turnOutlineTurns(item.projections?.values?.turnOutline);
      const last = outline[outline.length - 1];
      if (!last) return { status: 'running' };
      const reply = typeof last.response === 'string' ? last.response : '';
      if (reply.trim() !== '') {
        // 真答复到了：清掉宽限记录，否则同一会话的下一次提问会继承旧计时
        emptyReplySince.delete(sessionId);
        return { status: 'done', reply };
      }
      // 空答复先给宽限窗（见 EMPTY_REPLY_GRACE_MS）：窗内仍算 running，窗外才判「跑完没答案」。
      const seenAt = emptyReplySince.get(sessionId);
      const observedAt = typeof seenAt === 'number' ? seenAt : now();
      if (typeof seenAt !== 'number') emptyReplySince.set(sessionId, observedAt);
      if (now() - observedAt < EMPTY_REPLY_GRACE_MS) return { status: 'running' };
      return { status: 'error', error: 'empty-reply', sessionId };
    },
  };
}
