// dsh-lan-peers · real DSH runner.
//
// Turns an inbound peer prompt into a real DSH session in the configured
// workspace and reads the assistant reply back from the session projection.
// Talks to the local DSH over its loopback HTTP API (the same JSON-RPC the web
// UI uses), authenticating with the per-start session token.
import fs from 'node:fs';
import path from 'node:path';

const REQUEST_TIMEOUT_MS = 20_000;

/**
 * 铁律：workspace 只认**已存在的绝对目录**。不合法就抛错让上层回 runner-error，
 * 绝不静默回退到默认工作区 —— 否则界面里的「选择工作区」就是谎话。
 * 校验必须做在 RPC 之前：DSH 的 session/create 会 mkdir -p 掉不存在的 cwd，
 * 交给它去「校验」等于把打错的路径变成一个新建的空目录。
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

/** 两个目录是不是同一个（Windows 大小写不敏感） */
function sameDir(left, right) {
  if (typeof left !== 'string' || left === '' || typeof right !== 'string' || right === '') return false;
  const a = path.resolve(left);
  const b = path.resolve(right);
  return process.platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b;
}

export function createDshRunner({
  baseUrl = 'http://127.0.0.1:3080',
  tokenFile = '/run/dsh-web.token',
  workspace,
  agentPreset,
  now = Date.now,
  // 权限未生效时的 reason 只进日志，不进对端可见的数据
  log = () => {},
  // 测试注入点：真机一律用全局 fetch（本文件不依赖其它网络栈）
  fetchImpl = fetch,
} = {}) {
  let cookie = null;
  const base = String(baseUrl).replace(/\/$/, '');

  /**
   * 空答复的宽限窗：会话 running 翻成 false 的那一刻，最后一条助手消息可能还差一次
   * 投影写入才出现在 turnOutline 里（写序抖动）。所以「停下 + 没正文」先当一个**观察**，
   * 窗口内继续回 running 让调用方接着轮询，窗口过了才是真的「跑完没答案」。
   * 450ms = 3 × ANSWER_POLL_INTERVAL_MS（服务端 150ms 的轮询节奏）：足够吸掉一次写序抖动，
   * 又不至于把一次真的空答复拖成超时。
   */
  const EMPTY_REPLY_GRACE_MS = 450;
  /** sessionId → 第一次看到「已停下但正文为空」的时刻；真答复或重新提问都会清掉它 */
  const emptyReplySince = new Map();

  function readToken() {
    try {
      const value = fs.readFileSync(tokenFile, 'utf8').trim();
      return value || null;
    } catch {
      return null;
    }
  }

  async function mintCookie() {
    const token = readToken();
    if (!token) throw new Error(`no DSH session token in ${tokenFile}`);
    const res = await fetchImpl(`${base}/?token=${encodeURIComponent(token)}`, {
      redirect: 'manual',
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    const setCookie = res.headers.getSetCookie?.() ?? [];
    const raw = setCookie[0] || res.headers.get('set-cookie') || '';
    const value = raw.split(';')[0];
    if (!value) throw new Error(`token exchange returned no cookie (HTTP ${res.status})`);
    cookie = value;
    return cookie;
  }

  async function rpc(method, args) {
    if (!cookie) await mintCookie();
    const body = JSON.stringify({
      type: 'client-request',
      rpcId: `lan-peers-${now()}-${Math.random().toString(36).slice(2, 8)}`,
      method,
      payload: { args },
    });
    const send = async () => {
      const res = await fetchImpl(`${base}/api/${method}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: cookie },
        body,
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (res.status === 401) {
        cookie = null;
        await mintCookie();
        return fetchImpl(`${base}/api/${method}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Cookie: cookie },
          body,
          signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        });
      }
      return res;
    };
    const res = await send();
    const json = await res.json();
    if (!res.ok || json?.result?.ok === false) {
      const err = json?.result?.error;
      throw new Error(`DSH ${method} failed: ${err?.code || res.status} ${err?.message || ''}`.trim());
    }
    return json.result.value;
  }

  /**
   * 答复契约：poll 读回来的是本会话**最后一条助手消息的正文**（turnOutline 的
   * last.response，原样回传），而对端模型并不知道这件事 —— 它很容易用一句
   * 「好的，我这就去做」收尾，那句话于是成了答复（甚至是空答复）。所以每一轮都把
   * 契约作为**第二个文本块**附在提问后面：提问正文一个字都不改（对端原文照收），
   * 契约在问句之后，离生成最近。
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
    await rpc('session/prompt', {
      request: {
        requestId: `lan-peers-${now()}-${Math.random().toString(36).slice(2, 10)}`,
        sessionId,
        mode: 'queue',
        clientTimeZone: 'Asia/Shanghai',
        content: [
          { type: 'text', text: String(prompt) },
          { type: 'text', text: ANSWER_CONTRACT },
        ],
      },
    });
  }

  /**
   * DSH 里 cwd 进 session header、权限是 permissions 投影，两者都由会话自己持有；
   * 这里只读 session/list 做**核对**，据此如实回报，不猜。
   * @returns {{workingDirectory:string, permission:string}|null} null = 读不到
   */
  async function sessionState(sessionId) {
    try {
      const listed = await rpc('session/list', { _request: {} });
      const item = (listed?.items || []).find((entry) => entry?.sessionId === sessionId);
      if (!item) return null;
      const values = item.projections?.values ?? {};
      return {
        workingDirectory: typeof values.workingDirectory === 'string' ? values.workingDirectory : '',
        // permissions 投影的 wire view 形状是 { currentValue }
        permission: typeof values.permissions?.currentValue === 'string' ? values.permissions.currentValue : '',
      };
    } catch {
      return null;
    }
  }

  /**
   * 权限：session/create 没有权限字段（request 只有 cwd / workspaceId / agentPreset），
   * 会话级权限是会话事件 permission/preset + sandbox/mode + approval/policy 折叠出的投影。
   * 本 runner 只有 RPC，而写这条事件的只有 /permission 命令（会往对端会话里插一条命令
   * 运行记录）与 host 侧 permissionPresets.set（不是 Remote，RPC 到不了），
   * 所以**如实降级**：读回会话真实生效的权限值，honored 只在实际生效值等于请求值时为 true。
   */
  async function permissionReport(sessionId, requested) {
    if (requested === '') return {};
    const state = await sessionState(sessionId);
    const applied = state?.permission ?? '';
    const honored = applied !== '' && applied === requested;
    const reason = applied === ''
      ? 'session-permission-unreadable'
      : honored ? 'matched-effective' : 'session-permission-unsupported';
    log('permission requested=' + requested + ' applied=' + (applied || 'unknown') + ' honored=' + honored + ' reason=' + reason);
    return { appliedPermission: applied, permissionHonored: honored };
  }

  return {
    /**
     * 契约 §1：给了 sessionId 就在既有会话上继续，没给则新建。
     * 契约 §2：点名 workspace/permission 时按点名的那一组执行；都不点名时形状与行为逐字不变。
     *
     * 返回 { sessionId, reused } —— reused 为 false 表示「该会话已失效，回退新建」，
     * 调用方据此把本地记录的连续会话 id 换掉（私聊门面写回 dm 存储）。
     * 点名权限时再多 two keys：appliedPermission（真实生效值，读不到则 ''）与 permissionHonored。
     */
    async ask(prompt, options = {}) {
      const statedWorkspace = resolveWorkspace(options?.workspace);
      const statedPermission = resolvePermission(options?.permission);
      const wanted = typeof options?.sessionId === 'string' ? options.sessionId.trim() : '';

      // 复用前必须核对旧会话的两件事，核对不了就不假装续聊：
      //   1. cwd —— 点名为工作区时；
      //   2. 权限档 —— 权限不是 session/create 的字段（见上面 permissionReport 的注释），
      //     它折在会话事件里，所以「按这一档复用」必须先读回**会话真实的**那一档。
      //      读不到也算不可复用：跨档复用就是跨权限复用，宁可新建。
      let reuseAllowed = wanted !== '';
      // 空串 = 没点名权限（resolvePermission 的既有口径），此时不做档位比对
      const permissionStated = statedPermission !== '' && statedPermission !== undefined;
      if (reuseAllowed && (statedWorkspace !== undefined || permissionStated)) {
        const state = await sessionState(wanted);
        reuseAllowed = Boolean(state)
          && (statedWorkspace === undefined || sameDir(state.workingDirectory, statedWorkspace))
          && (!permissionStated || state.permission === statedPermission);
      }

      if (reuseAllowed) {
        try {
          await promptSession(wanted, prompt);
          return { sessionId: wanted, reused: true, ...(await permissionReport(wanted, statedPermission)) };
        } catch {
          // 会话被删/过期/不属于本机：不猜原因，一律回退新建（契约要求的行为）
        }
      }
      const created = await rpc('session/create', {
        // 不给 workspace 时 cwd 仍是 config.workspace —— 与以前一字不差
        request: { cwd: statedWorkspace ?? workspace, ...(agentPreset ? { agentPreset } : {}) },
      });
      const sessionId = created.sessionId;
      await promptSession(sessionId, prompt);
      return { sessionId, reused: false, ...(await permissionReport(sessionId, statedPermission)) };
    },

    async poll(sessionId) {
      const listed = await rpc('session/list', { _request: {} });
      const item = (listed?.items || []).find((entry) => entry.sessionId === sessionId);
      if (!item) return { status: 'error', error: 'session-not-found' };
      if (item.running) return { status: 'running' };
      const outline = item.projections?.values?.turnOutline || [];
      const last = outline[outline.length - 1];
      if (!last) return { status: 'running' };
      const reply = typeof last.response === 'string' ? last.response : '';
      if (reply.trim() !== '') {
        // 真答复到了：清掉宽限记录，否则同一会话的下一次提问会继承旧计时
        emptyReplySince.delete(sessionId);
        return { status: 'done', reply };
      }
      // 会话停下、正文为空：先给一个宽限窗（见 EMPTY_REPLY_GRACE_MS），窗内仍算 running。
      // 窗外仍为空才是「跑完了没答案」——显式失败，调用方才能把它和「还在跑」分开。
      const seenAt = emptyReplySince.get(sessionId);
      const observedAt = typeof seenAt === 'number' ? seenAt : now();
      if (typeof seenAt !== 'number') emptyReplySince.set(sessionId, observedAt);
      if (now() - observedAt < EMPTY_REPLY_GRACE_MS) return { status: 'running' };
      return { status: 'error', error: 'empty-reply', sessionId };
    },
  };
}
