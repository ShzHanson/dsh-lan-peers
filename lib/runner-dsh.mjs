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

  /** 往一个已有会话里发一轮（新建与续聊共用；续聊失败时调用方回退新建） */
  async function promptSession(sessionId, prompt) {
    await rpc('session/prompt', {
      request: {
        requestId: `lan-peers-${now()}-${Math.random().toString(36).slice(2, 10)}`,
        sessionId,
        mode: 'queue',
        clientTimeZone: 'Asia/Shanghai',
        content: [{ type: 'text', text: String(prompt) }],
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

      // 点名为工作区时，续聊前必须核对旧会话的 cwd —— 核对不了就不假装续聊。
      let reuseAllowed = wanted !== '';
      if (reuseAllowed && statedWorkspace !== undefined) {
        const state = await sessionState(wanted);
        reuseAllowed = Boolean(state) && sameDir(state.workingDirectory, statedWorkspace);
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
      if (!reply) return { status: 'running' };
      return { status: 'done', reply };
    },
  };
}
