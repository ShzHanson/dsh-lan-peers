// dsh-lan-peers · real DSH runner.
//
// Turns an inbound peer prompt into a real DSH session in the configured
// workspace and reads the assistant reply back from the session projection.
// Talks to the local DSH over its loopback HTTP API (the same JSON-RPC the web
// UI uses), authenticating with the per-start session token.
import fs from 'node:fs';

const REQUEST_TIMEOUT_MS = 20_000;

export function createDshRunner({
  baseUrl = 'http://127.0.0.1:3080',
  tokenFile = '/run/dsh-web.token',
  workspace,
  agentPreset,
  now = Date.now,
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
    const res = await fetch(`${base}/?token=${encodeURIComponent(token)}`, {
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
      const res = await fetch(`${base}/api/${method}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: cookie },
        body,
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (res.status === 401) {
        cookie = null;
        await mintCookie();
        return fetch(`${base}/api/${method}`, {
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

  return {
    async ask(prompt) {
      const created = await rpc('session/create', {
        request: { cwd: workspace, ...(agentPreset ? { agentPreset } : {}) },
      });
      const sessionId = created.sessionId;
      await rpc('session/prompt', {
        request: {
          requestId: `lan-peers-${now()}-${Math.random().toString(36).slice(2, 10)}`,
          sessionId,
          mode: 'queue',
          clientTimeZone: 'Asia/Shanghai',
          content: [{ type: 'text', text: String(prompt) }],
        },
      });
      return sessionId;
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
