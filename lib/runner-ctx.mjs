// dsh-lan-peers · in-process runner.
//
// Uses the harness services directly (ctx.sessionController) instead of the
// local HTTP API, so inbound peer asks need no web token at all. This is the
// only runner that works inside the Electron app, which exposes no token.
import fs from 'node:fs';

const DEBUG = process.env.LAN_PEERS_DEBUG || 'D:/DS-Harness/.tmp/lan-peers-debug.log';
function debug(line) {
  try { fs.appendFileSync(DEBUG, new Date().toISOString() + ' ' + line + '\n'); } catch {}
}

export function createCtxRunner(controller, { workspace, agentPreset } = {}) {
  debug('createCtxRunner controller=' + typeof controller + ' create=' + typeof controller?.create + ' prompt=' + typeof controller?.prompt + ' list=' + typeof controller?.list);
  if (!controller || typeof controller.create !== 'function' || typeof controller.prompt !== 'function') {
    throw new TypeError('ctx runner needs sessionController.create/prompt/list');
  }

  return {
    async ask(prompt) {
      debug('ask start');
      const created = await controller.create({
        cwd: workspace,
        ...(agentPreset ? { agentPreset } : {}),
      });
      const sessionId = created?.sessionId;
      debug('create -> ' + JSON.stringify(created).slice(0, 200));
      if (!sessionId) throw new Error('sessionController.create returned no sessionId');
      // The RPC layer always supplies an AbortSignal; the service dereferences it,
      // so a direct in-process call must pass one too.
      await controller.prompt({
        requestId: `lan-peers-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`,
        sessionId,
        mode: 'queue',
        clientTimeZone: 'Asia/Shanghai',
        content: [{ type: 'text', text: String(prompt) }],
      }, new AbortController().signal);
      return sessionId;
    },

    async poll(sessionId) {
      const listed = await controller.list({}, new AbortController().signal);
      debug('poll ' + sessionId + ' items=' + (listed?.items?.length ?? 'none'));
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
