// dsh-lan-peers · model-facing tools.
//
// `lan_peers` lists paired peers with a liveness probe; `lan_peer_ask` hands one
// prompt to a peer's agent and waits for its final reply. Both read the same
// peers.json the pairing CLI writes.
//
// Since v0.4.0 the wait is no longer a fixed 1.5s poll: a peer that advertises
// the "stream" capability answers over /v1/events (SSE, each event an encrypted
// envelope), and /v1/answer long-polling with waitMs is the fallback. A 0.3.1
// peer advertises neither, so it keeps exactly the old 1.5s cadence — decided by
// the unauthenticated capability probe before the ask is sent.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  DEFAULT_ANSWER_WAIT_MS,
  MAX_ANSWER_WAIT_MS,
  awaitPeerAnswer,
  callPeer,
  capabilityOf,
  probePeer,
} from '../client/peer-call.mjs';
import { createGroupMirror } from './group-client.mjs';
import { loadDshTools } from './dsh-tools.mjs';

const { defineTool } = await loadDshTools();

const text = (value) => [{ type: 'text', text: value }];

function stateDirOf(config) {
  return path.resolve(config?.stateDir || path.join(os.homedir(), '.dsh', 'lan-peers'));
}

function readPeers(config) {
  try {
    const raw = JSON.parse(fs.readFileSync(path.join(stateDirOf(config), 'peers.json'), 'utf8'));
    return Object.entries(raw.peers || {}).map(([peerId, peer]) => ({ peerId, ...peer }));
  } catch {
    return [];
  }
}

function readSelf(config) {
  try {
    const raw = JSON.parse(fs.readFileSync(path.join(stateDirOf(config), 'state.json'), 'utf8'));
    return { instanceId: raw.instanceId, name: raw.name };
  } catch {
    return { instanceId: null, name: config?.name || os.hostname() };
  }
}

async function signedCall({ baseUrl, secret, senderId, method, apiPath, body, timeoutMs = 30_000 }) {
  return callPeer({ baseUrl, secret, senderId, method, apiPath, body, timeoutMs });
}

function resolvePeer(config, wanted) {
  const peers = readPeers(config);
  return peers.find((peer) => peer.peerId === wanted || peer.name === wanted) || null;
}

/** configured hold per /v1/answer request; default 25s, hard cap 25s. */
export function answerWaitMsOf(config) {
  const raw = Number(config?.answerWaitMs);
  if (!Number.isFinite(raw) || raw <= 0) return DEFAULT_ANSWER_WAIT_MS;
  return Math.min(Math.max(1000, Math.round(raw)), MAX_ANSWER_WAIT_MS);
}

export function createLanPeerTools(config = {}, deps = {}) {
  const feed = deps.feed ?? null;
  const log = typeof deps.log === 'function' ? deps.log : null;
  const tools = [];

  tools.push(
    defineTool({
      name: 'lan_peers',
      description:
        'List the DSH peers paired on this LAN (name, id, online state). Use before lan_peer_ask to see who is reachable. Probing is local and costs nothing.',
      parameters: {},
      output: {
        schema: {
          type: 'object',
          additionalProperties: true,
          properties: { text: { type: 'string' } },
        },
        render: (_args, value) => text(value.text),
      },
      async execute() {
        const peers = readPeers(config);
        const rows = [];
        for (const peer of peers) {
          let online = false;
          try {
            const res = await fetch(String(peer.baseUrl).replace(/\/$/, '') + '/v1/health', {
              signal: AbortSignal.timeout(2000),
            });
            online = res.ok;
          } catch {
            online = false;
          }
          rows.push({ name: peer.name, peerId: peer.peerId, baseUrl: peer.baseUrl, online });
        }
        const summary =
          rows.length === 0
            ? 'No peers paired yet.'
            : rows.map((r) => r.name + '\t' + r.peerId + '\t' + (r.online ? r.online : 'offline')).join('\n');
        return { peers: rows, text: summary };
      },
    }),
  );

  tools.push(
    defineTool({
      name: 'lan_peer_ask',
      description:
        'Ask another paired DSH agent on the LAN to do something and return its final reply. The peer runs in its own workspace with its own permissions and spends its own model quota; it may refuse. Use it for work that belongs on the other machine (different files, different tools, different network position).',
      parameters: {
        peer: { type: 'string', required: true, description: 'Peer name or peerId from lan_peers.' },
        prompt: { type: 'string', required: true, description: 'The task or question to send.' },
        timeout_sec: {
          type: 'number',
          description: 'How long to wait for the reply. Default 300, maximum 900.',
        },
      },
      output: {
        schema: {
          type: 'object',
          additionalProperties: true,
          properties: { text: { type: 'string' } },
        },
        render: (_args, value) => text(value.text),
      },
      async execute(args) {
        const peer = resolvePeer(config, args.peer);
        if (!peer) throw new Error('unknown peer: ' + args.peer);
        const self = readSelf(config);
        if (!self.instanceId) throw new Error('local peer identity is missing (state.json)');

        const timeoutSec = Math.min(Number(args.timeout_sec) || 300, 900);
        // §6 进度镜像：group.enabled 且配了 hub 时，向群里投「开始 / 结束」两条。
        // 绝不发 prompt 原文与回复全文（只发长度）；投递失败只记日志。
        const mirror = createGroupMirror({
          config,
          peers: readPeers(config),
          self,
          log: log ?? (() => {}),
        });
        const accepted = await signedCall({
          baseUrl: peer.baseUrl,
          secret: peer.secret,
          senderId: self.instanceId,
          method: 'POST',
          apiPath: '/v1/ask',
          body: {
            requestId: 'lan-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8),
            prompt: args.prompt,
            timeoutSec,
          },
        });
        const sessionId = accepted?.sessionId;
        // 派单已被接受（sessionId 有了）才投「开始」：meta 里要带真实 sessionId。
        // 不 await —— 群投递绝不拖慢 1:1 派单；失败只记日志。
        const mirrorStarted = mirror.enabled
          ? mirror.start({ peer: peer.name, sessionId })
          : Promise.resolve({ ok: false, reason: 'group-mirror-not-configured' });

        const health = await probePeer({ baseUrl: peer.baseUrl, timeoutMs: 2000 });
        const streamCapable = capabilityOf(health).includes('stream');
        // No "stream" capability means a 0.3.1 host: it ignores waitMs and answers
        // immediately, so ask for the old 1.5s cadence instead of hammering it.
        const mode = streamCapable ? 'auto' : 'legacy';
        const job = feed?.begin?.({
          peer: peer.name,
          peerId: peer.peerId,
          sessionId,
          transport: streamCapable ? 'sse' : 'legacy-poll',
          timeoutSec,
        });

        const settled = await awaitPeerAnswer({
          baseUrl: peer.baseUrl,
          secret: peer.secret,
          senderId: self.instanceId,
          sessionId,
          timeoutMs: timeoutSec * 1000,
          waitMs: answerWaitMsOf(config),
          mode,
          onProgress: (info) =>
            feed?.update?.(job, { status: 'running', transport: info.transport, elapsedMs: info.elapsedMs }),
        });
        feed?.finish?.(job, {
          status: settled.status,
          transport: settled.transport,
          elapsedMs: settled.elapsedMs,
          error: settled.error ?? null,
          replyChars: settled.reply ? settled.reply.length : 0,
        });

        // 先等「开始」落地再发「结束」：群里两条的先后顺序是契约的一部分
        await mirrorStarted.catch(() => {});
        await mirror
          .finish({
            peer: peer.name,
            sessionId,
            status: settled.status,
            transport: settled.transport,
            elapsedMs: settled.elapsedMs,
            replyChars: settled.reply ? settled.reply.length : 0,
          })
          .catch(() => {});

        if (settled.status === 'done') {
          return { peer: peer.name, sessionId, status: 'done', reply: settled.reply, text: settled.reply };
        }
        if (settled.status === 'error') {
          return {
            peer: peer.name,
            sessionId,
            status: 'error',
            reply: '',
            text: 'peer error: ' + settled.error,
          };
        }
        return {
          peer: peer.name,
          sessionId,
          status: 'timeout',
          reply: '',
          text: 'timeout after ' + timeoutSec + 's; the peer may still be working',
        };
      },
    }),
  );

  return tools;
}
