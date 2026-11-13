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
import { loadDshTools } from './dsh-tools.mjs';

const text = (value) => [{ type: 'text', text: value }];

/**
 * defineTool 的解析推迟到「真的造工具」那一刻：装配失败仍然是同一处日志
 * （lib/index.js 的 try/catch），但本模块可以在没有 DSH 运行时的环境（单测）里被 import。
 * deps.defineTool 只为测试注入，生产走 loadDshTools()。
 */
async function resolveDefineTool(deps) {
  if (typeof deps?.defineTool === 'function') return deps.defineTool;
  const { defineTool } = await loadDshTools();
  return defineTool;
}

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


export async function createLanPeerTools(config = {}, deps = {}) {
  const defineTool = await resolveDefineTool(deps);
  const feed = deps.feed ?? null;
  const log = typeof deps.log === 'function' ? deps.log : null;
  // v0.8.5-α（契约 §3）：发送侧整块由 host 注入（server.files.send）——
  // 分块、逐块加密与 resumeFrom 只有一份实现，工具不重造一遍。
  const sendFile = typeof deps.sendFile === 'function' ? deps.sendFile : null;
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
        'Ask another paired DSH agent on the LAN to do something and return its final reply. The reply is the peer\'s final message, returned verbatim — nothing is pushed back before it finishes, so its answer has to live in that message; an `empty-reply` error means the peer finished without producing one. The peer runs in its own workspace with its own permissions and spends its own model quota; it may refuse. Use it for work that belongs on the other machine (different files, different tools, different network position).',
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
        // 0.10.0-α：§6 进度镜像（往群里投 progress/result 两条）随群内派单一起移除 ——
        // 这两种 kind 已不在 GROUP_KINDS 白名单里，再投只会拿到 400。1:1 派单本身不变。
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

  tools.push(
    defineTool({
      name: 'lan_peer_send_file',
      description:
        'Offer one local file to a paired peer. Only metadata (name/size/sha256) travels: the bytes stay in this host outbox as a pending download, and the peer pulls them when a human there clicks download (sha256 is verified on the receiving side, so a corrupted pull lands nothing). Returns fileId/bytes/sha256/offer — the file has NOT been transferred yet, and there is no way to choose the remote path.',
      parameters: {
        peer: { type: 'string', required: true, description: 'Peer name or peerId from lan_peers.' },
        path: { type: 'string', required: true, description: 'Local file path to send.' },
      },
      output: {
        schema: {
          type: 'object',
          additionalProperties: true,
          properties: {
            text: { type: 'string' },
            ok: { type: 'boolean' },
            fileId: { type: 'string' },
            bytes: { type: 'number' },
            sha256: { type: 'string' },
            offer: { type: 'string' },
            ms: { type: 'number' },
          },
        },
        render: (_args, value) => text(value.text),
      },
      async execute(args) {
        if (!sendFile) throw new Error('file transfer unavailable on this host (no files service)');
        const peer = resolvePeer(config, args.peer);
        if (!peer) throw new Error('unknown peer: ' + args.peer);
        const target = String(args.path ?? '').trim();
        if (target === '') throw new Error('path is required');
        const started = Date.now();
        let out;
        try {
          out = await sendFile({ peerId: peer.peerId, path: target });
        } catch (error) {
          log?.('[tool] send-file peer=' + String(peer.peerId).slice(0, 8)
            + ' state=error reason=' + String(error?.message ?? error).slice(0, 48));
          throw error;
        }
        const ok = out?.ok === true;
        // 0.12.0-α S1：不再有「已发送」这件事 —— 这里拿到的是 fileId（对方那边的一条待下载）。
        const fileId = String(out?.fileId ?? '');
        const bytes = Number(out?.bytes) || 0;
        const sha256 = String(out?.sha256 ?? '');
        const ms = Number.isFinite(Number(out?.ms)) ? Number(out.ms) : Date.now() - started;
        // 日志口径（契约 §0）：size / sha256 前 8 位 / 状态 —— 不带文件名与内容。
        log?.('[tool] send-file peer=' + String(peer.peerId).slice(0, 8) + ' file=' + fileId.slice(0, 8)
          + ' bytes=' + bytes + ' sha=' + sha256.slice(0, 8) + ' state=' + (ok ? 'offered' : 'rejected') + ' ms=' + ms);
        if (!ok) {
          const reason = String(out?.reason ?? 'send-failed');
          return {
            ok: false,
            fileId,
            bytes,
            sha256,
            offer: 'failed',
            ms,
            reason,
            text: 'offer failed (' + reason + ')',
          };
        }
        return {
          ok: true,
          fileId,
          bytes,
          sha256,
          offer: 'sent',
          ms,
          text: 'offered to ' + peer.name + ': fileId=' + fileId + ' bytes=' + bytes
            + ' sha256=' + sha256.slice(0, 8)
            + ' — the bytes stay here until that peer downloads it',
        };
      },
    }),
  );

  return tools;
}
