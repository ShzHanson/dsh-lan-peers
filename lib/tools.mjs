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
import { createGroupMirror, safeWorkspaceName } from './group-client.mjs';
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

/**
 * 点名范围（工作区 id / 权限档）的返回字段。只在调用方真的点名时追加 ——
 * 不点名时工具返回体与 0.8.4 逐字一致（形状也算行为）。
 * appliedPermission / permissionHonored 只信目标的回告：没回告就是空串 / false。
 */
function groupScopeFields(out, workspaceId, permission) {
  const raw = out?.workspace;
  const workspace = raw && typeof raw === 'object' && !Array.isArray(raw)
    ? { id: String(raw.id ?? ''), name: String(raw.name ?? '') }
    : (workspaceId === '' ? null : { id: workspaceId, name: '' });
  return {
    workspace,
    permission: permission === '' ? null : String(out?.permission ?? permission),
    appliedPermission: typeof out?.appliedPermission === 'string' ? out.appliedPermission : '',
    permissionHonored: out?.permissionHonored === true,
    approvalId: out?.approvalId ? String(out.approvalId) : null,
  };
}

/** 派单失败时给模型的一句人话（reason 是契约里的固定词表） */
const DISPATCH_HINTS = {
  unpaired: 'this node is not paired with that peer, so there is no per-peer key to reach it — pair first',
  'not-accepting': 'the target has group dispatch turned off (group.acceptDispatch=false on its side)',
  busy: 'rate limited: one dispatch per target per group.dispatchRateMs (default 60s) — wait before retrying',
  offline: 'the target is unreachable right now',
  empty: 'the task text is empty after removing the @!target marker',
  timeout: 'the target did not answer within the timeout; it may still be working',
  error: 'transport or agent error while dispatching',
  'group-disabled': 'group is not enabled on this node (config group.enabled / joined group)',
  // v0.8.5-α：点名了工作区/权限时，目标拒绝的 reason 是**协议 token**，原样透出。
  'permission-denied': 'the target refused this permission level: it is above its maxPermission, so nothing ran (never silently downgraded)',
  'unknown-workspace': 'the target does not know that workspace id; ask it for its workspace list before naming one',
  'bad-permission': 'permission must be one of read-only / workspace-write / danger-full-access',
};

export async function createLanPeerTools(config = {}, deps = {}) {
  const defineTool = await resolveDefineTool(deps);
  const feed = deps.feed ?? null;
  const log = typeof deps.log === 'function' ? deps.log : null;
  // 群内派单的执行侧由 host 注入（server.group.dispatchWithReply）：
  // 这样「作者侧解析 + 前置检查 + 群回执」只有一份实现，面板/CLI/工具共用。
  const dispatch = typeof deps.dispatch === 'function' ? deps.dispatch : null;
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

  tools.push(
    defineTool({
      name: 'lan_peer_send_file',
      description:
        'Send one local file to a paired peer (chunked, encrypted per peer, sha256-verified on the far side). The peer stores it in its own inbox and must confirm before it lands; there is no way to choose the remote path. Returns id/bytes/sha256/ms.',
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
            id: { type: 'string' },
            bytes: { type: 'number' },
            sha256: { type: 'string' },
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
        const id = String(out?.id ?? '');
        const bytes = Number(out?.bytes) || 0;
        const sha256 = String(out?.sha256 ?? '');
        const ms = Number.isFinite(Number(out?.ms)) ? Number(out.ms) : Date.now() - started;
        // 日志口径（契约 §0）：size / sha256 前 8 位 / 状态 —— 不带文件名与内容。
        log?.('[tool] send-file peer=' + String(peer.peerId).slice(0, 8) + ' id=' + id.slice(0, 8)
          + ' bytes=' + bytes + ' sha=' + sha256.slice(0, 8) + ' state=' + (ok ? 'ok' : 'rejected') + ' ms=' + ms);
        if (!ok) {
          const reason = String(out?.reason ?? 'send-failed');
          return {
            ok: false,
            id,
            bytes,
            sha256,
            ms,
            reason,
            text: 'send failed (' + reason + ')',
          };
        }
        return {
          ok: true,
          id,
          bytes,
          sha256,
          ms,
          text: 'sent to ' + peer.name + ': id=' + id + ' bytes=' + bytes
            + ' sha256=' + sha256.slice(0, 8) + ' ms=' + ms,
        };
      },
    }),
  );

  tools.push(
    defineTool({
      name: 'lan_group_ask',
      description:
        '群内派单：把任务派给群里的一个成员并等它的回复。与 lan_peer_ask 同形，但会在群历史里留下两条派单摘要（progress=开始、result=done|failed+耗时/字数），被派单者的回复正文只返回给你、不进群。'
        + '可选点名对方的工作区（workspace=工作区 id）和执行权限档（permission=read-only / workspace-write / danger-full-access）；两个都不传 = 用对方自己的默认工作区与默认权限档。',
      parameters: {
        peer: { type: 'string', required: true, description: '群成员的名字、短 id 或 peerId（同 lan_peers 的口径）。' },
        prompt: { type: 'string', required: true, description: '要派给对方的任务或问题。' },
        timeout_sec: {
          type: 'number',
          description: 'How long to wait for the reply. Default 300, maximum 900.',
        },
        workspace: {
          type: 'string',
          description: '目标的工作区 id（可选）。不传 = 用对方自己的默认工作区。只认 id：列表在对方那里（server.group.dispatchOptions / 面板），名字由对方回填，本机永远拿不到目录路径。不认识的 id 由对方拒绝：reason=unknown-workspace。',
        },
        permission: {
          type: 'string',
          description: '要对方以哪一档权限执行（可选），三档之一：read-only / workspace-write / danger-full-access。不传 = 用对方自己的默认权限档。高于对方上限直接拒绝（reason=permission-denied，绝不降级执行）；高于对方默认档但未超上限时不执行、需对方人工确认，工具返回 state=pending-approval + approvalId（受理态，不是失败）。档名写错由对方回 reason=bad-permission。',
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
        if (!dispatch) throw new Error('group dispatch unavailable on this host (no group service)');
        const timeoutSec = Math.min(Number(args.timeout_sec) || 300, 900);
        // v0.8.5-α：两个新入参都可空。都空 ⇒ 入参与返回体与 0.8.4 逐字一致。
        const workspaceId = typeof args.workspace === 'string' ? args.workspace.trim() : '';
        const permission = typeof args.permission === 'string' ? args.permission.trim() : '';
        const scoped = workspaceId !== '' || permission !== '';
        const input = { target: args.peer, task: args.prompt, timeoutSec };
        // 不点名时绝不带空字段：老对端的 /v1/ask 请求体必须与 0.8.4 一字不差。
        if (workspaceId !== '') input.workspaceId = workspaceId;
        if (permission !== '') input.permission = permission;
        // dispatchWithReply 是**工具专用**入口：只有它能拿到正文。
        // 走它而不是 server.group.post 有两条硬理由：post 不带 timeoutSec（工具的超时会被吞掉），
        // 且它会把任务正文当成一条群帖发出去（工具的契约是「群里只留两条摘要」）。
        const out = await dispatch(input);
        const peer = out?.targetName || out?.target || args.peer;
        const target = out?.target ?? null;
        const reply = typeof out?.reply === 'string' ? out.reply : '';
        // 只点名了才追加范围字段（不点名 = 0.8.4 的返回形状）。
        const appendScope = (result) => (scoped ? { ...result, ...groupScopeFields(out, workspaceId, permission) } : result);
        // 日志口径（契约 §0）：peer/id 前 8 位、权限档、工作区 id、字节数 —— 不记正文与 path。
        const logScoped = (state, reason, bytes) => {
          if (!scoped) return;
          log?.('[tool] group-ask peer=' + String(target ?? args.peer).slice(0, 8)
            + ' workspace=' + (safeWorkspaceName(workspaceId) || '-')
            + ' permission=' + (permission === '' ? '-' : permission.slice(0, 24))
            + ' state=' + state
            + (reason == null ? '' : ' reason=' + reason)
            + ' bytes=' + bytes);
        };

        // 契约 §2 的受理态：目标回 202（待人工批准）不是错误，工具照常返回 approvalId。
        if (String(out?.status ?? '') === 'pending-approval') {
          const approvalId = out?.approvalId ? String(out.approvalId) : '';
          logScoped('pending-approval', null, 0);
          return appendScope({
            peer,
            target,
            status: 'pending-approval',
            state: 'pending-approval',
            reason: null,
            reply: '',
            approvalId: approvalId === '' ? null : approvalId,
            text: '对方受理了这次派单但还没有开跑：对方需人工确认后才能执行'
              + (approvalId === '' ? '' : '（approvalId=' + approvalId + '）'),
          });
        }
        if (out?.status === 'done') {
          logScoped('done', null, Buffer.byteLength(reply, 'utf8'));
          return appendScope({ peer, target, status: 'done', reply, text: reply });
        }
        const status = String(out?.status ?? 'failed');
        const reason = String(out?.reason ?? 'error');
        logScoped(status, reason, Buffer.byteLength(reply, 'utf8'));
        return appendScope({
          peer,
          target,
          status,
          reason,
          reply: '',
          text: 'group dispatch ' + status + ' (' + reason + '): '
            + (DISPATCH_HINTS[reason] ?? DISPATCH_HINTS.error),
        });
      },
    }),
  );

  return tools;
}
