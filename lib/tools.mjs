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
// 0.12.7-alpha（slice C）：本机参与者发的帖子带一个标记（白名单字段 transport，见该常量注释）
import { PARTICIPANT_MARK } from './participant.mjs';

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
  // 0.12.7-alpha（slice B）：群提案/表决同样整块由 host 注入 —— 读口是面板那一条
  // （server.group.votes()：hub 读权威平面、成员读副本），写口是面板那一条
  // （server.group.castVote，票只记在本机名下）。工具这一层只做参数、错误口径与那条日志。
  const groupVotes = typeof deps.groupVotes === 'function' ? deps.groupVotes : null;
  const castGroupBallot = typeof deps.castGroupBallot === 'function' ? deps.castGroupBallot : null;
  // 0.12.7-alpha（slice C）：群内发言的写口同样整块由 host 注入 ——
  // 面板发言走的就是 server.group.post → commitLocalMessage（日志+commitSeq+复制队列），
  // 工具这一层不另起第二个写者。
  const groupPost = typeof deps.groupPost === 'function' ? deps.groupPost : null;
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
        // 0.12.0-alpha S1：不再有「已发送」这件事 —— 这里拿到的是 fileId（对方那边的一条待下载）。
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

  // ---- 0.12.7-alpha（slice B）：群提案 + 本机那一票 ---------------------------
  //
  // 模型能做的两件事与面板上的两个按钮一一对应：看开着的提案、投本机那一票。
  // 结果一律是稳定短串（not-in-group / unknown-proposal / bad-decision /
  // hub-unreachable），host 的异常绝不抛给模型。

  /** 裁决 ↔ 票面（与面板两个按钮、lib/group-vote.mjs 的 yes/no 同一口径） */
  const BALLOT_OF_DECISION = Object.freeze({ adopt: 'yes', reject: 'no' });
  const DECISION_OF_BALLOT = Object.freeze({ yes: 'adopt', no: 'reject' });
  const id8 = (value) => String(value ?? '').slice(0, 8);
  const deadlineText = (value) => (Number(value) > 0 ? new Date(Number(value)).toISOString() : 'none');

  /**
   * 表决平面 → 一行一提案。人已裁决、轮次已关的不端给 agent：
   * 它已经不在「等一个决定」这件事里，列出来只会诱使一次注定被拒的投票。
   */
  function openProposalRows(plane, selfId) {
    const source = plane && typeof plane === 'object' ? plane : {};
    const votes = source.votes && typeof source.votes === 'object' ? source.votes : {};
    const verdicts = source.verdicts && typeof source.verdicts === 'object' ? source.verdicts : {};
    const rows = [];
    for (const entry of Array.isArray(source.proposals) ? source.proposals : []) {
      const id = String(entry?.id ?? '');
      if (id === '' || verdicts[id]) continue;
      const vote = votes[id] && typeof votes[id] === 'object' ? votes[id] : null;
      if (vote && String(vote.status ?? 'open') !== 'open') continue;
      const ballots = vote?.ballots && typeof vote.ballots === 'object' ? vote.ballots : {};
      let adopt = 0;
      let reject = 0;
      for (const value of Object.values(ballots)) {
        const decision = DECISION_OF_BALLOT[String(value)];
        if (decision === 'adopt') adopt += 1;
        else if (decision === 'reject') reject += 1;
      }
      rows.push({
        id,
        id8: id8(id),
        kind: String(entry?.kind ?? ''),
        summary: String(entry?.text ?? '').slice(0, 120),
        deadline: Number(vote?.closesAt) > 0 ? Number(vote.closesAt) : 0,
        mine: DECISION_OF_BALLOT[String(ballots[String(selfId ?? '')] ?? '')] ?? '',
        adopt,
        reject,
        eligible: Array.isArray(vote?.roster) ? vote.roster.length : 0,
      });
    }
    return rows;
  }

  const proposalLine = (row) => row.id8 + ' ' + (row.kind === '' ? '-' : row.kind)
    + ' adopt=' + row.adopt + ' reject=' + row.reject + ' of=' + row.eligible
    + ' mine=' + (row.mine === '' ? '-' : row.mine)
    + ' deadline=' + deadlineText(row.deadline)
    + (row.summary === '' ? '' : ' — ' + row.summary);

  const groupRowsOut = { type: 'object', additionalProperties: true };

  tools.push(
    defineTool({
      name: 'lan_group_proposals',
      description:
        'List the open proposals in this node\'s group so you can vote on them: short id, kind, adopt/reject counts, the deadline, and the ballot this node already cast (empty when it has not voted yet). Read-only and local. Returns an "not-in-group" message with an empty list when this node is in no group, and an empty list when nothing is waiting for a decision. Use it before lan_group_vote — the id it prints is what that tool takes.',
      parameters: {},
      output: {
        schema: {
          type: 'object',
          additionalProperties: true,
          properties: {
            text: { type: 'string' },
            error: { type: 'string' },
            proposals: { type: 'array', items: groupRowsOut },
          },
        },
        render: (_args, value) => text(value.text),
      },
      async execute() {
        if (config?.group?.enabled !== true || !groupVotes) {
          return {
            error: 'not-in-group',
            proposals: [],
            text: 'not-in-group: this node is not in a group, so there are no proposals to show.',
          };
        }
        let plane;
        try {
          plane = await groupVotes();
        } catch {
          return {
            error: 'hub-unreachable',
            proposals: [],
            text: 'hub-unreachable: the group vote plane could not be read; try again later.',
          };
        }
        const self = readSelf(config);
        const rows = openProposalRows(plane, self.instanceId);
        if (rows.length === 0) {
          return { proposals: [], text: 'No open group proposals: nothing is waiting for a ballot right now.' };
        }
        return {
          proposals: rows,
          text: 'Open group proposals (' + rows.length + '):\n' + rows.map(proposalLine).join('\n')
            + '\nCast one with lan_group_vote {proposalId, decision} — the node has a single vote per proposal.',
        };
      },
    }),
  );

  tools.push(
    defineTool({
      name: 'lan_group_vote',
      description:
        'Cast THIS node\'s single ballot on one open group proposal. decision is "adopt" or "reject" — the same two buttons the human sees in the LAN peers panel. The node holds one vote per proposal: a second call OVERWRITES the previous ballot rather than adding another, so read lan_group_proposals first and spend it deliberately. The ballot is cast under this node\'s identity (never on behalf of another peer) and every agent-cast ballot is logged as by=agent, so the human operator can tell it was not their own click. Stable errors instead of exceptions: not-in-group, unknown-proposal (no such id, round closed, or this node is not eligible), bad-decision, hub-unreachable.',
      parameters: {
        proposalId: {
          type: 'string',
          required: true,
          description: 'Proposal id from lan_group_proposals (the full id; the 8-character prefix is what lists and logs show).',
        },
        decision: {
          type: 'string',
          required: true,
          description: 'adopt or reject.',
        },
      },
      output: {
        schema: {
          type: 'object',
          additionalProperties: true,
          properties: {
            text: { type: 'string' },
            ok: { type: 'boolean' },
            error: { type: 'string' },
            proposal: { type: 'string' },
            decision: { type: 'string' },
            adopt: { type: 'number' },
            reject: { type: 'number' },
          },
        },
        render: (_args, value) => text(value.text),
      },
      async execute(args) {
        const proposalId = String(args?.proposalId ?? '').trim();
        const decision = String(args?.decision ?? '').trim().toLowerCase();
        if (!Object.prototype.hasOwnProperty.call(BALLOT_OF_DECISION, decision)) {
          return {
            ok: false,
            error: 'bad-decision',
            proposal: id8(proposalId),
            text: 'bad-decision: decision must be "adopt" or "reject".',
          };
        }
        if (proposalId === '') {
          return {
            ok: false,
            error: 'unknown-proposal',
            proposal: '',
            text: 'unknown-proposal: proposalId is required (see lan_group_proposals).',
          };
        }
        if (config?.group?.enabled !== true || !castGroupBallot) {
          return {
            ok: false,
            error: 'not-in-group',
            proposal: id8(proposalId),
            text: 'not-in-group: this node is not in a group, so it has no ballot to cast.',
          };
        }
        const ballot = BALLOT_OF_DECISION[decision];
        let out;
        try {
          out = await castGroupBallot({ proposalId, ballot });
        } catch {
          return {
            ok: false,
            error: 'hub-unreachable',
            proposal: id8(proposalId),
            text: 'hub-unreachable: the group hub did not answer; the ballot was not recorded.',
          };
        }
        const reason = String(out?.error ?? out?.reason ?? '');
        // 写口拒绝：没有平面（not-in-group）/没有这条提案（unknown-proposal）/
        // 轮次关了或本机不在名单（仍然是「这条现在不能投」）。其余一律算链路问题。
        if (out?.ok !== true) {
          const error = reason === 'votes-hub-only'
            ? 'not-in-group'
            : (reason === 'vote-not-found' ? 'unknown-proposal' : 'hub-unreachable');
          return {
            ok: false,
            error,
            proposal: id8(proposalId),
            text: error + ': the ballot was not recorded'
              + (reason === '' ? '' : ' (' + reason.slice(0, 32) + ')') + '.',
          };
        }
        if (out.accepted !== true) {
          return {
            ok: false,
            error: 'unknown-proposal',
            proposal: id8(proposalId),
            text: 'unknown-proposal: ' + id8(proposalId) + ' is not accepting this node\'s ballot right now'
              + (reason === '' ? '' : ' (' + reason.slice(0, 32) + ')') + '.',
          };
        }
        const adopt = Number(out?.vote?.yes) || 0;
        const reject = Number(out?.vote?.no) || 0;
        // 契约 §0 的日志口径：一行一票，短 id + 裁决，谁的票（by=agent）必须写得出来 ——
        // 人能看出这不是自己点的那一下。
        log?.('[group] ballot cast by=agent proposal=' + id8(proposalId) + ' decision=' + decision);
        return {
          ok: true,
          error: '',
          proposal: id8(proposalId),
          decision,
          adopt,
          reject,
          text: 'ballot recorded: ' + decision + ' on ' + id8(proposalId)
            + ' (adopt=' + adopt + ' reject=' + reject + '; this node has one vote per proposal)',
        };
      },
    }),
  );

  // ---- 0.12.7-alpha（slice C）：群内发言 -------------------------------------
  //
  // 用户决定：**发言不限速**，所以这里没有任何速率闸 —— 只有一条稳定拒绝口径。
  // 写口是 host 注入的 server.group.post（面板发言同一条 commitLocalMessage），
  // 本工具只负责参数、参与者标记与错误口径。

  tools.push(
    defineTool({
      name: 'lan_group_post',
      description:
        'Post ONE message into this node\'s LAN group. The message is PUBLIC TO THE WHOLE GROUP: every member node sees it in its group history, so never put private or machine-local detail in it (use lan_peer_ask for one peer only). The post is authored under this node\'s identity and shows up in the group like any other message. Text is the only input and it is required. Stable refusals instead of exceptions: not-in-group (this node is in no group), bad-text (nothing to post), post-failed (the group did not accept the message).',
      parameters: {
        text: { type: 'string', required: true, description: 'The message body to publish to the whole group.' },
      },
      output: {
        schema: {
          type: 'object',
          additionalProperties: true,
          properties: {
            text: { type: 'string' },
            ok: { type: 'boolean' },
            error: { type: 'string' },
            seq: { type: 'number' },
          },
        },
        render: (_args, value) => text(value.text),
      },
      async execute(args) {
        const body = String(args?.text ?? '').trim();
        if (body === '') {
          return { ok: false, error: 'bad-text', seq: null, text: 'bad-text: text is required (nothing was posted).' };
        }
        if (config?.group?.enabled !== true || !groupPost) {
          return {
            ok: false,
            error: 'not-in-group',
            seq: null,
            text: 'not-in-group: this node is not in a group, so there is nothing to post to.',
          };
        }
        let out;
        try {
          // transport 是群 meta 白名单里唯一的自由字符串字段：用它标记「本机参与者发的帖子」，
          // 对面据此认出这是 agent 发的（乒乓闸）。
          out = await groupPost({ text: body, kind: 'chat', meta: { transport: PARTICIPANT_MARK } });
        } catch {
          return {
            ok: false,
            error: 'post-failed',
            seq: null,
            text: 'post-failed: the group did not accept this message; nothing was published.',
          };
        }
        const reason = String(out?.error ?? out?.reason ?? '');
        if (out?.ok !== true) {
          const error = reason === 'not-in-group' ? 'not-in-group' : 'post-failed';
          return {
            ok: false,
            error,
            seq: null,
            text: error + ': the group did not accept this message; nothing was published'
              + (reason === '' ? '' : ' (' + reason.slice(0, 32) + ')') + '.',
          };
        }
        const seq = Number(out?.seq) > 0 ? Number(out.seq) : null;
        const chars = Array.from(body).length;
        // 日志口径：条数/序号/长度，正文一个字都不进日志（与群消息同一口径）
        log?.('[group] post by=agent seq=' + (seq ?? '?') + ' chars=' + chars);
        return {
          ok: true,
          error: '',
          seq,
          text: 'posted to the whole group (seq=' + (seq ?? '?') + ', ' + chars + ' chars)'
            + ' — every member node sees this message.',
        };
      },
    }),
  );

  // ---- 0.12.7-alpha（slice D）：本机会话 —— 列出来、派进去 ---------------------
  //
  // 用户决定（已定，不在这里重新论证）：
  //   · 列表每行只回短 id / 最后活动时间 / 权限档 —— **绝不回 cwd**（cwd 是这台机器的
  //     私有事实，列表又会被模型原样读走）：「行里没有 cwd」因此是结构性保证。
  //   · 派单等对方的**最后一条助手消息**（不是 transcript），超时如实回 timeout。
  //   · 权限闸默认开：目标档比调用者档更高就拒绝；目标档读不出来按**最高档**算（fail-closed）。
  //
  // 短 id 取**尾部** 8 字符，不取头部：DSH 的会话 id 一律 session-<n>，头 8 字符恒为
  // 'session-'，按前缀显示出来的每一行都长一个样、按它派单必然 unknown-session。
  // 尾部撞车时才整体加长（见 sessionShorts），确定性来自「同一份名单永远算同一组短 id」。
  //
  // 两个门面都由 host 注入，本层不重造第二套实现：
  //   listSessions —— controller.list 挑三个字段（权限档走 lib/runner-ctx.mjs 的 permissionOf）
  //   askSession   —— runner.ask（发一轮）+ runner.poll（既有那条「读最后一条助手消息」）
  const listSessions = typeof deps.listSessions === 'function' ? deps.listSessions : null;
  const askSession = typeof deps.askSession === 'function' ? deps.askSession : null;
  const allowHigherPermission = typeof deps.allowHigherPermission === 'function' ? deps.allowHigherPermission : null;

  /** 三档顺序即档位高低（与 lib/runner-ctx.mjs 的 PERMISSION_TIERS、lib/dispatch-prefs.mjs 的 PERMISSION_LEVELS 同序） */
  const SESSION_TIERS = Object.freeze(['read-only', 'workspace-write', 'danger-full-access']);
  /** 序；不是三档之一一律 -1（读不出来 = 不可信，不是「最宽」也不是「最窄」） */
  const sessionTierRank = (value) => SESSION_TIERS.indexOf(String(value ?? ''));
  /** 读不出目标档时按这一档算：fail-closed（放行未知档比误拒危险得多） */
  const SESSION_TOP_TIER = SESSION_TIERS[SESSION_TIERS.length - 1];
  const SESSION_ASK_DEFAULT_SEC = 120;
  /** 整轮等待上限 900 s（与 lan_peer_ask 的 timeout_sec 上限同一口径）；单次 hold 另由 MAX_ANSWER_WAIT_MS 封顶 */
  const SESSION_ASK_MAX_SEC = 900;
  /** 短 id 的起点长度；也用作「至少这么长才算一次有效匹配」的下限 */
  const SESSION_SHORT_LEN = 8;
  /** 派单时接受的最短后缀：4 字符太短就不猜（撞车率高，猜错就是派到别的会话） */
  const SESSION_MIN_SUFFIX = 4;

  /** 尾部短 id（≤8）：只用于单值回执/日志 —— 与 lib/runner-ctx.mjs 的 shortId 同一口径 */
  const sessionTail = (value) => {
    const text = String(value ?? '');
    return text.length <= SESSION_SHORT_LEN ? text : text.slice(-SESSION_SHORT_LEN);
  };

  /**
   * 一屏内的短 id 表：从尾部 8 字符起，**全表**撞车就加长一位，直到彼此都不同。
   * 加长是全表一起加（不是各自加），所以同一份名单永远得到同一组短 id —— 确定性来自这里。
   * @returns {Map<string,string>} 全 id → 短 id
   */
  function sessionShorts(ids) {
    const longest = ids.reduce((max, id) => Math.max(max, id.length), 0);
    for (let len = SESSION_SHORT_LEN; len <= Math.max(SESSION_SHORT_LEN, longest); len += 1) {
      const shorts = ids.map((id) => (id.length <= len ? id : id.slice(-len)));
      if (new Set(shorts).size === shorts.length) return new Map(ids.map((id, i) => [id, shorts[i]]));
    }
    // 全 id 都撞车是不可能的（id 本身互不相同）：兜底回全 id，绝不回一个会误伤的短 id
    return new Map(ids.map((id) => [id, id]));
  }

  /**
   * 权限闸是否被抬起：**每次调用现读**（面板改完不必重启）。注入的读取器优先，
   * 没注入才退回插件 config 的同名字段；读不出来/抛错一律 false —— 闸门默认关着的是「更高那一档」。
   */
  const allowHigher = () => {
    const configured = config?.sessionDispatch?.allowHigherPermission === true;
    if (!allowHigherPermission) return configured;
    try { return allowHigherPermission() === true; } catch { return configured; }
  };

  const sessionLine = (row) => row.id + '\t'
    + (row.lastActivity > 0 ? new Date(row.lastActivity).toISOString() : '-') + '\t'
    + (row.permission === '' ? 'unknown' : row.permission);

  tools.push(
    defineTool({
      name: 'lan_sessions',
      description:
        'List the OTHER DSH sessions running in this app on this machine so you can dispatch into one with lan_session_ask. Each row is a short id (= the LAST 8 characters of the session id, lengthened only when two sessions would otherwise render identically), the last-activity time (epoch ms) and the permission tier (read-only / workspace-write / danger-full-access; empty means the tier could not be read). The working directory is deliberately omitted: a session list is read by a model and the cwd is machine-local detail it does not need. Read-only and local; a controller that cannot list comes back as the stable string list-failed, never as a thrown error.',
      parameters: {},
      output: {
        schema: {
          type: 'object',
          additionalProperties: true,
          properties: {
            text: { type: 'string' },
            error: { type: 'string' },
            sessions: { type: 'array', items: { type: 'object', additionalProperties: true } },
          },
        },
        render: (_args, value) => text(value.text),
      },
      async execute() {
        if (!listSessions) {
          return {
            error: 'list-failed',
            sessions: [],
            text: 'list-failed: this host exposes no session list (no in-process session controller).',
          };
        }
        let rows;
        try {
          rows = await listSessions();
        } catch {
          return {
            error: 'list-failed',
            sessions: [],
            text: 'list-failed: the session controller did not answer; try again later.',
          };
        }
        if (!Array.isArray(rows)) {
          return {
            error: 'list-failed',
            sessions: [],
            text: 'list-failed: the session controller returned no list.',
          };
        }
        // 只挑三个字段：投影与 cwd 一个都不碰（拿到的行里就算带着 cwd，也走不出这一层）
        const ids = rows.map((row) => String(row?.sessionId ?? '')).filter((id) => id !== '');
        const shorts = sessionShorts(ids);
        const list = rows
          .map((row) => ({
            id: shorts.get(String(row?.sessionId ?? '')) ?? '',
            lastActivity: Number(row?.lastActivity) > 0 ? Number(row.lastActivity) : 0,
            permission: sessionTierRank(row?.permission) >= 0 ? String(row.permission) : '',
          }))
          .filter((row) => row.id !== '');
        if (list.length === 0) {
          return { sessions: [], text: 'No other sessions on this machine right now.' };
        }
        return {
          sessions: list,
          text: 'Local sessions (' + list.length + '):\n' + list.map(sessionLine).join('\n')
            + '\nDispatch into one with lan_session_ask {sessionId, prompt} — the short id above (the last 8 characters of the session id), the full id, or any unique suffix of 4+ characters.',
        };
      },
    }),
  );

  tools.push(
    defineTool({
      name: 'lan_session_ask',
      description:
        'Send ONE prompt to another DSH session running in this same app on this machine and wait for that session\'s final assistant message — only that message comes back, not a transcript. sessionId is the short id from lan_sessions (that is the LAST 8 characters of the session id), the full session id, or any other unique suffix of at least 4 characters; an ambiguous or too-short value is refused as unknown-session instead of guessing. The other session keeps its own workspace, its own permission tier and its own model quota; it may refuse or take a while. A permission gate is on by default: a target whose tier is HIGHER than this session\'s (read-only < workspace-write < danger-full-access) is refused as target-permission-higher, and a target whose tier cannot be read counts as the highest tier, so it is refused too. Stable strings instead of exceptions: unknown-session, self-session, target-permission-higher, own-permission-unknown, bad-prompt, timeout (the target may still be working), list-failed, ask-failed.',
      parameters: {
        sessionId: {
          type: 'string',
          required: true,
          description: 'Target session from lan_sessions: its short id (last 8 characters), the full session id, or any unique suffix of 4+ characters.',
        },
        prompt: { type: 'string', required: true, description: 'The task or question to send to that session.' },
        timeoutSec: {
          type: 'number',
          description: 'How long to wait for the final message. Default ' + SESSION_ASK_DEFAULT_SEC + ', maximum ' + SESSION_ASK_MAX_SEC + '.',
        },
      },
      output: {
        schema: {
          type: 'object',
          additionalProperties: true,
          properties: {
            text: { type: 'string' },
            ok: { type: 'boolean' },
            error: { type: 'string' },
            session: { type: 'string' },
            reply: { type: 'string' },
          },
        },
        render: (_args, value) => text(value.text),
      },
      async execute(args, exec) {
        /** 一次调用一行日志：短 id + 稳定码，正文一个字都不进日志 */
        const refuse = (code, shown, detail) => {
          log?.('[session] ask refused target=' + shown + ' reason=' + code);
          return { ok: false, error: code, session: shown, reply: '', text: detail };
        };

        const prompt = String(args?.prompt ?? '');
        if (prompt.trim() === '') {
          return refuse('bad-prompt', '', 'bad-prompt: prompt is required (nothing was sent).');
        }
        const wanted = String(args?.sessionId ?? '').trim();
        if (wanted === '') {
          return refuse('unknown-session', '', 'unknown-session: sessionId is required (see lan_sessions).');
        }
        if (!listSessions) {
          return refuse('list-failed', sessionTail(wanted), 'list-failed: this host exposes no session list, so no session can be resolved.');
        }
        if (!askSession) {
          return refuse('ask-failed', sessionTail(wanted), 'ask-failed: this host has no session dispatch channel.');
        }

        let rows;
        try {
          rows = await listSessions();
        } catch {
          return refuse('list-failed', sessionTail(wanted), 'list-failed: the session controller did not answer; nothing was sent.');
        }
        if (!Array.isArray(rows)) {
          return refuse('list-failed', sessionTail(wanted), 'list-failed: the session controller returned no list; nothing was sent.');
        }

        // 解析目标：全 id 优先；否则按**后缀**匹配（短 id 就是尾部 8 字符）。
        // 撞车或太短一律 unknown-session —— 绝不猜一个去发（猜错就是派到别人的会话）。
        const ids = rows.map((row) => String(row?.sessionId ?? '')).filter((id) => id !== '');
        const shorts = sessionShorts(ids);
        const exact = ids.filter((id) => id === wanted);
        let matches = exact;
        if (matches.length === 0) {
          matches = wanted.length < SESSION_MIN_SUFFIX ? [] : ids.filter((id) => id.endsWith(wanted));
        }
        if (matches.length !== 1) {
          const shown = sessionTail(wanted);
          return refuse('unknown-session', shown, 'unknown-session: '
            + (matches.length === 0
              ? (wanted.length < SESSION_MIN_SUFFIX
                ? 'a suffix must be at least ' + SESSION_MIN_SUFFIX + ' characters'
                : 'no session ends with ' + shown)
              : matches.length + ' sessions end with ' + shown + ' — pass more characters or the full id')
            + '; nothing was sent.');
        }
        const targetId = matches[0];
        const shownId = shorts.get(targetId) ?? sessionTail(targetId);
        const targetRow = rows.find((row) => String(row?.sessionId ?? '') === targetId);

        // 调用自己的会话：就是这次工具调用所属 agent 的会话（DSH 把它放在 exec.agent 上）
        const ownId = String(exec?.agent?.sessionId ?? '');
        if (ownId !== '' && targetId === ownId) {
          return refuse('self-session', shownId, 'self-session: that is this session; use the tool normally instead of dispatching to yourself.');
        }

        const ownRow = ownId === '' ? null : rows.find((row) => String(row?.sessionId ?? '') === ownId);
        const ownTier = sessionTierRank(ownRow?.permission) >= 0 ? String(ownRow.permission) : '';
        if (!allowHigher()) {
          if (ownTier === '') {
            return refuse('own-permission-unknown', shownId, 'own-permission-unknown: this session\'s own permission tier '
              + (ownId === '' ? 'is not visible to the plugin' : 'could not be read from the session list')
              + ', so a dispatch to another session cannot be allowed safely.');
          }
          const targetTier = sessionTierRank(targetRow?.permission) >= 0 ? String(targetRow.permission) : SESSION_TOP_TIER;
          if (sessionTierRank(targetTier) > sessionTierRank(ownTier)) {
            return refuse('target-permission-higher', shownId, 'target-permission-higher: the target runs with ' + targetTier
              + ', higher than this session (' + ownTier + '); raise it in the panel settings (sessionDispatch.allowHigherPermission) to allow this.');
          }
        }

        const rawSec = Number(args?.timeoutSec);
        const timeoutSec = Number.isFinite(rawSec) && rawSec > 0
          ? Math.min(Math.max(1, Math.round(rawSec)), SESSION_ASK_MAX_SEC)
          : SESSION_ASK_DEFAULT_SEC;
        const started = Date.now();
        let out;
        try {
          out = await askSession({ sessionId: targetId, prompt, timeoutMs: timeoutSec * 1000 });
        } catch {
          return refuse('ask-failed', shownId, 'ask-failed: the dispatch channel failed; the target may not have received it.');
        }
        const ms = Date.now() - started;
        const reply = typeof out?.reply === 'string' ? out.reply : '';
        if (out?.status === 'done' && reply.trim() !== '') {
          log?.('[session] ask target=' + shownId + ' ms=' + ms);
          return { ok: true, error: '', session: shownId, reply, text: reply };
        }
        const code = out?.status === 'timeout'
          ? 'timeout'
          : (reply.trim() === '' ? 'empty-reply' : String(out?.error ?? 'ask-failed'));
        if (code === 'timeout') {
          return refuse('timeout', shownId, 'timeout after ' + timeoutSec + 's; that session may still be working on it.');
        }
        return refuse(code, shownId, code + ': that session did not produce a final message; nothing was returned.');
      },
    }),
  );

  return tools;
}
