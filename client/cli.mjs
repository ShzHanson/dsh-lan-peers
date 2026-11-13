#!/usr/bin/env node
// dsh-lan-peers — client half CLI.
//   node cli.mjs code   [--state-dir <dir>]
//   node cli.mjs pair   --url http://PEER:7788 --code 123456 [--name 本机名] [--peer-name 对端名] [--legacy-pair]
//   node cli.mjs peers  [--probe]
//   node cli.mjs ask    --peer <peerId|name> "prompt" [--timeout 300] [--legacy-poll]
//   node cli.mjs events --peer <peerId|name> --session <sessionId> [--duration 300] [--verbose]
//   node cli.mjs unpair --peer <peerId|name> [--local-only] [--timeout 10]
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  DEFAULT_ANSWER_WAIT_MS,
  MAX_ANSWER_WAIT_MS,
  awaitPeerAnswer,
  callPeer,
  capabilityOf,
  pairingEcdhAvailable,
  pairPeer,
  probePeer,
} from './peer-call.mjs';
import { readPeerEvents } from './sse.mjs';
import { resolveLang, t } from '../lib/i18n.mjs';
// v0.9.0-α：会话复用三元键的键名与区间只认 batch 1 那一份（CLI 不再抄一套常量）。
import {
  SESSION_NEW_APPROVAL_WINDOW_KEY,
  SESSION_NEW_REQUEST_ALLOWED_KEY,
  SESSION_REUSE_MS_MAX,
  SESSION_REUSE_MS_MIN,
  SESSION_REUSE_TTL_KEY,
} from '../lib/session-reuse-prefs.mjs';
// 面板在管理接口里解析，CLI 在发完消息后解析，两边落在同一个函数上。
import {
  GROUP_APPLY_POLL_INTERVAL_MS,
  GROUP_APPLY_POLL_TIMEOUT_MS,
  GROUP_KINDS,
  GROUP_LOOKUP_TIMEOUT_MS,
  GROUP_REPLICA_FILE,
  GROUP_TEXT_MAX_CHARS,
  applyGroupGrant,
  applyToGroup,
  broadcastGroupAdvertisement,
  fetchGroupHistory,
  fetchGroupState,
  joinGroup,
  lookupGroupNameEverywhere,
  normalizeGroupName,
  pollApplication,
  postGroup,
  postGroupWithGroupKey,
  probeGroupPeer,
  pullGroupMessages,
  readGroupEvents,
  readGroupKeyFile,
  readKnownGroups,
  rememberKnownGroup,
  resolveGroupName,
  sameGroupName,
  GROUP_ROLE_FILE,
  fetchGroupLease,
  readGroupRoleFile,
  readLocalGroupKey,
  requestGroupVote,
} from '../lib/group-client.mjs';

const DEFAULT_STATE_DIR = path.join(os.homedir(), '.dsh', 'lan-peers');

// v0.8.5-α §0.7b：输出语言。优先级 --lang > 配置 <stateDir>/config.json 的 lang > 自动探测
// （环境变量 DSH_LAN_PEERS_LANG > 系统语言 > zh）。文案全在 lib/i18n.mjs，这里只取值。
// 日志与协议字段不进词表：它们在任何语言下都是同样的稳定标识。
let LANG = 'zh';
const L = (key, params) => t(LANG, key, params);

function applyLang(args) {
  const config = readJson(path.join(stateDir(args), 'config.json'), {});
  // --lang 是最高优先：给了就压过配置；非法值按 auto 处理，不抛错（与缺 key 回落同一口径）
  const override = args.lang === undefined || args.lang === true ? undefined : String(args.lang);
  LANG = resolveLang({ lang: override === undefined ? (config && config.lang) : override });
}

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('--')) out[key] = true;
      else {
        out[key] = next;
        i++;
      }
    } else out._.push(arg);
  }
  return out;
}

const stateDir = (args) => path.resolve(args['state-dir'] || DEFAULT_STATE_DIR);
const readJson = (file, fallback) => {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
};
const writeJson = (file, value) => {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = file + '.' + process.pid + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, file);
};

function identity(dir) {
  const file = path.join(dir, 'state.json');
  const state = readJson(file, {});
  if (!state.instanceId) {
    state.instanceId = crypto.randomUUID();
    state.name = state.name || os.hostname();
    state.createdAt = new Date().toISOString();
    writeJson(file, state);
  }
  return state;
}

function findPeer(dir, wanted) {
  const store = readJson(path.join(dir, 'peers.json'), { peers: {} });
  const match = Object.entries(store.peers || {}).find(
    ([peerId, peer]) => peerId === wanted || peer.name === wanted,
  );
  if (!match) throw new Error(L('cli.common.unknownPeer', { peer: wanted }));
  return { store, peerId: match[0], peer: match[1] };
}

async function signedCall({ baseUrl, secret, senderId, method = 'GET', apiPath, body }) {
  return callPeer({ baseUrl, secret, senderId, method, apiPath, body, timeoutMs: 60_000 });
}

/**
 * M6：配对码只活在 daemon 进程内存里（state.json 不再持久化它）。本命令是**独立进程**，
 * 自己生成一个码打印出来，正在跑的 host 根本不知道 —— 用户抄走的是一条无效凭据
 * （旧行为「另一个进程能写码」本身也正是要堵掉的植入路径）。所以这里改成请本机 host 发码：
 * 它才是唯一该写这条的进程，也是唯一知道码的进程。
 *
 * 本机没有 host / 拿不到 token → exit 2 并说清怎么起 host，绝不本地造一个码糊弄过去。
 */
async function cmdCode(args) {
  const dir = stateDir(args);
  let url = '';
  let out;
  try {
    url = resolveAdminUrl(dir, args);
    out = await adminCall(url, 'code', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    }, dir);
  } catch (error) {
    const reason = String(error?.message ?? error);
    process.stderr.write(L('cli.code.hostRefused', { url: url || L('cli.common.localAdmin'), reason }) + '\n');
    process.exitCode = 2;
    return;
  }
  const code = String(out && out.code ? out.code : '').trim();
  if (!/^\d{6}$/.test(code)) {
    process.stderr.write(L('cli.code.badShape') + '\n');
    process.exitCode = 2;
    return;
  }
  console.log(L('cli.code.ok', { code }));
  console.log(L('cli.code.hintFillPeer'));
  console.log(L('cli.code.hintMemoryOnly'));
}

async function cmdPair(args) {
  const dir = stateDir(args);
  const me = identity(dir);
  const url = String(args.url || '').replace(/\/$/, '');
  const code = String(args.code || '');
  // Two different names, easy to confuse:
  //   selfName  — what we tell the peer about *us* (goes into the pairing body)
  //   label     — what we call the peer in our own list (--name / --peer-name)
  const selfName = String(me.name || os.hostname());
  const peerLabel = args.name || args['peer-name'];
  if (!url || !code) throw new Error(L('cli.help.pair'));

  const mode = args['legacy-pair'] ? 'legacy' : (args['ecdh-pair'] ? 'ecdh' : 'auto');
  // 把自己的可达地址一起发过去：接收方存进 peers.json 的该 peer 记录，
  // 之后广播/派单才不会因为「没有地址」而被跳过（v0.8.0 真机回归）。
  const selfBaseUrl = String(args['base-url'] ?? '').trim();
  const selfPort = Number(args.port) > 0 ? Math.floor(Number(args.port)) : undefined;
  const paired = await pairPeer({
    url,
    code,
    peerId: me.instanceId,
    peerName: selfName,
    mode,
    selfBaseUrl: selfBaseUrl === '' ? null : selfBaseUrl,
    ...(selfPort == null ? {} : { selfPort }),
  });

  const peersFile = path.join(dir, 'peers.json');
  const store = readJson(peersFile, { peers: {} });
  const previous = store.peers[paired.peerId] || {};
  // Two secrets per peer: `secret` is what the peer issued to us (we sign with
  // it), `inboundSecret` is what we issued to the peer (we verify with it).
  // Keeping both is what makes the pairing mutual in both directions.
  store.peers[paired.peerId] = {
    ...previous,
    name: peerLabel || paired.peerName || paired.peerId,
    baseUrl: url,
    secret: paired.secret,
    inboundSecret: paired.inboundSecret,
    transport: paired.transport,
    addedAt: previous.addedAt || new Date().toISOString(),
  };
  writeJson(peersFile, store);

  const label = store.peers[paired.peerId].name;
  const transport = paired.transport === 'ecdh' ? L('cli.pair.transportEcdh') : L('cli.pair.transportLegacy');
  console.log(L('cli.pair.ok', { label, peerId: paired.peerId, transport }));
  if (paired.transport === 'legacy') {
    const ecdhReady = await pairingEcdhAvailable();
    console.log(L(ecdhReady ? 'cli.pair.fallbackNoEcdh' : 'cli.pair.fallbackNoModule'));
  }
}

async function cmdPeers(args) {
  const dir = stateDir(args);
  const store = readJson(path.join(dir, 'peers.json'), { peers: {} });
  const entries = Object.entries(store.peers || {});
  if (entries.length === 0) {
    console.log(L('cli.peers.empty'));
    return;
  }
  for (const [peerId, peer] of entries) {
    let status = 'unknown';
    if (args.probe) {
      try {
        const res = await fetch(peer.baseUrl + '/v1/health', { signal: AbortSignal.timeout(2000) });
        status = res.ok ? 'online' : 'http ' + res.status;
      } catch {
        status = 'offline';
      }
    }
    console.log(peer.name + '\t' + peer.baseUrl + '\t' + peerId + '\t' + status);
  }
}

async function cmdAsk(args) {
  // /v1/ask 的报文里没有权限档：静默收下 --perm 等于让用户以为档位生效了（v0.10.3 实测无效）。
  // 带权限档的路径是 dm <peer> <正文> --perm <档>，这里直接拒绝并指过去。
  if (args.perm !== undefined) throw new Error(L('cli.ask.noPerm'));
  const dir = stateDir(args);
  const me = identity(dir);
  const prompt = args._.join(' ').trim();
  if (!args.peer || !prompt) throw new Error(L('cli.help.ask'));
  const { peer } = findPeer(dir, args.peer);

  const requestId = 'req-' + crypto.randomUUID();
  const accepted = await signedCall({
    baseUrl: peer.baseUrl,
    secret: peer.secret,
    senderId: me.instanceId,
    method: 'POST',
    apiPath: '/v1/ask',
    body: { requestId, prompt, timeoutSec: Number(args.timeout || 300) },
  });
  const sessionId = accepted.sessionId;
  process.stderr.write(L('cli.ask.dispatched', { name: peer.name, sessionId }) + '\n');

  // Capability decides the wire shape: a 0.3.1 peer has no "stream", so it keeps
  // the old 1.5s answer polling (waitMs is never sent to it).
  const health = await probePeer({ baseUrl: peer.baseUrl, timeoutMs: 2000 });
  const streamCapable = capabilityOf(health).includes('stream');
  const mode = args['legacy-poll'] ? 'legacy' : (streamCapable ? 'auto' : 'legacy');
  const waitMs = Math.min(Math.max(1000, Number(args['wait-ms']) || DEFAULT_ANSWER_WAIT_MS), MAX_ANSWER_WAIT_MS);

  const settled = await awaitPeerAnswer({
    baseUrl: peer.baseUrl,
    secret: peer.secret,
    senderId: me.instanceId,
    sessionId,
    timeoutMs: Number(args.timeout || 300) * 1000,
    waitMs,
    mode,
    onProgress: (info) => process.stderr.write(info.transport === 'sse' ? '·' : '.'),
  });
  process.stderr.write('\n');
  if (settled.status === 'done') {
    console.log(settled.reply);
    return;
  }
  if (settled.status === 'error') throw new Error(L('cli.ask.peerError', { error: settled.error }));
  console.log('timeout after ' + Math.round((settled.elapsedMs || 0) / 1000) + 's');
  process.exitCode = 2;
}

async function cmdEvents(args) {
  const dir = stateDir(args);
  const me = identity(dir);
  const sessionId = String(args.session || args['session-id'] || '');
  // Arguments first: a missing --session must not fall through to a peer lookup.
  if (!args.peer || !sessionId) throw new Error(L('cli.help.events'));
  const { peer } = findPeer(dir, args.peer);

  const health = await probePeer({ baseUrl: peer.baseUrl, timeoutMs: 3000, fresh: true });
  if (!capabilityOf(health).includes('stream')) {
    process.stderr.write(L('cli.events.noStream') + '\n');
    process.exitCode = 2;
    return;
  }

  const durationMs = Math.max(1000, Number(args.duration || 300) * 1000);
  process.stderr.write(L('cli.events.subscribed', { name: peer.name, sessionId }) + '\n');
  const out = await readPeerEvents({
    baseUrl: peer.baseUrl,
    secret: peer.secret,
    senderId: me.instanceId,
    sessionId,
    timeoutMs: durationMs,
    onEvent: (info) => {
      if (info.type === 'ping') {
        if (args.verbose) console.log('[ping]');
        return;
      }
      const body = info.reply !== undefined ? String(info.reply) : String(info.error ?? '');
      console.log('[' + (info.status || info.type) + '] elapsedMs=' + (info.elapsedMs ?? '?') + (body ? ' ' + body : ''));
    },
  });
  if (!out.ok) {
    process.stderr.write(L('cli.events.ended', { reason: out.reason }) + '\n');
    process.exitCode = 1;
    return;
  }
  process.stderr.write(L('cli.events.finalStatus', { status: out.status }) + '\n');
}

/** 按 peerId 或名字精确解析；返回全部命中，交给调用方判歧义 */
function resolvePeers(dir, wanted) {
  const store = readJson(path.join(dir, 'peers.json'), { peers: {} });
  const target = String(wanted ?? '').trim();
  const matches = Object.entries(store.peers || {})
    .filter(([peerId, peer]) => peerId === target || peer?.name === target);
  return { store, matches };
}

/**
 * 尽力通知对端把它那边的本端记录也删掉。与 /api/lan-peers/unpair 同一套门控：
 * 有地址、有密钥、/v1/health 的 capability 含 "unpair" 才发请求。
 * 任何失败都返回原因而不抛 —— 本地删除不允许被对端状态阻塞。
 */
async function notifyUnpair({ peer, senderId, timeoutSec }) {
  const baseUrl = String(peer?.baseUrl ?? '').trim().replace(/\/+$/, '');
  if (baseUrl === '') return { notified: false, reason: L('cli.unpair.reasonNoAddress') };
  if (!peer?.secret) return { notified: false, reason: L('cli.unpair.reasonNoSecret') };
  const probeMs = Math.max(500, Math.min(2000, timeoutSec * 1000));
  const health = await probePeer({ baseUrl, timeoutMs: probeMs, fresh: true });
  if (!health?.online) return { notified: false, reason: L('cli.unpair.reasonOffline') };
  if (!capabilityOf(health).includes('unpair')) return { notified: false, reason: L('cli.unpair.reasonNoCapability') };
  try {
    await callPeer({
      baseUrl,
      secret: peer.secret,
      senderId,
      method: 'POST',
      apiPath: '/v1/unpair',
      timeoutMs: Math.max(1000, timeoutSec * 1000),
    });
    return { notified: true };
  } catch (error) {
    return { notified: false, reason: String(error?.message ?? error) };
  }
}

async function cmdUnpair(args) {
  const dir = stateDir(args);
  const wanted = String(args.peer ?? '').trim();
  if (!wanted) throw new Error(L('cli.help.unpair'));
  const { matches } = resolvePeers(dir, wanted);
  if (matches.length === 0) {
    process.stderr.write(L('cli.common.unknownPeer', { peer: wanted }) + '\n' + L('cli.help.unpair') + '\n');
    process.exitCode = 2;
    return;
  }
  if (matches.length > 1) {
    process.stderr.write(L('cli.common.ambiguousPeer', { peer: wanted, count: matches.length }) + '\n');
    for (const [peerId, peer] of matches) {
      process.stderr.write('  ' + (peer?.name || L('cli.common.unnamed')) + '\t' + peerId + '\t'
        + (peer?.baseUrl || L('cli.common.inboundOnly')) + '\n');
    }
    process.exitCode = 2;
    return;
  }
  const [peerId, peer] = matches[0];
  const label = peer?.name || peerId;

  const remote = args['local-only']
    ? { notified: false, reason: L('cli.unpair.skippedRemote') }
    : await notifyUnpair({
        peer,
        senderId: identity(dir).instanceId,
        timeoutSec: Math.max(1, Number(args.timeout) || 10),
      });

  // Re-read before writing: a running host may have touched peers.json meanwhile.
  const fresh = readJson(path.join(dir, 'peers.json'), { peers: {} });
  if (fresh.peers && peerId in fresh.peers) {
    delete fresh.peers[peerId];
    writeJson(path.join(dir, 'peers.json'), fresh);
  }

  console.log(remote.notified
    ? L('cli.unpair.doneRemote', { label })
    : L('cli.unpair.doneLocal', { label, reason: remote.reason || L('cli.common.unknown') }));
}

// ---------------------------------------------------------------------------
// group（v0.5.0 Phase1）：成员侧只发签名+加密请求，hub 端点在 host/server.mjs
// ---------------------------------------------------------------------------

/** 解析要连的 hub：--peer 可给名字或 peerId；只有一个伙伴时自动采用 */
function resolveHubPeer(dir, wanted) {
  const entries = Object.entries(readJson(path.join(dir, 'peers.json'), { peers: {} }).peers || {});
  const target = String(wanted ?? '').trim();
  if (target === '') {
    if (entries.length === 1) return { peerId: entries[0][0], peer: entries[0][1] };
    const candidates = entries.map(([, peer]) => String(peer?.name ?? '?')).join(' / ');
    throw new Error(
      L('cli.group.needPeer')
        + (candidates ? L('cli.group.needPeerCandidates', { list: candidates }) : L('cli.group.needPeerEmpty'))
        + '\n' + L('cli.help.group'),
    );
  }
  const matches = entries.filter(([peerId, peer]) => peerId === target || String(peer?.name ?? '') === target);
  if (matches.length === 0) throw new Error(L('cli.common.unknownPeer', { peer: target }) + '\n' + L('cli.help.group'));
  if (matches.length > 1) {
    throw new Error(
      L('cli.common.ambiguousPeer', { peer: target, count: matches.length }) + '\n'
        + matches.map(([peerId, peer]) => '  ' + (peer?.name || L('cli.common.unnamed')) + '\t' + peerId).join('\n'),
    );
  }
  return { peerId: matches[0][0], peer: matches[0][1] };
}

/** 一行一条消息：seq / 时间 / 来源 / kind / 正文 / meta */
function formatGroupMessage(message) {
  const when = new Date(Number(message?.ts) || 0).toISOString();
  const from = message?.from?.name || message?.from?.peerId || '?';
  const meta = message?.meta && Object.keys(message.meta).length
    ? ' ' + Object.entries(message.meta).map(([key, value]) => key + '=' + value).join(' ')
    : '';
  const body = String(message?.text ?? '');
  return '#' + message.seq + ' ' + when + ' ' + from + ' [' + message.kind + ']' + (body ? ' ' + body : '') + meta;
}

const groupTarget = (dir, args) => {
  const { peer } = resolveHubPeer(dir, args.peer);
  return {
    baseUrl: String(peer.baseUrl ?? '').replace(/\/+$/, ''),
    secret: peer.secret,
    senderId: identity(dir).instanceId,
  };
};

/**
 * leader 是谁、在哪（v0.8.0 真机回归）。
 *
 * 写操作只有 leader 能落库，所以**先定 leader，再决定用哪条通道**：
 * group-key.json 的 leaderPeerId（缺失则 hub.peerId）→ members[leader].baseUrl（缺失则 hub.baseUrl）。
 */
function leaderIdentity(dir) {
  const keyFile = readGroupKeyFile(dir);
  if (!keyFile) return null;
  const leaderId = String(keyFile.leaderPeerId ?? '') || String(keyFile.hub?.peerId ?? '');
  const member = leaderId === '' ? null : (keyFile.members?.[leaderId] ?? null);
  const memberUrl = String(member?.baseUrl ?? '').replace(/\/+$/, '');
  const hubUrl = String(keyFile.hub?.baseUrl ?? '').replace(/\/+$/, '');
  return {
    peerId: leaderId,
    name: String(member?.name ?? keyFile.hub?.name ?? ''),
    baseUrl: memberUrl || hubUrl,
    hubUrl,
  };
}

/** 本机是否持有某个 peer 的 per-peer 密钥（peers.json 里那条要能签名） */
function pairedPeer(dir, peerId) {
  const id = String(peerId ?? '');
  if (id === '') return null;
  const peer = peerEntries(dir).find((entry) => entry.peerId === id && entry.baseUrl !== '');
  return peer?.secret ? peer : null;
}

/**
 * 「只有群密钥」的通道（v0.8.0 真机回归）：按名入群的节点握着 group-key.json 里的群密钥，
 * 但可能**没有** leader 的 per-peer 密钥。这种节点只能走群级签名。
 *
 * baseUrl 可显式覆盖（通常是 leader 的地址）——优先打 leader，而不是「随便哪个伙伴」。
 */
function groupKeyTransport(dir, { baseUrl = '' } = {}) {
  const keyFile = readGroupKeyFile(dir);
  if (!keyFile || !keyFile.key) return null;
  const leader = leaderIdentity(dir);
  const wanted = String(baseUrl ?? '').replace(/\/+$/, '');
  const peers = peerEntries(dir);
  const leaderId = String(leader?.peerId ?? '');
  const targetUrl = wanted
    || String(leader?.baseUrl ?? '')
    || String(keyFile.hub?.baseUrl ?? '').replace(/\/+$/, '')
    || String(peers.find((peer) => peer.peerId === leaderId)?.baseUrl ?? '')
    || String(keyFile.members?.[leaderId]?.baseUrl ?? '').replace(/\/+$/, '');
  if (targetUrl === '') return null;
  const hubId = leaderId || String(keyFile.hub?.peerId ?? '');
  return {
    baseUrl: targetUrl,
    groupKey: keyFile.key,
    groupId: keyFile.groupId,
    senderId: identity(dir).instanceId,
    hubId,
    hubName: String(leader?.name ?? keyFile.hub?.name ?? keyFile.members?.[hubId]?.name ?? ''),
    // 群名（probe 返回的 name 是 hub 的**设备名**，不是群名）
    groupName: normalizeGroupName(keyFile.groupName),
    members: keyFile.members ?? {},
  };
}

/**
 * 选通道（读路径与写路径共用一套优先级）：
 *   1. 显式 --peer：用户强制指定，就按指定目标走 per-peer（旧行为不变）；
 *   2. 本机持有 **leader** 的 per-peer 密钥 → per-peer 打 leader；
 *   3. 否则（有 group-key）→ 群级签名打 leader 的 baseUrl（leader 地址缺失回落 hub.baseUrl）；
 *   4. 没有 group-key（纯 1:1 节点）→ 旧逻辑：唯一的伙伴、per-peer。
 *
 * 真机教训：v0.8.0 早期版本「只要能解析出一个伙伴就走 per-peer」，
 * 于是按名入群的成员把写请求发给了唯一配对的**非 leader 成员**，被 404 not-leader 挡下。
 */
function resolveGroupChannel(dir, args = {}) {
  const explicit = String(args.peer ?? '').trim();
  if (explicit !== '') {
    return { mode: 'peer', peer: groupTarget(dir, args), key: groupKeyTransport(dir), reason: 'explicit-peer' };
  }
  const keyFile = readGroupKeyFile(dir);
  if (!keyFile) {
    return { mode: 'peer', peer: groupTarget(dir, args), key: null, reason: 'no-group-key' };
  }
  const leader = leaderIdentity(dir);
  const leaderPeer = pairedPeer(dir, leader?.peerId);
  if (leaderPeer) {
    return {
      mode: 'peer',
      peer: {
        baseUrl: leaderPeer.baseUrl || String(leader?.baseUrl ?? ''),
        secret: leaderPeer.secret,
        senderId: identity(dir).instanceId,
      },
      key: groupKeyTransport(dir),
      reason: 'leader-paired',
    };
  }
  const key = groupKeyTransport(dir);
  if (key) return { mode: 'group', peer: null, key, reason: 'leader-group-auth' };
  // 兜底：连 leader 的地址都没有 → 回到旧行为，让调用方拿到明确报错
  return { mode: 'peer', peer: groupTarget(dir, args), key: null, reason: 'fallback' };
}

/** state/history 的连接选择：与写路径同一套优先级（避免打给不可达的非 leader） */
function resolveGroupConnection(dir, args = {}) {
  try {
    return resolveGroupChannel(dir, args);
  } catch (error) {
    const key = groupKeyTransport(dir);
    if (!key) throw error;
    return { mode: 'group', peer: null, key };
  }
}

/** 发言通道：与读路径同一套优先级（写操作只有 leader 能落库） */
function resolvePostChannel(dir, args = {}) {
  try {
    return resolveGroupChannel(dir, args);
  } catch (error) {
    const key = groupKeyTransport(dir);
    if (!key) throw error;
    return { mode: 'group', peer: null, key };
  }
}

const groupSince = (args) => Math.max(0, Math.floor(Number(args.since ?? 0) || 0));

async function cmdGroupState(dir, args) {
  const { mode, peer, key } = resolveGroupConnection(dir, args);
  if (mode === 'peer') {
    const state = await fetchGroupState(peer);
    console.log(L('cli.group.stateHeaderPeer', {
      name: state.name,
      groupId: state.groupId,
      epoch: state.epoch,
      keyVersion: state.keyVersion,
      members: state.members.length,
    }));
    for (const member of state.members) {
      console.log(
        '  ' + (member.name || L('cli.common.unnamed')) + '\t' + member.peerId
          + '\t' + (member.online ? 'online' : 'offline')
          + '\tjoinedAt=' + (member.joinedAt ?? '?'),
      );
    }
    // 密钥本身永远不打印：只说「拿到了」
    const keyBytes = state.groupKey ? Buffer.from(String(state.groupKey), 'base64url').length : 0;
    console.log(L('cli.group.groupKeyLine', { value: keyBytes === 32 ? L('cli.group.groupKeyReceived') : L('cli.group.groupKeyNotSent') }));
    return;
  }
  // 只有群密钥（或 leader 没有配对记录）：probe 给世代/leader/lastSeq，pull 给成员表
  const probe = await probeGroupPeer({
    baseUrl: key.baseUrl,
    groupKey: key.groupKey,
    groupId: key.groupId,
    senderId: key.senderId,
  });
  const page = await pullGroupMessages({
    baseUrl: key.baseUrl,
    groupKey: key.groupKey,
    groupId: key.groupId,
    senderId: key.senderId,
    sinceSeq: 0,
    limit: 1,
  });
  const memberIds = Array.isArray(page?.memberIds) && page.memberIds.length > 0
    ? page.memberIds
    : Object.keys(key.members);
  console.log(L('cli.group.stateHeaderKey', {
    name: key.groupName || String(probe?.name ?? key.hubName ?? ''),
    groupId: String(probe?.groupId ?? key.groupId),
    epoch: probe?.epoch ?? 0,
    members: memberIds.length,
    baseUrl: key.baseUrl,
    leader: key.hubName || key.hubId.slice(0, 8),
  }));
  for (const peerId of memberIds) {
    const name = String(key.members?.[peerId]?.name ?? '');
    console.log('  ' + (name || L('cli.common.unnamed')) + '\t' + peerId
      + '\t' + (peerId === key.senderId ? L('cli.group.memberSelf') : ''));
  }
  console.log(L('cli.group.groupKeyLine', { value: L('cli.group.groupKeyOnDisk') }));
}

/** 发一条群消息（作者侧只负责投递；0.10.0-α 起群内派单已移除，不再有派单副作用）。 */
async function postGroupText(dir, args, text) {
  if (!text) throw new Error(L('cli.help.group'));
  if (Array.from(text).length > GROUP_TEXT_MAX_CHARS) {
    throw new Error(L('cli.group.textTooLong', { max: GROUP_TEXT_MAX_CHARS }));
  }
  const kind = String(args.kind ?? 'chat');
  if (!GROUP_KINDS.includes(kind)) throw new Error(L('cli.group.badKind', { kinds: GROUP_KINDS.join(' / ') }));
  const channel = resolvePostChannel(dir, args);
  const sent = channel.mode === 'peer'
    ? await postGroup({ ...channel.peer, kind, text })
    : await postGroupWithGroupKey({
      baseUrl: channel.key.baseUrl,
      groupKey: channel.key.groupKey,
      groupId: channel.key.groupId,
      senderId: channel.key.senderId,
      kind,
      text,
    });
  console.log(L('cli.group.sent', {
    seq: sent.seq,
    ts: new Date(Number(sent.ts)).toISOString(),
    channel: channel.mode === 'group' ? L('cli.group.sentViaGroupKey', { baseUrl: channel.key.baseUrl }) : '',
  }));
}

async function cmdGroupPost(dir, args) {
  const text = String(args.text ?? args._.slice(1).join(' ') ?? '').trim();
  await postGroupText(dir, args, text);
}

async function cmdGroupHistory(dir, args) {
  const { mode, peer, key } = resolveGroupConnection(dir, args);
  const limit = Math.min(Math.max(1, Math.floor(Number(args.limit ?? 200) || 200)), 200);
  const since = groupSince(args);
  if (mode === 'peer') {
    const page = await fetchGroupHistory({ ...peer, sinceSeq: since, limit });
    for (const message of page.messages) console.log(formatGroupMessage(message));
    process.stderr.write(L('cli.group.historyPeer', {
      groupId: page.groupId,
      count: page.messages.length,
      lastSeq: page.lastSeq,
    }) + '\n');
    return;
  }
  // 只有群密钥：/v1/group/pull 是群级白名单里的读路径，语义与 history 一致（按 seq 补差）
  const page = await pullGroupMessages({
    baseUrl: key.baseUrl,
    groupKey: key.groupKey,
    groupId: key.groupId,
    senderId: key.senderId,
    sinceSeq: since,
    limit,
  });
  const messages = Array.isArray(page?.messages) ? page.messages : [];
  for (const message of messages) console.log(formatGroupMessage(message));
  process.stderr.write(L('cli.group.historyKey', {
    groupId: String(page?.groupId ?? key.groupId),
    count: messages.length,
    lastSeq: page?.lastSeq ?? 0,
    baseUrl: key.baseUrl,
  }) + '\n');
}

async function cmdGroupTail(dir, args) {
  const target = groupTarget(dir, args);
  const since = groupSince(args);
  const durationMs = Math.max(1000, Number(args.duration ?? 60) * 1000);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error('duration-reached')), durationMs);
  process.stderr.write(L('cli.group.tailSubscribed', { since, seconds: Math.round(durationMs / 1000) }) + '\n');
  const out = await readGroupEvents({
    ...target,
    sinceSeq: since,
    signal: controller.signal,
    timeoutMs: durationMs + 5000,
    onMessage: (message) => console.log(formatGroupMessage(message)),
  });
  clearTimeout(timer);
  if (!out.ok && !out.aborted && out.reason !== 'stream-ended') {
    process.stderr.write(L('cli.events.ended', { reason: out.reason }) + '\n');
    process.exitCode = 1;
    return;
  }
  process.stderr.write(L('cli.group.tailEnded', { lastSeq: out.lastSeq }) + '\n');
}

async function cmdGroupJoin(dir, args) {
  const target = groupTarget(dir, args);
  // --name 只改本机在群里的显示名（hub 侧只允许写自己那一条）
  const name = typeof args.name === 'string' ? args.name.trim() : '';
  if (args.name != null && name === '') throw new Error(L('cli.group.joinNameEmpty') + '\n' + L('cli.help.group'));
  try {
    const joined = await joinGroup({ ...target, name });
    console.log(L('cli.group.joined', {
      groupId: joined.groupId,
      epoch: joined.epoch,
      name: joined.name ? L('cli.group.joinedName', { name: joined.name }) : '',
    }));
  } catch (error) {
    const text = String(error?.message ?? error);
    if (text.includes('403')) {
      process.stderr.write(L('cli.group.joinForbidden') + '\n');
      process.exitCode = 2;
      return;
    }
    throw error;
  }
}

/**
 * group probe：有本地群密钥（group-key.json）时走群级签名，否则回退 per-peer 签名。
 * 两条通道都由 host/server.mjs 的同一个端点处理，输出一致。
 */
async function cmdGroupProbe(dir, args) {
  const { peer } = resolveHubPeer(dir, args.peer);
  const baseUrl = String(peer.baseUrl ?? '').replace(/\/+$/, '');
  if (baseUrl === '') throw new Error(L('cli.group.probeNoAddress'));
  const senderId = identity(dir).instanceId;
  const localKey = readGroupKeyFile(dir);
  const info = localKey
    ? await probeGroupPeer({ baseUrl, groupKey: localKey.key, groupId: localKey.groupId, senderId })
    : await signedCall({ baseUrl, secret: peer.secret, senderId, method: 'GET', apiPath: '/v1/group/probe' });
  console.log(L('cli.group.probeLine', {
    name: info?.name || peer.name || '?',
    peerId: info?.peerId || '?',
    epoch: info?.epoch ?? 0,
    lastSeq: info?.lastSeq ?? 0,
  }));
  console.log(L('cli.group.probeAddress', { url: info?.advertiseBaseUrl || L('cli.group.probeNoPrivate') }));
  console.log(L('cli.group.probeGroup', {
    groupId: info?.groupId || '-',
    leader: info?.leaderPeerId || '-',
  }));
}

/** group replica：只读本地 <stateDir>/group-replica.json，不联网 */
function cmdGroupReplica(dir) {
  const file = path.join(dir, GROUP_REPLICA_FILE);
  const replica = readJson(file, null);
  if (!replica) {
    console.log(L('cli.group.replicaMissing', { file }));
    return;
  }
  const messages = Array.isArray(replica.messages) ? replica.messages : [];
  console.log(L('cli.group.replicaLine', {
    groupId: replica.groupId || '-',
    epoch: replica.epoch ?? 0,
    leader: replica.leaderPeerId || '-',
    lastSeq: replica.lastSeq ?? 0,
    count: messages.length,
  }));
  console.log(L('cli.group.replicaFile', { file }));
}

/**
 * group leader：只读本机 <stateDir>/group-role.json（角色/epoch/leader/租约）。
 * 给了 --peer 时再打一次对端的 GET /v1/group/lease（群级签名），看对端 live 快照。
 */
async function cmdGroupLeader(dir, args) {
  const role = readGroupRoleFile(dir);
  if (!role) {
    console.log(L('cli.group.roleMissing', { file: path.join(dir, GROUP_ROLE_FILE) }));
  } else {
    const remaining = role.leaseUntil > 0 ? Math.max(0, role.leaseUntil - Date.now()) : 0;
    const degraded = role.leaderPeerId === '' || Date.now() > role.leaseUntil;
    console.log(L('cli.group.roleLine', {
      role: role.role,
      epoch: role.epoch,
      leader: role.leaderPeerId || '-',
      commitSeq: role.commitSeq,
      remaining,
      degraded: degraded ? L('cli.group.degraded') : '',
    }));
  }
  if (args.peer == null) return;
  const { peer } = resolveHubPeer(dir, args.peer);
  const baseUrl = String(peer.baseUrl ?? '').replace(/\/+$/, '');
  const localKey = readLocalGroupKey(dir);
  if (!localKey) throw new Error(L('cli.group.noGroupKeyLease'));
  const senderId = identity(dir).instanceId;
  const remote = await fetchGroupLease({
    baseUrl,
    groupKey: localKey.key,
    groupId: localKey.groupId,
    senderId,
  });
  console.log(L('cli.group.leaseLine', {
    name: peer.name || peer.peerId,
    role: remote?.role ?? '?',
    epoch: remote?.epoch ?? '?',
    leader: remote?.leaderPeerId || '-',
    commitSeq: remote?.commitSeq ?? '?',
    pending: remote?.pendingCount ?? '?',
    quorum: remote?.quorum ?? '?',
    degraded: remote?.degraded ? L('cli.group.degraded') : '',
  }));
}

/**
 * group claim：手动接管。
 * 打本机 host 的回环地址（群级签名），body 里 candidate 就是本机实例 id ——
 * host 收到「本机自称候选」会立刻发起一轮选举，票数够就接任 leader（契约 §7）。
 */
async function cmdGroupClaim(dir, args) {
  const baseUrl = String(args.url ?? 'http://127.0.0.1:7788').replace(/\/+$/, '');
  const localKey = readLocalGroupKey(dir);
  if (!localKey) throw new Error(L('cli.group.noGroupKeyClaim'));
  const senderId = identity(dir).instanceId;
  const local = readGroupRoleFile(dir);
  const epoch = Math.max(1, (local?.epoch ?? 0) + 1);
  const reply = await requestGroupVote({
    baseUrl,
    groupKey: localKey.key,
    groupId: localKey.groupId,
    senderId,
    epoch,
    candidate: senderId,
  });
  if (reply?.vote === true && String(reply?.role ?? '') === 'leader') {
    console.log(L('cli.group.claimOk', { epoch: reply.epoch ?? epoch, senderId }));
    return;
  }
  process.stderr.write(L('cli.group.claimFailed', {
    reason: reply?.reason || 'vote-refused',
    votes: reply?.votes ?? '?',
    needed: reply?.needed ?? '?',
    memberCount: reply?.memberCount ?? '?',
  }) + '\n');
  // 契约 §3：落败者回到 follower 并更新 epoch —— 运维要立刻知道本机已经降级
  process.stderr.write(L('cli.group.claimDemoted', {
    role: reply?.role || 'follower',
    epoch: reply?.epoch ?? '?',
  }) + '\n');
  process.exitCode = 2;
}


// ---------------------------------------------------------------------------
// v0.8.0-β 归档（DESIGN §18.2）：只归档、不自动删除，删不删由人决定。
// 两个子命令都只打本机回环的 hub 管理接口 /api/lan-peers/group/archives，
// CLI 自己不去碰 stateDir 下的归档文件（那里只有 host 知道怎么读怎么写）。
// ---------------------------------------------------------------------------

const ADMIN_TIMEOUT_MS = 10000;
// S3：管理接口要 X-Lan-Peers-Token。host 启动时把它写到 <stateDir>/admin-token（0600），
// CLI 只读不写；token 本身绝不出现在 URL、日志或错误消息里（只说去哪读）。
const ADMIN_TOKEN_FILE = 'admin-token';
// 真机缺陷修复：管理接口挂在 **DSH web 端口**（NAS 3080、桌面每次重启还会变），而 7788 是
// peer 端口 —— 不带 --url 时打 7788 必然 404 not-found。所以地址由 admin 侧在收到回环管理
// 请求时记进 <stateDir>/admin-url（0600），CLI 只读不写；**这不是安全边界**，token 才是。
const ADMIN_URL_FILE = 'admin-url';

function readAdminToken(dir) {
  try {
    return fs.readFileSync(path.join(String(dir || DEFAULT_STATE_DIR), ADMIN_TOKEN_FILE), 'utf8').trim();
  } catch {
    return '';
  }
}

function readAdminUrl(dir) {
  try {
    return fs.readFileSync(path.join(String(dir || DEFAULT_STATE_DIR), ADMIN_URL_FILE), 'utf8').trim();
  } catch {
    return '';
  }
}

/**
 * 管理接口地址：`--url` → `<stateDir>/admin-url` → 报错。
 * 绝不静默回落到 peer 端口（那是一条必然 404 的路，比报错更难查）。
 */
function resolveAdminUrl(dir, args = {}) {
  const explicit = String(args.url ?? '').trim();
  if (explicit !== '') return explicit.replace(/\/+$/, '');
  const saved = readAdminUrl(dir);
  if (saved !== '') return saved.replace(/\/+$/, '');
  throw new Error(L('cli.admin.noUrl', {
    file: path.join(String(dir || DEFAULT_STATE_DIR), ADMIN_URL_FILE),
  }));
}

/** 打本机回环管理接口；非 2xx 抛 `<status> <error>` 形式的 Error（与 group-client 同款）。 */
async function adminCall(baseUrl, apiPath, init, dir) {
  const base = resolveAdminUrl(dir || DEFAULT_STATE_DIR, { url: baseUrl });
  const token = readAdminToken(dir);
  const headers = { ...(init && init.headers ? init.headers : {}) };
  if (token !== '') headers['X-Lan-Peers-Token'] = token;
  let reply;
  try {
    reply = await fetch(base + '/api/lan-peers/' + apiPath, {
      ...init,
      headers,
      signal: AbortSignal.timeout(ADMIN_TIMEOUT_MS),
    });
  } catch (error) {
    // 桌面每次重启 web 端口都会变：admin-url 里的地址可能已经过期，这里必须说清怎么刷新。
    throw new Error(L('cli.admin.unreachable', {
      base,
      reason: String(error?.message ?? error),
      file: path.join(String(dir || DEFAULT_STATE_DIR), ADMIN_URL_FILE),
    }));
  }
  const body = await reply.json().catch(() => ({}));
  if (!reply.ok) {
    const status = reply.status;
    const where = path.join(String(dir || DEFAULT_STATE_DIR), ADMIN_TOKEN_FILE);
    // 401 一定是 token 缺失/不匹配：直接指路（host 启动时写入，权限 0600）。
    const hint = status === 401 ? L('cli.admin.tokenHint', { file: where }) : '';
    throw new Error(status + ' ' + String(body.error || 'admin-call-failed') + hint);
  }
  return body;
}

/** 归档接口的失败口径：403/409 是「本机现在做不了这件事」（exit 2），其余算失败（exit 1）。 */
function reportArchiveError(error) {
  const text = String(error && error.message ? error.message : error);
  process.stderr.write(L('cli.group.archiveFailed', { text }) + '\n');
  process.exitCode = /^40[39]\b/.test(text) ? 2 : 1;
}

async function cmdGroupArchives(dir, args) {
  let out;
  try {
    out = await adminCall(args.url, 'group/archives', undefined, dir);
  } catch (error) {
    reportArchiveError(error);
    return;
  }
  const list = Array.isArray(out?.archives) ? out.archives : [];
  if (list.length === 0) {
    console.log(L('cli.group.archiveEmpty'));
    return;
  }
  const sum = list.reduce((total, item) => total + (Number(item?.bytes) || 0), 0);
  const total = Number.isFinite(Number(out?.totalBytes)) ? Number(out.totalBytes) : sum;
  for (const item of list) {
    const from = item?.fromSeq == null ? '—' : item.fromSeq;
    const to = item?.toSeq == null ? '—' : item.toSeq;
    const count = item?.count == null ? '?' : item.count;
    console.log(L('cli.group.archiveRow', {
      file: String(item?.file ?? L('cli.group.archiveUnnamed')),
      from,
      to,
      count,
      bytes: Number(item?.bytes) || 0,
      createdAt: String(item?.createdAt ?? '?'),
    }));
  }
  process.stderr.write(L('cli.group.archivesTotal', { count: list.length, bytes: total }) + '\n');
}

async function cmdGroupArchiveDelete(dir, args) {
  const file = String(args._[1] ?? args.file ?? '').trim();
  if (file === '') throw new Error(L('cli.group.archiveDeleteUsage') + '\n' + L('cli.help.group'));
  let out;
  try {
    out = await adminCall(args.url, 'group/archives', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ file: file, action: 'delete' }),
    }, dir);
  } catch (error) {
    reportArchiveError(error);
    return;
  }
  const removed = Number(out?.removedBytes);
  console.log(L('cli.group.archiveDeleted', {
    file,
    released: Number.isFinite(removed) && removed > 0 ? L('cli.group.archiveReleased', { bytes: removed }) : '',
  }));
}


// ---------------------------------------------------------------------------
// v0.8.0 群名发现 / 按名申请 / 手动广播（契约 §2/§3/§4）
// ---------------------------------------------------------------------------

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, Math.max(0, Number(ms) || 0)));

/** 伙伴列表（含 secret；广播/查找只用到 baseUrl + secret） */
function peerEntries(dir) {
  const store = readJson(path.join(dir, 'peers.json'), { peers: {} });
  return Object.entries(store.peers || {}).map(([peerId, peer]) => ({
    peerId,
    name: String(peer?.name ?? ''),
    baseUrl: String(peer?.baseUrl ?? '').replace(/\/+$/, ''),
    secret: peer?.secret,
    inboundSecret: peer?.inboundSecret,
  }));
}

/**
 * 本机的群身份（只读 state-dir，不联网、不打印密钥）：
 * hub 读 group.json，成员读 group-key.json；hub 地址取成员表里自报的那个。
 */
function localGroupIdentity(dir, args = {}) {
  const self = identity(dir);
  const memberFile = readGroupKeyFile(dir);
  const hubFile = readJson(path.join(dir, 'group.json'), null);
  const peers = Object.fromEntries(peerEntries(dir).map((peer) => [peer.peerId, peer]));
  const hubUrlOption = String(args['hub-url'] ?? '').replace(/\/+$/, '');

  if (hubFile && hubFile.groupId) {
    const hubId = self.instanceId;
    const member = (hubFile.members || {})[hubId] || null;
    const name = normalizeGroupName(hubFile.name) || 'default';
    const groupId = String(hubFile.groupId);
    const hub = {
      peerId: hubId,
      name: self.name,
      baseUrl: hubUrlOption || String(member?.baseUrl ?? '').replace(/\/+$/, ''),
    };
    return {
      groupId,
      name,
      hub,
      member: { peerId: hubId, name: self.name },
      group: { groupId, name, hub, members: Object.keys(hubFile.members || {}) },
    };
  }
  if (memberFile && memberFile.groupId) {
    const hubId = String(memberFile.leaderPeerId ?? '');
    const hubMember = (memberFile.members || {})[hubId] || null;
    const peer = peers[hubId] || null;
    // 成员侧群名只认 group-key.json 的 groupName（0.7.x 老文件为空 → 由
    // resolveLocalIdentity() 向 hub 现取）；绝不回落配置默认值 'default'。
    const name = normalizeGroupName(memberFile.groupName);
    const groupId = String(memberFile.groupId);
    const hub = {
      peerId: hubId,
      name: String(hubMember?.name ?? peer?.name ?? ''),
      baseUrl: hubUrlOption || String(hubMember?.baseUrl ?? peer?.baseUrl ?? '').replace(/\/+$/, ''),
    };
    return {
      groupId,
      name,
      hub,
      member: { peerId: self.instanceId, name: self.name },
      group: { groupId, name, hub, members: Object.keys(memberFile.members || {}) },
    };
  }
  return null;
}

/**
 * 群身份（带群名自愈）：本地 groupName 为空时向 hub 取一次权威群名并回写。
 * 拿不到就保持空串 —— 调用方必须报 unknown，不许拿配置默认值冒充真群名。
 */
async function resolveLocalIdentity(dir, args = {}) {
  // 注意变量名别叫 identity：那会遮住模块级 identity(dir)（本机身份读取函数）
  const group = localGroupIdentity(dir, args);
  if (!group || group.name !== '') return group;
  const hubPeer = peerEntries(dir).find((peer) => peer.peerId === group.hub?.peerId) ?? null;
  const resolved = await resolveGroupName({
    stateDir: dir,
    hub: hubPeer ? { baseUrl: hubPeer.baseUrl, secret: hubPeer.secret } : null,
    senderId: identity(dir).instanceId,
  }).catch(() => ({ name: '' }));
  if (resolved.name === '') return group;
  return { ...group, name: resolved.name, group: { ...group.group, name: resolved.name } };
}

/** 本地命中：本机自己的群 + 本地 known-groups（两步都不联网） */
async function localMatches(dir, wanted, args = {}) {
  const matches = [];
  const own = await resolveLocalIdentity(dir, args);
  if (own && sameGroupName(own.name, wanted)) {
    matches.push({ groupId: own.groupId, name: own.name, hub: own.hub, via: own.member });
  }
  for (const [groupId, entry] of Object.entries(readKnownGroups(dir).groups)) {
    if (matches.some((match) => match.groupId === groupId)) continue;
    if (!sameGroupName(entry.name, wanted)) continue;
    matches.push({ groupId, name: entry.name, hub: entry.hub, via: entry.source });
  }
  return matches;
}

/**
 * 契约 §3 的查找顺序：先本地 known-groups，未命中再向所有伙伴并发 lookup（2 秒超时）。
 * 命中结果顺手记进 known-groups，下次查找不用再联网。
 */
async function findGroupMatches(dir, rawName, args = {}) {
  const wanted = normalizeGroupName(rawName);
  if (wanted === '') throw new Error(L('cli.find.needName') + '\n' + L('cli.help.group'));
  const local = await localMatches(dir, wanted, args);
  if (local.length > 0) return { matches: local, source: 'local', failed: [] };
  const peers = peerEntries(dir).filter((peer) => peer.baseUrl !== '');
  if (peers.length === 0) return { matches: [], source: 'local', failed: [] };
  const out = await lookupGroupNameEverywhere({
    peers,
    name: wanted,
    timeoutMs: Number(args['lookup-timeout'] ?? GROUP_LOOKUP_TIMEOUT_MS),
  });
  for (const match of out.matches) {
    try {
      rememberKnownGroup({
        stateDir: dir,
        groupId: match.groupId,
        name: match.name,
        hub: match.hub,
        source: match.via,
      });
    } catch {
      /* 落盘失败不影响本次查找 */
    }
  }
  return { matches: out.matches, source: 'peers', failed: out.failed ?? [], peers: peers.length };
}

function printMatches(matches) {
  for (const match of matches) {
    process.stdout.write(L('cli.find.matchLine', {
      name: match.name || L('cli.common.unnamed'),
      groupId: String(match.groupId ?? '').slice(0, 8),
      hub: match.hub?.name || String(match.hub?.peerId ?? '').slice(0, 8) || '?',
      via: match.via?.name || String(match.via?.peerId ?? '').slice(0, 8) || '?',
    }) + '\n');
  }
}

async function cmdGroupFind(dir, args) {
  const found = await findGroupMatches(dir, args.name, args);
  if (found.matches.length === 0) {
    process.stderr.write(L('cli.find.notFound', {
      name: normalizeGroupName(args.name),
      peers: found.peers ?? 0,
    }) + '\n');
    process.exitCode = 2;
    return;
  }
  if (found.source === 'local') process.stderr.write(L('cli.find.localHit') + '\n');
  printMatches(found.matches);
  if (found.matches.length > 1) {
    process.stderr.write(L('cli.find.multiHit', { count: found.matches.length }) + '\n');
  }
  for (const failure of found.failed) {
    process.stderr.write(L('cli.find.failure', { name: failure.name || failure.peerId, reason: failure.reason }) + '\n');
  }
}

async function cmdGroupApply(dir, args) {
  const wanted = normalizeGroupName(args.name);
  if (wanted === '') throw new Error(L('cli.find.needName') + '\n' + L('cli.help.group'));
  const self = identity(dir);
  const found = await findGroupMatches(dir, wanted, args);
  if (found.matches.length === 0) {
    process.stderr.write(L('cli.apply.notFound', { name: wanted }) + '\n');
    process.exitCode = 2;
    return;
  }
  let match = found.matches[0];
  if (found.matches.length > 1) {
    const wantedTarget = String(args.peer ?? args.group ?? '').trim();
    const picked = wantedTarget === ''
      ? null
      : found.matches.find((entry) => entry.via?.peerId === wantedTarget
        || entry.via?.name === wantedTarget
        || entry.groupId === wantedTarget
        || String(entry.groupId).slice(0, 8) === wantedTarget);
    if (!picked) {
      process.stderr.write(L('cli.apply.multiHit', { count: found.matches.length }) + '\n');
      printMatches(found.matches);
      process.exitCode = 2;
      return;
    }
    match = picked;
  }
  const introducer = peerEntries(dir).find((peer) => peer.peerId === match.via?.peerId) ?? null;
  if (!introducer) {
    throw new Error(L('cli.apply.introducerMissing', { peerId: String(match.via?.peerId ?? '').slice(0, 8) }));
  }
  const intervalMs = Math.max(200, Number(args.interval ?? GROUP_APPLY_POLL_INTERVAL_MS) || GROUP_APPLY_POLL_INTERVAL_MS);
  const budgetMs = Math.max(1, Number(args.timeout ?? 0) > 0
    ? Number(args.timeout) * 1000
    : GROUP_APPLY_POLL_TIMEOUT_MS);
  const target = {
    baseUrl: introducer.baseUrl,
    secret: introducer.secret,
    senderId: self.instanceId,
    groupId: match.groupId,
  };
  const applicant = {
    peerId: self.instanceId,
    name: String(self.name ?? ''),
    baseUrl: String(args['base-url'] ?? '').replace(/\/+$/, ''),
  };
  const applied = await applyToGroup({ ...target, applicant });
  if (applied.status === 'rejected') {
    process.stderr.write(L('cli.apply.rejected', { reason: applied.reason || 'rejected' }) + '\n');
    process.exitCode = 2;
    return;
  }
  process.stdout.write(L('cli.apply.submitted', {
    via: match.via?.name || String(match.via?.peerId).slice(0, 8),
    name: match.name || wanted,
    groupId: String(match.groupId).slice(0, 8),
    status: applied.status,
  }) + '\n');

  const deadline = Date.now() + budgetMs;
  let polls = 0;
  let lastStatus = applied.status;
  let failures = 0;
  while (Date.now() < deadline) {
    // 第一次立刻查一次：autoJoin 的 hub 此时已经批完
    if (polls > 0) await sleep(intervalMs);
    polls += 1;
    let polled;
    try {
      polled = await pollApplication(target);
      failures = 0;
    } catch (error) {
      // 轮询期间的网络抖动不该让申请作废：记一行、按节奏继续等（契约 §5.2 的 10 分钟窗口）
      failures += 1;
      if (failures <= 3) {
        process.stderr.write(L('cli.apply.pollFailed', {
          attempt: failures,
          reason: String(error?.message ?? error).slice(0, 80),
        }) + '\n');
      }
      continue;
    }
    lastStatus = polled.status;
    if (polled.status === 'rejected') {
      process.stderr.write(L('cli.apply.rejected', { reason: polled.reason || 'rejected' }) + '\n');
      process.exitCode = 2;
      return;
    }
    if (polled.status === 'approved' && polled.grant) {
      const written = applyGroupGrant(dir, polled.grant);
      const memberCount = Object.keys(written.members || {}).length;
      process.stdout.write(L('cli.apply.granted', {
        name: normalizeGroupName(polled.grant.name) || match.name,
        groupId: String(written.groupId).slice(0, 8),
        keyVersion: Number(polled.grant.keyVersion ?? polled.grant.epoch) || written.epoch,
        members: memberCount,
      }) + '\n');
      await broadcastOwnGroupName(dir, args, { quiet: true });
      return;
    }
    if (polled.status === 'approved') {
      process.stdout.write(L('cli.apply.alreadyMember') + '\n');
      return;
    }
  }
  process.stderr.write(L('cli.apply.pending', {
    seconds: Math.round(budgetMs / 1000),
    status: lastStatus,
    name: wanted,
  }) + '\n');
  process.exitCode = 2;
}

/** 手动广播：把本机群名发给所有非成员伙伴（无节流），返回并打印对象清单 */
async function broadcastOwnGroupName(dir, args = {}, { quiet = false } = {}) {
  const own = await resolveLocalIdentity(dir, args);
  if (!own) throw new Error(L('cli.advertise.noGroup'));
  const override = normalizeGroupName(args.name);
  if (override !== '') own.name = override;
  if (own.name === '') {
    // 群名未知就不发：宁可什么都不广播，也不把配置默认值 'default' 当成真群名发给伙伴
    throw new Error(L('cli.advertise.nameUnknown'));
  }
  const peers = peerEntries(dir).filter((peer) => peer.secret !== undefined);
  const out = await broadcastGroupAdvertisement({
    peers,
    self: own.member,
    group: own.group,
    manual: true,
    stateDir: dir,
  });
  if (!quiet) {
    process.stdout.write(L('cli.advertise.summary', {
      name: own.name,
      groupId: own.groupId.slice(0, 8),
      sent: out.sent.length,
      skipped: out.skipped.length,
    }) + '\n');
    for (const entry of out.sent) {
      process.stdout.write('  → ' + (entry.name || entry.peerId.slice(0, 8)) + '  ' + entry.baseUrl + '\n');
    }
    for (const entry of out.skipped) {
      process.stdout.write(
        '  ✗ ' + (entry.name || String(entry.peerId).slice(0, 8)) + '  ' + entry.reason + '\n',
      );
    }
  } else if (out.sent.length > 0) {
    process.stdout.write(L('cli.advertise.sentOnly', { count: out.sent.length }) + '\n');
  }
  return out;
}

async function cmdGroupAdvertise(dir, args) {
  await broadcastOwnGroupName(dir, args);
}

async function cmdGroup(args) {
  const sub = String(args._[0] ?? '');
  if (!sub || sub === 'help') {
    console.log(L('cli.help.group'));
    return;
  }
  const dir = stateDir(args);
  const handlers = {
    state: cmdGroupState,
    post: cmdGroupPost,
    history: cmdGroupHistory,
    tail: cmdGroupTail,
    join: cmdGroupJoin,
    probe: cmdGroupProbe,
    replica: cmdGroupReplica,
    leader: cmdGroupLeader,
    claim: cmdGroupClaim,
    find: cmdGroupFind,
    apply: cmdGroupApply,
    advertise: cmdGroupAdvertise,
    archives: cmdGroupArchives,
    'archive-delete': cmdGroupArchiveDelete,
  };
  const handler = handlers[sub];
  if (!handler) throw new Error(L('cli.group.unknownSub', { sub }) + '\n' + L('cli.help.group'));
  try {
    return await handler(dir, args);
  } catch (error) {
    const text = String(error?.message ?? error);
    // 权限类失败（非成员/未启用/不是 leader）单独给 exit 2：和 unpair「找不到对端」同一档
    if (/^40[34]\b/.test(text)) {
      process.stderr.write(L('cli.group.rejected', { text }) + '\n');
      process.exitCode = 2;
      return;
    }
    throw error;
  }
}

// ---------------------------------------------------------------------------
// v0.8.5-α 文件互传（契约 §3/§4，Lane F2）
//
// 三条命令都只打本机回环管理接口（/api/lan-peers/files*）：CLI 是独立进程，
// 伙伴密钥与实际读写都在 host 里。0.12.0-alpha S1 起是**单发 offer/pull**：
// send-file 只在对方那里挂一条「待下载」，字节留在本机 outbox，等对方点下载时来拉。
// 日志/输出口径（契约 §0）：只报 size、sha256、状态与来源，不打印文件内容。
// ---------------------------------------------------------------------------

/** 403/409/501/503 = 本机现在做不了这件事（exit 2）；其余算失败（exit 1）。 */
function reportFilesError(error) {
  const text = String(error && error.message ? error.message : error);
  process.stderr.write(L('cli.file.failed', { text }) + '\n');
  // 0.12.0-alpha S1：503 holder-offline（对端关着/逐出了）与 409 file-gone 同属「现在做不了」
  process.exitCode = /^(40[39]|50[13])\b/.test(text) ? 2 : 1;
}

/**
 * 发送期间的进度轮询（契约 §4 只读 GET /api/lan-peers/files/progress?id=…）。
 *
 * 每一拍先看有没有 id：有就查 progress 打「已发 X/Y 字节（Z%）」，没有就打「已用 Ns」。
 * 唯一的坑是 id 的时机 —— 本机 send 的 transferId 由 host 内部生成、随结果一起返回
 * （host/server.mjs:6371 生成、:6450 从接收方 complete 响应取回），也就是说发送期间
 * 本机手上没有可查的 id，这一路必然先走「已用 Ns」。等 send 提前给 id（或面板在收件侧
 * 拿到 id）时，同一个循环会直接用上字节数，不需要第二次发送。
 * 查不到（404/501/401/超时）**静默降级**成已用时长：进度是锦上添花，绝不能让 send 失败。
 * 非 TTY 不刷（管道里刷 \r 只会污染输出）；测试/排障用 DSH_LAN_PEERS_PROGRESS=1 强制开。
 */
function startFileProgress({ dir, url, size, idSource, pendingSend, intervalMs = 500 }) {
  const forced = String(process.env.DSH_LAN_PEERS_PROGRESS ?? '').trim() === '1';
  if (!forced && process.stderr.isTTY !== true) return { stop() {} };
  const started = Date.now();
  let stopped = false;
  let painted = false;
  let degraded = false;
  const paint = (line) => {
    if (stopped) return;
    process.stderr.write('\r  ' + line + '   ');
    painted = true;
  };
  const elapsedLine = () => paint(L('cli.file.progressElapsed', { seconds: Math.round((Date.now() - started) / 1000) }));
  // send 期间本机还没有 transferId（那要等对端 complete 才回），所以先问**出站表**：
  // GET files/outbound 里按 (peerId, size) 认出这一趟，读到 sent/size 就画字节进度。
  // 表里没有（还没进分块循环）或接口不可用，就退回已用时长 —— 与以前完全一致。
  const paintOutbound = (want) => adminCall(url, 'files/outbound', undefined, dir)
    .then((rows) => {
      const list = Array.isArray(rows) ? rows : [];
      const row = list.find((item) => String(item?.peerId ?? '') === String(want.peerId ?? '')
        && Number(item?.size) === Number(want.size));
      if (!row) {
        elapsedLine();
        return;
      }
      const sent = Number(row.sent) || 0;
      const total = Number(row.size) > 0 ? Number(row.size) : size;
      if (!(total > 0)) {
        elapsedLine();
        return;
      }
      const pct = Math.max(0, Math.min(100, Math.round((sent / total) * 100)));
      paint(L('cli.file.progressBytes', { received: sent, total, pct }));
    })
    .catch(() => {
      // 出站表不可用（旧 host / 501 / 401）：这一趟退回已用时长，别把错误抛给 send。
      degraded = true;
      elapsedLine();
    });
  const timer = setInterval(() => {
    const id = String(idSource() ?? '').trim();
    if (degraded) {
      elapsedLine();
      return;
    }
    if (id === '') {
      // 先按老规矩把「已用 Ns」画上（同步、不依赖任何接口）；
      // 出站表回得够快就把同一行升级成字节进度，回晚了本来也已经看不到新东西。
      elapsedLine();
      const want = typeof pendingSend === 'function' ? pendingSend() : null;
      if (want) paintOutbound(want);
      return;
    }
    adminCall(url, 'files/progress?id=' + encodeURIComponent(id), undefined, dir)
      .then((out) => {
        const received = Number(out?.received);
        const total = Number(out?.size) > 0 ? Number(out.size) : size;
        if (!Number.isFinite(received) || !(total > 0)) {
          elapsedLine();
          return;
        }
        const pct = Math.max(0, Math.min(100, Math.round((received / total) * 100)));
        paint(L('cli.file.progressBytes', { received, total, pct }));
      })
      .catch(() => {
        // 拿不到进度：这一趟就退回已用时长，既不重试也不把错误抛给 send。
        degraded = true;
        elapsedLine();
      });
  }, intervalMs);
  timer.unref?.();
  return {
    stop() {
      stopped = true;
      clearInterval(timer);
      if (painted) process.stderr.write('\r' + ' '.repeat(36) + '\r');
    },
  };
}

async function cmdSendFile(args) {
  const dir = stateDir(args);
  const wanted = String(args._[0] ?? '').trim();
  const raw = String(args._[1] ?? '').trim();
  if (wanted === '' || raw === '') {
    throw new Error(L('cli.file.sendFileUsage') + '\n' + L('cli.help.sendFile'));
  }
  const { peerId, peer } = findPeer(dir, wanted);
  const file = path.resolve(raw);
  let stat;
  try {
    stat = fs.statSync(file);
  } catch {
    throw new Error(L('cli.file.notFound', { file: raw }));
  }
  if (!stat.isFile()) throw new Error(L('cli.file.notRegular', { file: raw }));
  const peerLabel = String(peer?.name ?? peerId);
  // 地址先解析好：未知地址要在「发送中」之前就报，而不是先喊一声再失败。
  let adminUrl;
  try {
    adminUrl = resolveAdminUrl(dir, args);
  } catch (error) {
    reportFilesError(error);
    return;
  }
  process.stderr.write(L('cli.common.sending', { label: peerLabel, bytes: stat.size }) + '\n');
  // offer 只有 metadata，本机没有「已发多少字节」可报（字节等对方来拉才离开本机），
  // 所以这一趟进度条只会滚「已用 Ns」——与以前的降级路径完全一致。
  let fileId = '';
  const progress = startFileProgress({
    dir,
    url: adminUrl,
    size: stat.size,
    idSource: () => fileId,
    pendingSend: () => ({ peerId, size: stat.size }),
  });
  let out;
  try {
    out = await adminCall(adminUrl, 'files/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ peerId, path: file }),
    }, dir);
  } catch (error) {
    progress.stop();
    reportFilesError(error);
    return;
  }
  fileId = String(out?.fileId ?? '');
  progress.stop();
  const bytes = Number.isFinite(Number(out?.bytes)) ? Number(out.bytes) : stat.size;
  const sha256 = String(out?.sha256 ?? '');
  const ms = Number.isFinite(Number(out?.ms)) ? Number(out.ms) : 0;
  console.log(L('cli.file.offered', { id: fileId, bytes, sha256, ms }));
}

const inboxSha = (row) => {
  const sha = String(row?.sha256 ?? '');
  return sha === '' ? '-' : sha;
};
const inboxFrom = (row) => {
  const from = row?.from;
  return String(from?.name ?? from?.peerId ?? '-') || '-';
};
const inboxAt = (row) => {
  const at = Number(row?.at);
  return Number.isFinite(at) && at > 0 ? new Date(at).toISOString() : '-';
};

/** files 的三桶：待下载（offer）/ 已收（done）/ 传输中（incoming） */
async function cmdInboxList(dir, args) {
  let out;
  try {
    out = await adminCall(args.url, 'files', undefined, dir);
  } catch (error) {
    reportFilesError(error);
    return;
  }
  const offers = Array.isArray(out?.offers) ? out.offers : [];
  const inbox = Array.isArray(out?.inbox) ? out.inbox : [];
  const incoming = Array.isArray(out?.incoming) ? out.incoming : [];
  const line = (row, tag) => [
    tag,
    String(row?.id ?? '-'),
    String(row?.name ?? '-'),
    (Number.isFinite(Number(row?.size)) ? Number(row.size) : 0) + 'B',
    'sha256 ' + inboxSha(row),
    'from ' + inboxFrom(row),
    inboxAt(row),
  ].join('\t');
  for (const row of offers) {
    // 信任标记并在 tag 里（不另开一列：面板/CLI 的列宽是给眼睛看的，不是给机器解析的）
    console.log(line(row, row?.trusted === true ? L('cli.inbox.tagOfferTrusted') : L('cli.inbox.tagOffer')));
  }
  for (const row of inbox) console.log(line(row, L('cli.inbox.tagReceived')));
  // 传输中的单独一行：id 前 8 位 + 名字 + 已收/总量（正在从 holder 拉）。
  for (const row of incoming) {
    console.log(L('cli.inbox.incomingLine', {
      id: String(row?.id ?? '').slice(0, 8),
      name: String(row?.name ?? '-') || '-',
      received: Number.isFinite(Number(row?.received)) ? Number(row.received) : 0,
      size: Number.isFinite(Number(row?.size)) ? Number(row.size) : 0,
    }));
  }
  process.stderr.write(L('cli.inbox.summary', { offers: offers.length, inbox: inbox.length }) + '\n');
}

/** download / decline：都只带 fileId 打一条写路由 */
async function cmdInboxDownload(dir, args) {
  const id = String(args._[0] ?? args.id ?? '').trim();
  if (id === '') {
    throw new Error(L('cli.inbox.usageDecide', { action: 'download' }) + '\n' + L('cli.help.inbox'));
  }
  let out;
  try {
    out = await adminCall(args.url, 'files/download', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fileId: id }),
    }, dir);
  } catch (error) {
    reportFilesError(error);
    return;
  }
  console.log(L('cli.inbox.downloaded', {
    id: String(out?.id ?? id),
    bytes: Number.isFinite(Number(out?.bytes)) ? Number(out.bytes) : 0,
    sha256: String(out?.sha256 ?? ''),
    ms: Number.isFinite(Number(out?.ms)) ? Number(out.ms) : 0,
  }));
}

async function cmdInboxDecline(dir, args) {
  const id = String(args._[0] ?? args.id ?? '').trim();
  if (id === '') {
    throw new Error(L('cli.inbox.usageDecide', { action: 'decline' }) + '\n' + L('cli.help.inbox'));
  }
  try {
    await adminCall(args.url, 'files/decline', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fileId: id }),
    }, dir);
  } catch (error) {
    reportFilesError(error);
    return;
  }
  console.log(L('cli.inbox.declined', { id }));
}

async function cmdInbox(args) {
  const sub = String(args._[0] ?? '');
  if (sub === '' || sub === 'help') {
    console.log(L('cli.help.inbox'));
    return;
  }
  const dir = stateDir(args);
  if (sub === 'list') return cmdInboxList(dir, args);
  if (sub === 'download') {
    args._ = args._.slice(1);
    return cmdInboxDownload(dir, args);
  }
  if (sub === 'decline') {
    args._ = args._.slice(1);
    return cmdInboxDecline(dir, args);
  }
  throw new Error(L('cli.inbox.unknownSub', { sub }) + '\n' + L('cli.help.inbox'));
}

/** 顶层 download / decline：等价于 inbox download / inbox decline（id 是第一个参数） */
async function cmdDownloadFile(args) {
  return cmdInboxDownload(stateDir(args), args);
}

async function cmdDeclineFile(args) {
  return cmdInboxDecline(stateDir(args), args);
}

// ---------------------------------------------------------------------------
// v0.8.5-α 私聊（契约 §4/§5，Lane G2）
//
// 私聊是 1:1 连续会话：会话、per-peer 签名/加密与落盘全在 host 里，CLI 是独立进程，
// 不可能也不该自己推数据 —— 三条命令都只打本机回环管理接口。
// 输出口径（契约 §0）：stdout 里的正文是用户自己要看的，但正文绝不进群、不进日志；
// 失败只报状态码与 reason。
// ---------------------------------------------------------------------------

// 契约 §1：权限三档（由低到高）。协议值，任何语言下都是英文原样。
const DISPATCH_PERMISSIONS = ['read-only', 'workspace-write', 'danger-full-access'];

/** 401/403/409/501 = 本机现在做不了（exit 2）；其余算失败（exit 1）。 */
function reportDispatchError(error) {
  const text = String(error && error.message ? error.message : error);
  process.stderr.write(L('cli.dispatch.failed', { text }) + '\n');
  process.exitCode = /^(401|403|409|501)\b/.test(text) ? 2 : 1;
}

/** 剩余秒数：过期时间缺失或已过都按 0（CLI 只做展示，判定在对端）。 */
function dispatchRemaining(expiresAt) {
  const left = Math.ceil((Number(expiresAt) - Date.now()) / 1000);
  return Number.isFinite(left) && left > 0 ? left : 0;
}

/** dispatch pending：逐行 id / 来自 / 工作区 / 权限 / 剩余秒数（没有就一行说明）。 */
async function cmdDispatchPending(dir, args) {
  let url;
  try {
    url = resolveAdminUrl(dir, args);
  } catch (error) {
    reportDispatchError(error);
    return;
  }
  let out;
  try {
    out = await adminCall(url, 'dispatch/pending', undefined, dir);
  } catch (error) {
    reportDispatchError(error);
    return;
  }
  const items = Array.isArray(out && out.items) ? out.items : [];
  if (items.length === 0) {
    process.stderr.write(L('cli.dispatch.pendingEmpty') + '\n');
    return;
  }
  for (const item of items) {
    console.log(L('cli.dispatch.row', {
      id: String(item?.approvalId ?? ''),
      from: String(item?.from ?? '').slice(0, 8) || '-',
      workspaceId: String(item?.workspaceId ?? ''),
      workspaceName: String(item?.workspaceName ?? '') || '-',
      permission: String(item?.permission ?? ''),
      sec: dispatchRemaining(item?.expiresAt),
    }));
  }
  process.stderr.write(L('cli.dispatch.summary', { count: items.length }) + '\n');
}

/** dispatch approve|reject <approvalId>：只转发结论，不在本地拍板。 */
async function cmdDispatchDecide(dir, args, action) {
  const approvalId = String(args._[1] ?? '').trim();
  if (approvalId === '') throw new Error(L('cli.dispatch.idRequired') + '\n' + L('cli.dispatch.usage'));
  let url;
  try {
    url = resolveAdminUrl(dir, args);
  } catch (error) {
    reportDispatchError(error);
    return;
  }
  let out;
  try {
    out = await adminCall(url, 'dispatch/' + action, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: approvalId }),
    }, dir);
  } catch (error) {
    reportDispatchError(error);
    return;
  }
  const key = action === 'approve' ? 'cli.dispatch.approved' : 'cli.dispatch.rejected';
  console.log(L(key, { id: approvalId, state: String(out?.state ?? '-') }));
}

/** 毫秒 → 人话（与面板同一套档位口径；面板摆的是下拉，这里写的是任意值）。 */
function reuseLabel(ms) {
  const value = Number(ms);
  if (!Number.isFinite(value) || value <= 0) return L('cli.dispatch.reuseOff');
  // 一天以内说小时（86400000 说「24 小时」，与面板那一档同一个说法），两天往上才说天。
  if (value % 86_400_000 === 0 && value >= 172_800_000) return L('cli.dispatch.reuseDays', { n: value / 86_400_000 });
  if (value % 3_600_000 === 0) return L('cli.dispatch.reuseHours', { n: value / 3_600_000 });
  if (value % 60_000 === 0) return L('cli.dispatch.reuseMinutes', { n: value / 60_000 });
  return L('cli.dispatch.reuseMs', { n: value });
}

/**
 * --reuse-ttl / --approval-window 的取值：off | 0 | <n>m | <n>h | <n>d | 纯毫秒。
 * 看不懂或越界（0 … 30 天）一律回 -1 —— 调用方据此报错并以非零退出，不猜、不夹。
 */
function parseReuseMs(value) {
  const text = String(value ?? '').trim().toLowerCase();
  if (text === 'off' || text === '0') return 0;
  const matched = /^(\d+)(ms|m|h|d)$/.exec(text);
  let ms;
  if (matched) {
    const unit = matched[2] === 'ms' ? 1 : matched[2] === 'm' ? 60_000 : matched[2] === 'h' ? 3_600_000 : 86_400_000;
    ms = Number(matched[1]) * unit;
  } else if (/^\d+$/.test(text)) {
    ms = Number(text);
  } else {
    return -1;
  }
  if (!Number.isSafeInteger(ms) || ms < SESSION_REUSE_MS_MIN || ms > SESSION_REUSE_MS_MAX) return -1;
  return ms;
}

/** 会话复用那三个值：只在宿主给了键时才打（老宿主没有这三个键，绝不假装是「关闭」）。 */
function printDispatchReuse(view) {
  const src = view && typeof view === 'object' ? view : {};
  if (!Object.prototype.hasOwnProperty.call(src, SESSION_REUSE_TTL_KEY)) return;
  console.log(L('cli.dispatch.reuseHead', {
    reuse: reuseLabel(src[SESSION_REUSE_TTL_KEY]),
    approval: reuseLabel(src[SESSION_NEW_APPROVAL_WINDOW_KEY]),
    allow: src[SESSION_NEW_REQUEST_ALLOWED_KEY] === true ? L('cli.dispatch.reuseYes') : L('cli.dispatch.reuseNo'),
  }));
}

/** 打印本机派单设置（本机视角，含 path —— 与面板设置页同一份口径）。 */
function printDispatchSettings(view) {
  const workspaces = Array.isArray(view?.workspaces) ? view.workspaces : [];
  console.log(L('cli.dispatch.settingsHead', {
    default: String(view?.defaultWorkspaceId ?? '') || '-',
    max: String(view?.maxPermission ?? '') || '-',
    count: workspaces.length,
  }));
  printDispatchReuse(view);
  for (const ws of workspaces) {
    console.log(L('cli.dispatch.workspaceRow', {
      id: String(ws?.id ?? ''),
      name: String(ws?.name ?? '') || '-',
      path: String(ws?.path ?? '') || '-',
    }));
  }
}

/** dispatch settings [--default <id>] [--max-perm <档>] [--reuse-ttl <24h>] [--approval-window <7d>] [--allow-new-request <true|false>] */
async function cmdDispatchSettings(dir, args) {
  const wantedDefault = args.default === undefined || args.default === true ? '' : String(args.default).trim();
  const wantedMax = args['max-perm'] === undefined || args['max-perm'] === true ? '' : String(args['max-perm']).trim();
  const rawTtl = args['reuse-ttl'] === undefined || args['reuse-ttl'] === true ? '' : String(args['reuse-ttl']).trim();
  const rawWindow = args['approval-window'] === undefined || args['approval-window'] === true
    ? '' : String(args['approval-window']).trim();
  const rawAllow = args['allow-new-request'] === undefined || args['allow-new-request'] === true
    ? '' : String(args['allow-new-request']).trim().toLowerCase();
  if (wantedMax !== '' && !DISPATCH_PERMISSIONS.includes(wantedMax)) {
    throw new Error(L('cli.dispatch.badPerm') + '\n' + L('cli.dispatch.usage'));
  }
  const ttlMs = rawTtl === '' ? -1 : parseReuseMs(rawTtl);
  if (rawTtl !== '' && ttlMs < 0) throw new Error(L('cli.dispatch.badReuseTtl') + '\n' + L('cli.dispatch.usage'));
  const windowMs = rawWindow === '' ? -1 : parseReuseMs(rawWindow);
  if (rawWindow !== '' && windowMs < 0) {
    throw new Error(L('cli.dispatch.badApprovalWindow') + '\n' + L('cli.dispatch.usage'));
  }
  if (rawAllow !== '' && rawAllow !== 'true' && rawAllow !== 'false') {
    throw new Error(L('cli.dispatch.badAllowNewRequest') + '\n' + L('cli.dispatch.usage'));
  }
  const patch = {};
  if (wantedDefault !== '') patch.defaultWorkspaceId = wantedDefault;
  if (wantedMax !== '') patch.maxPermission = wantedMax;
  if (ttlMs >= 0) patch[SESSION_REUSE_TTL_KEY] = ttlMs;
  if (windowMs >= 0) patch[SESSION_NEW_APPROVAL_WINDOW_KEY] = windowMs;
  if (rawAllow !== '') patch[SESSION_NEW_REQUEST_ALLOWED_KEY] = rawAllow === 'true';
  const write = Object.keys(patch).length > 0;
  let url;
  try {
    url = resolveAdminUrl(dir, args);
  } catch (error) {
    reportDispatchError(error);
    return;
  }
  let out;
  try {
    out = await adminCall(url, 'dispatch/settings', write ? {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(patch),
    } : undefined, dir);
  } catch (error) {
    reportDispatchError(error);
    return;
  }
  if (write) {
    console.log(L('cli.dispatch.saved', {
      default: String(out?.defaultWorkspaceId ?? '') || '-',
      max: String(out?.maxPermission ?? '') || '-',
      count: Array.isArray(out?.workspaces) ? out.workspaces.length : 0,
    }));
    printDispatchReuse(out);
    return;
  }
  printDispatchSettings(out);
}

async function cmdDispatch(args) {
  const dir = stateDir(args);
  const sub = String(args._[0] ?? '').trim();
  if (sub === '' || sub === 'help') {
    console.log(L('cli.dispatch.usage'));
    return;
  }
  if (sub === 'pending') return cmdDispatchPending(dir, args);
  if (sub === 'approve') return cmdDispatchDecide(dir, args, 'approve');
  if (sub === 'reject') return cmdDispatchDecide(dir, args, 'reject');
  if (sub === 'settings') return cmdDispatchSettings(dir, args);
  throw new Error(L('cli.common.unknownSubcommand', { name: sub }) + '\n' + L('cli.dispatch.usage'));
}

const DM_LOG_DEFAULT_LIMIT = 20;

/** 401/403/409/501 = 本机现在做不了这件事（exit 2）；其余算失败（exit 1）。 */
function reportDmError(error) {
  const text = String(error && error.message ? error.message : error);
  process.stderr.write(L('cli.dm.failed', { text }) + '\n');
  process.exitCode = /^(401|403|409|501)\b/.test(text) ? 2 : 1;
}

const dmWhen = (row) => {
  const at = Number(row && row.ts);
  return Number.isFinite(at) && at > 0 ? new Date(at).toISOString() : '-';
};
const dmFrom = (row) => (row && row.from === 'peer' ? L('cli.dm.fromPeer') : L('cli.dm.fromMe'));

/** 发一条私聊：打印回复 + sessionId/reused（同一伙伴连续发就是同一会话）。 */
async function cmdDmSend(dir, args) {
  const wanted = String(args._[0] ?? '').trim();
  const text = String(args._[1] ?? '');
  if (wanted === '' || text.trim() === '') {
    throw new Error(L('cli.dm.sendUsage') + '\n' + L('cli.help.dm'));
  }
  const { peerId, peer } = findPeer(dir, wanted);
  const label = String(peer?.name ?? peerId);
  // 契约 §2/§5：两个都可选；都不给就对端用它的默认工作区与默认档。
  const workspaceId = args.workspace === undefined || args.workspace === true ? '' : String(args.workspace).trim();
  const permission = args.perm === undefined || args.perm === true ? '' : String(args.perm).trim();
  if (permission !== '' && !DISPATCH_PERMISSIONS.includes(permission)) throw new Error(L('cli.dispatch.badPermDm'));
  let url;
  try {
    url = resolveAdminUrl(dir, args);
  } catch (error) {
    reportDmError(error);
    return;
  }
  // 先说「往哪发、多大」：正文本身只出现在下面打印的回复里，不进这一行。
  process.stderr.write(L('cli.common.sending', { label, bytes: Buffer.byteLength(text, 'utf8') }) + '\n');
  let out;
  try {
    out = await adminCall(url, 'dm/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        peerId,
        text,
        ...(workspaceId === '' ? {} : { workspaceId }),
        ...(permission === '' ? {} : { permission }),
      }),
    }, dir);
  } catch (error) {
    reportDmError(error);
    return;
  }
  // 契约 §2/§4：超过对端默认档时它还没执行 —— 只回 approvalId，这一条是真话，不能当成功。
  if (out && out.pendingApproval === true) {
    const approvalId = String(out.approvalId ?? '');
    console.log(L('cli.dm.queued', {
      label,
      id: approvalId,
      sec: dispatchRemaining(out.expiresAt),
    }));
    console.log('approvalId=' + approvalId + ' state=pending-approval');
    return;
  }
  const reply = String(out && out.reply != null ? out.reply : '');
  const elapsedMs = Number.isFinite(Number(out && out.elapsedMs)) ? Number(out.elapsedMs) : 0;
  console.log(L('cli.dm.reply', { text: reply === '' ? L('cli.common.emptyReply') : reply }));
  console.log('id=' + String(out?.id ?? '')
    + ' sessionId=' + String(out?.sessionId ?? '')
    + ' reused=' + (out?.reused === true ? 'true' : 'false')
    + ' elapsedMs=' + elapsedMs
    // 点名的派单把对端回告的「实际生效」那组也打出来（只有 id/name 与档位，没有 path）。
    + (out?.workspace || out?.permission
      ? ' workspace=' + String(out?.workspace?.id ?? '-') + ' perm=' + String(out?.permission ?? '-')
      : ''));
}

/** 打印本机这一对的私聊历史（服务端是权威；--limit 只影响打印，不影响存储）。 */
async function cmdDmLog(dir, args, wanted) {
  if (wanted === '') throw new Error(L('cli.dm.logUsage') + '\n' + L('cli.help.dm'));
  const { peerId } = findPeer(dir, wanted);
  let url;
  try {
    url = resolveAdminUrl(dir, args);
  } catch (error) {
    reportDmError(error);
    return;
  }
  let limit = DM_LOG_DEFAULT_LIMIT;
  if (args.limit !== undefined && args.limit !== true) {
    const parsed = Number(args.limit);
    if (!Number.isFinite(parsed) || parsed <= 0) throw new Error(L('cli.dm.limitInvalid') + '\n' + L('cli.help.dm'));
    limit = Math.floor(parsed);
  }
  let out;
  try {
    out = await adminCall(url, 'dm?peer=' + encodeURIComponent(peerId), undefined, dir);
  } catch (error) {
    reportDmError(error);
    return;
  }
  const rows = Array.isArray(out && out.messages) ? out.messages : [];
  const shown = rows.length > limit ? rows.slice(rows.length - limit) : rows;
  for (const row of shown) {
    console.log([
      dmWhen(row),
      dmFrom(row),
      String(row?.id ?? '-'),
      String(row?.sessionId ?? '-'),
    ].join('\t') + '\t' + String(row?.text ?? ''));
  }
  process.stderr.write(L('cli.dm.logSummary', {
    total: rows.length,
    shown: shown.length === rows.length ? '' : L('cli.dm.logSummaryShown', { count: shown.length }),
  }) + '\n');
}

/** 与对端交换双方缺失的条目，打印 added/total。 */
async function cmdDmSync(dir, args, wanted) {
  if (wanted === '') throw new Error(L('cli.dm.syncUsage') + '\n' + L('cli.help.dm'));
  const { peerId } = findPeer(dir, wanted);
  let url;
  try {
    url = resolveAdminUrl(dir, args);
  } catch (error) {
    reportDmError(error);
    return;
  }
  let out;
  try {
    out = await adminCall(url, 'dm/sync', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ peerId }),
    }, dir);
  } catch (error) {
    reportDmError(error);
    return;
  }
  const added = Number.isFinite(Number(out && out.added)) ? Number(out.added) : 0;
  const total = Number.isFinite(Number(out && out.total)) ? Number(out.total) : 0;
  console.log(L('cli.dm.synced', { added, total }));
}

async function cmdDm(args) {
  const dir = stateDir(args);
  const sub = String(args._[0] ?? '').trim();
  if (sub === '' || sub === 'help') {
    console.log(L('cli.help.dm'));
    return;
  }
  if (sub === 'log') return cmdDmLog(dir, args, String(args._[1] ?? '').trim());
  if (sub === 'sync') return cmdDmSync(dir, args, String(args._[1] ?? '').trim());
  return cmdDmSend(dir, args);
}

const commands = {
  code: cmdCode,
  pair: cmdPair,
  peers: cmdPeers,
  ask: cmdAsk,
  events: cmdEvents,
  unpair: cmdUnpair,
  group: cmdGroup,
  dm: cmdDm,
  dispatch: cmdDispatch,
  'send-file': cmdSendFile,
  inbox: cmdInbox,
  download: cmdDownloadFile,
  decline: cmdDeclineFile,
};
const helpFor = {
  code: 'cli.help.code',
  pair: 'cli.help.pair',
  peers: 'cli.help.peers',
  ask: 'cli.help.ask',
  events: 'cli.help.events',
  unpair: 'cli.help.unpair',
  group: 'cli.help.group',
  dm: 'cli.help.dm',
  dispatch: 'cli.dispatch.usage',
  'send-file': 'cli.help.sendFile',
  inbox: 'cli.help.inbox',
  download: 'cli.help.download',
  decline: 'cli.help.decline',
};

const args = parseArgs(process.argv.slice(2));
// 语言先定：后面每一条用户可见文案都取自词表
applyLang(args);
const name = args._[0];
if (!name) {
  console.log(L('cli.help.usage'));
  process.exit(args.help || args.h ? 0 : 1);
}
if (name === 'help') {
  console.log(L('cli.help.usage'));
  process.exit(0);
}
const command = commands[name];
if (!command) {
  console.error(L('cli.common.unknownSubcommand', { name }));
  console.error(L('cli.help.usage'));
  process.exit(1);
}
if (args.help || args.h) {
  console.log(L(helpFor[name] || 'cli.help.usage'));
  process.exit(0);
}
args._ = args._.slice(1);
command(args).catch((error) => {
  console.error(String(error.message || error));
  process.exit(1);
});
