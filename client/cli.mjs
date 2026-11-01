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
// v0.8.2-α（契约 §1/§5）：@! 的解析口径与面板共用一份 —— 解析属于协议，不属于某一端。
// 面板在管理接口里解析，CLI 在发完消息后解析，两边落在同一个函数上。
import { parseGroupDispatchCommand } from '../lib/admin.mjs';
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

const USAGE = [
  'dsh-lan-peers — 局域网伙伴 CLI',
  '',
  '用法: dsh-lan-peers <子命令> [选项]',
  '',
  '子命令:',
  '  code    生成一次性配对码（6 位，10 分钟，一次性）',
  '  pair    用配对码与对端互认（ECDH 两轮，自动回退旧明文）',
  '  peers   列出已配对伙伴',
  '  ask     向伙伴派单并等待回复',
  '  events  订阅伙伴 /v1/events 事件流（排障）',
  '  unpair  解除与某个伙伴的配对（尽力通知对端）',
  '  group   群聊：state / post / history / tail / join / probe / replica',
  '  help    显示本帮助',
  '',
  '全局选项:',
  '  --state-dir <路径>   状态目录（默认 ~/.dsh/lan-peers）',
  '  --help               查看子命令用法',
].join('\n');

const CODE_USAGE = [
  '用法: dsh-lan-peers code [--state-dir <目录>] [--url <本机管理接口>]',
  '',
  '请本机 host 生成一次性配对码（10 分钟有效，用后即焚）。',
  'M6 起码只活在 host 进程内存里：本命令是独立进程，自己生成的码对正在跑的 host 无效，',
  '所以必须先启动本机 host（或直接用界面面板的「生成配对码」）。',
].join('\n');

const PAIR_USAGE = [
  '用法: dsh-lan-peers pair --url http://PEER:7788 --code 123456 [--name 本机名] [--peer-name 对端名] [--legacy-pair]',
  '',
  '默认自适应：对端 /v1/health 的 capability 含 "pair-ecdh" 时走 ECDH 两轮',
  '（/v1/pair 交换临时公钥 → /v1/pair/confirm 用派生密钥包裹初始密钥），',
  '否则回退 0.3.1 的明文 /v1/pair。',
  '',
  '  --legacy-pair   强制旧明文路径（对端 0.3.1 或排障用）',
  '  --ecdh-pair     强制 ECDH，对端不支持则报错',
  '  --base-url      本机对外的可达地址（默认自动探测私有 IPv4 + 7788；',
  '                  会随配对请求发给对端，缺了它伙伴那边这条记录就没有地址）',
  '  --port          自动探测地址时用的端口（默认 7788；只在没给 --base-url 时有效）',
].join('\n');

const PEERS_USAGE = [
  '用法: dsh-lan-peers peers [--probe] [--state-dir <目录>]',
  '',
  '  --probe   逐个探活（GET /v1/health，2 秒超时）',
].join('\n');

const ASK_USAGE = [
  '用法: dsh-lan-peers ask --peer <peerId|名字> "prompt" [--timeout 300] [--legacy-poll] [--wait-ms 25000]',
  '',
  '对端声明 "stream" 时走 /v1/events（SSE），否则 /v1/answer 长轮询；',
  '--legacy-poll 强制 0.3.1 的 1.5 秒轮询（不带 waitMs）。',
].join('\n');

const EVENTS_USAGE = [
  '用法: dsh-lan-peers events --peer <peerId|名字> --session <sessionId> [--duration 300] [--verbose]',
  '',
  '订阅对端 /v1/events：每条事件独立加密，此处解密后逐条打印。',
  '对端 capability 不含 "stream" 时直接报错（0.3.1 没有该端点）。',
  '',
  '  --duration <秒>   最长订阅时间（默认 300）',
  '  --verbose         同时打印 ping 心跳',
].join('\n');

const UNPAIR_USAGE = [
  '用法: dsh-lan-peers unpair --peer <peerId|名字> [--local-only] [--timeout 10] [--state-dir <目录>]',
  '',
  '解除本端与某个伙伴的配对。默认先探活：对端声明 "unpair" 能力时发一次签名',
  'POST /v1/unpair 让它也删掉本端；不可达/旧版本/失败都只记录原因，本地一定删除。',
  '',
  '  --local-only     跳过对端通知，只删本地记录',
  '  --timeout <秒>   通知对端的超时（默认 10）',
].join('\n');

const GROUP_USAGE = [
  '用法: dsh-lan-peers group <子命令> [--peer <hub 名字|peerId>] [--state-dir <目录>]',
  '',
  '子命令:',
  '  state                     群信息 + 成员表（会拿到 groupKey，但不打印内容）',
  '  post --text "..."         发一条消息 [--kind chat|progress|result|system]',
  '                            正文含 @!名字 时作者侧自动派单（由本机 host 执行并打印回执摘要）',
  '  dispatch <目标> <任务...>  等价发一条 "@!目标 任务" 并派单，打印回执摘要',
  '  accept on|off             切换本机接单（写 profile 配置，热生效）',
  '  history [--since N]       取历史消息 [--limit 1..200]',
  '  tail [--since N]          跟随事件流并逐条打印 [--duration 秒]',
  '  join [--name 显示名]      向 hub 自助加入（hub 开了 autoJoin 才成功）',
  '  probe [--peer 名字|peerId] 群级探活：打印 peerId/epoch/lastSeq/可达地址',
  '  replica                   打印本地群副本（groupId/epoch/leader/lastSeq/条数）',
  '  leader [--peer X]         查看本机角色/epoch/租约（--peer 时改看对端 live 快照）',
  '  claim [--url http://…]    手动接管：让本机立刻发起选举成为 leader',
  '  find --name <群名>        按群名查找（先查本地已知群，再并发问所有伙伴，2 秒超时）',
  '  apply --name <群名>       按群名申请入群：申请 → 轮询 → 拿到授权后落 group-key.json',
  '  advertise                 把本机群名广播给我的伙伴（无节流，打印发送对象清单）',
  '  archives                  列出 hub 侧归档文件（走本机回环管理接口，只读）',
  '  archive-delete <file>     删除一个归档文件（不可撤销；seq 号不复用）',
  '',
  '  --peer        hub 的名字或 peerId；只有一个伙伴时可省略',
  '  --name        join 时上报的本机显示名（不传则用 state.json 的名字 / hostname；',
  '                同机跑多个节点时用它避免成员表撞名）',
  '  --state-dir   状态目录（默认 ~/.dsh/lan-peers）',
  '  --url         claim 的目标 / 归档接口要打的本机 host 地址（默认 http://127.0.0.1:7788）',
  '  --hub-url     advertise 时对外公布的 hub 地址（默认取群成员表里 hub 自报的地址）',
  '  --base-url    apply 时公布的申请者地址（默认留空，由介绍人按配对记录补）',
  '  --timeout     apply 的等待秒数（默认 600 = 契约 §5.2 的 10 分钟上限）',
  '  --interval    apply 的轮询毫秒数（默认 5000）',
  '',
  'group 端点只有 hub 提供；本机的伙伴列表里要先有 hub 的配对记录。',
  'S3 起 leader 由选举产生：claim 打本机回环（群级签名，正文用本机实例 id）。',
].join('\n');

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
  if (!match) throw new Error('未知对端: ' + wanted);
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
  const url = String(args.url ?? '').trim() || ADMIN_DEFAULT_URL;
  let out;
  try {
    out = await adminCall(url, 'code', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    }, dir);
  } catch (error) {
    const reason = String(error?.message ?? error);
    process.stderr.write('生成配对码失败：本机 host 未接受 ' + url + '（' + reason + '）\n'
      + '修法：请先启动本机 host（或用界面面板的「生成配对码」）—— 码只能在 host 进程里生成\n');
    process.exitCode = 2;
    return;
  }
  const code = String(out && out.code ? out.code : '').trim();
  if (!/^\d{6}$/.test(code)) {
    process.stderr.write('生成配对码失败：本机 host 未按契约回 6 位码\n');
    process.exitCode = 2;
    return;
  }
  console.log('配对码: ' + code + '   有效期: 10 分钟，一次性');
  console.log('对方把它填进「添加伙伴」里即可配对（地址填本机 http://<ip>:7788）');
  console.log('提示: 这个码只在本机 host 进程里有效，重启 host 即失效');
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
  if (!url || !code) throw new Error(PAIR_USAGE);

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
  const how = paired.transport === 'ecdh' ? 'ECDH 两轮' : '旧明文路径';
  console.log('已配对: ' + label + ' (' + paired.peerId + ') · ' + how);
  if (paired.transport === 'legacy') {
    const ecdhReady = await pairingEcdhAvailable();
    console.log(ecdhReady
      ? '提示: 对端未声明 pair-ecdh，已回退旧明文配对（初始密钥明文传输）'
      : '提示: 本构建缺少 lib/pairing-ecdh.mjs，已回退旧明文配对（初始密钥明文传输）');
  }
}

async function cmdPeers(args) {
  const dir = stateDir(args);
  const store = readJson(path.join(dir, 'peers.json'), { peers: {} });
  const entries = Object.entries(store.peers || {});
  if (entries.length === 0) {
    console.log('（尚未配对任何对端）');
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
  const dir = stateDir(args);
  const me = identity(dir);
  const prompt = args._.join(' ').trim();
  if (!args.peer || !prompt) throw new Error(ASK_USAGE);
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
  process.stderr.write('已派单 → ' + peer.name + ' (session ' + sessionId + ')\n');

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
  if (settled.status === 'error') throw new Error('对端返回错误: ' + settled.error);
  console.log('timeout after ' + Math.round((settled.elapsedMs || 0) / 1000) + 's');
  process.exitCode = 2;
}

async function cmdEvents(args) {
  const dir = stateDir(args);
  const me = identity(dir);
  const sessionId = String(args.session || args['session-id'] || '');
  // Arguments first: a missing --session must not fall through to a peer lookup.
  if (!args.peer || !sessionId) throw new Error(EVENTS_USAGE);
  const { peer } = findPeer(dir, args.peer);

  const health = await probePeer({ baseUrl: peer.baseUrl, timeoutMs: 3000, fresh: true });
  if (!capabilityOf(health).includes('stream')) {
    process.stderr.write('对端 /v1/health 未声明 "stream" 能力（0.3.1 无该端点），无法订阅事件\n');
    process.exitCode = 2;
    return;
  }

  const durationMs = Math.max(1000, Number(args.duration || 300) * 1000);
  process.stderr.write('订阅 ' + peer.name + ' 的 /v1/events (session ' + sessionId + ')\n');
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
    process.stderr.write('订阅结束: ' + out.reason + '\n');
    process.exitCode = 1;
    return;
  }
  process.stderr.write('终态: ' + out.status + '\n');
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
  if (baseUrl === '') return { notified: false, reason: '未记录对端地址' };
  if (!peer?.secret) return { notified: false, reason: '缺少对端密钥' };
  const probeMs = Math.max(500, Math.min(2000, timeoutSec * 1000));
  const health = await probePeer({ baseUrl, timeoutMs: probeMs, fresh: true });
  if (!health?.online) return { notified: false, reason: '对端不可达' };
  if (!capabilityOf(health).includes('unpair')) return { notified: false, reason: '对端不支持 unpair' };
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
  if (!wanted) throw new Error(UNPAIR_USAGE);
  const { matches } = resolvePeers(dir, wanted);
  if (matches.length === 0) {
    process.stderr.write('未知对端: ' + wanted + '\n' + UNPAIR_USAGE + '\n');
    process.exitCode = 2;
    return;
  }
  if (matches.length > 1) {
    process.stderr.write('对端名字有歧义: ' + wanted + ' 命中 ' + matches.length + ' 条，请改用 peerId\n');
    for (const [peerId, peer] of matches) {
      process.stderr.write('  ' + (peer?.name || '(无名)') + '\t' + peerId + '\t' + (peer?.baseUrl || '(仅入站)') + '\n');
    }
    process.exitCode = 2;
    return;
  }
  const [peerId, peer] = matches[0];
  const label = peer?.name || peerId;

  const remote = args['local-only']
    ? { notified: false, reason: '已跳过对端通知（--local-only）' }
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
    ? '已解除与 ' + label + ' 的配对（对端已同步删除）'
    : '已解除与 ' + label + ' 的配对（仅本地；原因：' + (remote.reason || '未知') + '）');
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
      '需要一个 --peer（hub 的名字或 peerId）'
        + (candidates ? '，候选: ' + candidates : '（本机还没有配对记录）')
        + '\n' + GROUP_USAGE,
    );
  }
  const matches = entries.filter(([peerId, peer]) => peerId === target || String(peer?.name ?? '') === target);
  if (matches.length === 0) throw new Error('未知对端: ' + target + '\n' + GROUP_USAGE);
  if (matches.length > 1) {
    throw new Error(
      '对端名字有歧义: ' + target + ' 命中 ' + matches.length + ' 条，请改用 peerId\n'
        + matches.map(([peerId, peer]) => '  ' + (peer?.name || '(无名)') + '\t' + peerId).join('\n'),
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
    console.log(
      '群组: ' + state.name + ' (' + state.groupId + ')  epoch=' + state.epoch
        + ' keyVersion=' + state.keyVersion + ' 成员=' + state.members.length,
    );
    for (const member of state.members) {
      console.log(
        '  ' + (member.name || '(无名)') + '\t' + member.peerId
          + '\t' + (member.online ? 'online' : 'offline')
          + '\tjoinedAt=' + (member.joinedAt ?? '?'),
      );
    }
    // 密钥本身永远不打印：只说「拿到了」
    const keyBytes = state.groupKey ? Buffer.from(String(state.groupKey), 'base64url').length : 0;
    console.log('groupKey: ' + (keyBytes === 32 ? '已收到（32B，不显示）' : '未下发'));
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
  console.log(
    '群组: ' + (key.groupName || String(probe?.name ?? key.hubName ?? ''))
      + ' (' + String(probe?.groupId ?? key.groupId) + ')'
      + '  epoch=' + (probe?.epoch ?? 0) + ' 成员=' + memberIds.length
      + '（群级签名直连 ' + key.baseUrl + '，leader=' + (key.hubName || key.hubId.slice(0, 8)) + '）',
  );
  for (const peerId of memberIds) {
    const name = String(key.members?.[peerId]?.name ?? '');
    console.log('  ' + (name || '(无名)') + '\t' + peerId
      + '\t' + (peerId === key.senderId ? 'online(本机)' : ''));
  }
  console.log('groupKey: 已在 group-key.json（32B，不显示）');
}

/**
 * 契约 §3 的回执摘要（CLI 口径，与面板同形）：派单 → 目标：done/failed（reason / 耗时 / 字数）。
 * skipped 是第三种终态：这条消息没有 @! 目标 —— 零消息写入，不能说成完成也不能说成失败。
 */
function formatDispatchLine(dispatch) {
  const data = dispatch && typeof dispatch === 'object' ? dispatch : {};
  const status = String(data.status ?? '');
  const who = String(data.targetName ?? '') || String(data.target ?? '') || '—';
  if (status === 'skipped') return '未派单（消息里没有 @! 目标）: ' + String(data.reason ?? 'no-target');
  // M1：同名歧义是「用户得先选一个」，不是网络错误 —— 给出可操作的重发语法。
  if (status === 'failed' && String(data.reason ?? '') === 'ambiguous') {
    return '派单 → ' + who + '：有多个同名成员，请用 @!名字 (短id) 重发';
  }
  const parts = [];
  // done 也可能带 reason（契约 §1：多个 @! 只取第一个，reason=multi-target-ignored）。
  const reason = String(data.reason ?? '');
  if (reason !== '') parts.push(reason);
  else if (status !== 'done') parts.push('error');
  const elapsed = Number(data.elapsedMs);
  if (Number.isFinite(elapsed) && elapsed >= 0) parts.push(Math.round(elapsed) + 'ms');
  const chars = Number(data.replyChars);
  if (Number.isFinite(chars) && chars >= 0) parts.push(Math.round(chars) + '字');
  return '派单 → ' + who + '：' + (status === 'done' ? 'done' : 'failed')
    + (parts.length ? '（' + parts.join(' / ') + '）' : '');
}

/**
 * 契约 §5：作者侧派单的执行口 = 本机回环的 POST /api/lan-peers/group/dispatch。
 * 派单要开 1:1 会话、要往群里写 progress/result，只有本机 host 做得到；CLI 直连 hub
 * 发消息，所以这里必须再打一次本机管理接口。
 *
 * 本机没有 host（纯 CLI 节点、host 没起）→ **如实报错并 exit 2**：
 * 静默把 "@!X 任务" 当成一条普普通通的群消息发出去，是最坏的一种失败。
 */
async function triggerDispatch(args, command) {
  const url = String(args.url ?? '').trim() || ADMIN_DEFAULT_URL;
  let out;
  try {
    out = await adminCall(url, 'group/dispatch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target: command.target,
        task: command.task,
        extraTargets: command.extraTargets,
      }),
    }, stateDir(args));
  } catch (error) {
    const reason = String(error?.message ?? error);
    process.stderr.write('消息已发出，但派单未触发：本机 host 未响应 ' + url + '（' + reason + '）\n'
      + '修法：先起本机 host（或对 --url 指向的管理接口重试 group dispatch）\n');
    process.exitCode = 2;
    return;
  }
  const dispatch = out && out.dispatch && typeof out.dispatch === 'object' ? out.dispatch : null;
  if (!dispatch) {
    process.stderr.write('派单未返回结果：本机 host 未按契约回 dispatch 摘要\n');
    process.exitCode = 2;
    return;
  }
  console.log(formatDispatchLine(dispatch));
  if (dispatch.status === 'failed') process.exitCode = 1;
}

/** 发一条群消息（post 与 dispatch 共用）；作者侧在 POST 之后按契约 §1 解析 @! 并派单。 */
async function postGroupText(dir, args, text) {
  if (!text) throw new Error(GROUP_USAGE);
  if (Array.from(text).length > GROUP_TEXT_MAX_CHARS) {
    throw new Error('text 超过 ' + GROUP_TEXT_MAX_CHARS + ' 字符上限（hub 会回 413 payload-too-large）');
  }
  const kind = String(args.kind ?? 'chat');
  if (!GROUP_KINDS.includes(kind)) throw new Error('--kind 必须是 ' + GROUP_KINDS.join(' / '));
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
  console.log(
    '已发送 seq=' + sent.seq + ' ts=' + new Date(Number(sent.ts)).toISOString()
      + (channel.mode === 'group' ? '（群级签名直连 ' + channel.key.baseUrl + '）' : ''),
  );
  // 只有 chat 参与解析：progress/result 本身就是回执，再解析一遍等于自己派自己。
  if (kind !== 'chat') return;
  const command = parseGroupDispatchCommand(text);
  if (!command) return;
  await triggerDispatch(args, command);
}

async function cmdGroupPost(dir, args) {
  const text = String(args.text ?? args._.slice(1).join(' ') ?? '').trim();
  await postGroupText(dir, args, text);
}

/** 契约 §5：显式入口 —— 等价发一条 "@!目标 任务" 再派单（消息先入库，回执摘要打印出来）。 */
async function cmdGroupDispatch(dir, args) {
  const target = String(args._[1] ?? '').trim();
  const task = args._.slice(2).join(' ').trim() || String(args.text ?? '').trim();
  if (target === '' || task === '') {
    throw new Error('用法: dsh-lan-peers group dispatch <目标> <任务...>\n' + GROUP_USAGE);
  }
  await postGroupText(dir, args, '@!' + target + ' ' + task);
}

/** 契约 §4/§5：切换本机接单开关（写 profile 配置、热生效；结果以 host 回的为准）。 */
async function cmdGroupAccept(dir, args) {
  const wanted = String(args._[1] ?? '').trim().toLowerCase();
  const value = wanted === 'on' ? true : (wanted === 'off' ? false : null);
  if (value === null) {
    throw new Error('用法: dsh-lan-peers group accept on|off\n' + GROUP_USAGE);
  }
  const url = String(args.url ?? '').trim() || ADMIN_DEFAULT_URL;
  let out;
  try {
    out = await adminCall(url, 'group/accept', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ acceptDispatch: value }),
    }, dir);
  } catch (error) {
    const reason = String(error?.message ?? error);
    process.stderr.write('切换接单失败：本机 host 未接受 ' + url + '（' + reason + '）\n'
      + '修法：确认本机 host 在跑且群功能已启用（' + reason + ' 为 501 表示 host 还没接线）\n');
    process.exitCode = /^(40[39]|501)\b/.test(reason) ? 2 : 1;
    return;
  }
  const applied = !(out && out.acceptDispatch === false);
  console.log('本机接单：' + (applied ? '接单中' : '已关闭')
    + (out && out.persisted === false ? '（仅本进程生效，重启后回到配置值）' : ''));
}

async function cmdGroupHistory(dir, args) {
  const { mode, peer, key } = resolveGroupConnection(dir, args);
  const limit = Math.min(Math.max(1, Math.floor(Number(args.limit ?? 200) || 200)), 200);
  const since = groupSince(args);
  if (mode === 'peer') {
    const page = await fetchGroupHistory({ ...peer, sinceSeq: since, limit });
    for (const message of page.messages) console.log(formatGroupMessage(message));
    process.stderr.write(
      '群 ' + page.groupId + ' · ' + page.messages.length + ' 条 · lastSeq=' + page.lastSeq + '\n',
    );
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
  process.stderr.write(
    '群 ' + String(page?.groupId ?? key.groupId) + ' · ' + messages.length + ' 条 · lastSeq='
      + (page?.lastSeq ?? 0) + '（群级签名直连 ' + key.baseUrl + '）\n',
  );
}

async function cmdGroupTail(dir, args) {
  const target = groupTarget(dir, args);
  const since = groupSince(args);
  const durationMs = Math.max(1000, Number(args.duration ?? 60) * 1000);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error('duration-reached')), durationMs);
  process.stderr.write('订阅群事件 sinceSeq=' + since + ' (' + Math.round(durationMs / 1000) + 's)\n');
  const out = await readGroupEvents({
    ...target,
    sinceSeq: since,
    signal: controller.signal,
    timeoutMs: durationMs + 5000,
    onMessage: (message) => console.log(formatGroupMessage(message)),
  });
  clearTimeout(timer);
  if (!out.ok && !out.aborted && out.reason !== 'stream-ended') {
    process.stderr.write('订阅结束: ' + out.reason + '\n');
    process.exitCode = 1;
    return;
  }
  process.stderr.write('订阅结束 lastSeq=' + out.lastSeq + '\n');
}

async function cmdGroupJoin(dir, args) {
  const target = groupTarget(dir, args);
  // --name 只改本机在群里的显示名（hub 侧只允许写自己那一条）
  const name = typeof args.name === 'string' ? args.name.trim() : '';
  if (args.name != null && name === '') throw new Error('--name 不能为空\n' + GROUP_USAGE);
  try {
    const joined = await joinGroup({ ...target, name });
    console.log(
      '已加入群 ' + joined.groupId + ' epoch=' + joined.epoch
        + (joined.name ? ' 显示名=' + joined.name : ''),
    );
  } catch (error) {
    const text = String(error?.message ?? error);
    if (text.includes('403')) {
      process.stderr.write('加入失败: hub 未允许自助加入（403 not-a-member），请让 hub 管理接口添加本机\n');
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
  if (baseUrl === '') throw new Error('对端没有记录地址，无法探测');
  const senderId = identity(dir).instanceId;
  const localKey = readGroupKeyFile(dir);
  const info = localKey
    ? await probeGroupPeer({ baseUrl, groupKey: localKey.key, groupId: localKey.groupId, senderId })
    : await signedCall({ baseUrl, secret: peer.secret, senderId, method: 'GET', apiPath: '/v1/group/probe' });
  console.log(
    '探测: ' + (info?.name || peer.name || '?')
      + ' peerId=' + (info?.peerId || '?')
      + ' epoch=' + (info?.epoch ?? 0)
      + ' lastSeq=' + (info?.lastSeq ?? 0),
  );
  console.log('  地址: ' + (info?.advertiseBaseUrl || '(未探测到私有地址)'));
  console.log('  groupId=' + (info?.groupId || '-') + ' leader=' + (info?.leaderPeerId || '-'));
}

/** group replica：只读本地 <stateDir>/group-replica.json，不联网 */
function cmdGroupReplica(dir) {
  const file = path.join(dir, GROUP_REPLICA_FILE);
  const replica = readJson(file, null);
  if (!replica) {
    console.log('本地没有群副本（' + file + '；成员启动并成功拉取后生成）');
    return;
  }
  const messages = Array.isArray(replica.messages) ? replica.messages : [];
  console.log(
    '副本: groupId=' + (replica.groupId || '-')
      + ' epoch=' + (replica.epoch ?? 0)
      + ' leader=' + (replica.leaderPeerId || '-')
      + ' lastSeq=' + (replica.lastSeq ?? 0)
      + ' 条数=' + messages.length,
  );
  console.log('  文件: ' + file);
}

/**
 * group leader：只读本机 <stateDir>/group-role.json（角色/epoch/leader/租约）。
 * 给了 --peer 时再打一次对端的 GET /v1/group/lease（群级签名），看对端 live 快照。
 */
async function cmdGroupLeader(dir, args) {
  const role = readGroupRoleFile(dir);
  if (!role) {
    console.log('本机还没有角色状态（' + path.join(dir, GROUP_ROLE_FILE) + '）；'
      + 'host 启动并启用群之后生成');
  } else {
    const remaining = role.leaseUntil > 0 ? Math.max(0, role.leaseUntil - Date.now()) : 0;
    const degraded = role.leaderPeerId === '' || Date.now() > role.leaseUntil;
    console.log(
      '角色: ' + role.role
        + ' epoch=' + role.epoch
        + ' leader=' + (role.leaderPeerId || '-')
        + ' commitSeq=' + role.commitSeq
        + ' 租约剩余=' + remaining + 'ms'
        + (degraded ? '  [degraded]' : ''),
    );
  }
  if (args.peer == null) return;
  const { peer } = resolveHubPeer(dir, args.peer);
  const baseUrl = String(peer.baseUrl ?? '').replace(/\/+$/, '');
  const localKey = readLocalGroupKey(dir);
  if (!localKey) throw new Error('本机没有群密钥（group-key.json / group.json），无法用群级签名查询对端');
  const senderId = identity(dir).instanceId;
  const remote = await fetchGroupLease({
    baseUrl,
    groupKey: localKey.key,
    groupId: localKey.groupId,
    senderId,
  });
  console.log(
    '对端: ' + (peer.name || peer.peerId)
      + ' role=' + (remote?.role ?? '?')
      + ' epoch=' + (remote?.epoch ?? '?')
      + ' leader=' + (remote?.leaderPeerId || '-')
      + ' commitSeq=' + (remote?.commitSeq ?? '?')
      + ' pending=' + (remote?.pendingCount ?? '?')
      + ' quorum=' + (remote?.quorum ?? '?')
      + (remote?.degraded ? '  [degraded]' : ''),
  );
}

/**
 * group claim：手动接管。
 * 打本机 host 的回环地址（群级签名），body 里 candidate 就是本机实例 id ——
 * host 收到「本机自称候选」会立刻发起一轮选举，票数够就接任 leader（契约 §7）。
 */
async function cmdGroupClaim(dir, args) {
  const baseUrl = String(args.url ?? 'http://127.0.0.1:7788').replace(/\/+$/, '');
  const localKey = readLocalGroupKey(dir);
  if (!localKey) throw new Error('本机没有群密钥（group-key.json / group.json），先让 host 启用群');
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
    console.log(
      '已接管为 leader: epoch=' + (reply.epoch ?? epoch)
        + ' 本机=' + senderId,
    );
    return;
  }
  process.stderr.write(
    '接管未成功: ' + (reply?.reason || 'vote-refused')
      + ' 票数=' + (reply?.votes ?? '?') + '/' + (reply?.needed ?? '?')
      + '（成员表 ' + (reply?.memberCount ?? '?') + ' 人；多数派分母是成员表全集，不是可达成员数）\n',
  );
  // 契约 §3：落败者回到 follower 并更新 epoch —— 运维要立刻知道本机已经降级
  process.stderr.write(
    '本机当前角色=' + (reply?.role || 'follower')
      + ' epoch=' + (reply?.epoch ?? '?')
      + '（落败即降级；等对端回来后会由租约过期重新选举）\n',
  );
  process.exitCode = 2;
}


// ---------------------------------------------------------------------------
// v0.8.0-β 归档（DESIGN §18.2）：只归档、不自动删除，删不删由人决定。
// 两个子命令都只打本机回环的 hub 管理接口 /api/lan-peers/group/archives，
// CLI 自己不去碰 stateDir 下的归档文件（那里只有 host 知道怎么读怎么写）。
// ---------------------------------------------------------------------------

const ADMIN_DEFAULT_URL = 'http://127.0.0.1:7788';
const ADMIN_TIMEOUT_MS = 10000;
// S3：管理接口要 X-Lan-Peers-Token。host 启动时把它写到 <stateDir>/admin-token（0600），
// CLI 只读不写；token 本身绝不出现在 URL、日志或错误消息里（只说去哪读）。
const ADMIN_TOKEN_FILE = 'admin-token';

function readAdminToken(dir) {
  try {
    return fs.readFileSync(path.join(String(dir || DEFAULT_STATE_DIR), ADMIN_TOKEN_FILE), 'utf8').trim();
  } catch {
    return '';
  }
}

/** 打本机回环管理接口；非 2xx 抛 `<status> <error>` 形式的 Error（与 group-client 同款）。 */
async function adminCall(baseUrl, apiPath, init, dir) {
  const base = String(baseUrl || ADMIN_DEFAULT_URL).replace(/\/+$/, '');
  const token = readAdminToken(dir);
  const headers = { ...(init && init.headers ? init.headers : {}) };
  if (token !== '') headers['X-Lan-Peers-Token'] = token;
  const reply = await fetch(base + '/api/lan-peers/' + apiPath, {
    ...init,
    headers,
    signal: AbortSignal.timeout(ADMIN_TIMEOUT_MS),
  });
  const body = await reply.json().catch(() => ({}));
  if (!reply.ok) {
    const status = reply.status;
    const where = path.join(String(dir || DEFAULT_STATE_DIR), ADMIN_TOKEN_FILE);
    // 401 一定是 token 缺失/不匹配：直接指路（host 启动时写入，权限 0600）。
    const hint = status === 401 ? '（管理接口需要 token：确认本机 host 在跑，且 ' + where + ' 可读）' : '';
    throw new Error(status + ' ' + String(body.error || 'admin-call-failed') + hint);
  }
  return body;
}

/** 归档接口的失败口径：403/409 是「本机现在做不了这件事」（exit 2），其余算失败（exit 1）。 */
function reportArchiveError(error) {
  const text = String(error && error.message ? error.message : error);
  process.stderr.write('归档操作失败: ' + text + '\n');
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
    console.log('没有归档（hub 侧还没有归档文件）');
    return;
  }
  const sum = list.reduce((total, item) => total + (Number(item?.bytes) || 0), 0);
  const total = Number.isFinite(Number(out?.totalBytes)) ? Number(out.totalBytes) : sum;
  for (const item of list) {
    const from = item?.fromSeq == null ? '—' : item.fromSeq;
    const to = item?.toSeq == null ? '—' : item.toSeq;
    const count = item?.count == null ? '?' : item.count;
    console.log(
      String(item?.file ?? '(未命名)')
        + '\tseq ' + from + '-' + to
        + '\t' + count + ' 条'
        + '\t' + (Number(item?.bytes) || 0) + 'B'
        + '\t' + String(item?.createdAt ?? '?'),
    );
  }
  process.stderr.write('共 ' + list.length + ' 个归档 · ' + total + ' 字节\n');
}

async function cmdGroupArchiveDelete(dir, args) {
  const file = String(args._[1] ?? args.file ?? '').trim();
  if (file === '') throw new Error('用法: dsh-lan-peers group archive-delete <file>\n' + GROUP_USAGE);
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
  console.log('已删除归档 ' + file
    + (Number.isFinite(removed) && removed > 0 ? '，释放 ' + removed + ' 字节' : ''));
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
  if (wanted === '') throw new Error('需要 --name <群名>\n' + GROUP_USAGE);
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
    process.stdout.write(
      '· ' + (match.name || '(无名)')
      + '  groupId=' + String(match.groupId ?? '').slice(0, 8) + '…'
      + '  hub=' + (match.hub?.name || String(match.hub?.peerId ?? '').slice(0, 8) || '?')
      + '  介绍人=' + (match.via?.name || String(match.via?.peerId ?? '').slice(0, 8) || '?')
      + '\n',
    );
  }
}

async function cmdGroupFind(dir, args) {
  const found = await findGroupMatches(dir, args.name, args);
  if (found.matches.length === 0) {
    process.stderr.write(
      '未发现群名「' + normalizeGroupName(args.name) + '」'
        + '（本地 known-groups 为空，向 ' + (found.peers ?? 0) + ' 个伙伴查找均未命中）\n',
    );
    process.exitCode = 2;
    return;
  }
  if (found.source === 'local') process.stderr.write('（本地命中，未联网）\n');
  printMatches(found.matches);
  if (found.matches.length > 1) {
    process.stderr.write('命中 ' + found.matches.length + ' 个同名群：apply 时用 --peer <介绍人> 或 --group <groupId> 指定\n');
  }
  for (const failure of found.failed) {
    process.stderr.write('（' + (failure.name || failure.peerId) + ' 查找失败: ' + failure.reason + '）\n');
  }
}

async function cmdGroupApply(dir, args) {
  const wanted = normalizeGroupName(args.name);
  if (wanted === '') throw new Error('需要 --name <群名>\n' + GROUP_USAGE);
  const self = identity(dir);
  const found = await findGroupMatches(dir, wanted, args);
  if (found.matches.length === 0) {
    process.stderr.write('未发现群「' + wanted + '」：先让群里的人把群名广播给你，或用 group find 确认\n');
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
      process.stderr.write('命中 ' + found.matches.length + ' 个同名群，请用 --peer <介绍人> 或 --group <groupId> 指定：\n');
      printMatches(found.matches);
      process.exitCode = 2;
      return;
    }
    match = picked;
  }
  const introducer = peerEntries(dir).find((peer) => peer.peerId === match.via?.peerId) ?? null;
  if (!introducer) {
    throw new Error('命中的介绍人不在伙伴列表里（' + String(match.via?.peerId ?? '').slice(0, 8) + '），无法签名申请');
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
    process.stderr.write('申请被拒绝：' + (applied.reason || 'rejected') + '\n');
    process.exitCode = 2;
    return;
  }
  process.stdout.write(
    '已向 ' + (match.via?.name || String(match.via?.peerId).slice(0, 8))
    + ' 提交入群申请（群 ' + (match.name || wanted) + '，groupId ' + String(match.groupId).slice(0, 8) + '…）'
    + '状态=' + applied.status + '\n',
  );

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
        process.stderr.write('轮询失败（第 ' + failures + ' 次，继续等待）: '
          + String(error?.message ?? error).slice(0, 80) + '\n');
      }
      continue;
    }
    lastStatus = polled.status;
    if (polled.status === 'rejected') {
      process.stderr.write('申请被拒绝：' + (polled.reason || 'rejected') + '\n');
      process.exitCode = 2;
      return;
    }
    if (polled.status === 'approved' && polled.grant) {
      const written = applyGroupGrant(dir, polled.grant);
      const memberCount = Object.keys(written.members || {}).length;
      process.stdout.write(
        '已入群：' + (normalizeGroupName(polled.grant.name) || match.name)
        + '（groupId ' + String(written.groupId).slice(0, 8) + '…）'
        + ' keyVersion=' + (Number(polled.grant.keyVersion ?? polled.grant.epoch) || written.epoch)
        + ' 成员=' + memberCount
        + '（群密钥已写入 group-key.json，不显示）\n',
      );
      await broadcastOwnGroupName(dir, args, { quiet: true });
      return;
    }
    if (polled.status === 'approved') {
      process.stdout.write('本机已经是该群成员（无需授权）\n');
      return;
    }
  }
  process.stderr.write(
    '仍在待批准（已等 ' + Math.round(budgetMs / 1000) + ' 秒，最后状态=' + lastStatus + '），稍后重试: group apply --name ' + wanted + '\n',
  );
  process.exitCode = 2;
}

/** 手动广播：把本机群名发给所有非成员伙伴（无节流），返回并打印对象清单 */
async function broadcastOwnGroupName(dir, args = {}, { quiet = false } = {}) {
  const own = await resolveLocalIdentity(dir, args);
  if (!own) throw new Error('本机没有群（group.json / group-key.json 都没有），先当 hub 或先入群');
  const override = normalizeGroupName(args.name);
  if (override !== '') own.name = override;
  if (own.name === '') {
    // 群名未知就不发：宁可什么都不广播，也不把配置默认值 'default' 当成真群名发给伙伴
    throw new Error(
      '本机群名未知（group-key.json 没有 groupName、也联系不上 hub 取权威群名）。'
        + '先让 host 拉到群状态，或用 --name <群名> 明确指定要广播的名字',
    );
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
    process.stdout.write(
      '广播群名「' + own.name + '」（groupId ' + own.groupId.slice(0, 8) + '…）'
      + '：发出 ' + out.sent.length + ' 个，跳过 ' + out.skipped.length + ' 个\n',
    );
    for (const entry of out.sent) {
      process.stdout.write('  → ' + (entry.name || entry.peerId.slice(0, 8)) + '  ' + entry.baseUrl + '\n');
    }
    for (const entry of out.skipped) {
      process.stdout.write(
        '  ✗ ' + (entry.name || String(entry.peerId).slice(0, 8)) + '  ' + entry.reason + '\n',
      );
    }
  } else if (out.sent.length > 0) {
    process.stdout.write('已把群名广播给 ' + out.sent.length + ' 个非成员伙伴\n');
  }
  return out;
}

async function cmdGroupAdvertise(dir, args) {
  await broadcastOwnGroupName(dir, args);
}

async function cmdGroup(args) {
  const sub = String(args._[0] ?? '');
  if (!sub || sub === 'help') {
    console.log(GROUP_USAGE);
    return;
  }
  const dir = stateDir(args);
  const handlers = {
    state: cmdGroupState,
    post: cmdGroupPost,
    dispatch: cmdGroupDispatch,
    accept: cmdGroupAccept,
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
  if (!handler) throw new Error('未知 group 子命令: ' + sub + '\n' + GROUP_USAGE);
  try {
    return await handler(dir, args);
  } catch (error) {
    const text = String(error?.message ?? error);
    // 权限类失败（非成员/未启用/不是 leader）单独给 exit 2：和 unpair「找不到对端」同一档
    if (/^40[34]\b/.test(text)) {
      process.stderr.write('群操作被拒绝: ' + text + '\n');
      process.exitCode = 2;
      return;
    }
    throw error;
  }
}

const commands = {
  code: cmdCode,
  pair: cmdPair,
  peers: cmdPeers,
  ask: cmdAsk,
  events: cmdEvents,
  unpair: cmdUnpair,
  group: cmdGroup,
};
const helpFor = {
  code: CODE_USAGE,
  pair: PAIR_USAGE,
  peers: PEERS_USAGE,
  ask: ASK_USAGE,
  events: EVENTS_USAGE,
  unpair: UNPAIR_USAGE,
  group: GROUP_USAGE,
};

const args = parseArgs(process.argv.slice(2));
const name = args._[0];
if (!name) {
  console.log(USAGE);
  process.exit(args.help || args.h ? 0 : 1);
}
if (name === 'help') {
  console.log(USAGE);
  process.exit(0);
}
const command = commands[name];
if (!command) {
  console.error('未知子命令: ' + name);
  console.error(USAGE);
  process.exit(1);
}
if (args.help || args.h) {
  console.log(helpFor[name] || USAGE);
  process.exit(0);
}
args._ = args._.slice(1);
command(args).catch((error) => {
  console.error(String(error.message || error));
  process.exit(1);
});
