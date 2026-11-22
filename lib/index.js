// dsh-lan-peers · DSH plugin entry.
//
// Starts the peer HTTP server (host/server.mjs) inside the DSH web process and
// registers the model-facing tools (lib/tools.mjs). A tool-registration failure
// must not take the peer server down, so the tool module is imported lazily.
import { createRequire } from 'node:module';

// Module-level breadcrumb: tells us whether the desktop loader imported this
// module at all (it applies the engines/inventory checks before importing).
try {
  const fs0 = createRequire(import.meta.url)('node:fs');
  const os0 = createRequire(import.meta.url)('node:os');
  const p0 = createRequire(import.meta.url)('node:path');
  fs0.appendFileSync(
    p0.join(os0.homedir(), '.dsh', 'lan-peers.log'),
    new Date().toISOString() + ' dsh-lan-peers: module imported by ' + process.execPath + '\n',
  );
} catch {}

import { createPeerServer, expandHome } from '../host/server.mjs';

const require$ = createRequire(import.meta.url);
import { createDshRunner } from './runner-dsh.mjs';
import { createCtxRunner, permissionOf } from './runner-ctx.mjs';
import {
  PANEL_SCRIPT,
  createAdmin,
  createDispatchFeed,
  readSessionDispatchAllowHigherPermission,
} from './admin.mjs';
import { groupCall, normalizeGroupConfig, resolveGroupHub } from './group-client.mjs';
// 0.12.7-alpha（slice C）：常驻参与者 —— 群消息/私聊进队列、按批唤醒本机 agent。
// 它自己的时钟/定时器可注入（用例里没有一个真 sleep），这里只把真时钟与真通道给它。
import { createParticipantWiring } from './participant.mjs';

export const name = 'lan-peers';
export const inject = ['tools', 'sessionController', 'webServer'];

/**
 * 会话权限的写入口只在插件进程内够得着：dsh-permission-presets 的 set/current
 * 不是 Remote（typert 只导出了 catalog），RPC 到不了，所以 NAS 那条远程 RPC 路径
 * 永远只能诚实降级；Electron 的 in-process runner 走这里拿到的服务对象。
 *
 * 不把这三个名字加进 inject：它们缺席时插件必须照常起（用户可能没挂权限预设包），
 * 所以用 ctx.get(name) 探测 —— 严格读不到就退一步用非严格读法（与既有
 * sessionController/webServer 的取法一致），最后兜底 ctx[name]。
 * 取不到的项一律 null，runner 据此维持旧的诚实降级。
 */
export function resolveRunnerServices(ctx) {
  const pick = (serviceName) => {
    try {
      if (typeof ctx?.get === 'function') {
        const strict = ctx.get(serviceName);
        if (strict !== undefined && strict !== null) return strict;
        return ctx.get(serviceName, false) ?? null;
      }
    } catch {}
    try {
      return ctx?.[serviceName] ?? null;
    } catch {
      return null;
    }
  };
  return {
    permissionPresets: pick('permissionPresets'),
    sessions: pick('sessions'),
    sandboxPolicy: pick('sandboxPolicy'),
  };
}

export async function apply(ctx, config = {}) {
  const log = (line) => {
    const text = String(line);
    if (typeof ctx?.logger?.info === 'function') ctx.logger.info(text);
    else console.log(text);
    // File sink: the Electron app's stdout is not reachable from a script, so a
    // short log under ~/.dsh keeps composition problems diagnosable.
    try {
      const os = require$('node:os');
      const fs = require$('node:fs');
      const p = require$('node:path');
      // 0.12.1：这一格 sink 必须跟着 config.logFile 走 —— 否则运维把 logFile 指到别处，
      // 轮转的是新文件，而插件自己的这几行还在把默认路径撑大。~ 用宿主那枚同一个展开函数。
      const configured = typeof config.logFile === 'string' ? config.logFile.trim() : '';
      const file = expandHome(configured === '' ? p.join(os.homedir(), '.dsh', 'lan-peers.log') : configured);
      fs.appendFileSync(file, new Date().toISOString() + ' ' + text + '\n');
    } catch {}
  };

  // Prefer the in-process service: it needs no web token, so inbound asks also
  // work inside the Electron app. Fall back to the loopback HTTP API when the
  // session controller is not mounted in this profile.
  const sessionController = (() => {
    try {
      if (typeof ctx.get === 'function') return ctx.get('sessionController', false);
    } catch {}
    try { return ctx.sessionController; } catch { return undefined; }
  })();
  const webServer = (() => {
    try {
      if (typeof ctx.get === 'function') return ctx.get('webServer', false);
    } catch {}
    try { return ctx.webServer; } catch { return undefined; }
  })();
  // v0.4.0 knobs. Both defaults keep the 0.3.1 path reachable: pairingMode 'auto'
  // still pairs with a 0.3.1 peer over the plaintext path, and answerWaitMs only
  // lengthens a hold the peer actually honours (a 0.3.1 peer ignores it).
  const pairingMode = ['auto', 'ecdh', 'legacy'].includes(config.pairingMode) ? config.pairingMode : 'auto';
  const answerWaitMs = (() => {
    const raw = Number(config.answerWaitMs);
    if (!Number.isFinite(raw) || raw <= 0) return 25_000;
    return Math.min(Math.max(1000, Math.round(raw)), 25_000);
  })();
  // v0.5.0 群配置：全部有默认值，不填 = 关闭。
  // hub 是「名字或 peerId」字符串，真正的解析放在使用侧（peers.json 会随配对变化）。
  const group = normalizeGroupConfig(config.group);
  // 0.12.7-alpha（slice D）：本地会话派单的权限闸默认值。只认真布尔，坏/缺一律 false。
  // 面板那个复选框落在 <stateDir>/config.json（sessionDispatchAllowHigherPermission），
  // 使用侧每次调用现读一次文件：改完不必重启，也不在这层缓存一份会和文件漂移的值。
  const sessionDispatchAllowHigherConfig = config?.sessionDispatch?.allowHigherPermission === true;

  // Shared with the panel: one ledger of in-flight dispatches, no prompt text.
  const feed = createDispatchFeed();

  log(`dsh-lan-peers services: tools=${typeof ctx.tools} sessionController=${typeof sessionController} webServer=${typeof webServer} pairingMode=${pairingMode} answerWaitMs=${answerWaitMs}`);
  // group.{advertiseBaseUrl, quorum, replicaPullMs} 原样透传给 host/server.mjs：
  // advertiseBaseUrl 空 = 自动探测私有 IPv4；quorum 本轮只解析不生效（S3 两阶段提交）。
  log(
    `dsh-lan-peers group: enabled=${group.enabled} role=${group.enabled ? (group.hub === '' ? 'hub' : 'member') : 'off'} `
      + `hub=${group.hub || '-'} name=${group.name} autoJoin=${group.autoJoin} retentionDays=${group.retentionDays} `
      + `advertiseBaseUrl=${group.advertiseBaseUrl || '-'} quorum=${group.quorum} replicaPullMs=${group.replicaPullMs}`,
  );

  // S3：选举/租约/两阶段提交的三个旋钮原样透传给 host（normalizeGroupConfig 已归一化）。
  log(
    'dsh-lan-peers group s3: heartbeatMs=' + group.heartbeatMs
      + ' (租约=' + group.heartbeatMs * 3 + 'ms)'
      + ' commitTimeoutMs=' + group.commitTimeoutMs
      + ' hubPriority=' + group.hubPriority,
  );
  let runner = null;
  try {
    if (sessionController) {
      // 权限服务：拿到就注入（会话级权限才真的设得进去），拿不到传 null（诚实降级）。
      const services = resolveRunnerServices(ctx);
      runner = createCtxRunner(sessionController, {
        workspace: config.workspace,
        agentPreset: config.agentPreset,
        ...services,
      });
      log('dsh-lan-peers runner: in-process sessionController'
        + ' permissionPresets=' + (services.permissionPresets ? 'present' : 'absent')
        + ' sessions=' + (services.sessions ? 'present' : 'absent')
        + ' sandboxPolicy=' + (services.sandboxPolicy ? 'present' : 'absent'));
    }
  } catch (error) {
    log(`dsh-lan-peers in-process runner unavailable: ${error?.message ?? error}`);
  }
  if (!runner) {
    runner = createDshRunner({
      baseUrl: config.dshBaseUrl,
      tokenFile: config.dshTokenFile,
      workspace: config.workspace,
      agentPreset: config.agentPreset,
    });
    log('dsh-lan-peers runner: loopback HTTP');
  }

  const participantStateDir = (() => {
    const raw = typeof config.stateDir === 'string' ? config.stateDir.trim() : '';
    if (raw !== '') return expandHome(raw);
    return require$('node:path').join(require$('node:os').homedir(), '.dsh', 'lan-peers');
  })();
  let server = null;
  // 装配全部收在 participant.mjs 的工厂里（入口文件只做一次构造，避免多片同时改这一处）
  const participantWiring = createParticipantWiring({
    runner,
    config,
    stateDir: participantStateDir,
    expandHome,
    log,
    selfId: () => String(server?.store?.instanceId ?? ''),
    proposalPlane: () => {
      const facade = server?.group;
      return facade && typeof facade.votes === 'function' ? facade.votes() : null;
    },
  });
  const participant = participantWiring.participant;
  /**
   * 0.12.7-alpha（slice H）：hub 总结会话的提问通道。
   * 与常驻参与者同一条 runner 通道（ask 发送 + poll 取回复），区别只是这里要把**回复正文**带回来
   * —— 摘要就是那段正文。任何失败都向上抛，让 group-digest 走确定性兜底摘要，绝不卡住摘要平面。
   */
  const digestPrompt = async (sessionId, prompt) => {
    const wanted = typeof sessionId === 'string' ? sessionId.trim() : '';
    const asked = wanted === '' ? await runner.ask(prompt) : await runner.ask(prompt, { sessionId: wanted });
    const next = String(asked?.sessionId ?? '') || wanted;
    if (next === '') throw new Error('no-session');
    const deadline = Date.now() + 55_000;
    for (;;) {
      const polled = await runner.poll(next);
      const status = String(polled?.status ?? '');
      if (status === 'done') {
        return {
          sessionId: next,
          reused: wanted !== '' && next === wanted && asked?.reused !== false,
          reply: String(polled?.reply ?? ''),
        };
      }
      if (status === 'error') throw new Error(String(polled?.error ?? 'ask-failed'));
      if (Date.now() >= deadline) throw Object.assign(new Error('timeout'), { code: 'timeout' });
      await new Promise((resolve) => setTimeout(resolve, 150));
    }
  };
  server = createPeerServer({
    ...config,
    group,
    runner,
    logger: log,
    // 唯一的注入口：host 只报告「本机刚看见什么」，判断全在 participant 里
    onParticipantEvent: (event) => participant.push(event),
    // hub 总结会话的提问通道（成员侧不建总结会话，因此这条在成员上不会被用到）
    digestPrompt,
  });
  const disposers = [];
  // close() 之后不留任何东西：定时器清掉、队列清空、常驻会话的记录留着（下次复用）
  disposers.push(() => {
    try { participant.close(); } catch {}
  });
  // cordis 在插件重载/卸载时会执行这个 effect 的清理函数；不清理就会残留监听
  // 端口和重复路由（本次调试里表现为 EADDRINUSE 与 duplicate route）。
  if (typeof ctx.effect === 'function') {
    ctx.effect(() => () => {
      for (const dispose of disposers) {
        try { dispose(); } catch {}
      }
      try { Promise.resolve(server.close()).catch(() => {}); } catch {}
    });
  }

  server.listen().then(
    (info) => {
      // 常驻参与者：监听起来之后才 arm（在此之前没有任何东西可收）
      try {
        const armed = participant.arm();
        log('dsh-lan-peers participant: group=' + armed.group + ' dm=' + armed.dm
          + ' batchMs=' + armed.batchMs + ' session=' + (armed.sessionId === '' ? 'pending' : 'resident'));
      } catch (error) {
        log('dsh-lan-peers participant unavailable: ' + (error?.message ?? error));
      }
      log(
        `dsh-lan-peers listening on http://${info.host}:${info.port} name=${server.config.name} `
          + `instance=${server.store.instanceId} allowRemotePrompts=${server.config.allowRemotePrompts}`,
      );
    },
    (error) => log(`dsh-lan-peers failed to listen: ${error?.message ?? error}`),
  );

  // Loopback-only admin API + the injected settings panel (device name,
  // one-time pairing code, add-a-peer form). `webServer` is optional: the
  // Electron composition may not mount one, and the peer side must still run.
  if (!webServer) log('dsh-lan-peers: no webServer service in this composition; panel not injected');
  try {
    if (!webServer) throw new Error('webServer service unavailable');
    const nameOf = () => server.config.name;
    const rename = (next) => {
      const name = server.store.rename(next);
      server.config.name = name;
      return name;
    };
    const admin = createAdmin({
      server, nameOf, rename, feed, pairing: { mode: pairingMode },
      // 面板的指挥输入框 → 本机指挥会话（唯一注入点；缺了它 GET commander 报 available:false）
      commanderSay: participantWiring.sayToCommander,
    });
    // 0.11.0 slice B（G4）：上传临时区的清理节拍挂在 admin 上（unref 起来的定时器
    // 不会吊住进程，但热重载/卸载会把它留在旧实例里）。这个插件唯一的收尾钩子是上面
    // ctx.effect 那个清理函数 —— 它遍历的正是这个 disposers 数组，所以 close 走这里。
    // 没有 ctx.effect 的组合里这段不会被执行（也没有别的退出钩子可挂）。
    disposers.push(() => {
      try { admin.close(); } catch {}
    });

    disposers.push(webServer.register({
      kind: 'exact',
      path: '/api/lan-peers/panel.js',
      handler: (req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/javascript; charset=utf-8', 'Cache-Control': 'no-store' });
        res.end(PANEL_SCRIPT);
      },
    }));

    disposers.push(webServer.register({
      kind: 'prefix',
      path: '/api/lan-peers',
      handler: (req, res) => {
        const url = new URL(req.url ?? '/', 'http://lan-peer.invalid');
        admin.handle(req, res, url).then((handled) => {
          if (!handled) {
            res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end('{"error":"not-found"}');
          }
        }).catch((error) => {
          res.writeHead(500, { 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ error: String(error?.message ?? error) }));
        });
      },
    }));

    disposers.push(webServer.tapIndex((html) => {
      if (html.includes('/api/lan-peers/panel.js')) return html;
      const tag = '<script defer src="/api/lan-peers/panel.js"></script>';
      return html.includes('</body>') ? html.replace('</body>', tag + '</body>') : html + tag;
    }));
    log('dsh-lan-peers admin panel registered');
  } catch (error) {
    log(`dsh-lan-peers admin panel unavailable: ${error?.message ?? error}`);
  }

  try {
    const { createLanPeerTools } = await import('./tools.mjs');
    // group + log 一起传下去：§6 进度镜像要往 hub 投两条，投递失败只写日志。
    // sendFile：v0.8.5-α §3 的发送侧门面（server.files.send，F1 挂在 host 上）。
    // 工具只挑伙伴、报结果；分块/加密/续传都在门面里，这里不重造一份。
    const sendFile = (input) => {
      const facade = server.files;
      if (!facade || typeof facade.send !== 'function') {
        throw new Error('file transfer unavailable on this host (no files service)');
      }
      return facade.send(input);
    };
    // 0.12.7-alpha（slice B）：agent 看的两个群门面。
    // 读 = server.group.votes()（hub 读权威平面、成员读副本 —— 与面板同一条读口）。
    // 写 = hub 侧 server.group.castVote(...)：管理接口 castVoteInput 调的正是这一份，
    // 票只记在本机名下。成员侧门面**没有**写口（votes-hub-only 是契约），所以成员
    // 走与面板同一条群级签名通道投给 hub —— 只是传输，不重造 hub 侧的计票逻辑。
    const groupVotes = () => {
      const facade = server.group;
      if (!facade || typeof facade.votes !== 'function') return null;
      return facade.votes();
    };
    const memberBallotToHub = async (facade, { proposalId, ballot }) => {
      const local = typeof facade.local === 'function' ? (facade.local() ?? {}) : {};
      const groupKey = String(local.groupKey ?? '');
      const groupId = String(local.groupId ?? '');
      const peers = typeof server.store?.listPeers === 'function' ? server.store.listPeers() : [];
      const hub = resolveGroupHub(Array.isArray(peers) ? peers : [], String(group.hub ?? '')) ?? null;
      if (groupKey === '' || groupId === '' || !hub || !hub.baseUrl) throw new Error('hub-unreachable');
      return (await groupCall({
        baseUrl: String(hub.baseUrl),
        groupKey,
        groupId,
        senderId: String(server.store?.instanceId ?? ''),
        selfBaseUrl: typeof facade.advertiseBaseUrl === 'function' ? String(facade.advertiseBaseUrl() ?? '') : '',
        method: 'POST',
        apiPath: '/v1/group/vote',
        body: { proposalId, ballot },
      })) ?? {};
    };
    const castGroupBallot = async ({ proposalId, ballot }) => {
      const facade = server.group;
      if (!facade || typeof facade.castVote !== 'function') return { ok: false, error: 'votes-hub-only' };
      if (facade.isHub === true) {
        return (await facade.castVote({
          proposalId,
          ballot,
          peerId: String(server.store?.instanceId ?? ''),
        })) ?? {};
      }
      return await memberBallotToHub(facade, { proposalId, ballot });
    };
    // 0.12.7-alpha（slice C）：群内发言的写口 = 面板发言那一条（server.group.post →
    // commitLocalMessage）。hub 走本地提交完备写，成员走既有回执通道 —— 这里一条 hub 调用都不重造。
    const groupPost = async ({ text, kind = 'chat', meta = null } = {}) => {
      const facade = server.group;
      if (group.enabled !== true || !facade || typeof facade.post !== 'function') {
        return { ok: false, error: 'not-in-group' };
      }
      // 作者必须由本机写死（面板的 post 路由就是这么传的：peerId + 本机名）——
      // 少了这两个键，那条帖子会以空作者落盘，连回声闸都认不出是自己发的。
      const out = await facade.post({
        peerId: String(server.store?.instanceId ?? ''),
        name: server.config.name,
        kind,
        text,
        meta,
      });
      return { ok: true, seq: Number(out?.seq) > 0 ? Number(out.seq) : null };
    };
    // 0.12.7-alpha（slice D）：本机会话列表。只挑三个字段 —— cwd 与其它投影都留在这一层
    // 之内，「列表里没有 cwd」是结构性保证，不是某处判断的结果。
    // 权限档用 lib/runner-ctx.mjs 里同一个 permissionOf 读（会话复用的核对也走它）。
    const listSessions = async () => {
      if (!sessionController || typeof sessionController.list !== 'function') {
        throw new Error('no in-process session controller');
      }
      const listed = await sessionController.list({}, new AbortController().signal);
      const items = Array.isArray(listed?.items) ? listed.items : [];
      return items
        .map((item) => ({
          sessionId: String(item?.sessionId ?? ''),
          lastActivity: Number(item?.updatedAt) || 0,
          permission: permissionOf(item?.projections?.values?.permissions),
        }))
        .filter((row) => row.sessionId !== '');
    };
    /**
     * 派一轮 + 读回**最后一条助手消息**：两条都复用既有实现，这里不写第二个轮询器。
     *   · 发：runner.ask(prompt, { sessionId }) —— 内部就是 promptSession（带答复契约）
     *   · 读：runner.poll(sessionId) —— turnOutline + 投影兜底的既有读法
     * 目标在列表之后消失时 runner 会回退「新建」并返回另一个 id：那不是这次派单的对象，
     * 如实回 unknown-session，绝不把新会话的答复冒充成目标的答复。
     */
    const SESSION_ASK_POLL_MS = 150;
    const askSession = async ({ sessionId, prompt, timeoutMs }) => {
      const sent = await runner.ask(prompt, { sessionId });
      if (String(sent?.sessionId ?? '') !== sessionId || sent?.reused === false) {
        return { status: 'error', error: 'unknown-session' };
      }
      const deadline = Date.now() + Math.max(1000, Number(timeoutMs) || 0);
      for (;;) {
        const polled = await runner.poll(sessionId);
        const status = String(polled?.status ?? '');
        if (status === 'done') return { status: 'done', reply: String(polled?.reply ?? '') };
        if (status === 'error') return { status: 'error', error: String(polled?.error ?? 'ask-failed') };
        if (Date.now() >= deadline) return { status: 'timeout' };
        await new Promise((resolve) => setTimeout(resolve, SESSION_ASK_POLL_MS));
      }
    };
    /** 每次调用现读：面板写过就以文件为准，没写过才用插件 config；读不到一律 false。 */
    const allowHigherPermission = () => {
      const fromFile = readSessionDispatchAllowHigherPermission(participantStateDir);
      return typeof fromFile === 'boolean' ? fromFile : sessionDispatchAllowHigherConfig;
    };
    for (const tool of await createLanPeerTools(
      { ...config, group, pairingMode, answerWaitMs, sessionDispatch: { allowHigherPermission: sessionDispatchAllowHigherConfig } },
      { feed, log, sendFile, groupVotes, castGroupBallot, groupPost, listSessions, askSession, allowHigherPermission },
    )) {
      ctx.tools.register(tool);
      log(`dsh-lan-peers registered tool ${tool.name}`);
    }
  } catch (error) {
    log(`dsh-lan-peers tools unavailable: ${error?.stack ?? error}`);
  }

  // cordis treats a plugin's return value as an effect; returning the server
  // object is rejected as "Invalid effect", so return nothing.
}
