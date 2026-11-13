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

import { createPeerServer } from '../host/server.mjs';

const require$ = createRequire(import.meta.url);
import { createDshRunner } from './runner-dsh.mjs';
import { createCtxRunner } from './runner-ctx.mjs';
import { PANEL_SCRIPT, createAdmin, createDispatchFeed } from './admin.mjs';
import { normalizeGroupConfig } from './group-client.mjs';

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
      const file = p.join(os.homedir(), '.dsh', 'lan-peers.log');
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

  const server = createPeerServer({ ...config, group, runner, logger: log });
  const disposers = [];
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
    (info) =>
      log(
        `dsh-lan-peers listening on http://${info.host}:${info.port} name=${server.config.name} `
          + `instance=${server.store.instanceId} allowRemotePrompts=${server.config.allowRemotePrompts}`,
      ),
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
    const admin = createAdmin({ server, nameOf, rename, feed, pairing: { mode: pairingMode } });
    // 0.10.5-α slice B（G4）：上传临时区的清理节拍挂在 admin 上（unref 起来的定时器
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
    for (const tool of await createLanPeerTools(
      { ...config, group, pairingMode, answerWaitMs },
      { feed, log, sendFile },
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
