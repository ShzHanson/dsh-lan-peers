/**
 * S3 测试脚手架：造一个 N 成员的群（第 0 台是 hub 角色 = 初始 leader，其余是成员角色），
 * 全部在 127.0.0.1 真监听、真签名、真加密；群密钥与成员表都按生产形状落盘。
 *
 * 关键约定：
 * - 每台自报地址用回环 URL（否则会探测到私网 IP，测试机上打不通）；
 * - hub 的 group.json 与成员的 group-key.json 里 members[].baseUrl 都填真地址 ——
 *   这是「这个成员真的在网络上」的证据，也是 quorum 集合的来源；
 * - peers.json 里 entry.secret 是**本机**签名用的密钥，inboundSecret 是对端的，
 *   与 host/server.mjs 的 authenticate 口径一致。
 */
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { createPeerServer } from '../server.mjs';
import { writeGroupKeyFile } from '../../lib/group-client.mjs';
import {
  isFetchBlockedPort,
  listenOnRandomPort,
  makeTempStateDir,
  request,
  writeJson0600,
} from './helpers.mjs';

// 全量测试是并行跑的，机器很忙：留足余量，避免「提交窗口/投票超时」偶发红
export const heartbeatMs = 120;
export const commitTimeoutMs = 600;
export const tickMs = 25;

export const secretOf = (peerId) => `sec-${peerId}`;

function writePeersJson(dir, ids, names, urls, selfIndex) {
  const peers = {};
  ids.forEach((id, index) => {
    if (index === selfIndex) return;
    peers[id] = {
      name: names[index],
      baseUrl: urls[index] ?? 'http://127.0.0.1:1',
      // 本机签名用自己的密钥，对端的进 inboundSecret（见文件头注释）
      secret: secretOf(ids[selfIndex]),
      inboundSecret: secretOf(id),
      addedAt: new Date().toISOString(),
      lastSeen: null,
    };
  });
  writeJson0600(path.join(dir, 'peers.json'), { peers });
}

/** 先挑一个「fetch 不拒绝」的空闲端口：节点重启时要在 listen **之前**就知道自己的地址 */
async function pickFreePort() {
  for (let attempt = 0; attempt < 10; attempt += 1) {
    const port = await new Promise((resolve, reject) => {
      const probe = net.createServer();
      probe.unref();
      probe.once('error', reject);
      probe.listen(0, '127.0.0.1', () => {
        const found = probe.address().port;
        probe.close(() => resolve(found));
      });
    });
    if (!isFetchBlockedPort(port)) return port;
  }
  throw new Error('no fetch-safe free port');
}

/** 以某个成员的身份发一个 per-peer 签名的请求（与 CLI/成员侧同一套签名） */
export function postAs(baseUrl, fromId, body, extra = {}) {
  return request(baseUrl, {
    method: 'POST',
    path: '/v1/group/post',
    peerId: fromId,
    secret: secretOf(fromId),
    body,
    ...extra,
  });
}

/** 加密通道（requireEncryption:true 的群）里发 post */
export function postAsEncrypted(baseUrl, fromId, body, extra = {}) {
  return postAs(baseUrl, fromId, body, { encrypt: true, ...extra });
}

export async function waitFor(check, { timeoutMs = 6_000, intervalMs = 20 } = {}) {
  const deadline = Date.now() + timeoutMs;
  let last;
  while (Date.now() < deadline) {
    last = await check();
    if (last) return last;
    await sleep(intervalMs);
  }
  return last;
}

export const roleOf = (node) => node.server.group.role();
export const roleFileOf = (node) => path.join(node.dir, 'group-role.json');
export const readRoleFile = (node) => JSON.parse(fs.readFileSync(roleFileOf(node), 'utf8'));

/**
 * 起一个群。返回 {nodes, hub, ids, urls, groupId, groupKey}。
 * nodes[0] 是 hub 角色；nodes[1..] 是成员角色（group.hub 指向 hub 的名字）。
 */
export async function startCluster(t, options = {}) {
  const {
    count = 3,
    // 允许按用例覆盖（选举用例要快：60ms 心跳 / 180ms 租约；冲突用例要静：5s 心跳 / 60s 检查）
    ids: customIds = null,
    quorum = 'majority',
    // v0.8.0：按名申请入群时 hub 是否自动批准（默认 true = 与 S3 既有用例一致）
    autoJoin = true,
    priorities = [],
    requireEncryption = false,
    logger = null,
    heartbeatMs: heartbeatOverride = heartbeatMs,
    commitTimeoutMs: commitOverride = commitTimeoutMs,
    tickMs: tickOverride = tickMs,
    jitterMs = 0,
    // S3 补充：哪些下标是「hub 角色」（配置上没有 group.hub，可参与启动接管）。默认只有 0。
    hubRoles = [0],
    // 预置角色文件：{ 下标: leader 下标 } → 该节点以 follower 起步（leader 指向另一台）
    followerOf = {},
    // 假时钟（「推进 30s 验证不再重试」这类断言用）
    now: nowOverride = null,
    // 额外的选举覆盖（v0.8.0-β §A1/A2：退避参数、周期纠偏节奏、关掉启动期一次性接管）
    electionExtra = {},
  } = options;

  const ids = customIds ?? Array.from({ length: count }, (_, index) => `peer-s3-${String.fromCharCode(97 + index)}`);
  const names = ids.map((id) => `node-${id.slice(-1)}`);
  const dirs = ids.map((id, index) => {
    const dir = makeTempStateDir('dsh-lan-peers-s3-');
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    writeJson0600(path.join(dir, 'state.json'), {
      instanceId: id,
      name: names[index],
      createdAt: new Date().toISOString(),
    });
    return dir;
  });

  const nodes = [];
  const urls = [];
  /** 每台节点的 createPeerServer 配置：真关停后再重启要用同一份（stateDir 等） */
  const optionsByIndex = {};
  const hubRoleIndexes = new Set(hubRoles);
  hubRoleIndexes.add(0);
  /** node0 的群快照：后面的 hub 角色节点要复用同一 groupId/groupKey */
  let hubSnapshot = null;
  for (let index = 0; index < count; index += 1) {
    // 先写 peers.json 再 listen：成员启动那一轮就能解析到 hub
    writePeersJson(dirs[index], ids, names, urls, index);
    const isHubRole = hubRoleIndexes.has(index);
    if (index > 0 && isHubRole && hubSnapshot) {
      // 第二个 hub 角色节点：先把 group.json 写成与 node0 同一把群密钥/groupId，
      // 否则 GroupStore 首次 load 会自己生成一份新的（那就不是一个群了）
      const members = {};
      for (let other = 0; other < index; other += 1) {
        members[ids[other]] = { name: names[other], baseUrl: urls[other], addedAt: new Date().toISOString() };
      }
      members[ids[index]] = { name: names[index], addedAt: new Date().toISOString() };
      writeJson0600(path.join(dirs[index], 'group.json'), {
        groupId: hubSnapshot.groupId,
        key: hubSnapshot.groupKey,
        keyVersion: hubSnapshot.epoch,
        name: hubSnapshot.name,
        createdAt: new Date().toISOString(),
        members,
        messages: [],
        pending: [],
        lastSeq: 0,
      });
    }
    if (index in followerOf) {
      // 预置角色文件：以 follower 起步（leader 指向 followerOf[index] 那台）
      writeJson0600(path.join(dirs[index], 'group-role.json'), {
        role: 'follower',
        epoch: hubSnapshot ? hubSnapshot.epoch : 1,
        leaderPeerId: ids[followerOf[index]],
        leaseUntil: Date.now() + 60_000,
        commitSeq: 0,
        votedFor: null,
        groupId: hubSnapshot ? hubSnapshot.groupId : '',
      });
    }
    const group = {
      enabled: true,
      name: 's3',
      autoJoin,
      retentionDays: 7,
      quorum,
      heartbeatMs: heartbeatOverride,
      commitTimeoutMs: commitOverride,
      hubPriority: priorities[index] ?? 0,
    };
    if (!isHubRole) group.hub = names[0];
    const peerOptions = {
      listenHost: '127.0.0.1',
      stateDir: dirs[index],
      requireEncryption,
      ...(nowOverride ? { now: nowOverride } : {}),
      allowRemotePrompts: true,
      logger,
      group,
      // 成员补差与复制重试在测试里由用例显式驱动
      groupReplica: { pullIntervalMs: 600_000, retryMs: 600_000 },
      groupElection: {
        heartbeatMs: heartbeatOverride,
        commitTimeoutMs: commitOverride,
        tickMs: tickOverride,
        jitterMs,
        peerTimeoutMs: 250,
        ...electionExtra,
      },
    };
    optionsByIndex[index] = peerOptions;
    const server = createPeerServer(peerOptions);
    const info = await listenOnRandomPort(server);
    server.config.group.advertiseBaseUrl = info.url;
    urls[index] = info.url;
    if (isHubRole) {
      const self = server.group.state().members[ids[index]];
      if (self) self.baseUrl = info.url;
      if (!hubSnapshot) hubSnapshot = server.group.state({ includeKey: true });
    }
    nodes.push({
      index,
      peerId: ids[index],
      name: names[index],
      server,
      baseUrl: info.url,
      dir: dirs[index],
    });
    t.after(async () => { await server.close(); });
  }

  for (let index = 0; index < count; index += 1) writePeersJson(dirs[index], ids, names, urls, index);

  const hub = nodes[0];
  for (let index = 1; index < count; index += 1) {
    hub.server.group.addMember(ids[index], names[index]);
    // 自报地址的直接写进 group.json（等价于真实流程里 probe/pull 带 X-Peer-Base）
    hub.server.group.state().members[ids[index]].baseUrl = urls[index];
  }

  // 第二个及以后的 hub 角色节点：成员表补齐（自己那条地址在 listen 后已写）
  for (const node of nodes.slice(1)) {
    if (!node.server.group.isHub) continue;
    for (let index = 0; index < count; index += 1) {
      if (index === node.index) continue;
      node.server.group.addMember(ids[index], names[index]);
      node.server.group.state().members[ids[index]].baseUrl = urls[index];
    }
  }

  const snapshot = hub.server.group.state({ includeKey: true });
  for (let index = 1; index < count; index += 1) {
    const members = {};
    for (let other = 0; other < count; other += 1) {
      members[ids[other]] = { name: names[other], baseUrl: urls[other] };
    }
    writeGroupKeyFile(dirs[index], {
      groupId: snapshot.groupId,
      key: snapshot.groupKey,
      epoch: snapshot.epoch,
      leaderPeerId: hub.peerId,
      name: names[index],
      members,
    });
  }

  const indexOf = (nodeOrIndex) => (typeof nodeOrIndex === 'number' ? nodeOrIndex : nodeOrIndex?.index);
  const rewriteAllPeers = () => {
    for (let index = 0; index < count; index += 1) writePeersJson(dirs[index], ids, names, urls, index);
  };

  /**
   * 制造**真不可达**：把该节点的监听关掉（连接会被真正拒绝）。
   *
   * 别再用「把成员表里的 baseUrl 改成黑洞地址」这一招（v0.8.0 起会失效）：
   *   1. 寻址有三层回退（群成员表 → 学到的地址缓存 → peers.json）；
   *   2. 更致命的是心跳/探活会把成员自报的地址**写回成员表**（X-Peer-Base），
   *      改完不到一个心跳就被学回来 —— 提案照样送达，quorum 满足，201 是产品的正确行为。
   * 所以不可达必须由真实连接失败制造。成员表与 quorum 分母保持不变（这正是要证的东西）。
   */
  async function makeUnreachable(nodeOrIndex) {
    const index = indexOf(nodeOrIndex);
    const node = nodes[index];
    if (!node) throw new Error('unknown node index ' + String(index));
    await node.server.close();
    return node;
  }

  /**
   * 恢复：用同一份 stateDir + 配置**重启**这台节点（新端口）。
   * 角色文件（group-role.json）与副本都在盘上，所以它回来仍是 follower/leader 原角色；
   * 新地址会在下一次心跳里由 X-Peer-Base 写回其它节点的成员表（所以调用方要 waitFor 这个事件）。
   */
  async function restore(nodeOrIndex) {
    const index = indexOf(nodeOrIndex);
    const node = nodes[index];
    if (!node) throw new Error('unknown node index ' + String(index));
    const previousUrl = urls[index];
    const previousPort = previousUrl ? Number(new URL(previousUrl).port) : 0;
    // 关键：advertiseBaseUrl 必须在 **listen 之前**就写进配置。
    // 否则节点在 listen 期间（memberTick/pull 已经跑起来）会用「自动探测到的私网 IP」自报，
    // 而测试节点只监听 127.0.0.1 —— 对端成员表里留下一条连不上的地址，提案会一直打到那儿。
    // 所以先挑端口、把回环地址写进 group.advertiseBaseUrl，再 listen 到同一个端口。
    const baseOptions = optionsByIndex[index];
    const makeOptions = (port) => ({
      ...baseOptions,
      group: { ...baseOptions.group, advertiseBaseUrl: 'http://127.0.0.1:' + port },
    });
    let port = previousPort > 0 ? previousPort : await pickFreePort();
    let server = createPeerServer(makeOptions(port));
    let info = null;
    try {
      info = await server.listen(port, '127.0.0.1');
    } catch {
      port = await pickFreePort();
      server = createPeerServer(makeOptions(port));
      info = await server.listen(port, '127.0.0.1');
    }
    // 自报一次（心跳带 X-Peer-Base）：让其它节点的成员表立刻拿到这个地址
    try {
      await server.group.heartbeat();
    } catch {
      /* 尽力而为：心跳失败不影响节点本身可用 */
    }
    urls[index] = info.url;
    node.server = server;
    node.baseUrl = info.url;
    if (server.group?.isHub) {
      const self = server.group.state().members[ids[index]];
      if (self) self.baseUrl = info.url;
    }
    rewriteAllPeers();
    t.after(async () => { await server.close(); });
    return node;
  }

  return {
    nodes,
    hub,
    ids,
    urls,
    groupId: snapshot.groupId,
    groupKey: snapshot.groupKey,
    makeUnreachable,
    restore,
  };
}

/** 顶层便捷入口：makeUnreachable(cluster, node) / restore(cluster, node) */
export const makeUnreachable = (cluster, node) => cluster.makeUnreachable(node);
export const restoreNode = (cluster, node) => cluster.restore(node);


