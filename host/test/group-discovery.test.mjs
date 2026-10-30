/**
 * v0.8.0 群名发现（契约 group-v08-contract.md §2/§3/§7）。
 *
 * 覆盖：advertise 落 known-groups.json（去重/刷新/0600）、只接受已配对对端、
 *      不覆盖自己的群信息、lookup 命中本机所属群与 known-groups、
 *      lookup 只回应已配对伙伴、名字比较大小写与空白不敏感、
 *      known-groups 的 30 天 TTL 与 50 条上限、广播只发非成员伙伴、
 *      6 小时/伙伴节流（假时钟，重启后仍生效）。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { createPeerServer } from '../server.mjs';
import {
  GROUP_ADVERTISEMENT_THROTTLE_MS,
  GROUP_ADVERTISE_STATE_FILE,
  GROUP_KNOWN_GROUPS_FILE,
  GROUP_KNOWN_GROUPS_LIMIT,
  readAdvertiseState,
  readKnownGroups,
  sameGroupName,
  writeKnownGroups,
} from '../../lib/group-client.mjs';
import { fileMode, listenOnRandomPort, makeTempStateDir, readJson, request, writeJson0600 } from './helpers.mjs';

const DAY = 86_400_000;

const A = { peerId: 'peer-disc-a', name: 'alpha' };
const B = { peerId: 'peer-disc-b', name: 'bravo' };
const C = { peerId: 'peer-disc-c', name: 'charlie' };

/** 每个节点一把 secret：本机签名用它，对端拿它当 inboundSecret（与 group-cluster 同口径） */
const secretOf = (peerId) => 'sec-' + peerId;

/**
 * 起一个节点：自己写 state.json 的身份与 peers.json。
 * peersJson 在 listen 之后重写一次 —— 地址只有 listen 完才知道（getPeer 每次读盘）。
 */
async function startNode(t, { identity, peerList = [], group = null, now = null, logger = null } = {}) {
  const dir = makeTempStateDir('dsh-lan-peers-disc-');
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  writeJson0600(path.join(dir, 'state.json'), {
    instanceId: identity.peerId,
    name: identity.name,
    createdAt: new Date().toISOString(),
  });
  const writePeers = (urls = {}) => {
    const peers = {};
    for (const peer of peerList) {
      peers[peer.peerId] = {
        name: peer.name,
        baseUrl: urls[peer.peerId] ?? 'http://127.0.0.1:1',
        secret: secretOf(identity.peerId),
        inboundSecret: secretOf(peer.peerId),
        addedAt: new Date().toISOString(),
        lastSeen: null,
      };
    }
    writeJson0600(path.join(dir, 'peers.json'), { peers });
  };
  writePeers();
  const logs = [];
  const server = createPeerServer({
    listenHost: '127.0.0.1',
    stateDir: dir,
    // 名字与 state.json 里的 identity 对齐：hub 自己的成员记录就是这个名字
    name: identity.name,
    requireEncryption: false,
    allowRemotePrompts: true,
    logger: logger ?? ((line) => logs.push(String(line))),
    ...(now ? { now } : {}),
    ...(group
      ? { group: { enabled: true, name: 'default', autoJoin: false, quorum: 'none', ...group } }
      : {}),
    groupReplica: { pullIntervalMs: 600_000, retryMs: 600_000 },
  });
  const info = await listenOnRandomPort(server);
  if (group) server.config.group.advertiseBaseUrl = info.url;
  const urls = { [identity.peerId]: info.url };
  const node = {
    identity,
    server,
    stateDir: dir,
    baseUrl: info.url,
    logs,
    knownGroupsFile: path.join(dir, GROUP_KNOWN_GROUPS_FILE),
    setPeerUrls(next) {
      Object.assign(urls, next);
      writePeers(urls);
    },
    knownGroups() {
      try {
        return readJson(node.knownGroupsFile);
      } catch {
        return null;
      }
    },
    logLines(pattern) {
      return logs.filter((line) => String(line).includes(pattern));
    },
  };
  t.after(async () => { await server.close(); });
  return node;
}

const advertiseBody = (overrides = {}) => ({
  groupId: 'group-alpha-1',
  name: 'Team Alpha',
  hub: { peerId: A.peerId, name: A.name, baseUrl: 'http://10.0.0.5:7788' },
  member: { peerId: A.peerId, name: A.name },
  at: Date.now(),
  ...overrides,
});

const postAdvertise = (node, fromId, body) => request(node.baseUrl, {
  method: 'POST',
  path: '/v1/group/advertise',
  peerId: fromId,
  secret: secretOf(fromId),
  body,
});

const postLookup = (node, fromId, name) => request(node.baseUrl, {
  method: 'POST',
  path: '/v1/group/lookup',
  peerId: fromId,
  secret: secretOf(fromId),
  body: { name },
});

// ---------------------------------------------------------------------------
// §2 广播接收
// ---------------------------------------------------------------------------

test('v0.8.0 §2 advertise 落 known-groups.json：按 groupId 去重、刷新 name/lastSeen、0600', async (t) => {
  const node = await startNode(t, { identity: B, peerList: [A] });

  const first = await postAdvertise(node, A.peerId, advertiseBody());
  assert.equal(first.status, 200, first.text);
  assert.deepEqual(first.json, { ok: true });

  const file = node.knownGroupsFile;
  if (process.platform !== 'win32') assert.equal(fileMode(file), 0o600, 'known-groups.json 必须 0600');
  const stored = readJson(file);
  const entry = stored.groups['group-alpha-1'];
  assert.ok(entry, '按 groupId 落一条');
  assert.equal(entry.name, 'Team Alpha');
  assert.deepEqual(entry.hub, { peerId: A.peerId, name: A.name, baseUrl: 'http://10.0.0.5:7788' });
  assert.deepEqual(entry.source, { peerId: A.peerId, name: A.name });
  assert.equal(typeof entry.firstSeen, 'number');
  assert.equal(entry.firstSeen, entry.lastSeen);

  // 同一个 groupId 再来一次（改名）：只刷新，不新增；firstSeen 不动
  await sleep(5);
  const second = await postAdvertise(node, A.peerId, advertiseBody({ name: 'Team Alpha 2' }));
  assert.equal(second.status, 200, second.text);
  const refreshed = readJson(file);
  assert.deepEqual(Object.keys(refreshed.groups), ['group-alpha-1']);
  assert.equal(refreshed.groups['group-alpha-1'].name, 'Team Alpha 2');
  assert.equal(refreshed.groups['group-alpha-1'].firstSeen, entry.firstSeen);
  assert.ok(refreshed.groups['group-alpha-1'].lastSeen >= entry.lastSeen);
});

test('v0.8.0 §9.3 advertise 只接受已配对对端，且不覆盖自己的群信息', async (t) => {
  const node = await startNode(t, { identity: B, peerList: [A] });

  // 未配对（peers.json 里没有）→ 401 unknown-peer，且不落盘
  const unknown = await postAdvertise(node, C.peerId, advertiseBody());
  assert.equal(unknown.status, 401, unknown.text);
  assert.equal(unknown.json.error, 'unknown-peer');
  assert.equal(fs.existsSync(node.knownGroupsFile), false, '未配对对端不得写入 known-groups');

  // 缺字段 → 400
  const bad = await postAdvertise(node, A.peerId, { groupId: 'g', name: '' });
  assert.equal(bad.status, 400);
  assert.equal(bad.json.error, 'bad-request');

  // 本机自己就属于这个群 → 忽略（不能让对端的快照覆盖本机事实）
  const hub = await startNode(t, { identity: A, peerList: [B], group: { name: 'own' } });
  const ownGroupId = hub.server.group.state().groupId;
  const ignored = await postAdvertise(hub, B.peerId, advertiseBody({ groupId: ownGroupId, name: 'own' }));
  assert.equal(ignored.status, 200, ignored.text);
  assert.deepEqual(ignored.json, { ok: true, ignored: 'own-group' });
  assert.equal(fs.existsSync(hub.knownGroupsFile), false, '自己的群不进 known-groups');
});

// ---------------------------------------------------------------------------
// §3 按名查找
// ---------------------------------------------------------------------------

test('v0.8.0 §3 lookup 命中 known-groups，名字比较大小写/空白不敏感', async (t) => {
  const node = await startNode(t, { identity: B, peerList: [A, C] });
  await postAdvertise(node, A.peerId, advertiseBody());

  const hit = await postLookup(node, C.peerId, '  team   ALPHA ');
  assert.equal(hit.status, 200, hit.text);
  assert.equal(hit.json.matches.length, 1);
  const [match] = hit.json.matches;
  assert.equal(match.groupId, 'group-alpha-1');
  assert.equal(match.name, 'Team Alpha');
  assert.deepEqual(match.hub, { peerId: A.peerId, name: A.name, baseUrl: 'http://10.0.0.5:7788' });
  assert.deepEqual(match.via, { peerId: A.peerId, name: A.name }, 'via = 把群名广播过来的那台');

  // 未命中
  const miss = await postLookup(node, C.peerId, 'Team Beta');
  assert.equal(miss.status, 200);
  assert.deepEqual(miss.json.matches, []);

  // 空名字 → 400
  const empty = await postLookup(node, C.peerId, '   ');
  assert.equal(empty.status, 400);

  // 未配对对端不得查（只回应已配对伙伴，§9.2）
  const stranger = await postLookup(node, 'peer-nobody', 'Team Alpha');
  assert.equal(stranger.status, 401);
  assert.equal(stranger.json.error, 'unknown-peer');

  assert.equal(sameGroupName('Team Alpha', ' team  alpha '), true);
});

test('v0.8.0 §3 lookup 也报本机所属群（via = 本机），未启用群的节点只报 known-groups', async (t) => {
  const hub = await startNode(t, { identity: A, peerList: [B], group: { name: 'Team Alpha' } });
  const groupId = hub.server.group.state().groupId;

  const res = await postLookup(hub, B.peerId, 'team alpha');
  assert.equal(res.status, 200, res.text);
  assert.equal(res.json.matches.length, 1);
  assert.equal(res.json.matches[0].groupId, groupId);
  assert.deepEqual(res.json.matches[0].hub, {
    peerId: A.peerId,
    name: A.name,
    baseUrl: hub.baseUrl,
  });
  assert.deepEqual(res.json.matches[0].via, { peerId: A.peerId, name: A.name });

  // 成员节点（没有群存储）也能报自己所属群：这里用一个「未启用群」的节点对照
  const plain = await startNode(t, { identity: B, peerList: [A] });
  const none = await postLookup(plain, A.peerId, 'Team Alpha');
  assert.equal(none.status, 200);
  assert.deepEqual(none.json.matches, [], '没收到广播、自己也不在群里 → 无命中');
});

// ---------------------------------------------------------------------------
// §7 存储策略
// ---------------------------------------------------------------------------

test('v0.8.0 §7 known-groups：30 天 TTL 与 50 条上限（读时清理）', async (t) => {
  const dir = makeTempStateDir('dsh-lan-peers-known-');
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  // 读盘时用的是真实时钟：假时间戳必须以「现在」为基准，否则全被判成过期
  const nowMs = Date.now();
  const groups = {};
  // 60 条新条目（都在 TTL 内）+ 1 条过期条目
  for (let index = 0; index < 60; index += 1) {
    groups['g-' + String(index).padStart(2, '0')] = {
      name: 'team-' + index,
      hub: { peerId: 'hub-' + index, name: 'hub', baseUrl: 'http://10.0.0.1:7788' },
      source: { peerId: A.peerId, name: A.name },
      firstSeen: nowMs - 1_000 - index,
      lastSeen: nowMs - 1_000 - index,
    };
  }
  groups['g-stale'] = {
    name: 'old-team',
    hub: { peerId: 'hub', name: 'hub', baseUrl: 'http://10.0.0.1:7788' },
    source: { peerId: A.peerId, name: A.name },
    firstSeen: nowMs - 40 * DAY,
    lastSeen: nowMs - 40 * DAY,
  };
  writeJson0600(path.join(dir, GROUP_KNOWN_GROUPS_FILE), { groups });

  const known = readKnownGroups(dir);
  const ids = Object.keys(known.groups);
  assert.equal(ids.length, GROUP_KNOWN_GROUPS_LIMIT, '上限 50 条');
  assert.equal(ids.includes('g-stale'), false, '超过 30 天的条目在读时被丢掉');
  // 保留的是「最近见到的」那批：g-00 最新
  assert.equal(ids[0], 'g-00');

  // 写回也走同一套清理，且 0600
  const written = writeKnownGroups(dir, { groups: { 'g-fresh': groups['g-00'] } });
  assert.deepEqual(Object.keys(written.groups), ['g-fresh']);
  if (process.platform !== 'win32') assert.equal(fileMode(path.join(dir, GROUP_KNOWN_GROUPS_FILE)), 0o600);
});

// ---------------------------------------------------------------------------
// §2a 广播：对象清单、只发非成员、6 小时节流
// ---------------------------------------------------------------------------

test('v0.8.0 §2a 手动广播：只发非成员伙伴，返回对象清单，并记节流时间戳', async (t) => {
  const member = { peerId: 'peer-disc-m', name: 'mike' };
  // 假时钟必须以真实时间为基准：per-peer 签名有 ±60s 时钟窗，两台节点的表要一致
  const clock = { ms: Date.now() };
  const now = () => clock.ms;
  const hub = await startNode(t, {
    identity: A,
    peerList: [B, member],
    group: { name: 'Team Alpha', autoJoin: true },
    now,
  });
  hub.server.group.addMember(member.peerId, member.name);
  const target = await startNode(t, { identity: B, peerList: [A], now });
  const insider = await startNode(t, { identity: member, peerList: [A], now });
  hub.setPeerUrls({ [B.peerId]: target.baseUrl, [member.peerId]: insider.baseUrl });

  assert.deepEqual(
    hub.server.group.nonMemberPeers().map((peer) => peer.peerId),
    [B.peerId],
    '成员不进广播目标',
  );

  const out = await hub.server.group.broadcast();
  assert.equal(out.ok, true);
  assert.equal(out.sent.length, 1, JSON.stringify(out));
  assert.equal(out.sent[0].peerId, B.peerId);
  assert.deepEqual(out.skipped, []);

  const known = target.knownGroups();
  const groupId = hub.server.group.state().groupId;
  assert.equal(known.groups[groupId].name, 'Team Alpha');
  assert.deepEqual(known.groups[groupId].hub, {
    peerId: A.peerId,
    name: A.name,
    baseUrl: hub.baseUrl,
  });
  assert.deepEqual(known.groups[groupId].source, { peerId: A.peerId, name: A.name });
  assert.equal(insider.knownGroups(), null, '成员伙伴不该收到广播');

  const stateFile = path.join(hub.stateDir, GROUP_ADVERTISE_STATE_FILE);
  if (process.platform !== 'win32') assert.equal(fileMode(stateFile), 0o600, 'advertise-state.json 必须 0600');
  assert.equal(readAdvertiseState(hub.stateDir)[B.peerId], clock.ms);
});

test('v0.8.0 §2a 没有地址的伙伴计 no-base-url，且不影响其它伙伴发送', async (t) => {
  const noAddress = { peerId: 'peer-disc-noaddr', name: 'noaddr' };
  const hub = await startNode(t, {
    identity: A,
    peerList: [B, noAddress],
    group: { name: 'Team Alpha', autoJoin: false },
  });
  const target = await startNode(t, { identity: B, peerList: [A] });
  // 只给 B 真地址；noaddr 的 baseUrl 仍是占位（127.0.0.1:1）→ 广播里应判 no-base-url
  hub.setPeerUrls({ [B.peerId]: target.baseUrl });
  const peersFile = path.join(hub.stateDir, 'peers.json');
  const stored = readJson(peersFile);
  stored.peers[noAddress.peerId].baseUrl = null;
  writeJson0600(peersFile, stored);

  const out = await hub.server.group.broadcast();
  assert.equal(out.ok, true, JSON.stringify(out));
  assert.deepEqual(out.sent.map((entry) => entry.peerId), [B.peerId], '有地址的伙伴照常收到');
  const skipped = out.skipped.find((entry) => entry.peerId === noAddress.peerId);
  assert.ok(skipped, '没有地址的伙伴必须出现在跳过清单里');
  assert.equal(skipped.reason, 'no-base-url');

  // 收到的那台正常落盘；没地址的那台什么也没收到
  const groupId = hub.server.group.state().groupId;
  assert.equal(target.knownGroups().groups[groupId].name, 'Team Alpha');
  assert.equal(fs.existsSync(path.join(hub.stateDir, 'known-groups.json')), false, 'hub 自己不落 known-groups');
});

test('v0.8.0 §2a 启动后一次广播 + 6 小时/伙伴节流（回拨节流表验证，重启后仍生效）', async (t) => {
  // 这里不拨假时钟：per-peer 签名有 ±60s 时钟窗，把「现在」推前 6 小时会让
  // 请求本身变成 clock-skew。改成把 advertise-state.json 里的时间戳往回拨。
  const member = { peerId: 'peer-disc-m', name: 'mike' };
  const target = await startNode(t, { identity: B, peerList: [A] });
  /** 每个 hub 实例都登记一个兜底 close：断言失败时也不会留下监听句柄（测试进程会挂住） */
  const hubs = [];
  t.after(async () => {
    for (const server of hubs.reverse()) await server.close().catch(() => {});
  });

  // hub 的 stateDir 要跨重启复用：单独造目录，不走 startNode 的清理
  const hubDir = makeTempStateDir('dsh-lan-peers-advertise-');
  t.after(() => fs.rmSync(hubDir, { recursive: true, force: true }));
  writeJson0600(path.join(hubDir, 'state.json'), {
    instanceId: A.peerId,
    name: A.name,
    createdAt: new Date().toISOString(),
  });
  const startHub = async () => {
    writeJson0600(path.join(hubDir, 'peers.json'), {
      peers: {
        [B.peerId]: {
          name: B.name,
          baseUrl: target.baseUrl,
          secret: secretOf(A.peerId),
          inboundSecret: secretOf(B.peerId),
          addedAt: new Date().toISOString(),
          lastSeen: null,
        },
        [member.peerId]: {
          name: member.name,
          baseUrl: 'http://127.0.0.1:1',
          secret: secretOf(A.peerId),
          inboundSecret: secretOf(member.peerId),
          addedAt: new Date().toISOString(),
          lastSeen: null,
        },
      },
    });
    const hubLogs = [];
    const server = createPeerServer({
      listenHost: '127.0.0.1',
      stateDir: hubDir,
      name: A.name,
      requireEncryption: false,
      allowRemotePrompts: true,
      logger: (line) => hubLogs.push(String(line)),
      group: { enabled: true, name: 'Team Alpha', autoJoin: false, quorum: 'none' },
      groupReplica: { pullIntervalMs: 600_000, retryMs: 600_000 },
    });
    hubs.push(server);
    const info = await listenOnRandomPort(server);
    server.config.group.advertiseBaseUrl = info.url;
    server.group.addMember(member.peerId, member.name);
    return { server, logs: hubLogs };
  };

  const waitForAdvertise = async (count, timeoutMs = 3_000) => {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (target.logLines('[group] advertise from=').length >= count) return true;
      await sleep(50);
    }
    return false;
  };

  // 节流时间戳是请求**返回之后**才落盘的：收方的日志先出现，所以这里要等一下文件
  const waitForStamp = async (timeoutMs = 3_000) => {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const stamped = readAdvertiseState(hubDir)[B.peerId];
      if (typeof stamped === 'number') return stamped;
      await sleep(50);
    }
    return undefined;
  };

  const first = await startHub();
  assert.equal(await waitForAdvertise(1), true, '启动后一次自动广播');
  const groupId = first.server.group.state().groupId;
  const stamped = await waitForStamp();
  assert.equal(typeof stamped, 'number', '广播后记节流时间戳');
  assert.ok(Math.abs(Date.now() - stamped) < 60_000, '时间戳就是广播时刻');
  assert.equal(target.knownGroups().groups[groupId].name, 'Team Alpha');
  assert.equal(
    target.logLines('[group] advertise from=').length,
    1,
    '成员伙伴不该收到（group.json 里只有 hub 与 mike）',
  );
  await first.server.close();

  // 6 小时内重启：节流生效，不再发
  const second = await startHub();
  assert.equal(
    await waitForAdvertise(2, 1_800),
    false,
    '6 小时内不重复广播: ' + JSON.stringify(second.logs.filter((line) => line.includes('advertise'))),
  );
  await second.server.close();

  // 把节流表回拨 6 小时+1 分钟：窗口过期，必须重新广播
  writeJson0600(
    path.join(hubDir, GROUP_ADVERTISE_STATE_FILE),
    { [B.peerId]: Date.now() - GROUP_ADVERTISEMENT_THROTTLE_MS - 60_000 },
  );
  const third = await startHub();
  const again = await waitForAdvertise(2, 3_000);
  assert.equal(
    again,
    true,
    '超过节流窗口必须再广播一次: '
      + JSON.stringify(third.logs.filter((line) => line.includes('advertise')))
      + ' / target=' + JSON.stringify(target.logs.slice(-6))
      + ' / state=' + JSON.stringify(readAdvertiseState(hubDir)),
  );
  await third.server.close();
});
