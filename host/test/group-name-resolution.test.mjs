/**
 * v0.8.0 真机回归 · 成员侧群名归属（缺陷 1）。
 *
 * 现场：group-key.json 是 0.7.x 时代写的（没有 groupName 字段），于是
 *   · CLI group advertise 打出「广播群名「default」」——配置默认值冒充了真群名；
 *   · lookup 用同一个错名字比对，申请者永远查不到群。
 * 本文件钉三件事：
 *   ① hub 是群名的唯一权威：pull / 广播自愈都会把真名回写 group-key.json；
 *   ② 本地 groupName 为空时，lookup 与 advertise 都必须用 hub 的真名（不是 config 默认值）；
 *   ③ 真名拿不到时不许瞎报（advertise 直接拒发 + 报 group-name-unknown）。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { createPeerServer } from '../server.mjs';
import {
  readGroupKeyFile,
  rememberGroupNameFromState,
  writeGroupKeyFile,
} from '../../lib/group-client.mjs';
import { listenOnRandomPort, makeTempStateDir, request, writeJson0600 } from './helpers.mjs';

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'client', 'cli.mjs');

const HUB = { peerId: 'peer-name-hub', name: 'nas-box' };
const MEMBER = { peerId: 'peer-name-member', name: 'desktop-box' };
const THIRD = { peerId: 'peer-name-third', name: 'third-box' };

const secretOf = (peerId) => 'sec-' + peerId;
const GROUP_NAME = 'team';

function writePeers(dir, selfId, peers) {
  const map = {};
  for (const peer of peers) {
    map[peer.peerId] = {
      name: peer.name,
      baseUrl: peer.baseUrl ?? '',
      secret: secretOf(selfId),
      inboundSecret: secretOf(peer.peerId),
      addedAt: new Date().toISOString(),
      lastSeen: null,
    };
  }
  writeJson0600(path.join(dir, 'peers.json'), { peers: map });
}

async function startNode(t, { identity, group, stateDir }) {
  const logs = [];
  const server = createPeerServer({
    listenHost: '127.0.0.1',
    stateDir,
    name: identity.name,
    requireEncryption: false,
    allowRemotePrompts: true,
    logger: (line) => logs.push(String(line)),
    ...(group ? { group } : {}),
    // 成员补差在用例里显式驱动（默认 10s 会把测试拖慢）
    groupReplica: { pullIntervalMs: 600_000, retryMs: 600_000 },
  });
  const info = await listenOnRandomPort(server);
  if (group) server.config.group.advertiseBaseUrl = info.url;
  t.after(async () => { await server.close(); });
  return { server, baseUrl: info.url, stateDir, identity, logs };
}

const waitFor = async (check, timeoutMs = 5_000) => {
  const deadline = Date.now() + timeoutMs;
  let last;
  while (Date.now() < deadline) {
    last = await check();
    if (last) return last;
    await sleep(30);
  }
  return last;
};

/**
 * 现场复刻：A=hub（群名 team）、B=成员（group-key.json 是 0.7.x 老形状，没有 groupName）、
 * C=只与 B 配对的第三方（用来观察 B 广播出去的到底是哪个名字）。
 */
async function startRig(t, { legacyMember = true } = {}) {
  const hubDir = makeTempStateDir('dsh-lan-peers-name-hub-');
  const memberDir = makeTempStateDir('dsh-lan-peers-name-member-');
  const thirdDir = makeTempStateDir('dsh-lan-peers-name-third-');
  for (const dir of [hubDir, memberDir, thirdDir]) t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

  writeJson0600(path.join(hubDir, 'state.json'), {
    instanceId: HUB.peerId, name: HUB.name, createdAt: new Date().toISOString(),
  });
  writeJson0600(path.join(memberDir, 'state.json'), {
    instanceId: MEMBER.peerId, name: MEMBER.name, createdAt: new Date().toISOString(),
  });
  writeJson0600(path.join(thirdDir, 'state.json'), {
    instanceId: THIRD.peerId, name: THIRD.name, createdAt: new Date().toISOString(),
  });

  // A：hub，群名 team；先只认 B 这一个已配对成员
  writePeers(hubDir, HUB.peerId, [MEMBER]);
  const hub = await startNode(t, {
    identity: HUB,
    stateDir: hubDir,
    group: { enabled: true, name: GROUP_NAME, autoJoin: false, quorum: 'none' },
  });

  // B：成员，group-key.json 用 0.7.x 形状（没有 groupName 字段 —— 现场实测就是这个）
  const hubSnapshot = hub.server.group.state({ includeKey: true });
  const memberPeers = [
    { peerId: HUB.peerId, name: HUB.name, baseUrl: hub.baseUrl },
    { peerId: THIRD.peerId, name: THIRD.name, baseUrl: '' },
  ];
  writePeers(memberDir, MEMBER.peerId, memberPeers);
  const legacyKey = {
    groupId: hubSnapshot.groupId,
    key: hubSnapshot.groupKey,
    epoch: hubSnapshot.epoch,
    leaderPeerId: HUB.peerId,
    name: MEMBER.name,
    members: {
      [HUB.peerId]: { name: HUB.name, baseUrl: hub.baseUrl },
      [MEMBER.peerId]: { name: MEMBER.name, baseUrl: '' },
    },
  };
  if (!legacyMember) legacyKey.groupName = GROUP_NAME;
  writeGroupKeyFile(memberDir, legacyKey);
  assert.equal(readGroupKeyFile(memberDir).groupName, '', '前提：老文件没有群名');

  const member = await startNode(t, {
    identity: MEMBER,
    stateDir: memberDir,
    group: { enabled: true, hub: HUB.name, name: 'default', autoJoin: false, quorum: 'none' },
  });
  // 成员侧配置里的 group.name 故意留默认值 'default'：它绝不能被当群名用
  assert.equal(member.server.config.group.name, 'default');

  // C：普通节点（没有群），只与 B 配对
  writePeers(thirdDir, THIRD.peerId, [{ peerId: MEMBER.peerId, name: MEMBER.name, baseUrl: member.baseUrl }]);
  const third = await startNode(t, { identity: THIRD, stateDir: thirdDir });

  // A 认得 B（成员表），B 知道 C 的地址，C 知道 B 的地址
  hub.server.group.addMember(MEMBER.peerId, MEMBER.name);
  hub.server.group.state().members[MEMBER.peerId].baseUrl = member.baseUrl;
  writePeers(memberDir, MEMBER.peerId, [
    { peerId: HUB.peerId, name: HUB.name, baseUrl: hub.baseUrl },
    { peerId: THIRD.peerId, name: THIRD.name, baseUrl: third.baseUrl },
  ]);
  return { hub, member, third, hubDir, memberDir, thirdDir };
}

test('v0.8.0 缺陷1：pull 成功后把 hub 的权威群名回写 group-key.json（有变化才写）', async (t) => {
  const rig = await startRig(t);

  // 成员启动即 pull：群名应当被学到并落盘
  const learned = await waitFor(() => readGroupKeyFile(rig.memberDir)?.groupName === GROUP_NAME);
  assert.equal(learned, true, 'pull 之后 group-key.json 必须有 groupName=team');

  // 幂等：名字没变就不重写文件（mtime 稳定）—— 直接用回写口的单元口径验证，
  // 避免被同一轮的成员表刷新（那是另一条合法写入）搅乱
  const file = path.join(rig.memberDir, 'group-key.json');
  const before = fs.statSync(file).mtimeMs;
  await sleep(30);
  assert.equal(rememberGroupNameFromState(rig.memberDir, { name: GROUP_NAME }), GROUP_NAME);
  assert.equal(fs.statSync(file).mtimeMs, before, '群名没变就不重写文件');
  // 名字变了才写
  assert.equal(rememberGroupNameFromState(rig.memberDir, { name: 'team-renamed' }), 'team-renamed');
  assert.equal(readGroupKeyFile(rig.memberDir).groupName, 'team-renamed');
});

/** 先把启动那轮 pull 显式跑完，再把 groupName 重置成「0.7.x 老文件」状态 */
async function resetToLegacy(rig) {
  await rig.member.server.group.pull();
  const current = readGroupKeyFile(rig.memberDir);
  assert.ok(current && current.groupId && current.key, '前提：group-key.json 本身是有效的');
  writeGroupKeyFile(rig.memberDir, { ...current, groupName: '' });
  assert.equal(readGroupKeyFile(rig.memberDir).groupName, '');
}

test('v0.8.0 缺陷1：groupName 为空时 advertise 用 hub 的真名，并回写文件', async (t) => {
  const rig = await startRig(t);
  // 把文件重置成「老文件」状态，确认广播自己会自愈
  await resetToLegacy(rig);

  const out = await rig.member.server.group.broadcast();
  assert.equal(out.ok, true, JSON.stringify(out));
  assert.equal(out.name, GROUP_NAME, '广播用的名字必须是 hub 的 team');
  assert.deepEqual(out.sent.map((entry) => entry.peerId), [THIRD.peerId], JSON.stringify(out));

  // C 落盘的 known-groups 里也必须是 team
  const knownC = JSON.parse(fs.readFileSync(path.join(rig.thirdDir, 'known-groups.json'), 'utf8'));
  const groupId = rig.hub.server.group.state().groupId;
  assert.equal(knownC.groups[groupId].name, GROUP_NAME);
  assert.notEqual(knownC.groups[groupId].name, 'default', '配置默认值绝不能冒充群名');

  // 回写：group-key.json 里补上 groupName
  assert.equal(readGroupKeyFile(rig.memberDir).groupName, GROUP_NAME, 'advertise 后必须回写 groupName');
});

test('v0.8.0 缺陷1：groupName 为空时 lookup 也用 hub 的真名（申请者查得到）', async (t) => {
  const rig = await startRig(t);
  await resetToLegacy(rig);

  const groupId = rig.hub.server.group.state().groupId;
  const hit = await request(rig.member.baseUrl, {
    method: 'POST',
    path: '/v1/group/lookup',
    peerId: THIRD.peerId,
    secret: secretOf(THIRD.peerId),
    body: { name: GROUP_NAME },
  });
  assert.equal(hit.status, 200, hit.text);
  assert.equal(
    hit.json.matches.length,
    1,
    JSON.stringify(hit.json) + ' member-logs=' + JSON.stringify(rig.member.logs.slice(-8))
      + ' hub-logs=' + JSON.stringify(rig.hub.logs.slice(-8)),
  );
  assert.equal(hit.json.matches[0].name, GROUP_NAME);
  assert.equal(hit.json.matches[0].groupId, groupId);

  // 用错名字（配置默认值）查不到 —— 说明暴露的确是真名而不是 default
  const miss = await request(rig.member.baseUrl, {
    method: 'POST',
    path: '/v1/group/lookup',
    peerId: THIRD.peerId,
    secret: secretOf(THIRD.peerId),
    body: { name: 'default' },
  });
  assert.equal(miss.status, 200);
  assert.deepEqual(miss.json.matches, []);
});

test('v0.8.0 缺陷1：真名拿不到（hub 不可达且本地为空）→ 拒发并报 group-name-unknown', async (t) => {
  const rig = await startRig(t);
  await resetToLegacy(rig);
  // hub 停掉：无法现取权威群名
  await rig.hub.server.close();
  // 让成员指向一个必然连不上的地址（避免等待真实超时）
  const peersFile = path.join(rig.memberDir, 'peers.json');
  const peers = JSON.parse(fs.readFileSync(peersFile, 'utf8'));
  peers.peers[HUB.peerId].baseUrl = 'http://127.0.0.1:1';
  writeJson0600(peersFile, peers);

  const out = await rig.member.server.group.broadcast();
  assert.equal(out.ok, false);
  assert.equal(out.reason, 'group-name-unknown');
  assert.deepEqual(out.sent, []);
  assert.equal(fs.existsSync(path.join(rig.thirdDir, 'known-groups.json')), false, '没名字就一条都不发');
});

test('v0.8.0 缺陷1（CLI）：group advertise 用 hub 的真名，不是配置默认值', async (t) => {
  // 真机现场：成员那台机器上跑 CLI（host 可能没起），group-key.json 是老形状
  const hubDir = makeTempStateDir('dsh-lan-peers-name-clihub-');
  const memberDir = makeTempStateDir('dsh-lan-peers-name-climember-');
  const thirdDir = makeTempStateDir('dsh-lan-peers-name-clithird-');
  for (const dir of [hubDir, memberDir, thirdDir]) t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

  writeJson0600(path.join(hubDir, 'state.json'), {
    instanceId: HUB.peerId, name: HUB.name, createdAt: new Date().toISOString(),
  });
  writeJson0600(path.join(memberDir, 'state.json'), {
    instanceId: MEMBER.peerId, name: MEMBER.name, createdAt: new Date().toISOString(),
  });
  writeJson0600(path.join(thirdDir, 'state.json'), {
    instanceId: THIRD.peerId, name: THIRD.name, createdAt: new Date().toISOString(),
  });

  writePeers(hubDir, HUB.peerId, [MEMBER]);
  const hub = await startNode(t, {
    identity: HUB,
    stateDir: hubDir,
    group: { enabled: true, name: GROUP_NAME, autoJoin: false, quorum: 'none' },
  });
  const snapshot = hub.server.group.state({ includeKey: true });
  hub.server.group.addMember(MEMBER.peerId, MEMBER.name);

  // C：普通节点，只与 E（成员那台）配对；用来观察广播是否真的发出去
  const third = await startNode(t, { identity: THIRD, stateDir: thirdDir });
  writePeers(thirdDir, THIRD.peerId, [{ peerId: MEMBER.peerId, name: MEMBER.name, baseUrl: '' }]);
  writePeers(memberDir, MEMBER.peerId, [
    { peerId: HUB.peerId, name: HUB.name, baseUrl: hub.baseUrl },
    { peerId: THIRD.peerId, name: THIRD.name, baseUrl: third.baseUrl },
  ]);
  // E 的 group-key.json 是 0.7.x 老形状（没有 groupName）
  const legacy = {
    groupId: snapshot.groupId,
    key: snapshot.groupKey,
    epoch: snapshot.epoch,
    leaderPeerId: HUB.peerId,
    name: MEMBER.name,
    members: {
      [HUB.peerId]: { name: HUB.name, baseUrl: hub.baseUrl },
      [MEMBER.peerId]: { name: MEMBER.name, baseUrl: '' },
    },
  };
  writeJson0600(path.join(memberDir, 'group-key.json'), legacy);
  assert.equal(readGroupKeyFile(memberDir).groupName, '');

  const out = await new Promise((resolve) => {
    execFile(process.execPath, [CLI, 'group', 'advertise', '--state-dir', memberDir], { encoding: 'utf8' },
      (error, stdout, stderr) => resolve({ status: error ? error.code : 0, stdout, stderr }));
  });
  assert.equal(out.status, 0, out.stderr || out.stdout);
  assert.match(out.stdout, /广播群名「team」/, out.stdout);
  assert.doesNotMatch(out.stdout, /default/);
  // 真的发出去了（不是 no-base-url）
  assert.match(out.stdout, /发出 1 个/, out.stdout);
  assert.match(out.stdout, new RegExp('→ ' + THIRD.name), out.stdout);

  const known = JSON.parse(fs.readFileSync(path.join(thirdDir, 'known-groups.json'), 'utf8'));
  assert.equal(known.groups[snapshot.groupId].name, GROUP_NAME);
  // 回写：老文件被补上 groupName
  assert.equal(readGroupKeyFile(memberDir).groupName, GROUP_NAME);
});

