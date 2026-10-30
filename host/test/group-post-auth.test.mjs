/**
 * v0.8.0 §9 · /v1/group/post 的新增鉴权模式（群级签名）。
 *
 * 背景（真机）：按名入群的成员只有 group-key.json 里的群密钥，没有与 hub 的 per-peer 密钥。
 * 若 post 只认 per-peer，它就「只能读不能发言」—— 与群聊目的不符。
 * 本文件钉五件事：
 *   ① 群级签名 post 成功，且 from 以签名为准（body 里的 from/peerId 一律忽略）；
 *   ② 非成员用群级签名 post → 401/403；
 *   ③ 被移除（blocked）的成员 → 拒；
 *   ④ per-peer 的既有行为一字不变（含 403 not-a-member、非法 kind 400、超长 413）；
 *   ⑤ CLI 在只有 group-key hub 时 group post 真的发得出去。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as sleep } from 'node:timers/promises';
import { createPeerServer } from '../server.mjs';
import {
  applyGroupGrant,
  decryptGroupJson,
  deriveGroupKeys,
  encryptGroupBody,
  groupAuthHeaders,
  postGroup,
  readGroupKeyFile,
} from '../../lib/group-client.mjs';
import { listenOnRandomPort, makeTempStateDir, peerFixture, seedPeers, startServer, writeJson0600 } from './helpers.mjs';

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'client', 'cli.mjs');
const MEMBER = peerFixture('peer-post-auth-1', { name: 'member-box' });
const OUTSIDER = peerFixture('peer-post-auth-2', { name: 'outsider-box' });
const KEYLESS = { peerId: 'peer-post-auth-3', name: 'keyless-box' };

/** hub：MEMBER 已入群；OUTSIDER 已配对但不在群里；KEYLESS 从来没配对过（只有群密钥） */
async function startHub(t) {
  const stateDir = makeTempStateDir('dsh-lan-peers-post-auth-');
  seedPeers(stateDir, [MEMBER, OUTSIDER]);
  const started = await startServer(t, {
    stateDir,
    group: { enabled: true, name: 'team', autoJoin: false, quorum: 'none' },
  });
  started.server.group.addMember(MEMBER.peerId, MEMBER.name);
  return started;
}

const groupKeyOf = (hub) => hub.server.group.state({ includeKey: true }).groupKey;
const groupIdOf = (hub) => hub.server.group.state().groupId;

/** 群级签名请求（响应按群信封解密）；可选注入伪造的 from/peerId */
async function groupRequest(baseUrl, { groupKey, groupId, senderId, method = 'POST', path: apiPath, body }) {
  const { headers, plain } = groupAuthHeaders({
    groupKey, groupId, senderId, method, apiPath, body,
  });
  const { bodyKey } = deriveGroupKeys(groupKey);
  const wire = plain.length ? Buffer.from(encryptGroupBody(bodyKey, plain), 'utf8') : Buffer.alloc(0);
  const res = await fetch(new URL(apiPath, baseUrl), {
    method,
    headers: { ...headers, 'x-peer-enc': 'v1' },
    body: wire.length ? wire : undefined,
  });
  const text = await res.text();
  let json = null;
  try {
    const parsed = JSON.parse(text);
    json = parsed && parsed.enc === 'v1' && typeof parsed.data === 'string'
      ? decryptGroupJson(bodyKey, parsed.data)
      : parsed;
  } catch { json = null; }
  return { status: res.status, json, text };
}

test('v0.8.0 §9 群级签名 post 成功，from 以签名为准（body 里的 from/peerId 被忽略）', async (t) => {
  const hub = await startHub(t);
  const groupKey = groupKeyOf(hub);
  const groupId = groupIdOf(hub);

  const res = await groupRequest(hub.baseUrl, {
    groupKey,
    groupId,
    senderId: MEMBER.peerId,
    path: '/v1/group/post',
    body: {
      kind: 'chat',
      text: 'hello via group-auth',
      // 刻意伪造：必须被忽略
      from: { peerId: OUTSIDER.peerId, name: 'forged' },
      peerId: OUTSIDER.peerId,
      name: 'forged',
    },
  });
  assert.equal(res.status, 201, JSON.stringify(res.json));
  assert.equal(typeof res.json.seq, 'number');

  const [message] = hub.server.group.history({ sinceSeq: 0 });
  assert.equal(message.text, 'hello via group-auth');
  assert.equal(message.from.peerId, MEMBER.peerId, '作者 = 签名里的 sender');
  assert.notEqual(message.from.peerId, OUTSIDER.peerId);
  assert.equal(message.from.name, MEMBER.name, '名字取成员表，不取 body');
});

test('v0.8.0 §9 群级签名 post：非成员 401/403，被移除（blocked）成员拒', async (t) => {
  const hub = await startHub(t);
  const groupKey = groupKeyOf(hub);
  const groupId = groupIdOf(hub);
  const post = (senderId, body = { kind: 'chat', text: 'x' }) => groupRequest(hub.baseUrl, {
    groupKey, groupId, senderId, path: '/v1/group/post', body,
  });

  // 已配对但不在成员表
  const outsider = await post(OUTSIDER.peerId);
  assert.equal(outsider.status, 401, JSON.stringify(outsider.json));
  assert.equal(outsider.json.error, 'not-a-member');

  // 从没配对、也不在成员表
  const stranger = await post(KEYLESS.peerId);
  assert.equal(stranger.status, 401, JSON.stringify(stranger.json));

  // 被移除的成员：旧群密钥直接 bad-signature（密钥已轮换），换新钥也不是成员
  await post(MEMBER.peerId, { kind: 'chat', text: 'before-kick' });
  hub.server.group.removeMember(MEMBER.peerId);
  const rotated = groupKeyOf(hub);
  const blocked = await groupRequest(hub.baseUrl, {
    groupKey: rotated,
    groupId,
    senderId: MEMBER.peerId,
    path: '/v1/group/post',
    body: { kind: 'chat', text: 'after-kick' },
  });
  assert.ok([401, 403].includes(blocked.status), JSON.stringify(blocked.json));
  assert.equal(hub.server.group.state().members[MEMBER.peerId], undefined);
});

test('v0.8.0 §9 成员表里还在、但 blocked 名单里有 → 群级 post 必须拒（403 blocked）', async (t) => {
  // 「还在成员表里却被 blocked」是防御深度要覆盖的脏状态（手工改过 group.json、或移除流程中断）。
  // 用预置 group.json 直接造出来：blocked 的判定不能依赖成员表。
  const stateDir = makeTempStateDir('dsh-lan-peers-post-blocked-');
  const groupId = 'group-post-auth-blocked';
  const groupKey = 'k'.repeat(43);
  writeJson0600(path.join(stateDir, 'group.json'), {
    groupId,
    name: 'team',
    key: groupKey,
    keyVersion: 1,
    createdAt: new Date().toISOString(),
    members: {
      'hub-owner': { name: 'hub', addedAt: new Date().toISOString() },
      [MEMBER.peerId]: { name: MEMBER.name, addedAt: new Date().toISOString() },
    },
    blocked: { [MEMBER.peerId]: new Date().toISOString() },
    messages: [],
    pending: [],
    lastSeq: 0,
  });
  writeJson0600(path.join(stateDir, 'state.json'), {
    instanceId: 'hub-owner', name: 'hub', createdAt: new Date().toISOString(),
  });
  seedPeers(stateDir, [MEMBER]);
  const hub = await startServer(t, {
    stateDir,
    group: { enabled: true, name: 'team', autoJoin: false, quorum: 'none' },
  });
  // 前提：成员表里确实有它（否则测的就不是 blocked 分支了）
  assert.ok(hub.server.group.state().members[MEMBER.peerId]);
  assert.equal(hub.server.group.isBlocked(MEMBER.peerId), true);

  const res = await groupRequest(hub.baseUrl, {
    groupKey,
    groupId,
    senderId: MEMBER.peerId,
    path: '/v1/group/post',
    body: { kind: 'chat', text: 'blocked speaker' },
  });
  assert.equal(res.status, 403, JSON.stringify(res.json));
  assert.equal(res.json.error, 'blocked');
  assert.equal(hub.server.group.state().lastSeq, 0, '被拒的发言不能落库');
});

test('v0.8.0 §9 per-peer 的 post 行为一字不变（403 not-a-member / 400 / 413 / 201）', async (t) => {
  const hub = await startHub(t);
  const asMember = (body) => postGroup({
    baseUrl: hub.baseUrl, secret: MEMBER.inboundSecret, senderId: MEMBER.peerId, kind: body.kind, text: body.text ?? '',
  });

  const ok = await asMember({ kind: 'chat', text: 'per-peer still works' });
  assert.equal(typeof ok.seq, 'number');

  // 非成员：403 not-a-member（与 v0.5.0 一致）
  const outsider = await postGroup({
    baseUrl: hub.baseUrl, secret: OUTSIDER.inboundSecret, senderId: OUTSIDER.peerId, kind: 'chat', text: 'x',
  }).catch((error) => error);
  assert.match(String(outsider.message), /403/);

  // 非法 kind / 超长 text：400 / 413
  const badKind = await postGroup({
    baseUrl: hub.baseUrl, secret: MEMBER.inboundSecret, senderId: MEMBER.peerId, kind: 'nope', text: 'x',
  }).catch((error) => error);
  assert.match(String(badKind.message), /400/);
  const tooLong = await asMember({ kind: 'chat', text: 'x'.repeat(4001) }).catch((error) => error);
  assert.match(String(tooLong.message), /413/);
});

test('v0.8.0 §9 群级 post 的正文校验与 per-peer 同口径（400/413），且不写进日志正文', async (t) => {
  const hub = await startHub(t);
  const groupKey = groupKeyOf(hub);
  const groupId = groupIdOf(hub);
  const post = (body) => groupRequest(hub.baseUrl, {
    groupKey, groupId, senderId: MEMBER.peerId, path: '/v1/group/post', body,
  });
  assert.equal((await post({ kind: 'nope', text: 'x' })).status, 400);
  assert.equal((await post({ kind: 'chat', text: 'x'.repeat(4001) })).status, 413);
  assert.equal((await post({ kind: 'chat', text: 'ok' })).status, 201);
});

test('v0.8.0 §9 CLI：只有 group-key hub 时 group post 真的发得出去', async (t) => {
  const hub = await startHub(t);
  // 申请者节点：没有群配置、也没有 hub 的配对记录，只有 grant 落盘的 group-key.json
  const joinerDir = makeTempStateDir('dsh-lan-peers-post-cli-');
  t.after(() => fs.rmSync(joinerDir, { recursive: true, force: true }));
  writeJson0600(path.join(joinerDir, 'state.json'), {
    instanceId: KEYLESS.peerId, name: KEYLESS.name, createdAt: new Date().toISOString(),
  });
  writeJson0600(path.join(joinerDir, 'peers.json'), { peers: {} });
  hub.server.group.addMember(KEYLESS.peerId, KEYLESS.name);
  const snapshot = hub.server.group.state({ includeKey: true });
  applyGroupGrant(joinerDir, {
    groupId: snapshot.groupId,
    name: snapshot.name,
    keyVersion: snapshot.keyVersion,
    key: snapshot.groupKey,
    hub: {
      peerId: hub.server.store.instanceId,
      name: hub.server.config.name,
      baseUrl: hub.baseUrl,
    },
    members: Object.entries(snapshot.members).map(([peerId, member]) => ({ peerId, name: String(member?.name ?? '') })),
  });
  assert.equal(readGroupKeyFile(joinerDir).hub.baseUrl, hub.baseUrl);

  const out = await new Promise((resolve) => {
    execFile(process.execPath, [CLI, 'group', 'post', '--text', 'from cli', '--state-dir', joinerDir],
      { encoding: 'utf8' }, (error, stdout, stderr) => resolve({ status: error ? error.code : 0, stdout, stderr }));
  });
  assert.equal(out.status, 0, out.stderr || out.stdout);
  assert.match(out.stdout, /已发送 seq=/);
  assert.match(out.stdout, /群级签名直连/);

  // hub 侧真的收到了，且作者是这台「只有群密钥」的节点
  const messages = hub.server.group.history({ sinceSeq: 0 });
  const last = messages.at(-1);
  assert.equal(last.text, 'from cli');
  assert.equal(last.from.peerId, KEYLESS.peerId);
  await sleep(1);
});
