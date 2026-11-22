// dsh-lan-peers · 0.12.8-alpha（slice H）群摘要：**线上**那一段（真节点、真群签名、真 pull）。
//
//   H1 hub 计数触发：40 条新消息 → 恰好一条摘要；平面形状 {rev,hubId,digests}；提示里只有群消息正文
//   H2 成员 pull 采纳 hub 摘要（rev 40）；非 hub 作者那份（rev 更大）被忽略、盘上不动
//   H3 没有摘要会话 → fallback 摘要在 hub 与成员两边都在（平面永不停摆）
//   H4 成员节点：摘要门面一律 hub-only，一次摘要会话都不建（注入的通道永远不被叫）
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

import { DIGEST_OUT_FILE } from '../../lib/group-digest.mjs';
import { secretOf, startCluster, waitFor } from './group-cluster.mjs';

/** 提示里那条「路径：<绝对路径>」——正文 handoff 的唯一来源 */
function handoffPathIn(prompt) {
  const line = prompt.split('\n').find((row) => row.startsWith('路径：'));
  return line ? line.slice('路径：'.length) : '';
}

/** 立刻补差一次：后台节拍可能正有一轮在飞（那时 pull() 报 skipped），让一让再试 */
async function pullNow(member, attempts = 40) {
  for (let index = 0; index < attempts; index += 1) {
    const out = await member.server.group.pull();
    if (out?.reason !== 'skipped') return out;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error('member pull kept being skipped');
}

/** hub 本机发一条群消息（面板/CLI 走的就是这条同步门面） */
const postHub = (hub, text) => hub.server.group.post({
  peerId: hub.peerId,
  name: hub.name,
  kind: 'chat',
  text,
});

const digestFileOf = (node) => JSON.parse(fs.readFileSync(path.join(node.dir, 'group-digests.json'), 'utf8'));

test('H1 hub 计数触发：40 条 → 一条摘要、窗口 1..40、平面形状对、提示里只有群消息正文', async (t) => {
  const cluster = await startCluster(t, { count: 2 });
  const [hub, member] = cluster.nodes;
  const prompts = [];
  // 摘要会话通道：只记账，回一段固定摘要（真机上这就是那个 hub 侧会话）
  assert.equal(hub.server.group.digest.setPrompt(async (sessionId, prompt) => {
    prompts.push({ sessionId, prompt });
    return { sessionId: sessionId || 's-digest', reused: sessionId !== '', reply: '大家确认了周四上线，张三补压测报告。' };
  }).ok, true);

  for (let index = 1; index <= 39; index += 1) postHub(hub, '第 ' + index + ' 条：进度同步');
  assert.equal(hub.server.group.digest.count(), 0, '39 条还不该有摘要');
  assert.equal(hub.server.group.digest.state().pending, 39);
  assert.equal(prompts.length, 0, '不到 40 条不许叫模型');
  postHub(hub, '第 40 条：压测报告我来写');

  assert.equal(await waitFor(() => hub.server.group.digest.count() === 1), true, '第 40 条必须触发一次摘要');
  assert.equal(prompts.length, 1, '恰好一次模型调用');
  const plane = hub.server.group.digest.plane();
  assert.deepEqual(Object.keys(plane).sort(), ['digests', 'hubId', 'rev']);
  assert.equal(plane.rev, 40);
  assert.equal(plane.hubId, hub.peerId, '平面必须自带 hub 作者身份（成员据此判作者）');
  assert.equal(plane.digests.length, 1);
  const only = plane.digests[0];
  assert.equal(only.fromSeq, 1);
  assert.equal(only.toSeq, 40);
  assert.equal(only.source, 'agent');
  assert.equal(only.text, '大家确认了周四上线，张三补压测报告。');

  // 提示里只有群消息正文：有 seq 与正文，没有对端密钥/文件名之类的别的东西
  assert.ok(prompts[0].prompt.includes('seq=1 '), '提示要带 seq');
  assert.ok(prompts[0].prompt.includes('第 40 条：压测报告我来写'));
  assert.equal(prompts[0].prompt.includes(secretOf(member.peerId)), false, '提示里不许出现对端密钥');
  assert.equal(prompts[0].prompt.includes(secretOf(hub.peerId)), false, '提示里不许出现本机密钥');

  // 正文 handoff：提示里给的是**绝对路径**，且只由 hub 的 stateDir 推出（不来自模型输出）
  const handoff = handoffPathIn(prompts[0].prompt);
  assert.equal(path.isAbsolute(handoff), true, 'handoff 路径必须是绝对路径');
  assert.equal(path.basename(handoff), DIGEST_OUT_FILE);
  assert.equal(handoff, path.join(path.resolve(hub.dir), DIGEST_OUT_FILE), '路径由 stateDir 推出');
  assert.ok(prompts[0].prompt.includes('DONE'), '回复只要一个 DONE');
  assert.equal(fs.existsSync(handoff), false, '这一趟没写文件 → 退回回复，且 stateDir 里不留文件');

  // 盘上就是那份 {version:1, digests:[...]}
  const file = digestFileOf(hub);
  assert.equal(file.version, 1);
  assert.equal(file.digests.length, 1);
  assert.equal(file.digests[0].digestId, 'd-1-40');

  // 没有新消息：再来一趟（计数路）什么都不写
  const again = hub.server.group.digest.summarize('count');
  const settled = await again;
  assert.equal(settled.ok, false);
  assert.equal(settled.error, 'no-new');
  assert.equal(hub.server.group.digest.count(), 1);
  assert.equal(prompts.length, 1);
});

test('H2 成员采纳 hub 摘要；非 hub 作者那份（rev 更大）被忽略', async (t) => {
  const cluster = await startCluster(t, { count: 2 });
  const [hub, member] = cluster.nodes;
  hub.server.group.digest.setPrompt(async (sessionId, prompt) => ({
    sessionId: sessionId || 's-digest',
    reused: sessionId !== '',
    reply: '摘要：周三冻结版本。',
  }));
  for (let index = 1; index <= 40; index += 1) postHub(hub, '消息 ' + index);
  assert.equal(await waitFor(() => hub.server.group.digest.count() === 1), true);

  await pullNow(member);
  const mirror = member.server.group.digest.plane();
  assert.equal(mirror.rev, 40, '成员镜像的 rev 必须跟得上 hub');
  assert.equal(mirror.hubId, hub.peerId);
  assert.equal(mirror.digests.length, 1);
  assert.equal(mirror.digests[0].text, '摘要：周三冻结版本。');
  assert.equal(member.server.group.digest.state().isHub, false, '成员不是作者');

  // 冒充：rev 更大但作者不是 hub → 一个字节都不落盘
  const before = JSON.stringify(member.server.group.digest.plane());
  const forged = {
    rev: 9_999,
    hubId: member.peerId,
    digests: [{ digestId: 'd-41-80', fromSeq: 41, toSeq: 80, at: 1, source: 'agent', text: '伪造摘要' }],
  };
  const ignored = member.server.group.digest.applyReplica(forged, { hubId: hub.peerId });
  assert.equal(ignored.adopted, false);
  assert.equal(ignored.error, 'not-hub-authored');
  assert.equal(JSON.stringify(member.server.group.digest.plane()), before);
  assert.equal(digestFileOf(member).digests.length, 1);
});

test('H3 没有摘要会话 → fallback 摘要，hub 与成员两边都有（平面不停摆）', async (t) => {
  const cluster = await startCluster(t, { count: 2 });
  const [hub, member] = cluster.nodes;
  // 故意不 setPrompt：装配里没有摘要会话 = 真机上「会话造不出来」那一条
  for (let index = 1; index <= 40; index += 1) postHub(hub, '原始消息 ' + index);
  assert.equal(await waitFor(() => hub.server.group.digest.count() === 1), true);
  const plane = hub.server.group.digest.plane();
  assert.equal(plane.rev, 40, '兜底摘要一样推 rev');
  assert.equal(plane.digests[0].source, 'fallback');
  assert.match(plane.digests[0].text, /^\[digest\] 40 条群消息（seq 1-40/);

  await pullNow(member);
  const mirror = member.server.group.digest.plane();
  assert.equal(mirror.rev, 40);
  assert.equal(mirror.digests[0].source, 'fallback');
  assert.match(mirror.digests[0].text, /^\[digest\] 40 条群消息（seq 1-40/);
});

test('H4 成员节点：摘要门面一律 hub-only，一次摘要会话都不建', async (t) => {
  const cluster = await startCluster(t, { count: 2 });
  const [hub, member] = cluster.nodes;
  let creates = 0;
  const refused = member.server.group.digest.setPrompt(async () => {
    creates += 1;
    return { sessionId: 's-x', reused: false, reply: '不该出现' };
  });
  assert.equal(refused.ok, false);
  assert.equal(refused.error, 'hub-only');
  const summarizing = await member.server.group.digest.summarize('timer');
  assert.equal(summarizing.error, 'hub-only');
  assert.equal(member.server.group.digest.noteNew().error, 'hub-only');
  assert.equal(member.server.group.digest.state().isHub, false);

  // 成员照样收得到群消息（原文），但绝不因此造摘要会话
  for (let index = 1; index <= 40; index += 1) postHub(hub, '群里第 ' + index + ' 条');
  assert.equal(await waitFor(() => hub.server.group.digest.count() === 1), true);
  await pullNow(member);
  const mirror = member.server.group.digest.plane();
  assert.equal(mirror.hubId, hub.peerId, '成员手上那份永远是 hub 写的');
  assert.equal(member.server.group.digest.state().count, mirror.digests.length);
  assert.equal(creates, 0, '成员节点一次摘要会话都不该建');
  assert.equal(fs.existsSync(path.join(member.dir, 'group-digest-session.json')), false);
});
