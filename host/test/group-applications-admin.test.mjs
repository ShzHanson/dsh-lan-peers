/**
 * v0.8.0 真集成回归：真 host + 真 admin（同进程 createAdmin）。
 *
 * 为什么必须有这条：lib/admin.mjs 的面板/接口调的是门面 decideApplication({peerId, action})，
 * 桩测试把它打桩了，所以「门面方法名对不上 → 面板批准 501」这种缺陷只能在真链路上暴露。
 *
 * 覆盖：GET /api/lan-peers/group/applications 的字段形状（含 introducedByName）、
 *      POST … {action:'approve'} 200 → 状态 approved → 申请者能拉到 grant → 真成员身份可用。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createAdmin } from '../../lib/admin.mjs';
import { applyGroupGrant, applyToGroup, groupCall, pollApplication } from '../../lib/group-client.mjs';
import { makeTempStateDir, peerFixture, readJson, seedPeers, startServer } from './helpers.mjs';

const APPLICANT = peerFixture('peer-admin-apply-1', { name: 'applicant-box' });

function makeResponse() {
  return {
    status: 0,
    headers: {},
    body: '',
    setHeader(key, value) { this.headers[key] = value; },
    writeHead(status, headers) { this.status = status; Object.assign(this.headers, headers || {}); },
    write(chunk) { this.body += chunk; return true; },
    end(chunk) { if (chunk) this.body += chunk; if (!this.status) this.status = 200; },
    once() {},
    on() {},
  };
}

/** 回环 admin 请求（与 GUI 面板同一个 handle 入口） */
function makeRequest(method, apiPath, body, admin) {
  const chunks = body === undefined ? [] : [Buffer.from(JSON.stringify(body))];
  const token = admin && typeof admin.token === 'string' ? admin.token : '';
  const req = {
    method,
    url: apiPath,
    socket: { remoteAddress: '127.0.0.1', setNoDelay() {} },
    // 回环 authority + 进程 token：S3 之后两道门都要过（面板带的就是这两个头）
    headers: {
      host: '127.0.0.1:7788',
      'content-type': 'application/json',
      'content-length': String(chunks[0]?.length ?? 0),
      ...(token === '' ? {} : { 'x-lan-peers-token': token }),
    },
    on() { return req; },
    once() { return req; },
    async *[Symbol.asyncIterator]() { for (const chunk of chunks) yield chunk; },
  };
  return req;
}

async function hit(admin, method, apiPath, body) {
  const res = makeResponse();
  const handled = await admin.handle(makeRequest(method, apiPath, body, admin), res, new URL('http://127.0.0.1' + apiPath));
  let json = null;
  try { json = JSON.parse(res.body); } catch { json = null; }
  return { handled, status: res.status, json };
}

test('v0.8.0 §8 真 admin：待批清单字段齐全，POST 批准 200 且申请者随后能拿到 grant', async (t) => {
  const stateDir = makeTempStateDir('dsh-lan-peers-admin-app-');
  seedPeers(stateDir, [APPLICANT]);
  const hub = await startServer(t, {
    stateDir,
    group: { enabled: true, name: 'admin-team', autoJoin: false, quorum: 'none' },
  });
  const admin = createAdmin({
    server: hub.server,
    nameOf: () => hub.server.config.name,
    rename: (next) => hub.server.store.rename(next),
  });

  // 申请者（已与 hub 配对、不在群里）走真 /v1/group/apply：介绍人就是 hub 自己
  const groupId = hub.server.group.state().groupId;
  const applied = await applyToGroup({
    baseUrl: hub.baseUrl,
    secret: APPLICANT.inboundSecret,
    senderId: APPLICANT.peerId,
    groupId,
    applicant: { peerId: APPLICANT.peerId, name: APPLICANT.name, baseUrl: 'http://10.0.0.44:7788' },
  });
  assert.equal(applied.status, 'pending', JSON.stringify(applied));

  // ① GET /api/lan-peers/group/applications —— 面板拿到的形状
  const listed = await hit(admin, 'GET', '/api/lan-peers/group/applications');
  assert.equal(listed.handled, true);
  assert.equal(listed.status, 200, JSON.stringify(listed.json));
  assert.equal(listed.json.applications.length, 1);
  const [pending] = listed.json.applications;
  assert.equal(pending.peerId, APPLICANT.peerId);
  assert.equal(pending.name, APPLICANT.name);
  assert.equal(pending.status, 'pending');
  assert.equal(pending.introducedBy, hub.server.store.instanceId, '介绍人就是 hub 自己');
  assert.equal(typeof pending.introducedByName, 'string', '面板要的名字字段必须在');
  assert.equal(pending.introducedByName.length > 0, true, '介绍人名字不能是空串');
  assert.equal(typeof pending.at, 'number');
  // decidedAt 目前只做字段存在性断言：admin 的归一化按「数值时间戳」理解，
  // 落盘的是 ISO 字符串，面板并不渲染它（这里不把 admin 的归一化口径钉进契约）。
  assert.ok('decidedAt' in pending);

  // ② POST … {action:'approve'} —— 这里曾经因为门面方法名不一致走 501
  const approved = await hit(admin, 'POST', '/api/lan-peers/group/applications', {
    peerId: APPLICANT.peerId,
    action: 'approve',
  });
  assert.equal(approved.handled, true);
  assert.equal(approved.status, 200, JSON.stringify(approved.json));
  assert.deepEqual(approved.json, { ok: true, status: 'approved' });
  assert.ok(hub.server.group.state().members[APPLICANT.peerId], '批准后必须真的进成员表');

  // 清单里那条变成 approved
  const after = await hit(admin, 'GET', '/api/lan-peers/group/applications');
  assert.equal(after.status, 200, JSON.stringify(after.json));
  assert.equal(after.json.applications[0].status, 'approved');
  assert.ok('decidedAt' in after.json.applications[0]);

  // ③ 申请者随后能拉到 grant，并真的能读群
  const polled = await pollApplication({
    baseUrl: hub.baseUrl,
    secret: APPLICANT.inboundSecret,
    senderId: APPLICANT.peerId,
    groupId,
  });
  assert.equal(polled.status, 'approved');
  assert.equal(polled.grant.groupId, groupId);
  assert.equal(typeof polled.grant.key, 'string');
  const applicantDir = makeTempStateDir('dsh-lan-peers-admin-grant-');
  t.after(() => fs.rmSync(applicantDir, { recursive: true, force: true }));
  const written = applyGroupGrant(applicantDir, polled.grant);
  assert.equal(readJson(path.join(applicantDir, 'group-key.json')).key, written.key);
  const view = await groupCall({
    baseUrl: hub.baseUrl,
    groupKey: written.key,
    groupId,
    senderId: APPLICANT.peerId,
    method: 'GET',
    apiPath: '/v1/group/pull?sinceSeq=0&limit=5',
  });
  assert.equal(view.groupId, groupId);

  // ④ 拒绝路径同样走门面（action:'reject'）：这条记录已被批准过，改判拒绝即可证明接线正确
  const rejected = await hit(admin, 'POST', '/api/lan-peers/group/applications', {
    peerId: APPLICANT.peerId,
    action: 'reject',
  });
  assert.equal(rejected.status, 200, JSON.stringify(rejected.json));
  assert.deepEqual(rejected.json, { ok: true, status: 'rejected' });

  // 非法 action 由 admin 层挡下（400），门面不会被调用
  const bad = await hit(admin, 'POST', '/api/lan-peers/group/applications', {
    peerId: APPLICANT.peerId,
    action: 'maybe',
  });
  assert.equal(bad.status, 400);
  assert.equal(bad.json.error, 'bad-action');
});

test('v0.8.0 §8 门面：decideApplication 接受四种 action 写法，未知申请返回 ok:false', async (t) => {
  const stateDir = makeTempStateDir('dsh-lan-peers-admin-app2-');
  seedPeers(stateDir, [APPLICANT]);
  const hub = await startServer(t, {
    stateDir,
    group: { enabled: true, name: 'admin-team', autoJoin: false, quorum: 'none' },
  });
  const group = hub.server.group;
  // 真申请路径造一条 pending（这样每次 decide 都有同一条记录可翻）
  const applied = await applyToGroup({
    baseUrl: hub.baseUrl,
    secret: APPLICANT.inboundSecret,
    senderId: APPLICANT.peerId,
    groupId: group.state().groupId,
    applicant: { peerId: APPLICANT.peerId, name: APPLICANT.name, baseUrl: 'http://10.0.0.44:7788' },
  });
  assert.equal(applied.status, 'pending', JSON.stringify(applied));

  for (const [action, status] of [['approve', 'approved'], ['APPROVED', 'approved'],
    ['reject', 'rejected'], ['Rejected', 'rejected']]) {
    const out = await group.decideApplication({ peerId: APPLICANT.peerId, action });
    assert.equal(out.ok, true, action);
    assert.equal(out.status, status, action);
  }

  const missing = await group.decideApplication({ peerId: 'nobody-here', action: 'approve' });
  assert.deepEqual(missing, { ok: false, reason: 'unknown-application' });

  const badAction = await group.decideApplication({ peerId: APPLICANT.peerId, action: 'nope' });
  assert.equal(badAction.ok, false);
  assert.equal(badAction.reason, 'bad-action');

  // 便捷别名与 applications() 仍在（老测试/脚本用）
  assert.equal(typeof group.approveApplication, 'function');
  assert.equal(typeof group.rejectApplication, 'function');

  // 门面视图：介绍人给两种形态（对象供面板取名、纯 peerId 供脚本比对），
  // decidedAt 落盘是 ISO 字符串，未决定时为 null。
  const [view] = group.applications();
  assert.equal(view.introducedByPeerId, view.introducedBy.peerId);
  assert.equal(typeof view.introducedBy.name, 'string');
  assert.equal(view.introducedBy.name.length > 0, true);
  assert.equal(typeof view.decidedAt, 'string');
  assert.ok(Number.isFinite(Date.parse(view.decidedAt)));
});
