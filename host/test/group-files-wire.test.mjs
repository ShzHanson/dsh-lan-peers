// dsh-lan-peers · 0.12.0-α（S2）群文件：**线上**那一段（真节点、真群签名、真信封）。
//
//   U1 三块上传 → finish：hub 盘上 sha 一致、公告 rev 前进（管理接口 send 走的是同一条路径）
//   U2 前跳 409 / 重放 200 replay:true 且 hub 盘上不出现重复字节
//   U3 坏块 → 409 integrity-failed，半截删掉，公告一条都不多
//   U4 配额（小配额集群）：第 4 份把 LRU 逐出（gone:true + pull 409）；超配额 → 413
//   U5 成员拉全文件 sha 一致；非目标成员 403 forbidden；非成员连门都进不来
//   U6 可见性：targets:[peerId] 只给那个人，targets:'all' 两边都见
//   U7 成员写平面 → 403 files-hub-only；成员镜像 rev 跟得上 hub
//   U8 withdraw：hub 删字节、公告翻 gone，成员镜像跟着变，pull 409
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';

import { setTimeout as sleep } from 'node:timers/promises';

import { groupCall } from '../../lib/group-client.mjs';
import { visibleFiles } from '../../lib/group-files.mjs';
import { startCluster, waitFor } from './group-cluster.mjs';

const sha256 = (buffer) => createHash('sha256').update(buffer).digest('hex');

function payload(length, seed = 7) {
  const buffer = Buffer.alloc(length);
  for (let index = 0; index < length; index += 1) buffer[index] = (index * 31 + seed) & 0xff;
  return buffer;
}

/** 群级签名的一条请求（与成员/提案走同一个通道）；失败抛 error.status / error.code */
function callAs(cluster, baseUrl, senderId, method, apiPath, body) {
  return groupCall({
    baseUrl,
    groupKey: cluster.groupKey,
    groupId: cluster.groupId,
    senderId,
    method,
    apiPath,
    body,
    timeoutMs: 15_000,
  });
}

const postAs = (cluster, baseUrl, senderId, apiPath, body) => callAs(cluster, baseUrl, senderId, 'POST', apiPath, body);

async function expectCode(promise, status, code) {
  await assert.rejects(promise, (error) => {
    assert.equal(error.status, status, 'HTTP 状态：' + String(error.message));
    assert.equal(error.code, code, '错误码：' + String(error.message));
    return true;
  });
}

/** 一条完整的上传：init → upload×N → finish（分块按 400 字节，用例要断言逐块 received） */
async function uploadFile(cluster, baseUrl, senderId, { name = 'r.bin', data, targets = 'all', chunkSize = 400 }) {
  const fileId = randomUUID();
  const init = await postAs(cluster, baseUrl, senderId, '/v1/group/file/init', {
    fileId, name, size: data.length, sha256: sha256(data), targets,
  });
  let offset = 0;
  const chunks = [];
  while (offset < data.length) {
    const slice = data.subarray(offset, Math.min(data.length, offset + chunkSize));
    const out = await postAs(cluster, baseUrl, senderId, '/v1/group/file/upload', {
      fileId, offset, dataBase64: slice.toString('base64'),
    });
    chunks.push(out);
    offset = Number(out.received);
  }
  const done = await postAs(cluster, baseUrl, senderId, '/v1/group/file/finish', { fileId });
  return { fileId, init, chunks, done };
}

/** 成员侧拉全文件（与面板/CLI 的下载同一个循环）；返回拼好的字节 */
async function pullAll(cluster, baseUrl, senderId, fileId, { chunkHint = 0 } = {}) {
  const pieces = [];
  let offset = 0;
  for (let round = 0; round < 64; round += 1) {
    const page = await postAs(cluster, baseUrl, senderId, '/v1/group/file/pull', { fileId, offset });
    const data = Buffer.from(String(page.dataBase64 ?? ''), 'base64');
    pieces.push(data);
    offset += data.length;
    if (page.eof === true || data.length === 0) break;
  }
  if (chunkHint) assert.equal(offset, chunkHint, '拉下来的字节数要等于声明 size');
  return Buffer.concat(pieces);
}

const pullNow = (member, attempts = 40) => (async () => {
  for (let index = 0; index < attempts; index += 1) {
    const out = await member.server.group.pull();
    if (out?.reason !== 'skipped') return out;
  }
  throw new Error('member pull kept being skipped');
})();

/** 管理接口的最小请求/应答桩（与 group-replica 的 N4/N5 同款） */
function adminRequest(admin, method, url, body) {
  const chunks = body === undefined ? [] : [Buffer.from(JSON.stringify(body))];
  const req = {
    method,
    url,
    socket: { remoteAddress: '127.0.0.1', setNoDelay() {} },
    headers: {
      host: '127.0.0.1:7788',
      'content-type': 'application/json',
      'content-length': String(chunks[0]?.length ?? 0),
      'x-lan-peers-token': String(admin.token ?? ''),
    },
    on() { return req; },
    once() { return req; },
    async *[Symbol.asyncIterator]() { for (const chunk of chunks) yield chunk; },
  };
  const res = {
    status: 0, headers: {}, body: '',
    setHeader(k, v) { this.headers[k] = v; },
    writeHead(status, headers) { this.status = status; Object.assign(this.headers, headers || {}); },
    write(chunk) { this.body += chunk; return true; },
    end(chunk) { if (chunk) this.body += chunk; if (!this.status) this.status = 200; },
    once() {}, on() {},
  };
  return { req, res };
}

async function hitAdmin(admin, method, apiPath, body) {
  const { req, res } = adminRequest(admin, method, apiPath, body);
  await admin.handle(req, res, new URL('http://127.0.0.1' + apiPath));
  return { status: res.status, json: (() => { try { return JSON.parse(res.body); } catch { return null; } })() };
}

test('S2-U1 三块上传 → finish：hub 盘上 sha 一致、公告 rev 前进（管理接口 send 同一条路径）', async (t) => {
  const cluster = await startCluster(t, { count: 2 });
  const [hub, member] = cluster.nodes;
  const data = payload(1_200, 3);

  const { fileId, init, chunks, done } = await uploadFile(cluster, hub.baseUrl, member.peerId, { name: '季度报告.pdf', data });
  assert.equal(init.ok, true);
  assert.equal(init.received, 0);
  assert.deepEqual(chunks.map((row) => row.received), [400, 800, 1_200], '逐块 received 必须单调到 size');
  assert.deepEqual(chunks.map((row) => row.replay), [false, false, false]);
  assert.equal(done.ok, true);
  assert.equal(done.size, data.length);
  assert.equal(done.sha256, sha256(data), 'finish 报回的 sha256 必须是盘上校验过的那个');
  assert.ok(done.rev >= 1, '公告 rev 必须前进');

  // hub 盘上真的有这份字节，且逐字相同
  const onDisk = path.join(hub.dir, 'group-files', fileId, 'data');
  assert.equal(fs.existsSync(onDisk), true, 'hub 必须收下这份字节（成员不再各自留一份）');
  assert.equal(sha256(fs.readFileSync(onDisk)), sha256(data));

  // 公告：同一条出现在平面里，rev 与 finish 一致
  const plane = hub.server.group.files.plane();
  assert.equal(plane.rev, done.rev);
  const row = plane.files.find((entry) => entry.fileId === fileId);
  assert.ok(row, 'finish 之后必须在公告里');
  assert.equal(row.name, '季度报告.pdf');
  assert.equal(row.size, data.length);
  assert.equal(row.sha256, sha256(data));
  assert.equal(row.from.peerId, member.peerId);
  assert.equal(row.gone, false);

  // 管理接口 send（hub 自己）走的是同一条语义：本地 apply*，不经回环 HTTP
  const { createAdmin } = await import('../../lib/admin.mjs');
  const hubAdmin = createAdmin({ server: hub.server });
  const localPath = path.join(hub.dir, 'send-local.bin');
  fs.writeFileSync(localPath, payload(900, 9));
  const sent = await hitAdmin(hubAdmin, 'POST', '/api/lan-peers/group/files/send', { peerId: 'all', path: localPath });
  assert.equal(sent.status, 200, JSON.stringify(sent.json));
  assert.equal(sent.json.ok, true);
  assert.equal(sent.json.bytes, 900);
  assert.equal(sent.json.sha256, sha256(fs.readFileSync(localPath)));
  assert.ok(hub.server.group.files.plane().files.some((entry) => entry.fileId === sent.json.fileId));
});

test('S2-U2 前跳 409、重放 200 replay:true 且盘上不重复写；续传能收完', async (t) => {
  const cluster = await startCluster(t, { count: 2 });
  const [hub, member] = cluster.nodes;
  const data = payload(1_200, 5);
  const fileId = randomUUID();
  await postAs(cluster, hub.baseUrl, member.peerId, '/v1/group/file/init', {
    fileId, name: 'g.bin', size: data.length, sha256: sha256(data), targets: 'all',
  });
  const first = await postAs(cluster, hub.baseUrl, member.peerId, '/v1/group/file/upload', {
    fileId, offset: 0, dataBase64: data.subarray(0, 400).toString('base64'),
  });
  assert.equal(first.received, 400);

  // 前跳（空洞）：offset 800 > received 400 → 409 offset-mismatch，并把 received 报回来
  await assert.rejects(
    () => postAs(cluster, hub.baseUrl, member.peerId, '/v1/group/file/upload', {
      fileId, offset: 800, dataBase64: data.subarray(800).toString('base64'),
    }),
    (error) => {
      assert.equal(error.status, 409);
      assert.equal(error.code, 'offset-mismatch');
      assert.equal(error.body?.received, 400, '要报回已收字节，客户端据此重对齐');
      return true;
    },
  );

  // 重放已收尾部：200 replay:true，且 hub 盘上**长度不变**
  const replay = await postAs(cluster, hub.baseUrl, member.peerId, '/v1/group/file/upload', {
    fileId, offset: 0, dataBase64: data.subarray(0, 400).toString('base64'),
  });
  assert.equal(replay.ok, true);
  assert.equal(replay.replay, true);
  assert.equal(replay.received, 400);
  const hubData = path.join(hub.dir, 'group-files', fileId, 'data');
  assert.equal(fs.statSync(hubData).size, 400, '重放不得把字节写第二遍');

  // 续传把剩下的拉完 → finish 成功
  const rest = Buffer.concat([data.subarray(400, 800), data.subarray(800)]);
  assert.equal((await postAs(cluster, hub.baseUrl, member.peerId, '/v1/group/file/upload', {
    fileId, offset: 400, dataBase64: rest.toString('base64'),
  })).received, 1_200);
  const done = await postAs(cluster, hub.baseUrl, member.peerId, '/v1/group/file/finish', { fileId });
  assert.equal(done.sha256, sha256(data));
});

test('S2-U3 坏块 → 409 integrity-failed，半截删掉，公告一条都不多', async (t) => {
  const cluster = await startCluster(t, { count: 2 });
  const [hub, member] = cluster.nodes;
  const good = payload(600, 4);
  const evil = Buffer.from(good);
  evil[17] ^= 0xff;
  const fileId = randomUUID();
  const revBefore = hub.server.group.files.plane().rev;
  await postAs(cluster, hub.baseUrl, member.peerId, '/v1/group/file/init', {
    fileId, name: 'bad.bin', size: good.length, sha256: sha256(good), targets: 'all',
  });
  assert.equal((await postAs(cluster, hub.baseUrl, member.peerId, '/v1/group/file/upload', {
    fileId, offset: 0, dataBase64: evil.toString('base64'),
  })).received, good.length);

  await expectCode(
    postAs(cluster, hub.baseUrl, member.peerId, '/v1/group/file/finish', { fileId }),
    409,
    'integrity-failed',
  );
  assert.equal(fs.existsSync(path.join(hub.dir, 'group-files', fileId)), false, '校验失败的半截必须删掉');
  assert.equal(hub.server.group.files.plane().rev, revBefore, '失败的校验不得推进公告 rev');
  assert.equal(hub.server.group.files.plane().files.some((entry) => entry.fileId === fileId), false);
  await expectCode(
    postAs(cluster, hub.baseUrl, member.peerId, '/v1/group/file/pull', { fileId, offset: 0 }),
    404,
    'unknown-file',
  );
});

test('S2-U4 小配额：第 4 份把 LRU 逐出（gone:true + pull 409）；超配额 → 413 且不清空', async (t) => {
  const previous = process.env.GROUP_FILES_QUOTA_BYTES;
  // 配额 3000：三份 1000 字节正好填满，第四份只能靠逐出才进得来（真实 20 GiB 是同一个数）
  process.env.GROUP_FILES_QUOTA_BYTES = '3000';
  let cluster;
  try {
    cluster = await startCluster(t, { count: 2 });
  } finally {
    if (previous === undefined) delete process.env.GROUP_FILES_QUOTA_BYTES;
    else process.env.GROUP_FILES_QUOTA_BYTES = previous;
  }
  const [hub, member] = cluster.nodes;
  assert.equal(hub.server.group.files.quotaBytes(), 3_000, '集群按环境变量起了小配额');

  // LRU 需要**可分辨**的 lastAccessAt：真机上三份文件不会落在同一毫秒，用例里补一点间隔
  const ids = [];
  for (let index = 0; index < 3; index += 1) {
    const { fileId } = await uploadFile(cluster, hub.baseUrl, member.peerId, {
      name: 'f' + index + '.bin', data: payload(1_000, index + 1),
    });
    ids.push(fileId);
    await sleep(15);
  }
  assert.equal(hub.server.group.files.plane().files.filter((row) => row.gone !== true).length, 3);

  await sleep(15);
  const fourth = await uploadFile(cluster, hub.baseUrl, member.peerId, { name: 'f3.bin', data: payload(1_000, 4) });
  assert.equal(fourth.done.ok, true, '第四份必须成功（先腾地方再收字节）');
  assert.equal(fs.existsSync(path.join(hub.dir, 'group-files', ids[0])), false, '逐出即删目录');
  assert.equal(fs.existsSync(path.join(hub.dir, 'group-files', ids[1])), true, '只有最久没被用的那一份被逐出');
  assert.equal(fs.existsSync(path.join(hub.dir, 'group-files', ids[2])), true);
  const plane = hub.server.group.files.plane();
  const evictedRow = plane.files.find((row) => row.fileId === ids[0]);
  assert.ok(evictedRow, '被逐出的条目要留在公告里');
  assert.equal(evictedRow.gone, true, '成员要看到「已失效」，不是凭空消失');
  assert.equal(plane.files.find((row) => row.fileId === fourth.fileId).gone, false);
  await expectCode(
    postAs(cluster, hub.baseUrl, member.peerId, '/v1/group/file/pull', { fileId: ids[0], offset: 0 }),
    409,
    'file-gone',
  );

  // 比整份配额还大：413 too-large，且**一个字节都不逐出**
  const survivors = hub.server.group.files.plane().files.filter((row) => row.gone !== true).length;
  await expectCode(
    postAs(cluster, hub.baseUrl, member.peerId, '/v1/group/file/init', {
      fileId: randomUUID(), name: 'huge.bin', size: 3_100, sha256: sha256(payload(8)), targets: 'all',
    }),
    413,
    'too-large',
  );
  assert.equal(
    hub.server.group.files.plane().files.filter((row) => row.gone !== true).length,
    survivors,
    '装不下的东西不得让别人被清空',
  );
});

test('S2-U5 成员拉全文件 sha 一致；非目标成员 403；非成员连门都进不来', async (t) => {
  const cluster = await startCluster(t, { count: 3 });
  const [hub, m1, m2] = cluster.nodes;
  const data = payload(1_100, 6);
  const { fileId, done } = await uploadFile(cluster, hub.baseUrl, m1.peerId, { name: 'all.bin', data });
  assert.equal(done.rev >= 1, true);

  // 真·第二个节点按块拉下来，sha 与 hub 上那份逐字相同
  const pulled = await pullAll(cluster, hub.baseUrl, m2.peerId, fileId, { chunkHint: data.length });
  assert.equal(sha256(pulled), sha256(data));
  assert.deepEqual(pulled, data);

  // 非目标成员：targets 只点自己之外的人 → 403 forbidden（「不是你的，一个字节也拿不走」）
  const targeted = await uploadFile(cluster, hub.baseUrl, m1.peerId, {
    name: 'only-m1.bin', data: payload(300, 8), targets: [m1.peerId],
  });
  await expectCode(
    postAs(cluster, hub.baseUrl, m2.peerId, '/v1/group/file/pull', { fileId: targeted.fileId, offset: 0 }),
    403,
    'forbidden',
  );
  // 非成员：连群级鉴权都过不了（比 403 更早一层的「不给答复」）
  await expectCode(
    postAs(cluster, hub.baseUrl, 'ghost-peer-not-in-group', '/v1/group/file/pull', { fileId, offset: 0 }),
    401,
    'not-a-member',
  );
});

test('S2-U6 可见性：targets:[peerId] 只给那个人，targets:all 两边都见（hub 全见）', async (t) => {
  const cluster = await startCluster(t, { count: 3 });
  const [hub, m1, m2] = cluster.nodes;
  const everyone = await uploadFile(cluster, hub.baseUrl, m1.peerId, { name: 'everyone.bin', data: payload(200, 2) });
  const onlyM2 = await uploadFile(cluster, hub.baseUrl, m1.peerId, {
    name: 'only-m2.bin', data: payload(200, 3), targets: [m2.peerId],
  });

  await pullNow(m1);
  await pullNow(m2);
  const m1Seen = m1.server.group.files.plane().files.map((row) => row.fileId);
  const m2Seen = m2.server.group.files.plane().files.map((row) => row.fileId);
  assert.equal(m1Seen.includes(everyone.fileId), true, 'targets:all 对谁都可见');
  assert.equal(m2Seen.includes(everyone.fileId), true);
  assert.equal(m1Seen.includes(onlyM2.fileId), false, '点名给 m2 的不得出现在 m1 的镜像里');
  assert.equal(m2Seen.includes(onlyM2.fileId), true);
  const hubSeen = hub.server.group.files.plane().files.map((row) => row.fileId);
  assert.equal(hubSeen.includes(everyone.fileId) && hubSeen.includes(onlyM2.fileId), true, 'hub 全见');
});

test('S2-U7 成员写平面 → 403 files-hub-only；成员镜像 rev 跟得上 hub', async (t) => {
  const cluster = await startCluster(t, { count: 2 });
  const [hub, member] = cluster.nodes;
  const { fileId, done } = await uploadFile(cluster, hub.baseUrl, member.peerId, {
    name: 'plane.bin', data: payload(400, 7),
  });
  // 成员写平面：与纪要同一条口径（门在 handler，不在白名单）
  await expectCode(postAs(cluster, hub.baseUrl, member.peerId, '/v1/group/files', {}), 403, 'files-hub-only');
  assert.equal(hub.server.group.files.plane().files.some((row) => row.fileId === fileId), true);

  // 成员不写、只读：pull 之后镜像 rev 与 hub 一致
  await pullNow(member);
  const hubPlane = hub.server.group.files.plane();
  const memberPlane = member.server.group.files.plane();
  assert.equal(memberPlane.rev, hubPlane.rev, '镜像 rev 必须跟得上 hub');
  assert.equal(memberPlane.files.some((row) => row.fileId === fileId), true);
  assert.equal(hubPlane.rev, done.rev);

  // 成员的管理接口读到的是同一份可见列表（面板 S3 要的三个状态字段都在）
  const { createAdmin } = await import('../../lib/admin.mjs');
  const memberAdmin = createAdmin({ server: member.server });
  const listed = await hitAdmin(memberAdmin, 'GET', '/api/lan-peers/group/files');
  assert.equal(listed.status, 200, JSON.stringify(listed.json));
  assert.equal(listed.json.rev, hubPlane.rev);
  const row = listed.json.files.find((entry) => entry.fileId === fileId);
  assert.equal(row.gone, false);
  assert.equal(row.downloaded, false, '还没下载过 → downloaded=false');
  assert.equal(row.mine, true, '自己传的 → mine=true');

  // 真下载一次 → 本机 inbox 有了，downloaded 翻真
  const downloaded = await hitAdmin(memberAdmin, 'POST', '/api/lan-peers/group/files/download', { fileId });
  assert.equal(downloaded.status, 200, JSON.stringify(downloaded.json));
  assert.equal(downloaded.json.bytes, 400);
  assert.equal(downloaded.json.sha256, done.sha256);
  const after = await hitAdmin(memberAdmin, 'GET', '/api/lan-peers/group/files');
  assert.equal(after.json.files.find((entry) => entry.fileId === fileId).downloaded, true);
});

test('S2-U8 withdraw：hub 删字节、公告翻 gone、成员镜像跟着变、pull 409', async (t) => {
  const cluster = await startCluster(t, { count: 3 });
  const [hub, m1, m2] = cluster.nodes;
  const data = payload(500, 8);
  const { fileId } = await uploadFile(cluster, hub.baseUrl, m1.peerId, { name: 'withdraw.bin', data });
  await pullNow(m1);
  await pullNow(m2);
  assert.equal(m1.server.group.files.plane().files.some((row) => row.fileId === fileId), true);

  // 只有上传者（或 hub）能收回：别的成员 403
  await expectCode(postAs(cluster, hub.baseUrl, m2.peerId, '/v1/group/file/withdraw', { fileId }), 403, 'forbidden');

  const out = await postAs(cluster, hub.baseUrl, m1.peerId, '/v1/group/file/withdraw', { fileId });
  assert.equal(out.ok, true);
  assert.equal(out.removed, true);
  assert.equal(out.gone, true);
  assert.equal(fs.existsSync(path.join(hub.dir, 'group-files', fileId)), false, 'hub 上的字节必须没了');
  const hubRow = hub.server.group.files.plane().files.find((row) => row.fileId === fileId);
  assert.ok(hubRow, '公告条目留着（墓碑），不是凭空消失');
  assert.equal(hubRow.gone, true);
  assert.equal(hub.server.group.files.plane().rev, out.rev);
  await expectCode(
    postAs(cluster, hub.baseUrl, m2.peerId, '/v1/group/file/pull', { fileId, offset: 0 }),
    409,
    'file-gone',
  );

  // 成员镜像：rev 前进到 hub 的 rev，条目 gone:true（谁都不能再显示成「可下载」）
  await pullNow(m1);
  await pullNow(m2);
  for (const node of [m1, m2]) {
    const plane = node.server.group.files.plane();
    assert.equal(plane.rev, out.rev);
    assert.equal(plane.files.find((row) => row.fileId === fileId).gone, true);
  }
});

// ---------------------------------------------------------------------------
// S3b：群发不再只认本机绝对路径 —— 浏览器选的文件走同一条 group 路由链
//
// 非空化：把 admin 的 files/upload/finish 里的 groupScope 分支拆掉（一律走
// facade.send）→ 下面「hub 盘上有字节 / 公告有这一条 / 没有 DM offer」三组断言全红，
// 因为那一刻走的是私聊 offer，hub 的群字节存储一个字节都收不到。
// ---------------------------------------------------------------------------

/** 浏览器上传链（管理接口那一侧）：init → chunk × N，返回 uploadId。 */
async function adminUpload(admin, { name, bytes, chunk = 400 }) {
  const init = await hitAdmin(admin, 'POST', '/api/lan-peers/files/upload/init', { name, bytes: bytes.length });
  assert.equal(init.status, 200, JSON.stringify(init.json));
  const uploadId = String(init.json.uploadId ?? '');
  assert.ok(uploadId !== '');
  let offset = 0;
  while (offset < bytes.length) {
    const slice = bytes.subarray(offset, Math.min(bytes.length, offset + chunk));
    const out = await hitAdmin(admin, 'POST', '/api/lan-peers/files/upload/chunk', {
      uploadId,
      offset,
      dataBase64: Buffer.from(slice).toString('base64'),
    });
    assert.equal(out.status, 200, JSON.stringify(out.json));
    offset += slice.length;
  }
  return uploadId;
}

test('Q3/Q4 files/upload/finish scope:group —— hub 收下字节、公告按 targets 可见、临时目录消失、无 DM offer', async (t) => {
  const cluster = await startCluster(t, { count: 3 });
  const [hub, m1, m2] = cluster.nodes;
  const { createAdmin } = await import('../../lib/admin.mjs');
  const hubAdmin = createAdmin({ server: hub.server });

  for (const [targets, visibleTo, hiddenFrom] of [
    ['all', [m1.peerId, m2.peerId], null],
    [m2.peerId, [m2.peerId], m1.peerId],
  ]) {
    const data = payload(900, 11);
    const name = 'browser-' + (targets === 'all' ? 'all' : 'direct') + '.bin';
    const uploadId = await adminUpload(hubAdmin, { name, bytes: data });
    const uploadDir = path.join(hub.dir, '.upload-tmp', uploadId);
    assert.equal(fs.existsSync(uploadDir), true, '上传过程中临时目录必须在');

    const finish = await hitAdmin(hubAdmin, 'POST', '/api/lan-peers/files/upload/finish', {
      uploadId, scope: 'group', targets,
    });
    assert.equal(finish.status, 200, JSON.stringify(finish.json));
    assert.equal(finish.json.ok, true);
    assert.equal(finish.json.uploadId, uploadId);
    assert.equal(finish.json.offer, undefined, '群这一趟没有 offer 这一格');
    const fileId = String(finish.json.fileId ?? '');
    assert.ok(fileId !== '');

    // 1) hub 盘上真的有这份字节，且逐字相同
    const onDisk = path.join(hub.dir, 'group-files', fileId, 'data');
    assert.equal(fs.existsSync(onDisk), true, 'hub 必须收下这份字节');
    assert.equal(sha256(fs.readFileSync(onDisk)), sha256(data));
    assert.equal(finish.json.sha256, sha256(data));

    // 2) 公告带着这一趟的 targets
    const plane = hub.server.group.files.plane();
    const row = plane.files.find((entry) => entry.fileId === fileId);
    assert.ok(row, 'finish 之后必须有这一条公告');
    assert.deepEqual(row.targets, targets === 'all' ? 'all' : [m2.peerId]);
    assert.equal(row.name, name);
    assert.equal(row.sha256, sha256(data));

    // 3) 可见性只走既有那一个实现
    for (const peerId of visibleTo) {
      assert.equal(
        visibleFiles(plane, { peerId }).some((entry) => entry.fileId === fileId),
        true,
        'targets 里的人必须看得见：' + peerId.slice(0, 8),
      );
    }
    if (hiddenFrom) {
      assert.equal(
        visibleFiles(plane, { peerId: hiddenFrom }).some((entry) => entry.fileId === fileId),
        false,
        '没被点名的人看不见：' + hiddenFrom.slice(0, 8),
      );
    }

    // 4) 临时目录不见了（同一个 finally），5) 没有挂出任何私聊 offer
    assert.equal(fs.existsSync(uploadDir), false, 'finish 之后临时目录必须消失');
    assert.deepEqual(hub.server.files.outbox(), [], '不许留下一条私聊 keeper 拷贝');
    assert.deepEqual(hub.server.files.list().filter((entry) => entry.state === 'offer'), [],
      '不许挂出私聊 offer（群这一趟终点在 hub）');
  }
});
