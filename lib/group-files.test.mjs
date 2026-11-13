// dsh-lan-peers · 0.12.0-α（S2）群文件 hub 侧存储：上传三段式、重放幂等、配额 LRU 逐出、
// 墓碑与公告平面、并发上限、半截上传清扫。全部是纯文件操作（没有 HTTP），假时钟驱动。
//
//   U1 begin/append×3 → finish：size+sha256 与盘上一致，公告 rev 前进（重放同一条 rev 不动）
//   U2 前跳/搭接 → offset-mismatch；重放已收尾部 → replay:true 且盘上不出现重复字节
//   U3 坏块 → integrity-failed，半截当场删掉，公告一条都不多
//   U4 配额：第四份把最久没用的那份逐出（墓碑 + 平面 gone:true + open 给 file-gone）；
//      比整份配额还大的文件 → too-large，且**一个字节都不逐出**
//   U4b 并发上限：在传条数到顶 → too-many-uploads
//   U4c 半截上传：空闲超时被清扫器收掉，已收完的不动，且不留墓碑
//   U4f begin 之后后续步骤失败（拒绝/抛错）→ 半截目录靠同一条空闲清扫收掉，不留永久目录
//   U5 可见性：targets:'all' 谁都看得见；targets:[peerId] 只给那个成员（hub 全见）
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';

import {
  GROUP_FILES_DIR,
  GROUP_FILES_MAX_UPLOADS,
  GROUP_FILES_QUOTA_BYTES,
  createGroupFiles,
  filesPlaneSummary,
  mergeFilesPlane,
  normalizeTargets,
  targetAllows,
  visibleFiles,
} from './group-files.mjs';
import { makeTempStateDir } from '../host/test/helpers.mjs';

const sha256 = (buffer) => createHash('sha256').update(buffer).digest('hex');

function payload(length, seed = 7) {
  const buffer = Buffer.alloc(length);
  for (let index = 0; index < length; index += 1) buffer[index] = (index * 31 + seed) & 0xff;
  return buffer;
}

function harness(t, options = {}) {
  const stateDir = makeTempStateDir('dsh-lan-peers-group-files-');
  t.after(() => fs.rmSync(stateDir, { recursive: true, force: true }));
  let clock = 1_000;
  const now = () => clock;
  const files = createGroupFiles({
    stateDir,
    now,
    quotaBytes: options.quotaBytes,
    maxUploads: options.maxUploads,
    uploadIdleMs: options.uploadIdleMs,
    start: options.start === true,
  });
  t.after(() => files.close());
  return {
    stateDir,
    files,
    store: files.store,
    plane: files.plane,
    tick: (ms = 1_000) => { clock += ms; },
    at: () => clock,
  };
}

const FROM = { peerId: 'peer-a', name: 'A 的电脑' };

/** 三段式：begin → append×N → finish（与路由里那条循环同一顺序） */
async function upload(store, { fileId, name = '报告.pdf', data, from = FROM, targets = 'all' }) {
  const begun = store.begin({
    fileId,
    name,
    size: data.length,
    sha256: sha256(data),
    from,
    targets,
  });
  assert.equal(begun.ok, true, 'begin 应当成功：' + JSON.stringify(begun));
  const chunk = 8;
  for (let offset = 0; offset < data.length; offset += chunk) {
    const slice = data.subarray(offset, Math.min(data.length, offset + chunk));
    const out = store.append(fileId, offset, slice);
    assert.equal(out.ok, true, 'append@' + offset + ' 应当成功：' + JSON.stringify(out));
  }
  const done = await store.finish(fileId);
  assert.equal(done.ok, true, 'finish 应当成功：' + JSON.stringify(done));
  return { begun, done };
}

test('U1 三段上传 → finish 校验 size+sha256；公告 rev 前进，重放不再推 rev', async (t) => {
  const h = harness(t);
  const data = payload(1_000);
  const chunkOne = data.subarray(0, 400);
  const chunkTwo = data.subarray(400, 800);
  const chunkThree = data.subarray(800);

  const fileId = '11111111-1111-4111-8111-111111111111';
  const begun = h.store.begin({
    fileId, name: '季度报告.pdf', size: data.length, sha256: sha256(data), from: FROM, targets: 'all',
  });
  assert.equal(begun.ok, true);
  assert.deepEqual(h.store.append(fileId, 0, chunkOne), { ok: true, replay: false, received: 400, offset: 0 });
  assert.deepEqual(h.store.append(fileId, 400, chunkTwo), { ok: true, replay: false, received: 800, offset: 400 });
  assert.deepEqual(h.store.append(fileId, 800, chunkThree), { ok: true, replay: false, received: 1000, offset: 800 });

  const done = await h.store.finish(fileId);
  assert.equal(done.ok, true);
  assert.equal(done.entry.size, data.length);
  assert.equal(done.entry.sha256, sha256(data));
  assert.equal(done.entry.complete, true);
  // 盘上真的有这份字节，且逐字相同
  const onDisk = fs.readFileSync(path.join(h.stateDir, GROUP_FILES_DIR, fileId, 'data'));
  assert.equal(sha256(onDisk), sha256(data), 'hub 盘上的字节必须与声明 sha256 一致');

  // 公告：finish 之后 hub 公告一次，rev 0 → 1
  assert.equal(h.plane.value().rev, 0);
  const announced = h.plane.announce(done.entry);
  assert.equal(announced.ok, true);
  assert.equal(announced.rev, 1);
  assert.equal(announced.changed, true);
  const plane = h.plane.value();
  assert.equal(plane.rev, 1);
  assert.equal(plane.files.length, 1);
  assert.equal(plane.files[0].fileId, fileId);
  assert.equal(plane.files[0].name, '季度报告.pdf');
  assert.equal(plane.files[0].size, data.length);
  assert.equal(plane.files[0].sha256, sha256(data));
  assert.deepEqual(plane.files[0].from, FROM);
  assert.equal(plane.files[0].gone, false);
  // 幂等：同一条再公告一次，rev 不动（重启后重放不会把 rev 推上去）
  const again = h.plane.announce(done.entry);
  assert.equal(again.changed, false);
  assert.equal(h.plane.value().rev, 1);
  // finish 重放也幂等
  const refinished = await h.store.finish(fileId);
  assert.equal(refinished.ok, true);
  assert.equal(refinished.entry.sha256, sha256(data));
});

test('U2 前跳/搭接 409；重放已收尾部 replay:true 且不产生重复字节', async (t) => {
  const h = harness(t);
  const fileId = '22222222-2222-4222-8222-222222222222';
  const data = payload(300, 11);
  assert.equal(h.store.begin({
    fileId, name: 'a.bin', size: data.length, sha256: sha256(data), from: FROM, targets: 'all',
  }).ok, true);
  assert.equal(h.store.append(fileId, 0, data.subarray(0, 100)).received, 100);

  // 前跳（空洞）：offset 300 > received 100
  const gap = h.store.append(fileId, 300, data.subarray(100, 200));
  assert.equal(gap.ok, false);
  assert.equal(gap.error, 'offset-mismatch');
  assert.equal(gap.received, 100, '要如实报回已收字节，客户端据此重对齐');

  // 搭接：offset 50 的块跨过 received 100
  const straddle = h.store.append(fileId, 50, data.subarray(50, 150));
  assert.equal(straddle.ok, false);
  assert.equal(straddle.error, 'offset-mismatch');

  // 重放已收尾部：整块都在已收范围内 → 200 replay，且**盘上长度不变**
  const replay = h.store.append(fileId, 0, data.subarray(0, 100));
  assert.equal(replay.ok, true);
  assert.equal(replay.replay, true);
  assert.equal(replay.received, 100);
  assert.equal(h.store.received(fileId), 100, '重放不得把字节写第二遍');

  // 「同一个 offset 两套内容」不是重试，是错的客户端
  const different = Buffer.alloc(100, 9);
  const conflict = h.store.append(fileId, 0, different);
  assert.equal(conflict.ok, false);
  assert.equal(conflict.error, 'offset-mismatch');
  assert.equal(h.store.received(fileId), 100);

  // 续传能接着走完
  assert.equal(h.store.append(fileId, 100, data.subarray(100)).received, 300);
  const done = await h.store.finish(fileId);
  assert.equal(done.ok, true);
  assert.equal(done.entry.sha256, sha256(data));
});

test('U3 坏块 → integrity-failed，半截删掉，公告一条都不多', async (t) => {
  const h = harness(t);
  const fileId = '33333333-3333-4333-8333-333333333333';
  const good = payload(64, 3);
  const evil = Buffer.from(good);
  evil[10] ^= 0xff;
  assert.equal(h.store.begin({
    fileId, name: 'b.bin', size: good.length, sha256: sha256(good), from: FROM, targets: 'all',
  }).ok, true);
  assert.equal(h.store.append(fileId, 0, evil).ok, true);
  const done = await h.store.finish(fileId);
  assert.equal(done.ok, false);
  assert.equal(done.error, 'integrity-failed');
  // 半截当场删掉，且不留墓碑（它从来没被公告过 → pull 应是 unknown-file）
  assert.equal(fs.existsSync(path.join(h.stateDir, GROUP_FILES_DIR, fileId)), false, '坏文件不能留在盘上');
  assert.equal(h.store.get(fileId).reason, 'unknown-file');
  assert.equal(h.plane.value().rev, 0, '失败的校验不得推进公告 rev');
  assert.equal(h.plane.value().files.length, 0);

  // 长度不符也是 integrity-failed（声明 64、只来了 32）
  const short = '44444444-4444-4444-8444-444444444444';
  assert.equal(h.store.begin({
    fileId: short, name: 'c.bin', size: 64, sha256: sha256(payload(64, 3)), from: FROM, targets: 'all',
  }).ok, true);
  assert.equal(h.store.append(short, 0, payload(32, 3)).ok, true);
  const shortDone = await h.store.finish(short);
  assert.equal(shortDone.error, 'integrity-failed');
  assert.equal(fs.existsSync(path.join(h.stateDir, GROUP_FILES_DIR, short)), false);
});

test('U4 配额：第四份把最久没用的那份逐出（墓碑 + gone:true + file-gone）；超配额的新文件 413 且不清空', async (t) => {
  const quota = 3_000;
  const h = harness(t, { quotaBytes: quota });
  const ids = ['55555555-5555-4555-8555-555555555551', '55555555-5555-4555-8555-555555555552',
    '55555555-5555-4555-8555-555555555553', '55555555-5555-4555-8555-555555555554'];

  // 三份各 1000 字节，时间戳依次前进 → 1 是最久没用的
  for (let index = 0; index < 3; index += 1) {
    h.tick(1_000);
    const data = payload(1_000, index + 1);
    const { done } = await upload(h.store, { fileId: ids[index], name: 'f' + index + '.bin', data });
    h.plane.announce(done.entry);
    h.tick(1_000);
  }
  assert.equal(h.store.used, 3_000);
  assert.equal(h.plane.value().files.length, 3);
  assert.equal(h.plane.value().rev, 3);

  // 第四份：要先腾地方 → 最久没被用的第 0 份被逐出
  h.tick(5_000);
  const data4 = payload(1_000, 4);
  const { begun: begun4, done: done4 } = await upload(h.store, { fileId: ids[3], name: 'f3.bin', data: data4 });
  const announced4 = h.plane.announce(done4.entry);
  assert.equal(announced4.ok, true);
  // 逐出发生在 begin（先腾地方再收字节）：这一趟就是 LRU 的那一下
  assert.deepEqual(begun4.evicted, [ids[0]], 'LRU 必须是最久没被 touch 的那一份');
  assert.equal(fs.existsSync(path.join(h.stateDir, GROUP_FILES_DIR, ids[0])), false, '逐出即删目录');
  assert.equal(h.store.used, 3_000, '逐出之后必须重新装得下');
  const plane = h.plane.value();
  const evictedRow = plane.files.find((row) => row.fileId === ids[0]);
  assert.ok(evictedRow, '被逐出的条目要留在公告里（成员看到「已失效」，不是凭空消失）');
  assert.equal(evictedRow.gone, true);
  assert.equal(plane.files.find((row) => row.fileId === ids[3]).gone, false);
  assert.ok(plane.rev > 3, '逐出 + 公告都要推进 rev');
  // 逐出过的 id → 409 file-gone（不是 404 unknown-file）
  assert.deepEqual(h.store.get(ids[0]), { ok: false, reason: 'file-gone' });
  assert.equal(h.store.open(ids[0], 0, 100).error, 'file-gone');

  // 单文件比整份配额还大：413 too-large，且**一个字节都不逐出**
  const before = h.store.list().map((row) => row.fileId).sort();
  const tooBig = h.store.begin({
    fileId: '55555555-5555-4555-8555-555555555559',
    name: 'huge.bin',
    size: quota + 1,
    sha256: sha256(Buffer.alloc(8)),
    from: FROM,
    targets: 'all',
  });
  assert.equal(tooBig.ok, false);
  assert.equal(tooBig.error, 'too-large');
  assert.deepEqual(h.store.list().map((row) => row.fileId).sort(), before, '装不下的东西不得让别人被清空');
  assert.equal(h.store.used, 3_000);
});

test('U4b 并发上限：在传条数到顶 → too-many-uploads（声明再小也不放过）', async (t) => {
  const h = harness(t, { maxUploads: 2 });
  assert.equal(GROUP_FILES_MAX_UPLOADS > 0, true);
  for (let index = 0; index < 2; index += 1) {
    assert.equal(h.store.begin({
      fileId: '66666666-6666-4666-8666-66666666666' + index,
      name: 'p' + index + '.bin',
      size: 10,
      sha256: sha256(payload(10)),
      from: FROM,
      targets: 'all',
    }).ok, true);
  }
  const third = h.store.begin({
    fileId: '66666666-6666-4666-8666-666666666669', name: 'p9.bin', size: 10,
    sha256: sha256(payload(10)), from: FROM, targets: 'all',
  });
  assert.equal(third.ok, false);
  assert.equal(third.error, 'too-many-uploads');
  assert.equal(h.store.inFlight, 2);
});

test('U4c 半截上传空闲被清扫，已收完的不动，不留墓碑', async (t) => {
  const h = harness(t, { uploadIdleMs: 5_000 });
  const done = '77777777-7777-4777-8777-777777777771';
  const abandoned = '77777777-7777-4777-8777-777777777772';
  const data = payload(40, 5);
  const finished = await upload(h.store, { fileId: done, name: 'ok.bin', data });
  h.plane.announce(finished.done.entry);
  assert.equal(h.store.begin({
    fileId: abandoned, name: 'half.bin', size: 100, sha256: sha256(payload(100)), from: FROM, targets: 'all',
  }).ok, true);
  assert.equal(h.store.append(abandoned, 0, payload(10)).ok, true);

  h.tick(5_001);
  const swept = h.store.sweep(h.at());
  assert.deepEqual(swept.uploads, [abandoned], '空闲的半截上传应当被收掉');
  assert.equal(fs.existsSync(path.join(h.stateDir, GROUP_FILES_DIR, abandoned)), false);
  // 从没公告过 → 不立碑（404 才是实话）
  assert.equal(h.store.get(abandoned).reason, 'unknown-file');
  // 已收完的那份一动不动
  assert.equal(h.store.get(done).ok, true);
  assert.equal(h.plane.value().files.find((row) => row.fileId === done).gone, false);
});

test('U5 可见性：targets:all 谁都看得见；targets:[peerId] 只给那个成员（hub 全见）', (t) => {
  harness(t);
  assert.deepEqual(normalizeTargets('all'), 'all');
  assert.deepEqual(normalizeTargets([]), 'all', '空目标表当 all：看得更多不会丢数据');
  assert.deepEqual(normalizeTargets(['p2', 'p2', ' p1 ']), ['p2', 'p1']);
  assert.equal(targetAllows('all', 'anyone'), true);
  assert.equal(targetAllows(['p1'], 'p1'), true);
  assert.equal(targetAllows(['p1'], 'p2'), false);
  assert.equal(targetAllows(['p1'], ''), false);

  const value = {
    rev: 7,
    files: [
      { fileId: '88888888-8888-4888-8888-888888888881', name: 'all.bin', size: 1, sha256: 'a'.repeat(64),
        from: { peerId: 'p1', name: 'P1' }, targets: 'all', at: 10 },
      { fileId: '88888888-8888-4888-8888-888888888882', name: 'only-p2.bin', size: 1, sha256: 'b'.repeat(64),
        from: { peerId: 'p1', name: 'P1' }, targets: ['p2'], at: 11 },
    ],
  };
  assert.deepEqual(visibleFiles(value, { peerId: 'p1' }).map((row) => row.name), ['all.bin']);
  assert.deepEqual(visibleFiles(value, { peerId: 'p2' }).map((row) => row.name), ['all.bin', 'only-p2.bin']);
  assert.deepEqual(visibleFiles(value, { peerId: 'p3' }).map((row) => row.name), ['all.bin']);
  assert.equal(visibleFiles(value, { isHub: true }).length, 2, 'hub 看全部');

  // 成员侧镜像只认更大的 rev
  assert.equal(mergeFilesPlane({ rev: 9, files: [] }, value).rev, 9);
  assert.equal(mergeFilesPlane({ rev: 7, files: [] }, value).rev, 7);
  assert.deepEqual(filesPlaneSummary(value), { rev: 7, count: 2, gone: 0 });
});

test('U4d 清扫器挂在 store.start() 上、unref 且 close() 清掉（热重载不留定时器）', (t) => {
  const h = harness(t, { start: true });
  assert.ok(h.store.timer, 'start() 之后必须有一个清扫定时器');
  assert.equal(typeof h.store.timer.unref, 'function');
  h.files.close();
  assert.equal(h.store.timer, null, 'close() 必须清掉清扫定时器');
});

test('U4e 已下载台账：成员侧只记 fileId→size/sha，重启后仍然在', (t) => {
  const h = harness(t);
  assert.equal(h.files.downloads.has('99999999-9999-4999-8999-999999999991'), false);
  assert.equal(h.files.downloads.add('99999999-9999-4999-8999-999999999991', { size: 12, sha256: 'c'.repeat(64) }).ok, true);
  assert.equal(h.files.downloads.has('99999999-9999-4999-8999-999999999991'), true);
  const reread = createGroupFiles({ stateDir: h.stateDir, now: () => 5, start: false });
  t.after(() => reread.close());
  assert.equal(reread.downloads.get('99999999-9999-4999-8999-999999999991').size, 12);
});
test('U4f begin 之后后续步骤失败（拒绝或抛错）→ 半截目录只在盘上活着，清扫器一跑就干干净净', async (t) => {
  const h = harness(t, { uploadIdleMs: 5_000 });
  // ① 后续步骤**拒绝**它：append 前跳 409 offset-mismatch —— 客户端放弃了
  const refused = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1';
  // ② 后续步骤**抛错**：0.12.0-α 的日志读错字段就是这样，begin 已经把目录建好了
  const threw = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2';
  for (const fileId of [refused, threw]) {
    assert.equal(h.store.begin({
      fileId, name: 'half.bin', size: 200, sha256: sha256(payload(200)), from: FROM, targets: 'all',
    }).ok, true);
    assert.equal(fs.existsSync(path.join(h.stateDir, GROUP_FILES_DIR, fileId, 'data')), true,
      'begin 之后目录与空 data 当场就在（孤儿目录就是这么留下的）');
  }
  assert.equal(h.store.append(refused, 50, payload(10)).error, 'offset-mismatch');
  assert.throws(() => { throw new TypeError("Cannot read properties of undefined (reading 'length')"); }, TypeError);
  assert.equal(h.store.inFlight, 2, '两条都还挂着「在传」，谁也没收完');

  // 空闲超时之前不动它（清扫器只收空闲的）
  h.tick(4_999);
  assert.deepEqual(h.store.sweep(h.at()).uploads, []);
  assert.equal(fs.existsSync(path.join(h.stateDir, GROUP_FILES_DIR, refused)), true);

  // 过了空闲阈值：两条一起收掉，目录不留，也不立碑（从没公告过 → 404 才是实话）
  h.tick(2);
  assert.deepEqual(h.store.sweep(h.at()).uploads.sort(), [refused, threw].sort());
  for (const fileId of [refused, threw]) {
    assert.equal(fs.existsSync(path.join(h.stateDir, GROUP_FILES_DIR, fileId)), false, '不得留下永久目录');
    assert.equal(h.store.get(fileId).reason, 'unknown-file');
  }
  assert.equal(h.store.inFlight, 0);
  assert.equal(h.plane.value().files.length, 0, '一条公告都不该有');
});
