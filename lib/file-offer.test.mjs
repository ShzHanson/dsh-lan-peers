// dsh-lan-peers · 0.12.0-alpha（S1）文件面存储层：outbox 配额/TTL/LRU、offer 条目、信任标记。
//
// 这一层全是纯文件操作（没有 HTTP），所以三条用例直接驱动假时钟：
//   T1 put → open 各处偏移 → 字节逐字相同；最后一块 eof=true
//   T2 超配额 → 按 lastPullAt 的 LRU 逐出，最近被拉过的留下，逐出即删目录
//   T3 过期的被扫掉，刚拉的/刚放下的不动
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

import { FileOffers, FileOutbox, FileTrust, parseFileId, sanitizeOfferName } from './file-offer.mjs';
import { makeTempStateDir } from '../host/test/helpers.mjs';

function payload(length, seed = 7) {
  const buffer = Buffer.alloc(length);
  for (let index = 0; index < length; index += 1) buffer[index] = (index * 31 + seed) & 0xff;
  return buffer;
}

function tmpDir(t) {
  const dir = makeTempStateDir('dsh-lan-peers-offer-');
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

/** 假时钟：now() 读它，用例自己往前拨 */
function clock(start = 1_000_000) {
  let at = start;
  return { now: () => at, set: (value) => { at = value; }, advance: (delta) => { at += delta; } };
}

async function putFile(outbox, dir, { name, bytes, to = 'peer-b', id }) {
  const source = path.join(dir, 'src-' + name);
  fs.writeFileSync(source, bytes);
  const out = await outbox.put({ fileId: id, name, sourcePath: source, to });
  assert.equal(out.ok, true, JSON.stringify(out));
  return out;
}

// ---------------------------------------------------------------------------
// T1
// ---------------------------------------------------------------------------

test('T1 outbox: put → open 任意偏移，字节逐字相同；最后一块 eof=true', async (t) => {
  const dir = tmpDir(t);
  const sourceBytes = payload(1000);
  const outbox = new FileOutbox({ stateDir: dir, now: () => 1_000_000 });
  const put = await putFile(outbox, dir, { name: '报告.pdf', bytes: sourceBytes });

  const fileId = put.fileId;
  assert.match(fileId, /^[0-9a-f-]{36}$/);
  assert.equal(put.size, 1000);
  assert.deepEqual(fs.readFileSync(path.join(dir, 'outbox', fileId, 'data')), sourceBytes,
    'keeper 拷贝就在 <stateDir>/outbox/<fileId>/data');
  assert.ok(fs.existsSync(path.join(dir, 'outbox', fileId, 'meta.json')));

  const first = outbox.open(fileId, 0, 400);
  assert.equal(first.error, undefined);
  assert.equal(first.offset, 0);
  assert.equal(first.size, 1000);
  assert.equal(first.eof, false, '1000 字节一次只取 400，还没到头');
  assert.deepEqual(first.data, sourceBytes.subarray(0, 400));

  const middle = outbox.open(fileId, 400, 400);
  assert.equal(middle.eof, false);
  assert.deepEqual(middle.data, sourceBytes.subarray(400, 800), '偏移是绝对的，不是「第几块」');

  const last = outbox.open(fileId, 800, 400);
  assert.equal(last.eof, true, '最后一块（只剩 200 字节）必须 eof');
  assert.deepEqual(last.data, sourceBytes.subarray(800, 1000));

  const past = outbox.open(fileId, 1000, 400);
  assert.deepEqual(past.data, Buffer.alloc(0));
  assert.equal(past.eof, true, '正好在末尾 = 空块 + eof，不报错');

  // 超范围 / 非整数偏移都是 bad-offset（不读盘、不越界）
  assert.equal(outbox.open(fileId, 1001, 10).error, 'bad-offset');
  assert.equal(outbox.open(fileId, -1, 10).error, 'bad-offset');
  assert.equal(outbox.open(fileId, 1.5, 10).error, 'bad-offset');

  // 单响应硬上限：要 10 MiB 也只给 FILE_CHUNK_HARD_MAX
  const capped = outbox.open(fileId, 0, 10 * 1024 * 1024);
  assert.ok(capped.data.length <= 512 * 1024);
});

// ---------------------------------------------------------------------------
// T2
// ---------------------------------------------------------------------------

test('T2 配额：按 lastPullAt 的 LRU 逐出，最近拉过的那条留下，逐出即删目录', async (t) => {
  const dir = tmpDir(t);
  const time = clock(1_000);
  // 三份 120B 的刚好塞满 360B 配额，第四份才触发逐出
  const outbox = new FileOutbox({ stateDir: dir, now: time.now, quotaBytes: 360 });
  assert.equal(outbox.total, 360);

  const a = await putFile(outbox, dir, { name: 'a.bin', bytes: payload(120, 1) });
  time.advance(1000);
  const b = await putFile(outbox, dir, { name: 'b.bin', bytes: payload(120, 2) });
  time.advance(1000);
  const c = await putFile(outbox, dir, { name: 'c.bin', bytes: payload(120, 3) });
  assert.equal(outbox.count, 3, '360B 正好等于配额：一个都不该走');
  assert.equal(outbox.used, 360);

  // b 在 5 秒后被真拉过一次 → 它的 lastPullAt 变成最新的
  time.advance(5000);
  const pulled = outbox.open(b.fileId, 0, 120);
  assert.deepEqual(pulled.data, payload(120, 2));

  time.advance(1000);
  const d = await putFile(outbox, dir, { name: 'd.bin', bytes: payload(100, 4) });

  assert.equal(outbox.count, 3, '超配额后必须少一条');
  assert.equal(outbox.get(a.fileId).ok, false, '最久没被拉的 a 被逐出');
  assert.equal(outbox.get(a.fileId).reason, 'file-gone', '逐出过 = file-gone（不是 unknown-file）');
  assert.equal(fs.existsSync(path.join(dir, 'outbox', a.fileId)), false, '逐出删掉整个目录');
  assert.equal(outbox.get(b.fileId).ok, true, '刚被拉过的 b 必须活着');
  assert.deepEqual(outbox.open(b.fileId, 0, 120).data, payload(120, 2), '活着就还能逐字拉出来');
  assert.equal(outbox.get(c.fileId).ok, true);
  assert.equal(outbox.get(d.fileId).ok, true, '刚放下的 d 也在');
  assert.ok(outbox.used <= outbox.total);

  // 墓碑要落盘：重启后同一个 id 仍然报 file-gone（不是「没见过」）
  const reopened = new FileOutbox({ stateDir: dir, now: time.now, quotaBytes: 360 });
  assert.equal(reopened.get(a.fileId).reason, 'file-gone');
  assert.equal(reopened.count, 3, '重启后按目录重建，条目一条不少');
});

// ---------------------------------------------------------------------------
// T3
// ---------------------------------------------------------------------------

test('T3 TTL：过期的被扫掉，刚放下/刚拉过的都不动（假时钟）', async (t) => {
  const dir = tmpDir(t);
  const time = clock(10_000);
  const outbox = new FileOutbox({ stateDir: dir, now: time.now, ttlMs: 1000 });

  const old = await putFile(outbox, dir, { name: 'old.bin', bytes: payload(10) });
  time.advance(600);
  const pulled = await putFile(outbox, dir, { name: 'pulled.bin', bytes: payload(10, 2) });
  time.advance(300);   // t = 10900
  outbox.open(pulled.fileId, 0, 10);   // 拉过一次 → lastPullAt = 10900

  // t = 11000：old 的 idle = 1000 → 到期；pulled 的 idle 只有 100
  time.advance(100);
  const swept = outbox.sweep();
  assert.deepEqual(swept.evicted, [old.fileId], '只有过期的 old 该走');
  assert.equal(fs.existsSync(path.join(dir, 'outbox', old.fileId)), false, '过期条目删目录');
  assert.equal(outbox.get(pulled.fileId).ok, true, '刚拉过的那条不动');

  // 再放一条新的：它当然也不该被扫掉
  time.advance(50);
  const fresh = await putFile(outbox, dir, { name: 'fresh.bin', bytes: payload(10, 3) });
  assert.equal(outbox.sweep().removed, 0);
  assert.equal(outbox.get(fresh.fileId).ok, true);
  assert.equal(outbox.get(pulled.fileId).ok, true);
});

// ---------------------------------------------------------------------------
// 其余存储口径（名字清洗 / offer 条目 / 信任）
// ---------------------------------------------------------------------------

test('offer 名字与收件箱同一份清洗：路径成分、保留设备名、控制符都被处理', () => {
  assert.equal(sanitizeOfferName('../../etc/passwd'), 'passwd', '目录成分被丢掉');
  assert.equal(sanitizeOfferName('C:\\tmp\\x.exe'), 'x.exe');
  assert.equal(sanitizeOfferName('CON'), '', '保留设备名直接拒收');
  assert.equal(sanitizeOfferName(''), '');
  assert.equal(parseFileId('../../etc/passwd'), '', '非 uuid 一律不拼路径');
  assert.equal(parseFileId('11111111-2222-4333-8444-555555555555'), '11111111-2222-4333-8444-555555555555');
});

test('FileOffers：只有 metadata，没有 data 文件；同 id 重发幂等；remove 删目录', async (t) => {
  const dir = tmpDir(t);
  const offers = new FileOffers({ stateDir: dir, now: () => 5000 });
  const fileId = '11111111-2222-4333-8444-555555555555';
  const sha = 'a'.repeat(64);
  const added = offers.add({
    fileId, name: '报告.pdf', size: 4096, sha256: sha, from: { peerId: 'peer-b', name: '书房' },
  });
  assert.equal(added.ok, true);
  assert.deepEqual(fs.readdirSync(path.join(dir, 'offers', fileId)).sort(), ['meta.json'],
    '待下载条目只有 meta.json —— 一个字节都不落');
  assert.equal(offers.list().length, 1);
  assert.deepEqual(offers.get(fileId).from, { peerId: 'peer-b', name: '书房' });

  offers.add({ fileId, name: '报告.pdf', size: 4096, sha256: sha, from: { peerId: 'peer-b', name: '书房' } });
  assert.equal(offers.list().length, 1, '同一个 fileId 重发不产生第二条');
  assert.equal(offers.get(fileId).at, 5000);

  assert.equal(offers.remove(fileId), true);
  assert.equal(offers.list().length, 0);
  assert.equal(fs.existsSync(path.join(dir, 'offers', fileId)), false);
  assert.equal(offers.add({ fileId: 'nope', name: 'x', size: 1, sha256: sha }).reason, 'bad-request');
  assert.equal(offers.add({ fileId, name: 'CON', size: 1, sha256: sha }).reason, 'bad-name');
});

test('FileTrust：缺省不信任；set 后落盘 0600；坏 JSON = 谁都不信任且不抛', (t) => {
  const dir = tmpDir(t);
  const trust = new FileTrust({ stateDir: dir, now: () => 1234 });
  assert.equal(trust.isTrusted('peer-b'), false, '默认不信任');
  assert.equal(trust.isTrusted(''), false);

  const set = trust.set('peer-b', true);
  assert.equal(set.ok, true);
  assert.equal(trust.isTrusted('peer-b'), true);
  const raw = JSON.parse(fs.readFileSync(path.join(dir, 'file-trust.json'), 'utf8'));
  assert.equal(raw.version, 1);
  assert.deepEqual(raw.peers['peer-b'], { trusted: true, updatedAt: 1234 });

  const reloaded = new FileTrust({ stateDir: dir });
  assert.equal(reloaded.isTrusted('peer-b'), true, '重启后仍然信任');

  assert.equal(trust.set('peer-b', false).ok, true);
  assert.equal(trust.isTrusted('peer-b'), false, '取消信任 = 删条目');
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(dir, 'file-trust.json'), 'utf8')).peers, {});

  fs.writeFileSync(path.join(dir, 'file-trust.json'), '{ this is not json');
  const broken = new FileTrust({ stateDir: dir });
  assert.equal(broken.isTrusted('peer-b'), false, '坏文件一律不信任');
  assert.deepEqual(broken.list(), []);
});
