/**
 * v0.8.0-β §18 · 消息体积上限 + 归档（替代直接删除）。
 *
 * 覆盖：① 21 MB 真文件启动即归档（活跃区回到 20 MB 以下、文件 0600、索引正确、
 *      seq 不回退不复用、history 对已归档区间回 archived 标记）；
 *      ② retentionDays=0 + 假时钟 → 旧消息进归档而不是消失；
 *      ③ 索引自愈 + deleteArchive 删文件并同步索引；
 *      ④ 索引超过 200 条只告警不自动删；日志不含正文与密钥。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { makeTempStateDir, peerFixture, request, seedPeers, startServer, writeJson0600 } from './helpers.mjs';
import { GROUP_ARCHIVE_BYTES_LIMIT, GROUP_ARCHIVE_INDEX_LIMIT, GroupStore } from '../server.mjs';

const MEMBER = peerFixture('peer-archive-1');
const BIG_TEXT = 'x'.repeat(4000);

/** 造一份「历史遗留的超大 group.json」：5250 条 × 4000 字符 ≈ 21 MB */
function seedOversizedGroup(stateDir, { count = 5250, ts = Date.now() } = {}) {
  const messages = Array.from({ length: count }, (_, index) => ({
    seq: index + 1,
    ts,
    from: { peerId: MEMBER.peerId, name: MEMBER.name },
    kind: 'chat',
    text: BIG_TEXT,
    meta: {},
  }));
  writeJson0600(path.join(stateDir, 'group.json'), {
    groupId: 'group-archive-fixture',
    name: 'default',
    createdAt: new Date(ts).toISOString(),
    key: randomBytes(32).toString('base64url'),
    keyVersion: 1,
    lastSeq: count,
    members: {
      [MEMBER.peerId]: { name: MEMBER.name, addedAt: new Date(ts).toISOString() },
    },
    messages,
    pending: [],
  });
  return messages;
}

const asMember = (baseUrl, options = {}) => request(baseUrl, {
  peerId: MEMBER.peerId,
  secret: MEMBER.inboundSecret,
  ...options,
});

const archiveDirOf = (stateDir) => path.join(stateDir, 'group-archive');

test('§18 21 MB 活跃区：启动即归档，活跃区 <20MB、文件 0600、索引正确、history 回 archived', async (t) => {
  const stateDir = makeTempStateDir('dsh-lan-peers-archive-');
  seedPeers(stateDir, [MEMBER]);
  seedOversizedGroup(stateDir);
  const { server, baseUrl } = await startServer(t, {
    stateDir,
    allowRemotePrompts: true,
    group: { enabled: true, name: 'default', autoJoin: false, retentionDays: 7, quorum: 'none' },
  });

  const manifests = server.group.archives();
  assert.ok(manifests.length >= 1, '超过 20 MB 必须产出至少一个归档块');
  const first = manifests[0];
  assert.equal(first.fromSeq, 1, '归档块从最旧的那条开始');
  assert.ok(first.toSeq >= first.fromSeq);
  assert.equal(first.file, first.fromSeq + '-' + first.toSeq + '.json', 'file 字段是纯文件名（便于管理接口透传）');
  assert.ok(first.bytes > 0);
  assert.equal(first.count, first.toSeq - first.fromSeq + 1);

  const file = path.join(archiveDirOf(stateDir), first.file);
  assert.ok(fs.existsSync(file), '归档文件必须落盘: ' + file);
  // Windows 不支持 Unix 权限位（与既有 group.json/peers.json 断言同一套跳法）
  if (process.platform !== 'win32') assert.equal(fs.statSync(file).mode & 0o777, 0o600, '归档文件必须是 0600');
  const archived = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.equal(archived.groupId, 'group-archive-fixture');
  assert.equal(archived.fromSeq, first.fromSeq);
  assert.equal(archived.toSeq, first.toSeq);
  assert.equal(archived.count, first.count);
  assert.equal(archived.messages.length, first.count);
  assert.equal(archived.messages[0].seq, first.fromSeq, '归档块内的消息按 seq 原样保存');
  assert.ok(typeof archived.createdAt === 'string' && archived.createdAt !== '');

  // 活跃区回到上限以下
  const onDisk = JSON.parse(fs.readFileSync(path.join(stateDir, 'group.json'), 'utf8'));
  const activeBytes = Buffer.byteLength(JSON.stringify(onDisk.messages), 'utf8');
  assert.ok(activeBytes <= GROUP_ARCHIVE_BYTES_LIMIT, '活跃区体积必须回到 20 MB 以下，实际 ' + activeBytes);
  assert.ok(onDisk.messages.length > 0, '活跃区不该被搬空');
  assert.equal(onDisk.lastSeq, 5250, '归档不推进也不回退 lastSeq');
  assert.deepEqual(onDisk.archives, manifests, 'group.json 的 archives 索引与门面一致');

  // history 落在已归档区间 → 明确回 archived，而不是静默空结果
  const archivedPage = await asMember(baseUrl, { path: '/v1/group/history?sinceSeq=0' });
  assert.equal(archivedPage.status, 200, archivedPage.text);
  assert.equal(archivedPage.json.archived, true);
  assert.equal(archivedPage.json.archiveFrom, first.fromSeq);
  assert.equal(archivedPage.json.archiveTo, first.toSeq);
  assert.deepEqual(archivedPage.json.messages, []);

  // 游标落在归档区之后：正常返回活跃区（不再带 archived 标记）
  const activePage = await asMember(baseUrl, {
    path: '/v1/group/history?sinceSeq=' + first.toSeq + '&limit=5',
  });
  assert.equal(activePage.status, 200);
  assert.equal(activePage.json.archived, undefined, '游标在归档区之后就不该再回 archived');
  assert.equal(activePage.json.messages.length, 5);
  // 契约 §3：limit 截断时保留**最新**的那批
  assert.equal(activePage.json.messages.at(-1).seq, 5250);
  assert.ok(activePage.json.messages.every((message) => message.seq > first.toSeq));

  // seq 不回退也不复用已归档的号
  const posted = await asMember(baseUrl, {
    method: 'POST',
    path: '/v1/group/post',
    body: { kind: 'chat', text: 'after-archive' },
  });
  assert.equal(posted.status, 201, posted.text);
  assert.equal(posted.json.seq, 5251, '新消息接着 lastSeq+1，绝不复用已归档的号');
});

test('§18 retentionDays=0 + 假时钟：过期消息进归档而不是消失', (t) => {
  const stateDir = makeTempStateDir();
  t.after(() => fs.rmSync(stateDir, { recursive: true, force: true }));
  let nowMs = 1_760_000_000_000;
  const clock = () => nowMs;
  const store = new GroupStore({ stateDir, name: 'g', retentionDays: 0, now: clock });

  assert.equal(store.append({ peerId: 'p1', name: 'P1', kind: 'chat', text: 'keep-1' }).seq, 1);
  assert.equal(store.append({ peerId: 'p1', name: 'P1', kind: 'chat', text: 'keep-2' }).seq, 2);
  nowMs += 1_000;

  // 读的时候也 prune：活跃区空，但两条都在归档里
  assert.equal(store.messages({ sinceSeq: 0 }).length, 0);
  const manifests = store.archives();
  assert.equal(manifests.length, 1, '到期消息整体切成一个归档块');
  assert.equal(manifests[0].fromSeq, 1);
  assert.equal(manifests[0].toSeq, 2);
  assert.equal(manifests[0].count, 2);

  const file = JSON.parse(fs.readFileSync(path.join(store.archiveDir, manifests[0].file), 'utf8'));
  assert.deepEqual(file.messages.map((message) => message.seq), [1, 2]);
  assert.equal(file.messages[0].text, 'keep-1', '归档保存完整正文（不删除、不改写）');
  assert.equal(store.state().lastSeq, 2, '归档不回退 lastSeq');
  assert.equal(store.append({ peerId: 'p1', name: 'P1', kind: 'chat', text: 'c' }).seq, 3, '绝不复用 1/2');
  assert.deepEqual(
    store.archivedRangeFor(0),
    { file: manifests[0].file, fromSeq: 1, toSeq: 2 },
    'history 游标 0 → 下一条落在归档区间',
  );
  assert.equal(store.archivedRangeFor(2), null, '游标已经在归档区之后');
});

test('§18 写入路径按体积归档 + deleteArchive 删文件并同步索引 + 索引自愈', (t) => {
  const stateDir = makeTempStateDir();
  t.after(() => fs.rmSync(stateDir, { recursive: true, force: true }));
  const lines = [];
  const store = new GroupStore({
    stateDir,
    name: 'g',
    retentionDays: 7,
    // 把 20 MB 压到 4 KB：写入路径的体积触发与真机同一段代码
    archiveBytes: 4096,
    logger: (line) => lines.push(String(line)),
  });

  for (let index = 1; index <= 40; index += 1) {
    store.append({ peerId: 'p1', name: 'P1', kind: 'chat', text: 'marker-body-' + 'y'.repeat(400) + '-' + index });
  }
  const manifests = store.archives();
  assert.ok(manifests.length >= 1, '写入路径也要触发归档');
  const activeBytes = Buffer.byteLength(JSON.stringify(JSON.parse(
    fs.readFileSync(store.groupPath, 'utf8'),
  ).messages), 'utf8');
  assert.ok(activeBytes <= 4096, '活跃区压回上限以内，实际 ' + activeBytes);
  assert.equal(store.state().lastSeq, 40);

  // 日志：有归档摘要行，但不含正文
  const wrote = lines.filter((line) => line.startsWith('[group] archive wrote file='));
  assert.ok(wrote.length >= 1);
  assert.match(wrote[0], /file=\d+-\d+\.json from=\d+ to=\d+ count=\d+ bytes=\d+/);
  for (const line of lines) {
    assert.ok(!line.includes('marker-body-'), '日志里不许出现正文: ' + line);
    assert.ok(!line.includes(store.state({ includeKey: true }).groupKey), '日志里不许出现群密钥: ' + line);
  }

  // 人工删除：文件消失、索引同步、removedBytes 有值
  const target = manifests[0];
  const removed = store.deleteArchive(target.file);
  assert.equal(removed.ok, true);
  assert.equal(removed.removedBytes, target.bytes);
  assert.equal(removed.removedFromIndex, true);
  assert.equal(fs.existsSync(path.join(store.archiveDir, target.file)), false);
  assert.equal(store.archives().some((entry) => entry.file === target.file), false, '索引必须同步移除');

  // 未知 / 非法文件名
  assert.deepEqual(store.deleteArchive(target.file), { ok: false, reason: 'unknown-archive' });
  assert.deepEqual(store.deleteArchive('../group.json'), { ok: false, reason: 'bad-file' });

  // 索引自愈：文件被外部删掉后，archives() 不再列出死条目
  const survivor = store.archives()[0];
  assert.ok(survivor, '还剩至少一个归档块');
  fs.unlinkSync(path.join(store.archiveDir, survivor.file));
  assert.equal(store.archives().some((entry) => entry.file === survivor.file), false, '死条目要自愈');
  const onDisk = JSON.parse(fs.readFileSync(store.groupPath, 'utf8'));
  assert.equal(onDisk.archives.some((entry) => entry.file === survivor.file), false);
});

test('§18 归档索引上限 200：超出只告警，绝不自动删文件', (t) => {
  const stateDir = makeTempStateDir();
  t.after(() => fs.rmSync(stateDir, { recursive: true, force: true }));
  const lines = [];
  const store = new GroupStore({
    stateDir,
    name: 'g',
    retentionDays: 7,
    // 上限 1 字节 → 每写入一条就把前面所有消息搬进一个新归档块，索引很快过 200
    archiveBytes: 1,
    logger: (line) => lines.push(String(line)),
  });
  const total = GROUP_ARCHIVE_INDEX_LIMIT + 5;
  for (let index = 1; index <= total; index += 1) {
    store.append({ peerId: 'p1', name: 'P1', kind: 'chat', text: 'm' + index });
  }
  const manifests = store.archives();
  assert.ok(manifests.length > GROUP_ARCHIVE_INDEX_LIMIT, '索引允许超过上限（' + manifests.length + '）');
  const files = fs.readdirSync(store.archiveDir);
  assert.ok(files.length >= manifests.length, '文件一个都不许被自动删');
  assert.ok(
    lines.some((line) => line.startsWith('[group] archive index full n=')),
    '超过 200 条要留一行告警',
  );
  assert.equal(store.state().lastSeq, total, 'seq 一路递增，不回退');
});
