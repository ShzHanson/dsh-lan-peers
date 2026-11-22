// dsh-lan-peers · 0.13.0-α 危险区：身份密钥重置的纯逻辑面（排定 / 备份 / 启动时执行）。
//
// 断言七件事（X5–X8 / Y1 / Y2 / Y4 + 备份布局）：
//   1. arm：备份目录里是**身份material**的那几个文件的逐字节副本（0600），目录 0700，README 说清怎么还原；
//   2. apply：instanceId 换新、peers.json 清空、group-key/group-role 消失、admin-token 换新、标记消失，备份留着旧值；
//   3. apply 不碰数据：group-digests / offers / dm 三个文件逐字节不变（X6）；
//   4. 标记损坏 → 一行 reset ignored 后原样返回，stateDir 一个字节都不动（X7）；
//   5. 第二次 apply 是 no-op（X8）；
//   6. 通知在重生**之前**发出，而且拿到的是旧 instanceId（Y1 的顺序断言）；
//   7. 通知抛错绝不阻断重置：failed 计数 + 一行 reset-notice failed，新身份照常就位（Y2）。
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  IDENTITY_BACKUP_FILES,
  IDENTITY_BACKUP_PREFIX,
  IDENTITY_GROUP_FILES,
  IDENTITY_LAST_RESET_FILE,
  IDENTITY_MARKER_FILE,
  applyPendingIdentityReset,
  armIdentityReset,
  cancelIdentityReset,
  createPeerResetNotifier,
  readIdentityState,
  utcStamp,
} from './identity.mjs';

const OLD_ID = '11111111-2222-3333-4444-555555555555';
const OLD_TOKEN = 'ab'.repeat(32);
const OLD_PEERS = {
  peers: {
    'peer-aaaa1111': {
      name: 'study', baseUrl: 'http://10.0.0.2:7788', secret: 'out-a', inboundSecret: 'in-a', addedAt: 'a', lastSeen: null,
    },
    'peer-bbbb2222': {
      name: 'living', baseUrl: 'http://10.0.0.3:7788', secret: 'out-b', inboundSecret: 'in-b', addedAt: 'b', lastSeen: null,
    },
  },
};
// 数据不是身份：这三个文件必须逐字节活到重置之后。
const DATA_FILES = {
  'group-digests.json': '{"digests":[{"id":"d-1","rev":3}],"rev":3}\n',
  'offers/offer-1.json': '{"offerId":"offer-1","name":"a.bin","size":3}\n',
  'dm/peer-aaaa1111.json': '{"messages":[{"id":"m-1","text":"hi"}]}\n',
};

function write(file, content) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, content, { mode: 0o600 });
}

function makeStateDir(t, { withGroup = true, marker = null } = {}) {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-lp-identity-'));
  t.after(() => fs.rmSync(stateDir, { recursive: true, force: true }));
  write(path.join(stateDir, 'state.json'), JSON.stringify({
    instanceId: OLD_ID, name: 'me', createdAt: '2026-01-01T00:00:00.000Z',
  }, null, 2) + '\n');
  write(path.join(stateDir, 'peers.json'), JSON.stringify(OLD_PEERS, null, 2) + '\n');
  write(path.join(stateDir, 'admin-token'), OLD_TOKEN + '\n');
  if (withGroup) {
    write(path.join(stateDir, 'group-key.json'), '{"groupKey":"k-old","groupId":"g-1"}\n');
    write(path.join(stateDir, 'group-role.json'), '{"role":"member"}\n');
  }
  for (const [name, text] of Object.entries(DATA_FILES)) write(path.join(stateDir, name), text);
  if (marker !== null) write(path.join(stateDir, IDENTITY_MARKER_FILE), marker);
  return stateDir;
}

const readJson = (file) => JSON.parse(fs.readFileSync(file, 'utf8'));
const listBackups = (stateDir) => fs.readdirSync(stateDir).filter((n) => n.startsWith(IDENTITY_BACKUP_PREFIX)).sort();
const snapshot = (stateDir, names) => Object.fromEntries(names.map((n) => [n, fs.readFileSync(path.join(stateDir, n), 'utf8')]));

test('X1 单元面：arm 先备份（0600 副本 + 0700 目录 + README）再落标记，且拒绝第二次排定', (t) => {
  const stateDir = makeStateDir(t);
  const at = Date.UTC(2026, 0, 2, 3, 4, 5);
  const armed = armIdentityReset({ stateDir, now: () => at, reason: 'tests' });
  assert.equal(armed.ok, true);
  assert.equal(armed.backup, IDENTITY_BACKUP_PREFIX + utcStamp(() => at));
  assert.deepEqual(armed.files, IDENTITY_BACKUP_FILES, '五个身份文件都在（当时都存在）');

  const backupDir = path.join(stateDir, armed.backup);
  assert.equal(fs.statSync(backupDir).isDirectory(), true);
  if (process.platform !== 'win32') assert.equal(fs.statSync(backupDir).mode & 0o777, 0o700);
  const readme = fs.readFileSync(path.join(backupDir, 'README.txt'), 'utf8');
  assert.match(readme, /How to restore by hand/);
  assert.match(readme, /identity-reset-pending\.json/, 'README 必须说清还原时要先删标记');
  assert.equal(/out-a|in-a|ab{32}|k-old/.test(readme), false, 'README 不得含密钥');
  for (const name of IDENTITY_BACKUP_FILES) {
    assert.equal(fs.readFileSync(path.join(backupDir, name), 'utf8'),
      fs.readFileSync(path.join(stateDir, name), 'utf8'), name + ' 备份必须是逐字节副本');
    if (process.platform !== 'win32') assert.equal(fs.statSync(path.join(backupDir, name)).mode & 0o777, 0o600);
  }

  const marker = readJson(path.join(stateDir, IDENTITY_MARKER_FILE));
  assert.equal(marker.backup, armed.backup);
  assert.equal(marker.resetAt, new Date(at).toISOString());

  // 已排定 → 不再备份第二次，目录数不变
  const again = armIdentityReset({ stateDir, now: () => at + 1000 });
  assert.deepEqual(again, { ok: false, reason: 'already-pending' });
  assert.equal(listBackups(stateDir).length, 1);
});

test('X5 apply：换 instanceId、清空 peers、删群身份、换 admin-token、删标记，备份仍留旧值', async (t) => {
  const stateDir = makeStateDir(t);
  const armed = armIdentityReset({ stateDir });
  const logs = [];
  const out = await applyPendingIdentityReset({ stateDir, log: (line) => logs.push(line) });
  assert.equal(out.applied, true);
  assert.equal(out.notified, 0, '没有注入 notify 时就是 0 次通知');
  assert.deepEqual(logs, ['[identity] reset applied backup=' + armed.backup + ' peers-cleared=1 group=cleared']);

  const state = readJson(path.join(stateDir, 'state.json'));
  assert.notEqual(state.instanceId, OLD_ID, 'instanceId 必须换新');
  assert.equal(state.name, 'me', '设备名不是身份，保持原样');
  assert.deepEqual(readJson(path.join(stateDir, 'peers.json')), { peers: {} }, '全部配对作废');
  for (const name of IDENTITY_GROUP_FILES) assert.equal(fs.existsSync(path.join(stateDir, name)), false, name + ' 必须消失');
  const token = fs.readFileSync(path.join(stateDir, 'admin-token'), 'utf8').trim();
  assert.match(token, /^[0-9a-f]{64}$/);
  assert.notEqual(token, OLD_TOKEN, 'admin-token 必须换新');
  assert.equal(fs.existsSync(path.join(stateDir, IDENTITY_MARKER_FILE)), false, '标记必须消失');

  const backupDir = path.join(stateDir, armed.backup);
  assert.equal(fs.statSync(backupDir).isDirectory(), true, '备份必须留着');
  assert.equal(readJson(path.join(backupDir, 'state.json')).instanceId, OLD_ID);
  assert.deepEqual(readJson(path.join(backupDir, 'peers.json')), OLD_PEERS);
  assert.equal(fs.readFileSync(path.join(backupDir, 'admin-token'), 'utf8').trim(), OLD_TOKEN);
});

test('X6 apply 不碰数据：摘要 / offers / dm 三个文件逐字节不变', async (t) => {
  const stateDir = makeStateDir(t);
  armIdentityReset({ stateDir });
  const before = snapshot(stateDir, Object.keys(DATA_FILES));
  await applyPendingIdentityReset({ stateDir });
  const after = snapshot(stateDir, Object.keys(DATA_FILES));
  assert.deepEqual(after, before, '数据不是身份：一个字节都不许动');
});

test('X7 标记损坏 → 不抛错、只记 reset ignored、stateDir 原样', async (t) => {
  const stateDir = makeStateDir(t, { marker: '{"resetAt": "2026-' });
  const before = snapshot(stateDir, ['state.json', 'peers.json', 'admin-token', 'group-key.json', 'group-role.json']);
  const logs = [];
  const out = await applyPendingIdentityReset({ stateDir, log: (line) => logs.push(line) });
  assert.equal(out.applied, false);
  assert.equal(out.reason, 'malformed');
  assert.deepEqual(logs, ['[identity] reset ignored reason=malformed']);
  assert.deepEqual(snapshot(stateDir, Object.keys(before)), before, '损坏的标记不能改动任何东西');
  assert.equal(fs.existsSync(path.join(stateDir, IDENTITY_MARKER_FILE)), true, '也不替人删掉它');
  assert.deepEqual(listBackups(stateDir), [], '更不能凭空造备份');
});

test('X7b 备份目录不见了 → 拒绝重置（没有还原点就不动身份）', async (t) => {
  const stateDir = makeStateDir(t, { marker: JSON.stringify({ resetAt: '2026-01-01T00:00:00Z', backup: 'identity-backup-20260101T000000Z' }) });
  const logs = [];
  const out = await applyPendingIdentityReset({ stateDir, log: (line) => logs.push(line) });
  assert.deepEqual(out, { applied: false, reason: 'no-backup' });
  assert.deepEqual(logs, ['[identity] reset ignored reason=no-backup']);
  assert.equal(readJson(path.join(stateDir, 'state.json')).instanceId, OLD_ID);
});

test('X8 幂等：对着同一个 stateDir 连 apply 两次，第二次是 no-op', async (t) => {
  const stateDir = makeStateDir(t);
  armIdentityReset({ stateDir });
  const first = await applyPendingIdentityReset({ stateDir });
  assert.equal(first.applied, true);
  const afterFirst = readJson(path.join(stateDir, 'state.json')).instanceId;
  const second = await applyPendingIdentityReset({ stateDir });
  assert.deepEqual(second, { applied: false, reason: 'no-marker' });
  assert.equal(readJson(path.join(stateDir, 'state.json')).instanceId, afterFirst, '第二次不许再换一次身份');
  assert.equal(listBackups(stateDir).length, 1);
});

test('X4b cancel：删标记；再 cancel 是 no-op（不抛错、不改别的）', (t) => {
  const stateDir = makeStateDir(t);
  armIdentityReset({ stateDir });
  assert.deepEqual(cancelIdentityReset({ stateDir }), { ok: true, removed: true });
  assert.equal(fs.existsSync(path.join(stateDir, IDENTITY_MARKER_FILE)), false);
  assert.deepEqual(cancelIdentityReset({ stateDir }), { ok: true, removed: false });
  assert.equal(listBackups(stateDir).length, 1, '撤排定不动备份');
});

test('Y1 通知先发、再生效：notifier 看到的是旧 instanceId，且每个 peer 一次；随后才换身份', async (t) => {
  const stateDir = makeStateDir(t);
  armIdentityReset({ stateDir });
  const seen = [];
  const out = await applyPendingIdentityReset({
    stateDir,
    notify: async (peer, notice) => {
      // 这一行是顺序断言：如果通知发生在重生之后，这里读到的会是新 id（或 peers.json 已空）。
      const live = readJson(path.join(stateDir, 'state.json')).instanceId;
      seen.push({ peer: peer.peerId, secret: peer.secret, baseUrl: peer.baseUrl, senderId: notice.senderId, live });
    },
  });
  assert.deepEqual(seen.map((one) => one.peer), ['peer-aaaa1111', 'peer-bbbb2222']);
  assert.deepEqual(seen.map((one) => one.secret), ['out-a', 'out-b'], '用的是旧配对里的出站密钥');
  for (const one of seen) {
    assert.equal(one.senderId, OLD_ID, '通知必须由旧身份签发');
    assert.equal(one.live, OLD_ID, '通知那一刻盘上还是旧身份');
  }
  assert.deepEqual({ notified: out.notified, failed: out.failed }, { notified: 2, failed: 0 });
  assert.notEqual(readJson(path.join(stateDir, 'state.json')).instanceId, OLD_ID, '通知之后才重生');
});

test('Y2 通知抛错不阻断：failed 计数 + 一行 reset-notice failed，新身份照常就位', async (t) => {
  const stateDir = makeStateDir(t);
  armIdentityReset({ stateDir });
  const logs = [];
  const out = await applyPendingIdentityReset({
    stateDir,
    log: (line) => logs.push(line),
    notify: async (peer) => {
      if (peer.peerId === 'peer-bbbb2222') throw new Error('offline');
    },
  });
  assert.equal(out.applied, true);
  assert.equal(out.notified, 1);
  assert.equal(out.failed, 1);
  assert.deepEqual(logs.slice().sort(), [
    '[identity] reset applied backup=' + out.backup + ' peers-cleared=1 group=cleared',
    '[identity] reset-notice failed peer=peer-bbb',
  ].sort());
  const state = readJson(path.join(stateDir, 'state.json'));
  assert.notEqual(state.instanceId, OLD_ID);
  assert.deepEqual(readJson(path.join(stateDir, 'peers.json')), { peers: {} });
  assert.equal(fs.existsSync(path.join(stateDir, IDENTITY_MARKER_FILE)), false);
});

test('Y4 lastResetNotified 落盘并经只读视图读回（GET identity 的数据源）', async (t) => {
  const stateDir = makeStateDir(t);
  assert.equal(readIdentityState({ stateDir }).lastResetNotified, null, '还没重置过就是 null');
  armIdentityReset({ stateDir });
  await applyPendingIdentityReset({
    stateDir,
    notify: async (peer) => { if (peer.peerId === 'peer-aaaa1111') throw new Error('nope'); },
  });
  const recorded = readJson(path.join(stateDir, IDENTITY_LAST_RESET_FILE));
  assert.deepEqual({ notified: recorded.notified, failed: recorded.failed }, { notified: 1, failed: 1 });
  const view = readIdentityState({ stateDir });
  assert.deepEqual(view.lastResetNotified, { notified: 1, failed: 1 });
  assert.equal(view.resetPending, false);
  assert.equal(view.peerCount, 0, '重置后没有任何配对');
  assert.equal(view.hasGroup, false, '群身份文件已删');
  assert.equal(view.lastBackup, recorded.backup);
});

test('Y1b createPeerResetNotifier：复用既有签名通道，reason 夹到 32 字，超时 5s', async () => {
  const calls = [];
  const notify = createPeerResetNotifier({
    callPeer: async (options) => { calls.push(options); return { ok: true }; },
  });
  await notify({ peerId: 'p-1', baseUrl: 'http://10.0.0.9:7788', secret: 's-1' }, {
    resetAt: '2026-01-02T03:04:05.000Z', reason: 'x'.repeat(60), senderId: OLD_ID,
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].apiPath, '/v1/peer/reset-notice');
  assert.equal(calls[0].method, 'POST');
  assert.equal(calls[0].senderId, OLD_ID);
  assert.equal(calls[0].baseUrl, 'http://10.0.0.9:7788');
  assert.equal(calls[0].secret, 's-1');
  assert.equal(calls[0].timeoutMs, 5000);
  assert.equal(calls[0].body.reason.length, 32);
  assert.equal(calls[0].body.resetAt, '2026-01-02T03:04:05.000Z');
  assert.throws(() => createPeerResetNotifier({}), /callPeer/);
});
