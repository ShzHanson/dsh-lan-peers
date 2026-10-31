/**
 * v0.8.2-α §1–§4 群内派单（作者侧执行面）。
 *
 * 覆盖：成功链路（progress+result 两条、正文不入群）、not-accepting、busy、offline、
 * unpaired、empty、多条 @! 只取第一个、普通 @ 零动作、接单开关的传播与热生效、
 * 冻结门面的形状（dispatch / setAcceptDispatch / dispatchState）、lan_group_ask 工具。
 *
 * 全部真进程：真监听、真签名、真加密、真 1:1 ask（MemoryRunner 1s 完成）。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createLanPeerTools } from '../../lib/tools.mjs';
import {
  GROUP_DEFAULT_DISPATCH_RATE_MS,
  acceptDispatchOf,
  normalizeGroupConfig,
  parseGroupDispatch,
} from '../../lib/group-client.mjs';
// host 侧还有一份 normalizeGroupConfig（老代码就一直有两份）：两个旋钮必须同步归一化，
// 否则「配置 dispatchRateMs: 0」在 host 里会被悄悄丢掉（本文件第一条用例专门盯这个）。
import { normalizeGroupConfig as hostGroupConfig } from '../server.mjs';
import { startCluster, waitFor } from './group-cluster.mjs';
import { makeTempStateDir, startServer, writeJson0600 } from './helpers.mjs';

const MARKER = 'SECRET-MARKER-9f3a';

const historyOf = (node) => node.server.group.history({ sinceSeq: 0 });
const kindsOf = (node, kind) => historyOf(node).filter((message) => message.kind === kind);

/** 只保留某些伙伴的 peers.json（模拟「没和这台配对」的现场形状） */
function keepOnlyPeers(dir, keepPeerIds) {
  const file = path.join(dir, 'peers.json');
  const store = JSON.parse(fs.readFileSync(file, 'utf8'));
  const peers = {};
  for (const [peerId, peer] of Object.entries(store.peers ?? {})) {
    if (keepPeerIds.includes(peerId)) peers[peerId] = peer;
  }
  writeJson0600(file, { peers });
  return peers;
}

// ---------------------------------------------------------------------------
// 纯函数：解析与配置默认值
// ---------------------------------------------------------------------------

test('v0.8.2-α 派单配置默认值：acceptDispatch=true、dispatchRateMs=60000（可被 config 覆盖）', () => {
  const defaults = normalizeGroupConfig({});
  assert.equal(defaults.acceptDispatch, true);
  assert.equal(defaults.dispatchRateMs, GROUP_DEFAULT_DISPATCH_RATE_MS);
  assert.equal(GROUP_DEFAULT_DISPATCH_RATE_MS, 60_000);
  const custom = normalizeGroupConfig({ acceptDispatch: false, dispatchRateMs: 5_000 });
  assert.equal(custom.acceptDispatch, false);
  assert.equal(custom.dispatchRateMs, 5_000);
  // 老对端缺字段 ⇒ 接单
  assert.equal(acceptDispatchOf({ name: 'old-peer' }), true);
  assert.equal(acceptDispatchOf({ acceptDispatch: false }), false);

  // host 侧那份归一化必须与 lib 一致（两份实现是既有事实，这里只钉住新增字段）
  const hostDefaults = hostGroupConfig({});
  assert.equal(hostDefaults.acceptDispatch, defaults.acceptDispatch);
  assert.equal(hostDefaults.dispatchRateMs, defaults.dispatchRateMs);
  assert.equal(hostGroupConfig({ dispatchRateMs: 0 }).dispatchRateMs, 0);
});

test('v0.8.2-α §1 解析：@! 四种写法、只取第一个、普通 @ 零动作', () => {
  const candidates = [
    { peerId: 'aaaaaaaa-1111-2222-3333-444444444444', name: 'desk-alpha' },
    { peerId: 'bbbbbbbb-1111-2222-3333-444444444444', name: 'desk-beta' },
  ];
  const byId = parseGroupDispatch('修个 bug @!aaaaaaaa-1111-2222-3333-444444444444 冒烟', candidates);
  assert.equal(byId.matched, true);
  assert.equal(byId.peerId, 'aaaaaaaa-1111-2222-3333-444444444444');
  // 契约 §1 只要求「去掉该片段后 trim」（首尾），片段两侧留下的空格不算错误
  assert.equal(byId.task, '修个 bug  冒烟', '去掉 @!X 后 trim');
  assert.equal(byId.multiTarget, false);

  const byName = parseGroupDispatch('@!desk-alpha 跑一下', candidates);
  assert.equal(byName.peerId, candidates[0].peerId);
  assert.equal(byName.task, '跑一下');

  const byShort = parseGroupDispatch('@!bbbbbbbb 跑一下', candidates);
  assert.equal(byShort.peerId, candidates[1].peerId);

  const byDisplay = parseGroupDispatch('@!desk-beta (bbbbbbbb) 跑一下', candidates);
  assert.equal(byDisplay.peerId, candidates[1].peerId);
  assert.equal(byDisplay.task, '跑一下', '名字 (短id) 整段都要切掉');

  // 前缀不能误命中更长的名字
  const prefixed = parseGroupDispatch('@!desk 跑一下', candidates);
  assert.equal(prefixed.peerId, '');

  // 多个 @!：只取第一个，并标记 multi-target-ignored（不整条拒绝）
  const multi = parseGroupDispatch('@!desk-alpha @!desk-beta 都跑', candidates);
  assert.equal(multi.peerId, candidates[0].peerId);
  assert.equal(multi.count, 2);
  assert.equal(multi.multiTarget, true);
  assert.equal(multi.task, '@!desk-beta 都跑', '只切掉第一个片段，其余原文保留');

  // 普通 @（没有感叹号）= 纯提及，零动作
  const plain = parseGroupDispatch('@desk-alpha 你看一下', candidates);
  assert.equal(plain.matched, false);
  assert.equal(plain.task, '@desk-alpha 你看一下');
});

// ---------------------------------------------------------------------------
// 成功链路
// ---------------------------------------------------------------------------

test('v0.8.2-α §3 成功派单：progress+result 两条摘要，正文只回发起方、不入群', async (t) => {
  const cluster = await startCluster(t, { count: 2 });
  const [a, b] = cluster.nodes;

  const summary = await a.server.group.dispatch({ target: b.peerId, task: 'echo ' + MARKER });
  assert.equal(summary.status, 'done');
  assert.equal(summary.target, b.peerId);
  assert.equal(summary.targetName, b.name);
  assert.ok(summary.replyChars > 0, '摘要里要有回复字数');
  assert.equal(Object.prototype.hasOwnProperty.call(summary, 'reply'), false, '门面只回摘要，绝不带正文');

  const progress = kindsOf(a, 'progress');
  const result = kindsOf(a, 'result');
  assert.equal(progress.length, 1);
  assert.equal(result.length, 1);
  assert.equal(progress[0].meta.phase, 'dispatch-start');
  assert.equal(progress[0].meta.target, b.peerId);
  assert.equal(progress[0].meta.by, a.peerId);
  assert.ok(progress[0].meta.sessionId, 'progress 必须带真实 sessionId');
  assert.equal(progress[0].text, '', 'progress 不带正文');
  assert.equal(result[0].meta.phase, 'dispatch-end');
  assert.equal(result[0].meta.status, 'done');
  assert.equal(result[0].meta.target, b.peerId);
  assert.equal(result[0].meta.by, a.peerId);
  assert.equal(result[0].meta.sessionId, progress[0].meta.sessionId);
  assert.ok(Number(result[0].meta.elapsedMs) >= 0);
  assert.ok(Number(result[0].meta.replyChars) > 0);
  assert.ok(progress[0].seq < result[0].seq, '开始必须在结束之前');

  // 隐私红线：群历史里既没有 prompt 原文，也没有回复全文（回复本身就是 prompt 的前 20 字）
  const blob = JSON.stringify(historyOf(a));
  assert.equal(blob.includes(MARKER), false, '群消息里不允许出现正文：' + blob);

  // 正文只经 dispatchWithReply（工具专用）回给发起方
  const full = await a.server.group.dispatchWithReply({ target: b.peerId, task: 'echo2 ' + MARKER });
  assert.equal(full.status, 'failed', '默认 60s 限流：同一目标第二次派单必须 busy');
  assert.equal(full.reason, 'busy');
});

test('v0.8.2-α §3 正文回发起方：dispatchWithReply 带着 reply，且它不进群', async (t) => {
  const cluster = await startCluster(t, { count: 2, groupExtra: { dispatchRateMs: 0 } });
  const [a, b] = cluster.nodes;

  const full = await a.server.group.dispatchWithReply({ target: b.peerId, task: 'only-me ' + MARKER });
  assert.equal(full.status, 'done');
  assert.equal(full.reply, 'OK ' + ('only-me ' + MARKER).slice(0, 20), '正文只有发起方拿得到');
  assert.equal(full.replyChars, full.reply.length);
  assert.equal(JSON.stringify(historyOf(a)).includes(MARKER), false);
});

test('v0.8.2-α §6.2 多条 @! 只派第一个：群里只有一条 progress，目标那台只收到一单', async (t) => {
  const cluster = await startCluster(t, { count: 3, groupExtra: { dispatchRateMs: 0 } });
  const [a, b, c] = cluster.nodes;

  const summary = await a.server.group.dispatch({ text: '@!' + b.peerId + ' @!' + c.peerId + ' 冒烟' });
  assert.equal(summary.status, 'done');
  assert.equal(summary.reason, 'multi-target-ignored', '多条 @! 不整条拒绝，但要记下这个 reason');
  assert.equal(summary.target, b.peerId);

  const result = kindsOf(a, 'result').pop();
  assert.equal(result.meta.reason, 'multi-target-ignored');
  assert.equal(result.meta.status, 'done');
  assert.equal(result.meta.target, b.peerId);

  assert.equal(b.server.sessions.size, 1, '第一个目标真的开了一单');
  assert.equal(c.server.sessions.size, 0, '第二个目标绝不能收到派单');
});

test('v0.8.2-α 管理接口自己解析时：extraTargets>0 也要把 multi-target-ignored 记进 meta', async (t) => {
  const cluster = await startCluster(t, { count: 2, groupExtra: { dispatchRateMs: 0 } });
  const [a, b] = cluster.nodes;

  // 等价于 Lane Y 的 admin/CLI：target/task 由它解析好，extraTargets 只是告诉 host「还有 1 个 @!」
  const summary = await a.server.group.dispatch({ target: b.peerId, task: '冒烟', extraTargets: 1 });
  assert.equal(summary.status, 'done');
  assert.equal(summary.reason, 'multi-target-ignored');
  const result = kindsOf(a, 'result').pop();
  assert.equal(result.meta.reason, 'multi-target-ignored');
  assert.equal(result.meta.status, 'done');
});

test('v0.8.2-α §6.3 普通 @（无感叹号）零动作、零消息', async (t) => {
  const cluster = await startCluster(t, { count: 2 });
  const [a, b] = cluster.nodes;

  const summary = await a.server.group.dispatch({ text: '@' + b.name + ' 只是提一句 ' + MARKER });
  assert.equal(summary.status, 'skipped');
  assert.equal(summary.reason, 'no-target');
  assert.equal(summary.target, null);
  assert.equal(historyOf(a).length, 0, '零消息');
  assert.equal(b.server.sessions.size, 0);
});

// ---------------------------------------------------------------------------
// 前置检查（契约 §2）
// ---------------------------------------------------------------------------

test('v0.8.2-α §4 接单开关：B 关掉 → hub 群状态回显 false → A 派单 not-accepting（且无 progress）', async (t) => {
  const cluster = await startCluster(t, { count: 2 });
  const [a, b] = cluster.nodes;

  assert.equal(a.server.group.state().members[b.peerId]?.acceptDispatch === false, false, '默认接单');
  assert.equal(b.server.group.acceptDispatch(), true);

  const off = b.server.group.setAcceptDispatch(false);
  assert.deepEqual(off, { acceptDispatch: false, persisted: true });
  assert.equal(b.server.group.acceptDispatch(), false, '热生效');
  // 落盘：重启后仍是关的（配置只是默认值来源）
  const prefs = JSON.parse(fs.readFileSync(path.join(b.dir, 'group-dispatch-prefs.json'), 'utf8'));
  assert.equal(prefs.acceptDispatch, false);

  // follower 的周期自报渠道是 pull（心跳只由 leader 发）。
  // 启动期那一轮自动 pull 可能还在飞（memberInFlight），所以这里显式重试到 hub 学到为止。
  const seen = await waitFor(async () => {
    await b.server.group.pull();
    return a.server.group.state().members[b.peerId]?.acceptDispatch === false;
  }, { timeoutMs: 8_000, intervalMs: 100 });
  assert.equal(seen, true, 'hub 必须从 pull 学到 acceptDispatch=false');

  const summary = await a.server.group.dispatch({ target: b.peerId, task: 'hi' });
  assert.equal(summary.status, 'failed');
  assert.equal(summary.reason, 'not-accepting');
  assert.equal(kindsOf(a, 'progress').length, 0, '没开跑就不写 progress');
  const result = kindsOf(a, 'result').pop();
  assert.equal(result.meta.status, 'failed');
  assert.equal(result.meta.reason, 'not-accepting');
  assert.equal(b.server.sessions.size, 0, '目标绝不能收到这一单');

  // 再打开即可恢复（不重启）
  assert.deepEqual(b.server.group.setAcceptDispatch(true), { acceptDispatch: true, persisted: true });
  const back = await waitFor(async () => {
    await b.server.group.pull();
    return a.server.group.state().members[b.peerId]?.acceptDispatch !== false;
  }, { timeoutMs: 8_000, intervalMs: 100 });
  assert.equal(back, true);
});

test('v0.8.2-α §2 限流：同一目标 60s 内第二单 busy，换目标不受影响', async (t) => {
  const cluster = await startCluster(t, { count: 3 });
  const [a, b, c] = cluster.nodes;

  const first = await a.server.group.dispatch({ target: b.peerId, task: 'one' });
  assert.equal(first.status, 'done');
  const second = await a.server.group.dispatch({ target: b.peerId, task: 'two' });
  assert.equal(second.status, 'failed');
  assert.equal(second.reason, 'busy');
  assert.equal(b.server.sessions.size, 1, '第二单根本没派出去');
  // 另一个目标不受这条限流影响
  const other = await a.server.group.dispatch({ target: c.peerId, task: 'three' });
  assert.equal(other.status, 'done');
});

test('v0.8.2-α §2 离线：目标不可达 → offline，不派单', async (t) => {
  const cluster = await startCluster(t, { count: 2 });
  const [a, b] = cluster.nodes;
  await cluster.makeUnreachable(b);

  const summary = await a.server.group.dispatch({ target: b.peerId, task: 'anyone there' });
  assert.equal(summary.status, 'failed');
  assert.equal(summary.reason, 'offline');
  const result = kindsOf(a, 'result').pop();
  assert.equal(result.meta.reason, 'offline');
});

test('v0.8.2-α §2 未配对：群里在、但本机没有它的 per-peer 密钥 → unpaired（明确回执，不静默）', async (t) => {
  const cluster = await startCluster(t, { count: 2 });
  const [a, b] = cluster.nodes;
  keepOnlyPeers(a.dir, []); // A 与任何人都没配对

  const summary = await a.server.group.dispatch({ target: b.peerId, task: 'reach me' });
  assert.equal(summary.status, 'failed');
  assert.equal(summary.reason, 'unpaired');
  const result = kindsOf(a, 'result').pop();
  assert.equal(result.meta.status, 'failed');
  assert.equal(result.meta.reason, 'unpaired');
  assert.equal(result.meta.target, b.peerId);
  assert.equal(b.server.sessions.size, 0);
});

test('v0.8.2-α §6.4 只有群密钥的成员（无 per-peer 密钥）发起派单 → unpaired，不静默', async (t) => {
  const cluster = await startCluster(t, { count: 2 });
  const [a, b] = cluster.nodes;
  // B 是成员节点，但 peers.json 里没有任何 per-peer 记录（等价于按名入群、只拿到群密钥）
  keepOnlyPeers(b.dir, []);
  assert.equal(fs.readFileSync(path.join(b.dir, 'peers.json'), 'utf8').includes(a.peerId), false);

  const summary = await b.server.group.dispatch({ target: a.peerId, task: 'help' });
  assert.equal(summary.status, 'failed');
  assert.equal(summary.reason, 'unpaired', '必须是明确的 unpaired，而不是静默什么都不做');
  assert.equal(summary.target, a.peerId);
  assert.equal(a.server.sessions.size, 0, '目标绝不能收到这一单');
});

test('v0.8.2-α §1 空任务：@!B 无正文 → empty，不派单', async (t) => {
  const cluster = await startCluster(t, { count: 2 });
  const [a, b] = cluster.nodes;

  const summary = await a.server.group.dispatch({ text: '@!' + b.peerId + '   ' });
  assert.equal(summary.status, 'failed');
  assert.equal(summary.reason, 'empty');
  const result = kindsOf(a, 'result').pop();
  assert.equal(result.meta.reason, 'empty');
  assert.equal(b.server.sessions.size, 0);
  assert.equal(kindsOf(a, 'progress').length, 0);
});


// ---------------------------------------------------------------------------
// 契约 §4 真机回归（2026-11-01）：开关必须真的传播，not-accepting 必须能触发
// ---------------------------------------------------------------------------

test('v0.8.2-α §4 hub 自己关单：立刻落 group.json，成员仅靠 pull 学到 → 派单 not-accepting', async (t) => {
  const cluster = await startCluster(t, { count: 2 });
  const [a, b] = cluster.nodes;

  // 启动即实数：hub 自己那条不再留 undefined
  assert.equal(a.server.group.state().members[a.peerId]?.acceptDispatch, true);
  assert.deepEqual(a.server.group.setAcceptDispatch(false), { acceptDispatch: false, persisted: true });
  // ① 切换立刻落盘（否则作者侧永远读到 undefined → 当 true）
  assert.equal(a.server.group.state().members[a.peerId]?.acceptDispatch, false);

  // ② 成员只靠 pull（不打心跳、不参与选举）就学到 hub 的关闭状态
  const learned = await waitFor(async () => {
    await b.server.group.pull();
    return b.server.group.local()?.members?.[a.peerId]?.acceptDispatch === false;
  }, { timeoutMs: 8_000, intervalMs: 100 });
  assert.equal(learned, true, '成员本地成员表必须从 pull 掩码学到 false');

  // ③ 派单被拒，且群里留下一条 failed/not-accepting 的 result
  const summary = await b.server.group.dispatch({ target: a.peerId, task: 'hub sleeping?' });
  assert.equal(summary.status, 'failed');
  assert.equal(summary.reason, 'not-accepting');
  assert.equal(a.server.sessions.size, 0, 'hub 绝不能收到这一单');
  const result = kindsOf(a, 'result').pop();
  assert.equal(result.meta.phase, 'dispatch-end');
  assert.equal(result.meta.status, 'failed');
  assert.equal(result.meta.reason, 'not-accepting');

  // ④ 打开后立刻恢复（同一条链路，不重启）
  assert.deepEqual(a.server.group.setAcceptDispatch(true), { acceptDispatch: true, persisted: true });
  const back = await waitFor(async () => {
    await b.server.group.pull();
    return b.server.group.local()?.members?.[a.peerId]?.acceptDispatch !== false;
  }, { timeoutMs: 8_000, intervalMs: 100 });
  assert.equal(back, true);
  const done = await b.server.group.dispatch({ target: a.peerId, task: 'hub awake?' });
  assert.equal(done.status, 'done');
});

test('v0.8.2-α §4 重启沿用 prefs：hub 新建即把自己那条写成 false', async (t) => {
  const stateDir = makeTempStateDir('dsh-lan-peers-prefs-');
  writeJson0600(path.join(stateDir, 'group-dispatch-prefs.json'), { acceptDispatch: false });
  const { server } = await startServer(t, {
    stateDir,
    group: { enabled: true, quorum: 'none', acceptDispatch: true },
  });
  assert.equal(server.group.acceptDispatch(), false, 'prefs 覆盖配置默认值');
  assert.equal(server.group.state().members[server.store.instanceId]?.acceptDispatch, false);
});

// ---------------------------------------------------------------------------
// 回执投递的两条通道（契约 §5：只有群密钥的作者也要能把派单写进群）
// ---------------------------------------------------------------------------

test('v0.8.2-α 回执通道降级：只有群密钥的成员派单成功 → 群历史里仍有 progress+result（正文不入群）', async (t) => {
  const cluster = await startCluster(t, { count: 3 });
  const [a, b, c] = cluster.nodes;
  // b 是作者：只和「目标 c」配对，**没有 hub(a) 的 per-peer 密钥**（等价于按名入群拿到的成员）
  keepOnlyPeers(b.dir, [c.peerId]);
  assert.equal(fs.readFileSync(path.join(b.dir, 'peers.json'), 'utf8').includes(a.peerId), false);

  const summary = await b.server.group.dispatch({ target: c.peerId, task: 'gk ' + MARKER });
  assert.equal(summary.status, 'done');
  assert.equal(summary.reason, null);
  assert.ok(summary.replyChars > 0);
  assert.equal(c.server.sessions.size, 1, '目标必须真的收到这一单');

  // 回执必须真的落进 hub 的群日志（per-peer 通道不可用时自动走群级签名）
  const messages = a.server.group.history({ sinceSeq: 0 });
  const progress = messages.filter((message) => message.kind === 'progress');
  const result = messages.filter((message) => message.kind === 'result');
  assert.equal(progress.length, 1, 'progress 必须落进群：' + JSON.stringify(messages));
  assert.equal(result.length, 1);
  assert.equal(progress[0].meta.phase, 'dispatch-start');
  assert.equal(progress[0].meta.by, b.peerId);
  assert.equal(progress[0].meta.target, c.peerId);
  assert.equal(result[0].meta.phase, 'dispatch-end');
  assert.equal(result[0].meta.status, 'done');
  assert.equal(result[0].meta.by, b.peerId);
  assert.ok(progress[0].seq < result[0].seq);
  // 隐私红线照旧：群级签名通道也不带正文
  assert.equal(JSON.stringify(messages).includes(MARKER), false);
});

test('v0.8.2-α 回执两条通道都失败：只记 group.error，派单 status 仍然准确', async (t) => {
  const cluster = await startCluster(t, { count: 3 });
  const [a, b, c] = cluster.nodes;
  keepOnlyPeers(b.dir, [c.peerId]); // 无 hub 的 per-peer 密钥 → 只能走群级签名
  await cluster.makeUnreachable(a); // hub 死掉 → 群级签名也打不到

  const full = await b.server.group.dispatchWithReply({ target: c.peerId, task: 'gk2 ' + MARKER });
  assert.equal(full.status, 'done', '回执失败绝不能把派单结果改成 failed');
  assert.equal(full.ok, true);
  assert.equal(full.reason, null);
  assert.ok(full.group.progressSeq === null, '回执没落地就没有 seq');
  assert.equal(typeof full.group.error, 'string');
  assert.ok(full.group.error.length > 0, '两条通道都失败时必须留下 group.error');
  assert.equal(c.server.sessions.size, 1, '派单本身照常发出');

  // 门面（面板/CLI 看到的那一份）不受影响：状态仍是 done，reason 仍是空
  const summary = await b.server.group.dispatch({ target: c.peerId, task: 'gk3' });
  assert.equal(summary.status, 'failed', '默认 60s 限流：第二次同目标必然 busy');
  assert.equal(summary.reason, 'busy');
});

// ---------------------------------------------------------------------------
// 冻结门面 + 工具
// ---------------------------------------------------------------------------

test('v0.8.2-α dispatchState：{ lastTarget, lastAt, inFlight }（派单期间 inFlight=true）', async (t) => {
  const cluster = await startCluster(t, { count: 2, groupExtra: { dispatchRateMs: 0 } });
  const [a, b] = cluster.nodes;

  assert.deepEqual(a.server.group.dispatchState(), { lastTarget: null, lastAt: 0, inFlight: false });

  const running = a.server.group.dispatch({ target: b.peerId, task: 'slow-ish' });
  await waitFor(() => a.server.group.dispatchState().inFlight === true);
  const during = a.server.group.dispatchState();
  assert.equal(during.inFlight, true);
  assert.equal(during.lastTarget, b.peerId);
  assert.ok(during.lastAt > 0);

  const summary = await running;
  assert.equal(summary.status, 'done');
  const after = a.server.group.dispatchState();
  assert.equal(after.inFlight, false);
  assert.equal(after.lastTarget, b.peerId);
});

test('v0.8.2-α lan_group_ask：与 lan_peer_ask 同形，先把 progress/result 写进群，回复只回调用方', async (t) => {
  const cluster = await startCluster(t, { count: 2, groupExtra: { dispatchRateMs: 0 } });
  const [a, b] = cluster.nodes;

  // defineTool 由 loadDshTools 提供（生产）；单测注入一个直通实现，避免依赖 DSH 安装
  const tools = await createLanPeerTools(
    { stateDir: a.dir, group: { enabled: true, hub: '' } },
    {
      feed: null,
      log: () => {},
      defineTool: (spec) => spec,
      dispatch: (input) => a.server.group.dispatchWithReply(input),
    },
  );
  const names = tools.map((tool) => tool.name);
  assert.ok(names.includes('lan_group_ask'), '新工具必须注册：' + names.join(','));
  assert.ok(names.includes('lan_peer_ask'), '既有 1:1 工具不能消失');

  const groupAsk = tools.find((tool) => tool.name === 'lan_group_ask');
  assert.deepEqual(Object.keys(groupAsk.parameters).sort(), ['peer', 'prompt', 'timeout_sec']);

  const out = await groupAsk.execute({ peer: b.name, prompt: 'tool ' + MARKER, timeout_sec: 30 });
  assert.equal(out.status, 'done');
  assert.equal(out.reply, 'OK ' + ('tool ' + MARKER).slice(0, 20), '工具把正文回给调用方');
  assert.equal(out.text, out.reply);

  const progress = kindsOf(a, 'progress');
  const result = kindsOf(a, 'result');
  assert.equal(progress.length, 1);
  assert.equal(result.length, 1);
  assert.equal(result[0].meta.status, 'done');
  assert.equal(JSON.stringify(historyOf(a)).includes(MARKER), false, '正文永远不入群');

  // 失败时工具回一句人话（reason 词表 → 提示）
  const failed = await groupAsk.execute({ peer: 'nobody-here', prompt: 'x' });
  assert.equal(failed.status, 'failed');
  assert.equal(failed.reason, 'unpaired');
  assert.match(failed.text, /not paired/);
});
