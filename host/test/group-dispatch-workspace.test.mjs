/**
 * 0.8.5-α 契约 §1/§2/§4：群派单的「工作区 + 权限」转交与回执。
 *
 * 覆盖：范围归一化与名字安全形状、双语回执 key、options 投影剥 path、
 * 不带新字段的 0.8.4 逐字一致、带字段透传（目标真按点名档执行）、
 * 202→pending-approval、403/409→failed 原样透出、未知字段忽略、
 * 群历史 JSON 里**没有任何 path**、server.group.post / dispatchOptions 两个门面。
 *
 * 全部真进程：真监听、真签名、真加密、真 1:1 ask（MemoryRunner 1s 完成）。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {
  dispatchOptionsView,
  groupDispatchReceiptText,
  normalizeDispatchScope,
  safeWorkspaceName,
} from '../../lib/group-client.mjs';
import { postAs, startCluster } from './group-cluster.mjs';
import { writeJson0600 } from './helpers.mjs';

const DOCS_NAME = '文档区';
const MAIN_NAME = '主工作区';

const historyOf = (node) => node.server.group.history({ sinceSeq: 0 });
const kindsOf = (node, kind) => historyOf(node).filter((message) => message.kind === kind);

/** JSON 里出现的路径有两种形状：原文与被 JSON 转义过的（反斜杠翻倍） */
function pathNeedles(absolute) {
  const encoded = JSON.stringify(absolute).slice(1, -1);
  return encoded === absolute ? [absolute] : [absolute, encoded];
}

function blobHasPath(blob, absolute) {
  return pathNeedles(absolute).some((needle) => blob.includes(needle));
}

/**
 * 给某台节点写一份 dispatch-prefs.json（host 每次请求现读现用，写完立刻生效）。
 * 刻意用两个**名字与 id 不同**的工作区：断言「回执里是名字，历史里没有 path」才有意义。
 */
function seedPrefs(node, { maxPermission = 'workspace-write', defaultWorkspaceId = 'main' } = {}) {
  const mainDir = path.join(node.dir, 'ws-main');
  const docsDir = path.join(node.dir, 'ws-docs');
  fs.mkdirSync(mainDir, { recursive: true });
  fs.mkdirSync(docsDir, { recursive: true });
  writeJson0600(path.join(node.dir, 'dispatch-prefs.json'), {
    defaultWorkspaceId,
    maxPermission,
    workspaces: [
      { id: 'main', name: MAIN_NAME, path: mainDir },
      { id: 'docs', name: DOCS_NAME, path: docsDir },
    ],
  });
  return { mainDir, docsDir };
}

// ---------------------------------------------------------------------------
// 纯函数：范围归一化 / 文案 / options 投影
// ---------------------------------------------------------------------------

test('0.8.5-α §1 范围归一化：只收字符串，path 形状的名字整条丢弃', () => {
  assert.deepEqual(normalizeDispatchScope({}), {
    workspaceId: '', workspaceName: '', permission: '', scoped: false,
  });
  assert.deepEqual(
    normalizeDispatchScope({ workspaceId: ' docs ', workspaceName: ' ' + DOCS_NAME + ' ', permission: ' read-only ' }),
    { workspaceId: 'docs', workspaceName: DOCS_NAME, permission: 'read-only', scoped: true },
  );
  // 名字像路径 → 只丢名字，id 仍是合法输入（展示回落 id）
  assert.equal(normalizeDispatchScope({ workspaceId: 'docs', workspaceName: 'D:\\secret\\ws' }).workspaceName, '');
  assert.equal(normalizeDispatchScope({ workspaceId: 'docs', workspaceName: '/home/u/ws' }).workspaceName, '');
  assert.equal(normalizeDispatchScope({ workspaceId: 'docs', workspaceName: '~/ws' }).workspaceName, '');
  // 非字符串一律当没给（不抛错）
  assert.equal(normalizeDispatchScope({ workspaceId: 42 }).scoped, false);
  assert.equal(normalizeDispatchScope(null).scoped, false);
  assert.equal(safeWorkspaceName('C:/work'), '');
  assert.equal(safeWorkspaceName(MAIN_NAME), MAIN_NAME);
  // 只给档位也算点名（目标用它的默认工作区）
  assert.equal(normalizeDispatchScope({ permission: 'read-only' }).scoped, true);
});

test('0.8.5-α §2 回执文案走 i18n 词表：zh / en 两份 key，工作区只出现名字', () => {
  const params = { target: 'node-b', workspaceId: 'docs', workspaceName: DOCS_NAME, permission: 'read-only' };
  const zhStart = groupDispatchReceiptText({ lang: 'zh', phase: 'dispatch-start', ...params });
  const enStart = groupDispatchReceiptText({ lang: 'en', phase: 'dispatch-start', ...params });
  assert.equal(zhStart, '派单 → node-b：进行中（工作区 ' + DOCS_NAME + ' · 权限 read-only）');
  assert.equal(enStart, 'dispatch → node-b: running (workspace ' + DOCS_NAME + ' · permission read-only)');
  // 有名字就不用 id：文案里不出现 workspaceId
  assert.equal(zhStart.includes('docs'), false);
  // 没有名字（目标没回告 / 拿不到）才回落 id
  const idOnly = groupDispatchReceiptText({
    lang: 'zh', phase: 'dispatch-start', target: 'node-b', workspaceId: 'docs', permission: 'read-only',
  });
  assert.match(idOnly, /工作区 docs · 权限 read-only/);

  // 结束三态：done / failed / pending-approval 都必须是词表里渲染出来的句子
  const done = groupDispatchReceiptText({ lang: 'zh', status: 'done', target: 'node-b', elapsedMs: 12, replyChars: 7 });
  assert.match(done, /^派单 → node-b：done（12ms · 7字）$/);
  const failed = groupDispatchReceiptText({ lang: 'en', status: 'failed', target: 'node-b', reason: 'permission-denied' });
  assert.equal(failed, 'dispatch → node-b: failed (permission-denied)');
  const pending = groupDispatchReceiptText({
    lang: 'zh', status: 'pending-approval', ...params,
  });
  assert.match(pending, new RegExp('pending-approval（工作区 ' + DOCS_NAME + ' · 权限 read-only'));
  // 两端都不写死语言：同一份参数在两种语言里只有词表不同
  assert.notEqual(
    groupDispatchReceiptText({ lang: 'zh', status: 'failed', target: 'x', reason: 'timeout' }),
    groupDispatchReceiptText({ lang: 'en', status: 'failed', target: 'x', reason: 'timeout' }),
  );
});

test('0.8.5-α §4 dispatchOptions 投影：对端回什么都只留 id 与名字（path 被剥掉）', () => {
  const view = dispatchOptionsView({
    defaultWorkspaceId: 'docs',
    maxPermission: 'workspace-write',
    // 对端「不小心」带上来的 path 与别的字段：这一层就要丢掉
    workspaces: [
      { id: 'main', name: MAIN_NAME, path: 'D:\\secret\\ws-main' },
      { id: 'docs', name: ' ' + DOCS_NAME + ' ', path: '/home/u/docs' },
      { id: '', name: 'no-id' },
      { id: 'deep', name: 'a/b' },
    ],
    secret: 'should-not-leak',
  });
  assert.deepEqual(view.workspaces, [
    { id: 'main', name: MAIN_NAME },
    { id: 'docs', name: DOCS_NAME },
    // 名字像路径 → 回落 id（宁可显示 id 也不显示半条路径）
    { id: 'deep', name: 'deep' },
  ]);
  assert.equal(view.defaultWorkspaceId, 'docs');
  assert.equal(view.maxPermission, 'workspace-write');
  const blob = JSON.stringify(view);
  assert.equal(blob.includes('secret'), false);
  assert.equal(blob.includes('\\'), false, '投影结果里连反斜杠都不该有: ' + blob);
  // 未知档位不猜：回空串
  assert.equal(dispatchOptionsView({ maxPermission: 'root' }).maxPermission, '');
  // 默认工作区指向不在清单里的 id → 回落到第一条
  assert.equal(dispatchOptionsView({ defaultWorkspaceId: 'ghost', workspaces: [{ id: 'main', name: 'm' }] }).defaultWorkspaceId, 'main');
  assert.deepEqual(dispatchOptionsView(null), { defaultWorkspaceId: '', maxPermission: '', workspaces: [] });
});

// ---------------------------------------------------------------------------
// 不带新字段：与 0.8.4 逐字一致
// ---------------------------------------------------------------------------

test('0.8.5-α §1 不带新字段：回执正文 / meta / 目标侧执行范围与 0.8.4 逐字一致', async (t) => {
  const cluster = await startCluster(t, { count: 2, groupExtra: { dispatchRateMs: 0 } });
  const [a, b] = cluster.nodes;
  seedPrefs(b);

  const summary = await a.server.group.dispatch({ target: b.peerId, task: 'echo plain' });
  assert.equal(summary.status, 'done');
  // 摘要上的范围字段全空（形状稳定，但值必须是「没点名」）
  assert.equal(summary.workspace, null);
  assert.equal(summary.permission, null);
  assert.equal(summary.appliedPermission, null);
  assert.equal(summary.permissionHonored, false);
  assert.equal(summary.approvalId, null);

  const progress = kindsOf(a, 'progress').pop();
  const result = kindsOf(a, 'result').pop();
  assert.equal(progress.text, '', 'progress 仍然不带正文');
  assert.match(result.text, /^done\/\d+ms\/\d+字$/, '旧格式逐字不变: ' + result.text);
  for (const key of ['workspaceId', 'workspaceName', 'permission']) {
    assert.equal(Object.prototype.hasOwnProperty.call(progress.meta, key), false, 'progress.meta 不该多出 ' + key);
    assert.equal(Object.prototype.hasOwnProperty.call(result.meta, key), false, 'result.meta 不该多出 ' + key);
  }

  // 目标侧：没点名 ⇒ 会话记录的 workspaceId/permission 为空，runner 用它的默认档
  const session = [...b.server.sessions.values()][0];
  assert.equal(session.workspaceId, '');
  assert.equal(session.workspaceName, '');
  assert.equal(session.permission, '');
});

// ---------------------------------------------------------------------------
// 带新字段：转交 + 回执
// ---------------------------------------------------------------------------

test('0.8.5-α §2 带 workspaceId + read-only：目标真按点名范围执行，回执只有名字与档位', async (t) => {
  const lines = [];
  const cluster = await startCluster(t, {
    count: 2,
    groupExtra: { dispatchRateMs: 0 },
    logger: (line) => lines.push(String(line)),
  });
  const [a, b] = cluster.nodes;
  const dirs = seedPrefs(b);

  const summary = await a.server.group.dispatch({
    target: b.peerId,
    task: 'echo scoped',
    workspaceId: 'docs',
    permission: 'read-only',
  });
  assert.equal(summary.status, 'done');
  assert.deepEqual(summary.workspace, { id: 'docs', name: DOCS_NAME });
  assert.equal(summary.permission, 'read-only', '请求档');
  assert.equal(summary.appliedPermission, 'read-only', '实际生效档由目标回告');
  assert.equal(summary.permissionHonored, true);

  // 目标侧日志：真的以只读档执行（真机验收同一条证据）
  assert.ok(
    lines.some((line) => /perm requested=read-only applied=read-only honored=true/.test(line)),
    '目标侧必须有 applied=read-only honored=true，实际日志: ' + lines.join(' | '),
  );
  // 目标侧会话记录：范围以 id + 名字落地，path 只交给 runner
  const bSession = [...b.server.sessions.values()][0];
  assert.equal(bSession.workspaceId, 'docs');
  assert.equal(bSession.workspaceName, DOCS_NAME);
  assert.equal(bSession.permission, 'read-only');

  // 回执 meta：三个范围键，只有 id / 名字 / 档位
  const progress = kindsOf(a, 'progress').pop();
  const result = kindsOf(a, 'result').pop();
  for (const message of [progress, result]) {
    assert.equal(message.meta.workspaceId, 'docs');
    assert.equal(message.meta.workspaceName, DOCS_NAME);
    assert.equal(message.meta.permission, 'read-only');
  }
  assert.equal(result.meta.status, 'done');

  // 回执正文是词表渲染的（语言取决于环境，两种形状都收；文案本身由纯函数用例钉住）
  assert.match(progress.text, new RegExp('(工作区 ' + DOCS_NAME + ' · 权限 read-only|workspace ' + DOCS_NAME + ' · permission read-only)'));
  assert.equal(progress.text.includes(dirs.docsDir), false);
  assert.equal(progress.text.includes(b.dir), false);

  // 群历史 JSON：有名字，没有任何绝对路径
  const blob = JSON.stringify(historyOf(a));
  assert.equal(blob.includes(DOCS_NAME), true, '工作区名字要在历史里（用于展示）');
  for (const absolute of [b.dir, dirs.mainDir, dirs.docsDir]) {
    assert.equal(blobHasPath(blob, absolute), false, '群历史里不允许出现 path: ' + absolute);
  }
});

test('0.8.5-α §2 超默认档 → 202 待批准：回执 pending-approval，不是失败', async (t) => {
  const cluster = await startCluster(t, { count: 2, groupExtra: { dispatchRateMs: 0 } });
  const [a, b] = cluster.nodes;
  seedPrefs(b);

  // 目标默认档 = read-only；这里要 workspace-write：≤ 上限(workspace-write) 但 > 默认档
  const summary = await a.server.group.dispatch({
    target: b.peerId,
    task: 'needs write',
    workspaceId: 'docs',
    permission: 'workspace-write',
  });
  assert.equal(summary.status, 'pending-approval');
  assert.equal(summary.reason, null, '待批准不是一个 reason');
  assert.ok(summary.approvalId, '发起方要拿 approvalId 继续等');
  assert.equal(summary.permissionHonored, false, '目标还没执行：绝不能报 honored');
  assert.deepEqual(summary.workspace, { id: 'docs', name: DOCS_NAME });

  const result = kindsOf(a, 'result').pop();
  assert.equal(result.meta.status, 'pending-approval');
  assert.equal(result.meta.reason, undefined);
  assert.equal(result.meta.workspaceId, 'docs');
  assert.equal(result.meta.permission, 'workspace-write');
  assert.equal(kindsOf(a, 'progress').length, 0, '待批准还没开会话，不该有 progress');
  assert.equal(b.server.sessions.size, 0);

  // 目标侧真的登记了这条待批准（id + 名字 + 档位，没有 path）
  const pending = b.server.dispatch.pending();
  assert.equal(pending.length, 1);
  assert.equal(pending[0].workspaceId, 'docs');
  assert.equal(pending[0].workspaceName, DOCS_NAME);
  assert.equal(pending[0].permission, 'workspace-write');
});

test('0.8.5-α §2 超目标上限 → 403：回执 failed 且 reason 原样透出', async (t) => {
  const cluster = await startCluster(t, { count: 2, groupExtra: { dispatchRateMs: 0 } });
  const [a, b] = cluster.nodes;
  seedPrefs(b);

  const summary = await a.server.group.dispatch({
    target: b.peerId,
    task: 'too much',
    workspaceId: 'docs',
    permission: 'danger-full-access',
  });
  assert.equal(summary.status, 'failed');
  assert.equal(summary.reason, 'permission-denied', '对方 403 的协议 token 原样透出');
  const result = kindsOf(a, 'result').pop();
  assert.equal(result.meta.status, 'failed');
  assert.equal(result.meta.reason, 'permission-denied');
  assert.equal(b.server.sessions.size, 0);
});

test('0.8.5-α §2 未知 workspaceId → 409：reason=unknown-workspace 原样透出', async (t) => {
  const cluster = await startCluster(t, { count: 2, groupExtra: { dispatchRateMs: 0 } });
  const [a, b] = cluster.nodes;
  seedPrefs(b);

  const summary = await a.server.group.dispatch({
    target: b.peerId,
    task: 'wrong place',
    workspaceId: 'ghost-workspace',
    permission: 'read-only',
  });
  assert.equal(summary.status, 'failed');
  assert.equal(summary.reason, 'unknown-workspace');
  const result = kindsOf(a, 'result').pop();
  assert.equal(result.meta.reason, 'unknown-workspace');
  assert.equal(b.server.sessions.size, 0);
  // 回执里仍然只有调用方点名的 id，没有对端任何目录信息
  assert.equal(result.meta.workspaceId, 'ghost-workspace');
  assert.equal(JSON.stringify(historyOf(a)).includes(b.dir), false);
});

// ---------------------------------------------------------------------------
// 旧成员兼容 / 群历史无 path
// ---------------------------------------------------------------------------

test('0.8.5-α §1 帖子顶层的新字段进 meta；未知字段被忽略，群历史里没有任何 path', async (t) => {
  const cluster = await startCluster(t, { count: 2 });
  const [a, b] = cluster.nodes;
  const dirs = seedPrefs(b);

  const res = await postAs(a.baseUrl, b.peerId, {
    kind: 'chat',
    text: 'hello',
    // 0.8.5 的 dispatch 帖：顶层带范围（hub 归一化后并入 meta）
    workspaceId: 'docs',
    workspaceName: DOCS_NAME,
    permission: 'read-only',
    // 旧成员那边会读到这些「未知字段」：必须忽略而不是抛错
    meta: { target: a.peerId, path: dirs.docsDir, secret: 'nope', nested: { deep: 1 } },
  });
  assert.equal(res.status, 201, '未知字段不能让发帖变成错误: ' + res.text);

  const message = historyOf(a).pop();
  assert.equal(message.kind, 'chat');
  assert.equal(message.meta.workspaceId, 'docs');
  assert.equal(message.meta.workspaceName, DOCS_NAME);
  assert.equal(message.meta.permission, 'read-only');
  assert.equal(message.meta.target, a.peerId);
  for (const junk of ['path', 'secret', 'nested']) {
    assert.equal(Object.prototype.hasOwnProperty.call(message.meta, junk), false, '未知字段 ' + junk + ' 必须被丢弃');
  }
  const blob = JSON.stringify(historyOf(a));
  assert.equal(blob.includes('"path"'), false);
  assert.equal(blobHasPath(blob, dirs.docsDir), false);
  assert.equal(blob.includes('nope'), false);

  // 非标量的新字段同样只被丢掉，不会 500 / 不会抛
  const weird = await postAs(a.baseUrl, b.peerId, {
    kind: 'chat',
    text: 'still fine',
    workspaceId: { nested: true },
    permission: ['read-only'],
  });
  assert.equal(weird.status, 201);
  const last = historyOf(a).pop();
  assert.equal(Object.prototype.hasOwnProperty.call(last.meta, 'workspaceId'), false);
  assert.equal(Object.prototype.hasOwnProperty.call(last.meta, 'permission'), false);
});

// ---------------------------------------------------------------------------
// 门面：server.group.post / server.group.dispatchOptions
// ---------------------------------------------------------------------------

test('0.8.5-α §4 server.group.post({workspaceId,permission})：发帖 + 派单，回执与历史都只有名字', async (t) => {
  const lines = [];
  const cluster = await startCluster(t, {
    count: 2,
    groupExtra: { dispatchRateMs: 0 },
    logger: (line) => lines.push(String(line)),
  });
  const [a, b] = cluster.nodes;
  const dirs = seedPrefs(b);

  const out = await a.server.group.post({
    text: '@!' + b.peerId + ' 冒烟',
    target: b.peerId,
    workspaceId: 'docs',
    permission: 'read-only',
  });
  assert.equal(out.status, 'done');
  assert.deepEqual(out.workspace, { id: 'docs', name: DOCS_NAME });
  assert.equal(out.permission, 'read-only');
  assert.equal(out.appliedPermission, 'read-only');
  assert.equal(out.permissionHonored, true);
  assert.ok(Number.isFinite(Number(out.seq)), '帖子要真的进群历史');

  const messages = historyOf(a);
  const post = messages.find((message) => message.kind === 'chat');
  assert.equal(post.meta.workspaceId, 'docs');
  assert.equal(post.meta.workspaceName, DOCS_NAME);
  assert.equal(post.meta.permission, 'read-only');
  assert.equal(post.meta.target, b.peerId);

  const blob = JSON.stringify(messages);
  assert.equal(blob.includes(DOCS_NAME), true);
  for (const absolute of [b.dir, dirs.docsDir, dirs.mainDir]) {
    assert.equal(blobHasPath(blob, absolute), false, '群历史里不允许出现 path: ' + absolute);
  }
  // 目标侧真的只读执行
  assert.ok(lines.some((line) => /perm requested=read-only applied=read-only honored=true/.test(line)));

  // 不带新字段时仍是 0.8.4 的同步 append（原样返回那条消息）
  const plain = a.server.group.post({ peerId: a.peerId, name: a.name, kind: 'chat', text: 'plain' });
  assert.equal(typeof plain.then, 'undefined', '老形状必须还是同步返回');
  assert.equal(plain.kind, 'chat');
  assert.equal(plain.text, 'plain');
});

test('0.8.5-α §4 dispatchOptions 代理：只有 id 与名字，未知对端回 ok:false', async (t) => {
  const cluster = await startCluster(t, { count: 2 });
  const [a, b] = cluster.nodes;
  seedPrefs(b);

  const view = await a.server.group.dispatchOptions(b.peerId);
  assert.equal(view.ok, true);
  assert.equal(view.defaultWorkspaceId, 'main');
  assert.equal(view.maxPermission, 'workspace-write');
  assert.deepEqual(view.workspaces, [
    { id: 'main', name: MAIN_NAME },
    { id: 'docs', name: DOCS_NAME },
  ]);
  const blob = JSON.stringify(view);
  assert.equal(blob.includes('ws-docs'), false, '代理结果里不允许出现 path: ' + blob);
  assert.equal(Object.prototype.hasOwnProperty.call(view.workspaces[0], 'path'), false);

  // 也认名字（面板从成员表拿到的就是显示名）
  const byName = await a.server.group.dispatchOptions(b.name);
  assert.equal(byName.ok, true);
  assert.deepEqual(byName.workspaces, view.workspaces);

  // 未知对端：不抛错，明确回 unknown-peer（调用方据此置灰弹层）
  const ghost = await a.server.group.dispatchOptions('ghost-node');
  assert.equal(ghost.ok, false);
  assert.equal(ghost.error, 'unknown-peer');
  assert.deepEqual(ghost.workspaces, []);
});
