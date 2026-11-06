// dsh-lan-peers · lan_group_ask 的工作区/权限（0.8.5-α §4）。
//
// 门面（server.group.dispatchWithReply）在这里用桩替掉：这些用例钉的是**工具侧**的
// 契约 —— 入参怎么落到派单器、返回值追加哪几键、202 不报错、拒绝 reason 原样透出。
// 真正的端到端（群历史里没有 path、两条回执）在 host/test 里另有用例。
import test from 'node:test';
import assert from 'node:assert/strict';

import { createLanPeerTools } from './tools.mjs';

const SECRET_PROMPT = 'SECRET-PROMPT-do-not-log-9f2c';
const SECRET_REPLY = 'the reply body that never reaches the group history';

/** 造工具：defineTool 直通（不依赖 DSH 安装），dispatch 换成桩 */
async function groupAskWith(dispatch, log = () => {}) {
  const list = await createLanPeerTools(
    { stateDir: 'unused-in-these-tests' },
    { defineTool: (spec) => spec, log, dispatch },
  );
  const tool = list.find((entry) => entry.name === 'lan_group_ask');
  assert.ok(tool, 'lan_group_ask still registered');
  return tool;
}

test('0.8.5-α lan_group_ask：不传 workspace/permission → 入参与返回体与 0.8.4 逐字一致', async () => {
  const seen = [];
  const tool = await groupAskWith(async (input) => {
    seen.push(input);
    // 门面的完整结果（含范围三键）照样回：不点名时工具必须一个都不带出去
    return {
      status: 'done',
      target: 'peer-1',
      targetName: 'node-b',
      reply: 'OK',
      workspace: null,
      permission: null,
      appliedPermission: '',
      permissionHonored: false,
      approvalId: '',
    };
  });

  const out = await tool.execute({ peer: 'node-b', prompt: 'hello' });
  assert.deepEqual(seen, [{ target: 'node-b', task: 'hello', timeoutSec: 300 }],
    '不点名时派单入参只有老三键，且不带空字段');
  assert.deepEqual(out, { peer: 'node-b', target: 'peer-1', status: 'done', reply: 'OK', text: 'OK' },
    '不点名时返回体不多一个键（形状也算行为）');
});

test('0.8.5-α lan_group_ask：点名 workspace/permission → 透传两个键，返回体追加范围字段', async () => {
  const seen = [];
  const tool = await groupAskWith(async (input) => {
    seen.push(input);
    return {
      status: 'done',
      target: 'peer-1',
      targetName: 'node-b',
      reply: 'OK',
      workspace: { id: 'main', name: '主库' },
      permission: 'workspace-write',
      appliedPermission: 'workspace-write',
      permissionHonored: true,
      approvalId: '',
    };
  });

  const out = await tool.execute({
    peer: 'node-b',
    prompt: 'fix it',
    timeout_sec: 60,
    workspace: ' main ',
    permission: 'workspace-write',
  });
  assert.deepEqual(seen, [{
    target: 'node-b',
    task: 'fix it',
    timeoutSec: 60,
    workspaceId: 'main',
    permission: 'workspace-write',
  }], '两个新入参归一化后进派单器（workspace → workspaceId）');
  assert.equal(out.status, 'done');
  assert.equal(out.reply, 'OK');
  assert.equal(out.text, 'OK', '成功时 text 仍是正文本身（模型侧读的就是它）');
  assert.deepEqual(out.workspace, { id: 'main', name: '主库' });
  assert.equal(out.permission, 'workspace-write');
  assert.equal(out.appliedPermission, 'workspace-write');
  assert.equal(out.permissionHonored, true);
  assert.equal(out.approvalId, null);

  // 只点名工作区：请求里不出现 permission 键（老对端不该看到空字段）
  seen.length = 0;
  await tool.execute({ peer: 'node-b', prompt: 'fix it', workspace: 'main' });
  assert.equal('permission' in seen[0], false);
  assert.equal(seen[0].workspaceId, 'main');

  // 只点名权限：不出现 workspaceId 键
  seen.length = 0;
  await tool.execute({ peer: 'node-b', prompt: 'fix it', permission: 'read-only' });
  assert.equal('workspaceId' in seen[0], false);
  assert.equal(seen[0].permission, 'read-only');
});

test('0.8.5-α lan_group_ask：202 待批准不是失败 —— state=pending-approval + approvalId，且不抛错', async () => {
  const tool = await groupAskWith(async () => ({
    status: 'pending-approval',
    target: 'peer-1',
    targetName: 'node-b',
    reply: '',
    workspace: { id: 'main', name: '主库' },
    permission: 'danger-full-access',
    appliedPermission: '',
    permissionHonored: false,
    approvalId: 'ap-9f2c',
  }));

  const out = await tool.execute({ peer: 'node-b', prompt: SECRET_PROMPT, permission: 'danger-full-access' });
  assert.equal(out.state, 'pending-approval');
  assert.equal(out.status, 'pending-approval');
  assert.equal(out.approvalId, 'ap-9f2c');
  assert.equal(out.reply, '');
  assert.match(out.text, /人工确认后才能执行/, '待批准要有一句人话，而不是报错');
  assert.match(out.text, /ap-9f2c/);
  assert.equal(out.permission, 'danger-full-access');
  assert.equal(out.permissionHonored, false, '目标没说生效就不许当成生效');
  assert.equal(out.appliedPermission, '');
});

test('0.8.5-α lan_group_ask：403/409/400 的稳定 reason 原样透出（permission-denied / unknown-workspace / bad-permission）', async () => {
  const cases = [
    ['permission-denied', /maxPermission/],
    ['unknown-workspace', /workspace id/],
    ['bad-permission', /read-only/],
  ];
  for (const [reason, hint] of cases) {
    const tool = await groupAskWith(async () => ({
      status: 'failed',
      reason,
      target: 'peer-1',
      targetName: 'node-b',
      reply: '',
      workspace: { id: 'main', name: '' },
      permission: 'danger-full-access',
      appliedPermission: '',
      permissionHonored: false,
      approvalId: '',
    }));
    const out = await tool.execute({ peer: 'node-b', prompt: 'x', workspace: 'main', permission: 'danger-full-access' });
    assert.equal(out.status, 'failed');
    assert.equal(out.reason, reason, '对方的协议 token 不许被改写成 error');
    assert.ok(out.text.includes('(' + reason + ')'), '人话里要带这个 token：' + out.text);
    assert.match(out.text, hint, '每档拒绝都要有自己的解释，不许笼统成 transport or agent error');
    assert.doesNotMatch(out.text, /transport or agent error/);
    assert.equal(out.reply, '');
  }
});

test('0.8.5-α lan_group_ask：日志只记前 8 位/档位/工作区 id/字节数 —— 不记正文', async () => {
  const lines = [];
  const tool = await groupAskWith(
    async () => ({
      status: 'done',
      target: 'peer-abcdef0123456',
      targetName: 'node-b',
      reply: SECRET_REPLY,
      workspace: { id: 'main', name: '主库' },
      permission: 'read-only',
      appliedPermission: 'read-only',
      permissionHonored: true,
      approvalId: '',
    }),
    (line) => lines.push(String(line)),
  );

  await tool.execute({ peer: 'node-b', prompt: SECRET_PROMPT, workspace: 'main', permission: 'read-only' });
  const joined = lines.join('\n');
  assert.match(joined, /peer=peer-abc/, 'peer id 只留前 8 位');
  assert.match(joined, /workspace=main/);
  assert.match(joined, /permission=read-only/);
  assert.match(joined, new RegExp('bytes=' + SECRET_REPLY.length), '只记字节数');
  assert.equal(joined.includes(SECRET_PROMPT), false, '正文（prompt）绝不进日志');
  assert.equal(joined.includes(SECRET_REPLY), false, '回复正文绝不进日志');

  // 日志口径里的工作区：给了像 path 的值就不记（info 形同 '-')
  lines.length = 0;
  await tool.execute({ peer: 'node-b', prompt: 'x', workspace: 'D:\\secret\\dir' });
  assert.equal(lines.join('\n').includes('secret'), false, 'path 形状的工作区值不进日志');
});
