// dsh-lan-peers · v0.8.5-α（契约 §5/§6，Lane H2）CLI：dispatch pending/approve/reject/settings
// 与 dm <peer> <正文> --workspace/--perm。
//
// 全部只打本机回环管理接口（/api/lan-peers/dispatch*），所以这里起一个只实现那几条路由的
// node:http 桩，真跑 cli.mjs 子进程，断言请求形状（含 token 头）、stdout 文案与退出码：
// 401/403/409/501 归「本机现在做不了」（exit 2），其余算失败（exit 1）。
// 铁律（契约 §0）：跨机只走 id+name；日志只记 id 前 8 位、权限档、工作区 id、字节数。
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { makeTempStateDir, writeJson0600 } from '../host/test/helpers.mjs';

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), 'cli.mjs');
const TOKEN = 'cli-dispatch-settings-token';
const PEER_ID = 'peer-b-1234';

function runAsync(args, env = {}) {
  return new Promise((resolve) => {
    execFile(process.execPath, [CLI, ...args],
      // 语言钉死：断言写的是中文文案，不能随机器 locale 翻成英文。
      { encoding: 'utf8', env: { ...process.env, DSH_LAN_PEERS_LANG: 'zh', ...env } },
      (error, stdout, stderr) => {
        resolve({ status: error ? error.code : 0, stdout, stderr });
      });
  });
}

async function startAdmin(t, handler, { token = TOKEN } = {}) {
  const seen = [];
  const server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (chunk) => { raw += chunk; });
    req.on('end', () => {
      const call = {
        method: req.method,
        url: req.url,
        token: req.headers['x-lan-peers-token'] ?? '',
        contentType: req.headers['content-type'] ?? '',
        body: raw === '' ? null : JSON.parse(raw),
      };
      seen.push(call);
      const reply = handler(call) ?? {};
      res.writeHead(reply.status ?? 200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(reply.body ?? {}));
    });
  });
  const port = await new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve(server.address().port));
  });
  t.after(() => new Promise((resolve) => { server.close(() => resolve()); }));

  const dir = makeTempStateDir('dsh-lan-peers-cli-dispatch-');
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  writeJson0600(path.join(dir, 'peers.json'), {
    peers: { [PEER_ID]: { name: '书房', baseUrl: 'http://10.0.0.2:7788', secret: 's', inboundSecret: 'i' } },
  });
  if (token !== '') fs.writeFileSync(path.join(dir, 'admin-token'), token + '\n', { mode: 0o600 });
  return { seen, url: 'http://127.0.0.1:' + port, dir };
}

const NOW = Date.now();
const PENDING = [
  {
    approvalId: 'ap-1', from: 'peer-b-12345678', workspaceId: 'main', workspaceName: '主工作区',
    permission: 'danger-full-access', promptBytes: 64, at: NOW, expiresAt: NOW + 120_000,
  },
];
const PREFS = {
  defaultWorkspaceId: 'main',
  maxPermission: 'workspace-write',
  workspaces: [
    { id: 'main', name: '主工作区', path: 'D:/work/main' },
    { id: 'docs', name: '文档', path: 'D:/work/docs' },
  ],
};

test('dispatch pending：GET dispatch/pending，逐行 id/来源/工作区/权限/剩余秒数', async (t) => {
  const admin = await startAdmin(t, () => ({ body: { items: PENDING } }));
  const out = await runAsync(['dispatch', 'pending', '--url', admin.url, '--state-dir', admin.dir]);

  assert.equal(out.status, 0, out.stderr);
  assert.equal(admin.seen.length, 1);
  assert.equal(admin.seen[0].method, 'GET');
  assert.equal(admin.seen[0].url, '/api/lan-peers/dispatch/pending');
  assert.equal(admin.seen[0].token, TOKEN);
  assert.match(out.stdout, /^ap-1\t来自 peer-b-1\t工作区 main\/主工作区\tdanger-full-access\t剩余 \d+s$/m);
  assert.match(out.stderr, /待批准 1 条/);
});

test('dispatch pending：没有待批准时只打一行说明，空表头不出现', async (t) => {
  const admin = await startAdmin(t, () => ({ body: { items: [] } }));
  const out = await runAsync(['dispatch', 'pending', '--url', admin.url, '--state-dir', admin.dir]);
  assert.equal(out.status, 0);
  assert.equal(out.stdout.trim(), '');
  assert.match(out.stderr, /（没有待批准请求）/);
});

test('dispatch approve <id>：POST { id } 并打印 state', async (t) => {
  const admin = await startAdmin(t, () => ({ body: { ok: true, state: 'approved' } }));
  const out = await runAsync(['dispatch', 'approve', 'ap-1', '--url', admin.url, '--state-dir', admin.dir]);

  assert.equal(out.status, 0, out.stderr);
  assert.equal(admin.seen[0].method, 'POST');
  assert.equal(admin.seen[0].url, '/api/lan-peers/dispatch/approve');
  assert.deepEqual(admin.seen[0].body, { id: 'ap-1' });
  assert.match(out.stdout, /^已批准 ap-1（state=approved）$/m);
});

test('dispatch reject <id>：POST { id }；未知 approval（404）exit 1，501 exit 2', async (t) => {
  const admin = await startAdmin(t, () => ({ body: { ok: true, state: 'rejected' } }));
  const ok = await runAsync(['dispatch', 'reject', 'ap-2', '--url', admin.url, '--state-dir', admin.dir]);
  assert.equal(ok.status, 0, ok.stderr);
  assert.equal(admin.seen[0].url, '/api/lan-peers/dispatch/reject');
  assert.deepEqual(admin.seen[0].body, { id: 'ap-2' });
  assert.match(ok.stdout, /^已拒绝 ap-2（state=rejected）$/m);

  const missing = await startAdmin(t, () => ({ status: 404, body: { error: 'unknown-approval' } }));
  const notFound = await runAsync(['dispatch', 'reject', 'ap-3', '--url', missing.url, '--state-dir', missing.dir]);
  assert.equal(notFound.status, 1, '404 是业务失败，不是「现在做不了」');
  assert.match(notFound.stderr, /派单设置操作失败: 404 unknown-approval/);

  const off = await startAdmin(t, () => ({ status: 501, body: { error: 'dispatch-unsupported' } }));
  const unsupported = await runAsync(['dispatch', 'reject', 'ap-4', '--url', off.url, '--state-dir', off.dir]);
  assert.equal(unsupported.status, 2, '501 = 本机还没有门面');
});

test('dispatch approve 缺 id：直接报用法，一个请求都不发', async (t) => {
  const admin = await startAdmin(t, () => ({ body: { ok: true } }));
  const out = await runAsync(['dispatch', 'approve', '--url', admin.url, '--state-dir', admin.dir]);
  assert.equal(out.status, 1);
  assert.match(out.stderr, /需要 approvalId/);
  assert.equal(admin.seen.length, 0);
});

test('dispatch settings：只读时 GET dispatch/settings，打印默认/上限/工作区清单（含 path）', async (t) => {
  const admin = await startAdmin(t, () => ({ body: PREFS }));
  const out = await runAsync(['dispatch', 'settings', '--url', admin.url, '--state-dir', admin.dir]);

  assert.equal(out.status, 0, out.stderr);
  assert.equal(admin.seen[0].method, 'GET');
  assert.equal(admin.seen[0].url, '/api/lan-peers/dispatch/settings');
  assert.match(out.stdout, /^默认工作区 main\t最大授权 workspace-write\t工作区 2 个$/m);
  assert.match(out.stdout, /^  main\t主工作区\tD:\/work\/main$/m);
  assert.match(out.stdout, /^  docs\t文档\tD:\/work\/docs$/m);
});

test('dispatch settings --default X --max-perm Y：POST 只带改动的字段；非法档位在本地挡住', async (t) => {
  const admin = await startAdmin(t, (call) => ({ body: { ...PREFS, ...call.body } }));
  const out = await runAsync([
    'dispatch', 'settings', '--default', 'docs', '--max-perm', 'read-only',
    '--url', admin.url, '--state-dir', admin.dir,
  ]);
  assert.equal(out.status, 0, out.stderr);
  assert.equal(admin.seen[0].method, 'POST');
  assert.deepEqual(admin.seen[0].body, { defaultWorkspaceId: 'docs', maxPermission: 'read-only' });
  assert.match(out.stdout, /^派单设置已保存: 默认 docs · 最大授权 read-only · 工作区 2 个$/m);

  const bad = await runAsync([
    'dispatch', 'settings', '--max-perm', 'root', '--url', admin.url, '--state-dir', admin.dir,
  ]);
  assert.equal(bad.status, 1);
  assert.match(bad.stderr, /--max-perm 只能是 read-only \| workspace-write \| danger-full-access/);
  assert.equal(admin.seen.length, 1, '非法档位不发第二个请求');
});

test('dm <peer> <正文> --workspace/--perm：body 带两个字段，打印实际生效的那组', async (t) => {
  const admin = await startAdmin(t, () => ({
    body: {
      ok: true, id: 'm-5', sessionId: 's-1', reply: '只读跑完了', elapsedMs: 30, reused: true,
      workspace: { id: 'docs', name: '文档' }, permission: 'read-only',
    },
  }));
  const out = await runAsync([
    'dm', '书房', '看下文档目录', '--workspace', 'docs', '--perm', 'read-only',
    '--url', admin.url, '--state-dir', admin.dir,
  ]);

  assert.equal(out.status, 0, out.stderr);
  assert.deepEqual(admin.seen[0].body, {
    peerId: PEER_ID, text: '看下文档目录', workspaceId: 'docs', permission: 'read-only',
  });
  assert.match(out.stdout, /workspace=docs perm=read-only$/m);
  assert.doesNotMatch(out.stderr, /看下文档目录/, '正文不进 stderr');
});

test('dm 完全权限：202 待确认时打印「等待对方确认」而不是假装有回复', async (t) => {
  const admin = await startAdmin(t, () => ({
    status: 202,
    body: { ok: true, pendingApproval: true, approvalId: 'ap-7', expiresAt: Date.now() + 600_000 },
  }));
  const out = await runAsync([
    'dm', '书房', '把构建跑一遍', '--perm', 'danger-full-access',
    '--url', admin.url, '--state-dir', admin.dir,
  ]);

  assert.equal(out.status, 0, out.stderr);
  assert.match(out.stdout, /^已发给 书房：等待对方确认这次派单（approval ap-7，剩余 \d+ 秒）$/m);
  assert.match(out.stdout, /^approvalId=ap-7 state=pending-approval$/m);
  assert.equal(/回复:/.test(out.stdout), false, '还没执行就没有回复可说');
});

test('dm 不带工作区与档位：请求体与以前一模一样（契约 §2 的「都不传」）', async (t) => {
  const admin = await startAdmin(t, () => ({ body: { ok: true, id: 'm-6', sessionId: 's-1', reply: 'ok', elapsedMs: 3, reused: false } }));
  const out = await runAsync(['dm', '书房', '在吗', '--url', admin.url, '--state-dir', admin.dir]);
  assert.equal(out.status, 0, out.stderr);
  assert.deepEqual(admin.seen[0].body, { peerId: PEER_ID, text: '在吗' });
  assert.match(out.stdout, /^id=m-6 sessionId=s-1 reused=false elapsedMs=3$/m);
});

test('语言钉住：每个 client/cli*.test.mjs 都显式设了 DSH_LAN_PEERS_LANG=zh', async () => {
  // 中文正则断言若依赖机器 locale，换到 en-US 机器会整体翻成英文而失败；
  // 这里把「必须显式钉住」变成一条断言，防止以后新加的 CLI 用例又漂回去。
  const dir = path.dirname(CLI);
  const files = fs.readdirSync(dir).filter((name) => /^cli.*\.test\.mjs$/.test(name));
  assert.ok(files.length >= 8, '至少覆盖现有的 8 个 CLI 测试文件');
  for (const name of files) {
    const text = fs.readFileSync(path.join(dir, name), 'utf8');
    assert.match(text, /DSH_LAN_PEERS_LANG['\]]?\s*[:=]\s*'zh'/, name + ' 必须把语言钉成 zh');
  }
});
