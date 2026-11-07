// dsh-lan-peers · v0.8.5-α（契约 §3/§4，Lane F2）CLI：send-file / inbox。
//
// 三条命令都只打本机回环管理接口（/api/lan-peers/files*），所以这里起一个只实现
// 那几条路由的 node:http 桩，真跑 cli.mjs 子进程，断言请求形状（含 token 头）、
// stdout 文案与退出码：403/409/501 归「本机现在做不了」（exit 2），其余算失败（exit 1）。
import test from 'node:test';
import assert from 'node:assert/strict';
import { listenOnRandomPort } from '../test-support/ports.mjs';
import http from 'node:http';
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { makeTempStateDir, writeJson0600 } from '../host/test/helpers.mjs';

process.env.DSH_LAN_PEERS_LANG = 'zh';   // 语言钉死：断言写的是中文文案，不随机器 locale 漂移

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), 'cli.mjs');
const TOKEN = 'cli-files-token';

function runAsync(args, env = {}) {
  return new Promise((resolve) => {
    execFile(process.execPath, [CLI, ...args], { encoding: 'utf8', env: { ...process.env, ...env } },
      (error, stdout, stderr) => {
        resolve({ status: error ? error.code : 0, stdout, stderr });
      });
  });
}

/** 只实现 /api/lan-peers/files* 的管理接口桩；handler(call) 决定状态码与响应体。 */
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
      // delayMs 让「发送中」的那一侧真的存在一会儿，进度轮询才有可观察的窗口。
      const send = () => {
        res.writeHead(reply.status ?? 200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(reply.body ?? {}));
      };
      if (reply.delayMs) setTimeout(send, reply.delayMs);
      else send();
    });
  });
  const { port } = await listenOnRandomPort(server);
  t.after(() => new Promise((resolve) => { server.close(() => resolve()); }));

  const dir = makeTempStateDir('dsh-lan-peers-cli-files-');
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  writeJson0600(path.join(dir, 'peers.json'), {
    peers: { 'peer-b-1234': { name: '书房', baseUrl: 'http://10.0.0.2:7788', secret: 's', inboundSecret: 'i' } },
  });
  if (token !== '') fs.writeFileSync(path.join(dir, 'admin-token'), token + '\n', { mode: 0o600 });
  const file = path.join(dir, 'payload.bin');
  fs.writeFileSync(file, Buffer.alloc(4096, 7));
  return { seen, url: 'http://127.0.0.1:' + port, dir, file };
}

const SHA = 'a'.repeat(64);
const AT = 1_760_000_000_000;

// ---------------------------------------------------------------------------
// send-file
// ---------------------------------------------------------------------------

test('send-file：POST { peerId, path } 带 token，打印 id/bytes/sha256/ms', async (t) => {
  const admin = await startAdmin(t, () => ({
    body: { ok: true, id: 'tx-7f3a91', bytes: 4096, sha256: SHA, ms: 37 },
  }));
  const out = await runAsync(['send-file', '书房', admin.file, '--url', admin.url, '--state-dir', admin.dir]);

  assert.equal(out.status, 0, out.stderr);
  assert.equal(out.stdout.trim(), '已发送 id=tx-7f3a91 bytes=4096 sha256=' + SHA + ' ms=37');
  assert.match(out.stderr, /发送中 → 书房 · 4096 字节/, '先把「往哪发、多大」说清楚');

  assert.equal(admin.seen.length, 1);
  assert.equal(admin.seen[0].method, 'POST');
  assert.equal(admin.seen[0].url, '/api/lan-peers/files/send');
  assert.deepEqual(admin.seen[0].body, { peerId: 'peer-b-1234', path: admin.file }, 'CLI 传 peerId，不传名字');
  assert.equal(admin.seen[0].token, TOKEN, '管理接口 token 从 state-dir 读出来带上');
});

test('send-file：未知伙伴 / 找不到文件都在本地就报错，不发请求', async (t) => {
  const admin = await startAdmin(t, () => ({ body: { ok: true } }));

  const unknownPeer = await runAsync(['send-file', '不存在的伙伴', admin.file, '--url', admin.url, '--state-dir', admin.dir]);
  assert.equal(unknownPeer.status, 1);
  assert.match(unknownPeer.stderr, /未知对端: 不存在的伙伴/);

  const unknownFile = await runAsync([
    'send-file', '书房', path.join(admin.dir, 'nope.bin'), '--url', admin.url, '--state-dir', admin.dir,
  ]);
  assert.equal(unknownFile.status, 1);
  assert.match(unknownFile.stderr, /找不到文件: .*nope\.bin/);

  const usage = await runAsync(['send-file', '书房', '--url', admin.url, '--state-dir', admin.dir]);
  assert.equal(usage.status, 1);
  assert.match(usage.stderr, /用法: dsh-lan-peers send-file <peer> <文件>/);

  assert.equal(admin.seen.length, 0, '本地就能拦下的错误不发请求');
});

test('send-file：进度轮询不可用（404/501）时静默降级为已用时长，不抛错也不改结果', async (t) => {
  // 现状（已在报告里标注）：出站 transfer 的 id 是发送完成才回的，所以 send 期间这一趟
  // 必然先走「已用 Ns」；progress 回 404/501 时同样静默退回，绝不让 send 失败。
  for (const status of [404, 501]) {
    const admin = await startAdmin(t, (call) => (call.url.includes('/files/progress')
      ? { status, body: { error: status === 404 ? 'unknown-id' : 'files-unsupported' } }
      : { body: { ok: true, id: 'tx-7f3a91', bytes: 4096, sha256: SHA, ms: 37 }, delayMs: 700 }));
    const out = await runAsync(
      ['send-file', '书房', admin.file, '--url', admin.url, '--state-dir', admin.dir],
      { DSH_LAN_PEERS_PROGRESS: '1' },
    );

    assert.equal(out.status, 0, out.stderr);
    assert.equal(out.stdout.trim(), '已发送 id=tx-7f3a91 bytes=4096 sha256=' + SHA + ' ms=37');
    assert.match(out.stderr, /已用 \d+s/, '拿不到字节进度就退回已用时长（TTY/强制模式才刷）');
    assert.equal(/文件操作失败/.test(out.stderr), false, '进度失败不外溢成命令失败');
  }
});

test('send-file：对端拒绝（409）走「现在做不了」exit 2，超限（400）exit 1', async (t) => {
  const refused = await startAdmin(t, () => ({ status: 409, body: { error: 'busy' } }));
  const out409 = await runAsync(['send-file', '书房', refused.file, '--url', refused.url, '--state-dir', refused.dir]);
  assert.equal(out409.status, 2);
  assert.match(out409.stderr, /文件操作失败: 409 busy/);

  const bad = await startAdmin(t, () => ({ status: 400, body: { error: 'too-large' } }));
  const out400 = await runAsync(['send-file', '书房', bad.file, '--url', bad.url, '--state-dir', bad.dir]);
  assert.equal(out400.status, 1);
  assert.match(out400.stderr, /400 too-large/);
});

// ---------------------------------------------------------------------------
// 管理地址解析（真机缺陷：不带 --url 时打到 peer 端口 7788 → 必然 404）
// ---------------------------------------------------------------------------

test('不带 --url 且没有 admin-url：明确报地址未知并退出 1，绝不静默回落 7788', async (t) => {
  const admin = await startAdmin(t, () => ({ body: { pending: [], inbox: [] } }));
  const out = await runAsync(['inbox', 'list', '--state-dir', admin.dir]);

  assert.equal(out.status, 1);
  assert.match(out.stderr, /本机管理接口地址未知/);
  assert.equal(out.stderr.includes('7788'), false, 'peer 端口绝不能出现在回落路径上');
  assert.equal(/文件操作失败: fetch failed/.test(out.stderr), false, '没有地址就不该发请求');
  assert.equal(admin.seen.length, 0);
});

test('admin-url 过期（端口已变、连不上）时给出可操作提示，而不是只留一句 fetch failed', async (t) => {
  const admin = await startAdmin(t, () => ({ body: { pending: [], inbox: [] } }));
  fs.writeFileSync(path.join(admin.dir, 'admin-url'), 'http://127.0.0.1:1\n', { mode: 0o600 });

  const out = await runAsync(['inbox', 'list', '--state-dir', admin.dir]);
  assert.equal(out.status, 1);
  assert.match(out.stderr, /连不上管理接口 http:\/\/127\.0\.0\.1:1/);
  assert.match(out.stderr, /地址可能已过期/);
  assert.match(out.stderr, /打开一次 DSH 面板/, '必须给出刷新地址的办法');
});

test('从 <stateDir>/admin-url 读到地址后直接成功（打开过一次面板就够）', async (t) => {
  const admin = await startAdmin(t, () => ({
    body: {
      pending: [],
      inbox: [{ id: 'id-done-1', name: 'photo.jpg', size: 2048, sha256: 'b'.repeat(64), from: { peerId: 'peer-b', name: '书房' }, at: AT, state: 'done' }],
    },
  }));
  // 面板/管理接口写下的就是这一行（http://<回环 Host>）。
  fs.writeFileSync(path.join(admin.dir, 'admin-url'), admin.url + '\n', { mode: 0o600 });

  const out = await runAsync(['inbox', 'list', '--state-dir', admin.dir]);
  assert.equal(out.status, 0, out.stderr);
  assert.equal(out.stdout.trim().split('\t')[0], '已收');
  assert.equal(admin.seen.length, 1);
  assert.equal(admin.seen[0].url, '/api/lan-peers/files');
  assert.equal(admin.seen[0].token, TOKEN, '地址来自文件，token 仍照常带');
});

test('send-file 回归：不带 --url 时用 admin-url 发出去（真机那条 404 的形状）', async (t) => {
  const admin = await startAdmin(t, () => ({ body: { ok: true, id: 'tx-7f3a91', bytes: 4096, sha256: SHA, ms: 29 } }));
  fs.writeFileSync(path.join(admin.dir, 'admin-url'), admin.url + '\n', { mode: 0o600 });

  const out = await runAsync(['send-file', '书房', admin.file, '--state-dir', admin.dir]);
  assert.equal(out.status, 0, out.stderr);
  assert.equal(out.stdout.trim(), '已发送 id=tx-7f3a91 bytes=4096 sha256=' + SHA + ' ms=29');
  assert.deepEqual(admin.seen.map((call) => call.url), ['/api/lan-peers/files/send']);
});

// ---------------------------------------------------------------------------
// inbox
// ---------------------------------------------------------------------------

test('inbox list：待确认与已收分行打印 id/文件名/体积/sha256/来源/时间，末行汇总', async (t) => {
  const admin = await startAdmin(t, () => ({
    body: {
      pending: [{ id: 'id-pending-1', name: '报告.pdf', size: 4096, sha256: SHA, from: { peerId: 'peer-b', name: '书房' }, at: AT, state: 'pending' }],
      inbox: [{ id: 'id-done-1', name: 'photo.jpg', size: 2048, sha256: 'b'.repeat(64), from: { peerId: 'peer-b', name: '书房' }, at: AT - 1000, state: 'done' }],
    },
  }));
  const out = await runAsync(['inbox', 'list', '--url', admin.url, '--state-dir', admin.dir]);

  assert.equal(out.status, 0, out.stderr);
  const lines = out.stdout.trim().split('\n');
  assert.equal(lines.length, 2);
  assert.equal(lines[0], ['待确认', 'id-pending-1', '报告.pdf', '4096B', 'sha256 ' + SHA, 'from 书房', new Date(AT).toISOString()].join('\t'));
  assert.equal(lines[1].split('\t')[0], '已收');
  assert.match(out.stderr, /待确认 1 个 · 已收 1 个/);
  assert.equal(admin.seen[0].method, 'GET');
  assert.equal(admin.seen[0].url, '/api/lan-peers/files');
  assert.equal(admin.seen[0].token, TOKEN);
});

test('inbox list：空收件箱只打一行汇总，不印空表头', async (t) => {
  const admin = await startAdmin(t, () => ({ body: { pending: [], inbox: [] } }));
  const out = await runAsync(['inbox', 'list', '--url', admin.url, '--state-dir', admin.dir]);
  assert.equal(out.status, 0, out.stderr);
  assert.equal(out.stdout, '');
  assert.match(out.stderr, /待确认 0 个 · 已收 0 个/);
});

test('inbox accept / reject：POST { id }，accept 打印落盘路径、reject 只回状态', async (t) => {
  const admin = await startAdmin(t, (call) => (call.url.endsWith('/accept')
    ? { body: { ok: true, path: '/state/inbox/id-pending-1__report.pdf' } }
    : { body: { ok: true } }));

  const accepted = await runAsync(['inbox', 'accept', 'id-pending-1', '--url', admin.url, '--state-dir', admin.dir]);
  assert.equal(accepted.status, 0, accepted.stderr);
  assert.equal(accepted.stdout.trim(), '已接受 id=id-pending-1 path=/state/inbox/id-pending-1__report.pdf');

  const rejected = await runAsync(['inbox', 'reject', 'id-pending-1', '--url', admin.url, '--state-dir', admin.dir]);
  assert.equal(rejected.status, 0, rejected.stderr);
  assert.equal(rejected.stdout.trim(), '已拒收 id=id-pending-1');

  assert.deepEqual(admin.seen.map((call) => [call.method, call.url, call.body]), [
    ['POST', '/api/lan-peers/files/accept', { id: 'id-pending-1' }],
    ['POST', '/api/lan-peers/files/reject', { id: 'id-pending-1' }],
  ]);
  assert.equal(admin.seen[0].contentType, 'application/json', '写操作必须是 JSON');
});

test('inbox：未知 id（404）exit 1；门面未接线（501）exit 2；缺 id 报用法且不发请求', async (t) => {
  const unknown = await startAdmin(t, () => ({ status: 404, body: { error: 'unknown-id' } }));
  const out404 = await runAsync(['inbox', 'accept', 'nope', '--url', unknown.url, '--state-dir', unknown.dir]);
  assert.equal(out404.status, 1);
  assert.match(out404.stderr, /文件操作失败: 404 unknown-id/);

  const unwired = await startAdmin(t, () => ({ status: 501, body: { error: 'files-unsupported' } }));
  const out501 = await runAsync(['inbox', 'list', '--url', unwired.url, '--state-dir', unwired.dir]);
  assert.equal(out501.status, 2);
  assert.match(out501.stderr, /文件操作失败: 501 files-unsupported/);

  const usage = await runAsync(['inbox', 'accept', '--url', unknown.url, '--state-dir', unknown.dir]);
  assert.equal(usage.status, 1);
  assert.match(usage.stderr, /用法: dsh-lan-peers inbox accept <id>/);
  assert.equal(unknown.seen.length, 1, '只有前一条 404 那次请求');

  const unknownSub = await runAsync(['inbox', 'nope', '--url', unknown.url, '--state-dir', unknown.dir]);
  assert.equal(unknownSub.status, 1);
  assert.match(unknownSub.stderr, /未知 inbox 子命令: nope/);
});

test('inbox：没有 admin-token 时 401 直接指路（告诉用户 token 在哪），不假装成功', async (t) => {
  const admin = await startAdmin(t, () => ({ status: 401, body: { error: 'token-required' } }), { token: '' });
  const out = await runAsync(['inbox', 'list', '--url', admin.url, '--state-dir', admin.dir]);
  assert.equal(out.status, 1);
  assert.match(out.stderr, /401 token-required/);
  assert.match(out.stderr, /管理接口需要 token/);
  assert.equal(admin.seen[0].token, '', '没有 token 文件就不带这个头');
});
