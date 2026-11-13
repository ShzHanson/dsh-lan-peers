// dsh-lan-peers · v0.8.5-α（契约 §5，Lane G2）CLI：dm <peer> <正文> / dm log / dm sync。
//
// 三条命令都只打本机回环管理接口（/api/lan-peers/dm*），所以这里起一个只实现那几条
// 路由的 node:http 桩，真跑 cli.mjs 子进程，断言请求形状（含 token 头）、stdout 文案与
// 退出码：401/403/409/501 归「本机现在做不了」（exit 2），其余算失败（exit 1）。
// 铁律（契约 §0）：正文可以进 stdout（用户自己要看的），但绝不进 stderr/日志。
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
const TOKEN = 'cli-dm-token';
const PEER_ID = 'peer-b-1234';

function runAsync(args, env = {}) {
  return new Promise((resolve) => {
    execFile(process.execPath, [CLI, ...args], { encoding: 'utf8', env: { ...process.env, ...env } },
      (error, stdout, stderr) => {
        resolve({ status: error ? error.code : 0, stdout, stderr });
      });
  });
}

/** 只实现 /api/lan-peers/dm* 的管理接口桩；handler(call) 决定状态码与响应体。 */
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
  const { port } = await listenOnRandomPort(server);
  t.after(() => new Promise((resolve) => { server.close(() => resolve()); }));

  const dir = makeTempStateDir('dsh-lan-peers-cli-dm-');
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  writeJson0600(path.join(dir, 'peers.json'), {
    peers: { [PEER_ID]: { name: '书房', baseUrl: 'http://10.0.0.2:7788', secret: 's', inboundSecret: 'i' } },
  });
  if (token !== '') fs.writeFileSync(path.join(dir, 'admin-token'), token + '\n', { mode: 0o600 });
  return { seen, url: 'http://127.0.0.1:' + port, dir };
}

const AT = 1_760_000_000_000;
const HISTORY = [
  { id: 'm-1', ts: AT, from: 'self', text: '我叫你小助手', sessionId: 's-1', state: 'sent' },
  { id: 'm-2', ts: AT + 900, from: 'peer', text: '好的，记住了', sessionId: 's-1', state: 'sent' },
];

// ---------------------------------------------------------------------------
// dm <peer> <正文>
// ---------------------------------------------------------------------------

test('dm <peer> <正文>：POST dm/send 带 token，打印回复与 sessionId/reused', async (t) => {
  const admin = await startAdmin(t, () => ({
    body: { ok: true, id: 'm-3', sessionId: 's-1', reply: '还记得，你让我叫小助手', elapsedMs: 1227, reused: true },
  }));
  const out = await runAsync(['dm', '书房', '我刚才让你叫什么？', '--url', admin.url, '--state-dir', admin.dir]);

  assert.equal(out.status, 0, out.stderr);
  assert.match(out.stdout, /^回复: 还记得，你让我叫小助手$/m);
  assert.match(out.stdout, /^id=m-3 sessionId=s-1 reused=true elapsedMs=1227$/m);
  assert.match(out.stderr, /发送中 → 书房 · 27 字节/, '先把「往哪发、多大」说清楚');

  assert.equal(admin.seen.length, 1);
  assert.equal(admin.seen[0].method, 'POST');
  assert.equal(admin.seen[0].url, '/api/lan-peers/dm/send');
  assert.deepEqual(admin.seen[0].body, { peerId: PEER_ID, text: '我刚才让你叫什么？' }, 'CLI 传 peerId，不传名字');
  assert.equal(admin.seen[0].token, TOKEN, '管理接口 token 从 state-dir 读出来带上');
  assert.doesNotMatch(out.stderr, /我刚才让你叫什么/, '正文不得进 stderr（日志口径只记字节数）');
});

test('dm <peer> <正文>：本机就能拦下的错误不发请求（未知对端 / 空正文 / 缺参数）', async (t) => {
  const admin = await startAdmin(t, () => ({ body: { ok: true } }));

  const unknown = await runAsync(['dm', '不存在的伙伴', '在吗', '--url', admin.url, '--state-dir', admin.dir]);
  assert.equal(unknown.status, 1);
  assert.match(unknown.stderr, /未知对端: 不存在的伙伴/);

  const blank = await runAsync(['dm', '书房', '   ', '--url', admin.url, '--state-dir', admin.dir]);
  assert.equal(blank.status, 1);
  assert.match(blank.stderr, /用法: dsh-lan-peers dm <peer> <正文>/);

  const missing = await runAsync(['dm', '书房', '--url', admin.url, '--state-dir', admin.dir]);
  assert.equal(missing.status, 1);
  assert.match(missing.stderr, /用法: dsh-lan-peers dm <peer> <正文>/);

  assert.equal(admin.seen.length, 0, '本地就能拦下的错误不发请求');
});

test('dm <peer> <正文> --perm <档>：校验档位并原样转发 permission（ask 改动的护栏）', async (t) => {
  const admin = await startAdmin(t, () => ({
    body: { ok: true, id: 'm-4', sessionId: 's-1', reply: '收到', permission: 'danger-full-access' },
  }));
  const out = await runAsync(['dm', '书房', '在吗', '--perm', 'danger-full-access', '--url', admin.url, '--state-dir', admin.dir]);

  assert.equal(out.status, 0, out.stderr);
  assert.equal(admin.seen.length, 1);
  assert.deepEqual(admin.seen[0].body, { peerId: PEER_ID, text: '在吗', permission: 'danger-full-access' }, '档位必须原样进 dm/send');
  assert.match(out.stdout, /perm=danger-full-access/);

  const bad = await runAsync(['dm', '书房', '在吗', '--perm', 'root', '--url', admin.url, '--state-dir', admin.dir]);
  assert.equal(bad.status, 1);
  assert.match(bad.stderr, /read-only \| workspace-write \| danger-full-access/, '非法档位仍在本机拦下');
  // 文案必须点对旗标：dm 用的是 --perm（dispatch settings 才用 --max-perm），
  // 共用一个键会让用户按提示去改一个这里不存在的旗标。
  assert.match(bad.stderr, /--perm 只能是/, 'dm 的报错必须点 --perm');
  assert.doesNotMatch(bad.stderr, /--max-perm/, 'dm 的报错不许提 --max-perm');
  assert.equal(admin.seen.length, 1, '档位非法时不发请求');
});

// ---------------------------------------------------------------------------
// dm log <peer>
// ---------------------------------------------------------------------------

test('dm log <peer> --limit N：GET dm?peer=，只打印最近 N 条', async (t) => {
  const admin = await startAdmin(t, () => ({ body: { peer: { peerId: PEER_ID, name: '书房' }, messages: HISTORY } }));
  const out = await runAsync(['dm', 'log', '书房', '--limit', '1', '--url', admin.url, '--state-dir', admin.dir]);

  assert.equal(out.status, 0, out.stderr);
  assert.equal(admin.seen.length, 1);
  assert.equal(admin.seen[0].method, 'GET');
  assert.equal(admin.seen[0].url, '/api/lan-peers/dm?peer=' + PEER_ID);
  assert.equal(admin.seen[0].token, TOKEN);

  const lines = out.stdout.trim().split('\n');
  assert.equal(lines.length, 1, '--limit 1 只打印一条');
  assert.equal(lines[0].split('\t')[1], '对方');
  assert.equal(lines[0].split('\t')[2], 'm-2');
  assert.match(lines[0], /好的，记住了$/);
  assert.match(out.stderr, /共 2 条，打印最近 1 条/);
});

test('dm log <peer>：默认打印全部（不超过 20 条），没有记录时也给出确定输出', async (t) => {
  const admin = await startAdmin(t, () => ({ body: { peer: { peerId: PEER_ID, name: '书房' }, messages: HISTORY } }));
  const out = await runAsync(['dm', 'log', '书房', '--url', admin.url, '--state-dir', admin.dir]);
  assert.equal(out.status, 0, out.stderr);
  const lines = out.stdout.trim().split('\n');
  assert.equal(lines.length, 2);
  assert.equal(lines[0].split('\t')[1], '我');
  assert.match(lines[0], /^\d{4}-\d{2}-\d{2}T/);
  assert.match(out.stderr.trim(), /共 2 条$/);

  const empty = await startAdmin(t, () => ({ body: { peer: { peerId: PEER_ID, name: '书房' }, messages: [] } }));
  const none = await runAsync(['dm', 'log', '书房', '--url', empty.url, '--state-dir', empty.dir]);
  assert.equal(none.status, 0, none.stderr);
  assert.equal(none.stdout, '');
  assert.match(none.stderr, /共 0 条/);

  const bad = await runAsync(['dm', 'log', '书房', '--limit', 'abc', '--url', admin.url, '--state-dir', admin.dir]);
  assert.equal(bad.status, 1);
  assert.match(bad.stderr, /--limit 必须是正整数/);
});

// ---------------------------------------------------------------------------
// dm sync <peer>
// ---------------------------------------------------------------------------

test('dm sync <peer>：POST dm/sync { peerId }，打印 added/total', async (t) => {
  const admin = await startAdmin(t, () => ({ body: { ok: true, added: 3, total: 5 } }));
  const out = await runAsync(['dm', 'sync', '书房', '--url', admin.url, '--state-dir', admin.dir]);

  assert.equal(out.status, 0, out.stderr);
  assert.equal(out.stdout.trim(), '已对齐 added=3 total=5');
  assert.equal(admin.seen.length, 1);
  assert.equal(admin.seen[0].url, '/api/lan-peers/dm/sync');
  assert.equal(admin.seen[0].method, 'POST');
  assert.deepEqual(admin.seen[0].body, { peerId: PEER_ID });
});

test('失败口径：501/409 归「本机现在做不了」exit 2，其余 exit 1，且都不把正文带上日志', async (t) => {
  const unsupported = await startAdmin(t, () => ({ status: 501, body: { error: 'dm-unsupported' } }));
  const unwired = await runAsync(['dm', '书房', '在吗', '--url', unsupported.url, '--state-dir', unsupported.dir]);
  assert.equal(unwired.status, 2);
  assert.match(unwired.stderr, /私聊失败: 501 dm-unsupported/);

  const offline = await startAdmin(t, () => ({ status: 409, body: { error: 'peer-offline' } }));
  const down = await runAsync(['dm', 'sync', '书房', '--url', offline.url, '--state-dir', offline.dir]);
  assert.equal(down.status, 2);
  assert.match(down.stderr, /私聊失败: 409 peer-offline/, '目标离线要原样给出 reason');

  const broken = await startAdmin(t, () => ({ status: 500, body: { error: 'boom' } }));
  const failed = await runAsync(['dm', '书房', '在吗', '--url', broken.url, '--state-dir', broken.dir]);
  assert.equal(failed.status, 1);
  assert.match(failed.stderr, /私聊失败: 500 boom/);
  assert.doesNotMatch(failed.stderr, /在吗/, '正文不得进错误输出');
});
