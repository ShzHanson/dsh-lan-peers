// dsh-lan-peers · v0.8.0-β（DESIGN §18.2）CLI：group archives / group archive-delete。
//
// 两个子命令都只打本机回环的 hub 管理接口（/api/lan-peers/group/archives），
// 所以这里起一个只实现这两条路由的 node:http 桩，真跑 cli.mjs 子进程，
// 断言请求形状、stdout 文案与退出码（403/409 归「现在做不了」，其余算失败）。
import test from 'node:test';
import assert from 'node:assert/strict';
import { listenOnRandomPort } from '../test-support/ports.mjs';
import http from 'node:http';
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { makeTempStateDir } from '../host/test/helpers.mjs';

process.env.DSH_LAN_PEERS_LANG = 'zh';   // 语言钉死：断言写的是中文文案，不随机器 locale 漂移

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), 'cli.mjs');
const MB = 1024 * 1024;

function runAsync(args) {
  return new Promise((resolve) => {
    execFile(process.execPath, [CLI, ...args], { encoding: 'utf8' }, (error, stdout, stderr) => {
      resolve({ status: error ? error.code : 0, stdout, stderr });
    });
  });
}

/** 起一个只实现 group/archives 的管理接口桩；handler 决定状态码与响应体。 */
async function startAdmin(t, handler) {
  const seen = [];
  const server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (chunk) => { raw += chunk; });
    req.on('end', () => {
      const body = raw === '' ? null : JSON.parse(raw);
      const call = { method: req.method, url: req.url, body };
      seen.push(call);
      const reply = handler(call) ?? {};
      res.writeHead(reply.status ?? 200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(reply.body ?? {}));
    });
  });
  const { port } = await listenOnRandomPort(server);
  t.after(() => new Promise((resolve) => { server.close(() => resolve()); }));
  const dir = makeTempStateDir('dsh-lan-peers-cli-archives-');
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return { seen, url: 'http://127.0.0.1:' + port, dir };
}

const ARCHIVES = [
  { file: '101-400.json', fromSeq: 101, toSeq: 400, count: 300, bytes: 12 * MB, createdAt: 1_700_000_000_000 },
  { file: '1-100.json', fromSeq: 1, toSeq: 100, count: 100, bytes: 9 * MB, createdAt: 1_600_000_000_000 },
];

test('group archives：逐行打印文件名 / seq 区间 / 条数 / 体积 / 时间，末行汇总', async (t) => {
  const admin = await startAdmin(t, () => ({ body: { archives: ARCHIVES, totalBytes: 21 * MB } }));
  const out = await runAsync(['group', 'archives', '--url', admin.url, '--state-dir', admin.dir]);
  assert.equal(out.status, 0, out.stderr);
  const lines = out.stdout.trim().split('\n');
  assert.equal(lines.length, 2);
  assert.match(lines[0], /^101-400\.json\tseq 101-400\t300 条\t12582912B\t1700000000000$/);
  assert.match(lines[1], /^1-100\.json\tseq 1-100\t100 条\t9437184B\t1600000000000$/);
  assert.match(out.stderr, /共 2 个归档 · 22020096 字节/);

  assert.equal(admin.seen.length, 1);
  assert.equal(admin.seen[0].method, 'GET');
  assert.equal(admin.seen[0].url, '/api/lan-peers/group/archives');
});

test('group archives：没有归档时给一行说明，不打印空表头', async (t) => {
  const admin = await startAdmin(t, () => ({ body: { archives: [], totalBytes: 0 } }));
  const out = await runAsync(['group', 'archives', '--url', admin.url, '--state-dir', admin.dir]);
  assert.equal(out.status, 0, out.stderr);
  assert.equal(out.stdout.trim(), '没有归档（hub 侧还没有归档文件）');
  assert.equal(out.stderr, '');
});

test('group archives：非 hub（403）按「现在做不了」退出 2，未启用（409）同理', async (t) => {
  const forbidden = await startAdmin(t, () => ({ status: 403, body: { error: 'hub-only' } }));
  const out403 = await runAsync(['group', 'archives', '--url', forbidden.url, '--state-dir', forbidden.dir]);
  assert.equal(out403.status, 2);
  assert.match(out403.stderr, /归档操作失败: 403 hub-only/);

  const disabled = await startAdmin(t, () => ({ status: 409, body: { error: 'group-disabled' } }));
  const out409 = await runAsync(['group', 'archives', '--url', disabled.url, '--state-dir', disabled.dir]);
  assert.equal(out409.status, 2);
  assert.match(out409.stderr, /409 group-disabled/);
});

test('group archives：门面未接线（501）如实报错并退出 1', async (t) => {
  const admin = await startAdmin(t, () => ({ status: 501, body: { error: 'archives-unsupported' } }));
  const out = await runAsync(['group', 'archives', '--url', admin.url, '--state-dir', admin.dir]);
  assert.equal(out.status, 1);
  assert.match(out.stderr, /归档操作失败: 501 archives-unsupported/);
  assert.equal(out.stdout, '');
});

test('group archive-delete：POST { file, action:"delete" } 并打印释放的字节', async (t) => {
  const admin = await startAdmin(t, () => ({ body: { ok: true, removedBytes: 12 * MB } }));
  const out = await runAsync(['group', 'archive-delete', '101-400.json', '--url', admin.url, '--state-dir', admin.dir]);
  assert.equal(out.status, 0, out.stderr);
  assert.equal(out.stdout.trim(), '已删除归档 101-400.json，释放 12582912 字节');
  assert.equal(admin.seen.length, 1);
  assert.equal(admin.seen[0].method, 'POST');
  assert.equal(admin.seen[0].url, '/api/lan-peers/group/archives');
  assert.deepEqual(admin.seen[0].body, { file: '101-400.json', action: 'delete' });
});

test('group archive-delete：未知归档（404）退出 1，权限失败（403）退出 2', async (t) => {
  const unknown = await startAdmin(t, () => ({ status: 404, body: { error: 'unknown-archive' } }));
  const out404 = await runAsync(['group', 'archive-delete', 'nope.json', '--url', unknown.url, '--state-dir', unknown.dir]);
  assert.equal(out404.status, 1);
  assert.match(out404.stderr, /归档操作失败: 404 unknown-archive/);

  const forbidden = await startAdmin(t, () => ({ status: 403, body: { error: 'hub-only' } }));
  const out403 = await runAsync(['group', 'archive-delete', '1-100.json', '--url', forbidden.url, '--state-dir', forbidden.dir]);
  assert.equal(out403.status, 2);
  assert.match(out403.stderr, /403 hub-only/);
});

test('group archive-delete：缺文件名直接报用法，不发请求', async (t) => {
  const admin = await startAdmin(t, () => ({ body: { ok: true, removedBytes: 0 } }));
  const out = await runAsync(['group', 'archive-delete', '--url', admin.url, '--state-dir', admin.dir]);
  assert.equal(out.status, 1);
  assert.match(out.stderr, /用法: dsh-lan-peers group archive-delete <file>/);
  assert.equal(admin.seen.length, 0);
});

test('group help：两个归档子命令都出现在帮助里', async () => {
  const out = await runAsync(['group', 'help']);
  assert.equal(out.status, 0);
  assert.match(out.stdout, /archives\s+列出 hub 侧归档文件/);
  assert.match(out.stdout, /archive-delete <file>\s+删除一个归档文件/);
});
