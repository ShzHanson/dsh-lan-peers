// dsh-lan-peers · CLI group-file：把本机一个文件发进本机所在的群。
//
// 命令走的是**面板群上传那条已经存在的链**（lib/admin.mjs files/upload/init → chunk × N → finish
// 且 finish 带 scope=group），所以这里起一个只实现那三条路由的 node:http 桩，真跑 cli.mjs
// 子进程，逐条断言请求序列与形状：片数、offset 严格递增、base64 原文、finish 的 scope 与 targets。
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { listenOnRandomPort } from '../test-support/ports.mjs';
import { keys, t as text } from '../lib/i18n.mjs';
import { makeTempStateDir, writeJson0600 } from '../host/test/helpers.mjs';

process.env.DSH_LAN_PEERS_LANG = 'zh';   // 语言钉死：断言写的是中文文案，不随机器 locale 漂移

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), 'cli.mjs');
const TOKEN = 'cli-group-file-token';
const UPLOAD_ID = '11111111-2222-3333-4444-555555555555';
const CHUNK = 512;                        // 服务端回显的 chunkBytes（= FILE_CHUNK_HARD_MAX）
const SHA = 'c0ffeeaa' + 'a'.repeat(56);  // 整文件摘要；成功行只留前 8 位
const FILE_ID = 'gfile-7f3a91c2';
const BODY = Buffer.alloc(1300);          // 512 + 512 + 276 → 恰好三片
for (let i = 0; i < BODY.length; i++) BODY[i] = i & 255;

function runAsync(args, env = {}) {
  return new Promise((resolve) => {
    execFile(process.execPath, [CLI, ...args], { encoding: 'utf8', env: { ...process.env, ...env } },
      (error, stdout, stderr) => resolve({ status: error ? error.code : 0, stdout, stderr }));
  });
}

/** 只实现 files/upload/init|chunk|finish|cancel 的管理接口桩；handler(call) 决定状态码与响应体。 */
async function startAdmin(t, handler, { bytes = BODY } = {}) {
  const seen = [];
  const server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (chunk) => { raw += chunk; });
    req.on('end', () => {
      const call = {
        method: req.method,
        url: req.url,
        token: req.headers['x-lan-peers-token'] ?? '',
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

  const dir = makeTempStateDir('dsh-lan-peers-cli-group-file-');
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  writeJson0600(path.join(dir, 'peers.json'), {
    peers: { 'peer-b-1234': { name: '书房', baseUrl: 'http://10.0.0.2:7788', secret: 's', inboundSecret: 'i' } },
  });
  fs.writeFileSync(path.join(dir, 'admin-token'), TOKEN + '\n', { mode: 0o600 });
  const file = path.join(dir, 'payload.bin');
  fs.writeFileSync(file, bytes);
  return { seen, url: 'http://127.0.0.1:' + port, dir, file };
}

const R = '/api/lan-peers/files/upload/';
const seqOf = (seen) => seen.map((call) => call.method + ' ' + call.url);
const decoded = (call) => Buffer.from(String(call.body?.dataBase64 ?? ''), 'base64');

/** 面板那条链的应答：init 回 uploadId/chunkBytes，chunk 回「offset + 这一片的字节数」。 */
function panelChain(onChunk) {
  return (call) => {
    if (call.url === R + 'init') return { body: { uploadId: UPLOAD_ID, chunkBytes: CHUNK, maxBytes: 512 * 1024 * 1024 } };
    if (call.url === R + 'chunk') {
      const bad = onChunk ? onChunk(call) : null;
      if (bad) return bad;
      return { body: { uploadId: UPLOAD_ID, received: call.body.offset + decoded(call).length, bytes: BODY.length } };
    }
    if (call.url === R + 'finish') {
      return { body: { ok: true, fileId: FILE_ID, bytes: BODY.length, sha256: SHA, targets: call.body.targets, rev: 42, ms: 12, uploadId: UPLOAD_ID } };
    }
    if (call.url === R + 'cancel') return { body: { ok: true, uploadId: call.body.uploadId, removed: true } };
    return { status: 404, body: { error: 'not-found' } };
  };
}

// ---------------------------------------------------------------------------
// G1 快乐路径：init → chunk × 3 → finish(scope=group)，一行成功文案
// ---------------------------------------------------------------------------

test('G1 group-file：init → chunk × 3 → finish(scope=group)，片数与形状和面板一致', async (t) => {
  const admin = await startAdmin(t, panelChain());
  const out = await runAsync(['group-file', admin.file, '--url', admin.url, '--state-dir', admin.dir]);

  assert.equal(out.status, 0, out.stderr);
  assert.deepEqual(seqOf(admin.seen), [
    'POST ' + R + 'init',
    'POST ' + R + 'chunk', 'POST ' + R + 'chunk', 'POST ' + R + 'chunk',
    'POST ' + R + 'finish',
  ], '请求序列＝面板群上传那一条：init → chunk × N → finish');

  const [init, ...rest] = admin.seen;
  const chunks = rest.slice(0, 3);
  const finish = rest[3];
  assert.deepEqual(init.body, { name: 'payload.bin', bytes: 1300 }, 'init 只报名字与体积，不带路径');
  assert.equal(init.token, TOKEN, '管理接口 token 从 state-dir 读出来带上');
  assert.equal(JSON.stringify(admin.seen.map((call) => ({ url: call.url, body: call.body }))).includes(TOKEN), false,
    'token 只走请求头，绝不进 URL 也不进请求体');

  // G6-1：下面这一条在「循环只发一片」时必红（1300 字节按 512 分片恰好是 3 片）。
  assert.equal(chunks.length, 3, '1300 字节按 512 分片 = 3 片，少一片就说明循环只跑了一次');
  assert.deepEqual(chunks.map((call) => call.body.offset), [0, 512, 1024], 'offset 严格顺序递增，与 received 逐片对齐');
  assert.deepEqual(chunks.map((call) => decoded(call).length), [512, 512, 276], '最后一片按剩余字节截断');
  assert.deepEqual(chunks.map((call) => call.body.uploadId), [UPLOAD_ID, UPLOAD_ID, UPLOAD_ID]);
  assert.deepEqual(Buffer.concat(chunks.map(decoded)), BODY, '三片拼回去就是原文件（base64 一个字节都没错）');

  // G6-2：下面这一条在 finish 少了 scope=group 时必红（deepEqual 逐字比，多一个字段也算红）。
  assert.deepEqual(finish.body, { uploadId: UPLOAD_ID, scope: 'group', targets: 'all' },
    '终点必须是群的 scope=group（缺了它就退回私聊 offer，群文件发不出去）');

  assert.equal(out.stdout.trim(),
    '已发到群 id=' + FILE_ID.slice(0, 8) + ' bytes=1300 sha256=' + SHA.slice(0, 8) + ' targets=all',
    '成功只有这一行：fileId(8) / bytes / sha256(8) / targets');
  assert.equal(out.stdout.trim().split('\n').length, 1, '不许多打第二行');
  assert.match(out.stderr, /发送中 → all · 1300 字节/);
  assert.equal(/文件操作失败/.test(out.stderr), false);
});

// ---------------------------------------------------------------------------
// G2 本地就能拦下的三种文件：一个请求都不发
// ---------------------------------------------------------------------------

test('G2 group-file：找不到 / 目录 / 空文件都在本地拒掉，零请求', async (t) => {
  const admin = await startAdmin(t, panelChain());

  const missing = await runAsync(['group-file', path.join(admin.dir, 'nope.bin'), '--url', admin.url, '--state-dir', admin.dir]);
  assert.equal(missing.status, 1);
  assert.match(missing.stderr, /找不到文件: .*nope\.bin/);

  const dirArg = await runAsync(['group-file', admin.dir, '--url', admin.url, '--state-dir', admin.dir]);
  assert.equal(dirArg.status, 1);
  assert.match(dirArg.stderr, /不是普通文件: /);

  const emptyPath = path.join(admin.dir, 'empty.bin');
  fs.writeFileSync(emptyPath, Buffer.alloc(0));
  const empty = await runAsync(['group-file', emptyPath, '--url', admin.url, '--state-dir', admin.dir]);
  assert.equal(empty.status, 1);
  assert.match(empty.stderr, /文件是空的（0 字节）: /);

  assert.equal(admin.seen.length, 0, '一个 init 都不发');
});

// ---------------------------------------------------------------------------
// G3 中途有一片失败：立刻中止，不发 finish
// ---------------------------------------------------------------------------

test('G3 group-file：某一片 500 → 中止并映射错误，之后没有 finish', async (t) => {
  const admin = await startAdmin(t, panelChain((call) => (call.body.offset >= CHUNK
    ? { status: 500, body: { error: 'upload-chunk-failed' } }
    : null)));
  const out = await runAsync(['group-file', admin.file, '--url', admin.url, '--state-dir', admin.dir]);

  assert.equal(out.status, 1, '500 算失败（exit 1）：它不是「本机现在做不了」那一档');
  assert.match(out.stderr, /文件操作失败: 500 upload-chunk-failed/);
  assert.equal(seqOf(admin.seen).includes('POST ' + R + 'finish'), false, '失败之后绝不再发 finish');
  assert.deepEqual(seqOf(admin.seen), [
    'POST ' + R + 'init', 'POST ' + R + 'chunk', 'POST ' + R + 'chunk', 'POST ' + R + 'cancel',
  ], '第二片就停：init + 两片 + 一次尽力 cancel（幂等接口，退掉临时区）');
  assert.equal(out.stdout, '', '失败不打印成功行');
});

// ---------------------------------------------------------------------------
// G4 --targets 原样透传；缺省 all
// ---------------------------------------------------------------------------

test('G4 group-file：--targets <peer> 原样交给 finish，缺省是 all', async (t) => {
  const named = await startAdmin(t, panelChain());
  const out = await runAsync(['group-file', named.file, '--targets', 'peer-b-1234', '--url', named.url, '--state-dir', named.dir]);
  assert.equal(out.status, 0, out.stderr);
  const finish = named.seen.find((call) => call.url === R + 'finish');
  assert.deepEqual(finish.body, { uploadId: UPLOAD_ID, scope: 'group', targets: 'peer-b-1234' },
    '目标原样透传，CLI 不做名字解析');
  assert.match(out.stdout.trim(), / targets=peer-b-1234$/);

  const bare = await startAdmin(t, panelChain());
  const plain = await runAsync(['group-file', bare.file, '--url', bare.url, '--state-dir', bare.dir]);
  assert.equal(plain.status, 0, plain.stderr);
  assert.equal(bare.seen.find((call) => call.url === R + 'finish').body.targets, 'all', '不带 --targets 就是 all');
  assert.match(plain.stdout.trim(), / targets=all$/);
});

// ---------------------------------------------------------------------------
// G5 帮助与词表：本命令出现在 help（两种语言，en 无中文）
// ---------------------------------------------------------------------------

test('G5 group-file：出现在顶层 help 与自己的 --help 里，两语言齐全且 en 无中文', async (t) => {
  const zhHelp = await runAsync(['group-file', '--help']);
  assert.equal(zhHelp.status, 0);
  assert.match(zhHelp.stdout, /用法: dsh-lan-peers group-file <文件> \[--targets all\|<peerId\|name>\]/);
  assert.match(zhHelp.stdout, /--targets/);

  const zhUsage = await runAsync(['help']);
  assert.match(zhUsage.stdout, /^  group-file <文件> +发进本群/m, '顶层用法表要列出这条命令');

  const enHelp = await runAsync(['group-file', '--help'], { DSH_LAN_PEERS_LANG: 'en' });
  assert.equal(enHelp.status, 0);
  assert.match(enHelp.stdout, /Usage: dsh-lan-peers group-file <file> \[--targets all\|<peerId\|name>\]/);
  assert.doesNotMatch(enHelp.stdout, /[\u4e00-\u9fa5]/, 'en 帮助里不许有中文');

  const enUsage = await runAsync(['help'], { DSH_LAN_PEERS_LANG: 'en' });
  assert.match(enUsage.stdout, /^  group-file <file> +Send one file into this host group/m);

  const zhKeys = new Set(keys('zh'));
  const enKeys = new Set(keys('en'));
  for (const key of ['cli.help.groupFile', 'cli.file.groupFileUsage', 'cli.file.groupSent', 'cli.file.empty', 'cli.file.readFailed']) {
    assert.ok(zhKeys.has(key), 'zh 缺 ' + key);
    assert.ok(enKeys.has(key), 'en 缺 ' + key);
    assert.doesNotMatch(String(text('en', key)), /[\u4e00-\u9fa5]/, 'en 文案不许有中文：' + key);
  }
  assert.match(text('zh', 'cli.file.groupSent'), /\{id\}.*\{bytes\}.*\{sha256\}.*\{targets\}/, '占位符要齐');
  assert.match(text('en', 'cli.file.groupSent'), /\{id\}.*\{bytes\}.*\{sha256\}.*\{targets\}/, '占位符要齐');
});

// ---------------------------------------------------------------------------
// G6 非空断言（这对拍的两条已写在 G1 的 chunk/finish 断言旁）：
//   · 「循环只发一片」→ G1 的 assert.equal(chunks.length, 3) 红；
//   · finish 丢掉 scope=group → G1 的 assert.deepEqual(finish.body, {..., scope:'group', ...}) 红。
// 下面这一条只是把两处锚点的形状再钉一次，防止有人把上面那两条改成「只比前缀」。
// ---------------------------------------------------------------------------

test('G6 非空性锚点：片数断言与 finish 的 scope 断言都在，且比较是逐字的', async (t) => {
  const admin = await startAdmin(t, panelChain());
  await runAsync(['group-file', admin.file, '--url', admin.url, '--state-dir', admin.dir]);
  const chunks = admin.seen.filter((call) => call.url === R + 'chunk');
  const finish = admin.seen.find((call) => call.url === R + 'finish');
  assert.equal(chunks.length > 1, true, '真跑出来是多片：单片跑的循环过不了 G1 的 3 片断言');
  assert.equal(Object.keys(finish.body).sort().join(','), 'scope,targets,uploadId', 'finish 只带这三个键，scope 在');
});
