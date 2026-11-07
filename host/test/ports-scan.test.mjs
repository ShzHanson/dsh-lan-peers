// dsh-lan-peers · 防回归：测试里不许再出现裸 listen( 0 )
//
// 背景（这个坑已经复现三次，每次都是「不知为什么红」）：
//   - 6000（X11）：cli-files 一条用例莫名其妙「连不上管理接口」；
//   - 6697（IRCS-over-TLS）：同一条用例又红一次；
//   - 4190：第三次。
// 根因是 undici/fetch 拒绝 WHATWG 的 bad port 列表，而 listen( 0 ) 让操作系统随便发一个端口。
// 机制早就有（test-support/ports.mjs 的 listenOnRandomPort：静态表快筛 + 真 fetch 自证），
// 只是没有被所有测试采用 —— 所以这里在源码层把它钉死：谁再写回裸 listen( 0 )，这条就红，
// 并且报错直接点名「文件:行」，不用再靠猜。
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const SKIP_DIRS = new Set(['node_modules', '.git', 'tmp', '.tmp']);
// 白名单留空：一个端口助手已经覆盖全部场景，没有「这一处可以例外」的理由。
const ALLOWLIST = [];

function testFiles(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      testFiles(path.join(dir, entry.name), out);
    } else if (entry.name.endsWith('.test.mjs')) {
      out.push(path.join(dir, entry.name));
    }
  }
  return out;
}

test('任何 *.test.mjs 都不许裸 listen( 0 )：一律用 test-support/ports.mjs 的助手', () => {
  const files = testFiles(ROOT).sort();
  assert.ok(files.length >= 20, '测试文件不该这么少，扫到的: ' + files.length);

  const hits = [];
  for (const file of files) {
    const rel = path.relative(ROOT, file).split(path.sep).join('/');
    const lines = fs.readFileSync(file, 'utf8').split('\n');
    lines.forEach((line, index) => {
      if (/\.listen\(\s*0\b/.test(line)) hits.push(rel + ':' + (index + 1) + ' -> ' + line.trim());
    });
  }
  const unexplained = hits.filter((hit) => !ALLOWLIST.some((prefix) => hit.startsWith(prefix)));
  assert.deepEqual(ALLOWLIST, [], '白名单必须为空：有例外就明说，别藏在断言里');
  assert.deepEqual(
    unexplained,
    [],
    '裸 listen( 0 ) 会被操作系统分到 fetch 黑名单端口（6000/4190/6697/10080…），\n'
      + '改成 await listenOnRandomPort(server)（test-support/ports.mjs）：\n'
      + unexplained.join('\n'),
  );
});

test('端口黑名单只有一份实现：helpers 只 re-export，不另抄一份', () => {
  const ports = fs.readFileSync(path.join(ROOT, 'test-support/ports.mjs'), 'utf8');
  assert.match(ports, /export const FETCH_BLOCKED_PORTS = new Set\(\[/, 'test-support/ports.mjs 必须是唯一实现');
  assert.match(ports, /export async function listenOnRandomPort\(/, '必须导出 listenOnRandomPort');

  const helpers = fs.readFileSync(path.join(ROOT, 'host/test/helpers.mjs'), 'utf8');
  assert.match(helpers, /from '..\/..\/test-support\/ports\.mjs'/, 'helpers.mjs 必须从 test-support/ports.mjs 取');
  assert.doesNotMatch(helpers, /FETCH_BLOCKED_PORTS = new Set\(/, 'helpers.mjs 不许再抄一份黑名单');
  assert.doesNotMatch(helpers, /export async function listenOnRandomPort\(/, 'helpers.mjs 不许再实现一份');
});
