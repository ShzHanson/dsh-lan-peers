// dsh-lan-peers · 发布纪律守门：版本号在 package.json 与 host/server.mjs 的 PLUGIN_VERSION 上
// 必须**逐字相同**，且必须是 ASCII 的 `X.Y.Z[- prerelease]`（npm 拒收 α 之类非 ASCII）。
// 在此之前这条纪律只靠人肉 grep —— 一漂移就发不出去的包，应当在测试里先炸。
//
// 口径：
//   - PLUGIN_VERSION 走**真 import**（host/server.mjs 结尾有 isMain 门禁，import 只解析不监听，
//     实测 ~44ms 且不落盘/不开端口），比正则抠字面量更硬：抠的是文本，断的是导出值。
//   - 断言 3 走**读源码**而不是 bootstrap：bootstrap 要在 lib/admin-files.test.mjs 里复用
//     stubAdmin + hit 那套 **该文件私有**的桩（约 40 行注入式依赖），照抄进来会让一份版本
//     纪律测试跟着 createAdmin 的 20 参签名一起漂；而 admin 的 version 本来就是运行时从
//     package.json 读的（见下方断言），钉住「派生关系」比采一次样更彻底。
//   - 负向对照只改内存里的字符串，**不写任何文件**。
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { PLUGIN_VERSION } from '../server.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PKG_PATH = path.join(HERE, '..', '..', 'package.json');
const ADMIN_PATH = path.join(HERE, '..', '..', 'lib', 'admin.mjs');

const VERSION_RE = /^\d+\.\d+\.\d+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$/;
const ASCII_RE = /^[\x00-\x7F]+$/;

/** 版本号口径：ASCII + X.Y.Z[-prerelease]（无 +build、无空格、无希腊字母） */
export function isValidVersion(value) {
  return typeof value === 'string' && ASCII_RE.test(value) && VERSION_RE.test(value);
}

test('package.json 的 version 与 host/server.mjs 导出的 PLUGIN_VERSION 逐字相同', () => {
  const pkg = JSON.parse(fs.readFileSync(PKG_PATH, 'utf8'));
  assert.equal(typeof pkg.version, 'string', 'package.json 必须有 version 字段');
  assert.equal(
    pkg.version,
    PLUGIN_VERSION,
    `版本漂移：package.json=${pkg.version} 但 PLUGIN_VERSION=${PLUGIN_VERSION}`,
  );
});

test('版本号是 ASCII 且形如 X.Y.Z[-prerelease]', () => {
  assert.match(PLUGIN_VERSION, VERSION_RE);
  assert.match(PLUGIN_VERSION, ASCII_RE, 'npm 拒收非 ASCII 版本号');
  assert.equal(isValidVersion(PLUGIN_VERSION), true);
});

test('admin bootstrap 报的 version 来自 package.json 运行时读取（不是第二份硬编码）', () => {
  const src = fs.readFileSync(ADMIN_PATH, 'utf8');
  assert.match(
    src,
    /fs\.readFileSync\(new URL\('\.\.\/package\.json', import\.meta\.url\)/,
    'lib/admin.mjs 应运行时读 package.json',
  );
  assert.match(src, /typeof raw\.version === 'string'/, 'version 取自 raw.version');
  assert.doesNotMatch(src, /PLUGIN_VERSION\s*=\s*['"`]/, 'PLUGIN_VERSION 不得硬编码字面量');
});

test('负向对照：把真版本号改成 0.9.0-α（仅内存）后校验器必须返回 false', () => {
  const real = PLUGIN_VERSION;
  const corrupted = `${real}-α`;

  assert.equal(isValidVersion(real), true, '原版必须通过，否则负向对照无意义');
  assert.equal(isValidVersion(corrupted), false, '带希腊字母的版本号必须被拒');
  assert.equal(ASCII_RE.test(corrupted), false, 'ASCII 守门单独也能拦住 α');
  assert.equal(isValidVersion(`${real}+build.1`), false, '+build 元数据不在本口径内');
  assert.equal(isValidVersion(`${real} `), false, '尾随空格必须被拒');
});
