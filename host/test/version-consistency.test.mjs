// dsh-lan-peers · 发布纪律守门：版本号在 package.json 与 host/server.mjs 的 PLUGIN_VERSION 上
// 必须**逐字相同**。在此之前这条纪律只靠人肉 grep —— 一漂移就发不出去的包，应当在测试里先炸。
//
// 口径（2026-11-10 修正）：§0.4 规定「未发布一律带希腊字母 α，发布时才去字母」。所以合法形态是**两种**：
//   - 开发态：`X.Y.Z-α`，且**只认 α 这一个**受认可的开发后缀（`-β`、`-α1` 之类一律拒）；
//   - 发布态：`X.Y.Z` 或 `X.Y.Z-<ASCII prerelease>`（npm 拒收非 ASCII，所以发布态必须纯 ASCII）。
// 初版守卫写成「一律 ASCII」，结果把项目自己的 `0.10.0-α` 判成非法——守卫拦住了它本该放行的东西，
// 这里按 §0.4 原文修回。
//
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

/** 发布态：纯 ASCII 的 X.Y.Z[-prerelease]（无 +build、无空格） */
const RELEASE_RE = /^\d+\.\d+\.\d+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$/;
/** 开发态：只认 §0.4 指定的希腊字母 α */
const DEV_RE = /^\d+\.\d+\.\d+-α$/;
const ASCII_RE = /^[\x00-\x7F]+$/;

/** 版本号口径：发布态 ASCII semver，或开发态 `X.Y.Z-α`（别的非 ASCII 一律非法） */
export function isValidVersion(value) {
  if (typeof value !== 'string') return false;
  if (DEV_RE.test(value)) return true;
  return ASCII_RE.test(value) && RELEASE_RE.test(value);
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

test('版本号是发布态 ASCII semver 或开发态 X.Y.Z-α', () => {
  assert.equal(isValidVersion(PLUGIN_VERSION), true, `非法版本号：${PLUGIN_VERSION}`);
  assert.match(PLUGIN_VERSION, /^\d+\.\d+\.\d+(-[0-9A-Za-z][0-9A-Za-z.-]*|-α)?$/);
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

test('负向对照：只放行 α，其余非 ASCII 与非法形态一律拒（仅内存，不写文件）', () => {
  const real = PLUGIN_VERSION;

  assert.equal(isValidVersion(real), true, '原版必须通过，否则负向对照无意义');

  // 开发态：α 是唯一受认可的后缀
  assert.equal(isValidVersion('0.10.0-α'), true, '开发态 0.10.0-α 必须放行');
  assert.equal(isValidVersion('1.2.3-α'), true, '任意数字位 + α 都合法');
  // 其余非 ASCII 与错误形态：拒
  assert.equal(isValidVersion('0.10.0-β'), false, '非 α 的希腊字母必须被拒');
  assert.equal(isValidVersion('0.10.0-α1'), false, 'α 后面不许再跟东西');
  assert.equal(isValidVersion('0.10.0-alpha-α'), false, '混拼形态必须被拒');
  assert.equal(ASCII_RE.test('0.10.0-β'), false, 'ASCII 守门单独也能拦住 β');
  assert.equal(isValidVersion(`${real}+build.1`), false, '+build 元数据不在本口径内');
  assert.equal(isValidVersion(`${real} `), false, '尾随空格必须被拒');
  assert.equal(isValidVersion('0.10'), false, 'X.Y 不是本项目的版本形态');
});
