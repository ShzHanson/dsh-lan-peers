// dsh-lan-peers · 发布纪律守门：版本号在 package.json 与 host/server.mjs 的 PLUGIN_VERSION 上
// 必须**逐字相同**。在此之前这条纪律只靠人肉 grep —— 一漂移就发不出去的包，应当在测试里先炸。
//
// 口径（2026-11-13 第二次修正）：版本号必须**纯 ASCII**，发布态与开发态共用同一把尺。
//   - 发布态：`X.Y.Z`；
//   - 开发态：`X.Y.Z-<ASCII prerelease>`，例如 `0.12.0-alpha`、`0.12.0-alpha.1`。
// 第一次修正按 §0.4 原文放行希腊字母 α（`X.Y.Z-α`）并拒绝其它开发后缀，理由是「未发布一律带 α」。
// 这条口径在**打包**上直接炸了：`package.json` 里非 ASCII 的 version 会让 **pnpm 报错**，连带把
// **依赖本插件的其它插件**的更新一起堵死（npm 侧同样拒收非 ASCII 的 prerelease）。所以 α 这个特例
// 被删掉：守卫要守的从来不是「某一种写法」，而是**版本号里不许出现能弄坏包管理器的字符**。
// 落成两条就是 —— ASCII prerelease 全放行；非 ASCII 一律拒。
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

/** 版本形态：纯 ASCII 的 X.Y.Z[-prerelease]（无 +build、无空格） */
const RELEASE_RE = /^\d+\.\d+\.\d+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$/;
/** 非 ASCII 一律非法：α 这类字符就是 pnpm/npm 报错的那一颗种子 */
const ASCII_RE = /^[\x00-\x7F]+$/;

/** 版本号口径：纯 ASCII 的 semver（开发态的 `-alpha`/`-alpha.1` 与发布态同一把尺，非 ASCII 一律非法） */
export function isValidVersion(value) {
  if (typeof value !== 'string') return false;
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

test('版本号是纯 ASCII 的 semver（X.Y.Z 或 X.Y.Z-<ASCII prerelease>）', () => {
  assert.equal(isValidVersion(PLUGIN_VERSION), true, `非法版本号：${PLUGIN_VERSION}`);
  assert.match(PLUGIN_VERSION, /^\d+\.\d+\.\d+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$/);
  assert.match(PLUGIN_VERSION, ASCII_RE, '版本号必须是纯 ASCII —— 非 ASCII 会让 pnpm 报错');
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

test('负向对照：ASCII prerelease 全放行，非 ASCII 与畸形形态一律拒（仅内存，不写文件）', () => {
  const real = PLUGIN_VERSION;

  assert.equal(isValidVersion(real), true, '原版必须通过，否则负向对照无意义');

  // 开发态 = ASCII prerelease：这是本修正放行的东西
  assert.equal(isValidVersion('0.12.0-alpha'), true, '开发态 0.12.0-alpha 必须放行');
  assert.equal(isValidVersion('0.12.0-alpha.1'), true, '多段 ASCII prerelease 同样合法');
  assert.equal(isValidVersion('1.2.3-rc.2'), true, '任意 ASCII prerelease 标识都合法');
  assert.equal(isValidVersion('0.12.0'), true, '正式发布号合法');
  // 原先的 α 特例已废除：非 ASCII 现在**正是**要拒的东西（pnpm 就是被它弄坏的）
  assert.equal(isValidVersion('0.12.0-α'), false, '希腊字母 α 现在必须被拒：它就是 pnpm 报错的原因');
  assert.equal(isValidVersion('0.10.0-α'), false, '历史形态 0.10.0-α 同样拒（不再有开发态特例）');
  assert.equal(isValidVersion('0.12.0-β'), false, '其余非 ASCII 字母必须被拒');
  assert.equal(isValidVersion('0.12.0-alpha-α'), false, 'ASCII 里混进非 ASCII 必须被拒');
  assert.equal(ASCII_RE.test('0.12.0-α'), false, 'ASCII 守门单独也能拦住 α');
  // 畸形 ASCII 形态：仍拒
  assert.equal(isValidVersion('0.12.0-alpha_beta'), false, '下划线不是 semver prerelease 字符');
  assert.equal(isValidVersion('0.12.0-alpha 1'), false, '空格必须被拒');
  assert.equal(isValidVersion(`${real}+build.1`), false, '+build 元数据不在本口径内');
  assert.equal(isValidVersion(`${real} `), false, '尾随空格必须被拒');
  assert.equal(isValidVersion('0.10'), false, 'X.Y 不是本项目的版本形态');
});
