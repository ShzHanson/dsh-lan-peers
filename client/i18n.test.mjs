// dsh-lan-peers · v0.8.5-α §0.7b 中英双语（词表 + CLI --lang + 配置旋钮）。
//
// 三条底线一起验：语言只影响「人看的文案」，稳定标识（命令名/参数名/退出码/HTTP 状态码/
// 协议 reason）与日志格式在任何语言下都不变；缺 key 只回落、绝不抛错。
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { LANGS, keys, resolveLang, t } from '../lib/i18n.mjs';
import { resolveConfig } from '../host/server.mjs';
import { makeTempStateDir, peerFixture, request, seedPeers, startServer } from '../host/test/helpers.mjs';

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), 'cli.mjs');
const CJK = /[\u4e00-\u9fff]/;

function run(args, env = {}) {
  return new Promise((resolve) => {
    execFile(process.execPath, [CLI, ...args], { encoding: 'utf8', env: { ...process.env, ...env } },
      (error, stdout, stderr) => resolve({ status: error ? error.code : 0, stdout, stderr }));
  });
}

function withEnv(value, fn) {
  const saved = process.env.DSH_LAN_PEERS_LANG;
  if (value === undefined) delete process.env.DSH_LAN_PEERS_LANG;
  else process.env.DSH_LAN_PEERS_LANG = value;
  try {
    return fn();
  } finally {
    if (saved === undefined) delete process.env.DSH_LAN_PEERS_LANG;
    else process.env.DSH_LAN_PEERS_LANG = saved;
  }
}

// ---------------------------------------------------------------------------
// resolveLang：配置 > 环境变量 > 系统语言 > zh
// ---------------------------------------------------------------------------

test('resolveLang：zh/en 直用，auto、缺失、非法值都交给探测', () => {
  withEnv('en', () => {
    assert.equal(resolveLang({ lang: 'zh' }), 'zh', '显式配置压过环境变量');
    assert.equal(resolveLang({ lang: 'en' }), 'en');
    assert.equal(resolveLang({ lang: 'EN' }), 'en', '大小写不敏感');
    assert.equal(resolveLang({ lang: 'auto' }), 'en', 'auto 读环境变量');
    assert.equal(resolveLang({}), 'en', '缺失也走探测');
    assert.equal(resolveLang({ lang: 'klingon' }), 'en', '非法值按 auto 处理，不抛错');
    assert.equal(resolveLang('en'), 'en', '也接受裸字符串');
  });
  withEnv('zh', () => {
    assert.equal(resolveLang({ lang: 'auto' }), 'zh');
    assert.equal(resolveLang({ lang: 'fr' }), 'zh');
  });
});

test('resolveLang：结果永远落在 LANGS 里，环境变量缺省时回落系统语言或 zh', () => {
  assert.deepEqual(LANGS, ['zh', 'en']);
  withEnv(undefined, () => {
    // 系统语言可以是任意值（本机 zh-CN、CI 可能 en-US）：只要求结果合法，绝不出现第三种取值
    assert.ok(LANGS.includes(resolveLang({ lang: 'auto' })));
    assert.ok(LANGS.includes(resolveLang({})));
  });
  withEnv('zh-CN', () => {
    assert.equal(resolveLang({ lang: 'auto' }), 'zh', '带地区后缀也算命中');
  });
});

// ---------------------------------------------------------------------------
// t：插值 + 回落
// ---------------------------------------------------------------------------

test('t：按语言取文案，params 做 {name} 插值', () => {
  assert.equal(t('zh', 'cli.pair.ok', { label: '书房', peerId: 'peer-b', transport: 'ECDH 两轮' }),
    '已配对: 书房 (peer-b) · ECDH 两轮');
  assert.equal(t('en', 'cli.pair.ok', { label: 'nas', peerId: 'peer-a', transport: 'ECDH two rounds' }),
    'paired: nas (peer-a) · ECDH two rounds');
  assert.match(t('en', 'cli.code.ok', { code: '123456' }), /123456/);
  // 没给的占位符原样保留：宁可露出一处 {peerId}，也不抛错、不拼出半句话
  assert.equal(t('zh', 'cli.pair.ok', { label: 'x' }), '已配对: x ({peerId}) · {transport}');
  // 没有 params 时不做任何替换
  assert.equal(t('zh', 'cli.group.acceptOn'), '接单中');
});

test('t：缺 key 回落英文，两格都缺则原样返回 key 且不抛错', () => {
  // 语言中立标记只写在英文格，中文格靠回落取到（这也是回落链的活体证据）
  assert.deepEqual(keys('en').filter((key) => !keys('zh').includes(key)), ['cli.group.degraded']);
  assert.equal(t('zh', 'cli.group.degraded'), '  [degraded]');
  assert.equal(t('en', 'cli.group.degraded'), '  [degraded]');
  // 两格都没有：返回 key 本身，不抛错（否则用户看到的是崩溃而不是英文）
  for (const lang of LANGS) {
    assert.equal(t(lang, 'cli.no.such.key'), 'cli.no.such.key');
    assert.equal(t(lang, 'cli.no.such.key', { anything: 'x' }), 'cli.no.such.key');
  }
  assert.equal(t('de', 'cli.pair.ok'), '已配对: {label} ({peerId}) · {transport}', '未知语言落回默认格');
});

// ---------------------------------------------------------------------------
// CLI：--lang 压过配置与探测
// ---------------------------------------------------------------------------

test('CLI --lang en：每个子命令的帮助全英文（无一个汉字）', async () => {
  const commands = ['code', 'pair', 'peers', 'ask', 'events', 'unpair', 'group', 'dm', 'send-file', 'inbox'];
  const root = await run(['--help', '--lang', 'en']);
  assert.equal(root.status, 0);
  assert.match(root.stdout, /Usage: dsh-lan-peers <subcommand> \[options\]/);
  assert.doesNotMatch(root.stdout, CJK, '根帮助里不该再有汉字');

  for (const command of commands) {
    const out = await run([command, '--help', '--lang', 'en']);
    assert.equal(out.status, 0, command + ': ' + out.stderr);
    assert.ok(out.stdout.includes('Usage: dsh-lan-peers'), command + ' 的英文帮助缺 Usage 行');
    assert.doesNotMatch(out.stdout, CJK, command + ' 的英文帮助里仍有汉字: ' + out.stdout);
  }
});

test('CLI --lang zh：同一批帮助仍是中文（词表回退不吞掉母语）', async () => {
  const commands = ['code', 'pair', 'peers', 'ask', 'events', 'unpair', 'group', 'dm', 'send-file', 'inbox'];
  for (const command of commands) {
    const out = await run([command, '--help', '--lang', 'zh']);
    assert.equal(out.status, 0, command + ': ' + out.stderr);
    assert.ok(out.stdout.includes('用法: dsh-lan-peers'), command + ' 的中文帮助缺用法行');
    assert.match(out.stdout, CJK);
  }
});

// ---------------------------------------------------------------------------
// 同一个错误在两种语言下
// ---------------------------------------------------------------------------

test('同一个错误在两种语言下：文案翻译，稳定标识与退出码不变', async () => {
  const dir = makeTempStateDir();

  const zh = await run(['unpair', '--peer', 'ghost-node', '--state-dir', dir, '--lang', 'zh']);
  const en = await run(['unpair', '--peer', 'ghost-node', '--state-dir', dir, '--lang', 'en']);
  assert.equal(zh.status, 2, '找不到对端是 exit 2，与语言无关');
  assert.equal(en.status, 2);
  assert.match(zh.stderr, /未知对端: ghost-node/);
  assert.match(en.stderr, /unknown peer: ghost-node/);
  assert.match(zh.stderr, /用法: dsh-lan-peers unpair --peer/);
  assert.match(en.stderr, /Usage: dsh-lan-peers unpair --peer/);
  for (const out of [zh, en]) {
    assert.ok(out.stderr.includes('ghost-node'), 'peerId 是稳定标识，任何语言都原样出现');
    assert.ok(out.stderr.includes('--state-dir'), '参数名不翻译');
    assert.ok(out.stderr.includes('/v1/unpair'), '协议路径不翻译');
  }

  const usageZh = await run(['inbox', 'accept', '--state-dir', dir, '--lang', 'zh']);
  const usageEn = await run(['inbox', 'accept', '--state-dir', dir, '--lang', 'en']);
  assert.equal(usageZh.status, 1, '缺 id 是用法错误 exit 1，与语言无关');
  assert.equal(usageEn.status, 1);
  assert.match(usageZh.stderr, /用法: dsh-lan-peers inbox accept <id>/);
  assert.match(usageEn.stderr, /Usage: dsh-lan-peers inbox accept <id>/);
});

// ---------------------------------------------------------------------------
// 日志与配置
// ---------------------------------------------------------------------------

test('日志不受语言影响：同一请求在 zh/en 配置下写出同样的行', async (t) => {
  const capture = async (lang) => {
    const lines = [];
    const stateDir = makeTempStateDir();
    const peer = peerFixture('peer-a');
    seedPeers(stateDir, [peer]);
    const { baseUrl } = await startServer(t, { stateDir, lang, logger: (line) => lines.push(String(line)) });
    const res = await request(baseUrl, { path: '/v1/peers', peerId: peer.peerId, secret: peer.inboundSecret });
    assert.equal(res.status, 200);
    return lines.filter((line) => line.includes('/v1/peers'));
  };

  const zh = await capture('zh');
  const en = await capture('en');
  assert.ok(zh.length >= 1 && en.length >= 1, '应有请求日志');
  // 时间戳/条数这类数字两边都会变，按形状比；文字部分必须逐字相同
  const shape = (list) => list.map((line) => line.replace(/\d+/g, 'N'));
  assert.deepEqual(shape(en), shape(zh), '日志格式不随语言变化');
  const joined = zh.join('\n');
  assert.match(joined, /\/v1\/peers/, '路径是稳定标识');
  assert.match(joined, /200/);
  assert.match(joined, /peer=peer-a/);
});

test('resolveConfig：lang 默认 auto，只认 zh/en，其余回落 auto', () => {
  assert.equal(resolveConfig({}).lang, 'auto');
  assert.equal(resolveConfig({ lang: 'zh' }).lang, 'zh');
  assert.equal(resolveConfig({ lang: 'en' }).lang, 'en');
  assert.equal(resolveConfig({ lang: 'auto' }).lang, 'auto');
  for (const junk of ['klingon', 'ZH', '', null, 42, {}]) {
    assert.equal(resolveConfig({ lang: junk }).lang, 'auto', '非法 lang 回落 auto: ' + String(junk));
  }
});
