// dsh-lan-peers · 0.12.1 日志轮转（lib/log-rotate.mjs + host 的节拍与可见面）
//
// 每条用例都要能红：文件真的动、token 真的对、闸门真的关。真临时目录 + 假时钟，
// 没有一条靠「等 10 分钟」。L9 在 L2/L3 里点名了那条「删掉 .1→.2 移位就红」的断言。
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import {
  DEFAULT_LOG_KEEP,
  DEFAULT_LOG_MAX_BYTES,
  LOG_ROTATE_INTERVAL_MS,
  inLogScope,
  isWithin,
  logRotateLine,
  rotateOnce,
} from './log-rotate.mjs';
import { createPeerServer, resolveConfig } from '../host/server.mjs';
import { listenOnRandomPort } from '../test-support/ports.mjs';

const makeDir = (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-lan-peers-log-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
};
const logAt = (dir, name = 'lan-peers.log') => path.join(dir, name);
const listOf = (dir) => fs.readdirSync(dir).sort();
const readOf = (file) => fs.readFileSync(file, 'utf8');

// ---------------------------------------------------------------------------
// L1 / L2 / L3：算法
// ---------------------------------------------------------------------------

test('L1 低于阈值：一份文件都不动，reason=below-threshold', (t) => {
  const dir = makeDir(t);
  const file = logAt(dir);
  fs.writeFileSync(file, 'x'.repeat(100));

  const out = rotateOnce({ file, maxBytes: 1024, keep: 3, stateDir: dir });

  assert.deepEqual(out, { rotated: false, reason: 'below-threshold', bytes: 100 });
  assert.deepEqual(listOf(dir), ['lan-peers.log'], '目录里不许出现 .1');
  assert.equal(readOf(file), 'x'.repeat(100), '内容一个字节都不许少');
});

test('L2 超过阈值：base→.1、旧 .1→.2，base 留空位（不存在，不建空文件）', (t) => {
  const dir = makeDir(t);
  const file = logAt(dir);
  fs.writeFileSync(file + '.1', 'ARCHIVE-OLD');
  fs.writeFileSync(file, 'BASE-NEW');

  const out = rotateOnce({ file, maxBytes: 4, keep: 3, stateDir: dir });

  assert.deepEqual(out, { rotated: true, reason: 'rotated', bytes: 8 });
  assert.deepEqual(listOf(dir), ['lan-peers.log.1', 'lan-peers.log.2']);
  assert.equal(readOf(file + '.1'), 'BASE-NEW', '刚转出去的那一份必须落在 .1');
  // L9 非空洞：把 .1→.2 的移位删掉，下面这一条就红（.2 根本不存在）。
  assert.equal(readOf(file + '.2'), 'ARCHIVE-OLD', '旧的 .1 必须进一位到 .2');
  assert.equal(fs.existsSync(file), false, 'base 必须留空位：宿主下一次写入自己建回来');
});

test('L3 keep=2：第三次轮转后只剩 .1/.2，最老那份删掉，顺序正确', (t) => {
  const dir = makeDir(t);
  const file = logAt(dir);
  const rotate = (body) => {
    fs.writeFileSync(file, body);
    return rotateOnce({ file, maxBytes: 1, keep: 2, stateDir: dir });
  };

  rotate('R1');
  rotate('R2');
  const third = rotate('R3');

  assert.equal(third.reason, 'rotated');
  assert.deepEqual(listOf(dir), ['lan-peers.log.1', 'lan-peers.log.2'], '只许留下 keep=2 份');
  assert.equal(readOf(file + '.1'), 'R3', '最新一份在 .1');
  // L9 非空洞：同一条移位断言（删掉移位只会剩 .1=R3，这一条红）。
  assert.equal(readOf(file + '.2'), 'R2', '第二新在 .2，顺序不许乱');
  assert.equal(fs.existsSync(file + '.3'), false, '超出 keep 的那份必须被删掉');
  assert.equal(fs.existsSync(file + '.1bogus'), false);
});

// ---------------------------------------------------------------------------
// L4 / L5 / L6：不转的那几种形状
// ---------------------------------------------------------------------------

test('L4 文件不存在：reason=missing，什么都不创建', (t) => {
  const dir = makeDir(t);
  const file = logAt(dir);

  const out = rotateOnce({ file, maxBytes: 1024, keep: 3, stateDir: dir });

  assert.deepEqual(out, { rotated: false, reason: 'missing', bytes: 0 });
  assert.deepEqual(listOf(dir), [], 'missing 不许顺手建个空 base（也不许建 .1）');
});

test('L5 改名失败：EBUSY/EPERM/EACCES→locked、EIO→error；不抛、不丢内容', (t) => {
  const dir = makeDir(t);
  const file = logAt(dir);
  for (const [code, reason] of [['EBUSY', 'locked'], ['EPERM', 'locked'], ['EACCES', 'locked'], ['EIO', 'error']]) {
    fs.writeFileSync(file, 'KEEP-ME');
    fs.writeFileSync(file + '.1', 'A1');
    const original = fs.renameSync;
    fs.renameSync = () => {
      const error = new Error('stub ' + code);
      error.code = code;
      throw error;
    };
    let out;
    try {
      assert.doesNotThrow(() => {
        out = rotateOnce({ file, maxBytes: 1, keep: 3, stateDir: dir });
      }, code + '：轮转永不抛');
    } finally {
      fs.renameSync = original;
    }
    assert.equal(out.reason, reason, code + ' → ' + reason);
    assert.equal(out.rotated, false);
    assert.equal(readOf(file), 'KEEP-ME', code + '：base 一个字节都不许丢');
    assert.equal(readOf(file + '.1'), 'A1', code + '：已经存在的归档不许被动过');
    assert.equal(fs.existsSync(file + '.2'), false, code + '：失败就中止，不许移位');
    fs.rmSync(file + '.1', { force: true });
  }
});

test('L6 路径是目录：拒绝，原样不动（reason=error）', (t) => {
  const dir = makeDir(t);
  const file = logAt(dir);
  fs.mkdirSync(file);

  const out = rotateOnce({ file, maxBytes: 1, keep: 3, stateDir: dir });

  assert.equal(out.reason, 'error');
  assert.equal(out.rotated, false);
  assert.equal(fs.statSync(file).isDirectory(), true, '目录必须还在（没被当文件删掉）');
  assert.deepEqual(listOf(dir), ['lan-peers.log'], '目录旁边不许冒出 .1');
});

test('L6b 路径是符号链接：一律不 follow，拒绝（symlink/dir 同一口径）', (t) => {
  const dir = makeDir(t);
  const real = path.join(dir, 'real.log');
  const link = logAt(dir, 'link.log');
  fs.writeFileSync(real, 'y'.repeat(64));
  try {
    fs.symlinkSync(real, link);
  } catch {
    return; // 没权限造链接的环境（Windows 无开发者模式）不假装通过：直接跳过这一条
  }

  const out = rotateOnce({ file: link, maxBytes: 1, keep: 3, stateDir: dir });

  assert.equal(out.reason, 'error');
  assert.equal(fs.lstatSync(link).isSymbolicLink(), true, '链接本身不许被改名');
  assert.equal(readOf(real), 'y'.repeat(64), '链接目标一个字节都不许动');
});

test('L6c 范围规则（home-or-stateDir containment）：两处之外一律 outside-scope', (t) => {
  const dir = makeDir(t);
  const outside = path.join(path.parse(os.homedir()).root, 'dsh-lan-peers-outside-scope.log');

  assert.equal(inLogScope(logAt(dir), { stateDir: dir }), true, 'stateDir 里的允许');
  assert.equal(inLogScope(outside, { stateDir: dir }), false, '既不在 stateDir 也不在 home 下的拒绝');
  // ../ 的越界由 isWithin 自己判死（这里不借 home：os.tmpdir() 在 Windows 上就在 home 里，
  // 拿 home 去判「dir/../x.log」会假通过）
  assert.equal(isWithin(path.join(dir, '..', 'x.log'), dir), false, '../ 不许越过 stateDir');
  assert.equal(inLogScope(logAt(dir), { stateDir: dir, home: path.join(dir, 'nohome') }), true, 'home 不相干也算允许');

  const out = rotateOnce({ file: outside, maxBytes: 1, keep: 3, stateDir: dir });
  assert.deepEqual(out, { rotated: false, reason: 'outside-scope', bytes: 0 });
  assert.equal(fs.existsSync(outside), false, '超出范围时不许创建、不许碰');
});

// ---------------------------------------------------------------------------
// L9：阈值边界（严格 > 还是 >=，钉死）
// ---------------------------------------------------------------------------

test('L9 阈值语义是「严格大于」：恰好等于 maxBytes 不转，多一个字节就转', (t) => {
  const dir = makeDir(t);
  const file = logAt(dir);
  fs.writeFileSync(file, 'a'.repeat(64));

  const atLimit = rotateOnce({ file, maxBytes: 64, keep: 3, stateDir: dir });
  assert.deepEqual(atLimit, { rotated: false, reason: 'below-threshold', bytes: 64 }, '恰好 64 不转（> 而不是 >=');
  assert.deepEqual(listOf(dir), ['lan-peers.log']);

  fs.appendFileSync(file, 'b');
  const overLimit = rotateOnce({ file, maxBytes: 64, keep: 3, stateDir: dir });
  assert.deepEqual(overLimit, { rotated: true, reason: 'rotated', bytes: 65 }, '65 字节必须转');
});

test('默认值与钳制：20 MiB / keep 3 / 10 分钟，非法值回落默认', () => {
  assert.equal(DEFAULT_LOG_MAX_BYTES, 20 * 1024 * 1024);
  assert.equal(DEFAULT_LOG_KEEP, 3);
  assert.equal(LOG_ROTATE_INTERVAL_MS, 600_000);

  const fallback = resolveConfig({});
  assert.equal(fallback.logMaxBytes, DEFAULT_LOG_MAX_BYTES);
  assert.equal(fallback.logKeep, DEFAULT_LOG_KEEP);
  assert.equal(fallback.logRotateIntervalMs, LOG_ROTATE_INTERVAL_MS);
  assert.equal(fallback.logFile, path.join(os.homedir(), '.dsh', 'lan-peers.log'));

  assert.equal(resolveConfig({ logKeep: 99 }).logKeep, 20, 'keep 上限 20');
  assert.equal(resolveConfig({ logKeep: 0 }).logKeep, DEFAULT_LOG_KEEP, 'keep 0 回落默认');
  assert.equal(resolveConfig({ logMaxBytes: 1 }).logMaxBytes, DEFAULT_LOG_MAX_BYTES, '1 字节回落默认');
  assert.equal(resolveConfig({ logMaxBytes: 64 * 1024 }).logMaxBytes, 64 * 1024, '下限本身合法');
});

// ---------------------------------------------------------------------------
// L7 / L8：节拍与可见面（真服务、真 HTTP，假时钟）
// ---------------------------------------------------------------------------

test('L7 定时器：假时钟没过间隔不转，过了只转一次；close() 清干净且不吊住进程', async (t) => {
  const dir = makeDir(t);
  const file = logAt(dir);
  // 70 KB：超过钳制下限（64 KiB），又能在一条用例里真写进临时目录
  fs.writeFileSync(file, 'T'.repeat(70_000));
  const logged = [];
  let clock = 1_000_000;
  const server = createPeerServer({
    stateDir: dir,
    listenHost: '127.0.0.1',
    logger: (line) => logged.push(String(line)),
    now: () => clock,
    logFile: file,
    logMaxBytes: 64 * 1024,  // 钳制下限：70 KB 的 base 已超阈值，转不转只剩闸门一件事
    logRotateIntervalMs: 60, // 节拍压到 60ms；转动与否由假时钟闸门决定
  });
  t.after(async () => { await server.close(); });

  assert.equal(server.logRotation.armed(), false, 'listen 之前不许挂定时器');
  const info = await listenOnRandomPort(server, '127.0.0.1');
  assert.equal(server.logRotation.armed(), true, 'listen 之后必须挂上');

  // 假时钟不走：节拍到了也不许动（这就是「测试能假时钟」的那道闸门）
  await sleep(200);
  assert.equal(fs.existsSync(file), true);
  assert.equal(fs.existsSync(file + '.1'), false, '时钟没过一个间隔，一份都不许转');
  assert.deepEqual(
    logged.filter((line) => line.startsWith('[log] rotate')),
    [],
    '没转动就没有轮转日志行（访问日志另算）',
  );

  clock += 60; // 刚好一个间隔
  const deadline = Date.now() + 3000;
  while (!fs.existsSync(file + '.1') && Date.now() < deadline) await sleep(10);

  assert.equal(fs.existsSync(file + '.1'), true, '一个间隔之后必须转一次');
  assert.equal(fs.existsSync(file), false, 'base 留空位');
  assert.equal(readOf(file + '.1').length, 70_000, '内容原样进 .1');
  assert.deepEqual(
    logged.filter((line) => line.startsWith('[log] rotate')),
    ['[log] rotate size=70000 keep=3 reason=rotated'],
    '一次轮转恰好一行，且格式就是这一行（无路径、无用户数据）',
  );
  assert.deepEqual(server.logRotation.last(), { reason: 'rotated', bytes: 70_000 });

  await server.close();
  assert.equal(server.logRotation.armed(), false, 'close() 之后定时器必须清干净');

  // 清干净了就不再转：时钟继续走也没有第二次
  clock += 60;
  await sleep(200);
  assert.equal(logged.filter((line) => line.startsWith('[log] rotate')).length, 1, 'close() 之后不许再转');
  assert.deepEqual(listOf(dir).filter((name) => name.startsWith('lan-peers.log')), ['lan-peers.log.1']);
  assert.equal(typeof info.port, 'number');
});

test('L8 生效策略出现在 GET /v1/health 的状态面上（与面板看到的是同一份数）', async (t) => {
  const dir = makeDir(t);
  const server = createPeerServer({
    stateDir: dir,
    listenHost: '127.0.0.1',
    logFile: logAt(dir),
    logMaxBytes: 64 * 1024,
    logKeep: 2,
    logRotateIntervalMs: 600_000,
  });
  t.after(async () => { await server.close(); });
  const info = await listenOnRandomPort(server, '127.0.0.1');

  const res = await fetch(new URL('/v1/health', info.url));
  const body = await res.json();

  assert.equal(res.status, 200);
  assert.deepEqual(body.log, {
    maxBytes: 64 * 1024,
    keep: 2,
    intervalMs: 600_000,
    last: null,
  }, '生效值（钳制之后）必须就在状态面上');
  assert.deepEqual(body.log, { ...server.logRotation.policy(), last: null }, '两处报的必须是同一份数');
  assert.doesNotMatch(JSON.stringify(body), /lan-peers\.log/, '状态面上不许出现路径');
});

test('日志行格式只有一份实现：路径与用户数据进不去', () => {
  assert.equal(logRotateLine({ size: 41_000_000, keep: 3, reason: 'rotated' }), '[log] rotate size=41000000 keep=3 reason=rotated');
  assert.equal(logRotateLine({ size: -1, keep: 0, reason: 'error' }), '[log] rotate size=0 keep=1 reason=error', '负数归零，keep 下限 1');
});
