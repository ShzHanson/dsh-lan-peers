// dsh-lan-peers · 日志轮转：纯逻辑 + fs，**没有任何定时器**（节拍在 host/server.mjs）。
//
// 背景（实测）：<home>/.dsh/lan-peers.log 曾长到 41 MB 且从未轮转。这个文件是插件自己写的
// （lib/index.js 的面包屑与 log() 落点），而且每次写都 open-append-close，没有持久 fd。
// 因此「改名 + 留空位」是安全的：rename 之后 base 不存在，下一次写入自己把它建回来。
// Windows 上文件可能被别的进程独占，rename 会 EBUSY/EPERM/EACCES —— 那就静默跳过
// （reason='locked'），等下一个节拍再看，**绝不在这里重试**。
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/** 超阈值线（严格大于才转）：20 MiB */
export const DEFAULT_LOG_MAX_BYTES = 20 * 1024 * 1024;
/** 保留几份归档（.1 .. .N） */
export const DEFAULT_LOG_KEEP = 3;
/** 轮转节拍：10 分钟 */
export const LOG_ROTATE_INTERVAL_MS = 10 * 60 * 1000;

/** logMaxBytes 的钳制区间：64 KiB .. 4 GiB（再小就每分钟都在转，再大就没有意义） */
export const LOG_MAX_BYTES_MIN = 64 * 1024;
export const LOG_MAX_BYTES_MAX = 4 * 1024 * 1024 * 1024;
/** logKeep 的钳制区间：1 .. 20 份 */
export const LOG_KEEP_MIN = 1;
export const LOG_KEEP_MAX = 20;
/** 节拍钳制区间：20 ms .. 24 h（下限这么小只为测试能压到毫秒级；生产用默认 10 分钟） */
export const LOG_ROTATE_INTERVAL_MIN_MS = 20;
export const LOG_ROTATE_INTERVAL_MAX_MS = 24 * 60 * 60 * 1000;

/**
 * child 是否落在 parent 里（含相等）。用 path.relative 判「..」而不是字符串前缀，
 * 这样 /home/a 与 /home/ab 不会互相冒充；Windows 的盘符大小写由 path.win32 自己归一。
 */
export function isWithin(child, parent) {
  const from = path.resolve(String(parent));
  const to = path.resolve(String(child));
  if (from === to) return true;
  const rel = path.relative(from, to);
  return rel !== '' && rel !== '..' && !rel.startsWith('..' + path.sep) && !path.isAbsolute(rel);
}

/**
 * 范围规则（本模块实现的唯一一条）：**home-or-stateDir containment** ——
 * 只允许转 <stateDir> 里的文件，或 <home>（默认 os.homedir()）下面的文件；其余一律
 * outside-scope。理由：运维手填的路径若指到 /etc 或 C:\\Windows，一个 rename 就是事故。
 */
export function inLogScope(file, { stateDir = '', home = os.homedir() } = {}) {
  const target = typeof file === 'string' ? file : '';
  if (target.trim() === '') return false;
  if (stateDir !== '' && isWithin(target, stateDir)) return true;
  return isWithin(target, home);
}

/** 唯一的日志行格式：size / keep / reason，不出路径、不出用户数据。 */
export function logRotateLine({ size = 0, keep = DEFAULT_LOG_KEEP, reason = 'error' } = {}) {
  const n = Number.isFinite(Number(size)) ? Math.max(0, Math.floor(Number(size))) : 0;
  const k = Number.isFinite(Number(keep)) ? Math.max(1, Math.floor(Number(keep))) : DEFAULT_LOG_KEEP;
  return '[log] rotate size=' + n + ' keep=' + k + ' reason=' + String(reason);
}

/** EBUSY/EPERM/EACCES = 被占（Windows 常态）；ENOENT 单独说成 missing；其余一律 error。 */
function reasonOf(error, { missing = 'missing', fallback = 'error' } = {}) {
  const code = String(error?.code ?? '');
  if (code === 'ENOENT') return missing;
  if (code === 'EBUSY' || code === 'EPERM' || code === 'EACCES') return 'locked';
  return fallback;
}

/** 删一个归档；不存在算成功。返回 false 表示这次删除真失败了（不抛）。 */
function unlinkQuiet(file) {
  try {
    fs.unlinkSync(file);
    return true;
  } catch (error) {
    return String(error?.code ?? '') === 'ENOENT';
  }
}

/**
 * 转一次。永不抛：每个失败都落到 reason 上，'locked' 就是「跳过、别重试」。
 *
 * 步骤：① 删掉 keep 之外的归档（.N+1、.N+2 …，上一轮 keep 更大时会残留）；
 * ② 从高到低移位 .keep-1→.keep … .1→.2（最高那一份超界，直接删）；
 * ③ base → .1。移位任一步失败就中止，base 一个字节都不动（Nothing lost）。
 *
 * **base 转完是「不存在」，不建空文件**：宿主是 per-write open-append（NAS 上无持久 fd），
 * 下一次写入会自己创建它；预先建一个 0 字节文件只会多一次写竞争，还会让运维误以为
 * 「文件在、但日志没了」。
 *
 * 符号链接：用 lstat 判类型，symlink 与目录、设备一样被拒（reason='error'）——绝不 follow，
 * 否则一个指向 /etc 的链接就能把范围规则绕过去。运维得手工把链接换成真文件。
 *
 * @returns {{rotated: boolean, reason: 'below-threshold'|'missing'|'locked'|'rotated'|'error'|'outside-scope', bytes: number}}
 */
export function rotateOnce({
  file,
  maxBytes = DEFAULT_LOG_MAX_BYTES,
  keep = DEFAULT_LOG_KEEP,
  stateDir = '',
  home = os.homedir(),
} = {}) {
  const target = typeof file === 'string' ? file.trim() : '';
  if (target === '') return { rotated: false, reason: 'error', bytes: 0 };
  if (!inLogScope(target, { stateDir, home })) return { rotated: false, reason: 'outside-scope', bytes: 0 };

  const resolved = path.resolve(target);
  const limit = Number.isFinite(Number(maxBytes)) && Number(maxBytes) > 0
    ? Math.floor(Number(maxBytes))
    : DEFAULT_LOG_MAX_BYTES;
  const depth = Number.isFinite(Number(keep)) && Number(keep) >= 1
    ? Math.floor(Number(keep))
    : DEFAULT_LOG_KEEP;

  let stat;
  try {
    stat = fs.lstatSync(resolved);
  } catch (error) {
    return { rotated: false, reason: reasonOf(error), bytes: 0 };
  }
  // 目录 / 符号链接 / 设备：一律不碰（base 本身是否普通文件由这一条判死）
  if (!stat.isFile()) return { rotated: false, reason: 'error', bytes: Number(stat.size) || 0 };

  const bytes = Number(stat.size) || 0;
  // 阈值语义钉死：**严格大于**才转。恰好等于 maxBytes 属于 below-threshold。
  if (bytes <= limit) return { rotated: false, reason: 'below-threshold', bytes };

  try {
    // ① 扫掉 keep 之外的残留归档（上一轮 keep 更大，或有人手工放过 .7）
    const dir = path.dirname(resolved);
    const base = path.basename(resolved);
    const pattern = new RegExp('^' + base.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\.(\\d+)$');
    let entries = [];
    try {
      entries = fs.readdirSync(dir);
    } catch {
      entries = [];
    }
    for (const entry of entries) {
      const match = pattern.exec(entry);
      if (match && Number(match[1]) > depth) unlinkQuiet(path.join(dir, entry));
    }

    // ② 从高到低移位：最高那份超界删掉，其余各进一位
    for (let index = depth; index >= 1; index -= 1) {
      const from = resolved + '.' + index;
      if (index === depth) {
        unlinkQuiet(from);
        continue;
      }
      if (!fs.existsSync(from)) continue;
      try {
        fs.renameSync(from, resolved + '.' + (index + 1));
      } catch (error) {
        // 移位失败就中止：base 还没动，一份内容都没丢
        return { rotated: false, reason: reasonOf(error), bytes };
      }
    }

    // ③ base → .1，然后 base 留空位（不建空文件）
    try {
      fs.renameSync(resolved, resolved + '.1');
    } catch (error) {
      return { rotated: false, reason: reasonOf(error, { missing: 'missing' }), bytes };
    }
    return { rotated: true, reason: 'rotated', bytes };
  } catch {
    // 兜底：任何出乎意料的东西都不许把服务打崩
    return { rotated: false, reason: 'error', bytes };
  }
}
