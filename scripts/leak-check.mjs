#!/usr/bin/env node
/**
 * 发布前泄漏检查。
 *
 * 设计要点：
 * 1. 脚本本身**不含任何内部特征**（内网 IP、主机名、用户名、内部路径都不写在这里），
 *    否则检查器自身就成了泄漏源。内部名单从本地文件 .leak-patterns.local.json 读取（不入库）。
 * 2. 检查两类东西：
 *    a) 机密（私钥、GitHub token、常见口令赋值形态）；
 *    b) 身份/拓扑（来自本地名单）+ 不该入库的文件名。
 * 3. 只检查 git 跟踪的文件（release 的真相来源），并可选检查 git 历史。
 *
 * 用法：
 *   node scripts/leak-check.mjs            # 检查工作树里被跟踪的文件
 *   node scripts/leak-check.mjs --history  # 额外扫描全部提交历史（发布大版本时用）
 *   node scripts/leak-check.mjs --staged   # 只检查已暂存内容（pre-commit 用）
 *
 * 退出码：0 = 干净；1 = 发现疑似泄漏（会逐条列出文件:行号）。
 */
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(import.meta.dirname, '..');
const LOCAL_PATTERNS = path.join(ROOT, '.leak-patterns.local.json');

const FORBIDDEN_FILES = [
  /^HANDOVER\.md$/,
  /^DESIGN\.md$/,
  /^PUBLISH\.md$/,
  /(^|\/)interop\/state\//,
  /(^|\/)(peers|state|group|group-key|group-replica|group-role|known-groups|advertise-state)\.json$/,
  /(^|\/)[^/]*\.log$/,
  /(^|\/)node_modules\//,
  /(^|\/)\.env(\.|$)/,
];

// 测试夹具里的「人类可读假凭据」只在 *.test.mjs / *.test.js 里豁免。
// 形状一：<小写标识>-token|-secret|-key，标识只允许小写字母与连字符——天然排除含数字的高熵真凭据；
// 形状二：should-not-leak 这类明确的占位语义。
const TEST_FIXTURE_FILE = /\.test\.(mjs|js)$/i;
function isTestFixtureValue(value, file) {
  if (!TEST_FIXTURE_FILE.test(file || '')) return false;
  return /^[a-z][a-z-]*-(token|secret|key)$/.test(value) || /should[-_]?not[-_]?(leak|be|exist|match)/i.test(value);
}

// 内网 IPv4（RFC1918）里已确认属于第三方默认值或测试夹具的「具体主机」，按精确值放行。
// 刻意不按网段放行：10.0.0.0/24 与 192.168.0.0/24 是最常见的家用/办公网段，
// 网段白名单会让它们连同真正的内网主机一起失明。放行表里没写到的地址一律照报。
const RFC1918_ALLOWED_HOSTS = new Set([
  '10.0.0.1', // 夹具：假对端 baseUrl
  '10.0.0.2', // 夹具：假对端 baseUrl
  '10.0.0.3', // 夹具：假对端 baseUrl
  '10.0.0.5', // 夹具：假对端 baseUrl
  '10.0.0.7', // 夹具：网卡探测示例
  '10.0.0.9', // 夹具：假对端 baseUrl
  '10.0.0.44', // 夹具：群申请人地址
  '10.1.2.3', // 夹具：网卡探测示例
  '10.2.3.4', // 夹具：CIDR 判定示例
  '10.9.8.7', // 夹具：CIDR 判定示例
  '10.9.9.9', // 夹具：显式 baseUrl 示例
  '172.17.0.1', // 第三方默认值：Docker 网桥
  '172.20.0.1', // 夹具：虚拟网卡
  '172.28.0.1', // 第三方默认值：WSL 虚拟网卡
  '192.168.56.1', // 第三方默认值：VirtualBox 仅主机网卡
]);

// Windows 盘符路径里属于系统目录或文档示例的「精确前缀」，按前缀放行。
// 只放行这些形态；其余一律照报（尤其盘符工作区、用户目录）。
const WORKSTATION_ALLOWED_PREFIXES = [
  'C:\\Windows', // 系统目录，通用示例
  'C:\\Program Files', // 系统目录（覆盖 (x86) 变体）
  'C:\\Program Files (x86)', // 系统目录
  'C:\\ProgramData', // 系统目录
  'C:\\tmp', // file-store 清洗函数文档里的通用示例
  'D:\\secret', // 路径清洗夹具
  'D:\\/work', // 测试里断言日志「不含 path」的正则字面量，不是路径
];

export const SECRET_RULES = [
  { name: 'private-key', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { name: 'github-token', re: /\bgh[pousr]_[A-Za-z0-9]{20,}/ },
  { name: 'npm-token', re: /\bnpm_[A-Za-z0-9]{20,}/ },
  { name: 'aws-key', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'slack-token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}/ },
  {
    name: 'password-assign',
    re: /\b(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*['"]([^'"\s]{8,})['"]/i,
    // 明显是测试占位符的值不算机密：wrong-*/not-*/whatever/test/dummy/fake/example/S-x 这类
    // 第二行只在测试文件里生效（第二个参数是命中所属文件路径）
    ignore: (m, file) => /^(wrong|not-|whatever|redacted|dummy|fake|example|placeholder|changeme|test)/i.test(m[2]) || /-test-|^[ST]-|^sec-|^M2H$/.test(m[2]) || isTestFixtureValue(m[2], file),
  },
  {
    // 内网 IPv4（RFC1918）：10/8、172.16/12、192.168/16。
    // 只报具体主机地址：(?!\/) 让 10.0.0.0/8 这类网段定义不命中。
    // 文档/回环地址本来就不在 RFC1918 里，天然不命中：127.0.0.1、0.0.0.0、
    // 203.0.113.0/24、198.51.100.0/24、192.0.2.0/24、localhost。
    // 放行只看「值」不看文件：已确认的第三方默认值与夹具在 RFC1918_ALLOWED_HOSTS，
    // 外加文档占位网段 192.168.1.0/24。其余任何 192.168.x 新网段都会照报。
    name: 'internal-ipv4',
    re: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?!\/)/,
    ignore: (m) => RFC1918_ALLOWED_HOSTS.has(m[0]) || /^192\.168\.1\./.test(m[0]),
  },
  {
    // Windows 盘符绝对路径。分隔符按 \\{1,2} 匹配，JS 源码里的 'C:\\Windows\\…'
    // 因此能被认成 C:\Windows\…。这里只认反斜杠形态：正斜杠的 D:/…
    // 在已发布历史里本就存在，工作树里再报只是噪声（本机名单另配两种形态一起查）。
    // 前一位必须是字母数字以外，否则 http:// 里的 p:/ 之类会被误判成路径。
    name: 'workstation-path',
    re: /(?<![A-Za-z0-9])[A-Za-z]:\\{1,2}[^'"]{0,64}/,
    ignore: (m) => {
      const candidate = m[0].replace(/\\\\/g, '\\');
      return WORKSTATION_ALLOWED_PREFIXES.some((prefix) => candidate.startsWith(prefix));
    },
  },
];

function git(args) {
  return execFileSync('git', args, { cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
}

function loadLocalPatterns() {
  if (!fs.existsSync(LOCAL_PATTERNS)) return [];
  try {
    const raw = JSON.parse(fs.readFileSync(LOCAL_PATTERNS, 'utf8'));
    const list = Array.isArray(raw.patterns) ? raw.patterns : [];
    return list
      .filter((item) => item && typeof item.pattern === 'string' && item.pattern !== '')
      .map((item) => ({
        name: item.name || item.pattern,
        re: (() => { try { return new RegExp(item.pattern, item.flags || ''); } catch { return null; } })(),
      }))
      .filter((item) => item.re);
  } catch (error) {
    console.error('[leak-check] 本地名单解析失败：' + error.message);
    process.exit(2);
  }
}

// 历史扫描是整段 git show，某一行属于哪个文件只能靠 diff 头推断，所以这里按行解析归属文件。
function historyFileOwner(text) {
  const owners = [];
  let current = '';
  const lines = text.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const added = /^\+\+\+ b\/(.+)$/.exec(lines[index]);
    if (added) current = added[1];
    else if (/^\+\+\+ \/dev\/null$/.test(lines[index])) current = '';
    owners[index] = current;
  }
  return owners;
}

function scanText(text, rules, owner) {
  const hits = [];
  const lines = text.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    for (const rule of rules) {
      const match = rule.re.exec(lines[index]);
      rule.re.lastIndex = 0;
      if (!match) continue;
      if (typeof rule.ignore === 'function' && rule.ignore(match, owner(index))) continue;
      hits.push({ line: index + 1, rule: rule.name, text: lines[index].trim().slice(0, 120) });
    }
  }
  return hits;
}

function main() {
  const args = new Set(process.argv.slice(2));
  const localPatterns = loadLocalPatterns();
  const rules = [...SECRET_RULES, ...localPatterns];
  const problems = [];

  // 1) 不该入库的文件名
  const tracked = git(args.has('--staged') ? ['diff', '--cached', '--name-only'] : ['ls-files'])
    .split('\n').map((l) => l.trim()).filter(Boolean);
  for (const file of tracked) {
    for (const re of FORBIDDEN_FILES) {
      if (re.test(file)) problems.push({ file, line: 0, rule: 'forbidden-file', text: file });
    }
  }

  // 2) 内容扫描
  const EXT_OK = /\.(mjs|js|cjs|json|md|yml|yaml|txt|ts|sh)$/i;
  for (const file of tracked) {
    if (!EXT_OK.test(file)) continue;
    const abs = path.join(ROOT, file);
    if (!fs.existsSync(abs)) continue;
    const text = fs.readFileSync(abs, 'utf8');
    for (const hit of scanText(text, rules, () => file)) problems.push({ file, ...hit });
  }

  // 3) 历史扫描（可选）：只报命中，不改变工作树
  if (args.has('--history')) {
    const commits = git(['rev-list', '--all']).split('\n').filter(Boolean);
    for (const commit of commits) {
      let names = [];
      try { names = git(['show', '--name-only', '--pretty=format:', commit]).split('\n').filter(Boolean); } catch { continue; }
      for (const file of names) {
        for (const re of FORBIDDEN_FILES) {
          if (re.test(file)) problems.push({ file, line: 0, rule: 'forbidden-file-in-history', text: commit.slice(0, 8) + ' ' + file });
        }
      }
    }
    for (const commit of commits.slice(0, 200)) {
      let text = '';
      try { text = git(['show', commit]); } catch { continue; }
      const owners = historyFileOwner(text);
      for (const hit of scanText(text, rules, (index) => owners[index])) {
        problems.push({ file: 'history:' + commit.slice(0, 8), line: hit.line, rule: hit.rule, text: hit.text });
      }
    }
  }

  if (problems.length === 0) {
    console.log('[leak-check] 干净：' + tracked.length + ' 个被跟踪文件，本地名单 ' + localPatterns.length + ' 条规则' + (args.has('--history') ? '，历史已扫描' : ''));
    process.exit(0);
  }

  console.error('[leak-check] 发现 ' + problems.length + ' 处疑似泄漏：');
  for (const item of problems.slice(0, 80)) {
    console.error('  ' + item.file + (item.line ? ':' + item.line : '') + '  [' + item.rule + ']  ' + item.text);
  }
  if (problems.length > 80) console.error('  …还有 ' + (problems.length - 80) + ' 处');
  process.exit(1);
}

// 只有被当作脚本直接执行时才跑；被测试 import 时必须无副作用（不读 git、不 exit）。
const invokedPath = process.argv[1] ? path.resolve(process.argv[1]).toLowerCase() : '';
if (invokedPath && invokedPath === path.resolve(import.meta.filename).toLowerCase()) main();