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

const SECRET_RULES = [
  { name: 'private-key', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { name: 'github-token', re: /\bgh[pousr]_[A-Za-z0-9]{20,}/ },
  { name: 'npm-token', re: /\bnpm_[A-Za-z0-9]{20,}/ },
  { name: 'aws-key', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'slack-token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}/ },
  {
    name: 'password-assign',
    re: /\b(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*['"]([^'"\s]{8,})['"]/i,
    // 明显是测试占位符的值不算机密：wrong-*/not-*/whatever/test/dummy/fake/example/S-x 这类
    ignore: (m) => /^(wrong|not-|whatever|redacted|dummy|fake|example|placeholder|changeme|test)/i.test(m[2]) || /-test-|^[ST]-|^sec-|^M2H$/.test(m[2]),
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

function scanText(text, rules) {
  const hits = [];
  const lines = text.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    for (const rule of rules) {
      const match = rule.re.exec(lines[index]);
      rule.re.lastIndex = 0;
      if (!match) continue;
      if (typeof rule.ignore === 'function' && rule.ignore(match)) continue;
      hits.push({ line: index + 1, rule: rule.name, text: lines[index].trim().slice(0, 120) });
    }
  }
  return hits;
}

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
  for (const hit of scanText(text, rules)) problems.push({ file, ...hit });
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
    for (const hit of scanText(text, rules)) {
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