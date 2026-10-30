#!/usr/bin/env node
/**
 * dsh-lan-peers . 新旧互通 harness（黑盒 / 真实进程）
 * =================================================
 *
 * 起两个真进程：旧 0.3.1 服务端（默认 D:/DS-Harness/.tmp/baseline-0.3.1，可用
 * INTEROP_OLD_ROOT 覆盖）与新服务端（默认本仓库，可用 INTEROP_NEW_ROOT 覆盖），
 * 再用两侧真实的 client/cli.mjs 与 client/peer-call.mjs 驱动冻结契约 v0.4.0 的兼容矩阵。
 *
 * 设计原则：不硬编码 0.4.0 行为。凡只有 0.4.0 才成立的断言，都以 /v1/health 的
 * capability 探测为开关 —— 新服务端今天仍是 0.3.1 行为，因此那些断言报 SKIP；
 * A/B 落地后同一个文件会自动把它们变成 PASS/FAIL，harness 无需改动。
 *
 * 用法：在 lan-peers 目录下 node interop/run-interop.mjs
 * 退出码：0 全通过 / 1 有 FAIL / 2 harness 自身故障（起不来、超硬超时）
 */
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const STATE_ROOT = path.join(HERE, 'state');
// 默认测 lan-peers；INTEROP_NEW_ROOT 用来把"被测"指向别处（例如指回 0.3.1 基线，
// 验证 A-D 老语义断言在"新服务端仍是 0.3.1 行为"时只出 SKIP、不出 FAIL）。
const NEW_ROOT = process.env.INTEROP_NEW_ROOT
  ? path.resolve(process.env.INTEROP_NEW_ROOT)
  : path.resolve(HERE, '..');
const OLD_ROOT = process.env.INTEROP_OLD_ROOT
  ? path.resolve(process.env.INTEROP_OLD_ROOT)
  : path.resolve(HERE, '..', '..', '.tmp', 'baseline-0.3.1');

const HTTP_TIMEOUT_MS = 5000;
const SERVER_READY_MS = 15000;
const SERVER_START_ATTEMPTS = 3;
const CLI_TIMEOUT_MS = 40000;
const ASK_TIMEOUT_SEC = 20;
const HARD_DEADLINE_MS = 170000;

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

const fmt = (tpl, ...args) => tpl.replace(/\{(\d+)\}/g, (m, i) => {
  const v = args[Number(i)];
  return v === undefined ? m : String(v);
});
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const oneLine = (s) => String(s === undefined || s === null ? '' : s).replace(/\s+/g, ' ').trim().slice(0, 220);
const need = (cond, msg) => { if (!cond) throw new Error(msg); };
const skip = (reason) => ({ skip: reason });
const hasCap = (server, cap) => Array.isArray(server.health && server.health.capability)
  && server.health.capability.includes(cap);

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
  });
}

function portInUse(port) {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.once('error', () => resolve(true));
    srv.once('listening', () => srv.close(() => resolve(false)));
    srv.listen(port, '127.0.0.1');
  });
}

async function httpJson(url, options) {
  const opts = options || {};
  const started = Date.now();
  const res = await fetch(url, {
    method: opts.method || 'GET',
    headers: opts.headers || {},
    body: opts.body,
    signal: AbortSignal.timeout(opts.timeoutMs || HTTP_TIMEOUT_MS),
  });
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { json = null; }
  return { status: res.status, json, text, elapsedMs: Date.now() - started };
}

function waitExit(child, ms) {
  return new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) return resolve(true);
    const onExit = () => { clearTimeout(timer); resolve(true); };
    const timer = setTimeout(() => { child.removeListener('exit', onExit); resolve(false); }, ms);
    child.once('exit', onExit);
  });
}

const LIVE = new Set();

async function killTree(child) {
  if (!child || child.exitCode !== null) return;
  try { child.kill('SIGTERM'); } catch { /* 已退出 */ }
  if (await waitExit(child, 2500)) return;
  if (process.platform === 'win32') {
    await new Promise((resolve) => {
      const tk = spawn('taskkill', ['/PID', String(child.pid), '/T', '/F'], { stdio: 'ignore' });
      tk.once('close', resolve);
      tk.once('error', resolve);
    });
  } else {
    try { child.kill('SIGKILL'); } catch { /* 已退出 */ }
  }
  await waitExit(child, 2000);
}

async function shutdownAll() {
  await Promise.all([...LIVE].map((child) => killTree(child)));
  LIVE.clear();
}

/** 一次性 node 调用（cli.mjs / server.mjs --code），带超时强杀 */
function runNode(root, argv, options) {
  const opts = options || {};
  return new Promise((resolve) => {
    const started = Date.now();
    const child = spawn(process.execPath, argv, { cwd: root, stdio: ['ignore', 'pipe', 'pipe'] });
    LIVE.add(child);
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      try { child.kill('SIGKILL'); } catch { /* ignore */ }
    }, opts.timeoutMs || CLI_TIMEOUT_MS);
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    const finish = (code, err) => {
      clearTimeout(timer);
      LIVE.delete(child);
      resolve({ code, stdout, stderr: err ? String(err) : stderr, timedOut, elapsedMs: Date.now() - started });
    };
    child.once('close', (code) => finish(code));
    child.once('error', (err) => finish(-1, err.message));
  });
}

const runCli = (root, argv, opts) => runNode(root, [path.join(root, 'client', 'cli.mjs')].concat(argv), opts);

// ---------------------------------------------------------------------------
// 服务端进程封装
// ---------------------------------------------------------------------------

class Server {
  constructor(spec) {
    this.label = spec.label;
    this.name = spec.name;
    this.root = spec.root;
    this.child = null;
    this.lines = [];
    this.health = null;
    this.port = null;
    this.url = null;
    this.stateDir = null;
    this.lastStartError = null;
  }

  async start() {
    for (let attempt = 1; attempt <= SERVER_START_ATTEMPTS; attempt++) {
      const port = await freePort();
      const stateDir = path.join(STATE_ROOT, 'server-' + this.label);
      fs.mkdirSync(stateDir, { recursive: true });
      const logPath = path.join(STATE_ROOT, this.label + '.log');
      fs.writeFileSync(logPath, '');

      this.port = port;
      this.url = 'http://127.0.0.1:' + port;
      this.stateDir = stateDir;
      this.lines = [];
      this.health = null;

      const child = spawn(process.execPath, [
        'host/server.mjs',
        '--port', String(port),
        '--state-dir', stateDir,
        '--allow-remote-prompts',
        '--name', this.name,
      ], { cwd: this.root, stdio: ['ignore', 'pipe', 'pipe'] });
      this.child = child;
      LIVE.add(child);

      const append = (chunk) => {
        if (this.lines.length < 4000) {
          this.lines.push(...String(chunk).split(/\r?\n/).filter(Boolean));
        }
        try { fs.appendFileSync(logPath, String(chunk)); } catch { /* ignore */ }
      };
      child.stdout.setEncoding('utf8');
      child.stderr.setEncoding('utf8');
      child.stdout.on('data', append);
      child.stderr.on('data', append);

      let exitInfo = null;
      child.once('exit', (code, signal) => { exitInfo = { code, signal }; LIVE.delete(child); });

      const deadline = Date.now() + SERVER_READY_MS;
      while (Date.now() < deadline) {
        if (exitInfo) break;
        const probe = await httpJson(this.url + '/v1/health', { timeoutMs: 1000 }).catch(() => null);
        if (probe && probe.status === 200 && probe.json && typeof probe.json === 'object') {
          this.health = probe.json;
          return this;
        }
        await sleep(120);
      }

      this.lastStartError = exitInfo
        ? fmt('进程退出 code={0} signal={1} · {2}', exitInfo.code, exitInfo.signal, oneLine(this.lines.slice(-6).join(' | ')))
        : fmt('{0}ms 内 /v1/health 无响应 · {1}', SERVER_READY_MS, oneLine(this.lines.slice(-6).join(' | ')));
      await this.stop();
      process.stdout.write(fmt('  ! 服务端 {0} 第 {1} 次启动失败（换端口重试）：{2}\n', this.label, attempt, this.lastStartError));
    }
    throw new Error(fmt('服务端 {0} 启动失败：{1}', this.label, this.lastStartError));
  }

  async stop() {
    const child = this.child;
    this.child = null;
    if (!child) return;
    LIVE.delete(child);
    await killTree(child);
  }

  lastLine(re) {
    for (let i = this.lines.length - 1; i >= 0; i--) if (re.test(this.lines[i])) return this.lines[i];
    return null;
  }

  count(re) { return this.lines.filter((line) => re.test(line)).length; }
}

/** 让该服务端生成一次性配对码（用服务端自己的包执行 --code，写同一个 state-dir） */
async function issueCode(server) {
  const r = await runNode(server.root, ['host/server.mjs', '--code', '--state-dir', server.stateDir], { timeoutMs: 20000 });
  need(r.code === 0, fmt('出码失败 exit={0} {1}', r.code, oneLine(r.stdout + r.stderr)));
  const match = /(\d{6})/.exec(r.stdout);
  need(match, fmt('出码输出没有 6 位码: {0}', oneLine(r.stdout)));
  return match[1];
}

// ---------------------------------------------------------------------------
// 断言收集
// ---------------------------------------------------------------------------

class Case {
  constructor(id, title) {
    this.id = id;
    this.title = title;
    this.checks = [];
  }

  async step(name, fn) {
    try {
      const detail = await fn();
      if (detail && typeof detail === 'object' && detail.skip) {
        this.checks.push({ status: 'SKIP', name, detail: detail.skip });
      } else {
        this.checks.push({ status: 'PASS', name, detail: typeof detail === 'string' ? detail : '' });
      }
    } catch (err) {
      this.checks.push({ status: 'FAIL', name, detail: oneLine(err && err.message ? err.message : err) });
    }
  }

  get status() {
    if (this.checks.some((c) => c.status === 'FAIL')) return 'FAIL';
    if (this.checks.some((c) => c.status === 'PASS')) return 'PASS';
    return 'SKIP';
  }

  get summary() {
    const fail = this.checks.find((c) => c.status === 'FAIL');
    if (fail) return fail.name + ' — ' + fail.detail;
    const skipped = this.checks.filter((c) => c.status === 'SKIP').length;
    const passed = this.checks.filter((c) => c.status === 'PASS');
    const last = passed.length ? passed[passed.length - 1] : null;
    const tail = skipped > 0 ? fmt(' · {0} 项 SKIP（等 0.4.0 落地）', skipped) : '';
    return (last ? last.detail : '') + tail;
  }
}

/** 用某个包（旧/新）的 client/cli.mjs 配对，并载入它的 peer-call 以便直接打协议 */
async function pairClient(spec) {
  const code = await issueCode(spec.server);
  const r = await runCli(spec.clientRoot, [
    'pair',
    '--url', spec.server.url,
    '--code', code,
    '--name', spec.clientName,
    '--peer-name', spec.peerName,
    '--state-dir', spec.clientDir,
  ], { timeoutMs: 20000 });
  need(r.code === 0 && /已配对/.test(r.stdout), fmt('cli pair 失败 exit={0} {1}', r.code, oneLine(r.stdout + r.stderr)));

  const state = JSON.parse(fs.readFileSync(path.join(spec.clientDir, 'state.json'), 'utf8'));
  const peersFile = JSON.parse(fs.readFileSync(path.join(spec.clientDir, 'peers.json'), 'utf8'));
  const entry = Object.entries(peersFile.peers || {})[0];
  need(entry, 'peers.json 里没有对端');
  const mod = await import(pathToFileURL(path.join(spec.clientRoot, 'client', 'peer-call.mjs')).href);
  return {
    peerId: entry[0],
    secret: entry[1].secret,
    senderId: state.instanceId,
    baseUrl: spec.server.url,
    callPeer: mod.callPeer,
  };
}

/** /v1/ask 之后立刻不带 waitMs 打 /v1/answer，返回结构与耗时 */
async function probeImmediateAnswer(client, tag) {
  const ask = await client.callPeer({
    baseUrl: client.baseUrl,
    secret: client.secret,
    senderId: client.senderId,
    method: 'POST',
    apiPath: '/v1/ask',
    body: { requestId: 'req-' + crypto.randomUUID(), prompt: 'interop-' + tag + ' immediate-answer probe', timeoutSec: ASK_TIMEOUT_SEC },
    timeoutMs: 15000,
  });
  need(ask && ask.sessionId, fmt('/v1/ask 未返回 sessionId: {0}', oneLine(JSON.stringify(ask))));
  const started = Date.now();
  const body = await client.callPeer({
    baseUrl: client.baseUrl,
    secret: client.secret,
    senderId: client.senderId,
    method: 'GET',
    apiPath: '/v1/answer?sessionId=' + encodeURIComponent(ask.sessionId),
    timeoutMs: 15000,
  });
  return { sessionId: ask.sessionId, body, elapsedMs: Date.now() - started };
}


// ---------------------------------------------------------------------------
// 冻结契约 §2/§3 的独立实现（harness 自己算 ECDH + HKDF，不复用仓库代码）
// ---------------------------------------------------------------------------

const PAIR_SALT = Buffer.from('dsh-lan-peers/pair/v1', 'utf8');
const PAIR_WRAP_INFO = Buffer.from('dsh-lan-peers/pair/wrap/v1', 'utf8');

const b64url = (buf) => Buffer.from(buf).toString('base64url');
const unb64url = (s) => Buffer.from(String(s), 'base64url');

function newPairingKeys() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const der = publicKey.export({ type: 'spki', format: 'der' });
  const point = der.subarray(der.length - 65); // 未压缩点：0x04 || X(32) || Y(32)
  need(point[0] === 0x04, '导出的 P-256 公钥不是未压缩点');
  return { privateKey, publicKeyB64url: b64url(point) };
}

function peerPublicKey(b64) {
  const point = unb64url(b64);
  need(point.length === 65 && point[0] === 0x04, 'publicKey 不是 65 字节未压缩 P-256 点（长度 ' + point.length + '）');
  return crypto.createPublicKey({
    key: {
      kty: 'EC',
      crv: 'P-256',
      x: b64url(point.subarray(1, 33)),
      y: b64url(point.subarray(33, 65)),
    },
    format: 'jwk',
  });
}

/** W = HKDF-SHA256(ikm=ECDH X, salt, info, 32) */
function deriveWrapKey(privateKey, peerPublicKeyB64url) {
  const z = crypto.diffieHellman({ privateKey, publicKey: peerPublicKey(peerPublicKeyB64url) });
  return Buffer.from(crypto.hkdfSync('sha256', z, PAIR_SALT, PAIR_WRAP_INFO, 32));
}

function wrapSecret(wrapKey, plainObject) {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', wrapKey, nonce);
  const ct = Buffer.concat([cipher.update(Buffer.from(JSON.stringify(plainObject), 'utf8')), cipher.final()]);
  return b64url(Buffer.concat([nonce, ct, cipher.getAuthTag()]));
}

function unwrapSecret(wrapKey, wrappedB64url) {
  const blob = unb64url(wrappedB64url);
  need(blob.length > 12 + 16, 'wrapped 太短');
  const decipher = crypto.createDecipheriv('aes-256-gcm', wrapKey, blob.subarray(0, 12));
  decipher.setAuthTag(blob.subarray(blob.length - 16));
  const pt = Buffer.concat([decipher.update(blob.subarray(12, blob.length - 16)), decipher.final()]);
  return JSON.parse(pt.toString('utf8'));
}


/**
 * 独立读一次 /v1/events（不依赖被测仓库的 sse.mjs）：
 * 用 baseline 的 protocol.mjs 签名、baseline 的 wire-crypto 逐条解密，
 * 从而把「每条事件独立加密、非ce 每次新随机」当作第三方断言来验。
 */
async function readSseRaw(spec) {
  const proto = await import(pathToFileURL(path.join(OLD_ROOT, 'client', 'protocol.mjs')).href);
  const wc = await import(pathToFileURL(path.join(OLD_ROOT, 'lib', 'wire-crypto.mjs')).href);
  const apiPath = '/v1/events?sessionId=' + encodeURIComponent(spec.sessionId);
  const ts = Date.now();
  const nonce = proto.newNonce();
  const sig = proto.sign(spec.secret, proto.canonical('GET', apiPath, ts, nonce, Buffer.alloc(0)));
  const started = Date.now();
  const res = await fetch(spec.baseUrl + apiPath, {
    method: 'GET',
    headers: {
      'X-Peer-Id': spec.senderId,
      'X-Peer-Ts': String(ts),
      'X-Peer-Nonce': nonce,
      'X-Peer-Sign': sig,
      'X-Peer-Enc': 'v1',
      Accept: 'text/event-stream',
    },
    signal: AbortSignal.timeout(spec.timeoutMs || 20000),
  });
  const contentType = String(res.headers.get('content-type') || '');
  const raw = await res.text(); // 服务端在终态事件后应主动 end，text() 才会返回
  const records = [];
  for (const block of raw.split(/\r?\n\r?\n/)) {
    if (!block.trim()) continue;
    let name = 'message';
    const dataLines = [];
    for (const line of block.split(/\r?\n/)) {
      if (line.startsWith(':')) continue;
      const idx = line.indexOf(':');
      const field = idx === -1 ? line : line.slice(0, idx);
      let value = idx === -1 ? '' : line.slice(idx + 1);
      if (value.startsWith(' ')) value = value.slice(1);
      if (field === 'event') name = value;
      else if (field === 'data') dataLines.push(value);
    }
    records.push({ event: name, data: dataLines.join('\n') });
  }
  const events = records.map((rec) => {
    const env = JSON.parse(rec.data);
    const nonceHex = String(env && env.data ? env.data : '').slice(0, 16);
    return { event: rec.event, env, nonceHex, payload: wc.decryptJson(spec.secret, env.data) };
  });
  return { status: res.status, contentType, records, events, raw, elapsedMs: Date.now() - started };
}

async function postJson(url, body, timeoutMs) {
  return httpJson(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    timeoutMs: timeoutMs || 8000,
  });
}

// ---------------------------------------------------------------------------
// 四个用例：兼容矩阵四行
// ---------------------------------------------------------------------------

async function caseA(ctx) {
  const c = new Case('A', '旧 0.3.1 客户端 → 新服务端：明文配对 + 派单 + 弃用告警');
  const server = ctx.newServer;
  const clientDir = path.join(STATE_ROOT, 'client-a');

  await c.step('health.capability 保留 "ask"/"pair"', async () => {
    const cap = (server.health && server.health.capability) || [];
    need(cap.includes('ask') && cap.includes('pair'), 'capability=' + JSON.stringify(cap));
    return 'capability=' + JSON.stringify(cap) + ' version=' + server.health.version;
  });

  await c.step('pair: 明文 POST /v1/pair 成功（新服务端）', async () => {
    const paired = await pairClient({ clientRoot: OLD_ROOT, server, clientDir, clientName: 'legacy-client', peerName: 'modern' });
    const line = server.lastLine(/POST \/v1\/pair/);
    need(line && /POST \/v1\/pair 200/.test(line), '新服务端日志未见 200: ' + (line || '(无 pair 日志)'));
    const status = /POST \/v1\/pair (\d{3})/.exec(line)[1];
    const took = / ([\d.]+)ms /.exec(line)[1];
    return fmt('HTTP {0} · {1}ms · peerId={2}…', status, took, paired.peerId.slice(0, 8));
  });

  await c.step('ask: 加密派单拿到 reply', async () => {
    const r = await runCli(OLD_ROOT, [
      'ask', '--peer', 'modern', 'interop-A: hello from legacy client',
      '--timeout', String(ASK_TIMEOUT_SEC), '--state-dir', clientDir,
    ], { timeoutMs: 35000 });
    need(r.code === 0, fmt('cli ask exit={0} · {1}', r.code, oneLine(r.stderr)));
    const reply = r.stdout.trim();
    need(reply.length > 0, 'reply 为空');
    need(/^OK /.test(reply), 'reply 非预期: ' + oneLine(reply));
    const polls = server.count(/GET \/v1\/answer 200/);
    need(polls >= 1, '新服务端无 GET /v1/answer 200 日志');
    return fmt('reply="{0}" · poll={1} · {2}ms', oneLine(reply), polls, r.elapsedMs);
  });

  await c.step('弃用告警 pair: legacy plaintext path used by <peerId>', async () => {
    if (!hasCap(server, 'pair-ecdh')) return skip('新服务端 capability 无 "pair-ecdh"（今日仍是 0.3.1 行为）');
    const line = server.lastLine(/legacy plaintext path/);
    need(line, '新服务端日志缺少弃用告警行');
    need(/legacy plaintext path used by \S+/.test(line), '告警行格式不符: ' + oneLine(line));
    return oneLine(line);
  });

  return c;
}

async function caseB(ctx) {
  const c = new Case('B', '新客户端 → 旧 0.3.1 服务端：自动回退明文配对 + 派单');
  const server = ctx.oldServer;
  const clientDir = path.join(STATE_ROOT, 'client-b');

  await c.step('pair: 新客户端向旧服务端配对成功', async () => {
    const paired = await pairClient({ clientRoot: NEW_ROOT, server, clientDir, clientName: 'modern-client', peerName: 'legacy' });
    const line = server.lastLine(/POST \/v1\/pair/);
    need(line && /POST \/v1\/pair 200/.test(line), '旧服务端日志未见 200: ' + (line || '(无 pair 日志)'));
    return fmt('HTTP 200 · peerId={0}… · {1}', paired.peerId.slice(0, 8), oneLine(line));
  });

  await c.step('回退依据：旧服务端 capability 不含 "pair-ecdh" → 只能走明文', async () => {
    const cap = (server.health && server.health.capability) || [];
    need(!cap.includes('pair-ecdh'), '旧服务端竟然声明了 pair-ecdh: ' + JSON.stringify(cap));
    return 'capability=' + JSON.stringify(cap) + ' version=' + server.health.version;
  });

  await c.step('ask: 派单拿到 reply（旧服务端）', async () => {
    const r = await runCli(NEW_ROOT, [
      'ask', '--peer', 'legacy', 'interop-B: hello from modern client',
      '--timeout', String(ASK_TIMEOUT_SEC), '--state-dir', clientDir,
    ], { timeoutMs: 35000 });
    need(r.code === 0, fmt('cli ask exit={0} · {1}', r.code, oneLine(r.stderr)));
    const reply = r.stdout.trim();
    need(/^OK /.test(reply), 'reply 非预期: ' + oneLine(reply));
    const polls = server.count(/GET \/v1\/answer 200/);
    need(polls >= 1, '旧服务端无 GET /v1/answer 200 日志');
    return fmt('reply="{0}" · {1}ms · poll={2}', oneLine(reply), r.elapsedMs, polls);
  });

  return c;
}

async function caseC(ctx) {
  const c = new Case('C', '旧客户端 → 新服务端 /v1/answer 无 waitMs：立即返回且语义不变');
  const newServer = ctx.newServer;
  const oldServer = ctx.oldServer;
  let modern = null;
  let baseline = null;
  let modernAnswer = null;

  await c.step('旧客户端对新服务端配对', async () => {
    modern = await pairClient({
      clientRoot: OLD_ROOT, server: newServer,
      clientDir: path.join(STATE_ROOT, 'client-c-new'), clientName: 'legacy-client', peerName: 'modern',
    });
    return 'paired peerId=' + modern.peerId.slice(0, 8) + '…';
  });

  await c.step('旧客户端对旧服务端配对（0.3.1 基线对照组）', async () => {
    baseline = await pairClient({
      clientRoot: OLD_ROOT, server: oldServer,
      clientDir: path.join(STATE_ROOT, 'client-c-old'), clientName: 'legacy-client', peerName: 'legacy',
    });
    return 'paired peerId=' + baseline.peerId.slice(0, 8) + '…';
  });

  await c.step('不带 waitMs → 立即返回（无 hold）', async () => {
    modernAnswer = await probeImmediateAnswer(modern, 'c-new');
    need(modernAnswer.elapsedMs < 800, fmt('耗时 {0}ms，疑似被 hold（应 < 800ms）', modernAnswer.elapsedMs));
    const status = modernAnswer.body && modernAnswer.body.status;
    need(status === 'running' || status === 'done', 'status 缺失或非法: ' + oneLine(JSON.stringify(modernAnswer.body)));
    return fmt('{0}ms · status={1} · keys={2}', modernAnswer.elapsedMs, status, Object.keys(modernAnswer.body || {}).join(','));
  });

  await c.step('响应结构与 0.3.1 一致（新增键只允许 elapsedMs）', async () => {
    const baseAnswer = await probeImmediateAnswer(baseline, 'c-old');
    const baseKeys = Object.keys(baseAnswer.body || {});
    const modernKeys = Object.keys(modernAnswer.body || {});
    const extra = modernKeys.filter((k) => baseKeys.indexOf(k) === -1);
    const missing = baseKeys.filter((k) => modernKeys.indexOf(k) === -1);
    need(missing.length === 0, '新服务端缺失 0.3.1 字段: ' + missing.join(','));
    need(extra.every((k) => k === 'elapsedMs'), '出现非预期新字段: ' + extra.join(','));
    return fmt('old={0} new={1} · 耗时 {2}ms / {3}ms', JSON.stringify(baseKeys), JSON.stringify(modernKeys), baseAnswer.elapsedMs, modernAnswer.elapsedMs);
  });

  await c.step('0.4.0 才要求：响应带 elapsedMs', async () => {
    if (!hasCap(newServer, 'stream')) return skip('新服务端 capability 无 "stream"（今日仍是 0.3.1 行为）');
    need(typeof (modernAnswer.body || {}).elapsedMs === 'number', 'elapsedMs 缺失或非数字: ' + oneLine(JSON.stringify(modernAnswer.body)));
    return 'elapsedMs=' + modernAnswer.body.elapsedMs;
  });

  return c;
}

async function caseD(ctx) {
  const c = new Case('D', '新客户端 → 旧 0.3.1 服务端：回退 1.5s 轮询并拿到 reply');
  const server = ctx.oldServer;
  const clientDir = path.join(STATE_ROOT, 'client-d');
  let cli = null;

  await c.step('配对成功（旧服务端）', async () => {
    await pairClient({ clientRoot: NEW_ROOT, server, clientDir, clientName: 'modern-client', peerName: 'legacy' });
    const line = server.lastLine(/POST \/v1\/pair/);
    need(line && /POST \/v1\/pair 200/.test(line), '旧服务端日志未见 pair 200: ' + (line || '(无)'));
    return oneLine(line);
  });

  await c.step('派单拿到 reply', async () => {
    cli = await runCli(NEW_ROOT, [
      'ask', '--peer', 'legacy', 'interop-D: polling fallback probe',
      '--timeout', String(ASK_TIMEOUT_SEC), '--state-dir', clientDir,
    ], { timeoutMs: 35000 });
    need(cli.code === 0, fmt('cli ask exit={0} · {1}', cli.code, oneLine(cli.stderr)));
    const reply = cli.stdout.trim();
    need(/^OK /.test(reply), 'reply 非预期: ' + oneLine(reply));
    return fmt('reply="{0}" · {1}ms', oneLine(reply), cli.elapsedMs);
  });

  await c.step('回退依据：旧服务端 capability 不含 "stream"', async () => {
    const cap = (server.health && server.health.capability) || [];
    need(!cap.includes('stream'), '旧服务端竟然声明了 stream: ' + JSON.stringify(cap));
    return 'capability=' + JSON.stringify(cap) + ' → 只能长轮询';
  });

  await c.step('确实走 1.5s 轮询（旧服务端日志 + 耗时）', async () => {
    const polls = server.count(/GET \/v1\/answer 200/);
    need(polls >= 1, '旧服务端无 GET /v1/answer 200 日志，说明没走轮询');
    need(cli.elapsedMs >= 1400, fmt('elapsed={0}ms < 1400ms，不符合 1.5s 轮询回退', cli.elapsedMs));
    return fmt('poll={0} · elapsed={1}ms ≥ 1400ms（1.5s 间隔）', polls, cli.elapsedMs);
  });

  await c.step('未对旧服务端成功使用 SSE', async () => {
    const ok = server.count(/GET \/v1\/events 2\d\d/);
    need(ok === 0, fmt('旧服务端出现 {0} 条 /v1/events 2xx，0.3.1 上不应成功', ok));
    return '/v1/events 2xx = 0';
  });

  return c;
}


async function caseE(ctx) {
  const c = new Case('E', 'EXTRA · 冻结契约 §2/§3：第三方实现走完 ECDH 配对（配对码不消费 + 确认换密钥）');
  const server = ctx.newServer;
  // 注意：服务端 state.json 只有一个配对码槽位，后出的码会顶掉前一个 —— 全程只持有一个码
  const code1 = await issueCode(server);

  let clientKeys = null;
  let wrapKey = null;
  let serverEcdh = null;

  await c.step('round1: POST /v1/pair + ecdh → 200 且返回服务端临时公钥', async () => {
    if (!hasCap(server, 'pair-ecdh')) return skip('新服务端 capability 无 "pair-ecdh"');
    clientKeys = newPairingKeys();
    const res = await postJson(server.url + '/v1/pair', {
      code: code1, peerId: 'interop-ecdh-client', peerName: 'ecdh-client',
      ecdh: { v: 1, curve: 'P-256', publicKey: clientKeys.publicKeyB64url },
    });
    need(res.status === 200, 'HTTP ' + res.status + ' ' + oneLine(res.text));
    serverEcdh = res.json.ecdh;
    need(serverEcdh && serverEcdh.v === 1 && serverEcdh.curve === 'P-256', 'ecdh 字段不符: ' + oneLine(res.text));
    need(unb64url(serverEcdh.publicKey).length === 65, '服务端公钥不是 65 字节');
    need(res.json.pairingTtlMs === 120000, 'pairingTtlMs 应为 120000，实际 ' + res.json.pairingTtlMs);
    return fmt('HTTP 200 · serverPub={0}… · pairingTtlMs={1}', String(serverEcdh.publicKey).slice(0, 12), res.json.pairingTtlMs);
  });


  let ecdhPeer = null;
  await c.step('confirm: wrapped 解出 S、返回 wrapped(T)，且 T 能真正签名派单', async () => {
    if (!hasCap(server, 'pair-ecdh')) return skip('新服务端 capability 无 "pair-ecdh"');
    wrapKey = deriveWrapKey(clientKeys.privateKey, serverEcdh.publicKey);
    const mySecret = b64url(crypto.randomBytes(32));
    const wrapped = wrapSecret(wrapKey, { secret: mySecret });
    const res = await postJson(server.url + '/v1/pair/confirm', {
      code: code1, peerId: 'interop-ecdh-client', peerName: 'ecdh-client', wrapped,
    });
    need(res.status === 200, 'confirm HTTP ' + res.status + ' ' + oneLine(res.text));
    need(res.json.peerId && res.json.peerName, 'confirm 响应缺 peerId/peerName: ' + oneLine(res.text));
    const opened = unwrapSecret(wrapKey, res.json.wrapped);
    need(typeof opened.secret === 'string' && opened.secret.length > 0, 'wrapped 里没有 secret');

    // 用换出来的 T 当旧客户端密钥，实际打一次签名+加密请求，证明通道成立
    const oldCall = await import(pathToFileURL(path.join(OLD_ROOT, 'client', 'peer-call.mjs')).href);
    ecdhPeer = res.json.peerId; // 服务端 instanceId 就是我们的对端 id
    const peers = await oldCall.callPeer({
      baseUrl: server.url, secret: opened.secret, senderId: 'interop-ecdh-client',
      method: 'GET', apiPath: '/v1/peers', timeoutMs: 10000,
    });
    need(Array.isArray(peers.peers), '/v1/peers 返回异常: ' + oneLine(JSON.stringify(peers)));

    const ask = await oldCall.callPeer({
      baseUrl: server.url, secret: opened.secret, senderId: 'interop-ecdh-client',
      method: 'POST', apiPath: '/v1/ask',
      body: { requestId: 'req-' + crypto.randomUUID(), prompt: 'interop-E: ecdh paired call', timeoutSec: 20 },
      timeoutMs: 15000,
    });
    need(ask && ask.sessionId, '/v1/ask 失败: ' + oneLine(JSON.stringify(ask)));
    const done = await oldCall.callPeer({
      baseUrl: server.url, secret: opened.secret, senderId: 'interop-ecdh-client',
      method: 'GET', apiPath: '/v1/answer?sessionId=' + encodeURIComponent(ask.sessionId) + '&waitMs=5000',
      timeoutMs: 15000,
    });
    need(done.status === 'done', 'waitMs 长轮询未拿到 done: ' + oneLine(JSON.stringify(done)));
    need(String(done.reply || '').length > 0, 'reply 为空');
    return fmt('confirm 200 · T 可签名（/v1/peers OK）· waitMs 长轮询 done reply="{0}"', oneLine(done.reply));
  });

  await c.step('round1 不消费配对码（同码仍可走旧明文路径）', async () => {
    if (!hasCap(server, 'pair-ecdh')) return skip('新服务端 capability 无 "pair-ecdh"');
    const code2 = await issueCode(server);
    const keys = newPairingKeys();
    const first = await postJson(server.url + '/v1/pair', {
      code: code2, peerId: 'interop-nonconsume', peerName: 'nonconsume',
      ecdh: { v: 1, curve: 'P-256', publicKey: keys.publicKeyB64url },
    });
    need(first.status === 200, 'round1 HTTP ' + first.status + ' ' + oneLine(first.text));
    const legacy = await postJson(server.url + '/v1/pair', {
      code: code2, peerId: 'interop-nonconsume-legacy', peerName: 'nonconsume-legacy',
      secret: b64url(crypto.randomBytes(32)),
    });
    need(legacy.status === 200, '同码明文配对应成功（说明码未被消费），实际 ' + legacy.status + ' ' + oneLine(legacy.text));
    return 'round1 后再用同码走明文 pair → HTTP 200（码未被消费）';
  });

  await c.step('密码学否定用例：码错 401 / publicKey 非法 400 / wrapped 被改 400', async () => {
    if (!hasCap(server, 'pair-ecdh')) return skip('新服务端 capability 无 "pair-ecdh"');
    const keys = newPairingKeys();
    const bad = await postJson(server.url + '/v1/pair/confirm', {
      code: code1, peerId: 'x', peerName: 'x', wrapped: wrapSecret(crypto.randomBytes(32), { secret: 'a' }),
    });
    need(bad.status === 401 && bad.json.error === 'invalid-code', 'confirm 用已消费码应为 401 invalid-code，实际 ' + bad.status + ' ' + oneLine(bad.text));

    const badKey = await postJson(server.url + '/v1/pair', {
      code: code1, peerId: 'x', peerName: 'x', ecdh: { v: 1, curve: 'P-256', publicKey: b64url(crypto.randomBytes(10)) },
    });
    need(badKey.status === 400 && badKey.json.error === 'bad-request', 'publicKey 非法应为 400 bad-request，实际 ' + badKey.status + ' ' + oneLine(badKey.text));

    const code3 = await issueCode(server);
    const tamperRound1 = await postJson(server.url + '/v1/pair', {
      code: code3, peerId: 'interop-tamper', peerName: 'tamper',
      ecdh: { v: 1, curve: 'P-256', publicKey: keys.publicKeyB64url },
    });
    need(tamperRound1.status === 200, '篡改用例的 round1 失败: ' + tamperRound1.status);
    const w = deriveWrapKey(keys.privateKey, tamperRound1.json.ecdh.publicKey);
    const tampered = unb64url(wrapSecret(w, { secret: 'a' }));
    tampered[tampered.length - 1] ^= 0xff;
    const badEnc = await postJson(server.url + '/v1/pair/confirm', {
      code: code3, peerId: 'interop-tamper', peerName: 'tamper', wrapped: b64url(tampered),
    });
    need(badEnc.status === 400 && badEnc.json.error === 'bad-encryption', 'wrapped 被篡改应为 400 bad-encryption，实际 ' + badEnc.status + ' ' + oneLine(badEnc.text));
    return '401 invalid-code / 400 bad-request / 400 bad-encryption 全部符合契约';
  });

  await c.step('新 CLI 默认 auto 配对 → 对新服务端选中 ECDH 两轮，且能继续派单', async () => {
    if (!hasCap(server, 'pair-ecdh')) return skip('新服务端 capability 无 "pair-ecdh"');
    const dir = path.join(STATE_ROOT, 'client-e-cli');
    const code = await issueCode(server);
    const pair = await runCli(NEW_ROOT, [
      'pair', '--url', server.url, '--code', code, '--name', 'ecdh-cli', '--peer-name', 'modern', '--state-dir', dir,
    ], { timeoutMs: 20000 });
    need(pair.code === 0, fmt('cli pair exit={0} · {1}', pair.code, oneLine(pair.stdout + pair.stderr)));
    need(/ECDH/.test(pair.stdout), 'CLI 没走 ECDH，输出: ' + oneLine(pair.stdout));
    const ask = await runCli(NEW_ROOT, [
      'ask', '--peer', 'modern', 'interop-E2: cli ecdh ask', '--timeout', String(ASK_TIMEOUT_SEC), '--state-dir', dir,
    ], { timeoutMs: 35000 });
    need(ask.code === 0, fmt('cli ask exit={0} · {1}', ask.code, oneLine(ask.stderr)));
    const reply = ask.stdout.trim();
    need(/^OK /.test(reply), 'ECDH 配对后 reply 非预期: ' + oneLine(reply));
    return fmt('CLI transport=ECDH · ask reply="{0}" · {1}ms', oneLine(reply), ask.elapsedMs);
  });

  return c;
}


async function caseF(ctx) {
  const c = new Case('F', 'EXTRA · /v1/events SSE：新服务端流式事件（逐条加密 + 终态 end 流 + 客户端回退）');
  const server = ctx.newServer;
  const oldServer = ctx.oldServer;
  const clientDir = path.join(STATE_ROOT, 'client-f');
  let peer = null;
  let sessionId = null;

  await c.step('前提：新服务端 capability 含 "stream"', async () => {
    if (!hasCap(server, 'stream')) return skip('新服务端 capability 无 "stream"');
    peer = await pairClient({ clientRoot: OLD_ROOT, server, clientDir, clientName: 'legacy-client', peerName: 'modern' });
    const ask = await peer.callPeer({
      baseUrl: peer.baseUrl, secret: peer.secret, senderId: peer.senderId,
      method: 'POST', apiPath: '/v1/ask',
      body: { requestId: 'req-' + crypto.randomUUID(), prompt: 'interop-F: sse stream probe', timeoutSec: ASK_TIMEOUT_SEC },
      timeoutMs: 15000,
    });
    need(ask && ask.sessionId, '/v1/ask 失败: ' + oneLine(JSON.stringify(ask)));
    sessionId = ask.sessionId;
    return 'capability=' + JSON.stringify(server.health.capability) + ' · session=' + sessionId.slice(0, 8) + '…';
  });

  await c.step('GET /v1/events → 200 text/event-stream 且终态后 end 流', async () => {
    if (!hasCap(server, 'stream')) return skip('新服务端 capability 无 "stream"');
    const sse = await readSseRaw({ baseUrl: server.url, secret: peer.secret, senderId: peer.senderId, sessionId, timeoutMs: 20000 });
    need(sse.status === 200, 'HTTP ' + sse.status + ' · ' + oneLine(sse.raw));
    need(sse.contentType.includes('text/event-stream'), 'content-type 不是 text/event-stream: ' + sse.contentType);
    need(sse.events.length > 0, '没有收到任何事件');
    c.lastSse = sse;
    const done = sse.events.filter((e) => e.payload && e.payload.status === 'done');
    need(done.length >= 1, '没有 done 事件: ' + oneLine(sse.raw));
    need(String(done[done.length - 1].payload.reply || '').length > 0, 'done 事件里 reply 为空');
    return fmt('HTTP 200 · {0} 条事件 · {1}ms（终态后服务端主动断开）', sse.events.length, sse.elapsedMs);
  });

  await c.step('每条事件独立加密：enc=v1 信封 + 非ce 每次新随机 + 能独立解出明文', async () => {
    if (!hasCap(server, 'stream')) return skip('新服务端 capability 无 "stream"');
    const sse = c.lastSse;
    need(sse, '上一步没有拿到流');
    const names = sse.events.map((e) => e.event);
    need(names.some((n) => n === 'status' || n === 'done'), '事件名里既无 status 也无 done: ' + names.join(','));
    for (const ev of sse.events) {
      need(ev.env && ev.env.enc === 'v1' && typeof ev.env.data === 'string', ev.event + ' 事件不是 {"enc":"v1","data":…} 信封');
      need(ev.payload && typeof ev.payload === 'object', ev.event + ' 事件解密失败');
    }
    const nonces = sse.events.map((e) => e.nonceHex);
    need(new Set(nonces).size === nonces.length, '出现重复 nonce，逐条加密不成立: ' + nonces.join(','));
    const running = sse.events.filter((e) => e.payload.status === 'running');
    need(running.length >= 1, '没有 status=running 事件（只有: ' + names.join(',') + '）');
    need(typeof running[0].payload.elapsedMs === 'number', 'running 事件缺 elapsedMs');
    return fmt('{0} 条事件全部独立解密 · nonce 全不同 · running={1} done={2}', sse.events.length, running.length, sse.events.length - running.length);
  });

  await c.step('新客户端 sse.mjs readPeerEvents 也能拿到 done（客户端半边）', async () => {
    if (!hasCap(server, 'stream')) return skip('新服务端 capability 无 "stream"');
    let sseMod;
    try {
      sseMod = await import(pathToFileURL(path.join(NEW_ROOT, 'client', 'sse.mjs')).href);
    } catch (err) {
      return skip('新客户端还没有 client/sse.mjs: ' + oneLine(err && err.message ? err.message : err));
    }
    const ask = await peer.callPeer({
      baseUrl: peer.baseUrl, secret: peer.secret, senderId: peer.senderId,
      method: 'POST', apiPath: '/v1/ask',
      body: { requestId: 'req-' + crypto.randomUUID(), prompt: 'interop-F2: client sse probe', timeoutSec: ASK_TIMEOUT_SEC },
      timeoutMs: 15000,
    });
    need(ask && ask.sessionId, '/v1/ask 失败: ' + oneLine(JSON.stringify(ask)));
    const seen = [];
    const result = await sseMod.readPeerEvents({
      baseUrl: server.url, secret: peer.secret, senderId: peer.senderId,
      sessionId: ask.sessionId, timeoutMs: 15000,
      onEvent: (e) => seen.push(e.type + ':' + (e.status || '')),
    });
    need(result && result.ok === true, 'readPeerEvents 未成功: ' + oneLine(JSON.stringify(result)));
    need(result.status === 'done', 'readPeerEvents 终态不是 done: ' + oneLine(JSON.stringify(result)));
    need(String(result.reply || '').length > 0, 'readPeerEvents 的 reply 为空');
    return fmt('ok=true status=done · 事件 {0}', seen.join(',').slice(0, 120));
  });

  await c.step('非 200 → 回退信号：readPeerEvents 对旧服务端返回 ok:false http-404', async () => {
    let sseMod;
    try {
      sseMod = await import(pathToFileURL(path.join(NEW_ROOT, 'client', 'sse.mjs')).href);
    } catch (err) {
      return skip('新客户端还没有 client/sse.mjs');
    }
    const result = await sseMod.readPeerEvents({
      baseUrl: oldServer.url, secret: b64url(crypto.randomBytes(32)), senderId: 'interop-sse-probe',
      sessionId: crypto.randomUUID(), timeoutMs: 8000,
    });
    need(result && result.ok === false, '旧服务端上 readPeerEvents 应返回 ok:false，实际 ' + oneLine(JSON.stringify(result)));
    need(String(result.reason || '').includes('404'), '回退原因应含 404，实际: ' + oneLine(String(result.reason)));
    return 'ok=false reason=' + oneLine(String(result.reason)) + '（客户端据此回退长轮询）';
  });

  await c.step('新 CLI → 新服务端 ask 走 SSE（服务端出现 /v1/events 200）', async () => {
    if (!hasCap(server, 'stream')) return skip('新服务端 capability 无 "stream"');
    const dir = path.join(STATE_ROOT, 'client-f-cli');
    const code = await issueCode(server);
    const pair = await runCli(NEW_ROOT, [
      'pair', '--url', server.url, '--code', code, '--name', 'sse-cli', '--peer-name', 'modern', '--state-dir', dir,
    ], { timeoutMs: 20000 });
    need(pair.code === 0, fmt('cli pair exit={0} · {1}', pair.code, oneLine(pair.stdout + pair.stderr)));
    const before = server.count(/GET \/v1\/events 200/);
    const ask = await runCli(NEW_ROOT, [
      'ask', '--peer', 'modern', 'interop-F3: cli sse ask', '--timeout', String(ASK_TIMEOUT_SEC), '--state-dir', dir,
    ], { timeoutMs: 35000 });
    need(ask.code === 0, fmt('cli ask exit={0} · {1}', ask.code, oneLine(ask.stderr)));
    const reply = ask.stdout.trim();
    need(/^OK /.test(reply), 'reply 非预期: ' + oneLine(reply));
    const after = server.count(/GET \/v1\/events 200/);
    need(after > before, fmt('新服务端没有出现 /v1/events 200（before={0} after={1}），CLI 可能仍走轮询', before, after));
    return fmt('reply="{0}" · /v1/events 200 由 {1} 增至 {2} · {3}ms', oneLine(reply), before, after, ask.elapsedMs);
  });

  return c;
}

// ---------------------------------------------------------------------------
// 输出
// ---------------------------------------------------------------------------

function printCase(c) {
  process.stdout.write('\n[' + c.id + '] ' + c.title + '\n');
  for (const check of c.checks) {
    const mark = check.status === 'PASS' ? '✔ PASS' : check.status === 'FAIL' ? '✘ FAIL' : '– SKIP';
    process.stdout.write('  ' + mark + '  ' + check.name + '\n');
    if (check.detail) process.stdout.write('          ' + check.detail + '\n');
  }
  process.stdout.write('  => ' + c.status + '\n');
}

function printSummary(cases, extra) {
  process.stdout.write('\n' + '='.repeat(96) + '\n汇总表\n' + '-'.repeat(96) + '\n');
  for (const c of cases) {
    process.stdout.write(c.id + '  ' + c.status.padEnd(6) + '  ' + c.title + '\n');
    if (c.summary) process.stdout.write('          ↳ ' + c.summary + '\n');
  }
  process.stdout.write('-'.repeat(96) + '\n');
  for (const line of extra) process.stdout.write(line + '\n');
  process.stdout.write('='.repeat(96) + '\n');
}

// ---------------------------------------------------------------------------
// 主流程
// ---------------------------------------------------------------------------

async function main() {
  process.stdout.write('dsh-lan-peers interop harness · ' + new Date().toISOString() + '\n');
  process.stdout.write('  新仓库(被测)  : ' + NEW_ROOT + '\n');
  process.stdout.write('  旧基线(对照组): ' + OLD_ROOT + '\n');
  process.stdout.write('  state / logs  : ' + STATE_ROOT + '\n');

  for (const pair of [['新仓库(被测)', NEW_ROOT], ['旧基线(对照组)', OLD_ROOT]]) {
    need(fs.existsSync(path.join(pair[1], 'host', 'server.mjs')), pair[0] + ' 缺少 host/server.mjs: ' + pair[1]);
    need(fs.existsSync(path.join(pair[1], 'client', 'cli.mjs')), pair[0] + ' 缺少 client/cli.mjs: ' + pair[1]);
  }

  fs.rmSync(STATE_ROOT, { recursive: true, force: true });
  fs.mkdirSync(STATE_ROOT, { recursive: true });

  const newServer = new Server({ label: 'modern', name: 'modern', root: NEW_ROOT });
  const oldServer = new Server({ label: 'legacy', name: 'legacy', root: OLD_ROOT });
  const cases = [];

  try {
    process.stdout.write('\n启动服务端…\n');
    await Promise.all([newServer.start(), oldServer.start()]);
    process.stdout.write('  legacy  ' + oldServer.url + '  version=' + oldServer.health.version
      + '  capability=' + JSON.stringify(oldServer.health.capability) + '\n');
    process.stdout.write('  modern  ' + newServer.url + '  version=' + newServer.health.version
      + '  capability=' + JSON.stringify(newServer.health.capability) + '\n');
    process.stdout.write('  0.4.0 就绪探测：pair-ecdh=' + hasCap(newServer, 'pair-ecdh')
      + ' stream=' + hasCap(newServer, 'stream') + ' → 未就绪的断言将报 SKIP\n');

    const ctx = { newServer, oldServer };
    const runners = [[caseA, 'A'], [caseB, 'B'], [caseC, 'C'], [caseD, 'D'], [caseE, 'E'], [caseF, 'F']];
    for (const entry of runners) {
      const started = Date.now();
      let result;
      try {
        result = await entry[0](ctx);
      } catch (err) {
        result = new Case(entry[1], '用例执行中断');
        result.checks.push({ status: 'FAIL', name: '用例执行中断', detail: oneLine(err && err.message ? err.message : err) });
      }
      printCase(result);
      process.stdout.write('  (' + (Date.now() - started) + 'ms)\n');
      cases.push(result);
    }
  } finally {
    await Promise.all([newServer.stop(), oldServer.stop()]);
  }

  const ports = [newServer.port, oldServer.port].filter(Boolean);
  await sleep(300);
  const still = [];
  for (const port of ports) if (await portInUse(port)) still.push(port);

  const extra = [];
  if (still.length === 0) {
    extra.push('端口回收：' + ports.join(', ') + ' 均已释放（无遗留监听）');
  } else {
    extra.push('端口回收：!! 仍有监听 ' + still.join(', '));
    const c = new Case('!', '端口回收');
    c.checks.push({ status: 'FAIL', name: '跑完仍有遗留监听', detail: '端口 ' + still.join(', ') });
    cases.push(c);
  }

  const failed = cases.filter((c) => c.status === 'FAIL');
  printSummary(cases, extra);
  const ready = hasCap(newServer, 'pair-ecdh') || hasCap(newServer, 'stream');
  process.stdout.write('\n结论：' + (failed.length === 0 ? '全部用例 PASS' : failed.length + ' 个用例 FAIL：' + failed.map((c) => c.id).join(', '))
    + '\n（新服务端 version=' + newServer.health.version + ' capability=' + JSON.stringify(newServer.health.capability) + ' → 0.4.0 断言'
    + (ready ? '已生效' : '全部 SKIP（新服务端仍是 0.3.1 行为，属预期）') + '）\n');

  fs.writeFileSync(path.join(STATE_ROOT, 'report.json'), JSON.stringify({
    generatedAt: new Date().toISOString(),
    newRoot: NEW_ROOT,
    oldRoot: OLD_ROOT,
    newServer: { url: newServer.url, health: newServer.health },
    oldServer: { url: oldServer.url, health: oldServer.health },
    cases: cases.map((c) => ({ id: c.id, title: c.title, status: c.status, checks: c.checks })),
    exitCode: failed.length === 0 ? 0 : 1,
  }, null, 2));

  return failed.length === 0 ? 0 : 1;
}

let finished = false;
const hardTimer = setTimeout(async () => {
  if (finished) return;
  process.stdout.write('\nFATAL: harness 超过 ' + HARD_DEADLINE_MS + 'ms，强制回收子进程后退出\n');
  await shutdownAll();
  process.exit(2);
}, HARD_DEADLINE_MS);
if (hardTimer.unref) hardTimer.unref();

main()
  .then(async (code) => {
    finished = true;
    clearTimeout(hardTimer);
    await shutdownAll();
    process.exit(code);
  })
  .catch(async (err) => {
    finished = true;
    clearTimeout(hardTimer);
    process.stdout.write('\nFATAL: ' + ((err && err.stack) || err) + '\n');
    await shutdownAll();
    process.exit(2);
  });
