// dsh-lan-peers · admin actions must leave a trace in the plugin log.
//
// The 4→1 mystery on 2026-10-27 was unsolvable because /api/lan-peers/unpair
// (and rename/code/pair) wrote nothing to the log. This test pins that down.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createAdmin } from './admin.mjs';

function makeResponse() {
  return {
    status: 0, headers: {}, body: '',
    setHeader(k, v) { this.headers[k] = v; },
    writeHead(status, headers) { this.status = status; Object.assign(this.headers, headers || {}); },
    write(chunk) { this.body += chunk; return true; },
    end(chunk) { if (chunk) this.body += chunk; if (!this.status) this.status = 200; },
    once() {}, on() {},
  };
}

function makeRequest(method, url, body, remote = '127.0.0.1') {
  // readJson() consumes the request with `for await`, so the stub must be an
  // async iterable rather than an EventEmitter.
  const chunks = body === undefined ? [] : [Buffer.from(JSON.stringify(body))];
  const req = {
    method,
    url,
    socket: { remoteAddress: remote, setNoDelay() {} },
    headers: { 'content-type': 'application/json', 'content-length': String(chunks[0]?.length ?? 0) },
    on() { return req; },
    once() { return req; },
    async *[Symbol.asyncIterator]() { for (const chunk of chunks) yield chunk; },
  };
  return req;
}

function boot({ peers }) {
  const lines = [];
  const store = {
    instanceId: 'inst-self',
    listPeers: () => peers.map((p) => ({ peerId: p.peerId, name: p.name, baseUrl: p.baseUrl, lastSeen: null })),
    getPeer: (id) => peers.find((p) => p.peerId === id) || null,
    issuePairingCode: () => ({ code: '123456', expiresAt: Date.now() + 600000 }),
    removePeer: (id) => {
      const i = peers.findIndex((p) => p.peerId === id);
      if (i < 0) return false;
      peers.splice(i, 1);
      return true;
    },
  };
  const admin = createAdmin({
    server: { config: { logger: (line) => lines.push(line) }, store },
    nameOf: () => 'self',
    rename: (n) => n,
    feed: null,
    pairing: { mode: 'auto' },
  });
  return { admin, lines };
}

async function hit(admin, method, apiPath, body) {
  const res = makeResponse();
  const handled = await admin.handle(makeRequest(method, apiPath, body), res, new URL('http://127.0.0.1' + apiPath));
  return { handled, res, json: (() => { try { return JSON.parse(res.body); } catch { return null; } })() };
}

test('解除配对会写入 [admin] unpair 日志（带 removed 与 remote 结果）', async () => {
  const peers = [{ peerId: 'peer-1', name: 'nas-box', baseUrl: 'http://127.0.0.1:1' }];
  const { admin, lines } = boot({ peers });
  await hit(admin, 'POST', '/api/lan-peers/unpair', { peerId: 'peer-1' });
  const line = lines.find((l) => l.includes('[admin] unpair'));
  assert.ok(line, '必须记录解除动作: ' + JSON.stringify(lines));
  assert.match(line, /peer-1/.source ? /peer-1/ : /peer-1/);
  assert.match(line, /removed=true/);
  assert.match(line, /remote=/);
});

test('未知对端的解除请求也留痕（404 路径不静默）', async () => {
  const { admin, lines } = boot({ peers: [] });
  const out = await hit(admin, 'POST', '/api/lan-peers/unpair', { peerId: 'ghost' });
  assert.equal(out.res.status, 404);
  assert.ok(lines.some((l) => l.includes('[admin] unpair')), '404 也应有一条日志');
});

test('发码只记录 TTL，不记录码本身', async () => {
  const { admin, lines } = boot({ peers: [] });
  await hit(admin, 'POST', '/api/lan-peers/code', {});
  const line = lines.find((l) => l.includes('[admin] pairing code issued'));
  assert.ok(line);
  assert.doesNotMatch(line, /123456/, '码是一次性凭据，不得进日志');
});
