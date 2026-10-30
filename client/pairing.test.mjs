// dsh-lan-peers · pairing client tests (ECDH two-round + plaintext legacy).
//
// The peer side uses lib/pairing-ecdh.mjs (A's implementation) so the wire format
// is exercised for real: 65-byte uncompressed P-256 point, base64url, HKDF wrap
// key, AES-256-GCM wrapped secret.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { deriveWrapKey, generateKeyPair, unwrapSecret, wrapSecret } from '../lib/pairing-ecdh.mjs';
import { pairPeer } from './peer-call.mjs';

const PEER_ID = 'peer-B';
const PEER_NAME = 'nas';
const SERVER_SECRET = 'secret-from-server-0123456789';

async function startPairingPeer({
  capability = ['ask', 'pair', 'pair-ecdh'],
  issuedSecret = SERVER_SECRET,
  confirmStatus = null,
} = {}) {
  const state = { pairBodies: [], confirmBodies: [], unwrapped: null, serverKeys: null };

  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString('utf8');
    const url = new URL(req.url, 'http://127.0.0.1');
    const json = (status, value) => {
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(value));
    };

    if (req.method === 'GET' && url.pathname === '/v1/health') {
      json(200, { name: PEER_NAME, instanceId: PEER_ID, version: '0.4.0', capability, peers: 0 });
      return;
    }
    if (req.method === 'POST' && url.pathname === '/v1/pair') {
      const body = JSON.parse(raw);
      state.pairBodies.push(body);
      if (confirmStatus === 'missing-confirm' && body.ecdh) {
        json(200, { ecdh: { v: 1, curve: 'P-256', publicKey: 'not-a-point' } });
        return;
      }
      if (body.ecdh) {
        state.serverKeys = generateKeyPair();
        state.clientPublicKey = body.ecdh.publicKey;
        json(200, {
          ecdh: { v: 1, curve: 'P-256', publicKey: state.serverKeys.publicKeyB64url },
          pairingTtlMs: 120000,
        });
        return;
      }
      // Legacy plaintext path: the client sends its inbound secret in the clear.
      json(200, { peerId: PEER_ID, peerName: PEER_NAME, secret: issuedSecret });
      return;
    }
    if (req.method === 'POST' && url.pathname === '/v1/pair/confirm') {
      const body = JSON.parse(raw);
      state.confirmBodies.push(body);
      const wrapKey = deriveWrapKey(state.serverKeys.privateKey, state.clientPublicKey);
      state.unwrapped = unwrapSecret(wrapKey, body.wrapped);
      json(200, {
        peerId: PEER_ID,
        peerName: PEER_NAME,
        wrapped: wrapSecret(wrapKey, { secret: issuedSecret }),
      });
      return;
    }
    json(404, { error: 'not-found' });
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  return {
    url: 'http://127.0.0.1:' + port,
    state,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

test('auto mode pairs over ECDH when the peer advertises pair-ecdh', async () => {
  const peer = await startPairingPeer();
  try {
    const out = await pairPeer({
      url: peer.url,
      code: '123456',
      peerId: 'peer-A',
      peerName: 'devA',
      mode: 'auto',
    });
    assert.equal(out.transport, 'ecdh');
    assert.equal(out.peerId, PEER_ID);
    assert.equal(out.peerName, PEER_NAME);
    assert.equal(out.secret, SERVER_SECRET);
    assert.ok(out.inboundSecret && out.inboundSecret.length >= 40);
    assert.equal(out.pairingTtlMs, 120000);

    // Round 1: a 65-byte uncompressed P-256 point, base64url encoded.
    // v0.8.0：第一轮额外带 baseUrl（本机的可达地址，接收方存进 peers.json —— 少了它
    // 「配进来的伙伴」在广播/派单里就只剩 no-base-url）。
    const round1 = peer.state.pairBodies[0];
    assert.deepEqual(Object.keys(round1).sort(), ['baseUrl', 'code', 'ecdh', 'peerId', 'peerName']);
    assert.match(String(round1.baseUrl), /^http:\/\/[\d.]+:\d+$/, 'baseUrl 必须是 http://私有地址:端口');
    assert.equal(round1.ecdh.v, 1);
    assert.equal(round1.ecdh.curve, 'P-256');
    const point = Buffer.from(round1.ecdh.publicKey, 'base64url');
    assert.equal(point.length, 65);
    assert.equal(point[0], 0x04);
    // The plaintext secret never leaves the client on this path.
    assert.equal(round1.secret, undefined);

    // Round 2: only the wrapped secret, which the peer unwrapped into our S.
    const round2 = peer.state.confirmBodies[0];
    assert.deepEqual(Object.keys(round2).sort(), ['code', 'peerId', 'peerName', 'wrapped']);
    assert.equal(peer.state.unwrapped.secret, out.inboundSecret);
  } finally {
    await peer.close();
  }
});

test('auto mode falls back to plaintext for a 0.3.1 peer without pair-ecdh', async () => {
  const peer = await startPairingPeer({ capability: ['ask', 'pair'] });
  try {
    const out = await pairPeer({ url: peer.url, code: '123456', peerId: 'peer-A', peerName: 'devA', mode: 'auto' });
    assert.equal(out.transport, 'legacy');
    assert.equal(out.secret, SERVER_SECRET);
    assert.ok(out.inboundSecret);
    assert.equal(peer.state.confirmBodies.length, 0);
    assert.equal(peer.state.pairBodies[0].ecdh, undefined);
    assert.equal(peer.state.pairBodies[0].secret, out.inboundSecret);
  } finally {
    await peer.close();
  }
});

test('legacy mode (--legacy-pair) never touches ECDH even when offered', async () => {
  const peer = await startPairingPeer();
  try {
    const out = await pairPeer({ url: peer.url, code: '123456', peerId: 'peer-A', peerName: 'devA', mode: 'legacy' });
    assert.equal(out.transport, 'legacy');
    assert.equal(peer.state.confirmBodies.length, 0);
    assert.equal(peer.state.pairBodies[0].ecdh, undefined);
  } finally {
    await peer.close();
  }
});

test('forced ecdh mode refuses a peer that does not advertise it', async () => {
  const peer = await startPairingPeer({ capability: ['ask', 'pair'] });
  try {
    await assert.rejects(
      pairPeer({ url: peer.url, code: '123456', peerId: 'peer-A', peerName: 'devA', mode: 'ecdh' }),
      /pairing-ecdh-unsupported/,
    );
    assert.equal(peer.state.pairBodies.length, 0);
  } finally {
    await peer.close();
  }
});

test('a rejected ECDH exchange is surfaced, not silently downgraded', async () => {
  const peer = await startPairingPeer({ confirmStatus: 'missing-confirm' });
  try {
    await assert.rejects(
      pairPeer({ url: peer.url, code: '123456', peerId: 'peer-A', peerName: 'devA', mode: 'auto' }),
      /did not return an ECDH public key|bad-ecdh|Invalid|point/i,
    );
    // No plaintext retry: the code may already be consumed by round 1.
    assert.equal(peer.state.pairBodies.length, 1);
    assert.equal(peer.state.pairBodies[0].secret, undefined);
  } finally {
    await peer.close();
  }
});

test('a bad pairing code reports the peer status', async () => {
  const server = http.createServer((req, res) => {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end('{"error":"invalid-code"}');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  try {
    await assert.rejects(
      pairPeer({ url: 'http://127.0.0.1:' + port, code: '000000', peerId: 'peer-A', peerName: 'devA', mode: 'legacy' }),
      (error) => error.status === 401 && error.code === 'invalid-code',
    );
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('a missing local pairing-ecdh module downgrades in auto and fails loudly in ecdh', async () => {
  const peer = await startPairingPeer();
  try {
    const out = await pairPeer({
      url: peer.url,
      code: '123456',
      peerId: 'peer-A',
      peerName: 'devA',
      mode: 'auto',
      ecdhModule: null,
    });
    assert.equal(out.transport, 'legacy');
    assert.equal(peer.state.pairBodies[0].ecdh, undefined);
    assert.equal(peer.state.confirmBodies.length, 0);

    await assert.rejects(
      pairPeer({
        url: peer.url,
        code: '123456',
        peerId: 'peer-A',
        peerName: 'devA',
        mode: 'ecdh',
        ecdhModule: null,
      }),
      /pairing-ecdh-unavailable/,
    );
  } finally {
    await peer.close();
  }
});
