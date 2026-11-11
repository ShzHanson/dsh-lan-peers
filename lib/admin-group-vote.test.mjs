// dsh-lan-peers · 0.10.0-α slice 4b-2：表决平面的三个管理接口。
//
// 契约口径（与 group/post、group/notes 同一套写法）：
//   POST group/proposal   —— 成员或 hub 都能提交（这是「输入」）；201 + 更新后的平面
//   POST group/vote       —— 投一票；200 + 更新后的平面（accepted:false 也回 200，面板要读原因）
//   POST group/adjudicate —— **hub 独有**；成员一律 votes-hub-only
// 状态机与 wire 都在上一片定稿了，这里只钉「路由层是否如实转发、是否守门、是否回平面」。
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createAdmin } from './admin.mjs';
import { makeTempStateDir } from '../host/test/helpers.mjs';

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

function makeRequest(method, url, body, admin) {
  const chunks = body === undefined ? [] : [Buffer.from(JSON.stringify(body))];
  const token = admin && typeof admin.token === 'string' ? admin.token : '';
  const req = {
    method,
    url,
    socket: { remoteAddress: '127.0.0.1', setNoDelay() {} },
    headers: {
      host: '127.0.0.1:7788',
      'content-type': 'application/json',
      'content-length': String(chunks[0]?.length ?? 0),
      ...(token === '' ? {} : { 'x-lan-peers-token': token }),
    },
    on() { return req; },
    once() { return req; },
    async *[Symbol.asyncIterator]() { for (const chunk of chunks) yield chunk; },
  };
  return req;
}

async function hit(admin, method, apiPath, body) {
  const res = makeResponse();
  const handled = await admin.handle(makeRequest(method, apiPath, body, admin), res, new URL('http://127.0.0.1' + apiPath));
  return { handled, res, json: (() => { try { return JSON.parse(res.body); } catch { return null; } })() };
}

const AT = 1_700_000_000_000;

/**
 * 群后端桩：一份**真的会变**的表决平面（提交会入库、投票会记名、shelved 由夹具给）。
 * 这里不重写状态机的口径（冻结名单/2-3 阈值都在 lib/group-vote.mjs 且已定稿），
 * 只回一份形状正确、随调用变化的平面，让路由层的转发与守门可以被断言。
 */
function voteApi({ isHub = true, shelved = [] } = {}) {
  const calls = [];
  const plane = {
    rev: 1,
    proposals: [],
    votes: {},
    shelved: shelved.map((entry) => ({ ...entry })),
  };
  return {
    calls,
    plane,
    enabled: true,
    isHub,
    state() {
      calls.push({ method: 'state' });
      return { groupId: 'g-1', name: 'default', members: [], messages: [], lastSeq: 0 };
    },
    notes() { return { rev: 0, notes: [] }; },
    votes() { return plane; },
    submitProposal(input) {
      calls.push({ method: 'submitProposal', ...input });
      const id = 'p' + (plane.proposals.length + 1);
      const proposal = {
        id,
        kind: input.kind,
        target: { type: input.target.type, id: input.target.id },
        text: String(input.text),
        author: String(input.author ?? ''),
        createdAt: AT,
      };
      plane.proposals.push(proposal);
      if (input.kind === 'objection') {
        plane.votes[id] = {
          proposalId: id,
          round: 1,
          roster: ['inst-self', 'peer-nas'],
          ballots: {},
          openedAt: AT,
          closesAt: AT + 600_000,
          status: 'open',
          closedAt: 0,
        };
      }
      return { ok: true, proposal, status: input.kind === 'objection' ? 'open' : 'adopted', vote: null };
    },
    castVote(input) {
      calls.push({ method: 'castVote', ...input });
      const vote = plane.votes[input.proposalId];
      if (!vote) return { ok: false, error: 'vote-not-found' };
      if (!vote.roster.includes(input.peerId)) return { ok: true, accepted: false, reason: 'vote-not-eligible', vote };
      vote.ballots = { ...vote.ballots, [input.peerId]: input.ballot };
      return { ok: true, accepted: true, reason: '', vote };
    },
  };
}

function stubAdmin({ api, stateDir = makeTempStateDir() } = {}) {
  const lines = [];
  const admin = createAdmin({
    server: {
      config: { logger: (line) => lines.push(line) },
      store: { instanceId: 'inst-self', stateDir, listPeers: () => [], getPeer: () => null },
      group: null,
    },
    nameOf: () => 'self',
    rename: (n) => n,
    feed: null,
    pairing: { mode: 'auto' },
    group: { enabled: true, hub: '' },
    groupApi: api,
  });
  return { admin, lines, stateDir };
}

test('U1 · 提交补充 → 201 且平面里就位（补充默认采纳，不开票）', async () => {
  const api = voteApi();
  const { admin, lines } = stubAdmin({ api });
  const out = await hit(admin, 'POST', '/api/lan-peers/group/proposal', {
    kind: 'supplement',
    target: { type: 'body', id: 'n7' },
    text: '把十月计划补成两周',
  });
  assert.equal(out.res.status, 201, '提交是「创建」，回 201');
  assert.equal(out.json.ok, true);
  assert.equal(out.json.votePlane.proposals.length, 1);
  assert.equal(out.json.votePlane.proposals[0].status, 'adopted', '没有反对的补充默认采纳');
  assert.equal(out.json.votePlane.proposals[0].vote, null, '补充不投票');
  assert.equal(out.json.votePlane.proposals[0].target.id, 'n7', '目标就是那条纪要的 id');
  assert.equal(out.json.voteSummary.proposals, 1, '同一次应答里带上摘要，面板不用再跑一趟');
  assert.equal(api.calls.filter((call) => call.method === 'submitProposal').length, 1);
  // 日志只有种类/长度：提案正文绝不进日志
  const log = lines.join('\n');
  assert.match(log, /\[admin\] group proposal in kind=supplement target=body textLen=9/);
  assert.equal(log.includes('把十月计划补成两周'), false, '提案正文不得进日志');
});

test('U1 · 提交反对 → 开第 1 轮，平面里 round=1 且有倒计时终点', async () => {
  const { admin } = stubAdmin({ api: voteApi() });
  const out = await hit(admin, 'POST', '/api/lan-peers/group/proposal', {
    kind: 'objection',
    target: { type: 'supplement', id: 'p0' },
    text: '这条不同意',
  });
  assert.equal(out.res.status, 201);
  const proposal = out.json.votePlane.proposals[0];
  assert.equal(proposal.status, 'open', '反对自动开票');
  assert.equal(proposal.vote.round, 1, '反对一提交就是第 1 轮');
  assert.equal(proposal.vote.threshold, 2, '名单 2 人 → 需要 2 票（ceil(2*2/3)）');
  assert.ok(proposal.vote.closesAt > proposal.vote.openedAt, '一轮有明确的截止时刻');
});

test('U1 · 投票 → 200 且平面反映计票与「我的票」；坏票面/缺参先被拒', async () => {
  const api = voteApi();
  const { admin, lines } = stubAdmin({ api });
  await hit(admin, 'POST', '/api/lan-peers/group/proposal', {
    kind: 'objection', target: { type: 'body', id: 'n1' }, text: '反对一下',
  });
  const voted = await hit(admin, 'POST', '/api/lan-peers/group/vote', { proposalId: 'p1', ballot: 'yes' });
  assert.equal(voted.res.status, 200);
  assert.equal(voted.json.accepted, true);
  const vote = voted.json.votePlane.proposals[0].vote;
  assert.equal(vote.yes, 1, '计票由服务端算，路由把同一份平面带回来');
  assert.equal(vote.mine, 'yes', '我的票也在这份平面里（面板据此置灰）');
  assert.equal(api.calls.filter((call) => call.method === 'castVote')[0].peerId, 'inst-self',
    '票只记在本机名下，body 里的 peerId 不认');

  const badBallot = await hit(admin, 'POST', '/api/lan-peers/group/vote', { proposalId: 'p1', ballot: 'abstain' });
  assert.equal(badBallot.res.status, 400);
  assert.equal(badBallot.json.error, 'bad-ballot');
  const missing = await hit(admin, 'POST', '/api/lan-peers/group/vote', { ballot: 'yes' });
  assert.equal(missing.json.error, 'proposalId-required');
  const unknown = await hit(admin, 'POST', '/api/lan-peers/group/vote', { proposalId: 'p404', ballot: 'yes' });
  assert.equal(unknown.res.status, 404, '不存在的提案如实回 404');
  // 日志：短 id + 结果，不含正文
  assert.match(lines.join('\n'), /\[admin\] group vote id=p1 ballot=yes accepted=1/);
  assert.equal(lines.join('\n').includes('反对一下'), false, '提案正文不得进日志');
});

test('U1 · 成员裁决 → votes-hub-only（403），且压根不写裁决记录', async () => {
  const api = voteApi({ isHub: false, shelved: [{ proposalId: 'p1', rounds: 3, at: AT }] });
  const { admin, lines, stateDir } = stubAdmin({ api });
  const out = await hit(admin, 'POST', '/api/lan-peers/group/adjudicate', { proposalId: 'p1', decision: 'adopt' });
  assert.equal(out.res.status, 403, '成员没有裁决口');
  assert.equal(out.json.error, 'votes-hub-only');
  assert.match(lines.join('\n'), /\[admin\] group adjudicate refused id=p1 \(hub only\)/);
  assert.equal(fs.existsSync(path.join(stateDir, 'group-vote-verdicts.json')), false,
    '被拒的裁决不得留下任何记录');
});

test('U1 · hub 裁决 shelved 提案 → adopted 且离开待裁决列表；未 shelved 的拒绝', async () => {
  const api = voteApi({ shelved: [{ proposalId: 'p9', rounds: 3, at: AT }] });
  // 平面上真有一条 shelved 的反对（夹具给的 shelved 集与 votes 里的状态一致）
  api.plane.proposals.push({
    id: 'p9', kind: 'objection', target: { type: 'body', id: 'n1' }, text: '三轮都没过',
    author: 'nas-box', createdAt: AT,
  });
  api.plane.votes.p9 = {
    proposalId: 'p9', round: 3, roster: ['inst-self', 'peer-nas'], ballots: { 'inst-self': 'no' },
    openedAt: AT, closesAt: AT + 600_000, status: 'shelved', closedAt: AT + 600_000,
  };
  const { admin, lines, stateDir } = stubAdmin({ api });

  const notShelved = await hit(admin, 'POST', '/api/lan-peers/group/adjudicate', { proposalId: 'p1', decision: 'adopt' });
  assert.equal(notShelved.res.status, 409);
  assert.equal(notShelved.json.error, 'vote-not-shelved', '只有 shelved 的提案才轮到人裁决');

  const adopted = await hit(admin, 'POST', '/api/lan-peers/group/adjudicate', {
    proposalId: 'p9', decision: 'adopt', reason: '先按这个来',
  });
  assert.equal(adopted.res.status, 200);
  assert.equal(adopted.json.ok, true);
  const decided = adopted.json.votePlane.proposals.find((item) => item.id === 'p9');
  assert.equal(decided.status, 'adopted', '人裁决之后状态变成 adopted');
  assert.equal(decided.decision, 'adopt');
  assert.equal(adopted.json.votePlane.shelved.length, 0, '已裁决的不再端给用户');
  assert.equal(adopted.json.voteSummary.shelved, 0);
  assert.match(lines.join('\n'), /\[admin\] group adjudicate id=p9 decision=adopt reasonLen=5/);
  assert.equal(lines.join('\n').includes('先按这个来'), false, '裁决理由不进日志');

  // 记录真的落盘（hub 重启后不会把同一条提案再问一遍）
  const file = path.join(stateDir, 'group-vote-verdicts.json');
  assert.equal(fs.existsSync(file), true);
  const saved = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.equal(saved.verdicts.p9.decision, 'adopt');
  assert.equal(saved.verdicts.p9.reason, '先按这个来');

  // 再问一次同一条 → 它已经不在 shelved 里，如实回 409
  const again = await hit(admin, 'POST', '/api/lan-peers/group/adjudicate', { proposalId: 'p9', decision: 'reject' });
  assert.equal(again.json.error, 'vote-not-shelved');
});

test('U1 · 拒绝：坏 decision / 缺 proposalId / 群未启用', async () => {
  const { admin } = stubAdmin({ api: voteApi({ shelved: [{ proposalId: 'p1', rounds: 3, at: AT }] }) });
  const badDecision = await hit(admin, 'POST', '/api/lan-peers/group/adjudicate', { proposalId: 'p1', decision: 'maybe' });
  assert.equal(badDecision.res.status, 400);
  assert.equal(badDecision.json.error, 'bad-decision');
  const missing = await hit(admin, 'POST', '/api/lan-peers/group/adjudicate', { decision: 'adopt' });
  assert.equal(missing.json.error, 'proposalId-required');

  const off = createAdmin({
    server: { config: { logger: () => {} }, store: { instanceId: 'inst-self', stateDir: makeTempStateDir() }, group: null },
    nameOf: () => 'self', rename: (n) => n, feed: null, pairing: { mode: 'auto' },
    group: { enabled: false },
  });
  const disabled = await hit(off, 'POST', '/api/lan-peers/group/proposal', {
    kind: 'supplement', target: { type: 'body', id: 'n1' }, text: 'x',
  });
  assert.equal(disabled.res.status, 409);
  assert.equal(disabled.json.error, 'group-disabled');
});

test('U1 · 坏提案（种类/目标）在路由层就被拒，不下发到后端', async () => {
  const api = voteApi();
  const { admin } = stubAdmin({ api });
  const badKind = await hit(admin, 'POST', '/api/lan-peers/group/proposal', {
    kind: 'nuke', target: { type: 'body', id: 'n1' }, text: 'x',
  });
  assert.equal(badKind.res.status, 400);
  assert.equal(badKind.json.error, 'bad-kind');
  const badTarget = await hit(admin, 'POST', '/api/lan-peers/group/proposal', {
    kind: 'supplement', target: { type: 'chat', id: 'n1' }, text: 'x',
  });
  assert.equal(badTarget.res.status, 400);
  assert.equal(badTarget.json.error, 'bad-target');
  assert.equal(api.calls.filter((call) => call.method === 'submitProposal').length, 0, '校验失败不得下发');
});
