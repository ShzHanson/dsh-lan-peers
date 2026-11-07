// 2026-11-08 真机回归：成员侧面板群聊空白。
//
// 真机现象：桌面成员的面板群聊一条消息都没有。根因不在服务端 ——
// hub 在「游标落在已归档区间」时**按设计**回 `{archived:true, messages:[]}`
// （host/server.mjs 的 groupHistory，§18「不静默给空结果」），而面板首屏正是
// 用 `sinceSeq=0` 取历史；成员侧直接把空数组交给面板，本机副本里的历史被丢掉了。
//
// 修法：只在「首屏 + hub 给空」时用副本尾部补齐（memberHistoryMessages）。
import test from 'node:test';
import assert from 'node:assert/strict';

import { memberHistoryMessages } from './admin.mjs';

const msg = (seq) => ({ seq, ts: 1_700_000_000_000 + seq, from: { peerId: 'peer-hub', name: 'hub' }, kind: 'chat', text: `m${seq}` });
const replica = () => [msg(68), msg(69), msg(70), msg(71), msg(72)];

test('首屏（sinceSeq=0）hub 回 archived 空结果 → 用副本尾部补齐', () => {
  const out = memberHistoryMessages({
    history: { archived: true, archiveFrom: 1, archiveTo: 72, messages: [], lastSeq: 72 },
    sinceSeq: 0,
    replicaMessages: replica(),
    limit: 200,
  });
  assert.equal(out.length, 5, '副本有 5 条就应补出 5 条');
  assert.equal(out[out.length - 1].seq, 72, '补的是尾部（最新）');
});

test('hub 有消息时以 hub 为准，不被副本覆盖', () => {
  const hubOnly = [msg(70)];
  const out = memberHistoryMessages({
    history: { messages: hubOnly, lastSeq: 72 },
    sinceSeq: 0,
    replicaMessages: replica(),
    limit: 200,
  });
  assert.deepEqual(out, hubOnly);
});

test('sinceSeq>0 的增量拉取永不回落到副本（否则会把旧消息当成新消息）', () => {
  const out = memberHistoryMessages({
    history: { messages: [], lastSeq: 72 },
    sinceSeq: 72,
    replicaMessages: replica(),
    limit: 200,
  });
  assert.deepEqual(out, [], '增量游标处 hub 给空就是空');
});

test('副本也为空时如实给空（不造假数据）', () => {
  const out = memberHistoryMessages({ history: { messages: [] }, sinceSeq: 0, replicaMessages: [], limit: 200 });
  assert.deepEqual(out, []);
});

test('副本超过上限时只取尾部 limit 条，且保留原有顺序', () => {
  const many = Array.from({ length: 50 }, (_, index) => msg(index + 1));
  const out = memberHistoryMessages({ history: { messages: [] }, sinceSeq: 0, replicaMessages: many, limit: 10 });
  assert.equal(out.length, 10);
  assert.equal(out[0].seq, 41);
  assert.equal(out[9].seq, 50);
  assert.deepEqual(out.map((m) => m.seq), [41, 42, 43, 44, 45, 46, 47, 48, 49, 50]);
});

test('history 形状异常（null / messages 非数组）不抛错', () => {
  assert.deepEqual(memberHistoryMessages({ history: null, sinceSeq: 0, replicaMessages: [] }), []);
  assert.deepEqual(memberHistoryMessages({ history: { messages: 'nope' }, sinceSeq: 0, replicaMessages: [] }), []);
  assert.equal(memberHistoryMessages({ history: null, sinceSeq: 0, replicaMessages: replica() }).length, 5);
});
