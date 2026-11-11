// dsh-lan-peers · 0.10.0-α slice 4a 群纪要（纯模块）。
//
// 覆盖 N1/N2/N3 与 N8 的模块那一半：校验、rev 单调、输入不可变、
// 「对端更旧时绝不丢本地新视图」。落盘与 hub-only 那两道门在 host 侧的用例里。
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  NOTE_TEXT_MAX,
  NOTES_LIMIT,
  appendNote,
  makeNote,
  mergeNotesReplica,
  normalizeNotesValue,
  notesSummary,
} from './group-notes.mjs';

const note = (id, text = '一条纪要', createdAt = 1_700_000_000_000) => ({ id, text, author: 'hub-box', createdAt });

// ---------------------------------------------------------------------------
// N1 校验
// ---------------------------------------------------------------------------

test('N1 makeNote：空/纯空白/超长/缺作者一律拒；正常文本接受；id 原样保留', () => {
  assert.deepEqual(makeNote({ id: 'n1', text: '', author: 'a', createdAt: 1 }), { ok: false, error: 'notes-text-empty' });
  assert.deepEqual(makeNote({ id: 'n1', text: '   \n\t ', author: 'a', createdAt: 1 }), { ok: false, error: 'notes-text-empty' });
  assert.deepEqual(makeNote({ id: 'n1', text: null, author: 'a', createdAt: 1 }), { ok: false, error: 'notes-text-empty' });

  const tooLong = 'x'.repeat(NOTE_TEXT_MAX + 1);
  assert.deepEqual(makeNote({ id: 'n1', text: tooLong, author: 'a', createdAt: 1 }), { ok: false, error: 'notes-text-too-long' });
  // 上限本身是允许的（边界不是「小于」）
  assert.equal(makeNote({ id: 'n1', text: 'x'.repeat(NOTE_TEXT_MAX), author: 'a', createdAt: 1 }).ok, true);
  // 按 code point 计：中文不会被拆半个字，NOTE_TEXT_MAX 个汉字刚好合法
  assert.equal(makeNote({ id: 'n1', text: '纪'.repeat(NOTE_TEXT_MAX), author: 'a', createdAt: 1 }).ok, true);
  assert.equal(makeNote({ id: 'n1', text: '纪'.repeat(NOTE_TEXT_MAX + 1), author: 'a', createdAt: 1 }).ok, false);

  assert.deepEqual(makeNote({ text: 'hi', author: 'a', createdAt: 1 }), { ok: false, error: 'notes-id-required' });
  assert.deepEqual(makeNote({ id: 'n1', text: 'hi', author: '  ', createdAt: 1 }), { ok: false, error: 'notes-author-required' });
  assert.deepEqual(makeNote({ id: 'n1', text: 'hi', author: 'a', createdAt: 0 }), { ok: false, error: 'notes-created-at-required' });

  const made = makeNote({ id: '  n7 ', text: '  正文前后留白会被去掉  ', author: ' hub-box ', createdAt: 1_700_000_000_123.7 });
  assert.equal(made.ok, true);
  // id 只去首尾空白（去掉内部/大小写改写会让两侧同一条纪要认不出来）
  assert.equal(made.note.id, 'n7');
  assert.equal(made.note.text, '正文前后留白会被去掉');
  assert.equal(made.note.author, 'hub-box');
  assert.equal(made.note.createdAt, 1_700_000_000_123);
  // id 稳定：同一份输入两次调用得到同一个 id（纯函数，不生成随机 id）
  assert.equal(makeNote({ id: 'n7', text: 'x', author: 'a', createdAt: 1 }).note.id, 'n7');
  assert.equal(makeNote({ id: 'N7', text: 'x', author: 'a', createdAt: 1 }).note.id, 'N7', 'id 不因大小写被改写');
});

// ---------------------------------------------------------------------------
// N2 rev 单调 + 输入不可变
// ---------------------------------------------------------------------------

test('N2 appendNote：rev 单调前进、输入数组与值对象一个字节都不改', () => {
  const first = { rev: 0, notes: [] };
  const snapshot = JSON.stringify(first);
  const one = appendNote(first, note('n1', '第一条'));
  assert.equal(one.ok, true);
  assert.equal(one.value.rev, 1);
  assert.equal(one.value.notes.length, 1);
  // 输入未被就地修改
  assert.equal(JSON.stringify(first), snapshot, 'appendNote 不许改输入值对象');
  assert.notEqual(one.value.notes, first.notes, '必须返回新数组，不是原数组');

  const two = appendNote(one.value, note('n2', '第二条'));
  const three = appendNote(two.value, note('n3', '第三条'));
  assert.deepEqual([one.value.rev, two.value.rev, three.value.rev], [1, 2, 3], 'rev 必须逐次 +1');
  assert.deepEqual(one.value.notes.map((entry) => entry.id), ['n1'], '旧值对象不跟着长');

  // rev 明确写在值对象上（不是推导量）：一份手写的 {rev: 41} 追加后就是 42
  const hand = appendNote({ rev: 41, notes: [] }, note('n1'));
  assert.equal(hand.value.rev, 42);
  // 坏输入不改任何东西，也不会把 rev 往前推
  const bad = appendNote({ rev: 5, notes: [] }, { id: 'n1', text: '   ', author: 'a', createdAt: 1 });
  assert.equal(bad.ok, false);
  assert.equal(bad.value.rev, 5);
  assert.deepEqual(bad.value.notes, []);
  // 同 id 幂等：重放不算新的一条，rev 也不动
  const dup = appendNote(one.value, note('n1', '第一条'));
  assert.equal(dup.duplicate, true);
  assert.equal(dup.value.rev, 1);
  assert.equal(dup.value.notes.length, 1);
  // 超过条数上限只丢最旧的，rev 不回退
  let big = { rev: 0, notes: [] };
  for (let index = 0; index < NOTES_LIMIT + 3; index += 1) big = appendNote(big, note('n' + index)).value;
  assert.equal(big.notes.length, NOTES_LIMIT);
  assert.equal(big.rev, NOTES_LIMIT + 3);
  assert.equal(big.notes[big.notes.length - 1].id, 'n' + (NOTES_LIMIT + 2));
});

// ---------------------------------------------------------------------------
// N3 成员侧合并
// ---------------------------------------------------------------------------

test('N3 mergeNotesReplica：remote 更新→采纳；更旧→留本地；rev 相等→留本地（不重写）', () => {
  const older = { rev: 2, notes: [note('n1', '旧一'), note('n2', '旧二')] };
  const newer = { rev: 3, notes: [note('n1', '旧一'), note('n2', '旧二'), note('n3', '新三')] };

  const adopted = mergeNotesReplica(older, newer);
  assert.equal(adopted.rev, 3);
  assert.deepEqual(adopted.notes.map((entry) => entry.id), ['n1', 'n2', 'n3']);

  const kept = mergeNotesReplica(newer, older);
  assert.equal(kept.rev, 3, '对端更旧时绝不回退本地 rev');
  assert.deepEqual(kept.notes.map((entry) => entry.id), ['n1', 'n2', 'n3'], '绝不丢本地已见的新视图');

  // rev 相等：保留本地（逐条相等，且没有 churn —— 内容一模一样才谈得上「保留」）
  const same = mergeNotesReplica(newer, { rev: 3, notes: [note('n1', '旧一'), note('n2', '旧二'), note('n3', '新三')] });
  assert.deepEqual(same, newer);
  // 空/坏值：本地有、对端空 → 留本地；本地空、对端有 → 采纳
  assert.deepEqual(mergeNotesReplica(newer, null), { rev: 3, notes: newer.notes });
  assert.equal(mergeNotesReplica({ rev: 0, notes: [] }, newer).rev, 3);
});

// ---------------------------------------------------------------------------
// 摘要 + 归一化（面板/状态行口径）
// ---------------------------------------------------------------------------

test('notesSummary：count/rev/lastAt 三个标量，空值对象不炸', () => {
  assert.deepEqual(notesSummary(null), { count: 0, rev: 0, lastAt: 0 });
  assert.deepEqual(notesSummary({ rev: 2, notes: [note('n1', 'x', 111), note('n2', 'y', 222)] }), { count: 2, rev: 2, lastAt: 222 });
  // lastAt 取**最后一条**（追加序），不是最大值：面板按追加序倒着渲染
  assert.equal(notesSummary({ rev: 1, notes: [note('n1', 'x', 999), note('n2', 'y', 111)] }).lastAt, 111);
});

test('normalizeNotesValue：坏文件收敛成 {rev, notes}，坏条目被丢掉而不是抛错', () => {
  assert.deepEqual(normalizeNotesValue(null), { rev: 0, notes: [] });
  assert.deepEqual(normalizeNotesValue({ rev: -3, notes: 'nope' }), { rev: 0, notes: [] });
  const cleaned = normalizeNotesValue({
    rev: 4,
    notes: [note('n1'), { id: 'n2', text: '', author: 'a', createdAt: 1 }, note('n1'), null],
  });
  assert.equal(cleaned.rev, 4);
  assert.deepEqual(cleaned.notes.map((entry) => entry.id), ['n1'], '坏条目与重复 id 都被丢掉');
});

// ---------------------------------------------------------------------------
// N8（模块那一半）：变异体必须让 N3 红 —— 否则 N3 是空断言
// ---------------------------------------------------------------------------

test('N8 非空性：mergeNotesReplica 若「总是采纳 remote」，N3 的老 rev 用例立刻红', () => {
  const local = { rev: 3, notes: [note('n1', 'a'), note('n2', 'b'), note('n3', 'c')] };
  const stale = { rev: 1, notes: [note('n1', 'a')] };
  // 真实现：留本地
  assert.equal(mergeNotesReplica(local, stale).rev, 3);
  // 变异体（总采纳 remote）：rev 掉到 1 —— 就是 N3 里那条断言的失败点
  const alwaysAdoptRemote = (mine, theirs) => normalizeNotesValue(theirs);
  assert.equal(alwaysAdoptRemote(local, stale).rev, 1);
  assert.notDeepEqual(alwaysAdoptRemote(local, stale), mergeNotesReplica(local, stale));
});
