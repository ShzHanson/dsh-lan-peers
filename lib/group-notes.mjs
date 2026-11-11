/**
 * dsh-lan-peers · 0.10.0-α slice 4a 群纪要（零 I/O 的纯模块）
 * ==========================================================
 * 用户决定：**纪要由 hub 单写，成员只读同步**（不做冲突合并）。4b 才加「成员提补充/异议 + 2/3 表决」，
 * 本模块里刻意没有任何投票、提议、合并冲突的形状 —— 只有「一条 append 进去的文本 + 一个 rev」。
 *
 * 值对象（落盘/上网/门面读口都是这一个形状）：
 *   { rev: number, notes: [{ id, text, author, createdAt }] }
 *
 * 四条不变量：
 *   1. rev 是**显式**字段，只由 appendNote 前进，永远不回退（成员据此判「谁的视图更新」）；
 *   2. 所有函数都不改输入（返回新值对象），输入数组永不被就地 push/sort；
 *   3. 纪要正文只进值对象，**不进日志**（调用方只记 rev 与条数）；
 *   4. 零 I/O、零依赖：落盘在 host/server.mjs 的 store 里，这里只认得内存形状。
 */

/** 单条纪要正文上限（Unicode code point 计：中文不会被拆半个字） */
export const NOTE_TEXT_MAX = 2000;

/** 单条纪要作者名上限（成员表里的名字口径一致） */
export const NOTE_AUTHOR_MAX = 64;

/** 纪要最多保留多少条：只丢最旧的，rev 不动（号不能复用） */
export const NOTES_LIMIT = 200;

const asText = (value) => (typeof value === 'string' ? value : '');

/** code point 长度：中文/emoji 都按一个字符算，避免把半个字切开 */
export function textLength(value) {
  return Array.from(asText(value)).length;
}

/**
 * 造一条纪要并校验。id 必须由调用方给（hub 用 `n<rev>` 这种短号）：
 * 本函数不生成 id —— 生成就得靠随机/时钟，那就不再是纯函数，而且同一份输入两次调用
 * 会得到两个不同的 id（去重就失效了）。
 *
 * 返回 {ok:true, note} 或 {ok:false, error}；error 是稳定的英文码（面板/日志都不翻译它）。
 */
export function makeNote(input = {}) {
  // null/数字/字符串都当成「什么都没给」：校验函数不该因为调用方传了坏形状就抛错
  const source = input && typeof input === 'object' ? input : {};
  const id = asText(source.id).trim();
  if (id === '') return { ok: false, error: 'notes-id-required' };
  // 正文：首尾空白去掉再判空 —— 只有空格的纪要等于没写
  const text = asText(source.text).trim();
  if (text === '') return { ok: false, error: 'notes-text-empty' };
  if (textLength(text) > NOTE_TEXT_MAX) return { ok: false, error: 'notes-text-too-long' };
  const author = asText(source.author).trim();
  if (author === '') return { ok: false, error: 'notes-author-required' };
  if (textLength(author) > NOTE_AUTHOR_MAX) return { ok: false, error: 'notes-author-too-long' };
  const at = Number(source.createdAt);
  if (!Number.isFinite(at) || at <= 0) return { ok: false, error: 'notes-created-at-required' };
  // id 原样保留（只去首尾空白）：一旦改写，成员两侧的同一条纪要就对不上了
  return { ok: true, note: { id, text, author, createdAt: Math.floor(at) } };
}

/** 值对象归一化：坏文件/缺字段的老数据都收敛成 {rev, notes}，绝不抛错 */
export function normalizeNotesValue(raw) {
  const source = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  const rev = Number(source.rev);
  const seen = new Set();
  const notes = [];
  for (const entry of Array.isArray(source.notes) ? source.notes : []) {
    const made = makeNote(entry);
    if (!made.ok) continue;
    if (seen.has(made.note.id)) continue;
    seen.add(made.note.id);
    notes.push(made.note);
  }
  return {
    rev: Number.isFinite(rev) && rev > 0 ? Math.floor(rev) : 0,
    notes,
  };
}

/**
 * 追加一条纪要：返回**新的**值对象，rev + 1，输入一个字节都不动。
 *
 * 同 id 已经在里面 → 原样返回（幂等：hub 重放同一条不会把 rev 推两次）。
 * rev 取 max(旧 rev, 0) + 1：即使旧值被人手改成负数也不会产出比过去更小的号。
 */
export function appendNote(value, note) {
  const base = normalizeNotesValue(value);
  const made = makeNote(note);
  if (!made.ok) {
    // 坏输入不改动任何东西：调用方按 made.error 回 400，而不是把脏行写进去
    return { ok: false, error: made.error, value: base };
  }
  if (base.notes.some((entry) => entry.id === made.note.id)) {
    return { ok: true, value: base, note: made.note, duplicate: true };
  }
  const kept = [...base.notes, made.note];
  // 只丢最旧的：rev 不回退，成员按 rev 判新旧仍然正确
  const notes = kept.length > NOTES_LIMIT ? kept.slice(kept.length - NOTES_LIMIT) : kept;
  return { ok: true, value: { rev: Math.max(0, base.rev) + 1, notes }, note: made.note, duplicate: false };
}

/**
 * 成员侧合并（只读同步）：**remote.rev 更大才采纳**，否则原样留住本地视图。
 *
 * rev 相等时保留本地对象本身（不是因为内容一样，而是「没新信息就别重写盘」——
 * 每轮 pull 都换一份新对象会让副本文件被无意义地重写一遍）。
 * 本地 rev 更大意味着「本地见过更新的 hub 视图」：绝不因为对端更旧就把新视图丢掉。
 */
export function mergeNotesReplica(local, remote) {
  const mine = normalizeNotesValue(local);
  const theirs = normalizeNotesValue(remote);
  if (theirs.rev > mine.rev) return theirs;
  return mine;
}

/** 状态行用的便宜摘要：条数 / rev / 最后一条的时间（没有纪要时 lastAt = 0） */
export function notesSummary(value) {
  const base = normalizeNotesValue(value);
  const last = base.notes.length > 0 ? base.notes[base.notes.length - 1] : null;
  return { count: base.notes.length, rev: base.rev, lastAt: last ? last.createdAt : 0 };
}
