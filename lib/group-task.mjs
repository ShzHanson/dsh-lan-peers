// dsh-lan-peers · 0.10.0-α slice 2 群内 `/task` 的纯解析与回执文案。
//
// 分界（契约 §0）：群聊本身**不再派单**（slice 1 已移除 lan_group_ask / group/dispatch*
// 与 progress/result 两种 kind）。这一层只做两件纯事：
//   parseGroupTask(text)              群消息正文 → 是不是一条 `/task @<成员> <指令>`
//   buildTaskReceipt({...})           转派结果 → 群里那**一条** system 回执的正文
//
// 铁律：
//   - 显式语法，不做语义猜测（「让 agent 自己判断什么算任务」是 slice 3 的事）；
//   - 回执只说「转给谁 + 结果」，**绝不带指令正文**，也不带完整 id（只带前 8 位）；
//   - 零副作用：不读文件、不写日志、不发网络请求；文案全部来自 lib/i18n.mjs。
//
// 本文件只被 lib/admin.mjs（发帖节点的一次转派）与 lib/group-task.test.mjs 使用。

import { DEFAULT_LANG, t } from './i18n.mjs';

/** 指令前缀：出现在群消息正文最前面才算一条任务（大小写不敏感）。 */
export const TASK_COMMAND = '/task';

/**
 * 解析层能给出的错误码（**协议口径**，进日志不进界面，任何语言下都保持英文原样）：
 *   empty               整条消息是空白/非字符串
 *   missing-target      有 /task，但后面没有 @<成员>
 *   missing-instruction 点到人了，但一句话都没说要做什么
 */
export const TASK_PARSE_ERRORS = Object.freeze(['empty', 'missing-target', 'missing-instruction']);

/**
 * 回执结果码（= 界面文案的 key 后缀，见 lib/i18n.mjs 的 group.task.*）。
 * 九个是闭集：新增一个就必须同时补两格词表。
 */
export const TASK_OUTCOMES = Object.freeze([
  'dispatched',
  'pending-approval',
  'refused-no-target',
  'refused-no-instruction',
  'refused-unknown-member',
  'refused-self',
  'refused-not-member',
  'refused-offline',
  'refused-unpaired',
  'error',
]);

/** 回执里出现的 taskId 片段长度上限（只给「待批准」用，永远不是完整 id）。 */
export const TASK_ID_PREFIX_CHARS = 8;

// `/task` 后面紧贴着字母/数字/下划线就不算（`/tasks`、`/task2` 都是普通聊天）；
// 紧贴 `@` 算（`/task@bob hi` 容忍不敲空格的人）。
const TASK_HEAD = /^\/task(?![A-Za-z0-9_-])/i;
const TASK_TARGET = /^@([^\s@]+)/;

const asText = (value) => (typeof value === 'string' ? value : '');

/**
 * 群消息正文 → { isTask, target, instruction, error }。纯函数，无 I/O。
 *
 * 语法（显式、只有这一种）：
 *   `/task @<name-or-peerId> <instruction>`
 *   - 前后空白无所谓，`/task` 大小写无所谓；
 *   - target 不含 `@`、到第一个空白为止；允许写 peerId；
 *   - instruction = 去掉前面那两段之后剩下的全部（**保留内部空格**，也保留内部的 `@`）。
 *
 * 非 `/task` 开头 → isTask:false（error 为空，普通聊天）；空白消息 → isTask:false +
 * error:'empty' —— 两者都能被调用方分开，正常聊天路径不会因为「空」被误判成任务。
 */
export function parseGroupTask(text) {
  const raw = asText(text);
  const trimmed = raw.trim();
  if (trimmed === '') {
    return { isTask: false, target: '', instruction: '', error: 'empty' };
  }
  const head = TASK_HEAD.exec(trimmed);
  if (!head) {
    return { isTask: false, target: '', instruction: '', error: '' };
  }
  const rest = trimmed.slice(head[0].length).trim();
  const hit = TASK_TARGET.exec(rest);
  if (!hit) {
    return { isTask: true, target: '', instruction: '', error: 'missing-target' };
  }
  const target = hit[1];
  const instruction = rest.slice(hit[0].length).trim();
  if (instruction === '') {
    return { isTask: true, target, instruction: '', error: 'missing-instruction' };
  }
  return { isTask: true, target, instruction, error: '' };
}

const OUTCOME_KEYS = Object.freeze({
  dispatched: 'group.task.dispatched',
  'pending-approval': 'group.task.pendingApproval',
  'refused-no-target': 'group.task.refusedNoTarget',
  'refused-no-instruction': 'group.task.refusedNoInstruction',
  'refused-unknown-member': 'group.task.refusedUnknownMember',
  'refused-self': 'group.task.refusedSelf',
  'refused-not-member': 'group.task.refusedNotMember',
  'refused-offline': 'group.task.refusedOffline',
  'refused-unpaired': 'group.task.refusedUnpaired',
  error: 'group.task.error',
});

/** 清成「能安全塞进一行回执」的目标名：去掉可能带回来的 `@`，空白退回 `?`。 */
const receiptName = (target) => {
  const name = asText(target).trim().replace(/^@+/, '').trim();
  return name === '' ? '?' : name;
};

/**
 * 转派结果 → 群里那一条 system 回执的正文。
 *
 *   target   目标成员的显示名（调用方给 name，拿不到就给 peerId 短前缀）
 *   outcome  TASK_OUTCOMES 之一；未知值一律按 error 处理（绝不抛错）
 *   taskId   「待批准」时传 approvalId：只取前 8 位，完整 id 永不出现在群里
 *   lang     'zh' | 'en'，缺省 zh（与 DEFAULT_LANG 同一口径）
 *
 * 回执里没有 instruction 参数 —— 这一层**结构上**就带不进指令正文。
 */
export function buildTaskReceipt({ target, outcome, taskId = '', lang = DEFAULT_LANG } = {}) {
  const code = OUTCOME_KEYS[String(outcome)] ? String(outcome) : 'error';
  const key = OUTCOME_KEYS[code];
  const id = asText(taskId).slice(0, TASK_ID_PREFIX_CHARS);
  const params = { name: receiptName(target) };
  if (code === 'pending-approval') params.id = id === '' ? '?' : id;
  return t(lang, key, params);
}
