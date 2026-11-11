// dsh-lan-peers · 0.10.0-α slice 2：群内 `/task` 的纯解析 + 回执文案。
//
// 这一层是纯函数，所以这里只钉两件事：
//   1. 语法**只有** `/task @<成员> <指令>` 这一种：不猜、不多认一个字符；
//   2. 回执只说「转给谁 + 结果」：句子里结构上就没有指令正文，id 只有前 8 位。
// 路由层的「一次派单 + 一条 system 回执」在 lib/admin-group.test.mjs 的 T2..T6。
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  TASK_ID_PREFIX_CHARS, TASK_OUTCOMES, TASK_PARSE_ERRORS, buildTaskReceipt, parseGroupTask,
} from './group-task.mjs';
import { keys, t } from './i18n.mjs';

const CJK = /[\u4e00-\u9fff]/;

test('T1 解析：标准句式拆出 target 与 instruction', () => {
  assert.deepEqual(parseGroupTask('/task @bob 把日志收一下'), {
    isTask: true, target: 'bob', instruction: '把日志收一下', error: '',
  });
});

test('T1 解析：只有 /task、只有点名人、指令为空都要报错', () => {
  assert.deepEqual(parseGroupTask('/task'), {
    isTask: true, target: '', instruction: '', error: 'missing-target',
  });
  assert.deepEqual(parseGroupTask('/task @bob'), {
    isTask: true, target: 'bob', instruction: '', error: 'missing-instruction',
  });
  assert.deepEqual(parseGroupTask('   /task   @bob   '), {
    isTask: true, target: 'bob', instruction: '', error: 'missing-instruction',
  });
  assert.deepEqual(TASK_PARSE_ERRORS, ['empty', 'missing-target', 'missing-instruction']);
});

test('T1 解析：空白消息不是任务，但错误码与普通聊天分得开', () => {
  assert.deepEqual(parseGroupTask(''), { isTask: false, target: '', instruction: '', error: 'empty' });
  assert.deepEqual(parseGroupTask('   '), { isTask: false, target: '', instruction: '', error: 'empty' });
  assert.deepEqual(parseGroupTask(null), { isTask: false, target: '', instruction: '', error: 'empty' });
});

test('T1 解析：普通聊天一律 isTask:false（不抢正文）', () => {
  assert.deepEqual(parseGroupTask('今天天气不错'), {
    isTask: false, target: '', instruction: '', error: '',
  });
  // 不是「手滑打了半个命令」也算聊天：只有前缀后面是分隔符才认
  for (const text of ['/tasks @bob x', '/task2 @bob x', '任务 /task @bob x', '//task @bob x']) {
    assert.equal(parseGroupTask(text).isTask, false, text + ' 不是一条任务');
  }
});

test('T1 解析：大小写与空格变体都认，且保留指令内部空格', () => {
  assert.deepEqual(parseGroupTask('/TASK @bob 把日志收一下'), {
    isTask: true, target: 'bob', instruction: '把日志收一下', error: '',
  });
  assert.deepEqual(parseGroupTask('   /TaSk    @bob     把日志收一下   '), {
    isTask: true, target: 'bob', instruction: '把日志收一下', error: '',
  });
  assert.deepEqual(parseGroupTask('/task@bob 把日志收一下'), {
    isTask: true, target: 'bob', instruction: '把日志收一下', error: '',
  });
  assert.deepEqual(parseGroupTask('/task @bob 把  日志\n收一下'), {
    isTask: true, target: 'bob', instruction: '把  日志\n收一下', error: '',
  });
});

test('T1 解析：目标可以是 peerId，指令里的 @ 原样保留', () => {
  assert.deepEqual(parseGroupTask('/task @peer-nas 重启一下'), {
    isTask: true, target: 'peer-nas', instruction: '重启一下', error: '',
  });
  assert.deepEqual(parseGroupTask('/task @bob 把 @alice 的日志收一下'), {
    isTask: true, target: 'bob', instruction: '把 @alice 的日志收一下', error: '',
  });
  assert.deepEqual(parseGroupTask('/task @bob @alice 收日志'), {
    isTask: true, target: 'bob', instruction: '@alice 收日志', error: '',
  });
});

test('S4 十档回执文案（zh）都点到了目标（语法档除外）、且没有一档带正文', () => {
  const texts = {};
  for (const outcome of TASK_OUTCOMES) {
    texts[outcome] = buildTaskReceipt({ target: 'nas-box', outcome, taskId: 'abcdef0123456789' });
    assert.ok(CJK.test(texts[outcome]), outcome + ' zh 格是中文');
    // 语法档没有可以点名的目标，其余七档必须点名
    if (outcome !== 'refused-no-target' && outcome !== 'refused-no-instruction') {
      assert.ok(texts[outcome].includes('nas-box'), outcome + ' 要点名目标');
    }
  }
  assert.deepEqual(texts, {
    dispatched: '任务 → nas-box：已转私聊',
    'pending-approval': '任务 → nas-box：待批准（#abcdef01）',
    'refused-no-target': '任务：缺少派给谁（用 @成员）',
    'refused-no-instruction': '任务：缺少内容',
    'refused-unknown-member': '任务 → nas-box：找不到该成员',
    'refused-self': '任务 → nas-box：不能派给自己',
    'refused-not-member': '任务 → nas-box：不是本群成员',
    'refused-offline': '任务 → nas-box：对方当前离线',
    'refused-unpaired': '任务 → nas-box：未与该成员配对',
    error: '任务 → nas-box：转派失败',
  });
});

test('T4 回执只带 approvalId 前 8 位，其它档位一个 id 字符都不带', () => {
  const full = 'abcdef0123456789ffff';
  const pending = buildTaskReceipt({ target: 'bob', outcome: 'pending-approval', taskId: full });
  assert.ok(pending.includes('#abcdef01'));
  assert.equal(pending.includes(full), false);
  assert.equal(pending.includes('abcdef01' + full.slice(TASK_ID_PREFIX_CHARS)), false);
  const dispatched = buildTaskReceipt({ target: 'bob', outcome: 'dispatched', taskId: full });
  assert.equal(dispatched.includes('abcdef01'), false, '非待批准档不带 id');
  // 未知档位一律按「转派失败」，绝不抛错、也绝不把未知串拼进正文
  assert.equal(buildTaskReceipt({ target: 'bob', outcome: 'who-knows' }), '任务 → bob：转派失败');
  assert.equal(buildTaskReceipt({}), '任务 → ?：转派失败');
});

test('T7 词表：十档 zh+en 都在，en 格没有中文，也没有回落成 key 名', () => {
  const zhKeys = keys('zh');
  const enKeys = keys('en');
  const wanted = [
    'group.task.dispatched',
    'group.task.pendingApproval',
    'group.task.refusedNoTarget',
    'group.task.refusedNoInstruction',
    'group.task.refusedUnknownMember',
    'group.task.refusedSelf',
    'group.task.refusedNotMember',
    'group.task.refusedOffline',
    'group.task.refusedUnpaired',
    'group.task.error',
  ];
  assert.equal(wanted.length, TASK_OUTCOMES.length, '每一档都要有一条 key');
  for (const key of wanted) {
    assert.ok(zhKeys.includes(key), 'zh 缺 ' + key);
    assert.ok(enKeys.includes(key), 'en 缺 ' + key);
    assert.notEqual(t('en', key, { name: 'bob', id: 'abcdef01' }), key, 'en 不能回落成 key 名');
    assert.equal(CJK.test(t('en', key, { name: 'bob', id: 'abcdef01' })), false, key + ' 的 en 格不许有中文');
  }
  // 两个语法档的 en 文案逐字钉住
  assert.equal(t('en', 'group.task.refusedNoTarget'), 'Task: missing target (use @member)');
  assert.equal(t('en', 'group.task.refusedNoInstruction'), 'Task: missing instruction');
  assert.equal(t('en', 'group.task.refusedUnpaired', { name: 'bob' }), 'Task → bob: not paired with that member');
  // 十档 * 两格 = 20 条非空文案
  let checked = 0;
  for (const outcome of TASK_OUTCOMES) {
    for (const lang of ['zh', 'en']) {
      const text = buildTaskReceipt({ target: 'bob', outcome, lang });
      assert.equal(typeof text, 'string');
      assert.ok(text.length > 0, lang + '/' + outcome + ' 不能是空串');
      assert.notEqual(text, 'group.task.' + outcome);
      checked += 1;
    }
  }
  assert.equal(checked, 20);
});
