/**
 * 调用方视角的答复口径（lib/tools.mjs 的 lan_peer_ask 描述）
 *
 * 铁律：模型读到的说明必须与执行侧的事实一致 —— 答复就是**对端最后一条消息的正文**
 * （不会被推送回来），对端跑完却没正文时拿到的是 `empty-reply` 失败。
 * 描述与 lib/runner-dsh.mjs / lib/runner-ctx.mjs 的实现漂移，就是一次「模型按说明
 * 理解、结果完全对不上」的谎。
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createLanPeerTools } from './tools.mjs';

async function askDescription() {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lan-peers-tools-'));
  // defineTool 注入成恒等函数：只读工具定义，不需要 DSH 运行时
  const tools = await createLanPeerTools({ stateDir }, { defineTool: (spec) => spec });
  const ask = tools.find((tool) => tool.name === 'lan_peer_ask');
  assert.ok(ask, 'lan_peer_ask 必须存在');
  fs.rmSync(stateDir, { recursive: true, force: true });
  return String(ask.description ?? '');
}

test('§4 lan_peer_ask 描述：答复是对端最后一条消息，empty-reply 表示跑完却没给答复', async () => {
  const description = await askDescription();
  assert.match(description, /The reply is the peer's final message, returned verbatim/);
  assert.match(description, /nothing is pushed back before it finishes/);
  assert.match(description, /an `empty-reply` error means the peer finished without producing one/);
  // 原有口径不能被改掉（配对/工作区/额度那几句仍在）
  assert.match(description, /spends its own model quota/);
});
