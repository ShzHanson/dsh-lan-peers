# 新-旧互通 harness（黑盒 / 真实进程）

冻结契约 v0.4.0 的兼容矩阵验证工具。**只读使用两个代码树，不修改任何仓库源码。**

- 被测（新）：`<repo>`（本仓库根目录）
- 对照（旧 0.3.1 只读快照）：`<baseline>`（自行准备）
- 本目录（唯一可写区）：`<repo>/interop/**`

## 怎么跑

```bash
cd <repo-parent>
node interop/run-interop.mjs
echo $?          # 0=全通过 / 1=有 FAIL / 2=harness 自身故障（起不来、硬超时）
```

单次运行约 17 秒（硬上限 170s）。想留一份可读日志就重定向到 **`state/` 以外**的地方
（`state/` 每次运行开头会被整体清空，写进去会被删掉）：

```bash
cd <repo> && node interop/run-interop.mjs > interop/last-run.txt 2>&1; echo $?
```

跑完 `state/` 下留：

| 路径 | 内容 |
|---|---|
| `state/modern.log` | 新服务端完整 stdout（含每条请求的 `<ISO> METHOD PATH status elapsedms peer=` 行） |
| `state/legacy.log` | 旧服务端完整 stdout |
| `state/report.json` | 机器可读结论：每个用例、每条断言的 PASS/FAIL/SKIP 与证据 |
| `state/server-*/` | 两个服务端各自的 state-dir（state.json / peers.json，含临时密钥，**不要外传**） |
| `state/client-*/` | 各用例的客户端 state-dir（每个用例独立，互不干扰） |

`state/` 在每次运行开头被整体清空，重复跑不会互相污染。

## 它到底测什么

起两个真实的 `node host/server.mjs` 进程（各自随机空闲端口 + 独立 state-dir + `--allow-remote-prompts`），
再用**两侧真实的 `client/cli.mjs` / `client/peer-call.mjs`** 驱动冻结契约的兼容矩阵。
没有 mock、没有用直接调库函数替代端到端路径。

### 兼容矩阵四行（A-D，矩阵必需）

| 用例 | 组合 | 断言 | 证据从哪来 |
|---|---|---|---|
| **A** | 旧 0.3.1 客户端 → 新服务端 | 明文 `POST /v1/pair`（无 ecdh 字段）仍成功；随后加密派单拿到 reply；`capability` 仍含 `ask`/`pair`；**并**要求新服务端日志出现弃用告警 `pair: legacy plaintext path used by <peerId>` | 旧 CLI 的 stdout/stderr、新服务端日志里的 `POST /v1/pair 200 ...ms` 与告警行 |
| **B** | 新客户端 → 旧 0.3.1 服务端 | 自动回退明文配对成功并派单拿到 reply；以旧服务端 `capability` 不含 `pair-ecdh` 作为「只能走明文」的证明 | 旧服务端日志里 `POST /v1/pair 200` / `GET /v1/answer 200` 的条数 |
| **C** | 旧客户端 → 新服务端 `/v1/answer`（**不带** waitMs） | 立即返回（`< 800ms`，未被 hold）；`status` 合法；键集相对 0.3.1 只允许新增 `elapsedMs`（同场景对旧服务端跑一遍做基线对照） | 计时 + 两侧响应键集对比 |
| **D** | 新客户端 → 旧 0.3.1 服务端 | 回退 1.5s 轮询并拿到 reply：旧服务端日志有 `GET /v1/answer 200`、CLI 耗时 `>= 1400ms`，且没有对旧服务端成功使用 SSE（`/v1/events 2xx = 0`） | 旧服务端日志 + CLI 计时 |

### EXTRA 两个（E-F，非矩阵必需，但同属冻结契约）

| 用例 | 测什么 |
|---|---|
| **E** | 用 harness **自己实现的** ECDH/HKDF（P-256 + HKDF-SHA256，salt=`dsh-lan-peers/pair/v1`，info=`.../pair/wrap/v1`）走完 `/v1/pair` → `/v1/pair/confirm`：round1 返回 65 字节服务端公钥 + `pairingTtlMs=120000`；**round1 不消费配对码**（同码仍能走明文配对）；confirm 解出 S 并换回 `wrapped(T)`，且换出的 T 真能签名调 `/v1/peers`、派单、`waitMs` 长轮询拿到 done；否定用例 401 `invalid-code` / 400 `bad-request` / 400 `bad-encryption`；最后用**新 CLI** 默认 `auto` 模式配对，断言它确实选中 ECDH（`pairPeer` 端到端）并能继续派单 |
| **F** | `GET /v1/events` SSE：200 + `text/event-stream`、终态后主动 end 流、事件名 `status`/`done`、**每条事件独立加密**（harness 用 baseline 的 wire-crypto 逐条解密并校验 nonce 互不相同）；再用新客户端 `client/sse.mjs` 的 `readPeerEvents` 走一遍拿到 done；最后对旧服务端（无该端点）应返回 `ok:false reason=http-404`，这正是客户端回退长轮询的触发条件；最后用**新 CLI** `ask` 打新服务端，断言服务端日志出现 `GET /v1/events 200`（即真的走了 SSE 而不是轮询） |

### 自适应（不硬编码 0.4.0）

启动后先读两个服务端的 `/v1/health.capability`，据此开关所有 0.4.0-only 断言：

- 新服务端没有 `pair-ecdh` → A 的弃用告警断言、E 全部 = **SKIP**
- 新服务端没有 `stream` → C 的 `elapsedMs` 断言、F 全部 = **SKIP**

所以同一份文件在「新服务端仍是 0.3.1 行为」的旧状态下也能跑完，只出 SKIP 不出 FAIL；
而 A/B/C/D 四行的 0.3.1 老语义断言在**任何状态**下都必须 PASS。

这条自适应可以直接用一条命令自证（把「被测」指回 0.3.1 基线，模拟 0.4.0 还没落地）：

```bash
cd <repo-parent> && INTEROP_NEW_ROOT=../.tmp/baseline-0.3.1 node interop/run-interop.mjs
# 预期：A/B/C/D PASS，E/F 全 SKIP，退出码 0（不是 FAIL）
```

## 稳定性设计

- **端口冲突自愈**：先 `net.createServer().listen(0)` 拿空闲端口；启动后 15s 内探 `/v1/health`，进程退出或探活失败就换端口重试，最多 3 次。
- **每个 HTTP 调用都有超时**：`fetch` 一律带 `AbortSignal.timeout`；CLI 子进程 40s 硬超时 + `SIGKILL`。
- **不留僵尸**：所有子进程登记在 `LIVE` 集合，`finally` 里 `SIGTERM` → 2.5s 未退再 `taskkill /T /F`；另有 170s 全局硬超时兜底，触发时先回收再 `exit(2)`。
- **端口回收自检**：跑完再尝试 bind 那两个端口，仍被占就多一条 FAIL 行 —— 这就是验收要求「netstat 无遗留监听」的机器化版本。
- **有界等待**：派单类用例统一 `--timeout 20` 秒 + 有限次轮询，没有无限循环。

## 今日实跑结论（2026-10-27，新仓库 = 0.4.0）

```
legacy(0.3.1) capability=["ask","pair"]
modern(0.4.0) capability=["ask","pair","pair-ecdh","stream"]

A PASS  旧客户端→新服务端：明文配对 200 (15.3ms) + 派单 OK + 日志有 legacy plaintext path 告警
B PASS  新客户端→旧服务端：明文回退配对 OK + 派单 reply OK (1759ms, poll=2)
C PASS  旧客户端→新服务端 /v1/answer 无 waitMs：6ms 立即返回，keys 只多了 elapsedMs
D PASS  新客户端→旧服务端：poll=5 · elapsed=1755ms >= 1400ms · /v1/events 2xx=0
E PASS  ECDH：round1 不消费码、confirm 换出 T 且 T 可签名派单、3 个否定用例符合契约、新 CLI auto 选中 ECDH
F PASS  SSE：2 条事件独立解密、nonce 全不同、终态 end 流、回退信号 http-404、新 CLI ask 走 SSE
端口回收：两个端口均已释放
退出码：0
```

## 已知限制 / 演进说明

1. **B/D 曾被真实缺陷阻塞，现已解除**（记下来是因为这正是本 harness 的价值所在）：0.4.0 工作副本一度把
   `client/peer-call.mjs` 的 `callPeer` 改成 `body: wire.length ? wire : Buffer.alloc(0)`，对 GET 也塞了
   0 长度 body，命中 undici 的 `Request with GET/HEAD method cannot have body` 硬规则 —— 新客户端取答复
   （`/v1/answer` 轮询、`/v1/peers`）全线失败，而单元测试因为注入了 `fetchImpl` 恰好绕开这条规则，仍然全绿。
   修好后 B/D 自动转 PASS，**harness 未做任何 workaround**（没有给 GET 加 body、没有换 HTTP 客户端）。复跑还是同一条命令：

   ```bash
   cd <repo> && node interop/run-interop.mjs
   ```

2. **`client/cli.mjs` 已迁移到 `pairPeer` / `awaitPeerAnswer`**，所以 B/D 验的就是上层编排的真实行为：
   B = 新 CLI `pairPeer` 对 0.3.1 对端自动回退明文；D = 新 CLI `awaitPeerAnswer` 对 0.3.1 对端自动回退 1.5s 轮询。
   E/F 再补 CLI 端到端的反向验证：对新服务端时 `auto` 必须选中 ECDH、`ask` 必须真的走 SSE（服务端出现 `/v1/events 200`），
   而不是「声明支持却悄悄退回轮询」。这四条断言合起来封住了「静默降级」这条最容易混过去的路径。
   注：早期版本 CLI 还是 0.3.1 的轮询循环时，B/D 也照样能跑 —— 断言只看服务端日志与最终 reply，不看客户端实现。
3. **单配对码槽位**：服务端 `state.json` 只存一个码，后出的码会顶掉前一个。任何「先出两个码」的写法都是错的
   （本 harness 全程只持有一个未消费的码；E 的「不消费」用例是在 confirm 消费掉旧码之后才出新码）。
4. **只监听回环**：两个服务端都在 `127.0.0.1`，未覆盖 `trustedCidrs` / 真实局域网路径；跨机互通（NAS ↔ 桌面）
   仍按 HANDOVER §8 的回归清单人工验。
5. **`MemoryRunner` 是 1 秒的假 runner**：`reply` 恒为 `OK <prompt 前 20 字>`，所以断言只校验「非空且以 OK 开头」，
   不校验真实模型输出。
6. **未覆盖**：`answerWaitMs` / `pairingMode` 两个配置项的取值行为（要改服务端启动参数，属实现方单测范围）；
   `ping` 事件（10s 间隔，会显著拉长单次运行时间）。