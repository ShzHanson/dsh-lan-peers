# 局域网 DSH 协同插件 · dsh-lan-peers

让同一局域网内的多个 **DeepSeek Harness (DSH)** 实例互认并协同：一次性配对码建立双向密钥，之后一个 agent 可以直接把任务派给另一个 agent，并取回它的回复。

```
┌──────────────┐   签名 + AES-256-GCM 加密    ┌──────────────┐
│  DSH (A)     │ ───────────────────────────▶ │  DSH (B)     │
│ lan_peer_ask │   POST /v1/ask                │  :7788       │
│              │ ◀─────────────────────────── │  peer server │
└──────────────┘   GET  /v1/answer (加密)      └──────────────┘
```

## 能力

| 面 | 内容 |
|---|---|
| 模型工具 | `lan_peers`（列出伙伴 + 在线探测）、`lan_peer_ask`（给伙伴派单并取回结果）、`lan_peer_send_file`（只发报价，字节留在本机，对端按需来拉） |
| 界面 | Web / 桌面窗口左下角的 **🔗 伙伴** 面板：改设备名、生成临时配对码、添加伙伴 |
| 认证 | 一次性 6 位配对码（10 分钟、单次），每对伙伴两把独立密钥 |
| 传输 | HMAC-SHA256 请求签名（±60s 时钟窗 + nonce 防重放），请求与响应体积用 **AES-256-GCM** 加密 |
| 隔离 | 默认拒绝远端派单；可配 CIDR 白名单；专用工作目录 |

## 环境要求

- DSH `>= 0.2.0-rc.2`（已在 0.2.1-rc.2 的 Node 版与桌面版上验证）
- Node.js 22 / 24（插件本身无第三方依赖，只用 Node 内置模块）

## 安装

### 1. 装包

```bash
# 从 tarball（releases 产出的 dsh-lan-peers-x.y.z.tgz）
dsh plugin --profile web add /path/to/dsh-lan-peers-<version>.tgz

# 或本地目录（开发时）
dsh plugin --profile web add link:/path/to/dsh-lan-peers

# 或发布 registry 之后
dsh plugin --profile web add dsh-lan-peers
```

这一步只把包放进 profile 的 `node_modules` 与 `package.json`。

### 2. 必须把插件登记为 profile bundle

**最容易踩的坑**：只写 `cordis.patch.yml` 的插件行，桌面版不会加载（网页版有时会，行为不一致）。把包名加进 profile 的 `dsh.profile.bundles`：

```jsonc
// ~/.dsh/profiles/web/package.json
{
  "dsh": {
    "profile": {
      "bundles": [
        "@deepseek-ai/dsh-base",
        "@deepseek-ai/dsh-web-app",
        // …
        "dsh-lan-peers"       // ← 加这一行
      ]
    }
  }
}
```

### 3. 配置

包自带的 `cordis.patch.yml` 会插入一行默认配置（端口 7788、拒绝远端派单）。要改就在 profile 的 `cordis.patch.yml` 里按 id 覆盖：

```yaml
- id: lan-peers
  name: dsh-lan-peers
  config:
    name: my-nas                  # 显示给伙伴的名字
    listenPort: 7788              # 监听 0.0.0.0:<port>
    stateDir: ~/.dsh/lan-peers    # 身份与伙伴表位置
    workspace: ~/.dsh/lan-peers/workspace   # 远端派单会话的工作目录
    allowRemotePrompts: false     # 默认关；打开后才接受别人的派单
    requireEncryption: true       # 默认开；旧版本对端会被拒绝
    trustedCidrs: ["192.168.1.0/24"]  # 可选，限制来源网段
    agentPreset: standard
```

各平台的参考覆盖片段在 `overlays/`：

- `overlays/web.patch.yml` —— 网页版（浏览器访问）
- `overlays/desktop.patch.yml` —— 桌面版（Electron）

### 4. 重启 DSH

```bash
# 网页版：重启 dsh web
# 桌面版：退出并重新打开应用
```

重启后 `http://<本机IP>:7788/v1/health` 应返回 `{"name":"…","capability":["ask","pair",…]}`（能力表随版本增长，以实际返回为准）。

> 桌面版 profile 由 Electron 独占管理，`dsh plugin --profile desktop` 会被拒绝。请按 `overlays/desktop.patch.yml` 手工编辑 `~/.dsh/profiles/desktop/{package.json,cordis.patch.yml}`，然后重启应用。

## 配对

**界面**：左下角 🔗 伙伴 → 「生成配对码」，把 6 位码给对方；对方在「添加伙伴」里填本机地址（如 `192.168.1.10:7788`）+ 码。两个方向各配一次，双方都能主动派单。

**命令行**：

```bash
npx dsh-lan-peers code  --state-dir ~/.dsh/lan-peers
npx dsh-lan-peers pair  --url http://192.168.1.10:7788 --code 123456 --name my-nas
npx dsh-lan-peers peers --probe
```

## 使用

模型侧（会话里直接说）：

> 用 lan_peer_ask 问 my-nas：`/data/project` 下 `pwd` 输出什么？

命令行：

```bash
npx dsh-lan-peers ask --peer my-nas "在 /data/project 执行 pwd" --timeout 120
```

对端会在自己的 `workspace` 里建真实会话、由对端模型执行，然后把最终回复加密回传。

## 文件收发

**模型**：发送方只发一份**报价**——文件名、体积、sha256、来自谁、时间，**一个字节都不发**；接收方点「下载」时字节才被拉过来；落盘前先核对整文件 sha256，对不上就失败、盘上不留半截文件；默认要先问一句，只有把那个人标成「信任」之后私聊文件才不再问（per-peer，记在本机）。

**私聊**：字节始终留在**发送方**（`<stateDir>/outbox`，配额 5 GiB，7 天没被拉过就过期，超配额时最久没被拉取的先逐出）。所以**发送方离线时这份文件就下不下来**——这是刻意的取舍：私聊文件不占 NAS 的盘。

**群聊**：由 **hub** 保管一份（总量 20 GiB，超了按最久没被访问的先逐出）；一份文件可以点名 全体成员 或 单个成员，没被点名的人在群里**根本看不到这一行**；被 hub 逐出的文件，成员面板上显示「已失效」，点下载得 `409 file-gone`。

**撤回**：只有**还没被下载过**的报价能撤回；本地这份拷贝要等对端确认后才释放，对端离线时撤回直接失败（`503 peer-offline`），什么都没丢，可以重试。已经下载走的撤不回来——字节已经在对方的盘上。

**命令行 / 工具**：`send-file <peer> <文件>` 现在只挂出报价（agent 侧的 `lan_peer_send_file` 语义相同）；收文件用 `download <fileId>`、不要了用 `decline <fileId>`（面板里就是「下载」那个按钮）。面板里浏览器上传固定上限 512 MiB，`fileMaxBytes` 调大也不放宽；更大的文件走命令行或工具这条路。

## 版本互通

同一个群里允许混版本，但 **0.10 与 0.9.x / 0.8.4 之间有两条硬断裂**；**0.12 又把文件面换了一整套路由**，见下表的 0.12 行与其后的说明。下表是「两端各自正常工作时，用户实际看到的结果」。

| 组合 | 私聊 ask | 群聊 chat | 群内派单 | 群纪要 | 群表决 | 引用行 |
|---|---|---|---|---|---|---|
| 0.12.x ↔ 0.11.x | WORKING | WORKING | 两侧都没有这条线（0.10 起已删除） | WORKING | WORKING | WORKING |
| 0.10.x ↔ 0.9.x | WORKING | WORKING | BROKEN：老节点发的 `progress`/`result` 被 0.10 hub 判 `400 {"error":"bad-request"}`，群里没有「开始/结果」回执 | DEGRADED：老 hub 的 pull 不带 `notes`，成员面板一直空白、不报错 | DEGRADED：同理；成员提提案/投票打到老 hub 得 `404 {"error":"not-found"}` | DEGRADED：老 hub 的 meta 白名单没有 `quote`，静默丢弃，只少「引用 …」那一行 |
| 0.10.x ↔ 0.8.4 | WORKING | WORKING | BROKEN：同上（0.8.4 的回执同样是 `progress`/`result`） | DEGRADED：同上 | DEGRADED：同上 | DEGRADED：同上 |

**变在哪、为什么断**

- **文件传输整条线断了（0.12）**：0.11 的文件路由集是 `/v1/file/{offer,chunk,complete,status}`（推块 + 接收方接受），0.12 换成 `/v1/file/{offer,pull,withdraw}`（报价 + 按需拉取），**没有一条共用语义**——0.12 节点与 0.11 节点之间**两个方向都传不了文件**；聊天与答题不受影响（那两条平面 0.12 没动）。**升级口径**：两台机器要在**同一个窗口**里一起升，否则文件传输会静默不工作 —— 没有版本协商。
- **两条硬断裂**：① 群内派单整条线在 0.10.0 删除（`lan_group_ask`、管理面 `group/dispatch-options` / `group/accept`、执行器、回执），`GROUP_KINDS` 只剩 `['chat','system']`；② 于是老对端继续投 `progress`/`result` 回执一律 `400 {"error":"bad-request"}` —— 老节点那边只留一行 `[group] dispatch receipt failed …` 日志，群里从此看不到派单进度。**历史不会丢**：已有聊天记录里的 `progress`/`result` 仍照常显示成一行系统行。
- **一条软断裂**：`meta.quote` 是 0.10 新增字段，老 hub 的 meta 白名单没有它，**静默丢弃、不报错**（HTTP 仍是 200）。代价是引用行消失，以及「首答胜」的去重判据在跨版本时失效。
- **身份面不是断裂**：0.8.4 只有 v1 群级鉴权（`X-Peer-Auth: group` + groupKey HMAC），0.9 起有 v2（证书 + ed25519），0.10 默认两种都收（`allowLegacyGroupAuth` 默认 true）。
- **私聊 ask 形状没变**：`/v1/answer` 三代一直是 `{status, reply|error, elapsedMs}`；0.10 只多一个错误码 `empty-reply`（对端跑完却没给正文），老调用方按 `peer error: …` 呈报即可。
- `acceptDispatch` 双向安全：0.10 出站不再发 `X-Peer-Accept`，入站遇到老字段直接丢弃；老 hub 缺这个字段按「接单」处理。

**升级口径**：hub 与所有成员**在同一个窗口内一起升到 0.10** —— 跨 0.10 线的群内派单双向都不工作，纪要与表决也要 hub 先到 0.10 才有数据。

> 证据：每格都能追到代码或用例（`host/server.mjs`、`lib/group-*.mjs`、`host/test/group.test.mjs`、`lib/panel-group.test.mjs`）。`interop/run-interop.mjs` 的六行 A–F 目前只覆盖 **0.3.1 基线 ↔ 当前版本**，**不含**上面两组 0.10 组合，也不含 0.12 那组 —— 所以本表是代码路径结论，不是互通实跑结论。

## 安全模型

- 配对码 6 位、10 分钟、一次性；每个伙伴两条独立密钥（我签给你的 / 你签给我的）。
- 每条认证请求验签：五行 canonical、±60s 时钟窗、nonce 防重放、定时安全比较。
- **报文加密**：`/v1/ask`、`/v1/answer`、`/v1/peers` 的请求体与响应体用 AES-256-GCM 加密，密钥由该方向 HMAC 密钥经 HKDF 派生；缺 `X-Peer-Enc` 的请求返回 `400 encryption-required`。
- `/v1/health` 公开；`/v1/pair` 因尚无共享密钥仍是明文——**只应在可信局域网内配对**。
- 管理接口（改名/发码/配对）只在 `/api/lan-peers/*` 且要求 Host 为回环地址，局域网访问 403。
- `allowRemotePrompts` 默认 `false`：装完不会自动被别人驱动。

## 故障排查

| 现象 | 原因 / 处理 |
|---|---|
| 装完没有 7788 监听、日志无输出 | 插件没进 `dsh.profile.bundles`（安装第 2 步） |
| 启动日志 `is incompatible with dsh …` | 插件 `engines.dsh` 高于本机运行时；升级 DSH 或改 `engines` |
| `EADDRINUSE ... :7788` | 同机跑了两个 DSH 实例；给其中一个改 `listenPort` |
| 面板看不到 | 注入只对 HTTP 页面生效；桌面窗口是 `dsh-app://`，走 `lib/client.js` 客户端插件，需重启应用 |
| `400 encryption-required` | 对端是加密前的旧版本，两端都升级 |
| `401 bad-signature` / `clock-skew` / `replay` | 两端时钟偏差超过 60s、密钥不一致，或 nonce 重放 |

## 开发

```bash
node --test host/test/auth.test.mjs host/test/api.test.mjs   # 协议/端点
node --test lib/wire-crypto.test.mjs                          # 加密
node host/server.mjs --port 7799 --state-dir /tmp/lp          # 独立 host（内存 runner）
```

## 许可

MIT
