// dsh-lan-peers · i18n (v0.8.5-α §0.7b)
//
// 纯对象 + 零依赖：一个词表、两个函数。
//   resolveLang(config) -> 'zh' | 'en'   决定用哪一格词表
//   t(lang, key, params) -> string       取一条文案（{name} 插值，缺 key 回落英文，再缺原样返回 key）
//
// 铁律（契约 §0）：
//   - 日志与协议字段绝不进本文件 —— 日志是排障稳定格式，协议字段（unpaired / not-accepting
//     这类 reason、HTTP 状态码、命令名、参数名、退出码）是线格式，任何语言下都保持英文原样；
//   - 词表里不得出现密钥、token、内网 IP、用户名。
//
// 分域：cli.*   命令行帮助与成功/失败文案（本批已接线）
//       panel.* 面板文案（本批只铺 key 与一份占位值，面板 lane 接线时按语言拆成两份）

export const LANGS = ['zh', 'en'];
export const DEFAULT_LANG = 'zh';
export const ENV_LANG_VAR = 'DSH_LAN_PEERS_LANG';

// ---------------------------------------------------------------------------
// 词表：cli 域（中文格，缺英文时由 en 格兜底）
// ---------------------------------------------------------------------------

const CLI_TEXT = {
  // ---- 帮助（--help / group help / 用法错误的尾巴）----
  'cli.help.usage': [
    'dsh-lan-peers — 局域网伙伴 CLI',
    '',
    '用法: dsh-lan-peers <子命令> [选项]',
    '',
    '子命令:',
    '  code    生成一次性配对码（6 位，10 分钟，一次性）',
    '  pair    用配对码与对端互认（ECDH 两轮，自动回退旧明文）',
    '  peers   列出已配对伙伴',
    '  ask     向伙伴派单并等待回复',
    '  events  订阅伙伴 /v1/events 事件流（排障）',
    '  unpair  解除与某个伙伴的配对（尽力通知对端）',
    '  group   群聊：state / post / history / tail / join / probe / replica',
    '  dm      私聊：<peer> <正文> [--workspace <id>] [--perm <档>] 发一条 / log <peer> 看历史 / sync <peer> 对齐',
    '  dispatch 派单设置：pending / approve <id> / reject <id> / settings [--default <id>] [--max-perm <档>]',
    '  send-file <peer> <文件>   分块加密发给伙伴（对端确认后才入 inbox）',
    '  inbox   文件收件箱：list / accept <id> / reject <id>',
    '  help    显示本帮助',
    '',
    '全局选项:',
    '  --state-dir <路径>   状态目录（默认 ~/.dsh/lan-peers）',
    '  --lang <zh|en>       输出语言（默认 auto：先看配置 lang，再看环境变量 DSH_LAN_PEERS_LANG，最后看系统语言）',
    '  --help               查看子命令用法',
  ].join('\n'),
  'cli.help.code': [
    '用法: dsh-lan-peers code [--state-dir <目录>] [--url <本机管理接口>]',
    '',
    '请本机 host 生成一次性配对码（10 分钟有效，用后即焚）。',
    'M6 起码只活在 host 进程内存里：本命令是独立进程，自己生成的码对正在跑的 host 无效，',
    '所以必须先启动本机 host（或直接用界面面板的「生成配对码」）。',
  ].join('\n'),
  'cli.help.pair': [
    '用法: dsh-lan-peers pair --url http://PEER:7788 --code 123456 [--name 本机名] [--peer-name 对端名] [--legacy-pair]',
    '',
    '默认自适应：对端 /v1/health 的 capability 含 "pair-ecdh" 时走 ECDH 两轮',
    '（/v1/pair 交换临时公钥 → /v1/pair/confirm 用派生密钥包裹初始密钥），',
    '否则回退 0.3.1 的明文 /v1/pair。',
    '',
    '  --legacy-pair   强制旧明文路径（对端 0.3.1 或排障用）',
    '  --ecdh-pair     强制 ECDH，对端不支持则报错',
    '  --base-url      本机对外的可达地址（默认自动探测私有 IPv4 + 7788；',
    '                  会随配对请求发给对端，缺了它伙伴那边这条记录就没有地址）',
    '  --port          自动探测地址时用的端口（默认 7788；只在没给 --base-url 时有效）',
  ].join('\n'),
  'cli.help.peers': [
    '用法: dsh-lan-peers peers [--probe] [--state-dir <目录>]',
    '',
    '  --probe   逐个探活（GET /v1/health，2 秒超时）',
  ].join('\n'),
  'cli.help.ask': [
    '用法: dsh-lan-peers ask --peer <peerId|名字> "prompt" [--timeout 300] [--legacy-poll] [--wait-ms 25000]',
    '',
    '对端声明 "stream" 时走 /v1/events（SSE），否则 /v1/answer 长轮询；',
    '--legacy-poll 强制 0.3.1 的 1.5 秒轮询（不带 waitMs）。',
  ].join('\n'),
  'cli.help.events': [
    '用法: dsh-lan-peers events --peer <peerId|名字> --session <sessionId> [--duration 300] [--verbose]',
    '',
    '订阅对端 /v1/events：每条事件独立加密，此处解密后逐条打印。',
    '对端 capability 不含 "stream" 时直接报错（0.3.1 没有该端点）。',
    '',
    '  --duration <秒>   最长订阅时间（默认 300）',
    '  --verbose         同时打印 ping 心跳',
  ].join('\n'),
  'cli.help.unpair': [
    '用法: dsh-lan-peers unpair --peer <peerId|名字> [--local-only] [--timeout 10] [--state-dir <目录>]',
    '',
    '解除本端与某个伙伴的配对。默认先探活：对端声明 "unpair" 能力时发一次签名',
    'POST /v1/unpair 让它也删掉本端；不可达/旧版本/失败都只记录原因，本地一定删除。',
    '',
    '  --local-only     跳过对端通知，只删本地记录',
    '  --timeout <秒>   通知对端的超时（默认 10）',
  ].join('\n'),
  'cli.help.group': [
    '用法: dsh-lan-peers group <子命令> [--peer <hub 名字|peerId>] [--state-dir <目录>]',
    '',
    '子命令:',
    '  state                     群信息 + 成员表（会拿到 groupKey，但不打印内容）',
    '  post --text "..."         发一条消息 [--kind chat|progress|result|system]',
    '                            正文含 @!名字 时作者侧自动派单（由本机 host 执行并打印回执摘要）',
    '  dispatch <目标> <任务...>  等价发一条 "@!目标 任务" 并派单，打印回执摘要',
    '  accept on|off             切换本机接单（写 profile 配置，热生效）',
    '  history [--since N]       取历史消息 [--limit 1..200]',
    '  tail [--since N]          跟随事件流并逐条打印 [--duration 秒]',
    '  join [--name 显示名]      向 hub 自助加入（hub 开了 autoJoin 才成功）',
    '  probe [--peer 名字|peerId] 群级探活：打印 peerId/epoch/lastSeq/可达地址',
    '  replica                   打印本地群副本（groupId/epoch/leader/lastSeq/条数）',
    '  leader [--peer X]         查看本机角色/epoch/租约（--peer 时改看对端 live 快照）',
    '  claim [--url http://…]    手动接管：让本机立刻发起选举成为 leader',
    '  find --name <群名>        按群名查找（先查本地已知群，再并发问所有伙伴，2 秒超时）',
    '  apply --name <群名>       按群名申请入群：申请 → 轮询 → 拿到授权后落 group-key.json',
    '  advertise                 把本机群名广播给我的伙伴（无节流，打印发送对象清单）',
    '  archives                  列出 hub 侧归档文件（走本机回环管理接口，只读）',
    '  archive-delete <file>     删除一个归档文件（不可撤销；seq 号不复用）',
    '',
    '  --peer        hub 的名字或 peerId；只有一个伙伴时可省略',
    '  --name        join 时上报的本机显示名（不传则用 state.json 的名字 / hostname；',
    '                同机跑多个节点时用它避免成员表撞名）',
    '  --state-dir   状态目录（默认 ~/.dsh/lan-peers）',
    '  --url         claim 的目标（默认 http://127.0.0.1:7788 = peer 端口）/ 管理接口要打的本机',
    '                地址（默认读 <stateDir>/admin-url，由面板或 host 自己写下来）',
    '  --hub-url     advertise 时对外公布的 hub 地址（默认取群成员表里 hub 自报的地址）',
    '  --base-url    apply 时公布的申请者地址（默认留空，由介绍人按配对记录补）',
    '  --timeout     apply 的等待秒数（默认 600 = 契约 §5.2 的 10 分钟上限）',
    '  --interval    apply 的轮询毫秒数（默认 5000）',
    '',
    'group 端点只有 hub 提供；本机的伙伴列表里要先有 hub 的配对记录。',
    'S3 起 leader 由选举产生：claim 打本机回环（群级签名，正文用本机实例 id）。',
  ].join('\n'),
  'cli.help.sendFile': [
    '用法: dsh-lan-peers send-file <peer> <文件> [--url <本机管理接口>] [--state-dir <目录>]',
    '',
    '把本机一个文件分块加密发给伙伴（契约 §1：offer → chunk → complete，逐块 AES-256-GCM）。',
    '对端落在它自己的 inbox 里、等它确认；**本命令无法指定对端路径**（契约 §0）。',
    '打印: id / bytes / sha256 / ms —— sha256 是整文件的摘要，可直接和对端核对。',
    'TTY 上每 0.5s 刷一次进度：有 id 时报「已发 X/Y 字节（Z%）」，拿不到 id 时报已用时长。',
    '',
    '  --url   本机 host 的管理接口（默认读 <stateDir>/admin-url；地址未知时会报错让你指定）',
  ].join('\n'),
  'cli.help.inbox': [
    '用法: dsh-lan-peers inbox <list|accept|reject> [id] [--url <地址>] [--state-dir <目录>]',
    '',
    '  list            待确认文件与已收文件（id / 文件名 / 体积 / sha256 / 来源 / 时间）',
    '  accept <id>     接受一个待确认文件：移入 inbox 并打印落盘路径',
    '  reject <id>     拒收并删除（10 分钟未确认的也会自动走这条路）',
    '',
    '  --url   本机 host 的管理接口（默认读 <stateDir>/admin-url；地址未知时会报错让你指定）',
  ].join('\n'),
  'cli.help.dm': [
    '用法: dsh-lan-peers dm <peer> <正文> [--workspace <id>] [--perm <档>] [--url <地址>] [--state-dir <目录>]',
    '      dsh-lan-peers dm log <peer> [--limit N]',
    '      dsh-lan-peers dm sync <peer>',
    '',
    '私聊（1:1 连续会话）：正文只发给这一个伙伴 —— 不进群历史、不进群日志。',
    '伙伴密钥、签名与落盘都在本机 host 里，所以三条命令都只打本机回环管理接口。',
    '',
    '  <peer> <正文>   发一条并打印回复；同一伙伴连续发会复用会话（看 reused / sessionId）',
    '  log <peer>      打印本机这一对的私聊历史（时间 / 方向 / id / 正文）',
    '  sync <peer>     与对端交换双方缺失的条目（面板打开私聊时也会自动做一次）',
    '',
    '  --limit N   log 只打印最近 N 条（默认 20）',
    '  --workspace <id>  点名对端的某个工作区（不认识的 id 会被对端拒绝：unknown-workspace）',
    '  --perm <档>       这次派单申请 read-only | workspace-write | danger-full-access；',
    '                    超过对端上限直接 403，超过对端默认档要它人工确认（等待 approvalId）',
    '  --url       本机 host 的管理接口（默认读 <stateDir>/admin-url）',
  ].join('\n'),

  // ---- 通用 ----
  'cli.common.unknownSubcommand': '未知子命令: {name}',
  'cli.common.unknownPeer': '未知对端: {peer}',
  'cli.common.ambiguousPeer': '对端名字有歧义: {peer} 命中 {count} 条，请改用 peerId',
  'cli.common.unnamed': '(无名)',
  'cli.common.inboundOnly': '(仅入站)',
  'cli.common.unknown': '未知',
  'cli.common.localAdmin': '本机管理接口',
  'cli.common.sending': '发送中 → {label} · {bytes} 字节',
  'cli.common.emptyReply': '（空）',

  // ---- code ----
  'cli.code.hostRefused': '生成配对码失败：本机 host 未接受 {url}（{reason}）\n修法：请先启动本机 host（或用界面面板的「生成配对码」）—— 码只能在 host 进程里生成',
  'cli.code.badShape': '生成配对码失败：本机 host 未按契约回 6 位码',
  'cli.code.ok': '配对码: {code}   有效期: 10 分钟，一次性',
  'cli.code.hintFillPeer': '对方把它填进「添加伙伴」里即可配对（地址填本机 http://<ip>:7788）',
  'cli.code.hintMemoryOnly': '提示: 这个码只在本机 host 进程里有效，重启 host 即失效',

  // ---- pair ----
  'cli.pair.transportEcdh': 'ECDH 两轮',
  'cli.pair.transportLegacy': '旧明文路径',
  'cli.pair.ok': '已配对: {label} ({peerId}) · {transport}',
  'cli.pair.fallbackNoEcdh': '提示: 对端未声明 pair-ecdh，已回退旧明文配对（初始密钥明文传输）',
  'cli.pair.fallbackNoModule': '提示: 本构建缺少 lib/pairing-ecdh.mjs，已回退旧明文配对（初始密钥明文传输）',

  // ---- peers ----
  'cli.peers.empty': '（尚未配对任何对端）',

  // ---- ask / events ----
  'cli.ask.dispatched': '已派单 → {name} (session {sessionId})',
  'cli.ask.peerError': '对端返回错误: {error}',
  'cli.events.noStream': '对端 /v1/health 未声明 "stream" 能力（0.3.1 无该端点），无法订阅事件',
  'cli.events.subscribed': '订阅 {name} 的 /v1/events (session {sessionId})',
  'cli.events.ended': '订阅结束: {reason}',
  'cli.events.finalStatus': '终态: {status}',

  // ---- unpair ----
  'cli.unpair.reasonNoAddress': '未记录对端地址',
  'cli.unpair.reasonNoSecret': '缺少对端密钥',
  'cli.unpair.reasonOffline': '对端不可达',
  'cli.unpair.reasonNoCapability': '对端不支持 unpair',
  'cli.unpair.skippedRemote': '已跳过对端通知（--local-only）',
  'cli.unpair.doneRemote': '已解除与 {label} 的配对（对端已同步删除）',
  'cli.unpair.doneLocal': '已解除与 {label} 的配对（仅本地；原因：{reason}）',

  // ---- group：hub 解析 / state ----
  'cli.group.needPeer': '需要一个 --peer（hub 的名字或 peerId）',
  'cli.group.needPeerCandidates': '，候选: {list}',
  'cli.group.needPeerEmpty': '（本机还没有配对记录）',
  'cli.group.stateHeaderPeer': '群组: {name} ({groupId})  epoch={epoch} keyVersion={keyVersion} 成员={members}',
  'cli.group.stateHeaderKey': '群组: {name} ({groupId})  epoch={epoch} 成员={members}（群级签名直连 {baseUrl}，leader={leader}）',
  'cli.group.groupKeyReceived': '已收到（32B，不显示）',
  'cli.group.groupKeyNotSent': '未下发',
  'cli.group.groupKeyOnDisk': '已在 group-key.json（32B，不显示）',
  'cli.group.groupKeyLine': 'groupKey: {value}',
  'cli.group.memberSelf': 'online(本机)',

  // ---- group：派单摘要 / post ----
  'cli.group.dispatchSkipped': '未派单（消息里没有 @! 目标）: {reason}',
  'cli.group.dispatchAmbiguous': '派单 → {who}：有多个同名成员，请用 @!名字 (短id) 重发',
  'cli.group.dispatchLine': '派单 → {who}：{status}{detail}',
  'cli.group.dispatchDetail': '（{parts}）',
  'cli.group.dispatchChars': '{chars}字',
  'cli.group.dispatchNotTriggered': '消息已发出，但派单未触发：本机 host 未响应 {url}（{reason}）\n修法：先起本机 host（或对 --url 指向的管理接口重试 group dispatch）',
  'cli.group.dispatchNoSummary': '派单未返回结果：本机 host 未按契约回 dispatch 摘要',
  'cli.group.textTooLong': 'text 超过 {max} 字符上限（hub 会回 413 payload-too-large）',
  'cli.group.badKind': '--kind 必须是 {kinds}',
  'cli.group.sent': '已发送 seq={seq} ts={ts}{channel}',
  'cli.group.sentViaGroupKey': '（群级签名直连 {baseUrl}）',
  'cli.group.dispatchUsage': '用法: dsh-lan-peers group dispatch <目标> <任务...>',
  'cli.group.acceptUsage': '用法: dsh-lan-peers group accept on|off',
  'cli.group.acceptFailed': '切换接单失败：本机 host 未接受 {url}（{reason}）\n修法：确认本机 host 在跑且群功能已启用（{reason} 为 501 表示 host 还没接线）',
  'cli.group.acceptOn': '接单中',
  'cli.group.acceptOff': '已关闭',
  'cli.group.acceptEphemeral': '（仅本进程生效，重启后回到配置值）',
  'cli.group.acceptLine': '本机接单：{state}{extra}',

  // ---- group：history / tail / join ----
  'cli.group.historyPeer': '群 {groupId} · {count} 条 · lastSeq={lastSeq}',
  'cli.group.historyKey': '群 {groupId} · {count} 条 · lastSeq={lastSeq}（群级签名直连 {baseUrl}）',
  'cli.group.tailSubscribed': '订阅群事件 sinceSeq={since} ({seconds}s)',
  'cli.group.tailEnded': '订阅结束 lastSeq={lastSeq}',
  'cli.group.joinNameEmpty': '--name 不能为空',
  'cli.group.joined': '已加入群 {groupId} epoch={epoch}{name}',
  'cli.group.joinedName': ' 显示名={name}',
  'cli.group.joinForbidden': '加入失败: hub 未允许自助加入（403 not-a-member），请让 hub 管理接口添加本机',

  // ---- group：probe / replica / leader / claim ----
  'cli.group.probeNoAddress': '对端没有记录地址，无法探测',
  'cli.group.probeLine': '探测: {name} peerId={peerId} epoch={epoch} lastSeq={lastSeq}',
  'cli.group.probeAddress': '  地址: {url}',
  'cli.group.probeNoPrivate': '(未探测到私有地址)',
  'cli.group.probeGroup': '  groupId={groupId} leader={leader}',
  'cli.group.replicaMissing': '本地没有群副本（{file}；成员启动并成功拉取后生成）',
  'cli.group.replicaLine': '副本: groupId={groupId} epoch={epoch} leader={leader} lastSeq={lastSeq} 条数={count}',
  'cli.group.replicaFile': '  文件: {file}',
  'cli.group.roleMissing': '本机还没有角色状态（{file}）；host 启动并启用群之后生成',
  'cli.group.roleLine': '角色: {role} epoch={epoch} leader={leader} commitSeq={commitSeq} 租约剩余={remaining}ms{degraded}',
  'cli.group.leaseLine': '对端: {name} role={role} epoch={epoch} leader={leader} commitSeq={commitSeq} pending={pending} quorum={quorum}{degraded}',
  // cli.group.degraded 只写在英文格：语言中立标记，中文格靠「缺 key 回落英文」取到
  'cli.group.noGroupKeyLease': '本机没有群密钥（group-key.json / group.json），无法用群级签名查询对端',
  'cli.group.noGroupKeyClaim': '本机没有群密钥（group-key.json / group.json），先让 host 启用群',
  'cli.group.claimOk': '已接管为 leader: epoch={epoch} 本机={senderId}',
  'cli.group.claimFailed': '接管未成功: {reason} 票数={votes}/{needed}（成员表 {memberCount} 人；多数派分母是成员表全集，不是可达成员数）',
  'cli.group.claimDemoted': '本机当前角色={role} epoch={epoch}（落败即降级；等对端回来后会由租约过期重新选举）',

  // ---- group：归档 ----
  'cli.group.archiveFailed': '归档操作失败: {text}',
  'cli.group.archiveEmpty': '没有归档（hub 侧还没有归档文件）',
  'cli.group.archiveUnnamed': '(未命名)',
  'cli.group.archiveRow': '{file}\tseq {from}-{to}\t{count} 条\t{bytes}B\t{createdAt}',
  'cli.group.archivesTotal': '共 {count} 个归档 · {bytes} 字节',
  'cli.group.archiveDeleteUsage': '用法: dsh-lan-peers group archive-delete <file>',
  'cli.group.archiveDeleted': '已删除归档 {file}{released}',
  'cli.group.archiveReleased': '，释放 {bytes} 字节',
  'cli.group.unknownSub': '未知 group 子命令: {sub}',
  'cli.group.rejected': '群操作被拒绝: {text}',

  // ---- find / apply / advertise ----
  'cli.find.needName': '需要 --name <群名>',
  'cli.find.notFound': '未发现群名「{name}」（本地 known-groups 为空，向 {peers} 个伙伴查找均未命中）',
  'cli.find.localHit': '（本地命中，未联网）',
  'cli.find.multiHit': '命中 {count} 个同名群：apply 时用 --peer <介绍人> 或 --group <groupId> 指定',
  'cli.find.failure': '（{name} 查找失败: {reason}）',
  'cli.find.matchLine': '· {name}  groupId={groupId}…  hub={hub}  介绍人={via}',
  'cli.apply.notFound': '未发现群「{name}」：先让群里的人把群名广播给你，或用 group find 确认',
  'cli.apply.multiHit': '命中 {count} 个同名群，请用 --peer <介绍人> 或 --group <groupId> 指定：',
  'cli.apply.introducerMissing': '命中的介绍人不在伙伴列表里（{peerId}），无法签名申请',
  'cli.apply.rejected': '申请被拒绝：{reason}',
  'cli.apply.submitted': '已向 {via} 提交入群申请（群 {name}，groupId {groupId}…）状态={status}',
  'cli.apply.pollFailed': '轮询失败（第 {attempt} 次，继续等待）: {reason}',
  'cli.apply.granted': '已入群：{name}（groupId {groupId}…）keyVersion={keyVersion} 成员={members}（群密钥已写入 group-key.json，不显示）',
  'cli.apply.alreadyMember': '本机已经是该群成员（无需授权）',
  'cli.apply.pending': '仍在待批准（已等 {seconds} 秒，最后状态={status}），稍后重试: group apply --name {name}',
  'cli.advertise.noGroup': '本机没有群（group.json / group-key.json 都没有），先当 hub 或先入群',
  'cli.advertise.nameUnknown': '本机群名未知（group-key.json 没有 groupName、也联系不上 hub 取权威群名）。先让 host 拉到群状态，或用 --name <群名> 明确指定要广播的名字',
  'cli.advertise.summary': '广播群名「{name}」（groupId {groupId}…）：发出 {sent} 个，跳过 {skipped} 个',
  'cli.advertise.sentOnly': '已把群名广播给 {count} 个非成员伙伴',

  // ---- 本机回环管理接口 ----
  'cli.admin.noUrl': '本机管理接口地址未知：请先打开一次 DSH 面板（面板会把自己的地址写进 {file}），或用 --url http://127.0.0.1:<DSH web 端口> 指定',
  'cli.admin.unreachable': '连不上管理接口 {base}（{reason}）：地址可能已过期（桌面重启后 web 端口会变）—— 打开一次 DSH 面板刷新 {file}，或用 --url 指定',
  'cli.admin.tokenHint': '（管理接口需要 token：确认本机 host 在跑，且 {file} 可读）',

  // ---- 文件互传 ----
  'cli.file.failed': '文件操作失败: {text}',
  'cli.file.sendFileUsage': '用法: dsh-lan-peers send-file <peer> <文件>',
  'cli.file.notFound': '找不到文件: {file}',
  'cli.file.notRegular': '不是普通文件: {file}',
  'cli.file.sent': '已发送 id={id} bytes={bytes} sha256={sha256} ms={ms}',
  'cli.file.progressElapsed': '已用 {seconds}s',
  'cli.file.progressBytes': '已发 {received}/{total} 字节（{pct}%）',
  'cli.inbox.usageDecide': '用法: dsh-lan-peers inbox {action} <id>',
  'cli.inbox.tagPending': '待确认',
  'cli.inbox.tagReceived': '已收',
  'cli.inbox.summary': '待确认 {pending} 个 · 已收 {inbox} 个',
  'cli.inbox.unknownSub': '未知 inbox 子命令: {sub}',
  'cli.inbox.accepted': '已接受 id={id} path={path}',
  'cli.inbox.rejected': '已拒收 id={id}',

  // ---- 私聊 ----
  'cli.dm.failed': '私聊失败: {text}',
  'cli.dm.fromPeer': '对方',
  'cli.dm.fromMe': '我',
  'cli.dm.sendUsage': '用法: dsh-lan-peers dm <peer> <正文>',
  'cli.dm.reply': '回复: {text}',
  'cli.dm.logUsage': '用法: dsh-lan-peers dm log <peer>',
  'cli.dm.limitInvalid': '--limit 必须是正整数',
  'cli.dm.syncUsage': '用法: dsh-lan-peers dm sync <peer>',
  'cli.dm.logSummary': '共 {total} 条{shown}',
  'cli.dm.logSummaryShown': '，打印最近 {count} 条',
  'cli.dm.synced': '已对齐 added={added} total={total}',
  'cli.dm.queued': '已发给 {label}：等待对方确认这次派单（approval {id}，剩余 {sec} 秒）',

  // ---- 派单设置（契约 §5/§6）：pending / approve / reject / settings ----
  'cli.dispatch.usage': [
    '用法: dsh-lan-peers dispatch <子命令> [选项]',
    '',
    '  pending                                    列出待批准派单',
    '  approve <approvalId>                       批准并立即执行',
    '  reject <approvalId>                        拒绝（正文当场丢弃）',
    '  settings                                   查看本机派单设置',
    '  settings [--default <id>] [--max-perm <档>] 修改本机派单设置',
    '',
    '权限三档（由低到高）: read-only | workspace-write | danger-full-access',
  ].join('\n'),
  'cli.dispatch.pendingEmpty': '（没有待批准请求）',
  'cli.dispatch.row': '{id}\t来自 {from}\t工作区 {workspaceId}/{workspaceName}\t{permission}\t剩余 {sec}s',
  'cli.dispatch.summary': '待批准 {count} 条',
  'cli.dispatch.approved': '已批准 {id}（state={state}）',
  'cli.dispatch.rejected': '已拒绝 {id}（state={state}）',
  'cli.dispatch.settingsHead': '默认工作区 {default}\t最大授权 {max}\t工作区 {count} 个',
  'cli.dispatch.workspaceRow': '  {id}\t{name}\t{path}',
  'cli.dispatch.saved': '派单设置已保存: 默认 {default} · 最大授权 {max} · 工作区 {count} 个',
  'cli.dispatch.failed': '派单设置操作失败: {text}',
  'cli.dispatch.badPerm': '--max-perm 只能是 read-only | workspace-write | danger-full-access',
  'cli.dispatch.idRequired': '需要 approvalId: dsh-lan-peers dispatch approve <id>',

  // ---- 群派单回执（0.8.5-α 契约 §2）----
  // 只在**点名了工作区/权限**的群派单上使用（不带新字段的派单保持 0.8.4 的原文案）。
  // {workspace} 只可能是工作区名（或 id），绝不是路径。
  'group.dispatch.progress': '派单 → {target}：进行中（工作区 {workspace} · 权限 {permission}）',
  'group.dispatch.done': '派单 → {target}：done（{elapsedMs}ms · {replyChars}字）',
  'group.dispatch.failed': '派单 → {target}：failed（{reason}）',
  'group.dispatch.pendingApproval': '派单 → {target}：pending-approval（工作区 {workspace} · 权限 {permission}，等对方批准）',
};

// ---------------------------------------------------------------------------
// 词表：cli 域的英文格（键必须与中文格一一对应）
// ---------------------------------------------------------------------------

const CLI_TEXT_EN = {
  'cli.help.usage': [
    'dsh-lan-peers — LAN peer CLI',
    '',
    'Usage: dsh-lan-peers <subcommand> [options]',
    '',
    'Subcommands:',
    '  code    Mint a one-time pairing code (6 digits, 10 minutes, single use)',
    '  pair    Pair with a peer using a code (ECDH two rounds, legacy fallback)',
    '  peers   List paired peers',
    '  ask     Dispatch a task to a peer and wait for the reply',
    '  events  Subscribe to a peer /v1/events stream (troubleshooting)',
    '  unpair  Drop the pairing with a peer (best effort notification)',
    '  group   Group chat: state / post / history / tail / join / probe / replica',
    '  dm      Direct chat: <peer> <text> [--workspace <id>] [--perm <level>] send / log <peer> history / sync <peer> reconcile',
    '  dispatch Dispatch settings: pending / approve <id> / reject <id> / settings [--default <id>] [--max-perm <level>]',
    '  send-file <peer> <file>   Chunked encrypted transfer (the peer accepts it into its inbox)',
    '  inbox   File inbox: list / accept <id> / reject <id>',
    '  help    Show this help',
    '',
    'Global options:',
    '  --state-dir <path>   State directory (default ~/.dsh/lan-peers)',
    '  --lang <zh|en>       Output language (default auto: config lang, then DSH_LAN_PEERS_LANG, then the system locale)',
    '  --help               Show the usage of a subcommand',
  ].join('\n'),
  'cli.help.code': [
    'Usage: dsh-lan-peers code [--state-dir <dir>] [--url <local admin endpoint>]',
    '',
    'Ask the local host for a one-time pairing code (valid 10 minutes, burned on use).',
    'Since M6 the code lives only in host process memory: this command is a separate',
    'process, so a code minted here would be worthless to the running host.',
    'Start the local host first (or use Generate pairing code in the panel).',
  ].join('\n'),
  'cli.help.pair': [
    'Usage: dsh-lan-peers pair --url http://PEER:7788 --code 123456 [--name local-name] [--peer-name peer-label] [--legacy-pair]',
    '',
    'Adaptive by default: when the peer /v1/health capability list has "pair-ecdh" it runs',
    'the two-round ECDH flow (/v1/pair swaps ephemeral keys, /v1/pair/confirm wraps the',
    'initial secret with the derived key); otherwise it falls back to the plaintext',
    '/v1/pair of 0.3.1.',
    '',
    '  --legacy-pair   Force the old plaintext path (0.3.1 peer, or troubleshooting)',
    '  --ecdh-pair     Force ECDH, error out when the peer does not support it',
    '  --base-url      Address this host is reachable at (default: probe a private IPv4 + 7788;',
    '                  sent with the pairing request, without it the peer has no address on record)',
    '  --port          Port used when probing that address (default 7788; only without --base-url)',
  ].join('\n'),
  'cli.help.peers': [
    'Usage: dsh-lan-peers peers [--probe] [--state-dir <dir>]',
    '',
    '  --probe   Probe every peer (GET /v1/health, 2 second timeout)',
  ].join('\n'),
  'cli.help.ask': [
    'Usage: dsh-lan-peers ask --peer <peerId|name> "prompt" [--timeout 300] [--legacy-poll] [--wait-ms 25000]',
    '',
    'A peer advertising "stream" is driven over /v1/events (SSE), otherwise long polling',
    'on /v1/answer; --legacy-poll forces the 1.5 second polling of 0.3.1 (no waitMs).',
  ].join('\n'),
  'cli.help.events': [
    'Usage: dsh-lan-peers events --peer <peerId|name> --session <sessionId> [--duration 300] [--verbose]',
    '',
    'Subscribe to the peer /v1/events: every event is encrypted on its own, decrypted here',
    'and printed one per line.',
    'A peer whose capability list has no "stream" is rejected outright (0.3.1 has no such',
    'endpoint).',
    '',
    '  --duration <seconds>   Longest subscription (default 300)',
    '  --verbose              Also print ping heartbeats',
  ].join('\n'),
  'cli.help.unpair': [
    'Usage: dsh-lan-peers unpair --peer <peerId|name> [--local-only] [--timeout 10] [--state-dir <dir>]',
    '',
    'Drop the pairing between this host and one peer. It probes first by default: when the',
    'peer advertises "unpair" it sends one signed POST /v1/unpair so the peer drops this',
    'host too; unreachable, older peer or failure only records a reason, the local record',
    'is always removed.',
    '',
    '  --local-only     Skip the peer notification, remove the local record only',
    '  --timeout <sec>  Timeout for notifying the peer (default 10)',
  ].join('\n'),
  'cli.help.group': [
    'Usage: dsh-lan-peers group <subcommand> [--peer <hub name|peerId>] [--state-dir <dir>]',
    '',
    'Subcommands:',
    '  state                     Group info + member table (gets the groupKey, never prints it)',
    '  post --text "..."         Send one message [--kind chat|progress|result|system]',
    '                            text containing @!name dispatches on the author side (the local host runs it and prints a receipt)',
    '  dispatch <target> <task...> Same as sending "@!target task" and dispatching, prints the receipt',
    '  accept on|off             Toggle accepting dispatches here (writes the profile config, hot)',
    '  history [--since N]       Read history [--limit 1..200]',
    '  tail [--since N]          Follow the event stream and print every message [--duration seconds]',
    '  join [--name display]     Self-join the hub (only when the hub enables autoJoin)',
    '  probe [--peer name|peerId] Group level probe: prints peerId/epoch/lastSeq/reachable address',
    '  replica                   Print the local group replica (groupId/epoch/leader/lastSeq/count)',
    '  leader [--peer X]         Show the local role/epoch/lease (with --peer: the peer live snapshot)',
    '  claim [--url http://…]    Take over manually: make this host start an election now',
    '  find --name <group>       Look a group up by name (local known groups first, then every peer, 2 second timeout)',
    '  apply --name <group>      Ask to join by group name: apply, poll, then write group-key.json',
    '  advertise                 Broadcast this host group name to peers (no throttle, prints the targets)',
    '  archives                  List the hub side archive files (local loopback admin endpoint, read only)',
    '  archive-delete <file>     Delete one archive file (irreversible; seq numbers are never reused)',
    '',
    '  --peer        The hub name or peerId; optional when there is exactly one peer',
    '  --name        Display name reported on join (defaults to the state.json name / hostname;',
    '                use it when several nodes run on one machine)',
    '  --state-dir   State directory (default ~/.dsh/lan-peers)',
    '  --url         claim target (default http://127.0.0.1:7788 = the peer port) / the local address',
    '                the admin endpoint is reached at (default: <stateDir>/admin-url, written by the panel or host)',
    '  --hub-url     Hub address published by advertise (default: the address the hub reports)',
    '  --base-url    Applicant address published on apply (default empty, the introducer fills it in)',
    '  --timeout     apply wait in seconds (default 600 = the 10 minute cap in contract §5.2)',
    '  --interval    apply poll interval in milliseconds (default 5000)',
    '',
    'Only the hub serves the group endpoints; the hub has to be in this host peer list first.',
    'Since S3 the leader is elected: claim hits the local loopback (group signature, body carries this instance id).',
  ].join('\n'),
  'cli.help.sendFile': [
    'Usage: dsh-lan-peers send-file <peer> <file> [--url <local admin endpoint>] [--state-dir <dir>]',
    '',
    'Send one local file to a peer as encrypted chunks (contract §1: offer, chunk, complete; AES-256-GCM per chunk).',
    'The peer stores it in its own inbox and waits for the peer to confirm; **this command cannot pick the remote path** (contract §0).',
    'Prints: id / bytes / sha256 / ms — sha256 is the digest of the whole file, verify it with the peer.',
    'On a TTY it repaints every 0.5s: with an id it reports "sent X/Y bytes (Z%)", without one the elapsed time.',
    '',
    '  --url   The local host admin endpoint (default <stateDir>/admin-url; an unknown address is an error that asks you to pass one)',
  ].join('\n'),
  'cli.help.inbox': [
    'Usage: dsh-lan-peers inbox <list|accept|reject> [id] [--url <address>] [--state-dir <dir>]',
    '',
    '  list            Pending and received files (id / file name / size / sha256 / source / time)',
    '  accept <id>     Accept one pending file: move it into the inbox and print the path',
    '  reject <id>     Reject and delete it (an unconfirmed file expires this way after 10 minutes)',
    '',
    '  --url   The local host admin endpoint (default <stateDir>/admin-url; an unknown address is an error that asks you to pass one)',
  ].join('\n'),
  'cli.help.dm': [
    'Usage: dsh-lan-peers dm <peer> <text> [--workspace <id>] [--perm <level>] [--url <address>] [--state-dir <dir>]',
    '      dsh-lan-peers dm log <peer> [--limit N]',
    '      dsh-lan-peers dm sync <peer>',
    '',
    'Direct chat (a 1:1 continuous session): the text goes to this one peer only — it never',
    'enters group history and never enters a log.',
    'The peer keys, signatures and storage all live in the local host, so all three commands',
    'only talk to the local loopback admin endpoint.',
    '',
    '  <peer> <text>   Send one message and print the reply; the same peer reuses the session (see reused / sessionId)',
    '  log <peer>      Print this pair history (time / direction / id / text)',
    '  sync <peer>     Exchange the entries each side is missing (the panel does one sync on open too)',
    '',
    '  --limit N   log prints only the last N entries (default 20)',
    '  --workspace <id>  name one of the peer workspaces (an unknown id is refused with unknown-workspace)',
    '  --perm <level>    ask for read-only | workspace-write | danger-full-access on this dispatch;',
    '                    above the peer limit is a 403, above the peer default needs its approval (approvalId)',
    '  --url       The local host admin endpoint (default <stateDir>/admin-url)',
  ].join('\n'),

  'cli.common.unknownSubcommand': 'unknown subcommand: {name}',
  'cli.common.unknownPeer': 'unknown peer: {peer}',
  'cli.common.ambiguousPeer': 'ambiguous peer name: {peer} matches {count} entries, use the peerId instead',
  'cli.common.unnamed': '(unnamed)',
  'cli.common.inboundOnly': '(inbound only)',
  'cli.common.unknown': 'unknown',
  'cli.common.localAdmin': 'the local admin endpoint',
  'cli.common.sending': 'sending → {label} · {bytes} bytes',
  'cli.common.emptyReply': '(empty)',

  'cli.code.hostRefused': 'pairing code failed: the local host rejected the request to {url} ({reason})\nfix: start the local host first (or use Generate pairing code in the panel) — a code can only be minted inside the host process',
  'cli.code.badShape': 'pairing code failed: the local host did not return the 6 digit code the contract requires',
  'cli.code.ok': 'pairing code: {code}   valid for 10 minutes, single use',
  'cli.code.hintFillPeer': 'the peer pastes it into Add peer to pair (address: this host at http://<ip>:7788)',
  'cli.code.hintMemoryOnly': 'note: the code lives only in the local host process, restarting the host invalidates it',

  'cli.pair.transportEcdh': 'ECDH two rounds',
  'cli.pair.transportLegacy': 'legacy plaintext path',
  'cli.pair.ok': 'paired: {label} ({peerId}) · {transport}',
  'cli.pair.fallbackNoEcdh': 'note: the peer does not advertise pair-ecdh, fell back to legacy pairing (initial secret sent in plaintext)',
  'cli.pair.fallbackNoModule': 'note: this build has no lib/pairing-ecdh.mjs, fell back to legacy pairing (initial secret sent in plaintext)',

  'cli.peers.empty': '(no peers paired yet)',

  'cli.ask.dispatched': 'dispatched → {name} (session {sessionId})',
  'cli.ask.peerError': 'the peer returned an error: {error}',
  'cli.events.noStream': 'the peer /v1/health does not advertise "stream" (0.3.1 has no such endpoint), cannot subscribe',
  'cli.events.subscribed': 'subscribing to {name} /v1/events (session {sessionId})',
  'cli.events.ended': 'subscription ended: {reason}',
  'cli.events.finalStatus': 'final status: {status}',

  'cli.unpair.reasonNoAddress': 'no peer address on record',
  'cli.unpair.reasonNoSecret': 'no peer secret',
  'cli.unpair.reasonOffline': 'peer unreachable',
  'cli.unpair.reasonNoCapability': 'peer does not support unpair',
  'cli.unpair.skippedRemote': 'peer notification skipped (--local-only)',
  'cli.unpair.doneRemote': 'unpaired from {label} (the peer dropped this host too)',
  'cli.unpair.doneLocal': 'unpaired from {label} (local only; reason: {reason})',

  'cli.group.needPeer': 'a --peer is required (the hub name or peerId)',
  'cli.group.needPeerCandidates': ', candidates: {list}',
  'cli.group.needPeerEmpty': ' (no peers paired yet)',
  'cli.group.stateHeaderPeer': 'group: {name} ({groupId})  epoch={epoch} keyVersion={keyVersion} members={members}',
  'cli.group.stateHeaderKey': 'group: {name} ({groupId})  epoch={epoch} members={members} (group signature direct to {baseUrl}, leader={leader})',
  'cli.group.groupKeyReceived': 'received (32B, not shown)',
  'cli.group.groupKeyNotSent': 'not sent',
  'cli.group.groupKeyOnDisk': 'already in group-key.json (32B, not shown)',
  'cli.group.groupKeyLine': 'groupKey: {value}',
  'cli.group.memberSelf': 'online(this host)',

  'cli.group.dispatchSkipped': 'not dispatched (the message has no @! target): {reason}',
  'cli.group.dispatchAmbiguous': 'dispatch → {who}: several members share that name, resend as @!name (short id)',
  'cli.group.dispatchLine': 'dispatch → {who}: {status}{detail}',
  'cli.group.dispatchDetail': ' ({parts})',
  'cli.group.dispatchChars': '{chars} chars',
  'cli.group.dispatchNotTriggered': 'the message was sent but the dispatch did not fire: the local host did not answer at {url} ({reason})\nfix: start the local host (or retry group dispatch against the admin endpoint given by --url)',
  'cli.group.dispatchNoSummary': 'the dispatch returned nothing: the local host did not answer with the dispatch receipt the contract requires',
  'cli.group.textTooLong': 'text exceeds the {max} character limit (the hub answers 413 payload-too-large)',
  'cli.group.badKind': '--kind must be one of {kinds}',
  'cli.group.sent': 'sent seq={seq} ts={ts}{channel}',
  'cli.group.sentViaGroupKey': ' (group signature direct to {baseUrl})',
  'cli.group.dispatchUsage': 'Usage: dsh-lan-peers group dispatch <target> <task...>',
  'cli.group.acceptUsage': 'Usage: dsh-lan-peers group accept on|off',
  'cli.group.acceptFailed': 'toggling dispatch acceptance failed: the local host rejected the request to {url} ({reason})\nfix: make sure the local host runs with the group feature enabled (a 501 means the host has not wired it up yet)',
  'cli.group.acceptOn': 'accepting',
  'cli.group.acceptOff': 'off',
  'cli.group.acceptEphemeral': ' (this process only, a restart returns to the configured value)',
  'cli.group.acceptLine': 'dispatch acceptance: {state}{extra}',

  'cli.group.historyPeer': 'group {groupId} · {count} messages · lastSeq={lastSeq}',
  'cli.group.historyKey': 'group {groupId} · {count} messages · lastSeq={lastSeq} (group signature direct to {baseUrl})',
  'cli.group.tailSubscribed': 'subscribing to group events sinceSeq={since} ({seconds}s)',
  'cli.group.tailEnded': 'subscription ended lastSeq={lastSeq}',
  'cli.group.joinNameEmpty': '--name cannot be empty',
  'cli.group.joined': 'joined group {groupId} epoch={epoch}{name}',
  'cli.group.joinedName': ' display name={name}',
  'cli.group.joinForbidden': 'join failed: the hub does not allow self-join (403 not-a-member), ask the hub admin endpoint to add this host',

  'cli.group.probeNoAddress': 'the peer has no address on record, cannot probe',
  'cli.group.probeLine': 'probe: {name} peerId={peerId} epoch={epoch} lastSeq={lastSeq}',
  'cli.group.probeAddress': '  address: {url}',
  'cli.group.probeNoPrivate': '(no private address probed)',
  'cli.group.probeGroup': '  groupId={groupId} leader={leader}',
  'cli.group.replicaMissing': 'no local group replica ({file}; it appears once a member starts and pulls)',
  'cli.group.replicaLine': 'replica: groupId={groupId} epoch={epoch} leader={leader} lastSeq={lastSeq} messages={count}',
  'cli.group.replicaFile': '  file: {file}',
  'cli.group.roleMissing': 'no local role state yet ({file}); it appears once the host starts with the group enabled',
  'cli.group.roleLine': 'role: {role} epoch={epoch} leader={leader} commitSeq={commitSeq} lease remaining={remaining}ms{degraded}',
  'cli.group.leaseLine': 'peer: {name} role={role} epoch={epoch} leader={leader} commitSeq={commitSeq} pending={pending} quorum={quorum}{degraded}',
  'cli.group.degraded': '  [degraded]',
  'cli.group.noGroupKeyLease': 'this host has no group key (group-key.json / group.json), cannot query the peer with a group signature',
  'cli.group.noGroupKeyClaim': 'this host has no group key (group-key.json / group.json), let the host enable the group first',
  'cli.group.claimOk': 'took over as leader: epoch={epoch} host={senderId}',
  'cli.group.claimFailed': 'takeover failed: {reason} votes={votes}/{needed} (the member table holds {memberCount}; the majority denominator is the whole table, not the reachable members)',
  'cli.group.claimDemoted': 'this host is now role={role} epoch={epoch} (a lost vote demotes it; the lease expiry starts a new election once the peer returns)',

  'cli.group.archiveFailed': 'archive operation failed: {text}',
  'cli.group.archiveEmpty': 'no archives (the hub has not archived anything yet)',
  'cli.group.archiveUnnamed': '(unnamed)',
  'cli.group.archiveRow': '{file}\tseq {from}-{to}\t{count} messages\t{bytes}B\t{createdAt}',
  'cli.group.archivesTotal': '{count} archives · {bytes} bytes',
  'cli.group.archiveDeleteUsage': 'Usage: dsh-lan-peers group archive-delete <file>',
  'cli.group.archiveDeleted': 'deleted archive {file}{released}',
  'cli.group.archiveReleased': ', freed {bytes} bytes',
  'cli.group.unknownSub': 'unknown group subcommand: {sub}',
  'cli.group.rejected': 'group operation rejected: {text}',

  'cli.find.needName': 'a --name <group> is required',
  'cli.find.notFound': 'group name "{name}" not found (local known-groups is empty and all {peers} peers missed)',
  'cli.find.localHit': '(local hit, no network)',
  'cli.find.multiHit': '{count} groups share that name: pass --peer <introducer> or --group <groupId> to apply',
  'cli.find.failure': '({name} lookup failed: {reason})',
  'cli.find.matchLine': '· {name}  groupId={groupId}…  hub={hub}  introducer={via}',
  'cli.apply.notFound': 'group "{name}" not found: ask a member to broadcast the group name to you, or check with group find',
  'cli.apply.multiHit': '{count} groups share that name, pass --peer <introducer> or --group <groupId>:',
  'cli.apply.introducerMissing': 'the matching introducer is not in the peer list ({peerId}), cannot sign the application',
  'cli.apply.rejected': 'application rejected: {reason}',
  'cli.apply.submitted': 'applied to {via} for membership (group {name}, groupId {groupId}…) status={status}',
  'cli.apply.pollFailed': 'poll failed (attempt {attempt}, still waiting): {reason}',
  'cli.apply.granted': 'joined: {name} (groupId {groupId}…) keyVersion={keyVersion} members={members} (the group key is in group-key.json, not shown)',
  'cli.apply.alreadyMember': 'this host is already a member of that group (no grant needed)',
  'cli.apply.pending': 'still pending approval (waited {seconds}s, last status={status}), retry later: group apply --name {name}',
  'cli.advertise.noGroup': 'this host has no group (neither group.json nor group-key.json), become a hub or join one first',
  'cli.advertise.nameUnknown': 'the local group name is unknown (group-key.json has no groupName and the hub did not answer). Let the host pull the group state, or name the broadcast target with --name <group>',
  'cli.advertise.summary': 'broadcasting group name "{name}" (groupId {groupId}…): sent {sent}, skipped {skipped}',
  'cli.advertise.sentOnly': 'broadcast the group name to {count} non-member peers',

  'cli.admin.noUrl': 'the local admin endpoint address is unknown: open the DSH panel once (it writes its own address into {file}), or pass --url http://127.0.0.1:<DSH web port>',
  'cli.admin.unreachable': 'cannot reach the admin endpoint {base} ({reason}): the address may be stale (the web port changes after a desktop restart) — open the DSH panel once to refresh {file}, or pass --url',
  'cli.admin.tokenHint': ' (the admin endpoint needs a token: check that the local host runs and that {file} is readable)',

  'cli.file.failed': 'file operation failed: {text}',
  'cli.file.sendFileUsage': 'Usage: dsh-lan-peers send-file <peer> <file>',
  'cli.file.notFound': 'file not found: {file}',
  'cli.file.notRegular': 'not a regular file: {file}',
  'cli.file.sent': 'sent id={id} bytes={bytes} sha256={sha256} ms={ms}',
  'cli.file.progressElapsed': 'elapsed {seconds}s',
  'cli.file.progressBytes': 'sent {received}/{total} bytes ({pct}%)',
  'cli.inbox.usageDecide': 'Usage: dsh-lan-peers inbox {action} <id>',
  'cli.inbox.tagPending': 'pending',
  'cli.inbox.tagReceived': 'received',
  'cli.inbox.summary': '{pending} pending · {inbox} received',
  'cli.inbox.unknownSub': 'unknown inbox subcommand: {sub}',
  'cli.inbox.accepted': 'accepted id={id} path={path}',
  'cli.inbox.rejected': 'rejected id={id}',

  'cli.dm.failed': 'direct message failed: {text}',
  'cli.dm.fromPeer': 'peer',
  'cli.dm.fromMe': 'me',
  'cli.dm.sendUsage': 'Usage: dsh-lan-peers dm <peer> <text>',
  'cli.dm.reply': 'reply: {text}',
  'cli.dm.logUsage': 'Usage: dsh-lan-peers dm log <peer>',
  'cli.dm.limitInvalid': '--limit must be a positive integer',
  'cli.dm.syncUsage': 'Usage: dsh-lan-peers dm sync <peer>',
  'cli.dm.logSummary': '{total} entries{shown}',
  'cli.dm.logSummaryShown': ', showing the last {count}',
  'cli.dm.synced': 'reconciled added={added} total={total}',
  'cli.dm.queued': 'sent to {label}: waiting for the peer to approve this dispatch (approval {id}, {sec}s left)',

  // ---- dispatch settings (contract §5/§6): pending / approve / reject / settings ----
  'cli.dispatch.usage': [
    'Usage: dsh-lan-peers dispatch <subcommand> [options]',
    '',
    '  pending                                     list the dispatch requests waiting for approval',
    '  approve <approvalId>                        approve and run it now',
    '  reject <approvalId>                         reject it (the prompt is dropped)',
    '  settings                                    show the local dispatch settings',
    '  settings [--default <id>] [--max-perm <level>] change the local dispatch settings',
    '',
    'Permission levels (low to high): read-only | workspace-write | danger-full-access',
  ].join('\n'),
  'cli.dispatch.pendingEmpty': '(no request waiting for approval)',
  'cli.dispatch.row': '{id}\tfrom {from}\tworkspace {workspaceId}/{workspaceName}\t{permission}\t{sec}s left',
  'cli.dispatch.summary': '{count} waiting for approval',
  'cli.dispatch.approved': 'approved {id} (state={state})',
  'cli.dispatch.rejected': 'rejected {id} (state={state})',
  'cli.dispatch.settingsHead': 'default workspace {default}\tmax permission {max}\t{count} workspaces',
  'cli.dispatch.workspaceRow': '  {id}\t{name}\t{path}',
  'cli.dispatch.saved': 'dispatch settings saved: default {default} · max permission {max} · {count} workspaces',
  'cli.dispatch.failed': 'dispatch settings operation failed: {text}',
  'cli.dispatch.badPerm': '--max-perm must be one of read-only | workspace-write | danger-full-access',
  'cli.dispatch.idRequired': 'an approvalId is required: dsh-lan-peers dispatch approve <id>',

  // group-dispatch receipts (0.8.5-α contract §2). Wire values (reason tokens,
  // permission names) stay verbatim in every language.
  'group.dispatch.progress': 'dispatch → {target}: running (workspace {workspace} · permission {permission})',
  'group.dispatch.done': 'dispatch → {target}: done ({elapsedMs}ms · {replyChars} chars)',
  'group.dispatch.failed': 'dispatch → {target}: failed ({reason})',
  'group.dispatch.pendingApproval': 'dispatch → {target}: pending-approval (workspace {workspace} · permission {permission}; waiting for the peer to approve)',
};

// ---------------------------------------------------------------------------
// 词表：panel 域
//
// 本批只铺 key 与一份占位值（当前面板上的中文文案），面板 lane 接线时按语言拆成两份：
// 这些 key 是两格共用的，en 格拿到的是同一份中文占位值 —— 面板接线时必须替换。
// 新增行零反引号：面板段一律单引号 + 模板字符串之外的写法。
// ---------------------------------------------------------------------------

const PANEL_TEXT = {
  'panel.title': '局域网伙伴',
  'panel.tab.peers': '伙伴',
  'panel.tab.group': '群组',
  'panel.tab.files': '文件',
  'panel.tab.dm': '私聊',
  'panel.peers.empty': '还没有已配对的伙伴',
  'panel.peers.columnName': '名字',
  'panel.peers.actionPair': '建立伙伴关系',
  'panel.peers.actionUnpair': '解除',
  'panel.group.role': '我的角色',
  'panel.group.leader': '当前 leader',
  'panel.group.members': '成员',
  'panel.group.unnamed': '未命名群',
  'panel.group.joined': '已加入群组',
  'panel.group.joinFailed': '加入群组失败：',
  'panel.group.dispatch': '派单 → ',
  'panel.group.acceptOn': '接单中',
  'panel.group.acceptOff': '已关闭',
  // v0.8.5-α（契约 §3）：群组页「⚙ 派单设置」弹层与群派单回执。这批 key 两格都是真文案。
  'panel.group.dispatchButton': '⚙ 派单设置',
  'panel.group.dispatchTitle': '这次群派单的目标、工作区与权限',
  'panel.group.target': '目标成员',
  'panel.group.workspace': '工作区',
  'panel.group.permission': '权限',
  'panel.group.close': '收起',
  'panel.group.noMembers': '群里还没有可选成员',
  'panel.group.noWorkspace': '对方未提供可选工作区',
  'panel.group.overLimit': '超过对方上限（{max}），已置灰',
  'panel.group.hint': '工作区与权限来自目标成员；超过其上限的档位已置灰。',
  'panel.group.loadFailed': '读取对方派单设置失败：{text}',
  'panel.group.receiptScope': '工作区 {workspace} · 权限 {permission}',
  'panel.group.pendingApproval': '等待对方确认…',
  'panel.files.pending': '待批准',
  'panel.files.approved': '已批准',
  'panel.files.rejected': '已拒绝',
  'panel.files.archives': '归档 {count} 个 · 共 {bytes} B',
  'panel.dm.body': '正文',
  'panel.dm.direction': '方向',
  'panel.common.send': '发送',
  'panel.common.refresh': '刷新',
  'panel.common.unknown': '未知',
  'panel.common.unnamed': '未命名',
  'panel.common.count': '{count} 条',

  // 设置页签与私聊派单弹层（0.8.5-α 契约 §6）。这两块从 0.8.5-α 起就走 t(lang, key)，
  // 所以下面这批 key 两格都必须是真文案（不是占位值）。
  'panel.tab.settings': '设置',
  'panel.settings.head': '本机派单设置（只在本机生效；路径不会外发）',
  'panel.settings.defaultWorkspace': '默认工作区',
  'panel.settings.maxPermission': '最大授权等级',
  'panel.settings.workspaces': '命名工作区（id / 名字 / 路径）',
  'panel.settings.empty': '还没有命名工作区',
  'panel.settings.newWorkspace': '新增工作区',
  'panel.settings.idPlaceholder': 'id（英文短名，如 main）',
  'panel.settings.namePlaceholder': '名字',
  'panel.settings.pathPlaceholder': '本机路径（必须是已存在的目录）',
  'panel.settings.add': '添加',
  'panel.settings.remove': '删除',
  'panel.settings.save': '保存设置',
  'panel.settings.saved': '设置已保存（立即生效）',
  'panel.settings.badId': '工作区 id 不能为空',
  'panel.settings.badPath': '路径不能为空',
  'panel.settings.pending': '待批准（别人派给本机、等你点头）',
  'panel.settings.pendingEmpty': '没有待批准请求',
  'panel.settings.from': '来自 {name}',
  'panel.settings.remaining': '剩余 {sec} 秒',
  'panel.settings.approve': '批准',
  'panel.settings.reject': '拒绝',
  'panel.settings.approved': '已批准',
  'panel.settings.rejected': '已拒绝',
  'panel.settings.unsupported': '本机还没有派单门面（待 H1 接线）',
  'panel.dispatch.button': '⚙ 派单设置',
  'panel.dispatch.title': '这次派单的工作区与权限',
  'panel.dispatch.workspace': '工作区',
  'panel.dispatch.permission': '权限',
  'panel.dispatch.close': '收起',
  'panel.dispatch.overLimit': '超过对方上限（{max}），已置灰',
  'panel.dispatch.hint': '超过对方默认档需要对方人工确认；超上限的档位已置灰。',
  'panel.dispatch.noWorkspace': '对方没有可选工作区',
  'panel.dispatch.loadFailed': '读取对方派单设置失败：{text}',
  'panel.dm.waitingApproval': '等待对方确认…',
  'panel.dm.approvalApproved': '对方已批准，正在执行…',
  'panel.dm.approvalRejected': '对方拒绝了这次派单（超出其默认授权档）',
  'panel.dm.approvalExpired': '等待超时，对方没有处理',
};

// 设置页与派单弹层的英文格。旧的 panel.* 占位值仍是中文（面板其余部分本批不接线），
// 但 0.8.5-α 新增的这批 key 两格都是真文案 —— 面板按浏览器语言取整张表。
const PANEL_TEXT_EN = {
  'panel.tab.settings': 'Settings',
  'panel.settings.head': 'Local dispatch settings (this host only; paths never leave it)',
  'panel.settings.defaultWorkspace': 'Default workspace',
  'panel.settings.maxPermission': 'Maximum permission',
  'panel.settings.workspaces': 'Named workspaces (id / name / path)',
  'panel.settings.empty': 'No named workspace yet',
  'panel.settings.newWorkspace': 'Add a workspace',
  'panel.settings.idPlaceholder': 'id (short slug, e.g. main)',
  'panel.settings.namePlaceholder': 'name',
  'panel.settings.pathPlaceholder': 'local path (must be an existing directory)',
  'panel.settings.add': 'Add',
  'panel.settings.remove': 'Remove',
  'panel.settings.save': 'Save settings',
  'panel.settings.saved': 'Settings saved (effective immediately)',
  'panel.settings.badId': 'a workspace id is required',
  'panel.settings.badPath': 'a path is required',
  'panel.settings.pending': 'Waiting for your approval',
  'panel.settings.pendingEmpty': 'No request waiting for approval',
  'panel.settings.from': 'from {name}',
  'panel.settings.remaining': '{sec}s left',
  'panel.settings.approve': 'Approve',
  'panel.settings.reject': 'Reject',
  'panel.settings.approved': 'approved',
  'panel.settings.rejected': 'rejected',
  'panel.settings.unsupported': 'this host has no dispatch facade yet (waiting for H1)',
  'panel.dispatch.button': '⚙ Dispatch settings',
  'panel.dispatch.title': 'Workspace and permission for this dispatch',
  'panel.dispatch.workspace': 'Workspace',
  'panel.dispatch.permission': 'Permission',
  'panel.dispatch.close': 'Collapse',
  'panel.dispatch.overLimit': 'above the peer limit ({max}), disabled',
  'panel.dispatch.hint': 'Above the peer default needs their approval; levels above their limit are disabled.',
  'panel.dispatch.noWorkspace': 'the peer exposes no workspace',
  'panel.dispatch.loadFailed': 'cannot read the peer dispatch settings: {text}',
  'panel.dm.waitingApproval': 'waiting for the peer to approve…',
  'panel.dm.approvalApproved': 'approved by the peer, running…',
  'panel.dm.approvalRejected': 'the peer rejected this dispatch (above its default permission)',
  'panel.dm.approvalExpired': 'timed out; the peer did not handle it',
  'panel.group.dispatchButton': '⚙ Dispatch settings',
  'panel.group.dispatchTitle': 'Target, workspace and permission for this group dispatch',
  'panel.group.target': 'Target member',
  'panel.group.workspace': 'Workspace',
  'panel.group.permission': 'Permission',
  'panel.group.close': 'Collapse',
  'panel.group.noMembers': 'no member to target yet',
  'panel.group.noWorkspace': 'the target exposes no workspace',
  'panel.group.overLimit': 'above the target limit ({max}), disabled',
  'panel.group.hint': 'Workspace and permission come from the target member; levels above its limit are disabled.',
  'panel.group.loadFailed': 'cannot read the target dispatch settings: {text}',
  'panel.group.receiptScope': 'workspace {workspace} · permission {permission}',
  'panel.group.pendingApproval': 'waiting for the target to approve…',
};


const DICT = Object.freeze({
  zh: Object.freeze({ ...CLI_TEXT, ...PANEL_TEXT }),
  en: Object.freeze({ ...CLI_TEXT_EN, ...PANEL_TEXT, ...PANEL_TEXT_EN }),
});

// ---------------------------------------------------------------------------
// 语言决策
// ---------------------------------------------------------------------------

function normalizeLangValue(raw) {
  const value = typeof raw === 'string' ? raw.trim().toLowerCase() : '';
  if (value === 'zh' || value === 'en') return value;
  // 带地区后缀也算命中：zh-CN/zh-Hans 归 zh，en-US 归 en；其余交给下一层
  if (value.startsWith('zh-')) return 'zh';
  if (value.startsWith('en-')) return 'en';
  return '';
}

function localeLang() {
  try {
    const locale = Intl.DateTimeFormat().resolvedOptions().locale;
    return normalizeLangValue(locale);
  } catch {
    /* Intl 不可用就交给兜底 */
  }
  return '';
}

/**
 * 配置 lang 为 zh/en 时直接用；为 auto、缺失或非法值时看环境：
 *   DSH_LAN_PEERS_LANG > Intl 系统语言 > 'zh'。
 * 非法值不抛错 —— 与「缺 key 回落」同一口径：文案层永远不制造崩溃。
 */
export function resolveLang(config = {}) {
  const raw = typeof config === 'string'
    ? config
    : (config && typeof config === 'object' ? config.lang : undefined);
  const explicit = normalizeLangValue(raw);
  if (explicit !== '') return explicit;
  let env;
  try {
    env = process.env[ENV_LANG_VAR];
  } catch {
    env = undefined;
  }
  const fromEnv = normalizeLangValue(env);
  if (fromEnv !== '') return fromEnv;
  return localeLang() || DEFAULT_LANG;
}

function interpolate(text, params) {
  if (!params || typeof params !== 'object') return String(text);
  return String(text).replace(/\{([A-Za-z][A-Za-z0-9]*)\}/g, (whole, name) => (
    Object.prototype.hasOwnProperty.call(params, name) && params[name] != null
      ? String(params[name])
      : whole
  ));
}

/**
 * 取一条文案。缺 key 回落英文；英文也缺就原样返回 key 本身 —— 绝不抛错：
 * 用户该看到一条稍显奇怪的英文，而不是一个栈。
 */
export function t(lang, key, params = null) {
  const wanted = normalizeLangValue(lang) || DEFAULT_LANG;
  const name = String(key);
  const dict = DICT[wanted] || DICT[DEFAULT_LANG];
  let text = dict[name];
  if (text === undefined) text = DICT.en[name];
  if (text === undefined) return name;
  return interpolate(text, params);
}

/** 某个语言格的 key 清单（排序），用来核对词表规模与两格是否对齐。 */
export function keys(lang = DEFAULT_LANG) {
  const wanted = normalizeLangValue(lang) || DEFAULT_LANG;
  return Object.keys(DICT[wanted] || {}).sort();
}
