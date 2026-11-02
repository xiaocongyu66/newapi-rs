# P0 具名异步入口静态收口

日期：2026-11-02。仅新增本文件；参考源码 `/root/newapi` 只读，主计划及台账 `/root/newapi-rs/docs` 只读。未构建、测试、执行脚本、启动服务或容器，未提交、推送。基线标识沿用主台账 `17970da4571e81308f176a0e61a38276e5771606`，本次不另作 Git 身份验证。

## 1. 范围与结论

有限分母是 `/root/newapi-rs/docs/data-coverage.md:147–151` 的五组具名入口，供应商集合严格取 `/root/newapi-rs/docs/data-jobs-inventory.md:246` 的 baidu/cohere/palm/xunfei/zhipu。五组均已给出静态结论；“已关闭”仅指入口、触发、副作用、owner、取消/退出与阶段不再不明，不表示旧实现无缺陷、Rust 已实现或运行验收通过。本文件不替代 P0 整体独立验收，不扩张为全仓库 AST 完备性证明。

证据简写：以下源码相对路径一律相对于绝对目录 `/root/newapi/apps/api/internal/`；`main` 指 `/root/newapi/apps/api/main.go`。目标 owner 是 Rust 模块化边界，不照搬 Go 的跨域依赖；transport 只承接协议，catalog/identity/billing/usage 各自拥有写入，integrations 拥有外部通信，jobs 只调度。阶段遵循 `/root/newapi-rs/docs/rust-backend-migration-plan.md`。

关键纠正：

- `ops/limit_notify.go:32` 是通知限流内存清理，不是发通知闭包。
- `egress/dial_singbox.go:82` 是限时关闭 sing-box，不是拨号或网络桥接协程。
- `baidu/relay-baidu.go:194` 是 access token 预刷新，不是 stream reader。
- 管理同步四个闭包及价格比率扇出均在请求内 `Wait`，不是可持久化后台 job。
- `track_health.go:246` 与旧表已核的 `fallback_health.go:175` 是不同调用点，不因逻辑相似而抹掉前者。

## 2. QQ webhook：验签、去重及完整分派

证据：`billing/manage_qqbot.go:31–123,135–341`，`billing/qqbot_signature.go:13–97`，`billing/qqbot_service.go:474–768`。

### 2.1 派发之前的确定顺序

1. AppSecret 为空返回 503；配置 WebhookPathToken 时只接受对应路径，否则 404。读取最多 1 MiB 后解析 JSON；读取/解析失败 400。
2. op=13 是验证回调的同步签名分支，不派发事件。必须配置路径 token，且 plain_token 等于该 token；否则分别 503/401。对 event_ts+plain_token 签名后返回。
3. 其他 op 先 VerifySignature：时间戳须为整数且与当前时间差在 ±300 秒内；签名 hex 解码、长度 64、高位检查及 Ed25519(timestamp+原始 body) 校验。密钥由重复 secret 后截断 32 字节的 seed 派生。失败 401；通过后非 op=0 只 ACK。
4. op=0 拷贝 D 字节，计算去重键并先标记，再 `go handleQQBotEvent`，随后 ACK。重复事件只 ACK，不派发。不是“处理成功后标记”，崩溃/失败可能已 ACK 且保留去重标记。
5. 群消息、私信：有 Content 时 SHA1(group+author.ID+content)，群 @/普通消息共用语义键；互动按钮：SHA1(group+member+user+buttonData)。两类指纹 TTL=2秒；字段不足时非空 eventID 回退 type+ID，TTL=24小时。GROUP_JOIN_REQUEST 及其他类型键为空，跳过去重。
6. Redis 非空且启用时 SETNX+TTL。**实际代码 Redis 出错会记录“回退内存”，但随后直接返回 true；没有执行下方内存分支**，因此该事件会被当作重复丢弃。禁用/无 Redis 才进入内存；内存是一个全局 map/order、容量 256，不是注释所说的每类型256。过期访问删除并重新记入，超过容量删除队首键。

### 2.2 分派表

| 入口/触发 | owner 与数据/外部副作用 | 取消、退出、失败边界 | 阶段及结论 |
|---|---|---|---|
| handleQQBotEvent，已验签且未去重命中 | integrations 编排；记录最多500字节事件预览；按事件类型解析 D | goroutine 不持有 HTTP context、无 join/持久化投递/自动重试；panic recover 仅记日志；解析失败返回，未知类型只落预览日志后结束 | P7，静态关闭；隐私及可靠投递验收 P7/P8 |
| GROUP_AT_MESSAGE_CREATE / GROUP_MESSAGE_CREATE → HandleGroupAtMessage | identity 绑定；billing 签到、转账、红包、偷取、掉落；usage 日志；integrations 回复/撤回；命令开关由 QQ 配置领域拥有。菜单/余额/费率为查询；普通消息进入诱饵采样与掉落累计 | nil/bot跳过；另有 markMessageSeen(event.ID)；命令按作用域冷却，拒绝静默；按条件单分支返回。异步账务后置缓存已由 data-jobs §10登记，不重复算新任务 | 核心账务P4，QQ集成P7；静态关闭 |
| INTERACTION_CREATE → HandleInteraction | type11/12先 AnswerInteraction；仅群场景继续；菜单回调、批量/单个抢红包、详情及签到，回复使用外层 PayloadEventID（为空回退 ID） | 内层ID空才用外层补齐；作用域冷却、群签到开关；失败日志，不撤销 webhook 去重标记 | billing P4 / integrations P7；静态关闭 |
| GROUP_JOIN_REQUEST → HandleGroupJoinRequest | integrations 读取自动批准开关/关键词；username、验证消息和QA文本命中后 ApproveJoinRequest | 已自动审批、关闭、空关键词、不命中均退出；平台调用失败只日志；webhook 去重键为空 | P7；静态关闭，不宣称事件幂等 |
| C2C_MESSAGE_CREATE → HandleC2CMessageForBind | identity.ConsumeQQBindCode 消耗绑定码/绑定身份；usage.RecordLog；integrations.SendC2CMessage | nil/bot/非绑定码跳过；失败回复，发送错误忽略；无请求取消传播 | identity P2 / integrations P7；静态关闭 |

未知的群ID、OpenID、命令参数、红包ID是运行时值，不增加入口分母。QQ Redis错误丢事件、预览原文隐私与 ACK/去重/业务事务不原子均为已定位后阶段问题，不是要求 P0 先执行故障测试。

## 3. 通知、健康、审计与日志

| 证据/触发 | owner、数据副作用 | 取消/退出与重试 | 阶段/静态结论 |
|---|---|---|---|
| ops/limit_notify.go:30–46,89–117 startCleanupTask；第一次内存 checkMemoryLimit 经 cleanupOnce.Do | ops/security 的通知抑制状态；每小时遍历 sync.Map，删除 age≥当前通知窗口的项；不是发送邮件、不是改数据库。用户+通知类型+小时组成键；Redis分支依靠TTL不启动该清理 | 无限 Sleep，无 stop/context/join；配置变化影响每轮过期判定。进程退出才终止 | P2/P7；关闭，懒启动清理应纳入jobs生命周期 |
| catalog/track_health.go:232–265 HealthStore.escalateModelLocked；fatal模型失败累计达到冷却阈值，再达到正数 CooldownDisableStreak | catalog 健康内存计数→ChannelModelDisabler（bridge_channel_health.go:157 默认 DisableChannelModel）禁用渠道模型 | 持锁内摘除计数并捕获hook后派发；失败重新持锁、存在当前channel时恢复计数至少reached，下一次冷却再试；无timer/持续worker/context/join。不是channel_test | P5/P7；关闭 |
| security/audit_access.go:75–140 finishAdminAudit；Admin/Root写操作 Next之后，非nil capture且未手工埋点 | security采集operator、IP、method/route/path、状态及params，usage.RecordOperationAuditLog 写审计；64KiB响应仅用于成功判断，不直接作为审计body写入 | 入闭包前提取上下文值；无取消/join/显式重试。route params来自c.Params，不能由此声称所有容器均深拷贝。响应JSON success优先，状态≥400失败 | P2/P7；关闭，隐私/丢失策略P8 |
| sensitive/audit_block.go:46–103 startSensitiveAuditWorker / RecordSensitiveBlock；审计开关开且首次记录 | security→usage，Once创建1024有界队列；单worker写LogTypeSensitive审计；snippet按UTF-8边界截断256字节，matched及模型/渠道/IP进入params。usage/register_sensitive_hooks.go:15安装RecordSensitiveAuditLog | 队列满非阻塞丢弃、首个及每1000次日志；nil hook静默跳过；range channel，无生产close/stop实现；请求值先采集，不依赖请求继续存活。不是SensitiveAuditCleanup留存清理 | P5/P7；关闭，停机排空和原文保留P7/P8 |
| logger/logger.go:95–117 logHelper；logCount>1,000,000且!setupLogWorking | ops/storage；当前行同步写stdout/stderr+文件，异步仅SetupLogger轮转；配置LogDir时按秒命名append打开0644文件、切换writer并关闭旧文件 | TryLock失败返回；无LogDir则不建文件；打开失败log.Fatal；写锁保护切换/旧文件关闭；无单独flush任务/join。计数和working标志非完整同步，不能证明无竞争 | P1/P9；关闭 |

## 4. 管理扇出、探测及 relay 后处理

| 固定调用点与触发 | owner / 副作用 | 取消、等待、退出 | 阶段/结论 |
|---|---|---|---|
| ops/manage_model_metadata_sync.go:613–974 FetchUpstreamRatios，:673每个有效upstream派发 | catalog读取渠道/启用key及本地价格；integrations GET上游价格/模型，OpenRouter按渠道注入Bearer；归并转换后的比率和错误供响应，不在该闭包写models。并发信号量上限8，goroutine数量仍为输入项数 | 每项取得sem后才基于c.Context设timeout；sem等待不select取消。HTTP至多3次，失败Sleep 200/400/800ms；body defer Close。结果channel容量=len(upstreams)，wg.Wait后close并汇总，因此请求内扇出。地址可以是输入endpoint；不能把其http前缀过滤称完整SSRF防护 | catalog P3 / integrations P7；关闭；URL安全验收P8 |
| handler/handle_model_sync.go:313 SyncUpstreamModels vendors闭包 | integrations拉vendors→请求内映射；后续主流程由catalog创建Vendor/Model、选择字段覆盖已有模型；sync_official=0跳过 | WithTimeout(c.Context)，默认15秒；defer wg.Done；vendor错误忽略；wg.Wait后才处理 | P3/P7；关闭 |
| 同文件:318 SyncUpstreamModels models闭包 | integrations拉models，fetchErr决定失败响应 | 与:313共用超时和Wait；models失败终止同步；不是异步DB写入 | P3/P7；关闭 |
| 同文件:513 SyncUpstreamPreview vendors闭包 | integrations读vendors；catalog后续查本地模型/厂商构造差异，不执行正式同步写入 | 默认15秒请求context；vendor错误忽略；Wait | P3/P7；关闭 |
| 同文件:517 SyncUpstreamPreview models闭包 | integrations读models；错误返回预览失败 | 与:513共用context；Wait；fetchJSON中的Sleep不感知取消，但HTTP请求带ctx | P3/P7；关闭 |
| handler/handle_channel_probe.go:905 手动TestChannel，testChannel返回localErr=nil之后 | catalog.Channel.UpdateResponseTime 写渠道响应耗时；即使newAPIError非nil仍会派发，不仅成功探测 | 请求内探测传requestCtx；落库goroutine无context/join/重试，返回不等落库；不是整轮channel_test调度 | P3/P5/P7；关闭；渠道删除并发语义P7 |
| handler/handle_relay.go:502 Relay最终newAPIError非nil | usage.RecordRelaySample(relayInfo,false,0)，失败采样，不是再次扣款 | 捕获relayInfo指针，未join，无显式取消/重试；采样不能让relay跨域直接写usage表 | P5/P7；关闭 |
| handler/handle_relay.go:689 processChannelError，ShouldDisableChannel且AutoBan | catalog.DisableChannel，渠道/多key状态禁用及其领域处理；err信息用于禁用原因 | 捕获channelError及err而非从异步context重新取渠道；无join/context。紧随其后的RecordErrorLog在调用线程执行，不混为这个闭包 | P5/P7；关闭 |

管理同步 HTTP 客户端与目标URL策略须在 integrations 实现，catalog 的写入通过公开端口；不把旧 handler 内直接 GORM 查询/事务复制到 Axum transport。

## 5. 连接生命周期及五家供应商

| 入口/触发 | owner / 数据与外部副作用 | 取消、退出、资源边界 | 阶段/静态结论 |
|---|---|---|---|
| egress/dial_singbox.go:78–93 SingBoxDialer.Close，热重建替换旧实例或CloseSingBoxDialer | integrations.egress：调用box.Close释放网络资源；拨号本身:73–75同步委托DialContext | sync.Once；goroutine结束close(done)，调用者最多等10秒。超时只返回错误，不终止box.Close；err由协程与超时分支共享，不能证明无竞态。无DB写入 | P5/P7；关闭，纠正“拨号协程” |
| fiberadapter/stream.go:159–198 responseState.run，modeChain | transport执行请求链；先完成则buffered，先stream/upgrade则提交响应并允许链继续 | 链goroutine recover panic，defer finished/done及最后cancel；不能dispatcher返回就取消，否则流首帧后中断。direct/synthetic同步执行 | P5/P6；关闭，Axum须保留生命周期语义而非Fiber实现 |
| 同文件:273–306 commitStream，安装pipe读取端后 | transport：回放pending字节、flush、等待链结束、最终flush并关闭写端生成EOF | :450–457写失败markDisconnected取消请求；flush失败路径传播断连；worker等finished，无独立持久化任务。链若不返回则不能静态保证排空完成 | P5/P6；关闭 |
| openai/relay_realtime.go:37 client reader | relay：读客户端WS，更新tools/localUsage，转发target；观测channel容量100、满则丢观测消息 | 循环开始检查c.Context.Done，ReadMessage本身不被select抢占；读错关闭clientClosed，解析/写错送errChan；panic送errChan。无WaitGroup | P6，账务P4；关闭 |
| 同文件:97 target reader | relay→billing：读上游事件、更新音频格式及usage；response.done调用preConsumeUsage→PreWssConsumeQuota，转发client | 与上行相同；主select收到任一关闭/error/context即结束并补结未零usage/localUsage，补结错误忽略；尚未join两个reader。relay/handle_websocket.go:37由外层defer关闭target、:46后结算。共享usage对象的并发与断连结算归P4/P6，不宣称无竞态或exactly-once | P6/P4；关闭 |
| baidu/relay-baidu.go:188–242 getBaiduAccessToken，缓存token距过期≤1小时 | relay/integrations：go getBaiduAccessTokenHelper POST OAuth，更新baiduTokenStore；立即返回现有token，未命中则同步获取 | helper defer body.Close；请求未附调用者ctx，异步错误忽略；无singleflight/join，近到期并发请求可重复刷新。不是stream闭包 | P6；关闭 |
| cohere/relay-cohere.go:82–175 cohereStreamHandler | relay：reader扫描上游逐行送dataChan；主循环转SSE、累计usage/text，结束DONE；无独立DB写入 | 无缓冲data/stop channel；EOF/scan错误后stop发送；两个循环均无ctx选择；本函数未见resp.Body.Close，不能承诺本地释放完整。写SSE错误未驱动退出 | P6；关闭，取消/资源释放债务已定位 |
| palm/relay-palm.go:52–103 palmStreamHandler | relay：worker ReadAll整包后转换一条SSE、传responseText；并非真正逐token上游流 | 错误经stop通道结束；正常读完关闭body，主循环结束再关闭；无ctx选择，ReadAll及无缓冲发送可能等待；SSERender错误未驱动退出 | P6；关闭 |
| xunfei/relay-xunfei.go:204–248 xunfeiMakeRequest，流式与非流式消费者共用 | relay/integrations：WS拨号握手5秒，WriteJSON请求；worker读/解码响应→dataChan，status=2结束 | worker defer conn.Close；read/parse错误break后发送stop。无ctx入参，无缓冲send阻塞会阻止defer；WriteJSON失败发生在启动worker之前且未见Close。不是只属于stream调用路径 | P6；关闭 |
| zhipu/relay-zhipu.go:157–223 zhipuStreamHandler | relay：scanner拆data/meta，无缓冲通道；主循环转SSE、解析usage，EOF后DONE | scan错误只日志；stop发送后主循环退出并关闭body；无ctx选择，写错误未控制退出；不得把正常EOF释放等同取消可靠 | P6；关闭 |

这些入口无须枚举运行时连接数或供应商账号数。后阶段必须明确请求取消、关闭读写端、join/排空顺序与账务唯一结算；本次只冻结旧事实和债务，不写Rust服务，也不要求现在跑断连测试。

## 6. clearExpiredItems 完整生命周期

证据：`common/rate-limit.go:8–75`；`common/constants.go:227`；`transport/middleware/limit_rate.go:38,154,208`；`transport/middleware/limit_email_verification.go:63`。

| 触发 / owner | 数据副作用 | 取消/退出 / 确切边界 | 阶段/结论 |
|---|---|---|---|
| security中间件共享一个inMemoryRateLimiter；IP、用户、邮件验证码内存路径调用Init；store首次为nil且expirationDuration>0启动 | 默认20分钟Sleep，然后锁内扫描：空队列或最后时间距今严格大于expirationDuration秒数则delete；只清进程内map，不删除Redis/数据库 | 双重nil检查，锁内只启动一次；重复Init不更新周期。无stop/context/join，Reset仅测试清空map且不停止原worker。Request自身未加mutex，不能据cleanup持锁断言并发安全；Init外层读亦非完整同步 | P2/P7；关闭，不是每个限流键一条任务 |

## 7. 定时/等待候选与既有30行表的静态差集

方法：对 `/root/newapi/apps/api/main.go` 与 `/root/newapi/apps/api/internal/**/*.go` 用Grep核对 `time.(Sleep|NewTicker|AfterFunc|Tick|NewTimer|After)(`，读取具名函数/邻近上下文；额外追踪 RandomSleep、SafeSendStringTimeout 的调用者。匹配测试文件不算生产任务；`transport/contract/conformance/stream_cases.go:603`虽非 `_test.go` 仍是契约测试慢流模拟；main:286的ticker注释不算入口。该词法候选集合不冒充任意别名/第三方库内部定时器的AST全集。

### 7.1 已落在30行启动/handler/观测台账的交集（不新增任务）

原表见 `/root/newapi-rs/docs/data-jobs-inventory.md:113–142`。以下列出全部本轮timer命中对应关系；原表无timer命中的行不因此消失。

| 候选位置（internal下） | 对应已有行 / owner / 阶段 |
|---|---|
| catalog/cache_channels.go:109 | SyncChannelCache，catalog P3/P7 |
| catalog/publish_gateway_config.go:67 | GatewayConfigOutboxPublisher，catalog/jobs P3/P7 |
| dbinfra/store_options.go:74 | SyncOptions，config P1/P7 |
| identity/policy/enforcer.go:89 | StartPolicySync，security P2/P7 |
| usage/store_usedata.go:53 | UpdateQuotaData，usage/billing P4/P7 |
| usage/user_insight.go:228 | UpdateInsightProfiles，usage P7 |
| usage/user_insight_sample.go:458 | MaintainInsightSamples，usage P7 |
| billing/qq_redpacket.go:428 | MaintainQQRedPackets，billing P4/P7 |
| main:293 | runRouteStatsSweep，catalog P5/P7 |
| billing/fetch_channel_balance.go:481 | AutomaticallyUpdateChannels，catalog/integrations P7 |
| catalog/schedule_codex_refresh.go:40 | CodexCredentialAutoRefresh，integrations/catalog P6/P7 |
| billing/reset_subscription_cycle.go:35 | SubscriptionQuotaReset，billing P4/P7 |
| ops/schedule_tasks.go:130,309,525 | SystemTaskRunner/续租及SystemInstanceReporter，jobs/ops P7；不是三个新调度种类 |
| dbinfra/batch_update.go:15 | BatchUpdater，billing/identity P4/P7 |
| common/pprof.go:39,43 | pprof/Monitor观测，ops P9 |
| usage/record_perf.go:684 | perf flush，usage P7 |
| common/system_monitor.go:42,47 | SystemMonitor，ops P7/P9 |
| identity/gc_session.go:20 | AuthArtifactCleanup，identity P2/P7 |
| sensitive/gc_audit.go:20 | SensitiveAuditCleanup，security/usage P7；不等于audit_block worker |

### 7.2 表外差集：实际长生命周期/延迟工作及连接派生

| 候选位置 | 分类与触发/副作用 | 退出及归属 |
|---|---|---|
| common/rate-limit.go:38 | 本文§6懒初始化清理 | 无stop，security/jobs P2/P7 |
| ops/limit_notify.go:34 | 本文§3首次内存通知检查启动清理 | 无stop，ops/jobs P7 |
| billing/qqbot_service.go:424 | 成功发送消息后delay>0且msgID非空，AfterFunc延迟撤回；既有data-coverage:119已核 | 单次RecallGroupMessage；无持久化/重启恢复、失败日志；integrations P7 |
| egress/dial_singbox.go:88 | Close的10秒等待上限；实际worker在:82，本文§5 | 超时不杀worker；integrations P5/P7 |
| gateway/scan_sse.go:163,185,235 | 每次ScanSSE超时ticker、可选ping ticker及ping最长30分钟timer；SSE写入和stream状态 | cleanup cancel/stop/Close body/Stop tickers/wg.Wait；ping监听request Done、stop、超时。relay P5/P6；不是全局job |
| relay/channel/api_request.go:434,446 | startPingKeepAlive请求keepalive，周期ticker及120分钟上限 | Stop ticker/timer；ping失败、pinger取消、request Done或超时退出；返回stopPinger+done供调用者收束。relay/transport P5/P6 |

### 7.3 表外差集：内联等待，不是独立后台任务

| 候选位置 / 函数 | 触发和副作用；退出与阶段 |
|---|---|
| main:242 | server.Serve goroutine启动后等待100ms才记启动成功；这次Sleep本身不是后台worker。HTTP监听归transport P1/P9，不伪装成第31个定时job |
| billing/fetch_channel_balance.go:460 updateAllChannelsBalance | 渠道余额查询循环内RequestInterval节流；已有关联AutomaticallyUpdateChannels，手动调用同样内联；catalog/integrations P7 |
| billing/resolve_funding_source.go:166 refundWithRetry | 事务退款最多3次，重试间200/400ms；Sleep不感知ctx；billing P4，不增加退款调度任务 |
| catalog/health_unit_store.go:95 casBackoff | CAS重试attempt×200μs，casMaxAttempts=16；catalog P5/P7；不是健康清理循环 |
| common/go-channel.go:35 SafeSendStringTimeout | 通道发送与timeout竞争，无go启动；main/internal检索未见生产调用者，作为未用封装归公共基础P1，不虚构worker |
| common/utils.go:220 RandomSleep → billing/store_redemption.go:90 | 兑换流程0–2999ms随机等待；无go、无ctx；billing P4 |
| ops/manage_model_metadata_sync.go:740 | 本文§4扇出worker内部HTTP退避，不能再计一个job；catalog/integrations P3/P7 |
| handler/handle_model_sync.go:160,232 fetchJSON | 请求内HTTP错误/重试响应退避+jitter，ctx附请求但Sleep不可取消；catalog/integrations P3/P7 |
| handler/handle_channel_probe.go:1003,1008 | 整轮探测渠道间节流，nil ctx使用Sleep，否则Done/After选择；已有channel_test行，catalog P5/P7 |
| handler/handle_upstream_update.go:750,755 | 模型更新渠道间节流，同上nil ctx及可取消分支；已有model_update行，catalog P3/P7 |
| handler/relay_failover.go:151,155 | failover内等待，nil ctx Sleep否则Done/After；relay P5，非恢复调度器 |
| task/poll_task.go:421 | video任务间1秒可取消节流；DisableTaskPollingSleep或最后一项跳过；已有async_task_poll行，jobs/relay P6/P7 |
| relay/channel/ali/image.go:232,241,262 asyncTaskWait | 同步等待上游异步图片结果：先5秒、后10秒查询；成功响应路径检查20步上限；错误分支continue绕过maxStep检查，不能宣称绝对20次有界。Sleep无ctx；relay P6，不是独立持久化轮询job |
| relay/channel/coze/adaptor.go:98 DoRequest | 非stream请求创建会话后每秒检查完成，完成/错误退出；无本地最大次数及Sleep取消；stream直接DoApiRequest不进此循环。relay P6 |

由此，限定main/internal计时器候选的差集每项均已分类；长生命周期任务、按请求派生协程、内联等待、测试模拟与注释分开，不以“有Sleep/ticker”机械增加后台任务分母。既有30行本来包含handler、观测与停机动作，不是30个独立定时器。

## 8. 收口状态及后阶段责任

| 原data-coverage行 | 本次静态关闭内容 | 后阶段责任（不前置阻塞本清单） |
|---|---|---|
| 147 | QQ验签、去重键/TTL/Redis失败实际分支、5种事件名称对应4条处理分支 | integrations P7：持久化/重放/ACK策略；billing P4资金幂等；security P8隐私 |
| 148 | 通知清理、健康禁用、管理审计、敏感队列、文件轮转均核清 | owner按§3落实有界队列、退出/排空、日志脱敏；P2/P5/P7/P9 |
| 149 | 价格扇出、4个模型同步闭包、probe耗时、2个relay后处理逐点结论 | catalog/integrations P3/P7；usage/relay P5/P7；URL约束P8 |
| 150 | sing-box关闭、2个Fiber闭包、2个realtime方向、5家供应商逐点结论 | integrations/transport/relay P5/P6；realtime账务P4；无泄漏及取消运行证明留后阶段 |
| 151 | 共享限流器完整生命周期；main/internal等待候选对30行表差集逐项归属 | security P2；jobs P7；请求取消P5/P6 |

真实尚不能由静态阅读证明的事项已具体化：sing-box.Close超时后的第三方内部资源是否最终释放；OpenaiRealtimeHandler共享usage并发及两个reader是否在外层关闭后及时退场；Cohere本函数不关闭body时所有上层路径的最终释放；无stop worker的进程退出丢失窗口。这些分别属于 integrations P5/P7、relay/billing P4/P6、relay P6、jobs/usage P7/P9 的实现及运行验收，不是新增无限入口分母。源码中“没有取消/没有join”的事实本身已经完成P0登记，不用未来故障测试PASS替代静态清单。

本文件不修改其他台账旧勾选，供集成者按147–151五组引用合并；不对data-coverage:144–146配置/SQL工作项、其他代理审计或P0全局通过作结论。
