# P0 数据、任务、集成与配置台账

状态：进行中，未验收。审阅日期：2026-11-02。源码固定为 `17970da4571e81308f176a0e61a38276e5771606`；本文源码路径均相对于只读上游 `/root/newapi`。没有执行本地构建、测试、服务、容器或脚本。已有Go远程基线：ci-baseline.md记录run 41425478831 attempt 1/2、SHA 6e599ec59837d645b4740ebe363790beda6b40f1均success；不代表Rust或后续数据库/业务阶段通过。

## 1. 覆盖边界与重要范围差异

**最新批准范围**：Rust目标只SQLite+PostgreSQL；MySQL历史事实保留，但不迁移、不支持，不要求MySQL CI/最低版本验收。兼容原表/字段/ID/额度/时间/软删除，差异显式记录，禁止未经批准有损转换。ClickHouse独立日志及Timescale扩展不自动移除。

本轮覆盖生产代码的迁移注册点、启动入口、显式 TableName、版本化 SQL 文件发现、主要配置入口和外部集成文件发现。**不是全量列/索引/调用点审计，不能据此通过 P0。** 表名未显式定义者下表是 GORM 默认命名预期，必须在远程从实际 schema 验证（尤其 TwoFA 缩写）。目标归属是 Rust 设计约束，不是声称 Go 已无跨域直接写表。

旧计划曾列三种SQL数据库，现Rust目标调整为SQLite+PostgreSQL； `apps/api/internal/dbinfra/open_db.go:63–104,148–247` 实际支持 **ClickHouse 独立日志库和 PostgreSQL TimescaleDB 扩展**。必须由集成者登记计划修订并征求确认，不能默默删掉；SQLx SQLite/PostgreSQL两目标库实现不能自动视为覆盖 ClickHouse。

## 2. 表/模型逐项台账

以下每行状态均为“进行中：已定位，schema/行为待验”。W 为目标唯一写入域，R 为经公开端口读取的域；跨域资金写入必须由 billing 应用服务编排，identity 负责用户/令牌行持久化与锁协议，不允许 relay 自行改余额。证据简称：`I=apps/api/internal/identity/migrate_identity.go:12–34`；`C=apps/api/internal/catalog/register_migrations.go:9–19`；`B=apps/api/internal/billing/register_migrations.go:8–20`；`U=apps/api/internal/usage/register_migrations.go:8–15`；`O=apps/api/internal/ops/register_migrations.go:10–16`；`T=apps/api/internal/task/register_migrations.go:8–10`。

| 模型 / 表名（默认命名待 schema 确认） | W / R | 阶段 | 注册证据及关键兼容项 |
|---|---|---|---|
| Option / options | catalog / config及全域（公开端口） | P1读取、P3写入 | dbinfra/run_migrations.go:12；key/value、热更新、敏感配置 |
| Setup / setups | storage初始化 / identity,ops | P2 | O；初始化版本/时间、旧重复记录修复 |
| User / users | identity（资金由billing编排） / identity,billing,usage | P2/P3/P4 | I；密码、权限、余额、软删除、auth_version |
| Token / tokens | identity（额度由billing编排） / relay,billing | P2/P3/P4 | I；密钥、额度、model_limits、撤销 |
| UserSession / user_sessions | identity / security | P2 | I；会话散列、撤销、保留期 |
| AuthFlow / auth_flows | identity / security | P2/P7 | I；短期流程、过期、单次消费 |
| ExternalIdentityClaim / external_identity_claims | identity / security | P2/P7 | I；外部身份唯一声明及回填 |
| PasskeyCredential / passkey_credentials | identity / security | P7 | I；凭证、计数器，P2不得误报可用 |
| TwoFA / 默认表名待实测 | identity / security | P2 | I；密文种子、验证及锁定 |
| TwoFABackupCode / 默认表名待实测 | identity / security | P2 | I；备份码单次消费 |
| CustomOAuthProvider / custom_oauth_providers | identity / integrations | P3/P7 | I；客户端秘密与动态提供商 |
| UserOAuthBinding / user_oauth_bindings | identity / integrations | P7 | I；用户与提供商绑定唯一性 |
| CasbinRule / casbin_rule | identity / security及全域鉴权（公开端口） | P2/P3 | I；显式单数表名、策略同步 |
| AuthzRole / authz_roles | identity / security（公开端口） | P2/P3 | I；角色与策略一致性 |
| QQBinding / qq_bindings | identity / integrations,billing | P7 | I；QQ外部身份 |
| QQBindCode / qq_bind_codes | identity / integrations | P7 | I；绑定码过期/消费 |
| QQUnbindRecord / qq_unbind_records | identity / billing,integrations | P7 | I；解绑记录及计费限制 |
| Ability / abilities | catalog / relay | P3/P5 | C；能力索引、重建 |
| Channel / channels | catalog / relay,integrations | P3/P5/P6 | C；密钥、多key、JSON配置、代理、状态 |
| ChannelModelHealth / channel_model_health | catalog / relay,jobs | P5/P7 | C；显式表名；channel/key/model复合主键、毫秒冷却 |
| ChannelModelRoute / channel_model_routes | catalog / relay | P3/P5 | C；去分组唯一键、权重/优先级退役 |
| GatewayConfigOutbox / gateway_config_outboxes | catalog / jobs | P3/P7 | C；事务内发布意图、重试与重复投递 |
| GatewayConfigRevision / gateway_config_revisions | catalog / 全实例缓存 | P3/P7 | C；版本种子/原子更新 |
| Model / models | catalog / relay,billing | P3 | C；模型元数据 |
| PrefillGroup / prefill_groups | catalog / relay | P3/P5 | C；名称唯一约束升级 |
| Vendor / vendors | catalog / relay | P3 | C；供应商目录 |
| Redemption / redemptions | billing / identity,ops | P4 | B；兑换码、原子兑换、软删除 |
| TopUp / top_ups | billing / integrations,usage | P4/P7 | B；金额精度、支付订单幂等 |
| Checkin / checkins | billing / identity | P4 | B；日边界、重复签到 |
| SubscriptionPlan / subscription_plans | billing / catalog,identity | P4 | billing/bootstrap_subscription_plan.go:15–21；不在普通注册列表中 |
| SubscriptionOrder / subscription_orders | billing / integrations | P4/P7 | B；支付状态机与回调重放 |
| UserSubscription / user_subscriptions | billing / relay,identity | P4 | B；配额、周期重置、到期 |
| SubscriptionPreConsumeRecord / subscription_pre_consume_records | billing / relay | P4 | B；预扣、结算、退款幂等 |
| QQCheckin / qq_checkins | billing / integrations | P4/P7 | B；QQ签到收益 |
| QQDrop / qq_drops | billing / integrations | P4/P7 | B；拾取原子性 |
| QQTransfer / qq_transfers | billing / integrations | P4/P7 | B；转账双边锁序 |
| QQRedPacket / qq_red_packets | billing / integrations,jobs | P4/P7 | B；红包余额/过期退回 |
| QQRedPacketGrab / qq_red_packet_grabs | billing / integrations | P4/P7 | B；重复领取唯一性 |
| QQSteal / qq_steals | billing / integrations | P4/P7 | B；并发额度变化 |
| ProxyNode / proxy_nodes | catalog / integrations,relay（公开端口） | P3/P7 | egress/store_proxy_node.go:137；代理秘密与出站配置 |
| SMTPQuotaUsage / smtp_quota_usage | usage / integrations（配额端口）,identity,ops | P7 | mailer/quota_usage.go:22–27；显式单数usage、配额 |
| SystemInstance / system_instances | jobs / ops | P7 | O；实例心跳与清理 |
| SystemTask / system_tasks | jobs / ops及任务处理域 | P7 | O；执行状态、payload/result、重试 |
| SystemTaskLock / system_task_locks | jobs / jobs | P7 | O；跨master租约、续租、过期接管 |
| Midjourney / midjourneys | jobs / relay,usage | P6/P7 | T；外部任务ID、轮询和退款 |
| Task / tasks | jobs / relay,billing,usage | P6/P7 | T；私有JSON、计费上下文、取消/超时 |
| Log / logs | usage / ops,billing | P4/P7 | U；同时登记主库及日志库；实际写库需逐调用核验 |
| QuotaData / quota_data | usage / ops | P4/P7 | U；内存聚合、停机落库 |
| UserInsightProfile / user_insight_profiles | usage / ops | P7 | U；增量合并 |
| UserInsightSample / user_insight_samples | usage / ops | P7 | U；采样、留存/隐私 |
| UserInsightClientBan / user_insight_client_bans | usage / security | P7 | U；封禁传播 |
| PerfMetric / perf_metrics | usage / ops | P7 | usage/record_perf.go:231–232；桶聚合落盘 |
| schema_migrations（原生SQL） | storage迁移 / storage | P1禁自动修改，P8升级 | dbinfra/sql_migrations.go:47–51；version主键、applied_at非空 |

不应把查询 DTO 误记成独立表：`TokenNameRow`映射tokens、`UserQuotaRow`映射users、egress `optionRow`映射options；`CheckinRecord`出现在测试AutoMigrate，但生产迁移只注册Checkin，需进一步核验其用途。`Pricing`、`FlowQuotaData`、统计返回对象亦未由本次生产注册扫描证明为独立表。未排除其他原生 SQL/动态表。

### 2.1 集合分母与DAG口径（当前有效）

生产主库注册分母=51：identity 15 + catalog 9 + billing 12 + ops 4 + task源码包2 + usage普通注册5 + dbinfra Option 1 + egress ProxyNode 1 + mailer SMTPQuotaUsage 1 + usage PerfMetric 1。另有后置SubscriptionPlan 1，合计52个独立模型；日志注册Log 1为同一模型第二个数据库目标，不重复算实体。原生schema_migrations另计1，不在52中。来源为§2各注册点和common/dbx/migrate.go:17–52（append保存注册次序，无去重）。字段登记52/52见schema §2、§6，运行DDL未验收。

注册集合与执行集合不同：主库迁移master门控；SubscriptionPlan在post migration；日志共库复用DB，独立关系日志库走Log注册，ClickHouse走原生DDL，Timescale走扩展分支。schema §4逐项登记动态/原生表与分支；全仓Raw/Exec动态实参闭包尚未证明，不能把52当全部物理表数量。测试AutoMigrate及DTO不加入生产分母。

持久化owner严格遵循现有DAG：options、ProxyNode归catalog；CasbinRule/AuthzRole归identity；Task/Midjourney及SystemTask/SystemTaskLock/SystemInstance归jobs；SMTPQuotaUsage归usage。config、安全中间件及integrations只经既有公开端口使用，不新增task crate或反向依赖。下文task源码路径及旧集成分类只描述Go位置/业务语义，不覆盖本段持久化owner。

任务分母分层：§4为30行启动/注册/退出任务族（包含组合条目，不声称30个独立goroutine）；§7为30行非启动候选族，每行可能有多个调用点。当前已逐行给owner/阶段，尚未将所有调用点拆为独立ID并追完init/封装/relaykit入口，因此全量任务分母仍受阻，不能报告100%任务覆盖。请求流式协程与持久化调度任务分开验收。

## 3. 迁移与数据库版本

| 项目 | 证据 | 行为/阶段 |
|---|---|---|
| DB选择与连接池 | dbinfra/open_db.go:63–193 | P1：SQL_DSN默认SQLite；postgres/postgresql前缀选PG，其余默认MySQL；local前缀SQLite；LOG_SQL_DSN可独立。SQL_MAX_IDLE_CONNS=100、OPEN=1000、LIFETIME=60秒；MySQL补parseTime并校验中文字符集 |
| 迁移执行权 | 同文件:133–140,183–188 | 旧Go仅master自动迁移；Rust不照搬启动自动写旧库，P8/P9授权升级 |
| 前置迁移顺序 | 同文件:195–214 | token model_limits→text；PG prefill旧唯一约束；CollapseRouteUnitGroups必须先于AutoMigrate，否则新唯一索引失败 |
| 注册模型及后置回填 | 同文件:215–229 | AutoMigrate→RunPostMigrations→版本SQL→DropLegacySchedulingColumns；不可仅移植SQL文件 |
| 身份回填 | identity/migrate_identity.go:31–34 | InitializeUserAuthVersions、InitializeExternalIdentityClaims；P2/P8 |
| 渠道回填 | catalog/bootstrap_migrations.go:20–25 | health key_index复合主键；旧健康状态→毫秒冷却、禁用档位；SeedChannelModelRoutes、InitializeGatewayConfigRevision；P3/P5/P8 |
| 套餐特殊迁移 | billing/bootstrap_subscription_plan.go | 单独AutoMigrate及旧列处理；P4/P8，字段级审计未完成 |
| 初始化修复 | ops/register_migrations.go:16 | RepairLegacySetups；P2/P8 |
| 前端配置迁移 | main.go:407–412；dbinfra/migrate_frontend_options.go | master运行，先验证控制台配置再初始化options；P1/P3/P8 |
| SQL账本 | dbinfra/sql_migrations.go:83–143 | 文件名排序、applies-to、每文件事务和记账；Timescale禁用时跳过而不记已应用；DDL跨库事务差异须测 |
| 001_drop_unused_log_indexes.sql | dbinfra/migrations/ | P7/P8；文件已定位，SQL逐句审计待补 |
| 002_logs_timescale_hypertable.sql | dbinfra/migrations/ | P7/P8；Timescale gate；主/独立日志库路径必须分别验 |
| Timescale运行时建表 | dbinfra/timescale_log.go；open_db.go:148–159,232–239 | 共享主库也会触发；P7/P8，不等同普通PG |
| ClickHouse日志 | open_db.go:242–329 | MergeTree、按月分区、created_at/request_id排序；LOG_SQL_CLICKHOUSE_TTL_DAYS控制TTL，包括移除TTL；P7/P8待范围确认 |
| 历史SQL | db/archive/migration_v0.2-v0.3.sql、migration_v0.3-v0.4.sql | 归档，不是上述embed迁移集合；P8旧版本路径审阅，不自动执行 |

最低版本声明来自 `README.md:264`、`apps/api/README.md:20`：MySQL ≥5.7.8、PostgreSQL ≥9.6；SQLite未声明最低版本。部署示例 `deploy/docker-compose.yml` 使用PG18、注释MySQL8.2/ClickHouse24.8；dev使用PG18/Redis7；`docs/k8s/data-layer.md`提及Timescale2.29.2-pg18。**部署示例不是最低版本验收结果。** 用户已将最低支持版本修订为 PostgreSQL 14（2026-11-05），pg9.6不再作为验收目标；SQLx版本尚未锁定；MySQL5.7.8仅历史声明、不迁移也不要求验证；Redis/ClickHouse/Timescale最低版本尚未确认。

## 4. 后台任务逐项台账

所有条目状态进行中，启动定位不等于已证明所有goroutine完备。main证据指 `apps/api/main.go`。jobs只调度，副作用通过拥有域端口执行。

| 任务 | 入口/门控证据 | R→W或外部副作用 | 阶段 |
|---|---|---|---|
| SyncChannelCache | main:94–117，内存缓存开启；Redis使其开启 | catalog库→实例缓存 | P3/P7 |
| RunGatewayConfigOutboxPublisher | main:124–126 | outbox→发布/确认、版本传播 | P3/P7 |
| SyncOptions | main:129，SYNC_FREQUENCY默认60秒 | options→配置缓存 | P1/P7 |
| StartPolicySync | main:132，同步频率 | 策略表→安全缓存 | P2/P7 |
| UpdateQuotaData | main:135 | 用量内存→quota_data | P4/P7 |
| UpdateInsightProfiles | main:138 | 内存增量→画像表 | P7 |
| MaintainInsightSamples | main:139–140 | 样本配额初始化、清理 | P7 |
| MaintainQQRedPackets | main:142 | 过期红包→余额退回 | P4/P7 |
| runRouteStatsSweep | main:149,292–315，每小时 | 清理EWMA及share pools内存 | P5/P7 |
| AutomaticallyUpdateChannels | main:151–157；CHANNEL_UPDATE_FREQUENCY | 上游查询→渠道余额/状态（细节待审） | P7 |
| CodexCredentialAutoRefresh | main:160；catalog/schedule_codex_refresh.go | 外部OAuth→渠道凭证 | P6/P7 |
| SubscriptionQuotaReset | main:163；billing/reset_subscription_cycle.go | 订阅周期→配额 | P4/P7 |
| SystemInstanceReporter | main:167；ops/schedule_tasks.go | 实例→system_instances | P7 |
| SystemTaskRunner / lease续租 | main:179–180；ops/schedule_tasks.go | system_tasks/locks；master去重、接管 | P7 |
| channel_test | handler/handle_system_task_runners.go:35–47 | Monitor开关，默认10分钟；模拟上游探测→健康状态 | P5/P7 |
| model_update | 同文件:78–91 | 默认开启/30分钟；上游目录→渠道模型，手动与自动不同 | P3/P7 |
| midjourney_poll | 同文件:122–134 | UPDATE_TASK且有未完成任务；15秒；外部任务→状态/账务 | P6/P7 |
| async_task_poll | 同文件:142–154 | UPDATE_TASK且有未完成任务；15秒；Suno/video→状态/退款 | P6/P7 |
| home_stats | 同文件:160–176 | HOME_STATS_TASK_ENABLED默认true；24小时；统计→缓存 | P7 |
| log_cleanup | ops/schedule_tasks.go:86 | 日志删除；留存/授权与独立库 | P7 |
| BatchUpdater | main:182–186，BATCH_UPDATE_ENABLED=true | 批量缓冲→用户/令牌/渠道计数；崩溃窗口待验 | P4/P7 |
| pprof与Monitor | main:188–194，ENABLE_PPROF=true | 8005监听、监控输出；不是普通业务任务 | P9 |
| Pyroscope | main:196 | 外部性能数据发送 | P9 |
| GeoIP启动更新 | main:414–415 | 网络下载→本地GeoIP文件 | P7 |
| CleanupOldCacheFiles | main:417–418 | 启动时删除旧磁盘缓存 | P7 |
| perf flush | main:434–437；usage.Init | 内存桶→perf_metrics | P7 |
| SystemMonitor | main:439–440 | 资源采样→内存/观测（详细写路径待审） | P7/P9 |
| AuthArtifactCleanup | main:484；identity/gc_session.go | master；会话/认证工件清理 | P2/P7 |
| SensitiveAuditCleanup | main:486；sensitive/gc_audit.go | master；敏感审计日志清理 | P7 |
| shutdown SaveQuotaDataCache | main:258–260，DataExportEnabled | 停机内存→统计表；优雅退出顺序 | P4/P9 |

请求生命周期SSE ping/超时计时器见 `gateway/scan_sse.go`、`relay/channel/api_request.go`，归P5/P6而不是定时系统任务。未逐项审查time.Sleep循环、包init启动、gopool/异步通知/按请求派生任务，故后台覆盖尚未封闭。

## 5. 外部集成与存储

| 项目 | 静态证据（apps/api/internal/ 下） | 归属与阶段 / 必需远程证据 |
|---|---|---|
| Redis | common/redis.go，main.go:426–430 | storage P2；连接失败、缓存键/TTL、限流、跨实例一致性待完整提取 |
| GitHub OAuth | security/oauth/github.go | integrations+identity P7；state/回调绑定/唯一声明 |
| Discord OAuth | security/oauth/discord.go | 同上；提供商错误与身份变化 |
| LinuxDO OAuth | security/oauth/linuxdo.go | 同上；信任级别与账号绑定 |
| OIDC | security/oauth/oidc.go | 同上；issuer、audience、nonce、JWKS刷新 |
| 自定义OAuth | security/oauth/generic.go、registry.go | DB配置→动态提供商；URL/秘密保护 |
| Passkey / 2FA | identity/passkey_credential.go、store_twofa.go | P7/P2；签名计数器、RP/origin、密文兼容、备份码重放 |
| Epay | billing/call_epay.go、subscription_payment_epay.go | billing端口+integrations P4/P7；签名、订单幂等；许可证阻塞见基线文档 |
| Stripe | billing/topup_stripe.go、subscription_payment_stripe.go | P4/P7；webhook签名、币种、舍入 |
| Creem | billing/topup_creem.go、subscription_payment_creem.go | P4/P7；回调/订阅一致性 |
| CodePay | billing/subscription_payment_codepay.go | P4/P7；充值及订阅路径逐项对照 |
| VMQ | billing/subscription_payment_vmq.go | P4/P7；同上 |
| Waffo | billing/topup_waffo.go | P4/P7；签名及幂等 |
| Waffo Pancake | billing/topup_waffo_pancake.go、subscription_payment_waffo_pancake.go | P4/P7；不得与Waffo普通接口合并遗漏 |
| SMTP池 | common/email_smtp_sender.go、mailer/quota_usage.go、transport/handler/handle_smtp_pool.go | integrations P2基础验证码/P7池；TLS、日配额、失败重试不可重复邮件 |
| QQ机器人及经济行为 | identity/qq_binding.go、billing/qq_*.go | integrations调用identity/billing P7；转账/红包核心P4；机器人网络协议仍待逐文件核验 |
| 代理/内嵌sing-box | egress/store_proxy_node.go；main.go:87–88 | integrations P5/P7；SSRF、代理凭据、关闭资源；许可证与“进程隔离”说法冲突 |
| GeoIP | geoip；main.go:414–415 | integrations P7；下载来源、完整性、授权、路径和过期行为待审 |
| 磁盘缓存/日志/前端嵌入 | common/disk_cache_config.go；main.go:51–55,417–418 | storage P7/P9；权限、清理、敏感内容；非对象存储能力声明 |
| Umami / Google Analytics | main.go:318–358 | 配置/前端 P9；动态脚本URL及ID、隐私告知 |
| Pyroscope / pprof | main.go:188–199 | ops P9；出站脱敏、禁生产默认暴露 |
| AI供应商与异步平台 | relay/channel、modules/relaykit、task | P5/P6；本台账未枚举全部适配器，必须并入协议代理台账，不能声称集成全集 |

尚未证明是否存在独立对象存储、Telegram/微信等其他登录或通知提供商；不能把上表当成排除性结论。

## 6. 配置入口与已定位逐项组

配置所有权：config只负责加载/校验/敏感值容器，领域决定语义；options写入P3，热更新不可越过领域验证。以下以组列出原样变量名，不宣称所有键或默认值已完成。

| 变量/参数 | 证据 | 阶段/语义 |
|---|---|---|
| --port、--version、--help、--log-dir；PORT、VERSION | common/init.go:18–47；main.go:231–234 | P1/P9；PORT覆盖flag端口，flag默认3000 |
| .env | main.go:364–372 | P1；先加载再InitEnv，读取失败处理不同于值非法 |
| SESSION_SECRET、CRYPTO_SECRET | common/init.go:50–64 | P2；后者缺失回退前者，默认占位secret致命错误 |
| USER_SESSION_ACTIVE_LIMIT、USER_SESSION_ISSUANCE_LIMIT、USER_SESSION_ISSUANCE_WINDOW_SECONDS、USER_SESSION_REVOKED_RETENTION_DAYS、USER_SESSION_HOURLY_ALERT_THRESHOLD | common/init.go:139–173 | P2；正数回退、窗口截断、溢出保护；cookie变量另待提取 |
| SQLITE_PATH、SQL_DSN、LOG_SQL_DSN、SQL_MAX_IDLE_CONNS、SQL_MAX_OPEN_CONNS、SQL_MAX_LIFETIME | common/init.go:69–70；dbinfra/open_db.go | P1目标SQLite/PostgreSQL+独立日志库；旧Go第三主库MySQL不迁移 |
| TIMESCALEDB_ENABLED、LOG_SQL_CLICKHOUSE_TTL_DAYS | dbinfra/sql_migrations.go:110–113；open_db.go:250–255 | P7/P8；扩展/保留期开关 |
| DEBUG、MEMORY_CACHE_ENABLED、NODE_TYPE、SYNC_FREQUENCY | common/init.go:87–109 | P1/P7；NODE_TYPE非slave即master |
| TLS_INSECURE_SKIP_VERIFY | common/init.go:91–100 | P1/P5；默认false；必须明确危险配置，不擅改兼容语义 |
| SMTP_STARTTLS_ENABLE、SMTP_STARTTLS_ENABLED、SMTP_INSECURE_SKIP_VERIFY、SMTP_TLS_INSECURE_SKIP_VERIFY | common/init.go:101–102 | P2/P7；兼容别名/优先级 |
| POLLING_INTERVAL、BATCH_UPDATE_ENABLED、BATCH_UPDATE_INTERVAL | common/init.go:104–110；main.go:182 | P4/P7 |
| RELAY_TIMEOUT、RELAY_IDLE_CONN_TIMEOUT、RELAY_MAX_IDLE_CONNS、RELAY_MAX_IDLE_CONNS_PER_HOST | common/init.go:111–114 | P5；默认0/90/500/100 |
| GEMINI_SAFETY_SETTING、COHERE_SAFETY_SETTING | common/init.go:117–118 | P6；BLOCK_NONE/NONE |
| GLOBAL_API_RATE_LIMIT_ENABLE、GLOBAL_API_RATE_LIMIT、GLOBAL_API_RATE_LIMIT_DURATION | common/init.go:121–123 | P2；true/360/180 |
| GLOBAL_WEB_RATE_LIMIT_ENABLE、GLOBAL_WEB_RATE_LIMIT、GLOBAL_WEB_RATE_LIMIT_DURATION | common/init.go:125–127 | P2；true/120/180 |
| CRITICAL_RATE_LIMIT_ENABLE、CRITICAL_RATE_LIMIT、CRITICAL_RATE_LIMIT_DURATION | common/init.go:129–131 | P2；true/20/1200 |
| SEARCH_RATE_LIMIT_ENABLE、SEARCH_RATE_LIMIT、SEARCH_RATE_LIMIT_DURATION | common/init.go:133–135 | P2/P3；true/10/60 |
| STREAMING_TIMEOUT、DIFY_DEBUG、MAX_FILE_DOWNLOAD_MB、STREAM_SCANNER_MAX_BUFFER_MB、MAX_REQUEST_BODY_MB、ANONYMOUS_REQUEST_BODY_LIMIT_KB | common/init.go:176–183 | P1/P5/P6；300/true/64/128/128/512 |
| FORCE_STREAM_OPTION、CountToken、GET_MEDIA_TOKEN、GET_MEDIA_TOKEN_NOT_STREAM | common/init.go:185–188 | P4/P5/P6；注意CountToken大小写 |
| UPDATE_TASK、TASK_QUERY_LIMIT、TASK_TIMEOUT_MINUTES、TASK_PRICE_PATCH | common/init.go:189,198–212 | P6/P7；true/1000/1440；0超时禁用；价格补丁列表 |
| AZURE_DEFAULT_API_VERSION | common/init.go:190 | P6；2025-04-01-preview |
| NOTIFY_LIMIT_COUNT、NOTIFICATION_LIMIT_DURATION_MINUTE、GENERATE_DEFAULT_TOKEN、ERROR_LOG_ENABLED | common/init.go:191–196 | P2/P7；2/10/false/false |
| TRUSTED_REDIRECT_DOMAINS | common/init.go:215–226 | P2/P7；逗号分隔、小写归一化 |
| CHANNEL_UPDATE_FREQUENCY、CHANNEL_UPSTREAM_MODEL_UPDATE_TASK_ENABLED、CHANNEL_UPSTREAM_MODEL_UPDATE_TASK_INTERVAL_MINUTES、HOME_STATS_TASK_ENABLED | main.go:151；handler/handle_system_task_runners.go | P7；见任务表 |
| ENABLE_PPROF、SHUTDOWN_TIMEOUT_SECONDS、UMAMI_WEBSITE_ID、UMAMI_SCRIPT_URL、GOOGLE_ANALYTICS_ID | main.go:188,252,318–358 | P9；停机默认120秒 |
| 持久化Option键、settings注册组 | dbinfra/store_options.go、settings/config.go及各域configure文件 | P1/P3/P7；**尚未逐键列出**，必须补齐默认值、秘密、热更新验证 |

## 7. 本轮增量与非启动任务核对清单

**后续增量以[data-coverage.md](data-coverage.md)为准**：主库注册51模型+后置SubscriptionPlan=52个独立模型，日志注册Log不重复计数；原10模型之外新增42模型字段登记（schema-inventory §6）。注册SystemTaskHandler分母6种，包含手动入口及非Scheduled的log_cleanup。该覆盖清单逐项列出静态勾选/未验运行证据、SQLite原生套餐与临时健康表、4组非启动任务的逐体核查及仍开放的全量异步任务分母；不宣称P0完成。以下早期“其余模型未展开”等描述由此增量取代。

新增字段台账见 [schema-inventory.md](schema-inventory.md)，配置键台账见 [config-inventory.md](config-inventory.md)。两份均明确区分事实/推断/待验证：历史首轮展开10个模型；本轮schema §6补齐其余42个模型的字段及标签，合计52个独立模型。实际DDL与行为仍按所属后续阶段验证，**不是全schema运行验收完成**。options新增固定键和领域hook键清单、反射注册组待办、env增量与动态参数缺口；未宣称全集。

下面是源码非启动并发入口的可核对候选。除明确说明已阅读函数体者外，**事实仅为调用点存在**；目标归属/阶段为推断；触发条件、准确副作用、调用者、取消与重试策略均待逐体核验。不得把候选任务名当成已确认行为，也不得将测试或注释里的go误记为生产入口。证据路径均在 apps/api/internal 下。

| 独立入口/候选任务 | 源码事实证据 | 目标归属/阶段 | 待验证 |
|---|---|---|---|
| 内存限流器清理 | common/rate-limit.go:14–24,36–40；Init仅store未建且expirationDuration>0时启动clearExpiredItems | security P2 | 已阅读函数体；实例数、周期、退出、重复Init竞争 |
| QQ webhook事件分派 | billing/manage_qqbot.go:247 `go handleQQBotEvent` | integrations→billing P4/P7 | webhook验签后的准确触发路径、eventID去重、重放 |
| QQ延迟操作 | billing/qqbot_service.go:424 time.AfterFunc | integrations P7 | 延迟实参、撤回/通知行为、重启后丢失及是否补偿 |
| QQ签到异步路径 | billing/qq_checkin.go:124,157 | billing P4/P7 | 两处分别核验日志/通知/缓存副作用 |
| QQ掉落异步路径 | billing/qq_drop.go:183 | billing P4/P7 | 同上，资金提交与异步失败边界 |
| QQ红包创建/领取异步路径 | billing/qq_redpacket.go:221,342 | billing P4/P7 | 每入口分别对账，不与启动过期维护合并 |
| QQ偷取异步路径 | billing/qq_steal.go:204 | billing P4/P7 | 失败后账务是否需重试 |
| QQ转账异步路径 | billing/qq_transfer.go:190,253 | billing P4/P7 | 双边提交后缓存/日志与幂等 |
| 普通签到异步路径 | billing/store_checkin.go:208,242 | billing P4/P7 | 两入口触发条件与事件丢失 |
| 实时计费异步路径 | billing/consume_quota_realtime.go:404,450,498 | billing P4/P6 | 每入口的资金/日志/通知操作与断连清算 |
| 文本计费异步路径 | billing/consume_text_quota.go:649 | billing P4/P5 | 结算返回前后顺序 |
| 账务session异步路径 | billing/open_billing_session.go:108 | billing P4 | 取消/退款、任务持有上下文寿命 |
| 用户写入后异步路径 | identity/store_users.go:1065,1094,1130,1155,1267 | identity经billing端口 P2/P4 | 五个调用点分别登记缓存失效/资金更新，不以一个名字验收 |
| token异步路径 | identity/token_store.go:336,378 | identity P2/P4 | 两入口缓存一致性、更新失败 |
| fallback health协程 | catalog/fallback_health.go:175 | catalog P5 | 是否懒初始化循环及清理时机 |
| health持久化异步路径 | catalog/health_unit_store.go:424 | catalog P5/P7 | 具体函数体、内存/库同步 |
| key probe异步路径 | catalog/store_key_probe.go:72 | catalog P5/P7 | lazy启动、探测限流、外网禁用 |
| health异步路径 | catalog/track_health.go:246 | catalog P5/P7 | 与系统channel_test区别、重入锁 |
| 通知限流异步入口 | ops/limit_notify.go:32 | ops/integrations P7 | 收件人与重复通知抑制 |
| 上游模型元数据并发 | ops/manage_model_metadata_sync.go:673 | catalog/integrations P3/P7 | 扇出上限、代理、安全取消 |
| 管理API模型同步 | transport/handler/handle_model_sync.go:313,318,513,517 | catalog/integrations P3/P7 | 四入口分别登记，是否请求内等待、失败汇总 |
| 手动渠道探测响应时长落库 | transport/handler/handle_channel_probe.go:905 `go channel.UpdateResponseTime` | catalog P3/P7 | 请求结束后写入、删除渠道并发 |
| relay请求后异步路径 | transport/handler/handle_relay.go:502,689 | relay→billing/catalog P4/P5 | 两入口逐体确认，不让relay直接跨域写表 |
| 访问审计异步入口 | security/audit_access.go:138 | security→usage P2/P7 | 隐私/脱敏、丢日志与缓冲边界 |
| 敏感内容审计异步入口 | sensitive/audit_block.go:49 | security→usage P5/P7 | 请求取消后上下文与日志保留 |
| 日志异步入口 | logger/logger.go:114 | storage/ops P1/P9 | 文件写/轮转/flush顺序待确认 |
| sing-box拨号协程 | egress/dial_singbox.go:82 | integrations.egress P5/P7 | 网络桥接与退出，不是持久化任务 |
| Fiber stream协程 | transport/fiberadapter/stream.go:169,296 | transport P5/P6 | 连接关闭/取消传播，不是定时job |
| realtime双向协程 | relay/channel/openai/relay_realtime.go:37,97 | relay P6 | 两方向关闭、计费结算 |
| 供应商流式协程 | relay/channel/baidu/relay-baidu.go:194；cohere/relay-cohere.go:102；palm/relay-palm.go:58；xunfei/relay-xunfei.go:221；zhipu/relay-zhipu.go:164 | relay P6 | 每供应商独立登记取消与资源释放 |

【待验证】上述为internal下静态增量，不覆盖modules/relaykit及全仓库包init/time.Sleep/定时器封装。下一轮逐调用记录函数名、上游触发路由或初始化点、门控、周期、读写表、外部副作用、幂等/租约/退出，并与启动任务去重。只有源码命中不得标记该任务已验收。

【事实纠正】settings/settings.go:181–182,228–232存在TelegramOAuthEnabled、TelegramBotToken/Name及WeChatAuthEnabled、WeChatServerAddress/Token/QRCodeImageURL。原§5“尚未证明提供商”仍是实现全集待核验，而不代表配置入口不存在。

## 10. 非启动入口续核：账务与缓存（覆盖§7同名候选）

以下是固定代码入口，不按userId、红包、请求或goroutine实例数量增加分母。副作用重试/崩溃运行验证归P4/P7，不前置要求P0通过；本节不宣称运行成功。

| 入口及逐调用证据（internal下） | 已读闭包的准确副作用 | 目标所有权/阶段 |
|---|---|---|
| billing/qq_checkin.go:124,157 | 两数据库路径均IncrUser(userId,quotaAwarded)，错误忽略；不是通知/日志任务 | billing编排、identity额度缓存端口，P4/P7 |
| billing/store_checkin.go:208,242 | 网页签到两路径均IncrUser(userId,quotaAwarded)，错误忽略 | 同上P4 |
| billing/qq_drop.go:183 | IncrUser(userId,drop.QuotaAwarded)，错误忽略 | 同上P4/P7 |
| billing/qq_redpacket.go:221,342 | 创建后DecrUser(sender,total)，领取后IncrUser(user,grab.Amount)；不是过期维护循环 | 同上P4/P7 |
| billing/qq_steal.go:204 | 闭包先DecrUser(victim,amount)，再IncrUser(thief,amount)，两错误忽略 | 同上P4/P7，守恒验收仍需事务/缓存故障fixture |
| billing/qq_transfer.go:190,253 | 两路径先IncrUser(from,-amount)，再IncrUser(to,Received)，不是转账主事务在go内执行 | 同上P4/P7 |
| billing/consume_text_quota.go:649；consume_quota_realtime.go:404 | RecordRelaySample(relayInfo,true,completionTokens) | usage采样/统计，P4/P7；非第二次扣费 |
| billing/open_billing_session.go:84–125 BillingSession.Refund | 锁下排除settled/refunded/无需退款，先置refunded；复制token/funding等到闭包；funding.Refund→订阅extraReserved负delta→非playground且tokenConsumed>0时IncreaseTokenQuota，失败各自记日志 | billing资金编排→identity令牌端口，P4；内存幂等标志不证明崩溃持久化幂等，未见闭包自动重试 |
| identity/store_users.go:1065,1094,1267 | 分别RefreshUserGroupCache、updateUserSettingCache、updateUserNameCache；不能统一称“写用户后任务”，有读取回填用途 | identity DB读→缓存，P2/P3 |
| identity/store_users.go:1130,1155 | 分别IncrUser/DecrUser；异步在后续BatchUpdate/DB分支之前派发，不应声称DB提交后才更新缓存 | identity缓存，billing编排额度，P4 |
| identity/token_store.go:336,378 | ApplyTokenDelta正/负额度，缺hash跳过由下次DB读取水合，不创建残缺hash；后续另有BatchUpdate/DB分支 | identity令牌缓存，billing编排，P4 |

以上消除QQ签到/掉落/红包/偷取/转账、普通签到、文本采样、退款session、用户/token闭包的副作用不明；实时计费另外两入口亦已续读：consume_quota_realtime.go:449–495 checkAndSendQuotaNotify，UserQuota-(quota+preConsumedQuota)<threshold才notifyUser；threshold优先用户非零QuotaWarningThreshold，否则全局；调用点443要求sendEmail且本次总额度非零。497–543 checkAndSendSubscriptionQuotaNotify先排除nil、无订阅/总额度<=0，remaining=total-(usedAfterPreConsume+postDelta)，小于threshold才通知。空NotifyType默认Email，Bark/Gotify用短文本，其他采用含wallet链接HTML；失败只记日志。归billing决定通知语义→integrations发送，P4/P7，不是新的持久化账务任务，通知限流另见ops/limit_notify.go。

## 8. 未完成项与远程验收设计

1. **已有Go基线证据**：ci-baseline.md首轮记录run 41425478831 attempt 1/2，SHA 6e599ec59837d645b4740ebe363790beda6b40f1均success；attempt 1 public-config 19/0、focused 295/2、full-api 2745/7、relaykit 280/0（pass/skip），四组退出码0。独立验证对CI基础交付PASS，不等于P0整体通过。以下2–6项为分阶段验证方案：P0只验集合、字段、归属与方案；P1验SQLxSQLite/PostgreSQL两目标库；P4验账务；P7验任务恢复；P8验完整升级。不得要求后阶段运行通过才验收P0清单。
2. 列/索引/约束/JSON/密文/软删除尚未逐表展开。远程固定基线分别创建空库，导出SQLite/PostgreSQL两目标库 schema（含主/独立日志库），与GORM字段标签对账；另外从脱敏历史schema升级并重复运行迁移。输出DDL、版本、fixture校验和，不含秘密。
3. SQLx目标验收仅SQLite与PostgreSQL；PostgreSQL 14（当前最低）与现代部署版本17都需真实连接/CRUD/事务证据，SQLite记录实际引擎版本。MySQL5.7.8仅历史事实，不迁移、不安排CI。ClickHouse24.8与Timescale样例另矩阵，不因两目标主库通过就认定扩展通过。
4. 注册模型集合之外，须静态扫描所有原生CREATE/ALTER/Table/AutoMigrate、init及goroutine/time.Sleep，建立未归属条目清零证据；全适配器/所有options/env/通知渠道交叉对账尚未完成。
5. 账务事务、锁顺序、缓存key和TTL、outbox交付、支付幂等、任务租约尚未逐调用冻结；Actions模拟双实例、崩溃接管、重复webhook、订阅跨日/周/月/时区、退款守恒、断连结算；禁止真实支付/邮件/付费上游。
6. 文件存储、安全日志、GeoIP下载和可能对象存储尚未证明全集；需要路径/权限/清理/保留期台账，影子实例所有副作用默认禁用。
7. CI仅由集成者在新仓库经授权触发；本代理仅提出验证方案。每次结果绑定目标SHA、上游SHA、workflow run ID、镜像版本/摘要、退出码、测试/跳过数量，独立verification审阅后才可改为已验收。任何范围豁免须用户确认。
