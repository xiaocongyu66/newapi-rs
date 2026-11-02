# P0 数据覆盖与逐项验收

2026-11-02；状态：进行中，未验收。只读源码 `/root/newapi`，基线 `17970da4571e81308f176a0e61a38276e5771606`。本轮只阅读/编辑文档，没有构建、测试、执行脚本、启动服务/容器、提交或推送。P0未通过，P1不得开始。

勾选仅表示**静态登记交付已具备**，不是运行或独立验收PASS。字段出处见schema-inventory.md §2/§6，逐模型W/R与阶段见data-jobs-inventory.md §2。本文件补充该文件尚未合入的注册分母、分支与非启动入口核查，不覆盖已有交付。

## 0. 最新批准数据库范围

Rust目标仅SQLite+PostgreSQL；MySQL历史源码事实保留但不迁移、不支持，不要求MySQL CI/最低版本验证。尽量兼容原表/字段/ID/额度/时间/软删除；差异必须显式记录，禁止未经批准有损转换。ClickHouse独立日志及Timescale扩展不自动移除，仍独立列账。

## 1. 分母及范围

- [x] 主库生产注册51条/51模型：dbinfra 1 + identity含policy 15 + catalog 9 + billing 12 + ops 4 + task 2 + usage基本5 + PerfMetric 1 + egress 1 + mailer 1。
- [x] 后置SubscriptionPlan单独计1，业务模型并集52；日志库注册1条Log与主库重叠，不计第53模型。
- [x] 注册来源：各域register_migrations.go、identity/migrate_identity.go、dbinfra/run_migrations.go、egress/store_proxy_node.go、mailer/quota_usage.go、usage/record_perf.go；逐项文件/行号见schema §3。
- [x] common/dbx/migrate.go:27–52是append无去重；dbinfra/run_migrations.go:19–35原样展开，不能假设按Name去重或按文档排序执行。
- [ ] main导入链最终运行注册顺序、构建条件与主/日志实际表集合的远程导出。
- [x] schema_migrations原生账本不属于52模型；Timescale chunks是扩展内部对象，临时重建表不是额外业务模型。
- [ ] 全仓库Raw/Exec/Migrator/Table实参封闭、历史db/archive路径、JSON嵌套结构/Scan/Value及密文算法fixture。

### 逐模型静态登记与运行验收

S=源码字段/标签登记；O=已有读写归属及阶段；V=真实schema、约束、序列化、升级/重入综合验证。V全部未完成，不以勾S/O替代V。

| 模型 | S | O | V |
|---|---|---|---|
| Option | [x] | [x] | [ ] |
| User | [x] | [x] | [ ] |
| Token | [x] | [x] | [ ] |
| UserSession | [x] | [x] | [ ] |
| AuthFlow | [x] | [x] | [ ] |
| ExternalIdentityClaim | [x] | [x] | [ ] |
| PasskeyCredential | [x] | [x] | [ ] |
| TwoFA | [x] | [x] | [ ] |
| TwoFABackupCode | [x] | [x] | [ ] |
| CustomOAuthProvider | [x] | [x] | [ ] |
| UserOAuthBinding | [x] | [x] | [ ] |
| CasbinRule | [x] | [x] | [ ] |
| AuthzRole | [x] | [x] | [ ] |
| QQBinding | [x] | [x] | [ ] |
| QQBindCode | [x] | [x] | [ ] |
| QQUnbindRecord | [x] | [x] | [ ] |
| Channel | [x] | [x] | [ ] |
| Ability | [x] | [x] | [ ] |
| ChannelModelHealth | [x] | [x] | [ ] |
| ChannelModelRoute | [x] | [x] | [ ] |
| GatewayConfigRevision | [x] | [x] | [ ] |
| GatewayConfigOutbox | [x] | [x] | [ ] |
| Model | [x] | [x] | [ ] |
| PrefillGroup | [x] | [x] | [ ] |
| Vendor | [x] | [x] | [ ] |
| Redemption | [x] | [x] | [ ] |
| TopUp | [x] | [x] | [ ] |
| Checkin | [x] | [x] | [ ] |
| SubscriptionPlan | [x] | [x] | [ ] |
| SubscriptionOrder | [x] | [x] | [ ] |
| UserSubscription | [x] | [x] | [ ] |
| SubscriptionPreConsumeRecord | [x] | [x] | [ ] |
| QQCheckin | [x] | [x] | [ ] |
| QQDrop | [x] | [x] | [ ] |
| QQTransfer | [x] | [x] | [ ] |
| QQRedPacket | [x] | [x] | [ ] |
| QQRedPacketGrab | [x] | [x] | [ ] |
| QQSteal | [x] | [x] | [ ] |
| Setup（dbinfra，不是ops DTO） | [x] | [x] | [ ] |
| SystemInstance | [x] | [x] | [ ] |
| SystemTask | [x] | [x] | [ ] |
| SystemTaskLock | [x] | [x] | [ ] |
| Midjourney | [x] | [x] | [ ] |
| Task | [x] | [x] | [ ] |
| Log（主/日志分别验） | [x] | [x] | [ ] |
| QuotaData | [x] | [x] | [ ] |
| UserInsightProfile | [x] | [x] | [ ] |
| UserInsightSample | [x] | [x] | [ ] |
| UserInsightClientBan | [x] | [x] | [ ] |
| PerfMetric | [x] | [x] | [ ] |
| ProxyNode | [x] | [x] | [ ] |
| SMTPQuotaUsage | [x] | [x] | [ ] |

计数校对：1+15+9+12+4+2+5+1+1+1=51个主注册，另加SubscriptionPlan为52；原10个已展开模型之外，本轮新增42个字段登记。日志重复注册不重复计模型。

## 2. 条件迁移与动态表增量

- [x] `billing/bootstrap_subscription_plan.go:15–22`后置先转换price_amount、清理pay_mode，SQLite走原生ensureSubscriptionPlanTableSQLite，其余库才AutoMigrate。
- [x] 同29–101：tableName固定subscription_plans，补列来自required静态白名单；SQLite新表price_amount无default:0，两个allow_*列numeric DEFAULT 1，与结构标签不同。已有表只补缺列，不归一化所有类型。
- [x] `catalog/bootstrap_migrations.go:46–78`SQLite使用channel_model_health_new重建再改名；MySQL/PG改同一健康表主键。临时对象W=storage迁移经catalog契约、R=迁移、阶段P8。
- [x] `catalog/store_channel.go:1153`Table("(?) as sub", subQuery)是派生查询，不是创建动态业务表。
- [x] `usage/record_perf.go:195–196`明确PerfMetric override perf_metrics，不按模型/桶动态建表。
- [x] `usage/store_log.go:590,948`主库读channels名称，统计/清理走LogDB；`store_usedata.go:116–126`主库写quota_data。Rust须经catalog公开查询端口替代跨域直接读表。
- [ ] master/slave、主日志共库/分库、ClickHouse、Timescale启停各分支实际DDL。Log.ChannelName的gorm:"->"是只读非忽略迁移，ClickHouse原生DDL无该列，必须分别验证。
- [ ] TwoFA默认表名、NULL唯一性、软删除复合唯一、PrefillGroup部分索引跨库差异、价格decimal与Go float64舍入、seconds/ms边界。

## 3. 任务分母与非启动入口

注册SystemTaskHandler分母**6种**：handler/handle_system_task_runners.go:23–27注册5种，ops/schedule_tasks.go:85–87包init注册log_cleanup。map按Type覆盖，runner每轮snapshot；6/6已有阶段不等于全后台任务覆盖。

| 类型 | 入口/条件 | 读写与阶段 | 登记 | 运行验收 |
|---|---|---|---|---|
| channel_test | monitor门控；handle_channel_probe.go:1069手动Enqueue | 上游探测→catalog健康，P5/P7 | [x] | [ ] |
| model_update | env门控；handle_upstream_update.go:1082 Manual:true手动Enqueue | 上游→catalog模型，P3/P7 | [x] | [ ] |
| midjourney_poll | UPDATE_TASK且有未完成任务；提交生成midjourneys | jobs持久化任务状态，经billing结算，P6/P7 | [x] | [ ] |
| async_task_poll | UPDATE_TASK且有未完成任务；提交生成tasks | jobs持久化任务状态，经billing退款，P6/P7 | [x] | [ ] |
| home_stats | HOME_STATS_TASK_ENABLED；无额外Enqueue命中，不排除其他创建路径 | usage统计→缓存，P7 | [x] | [ ] |
| log_cleanup | 非Scheduled接口；handle_system_task.go:22→StartLogCleanupTask | usage删除LogDB日志，P7 | [x] | [ ] |

`ops/schedule_tasks.go:119–159` master+sync.Once，idle/schedule 15秒、过期锁清理30秒；租约60秒（20–26）。手动入队先查active，Create冲突后再查active，成功唤醒runner（163–212）。未证明跨实例互斥与续租通过。

- [x] data-jobs §4已有30行启动/关停/handler观测项，包含上述6种handler、pprof/Pyroscope与停机flush，不能称30个独立定时任务。
- [x] data-jobs §7已有30组非启动候选，多个调用点分别保留；组数不等于协程数。
- [ ] 全量异步任务分母仍开放，尚不能给全仓库已验收百分比。

本轮逐体确认4组，替代旧候选的不确定描述：

| 入口 | 实际触发与副作用 | R/W与阶段 | 登记/行为 |
|---|---|---|---|
| catalog/fallback_health.go:161–193 | escalateModelLocked达到正数CooldownDisableStreak后go禁用模型，失败恢复计数至少reached | 内存冷却→catalog渠道模型，P5/P7；不是懒清理循环 | [x] / [ ] |
| catalog/health_unit_store.go:413–427 | disable streak首次跨cap且hook非nil，gopool调用UnitDisabledHook | catalog健康→key probe，P5/P7；不是通用flush | [x] / [ ] |
| catalog/store_key_probe.go:45–75 | init只安装hook，触发后再次gopool执行verifyKeyAndCascade；失败级联DisableUnit和UpdateChannelStatus | catalog读渠道/路由→health/多key状态与外部探测，P5/P7；两层异步同一链 | [x] / [ ] |
| billing/qqbot_service.go:414–430 | 发消息成功、delaySeconds>0且msgID非空，AfterFunc延迟秒数后撤回，失败只记日志 | integrations外部RecallGroupMessage，P7；未见持久化timer/重启恢复 | [x] / [ ] |

- [x] 补查apps/api/modules的go/gopool/AfterFunc/NewTicker文本无生产Go异步命中；README/go.mod不是任务，不作为AST完备证明。
- [ ] data-jobs §7剩余26组的逐体触发、调用者、准确副作用、取消/重试/退出核查（内存限流已有部分函数体证据，仍需完整生命周期）。
- [ ] 全仓库time.Sleep/封装计时器、包init与其他命令入口未归属项清零。

## 4. 配置增量验收

- [x] config-inventory §6展开9组40个反射字段键，名称/类型可逐项核查；其他组未声称完成。
- [x] catalog gateway dispatch 14键、route stats 12键展开，并确认previousSeed链式保留。
- [x] monitor默认false/10/scheduled_all与env覆盖顺序（频率先、显式enabled后）已核。
- [x] Passkey默认与getter从ServerAddress派生RPID/Origins已登记，不冒充固定DB默认。
- [ ] 所有注册组的字段、默认、权限/秘密、非法/空值、热更新、动态env实参及最终seed/read/write差集。

## 5. 仍需远程证据与P0阻塞

阶段区分：P0阻塞是静态全集/归属/契约与Go基线证据未闭环；以下SQLx实现、Rust账务、任务恢复及完整升级执行分别归P1/P4/P7/P8，不要求后阶段实现测试提前通过。V空框记录未来验收债务，不单凭它认定P0不合格。当前全量异步入口与配置静态缺口仍足以阻止自行宣布P0通过。

1. 已阅读ci-baseline.md：Go Actions run 41425478831 attempt 1/2、SHA 6e599ec59837d645b4740ebe363790beda6b40f1均success；attempt 1四组pass/skip为19/0、295/2、2745/7、280/0，退出码均0，CI基础交付独立复核PASS。data-jobs导言与末节已同步，不再把无Go基线列为当前阻塞。此证据不是SQLx SQLite/PostgreSQL两目标库、Rust账务或任务恢复通过。
2. SQLite/PostgreSQL两目标主库空库、历史升级、连续两次迁移的DDL/列/NULL/default/PK/unique/index/FK/check导出；日志共库/分库、SQLite原生SubscriptionPlan、ClickHouse、Timescale单列矩阵。实际数据库最低版本/SQLx兼容未通过，扩展范围仍需确认。
3. 日志/金额/JSON/密码与密文脱敏fixture、软删除复用、同request_id重复预扣/退款、支付重放、余额守恒、任务双实例锁与重启接管、配置/outbox传播均未取得运行证据。
4. 非启动异步入口与动态SQL/配置全集尚有静态缺口，不能把模型字段登记替代P0完整清单。
5. 远程结果必须绑定集成SHA、上游SHA、run ID、数据库版本及镜像摘要、退出码、测试/跳过数；独立verification未签收前保持未验收，不进入P1。
