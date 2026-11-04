# Rust + Axum 模块化单体架构与所有权（P0 设计基线）

## 1. 状态与边界

- 对应主计划 `/root/newapi-rs-p0-contracts/docs/rust-backend-migration-plan.md`，源码基线 `17970da4571e81308f176a0e61a38276e5771606`。接口清单见同目录 `contracts-inventory.md`。
- 本文为待独立复核的设计，状态 **进行中**；不是 Rust 实现或 P0 验收证据。仅写本文和 contracts 台账；未修改主计划、未创建 Rust 代码，未构建、测试、启动服务、执行容器或脚本，未提交/推送。
- 目标是一个 Cargo workspace、一个部署服务进程、域内模块化的单体；不拆微服务、不以 Go 反向代理充当 Rust 实现。目录在对应阶段有真实垂直切片时才创建，不预建空 crate。
- Go 基线已有远程证据：run 41425478831 attempts 1、2 成功，精确 SHA 和覆盖范围见 ci-baseline.md。P0 尚需清单闭环、唯一数据归属、依赖方案和来源处理边界；SQLite/PostgreSQL 两库实现验证、领域功能及发行审计在对应 P1–P8 阶段验收，不统当前置。下述依赖方向作为实施约束，Cargo.lock 只在远程经受控流程生成并回收。

## 2. Workspace 与 Cargo DAG

目录相对于未来新仓库 `/root/newapi-rs`，开发时映射至各自独立 worktree。箭头 `A → B` 表示 A 允许依赖 B 的公开 API，不表示运行时调用必然发生。所有业务 crate 可依赖少量 foundation 类型和 storage 连接能力；**storage 不含业务 repository、表模型或跨域 SQL**。

```text
apps/server (唯一 composition root / Axum transport / use-case orchestration)
  ├── config
  ├── foundation
  ├── storage
  ├── identity
  ├── security
  ├── catalog
  ├── billing
  ├── usage
  ├── relay
  ├── jobs
  └── integrations

config       → foundation
storage      → foundation
identity     → foundation, storage
security     → foundation
catalog      → foundation, storage
billing      → foundation, storage
usage        → foundation, storage
relay        → foundation
jobs         → foundation, storage
integrations → foundation
```

这是完整**允许的域间直接依赖集合**，没有 identity↔billing、catalog↔relay、jobs↔integrations 等循环。`server` 可依赖所有域，但其他 crate 一律不得反向依赖 server。对第三方库的依赖不在此图展开：Axum/Tower 在 server transport，Tokio 在需要异步任务的实现，Reqwest 在出站实现；Serde 用于边界 DTO，SQLx 在 storage 及拥有 repository 的域，tracing 在脱敏后的边界。不是所有域必须直接依赖每个基础库。

跨域业务通过**消费者拥有的 trait 端口**与 server 内的桥接实现协作。例如 relay 声明 `BillingPort`，server 的桥接对象调用 billing 的公开服务；relay 并不导入 billing。该结构既允许运行时调用，又避免 Cargo 循环和共享大 DTO crate。每个 trait 的输入/输出定义在消费域或由提供域公开，转换仅发生在桥接层。

不创建无边界 `common`：foundation 仅可收纳确实稳定的 RequestId、脱敏错误分类、Clock/随机数抽象、取消与观测基本约定。用户、渠道、金额、价格、协议请求、权限枚举不放在 foundation。跨域 ID 的必要转换必须类型化，不公开数据库 row。

### 2.1 目录内部约束

- 每个持久化业务域：`domain/`（不含 SQL/Axum）、`application/`（use case、消费者端口）、`persistence/`（该域自己的 SQLx repositories/方言）、`public/` 或显式 `pub use`（稳定接口）、`tests/`。
- server：`transport/http/`（按域分 router/DTO/错误映射）、`transport/middleware/`、`composition/`（依赖注入）、`workflows/`（确有跨域顺序的应用编排）、启动/关闭。handler 仅解析、调用、转换，禁止写 SQL 或计算账务。
- relay：`protocol/`（OpenAI/Claude/Gemini/SSE/WS 编码）、`adapters/`（每个供应商独立模块）、`application/`（请求生命周期与消费者端口）。P5/P6 可先作为一个 crate 内模块，不为每供应商拆空 crate。
- integrations：`oauth/`、`payments/`、`mail/`、`bots/`、`egress/` 等内部模块；无所有权的数据必须经端口交还拥有域，外部 SDK 不泄漏至业务域。
- 各域测试能用 fake Clock/HTTP/端口，但测试不得把成功空对象当作待实现业务。编排集成测试必须验证真实 repository/事务，不仅 mock。

## 3. 模块所有权与阶段

下表是逻辑所有权，不宣称已完成实际表名核对。实际表/列读写归属由并行 data/ops P0 台账补全后冻结；未核清前不得创建替代 schema。

| 所有权角色 | crate/目录 | 独占职责与数据 | 公开接口方向 | 阶段 |
|---|---|---|---|---|
| 集成负责人 | apps/server、根 Cargo.toml/Cargo.lock、CI | 装配、HTTP DTO/路由、中间件顺序、进程生命周期、跨域桥接；不拥有业务表 | 调用各域公开服务，注入端口 | P1起 |
| 配置负责人 | crates/config | 环境与启动参数解析/校验、不可变启动配置；不直接写业务options | 给 composition 配置快照 | P1 |
| 基础设施负责人 | crates/foundation | 请求ID、时钟/随机、基础错误/观测约定 | 只向上提供稳定基础类型 | P1 |
| 存储负责人 | crates/storage | SQLxSQLite/PostgreSQL 两库连接池、连接生命周期、方言能力、事务基础能力；不成为统一DAO | 域内repository使用pool/连接，禁止全局可变DB | P1 |
| 身份负责人 | crates/identity | 用户、会话、PAT/API key、密码/2FA/Passkey凭证、绑定记录、角色/权限持久化；字段映射待数据台账冻结 | authenticate、principal查询、凭证撤销、用户/策略管理 | P2/P3/P7 |
| 安全负责人 | crates/security | 纯授权决策、Token/用户认证流程协调、Origin/CSRF、配额外的速率限制、可信代理/地理策略所需决策；无用户表副本 | 决策与身份/限流消费者端口；HTTP适配在server | P2/P5 |
| 目录负责人 | crates/catalog | 渠道/凭证、模型/供应商、组/预填组、路由单元、能力/健康/亲和缓存、配置版本与outbox；系统options的非账务存储和读取 | catalog snapshot、select/report health、管理服务、配置视图 | P1读配置/P3/P5/P7 |
| 账务负责人 | crates/billing | 钱包/额度、价格/倍率规则、订阅、兑换、充值订单、预扣/结算/退款、资金相关签到/推广转移/红包；兼容旧schema | quote/reserve/settle/refund、record verified payment、余额/订阅查询 | P4/P7 |
| 用量负责人 | crates/usage | 消费日志、统计聚合、画像/样本、排行/性能、审计查询及保留策略；不自行扣款 | record usage/audit、query stats、insight ban view | P4日志/P7全面 |
| 网关负责人 | crates/relay | 协议、所有上游适配器、流生命周期/重试/取消、异步提交/查询语义；不直接访问identity/catalog/billing表 | relay execute、TaskAdapter、业务消费者端口 | P5/P6 |
| 作业负责人 | crates/jobs | 任务/租约/执行历史、持久化异步任务状态、重试调度、多实例单一执行、实例心跳与清理；不得拥有账务结算规则 | enqueue/load/claim/complete、调用JobHandler/TaskDriver端口 | P6持久化/P7调度 |
| 集成负责人（域） | crates/integrations | OAuth/OIDC/第三方登录、支付签名/外部订单协议、邮件/机器人、代理/GeoIP下载等外部IO；不直接写用户/钱包 | 返回验证后的外部事实；发送器/egress/provider端口 | P2邮件最小依赖/P7全面 |

注意：将旧 Go 包名视作职责线索，不照搬其互相 import。例如 `identity.TopUp` 必须由 billing 业务服务执行，HTTP路径保持不变；`billing.QQBotWebhook` 的协议签名属于 integrations，但红包资金仍归 billing。

系统 options 存储归 catalog 的配置 repository，不允许任意域通过字符串直接修改所有 key。billing 持有计费配置语义与版本；catalog 只通过显式提交接口持久化已经验证的配置快照。GeoIP/代理节点等运维记录可归 catalog 内受限配置子模块，jobs 管运行历史，integrations 管实际 IO，表级归属仍待 data/ops 台账确认。

## 4. 跨域接口契约（设计，不是已编译 Rust 签名）

端口由消费者定义，server 桥接调用提供者公开 API。此处给出信息边界和失败约定，不预先锁死未经 fixture 确认的 JSON DTO。

| 消费者端口 | 提供者/桥接 | 输入 → 输出与不变量 |
|---|---|---|
| security.IdentityPort | identity | 原始凭证（受保护容器）/请求上下文 → Principal（user/token/session ID、角色、状态、策略版本）；匿名/无效/过期/禁用必须区分；撤销后不得复用陈旧缓存 |
| security.PolicyPort | identity + catalog配置视图 | principal、动作、资源 → Allow/Deny及原因；保留Admin、Root、细粒度permission叠加，不把admin自动当root |
| security.RateLimitStore | server注入Redis/内存实现 | 作用域、主体、窗口 → 允许/重试时间；分布式原子性和禁用Redis退化行为须与Go一致 |
| relay.AuthorizationPort | security桥接 | 已认证principal、模型/组/来源IP → 授权上下文；token只读与relay token不能混淆 |
| relay.CatalogPort | catalog | 模型/组/协议、请求特征、候选排除集 → 不可变RouteLease（渠道/路由单元/配置版本、受保护凭证引用）；健康反馈明确路由单元，不跨域改表 |
| relay.PricePort | billing | 授权主体、模型、计费维度、pricing版本 → PriceQuote；冻结单位/舍入/表达式版本，不使用随时间变化的报价进行同请求结算 |
| relay.BillingPort | billing | RequestId/幂等键、quote、预算 → Reservation；Reservation+实际usage/失败原因 → Settlement/Refund。重试共享请求账务身份，不能每次尝试重新扣用户 |
| relay.UsagePort | usage | 经过脱敏的usage事实、reservation/settlement ID、时间/渠道版本 → 持久化结果；写日志失败不能伪装结算成功或重新扣费 |
| relay.InsightPort | usage | 客户端特征/有限请求摘要 → ban decision、记录受控样本；不把原始prompt放进通用日志 |
| relay.OutboundPort | integrations egress或server Reqwest桥接 | 安全校验后的目标、代理策略、受保护headers、可取消body → 状态/headers/流；密钥不出现在Debug/trace，禁止无限重定向和任意内网访问 |
| relay.TaskStorePort | jobs | owner、platform、remote taskID、billing reservation、请求版本 → 持久任务句柄；读取强制owner授权，禁止枚举他人任务 |
| jobs.TaskDriverPort | relay | 已租约领取的任务 → 提交/轮询结果；终态事实交由billing完成幂等结算，不能由轮询器直接改quota |
| jobs.JobHandler | server提供域桥接 | 带lease/运行ID/截止时间的命令 → 运行结果和重试分类；支持取消、主节点与enabled开关、多实例去重 |
| identity.ExternalIdentityPort | integrations | 已绑定state/nonce/PKCE的OAuth或Passkey证据 → VerifiedIdentity；外部身份仅是事实，用户绑定/创建/禁用决策仍由identity控制 |
| identity.NotificationPort | integrations | 明确接收方、模板、用途、过期策略 → 发送/重试状态；测试/影子模式不发送真实邮件 |
| integrations.PaymentApplicationPort | billing桥接 | 经签名、环境、金额/币种核验的ProviderEvent → 一次性入账结果；幂等键含provider/env/event，不仅使用body hash |
| integrations.BotApplicationPort | identity/billing桥接 | 验证签名/路径token后的事件 → 绑定/余额/红包命令；同一事件重放不重复派发资金 |
| billing.IdentityAccountPort | identity桥接 | user/token ID → 计费所需状态与账户上下文；不复制密码/会话资料 |
| billing.QuotaMutationPort | identity桥接（必要时） | 有事务约束的token额度变更 → 结果；仅用于旧schema将token quota放identity表的情况，不能独立提交造成部分扣款 |
| usage.AuditSink（公开提供接口） | security/server调用 | actor、动作、资源、结果、请求ID → 追加记录；禁止记录明文token/channel key/支付签名原文 |
| catalog.ConfigChangePort / jobs消费 | catalog outbox + jobs | 配置版本事件 → 刷新/应用ack；不能先广播后事务回滚，也不能跨实例无限陈旧 |

### 4.1 事务边界不是“调用两个端口就算原子”

1. 账务 reserve/settle/refund 必须由 billing 的单一幂等状态机支配。旧schema如果要求同时更新 user/token quota，先由 data P0 明确写入归属与锁序；通过拥有者的受限事务端口在**同一SQLx连接/事务**执行，不能把pool交给relay任意写表。
2. server 的跨域 UnitOfWork 桥接可以借用同一事务，并向域提供受限repository操作，不能公开SQL/表名作为接口。不同数据库/独立日志库不能靠一个本地事务假装原子；采用可恢复outbox/补偿且须兼容旧schema，新增表/幂等字段必须先确认方案。
3. usage写入与余额扣减之间的失败窗口、批量更新旧语义、订阅重置、签到/红包原子性均需Go金标准。尚未证明可原子复现时标受阻，不将资金写入开放。
4. 消费日志不反向驱动再次结算；异步任务终态用持久化幂等键回交billing。客户端断连、上游已计费但usage缺失、提交成功但taskID落库失败，都要有明确恢复策略与fixture，不“出错就全退”。

## 5. HTTP 装配与兼容性策略

- 原服务不是 Gin 主入口：`/root/newapi/apps/api/main.go:211` 使用 Fiber adapter。以 compose、adapter 和实际fixture为准，不以旧README或Axum默认行为为准。
- 精确 middleware 链、路径、handler、前端调用及迁移阶段见 contracts 台账。普通管理 API、旧版dashboard、模型查询、relay、MJ图片、视频内容、Web使用不同链；禁止一个全局鉴权层替代。
- Axum 路径参数语法由 adapter/装配转换，但外部路径不变；字面量优先级、尾斜线、wildcard、隐式 HEAD/OPTIONS、方法错误需逐项快照。未实现的 API 显式失败，不落入SPA 200；与Go现有fallback的差异提交审批。
- Cookie/session/PAT/API key/`x-api-key`/`x-goog-api-key`/query key 的优先级、Origin校验和错误结构需fixture冻结；不自行要求所有前端换Authorization header。
- Tower layer层序必须通过请求前/响应后的事件测试，而不是凭代码书写顺序推断。完整请求body缓存、解压上限、匿名请求上限、清理时机需独立测试。
- SSE 使用可取消、带背压的流，不全量buffer后返回；响应开始后禁盲目重试。WebSocket双向关闭、音频/图像multipart、视频Range、Ollama管理流分别验收。
- 错误分层：内部域错误不含框架状态码；transport按现有管理API/relay/第三方回调契约映射。不能统一把业务失败变成500，也不能统一HTTP200。
- 静态产物与运行时二进制的归档在P9完善，P1需明确未实现API/fallback边界；不把前端大规模改写作为兼容性捷径。

## 6. 阶段与并行开发约束

| 阶段 | 允许推进的实际切片 | 必须等待的前置条件 |
|---|---|---|
| P0 | 完整台账/所有权/端口草案/远程Go基线 | 任一表/路由/任务缺口及远程证据未补齐，不能标验收 |
| P1 | config/storage/catalog配置读取/server基础传输 | 不提前创建全套空crate；notice/about/home/legal有真实options读取 |
| P2 | identity/security、初始化、会话、令牌、最小验证码发送端口 | P1已验收；邮件模拟只能验流程，真实集成未验收不得误报 |
| P3 | 非资金管理、目录/权限、前端CRUD | P2已验收；资金字段/动作留待P4，显式失败 |
| P4 | billing/必要usage、完整一致性与计费golden | P3已验收；通过后才允许P5承载计费链 |
| P5 | relay核心、catalog选择、安全与账务连接 | P4通过；insight禁用策略不能等P7才补安全放行 |
| P6 | 每个现有适配器/协议、task持久化最小切片 | P5通过；平台别名各有fixture |
| P7 | integrations/jobs/usage全量与运维管理 | P6通过；生产副作用默认关闭 |
| P8/P9/P10 | 全面差分、安全性能、构建部署切流、退役 | 分阶段独立验收；生产切流/退役另行授权 |

- 最多三个开发Agent同时进行、每人独立worktree和分支；同一文件不并写。共享 Cargo manifests/lock、public接口、HTTP DTO、CI 只由集成负责人合并。
- 分配例：阶段内A做领域与repository，B做transport/前端契约fixtures，C做模拟上游或集成测试；verification独立审查，不由实现者自签PASS。
- 若端口变更涉及资金单位、schema、阶段范围或兼容性，先记录决策/影响并请求确认，不能直接改主计划。
- 本次所有写入仅 `/root/newapi-rs-p0-contracts/docs/contracts-inventory.md` 与 `/root/newapi-rs-p0-contracts/docs/architecture.md`，参考仓库保持只读。

## 7. 远程验证与验收门槛

所有命令**仅允许 GitHub-hosted Actions runner**。本次没有执行或验证下面的命令，不提供虚构PASS。

1. P0：只读checkout固定上游SHA，运行compose路由快照/遮蔽/退役路径、middleware、Fiber契约与Go金标准；确认嵌入frontend/Go module前置条件。将结果回填contracts台账。
2. Rust存在后，远程运行 `cargo fmt --check`、`cargo check --locked --workspace`、`cargo clippy --locked --workspace --all-targets -- -D warnings`、`cargo test --locked --workspace`。通过远程 `cargo metadata --locked --format-version 1` 的workspace依赖图验证第2节白名单；禁止依靠构建成功就推断领域依赖合规。
3. SQLite/PostgreSQL 两数据库分别实连并导入脱敏旧schema；SQLx不假定跨库SQL相同，不无声提高数据库最低版本；连接失败/测试跳过均不能记通过。使用独立日志库时要测试其单独故障。
4. 领域端口测试至少覆盖撤销/禁用用户、鉴权越权、跨用户task、并发扣款、重放、outbox回滚、缓存失效、任务租约与进程崩溃恢复；协议差分包含背压、断连、取消和半途错误。
5. 对 public/trait边界进行静态审核：域不导入server/Axum、不跨域直接SQL、不把Secrets派生Debug/Serialize、不持有可任意写全库的全局对象。模型/价格版本与幂等策略必须可观察但不泄漏敏感内容。
6. 证据绑定上游SHA、新仓库精确commit、workflow run ID/URL、环境、命令、退出码、测试和跳过数。集成者用gh读取日志抽查2–3条命令，独立verification判定PASS/FAIL/PARTIAL。已有 Go 基线证据见 ci-baseline.md；尚无 Rust 实现及本节后续阶段专项证据，不能将 Go 基线成功等同架构实现通过。

## 8. 补充探索形成的不可省略兼容边界

以下证据由用户补充探索提供，作为待独立复核的设计约束，不冒充本任务已完成全部实现分析；它们不改变第2节消费者端口DAG。

|补充能力|参考源码|本架构所有者/边界|远程验收及当前状态|
|---|---|---|---|
|独立 LOG_SQL_DSN 与 ClickHouse 日志库|`/root/newapi/apps/api/internal/dbinfra/open_db.go:63–103,148–161`|storage提供独立连接能力，usage拥有日志repository；日志不与业务库假设同事务|SQLite/PostgreSQL 两主库矩阵不能代替ClickHouse；驱动/协议选择与最低版本待确认，受阻|
|修复、AutoMigrate、回填型升级|同文件:195–239|storage只负责执行机制，各领域拥有本域升级规则；data负责人逐项冻结|不只移植SQL文件；重复执行、失败中断、备份恢复、共存schema测试；未开始|
|JWT用途隔离、refresh轮换/撤销|authtoken与identity session；具体函数行号待补|identity拥有凭证生命周期，security验证用途与策略，server适配cookie/headers|access/session/refresh/proof不能仅凭同一签名验证器混用；重放/撤销/2FA轮换fixture；未开始|
|sing-box/uTLS/WireGuard|internal/egress；具体函数行号待补|integrations/egress经relay.OutboundPort提供能力，不改变域依赖|普通Reqwest proxy不等于完整替代；Rust替代能力未证明，受阻；不得静默保留Go sidecar冒充完整重写|
|后台任务、master租约、失锁取消|main.go:116–185；internal/ops/schedule_tasks.go|jobs拥有租约与状态机，域JobHandler执行；billing保持资金终态幂等|多实例竞争、续期失败/失锁立即取消、重启恢复、影子无副作用；未开始|
|internal共24模块及modules/relaykit|完整目录映射由P0各所有者合并|不强求一包一crate，但每项能力必须有owner；relaykit归relay协议转换边界|当前本文不是24模块全量映射表；各模块/表/任务缺口未补齐前P0受阻|

ClickHouse适配可能需要SQLx以外客户端；这里只标记待选型，不声称SQLite/PostgreSQL 两库SQLx方案已经覆盖。涉及新增依赖、最低版本或支持范围变化，须按主计划记录影响并确认。现有特殊网络能力也不得以“标准HTTP可用”视为验收。

进程退出必须编排停止接收请求/领取任务、限时drain在途流、持久化待恢复账务状态、取消或释放租约、关闭日志/数据库；不能只依赖Drop进行异步退款。进入切流前冻结Go/Rust会话、缓存、在途结算与任务单执行权；应用回滚与数据库恢复不得混为恢复旧备份。

## 9. 明确不实现范围

以下能力经用户确认不属于 Rust 重写范围，不建立对应端口、配置项或路由：

- **Worker 代理**（Go `internal/egress`）：`WorkerUrl`、`WorkerValidKey`、`WorkerAllowHttpImageRequestEnabled` 三项 options，以及 `fetch_url.go`、`fetch_file.go`、`ops/dispatch_webhook.go`、`ops/notify_user.go` 中经 Worker 转发的分支。前端 `system-settings/integrations/worker-settings-section.tsx` 对应设置页不迁移。无 Worker 时的直连出站 HTTP 仍需保留，并由 integrations/egress 以直连实现。
- Rust 不提供 Worker 配置的热加载、密钥保存或 HTTP 图片放行开关；遇到旧库中残留的这些 options 行只按普通未知配置忽略，不据此改变出站行为。

### 9.1 延后实现（不取消）

- **sing-box 出站代理**：Go `internal/egress` 的代理能力需要重新实现，归属 `integrations/egress`，通过 `relay.OutboundPort` 提供，不保留 Go sidecar。排期放在最后阶段（P7 末端），在 Relay 协议、计费、catalog、usage 等主链之后实施；在此之前出站默认直连，并显式标记代理能力未启用，不伪装已支持。

## 10. 尚待决策/阻塞

- 表级归属与跨域同事务端口需要data/ops负责人补全，特别是user/token额度、订阅、usage独立库、任务与outbox。
- 本文提出catalog承接非账务options、jobs承接异步task持久化；需主集成者与数据台账核对后冻结，不是对旧schema重构的授权。
- Axum/Tower/SQLx版本及最低数据库兼容性未锁定；不得在本地运行Cargo来补证据。
- Go路由源码已展开，但请求/响应字段和全部适配器行为尚未冻结；contracts清单不能替代差分fixture。
- Go/Rust共存的session/cache共享或重新登录策略、任务单一执行权、在途账务drain必须在切流前明确；未经确认不共享生产数据库。
