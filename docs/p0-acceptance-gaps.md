# P0 验收缺口与远程证据边界

日期：2026-11-02。状态：**受阻；P0未验收，P1不得开始**。本文是独立静态核查与交接，不替代verification，也不修改 `/root/newapi-rs/docs/rust-backend-migration-plan.md`。事实/推断/待验证明确区分；原有台账中历史“未运行”文字不能覆盖后续真实CI结果，但新CI成功也不能自动关闭其他缺口。

## 1. 已有远程成功，不再把“Go基线未运行”作为阻塞

**事实（本轮只读API独立确认）**：

- 仓库 `xiaocongyu66/newapi-rs`，workflow `.github/workflows/p0-baseline.yml`。
- run https://github.com/xiaocongyu66/newapi-rs/actions/runs/41425478831 ，attempt **1和2均success**；两次新仓库SHA均为 `6e599ec59837d645b4740ebe363790beda6b40f1`。
- 上游固定SHA `17970da4571e81308f176a0e61a38276e5771606`。本轮读取主工作区ci-baseline记录及工作区原始CI设计；未改动CI配置。
- attempt 2 jobs API：Rust工具存在性job `125215812511`、API `125215812714`、relaykit `125215812778`均success，工具查询/基线执行步骤均success。

**事实（已有证据记录，非本轮重新统计原始JSON）**：`/root/newapi-rs/docs/ci-baseline.md:3–12`记录attempt 1经独立verification对CI基础交付判PASS：

| 套件 | test pass | test skip | 退出码 |
|---|---:|---:|---:|
| public-config | 19 | 0 | 0 |
| focused | 295 | 2 | 0 |
| full-api | 2745 | 7 | 0 |
| relaykit | 280 | 0 | 0 |

计数包含子测试/套件重复，不得相加当独立契约数。attempt 2本轮确认任务成功，**未重新取得并逐项统计其results.json，不把attempt 1计数直接冒充attempt 2计数**。本轮尝试只读`gh run view --attempt 2 --log`抽查，尚未取得可引用的命令/计数正文；日志详细复核保持待验证。

**推断**：Go可运行基线和标准runner工具可用性已有积极证据；不应反复修改已绿CI来制造新成果。Rust任务只运行版本查询，不证明Rust workspace、依赖可构建、SQLx旧库兼容或P1实现通过。skip未因此消失；本轮也不重新自签CI基础交付PASS。

## 2. P0门槛逐项差距（依据主计划第2–4、6–7节）

| ID | 事实/当前证据 | 待验证与关闭条件 | 归属/是否阻止P0 |
|---|---|---|---|
| G01 来源与法律 | 固定上游、LICENSE/NOTICE、来源台账存在；epay许可证据不足、sing-box隔离说法不符源码 | 见license-dependency-review.md；固定素材来源/文本比对、许可处理责任与用户决策记录；不得写“已全部获许可” | 来源/维护者；P0处理路线未闭环阻塞，最终发行审计不前置到P0 |
| G02 路由/前端完整性 | contracts台账逐项注册及阶段已建立，但请求/响应/默认值等统一待核查；源码快照默认388项（API302、dashboard4、relay71、video11） | 对照精确注册快照与台账差集为零；dev、HEAD/OPTIONS、静态/fallback、pprof独立listener另列；逐项字段/中间件/前端消费者/错误/流语义冻结。快照engine中间件no-op不能证明鉴权 | contracts；阻塞 |
| G03 表与数据 | data台账已有模型/读写owner和迁移线索，非完整字段schema证明 | 全字段/索引/约束/默认值/JSON/加密/软删除、原生SQL及非模型表清单闭环；每业务表唯一写入责任、跨域事务和缓存失效边界 | data/各域；阻塞 |
| G04 后台任务/集成 | main启动及任务注册已有归属，尚未证明全部goroutine/ticker/init注册无遗漏 | 静态全集与台账差集；每项P阶段、owner、副作用、master/租约、取消/重启行为与模拟策略；全适配器、通知、支付及配置键交叉对账 | jobs/integrations；阻塞 |
| G05 数据库版本/测试方法 | 目标主库SQLite/PostgreSQL，MySQL已获批不迁移；ClickHouse仅日志；Timescale是PG日志扩展；旧README最低版本未实测 | 用户确认补充范围/最低版本和测试办法；SQLx兼容证据设计、旧版镜像不可用处置；SQLite实际engine版本不可用Go模块号代替 | storage；两主库范围已批准；PG9.6及现代版本、SQLite实际引擎的远程测试方案见test-isolation.md；具体版本不可获取或驱动不兼容时才提交实际证据请求决策。功能通过属P1及后续阶段 |
| G06 Go基线/fixture | 两次run成功，公共配置fixture通过；MySQL/PG、支付签名原生skip | 归档命令、环境、退出码、skip名称/原因、证据SHA；确认P0“相关基线”充分性，未覆盖项明确阶段；需豁免只能由用户批准替代证据 | CI/verification；已执行部分不再阻塞，但不能用跳过项证明SQLite/PostgreSQL 两库通过 |
| G07 隔离方案 | 当前CI临时源码副本、无生产凭证、无真实服务；设计已有基础 | 冻结测试数据库、临时账号/数据、端口及生命周期；模拟上游域名/出站限制；禁邮件/支付/通知副作用；脱敏fixture可复现并不依赖本机目录 | CI/security；方案已交付并经独立审阅，见test-isolation.md；实现按阶段远程验证，不再作为缺方案阻塞 |
| G08 架构/工具依赖 | architecture为待复核设计；runner Rust版本查询通过；尚无Cargo.lock | 固定workspace DAG/公共契约，核查Axum/Tokio/SQLx等版本兼容及远程锁文件回收流程。用户已于2026-11-02明确批准P0建立最小依赖解析清单及必要target，由Actions生成验证并回收Cargo.lock；P1再建立真实业务workspace。不以探针目标冒充业务实现 | 架构/集成者；P0冻结要求未满足阻塞 |
| G09 最终独立验收 | 已有CI子交付PASS，不是P0全阶段PASS | 对合并后的精确SHA审阅主计划全部交付、归属和证据；抽查2–3组命令；独立verification给PASS/FAIL/PARTIAL，PARTIAL继续受阻 | 独立verification；阻塞 |

**推断**：缺口多数是台账、证据和决策工作，不是要求现在抢跑P1实现。不得把P8完整性能/安全/发布检查提前变为P0硬门槛，也不能用“后面补”取消P0要求的契约冻结与归属完整性。

## 3. 必须用户决策的真实问题

1. **D-SCOPE（范围已明确，版本证据待验证）**：用户取消MySQL，主库仅SQLite/PostgreSQL；保留现有ClickHouse日志与Timescale扩展的迁移台账，按P7/P8验收，不视为额外主库。SQLx不能满足PG9.6时不可默认升级门槛，须提交具体证据再确认，不提前假设不兼容。
2. **L-EPAY（待确认）**：固定v0.0.4未发现独立许可证；用户/维护者提供授权证据或批准合法来源的实现方案。未决不等于无授权，公共仓库也不等于授权。至少先冻结不复制不明素材的边界、责任人和解决阶段；无法满足P0许可处理要求时保持受阻。
3. **L-EGRESS（待确认）**：sing-box实际进程内库，Rust完整协议保留路径和合规方案需确认；换外部进程/删能力/保留Go运行时均不能悄悄执行。GPL与AGPL并非自动不兼容。
4. **D-EVIDENCE（条件性待确认）**：历史数据库不可获取、相关基线无法运行或独立复核不可用时，是否接受具体替代证据/豁免，只能用户决定。一般未完成台账由开发者补齐，无须把普通工作误包装成用户审批。

## 4. 不应单独阻止P1的后期事项（前提：P0已正式验收）

- **待验证/P1**：真实SQLite/PostgreSQL 两库连接、options持久读取、空/合法配置、库不可用、非法环境、错误方法、未实现路由失败语义；Cargo fmt/check/clippy/test。这些是P1交付，不是说现CI已覆盖。
- **待验证/P4–P7**：支付回调/金额/幂等、供应商真实凭证、sing-box替代协议golden、ClickHouse/Timescale实现和隔离副作用测试；不涉及这些组件的P1不必先获得真实付费调用授权。功能范围与许可处理决策仍需前置记录。
- **待验证/P8–P9**：全量传递依赖SBOM、发布包法律文本、字体/图标、UI归属、对应源代码入口、压力/性能/容器/部署/切流。远程Go测试成功不等于这些完成，也不能据此删功能。

## 5. 仅GitHub Actions的后续验证顺序

1. 集成者先合并台账/本次文档，保留现有未提交交付与已通过CI。获得相应授权后由集成者提交/推送；本代理不执行。固定新SHA、上游SHA、workflow/run/attempt。
2. 只读复核已有运行：
   - `gh api repos/xiaocongyu66/newapi-rs/actions/runs/41425478831/attempts/1`
   - `gh api repos/xiaocongyu66/newapi-rs/actions/runs/41425478831/attempts/2`
   - `gh run view 41425478831 -R xiaocongyu66/newapi-rs --attempt 2 --log`
   - 归档各attempt的environment、go-version、results.json及原始JSONL；artifact需核对attempt，不能拿最新同名文件替代历史。过期/缺失则报告缺口，授权后远程重建证据，不在本机复跑。
3. 远程抽查公共配置、focused（handler/compose/dbinfra）、relaykit三组命令，并核对full-api未排除失败包；核对非零测试数、原生skip和实际Go/Rust版本。不能把API job绿灯当所有测试均执行。
4. 新远程证据任务由CI owner评审，不修改本轮已绿配置：路由/任务/表台账差集、素材与法律文件一致性、依赖元数据；数据库按批准的版本和隔离方案在Actions建临时服务。P1再增加真实SQLxSQLite/PostgreSQL 两库契约，ClickHouse/Timescale按批准阶段新增独立矩阵，扩展探测降级不计扩展成功。
5. 独立verification对最终精确SHA和所有P0门槛复核；只有完整PASS且用户决策闭环后，主代理才更新主计划状态、启动P1。代码/CI改变后旧SHA PASS不能直接沿用。

## 6. 本轮交付边界

**事实**：仅新增本工作区 `docs/license-dependency-review.md`、`docs/p0-acceptance-gaps.md`。只读参考 `/root/newapi` 与主工作区文档；未修改主计划/CI、未提交推送、未启动服务/容器、未本地构建测试或运行自写脚本。保留原有未提交 `.github/`、`scripts/`、`docs/ci-baseline.md`。本文件不声称已完成完整许可证审计或P0验收。
