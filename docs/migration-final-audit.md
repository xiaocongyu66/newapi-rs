# P0 迁移有限范围最终静态审计

日期：2026-11-02。结论：**本次指派的迁移具名缺口已静态闭合；不代表整个 P0 或升级运行验收通过。** 本文仅新增于 `/root/newapi-rs-p0-ci/docs/migration-final-audit.md`；未修改其他文件、未提交推送、未执行本地构建/测试/脚本/服务/容器。核查仅用 Read/Grep/Glob，写入仅用 Write。

依据：只读 `/root/newapi-rs/docs/data-coverage.md`（§6 具名“旧路由去组/策略SQL参数”、§1/§2 模型与原生对象）、`/root/newapi-rs/docs/schema-inventory.md`、`/root/newapi-rs/docs/rust-backend-migration-plan.md`。这些台账声明上游基线 `17970da4571e81308f176a0e61a38276e5771606`；本轮未执行 git 重新认证工作树 SHA。以下源码路径除特别注明外，均以 `/root/newapi/apps/api/internal/` 为绝对根。源码高于注释及 README。主库目标仅 SQLite、PostgreSQL；MySQL 只作为历史分支事实，不引入 Rust MySQL 支持或验收任务。ClickHouse 仍是独立日志选项，Timescale 是 PostgreSQL 日志扩展，不能据主库范围自动删除它们。

## 1. 有限缺口逐项结论

| data-coverage 所指项目 | 本次结论 | owner / 后续阶段 |
|---|---|---|
| `common/dbx/migrate_route_unit_group.go` / `CollapseRouteUnitGroups` | 已闭合：固定表/列、合并键、保留规则、值绑定、前置顺序、非整体事务和重跑边界见§2 | catalog 业务语义；storage 迁移执行，P8 |
| `dbinfra/timescale_log.go` / `setupTimescaleLogHypertable` 与两策略函数 | 已闭合：固定对象、4个环境键、共库/分库调用、扩展门控、策略非对账式更新、版本SQL差异见§4 | usage 日志/保留契约；storage DDL；config 解析，P8 |
| `/root/newapi/db/archive` 两份历史 SQL | 2/2 已闭合：历史人工补丁，非自动启动输入；不复制为 Rust 自动迁移，也不删除历史材料，见§5 | billing/identity 与 catalog 历史契约；storage P8 按显式升级来源处理 |
| 已登记旧调度列删除目标 | 4/4 已闭合：精确目标、权重先转存、目录索引来源、schema/引用边界见§3 | catalog + storage P8 |
| 52模型与额外原生表/账本 | 已核对注册分母和本范围原生对象；新增业务模型为0，独立原生迁移账本为1，见§6 | 各业务 owner；storage P1/P8 |

这不是全仓库任意 Raw/Exec/Migrator/Table 的完备证明。对台账那条复合开放项，本轮只关闭其具名迁移/历史SQL子集，不冒充关闭 JSON/Scan/Value/密文 fixture、其他配置或异步入口。

## 2. 路由单元去组

证据：`/root/newapi/apps/api/internal/common/dbx/migrate_route_unit_group.go:44–134`；启动顺序 `/root/newapi/apps/api/internal/dbinfra/open_db.go:195–229`。

- **固定标识符**：唯一业务表 `channel_model_routes`；退役列 `group`；聚合身份是 `(public_model_alias, channel_id, key_index, upstream_model)`。查询字段、GROUP BY、更新字段名、PG cast 分支全部是代码常量，不来自 HTTP 或用户可自定义表名。
- **数据/用户输入**：别名、upstream model、渠道ID、key index、权重与 enabled 来自已有行，可能最初由管理员配置；它们是数据，不是 SQL 标识符。删除的 keepIds 与更新的 KeepId 通过 GORM 占位绑定，权重/enabled 通过 Updates map 值传入；别名仅进入审计日志，不拼接 SQL。
- **精确语义**：每个身份保留最小 id；取最大 static_weight；任一 enabled 即保留启用。不是保留任意第一行、最小权重或固定重置100。MinWeight 只用于分歧审计日志。其他兄弟行删除，不合并不同 upstream/key/channel/alias。缺表、缺 group 返回；空表直接尝试删除 group。
- **顺序**：master 的 `migrateDB` 在 AutoMigrate 建新唯一索引前调用折叠；其后 AutoMigrate → 注册后置迁移（含 route seed）→ RunSQLMigrations → 四旧列清理。去组不得挪入 AutoMigrate 后的版本SQL队列。
- **事务与重跑**：聚合查询在事务外；删除兄弟行和修改保留行在一个事务内；删索引/删 group 在该事务提交后，不是端到端原子事务。删列失败时已折叠数据可能已提交，重跑可再次折叠剩余行；完整成功后以 group 不存在跳过。不能声称并发写入受保护：事务外快照加 `id NOT IN keepIds` 在迁移并发写入时有删除新增行的危险，必须由 storage P8 的迁移停写/排他策略处理。
- **方言**：SQLite 通用 CASE/max；PostgreSQL enabled 聚合另加 `::int`；group 引用交由固定目标 drop helper；MySQL仅历史。不新增动态表。丢弃的 group 信息不可逆，P8 必须验证备份恢复，而不是假定降级二进制可读。
- **失败语义**：聚合、事务、drop 返回的错误会使启动失败；但 `tableExists/columnExists` 会把目录查询错误降为 false（见§3），所以不能笼统称任何探测失败必拒启。

## 3. 四个旧列与运行时索引名

证据：`/root/newapi/apps/api/internal/common/dbx/migrate_priority_weight.go:42–270`。

| 固定删除目标 | 转存/删除语义 | owner |
|---|---|---|
| `channels.priority` | 无 priority 转存逻辑；在权重转存成功后删除 | catalog；storage 执行 |
| `channels.weight` | 先读取非NULL且>0的旧权重；仅覆盖同 channel_id 且 static_weight=100 的路由行，再删除旧列 | catalog；storage 执行 |
| `abilities.priority` | 无单独转存；删除引用它的可发现索引后删列 | catalog；storage 执行 |
| `abilities.weight` | 不作为 route 权重来源；删除引用它的可发现索引后删列 | catalog；storage 执行 |

1. 四对 table/column 来自函数内静态切片，不来自用户；`channel_model_routes.group` 是§2单独的第五个退役列，不得混为原有“四列”或漏记。**禁止泛化删除所有 weight/priority/group 列**，其他表的同名列不在授权目标中。
2. `carryOverChannelWeightToRoutes` 读取 `channels`，写固定 `channel_model_routes`；row.Id、常量100与权重作为值绑定；仅更新seed值，已经调过的非100 route权重优先。扫描在事务外，更新循环在事务内，之后四次drop不在同一个总事务。注释77行称其在AutoMigrate前运行，与真实调用位置不符；以 `open_db.go:229` 的后置调用为准。
3. 重跑依赖缺列跳过；已转存的非100值不会再匹配seed条件。若四列删除中途失败，前面的删除不会整体撤销。正数权重转换 `uint→int` 的边界属于 P8 脱敏fixture，不把“所有历史值安全”作为静态事实。
4. SQLite `tableExists` 读 `sqlite_master`，`columnExists` 读 `pragma_table_info(?)`；PG 查询 `information_schema` 并限定 `current_schema()`。table/column为绑定值，拼接的 schema 函数来自固定方言分支。两个探测函数吞错误返回false，需 P8 验证权限错误与缺表的区别。
5. **运行时标识符来源**：SQLite 从 `pragma_index_list(?)` 联接 `pragma_index_info(il.name)` 得到索引名；PG 从 `pg_index/pg_class/pg_attribute` 得到非主键索引名；历史MySQL从 information_schema.statistics 得到非PRIMARY名。这些是数据库目录对象，可由DBA创建，不是直接HTTP输入；不要求枚举每个部署的索引名。
6. DROP INDEX 将目录名包反引号（SQLite/历史MySQL）或双引号（PG）后拼接，**未转义名字内部引号**。PG检索只限定 `t.relname`，没有 namespace 条件，DROP又不带schema；同名跨schema可能选错/删错/失败。SQLite的join不能保证覆盖表达式或仅在partial predicate引用旧列的索引；PK/unique约束与自动索引也不能当成普通可删索引。上述是已定位的实现边界，不是要求P0遍历无限目录值。
7. SQLite原生DROP COLUMN依赖3.35+且受索引/约束依赖限制；PG双引号引用；历史MySQL用 ALTER TABLE DROP INDEX。Rust P1锁定驱动/最低SQLite版本，P8修复或显式拒绝不支持的依赖，测试引用转义、跨schema、表达式/partial/约束依赖、部分失败恢复。不得仅按注释推断“每个引用索引都能找到”。

## 4. Timescale与当前自动版本SQL

### 4.1 Go日志初始化

证据：`/root/newapi/apps/api/internal/dbinfra/timescale_log.go:25–148`；`/root/newapi/apps/api/internal/dbinfra/open_db.go:148–247`。

- **调用**：无 LOG_SQL_DSN 时 LogDB=DB，master在InitLogDB调用setup；分库master由migrateLOGDB先迁移日志模型再setup；非master跳过迁移；ClickHouse先走独立原生日志DDL并返回，不走Timescale。setup只在 TIMESCALEDB_ENABLED=true 且日志DB为PG时执行。
- **固定对象**：`logs`、`created_at`、`logs_pkey`、`idx_logs_id`、`logs_created_at_now()`、扩展 `timescaledb` 及 `pg_available_extensions/pg_constraint`。没有按请求/用户组创建表或函数。未限定schema的 `logs` 由PG search_path解析，这不是用户自选动态业务表，却是需要固定部署schema的运行上下文。
- **四个运维输入**：TIMESCALEDB_ENABLED默认false；TIMESCALEDB_CHUNK_INTERVAL_SECONDS默认604800，<=0回退默认；TIMESCALEDB_COMPRESS_AFTER_DAYS默认0；TIMESCALEDB_RETENTION_DAYS默认0，后二者<=0跳过。正天数乘86400后以 `?::bigint` 绑定；chunk interval同样绑定，不作为标识符拼接。无HTTP直接入参；极端整数乘法溢出与边界校验归config/storage P8。
- **扩展条件**：探测的是 `pg_available_extensions`（可安装，不等于已安装）；不可用则日志提示并返回nil；可用会尝试 CREATE EXTENSION IF NOT EXISTS，权限/SQL失败返回错误，不自动降级。源码文件头的“未安装便跳过”不能替代此实际行为。
- **主键**：按固定约束名logs_pkey+logs regclass查询，恰好等于PRIMARY KEY(id)时改为(created_at,id)，同时创建非唯一idx_logs_id。无该约束或其他形状时不改，但仍调用create_hypertable，可能因其他唯一约束失败。不要声称任意自定义PK都自动修复。created_at是bigint epoch秒；创建/替换now函数返回epoch秒，策略单位也是秒。
- **事务**：setup没有外围事务；建扩展、PK多语句Exec、hypertable、函数、compression、retention分步执行。不能仅因PK几条SQL在同一Exec就声称整个过程可回滚。前一步成功、后一步失败可留下部分状态。
- **重跑**：IF NOT EXISTS / replace_if_exists只表示重复创建容忍，不保证配置收敛。已有hypertable的chunk interval未见显式更新；正数策略用if_not_exists，不替换已有策略；把天数改为0只跳过，不删除现有策略，TIMESCALEDB_ENABLED=false也不逆向转换/删除已有扩展或策略。保留策略会删除账单证据，不能擅自增加默认值或清理既有策略。
- **owner**：usage定义日志证据保留/压缩契约；storage实施扩展、schema与迁移；config解析运维值。P8批准扩展版本、权限、schema、参数更新契约及部分失败恢复矩阵；不是P0实现Rust服务的任务。

### 4.2 自动版本SQL与账本

证据：`/root/newapi/apps/api/internal/dbinfra/sql_migrations.go:15–143`；该目录 `migrations/001_drop_unused_log_indexes.sql`、`002_logs_timescale_hypertable.sql`；`/root/newapi/apps/api/internal/common/database.go:8`。

- embed范围仅同包 `migrations/*.sql`，按文件名排序；不是递归执行 `/root/newapi/db`。实际方言值 `DatabaseTypePostgreSQL="postgres"`，所以文件头postgres确实匹配；runner注释的postgresql字样不是枚举实值。
- 唯一额外永久原生表 `schema_migrations(version varchar(255) PRIMARY KEY, applied_at bigint NOT NULL)`。文件名为构建期项目输入，版本查找与插入使用参数绑定；applied_at=time.Now().Unix()秒。无checksum列；已登记版本不重跑，即使内容修改也不会重新执行。
- 主库master在AutoMigrate和后置迁移之后调用runner；独立日志库migrateLOGDB没有调用RunSQLMigrations。因此不能假定001在分离日志库执行，也不能把主库账本等同日志库账本。
- 每个适用且未记录文件单独事务，所有语句+成功账本插入一起提交；建账本自身在外部。文件间没有全局事务；查询已执行状态在文件事务外，未见跨实例迁移锁。nil DB或无文件返回。按方言跳过和TIMESCALEDB_ENABLED关闭跳过都不记版本；SQL内部条件RETURN但无错误则仍记版本。
- **001**：适用postgres/sqlite；只删除6个固定索引 `idx_logs_request_id`、`idx_logs_upstream_request_id`、`idx_logs_ip`、`idx_logs_group`、`idx_logs_token_name`、`idx_logs_token_id`，IF EXISTS容忍缺失。没有删除列、表或Log模型；不存在动态索引名输入。记账后若AutoMigrate或管理员重新创建索引，runner不会自动再删。owner usage+storage P8。
- **002**：适用postgres，runner还以SQL包含create_hypertable且TIMESCALEDB_ENABLED开启为门。DO块只在扩展已安装时工作，不负责安装；检测hypertable已存在直接返回；以public.logs检查表/created_at与主键，但部分实际DDL/函数仍为不带schema名称。固定chunk interval为86400秒，与Go默认604800不同。未知主键形状返回；无PK时补PK，而Go函数不补这一分支；二者并非可互换副本。函数里的EXECUTE是固定SQL字符串，不是用户动态SQL。
- **002重跑差异**：若扩展未安装，DO RETURN仍可能被记作成功，之后不会重试文件；日志初始化的Go路径仍可在以后安装扩展并转换。同库已安装扩展时SQL可先以1日转换，后续Go IF NOT EXISTS不等同修改为7日。独立日志库只走Go setup。未知主键/非public schema/不同search_path下两条路径的差异是P8精确fixture范围，不可凭“幂等”注释合并掉。

## 5. 历史手工SQL与仅供审查的参考SQL

证据：`/root/newapi/db/README.md:9–42`；`/root/newapi/db/route-unit-degroup/README.md:54–88`；两份archive文件全文；实际embed与启动调用见§4。对 `/root/newapi/apps/api` 的Go源码检索没有发现archive/migration_v0引用。一次全仓泛搜超时未用于声称全仓无引用；确定结论依赖embed白名单和实际入口。

| 文件 | 固定对象、数据来源与行为 | 事务/重跑/方言/处理结论 |
|---|---|---|
| `/root/newapi/db/archive/migration_v0.2-v0.3.sql` | 固定users、tokens；按tokens.user_id=users.id把SUM(remain_quota)加到users.quota。没有用户SQL参数，也无额外表。owner billing资金语义+identity账户存储 | 一条UPDATE，无脚本级BEGIN或账本。重复会再次加额度，不幂等；无匹配token时SUM=NULL，未COALESCE，可能产生NULL或触发约束失败。SQLite/PG语法可表达不代表允许执行。历史人工升级补丁，绝不能作为每次启动迁移或补跑推断；仅在明确旧版本来源、备份和一次性核算批准后由P8处理，账务结果归P4 |
| `/root/newapi/db/archive/migration_v0.3-v0.4.sql` | 固定abilities/channels；读取c.group/id/status，CROSS JOIN固定4模型gpt-3.5-turbo、gpt-3.5-turbo-0301、gpt-4、gpt-4-0314；仅status=1且同group/model/channel不存在时插入enabled=1。没有运行时标识符或新增模型表 | 一条INSERT SELECT，无显式外层事务/账本。NOT EXISTS只提供顺序重跑缺项跳过，并发仍依赖唯一约束/隔离；不更新已存在enabled。反引号是历史MySQL式引用（SQLite亦接受），PG不能照抄。它不是当前route seed，也不将四个过时模型自动播种进Rust。owner catalog，P8历史输入审查 |

`/root/newapi/db/route-unit-degroup/README.md` 是Go启动迁移的档案，而非启动加载器：其中 `CREATE TABLE channel_model_routes_new ... DROP TABLE ... RENAME` 是参考SQL，实际Go原地折叠，不创建该表；`channel_model_routes_pre_degroup` 只是一项未实现备份建议。两者都不进入“实际新增表”分母，也不能误执行、误删。文档里的pg_dump/restore示例本轮未执行。保留历史材料，不将archive和当前嵌入001/002混类。

## 6. 52模型与原生对象交叉核对

本轮检索生产RegisterMigrations/模型声明，与台账逐项组对照（测试注册排除）；注册仅append、无去重，展开函数不按Name排序。来源 `/root/newapi/apps/api/internal/common/dbx/migrate.go:27–52`、`/root/newapi/apps/api/internal/dbinfra/run_migrations.go:19–35` 和下表注册点。

| 生产注册来源（上述源码根下） | 已核对模型 | 数量 |
|---|---|---:|
| dbinfra/run_migrations.go | Option | 1 |
| identity/migrate_identity.go | Token、User、UserSession、AuthFlow、ExternalIdentityClaim、PasskeyCredential、TwoFA、TwoFABackupCode、CustomOAuthProvider、UserOAuthBinding、CasbinRule、AuthzRole、QQBinding、QQBindCode、QQUnbindRecord | 15 |
| catalog/register_migrations.go | Ability、Channel、ChannelModelHealth、ChannelModelRoute、GatewayConfigOutbox、GatewayConfigRevision、Model、PrefillGroup、Vendor | 9 |
| billing/register_migrations.go | Redemption、TopUp、Checkin、SubscriptionOrder、UserSubscription、SubscriptionPreConsumeRecord、QQCheckin、QQDrop、QQTransfer、QQRedPacket、QQRedPacketGrab、QQSteal | 12 |
| ops/register_migrations.go | dbinfra.Setup、SystemInstance、SystemTask、SystemTaskLock | 4 |
| task/register_migrations.go | Midjourney、Task | 2 |
| usage/register_migrations.go | Log、QuotaData、UserInsightProfile、UserInsightSample、UserInsightClientBan | 5 |
| usage/record_perf.go:231–233 | PerfMetric | 1 |
| egress/store_proxy_node.go:137 | ProxyNode | 1 |
| mailer/quota_usage.go:27 | SMTPQuotaUsage | 1 |
| billing/bootstrap_subscription_plan.go:15–22 后置 | SubscriptionPlan（不在上述51主注册内） | +1 |

结论：51主注册+1后置=52独立业务模型；usage另外RegisterLogMigrations(Log)与主库Log重叠，不是第53模型。这里只重核注册集合与迁移路径，不宣称重新验证了52项所有字段/JSON/实际DDL。

| 原生/附加对象 | 与52模型关系、固定/动态来源 | owner与结论 |
|---|---|---|
| schema_migrations | 固定原生永久账本，无业务模型；版本行来自嵌入文件名 | storage P8；额外账本必须保留独立核对 |
| subscription_plans | SQLite固定CREATE和白名单补列，已经是第52模型，不另计；无整体事务，逐列缺失才补；不归一化既有列类型 | billing契约/storage P8；原生默认与GORM标签的差别保留；证据bootstrap_subscription_plan.go:25–101 |
| channel_model_health_new | SQLite事务内固定重建临时名字，复制旧表后删旧改名；完成后是现有ChannelModelHealth | catalog/storage P8；不是永久第53业务模型；证据catalog/bootstrap_migrations.go:28–79 |
| ClickHouse logs | 固定原生DDL，是Log的独立日志物理实现；MergeTree、月分区与(created_at,request_id)排序；没有channel_name列 | usage/storage P8；证据open_db.go:242–328；TTL来自整数环境值，<=0无TTL，正数格式化数字并同步TTL，不新增业务表 |
| Timescale logs/chunks、扩展目录、整数now函数与策略 | logs仍为Log；chunks/策略内部对象由扩展运行时生成，不可预枚举，也不是额外业务模型 | usage/storage P8；登记扩展/策略生命周期即可，不用枚举每个chunk阻塞P0 |
| channel_model_routes_new / channel_model_routes_pre_degroup | 仅README参考SQL/未实现建议 | 排除实际生产表集合，不做自动清理 |
| SQL派生别名与历史SQL的c/m/a | 查询作用域别名，不是表创建 | 不新增模型；不混入物理表分母 |

因此本范围没有发现台账遗漏的业务模型；**52不是实际部署永久表总数**，需另加账本，并区分共库/分库日志及扩展对象。最终运行注册顺序、实际物理表名（包括TwoFA默认命名）和约束需按P1/P8证据验证，不由源码登记伪造。

## 7. 有限剩余项与交付边界

### 7.1 本次具名范围的静态剩余

**无未读的具名迁移入口。** 所有权、固定名/运行时目录名/用户数据边界、事务、重跑、方言与历史分类均已说明。发现的代码边界不以“待继续核查”悬置，而归入以下具体后阶段验收：

| 有限验收项 | 具体函数/原因 | 阶段与owner |
|---|---|---|
| 去组+转存+删列失败恢复与迁移排他 | CollapseRouteUnitGroups事务外聚合；carryOverChannelWeightToRoutes与drop拆事务；并发写入不受统一保护 | P8 storage+catalog：停写、连续两次迁移、阶段性失败及备份恢复 |
| 目录错误/标识符/索引依赖 | tableExists/columnExists吞错误；dropIndexesOnColumn内部引号、PG namespace、表达式/partial/约束边界 | P1 storage锁SQLite最低版本；P8 storage实现安全引用和依赖处理并做定向fixture |
| 扩展矩阵与策略变更 | setupTimescaleLogHypertable及applyTimescaleCompression/Retention无整体事务、不是配置收敛；002与Go存在PK/schema/interval差别 | P8 usage+storage：共/分库、扩展缺失/权限、既有PK、search_path、0→正→0、失败恢复；扩展版本由部署范围批准 |
| 原生表/账本运行对账 | RunSQLMigrations缺跨实例锁/内容校验；主库与分离日志作用域不同；原生订阅与健康重建 | P8 storage+billing+catalog：空库/旧库/重入、实际DDL/行数/账本对账；账务历史补丁不得默认执行 |
| fixture未知实际数据 | 没有授权/提供部署schema、历史权重与脱敏金额/密文样本，不可从代码推导真实值分布 | P4 billing资金验证；P8 storage升级验证；不要求P0获得无限用户值 |

### 7.2 不冒领其他并行静态工作

`/root/newapi-rs/docs/data-coverage.md:140–151` 的另外7行不在本任务读取/写入授权的迁移核查范围，本文件不替它们勾选：

| 具名行 | 本轮结论与确切交接 |
|---|---|
| catalog种子hook/ValidateGatewayDispatchOption | 非迁移SQL缺口；由config/catalog静态收口负责，P3/P5契约 |
| totp/utils/init/ali动态env | 非本范围；identity/config/relay负责容器与消费者，P2/P6，不枚举环境变量值全集 |
| manage_qqbot.handleQQBotEvent | 非本范围；integrations/billing负责验签/去重/分派，P7 |
| ops.limit_notify/track_health/security/sensitive/logger入口 | 非本范围；ops/catalog/security/usage负责逐闭包生命周期，P2/P5/P7/P9 |
| metadata_sync/model_sync/channel_probe/relay后处理 | 非本范围；catalog/integrations/relay负责扇出和副作用，P3/P5/P7 |
| singbox/fiberadapter/realtime/供应商stream | 非本范围；integrations/transport/relay负责取消与连接退出，P5/P6 |
| rate-limit与main/internal定时器差集 | 非本范围；security/jobs负责封装计时器和既有启动表差集，P2/P7 |

这些行需要其各自静态交付才能由集成者判断P0总门禁；本审计既不宣告它们完成，也不把它们扩张成“继续全仓无限搜”。现台账的52模型V空框、后续Rust升级/任务恢复运行测试不能单独前置为P0不通过原因。整体P0验收与独立verification由集成流程决定，本文件只提供已闭合的迁移子集及可执行的后阶段验收边界。
