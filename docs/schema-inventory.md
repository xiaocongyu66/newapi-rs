# P0 schema 字段与迁移核对清单

状态：进行中，未验收；2026-11-02；上游 `17970da4571e81308f176a0e61a38276e5771606`。路径相对只读 `/root/newapi/apps/api/internal/`。事实=源码声明；推断=命名/目标所有权；待验证=尚未导出实际数据库。不得把 Go 类型或 GORM 标签当成SQLite/PostgreSQL两目标库实际 DDL。

## 1. 阅读规则与验收列

**最新用户批准范围**：Rust目标仅SQLite+PostgreSQL；MySQL分支/标签差异仅保留为历史事实，不迁移、不要求MySQL CI/最低版本测试。尽量兼容原表/字段/ID/额度/时间单位/软删除，差异显式记录，禁止未经批准有损转换。ClickHouse独立日志与Timescale扩展仍保留台账，不自动移除。

以下字段使用 Go 原名，未注明 column 的 SQL 列名是 GORM snake_case **推断**；`∅` 表示无显式 gorm tag，不表示 NOT NULL/默认值。未标注 override 的表名均为默认命名推断。`primaryKey`、`index`、`uniqueIndex`、`type:*` 等是标签事实，自动生成名称、NULL/排序规则、长度截断、外键与实际索引必须在 Actions 核验。所有权/阶段沿用 data-jobs-inventory.md，各表物理写入不等同目标域边界。

分阶段验收：P0冻结集合、源码字段/忽略字段/标签、读写归属和测试方案；P1验证SQLxSQLite/PostgreSQL两目标库连接与基础数据访问；P4验证账务；P7验证任务恢复；P8完整升级演练及最终DDL对账。实际表/列名、类型/NULL/default、PK/unique/index/FK/check、JSON/密文/软删除与重复迁移的运行证据按所属阶段取得，不前置为P0通过条件。已有Go基线见ci-baseline.md：run 41425478831 attempt 1/2，SHA 6e599ec59837d645b4740ebe363790beda6b40f1均success；该结果不替代后阶段运行验收。

## 2. 已逐字段登记

### Option → options（catalog持久化；config经公开端口加载；P1/P3）

事实 `dbinfra/store_options.go:42–45`：Key string〔primaryKey〕；Value string〔∅〕。无显式 TableName；值是字符串容器，不可把 JSON 内容误建 JSON SQL 列。事务更新先验证再持久化；gateway routing 键需 catalog revision/outbox hook，hook 未接线返回错误，不能退化普通写（同文件84–163）。

### User → users（identity 持久化、billing 编排资金；P2/P3/P4）

事实 `identity/store_users.go:80–125`，完整字段及标签：

| Go字段 : 类型 | gorm tag（无显式标签写∅） |
|---|---|
| Id : int | ∅ |
| Username : string | unique;index |
| Password : string | not null; |
| OriginalPassword : string | -:all |
| DisplayName : string | index |
| Role / Status : int | type:int;default:1 |
| Email : string | index |
| GitHubId / DiscordId / OidcId / WeChatId / TelegramId : string | 分别 column:github_id / discord_id / oidc_id / wechat_id / telegram_id；均 index |
| VerificationCode : string | -:all |
| AccessToken : *string | type:char(32);column:access_token;uniqueIndex |
| Quota : int | type:int;default:0 |
| UsedQuota : int | type:int;default:0;column:used_quota |
| QuotaDisplay / UsedQuotaDisplay / AffQuotaDisplay / AffHistoryQuotaDisplay : float64 | - |
| RequestCount : int | type:int;default:0; |
| Group : string | type:varchar(64);default:'default' |
| AffCode : string | type:varchar(32);column:aff_code;uniqueIndex |
| AffCount : int | type:int;default:0;column:aff_count |
| AffQuota : int | type:int;default:0;column:aff_quota |
| AffHistoryQuota : int | type:int;default:0;column:aff_history |
| InviterId : int | type:int;column:inviter_id;index |
| DeletedAt : gorm.DeletedAt | index |
| LinuxDOId : string | column:linux_do_id;index |
| Setting : string | type:text;column:setting |
| Remark : string | type:varchar(255) |
| StripeCustomer : string | type:varchar(64);column:stripe_customer;index |
| CreatedAt : int64 | autoCreateTime;column:created_at |
| LastLoginAt : int64 | default:0;column:last_login_at |
| AuthVersion : int64 | type:bigint;not null;default:1;column:auth_version |
| AdminPermissions : map[string]map[string]bool / QQOpenID : string | -:all |

待验证：Id 隐式主键/自增、软删除下 Username/AffCode 唯一性、NULL AccessToken 唯一性；密码散列不是可直接改算法的字段；`aff_history` 与 JSON `aff_history_quota` 不同。QQOpenID 不是 users 列。展示金额不落库。

### Token → tokens（identity；P2/P3/P4）

事实 `identity/token_store.go:16–37`：Id int〔∅〕；UserId int〔index〕；Key string〔type:varchar(128);uniqueIndex〕；Status int〔default:1〕；Name string〔index〕；CreatedTime/AccessedTime int64〔bigint〕；ExpiredTime int64〔bigint;default:-1〕；RemainQuota/UsedQuota int〔default:0〕；RemainQuotaDisplay/UsedQuotaDisplay float64〔-〕；UnlimitedQuota/ModelLimitsEnabled/CrossGroupRetry bool〔∅〕；ModelLimits/AutoGroups string〔type:text〕；AllowIps *string〔default:''〕；Group string〔default:''〕；DeletedAt gorm.DeletedAt〔index〕。AutoGroups JSON 编码见47–65，列仍是 text。待验证：key 大小写唯一、-1 永不过期、软删除复用、text 历史升级。

### UserSession → user_sessions（显式 override；identity；P2）

事实 `identity/session_store.go:43–64`：SID string〔column:sid;type:varchar(64);primaryKey〕；UserID int〔column:user_id;not null〕；Version int64〔type:bigint;not null;default:1〕；UserAuthVersion int64〔type:bigint;not null〕；Status string〔type:varchar(16);not null〕；RefreshHash string〔type:char(64);not null〕；PreviousRefreshHash string〔type:varchar(64)〕；PreviousValidUntil int64〔type:bigint;not null;default:0〕；LoginMethod string〔type:varchar(32);not null〕；IP string〔type:varchar(64)〕；UserAgent string〔type:text〕；CreatedAt int64〔autoCreateTime;column:created_at〕；LastActiveAt int64〔type:bigint;not null;column:last_active_at〕；ExpiresAt int64〔type:bigint;not null;column:expires_at〕；RevokedAt int64〔type:bigint;not null;default:0;column:revoked_at〕；RevokedReason string〔type:varchar(64);column:revoked_reason〕。

事实附加索引标签：`idx_user_sessions_user_status_expiry`=(UserID priority:1,Status:2,ExpiresAt:3)；`idx_user_sessions_user_created`=(UserID:1,CreatedAt:2)；`idx_user_sessions_status_revoked`=(Status:1,RevokedAt:2)；ExpiresAt另有 `index:idx_user_sessions_expires_at`。待验证：刷新竞争、旧hash宽限、撤销与 auth_version 一致性；不可按字段名误推外键。

### AuthFlow → auth_flows（显式 override；identity；P2/P7）

事实 `identity/run_authflow.go:40–55`：Id int64〔primaryKey〕；TokenHash string〔type:char(64);not null;uniqueIndex〕；Purpose string〔type:varchar(32);not null;index:idx_auth_flow_purpose_expiry〕；Provider string〔type:varchar(64)〕；Intent string〔type:varchar(16)〕；UserId int〔index〕；SessionId string〔type:varchar(64);index〕；Payload string〔type:text〕；CreatedAt time.Time〔∅〕；ExpiresAt time.Time〔not null;index:idx_auth_flow_purpose_expiry〕；ConsumedAt *time.Time〔index〕。待验证：复合索引实际顺序、消费原子性及 NULL consumed_at。

### Channel → channels（catalog；P3/P5/P6）

事实 `catalog/store_channel.go:24–63`：Id int〔∅〕；Type int〔default:0〕；Key string〔not null〕；OpenAIOrganization/TestModel *string〔∅〕；Status int〔default:1〕；Name string〔index〕；CreatedTime/TestTime/BalanceUpdatedTime int64〔bigint〕；ResponseTime int〔∅〕；BaseURL *string〔column:base_url;default:''〕；Other/Models/OtherInfo string〔∅〕；Balance float64〔∅〕；Group string〔type:varchar(64);default:'default'〕；UsedQuota int64〔bigint;default:0〕；UsedQuotaDisplay float64〔-〕；ModelMapping *string〔type:text〕；StatusCodeMapping *string〔type:varchar(1024);default:''〕；AutoBan *int〔default:1〕；Tag *string〔index〕；Setting/ParamOverride/HeaderOverride *string〔type:text〕；Remark *string〔type:varchar(255)〕；ChannelInfo ChannelInfo〔type:json〕；OtherSettings string〔column:settings〕；Keys []string〔-〕。注释掉的 MaxInputTokens 不是当前字段。

事实 ChannelInfo JSON 成员见65–73：is_multi_key、multi_key_size、multi_key_status_list、multi_key_disabled_reason、multi_key_disabled_time、multi_key_polling_index、multi_key_mode。待验证：map[int]序列化键、空/NULL、秘密遮盖、Key多key拆分、settings与setting区别。

### Ability → abilities（catalog；P3/P5）

事实 `catalog/store_ability.go:19–25`：Group string〔type:varchar(64);primaryKey;autoIncrement:false〕；Model string〔type:varchar(255);primaryKey;autoIncrement:false〕；ChannelId int〔primaryKey;autoIncrement:false;index〕；Enabled bool〔∅〕；Tag *string〔index〕。待验证：三列主键、引用channel不存在的行为及 legacy priority/weight 删除。

### ChannelModelRoute → channel_model_routes（catalog；P3/P5）

事实 `catalog/store_model_routes.go:29–37`：Id int〔primaryKey;autoIncrement〕；PublicModelAlias string〔type:varchar(255);uniqueIndex:idx_route_unit,priority:1〕；ChannelId int〔uniqueIndex:idx_route_unit,priority:2;index:idx_route_channel〕；KeyIndex int〔uniqueIndex:idx_route_unit,priority:3〕；UpstreamModel string〔type:varchar(255);uniqueIndex:idx_route_unit,priority:4〕；StaticWeight int、Enabled bool〔∅〕。待验证：去 group 合并先于创建该唯一索引，多组旧记录去重后的权重/启用状态。

### GatewayConfigRevision / GatewayConfigOutbox（catalog；P3/P7）

事实 `catalog/store_gateway_revision.go:30–46`：Revision：ID int〔primaryKey〕；RoutingRevision int64〔not null〕。Outbox：ID int〔primaryKey〕；RoutingRevision int64〔not null;uniqueIndex〕；CreatedAt time.Time、PublishedAt *time.Time〔∅〕；PublishAttempts int〔not null〕；LastPublishErrorClass string〔type:varchar(64)〕。表名推断 gateway_config_revisions / gateway_config_outboxes。事实注释明确 outbox 不保存配置 payload/秘密；InitializeGatewayConfigRevision 在空表插入单例。待验证：单例约束不是仅凭ID标签就能证明、并发种子、跨实例发布与重试。

## 3. 其余模型注册索引

本轮已将以下42个模型的源码字段展开至§6，不重复§2的10个模型。注册集合共52个独立模型（51个主库注册+后置SubscriptionPlan）；字段登记不等于实际DDL或行为通过。表名依据 data-jobs-inventory.md，默认命名仍须远程验证。下表保留注册证据与阶段索引；六类运行验收均未闭环。

| 注册点/顺序事实 | 模型（字段见§6；每个模型单独验收六项） | 目标所有权/阶段 |
|---|---|---|
| identity/migrate_identity.go:17 | ExternalIdentityClaim | identity P2/P7 |
| 同:18 | PasskeyCredential | identity P7 |
| 同:19 | TwoFA（实际默认表名尤其待确认） | identity P2 |
| 同:20 | TwoFABackupCode（实际默认表名尤其待确认） | identity P2 |
| 同:21 | CustomOAuthProvider | identity P3/P7 |
| 同:22 | UserOAuthBinding | identity P7 |
| 同:23 | policy.CasbinRule，override casbin_rule | identity持久化，security经端口鉴权 P2/P3 |
| 同:24 | policy.AuthzRole | identity持久化，security经端口鉴权 P2/P3 |
| 同:25 | QQBinding | identity P7 |
| 同:26 | QQBindCode | identity P7 |
| 同:27 | QQUnbindRecord | identity P7 |
| catalog/register_migrations.go:12 | ChannelModelHealth，override channel_model_health | catalog P5/P7 |
| 同:16 | Model | catalog P3 |
| 同:17 | PrefillGroup | catalog P3/P5 |
| 同:18 | Vendor | catalog P3 |
| billing/register_migrations.go:9 | Redemption | billing P4 |
| 同:10 | TopUp | billing P4/P7 |
| 同:11 | Checkin | billing P4 |
| 同:12 | SubscriptionOrder | billing P4/P7 |
| 同:13 | UserSubscription | billing P4 |
| 同:14 | SubscriptionPreConsumeRecord | billing P4 |
| 同:15 | QQCheckin | billing P4/P7 |
| 同:16 | QQDrop | billing P4/P7 |
| 同:17 | QQTransfer | billing P4/P7 |
| 同:18 | QQRedPacket | billing P4/P7 |
| 同:19 | QQRedPacketGrab | billing P4/P7 |
| 同:20 | QQSteal | billing P4/P7 |
| billing/bootstrap_subscription_plan.go:15–21，后置单独迁移 | SubscriptionPlan | billing P4/P8 |
| ops/register_migrations.go:11 | dbinfra.Setup（不是ops同名DTO） | storage/identity P2 |
| 同:12 | SystemInstance | jobs P7 |
| 同:13 | SystemTask | jobs P7 |
| 同:14 | SystemTaskLock | jobs P7 |
| task/register_migrations.go:9 | Midjourney | jobs P6/P7 |
| 同:10 | Task | jobs P6/P7 |
| usage/register_migrations.go:9,15 | Log，主库与日志库分别验 | usage P4/P7 |
| 同:10 | QuotaData | usage P4/P7 |
| 同:11 | UserInsightProfile | usage P7 |
| 同:12 | UserInsightSample | usage P7 |
| 同:13 | UserInsightClientBan | usage P7 |
| egress/store_proxy_node.go:137 | ProxyNode | catalog持久化，integrations经端口 P3/P7 |
| mailer/quota_usage.go:22–27 | SMTPQuotaUsage，override smtp_quota_usage | usage持久化，integrations经配额端口 P7 |
| usage/record_perf.go:195,231–232 | PerfMetric，显式TableName函数需核对返回值 | usage P7 |

## 4. 迁移顺序与动态 SQL

【事实】`dbinfra/open_db.go:195–229` 固定阶段：token model_limits→text → PG旧prefill唯一约束 → CollapseRouteUnitGroups → 注册AutoMigrate → RunPostMigrations → RunSQLMigrations → DropLegacySchedulingColumns。注册列表内顺序见上述路径；**跨包init的最终总序尚未冻结**，不能把文档按域排列当执行顺序。Actions需导出 dbx.Migrations、LogMigrations及后置回调执行轨迹；同一次启动不同数据库分支分别记录。

【事实】`sql_migrations.go:47–51` 原生 schema_migrations：version varchar(255) PRIMARY KEY；applied_at bigint NOT NULL。文件名排序，每文件事务执行SQL后记账；header过滤不匹配与 Timescale gate关闭不记账。`common/database.go:8` 的 PG枚举是 `postgres`（不是解析器注释中的postgresql）。

【事实】001_drop_unused_log_indexes.sql 只适用 postgres/sqlite：删除 idx_logs_request_id、idx_logs_upstream_request_id、idx_logs_ip、idx_logs_group、idx_logs_token_name、idx_logs_token_id；均 IF EXISTS。002仅postgres：检查extension、hypertable、public.logs和created_at；主键(id)改(created_at,id)，新增idx_logs_id；create_hypertable chunk=86400，migrate_data=true；定义 logs_created_at_now() 并 set_integer_now_func。

【推断/待验证】002的DO块可RETURN而事务仍成功记账，因此“账本已应用”不证明成功转换；必须同时断言实际hypertable。AutoMigrate可能重建001已删除索引，而账本阻止001重跑，重复启动后的DDL必须比对。不得仅断言迁移返回nil。

【事实】日志库 `open_db.go:232–247` 非ClickHouse走logMigrationModels→setupTimescaleLogHypertable，不是调用同一版本SQL runner；主/独立日志库不能共用一份schema验收。ClickHouse原生 logs（273–299）：id Int64；user_id/type/quota/prompt_tokens/completion_tokens/use_time/channel_id/token_id Int32；created_at Int64；is_stream UInt8；content/username/token_name/model_name/group/ip/request_id/upstream_request_id/other String；数字默认0、字符串默认空。MergeTree按toYYYYMM(toDateTime(created_at))分区，ORDER BY(created_at,request_id)，这不是关系型唯一主键。TTL动态表达式及MODIFY/REMOVE见258–315。

| 动态/原生目标 | 证据事实 | 所有权/阶段；待验证 |
|---|---|---|
| channels、channel_model_routes | common/dbx/migrate_priority_weight.go:88,104 | catalog P8；字段回填与权重转换 |
| 动态 ALTER TABLE / DROP INDEX | 同:212,263 | storage执行/catalog拥有 P8；枚举table/column/index参数来源白名单，尚未闭环 |
| channel_model_routes | common/dbx/migrate_route_unit_group.go:70,91,97 | catalog P8；删重复记录、更新保留行、旧索引移除 |
| logs / schema_migrations / logs_created_at_now函数 / Timescale chunks | 上述SQL及timescale_log.go | usage/storage P7/P8；压缩、保留策略、扩展内部表不当成业务实体 |
| tokens / users / options 的表绑定DTO | dbinfra/forward_identity.go、identity/query_users.go、egress/read_option.go | identity/config P1/P2/P4；不是新增实体 |

【待验证】全仓库（含modules/relaykit、db/archive）的 Table(expr)、Raw/Exec、Migrator、CREATE/ALTER 参数来源清单尚未封闭。只扫描注册点不能证明无额外业务表；不能据此宣布P0完成。

## 6. 本轮新增42模型逐字段登记

以下为源码结构声明事实，不是运行DDL。简记：PK=primaryKey（旧式primary_key另注）；AI=autoIncrement；NN=not null；U=uniqueIndex；I=index；D=default；V(n)=type:varchar(n)；S(n)=size:n；B=bigint；T=type:text；J=type:json；省略标签=∅。同一斜线组内各字段分别拥有相同类型/标签，不代表一个复合字段。列名除显式column外仍按默认命名待核。所有权、R/W与阶段逐模型见data-jobs §2及本文件§3。

### 身份与策略（11）

- **ExternalIdentityClaim** `identity/claim_external_identity.go:22–28`：Id int64[PK]；Provider string[V(32),NN,U:idx_external_identity_subject priority1,U:idx_external_identity_user priority1]；Subject string[V(128),NN,U:idx_external_identity_subject priority2]；UserId int[NN,I,U:idx_external_identity_user priority2]；CreatedAt time.Time。两组唯一约束分别约束外部主体与用户；回填冲突不能静默覆盖。
- **PasskeyCredential** `identity/passkey_credential.go:23–42`：ID int[PK]；UserID int[U,NN]；CredentialID string[V(512),U,NN]；PublicKey string[T,NN]；AttestationType string[V(255)]；AAGUID string[V(512)]；SignCount uint32[D:0]；CloneWarning/UserPresent/UserVerified/BackupEligible/BackupState bool；Transports string[T]；Attachment string[V(32)]；LastUsedAt *time.Time；CreatedAt/UpdatedAt time.Time；DeletedAt gorm.DeletedAt[I]。CredentialID/PublicKey/AAGUID源码注释为base64；用户唯一及软删除后重注册需实测，不能改成无限凭证。
- **TwoFA** `identity/store_twofa.go:15–26`：Id int[PK]；UserId int[unique,NN,I]；Secret string[V(255),NN,json隐藏]；IsEnabled bool；FailedAttempts int[D:0]；LockedUntil/LastUsedAt *time.Time；CreatedAt/UpdatedAt time.Time；DeletedAt gorm.DeletedAt[I]。密文格式与密钥轮换须追加密函数及fixture，不因json隐藏就宣称加密验收。
- **TwoFABackupCode** 同文件29–37：Id int[PK]；UserId int[NN,I]；CodeHash string[V(255),NN,json隐藏]；IsUsed bool；UsedAt *time.Time；CreatedAt time.Time；DeletedAt gorm.DeletedAt[I]。无声明码唯一约束，单次消费须事务验证。
- **CustomOAuthProvider** `identity/resolve_oauth_provider.go:41–68`：Id int[PK]；Name string[V(64),NN]；Slug string[V(64),U,NN]；Icon string[V(128),D:'']；Enabled bool[D:false]；ClientId string[V(256)]；ClientSecret string[V(512),json隐藏]；AuthorizationEndpoint/TokenEndpoint/UserInfoEndpoint string[V(512)]；Scopes string[V(256),D:'openid profile email']；UserIdField/UsernameField/DisplayNameField/EmailField string[V(128)，默认依次'sub'/'preferred_username'/'name'/'email']；WellKnown string[V(512)]；AuthStyle int[D:0]；AccessPolicy string[T]；AccessDeniedMessage string[V(512)]；CreatedAt/UpdatedAt time.Time。AccessPolicy内容JSON不等于SQL JSON；秘密存储、发现URL与SSRF另验。
- **UserOAuthBinding** `identity/bind_oauth.go:12–18`：Id int[PK]；UserId int[NN,U:ux_user_provider]；ProviderId int[NN,U:ux_user_provider,U:ux_provider_userid]；ProviderUserId string[V(256),NN,U:ux_provider_userid]；CreatedAt time.Time。标签没有声明外键。
- **CasbinRule** `identity/policy/casbin_rule.go:3–12`：Id uint[PK,AI]；Ptype/V0/V1/V2/V3/V4/V5 string[S(100)]，按此顺序分别拥有I:idx_casbin_rule与U:idx_casbin_rule_unique，priority依次1至7。表override casbin_rule；空串/NULL去重与策略加载另验。
- **AuthzRole** `identity/policy/authz_role.go:3–13`：Id uint[PK,AI]；Key string[S(64),U,NN]；Name string[S(100),NN]；Description string[T]；BuiltIn/Enabled bool；Sort int；CreatedAt int64[autoCreateTime,column:created_at]；UpdatedAt int64[autoUpdateTime,column:updated_at]。
- **QQBinding** `identity/qq_binding.go:16–23`：Id int[PK,AI]；UserId int[NN,U:idx_qq_binding_user]；OpenID string[V(128),NN,U:idx_qq_binding_openid]；UnionOpenID string[V(128)]；Username string[V(64)]；CreatedAt int64[B]。
- **QQBindCode** 同30–37：Id int[PK,AI]；Code string[V(16),NN,U:idx_qq_bind_code]；UserId int[NN,I]；ExpiredAt int64[B,I]；Used bool[D:false]；CreatedAt int64[B]。
- **QQUnbindRecord** 同44–48：UserId int64[PK]；UnbindAt int64[B,NN]；CreatedAt int64[B]。注意UserId这里为int64且无autoIncrement:false，实际自增需验，不能沿用QQBinding的主键策略。

### 目录（4）

- **ChannelModelHealth** `catalog/health_unit_store.go:22–57`：ChannelId int[PK]；KeyIndex int[PK,NN,D:0]；Model string[PK,S(255)]；State string[S(16),NN,D:healthy]；IsolationLevel int[NN,D:0]；Until *int64[B]；Version int[NN,D:1]；DormantDisableCount/LocalFailureCount/UpstreamFailureCount int[NN,D:0]；LastErrorCode string[S(64)]；LastErrorAt/LastSuccessAt *int64[B]；EwmaScore float64[NN,D:1]；LatencyEwmaMs float64[NN,D:0]；LatencyUpdatedAtMs int64[NN,D:0]；RequestCount/UnauthorizedRun int[NN,D:0]；RampExited/RampPending bool[NN,D:false]；CooldownStreak/ThrottleStreak int[NN,D:0]；CooldownUntilMs/ScoreUpdatedAtMs/AnnealSinceMs int64[NN,D:0]；LastCoolingOutcome int[NN,D:-1]；DisableStreak int[NN,D:0]；UpdatedAt int64[B]。旧Until秒与新*Ms毫秒不可统一单位；复合主键迁移和过期条件另验。
- **Model** `catalog/store_model_meta.go:25–46`：Id int；ModelName string[S(128),NN,U:uk_model_name_delete_at priority1]；Description string[T]；Icon string[V(128)]；Tags string[V(255)]；VendorID int[I]；Endpoints string[T]；Status/SyncOfficial int[D:1]；CreatedTime/UpdatedTime int64[B]；DeletedAt gorm.DeletedAt[I,U:uk_model_name_delete_at priority2]；NameRule int[D:0]。忽略字段：BoundChannels []BoundChannel、EnableGroups []string、QuotaTypes []int、MatchedModels []string、MatchedCount int均[-]。唯一键含可空deleted_at，不能直接认定活跃名称唯一。
- **PrefillGroup** `catalog/store_prefill_group.go:76–85`：Id int；Name string[S(64),NN,U:uk_prefill_name where:deleted_at IS NULL]；Type string[S(32),I,NN]；Items JSONValue[J]；Description string[V(255)]；CreatedTime/UpdatedTime int64[B]；DeletedAt gorm.DeletedAt[I]。部分唯一索引PG/SQLite必须导出DDL验证；MySQL差异仅历史参考，不迁移；JSONValue的Scan/Value边界仍待fixture。
- **Vendor** `catalog/store_vendor_meta.go:16–25`：Id int；Name string[S(128),NN,U:uk_vendor_name_delete_at priority1]；Description string[T]；Icon string[V(128)]；Status int[D:1]；CreatedTime/UpdatedTime int64[B]；DeletedAt gorm.DeletedAt[I,U:uk_vendor_name_delete_at priority2]。

### 账务与QQ经济（13）

- **Redemption** `billing/store_redemption.go:19–33`：Id/UserId int；Key string[type:char(32),U]；Status int[D:1]；Name string[I]；Quota int[D:100]；QuotaDisplay float64[-]；RedeemedTime/CreatedTime int64[B]；UsedUserId int；Count int[-:all]；DeletedAt gorm.DeletedAt[I]；ExpiredTime int64[B]。0永不过期来自注释，不是默认约束；兑换锁及软删key复用待验。
- **TopUp** `billing/store_topup.go:18–29`：Id int；UserId int[I]；Amount int64；Money float64；TradeNo string[unique,V(255),I]；PaymentMethod string[V(50)]；PaymentProvider string[V(50),D:'']；CreateTime/CompleteTime int64；Status string。Amount整数与Money浮点不可互换；TradeNo不是仅普通索引。
- **Checkin** `billing/store_checkin.go:18–24`：Id int[PK,AI]；UserId int[NN,U:idx_user_checkin_date]；CheckinDate string[V(10),NN,U:idx_user_checkin_date]；QuotaAwarded int[NN]；CreatedAt int64[B]。日期字符串YYYY-MM-DD，时区与唯一冲突后的余额回滚待验。
- **SubscriptionPlan** `billing/store_subscription.go:104–155`：Id int；Title string[V(128),NN]；Subtitle string[V(255),D:'']；PriceAmount float64[type:decimal(10,6),NN,D:0]；Currency string[V(8),NN,D:'USD']；DurationUnit string[V(16),NN,D:'month']；DurationValue int[type:int,NN,D:1]；CustomSeconds int64[type:bigint,NN,D:0]；Enabled bool[D:true]；SortOrder int[type:int,D:0]；AllowBalancePay/AllowWalletOverflow *bool；StripePriceId/CreemProductId/WaffoPancakeProductId string[V(128),D:'']；MaxPurchasePerUser int[type:int,D:0]；UpgradeGroup/DowngradeGroup string[V(64),D:'']；TotalAmount int64[type:bigint,NN,D:0]；TotalAmountDisplay/BalanceCostDisplay float64[-]；QuotaResetPeriod string[V(16),D:'never']；QuotaResetCustomSeconds int64[type:bigint,D:0]；CreatedAt/UpdatedAt int64[B]。NormalizeDefaults将两个nil布尔转true（182–188），不是SQL default；免费权益购买次数校验见208–217。
- **SubscriptionOrder** 同221–235：Id int；UserId/PlanId int[I]；Money float64；TradeNo string[unique,V(255),I]；PaymentMethod string[V(50)]；PaymentProvider string[V(50),D:'']；Status string；CreateTime/CompleteTime int64；ProviderPayload string[T]。支付原始载荷需秘密与保留期处理。
- **UserSubscription** 同249–282：Id int；UserId int[I,I:idx_user_sub_active priority1]；PlanId int[I]；AmountTotal/AmountUsed int64[type:bigint,NN,D:0]；AmountTotalDisplay/AmountUsedDisplay float64[-]；StartTime int64[B]；EndTime int64[B,I,I:idx_user_sub_active priority3]；Status string[V(32),I,I:idx_user_sub_active priority2]；Source string[V(32),D:'order']；LastResetTime int64[type:bigint,D:0]；NextResetTime int64[type:bigint,D:0,I]；UpgradeGroup/PrevUserGroup/DowngradeGroup string[V(64),D:'']；AllowWalletOverflow bool；CreatedAt/UpdatedAt int64[B]。BeforeCreate/BeforeUpdate赋Unix时间，AfterFind填展示值（284–299），不能遗漏hook。
- **SubscriptionPreConsumeRecord** 同976–985：Id int；RequestId string[V(64),U]；UserId/UserSubscriptionId int[I]；PreConsumed int64[type:bigint,NN,D:0]；Status string[V(32),I]；CreatedAt int64[B]；UpdatedAt int64[B,I]。RequestId幂等范围、退款状态转移待验。
- **QQCheckin** `billing/qq_checkin.go:18–26`：Id int[PK,AI]；UserId int[NN,U:idx_qq_user_checkin_date]；CheckinDate string[V(10),NN,U:idx_qq_user_checkin_date]；QuotaAwarded int[NN]；OpenID/GroupOpenID string[V(128)]；CreatedAt int64[B]。
- **QQDrop** `billing/qq_drop.go:17–25`：Id int[PK,AI]；UserId int[NN,I:idx_qq_drop_user_date priority1]；DropDate string[V(10),NN,I:idx_qq_drop_user_date priority2]；QuotaAwarded int[NN]；OpenID/GroupOpenID string[V(128)]；CreatedAt int64[B,I]。与签到不同，此复合索引不是unique。
- **QQTransfer** `billing/qq_transfer.go:18–33`：Id int[PK,AI]；FromUserId int[NN,I:idx_qq_transfer_from_date priority1]；ToUserId int[NN,I:idx_qq_transfer_to_date priority1]；TransferDate string[V(10),NN,前述两个索引priority2]；Amount/Fee/Received int[NN]；FromOpenID/ToOpenID/GroupOpenID string[V(128)]；CreatedAt int64[B,I]。Received=Amount-Fee是源码注释语义，不是SQL CHECK。
- **QQRedPacket** `billing/qq_redpacket.go:30–49`：Id int[PK,AI]；SenderUserId int[NN,I:idx_qq_rp_sender_date priority1]；SendDate string[V(10),NN,I:idx_qq_rp_sender_date priority2]；GroupOpenID string[V(128),I]；SenderOpenID/Blessing string[V(128)]；TotalAmount/TotalCount/RemainingAmount/RemainingCount int[NN]；Status int[NN,D:1,I]；ExpireAt/CreatedAt int64[B,I]。
- **QQRedPacketGrab** 同59–68：Id int[PK,AI]；PacketId/UserId int[NN,U:idx_qq_rp_grab_unique priority分别1/2]；OpenID string[V(128)]；Amount int[NN]；IsLuckic bool[column:is_luckiest,D:false]；CreatedAt int64[B,I]。Go拼写IsLuckic不是SQL is_luckic。
- **QQSteal** `billing/qq_steal.go:22–40`：Id int[PK,AI]；ThiefUserId int[NN,I:idx_qq_steal_thief_date priority1]；VictimUserId int[NN,I:idx_qq_steal_victim_date priority1]；StealDate string[V(10),NN,前述两个索引priority2]；Amount int[NN]；Success bool[NN]；Reason string[V(64)]；ThiefOpenID/VictimOpenID/GroupOpenID string[V(128)]；CreatedAt int64[B,I]。

### 系统与集成（6）

- **dbinfra.Setup** `dbinfra/read_setup.go:13–17`：ID uint[PK]；Version string[V(50),NN,D:legacy-unknown]；InitializedAt int64[type:bigint,NN,D:0]。ops.Setup是响应DTO，不计第二张表。
- **SystemInstance** `ops/store_system_instance.go:18–25`：NodeName string[V(128),PK]；Info string[T]；StartedAt/LastSeenAt/CreatedAt/UpdatedAt int64[B,I]。
- **SystemTask** `ops/store_system_task.go:30–43`：ID int64[primary_key]；TaskID string[V(64),U]；Type string[V(64),I]；Status SystemTaskStatus[V(32),I]；ActiveKey *string[V(64),U]；Payload/State/Result/Error string[T]；LockedBy string[V(128),I]；CreatedAt/UpdatedAt int64[B,I]。NULL ActiveKey允许多行的SQLite/PostgreSQL两目标库一致性及完成时清空必须测。
- **SystemTaskLock** 同45–51：Type string[V(64),PK]；TaskID string[V(64),I]；LockedBy string[V(128),I]；LockedUntil/UpdatedAt int64[B,I]。类型级锁而非每task_id主键；续租与回收需竞争fixture。
- **ProxyNode** `egress/store_proxy_node.go:15–30`：ID uint[PK]；Name string[NN,I]；Enabled bool；EncryptedProxyConfig string[T,NN,json隐藏]；Protocol string[S(32),I]；ScopeType string[S(16),NN,I:idx_proxy_node_scope priority1]；ScopeValue string[S(128),I:idx_proxy_node_scope priority2]；Health float64；FailureCount int；CooldownUntil *time.Time；LastError string[T]；LastProbeAt *time.Time；CreatedAt/UpdatedAt time.Time。密文算法/旧密钥解密未验，字段名本身不证明格式兼容。
- **SMTPQuotaUsage** `mailer/quota_usage.go:15–20`：Account/Day string[PK,column分别account/day]；Used int[column:used]；UpdatedAt time.Time[column:updated_at]。日配额复合主键，跨天与失败邮件配额恢复需验。

### 异步任务（2）

- **Midjourney** `task/store_midjourney_record.go:7–33`：Id/Code int；UserId int[I]；Action string[V(40),I]；MjId string[I]；Prompt/PromptEn/Description/State string；SubmitTime/StartTime/FinishTime int64[I]；ImageUrl/VideoUrl/VideoUrls string；Status string[V(20),I]；Progress string[V(30),I]；FailReason string；ChannelId/Quota int；Buttons/Properties string；TokenId/BillingChannelId int[D:0,json隐藏]。字符串JSON载荷不自动改SQL类型；MjId未声明unique。
- **Task** `task/store_task.go:49–71`：ID int64[primary_key;AUTO_INCREMENT]；CreatedAt int64[I]；UpdatedAt int64；TaskID string[V(191),I]；Platform constant.TaskPlatform[V(30),I]；UserId int[I]；Group string[V(50)]；ChannelId int[I]；Quota int；Action string[V(40),I]；Status TaskStatus[V(20),I]；FailReason string；SubmitTime/StartTime/FinishTime int64[I]；Progress string[V(20),I]；Properties Properties[J]；Username string[-]；PrivateData TaskPrivateData[column:private_data,J,json隐藏]；Data json.RawMessage[J]。Properties/TaskPrivateData的嵌套成员与Scan/Value需进一步差分fixture，不能向用户暴露PrivateData；TaskID不是唯一键。

### 用量与画像（6）

- **Log** `usage/store_log.go:63–92`：Id int[I:idx_created_at_id priority2,I:idx_user_id_id priority2]；UserId int[I,I:idx_user_id_id priority1]；CreatedAt int64[B,NN,I:idx_created_at_id priority1,I:idx_created_at_type]；Type int[I:idx_created_at_type]；Content string；Username string[I,I:index_username_model_name priority2,D:'']；TokenName string[D:'']；ModelName string[I,I:index_username_model_name priority1,D:'']；Quota/PromptTokens/CompletionTokens/UseTime int[D:0]；QuotaDisplay float64[-]；IsStream bool；ChannelId int[I,json:channel]；ChannelName string[->]；TokenId int[D:0]；Group string；Ip string[D:'']；RequestId string[V(64),D:'']；UpstreamRequestId string[V(128),D:'']；Other string。**ChannelName的->是只读权限，不是-忽略迁移**；关系库是否创建此列必须导出schema，ClickHouse原生DDL无此列。主库注册不能证明实际日志写入主库。
- **QuotaData** `usage/store_usedata.go:14–32`：Id int；UserID int[I]；Username string[I:idx_qdt_model_user_name priority2,S(64),D:'']；ModelName string[同索引priority1,S(64),D:'']；CreatedAt int64[B,I:idx_qdt_created_at priority2]；UseGroup string[I,S(64),D:'']；TokenID/ChannelID int[I,D:0]；NodeName string[I,S(64),D:'']；TokenUsed/Count/Quota int[D:0]；QuotaDisplay float64[-]。未声明聚合维度唯一约束。
- **PerfMetric** `usage/record_perf.go:181–193`：Id int[PK]；ModelName string[S(128),U:idx_perf_model_group_bucket priority1]；Group string[column:group,S(64),同U priority2]；BucketTs int64[同U priority3,I:idx_perf_bucket_ts]；RequestCount/SuccessCount/TotalLatencyMs/TtftSumMs/TtftCount/OutputTokens/GenerationMs int64[D:0,json隐藏]。秒桶与毫秒累计单位分别核对，json隐藏不代表不持久化。
- **UserInsightProfile** `usage/user_insight.go:19–78`：UserId int[PK,autoIncrement:false]；Username string[S(64),I,D:'']；FirstSeenAt int64[B,D:0]；LastSeenAt int64[B,I,D:0]；下列各自int[D:0]：TotalRequests、CodeRequests、RoleplayRequests、QARequests、TranslateRequests、EmbeddingRequests、OtherRequests、FrontendScoreSum、BackendScoreSum、InfraRequests、MobileRequests、DataRequests、MaleGuessRequests、FemaleGuessRequests、MaleSelfReportRequests、FemaleSelfReportRequests、MalePreferenceRequests、FemalePreferenceRequests、AIFemaleRequests、AIMaleRequests、JailbreakSuspect、JailbreakLikely、JailbreakConfirmed、JailbreakMaxScore、RelayRequests；LastJailbreakAt int64[B,D:0]；ClientsJSON/RelayVendorsJSON/JailbreakTagsJSON/LanguagesJSON string[T]。推测、自述、偏好计数不可合并；JSON为text，画像隐私与删除传播待验。
- **UserInsightSample** `usage/user_insight_sample.go:17–64`：Id int64[PK]；UserId int[I:idx_insight_sample_user priority1]；Username string[S(64),D:'']；CreatedAt int64[B,I:idx_insight_sample_user priority2,I:idx_insight_sample_created]；RequestId string[S(64),D:'']；ModelName/Path string[S(128),D:'']；Category string[S(32),D:'']；Client string[S(64),D:'']；ClientVersion string[S(32),D:'']；IsRelay bool[I]；RelayVendor string[S(32),D:'']；RiskLevel string[S(16),I,D:'']；JailbreakScore int[D:0]；GuessGender/GenderBasis string[S(16),D:'']；EvidenceJSON/Body string[T]；BodySize int[D:0]；Fingerprint string[S(32),I:idx_insight_sample_fp priority2,D:'']；HitCount int[D:1]；LastSeenAt int64[B,D:0]；ByteSize int[D:0]；Priority int[I,D:0]。Fingerprint不是unique；原始Body有敏感内容，禁止上传真实fixture。
- **UserInsightClientBan** `usage/user_insight_client_ban.go:28–32`：UserId int[PK,autoIncrement:false]；Client string[S(64),PK]；CreatedAt int64[B,D:0]。用户+客户端复合主键，封禁缓存失效待验。

以上42项仅字段、标签静态登记完成；显式/默认表名、实际列约束、嵌套JSON序列化、密文fixture、升级和重复迁移六类证据保持未验收。没有用源码标签伪造数据库执行结果。

## 5. 远程验收交付

仅由集成者获授权后在 GitHub Actions 固定上游SHA：SQLite/PostgreSQL两目标库空库迁移并导出表/列/索引/约束；导出注册顺序；脱敏旧schema升级及连续两次启动对比；主日志共库/分库分别覆盖；ClickHouse/Timescale独立矩阵等待范围批准。断言 ignore 字段没有落库、金额整数/decimal无漂移、NULL/软删除唯一性及迁移前后行数/校验和。结果必须绑定集成SHA、run ID、数据库版本/镜像摘要、退出码和测试/跳过数；独立verification复核前本清单保持未验收。未运行任何本地验证。
