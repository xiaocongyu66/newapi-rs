# P0 options / env 可核对增量清单

2026-11-02；进行中、未验收。基线 `17970da4571e81308f176a0e61a38276e5771606`；证据路径相对 `/root/newapi/apps/api/internal/`。与 data-jobs-inventory.md §6 合并阅读；不是全量配置已闭环声明。每个反引号内的键是独立核对项，不能仅验收组名。事实=名称/读取点已找到；目标域和阶段是迁移设计推断；默认值、安全分类与行为未核实者明确待验证。

## 1. 配置加载契约

**最新用户批准范围**：Rust仅支持SQLite+PostgreSQL，不迁移MySQL；旧MySQL配置/测试变量只作历史事实，不要求其CI或最低版本验证。旧表/字段/ID/额度/时间/软删除尽量兼容，差异须记录、不得未经批准有损转换。ClickHouse独立日志和Timescale扩展不自动移除，相关配置继续登记。

**当前DAG归属**：Option/options持久化owner=catalog，config只加载/解析；下表归属指配置语义而非表owner。CasbinRule/AuthzRole存储归identity，security经端口鉴权；Task/Midjourney及任务运行记录归jobs，不新增task crate；ProxyNode持久化归catalog，integrations经端口使用；SMTPQuotaUsage归usage，integrations调用配额端口。源码task/egress/mailer目录不是Rust crate划分。

**已有基线与阶段边界**：ci-baseline.md记录run 41425478831 attempt 1/2，SHA 6e599ec59837d645b4740ebe363790beda6b40f1均success。P0核对集合/字段/归属/测试方案；P1执行SQLxSQLite/PostgreSQL两目标库及加载契约；P4账务；P7任务恢复；P8完整升级演练。后阶段通过不是P0前置条件，原生skip不构成SQLite/PostgreSQL两目标库通过。

【事实】dbinfra/store_options.go:54–77 先 SeedOptionMap，再从DB逐条ApplyOption，读取AllOption错误被忽略，单键Apply错误记录日志，SyncOptions睡眠后重载。Rust P1必须区分DB不可用与空配置（主计划要求），不能把旧吞错当成功fixture。

【事实】settings/config.go:39–87、90–159 通过 `<注册名>.<json标签或Go字段名>` 动态生成键；json为空或`-`回退Go字段名，复杂类型JSON序列化，nil指针写`null`。因此只搜索字符串常量无法获得全集。seed还串联OnSeedCatalogOptions、OnSeedPaymentOptions、OnSeedUsageOptions、OnSeedEgressOptions、OnSeedRatioOptions（settings.go:268–282）。

【待验证】每个键仍需逐项冻结：值类型、默认表达式/最终值、空值/缺失/非法值、秘密遮盖、修改权限、是否即时生效、跨实例同步、环境变量和DB覆盖顺序；配置不能只按名字判断是否含秘密，URL/JSON也可能包含凭据。

## 2. 固定 options 键名事实

本节枚举 settings/settings.go:172–263 的显式种子键，证据行范围亦是下一轮对账边界。该文件的公共变量默认值未全部追溯；除明确空字符串外，默认均【待验证：追 common/领域变量初始化】。所有持久化写入P3，业务生效按下表阶段；config加载器不拥有领域语义。

| 证据行 | 独立键名（事实） | 目标归属/生效阶段 |
|---|---|---|
| 172–175 | `FileUploadPermission` `FileDownloadPermission` `ImageUploadPermission` `ImageDownloadPermission` | security/storage P2/P7 |
| 176–184 | `PasswordLoginEnabled` `PasswordRegisterEnabled` `EmailVerificationEnabled` `GitHubOAuthEnabled` `LinuxDOOAuthEnabled` `TelegramOAuthEnabled` `WeChatAuthEnabled` `TurnstileCheckEnabled` `RegisterEnabled` | identity/security P2/P7 |
| 185–194 | `AutomaticDisableChannelEnabled` `AutomaticEnableChannelEnabled` `LogConsumeEnabled` `DisplayInCurrencyEnabled` `DisplayTokenStatEnabled` `DisplayGroupRatioTable` `DrawingEnabled` `TaskEnabled` `DataExportEnabled` `ChannelDisableThreshold` | catalog/usage/billing/task P3/P4/P6/P7 |
| 195–198 | `EmailDomainRestrictionEnabled` `EmailAliasRestrictionEnabled` `EmailDomainWhitelist` `EmailFormatRegex` | identity P2 |
| 199–208 | `SMTPServer` `SMTPFrom` `SMTPPort` `SMTPAccount` `SMTPToken` `SMTPSSLEnabled` `SMTPStartTLSEnabled` `SMTPInsecureSkipVerify` `SMTPForceAuthLogin` `SMTPAccountPool` | integrations.mail P2/P7；Server/From/Account/Token/Pool种子为空 |
| 209–215 | `Notice` `About` `HomePageContent` `Footer` `SystemName` `Logo` `ServerAddress` | config/ops P1/P3；Notice/About/HomePageContent/ServerAddress种子为空 |
| 216–225 | `PayAddress` `CustomCallbackAddress` `EpayId` `EpayKey` `VmqAddress` `VmqKey` `CodePayAddress` `CodePayId` `CodePayKey` `TopupGroupRatio` | billing P4/P7；除TopupGroupRatio外此处种子为空，但领域hook可覆盖 |
| 226–234 | `GitHubClientId` `GitHubClientSecret` `TelegramBotToken` `TelegramBotName` `WeChatServerAddress` `WeChatServerToken` `WeChatAccountQRCodeImageURL` `TurnstileSiteKey` `TurnstileSecretKey` | integrations/identity/security P2/P7；此处种子全为空 |
| 235–239 | `QuotaForNewUser` `QuotaForInviter` `QuotaForInvitee` `QuotaRemindThreshold` `PreConsumedQuota` | billing P4（P2注册不得临时无账务赋值） |
| 240–243 | `ModelRequestRateLimitCount` `ModelRequestRateLimitDurationMinutes` `ModelRequestRateLimitSuccessCount` `ModelRequestRateLimitGroup` | security/relay P2/P5 |
| 244–249 | `TopUpLink` `QuotaPerUnit` `RetryTimes` `DataExportInterval` `DataExportDefaultTime` `DefaultCollapseSidebar` | billing/relay/usage/ops P3/P4/P5/P7 |
| 250–257 | `CheckSensitiveEnabled` `ModelRequestRateLimitEnabled` `CheckSensitiveOnPromptEnabled` `CheckSensitiveOnCompletionEnabled` `StopOnSensitiveEnabled` `SensitiveWords` `SensitiveBlockGroups` `StreamCacheQueueLength` | security/relay P2/P5/P7 |
| 258–263 | `AutomaticDisableStatusCodes` `AutomaticRetryStatusCodes` `proxy_config` `ThemeCustomization` | catalog/relay/egress/ops P3/P5/P7；后两项种子为空，ThemeCustomization常量见settings/theme_customization.go:20 |

【事实但尚未归入种子全集】读点 transport/handler/handle_misc.go:109–110,223 与 middleware/gate_header_nav.go:25 有 `HeaderNavModules`、`SidebarModulesAdmin`、`Midjourney`；要追其写入/废弃迁移，不能因未出现在seed而删掉。Telegram/WeChat存在明确配置键，不再表述为“完全没发现”；真实提供商实现与路由仍待集成台账核验。

## 3. 领域 hook 新增键名事实

| 证据 | 独立键名 | 归属/阶段、待验证 |
|---|---|---|
| billing/register_option_hooks.go:21–65 | `Price` `USDExchangeRate` `MinTopUp` `StripeMinTopUp` `StripeApiSecret` `StripeWebhookSecret` `StripePriceId` `StripeUnitPrice` `StripePromotionCodesEnabled` | billing P4/P7；默认来自同名领域变量 |
| 同 | `CreemApiKey` `CreemProducts` `CreemTestMode` `CreemWebhookSecret` | billing P4/P7 |
| 同 | `WaffoEnabled` `WaffoApiKey` `WaffoPrivateKey` `WaffoPublicCert` `WaffoSandboxPublicCert` `WaffoSandboxApiKey` `WaffoSandboxPrivateKey` `WaffoSandbox` `WaffoMerchantId` `WaffoNotifyUrl` `WaffoReturnUrl` `WaffoSubscriptionReturnUrl` `WaffoCurrency` `WaffoUnitPrice` `WaffoMinTopUp` `WaffoPayMethods` | billing P4/P7；WaffoPayMethods seed为`[]` |
| 同 | `WaffoPancakeMerchantID` `WaffoPancakePrivateKey` `WaffoPancakeReturnURL` `WaffoPancakeStoreID` `WaffoPancakeProductID` `WaffoPancakeUnitPrice` `WaffoPancakeMinTopUp` `PayMethods` | billing P4/P7；ID/URL大小写不能归一化；Vmq/CodePay键在hook重复覆盖 |
| usage/register_option_hooks.go:12–20 | `Chats` `MjNotifyEnabled` `MjAccountFilterEnabled` `MjModeClearEnabled` `MjForwardUrlEnabled` `MjActionCheckSuccessEnabled` | usage/jobs P6/P7 |
| egress/register_option_hooks.go:13–18 | `WorkerUrl` `WorkerValidKey` `WorkerAllowHttpImageRequestEnabled` | integrations.egress P5/P7；WorkerValidKey按秘密处理（推断，待遮盖契约核验） |
| catalog/configure_ratio/register_option_hooks.go:12–25 | `ModelRatio` `ModelPrice` `CacheRatio` `CreateCacheRatio` `GroupRatio` `GroupGroupRatio` `CompletionRatio` `ImageRatio` `AudioRatio` `AudioCompletionRatio` `ExposeRatioEnabled` | catalog配置/billing计费 P3/P4/P6；除末项均通过JSON函数生成默认 |

【待验证】Catalog hook链不能漏：catalog/configure_gateway_dispatch.go:25、configure_route_stats.go:25、manage_channels.go:74、resolve_group.go:255、track_health.go:551 均赋值OnSeedCatalogOptions；逐项审阅是否串联前一个hook并展开每个key，当前未完成。

## 4. 反射键注册组——逐组尚未展开，不算逐键完成

每行均【事实：注册存在；待验证：展开全部导出字段及json标签、默认、校验】。同一组必须形成独立键行后才可验收。

| 注册名 | 证据 | 归属/阶段 |
|---|---|---|
| quota_setting | billing/consume_quota_setting.go:18 | billing P4 |
| checkin_setting | billing/do_checkin_setting.go:40 | billing P4 |
| general_setting | billing/manage_subscription.go:618 | billing P4 |
| payment_setting | billing/pay_subscription.go:46 | billing P4/P7 |
| tool_price_setting | billing/price_expression/price_tools.go:64 | billing P4/P6 |
| qq_bot_setting | billing/qqbot_setting.go:275 | billing/integrations P4/P7 |
| billing_setting | billing/settle_tiered.go:217 | billing P4 |
| group_ratio_setting | catalog/configure_ratio/configure_group_ratio.go:35 | catalog/billing P3/P4 |
| global、claude、gemini、grok、qwen（各自独立） | catalog/manage_models.go:308–312 | catalog/relay P3/P6 |
| channel_affinity_setting | catalog/track_affinity_setting.go:153 | catalog P5 |
| fetch_setting | egress/fetch_url.go:29 | integrations.egress P5/P7 |
| geo_block_setting | geoip/geoip.go:42 | security/geoip P7 |
| token_setting | identity/configure_token_setting.go:17 | identity P2/P3 |
| monitor_setting | ops/configure_monitor_setting.go:30 | jobs/ops P7 |
| discord | security/configure_discord.go:16 | integrations P7 |
| legal | security/configure_legal.go:16 | config/security P1/P3 |
| oidc | security/configure_oidc.go:24 | integrations P7 |
| passkey | security/configure_passkey.go:24 | identity P7 |
| console_setting | usage/configure_perf.go:90 | usage/ops P7 |
| perf_metrics_setting | usage/configure_perf.go:119 | usage P7 |
| performance_setting | usage/configure_perf.go:182 | usage/ops P7 |
| user_insight_setting | usage/user_insight_setting.go:77 | usage P7 |

## 5. env 增量（不重复主台账已列值）

下列名称/调用默认均【事实】，括号中值为读取点fallback，不等于最终有效值；需继续核对后续clamp/覆盖。未给值者明确待验证。归属/阶段为设计推断。

| 独立变量 | 证据 | 默认与归属/阶段 |
|---|---|---|
| SUBSCRIPTION_PLAN_CACHE_TTL / SUBSCRIPTION_PLAN_CACHE_CAP | billing/store_subscription.go:60,68 | 300 / 5000；billing P4 |
| SUBSCRIPTION_PLAN_INFO_CACHE_TTL / SUBSCRIPTION_PLAN_INFO_CACHE_CAP | 同:1635,1642 | 120 / 10000；billing P4 |
| GATEWAY_OUTBOX_PUBLISH_INTERVAL_SECONDS | catalog/publish_gateway_config.go:63 | 1；catalog/jobs P7 |
| NODE_NAME | common/node_identity.go:13 | fallback待验证；jobs P7 |
| PYROSCOPE_URL / PYROSCOPE_APP_NAME | common/pyro.go:11,16 | 空 / new-api；ops P9 |
| PYROSCOPE_BASIC_AUTH_USER / PYROSCOPE_BASIC_AUTH_PASSWORD | 同:17–18 | 空；秘密处理，ops P9 |
| HOSTNAME / PYROSCOPE_MUTEX_RATE / PYROSCOPE_BLOCK_RATE | 同:19–22 | new-api / 5 / 5；ops P9 |
| REDIS_CONN_STRING / REDIS_POOL_SIZE | common/redis.go:25–39 | 空串禁用 / 10；storage P2；URL需脱敏 |
| SESSION_COOKIE_SECURE / SESSION_COOKIE_TRUSTED_URL | common/session_cookie.go:45–46 | trim读取，默认/URL策略待逐分支核验；identity P2 |
| SQL_SLOW_THRESHOLD_MS | dbinfra/log_gorm.go:33 | defaultSlowThresholdMs常量待展开；storage P1 |
| TIMESCALEDB_CHUNK_INTERVAL_SECONDS | dbinfra/timescale_log.go:76 | defaultChunkIntervalSeconds待展开；usage/storage P7/P8 |
| TIMESCALEDB_COMPRESS_AFTER_DAYS / TIMESCALEDB_RETENTION_DAYS | 同:115,137 | 0 / 0；usage P7/P8 |
| GEOIP_DB_URL / GEOIP_DB_PATH | geoip/database.go:46–69 | trim读取，默认路径/URL待验证；integrations P7 |
| DEV_AUTO_LOGIN | identity/dev_autologin.go:26 | false；identity P2；生产禁用与鉴权绕过边界必验 |
| CHANNEL_TEST_FREQUENCY / CHANNEL_TEST_ENABLED | ops/configure_monitor_setting.go:34–42 | env覆盖，默认及非法值待验；jobs P7 |
| SINGBOX_CONTAINER_NAME | ops/manage_proxy.go:624 | fallback待验；egress/ops P7/P9 |
| LINUX_DO_TOKEN_ENDPOINT / LINUX_DO_USER_ENDPOINT | security/oauth/linuxdo.go:52,110 | https://connect.linux.do/oauth2/token / https://connect.linux.do/api/user；integrations P7 |
| FRONTEND_BASE_URL | transport/compose/compose.go:19 | fallback待验；transport P1/P9 |
| SYNC_UPSTREAM_BASE | transport/handler/handle_model_sync.go:40 | https://basellm.github.io/llm-metadata；catalog/integrations P3/P7 |
| SYNC_HTTP_TIMEOUT_SECONDS | 同:93,303,501 | 同一key在不同读点分别默认10、15、15秒，不得擅自统一；catalog P7 |
| SYNC_HTTP_RETRY / SYNC_HTTP_MAX_MB | 同:135,140 | 3 / 10；catalog P7 |
| TRUSTED_PROXIES | transport/middleware/trust_proxies.go:23 | trim读取，空值策略待验；security/transport P2 |

【待验证的动态变量入口】common/totp.go:121 的LookupEnv(key)、common/utils.go:102 的Getenv(envVar)、common/init.go:168 的动态name、relay/channel/ali/adaptor.go:49 的aliAnthropicMessagesModelsEnv，以及transport/handler/handle_upstream_update.go:256的多行调用，需追实参/常量；不能把“搜索Getenv的输出”当全集。还需扫描main、modules、部署/启动脚本和flag/env注入。TEST_MYSQL_DSN/TEST_POSTGRES_DSN属于测试矩阵，不应混入生产配置。

## 6. 本轮反射键与catalog hook展开

本节是源码键登记，非运行验收。反射组前缀+以下每个后缀构成一个独立键；类型据结构体，默认未列者仍待核。DB写入P3，业务阶段沿用§4。

| 组前缀 | 已展开后缀（各自独立）与类型 | 源码 |
|---|---|---|
| quota_setting | enable_free_model_pre_consume bool；empty_response_multiplier float64 | billing/consume_quota_setting.go:5–8 |
| checkin_setting | enabled/single_platform_only/require_qq_bound/show_bind_code_card bool；min_quota/max_quota int | billing/do_checkin_setting.go:11–26 |
| payment_setting | amount_options []int；amount_discount map[int]float64；compliance_confirmed bool；compliance_terms_version/compliance_confirmed_ip string；compliance_confirmed_at int64；compliance_confirmed_by int | billing/pay_subscription.go:25–34 |
| token_setting | max_user_tokens int | identity/configure_token_setting.go:6–8 |
| monitor_setting | auto_test_channel_enabled bool默认false；auto_test_channel_minutes float64默认10；channel_test_mode string默认scheduled_all | ops/configure_monitor_setting.go:9–26 |
| discord | enabled bool；client_id/client_secret string（secret不得导出） | security/configure_discord.go:5–9 |
| legal | user_agreement/privacy_policy string | security/configure_legal.go:5–8 |
| oidc | enabled bool；display_name/client_id/client_secret/well_known/authorization_endpoint/token_endpoint/user_info_endpoint string | security/configure_oidc.go:8–17 |
| fetch_setting | enable_ssrf_protection/allow_private_ip/domain_filter_mode/ip_filter_mode/apply_ip_filter_for_domain bool；domain_list/ip_list/allowed_ports []string | egress/fetch_url.go:5–14 |

以上9组共40个字段键，仅登记名称/类型（2+6+7+1+3+3+2+8+8）；未声称全部注册组或全配置全集。复杂类型仍存options字符串JSON，不创建独立表。

monitor读取覆盖顺序已核：GetMonitorSetting先读取CHANNEL_TEST_FREQUENCY，合法正整数启用测试、设置分钟并强制scheduled_all；随后CHANNEL_TEST_ENABLED若存在且ParseBool成功覆盖enabled，非法值不覆盖；模式只保留auto_ban_only/passive_recovery，其他归scheduled_all（33–53）。因此false可覆盖频率隐式true，不应交换顺序。

catalog/configure_gateway_dispatch.go:24–34和configure_route_stats.go:24–34均捕获previousSeed并先调用，再写自身键，不是丢弃之前hook。新增独立键（值来自各getter/default结构，最终默认和校验待核）：

- gateway dispatch共14键，catalog/relay P3/P5/P7：GatewayDispatchCooldownBaseMs、GatewayDispatchCooldownMaxMs、GatewayDispatchCooldownRampSteps、GatewayDispatchThrottleBaseMs、GatewayDispatchThrottleMaxMs、GatewayDispatchScoreDecayTauMs、GatewayDispatchHealthAlpha、GatewayDispatchHealthMinRequests、GatewayDispatchHealthMinScoreFloor、GatewayRetryTotalBudgetMs、GatewayForwardMaxConcurrency、GatewayChannelMaxConcurrency、EmergencyThreshold、WarningThreshold（configure_gateway_dispatch.go:40–58）。Ms不可误解释为秒；后两键保留历史命名。
- route stats共12键，catalog P3/P5/P7：RouteStatsEnabled、RouteStatsShareWindowSize、RouteStatsShareCorrMin、RouteStatsShareCorrMax、RouteStatsMinSamples、RouteStatsTTLSeconds、RouteStatsTTFTTargetMs、RouteStatsTPSTarget、RouteStatsQualityFloor、RouteStatsQualityCeil、RouteStatsComponentFloor、RouteStatsComponentCeil（configure_route_stats.go:40–55）。

Passkey默认补证（security/configure_passkey.go:13–42）：Enabled=false、RPDisplayName=common.SystemName、RPID/Origins/AttachmentPreference空、AllowInsecureOrigin=false、UserVerification=preferred。getter在RPID空且ServerAddress非空时从URL Host或原地址填充，Origins空或[]时填ServerAddress；这些是读取时变更，不是固定DB默认。反射json键仍须对identity.PasskeySettings声明核对，未计上述40键。

## 8. 固定注册全集与运行时值边界（本轮续补）

生产`settings.GlobalConfig.Register`调用点共26组（全internal检索，排除测试及注释），不是不可穷举集合。§6已展开9组；本节补余17组。注册名固定；map的模型名、用户组、工具名，数组规则实例和OAuth提供商记录是**运行时数据**，不新增注册项、表或后台任务。P0验收容器类型、输入校验和消费者，而非枚举每个可能模型/域名/金额。W统一由catalog持久化options端口，以下owner为语义域；默认及校验运行验证归对应后续阶段。

下表每个后缀与组前缀用点连接，是独立持久化键；JSON嵌套成员不递归生成options键。

| 固定注册组 | 全部顶层后缀 | 证据 / 语义owner与阶段 |
|---|---|---|
| general_setting | docs_link, ping_interval_enabled, ping_interval_seconds, quota_display_type, custom_currency_symbol, custom_currency_exchange_rate, amount_name, amount_unit | billing/manage_subscription.go:588–618，billing/relay P4/P5 |
| tool_price_setting | prices（map[string]float64） | billing/price_expression/price_tools.go:55–64，billing P4/P6 |
| billing_setting | billing_mode, billing_expr（均map[string]string） | billing/settle_tiered.go:206–217，billing P4 |
| group_ratio_setting | group_ratio, group_group_ratio, group_special_usable_group（RWMap及嵌套map） | catalog/configure_ratio/configure_group_ratio.go:17–35，catalog/billing P3/P4 |
| global | pass_through_request_enabled, thinking_model_blacklist, chat_completions_to_responses_policy | catalog/manage_models.go:38–42,308，catalog/relay P3/P6 |
| claude | model_headers_settings, default_max_tokens, thinking_adapter_enabled, thinking_adapter_budget_tokens_percentage | 同58–63,309，catalog/relay P3/P6 |
| gemini | safety_settings, version_settings, supported_imagine_models, thinking_adapter_enabled, thinking_adapter_budget_tokens_percentage, function_call_thought_signature_enabled, remove_function_response_id_enabled | 同87–95,310，catalog/relay P3/P6 |
| grok | violation_deduction_enabled, violation_deduction_amount | 同122–125,311，catalog/billing P4/P6 |
| qwen | sync_image_models | 同138–140,312，catalog/relay P3/P6 |
| channel_affinity_setting | enabled, switch_on_success, keep_on_channel_disabled, max_entries, default_ttl_seconds, rules | catalog/track_affinity_setting.go:30–36,153，catalog P5 |
| geo_block_setting | enabled, allow_admin, blocked_countries | geoip/geoip.go:20–42，security/integrations P7 |
| passkey | enabled, rp_display_name, rp_id, origins, allow_insecure_origin, user_verification, attachment_preference | identity/passkey_settings.go:3–10；security/configure_passkey.go:24，identity P7 |
| console_setting | api_info, uptime_kuma_groups, announcements, faq, api_info_enabled, uptime_kuma_enabled, announcements_enabled, faq_enabled | usage/configure_perf.go:62–90，usage P7 |
| perf_metrics_setting | enabled, flush_interval, bucket_time, retention_days | 同104–119，usage P7 |
| performance_setting | disk_cache_enabled, disk_cache_threshold_mb, disk_cache_max_size_mb, disk_cache_path, monitor_enabled, monitor_cpu_threshold, monitor_memory_threshold, monitor_disk_threshold | 同147–182，storage/usage P7/P9 |
| user_insight_setting | enabled, record_in_log, jailbreak_alert_score, gender_inference_enabled, sample_enabled, sample_rate_percent, sample_keep_body, sample_quota_mb, sample_retention_days, auto_ban_enabled, auto_ban_min_risk, auto_ban_code_ratio_enabled, auto_ban_code_ratio_percent, auto_ban_code_min_requests, client_ban_enabled, blocked_clients | usage/user_insight_setting.go:7–77，usage/security P7 |
| qq_bot_setting | 见下面完整后缀表 | billing/qqbot_setting.go:9–184,275，billing/integrations P4/P7 |

qq_bot_setting全部顶层后缀（同一结构体，不是多注册组）：

- 身份/签到：app_id, app_secret, webhook_path_token, min_quota, max_quota, qq_checkin_enabled, checkin_disabled_groups, web_checkin_enabled, single_platform_only, notify_template, auto_approve_enabled, auto_approve_keyword。
- 掉落：drop_enabled, drop_groups, drop_min_messages, drop_max_messages, drop_min_quota, drop_max_quota, drop_daily_limit, drop_template, drop_balance_anchor, drop_daily_guarantee。
- 转账：transfer_enabled, transfer_disabled_groups, transfer_daily_limit, transfer_min_amount, transfer_max_amount, transfer_fee_brackets。
- 红包：red_packet_enabled, red_packet_disabled_groups, red_packet_daily_limit, red_packet_min_amount, red_packet_max_amount, red_packet_default_count, red_packet_max_count, red_packet_expire_seconds, red_packet_allow_own_grab。
- 冷却/撤回：command_cooldown_seconds, rebind_cooldown_seconds, recall_failed_messages, recall_delay_seconds, recall_policies, admin_open_ids。
- 偷取/诱饵：steal_enabled, steal_success_rate, steal_min_amount, steal_max_amount, steal_daily_limit, steal_recipient_grace_seconds, bait_keyword, bait_strict_match, bait_window_minutes, bait_victim_extra_rate, bait_global_extra_multiplier, bait_drop_max_deny_rate, bait_spam_threshold, bait_spam_penalty_minutes, bait_spam_stack_step, bait_spam_deny_rate, bait_spam_steal_rate。

秘密：app_secret/webhook_path_token及provider/header配置中的凭据不能随配置dump；后台QQ事件/延迟撤回实例数量随流量变化，不增加固定任务类型。rules嵌套结构明确来自ChannelAffinityRule（同文件11–28）：name/model_regex/path_regex/user_agent_include/key_sources/value_regex/ttl_seconds/param_override_template/skip_retry_on_failure/include_using_group/include_model_name/include_rule_name；key_sources成员type/key/path。global.chat_completions_to_responses_policy成员enabled/all_channels/channel_ids/channel_types/model_patterns（manage_models.go:13–19）；均作为一个JSON值管理。

## 7. Actions闭环要求

仅远程Actions：固定SHA枚举seed最终键集合与GlobalConfig反射键集合，和读/写键集合做差集；报告未知/废弃键及所有动态env实参。用脱敏fixture测缺失、空、非法、大小写、别名优先级、热更新及DB故障；敏感值只输出键名/分类，绝不dump真实options或env。每键至少有owner、阶段、默认和测试映射；差集未清零保持P0受阻。提交/推送/触发由获授权集成者操作，本代理未触发；已有Go基线success证据见§1，不把该基线当逐键配置验证。
