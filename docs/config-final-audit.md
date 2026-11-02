# P0 配置具名缺口最终静态核查

2026-11-02。仅新增本文件；只读 `/root/newapi` 源码和 `/root/newapi-rs/docs/config-inventory.md`，未构建、测试、执行脚本、启动服务/容器、提交或推送。范围严格为 data-coverage §6 的配置两项具名入口，以及 config-inventory §8 的26注册组默认/校验/秘密/更新契约。不替其他代理签收SQL、异步任务、Go CI或整个P0。

源码引用以下相对路径均以 `/root/newapi/apps/api/internal/` 为根。既有键清单沿用 `/root/newapi-rs/docs/config-inventory.md` §6/§8；这里补缺失初始化/getter/validator，不重新枚举已核的所有字段。默认指源码初始表达式，不指部署DB覆盖后的最终值。SQLite/PostgreSQL为Rust目标；Option持久化owner=catalog，config只负责解析，语义owner见表。

## 1. 结论与分母

- **关闭：三个catalog init的遗漏种子/链式注册**。共补14个固定键：操作3、分组4、健康7；均先调用previousSeed再覆盖自身键，没有截断上游链。健康桥和identity分组桥是函数注册，不产生新配置键。
- **关闭：ValidateGatewayDispatchOption的14键解析/范围/实际apply语义**。发现NaN接受、重试预算注释与实现不一致及渠道并发延后生效，均明确登记，不以“有validator”推断安全。
- **关闭：四个动态env具名入口**。totp封装无调用者，不虚构env名；utils是固定3名探测；init是固定5名函数实参，不是无限name循环；Ali是固定1名、动态模型模式值。
- **关闭：26/26注册组的初始化表达式、通用解析、HTTP专用校验、secret分类、更新方式静态登记**。没有业务validator也是确定结论，不标成“待继续”。下表“R”不意味着有效业务输入已严格验证。
- **没有声称全仓库seed/read/write差集为零或运行验证通过**。本次有限范围之外的旧显式键、其它env/命令入口仍归集成台账；不以任意用户模型名、规则实例、域名、OpenID的不可穷举性阻塞本范围。

## 2. 所有注册组共享的精确契约

### 2.1 权限、输入与持久化

`transport/compose/register_api.go:298–303`：`/option`使用 **AdminAuth + RequirePermission(policy.SystemSettings)**，不是RootAuth。`ops/manage_options.go:83–112,353–380`把JSON标量转字符串；复杂值应提交JSON字符串，不应假设原生JSON对象会自动正确编码。审计仅记录键名。

本文R表示 `settings/config.go:updateConfigFromMap:163–270`：缺失字段保持当前值；string可写空；bool用ParseBool，非法跳过；int先ParseInt，失败再ParseFloat转int64（可截断小数），float用ParseFloat，无通用finite/range检查；非法解析通常continue且函数返回nil。map新建后解码替换，避免残留旧键；slice/struct直接解码到原字段，不能假定失败时完全无副作用；JSON null可清空map/slice，指针显式null置nil。**R是宽松加载器而非拒绝非法输入的validator**。

`settings/settings.go:116–162`公共ValidateOptionValue只特别处理工具价格、MaxTokenAutoGroups、SMTP池、route stats、gateway dispatch、channel health和theme。HTTP专用规则在`ops/manage_options.go`，不自动覆盖DB重载/其它调用路径。`dbinfra/store_options.go:84–104,112–151`先验证/事务持久化，再Apply；内存apply失败不等于DB回滚，bulk DB事务也不保证所有内存字段原子切换。

### 2.2 热更新定义

下表H表示`settings/settings.go:656–690`按注册前缀定位对象、原位反射更新；getter随后读取新对象字段。并不证明线程安全、在途请求快照一致或已有timer/连接重建。跨实例通过原有SyncOptions重载（既有台账已核），不是同步广播成功保证。特殊路径：工具价格用域loader并原子重建索引；user_insight的blocked_clients经域hook锁；performance经OnPerformanceSettingChanged同步common；billing_setting经OnBillingSettingChanged后处理。`main.go:432`接线performance hook，`catalog/register_group_resolver.go`接线billing缓存更新。Rust P1应采用明确校验和快照发布；业务行为验收在各归属阶段。

### 2.3 秘密与可见性

`ops/store_options.go:27–33,70–108`仅按大小写敏感后缀Token、Secret、Key、secret、api_key排除整键，并非递归脱敏。`discord.client_secret`、`oidc.client_secret`、`qq_bot_setting.app_secret`会被隐藏；**qq_bot_setting.webhook_path_token不匹配这些后缀，会进入可见options**。Claude headers、affinity override、任意URL查询参数/文案内凭据亦不会自动剥离。注册配置导出本身不是安全dump。

下表N=字段语义非凭据，但用户文本/URL仍应避免整值日志；S=明确凭据；P=隐私/敏感策略或可嵌入秘密。Rust P2/P3需显式敏感键及嵌套遮盖策略，不复制后缀缺陷。静态发现已闭合，修复/fixture不是本次编写Rust的理由。

## 3. 三个catalog init与gateway validator

### 3.1 操作种子（catalog/manage_channels.go:11–84）

| 固定键 | 初始值/表达式 | 校验与更新 |
|---|---|---|
| DemoSiteEnabled | false | `value == "true"`，其它字符串均false；直接修改全局 |
| SelfUseModeEnabled | false | 同上，同时写configure_ratio.SelfUseModeEnabled |
| AutomaticDisableKeywords | AutomaticDisableKeywordsToString：7个默认文本以换行连接 | 更新清空旧列表，再逐行trim、lowercase、去空；无拒绝分支 |

7个初始文本依次为`Your credit balance is too low`、`This organization has been disabled.`、`You exceeded your current quota`、`Permission denied`、`The security token included in the request is invalid`、`Operation not allowed`、`Your account is not authorized`。初始列表不是小写，apply后小写；不能只保存最终推断值而丢失表达式。三键非secret，catalog P3/P5。

### 3.2 分组种子（catalog/resolve_group.go:22–115,213–265）

| 固定键 | 初始值 | 校验/热更新 |
|---|---|---|
| DefaultUseAutoGroup | false | 精确字符串true才开启 |
| UserUsableGroups | JSON `{default:"默认分组",vip:"vip分组"}` | mutex内先清空map再Unmarshal；失败可能已改变状态 |
| AutoGroups | JSON `["default"]` | 先清空slice再Unmarshal；非法不是安全保留旧值 |
| MaxTokenAutoGroups | DefaultMaxTokenAutoGroups=5，atomic init | Atoi且>0，成功atomic.Store；拒绝空/非整数/非正 |

init另安装identity.OnGetMaxTokenAutoGroups、OnIsUserSelectableGroup、OnGetUserAutoGroup、OnGetUserUsableGroups、OnDefaultUseAutoGroup。组名/描述是值，不是新增options键。非secret，catalog/identity P2/P3/P5。

### 3.3 健康种子（catalog/track_health.go:526–560,648–681,779–894）

先注册HealthBridge，atomic.Store(DefaultChannelHealthSetting())，安装Is/Validate/Apply三hook，再链式seed。seed明确调用**DefaultChannelHealthSetting**，不是当前getter。

| 固定键 | seed字符串对应值 | Validate范围 |
|---|---|---|
| ChannelHealthEnabled | true | bool解析 |
| ChannelHealthCooldownThreshold | 5 | 整数>=1 |
| ChannelHealthCooldownBaseSeconds | 10 | >=0且<=当前max |
| ChannelHealthCooldownMaxSeconds | 60 | >=0且>=当前base |
| ChannelHealthCooldownMaxEjectionPercent | 50 | 整数[0,100] |
| ChannelHealthCooldownAlpha | `0.30`（fmt %.2f） | float[0,1]比较 |
| ChannelHealthCooldownDisableStreak | 40 | 整数>=0 |

DefaultChannelHealthSetting另含Alpha=.3、MinScore=.05、MinRequests=5，**不是这7个种子之外的隐式option键**。validate依赖已初始化atomic配置，未知键报错；更新CAS只改目标字段，normalize兜底；启用→禁用触发健康状态reset，非普通“不影响存量状态”的更新。Alpha范围比较无显式NaN检查，需在P5 fixture覆盖。所有值非secret；秒单位不可与dispatch的毫秒混同。

### 3.4 Gateway dispatch（catalog/configure_gateway_dispatch.go:40–58,91–263）

默认来自`health_unit.go:134–166`和`gate_concurrency.go:331–350`的live getter；初始如下。

| 固定键 | 初始值 | Validate / Apply |
|---|---|---|
| GatewayDispatchCooldownBaseMs | 300 | Atoi，>=0 |
| GatewayDispatchCooldownMaxMs | 10000 | Atoi，>=0；无base/max联动验证 |
| GatewayDispatchCooldownRampSteps | 12 | Atoi，>=1 |
| GatewayDispatchThrottleBaseMs | 200 | Atoi，>=0 |
| GatewayDispatchThrottleMaxMs | 1000 | Atoi，>=0；无base/max联动验证 |
| GatewayDispatchScoreDecayTauMs | 900000 | Atoi，>=0 |
| GatewayDispatchHealthAlpha | .3 | ParseFloat，(0,1]比较 |
| GatewayDispatchHealthMinRequests | 5 | Atoi，>=0 |
| GatewayDispatchHealthMinScoreFloor | .05 | ParseFloat，[0,1]比较 |
| GatewayRetryTotalBudgetMs | 30000 | 任意Atoi成功值接受，apply钳制[1000,300000] |
| GatewayForwardMaxConcurrency | 0 | Atoi，>=0；0无限；发布并ApplyGlobalConcurrencyLimit |
| GatewayChannelMaxConcurrency | 0 | Atoi，>=0；发布配置，按下一次channel snapshot rebuild取值，已安装池不替换 |
| EmergencyThreshold | 20 | Atoi，[0,100] |
| WarningThreshold | 50 | Atoi，[0,100]；无二者大小联动验证 |

未知key先拒绝；空值/非数字拒绝。Alpha/MinScoreFloor对NaN只有大小比较，故ParseFloat("NaN")可通过，不能宣称finite已校验。预算getter注释说0关闭，但**当前option apply把0变成1000**，迁移契约取实际执行行为并保留该差异。普通健康更新复制并atomic替换参数、不重置unit冷却/streak/EWMA；与ChannelHealthEnabled关停reset区别明确。所有键非secret；catalog/relay P3/P5，传播P7。

### 3.5 独立验证补漏：RouteStats全部12个显式键

`catalog/configure_route_stats.go:19–55`安装Is/Validate/Apply hook并保留previousSeed链；seed来源是`routestats.DefaultRouteStatsSetting()`，**不是live getter**。默认表达式位于`catalog/routestats/setting.go:68–96`，bool按FormatBool、整数按Itoa、float按FormatFloat('f', -1, 64)生成字符串。以下12键不是GlobalConfig第27个注册组；其它RouteStatsSetting内部字段不自动成为options键。

| 固定键 | 默认来源字段 / seed值 | ValidateRouteStatsSettingValue范围 |
|---|---|---|
| RouteStatsEnabled | Enabled / true | 只接受精确小写字符串true或false，不接受1/TRUE |
| RouteStatsShareWindowSize | ShareWindowSize / 200 | Atoi整数[0,100000]；0保留，关闭share correction |
| RouteStatsShareCorrMin | ShareCorrMin / 0.5 | ParseFloat，(0,1] |
| RouteStatsShareCorrMax | ShareCorrMax / 2 | ParseFloat，>=1，无上限 |
| RouteStatsMinSamples | MinSamples / 5 | Atoi整数>=1 |
| RouteStatsTTLSeconds | TTLSeconds / 86400 | Atoi整数>=1，秒 |
| RouteStatsTTFTTargetMs | TTFTTargetMs / 2000 | Atoi整数>=1，毫秒 |
| RouteStatsTPSTarget | TPSTarget / 20 | Atoi整数>=1 |
| RouteStatsQualityFloor | QualityFloor / 0.5 | ParseFloat，[0,1] |
| RouteStatsQualityCeil | QualityCeil / 1.5 | ParseFloat，>=1，无上限 |
| RouteStatsComponentFloor | ComponentFloor / 0.2 | ParseFloat，[0,1] |
| RouteStatsComponentCeil | ComponentCeil / 1.5 | ParseFloat，>=1，无上限 |

校验入口`configure_route_stats.go:82–159`先拒绝未知键；空值、解析失败和上述范围外值报错，未做trim或float→int兼容。六个float键无IsNaN/IsInf检查：NaN均可穿过比较；三个只有>=1下界的Max/Ceil键还接受正无穷，不能写成“必须有限”。

Apply规则（同162–212）：先调用validator，失败不发布；取当前GetRouteStatsSetting（nil才回默认），复制完整结构，仅改命中字段，交给`routestats.SetRouteStatsSetting`。后者（setting.go:116–217）再次复制、normalize整个结构、atomic.Store；不是CAS重试，也没有在此链重置已有统计状态。正常有限合法option值保持不变，ShareWindowSize=0不会被回填200。直接setter/旧内部状态的normalize与option validator不同：负window改0（没有100000上限钳制）；ShareCorrMin非法回.5，ShareCorrMax<1改1；MinSamples<0回5但0保留；TTL<=0回86400；TTFT/TPS<=0回2000/20；两个floor钳制[0,1]，对应ceil低于floor时抬至floor（不是统一抬到1）。normalize还处理内部alpha/tau/weights/caps等字段，但不新增持久化键，且大小比较仍不清除NaN。

结论：12/12默认、校验和apply静态补齐；非secret，catalog配置P3、调度P5、传播P7。热读取由atomic getter取得新配置；并发多键更新是否丢失、统计生命周期及非有限数fixture仍归后续阶段，不声称已运行验证。

## 4. 动态env实参逐项关闭

| 具名入口与证据 | 固定名/默认与边界 | 归属/生效 |
|---|---|---|
| common/totp.go:115–125 getEnvOrDefault | internal内检索只有定义，无调用实参；Get2FAIssuer直接返回SystemName。不能制造TOTP_ISSUER等配置。封装若被调用，LookupEnv存在但空也返回空，缺失才fallback | identity P2；当前无活跃env消费者 |
| common/utils.go:94–105 containerEnvVars循环 | 固定`KUBERNETES_SERVICE_HOST`、`DOCKER_CONTAINER`、`container`；任一非空判定容器，非布尔解析。缺失/空不命中；还存在/proc等其它探测 | config/ops P1/P9；环境探测，不是secret，不新增运行时任意键 |
| common/init.go:140–174 positiveUserSessionEnv | 五个固定调用，见下表；不是用户提供name，也不是无限循环 | identity/config P2；启动加载，无options热更新 |
| relay/channel/ali/adaptor.go:27–53 aliAnthropicMessagesModelsEnv | 固定`ALI_ANTHROPIC_MESSAGES_MODELS`；默认`qwen,deepseek-v4,kimi,glm,minimax-m`；GetEnvOrDefaultString缺失或空回默认，逗号split/trim/lowercase/去空，以Contains匹配规范化模型名，非regex。仅空白或逗号可形成空模式列表 | integrations/relay P6；每次getter读取env，非DB覆盖；模型子串是值而不是env名 |

session固定名：USER_SESSION_ACTIVE_LIMIT=50；USER_SESSION_ISSUANCE_LIMIT=100；USER_SESSION_ISSUANCE_WINDOW_SECONDS=24*60*60=86400；USER_SESSION_REVOKED_RETENTION_DAYS=7；USER_SESSION_HOURLY_ALERT_THRESHOLD=5000（common/constants.go:43–47）。common/env.go:9–18缺失/空/非法整数回fallback，positiveUserSessionEnv再将<=0回fallback；retention days超MaxInt64/86400回7，issuance window大于有效retention秒数则截到后者。无secret。只需要这些有限实参与解析fixture，不需要枚举实际容器地址或模型名。

### 4.1 独立验证补漏：上游模型更新最小检查间隔

固定环境名 **CHANNEL_UPSTREAM_MODEL_UPDATE_MIN_CHECK_INTERVAL_SECONDS**，不是动态键。`transport/handler/handle_upstream_update.go:38`声明默认常量`channelUpstreamModelUpdateMinCheckIntervalSeconds = 300`（秒）；`getUpstreamModelUpdateMinCheckIntervalSeconds:255–264`通过多行`common.GetEnvOrDefault`调用读取，先解析为Go int再转int64，负数回300，**0原样保留**，正数无额外上限钳制。

公共解析契约来自`common/env.go:9–18`：环境名为空或Getenv结果为空（含未设置）直接fallback；否则strconv.Atoi，失败记录SysError并fallback。因此本键缺失、空、非整数、超出平台int范围都回300；没有TrimSpace，带空白整数及小数字符串不是合法整数；负整数先解析成功再由专用getter回300。不要套用positiveUserSessionEnv的<=0规则，否则会错误吞掉合法0。

实际读取点`checkAndPersistChannelUpstreamModelUpdates`（同475–491）：仅`!force`时调用getter；若LastCheckTime>0且`now-LastCheckTime < minInterval`，直接返回(false,0,nil)，不抓取上游。force=true绕过读取与间隔门；等于阈值允许继续。0在时钟正常前进时取消正数最小等待，但若LastCheckTime在未来，负时间差仍满足<0并跳过，不能把0描述为无条件绕过所有检查。通过门后调用collectPendingUpstreamModelChanges并更新LastCheckTime；该配置不是另一个任务调度周期。

结论：该遗漏固定名、300默认、负数/0语义、公共解析和消费点已静态闭合。非secret；config解析P1，catalog/integrations模型更新与jobs调度P3/P7。每次非force检查读取进程env，无DB option覆盖或启动缓存；不要求枚举部署环境实际值。本次只补该env和§3.5的12个RouteStats键，未扩大研究或修改主计划/文档状态。

## 5. 26注册组逐项结论

键后缀沿用主config-inventory §6/§8；下列每行明确覆盖该组全部顶层字段。未列初始化字段按Go零值（bool=false、数值0、string空、slice/map=nil）登记，不把nil与空容器混同。R/H/N/S/P定义见§2；“无专用写校验”是本次读取通用与HTTP完整分派后的结论，不代表业务消费完全不防御。

| # / 注册组 | 默认表达式（按字段） | 输入校验/getter归一化 | secret / 热更新 / owner阶段 |
|---|---|---|---|
| 1 quota_setting | enable_free_model_pre_consume=true；empty_response_multiplier=.1（consume_quota_setting.go:11–23） | R；注释0–1不是写入范围validator | N；H；billing P4 |
| 2 checkin_setting | enabled=false；min_quota=1000；max_quota=10000；single_platform_only=true；require_qq_bound=false；show_bind_code_card=true（do_checkin_setting.go:29–50） | R；HTTP `_display`有限金额转换后存base键；无min<=max统一写校验 | N；H；billing P4 |
| 3 general_setting | docs_link=https://docs.newapi.pro；ping=true/10秒；quota_display_type=USD；custom_currency_symbol空；custom_currency_exchange_rate=1；amount_name空；amount_unit=usd（manage_subscription.go:605–684） | R；AmountUnitEffective仅cny/custom原样，其它usd；custom汇率<=0回1；custom符号空回¤；未知展示类型符号空 | N/URL可能P；H；billing/relay P4/P5 |
| 4 payment_setting | amount_options=[10,20,50,100,200,500]；amount_discount={}；五个compliance字段零值（pay_subscription.go:39–55） | R；HTTP禁止所有payment_setting.compliance_*通用写，专用确认接口；confirmed且版本=v1才有效 | IP/by为P，不是凭据；H；billing P4/P7 |
| 5 tool_price_setting | prices=make(map)，即{}；有效索引另合并hardcoded 9条，不把fallback写作DB默认（price_tools.go:29–65） | ValidateToolPricesJSON要求JSON object、每值有限非负数字；0有效。历史loader忽略非法条目，整个非法回空覆盖；最长模型前缀优先、命中0终止 | N；专用loader+atomic index重建；billing P4/P6 |
| 6 qq_bot_setting | 见§5.1，qqbot_setting.go:194–281 | R，无组级业务写validator；GetQQBotSetting同步identity重绑冷却；空模板读时回默认，红包expire<=0回86400 | app_secret/webhook_path_token=S；admin/group OpenID=P；H；billing/integrations P4/P7 |
| 7 billing_setting | billing_mode={}；billing_expr={}（settle_tiered.go:211–253） | R；未配置model mode回BillingModeRatio；expr getter返回(value,exists)。写路径无表达式编译校验，不把JSON解码等同计费语义验证 | N；H+OnBillingSettingChanged；billing P4 |
| 8 group_ratio_setting | 三个指针分别指向空RWMap；special默认{}（configure_group_ratio.go:11–43） | R指针JSON；special nil由getter重建，另两指针无此getter修复。旧显式GroupRatio的CheckGroupRatio拒绝负值，但不能推断点号group_ratio同样走该HTTP分支。GetGroupRatio缺项回1；group-group缺项(-1,false) | N；H，别名指针/旧键共存；catalog/billing P3/P4 |
| 9 global | passthrough=false；blacklist=[moonshotai/kimi-k2-thinking,kimi-k2-thinking]；policy={enabled:false,all_channels:true}，其余nil（manage_models.go:44–56） | R；无policy专用写validator；IsChannelEnabled先enabled，再all，再正ID/type成员匹配；模型黑名单trim精确匹配 | N；H；catalog/relay P3/P6 |
| 10 claude | headers={}；default_max_tokens={default:8192}；thinking=true；percentage=.8（同65–74） | R；HTTP tokens必须非null JSON map[string]int且各>=0；getter缺default补8192。headers写入请求时trim、拆逗号、去重；percentage无范围写校验 | headers可嵌S且旧可见接口不遮盖；H；catalog/relay P3/P6 |
| 11 gemini | safety={default:OFF}；version={default:v1beta,gemini-1.0-pro:v1}；supported_imagine_models=源码97–118的7项静态slice；thinking=false/.6；function_call_thought_signature=true；remove_function_response_id=true | HTTP safety要求非null字符串map，空threshold允许；非空限OFF/BLOCK_NONE/BLOCK_ONLY_HIGH/BLOCK_MEDIUM_AND_ABOVE/BLOCK_LOW_AND_ABOVE/HARM_BLOCK_THRESHOLD_UNSPECIFIED。读按类别非空→default非空→OFF；version按存在性回default；其余R | N；H；catalog/relay P3/P6 |
| 12 grok | violation_deduction_enabled=true；amount=.05（同127–135） | R；无金额范围专用写校验 | N；H；catalog/billing P4/P6 |
| 13 qwen | sync_image_models=defaultQwenSettings.SyncImageModels（同142–154），10项：z-image,qwen-image,wan2.6,wan2.7,qwen-image-edit,qwen-image-edit-max,qwen-image-edit-max-2026-01-16,qwen-image-edit-plus,qwen-image-edit-plus-2025-12-15,qwen-image-edit-plus-2025-10-30 | R；IsSyncImageModel用Contains，不是严格枚举/前缀 | N；H；catalog/relay P3/P6 |
| 14 channel_affinity_setting | enabled=true；switch_on_success=true；keep_on_channel_disabled=false；max_entries=100000；ttl=3600；rules=track_affinity_setting.go:118–149两条codex/claude trace（见§5.2） | R；无通用入口regex/ttl/模板业务validator；getter原样返回，不能宣称写时已编译正则 | override可能S；H只证明配置可见，已有cache条目失效不是同步保证；catalog P5 |
| 15 fetch_setting | ssrf=true；private=false；domain/ip白名单模式=false；domain/ip list=[]；ports=[80,443,8080,8443]；apply_ip_filter_for_domain=true（fetch_url.go:16–34） | R；写时无CIDR/port/URL专用validator。消费者egress/build_client.go:67、fetch_file.go:32调用common.ValidateURLWithFetchSetting，须区别请求校验和配置写校验 | N/内部网络策略P；H；integrations/security P5/P7 |
| 16 geo_block_setting | enabled=false；allow_admin=true；countries=[CN]（geoip.go:35–64） | R；NormalizedBlockedCountries trim/uppercase/去空去重；HTTP启用时EnsureFreshForEnable失败拒绝，不保证country输入合法ISO代码 | N；H；security/integrations P7 |
| 17 token_setting | max_user_tokens=1000（configure_token_setting.go:11–27） | R；GetMaxUserTokens原样返回，无正数写校验 | N；H；identity P2/P3 |
| 18 monitor_setting | false/10/scheduled_all；沿用已核ops/configure_monitor_setting.go:9–53 | R；CHANNEL_TEST_FREQUENCY合法正整数先启用/设分钟/scheduled_all；CHANNEL_TEST_ENABLED合法bool随后覆盖enabled；模式只保留auto_ban_only/passive_recovery，其余scheduled_all | N；H但env getter优先；jobs/ops P7 |
| 19 discord | DiscordSettings{}：false/空client_id/空client_secret（configure_discord.go:12–20） | R；HTTP启用只检查ClientId非空，错误提示提Secret不等于代码验证了Secret | client_secret=S，旧接口隐藏；H；integrations P7 |
| 20 legal | agreement/privacy空（configure_legal.go:10–20） | R字符串，无专用内容validator | N/任意文本P；H；config/security P1/P3 |
| 21 oidc | OIDCSettings{}：enabled=false，其余7字符串空（configure_oidc.go:20–39） | R；HTTP启用仅ClientId；GetEffectiveDisplayName trim后空回OIDC；无通用endpoint URL写validator | client_secret=S，endpoint URL可能P；H；integrations P7 |
| 22 passkey | false；rp_display_name=common.SystemName；rp_id/origins/attachment空；allow_insecure_origin=false；user_verification=preferred；沿用已核configure_passkey.go:13–42 | R，无HTTP专用分支；getter空RPID从ServerAddress URL Host或原串派生，Origins空或[]填ServerAddress；这是getter变更而非固定持久化值 | N/信任策略P；H，认证时语义验收归identity P7 |
| 23 console_setting | 4内容字符串空；4enabled=true（configure_perf.go:74–95） | R+HTTP ValidateConsoleSettings，空可清除，具体边界见§5.3；内容string中的JSON不作为递归options键 | URL/文本可能P；H；usage P7 |
| 24 perf_metrics_setting | enabled=true；flush_interval=5；bucket_time=hour；retention_days=0（同111–144） | R；GetBucketSeconds minute=60/5min=300/hour或其它=3600；GetFlushIntervalMinutes最小1（单位分钟） | N；H但既有timer重建不由反射保证；usage P7 |
| 25 performance_setting | disk_cache=false/10MB/1024MB/path空；monitor=true/CPU90/memory90/disk95（同168–213） | R；无百分比/目录专用写validator；path空语义系统临时目录 | 路径P；H+syncToCommon；storage/usage P7/P9 |
| 26 user_insight_setting | true/record=true/alert70/gender=true/sample=true/rate5/keep_body=false/quota1024MB/retention30/auto_ban=false/risk=confirmed/code_ratio=false/percent60/min_requests20；client_ban=false、blocked_clients=nil（user_insight_setting.go:58–82） | R；getter alert非法回70；quota<=0回1024且上限4096；rate钳制0–100；risk仅suspect/likely/confirmed否则confirmed；ratio非法回60；min_requests<1回20（85–143） | 画像/原文策略P；H，blocked_clients域hook加锁；usage/security P7 |

### 5.1 QQ全部默认闭合

以下按既有固定后缀表列默认，数值单位不可混同：quota字段为内部额度，steal金额为浮点展示金额。

- app_id/app_secret/webhook_path_token空；min_quota=375000、max_quota=750000、qq_checkin_enabled=false、checkin_disabled_groups空；web_checkin_enabled=true、single_platform_only=true；notify_template=DefaultNotifyTemplate（“签到成功！获得 {货币} {金额}”）；auto_approve_enabled=false、auto_approve_keyword空。
- drop_enabled=false、drop_groups空、min/max_messages=5/30、min/max_quota=150000/1500000、daily_limit=3；drop_template=DefaultDropTemplate（qqbot_setting.go:192静态文案）；balance_anchor/daily_guarantee=0。
- transfer_enabled=false、disabled_groups空、daily_limit=2、min/max_amount=50000/50000000、fee_brackets空。
- red_packet_enabled=false、disabled_groups空、daily_limit=3、min/max_amount=500000/100000000、default/max_count=5/50、expire_seconds=24*3600、allow_own_grab=false。
- command_cooldown_seconds=0、rebind_cooldown_seconds=3600、recall_failed_messages=false、recall_delay_seconds=10、recall_policies/admin_open_ids空。
- steal_enabled=false、success_rate=50、min/max_amount=.1/.5、daily_limit=3、recipient_grace_seconds=0。
- bait_keyword=杰瑞、strict_match=false、window_minutes=30、victim_extra_rate/global_extra_multiplier/drop_max_deny_rate=0；spam_threshold=0、spam_penalty_minutes=10、spam_stack_step/spam_deny_rate/spam_steal_rate=0。

Getter只返回配置或局部fallback，不是统一验证整个奖励/费率/概率关系。用户输入费率JSON、QQ群和OpenID字符串由业务消费，均为值容器，不新增组。P4验金额/守恒，P7验事件/重绑/撤回与凭据遮盖；这不再是P0初始化未知。

### 5.2 模型/工具/affinity静态容器边界

工具fallback九项（不新增键）：web_search=10、web_search_preview=10、file_search=2.5、google_search=14、image_generation=150；web_search_preview对gpt-4o*、gpt-4.1*、gpt-4o-mini*、gpt-4.1-mini*均25（美元/千次）。operator map覆盖有效索引，动态工具名/model prefix只是prices成员。

Gemini七项初始模型为gemini-2.0-flash-exp-image-generation、gemini-2.0-flash-exp、gemini-3-pro-image-preview、gemini-3-pro-image、gemini-2.5-flash-image、gemini-3.1-flash-image、gemini-3.1-flash-image-preview。

Affinity两规则：codex模型`^gpt-.*$`、路径`/v1/responses`、gjson prompt_cache_key；claude模型`^claude-.*$`、路径`/v1/messages`、gjson metadata.user_id。均value_regex空、ttl=0、skip_retry=true、include_group=true、include_rule_name=true、include_model_name零值false、UA=nil；override分别buildCodexPassHeaderTemplate()/buildPassHeaderTemplate(claudeCliPassThroughHeaders)，结构operations=[{mode:pass_headers,value:静态header列表,keep_origin:true}]。header列表精确表达式保留在track_affinity_setting.go:47–109。默认表达式已定位，不把未来用户任意header名当固定options键。

### 5.3 Console四个专用validator

`usage/configure_perf.go:237–515`：空字符串允许；其它按JSON数组解码到[]map，未知settingType报错。未额外显式拒绝JSON null，不能宣称必须非null数组。

- ApiInfo最多50；url/route/description/color必须非空字符串；URL regex+url.Parse，长度UTF-16计数<=500/100/200；color取validColors静态17项；description/route拒绝危险子串。
- Announcements最多100；content和publishDate必填，日期RFC3339；content<=500、字符串extra<=100；type为字符串时限定default/ongoing/success/warning/error，非字符串的可选type未在该分支拒绝。
- FAQ最多100；question/answer非空字符串，<=200/1000。
- UptimeKumaGroups最多20；categoryName非空且唯一，url/slug非空；description非字符串回空；长度<=50/500/100/200；slug匹配字母数字下划线连字符；categoryName/description危险子串检查。

这些HTTP校验不自动执行于直接DB导入。URL验证也不是凭据剥离或完整SSRF审计。

## 6. 精确的未执行项与后续归属（不是无限P0前置）

| 已知差异/未取得证据 | 具体原因/入口 | 后续owner与阶段 |
|---|---|---|
| 非法输入持久化成功但runtime保持/部分改变 | UpdateConfigFromMap吞解析错误；DB事务在Apply前完成；不是“所有26组都有严格validator” | config/catalog P1解析与发布契约；对应业务阶段fixture |
| NaN、float转int、null指针、base/max及min/max关系 | Gateway/health大小比较、R宽松解析和无统一跨字段validator；静态已定性，未运行样例 | config P1；catalog P5；billing P4 |
| webhook_path_token及嵌套header凭据可见 | settingIsSensitiveOptionKey后缀规则不足；不读取真实值，不输出配置dump | security/identity/catalog P2/P3；integrations P7 |
| 在途读并发、跨实例及时性、timer/缓存/池状态 | H只改对象；channel并发池有明确延后规则，未执行压力/恢复实验 | catalog/relay P5、jobs/usage P7、ops P9 |
| passkey最终RPID/origin、QQ最终账号、用户map实际成员 | 来自部署DB/env/ServerAddress或业务数据，静态源码不包含这些值；不是缺失固定键 | 部署脱敏fixture，identity/integrations P7；不要求枚举生产秘密 |
| 全仓库最终seed/read/write差集 | 本文件只对data-coverage具名配置入口与26注册组负责，既有config-inventory §2/§5更广范围不在本轮重审；没有执行固定SHA导出 | 集成P0静态差集签收；远程P1加载契约，不以本文件宣称整仓完成 |

交付可据此关闭data-coverage §6配置两行及“26组默认/校验未逐项核”这一有限缺口；其它行保持原责任代理结论。源码缺陷的静态登记完成不等于修复，未来运行fixture未执行不等于本次仍需无限枚举。整个P0是否通过由集成与独立验证签收决定。
