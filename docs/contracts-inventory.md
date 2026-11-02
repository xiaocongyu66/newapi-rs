# P0 HTTP、前端与 relay 契约逐项台账

## 基线、范围与证据等级

- 用户最新确认的目标主库仅为 **SQLite + PostgreSQL**，尽量兼容原 schema；**MySQL 不支持、不迁移，不纳入目标实现或验收矩阵**。下文 Go 源码/CI 中 MySQL 仅保留为历史事实，不构成待补迁移或验收项。此范围更新不改变既有基线结果，也不宣称两库兼容已验收。

- 参考基线：`17970da4571e81308f176a0e61a38276e5771606`；只读源码根 `/root/newapi`。本文件属于 `/root/newapi-rs-p0-contracts`，不改变主计划。
- 状态：**进行中，P0 验收受阻**。下列是注册源码级逐项清单，不是行为验收。没有运行本地构建、测试、服务、容器或生成脚本，没有 Rust 实现，没有提交或推送。
- 已阅读全文：compose 的全部生产注册文件（api/authz/channels/dashboard/dev/relay/video/web/compose），以及 Fiber 路径合并/中间件作用域、static fallback、relay 工厂与适配器接口。前端通过源码检索建立调用位置映射；检索命中不等于调用行为已验证。
- 第 2–3 节共 **389 条显式 method/path 注册**：生产 388 条、dev 条件注册 1 条；另列 4 条静态/fallback 行为规则（不是四个 endpoint）。MJ 的 `/mj` 与 `/:mode/mj` 两套挂载分别展开。已按固定源码和四份快照人工逐项核对，生产集合无发现缺项/多项，每行都有阶段归属；未执行机器差集或运行测试。计数、条件、别名及 HEAD/OPTIONS 证据见 [routes-coverage.md](routes-coverage.md)。
- 行号是**注册点**，不是 handler 定义点。表内源文件代号及前端代号均在本文定义；所有源位置以基线为准。
- 所有条目迁移状态统一为 **未开始**（包括已有 Go handler 返回 NotImplemented 的条目）；表中阶段是计划归属，不表示阶段已启动。台账整理状态与实现状态分开。
- 公共配置五条路由的 handler/settings/DB/前端补录见 [public-config-contracts.md](public-config-contracts.md)；初始化、登录、刷新补录见下节。补录仅是源码事实与推导，不代表运行验收；未读依赖仍明确待验证。
- 除上述明确补录字段外，每条 HTTP 项目的未冻结字段统一为 **待核查**：请求字段/默认值、返回字段/类型、成功与失败状态码、响应头、分页边界、国际化、Cookie/CORS 细节、上传上限、流帧/取消语义、handler 内部权限/签名与幂等。表中 `—` 前端列表示**待核查/尚未定位调用**，不表示无消费者。

## 0. P0 身份字段与错误分支补录（源码级）

状态仍为进行中/P0 受阻/P2 未开始。以下 **事实** 表示已读取函数源，**推断** 表示静态推导，**待验证** 表示必须远程 Actions 验证。路径前缀 B=`/root/newapi/apps/api/internal/`，W=`/root/newapi/apps/web/src/`。中间件错误不是下列 handler 错误的子集，仍须独立补齐。公共配置详见同目录 `public-config-contracts.md`。

### 0.1 GET /api/setup 与 POST /api/setup

**事实**（B/ops/configure_system.go:22–53）：GET 无 handler 输入字段，返回 HTTP 200 `{success:true,data:{status:boolean,root_init:boolean,database_type:string}}`，没有 message。status 为 constant.Setup；已完成时另两字段仍输出 false/空串，未完成才查询 RootUserExists 并填 MainDatabaseType。RootUserExists 的 DB 失败处理尚未追踪，不能据此承诺可靠区分未初始化/DB 异常。

**事实**（同文件:28–34,55–103）：POST JSON 字段精确为 username/password/confirmPassword:string、SelfUseModeEnabled/DemoSiteEnabled:boolean；缺字段 Go 零值是空串/false。已初始化先返回；rootExists 在 BindJSON 前查询。只有无 root 时校验 username 的 `len > 12`（Go 字节长度，不是 Unicode 字符数），密码不一致、password 字节长度 <8；此 handler 无 username 非空校验。已有 root 时跳过三项校验。

**事实**（同文件:55–188）：以下分支全部 HTTP 200，失败为 `{success:false,message:string}`，无 data/code：

| 条件 | message 原文 | 行号 |
|---|---|---|
| constant.Setup 已真；或事务计数>0 | 系统已经初始化完成 | 57–63、168–173 |
| JSON 绑定失败 | 请求参数有误 | 68–75 |
| 无 root 且 username 太长 | 用户名长度不能超过12个字符 | 79–85 |
| 无 root 且两次密码不同 | 两次输入的密码不一致 | 88–94 |
| 无 root 且密码太短 | 密码长度至少为8个字符 | 96–102 |
| 保存 SelfUseModeEnabled 失败 | 保存自用模式设置失败: + err.Error() | 111–117 |
| 保存 DemoSiteEnabled 失败 | 保存演示站点模式设置失败: + err.Error() | 120–126 |
| setup 事务其他失败（含哈希/创建） | 创建管理员账号失败: + setupErr.Error() | 133–180 |
| 成功 | success:true，message:系统初始化成功 | 183–188 |

**事实**（同文件:105–167）：两个模式先赋内存，再分别 UpdateOption，位于 root/setup 事务之外；setup 事务检查记录数、插入 ID=1/version/Unix initialized_at，再按需创建 root（display_name Root User、quota 100000000、AccessToken nil、root role/enabled status）。**推断**：后续失败不能回滚前面模式更新；并发重复键错误可能落“创建管理员账号失败”而非“系统已经初始化完成”。不同数据库的并发结论 **待验证**，不能仅依据注释宣称通过。

**事实**（W/features/setup/api.ts:23–58）：GET 带 t=Date.now()（handler 不消费）；POST 原样发送 payload；rootInitialized=true 时 buildSetupPayload 仅输出两个模式 bool，usageMode self/demo 决定各值。UI 表单额外限制及完整初始化持久化模型 **待核查**。

### 0.2 POST /api/user/login

**事实**（B/identity/manage_users.go:29–112）：JSON username/password 为 string，默认空串，任一空即失败；不在此 handler trim。前端 W/features/auth/api.ts:43–54 在 query 传 turnstile（默认空串），body 只含两字段，skipAuthRefresh=true；Turnstile 中间件具体拒绝仍待核查。

**事实**：B/common/transport.go:53–82 的 CtxApiError/CtxApiErrorI18n 都返回 HTTP 200 `{success:false,message:string}`，无 data/code。登录前置失败列表如下，message 是国际化键的翻译，不可冻结成单一中文：

| 条件 | 键/来源 | manage_users.go 行号 |
|---|---|---|
| PasswordLoginEnabled=false | MsgUserPasswordLoginDisabled | 40–42 |
| 绑定失败/空输入 | MsgInvalidParams | 45–54 |
| ValidateAndFill 返回 ErrDatabase | MsgDatabaseError | 60–65 |
| ValidateAndFill 返回 ErrUserEmptyCredentials | MsgInvalidParams | 66–67 |
| ValidateAndFill 其他错误 | MsgUserUsernameOrPasswordError | 68–71 |
| IsTwoFAEnabled 查询失败 | MsgDatabaseError | 75–79 |
| 2FA payload marshal/AuthFlow 创建失败 | err.Error() | 83–96 |

**事实**（同文件:81–108）：启用 2FA 时返回 HTTP 200 `{success:true,message:<MsgUserRequire2FA 翻译>,data:{require_2fa:true,flow_token:string,expires_at:int64 Unix秒}}`，期限 now+5分钟；不是完整登录 bundle，不在本分支写 refresh cookie。后续 `/login/2fa` handler 尚未闭环。

**事实**（同文件:157–206）：非 2FA 经 SetupLogin；nil/非法 ID/禁用用户返回 MsgAuthUserBanned；GetUserById 错误为 HTTP 200 err.Error()；创建会话错误走下文 auth 错误映射。成功更新 last-login、写 Cookie、no-store、记录成功登录审计，再返回 HTTP 200 `{success:true,message:"",data:{access_token:string,token_type:string,access_expires_at:int64,session:object,user:object}}`。token_type 固定 Bearer（B/identity/authenticate.go:337–343）。

**事实**（B/identity/authenticate.go:24–41）：session 字段 sid/login_method/ip/user_agent:string、current:boolean、created_at/last_active_at/expires_at:int64。refresh_token 被 json:"-" 排除，仅经 Cookie 输出。

**事实**（B/identity/manage_users.go:526–560）：user 不是单纯 User 模型序列化，字段全集为 id、username、display_name、role、status、email、github_id、discord_id、oidc_id、wechat_id、telegram_id、group、quota、quota_display、used_quota、used_quota_display、request_count、aff_code、aff_count、aff_quota、aff_quota_display、aff_history_quota_display、aff_history_quota、inviter_id、linux_do_id、setting、stripe_customer、sidebar_modules、permissions。permissions 追加 admin_permissions；:564–588 中 sidebar_settings:boolean，sidebar_modules 按角色为对象（普通用户 admin:false，管理员 admin.setting 为权限 bool，root 空对象）。**待核查**：user 模型逐字段类型、display 金额格式、设置解析默认值、policy.Capabilities 结构，不将只读到字段名误报成完整 schema。

### 0.3 POST /api/user/auth/refresh

**事实**（B/identity/manage_sessions.go:16–44）：无 JSON body 绑定；读 Cookie new_api_refresh 和可选 X-Auth-Session，以及 IP/UA。先设 Cache-Control:no-store。Cookie 不存在/空时清 Cookie，返回 AuthSessionError。成功重新写 Cookie，HTTP 200 success:true/message:""，data 字段与上述 bundle 一致，user 为当前用户。前端 W/lib/auth-session.ts:274–312 body=undefined，仅有期望 SID 才附 header。

**事实**（B/identity/authenticate.go:199–258,359–367）：refresh token trim 后必须为 UUID sid + 一个点 + 非空 secret，secret 不能含点。期望 SID trim 后非空且不同返回 mismatch；会话缓存错误（inactive→revoked，其他→invalid）；非 active/已撤销/过期→revoked；用户缓存或 DB 查询错误直接传播；禁用或 AuthVersion 不匹配尝试撤销并返回 revoked。轮换 reuse→revoked、invalid→invalid、race→race；若 race 返回的 hash 恰为推导的 next hash 则允许重新签发成功。其余存储/签发错误原样传到错误映射。底层轮换事务、replay window 值与并发重放矩阵 **待验证**。

**事实**（B/identity/authenticate.go:386–404；manage_sessions.go:163–179）：统一错误 JSON `{success:false,code:string,message:http.StatusText(status)}`，无 data；gorm.ErrRecordNotFound 特判 401/AUTH_UNAUTHORIZED；其他映射如下。映射表是通用函数的完整分支，不代表 refresh 必然可达每个分支。

| 错误 | HTTP/code |
|---|---|
| ErrUserSessionLimit | 409 / AUTH_SESSION_LIMIT |
| ErrUserSessionIssuanceLimit | 429 / AUTH_SESSION_ISSUANCE_LIMIT |
| ErrLoginSessionMismatch | 409 / AUTH_SESSION_MISMATCH |
| ErrRefreshRace | 409 / AUTH_REFRESH_RACE |
| ErrAuthTokenExpired | 401 / AUTH_TOKEN_EXPIRED |
| ErrLoginSessionRevoked | 401 / AUTH_SESSION_REVOKED |
| ErrRefreshTokenInvalid、ErrAuthTokenInvalid | 401 / AUTH_UNAUTHORIZED |
| 其余（包括未显式匹配的 ErrLoginSessionInvalid） | 500 / AUTH_INTERNAL_ERROR |

**事实**（manage_sessions.go:18–29）：只有缺/空 Cookie、refresh invalid、session revoked 会在此 handler 清 Cookie；mismatch/race/一般内部错误不清。**事实**（authenticate.go:290–323）：Cookie Path=/api/user/auth，HttpOnly=true，Secure=common.SessionCookieSecure，SameSite=Strict，无显式 Domain；Expires 优先会话未来过期时刻，否则 now+LoginSessionTTL，MaxAge 向秒取整且至少1；清除为 value 空串、MaxAge=-1、Expires=Unix(1,0)。TTL 配置、代理影响 Secure 和 OriginGuard 拒绝分支仍 **待核查**。

**事实**（W/lib/auth-session.ts:250–268,315–340）：401 清认证并同步；网络无状态/5xx/429 保持 transient；其他不符合预期响应 out_of_sync；浏览器 navigator.locks 串行 refresh，refreshPromise 合并当前请求。此前 409 race/mismatch 的恢复状态机尚未阅读全文，不能把上述片段当完整前端协议。

### 0.4 远程验证与未覆盖项

全部 **待验证**：Actions 固定 Go SHA 后测试 setup 的已完成/root已存在/缺字段/多字节用户名/模式写失败/并发；login 的禁用/畸形 JSON/错误凭据/DB失败/2FA/bundle；refresh 的缺 Cookie/过期/撤销/用户禁用与版本变化/mismatch/replay/race/DB错误，逐项校验状态、字段类型、国际化、Set-Cookie/no-store。SQLite/PostgreSQL 两库事务与竞争分别报告；保留 run ID、SHA、命令、退出码、数量/跳过数和脱敏 artifacts。当前没有执行证据，不签 PASS。

仍未闭环：ValidateAndFill/密码算法、CreateLoginSession 全链、2FA完成、注册/验证码/重置、退出与撤销、用户字段类型、初始化 RootUserExists、全部身份中间件拒绝、JWT/Redis/TTL 配置、前端完整登录状态接纳。原注册台账这些项继续未开始，不能因本补录改成已完成。

## 1. 路径、权限与中间件字典

源文件代号（相对于 `/root/newapi/apps/api/internal/transport/compose/`）：A=`register_api.go`，C=`register_channels.go`，Z=`register_authz.go`，D=`register_dashboard.go`，R=`register_relay.go`，V=`register_video.go`，DEV=`register_dev_autologin.go`，W=`register_web.go`，ROOT=`compose.go`。

前端位置相对于 `/root/newapi/apps/web/src/`。短名如 `auth:47` 指 `features/auth/api.ts:47`；`keys`、`profile`、`channels`、`models`、`wallet`、`subscriptions`、`users`、`setup`、`pricing`、`rankings`、`about`、`home`、`legal`、`dashboard`、`performance-metrics`、`usage-logs`、`user-insights`、`system-info`、`system-settings`、`redemption-codes` 同理。特殊短名：`lib`=`lib/api.ts`；`pk`=`features/auth/passkey/api.ts`；`proxy`=`features/proxy/proxy-node-api.ts`；`custom-oauth`=`features/system-settings/auth/custom-oauth/api.ts`；`affinity`=`features/system-settings/general/channel-affinity/api.ts`；`pancake`=`features/system-settings/integrations/waffo-pancake-api.ts`；`route-units`=`features/system-settings/models/api-route-units.ts`；`upstream`=`features/channels/hooks/use-channel-upstream-updates.ts`。动态 URL 按注册模板对应，保留客户端尾斜线差异待差分验证。

权限：N=注册链无认证（**不代表 handler 不校验**）；U=UserAuth；A=AdminAuth；ROOT=RootAuth；T=TokenAuth；TR=TokenAuthReadOnly；TU=TokenOrUserAuth；TRY=TryUserAuth；SS=RequirePermission(SystemSettings)；NAV(p)=HeaderNavModuleAuth(p)；NAVPU(p)=HeaderNavModulePublicOrUserAuth(p)。权限源 `/root/newapi/apps/api/internal/security/authenticate.go:44,77,91,97,103,222,240,271,344`；Origin guard 源 `authorize_origin.go:18`。U/A/ROOT 非简单 Cookie 存在判断，校验用户状态/角色并含管理写审计；TRY 遇非法凭证也可失败。

中间件链代号（每条路由必须叠加其组链及该行额外项）：

| 链/额外项 | 顺序及注册源 | 迁移阶段 | 状态 |
|---|---|---|---|
| G | main.go:201–222 recovery、可信代理配置、RequestId、Version、I18n、GeoBlock、logger | P1/P2 | 未开始 |
| API | G + RouteTag(api)、UseCompression、BodyStorageCleanup、GlobalAPIRateLimit（A:20–24） | P1/P2 | 未开始 |
| RELAY | G + UseCORS、DecompressRequestMiddleware、BodyStorageCleanup、StatsMiddleware（R:15–18）；只影响此后注册的路由 | P5 | 未开始 |
| CORE | RELAY + RouteTag(relay)、SystemPerformanceCheck、T、ModelRequestRateLimit、UserInsight、InsightClientBan、Distribute（R:70–88） | P5/P7 | 未开始 |
| MODELS | RELAY + RouteTag(relay)、T（R:20–59） | P5/P6 | 未开始 |
| PG | RELAY + RouteTag(relay)、SystemPerformanceCheck、U、Distribute（R:63–68） | P5 | 未开始 |
| MJ-image | RELAY + RouteTag(relay)、SystemPerformanceCheck；image 在 T/Distribute 前注册（R:175–182,210–211） | P6 | 未开始 |
| MJ | MJ-image + T、Distribute（R:211） | P6 | 未开始 |
| SUNO | RELAY + RouteTag(relay)、SystemPerformanceCheck、T、Distribute（R:184–191） | P6 | 未开始 |
| GEMINI | RELAY + RouteTag(relay)、SystemPerformanceCheck、T、ModelRequestRateLimit、UserInsight、InsightClientBan、Distribute（R:193–205） | P6/P7 | 未开始 |
| VIDEO | RELAY + RouteTag(relay)、T、Distribute（V:21–23）；无 CORE 的组级性能/模型限流/insight 链 | P6 | 未开始 |
| VIDEO-content | RELAY + RouteTag(relay)、TU（V:14–18） | P6 | 未开始 |
| KLING | RELAY + RouteTag(relay)、KlingRequestConvert、T、Distribute（V:36–38） | P6 | 未开始 |
| JIMENG | RELAY + RouteTag(relay)、JimengRequestConvert、T、Distribute（V:47–49） | P6 | 未开始 |
| OLD | G + RouteTag(old_api)、UseCompression、GlobalAPIRateLimit、T（D:12–16）；注册早于 RELAY | P4 | 未开始 |
| WEB | RELAY 引擎现有链 + UseCompression、GlobalWebRateLimit、Cache（W:13–17），静态与 fallback 原生层行为待核查 | P1/P9 | 未开始 |
| B | AnonymousRequestBodyLimit（A:25） | P1/P2 | 未开始 |
| CR / UCR(x) | CriticalRateLimit / UserCriticalRateLimit(x) | P2 | 未开始 |
| SR / EV | SearchRateLimit / EmailVerificationRateLimit | P2 | 未开始 |
| NC / TS | DisableCache / TurnstileCheck | P1/P2 | 未开始 |
| OG / SV | SessionCookieOriginGuard / SecureVerificationRequired | P2 | 未开始 |
| PC | billing.RequirePaymentComplianceMiddleware（A:179） | P4/P7 | 未开始 |
| LOG-token | API + log 组后加 UseCORS、CR，只影响 /api/log/token（A:58–61） | P2/P7 | 未开始 |
| USAGE-token | API + UseCORS、CR、TR（A:375–382） | P2/P4 | 未开始 |

Fiber `/root/newapi/apps/api/internal/transport/fiberadapter/router.go:190–215` 保留相对路径尾斜线；Group 创建时拷贝链、Use 只影响后续注册，不能把晚加的 middleware 倒灌到先前路由。Rust 的 layer/route_layer 装配必须用测试显式证明此行为。全局 gzip 不得压住 SSE（main.go:216–217）。

### 1.1 中间件实现定位补录

下面每个实现均为独立待迁移项目；阶段继承上表，状态均未开始。路径根为 `/root/newapi/apps/api/internal/transport/middleware/`。仅函数定位与注册链已确认，阈值/Redis语义/完整响应仍待核查。

| 函数 | 实现文件:行 |
|---|---|
| RequestId | assign_request_id.go:9 |
| Version | set_version_header.go:8 |
| I18n | negotiate_locale.go:13 |
| GeoBlock | geo_block.go:85 |
| SetUpLogger | log_request.go:19 |
| RouteTag | log_request.go:12 |
| Cache | cache_response.go:28 |
| DisableCache | disable_cache.go:5 |
| SystemPerformanceCheck | check_performance.go:14 |
| TurnstileCheck | check_turnstile.go:15 |
| BodyStorageCleanup | cleanup_body.go:11 |
| StatsMiddleware | collect_stats.go:16 |
| UserInsight | collect_user_insight.go:22 |
| InsightClientBan | insight_client_ban.go:22 |
| DecompressRequestMiddleware | compress_gzip.go:63 |
| JimengRequestConvert | convert_jimeng.go:12 |
| KlingRequestConvert | convert_kling.go:10 |
| Distribute | distribute_channel.go:35 |
| HeaderNavModuleAuth | gate_header_nav.go:105 |
| HeaderNavModulePublicOrUserAuth | gate_header_nav.go:126 |
| AnonymousRequestBodyLimit | limit_body_size.go:11 |
| EmailVerificationRateLimit | limit_email_verification.go:60 |
| ModelRequestRateLimit | limit_model_rate.go:168 |
| GlobalWebRateLimit | limit_rate.go:160 |
| GlobalAPIRateLimit | limit_rate.go:167 |
| CriticalRateLimit | limit_rate.go:174 |
| UserCriticalRateLimit | limit_rate.go:181 |
| SearchRateLimit | limit_rate.go:241 |
| SecureVerificationRequired | verify_secure_action.go:13 |

UseCORS/UseCompression 是 transport adapter 能力而非上述目录函数；实际实现与隐式路由仍需远程契约确认。

## 2. 管理 API 逐项注册

本节默认链 API；权限列额外项以 `+` 顺序排列；源 `A:n`。状态每行均为未开始，详见本文件统一状态声明。

| Method | Path | Handler（Go） | Auth / 额外链 | 源 | 阶段 | 前端调用 |
|---|---|---|---|---|---|---|
| GET | /api/setup | ops.GetSetup | N | A:27 | P2 | setup:24 |
| POST | /api/setup | ops.PostSetup | N+B | A:28 | P2 | setup:36 |
| GET | /api/status | handler.GetStatus | N | A:29 | P2 | lib:71; hooks/use-system-config.ts:121 |
| GET | /api/home_stats | handler.GetHomeStats | N | A:30 | P7 | lib:86 |
| GET | /api/uptime/status | ops.GetUptimeKumaStatus | N | A:31 | P7 | dashboard:90 |
| GET | /api/models | handler.DashboardListModels | U | A:32 | P3 | — |
| GET | /api/status/test | handler.TestStatus | A | A:33 | P2 | — |
| GET | /api/notice | handler.GetNotice | N | A:34 | P1 | lib:97 |
| GET | /api/user-agreement | handler.GetUserAgreement | N | A:35 | P1 | legal:24 |
| GET | /api/privacy-policy | handler.GetPrivacyPolicy | N | A:36 | P1 | legal:29 |
| GET | /api/about | handler.GetAbout | N | A:37 | P1 | about:24 |
| GET | /api/home_page_content | handler.GetHomePageContent | N | A:39 | P1 | home:32 |
| POST | /api/qqbot/webhook | billing.QQBotWebhook | N+B；handler签名 | A:46 | P7 | — |
| POST | /api/qqbot/webhook/*token | billing.QQBotWebhook | N+B；handler签名/路径token | A:47 | P7 | — |
| GET | /api/pricing | handler.GetPricing | NAV(pricing) | A:48 | P3/P4 | pricing:29 |
| GET | /api/log/ | handler.GetAllLogs | A | A:51 | P7 | usage-logs:74 |
| GET | /api/log/stat | handler.GetLogsStat | A | A:52 | P7 | usage-logs:81 |
| GET | /api/log/self/stat | handler.GetLogsSelfStat | U | A:53 | P7 | usage-logs:85 |
| GET | /api/log/channel_affinity_usage_cache | handler.GetChannelAffinityUsageCacheStats | A | A:54 | P7 | affinity:59 |
| GET | /api/log/search | handler.SearchAllLogs | A | A:55 | P7 | — |
| GET | /api/log/self | handler.GetUserLogs | U | A:56 | P7 | usage-logs:78 |
| GET | /api/log/self/search | handler.SearchUserLogs | U+SR | A:57 | P7 | — |
| GET | /api/log/token | handler.GetLogByKey | LOG-token+TR | A:61 | P7 | — |
| GET | /api/data/ | handler.GetAllQuotaDates | A | A:66 | P7 | dashboard:46 |
| GET | /api/data/users | handler.GetQuotaDatesByUser | A | A:67 | P7 | dashboard:63 |
| GET | /api/data/self | handler.GetUserQuotaDates | U | A:68 | P7 | dashboard:46 |
| GET | /api/data/flow | handler.GetAllFlowQuotaDates | A | A:69 | P7 | dashboard:78 |
| GET | /api/data/flow/self | handler.GetUserFlowQuotaDates | U | A:70 | P7 | dashboard:78 |
| GET | /api/rankings | handler.GetRankings | NAV(rankings) | A:73 | P7 | rankings:32 |
| GET | /api/perf-metrics/summary | handler.GetPerfMetricsSummary | NAVPU(pricing) | A:79 | P7 | performance-metrics:26 |
| GET | /api/perf-metrics | handler.GetPerfMetrics | NAVPU(pricing) | A:80 | P7 | performance-metrics:36 |
| GET | /api/performance/stats | usage.GetPerformanceStats | A+SS | A:87 | P7 | features/system-settings/maintenance/performance-section.tsx:217 |
| DELETE | /api/performance/disk_cache | usage.ClearDiskCache | A+SS | A:88 | P7 | features/system-settings/maintenance/performance-section.tsx:254 |
| POST | /api/performance/reset_stats | usage.ResetPerformanceStats | A+SS | A:89 | P7 | features/system-settings/maintenance/performance-section.tsx:266 |
| POST | /api/performance/gc | usage.ForceGC | A+SS | A:90 | P7 | features/system-settings/maintenance/performance-section.tsx:278 |
| GET | /api/performance/logs | usage.GetLogFiles | A+SS | A:91 | P7 | features/system-settings/maintenance/log-settings-section.tsx:169 |
| DELETE | /api/performance/logs | usage.CleanupLogFiles | A+SS | A:92 | P7 | features/system-settings/maintenance/log-settings-section.tsx:316 |
| GET | /api/route_unit/audit | handler.GetRouteUnitAudit | A+SS | A:97 | P7 | — |
| GET | /api/verification | identity.SendEmailVerification | N+EV+TS | A:99 | P2/P7 | auth:191; profile:111 |
| GET | /api/reset_password | identity.SendPasswordResetEmail | N+CR+TS | A:100 | P2/P7 | auth:124 |
| POST | /api/user/reset | identity.ResetPassword | N+CR+B | A:101 | P2 | features/auth/reset-password-confirm/index.tsx:68 |
| POST | /api/oauth/state | handler.GenerateOAuthCode | CR+NC+TRY+B | A:103 | P7 | auth:142 |
| POST | /api/oauth/email/bind | identity.EmailBind | U+CR | A:104 | P7 | profile:122 |
| GET | /api/oauth/wechat | identity.WeChatAuth | N+CR+NC | A:106 | P7 | auth:157 |
| POST | /api/oauth/wechat/bind | identity.WeChatBind | U+CR | A:107 | P7 | profile:134 |
| GET | /api/oauth/telegram/login | identity.TelegramLogin | N+CR+NC | A:108 | P7 | auth:164 |
| POST | /api/oauth/telegram/bind/start | identity.TelegramBindStart | U+CR+NC | A:109 | P7 | profile:150 |
| GET | /api/oauth/telegram/bind/:flow_token | identity.TelegramBind | N+CR+NC | A:110 | P7 | — |
| GET | /api/oauth/:provider | handler.HandleOAuth | CR+NC+TRY | A:112 | P7 | routes/oauth/$provider.tsx:200; features/profile/components/tabs/account-bindings-tab.tsx:247 |
| GET | /api/ratio_config | handler.GetRatioConfig | N+CR | A:113 | P4 | — |
| POST | /api/stripe/webhook | billing.StripeWebhook | N+B；handler校验待核查 | A:115 | P7 | — |
| POST | /api/creem/webhook | billing.CreemWebhook | N+B；handler校验待核查 | A:116 | P7 | — |
| POST | /api/waffo/webhook | billing.WaffoWebhook | N+B；handler校验待核查 | A:117 | P7 | — |
| POST | /api/waffo-pancake/webhook/:env | billing.WaffoPancakeWebhook | N+B；环境/签名待核查 | A:120 | P7 | — |
| POST | /api/verify | identity.UniversalVerify | U+CR+NC | A:123 | P2 | features/auth/secure-verification/api.ts:109 |
| POST | /api/user/auth/refresh | identity.RefreshAuth | N+OG+CR+NC | A:127 | P2 | lib/auth-session.ts:279 |
| POST | /api/user/auth/logout | identity.AuthLogout | N+OG+CR+NC | A:128 | P2 | auth:104 |
| POST | /api/user/register | identity.Register | N+CR+B+TS | A:129 | P2 | auth:180 |
| POST | /api/user/login | identity.Login | N+CR+NC+B+TS | A:130 | P2 | auth:47 |
| POST | /api/user/dev/auto-login | identity.DevAutoLogin | N+CR+NC；仅dev构建 | DEV:15–19 | P2 | lib/dev-auto-login.ts:75 |
| POST | /api/user/login/2fa | identity.Verify2FALogin | N+CR+NC+B | A:134 | P2 | auth:59 |
| POST | /api/user/passkey/login/begin | identity.PasskeyLoginBegin | N+CR+NC+B | A:135 | P7 | pk:75 |
| POST | /api/user/passkey/login/finish | identity.PasskeyLoginFinish | N+CR+NC+B | A:136 | P7 | pk:85 |
| POST | /api/user/epay/notify | billing.EpayNotify | N+B | A:138 | P7 | — |
| GET | /api/user/epay/notify | billing.EpayNotify | N | A:139 | P7 | — |
| POST | /api/user/vmq/notify | billing.VmqNotify | N+B | A:140 | P7 | — |
| GET | /api/user/vmq/notify | billing.VmqNotify | N | A:141 | P7 | — |
| POST | /api/user/codepay/notify | billing.CodePayNotify | N+B | A:142 | P7 | — |
| GET | /api/user/codepay/notify | billing.CodePayNotify | N | A:143 | P7 | — |
| GET | /api/user/groups | handler.GetUserGroups | N | A:144 | P3 | — |
| GET | /api/user/sessions | identity.GetLoginSessions | U+NC | A:149 | P2 | profile:159 |
| DELETE | /api/user/sessions/:sid | identity.DeleteLoginSession | U+NC | A:150 | P2 | profile:164 |
| POST | /api/user/sessions/revoke-others | identity.RevokeOtherLoginSessions | U+NC | A:151 | P2 | profile:169 |
| GET | /api/user/self/groups | handler.GetUserGroups | U | A:152 | P3 | lib:62; features/playground/constants.ts:39 |
| GET | /api/user/self | identity.GetSelf | U | A:153 | P2 | profile:42; lib:42 |
| GET | /api/user/models | identity.GetUserModels | U | A:154 | P3 | lib:53; features/playground/constants.ts:38 |
| PUT | /api/user/self | identity.UpdateSelf | U+CR+NC | A:155 | P3 | profile:52,74; components/language-switcher.tsx:48 |
| DELETE | /api/user/self | identity.DeleteSelf | U | A:156 | P3 | profile:84 |
| GET | /api/user/token | identity.GenerateAccessToken | U+CR+UCR(access-token)+NC | A:157 | P2 | profile:92 |
| GET | /api/user/passkey | identity.PasskeyStatus | U | A:158 | P7 | pk:32 |
| POST | /api/user/passkey/register/begin | identity.PasskeyRegisterBegin | U+NC | A:159 | P7 | pk:40 |
| POST | /api/user/passkey/register/finish | identity.PasskeyRegisterFinish | U+NC | A:160 | P7 | pk:53 |
| POST | /api/user/passkey/verify/begin | identity.PasskeyVerifyBegin | U+NC | A:161 | P7 | pk:96 |
| POST | /api/user/passkey/verify/finish | identity.PasskeyVerifyFinish | U+NC | A:162 | P7 | pk:107 |
| DELETE | /api/user/passkey | identity.PasskeyDelete | U+NC | A:163 | P7 | pk:64 |
| GET | /api/user/aff | identity.GetAffCode | U | A:164 | P4 | wallet:217 |
| GET | /api/user/topup/info | billing.GetTopUpInfo | U | A:165 | P4/P7 | wallet:59 |
| GET | /api/user/topup/self | billing.GetUserTopUps | U | A:166 | P4 | wallet:246 |
| POST | /api/user/topup | identity.TopUp | U+CR | A:167 | P4 | wallet:69 |
| POST | /api/user/pay | billing.RequestEpay | U+CR | A:168 | P7 | wallet:115 |
| POST | /api/user/amount | billing.RequestAmount | U | A:169 | P4/P7 | wallet:79 |
| POST | /api/user/stripe/pay | billing.RequestStripePay | U+CR | A:170 | P7 | wallet:130 |
| POST | /api/user/stripe/amount | billing.RequestStripeAmount | U | A:171 | P4/P7 | wallet:91 |
| POST | /api/user/creem/pay | billing.RequestCreemPay | U+CR | A:172 | P7 | wallet:142 |
| POST | /api/user/waffo/amount | billing.RequestWaffoAmount | U | A:173 | P4/P7 | wallet:103 |
| POST | /api/user/waffo/pay | billing.RequestWaffoPay | U+CR | A:174 | P7 | wallet:154 |
| POST | /api/user/waffo-pancake/amount | billing.RequestWaffoPancakeAmount | U | A:175 | P4/P7 | wallet:166 |
| POST | /api/user/waffo-pancake/pay | billing.RequestWaffoPancakePay | U+CR | A:176 | P7 | wallet:178 |
| POST | /api/user/vmq/pay | billing.RequestVmqPay | U+CR | A:177 | P7 | wallet:189 |
| POST | /api/user/codepay/pay | billing.RequestCodePayPay | U+CR | A:178 | P7 | wallet:204 |
| POST | /api/user/aff_transfer | identity.TransferAffQuota | U+UCR(aff-transfer)+PC | A:179 | P4 | wallet:227 |
| PUT | /api/user/setting | identity.UpdateUserSettingHandler | U | A:180 | P3 | profile:64 |
| GET | /api/user/2fa/status | identity.Get2FAStatus | U | A:183 | P2 | lib:106 |
| POST | /api/user/2fa/setup | identity.Setup2FA | U+NC | A:184 | P2 | lib:111 |
| POST | /api/user/2fa/enable | identity.Enable2FA | U+NC | A:185 | P2 | lib:117 |
| POST | /api/user/2fa/disable | identity.Disable2FA | U+NC | A:186 | P2 | lib:126 |
| POST | /api/user/2fa/backup_codes | identity.RegenerateBackupCodes | U+NC | A:187 | P2 | lib:135 |
| GET | /api/user/checkin | billing.GetCheckinStatus | U | A:190 | P4 | profile:213 |
| POST | /api/user/checkin | billing.DoCheckin | U+TS | A:191 | P4 | profile:224–225 |
| GET | /api/user/qq/bind | billing.GetQQBindStatus | U | A:194 | P7 | profile:240 |
| POST | /api/user/qq/bind/code | billing.GenerateQQBindCode | U+CR+NC | A:195 | P7 | profile:250 |
| DELETE | /api/user/qq/bind | billing.UnbindQQ | U+CR | A:196 | P7 | profile:258 |
| POST | /api/user/qq/panel/sync | billing.SyncQQPanel | U+A+CR | A:197 | P7 | — |
| GET | /api/user/oauth/bindings | identity.GetUserOAuthBindings | U | A:200 | P7 | profile:189 |
| DELETE | /api/user/oauth/bindings/:provider_id | identity.UnbindCustomOAuth | U | A:201 | P7 | profile:199 |
| GET | /api/user/ | identity.GetAllUsers | A | A:207 | P3 | users:44 |
| GET | /api/user/topup | billing.GetAllTopUps | A | A:208 | P4 | wallet:265 |
| POST | /api/user/topup/complete | billing.AdminCompleteTopUp | A | A:209 | P4 | wallet:275 |
| GET | /api/user/search | identity.SearchUsersHandler | A | A:210 | P3 | users:80 |
| GET | /api/user/:id/oauth/bindings | identity.GetUserOAuthBindingsByAdmin | A | A:211 | P7 | users:194 |
| DELETE | /api/user/:id/oauth/bindings/:provider_id | identity.UnbindCustomOAuthByAdmin | A | A:212 | P7 | users:217 |
| DELETE | /api/user/:id/bindings/:binding_type | identity.AdminClearUserBinding | A | A:213 | P7 | users:205 |
| GET | /api/user/:id | identity.GetUser | A | A:214 | P3 | users:88; usage-logs:90 |
| POST | /api/user/ | identity.CreateUser | A | A:215 | P3/P4资金字段 | users:98 |
| POST | /api/user/manage | identity.ManageUser | A | A:216 | P3/P4资金动作 | users:127,137; user-insights:85 |
| PUT | /api/user/ | identity.UpdateUser | A | A:217 | P3/P4资金字段 | users:108 |
| DELETE | /api/user/:id | identity.DeleteUser | A | A:218 | P3 | users:116 |
| DELETE | /api/user/:id/reset_passkey | identity.AdminResetPasskey | A | A:219 | P7 | users:145 |
| GET | /api/user/2fa/stats | identity.Admin2FAStats | A | A:222 | P2 | — |
| DELETE | /api/user/:id/2fa | identity.AdminDisable2FA | A | A:223 | P2 | users:153 |
| GET | /api/user-insight/summary | usage.HandleGetUserInsightSummary | A | A:232 | P7 | user-insights:58 |
| GET | /api/user-insight | usage.HandleGetUserInsights | A | A:233 | P7 | user-insights:40 |
| GET | /api/user-insight/client-catalog | usage.HandleGetClientCatalog | A | A:234 | P7 | user-insights:113 |
| GET | /api/user-insight/:id | usage.HandleGetUserInsightDetail | A | A:235 | P7 | — |
| DELETE | /api/user-insight/:id | usage.HandlePurgeUserInsight | A | A:236 | P7 | user-insights:71 |
| POST | /api/user-insight/client-ban | usage.HandleSetGlobalClientBan | A | A:239 | P7 | user-insights:100 |
| POST | /api/user-insight/:id/client-ban | usage.HandleToggleUserClientBan | A | A:240 | P7 | user-insights:126 |
| GET | /api/insight-sample | usage.HandleGetInsightSamples | A | A:247 | P7 | user-insights:143 |
| GET | /api/insight-sample/:id | usage.HandleGetInsightSampleDetail | A | A:248 | P7 | user-insights:181 |
| DELETE | /api/insight-sample/user/:id | usage.HandleDeleteUserInsightSamples | A | A:249 | P7 | user-insights:193 |
| GET | /api/insight-sample-group | usage.HandleGetInsightSampleGroups | A | A:254 | P7 | user-insights:166 |
| GET | /api/subscription/plans | billing.GetSubscriptionPlans | U | A:261 | P4 | subscriptions:236 |
| GET | /api/subscription/self | billing.GetSubscriptionSelf | U | A:262 | P4 | subscriptions:231 |
| PUT | /api/subscription/self/preference | billing.UpdateSubscriptionPreference | U | A:263 | P4 | subscriptions:243 |
| POST | /api/subscription/balance/pay | billing.SubscriptionRequestBalancePay | U+CR | A:264 | P4 | subscriptions:161 |
| POST | /api/subscription/epay/pay | billing.SubscriptionRequestEpay | U+CR | A:265 | P7 | subscriptions:197 |
| POST | /api/subscription/stripe/pay | billing.SubscriptionRequestStripePay | U+CR | A:266 | P7 | subscriptions:140 |
| POST | /api/subscription/creem/pay | billing.SubscriptionRequestCreemPay | U+CR | A:267 | P7 | subscriptions:147 |
| POST | /api/subscription/waffo-pancake/pay | billing.SubscriptionRequestWaffoPancakePay | U+CR | A:268 | P7 | subscriptions:154 |
| POST | /api/subscription/vmq/pay | billing.SubscriptionRequestVmqPay | U+CR | A:269 | P7 | subscriptions:207 |
| POST | /api/subscription/codepay/pay | billing.SubscriptionRequestCodePayPay | U+CR | A:270 | P7 | subscriptions:217 |
| GET | /api/subscription/admin/plans | billing.AdminListSubscriptionPlans | A | A:275 | P4 | subscriptions:40 |
| POST | /api/subscription/admin/plans | billing.AdminCreateSubscriptionPlan | A | A:276 | P4 | subscriptions:47 |
| PUT | /api/subscription/admin/plans/:id | billing.AdminUpdateSubscriptionPlan | A | A:277 | P4 | subscriptions:55 |
| PATCH | /api/subscription/admin/plans/:id | billing.AdminUpdateSubscriptionPlanStatus | A | A:278 | P4 | subscriptions:63 |
| POST | /api/subscription/admin/bind | billing.AdminBindSubscription | A | A:279 | P4 | — |
| POST | /api/subscription/admin/plans/:id/subscriptions/reset | billing.AdminResetPlanSubscriptions | A | A:280 | P4 | subscriptions:127 |
| GET | /api/subscription/admin/users/:id/subscriptions | billing.AdminListUserSubscriptions | A | A:283 | P4 | subscriptions:77 |
| POST | /api/subscription/admin/users/:id/subscriptions | billing.AdminCreateUserSubscription | A | A:284 | P4 | subscriptions:87 |
| POST | /api/subscription/admin/users/:id/subscriptions/reset | billing.AdminResetUserSubscriptionsByPlan | A | A:285 | P4 | subscriptions:116 |
| POST | /api/subscription/admin/user_subscriptions/:id/invalidate | billing.AdminInvalidateUserSubscription | A | A:286 | P4 | subscriptions:97 |
| DELETE | /api/subscription/admin/user_subscriptions/:id | billing.AdminDeleteUserSubscription | A | A:287 | P4 | subscriptions:106 |
| POST | /api/subscription/epay/notify | billing.SubscriptionEpayNotify | N+B | A:291 | P7 | — |
| GET | /api/subscription/epay/notify | billing.SubscriptionEpayNotify | N | A:292 | P7 | — |
| GET | /api/subscription/epay/return | billing.SubscriptionEpayReturn | N | A:293 | P7 | — |
| POST | /api/subscription/vmq/notify | billing.SubscriptionVmqNotify | N+B | A:294 | P7 | — |
| GET | /api/subscription/vmq/notify | billing.SubscriptionVmqNotify | N | A:295 | P7 | — |
| POST | /api/subscription/codepay/notify | billing.SubscriptionCodePayNotify | N+B | A:296 | P7 | — |
| GET | /api/subscription/codepay/notify | billing.SubscriptionCodePayNotify | N | A:297 | P7 | — |
| GET | /api/option/ | ops.GetOptions | A+SS | A:301 | P3 | system-settings:37 |
| PUT | /api/option/ | ops.UpdateOption | A+SS | A:302 | P3/P4计费配置 | system-settings:42; lib/theme-persistence.ts:230,243 |
| POST | /api/option/payment_compliance | billing.ConfirmPaymentCompliance | A+SS | A:303 | P7 | system-settings:48 |
| GET | /api/option/channel_affinity_cache | handler.GetChannelAffinityCacheStats | A+SS | A:304 | P3 | affinity:28 |
| GET | /api/option/smtp_pool_status | handler.GetSMTPPoolStatus | A+SS | A:305 | P7 | system-settings:118 |
| DELETE | /api/option/channel_affinity_cache | handler.ClearChannelAffinityCache | A+SS | A:306 | P3 | affinity:38,47 |
| POST | /api/option/rest_model_ratio | handler.ResetModelRatio | A+SS | A:307 | P4 | system-settings:91 |
| GET | /api/option/waffo-pancake/catalog | billing.ListWaffoPancakeCatalog | A+SS | A:308 | P7 | pancake:68 |
| POST | /api/option/waffo-pancake/pair | billing.CreateWaffoPancakePair | A+SS | A:309 | P7 | pancake:79 |
| POST | /api/option/waffo-pancake/save | billing.SaveWaffoPancake | A+SS | A:310 | P7 | pancake:94 |
| POST | /api/option/waffo-pancake/subscription-product | billing.CreateWaffoPancakeSubscriptionProduct | A+SS | A:311 | P7 | subscriptions:174 |
| GET | /api/option/waffo-pancake/subscription-product-options | billing.ListWaffoPancakeSubscriptionProductOptions | A+SS | A:312 | P7 | subscriptions:189 |
| GET | /api/geoip/database | ops.GetGeoIPDatabase | A+SS | A:317 | P7 | system-settings:112 |
| POST | /api/geoip/database/update | ops.UpdateGeoIPDatabase | A+SS | A:318 | P7 | system-settings:125 |
| GET | /api/proxy/config | ops.GetProxyConfig | A+SS | A:323 | P7 | — |
| PUT | /api/proxy/config | ops.UpdateProxyConfig | A+SS | A:324 | P7 | — |
| GET | /api/proxy/config/generate | ops.GenerateProxyConfig | A+SS | A:325 | P7 | — |
| GET | /api/proxy/status | ops.GetProxyStatus | A+SS | A:326 | P7 | — |
| POST | /api/proxy/reload | ops.ReloadProxy | A+SS | A:327 | P7 | — |
| GET | /api/proxy/nodes | ops.ListProxyNodes | A+SS | A:328 | P7 | proxy:31 |
| GET | /api/proxy/nodes/report | ops.GetProxyNodeReport | A+SS | A:329 | P7 | proxy:37 |
| POST | /api/proxy/nodes | ops.CreateProxyNode | A+SS | A:330 | P7 | — |
| POST | /api/proxy/nodes/batch | ops.BatchCreateProxyNodes | A+SS | A:331 | P7 | proxy:112 |
| POST | /api/proxy/nodes/batch-enabled | ops.BatchSetProxyNodesEnabled | A+SS | A:332 | P7 | proxy:90 |
| POST | /api/proxy/nodes/batch-clear-errors | ops.BatchClearProxyNodeErrors | A+SS | A:333 | P7 | proxy:100 |
| GET | /api/proxy/nodes/:id | ops.GetProxyNode | A+SS | A:334 | P7 | — |
| PUT | /api/proxy/nodes/:id | ops.UpdateProxyNode | A+SS | A:335 | P7 | proxy:47,63 |
| DELETE | /api/proxy/nodes/:id | ops.DeleteProxyNode | A+SS | A:336 | P7 | proxy:55 |
| POST | /api/proxy/nodes/:id/test | ops.TestProxyNode | A+SS | A:337 | P7 | proxy:69 |
| POST | /api/proxy/nodes/test | ops.TestAllProxyNodes | A+SS | A:338 | P7 | proxy:79 |
| POST | /api/custom-oauth-provider/discovery | identity.FetchCustomOAuthDiscovery | A+SS | A:345 | P7 | custom-oauth:69 |
| GET | /api/custom-oauth-provider/ | identity.GetCustomOAuthProviders | A+SS | A:346 | P7 | custom-oauth:40 |
| GET | /api/custom-oauth-provider/:id | identity.GetCustomOAuthProvider | A+SS | A:347 | P7 | — |
| POST | /api/custom-oauth-provider/ | identity.CreateCustomOAuthProvider | A+SS | A:348 | P7 | custom-oauth:47 |
| PUT | /api/custom-oauth-provider/:id | identity.UpdateCustomOAuthProvider | A+SS | A:349 | P7 | custom-oauth:55 |
| DELETE | /api/custom-oauth-provider/:id | identity.DeleteCustomOAuthProvider | A+SS | A:350 | P7 | custom-oauth:62 |
| GET | /api/ratio_sync/channels | handler.GetSyncableChannels | A+SS | A:355 | P4/P7 | system-settings:98 |
| POST | /api/ratio_sync/fetch | handler.FetchUpstreamRatios | A+SS | A:356 | P4/P7 | system-settings:105 |
| GET | /api/token/ | identity.GetAllTokens | U | A:363 | P3 | keys:40 |
| GET | /api/token/search | identity.SearchTokens | U+SR | A:364 | P3 | keys:54 |
| GET | /api/token/auto-groups | identity.GetTokenAutoGroups | U | A:365 | P3 | keys:68 |
| GET | /api/token/:id | identity.GetToken | U | A:366 | P3 | keys:60 |
| POST | /api/token/:id/key | identity.GetTokenKey | U+CR+NC | A:367 | P3 | keys:115 |
| POST | /api/token/ | identity.AddToken | U | A:368 | P3 | keys:76 |
| PUT | /api/token/ | identity.UpdateToken | U | A:369 | P3 | keys:84,107 |
| DELETE | /api/token/:id | identity.DeleteToken | U | A:370 | P3 | keys:90 |
| POST | /api/token/batch | identity.DeleteTokenBatch | U | A:371 | P3 | keys:98 |
| POST | /api/token/batch/keys | identity.GetTokenKeysBatch | U+CR+NC | A:372 | P3 | keys:125 |
| GET | /api/usage/token/ | identity.GetTokenUsage | USAGE-token | A:382 | P4 | — |
| GET | /api/redemption/ | billing.GetAllRedemptions | A | A:389 | P4 | redemption-codes:39 |
| GET | /api/redemption/search | billing.SearchRedemptions | A | A:390 | P4 | redemption-codes:53 |
| GET | /api/redemption/:id | billing.GetRedemption | A | A:391 | P4 | redemption-codes:61 |
| POST | /api/redemption/ | billing.AddRedemption | A | A:392 | P4 | redemption-codes:69 |
| PUT | /api/redemption/ | billing.UpdateRedemption | A | A:393 | P4 | redemption-codes:77,86 |
| DELETE | /api/redemption/invalid | billing.DeleteInvalidRedemption | A | A:394 | P4 | redemption-codes:98 |
| DELETE | /api/redemption/:id | billing.DeleteRedemption | A | A:395 | P4 | redemption-codes:92 |
| POST | /api/system-task/log-cleanup | handler.CreateLogCleanupSystemTask | A+SS | A:401 | P7 | system-settings:56 |
| GET | /api/system-task/list | handler.ListSystemTasks | A+SS | A:402 | P7 | system-settings:83 |
| GET | /api/system-task/current | handler.GetCurrentSystemTask | A+SS | A:403 | P7 | system-settings:67 |
| GET | /api/system-task/:task_id | handler.GetSystemTask | A+SS | A:404 | P7 | system-settings:77 |
| GET | /api/system-info/instances | handler.ListSystemInstances | A+SS | A:409 | P7 | system-info:28 |
| DELETE | /api/system-info/stale-instances | handler.DeleteStaleSystemInstances | A+SS | A:410 | P7 | system-info:35 |
| DELETE | /api/system-info/instances/:node_name | handler.DeleteStaleSystemInstance | A+SS | A:411 | P7 | system-info:42 |
| GET | /api/group/ | handler.GetGroups | A | A:417 | P3 | users:161; subscriptions:250 |
| GET | /api/prefill_group/ | handler.GetPrefillGroups | A | A:423 | P3 | models:225; channels:714 |
| POST | /api/prefill_group/ | handler.CreatePrefillGroup | A | A:424 | P3 | models:240 |
| PUT | /api/prefill_group/ | handler.UpdatePrefillGroup | A | A:425 | P3 | models:254 |
| DELETE | /api/prefill_group/:id | handler.DeletePrefillGroup | A | A:426 | P3 | models:264 |
| GET | /api/mj/self | handler.GetUserMidjourney | U | A:430 | P7 | usage-logs:102 |
| GET | /api/mj/ | handler.GetAllMidjourney | A | A:431 | P7 | usage-logs:99 |
| GET | /api/task/self | handler.GetUserTask | U | A:435 | P7 | usage-logs:112 |
| GET | /api/task/ | handler.GetAllTask | A | A:436 | P7 | usage-logs:109 |
| GET | /api/vendors/ | handler.GetAllVendors | A | A:442 | P3 | models:122 |
| GET | /api/vendors/search | handler.SearchVendors | A | A:443 | P3 | — |
| GET | /api/vendors/:id | handler.GetVendorMeta | A | A:444 | P3 | — |
| POST | /api/vendors/ | handler.CreateVendorMeta | A | A:445 | P3 | models:134 |
| PUT | /api/vendors/ | handler.UpdateVendorMeta | A | A:446 | P3 | models:144 |
| DELETE | /api/vendors/:id | handler.DeleteVendorMeta | A | A:447 | P3 | models:154 |
| GET | /api/models/sync_upstream/preview | handler.SyncUpstreamPreview | A | A:453 | P3/P7 | models:190–191 |
| POST | /api/models/sync_upstream | handler.SyncUpstreamModels | A | A:454 | P3/P7 | models:170 |
| GET | /api/models/missing | handler.GetMissingModels | A | A:455 | P3 | models:215 |
| GET | /api/models/meta | handler.GetAllModelsMeta | A | A:456 | P3 | models:48 |
| GET | /api/models/search | handler.SearchModelsMeta | A | A:457 | P3 | models:58 |
| GET | /api/models/:id | handler.GetModelMeta | A | A:458 | P3 | models:66 |
| POST | /api/models/ | handler.CreateModelMeta | A | A:459 | P3 | models:76 |
| PUT | /api/models/ | handler.UpdateModelMeta | A | A:460 | P3 | models:86,97 |
| DELETE | /api/models/:id | handler.DeleteModelMeta | A | A:461 | P3 | models:107 |
| GET | /api/authz/catalog | policy.GetPermissionCatalogHandler | A | Z:17 | P3 | users:170 |

### 2.1 渠道权限表展开

默认 API+A；permission 是额外 RequirePermission，不替代 AdminAuth。handler 未标包名者均属于 `handler`。以下逐项状态均未开始。

| Method | Path | Handler | Auth / permission / 额外链 | 源 | 阶段 | 前端 |
|---|---|---|---|---|---|---|
| POST | /api/channel/:id/key | GetChannelKey | A+ROOT+CR+NC+SV | C:26–31 | P3 | channels:292 |
| GET | /api/channel/ | GetAllChannels | A+ChannelRead | C:51 | P3 | channels:85 |
| GET | /api/channel/search | SearchChannels | A+ChannelRead | C:52 | P3 | channels:95 |
| GET | /api/channel/models | ChannelListModels | A+ChannelRead | C:53 | P3 | channels:671 |
| GET | /api/channel/models_enabled | EnabledListModels | A+ChannelRead | C:54 | P3 | channels:683 |
| GET | /api/channel/ops | GetChannelOps | A+ChannelRead | C:55 | P3 | — |
| GET | /api/channel/test | TestAllChannels | A+ChannelOperate | C:56 | P7 | channels:645 |
| GET | /api/channel/update_balance | billing.UpdateAllChannelsBalance | A+ChannelOperate | C:57 | P7 | channels:657 |
| GET | /api/channel/health | GetChannelModelHealth | A+ChannelRead | C:58 | P3/P5 | channels:368,416 |
| GET | /api/channel/request_stats | GetChannelRequestStats | A+ChannelRead | C:59 | P7 | channels:405 |
| GET | /api/channel/route_unit/ | GetRouteUnitViews | A+ChannelRead | C:60 | P3 | route-units:70 |
| GET | /api/channel/:id | GetChannel | A+ChannelRead | C:61 | P3 | channels:103 |
| GET | /api/channel/test/:id | TestChannel | A+ChannelOperate | C:62 | P7 | channels:209 |
| GET | /api/channel/update_balance/:id | billing.UpdateChannelBalance | A+ChannelOperate | C:63 | P7 | channels:222 |
| POST | /api/channel/ | AddChannel | A+ChannelSensitiveWrite | C:64 | P3 | channels:114 |
| PUT | /api/channel/ | UpdateChannel | A+ChannelWrite | C:65 | P3 | channels:126 |
| POST | /api/channel/status/batch | BatchUpdateChannelStatus | A+ChannelOperate | C:66 | P3 | channels:156 |
| POST | /api/channel/:id/status | UpdateChannelStatus | A+ChannelOperate | C:67 | P3 | channels:141 |
| DELETE | /api/channel/disabled | DeleteDisabledChannel | A+ChannelSensitiveWrite | C:68 | P3 | channels:280 |
| POST | /api/channel/tag/disabled | DisableTagChannels | A+ChannelOperate | C:69 | P3 | channels:573 |
| POST | /api/channel/tag/enabled | EnableTagChannels | A+ChannelOperate | C:70 | P3 | channels:559 |
| PUT | /api/channel/tag | EditTagChannels | A+ChannelWrite | C:71 | P3 | channels:586 |
| DELETE | /api/channel/:id | DeleteChannel | A+ChannelSensitiveWrite | C:72 | P3 | channels:169 |
| POST | /api/channel/batch | DeleteChannelBatch | A+ChannelSensitiveWrite | C:73 | P3 | channels:179 |
| POST | /api/channel/fix | FixChannelsAbilities | A+ChannelOperate | C:74 | P3 | channels:265 |
| GET | /api/channel/fetch_models/:id | FetchUpstreamModels | A+ChannelOperate | C:75 | P3/P7 | channels:235 |
| POST | /api/channel/fetch_models | FetchModels | A+ChannelSensitiveWrite | C:76 | P3/P7 | channels:617 |
| POST | /api/channel/:id/codex/refresh | RefreshCodexChannelCredential | A+ChannelSensitiveWrite | C:77 | P7 | channels:309 |
| GET | /api/channel/:id/codex/usage | GetCodexChannelUsage | A+ChannelRead | C:78 | P7 | channels:320 |
| GET | /api/channel/:id/codex/usage/reset-credits | GetCodexChannelRateLimitResetCredits | A+ChannelRead | C:79 | P7 | channels:330 |
| POST | /api/channel/:id/codex/usage/reset | ResetCodexChannelUsage | A+ChannelOperate | C:80 | P7 | channels:340 |
| POST | /api/channel/ollama/pull | OllamaPullModel | A+ChannelSensitiveWrite | C:81 | P7 | — |
| POST | /api/channel/ollama/pull/stream | OllamaPullModelStream | A+ChannelSensitiveWrite | C:82 | P7 | features/channels/components/dialogs/ollama-models-dialog.tsx:249 |
| DELETE | /api/channel/ollama/delete | OllamaDeleteModel | A+ChannelSensitiveWrite | C:83 | P7 | channels:632 |
| GET | /api/channel/ollama/version/:id | OllamaVersion | A+ChannelSensitiveWrite | C:84 | P7 | — |
| POST | /api/channel/batch/tag | BatchSetChannelTag | A+ChannelWrite | C:85 | P3 | channels:190 |
| GET | /api/channel/tag/models | GetTagModels | A+ChannelRead | C:86 | P3 | channels:596 |
| POST | /api/channel/copy/:id | CopyChannel | A+ChannelSensitiveWrite | C:87 | P3 | channels:249 |
| POST | /api/channel/multi_key/manage | ManageMultiKeys | A+ChannelOperate | C:88 | P3 | channels:445 |
| POST | /api/channel/upstream_updates/apply | ApplyChannelUpstreamModelUpdates | A+ChannelWrite | C:89 | P7 | upstream:120 |
| POST | /api/channel/upstream_updates/apply_all | ApplyAllChannelUpstreamModelUpdates | A+ChannelWrite | C:90 | P7 | upstream:170 |
| POST | /api/channel/upstream_updates/detect | DetectChannelUpstreamModelUpdates | A+ChannelOperate | C:91 | P7 | upstream:214 |
| POST | /api/channel/upstream_updates/detect_all | DetectAllChannelUpstreamModelUpdates | A+ChannelOperate | C:92 | P7 | upstream:252 |
| GET | /api/channel/route_unit/aliases | ListRouteUnitAliases | A+ChannelRead | C:93 | P3 | route-units:65 |
| PUT | /api/channel/route_unit/:id | UpdateRouteUnit | A+ChannelWrite | C:94 | P3 | route-units:77 |
| POST | /api/channel/health/:action | UpdateChannelModelHealth | A+ChannelOperate | C:95 | P3/P5 | channels:426 |

## 3. AI、旧版账务、视频与 Web

handler 未标包者属于 `handler`。`Relay(format)` 中 format 省略共同前缀 `types.RelayFormat`。所有条目状态未开始；客户端未标明者为外部 API 消费者/待核查，不可据此裁剪路由。

| Method | Path | Handler / format | Auth / 链 | 源 | 阶段 |
|---|---|---|---|---|---|
| GET | /dashboard/billing/subscription | billing.GetSubscription | T/OLD | D:18 | P4 |
| GET | /v1/dashboard/billing/subscription | billing.GetSubscription | T/OLD | D:19 | P4 |
| GET | /dashboard/billing/usage | billing.GetUsage | T/OLD | D:20 | P4 |
| GET | /v1/dashboard/billing/usage | billing.GetUsage | T/OLD | D:21 | P4 |
| GET | /v1/models | closure: ListModels(Anthropic/OpenAI) 或 RetrieveModel(Gemini)，由 headers/query 分支 | T/MODELS | R:24–33 | P5/P6 |
| GET | /v1/models/:model | closure: RetrieveModel(Anthropic/OpenAI) | T/MODELS | R:35–42 | P5/P6 |
| GET | /v1beta/models | closure: ListModels(Gemini) | T/MODELS | R:49–51 | P6 |
| GET | /v1beta/openai/models | closure: ListModels(OpenAI) | T/MODELS | R:58–60 | P6 |
| POST | /pg/chat/completions | Playground | U/PG | R:68 | P5 |
| GET | /v1/realtime | Relay(OpenAIRealtime)；WebSocket | T/CORE | R:81–83 | P6 |
| POST | /v1/messages | Relay(Claude) | T/CORE | R:91–93 | P6 |
| POST | /v1/completions | Relay(OpenAI) | T/CORE | R:96–98 | P5 |
| POST | /v1/chat/completions | Relay(OpenAI) | T/CORE | R:99–101 | P5 |
| POST | /v1/responses | Relay(OpenAIResponses) | T/CORE | R:104–106 | P6 |
| POST | /v1/responses/compact | Relay(OpenAIResponsesCompaction) | T/CORE | R:107–109 | P6 |
| POST | /v1/alpha/search | Relay(OpenAIAlphaSearch) | T/CORE | R:112–114 | P6 |
| POST | /v1/edits | Relay(OpenAIImage) | T/CORE | R:117–119 | P6 |
| POST | /v1/images/generations | Relay(OpenAIImage) | T/CORE | R:120–122 | P6 |
| POST | /v1/images/edits | Relay(OpenAIImage) | T/CORE | R:123–125 | P6 |
| POST | /v1/embeddings | Relay(Embedding) | T/CORE | R:128–130 | P6 |
| POST | /v1/audio/transcriptions | Relay(OpenAIAudio) | T/CORE | R:133–135 | P6 |
| POST | /v1/audio/translations | Relay(OpenAIAudio) | T/CORE | R:136–138 | P6 |
| POST | /v1/audio/speech | Relay(OpenAIAudio) | T/CORE | R:139–141 | P6 |
| POST | /v1/rerank | Relay(Rerank) | T/CORE | R:144–146 | P6 |
| POST | /v1/engines/:model/embeddings | Relay(Gemini) | T/CORE | R:149–151 | P6 |
| POST | /v1/models/*path | Relay(Gemini) | T/CORE | R:152–154 | P6 |
| POST | /v1/moderations | Relay(OpenAI) | T/CORE | R:157–159 | P6 |
| POST | /v1/images/variations | RelayNotImplemented | T/CORE | R:162 | P6负向契约 |
| GET | /v1/files | RelayNotImplemented | T/CORE | R:163 | P6负向契约 |
| POST | /v1/files | RelayNotImplemented | T/CORE | R:164 | P6负向契约 |
| DELETE | /v1/files/:id | RelayNotImplemented | T/CORE | R:165 | P6负向契约 |
| GET | /v1/files/:id | RelayNotImplemented | T/CORE | R:166 | P6负向契约 |
| GET | /v1/files/:id/content | RelayNotImplemented | T/CORE | R:167 | P6负向契约 |
| POST | /v1/fine-tunes | RelayNotImplemented | T/CORE | R:168 | P6负向契约 |
| GET | /v1/fine-tunes | RelayNotImplemented | T/CORE | R:169 | P6负向契约 |
| GET | /v1/fine-tunes/:id | RelayNotImplemented | T/CORE | R:170 | P6负向契约 |
| POST | /v1/fine-tunes/:id/cancel | RelayNotImplemented | T/CORE | R:171 | P6负向契约 |
| GET | /v1/fine-tunes/:id/events | RelayNotImplemented | T/CORE | R:172 | P6负向契约 |
| DELETE | /v1/models/:model | RelayNotImplemented | T/CORE | R:173 | P6负向契约 |
| POST | /suno/submit/:action | RelayTask | T/SUNO | R:189 | P6 |
| POST | /suno/fetch | RelayTaskFetch | T/SUNO | R:190 | P6 |
| GET | /suno/fetch/:id | RelayTaskFetch | T/SUNO | R:191 | P6 |
| POST | /v1beta/models/*path | Relay(Gemini) | T/GEMINI | R:203–205 | P6 |
| GET | /mj/image/:id | relay.RelayMidjourneyImage | N/MJ-image | R:178,210 | P6 |
| POST | /mj/submit/action | RelayMidjourney | T/MJ | R:178,213 | P6 |
| POST | /mj/submit/shorten | RelayMidjourney | T/MJ | R:178,214 | P6 |
| POST | /mj/submit/modal | RelayMidjourney | T/MJ | R:178,215 | P6 |
| POST | /mj/submit/imagine | RelayMidjourney | T/MJ | R:178,216 | P6 |
| POST | /mj/submit/change | RelayMidjourney | T/MJ | R:178,217 | P6 |
| POST | /mj/submit/simple-change | RelayMidjourney | T/MJ | R:178,218 | P6 |
| POST | /mj/submit/describe | RelayMidjourney | T/MJ | R:178,219 | P6 |
| POST | /mj/submit/blend | RelayMidjourney | T/MJ | R:178,220 | P6 |
| POST | /mj/submit/edits | RelayMidjourney | T/MJ | R:178,221 | P6 |
| POST | /mj/submit/video | RelayMidjourney | T/MJ | R:178,222 | P6 |
| GET | /mj/task/:id/fetch | RelayMidjourney | T/MJ | R:178,224 | P6 |
| GET | /mj/task/:id/image-seed | RelayMidjourney | T/MJ | R:178,225 | P6 |
| POST | /mj/task/list-by-condition | RelayMidjourney | T/MJ | R:178,226 | P6 |
| POST | /mj/insight-face/swap | RelayMidjourney | T/MJ | R:178,227 | P6 |
| POST | /mj/submit/upload-discord-images | RelayMidjourney | T/MJ | R:178,228 | P6 |
| GET | /:mode/mj/image/:id | relay.RelayMidjourneyImage | N/MJ-image | R:182,210 | P6 |
| POST | /:mode/mj/submit/action | RelayMidjourney | T/MJ | R:182,213 | P6 |
| POST | /:mode/mj/submit/shorten | RelayMidjourney | T/MJ | R:182,214 | P6 |
| POST | /:mode/mj/submit/modal | RelayMidjourney | T/MJ | R:182,215 | P6 |
| POST | /:mode/mj/submit/imagine | RelayMidjourney | T/MJ | R:182,216 | P6 |
| POST | /:mode/mj/submit/change | RelayMidjourney | T/MJ | R:182,217 | P6 |
| POST | /:mode/mj/submit/simple-change | RelayMidjourney | T/MJ | R:182,218 | P6 |
| POST | /:mode/mj/submit/describe | RelayMidjourney | T/MJ | R:182,219 | P6 |
| POST | /:mode/mj/submit/blend | RelayMidjourney | T/MJ | R:182,220 | P6 |
| POST | /:mode/mj/submit/edits | RelayMidjourney | T/MJ | R:182,221 | P6 |
| POST | /:mode/mj/submit/video | RelayMidjourney | T/MJ | R:182,222 | P6 |
| GET | /:mode/mj/task/:id/fetch | RelayMidjourney | T/MJ | R:182,224 | P6 |
| GET | /:mode/mj/task/:id/image-seed | RelayMidjourney | T/MJ | R:182,225 | P6 |
| POST | /:mode/mj/task/list-by-condition | RelayMidjourney | T/MJ | R:182,226 | P6 |
| POST | /:mode/mj/insight-face/swap | RelayMidjourney | T/MJ | R:182,227 | P6 |
| POST | /:mode/mj/submit/upload-discord-images | RelayMidjourney | T/MJ | R:182,228 | P6 |
| GET | /v1/videos/:task_id/content | task.VideoProxy | TU/VIDEO-content | V:18 | P6 |
| POST | /v1/video/generations | RelayTask | T/VIDEO | V:25 | P6 |
| GET | /v1/video/generations/:task_id | RelayTaskFetch | T/VIDEO | V:26 | P6 |
| POST | /v1/videos/:video_id/remix | RelayTask | T/VIDEO | V:27 | P6 |
| POST | /v1/videos | RelayTask | T/VIDEO | V:32 | P6 |
| GET | /v1/videos/:task_id | RelayTaskFetch | T/VIDEO | V:33 | P6 |
| POST | /kling/v1/videos/text2video | RelayTask | T/KLING | V:40 | P6 |
| POST | /kling/v1/videos/image2video | RelayTask | T/KLING | V:41 | P6 |
| GET | /kling/v1/videos/text2video/:task_id | RelayTaskFetch | T/KLING | V:42 | P6 |
| GET | /kling/v1/videos/image2video/:task_id | RelayTaskFetch | T/KLING | V:43 | P6 |
| POST | /jimeng/ | RelayTask | T/JIMENG | V:52 | P6 |
| 静态 probe，all-method fallback 内 | / 下真实资源 | ServeAssets(frontendFS) | N/WEB；具体原生链待核查 | W:17 → static/serve_assets.go:25 | P1/P9 |
| NoRoute，all-method Use 层 | 未匹配 /v1*、/api*、/assets* | RelayNotFound | N/WEB | static/serve_assets.go:26–31 | P1/P8 |
| NoRoute，all-method Use 层 | 其余未匹配路径 | HTML index；Cache-Control:no-cache；200 | N/WEB | static/serve_assets.go:33–34 | P1/P9 |
| NoRoute，all-method Use 层 | FRONTEND_BASE_URL非空且非master的未匹配路径 | 301 redirect(base + RequestURI) | N；ROOT分支 | ROOT:19–31 | P1/P9 |

### 注册与前端边界注意事项

1. 优先级：ROOT:15–18 的 API→dashboard→relay→video；以注册源码顺序为准，不以本文展示顺序注册。本文把 channels/authz 移到管理表末尾、把 MJ 两套挂载放到 Suno/Gemini 后便于阅读；实际 A:358–359 在 token 之前调用 channels/authz，R:175–182 在 Suno/Gemini 之前挂载 MJ。渠道 C:42–48 明确字面量必须位于重叠参数之前；不能用排序后的 map 注册代替。OAuth 固定路径必须先于 `:provider`。`GET /api/models` 与 `/api/models/:id` 的 U/A 不同。
2. `GET /v1/models` Gemini 分支确实调用 RetrieveModel，不擅自“修正”为 ListModels；通过 Go fixture 决定兼容性。
3. `GET /mj/image/:id` 两套挂载都先于 TokenAuth；不能把整个 MJ 组错误标为 T。这不免除 handler 的资源访问审查。
4. 原源码明确 NotImplemented 的 12 条路由应保留负向契约，不凭空增加上游能力；注释中的 `/api/midjourney`、`/api/user/tokenlog`、MJ `/notify` 不算注册路由。
5. dev 登录必须在非dev版本不存在，不能作为生产便利接口迁入。
6. SPA 当前按字符串前缀排除 `/api`、`/v1`、`/assets`；不自动覆盖 `/mj`、`/suno`、`/kling`、`/pg`、`/jimeng`，外置前端分支又是另一套行为。主计划要求未实现 API 不得返回假成功；如与 Go 未注册路径行为冲突，应显式记录差异并审批，而非静默修改。
7. 前端 `features/playground/constants.ts:37` 使用 `/pg/chat/completions`；`features/usage-logs/components/columns/task-logs-columns.tsx:251` 用视频 content URL。请求发送器、SSE parser、浏览器 Cookie 跨域等细节待专项核查。
8. `features/models/constants.ts:124–130` 和 `features/channels/lib/advanced-custom.ts:99–155` 是协议配置/展示，不是全部实际浏览器调用；OAuth provider 模板的 `/api/v3/user` 等为第三方地址，不应注册成本服务 API。
9. `features/system-settings/models/model-ratio-form.tsx:283,356` 文案提 `/api/ratio`，实际注册为 `/api/ratio_config`；这是文案漂移候选，不创建不存在的接口。
10. 前端确有无尾斜线请求（如 `/api/channel`、`/api/data`）与带尾斜线注册，以及 token/user DELETE 额外尾斜线；冻结 redirect/匹配行为前不做全局 URL 规范化。
11. 前端动态日志 helper 已阅读：`features/usage-logs/api.ts:36–65` 生成 `/self`、`/stat`，默认 `p=1,page_size=20`。keys 使用 `size`，redemption 使用 `page_size`；不可统一改名。
12. 重复调用位置补录：`features/profile/components/sidebar-modules-card.tsx:129,174` GET/PUT `/api/user/self`；`features/users/components/dialogs/user-binding-dialog.tsx:102` GET `/api/status`；`features/system-settings/request-limits/sensitive-audit-table.tsx:78` GET `/api/log/`（type/p/page_size）；`lib/api.ts:42` 共享自信息刷新。测试 mock 命中不当作生产调用。

## 4. Relay 适配器逐项工厂台账

工厂源 F=`/root/newapi/apps/api/internal/relay/resolve_adaptor.go`。实现路径根 CH=`/root/newapi/apps/api/internal/relay/channel/`。每行必须单独提供 golden/错误/流式/usage 证据；当前全部未开始。`APIType` 不等于 `ChannelType`，类型数字映射/历史别名仍待常量表专项审阅。仅确认工厂选择，**不宣称每适配器支持接口声明中的全部协议**。远程凭证未提供，真实供应商验收全部受阻。

| APIType（省略constant.） | 具体实现文件/类型 | 工厂行 | 阶段 | 状态 |
|---|---|---|---|---|
| APITypeAli | CH ali/adaptor.go Adaptor | F:62–63 | P6 | 未开始 |
| APITypeAnthropic | CH claude/adaptor.go Adaptor | F:64–65 | P6 | 未开始 |
| APITypeBaidu | CH baidu/adaptor.go Adaptor | F:66–67 | P6 | 未开始 |
| APITypeGemini | CH gemini/adaptor.go Adaptor | F:68–69 | P6 | 未开始 |
| APITypeOpenAI | CH openai/adaptor.go Adaptor | F:70–71 | P5核心/P6其余 | 未开始 |
| APITypePaLM | CH palm/adaptor.go Adaptor | F:72–73 | P6 | 未开始 |
| APITypeTencent | CH tencent/adaptor.go DispatchAdaptor | F:74–75 | P6 | 未开始 |
| APITypeXunfei | CH xunfei/adaptor.go Adaptor | F:76–77 | P6 | 未开始 |
| APITypeZhipu | CH zhipu/adaptor.go Adaptor | F:78–79 | P6 | 未开始 |
| APITypeZhipuV4 | CH zhipu_4v/adaptor.go Adaptor | F:80–81 | P6 | 未开始 |
| APITypeOllama | CH ollama/adaptor.go Adaptor | F:82–83 | P6 | 未开始 |
| APITypePerplexity | CH perplexity/adaptor.go Adaptor | F:84–85 | P6 | 未开始 |
| APITypeAws | CH aws/adaptor.go Adaptor | F:86–87 | P6 | 未开始 |
| APITypeCohere | CH cohere/adaptor.go Adaptor | F:88–89 | P6 | 未开始 |
| APITypeDify | CH dify/adaptor.go Adaptor | F:90–91 | P6 | 未开始 |
| APITypeJina | CH jina/adaptor.go Adaptor | F:92–93 | P6 | 未开始 |
| APITypeCloudflare | CH cloudflare/adaptor.go Adaptor | F:94–95 | P6 | 未开始 |
| APITypeSiliconFlow | CH siliconflow/adaptor.go Adaptor | F:96–97 | P6 | 未开始 |
| APITypeVertexAi | CH vertex/adaptor.go Adaptor | F:98–99 | P6 | 未开始 |
| APITypeMistral | CH mistral/adaptor.go Adaptor | F:100–101 | P6 | 未开始 |
| APITypeDeepSeek | CH deepseek/adaptor.go Adaptor | F:102–103 | P6 | 未开始 |
| APITypeMokaAI | CH mokaai/adaptor.go Adaptor | F:104–105 | P6 | 未开始 |
| APITypeVolcEngine | CH volcengine/adaptor.go Adaptor | F:106–107 | P6 | 未开始 |
| APITypeBaiduV2 | CH baidu_v2/adaptor.go Adaptor | F:108–109 | P6 | 未开始 |
| APITypeOpenRouter | CH openai/adaptor.go Adaptor（独立别名fixture） | F:110–111 | P6 | 未开始 |
| APITypeXinference | CH openai/adaptor.go Adaptor（独立别名fixture） | F:112–113 | P6 | 未开始 |
| APITypeXai | CH xai/adaptor.go Adaptor | F:114–115 | P6 | 未开始 |
| APITypeCoze | CH coze/adaptor.go Adaptor | F:116–117 | P6 | 未开始 |
| APITypeJimeng | CH jimeng/adaptor.go Adaptor | F:118–119 | P6 | 未开始 |
| APITypeMoonshot | CH moonshot/adaptor.go Adaptor（工厂注释Claude API） | F:120–121 | P6 | 未开始 |
| APITypeSubmodel | CH submodel/adaptor.go Adaptor | F:122–123 | P6 | 未开始 |
| APITypeMiniMax | CH minimax/adaptor.go Adaptor | F:124–125 | P6 | 未开始 |
| APITypeReplicate | CH replicate/adaptor.go Adaptor | F:126–127 | P6 | 未开始 |
| APITypeCodex | CH codex/adaptor.go Adaptor | F:128–129 | P6 | 未开始 |
| APITypeAdvancedCustom | CH advancedcustom/adaptor.go Adaptor | F:130–131 | P6 | 未开始 |
| APITypeSub2API | CH sub2api/adaptor.go Adaptor | F:132–133 | P6 | 未开始 |
| APITypeNewAPI | CH newapi/adaptor.go Adaptor | F:134–135 | P6 | 未开始 |
| 未匹配apiType | nil；调用者错误处理待核查 | F:137 | P5/P6 | 未开始 |

### 4.1 Task 分派（每个别名单列）

| TaskPlatform / ChannelType | 具体实现 | 工厂行 | 阶段 | 状态 |
|---|---|---|---|---|
| TaskPlatformSuno | CH task/suno/adaptor.go TaskAdaptor | F:152–153 | P6 | 未开始 |
| ChannelTypeAli | CH task/ali/adaptor.go TaskAdaptor | F:157–158 | P6 | 未开始 |
| ChannelTypeKling | CH task/kling/adaptor.go TaskAdaptor | F:159–160 | P6 | 未开始 |
| ChannelTypeJimeng | CH task/jimeng/adaptor.go TaskAdaptor | F:161–162 | P6 | 未开始 |
| ChannelTypeVertexAi | CH task/vertex/adaptor.go TaskAdaptor | F:163–164 | P6 | 未开始 |
| ChannelTypeVidu | CH task/vidu/adaptor.go TaskAdaptor | F:165–166 | P6 | 未开始 |
| ChannelTypeDoubaoVideo | CH task/doubao/adaptor.go TaskAdaptor | F:167–168 | P6 | 未开始 |
| ChannelTypeVolcEngine | CH task/doubao/adaptor.go TaskAdaptor | F:167–168 | P6 | 未开始 |
| ChannelTypeSora | CH task/sora/adaptor.go TaskAdaptor | F:169–170 | P6 | 未开始 |
| ChannelTypeOpenAI | CH task/sora/adaptor.go TaskAdaptor | F:169–170 | P6 | 未开始 |
| ChannelTypeGemini | CH task/gemini/adaptor.go TaskAdaptor | F:171–172 | P6 | 未开始 |
| ChannelTypeMiniMax | CH task/hailuo/adaptor.go TaskAdaptor | F:173–174 | P6 | 未开始 |
| 未匹配platform/channelType | nil；调用者错误处理待核查 | F:177 | P6 | 未开始 |
| Midjourney | 非上述工厂，RelayMidjourney/RelayMidjourneyImage 独立路径 | R:210–228 | P6 | 未开始 |

接口基线 `/root/newapi/apps/api/internal/relay/channel/adapter.go`：

| 契约项 | 源行 | 必测边界 | 阶段/状态 |
|---|---|---|---|
| Init / GetRequestURL / SetupRequestHeader | 18–20 | 模型路由、base URL、代理、凭证覆盖/泄漏、SSRF | P5/P6 未开始 |
| ConvertOpenAIRequest | 21 | 默认值、工具、多模态、未知字段 | P5/P6 未开始 |
| ConvertRerankRequest | 22 | 排序/索引/usage | P6 未开始 |
| ConvertEmbeddingRequest | 23 | 向量编码、批次/维度 | P6 未开始 |
| ConvertAudioRequest | 24 | multipart、二进制/流式 | P6 未开始 |
| ConvertImageRequest | 25 | multipart、URL/base64、大小 | P6 未开始 |
| ConvertOpenAIResponsesRequest | 26 | event类型、compact/search、桥接 | P6 未开始 |
| DoRequest / DoResponse | 27–28 | 流帧、背压、错误、取消、usage结算 | P5/P6 未开始 |
| GetModelList / GetChannelName | 29–30 | 目录与显示兼容 | P3/P6 未开始 |
| ConvertClaudeRequest | 31 | tools/thinking/cache usage | P6 未开始 |
| ConvertGeminiRequest | 32 | contents/parts、function调用、usage | P6 未开始 |
| Task Init / ValidateRequestAndSetAction | 36–38 | action权限/参数默认值 | P6 未开始 |
| EstimateBilling | 47 | 请求阶段估价倍率 | P4/P6 未开始 |
| AdjustBillingOnSubmit | 55 | 提交后实际参数差额 | P4/P6 未开始 |
| AdjustBillingOnComplete | 62 | 终态补扣/退还，0保持预扣 | P4/P6 未开始 |
| BuildRequestURL/Header/Body | 66–68 | 上游凭证、代理、请求编码 | P6 未开始 |
| Task DoRequest / DoResponse | 70–71 | taskID/原始taskData、提交失败 | P6 未开始 |
| Task GetModelList / GetChannelName | 73–74 | 异步模型目录 | P6 未开始 |
| FetchTask / ParseTaskResult | 78–79 | 轮询失败、终态幂等、超时 | P6/P7 未开始 |
| OpenAIVideoConverter.ConvertToOpenAIVideo | 82–84 | 视频状态/格式兼容 | P6 未开始 |

## 5. P0 收口与后续阶段待办（不得混同阶段门禁）

P0 仅冻结集合、契约、映射和 Go 基线，不以前置完成 Rust 行为验收为条件。以下未来阶段待办不自动构成 P0 阻塞；P1 故障/SQLite/PostgreSQL 两库验收、P6 真实上游验收必须留在所属阶段。远程已有证据以 `/root/newapi-rs/docs/ci-baseline.md` 为准：新仓库 SHA `6e599ec59837d645b4740ebe363790beda6b40f1`，run [41425478831](https://github.com/xiaocongyu66/newapi-rs/actions/runs/41425478831)，attempts 1/2 均 success；首轮 CI 基础交付独立 verification 为 PASS。此结论不覆盖所有契约，也不是本次文档修订或整个 P0 的 PASS。

| ID | 缺口 | 责任/后续 | 状态 |
|---|---|---|---|
| C01 | 当前集合、已知契约与阶段映射已记录；未来 handler 详细字段/分页/错误 fixture 尚未全部展开 | P0 保留已知契约和待核查映射；P1–P7 各域逐阶段补齐，不以所有未来 fixture 前置阻塞 P0 | 后续阶段未开始 |
| C02 | 388 生产注册静态闭环，dev +1 与 4 条 Web 规则另列；现有 compose/fiberadapter 测试所在 focused/full-api 基线已有 success，但未证明 Markdown 三方机器差集或全部方法矩阵 | P0 复核集合/契约/映射与现有基线；P1/P2/P8 方法行为、P9 产物验收后置，见 routes-coverage.md | 静态闭环；本次文档待独立复核 |
| C03 | middleware 注册顺序已列，全部实现阈值/存储/错误格式未逐个冻结 | security/transport 负责人逐函数补充；特别是 token headers、CORS、解压后限制 | 进行中 |
| C04 | 前端调用位置映射已录；动态变量、共享 request/fetch wrapper、SSE/WS、重试与刷新完整性未证明 | 远程静态抽取并人工排除文案/mock，补齐无字面量URL调用 | 进行中 |
| C05 | 适配器工厂分支已逐项列出；每个实现支持/不支持的协议、上游URL及认证方式尚待全文审阅 | relay owner 补充 apiType×协议×流/非流矩阵；每个nil/unsupported也需fixture | 进行中 |
| C06 | P6 真实供应商验收尚无合法凭证/真实付费调用授权 | 归 P6；届时模拟上游不能代替真实验收，须用户授权；不是 P0 阻塞 | P6 未开始 |
| C07 | 后台任务、表/字段归属与启动依赖属于并行 P0 data/ops 台账，本文件不代替它们 | 集成者合并关联；需包括 main.go:188 的独立 pprof listener，不在 compose 路由表内 | 受阻 |
| C08 | Go 远程基线及 Rust 工具存在已有 ci-baseline 证据；不证明 Rust 依赖构建、SQLite/PostgreSQL 两库兼容或全部 P0 交付 | P0 核对基线及版本/许可证映射；P1 故障与SQLite/PostgreSQL 两库实连验收留在 P1，各阶段矩阵不得前置 | CI 基础交付 PASS；P0 总验收另行复核 |
| C09 | P2邮件依赖/P7邮件全面集成、P5 insight enforcement/P7管理、P3配置/P4资金边界 | 提前实现必要端口与安全行为，但全面验收仍按阶段；不能先放行后补鉴权/账务 | 进行中 |

## 6. 明确未实现端点、计数与跨域补充核查

### 6.1 原始失败契约（不能改成空成功）

上述12条 `RelayNotImplemented` 路由都继承 CORE，包括认证与 Distribute；**只有前置链放行才到达501**。源 `/root/newapi/apps/api/internal/transport/handler/handle_relay.go:772–781`，序列化结构 `/root/newapi/apps/api/modules/relaykit/types/error.go:15–20`。HTTP 501 的 JSON 为：

```json
{"error":{"message":"API not implemented","type":"new_api_error","param":"","code":"api_not_implemented"}}
```

`param` 与 `code` 无 omitempty，必须保留；nil metadata 省略。这些是原有负向功能契约，不是授权缩减其他尚未迁移功能。每条分别覆盖匿名/无效key、模型分发失败、到达handler的501，不能为了测试501跳过认证。

`RelayNotFound` 的 HTTP 404 来自同文件:784–793：

```json
{"error":{"message":"Invalid URL (<METHOD> <PATH>)","type":"invalid_request_error","param":"","code":""}}
```

其中 message 按实际 Method()/Path() 插值。HTTP头、框架序列化与 method-not-allowed 行为仍待远程fixture确认。

### 6.2 路由总量证据边界

`/root/newapi/apps/api/internal/transport/compose/route_snapshot_test.go:17–34` 声明默认总数 **388**，四份 testdata 快照为 API 302（A 255 + C 46 + Z 1）、dashboard 4、relay 71、video 11。已阅读全文并人工按 method/path 对照本文第 2–3 节及所有生产注册点，未发现生产集合差异；389 条显式台账与 388 快照的唯一条件增量是 dev 登录 1 条，另 4 条 Web 行是行为规则，不参与 endpoint 求和。逐项阶段均已填写，跨阶段项按后置依赖验收，不表示提前启动阶段。

完整计数矩阵、条件分支、别名及 HEAD/OPTIONS 解释见 [routes-coverage.md](routes-coverage.md)。**本任务未运行测试或三方机器差集；已有远程 Go 基线 success 见第 5 节，静态闭环与该基线均不等于 P0 全部验收**。snapshot engine 的 Use/CORS/Compression/ServeAssets 是 no-op，NoRoute 仅存 handler，排序还丢失顺序；它不能证明权限链、运行时可达性、静态产物或方法行为兼容。当前收口目标为 P0 注册集合，不继续把所有未来阶段 handler 字段展开当作注册闭环前置；P1 五公共接口字段沿用专项文档，其余字段保留待核查且不视为已冻结。

### 6.3 并行探索交接约束

以下为用户提供的探索补充，纳入设计/验证范围，未冒充本任务全文验证：

- `dbinfra/open_db.go:63–103,148–161` 支持独立 `LOG_SQL_DSN` 与 ClickHouse 日志库；目标 SQLite/PostgreSQL 两类主库测试不能覆盖或取代日志库矩阵；旧 Go 的 MySQL 支持仅为历史事实，不迁移，不纳入目标验收。
- 同文件:195–239 的升级包含修复、AutoMigrate、回填，不只是 SQL 文件；应由 data/ops 所有者逐项冻结。HTTP/usage owner 不得因 SQLx 方案忽略这类升级。
- authtoken 与 identity session 的 JWT 用途隔离、refresh 轮换/撤销必须在 P2 冻结；不能仅复用同一 JWT decoder 视为会话兼容。
- egress 的 sing-box/uTLS/WireGuard 不是普通 Reqwest proxy 的同义替代；P5/P6 依赖出站能力兼容，P7 管理界面不能掩盖出站缺失。
- `main.go:116–185` 后台任务及 `ops/schedule_tasks.go` 的 master 租约、失锁取消须由 jobs 所有者承接；失锁后继续任务可能重复扣费/发送通知。
- internal 24 个模块及 `modules/relaykit` 的全量映射由架构/各域补齐；本台账只完成注册面与factory级追踪，未宣称全业务实现覆盖。

## 7. 后续分阶段远程验证交接（仅 GitHub-hosted Actions）

已有 Go 基线执行见第 5 节及 ci-baseline；以下是增量/后续阶段工作，不表示现有测试全部未运行，也不是把全部矩阵设为 P0 门禁。P0 收口集合/契约/映射及基线；第 4 项按 P1/P2/P4–P8 分阶段验收，第 5 项 E2E 属 P8，真实静态构建产物属 P9。

1. 集成者在新仓库开发分支合并本文后，用已授权 Git 策略提交/推送。Actions 只读检出原仓库精确基线 SHA，并核对 `git rev-parse HEAD`；不得把原仓库的默认分支当稳定基线。
2. 在 runner 中检查 Go workspace/module 与 frontend embed 前置条件，再运行原有 compose、fiberadapter、middleware、security 测试；建议候选命令（**只在远程，具体 working-directory 为检出的 apps/api，须先核对 go.mod/go.work**）：`go test ./internal/transport/compose ./internal/transport/fiberadapter ./internal/transport/middleware ./internal/security`。分别记录 dev/non-dev 路由快照，不为缺少 embed 文件生成假的成功页面。
3. 将实际路由注册顺序、method、path、handler/权限链与本表比较；包括 retired_frontend_routes、route_shadowing、models_reachability、web_fallback 等已有测试。差异逐项回填，不用总测试成功推断清单无遗漏。
4. 远程建立仅测试数据库/模拟上游 fixture：匿名/U/A/ROOT/TR/T 错误与成功、禁用用户、跨用户资源、Origin/CSRF、支付签名重放、gzip炸弹、无尾斜线、HEAD/OPTIONS、SSE/WS断连、视频 Range/下载权限。先冻结 Go 行为，再逐阶段差分 Rust；真实计费/邮件/机器人默认禁止。
5. 远程前端抽取实际调用图，与本表一一关联。通过现有真实 frontend 测试及 P8 E2E，不能用 mock-only 证明后端兼容。
6. 证据必须带新仓库 commit、上游 SHA、workflow run ID/URL、命令、退出码、测试/跳过数量、数据库实连信息；使用 `gh run view` 只读复核，独立 verification 给 PASS/FAIL/PARTIAL。已有 run `41425478831` attempts 1/2 success（SHA `6e599ec59837d645b4740ebe363790beda6b40f1`）及首轮 CI 基础交付 PASS；证据引用 ci-baseline，非本任务重新执行。public-config 19 pass/0 skip、focused 295/2、full-api 2745/7、relaykit 280/0，四组退出码均为 0（计数包含子测试/跨套件重复）。原生 MySQL/PostgreSQL 与支付签名 skip 作为历史基线事实保留（MySQL 不迁移，不要求补齐其目标验收；PostgreSQL 仍属于目标主库）；不能推导完整契约、P1 故障/SQLite/PostgreSQL 两库或 P6 真实上游已通过。本次文档修订仍待独立复核，P0 总状态由主代理按本阶段门禁判断。
