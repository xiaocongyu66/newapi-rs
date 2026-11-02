# P2 security / policy 实现契约

日期：2026-11-02。仅文档冻结，未实现、未执行验证、不签 P2 PASS。P1 独立 PASS 及 P2 已批准以主计划当前状态为准；旧台账中的“P0受阻/P2未开始”是历史记录。

## 1. 范围与依据

先读取 `/root/newapi-rs/docs/rust-backend-migration-plan.md`、`contracts-inventory.md`、`schema-inventory.md`、`dependency-baseline.md`。本文件补足 security 决策、端口与一致性，不复制全量389路由或schema，不替代 identity 负责人对登录业务 DTO 的冻结。上游只读根 `/root/newapi`，基线 `17970da4571e81308f176a0e61a38276e5771606`；以下源文件均相对此根的 `apps/api/internal/`。

强制 Rust **1.99.1 / Edition 2024**、模块化 workspace、SQLite/PostgreSQL 两种主库；不使用 Moka、MySQL/SQLx Any。无本地构建、测试、启动、脚本、提交、推送。本次唯一写入本文件。

P2 必须交付初始化并发防护、登录/退出/refresh/撤销、注册与邮件验证码/重置、已启用2FA账户完整登录、用户状态/角色/策略、API Key限制、限流及所需Redis、真实status声明。P3管理CRUD、P4结算、P5分发/协议转换、P7第三方登录不在本次实现范围；不能以这些后续阶段为由删去P2校验与端口。未实现能力保持明确失败且不宣称启用。

## 2. 依赖方向与端口（实现冻结）

- `identity`拥有 users/tokens/user_sessions/auth_flows/2FA及policy表的SQLx仓储、密码与JWT/refresh、会话与一次性凭据状态机。不依赖 security 或 Axum。
- `security`依赖 identity 的公开只读/应用端口，负责 credential kind 分类、角色门槛、permission决策、APIKey约束、Origin判断和限流决策；不得直接查询上述表。`apps/server`完成HTTP提取、错误渲染、可信代理/IP与TLS元数据、路由顺序、审计装配。identity不得导入security形成环。
- 首批公开类型：`CredentialKind={DashboardSession,PersonalAccessToken,RelayApiKey}`；`AuthIdentity{user_id,sid?,user_auth_version,session_version?}`；`Principal{identity,kind,username,role,status,user_group}`；`TokenGrant{token_id,owner_id,group,model_limits_enabled,model_limits,allow_ips,unlimited_quota,remain_quota,cross_group_retry,auto_groups}`。不把secret放入可Debug/Serialize对象。
- identity端口：`classify_dashboard_credential(raw)`、`validate_live_session(identity)`、`validate_pat(raw)`、`lookup_api_key(raw, Full|ReadOnly)`、`load_authz_snapshot(user_id)`；应用端口负责`refresh/logout/revoke`与`mutate_security_state(expected_version)`。业务错误为枚举，HTTP映射在transport，禁止用字符串判断DB失败。
- security端口：`authorize_role(principal,min_role)`、`authorize_permission(principal,resource,action)`、`check_api_key(grant,client_ip,group_snapshot)`、`check_session_origin(metadata)`、`take_rate_limit(scope,key,limit,window)`。组权限通过配置/目录公开快照端口，不直接依赖catalog内部表；P2验证模型限制解析与传播，P5调用模型授权决策后才可分发。
- 可替换的Clock/CSPRNG、Mailer、TurnstileVerifier、审计sink、Redis原子操作端口必需；邮件和Turnstile真实适配属于P2所需最小集成，不能全部推给P7。请求日志必须遮盖Authorization、Cookie、query key/turnstile/reset token、验证码与返回随机密码。

## 3. 凭据与中间件矩阵

源码 `security/authenticate.go:44–516`、`authtoken/authtoken.go`。

| 中间件 | 接受/拒绝与成功上下文 | 拒绝契约 |
|---|---|---|
| UserAuth | Dashboard JWT或users.access_token PAT；用户enabled、用户名trim非空、角色合法；门槛1 | 401 AUTH_UNAUTHORIZED/EXPIRED/SESSION_REVOKED/USER_DISABLED/USER_INVALID；低角色403 AUTH_INSUFFICIENT_PRIVILEGE；内部错误500 AUTH_INTERNAL_ERROR |
| AdminAuth / RootAuth | 同上，门槛10/100；管理写操作自动审计且避免重复；不能仅凭JWT role | 同UserAuth；permission不替代角色门槛 |
| TryUserAuth | 无匹配凭据可匿名；已识别但非法的内部JWT不得降级；有效凭据写上下文 | 错误仍走dashboard映射，不能吞成匿名 |
| TokenOrUserAuth | 内部JWT走会话验证；opaque只走APIKey，绝不PAT fallback | dashboard或TokenAuth对应envelope |
| TokenAuth | tokens.key及owner；有效状态、期限、额度、IP、组；传递模型/额度/重试限制 | 无效401；DB500；封禁/IP/组/指定渠道越权403，OpenAI envelope |
| TokenAuthReadOnly | key存在、未软删、owner enabled；允许过期/耗尽，**明确disabled仍拒绝**（注释与实际代码冲突，以309行分支为准） | 缺key/无效/disabled 401；owner禁用403；DB500；`{success:false,message}`，无code |
| RequirePermission | 必须在认证之后，使用当前user_id/role，不信任输入 | 403 `{success:false,message:<权限不足翻译>}`，无code |

Dashboard错误均 `{success:false,code,message:<原国际化键翻译>}`。JWT识别用issuer=new-api、audience包含new-api-dashboard、known token_use；识别后签名/用途/期限失败终止，不能换PAT/APIKey重试。JWT HS256，派生key=HMAC-SHA256(SessionSecret, `new-api/auth/<purpose>/v1`)；access=15分钟，proof=5分钟，会话=30天，refresh replay window=30秒；claims包含sub/sid/uv/sv，role/status/group必须读当前用户。proof不是access，不得调用UserAuth；PAT无sid，不能管理浏览器会话或签发session proof。

成功dashboard保留响应头 `Auth-Version: 864b7076dbcd0a3c01b5520316720ebf`；类型化上下文投影旧键username/role/id/group/user_group/use_access_token/session_id/auth_version/session_version，PAT use_access_token=true。只读APIKey仅有id/token_id/token_key；不得伪造session或admin上下文。

Token完整校验：status必须enabled；expired_time=-1无限，否则`expired_time < now`拒绝（等号边界不能改）；非unlimited且remain_quota<=0拒绝。无Redis时原实现尝试把状态改expired/exhausted；P2仓储保留这一可观察状态转换，但不扣款。allow_ips非空时按可信客户端IP/CIDR验证。token.group非空须属于用户可用组且存在倍率配置，auto例外；生成using_group，不覆盖原user_group。auto_groups非法JSON按空列表并记脱敏错误。模型限制为明确enabled+集合，不把空集合解释成无限制。key后缀指定channel仅owner管理员允许，否则403并附 `specific_channel_version: 701e3ae1dc3f7975556d354e0675168d004891c8`。

P2仅冻结凭据入口，不实现转发：普通Authorization支持原Bearer/bearer、sk-与后缀拆分；兼容路径上的WS subprotocol、x-api-key、Gemini query key/x-goog-api-key、mj-api-secret优先级依 `authenticate.go:344–399`做纯提取fixture，不能全局接受这些header给dashboard鉴权。OpenAI拒绝体=`{error:{message:<含request-id>,type:"new_api_error",code:""}}`；IP白名单拒绝使用access-denied原错误码，勿强行统一为dashboard envelope。

## 4. 逐接口装配及错误边界

所有/api路由继承GlobalAPIRateLimit；链顺序严格按 `transport/compose/register_api.go`，Axum layer执行逆序不能改变首个错误。CR=Critical、B=匿名body上限、TS=Turnstile、NC=no-store、U=UserAuth、OG=Origin guard。

| method path | 本阶段链/状态责任 |
|---|---|
| GET /api/setup | 公共；响应精确沿用contracts §0.1；DB故障不可当未初始化 |
| POST /api/setup | B；root/setup唯一事务争用必须只有一个成功；mode配置与root创建不能以部分成功发布；兼容200业务envelope，具体既有文案沿用§0.1 |
| GET /api/status | 公共；按真实已接线能力声明，OAuth/Passkey等未实现不得报启用 |
| POST /api/user/login | CR→NC→B→TS；用户名/密码错误与DB错误沿用contracts §0.2；有2FA只发5分钟flow，不发access或refresh cookie |
| POST /api/user/login/2fa | CR→NC→B；body code/flow_token；flow purpose/user/auth_version/未消费/期限及当前enabled全部验证后消费并签发 |
| POST /api/user/auth/refresh | OG→CR→NC；Cookie+可选X-Auth-Session；401/409/429/500精确映射沿用contracts §0.3，绝不转200 |
| POST /api/user/auth/logout | OG→CR→NC；期望SID与cookie/access不符409 AUTH_SESSION_MISMATCH且不清cookie；有效access按其SID撤销，仅同SID cookie清除；无access无cookie时清cookie并200 success/message；cookie分支撤销失败不假成功 |
| GET /api/user/sessions | U→NC；还必须browser session，PAT403 AUTH_SESSION_REQUIRED；成功data数组 |
| DELETE /api/user/sessions/:sid | U→NC；空sid400 AUTH_SESSION_ID_REQUIRED，非所属/不存在404 AUTH_SESSION_NOT_FOUND；成功data={revoked_sid,current}；只清匹配SID cookie |
| POST /api/user/sessions/revoke-others | U→NC；必须browser session；成功data.revoked_count，不接受请求body指定user_id |
| GET /api/verification | EV→TS；query email，规范化并检查domain/alias/regex与占用；200 success/message或业务错误 |
| GET /api/reset_password | CR→TS；query email，格式非法业务失败；存在/不存在/重复邮箱及邮件失败对外相同200 success=true/message=""，防枚举 |
| POST /api/user/reset | CR→B；body email/token；purpose=r，成功data为新随机12字符密码，不是输入新密码；无自动登录，不清2FA；业务失败200 |
| POST /api/user/register | CR→B→TS；RegisterEnabled与PasswordRegisterEnabled；trim用户名、NormalizeEmail、字段校验、唯一性、purpose=v；只从白名单字段构造普通用户，拒绝role/status/quota/PAT等批量赋值 |
| POST /api/verify | U→CR→NC；另要求browser session，否则401 `{success:false,message:"当前认证方式不支持安全验证"}`；body method/code/scope，2FA方法+白名单scope；返回proof_token/expires_at/method/scope，错误业务200 |
| GET /api/user/2fa/status；POST /api/user/2fa/{setup,enable,disable,backup_codes} | U，POST另NC；所有者来自认证；setup不直接enabled，enable/disable/regen必须验证；已有2FA登录闭环及安全状态版本推进不得延后P2 |
| GET /api/user/token | U→CR→UserCritical(access-token)→NC；PAT生成/轮换不是APIKey签发，必须使旧PAT立即失效 |

session错误统一 `{success:false,code,message:<HTTP StatusText>}`：limit409 AUTH_SESSION_LIMIT、issuance429 AUTH_SESSION_ISSUANCE_LIMIT、mismatch409、race409 AUTH_REFRESH_RACE、expired401 AUTH_TOKEN_EXPIRED、revoked401 AUTH_SESSION_REVOKED、invalid401 AUTH_UNAUTHORIZED、其他500 AUTH_INTERNAL_ERROR。session handler的record-not-found映射401 UNAUTHORIZED，与dashboard middleware的SESSION_REVOKED不同。

Cookie固定new_api_refresh、Path=/api/user/auth、HttpOnly、SameSite=Strict、Secure按配置、无Domain；refresh secret不进JSON。缺cookie/invalid/revoked清cookie；mismatch/race/内部错误不清。清除MaxAge=-1/Expires=Unix(1,0)。成功、失败及链上提前拒绝的NC头分别按Go路由顺序做fixture，不假设所有拒绝都有no-store。

初始化将mode与root/setup成功原子发布是满足P2并发目标的实现约束；旧实现在事务外写mode的部分失败行为不得作为正确性目标。若需改变既有失败文案/外部重试语义，作为差异单独审批，不默改既有envelope。

## 5. Origin / CORS

`security/authorize_origin.go`：OG只装refresh/logout，不放relay。Secure=false原行为跳过；生产必须显式评估该开关，不能靠伪造X-Forwarded-Proto开启。Secure=true接受一个规范化Origin；重复、逗号拼接、null/非法拒绝；有Origin但非法不能退Referer；缺Origin才接受一个Referer并提取scheme+host，拒绝userinfo。与真实transport TLS+Host构造origin或SessionCookieTrustedURLs精确比较；不信任客户端forwarded scheme。

拒绝403 `{success:false,code:"AUTH_ORIGIN_FORBIDDEN",message:"request origin is not allowed"}`。OG不加CORS。`fiberadapter/router.go:379–407` 的CORS仅显式挂载组：无Origin或http(s)://同host不加头；跨源原样输出Allow-Origin=*、Allow-Credentials=true；预检204、Allow-Headers=*，methods/max-age沿原常量。该历史组合不等于浏览器允许携带cookie，也绝不能扩散到auth组或改成反射任意Origin。P2保留APIKey只读挂载边界；未来调整CORS需明确兼容变更，而非使用Tower默认配置偷偷改变。

## 6. Casbin与数据字段

字段全集复用schema §2、§6；本阶段读写必须覆盖：users的id/username/password/role/status/group/deleted_at/access_token/auth_version；tokens的key/status/expired_time/remain_quota/unlimited_quota/model_limits_enabled/model_limits/allow_ips/group/auto_groups/cross_group_retry/deleted_at；user_sessions的sid/user_id/version/user_auth_version/status/refresh_hash/previous_refresh_hash/previous_valid_until/expires_at/revoked_at/revoked_reason及审计时间字段；auth_flows的token_hash/purpose/user_id/session_id/payload/expires_at/consumed_at。保持整数额度、Unix秒和NULL语义，不把上述text列改JSON数据库类型。

2FA的secret不是因json隐藏就可宣称加密；读取旧格式及备份码hash必须兼容fixture，不先做有损加密迁移。TwoFA failed_attempts/locked_until/last_used_at和backup is_used/used_at必须持久化，不能用进程内map代替锁定/消费。

policy持久化由identity拥有：casbin_rule ptype/v0…v5复合唯一；ptype=p时v0=subject、v1=resource、v2=action、v3=effect，空effect视allow；subject精确 `user:<id>`、`role:admin/root`。authz_roles现有key/name/description/built_in/enabled/sort/time保持，不能据表推导不存在的动态角色分配：实际resolve按system role>=100 root、>=10 admin、普通用户无policy角色。

决策顺序固定：无角色deny；root superuser直接allow；非root未知permission deny；enforcer未初始化deny；用户显式deny优先allow；用户无覆盖才角色基线allow并集。不要仅调用Casbin `some allow` matcher，它不等于外层override语义。权限集合：system.settings；channel.read/operate/write/sensitive_write/secret_view。admin默认前三项channel允许，settings/sensitive_write/secret_view默认不允许；root全允。P2完成决策器、表读取及权限变化生效；P3才扩展策略管理HTTP，不删P2策略测试。

## 7. 一致性、撤销与Redis

**首批可实施的正确性基线**：认证敏感数据直接查主库，不启用授权正向缓存；permission每请求读取一致快照并纯函数求值。该内部性能选择避免把上游policy定时同步误宣称即时撤销；不是删除Redis限流支持。状态变更提交后开始的新请求不得看到旧grant，已通过鉴权的在途请求不承诺回溯撤回；敏感写事务提交前按expected auth_version复核。SQLite用写事务串行化/CAS，PG用行锁/CAS，不用无锁“先查后写”；锁序用户→会话/flow→2FA消费记录，争用不得双签发。

缓存优化可在P2内递增，但不得降级撤销语义：上游 `cache_user_auth.go`有 `auth:user:fence:<id>` 与 `auth:user:version:<id>`，先pending fence，再DB版本提交，再发布永久单调floor；pending TTL大于旧hash TTL；延迟旧快照不得回填覆盖。只做DEL/TTL不够。Redis失败时查权威DB或拒绝，不可使用过期allow。撤销session还须阻止active缓存覆盖revoking/revoked版本；refresh哈希不在session缓存，轮换/重放以DB事务为准。DB失败与不存在区分，禁止返回guest或未初始化。

角色/禁用/删除/密码/2FA变更与auth_version提升同事务；需保留当前会话的安全变更只推进该会话版本并返回新bundle，其余会话失效。PAT轮换查询权威users.access_token；APIKey禁用/软删立即拒绝（只读模式同样拒绝disabled）。P2不把quota从DB快照覆盖Redis原子预扣值，P4接管额度写入。

refresh轮换必须覆盖current hash、previous hash在30秒窗口、并发相同后继secret、窗口外reuse撤销、version变化与会话数量/签发速率约束。不能把所有旧refresh统一允许，也不能把正常race误作窃取；算法与字节fixture由identity从 `authenticate.go`/`session_store.go`闭环。旧session共享是P2验收门槛，若不能兼容必须先批准重新登录策略。

## 8. 限流与旁路风险

`middleware/limit_rate.go`：Redis `rateLimit:v2:ip:<GA|GW|CT|EV>:<clientIP>`；用户 `rateLimit:v2:user:<UC:scope|SR>:<id>`。单Lua原子INCR/首次EXPIRE/补无TTL/读取TTL/判count>max，固定窗口且拒绝也计数；不得偷偷换滑动窗口。Redis关闭时原内存时间队列滑动窗口，线程安全实现且有界清理，不能把两模式误当同算法。一般超限空body429+正TTL Retry-After；Redis错误空body500且终止，不静默fallback。用户限流须在U之后，缺id空body401。

EV特殊：每IP 30秒2次；Redis失败退本机限流；拒绝429 `{success:false,message:"发送过于频繁，请等待 N 秒后再试"}`，本机文案“发送过于频繁，请稍后再试”，不自动加普通限流Retry-After。该降级不是全局多实例配额保证；保持语义并暴露退化监控，不能以它保护所有敏感操作。GA/CT/SR及开关从原配置读取，不另硬编码统一值。多实例共享限流必须Redis；配置Redis开启却未就绪不能伪装全部安全能力可用。

TS按原query turnstile和站点验证endpoint，提交secret/response/remoteip；开启且缺token返回200 false/“Turnstile token 为空”；校验失败200 false/“Turnstile 校验失败，请刷新重试！”；网络/解码失败不放行。Rust加超时和响应上限，不能把外部错误中的secret直接返给用户。

注册：验证码函数实际截取UUID hex **6字符，不保证十进制**，原注释“6-digit”不可靠；TTL10分钟，purpose=v与reset r隔离。注册只落cleanUser，email仅在验证开关开启时保留；默认APIKey开关、默认组与邀请初始权益由identity保留主计划既有业务，不扩展P4资金管理API。检查username包括软删用户；邮箱歧义不可任意选一人。

重置：原VerifyCode仅比较而Delete在成功后，存在并发重复消费窗口；本阶段必须以一次性claim/CAS阻止两个成功重置，失败不得重放已完成写。推荐复用auth_flows的purpose隔离和DB原子消费（旧内存验证码不跨进程/重启恢复，活跃挑战切换需记录边界）；验证码存hash、不存日志。不得让密码重置清除2FA或直接发会话。

2FA：flow携带auth_version，成功前重新验证用户状态与版本，目的不是普通安全proof；检查失败不发bundle。flow一次消费、备份码一次消费与锁定计数须两库并发测试。TOTP last_used_at是使用时间，不等于已证明同时间步防重放；同码能否跨flow重用必须独立fixture，不能宣称上游有不存在的replay保障。P2至少保证同flow不会双登录、备份码不会双消费。生产dev免密登录路由不得挂载；未实现OAuth/Passkey不可绕过既有2FA账户。

## 9. 必需依赖与首批切片

复用P1已锁Axum/Tokio/Tower/Serde/SQLx/Reqwest/tracing；新增候选仅限bcrypt（兼容旧密码与备份码散列）、JWT HS256库、hmac/sha2、uuid安全随机、常量时间比较、TOTP实现、CIDR解析、Redis Tokio客户端、SMTP适配。Casbin Rust库可复用，但必须保留上述override解析器；若采用小型显式求值器，须证明同一casbin_rule语义且不得改表。所有新版本由集成者远程解析锁定，不在本文虚报版本/MSRV/编译可用。密码边界、bcrypt版本前缀、TOTP窗口等由identity以旧fixture冻结，禁止默认库参数代替原算法。

**首批必须实现**（顺序固定）：
1. identity公开错误/Principal/TokenGrant端口与SQLite/PG权威只读仓储；JWT/PAT/APIKey用途隔离及session验证，先不缓存。
2. security User/Admin/Root/Try/Token/ReadOnly/Permission纯决策及原错误映射；Origin纯函数；server按原路由顺序装配。Casbin规则逐项golden fixture，包含disabled只读key和PAT session拒绝。
3. Redis固定窗口原子适配+无Redis本机模式+EV特殊fallback；可信IP、CORS作用域与脱敏契约。
4. 接identity会话变更/refresh/注册重置/2FA端口完成闭环，并验证撤销、争用、状态声明；不得以首批完成标P2通过。

**可阶段内递增，P2结束前不可缺**：授权缓存fence优化不是首批前置；邮件/Turnstile可先mock后真实适配，但能力开关只能在真实适配完成后启用；2FA安全管理与proof、默认令牌、初始化竞争/刷新race、status全字段声明与两库故障矩阵需在P2终验闭环。P3权限CRUD/P5转发不前移。

验收仅后续获授权Actions：SQLite+PG两库、Redis启用/关闭/故障、多实例禁用/降权/删除/PAT轮换、旧快照回填、refresh并发重放、跨用户SID、错误envelope/header/order、purpose混用、匿名注册批量赋值、邮箱歧义/重复消费、2FA flow版本/备份码竞争。需绑定精确SHA/run ID与独立结论；本文件是实施契约及差异风险记录，不是这些测试已通过的证据。
