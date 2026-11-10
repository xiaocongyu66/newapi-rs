# P2 密码认证与会话实现契约

2026-11-02；源码基线 `17970da4571e81308f176a0e61a38276e5771606`。状态：P2 进行中，以下原始契约不代表所有能力已实现。

## 分批验收记录

- 身份纯算法、setup 仓储当前测试及 security 纯决策：独立限定 PASS，提交 `72cf7c93a3a9d5d7ce7eb45063d8b0f3f7da4f69`，Actions run `41469554946` attempt 1。PG9.6/17 各46个 workspace 测试通过，无失败/忽略；fmt/check/clippy 与已提交根锁验证通过。Go crypto 与40个 Origin 输入均实际生成并由Rust消费；主执行者抽查状态、测试统计及锁摘要一致。
- 会话 DB 仓储及显式撤销 fence 端口：提交 `3656ce2293cfea935c5d419d634bd7e89c5db7c3`，尚待远程及独立验收；不包含真实 Redis active-cache/Lua/TTL、users 缓存栅栏或认证 HTTP 接线。
- `23e84de` / run `41587051202` 虽通过两个矩阵各72项测试，独立复核仍为 FAIL：注销存储错误回退、列表故障误401、Origin非法头值丢弃、终态fence报告丢失。后续安全修复已在 `1be491c` / 普通push run `41596516959` 独立限定PASS；两个矩阵各77项通过、0失败0忽略，fmt/check/clippy及已提交根锁验证通过。三个会话端点已从生产router移除，仅供隔离测试。SelfUser、限流和完整UserAuth保护补齐前不得重新开放，不增加运行期开关绕过。
- 会话编排（refresh/logout/identify/sessions）+ 三个会话端点（以下描述实现草稿，不代表已开放）：提交 `6bb5da6` 及后续，尚待远程与独立验收。端点已接线 Cookie（`new_api_refresh`、Path=`/api/user/auth`、HttpOnly、SameSite=Strict、Secure 可配）、Secure 模式 Origin 守卫、错误码映射。**未完成**：响应未包含 `user:SelfUser` 投影（依赖未移植的权限/额度端口）；`GET /api/user/sessions` 未区分 UserAuth 401 与缺 browser-session 403 `AUTH_SESSION_REQUIRED`；DELETE/revoke-others 正在追加隔离实现及所有权/Cookie范围回归，尚未验收或开放；限流、Turnstile、login/2FA 仍由相邻切片负责。Redis 仅在配置 `REDIS_CONN_STRING` 时启用，连接失败终止启动而非静默降级。
- 未关闭问题：run `41464623155` 中 SQLite setup 全量测试曾出现失败。后续诊断和格式提交中未复现，尚无根因和生产修复证据；保留测试与安全动作/错误码诊断，禁止将单次绿灯标为修复。
- 会话元数据 UTF-8 截断兼容边界仍待决定；不将内部 `MetadataEncodingUnsupported` 直接映射为HTTP 400，也不静默丢弃或替换原数据。
- 本记录不是整个P2验收。登录、刷新、注销及会话管理端点必须在权威会话/用户状态与撤销链完整接入后开放；后续邮件、验证码、2FA、API Key、权限、限流等仍依主计划完成。

## 1. 边界与输入

已先读 `/root/newapi-rs/docs/rust-backend-migration-plan.md`、`schema-inventory.md`、`contracts-inventory.md`，复用其 users/token/schema 清单及登录 envelope，不重做全仓研究。历史台账中的“P0受阻/P2未开始”不是当前阶段状态；主计划与用户确认优先：P1 PASS，P2 获批。

本切片拥有密码校验、dashboard JWT、refresh/logout、会话持久化/撤销/墓碑和六条会话相关 HTTP 契约。初始化、注册/验证码、重置密码、2FA完成流程、策略/API Key/限流完整实现及 status 声明由 P2 相邻切片负责，并通过下述端口接入，**不是取消或挪出 P2**。不开展 OAuth/Passkey 提供商实现（主计划 P7），但保留 security_proof 用途隔离。Rust 1.99.1、Edition 2024，模块化 workspace；主库仅 SQLite/PG，无 MySQL、无 Moka。原仓只读；本轮仅写本文，不修改 Cargo，不构建、不测试、不执行脚本、不提交推送。

下文 B=`/root/newapi/apps/api/internal/`，W=`/root/newapi/apps/web/src/`，用于定位证据，不作为新仓 CI 运行依赖。

## 2. HTTP 冻结

路由证据 B`transport/compose/register_api.go:127–151`；handler B`identity/manage_users.go:29–206`、`manage_sessions.go:16–179`。

成功一般为 HTTP 200 `{success:true,message:"",data:...}`。登录的业务错误仍 HTTP 200 `{success:false,message:<翻译或错误文本>}`，**不能统一改成401**；会话错误则用下表 HTTP/code，无 data，message 为标准 HTTP reason phrase。

|方法/路径|请求与成功 data|拒绝/副作用|
|---|---|---|
|POST `/api/user/login`|JSON `username,password:string`，缺失默认空；query `turnstile`。正常 data=AuthBundle+user|开关关闭 MsgUserPasswordLoginDisabled；绑定/空字段 MsgInvalidParams；DB错误 MsgDatabaseError；不存在/错密码/禁用 MsgUserUsernameOrPasswordError。2FA查询失败为DB错误。2FA开启返回 `{require_2fa:true,flow_token,expires_at}` 和 MsgUserRequire2FA，5分钟，不创建完整登录会话、不写 refresh cookie；flow创建失败走200错误。正常 SetupLogin 重新查用户，禁用/非法ID MsgAuthUserBanned，查询失败返回错误文本；创建会话失败走会话错误映射；成功更新 last_login_at、审计、写cookie。|
|POST `/api/user/auth/refresh`|无JSON绑定；cookie `new_api_refresh`；可选 `X-Auth-Session`；成功 data=AuthBundle+当前user|缺cookie/invalid/revoked清cookie；mismatch/race/内部错误不清。SID比较先于会话读取。|
|POST `/api/user/auth/logout`|无JSON绑定；可选 Bearer、cookie、`X-Auth-Session`|合法cookie SID与期望不同先409，不能清cookie。可解析access优先：再检查期望SID，按user+SID撤销，返回 `{revoked_sid,cookie_cleared}`；只有cookie SID相同才清。access不可解析（包括过期）回退cookie；缺cookie/空cookie/畸形refresh均幂等200，无data，清cookie；合法refresh须验证secret才能撤销。不能凭SID撤销、不能清另一会话cookie。|
|GET `/api/user/sessions`|UserAuth后必须browser session；data=SessionView数组|按当前用户auth_version、active、expires_at>now过滤；当前SID置首，其余last_active_at DESC、created_at DESC；总上限100。|
|DELETE `/api/user/sessions/:sid`|trim sid；data=`{revoked_sid,current:bool}`|空SID 400/AUTH_SESSION_ID_REQUIRED，message=`session id is required`；非本人/不存在/不活跃404/AUTH_SESSION_NOT_FOUND，message=`session not found`。cookie SID相同才清。|
|POST `/api/user/sessions/revoke-others`|data=`{revoked_count:int64}`|只撤本人且SID非当前的活跃会话；批次失败可已部分成功，不能报告全部成功。|

后三条缺 browser-session context 均403/AUTH_SESSION_REQUIRED，message=`a dashboard login session is required`；PAT通过UserAuth不等于能管理browser session。UserAuth前置错误由security切片负责，不能跳过。

会话错误：409 `AUTH_SESSION_LIMIT`（活跃数）、429 `AUTH_SESSION_ISSUANCE_LIMIT`（发行数）、409 `AUTH_SESSION_MISMATCH`、409 `AUTH_REFRESH_RACE`、401 `AUTH_TOKEN_EXPIRED`、401 `AUTH_SESSION_REVOKED`、401 `AUTH_UNAUTHORIZED`（refresh/JWT invalid及record not found）、其余500 `AUTH_INTERNAL_ERROR`。注意未显式映射的 LoginSessionInvalid/存储Inactive 不能擅自全部改401。500不得泄露SQL、secret。

### Bundle、user 与头

AuthBundle公开字段 `access_token:string,token_type:"Bearer",access_expires_at:int64,session:SessionView,user:SelfUser`；refresh_token永不出现在JSON。SessionView：`sid,login_method,ip,user_agent:string; current:bool; created_at,last_active_at,expires_at:int64`，时间均Unix秒。

SelfUser以 B`identity/manage_users.go:526–588` 为唯一装配源，不序列化整个users行。字段全集复用 `/root/newapi-rs/docs/contracts-inventory.md:66`。id/role/status/quota/used_quota/request_count/aff_count/aff_quota/aff_history_quota/inviter_id为整数；四项`*_display`为数值；username/display_name/email/各外部id/group/aff_code/setting/stripe_customer为字符串；sidebar_modules从setting解析；permissions含sidebar_settings、sidebar_modules、admin_permissions。后两者必须由策略切片真实投影，不用空对象伪装已有权限；额度展示由展示端口提供，不能自行假定单位。B`identity/quota_display_hook.go:20–25`无hook才回退float64(quota)。不得输出password/access_token数据库字段/auth_version。

DisableCache中间件设 `Cache-Control:no-store, no-cache, must-revalidate, private, max-age=0`、`Pragma:no-cache`、`Expires:0`；refresh/logout及完整登录handler将Cache-Control覆盖为`no-store`。错误被前置Origin/限流截断时不可保证已经执行DisableCache。

Cookie固定Name=`new_api_refresh`、Path=`/api/user/auth`、HttpOnly、SameSite=Strict、无Domain，Secure来自SessionCookieSecure。Expires取未来session.expires_at，否则now+30天；MaxAge=floor(remaining秒)，至少1；删除value空、MaxAge=-1（HTTP编码删除）、Expires=Unix秒1。会话到期是固定30天，refresh不续期。

### 必需前置保护及前端依赖

refresh/logout顺序OriginGuard→CriticalRateLimit→DisableCache；login顺序CriticalRateLimit→DisableCache→anonymousRequestBodyLimit→Turnstile。secure模式OriginGuard：单一合法Origin优先，否则仅在Origin缺失时取单一Referer的scheme+host；拒绝多值/逗号、非法来源；匹配实际TLS+Host或可信URL列表，不信X-Forwarded-Proto。拒绝403 `{success:false,code:"AUTH_ORIGIN_FORBIDDEN",message:"request origin is not allowed"}`；insecure模式跳过，不额外加CORS（B`security/authorize_origin.go`）。

Turnstile开启时缺query返回200“Turnstile token 为空”，验证false为200“Turnstile 校验失败，请刷新重试！”，网络/解码失败200错误文本；均success:false。站点验证出站通过mockable端口，禁止上线时恒true。限流接口由security切片交付：CT共享IP桶；Redis key=`rateLimit:v2:ip:CT:<clientIP>`，INCR/EXPIRE/TTL同Lua固定窗口，不改滑动窗口；Redis失败500，超限429+Retry-After，不混同会话发行429。body限制/全局限流和UserAuth应由集成者沿既有路由配置接入，本文不重复其独立契约。

W`features/auth/api.ts:43–54,104`发送密码登录并skipAuthRefresh、logout带SID；W`features/profile/api.ts`消费sessions。W`lib/auth-session.ts:209–340`：401清认证并跨tab同步；网络/5xx/429保持transient；409 race依次80/200/500ms重试后out_of_sync；409 mismatch清本地、不广播、无期望SID重试一次。使用navigator.locks与refreshPromise合并。服务端必须保留code和cookie条件，不能将409都变401。

## 3. 密码与JWT算法（字节级）

证据 B`common/crypto.go:17–37`、`identity/store_users.go:915–939`、`authtoken/authtoken.go`、`identity/authenticate.go`。

密码：仅trim用户名（支持username或email），不trim密码；查询`(username=? OR email=?) AND deleted_at IS NULL`，保留GORM First主键优先语义；空password存储是无密码账户，必拒绝。新hash为bcrypt DefaultCost=10；校验现存bcrypt，登录不自动rehash。当前基线**没有MD5/SHA1/plaintext旧hash回退**，不得为“旧哈希兼容”自行增加弱算法。Rust须针对Go接受的历史bcrypt版本、cost、UTF-8字节、NUL及72字节边界做差分；新建hash>72字节遵循Go报错，verify长输入语义不能靠Rust库默认猜测。未能匹配的历史hash是明确阻塞，不以强制全员重置替代。

令 `K(p)=HMAC-SHA256(key=UTF8(SessionSecret), data=UTF8("new-api/auth/"+p+"/v1"))`，结果是原始32字节，不是hex。JWT仅HS256：access key=K("access")，proof key=K("security_proof")；标准JWT base64url无padding。

access claims：`token_use="access",sid,uv:i64,sv:i64,iss="new-api",sub=十进制userID字符串,aud=["new-api-dashboard"],exp=now+900,nbf=now-5,iat=now,jti=UUIDv4`。proof TTL=300，token_use=`security_proof`，另带trim后非空method及非空scopes；其余身份claim同上。JWT不带role/status/group授权快照。

验签必须限定HS256、issuer/audience匹配、exp必需，验证iat/nbf并使用5秒leeway；iat、nbf必须存在，jti非空，token_use正确；userID/uv/sv>0、sid非空。access解析不强制SID为UUID（原测试用session-1），只有refresh格式强制UUID。proof绑定userID/SID/uv/sv，scope精确成员匹配，allowedMethods为空代表不限制method；比较使用常量时间。proof不是一次性消费令牌，不能自创jti消费表。

Dashboard分类先不验签读claims：issuer、aud、已知token_use符合即internal=true；随后验签/用途/期限失败**不得回退PAT/API Key认证**。同secret+schema的旧Go会话应可共享；不得擅自轮换SessionSecret或要求重登。

refresh初始secret为crypto RNG均匀抽取64字符，字母表`0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ`；SID UUIDv4。raw=`sid.secret`，整体trim后分第一个点，secret非空且无其他点，UUID按Go解析兼容。`refresh_hash=lowerhex(HMAC-SHA256(K("refresh"),secret))`；`nextSecret=lowerhex(HMAC-SHA256(K("refresh-rotate"),sid+"."+currentSecret))`。因此同一输入确定性地产生同一nextSecret，race可幂等收敛。常量时间比较hash。

## 4. DB、事务、撤销与重放

完整字段/索引以 `/root/newapi-rs/docs/schema-inventory.md:61–65` 为基表，本文冻结物理列：

- `user_sessions.sid varchar(64)` PK；`user_id`整数NN；`version bigint NN default1`；`user_auth_version bigint NN`；`status varchar(16) NN`（active/revoking/revoked）；`refresh_hash char(64) NN`；`previous_refresh_hash varchar(64)`可NULL；`previous_valid_until bigint NN default0`。
- `login_method varchar(32) NN,ip varchar(64),user_agent text`；`created_at`Unix秒；`last_active_at,expires_at bigint NN`；`revoked_at bigint NN default0,revoked_reason varchar(64)`。除已列NN/default，不凭Go零值虚构DDL。previous NULL→空，读取TrimSpace以兼容旧CHAR填充。
- 索引：`idx_user_sessions_user_status_expiry(user_id,status,expires_at)`、`idx_user_sessions_user_created(user_id,created_at)`、`idx_user_sessions_status_revoked(status,revoked_at)`、`idx_user_sessions_expires_at(expires_at)`。无新增FK/软删除列。SQLite/PG分别绑定参数/DDL；未经授权不自动迁移生产库。
- users复用原字段，关键 `password,deleted_at,status,auth_version(bigint NN default1),last_login_at`；不可把全局auth_version和会话version合并。

创建：用户enabled、auth_version>0，指定expected_auth_version时必须相等；active数量计所有auth_version、status=active且expires_at>now；发行数计所有状态created_at>now-window。默认50活跃、100发行/86400秒，配置来源B`common/constants.go:43–53`、`init.go:140–162`（发行窗口不超过撤销保留期）。计数DB失败闭锁。初始version=1，expires=created+30天；login_method trim空变unknown；IP/UA trim后按Go字节截64/512。签token失败尝试以token_issue_failed撤销。原计数→INSERT不在同一事务，不能宣称已有并发硬上限；Rust若增强为用户锁内计数+创建，应标明安全强化并补两库竞争fixture。

验证access：必须查询session且userID、active、revoked_at=0、expires_at>now、sv、uv全部匹配；再加载当前用户enabled与auth_version。仅验JWT不成立。权限变更通过用户认证版本/缓存栅栏端口生效，不能等access自然过期。

refresh会额外同时核用户cache和DB当前行；禁用/uv不匹配尝试以user_security_changed撤销。轮换实际是**非包裹事务的最多3次读取+CAS**（不要误称整段事务）：WHERE sid,user_id,status=active,revoked_at=0,expires_at>now,refresh_hash=presented；成功写previous_hash=current、previous_valid_until=now+30、refresh_hash=next、last_active_at=now，**不增加version、不延长expires**。CAS零行重读；三次落空返回invalid。返回视图IP/UA会被新请求覆盖但轮换SQL不持久化这两列。

呈现current hash→轮换；呈现previous且now<=previous_valid_until→存储race；应用层若推导next hash等于当前hash，则成功返回同一next refresh；否则409。previous已过宽限→先发布revoking墓碑，再以active条件撤销整个SID，原因refresh_reuse；即使并发再轮换也撤销。未知/更老hash仅invalid，**不能撤销受害会话**；只保存一代previous，不宣称识别无限历史。

单SID撤销：按user+sid查候选→发布revoking→DB事务重读（PG FOR UPDATE，SQLite无同类行锁，靠条件更新/事务）→status revoked/revoked_at/reason→提交→终态墓碑。不存在/失活返回false。cookie-only logout在事务内校验current或宽限内previous hash后发布墓碑并更新；秘密错误返回false但handler仍幂等成功。Redis fence失败不进行撤销DB写；DB失败后的临时deny不提前移除，允许TTL后恢复。终态缓存写失败记录错误但已提交撤销不回滚。

批量按SID排序，每批500，先逐个fence，再事务重读active并更新；失败返回累计进度供重试。安全设置更新：用户auth_version先递增；保留当前SID须CAS expected uv/sv，将version+1、user_auth_version=new、last_active_at=now；撤销其他会话并签新access（没有新refresh时不写空cookie）。密码更新应与users.auth_version递增同事务，再调用保留/撤销端口；并非一个跨DB/Redis全局事务。

## 5. Redis共享协议（非可选正确性细节）

证据 B`identity/session_store.go:71–394`；`cache_user.go:48–53`。禁Redis可直接查DB；启Redis miss/读失败可回DB，但命中deny绝不回源放行。

key=`auth:session:`+lowerhex(HMAC-SHA256(key=UTF8("user-session-cache-v1:"+SessionSecret),data=SID))。

Redis HASH字段严格为Go大写名 `SID,UserID,Version,UserAuthVersion,Status,LoginMethod,IP,UserAgent,CreatedAt,LastActiveAt,ExpiresAt,RevokedAt,RevokedReason,CacheSchema`（schema=1）；整数十进制。**无RefreshHash/PreviousRefreshHash/secret**。读需校验schema、SID、正ID/版本，再校验状态/到期。

缓存窗口C=RedisKeyCacheSeconds，<=0回退60秒。active快照在权威DB读取/修改**之前**捕获deadline=now+C；Lua HSET后PEXPIREAT=min(deadline,session expiry)毫秒绝对时间，不在迟到回填时重启TTL。写前窗口耗尽/<1ms或写后已过deadline视stale，回查DB完整active+sv+uv条件确认；已到期拒绝。

deny TTL=min(session剩余,C)，<=0取1秒，PEXPIRE相对毫秒。Lua原子检查：已有revoking/revoked拒绝active覆盖；已有Version>incoming拒绝降版本；否则HSET+到期。Lua拒绝映射Inactive。无需跨Redis与SQL分布式事务，但上述顺序不可倒置。独立Redis实例仅保证短缓存TTL后收敛，不能承诺跨独立Redis即时撤销；共享Redis先fence保证热缓存拒绝。users认证缓存的pending fence/committed floor也必须由相邻切片实现，session墓碑不能替代它。

## 6. 最小Rust公开边界与新增依赖建议

建议新增 `crates/identity` 内部分 `password/token/session/service/repository`，公开DTO不暴露持久化hash；transport仅负责JSON/cookie/头，repo分别SQLite/PG，无跨域直接访问私有表。固定时钟/RNG/用户策略投影/Redis为可替换端口。

```rust
pub struct AuthIdentity { pub user_id: i64, pub sid: String, pub user_auth_version: i64, pub session_version: i64 }
pub enum LoginOutcome { Authenticated(LoginResult), TwoFactorRequired(TwoFactorChallenge) }
// LoginResult = public AuthBundle + 私有 RefreshCredential + SelfUser投影
impl AuthService {
    pub async fn password_login(&self, req: PasswordLogin, meta: ClientMeta) -> Result<LoginOutcome, AuthError>;
    pub async fn refresh(&self, raw: &str, expected_sid: Option<&str>, meta: ClientMeta) -> Result<LoginResult, AuthError>;
    pub async fn logout(&self, req: LogoutRequest) -> Result<LogoutResult, AuthError>;
    pub async fn authenticate_access(&self, raw: &str) -> Result<AuthenticatedUser, AuthError>;
    pub async fn list_sessions(&self, who: &AuthIdentity) -> Result<Vec<SessionView>, AuthError>;
    pub async fn revoke_session(&self, who: &AuthIdentity, sid: &str) -> Result<bool, AuthError>;
    pub async fn revoke_others(&self, who: &AuthIdentity) -> Result<i64, AuthError>;
    pub async fn advance_current(&self, who: &AuthIdentity, reason: &str) -> Result<AuthBundle, AuthError>;
}
```

签名是集成冻结建议，不是可编译实现。AuthError必须区分BusinessLogin/Invalid/Expired/Revoked/Mismatch/Race/ActiveLimit/IssuanceLimit/NotFound/Internal，handler再按接口映射，不能所有错误统一Unauthorized。LogoutResult显式表达是否带data和是否清cookie；RefreshCredential不derive Debug/Serialize。公开token模块提供issue/parse/classify_dashboard及issue/verify_security_proof；opaque分类不是验证成功。

当前Cargo仅有Axum/Tokio/Tower/Serde/SQLx/tracing。本切片必须补足的能力及建议依赖：`bcrypt`（Go兼容）、`hmac`+`sha2`（派生）、`subtle`（常量时间）、`jsonwebtoken`（严格HS256及claim验证，确认所选版本的crypto backend feature）、`uuid`（v4）、`rand`或`getrandom`（OS随机、无偏字符抽样）、`serde_json`、`redis`（Tokio async+Lua）、`cookie`（严格Set-Cookie）。hex可手写固定编码避免另加依赖。Turnstile通过集成者统一`reqwest`客户端；不重复引入第二HTTP栈。全部版本由集成者按Rust1.99.1/许可证远程解析后精确锁定；本文不凭未运行resolver宣称版本可用，不修改Cargo/lock。SQLx沿用SQLite+PG features，不引入Moka/MySQL或JWT默认宽松策略。

## 7. 首批顺序、fixture与完成条件

**首批必须整体交付**：①password/token纯算法+错误枚举/clock/RNG端口；②两库session repository（含CAS/revoke/字段NULL兼容）；③Redis墓碑协议；④login/refresh/logout真实垂直链路及六路由接线/权限保护。只有①不能宣称登录可用；暂未接2FA不得给已启用2FA用户发完整bundle。首批先冻结SelfUser、UserAuth/权限、配置、2FA challenge端口，避免并行代理各自造用户模型。

**可P2内递增但阶段验收前必须完成**：会话列表/批量撤销UI联调、安全设置保留当前会话、清理/发行告警、两库旧schema差分、完整注册/重置/初始化/API Key/限流/status等相邻切片。清理按B`session_store.go:777–869`保留发行窗口内记录及撤销保留期；扫描1000、删除500、删除时重查predicate，不能删掉计数证据。P2目标不因本文切片变窄而删除。

仅用脱敏合成fixture，来源：

- B`authtoken/authtoken_test.go:14–37`固定secret=`test-session-secret-with-sufficient-entropy`，identity=(42,session-1,uv3,sv2)；沿用purpose isolation/tamper/classification，远程加固定now/jti的Go→Rust/Rust→Go golden，exp/nbf/iat±5秒、alg:none/HS384、aud字符串/数组、缺claim、proof错scope/method。原测试动态now，不是现成静态JWT字符串。
- B`identity/manage_sessions_test.go:247–309`：now+10轮换，宽限到now+40；now+20 previous race，unknown不撤销；now+41 previous reuse撤销；legacy previous CHAR空格/NULL。并覆盖该文件100–196的短TTL/迟到回填/Lua绝对active与相对deny，312的Redis不含hash，372的cookie secret校验，428的列表上限，460的部分批次失败。
- B`identity/authenticate_test.go`：CreateRefreshAndRevoke、IndependentRedisSessionRevokeConvergesAfterCacheTTL、IndependentRedisAuthVersionAdvanceConvergesAfterCacheTTL、UserAuthVersionInvalidatesExistingSession、limits计数失败闭锁。
- B`identity/manage_sessions_api_test.go`：logout mismatch、增长限制错误码和拒绝登录不记成功；B`security/authorize_origin_test.go`：安全/开发模式及伪造forwarded协议。
- B`identity/user_session_migration_test.go:71–143`：nullable varchar、旧CHAR读回规范化、二次迁移无重复DDL；只取SQLite/PG分支，不迁移MySQL测试矩阵。
- 密码从 B`common/crypto.go` 在获批远程Go fixture任务生成，结合 B`identity/store_users_update_test.go:242`无密码账户、`store_users_lifecycle_test.go`重置版本失效；新增bcrypt版本/超长/NUL/Unicode、软删除、同email歧义用例，不能声称现有测试已覆盖这些边界。

远程验收必须实际连接SQLite、PG及Redis，覆盖同一cookie并发刷新、refresh与logout竞争、过宽限replay与并发轮换、fence失败/DB回滚/终态写失败、用户禁用/降权后的旧access、跨用户撤销；断言HTTP JSON/头/cookie和DB最终状态。绑定集成SHA、Actions run ID、退出码、测试/跳过数，独立复核后才PASS。本轮没有任何运行结果，也没有复制真实用户凭据。

## 8. 2026-11-06 登录与会话路由切片状态（待独立复核）

**已通过远程 CI 的实现**（普通 push 的 locked 门禁；独立复核结论尚未回填）：
- 登录垂直切片 @ `2db1e9d`，P1 run `42145672841`：prepare、Go oracle、process differential（9/9、35 http_checks）、verify pg14+pg17 全绿。覆盖 `POST /api/user/login`、`POST /api/user/login/2fa`（密码/2FA pending/2FA 校验/会话签发/最后登录/登录审计/SelfUser 装配）、额度展示快照、`UserProfile.auth_version`、关键路径限流、可信代理客户端 IP、匿名体上限与 DisableCache 三头、Accept-Language 语言解析、Turnstile 决策层接线；`apps/server/tests/{login_http,login_success}.rs` 覆盖中间件顺序、成功登录、2FA pending/错误码/备用码。
- 会话路由注册 @ `aa3b9d7`，P1 run `42147797666`：同样全绿。refresh/logout 按 `Origin → CriticalRateLimit → DisableCache`；sessions 三端点按 `Bearer 校验 → DisableCache`；`session_routes.rs` 覆盖注册、缓存头、来源拒绝、429 与无 Bearer 401。DisableCache 在 handler 之后补齐，成功登录等显式 `Cache-Control: no-store` 不会被覆盖。
- Redis 关键路径限流（Lua 固定窗口，键 `rateLimit:v2:ip:<mark>:<ip>`，mark=`CT`）已随上述 SHA 合入，配置 `REDIS_CONN_STRING` 时替代进程内滑动窗口；`tests/redis_rate_limit.rs` 在真实 Redis 上执行。

**明确未完成，不得视为本阶段通过**：
- Turnstile 只有纯决策层；工作区没有 HTTP client 依赖，**未实现向 Cloudflare 的 `siteverify` 请求**。开关启用时密码登录返回 HTTP 200 `{success:false,message: Turnstile 校验暂不可用…}`（Go 的网络错误也是 200 + message），不会静默放行；补齐传输层前不得宣称 Turnstile 可用。
- Go 默认启用的全局 Web/API 限流（`GLOBAL_WEB_RATE_LIMIT_*`、`GLOBAL_API_RATE_LIMIT_*`）尚未合并；当前仅有关键路径限流。
- 注册、验证码、密码重置、初始化、API Key、`/api/status` 等 P2 项未在本切片。

**验收前置**：上述 SHA 的 fmt/check/clippy/test 已全绿且实际连接 SQLite、PostgreSQL 14/17 与 Redis；仍需独立 verification 按精确 SHA 复核后才可标记通过，届时更新本节。

### 8.1 2026-11-06 全局限流、`/api/status` 与验证者修复 @ `6fe70b2`

**证据绑定（普通 push）**
- Rust SHA：`6fe70b2d633808bda88efbef25cc9e627c410243`（`migration/p2`，`xiaocongyu66/newapi-rs`）
- P1 Rust workspace run `42181685244`，attempt `1`，conclusion `success`
  - https://github.com/xiaocongyu66/newapi-rs/actions/runs/42181685244/attempts/1
  - jobs 全 success：`prepare`、`P2 fixed upstream crypto and Origin oracles`、`Fixed Go oracle and Rust process differential`、`verify (pg14, postgres@sha256:85297aa…, 14)`、`verify (pg17, postgres@sha256:748a18a…, 17)`
- Go upstream oracle SHA：`ec542e7050932b82a2c087004ce54131ea67a836`
- pg14：PostgreSQL 14.24 policy_ok、Redis 7.2.17 policy_ok；fmt/check/clippy exit 0；workspace-tests **302 passed / 0 failed**；`session_cache` 9/0；`origin_matches_go_oracle` 1/0
- pg17：PostgreSQL 17.11 policy_ok；fmt/check/clippy exit 0；workspace-tests **302 passed / 0 failed**；`session_cache` 9/0
- 实际执行的关键用例（pg14 `workspace-tests.log`）：`policy_storage_failure_degrades_to_denied_permissions`、`status_route_serves_the_envelope_over_http`、`global_limit_precedes_critical_limit`、`default_state_without_global_limiter_never_misreports_429`、`format_http_date_matches_go_rfc1123_vectors`、`successful_password_login_creates_session_and_audit_log`
- `P0 inventory consistency` 仍是既有非验收项（exit 2 / undetermined scope items），不计入本切片通过证据。

**本切片新增/修复**
- 全局 API 限流 `GlobalAPIRateLimit`（mark `GA`，默认 `GLOBAL_API_RATE_LIMIT_ENABLE=true` / `360` / `180s`）：`apps/server/src/global_limit.rs` 覆盖 `/api` 与 `/api/*`（含 fallback），先于路由级 `CriticalRateLimit`/会话守卫；超限裸 `429` + `Retry-After`（>0），后端故障裸 `500`，均位于 DisableCache 之前；`AppState::default()` 未绑定限流器时直通，避免误报 429。`apps/server/tests/global_rate_limit.rs` 覆盖 GA 先于 CT、无缓存头、按 IP 隔离、禁用不拒绝。
- `GET /api/status`：`apps/server/src/status.rs` + `apps/server/tests/status_routes.rs`，Go 封套 `{success,message,data}`；AuthSettings/PublicConfig/QuotaDisplay 真实快照透传；未移植子系统输出经逐字段核对 Go 源码的运行时默认值并注释来源/补齐阶段，不把未实现功能标为启用；该路由不挂 DisableCache。
- 验证者 Medium 修复：`crates/identity/src/login/orchestrate.rs` 的 `complete()` 在策略加载失败时降级为 `denied_permissions()` 并记录 `permissions_load_failed`，会话照常签发——对齐 Go `policy.Capabilities()` 从不返回错误的语义（`apps/api/internal/identity/policy/resolver.go:38+`）；刷新 Cookie 补 `Expires`（RFC1123 GMT）并让清除 Cookie 使用 `Expires=Thu, 01 Jan 1970 00:00:01 GMT; Max-Age=-1`，对齐 Go `WriteRefreshCookie`/`ClearRefreshCookie`（`apps/api/internal/identity/authenticate.go:290+`）；登录成功缓存头改为精确断言 `Cache-Control=no-store`、`Pragma=no-cache`、`Expires=0`（此前仅 `contains("no-store")`）。

**仍然明确未完成**
- Turnstile 仍只有决策层，**未实现 `siteverify` 传输层**；开关启用时不静默放行。
- 注册、验证码、密码重置、初始化、API Key 等 P2 其余项未移植；全局 Web 限流（`GW`）未移植。
- GA 在生产组装中使用独立 Redis 连接（Go 共享 RDB），行为等价但连接数 +1，列入后续优化。
- `/api/status` 的 `version` 无 Go ldflags 注入的 `v` 前缀；部分字段为诚实默认值，待 P3/P7 子系统补齐。

**上游基线漂移**
- Go `origin/main` 已从 `ec542e705` 前进到 `a508a866c`（含 #659 Fiber v3 迁移、#668 只读 API 响应缓存、#660 计费截断修复等）。本切片引用的基线文件中，`limit_rate.go`、`init.go`、`authenticate.go`、`policy/resolver.go`、`configure_perf.go`、`fetch_url.go` 未变更；`register_api.go` 为 `/models`、`/log/stat`、`/data`、`/rankings` 新增 `ReadOnlyCache` 挂载（GA 行与 `/status` 注册行未变），新增中间件文件 `middleware/cache_readonly.go`（相关路由尚未移植）；`handle_misc.go` 除 gofmt 对齐外**新增 `/api/status` 字段 `truncated_response_multiplier`（Go 默认 0.3）**，已在 `1cc35fe` 补齐（`apps/server/src/status.rs`，含默认值断言）。后续切片需按新基线重新审计。

**复核状态**：上述 CI 证据已绑定精确 SHA；独立 `verification` 子代理因运行环境工具调用异常未能给出有效 verdict，本节仅记录 CI 与人工源码审计结果，不宣称独立复核 PASS。

### 8.2 2026-11-06 setup 向导、UserAuth/self/token 与降级形状对齐 @ `57f6947`

**证据绑定（普通 push）**
- Rust SHA：`57f6947d8d…`（`migration/p2`），P1 Rust workspace run `42198229885`，attempt `1`，**success**
- pg14：PostgreSQL 14.24、fmt/check/clippy exit 0、workspace-tests **319 passed / 0 failed**、session_cache 9/0、catalog 契约 2/2（sqlite+postgres）
- pg17：PostgreSQL 17.11、fmt/check/clippy exit 0、workspace-tests **319 passed / 0 failed**、session_cache 9/0、catalog 契约 2/2
- `P0 inventory consistency` 仍是既有非验收项。

**本切片交付**
- `GET/POST /api/setup`（`apps/server/src/setup_http.rs`）：GET 无中间件、POST 仅匿名体上限（Go `register_api.go:27-28`）；业务结果 200 + `{success,message}`，schema/DB 门禁 503 `setup.schema_not_ready`；复用 `SetupRepository` 事务；成功后重载配置快照。
- 运行模式：`PublicConfig` 新增 `self_use_mode_enabled`/`demo_site_enabled`（严格 `value == "true"`，对齐 Go `applyOperationSetting`），`/api/status` 改为读快照。
- 通用 `UserAuth`（`apps/server/src/auth.rs`）：dashboard JWT → PAT；失败映射固定（401 `AUTH_UNAUTHORIZED` / 401 `AUTH_SESSION_REVOKED` / 401 `AUTH_USER_DISABLED` / 403 `AUTH_INSUFFICIENT_PRIVILEGE` / 500 `AUTH_INTERNAL_ERROR`）。
- `GET /api/user/self`（`self_http.rs`）：复用 `assemble_self_user`，字段对齐 Go `buildSelfUserData`；策略读取失败降级。
- `GET /api/user/token`：轮换 `users.access_token`（唯一性检查），DisableCache 三头；接线顺序 `UserAuth → CriticalRateLimit → handler`。
- 降级权限形状对齐 Go 空 enforcer：`denied_permissions(role)` 返回完整资源/动作矩阵（全 false），侧栏按角色（root 无侧栏；admin `{"admin":{"setting":false}}`；普通用户 `{"admin":false}`）。
- 清除 Cookie 字节对齐：Go `net/http` 对 `MaxAge<0` 写 `Max-Age=0`，Rust 同步。

**契约差分（须保留记录）**
- 模式写入与 root/setup **同事务**（Go 在事务外），失败全回滚；因此两条模式失败文案合并为 `setup.mode_save_failed`，且无法区分是 SelfUse 还是 Demo 写失败。
- `UserCriticalRateLimit("access-token")` 未移植（用户维度限流），当前仅 CT 关键路径限流。
- 过期 JWT 返回 `AUTH_UNAUTHORIZED`（Go 为 `AUTH_TOKEN_EXPIRED`）；`Auth-Version` 响应头未复刻；PAT token 形态为 32 位字母数字（Go 为变长 Base64）。
- `/api/user/self/groups`、`/api/user/groups`、`/api/user/models` 未移植（依赖 group ratio 设置）。
- 注册 `POST /api/user/register` 正在并行实现；Turnstile `siteverify` 传输层仍缺。

### 8.3 2026-11-06 注册、Turnstile 传输、用户组/模型、self 更新/注销、2FA 与用户维度限流 @ `4b9c493`

**证据绑定（普通 push）**
- Rust SHA：`4b9c493279…`（`migration/p2`），P1 run `42222126442`，attempt `1`，**success**
- pg14（14.24）/ pg17（17.11）：fmt/check/clippy exit 0；workspace-tests **354 passed / 0 failed**；session_cache 9/0；catalog 契约 3/3；identity 10（sqlite）/ 9（postgres）passed
- 证据目录：`/tmp/p1-evidence-4b9c/`

**本切片交付**
- `POST /api/user/register`（`register_http.rs` + `registration.rs`）：开关顺序、Go v10 校验文案、邮箱验证分支、软删用户名占用、邀请码、创建默认字段、双后端契约测试。
- Turnstile `siteverify` 传输层（`turnstile.rs`）：`reqwest 0.13.5`（探针基线）+ `rustls` aws-lc provider；form `secret/response/remoteip`；传输/解码失败 fail-closed；登录与注册 guard 接入；测试用注入 verifier 保持确定性。
- `GET /api/user/groups`（匿名）、`GET /api/user/self/groups`、`GET /api/user/models`（`groups_http.rs` + `catalog/group_settings`）：`GroupRatio`/`UserUsableGroups`/`GroupGroupRatio` 快照与默认值、`auto` 字符串比例、用户组自追加；models 暂为空数组（等价 resolver 未注册）。
- `PUT/DELETE /api/user/self`（`self_http.rs` + `users.rs`）：侧栏/语言优先分支、占位密码回滚、旧密码校验、`auth_version` 递增与会话轮换、软删除、root 保护；PUT 挂 CT + handler 写 DisableCache，DELETE 仅 UserAuth。
- 2FA 管理（`twofa_http.rs` + `two_fa/repository.rs`）：status/setup/enable/disable/backup_codes，锁定与失败计数、4×`XXXX-XXXX` 备用码、otpauth URI、`auth_version+1` 与会话轮换。
- 用户维度关键限流（`state.rs` / `limit_redis.rs` / `http.rs`）：`UserCriticalRateLimit("access-token")`，内存键 `<mark>:user:<id>`、Redis 键 `rateLimit:v2:user:<mark>:<id>`，`/api/user/token` 顺序 `UserAuth → CT → 用户限流 → handler`。
- 验证者 `57f6947` 两处阻塞缺陷已修：`/api/status` 的 `setup` 读持久 `setups` 表；root 降级权限为 Go superuser 短路下的全 true。

**契约差分（须保留记录）**
- 注册：默认 token 生成（Go 默认关闭）、`finishInsert` 侧栏初始化与邀请人奖励、发码端点、form-urlencoded/multipart 绑定未移植。
- models：`abilities` 解析与 `group` 查询参数选择未移植，恒返回空数组。
- 2FA：`SystemName` 未入快照（issuer 固定 `New API`）、系统日志表写入与 `PublishUserAuthCache` 未移植、管理端 `Admin2FA*` 不在范围。
- Turnstile：10s 超时与 64 KiB 响应上限为契约要求的安全差异；错误文案使用固定 i18n key（不泄露外部错误文本）。
- 用户维度限流仅接入 `/api/user/token`；Go 另有 `/api/verify` 等未移植路由。

**独立复核（`4b9c493`，verification agent）**
- 结论 **PASS**：注册/Turnstile/groups/self 更新/2FA/用户限流与 Go 语义逐项对照通过，未发现数据完整性、认证、授权、fail-open 或路由可达性缺陷。
- 已记录的非阻塞差异：
  - 2FA 空/缺失 `code` 的状态检查顺序（已在 `1e53866` 对齐 Go zero-value 语义）。
  - Turnstile：畸形 `%` 转义 Go 丢弃该参数、Rust 作为字面 token 发送（仍 fail-closed）；Go 的 JSON 字段匹配大小写不敏感（`SUCCESS`），Rust 要求小写；Cloudflare 实际只发小写。
  - `PUT /api/user/self` 空体/非 JSON：Go 视为无操作成功，Rust 返回 `common.invalid_params`。
  - `GroupSpecialUsableGroup` 覆盖层未加载（Go 默认空，配置后才会不同）；groups handler 目前每请求读 options（待 AppState 快照接管）。
  - 注册的存储/bcrypt 错误统一收敛为 `common.database_error`（代码注释已说明，避免泄露）。
- 文档定位：§8.3 的差分清单以 `e88494f` 起为准；`4b9c493` 本身仍是旧 §8.2 文本。

### 8.4 2026-11-06 邀请码端点与 JWT 篡改用例修复 @ `79e856a`

**证据绑定（普通 push）**
- Rust SHA：`79e856a78d…`（`migration/p2`），P1 run `42230524900`，attempt `1`，**success**
- pg14（14.24）/ pg17（17.11）：fmt/check/clippy exit 0；workspace-tests **360 passed / 0 failed**；session_cache 9/0
- 证据目录：`/tmp/p1-evidence-79e8/`

**本切片交付**
- `GET /api/user/aff`（`aff_http.rs` + `users.rs`）：`UserAuth`、无缓存头；空 aff_code 时生成 4 位字母数字，条件更新保证并发只写一个值，其余请求读胜出值；失效用户返回固定 i18n 文案。
- 测试修复：JWT 篡改用例改为翻转签名**首字符**。base64url 末字符可能只承载填充位，翻转后解码字节不变，签名仍有效，导致用例偶发走到 `AUTH_SESSION_REVOKED`。
- 2FA 空/缺失 `code` 语义对齐（`1e53866`）：缺失、`null`、空串先走状态检查，与 Go `BindJSON` 零值一致。

**契约差分（新增）**
- aff：4 位码唯一索引冲突时返回 `common.database_error`（Go 返回原始错误文本），不做冲突重试。

### 8.5 2026-11-06 API Token 管理端点与搜索限流 @ `fdf9a0a`

**证据绑定（普通 push）**
- Rust SHA：`fdf9a0a544…`（`migration/p2`），P1 run `42239814982`，attempt `1`，**success**
- pg14（14.24）/ pg17（17.11）：fmt/check/clippy exit 0；workspace-tests **370 passed / 0 failed**；session_cache 9/0
- 证据目录：`/tmp/p1-evidence-fdf9/`

**本切片交付**
- `/api/token` 八个端点（`token_http.rs` + `tokens.rs`）：列表/搜索/auto-groups/详情/取 key/创建/更新/删除；全部按 `user_id` 限定，他人 token 返回业务失败而非 404/403。
- 分页别名 `p/page_size/ps/size`、上限 100；搜索 `keyword`/`token`（剥一次 `sk-`）、`%` 通配规则与超量用户限制；掩码规则与 Go 一致；仅 `/{id}/key` 返回明文并写三个缓存头。
- quota 校验（非负、`QuotaPerUnit` 上限、NaN/Inf）、名称字节长度、token 数量上限、`auto_groups` 三态与非 auto 清空 + `cross_group_retry=false`。
- 路由分层：组级 `UserAuth`；`/search` 挂用户维度 `SearchRateLimit`（mark "SR"）；`/{id}/key` 挂 `CriticalRateLimit`；`/api/token` 与 `/api/token/` 均可达。
- 新增 `SEARCH_RATE_LIMIT_ENABLE/SEARCH_RATE_LIMIT/SEARCH_RATE_LIMIT_DURATION`（默认 true/10/60），Redis 优先、否则进程内；内存键 `<mark>:user:<id>`、Redis 键 `rateLimit:v2:user:<mark>:<id>`。
- 查询解析为避免 axum `query` 特性引入新依赖，改为本地 `%XX`/`+` 解码（仅影响畸形转义的边界情形）。

**契约差分（新增，须保留记录）**
- 未移植 `/api/token/batch`、`/api/token/batch/keys`；未移植 token Redis 缓存及写后失效。
- `token_setting.max_user_tokens`、`AutoGroups`、`MaxTokenAutoGroups`、`GroupRatio`/`UserUsableGroups` 仍每请求读 `options`。
- `GroupSpecialUsableGroup` 覆盖层未加载；`Token.DeletedAt` 不作为 JSON 字段输出。
- 搜索 `keyword` 不做自动加 `%`：与 Go `SanitizeLikePattern` 一致，客户端需自带通配符。
- 空 body/非 JSON 的 token 创建/更新请求：`null` 视为零值，其余非对象为无效参数（Go `BindJSON` 语义）。

**独立复核（aff 切片 `79e856a`）**
- 结论 **PASS**：字母表/长度、软删作用域、条件更新并发语义、信封与路由、测试确定性（含 PG）均核对通过。
- 非阻塞：`parse_code(b"")` 已在 `e603789` 对齐 Go 零值；`/api/user/aff` 未断言无缓存头（路由仅挂 `UserAuth`）；未做并发声明专门测试（SQL 探针已独立验证）。

### 8.6 2026-11-08 `POST /api/user/aff_transfer` 契约全量复核（远程证据待回填）

复核对象 `apps/server/tests/aff_routes.rs` 的 aff_transfer 契约（sqlite/postgres 双后端），逐条对照 Go：`identity/manage_users.go:443-473`（`TransferAffQuota`）、`identity/store_users.go:453-493`（`TransferAffQuotaToQuota`）、`transport/compose/register_api.go:179`（`UserAuth → UserCriticalRateLimit("aff-transfer") → RequirePaymentComplianceMiddleware → handler`）、`security/authenticate.go`（`TokenAuth`）。远程 CI 证据与独立复核尚待回填，本节仅记录源码级裁决。

**修正（单一提交）**
- 失败信封缺 `划转失败 ` 前缀（实现缺陷）：Go 把 `TransferAffQuotaToQuota` 的**所有**错误经 `CtxApiErrorI18n(i18n.MsgUserTransferFailed, {"Error": err.Error()})`（`manage_users.go:467-471`）渲染，zh 模板 `user.transfer_failed: "划转失败 {{.Error}}"`（`i18n/locales/zh-CN.yaml:102`）。此前 `apps/server/src/aff_http.rs` 对最小门限（`store_users.go:455-457` 的 `fmt.Errorf("转移额度最小为%s！"...)`）与余额不足（`store_users.go:473-475` 的 `errors.New("邀请额度不足！")`）直接返回内层文案，丢了外层模板；已改为先渲染内层文案再包 `user.transfer_failed`，测试三处预期同步更新为 `划转失败 转移额度最小为＄1.000000 额度！` / `划转失败 邀请额度不足！`。`crates/identity/src/users.rs` 中“Go 逐字返回 bare 错误文本”的领域文档表述有误，已更正。
- 软删用户带有效 PAT（前任失败点，测试错）：见下述契约差分第 1 条，断言改为 401 并补“余额未动”。

**契约差分（已知，须保留）**
1. **软删用户访问 `aff_transfer`（或 `/aff`）**：Go 的 `TokenAuth` 校验 token 通过后，`GetUserCache → GetUserById` 命中带 `gorm.DeletedAt` 的 `User` 模型（`store_users.go:113`），GORM 默认作用域过滤软删行，查不到用户后 `abortWithOpenAiMessage` 返回 **500**（`MsgDatabaseError`），handler 不可达。本端口 PAT 查询自带 `deleted_at IS NULL`（`crates/identity/src/user_auth.rs:59`），软删用户等同未知 token，**刻意返回 401 `AUTH_UNAUTHORIZED`**——比把数据库错误透出给客户端更安全，且两种实现都不可能移动余额。此为两项路由共有的既定裁决，前任测试误把 Go 侧不存在路径（`用户不存在`）当作预期，已按 401 修正。
2. `GetUserById` 失败时 Go 返回 `划转失败 record not found`（原始 GORM 文本）；本端口映射为固定 i18n `user.not_exists`（`用户不存在`），不泄漏数据库文本。
3. `UserCriticalRateLimit("aff-transfer")` 用户维度限流未移植（仅 CT 关键路径限流）；compliance 门为 handler 内联实现（`TopUpSettings::payment_compliance_confirmed` 二段门 `confirmed && terms_version == "v1"`，对齐 Go `IsPaymentComplianceConfirmed`）。
4. 最小门限的 `quota_per_unit` 取自可配置展示设置（默认 500_000），Go 用 `common.QuotaPerUnit` 常量（仅测试改写）；默认值一致，仅可配置性不同（端口既有设计，非本路由特有）。

8.6 的修复随 `a7a83ec` 推送；该提交的 P1 run `42483050976` 因其它被掩盖的签到失败未绿，本节记录的 aff_transfer 四个用例在该 run 全部通过（aff_routes 二进制 4/4），最终由 `ba7554c` 的 run `42506448654`（attempt 1，conclusion `success`）整体验证：pg14/pg17 各 454 项 workspace 测试全部通过，fmt/check/clippy exit 0。

### 8.7 2026-11-08 签到契约修复：月份窗口的引擎排序差异与发放余量（远程证据待回填）

`a7a83ec` 的 P1 run（`42483050976`）workspace-tests 369 过 3 败，三败全在 `apps/server/tests/checkin_routes.rs`——此前 `aff_routes` 二进制失败时 cargo 默认不加 `--no-fail-fast`，会在第一个失败二进制处中止后续二进制，签到二进制从未跑到，属于被掩盖的既有失败。两处均为**测试错**，实现与 Go 一致：

1. **`sqlite/postgres_post_checkin_contract`（7877 vs 7777）**：用户 33 由 fixture 播种 `quota=100`（`checkin_routes.rs` 的 `seed_checkin_user(&db, 33, ..., 100)`），此时生效配置 `min_quota == max_quota == 7777`，Go `evaluateDailyCheckin` 在区间相等时直接返回 `min_quota`（`store_checkin.go:111-128`），发放写入 `quota + 7777`（`store_checkin.go:195-198` 的 `Update("quota", gorm.Expr("quota + ?"))`），余量即 100+7777=**7877**——与同用例中用户 32 的 `7_877` 断言同算术。原断言 7777 是漏加种子额度的笔误，已改为 `7_877`；Go 侧没有任何“默认 +100”行为。
2. **`postgres_checkin_routes_contract`（6 ≠ 0，仅 PG）**：空 `?month=` 时 Go `DefaultQuery` 只在缺键时回退当前月（`do_checkin.go:23`），键在值空时得到空串，拼出 `-01` .. `-31` 区间（`store_checkin.go:252-253`），`GetUserCheckinRecords` 用同区间做 SQL 比较（`store_checkin.go:37-44`）。**比较结果由数据库排序规则裁决**：SQLite 的 BINARY 字节序把 `-`(0x2D) 排在数字前，区间不匹配任何记录；CI 的 Postgres 镜像默认 `LANG=en_US.UTF-8`（glibc），标点在主权重被忽略，等价于去连字符比较，`-01` ≤ `2026-…` ≤ `-31` 成立，播种的六行**全部**命中。Go 生产环境跑在同一 PG 上、发出同一条 SQL，结果同样是六条——不存在端口偏差。`expected_records` 因此带上 `db` 参数按后端分别计算（PG 分支的去连字符比较已对全部用到的月份窗口与 glibc `strcoll` 逐一验证相等），SQLite 侧保持字节序断言。非空月份（当前月、40 天前月、`abc`）在两套排序下结果一致，不受影响。

**引擎差异（已知，须保留）**：签到月份窗口的字符串区间在 SQLite(BINARY) 与 Postgres(glibc, LANG=en_US.UTF-8) 之间不同——同一 SQL、不同排序规则。若未来 CI Postgres 镜像改用 C/ICU 排序规则，`expected_records` 的 PG 分支需同步复核。

**日界时区（测试侧修复）**：服务端“今天/本月”按 Go 部署清单的本地时区（`datetime.rs`：`CHECKIN_TZ_OFFSET_MINUTES` 优先，其次登记过的 `TZ` 名，缺省 +480，即 UTC+8），而测试原先用裸 UTC epoch 播种。两条日界在 UTC 16:00–24:00 相差一天，`checked_in_today` 与整月窗口因此整体错位（实际触发于 16:31Z 的 run `42500288377`）。`run_contract` 现在与服务端同算法复算偏移（`tz_offset_seconds`）后再播种、再算期望月份；`run_post_contract` 本就用服务端 `today()`，未受影响。

8.7 的修复分三步推送：`51569be`（发放余量 7877 与 PG 排序分支）、`3c02ab1`（空月份期望全集补老行）、`f9d15c9`+`7d5c34b`（日界偏移播种）。全部包含在 `ba7554c` 的 run `42506448654`（success）中验证：pg14/pg17 各 454 项全过，`checkin_routes` 四用例与 `setting_routes`/`topup_amount_routes` 双后端全绿。

### 8.8 2026-11-08 用户设置解析按 Go 部分采用（实现缺陷）（远程证据待回填）

`UserSetting::from_json`（`crates/identity/src/users.rs`）此前用 serde 的全有或无语义：任何字段类型不匹配就整体回退到零值设置，注释称“不部分采用”。这与 Go 不符：Go `User.GetSetting`（`store_users.go:165-174`）忽略 `json.Unmarshal` 的错误返回部分解码结果，而 `encoding/json` 对字段类型不匹配的规定是“跳过该字段、尽可能解码其余字段、结尾才报告 `UnmarshalTypeError`”。真实影响：`PUT /api/user/setting` 与 `PUT /api/user/self` 对已存 `sidebar_modules` 为对象（前端写入形态）的用户，会把 `upstream_model_update_notify_enabled` 等其余字段静默清零——普通角色因此无法保留管理员专属开关（`manage_users.go:1457-1461` 的 carry-over），`PUT /api/user/self` 的读-改-写会整体抹掉其它设置。已改为按字段单独解码，类型不匹配的字段留零值、其余照常采用；`null` 与缺键仍为零值，JSON 非对象仍整体为零值。测试侧 `setting_routes.rs` 的“普通角色发 false 仍保留 stored true”用例（Go 依据同上）随之通过。

8.8 的修复随 `52ab874` 推送，因签到日界 flake（`f9d15c9` 修复）前未单独绿；最终由 `ba7554c` 的 run `42506448654`（success）验证：pg14/pg17 各 454 项全过，`setting_routes.rs` 的普通角色保留管理员开关用例双后端通过。

### 8.9 2026-11-10 独立金钱审计两处差异修复：redemption.create 审计口径按 Go 对齐 + quota_from_scaled 下界闭端点（含 Go 实现缺陷，供上游反馈）（远程证据待回填）

**1. `redemption.create` 审计的 quota 口径（Go 侧原始缺陷，两侧已对齐到 Go 口径）**

Go `billing.AddRedemption` 的管理审计记的是 `logger.LogQuota(redemption.Quota)`（`apps/api/internal/billing/redeem_code.go:91`），即**请求体里的原始 `quota` 字段**（`Redemption.Quota`，`store_redemption.go:25` 的 `int` 列）；而实际入库的是 `QuotaFromDisplayAmount(redemption.QuotaDisplay)`（`redeem_code.go:73`）。即 Go 审计记录的是一个未换算、前端通常不发送而为 0 的原始字段，与入库值系统性不一致——这是 **Go 侧的原始缺陷**，登记供上游反馈。按“Go 是 oracle（含其既有缺陷）”策略，Rust `apps/server/src/redemption_http.rs` 的审计改为记录请求体 `quota` 原值（`display.format_quota(request.quota.unwrap_or(0), true)`）；**响应与入库值不变**（仍是 `quota_display` 换算值，与 Go 一致），仅审计记录口径对齐。契约测试 `apps/server/tests/redemption_routes.rs` 原先刻意不断言审计 `quota`（断言被调平），现已显式断言：请求未带 `quota` 时审计为零值展示串 `"＄0.000000 额度"`（Go 口径），与入库的 `500_000`（`quota_display=1` 换算，`stored_rows` 断言）形成对照，任何回到“记换算值”的回归都会让该断言失败。

**2. `quota_from_scaled` 的 `i32::MIN` 端点（开端点→闭端点，一行修复）**

Go `saturateQuota` 对两侧边界都用闭端点：`value >= MaxQuota` 与 `value <= MinQuota`（`apps/api/internal/common/quota_math.go:77-80`），故 `QuotaFromDecimalStrict`（`quota_math.go:152`）**拒绝 -2147483648**（下界含等号）。Rust `crates/billing/src/topup/quote.rs` 的 `quota_from_scaled` 此前只有 `quota < i32::MIN` 才拒绝（开端点），-2147483648 被当作可表示值接受。已改为 `quota <= i128::from(i32::MIN)` 闭端点，上界 `>= MaxQuota` 原本已是闭端点，未动；并补单测 `quota_from_scaled_rejects_both_closed_int32_bounds`：`i32::MAX` 与 `i32::MIN` 均拒绝、各自内侧一值（`MaxQuota - 1`、`i32::MIN + 1`）仍可表示。`validate_credited_quota`/`check_capacity` 已有 `<= 0` 拒绝，负值端不受影响。
