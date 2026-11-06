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

## 8. 2026-11-06 登录垂直切片状态（未验收）

**已实现并待远程 CI 验证**：`POST /api/user/login`、`POST /api/user/login/2fa` 编排（密码/2FA pending/2FA 校验/会话签发/最后登录/登录审计/SelfUser 装配）、额度展示快照、`UserProfile.auth_version`、关键路径滑动窗口限流（内存）、可信代理客户端 IP、匿名体上限与 DisableCache 三头、Accept-Language 语言解析、Turnstile 决策层接线、登录/2FA 文案 key；`apps/server/tests/{login_http,login_success}.rs` 覆盖中间件顺序、成功登录、2FA pending/错误码/备用码。

**明确未完成，不得视为本切片通过**：
- Turnstile 只有纯决策层；工作区没有 HTTP client 依赖，**未实现向 Cloudflare 的 `siteverify` 请求**。开关启用时密码登录返回 HTTP 200 `{success:false,message: Turnstile 校验暂不可用…}`（Go 的网络错误也是 200 + message），不会静默放行；补齐传输层前不得宣称 Turnstile 可用。
- 限流仅有进程内实现；配置 Redis 时 Go 走 Redis 固定窗口，Rust 尚未实现，多实例下限流不共享。Go 默认启用的全局 Web/API 限流（`GLOBAL_WEB_RATE_LIMIT_*`、`GLOBAL_API_RATE_LIMIT_*`）同样未移植。
- `/api/user/auth/refresh|logout`、`/api/user/sessions*` 仍不在生产 router 注册（既有切片遗留）。
- 注册、验证码、密码重置、初始化、API Key、`/api/status` 等 P2 项未在本切片。

**验收前置**：远程 Actions 的 fmt/check/clippy/test 全绿且实际连接 SQLite、PostgreSQL 与 Redis；登录 HTTP 契约测试覆盖成功、2FA pending、非法参数、禁用账号、存储故障、限流 429、体上限 413、DisableCache/Cookie 头；独立 verification 复核后更新本节。
