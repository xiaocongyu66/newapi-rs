use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{ConnectInfo, Path, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
use newapi_identity::auth_session::{SessionAuthError, SessionView};
use newapi_security::{OriginRequest, check_session_origin};
use serde::Serialize;

use crate::AppState;
use crate::boundary_mw::{disable_cache_headers, fill_disable_cache_headers};

const REFRESH_COOKIE: &str = "new_api_refresh";
const REFRESH_COOKIE_PATH: &str = "/api/user/auth";

pub const MAX_BODY_BYTES: usize = 64 * 1024;
static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Serialize)]
struct Envelope {
    success: bool,
    message: &'static str,
    data: String,
}

fn success(data: String) -> Response {
    Json(Envelope {
        success: true,
        message: "",
        data,
    })
    .into_response()
}

fn failure(status: StatusCode, message: &'static str) -> Response {
    (
        status,
        Json(Envelope {
            success: false,
            message,
            data: String::new(),
        }),
    )
        .into_response()
}

/// Axum GET includes implicit HEAD. Other methods get JSON 405, unknown paths
/// JSON 404, including /api and trailing slashes. These are explicit P1 choices,
/// not claims of equivalence with the unmeasured Go/Fiber middleware chain.
pub fn router(state: AppState) -> Router {
    build_router(state)
}

fn build_router(state: AppState) -> Router {
    let app = Router::new()
        .route("/api/notice", get(notice))
        .route("/api/about", get(about))
        .route("/api/home_page_content", get(home_page_content))
        .route("/api/user-agreement", get(user_agreement))
        .route("/api/privacy-policy", get(privacy_policy))
        .route("/api/status", get(crate::status::handle))
        .route("/api/setup", get(crate::setup_http::inspect))
        .route("/health/live", get(live))
        .route("/health/ready", get(ready));
    // Go `POST /api/setup` 只挂匿名体上限（`register_api.go:28`）。
    let setup_state = state.clone();
    let app = app.merge(
        Router::new()
            .route("/api/setup", post(crate::setup_http::complete))
            .route_layer(middleware::from_fn_with_state(
                setup_state,
                crate::setup_http::setup_body_limit,
            )),
    );
    // `/api/user/groups`：Go 该路由不挂 UserAuth；同 handler 也挂在
    // `/api/user/self/groups`（那一条在 UserAuth 组内）。
    let app = app.route("/api/user/groups", get(crate::groups_http::user_groups));
    // `POST /api/user/register`：Go 顺序 CriticalRateLimit → 匿名体上限 →
    // TurnstileCheck → handler（该路由不挂 DisableCache）。
    let register_state = state.clone();
    let app = app.merge(
        Router::new()
            .route("/api/user/register", post(crate::register_http::register))
            .route_layer(middleware::from_fn_with_state(
                register_state,
                crate::register_http::register_guard,
            )),
    );
    // `POST /api/user/reset`：Go `apiRouter` 直接挂载（匿名），顺序
    // CriticalRateLimit → 匿名体上限 → handler，无 Turnstile、无 UserAuth。
    let reset_state = state.clone();
    let app = app.merge(
        Router::new()
            .route("/api/user/reset", post(crate::reset_http::reset_password))
            .route_layer(middleware::from_fn_with_state(
                reset_state,
                crate::reset_http::reset_guard,
            )),
    );
    // `GET /api/verification`（register_api.go:99）：顺序
    // EmailVerificationRateLimit → TurnstileCheck → handler；无体上限、
    // 无 UserAuth、无 DisableCache。
    let verification_state = state.clone();
    let app = app.merge(
        Router::new()
            .route(
                "/api/verification",
                get(crate::verification_http::send_email_verification),
            )
            .route_layer(middleware::from_fn_with_state(
                verification_state,
                crate::verification_http::verification_guard,
            )),
    );
    // `GET /api/reset_password`（register_api.go:100）：顺序
    // CriticalRateLimit → TurnstileCheck → handler；同样三无。
    let reset_email_state = state.clone();
    let app = app.merge(
        Router::new()
            .route(
                "/api/reset_password",
                get(crate::verification_http::send_password_reset_email),
            )
            .route_layer(middleware::from_fn_with_state(
                reset_email_state,
                crate::verification_http::reset_password_guard,
            )),
    );
    // `GET /api/user/topup/info` 与 `GET /api/user/topup/self`：Go `selfRoute`
    // 组内纯 `UserAuth`，无限流、无 DisableCache。
    let topup_state = state.clone();
    let app = app.merge(
        Router::new()
            .route("/api/user/topup/info", get(crate::topup_http::topup_info))
            .route("/api/user/topup/self", get(crate::topup_http::user_topups))
            .route_layer(middleware::from_fn_with_state(
                topup_state,
                crate::auth::user_auth,
            )),
    );
    // `GET /api/user/checkin`：Go `selfRoute` 组内纯 `UserAuth`
    // （`register_api.go:190-191`），无限流、无 DisableCache。
    // POST 同组但多挂 `middleware.TurnstileCheck()`；本端口把该门内联进
    // handler 顶部（可观察结果等价：都是 200 + JSON 且不触达写路径），
    // 见 `checkin_http::do_checkin`。
    let checkin_state = state.clone();
    let app = app.merge(
        Router::new()
            .route(
                "/api/user/checkin",
                get(crate::checkin_http::checkin_status).post(crate::checkin_http::do_checkin),
            )
            .route_layer(middleware::from_fn_with_state(
                checkin_state,
                crate::auth::user_auth,
            )),
    );
    // `/api/subscription` 自助三路由（`register_api.go:257-263`）：组内纯
    // `UserAuth`，无限流、无 Turnstile、无 DisableCache。支付下单七条与
    // admin 组、支付回调不在本切片。
    let subscription_state = state.clone();
    let app = app.merge(
        Router::new()
            .route(
                "/api/subscription/plans",
                get(crate::subscription_http::plans),
            )
            .route(
                "/api/subscription/self",
                get(crate::subscription_http::self_subscriptions),
            )
            .route(
                "/api/subscription/self/preference",
                put(crate::subscription_http::update_preference),
            )
            .route_layer(middleware::from_fn_with_state(
                subscription_state,
                crate::auth::user_auth,
            )),
    );
    // QQ 绑定路由（`register_api.go:193-197`，紧跟 checkin 之后注册）：
    // - `GET /qq/bind`：`selfRoute` 组内纯 `UserAuth`，无限流、无 DisableCache。
    // - `POST /qq/bind/code`：`UserAuth → CriticalRateLimit → DisableCache`。
    //   429 与 Redis 故障（500）都在 DisableCache 之前产生，不带缓存头。
    // - `DELETE /qq/bind`：`UserAuth → CriticalRateLimit`，**无** DisableCache。
    // - `POST /qq/panel/sync`：`selfRoute` 组级 `UserAuth` → 路由级
    //   `security.AdminAuth()` → `CriticalRateLimit`，同样无 DisableCache。
    //   与 admin 2FA 那两条不同（它们在 `userRoute` 直下、没有组级 UserAuth），
    //   这里的 `AdminAuth` 是叠加在 `UserAuth` 之上的角色门；两者对同一凭据
    //   的判定同序（状态 → 角色 → 用户信息），只是最低角色从 1 提到 10。
    let qq_bind_state = state.clone();
    let app = app.merge(
        Router::new()
            .route("/api/user/qq/bind", get(crate::qq_bind_http::bind_status))
            .route_layer(middleware::from_fn_with_state(
                qq_bind_state,
                crate::auth::user_auth,
            )),
    );
    let qq_code_state = state.clone();
    let app = app.merge(
        Router::new()
            .route(
                "/api/user/qq/bind/code",
                post(crate::qq_bind_http::generate_bind_code),
            )
            .route_layer(middleware::from_fn(qq_disable_cache_guard))
            .route_layer(middleware::from_fn_with_state(
                qq_code_state.clone(),
                critical_guard,
            ))
            .route_layer(middleware::from_fn_with_state(
                qq_code_state,
                crate::auth::user_auth,
            )),
    );
    let qq_unbind_state = state.clone();
    let app = app.merge(
        Router::new()
            .route("/api/user/qq/bind", delete(crate::qq_bind_http::unbind))
            .route_layer(middleware::from_fn_with_state(
                qq_unbind_state.clone(),
                critical_guard,
            ))
            .route_layer(middleware::from_fn_with_state(
                qq_unbind_state,
                crate::auth::user_auth,
            )),
    );
    let qq_panel_state = state.clone();
    let app = app.merge(
        Router::new()
            .route(
                "/api/user/qq/panel/sync",
                post(crate::qq_bind_http::sync_panel),
            )
            .route_layer(middleware::from_fn_with_state(
                qq_panel_state.clone(),
                critical_guard,
            ))
            .route_layer(middleware::from_fn_with_state(
                qq_panel_state.clone(),
                crate::auth::admin_auth,
            ))
            .route_layer(middleware::from_fn_with_state(
                qq_panel_state,
                crate::auth::user_auth,
            )),
    );
    // 四条报价路由：Go `selfRoute` 组内纯 `UserAuth`（`/api/user/amount` 一线
    // 同样无限流）。响应是裸 `common.H` 包裹而非 `CtxApiSuccess`，详见
    // `amount_http` 的模块注释。
    let amount_state = state.clone();
    let app = app.merge(
        Router::new()
            .route("/api/user/amount", post(crate::amount_http::request_amount))
            .route(
                "/api/user/stripe/amount",
                post(crate::amount_http::request_stripe_amount),
            )
            .route(
                "/api/user/waffo/amount",
                post(crate::amount_http::request_waffo_amount),
            )
            .route(
                "/api/user/waffo-pancake/amount",
                post(crate::amount_http::request_waffo_pancake_amount),
            )
            .route_layer(middleware::from_fn_with_state(
                amount_state,
                crate::auth::user_auth,
            )),
    );
    // 网关回调：Go `userRoute` 直下、**匿名可打**（`register_api.go:138-143`），
    // POST 带匿名体上限，GET 无体。响应体恒为 "success"/"fail"。
    let notify_state = state.clone();
    let app = app.merge(
        Router::new()
            .route(
                "/api/user/epay/notify",
                get(crate::gateway_http::epay_notify).post(crate::gateway_http::epay_notify),
            )
            .route(
                "/api/user/vmq/notify",
                get(crate::gateway_http::vmq_notify).post(crate::gateway_http::vmq_notify),
            )
            .route(
                "/api/user/codepay/notify",
                get(crate::gateway_http::codepay_notify).post(crate::gateway_http::codepay_notify),
            )
            .route_layer(middleware::from_fn_with_state(
                notify_state,
                crate::gateway_http::notify_body_limit,
            )),
    );
    // 支付发起与兑换：Go `selfRoute` 组内 `UserAuth → CriticalRateLimit`
    // （`register_api.go:167,170,177,178`）。
    let pay_state = state.clone();
    let app = app.merge(
        Router::new()
            .route("/api/user/pay", post(crate::gateway_http::request_epay))
            .route(
                "/api/user/vmq/pay",
                post(crate::gateway_http::request_vmq_pay),
            )
            .route(
                "/api/user/codepay/pay",
                post(crate::gateway_http::request_codepay_pay),
            )
            .route("/api/user/topup", post(crate::gateway_http::topup_redeem))
            .route_layer(middleware::from_fn_with_state(
                pay_state.clone(),
                critical_guard,
            ))
            .route_layer(middleware::from_fn_with_state(
                pay_state,
                crate::auth::user_auth,
            )),
    );
    // 管理员补单：Go `adminRoute` 组内仅 `AdminAuth`（`register_api.go:209`）。
    let complete_state = state.clone();
    let app = app.merge(
        Router::new()
            .route(
                "/api/user/topup/complete",
                post(crate::gateway_http::admin_topup_complete),
            )
            .route_layer(middleware::from_fn_with_state(
                complete_state,
                crate::auth::admin_auth,
            )),
    );
    // `/api/user/2fa/*`：Go `selfRoute` 组内（`UserAuth`）；status 无
    // DisableCache，四个 POST 由 handler 自行写缓存头。
    let twofa_state = state.clone();
    let app = app.merge(
        Router::new()
            .route("/api/user/2fa/status", get(crate::twofa_http::status))
            .route("/api/user/2fa/setup", post(crate::twofa_http::setup))
            .route("/api/user/2fa/enable", post(crate::twofa_http::enable))
            .route("/api/user/2fa/disable", post(crate::twofa_http::disable))
            .route(
                "/api/user/2fa/backup_codes",
                post(crate::twofa_http::backup_codes),
            )
            .route_layer(middleware::from_fn_with_state(
                twofa_state,
                crate::auth::user_auth,
            )),
    );
    // Admin 2FA 路由：Go `adminRoute`（`register_api.go:204-223`）。`userRoute`
    // 自身没有组级中间件，因此 admin 链只有 `AdminAuth()`（role >= 10）一道，
    // 两条路由均无 `DisableCache`、无限流；403/401 的 code 与文案随中间件。
    let admin_twofa_state = state.clone();
    let app = app.merge(
        Router::new()
            .route(
                "/api/user/2fa/stats",
                get(crate::admin_twofa_http::admin_stats),
            )
            .route(
                "/api/user/{id}/2fa",
                delete(crate::admin_twofa_http::admin_disable),
            )
            .route_layer(middleware::from_fn_with_state(
                admin_twofa_state,
                crate::auth::admin_auth,
            )),
    );
    // 用户管理端七路由：Go `adminRoute`（`register_api.go:204-218`）中
    // `identity.GetAllUsers`/`GetUser`/`CreateUser`/`UpdateUser`/`DeleteUser`/
    // `SearchUsersHandler`/`ManageUser` 七条。组级同样只有 `AdminAuth()`
    // （role >= 10）一道，无 DisableCache、无限流；401/403 只来自鉴权链。
    // `/api/user/{id}` 与静态段 `/api/user/search`、`/api/user/manage` 共存，
    // axum 的 matchit 静态段优先匹配；Fiber 非严格路由使 `/api/user` 等价于
    // `/api/user/`，两种形态都注册（与 `/api/token` 一致）。
    let admin_users_state = state.clone();
    let app = app.merge(
        Router::new()
            .route(
                "/api/user/",
                get(crate::admin_users_http::list_users)
                    .post(crate::admin_users_http::create_user)
                    .put(crate::admin_users_http::update_user),
            )
            .route(
                "/api/user",
                get(crate::admin_users_http::list_users)
                    .post(crate::admin_users_http::create_user)
                    .put(crate::admin_users_http::update_user),
            )
            .route(
                "/api/user/search",
                get(crate::admin_users_http::search_users),
            )
            .route(
                "/api/user/manage",
                post(crate::admin_users_http::manage_user),
            )
            .route(
                "/api/user/{id}",
                get(crate::admin_users_http::get_user).delete(crate::admin_users_http::delete_user),
            )
            .route_layer(middleware::from_fn_with_state(
                admin_users_state,
                crate::auth::admin_auth,
            )),
    );
    // OAuth 绑定的 self 路由：Go `selfRoute`（`register_api.go:200-201`），组内
    // 纯 `UserAuth`，无限流、无 `DisableCache`。`UserAuth` 的 minRole 低于
    // `RoleAdminUser`，Go 的 `beginAdminAudit` 不开捕获，因此这两条不写审计。
    let oauth_bindings_state = state.clone();
    let app = app.merge(
        Router::new()
            .route(
                "/api/user/oauth/bindings",
                get(crate::oauth_bindings_http::user_bindings),
            )
            .route(
                "/api/user/oauth/bindings/{provider_id}",
                delete(crate::oauth_bindings_http::unbind),
            )
            .route_layer(middleware::from_fn_with_state(
                oauth_bindings_state,
                crate::auth::user_auth,
            )),
    );
    // OAuth 绑定的 admin 路由：Go `adminRoute`（`register_api.go:211-212`），
    // 同样只有 `AdminAuth()` 一道。admin DELETE 的审计由 Go 的
    // `finishAdminAudit` 兜底（handler 未手动埋点），本端口内联进
    // `oauth_bindings_http::admin_unbind`，写方法与业务成败无关都落库。
    let admin_oauth_state = state.clone();
    let app = app.merge(
        Router::new()
            .route(
                "/api/user/{id}/oauth/bindings",
                get(crate::oauth_bindings_http::admin_user_bindings),
            )
            .route(
                "/api/user/{id}/oauth/bindings/{provider_id}",
                delete(crate::oauth_bindings_http::admin_unbind),
            )
            .route_layer(middleware::from_fn_with_state(
                admin_oauth_state,
                crate::auth::admin_auth,
            )),
    );
    // 自定义 OAuth 提供商管理端（`register_api.go:342-352`）：组内
    // `AdminAuth()` + `RequirePermission(policy.SystemSettings)`，无
    // DisableCache、无限流。权限层 (`require_system_settings`) 叠在
    // `admin_auth` 之后（`route_layer` 后加先执行）；根路由同时注册带尾斜线
    // 与不带尾斜线两种形态，对齐 Fiber StrictRouting=false 的匹配行为。
    let custom_oauth_state = state.clone();
    let app = app.merge(
        Router::new()
            .route(
                "/api/custom-oauth-provider/",
                get(crate::custom_oauth_http::list).post(crate::custom_oauth_http::create),
            )
            .route(
                "/api/custom-oauth-provider",
                get(crate::custom_oauth_http::list).post(crate::custom_oauth_http::create),
            )
            .route(
                "/api/custom-oauth-provider/discovery",
                post(crate::custom_oauth_http::discovery),
            )
            .route(
                "/api/custom-oauth-provider/{id}",
                get(crate::custom_oauth_http::get_one)
                    .put(crate::custom_oauth_http::update)
                    .delete(crate::custom_oauth_http::delete),
            )
            .route_layer(middleware::from_fn_with_state(
                custom_oauth_state.clone(),
                crate::custom_oauth_http::require_system_settings,
            ))
            .route_layer(middleware::from_fn_with_state(
                custom_oauth_state,
                crate::auth::admin_auth,
            )),
    );
    // `/api/option/*`：Go `optionRoute` 组（`register_api.go:298-312`），
    // 组级 `AdminAuth()` + `RequirePermission(policy.SystemSettings)`，无
    // DisableCache、无限流。根路由注册带尾斜线与不带尾斜线两种形态，对齐
    // Fiber StrictRouting=false 的匹配行为。
    let option_state = state.clone();
    let app = app.merge(
        Router::new()
            .route(
                "/api/option/",
                get(crate::option_http::get_options).put(crate::option_http::update_option),
            )
            .route(
                "/api/option",
                get(crate::option_http::get_options).put(crate::option_http::update_option),
            )
            .route(
                "/api/option/channel_affinity_cache",
                get(crate::option_http::affinity_cache_stats)
                    .delete(crate::option_http::clear_affinity_cache),
            )
            .route(
                "/api/option/smtp_pool_status",
                get(crate::option_http::smtp_pool_status),
            )
            .route(
                "/api/option/rest_model_ratio",
                post(crate::option_http::reset_model_ratio),
            )
            .route(
                "/api/option/payment_compliance",
                post(crate::option_http::confirm_payment_compliance),
            )
            .route(
                "/api/option/waffo-pancake/catalog",
                get(crate::option_http::waffo_catalog),
            )
            .route(
                "/api/option/waffo-pancake/pair",
                post(crate::option_http::waffo_pair),
            )
            .route(
                "/api/option/waffo-pancake/save",
                post(crate::option_http::waffo_save),
            )
            .route(
                "/api/option/waffo-pancake/subscription-product",
                post(crate::option_http::waffo_subscription_product),
            )
            .route(
                "/api/option/waffo-pancake/subscription-product-options",
                get(crate::option_http::waffo_subscription_product_options),
            )
            .route_layer(middleware::from_fn_with_state(
                option_state.clone(),
                crate::option_http::require_system_settings,
            ))
            .route_layer(middleware::from_fn_with_state(
                option_state,
                crate::auth::admin_auth,
            )),
    );
    // `PUT /api/user/self`：Go `UserAuth → CriticalRateLimit → DisableCache →
    // handler`（缓存头由 handler 写）；`DELETE /api/user/self` 仅 `UserAuth`。
    let self_put_state = state.clone();
    let app = app.merge(
        Router::new()
            .route("/api/user/self", put(crate::self_http::update_self))
            .route_layer(middleware::from_fn_with_state(
                self_put_state.clone(),
                critical_guard,
            ))
            .route_layer(middleware::from_fn_with_state(
                self_put_state,
                crate::auth::user_auth,
            )),
    );
    let self_delete_state = state.clone();
    let app = app.merge(
        Router::new()
            .route("/api/user/self", delete(crate::self_http::delete_self))
            .route_layer(middleware::from_fn_with_state(
                self_delete_state,
                crate::auth::user_auth,
            )),
    );
    // `/api/token*`：Go 组级 `UserAuth`；`/search` 另挂 `SearchRateLimit`，
    // `/{id}/key` 另挂 `CriticalRateLimit`，缓存头由 handler 写。
    let token_state = state.clone();
    let app = app.merge(
        Router::new()
            .route(
                "/api/token/",
                get(crate::token_http::list_tokens)
                    .post(crate::token_http::add_token)
                    .put(crate::token_http::update_token),
            )
            .route(
                "/api/token",
                get(crate::token_http::list_tokens)
                    .post(crate::token_http::add_token)
                    .put(crate::token_http::update_token),
            )
            .route(
                "/api/token/auto-groups",
                get(crate::token_http::token_auto_groups),
            )
            .route(
                "/api/token/{id}",
                get(crate::token_http::get_token).delete(crate::token_http::delete_token),
            )
            .route_layer(middleware::from_fn_with_state(
                token_state.clone(),
                crate::auth::user_auth,
            )),
    );
    let token_search_state = state.clone();
    let app = app.merge(
        Router::new()
            .route("/api/token/search", get(crate::token_http::search_tokens))
            .route_layer(middleware::from_fn_with_state(
                token_search_state.clone(),
                search_guard,
            ))
            .route_layer(middleware::from_fn_with_state(
                token_search_state,
                crate::auth::user_auth,
            )),
    );
    let token_key_state = state.clone();
    let app = app.merge(
        Router::new()
            .route(
                "/api/token/{id}/key",
                post(crate::token_http::get_token_key),
            )
            .route_layer(middleware::from_fn_with_state(
                token_key_state.clone(),
                critical_guard,
            ))
            .route_layer(middleware::from_fn_with_state(
                token_key_state,
                crate::auth::user_auth,
            )),
    );
    // `GET /api/log/token`：Go `logRoute` 组级 CORS → `CriticalRateLimit` 之后
    // 路由级 `TokenAuthReadOnly()`（`register_api.go:59-62`）。宽松令牌认证只验
    // key 存在（显式禁用与封禁用户除外），失败体无 code 字段。
    let log_token_state = state.clone();
    let app = app.merge(
        Router::new()
            .route("/api/log/token", get(crate::readonly_http::log_by_token))
            .route_layer(middleware::from_fn_with_state(
                log_token_state.clone(),
                crate::auth::token_auth_read_only,
            ))
            .route_layer(middleware::from_fn_with_state(
                log_token_state,
                critical_guard,
            )),
    );
    // `/api/log` 读取端（`register_api.go:49-57`）：Go 在 `logRoute` 组内先注册
    // 7 条路由、后挂 CORS/CriticalRateLimit，因此鉴权链只有路由级的
    // AdminAuth/UserAuth（`/api/log/self/search` 另挂 SearchRateLimit，与
    // `/api/token/search` 相同）。`/search` 与列表在 Go 是同一 handler 的转发，
    // 两种尾斜杠形态都注册（axum 不做归一化）。
    let log_admin_state = state.clone();
    let app = app.merge(
        Router::new()
            .route("/api/log/", get(crate::log_http::list_logs))
            .route("/api/log", get(crate::log_http::list_logs))
            .route("/api/log/search", get(crate::log_http::list_logs))
            .route("/api/log/stat", get(crate::log_http::logs_stat))
            .route(
                "/api/log/channel_affinity_usage_cache",
                get(crate::log_http::channel_affinity_usage_cache),
            )
            .route_layer(middleware::from_fn_with_state(
                log_admin_state,
                crate::auth::admin_auth,
            )),
    );
    let log_self_state = state.clone();
    let app = app.merge(
        Router::new()
            .route("/api/log/self", get(crate::log_http::list_user_logs))
            .route("/api/log/self/stat", get(crate::log_http::logs_self_stat))
            .route_layer(middleware::from_fn_with_state(
                log_self_state,
                crate::auth::user_auth,
            )),
    );
    let log_self_search_state = state.clone();
    let app = app.merge(
        Router::new()
            .route("/api/log/self/search", get(crate::log_http::list_user_logs))
            .route_layer(middleware::from_fn_with_state(
                log_self_search_state.clone(),
                search_guard,
            ))
            .route_layer(middleware::from_fn_with_state(
                log_self_search_state,
                crate::auth::user_auth,
            )),
    );
    // `GET /api/usage/token/`：Go `usageRoute` 组级 CORS → `CriticalRateLimit`
    // → 组级 `TokenAuthReadOnly()`（`register_api.go:375-384`）。axum 不做尾部
    // 斜杠归一化，两种写法都注册（与 `/api/token` 一致）。
    let usage_token_state = state.clone();
    let app = app.merge(
        Router::new()
            .route("/api/usage/token/", get(crate::readonly_http::token_usage))
            .route("/api/usage/token", get(crate::readonly_http::token_usage))
            .route_layer(middleware::from_fn_with_state(
                usage_token_state.clone(),
                crate::auth::token_auth_read_only,
            ))
            .route_layer(middleware::from_fn_with_state(
                usage_token_state,
                critical_guard,
            )),
    );
    // `POST /api/token/batch`（`register_api.go:371`）：Go `tokenRoute` 组内，
    // 仅 `UserAuth`，无关键路径限流、无缓存头。
    let token_batch_state = state.clone();
    let app = app.merge(
        Router::new()
            .route(
                "/api/token/batch",
                post(crate::token_http::delete_token_batch),
            )
            .route_layer(middleware::from_fn_with_state(
                token_batch_state,
                crate::auth::user_auth,
            )),
    );
    // `POST /api/token/batch/keys`（`register_api.go:372`）：Go 链
    // `UserAuth → CriticalRateLimit → DisableCache → handler`；no-cache 头由
    // handler 写在所有响应上，限流产生的 429/500 在其之前不带缓存头。
    let token_batch_keys_state = state.clone();
    let app = app.merge(
        Router::new()
            .route(
                "/api/token/batch/keys",
                post(crate::token_http::get_token_keys_batch),
            )
            .route_layer(middleware::from_fn_with_state(
                token_batch_keys_state.clone(),
                critical_guard,
            ))
            .route_layer(middleware::from_fn_with_state(
                token_batch_keys_state,
                crate::auth::user_auth,
            )),
    );
    // `/api/redemption/*`：Go redemptionRoute = apiRouter.Group("/redemption")
    // （`register_api.go:386-396`），组级只有 `security.AdminAuth()` 一道，
    // 无限流、无 DisableCache。Fiber 非严格路由使无尾斜杠的 `/api/redemption`
    // 等价于 `/api/redemption/`，因此两种形态都注册（与 `/api/token` 一致）。
    let redemption_state = state.clone();
    let app = app.merge(
        Router::new()
            .route(
                "/api/redemption/",
                get(crate::redemption_http::list_redemptions)
                    .post(crate::redemption_http::add_redemption)
                    .put(crate::redemption_http::update_redemption),
            )
            .route(
                "/api/redemption",
                get(crate::redemption_http::list_redemptions)
                    .post(crate::redemption_http::add_redemption)
                    .put(crate::redemption_http::update_redemption),
            )
            .route(
                "/api/redemption/search",
                get(crate::redemption_http::search_redemptions),
            )
            .route(
                "/api/redemption/invalid",
                delete(crate::redemption_http::delete_invalid_redemptions),
            )
            .route(
                "/api/redemption/{id}",
                get(crate::redemption_http::get_redemption)
                    .delete(crate::redemption_http::delete_redemption),
            )
            .route_layer(middleware::from_fn_with_state(
                redemption_state,
                crate::auth::admin_auth,
            )),
    );

    // `/api/user-insight/*`：Go insightRoute = apiRouter.Group("/user-insight")
    // （`register_api.go:227-241`），组级只有 `security.AdminAuth()` 一道，
    // 无限流、无 DisableCache。Fiber 非严格路由使无尾斜杠的 `/api/user-insight`
    // 等价于 `/api/user-insight/`，两种形态都注册（与 `/api/redemption` 一致）。
    let user_insight_state = state.clone();
    let app = app.merge(
        Router::new()
            .route(
                "/api/user-insight/",
                get(crate::user_insight_http::list_user_insights),
            )
            .route(
                "/api/user-insight",
                get(crate::user_insight_http::list_user_insights),
            )
            .route(
                "/api/user-insight/summary",
                get(crate::user_insight_http::get_user_insight_summary),
            )
            .route(
                "/api/user-insight/client-catalog",
                get(crate::user_insight_http::get_client_catalog),
            )
            .route(
                "/api/user-insight/client-ban",
                post(crate::user_insight_http::set_global_client_ban),
            )
            .route(
                "/api/user-insight/{id}",
                get(crate::user_insight_http::get_user_insight_detail)
                    .delete(crate::user_insight_http::purge_user_insight_handler),
            )
            .route(
                "/api/user-insight/{id}/client-ban",
                post(crate::user_insight_http::toggle_user_client_ban_handler),
            )
            .route_layer(middleware::from_fn_with_state(
                user_insight_state,
                crate::auth::admin_auth,
            )),
    );

    // `/api/channel*` 基础 CRUD（Go `register_channels.go` 的前八条）：
    // 组级 `AdminAuth()` 之后是路由级 `RequirePermission(...)`——permission
    // 403 在 handler 入口的 `channel_http::require_permission` 复现（401/403
    // 只来自鉴权链；业务结果一律 HTTP 200 + 信封）。axum 不做尾部斜杠归一
    // 化，两种写法都注册（与 `/api/token` 一致）。
    let channel_state = state.clone();
    let app = app.merge(
        Router::new()
            .route(
                "/api/channel/",
                get(crate::channel_http::list_channels)
                    .post(crate::channel_http::add_channel)
                    .put(crate::channel_http::update_channel),
            )
            .route(
                "/api/channel",
                get(crate::channel_http::list_channels)
                    .post(crate::channel_http::add_channel)
                    .put(crate::channel_http::update_channel),
            )
            .route(
                "/api/channel/search",
                get(crate::channel_http::search_channels),
            )
            .route(
                "/api/channel/disabled",
                delete(crate::channel_http::delete_disabled_channels),
            )
            .route(
                "/api/channel/batch",
                post(crate::channel_http::delete_channel_batch),
            )
            .route(
                "/api/channel/{id}",
                get(crate::channel_http::get_channel).delete(crate::channel_http::delete_channel),
            )
            .route_layer(middleware::from_fn_with_state(
                channel_state,
                crate::auth::admin_auth,
            )),
    );
    // `GET /api/models`：Go `apiRouter.GET("/models", UserAuth(),
    // DashboardListModels)`（`register_api.go:32`）——静态目录，挂在
    // UserAuth 之下，与下面的 admin 组互不重叠（方法也不同）。
    let dashboard_models_state = state.clone();
    let app = app.merge(
        Router::new()
            .route("/api/models", get(crate::models_http::dashboard_models))
            .route_layer(middleware::from_fn_with_state(
                dashboard_models_state,
                crate::auth::user_auth,
            )),
    );
    // `/api/models*` 管理端九条（Go `modelsRoute`，`register_api.go:450-462`）：
    // 组级 `AdminAuth()`，无路由级 RequirePermission；全部业务结果 HTTP 200
    // + 信封（401/403 只来自鉴权链）。Go 的 `POST/PUT("/api/models/")` 带
    // 尾斜杠，gin 的 trailing-slash 重定向让无斜杠形式也能用；axum 不做归
    // 一化，前端（`features/models/api.ts`）只用带斜杠形式，这里只注册
    // 带斜杠版本。
    let models_state = state.clone();
    let app = app.merge(
        Router::new()
            .route(
                "/api/models/",
                post(crate::models_http::create_model).put(crate::models_http::update_model),
            )
            .route("/api/models/meta", get(crate::models_http::list_models))
            .route("/api/models/search", get(crate::models_http::search_models))
            .route(
                "/api/models/missing",
                get(crate::models_http::missing_models),
            )
            .route(
                "/api/models/sync_upstream",
                post(crate::models_http::sync_upstream),
            )
            .route(
                "/api/models/sync_upstream/preview",
                get(crate::models_http::sync_upstream_preview),
            )
            .route(
                "/api/models/{id}",
                get(crate::models_http::get_model).delete(crate::models_http::delete_model),
            )
            .route_layer(middleware::from_fn_with_state(
                models_state,
                crate::auth::admin_auth,
            )),
    );
    // `GET /api/user/aff`：Go `selfRoute` 组内（`UserAuth`），无缓存头。
    // `POST /api/user/aff_transfer` 同组，但 Go 在它前面多挂
    // `UserCriticalRateLimit("aff-transfer")` 与
    // `RequirePaymentComplianceMiddleware`（`register_api.go:179`）。端口尚无
    // 按 key 的 critical 限流器，因此只把合规门内联进 handler（见 `aff_http`）。
    let aff_state = state.clone();
    let app = app.merge(
        Router::new()
            .route("/api/user/aff", get(crate::aff_http::aff_code))
            .route(
                "/api/user/aff_transfer",
                post(crate::aff_http::transfer_aff_quota),
            )
            .route_layer(middleware::from_fn_with_state(
                aff_state,
                crate::auth::user_auth,
            )),
    );
    // `PUT /api/user/setting`：Go `selfRoute.PUT("/setting", ...)`
    // （`register_api.go:180`），组内纯 `UserAuth`，无 DisableCache、无限流。
    // 全部结果都是 HTTP 200，分支顺序即契约（见 `setting_http` 的模块注释）。
    let setting_state = state.clone();
    let app = app.merge(
        Router::new()
            .route(
                "/api/user/setting",
                put(crate::setting_http::update_user_setting),
            )
            .route_layer(middleware::from_fn_with_state(
                setting_state,
                crate::auth::user_auth,
            )),
    );
    // `/api/user/self/groups` 与 `/api/user/models`：Go `UserAuth` → handler。
    let groups_auth_state = state.clone();
    let app = app.merge(
        Router::new()
            .route(
                "/api/user/self/groups",
                get(crate::groups_http::user_groups),
            )
            .route("/api/user/models", get(crate::groups_http::user_models))
            .route_layer(middleware::from_fn_with_state(
                groups_auth_state,
                crate::auth::user_auth,
            )),
    );
    // `/api/user/self`：Go `UserAuth` → handler（该路由不挂 DisableCache）。
    let self_state = state.clone();
    let app = app.merge(
        Router::new()
            .route("/api/user/self", get(crate::self_http::self_user))
            .route_layer(middleware::from_fn_with_state(
                self_state,
                crate::auth::user_auth,
            )),
    );
    // `/api/user/token`：Go `UserAuth` → CriticalRateLimit →
    // UserCriticalRateLimit("access-token") → DisableCache → handler；
    // handler 自写缓存头，限流的 429/500 不带缓存头。
    let token_state = state.clone();
    let app = app.merge(
        Router::new()
            .route("/api/user/token", get(crate::self_http::access_token))
            .route_layer(middleware::from_fn_with_state(
                token_state.clone(),
                user_critical_guard,
            ))
            .route_layer(middleware::from_fn_with_state(
                token_state.clone(),
                critical_guard,
            ))
            .route_layer(middleware::from_fn_with_state(
                token_state,
                crate::auth::user_auth,
            )),
    );
    // 登录路由：Go 顺序 CriticalRateLimit → DisableCache → 匿名体上限 → handler。
    // 中间件依赖 AppState，必须用 from_fn_with_state 才能在 with_state 之前布层。
    let login_state = state.clone();
    let app = app.merge(
        Router::new()
            .route("/api/user/login", post(crate::login_http::login))
            .route("/api/user/login/2fa", post(crate::login_http::login_two_fa))
            .route_layer(middleware::from_fn_with_state(
                login_state,
                crate::login_http::login_guard,
            )),
    );
    // passkey 自管理路由（`register_api.go:158-163`）：`selfRoute` 组内
    // 纯 UserAuth；status 无 DisableCache，四个 POST 与 DELETE 的 no-cache
    // 头由 handler 自写（Go 的 DisableCache 中间件）。
    let passkey_state = state.clone();
    let app = app.merge(
        Router::new()
            .route("/api/user/passkey", get(crate::passkey_http::status))
            .route(
                "/api/user/passkey/register/begin",
                post(crate::passkey_http::register_begin),
            )
            .route(
                "/api/user/passkey/register/finish",
                post(crate::passkey_http::register_finish),
            )
            .route(
                "/api/user/passkey/verify/begin",
                post(crate::passkey_http::verify_begin),
            )
            .route(
                "/api/user/passkey/verify/finish",
                post(crate::passkey_http::verify_finish),
            )
            .route("/api/user/passkey", delete(crate::passkey_http::delete))
            .route_layer(middleware::from_fn_with_state(
                passkey_state,
                crate::auth::user_auth,
            )),
    );
    // passkey 匿名登录路由（`register_api.go:135-136`）：CriticalRateLimit →
    // DisableCache → 匿名体上限 → handler（guard 内不含 Turnstile）。
    let passkey_login_state = state.clone();
    let app = app.merge(
        Router::new()
            .route(
                "/api/user/passkey/login/begin",
                post(crate::passkey_http::login_begin),
            )
            .route(
                "/api/user/passkey/login/finish",
                post(crate::passkey_http::login_finish),
            )
            .route_layer(middleware::from_fn_with_state(
                passkey_login_state,
                crate::passkey_http::login_guard,
            )),
    );
    // passkey 管理员重置（`register_api.go:219`）：adminRoute 组内纯
    // AdminAuth，无 DisableCache、无限流。
    let admin_passkey_state = state.clone();
    let app = app.merge(
        Router::new()
            .route(
                "/api/user/{id}/reset_passkey",
                delete(crate::passkey_http::admin_reset),
            )
            .route_layer(middleware::from_fn_with_state(
                admin_passkey_state,
                crate::auth::admin_auth,
            )),
    );
    // refresh/logout：Go 顺序 SessionCookieOriginGuard → CriticalRateLimit →
    // DisableCache → handler。
    let mutation_state = state.clone();
    let app = app.merge(
        Router::new()
            .route("/api/user/auth/refresh", post(refresh))
            .route("/api/user/auth/logout", post(logout))
            .route_layer(middleware::from_fn_with_state(
                mutation_state,
                session_mutation_guard,
            )),
    );
    // sessions 读端点：Go 顺序 UserAuth → DisableCache，不参与关键路径限流。
    let read_state = state.clone();
    let app = app.merge(
        Router::new()
            .route("/api/user/sessions", get(sessions))
            .route("/api/user/sessions/{sid}", delete(delete_session))
            .route(
                "/api/user/sessions/revoke-others",
                post(revoke_other_sessions),
            )
            .route_layer(middleware::from_fn_with_state(
                read_state,
                session_read_guard,
            )),
    );
    // Go `apiRouter.Use(GlobalAPIRateLimit)`：GA 位于所有路由级中间件之前，
    // 因此对全部 /api 路径（含未匹配的 /api 回退）先于 CT 执行。此层在
    // boundary 之前添加，boundary 保持最外层；非 /api 路径由中间件内部直通。
    let global_limit_state = state.clone();
    // Go `SetWebRouter` 的 `router.Use(GlobalWebRateLimit)`（register_web.go:15）
    // 仅覆盖其后注册的静态资源与 NoRoute 兜底链；本端口无静态资源，GW 表面
    // 是 `/api`、`/health/*` 之外的兜底路径。两中间件的路径门互补，同一请求
    // 至多命中一个（Go 中 GA/GW 也从不在同一请求上同时出现）。
    let web_limit_state = state.clone();
    app.fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(middleware::from_fn_with_state(
            global_limit_state,
            crate::global_limit::global_api_rate_limit,
        ))
        .layer(middleware::from_fn_with_state(
            web_limit_state,
            crate::web_limit::global_web_rate_limit,
        ))
        .with_state(state)
        .layer(middleware::from_fn(boundary))
}

async fn notice(State(state): State<AppState>) -> Response {
    success(state.snapshot().notice)
}

async fn about(State(state): State<AppState>) -> Response {
    success(state.snapshot().about)
}

async fn home_page_content(State(state): State<AppState>) -> Response {
    success(state.snapshot().home_page_content)
}

async fn user_agreement(State(state): State<AppState>) -> Response {
    success(state.snapshot().user_agreement)
}

async fn privacy_policy(State(state): State<AppState>) -> Response {
    success(state.snapshot().privacy_policy)
}

async fn live() -> Response {
    success("live".into())
}

async fn ready(State(state): State<AppState>) -> Response {
    if state.is_ready() {
        success("ready".into())
    } else {
        failure(StatusCode::SERVICE_UNAVAILABLE, "not ready")
    }
}

#[derive(Serialize)]
pub(crate) struct SessionBody {
    sid: String,
    current: bool,
    login_method: String,
    ip: String,
    user_agent: String,
    created_at: i64,
    last_active_at: i64,
    expires_at: i64,
}

impl From<SessionView> for SessionBody {
    fn from(view: SessionView) -> Self {
        Self {
            sid: view.sid,
            current: view.current,
            login_method: view.login_method,
            ip: view.ip,
            user_agent: view.user_agent,
            created_at: view.created_at,
            last_active_at: view.last_active_at,
            expires_at: view.expires_at,
        }
    }
}

#[derive(Serialize)]
struct RotationBody {
    access_token: String,
    token_type: &'static str,
    access_expires_at: i64,
    session: SessionBody,
}

#[derive(Serialize)]
struct DataEnvelope<T> {
    success: bool,
    message: &'static str,
    data: T,
}

#[derive(Serialize)]
struct MessageEnvelope {
    success: bool,
    message: &'static str,
}

#[derive(Serialize)]
struct LogoutBody {
    revoked_sid: String,
    cookie_cleared: bool,
}

#[derive(Serialize)]
struct AuthFailure {
    success: bool,
    code: &'static str,
    message: &'static str,
}

fn success_data<T: Serialize>(data: T) -> Response {
    Json(DataEnvelope {
        success: true,
        message: "",
        data,
    })
    .into_response()
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn auth_failure(status: StatusCode, code: &'static str) -> Response {
    (
        status,
        Json(AuthFailure {
            success: false,
            code,
            message: status.canonical_reason().unwrap_or("error"),
        }),
    )
        .into_response()
}

pub(crate) fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0)
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| key.trim() == name)
        .map(|(_, value)| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let mut parts = value.split_whitespace();
    match (parts.next(), parts.next(), parts.next()) {
        (Some(scheme), Some(token), None)
            if scheme.eq_ignore_ascii_case("bearer") && !token.is_empty() =>
        {
            Some(token)
        }
        _ => None,
    }
}

fn single_header(
    headers: &HeaderMap,
    name: header::HeaderName,
) -> Result<Vec<&str>, axum::http::header::ToStrError> {
    headers
        .get_all(name)
        .iter()
        .map(HeaderValue::to_str)
        .collect()
}

/// 仅在 Secure Cookie 模式校验来源；明文本地开发保持原行为。
fn origin_allowed(state: &AppState, headers: &HeaderMap) -> bool {
    let cookie = state.session_cookie();
    if !cookie.secure {
        return true;
    }
    let (Ok(host), Ok(origin), Ok(referer)) = (
        single_header(headers, header::HOST),
        single_header(headers, header::ORIGIN),
        single_header(headers, header::REFERER),
    ) else {
        return false;
    };
    let trusted: Vec<&str> = cookie.trusted_origins.iter().map(String::as_str).collect();
    check_session_origin(&OriginRequest {
        secure_cookie: cookie.secure,
        // TLS 通常在上游终止；此时依赖可信来源精确匹配。
        transport_tls: false,
        host_headers: &host,
        origin_headers: &origin,
        referer_headers: &referer,
        trusted_urls: &trusted,
    })
    .is_ok()
}

/// 对齐 fasthttp `Peek`：重复头的多个值按逗号合并，解析器再按逗号切分。
fn joined_header(headers: &HeaderMap, name: header::HeaderName) -> Option<String> {
    let mut values = headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok());
    let first = values.next()?;
    Some(values.fold(first.to_owned(), |mut acc, value| {
        acc.push_str(", ");
        acc.push_str(value);
        acc
    }))
}

/// 可信代理链解析；`ConnectInfo` 缺失（测试直连）时 peer 为空，结果为空串，
/// 与登录中间件的处理一致。
pub(crate) fn request_ip(
    state: &AppState,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
) -> String {
    let forwarded_for = joined_header(headers, header::HeaderName::from_static("x-forwarded-for"));
    let real_ip = joined_header(headers, header::HeaderName::from_static("x-real-ip"));
    state.client_ip(
        peer.map(|address| address.ip()),
        forwarded_for.as_deref(),
        real_ip.as_deref(),
    )
}

/// Go `SearchRateLimit`（mark "SR"，用户维度）：未认证返回 401，429/500
/// 在 handler 写缓存头之前产生。
async fn search_guard(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let Some(user) = request
        .extensions()
        .get::<crate::auth::AuthenticatedUser>()
        .cloned()
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    match state
        .check_search_rate_limit(user.0.user_id, now_seconds())
        .await
    {
        Ok(None) => next.run(request).await,
        Ok(Some(retry_after)) => {
            let mut response = StatusCode::TOO_MANY_REQUESTS.into_response();
            if retry_after > 0
                && let Ok(value) = HeaderValue::from_str(&retry_after.to_string())
            {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            response
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// Go `UserCriticalRateLimit(scope)`：在 `UserAuth` 之后按用户 ID 限流，
/// 键为 `UC:<scope>` + user id；未认证（无扩展）时按 Go 返回 401。
async fn user_critical_guard(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let Some(user) = request
        .extensions()
        .get::<crate::auth::AuthenticatedUser>()
        .cloned()
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    match state
        .check_user_rate_limit("UC:access-token", user.0.user_id, now_seconds())
        .await
    {
        Ok(None) => next.run(request).await,
        Ok(Some(retry_after)) => {
            let mut response = StatusCode::TOO_MANY_REQUESTS.into_response();
            if retry_after > 0
                && let Ok(value) = HeaderValue::from_str(&retry_after.to_string())
            {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            response
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// Go `CriticalRateLimit`（mark "CT"）：仅做限流，429/500 都在
/// DisableCache 之前产生，因此响应不带缓存头。
async fn critical_guard(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0);
    let ip = request_ip(&state, request.headers(), peer);
    match state.check_rate_limit("CT", &ip, now_seconds()).await {
        Ok(None) => next.run(request).await,
        Ok(Some(retry_after)) => {
            let mut response = StatusCode::TOO_MANY_REQUESTS.into_response();
            if retry_after > 0
                && let Ok(value) = HeaderValue::from_str(&retry_after.to_string())
            {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            response
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// `POST /api/user/qq/bind/code` 的 Go `middleware.DisableCache()`：在
/// CriticalRateLimit 之后用 `SetHeader` 覆写三个 no-cache 头，只影响 handler
/// 的 200 响应；限流产生的 429/500 在本层之前，不带缓存头。
async fn qq_disable_cache_guard(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    disable_cache_headers(&mut response);
    response
}

/// refresh/logout 的保护链，复刻 Go 注册顺序：
/// `SessionCookieOriginGuard` → `CriticalRateLimit` → `DisableCache` → handler。
/// 因此 429 与限流后端故障（500）都在 DisableCache 之前产生，不带 no-cache 头。
async fn session_mutation_guard(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0);
    let ip = request_ip(&state, request.headers(), peer);
    if !origin_allowed(&state, request.headers()) {
        // Go 的来源守卫在 DisableCache 之前中止，因此拒绝响应不带缓存头。
        return auth_failure(StatusCode::FORBIDDEN, "AUTH_ORIGIN_FORBIDDEN");
    }
    let now = now_seconds();
    // Go `mark` 为 "CT"：内存键是 mark + ClientIP，Redis 键由 limiter 组装。
    match state.check_rate_limit("CT", &ip, now).await {
        Ok(None) => {}
        Ok(Some(retry_after)) => {
            let mut response = StatusCode::TOO_MANY_REQUESTS.into_response();
            if retry_after > 0
                && let Ok(value) = HeaderValue::from_str(&retry_after.to_string())
            {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            return response;
        }
        // Go 的 Redis 故障分支：500 空体，位于 DisableCache 之前。
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    let mut response = next.run(request).await;
    // handler 显式设置的 `Cache-Control: no-store` 必须保留（Go 的 setAuthNoStore）。
    fill_disable_cache_headers(&mut response);
    response
}

/// sessions 读端点：Go `UserAuth` → `DisableCache`，不参与关键路径限流。
async fn session_read_guard(
    State(_state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    disable_cache_headers(&mut response);
    response
}

pub(crate) fn set_cookie(
    response: &mut Response,
    value: &str,
    expires_at: i64,
    max_age: i64,
    secure: bool,
) {
    let mut cookie = format!(
        "{REFRESH_COOKIE}={value}; Path={REFRESH_COOKIE_PATH}; Expires={}; Max-Age={}; HttpOnly; SameSite=Strict",
        format_http_date(expires_at),
        max_age.max(1)
    );
    if secure {
        cookie.push_str("; Secure");
    }
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

fn clear_cookie(response: &mut Response, secure: bool) {
    // Go `ClearRefreshCookie` 设置 `MaxAge=-1`、`Expires=time.Unix(1,0)`；
    // stdlib 对 `MaxAge < 0` 序列化为 `Max-Age=0`（net/http cookie.go），因此
    // 线上字节是 `Expires=Thu, 01 Jan 1970 00:00:01 GMT; Max-Age=0`。
    let mut cookie = format!(
        "{REFRESH_COOKIE}=; Path={REFRESH_COOKIE_PATH}; Expires=Thu, 01 Jan 1970 00:00:01 GMT; Max-Age=0; HttpOnly; SameSite=Strict"
    );
    if secure {
        cookie.push_str("; Secure");
    }
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

/// RFC1123 HTTP-date（UTC，固定 `GMT` 后缀），对齐 Go `net/http` Cookie.String()
/// 与 `httpdate::fmt_http_date` 输出。算法移植自 httpdate 1.0.3（MIT OR
/// Apache-2.0，`src/date.rs`），只依赖整数算术，不引入额外直接依赖。
pub(crate) fn format_http_date(epoch: i64) -> String {
    let epoch = epoch.clamp(0, 253_402_300_799);
    let days = epoch.div_euclid(86_400);
    let secs = epoch.rem_euclid(86_400);
    let hour = (secs / 3_600) as u32;
    let min = ((secs % 3_600) / 60) as u32;
    let sec = (secs % 60) as u32;

    const WEEKDAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    const LEAPOCH: i64 = 11_017;
    const DAYS_PER_400Y: i64 = 365 * 400 + 97;
    const DAYS_PER_100Y: i64 = 365 * 100 + 24;
    const DAYS_PER_4Y: i64 = 365 * 4 + 1;
    const MONTH_LENGTHS: [i64; 12] = [31, 30, 31, 30, 31, 31, 30, 31, 30, 31, 31, 29];

    let days_since_leapoch = days - LEAPOCH;
    let mut quad_century_cycles = days_since_leapoch / DAYS_PER_400Y;
    let mut remdays = days_since_leapoch % DAYS_PER_400Y;
    if remdays < 0 {
        remdays += DAYS_PER_400Y;
        quad_century_cycles -= 1;
    }

    let mut century_cycles = remdays / DAYS_PER_100Y;
    if century_cycles == 4 {
        century_cycles -= 1;
    }
    remdays -= century_cycles * DAYS_PER_100Y;

    let mut quad_cycles = remdays / DAYS_PER_4Y;
    if quad_cycles == 25 {
        quad_cycles -= 1;
    }
    remdays -= quad_cycles * DAYS_PER_4Y;

    let mut remyears = remdays / 365;
    if remyears == 4 {
        remyears -= 1;
    }
    remdays -= remyears * 365;

    let mut year =
        2000 + remyears + 4 * quad_cycles + 100 * century_cycles + 400 * quad_century_cycles;

    let mut month_index = 0usize;
    for month_len in MONTH_LENGTHS {
        month_index += 1;
        if remdays < month_len {
            break;
        }
        remdays -= month_len;
    }
    let mday = remdays + 1;
    let month = if month_index + 2 > 12 {
        year += 1;
        month_index - 10
    } else {
        month_index + 2
    };

    let mut wday = (3 + days_since_leapoch) % 7;
    if wday <= 0 {
        wday += 7;
    }

    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        WEEKDAYS[(wday - 1) as usize],
        mday,
        MONTHS[month - 1],
        year,
        hour,
        min,
        sec
    )
}

async fn refresh(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !origin_allowed(&state, &headers) {
        return no_store(auth_failure(StatusCode::FORBIDDEN, "AUTH_ORIGIN_FORBIDDEN"));
    }
    let Some(auth) = state.auth() else {
        return no_store(auth_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "AUTH_INTERNAL_ERROR",
        ));
    };
    let secure = state.session_cookie().secure;
    let Some(raw) = cookie_value(&headers, REFRESH_COOKIE) else {
        let mut response = auth_failure(StatusCode::UNAUTHORIZED, "AUTH_UNAUTHORIZED");
        clear_cookie(&mut response, secure);
        return no_store(response);
    };
    let expected = headers
        .get("x-auth-session")
        .and_then(|value| value.to_str().ok());
    let now = now_seconds();
    match auth.refresh(&raw, expected, now).await {
        Ok(result) => {
            let max_age = result.session.expires_at - now;
            let expires_at = result.session.expires_at;
            let body = RotationBody {
                access_token: result.access_token.expose_secret().to_owned(),
                token_type: "Bearer",
                access_expires_at: result.access_expires_at,
                session: result.session.into(),
            };
            let mut response = success_data(body);
            set_cookie(
                &mut response,
                result.refresh_token.expose_secret(),
                expires_at,
                max_age,
                secure,
            );
            no_store(response)
        }
        Err(error) => {
            let mut response = match error {
                SessionAuthError::RefreshInvalid => {
                    auth_failure(StatusCode::UNAUTHORIZED, "AUTH_UNAUTHORIZED")
                }
                SessionAuthError::SessionRevoked => {
                    auth_failure(StatusCode::UNAUTHORIZED, "AUTH_SESSION_REVOKED")
                }
                SessionAuthError::SessionMismatch => {
                    auth_failure(StatusCode::CONFLICT, "AUTH_SESSION_MISMATCH")
                }
                SessionAuthError::Race => auth_failure(StatusCode::CONFLICT, "AUTH_REFRESH_RACE"),
                SessionAuthError::SessionIdRequired => {
                    auth_failure(StatusCode::BAD_REQUEST, "AUTH_SESSION_ID_REQUIRED")
                }
                SessionAuthError::Unauthorized => {
                    auth_failure(StatusCode::UNAUTHORIZED, "AUTH_UNAUTHORIZED")
                }
                SessionAuthError::TokenExpired => {
                    auth_failure(StatusCode::UNAUTHORIZED, "AUTH_TOKEN_EXPIRED")
                }
                SessionAuthError::Fence => {
                    tracing::error!(event = "auth_fence_error", "session fence failed");
                    auth_failure(StatusCode::INTERNAL_SERVER_ERROR, "AUTH_INTERNAL_ERROR")
                }
                SessionAuthError::Storage(_) | SessionAuthError::BatchFailed { .. } => {
                    tracing::error!(event = "auth_storage_error", "session refresh failed");
                    auth_failure(StatusCode::INTERNAL_SERVER_ERROR, "AUTH_INTERNAL_ERROR")
                }
            };
            // 无效或已撤销的凭据必须清掉浏览器里的旧 Cookie。
            if matches!(
                error,
                SessionAuthError::RefreshInvalid | SessionAuthError::SessionRevoked
            ) {
                clear_cookie(&mut response, secure);
            }
            no_store(response)
        }
    }
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !origin_allowed(&state, &headers) {
        return no_store(auth_failure(StatusCode::FORBIDDEN, "AUTH_ORIGIN_FORBIDDEN"));
    }
    let Some(auth) = state.auth() else {
        return no_store(auth_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "AUTH_INTERNAL_ERROR",
        ));
    };
    let secure = state.session_cookie().secure;
    let now = now_seconds();
    let expected = headers
        .get("x-auth-session")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let raw_cookie = cookie_value(&headers, REFRESH_COOKIE);

    // 原实现先比较 Cookie SID 与期望 SID：不一致即 409，且不清 Cookie。
    if let Some(expected) = expected
        && let Some(cookie_sid) = raw_cookie.as_deref().and_then(|raw| {
            newapi_identity::crypto::RefreshCredential::parse(raw)
                .ok()
                .map(|credential| credential.sid().to_owned())
        })
        && expected != cookie_sid.as_str()
    {
        return no_store(auth_failure(StatusCode::CONFLICT, "AUTH_SESSION_MISMATCH"));
    }

    // 有有效访问令牌时按其 SID 注销，并只在 Cookie 属于同一会话时清 Cookie。
    if let Some(token) = bearer(&headers)
        && let Ok(identity) = auth.parse_access(token, now)
    {
        if expected.is_some_and(|value| value != identity.sid.as_str()) {
            return no_store(auth_failure(StatusCode::CONFLICT, "AUTH_SESSION_MISMATCH"));
        }
        if auth.revoke_session(&identity, now).await.is_err() {
            tracing::error!(event = "auth_storage_error", "session revoke failed");
            return no_store(auth_failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "AUTH_INTERNAL_ERROR",
            ));
        }
        let cookie_cleared = match raw_cookie.as_deref() {
            Some(raw) => raw
                .split_once('.')
                .is_some_and(|(sid, _)| sid == identity.sid.as_str()),
            None => false,
        };
        if cookie_cleared
            && auth
                .logout(raw_cookie.as_deref(), Some(identity.sid.as_str()), now)
                .await
                .is_err()
        {
            return no_store(auth_failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "AUTH_INTERNAL_ERROR",
            ));
        }
        let mut response = success_data(LogoutBody {
            revoked_sid: identity.sid,
            cookie_cleared,
        });
        // 只清属于本次注销会话的 Cookie，不能误清另一会话。
        if cookie_cleared {
            clear_cookie(&mut response, secure);
        }
        return no_store(response);
    }

    match auth.logout(raw_cookie.as_deref(), expected, now).await {
        Ok(()) => {
            let mut response = Json(MessageEnvelope {
                success: true,
                message: "",
            })
            .into_response();
            clear_cookie(&mut response, secure);
            no_store(response)
        }
        Err(SessionAuthError::SessionMismatch) => {
            no_store(auth_failure(StatusCode::CONFLICT, "AUTH_SESSION_MISMATCH"))
        }
        Err(_) => {
            tracing::error!(event = "auth_storage_error", "session logout failed");
            no_store(auth_failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "AUTH_INTERNAL_ERROR",
            ))
        }
    }
}

async fn sessions(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(auth) = state.auth() else {
        return no_store(auth_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "AUTH_INTERNAL_ERROR",
        ));
    };
    let Some(token) = bearer(&headers) else {
        return no_store(auth_failure(StatusCode::UNAUTHORIZED, "AUTH_UNAUTHORIZED"));
    };
    let now = now_seconds();
    let identity = match auth.identify(token, now).await {
        Ok(identity) => identity,
        Err(SessionAuthError::Storage(_)) => {
            return no_store(auth_failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "AUTH_INTERNAL_ERROR",
            ));
        }
        // Go UserAuth 对过期访问令牌回 AUTH_TOKEN_EXPIRED（authenticate.go:206-207）。
        Err(SessionAuthError::TokenExpired) => {
            return no_store(auth_failure(StatusCode::UNAUTHORIZED, "AUTH_TOKEN_EXPIRED"));
        }
        Err(_) => {
            return no_store(auth_failure(
                StatusCode::UNAUTHORIZED,
                "AUTH_SESSION_REVOKED",
            ));
        }
    };
    match auth.sessions(&identity, now).await {
        Ok(list) => {
            let body: Vec<SessionBody> = list.into_iter().map(SessionBody::from).collect();
            no_store(success_data(body))
        }
        Err(_) => {
            tracing::error!(event = "auth_storage_error", "session list failed");
            no_store(auth_failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "AUTH_INTERNAL_ERROR",
            ))
        }
    }
}

#[derive(Serialize)]
struct DeletedSessionBody {
    revoked_sid: String,
    current: bool,
}

#[derive(Serialize)]
struct RevokedOthersBody {
    revoked_count: u64,
}

async fn session_identity(
    state: &AppState,
    headers: &HeaderMap,
    now: i64,
) -> Result<newapi_identity::AuthIdentity, (StatusCode, &'static str)> {
    let auth = state
        .auth()
        .ok_or((StatusCode::SERVICE_UNAVAILABLE, "AUTH_INTERNAL_ERROR"))?;
    let token = bearer(headers).ok_or((StatusCode::UNAUTHORIZED, "AUTH_UNAUTHORIZED"))?;
    auth.identify(token, now)
        .await
        .map_err(|error| match error {
            SessionAuthError::Storage(_)
            | SessionAuthError::BatchFailed { .. }
            | SessionAuthError::Fence => (StatusCode::INTERNAL_SERVER_ERROR, "AUTH_INTERNAL_ERROR"),
            // Go UserAuth 对过期访问令牌回 AUTH_TOKEN_EXPIRED（authenticate.go:206-207）。
            SessionAuthError::TokenExpired => (StatusCode::UNAUTHORIZED, "AUTH_TOKEN_EXPIRED"),
            SessionAuthError::RefreshInvalid
            | SessionAuthError::SessionRevoked
            | SessionAuthError::SessionMismatch
            | SessionAuthError::Race
            | SessionAuthError::SessionIdRequired
            | SessionAuthError::Unauthorized => (StatusCode::UNAUTHORIZED, "AUTH_SESSION_REVOKED"),
        })
}

async fn delete_session(
    State(state): State<AppState>,
    Path(sid): Path<String>,
    headers: HeaderMap,
) -> Response {
    let now = now_seconds();
    let identity = match session_identity(&state, &headers, now).await {
        Ok(identity) => identity,
        Err((status, code)) => return no_store(auth_failure(status, code)),
    };
    let sid = sid.trim();
    if sid.is_empty() {
        return no_store(
            (
                StatusCode::BAD_REQUEST,
                Json(AuthFailure {
                    success: false,
                    code: "AUTH_SESSION_ID_REQUIRED",
                    message: "session id is required",
                }),
            )
                .into_response(),
        );
    }
    let auth = state.auth().expect("身份验证已确认服务存在");
    match auth.revoke_sid(&identity, sid, now).await {
        Ok(true) => {
            let mut response = success_data(DeletedSessionBody {
                revoked_sid: sid.to_owned(),
                current: sid == identity.sid,
            });
            if cookie_value(&headers, REFRESH_COOKIE)
                .and_then(|raw| newapi_identity::crypto::RefreshCredential::parse(&raw).ok())
                .is_some_and(|credential| credential.sid() == sid)
            {
                clear_cookie(&mut response, state.session_cookie().secure);
            }
            no_store(response)
        }
        Ok(false) => no_store(
            (
                StatusCode::NOT_FOUND,
                Json(AuthFailure {
                    success: false,
                    code: "AUTH_SESSION_NOT_FOUND",
                    message: "session not found",
                }),
            )
                .into_response(),
        ),
        Err(_) => no_store(auth_failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "AUTH_INTERNAL_ERROR",
        )),
    }
}

async fn revoke_other_sessions(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let now = now_seconds();
    let identity = match session_identity(&state, &headers, now).await {
        Ok(identity) => identity,
        Err((status, code)) => return no_store(auth_failure(status, code)),
    };
    let auth = state.auth().expect("身份验证已确认服务存在");
    match auth.revoke_others(&identity, now).await {
        Ok(revoked_count) => no_store(success_data(RevokedOthersBody { revoked_count })),
        Err(SessionAuthError::BatchFailed {
            committed_count, ..
        }) => {
            tracing::error!(
                event = "session_batch_failure",
                committed_count,
                "会话批次撤销未全部完成"
            );
            no_store(auth_failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "AUTH_INTERNAL_ERROR",
            ))
        }
        Err(_) => no_store(auth_failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "AUTH_INTERNAL_ERROR",
        )),
    }
}

async fn not_found() -> Response {
    failure(StatusCode::NOT_FOUND, "not found")
}

async fn method_not_allowed() -> Response {
    failure(StatusCode::METHOD_NOT_ALLOWED, "method not allowed")
}

/// Do not use the default TraceLayer span: it records the URI, including query
/// credentials. Never trust or log an incoming request-id/header/body either.
async fn boundary(request: Request, next: Next) -> Response {
    // 登录路由的体上限由 login_guard 按 Go 顺序处理（并带 no-cache 头），
    // 这里不预缓冲，否则会先按 64KB 截断。
    if is_login_path(request.uri().path()) {
        return boundary_inner(request, next, Duration::from_secs(30), None).await;
    }
    boundary_inner(request, next, Duration::from_secs(30), Some(MAX_BODY_BYTES)).await
}

fn is_login_path(path: &str) -> bool {
    matches!(path, "/api/user/login" | "/api/user/login/2fa")
}

// 测试可注入短超时，无需等待生产环境的三十秒期限。
#[cfg(test)]
async fn boundary_with_timeout(request: Request, next: Next, timeout: Duration) -> Response {
    boundary_inner(request, next, timeout, Some(MAX_BODY_BYTES)).await
}

async fn boundary_inner(
    request: Request,
    next: Next,
    timeout: Duration,
    buffer_limit: Option<usize>,
) -> Response {
    let is_head = request.method() == Method::HEAD;
    let id = REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    // A Tokio task boundary catches unwinding handler panics without an extra
    // dependency. main installs a hook that never emits the panic payload.
    let mut task = tokio::spawn(async move {
        let Some(limit) = buffer_limit else {
            return next.run(request).await;
        };
        let (parts, body) = request.into_parts();
        // Read a bounded body even for GET and fallbacks: extractor-only limits
        // otherwise do not protect endpoints that never extract their body.
        match to_bytes(body, limit).await {
            Ok(bytes) => {
                next.run(Request::from_parts(parts, Body::from(bytes)))
                    .await
            }
            Err(_) => failure(StatusCode::PAYLOAD_TOO_LARGE, "request body rejected"),
        }
    });
    // Dropping the HTTP future (client disconnect) must not detach body reads.
    let _abort_on_drop = AbortOnDrop(task.abort_handle());
    let mut response = match tokio::time::timeout(timeout, &mut task).await {
        Ok(Ok(response)) => response,
        Ok(Err(_)) => failure(StatusCode::INTERNAL_SERVER_ERROR, "internal server error"),
        Err(_) => {
            task.abort();
            let _ = task.await;
            failure(StatusCode::REQUEST_TIMEOUT, "request timed out")
        }
    };
    // 外层产生的错误不经过 Axum 的 HEAD 路由处理，必须在最终出口统一去体。
    // 保留原响应头和状态，不把 GET 表示长度改成零。
    if is_head {
        *response.body_mut() = Body::empty();
    }
    if let Ok(value) = HeaderValue::from_str(&format!("p1-{id}")) {
        response.headers_mut().insert("x-request-id", value);
    }
    tracing::info!(
        request_id = id,
        status = response.status().as_u16(),
        "request completed"
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    fn auth_state(db: newapi_storage::Database, secure: bool) -> AppState {
        use newapi_identity::{
            auth_session::{AuthFence, SessionAuth},
            crypto::AuthKeys,
            sessions::NoCache,
        };
        AppState::default().bind_auth(
            std::sync::Arc::new(SessionAuth::with_fence(
                db,
                AuthKeys::new("test-session-secret"),
                AuthFence::Disabled(NoCache::explicitly_disabled()),
            )),
            newapi_config::SessionCookieSettings {
                secure,
                trusted_origins: vec!["https://console.example".into()],
            },
        )
    }

    #[tokio::test]
    async fn storage_failures_never_become_logout_success_or_session_unauthorized() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .connect_lazy("sqlite::memory:")
            .unwrap();
        pool.close().await;
        let state = auth_state(newapi_storage::Database::Sqlite(pool), false);
        let now = now_seconds();
        let identity = newapi_identity::AuthIdentity {
            user_id: 1,
            sid: "ffffffff-ffff-4fff-8fff-ffffffffffff".into(),
            user_auth_version: 1,
            session_version: 1,
        };
        let token = newapi_identity::crypto::AuthKeys::new("test-session-secret")
            .issue_access(&identity, now)
            .unwrap();
        for path in ["/api/user/auth/logout", "/api/user/sessions"] {
            let response = build_router(state.clone())
                .oneshot(
                    Request::builder()
                        .method(if path.ends_with("logout") {
                            Method::POST
                        } else {
                            Method::GET
                        })
                        .uri(path)
                        .header(
                            header::AUTHORIZATION,
                            format!("Bearer {}", token.token.expose_secret()),
                        )
                        .header(
                            header::COOKIE,
                            "new_api_refresh=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa.secret",
                        )
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            assert!(!response.headers().contains_key(header::SET_COOKIE));
            let body = to_bytes(response.into_body(), 1024).await.unwrap();
            assert!(
                std::str::from_utf8(&body)
                    .unwrap()
                    .contains("\"code\":\"AUTH_INTERNAL_ERROR\"")
            );
        }
        let response = build_router(state)
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/user/auth/logout")
                    .header(
                        header::COOKIE,
                        "new_api_refresh=ffffffff-ffff-4fff-8fff-ffffffffffff.secret",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!response.headers().contains_key(header::SET_COOKIE));
    }

    #[tokio::test]
    async fn secure_origin_rejects_undecodable_values_without_fallback() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .connect_lazy("sqlite::memory:")
            .unwrap();
        let state = auth_state(newapi_storage::Database::Sqlite(pool), true);
        for second_valid in [false, true] {
            let mut request = Request::builder()
                .method(Method::POST)
                .uri("/api/user/auth/refresh")
                .header(header::HOST, "console.example")
                .header(header::REFERER, "https://console.example/")
                .body(Body::empty())
                .unwrap();
            request
                .headers_mut()
                .append(header::ORIGIN, HeaderValue::from_bytes(b"\xff").unwrap());
            if second_valid {
                request.headers_mut().append(
                    header::ORIGIN,
                    HeaderValue::from_static("https://console.example"),
                );
            }
            let response = build_router(state.clone()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            let body = to_bytes(response.into_body(), 1024).await.unwrap();
            assert!(
                std::str::from_utf8(&body)
                    .unwrap()
                    .contains("\"code\":\"AUTH_ORIGIN_FORBIDDEN\"")
            );
        }
    }

    #[tokio::test]
    async fn session_management_http_preserves_ownership_and_cookie_scope() {
        use newapi_identity::{
            crypto::{AuthKeys, RefreshCredential},
            sessions::{CreateSession, RefreshHash, SessionLimits, SessionRepository},
        };
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        for ddl in [
            "CREATE TABLE users (id INTEGER PRIMARY KEY,status INTEGER,auth_version BIGINT,deleted_at TIMESTAMP)",
            "INSERT INTO users VALUES (1,1,1,NULL),(2,1,1,NULL)",
            "CREATE TABLE user_sessions (sid TEXT PRIMARY KEY,user_id INTEGER,version BIGINT,user_auth_version BIGINT,status TEXT,refresh_hash TEXT,previous_refresh_hash TEXT,previous_valid_until BIGINT,login_method TEXT,ip TEXT,user_agent TEXT,created_at BIGINT,last_active_at BIGINT,expires_at BIGINT,revoked_at BIGINT,revoked_reason TEXT)",
        ] {
            sqlx::query(ddl).execute(&pool).await.unwrap();
        }
        let db = newapi_storage::Database::Sqlite(pool);
        let repo = SessionRepository::new(db.clone());
        let keys = AuthKeys::new("test-session-secret");
        let now = now_seconds();
        let current = RefreshCredential::generate().unwrap();
        let other = RefreshCredential::generate().unwrap();
        let foreign = RefreshCredential::generate().unwrap();
        for (credential, user_id) in [(&current, 1), (&other, 1), (&foreign, 2)] {
            repo.create(
                CreateSession {
                    sid: credential.sid().to_owned(),
                    user_id,
                    expected_auth_version: Some(1),
                    refresh_hash: RefreshHash::from_lower_hex(
                        keys.refresh_hash(credential.secret())
                            .expose_secret()
                            .to_owned(),
                    )
                    .unwrap(),
                    login_method: "password".into(),
                    ip: "127.0.0.1".into(),
                    user_agent: "fixture".into(),
                },
                SessionLimits::default(),
                now,
            )
            .await
            .unwrap();
        }
        let token = keys
            .issue_access(
                &newapi_identity::AuthIdentity {
                    user_id: 1,
                    sid: current.sid().into(),
                    user_auth_version: 1,
                    session_version: 1,
                },
                now,
            )
            .unwrap();
        let app = build_router(auth_state(db.clone(), false));
        let authorization = format!("Bearer {}", token.token.expose_secret());
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::DELETE)
                    .uri(format!("/api/user/sessions/{}", foreign.sid()))
                    .header(header::AUTHORIZATION, &authorization)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        assert!(
            std::str::from_utf8(&body)
                .unwrap()
                .contains("AUTH_SESSION_NOT_FOUND")
        );
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::DELETE)
                    .uri(format!("/api/user/sessions/{}", other.sid()))
                    .header(header::AUTHORIZATION, &authorization)
                    .header(
                        header::COOKIE,
                        format!("new_api_refresh={}", current.raw().expose_secret()),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key(header::SET_COOKIE));
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/user/sessions/revoke-others")
                    .header(header::AUTHORIZATION, &authorization)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        assert!(
            std::str::from_utf8(&body)
                .unwrap()
                .contains("\"revoked_count\":0")
        );
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::DELETE)
                    .uri(format!("/api/user/sessions/{}", current.sid()))
                    .header(header::AUTHORIZATION, &authorization)
                    .header(
                        header::COOKIE,
                        format!("new_api_refresh={}", current.raw().expose_secret()),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().contains_key(header::SET_COOKIE));
        assert_eq!(
            repo.authoritative(foreign.sid())
                .await
                .unwrap()
                .unwrap()
                .metadata
                .status,
            "active"
        );
        db.close().await;
    }

    #[tokio::test]
    async fn session_routes_are_registered_in_production_router() {
        for (method, path) in [
            (Method::POST, "/api/user/auth/refresh"),
            (Method::POST, "/api/user/auth/logout"),
            (Method::GET, "/api/user/sessions"),
            (Method::DELETE, "/api/user/sessions/example"),
            (Method::POST, "/api/user/sessions/revoke-others"),
        ] {
            let response = router(AppState::default())
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_ne!(response.status(), StatusCode::NOT_FOUND, "{path}");
            // 未注入认证编排时，所有会话端点统一返回不可用。
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{path}");
        }
    }

    #[test]
    fn cookie_and_bearer_parsing_rejects_ambiguity() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("a=1; new_api_refresh=sid.secret; b=2"),
        );
        assert_eq!(
            cookie_value(&headers, REFRESH_COOKIE).as_deref(),
            Some("sid.secret")
        );
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer token-1"),
        );
        assert_eq!(bearer(&headers), Some("token-1"));
        for malformed in ["Bearer a b", "Basic x", "Bearer", "Bearer  "] {
            headers.insert(
                header::AUTHORIZATION,
                HeaderValue::from_str(malformed).unwrap(),
            );
            assert_eq!(bearer(&headers), None, "accepted {malformed}");
        }
    }

    #[test]
    fn refresh_cookie_carries_required_attributes() {
        let mut response = StatusCode::OK.into_response();
        set_cookie(&mut response, "sid.secret", 1_700_000_005, 5, true);
        let value = response.headers()[header::SET_COOKIE].to_str().unwrap();
        for attribute in [
            "new_api_refresh=sid.secret",
            "Path=/api/user/auth",
            "Expires=Tue, 14 Nov 2023 22:13:25 GMT",
            "Max-Age=5",
            "HttpOnly",
            "SameSite=Strict",
            "; Secure",
        ] {
            assert!(value.contains(attribute), "missing {attribute} in {value}");
        }
        // Go Cookie.String() 写 Expires 后紧跟 Max-Age。
        assert!(
            value.contains("Expires=Tue, 14 Nov 2023 22:13:25 GMT; Max-Age=5"),
            "unexpected cookie attribute order in {value}"
        );
        let mut cleared = StatusCode::OK.into_response();
        clear_cookie(&mut cleared, false);
        let value = cleared.headers()[header::SET_COOKIE].to_str().unwrap();
        for attribute in [
            "Expires=Thu, 01 Jan 1970 00:00:01 GMT",
            "Max-Age=0",
            "HttpOnly",
            "SameSite=Strict",
        ] {
            assert!(value.contains(attribute), "missing {attribute} in {value}");
        }
        assert!(
            value.contains("Expires=Thu, 01 Jan 1970 00:00:01 GMT; Max-Age=0"),
            "unexpected clear-cookie attribute order in {value}"
        );
        assert!(!value.contains("; Secure"));
    }

    #[test]
    fn format_http_date_matches_go_rfc1123_vectors() {
        for (epoch, expected) in [
            (0, "Thu, 01 Jan 1970 00:00:00 GMT"),
            (1, "Thu, 01 Jan 1970 00:00:01 GMT"),
            (1_700_000_000, "Tue, 14 Nov 2023 22:13:20 GMT"),
            (2_000_000_000, "Wed, 18 May 2033 03:33:20 GMT"),
            (951_782_399, "Mon, 28 Feb 2000 23:59:59 GMT"),
            (951_782_400, "Tue, 29 Feb 2000 00:00:00 GMT"),
            (4_107_542_399, "Sun, 28 Feb 2100 23:59:59 GMT"),
            (4_107_542_400, "Mon, 01 Mar 2100 00:00:00 GMT"),
            (253_402_300_799, "Fri, 31 Dec 9999 23:59:59 GMT"),
        ] {
            assert_eq!(format_http_date(epoch), expected, "epoch {epoch}");
        }
    }

    #[test]
    fn insecure_mode_skips_origin_validation() {
        let state = AppState::default();
        assert!(origin_allowed(&state, &HeaderMap::new()));
    }

    #[tokio::test]
    async fn head_boundary_errors_have_no_body() {
        async fn panic_handler() -> StatusCode {
            panic!("private panic payload")
        }
        async fn blocked_handler() -> StatusCode {
            std::future::pending().await
        }
        async fn short_boundary(request: Request, next: Next) -> Response {
            let timeout = if request.uri().path() == "/blocked" {
                Duration::from_millis(10)
            } else {
                Duration::from_secs(30)
            };
            boundary_with_timeout(request, next, timeout).await
        }
        let app = Router::new()
            .route("/ok", get(|| async { StatusCode::OK }))
            .route("/panic", get(panic_handler))
            .route("/blocked", get(blocked_handler))
            .layer(middleware::from_fn(short_boundary));
        for (path, size, expected) in [
            ("/ok", MAX_BODY_BYTES + 1, StatusCode::PAYLOAD_TOO_LARGE),
            ("/blocked", 0, StatusCode::REQUEST_TIMEOUT),
            ("/panic", 0, StatusCode::INTERNAL_SERVER_ERROR),
        ] {
            for method in [Method::GET, Method::HEAD] {
                let is_head = method == Method::HEAD;
                let response = app
                    .clone()
                    .oneshot(
                        Request::builder()
                            .method(method)
                            .uri(path)
                            .body(Body::from(vec![b'x'; size]))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), expected);
                assert_eq!(response.headers()["content-type"], "application/json");
                assert!(response.headers().contains_key("x-request-id"));
                let bytes = to_bytes(response.into_body(), 1024).await.unwrap();
                assert_eq!(bytes.is_empty(), is_head);
                assert!(!String::from_utf8_lossy(&bytes).contains("private panic payload"));
            }
        }
    }

    #[tokio::test]
    async fn panic_returns_sanitized_json_and_request_id() {
        async fn panic_handler() -> StatusCode {
            panic!("private panic payload")
        }
        let app = Router::new()
            .route("/panic", get(panic_handler))
            .layer(middleware::from_fn(boundary));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/panic")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(response.headers().contains_key("x-request-id"));
        let bytes = to_bytes(response.into_body(), 1024).await.unwrap();
        assert_eq!(
            bytes.as_ref(),
            br#"{"success":false,"message":"internal server error","data":""}"#
        );
    }
}
