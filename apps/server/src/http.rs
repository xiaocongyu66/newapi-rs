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
    routing::{delete, get, post},
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
        .route("/health/live", get(live))
        .route("/health/ready", get(ready));
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
    app.fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(middleware::from_fn_with_state(
            global_limit_state,
            crate::global_limit::global_api_rate_limit,
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

pub(crate) fn set_cookie(response: &mut Response, value: &str, max_age: i64, secure: bool) {
    let mut cookie = format!(
        "{REFRESH_COOKIE}={value}; Path={REFRESH_COOKIE_PATH}; Max-Age={}; HttpOnly; SameSite=Strict",
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
    let mut cookie = format!(
        "{REFRESH_COOKIE}=; Path={REFRESH_COOKIE_PATH}; Max-Age=0; HttpOnly; SameSite=Strict"
    );
    if secure {
        cookie.push_str("; Secure");
    }
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
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
        set_cookie(&mut response, "sid.secret", 5, true);
        let value = response.headers()[header::SET_COOKIE].to_str().unwrap();
        for attribute in [
            "new_api_refresh=sid.secret",
            "Path=/api/user/auth",
            "Max-Age=5",
            "HttpOnly",
            "SameSite=Strict",
            "; Secure",
        ] {
            assert!(value.contains(attribute), "missing {attribute} in {value}");
        }
        let mut cleared = StatusCode::OK.into_response();
        clear_cookie(&mut cleared, false);
        let value = cleared.headers()[header::SET_COOKIE].to_str().unwrap();
        assert!(value.contains("Max-Age=0"));
        assert!(!value.contains("; Secure"));
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
