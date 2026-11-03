use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use newapi_identity::auth_session::{SessionAuthError, SessionView};
use newapi_security::{OriginRequest, check_session_origin};
use serde::Serialize;

use crate::AppState;

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
    Router::new()
        .route("/api/notice", get(notice))
        .route("/api/about", get(about))
        .route("/api/home_page_content", get(home_page_content))
        .route("/api/user-agreement", get(user_agreement))
        .route("/api/privacy-policy", get(privacy_policy))
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/api/user/auth/refresh", post(refresh))
        .route("/api/user/auth/logout", post(logout))
        .route("/api/user/sessions", get(sessions))
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
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
struct SessionBody {
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

fn now_seconds() -> i64 {
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

fn single_header<'a>(headers: &'a HeaderMap, name: header::HeaderName) -> Vec<&'a str> {
    headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect()
}

/// 仅在 Secure Cookie 模式校验来源；明文本地开发保持原行为。
fn origin_allowed(state: &AppState, headers: &HeaderMap) -> bool {
    let cookie = state.session_cookie();
    let host = single_header(headers, header::HOST);
    let origin = single_header(headers, header::ORIGIN);
    let referer = single_header(headers, header::REFERER);
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

fn set_cookie(response: &mut Response, value: &str, max_age: i64, secure: bool) {
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
                SessionAuthError::Storage(_) => {
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

    // 有有效访问令牌时按其 SID 注销，并只在 Cookie 属于同一会话时清 Cookie。
    if let Some(token) = bearer(&headers) {
        if let Ok(identity) = auth.identify(token, now).await {
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
            if cookie_cleared {
                let _ = auth
                    .logout(raw_cookie.as_deref(), Some(identity.sid.as_str()), now)
                    .await;
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
    let Ok(identity) = auth.identify(token, now).await else {
        return no_store(auth_failure(
            StatusCode::UNAUTHORIZED,
            "AUTH_SESSION_REVOKED",
        ));
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

async fn not_found() -> Response {
    failure(StatusCode::NOT_FOUND, "not found")
}

async fn method_not_allowed() -> Response {
    failure(StatusCode::METHOD_NOT_ALLOWED, "method not allowed")
}

/// Do not use the default TraceLayer span: it records the URI, including query
/// credentials. Never trust or log an incoming request-id/header/body either.
async fn boundary(request: Request, next: Next) -> Response {
    boundary_with_timeout(request, next, Duration::from_secs(30)).await
}

// 测试可注入短超时，无需等待生产环境的三十秒期限。
async fn boundary_with_timeout(request: Request, next: Next, timeout: Duration) -> Response {
    let is_head = request.method() == Method::HEAD;
    let id = REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    // A Tokio task boundary catches unwinding handler panics without an extra
    // dependency. main installs a hook that never emits the panic payload.
    let mut task = tokio::spawn(async move {
        let (parts, body) = request.into_parts();
        // Read a bounded body even for GET and fallbacks: extractor-only limits
        // otherwise do not protect endpoints that never extract their body.
        match to_bytes(body, MAX_BODY_BYTES).await {
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
