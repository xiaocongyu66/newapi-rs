//! HTTP contracts for the session routes wired into the production router.
//! Run only in GitHub Actions; every database here is an isolated in-memory
//! fixture (or a lazy pool that the tested paths never touch).
use std::net::SocketAddr;

use axum::{
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{HeaderMap, Method, Request, StatusCode, header},
    response::Response,
};
use newapi_config::SessionCookieSettings;
use newapi_identity::{
    auth_session::{AuthFence, SessionAuth},
    crypto::AuthKeys,
    sessions::NoCache,
};
use newapi_security::client_ip::ProxyPolicy;
use newapi_server::{AppState, RateLimiter, limit::RateLimitSettings, router};
use newapi_storage::Database;
use tower::ServiceExt;

const ANONYMOUS_LIMIT_KB: i64 = 512;
const CACHE_CONTROL_VALUE: &str = "no-store, no-cache, must-revalidate, private, max-age=0";

fn peer(ip: &str) -> SocketAddr {
    format!("{ip}:40000").parse().unwrap()
}

/// 绑定认证编排但没有可用数据库：未到数据库的路径（缺 Cookie / 缺 Bearer）
/// 才能返回 401，而不会落到 503。
fn auth_state(secure: bool) -> AppState {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .connect_lazy("sqlite::memory:")
        .unwrap();
    AppState::default().bind_auth(
        std::sync::Arc::new(SessionAuth::with_fence(
            Database::Sqlite(pool),
            AuthKeys::new("test-session-secret"),
            AuthFence::Disabled(NoCache::explicitly_disabled()),
        )),
        SessionCookieSettings {
            secure,
            trusted_origins: vec!["https://console.example".into()],
        },
    )
}

fn transport_state(rate_limit: RateLimitSettings) -> AppState {
    AppState::default().bind_transport(
        ProxyPolicy::parse_trusted_proxies(None).unwrap(),
        RateLimiter::memory(rate_limit),
        ANONYMOUS_LIMIT_KB,
    )
}

async fn send(state: &AppState, request: Request<Body>) -> Response {
    send_from(state, peer("198.51.100.99"), request).await
}

async fn send_from(state: &AppState, peer: SocketAddr, mut request: Request<Body>) -> Response {
    request.extensions_mut().insert(ConnectInfo(peer));
    router(state.clone()).oneshot(request).await.unwrap()
}

async fn body_bytes(response: Response) -> Vec<u8> {
    to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .unwrap()
        .to_vec()
}

async fn body_text(response: Response) -> String {
    String::from_utf8(body_bytes(response).await).unwrap()
}

fn request(method: Method, path: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .body(Body::empty())
        .unwrap()
}

fn post(path: &str) -> Request<Body> {
    request(Method::POST, path)
}

fn assert_disable_cache(headers: &HeaderMap) {
    assert_eq!(headers[header::CACHE_CONTROL], CACHE_CONTROL_VALUE);
    assert_eq!(headers[header::PRAGMA], "no-cache");
    assert_eq!(headers[header::EXPIRES], "0");
}

fn assert_no_disable_cache(headers: &HeaderMap) {
    assert!(!headers.contains_key(header::CACHE_CONTROL));
    assert!(!headers.contains_key(header::PRAGMA));
    assert!(!headers.contains_key(header::EXPIRES));
}

#[tokio::test]
async fn all_session_routes_are_registered_in_production_router() {
    let state = AppState::default();
    for (method, path) in [
        (Method::POST, "/api/user/auth/refresh"),
        (Method::POST, "/api/user/auth/logout"),
        (Method::GET, "/api/user/sessions"),
        (Method::DELETE, "/api/user/sessions/example"),
        (Method::POST, "/api/user/sessions/revoke-others"),
    ] {
        let response = send(&state, request(method, path)).await;
        let status = response.status();
        assert_ne!(status, StatusCode::NOT_FOUND, "{path}");
        assert!(
            matches!(status, StatusCode::UNAUTHORIZED | StatusCode::SERVICE_UNAVAILABLE),
            "{path} -> {status}"
        );
    }
}

#[tokio::test]
async fn refresh_and_logout_business_responses_disable_cache() {
    let state = auth_state(false);

    // 缺少刷新 Cookie 的业务拒绝：401。
    let response = send(&state, post("/api/user/auth/refresh")).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_disable_cache(response.headers());

    // 无 Cookie 的登出按 Go 语义成功并清 Cookie。
    let response = send(&state, post("/api/user/auth/logout")).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_disable_cache(response.headers());
}

#[tokio::test]
async fn secure_origin_rejection_disables_cache() {
    // secure 模式下缺少 Origin/Referer 即被来源守卫拒绝。
    let state = auth_state(true);
    for path in ["/api/user/auth/refresh", "/api/user/auth/logout"] {
        let response = send(&state, post(path)).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_disable_cache(response.headers());
        assert!(
            body_text(response).await.contains("AUTH_ORIGIN_FORBIDDEN"),
            "{path}"
        );
    }
}

#[tokio::test]
async fn session_read_endpoints_disable_cache() {
    let state = auth_state(false);
    for (method, path) in [
        (Method::GET, "/api/user/sessions"),
        (Method::DELETE, "/api/user/sessions/example"),
        (Method::POST, "/api/user/sessions/revoke-others"),
    ] {
        let response = send(&state, request(method, path)).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
        assert_disable_cache(response.headers());
    }
}

#[tokio::test]
async fn sessions_without_bearer_is_unauthorized_not_not_found() {
    let state = auth_state(false);
    let response = send(&state, request(Method::GET, "/api/user/sessions")).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_ne!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn second_refresh_and_logout_are_rate_limited_without_cache_headers() {
    for path in ["/api/user/auth/refresh", "/api/user/auth/logout"] {
        // 每个路径独立状态，避免共享同一个 "CT" + IP 窗口。
        let state = transport_state(RateLimitSettings {
            enabled: true,
            requests: 1,
            window_seconds: 60,
        });
        let addr = peer("198.51.100.30");

        let first = send_from(&state, addr, post(path)).await;
        assert_ne!(first.status(), StatusCode::TOO_MANY_REQUESTS, "{path}");
        assert_disable_cache(first.headers());

        let second = send_from(&state, addr, post(path)).await;
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS, "{path}");
        assert_eq!(second.headers()[header::RETRY_AFTER], "60");
        // 限流位于 DisableCache 之前：429 不携带 no-cache 头。
        assert_no_disable_cache(second.headers());
        assert!(body_bytes(second).await.is_empty());
    }
}

#[tokio::test]
async fn default_state_without_limiter_never_misreports_429() {
    let state = AppState::default();
    for _ in 0..3 {
        let response = send(&state, post("/api/user/auth/refresh")).await;
        assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
