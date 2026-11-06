//! HTTP contracts for the global API rate limit (Go `GlobalAPIRateLimit`,
//! mark "GA") wired in front of every `/api` route. Run only in GitHub
//! Actions; every state here is the default in-memory backend.
use std::net::SocketAddr;

use axum::{
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{Method, Request, StatusCode, header},
    response::Response,
};
use newapi_security::client_ip::ProxyPolicy;
use newapi_server::{AppState, RateLimiter, limit::RateLimitSettings, router};
use tower::ServiceExt;

const ANONYMOUS_LIMIT_KB: i64 = 512;

fn peer(ip: &str) -> SocketAddr {
    format!("{ip}:40000").parse().unwrap()
}

fn settings(enabled: bool, requests: i64, window_seconds: i64) -> RateLimitSettings {
    RateLimitSettings {
        enabled,
        requests,
        window_seconds,
    }
}

fn transport_state(global: RateLimitSettings, critical: RateLimitSettings) -> AppState {
    AppState::default()
        .bind_transport(
            ProxyPolicy::parse_trusted_proxies(None).unwrap(),
            RateLimiter::memory(critical),
            ANONYMOUS_LIMIT_KB,
        )
        .bind_global_api_rate_limit(RateLimiter::memory(global))
}

async fn send_from(state: &AppState, addr: SocketAddr, mut request: Request<Body>) -> Response {
    request.extensions_mut().insert(ConnectInfo(addr));
    router(state.clone()).oneshot(request).await.unwrap()
}

async fn body_bytes(response: Response) -> Vec<u8> {
    to_bytes(response.into_body(), 1024).await.unwrap().to_vec()
}

fn get(path: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(path)
        .body(Body::empty())
        .unwrap()
}

fn post(path: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(path)
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn second_request_from_same_ip_is_rate_limited_with_retry_after() {
    let state = transport_state(settings(true, 1, 120), settings(true, 10, 600));
    let addr = peer("198.51.100.40");

    let first = send_from(&state, addr, get("/api/notice")).await;
    assert_ne!(first.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(!first.headers().contains_key(header::RETRY_AFTER));

    let second = send_from(&state, addr, get("/api/notice")).await;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    // 内存后端报告完整窗口，与 Go 的保守提示一致。
    assert_eq!(second.headers()[header::RETRY_AFTER], "120");
    // 429 位于 DisableCache 之前：裸状态码，无缓存头、无 JSON 体。
    assert!(!second.headers().contains_key(header::CACHE_CONTROL));
    assert!(!second.headers().contains_key(header::PRAGMA));
    assert!(!second.headers().contains_key(header::EXPIRES));
    assert!(body_bytes(second).await.is_empty());
}

#[tokio::test]
async fn rate_limit_counts_are_isolated_per_client_ip() {
    let state = transport_state(settings(true, 1, 120), settings(true, 10, 600));
    let first_ip = peer("198.51.100.41");
    let second_ip = peer("198.51.100.42");

    let response = send_from(&state, first_ip, get("/api/notice")).await;
    assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let response = send_from(&state, first_ip, get("/api/notice")).await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    // 另一 IP 的配额不受影响。
    let response = send_from(&state, second_ip, get("/api/notice")).await;
    assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn disabled_global_limit_never_rejects() {
    let state = transport_state(settings(false, 1, 120), settings(true, 10, 600));
    let addr = peer("198.51.100.43");
    for _ in 0..5 {
        let response = send_from(&state, addr, get("/api/notice")).await;
        assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}

#[tokio::test]
async fn global_limit_precedes_critical_limit() {
    // GA requests=1 window=120，CT requests=1 window=600：第二次登录请求若被
    // GA 先拒绝，Retry-After 是 GA 的 120；若 CT 先跑（其配额同样耗尽），
    // Retry-After 会是 CT 的 600。断言 120 固化 Go 中
    // apiRouter.Use(GlobalAPIRateLimit) 先于路由级 CriticalRateLimit 的顺序。
    let state = transport_state(settings(true, 1, 120), settings(true, 1, 600));
    let addr = peer("198.51.100.44");

    let first = send_from(&state, addr, post("/api/user/login")).await;
    assert_ne!(first.status(), StatusCode::TOO_MANY_REQUESTS);

    let second = send_from(&state, addr, post("/api/user/login")).await;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(second.headers()[header::RETRY_AFTER], "120");
    // GA 的 429 在 DisableCache 之前产生：登录路由的 no-cache 头不出现。
    assert!(!second.headers().contains_key(header::CACHE_CONTROL));
    assert!(!second.headers().contains_key(header::PRAGMA));
    assert!(!second.headers().contains_key(header::EXPIRES));
    assert!(body_bytes(second).await.is_empty());
}

#[tokio::test]
async fn non_api_paths_are_not_globally_limited() {
    let state = transport_state(settings(true, 1, 120), settings(true, 10, 600));
    let addr = peer("198.51.100.45");
    // /api 路径先耗尽配额……
    let response = send_from(&state, addr, get("/api/notice")).await;
    assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let response = send_from(&state, addr, get("/api/notice")).await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    // ……/health 不在 Go 的 apiRouter 组内，不受 GA 约束。
    for _ in 0..3 {
        let response = send_from(&state, addr, get("/health/live")).await;
        assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}

#[tokio::test]
async fn default_state_without_global_limiter_never_misreports_429() {
    // 未 bind 限流器时 GA 直通（与 CT 的默认一致），既有默认 state 测试
    // 的语义在此对 GA 同样成立。
    let state = AppState::default();
    let addr = peer("198.51.100.46");
    for _ in 0..5 {
        let response = send_from(&state, addr, get("/api/notice")).await;
        assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
