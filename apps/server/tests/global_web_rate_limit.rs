//! HTTP contracts for the global web rate limit (Go `GlobalWebRateLimit`,
//! mark "GW") wired over the fallback surface: any path outside `/api` and
//! the P1 health endpoints, mirroring Go's NoRoute chain (`register_web.go` +
//! `static.ServeStatic`). Run only in GitHub Actions; every state here is
//! the default in-memory backend.
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

/// GA 用宽松配额，确保观测到的 429 只可能来自 GW（mark "GW"）。
fn web_state(web: RateLimitSettings) -> AppState {
    AppState::default()
        .bind_transport(
            ProxyPolicy::parse_trusted_proxies(None).unwrap(),
            RateLimiter::memory(settings(true, 100, 600)),
            ANONYMOUS_LIMIT_KB,
        )
        .bind_global_api_rate_limit(RateLimiter::memory(settings(true, 100, 600)))
        .bind_global_web_rate_limit(RateLimiter::memory(web))
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
    let state = web_state(settings(true, 1, 120));
    let addr = peer("198.51.100.40");

    let first = send_from(&state, addr, get("/")).await;
    // 兜底链仍正常应答（本端口无静态资源，未匹配路径回 JSON 404）。
    assert_eq!(first.status(), StatusCode::NOT_FOUND);
    assert!(!first.headers().contains_key(header::RETRY_AFTER));

    let second = send_from(&state, addr, get("/")).await;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    // 内存后端报告完整窗口，与 Go 的保守提示一致。
    assert_eq!(second.headers()[header::RETRY_AFTER], "120");
    // 429 位于 Cache 之前：裸状态码，无缓存头、无 JSON 体。
    assert!(!second.headers().contains_key(header::CACHE_CONTROL));
    assert!(!second.headers().contains_key(header::PRAGMA));
    assert!(!second.headers().contains_key(header::EXPIRES));
    assert!(body_bytes(second).await.is_empty());
}

#[tokio::test]
async fn rate_limit_counts_are_isolated_per_client_ip() {
    let state = web_state(settings(true, 1, 120));
    let first_ip = peer("198.51.100.41");
    let second_ip = peer("198.51.100.42");

    let response = send_from(&state, first_ip, get("/")).await;
    assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let response = send_from(&state, first_ip, get("/")).await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    // 另一 IP 的配额不受影响。
    let response = send_from(&state, second_ip, get("/")).await;
    assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn web_surface_applies_to_any_path_and_method() {
    let state = web_state(settings(true, 2, 120));
    let addr = peer("198.51.100.42");

    // Go 的 NoRoute 兜底对任意方法生效（gin HandleMethodNotAllowed=false），
    // `/v1/...`、`/assets/...` 都落到 web 链。
    let response = send_from(&state, addr, get("/v1/models")).await;
    assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let response = send_from(&state, addr, post("/assets/main.js")).await;
    assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    // 配额在 web 表面内跨路径、跨方法共享（同一 ClientIP 的同一 mark）。
    let response = send_from(&state, addr, get("/")).await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn disabled_web_limit_never_rejects() {
    let state = web_state(settings(false, 1, 120));
    let addr = peer("198.51.100.43");
    for _ in 0..5 {
        let response = send_from(&state, addr, get("/")).await;
        assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}

#[tokio::test]
async fn api_and_health_paths_are_not_web_limited() {
    let state = web_state(settings(true, 1, 120));
    let addr = peer("198.51.100.44");
    // `/api`、`/health/*` 由 GA / 业务路由接管，不经 GW。
    for path in ["/api/notice", "/health/live", "/health/ready"] {
        for _ in 0..3 {
            let response = send_from(&state, addr, get(path)).await;
            assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS, "{path}");
        }
    }
}

#[tokio::test]
async fn web_limit_is_independent_of_api_limit() {
    // GA、GW 各配额 1，窗口分别为 600/120：Retry-After 区分 429 的来源。
    let state = AppState::default()
        .bind_transport(
            ProxyPolicy::parse_trusted_proxies(None).unwrap(),
            RateLimiter::memory(settings(true, 100, 600)),
            ANONYMOUS_LIMIT_KB,
        )
        .bind_global_api_rate_limit(RateLimiter::memory(settings(true, 1, 600)))
        .bind_global_web_rate_limit(RateLimiter::memory(settings(true, 1, 120)));
    let addr = peer("198.51.100.45");

    let response = send_from(&state, addr, get("/api/notice")).await;
    assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let response = send_from(&state, addr, get("/api/notice")).await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers()[header::RETRY_AFTER], "600");
    // GW 配额独立：web 表面仍放行，直到自身配额耗尽。
    let response = send_from(&state, addr, get("/")).await;
    assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let response = send_from(&state, addr, get("/")).await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers()[header::RETRY_AFTER], "120");
    // GA 表面在 GW 耗尽后仍按自身配额拒绝（Retry-After 仍是 GA 的 600）。
    let response = send_from(&state, addr, get("/api/notice")).await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers()[header::RETRY_AFTER], "600");
}

#[tokio::test]
async fn default_state_without_web_limiter_never_misreports_429() {
    // 未 bind 限流器时 GW 直通（与 GA 的默认一致）。
    let state = AppState::default();
    let addr = peer("198.51.100.46");
    for _ in 0..5 {
        let response = send_from(&state, addr, get("/")).await;
        assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
