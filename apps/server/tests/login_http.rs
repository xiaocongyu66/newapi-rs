//! HTTP contracts for the login route middleware chain. Run only in GitHub
//! Actions; every database here is an isolated in-memory fixture.
use std::net::SocketAddr;

use axum::{
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{HeaderMap, Method, Request, StatusCode, header},
    response::Response,
};
use newapi_security::client_ip::ProxyPolicy;
use newapi_server::{AppState, limit::RateLimitSettings, router};
use newapi_storage::Database;
use tower::ServiceExt;

const ANONYMOUS_LIMIT_KB: i64 = 512;
const LIMIT: usize = 512 * 1024;
const CACHE_CONTROL_VALUE: &str = "no-store, no-cache, must-revalidate, private, max-age=0";

fn peer(ip: &str) -> SocketAddr {
    format!("{ip}:40000").parse().unwrap()
}

fn transport_state(rate_limit: RateLimitSettings) -> AppState {
    AppState::default().bind_transport(
        ProxyPolicy::parse_trusted_proxies(None).unwrap(),
        rate_limit,
        ANONYMOUS_LIMIT_KB,
    )
}

async fn options_state(rows: &[(&str, &str)]) -> (AppState, Database) {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::query(r#"CREATE TABLE options ("key" TEXT PRIMARY KEY, "value" TEXT)"#)
        .execute(&pool)
        .await
        .unwrap();
    for (key, value) in rows {
        sqlx::query(r#"INSERT INTO options ("key", "value") VALUES (?, ?)"#)
            .bind(*key)
            .bind(*value)
            .execute(&pool)
            .await
            .unwrap();
    }
    let db = Database::Sqlite(pool);
    let state = AppState::initialize(&db).await.unwrap();
    (state, db)
}

async fn send(state: &AppState, peer: SocketAddr, mut request: Request<Body>) -> Response {
    request.extensions_mut().insert(ConnectInfo(peer));
    router(state.clone()).oneshot(request).await.unwrap()
}

async fn body_bytes(response: Response) -> Vec<u8> {
    to_bytes(response.into_body(), 2 * LIMIT)
        .await
        .unwrap()
        .to_vec()
}

async fn body_text(response: Response) -> String {
    String::from_utf8(body_bytes(response).await).unwrap()
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

fn login_request() -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/api/user/login")
        .body(Body::empty())
        .unwrap()
}

fn post_with_language(path: &str, language: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::ACCEPT_LANGUAGE, language)
        .body(Body::empty())
        .unwrap()
}

fn forwarded_login(forwarded_for: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/api/user/login")
        .header("x-forwarded-for", forwarded_for)
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn rate_limit_rejects_second_request_from_the_same_client() {
    let state = transport_state(RateLimitSettings {
        enabled: true,
        requests: 1,
        window_seconds: 60,
    });
    let addr = peer("198.51.100.20");

    let first = send(&state, addr, login_request()).await;
    assert_eq!(first.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_disable_cache(first.headers());

    let second = send(&state, addr, login_request()).await;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(second.headers()[header::RETRY_AFTER], "60");
    assert_no_disable_cache(second.headers());
    assert!(body_bytes(second).await.is_empty());
}

#[tokio::test]
async fn rate_limit_keys_use_trusted_forwarded_addresses() {
    let state = transport_state(RateLimitSettings {
        enabled: true,
        requests: 1,
        window_seconds: 300,
    });
    let proxy = peer("127.0.0.1");

    let response = send(&state, proxy, forwarded_login("203.0.113.10")).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    let response = send(&state, proxy, forwarded_login("203.0.113.10")).await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

    let response = send(&state, proxy, forwarded_login("203.0.113.11")).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn anonymous_body_limit_rejects_oversized_content_length() {
    let state = transport_state(RateLimitSettings {
        enabled: false,
        requests: 0,
        window_seconds: 0,
    });
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/user/login")
        .header(header::CONTENT_LENGTH, (LIMIT + 1).to_string())
        .body(Body::empty())
        .unwrap();

    let response = send(&state, peer("192.0.2.10"), request).await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_disable_cache(response.headers());
    assert!(body_bytes(response).await.is_empty());
}

#[tokio::test]
async fn anonymous_body_limit_accepts_exact_limit_and_unbounded_declarations() {
    let state = transport_state(RateLimitSettings {
        enabled: false,
        requests: 0,
        window_seconds: 0,
    });
    let addr = peer("192.0.2.11");

    let exact = Request::builder()
        .method(Method::POST)
        .uri("/api/user/login")
        .header(header::CONTENT_LENGTH, LIMIT.to_string())
        .body(Body::from(vec![b'x'; LIMIT]))
        .unwrap();
    let response = send(&state, addr, exact).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_disable_cache(response.headers());

    let zero = Request::builder()
        .method(Method::POST)
        .uri("/api/user/login")
        .header(header::CONTENT_LENGTH, "0")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        send(&state, addr, zero).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );

    let missing = Request::builder()
        .method(Method::POST)
        .uri("/api/user/login")
        .body(Body::from("{\"username\":\"fixture\"}"))
        .unwrap();
    assert_eq!(
        send(&state, addr, missing).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn turnstile_enabled_gates_the_login_route_only() {
    let (state, db) = options_state(&[("TurnstileCheckEnabled", "true")]).await;
    let addr = peer("192.0.2.12");

    let response = send(&state, addr, post_with_language("/api/user/login", "zh-CN")).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_disable_cache(response.headers());
    let body = body_text(response).await;
    assert!(body.contains("\"success\":false"));
    assert!(body.contains("\"message\":\"Turnstile token 为空\""));

    let response = send(
        &state,
        addr,
        post_with_language("/api/user/login?turnstile=opaque-token", "zh-CN"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_disable_cache(response.headers());
    let body = body_text(response).await;
    assert!(body.contains("\"success\":false"));
    assert!(body.contains("Turnstile 校验暂不可用"));
    assert!(!body.contains("opaque-token"));

    let response = send(
        &state,
        addr,
        post_with_language("/api/user/login/2fa", "zh-CN"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    db.close().await;
}

#[tokio::test]
async fn turnstile_disabled_passes_missing_token_to_the_handler() {
    let response = send(&AppState::default(), peer("192.0.2.13"), login_request()).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_disable_cache(response.headers());
}

#[tokio::test]
async fn turnstile_rejection_message_follows_accept_language() {
    let (state, db) = options_state(&[("TurnstileCheckEnabled", "true")]).await;
    let addr = peer("192.0.2.14");

    for (language, expected) in [
        ("en", "Turnstile token is empty"),
        ("zh-CN", "Turnstile token 为空"),
    ] {
        let response = send(
            &state,
            addr,
            post_with_language("/api/user/login", language),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_text(response).await;
        assert!(body.contains(expected), "language {language}");
    }

    db.close().await;
}

#[tokio::test]
async fn login_route_shape_and_method_fallbacks_are_explicit() {
    let state = AppState::default();
    let addr = peer("192.0.2.15");

    let get = Request::builder()
        .method(Method::GET)
        .uri("/api/user/login")
        .body(Body::empty())
        .unwrap();
    let response = send(&state, addr, get).await;
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert!(body_text(response).await.contains("method not allowed"));

    let trailing = Request::builder()
        .method(Method::POST)
        .uri("/api/user/login/")
        .body(Body::empty())
        .unwrap();
    let response = send(&state, addr, trailing).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(body_text(response).await.contains("not found"));
}
