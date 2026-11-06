//! Route-level Turnstile gating with an injected siteverify verifier.
//!
//! Run only in GitHub Actions. No test here resolves or contacts
//! `challenges.cloudflare.com`: the fake verifier records what the guard
//! passed and returns a canned outcome.

use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use axum::{
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{Method, Request, StatusCode, header},
    response::Response,
};
use newapi_server::{
    AppState, router,
    turnstile::{InjectedVerifier, Verifier, VerifyError, VerifyFuture},
};
use newapi_storage::Database;
use tower::ServiceExt;

const SECRET: &str = "test-turnstile-secret";
const TOKEN: &str = "opaque-response-token";
const LIMIT: usize = 512 * 1024;

fn peer(ip: &str) -> SocketAddr {
    format!("{ip}:40000").parse().unwrap()
}

async fn options_state(enabled: bool) -> (AppState, Database) {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::query(r#"CREATE TABLE options ("key" TEXT PRIMARY KEY, "value" TEXT)"#)
        .execute(&pool)
        .await
        .unwrap();
    let rows = [
        (
            "TurnstileCheckEnabled",
            if enabled { "true" } else { "false" },
        ),
        ("TurnstileSecretKey", SECRET),
    ];
    for (key, value) in rows {
        sqlx::query(r#"INSERT INTO options ("key", "value") VALUES (?, ?)"#)
            .bind(key)
            .bind(value)
            .execute(&pool)
            .await
            .unwrap();
    }
    let db = Database::Sqlite(pool);
    let state = AppState::initialize(&db).await.unwrap();
    (state, db)
}

/// Verifier that records each call and returns a fixed result.
struct FakeVerifier {
    result: Result<bool, VerifyError>,
    calls: AtomicUsize,
    captured: Mutex<Option<(String, String, Option<String>)>>,
}

impl FakeVerifier {
    fn new(result: Result<bool, VerifyError>) -> Arc<Self> {
        Arc::new(Self {
            result,
            calls: AtomicUsize::new(0),
            captured: Mutex::new(None),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn captured(&self) -> Option<(String, String, Option<String>)> {
        self.captured
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

impl Verifier for FakeVerifier {
    fn verify<'a>(
        &'a self,
        secret: &'a str,
        token: &'a str,
        remote_ip: Option<&'a str>,
    ) -> VerifyFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self
            .captured
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some((
            secret.to_owned(),
            token.to_owned(),
            remote_ip.map(str::to_owned),
        ));
        let result = self.result;
        Box::pin(async move { result })
    }
}

async fn send(
    state: &AppState,
    verifier: Option<Arc<FakeVerifier>>,
    uri: &str,
    language: &str,
) -> Response {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::ACCEPT_LANGUAGE, language)
        .body(Body::empty())
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(peer("192.0.2.40")));
    if let Some(verifier) = verifier {
        let verifier: Arc<dyn Verifier> = verifier;
        request.extensions_mut().insert(InjectedVerifier(verifier));
    }
    router(state.clone()).oneshot(request).await.unwrap()
}

async fn body_text(response: Response) -> String {
    let bytes = to_bytes(response.into_body(), 2 * LIMIT).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn empty_token_rejects_without_calling_the_verifier() {
    let (state, db) = options_state(true).await;
    let fake = FakeVerifier::new(Ok(true));

    let response = send(&state, Some(fake.clone()), "/api/user/login", "zh-CN").await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(body.contains("\"success\":false"));
    assert!(body.contains("Turnstile token 为空"));
    assert_eq!(fake.calls(), 0);

    db.close().await;
}

#[tokio::test]
async fn successful_verification_forwards_the_request() {
    let (state, db) = options_state(true).await;
    let fake = FakeVerifier::new(Ok(true));

    let response = send(
        &state,
        Some(fake.clone()),
        "/api/user/login?turnstile=opaque-response-token",
        "zh-CN",
    )
    .await;
    // This fixture binds no login service, so the handler's own 503 proves the
    // guard forwarded instead of rejecting.
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(fake.calls(), 1);
    assert_eq!(
        fake.captured(),
        Some((SECRET.into(), TOKEN.into(), Some("192.0.2.40".into()))),
    );

    db.close().await;
}

#[tokio::test]
async fn failed_verification_uses_the_fixed_rejection_message() {
    let (state, db) = options_state(true).await;
    let fake = FakeVerifier::new(Ok(false));

    let response = send(
        &state,
        Some(fake.clone()),
        "/api/user/login?turnstile=opaque-response-token",
        "zh-CN",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(body.contains("\"success\":false"));
    assert!(body.contains("Turnstile 校验失败，请刷新重试！"));
    assert!(!body.contains(TOKEN));
    assert!(!body.contains(SECRET));
    assert_eq!(fake.calls(), 1);

    db.close().await;
}

#[tokio::test]
async fn transport_error_is_rejected_like_go() {
    // Go's `http.PostForm` error branch writes 200 `{success:false,...}` then
    // aborts, so a transport failure never fails open.
    let (state, db) = options_state(true).await;
    let fake = FakeVerifier::new(Err(VerifyError::Transport));

    let response = send(
        &state,
        Some(fake.clone()),
        "/api/user/login?turnstile=opaque-response-token",
        "zh-CN",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(body.contains("\"success\":false"));
    assert!(body.contains("Turnstile 校验失败，请稍后重试"));
    assert!(!body.contains(TOKEN));
    assert!(!body.contains(SECRET));
    assert_eq!(fake.calls(), 1);

    db.close().await;
}

#[tokio::test]
async fn disabled_check_never_calls_the_verifier() {
    let (state, db) = options_state(false).await;
    let fake = FakeVerifier::new(Err(VerifyError::Transport));

    for uri in [
        "/api/user/login",
        "/api/user/login?turnstile=opaque-response-token",
    ] {
        let response = send(&state, Some(fake.clone()), uri, "zh-CN").await;
        // The guard passes through to the unbound handler.
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
    assert_eq!(fake.calls(), 0);

    db.close().await;
}
