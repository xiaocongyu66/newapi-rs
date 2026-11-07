//! HTTP contracts for `POST /api/user/reset` — port of Go `identity.ResetPassword`
//! (`apps/api/internal/identity/verify_email.go:133`).
//!
//! Runs only in remote CI. Every scenario uses an isolated synthetic fixture
//! (in-memory SQLite or an isolated PostgreSQL schema); no service is started.
//! The PostgreSQL test runs whenever `TEST_POSTGRES_DSN` is present.
//!
//! The route is composed here exactly as the composition slice will wire it:
//! `post(reset_password)` behind `from_fn_with_state(reset_guard)`. Go registers
//! it with `CriticalRateLimit("CT")` → `AnonymousRequestBodyLimit` and nothing
//! else (no `UserAuth`, no `DisableCache`, no Turnstile).
//!
//! The reset token is the code Go sends by email: `GenerateVerificationCode(0)`
//! (a full 32-char dashless UUID). The generated replacement password is
//! `GenerateVerificationCode(12)`. The verification cache is the in-process map
//! from `identity::registration`, seeded here through `register_verification_code`.

use std::sync::atomic::{AtomicU64, Ordering};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode, header},
    middleware,
    response::Response,
    routing::post,
};
use newapi_identity::{
    crypto::verify_password, registration::PASSWORD_RESET_PURPOSE,
    registration::register_verification_code,
};
use newapi_security::client_ip::ProxyPolicy;
use newapi_server::{AppState, RateLimiter, limit::RateLimitSettings, reset_http};
use newapi_storage::Database;
use serde_json::{Value, json};
use sqlx::{
    ConnectOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::SqlitePoolOptions,
};
use tower::ServiceExt;

static NEXT: AtomicU64 = AtomicU64::new(0);

/// `password_reset` 的验证码存在**进程内**全局 map 里（`registration.rs`
/// 的 `verification_map`），而同一测试二进制里的 `#[tokio::test]` 是并行跑的。
/// SQLite 与 PostgreSQL 两份 fixture 若都用 `resetme@example.com` 注册同一个
/// token，两条用例会互相 `delete`/重读对方的一次性 code：一条先重置成功
/// 删掉 key，另一条随之把"已删除"误判成自己的成功路径。串行化后每条用例
/// 独享该 map，且与 Go 无关——Go 侧同一进程同样只有一个 map。
static CONTRACT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

const SECRET: &str = "reset-routes-fixture-secret";

/// 32-char dashless-hex token, matching Go `GenerateVerificationCode(0)`.
const TOKEN: &str = "abcdef0123456789abcdef0123456789";

const SQLITE_USERS: &str = r#"CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE, password TEXT NOT NULL,
    display_name TEXT, role INTEGER DEFAULT 1, status INTEGER DEFAULT 1,
    email TEXT, github_id TEXT, discord_id TEXT, oidc_id TEXT,
    wechat_id TEXT, telegram_id TEXT, access_token CHAR(32) UNIQUE,
    quota INTEGER DEFAULT 0, used_quota INTEGER DEFAULT 0,
    request_count INTEGER DEFAULT 0, "group" VARCHAR(64) DEFAULT 'default',
    aff_code VARCHAR(32) UNIQUE, aff_count INTEGER DEFAULT 0,
    aff_quota INTEGER DEFAULT 0, aff_history INTEGER DEFAULT 0,
    inviter_id INTEGER, deleted_at TIMESTAMP, linux_do_id TEXT,
    setting TEXT, remark VARCHAR(255), stripe_customer VARCHAR(64),
    created_at BIGINT, last_login_at BIGINT DEFAULT 0,
    auth_version BIGINT NOT NULL DEFAULT 1
)"#;

const POSTGRES_USERS: &str = r#"CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    username TEXT UNIQUE, password TEXT NOT NULL,
    display_name TEXT, role INTEGER DEFAULT 1, status INTEGER DEFAULT 1,
    email TEXT, github_id TEXT, discord_id TEXT, oidc_id TEXT,
    wechat_id TEXT, telegram_id TEXT, access_token CHAR(32) UNIQUE,
    quota INTEGER DEFAULT 0, used_quota INTEGER DEFAULT 0,
    request_count INTEGER DEFAULT 0, "group" VARCHAR(64) DEFAULT 'default',
    aff_code VARCHAR(32) UNIQUE, aff_count INTEGER DEFAULT 0,
    aff_quota INTEGER DEFAULT 0, aff_history INTEGER DEFAULT 0,
    inviter_id INTEGER, deleted_at TIMESTAMP, linux_do_id TEXT,
    setting TEXT, remark VARCHAR(255), stripe_customer VARCHAR(64),
    created_at BIGINT, last_login_at BIGINT DEFAULT 0,
    auth_version BIGINT NOT NULL DEFAULT 1
)"#;

const OPTIONS: &str = "CREATE TABLE options (\"key\" TEXT PRIMARY KEY, value TEXT)";

macro_rules! exec {
    ($db:expr, $sql:expr $(, $arg:expr)* $(,)?) => {{
        match $db {
            Database::Sqlite(pool) => {
                sqlx::query($sql)
                    $(.bind($arg))*
                    .execute(pool)
                    .await
                    .expect("fixture statement");
            }
            Database::Postgres(pool) => {
                sqlx::query($sql)
                    $(.bind($arg))*
                    .execute(pool)
                    .await
                    .expect("fixture statement");
            }
        }
    }};
}

macro_rules! fetch_one {
    ($db:expr, $sql:expr $(, $arg:expr)* $(,)?) => {{
        match $db {
            Database::Sqlite(pool) => sqlx::query_scalar($sql)
                $(.bind($arg))*
                .fetch_one(pool)
                .await
                .expect("fixture query"),
            Database::Postgres(pool) => sqlx::query_scalar($sql)
                $(.bind($arg))*
                .fetch_one(pool)
                .await
                .expect("fixture query"),
        }
    }};
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/user/reset", post(reset_http::reset_password))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            reset_http::reset_guard,
        ))
        .with_state(state)
}

async fn state(db: &Database) -> AppState {
    AppState::initialize(db)
        .await
        .expect("state snapshot")
        .bind_runtime(db.clone(), SECRET)
}

fn reset_request(body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/user/reset")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT_LANGUAGE, "zh-CN")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

async fn send(state: &AppState, request: Request<Body>) -> Response {
    router(state.clone()).oneshot(request).await.unwrap()
}

async fn send_body(state: &AppState, body: &str) -> Response {
    send(state, reset_request(body)).await
}

async fn body_json(response: Response) -> Value {
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body");
    serde_json::from_slice(&bytes).expect("response JSON")
}

fn assert_no_cache_headers(headers: &HeaderMap) {
    assert!(!headers.contains_key(header::CACHE_CONTROL));
    assert!(!headers.contains_key(header::PRAGMA));
    assert!(!headers.contains_key(header::EXPIRES));
}

fn assert_link_invalid(body: &Value) {
    assert_eq!(body["success"], json!(false));
    assert_eq!(body["message"], json!("重置链接非法或已过期"));
}

async fn run_contract(db: Database) {
    exec!(&db, OPTIONS);
    let app = state(&db).await;

    // ---- binding and empty guards (Go `MsgInvalidParams`) ----
    // Malformed JSON collapses to `common.invalid_params` under the port's
    // sanitizing convention (Go would surface the raw bind error).
    let body = body_json(send_body(&app, "{").await).await;
    assert_eq!(body["success"], json!(false));
    assert_eq!(body["message"], json!("无效的参数"));

    // Missing email and token after normalization.
    let body = body_json(send_body(&app, r#"{"email":"  ","token":""}"#).await).await;
    assert_eq!(body["message"], json!("无效的参数"));

    // Non-JSON content type is skipped → zero values → still `invalid_params`.
    let request = Request::builder()
        .method("POST")
        .uri("/api/user/reset")
        .header(header::CONTENT_TYPE, "text/plain")
        .header(header::ACCEPT_LANGUAGE, "zh-CN")
        .body(Body::from(
            r#"{"email":"anyone@example.com","token":"whatever"}"#,
        ))
        .unwrap();
    let response = send(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_no_cache_headers(response.headers());
    let body = body_json(response).await;
    assert_eq!(body["message"], json!("无效的参数"));

    // Token present but email empty → `invalid_params`.
    let body = body_json(send_body(&app, r#"{"token":"tok"}"#).await).await;
    assert_eq!(body["message"], json!("无效的参数"));

    // ---- verification failure (Go `MsgUserPasswordResetLinkInvalid`) ----
    // No code registered for this email yet.
    let body =
        body_json(send_body(&app, r#"{"email":"wrongcode@example.com","token":"nope"}"#).await)
            .await;
    assert_link_invalid(&body);

    // ---- valid token, but no matching user ----
    register_verification_code(PASSWORD_RESET_PURPOSE, "ghost@example.com", TOKEN);
    let body = body_json(
        send_body(
            &app,
            r#"{"email":"Ghost@Example.com","token":"abcdef0123456789abcdef0123456789"}"#,
        )
        .await,
    )
    .await;
    assert_link_invalid(&body);

    // ---- ambiguous email hides the account identically ----
    exec!(
        &db,
        "INSERT INTO users (username,password,role,status,email) VALUES ($1,$2,1,1,$3)",
        "dup_a",
        "fixture-hash",
        "Dup@Example.com",
    );
    exec!(
        &db,
        "INSERT INTO users (username,password,role,status,email) VALUES ($1,$2,1,1,$3)",
        "dup_b",
        "fixture-hash",
        "dup@example.com",
    );
    register_verification_code(PASSWORD_RESET_PURPOSE, "dup@example.com", TOKEN);
    let body = body_json(
        send_body(
            &app,
            r#"{"email":"dup@example.com","token":"abcdef0123456789abcdef0123456789"}"#,
        )
        .await,
    )
    .await;
    assert_link_invalid(&body);

    // ---- success: fresh 12-char password, bcrypt stored, code consumed ----
    exec!(
        &db,
        "INSERT INTO users (username,password,role,status,email,auth_version) VALUES ($1,$2,1,1,$3,$4)",
        "resetuser",
        "fixture-hash",
        "resetme@example.com",
        1_i64,
    );
    register_verification_code(PASSWORD_RESET_PURPOSE, "resetme@example.com", TOKEN);
    let response = send_body(
        &app,
        r#"{"email":"ResetMe@Example.com","token":"abcdef0123456789abcdef0123456789"}"#,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_no_cache_headers(response.headers());
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true));
    assert_eq!(body["message"], json!(""));
    let generated = body["data"]
        .as_str()
        .expect("plaintext password")
        .to_owned();
    assert_eq!(generated.len(), 12);
    assert!(
        generated
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    );

    // Stored hash now verifies against the returned plaintext; auth_version bumped.
    let stored: String = fetch_one!(
        &db,
        "SELECT password FROM users WHERE username = $1",
        "resetuser",
    );
    assert!(verify_password(generated.as_bytes(), &stored).unwrap());
    let auth_version: i64 = fetch_one!(
        &db,
        "SELECT CAST(auth_version AS BIGINT) FROM users WHERE username = $1",
        "resetuser",
    );
    assert_eq!(auth_version, 2);

    // The code is one-shot: replaying it fails verification now.
    let body = body_json(
        send_body(
            &app,
            r#"{"email":"resetme@example.com","token":"abcdef0123456789abcdef0123456789"}"#,
        )
        .await,
    )
    .await;
    assert_link_invalid(&body);

    // ---- auth_version NULL/0 floor: Go writes 2 when current is < 1 ----
    exec!(
        &db,
        "INSERT INTO users (username,password,role,status,email,auth_version) VALUES ($1,$2,1,1,$3,$4)",
        "resetzero",
        "fixture-hash",
        "zero@example.com",
        0_i64,
    );
    register_verification_code(PASSWORD_RESET_PURPOSE, "zero@example.com", TOKEN);
    let body = body_json(
        send_body(
            &app,
            r#"{"email":"zero@example.com","token":"abcdef0123456789abcdef0123456789"}"#,
        )
        .await,
    )
    .await;
    assert_eq!(body["success"], json!(true));
    let auth_version: i64 = fetch_one!(
        &db,
        "SELECT CAST(auth_version AS BIGINT) FROM users WHERE username = $1",
        "resetzero",
    );
    assert_eq!(auth_version, 2);

    // ---- CriticalRateLimit("CT") ----
    let limited = state(&db).await.bind_transport(
        ProxyPolicy::parse_trusted_proxies(None).unwrap(),
        RateLimiter::memory(RateLimitSettings {
            enabled: true,
            requests: 1,
            window_seconds: 60,
        }),
        512,
    );
    exec!(
        &db,
        "INSERT INTO users (username,password,role,status,email) VALUES ($1,$2,1,1,$3)",
        "ratelimit",
        "fixture-hash",
        "rl@example.com",
    );
    let first = send_body(&limited, r#"{"email":"rl@example.com","token":"bad"}"#).await;
    assert_eq!(first.status(), StatusCode::OK);
    let body = body_json(first).await;
    assert_link_invalid(&body);

    let second = send_body(&limited, r#"{"email":"rl@example.com","token":"bad"}"#).await;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_no_cache_headers(second.headers());
    assert_eq!(second.headers()[header::RETRY_AFTER], "60");
    let bytes = to_bytes(second.into_body(), 1024).await.unwrap();
    assert!(bytes.is_empty());
}

#[tokio::test]
async fn sqlite_reset_routes_contract() {
    let _guard = CONTRACT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    let db = Database::Sqlite(pool);
    exec!(&db, SQLITE_USERS);
    run_contract(db).await;
}

#[tokio::test]
async fn postgres_reset_routes_contract() {
    let _guard = CONTRACT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Ok(dsn) = std::env::var("TEST_POSTGRES_DSN") else {
        return;
    };
    let options: PgConnectOptions = dsn
        .parse()
        .unwrap_or_else(|_| panic!("invalid PostgreSQL fixture config"));
    let options = options.disable_statement_logging();
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone())
        .await
        .expect("connect PostgreSQL fixture");
    let schema = format!(
        "reset_routes_{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    assert!(
        schema
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    );
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA \"{schema}\"")))
        .execute(&admin)
        .await
        .expect("create isolated schema");
    let search_path = schema.clone();
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .after_connect(move |connection, _| {
            let path = search_path.clone();
            Box::pin(async move {
                sqlx::query("SELECT set_config('search_path', $1, false)")
                    .bind(path)
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect_with(options)
        .await
        .expect("connect isolated PostgreSQL pool");
    let db = Database::Postgres(pool);
    exec!(&db, POSTGRES_USERS);
    run_contract(db).await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA \"{schema}\" CASCADE"
    )))
    .execute(&admin)
    .await
    .expect("drop isolated schema");
    admin.close().await;
}
