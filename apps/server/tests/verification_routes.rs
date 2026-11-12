//! HTTP contracts for `GET /api/verification` and `GET /api/reset_password`
//! — ports of Go `identity.SendEmailVerification` /
//! `identity.SendPasswordResetEmail`
//! (`apps/api/internal/identity/verify_email.go`).
//!
//! Runs only in remote CI. Every scenario uses an isolated synthetic fixture
//! (in-memory SQLite or an isolated PostgreSQL schema); no service is
//! started. The PostgreSQL test runs whenever `TEST_POSTGRES_DSN` is present.
//!
//! Route composition mirrors `register_api.go:99-100`:
//! - `/api/verification`：`EmailVerificationRateLimit("EV")` →
//!   `TurnstileCheck()` → handler；
//! - `/api/reset_password`：`CriticalRateLimit("CT")` → `TurnstileCheck()`
//!   → handler.
//!
//! SMTP 传输未移植（P7 integrations.mail）：`EmailSender` 端口的默认实现
//! 恒返回 Go 逐字错误 `"SMTP 服务器未配置"`。Go 先生成并存储验证码再
//! 发送，发送失败不删除、限流配额照常消耗——这些副作用由下列用例钉住。

use std::sync::atomic::{AtomicU64, Ordering};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode, header},
    middleware,
    response::Response,
    routing::get,
};
use newapi_security::client_ip::ProxyPolicy;
use newapi_server::{
    AppState, RateLimiter, limit::RateLimitSettings, limit_email, verification_http,
};
use newapi_storage::Database;
use serde_json::{Value, json};
use sqlx::{
    ConnectOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::SqlitePoolOptions,
};
use tower::ServiceExt;

static NEXT: AtomicU64 = AtomicU64::new(0);

const SECRET: &str = "verification-routes-fixture-secret";

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

const UPSERT_OPTION: &str = "INSERT INTO options (\"key\", value) VALUES ($1, $2) \
    ON CONFLICT (\"key\") DO UPDATE SET value = excluded.value";

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

fn router(state: AppState) -> Router {
    Router::new()
        .merge(
            Router::new()
                .route(
                    "/api/verification",
                    get(verification_http::send_email_verification),
                )
                .route_layer(middleware::from_fn_with_state(
                    state.clone(),
                    verification_http::verification_guard,
                )),
        )
        .merge(
            Router::new()
                .route(
                    "/api/reset_password",
                    get(verification_http::send_password_reset_email),
                )
                .route_layer(middleware::from_fn_with_state(
                    state.clone(),
                    verification_http::reset_password_guard,
                )),
        )
        .with_state(state)
}

async fn state(db: &Database) -> AppState {
    AppState::initialize(db)
        .await
        .expect("state snapshot")
        .bind_runtime(db.clone(), SECRET)
}

async fn set_option(db: &Database, key: &str, value: &str) {
    exec!(db, UPSERT_OPTION, key, value);
}

fn verification_request(query: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(format!("/api/verification?{query}"))
        .header(header::ACCEPT_LANGUAGE, "zh-CN")
        .body(Body::empty())
        .unwrap()
}

fn reset_request(query: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(format!("/api/reset_password?{query}"))
        .header(header::ACCEPT_LANGUAGE, "zh-CN")
        .body(Body::empty())
        .unwrap()
}

async fn send(state: &AppState, request: Request<Body>) -> Response {
    router(state.clone()).oneshot(request).await.unwrap()
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

/// `GET /api/verification` 契约（Go `SendEmailVerification`）。
async fn run_verification_contract(db: Database) {
    // 调用方已创建 users/options 表。
    let app = state(&db).await;

    // ---- 校验：required/email（Go `MsgInvalidParams`）----
    let body = body_json(send(&app, verification_request("email=")).await).await;
    assert_eq!(body["success"], json!(false));
    assert_eq!(body["message"], json!("无效的参数"));

    let body = body_json(send(&app, verification_request("email=notanemail")).await).await;
    assert_eq!(body["message"], json!("无效的参数"));
    // Go validator 要求域至少一段点：`a@b` 同样是 invalid_params。
    let body = body_json(send(&app, verification_request("email=a@b")).await).await;
    assert_eq!(body["message"], json!("无效的参数"));

    // ---- `@` 拆分校验（Go 固定文案，不经 i18n）----
    // 本端口的 validator 近似先拦截，此分支保持结构等价。

    // ---- 邮箱未被占用：Go 先生成并存储验证码，再发送；SMTP 未配置 →
    // 逐字 `"SMTP 服务器未配置"`（email.go:168）。----
    let response = send(&app, verification_request("email=fresh@example.com")).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_no_cache_headers(response.headers());
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false));
    assert_eq!(body["message"], json!("SMTP 服务器未配置"));

    // ---- 邮箱已占用（Go `MsgUserEmailAlreadyTaken`）----
    exec!(
        &db,
        "INSERT INTO users (username,password,role,status,email) VALUES ($1,$2,1,1,$3)",
        "existing",
        "fixture-hash",
        "taken@example.com",
    );
    let body = body_json(send(&app, verification_request("email=Taken@Example.com")).await).await;
    assert_eq!(body["success"], json!(false));
    assert_eq!(body["message"], json!("邮箱地址已被占用"));

    // ---- 域名白名单（Go 固定英文文案）----
    set_option(&db, "EmailDomainRestrictionEnabled", "true").await;
    set_option(&db, "EmailDomainWhitelist", "allowed.com").await;
    let app = state(&db).await;
    let body = body_json(send(&app, verification_request("email=other@example.com")).await).await;
    assert_eq!(body["success"], json!(false));
    assert_eq!(
        body["message"],
        json!(
            "The administrator has enabled the email domain name whitelist, and your email address is not allowed due to special symbols or it's not in the whitelist."
        )
    );
    // 命中白名单则放行到发送步骤（SMTP 未配置错误）。
    let body = body_json(send(&app, verification_request("email=mine@allowed.com")).await).await;
    assert_eq!(body["message"], json!("SMTP 服务器未配置"));
    set_option(&db, "EmailDomainRestrictionEnabled", "false").await;

    // ---- 别名限制（Go 固定中文文案）----
    set_option(&db, "EmailAliasRestrictionEnabled", "true").await;
    let app = state(&db).await;
    // 查询串里的 `+` 会按 form 编码解码成空格（Go 的 fasthttp 同样），
    // 命中别名限制的 `+` 必须百分号编码。
    let body =
        body_json(send(&app, verification_request("email=alias%2Btag@example.com")).await).await;
    assert_eq!(body["success"], json!(false));
    assert_eq!(
        body["message"],
        json!("管理员已启用邮箱地址别名限制，您的邮箱地址由于包含特殊符号而被拒绝。")
    );
    set_option(&db, "EmailAliasRestrictionEnabled", "false").await;

    // ---- Turnstile（Go `TurnstileCheck`）----
    set_option(&db, "TurnstileCheckEnabled", "true").await;
    let app = state(&db).await;
    let response = send(&app, verification_request("email=turn@example.com")).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_no_cache_headers(response.headers());
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false));
    assert_eq!(body["message"], json!("Turnstile token 为空"));
    set_option(&db, "TurnstileCheckEnabled", "false").await;

    // ---- EmailVerificationRateLimit("EV")：2 次/30 秒 ----
    let app = state(&db)
        .await
        .bind_email_verification_rate_limit(limit_email::EmailVerificationLimiter::memory_only());
    let first = send(&app, verification_request("email=ev1@example.com")).await;
    assert_eq!(first.status(), StatusCode::OK);
    let second = send(&app, verification_request("email=ev2@example.com")).await;
    assert_eq!(second.status(), StatusCode::OK);
    let third = send(&app, verification_request("email=ev3@example.com")).await;
    assert_eq!(third.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_no_cache_headers(third.headers());
    // Go 的 EV 拒绝是 429 + JSON 信封（内存路径固定文案），无 Retry-After。
    assert!(!third.headers().contains_key(header::RETRY_AFTER));
    let body = body_json(third).await;
    assert_eq!(body["success"], json!(false));
    assert_eq!(body["message"], json!("发送过于频繁，请稍后再试"));
}

/// `GET /api/reset_password` 契约（Go `SendPasswordResetEmail`）。
/// 复用同一 fixture（`users`/`options` 表由调用方创建）。
async fn run_reset_email_contract(db: Database) {
    let app = state(&db).await;

    // ---- 校验：required/email ----
    let body = body_json(send(&app, reset_request("email=")).await).await;
    assert_eq!(body["success"], json!(false));
    assert_eq!(body["message"], json!("无效的参数"));
    let body = body_json(send(&app, reset_request("email=notanemail")).await).await;
    assert_eq!(body["message"], json!("无效的参数"));

    // ---- 未知邮箱：同样成功，不泄露账号是否存在 ----
    let response = send(&app, reset_request("email=ghost@example.com")).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_no_cache_headers(response.headers());
    let body = body_json(response).await;
    assert_eq!(body, json!({"success": true, "message": ""}));

    // ---- 唯一邮箱：生成验证码并尝试发送；SMTP 未配置只记日志，响应仍成功 ----
    exec!(
        &db,
        "INSERT INTO users (username,password,role,status,email) VALUES ($1,$2,1,1,$3)",
        "resetter",
        "fixture-hash",
        "reset@example.com",
    );
    let response = send(&app, reset_request("email=Reset@Example.com")).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body, json!({"success": true, "message": ""}));

    // ---- 歧义邮箱：同样成功（Go 不发送也不报错）----
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
    let body = body_json(send(&app, reset_request("email=dup@example.com")).await).await;
    assert_eq!(body, json!({"success": true, "message": ""}));

    // ---- Turnstile ----
    set_option(&db, "TurnstileCheckEnabled", "true").await;
    let app = state(&db).await;
    let response = send(&app, reset_request("email=ts@example.com")).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false));
    assert_eq!(body["message"], json!("Turnstile token 为空"));
    set_option(&db, "TurnstileCheckEnabled", "false").await;

    // ---- CriticalRateLimit("CT")：裸 429 + Retry-After，无 JSON 体 ----
    let limited = state(&db).await.bind_transport(
        ProxyPolicy::parse_trusted_proxies(None).unwrap(),
        RateLimiter::memory(RateLimitSettings {
            enabled: true,
            requests: 1,
            window_seconds: 60,
        }),
        512,
    );
    let first = send(&limited, reset_request("email=rl@example.com")).await;
    assert_eq!(first.status(), StatusCode::OK);
    let second = send(&limited, reset_request("email=rl@example.com")).await;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_no_cache_headers(second.headers());
    assert_eq!(second.headers()[header::RETRY_AFTER], "60");
    let bytes = to_bytes(second.into_body(), 1024).await.unwrap();
    assert!(bytes.is_empty());
}

#[tokio::test]
async fn sqlite_verification_routes_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    let db = Database::Sqlite(pool);
    exec!(&db, SQLITE_USERS);
    exec!(&db, OPTIONS);
    run_verification_contract(db.clone()).await;
    run_reset_email_contract(db).await;
}

#[tokio::test]
async fn postgres_verification_routes_contract() {
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
        "verification_routes_{}_{}",
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
    exec!(&db, OPTIONS);
    run_verification_contract(db.clone()).await;
    run_reset_email_contract(db).await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA \"{schema}\" CASCADE"
    )))
    .execute(&admin)
    .await
    .expect("drop isolated schema");
    admin.close().await;
}

// ---- feat/log-write-email：发送端口接线契约 ----
//
// `bind_email_sender` 注入的替身被 verification/reset 两个 handler 真实调用：
// - 验证码场景：发送成功 → 200 `{"success":true}`，替身收到 Go 模板的主题
//   与正文（SystemName + 验证码占位）；
// - 重置场景：发送成功 → 响应保持恒成功的 Go 形态。

use std::sync::{Arc, Mutex as StdMutex};

#[derive(Default)]
struct CapturingSender {
    messages: StdMutex<Vec<(String, String, String)>>,
}

impl newapi_identity::email::EmailSender for CapturingSender {
    fn send<'a>(
        &'a self,
        message: &'a newapi_identity::email::OutgoingMessage<'a>,
    ) -> newapi_identity::email::SendFuture<'a> {
        Box::pin(async move {
            self.messages.lock().unwrap().push((
                message.subject.to_owned(),
                message.receiver.to_owned(),
                message.content.to_owned(),
            ));
            Ok(())
        })
    }
}

#[tokio::test]
async fn bound_sender_receives_the_verification_email() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    let db = Database::Sqlite(pool);
    exec!(&db, SQLITE_USERS);
    exec!(&db, OPTIONS);
    let sender = Arc::new(CapturingSender::default());
    let app = state(&db)
        .await
        .bind_email_sender(sender.clone() as Arc<dyn newapi_identity::email::EmailSender>);
    let response = send(&app, verification_request("email=wired@example.com")).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body, json!({"success": true, "message": ""}));
    let messages = sender.messages.lock().unwrap();
    assert_eq!(messages.len(), 1);
    let (subject, receiver, content) = &messages[0];
    assert_eq!(subject, "New API邮箱验证邮件");
    assert_eq!(receiver, "wired@example.com");
    assert!(content.contains("邮箱验证"));
    assert!(content.contains("分钟内有效"));
}

#[tokio::test]
async fn bound_sender_receives_the_password_reset_email() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    let db = Database::Sqlite(pool);
    exec!(&db, SQLITE_USERS);
    exec!(&db, OPTIONS);
    exec!(
        &db,
        "INSERT INTO users (username,password,role,status,email) VALUES ($1,$2,1,1,$3)",
        "wired",
        "fixture-hash",
        "wired@example.com",
    );
    let sender = Arc::new(CapturingSender::default());
    let app = state(&db)
        .await
        .bind_email_sender(sender.clone() as Arc<dyn newapi_identity::email::EmailSender>);
    let response = send(&app, reset_request("email=wired@example.com")).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body, json!({"success": true, "message": ""}));
    let messages = sender.messages.lock().unwrap();
    assert_eq!(messages.len(), 1);
    let (subject, receiver, content) = &messages[0];
    assert_eq!(subject, "New API密码重置");
    assert_eq!(receiver, "wired@example.com");
    assert!(content.contains("/user/reset?email=wired@example.com&token="));
}
