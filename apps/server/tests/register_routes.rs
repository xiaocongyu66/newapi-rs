//! HTTP contracts for `POST /api/user/register`.
//!
//! Runs only in remote CI. Every scenario uses an isolated synthetic fixture
//! (in-memory SQLite or an isolated PostgreSQL schema); no service is started.
//! The PostgreSQL test runs whenever `TEST_POSTGRES_DSN` is present.
//!
//! The route is composed here exactly as the composition slice will wire it:
//! `post(register)` behind `from_fn_with_state(register_guard)`.

use std::sync::atomic::{AtomicU64, Ordering};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode, header},
    middleware,
    response::Response,
    routing::post,
};
use newapi_identity::{crypto::verify_password, registration::register_email_verification_code};
use newapi_security::client_ip::ProxyPolicy;
use newapi_server::{AppState, RateLimiter, limit::RateLimitSettings, register_http};
use newapi_storage::Database;
use serde_json::{Value, json};
use sqlx::{
    ConnectOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::SqlitePoolOptions,
};
use tower::ServiceExt;

static NEXT: AtomicU64 = AtomicU64::new(0);

const SECRET: &str = "register-routes-fixture-secret";

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

const LOGS: &str = r#"CREATE TABLE logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
    created_at BIGINT NOT NULL, type INTEGER, content TEXT, username TEXT,
    token_name TEXT, model_name TEXT, quota INTEGER,
    prompt_tokens INTEGER, completion_tokens INTEGER, use_time INTEGER,
    is_stream INTEGER, ip TEXT, request_id VARCHAR(64), other TEXT
)"#;

const LOGS_POSTGRES: &str = r#"CREATE TABLE logs (
    id BIGSERIAL PRIMARY KEY, user_id BIGINT,
    created_at BIGINT NOT NULL, type BIGINT, content TEXT, username TEXT,
    token_name TEXT, model_name TEXT, quota BIGINT,
    prompt_tokens BIGINT, completion_tokens BIGINT, use_time BIGINT,
    is_stream BOOLEAN, ip TEXT, request_id VARCHAR(64), other TEXT
)"#;

const TOKENS: &str = r#"CREATE TABLE tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id BIGINT NOT NULL,
    "key" TEXT NOT NULL UNIQUE,
    status INTEGER NOT NULL DEFAULT 1,
    name TEXT NOT NULL DEFAULT '',
    created_time BIGINT NOT NULL DEFAULT 0,
    accessed_time BIGINT NOT NULL DEFAULT 0,
    expired_time BIGINT NOT NULL DEFAULT -1,
    remain_quota BIGINT NOT NULL DEFAULT 0,
    used_quota BIGINT NOT NULL DEFAULT 0,
    unlimited_quota INTEGER NOT NULL DEFAULT 0,
    model_limits_enabled INTEGER NOT NULL DEFAULT 0,
    model_limits TEXT NOT NULL DEFAULT '',
    allow_ips TEXT,
    "group" TEXT NOT NULL DEFAULT '',
    cross_group_retry INTEGER NOT NULL DEFAULT 0,
    auto_groups TEXT NOT NULL DEFAULT '',
    deleted_at TIMESTAMP
)"#;

const TOKENS_POSTGRES: &str = r#"CREATE TABLE tokens (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    "key" VARCHAR(128) NOT NULL UNIQUE,
    status INTEGER NOT NULL DEFAULT 1,
    name TEXT NOT NULL DEFAULT '',
    created_time BIGINT NOT NULL DEFAULT 0,
    accessed_time BIGINT NOT NULL DEFAULT 0,
    expired_time BIGINT NOT NULL DEFAULT -1,
    remain_quota BIGINT NOT NULL DEFAULT 0,
    used_quota BIGINT NOT NULL DEFAULT 0,
    unlimited_quota BOOLEAN NOT NULL DEFAULT false,
    model_limits_enabled BOOLEAN NOT NULL DEFAULT false,
    model_limits TEXT NOT NULL DEFAULT '',
    allow_ips TEXT,
    "group" TEXT NOT NULL DEFAULT '',
    cross_group_retry BOOLEAN NOT NULL DEFAULT false,
    auto_groups TEXT NOT NULL DEFAULT '',
    deleted_at TIMESTAMP
)"#;

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
        .route("/api/user/register", post(register_http::register))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            register_http::register_guard,
        ))
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

fn register_request(body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/user/register")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT_LANGUAGE, "zh-CN")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

fn register_request_with_query(query: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/api/user/register?{query}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT_LANGUAGE, "zh-CN")
        .body(Body::from(
            r#"{"username":"turnstile","password":"secret123"}"#.to_owned(),
        ))
        .unwrap()
}

/// Deterministic siteverify stub: no network is touched in CI.
struct FixedVerifier(bool);

impl newapi_server::turnstile::Verifier for FixedVerifier {
    fn verify<'a>(
        &'a self,
        _secret: &'a str,
        _token: &'a str,
        _remote_ip: Option<&'a str>,
    ) -> newapi_server::turnstile::VerifyFuture<'a> {
        Box::pin(async move { Ok(self.0) })
    }
}

fn register_request_with_verdict(query: &str, verdict: bool) -> Request<Body> {
    let mut request = register_request_with_query(query);
    request
        .extensions_mut()
        .insert(newapi_server::turnstile::InjectedVerifier(
            std::sync::Arc::new(FixedVerifier(verdict)),
        ));
    request
}

async fn send(state: &AppState, request: Request<Body>) -> Response {
    router(state.clone()).oneshot(request).await.unwrap()
}

async fn send_body(state: &AppState, body: &str) -> Response {
    send(state, register_request(body)).await
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

fn field_error(field: &str, tag: &str) -> String {
    format!("Key: 'User.{field}' Error:Field validation for '{field}' failed on the '{tag}' tag")
}

async fn run_contract(db: Database) {
    // 调用方已创建 users/options/logs/tokens 表。

    // ---- switch gates ----
    set_option(&db, "RegisterEnabled", "false").await;
    let app = state(&db).await;
    let response = send_body(&app, r#"{"username":"user","password":"secret123"}"#).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_no_cache_headers(response.headers());
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false));
    assert_eq!(body["message"], json!("管理员关闭了新用户注册"));

    set_option(&db, "RegisterEnabled", "true").await;
    set_option(&db, "PasswordRegisterEnabled", "false").await;
    let app = state(&db).await;
    let body =
        body_json(send_body(&app, r#"{"username":"user","password":"secret123"}"#).await).await;
    assert_eq!(
        body["message"],
        json!("管理员关闭了通过密码进行注册，请使用第三方账户验证的形式进行注册"),
    );
    assert_eq!(fetch_count(&db, "user").await, 0);

    set_option(&db, "PasswordRegisterEnabled", "true").await;
    let app = state(&db).await;

    // ---- binding and validation ----
    let body = body_json(send_body(&app, "{").await).await;
    assert_eq!(body["success"], json!(false));
    assert_eq!(body["message"], json!("无效的参数"));

    let body =
        body_json(send_body(&app, r#"{"username":"   ","password":"secret123"}"#).await).await;
    assert_eq!(body["message"], json!("无效的参数"));

    let long_username = "u".repeat(21);
    let request = format!(r#"{{"username":"{long_username}","password":"secret123"}}"#);
    let body = body_json(send_body(&app, &request).await).await;
    assert_eq!(
        body["message"],
        json!(format!("输入不合法 {}", field_error("Username", "max"))),
    );

    let body =
        body_json(send_body(&app, r#"{"username":"shortpw","password":"1234567"}"#).await).await;
    assert_eq!(
        body["message"],
        json!(format!("输入不合法 {}", field_error("Password", "min"))),
    );

    let long_password = "x".repeat(21);
    let request = format!(r#"{{"username":"longpw","password":"{long_password}"}}"#);
    let body = body_json(send_body(&app, &request).await).await;
    assert_eq!(
        body["message"],
        json!(format!("输入不合法 {}", field_error("Password", "max"))),
    );

    // ---- success and Go default fields ----
    // Email verification is off, so the supplied email is ignored.
    let response = send_body(
        &app,
        r#"{"username":"newuser","password":"secret123","email":"ignored@example.com"}"#,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_no_cache_headers(response.headers());
    let body = body_json(response).await;
    assert_eq!(body, json!({"success": true, "message": ""}));

    let newuser_id: i64 = fetch_one!(
        &db,
        "SELECT CAST(id AS BIGINT) FROM users WHERE username = $1",
        "newuser",
    );
    let role: i64 = fetch_one!(
        &db,
        "SELECT CAST(role AS BIGINT) FROM users WHERE username = $1",
        "newuser",
    );
    let status: i64 = fetch_one!(
        &db,
        "SELECT CAST(status AS BIGINT) FROM users WHERE username = $1",
        "newuser",
    );
    let quota: i64 = fetch_one!(
        &db,
        "SELECT CAST(quota AS BIGINT) FROM users WHERE username = $1",
        "newuser",
    );
    let inviter_id: i64 = fetch_one!(
        &db,
        "SELECT CAST(inviter_id AS BIGINT) FROM users WHERE username = $1",
        "newuser",
    );
    let auth_version: i64 = fetch_one!(
        &db,
        "SELECT CAST(auth_version AS BIGINT) FROM users WHERE username = $1",
        "newuser",
    );
    let display_name: String = fetch_one!(
        &db,
        "SELECT display_name FROM users WHERE username = $1",
        "newuser",
    );
    let group: String = fetch_one!(
        &db,
        "SELECT \"group\" FROM users WHERE username = $1",
        "newuser",
    );
    let email: String = fetch_one!(
        &db,
        "SELECT email FROM users WHERE username = $1",
        "newuser",
    );
    let setting: String = fetch_one!(
        &db,
        "SELECT setting FROM users WHERE username = $1",
        "newuser",
    );
    let aff_code: String = fetch_one!(
        &db,
        "SELECT aff_code FROM users WHERE username = $1",
        "newuser",
    );
    let password: String = fetch_one!(
        &db,
        "SELECT password FROM users WHERE username = $1",
        "newuser",
    );
    let deleted: i64 = fetch_one!(
        &db,
        "SELECT count(*) FROM users WHERE username = $1 AND deleted_at IS NULL",
        "newuser",
    );
    assert_eq!(role, 1);
    assert_eq!(status, 1);
    assert_eq!(quota, 0);
    assert_eq!(inviter_id, 0);
    assert_eq!(auth_version, 1);
    assert_eq!(display_name, "newuser");
    assert_eq!(group, "default");
    assert_eq!(email, "");
    // finishInsert 已把按角色生成的侧栏配置并入 setting；
    // sidebar_modules 是 dto.UserSetting 的字符串字段，存的是被串化
    // （带转义）的 JSON 串。
    assert_eq!(
        setting,
        format!(
            r#"{{"gotify_priority":0,"sidebar_modules":{}}}"#,
            serde_json::to_string(
                &newapi_identity::registration::default_sidebar_config_for_role(1)
            )
            .expect("sidebar config serializes")
        )
    );
    assert_eq!(aff_code.len(), 4);
    assert!(aff_code.bytes().all(|byte| byte.is_ascii_alphanumeric()));
    assert!(verify_password(b"secret123", &password).unwrap());
    assert_eq!(deleted, 1);

    // ---- finishInsert：默认额度（全 0）不写系统日志、不改 quota ----
    let log_count: i64 = fetch_one!(
        &db,
        "SELECT count(*) FROM logs WHERE user_id = $1",
        newuser_id,
    );
    assert_eq!(log_count, 0);
    // Go 的 GenerateDefaultToken 默认关闭：不产生初始令牌。
    let token_count: i64 = fetch_one!(
        &db,
        "SELECT count(*) FROM tokens WHERE user_id = $1",
        newuser_id,
    );
    assert_eq!(token_count, 0);

    // ---- duplicate and soft-deleted usernames ----
    let body =
        body_json(send_body(&app, r#"{"username":"newuser","password":"secret123"}"#).await).await;
    assert_eq!(body["message"], json!("用户名已存在，或已注销"));

    exec!(
        &db,
        "INSERT INTO users (username,password,role,status,deleted_at) VALUES ($1,$2,1,1,CAST('2026-01-01 00:00:00' AS TIMESTAMP))",
        "ghost",
        "fixture-hash",
    );
    let body =
        body_json(send_body(&app, r#"{"username":"ghost","password":"secret123"}"#).await).await;
    assert_eq!(body["message"], json!("用户名已存在，或已注销"));

    // ---- email verification enabled ----
    set_option(&db, "EmailVerificationEnabled", "true").await;
    let app = state(&db).await;

    let body = body_json(
        send_body(
            &app,
            r#"{"username":"emailuser","password":"secret123","email":"nobody@example.com"}"#,
        )
        .await,
    )
    .await;
    assert_eq!(
        body["message"],
        json!("管理员开启了邮箱验证，请输入邮箱地址和验证码")
    );

    exec!(
        &db,
        "INSERT INTO users (username,password,role,status,email) VALUES ($1,$2,1,1,$3)",
        "existing_mail",
        "fixture-hash",
        "taken@example.com",
    );
    register_email_verification_code("taken@example.com", "654321");
    let body = body_json(
        send_body(
            &app,
            r#"{"username":"dupmail","password":"secret123","email":"Taken@Example.com","verification_code":"654321"}"#,
        )
        .await,
    )
    .await;
    assert_eq!(body["message"], json!("邮箱地址已被占用"));

    let body = body_json(
        send_body(
            &app,
            r#"{"username":"badcode","password":"secret123","email":"fresh2@example.com","verification_code":"wrong"}"#,
        )
        .await,
    )
    .await;
    assert_eq!(body["message"], json!("验证码错误或已过期"));

    register_email_verification_code("fresh@example.com", "111111");
    let body = body_json(
        send_body(
            &app,
            r#"{"username":"emailok","password":"secret123","email":"Fresh@Example.com","verification_code":"111111"}"#,
        )
        .await,
    )
    .await;
    assert_eq!(body, json!({"success": true, "message": ""}));
    let stored_email: String = fetch_one!(
        &db,
        "SELECT email FROM users WHERE username = $1",
        "emailok",
    );
    assert_eq!(stored_email, "fresh@example.com");

    set_option(&db, "EmailVerificationEnabled", "false").await;

    // ---- invitation code ----
    exec!(
        &db,
        "INSERT INTO users (username,password,role,status,aff_code) VALUES ($1,$2,1,1,$3)",
        "inviter",
        "fixture-hash",
        "ABCD",
    );
    let inviter_row: i64 = fetch_one!(
        &db,
        "SELECT CAST(id AS BIGINT) FROM users WHERE username = $1",
        "inviter",
    );
    let app = state(&db).await;

    let body = body_json(
        send_body(
            &app,
            r#"{"username":"invitee","password":"secret123","aff_code":"ABCD"}"#,
        )
        .await,
    )
    .await;
    assert_eq!(body["success"], json!(true));
    let stored_inviter: i64 = fetch_one!(
        &db,
        "SELECT CAST(inviter_id AS BIGINT) FROM users WHERE username = $1",
        "invitee",
    );
    assert_eq!(stored_inviter, inviter_row);

    let body = body_json(
        send_body(
            &app,
            r#"{"username":"invitee2","password":"secret123","aff_code":"NOPE"}"#,
        )
        .await,
    )
    .await;
    assert_eq!(body["success"], json!(true));
    let stored_inviter: i64 = fetch_one!(
        &db,
        "SELECT CAST(inviter_id AS BIGINT) FROM users WHERE username = $1",
        "invitee2",
    );
    assert_eq!(stored_inviter, 0);

    // ---- Go `finishInsert` 的额度赠送与邀请奖励（合规门确认后）----
    // 默认 quota 全 0、合规未确认：邀请关系已记录但 aff_* 不增长。
    let aff_count: i64 = fetch_one!(
        &db,
        "SELECT CAST(aff_count AS BIGINT) FROM users WHERE username = $1",
        "inviter",
    );
    assert_eq!(aff_count, 0);

    set_option(&db, "QuotaForNewUser", "100").await;
    set_option(&db, "QuotaForInvitee", "50").await;
    set_option(&db, "QuotaForInviter", "200").await;
    set_option(&db, "payment_setting.compliance_confirmed", "true").await;
    set_option(&db, "payment_setting.compliance_terms_version", "v1").await;
    let app = state(&db).await;
    let body = body_json(
        send_body(
            &app,
            r#"{"username":"rewarded","password":"secret123","aff_code":"ABCD"}"#,
        )
        .await,
    )
    .await;
    assert_eq!(body["success"], json!(true));

    // 新用户额度：quota = 100（Insert 写入 QuotaForNewUser）+ 50（邀请码赠送）。
    let quota: i64 = fetch_one!(
        &db,
        "SELECT CAST(quota AS BIGINT) FROM users WHERE username = $1",
        "rewarded",
    );
    assert_eq!(quota, 150);

    // 系统日志：新用户两行（注册赠送 + 邀请码赠送），邀请人一行。
    let rewarded_id: i64 = fetch_one!(
        &db,
        "SELECT CAST(id AS BIGINT) FROM users WHERE username = $1",
        "rewarded",
    );
    let logs: Vec<(String, String)> = match &db {
        Database::Sqlite(pool) => {
            sqlx::query_as("SELECT content, username FROM logs WHERE user_id = $1 ORDER BY id")
                .bind(rewarded_id)
                .fetch_all(pool)
                .await
                .expect("fixture logs")
        }
        Database::Postgres(pool) => {
            sqlx::query_as("SELECT content, username FROM logs WHERE user_id = $1 ORDER BY id")
                .bind(rewarded_id)
                .fetch_all(pool)
                .await
                .expect("fixture logs")
        }
    };
    assert_eq!(
        logs.iter()
            .map(|(content, _)| content.clone())
            .collect::<Vec<_>>(),
        vec![
            "新用户注册赠送 ＄0.000200 额度",
            "使用邀请码赠送 ＄0.000100 额度",
        ],
    );
    assert_eq!(
        logs.iter()
            .map(|(_, username)| username.clone())
            .collect::<Vec<_>>(),
        vec!["rewarded"; 2]
    );
    let inviter_logs: i64 = fetch_one!(
        &db,
        "SELECT count(*) FROM logs WHERE user_id = $1 AND content LIKE '邀请用户赠送%'",
        inviter_row,
    );
    assert_eq!(inviter_logs, 1);

    // 邀请人：aff_count + 1，且额度奖励按 QuotaForInviter 增长。
    let aff_count: i64 = fetch_one!(
        &db,
        "SELECT CAST(aff_count AS BIGINT) FROM users WHERE username = $1",
        "inviter",
    );
    assert_eq!(aff_count, 1);
    let aff_quota: i64 = fetch_one!(
        &db,
        "SELECT CAST(aff_quota AS BIGINT) FROM users WHERE username = $1",
        "inviter",
    );
    assert_eq!(aff_quota, 200);
    let aff_history: i64 = fetch_one!(
        &db,
        "SELECT CAST(aff_history AS BIGINT) FROM users WHERE username = $1",
        "inviter",
    );
    assert_eq!(aff_history, 200);

    // ---- form-urlencoded 绑定（Go `UnmarshalBodyReusable` 的表单分支）----
    let request = Request::builder()
        .method("POST")
        .uri("/api/user/register")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::ACCEPT_LANGUAGE, "zh-CN")
        .body(Body::from(
            "username=formuser&password=secret123".to_owned(),
        ))
        .unwrap();
    let response = send(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body, json!({"success": true, "message": ""}));
    let form_count: i64 = fetch_count(&db, "formuser").await;
    assert_eq!(form_count, 1);

    // ---- Turnstile enabled ----
    set_option(&db, "TurnstileCheckEnabled", "true").await;
    let app = state(&db).await;
    let response = send_body(&app, r#"{"username":"turnstile","password":"secret123"}"#).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_no_cache_headers(response.headers());
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false));
    assert_eq!(body["message"], json!("Turnstile token 为空"));

    // A rejecting siteverify yields Go's fixed failure, never a pass.
    let body = body_json(
        send(
            &app,
            register_request_with_verdict("turnstile=token", false),
        )
        .await,
    )
    .await;
    assert_eq!(body["message"], json!("Turnstile 校验失败，请刷新重试！"));
    set_option(&db, "TurnstileCheckEnabled", "false").await;

    // ---- CriticalRateLimit("CT") ----
    let app = state(&db).await.bind_transport(
        ProxyPolicy::parse_trusted_proxies(None).unwrap(),
        RateLimiter::memory(RateLimitSettings {
            enabled: true,
            requests: 1,
            window_seconds: 60,
        }),
        512,
    );
    let first = send_body(&app, r#"{"username":"ratelimit1","password":"secret123"}"#).await;
    assert_eq!(first.status(), StatusCode::OK);
    let body = body_json(first).await;
    assert_eq!(body["success"], json!(true));

    let second = send_body(&app, r#"{"username":"ratelimit2","password":"secret123"}"#).await;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_no_cache_headers(second.headers());
    assert_eq!(second.headers()[header::RETRY_AFTER], "60");
    let bytes = to_bytes(second.into_body(), 1024).await.unwrap();
    assert!(bytes.is_empty());
}

async fn fetch_count(db: &Database, username: &str) -> i64 {
    fetch_one!(
        db,
        "SELECT count(*) FROM users WHERE username = $1",
        username,
    )
}

#[tokio::test]
async fn sqlite_register_routes_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    let db = Database::Sqlite(pool);
    exec!(&db, SQLITE_USERS);
    exec!(&db, OPTIONS);
    exec!(&db, LOGS);
    exec!(&db, TOKENS);
    run_contract(db).await;
}

#[tokio::test]
async fn postgres_register_routes_contract() {
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
        "register_routes_{}_{}",
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
    exec!(&db, LOGS_POSTGRES);
    exec!(&db, TOKENS_POSTGRES);
    run_contract(db).await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA \"{schema}\" CASCADE"
    )))
    .execute(&admin)
    .await
    .expect("drop isolated schema");
    admin.close().await;
}
