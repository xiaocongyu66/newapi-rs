//! 登录成功与 2FA 的 HTTP + 数据库契约；仅交远程 CI 执行。
//!
//! 合成 fixture 只包含各仓储 SQL 实际读取的列，不是生产迁移或完整 Go schema
//! 金标准。所有写入均为隔离的 SQLite 内存库，测试之间不共享数据。

use std::{
    net::SocketAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{HeaderMap, Method, Request, StatusCode, header},
};
use newapi_config::SessionCookieSettings;
use newapi_identity::{
    auth_session::{AuthFence, SessionAuth},
    crypto::{AuthKeys, hash_password},
    sessions::NoCache,
    two_fa::totp::normalize_backup_code,
};
use newapi_server::{AppState, router};
use newapi_storage::Database;
use serde_json::{Value, json};
use sqlx::sqlite::SqlitePoolOptions;
use tower::ServiceExt;

const SECRET: &str = "test-session-secret";
const USER_ID: i64 = 1;
const USERNAME: &str = "alice";
const PASSWORD: &str = "correct horse battery staple";
const USER_AGENT: &str = "login-contract/1.0";
// RFC 4226 共享密钥的 base32 形式；仅用于让 2FA 记录可被仓储读取。
const TOTP_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const MSG_CREDENTIAL_ERROR: &str = "用户名或密码错误，或用户已被封禁";
const MSG_INVALID_PARAMS: &str = "无效的参数";
const MSG_LOGIN_DISABLED: &str = "管理员关闭了密码登录";
const MSG_FLOW_EXPIRED: &str = "会话已过期，请重新登录";
const MSG_CODE_INCORRECT: &str = "验证码或备用码错误，请重试";
const MSG_CODE_INVALID: &str = "验证码或备用码不正确";

const SELECT_SESSIONS: &str = "SELECT sid, status, login_method, ip, user_agent, refresh_hash \
    FROM user_sessions";
const INSERT_TWO_FA: &str = "INSERT INTO two_fas (user_id, secret, is_enabled, failed_attempts) \
    VALUES (?, ?, 1, 0)";
const SELECT_CONSUMED_AT: &str = "SELECT CAST(strftime('%s', consumed_at) AS TEXT) \
    FROM auth_flows";

type SessionRow = (String, String, String, String, String, String);

/// 每个仓储实际 SELECT/INSERT 的最小列集合；类型沿用 Go 旧库列宽。
const DDL: &[&str] = &[
    r#"CREATE TABLE options ("key" TEXT PRIMARY KEY, "value" TEXT)"#,
    r#"CREATE TABLE users (
        id INTEGER PRIMARY KEY, username TEXT, password TEXT NOT NULL,
        display_name TEXT, role INTEGER, status INTEGER, email TEXT,
        github_id TEXT, discord_id TEXT, oidc_id TEXT, wechat_id TEXT, telegram_id TEXT,
        access_token CHAR(32), quota INTEGER, used_quota INTEGER, request_count INTEGER,
        "group" VARCHAR(64), aff_code VARCHAR(32), aff_count INTEGER,
        aff_quota INTEGER, aff_history INTEGER, inviter_id INTEGER,
        deleted_at TIMESTAMP, linux_do_id TEXT, setting TEXT,
        remark VARCHAR(255), stripe_customer VARCHAR(64), created_at BIGINT,
        last_login_at BIGINT, auth_version BIGINT
    )"#,
    r#"CREATE TABLE user_sessions (
        sid VARCHAR(64) PRIMARY KEY, user_id INTEGER NOT NULL,
        version BIGINT NOT NULL DEFAULT 1, user_auth_version BIGINT NOT NULL,
        status VARCHAR(16) NOT NULL, refresh_hash CHAR(64) NOT NULL,
        previous_refresh_hash VARCHAR(64), previous_valid_until BIGINT NOT NULL DEFAULT 0,
        login_method VARCHAR(32) NOT NULL, ip VARCHAR(64), user_agent TEXT,
        created_at BIGINT, last_active_at BIGINT NOT NULL, expires_at BIGINT NOT NULL,
        revoked_at BIGINT NOT NULL DEFAULT 0, revoked_reason VARCHAR(64)
    )"#,
    r#"CREATE TABLE logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
        created_at BIGINT NOT NULL, type INTEGER, content TEXT, username TEXT,
        token_name TEXT, model_name TEXT, quota INTEGER,
        prompt_tokens INTEGER, completion_tokens INTEGER, use_time INTEGER,
        is_stream INTEGER, ip TEXT, request_id VARCHAR(64), other TEXT
    )"#,
    r#"CREATE TABLE two_fas (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL UNIQUE,
        secret VARCHAR(255) NOT NULL, is_enabled INTEGER NOT NULL DEFAULT 0,
        failed_attempts INTEGER NOT NULL DEFAULT 0, locked_until DATETIME,
        last_used_at DATETIME, created_at DATETIME, updated_at DATETIME,
        deleted_at DATETIME
    )"#,
    r#"CREATE TABLE two_fa_backup_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
        code_hash VARCHAR(255) NOT NULL, is_used INTEGER NOT NULL DEFAULT 0,
        used_at DATETIME, created_at DATETIME, deleted_at DATETIME
    )"#,
    r#"CREATE TABLE casbin_rule (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ptype TEXT,
        v0 TEXT, v1 TEXT, v2 TEXT, v3 TEXT, v4 TEXT, v5 TEXT
    )"#,
    r#"CREATE TABLE auth_flows (
        id INTEGER PRIMARY KEY AUTOINCREMENT, token_hash CHAR(64) NOT NULL UNIQUE,
        purpose VARCHAR(32) NOT NULL, user_id BIGINT, session_id VARCHAR(64),
        payload TEXT, expires_at DATETIME NOT NULL, consumed_at DATETIME,
        created_at DATETIME
    )"#,
];

fn sqlite_pool(db: &Database) -> &sqlx::SqlitePool {
    match db {
        Database::Sqlite(pool) => pool,
        Database::Postgres(_) => panic!("contract test uses the SQLite fixture"),
    }
}

async fn fixture() -> Database {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("connect SQLite in-memory fixture");
    for statement in DDL.iter().copied() {
        sqlx::query(statement)
            .execute(&pool)
            .await
            .expect("create SQLite fixture schema");
    }
    Database::Sqlite(pool)
}

async fn seed_user(db: &Database, status: i64, auth_version: i64) {
    let password_hash = hash_password(PASSWORD.as_bytes())
        .expect("hash fixture password")
        .expose_secret()
        .to_owned();
    sqlx::query(
        r#"INSERT INTO users (
            id,username,password,display_name,role,status,email,github_id,discord_id,
            oidc_id,wechat_id,telegram_id,"group",quota,used_quota,request_count,
            aff_code,aff_count,aff_quota,aff_history,inviter_id,deleted_at,linux_do_id,
            setting,stripe_customer,created_at,last_login_at,auth_version
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,'','','',0,0,?)"#,
    )
    .bind(USER_ID)
    .bind(USERNAME)
    .bind(password_hash)
    .bind("Alice Example")
    .bind(1_i64)
    .bind(status)
    .bind("alice@example.invalid")
    .bind("")
    .bind("")
    .bind("")
    .bind("")
    .bind("")
    .bind("default")
    .bind(1_000_i64)
    .bind(10_i64)
    .bind(2_i64)
    .bind("")
    .bind(0_i64)
    .bind(0_i64)
    .bind(0_i64)
    .bind(0_i64)
    .bind(auth_version)
    .execute(sqlite_pool(db))
    .await
    .expect("seed fixture user");
}

async fn seed_two_fa(db: &Database) {
    sqlx::query(INSERT_TWO_FA)
        .bind(USER_ID)
        .bind(TOTP_SECRET)
        .execute(sqlite_pool(db))
        .await
        .expect("seed fixture two_fa");
}

async fn seed_backup_code(db: &Database, code: &str) {
    let normalized = normalize_backup_code(code).expect("fixture backup code must be valid");
    let code_hash = hash_password(normalized.as_bytes())
        .expect("hash fixture backup code")
        .expose_secret()
        .to_owned();
    sqlx::query("INSERT INTO two_fa_backup_codes (user_id, code_hash, is_used) VALUES (?, ?, 0)")
        .bind(USER_ID)
        .bind(code_hash)
        .execute(sqlite_pool(db))
        .await
        .expect("seed fixture backup code");
}

async fn set_option(db: &Database, key: &str, value: &str) {
    sqlx::query(r#"INSERT INTO options ("key", "value") VALUES (?, ?)"#)
        .bind(key)
        .bind(value)
        .execute(sqlite_pool(db))
        .await
        .expect("seed fixture option");
}

async fn state_for(db: &Database) -> AppState {
    let auth = SessionAuth::with_fence(
        db.clone(),
        AuthKeys::new(SECRET),
        AuthFence::Disabled(NoCache::explicitly_disabled()),
    );
    AppState::initialize(db)
        .await
        .expect("initialize app state")
        .bind_auth(
            Arc::new(auth),
            SessionCookieSettings {
                secure: false,
                trusted_origins: Vec::new(),
            },
        )
        .bind_runtime(db.clone(), SECRET)
}

async fn count(db: &Database, sql: &'static str) -> i64 {
    sqlx::query_scalar(sql)
        .fetch_one(sqlite_pool(db))
        .await
        .expect("count fixture rows")
}

async fn send(
    state: &AppState,
    path: &str,
    accept_language: Option<&str>,
    content_type: &str,
    body: Vec<u8>,
) -> (StatusCode, HeaderMap, Value) {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::USER_AGENT, USER_AGENT)
        .header("x-forwarded-for", "203.0.113.7")
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 43_210))));
    if let Some(language) = accept_language {
        builder = builder.header(header::ACCEPT_LANGUAGE, language);
    }
    let request = builder.body(Body::from(body)).expect("build request");
    let response = router(state.clone()).oneshot(request).await.expect("route login request");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.expect("read response body");
    let value = serde_json::from_slice(&bytes).expect("response body is JSON");
    (status, headers, value)
}

async fn post_json(
    state: &AppState,
    path: &str,
    accept_language: Option<&str>,
    body: Value,
) -> (StatusCode, HeaderMap, Value) {
    send(
        state,
        path,
        accept_language,
        "application/json",
        body.to_string().into_bytes(),
    )
    .await
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0)
}

fn refresh_cookie(headers: &HeaderMap) -> String {
    let cookie = headers
        .get(header::SET_COOKIE)
        .expect("successful login must set the refresh cookie")
        .to_str()
        .expect("cookie is ASCII");
    let (pair, _) = cookie.split_once(';').expect("cookie has attributes");
    pair.strip_prefix("new_api_refresh=")
        .expect("cookie carries the refresh name")
        .to_owned()
}

#[tokio::test]
async fn successful_password_login_creates_session_and_audit_log() {
    let db = fixture().await;
    seed_user(&db, 1, 1).await;
    let state = state_for(&db).await;
    let before = unix_now();

    let (status, headers, body) = post_json(
        &state,
        "/api/user/login",
        Some("zh-CN"),
        json!({ "username": USERNAME, "password": PASSWORD }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["success"], true);
    assert_eq!(body["message"], "");
    let data = &body["data"];
    assert_eq!(data["token_type"], "Bearer");
    let access_token = data["access_token"].as_str().expect("access token is a string");
    assert!(!access_token.is_empty());
    let segments: Vec<&str> = access_token.split('.').collect();
    assert_eq!(segments.len(), 3);
    assert!(segments.iter().all(|segment| !segment.is_empty()));
    let access_expires_at = data["access_expires_at"].as_i64().expect("access expiry");
    assert!(access_expires_at > before);

    let session = &data["session"];
    let sid = session["sid"].as_str().expect("session sid");
    assert!(!sid.is_empty());
    assert_eq!(session["current"], true);
    assert_eq!(session["login_method"], "password");
    assert_eq!(session["ip"], "127.0.0.1");
    assert_eq!(session["user_agent"], USER_AGENT);

    let user = &data["user"];
    assert_eq!(user["username"], USERNAME);
    assert_eq!(user["display_name"], "Alice Example");
    assert_eq!(user["email"], "alice@example.invalid");
    assert_eq!(user["role"], 1);
    assert_eq!(user["status"], 1);
    assert_eq!(user["group"], "default");
    assert_eq!(user["quota"], 1_000);

    let cookie = headers
        .get(header::SET_COOKIE)
        .expect("refresh cookie header")
        .to_str()
        .expect("cookie is ASCII");
    let (_, attributes) = cookie.split_once(';').expect("cookie attributes");
    assert!(cookie.starts_with("new_api_refresh="));
    assert!(attributes.contains("Path=/api/user/auth"));
    assert!(attributes.contains("HttpOnly"));
    assert!(attributes.contains("SameSite=Strict"));
    assert!(!attributes.contains("Secure"));
    let max_age = attributes
        .split(';')
        .find_map(|part| part.trim().strip_prefix("Max-Age="))
        .and_then(|value| value.parse::<i64>().ok());
    assert!(max_age.is_some_and(|value| value > 0));
    let refresh = refresh_cookie(&headers);
    let (refresh_sid, refresh_secret) = refresh.split_once('.').expect("refresh credential");
    assert_eq!(refresh_sid, sid);
    let expected_refresh_hash = AuthKeys::new(SECRET).refresh_hash(refresh_secret);

    let cache_control = headers
        .get(header::CACHE_CONTROL)
        .expect("login responses are non-cacheable")
        .to_str()
        .expect("cache-control is ASCII");
    assert!(cache_control.contains("no-store"));

    let pool = sqlite_pool(&db);
    let sessions: Vec<SessionRow> = sqlx::query_as(SELECT_SESSIONS)
        .fetch_all(pool)
        .await
        .expect("read created session");
    assert_eq!(sessions.len(), 1);
    let (sid, session_status, login_method, ip, user_agent, refresh_hash) = &sessions[0];
    assert_eq!(session_status, "active");
    assert_eq!(login_method, "password");
    assert_eq!(ip, "127.0.0.1");
    assert_eq!(user_agent, USER_AGENT);
    assert!(!sid.is_empty());
    assert_eq!(refresh_hash.as_str(), expected_refresh_hash.expose_secret());

    let last_login_at: i64 = sqlx::query_scalar("SELECT last_login_at FROM users WHERE id = ?")
        .bind(USER_ID)
        .fetch_one(pool)
        .await
        .expect("read last_login_at");
    assert!(last_login_at > 0);

    let logs: Vec<(i64, String, String)> = sqlx::query_as("SELECT type, content, other FROM logs")
        .fetch_all(pool)
        .await
        .expect("read login audit log");
    assert_eq!(logs.len(), 1);
    let (log_type, content, other) = &logs[0];
    assert_eq!(*log_type, 7);
    assert_eq!(content, "Logged in successfully via password");
    let other: Value = serde_json::from_str(other).expect("audit other is JSON");
    assert_eq!(other["login_method"], "password");
    assert_eq!(other["user_agent"], USER_AGENT);
    assert_eq!(other["op"]["action"], "login");

    db.close().await;
}

#[tokio::test]
async fn wrong_password_returns_generic_error_without_side_effects() {
    let db = fixture().await;
    seed_user(&db, 1, 1).await;
    let state = state_for(&db).await;

    let (status, headers, body) = post_json(
        &state,
        "/api/user/login",
        Some("zh-CN"),
        json!({ "username": USERNAME, "password": "wrong password" }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["success"], false);
    assert_eq!(body["message"], MSG_CREDENTIAL_ERROR);
    assert!(!headers.contains_key(header::SET_COOKIE));
    assert_eq!(count(&db, "SELECT COUNT(*) FROM user_sessions").await, 0);
    assert_eq!(count(&db, "SELECT COUNT(*) FROM logs").await, 0);

    db.close().await;
}

#[tokio::test]
async fn empty_credentials_return_invalid_parameters() {
    let db = fixture().await;
    seed_user(&db, 1, 1).await;
    let state = state_for(&db).await;

    let (status, headers, body) = post_json(
        &state,
        "/api/user/login",
        Some("zh-CN"),
        json!({ "username": "", "password": "" }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["success"], false);
    assert_eq!(body["message"], MSG_INVALID_PARAMS);
    assert!(!headers.contains_key(header::SET_COOKIE));
    assert_eq!(count(&db, "SELECT COUNT(*) FROM user_sessions").await, 0);

    db.close().await;
}

#[tokio::test]
async fn password_login_disabled_precedes_body_parsing() {
    let db = fixture().await;
    seed_user(&db, 1, 1).await;
    set_option(&db, "PasswordLoginEnabled", "false").await;
    let state = state_for(&db).await;

    // Go 在 BindJSON 之前检查开关，因此非法 JSON 仍返回禁用文案。
    let (status, headers, body) = send(
        &state,
        "/api/user/login",
        Some("zh-CN"),
        "application/json",
        b"this is not json".to_vec(),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["success"], false);
    assert_eq!(body["message"], MSG_LOGIN_DISABLED);
    assert!(!headers.contains_key(header::SET_COOKIE));
    assert_eq!(count(&db, "SELECT COUNT(*) FROM user_sessions").await, 0);

    db.close().await;
}

#[tokio::test]
async fn enabled_two_fa_returns_pending_flow_without_session() {
    let db = fixture().await;
    seed_user(&db, 1, 1).await;
    seed_two_fa(&db).await;
    let state = state_for(&db).await;
    let before = unix_now();

    let (status, headers, body) = post_json(
        &state,
        "/api/user/login",
        Some("zh-CN"),
        json!({ "username": USERNAME, "password": PASSWORD }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["success"], true);
    let data = &body["data"];
    assert_eq!(data["require_2fa"], true);
    assert!(data["flow_token"].as_str().is_some_and(|token| !token.is_empty()));
    let expires_at = data["expires_at"].as_i64().expect("flow expiry");
    assert!(
        (expires_at - before).abs() <= 10,
        "pending flow should expire about 300 seconds after the request"
    );
    assert!(!headers.contains_key(header::SET_COOKIE));

    let pool = sqlite_pool(&db);
    let flows: Vec<(String, String)> = sqlx::query_as("SELECT purpose, payload FROM auth_flows")
        .fetch_all(pool)
        .await
        .expect("read pending auth flow");
    assert_eq!(flows.len(), 1);
    let (purpose, payload) = &flows[0];
    assert_eq!(purpose, "2fa_login");
    let payload: Value = serde_json::from_str(payload).expect("flow payload is JSON");
    assert_eq!(payload["auth_version"], 1);
    assert_eq!(count(&db, "SELECT COUNT(*) FROM user_sessions").await, 0);

    db.close().await;
}

#[tokio::test]
async fn unknown_two_fa_flow_is_reported_as_expired() {
    let db = fixture().await;
    seed_user(&db, 1, 1).await;
    let state = state_for(&db).await;

    let (status, headers, body) = post_json(
        &state,
        "/api/user/login/2fa",
        Some("zh-CN"),
        json!({ "flow_token": "unknown-flow-token", "code": "123456" }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["success"], false);
    assert_eq!(body["message"], MSG_FLOW_EXPIRED);
    assert!(!headers.contains_key(header::SET_COOKIE));
    assert_eq!(count(&db, "SELECT COUNT(*) FROM user_sessions").await, 0);

    db.close().await;
}

#[tokio::test]
async fn wrong_two_fa_code_keeps_flow_retryable() {
    let db = fixture().await;
    seed_user(&db, 1, 1).await;
    seed_two_fa(&db).await;
    let state = state_for(&db).await;

    let (_, _, pending) = post_json(
        &state,
        "/api/user/login",
        Some("zh-CN"),
        json!({ "username": USERNAME, "password": PASSWORD }),
    )
    .await;
    let pending_token = &pending["data"]["flow_token"];
    let flow_token = pending_token.as_str().expect("pending flow token").to_owned();

    // 格式合法但未命中的备用码，走 Incorrect 分支。
    let wrong = json!({ "flow_token": flow_token, "code": "ZZZZ-ZZZZ" });
    let (status, headers, first) =
        post_json(&state, "/api/user/login/2fa", Some("zh-CN"), wrong.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["success"], false);
    let message = first["message"].as_str().expect("error message");
    assert!(
        message == MSG_CODE_INCORRECT || message == MSG_CODE_INVALID,
        "unexpected 2FA error message"
    );
    assert_ne!(message, MSG_FLOW_EXPIRED);
    assert!(!headers.contains_key(header::SET_COOKIE));

    let (status, _, second) =
        post_json(&state, "/api/user/login/2fa", Some("zh-CN"), wrong).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(second["success"], false);
    assert_eq!(second["message"], message);
    assert_ne!(second["message"], MSG_FLOW_EXPIRED);
    assert_eq!(count(&db, "SELECT COUNT(*) FROM user_sessions").await, 0);

    db.close().await;
}

#[tokio::test]
async fn backup_code_completes_two_fa_login_and_creates_session() {
    let db = fixture().await;
    seed_user(&db, 1, 1).await;
    seed_two_fa(&db).await;
    seed_backup_code(&db, "ABCD-EFGH").await;
    let state = state_for(&db).await;

    let (_, _, pending) = post_json(
        &state,
        "/api/user/login",
        Some("zh-CN"),
        json!({ "username": USERNAME, "password": PASSWORD }),
    )
    .await;
    let pending_token = &pending["data"]["flow_token"];
    let flow_token = pending_token.as_str().expect("pending flow token").to_owned();

    let (status, headers, body) = post_json(
        &state,
        "/api/user/login/2fa",
        Some("zh-CN"),
        json!({ "flow_token": flow_token, "code": "ABCD-EFGH" }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["success"], true);
    let data = &body["data"];
    let access_token = data["access_token"].as_str().expect("access token is a string");
    assert_eq!(access_token.split('.').count(), 3);
    assert_eq!(data["token_type"], "Bearer");
    assert_eq!(data["session"]["login_method"], "2fa");
    assert_eq!(data["session"]["ip"], "127.0.0.1");
    assert!(!refresh_cookie(&headers).is_empty());

    let pool = sqlite_pool(&db);
    let methods: Vec<(String, String)> =
        sqlx::query_as("SELECT status, login_method FROM user_sessions")
            .fetch_all(pool)
            .await
            .expect("read 2FA-created session");
    assert_eq!(methods.len(), 1);
    assert_eq!(methods[0], ("active".to_owned(), "2fa".to_owned()));

    let consumed: Option<String> = sqlx::query_scalar(SELECT_CONSUMED_AT)
        .fetch_one(pool)
        .await
        .expect("read consumed flow");
    assert!(consumed.is_some());

    let logged: String = sqlx::query_scalar("SELECT content FROM logs")
        .fetch_one(pool)
        .await
        .expect("read 2FA login log");
    assert_eq!(logged, "Logged in successfully via 2fa");

    db.close().await;
}
