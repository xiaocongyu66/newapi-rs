//! HTTP contracts for `/api/user/2fa/*`.
//!
//! Runs only in remote CI. Every scenario uses an isolated synthetic fixture
//! (in-memory SQLite or an isolated PostgreSQL schema); no service is started.
//! The fixture DDL mirrors the Go GORM columns for `two_fas` /
//! `two_fa_backup_codes` plus the user/session columns used by `UserAuth`.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::Request,
    http::{HeaderMap, Method, StatusCode, header},
    middleware,
    response::Response,
    routing::{get, post},
};
use newapi_config::SessionCookieSettings;
use newapi_identity::{
    AuthIdentity,
    auth_session::{AuthFence, SessionAuth},
    crypto::{AuthKeys, verify_password},
    sessions::NoCache,
    two_fa::{TwoFaRepository, totp::normalize_backup_code, totp_code_at},
};
use newapi_security::client_ip::ProxyPolicy;
use newapi_server::{AppState, RateLimiter, auth::user_auth, limit::RateLimitSettings, twofa_http};
use newapi_storage::Database;
use serde_json::{Value, json};
use sqlx::{
    ConnectOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::SqlitePoolOptions,
};
use tower::ServiceExt;

static NEXT: AtomicU64 = AtomicU64::new(0);

const SECRET: &str = "twofa-routes-fixture-secret";
const USER_ID: i64 = 17;
const CACHE_CONTROL_VALUE: &str = "no-store, no-cache, must-revalidate, private, max-age=0";

const USERS_SQLITE: &str = r#"CREATE TABLE users (
    id INTEGER PRIMARY KEY, username TEXT, display_name TEXT,
    role INTEGER, status INTEGER, email TEXT, github_id TEXT, discord_id TEXT,
    oidc_id TEXT, wechat_id TEXT, telegram_id TEXT, "group" TEXT,
    quota INTEGER, used_quota INTEGER, request_count INTEGER, aff_code TEXT,
    aff_count INTEGER, aff_quota INTEGER, aff_history INTEGER, inviter_id INTEGER,
    linux_do_id TEXT, setting TEXT, stripe_customer TEXT, auth_version BIGINT,
    access_token TEXT, deleted_at TIMESTAMP, password TEXT
)"#;

const USERS_POSTGRES: &str = r#"CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY, username TEXT, display_name TEXT,
    role BIGINT, status BIGINT, email TEXT, github_id TEXT, discord_id TEXT,
    oidc_id TEXT, wechat_id TEXT, telegram_id TEXT, "group" TEXT,
    quota BIGINT, used_quota BIGINT, request_count BIGINT, aff_code TEXT,
    aff_count BIGINT, aff_quota BIGINT, aff_history BIGINT, inviter_id BIGINT,
    linux_do_id TEXT, setting TEXT, stripe_customer TEXT, auth_version BIGINT,
    access_token TEXT, deleted_at TIMESTAMPTZ, password TEXT
)"#;

const SESSIONS: &str = r#"CREATE TABLE user_sessions (
    sid VARCHAR(64) PRIMARY KEY, user_id BIGINT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1, user_auth_version BIGINT NOT NULL,
    status VARCHAR(16) NOT NULL, refresh_hash CHAR(64) NOT NULL,
    previous_refresh_hash VARCHAR(64), previous_valid_until BIGINT NOT NULL DEFAULT 0,
    login_method VARCHAR(32) NOT NULL, ip VARCHAR(64), user_agent TEXT,
    created_at BIGINT, last_active_at BIGINT NOT NULL, expires_at BIGINT NOT NULL,
    revoked_at BIGINT NOT NULL DEFAULT 0, revoked_reason VARCHAR(64)
)"#;

const TWO_FAS_SQLITE: &str = r#"CREATE TABLE two_fas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    secret VARCHAR(255) NOT NULL,
    is_enabled INTEGER NOT NULL DEFAULT 0,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until DATETIME,
    last_used_at DATETIME,
    created_at DATETIME,
    updated_at DATETIME,
    deleted_at DATETIME
)"#;

const TWO_FAS_POSTGRES: &str = r#"CREATE TABLE two_fas (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL UNIQUE,
    secret VARCHAR(255) NOT NULL,
    is_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    failed_attempts BIGINT NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ
)"#;

const BACKUP_CODES_SQLITE: &str = r#"CREATE TABLE two_fa_backup_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    code_hash VARCHAR(255) NOT NULL,
    is_used INTEGER NOT NULL DEFAULT 0,
    used_at DATETIME,
    created_at DATETIME,
    deleted_at DATETIME
)"#;

const BACKUP_CODES_POSTGRES: &str = r#"CREATE TABLE two_fa_backup_codes (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    code_hash VARCHAR(255) NOT NULL,
    is_used BOOLEAN NOT NULL DEFAULT FALSE,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ
)"#;

macro_rules! backend {
    ($db:expr, $pool:ident, $body:block) => {
        match $db {
            Database::Sqlite($pool) => $body,
            Database::Postgres($pool) => $body,
        }
    };
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0)
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/user/2fa/status", get(twofa_http::status))
        .route("/api/user/2fa/setup", post(twofa_http::setup))
        .route("/api/user/2fa/enable", post(twofa_http::enable))
        .route("/api/user/2fa/disable", post(twofa_http::disable))
        .route("/api/user/2fa/backup_codes", post(twofa_http::backup_codes))
        .route_layer(middleware::from_fn_with_state(state.clone(), user_auth))
        .with_state(state)
}

fn state(db: &Database) -> AppState {
    let auth = Arc::new(SessionAuth::with_fence(
        db.clone(),
        AuthKeys::new(SECRET),
        AuthFence::Disabled(NoCache::explicitly_disabled()),
    ));
    AppState::default()
        .bind_auth(
            auth,
            SessionCookieSettings {
                secure: false,
                trusted_origins: Vec::new(),
            },
        )
        .bind_runtime(db.clone(), SECRET)
        .bind_transport(
            ProxyPolicy::parse_trusted_proxies(None).expect("proxy policy"),
            RateLimiter::memory(RateLimitSettings {
                enabled: false,
                requests: 1,
                window_seconds: 60,
            }),
            512,
        )
}

async fn exec(db: &Database, statement: &'static str) {
    backend!(db, pool, {
        sqlx::query(statement)
            .execute(pool)
            .await
            .expect("fixture statement");
    });
}

async fn create_schema(db: &Database) {
    match db {
        Database::Sqlite(_) => {
            for statement in [USERS_SQLITE, SESSIONS, TWO_FAS_SQLITE, BACKUP_CODES_SQLITE] {
                exec(db, statement).await;
            }
        }
        Database::Postgres(_) => {
            for statement in [
                USERS_POSTGRES,
                SESSIONS,
                TWO_FAS_POSTGRES,
                BACKUP_CODES_POSTGRES,
            ] {
                exec(db, statement).await;
            }
        }
    }
}

async fn reset(db: &Database) {
    exec(db, "DELETE FROM user_sessions").await;
    exec(db, "DELETE FROM two_fa_backup_codes").await;
    exec(db, "DELETE FROM two_fas").await;
    exec(db, "DELETE FROM users").await;
}

async fn seed_user(db: &Database, auth_version: i64, pat: Option<&str>) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO users
                (id,username,display_name,role,status,"group",auth_version,access_token)
                VALUES ($1,$2,$3,1,1,'default',$4,$5)"#,
        )
        .bind(USER_ID)
        .bind("fixture")
        .bind("Fixture")
        .bind(auth_version)
        .bind(pat)
        .execute(pool)
        .await
        .expect("seed user");
    });
}

async fn set_pat(db: &Database, pat: Option<&str>) {
    backend!(db, pool, {
        sqlx::query("UPDATE users SET access_token=$1 WHERE id=$2")
            .bind(pat)
            .bind(USER_ID)
            .execute(pool)
            .await
            .expect("update PAT");
    });
}

async fn seed_session(db: &Database, sid: &str, uv: i64, sv: i64, at: i64) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO user_sessions
                (sid,user_id,version,user_auth_version,status,refresh_hash,
                 previous_refresh_hash,previous_valid_until,login_method,ip,
                 user_agent,created_at,last_active_at,expires_at,revoked_at,revoked_reason)
                VALUES ($1,$2,$3,$4,'active','fixture-hash',NULL,0,'password','',
                        '',$5,$5,$6,0,'')"#,
        )
        .bind(sid)
        .bind(USER_ID)
        .bind(sv)
        .bind(uv)
        .bind(at)
        .bind(at + 3600)
        .execute(pool)
        .await
        .expect("seed session");
    });
}

fn jwt(sid: &str, uv: i64, sv: i64, issued_at: i64) -> String {
    AuthKeys::new(SECRET)
        .issue_access(
            &AuthIdentity {
                user_id: USER_ID,
                sid: sid.to_owned(),
                user_auth_version: uv,
                session_version: sv,
            },
            issued_at,
        )
        .expect("issue access token")
        .token
        .expose_secret()
        .to_owned()
}

async fn send(
    state: &AppState,
    method: Method,
    path: &str,
    authorization: Option<&str>,
    body: Option<&Value>,
) -> Response {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(value) = authorization {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    let body = match body {
        Some(value) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(serde_json::to_vec(value).expect("request JSON"))
        }
        None => Body::empty(),
    };
    router(state.clone())
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap()
}

async fn send_post(state: &AppState, path: &str, authorization: &str, body: &Value) -> Response {
    send(state, Method::POST, path, Some(authorization), Some(body)).await
}

async fn body_json(response: Response) -> Value {
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body");
    serde_json::from_slice(&bytes).expect("response JSON")
}

fn translated(key: &str) -> String {
    newapi_i18n::translate("en", key, std::iter::empty::<(&str, &str)>())
}

fn assert_disable_cache(headers: &HeaderMap) {
    assert_eq!(headers[header::CACHE_CONTROL], CACHE_CONTROL_VALUE);
    assert_eq!(headers[header::PRAGMA], "no-cache");
    assert_eq!(headers[header::EXPIRES], "0");
}

fn assert_no_cache_headers(headers: &HeaderMap) {
    assert!(!headers.contains_key(header::CACHE_CONTROL));
    assert!(!headers.contains_key(header::PRAGMA));
    assert!(!headers.contains_key(header::EXPIRES));
}

async fn assert_auth_failure(response: Response, code: &str) {
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_no_cache_headers(response.headers());
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false));
    assert_eq!(body["code"], json!(code));
}

async fn assert_business_error(response: Response, key: &str) {
    assert_eq!(response.status(), StatusCode::OK);
    assert_disable_cache(response.headers());
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false), "{body}");
    assert_eq!(body["message"], json!(translated(key)), "{body}");
}

async fn assert_success(response: Response) -> Value {
    assert_eq!(response.status(), StatusCode::OK);
    assert_disable_cache(response.headers());
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true), "{body}");
    body
}

async fn stored_auth_version(db: &Database) -> i64 {
    backend!(db, pool, {
        sqlx::query_scalar::<_, i64>("SELECT CAST(auth_version AS BIGINT) FROM users WHERE id=$1")
            .bind(USER_ID)
            .fetch_one(pool)
            .await
            .expect("stored auth version")
    })
}

async fn factor_count(db: &Database) -> i64 {
    backend!(db, pool, {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM two_fas WHERE user_id=$1 AND deleted_at IS NULL",
        )
        .bind(USER_ID)
        .fetch_one(pool)
        .await
        .expect("factor count")
    })
}

async fn stored_factor(db: &Database) -> Option<(String, bool, i64, Option<i64>)> {
    match db {
        Database::Sqlite(pool) => sqlx::query_as::<_, (String, bool, i64, Option<i64>)>(
            "SELECT secret, is_enabled, failed_attempts, \
                CAST(strftime('%s', locked_until) AS INTEGER) \
             FROM two_fas WHERE user_id=$1 AND deleted_at IS NULL",
        )
        .bind(USER_ID)
        .fetch_optional(pool)
        .await
        .expect("stored factor"),
        Database::Postgres(pool) => sqlx::query_as::<_, (String, bool, i64, Option<i64>)>(
            "SELECT secret, is_enabled, failed_attempts, \
                CAST(EXTRACT(EPOCH FROM locked_until) AS BIGINT) \
             FROM two_fas WHERE user_id=$1 AND deleted_at IS NULL",
        )
        .bind(USER_ID)
        .fetch_optional(pool)
        .await
        .expect("stored factor"),
    }
}

async fn active_code_hashes(db: &Database) -> Vec<String> {
    let rows: Vec<(String,)> = backend!(db, pool, {
        sqlx::query_as::<_, (String,)>(
            "SELECT code_hash FROM two_fa_backup_codes \
             WHERE user_id=$1 AND deleted_at IS NULL ORDER BY id",
        )
        .bind(USER_ID)
        .fetch_all(pool)
        .await
        .expect("active backup codes")
    });
    rows.into_iter().map(|(hash,)| hash).collect()
}

async fn total_code_rows(db: &Database) -> i64 {
    backend!(db, pool, {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM two_fa_backup_codes WHERE user_id=$1")
            .bind(USER_ID)
            .fetch_one(pool)
            .await
            .expect("total backup code rows")
    })
}

fn hash_matches(plain: &str, hash: &str) -> bool {
    let normalized = normalize_backup_code(plain).expect("valid backup code");
    matches!(verify_password(normalized.as_bytes(), hash), Ok(true))
}

fn assert_backup_codes(codes: &Value) -> Vec<String> {
    let codes = codes.as_array().expect("backup code array");
    assert_eq!(codes.len(), 4, "Go BackupCodeCount is 4");
    let mut values = Vec::with_capacity(codes.len());
    for code in codes {
        let value = code.as_str().expect("backup code string").to_owned();
        assert_eq!(value.len(), 9, "{value}");
        let bytes = value.as_bytes();
        assert_eq!(bytes[4], b'-', "{value}");
        for (index, byte) in bytes.iter().enumerate() {
            if index == 4 {
                continue;
            }
            assert!(
                byte.is_ascii_uppercase() || byte.is_ascii_digit(),
                "{value}"
            );
        }
        values.push(value);
    }
    values
}

fn assert_qr(qr: &str, secret: &str) {
    assert_eq!(
        qr,
        format!(
            "otpauth://totp/New API:fixture (New API)?secret={secret}&issuer=New API&digits=6&period=30"
        )
    );
}

fn valid_code(secret: &str, at: i64) -> String {
    totp_code_at(secret, at).expect("deterministic TOTP")
}

/// A six-digit value outside the accepted ±1 step window.
fn invalid_code(secret: &str, at: i64) -> String {
    let accepted: Vec<String> = [at - 30, at, at + 30]
        .into_iter()
        .filter_map(|moment| totp_code_at(secret, moment))
        .collect();
    for candidate in 0..10_000u32 {
        let value = format!("{candidate:06}");
        if !accepted.contains(&value) {
            return value;
        }
    }
    unreachable!("the ±1 window covers at most three codes")
}

async fn setup_pending(state: &AppState, token: &str) -> (String, Vec<String>) {
    let response = send_post(state, "/api/user/2fa/setup", token, &json!({})).await;
    let body = assert_success(response).await;
    assert_eq!(body["message"], json!(translated("twofa.setup_success")));
    let secret = body["data"]["secret"]
        .as_str()
        .expect("setup secret")
        .to_owned();
    let codes = assert_backup_codes(&body["data"]["backup_codes"]);
    assert_qr(
        body["data"]["qr_code_data"].as_str().expect("qr data"),
        &secret,
    );
    (secret, codes)
}

async fn enable_with(state: &AppState, token: &str, secret: &str) -> (String, String) {
    let code = valid_code(secret, now());
    let response = send_post(state, "/api/user/2fa/enable", token, &json!({"code": code})).await;
    let body = assert_success(response).await;
    assert_eq!(body["message"], json!(translated("twofa.enable_success")));
    let new_token = body["data"]["access_token"]
        .as_str()
        .expect("rotated token")
        .to_owned();
    assert_eq!(body["data"]["token_type"], json!("Bearer"));
    assert_eq!(body["data"]["session"]["current"], json!(true));
    assert_eq!(body["data"]["session"]["sid"], json!("sid-twofa"));
    (new_token, code)
}

async fn run_contract(db: Database) {
    create_schema(&db).await;
    let app = state(&db);

    // UserAuth runs before every handler; its rejection carries no cache headers.
    for (method, path) in [
        (Method::GET, "/api/user/2fa/status"),
        (Method::POST, "/api/user/2fa/setup"),
        (Method::POST, "/api/user/2fa/enable"),
        (Method::POST, "/api/user/2fa/disable"),
        (Method::POST, "/api/user/2fa/backup_codes"),
    ] {
        let body = (method == Method::POST).then(|| json!({"code": "123456"}));
        let response = send(&app, method, path, None, body.as_ref()).await;
        assert_auth_failure(response, "AUTH_UNAUTHORIZED").await;
    }

    // ---- status: not enabled --------------------------------------------
    reset(&db).await;
    seed_user(&db, 1, None).await;
    let at = now();
    seed_session(&db, "sid-twofa", 1, 1, at).await;
    let token = format!("Bearer {}", jwt("sid-twofa", 1, 1, at));

    let response = send(
        &app,
        Method::GET,
        "/api/user/2fa/status",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_no_cache_headers(response.headers());
    let body = body_json(response).await;
    assert_eq!(
        body,
        json!({"success": true, "message": "", "data": {"enabled": false, "locked": false}})
    );

    // ---- setup: secret, otpauth URI, four backup codes -------------------
    let (first_secret, first_codes) = setup_pending(&app, &token).await;
    assert_eq!(first_secret.len(), 32);
    assert!(
        first_secret
            .bytes()
            .all(|byte| { byte.is_ascii_uppercase() || (b'2'..=b'7').contains(&byte) })
    );
    assert_eq!(stored_auth_version(&db).await, 1);
    assert_eq!(factor_count(&db).await, 1);
    let (stored_secret, enabled, attempts, locked) = stored_factor(&db).await.expect("factor");
    assert_eq!(stored_secret, first_secret);
    assert!(!enabled);
    assert_eq!(attempts, 0);
    assert!(locked.is_none());
    let hashes = active_code_hashes(&db).await;
    assert_eq!(hashes.len(), 4);
    for code in &first_codes {
        assert!(
            hashes.iter().any(|hash| hash_matches(code, hash)),
            "setup must persist a hash for every returned code"
        );
    }

    let response = send(
        &app,
        Method::GET,
        "/api/user/2fa/status",
        Some(&token),
        None,
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(
        body,
        json!({"success": true, "message": "", "data": {"enabled": false, "locked": false}})
    );

    // A second setup hard-deletes the pending factor and its old codes.
    let (secret, _codes) = setup_pending(&app, &token).await;
    assert_ne!(secret, first_secret);
    assert_eq!(factor_count(&db).await, 1);
    assert_eq!(active_code_hashes(&db).await.len(), 4);
    assert_eq!(
        total_code_rows(&db).await,
        4,
        "pending replacement hard-deletes old codes"
    );
    let repo = TwoFaRepository::new(db.clone());
    assert_eq!(
        repo.validate_backup_code(USER_ID, &first_codes[0], now())
            .await,
        Ok(false),
        "replaced codes must not validate"
    );

    // ---- enable: format errors, wrong code, then success -----------------
    let response = send_post(
        &app,
        "/api/user/2fa/enable",
        &token,
        &json!({"code": "12345"}),
    )
    .await;
    assert_business_error(response, "twofa.code_length").await;
    let response = send_post(
        &app,
        "/api/user/2fa/enable",
        &token,
        &json!({"code": "abcdef"}),
    )
    .await;
    assert_business_error(response, "twofa.code_numeric").await;
    let wrong = invalid_code(&secret, now());
    let response = send_post(
        &app,
        "/api/user/2fa/enable",
        &token,
        &json!({"code": wrong}),
    )
    .await;
    assert_business_error(response, "twofa.code_incorrect").await;
    assert_eq!(stored_auth_version(&db).await, 1);
    assert!(!stored_factor(&db).await.expect("pending").1);

    let (rotated, _) = enable_with(&app, &token, &secret).await;
    assert_eq!(stored_auth_version(&db).await, 2);
    let (_, enabled, attempts, locked) = stored_factor(&db).await.expect("enabled factor");
    assert!(enabled);
    assert_eq!(attempts, 0);
    assert!(locked.is_none());
    let rotated = format!("Bearer {rotated}");

    // The pre-enrollment JWT is revoked; the rotated one authenticates.
    let response = send(
        &app,
        Method::GET,
        "/api/user/2fa/status",
        Some(&token),
        None,
    )
    .await;
    assert_auth_failure(response, "AUTH_SESSION_REVOKED").await;
    let response = send(
        &app,
        Method::GET,
        "/api/user/2fa/status",
        Some(&rotated),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_no_cache_headers(response.headers());
    let body = body_json(response).await;
    assert_eq!(
        body,
        json!({
            "success": true,
            "message": "",
            "data": {"enabled": true, "locked": false, "backup_codes_remaining": 4},
        })
    );

    // Re-enabling and re-setting an enabled factor are distinct branches.
    let response = send_post(
        &app,
        "/api/user/2fa/enable",
        &rotated,
        &json!({"code": valid_code(&secret, now())}),
    )
    .await;
    assert_business_error(response, "twofa.already_enabled").await;
    let response = send_post(&app, "/api/user/2fa/setup", &rotated, &json!({})).await;
    assert_business_error(response, "twofa.setup_already_enabled").await;
    assert_eq!(stored_auth_version(&db).await, 2);

    // ---- disable: wrong code, PAT gate, then success ---------------------
    // A six-digit TOTP failure falls through to backup-code format validation,
    // which rejects "123456" as malformed: Go reports code_invalid here.
    let response = send_post(
        &app,
        "/api/user/2fa/disable",
        &rotated,
        &json!({"code": invalid_code(&secret, now())}),
    )
    .await;
    assert_business_error(response, "twofa.code_invalid").await;
    // A well-formed but unknown backup code consumes a failure and reports
    // the retry message.
    let response = send_post(
        &app,
        "/api/user/2fa/disable",
        &rotated,
        &json!({"code": "ZZZZ-ZZZZ"}),
    )
    .await;
    assert_business_error(response, "twofa.code_incorrect").await;
    assert_eq!(stored_auth_version(&db).await, 2);
    assert!(stored_factor(&db).await.expect("enabled").1);

    // A personal access token is authenticated but is not a browser session;
    // Go answers the bare "current auth method does not support security
    // verification" and leaves the factor untouched.
    set_pat(&db, Some("pat-twofa-fixture")).await;
    let response = send_post(
        &app,
        "/api/user/2fa/disable",
        "Bearer pat-twofa-fixture",
        &json!({"code": valid_code(&secret, now())}),
    )
    .await;
    assert_business_error(response, "auth.session_required").await;
    assert_eq!(stored_auth_version(&db).await, 2);
    assert!(stored_factor(&db).await.expect("enabled").1);
    set_pat(&db, None).await;

    let response = send_post(
        &app,
        "/api/user/2fa/disable",
        &rotated,
        &json!({"code": valid_code(&secret, now())}),
    )
    .await;
    let body = assert_success(response).await;
    assert_eq!(body["message"], json!(translated("twofa.disable_success")));
    assert!(body["data"]["access_token"].is_string());
    assert_eq!(stored_auth_version(&db).await, 3);
    assert_eq!(factor_count(&db).await, 0);
    assert_eq!(total_code_rows(&db).await, 0);
    let after_disable = format!(
        "Bearer {}",
        body["data"]["access_token"]
            .as_str()
            .expect("disable token")
    );
    let response = send(
        &app,
        Method::GET,
        "/api/user/2fa/status",
        Some(&rotated),
        None,
    )
    .await;
    assert_auth_failure(response, "AUTH_SESSION_REVOKED").await;
    let response = send(
        &app,
        Method::GET,
        "/api/user/2fa/status",
        Some(&after_disable),
        None,
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["data"], json!({"enabled": false, "locked": false}));

    let response = send_post(
        &app,
        "/api/user/2fa/disable",
        &after_disable,
        &json!({"code": valid_code(&secret, now())}),
    )
    .await;
    assert_business_error(response, "twofa.not_enabled").await;

    // ---- backup_codes: wrong code, then regeneration ---------------------
    reset(&db).await;
    seed_user(&db, 1, None).await;
    let at = now();
    seed_session(&db, "sid-twofa", 1, 1, at).await;
    let token = format!("Bearer {}", jwt("sid-twofa", 1, 1, at));
    let (secret, old_codes) = setup_pending(&app, &token).await;
    let (rotated, _) = enable_with(&app, &token, &secret).await;
    let rotated = format!("Bearer {rotated}");

    let response = send_post(
        &app,
        "/api/user/2fa/backup_codes",
        &rotated,
        &json!({"code": invalid_code(&secret, now())}),
    )
    .await;
    assert_business_error(response, "twofa.code_incorrect").await;
    assert_eq!(stored_auth_version(&db).await, 2);
    assert_eq!(active_code_hashes(&db).await.len(), 4);
    let response = send_post(
        &app,
        "/api/user/2fa/backup_codes",
        &rotated,
        &json!({"code": "12345"}),
    )
    .await;
    assert_business_error(response, "twofa.code_length").await;

    let response = send_post(
        &app,
        "/api/user/2fa/backup_codes",
        &rotated,
        &json!({"code": valid_code(&secret, now())}),
    )
    .await;
    let body = assert_success(response).await;
    assert_eq!(
        body["message"],
        json!(translated("twofa.backup_regenerated"))
    );
    let new_codes = assert_backup_codes(&body["data"]["backup_codes"]);
    for old in &old_codes {
        assert!(!new_codes.contains(old), "regeneration must replace codes");
    }
    assert_eq!(stored_auth_version(&db).await, 3);
    assert_eq!(active_code_hashes(&db).await.len(), 4);
    assert_eq!(total_code_rows(&db).await, 8, "old codes are soft-deleted");
    assert_eq!(
        repo.validate_backup_code(USER_ID, &old_codes[0], now())
            .await,
        Ok(false),
        "old backup codes must stop validating"
    );
    let fresh = format!(
        "Bearer {}",
        body["data"]["access_token"]
            .as_str()
            .expect("regeneration token")
    );
    let response = send(
        &app,
        Method::GET,
        "/api/user/2fa/status",
        Some(&rotated),
        None,
    )
    .await;
    assert_auth_failure(response, "AUTH_SESSION_REVOKED").await;
    let response = send(
        &app,
        Method::GET,
        "/api/user/2fa/status",
        Some(&fresh),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    // ---- disable with a backup code --------------------------------------
    reset(&db).await;
    seed_user(&db, 1, None).await;
    let at = now();
    seed_session(&db, "sid-twofa", 1, 1, at).await;
    let token = format!("Bearer {}", jwt("sid-twofa", 1, 1, at));
    let (secret, codes) = setup_pending(&app, &token).await;
    let (rotated, _) = enable_with(&app, &token, &secret).await;
    let rotated = format!("Bearer {rotated}");
    let response = send_post(
        &app,
        "/api/user/2fa/disable",
        &rotated,
        &json!({"code": codes[0]}),
    )
    .await;
    let body = assert_success(response).await;
    assert_eq!(body["message"], json!(translated("twofa.disable_success")));
    assert_eq!(factor_count(&db).await, 0);
    assert_eq!(total_code_rows(&db).await, 0);

    // ---- enable without a pending setup ----------------------------------
    reset(&db).await;
    seed_user(&db, 1, None).await;
    let at = now();
    seed_session(&db, "sid-twofa", 1, 1, at).await;
    let token = format!("Bearer {}", jwt("sid-twofa", 1, 1, at));
    let response = send_post(
        &app,
        "/api/user/2fa/enable",
        &token,
        &json!({"code": "123456"}),
    )
    .await;
    assert_business_error(response, "twofa.setup_required").await;

    // ---- business 200s still carry DisableCache for POSTs ---------------
    let response = send_post(
        &app,
        "/api/user/2fa/enable",
        &token,
        &json!({"code": "123456"}),
    )
    .await;
    assert_disable_cache(response.headers());
}

#[tokio::test]
async fn sqlite_twofa_routes_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    run_contract(Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn postgres_twofa_routes_contract() {
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
        "twofa_routes_{}_{}",
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
    run_contract(Database::Postgres(pool)).await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA \"{schema}\" CASCADE"
    )))
    .execute(&admin)
    .await
    .expect("drop isolated schema");
    admin.close().await;
}
