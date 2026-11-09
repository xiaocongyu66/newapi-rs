//! HTTP contracts for `TokenAuthReadOnly` and its two read-only routes:
//! `GET /api/log/token` and `GET /api/usage/token/`.
//!
//! Runs only in remote CI. Every scenario uses an isolated synthetic fixture
//! (in-memory SQLite or an isolated PostgreSQL schema); no service is started.
//! The PostgreSQL test is skipped when `TEST_POSTGRES_DSN` is absent.
//!
//! Go semantics notes (oracle: `apps/api/internal/security/authenticate.go`):
//! - The middleware validates only that the token key exists; status (except
//!   explicit disable), expiry and quota never block the request.
//! - Failure bodies carry `success` + `message` only (no `code`), because Go
//!   uses `c.JSON` instead of `writeDashboardAuthError`.
//! - `handler.GetLogByKey` never checks that the queried `token_id` belongs to
//!   the authenticated token; `GetTokenUsage` re-parses the Authorization
//!   header itself and accepts only an exact two-segment Bearer pair.

use std::sync::atomic::{AtomicU64, Ordering};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::Request,
    http::{Method, StatusCode, header},
    middleware,
    response::Response,
    routing::get,
};
use newapi_server::{AppState, auth::token_auth_read_only, readonly_http};
use newapi_storage::Database;
use serde_json::Value;
use sqlx::{
    ConnectOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::SqlitePoolOptions,
};
use tower::ServiceExt;

static NEXT: AtomicU64 = AtomicU64::new(0);

const SECRET: &str = "readonly-token-routes-fixture-secret";
const USER_ID: i64 = 201;

const SQLITE_USERS: &str = r#"CREATE TABLE users (
    id BIGINT PRIMARY KEY, username TEXT, display_name TEXT,
    role BIGINT, status BIGINT, email TEXT, github_id TEXT, discord_id TEXT,
    oidc_id TEXT, wechat_id TEXT, telegram_id TEXT, "group" TEXT,
    quota BIGINT, used_quota BIGINT, request_count BIGINT, aff_code TEXT,
    aff_count BIGINT, aff_quota BIGINT, aff_history BIGINT, inviter_id BIGINT,
    linux_do_id TEXT, setting TEXT, stripe_customer TEXT, auth_version BIGINT,
    access_token TEXT, deleted_at TIMESTAMP
)"#;

const POSTGRES_USERS: &str = SQLITE_USERS;

const SQLITE_TOKENS: &str = r#"CREATE TABLE tokens (
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

const POSTGRES_TOKENS: &str = r#"CREATE TABLE tokens (
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
    unlimited_quota BOOLEAN NOT NULL DEFAULT FALSE,
    model_limits_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    model_limits TEXT NOT NULL DEFAULT '',
    allow_ips TEXT,
    "group" TEXT NOT NULL DEFAULT '',
    cross_group_retry BOOLEAN NOT NULL DEFAULT FALSE,
    auto_groups TEXT NOT NULL DEFAULT '',
    deleted_at TIMESTAMP
)"#;

const SQLITE_LOGS: &str = r#"CREATE TABLE logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL DEFAULT 0,
    type INTEGER NOT NULL DEFAULT 0,
    content TEXT NOT NULL DEFAULT '',
    username TEXT NOT NULL DEFAULT '',
    token_name TEXT NOT NULL DEFAULT '',
    model_name TEXT NOT NULL DEFAULT '',
    quota INTEGER NOT NULL DEFAULT 0,
    prompt_tokens INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    use_time INTEGER NOT NULL DEFAULT 0,
    is_stream INTEGER NOT NULL DEFAULT 0,
    channel_id INTEGER NOT NULL DEFAULT 0,
    channel_name TEXT NOT NULL DEFAULT '',
    token_id INTEGER NOT NULL DEFAULT 0,
    "group" TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    request_id TEXT NOT NULL DEFAULT '',
    upstream_request_id TEXT NOT NULL DEFAULT '',
    other TEXT NOT NULL DEFAULT ''
)"#;

const POSTGRES_LOGS: &str = r#"CREATE TABLE logs (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL DEFAULT 0,
    type BIGINT NOT NULL DEFAULT 0,
    content TEXT NOT NULL DEFAULT '',
    username TEXT NOT NULL DEFAULT '',
    token_name TEXT NOT NULL DEFAULT '',
    model_name TEXT NOT NULL DEFAULT '',
    quota BIGINT NOT NULL DEFAULT 0,
    prompt_tokens BIGINT NOT NULL DEFAULT 0,
    completion_tokens BIGINT NOT NULL DEFAULT 0,
    use_time BIGINT NOT NULL DEFAULT 0,
    is_stream BOOLEAN NOT NULL DEFAULT FALSE,
    channel_id BIGINT NOT NULL DEFAULT 0,
    channel_name TEXT NOT NULL DEFAULT '',
    token_id BIGINT NOT NULL DEFAULT 0,
    "group" TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    request_id TEXT NOT NULL DEFAULT '',
    upstream_request_id TEXT NOT NULL DEFAULT '',
    other TEXT NOT NULL DEFAULT ''
)"#;

macro_rules! backend {
    ($db:expr, $pool:ident, $body:block) => {
        match $db {
            Database::Sqlite($pool) => $body,
            Database::Postgres($pool) => $body,
        }
    };
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/log/token", get(readonly_http::log_by_token))
        .route("/api/usage/token/", get(readonly_http::token_usage))
        .route("/api/usage/token", get(readonly_http::token_usage))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            token_auth_read_only,
        ))
        .with_state(state)
}

fn state(db: &Database) -> AppState {
    // Token lookup and user projection only touch the database; no SessionAuth
    // and no rate limiter are bound.
    AppState::default().bind_runtime(db.clone(), SECRET)
}

async fn exec(db: &Database, statement: &'static str) {
    backend!(db, pool, {
        sqlx::query(statement)
            .execute(pool)
            .await
            .expect("fixture statement");
    });
}

async fn setup(db: &Database) {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query(SQLITE_USERS)
                .execute(pool)
                .await
                .expect("users");
            sqlx::query(SQLITE_TOKENS)
                .execute(pool)
                .await
                .expect("tokens");
            sqlx::query(SQLITE_LOGS).execute(pool).await.expect("logs");
        }
        Database::Postgres(pool) => {
            sqlx::query(POSTGRES_USERS)
                .execute(pool)
                .await
                .expect("users");
            sqlx::query(POSTGRES_TOKENS)
                .execute(pool)
                .await
                .expect("tokens");
            sqlx::query(POSTGRES_LOGS)
                .execute(pool)
                .await
                .expect("logs");
        }
    }
}

async fn reset(db: &Database) {
    exec(db, "DELETE FROM logs").await;
    exec(db, "DELETE FROM tokens").await;
    exec(db, "DELETE FROM users").await;
}

async fn seed_user(db: &Database, id: i64, status: i64) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO users
                (id,username,display_name,role,status,"group",auth_version,access_token)
                VALUES ($1,$2,'Fixture',1,$3,'default',1,'')"#,
        )
        .bind(id)
        .bind(format!("user{id}"))
        .bind(status)
        .execute(pool)
        .await
        .expect("seed user");
    });
}

struct TokenSeed<'a> {
    user_id: i64,
    key: &'a str,
    name: &'a str,
    status: i64,
    expired_time: i64,
    remain_quota: i64,
    used_quota: i64,
    unlimited_quota: bool,
    model_limits: &'a str,
    model_limits_enabled: bool,
}

async fn seed_token(db: &Database, seed: &TokenSeed<'_>) -> i64 {
    backend!(db, pool, {
        sqlx::query_scalar::<_, i64>(
            r#"INSERT INTO tokens
                (user_id,"key",status,name,created_time,accessed_time,expired_time,
                 remain_quota,used_quota,unlimited_quota,model_limits_enabled,
                 model_limits,allow_ips,"group",cross_group_retry,auto_groups)
                VALUES ($1,$2,$3,$4,1,1,$5,$6,$7,$8,$9,$10,'','default',FALSE,'')
                RETURNING CAST(id AS BIGINT)"#,
        )
        .bind(seed.user_id)
        .bind(seed.key)
        .bind(seed.status)
        .bind(seed.name)
        .bind(seed.expired_time)
        .bind(seed.remain_quota)
        .bind(seed.used_quota)
        .bind(seed.unlimited_quota)
        .bind(seed.model_limits_enabled)
        .bind(seed.model_limits)
        .fetch_one(pool)
        .await
        .expect("seed token")
    })
}

struct LogSeed<'a> {
    user_id: i64,
    created_at: i64,
    log_type: i64,
    content: &'a str,
    model_name: &'a str,
    quota: i64,
    is_stream: bool,
    channel_id: i64,
    channel_name: &'a str,
    token_id: i64,
    ip: &'a str,
    request_id: &'a str,
    upstream_request_id: &'a str,
}

async fn seed_log(db: &Database, seed: &LogSeed<'_>) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO logs
                (user_id,created_at,type,content,username,token_name,model_name,quota,
                 prompt_tokens,completion_tokens,use_time,is_stream,channel_id,
                 channel_name,token_id,"group",ip,request_id,upstream_request_id,other)
                VALUES ($1,$2,$3,$4,'fixture','fixture',$5,$6,7,11,13,$7,$8,$9,$10,
                        'default',$11,$12,$13,'{}')"#,
        )
        .bind(seed.user_id)
        .bind(seed.created_at)
        .bind(seed.log_type)
        .bind(seed.content)
        .bind(seed.model_name)
        .bind(seed.quota)
        .bind(seed.is_stream)
        .bind(seed.channel_id)
        .bind(seed.channel_name)
        .bind(seed.token_id)
        .bind(seed.ip)
        .bind(seed.request_id)
        .bind(seed.upstream_request_id)
        .execute(pool)
        .await
        .expect("seed log");
    });
}

async fn send(state: &AppState, path: &str, authorization: Option<&str>) -> Response {
    let mut builder = Request::builder().method(Method::GET).uri(path);
    if let Some(value) = authorization {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    router(state.clone())
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap()
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

/// Middleware failures carry `success` + `message` only; assert both the fixed
/// pair and the absence of Go's dashboard `code` field.
async fn assert_readonly_failure(response: Response, status: StatusCode, message_key: &str) {
    assert_eq!(response.status(), status);
    let body = body_json(response).await;
    assert_eq!(body["success"], serde_json::json!(false));
    assert_eq!(body["message"], serde_json::json!(translated(message_key)));
    assert_eq!(
        body.get("code"),
        None,
        "TokenAuthReadOnly failures have no code"
    );
}

async fn run_contract(db: &Database) {
    setup(db).await;

    // --- TokenAuthReadOnly 分支顺序（Go authenticate.go:271-342） ---

    // Missing header (authenticate.go:273-281): 401 token.not_provided.
    let response = send(&state(db), "/api/log/token", None).await;
    assert_readonly_failure(response, StatusCode::UNAUTHORIZED, "token.not_provided").await;

    // Empty header is Go's `key == ""` check: same branch.
    let response = send(&state(db), "/api/log/token", Some("")).await;
    assert_readonly_failure(response, StatusCode::UNAUTHORIZED, "token.not_provided").await;

    // Unknown key (authenticate.go:291-295): 401 token.invalid.
    let response = send(&state(db), "/api/log/token", Some("Bearer nope")).await;
    assert_readonly_failure(response, StatusCode::UNAUTHORIZED, "token.invalid").await;

    // Key rules (authenticate.go:282-287): the sk- prefix and the part before
    // the first `-` are both stripped, and a raw key without Bearer is
    // accepted. The log endpoint itself never re-parses the header, so
    // reaching its handler proves the middleware let the key through.
    reset(db).await;
    seed_user(db, USER_ID, 1).await;
    let token = seed_token(
        db,
        &TokenSeed {
            user_id: USER_ID,
            key: "ro-abc",
            name: "readonly",
            status: 1,
            expired_time: -1,
            remain_quota: 0,
            used_quota: 0,
            unlimited_quota: true,
            model_limits: "",
            model_limits_enabled: false,
        },
    )
    .await;
    for header in [
        "ro-abc",
        "sk-ro-abc",
        "ro-abc-123",
        "sk-ro-abc-123",
        "Bearer ro-abc",
        "bearer ro-abc",
        "Bearer sk-ro-abc-def",
    ] {
        let response = send(
            &state(db),
            &format!("/api/log/token?token_id={token}"),
            Some(header),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "key rule header `{header}` must reach the handler"
        );
        let body = body_json(response).await;
        assert_eq!(body["success"], serde_json::json!(true));
    }

    // A key that still carries a `-` (i.e. the stored key really contains one)
    // resolves to the pre-dash segment and misses: 401 token.invalid.
    let response = send(&state(db), "/api/log/token", Some("Bearer ro-abc-")).await;
    assert_readonly_failure(response, StatusCode::UNAUTHORIZED, "token.invalid").await;

    // Explicitly disabled (status 2, authenticate.go:309-316): 401.
    reset(db).await;
    seed_user(db, USER_ID, 1).await;
    seed_token(
        db,
        &TokenSeed {
            user_id: USER_ID,
            key: "disabled-key",
            name: "disabled",
            status: 2,
            expired_time: -1,
            remain_quota: 0,
            used_quota: 0,
            unlimited_quota: true,
            model_limits: "",
            model_limits_enabled: false,
        },
    )
    .await;
    let response = send(&state(db), "/api/log/token", Some("Bearer disabled-key")).await;
    assert_readonly_failure(
        response,
        StatusCode::UNAUTHORIZED,
        "token.status_unavailable",
    )
    .await;

    // Expired (status 3) and exhausted (status 4) tokens stay readable: this is
    // the whole point of the read-only variant (authenticate.go:307-308).
    for status in [3i64, 4] {
        reset(db).await;
        seed_user(db, USER_ID, 1).await;
        seed_token(
            db,
            &TokenSeed {
                user_id: USER_ID,
                key: "stale-key",
                name: "stale",
                status,
                expired_time: 1,
                remain_quota: 0,
                used_quota: 1,
                unlimited_quota: false,
                model_limits: "",
                model_limits_enabled: false,
            },
        )
        .await;
        let response = send(&state(db), "/api/usage/token/", Some("Bearer stale-key")).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["code"], serde_json::json!(true));
        assert_eq!(body["data"]["total_available"], serde_json::json!(0));
    }

    // Banned user (authenticate.go:328-335): 403 auth.user_banned.
    reset(db).await;
    seed_user(db, USER_ID, 2).await;
    seed_token(
        db,
        &TokenSeed {
            user_id: USER_ID,
            key: "banned-key",
            name: "banned",
            status: 1,
            expired_time: -1,
            remain_quota: 0,
            used_quota: 0,
            unlimited_quota: true,
            model_limits: "",
            model_limits_enabled: false,
        },
    )
    .await;
    let response = send(&state(db), "/api/log/token", Some("Bearer banned-key")).await;
    assert_readonly_failure(response, StatusCode::FORBIDDEN, "auth.user_banned").await;
    // The middleware rejects before the usage handler runs.
    let response = send(&state(db), "/api/usage/token/", Some("Bearer banned-key")).await;
    assert_readonly_failure(response, StatusCode::FORBIDDEN, "auth.user_banned").await;

    // User vanished (authenticate.go:318-327 maps every GetUserCache error to
    // 500, and a missing user is an error there): 500 database_error.
    reset(db).await;
    seed_token(
        db,
        &TokenSeed {
            user_id: 9999,
            key: "orphan-key",
            name: "orphan",
            status: 1,
            expired_time: -1,
            remain_quota: 0,
            used_quota: 0,
            unlimited_quota: true,
            model_limits: "",
            model_limits_enabled: false,
        },
    )
    .await;
    let response = send(&state(db), "/api/log/token", Some("Bearer orphan-key")).await;
    assert_readonly_failure(
        response,
        StatusCode::INTERNAL_SERVER_ERROR,
        "common.database_error",
    )
    .await;

    // Soft-deleted tokens are invisible (GORM default scope in by_key).
    reset(db).await;
    seed_user(db, USER_ID, 1).await;
    seed_token(
        db,
        &TokenSeed {
            user_id: USER_ID,
            key: "gone-key",
            name: "gone",
            status: 1,
            expired_time: -1,
            remain_quota: 0,
            used_quota: 0,
            unlimited_quota: true,
            model_limits: "",
            model_limits_enabled: false,
        },
    )
    .await;
    exec(
        db,
        "UPDATE tokens SET deleted_at=CURRENT_TIMESTAMP WHERE \"key\"='gone-key'",
    )
    .await;
    let response = send(&state(db), "/api/log/token", Some("Bearer gone-key")).await;
    assert_readonly_failure(response, StatusCode::UNAUTHORIZED, "token.invalid").await;

    // --- handler.GetLogByKey (handle_logs.go:68-89) ---

    reset(db).await;
    seed_user(db, USER_ID, 1).await;
    let log_token = seed_token(
        db,
        &TokenSeed {
            user_id: USER_ID,
            key: "log-key",
            name: "logs",
            status: 1,
            expired_time: -1,
            remain_quota: 0,
            used_quota: 0,
            unlimited_quota: true,
            model_limits: "",
            model_limits_enabled: false,
        },
    )
    .await;
    let other_token = seed_token(
        db,
        &TokenSeed {
            user_id: USER_ID,
            key: "other-key",
            name: "other",
            status: 1,
            expired_time: -1,
            remain_quota: 0,
            used_quota: 0,
            unlimited_quota: true,
            model_limits: "",
            model_limits_enabled: false,
        },
    )
    .await;

    // Missing or non-numeric token_id: 400 with Go's fixed literal message.
    for path in [
        "/api/log/token",
        "/api/log/token?token_id=",
        "/api/log/token?token_id=abc",
    ] {
        let response = send(&state(db), path, Some("Bearer log-key")).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = body_json(response).await;
        assert_eq!(body["success"], serde_json::json!(false));
        assert_eq!(body["message"], serde_json::json!("invalid token id"));
    }

    seed_log(
        db,
        &LogSeed {
            user_id: USER_ID,
            created_at: 100,
            log_type: 2,
            content: "first",
            model_name: "gpt-4",
            quota: 1_000_000,
            is_stream: true,
            channel_id: 5,
            channel_name: "ch",
            token_id: log_token,
            ip: "1.2.3.4",
            request_id: "",
            upstream_request_id: "",
        },
    )
    .await;
    seed_log(
        db,
        &LogSeed {
            user_id: USER_ID,
            created_at: 200,
            log_type: 2,
            content: "second",
            model_name: "gpt-3.5",
            quota: 500_000,
            is_stream: false,
            channel_id: 6,
            channel_name: "",
            token_id: log_token,
            ip: "",
            request_id: "req-1",
            upstream_request_id: "up-1",
        },
    )
    .await;
    // Belongs to the other token: must not appear.
    seed_log(
        db,
        &LogSeed {
            user_id: USER_ID,
            created_at: 300,
            log_type: 2,
            content: "other token",
            model_name: "gpt-4",
            quota: 1,
            is_stream: false,
            channel_id: 1,
            channel_name: "",
            token_id: other_token,
            ip: "",
            request_id: "req-2",
            upstream_request_id: "",
        },
    )
    .await;

    let response = send(
        &state(db),
        &format!("/api/log/token?token_id={log_token}"),
        Some("Bearer log-key"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], serde_json::json!(true));
    let data = body["data"].as_array().expect("log array");
    assert_eq!(data.len(), 2, "Token facts are scoped by token_id");
    // GORM `Order("id desc")`.
    assert_eq!(data[0]["content"], serde_json::json!("second"));
    assert_eq!(data[1]["content"], serde_json::json!("first"));
    let entry = &data[0];
    assert_eq!(entry["id"], serde_json::json!(2));
    assert_eq!(entry["user_id"], serde_json::json!(USER_ID));
    assert_eq!(entry["created_at"], serde_json::json!(200));
    assert_eq!(entry["type"], serde_json::json!(2));
    assert_eq!(entry["model_name"], serde_json::json!("gpt-3.5"));
    assert_eq!(entry["quota"], serde_json::json!(500_000));
    // quota_display = quota / QuotaPerUnit (500000 by default).
    assert_eq!(entry["quota_display"], serde_json::json!(1.0));
    assert_eq!(entry["prompt_tokens"], serde_json::json!(7));
    assert_eq!(entry["completion_tokens"], serde_json::json!(11));
    assert_eq!(entry["use_time"], serde_json::json!(13));
    assert_eq!(entry["is_stream"], serde_json::json!(false));
    assert_eq!(
        entry["channel"],
        serde_json::json!(6),
        "ChannelId is `channel`"
    );
    assert_eq!(entry["channel_name"], serde_json::json!(""));
    assert_eq!(entry["token_id"], serde_json::json!(log_token));
    assert_eq!(entry["group"], serde_json::json!("default"));
    assert_eq!(entry["request_id"], serde_json::json!("req-1"));
    assert_eq!(entry["upstream_request_id"], serde_json::json!("up-1"));
    assert_eq!(entry["other"], serde_json::json!("{}"));
    // Go's omitempty: empty request ids drop the keys entirely.
    assert_eq!(
        data[1].get("request_id"),
        None,
        "empty request_id is omitted"
    );
    assert_eq!(
        data[1].get("upstream_request_id"),
        None,
        "empty upstream_request_id is omitted"
    );
    assert_eq!(data[1]["is_stream"], serde_json::json!(true));
    assert_eq!(data[1]["quota_display"], serde_json::json!(2.0));
    assert_eq!(data[1]["channel"], serde_json::json!(5));

    // A token id without rows is 200 + empty array, not an error.
    let response = send(
        &state(db),
        &format!("/api/log/token?token_id={other_token}"),
        Some("Bearer log-key"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], serde_json::json!(true));
    assert_eq!(body["data"], serde_json::json!([]));

    // --- identity.GetTokenUsage (manage_tokens.go:196-243) ---

    reset(db).await;
    seed_user(db, USER_ID, 1).await;
    seed_token(
        db,
        &TokenSeed {
            user_id: USER_ID,
            key: "usage-key",
            name: "usage",
            status: 1,
            expired_time: -1,
            remain_quota: 300_000,
            used_quota: 200_000,
            unlimited_quota: false,
            model_limits: "gpt-4,gpt-3.5",
            model_limits_enabled: true,
        },
    )
    .await;
    // Under Go's route the trailing slash exists; both spellings behave alike.
    for path in ["/api/usage/token/", "/api/usage/token"] {
        let response = send(&state(db), path, Some("Bearer usage-key")).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["code"], serde_json::json!(true));
        assert_eq!(body["message"], serde_json::json!("ok"));
        let data = &body["data"];
        assert_eq!(data["object"], serde_json::json!("token_usage"));
        assert_eq!(data["name"], serde_json::json!("usage"));
        assert_eq!(data["total_granted"], serde_json::json!(500_000));
        assert_eq!(data["total_used"], serde_json::json!(200_000));
        assert_eq!(data["total_available"], serde_json::json!(300_000));
        assert_eq!(data["unlimited_quota"], serde_json::json!(false));
        // Go marshals the map with sorted keys.
        assert_eq!(
            data["model_limits"],
            serde_json::json!({"gpt-3.5": true, "gpt-4": true})
        );
        assert_eq!(data["model_limits_enabled"], serde_json::json!(true));
        // expired_time -1 is rendered as 0 (manage_tokens.go:223-226).
        assert_eq!(data["expires_at"], serde_json::json!(0));
    }

    // A concrete expiry is rendered as-is; the sk- prefix is stripped once.
    reset(db).await;
    seed_user(db, USER_ID, 1).await;
    seed_token(
        db,
        &TokenSeed {
            user_id: USER_ID,
            key: "expiry-key",
            name: "expiry",
            status: 1,
            expired_time: 123,
            remain_quota: 0,
            used_quota: 0,
            unlimited_quota: true,
            model_limits: "",
            model_limits_enabled: false,
        },
    )
    .await;
    let response = send(
        &state(db),
        "/api/usage/token/",
        Some("Bearer sk-expiry-key"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["data"]["expires_at"], serde_json::json!(123));
    assert_eq!(body["data"]["model_limits"], serde_json::json!({}));
    assert_eq!(body["data"]["unlimited_quota"], serde_json::json!(true));

    // handler re-parses Authorization (manage_tokens.go:197-213): exactly one
    // space-separated Bearer pair. Wrong segment counts are 401 even though
    // the middleware already accepted the key.
    reset(db).await;
    seed_user(db, USER_ID, 1).await;
    seed_token(
        db,
        &TokenSeed {
            user_id: USER_ID,
            key: "pair-key",
            name: "pair",
            status: 1,
            expired_time: -1,
            remain_quota: 0,
            used_quota: 0,
            unlimited_quota: true,
            model_limits: "",
            model_limits_enabled: false,
        },
    )
    .await;
    for header in ["pair-key", "Bearer  pair-key", "Bearer pair-key third"] {
        let response = send(&state(db), "/api/usage/token/", Some(header)).await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "header `{header}`"
        );
        let body = body_json(response).await;
        assert_eq!(body["success"], serde_json::json!(false));
        assert_eq!(
            body["message"],
            serde_json::json!("Invalid Bearer token"),
            "handler rejects the non-pair header `{header}`",
        );
    }
    // The scheme check is case-insensitive: BEARER/bearer both reach the token.
    for header in ["BEARER pair-key", "bearer pair-key"] {
        let response = send(&state(db), "/api/usage/token/", Some(header)).await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "case-insensitive header `{header}`"
        );
        let body = body_json(response).await;
        assert_eq!(body["code"], serde_json::json!(true));
        assert_eq!(body["data"]["name"], serde_json::json!("pair"));
    }
    // Unknown key: 200 + translated token.get_info_failed (CtxApiErrorI18n).
    let response = send(&state(db), "/api/usage/token/", Some("Bearer unknown-key")).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], serde_json::json!(false));
    assert_eq!(
        body["message"],
        serde_json::json!(translated("token.get_info_failed"))
    );
    assert_eq!(body.get("code"), None, "no code on this Go failure branch");

    reset(db).await;
}

#[tokio::test]
async fn sqlite_readonly_token_routes_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    run_contract(Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn postgres_readonly_token_routes_contract() {
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
        "readonly_token_routes_{}_{}",
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
}
