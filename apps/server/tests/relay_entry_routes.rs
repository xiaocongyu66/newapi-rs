//! HTTP contracts for the relay entry pipeline: full `TokenAuth`, the
//! `InsightClientBan` middleware, the `/v1` route group chain order, the
//! Distribute interception contract, and the `/v1/models` gate.
//!
//! Runs only in remote CI. Every scenario uses an isolated synthetic fixture
//! (in-memory SQLite or an isolated PostgreSQL schema); no service is started.
//! The PostgreSQL test is skipped when `TEST_POSTGRES_DSN` is absent.
//!
//! Go oracle:
//! - `apps/api/internal/security/authenticate.go:344-517` (`TokenAuth`)
//! - `apps/api/internal/transport/middleware/insight_client_ban.go`
//! - `apps/api/internal/usage/user_insight_client_ban.go:169-185` (CheckClientBan)
//! - `apps/api/internal/transport/compose/register_relay.go`
//! - `apps/api/internal/transport/httperr/abort.go` (OpenAI error envelope)

use std::sync::atomic::{AtomicU64, Ordering};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, StatusCode, header},
    response::Response,
};
use newapi_server::{AppState, relay_http};
use newapi_storage::Database;
use serde_json::Value;
use sqlx::{
    ConnectOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::SqlitePoolOptions,
};
use tower::ServiceExt;

static NEXT: AtomicU64 = AtomicU64::new(0);

const SECRET: &str = "relay-entry-routes-fixture-secret";
const USER_ID: i64 = 401;
const TOKEN_KEY: &str = "relayentrykey";

const USERS_SQLITE: &str = r#"CREATE TABLE users (
    id INTEGER PRIMARY KEY, username TEXT, display_name TEXT,
    role INTEGER, status INTEGER, email TEXT, github_id TEXT, discord_id TEXT,
    oidc_id TEXT, wechat_id TEXT, telegram_id TEXT, "group" TEXT,
    quota INTEGER, used_quota INTEGER, request_count INTEGER, aff_code TEXT,
    aff_count INTEGER, aff_quota INTEGER, aff_history INTEGER, inviter_id INTEGER,
    linux_do_id TEXT, setting TEXT, stripe_customer TEXT, auth_version INTEGER,
    access_token TEXT, password TEXT, remark TEXT, created_at BIGINT,
    last_login_at BIGINT, deleted_at TIMESTAMP
)"#;

const USERS_POSTGRES: &str = r#"CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY, username TEXT, display_name TEXT,
    role BIGINT, status BIGINT, email TEXT, github_id TEXT, discord_id TEXT,
    oidc_id TEXT, wechat_id TEXT, telegram_id TEXT, "group" TEXT,
    quota BIGINT, used_quota BIGINT, request_count BIGINT, aff_code TEXT,
    aff_count BIGINT, aff_quota BIGINT, aff_history BIGINT, inviter_id BIGINT,
    linux_do_id TEXT, setting TEXT, stripe_customer TEXT, auth_version BIGINT,
    access_token TEXT, password TEXT, remark TEXT, created_at BIGINT,
    last_login_at BIGINT, deleted_at TIMESTAMPTZ
)"#;

const TOKENS_SQLITE: &str = r#"CREATE TABLE tokens (
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
    status BIGINT NOT NULL DEFAULT 1,
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

const BANS: &str = r#"CREATE TABLE user_insight_client_bans (
    user_id BIGINT NOT NULL,
    client VARCHAR(64) NOT NULL,
    created_at BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, client)
)"#;

const OPTIONS: &str = r#"CREATE TABLE options (
    "key" TEXT PRIMARY KEY, "value" TEXT
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
    relay_http::relay_routes(state.clone()).with_state(state)
}

fn state(db: &Database) -> AppState {
    // TokenAuth + InsightClientBan 只触库；无 SessionAuth / Redis 限流。
    AppState::default().bind_runtime(db.clone(), SECRET)
}

fn translated(key: &str) -> String {
    newapi_i18n::translate("en", key, std::iter::empty::<(&str, &str)>())
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
            for statement in [USERS_SQLITE, TOKENS_SQLITE, BANS, OPTIONS] {
                exec(db, statement).await;
            }
        }
        Database::Postgres(_) => {
            for statement in [USERS_POSTGRES, TOKENS_POSTGRES, BANS, OPTIONS] {
                exec(db, statement).await;
            }
        }
    }
}

async fn reset(db: &Database) {
    for table in ["options", "user_insight_client_bans", "tokens", "users"] {
        backend!(db, pool, {
            sqlx::query(&format!("DELETE FROM {table}"))
                .execute(pool)
                .await
                .expect("reset table");
        });
    }
}

async fn seed_user(db: &Database, id: i64, status: i64, group: &str) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO users
                (id,username,display_name,role,status,"group",auth_version,access_token)
                VALUES ($1,$2,'Fixture',1,$3,$4,1,'')"#,
        )
        .bind(id)
        .bind(format!("user{id}"))
        .bind(status)
        .bind(group)
        .execute(pool)
        .await
        .expect("seed user");
    });
}

async fn seed_token(db: &Database, key: &str, group: &str, unlimited_quota: bool) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO tokens
                (user_id,"key",status,name,created_time,accessed_time,expired_time,
                 remain_quota,used_quota,unlimited_quota,model_limits_enabled,
                 model_limits,allow_ips,"group",cross_group_retry,auto_groups)
                VALUES ($1,$2,1,'fixture',1,1,-1,1000000,0,$3,FALSE,'','',$4,FALSE,'')"#,
        )
        .bind(USER_ID)
        .bind(key)
        .bind(unlimited_quota)
        .bind(group)
        .execute(pool)
        .await
        .expect("seed token");
    });
}

async fn set_option(db: &Database, key: &str, value: &str) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO options ("key", "value") VALUES ($1, $2)
               ON CONFLICT ("key") DO UPDATE SET "value" = EXCLUDED."value""#,
        )
        .bind(key)
        .bind(value)
        .execute(pool)
        .await
        .expect("seed option");
    });
}

async fn seed_user_ban(db: &Database, client: &str) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO user_insight_client_bans (user_id, client, created_at)
               VALUES ($1, $2, 1)"#,
        )
        .bind(USER_ID)
        .bind(client)
        .execute(pool)
        .await
        .expect("seed user ban");
    });
}

async fn send_relay(
    state: &AppState,
    path: &str,
    authorization: Option<&str>,
    user_agent: &str,
    body: &str,
) -> Response {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(value) = authorization {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    if !user_agent.is_empty() {
        builder = builder.header(header::USER_AGENT, user_agent);
    }
    router(state.clone())
        .oneshot(builder.body(Body::from(body.to_owned())).unwrap())
        .await
        .unwrap()
}

async fn send_get(state: &AppState, path: &str, authorization: Option<&str>) -> Response {
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

fn valid_auth() -> Option<String> {
    Some(format!("Bearer sk-{TOKEN_KEY}"))
}

async fn run_contract(db: &Database) {
    create_schema(db).await;
    reset(db).await;

    // ── 缺少凭据：401 + OpenAI 信封（Go abortWithOpenAiMessage）──────────
    let response = send_relay(&state(db), "/v1/chat/completions", None, "", "{}").await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = body_json(response).await;
    assert_eq!(body["error"]["type"], "new_api_error");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains(&translated("token.invalid"))
    );

    // ── 无效令牌：401 ────────────────────────────────────────────────────
    let response = send_relay(
        &state(db),
        "/v1/chat/completions",
        Some("Bearer sk-nonexistent"),
        "",
        "{}",
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = body_json(response).await;
    assert_eq!(body["error"]["type"], "new_api_error");

    // ── 用户被禁用：403 auth.user_banned ────────────────────────────────
    seed_user(db, USER_ID, 2, "default").await;
    seed_token(db, TOKEN_KEY, "", true).await;
    let response = send_relay(
        &state(db),
        "/v1/chat/completions",
        valid_auth().as_deref(),
        "",
        "{}",
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = body_json(response).await;
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains(&translated("auth.user_banned"))
    );
    exec(db, "DELETE FROM users").await;

    // ── 分组门：令牌指定分组不在可用列表 → 403 ──────────────────────────
    seed_user(db, USER_ID, 1, "default").await;
    seed_token(db, TOKEN_KEY, "vip", true).await;
    let response = send_relay(
        &state(db),
        "/v1/chat/completions",
        valid_auth().as_deref(),
        "",
        "{}",
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = body_json(response).await;
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("无权访问 vip 分组")
    );
    exec(db, "DELETE FROM tokens").await;

    // ── 有效链路：TokenAuth → Ban → handler，Distribute 拦截契约 503 ────
    seed_token(db, TOKEN_KEY, "", true).await;
    let response = send_relay(
        &state(db),
        "/v1/chat/completions",
        valid_auth().as_deref(),
        "",
        r#"{"model":"gpt-4","messages":[]}"#,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = body_json(response).await;
    assert_eq!(body["error"]["code"], "model_not_found");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("No available channel for model gpt-4 under group default")
    );

    // ── InsightClientBan：总开关关闭时放行（走到 Distribute 契约）────────
    set_option(db, "user_insight_setting.client_ban_enabled", "false").await;
    set_option(db, "user_insight_setting.blocked_clients", r#"["curl"]"#).await;
    let response = send_relay(
        &state(db),
        "/v1/chat/completions",
        valid_auth().as_deref(),
        "curl/8.1.0",
        r#"{"model":"gpt-4"}"#,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    // ── 全局封禁：识别为 curl → 403（封禁的代价为零，不进渠道分发）──────
    set_option(db, "user_insight_setting.client_ban_enabled", "true").await;
    let response = send_relay(
        &state(db),
        "/v1/chat/completions",
        valid_auth().as_deref(),
        "curl/8.1.0",
        r#"{"model":"gpt-4"}"#,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = body_json(response).await;
    assert_eq!(body["error"]["message"], "您使用的客户端已被站点管理员封禁");

    // ── 单用户封禁：换其它客户端仍可用 ───────────────────────────────────
    set_option(db, "user_insight_setting.blocked_clients", "[]").await;
    seed_user_ban(db, "okhttp").await;
    let response = send_relay(
        &state(db),
        "/v1/chat/completions",
        valid_auth().as_deref(),
        "okhttp/4.12.0",
        r#"{"model":"gpt-4"}"#,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = body_json(response).await;
    assert_eq!(body["error"]["message"], "该客户端已被管理员对您的账号禁用");
    exec(db, "DELETE FROM user_insight_client_bans").await;

    // 识别不出客户端（空 UA）时不封。
    let response = send_relay(
        &state(db),
        "/v1/chat/completions",
        valid_auth().as_deref(),
        "",
        r#"{"model":"gpt-4"}"#,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    // ── /v1/models：仅 TokenAuth；封禁中间件不在该组 ─────────────────────
    set_option(db, "user_insight_setting.client_ban_enabled", "true").await;
    set_option(db, "user_insight_setting.blocked_clients", r#"["curl"]"#).await;
    let response = send_get(&state(db), "/v1/models", None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    // 封禁开关开着、UA 是 curl，但 models 组不挂 Ban → 200。
    let response = send_get(&state(db), "/v1/models", valid_auth().as_deref()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], true);
    assert_eq!(body["object"], "list");

    // ── 令牌状态非启用 → 401（Go ValidateUserToken）─────────────────────
    exec(db, "DELETE FROM tokens").await;
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO tokens
                (user_id,"key",status,name,created_time,accessed_time,expired_time,
                 remain_quota,used_quota,unlimited_quota,model_limits_enabled,
                 model_limits,allow_ips,"group",cross_group_retry,auto_groups)
                VALUES ($1,$2,2,'fixture',1,1,-1,1000000,0,TRUE,FALSE,'','',$3,FALSE,'')"#,
        )
        .bind(USER_ID)
        .bind(TOKEN_KEY)
        .bind("")
        .execute(pool)
        .await
        .expect("seed disabled token");
    });
    let response = send_relay(
        &state(db),
        "/v1/chat/completions",
        valid_auth().as_deref(),
        "",
        "{}",
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    reset(db).await;
}

#[tokio::test]
async fn sqlite_relay_entry_routes_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    run_contract(&Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn postgres_relay_entry_routes_contract() {
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
        "relay_entry_routes_{}_{}",
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
    run_contract(&Database::Postgres(pool)).await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA \"{schema}\" CASCADE"
    )))
    .execute(&admin)
    .await
    .expect("drop isolated schema");
}
