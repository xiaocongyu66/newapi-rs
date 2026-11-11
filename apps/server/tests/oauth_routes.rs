//! HTTP contracts for the eight OAuth login/bind routes:
//! `POST /api/oauth/state`, `GET /api/oauth/:provider`,
//! `GET /api/oauth/wechat`, `POST /api/oauth/wechat/bind`,
//! `POST /api/oauth/email/bind`, `POST /api/oauth/telegram/bind/start`,
//! `GET /api/oauth/telegram/bind/:flow_token`,
//! `GET /api/oauth/telegram/login`.
//!
//! Runs only in remote CI. Every scenario uses an isolated synthetic fixture
//! (in-memory SQLite or an isolated PostgreSQL schema). The PostgreSQL tests
//! are skipped when `TEST_POSTGRES_DSN` is absent.
//!
//! Go references:
//! - `apps/api/internal/transport/handler/handle_oauth.go` (state + callback)
//! - `apps/api/internal/identity/bind_wechat.go` / `bind_telegram.go`
//! - `apps/api/internal/identity/manage_users.go` (`EmailBind`)
//! - `apps/api/internal/transport/compose/register_api.go:103-112` (chains)
//! - `apps/api/internal/identity/run_authflow.go` (purposes, assertion replay)
//! - `apps/api/internal/identity/claim_external_identity.go`
//!
//! Outbound HTTP (provider token/userinfo, WeChat server) is injected through
//! `oauth_http::InjectedOAuthTransport` — the same seam as `turnstile` and
//! `qqbot`. Signing fixtures for Telegram recompute the HMAC with SHA256(bot
//! token) exactly like the widget does.

use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
    middleware,
    response::Response,
};
use newapi_config::SessionCookieSettings;
use newapi_identity::{
    AuthIdentity,
    auth_session::{AuthFence, SessionAuth},
    crypto::AuthKeys,
    oauth_flow::providers::{
        OutboundError, OutboundFuture, OutboundRequest, OutboundResponse, OutboundTransport,
    },
    sessions::NoCache,
};
use newapi_server::{
    AppState,
    auth::{try_user_auth, user_auth},
    oauth_http::{
        ClientIp, InjectedOAuthTransport, email_bind, handle_provider, oauth_state, telegram_bind,
        telegram_bind_start, telegram_login, wechat_bind, wechat_login,
    },
};
use newapi_storage::Database;
use serde_json::{Value, json};
use sqlx::{
    ConnectOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::SqlitePoolOptions,
};
use std::sync::atomic::{AtomicU64, Ordering};
use tower::ServiceExt;

static NEXT: AtomicU64 = AtomicU64::new(0);

const SECRET: &str = "oauth-routes-fixture-secret";
const USER_ID: i64 = 7;
const PAT: &str = "pat-oauth";

// ---------------------------------------------------------------------------
// Fixture schema（各仓储实际读写的最小列集；类型沿用 Go 旧库）
// ---------------------------------------------------------------------------

const USERS: &str = r#"CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL,
    password TEXT NOT NULL DEFAULT '', display_name TEXT,
    role BIGINT, status INTEGER, email TEXT, github_id TEXT, discord_id TEXT,
    oidc_id TEXT, wechat_id TEXT, telegram_id TEXT, "group" TEXT,
    quota BIGINT, used_quota BIGINT, request_count BIGINT, aff_code TEXT,
    aff_count BIGINT, aff_quota BIGINT, aff_history BIGINT, inviter_id BIGINT,
    linux_do_id TEXT, setting TEXT, remark VARCHAR(255), stripe_customer TEXT,
    created_at BIGINT, last_login_at BIGINT, auth_version BIGINT,
    access_token TEXT, deleted_at TIMESTAMP
)"#;

const USERS_PG: &str = r#"CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY, username TEXT NOT NULL, password TEXT NOT NULL DEFAULT '',
    display_name TEXT,
    role BIGINT, status INTEGER, email TEXT, github_id TEXT, discord_id TEXT,
    oidc_id TEXT, wechat_id TEXT, telegram_id TEXT, "group" TEXT,
    quota BIGINT, used_quota BIGINT, request_count BIGINT, aff_code TEXT,
    aff_count BIGINT, aff_quota BIGINT, aff_history BIGINT, inviter_id BIGINT,
    linux_do_id TEXT, setting TEXT, remark VARCHAR(255), stripe_customer TEXT,
    created_at BIGINT, last_login_at BIGINT, auth_version BIGINT,
    access_token TEXT, deleted_at TIMESTAMP
)"#;

fn users_ddl(db: &Database) -> &'static str {
    match db {
        Database::Sqlite(_) => USERS,
        Database::Postgres(_) => USERS_PG,
    }
}

const OPTIONS: &str = r#"CREATE TABLE options ("key" TEXT PRIMARY KEY, "value" TEXT)"#;

const AUTH_FLOWS: &str = r#"CREATE TABLE auth_flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT, token_hash CHAR(64) NOT NULL UNIQUE,
    purpose VARCHAR(32) NOT NULL, provider VARCHAR(64), intent VARCHAR(16),
    user_id BIGINT, session_id VARCHAR(64), payload TEXT,
    expires_at DATETIME NOT NULL, consumed_at DATETIME, created_at DATETIME
)"#;

const AUTH_FLOWS_PG: &str = r#"CREATE TABLE auth_flows (
    id BIGSERIAL PRIMARY KEY, token_hash CHAR(64) NOT NULL UNIQUE,
    purpose VARCHAR(32) NOT NULL, provider VARCHAR(64), intent VARCHAR(16),
    user_id BIGINT, session_id VARCHAR(64), payload TEXT,
    expires_at TIMESTAMPTZ NOT NULL, consumed_at TIMESTAMPTZ, created_at TIMESTAMPTZ
)"#;

const EXTERNAL_CLAIMS: &str = r#"CREATE TABLE external_identity_claims (
    id INTEGER PRIMARY KEY AUTOINCREMENT, provider VARCHAR(32) NOT NULL,
    subject VARCHAR(128) NOT NULL, user_id BIGINT NOT NULL, created_at DATETIME,
    UNIQUE (provider, subject), UNIQUE (provider, user_id)
)"#;

const EXTERNAL_CLAIMS_PG: &str = r#"CREATE TABLE external_identity_claims (
    id BIGSERIAL PRIMARY KEY, provider VARCHAR(32) NOT NULL,
    subject VARCHAR(128) NOT NULL, user_id BIGINT NOT NULL, created_at TIMESTAMPTZ,
    UNIQUE (provider, subject), UNIQUE (provider, user_id)
)"#;

const USER_SESSIONS: &str = r#"CREATE TABLE user_sessions (
    sid VARCHAR(64) PRIMARY KEY, user_id BIGINT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1, user_auth_version BIGINT NOT NULL,
    status VARCHAR(16) NOT NULL, refresh_hash CHAR(64) NOT NULL,
    previous_refresh_hash VARCHAR(64), previous_valid_until BIGINT NOT NULL DEFAULT 0,
    login_method VARCHAR(32) NOT NULL, ip VARCHAR(64), user_agent TEXT,
    created_at BIGINT, last_active_at BIGINT NOT NULL, expires_at BIGINT NOT NULL,
    revoked_at BIGINT NOT NULL DEFAULT 0, revoked_reason VARCHAR(64)
)"#;

const CUSTOM_PROVIDERS: &str = r#"CREATE TABLE custom_oauth_providers (
    id INTEGER PRIMARY KEY, name TEXT, slug TEXT UNIQUE, icon TEXT,
    enabled INTEGER, client_id TEXT, client_secret TEXT,
    authorization_endpoint TEXT, token_endpoint TEXT, user_info_endpoint TEXT,
    scopes TEXT, user_id_field TEXT, username_field TEXT,
    display_name_field TEXT, email_field TEXT, well_known TEXT,
    auth_style BIGINT, access_policy TEXT, access_denied_message TEXT,
    created_at DATETIME, updated_at DATETIME
)"#;

const CUSTOM_PROVIDERS_PG: &str = r#"CREATE TABLE custom_oauth_providers (
    id BIGSERIAL PRIMARY KEY, name TEXT, slug TEXT UNIQUE, icon TEXT,
    enabled BOOLEAN, client_id TEXT, client_secret TEXT,
    authorization_endpoint TEXT, token_endpoint TEXT, user_info_endpoint TEXT,
    scopes TEXT, user_id_field TEXT, username_field TEXT,
    display_name_field TEXT, email_field TEXT, well_known TEXT,
    auth_style BIGINT, access_policy TEXT, access_denied_message TEXT,
    created_at TIMESTAMPTZ, updated_at TIMESTAMPTZ
)"#;

const LOGS: &str = r#"CREATE TABLE logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
    created_at BIGINT NOT NULL, type INTEGER, content TEXT, username TEXT,
    token_name TEXT, model_name TEXT, quota INTEGER,
    prompt_tokens INTEGER, completion_tokens INTEGER, use_time INTEGER,
    is_stream INTEGER, ip TEXT, request_id VARCHAR(64), other TEXT
)"#;

const LOGS_PG: &str = r#"CREATE TABLE logs (
    id BIGSERIAL PRIMARY KEY, user_id BIGINT,
    created_at BIGINT NOT NULL, type BIGINT, content TEXT, username TEXT,
    token_name TEXT, model_name TEXT, quota BIGINT,
    prompt_tokens BIGINT, completion_tokens BIGINT, use_time BIGINT,
    is_stream BIGINT, ip TEXT, request_id VARCHAR(64), other TEXT
)"#;

const CASBIN_RULE: &str = r#"CREATE TABLE casbin_rule (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ptype TEXT,
    v0 TEXT, v1 TEXT, v2 TEXT, v3 TEXT, v4 TEXT, v5 TEXT
)"#;

const CASBIN_RULE_PG: &str = r#"CREATE TABLE casbin_rule (
    id BIGSERIAL PRIMARY KEY, ptype TEXT,
    v0 TEXT, v1 TEXT, v2 TEXT, v3 TEXT, v4 TEXT, v5 TEXT
)"#;

const USER_OAUTH_BINDINGS: &str = r#"CREATE TABLE user_oauth_bindings (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id BIGINT NOT NULL,
    provider_id BIGINT NOT NULL, provider_user_id VARCHAR(256) NOT NULL,
    created_at DATETIME,
    UNIQUE (user_id, provider_id), UNIQUE (provider_id, provider_user_id)
)"#;

const USER_OAUTH_BINDINGS_PG: &str = r#"CREATE TABLE user_oauth_bindings (
    id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL,
    provider_id BIGINT NOT NULL, provider_user_id VARCHAR(256) NOT NULL,
    created_at TIMESTAMPTZ,
    UNIQUE (user_id, provider_id), UNIQUE (provider_id, provider_user_id)
)"#;

// Go 硬编码文案与状态码断言锚点。
const MSG_STATE_INVALID_ZH: &str = "state 参数为空或不匹配";
const MSG_WECHAT_DISABLED: &str = "管理员未开启通过微信登录以及注册";
const MSG_TELEGRAM_DISABLED: &str = "管理员未开启通过 Telegram 登录以及注册";
const MSG_BIND_NEEDS_LOGIN: &str = "绑定操作需要登录";
const MSG_WECHAT_ALREADY_BOUND: &str = "该微信账号已被绑定";
const MSG_TELEGRAM_REPLAYED: &str = "该登录凭据已被使用";
const MSG_WECHAT_REGISTER_DISABLED: &str = "管理员关闭了新用户注册";
const MSG_TELEGRAM_NOT_BOUND: &str = "该 Telegram 账户未绑定";

fn auth_flows_ddl(db: &Database) -> &'static str {
    match db {
        Database::Sqlite(_) => AUTH_FLOWS,
        Database::Postgres(_) => AUTH_FLOWS_PG,
    }
}

fn external_claims_ddl(db: &Database) -> &'static str {
    match db {
        Database::Sqlite(_) => EXTERNAL_CLAIMS,
        Database::Postgres(_) => EXTERNAL_CLAIMS_PG,
    }
}

fn custom_providers_ddl(db: &Database) -> &'static str {
    match db {
        Database::Sqlite(_) => CUSTOM_PROVIDERS,
        Database::Postgres(_) => CUSTOM_PROVIDERS_PG,
    }
}

fn bindings_ddl(db: &Database) -> &'static str {
    match db {
        Database::Sqlite(_) => USER_OAUTH_BINDINGS,
        Database::Postgres(_) => USER_OAUTH_BINDINGS_PG,
    }
}

// ---------------------------------------------------------------------------
// 测试路由器：与生产 http.rs 的 oauth 分组同链（CT/NC 由专用测试覆盖，
// 这里保留鉴权层与 handler，可观察行为一致）。
// ---------------------------------------------------------------------------

fn router(state: AppState) -> Router {
    // TryUserAuth 组（state + callback）。
    let anonymous = Router::new()
        .route("/api/oauth/state", axum::routing::post(oauth_state))
        .route("/api/oauth/{provider}", axum::routing::get(handle_provider))
        .route_layer(middleware::from_fn_with_state(state.clone(), try_user_auth));
    // UserAuth 组（email bind / wechat bind / telegram bind start）。
    let user = Router::new()
        .route("/api/oauth/email/bind", axum::routing::post(email_bind))
        .route("/api/oauth/wechat/bind", axum::routing::post(wechat_bind))
        .route(
            "/api/oauth/telegram/bind/start",
            axum::routing::post(telegram_bind_start),
        )
        .route_layer(middleware::from_fn_with_state(state.clone(), user_auth));
    // 匿名组（wechat login / telegram login / telegram bind callback）。
    let callback = Router::new()
        .route("/api/oauth/wechat", axum::routing::get(wechat_login))
        .route(
            "/api/oauth/telegram/login",
            axum::routing::get(telegram_login),
        )
        .route(
            "/api/oauth/telegram/bind/{flow_token}",
            axum::routing::get(telegram_bind),
        );
    anonymous.merge(user).merge(callback).with_state(state)
}

async fn state(db: &Database) -> AppState {
    // 与 login_success 等切片一致：先 initialize（装载 auth_settings 快照
    // 等），再注入 SessionAuth 与运行时；仅 bind_runtime 会让 register_enabled
    // 等快照停留在默认值。
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

async fn exec(db: &Database, statement: &'static str) {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query(statement)
                .execute(pool)
                .await
                .expect("fixture ddl");
        }
        Database::Postgres(pool) => {
            sqlx::query(statement)
                .execute(pool)
                .await
                .expect("fixture ddl");
        }
    }
}

async fn fixture(db: &Database) {
    exec(db, users_ddl(db)).await;
    exec(db, OPTIONS).await;
    exec(db, auth_flows_ddl(db)).await;
    exec(db, external_claims_ddl(db)).await;
    exec(db, user_sessions_ddl(db)).await;
    exec(db, custom_providers_ddl(db)).await;
    exec(db, bindings_ddl(db)).await;
    match db {
        Database::Sqlite(_) => exec(db, LOGS).await,
        Database::Postgres(_) => exec(db, LOGS_PG).await,
    }
    match db {
        Database::Sqlite(_) => exec(db, CASBIN_RULE).await,
        Database::Postgres(_) => exec(db, CASBIN_RULE_PG).await,
    }
}

fn user_sessions_ddl(_db: &Database) -> &'static str {
    USER_SESSIONS
}

async fn set_option(db: &Database, key: &str, value: &str) {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query(
                r#"INSERT INTO options ("key", "value") VALUES ($1, $2)
                   ON CONFLICT ("key") DO UPDATE SET "value" = excluded."value""#,
            )
            .bind(key)
            .bind(value)
            .execute(pool)
            .await
            .expect("seed option");
        }
        Database::Postgres(pool) => {
            sqlx::query(
                r#"INSERT INTO options ("key", "value") VALUES ($1, $2)
                   ON CONFLICT ("key") DO UPDATE SET "value" = excluded."value""#,
            )
            .bind(key)
            .bind(value)
            .execute(pool)
            .await
            .expect("seed option");
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn seed_user(db: &Database, id: i64, pat: &str, role: i64, auth_version: i64) {
    let insert = r#"INSERT INTO users
        (id,username,display_name,role,status,"group",auth_version,access_token,aff_code)
        VALUES ($1,'fixture','Fixture',$2,1,'default',$3,$4,'')"#;
    match db {
        Database::Sqlite(pool) => {
            sqlx::query(insert)
                .bind(id)
                .bind(role)
                .bind(auth_version)
                .bind(pat)
                .execute(pool)
                .await
                .expect("seed user");
        }
        Database::Postgres(pool) => {
            sqlx::query(insert)
                .bind(id)
                .bind(role)
                .bind(auth_version)
                .bind(pat)
                .execute(pool)
                .await
                .expect("seed user");
        }
    }
}

async fn seed_session(db: &Database, sid: &str, user_id: i64, auth_version: i64) {
    let insert = r#"INSERT INTO user_sessions
        (sid,user_id,version,user_auth_version,status,refresh_hash,previous_valid_until,
         login_method,ip,user_agent,created_at,last_active_at,expires_at,revoked_at)
        VALUES ($1,$2,1,$3,'active',CASE($4) WHEN 1 THEN 'x' ELSE 'x' END,0,'password',
        '203.0.113.9','agent/1',0,0,9999999999,0)"#;
    match db {
        Database::Sqlite(pool) => {
            sqlx::query(insert)
                .bind(sid)
                .bind(user_id)
                .bind(auth_version)
                .bind(1_i64)
                .execute(pool)
                .await
                .expect("seed session");
        }
        Database::Postgres(pool) => {
            sqlx::query(insert)
                .bind(sid)
                .bind(user_id)
                .bind(auth_version)
                .bind(1_i64)
                .execute(pool)
                .await
                .expect("seed session");
        }
    }
}

async fn send(
    state: &AppState,
    method: Method,
    uri: &str,
    authorization: Option<&str>,
    body: Option<Value>,
) -> Response {
    let builder = Request::builder()
        .method(method)
        .uri(uri)
        // 与 Go 默认 locale（zh-CN）一致，断言固定中文文案。
        .header(header::ACCEPT_LANGUAGE, "zh-CN");
    let builder = match authorization {
        Some(value) => builder.header(header::AUTHORIZATION, value),
        None => builder,
    };
    let builder = match body {
        Some(value) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(value.to_string())),
        None => builder.body(Body::empty()),
    };
    let mut request = builder.unwrap();
    // 生产 critical_guard 注入 ClientIp；测试路由器直接补上同一扩展。
    request
        .extensions_mut()
        .insert(ClientIp("127.0.0.1".into()));
    router(state.clone()).oneshot(request).await.unwrap()
}

/// `send` + 出站传输注入（假 transport 经 Request 扩展进入 handler）。
async fn send_injected(
    state: &AppState,
    method: Method,
    uri: &str,
    authorization: Option<&str>,
    body: Option<Value>,
    transport: FakeTransport,
) -> Response {
    let builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::ACCEPT_LANGUAGE, "zh-CN");
    let builder = match authorization {
        Some(value) => builder.header(header::AUTHORIZATION, value),
        None => builder,
    };
    let builder = match body {
        Some(value) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(value.to_string())),
        None => builder.body(Body::empty()),
    };
    let mut request = builder.unwrap();
    request.extensions_mut().insert(injected(transport));
    request
        .extensions_mut()
        .insert(ClientIp("127.0.0.1".into()));
    router(state.clone()).oneshot(request).await.unwrap()
}

async fn body_json(response: Response) -> Value {
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body");
    serde_json::from_slice(&bytes).expect("response JSON")
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// ---------------------------------------------------------------------------
// 假出站传输（provider token / userinfo、wechat server）
// ---------------------------------------------------------------------------

#[derive(Default)]
struct FakeTransport {
    /// url → (status, body)
    responses: std::sync::Mutex<Vec<(String, u16, String)>>,
}

impl FakeTransport {
    fn with(url: &str, status: u16, body: &str) -> Self {
        Self {
            responses: std::sync::Mutex::new(vec![(url.to_owned(), status, body.to_owned())]),
        }
    }
}

impl OutboundTransport for FakeTransport {
    fn send(&self, request: OutboundRequest) -> OutboundFuture<'_> {
        Box::pin(async move {
            let responses = self.responses.lock().expect("lock");
            for (url, status, body) in responses.iter() {
                if request.url.starts_with(url.as_str()) {
                    return Ok(OutboundResponse {
                        status: *status,
                        body: body.clone(),
                    });
                }
            }
            Err(OutboundError::Transport)
        })
    }
}

fn injected(transport: FakeTransport) -> InjectedOAuthTransport {
    InjectedOAuthTransport(Arc::new(transport))
}

// ---------------------------------------------------------------------------
// POST /api/oauth/state
// ---------------------------------------------------------------------------

async fn run_state_contract(db: Database) {
    fixture(&db).await;
    seed_user(&db, USER_ID, PAT, 1, 1).await;
    seed_session(&db, "sess-1", USER_ID, 1).await;
    let app = state(&db).await;
    // Go ReadSessionAuthIdentity 语义：bind intent 需要仪表板会话 JWT。
    let jwt = AuthKeys::new(SECRET)
        .issue_access(
            &AuthIdentity {
                user_id: USER_ID,
                sid: "sess-1".into(),
                user_auth_version: 1,
                session_version: 1,
            },
            now(),
        )
        .expect("issue access token")
        .token
        .expose_secret()
        .to_owned();
    let auth = format!("Bearer {jwt}");

    // 未登录 + bind intent → 401 固定文案。
    let response = send(
        &app,
        Method::POST,
        "/api/oauth/state",
        None,
        Some(json!({
            "provider": "github", "intent": "bind",
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        body_json(response).await["message"],
        json!(MSG_BIND_NEEDS_LOGIN)
    );

    // login intent 未登录也生成（state 是匿名可建的 CSRF token）。
    let response = send(
        &app,
        Method::POST,
        "/api/oauth/state",
        None,
        Some(json!({
            "provider": "github", "intent": "login", "aff": "abcd",
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true));
    assert_eq!(body["data"]["expires_at"].as_i64().unwrap(), now() + 600);

    // 未知 provider / 非法 intent → common.invalid_params。
    for payload in [
        json!({"provider": "nope", "intent": "login"}),
        json!({"provider": "github", "intent": "other"}),
        json!({"provider": "github", "intent": "login", "aff": "x".repeat(33)}),
        json!({"provider": "github", "intent": "bind", "aff": "x"}),
    ] {
        let response = send(&app, Method::POST, "/api/oauth/state", None, Some(payload)).await;
        let body = body_json(response).await;
        assert_eq!(body["success"], json!(false), "{body}");
    }

    // bind intent 携带会话 → 成功且 flow 绑定会话（行内 user_id 落库）。
    let response = send(
        &app,
        Method::POST,
        "/api/oauth/state",
        Some(&auth),
        Some(json!({
            "provider": "github", "intent": "bind",
        })),
    )
    .await;
    assert_eq!(body_json(response).await["success"], json!(true));

    // 自定义 provider（custom 行存在即注册，enabled 不影响 state）。
    match &db {
        Database::Sqlite(pool) => {
            sqlx::query(
                "INSERT INTO custom_oauth_providers (id,name,slug,enabled,client_id) \
                 VALUES (1,'Corp','corp-sso',0,'cid')",
            )
            .execute(pool)
            .await
            .unwrap();
        }
        Database::Postgres(pool) => {
            sqlx::query(
                "INSERT INTO custom_oauth_providers (id,name,slug,enabled,client_id) \
                 VALUES (1,'Corp','corp-sso',FALSE,'cid')",
            )
            .execute(pool)
            .await
            .unwrap();
        }
    }
    let response = send(
        &app,
        Method::POST,
        "/api/oauth/state",
        None,
        Some(json!({
            "provider": "corp-sso", "intent": "login",
        })),
    )
    .await;
    assert_eq!(body_json(response).await["success"], json!(true));
}

// ---------------------------------------------------------------------------
// GET /api/oauth/:provider — 禁用/未启用/登录/绑定分支
// ---------------------------------------------------------------------------

async fn run_provider_disabled_contract(db: Database) {
    fixture(&db).await;
    let app = state(&db).await;
    // 未启用：state 有效 + provider 恒注册 → oauth.not_enabled（200）。
    let response = send(
        &app,
        Method::POST,
        "/api/oauth/state",
        None,
        Some(json!({
            "provider": "github", "intent": "login",
        })),
    )
    .await;
    let token = body_json(response).await["data"]["flow_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let response = send(
        &app,
        Method::GET,
        &format!("/api/oauth/github?code=c&state={token}"),
        None,
        None,
    )
    .await;
    let status = response.status();
    let body = body_json(response).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["success"], json!(false));
    assert!(
        body["message"].as_str().unwrap().contains("GitHub"),
        "{body}"
    );
}

async fn run_provider_unknown_contract(db: Database) {
    fixture(&db).await;
    let app = state(&db).await;
    // 未知 provider → 400 + oauth.unknown_provider（无需 state）。
    let response = send(&app, Method::GET, "/api/oauth/nope?state=x", None, None).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false));
}

async fn run_provider_state_invalid_contract(db: Database) {
    fixture(&db).await;
    let app = state(&db).await;
    // state 缺失/无效 → 403 + oauth.state_invalid。
    let response = send(&app, Method::GET, "/api/oauth/github", None, None).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(response).await["message"],
        json!(MSG_STATE_INVALID_ZH)
    );
    let response = send(
        &app,
        Method::GET,
        "/api/oauth/github?state=bogus",
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

async fn run_provider_login_contract(db: Database) {
    fixture(&db).await;
    seed_user(&db, 1, "pat-existing", 1, 1).await;
    let app = state(&db).await;
    // 启用 GitHub OAuth。
    set_option(&db, "GitHubOAuthEnabled", "true").await;
    set_option(&db, "GitHubClientId", "cid").await;
    set_option(&db, "GitHubClientSecret", "csecret").await;
    // state。
    let response = send(
        &app,
        Method::POST,
        "/api/oauth/state",
        None,
        Some(json!({
            "provider": "github", "intent": "login",
        })),
    )
    .await;
    let token = body_json(response).await["data"]["flow_token"]
        .as_str()
        .unwrap()
        .to_owned();
    // 注入假 GitHub：token 交换 + 用户信息（与 qq panel 注入同一手法：
    // 先造 Request，经 extensions_mut 插入假传输，再交给 router oneshot）。
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/oauth/github?code=c&state={token}"))
        .body(Body::empty())
        .unwrap();
    let mut request = request;
    // 生产 critical_guard 注入 ClientIp；测试路由器直接补上同一扩展。
    request
        .extensions_mut()
        .insert(ClientIp("127.0.0.1".into()));
    request.extensions_mut().insert(injected(FakeTransport {
        responses: std::sync::Mutex::new(vec![
            (
                "https://github.com/login/oauth/access_token".to_owned(),
                200,
                r#"{"access_token":"gho_t"}"#.to_owned(),
            ),
            (
                "https://api.github.com/user".to_owned(),
                200,
                r#"{"id":9000000001,"login":"octocat","name":"Octo Cat","email":""}"#.to_owned(),
            ),
        ]),
    }));
    let response = router(app.clone()).oneshot(request).await.unwrap();
    let status = response.status();
    let body = body_json(response).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["success"], json!(true), "{body}");
    // auth bundle 形状（SetupLogin）。
    let data = &body["data"];
    assert!(data["access_token"].as_str().is_some(), "{body}");
    assert_eq!(data["session"]["login_method"], json!("oauth:github"));
    assert_eq!(data["user"]["username"], json!("octocat"));
}

// ---------------------------------------------------------------------------
// GET /api/oauth/wechat — 微信登录（远端注入）
// ---------------------------------------------------------------------------

async fn run_wechat_login_contract(db: Database) {
    fixture(&db).await;
    seed_user(&db, USER_ID, PAT, 1, 1).await;
    let app = state(&db).await;
    // 未启用 → 固定文案。
    let response = send(&app, Method::GET, "/api/oauth/wechat?code=c", None, None).await;
    assert_eq!(
        body_json(response).await["message"],
        json!(MSG_WECHAT_DISABLED)
    );

    set_option(&db, "WeChatAuthEnabled", "true").await;
    set_option(&db, "WeChatServerAddress", "http://wechat.internal").await;
    set_option(&db, "WeChatServerToken", "wtok").await;
    let app = state(&db).await;
    // 远端 success=false → 固定折叠文案。
    let response = send_injected(
        &app,
        Method::GET,
        "/api/oauth/wechat?code=c",
        None,
        None,
        FakeTransport::with(
            "http://wechat.internal/api/wechat/user",
            200,
            r#"{"success":false,"message":"bad","data":""}"#,
        ),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false), "{body}");

    // 远端返回新 wechat id + 注册关闭 → 管理员关闭了新用户注册。
    // 先关注册并重建快照，再发请求（state() 每次重建装载 options）。
    set_option(&db, "RegisterEnabled", "false").await;
    let app = state(&db).await;
    let response = send_injected(
        &app,
        Method::GET,
        "/api/oauth/wechat?code=c",
        None,
        None,
        FakeTransport::with(
            "http://wechat.internal/api/wechat/user",
            200,
            r#"{"success":true,"message":"","data":"wx-1"}"#,
        ),
    )
    .await;
    assert_eq!(
        body_json(response).await["message"],
        json!(MSG_WECHAT_REGISTER_DISABLED)
    );
    set_option(&db, "RegisterEnabled", "true").await;
    let app = state(&db).await;

    // 新用户注册路径：远端 id → 创建用户 → SetupLogin bundle。
    let response = send_injected(
        &app,
        Method::GET,
        "/api/oauth/wechat?code=c",
        None,
        None,
        FakeTransport::with(
            "http://wechat.internal/api/wechat/user",
            200,
            r#"{"success":true,"message":"","data":"wx-2"}"#,
        ),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true), "{body}");
    assert_eq!(body["data"]["session"]["login_method"], json!("wechat"));
    assert_eq!(body["data"]["user"]["username"], json!("wechat_1"));

    // 再次登录同一 wechat id：绑定用户直接登录。
    let response = send_injected(
        &app,
        Method::GET,
        "/api/oauth/wechat?code=c",
        None,
        None,
        FakeTransport::with(
            "http://wechat.internal/api/wechat/user",
            200,
            r#"{"success":true,"message":"","data":"wx-2"}"#,
        ),
    )
    .await;
    assert_eq!(body_json(response).await["success"], json!(true));
}

// ---------------------------------------------------------------------------
// POST /api/oauth/wechat/bind
// ---------------------------------------------------------------------------

async fn run_wechat_bind_contract(db: Database) {
    fixture(&db).await;
    seed_user(&db, USER_ID, PAT, 1, 1).await;
    let app = state(&db).await;
    let auth = format!("Bearer {PAT}");
    // 未启用。
    let response = send(
        &app,
        Method::POST,
        "/api/oauth/wechat/bind",
        Some(&auth),
        Some(json!({"code": "c"})),
    )
    .await;
    assert_eq!(
        body_json(response).await["message"],
        json!(MSG_WECHAT_DISABLED)
    );

    set_option(&db, "WeChatAuthEnabled", "true").await;
    set_option(&db, "WeChatServerAddress", "http://wechat.internal").await;
    set_option(&db, "WeChatServerToken", "wtok").await;
    let app = state(&db).await;
    // 已被占用：先落另一个用户的微信 ID（先 seed 再 UPDATE，保证行存在）。
    seed_user(&db, USER_ID + 1, "pat-other", 1, 1).await;
    match &db {
        Database::Sqlite(pool) => {
            sqlx::query("UPDATE users SET wechat_id = 'wx-taken' WHERE id = $1")
                .bind(USER_ID + 1)
                .execute(pool)
                .await
                .unwrap();
        }
        Database::Postgres(pool) => {
            sqlx::query("UPDATE users SET wechat_id = 'wx-taken' WHERE id = $1")
                .bind(USER_ID + 1)
                .execute(pool)
                .await
                .unwrap();
        }
    }
    let response = send_injected(
        &app,
        Method::POST,
        "/api/oauth/wechat/bind",
        Some(&auth),
        Some(json!({"code": "c"})),
        FakeTransport::with(
            "http://wechat.internal/api/wechat/user",
            200,
            r#"{"success":true,"message":"","data":"wx-taken"}"#,
        ),
    )
    .await;
    assert_eq!(
        body_json(response).await["message"],
        json!(MSG_WECHAT_ALREADY_BOUND)
    );

    // 新 id → 绑定成功 {"success":true,"message":""}，wechat_id 落列。
    let response = send_injected(
        &app,
        Method::POST,
        "/api/oauth/wechat/bind",
        Some(&auth),
        Some(json!({"code": "c"})),
        FakeTransport::with(
            "http://wechat.internal/api/wechat/user",
            200,
            r#"{"success":true,"message":"","data":"wx-new"}"#,
        ),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true), "{body}");
    assert_eq!(body["message"], json!(""));
    let stored: String = match &db {
        Database::Sqlite(pool) => sqlx::query_scalar("SELECT wechat_id FROM users WHERE id = $1")
            .bind(USER_ID)
            .fetch_one(pool)
            .await
            .unwrap(),
        Database::Postgres(pool) => sqlx::query_scalar("SELECT wechat_id FROM users WHERE id = $1")
            .bind(USER_ID)
            .fetch_one(pool)
            .await
            .unwrap(),
    };
    assert_eq!(stored, "wx-new");
}

// ---------------------------------------------------------------------------
// POST /api/oauth/email/bind
// ---------------------------------------------------------------------------

async fn run_email_bind_contract(db: Database) {
    fixture(&db).await;
    seed_user(&db, USER_ID, PAT, 1, 1).await;
    let app = state(&db).await;
    let auth = format!("Bearer {PAT}");
    // 验证码错误。
    let response = send(
        &app,
        Method::POST,
        "/api/oauth/email/bind",
        Some(&auth),
        Some(json!({"email": "a@b", "code": "nope"})),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false));
    assert!(
        body["message"].as_str().unwrap().contains("验证码"),
        "{body}"
    );

    // 注册验证码（同 Go：UUID 前缀去横线前 6 位由调用方注册；测试直接以
    // register API 注入内存验证码——使用注册 crate 的注册函数）。
    newapi_identity::registration::register_email_verification_code("a@b", "123456");
    let response = send(
        &app,
        Method::POST,
        "/api/oauth/email/bind",
        Some(&auth),
        Some(json!({"email": "A@B ", "code": "123456"})),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true), "{body}");
    assert_eq!(body["message"], json!(""));
    let stored: String = match &db {
        Database::Sqlite(pool) => sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
            .bind(USER_ID)
            .fetch_one(pool)
            .await
            .unwrap(),
        Database::Postgres(pool) => sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
            .bind(USER_ID)
            .fetch_one(pool)
            .await
            .unwrap(),
    };
    assert_eq!(stored, "a@b");

    // 重放同一验证码（Go VerifyCodeWithKey 不消费，可重复；重复绑定同邮箱
    // 也成功）。
    let response = send(
        &app,
        Method::POST,
        "/api/oauth/email/bind",
        Some(&auth),
        Some(json!({"email": "a@b", "code": "123456"})),
    )
    .await;
    assert_eq!(body_json(response).await["success"], json!(true));
}

// ---------------------------------------------------------------------------
// Telegram：bind start → bind callback（签名/重放/会话）与 login
// ---------------------------------------------------------------------------

fn telegram_signature(params: &[(String, String)], bot_token: &str) -> String {
    newapi_identity::oauth_flow::telegram::widget_signature(bot_token, params)
}

fn telegram_params(auth_date: i64) -> Vec<(String, String)> {
    vec![
        ("id".to_owned(), "9000000002".to_owned()),
        ("first_name".to_owned(), "San".to_owned()),
        ("username".to_owned(), "sanuser".to_owned()),
        ("auth_date".to_owned(), auth_date.to_string()),
    ]
}

async fn run_telegram_login_contract(db: Database) {
    fixture(&db).await;
    seed_user(&db, USER_ID, PAT, 1, 1).await;
    let app = state(&db).await;
    // 未启用。
    let response = send(&app, Method::GET, "/api/oauth/telegram/login", None, None).await;
    assert_eq!(
        body_json(response).await["message"],
        json!(MSG_TELEGRAM_DISABLED)
    );

    set_option(&db, "TelegramOAuthEnabled", "true").await;
    set_option(&db, "TelegramBotToken", "bot-token").await;
    // 未绑定账户。
    let params = telegram_params(now());
    let signature = telegram_signature(&params, "bot-token");
    let mut query = params
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&");
    query.push_str(&format!("&hash={signature}"));
    let response = send(
        &app,
        Method::GET,
        &format!("/api/oauth/telegram/login?{query}"),
        None,
        None,
    )
    .await;
    assert_eq!(
        body_json(response).await["message"],
        json!(MSG_TELEGRAM_NOT_BOUND)
    );

    // 绑定 + 一次性断言 → 登录成功。
    match &db {
        Database::Sqlite(pool) => {
            sqlx::query("UPDATE users SET telegram_id = '9000000002' WHERE id = $1")
                .bind(USER_ID)
                .execute(pool)
                .await
                .unwrap();
        }
        Database::Postgres(pool) => {
            sqlx::query("UPDATE users SET telegram_id = '9000000002' WHERE id = $1")
                .bind(USER_ID)
                .execute(pool)
                .await
                .unwrap();
        }
    }
    let response = send(
        &app,
        Method::GET,
        &format!("/api/oauth/telegram/login?{query}"),
        None,
        None,
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true), "{body}");
    assert_eq!(body["data"]["session"]["login_method"], json!("telegram"));

    // 同一断言重放 → 403 固定文案。
    let response = send(
        &app,
        Method::GET,
        &format!("/api/oauth/telegram/login?{query}"),
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(response).await["message"],
        json!(MSG_TELEGRAM_REPLAYED)
    );
}

async fn run_telegram_bind_contract(db: Database) {
    fixture(&db).await;
    seed_user(&db, USER_ID, PAT, 1, 1).await;
    // 绑定守卫是 `telegram_id = ''`（Go 空串语义），fixture 默认列是 NULL。
    match &db {
        Database::Sqlite(pool) => {
            sqlx::query("UPDATE users SET telegram_id = '' WHERE id = $1")
                .bind(USER_ID)
                .execute(pool)
                .await
                .unwrap();
        }
        Database::Postgres(pool) => {
            sqlx::query("UPDATE users SET telegram_id = '' WHERE id = $1")
                .bind(USER_ID)
                .execute(pool)
                .await
                .unwrap();
        }
    }
    seed_session(&db, "sess-1", USER_ID, 1).await;
    let app = state(&db).await;
    // Go ReadSessionAuthIdentity 语义：bind/start 需要仪表板会话 JWT（PAT 不行）。
    let jwt = AuthKeys::new(SECRET)
        .issue_access(
            &AuthIdentity {
                user_id: USER_ID,
                sid: "sess-1".into(),
                user_auth_version: 1,
                session_version: 1,
            },
            now(),
        )
        .expect("issue access token")
        .token
        .expose_secret()
        .to_owned();
    let auth = format!("Bearer {jwt}");
    set_option(&db, "TelegramOAuthEnabled", "true").await;
    set_option(&db, "TelegramBotToken", "bot-token").await;

    // bind/start → flow_token。
    let response = send(
        &app,
        Method::POST,
        "/api/oauth/telegram/bind/start",
        Some(&auth),
        None,
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true), "{body}");
    let flow_token = body["data"]["flow_token"].as_str().unwrap().to_owned();
    assert_eq!(
        body["data"]["callback_url"],
        json!(format!("/api/oauth/telegram/bind/{flow_token}"))
    );

    // 坏签名 → 302 INVALID_REQUEST。
    let bad_params = [
        ("id".to_owned(), "9000000002".to_owned()),
        ("auth_date".to_owned(), now().to_string()),
    ];
    let query = bad_params
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&");
    let response = send(
        &app,
        Method::GET,
        &format!("/api/oauth/telegram/bind/{flow_token}?{query}&hash=deadbeef"),
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(
        location.contains("telegram_bind=error")
            && location.contains("TELEGRAM_BIND_INVALID_REQUEST"),
        "{location}"
    );

    // 好签名 + 有效会话 → 302 success，telegram_id 落列 + claim 落表。
    let params = telegram_params(now());
    let signature = telegram_signature(&params, "bot-token");
    let mut query = params
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&");
    query.push_str(&format!("&hash={signature}"));
    let response = send(
        &app,
        Method::GET,
        &format!("/api/oauth/telegram/bind/{flow_token}?{query}"),
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(location.contains("telegram_bind=success"), "{location}");
    let stored: String = match &db {
        Database::Sqlite(pool) => sqlx::query_scalar("SELECT telegram_id FROM users WHERE id = $1")
            .bind(USER_ID)
            .fetch_one(pool)
            .await
            .unwrap(),
        Database::Postgres(pool) => {
            sqlx::query_scalar("SELECT telegram_id FROM users WHERE id = $1")
                .bind(USER_ID)
                .fetch_one(pool)
                .await
                .unwrap()
        }
    };
    assert_eq!(stored, "9000000002");

    // 同一 flow 重放 → 302 FLOW_INVALID（单次消费）。
    let response = send(
        &app,
        Method::GET,
        &format!("/api/oauth/telegram/bind/{flow_token}?{query}"),
        None,
        None,
    )
    .await;
    let location = response
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(
        location.contains("TELEGRAM_BIND_FLOW_INVALID"),
        "{location}"
    );
}

// ---------------------------------------------------------------------------
// 测试入口（SQLite + PostgreSQL）
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sqlite_oauth_state_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    run_state_contract(Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn sqlite_oauth_provider_disabled_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    run_provider_disabled_contract(Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn sqlite_oauth_provider_unknown_and_state_contract() {
    // 两个契约各自 fixture（建表非幂等），分别用独立内存库。
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    run_provider_unknown_contract(Database::Sqlite(pool)).await;
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    run_provider_state_invalid_contract(Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn sqlite_oauth_provider_login_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    run_provider_login_contract(Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn sqlite_oauth_wechat_login_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    run_wechat_login_contract(Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn sqlite_oauth_wechat_bind_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    run_wechat_bind_contract(Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn sqlite_oauth_email_bind_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    run_email_bind_contract(Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn sqlite_oauth_telegram_login_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    run_telegram_login_contract(Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn sqlite_oauth_telegram_bind_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    run_telegram_bind_contract(Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn postgres_oauth_state_contract() {
    let Some(db) = postgres_fixture("oauth_state").await else {
        return;
    };
    run_state_contract(db).await;
}

#[tokio::test]
async fn postgres_oauth_provider_login_contract() {
    let Some(db) = postgres_fixture("oauth_provider_login").await else {
        return;
    };
    run_provider_login_contract(db).await;
}

#[tokio::test]
async fn postgres_oauth_wechat_bind_contract() {
    let Some(db) = postgres_fixture("oauth_wechat_bind").await else {
        return;
    };
    run_wechat_bind_contract(db).await;
}

#[tokio::test]
async fn postgres_oauth_email_bind_contract() {
    let Some(db) = postgres_fixture("oauth_email_bind").await else {
        return;
    };
    run_email_bind_contract(db).await;
}

#[tokio::test]
async fn postgres_oauth_telegram_bind_contract() {
    let Some(db) = postgres_fixture("oauth_telegram_bind").await else {
        return;
    };
    run_telegram_bind_contract(db).await;
}

/// 隔离的 PostgreSQL schema；`TEST_POSTGRES_DSN` 缺失时整个用例跳过。
async fn postgres_fixture(label: &str) -> Option<Database> {
    let Ok(dsn) = std::env::var("TEST_POSTGRES_DSN") else {
        return None;
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
        "oauth_routes_{label}_{}_{}",
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
    Some(Database::Postgres(pool))
}
