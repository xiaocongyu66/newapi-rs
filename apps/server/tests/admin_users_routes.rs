//! HTTP contracts for the seven admin user routes (`/api/user/` GET/POST/PUT,
//! `/api/user/search` GET, `/api/user/:id` GET/DELETE, `/api/user/manage` POST).
//!
//! Runs only in remote CI. Every scenario uses an isolated synthetic fixture
//! (in-memory SQLite or an isolated PostgreSQL schema); no service is started.
//! The PostgreSQL test is skipped when `TEST_POSTGRES_DSN` is absent.
//!
//! Go references: `apps/api/internal/identity/manage_users.go`
//! (GetAllUsers/SearchUsersHandler/GetUser/CreateUser/UpdateUser/DeleteUser/
//! ManageUser), `store_users.go` (SearchUsers/InsertWithTx/EditWithTx/
//! UpdateWithTx), `store_users_lifecycle.go` (listAllUsers/HardDeleteUserById),
//! `policy/override.go` (user-level overrides),
//! `transport/compose/register_api.go:204-218` (adminRoute: only
//! `security.AdminAuth()`; no DisableCache, no rate limit).

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
    crypto::AuthKeys,
    sessions::NoCache,
};
use newapi_security::client_ip::ProxyPolicy;
use newapi_server::{
    AppState, RateLimiter, admin_users_http, auth as server_auth, limit::RateLimitSettings,
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

const SECRET: &str = "admin-users-routes-fixture-secret";
const PAT_ADMIN: &str = "pat-admin-one";

/// Go i18n 键的英文渲染（`crates/i18n/locales/en.yaml`）。
fn translated(key: &str) -> String {
    newapi_i18n::translate("en", key, std::iter::empty::<(&str, &str)>())
}

/// Go `GetUserById(0)` 的硬编码中文（`store_users.go:411-413`）。
const MSG_ID_EMPTY: &str = "id 为空！";
/// Go `ManageUser` add_quota 的硬编码中文（`manage_users.go:1142`）。
const MSG_INVALID_QUOTA_VALUE: &str = "无效的额度数值";
/// Go `updateAdminPermissionsForUserInTx` 的固定文本（`manage_users.go:1029`）。
const MSG_ONLY_ROOT_PERMISSIONS: &str = "only root can update admin permissions";
/// 默认展示设置（Usd、quota_per_unit=500000）下 2.0 的内部额度。
const DISPLAY_TWO_IN_QUOTA: i64 = 1_000_000;
/// Go `logger.LogQuota(500)`（Usd 展示，`billing.formatQuota` 带后缀）。
const LOG_QUOTA_500: &str = "＄0.001000 额度";

const USERS_SQLITE: &str = r#"CREATE TABLE users (
    id INTEGER PRIMARY KEY, username TEXT, display_name TEXT,
    role INTEGER, status INTEGER, email TEXT, github_id TEXT, discord_id TEXT,
    oidc_id TEXT, wechat_id TEXT, telegram_id TEXT, "group" TEXT,
    quota INTEGER, used_quota INTEGER, request_count INTEGER, aff_code TEXT,
    aff_count INTEGER, aff_quota INTEGER, aff_history INTEGER, inviter_id INTEGER,
    linux_do_id TEXT, setting TEXT, stripe_customer TEXT, auth_version BIGINT,
    access_token TEXT, deleted_at TIMESTAMP, password TEXT,
    remark TEXT, created_at BIGINT, last_login_at BIGINT
)"#;

const USERS_POSTGRES: &str = r#"CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY, username TEXT, display_name TEXT,
    role BIGINT, status BIGINT, email TEXT, github_id TEXT, discord_id TEXT,
    oidc_id TEXT, wechat_id TEXT, telegram_id TEXT, "group" TEXT,
    quota BIGINT, used_quota BIGINT, request_count BIGINT, aff_code TEXT,
    aff_count BIGINT, aff_quota BIGINT, aff_history BIGINT, inviter_id BIGINT,
    linux_do_id TEXT, setting TEXT, stripe_customer TEXT, auth_version BIGINT,
    access_token TEXT, deleted_at TIMESTAMPTZ, password TEXT,
    remark TEXT, created_at BIGINT, last_login_at BIGINT
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

const LOGS_SQLITE: &str = r#"CREATE TABLE logs (
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

const CASBIN_SQLITE: &str = r#"CREATE TABLE casbin_rule (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ptype VARCHAR(100), v0 VARCHAR(100), v1 VARCHAR(100), v2 VARCHAR(100),
    v3 VARCHAR(100), v4 VARCHAR(100), v5 VARCHAR(100)
)"#;

const CASBIN_POSTGRES: &str = r#"CREATE TABLE casbin_rule (
    id BIGSERIAL PRIMARY KEY,
    ptype VARCHAR(100), v0 VARCHAR(100), v1 VARCHAR(100), v2 VARCHAR(100),
    v3 VARCHAR(100), v4 VARCHAR(100), v5 VARCHAR(100)
)"#;

/// `HardDelete` 逐表清理的其余认证数据表：删除语句只引用 user_id，
/// 最小表形即可。
macro_rules! simple_table {
    ($sqlite_name:literal, $name:ident, $postgres_name:ident) => {
        const $name: &str = concat!("CREATE TABLE ", $sqlite_name, " (user_id INTEGER)");
        const $postgres_name: &str = concat!("CREATE TABLE ", $sqlite_name, " (user_id BIGINT)");
    };
}

simple_table!("tokens", TOKENS_POSTGRES, TOKENS_SQLITE);
simple_table!("two_fas", TWO_FAS_POSTGRES, TWO_FAS_SQLITE);
simple_table!(
    "two_fa_backup_codes",
    BACKUP_CODES_POSTGRES,
    BACKUP_CODES_SQLITE
);
simple_table!("passkey_credentials", PASSKEYS_POSTGRES, PASSKEYS_SQLITE);
simple_table!("auth_flows", AUTH_FLOWS_POSTGRES, AUTH_FLOWS_SQLITE);
simple_table!(
    "external_identity_claims",
    EXTERNAL_POSTGRES,
    EXTERNAL_SQLITE
);
simple_table!(
    "user_oauth_bindings",
    OAUTH_BINDINGS_POSTGRES,
    OAUTH_BINDINGS_SQLITE
);
simple_table!("qq_bindings", QQ_POSTGRES, QQ_SQLITE);

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

/// Go `adminRoute`：只有 `AdminAuth()`（role >= 10）一道中间件。
fn router(state: AppState) -> Router {
    Router::new()
        .route(
            "/api/user/",
            get(admin_users_http::list_users)
                .post(admin_users_http::create_user)
                .put(admin_users_http::update_user),
        )
        .route(
            "/api/user",
            get(admin_users_http::list_users)
                .post(admin_users_http::create_user)
                .put(admin_users_http::update_user),
        )
        .route("/api/user/search", get(admin_users_http::search_users))
        .route("/api/user/manage", post(admin_users_http::manage_user))
        .route(
            "/api/user/{id}",
            get(admin_users_http::get_user).delete(admin_users_http::delete_user),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            server_auth::admin_auth,
        ))
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
            for statement in [
                USERS_SQLITE,
                SESSIONS,
                LOGS_SQLITE,
                CASBIN_SQLITE,
                TOKENS_SQLITE,
                TWO_FAS_SQLITE,
                BACKUP_CODES_SQLITE,
                PASSKEYS_SQLITE,
                AUTH_FLOWS_SQLITE,
                EXTERNAL_SQLITE,
                OAUTH_BINDINGS_SQLITE,
                QQ_SQLITE,
            ] {
                exec(db, statement).await;
            }
        }
        Database::Postgres(_) => {
            for statement in [
                USERS_POSTGRES,
                SESSIONS,
                LOGS_POSTGRES,
                CASBIN_POSTGRES,
                TOKENS_POSTGRES,
                TWO_FAS_POSTGRES,
                BACKUP_CODES_POSTGRES,
                PASSKEYS_POSTGRES,
                AUTH_FLOWS_POSTGRES,
                EXTERNAL_POSTGRES,
                OAUTH_BINDINGS_POSTGRES,
                QQ_POSTGRES,
            ] {
                exec(db, statement).await;
            }
        }
    }
}

async fn reset(db: &Database) {
    for table in [
        "logs",
        "casbin_rule",
        "tokens",
        "two_fa_backup_codes",
        "two_fas",
        "passkey_credentials",
        "auth_flows",
        "external_identity_claims",
        "user_oauth_bindings",
        "qq_bindings",
        "user_sessions",
        "users",
    ] {
        backend!(db, pool, {
            sqlx::query(sqlx::AssertSqlSafe(format!("DELETE FROM {table}")))
                .execute(pool)
                .await
                .expect("reset table");
        });
    }
}

/// Go `User.Role`：Guest=0 / Common=1 / Admin=10 / Root=100。
async fn seed_user(db: &Database, id: i64, username: &str, role: i64, pat: Option<&str>) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO users
                (id,username,display_name,role,status,"group",auth_version,
                 access_token,quota,setting)
                VALUES ($1,$2,$3,$4,1,'default',1,$5,0,$6)"#,
        )
        .bind(id)
        .bind(username)
        .bind(username)
        .bind(role)
        .bind(pat)
        .bind(r#"{"gotify_priority":0}"#)
        .execute(pool)
        .await
        .expect("seed user");
    });
}

/// Go GORM 软删除：`users.deleted_at` 置为非 NULL。
async fn soft_delete_user(db: &Database, id: i64) {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query("UPDATE users SET deleted_at = datetime($1, 'unixepoch') WHERE id = $2")
                .bind(now())
                .bind(id)
                .execute(pool)
                .await
                .expect("soft delete user");
        }
        Database::Postgres(pool) => {
            sqlx::query("UPDATE users SET deleted_at = to_timestamp($1::BIGINT) WHERE id = $2")
                .bind(now())
                .bind(id)
                .execute(pool)
                .await
                .expect("soft delete user");
        }
    }
}

async fn seed_session(db: &Database, sid: &str, user_id: i64, at: i64) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO user_sessions
                (sid,user_id,version,user_auth_version,status,refresh_hash,
                 previous_refresh_hash,previous_valid_until,login_method,ip,
                 user_agent,created_at,last_active_at,expires_at,revoked_at,revoked_reason)
                VALUES ($1,$2,1,1,'active','fixture-hash',NULL,0,'password','',
                        '',$3,$3,$4,0,'')"#,
        )
        .bind(sid)
        .bind(user_id)
        .bind(at)
        .bind(at + 3600)
        .execute(pool)
        .await
        .expect("seed session");
    });
}

async fn seed_rule(db: &Database, subject: &str, resource: &str, action: &str, effect: &str) {
    backend!(db, pool, {
        sqlx::query(
            "INSERT INTO casbin_rule (ptype,v0,v1,v2,v3,v4,v5) VALUES ('p',$1,$2,$3,$4,'','')",
        )
        .bind(subject)
        .bind(resource)
        .bind(action)
        .bind(effect)
        .execute(pool)
        .await
        .expect("seed rule");
    });
}

async fn seed_qq(db: &Database, user_id: i64, open_id: &str) {
    backend!(db, pool, {
        sqlx::query("INSERT INTO qq_bindings (user_id, open_id) VALUES ($1, $2)")
            .bind(user_id)
            .bind(open_id)
            .execute(pool)
            .await
            .expect("seed qq binding");
    });
}

async fn seed_one_column(db: &Database, table: &str, user_id: i64) {
    backend!(db, pool, {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "INSERT INTO {table} (user_id) VALUES ({user_id})"
        )))
        .execute(pool)
        .await
        .expect("seed auth table row");
    });
}

async fn seed_token(db: &Database, user_id: i64, key: &str) {
    backend!(db, pool, {
        sqlx::query("INSERT INTO tokens (user_id, \"key\") VALUES ($1, $2)")
            .bind(user_id)
            .bind(key)
            .execute(pool)
            .await
            .expect("seed token");
    });
}

fn jwt(user_id: i64, sid: &str, uv: i64, sv: i64, issued_at: i64) -> String {
    AuthKeys::new(SECRET)
        .issue_access(
            &AuthIdentity {
                user_id,
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

async fn send_json(
    state: &AppState,
    method: Method,
    path: &str,
    authorization: &str,
    body: &Value,
) -> Response {
    send(state, method, path, Some(authorization), Some(body)).await
}

async fn body_json(response: Response) -> Value {
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body");
    serde_json::from_slice(&bytes).expect("response JSON")
}

fn admin_token() -> String {
    format!("Bearer {}", jwt(1, "sid-admin", 1, 1, now()))
}

fn root_token() -> String {
    format!("Bearer {}", jwt(4, "sid-root", 1, 1, now()))
}

fn common_token() -> String {
    format!("Bearer {}", jwt(5, "sid-common", 1, 1, now()))
}

fn guest_token() -> String {
    format!("Bearer {}", jwt(9, "sid-guest", 1, 1, now()))
}

/// 两条 admin 路由族都不挂 `DisableCache`（Go `register_api.go:204-218`）。
fn assert_no_cache_headers(headers: &HeaderMap) {
    assert!(!headers.contains_key(header::CACHE_CONTROL));
    assert!(!headers.contains_key(header::PRAGMA));
    assert!(!headers.contains_key(header::EXPIRES));
}

/// `AdminAuth` 的拒绝：401/403 + 固定 code，且无缓存头。
async fn assert_auth_failure(response: Response, status: StatusCode, code: &str) {
    assert_eq!(response.status(), status);
    assert_no_cache_headers(response.headers());
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false));
    assert_eq!(body["code"], json!(code));
}

/// Go `common.CtxApiError` 的 HTTP 200 业务失败信封。
async fn assert_business_message(response: Response, message: &str) -> Value {
    assert_eq!(response.status(), StatusCode::OK);
    assert_no_cache_headers(response.headers());
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false), "{body}");
    assert_eq!(body["message"], json!(message), "{body}");
    body
}

async fn assert_success(response: Response) -> Value {
    assert_eq!(response.status(), StatusCode::OK);
    assert_no_cache_headers(response.headers());
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true), "{body}");
    assert_eq!(body["message"], json!(""), "{body}");
    body
}

/// `logs` 行的最小投影：归属用户、类型、内容、用户名、`other` JSON。
async fn audit_logs(db: &Database) -> Vec<(i64, i64, String, String, String)> {
    backend!(db, pool, {
        sqlx::query_as::<_, (i64, i64, String, String, String)>(
            "SELECT CAST(user_id AS BIGINT), CAST(type AS BIGINT), content, username, other \
             FROM logs ORDER BY id",
        )
        .fetch_all(pool)
        .await
        .expect("audit logs")
    })
}

async fn user_column_text(db: &Database, id: i64, column: &str) -> String {
    backend!(db, pool, {
        let sql = format!("SELECT COALESCE({column}, '') FROM users WHERE id = {id}");
        sqlx::query_scalar(sqlx::AssertSqlSafe(sql.clone()))
            .fetch_one(pool)
            .await
            .expect("user text column")
    })
}

async fn user_column_i64(db: &Database, id: i64, column: &str) -> i64 {
    backend!(db, pool, {
        let sql =
            format!("SELECT CAST(COALESCE({column}, 0) AS BIGINT) FROM users WHERE id = {id}");
        sqlx::query_scalar(sqlx::AssertSqlSafe(sql.clone()))
            .fetch_one(pool)
            .await
            .expect("user int column")
    })
}

async fn row_count(db: &Database, table: &str, predicate: &str) -> i64 {
    backend!(db, pool, {
        let sql = format!("SELECT COUNT(*) FROM {table} WHERE {predicate}");
        sqlx::query_scalar(sqlx::AssertSqlSafe(sql.clone()))
            .fetch_one(pool)
            .await
            .expect("row count")
    })
}

async fn session_status(db: &Database, sid: &str) -> String {
    backend!(db, pool, {
        sqlx::query_scalar("SELECT status FROM user_sessions WHERE sid = $1")
            .bind(sid)
            .fetch_one(pool)
            .await
            .expect("session status")
    })
}

async fn run_contract(db: Database) {
    create_schema(&db).await;
    reset(&db).await;
    let at = now();
    seed_user(&db, 1, "admin-one", 10, Some(PAT_ADMIN)).await;
    seed_user(&db, 2, "target-common", 1, None).await;
    seed_user(&db, 3, "admin-two", 10, None).await;
    seed_user(&db, 4, "root-one", 100, None).await;
    seed_user(&db, 5, "plain-common", 1, None).await;
    seed_user(&db, 7, "deleted-common", 1, None).await;
    seed_user(&db, 9, "guest-one", 0, None).await;
    soft_delete_user(&db, 7).await;
    seed_session(&db, "sid-admin", 1, at).await;
    seed_session(&db, "sid-root", 4, at).await;
    seed_session(&db, "sid-common", 5, at).await;
    seed_session(&db, "sid-target", 2, at).await;
    seed_rule(&db, "user:2", "channel", "read", "allow").await;
    seed_qq(&db, 2, "qq-open-2").await;
    seed_token(&db, 2, "tk-target").await;
    for table in [
        "two_fas",
        "two_fa_backup_codes",
        "passkey_credentials",
        "auth_flows",
        "external_identity_claims",
        "user_oauth_bindings",
    ] {
        seed_one_column(&db, table, 2).await;
    }
    // PG 的 BIGSERIAL 序列不随显式 id 插入推进；同步到种子最大 id 之后，
    // 使两条后端的新行 id 一致（SQLite AUTOINCREMENT 自动续接）。
    if let Database::Postgres(pool) = &db {
        sqlx::query(
            "SELECT setval(pg_get_serial_sequence('users','id'), \
             (SELECT COALESCE(MAX(id), 0) + 1 FROM users))",
        )
        .execute(pool)
        .await
        .expect("sync users id sequence");
    }
    let app = state(&db);
    let admin = admin_token();
    let root = root_token();
    let common = common_token();
    let guest = guest_token();

    // ---- guard chain: Go `security.AdminAuth()` only -----------------------
    for (method, path) in [
        (Method::GET, "/api/user/"),
        (Method::GET, "/api/user/search"),
        (Method::GET, "/api/user/2"),
        (Method::POST, "/api/user/"),
        (Method::PUT, "/api/user/"),
        (Method::DELETE, "/api/user/2"),
        (Method::POST, "/api/user/manage"),
    ] {
        assert_auth_failure(
            send(&app, method, path, None, None).await,
            StatusCode::UNAUTHORIZED,
            "AUTH_UNAUTHORIZED",
        )
        .await;
        assert_auth_failure(
            send(&app, method, path, Some(&common), None).await,
            StatusCode::FORBIDDEN,
            "AUTH_INSUFFICIENT_PRIVILEGE",
        )
        .await;
        assert_auth_failure(
            send(&app, method, path, Some(&guest), None).await,
            StatusCode::FORBIDDEN,
            "AUTH_INSUFFICIENT_PRIVILEGE",
        )
        .await;
    }

    // ---- list: unscoped rows, default pagination, id desc -------------------
    let response = send(&app, Method::GET, "/api/user/", Some(&admin), None).await;
    let body = assert_success(response).await;
    let data = &body["data"];
    assert_eq!(data["page"], json!(1));
    assert_eq!(data["page_size"], json!(10));
    // Unscoped：软删除的 id=7 也在列表里，共 7 行。
    assert_eq!(data["total"], json!(7));
    let items = data["items"].as_array().expect("items");
    assert_eq!(items.len(), 7);
    assert_eq!(items[0]["id"], json!(9), "默认 id desc");
    assert_eq!(items[0]["username"], json!("guest-one"));
    // Go `User` JSON 形状：口令/PAT 键恒为空串；remark omitempty 缺键；
    // quota_display 为 0（Usd 展示 0/500000）。
    let first = &items[0];
    assert_eq!(first["password"], json!(""));
    assert_eq!(first["original_password"], json!(""));
    assert_eq!(first["verification_code"], json!(""));
    assert_eq!(first["group"], json!("default"));
    assert_eq!(first["quota"], json!(0));
    assert_eq!(first["quota_display"].as_f64(), Some(0.0));
    assert!(first.get("remark").is_none(), "空 remark 缺键");
    assert!(first.get("admin_permissions").is_none());
    assert!(first.get("qq_open_id").is_none());
    for forbidden in ["access_token", "auth_version", "DeletedAt"] {
        assert!(first.get(forbidden).is_none(), "{forbidden}");
    }
    // `/api/user`（无尾斜杠）同形。
    let body = assert_success(send(&app, Method::GET, "/api/user", Some(&admin), None).await).await;
    assert_eq!(body["data"]["total"], json!(7));
    // `ps` 兼容别名。
    let response = send(&app, Method::GET, "/api/user/?p=2&ps=2", Some(&admin), None).await;
    let body = assert_success(response).await;
    assert_eq!(body["data"]["page"], json!(2));
    assert_eq!(body["data"]["page_size"], json!(2));
    let items = body["data"]["items"].as_array().expect("items");
    assert_eq!(items.len(), 2);
    assert_eq!(
        items[0]["id"],
        json!(5),
        "第二页从 id=5 起（id desc 全序 9,7,5,4,...）"
    );
    // sort_by=quota&sort_order=asc：全部 quota=0，次级 id DESC 仍生效。
    let response = send(
        &app,
        Method::GET,
        "/api/user/?sort_by=quota&sort_order=asc",
        Some(&admin),
        None,
    )
    .await;
    let body = assert_success(response).await;
    let ids: Vec<i64> = body["data"]["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["id"].as_i64().expect("id"))
        .collect();
    assert_eq!(ids, vec![9, 7, 5, 4, 3, 2, 1]);

    // ---- search: keyword/group/role/status ----------------------------------
    let response = send(
        &app,
        Method::GET,
        "/api/user/search?keyword=common",
        Some(&admin),
        None,
    )
    .await;
    let body = assert_success(response).await;
    assert_eq!(
        body["data"]["total"],
        json!(3),
        "username LIKE 命中三个 common"
    );
    // 数值 keyword 走 id 命中。
    let response = send(
        &app,
        Method::GET,
        "/api/user/search?keyword=2",
        Some(&admin),
        None,
    )
    .await;
    let body = assert_success(response).await;
    assert_eq!(body["data"]["total"], json!(1));
    assert_eq!(body["data"]["items"][0]["id"], json!(2));
    // role 过滤。
    let response = send(
        &app,
        Method::GET,
        "/api/user/search?role=10",
        Some(&admin),
        None,
    )
    .await;
    let body = assert_success(response).await;
    assert_eq!(body["data"]["total"], json!(2));
    // status=-1 只看软删除行。
    let response = send(
        &app,
        Method::GET,
        "/api/user/search?status=-1",
        Some(&admin),
        None,
    )
    .await;
    let body = assert_success(response).await;
    assert_eq!(body["data"]["total"], json!(1));
    assert_eq!(body["data"]["items"][0]["id"], json!(7));
    // 非法 role/status 被忽略（Go Atoi 失败 → 不过滤）。
    let response = send(
        &app,
        Method::GET,
        "/api/user/search?role=x&status=x",
        Some(&admin),
        None,
    )
    .await;
    let body = assert_success(response).await;
    assert_eq!(body["data"]["total"], json!(7));
    // group 过滤；空结果。
    let response = send(
        &app,
        Method::GET,
        "/api/user/search?group=none",
        Some(&admin),
        None,
    )
    .await;
    let body = assert_success(response).await;
    assert_eq!(body["data"]["total"], json!(0));
    assert_eq!(body["data"]["items"], json!([]));

    // ---- get: id 解析与角色门 ------------------------------------------------
    assert_business_message(
        send(&app, Method::GET, "/api/user/abc", Some(&admin), None).await,
        &translated("common.invalid_params"),
    )
    .await;
    assert_business_message(
        send(&app, Method::GET, "/api/user/0", Some(&admin), None).await,
        MSG_ID_EMPTY,
    )
    .await;
    assert_business_message(
        send(&app, Method::GET, "/api/user/999", Some(&admin), None).await,
        &translated("user.not_exists"),
    )
    .await;
    // 软删除行不可见（GORM 默认作用域）。
    assert_business_message(
        send(&app, Method::GET, "/api/user/7", Some(&admin), None).await,
        &translated("user.not_exists"),
    )
    .await;
    // admin 不能看同级 admin（canManageTargetRole 同级拒绝）。
    assert_business_message(
        send(&app, Method::GET, "/api/user/3", Some(&admin), None).await,
        &translated("user.no_permission_same_level"),
    )
    .await;
    // root 看 admin：admin_permissions 恒在（root 全真）。
    let body =
        assert_success(send(&app, Method::GET, "/api/user/3", Some(&root), None).await).await;
    assert_eq!(body["data"]["id"], json!(3));
    let matrix = &body["data"]["admin_permissions"];
    assert_eq!(matrix["channel"]["read"], json!(true));
    assert_eq!(matrix["channel"]["sensitive_write"], json!(true));
    assert_eq!(matrix["system"]["settings"], json!(true));
    assert!(body["data"].get("qq_open_id").is_none(), "未绑定 QQ 缺键");
    // root 看 common：qq_open_id 有值；普通用户的矩阵全假。
    let body =
        assert_success(send(&app, Method::GET, "/api/user/2", Some(&root), None).await).await;
    assert_eq!(body["data"]["qq_open_id"], json!("qq-open-2"));
    assert_eq!(
        body["data"]["admin_permissions"]["channel"]["read"],
        json!(false)
    );
    // 普通用户目标的矩阵全假（Go `RoleFromSystemRole(1)` → 无基线角色，
    // `Capabilities` 全 false；与查看者角色无关）。
    let body =
        assert_success(send(&app, Method::GET, "/api/user/2", Some(&admin), None).await).await;
    assert_eq!(
        body["data"]["admin_permissions"]["channel"]["read"],
        json!(false)
    );
    assert_eq!(
        body["data"]["admin_permissions"]["channel"]["sensitive_write"],
        json!(false)
    );

    // ---- create --------------------------------------------------------------
    assert_business_message(
        send_json(
            &app,
            Method::POST,
            "/api/user/",
            &admin,
            &json!({"username": "newbie"}),
        )
        .await,
        &translated("common.invalid_params"),
    )
    .await;
    assert_business_message(
        send_json(
            &app,
            Method::POST,
            "/api/user/",
            &admin,
            &json!({"username": "", "password": "password123"}),
        )
        .await,
        &translated("common.invalid_params"),
    )
    .await;
    // 校验错误原文（validator Error 形状）。
    let response = send_json(
        &app,
        Method::POST,
        "/api/user/",
        &admin,
        &json!({"username": "newbie", "password": "short"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false));
    assert!(
        body["message"].as_str().expect("message").contains(
            "Key: 'User.Password' Error:Field validation for 'Password' failed on the 'min' tag"
        ),
        "{body}"
    );
    // admin 不能创建同级角色。
    assert_business_message(
        send_json(
            &app,
            Method::POST,
            "/api/user/",
            &admin,
            &json!({"username": "newadmin", "password": "password123", "role": 10}),
        )
        .await,
        &translated("user.cannot_create_higher_level"),
    )
    .await;
    // 非 root 携带 admin_permissions。
    assert_business_message(
        send_json(
            &app,
            Method::POST,
            "/api/user/",
            &admin,
            &json!({
                "username": "newbie",
                "password": "password123",
                "role": 1,
                "admin_permissions": {"channel": {"read": true}}
            }),
        )
        .await,
        MSG_ONLY_ROOT_PERMISSIONS,
    )
    .await;
    assert_eq!(
        row_count(&db, "users", "username = 'newbie'").await,
        0,
        "失败创建不落库"
    );
    // 成功创建：默认字段与 Go `InsertWithTx` 一致。
    let body = assert_success(
        send_json(
            &app,
            Method::POST,
            "/api/user/",
            &admin,
            &json!({"username": "newbie", "password": "password123"}),
        )
        .await,
    )
    .await;
    assert!(body.get("data").is_none());
    // 按 id 读取新行（seed 行最大 id=9，序列同步后新行 id=10）。
    let body =
        assert_success(send(&app, Method::GET, "/api/user/10", Some(&admin), None).await).await;
    assert_eq!(body["data"]["username"], json!("newbie"));
    assert_eq!(
        body["data"]["display_name"],
        json!("newbie"),
        "昵称默认取用户名"
    );
    assert_eq!(body["data"]["role"], json!(1));
    assert_eq!(body["data"]["status"], json!(1));
    assert_eq!(body["data"]["group"], json!("default"));
    assert_eq!(body["data"]["quota"], json!(0), "QuotaForNewUser 默认 0");
    assert_eq!(body["data"]["email"], json!(""), "cleanUser 不带邮箱");
    // 侧栏配置已由 finishInsert 初始化。
    assert_eq!(
        body["data"]["setting"],
        json!(
            r#"{"gotify_priority":0,"sidebar_modules":"{\"chat\":{\"chat\":true,\"enabled\":true,\"playground\":true},\"console\":{\"detail\":true,\"enabled\":true,\"log\":true,\"midjourney\":true,\"task\":true,\"token\":true},\"personal\":{\"enabled\":true,\"personal\":true,\"topup\":true}}"}"#
        )
    );
    // 口令已散列（非空、非原文）。
    let stored_hash = user_column_text(&db, 10, "password").await;
    assert!(!stored_hash.is_empty() && stored_hash != "password123");
    // 用户名唯一约束冲突 → 固定数据库错误（Go 原文回显 SQL 错误）。
    assert_business_message(
        send_json(
            &app,
            Method::POST,
            "/api/user/",
            &admin,
            &json!({"username": "newbie", "password": "password456"}),
        )
        .await,
        &translated("common.database_error"),
    )
    .await;
    // root 创建 admin 并写覆盖行：sensitive_write=true（基线假）→ allow，
    // read=false（基线真）→ deny；未提及的动作不写。
    let body = assert_success(
        send_json(
            &app,
            Method::POST,
            "/api/user/",
            &root,
            &json!({
                "username": "perm-admin",
                "password": "password123",
                "role": 10,
                "admin_permissions": {"channel": {"sensitive_write": true, "read": false}}
            }),
        )
        .await,
    )
    .await;
    assert!(body.get("data").is_none());
    assert_eq!(
        row_count(&db, "casbin_rule", "v0 = 'user:11' AND v1 = 'channel'").await,
        2,
        "allow sensitive_write + deny read"
    );
    assert_eq!(
        row_count(
            &db,
            "casbin_rule",
            "v0 = 'user:11' AND v1 = 'channel' AND v2 = 'sensitive_write' AND v3 = 'allow'"
        )
        .await,
        1
    );
    assert_eq!(
        row_count(
            &db,
            "casbin_rule",
            "v0 = 'user:11' AND v1 = 'channel' AND v2 = 'read' AND v3 = 'deny'"
        )
        .await,
        1
    );
    // root 创建普通用户且不带 admin_permissions：permissions==nil 分支对
    // 新用户无可清除行，行为等价于无操作（清除语义由 demote 用例验证）。
    assert_success(
        send_json(
            &app,
            Method::POST,
            "/api/user/",
            &root,
            &json!({"username": "cleared-target", "password": "password123", "role": 1}),
        )
        .await,
    )
    .await;
    let logs = audit_logs(&db).await;
    let last = &logs[logs.len() - 1];
    assert_eq!(last.2, "Created user cleared-target (role 1)");
    assert_eq!(last.3, "root-one");
    let other: Value = serde_json::from_str(&last.4).expect("other JSON");
    assert_eq!(other["op"]["action"], json!("user.create"));
    assert_eq!(other["op"]["params"]["username"], json!("cleared-target"));
    assert_eq!(other["op"]["params"]["role"], json!(1));

    // ---- update --------------------------------------------------------------
    assert_business_message(
        send_json(
            &app,
            Method::PUT,
            "/api/user/",
            &admin,
            &json!({"username": "x", "password": "password123"}),
        )
        .await,
        &translated("common.invalid_params"),
    )
    .await;
    assert_business_message(
        send_json(
            &app,
            Method::PUT,
            "/api/user/",
            &admin,
            &json!({"id": 5, "username": "", "password": "password123"}),
        )
        .await,
        &translated("common.invalid_params"),
    )
    .await;
    // 角色不可经 PUT 修改（请求角色非 guest 且与原值不同）。
    assert_business_message(
        send_json(
            &app,
            Method::PUT,
            "/api/user/",
            &admin,
            &json!({"id": 5, "username": "plain-common", "role": 10}),
        )
        .await,
        &translated("common.invalid_params"),
    )
    .await;
    // admin 不能更新同级。
    assert_business_message(
        send_json(
            &app,
            Method::PUT,
            "/api/user/",
            &admin,
            &json!({"id": 3, "username": "admin-two"}),
        )
        .await,
        &translated("user.no_permission_higher_level"),
    )
    .await;
    // 更新昵称/分组/备注：分组变化 → auth_version 递增 + 全部会话撤销。
    let body = assert_success(
        send_json(
            &app,
            Method::PUT,
            "/api/user/",
            &admin,
            &json!({
                "id": 5,
                "username": "plain-common",
                "display_name": "Renamed",
                "group": "vip",
                "remark": "note"
            }),
        )
        .await,
    )
    .await;
    assert!(body.get("data").is_none());
    assert_eq!(user_column_text(&db, 5, "display_name").await, "Renamed");
    assert_eq!(user_column_text(&db, 5, "\"group\"").await, "vip");
    assert_eq!(user_column_text(&db, 5, "remark").await, "note");
    assert_eq!(user_column_i64(&db, 5, "auth_version").await, 2);
    assert_eq!(session_status(&db, "sid-common").await, "revoked");
    // 第二次更新不带 group：map 语义写空串 → 再次触发版本递增与会话撤销。
    seed_session(&db, "sid-common2", 5, at).await;
    assert_success(
        send_json(
            &app,
            Method::PUT,
            "/api/user/",
            &admin,
            &json!({"id": 5, "username": "plain-common", "display_name": "Renamed2"}),
        )
        .await,
    )
    .await;
    assert_eq!(user_column_text(&db, 5, "\"group\"").await, "");
    assert_eq!(user_column_i64(&db, 5, "auth_version").await, 3);
    assert_eq!(session_status(&db, "sid-common2").await, "revoked");
    // 改密码：哈希变化 + 版本递增；空密码走占位符不修改。
    let old_hash = user_column_text(&db, 5, "password").await;
    assert_success(
        send_json(
            &app,
            Method::PUT,
            "/api/user/",
            &admin,
            &json!({"id": 5, "username": "plain-common", "password": "newpassword1"}),
        )
        .await,
    )
    .await;
    let new_hash = user_column_text(&db, 5, "password").await;
    assert!(!new_hash.is_empty() && new_hash != old_hash);
    assert_eq!(user_column_i64(&db, 5, "auth_version").await, 4);
    // 不改密码（空串占位往返）：哈希与版本都不变。
    assert_success(
        send_json(
            &app,
            Method::PUT,
            "/api/user/",
            &admin,
            &json!({"id": 5, "username": "plain-common"}),
        )
        .await,
    )
    .await;
    assert_eq!(user_column_text(&db, 5, "password").await, new_hash);
    assert_eq!(user_column_i64(&db, 5, "auth_version").await, 4);
    // 不存在目标。
    assert_business_message(
        send_json(
            &app,
            Method::PUT,
            "/api/user/",
            &admin,
            &json!({"id": 999, "username": "ghost"}),
        )
        .await,
        &translated("user.not_exists"),
    )
    .await;
    // 审计 user.update。
    let logs = audit_logs(&db).await;
    let last = &logs[logs.len() - 1];
    assert_eq!(last.2, "Updated user plain-common (ID: 5)");

    // ---- hard delete ---------------------------------------------------------
    assert_business_message(
        send(&app, Method::DELETE, "/api/user/abc", Some(&admin), None).await,
        &translated("common.invalid_params"),
    )
    .await;
    assert_business_message(
        send(&app, Method::DELETE, "/api/user/0", Some(&admin), None).await,
        MSG_ID_EMPTY,
    )
    .await;
    // admin 不能删除同级与 root（严格更高才可）。
    assert_business_message(
        send(&app, Method::DELETE, "/api/user/3", Some(&admin), None).await,
        &translated("user.no_permission_higher_level"),
    )
    .await;
    assert_business_message(
        send(&app, Method::DELETE, "/api/user/4", Some(&admin), None).await,
        &translated("user.no_permission_higher_level"),
    )
    .await;
    // root 硬删 admin-two（3）：用户行与全部认证数据消失。
    seed_session(&db, "sid-three", 3, at).await;
    seed_token(&db, 3, "tk-three").await;
    for table in [
        "two_fas",
        "passkey_credentials",
        "qq_bindings",
        "casbin_rule",
    ] {
        if table == "casbin_rule" {
            seed_rule(&db, "user:3", "channel", "read", "allow").await;
        } else {
            seed_one_column(&db, table, 3).await;
        }
    }
    let body =
        assert_success(send(&app, Method::DELETE, "/api/user/3", Some(&root), None).await).await;
    assert!(body.get("data").is_none());
    assert_eq!(row_count(&db, "users", "id = 3").await, 0, "硬删除不留行");
    assert_eq!(row_count(&db, "tokens", "user_id = 3").await, 0);
    assert_eq!(row_count(&db, "user_sessions", "user_id = 3").await, 0);
    assert_eq!(row_count(&db, "two_fas", "user_id = 3").await, 0);
    assert_eq!(
        row_count(&db, "two_fa_backup_codes", "user_id = 3").await,
        0
    );
    assert_eq!(
        row_count(&db, "passkey_credentials", "user_id = 3").await,
        0
    );
    assert_eq!(row_count(&db, "auth_flows", "user_id = 3").await, 0);
    assert_eq!(
        row_count(&db, "external_identity_claims", "user_id = 3").await,
        0
    );
    assert_eq!(
        row_count(&db, "user_oauth_bindings", "user_id = 3").await,
        0
    );
    assert_eq!(row_count(&db, "qq_bindings", "user_id = 3").await, 0);
    assert_eq!(row_count(&db, "casbin_rule", "v0 = 'user:3'").await, 0);
    // root 不能删除 root（同级严格拒绝）。
    assert_business_message(
        send(&app, Method::DELETE, "/api/user/4", Some(&root), None).await,
        &translated("user.no_permission_higher_level"),
    )
    .await;
    // 审计 user.delete。
    let logs = audit_logs(&db).await;
    let last = &logs[logs.len() - 1];
    assert_eq!(last.2, "Deleted user admin-two (ID: 3)");
    assert_eq!(last.3, "root-one");

    // ---- manage: disable/enable ----------------------------------------------
    assert_business_message(
        send_json(
            &app,
            Method::POST,
            "/api/user/manage",
            &admin,
            &json!({"id": 2, "action": "explode"}),
        )
        .await,
        &translated("common.invalid_params"),
    )
    .await;
    assert_business_message(
        send_json(
            &app,
            Method::POST,
            "/api/user/manage",
            &admin,
            &json!({"id": 4, "action": "disable"}),
        )
        .await,
        &translated("user.cannot_disable_root_user"),
    )
    .await;
    assert_business_message(
        send_json(
            &app,
            Method::POST,
            "/api/user/manage",
            &admin,
            &json!({"id": 999, "action": "disable"}),
        )
        .await,
        &translated("user.not_exists"),
    )
    .await;
    // disable：状态写库、版本递增、会话撤销、响应为全零结构 + role/status。
    let response = send_json(
        &app,
        Method::POST,
        "/api/user/manage",
        &admin,
        &json!({"id": 2, "action": "disable"}),
    )
    .await;
    let body = assert_success(response).await;
    assert_eq!(body["data"]["role"], json!(1));
    assert_eq!(body["data"]["status"], json!(2));
    assert_eq!(body["data"]["id"], json!(0), "其余字段为 Go 零值");
    assert_eq!(body["data"]["username"], json!(""));
    assert_eq!(user_column_i64(&db, 2, "status").await, 2);
    assert_eq!(user_column_i64(&db, 2, "auth_version").await, 2);
    assert_eq!(session_status(&db, "sid-target").await, "revoked");
    // enable：恢复，再递增一次。
    let response = send_json(
        &app,
        Method::POST,
        "/api/user/manage",
        &admin,
        &json!({"id": 2, "action": "enable"}),
    )
    .await;
    let body = assert_success(response).await;
    assert_eq!(body["data"]["status"], json!(1));
    assert_eq!(user_column_i64(&db, 2, "auth_version").await, 3);
    // 已启用的用户再 enable：无状态变化 → 不递增、不撤销。
    seed_session(&db, "sid-target2", 2, at).await;
    assert_success(
        send_json(
            &app,
            Method::POST,
            "/api/user/manage",
            &admin,
            &json!({"id": 2, "action": "enable"}),
        )
        .await,
    )
    .await;
    assert_eq!(user_column_i64(&db, 2, "auth_version").await, 3);
    assert_eq!(session_status(&db, "sid-target2").await, "active");

    // ---- manage: delete（软删除） ---------------------------------------------
    assert_business_message(
        send_json(
            &app,
            Method::POST,
            "/api/user/manage",
            &admin,
            &json!({"id": 4, "action": "delete"}),
        )
        .await,
        &translated("user.cannot_delete_root_user"),
    )
    .await;
    assert_success(
        send_json(
            &app,
            Method::POST,
            "/api/user/manage",
            &admin,
            &json!({"id": 2, "action": "delete"}),
        )
        .await,
    )
    .await;
    // 软删除：行仍在，deleted_at 非 NULL；QQ 绑定解绑；会话撤销。
    assert_eq!(row_count(&db, "users", "id = 2").await, 1);
    assert_eq!(
        row_count(&db, "users", "id = 2 AND deleted_at IS NOT NULL").await,
        1
    );
    assert_eq!(row_count(&db, "qq_bindings", "user_id = 2").await, 0);
    assert_eq!(session_status(&db, "sid-target2").await, "revoked");
    // 软删除目标再走 enable：scoped First 失败 → 固定数据库错误。
    assert_business_message(
        send_json(
            &app,
            Method::POST,
            "/api/user/manage",
            &admin,
            &json!({"id": 2, "action": "enable"}),
        )
        .await,
        &translated("common.database_error"),
    )
    .await;
    // 审计 user.manage（disable/enable/重复 enable/delete 四条；无变化的
    // enable 同样落审计，与 Go 逐字一致）。
    let logs = audit_logs(&db).await;
    let manage_logs: Vec<&(i64, i64, String, String, String)> = logs
        .iter()
        .filter(|log| log.2.starts_with("Performed "))
        .collect();
    assert_eq!(manage_logs.len(), 4, "{manage_logs:?}");
    assert_eq!(
        manage_logs[0].2,
        "Performed disable on user target-common (ID: 2)"
    );
    assert_eq!(
        manage_logs[3].2,
        "Performed delete on user target-common (ID: 2)"
    );

    // ---- manage: promote/demote ----------------------------------------------
    assert_business_message(
        send_json(
            &app,
            Method::POST,
            "/api/user/manage",
            &admin,
            &json!({"id": 5, "action": "promote"}),
        )
        .await,
        &translated("user.admin_cannot_promote"),
    )
    .await;
    assert_business_message(
        send_json(
            &app,
            Method::POST,
            "/api/user/manage",
            &root,
            &json!({"id": 4, "action": "promote"}),
        )
        .await,
        &translated("user.already_root"),
    )
    .await;
    assert_business_message(
        send_json(
            &app,
            Method::POST,
            "/api/user/manage",
            &root,
            &json!({"id": 4, "action": "demote"}),
        )
        .await,
        &translated("user.cannot_demote_self"),
    )
    .await;
    assert_business_message(
        send_json(
            &app,
            Method::POST,
            "/api/user/manage",
            &root,
            &json!({"id": 9, "action": "demote"}),
        )
        .await,
        &translated("user.already_common"),
    )
    .await;
    // promote common → admin：角色写库 + 版本递增 + 会话撤销。
    seed_session(&db, "sid-common3", 5, at).await;
    let response = send_json(
        &app,
        Method::POST,
        "/api/user/manage",
        &root,
        &json!({"id": 5, "action": "promote"}),
    )
    .await;
    let body = assert_success(response).await;
    assert_eq!(body["data"]["role"], json!(10));
    assert_eq!(body["data"]["status"], json!(1));
    assert_eq!(user_column_i64(&db, 5, "role").await, 10);
    assert_eq!(user_column_i64(&db, 5, "auth_version").await, 5);
    assert_eq!(session_status(&db, "sid-common3").await, "revoked");
    // 再 promote → root。
    assert_success(
        send_json(
            &app,
            Method::POST,
            "/api/user/manage",
            &root,
            &json!({"id": 5, "action": "promote"}),
        )
        .await,
    )
    .await;
    assert_eq!(user_column_i64(&db, 5, "role").await, 100);
    // demote：清 casbin 覆盖 + 版本递增 + admin_demote 撤销。
    seed_rule(&db, "user:5", "channel", "read", "allow").await;
    seed_session(&db, "sid-common4", 5, at).await;
    let response = send_json(
        &app,
        Method::POST,
        "/api/user/manage",
        &root,
        &json!({"id": 5, "action": "demote"}),
    )
    .await;
    let body = assert_success(response).await;
    assert_eq!(body["data"]["role"], json!(10));
    assert_eq!(user_column_i64(&db, 5, "role").await, 10);
    assert_eq!(user_column_i64(&db, 5, "auth_version").await, 7);
    assert_eq!(row_count(&db, "casbin_rule", "v0 = 'user:5'").await, 0);
    assert_eq!(session_status(&db, "sid-common4").await, "revoked");
    // 撤销原因区分：demote 为 admin_demote，promote 为 user_security_changed。
    backend!(db, pool, {
        let demote_reason: String = sqlx::query_scalar(
            "SELECT revoked_reason FROM user_sessions WHERE sid = 'sid-common4'",
        )
        .fetch_one(&pool)
        .await
        .expect("demote reason");
        assert_eq!(demote_reason, "admin_demote");
    });
    // 再 demote → common。
    assert_success(
        send_json(
            &app,
            Method::POST,
            "/api/user/manage",
            &root,
            &json!({"id": 5, "action": "demote"}),
        )
        .await,
    )
    .await;
    assert_eq!(user_column_i64(&db, 5, "role").await, 1);

    // ---- manage: add_quota ----------------------------------------------------
    // add：正数、value_display 换算、零值拒绝。
    assert_success(
        send_json(
            &app,
            Method::POST,
            "/api/user/manage",
            &admin,
            &json!({"id": 5, "action": "add_quota", "mode": "add", "value": 500}),
        )
        .await,
    )
    .await;
    assert_eq!(user_column_i64(&db, 5, "quota").await, 500);
    let response = send_json(
        &app,
        Method::POST,
        "/api/user/manage",
        &admin,
        &json!({"id": 5, "action": "add_quota", "mode": "add", "value_display": 2.0}),
    )
    .await;
    assert_success(response).await;
    assert_eq!(
        user_column_i64(&db, 5, "quota").await,
        500 + DISPLAY_TWO_IN_QUOTA
    );
    assert_business_message(
        send_json(
            &app,
            Method::POST,
            "/api/user/manage",
            &admin,
            &json!({"id": 5, "action": "add_quota", "mode": "add", "value": 0}),
        )
        .await,
        &translated("user.quota_change_zero"),
    )
    .await;
    // value_display 类型错误（字符串）→ 绑定失败。
    assert_business_message(
        send_json(
            &app,
            Method::POST,
            "/api/user/manage",
            &admin,
            &json!({"id": 5, "action": "add_quota", "mode": "add", "value_display": "x"}),
        )
        .await,
        &translated("common.invalid_params"),
    )
    .await;
    // subtract。
    assert_success(
        send_json(
            &app,
            Method::POST,
            "/api/user/manage",
            &admin,
            &json!({"id": 5, "action": "add_quota", "mode": "subtract", "value": 200}),
        )
        .await,
    )
    .await;
    assert_eq!(
        user_column_i64(&db, 5, "quota").await,
        500 + DISPLAY_TWO_IN_QUOTA - 200
    );
    // override：可正可负（Go 无正负守卫）。
    assert_success(
        send_json(
            &app,
            Method::POST,
            "/api/user/manage",
            &admin,
            &json!({"id": 5, "action": "add_quota", "mode": "override", "value": 42}),
        )
        .await,
    )
    .await;
    assert_eq!(user_column_i64(&db, 5, "quota").await, 42);
    assert_success(
        send_json(
            &app,
            Method::POST,
            "/api/user/manage",
            &admin,
            &json!({"id": 5, "action": "add_quota", "mode": "override", "value": -5}),
        )
        .await,
    )
    .await;
    assert_eq!(user_column_i64(&db, 5, "quota").await, -5);
    // 未知 mode。
    assert_business_message(
        send_json(
            &app,
            Method::POST,
            "/api/user/manage",
            &admin,
            &json!({"id": 5, "action": "add_quota", "mode": "multiply", "value": 1}),
        )
        .await,
        &translated("common.invalid_params"),
    )
    .await;
    // quota 审计：quota 参数为 LogQuota 展示字符串。
    let logs = audit_logs(&db).await;
    let quota_logs: Vec<&(i64, i64, String, String, String)> = logs
        .iter()
        .filter(|log| log.2.starts_with("Increased user quota"))
        .collect();
    assert_eq!(quota_logs.len(), 2, "{quota_logs:?}");
    assert_eq!(
        quota_logs[0].2,
        format!("Increased user quota by {LOG_QUOTA_500}")
    );
    let other: Value = serde_json::from_str(&quota_logs[0].4).expect("other JSON");
    assert_eq!(other["op"]["action"], json!("user.quota_add"));
    assert_eq!(
        other["op"]["params"]["quota"],
        json!(LOG_QUOTA_500.to_string())
    );

    // ---- PAT 鉴权（管理员 PAT 走同一门） ---------------------------------------
    let pat = format!("Bearer {PAT_ADMIN}");
    let body = assert_success(send(&app, Method::GET, "/api/user/", Some(&pat), None).await).await;
    assert_eq!(
        body["data"]["total"],
        json!(10),
        "种子 7 行 + newbie + perm-admin + cleared-target"
    );
    assert_success(
        send_json(
            &app,
            Method::POST,
            "/api/user/manage",
            &pat,
            &json!({"id": 10, "action": "disable"}),
        )
        .await,
    )
    .await;
    assert_eq!(user_column_i64(&db, 10, "status").await, 2);

    // ---- id=0 的 GORM struct 条件退化（按主键取第一行） -------------------------
    // Go `ManageUser` 对 id=0 的 `Unscoped().Where(&user).First(&user)` 退化为
    // 无条件 First：最低 id 的行（admin-one, id=1）成为目标。
    let response = send_json(
        &app,
        Method::POST,
        "/api/user/manage",
        &root,
        &json!({"id": 0, "action": "promote"}),
    )
    .await;
    let body = assert_success(response).await;
    assert_eq!(
        body["data"]["role"],
        json!(100),
        "id=1 的 admin 被升为 root"
    );
    assert_eq!(user_column_i64(&db, 1, "role").await, 100);
}

#[tokio::test]
async fn sqlite_admin_users_routes_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    run_contract(Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn postgres_admin_users_routes_contract() {
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
        "admin_users_routes_{}_{}",
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
