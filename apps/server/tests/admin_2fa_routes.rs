//! HTTP contracts for `GET /api/user/2fa/stats` and `DELETE /api/user/:id/2fa`.
//!
//! Runs only in remote CI. Every scenario uses an isolated synthetic fixture
//! (in-memory SQLite or an isolated PostgreSQL schema); no service is started.
//! The PostgreSQL test is skipped when `TEST_POSTGRES_DSN` is absent.
//!
//! Go references: `apps/api/internal/identity/manage_twofa.go:526-591`,
//! `apps/api/internal/identity/store_twofa.go:400-424`,
//! `apps/api/internal/transport/compose/register_api.go:204-223` (adminRoute:
//! only `security.AdminAuth()` — `userRoute` itself carries no group middleware —
//! and neither route has `DisableCache`).

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
    routing::{delete, get},
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
    AppState, RateLimiter, admin_twofa_http, auth as server_auth, limit::RateLimitSettings,
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

const SECRET: &str = "admin-2fa-routes-fixture-secret";
const PAT_ADMIN: &str = "pat-admin-one";

/// Go 硬编码中文（`manage_twofa.go`）：前端按字面量比对，不经 i18n。
const MSG_ID_FORMAT_ERROR: &str = "用户ID格式错误";
const MSG_ID_EMPTY_ERROR: &str = "id 为空！";
const MSG_ROLE_INSUFFICIENT: &str = "无权操作同级或更高级用户的2FA设置";
const MSG_NOT_ENABLED: &str = "用户未启用2FA";
const MSG_ADMIN_DISABLED: &str = "用户2FA已被强制禁用";
/// Go `auditContentTemplates["user.2fa_disable"]`（`usage/write_audit.go:25`）。
const AUDIT_CONTENT: &str = "Force-disabled two-factor authentication for the user";

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

/// `usage.Log` 的管理审计列集合（`usage/store_log.go:60-92`）。
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
        .route("/api/user/2fa/stats", get(admin_twofa_http::admin_stats))
        .route(
            "/api/user/{id}/2fa",
            delete(admin_twofa_http::admin_disable),
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
                TWO_FAS_SQLITE,
                BACKUP_CODES_SQLITE,
                LOGS_SQLITE,
            ] {
                exec(db, statement).await;
            }
        }
        Database::Postgres(_) => {
            for statement in [
                USERS_POSTGRES,
                SESSIONS,
                TWO_FAS_POSTGRES,
                BACKUP_CODES_POSTGRES,
                LOGS_POSTGRES,
            ] {
                exec(db, statement).await;
            }
        }
    }
}

async fn reset(db: &Database) {
    exec(db, "DELETE FROM logs").await;
    exec(db, "DELETE FROM two_fa_backup_codes").await;
    exec(db, "DELETE FROM two_fas").await;
    exec(db, "DELETE FROM user_sessions").await;
    exec(db, "DELETE FROM users").await;
}

/// Go `User.Role`：Guest=0 / Common=1 / Admin=10 / Root=100。
async fn seed_user(db: &Database, id: i64, username: &str, role: i64, pat: Option<&str>) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO users
                (id,username,display_name,role,status,"group",auth_version,access_token)
                VALUES ($1,$2,$3,1,1,'default',1,$4)"#,
        )
        .bind(id)
        .bind(username)
        .bind(role)
        .bind(pat)
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
                .expect("soft delete user")
        }
        Database::Postgres(pool) => {
            sqlx::query("UPDATE users SET deleted_at = to_timestamp($1::BIGINT) WHERE id = $2")
                .bind(now())
                .bind(id)
                .execute(pool)
                .await
                .expect("soft delete user")
        }
    };
}

async fn seed_session(db: &Database, sid: &str, user_id: i64, uv: i64, sv: i64, at: i64) {
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
        .bind(user_id)
        .bind(sv)
        .bind(uv)
        .bind(at)
        .bind(at + 3600)
        .execute(pool)
        .await
        .expect("seed session");
    });
}

async fn seed_factor(db: &Database, user_id: i64, secret: &str, enabled: bool) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO two_fas (user_id, secret, is_enabled, failed_attempts)
                VALUES ($1,$2,$3,0)"#,
        )
        .bind(user_id)
        .bind(secret)
        .bind(enabled)
        .execute(pool)
        .await
        .expect("seed factor");
    });
}

async fn seed_backup_code(db: &Database, user_id: i64, code_hash: &str) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO two_fa_backup_codes (user_id, code_hash, is_used)
                VALUES ($1,$2,0)"#,
        )
        .bind(user_id)
        .bind(code_hash)
        .execute(pool)
        .await
        .expect("seed backup code");
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

async fn send_delete(state: &AppState, path: &str, authorization: &str) -> Response {
    send(state, Method::DELETE, path, Some(authorization), None).await
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

/// 两条 admin 路由都不挂 `DisableCache`（Go `register_api.go:222-223`）。
fn assert_no_cache_headers(headers: &HeaderMap) {
    assert!(!headers.contains_key(header::CACHE_CONTROL));
    assert!(!headers.contains_key(header::PRAGMA));
    assert!(!headers.contains_key(header::EXPIRES));
}

/// `UserAuth` 的拒绝：401 + 固定 code，且无缓存头。
async fn assert_auth_failure(response: Response, code: &str) {
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_no_cache_headers(response.headers());
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false));
    assert_eq!(body["code"], json!(code));
}

/// Go `AdminAuth` 对非 admin 的拒绝：403（`authenticate.go:54-57`）。
async fn assert_forbidden(response: Response) {
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_no_cache_headers(response.headers());
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false));
    assert_eq!(body["code"], json!("AUTH_INSUFFICIENT_PRIVILEGE"));
    assert_eq!(
        body["message"],
        json!(translated("auth.insufficient_privilege"))
    );
}

/// Go `common.H{"success":false,...}`：HTTP 200 业务失败，无缓存头。
async fn assert_business_message(response: Response, message: &str) -> Value {
    assert_eq!(response.status(), StatusCode::OK, "{message}");
    assert_no_cache_headers(response.headers());
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false), "{body}");
    assert_eq!(body["message"], json!(message), "{body}");
    body
}

async fn assert_success_message(response: Response, message: &str) -> Value {
    assert_eq!(response.status(), StatusCode::OK, "{message}");
    assert_no_cache_headers(response.headers());
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true), "{body}");
    assert_eq!(body["message"], json!(message), "{body}");
    body
}

async fn factor_rows(db: &Database, user_id: i64) -> i64 {
    backend!(db, pool, {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM two_fas WHERE user_id=$1")
            .bind(user_id)
            .fetch_one(pool)
            .await
            .expect("factor rows")
    })
}

async fn backup_code_rows(db: &Database, user_id: i64) -> i64 {
    backend!(db, pool, {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM two_fa_backup_codes WHERE user_id=$1")
            .bind(user_id)
            .fetch_one(pool)
            .await
            .expect("backup code rows")
    })
}

async fn stored_auth_version(db: &Database, user_id: i64) -> i64 {
    backend!(db, pool, {
        sqlx::query_scalar::<_, i64>("SELECT CAST(auth_version AS BIGINT) FROM users WHERE id=$1")
            .bind(user_id)
            .fetch_one(pool)
            .await
            .expect("stored auth version")
    })
}

/// `logs` 行的最小投影：归属用户、类型、英文兜底文案、用户名、`other` JSON。
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

async fn seed_all(db: &Database) {
    // id=1 管理员（PAT + 会话），2/8 启用 2FA 的普通用户，3 另一管理员（启用），
    // 4 root，5 无 2FA 的普通用户，6 仅有待验证因子，7 已软删除，9 guest。
    // 注意 Go 的 `enabled_users` 只统计 `two_fas` 行本身，与所属用户是否软删除
    // 无关；这里不给 7 配因子，保持断言聚焦"用户维度"的软删除排除。
    seed_user(db, 1, "admin-one", 10, Some(PAT_ADMIN)).await;
    seed_user(db, 2, "target-common", 1, None).await;
    seed_user(db, 3, "admin-two", 10, None).await;
    seed_user(db, 4, "root-one", 100, None).await;
    seed_user(db, 5, "plain-common", 1, None).await;
    seed_user(db, 6, "pending-common", 1, None).await;
    seed_user(db, 7, "deleted-common", 1, None).await;
    seed_user(db, 8, "common-twofa", 1, None).await;
    seed_user(db, 9, "guest-one", 0, None).await;
    seed_factor(db, 2, "SECRETONE", true).await;
    seed_backup_code(db, 2, "fixture-hash-one").await;
    seed_backup_code(db, 2, "fixture-hash-two").await;
    seed_factor(db, 3, "SECRETTWO", true).await;
    seed_factor(db, 6, "SECRETPENDING", false).await;
    seed_factor(db, 8, "SECRETTHREE", true).await;
    soft_delete_user(db, 7).await;
    let at = now();
    seed_session(db, "sid-admin", 1, 1, 1, at).await;
    seed_session(db, "sid-root", 4, 1, 1, at).await;
    seed_session(db, "sid-common", 5, 1, 1, at).await;
    seed_session(db, "sid-guest", 9, 1, 1, at).await;
}

fn admin_token() -> String {
    let at = now();
    format!("Bearer {}", jwt(1, "sid-admin", 1, 1, at))
}

fn root_token() -> String {
    let at = now();
    format!("Bearer {}", jwt(4, "sid-root", 1, 1, at))
}

fn common_token() -> String {
    let at = now();
    format!("Bearer {}", jwt(5, "sid-common", 1, 1, at))
}

fn guest_token() -> String {
    let at = now();
    format!("Bearer {}", jwt(9, "sid-guest", 1, 1, at))
}

async fn run_contract(db: Database) {
    create_schema(&db).await;
    reset(&db).await;
    seed_all(&db).await;
    let app = state(&db);
    let admin = admin_token();
    let root = root_token();
    let common = common_token();
    let guest = guest_token();

    // ---- guard chain: Go `security.AdminAuth()` only -----------------------
    // 无凭据：401（凭据分类失败，`writeDashboardAuthError`）。
    assert_auth_failure(
        send(&app, Method::GET, "/api/user/2fa/stats", None, None).await,
        "AUTH_UNAUTHORIZED",
    )
    .await;
    assert_auth_failure(
        send(&app, Method::DELETE, "/api/user/2/2fa", None, None).await,
        "AUTH_UNAUTHORIZED",
    )
    .await;
    // 普通用户与 guest：403 AUTH_INSUFFICIENT_PRIVILEGE（`authenticate.go:54-57`），
    // 不是 401——AdminAuth 的角色检查在 UserAuth 的最低角色检查之前。
    assert_forbidden(
        send(
            &app,
            Method::GET,
            "/api/user/2fa/stats",
            Some(&common),
            None,
        )
        .await,
    )
    .await;
    assert_forbidden(send_delete(&app, "/api/user/2/2fa", &common).await).await;
    assert_forbidden(send(&app, Method::GET, "/api/user/2fa/stats", Some(&guest), None).await)
        .await;
    assert_forbidden(send_delete(&app, "/api/user/2/2fa", &guest).await).await;

    // ---- stats: soft-deleted users excluded, rate is a percent string ------
    // 未删除用户 1/2/3/4/5/6/8/9 = 8；启用因子 2/3/8 = 3；3/8 = 37.5%。
    let response = send(&app, Method::GET, "/api/user/2fa/stats", Some(&admin), None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_no_cache_headers(response.headers());
    let body = body_json(response).await;
    assert_eq!(
        body,
        json!({
            "success": true,
            "message": "",
            "data": {
                "total_users": 8,
                "enabled_users": 3,
                "enabled_rate": "37.5%",
            },
        })
    );
    // root 也满足 role >= 10。
    let response = send(&app, Method::GET, "/api/user/2fa/stats", Some(&root), None).await;
    let body = body_json(response).await;
    assert_eq!(body["data"]["enabled_users"], json!(3));

    // ---- disable: id parsing ----------------------------------------------
    assert_business_message(
        send_delete(&app, "/api/user/abc/2fa", &admin).await,
        MSG_ID_FORMAT_ERROR,
    )
    .await;
    assert_business_message(
        send_delete(&app, "/api/user/99999999999999999999/2fa", &admin).await,
        MSG_ID_FORMAT_ERROR,
    )
    .await;
    // Go `GetUserById(0)` 的固定文案。
    assert_business_message(
        send_delete(&app, "/api/user/0/2fa", &admin).await,
        MSG_ID_EMPTY_ERROR,
    )
    .await;

    // ---- disable: target lookup -------------------------------------------
    // 不存在的用户与已软删除用户都看不见（GORM 作用域）。
    assert_business_message(
        send_delete(&app, "/api/user/999/2fa", &admin).await,
        translated("twofa.user_not_found"),
    )
    .await;
    assert_business_message(
        send_delete(&app, "/api/user/7/2fa", &admin).await,
        translated("twofa.user_not_found"),
    )
    .await;
    // 目标存在但没有启用 2FA（无因子 / 仅有待验证因子）。
    assert_business_message(
        send_delete(&app, "/api/user/5/2fa", &admin).await,
        MSG_NOT_ENABLED,
    )
    .await;
    assert_business_message(
        send_delete(&app, "/api/user/6/2fa", &admin).await,
        MSG_NOT_ENABLED,
    )
    .await;
    assert_eq!(factor_rows(&db, 6).await, 1);
    assert_eq!(stored_auth_version(&db, 6).await, 1);

    // ---- disable: canManageTargetRole matrix --------------------------------
    // admin 不能动同级 admin，也不能动 root；目标因子保持原状。
    assert_business_message(
        send_delete(&app, "/api/user/3/2fa", &admin).await,
        MSG_ROLE_INSUFFICIENT,
    )
    .await;
    assert_business_message(
        send_delete(&app, "/api/user/4/2fa", &admin).await,
        MSG_ROLE_INSUFFICIENT,
    )
    .await;
    assert_eq!(factor_rows(&db, 3).await, 1);
    assert_eq!(stored_auth_version(&db, 3).await, 1);
    assert!(audit_logs(&db).await.is_empty(), "被拒绝的请求不写审计");

    // ---- disable: root force-disables an admin ------------------------------
    let body = assert_success_message(
        send_delete(&app, "/api/user/3/2fa", &root).await,
        MSG_ADMIN_DISABLED,
    )
    .await;
    assert!(body.get("data").is_none(), "成功后无 data 字段");
    assert_eq!(factor_rows(&db, 3).await, 0);
    assert_eq!(stored_auth_version(&db, 3).await, 2);

    // ---- disable: admin force-disables a common user ------------------------
    let body = assert_success_message(
        send_delete(&app, "/api/user/2/2fa", &admin).await,
        MSG_ADMIN_DISABLED,
    )
    .await;
    assert!(body.get("data").is_none());
    // 因子与备用码都被硬删除（Go `DisableTwoFAWithAuthVersion`）。
    assert_eq!(factor_rows(&db, 2).await, 0);
    assert_eq!(backup_code_rows(&db, 2).await, 0);
    assert_eq!(stored_auth_version(&db, 2).await, 2);

    // ---- disable: personal access token authenticates as admin --------------
    let pat = format!("Bearer {PAT_ADMIN}");
    assert_success_message(
        send_delete(&app, "/api/user/8/2fa", &pat).await,
        MSG_ADMIN_DISABLED,
    )
    .await;
    assert_eq!(factor_rows(&db, 8).await, 0);
    assert_eq!(stored_auth_version(&db, 8).await, 2);

    // ---- audit: one manage log per success -----------------------------------
    let logs = audit_logs(&db).await;
    assert_eq!(logs.len(), 3, "{logs:?}");
    // Go `RecordManageAuditFor`：日志归属操作者；op 携带 action 与 target_user_id。
    let (operator, log_type, content, username, other) = &logs[0];
    assert_eq!(*operator, 4, "root 操作，日志归属 root");
    assert_eq!(*log_type, 3, "Go LogTypeManage");
    assert_eq!(content, AUDIT_CONTENT);
    assert_eq!(username, "root-one");
    let other: Value = serde_json::from_str(other).expect("other JSON");
    assert_eq!(other["op"]["action"], json!("user.2fa_disable"));
    assert_eq!(other["op"]["params"]["target_user_id"], json!(3));
    assert_eq!(other["admin_info"]["admin_id"], json!(4));
    assert_eq!(other["admin_info"]["admin_username"], json!("root-one"));
    assert_eq!(other["admin_info"]["admin_role"], json!(100));
    assert_eq!(other["admin_info"]["auth_method"], json!("session"));
    let (operator, _log_type, _content, _username, other) = &logs[2];
    assert_eq!(*operator, 1, "PAT 操作同样归属管理员");
    let other: Value = serde_json::from_str(other).expect("other JSON");
    assert_eq!(other["op"]["params"]["target_user_id"], json!(8));
    assert_eq!(other["admin_info"]["auth_method"], json!("access_token"));

    // ---- stats after the disables --------------------------------------------
    let body =
        body_json(send(&app, Method::GET, "/api/user/2fa/stats", Some(&admin), None).await).await;
    assert_eq!(
        body["data"],
        json!({
            "total_users": 8,
            "enabled_users": 0,
            "enabled_rate": "0.0%",
        })
    );
}

#[tokio::test]
async fn sqlite_admin_2fa_routes_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    run_contract(Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn postgres_admin_2fa_routes_contract() {
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
        "admin_2fa_routes_{}_{}",
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
