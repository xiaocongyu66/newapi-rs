//! HTTP contracts for the four OAuth binding routes:
//! `GET /api/user/oauth/bindings`, `DELETE /api/user/oauth/bindings/:provider_id`
//! (self) and the two admin variants at `/api/user/:id/oauth/bindings`.
//!
//! Runs only in remote CI. Every scenario uses an isolated synthetic fixture
//! (in-memory SQLite or an isolated PostgreSQL schema); no service is started.
//! The PostgreSQL test is skipped when `TEST_POSTGRES_DSN` is absent.
//!
//! Go references: `apps/api/internal/identity/bind_custom_oauth.go:467-582`,
//! `register_api.go:200-212` (selfRoute / adminRoute wiring),
//! `security/audit_access.go:21+83-147` (admin DELETE fallback audit),
//! `store_users.go:411-413` (`GetUserById` id==0), `manage_users.go:374-376`
//! (`canManageTargetRole`).

use std::sync::atomic::{AtomicU64, Ordering};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Method, Request, StatusCode, header},
    middleware,
    response::Response,
    routing::{delete, get},
};
use newapi_server::{AppState, auth as server_auth, oauth_bindings_http};
use newapi_storage::Database;
use serde_json::{Value, json};
use sqlx::{
    ConnectOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::SqlitePoolOptions,
};
use tower::ServiceExt;

static NEXT: AtomicU64 = AtomicU64::new(0);

const SECRET: &str = "oauth-binding-routes-fixture-secret";

/// 每个 fixture 用户一个唯一 PAT，避免跨测试串味。
const PAT_COMMON: &str = "pat-oauth-common";
const PAT_ADMIN: &str = "pat-oauth-admin";
const PAT_ROOT: &str = "pat-oauth-root";
const PAT_GUEST: &str = "pat-oauth-guest";
const PAT_EMPTY: &str = "pat-oauth-empty";

/// Go 硬编码字面量（前端按字面量比对，不经 i18n）。
const MSG_INVALID_PROVIDER_ID: &str = "无效的提供商 ID";
const MSG_UNBOUND: &str = "解绑成功";
const MSG_INVALID_USER_ID: &str = "invalid user id";
const MSG_NO_PERMISSION: &str = "no permission";
const MSG_INVALID_PROVIDER_ID_ADMIN: &str = "invalid provider id";
const MSG_UNBOUND_ADMIN: &str = "success";
const MSG_USER_ID_EMPTY: &str = "id 为空！";

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
    oidc_id BIGINT, wechat_id TEXT, telegram_id TEXT, "group" TEXT,
    quota BIGINT, used_quota BIGINT, request_count BIGINT, aff_code TEXT,
    aff_count BIGINT, aff_quota BIGINT, aff_history BIGINT, inviter_id BIGINT,
    linux_do_id TEXT, setting TEXT, stripe_customer TEXT, auth_version BIGINT,
    access_token TEXT, deleted_at TIMESTAMPTZ, password TEXT
)"#;

/// Go `identity.CustomOAuthProvider`（`resolve_oauth_provider.go:41-68`）里
/// 响应用到的三列；其余端点/密钥列由生产 schema 提供，本切片不读取。
const PROVIDERS_SQLITE: &str = r#"CREATE TABLE custom_oauth_providers (
    id INTEGER PRIMARY KEY,
    name VARCHAR(64) NOT NULL,
    slug VARCHAR(64) NOT NULL,
    icon VARCHAR(128) DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 0
)"#;

const PROVIDERS_POSTGRES: &str = r#"CREATE TABLE custom_oauth_providers (
    id BIGINT PRIMARY KEY,
    name VARCHAR(64) NOT NULL,
    slug VARCHAR(64) NOT NULL,
    icon VARCHAR(128) DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT FALSE
)"#;

/// Go `identity.UserOAuthBinding`（`bind_oauth.go:12-21`）。`created_at` 只在
/// 真实 schema 里存在，`GetUserOAuthBindingsByUserId` 不读它。
const BINDINGS_SQLITE: &str = r#"CREATE TABLE user_oauth_bindings (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    provider_id INTEGER NOT NULL,
    provider_user_id VARCHAR(256) NOT NULL,
    created_at BIGINT
)"#;

const BINDINGS_POSTGRES: &str = r#"CREATE TABLE user_oauth_bindings (
    id BIGINT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    provider_id BIGINT NOT NULL,
    provider_user_id VARCHAR(256) NOT NULL,
    created_at BIGINT
)"#;

/// `usage.Log` 的审计列集合（`usage/store_log.go:63-92`）。
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

/// Go `selfRoute` 两条路由 + `adminRoute` 两条路由；本端口与 http.rs 的注册
/// 保持同一形状（静态段优先于参数段）。
fn router(state: AppState) -> Router {
    // 与 http.rs 一致：self 两条只挂 `UserAuth`，admin 两条只挂 `AdminAuth`。
    // 两类路由必须分开布层——叠在一起会让 self 路由也要求 admin 角色。
    let self_routes = Router::new()
        .route(
            "/api/user/oauth/bindings",
            get(oauth_bindings_http::user_bindings),
        )
        .route(
            "/api/user/oauth/bindings/{provider_id}",
            delete(oauth_bindings_http::unbind),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            server_auth::user_auth,
        ));
    let admin_routes = Router::new()
        .route(
            "/api/user/{id}/oauth/bindings",
            get(oauth_bindings_http::admin_user_bindings),
        )
        .route(
            "/api/user/{id}/oauth/bindings/{provider_id}",
            delete(oauth_bindings_http::admin_unbind),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            server_auth::admin_auth,
        ));
    self_routes.merge(admin_routes).with_state(state)
}

fn state(db: &Database) -> AppState {
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

async fn create_schema(db: &Database) {
    match db {
        Database::Sqlite(_) => {
            for statement in [USERS_SQLITE, PROVIDERS_SQLITE, BINDINGS_SQLITE, LOGS_SQLITE] {
                exec(db, statement).await;
            }
        }
        Database::Postgres(_) => {
            for statement in [
                USERS_POSTGRES,
                PROVIDERS_POSTGRES,
                BINDINGS_POSTGRES,
                LOGS_POSTGRES,
            ] {
                exec(db, statement).await;
            }
        }
    }
}

async fn seed_user(db: &Database, id: i64, username: &str, role: i64, pat: Option<&str>) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO users (id,username,display_name,role,status,"group",
                                 auth_version,access_token)
               VALUES ($1,$2,$2,$3,1,'default',1,$4)"#,
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

async fn soft_delete_user(db: &Database, id: i64) {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query("UPDATE users SET deleted_at = datetime('now') WHERE id = $1")
                .bind(id)
                .execute(pool)
                .await
                .expect("soft delete user");
        }
        Database::Postgres(pool) => {
            sqlx::query("UPDATE users SET deleted_at = CURRENT_TIMESTAMP WHERE id = $1")
                .bind(id)
                .execute(pool)
                .await
                .expect("soft delete user");
        }
    }
}

async fn seed_provider(db: &Database, id: i64, name: &str, slug: &str, icon: &str) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO custom_oauth_providers (id,name,slug,icon,enabled)
               VALUES ($1,$2,$3,$4,true)"#,
        )
        .bind(id)
        .bind(name)
        .bind(slug)
        .bind(icon)
        .execute(pool)
        .await
        .expect("seed provider");
    });
}

async fn seed_binding(db: &Database, id: i64, user_id: i64, provider_id: i64, subject: &str) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO user_oauth_bindings (id,user_id,provider_id,provider_user_id,created_at)
               VALUES ($1,$2,$3,$4,0)"#,
        )
        .bind(id)
        .bind(user_id)
        .bind(provider_id)
        .bind(subject)
        .execute(pool)
        .await
        .expect("seed binding");
    });
}

/// `user_oauth_bindings` 的 `(provider_id, provider_user_id)` 行，按 id 升序。
async fn stored_bindings(db: &Database, user_id: i64) -> Vec<(i64, String)> {
    backend!(db, pool, {
        sqlx::query_as::<_, (i64, String)>(
            "SELECT CAST(provider_id AS BIGINT), provider_user_id \
             FROM user_oauth_bindings WHERE user_id = $1 ORDER BY id",
        )
        .bind(user_id)
        .fetch_all(pool)
        .await
        .expect("stored bindings")
    })
}

/// `logs` 行的最小投影：归属、类型、content、用户名、`other` JSON。
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

async fn send(
    state: &AppState,
    method: Method,
    path: &str,
    authorization: Option<&str>,
) -> Response {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::ACCEPT_LANGUAGE, "en");
    if let Some(value) = authorization {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    router(state.clone())
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn get_with(state: &AppState, path: &str, authorization: Option<&str>) -> Response {
    send(state, Method::GET, path, authorization).await
}

async fn delete_with(state: &AppState, path: &str, authorization: Option<&str>) -> Response {
    send(state, Method::DELETE, path, authorization).await
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

/// 四条路由都不挂 `DisableCache`（Go `register_api.go:200-212`）。
fn assert_no_cache_headers(headers: &HeaderMap) {
    assert!(!headers.contains_key(header::CACHE_CONTROL));
    assert!(!headers.contains_key(header::PRAGMA));
    assert!(!headers.contains_key(header::EXPIRES));
}

/// Go `common.CtxApiErrorMsg`：HTTP 200 + `{success:false,message}`，无 data。
async fn assert_business_message(response: Response, message: &str) -> Value {
    assert_eq!(response.status(), StatusCode::OK, "{message}");
    assert_no_cache_headers(response.headers());
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false), "{body}");
    assert_eq!(body["message"], json!(message), "{body}");
    assert!(body.get("data").is_none(), "unexpected data: {body}");
    body
}

/// Go 手写成功体：HTTP 200 + `{success:true,message}`。
async fn assert_success_message(response: Response, message: &str) -> Value {
    assert_eq!(response.status(), StatusCode::OK, "{message}");
    assert_no_cache_headers(response.headers());
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true), "{body}");
    assert_eq!(body["message"], json!(message), "{body}");
    assert!(body.get("data").is_none(), "unexpected data: {body}");
    body
}

/// Go 的 GET 成功体：`{success:true,message:"",data:[...]}`。
async fn assert_bindings(response: Response, expected: &Value) -> Value {
    assert_eq!(response.status(), StatusCode::OK, "{expected}");
    assert_no_cache_headers(response.headers());
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true), "{body}");
    assert_eq!(body["message"], json!(""), "GET 成功带空 message");
    assert_eq!(body["data"], *expected, "{body}");
    assert!(body["data"].is_array(), "data 必须是数组");
    body
}

/// 用户矩阵：common/admin/root/guest 各一个 PAT，另有无绑定的普通用户、
/// 绑定的目标普通用户、同级 admin 目标、软删除目标。
async fn seed_users(db: &Database) {
    seed_user(db, 1, "fixture-common", 1, Some(PAT_COMMON)).await;
    seed_user(db, 2, "fixture-admin", 10, Some(PAT_ADMIN)).await;
    seed_user(db, 3, "fixture-root", 100, Some(PAT_ROOT)).await;
    seed_user(db, 4, "fixture-guest", 0, Some(PAT_GUEST)).await;
    seed_user(db, 5, "fixture-empty", 1, Some(PAT_EMPTY)).await;
    seed_user(db, 6, "fixture-target", 1, None).await;
    seed_user(db, 7, "fixture-admin-two", 10, None).await;
    seed_user(db, 8, "fixture-deleted", 1, None).await;
}

async fn seed_providers(db: &Database) {
    seed_provider(db, 11, "GitHub Enterprise", "github-enterprise", "github").await;
    seed_provider(db, 12, "GitLab CE", "gitlab-ce", "").await;
    seed_provider(db, 13, "Okta", "okta", "okta").await;
}

// ---------------------------------------------------------------------------
// self 路由
// ---------------------------------------------------------------------------

async fn run_self_contract(db: Database) {
    create_schema(&db).await;
    seed_users(&db).await;
    seed_providers(&db).await;
    let app = state(&db);
    let authorization = format!("Bearer {PAT_COMMON}");
    let empty_authorization = format!("Bearer {PAT_EMPTY}");

    // ---- 鉴权：UserAuth 拦截无凭据 ----------------------------------------
    assert_eq!(
        get_with(&app, "/api/user/oauth/bindings", None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        delete_with(&app, "/api/user/oauth/bindings/11", None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    // 坏凭据同样 401，且不写缓存头。
    let response = get_with(&app, "/api/user/oauth/bindings", Some("Bearer nope")).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_no_cache_headers(response.headers());

    // ---- 空列表：Go `make(..., 0, len)` 序列化成 [] 而非 null ---------------
    assert_bindings(
        get_with(&app, "/api/user/oauth/bindings", Some(&empty_authorization)).await,
        &json!([]),
    )
    .await;

    // ---- 绑定列表 + 缺失提供商被静默跳过 ---------------------------------
    seed_binding(&db, 1, 1, 11, "gh-self").await;
    seed_binding(&db, 2, 1, 12, "gl-self").await;
    // provider 999 不存在：Go 的 `GetCustomOAuthProviderById` 失败后 continue。
    seed_binding(&db, 3, 1, 999, "phantom-self").await;
    seed_binding(&db, 4, 1, 13, "okta-self").await;
    assert_bindings(
        get_with(&app, "/api/user/oauth/bindings", Some(&authorization)).await,
        &json!([
            {
                "provider_id": 11,
                "provider_name": "GitHub Enterprise",
                "provider_slug": "github-enterprise",
                "provider_icon": "github",
                "provider_user_id": "gh-self",
            },
            {
                "provider_id": 12,
                "provider_name": "GitLab CE",
                "provider_slug": "gitlab-ce",
                "provider_icon": "",
                "provider_user_id": "gl-self",
            },
            {
                "provider_id": 13,
                "provider_name": "Okta",
                "provider_slug": "okta",
                "provider_icon": "okta",
                "provider_user_id": "okta-self",
            },
        ]),
    )
    .await;

    // ---- provider_id 解析分支（硬编码中文） --------------------------------
    // 只取能作为单个路径段出现的形态：空串与带空格段根本无法路由到
    // `{provider_id}`（Axum 对无法 percent 解码的段回 400），Go 的
    // `strconv.Atoi` 分支只覆盖真正到达 handler 的文本。
    for provider_id in ["abc", "99999999999999999999", "0x11", "1_1", "+1a"] {
        assert_business_message(
            delete_with(
                &app,
                &format!("/api/user/oauth/bindings/{provider_id}"),
                Some(&authorization),
            )
            .await,
            MSG_INVALID_PROVIDER_ID,
        )
        .await;
    }
    // 解析失败的请求不改动绑定表。
    assert_eq!(stored_bindings(&db, 1).await.len(), 4);

    // ---- 解绑成功：硬编码中文消息，无 data 键 ------------------------------
    assert_success_message(
        delete_with(&app, "/api/user/oauth/bindings/12", Some(&authorization)).await,
        MSG_UNBOUND,
    )
    .await;
    assert_eq!(stored_bindings(&db, 1).await.len(), 3);
    assert_bindings(
        get_with(&app, "/api/user/oauth/bindings", Some(&authorization)).await,
        &json!([
            {
                "provider_id": 11,
                "provider_name": "GitHub Enterprise",
                "provider_slug": "github-enterprise",
                "provider_icon": "github",
                "provider_user_id": "gh-self",
            },
            {
                "provider_id": 13,
                "provider_name": "Okta",
                "provider_slug": "okta",
                "provider_icon": "okta",
                "provider_user_id": "okta-self",
            },
        ]),
    )
    .await;

    // ---- 幂等：解绑一条不存在的绑定同样成功 --------------------------------
    // Go 的 GORM `Delete` 不把零行匹配当错误；仓储层同样不把行数当错误。
    assert_success_message(
        delete_with(&app, "/api/user/oauth/bindings/9999", Some(&authorization)).await,
        MSG_UNBOUND,
    )
    .await;
    assert_eq!(stored_bindings(&db, 1).await.len(), 3);

    // ---- 其他用户的绑定不受影响 -------------------------------------------
    seed_binding(&db, 10, 6, 11, "gh-target").await;
    assert_bindings(
        get_with(&app, "/api/user/oauth/bindings", Some(&authorization)).await,
        &json!([
            {
                "provider_id": 11,
                "provider_name": "GitHub Enterprise",
                "provider_slug": "github-enterprise",
                "provider_icon": "github",
                "provider_user_id": "gh-self",
            },
            {
                "provider_id": 13,
                "provider_name": "Okta",
                "provider_slug": "okta",
                "provider_icon": "okta",
                "provider_user_id": "okta-self",
            },
        ]),
    )
    .await;
    // self 路线解绑只影响自己的行：目标用户 6 的绑定仍在。
    assert_success_message(
        delete_with(&app, "/api/user/oauth/bindings/11", Some(&authorization)).await,
        MSG_UNBOUND,
    )
    .await;
    assert_eq!(stored_bindings(&db, 1).await.len(), 2);
    assert_eq!(stored_bindings(&db, 6).await.len(), 1);

    // ---- self 路线不写审计（UserAuth 的 minRole < RoleAdminUser） ----------
    assert!(audit_logs(&db).await.is_empty(), "self 路线无审计");
}

// ---------------------------------------------------------------------------
// admin 路由
// ---------------------------------------------------------------------------

async fn run_admin_contract(db: Database) {
    create_schema(&db).await;
    seed_users(&db).await;
    seed_providers(&db).await;
    soft_delete_user(&db, 8).await;
    let app = state(&db);
    let common = format!("Bearer {PAT_COMMON}");
    let admin = format!("Bearer {PAT_ADMIN}");
    let root = format!("Bearer {PAT_ROOT}");
    let guest = format!("Bearer {PAT_GUEST}");

    // ---- AdminAuth 拦截 ----------------------------------------------------
    assert_eq!(
        get_with(&app, "/api/user/6/oauth/bindings", None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    // 普通用户与 guest：403（`AdminAuth` 的角色检查先于 UserAuth 的最低角色检查）。
    for authorization in [common.as_str(), guest.as_str()] {
        let response = get_with(&app, "/api/user/6/oauth/bindings", Some(authorization)).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = body_json(response).await;
        assert_eq!(body["code"], json!("AUTH_INSUFFICIENT_PRIVILEGE"));
    }

    // ---- id 解析 -----------------------------------------------------------
    assert_business_message(
        get_with(&app, "/api/user/abc/oauth/bindings", Some(&admin)).await,
        MSG_INVALID_USER_ID,
    )
    .await;
    assert_business_message(
        get_with(&app, "/api/user/0/oauth/bindings", Some(&admin)).await,
        MSG_USER_ID_EMPTY,
    )
    .await;
    assert_business_message(
        delete_with(&app, "/api/user/abc/oauth/bindings/11", Some(&admin)).await,
        MSG_INVALID_USER_ID,
    )
    .await;
    assert_business_message(
        delete_with(&app, "/api/user/0/oauth/bindings/11", Some(&admin)).await,
        MSG_USER_ID_EMPTY,
    )
    .await;

    // ---- 目标用户查找：不存在与软删除都不可见 -------------------------------
    let not_found = translated("user.not_exists");
    assert_business_message(
        get_with(&app, "/api/user/999/oauth/bindings", Some(&admin)).await,
        &not_found,
    )
    .await;
    assert_business_message(
        get_with(&app, "/api/user/8/oauth/bindings", Some(&admin)).await,
        &not_found,
    )
    .await;
    assert_business_message(
        delete_with(&app, "/api/user/999/oauth/bindings/11", Some(&admin)).await,
        &not_found,
    )
    .await;
    assert_business_message(
        delete_with(&app, "/api/user/8/oauth/bindings/11", Some(&admin)).await,
        &not_found,
    )
    .await;

    // ---- canManageTargetRole 矩阵 ------------------------------------------
    // admin 不能动同级 admin，也不能动 root。
    assert_business_message(
        get_with(&app, "/api/user/7/oauth/bindings", Some(&admin)).await,
        MSG_NO_PERMISSION,
    )
    .await;
    assert_business_message(
        get_with(&app, "/api/user/3/oauth/bindings", Some(&admin)).await,
        MSG_NO_PERMISSION,
    )
    .await;
    // root 可动任何角色（含同级 admin）。
    assert_bindings(
        get_with(&app, "/api/user/7/oauth/bindings", Some(&root)).await,
        &json!([]),
    )
    .await;
    // admin → 普通用户放行。
    assert_bindings(
        get_with(&app, "/api/user/6/oauth/bindings", Some(&admin)).await,
        &json!([]),
    )
    .await;

    // ---- admin GET 的 data 与 self 同构，且不写审计 -------------------------
    // 此刻已有 4 条审计（2 个 id 解析失败 + 2 个目标查找失败）；此后的 GET
    // 不论成败都不新增——“写方法才被 beginAdminAudit 捕获”。
    seed_binding(&db, 20, 6, 11, "gh-target").await;
    seed_binding(&db, 21, 6, 12, "gl-target").await;
    assert_bindings(
        get_with(&app, "/api/user/6/oauth/bindings", Some(&admin)).await,
        &json!([
            {
                "provider_id": 11,
                "provider_name": "GitHub Enterprise",
                "provider_slug": "github-enterprise",
                "provider_icon": "github",
                "provider_user_id": "gh-target",
            },
            {
                "provider_id": 12,
                "provider_name": "GitLab CE",
                "provider_slug": "gitlab-ce",
                "provider_icon": "",
                "provider_user_id": "gl-target",
            },
        ]),
    )
    .await;
    let logs_before_get = audit_logs(&db).await.len();
    assert_eq!(logs_before_get, 4, "此前失败 DELETE 已落 4 条");
    // 失败的 admin GET 也不写审计：成功 GET 已证明，再用两个失败 GET 收尾。
    assert_business_message(
        get_with(&app, "/api/user/999/oauth/bindings", Some(&admin)).await,
        &not_found,
    )
    .await;
    assert_business_message(
        get_with(&app, "/api/user/7/oauth/bindings", Some(&admin)).await,
        MSG_NO_PERMISSION,
    )
    .await;
    assert_eq!(
        audit_logs(&db).await.len(),
        logs_before_get,
        "admin GET 不写审计"
    );

    // ---- admin 解绑顺序：provider_id 解析在角色检查之后 ---------------------
    // 无权限时即使 provider_id 非法，先看到 no permission（admin 不能动同级
    // admin，用户 7 也是 role 10）。
    assert_business_message(
        delete_with(&app, "/api/user/7/oauth/bindings/abc", Some(&admin)).await,
        MSG_NO_PERMISSION,
    )
    .await;
    // root（100）可以管理 role 10，于是越过角色检查，落在自己的
    // provider_id 解析分支——证明顺序是「角色 → 解析」而不是反过来。
    assert_business_message(
        delete_with(&app, "/api/user/7/oauth/bindings/0x11", Some(&root)).await,
        MSG_INVALID_PROVIDER_ID_ADMIN,
    )
    .await;
    // 有权限时非法 provider_id 走自己的分支。
    assert_business_message(
        delete_with(&app, "/api/user/6/oauth/bindings/abc", Some(&admin)).await,
        MSG_INVALID_PROVIDER_ID_ADMIN,
    )
    .await;
    // 目标用户存在但 provider_id 越界溢出同样解析失败。
    assert_business_message(
        delete_with(
            &app,
            "/api/user/6/oauth/bindings/99999999999999999999",
            Some(&admin),
        )
        .await,
        MSG_INVALID_PROVIDER_ID_ADMIN,
    )
    .await;
    assert_eq!(stored_bindings(&db, 6).await.len(), 2, "解析失败不改动");

    // ---- admin 解绑成功：英文 "success"，无 data ----------------------------
    assert_success_message(
        delete_with(&app, "/api/user/6/oauth/bindings/12", Some(&admin)).await,
        MSG_UNBOUND_ADMIN,
    )
    .await;
    assert_eq!(stored_bindings(&db, 6).await.len(), 1);
    // 幂等：再解一次同样成功。
    assert_success_message(
        delete_with(&app, "/api/user/6/oauth/bindings/12", Some(&admin)).await,
        MSG_UNBOUND_ADMIN,
    )
    .await;
    // admin 可解绑 root 目标（root→admin 放行）。
    seed_binding(&db, 22, 7, 13, "okta-admin-two").await;
    assert_success_message(
        delete_with(&app, "/api/user/7/oauth/bindings/13", Some(&root)).await,
        MSG_UNBOUND_ADMIN,
    )
    .await;
    assert!(stored_bindings(&db, 7).await.is_empty());

    // ---- 审计：admin DELETE 每次尝试都写一条 --------------------------------
    // 逐次数到达 handler 的 DELETE：2 个 id 解析失败（abc / 0）+
    // 2 个目标查找失败（999 / 软删除 8）+ 1 个权限拒绝（admin→admin 7）+
    // 1 个 root 的 provider_id 解析失败 + 2 个 admin 的 provider_id 解析失败
    // + 3 次成功解绑 = 11 条。GET 与此前各失败 DELETE 的差异正是「写方法才捕获」。
    let logs = audit_logs(&db).await;
    assert_eq!(logs.len(), 11, "{logs:?}");
    for (operator, log_type, content, _username, other) in &logs {
        // 只有 admin（2）与 root（3）的请求能进 handler；普通用户的 403 在
        // `AdminAuth` 就中断，不会留下日志。
        assert!(
            *operator == 2 || *operator == 3,
            "操作者必须是 admin 或 root"
        );
        assert_eq!(*log_type, 3, "Go LogTypeManage");
        assert_eq!(
            content, "DELETE /api/user/:id/oauth/bindings/:provider_id",
            "Go `content = method + \" \" + route`"
        );
        let other: Value = serde_json::from_str(other).expect("other JSON");
        // 已登记 action 的兜底记录 `other.op` 只有 action，没有 params 键。
        assert_eq!(other["op"]["action"], json!("user.oauth_unbind"), "{other}");
        assert!(
            other["op"].get("params").is_none(),
            "非 generic action 不带 op.params: {other}"
        );
        // identity 随操作者推导：admin 是 id 2 / role 10，root 是 id 3 / role 100。
        let (expected_id, expected_username, expected_role) = if *operator == 2 {
            (2, "fixture-admin", 10)
        } else {
            (3, "fixture-root", 100)
        };
        assert_eq!(
            other["admin_info"]["admin_id"],
            json!(expected_id),
            "{other}"
        );
        assert_eq!(
            other["admin_info"]["admin_username"],
            json!(expected_username),
            "{other}"
        );
        assert_eq!(
            other["admin_info"]["admin_role"],
            json!(expected_role),
            "{other}"
        );
        assert_eq!(
            other["admin_info"]["auth_method"],
            json!("access_token"),
            "PAT 鉴权在 Go 写 access_token"
        );
        assert_eq!(other["audit_info"]["method"], json!("DELETE"), "{other}");
        assert_eq!(
            other["audit_info"]["route"],
            json!("/api/user/:id/oauth/bindings/:provider_id"),
            "{other}"
        );
        assert_eq!(other["audit_info"]["status"], json!(200), "{other}");
    }

    // 首条（`invalid user id`）与末条（成功）的 success 标志必须相反。
    let first = parse_other(&logs[0].4);
    assert_eq!(first["audit_info"]["success"], json!(false), "{first}");
    assert_eq!(
        first["audit_info"]["path"],
        json!("/api/user/abc/oauth/bindings/11"),
        "{first}"
    );
    assert_eq!(first["audit_info"]["params"]["id"], json!("abc"), "{first}");
    assert_eq!(
        first["audit_info"]["params"]["provider_id"],
        json!(11),
        "{first}"
    );
    let last = parse_other(&logs[logs.len() - 1].4);
    assert_eq!(last["audit_info"]["success"], json!(true), "{last}");
    assert_eq!(
        last["audit_info"]["path"],
        json!("/api/user/7/oauth/bindings/13"),
        "{last}"
    );
    assert_eq!(last["audit_info"]["params"]["id"], json!(7), "{last}");
    assert_eq!(
        last["audit_info"]["params"]["provider_id"],
        json!(13),
        "{last}"
    );

    // ---- root 操作：审计归属操作者而非目标 ----------------------------------
    // 用 root PAT 再解绑一次：日志归属 root（id 3）、admin_role 100，
    // 而 auth_method 仍是 access_token（Go 对 PAT 鉴权写 `access_token`，
    // `CredentialKind::PersonalAccessToken` 映射同一字符串）。
    seed_binding(&db, 23, 6, 13, "okta-target").await;
    assert_success_message(
        delete_with(&app, "/api/user/6/oauth/bindings/13", Some(&root)).await,
        MSG_UNBOUND_ADMIN,
    )
    .await;
    let logs = audit_logs(&db).await;
    assert_eq!(logs.len(), 12, "{logs:?}");
    let (operator, _log_type, _content, username, other) = &logs[11];
    assert_eq!(*operator, 3, "root 操作，日志归属 root");
    assert_eq!(username.as_str(), "fixture-root");
    let other = parse_other(other);
    assert_eq!(other["admin_info"]["admin_role"], json!(100), "{other}");
    assert_eq!(
        other["admin_info"]["auth_method"],
        json!("access_token"),
        "{other}"
    );
    assert_eq!(other["audit_info"]["success"], json!(true), "{other}");

    // ---- 401/403 不写审计 ---------------------------------------------------
    let before = audit_logs(&db).await.len();
    assert_eq!(
        get_with(&app, "/api/user/6/oauth/bindings", None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        delete_with(&app, "/api/user/6/oauth/bindings/11", Some(&common))
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        audit_logs(&db).await.len(),
        before,
        "鉴权失败的请求不进 handler，不写审计"
    );
}

fn parse_other(other: &str) -> Value {
    serde_json::from_str(other).expect("other JSON")
}

#[tokio::test]
async fn sqlite_oauth_binding_self_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    run_self_contract(Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn postgres_oauth_binding_self_contract() {
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
        "oauth_self_{}_{}",
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
    run_self_contract(Database::Postgres(pool)).await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA \"{schema}\" CASCADE"
    )))
    .execute(&admin)
    .await
    .expect("drop isolated schema");
    admin.close().await;
}

#[tokio::test]
async fn sqlite_oauth_binding_admin_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    run_admin_contract(Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn postgres_oauth_binding_admin_contract() {
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
        "oauth_admin_{}_{}",
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
    run_admin_contract(Database::Postgres(pool)).await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA \"{schema}\" CASCADE"
    )))
    .execute(&admin)
    .await
    .expect("drop isolated schema");
    admin.close().await;
}
