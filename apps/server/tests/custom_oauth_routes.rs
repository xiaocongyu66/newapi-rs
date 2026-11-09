//! HTTP contracts for the six custom OAuth provider management routes:
//! `GET/POST /api/custom-oauth-provider/`, `GET/PUT/DELETE
//! /api/custom-oauth-provider/:id` and `POST
//! /api/custom-oauth-provider/discovery`.
//!
//! Runs only in remote CI. Every scenario uses an isolated synthetic fixture
//! (in-memory SQLite or an isolated PostgreSQL schema); no service is started.
//! The discovery scenarios never touch the network: the transport is injected
//! via `InjectedDiscoveryTransport` (the same seam `login_http` uses for
//! Turnstile).
//!
//! Go references: `apps/api/internal/identity/bind_custom_oauth.go:71-440`,
//! `apps/api/internal/identity/resolve_oauth_provider.go` (table + validation),
//! `register_api.go:342-352` (AdminAuth + RequirePermission(SystemSettings)),
//! `security/audit_access.go:29-31+83-147` (fallback audit, incl. the 403
//! from RequirePermission), `security/oauth/{discord,github,linuxdo,oidc}.go`
//! (built-in slug set).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Method, Request, StatusCode, header},
    middleware,
    response::Response,
    routing::{delete, get, post, put},
};
use newapi_server::custom_oauth_http::{
    DiscoveryError, DiscoveryFuture, DiscoveryResponse, DiscoveryTransport,
    InjectedDiscoveryTransport, create, delete, discovery, get_one, list, require_system_settings,
    update,
};
use newapi_server::{AppState, auth as server_auth};
use newapi_storage::Database;
use serde_json::{Value, json};
use sqlx::{
    ConnectOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::SqlitePoolOptions,
};
use tower::ServiceExt;

static NEXT: AtomicU64 = AtomicU64::new(0);

const SECRET: &str = "custom-oauth-routes-fixture-secret";

/// 每个 fixture 用户一个唯一 PAT，避免跨测试串味。
const PAT_COMMON: &str = "pat-custom-oauth-common";
const PAT_ADMIN: &str = "pat-custom-oauth-admin";
const PAT_ROOT: &str = "pat-custom-oauth-root";
const PAT_ADMIN_ALLOWED: &str = "pat-custom-oauth-allowed";
const PAT_ADMIN_DENIED: &str = "pat-custom-oauth-denied";

/// Go 硬编码字面量（前端按字面量比对，不经 i18n）。
const MSG_INVALID_ID: &str = "无效的 ID";
const MSG_PROVIDER_NOT_FOUND: &str = "未找到该 OAuth 提供商";
const MSG_SLUG_TAKEN: &str = "该 Slug 已被使用";
const MSG_SLUG_BUILTIN_CONFLICT: &str = "该 Slug 与内置 OAuth 提供商冲突";
const MSG_CREATED: &str = "创建成功";
const MSG_UPDATED: &str = "更新成功";
const MSG_DELETED: &str = "删除成功";
const MSG_BINDING_COUNT_FAILED: &str = "检查用户绑定时发生错误，请稍后重试";
const MSG_DELETE_HAS_BINDINGS: &str =
    "该 OAuth 提供商还有用户绑定，无法删除。请先解除所有用户绑定。";
const MSG_DISCOVERY_EMPTY: &str = "请先填写 Discovery URL 或 Issuer URL";
const MSG_DISCOVERY_INVALID_URL: &str = "Discovery URL 无效，仅支持 http/https";
const MSG_DISCOVERY_FETCH_FAILED: &str = "获取 Discovery 配置失败";
const MSG_DISCOVERY_PARSE_FAILED: &str = "解析 Discovery 配置失败";
/// 本端口对 Go 框架错误文本的折叠键。
const MSG_INVALID_PARAMS: &str = "common.invalid_params";

const AUTH_INSUFFICIENT_PRIVILEGE_CODE: &str = "AUTH_INSUFFICIENT_PRIVILEGE";

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

/// `crates/identity/src/setup.rs` 的 `casbin_rule` 清单；权限策略只读求值
/// 只需 p 行字段。
const CASBIN_SQLITE: &str = r#"CREATE TABLE casbin_rule (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ptype TEXT, v0 TEXT, v1 TEXT,
    v2 TEXT, v3 TEXT, v4 TEXT, v5 TEXT
)"#;

const CASBIN_POSTGRES: &str = r#"CREATE TABLE casbin_rule (
    id BIGSERIAL PRIMARY KEY, ptype TEXT, v0 TEXT, v1 TEXT,
    v2 TEXT, v3 TEXT, v4 TEXT, v5 TEXT
)"#;

/// Go `identity.CustomOAuthProvider`（`resolve_oauth_provider.go:41-68`）的
/// 列清单；`enabled` 对应 Go bool（SQLite 0/1，PG BOOLEAN）。
const PROVIDERS_SQLITE: &str = r#"CREATE TABLE custom_oauth_providers (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL, slug TEXT NOT NULL,
    icon TEXT DEFAULT '', enabled INTEGER NOT NULL DEFAULT 0, client_id TEXT,
    client_secret TEXT, authorization_endpoint TEXT, token_endpoint TEXT,
    user_info_endpoint TEXT, scopes TEXT, user_id_field TEXT,
    username_field TEXT, display_name_field TEXT, email_field TEXT,
    well_known TEXT, auth_style INTEGER DEFAULT 0, access_policy TEXT,
    access_denied_message TEXT, created_at TEXT, updated_at TEXT
)"#;

const PROVIDERS_POSTGRES: &str = r#"CREATE TABLE custom_oauth_providers (
    id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, slug TEXT NOT NULL,
    icon TEXT DEFAULT '', enabled BOOLEAN NOT NULL DEFAULT FALSE, client_id TEXT,
    client_secret TEXT, authorization_endpoint TEXT, token_endpoint TEXT,
    user_info_endpoint TEXT, scopes TEXT, user_id_field TEXT,
    username_field TEXT, display_name_field TEXT, email_field TEXT,
    well_known TEXT, auth_style BIGINT DEFAULT 0, access_policy TEXT,
    access_denied_message TEXT, created_at TIMESTAMPTZ, updated_at TIMESTAMPTZ
)"#;

const BINDINGS_SQLITE: &str = r#"CREATE TABLE user_oauth_bindings (
    id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, provider_id INTEGER NOT NULL,
    provider_user_id TEXT NOT NULL, created_at BIGINT
)"#;

const BINDINGS_POSTGRES: &str = r#"CREATE TABLE user_oauth_bindings (
    id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL, provider_id BIGINT NOT NULL,
    provider_user_id TEXT NOT NULL, created_at BIGINT
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

/// Go `register_api.go:342-352`：组内 `AdminAuth` + `RequirePermission`；
/// 与 `http.rs` 的注册保持同一形态（含根路由的尾斜线双注册）。
fn router(state: AppState) -> Router {
    let routes = Router::new()
        .route("/api/custom-oauth-provider/", get(list).post(create))
        .route("/api/custom-oauth-provider", get(list).post(create))
        .route("/api/custom-oauth-provider/discovery", post(discovery))
        .route(
            "/api/custom-oauth-provider/{id}",
            get(get_one).put(update).delete(delete),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_system_settings,
        ))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            server_auth::admin_auth,
        ));
    routes.with_state(state)
}

fn state(db: &Database) -> AppState {
    AppState::default().bind_runtime(db.clone(), SECRET)
}

async fn exec(db: &Database, statement: &str) {
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
                CASBIN_SQLITE,
                PROVIDERS_SQLITE,
                BINDINGS_SQLITE,
                LOGS_SQLITE,
            ] {
                exec(db, statement).await;
            }
        }
        Database::Postgres(_) => {
            for statement in [
                USERS_POSTGRES,
                CASBIN_POSTGRES,
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

/// Go `policy.Can` 的用户级覆盖：`p, user:<id>, system, settings, <effect>`，
/// 空 effect 与 `allow` 同义，`deny` 短路否决。
async fn seed_policy(db: &Database, user_id: i64, effect: &str) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO casbin_rule (ptype,v0,v1,v2,v3) VALUES ('p',$1,'system','settings',$2)"#,
        )
        .bind(format!("user:{user_id}"))
        .bind(effect)
        .execute(pool)
        .await
        .expect("seed policy");
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

/// 审计行的内容投影（`logs.other` JSON 解码）。
struct AuditRow {
    user_id: i64,
    action: String,
    method: String,
    route: String,
    path: String,
    status: i64,
    success: bool,
    params: Option<Value>,
    op_params: Option<Value>,
}

async fn audit_rows(db: &Database) -> Vec<AuditRow> {
    let rows = backend!(db, pool, {
        sqlx::query_as::<_, (i64, String)>(
            "SELECT CAST(user_id AS BIGINT) AS user_id, other FROM logs ORDER BY id ASC",
        )
        .fetch_all(pool)
        .await
        .expect("audit rows")
    });
    rows.into_iter()
        .map(|(user_id, other)| {
            let value: Value = serde_json::from_str(&other).expect("other JSON");
            AuditRow {
                user_id,
                action: value["op"]["action"].as_str().unwrap_or("").to_owned(),
                method: value["audit_info"]["method"]
                    .as_str()
                    .unwrap_or("")
                    .to_owned(),
                route: value["audit_info"]["route"]
                    .as_str()
                    .unwrap_or("")
                    .to_owned(),
                path: value["audit_info"]["path"]
                    .as_str()
                    .unwrap_or("")
                    .to_owned(),
                status: value["audit_info"]["status"].as_i64().unwrap_or(0),
                success: value["audit_info"]["success"].as_bool().unwrap_or(false),
                params: value["audit_info"].get("params").cloned(),
                op_params: value["op"].get("params").cloned(),
            }
        })
        .collect()
}

/// 提供商行的断言投影（含 client_secret，供“落库但回显”断言使用）。
async fn provider_row(db: &Database, id: i64) -> Option<Value> {
    let row = backend!(db, pool, {
        sqlx::query_as::<
            _,
            (
                Option<String>,
                Option<bool>,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
            ),
        >(
            r#"SELECT slug, enabled, client_id, client_secret, token_endpoint,
                      access_policy, well_known
               FROM custom_oauth_providers WHERE id = $1"#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await
        .expect("provider row")
    });
    row.map(
        |(slug, enabled, client_id, client_secret, token_endpoint, access_policy, well_known)| {
            json!({
                "slug": slug.unwrap_or_default(),
                "enabled": enabled.unwrap_or(false),
                "client_id": client_id.unwrap_or_default(),
                "client_secret": client_secret.unwrap_or_default(),
                "token_endpoint": token_endpoint.unwrap_or_default(),
                "access_policy": access_policy.unwrap_or_default(),
                "well_known": well_known.unwrap_or_default(),
            })
        },
    )
}

/// 注入式 discovery 传输的预置响应。
#[derive(Clone)]
enum CannedDiscovery {
    Transport,
    Status(u16, String),
    Json(String),
}

#[derive(Clone)]
struct FakeDiscoveryTransport {
    calls: Arc<Mutex<Vec<String>>>,
    queue: Arc<Mutex<VecDeque<CannedDiscovery>>>,
}

impl FakeDiscoveryTransport {
    fn new(queue: Vec<CannedDiscovery>) -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            queue: Arc::new(Mutex::new(VecDeque::from(queue))),
        }
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("calls").clone()
    }
}

impl DiscoveryTransport for FakeDiscoveryTransport {
    fn fetch<'a>(&'a self, url: &'a str) -> DiscoveryFuture<'a> {
        {
            let mut calls = self.calls.lock().expect("calls");
            calls.push(url.to_owned());
        }
        let canned = self.queue.lock().expect("queue").pop_front();
        Box::pin(async move {
            match canned {
                Some(CannedDiscovery::Transport) => Err(DiscoveryError::Transport),
                Some(CannedDiscovery::Status(status, body)) => Ok(DiscoveryResponse {
                    status,
                    body: body.into_bytes(),
                }),
                Some(CannedDiscovery::Json(body)) => Ok(DiscoveryResponse {
                    status: StatusCode::OK.as_u16(),
                    body: body.into_bytes(),
                }),
                None => panic!("discovery transport queue exhausted"),
            }
        })
    }
}

async fn send(
    state: &AppState,
    method: Method,
    path: &str,
    authorization: Option<&str>,
    body: Option<&str>,
    transport: Option<Arc<FakeDiscoveryTransport>>,
) -> Response {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::ACCEPT_LANGUAGE, "en");
    if let Some(value) = authorization {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    let body = match body {
        Some(text) => Body::from(text.to_owned()),
        None => Body::empty(),
    };
    let mut request = builder.body(body).unwrap();
    if let Some(transport) = transport {
        request
            .extensions_mut()
            .insert(InjectedDiscoveryTransport(transport));
    }
    router(state.clone()).oneshot(request).await.unwrap()
}

async fn post_with(
    state: &AppState,
    path: &str,
    authorization: Option<&str>,
    body: Option<&str>,
) -> Response {
    send(state, Method::POST, path, authorization, body, None).await
}

async fn put_with(
    state: &AppState,
    path: &str,
    authorization: Option<&str>,
    body: Option<&str>,
) -> Response {
    send(state, Method::PUT, path, authorization, body, None).await
}

async fn delete_with(state: &AppState, path: &str, authorization: Option<&str>) -> Response {
    send(state, Method::DELETE, path, authorization, None, None).await
}

async fn discovery_with(
    state: &AppState,
    authorization: &str,
    body: &str,
    transport: Arc<FakeDiscoveryTransport>,
) -> Response {
    send(
        state,
        Method::POST,
        "/api/custom-oauth-provider/discovery",
        Some(authorization),
        Some(body),
        Some(transport),
    )
    .await
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

/// 六条路由都不挂 `DisableCache`（Go `register_api.go:342-352`）。
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

/// Go 手写成功体：HTTP 200 + `{success:true,message}`（list/get 另带 data）。
async fn assert_message(response: Response, message: &str) -> Value {
    assert_eq!(response.status(), StatusCode::OK, "{message}");
    assert_no_cache_headers(response.headers());
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true), "{body}");
    assert_eq!(body["message"], json!(message), "{body}");
    body
}

/// Go 的 GET 成功体：`{success:true,message:"",data}`。
async fn assert_data(response: Response, expected: &Value) -> Value {
    assert_eq!(response.status(), StatusCode::OK, "{expected}");
    assert_no_cache_headers(response.headers());
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true), "{body}");
    assert_eq!(body["message"], json!(""), "GET 成功带空 message");
    assert_eq!(body["data"], *expected, "{body}");
    body
}

const FULL_CREATE_BODY: &str = r#"{"name":"GitHub Enterprise","slug":"github-enterprise",
"icon":"github","enabled":true,"client_id":"gh-client-id","client_secret":"gh-client-secret",
"authorization_endpoint":"https://gh.example/login/oauth/authorize",
"token_endpoint":"https://gh.example/login/oauth/token",
"user_info_endpoint":"https://gh.example/api/v3/user","scopes":"user:email",
"user_id_field":"id","username_field":"login","display_name_field":"name",
"email_field":"email"}"#;

// ---------------------------------------------------------------------------
// 鉴权与权限契约
// ---------------------------------------------------------------------------

async fn run_auth_contract(db: Database) {
    create_schema(&db).await;
    seed_user(&db, 1, "fixture-common", 1, Some(PAT_COMMON)).await;
    seed_user(&db, 2, "fixture-admin", 10, Some(PAT_ADMIN)).await;
    seed_user(&db, 3, "fixture-root", 100, Some(PAT_ROOT)).await;
    seed_user(&db, 4, "fixture-admin-allowed", 10, Some(PAT_ADMIN_ALLOWED)).await;
    seed_user(&db, 5, "fixture-admin-denied", 10, Some(PAT_ADMIN_DENIED)).await;
    seed_policy(&db, 4, "").await;
    // deny 短路：即使同主体存在 allow 行也拒绝（Go `explicitSubjectEffect`）。
    seed_policy(&db, 5, "allow").await;
    seed_policy(&db, 5, "deny").await;
    let app = state(&db);
    let common = format!("Bearer {PAT_COMMON}");
    let admin = format!("Bearer {PAT_ADMIN}");
    let root = format!("Bearer {PAT_ROOT}");
    let allowed = format!("Bearer {PAT_ADMIN_ALLOWED}");
    let denied = format!("Bearer {PAT_ADMIN_DENIED}");

    // ---- AdminAuth：无凭据一律 401，且不落审计 -------------------------------
    for (method, path) in [
        (Method::GET, "/api/custom-oauth-provider/"),
        (Method::GET, "/api/custom-oauth-provider/1"),
        (Method::POST, "/api/custom-oauth-provider/"),
        (Method::PUT, "/api/custom-oauth-provider/1"),
        (Method::DELETE, "/api/custom-oauth-provider/1"),
        (Method::POST, "/api/custom-oauth-provider/discovery"),
    ] {
        assert_eq!(
            send(&app, method, path, None, None, None).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }
    assert!(
        audit_rows(&db).await.is_empty(),
        "401 不进 handler，不写审计"
    );

    // ---- 普通用户：AdminAuth 的角色检查先于 RequirePermission -----------------
    // 带 `code`（AUTH_INSUFFICIENT_PRIVILEGE），与权限层的 403 不同。
    for (method, path, body) in [
        (Method::GET, "/api/custom-oauth-provider/", None),
        (Method::GET, "/api/custom-oauth-provider/1", None),
        (Method::POST, "/api/custom-oauth-provider/", None),
        (Method::PUT, "/api/custom-oauth-provider/1", Some("{}")),
        (Method::DELETE, "/api/custom-oauth-provider/1", None),
        (Method::POST, "/api/custom-oauth-provider/discovery", None),
    ] {
        let response = send(&app, method, path, Some(&common), body, None).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = body_json(response).await;
        assert_eq!(
            body["code"],
            json!(AUTH_INSUFFICIENT_PRIVILEGE_CODE),
            "{body}"
        );
    }
    assert!(audit_rows(&db).await.is_empty(), "角色 403 不写审计");

    // ---- RequirePermission：admin 无授权 → 403，无 code、无 data --------------
    let insufficient = translated("auth.insufficient_privilege");
    for (method, path, body) in [
        (Method::GET, "/api/custom-oauth-provider/", None),
        (Method::GET, "/api/custom-oauth-provider/1", None),
        (Method::POST, "/api/custom-oauth-provider/", None),
        (Method::PUT, "/api/custom-oauth-provider/1", Some("{}")),
        (Method::DELETE, "/api/custom-oauth-provider/1", None),
        (Method::POST, "/api/custom-oauth-provider/discovery", None),
    ] {
        let response = send(&app, method, path, Some(&admin), body, None).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_no_cache_headers(response.headers());
        let body = body_json(response).await;
        assert_eq!(body["success"], json!(false), "{body}");
        assert_eq!(body["message"], json!(insufficient), "{body}");
        assert!(body.get("code").is_none(), "权限层 403 不带 code: {body}");
        assert!(body.get("data").is_none(), "unexpected data: {body}");
    }
    // 同主体的 deny 规则同样拒绝（user 5）。
    let response = send(
        &app,
        Method::GET,
        "/api/custom-oauth-provider/",
        Some(&denied),
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // ---- 权限通过：root 超级用户短路、admin 的用户级 allow ---------------------
    for authorization in [root.as_str(), allowed.as_str()] {
        assert_data(
            send(
                &app,
                Method::GET,
                "/api/custom-oauth-provider/",
                Some(authorization),
                None,
                None,
            )
            .await,
            &json!([]),
        )
        .await;
    }

    // ---- 权限 403 的兜底审计（Go finishAdminAudit 在 RequirePermission 之外）--
    // 此时没有 handler 结果，仅四条写方法的 403 审计（GET 的 403 不落库）。
    let rows = audit_rows(&db).await;
    assert_eq!(rows.len(), 4, "{rows:?}");
    let expected = [
        ("custom_oauth.create", "POST", "/api/custom-oauth-provider/"),
        (
            "custom_oauth.update",
            "PUT",
            "/api/custom-oauth-provider/:id",
        ),
        (
            "custom_oauth.delete",
            "DELETE",
            "/api/custom-oauth-provider/:id",
        ),
        ("generic", "POST", "/api/custom-oauth-provider/discovery"),
    ];
    for (row, (action, method, route)) in rows.iter().zip(expected) {
        assert_eq!(row.user_id, 2, "操作者是 admin（user 2）: {row:?}");
        assert_eq!(row.status, 403, "{row:?}");
        assert!(!row.success, "{row:?}");
        assert_eq!(row.action, action, "{row:?}");
        assert_eq!(row.method, method, "{row:?}");
        assert_eq!(row.route, route, "{row:?}");
    }
    // id 路由的 403 审计携带 params（字符串值）；audit_info.path 是实际请求路径。
    let params = rows[1].params.clone().expect("update params");
    assert_eq!(params["id"], json!("1"), "{params}");
    assert_eq!(rows[1].path, "/api/custom-oauth-provider/1", "{rows:?}");
    // generic（discovery）的 op 带 method/route。
    let op_params = rows[3].op_params.clone().expect("generic op params");
    assert_eq!(op_params["method"], json!("POST"), "{op_params}");
    assert_eq!(
        op_params["route"],
        json!("/api/custom-oauth-provider/discovery"),
        "{op_params}"
    );

    // ---- root 的业务失败也落审计；GET 不落 -------------------------------------
    assert_business_message(
        post_with(
            &app,
            "/api/custom-oauth-provider/",
            Some(&root),
            Some("not json"),
        )
        .await,
        &translated(MSG_INVALID_PARAMS),
    )
    .await;
    assert_data(
        send(
            &app,
            Method::GET,
            "/api/custom-oauth-provider/",
            Some(&root),
            None,
            None,
        )
        .await,
        &json!([]),
    )
    .await;
    let rows = audit_rows(&db).await;
    assert_eq!(rows.len(), 5, "{rows:?}");
    assert_eq!(rows[4].user_id, 3);
    assert_eq!(rows[4].action, "custom_oauth.create");
    assert!(!rows[4].success, "无效请求体是业务失败");
    assert_eq!(rows[4].status, 200);
}

// ---------------------------------------------------------------------------
// CRUD 契约
// ---------------------------------------------------------------------------

async fn run_crud_contract(db: Database) {
    create_schema(&db).await;
    seed_user(&db, 3, "fixture-root", 100, Some(PAT_ROOT)).await;
    let app = state(&db);
    let root = format!("Bearer {PAT_ROOT}");

    // ---- 列表：空集合是 [] 而非 null ----------------------------------------
    for path in ["/api/custom-oauth-provider/", "/api/custom-oauth-provider"] {
        assert_data(
            send(&app, Method::GET, path, Some(&root), None, None).await,
            &json!([]),
        )
        .await;
    }

    // ---- 单读：id 解析分支 ---------------------------------------------------
    for id in ["abc", "99999999999999999999", "+1a", "0x11", "1_1"] {
        assert_business_message(
            send(
                &app,
                Method::GET,
                &format!("/api/custom-oauth-provider/{id}"),
                Some(&root),
                None,
                None,
            )
            .await,
            MSG_INVALID_ID,
        )
        .await;
    }
    assert_business_message(
        send(
            &app,
            Method::GET,
            "/api/custom-oauth-provider/999",
            Some(&root),
            None,
            None,
        )
        .await,
        MSG_PROVIDER_NOT_FOUND,
    )
    .await;

    // ---- 创建：BindJSON 分支（gin required → 固定键） -------------------------
    let invalid_params = translated(MSG_INVALID_PARAMS);
    for body in [
        None,
        Some("not json"),
        Some("[]"),
        Some("null"),
        Some("{}"),
        Some(r#"{"name":"x"}"#),
        Some(r#"{"name":"x","slug":"s"}"#),
        // 空字符串同缺字段：gin 的 required 对零值失败。
        Some(
            r#"{"name":"","slug":"","client_id":"","client_secret":"",
                 "authorization_endpoint":"","token_endpoint":"","user_info_endpoint":""}"#,
        ),
        // 类型不符 → unmarshal 失败。
        Some(
            r#"{"name":"x","slug":"s","client_id":"c","client_secret":"s",
                 "authorization_endpoint":"a","token_endpoint":"t","user_info_endpoint":"u",
                 "enabled":"yes"}"#,
        ),
        Some(
            r#"{"name":"x","slug":"s","client_id":"c","client_secret":"s",
                 "authorization_endpoint":"a","token_endpoint":"t","user_info_endpoint":"u",
                 "auth_style":"auto"}"#,
        ),
    ] {
        assert_business_message(
            post_with(&app, "/api/custom-oauth-provider/", Some(&root), body).await,
            &invalid_params,
        )
        .await;
    }

    // ---- 创建成功：全字段回显，client_secret 不回显但落库 ---------------------
    let body = assert_message(
        post_with(
            &app,
            "/api/custom-oauth-provider/",
            Some(&root),
            Some(FULL_CREATE_BODY),
        )
        .await,
        MSG_CREATED,
    )
    .await;
    let provider_id = body["data"]["id"].as_i64().expect("assigned id");
    assert!(provider_id > 0, "回填的数据库 id: {provider_id}");
    assert_eq!(
        body["data"],
        json!({
            "id": provider_id,
            "name": "GitHub Enterprise",
            "slug": "github-enterprise",
            "icon": "github",
            "enabled": true,
            "client_id": "gh-client-id",
            "authorization_endpoint": "https://gh.example/login/oauth/authorize",
            "token_endpoint": "https://gh.example/login/oauth/token",
            "user_info_endpoint": "https://gh.example/api/v3/user",
            "scopes": "user:email",
            "user_id_field": "id",
            "username_field": "login",
            "display_name_field": "name",
            "email_field": "email",
            "well_known": "",
            "auth_style": 0,
            "access_policy": "",
            "access_denied_message": "",
        }),
        "{body}"
    );
    // client_secret 绝不出现在任何响应里。
    assert!(
        body["data"].get("client_secret").is_none(),
        "client_secret 不得回显: {body}"
    );
    let stored = provider_row(&db, provider_id).await.expect("stored row");
    assert_eq!(
        stored["client_secret"],
        json!("gh-client-secret"),
        "{stored}"
    );

    // ---- 单读：完整投影 ------------------------------------------------------
    assert_data(
        send(
            &app,
            Method::GET,
            &format!("/api/custom-oauth-provider/{provider_id}"),
            Some(&root),
            None,
            None,
        )
        .await,
        &body["data"],
    )
    .await;

    // ---- 创建：slug 重复 / 内置冲突 / 字符集 ----------------------------------
    assert_business_message(
        post_with(
            &app,
            "/api/custom-oauth-provider/",
            Some(&root),
            Some(FULL_CREATE_BODY),
        )
        .await,
        MSG_SLUG_TAKEN,
    )
    .await;
    for builtin in ["github", "discord", "linuxdo", "oidc"] {
        let body = format!(
            r#"{{"name":"{builtin}","slug":"{builtin}","client_id":"c","client_secret":"s",
                 "authorization_endpoint":"a","token_endpoint":"t","user_info_endpoint":"u"}}"#
        );
        assert_business_message(
            post_with(
                &app,
                "/api/custom-oauth-provider/",
                Some(&root),
                Some(&body),
            )
            .await,
            MSG_SLUG_BUILTIN_CONFLICT,
        )
        .await;
    }
    let body = r#"{"name":"Bad Slug","slug":"has_underscore","client_id":"c","client_secret":"s",
                 "authorization_endpoint":"a","token_endpoint":"t","user_info_endpoint":"u"}"#;
    assert_business_message(
        post_with(&app, "/api/custom-oauth-provider/", Some(&root), Some(body)).await,
        "provider slug must contain only lowercase letters, numbers, and hyphens",
    )
    .await;

    // ---- 创建：混合大小写 slug 被 validate 小写化后落库 -----------------------
    let body = r#"{"name":"Mixed Case","slug":"Mixed-Case","client_id":"c","client_secret":"s",
                 "authorization_endpoint":"a","token_endpoint":"t","user_info_endpoint":"u"}"#;
    let mixed = assert_message(
        post_with(&app, "/api/custom-oauth-provider/", Some(&root), Some(body)).await,
        MSG_CREATED,
    )
    .await;
    assert_eq!(mixed["data"]["slug"], json!("mixed-case"), "{mixed}");
    let mixed_id = mixed["data"]["id"].as_i64().expect("id");
    assert_eq!(
        provider_row(&db, mixed_id).await.expect("row")["slug"],
        json!("mixed-case")
    );

    // ---- 创建：字段映射与 scopes 的默认值填充 ---------------------------------
    let body = r#"{"name":"Plain OIDC","slug":"plain-oidc","client_id":"cid","client_secret":"sec",
                 "authorization_endpoint":"https://a","token_endpoint":"https://t",
                 "user_info_endpoint":"https://u"}"#;
    let plain = assert_message(
        post_with(&app, "/api/custom-oauth-provider/", Some(&root), Some(body)).await,
        MSG_CREATED,
    )
    .await;
    assert_eq!(
        plain["data"]["scopes"],
        json!("openid profile email"),
        "{plain}"
    );
    assert_eq!(plain["data"]["user_id_field"], json!("sub"));
    assert_eq!(plain["data"]["username_field"], json!("preferred_username"));
    assert_eq!(plain["data"]["display_name_field"], json!("name"));
    assert_eq!(plain["data"]["email_field"], json!("email"));
    assert_eq!(plain["data"]["icon"], json!(""));
    assert_eq!(plain["data"]["enabled"], json!(false));
    let plain_id = plain["data"]["id"].as_i64().expect("id");

    // ---- 创建：access_policy 校验三分支 ---------------------------------------
    for (index, (policy, message)) in [
        ("not json", "access_policy must be valid JSON"),
        ("[1,2]", "access_policy must be valid JSON"),
        (
            r#"{"logic":"xor"}"#,
            "access_policy is invalid: unsupported logic: xor",
        ),
        (
            r#"{"logic":"and"}"#,
            "access_policy is invalid: policy requires at least one condition or group",
        ),
        (
            r#"{"conditions":[{"op":"eq","value":"a"}]}"#,
            "access_policy is invalid: condition[0].field is required",
        ),
        (
            r#"{"conditions":[{"field":"email","op":"eq","value":"a"}],
                "groups":[{"logic":"and"}]}"#,
            "access_policy is invalid: group[0]: policy requires at least one condition or group",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let body = format!(
            r#"{{"name":"Policy","slug":"policy-{index}","client_id":"c","client_secret":"s",
                 "authorization_endpoint":"a","token_endpoint":"t","user_info_endpoint":"u",
                 "access_policy":{policy}}}"#
        );
        assert_business_message(
            post_with(
                &app,
                "/api/custom-oauth-provider/",
                Some(&root),
                Some(&body),
            )
            .await,
            message,
        )
        .await;
    }
    // 合法策略落库并原样回显（JSON 字符串列）。
    let valid_policy =
        r#"{"logic":"and","conditions":[{"field":"email","op":"eq","value":"a@b"}]}"#;
    let body = format!(
        r#"{{"name":"Policy OK","slug":"policy-ok","client_id":"c","client_secret":"s",
            "authorization_endpoint":"a","token_endpoint":"t","user_info_endpoint":"u",
            "access_policy":{valid_policy}}}"#
    );
    let policy_ok = assert_message(
        post_with(
            &app,
            "/api/custom-oauth-provider/",
            Some(&root),
            Some(&body),
        )
        .await,
        MSG_CREATED,
    )
    .await;
    assert_eq!(
        policy_ok["data"]["access_policy"],
        json!(valid_policy),
        "{policy_ok}"
    );
    let policy_ok_id = policy_ok["data"]["id"].as_i64().expect("id");

    // ---- 列表：按 id 升序 ------------------------------------------------------
    let listing = assert_message(
        send(
            &app,
            Method::GET,
            "/api/custom-oauth-provider/",
            Some(&root),
            None,
            None,
        )
        .await,
        "",
    )
    .await;
    let listing: Vec<(i64, String)> = listing["data"]
        .as_array()
        .expect("data is array")
        .iter()
        .map(|item| {
            (
                item["id"].as_i64().expect("id"),
                item["slug"].as_str().expect("slug").to_owned(),
            )
        })
        .collect();
    assert_eq!(
        listing,
        vec![
            (provider_id, "github-enterprise".to_owned()),
            (mixed_id, "mixed-case".to_owned()),
            (plain_id, "plain-oidc".to_owned()),
            (policy_ok_id, "policy-ok".to_owned()),
        ],
        "列表顺序与各创建后的 slug 不符"
    );

    // ---- 更新：分支顺序（id → body → 查库）------------------------------------
    assert_business_message(
        put_with(
            &app,
            "/api/custom-oauth-provider/abc",
            Some(&root),
            Some("{}"),
        )
        .await,
        MSG_INVALID_ID,
    )
    .await;
    assert_business_message(
        put_with(
            &app,
            &format!("/api/custom-oauth-provider/{provider_id}"),
            Some(&root),
            Some("not json"),
        )
        .await,
        &invalid_params,
    )
    .await;
    assert_business_message(
        put_with(
            &app,
            "/api/custom-oauth-provider/999",
            Some(&root),
            Some("{}"),
        )
        .await,
        MSG_PROVIDER_NOT_FOUND,
    )
    .await;

    // ---- 更新：空体 / null 不改一行 --------------------------------------------
    for body in ["{}", "null"] {
        let body = assert_message(
            put_with(
                &app,
                &format!("/api/custom-oauth-provider/{provider_id}"),
                Some(&root),
                Some(body),
            )
            .await,
            MSG_UPDATED,
        )
        .await;
        assert_eq!(body["data"]["name"], json!("GitHub Enterprise"), "{body}");
        assert_eq!(body["data"]["slug"], json!("github-enterprise"));
        assert_eq!(body["data"]["enabled"], json!(true));
    }
    assert_eq!(
        provider_row(&db, provider_id).await.expect("row")["client_secret"],
        json!("gh-client-secret")
    );

    // ---- 更新：部分覆盖与“空值保留” --------------------------------------------
    let body = assert_message(
        put_with(
            &app,
            &format!("/api/custom-oauth-provider/{provider_id}"),
            Some(&root),
            Some(r#"{"name":"GH Enterprise 2"}"#),
        )
        .await,
        MSG_UPDATED,
    )
    .await;
    assert_eq!(body["data"]["name"], json!("GH Enterprise 2"), "{body}");
    assert_eq!(body["data"]["slug"], json!("github-enterprise"));

    // 指针字段：显式空串清空原值；enabled/auth_style 有值即写回。
    let body = assert_message(
        put_with(
            &app,
            &format!("/api/custom-oauth-provider/{provider_id}"),
            Some(&root),
            Some(r#"{"icon":"","enabled":false,"auth_style":2}"#),
        )
        .await,
        MSG_UPDATED,
    )
    .await;
    assert_eq!(body["data"]["icon"], json!(""), "{body}");
    assert_eq!(body["data"]["enabled"], json!(false));
    assert_eq!(body["data"]["auth_style"], json!(2));

    // 字符串字段：空串与 null 都保留原值；空白字符串非空，按 Go 的
    // `!= ""` 判断会被写入（与 Go oracle 一致）。
    assert_message(
        put_with(
            &app,
            &format!("/api/custom-oauth-provider/{provider_id}"),
            Some(&root),
            Some(r#"{"client_secret":"","client_id":null,"token_endpoint":" "}"#),
        )
        .await,
        MSG_UPDATED,
    )
    .await;
    let stored = provider_row(&db, provider_id).await.expect("row");
    assert_eq!(
        stored["client_secret"],
        json!("gh-client-secret"),
        "空串保留原密钥"
    );
    assert_eq!(stored["client_id"], json!("gh-client-id"), "null 保留原值");
    assert_eq!(
        stored["token_endpoint"],
        json!(" "),
        "空白字符串被写入: {stored}"
    );
    // 恢复 token_endpoint，避免污染后续断言；同时覆盖一次普通写。
    assert_message(
        put_with(
            &app,
            &format!("/api/custom-oauth-provider/{provider_id}"),
            Some(&root),
            Some(r#"{"token_endpoint":"https://gh.example/login/oauth/token"}"#),
        )
        .await,
        MSG_UPDATED,
    )
    .await;

    // 密钥轮换：非空才覆盖；回显同样不含 client_secret。
    assert_message(
        put_with(
            &app,
            &format!("/api/custom-oauth-provider/{provider_id}"),
            Some(&root),
            Some(r#"{"client_secret":"rotated-secret"}"#),
        )
        .await,
        MSG_UPDATED,
    )
    .await;
    assert_eq!(
        provider_row(&db, provider_id).await.expect("row")["client_secret"],
        json!("rotated-secret")
    );
    let body = assert_message(
        send(
            &app,
            Method::GET,
            &format!("/api/custom-oauth-provider/{provider_id}"),
            Some(&root),
            None,
            None,
        )
        .await,
        "",
    )
    .await;
    assert!(body["data"].get("client_secret").is_none(), "{body}");

    // access_policy：显式空串清空；null 保留。
    assert_message(
        put_with(
            &app,
            &format!("/api/custom-oauth-provider/{provider_id}"),
            Some(&root),
            Some(r#"{"access_policy":""}"#),
        )
        .await,
        MSG_UPDATED,
    )
    .await;
    assert_eq!(
        provider_row(&db, provider_id).await.expect("row")["access_policy"],
        json!(""),
        "显式空串清空策略"
    );
    assert_message(
        put_with(
            &app,
            &format!("/api/custom-oauth-provider/{provider_id}"),
            Some(&root),
            Some(r#"{"access_policy":null,"well_known":"https://idp.example"}"#),
        )
        .await,
        MSG_UPDATED,
    )
    .await;
    let stored = provider_row(&db, provider_id).await.expect("row");
    assert_eq!(
        stored["access_policy"],
        json!(""),
        "null 不改写已清空的策略: {stored}"
    );
    assert_eq!(stored["well_known"], json!("https://idp.example"));

    // ---- 更新：slug 冲突（排除自身；同 slug 不检查）----------------------------
    let body = assert_message(
        put_with(
            &app,
            &format!("/api/custom-oauth-provider/{provider_id}"),
            Some(&root),
            Some(r#"{"slug":"github-enterprise"}"#),
        )
        .await,
        MSG_UPDATED,
    )
    .await;
    assert_eq!(body["data"]["slug"], json!("github-enterprise"));
    // 其他提供商已占用 plain-oidc。
    assert_business_message(
        put_with(
            &app,
            &format!("/api/custom-oauth-provider/{provider_id}"),
            Some(&root),
            Some(r#"{"slug":"plain-oidc"}"#),
        )
        .await,
        MSG_SLUG_TAKEN,
    )
    .await;
    assert_business_message(
        put_with(
            &app,
            &format!("/api/custom-oauth-provider/{provider_id}"),
            Some(&root),
            Some(r#"{"slug":"github"}"#),
        )
        .await,
        MSG_SLUG_BUILTIN_CONFLICT,
    )
    .await;
    // 更新的 slug 同样被 validate 小写化。
    let body = assert_message(
        put_with(
            &app,
            &format!("/api/custom-oauth-provider/{provider_id}"),
            Some(&root),
            Some(r#"{"slug":"GH-Enterprise"}"#),
        )
        .await,
        MSG_UPDATED,
    )
    .await;
    assert_eq!(body["data"]["slug"], json!("gh-enterprise"), "{body}");
    // 更新路径上非法字符集仍走 validate。
    assert_business_message(
        put_with(
            &app,
            &format!("/api/custom-oauth-provider/{provider_id}"),
            Some(&root),
            Some(r#"{"slug":"gh_enterprise"}"#),
        )
        .await,
        "provider slug must contain only lowercase letters, numbers, and hyphens",
    )
    .await;

    // ---- 删除：分支顺序与绑定门禁 ----------------------------------------------
    assert_business_message(
        delete_with(&app, "/api/custom-oauth-provider/abc", Some(&root)).await,
        MSG_INVALID_ID,
    )
    .await;
    assert_business_message(
        delete_with(&app, "/api/custom-oauth-provider/999", Some(&root)).await,
        MSG_PROVIDER_NOT_FOUND,
    )
    .await;
    seed_binding(&db, 1, 1, provider_id, "gh-admin-1").await;
    assert_business_message(
        delete_with(
            &app,
            &format!("/api/custom-oauth-provider/{provider_id}"),
            Some(&root),
        )
        .await,
        MSG_DELETE_HAS_BINDINGS,
    )
    .await;
    assert!(
        provider_row(&db, provider_id).await.is_some(),
        "有绑定时不删除提供商"
    );
    // 解除绑定后可删；成功响应无 data 键。
    backend!(&db, pool, {
        sqlx::query("DELETE FROM user_oauth_bindings WHERE provider_id = $1")
            .bind(provider_id)
            .execute(pool)
            .await
            .expect("clear bindings");
    });
    let body = assert_message(
        delete_with(
            &app,
            &format!("/api/custom-oauth-provider/{provider_id}"),
            Some(&root),
        )
        .await,
        MSG_DELETED,
    )
    .await;
    assert!(body.get("data").is_none(), "删除成功无 data: {body}");
    assert!(provider_row(&db, provider_id).await.is_none(), "行已删除");
    assert_business_message(
        send(
            &app,
            Method::GET,
            &format!("/api/custom-oauth-provider/{provider_id}"),
            Some(&root),
            None,
            None,
        )
        .await,
        MSG_PROVIDER_NOT_FOUND,
    )
    .await;

    // ---- 删除：绑定计数读取失败 → 固定中文，不转述 SQL --------------------------
    exec(&db, "DROP TABLE user_oauth_bindings").await;
    assert_business_message(
        delete_with(
            &app,
            &format!("/api/custom-oauth-provider/{mixed_id}"),
            Some(&root),
        )
        .await,
        MSG_BINDING_COUNT_FAILED,
    )
    .await;
    assert!(
        provider_row(&db, mixed_id).await.is_some(),
        "计数失败不删除提供商"
    );

    // ---- 审计：写方法全落库、读方法不落、顺序即场景 ----------------------------
    // 到达 handler 的写请求：创建 26 条（10 无效体 + 成功 + slug 重复 +
    // 4 内置冲突 + 字符集 + mixed/plain 成功 + 6 策略失败 + 策略成功）、
    // 更新 17 条、删除 5 条。
    let rows = audit_rows(&db).await;
    assert_eq!(rows.len(), 48, "{rows:?}");
    let mut expected = Vec::new();
    // 创建：10 条无效请求体。
    for _ in 0..10 {
        expected.push(("custom_oauth.create", false));
    }
    // 创建：成功 + slug 重复 + 4 内置冲突 + 字符集 + mixed/plain 两条成功。
    expected.extend([
        ("custom_oauth.create", true),
        ("custom_oauth.create", false),
        ("custom_oauth.create", false),
        ("custom_oauth.create", false),
        ("custom_oauth.create", false),
        ("custom_oauth.create", false),
        ("custom_oauth.create", false),
        ("custom_oauth.create", true),
        ("custom_oauth.create", true),
    ]);
    // 创建：6 条 access_policy 失败 + 1 条成功。
    for _ in 0..6 {
        expected.push(("custom_oauth.create", false));
    }
    expected.push(("custom_oauth.create", true));
    // 更新：3 条前置失败（非法 id / 非法体 / 未找到）→ 10 条成功 →
    // slug 占用与内置冲突 → mixed-case 成功 → 字符集失败。
    expected.extend([
        ("custom_oauth.update", false),
        ("custom_oauth.update", false),
        ("custom_oauth.update", false),
        ("custom_oauth.update", true),
        ("custom_oauth.update", true),
        ("custom_oauth.update", true),
        ("custom_oauth.update", true),
        ("custom_oauth.update", true),
        ("custom_oauth.update", true),
        ("custom_oauth.update", true),
        ("custom_oauth.update", true),
        ("custom_oauth.update", true),
        ("custom_oauth.update", true),
        ("custom_oauth.update", false),
        ("custom_oauth.update", false),
        ("custom_oauth.update", true),
        ("custom_oauth.update", false),
    ]);
    // 删除：非法 id / 未找到 / 有绑定 / 成功 / 绑定计数失败。
    expected.extend([
        ("custom_oauth.delete", false),
        ("custom_oauth.delete", false),
        ("custom_oauth.delete", false),
        ("custom_oauth.delete", true),
        ("custom_oauth.delete", false),
    ]);
    let actual: Vec<(String, bool)> = rows
        .iter()
        .map(|row| (row.action.clone(), row.success))
        .collect();
    assert_eq!(
        actual,
        expected
            .iter()
            .map(|(action, success)| (action.to_string(), *success))
            .collect::<Vec<_>>(),
        "审计序列与场景顺序不符"
    );
    // 内容与归属抽两条核对（Go content = method + " " + route）。
    let create_row = &rows[10];
    assert_eq!(create_row.action, "custom_oauth.create");
    assert!(create_row.success);
    assert_eq!(create_row.user_id, 3);
    assert_eq!(create_row.method, "POST");
    assert_eq!(create_row.route, "/api/custom-oauth-provider/");
    assert_eq!(create_row.path, "/api/custom-oauth-provider/");
    assert_eq!(create_row.status, 200);
    assert!(
        create_row.op_params.is_none(),
        "已登记 action 不带 op.params: {:?}",
        create_row.op_params
    );
    let delete_row = rows
        .iter()
        .find(|row| row.action == "custom_oauth.delete" && row.success)
        .expect("成功删除审计");
    assert_eq!(delete_row.route, "/api/custom-oauth-provider/:id");
    assert_eq!(delete_row.method, "DELETE");
    assert_eq!(
        delete_row.params.as_ref().expect("params")["id"],
        json!(provider_id.to_string())
    );
    // 全部审计都归属 root（type=3 由仓储写入，见 oauth_binding_routes 的同款断言）。
    for row in &rows {
        assert_eq!(row.user_id, 3, "操作者是 root: {row:?}");
    }
}

// ---------------------------------------------------------------------------
// discovery 契约
// ---------------------------------------------------------------------------

async fn run_discovery_contract(db: Database) {
    create_schema(&db).await;
    // discovery 不读写提供商表；只需要 root 能通过权限层。
    seed_user(&db, 3, "fixture-root", 100, Some(PAT_ROOT)).await;
    let app = state(&db);
    let root = format!("Bearer {PAT_ROOT}");
    let invalid_params = translated(MSG_INVALID_PARAMS);

    // ---- BindJSON 分支与两个 URL 都空 ----------------------------------------
    assert_business_message(
        post_with(
            &app,
            "/api/custom-oauth-provider/discovery",
            Some(&root),
            Some("not json"),
        )
        .await,
        &invalid_params,
    )
    .await;
    assert_business_message(
        post_with(
            &app,
            "/api/custom-oauth-provider/discovery",
            Some(&root),
            Some("{}"),
        )
        .await,
        MSG_DISCOVERY_EMPTY,
    )
    .await;
    // 空白串 trim 后同样视为空。
    assert_business_message(
        post_with(
            &app,
            "/api/custom-oauth-provider/discovery",
            Some(&root),
            Some(r#"{"well_known_url":"   ","issuer_url":" "}"#),
        )
        .await,
        MSG_DISCOVERY_EMPTY,
    )
    .await;

    // ---- issuer 推导：去尾斜线 + discovery 后缀 --------------------------------
    let transport = FakeDiscoveryTransport::new(vec![CannedDiscovery::Json(
        "{\"issuer\":\"https://idp.example\"}".to_owned(),
    )]);
    let transport = Arc::new(transport);
    let body = assert_message(
        discovery_with(
            &app,
            &root,
            r#"{"issuer_url":"https://idp.example///"}"#,
            transport.clone(),
        )
        .await,
        "",
    )
    .await;
    assert_eq!(
        body["data"]["well_known_url"],
        json!("https://idp.example/.well-known/openid-configuration"),
        "{body}"
    );
    assert_eq!(
        body["data"]["discovery"],
        json!({"issuer": "https://idp.example"}),
        "{body}"
    );
    assert_eq!(
        transport.calls(),
        vec!["https://idp.example/.well-known/openid-configuration".to_owned()]
    );

    // ---- URL 校验：scheme 与 host ---------------------------------------------
    for body in [
        r#"{"well_known_url":"ftp://evil.example/.well-known/openid-configuration"}"#,
        r#"{"well_known_url":"example.com/.well-known/openid-configuration"}"#,
        r#"{"well_known_url":"http:///path"}"#,
        r#"{"well_known_url":"https://"}"#,
        r#"{"issuer_url":"/issuer"}"#,
    ] {
        assert_business_message(
            post_with(
                &app,
                "/api/custom-oauth-provider/discovery",
                Some(&root),
                Some(body),
            )
            .await,
            MSG_DISCOVERY_INVALID_URL,
        )
        .await;
    }
    // Go 的 url.Parse 小写化 scheme：HTTP:// 同样放行，目标串按原样请求。
    let transport = FakeDiscoveryTransport::new(vec![CannedDiscovery::Json("{}".to_owned())]);
    let transport = Arc::new(transport);
    assert_message(
        discovery_with(
            &app,
            &root,
            r#"{"well_known_url":"HTTP://ok.example/.well-known/openid-configuration"}"#,
            transport.clone(),
        )
        .await,
        "",
    )
    .await;
    assert_eq!(
        transport.calls(),
        vec!["HTTP://ok.example/.well-known/openid-configuration".to_owned()]
    );
    // well_known 优先于 issuer。
    let transport = FakeDiscoveryTransport::new(vec![CannedDiscovery::Json("{}".to_owned())]);
    let transport = Arc::new(transport);
    assert_message(
        discovery_with(
            &app,
            &root,
            r#"{"well_known_url":"https://wk.example/oidc","issuer_url":"https://issuer.example"}"#,
            transport.clone(),
        )
        .await,
        "",
    )
    .await;
    assert_eq!(
        transport.calls(),
        vec!["https://wk.example/oidc".to_owned()]
    );

    // ---- 传输失败 / 非 200 / 解析失败 -------------------------------------------
    let transport = FakeDiscoveryTransport::new(vec![CannedDiscovery::Transport]);
    assert_business_message(
        discovery_with(
            &app,
            &root,
            r#"{"well_known_url":"https://wk.example/oidc"}"#,
            Arc::new(transport),
        )
        .await,
        MSG_DISCOVERY_FETCH_FAILED,
    )
    .await;
    // 非 200：透传上游响应体（至多 512 字节）。
    let transport = FakeDiscoveryTransport::new(vec![CannedDiscovery::Status(
        404,
        "no such discovery document".to_owned(),
    )]);
    assert_business_message(
        discovery_with(
            &app,
            &root,
            r#"{"well_known_url":"https://wk.example/oidc"}"#,
            Arc::new(transport),
        )
        .await,
        &format!("{MSG_DISCOVERY_FETCH_FAILED}: no such discovery document"),
    )
    .await;
    // 非 200 且响应体为空：用 Go 的 resp.Status（"<code> <reason>"）。
    let transport = FakeDiscoveryTransport::new(vec![CannedDiscovery::Status(500, String::new())]);
    assert_business_message(
        discovery_with(
            &app,
            &root,
            r#"{"well_known_url":"https://wk.example/oidc"}"#,
            Arc::new(transport),
        )
        .await,
        &format!("{MSG_DISCOVERY_FETCH_FAILED}: 500 Internal Server Error"),
    )
    .await;
    // 200 但非 JSON 对象：解析失败。
    let transport = FakeDiscoveryTransport::new(vec![CannedDiscovery::Json("[1,2]".to_owned())]);
    assert_business_message(
        discovery_with(
            &app,
            &root,
            r#"{"well_known_url":"https://wk.example/oidc"}"#,
            Arc::new(transport),
        )
        .await,
        MSG_DISCOVERY_PARSE_FAILED,
    )
    .await;

    // ---- 200：常规文档 / 尾随内容 / null --------------------------------------
    let document = r#"{"authorization_endpoint":"https://a","token_endpoint":"https://t",
        "userinfo_endpoint":"https://u","scopes_supported":["openid","profile"],
        "issuer":"https://idp.example"}"#;
    let transport = FakeDiscoveryTransport::new(vec![
        CannedDiscovery::Json(format!("{document} trailing")),
        CannedDiscovery::Json("null".to_owned()),
    ]);
    let transport = Arc::new(transport);
    let body = assert_message(
        discovery_with(
            &app,
            &root,
            r#"{"well_known_url":" https://wk.example/.well-known/openid-configuration "}"#,
            transport.clone(),
        )
        .await,
        "",
    )
    .await;
    // Go 的 json.NewDecoder 只读首个完整值：尾随内容被忽略。
    assert_eq!(
        body["data"]["discovery"],
        json!({
            "authorization_endpoint": "https://a",
            "token_endpoint": "https://t",
            "userinfo_endpoint": "https://u",
            "scopes_supported": ["openid", "profile"],
            "issuer": "https://idp.example",
        }),
        "{body}"
    );
    assert_eq!(
        body["data"]["well_known_url"],
        json!("https://wk.example/.well-known/openid-configuration"),
        "{body}"
    );
    // Go 的 null → nil map：discovery 字段为 JSON null。
    let body = assert_message(
        discovery_with(
            &app,
            &root,
            r#"{"well_known_url":"https://wk.example/oidc"}"#,
            transport.clone(),
        )
        .await,
        "",
    )
    .await;
    assert_eq!(body["data"]["discovery"], json!(Value::Null), "{body}");
    assert_eq!(
        transport.calls(),
        vec![
            "https://wk.example/.well-known/openid-configuration".to_owned(),
            "https://wk.example/oidc".to_owned(),
        ]
    );

    // ---- 审计：discovery 的每次尝试都落 generic --------------------------------
    // 上面的请求全部到达 handler：1 invalid + 2 empty + 3 issuer 推导与
    // HTTP/wk 优先 + 5 非法 URL + 1 传输失败 + 2 非 200 + 1 解析失败
    // + 2 成功 = 17 条，全部 action=generic（op.params 带 method/route）。
    let rows = audit_rows(&db).await;
    assert_eq!(rows.len(), 17, "{rows:?}");
    for row in &rows {
        assert_eq!(row.action, "generic", "{row:?}");
        assert_eq!(row.method, "POST", "{row:?}");
        assert_eq!(row.route, "/api/custom-oauth-provider/discovery", "{row:?}");
        assert_eq!(
            row.op_params.as_ref().expect("op params")["method"],
            json!("POST")
        );
        assert_eq!(
            row.op_params.as_ref().expect("op params")["route"],
            json!("/api/custom-oauth-provider/discovery")
        );
        assert!(row.params.is_none(), "discovery 无路由参数: {row:?}");
    }
    // 成功五条（issuer 推导 + HTTP 放行 + wk 优先 + 两份文档）；其余为失败。
    let successes = rows.iter().filter(|row| row.success).count();
    assert_eq!(successes, 5, "{rows:?}");
    assert_eq!(rows[0].user_id, 3, "操作者是 root");
}

// ---------------------------------------------------------------------------
// 两个后端的入口
// ---------------------------------------------------------------------------

async fn sqlite_fixture() -> Database {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    Database::Sqlite(pool)
}

async fn postgres_fixture(schema_prefix: &str) -> Option<Database> {
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
        "{schema_prefix}_{}_{}",
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

async fn drop_schema(db: &Database) {
    let Database::Postgres(pool) = db else {
        return;
    };
    let schema =
        sqlx::query_scalar::<_, String>("SELECT current_setting('search_path') AS search_path")
            .fetch_one(pool)
            .await
            .expect("read search_path");
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(
            std::env::var("TEST_POSTGRES_DSN")
                .expect("TEST_POSTGRES_DSN")
                .as_str(),
        )
        .await
        .expect("reconnect admin pool");
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA \"{}\" CASCADE",
        schema.split(',').next().unwrap_or(&schema)
    )))
    .execute(&admin)
    .await
    .expect("drop isolated schema");
    admin.close().await;
}

#[tokio::test]
async fn sqlite_custom_oauth_auth_contract() {
    run_auth_contract(sqlite_fixture().await).await;
}

#[tokio::test]
async fn postgres_custom_oauth_auth_contract() {
    let Some(db) = postgres_fixture("custom_oauth_auth").await else {
        return;
    };
    run_auth_contract(db.clone()).await;
    drop_schema(&db).await;
}

#[tokio::test]
async fn sqlite_custom_oauth_crud_contract() {
    run_crud_contract(sqlite_fixture().await).await;
}

#[tokio::test]
async fn postgres_custom_oauth_crud_contract() {
    let Some(db) = postgres_fixture("custom_oauth_crud").await else {
        return;
    };
    run_crud_contract(db.clone()).await;
    drop_schema(&db).await;
}

#[tokio::test]
async fn sqlite_custom_oauth_discovery_contract() {
    run_discovery_contract(sqlite_fixture().await).await;
}

#[tokio::test]
async fn postgres_custom_oauth_discovery_contract() {
    let Some(db) = postgres_fixture("custom_oauth_discovery").await else {
        return;
    };
    run_discovery_contract(db.clone()).await;
    drop_schema(&db).await;
}
