//! 选项/系统设置管理端 12 路由的 HTTP 契约。
//!
//! 仅在远程 CI 运行。每个场景使用隔离的合成 fixture（内存 SQLite 或隔离
//! PostgreSQL schema），不启动服务、不连生产库。waffo-pancake 上游通过
//! `InjectedPancakeTransport` 注入假传输，测试从不触网。
//!
//! Go 参考：`register_api.go:298-312`（路由链）、`ops/manage_options.go`
//! （GET/PUT 契约）、`ops/store_options.go`（可见快照）、
//! `billing/payment_compliance.go`、`billing/topup_waffo_pancake.go`、
//! `handler/handle_affinity_cache.go`/`handle_smtp_pool.go`、
//! `ops/manage_model_metadata.go:407`（ResetModelRatio）、
//! `security/audit_access.go`（兜底审计 action）。

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::State,
    http::{Method, Request, StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use newapi_server::option_http::{
    affinity_cache_stats, clear_affinity_cache, confirm_payment_compliance, get_options,
    require_system_settings, reset_model_ratio, smtp_pool_status, update_option, waffo_catalog,
    waffo_pair, waffo_save, waffo_subscription_product, waffo_subscription_product_options,
};
use newapi_server::pancake::{
    DEFAULT_PRODUCT_NAME, DEFAULT_STORE_NAME, InjectedPancakeTransport, PairOutcome, PancakeError,
    PancakeTransport, WaffoPancakeCatalog, WaffoPancakeCatalogProduct, WaffoPancakeCatalogStore,
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

static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

const SECRET: &str = "option-routes-fixture-secret";

const PAT_COMMON: &str = "pat-option-common";
const PAT_ADMIN: &str = "pat-option-admin";
const PAT_ROOT: &str = "pat-option-root";
const PAT_ADMIN_ALLOWED: &str = "pat-option-allowed";
const PAT_ADMIN_DENIED: &str = "pat-option-denied";

const AUTH_INSUFFICIENT_PRIVILEGE_CODE: &str = "AUTH_INSUFFICIENT_PRIVILEGE";

/// Go 固定文案。
const MSG_RESET_RATIO_SUCCESS: &str = "重置模型倍率成功";
const MSG_SESSION_ONLY: &str =
    "This operation requires dashboard session authentication. API access token is not allowed.";
const MSG_CONFIRM_REQUIRED: &str = "请确认合规声明";
const MSG_GITHUB_NEEDS_CLIENT_ID: &str =
    "无法启用 GitHub OAuth，请先填入 GitHub Client Id 以及 GitHub Client Secret！";
const MSG_THEME_REMOVED: &str = "Classic 前端已移除，主题只能设置为 default";
const MSG_COMPLIANCE_FIELDS_FORBIDDEN: &str = "合规确认字段不允许通过通用设置接口修改";
const MSG_AFFINITY_RULE_REQUIRED: &str = "缺少参数：rule_name，或使用 all=true 清空全部";
const MSG_AFFINITY_UNKNOWN_RULE: &str = "未知规则名称";
const MSG_PANCAKE_NOT_BOUND: &str = "Waffo Pancake 未完成配置，请先在支付设置中完成网关绑定";
const MSG_PANCAKE_CREDITS_MISSING: &str = "Waffo Pancake 凭证未配置";
const MSG_SAVE_FAILED: &str = "保存配置失败";

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

const CASBIN_SQLITE: &str = r#"CREATE TABLE casbin_rule (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ptype TEXT, v0 TEXT, v1 TEXT,
    v2 TEXT, v3 TEXT, v4 TEXT, v5 TEXT
)"#;

const CASBIN_POSTGRES: &str = r#"CREATE TABLE casbin_rule (
    id BIGSERIAL PRIMARY KEY, ptype TEXT, v0 TEXT, v1 TEXT,
    v2 TEXT, v3 TEXT, v4 TEXT, v5 TEXT
)"#;

const OPTIONS_SQLITE: &str = r#"CREATE TABLE options ("key" TEXT PRIMARY KEY, "value" TEXT)"#;

const OPTIONS_POSTGRES: &str = r#"CREATE TABLE options ("key" TEXT PRIMARY KEY, "value" TEXT)"#;

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

/// 与 `http.rs` 的注册保持同一形态（含根路由的尾斜线双注册）。
fn router(state: AppState) -> Router {
    let routes = Router::new()
        .route("/api/option/", get(get_options).put(update_option))
        .route("/api/option", get(get_options).put(update_option))
        .route(
            "/api/option/channel_affinity_cache",
            get(affinity_cache_stats).delete(clear_affinity_cache),
        )
        .route("/api/option/smtp_pool_status", get(smtp_pool_status))
        .route("/api/option/rest_model_ratio", post(reset_model_ratio))
        .route(
            "/api/option/payment_compliance",
            post(confirm_payment_compliance),
        )
        .route("/api/option/waffo-pancake/catalog", get(waffo_catalog))
        .route("/api/option/waffo-pancake/pair", post(waffo_pair))
        .route("/api/option/waffo-pancake/save", post(waffo_save))
        .route(
            "/api/option/waffo-pancake/subscription-product",
            post(waffo_subscription_product),
        )
        .route(
            "/api/option/waffo-pancake/subscription-product-options",
            get(waffo_subscription_product_options),
        )
        .route("/api/notice", get(notice_probe))
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

/// 公共 GET /api/notice 的等价投影（http.rs 的 `notice` 为私有；这里按
/// 同一快照语义构造，供 audit #47 的 reload 可见性断言使用）。
async fn notice_probe(State(state): State<AppState>) -> Response {
    let notice = state.snapshot().notice;
    Json(serde_json::json!({ "success": true, "message": "", "data": notice })).into_response()
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
            for statement in [USERS_SQLITE, CASBIN_SQLITE, OPTIONS_SQLITE, LOGS_SQLITE] {
                exec(db, statement).await;
            }
        }
        Database::Postgres(_) => {
            for statement in [
                USERS_POSTGRES,
                CASBIN_POSTGRES,
                OPTIONS_POSTGRES,
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

/// Go `policy.Can` 的用户级覆盖。
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

async fn seed_option(db: &Database, key: &str, value: &str) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO options ("key", "value") VALUES ($1, $2)
               ON CONFLICT ("key") DO UPDATE SET "value" = excluded."value""#,
        )
        .bind(key)
        .bind(value)
        .execute(pool)
        .await
        .expect("seed option");
    });
}

async fn option_row(db: &Database, key: &str) -> Option<String> {
    backend!(db, pool, {
        sqlx::query_scalar::<_, Option<String>>(r#"SELECT "value" FROM options WHERE "key" = $1"#)
            .bind(key)
            .fetch_optional(pool)
            .await
            .expect("option row")
            .flatten()
    })
}

/// 审计行的内容投影（`logs.other` JSON 解码）。
#[derive(Debug)]
struct AuditRow {
    user_id: i64,
    action: String,
    method: String,
    route: String,
    status: i64,
    success: bool,
}

async fn audit_rows(db: &Database) -> Vec<AuditRow> {
    let rows = backend!(db, pool, {
        sqlx::query_as::<_, (i64, Option<String>)>(
            "SELECT CAST(user_id AS BIGINT) AS user_id, other FROM logs ORDER BY id ASC",
        )
        .fetch_all(pool)
        .await
        .expect("audit rows")
    });
    rows.into_iter()
        .map(|(user_id, other)| {
            let value: Value =
                serde_json::from_str(&other.unwrap_or_default()).expect("other JSON");
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
                status: value["audit_info"]["status"].as_i64().unwrap_or(0),
                success: value["audit_info"]["success"].as_bool().unwrap_or(false),
            }
        })
        .collect()
}

/// 注入式 Pancake 传输的预置行为。
#[derive(Clone)]
enum Canned {
    Catalog(Result<WaffoPancakeCatalog, PancakeError>),
    Pair(PairOutcome),
    Transport,
}

#[derive(Clone)]
struct FakePancakeTransport {
    calls: Arc<Mutex<Vec<String>>>,
    queue: Arc<Mutex<Vec<Canned>>>,
}

impl FakePancakeTransport {
    fn new(canned: Vec<Canned>) -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            queue: Arc::new(Mutex::new(canned)),
        }
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("calls").clone()
    }

    fn record(&self, call: &str) {
        self.calls.lock().expect("calls").push(call.to_owned());
    }

    fn take(&self) -> Canned {
        self.queue
            .lock()
            .expect("queue")
            .pop_front()
            .unwrap_or(Canned::Transport)
    }
}

impl PancakeTransport for FakePancakeTransport {
    fn catalog<'a>(
        &'a self,
        merchant_id: &'a str,
        _private_key: &'a str,
    ) -> newapi_server::pancake::PancakeFuture<'a, WaffoPancakeCatalog> {
        self.record("catalog");
        Box::pin(async move {
            let _ = merchant_id;
            match self.take() {
                Canned::Catalog(result) => result,
                _ => Err(PancakeError("unexpected call".to_owned())),
            }
        })
    }

    fn create_pair<'a>(
        &'a self,
        _merchant_id: &'a str,
        _private_key: &'a str,
        _return_url: &'a str,
    ) -> newapi_server::pancake::PancakeFuture<'a, PairOutcome> {
        self.record("create_pair");
        Box::pin(async move {
            match self.take() {
                Canned::Pair(outcome) => Ok(outcome),
                _ => Err(PancakeError("unexpected call".to_owned())),
            }
        })
    }

    fn create_product<'a>(
        &'a self,
        _merchant_id: &'a str,
        _private_key: &'a str,
        store_id: &'a str,
        name: &'a str,
        _amount: &'a str,
        _return_url: &'a str,
    ) -> newapi_server::pancake::PancakeFuture<'a, String> {
        self.record(format!("create_product:{store_id}:{name}").as_str());
        Box::pin(async move {
            match self.take() {
                Canned::Pair(PairOutcome::Complete(result)) => Ok(result.product_id),
                Canned::Pair(PairOutcome::Failed(message)) => Err(PancakeError(message)),
                Canned::Pair(PairOutcome::OrphanStore { error, .. }) => Err(PancakeError(error)),
                _ => Err(PancakeError("unexpected call".to_owned())),
            }
        })
    }
}

fn catalog_fixture() -> WaffoPancakeCatalog {
    WaffoPancakeCatalog {
        stores: vec![WaffoPancakeCatalogStore {
            id: "STO_1".to_owned(),
            name: "store one".to_owned(),
            status: "active".to_owned(),
            prod_enabled: true,
            onetime_products: vec![WaffoPancakeCatalogProduct {
                id: "PROD_1".to_owned(),
                name: "product one".to_owned(),
                status: "active".to_owned(),
            }],
        }],
    }
}

fn sqlite_fixture() -> Database {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .expect("sqlite fixture");
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
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
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

async fn send(
    state: &AppState,
    method: Method,
    path: &str,
    authorization: Option<&str>,
    body: Option<&str>,
    transport: Option<Arc<FakePancakeTransport>>,
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
            .insert(InjectedPancakeTransport(transport));
    }
    router(state.clone()).oneshot(request).await.unwrap()
}

async fn body_json(response: Response) -> Value {
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

fn translated(key: &str) -> String {
    newapi_i18n::translate("en", key, std::iter::empty::<(&str, &str)>())
}

fn admin_auth() -> String {
    format!("Bearer {PAT_ADMIN}")
}

// ---------------------------------------------------------------------------
// 契约组 1：鉴权与权限
// ---------------------------------------------------------------------------

async fn run_auth_contract(db: Database) {
    create_schema(&db).await;
    seed_user(&db, 1, "fixture-common", 1, Some(PAT_COMMON)).await;
    seed_user(&db, 2, "fixture-admin", 10, Some(PAT_ADMIN)).await;
    seed_user(&db, 3, "fixture-root", 100, Some(PAT_ROOT)).await;
    seed_user(&db, 4, "fixture-admin-allowed", 10, Some(PAT_ADMIN_ALLOWED)).await;
    seed_user(&db, 5, "fixture-admin-denied", 10, Some(PAT_ADMIN_DENIED)).await;
    seed_policy(&db, 4, "").await;
    seed_policy(&db, 5, "allow").await;
    seed_policy(&db, 5, "deny").await;
    let app = state(&db);

    // 无凭据一律 401。
    assert_eq!(
        send(&app, Method::GET, "/api/option/", None, None, None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    // 普通用户：AdminAuth 先拒。
    let response = send(
        &app,
        Method::GET,
        "/api/option/",
        Some(&format!("Bearer {PAT_COMMON}")),
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = body_json(response).await;
    assert_eq!(
        body["code"],
        json!(AUTH_INSUFFICIENT_PRIVILEGE_CODE),
        "{body}"
    );
    // admin 无授权 → 403，`auth.insufficient_privilege`，无 code。
    let response = send(
        &app,
        Method::GET,
        "/api/option/",
        Some(&admin_auth()),
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false), "{body}");
    assert_eq!(
        body["message"],
        json!(translated("auth.insufficient_privilege")),
        "{body}"
    );
    assert!(body.get("code").is_none(), "{body}");
    // deny 短路。
    let response = send(
        &app,
        Method::GET,
        "/api/option/",
        Some(&format!("Bearer {PAT_ADMIN_DENIED}")),
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    // root 超级用户短路、admin 的用户级 allow。
    for authorization in [
        format!("Bearer {PAT_ROOT}"),
        format!("Bearer {PAT_ADMIN_ALLOWED}"),
    ] {
        let response = send(
            &app,
            Method::GET,
            "/api/option/",
            Some(authorization.as_str()),
            None,
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "{authorization}");
        let body = body_json(response).await;
        assert_eq!(body["success"], json!(true), "{body}");
    }
    // 写方法的权限 403 落兜底审计；GET 的 403 不落。
    send(
        &app,
        Method::POST,
        "/api/option/rest_model_ratio",
        Some(&admin_auth()),
        None,
        None,
    )
    .await;
    send(
        &app,
        Method::GET,
        "/api/option/",
        Some(&admin_auth()),
        None,
        None,
    )
    .await;
    let rows = audit_rows(&db).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].action, "option.reset_ratio", "{rows:?}");
    assert_eq!(rows[0].status, 403);
    assert!(!rows[0].success);
    assert_eq!(rows[0].user_id, 2);
}

#[tokio::test]
async fn sqlite_option_auth_contract() {
    run_auth_contract(sqlite_fixture()).await;
}

#[tokio::test]
async fn postgres_option_auth_contract() {
    let Some(db) = postgres_fixture("option_auth").await else {
        return;
    };
    run_auth_contract(db.clone()).await;
    drop_schema(&db).await;
}

// ---------------------------------------------------------------------------
// 契约组 2：GET /api/option/ 快照
// ---------------------------------------------------------------------------

async fn run_get_options_contract(db: Database) {
    create_schema(&db).await;
    seed_user(&db, 3, "fixture-root", 100, Some(PAT_ROOT)).await;
    seed_option(&db, "Notice", "自定义公告").await;
    seed_option(&db, "QuotaForNewUser", "100000").await;
    let app = state(&db);
    let response = send(
        &app,
        Method::GET,
        "/api/option/",
        Some(&format!("Bearer {PAT_ROOT}")),
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true));
    let entries = body["data"].as_array().expect("data array");
    let map: BTreeMap<String, String> = entries
        .iter()
        .map(|entry| {
            (
                entry["key"].as_str().expect("key").to_owned(),
                entry["value"].as_str().expect("value").to_owned(),
            )
        })
        .collect();

    // 敏感键不回显（Token/Secret/Key/secret/api_key 结尾）。
    for sensitive in [
        "SMTPToken",
        "GitHubClientSecret",
        "TurnstileSiteKey",
        "TurnstileSecretKey",
        "EpayKey",
        "VmqKey",
        "CodePayKey",
        "proxy_config",
    ] {
        assert!(!map.contains_key(sensitive), "{sensitive} must be hidden");
    }
    // `theme.frontend` 永不出现。
    assert!(!map.contains_key("theme.frontend"));
    // 种子默认值在缺行时出现。
    assert_eq!(map.get("SystemName").map(String::as_str), Some("New API"));
    assert_eq!(map.get("SMTPPort").map(String::as_str), Some("587"));
    assert_eq!(map.get("QuotaPerUnit").map(String::as_str), Some("500000"));
    // 数据库行覆盖种子。
    assert_eq!(map.get("Notice").map(String::as_str), Some("自定义公告"));
    // 金额键的 `_display` 兄弟键（默认 USD：quota / 500000）。
    assert_eq!(
        map.get("QuotaForNewUser").map(String::as_str),
        Some("100000")
    );
    assert_eq!(
        map.get("QuotaForNewUser_display").map(String::as_str),
        Some("0.2")
    );
    // 种子里 QuotaForNewUser 默认 0 → display "0"。
    assert_eq!(
        map.get("QuotaRemindThreshold").map(String::as_str),
        Some("1000")
    );
    assert_eq!(
        map.get("QuotaRemindThreshold_display").map(String::as_str),
        Some("0.002")
    );
    // CompletionRatioMeta 恒为最后一个条目，且是合法 JSON 对象。
    let last = entries.last().expect("meta entry");
    assert_eq!(last["key"], json!("CompletionRatioMeta"));
    let meta: Value =
        serde_json::from_str(last["value"].as_str().expect("meta value")).expect("meta JSON");
    assert!(meta.is_object(), "{meta}");
    // GET 不写审计。
    assert!(audit_rows(&db).await.is_empty(), "GET 不落审计");
}

#[tokio::test]
async fn sqlite_option_get_contract() {
    run_get_options_contract(sqlite_fixture()).await;
}

#[tokio::test]
async fn postgres_option_get_contract() {
    let Some(db) = postgres_fixture("option_get").await else {
        return;
    };
    run_get_options_contract(db.clone()).await;
    drop_schema(&db).await;
}

// ---------------------------------------------------------------------------
// 契约组 3：PUT /api/option/
// ---------------------------------------------------------------------------

async fn run_put_option_contract(db: Database) {
    create_schema(&db).await;
    seed_user(&db, 3, "fixture-root", 100, Some(PAT_ROOT)).await;
    let app = state(&db);
    let root = format!("Bearer {PAT_ROOT}");
    let put = |path: &'static str, body: Option<&'static str>| {
        let app = app.clone();
        let root = root.clone();
        Box::pin(
            async move { send(&app, Method::PUT, path, Some(root.as_str()), body, None).await },
        )
    };

    // 绑定失败：空体与坏 JSON → 400 "无效的参数"。
    for payload in [None, Some("{bad")] {
        let response = put("/api/option/", payload).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{payload:?}");
        let body = body_json(response).await;
        assert_eq!(body["success"], json!(false), "{body}");
        assert_eq!(body["message"], json!("无效的参数"), "{body}");
    }

    // `payment_setting.compliance_` 前缀拒绝。
    let response = put(
        "/api/option/",
        Some(r#"{"key":"payment_setting.compliance_confirmed","value":"true"}"#),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(
        body["message"],
        json!(MSG_COMPLIANCE_FIELDS_FORBIDDEN),
        "{body}"
    );

    // 合规门：邀请奖励键在未确认合规时拒绝（i18n key）。
    let response = put(
        "/api/option/",
        Some(r#"{"key":"QuotaForInviter_display","value":"5"}"#),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(
        body["message"],
        json!(translated("payment.compliance_required")),
        "{body}"
    );
    // 确认合规后放行，且 `_display` 归一为 base 键 + quota 换算。
    seed_option(&db, "payment_setting.compliance_confirmed", "true").await;
    seed_option(&db, "payment_setting.compliance_terms_version", "v1").await;
    let response = put(
        "/api/option/",
        Some(r#"{"key":"QuotaForInviter_display","value":"5"}"#),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true), "{body}");
    assert_eq!(
        option_row(&db, "QuotaForInviter").await.as_deref(),
        Some("2500000"),
        "5 USD * 500000"
    );

    // OAuth 启用守卫：缺 Client Id。
    let response = put(
        "/api/option/",
        Some(r#"{"key":"GitHubOAuthEnabled","value":true}"#),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["message"], json!(MSG_GITHUB_NEEDS_CLIENT_ID), "{body}");
    // 填好 Client Id 后放行（bool 值串化为 "true"）。
    seed_option(&db, "GitHubClientId", "Iv1.example").await;
    let response = put(
        "/api/option/",
        Some(r#"{"key":"GitHubOAuthEnabled","value":true}"#),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true), "{body}");
    assert_eq!(
        option_row(&db, "GitHubOAuthEnabled").await.as_deref(),
        Some("true")
    );

    // theme.frontend 只允许 default。
    let response = put(
        "/api/option/",
        Some(r#"{"key":"theme.frontend","value":"classic"}"#),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["message"], json!(MSG_THEME_REMOVED), "{body}");

    // GroupRatio 负倍率。
    let response = put(
        "/api/option/",
        Some(r#"{"key":"GroupRatio","value":"{\"vip\":-1}"}"#),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(
        body["message"],
        json!("group ratio must be not less than 0: vip"),
        "{body}"
    );

    // EmailFormatRegex 逐行校验。
    let response = put(
        "/api/option/",
        Some(r#"{"key":"EmailFormatRegex","value":"^a+$\n([bad"}"#),
    )
    .await;
    let body = body_json(response).await;
    assert!(
        body["message"]
            .as_str()
            .unwrap_or("")
            .starts_with("邮箱格式限制正则第 2 行无效"),
        "{body}"
    );

    // AutomaticDisableStatusCodes 非法段。
    let response = put(
        "/api/option/",
        Some(r#"{"key":"AutomaticDisableStatusCodes","value":"401,abc"}"#),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(
        body["message"],
        json!("invalid http status code rules: abc"),
        "{body}"
    );

    // MaxTokenAutoGroups 必须为正整数。
    let response = put(
        "/api/option/",
        Some(r#"{"key":"MaxTokenAutoGroups","value":"0"}"#),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(
        body["message"],
        json!("MaxTokenAutoGroups must be a positive integer"),
        "{body}"
    );

    // ResponseCacheTtlSeconds 非负。
    let response = put(
        "/api/option/",
        Some(r#"{"key":"ResponseCacheTtlSeconds","value":"-1"}"#),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(
        body["message"],
        json!("ResponseCacheTtlSeconds must be a non-negative integer"),
        "{body}"
    );

    // console_setting.faq 校验（缺答案字段）。
    let response = put(
        "/api/option/",
        Some(r#"{"key":"console_setting.faq","value":"[{\"question\":\"q\"}]"}"#),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["message"], json!("第1个FAQ缺少答案字段"), "{body}");

    // 成功路径：写库 + 强制 reload（audit #47）——Notice 通过公共 GET 立即可见。
    let response = put(
        "/api/option/",
        Some(r#"{"key":"Notice","value":"reload-visible"}"#),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true), "{body}");
    assert_eq!(body["message"], json!(""), "{body}");
    assert!(body.get("data").is_none(), "{body}");
    assert_eq!(
        option_row(&db, "Notice").await.as_deref(),
        Some("reload-visible")
    );
    // 公共 GET 读快照：写后 reload 使其立刻反映新值。
    let notice_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/notice")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(notice_response.status(), StatusCode::OK);
    let notice_body = body_json(notice_response).await;
    assert_eq!(
        notice_body["data"],
        json!("reload-visible"),
        "{notice_body}"
    );

    // 手动审计：option.update 只记键名。
    let rows = audit_rows(&db).await;
    let update_rows: Vec<&AuditRow> = rows.iter().filter(|row| row.method.is_empty()).collect();
    assert!(!update_rows.is_empty(), "option.update 审计缺失: {rows:?}");
    // option.update 是手动管理审计（无 audit_info），content 为英文模板。
    // 仅校验类型与其余兜底审计不相混。
    let response = put(
        "/api/option/",
        Some(r#"{"key":"StopOnSensitiveEnabled","value":"false"}"#),
    )
    .await;
    assert_eq!(body_json(response).await["success"], json!(true));
}

#[tokio::test]
async fn sqlite_option_put_contract() {
    run_put_option_contract(sqlite_fixture()).await;
}

#[tokio::test]
async fn postgres_option_put_contract() {
    let Some(db) = postgres_fixture("option_put").await else {
        return;
    };
    run_put_option_contract(db.clone()).await;
    drop_schema(&db).await;
}

// ---------------------------------------------------------------------------
// 契约组 4：affinity / smtp / rest_model_ratio
// ---------------------------------------------------------------------------

async fn run_subresource_contract(db: Database) {
    create_schema(&db).await;
    seed_user(&db, 3, "fixture-root", 100, Some(PAT_ROOT)).await;
    let app = state(&db);
    let root = format!("Bearer {PAT_ROOT}");

    // affinity stats：默认配置（两条内置规则）+ 空缓存。
    let response = send(
        &app,
        Method::GET,
        "/api/option/channel_affinity_cache",
        Some(root.as_str()),
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true));
    let data = &body["data"];
    assert_eq!(data["enabled"], json!(true), "{data}");
    assert_eq!(data["total"], json!(0), "{data}");
    assert_eq!(data["unknown"], json!(0), "{data}");
    assert_eq!(data["cache_capacity"], json!(100000), "{data}");
    assert_eq!(data["cache_algo"], json!("lru"), "{data}");
    let by_rule = &data["by_rule_name"];
    assert_eq!(by_rule["codex cli trace"], json!(0), "{data}");
    assert_eq!(by_rule["claude cli trace"], json!(0), "{data}");

    // DELETE：缺参 → 400；未知规则 → 400；all=true → deleted 0。
    let response = send(
        &app,
        Method::DELETE,
        "/api/option/channel_affinity_cache",
        Some(root.as_str()),
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(response).await["message"],
        json!(MSG_AFFINITY_RULE_REQUIRED)
    );
    let response = send(
        &app,
        Method::DELETE,
        "/api/option/channel_affinity_cache?rule_name=nope",
        Some(root.as_str()),
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(response).await["message"],
        json!(MSG_AFFINITY_UNKNOWN_RULE)
    );
    let response = send(
        &app,
        Method::DELETE,
        "/api/option/channel_affinity_cache?rule_name=codex%20cli%20trace",
        Some(root.as_str()),
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["data"]["deleted"], json!(0));
    let response = send(
        &app,
        Method::DELETE,
        "/api/option/channel_affinity_cache?all=true",
        Some(root.as_str()),
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["data"]["deleted"], json!(0));
    // DELETE 的兜底审计（含 400 分支）。
    let delete_audits: Vec<&AuditRow> = audit_rows(&db)
        .await
        .into_iter()
        .filter(|row| row.action == "option.clear_affinity_cache")
        .collect();
    assert_eq!(delete_audits.len(), 4, "{delete_audits:?}");
    assert!(!delete_audits[0].success, "400 分支 success=false");
    assert!(delete_audits[2].success, "200 分支 success=true");

    // smtp_pool_status：空池。
    let response = send(
        &app,
        Method::GET,
        "/api/option/smtp_pool_status",
        Some(root.as_str()),
        None,
        None,
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["data"]["senders"], json!([]), "{body}");
    assert_eq!(body["data"]["sentToday"], json!(0), "{body}");
    assert_eq!(body["data"]["remainingToday"], json!(0), "{body}");

    // smtp_pool_status：配置池按选项回显，用量为零。
    seed_option(
        &db,
        "SMTPAccountPool",
        r#"[{"server":"smtp.example.com","port":465,"account":"a@x.com","dailyLimit":100,"priority":1}]"#,
    )
    .await;
    let response = send(
        &app,
        Method::GET,
        "/api/option/smtp_pool_status",
        Some(root.as_str()),
        None,
        None,
    )
    .await;
    let body = body_json(response).await;
    let senders = body["data"]["senders"].as_array().expect("senders");
    assert_eq!(senders.len(), 1, "{body}");
    assert_eq!(senders[0]["account"], json!("a@x.com"), "{body}");
    assert_eq!(senders[0]["usedToday"], json!(0), "{body}");
    assert_eq!(senders[0]["remainingToday"], json!(100), "{body}");
    assert_eq!(body["data"]["remainingToday"], json!(100), "{body}");

    // rest_model_ratio：写默认表 + 兜底审计。
    let response = send(
        &app,
        Method::POST,
        "/api/option/rest_model_ratio",
        Some(root.as_str()),
        Some(""),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true), "{body}");
    assert_eq!(body["message"], json!(MSG_RESET_RATIO_SUCCESS), "{body}");
    let stored = option_row(&db, "ModelRatio").await.expect("ModelRatio row");
    let parsed: Value = serde_json::from_str(&stored).expect("ModelRatio JSON");
    assert_eq!(parsed["gpt-4-gizmo-*"], json!(15.0), "{stored}");
    let reset_audits: Vec<&AuditRow> = audit_rows(&db)
        .await
        .into_iter()
        .filter(|row| row.action == "option.reset_ratio")
        .collect();
    assert!(!reset_audits.is_empty());
    assert!(reset_audits.last().expect("audit").success);
}

#[tokio::test]
async fn sqlite_option_subresource_contract() {
    run_subresource_contract(sqlite_fixture()).await;
}

#[tokio::test]
async fn postgres_option_subresource_contract() {
    let Some(db) = postgres_fixture("option_sub").await else {
        return;
    };
    run_subresource_contract(db.clone()).await;
    drop_schema(&db).await;
}

// ---------------------------------------------------------------------------
// 契约组 5：payment_compliance
// ---------------------------------------------------------------------------

async fn run_compliance_contract(db: Database) {
    create_schema(&db).await;
    seed_user(&db, 3, "fixture-root", 100, Some(PAT_ROOT)).await;
    seed_user(&db, 4, "fixture-pat", 10, Some(PAT_ADMIN_ALLOWED)).await;
    seed_policy(&db, 4, "").await;
    let app = state(&db);

    // PAT 一律 403。
    let response = send(
        &app,
        Method::POST,
        "/api/option/payment_compliance",
        Some(&format!("Bearer {PAT_ADMIN_ALLOWED}")),
        Some(r#"{"confirmed":true}"#),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(response).await["message"],
        json!(MSG_SESSION_ONLY)
    );

    let root = format!("Bearer {PAT_ROOT}");
    // 未确认 → 拒绝。
    let response = send(
        &app,
        Method::POST,
        "/api/option/payment_compliance",
        Some(root.as_str()),
        Some(r#"{"confirmed":false}"#),
        None,
    )
    .await;
    assert_eq!(
        body_json(response).await["message"],
        json!(MSG_CONFIRM_REQUIRED)
    );
    // 确认 → 五行落库 + data 携带确认信息。
    let response = send(
        &app,
        Method::POST,
        "/api/option/payment_compliance",
        Some(root.as_str()),
        Some(r#"{"confirmed":true}"#),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true), "{body}");
    assert_eq!(body["data"]["confirmed"], json!(true), "{body}");
    assert_eq!(body["data"]["terms_version"], json!("v1"), "{body}");
    assert_eq!(body["data"]["confirmed_by"], json!(3), "{body}");
    for key in [
        "payment_setting.compliance_confirmed",
        "payment_setting.compliance_terms_version",
        "payment_setting.compliance_confirmed_at",
        "payment_setting.compliance_confirmed_by",
        "payment_setting.compliance_confirmed_ip",
    ] {
        assert!(option_row(&db, key).await.is_some(), "{key} missing");
    }
    assert_eq!(
        option_row(&db, "payment_setting.compliance_terms_version")
            .await
            .as_deref(),
        Some("v1")
    );
    let audits: Vec<&AuditRow> = audit_rows(&db)
        .await
        .into_iter()
        .filter(|row| row.action == "option.payment_compliance")
        .collect();
    assert!(!audits.is_empty(), "compliance 审计缺失");
    assert!(audits.last().expect("audit").success);
}

#[tokio::test]
async fn sqlite_option_compliance_contract() {
    run_compliance_contract(sqlite_fixture()).await;
}

#[tokio::test]
async fn postgres_option_compliance_contract() {
    let Some(db) = postgres_fixture("option_compliance").await else {
        return;
    };
    run_compliance_contract(db.clone()).await;
    drop_schema(&db).await;
}

// ---------------------------------------------------------------------------
// 契约组 6：waffo-pancake 五端点
// ---------------------------------------------------------------------------

async fn run_waffo_contract(db: Database) {
    create_schema(&db).await;
    seed_user(&db, 3, "fixture-root", 100, Some(PAT_ROOT)).await;
    let app = state(&db);
    let root = format!("Bearer {PAT_ROOT}");
    let transport = |canned: Vec<Canned>| Arc::new(FakePancakeTransport::new(canned));

    // catalog：无持久化凭据且无查询参数 → 凭证未配置。
    let response = send(
        &app,
        Method::GET,
        "/api/option/waffo-pancake/catalog",
        Some(root.as_str()),
        None,
        None,
    )
    .await;
    assert_eq!(
        body_json(response).await["data"],
        json!(MSG_PANCAKE_CREDITS_MISSING)
    );

    // catalog：注入传输成功。
    let response = send(
        &app,
        Method::GET,
        "/api/option/waffo-pancake/catalog?merchant_id=MER_1&private_key=k",
        Some(root.as_str()),
        None,
        Some(transport(vec![Canned::Catalog(Ok(catalog_fixture()))])),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["message"], json!("success"), "{body}");
    assert_eq!(body["data"]["stores"][0]["id"], json!("STO_1"), "{body}");
    assert_eq!(
        body["data"]["stores"][0]["onetimeProducts"][0]["id"],
        json!("PROD_1"),
        "{body}"
    );

    // catalog：上游失败 → 拉取目录失败。
    let response = send(
        &app,
        Method::GET,
        "/api/option/waffo-pancake/catalog?merchant_id=MER_1&private_key=k",
        Some(root.as_str()),
        None,
        Some(transport(vec![Canned::Catalog(Err(PancakeError(
            "upstream".to_owned(),
        )))])),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["message"], json!("error"), "{body}");
    assert_eq!(body["data"], json!("拉取目录失败"), "{body}");

    // pair：Complete / OrphanStore / Failed。
    let response = send(
        &app,
        Method::POST,
        "/api/option/waffo-pancake/pair",
        Some(root.as_str()),
        Some(r#"{"merchant_id":"MER_1","private_key":"k","return_url":"https://r"}"#),
        Some(transport(vec![Canned::Pair(PairOutcome::Complete(
            newapi_server::pancake::WaffoPancakePairResult {
                store_id: "STO_9".to_owned(),
                store_name: DEFAULT_STORE_NAME.to_owned(),
                product_id: "PROD_9".to_owned(),
                product_name: DEFAULT_PRODUCT_NAME.to_owned(),
            },
        ))])),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["message"], json!("success"), "{body}");
    assert_eq!(body["data"]["store_id"], json!("STO_9"), "{body}");
    assert_eq!(
        body["data"]["product_name"],
        json!(DEFAULT_PRODUCT_NAME),
        "{body}"
    );

    let response = send(
        &app,
        Method::POST,
        "/api/option/waffo-pancake/pair",
        Some(root.as_str()),
        Some(r#"{"merchant_id":"MER_1","private_key":"k"}"#),
        Some(transport(vec![Canned::Pair(PairOutcome::OrphanStore {
            store_id: "STO_8".to_owned(),
            store_name: DEFAULT_STORE_NAME.to_owned(),
            error: "product failed".to_owned(),
        })])),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["message"], json!("error"), "{body}");
    assert_eq!(body["data"]["orphan_store"], json!(true), "{body}");
    assert_eq!(body["data"]["store_id"], json!("STO_8"), "{body}");

    // save：必填校验。
    let response = send(
        &app,
        Method::POST,
        "/api/option/waffo-pancake/save",
        Some(root.as_str()),
        Some(r#"{"merchant_id":"MER_1"}"#),
        None,
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["data"], json!(MSG_SAVE_FAILED), "{body}");

    // save：空私钥保留现有值；成功后回显写入值。
    seed_option(&db, "WaffoPancakePrivateKey", "old-key").await;
    let response = send(
        &app,
        Method::POST,
        "/api/option/waffo-pancake/save",
        Some(root.as_str()),
        Some(r#"{"merchant_id":"MER_2","private_key":"","return_url":"https://r","store_id":"STO_2","product_id":"PROD_2"}"#),
        None,
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["message"], json!("success"), "{body}");
    assert_eq!(body["data"]["store_id"], json!("STO_2"), "{body}");
    assert_eq!(body["data"]["product_id"], json!("PROD_2"), "{body}");
    assert_eq!(
        option_row(&db, "WaffoPancakePrivateKey").await.as_deref(),
        Some("old-key"),
        "空私钥保留现有值"
    );
    assert_eq!(
        option_row(&db, "WaffoPancakeMerchantID").await.as_deref(),
        Some("MER_2")
    );
    assert_eq!(
        option_row(&db, "WaffoPancakeStoreID").await.as_deref(),
        Some("STO_2")
    );

    // subscription-product：name/amount 校验。
    for (payload, expected) in [
        (r#"{"amount":"5"}"#, "套餐名称不能为空"),
        (r#"{"name":"plan"}"#, "套餐价格不能为空"),
    ] {
        let response = send(
            &app,
            Method::POST,
            "/api/option/waffo-pancake/subscription-product",
            Some(root.as_str()),
            Some(payload),
            None,
        )
        .await;
        assert_eq!(
            body_json(response).await["data"],
            json!(expected),
            "{payload}"
        );
    }

    // subscription-product：未完成网关绑定（无 StoreID）。
    let response = send(
        &app,
        Method::POST,
        "/api/option/waffo-pancake/subscription-product",
        Some(root.as_str()),
        Some(r#"{"name":"plan","amount":"5"}"#),
        Some(transport(vec![])),
    )
    .await;
    assert_eq!(
        body_json(response).await["data"],
        json!(MSG_PANCAKE_NOT_BOUND)
    );

    // subscription-product：凭据齐备后铸品成功（StoreID 来自 save）。
    let response = send(
        &app,
        Method::POST,
        "/api/option/waffo-pancake/subscription-product",
        Some(root.as_str()),
        Some(r#"{"name":"plan","amount":"5"}"#),
        Some(transport(vec![Canned::Pair(PairOutcome::Complete(
            newapi_server::pancake::WaffoPancakePairResult {
                product_id: "PROD_7".to_owned(),
                ..Default::default()
            },
        ))])),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["message"], json!("success"), "{body}");
    assert_eq!(body["data"]["product_id"], json!("PROD_7"), "{body}");
    assert_eq!(body["data"]["store_id"], json!("STO_2"), "{body}");

    // subscription-product-options：按 StoreID 过滤目录。
    let response = send(
        &app,
        Method::GET,
        "/api/option/waffo-pancake/subscription-product-options",
        Some(root.as_str()),
        None,
        Some(transport(vec![Canned::Catalog(Ok(catalog_fixture()))])),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["message"], json!("success"), "{body}");
    assert_eq!(body["data"]["store_id"], json!("STO_2"), "{body}");
    // STO_2 不在 fixture 目录里 → 空数组。
    assert_eq!(body["data"]["products"], json!([]), "{body}");

    let response = send(
        &app,
        Method::GET,
        "/api/option/waffo-pancake/subscription-product-options",
        Some(root.as_str()),
        None,
        Some(transport(vec![Canned::Catalog(Ok(WaffoPancakeCatalog {
            stores: vec![WaffoPancakeCatalogStore {
                id: "STO_2".to_owned(),
                onetime_products: vec![WaffoPancakeCatalogProduct {
                    id: "PROD_5".to_owned(),
                    name: "p".to_owned(),
                    status: "active".to_owned(),
                }],
                ..Default::default()
            }],
        }))])),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["data"]["products"][0]["id"], json!("PROD_5"), "{body}");

    // waffo 写路径的兜底审计：save 落 generic。
    let generic: Vec<&AuditRow> = audit_rows(&db)
        .await
        .into_iter()
        .filter(|row| row.action == "generic")
        .collect();
    assert!(!generic.is_empty(), "waffo save 审计缺失");
    assert_eq!(generic[0].route, "/api/option/waffo-pancake/save");
}

#[tokio::test]
async fn sqlite_option_waffo_contract() {
    run_waffo_contract(sqlite_fixture()).await;
}

#[tokio::test]
async fn postgres_option_waffo_contract() {
    let Some(db) = postgres_fixture("option_waffo").await else {
        return;
    };
    run_waffo_contract(db.clone()).await;
    drop_schema(&db).await;
}
