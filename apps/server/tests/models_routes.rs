//! `/api/models*` 管理端与 `GET /api/models` 的 HTTP 契约
//! （Go `handle_model.go` / `ops/manage_model_metadata.go` /
//! `handle_model_sync.go` / `handle_missing_models.go`）。
//!
//! 仅在远端 CI 运行；每个场景用隔离的合成 fixture（内存 SQLite 或独立
//! PostgreSQL schema），不启动服务、不发起真实上游请求（sync/preview 经
//! `models_http::sync_upstream_with` / `sync_upstream_preview_with` 注入
//! 假 fetcher）。PostgreSQL 变体在 `TEST_POSTGRES_DSN` 缺失时跳过。
//!
//! 断言对齐 Go：业务结果一律 HTTP 200 + `{"success":...}` 信封，401/403
//! 只来自鉴权链（`modelsRoute` 组只有 `AdminAuth()`）。

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::Request,
    http::{Method, StatusCode, header},
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
    AppState, RateLimiter,
    auth::{admin_auth, user_auth},
    limit::RateLimitSettings,
    models_http,
};
use newapi_storage::Database;
use serde_json::{Value, json};
use sqlx::{
    ConnectOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use tower::ServiceExt;

static NEXT: AtomicU64 = AtomicU64::new(0);

const SECRET: &str = "models-routes-fixture-secret";

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

const MODELS_SQLITE: &str = r#"CREATE TABLE models (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    model_name VARCHAR(128) NOT NULL,
    description TEXT,
    icon VARCHAR(128),
    tags VARCHAR(255),
    vendor_id INTEGER,
    endpoints TEXT,
    status INTEGER DEFAULT 1,
    sync_official INTEGER DEFAULT 1,
    created_time BIGINT,
    updated_time BIGINT,
    deleted_at TIMESTAMP,
    name_rule INTEGER DEFAULT 0
)"#;

const MODELS_POSTGRES: &str = r#"CREATE TABLE models (
    id BIGSERIAL PRIMARY KEY,
    model_name VARCHAR(128) NOT NULL,
    description TEXT,
    icon VARCHAR(128),
    tags VARCHAR(255),
    vendor_id BIGINT,
    endpoints TEXT,
    status BIGINT DEFAULT 1,
    sync_official BIGINT DEFAULT 1,
    created_time BIGINT,
    updated_time BIGINT,
    deleted_at TIMESTAMPTZ,
    name_rule BIGINT DEFAULT 0
)"#;

const VENDORS_SQLITE: &str = r#"CREATE TABLE vendors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(128) NOT NULL,
    description TEXT,
    icon VARCHAR(128),
    status INTEGER DEFAULT 1,
    created_time BIGINT,
    updated_time BIGINT,
    deleted_at TIMESTAMP
)"#;

const VENDORS_POSTGRES: &str = r#"CREATE TABLE vendors (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    description TEXT,
    icon VARCHAR(128),
    status BIGINT DEFAULT 1,
    created_time BIGINT,
    updated_time BIGINT,
    deleted_at TIMESTAMPTZ
)"#;

const CHANNELS_SQLITE: &str = r#"CREATE TABLE channels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    "type" INTEGER NOT NULL DEFAULT 0,
    status INTEGER NOT NULL DEFAULT 1
)"#;

const CHANNELS_POSTGRES: &str = r#"CREATE TABLE channels (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    "type" BIGINT NOT NULL DEFAULT 0,
    status BIGINT NOT NULL DEFAULT 1
)"#;

const ABILITIES_SQLITE: &str = r#"CREATE TABLE abilities (
    "group" VARCHAR(64) NOT NULL,
    model VARCHAR(255) NOT NULL,
    channel_id INTEGER NOT NULL,
    enabled BOOLEAN NOT NULL,
    tag TEXT,
    PRIMARY KEY ("group", model, channel_id)
)"#;

const ABILITIES_POSTGRES: &str = r#"CREATE TABLE abilities (
    "group" VARCHAR(64) NOT NULL,
    model VARCHAR(255) NOT NULL,
    channel_id BIGINT NOT NULL,
    enabled BOOLEAN NOT NULL,
    tag TEXT,
    PRIMARY KEY ("group", model, channel_id)
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

/// Go `modelsRoute`（组级 `AdminAuth()`）与 `GET /api/models`
/// （`UserAuth`）的组合路由，与 `http.rs` 的注册一致。
fn router(state: AppState) -> Router {
    let dashboard_state = state.clone();
    let models_state = state.clone();
    Router::new()
        .route("/api/models", get(models_http::dashboard_models))
        .route_layer(middleware::from_fn_with_state(dashboard_state, user_auth))
        .route(
            "/api/models/",
            post(models_http::create_model).put(models_http::update_model),
        )
        .route("/api/models/meta", get(models_http::list_models))
        .route("/api/models/search", get(models_http::search_models))
        .route("/api/models/missing", get(models_http::missing_models))
        .route(
            "/api/models/sync_upstream",
            post(models_http::sync_upstream),
        )
        .route(
            "/api/models/sync_upstream/preview",
            get(models_http::sync_upstream_preview),
        )
        .route(
            "/api/models/{id}",
            get(models_http::get_model).delete(models_http::delete_model),
        )
        .route_layer(middleware::from_fn_with_state(models_state, admin_auth))
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
        sqlx::query(statement).execute(pool).await.expect("fixture");
    });
}

async fn create_schema(db: &Database) {
    match db {
        Database::Sqlite(_) => {
            for statement in [
                USERS_SQLITE,
                SESSIONS,
                MODELS_SQLITE,
                VENDORS_SQLITE,
                CHANNELS_SQLITE,
                ABILITIES_SQLITE,
            ] {
                exec(db, statement).await;
            }
        }
        Database::Postgres(_) => {
            for statement in [
                USERS_POSTGRES,
                SESSIONS,
                MODELS_POSTGRES,
                VENDORS_POSTGRES,
                CHANNELS_POSTGRES,
                ABILITIES_POSTGRES,
            ] {
                exec(db, statement).await;
            }
        }
    }
}

async fn reset(db: &Database) {
    exec(db, "DELETE FROM abilities").await;
    exec(db, "DELETE FROM channels").await;
    exec(db, "DELETE FROM vendors").await;
    exec(db, "DELETE FROM models").await;
    exec(db, "DELETE FROM user_sessions").await;
    exec(db, "DELETE FROM users").await;
}

async fn seed_user(db: &Database, id: i64, username: &str, role: i64) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO users
                (id,username,display_name,role,status,"group",auth_version)
                VALUES ($1,$2,$3,$4,1,'default',1)"#,
        )
        .bind(id)
        .bind(username)
        .bind(username)
        .bind(role)
        .execute(pool)
        .await
        .expect("seed user");
    });
}

async fn seed_session(db: &Database, sid: &str, user_id: i64, at: i64) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO user_sessions
                (sid,user_id,version,user_auth_version,status,refresh_hash,
                 login_method,created_at,last_active_at,expires_at)
                VALUES ($1,$2,1,1,'active','fixture-hash','password',$3,$3,$4)"#,
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

fn jwt(user_id: i64, sid: &str, at: i64) -> String {
    AuthKeys::new(SECRET)
        .issue_access(
            &AuthIdentity {
                user_id,
                sid: sid.to_owned(),
                user_auth_version: 1,
                session_version: 1,
            },
            at,
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

async fn body_json(response: Response) -> Value {
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body");
    serde_json::from_slice(&bytes).expect("response JSON")
}

fn translated(key: &str) -> String {
    newapi_i18n::translate("en", key, std::iter::empty::<(&str, &str)>())
}

/// Go `common.H{"success":true,...}`：HTTP 200 + 信封。
async fn assert_success(response: Response) -> Value {
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true), "{}", body);
    body
}

async fn assert_business_error(response: Response, key: &str) -> Value {
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false), "{}", body);
    assert_eq!(body["message"], json!(translated(key)), "{}", body);
    body
}

async fn seed_model(db: &Database, id: i64, name: &str, name_rule: i64, sync_official: i64) {
    backend!(db, pool, {
        sqlx::query(
            "INSERT INTO models (id, model_name, name_rule, sync_official, updated_time) \
             VALUES ($1,$2,$3,$4,0)",
        )
        .bind(id)
        .bind(name)
        .bind(name_rule)
        .bind(sync_official)
        .execute(pool)
        .await
        .expect("seed model");
    });
}

async fn model_updated_time(db: &Database, id: i64) -> i64 {
    backend!(db, pool, {
        sqlx::query_scalar::<_, i64>(
            "SELECT CAST(COALESCE(updated_time, 0) AS BIGINT) FROM models WHERE id = $1",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("updated_time")
    })
}

/// sync/preview 共用的假上游：按 URL 返回响应体；缺失的 URL 报 Transport。
struct FakeUpstream {
    responses: BTreeMap<String, Vec<u8>>,
}

impl FakeUpstream {
    fn with_envelope(models: Value, vendors: Value) -> Self {
        Self::with_envelope_locale(models, vendors, "")
    }

    /// 按请求 locale 注册响应 URL（`upstream_urls(locale)` 与
    /// handler 内的取 URL 逻辑同源）。
    fn with_envelope_locale(models: Value, vendors: Value, locale: &str) -> Self {
        let (models_url, vendors_url) = models_http::upstream_urls(locale);
        Self {
            responses: BTreeMap::from([
                (models_url, serde_json::to_vec(&models).unwrap()),
                (vendors_url, serde_json::to_vec(&vendors).unwrap()),
            ]),
        }
    }
}

impl newapi_server::models_http::UpstreamFetch for FakeUpstream {
    fn fetch<'a>(&'a self, url: &'a str) -> newapi_server::models_http::UpstreamFetchFuture<'a> {
        Box::pin(async move {
            match self.responses.get(url) {
                Some(body) => Ok(body.clone()),
                None => Err(newapi_server::models_http::UpstreamFetchError::Transport),
            }
        })
    }
}

#[tokio::test]
async fn sqlite_models_routes_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .idle_timeout(None)
        .max_lifetime(None)
        .connect_with(SqliteConnectOptions::new().in_memory(true))
        .await
        .unwrap();
    contract(&Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn postgres_models_routes_contract() {
    let Ok(dsn) = std::env::var("TEST_POSTGRES_DSN") else {
        return;
    };
    let options: PgConnectOptions = dsn.parse().unwrap();
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone().disable_statement_logging())
        .await
        .unwrap();
    let schema = format!(
        "models_routes_{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"
    )))
    .execute(&admin)
    .await
    .unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA \"{schema}\"")))
        .execute(&admin)
        .await
        .unwrap();
    let search_path = schema.clone();
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .idle_timeout(None)
        .max_lifetime(None)
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
        .connect_with(options.disable_statement_logging())
        .await
        .unwrap();
    contract(&Database::Postgres(pool.clone())).await;
    pool.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA \"{schema}\" CASCADE"
    )))
    .execute(&admin)
    .await
    .unwrap();
    admin.close().await;
}

async fn contract(db: &Database) {
    create_schema(db).await;
    reset(db).await;
    seed_user(db, 1, "admin-one", 10).await;
    seed_user(db, 3, "common-one", 1).await;
    let at = now();
    seed_session(db, "sid-admin", 1, at).await;
    seed_session(db, "sid-common", 3, at).await;
    let app = state(db);
    let admin = format!("Bearer {}", jwt(1, "sid-admin", at));
    let common = format!("Bearer {}", jwt(3, "sid-common", at));

    // ---- 鉴权链：AdminAuth 的 401/403 ------------------------------
    let response = send(&app, Method::GET, "/api/models/meta", None, None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = send(&app, Method::GET, "/api/models/meta", Some(&common), None).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    // GET /api/models 是 UserAuth：未认证 401。
    let response = send(&app, Method::GET, "/api/models", None, None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // ---- GET /api/models：静态目录，成功体无 message 键 -------------
    let body =
        assert_success(send(&app, Method::GET, "/api/models", Some(&admin), None).await).await;
    assert!(body.get("message").is_none(), "{}", body);
    let data = &body["data"];
    assert_eq!(data["1"][0], json!("gpt-3.5-turbo"));
    assert_eq!(data["37"], json!(null)); // Dify：nil 切片
    assert_eq!(data["20"], json!([])); // OpenRouter：空切片
    assert!(data.as_object().unwrap().contains_key("24"));

    // ---- 列表：空库信封 --------------------------------------------
    let body =
        assert_success(send(&app, Method::GET, "/api/models/meta", Some(&admin), None).await).await;
    assert_eq!(body["message"], json!(""));
    assert_eq!(body["data"]["items"], json!([]));
    assert_eq!(body["data"]["total"], json!(0));
    assert_eq!(body["data"]["page"], json!(1));
    assert_eq!(body["data"]["page_size"], json!(10));
    assert_eq!(body["data"]["vendor_counts"], json!({}));

    // ---- 种入数据 + abilities，验证富化与过滤 ----------------------
    seed_model(db, 2, "gpt-alpha", 0, 1).await;
    seed_model(db, 3, "gpt-beta", 1, 0).await;
    exec(db, "INSERT INTO vendors (id, name) VALUES (7, 'OpenAI')").await;
    exec(
        db,
        "UPDATE models SET vendor_id = 7, description = 'alpha desc', tags = 't-a' WHERE id = 2",
    )
    .await;
    exec(
        db,
        "INSERT INTO channels (id, name, \"type\") VALUES (10, 'ch-a', 1)",
    )
    .await;
    exec(db, "INSERT INTO abilities (\"group\", model, channel_id, enabled) VALUES ('default', 'gpt-alpha', 10, TRUE)").await;

    let body =
        assert_success(send(&app, Method::GET, "/api/models/meta", Some(&admin), None).await).await;
    assert_eq!(body["data"]["total"], json!(2));
    let items = body["data"]["items"].as_array().unwrap();
    // id DESC：gpt-beta 在前。
    assert_eq!(items[0]["model_name"], json!("gpt-beta"));
    // 规则模型：无定价缓存 → 无 bound_channels / endpoints。
    assert!(items[0].get("bound_channels").is_none());
    assert!(items[0].get("endpoints").is_none());
    // 精确模型：endpoints 空缓存语义为 "[]"，bound_channels 来自 abilities。
    assert_eq!(items[1]["model_name"], json!("gpt-alpha"));
    assert_eq!(items[1]["endpoints"], json!("[]"));
    assert_eq!(
        items[1]["bound_channels"],
        json!([{"name": "ch-a", "type": 1}])
    );
    assert_eq!(items[1]["vendor_id"], json!(7));
    assert_eq!(body["data"]["vendor_counts"], json!({"0": 1, "7": 1}));

    // status / sync_official 过滤与分页。
    let body = assert_success(
        send(
            &app,
            Method::GET,
            "/api/models/meta?status=1&sync_official=no",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["total"], json!(1));
    assert_eq!(body["data"]["items"][0]["model_name"], json!("gpt-beta"));
    let body = assert_success(
        send(
            &app,
            Method::GET,
            "/api/models/meta?p=2&page_size=1",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["page"], json!(2));
    assert_eq!(body["data"]["page_size"], json!(1));
    assert_eq!(body["data"]["total"], json!(2));
    assert_eq!(body["data"]["items"].as_array().unwrap().len(), 1);

    // ---- 搜索：keyword 与 vendor 文本过滤 --------------------------
    let body = assert_success(
        send(
            &app,
            Method::GET,
            "/api/models/search?keyword=alpha",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["total"], json!(1));
    assert_eq!(body["data"]["items"][0]["model_name"], json!("gpt-alpha"));
    let body = assert_success(
        send(
            &app,
            Method::GET,
            "/api/models/search?keyword=t-a",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["total"], json!(1));
    let body = assert_success(
        send(
            &app,
            Method::GET,
            "/api/models/search?vendor=Open",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["total"], json!(1));

    // ---- 详情：富化 / 非法 id / 缺失 -------------------------------
    let body =
        assert_success(send(&app, Method::GET, "/api/models/2", Some(&admin), None).await).await;
    assert_eq!(body["data"]["model_name"], json!("gpt-alpha"));
    assert_eq!(body["data"]["endpoints"], json!("[]"));
    assert_business_error(
        send(&app, Method::GET, "/api/models/abc", Some(&admin), None).await,
        "model.id_format_error",
    )
    .await;
    assert_business_error(
        send(&app, Method::GET, "/api/models/999", Some(&admin), None).await,
        "model.not_exists",
    )
    .await;

    // ---- 创建：回显 + 零值 status 落库 + 重名校验 ------------------
    let payload = json!({
        "model_name": "m-new",
        "description": "new model",
        "status": 0,
        "sync_official": 0,
        "name_rule": 2,
    });
    let body = assert_success(
        send(
            &app,
            Method::POST,
            "/api/models/",
            Some(&admin),
            Some(&payload),
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["model_name"], json!("m-new"));
    assert_eq!(body["data"]["status"], json!(0));
    assert_eq!(body["data"]["sync_official"], json!(0));
    assert_eq!(body["data"]["name_rule"], json!(2));
    assert!(body["data"]["id"].as_i64().unwrap() > 0);
    let created_id = body["data"]["id"].as_i64().unwrap();
    let (db_status, db_sync): (i64, i64) = backend!(db, pool, {
        sqlx::query_as::<_, (i64, i64)>(
            "SELECT CAST(status AS BIGINT), CAST(sync_official AS BIGINT) \
             FROM models WHERE id = $1",
        )
        .bind(created_id)
        .fetch_one(pool)
        .await
        .expect("created row")
    });
    assert_eq!(db_status, 0);
    assert_eq!(db_sync, 0);

    assert_business_error(
        send(
            &app,
            Method::POST,
            "/api/models/",
            Some(&admin),
            Some(&json!({"description": "x"})),
        )
        .await,
        "model.name_empty",
    )
    .await;
    assert_business_error(
        send(
            &app,
            Method::POST,
            "/api/models/",
            Some(&admin),
            Some(&json!({"model_name": "gpt-alpha"})),
        )
        .await,
        "model.name_exists",
    )
    .await;
    // 绑定失败 → common.invalid_params（Go 的绑定错误折叠）。
    let response = send(
        &app,
        Method::POST,
        "/api/models/",
        Some(&admin),
        Some(&json!([])),
    )
    .await;
    assert_eq!(
        body_json(response).await["message"],
        json!(translated("common.invalid_params"))
    );

    // ---- 更新：status_only 不刷新 updated_time；全量整列覆写 --------
    let before = model_updated_time(db, 2).await;
    let body = assert_success(
        send(
            &app,
            Method::PUT,
            "/api/models/?status_only=true",
            Some(&admin),
            Some(&json!({"id": 2, "status": 0})),
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["id"], json!(2));
    assert_eq!(body["data"]["status"], json!(0));
    assert_eq!(model_updated_time(db, 2).await, before);

    let payload = json!({"id": 2, "model_name": "gpt-alpha-2", "status": 1});
    let body = assert_success(
        send(
            &app,
            Method::PUT,
            "/api/models/",
            Some(&admin),
            Some(&payload),
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["model_name"], json!("gpt-alpha-2"));
    // 整列覆写：未指定的 description/vendor_id 归零。
    assert!(body["data"].get("description").is_none());
    assert!(body["data"].get("vendor_id").is_none());
    assert!(body["data"]["updated_time"].as_i64().unwrap() >= before);
    // tags 也应被覆写清空（Go Select 全列）。
    let (tags,): (Option<String>,) = backend!(db, pool, {
        sqlx::query_as("SELECT tags FROM models WHERE id = 2")
            .fetch_one(pool)
            .await
            .expect("tags")
    });
    assert_eq!(tags.unwrap_or_default(), "");

    assert_business_error(
        send(
            &app,
            Method::PUT,
            "/api/models/",
            Some(&admin),
            Some(&json!({"status": 1})),
        )
        .await,
        "model.id_missing",
    )
    .await;
    assert_business_error(
        send(
            &app,
            Method::PUT,
            "/api/models/",
            Some(&admin),
            Some(&json!({"id": created_id, "model_name": "gpt-alpha-2"})),
        )
        .await,
        "model.name_exists",
    )
    .await;

    // ---- 缺失模型：abilities 减 models 表 --------------------------
    exec(db, "INSERT INTO abilities (\"group\", model, channel_id, enabled) VALUES ('default', 'abilities-only', 10, TRUE)").await;
    let body =
        assert_success(send(&app, Method::GET, "/api/models/missing", Some(&admin), None).await)
            .await;
    assert!(body.get("message").is_none(), "{}", body);
    // gpt-alpha 已改名 gpt-alpha-2，能力行还引用旧名 → 两处缺失按
    // enabled 顺序（alphabetical）返回。
    assert_eq!(body["data"], json!(["abilities-only", "gpt-alpha"]));

    // ---- 删除：软删除 + data:null ----------------------------------
    let response = send(&app, Method::DELETE, "/api/models/3", Some(&admin), None).await;
    let body = assert_success(response).await;
    assert_eq!(body["data"], json!(null));
    assert_business_error(
        send(&app, Method::GET, "/api/models/3", Some(&admin), None).await,
        "model.not_exists",
    )
    .await;
    assert_business_error(
        send(&app, Method::DELETE, "/api/models/3", Some(&admin), None).await,
        "model.not_exists",
    )
    .await;
    assert_business_error(
        send(&app, Method::DELETE, "/api/models/abc", Some(&admin), None).await,
        "model.id_format_error",
    )
    .await;

    // ---- sync_upstream：无缺失无覆盖 → 零结果（不请求上游）---------
    // 清掉旧名能力行并把 abilities-only 建掉，让 missing 为空。
    exec(db, "DELETE FROM abilities WHERE model = 'gpt-alpha'").await;
    seed_model(db, 5, "abilities-only", 0, 1).await;
    let fake = FakeUpstream {
        responses: BTreeMap::new(), // 任何 fetch 都是失败：证明走的是早退分支
    };
    let response = models_http::sync_upstream_with(db, &Default::default(), b"", &fake).await;
    let body = assert_success(response).await;
    assert_eq!(body["data"]["created_models"], json!(0));
    assert_eq!(body["data"]["created_vendors"], json!(0));
    assert_eq!(body["data"]["updated_models"], json!(0));
    assert_eq!(body["data"]["skipped_models"], json!([]));
    assert_eq!(body["data"]["created_list"], json!([]));
    assert_eq!(body["data"]["updated_list"], json!([]));
    assert_eq!(body["data"]["source"]["locale"], json!(""));

    // ---- sync_upstream：缺失补建 + 供应商补建 + 上游缺失跳过 --------
    exec(db, "DELETE FROM models WHERE id = 5").await;
    let upstream = json!([
        {"model_name": "abilities-only", "description": "up desc", "icon": "up-icon",
         "tags": "up-tag", "vendor_name": "UpVendor", "status": 0, "name_rule": 1},
        {"model_name": "another", "description": "another"}
    ]);
    let vendors = json!([
        {"name": "UpVendor", "description": "upstream vendor", "icon": "up-vendor-icon", "status": 2}
    ]);
    let fake = FakeUpstream::with_envelope(upstream, vendors);
    let response = models_http::sync_upstream_with(db, &Default::default(), b"", &fake).await;
    let body = assert_success(response).await;
    assert_eq!(body["data"]["created_models"], json!(1), "{}", body);
    assert_eq!(body["data"]["created_vendors"], json!(1), "{}", body);
    assert_eq!(body["data"]["created_list"], json!(["abilities-only"]));
    // 上游没有的 missing 名字跳过（another 不在 abilities）。
    assert_eq!(body["data"]["skipped_models"], json!([]));
    let (vendor_id, vendor_status): (i64, i64) = backend!(db, pool, {
        sqlx::query_as::<_, (i64, i64)>(
            "SELECT CAST(id AS BIGINT), CAST(status AS BIGINT) FROM vendors WHERE name = 'UpVendor'",
        )
        .fetch_one(pool)
        .await
        .expect("upserted vendor")
    });
    assert_eq!(vendor_status, 2);
    let (status, sync_official, name_rule, vendor): (i64, i64, i64, i64) = backend!(db, pool, {
        sqlx::query_as::<_, (i64, i64, i64, i64)>(
            "SELECT CAST(status AS BIGINT), CAST(sync_official AS BIGINT), \
             CAST(name_rule AS BIGINT), CAST(vendor_id AS BIGINT) \
             FROM models WHERE model_name = 'abilities-only'",
        )
        .fetch_one(pool)
        .await
        .expect("synced model")
    });
    // 上游 status=0 → chooseStatus(0,1)=1；sync_official 恒为 0。
    assert_eq!(status, 1);
    assert_eq!(sync_official, 0);
    assert_eq!(name_rule, 1);
    assert_eq!(vendor, vendor_id);
    assert_eq!(body["data"]["source"]["models_url"], {
        let (models_url, _) = models_http::upstream_urls("");
        json!(models_url)
    });

    // ---- sync_upstream：覆盖更新（sync_official=0 跳过）------------
    // abilities-only 刚由 sync 创建（sync_official=0）→ 覆盖跳过；
    // gpt-alpha-2 是 sync_official=1 → 覆盖生效。
    exec(
        db,
        "UPDATE models SET sync_official = 1 WHERE model_name = 'gpt-alpha-2'",
    )
    .await;
    let overwrite = json!({
        "locale": "en",
        "overwrite": [
            {"model_name": "abilities-only", "fields": ["description", "status"]},
            {"model_name": "gpt-alpha-2", "fields": ["Description", "status", "vendor", "name_rule"]},
            {"model_name": "ghost", "fields": ["description"]}
        ]
    });
    let payload = serde_json::to_vec(&overwrite).unwrap();
    let upstream = json!([
        {"model_name": "abilities-only", "description": "should-not-apply", "status": 2},
        {"model_name": "gpt-alpha-2", "description": "  patched  ", "status": 0,
         "vendor_name": "UpVendor", "name_rule": 3}
    ]);
    let vendors = json!([]);
    // 覆盖请求带 locale=en，响应 URL 必须按同一 locale 注册。
    let fake = FakeUpstream::with_envelope_locale(upstream, vendors, "en");
    let response = models_http::sync_upstream_with(db, &Default::default(), &payload, &fake).await;
    let body = assert_success(response).await;
    assert_eq!(body["data"]["created_models"], json!(0));
    // abilities-only 跳过（sync_official=0）；gpt-alpha-2 更新；ghost 不存在。
    assert_eq!(body["data"]["updated_models"], json!(1));
    assert_eq!(body["data"]["updated_list"], json!(["gpt-alpha-2"]));
    let (description, status, name_rule): (String, i64, i64) = backend!(db, pool, {
        sqlx::query_as::<_, (String, i64, i64)>(
            "SELECT description, CAST(status AS BIGINT), CAST(name_rule AS BIGINT) \
             FROM models WHERE model_name = 'gpt-alpha-2'",
        )
        .fetch_one(pool)
        .await
        .expect("overwritten model")
    });
    assert_eq!(description, "  patched  ");
    // 上游 status=0 → chooseStatus(0, local.status=1) = 1（保留原值）。
    assert_eq!(status, 1);
    assert_eq!(name_rule, 3);
    let (synced_status,): (i64,) = backend!(db, pool, {
        sqlx::query_as::<_, (i64,)>(
            "SELECT CAST(status AS BIGINT) FROM models WHERE model_name = 'abilities-only'",
        )
        .fetch_one(pool)
        .await
        .expect("skipped model")
    });
    assert_eq!(synced_status, 1); // 覆盖未生效
    assert_eq!(body["data"]["source"]["locale"], json!("en"));

    // ---- sync_upstream：上游模型拉取失败 ---------------------------
    // abilities-only 已在上一场景创建成功；删掉它让 missing 非空，
    // 否则走早退分支拿不到上游错误体。
    exec(db, "DELETE FROM models WHERE model_name = 'abilities-only'").await;
    let fake = FakeUpstream {
        responses: BTreeMap::new(),
    };
    let payload = serde_json::to_vec(&json!({"locale": "zh-CN"})).unwrap();
    let response = models_http::sync_upstream_with(db, &Default::default(), &payload, &fake).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false));
    assert_eq!(body["message"], json!(translated("model.get_failed")));
    assert_eq!(body["locale"], json!("zh-CN"));
    let (models_url, vendors_url) = models_http::upstream_urls("zh-CN");
    assert_eq!(body["source_urls"]["models_url"], json!(models_url));
    assert_eq!(body["source_urls"]["vendors_url"], json!(vendors_url));

    // ---- preview：缺失与冲突（空为 null）---------------------------
    // 当前 abilities-only 已在 models 表（sync 创建）→ missing 空；
    // gpt-alpha-2（sync_official=1）与上游同名字段 trim 后全等
    // （status 走 chooseStatus 语义）→ conflicts 空。
    let upstream = json!([
        {"model_name": "abilities-only", "description": "up desc", "icon": "up-icon",
         "tags": "up-tag", "vendor_name": "UpVendor", "name_rule": 1, "status": 0},
        {"model_name": "gpt-alpha-2", "description": "patched", "status": 0,
         "name_rule": 3, "vendor_name": "UpVendor"}
    ]);
    let vendors = json!([{"name": "UpVendor"}]);
    let fake = FakeUpstream::with_envelope(upstream, vendors);
    // fetch 失败场景删掉了 abilities-only；补回它（sync_official=0 不参与
    // 可覆盖比对），使 missing 不含它。
    seed_model(db, 6, "abilities-only", 1, 0).await;
    let response = models_http::sync_upstream_preview_with(
        db,
        &Default::default(),
        &"/api/models/sync_upstream/preview".parse().unwrap(),
        &fake,
    )
    .await;
    let body = assert_success(response).await;
    // 本地可覆盖模型与上游无差异时 conflicts 为 null（Go nil 切片）。
    assert_eq!(body["data"]["missing"], json!(null));
    assert_eq!(body["data"]["conflicts"], json!(null));
    assert_eq!(body["data"]["source"]["locale"], json!(""));

    // 制造差异：abilities-only 设为 syncable（sync_official=1），上游 vendor
    // 与 status 不同；abilities-only-2 进入 abilities 成为缺失。
    exec(
        db,
        "UPDATE models SET sync_official = 1 WHERE model_name = 'abilities-only'",
    )
    .await;
    exec(
        db,
        "INSERT INTO abilities (\"group\", model, channel_id, enabled) VALUES ('default', 'abilities-only-2', 10, TRUE)",
    )
    .await;
    let upstream = json!([
        {"model_name": "abilities-only", "description": "up desc", "icon": "up-icon",
         "tags": "up-tag", "vendor_name": "OtherVendor", "name_rule": 1, "status": 3},
        {"model_name": "abilities-only-2"}
    ]);
    let fake = FakeUpstream::with_envelope_locale(upstream, json!([]), "en");
    let response = models_http::sync_upstream_preview_with(
        db,
        &Default::default(),
        &"/api/models/sync_upstream/preview?locale=en"
            .parse()
            .unwrap(),
        &fake,
    )
    .await;
    let body = assert_success(response).await;
    assert_eq!(body["data"]["missing"], json!(["abilities-only-2"]));
    let conflicts = body["data"]["conflicts"].as_array().unwrap();
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0]["model_name"], json!("abilities-only"));
    let fields = conflicts[0]["fields"].as_array().unwrap();
    let field_names: Vec<&str> = fields
        .iter()
        .map(|field| field["field"].as_str().unwrap())
        .collect();
    // 本地：sync 创建时的 up desc/up-icon/up-tag + UpVendor + rule 1 + status 1；
    // 上游：相同文本 + OtherVendor + rule 1 + status 3 → 差异是 vendor 和 status。
    assert_eq!(field_names, vec!["vendor", "status"]);
    assert_eq!(fields[0]["local"], json!("UpVendor"));
    assert_eq!(fields[0]["upstream"], json!("OtherVendor"));
    assert_eq!(fields[1]["local"], json!(1));
    assert_eq!(fields[1]["upstream"], json!(3)); // 上游原始值，不经 chooseStatus

    // preview 上游失败：错误体带 locale + source_urls。
    let fake = FakeUpstream {
        responses: BTreeMap::new(),
    };
    let response = models_http::sync_upstream_preview_with(
        db,
        &Default::default(),
        &"/x".parse().unwrap(),
        &fake,
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false));
    assert_eq!(body["message"], json!(translated("model.get_failed")));
    assert!(body["source_urls"]["models_url"].is_string());
}
