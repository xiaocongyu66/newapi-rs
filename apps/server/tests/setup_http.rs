//! HTTP contracts for `GET /api/setup` and `POST /api/setup`.
//!
//! Run only in GitHub Actions. The SQLite fixture lives in memory; the
//! PostgreSQL fixture creates a uniquely named schema and is skipped only when
//! `TEST_POSTGRES_DSN` is absent. The production router does not register
//! these routes yet, so the tests build the shape the composition slice will
//! use: GET unwrapped, POST behind the anonymous body limit.
//!
//! The synthetic DDL is an isolated test fixture, never a production migrator.

use std::sync::atomic::{AtomicU64, Ordering};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
    middleware,
    routing::{get, post},
};
use newapi_identity::{crypto::verify_password, setup::REQUIRED_SCHEMA_COLUMNS};
use newapi_security::client_ip::ProxyPolicy;
use newapi_server::{AppState, RateLimiter, limit::RateLimitSettings, setup_http};
use newapi_storage::Database;
use serde_json::Value;
use sqlx::{
    ConnectOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::SqlitePoolOptions,
};
use tower::ServiceExt;

static NEXT: AtomicU64 = AtomicU64::new(0);

const VALID_BODY: &str = r#"{"username":"管理员","password":"secret123","confirmPassword":"secret123","SelfUseModeEnabled":true,"DemoSiteEnabled":false}"#;
const ROOT_USER_SKIP_BODY: &str = r#"{"username":"","password":"","confirmPassword":""}"#;

// Fixed test DDL; columns mirror the identity repository fixture.
const SQLITE_USERS_TABLE: &str = r#"CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE, password TEXT NOT NULL,
    display_name TEXT, role INTEGER DEFAULT 1, status INTEGER DEFAULT 1,
    email TEXT, github_id TEXT, discord_id TEXT, oidc_id TEXT,
    wechat_id TEXT, telegram_id TEXT, access_token CHAR(32) UNIQUE,
    quota INTEGER DEFAULT 0, used_quota INTEGER DEFAULT 0,
    request_count INTEGER DEFAULT 0, "group" VARCHAR(64) DEFAULT 'default',
    aff_code VARCHAR(32) UNIQUE, aff_count INTEGER DEFAULT 0,
    aff_quota INTEGER DEFAULT 0, aff_history INTEGER DEFAULT 0,
    inviter_id INTEGER, deleted_at TIMESTAMP, linux_do_id TEXT,
    setting TEXT, remark VARCHAR(255), stripe_customer VARCHAR(64),
    created_at BIGINT, last_login_at BIGINT DEFAULT 0,
    auth_version BIGINT NOT NULL DEFAULT 1
)"#;
const POSTGRES_USERS_TABLE: &str = r#"CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    username TEXT UNIQUE, password TEXT NOT NULL,
    display_name TEXT, role INTEGER DEFAULT 1, status INTEGER DEFAULT 1,
    email TEXT, github_id TEXT, discord_id TEXT, oidc_id TEXT,
    wechat_id TEXT, telegram_id TEXT, access_token CHAR(32) UNIQUE,
    quota INTEGER DEFAULT 0, used_quota INTEGER DEFAULT 0,
    request_count INTEGER DEFAULT 0, "group" VARCHAR(64) DEFAULT 'default',
    aff_code VARCHAR(32) UNIQUE, aff_count INTEGER DEFAULT 0,
    aff_quota INTEGER DEFAULT 0, aff_history INTEGER DEFAULT 0,
    inviter_id INTEGER, deleted_at TIMESTAMP, linux_do_id TEXT,
    setting TEXT, remark VARCHAR(255), stripe_customer VARCHAR(64),
    created_at BIGINT, last_login_at BIGINT DEFAULT 0,
    auth_version BIGINT NOT NULL DEFAULT 1
)"#;
const SETUPS_TABLE: &str = "CREATE TABLE setups (id BIGINT PRIMARY KEY, version VARCHAR(50) NOT NULL DEFAULT 'legacy-unknown', initialized_at BIGINT NOT NULL DEFAULT 0)";
const OPTIONS_TABLE: &str = "CREATE TABLE options (\"key\" TEXT PRIMARY KEY, value TEXT)";

const COUNT_SETUPS: &str = "SELECT count(*) FROM setups";
const COUNT_USERS: &str = "SELECT count(*) FROM users";
const SETUP_VERSION: &str = "SELECT version FROM setups WHERE id = 1";
const SETUP_INITIALIZED_AT: &str = "SELECT initialized_at FROM setups WHERE id = 1";
const SELF_USE_MODE: &str = "SELECT value FROM options WHERE \"key\" = 'SelfUseModeEnabled'";
const DEMO_SITE_MODE: &str = "SELECT value FROM options WHERE \"key\" = 'DemoSiteEnabled'";
const ROOT_ROW: &str = "SELECT count(*) FROM users WHERE role = 100 AND status = 1 AND quota = 100000000 AND auth_version = 1 AND access_token IS NULL AND deleted_at IS NULL AND \"group\" = 'default' AND display_name = 'Root User' AND username = '管理员'";
const ROOT_PASSWORD: &str = "SELECT password FROM users WHERE role = 100";
const INSERT_LEGACY_SETUP: &str = "INSERT INTO setups(id) VALUES (42)";
const INSERT_EXISTING_ROOT: &str = "INSERT INTO users(username,password,role,status,aff_code) VALUES ('root','fixture',100,1,'aff')";

fn router(state: AppState) -> Router {
    let post_only = Router::new()
        .route("/api/setup", post(setup_http::complete))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            setup_http::setup_body_limit,
        ));
    Router::new()
        .route("/api/setup", get(setup_http::inspect))
        .merge(post_only)
        .with_state(state)
}

async fn send(state: &AppState, request: Request<Body>) -> (StatusCode, Value) {
    let response = router(state.clone()).oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or_default();
    (status, body)
}

fn get_setup() -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri("/api/setup")
        .header(header::ACCEPT_LANGUAGE, "zh-CN")
        .body(Body::empty())
        .unwrap()
}

fn post_setup(body: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/api/setup")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT_LANGUAGE, "zh-CN")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

async fn exec(db: &Database, sql: &'static str) {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query::<sqlx::Sqlite>(sql)
                .execute(pool)
                .await
                .unwrap();
        }
        Database::Postgres(pool) => {
            sqlx::query::<sqlx::Postgres>(sql)
                .execute(pool)
                .await
                .unwrap();
        }
    }
}

async fn scalar_i64(db: &Database, sql: &'static str) -> i64 {
    match db {
        Database::Sqlite(pool) => sqlx::query_scalar::<_, i64>(sql)
            .fetch_one(pool)
            .await
            .unwrap(),
        Database::Postgres(pool) => sqlx::query_scalar::<_, i64>(sql)
            .fetch_one(pool)
            .await
            .unwrap(),
    }
}

async fn scalar_string(db: &Database, sql: &'static str) -> String {
    match db {
        Database::Sqlite(pool) => sqlx::query_scalar::<_, String>(sql)
            .fetch_one(pool)
            .await
            .unwrap(),
        Database::Postgres(pool) => sqlx::query_scalar::<_, String>(sql)
            .fetch_one(pool)
            .await
            .unwrap(),
    }
}

fn database_type(db: &Database) -> &'static str {
    match db {
        Database::Sqlite(_) => "sqlite",
        Database::Postgres(_) => "postgres",
    }
}

/// Creates the full column whitelist the setup gate checks. Non-core tables
/// only need the fixed column names; the core tables carry the unique
/// constraints the gate also verifies.
async fn create_schema(db: &Database) {
    match db {
        Database::Sqlite(_) => exec(db, SQLITE_USERS_TABLE).await,
        Database::Postgres(_) => exec(db, POSTGRES_USERS_TABLE).await,
    }
    exec(db, SETUPS_TABLE).await;
    exec(db, OPTIONS_TABLE).await;
    for &(table, columns) in REQUIRED_SCHEMA_COLUMNS {
        if matches!(table, "users" | "setups" | "options") {
            continue;
        }
        let definitions = columns
            .split(',')
            .map(|column| format!("\"{column}\" TEXT"))
            .collect::<Vec<_>>()
            .join(",");
        let statement = format!("CREATE TABLE \"{table}\" ({definitions})");
        exec(db, Box::leak(statement.into_boxed_str())).await;
    }
}

async fn sqlite_fixture() -> Database {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let db = Database::Sqlite(pool);
    create_schema(&db).await;
    db
}

fn state_with(db: &Database) -> AppState {
    let state = AppState::default();
    state.bind_runtime(db.clone(), "setup-http-test-secret")
}

async fn database_scenarios(db: &Database) {
    let state = state_with(db);

    // GET before initialization reports the live root/database.
    let (status, body) = send(&state, get_setup()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["success"], true);
    assert!(body.get("message").is_none());
    assert_eq!(body["data"]["status"], false);
    assert_eq!(body["data"]["root_init"], false);
    assert_eq!(body["data"]["database_type"], database_type(db));

    // Malformed JSON.
    let (status, body) = send(&state, post_setup("{")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["success"], false);
    assert_eq!(body["message"], "请求参数有误");

    // 5 CJK characters are 15 UTF-8 bytes: Go's byte-length limit rejects them.
    let long = r#"{"username":"管理员管理员管理员管理员管理员","password":"secret123","confirmPassword":"secret123"}"#;
    let (_, body) = send(&state, post_setup(long)).await;
    assert_eq!(body["message"], "用户名长度不能超过12个字符");

    let mismatch = r#"{"username":"管理员","password":"secret123","confirmPassword":"secret124"}"#;
    let (_, body) = send(&state, post_setup(mismatch)).await;
    assert_eq!(body["message"], "两次输入的密码不一致");

    let short = r#"{"username":"管理员","password":"1234567","confirmPassword":"1234567"}"#;
    let (_, body) = send(&state, post_setup(short)).await;
    assert_eq!(body["message"], "密码长度至少为8个字符");

    // Non-JSON content types are skipped, leaving Go's zero values.
    let skipped = Request::builder()
        .method(Method::POST)
        .uri("/api/setup")
        .header(header::CONTENT_TYPE, "text/plain")
        .header(header::ACCEPT_LANGUAGE, "zh-CN")
        .body(Body::from(VALID_BODY))
        .unwrap();
    let (_, body) = send(&state, skipped).await;
    assert_eq!(body["message"], "密码长度至少为8个字符");
    assert_eq!(scalar_i64(db, COUNT_SETUPS).await, 0);

    // Successful initialization.
    let (status, body) = send(&state, post_setup(VALID_BODY)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["success"], true);
    assert_eq!(body["message"], "系统初始化成功");
    assert!(body.get("data").is_none());

    // setups: fixed id=1, version, positive Unix seconds.
    assert_eq!(scalar_i64(db, COUNT_SETUPS).await, 1);
    assert_eq!(
        scalar_string(db, SETUP_VERSION).await,
        env!("CARGO_PKG_VERSION")
    );
    assert!(scalar_i64(db, SETUP_INITIALIZED_AT).await > 0);

    // users: one Go-shaped root with a bcrypt cost10 hash of the password.
    assert_eq!(scalar_i64(db, ROOT_ROW).await, 1);
    let stored = scalar_string(db, ROOT_PASSWORD).await;
    assert!(verify_password(b"secret123", &stored).unwrap());

    // options: both modes are committed with the root/setup transaction.
    assert_eq!(scalar_string(db, SELF_USE_MODE).await, "true");
    assert_eq!(scalar_string(db, DEMO_SITE_MODE).await, "false");

    // GET after initialization zeroes the unused fields.
    let (status, body) = send(&state, get_setup()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["status"], true);
    assert_eq!(body["data"]["root_init"], false);
    assert_eq!(body["data"]["database_type"], "");

    // A repeated POST is rejected before body binding.
    let (status, body) = send(&state, post_setup("{")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["success"], false);
    assert_eq!(body["message"], "系统已经初始化完成");
    assert_eq!(scalar_i64(db, COUNT_SETUPS).await, 1);
}

#[tokio::test]
async fn sqlite_setup_http_contract() {
    let db = sqlite_fixture().await;
    database_scenarios(&db).await;
    db.close().await;
}

async fn postgres_fixture() -> Option<(Database, sqlx::PgPool, String)> {
    let dsn = std::env::var("TEST_POSTGRES_DSN")
        .ok()
        .filter(|dsn| !dsn.is_empty())?;
    let options: PgConnectOptions = dsn
        .parse()
        .unwrap_or_else(|_| panic!("invalid PostgreSQL fixture config"));
    let options = options.disable_statement_logging();
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone())
        .await
        .unwrap();
    let schema = format!(
        "setup_http_fixture_{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    // The identifier is a fixed prefix plus process-generated digits.
    assert!(
        schema
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    );
    let mut create = sqlx::QueryBuilder::new("CREATE SCHEMA \"");
    create.push(&schema).push("\"");
    create.build().execute(&admin).await.unwrap();
    let search_path = schema.clone();
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .after_connect(move |conn, _| {
            let path = search_path.clone();
            Box::pin(async move {
                sqlx::query::<sqlx::Postgres>("SELECT set_config('search_path', $1, false)")
                    .bind(path)
                    .execute(conn)
                    .await?;
                Ok(())
            })
        })
        .connect_with(options)
        .await
        .unwrap();
    let db = Database::Postgres(pool);
    create_schema(&db).await;
    Some((db, admin, schema))
}

async fn drop_schema(admin: &sqlx::PgPool, schema: &str) {
    let mut drop = sqlx::QueryBuilder::new("DROP SCHEMA \"");
    drop.push(schema).push("\" CASCADE");
    drop.build().execute(admin).await.unwrap();
}

#[tokio::test]
async fn postgres_setup_http_contract() {
    let Some((db, admin, schema)) = postgres_fixture().await else {
        // TEST_POSTGRES_DSN is optional locally; CI provides it.
        return;
    };
    database_scenarios(&db).await;
    db.close().await;
    drop_schema(&admin, &schema).await;
    admin.close().await;
}

#[tokio::test]
async fn existing_root_skips_validation_and_account_creation() {
    let db = sqlite_fixture().await;
    exec(&db, INSERT_EXISTING_ROOT).await;
    let state = state_with(&db);

    // Empty credentials would fail validation if it ran; an existing root
    // skips all three checks, exactly like Go.
    let (status, body) = send(&state, post_setup(ROOT_USER_SKIP_BODY)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["success"], true);
    assert_eq!(body["message"], "系统初始化成功");

    assert_eq!(scalar_i64(&db, COUNT_USERS).await, 1);
    assert_eq!(scalar_i64(&db, COUNT_SETUPS).await, 1);
    db.close().await;
}

#[tokio::test]
async fn any_setup_row_means_already_initialized() {
    let db = sqlite_fixture().await;
    exec(&db, INSERT_LEGACY_SETUP).await;
    let state = state_with(&db);

    let (status, body) = send(&state, get_setup()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["status"], true);
    assert_eq!(body["data"]["root_init"], false);
    assert_eq!(body["data"]["database_type"], "");

    let (status, body) = send(&state, post_setup(VALID_BODY)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["success"], false);
    assert_eq!(body["message"], "系统已经初始化完成");
    assert_eq!(scalar_i64(&db, COUNT_SETUPS).await, 1);
    db.close().await;
}

#[tokio::test]
async fn password_over_bcrypt_limit_writes_nothing() {
    let db = sqlite_fixture().await;
    let state = state_with(&db);
    let password = "x".repeat(73);
    let body = serde_json::json!({
        "username": "管理员",
        "password": password.clone(),
        "confirmPassword": password,
    })
    .to_string();

    let (status, body) = send(&state, post_setup(&body)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["success"], false);
    // Go reports a bcrypt failure through the transaction-failure branch.
    assert_eq!(body["message"], "创建管理员账号失败");
    assert_eq!(scalar_i64(&db, COUNT_SETUPS).await, 0);
    assert_eq!(scalar_i64(&db, COUNT_USERS).await, 0);
    db.close().await;
}

#[tokio::test]
async fn missing_schema_answers_503_for_both_methods() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let db = Database::Sqlite(pool);
    let state = state_with(&db);

    for request in [get_setup(), post_setup(VALID_BODY)] {
        let (status, body) = send(&state, request).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["success"], false);
        assert_eq!(body["message"], "数据库结构未就绪");
    }
    db.close().await;
}

#[tokio::test]
async fn post_setup_enforces_the_anonymous_body_limit() {
    let db = sqlite_fixture().await;
    let state = AppState::default()
        .bind_runtime(db.clone(), "setup-http-test-secret")
        .bind_transport(
            ProxyPolicy::parse_trusted_proxies(None).unwrap(),
            RateLimiter::memory(RateLimitSettings {
                enabled: false,
                requests: 0,
                window_seconds: 0,
            }),
            1,
        );
    let body = vec![b'x'; 2048];
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/setup")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_LENGTH, body.len().to_string())
        .body(Body::from(body))
        .unwrap();
    let response = router(state).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let body = to_bytes(response.into_body(), 1024).await.unwrap();
    assert!(body.is_empty());
    db.close().await;
}
