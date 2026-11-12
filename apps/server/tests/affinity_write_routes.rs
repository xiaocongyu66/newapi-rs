//! `GET /api/log/channel_affinity_usage_cache` 与写侧的契约（写侧
//! `newapi_catalog::affinity::observe_channel_affinity_usage_cache` 注入
//! 进程内计数器后，读端点必须返回真实数据而非恒 miss 形态）。
//!
//! Go oracle：`handle_affinity_cache.go:63-89`（参数校验）+
//! `track_affinity.go:776-810`（读）。仅内存缓存，无数据库参与；管理员
//! PAT 认证沿用 log_routes 的 fixture 形态。

use std::sync::atomic::{AtomicU64, Ordering};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, StatusCode, header},
    middleware,
    response::Response,
    routing::get,
};
use newapi_catalog::affinity::{self, ChannelAffinityStatsContext, UsageObservation};
use newapi_server::{AppState, log_http};
use newapi_storage::Database;
use serde_json::{Value, json};
use sqlx::{
    ConnectOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::SqlitePoolOptions,
};
use tower::ServiceExt;

static NEXT: AtomicU64 = AtomicU64::new(0);

const SECRET: &str = "affinity-write-fixture-secret";
const ADMIN_ID: i64 = 10;
const ADMIN_PAT: &str = "affinity-admin-pat";

const SQLITE_USERS: &str = r#"CREATE TABLE IF NOT EXISTS users (
    id BIGINT PRIMARY KEY, username TEXT, display_name TEXT,
    role BIGINT, status BIGINT, email TEXT, github_id TEXT, discord_id TEXT,
    oidc_id TEXT, wechat_id TEXT, telegram_id TEXT, "group" TEXT,
    quota BIGINT, used_quota BIGINT, request_count BIGINT, aff_code TEXT,
    aff_count BIGINT, aff_quota BIGINT, aff_history BIGINT, inviter_id BIGINT,
    linux_do_id TEXT, setting TEXT, stripe_customer TEXT, auth_version BIGINT,
    access_token TEXT, deleted_at TIMESTAMP
)"#;

fn state(db: &Database) -> AppState {
    AppState::default().bind_runtime(db.clone(), SECRET)
}

fn router(state: AppState) -> Router {
    Router::new()
        .route(
            "/api/log/channel_affinity_usage_cache",
            get(log_http::channel_affinity_usage_cache),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            newapi_server::auth::admin_auth,
        ))
        .with_state(state)
}

async fn sqlite_fixture() -> Database {
    let pool = SqlitePoolOptions::new()
        .max_connections(2)
        .connect(":memory:")
        .await
        .expect("in-memory SQLite fixture");
    sqlx::query(SQLITE_USERS)
        .execute(&pool)
        .await
        .expect("users");
    seed_admin(&pool).await;
    Database::Sqlite(pool)
}

async fn seed_admin(pool: &sqlx::SqlitePool) {
    sqlx::query(
        r#"INSERT INTO users
            (id,username,display_name,role,status,"group",auth_version,access_token)
            VALUES ($1,'admin','Fixture',10,1,'default',1,$2)"#,
    )
    .bind(ADMIN_ID)
    .bind(ADMIN_PAT)
    .execute(pool)
    .await
    .expect("seed admin");
}

async fn postgres_fixture() -> Option<Database> {
    let Ok(dsn) = std::env::var("TEST_POSTGRES_DSN") else {
        return None;
    };
    let options: PgConnectOptions = dsn
        .parse::<PgConnectOptions>()
        .expect("invalid PostgreSQL fixture config")
        .disable_statement_logging();
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone())
        .await
        .expect("connect PostgreSQL fixture");
    let schema = format!(
        "affinity_write_{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
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
    sqlx::query(SQLITE_USERS)
        .execute(&pool)
        .await
        .expect("users");
    sqlx::query(
        r#"INSERT INTO users
            (id,username,display_name,role,status,"group",auth_version,access_token)
            VALUES ($1,'admin','Fixture',10,1,'default',1,$2)"#,
    )
    .bind(ADMIN_ID)
    .bind(ADMIN_PAT)
    .execute(&pool)
    .await
    .expect("seed admin");
    Some(Database::Postgres(pool))
}

async fn request(state: &AppState, uri: &str) -> (StatusCode, Value) {
    let response: Response = router(state.clone())
        .oneshot(
            axum::http::Request::builder()
                .method(Method::GET)
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {ADMIN_PAT}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, body)
}

#[tokio::test]
async fn missing_params_still_reject_with_the_go_literals() {
    let db = sqlite_fixture().await;
    let state = state(&db);
    let (status, body) = request(&state, "/api/log/channel_affinity_usage_cache").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], json!("missing param: rule_name"));
    let (status, body) = request(&state, "/api/log/channel_affinity_usage_cache?rule_name=r").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], json!("missing param: key_fp"));
}

#[tokio::test]
async fn endpoint_returns_observed_counters_instead_of_constant_miss() {
    let db = sqlite_fixture().await;
    let state = state(&db);
    affinity::reset_caches_for_test();
    let ctx = ChannelAffinityStatsContext {
        rule_name: "codex cli trace".to_owned(),
        using_group: "default".to_owned(),
        key_fp: "aaf4c61d".to_owned(),
        ttl_seconds: 120,
    };
    affinity::observe_channel_affinity_usage_cache(
        &ctx,
        &UsageObservation {
            prompt_tokens: 90,
            completion_tokens: 9,
            total_tokens: 99,
            cached_tokens: 30,
            prompt_cache_hit_tokens: 0,
        },
        "cached_over_prompt",
    );
    let (status, body) = request(
        &state,
        "/api/log/channel_affinity_usage_cache?rule_name=codex%20cli%20trace&using_group=default&key_fp=aaf4c61d",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let data = &body["data"];
    assert_eq!(data["rule_name"], json!("codex cli trace"));
    assert_eq!(data["using_group"], json!("default"));
    assert_eq!(data["key_fp"], json!("aaf4c61d"));
    assert_eq!(data["cached_token_rate_mode"], json!("cached_over_prompt"));
    assert_eq!(data["total"], json!(1));
    assert_eq!(data["hit"], json!(1));
    assert_eq!(data["window_seconds"], json!(120));
    assert_eq!(data["prompt_tokens"], json!(90));
    assert_eq!(data["completion_tokens"], json!(9));
    assert_eq!(data["total_tokens"], json!(99));
    assert_eq!(data["cached_tokens"], json!(30));
    assert!(data["last_seen_at"].as_i64().unwrap() > 0);
    // 未命中键仍回显零值（Go 空形态）。
    let (_, body) = request(
        &state,
        "/api/log/channel_affinity_usage_cache?rule_name=other&key_fp=fp",
    )
    .await;
    assert_eq!(body["data"]["total"], json!(0));
    assert_eq!(body["data"]["rule_name"], json!("other"));
    affinity::reset_caches_for_test();
}

#[tokio::test]
async fn postgres_fixture_runs_the_same_contract() {
    let Some(db) = postgres_fixture().await else {
        eprintln!("TEST_POSTGRES_DSN absent; PostgreSQL half skipped");
        return;
    };
    let state = state(&db);
    let (status, body) = request(
        &state,
        "/api/log/channel_affinity_usage_cache?rule_name=r&key_fp=f",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["total"], json!(0));
}
