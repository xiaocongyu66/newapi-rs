//! HTTP contracts for the subscription self-service routes:
//! `GET /api/subscription/plans`, `GET /api/subscription/self`,
//! `PUT /api/subscription/self/preference`.
//!
//! Runs only in remote CI. Every scenario uses an isolated synthetic fixture
//! (in-memory SQLite or an isolated PostgreSQL schema); no service is started.
//! The PostgreSQL test is skipped when `TEST_POSTGRES_DSN` is absent.

use std::sync::atomic::{AtomicU64, Ordering};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    middleware,
    response::Response,
    routing::{get, put},
};
use newapi_server::{AppState, auth::user_auth, subscription_http};
use newapi_storage::Database;
use serde_json::{Value, json};
use sqlx::{
    ConnectOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::SqlitePoolOptions,
};
use tower::ServiceExt;

static NEXT: AtomicU64 = AtomicU64::new(0);

const SECRET: &str = "subscription-routes-fixture-secret";

const USERS: &str = r#"CREATE TABLE users (
    id BIGINT PRIMARY KEY, username TEXT, display_name TEXT,
    role BIGINT, status INTEGER, email TEXT, github_id TEXT, discord_id TEXT,
    oidc_id TEXT, wechat_id TEXT, telegram_id TEXT, "group" TEXT,
    quota BIGINT, used_quota BIGINT, request_count BIGINT, aff_code TEXT,
    aff_count BIGINT, aff_quota BIGINT, aff_history BIGINT, inviter_id INTEGER,
    linux_do_id TEXT, setting TEXT, stripe_customer TEXT, auth_version BIGINT,
    access_token TEXT, deleted_at TIMESTAMP
)"#;

const OPTIONS: &str = r#"CREATE TABLE options ("key" TEXT PRIMARY KEY, "value" TEXT)"#;

// One DDL for both backends: `DOUBLE PRECISION` is REAL affinity on SQLite
// and float8 on PostgreSQL; booleans are BIGINT so the CAST reads are uniform.
const SUBSCRIPTION_PLANS: &str = r#"CREATE TABLE subscription_plans (
    id BIGINT PRIMARY KEY,
    title VARCHAR(128) NOT NULL,
    subtitle VARCHAR(255) DEFAULT '',
    price_amount DOUBLE PRECISION NOT NULL DEFAULT 0,
    currency VARCHAR(8) NOT NULL DEFAULT 'USD',
    duration_unit VARCHAR(16) NOT NULL DEFAULT 'month',
    duration_value BIGINT NOT NULL DEFAULT 1,
    custom_seconds BIGINT NOT NULL DEFAULT 0,
    enabled BIGINT DEFAULT 1,
    sort_order BIGINT DEFAULT 0,
    allow_balance_pay BIGINT DEFAULT 1,
    allow_wallet_overflow BIGINT DEFAULT 1,
    stripe_price_id VARCHAR(128) DEFAULT '',
    creem_product_id VARCHAR(128) DEFAULT '',
    waffo_pancake_product_id VARCHAR(128) DEFAULT '',
    max_purchase_per_user BIGINT DEFAULT 0,
    upgrade_group VARCHAR(64) DEFAULT '',
    downgrade_group VARCHAR(64) DEFAULT '',
    total_amount BIGINT NOT NULL DEFAULT 0,
    quota_reset_period VARCHAR(16) DEFAULT 'never',
    quota_reset_custom_seconds BIGINT DEFAULT 0,
    created_at BIGINT,
    updated_at BIGINT
)"#;

const USER_SUBSCRIPTIONS: &str = r#"CREATE TABLE user_subscriptions (
    id BIGINT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    plan_id BIGINT NOT NULL,
    amount_total BIGINT NOT NULL DEFAULT 0,
    amount_used BIGINT NOT NULL DEFAULT 0,
    start_time BIGINT,
    end_time BIGINT,
    status VARCHAR(32),
    source VARCHAR(32) DEFAULT 'order',
    last_reset_time BIGINT DEFAULT 0,
    next_reset_time BIGINT DEFAULT 0,
    upgrade_group VARCHAR(64) DEFAULT '',
    prev_user_group VARCHAR(64) DEFAULT '',
    downgrade_group VARCHAR(64) DEFAULT '',
    allow_wallet_overflow BIGINT DEFAULT 1,
    created_at BIGINT,
    updated_at BIGINT
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
    Router::new()
        .route("/api/subscription/plans", get(subscription_http::plans))
        .route(
            "/api/subscription/self",
            get(subscription_http::self_subscriptions),
        )
        .route(
            "/api/subscription/self/preference",
            put(subscription_http::update_preference),
        )
        .route_layer(middleware::from_fn_with_state(state.clone(), user_auth))
        .with_state(state)
}

fn state(db: &Database) -> AppState {
    AppState::default().bind_runtime(db.clone(), SECRET)
}

async fn exec(db: &Database, statement: &'static str) {
    backend!(db, pool, {
        sqlx::query(statement)
            .execute(pool)
            .await
            .expect("fixture ddl");
    });
}

async fn seed_user(db: &Database, id: i64, token: &str) {
    seed_user_setting(db, id, token, None).await;
}

async fn seed_user_setting(db: &Database, id: i64, token: &str, setting: Option<&str>) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO users
                (id,username,display_name,role,status,"group",auth_version,access_token,setting)
                VALUES ($1,'fixture','Fixture',1,1,'default',1,$2,$3)"#,
        )
        .bind(id)
        .bind(token)
        .bind(setting)
        .execute(pool)
        .await
        .expect("seed user");
    });
}

async fn seed_option(db: &Database, key: &str, value: &str) {
    backend!(db, pool, {
        sqlx::query("INSERT INTO options (\"key\", \"value\") VALUES ($1, $2)")
            .bind(key)
            .bind(value)
            .execute(pool)
            .await
            .expect("seed option");
    });
}

#[allow(clippy::too_many_arguments)]
async fn seed_plan(
    db: &Database,
    id: i64,
    title: &str,
    price_amount: f64,
    enabled: i64,
    sort_order: i64,
    total_amount: i64,
    allow_balance_pay: Option<i64>,
) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO subscription_plans
                (id,title,price_amount,currency,duration_unit,duration_value,enabled,sort_order,total_amount,allow_balance_pay,created_at,updated_at)
                VALUES ($1,$2,$3,'USD','month',1,$4,$5,$6,$7,100,200)"#,
        )
        .bind(id)
        .bind(title)
        .bind(price_amount)
        .bind(enabled)
        .bind(sort_order)
        .bind(total_amount)
        .bind(allow_balance_pay)
        .execute(pool)
        .await
        .expect("seed plan");
    });
}

#[allow(clippy::too_many_arguments)]
async fn seed_subscription(
    db: &Database,
    id: i64,
    user_id: i64,
    plan_id: i64,
    amount_total: i64,
    amount_used: i64,
    status: &str,
    end_time: i64,
) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO user_subscriptions
                (id,user_id,plan_id,amount_total,amount_used,start_time,end_time,status,source,created_at,updated_at)
                VALUES ($1,$2,$3,$4,$5,1,$6,$7,'order',100,200)"#,
        )
        .bind(id)
        .bind(user_id)
        .bind(plan_id)
        .bind(amount_total)
        .bind(amount_used)
        .bind(end_time)
        .bind(status)
        .execute(pool)
        .await
        .expect("seed subscription");
    });
}

async fn send(
    state: &AppState,
    method: &str,
    uri: &str,
    authorization: Option<&str>,
    body: Option<String>,
) -> Response {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(value) = authorization {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    router(state.clone())
        .oneshot(
            builder
                .body(
                    body.map(Body::from)
                        .unwrap_or_else(|| Body::from(String::new())),
                )
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn body_json(response: Response) -> Value {
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body");
    serde_json::from_slice(&bytes).expect("response JSON")
}

async fn assert_success(response: Response) -> Value {
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true), "{body}");
    assert_eq!(body["message"], json!(""));
    body
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

async fn run_contract(db: Database) {
    exec(&db, USERS).await;
    exec(&db, OPTIONS).await;
    exec(&db, SUBSCRIPTION_PLANS).await;
    exec(&db, USER_SUBSCRIPTIONS).await;
    seed_user(&db, 7, "pat-sub").await;
    seed_user(&db, 8, "pat-other").await;
    let auth = "Bearer pat-sub";
    let app = state(&db);

    // UserAuth guards all three routes: no credential is 401.
    assert_eq!(
        send(&app, "GET", "/api/subscription/plans", None, None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(&app, "GET", "/api/subscription/self", None, None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(&app, "PUT", "/api/subscription/self/preference", None, None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );

    // --- plans ---
    // Compliance gate closed: Go returns an empty success list without
    // querying, even when enabled rows exist.
    seed_plan(&db, 1, "Starter", 1.0, 1, 1, 0, None).await;
    let body =
        assert_success(send(&app, "GET", "/api/subscription/plans", Some(auth), None).await).await;
    assert_eq!(body["data"], json!([]), "{body}");

    // Compliance confirmed: enabled plans, sorted sort_order desc / id desc,
    // disabled rows excluded, DTO wrapper, display fields rendered.
    seed_option(&db, "payment_setting.compliance_confirmed", "true").await;
    seed_option(&db, "payment_setting.compliance_terms_version", "v1").await;
    seed_plan(&db, 2, "Pro", 2.0, 1, 10, 1_000_000, None).await;
    seed_plan(&db, 3, "Max", 5.0, 1, 10, 500_000, Some(0)).await;
    seed_plan(&db, 4, "Disabled", 9.0, 0, 99, 0, None).await;
    let body =
        assert_success(send(&app, "GET", "/api/subscription/plans", Some(auth), None).await).await;
    let plans = body["data"].as_array().expect("plans array");
    assert_eq!(plans.len(), 3, "{body}");
    // sort_order 10 ties → id desc: 3 then 2; starter last.
    assert_eq!(plans[0]["plan"]["id"], json!(3));
    assert_eq!(plans[1]["plan"]["id"], json!(2));
    assert_eq!(plans[2]["plan"]["id"], json!(1));
    // AfterFind/NormalizeDefaults rendering (USD: /500000).
    assert_eq!(plans[1]["plan"]["title"], json!("Pro"));
    assert_eq!(plans[1]["plan"]["total_amount_display"], json!(2.0));
    assert_eq!(plans[1]["plan"]["balance_cost_display"], json!(2.0));
    // NULL pointer columns normalize to true.
    assert_eq!(plans[1]["plan"]["allow_balance_pay"], json!(true));
    assert_eq!(plans[1]["plan"]["allow_wallet_overflow"], json!(true));
    // Explicit false survives.
    assert_eq!(plans[0]["plan"]["allow_balance_pay"], json!(false));
    assert_eq!(plans[1]["plan"]["price_amount"], json!(2.0));
    assert_eq!(plans[1]["plan"]["currency"], json!("USD"));

    // --- self ---
    // Empty state: default preference, empty arrays.
    let body =
        assert_success(send(&app, "GET", "/api/subscription/self", Some(auth), None).await).await;
    assert_eq!(
        body["data"]["billing_preference"],
        json!("subscription_first")
    );
    assert_eq!(body["data"]["subscriptions"], json!([]));
    assert_eq!(body["data"]["all_subscriptions"], json!([]));

    // Active vs expired: `subscriptions` keeps only status='active' with
    // end_time in the future; `all_subscriptions` keeps everything, ordered
    // end_time desc / id desc.
    let now = now();
    seed_subscription(&db, 1, 7, 2, 1_000_000, 250_000, "active", now + 3600).await;
    seed_subscription(&db, 2, 7, 1, 500_000, 100_000, "expired", now - 3600).await;
    seed_subscription(&db, 3, 7, 1, 500_000, 0, "active", now - 10).await;
    seed_subscription(&db, 4, 7, 1, 500_000, 0, "cancelled", now + 9999).await;
    // Another user's rows are invisible.
    seed_subscription(&db, 5, 8, 1, 500_000, 0, "active", now + 9999).await;
    let body =
        assert_success(send(&app, "GET", "/api/subscription/self", Some(auth), None).await).await;
    let data = &body["data"];
    let active = data["subscriptions"].as_array().expect("active");
    assert_eq!(active.len(), 1, "{body}");
    assert_eq!(active[0]["subscription"]["id"], json!(1));
    assert_eq!(active[0]["subscription"]["status"], json!("active"));
    assert_eq!(
        active[0]["subscription"]["amount_total_display"],
        json!(2.0)
    );
    assert_eq!(active[0]["subscription"]["amount_used_display"], json!(0.5));
    let all = data["all_subscriptions"].as_array().expect("all");
    // end_time desc: id 4 (now+9999), 1 (now+3600), 3 (now-10), 2 (now-3600).
    let all_ids: Vec<_> = all
        .iter()
        .map(|s| s["subscription"]["id"].clone())
        .collect();
    assert_eq!(json!(all_ids), json!([4, 1, 3, 2]), "{body}");

    // Stored preference is echoed through normalization. User 8 was seeded
    // earlier without a setting row value, so update it in place instead of
    // inserting a duplicate.
    backend!(db, pool, {
        sqlx::query("UPDATE users SET setting = $1 WHERE id = 8")
            .bind(r#"{"billing_preference":"wallet_first"}"#)
            .execute(pool)
            .await
            .expect("update user setting");
    });
    let body = assert_success(
        send(
            &app,
            "GET",
            "/api/subscription/self",
            Some("Bearer pat-other"),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["billing_preference"], json!("wallet_first"));

    // --- preference PUT ---
    // Valid value: echoed and persisted into users.setting.
    let body = assert_success(
        send(
            &app,
            "PUT",
            "/api/subscription/self/preference",
            Some(auth),
            Some(r#"{"billing_preference":"wallet_only"}"#.into()),
        )
        .await,
    )
    .await;
    assert_eq!(body["data"], json!({"billing_preference": "wallet_only"}));
    backend!(db, pool, {
        let stored: Option<String> = sqlx::query_scalar("SELECT setting FROM users WHERE id = 7")
            .fetch_one(&pool)
            .await
            .expect("read back setting");
        let stored: Value = serde_json::from_str(&stored.expect("setting written")).unwrap();
        assert_eq!(
            stored["billing_preference"],
            json!("wallet_only"),
            "{stored}"
        );
    });

    // Unrecognized value normalizes to the Go default and persists as such.
    let body = assert_success(
        send(
            &app,
            "PUT",
            "/api/subscription/self/preference",
            Some(auth),
            Some(r#"{"billing_preference":"bogus"}"#.into()),
        )
        .await,
    )
    .await;
    assert_eq!(
        body["data"],
        json!({"billing_preference": "subscription_first"})
    );

    // Empty body is Go's zero-value bind, not an error: normalizes to the
    // default preference.
    let body = assert_success(
        send(
            &app,
            "PUT",
            "/api/subscription/self/preference",
            Some(auth),
            Some(String::new()),
        )
        .await,
    )
    .await;
    assert_eq!(
        body["data"],
        json!({"billing_preference": "subscription_first"})
    );

    // Malformed JSON is Go's hardcoded 参数错误.
    let response = send(
        &app,
        "PUT",
        "/api/subscription/self/preference",
        Some(auth),
        Some("{not json".into()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false));
    assert_eq!(body["message"], json!("参数错误"));
}

async fn sqlite_fixture() -> Database {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    Database::Sqlite(pool)
}

async fn postgres_fixture() -> Result<Option<Database>, ()> {
    let Ok(dsn) = std::env::var("TEST_POSTGRES_DSN") else {
        eprintln!("TEST_POSTGRES_DSN absent; skipping PostgreSQL contract");
        return Ok(None);
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
        "subscription_self_{}_{}",
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
    Ok(Some(Database::Postgres(pool)))
}

#[tokio::test]
async fn subscription_routes_sqlite() {
    let db = sqlite_fixture().await;
    run_contract(db).await;
}

#[tokio::test]
async fn subscription_routes_postgres() {
    let Some(db) = postgres_fixture().await.expect("postgres fixture") else {
        return;
    };
    run_contract(db).await;
}
