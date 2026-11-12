//! HTTP contracts for the subscription admin routes
//! (`/api/subscription/admin/*`).
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
    routing::{delete, get, post, put},
};
use newapi_server::{AppState, auth::admin_auth, subscription_admin_http};
use newapi_storage::Database;
use serde_json::{Value, json};
use sqlx::{
    ConnectOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::SqlitePoolOptions,
};
use tower::ServiceExt;

static NEXT: AtomicU64 = AtomicU64::new(0);

const SECRET: &str = "subscription-admin-fixture-secret";

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
// and float8 on PostgreSQL; booleans are BOOLEAN (SQLite NUMERIC affinity
// stores 1/0, the repo reads them through CAST(... AS BIGINT)).
const SUBSCRIPTION_PLANS: &str = r#"CREATE TABLE subscription_plans (
    id INTEGER PRIMARY KEY,
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
    id INTEGER PRIMARY KEY,
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
        .route(
            "/api/subscription/admin/plans",
            get(subscription_admin_http::admin_list_plans)
                .post(subscription_admin_http::admin_create_plan),
        )
        .route(
            "/api/subscription/admin/plans/{id}",
            put(subscription_admin_http::admin_update_plan)
                .patch(subscription_admin_http::admin_update_plan_status),
        )
        .route(
            "/api/subscription/admin/plans/{id}/subscriptions/reset",
            post(subscription_admin_http::admin_reset_plan_subscriptions),
        )
        .route(
            "/api/subscription/admin/bind",
            post(subscription_admin_http::admin_bind),
        )
        .route(
            "/api/subscription/admin/users/{id}/subscriptions",
            get(subscription_admin_http::admin_list_user_subscriptions)
                .post(subscription_admin_http::admin_create_user_subscription),
        )
        .route(
            "/api/subscription/admin/users/{id}/subscriptions/reset",
            post(subscription_admin_http::admin_reset_user_subscriptions),
        )
        .route(
            "/api/subscription/admin/user_subscriptions/{id}/invalidate",
            post(subscription_admin_http::admin_invalidate_subscription),
        )
        .route(
            "/api/subscription/admin/user_subscriptions/{id}",
            delete(subscription_admin_http::admin_delete_subscription),
        )
        .route_layer(middleware::from_fn_with_state(state.clone(), admin_auth))
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

/// PostgreSQL `INTEGER PRIMARY KEY` has no default; wire named sequences.
/// SQLite's `INTEGER PRIMARY KEY` auto-assigns max(id)+1 natively.
async fn setup_pg_sequences(db: &Database) {
    if let Database::Postgres(pool) = db {
        for (table, seq) in [
            ("subscription_plans", "subscription_plans_seq"),
            ("user_subscriptions", "user_subscriptions_seq"),
        ] {
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "CREATE SEQUENCE IF NOT EXISTS {seq}"
            )))
            .execute(pool)
            .await
            .expect("create sequence");
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "ALTER TABLE {table} ALTER COLUMN id SET DEFAULT nextval('{seq}')"
            )))
            .execute(pool)
            .await
            .expect("wire sequence default");
        }
        sync_pg_sequences(db).await;
    }
}

/// Explicit-id seeds leave the sequence behind; resync so auto-generated
/// inserts don't collide with seeded ids. Must re-run after every block of
/// explicit-id seeds.
async fn sync_pg_sequences(db: &Database) {
    if let Database::Postgres(pool) = db {
        for (table, seq) in [
            ("subscription_plans", "subscription_plans_seq"),
            ("user_subscriptions", "user_subscriptions_seq"),
        ] {
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "SELECT setval('{seq}', GREATEST((SELECT COALESCE(MAX(id), 0) FROM {table}), 1))"
            )))
            .execute(pool)
            .await
            .expect("sync sequence");
        }
    }
}

async fn seed_user(db: &Database, id: i64, role: i64, token: &str, group: &str) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO users
                (id,username,display_name,role,status,"group",auth_version,access_token)
                VALUES ($1,'fixture','Fixture',$2,1,$3,1,$4)"#,
        )
        .bind(id)
        .bind(role)
        .bind(group)
        .bind(token)
        .execute(pool)
        .await
        .expect("seed user");
    });
}

async fn seed_option(db: &Database, key: &str, value: &str) {
    backend!(db, pool, {
        sqlx::query(r#"INSERT INTO options ("key", "value") VALUES ($1, $2)"#)
            .bind(key)
            .bind(value)
            .execute(pool)
            .await
            .expect("seed option");
    });
}

async fn seed_plan(db: &Database, id: i64, title: &str, sort_order: i64, enabled: bool) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO subscription_plans
                (id,title,price_amount,currency,duration_unit,duration_value,enabled,sort_order,total_amount,created_at,updated_at)
                VALUES ($1,$2,1.0,'USD','month',1,$3,$4,0,100,200)"#,
        )
        .bind(id)
        .bind(title)
        .bind(enabled as i64)
        .bind(sort_order)
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
    amount_used: i64,
    status: &str,
    end_time: i64,
    upgrade_group: &str,
    prev_user_group: &str,
) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO user_subscriptions
                (id,user_id,plan_id,amount_total,amount_used,start_time,end_time,status,source,upgrade_group,prev_user_group,created_at,updated_at)
                VALUES ($1,$2,$3,1000,$4,1,$5,$6,'admin',$7,$8,100,200)"#,
        )
        .bind(id)
        .bind(user_id)
        .bind(plan_id)
        .bind(amount_used)
        .bind(end_time)
        .bind(status)
        .bind(upgrade_group)
        .bind(prev_user_group)
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

async fn assert_failure(response: Response, message: Value) -> Value {
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false), "{body}");
    assert_eq!(body["message"], message, "{body}");
    body
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

async fn seed_compliance(db: &Database) {
    seed_option(db, "payment_setting.compliance_confirmed", "true").await;
    seed_option(db, "payment_setting.compliance_terms_version", "v1").await;
}

async fn run_contract(db: Database) {
    exec(&db, USERS).await;
    exec(&db, OPTIONS).await;
    exec(&db, SUBSCRIPTION_PLANS).await;
    exec(&db, USER_SUBSCRIPTIONS).await;
    seed_user(&db, 1, 10, "tok-admin", "default").await;
    seed_user(&db, 2, 1, "tok-user", "default").await;
    seed_user(&db, 3, 10, "tok-low", "default").await;
    setup_pg_sequences(&db).await;
    let auth = "Bearer tok-admin";
    let user_auth = "Bearer tok-user";
    let low_auth = "Bearer tok-low";
    let app = state(&db);

    // --- auth ---
    assert_eq!(
        send(&app, "GET", "/api/subscription/admin/plans", None, None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    // Non-admin credentials pass UserAuth but fail the role>=10 gate with 403.
    assert_eq!(
        send(
            &app,
            "GET",
            "/api/subscription/admin/plans",
            Some(user_auth),
            None
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    // role 10 satisfies AdminAuth.
    assert_eq!(
        send(
            &app,
            "GET",
            "/api/subscription/admin/plans",
            Some(low_auth),
            None
        )
        .await
        .status(),
        StatusCode::OK
    );

    // --- admin list: no compliance gate, includes disabled, sorted ---
    seed_plan(&db, 1, "Disabled", 99, false).await;
    seed_plan(&db, 2, "Pro", 10, true).await;
    seed_plan(&db, 3, "Max", 10, true).await;
    sync_pg_sequences(&db).await;
    let body = assert_success(
        send(
            &app,
            "GET",
            "/api/subscription/admin/plans",
            Some(auth),
            None,
        )
        .await,
    )
    .await;
    let plans = body["data"].as_array().expect("plans array");
    assert_eq!(plans.len(), 3, "{body}");
    // sort_order desc first: Disabled (99), then the sort-10 tie broken by id desc.
    assert_eq!(plans[0]["plan"]["id"], json!(1));
    assert_eq!(plans[1]["plan"]["id"], json!(3));
    assert_eq!(plans[2]["plan"]["id"], json!(2));
    assert_eq!(plans[0]["plan"]["enabled"], json!(false));

    // --- create: compliance gate first ---
    let response = send(
        &app,
        "POST",
        "/api/subscription/admin/plans",
        Some(auth),
        Some(r#"{"plan":{"title":"X"}}"#.into()),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false), "{body}");
    assert!(!body["message"].as_str().unwrap().is_empty(), "{body}");

    seed_compliance(&db).await;

    // Bind with malformed JSON is 参数错误.
    seed_option(&db, "GroupRatio", r#"{"default":1,"vip":0.5}"#).await;
    app.reload(&db).await.unwrap();
    let response = send(
        &app,
        "POST",
        "/api/subscription/admin/plans",
        Some(auth),
        Some("{not json".into()),
    )
    .await;
    assert_failure(response, json!("参数错误")).await;

    // Validation ladder mirrors the Go order.
    for (payload, message) in [
        (r#"{"plan":{}}"#, "套餐标题不能为空"),
        (
            r#"{"plan":{"title":"X","price_amount":-1}}"#,
            "价格不能为负数",
        ),
        (
            r#"{"plan":{"title":"X","price_amount":10000}}"#,
            "价格不能超过9999",
        ),
        (
            r#"{"plan":{"title":"X","max_purchase_per_user":-1}}"#,
            "购买上限不能为负数",
        ),
        (
            r#"{"plan":{"title":"X","total_amount_display":"1e999"}}"#,
            "参数错误",
        ),
        // "ghost" is absent from the seeded GroupRatio; note "vip" IS known,
        // so a vip plan falls through to the free-plan-cap check instead.
        (
            r#"{"plan":{"title":"X","upgrade_group":"ghost"}}"#,
            "升级分组不存在",
        ),
        (
            r#"{"plan":{"title":"X","downgrade_group":"ghost"}}"#,
            "降级分组不存在",
        ),
        (
            r#"{"plan":{"title":"X","quota_reset_period":"custom","quota_reset_custom_seconds":0}}"#,
            "自定义重置周期需大于0秒",
        ),
        (
            r#"{"plan":{"title":"X","total_amount":100}}"#,
            "免费赠送额度或升级权益的套餐必须设置每用户购买上限",
        ),
    ] {
        let response = send(
            &app,
            "POST",
            "/api/subscription/admin/plans",
            Some(auth),
            Some(payload.into()),
        )
        .await;
        assert_failure(response, json!(message)).await;
    }

    // Happy path: defaults applied (currency USD, duration month/1, pointers
    // true), total_amount_display converts server-side, id backfilled, the
    // response mirrors the Create struct (display fields are zero, not
    // recomputed — Go Create does not run AfterFind).
    let payload = json!({
        "plan": {
            "title": "Pro",
            "price_amount": 2.0,
            "total_amount_display": 2.0,
            "max_purchase_per_user": 3,
            "upgrade_group": "vip",
            "sort_order": 5,
            "quota_reset_period": "monthly"
        }
    })
    .to_string();
    let body = assert_success(
        send(
            &app,
            "POST",
            "/api/subscription/admin/plans",
            Some(auth),
            Some(payload),
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["currency"], json!("USD"));
    assert_eq!(body["data"]["duration_unit"], json!("month"));
    assert_eq!(body["data"]["duration_value"], json!(1));
    assert_eq!(body["data"]["allow_balance_pay"], json!(true));
    assert_eq!(body["data"]["allow_wallet_overflow"], json!(true));
    assert_eq!(body["data"]["total_amount"], json!(1_000_000));
    assert_eq!(body["data"]["total_amount_display"], json!(0.0));
    assert_eq!(body["data"]["balance_cost_display"], json!(0.0));
    assert_eq!(body["data"]["upgrade_group"], json!("vip"));
    assert_eq!(body["data"]["quota_reset_period"], json!("monthly"));
    assert!(body["data"]["id"].as_i64().unwrap() > 0, "{body}");
    let pro_id = body["data"]["id"].as_i64().unwrap();

    // The stored row renders displays through the list endpoint.
    let body = assert_success(
        send(
            &app,
            "GET",
            "/api/subscription/admin/plans",
            Some(auth),
            None,
        )
        .await,
    )
    .await;
    let plans = body["data"].as_array().unwrap();
    let pro = plans
        .iter()
        .find(|p| p["plan"]["id"] == json!(pro_id))
        .unwrap();
    assert_eq!(pro["plan"]["total_amount_display"], json!(2.0));

    // --- update (PUT): full-column overwrite, nil pointers keep values ---
    let response = send(
        &app,
        "PUT",
        &format!("/api/subscription/admin/plans/{pro_id}"),
        Some(auth),
        Some(r#"{"plan":{"title":"Pro2","price_amount":3.0,"max_purchase_per_user":2}}"#.into()),
    )
    .await;
    let body = assert_success(response).await;
    assert_eq!(body["data"], json!(null), "{body}");

    let body = assert_success(
        send(
            &app,
            "GET",
            "/api/subscription/admin/plans",
            Some(auth),
            None,
        )
        .await,
    )
    .await;
    let plans = body["data"].as_array().unwrap();
    let pro = plans
        .iter()
        .find(|p| p["plan"]["id"] == json!(pro_id))
        .unwrap();
    assert_eq!(pro["plan"]["title"], json!("Pro2"));
    assert_eq!(pro["plan"]["price_amount"], json!(3.0));
    assert_eq!(pro["plan"]["allow_balance_pay"], json!(true));
    assert_eq!(pro["plan"]["total_amount"], json!(0));
    // `enabled` omitted → Go map update writes the zero value false.
    assert_eq!(pro["plan"]["enabled"], json!(false));

    // An explicit enabled=false PUT is the same zero-value overwrite.
    let _ = send(
        &app,
        "PUT",
        &format!("/api/subscription/admin/plans/{pro_id}"),
        Some(auth),
        Some(r#"{"plan":{"title":"Pro2","price_amount":3.0,"enabled":false}}"#.into()),
    )
    .await;
    let body = assert_success(
        send(
            &app,
            "GET",
            "/api/subscription/admin/plans",
            Some(auth),
            None,
        )
        .await,
    )
    .await;
    let plans = body["data"].as_array().unwrap();
    let pro = plans
        .iter()
        .find(|p| p["plan"]["id"] == json!(pro_id))
        .unwrap();
    assert_eq!(pro["plan"]["enabled"], json!(false));

    // Invalid / zero id.
    let response = send(
        &app,
        "PUT",
        "/api/subscription/admin/plans/abc",
        Some(auth),
        Some(r#"{"plan":{"title":"X"}}"#.into()),
    )
    .await;
    assert_failure(response, json!("无效的ID")).await;

    // --- PATCH status ---
    let response = send(
        &app,
        "PATCH",
        &format!("/api/subscription/admin/plans/{pro_id}"),
        Some(auth),
        Some(r#"{"enabled":true}"#.into()),
    )
    .await;
    assert_success(response).await;
    let body = assert_success(
        send(
            &app,
            "GET",
            "/api/subscription/admin/plans",
            Some(auth),
            None,
        )
        .await,
    )
    .await;
    let plans = body["data"].as_array().unwrap();
    let pro = plans
        .iter()
        .find(|p| p["plan"]["id"] == json!(pro_id))
        .unwrap();
    assert_eq!(pro["plan"]["enabled"], json!(true));
    // enabled null → 参数错误.
    let response = send(
        &app,
        "PATCH",
        &format!("/api/subscription/admin/plans/{pro_id}"),
        Some(auth),
        Some(r#"{}"#.into()),
    )
    .await;
    assert_failure(response, json!("参数错误")).await;

    // --- bind: creates a subscription, applies upgrade group ---
    let payload = json!({"plan":{"title":"VipPlan","price_amount":1.0,"max_purchase_per_user":2,"upgrade_group":"vip"}}).to_string();
    let body = assert_success(
        send(
            &app,
            "POST",
            "/api/subscription/admin/plans",
            Some(auth),
            Some(payload),
        )
        .await,
    )
    .await;
    let vip_plan_id = body["data"]["id"].as_i64().unwrap();

    let response = send(
        &app,
        "POST",
        "/api/subscription/admin/bind",
        Some(auth),
        Some(json!({"user_id": 2, "plan_id": vip_plan_id}).to_string()),
    )
    .await;
    let body = assert_success(response).await;
    assert_eq!(
        body["data"]["message"],
        json!("用户分组将升级到 vip"),
        "{body}"
    );
    // The user's group was upgraded.
    backend!(&db, pool, {
        let group: String = sqlx::query_scalar(r#"SELECT "group" FROM users WHERE id = 2"#)
            .fetch_one(pool)
            .await
            .expect("user group");
        assert_eq!(group, "vip");
    });

    // The created subscription is listed for the user.
    let body = assert_success(
        send(
            &app,
            "GET",
            "/api/subscription/admin/users/2/subscriptions",
            Some(auth),
            None,
        )
        .await,
    )
    .await;
    let subs = body["data"].as_array().unwrap();
    assert_eq!(subs.len(), 1, "{body}");
    assert_eq!(subs[0]["subscription"]["plan_id"], json!(vip_plan_id));
    assert_eq!(subs[0]["subscription"]["source"], json!("admin"));
    assert_eq!(subs[0]["subscription"]["status"], json!("active"));
    assert_eq!(subs[0]["subscription"]["upgrade_group"], json!("vip"));
    assert_eq!(subs[0]["subscription"]["prev_user_group"], json!("default"));

    // Second bind hits the per-user purchase cap.
    let response = send(
        &app,
        "POST",
        "/api/subscription/admin/bind",
        Some(auth),
        Some(json!({"user_id": 2, "plan_id": vip_plan_id}).to_string()),
    )
    .await;
    assert_failure(response, json!("已达到该套餐购买上限")).await;

    // Unknown plan / unknown user are gorm record not found.
    let response = send(
        &app,
        "POST",
        "/api/subscription/admin/bind",
        Some(auth),
        Some(json!({"user_id": 2, "plan_id": 9999}).to_string()),
    )
    .await;
    assert_failure(response, json!("record not found")).await;
    let response = send(
        &app,
        "POST",
        "/api/subscription/admin/bind",
        Some(auth),
        Some(json!({"user_id": 9999, "plan_id": vip_plan_id}).to_string()),
    )
    .await;
    assert_failure(response, json!("record not found")).await;
    // Bad params.
    let response = send(
        &app,
        "POST",
        "/api/subscription/admin/bind",
        Some(auth),
        Some(json!({"user_id": 0, "plan_id": 1}).to_string()),
    )
    .await;
    assert_failure(response, json!("参数错误")).await;

    // POST /users/:id/subscriptions is the same bind flow.
    let response = send(
        &app,
        "POST",
        "/api/subscription/admin/users/3/subscriptions",
        Some(auth),
        Some(json!({"plan_id": vip_plan_id}).to_string()),
    )
    .await;
    let body = assert_success(response).await;
    assert_eq!(
        body["data"]["message"],
        json!("用户分组将升级到 vip"),
        "{body}"
    );
    let response = send(
        &app,
        "POST",
        "/api/subscription/admin/users/-1/subscriptions",
        Some(auth),
        Some(json!({"plan_id": vip_plan_id}).to_string()),
    )
    .await;
    assert_failure(response, json!("无效的用户ID")).await;
    let response = send(
        &app,
        "GET",
        "/api/subscription/admin/users/-1/subscriptions",
        Some(auth),
        None,
    )
    .await;
    assert_failure(response, json!("无效的用户ID")).await;

    // --- reset (user scope) ---
    let future = now() + 3600;
    seed_subscription(
        &db,
        11,
        3,
        vip_plan_id,
        400,
        "active",
        future,
        "vip",
        "default",
    )
    .await;
    seed_subscription(
        &db,
        12,
        3,
        vip_plan_id,
        500,
        "active",
        future + 10,
        "vip",
        "default",
    )
    .await;
    // Expired and other-plan rows must not be matched.
    seed_subscription(
        &db,
        13,
        3,
        vip_plan_id,
        600,
        "expired",
        future,
        "vip",
        "default",
    )
    .await;
    seed_subscription(&db, 14, 3, 1, 700, "active", future, "", "").await;
    sync_pg_sequences(&db).await;

    let response = send(
        &app,
        "POST",
        "/api/subscription/admin/users/3/subscriptions/reset",
        Some(auth),
        Some(json!({"plan_id": vip_plan_id, "advance_reset_time": false}).to_string()),
    )
    .await;
    let body = assert_success(response).await;
    assert_eq!(body["data"]["plan_id"], json!(vip_plan_id), "{body}");
    assert_eq!(body["data"]["matched_count"], json!(2));
    assert_eq!(body["data"]["reset_count"], json!(2));
    assert_eq!(body["data"]["user_count"], json!(1));
    assert_eq!(body["data"]["advance_reset_time"], json!(false));
    backend!(&db, pool, {
        let (used, last, next): (i64, i64, i64) = sqlx::query_as(
            "SELECT amount_used, last_reset_time, next_reset_time FROM user_subscriptions WHERE id = 11",
        )
        .fetch_one(pool)
        .await
        .expect("reset row");
        assert_eq!(used, 0);
        assert_eq!(last, 100, "advance_reset_time=false keeps last_reset_time");
        assert_eq!(next, 0, "advance_reset_time=false keeps next_reset_time");
    });

    // advance_reset_time defaults to true and moves the monthly reset point.
    backend!(&db, pool, {
        sqlx::query("UPDATE subscription_plans SET quota_reset_period = 'monthly' WHERE id = $1")
            .bind(vip_plan_id)
            .execute(pool)
            .await
            .expect("plan reset period");
    });
    let response = send(
        &app,
        "POST",
        "/api/subscription/admin/users/3/subscriptions/reset",
        Some(auth),
        Some(json!({"plan_id": vip_plan_id}).to_string()),
    )
    .await;
    let body = assert_success(response).await;
    assert_eq!(body["data"]["advance_reset_time"], json!(true));
    backend!(&db, pool, {
        let (last, next): (i64, i64) = sqlx::query_as(
            "SELECT last_reset_time, next_reset_time FROM user_subscriptions WHERE id = 11",
        )
        .fetch_one(pool)
        .await
        .expect("reset row");
        assert!(last > 0, "{last}");
        assert!(
            next > last,
            "next_reset_time must advance past now ({next} <= {last})"
        );
    });

    // No active subscription → business error.
    let response = send(
        &app,
        "POST",
        "/api/subscription/admin/users/2/subscriptions/reset",
        Some(auth),
        Some(json!({"plan_id": 9999}).to_string()),
    )
    .await;
    // plan 9999 doesn't exist → record not found first.
    assert_failure(response, json!("record not found")).await;
    // A plan with no active subs for the user → 该用户没有有效的此套餐订阅.
    let payload =
        json!({"plan":{"title":"Lonely","price_amount":1.0,"max_purchase_per_user":5}}).to_string();
    let body = assert_success(
        send(
            &app,
            "POST",
            "/api/subscription/admin/plans",
            Some(auth),
            Some(payload),
        )
        .await,
    )
    .await;
    let lonely_id = body["data"]["id"].as_i64().unwrap();
    let response = send(
        &app,
        "POST",
        "/api/subscription/admin/users/2/subscriptions/reset",
        Some(auth),
        Some(json!({"plan_id": lonely_id}).to_string()),
    )
    .await;
    assert_failure(response, json!("该用户没有有效的此套餐订阅")).await;
    // plan_id <= 0 → 参数错误.
    let response = send(
        &app,
        "POST",
        "/api/subscription/admin/users/2/subscriptions/reset",
        Some(auth),
        Some(json!({"plan_id": 0}).to_string()),
    )
    .await;
    assert_failure(response, json!("参数错误")).await;

    // --- reset (plan scope) ---
    seed_subscription(
        &db,
        21,
        2,
        vip_plan_id,
        300,
        "active",
        future + 20,
        "vip",
        "default",
    )
    .await;
    sync_pg_sequences(&db).await;

    let response = send(
        &app,
        "POST",
        &format!("/api/subscription/admin/plans/{vip_plan_id}/subscriptions/reset"),
        Some(auth),
        Some(json!({"advance_reset_time": false}).to_string()),
    )
    .await;
    let body = assert_success(response).await;
    // Active subs of this plan: 11, 12 (user 3) and 21 (user 2).
    assert_eq!(body["data"]["matched_count"], json!(3), "{body}");
    assert_eq!(body["data"]["user_count"], json!(2));
    let response = send(
        &app,
        "POST",
        "/api/subscription/admin/plans/9999/subscriptions/reset",
        Some(auth),
        Some(json!({}).to_string()),
    )
    .await;
    assert_failure(response, json!("record not found")).await;
    let response = send(
        &app,
        "POST",
        "/api/subscription/admin/plans/abc/subscriptions/reset",
        Some(auth),
        Some(json!({}).to_string()),
    )
    .await;
    assert_failure(response, json!("无效的ID")).await;

    // --- invalidate: cancels and downgrades the group ---
    // user 3 has two active upgraded subs (11, 12) → the "other active"
    // guard keeps the group on the first invalidate.
    let response = send(
        &app,
        "POST",
        "/api/subscription/admin/user_subscriptions/11/invalidate",
        Some(auth),
        None,
    )
    .await;
    let body = assert_success(response).await;
    assert_eq!(body["data"], json!(null), "{body}");
    backend!(&db, pool, {
        let (status, end, group): (String, i64, String) = sqlx::query_as(
            r#"SELECT s.status, s.end_time, u."group" FROM user_subscriptions s
               JOIN users u ON u.id = s.user_id WHERE s.id = 11"#,
        )
        .fetch_one(pool)
        .await
        .expect("invalidated row");
        assert_eq!(status, "cancelled");
        assert!(end >= now() - 5 && end <= now() + 5, "{end}");
        assert_eq!(group, "vip", "another active upgraded sub keeps the group");
    });

    // Invalidate the last upgraded sub → group falls back.
    let response = send(
        &app,
        "POST",
        "/api/subscription/admin/user_subscriptions/12/invalidate",
        Some(auth),
        None,
    )
    .await;
    let body = assert_success(response).await;
    assert_eq!(
        body["data"]["message"],
        json!("用户分组将回退到 default"),
        "{body}"
    );
    backend!(&db, pool, {
        let group: String = sqlx::query_scalar(r#"SELECT "group" FROM users WHERE id = 3"#)
            .fetch_one(pool)
            .await
            .expect("user group");
        assert_eq!(group, "default");
    });

    // Unknown subscription → record not found; bad id → 无效的订阅ID.
    let response = send(
        &app,
        "POST",
        "/api/subscription/admin/user_subscriptions/9999/invalidate",
        Some(auth),
        None,
    )
    .await;
    assert_failure(response, json!("record not found")).await;
    let response = send(
        &app,
        "POST",
        "/api/subscription/admin/user_subscriptions/abc/invalidate",
        Some(auth),
        None,
    )
    .await;
    assert_failure(response, json!("无效的订阅ID")).await;

    // --- delete: hard delete, same downgrade semantics ---
    let response = send(
        &app,
        "DELETE",
        "/api/subscription/admin/user_subscriptions/21",
        Some(auth),
        None,
    )
    .await;
    let body = assert_success(response).await;
    assert_eq!(
        body["data"]["message"],
        json!("用户分组将回退到 default"),
        "{body}"
    );
    backend!(&db, pool, {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM user_subscriptions WHERE id = 21")
                .fetch_one(pool)
                .await
                .expect("deleted row");
        assert_eq!(count, 0);
    });
    let response = send(
        &app,
        "DELETE",
        "/api/subscription/admin/user_subscriptions/21",
        Some(auth),
        None,
    )
    .await;
    assert_failure(response, json!("record not found")).await;
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
        "subscription_admin_{}_{}",
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
async fn subscription_admin_routes_sqlite() {
    let db = sqlite_fixture().await;
    run_contract(db).await;
}

#[tokio::test]
async fn subscription_admin_routes_postgres() {
    let Some(db) = postgres_fixture().await.expect("postgres fixture") else {
        return;
    };
    run_contract(db).await;
}
