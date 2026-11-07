//! HTTP contracts for the four top-up quoting endpoints:
//! `POST /api/user/{amount,stripe/amount,waffo/amount,waffo-pancake/amount}`.
//!
//! Runs only in remote CI. Every scenario uses an isolated synthetic fixture
//! (in-memory SQLite or an isolated PostgreSQL schema); no service is started.
//! The PostgreSQL test is skipped when `TEST_POSTGRES_DSN` is absent.
//!
//! Unlike the read endpoints, these four write a **raw** `common.H` envelope:
//! `{"message":"success","data":"<price>"}` on success and
//! `{"message":"error","data":"<literal>"}` on failure — no `success` field
//! and no i18n translation. The tests therefore assert the exact body.

use std::sync::atomic::{AtomicU64, Ordering};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    middleware,
    response::Response,
    routing::post,
};
use newapi_server::{AppState, amount_http, auth::user_auth};
use newapi_storage::Database;
use serde_json::{Value, json};
use sqlx::{
    ConnectOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::SqlitePoolOptions,
};
use tower::ServiceExt;

static NEXT: AtomicU64 = AtomicU64::new(0);

const SECRET: &str = "amount-routes-fixture-secret";

/// `DOUBLE PRECISION` works as REAL affinity on SQLite and as the native
/// float8 on PostgreSQL, so one DDL serves both backends.
const USERS_SQLITE: &str = r#"CREATE TABLE users (
    id BIGINT PRIMARY KEY, username TEXT, display_name TEXT,
    role BIGINT, status INTEGER, email TEXT, github_id TEXT, discord_id TEXT,
    oidc_id TEXT, wechat_id TEXT, telegram_id TEXT, "group" TEXT,
    quota BIGINT, used_quota BIGINT, request_count BIGINT, aff_code TEXT,
    aff_count BIGINT, aff_quota BIGINT, aff_history BIGINT, inviter_id INTEGER,
    linux_do_id TEXT, setting TEXT, stripe_customer TEXT, auth_version BIGINT,
    access_token TEXT, deleted_at TIMESTAMP
)"#;

const OPTIONS: &str = r#"CREATE TABLE options ("key" TEXT PRIMARY KEY, "value" TEXT)"#;

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
        .route("/api/user/amount", post(amount_http::request_amount))
        .route(
            "/api/user/stripe/amount",
            post(amount_http::request_stripe_amount),
        )
        .route(
            "/api/user/waffo/amount",
            post(amount_http::request_waffo_amount),
        )
        .route(
            "/api/user/waffo-pancake/amount",
            post(amount_http::request_waffo_pancake_amount),
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

async fn create_schema(db: &Database) {
    exec(db, USERS_SQLITE).await;
    exec(db, OPTIONS).await;
}

async fn reset(db: &Database) {
    backend!(db, pool, {
        sqlx::query("DELETE FROM users")
            .execute(pool)
            .await
            .expect("reset users");
        sqlx::query("DELETE FROM options")
            .execute(pool)
            .await
            .expect("reset options");
    });
}

/// Seeds one user with an explicit group, wallet balance and quota display.
/// `quota_display_type` lands in the load-bearing option row so the handler
/// picks it up from the same snapshot it reads the prices from.
async fn seed_user(db: &Database, id: i64, group: &str, quota: i64, token: &str) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO users
                (id,username,display_name,role,status,"group",quota,
                 auth_version,access_token)
                VALUES ($1,'fixture','Fixture',1,1,$2,$3,1,$4)"#,
        )
        .bind(id)
        .bind(group)
        .bind(quota)
        .bind(token)
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

async fn clear_options(db: &Database) {
    backend!(db, pool, {
        sqlx::query("DELETE FROM options")
            .execute(pool)
            .await
            .expect("clear options");
    });
}

async fn post_amount(
    app: &Router,
    path: &str,
    authorization: Option<&str>,
    body: Body,
) -> Response {
    let mut request = Request::builder().method("POST").uri(path);
    if let Some(authorization) = authorization {
        request = request.header(header::AUTHORIZATION, authorization);
    }
    app.clone()
        .oneshot(request.body(body).unwrap())
        .await
        .expect("request")
}

/// Sends the `{"amount":N}` body exactly like the console does.
async fn post_quote(
    app: &Router,
    path: &str,
    authorization: Option<&str>,
    amount: i64,
) -> Response {
    post_amount(
        app,
        path,
        authorization,
        Body::from(json!({"amount": amount}).to_string()),
    )
    .await
}

async fn body_json(response: Response) -> Value {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

/// The raw `common.H` envelope: `message` is a literal, `data` carries the
/// price string on success.
async fn assert_quote(response: Response, expected_data: &str) {
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(
        body,
        json!({"message": "success", "data": expected_data}),
        "raw common.H envelope with no success field"
    );
}

async fn assert_error(response: Response, expected_data: &str) {
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body, json!({"message": "error", "data": expected_data}));
}

async fn error_data(response: Response) -> String {
    body_json(response).await["data"]
        .as_str()
        .unwrap()
        .to_owned()
}

// ---- the contract, run per backend --------------------------------------

async fn run_contract(db: Database) {
    create_schema(&db).await;
    reset(&db).await;

    // USD display is the default, so the price is the plain product.
    seed_user(&db, 1, "default", 0, "token-1").await;

    let app = state(&db);
    let router = router(app.clone());
    let auth = Some("Bearer token-1");

    // ---- POST /api/user/amount -------------------------------------------
    // Default options: MinTopUp 1, Price 7.3, no group ratio, no discount.
    assert_quote(
        post_quote(&router, "/api/user/amount", auth, 10).await,
        "73.00",
    )
    .await;

    // Below the minimum: Go interpolates the configured minimum.
    assert_error(
        post_quote(&router, "/api/user/amount", auth, 0).await,
        "充值数量不能小于 1",
    )
    .await;

    // A preset discount applies to the original request amount.
    seed_option(&db, "payment_setting.amount_discount", "{\"10\":0.5}").await;
    assert_quote(
        post_quote(&router, "/api/user/amount", auth, 10).await,
        "36.50",
    )
    .await;
    clear_options(&db).await;

    // Group ratio multiplies the price.
    seed_option(&db, "TopupGroupRatio", "{\"vip\":2}").await;
    seed_user(&db, 2, "vip", 0, "token-2").await;
    assert_quote(
        post_quote(&router, "/api/user/amount", Some("Bearer token-2"), 10).await,
        "146.00",
    )
    .await;
    clear_options(&db).await;

    // ---- Stripe ----------------------------------------------------------
    // Stripe's default unit price is 8.0 and its minimum is 1.
    assert_quote(
        post_quote(&router, "/api/user/stripe/amount", auth, 10).await,
        "80.00",
    )
    .await;
    // The hard ceiling is 10000 units.
    assert_error(
        post_quote(&router, "/api/user/stripe/amount", auth, 10_001).await,
        "充值数量不能大于 10000",
    )
    .await;

    // ---- Waffo / WaffoPancake -------------------------------------------
    assert_quote(
        post_quote(&router, "/api/user/waffo/amount", auth, 10).await,
        "10.00",
    )
    .await;
    assert_quote(
        post_quote(&router, "/api/user/waffo-pancake/amount", auth, 10).await,
        "10.00",
    )
    .await;

    // ---- wallet capacity ------------------------------------------------
    // A wallet that cannot absorb the credit reports Go's English sentinel.
    seed_user(&db, 3, "default", 2_147_483_000, "token-3").await;
    let response = post_quote(&router, "/api/user/amount", Some("Bearer token-3"), 10).await;
    assert_eq!(
        error_data(response).await,
        "top-up quota limit exceeded",
        "capacity rejection is an English sentinel, verbatim from Go"
    );
    // Stripe's *quote* endpoint runs the same capacity check: Go's
    // `rejectInvalidCreditedQuota` (`topup_api.go:277-287`) calls
    // `ValidateTopUpQuotaCapacity` whenever `validateCreditedQuota` accepts
    // the credited product, so the ceiling wallet is refused here too.
    assert_eq!(
        error_data(
            post_quote(
                &router,
                "/api/user/stripe/amount",
                Some("Bearer token-3"),
                10
            )
            .await
        )
        .await,
        "top-up quota limit exceeded",
        "Stripe's quote endpoint validates the wallet, not just the range"
    );

    // ---- TOKENS display -------------------------------------------------
    // `quota_display` is a state snapshot refreshed by `reload`, so the option
    // rows have to exist before the reload that adopts them.
    seed_option(&db, "general_setting.quota_display_type", "TOKENS").await;
    seed_option(&db, "QuotaPerUnit", "500000").await;
    app.reload(&db).await.expect("reload quota display");
    // 500000 tokens -> 1 USD of input -> 7.30.
    assert_quote(
        post_quote(&router, "/api/user/amount", auth, 500_000).await,
        "7.30",
    )
    .await;
    // TOKENS scales Stripe's minimum by QuotaPerUnit: 1 * 500000 = 500000.
    assert_error(
        post_quote(&router, "/api/user/stripe/amount", auth, 499_999).await,
        "充值数量不能小于 500000",
    )
    .await;
    // `getMinTopup` scales the amount route's minimum the same way
    // (`topup_api.go:215-223`), so a sub-unit token count is refused at the
    // minimum check rather than falling through to `validateTopUpQuota`'s
    // `充值数量无效`. This is the gate that pins the difference.
    assert_error(
        post_quote(&router, "/api/user/amount", auth, 499_999).await,
        "充值数量不能小于 500000",
    )
    .await;
    // One unit exactly clears the scaled minimum.
    assert_quote(
        post_quote(&router, "/api/user/amount", auth, 500_000).await,
        "7.30",
    )
    .await;
    // Stripe's own minimum is scaled by `QuotaPerUnit` (1 * 500000), so any
    // request that clears it is far above the flat `> 10000` ceiling Go
    // applies to the raw amount (`topup_stripe.go:47-50`). In TOKENS mode a
    // Stripe quote is therefore unreachable by this route: the one amount
    // that clears the scaled minimum (500000) trips the ceiling instead.
    assert_error(
        post_quote(&router, "/api/user/stripe/amount", auth, 500_000).await,
        "充值数量不能大于 10000",
    )
    .await;
    // The Waffo family does **not** scale its minimum.
    assert_quote(
        post_quote(&router, "/api/user/waffo/amount", auth, 500_000).await,
        "1.00",
    )
    .await;
    clear_options(&db).await;
    app.reload(&db)
        .await
        .expect("reload back to the default display");

    // ---- auth + body binding --------------------------------------------
    // No credential: the `UserAuth` middleware rejects before the handler.
    assert_eq!(
        post_amount(&router, "/api/user/amount", None, Body::empty())
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        post_quote(&router, "/api/user/amount", Some("Bearer token-1"), 10)
            .await
            .status(),
        StatusCode::OK
    );
    // Empty body binds the zero value, so it fails the minimum check.
    let response = post_amount(&router, "/api/user/amount", auth, Body::empty()).await;
    assert_eq!(
        error_data(response).await,
        "充值数量不能小于 1",
        "an empty body binds amount = 0"
    );
    // A non-JSON content type also binds the zero value.
    let request = Request::builder()
        .method("POST")
        .uri("/api/user/amount")
        .header(header::AUTHORIZATION, "Bearer token-1")
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from("10"))
        .unwrap();
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("non-json request");
    assert_eq!(
        error_data(response).await,
        "充值数量不能小于 1",
        "a non-JSON content type skips parsing and binds the zero value"
    );
    // Malformed JSON: Go `BindJSON` fails, so the literal error.
    let response = post_amount(
        &router,
        "/api/user/amount",
        auth,
        Body::from(r#"{"amount":"not-a-number"}"#),
    )
    .await;
    assert_eq!(error_data(response).await, "参数错误");
}

#[tokio::test]
async fn sqlite_amount_routes_contract() {
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    run_contract(Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn postgres_amount_routes_contract() {
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
        "amount_routes_{}_{}",
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
        .expect("create schema");
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "SET search_path TO \"{schema}\""
    )))
    .execute(&admin)
    .await
    .expect("set search_path");
    // `set_config(..., false)` is local to the session, so every pooled
    // connection carries its own isolated search_path (as in topup_routes).
    let search_path = schema.clone();
    let pool = PgPoolOptions::new()
        .max_connections(1)
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
        .expect("connect isolated PostgreSQL schema");
    run_contract(Database::Postgres(pool)).await;
}
