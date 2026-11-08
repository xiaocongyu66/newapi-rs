//! HTTP contracts for `GET /api/user/aff` (Go `GetAffCode`).
//!
//! Runs only in remote CI. Every scenario uses an isolated synthetic fixture
//! (in-memory SQLite or an isolated PostgreSQL schema); no service is started.
//! The PostgreSQL test is skipped when `TEST_POSTGRES_DSN` is absent.

use std::sync::atomic::{AtomicU64, Ordering};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Extension, State},
    http::{HeaderMap, Request, StatusCode, header},
    middleware,
    response::Response,
    routing::get,
};
use newapi_identity::user_auth::{CredentialKind, UserAuthIdentity};
use newapi_server::{
    AppState, aff_http,
    auth::{AuthenticatedUser, user_auth},
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

const SECRET: &str = "aff-routes-fixture-secret";

const USERS: &str = r#"CREATE TABLE users (
    id INTEGER PRIMARY KEY, username TEXT, display_name TEXT,
    role INTEGER, status INTEGER, email TEXT, github_id TEXT, discord_id TEXT,
    oidc_id TEXT, wechat_id TEXT, telegram_id TEXT, "group" TEXT,
    quota INTEGER, used_quota INTEGER, request_count INTEGER, aff_code TEXT,
    aff_count INTEGER, aff_quota INTEGER, aff_history INTEGER, inviter_id INTEGER,
    linux_do_id TEXT, setting TEXT, stripe_customer TEXT, auth_version BIGINT,
    access_token TEXT, deleted_at TIMESTAMP
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
        .route("/api/user/aff", get(aff_http::aff_code))
        .route_layer(middleware::from_fn_with_state(state.clone(), user_auth))
        .with_state(state)
}

fn state(db: &Database) -> AppState {
    // PAT authentication and the handler both read only the database.
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

async fn seed_user(db: &Database, id: i64, aff_code: Option<&str>, token: &str) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO users
                (id,username,display_name,role,status,"group",auth_version,access_token,aff_code)
                VALUES ($1,'fixture','Fixture',1,1,'default',1,$2,$3)"#,
        )
        .bind(id)
        .bind(token)
        .bind(aff_code)
        .execute(pool)
        .await
        .expect("seed user");
    });
}

async fn soft_delete(db: &Database, id: i64) {
    backend!(db, pool, {
        sqlx::query(
            "UPDATE users SET deleted_at=CAST('2026-01-01 00:00:00' AS TIMESTAMP) WHERE id=$1",
        )
        .bind(id)
        .execute(pool)
        .await
        .expect("soft delete user");
    });
}

async fn stored_aff_code(db: &Database, id: i64) -> Option<String> {
    backend!(db, pool, {
        sqlx::query_scalar::<_, Option<String>>("SELECT aff_code FROM users WHERE id=$1")
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("stored aff code")
    })
}

async fn send(state: &AppState, authorization: Option<&str>) -> Response {
    let mut builder = Request::builder().method("GET").uri("/api/user/aff");
    if let Some(value) = authorization {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    router(state.clone())
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

/// Call the handler with a fabricated authenticated identity. This exercises
/// the branch Go reaches when the user disappears between `UserAuth` and
/// `GetUserById`; the real middleware would reject the same request earlier.
async fn send_authenticated(state: &AppState, user_id: i64) -> Response {
    let identity = UserAuthIdentity {
        user_id,
        username: "fixture".to_owned(),
        role: 1,
        status: 1,
        auth_version: 1,
        group: "default".to_owned(),
        credential: CredentialKind::PersonalAccessToken,
    };
    aff_http::aff_code(
        State(state.clone()),
        Extension(AuthenticatedUser(identity)),
        HeaderMap::new(),
    )
    .await
}

async fn body_json(response: Response) -> Value {
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body");
    serde_json::from_slice(&bytes).expect("response JSON")
}

async fn assert_auth_failure(response: Response) {
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false));
    assert_eq!(body["code"], json!("AUTH_UNAUTHORIZED"));
}

fn assert_success(body: &Value) {
    assert_eq!(body["success"], json!(true));
    assert_eq!(body["message"], json!(""));
}

fn assert_not_found(body: &Value) {
    assert_eq!(body["success"], json!(false));
    assert_eq!(body["message"], json!("User does not exist"));
    assert!(body.get("data").is_none());
}

async fn run_contract(db: Database) {
    exec(&db, USERS).await;
    let app = state(&db);

    // Go `UserAuth` wraps `/aff`: absent and invalid credentials are 401.
    assert_auth_failure(send(&app, None).await).await;
    assert_auth_failure(send(&app, Some("Bearer not-a-token")).await).await;

    // A persisted code is returned unchanged and never rewritten.
    seed_user(&db, 1, Some("Ab12"), "pat-existing").await;
    let response = send(&app, Some("Bearer pat-existing")).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_success(&body);
    assert_eq!(body["data"], json!("Ab12"));
    assert_eq!(stored_aff_code(&db, 1).await.as_deref(), Some("Ab12"));

    // NULL and empty codes are (re)generated as 4 alphanumeric characters and
    // persisted; a second call returns the same value.
    seed_user(&db, 2, None, "pat-null").await;
    seed_user(&db, 3, Some(""), "pat-blank").await;
    for (id, token) in [(2, "pat-null"), (3, "pat-blank")] {
        let authorization = format!("Bearer {token}");
        let response = send(&app, Some(&authorization)).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_success(&body);
        let code = body["data"].as_str().expect("aff code string").to_owned();
        assert_eq!(code.len(), 4);
        assert!(code.bytes().all(|byte| byte.is_ascii_alphanumeric()));
        assert_eq!(
            stored_aff_code(&db, id).await.as_deref(),
            Some(code.as_str())
        );

        let response = send(&app, Some(&authorization)).await;
        let body = body_json(response).await;
        assert_success(&body);
        assert_eq!(body["data"], json!(code.as_str()));
        assert_eq!(
            stored_aff_code(&db, id).await.as_deref(),
            Some(code.as_str())
        );
    }

    // GORM's default scope hides soft-deleted rows, so `UserAuth` rejects the
    // PAT exactly like an unknown token.
    seed_user(&db, 4, Some("Gd41"), "pat-deleted").await;
    soft_delete(&db, 4).await;
    assert_auth_failure(send(&app, Some("Bearer pat-deleted")).await).await;

    // If authentication passed just before deletion, Go's `GetUserById` fails
    // with `record not found` and `CtxApiError` returns HTTP 200 with
    // `success:false`. This port keeps the shape but uses a fixed translated
    // message instead of database text.
    for user_id in [4, 99] {
        let response = send_authenticated(&app, user_id).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_not_found(&body_json(response).await);
    }
}

#[tokio::test]
async fn sqlite_aff_routes_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    run_contract(Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn postgres_aff_routes_contract() {
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
        "aff_routes_{}_{}",
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

// ---------------------------------------------------------------------------
// POST /api/user/aff_transfer — Go `identity.TransferAffQuota`
// ---------------------------------------------------------------------------

const OPTIONS: &str = r#"CREATE TABLE options (
    "key" TEXT PRIMARY KEY,
    value TEXT
)"#;

fn transfer_router(state: AppState) -> Router {
    Router::new()
        .route(
            "/api/user/aff_transfer",
            axum::routing::post(aff_http::transfer_aff_quota),
        )
        .route_layer(middleware::from_fn_with_state(state.clone(), user_auth))
        .with_state(state)
}

async fn seed_transfer_user(db: &Database, id: i64, token: &str, aff_quota: i64, quota: i64) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO users
                (id,username,display_name,role,status,"group",auth_version,
                 access_token,aff_code,aff_quota,quota)
                VALUES ($1,'transfer','Transfer',1,1,'default',1,$2,
                        'Xf99',$3,$4)"#,
        )
        .bind(id)
        .bind(token)
        .bind(aff_quota)
        .bind(quota)
        .execute(pool)
        .await
        .expect("seed transfer user");
    });
}

/// Go `dbinfra.UpdateOption` 是 FirstOrCreate + Save 的 upsert 语义：同一 key
/// 再次“播种”是改值而非插入。SQLite 3.24+ 与 PostgreSQL 的 upsert 语法一致，
/// 同一语句两个驱动都能跑。
async fn seed_option(db: &Database, key: &str, value: &str) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO options ("key", value) VALUES ($1,$2)
               ON CONFLICT("key") DO UPDATE SET value = excluded.value"#,
        )
        .bind(key)
        .bind(value)
        .execute(pool)
        .await
        .expect("seed option");
    });
}

/// PG 的余额列沿用 Go schema 的 INTEGER（INT4），实现层统一以 CAST(... AS
/// BIGINT) 提升为 i64 再解码（见 UserProfileRepository::PROFILE_BY_ID 的
/// 处理）；SQLite 的 BIGINT 亲和性同为 INTEGER，同一语句两驱动通用。
async fn stored_quota(db: &Database, id: i64) -> (i64, i64) {
    backend!(db, pool, {
        sqlx::query_as::<_, (i64, i64)>(
            "SELECT CAST(aff_quota AS BIGINT), CAST(quota AS BIGINT) FROM users WHERE id = $1",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("stored balances")
    })
}

async fn send_transfer(
    state: &AppState,
    authorization: Option<&str>,
    body: &'static str,
) -> Response {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/api/user/aff_transfer")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT_LANGUAGE, "zh-CN");
    if let Some(value) = authorization {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    transfer_router(state.clone())
        .oneshot(builder.body(Body::from(body.to_owned())).unwrap())
        .await
        .unwrap()
}

async fn run_transfer_contract(db: Database) {
    exec(&db, USERS).await;
    exec(&db, OPTIONS).await;
    let app = state(&db);

    // ---- the compliance gate precedes every other branch ----------------
    // Go's `RequirePaymentComplianceMiddleware` runs before the handler, so an
    // unconfirmed site never reaches the transfer — and never even binds the
    // body.
    seed_option(&db, "payment_setting.compliance_confirmed", "false").await;
    seed_transfer_user(&db, 1, "pat-1", 2_000_000, 0).await;
    let response = send_transfer(&app, Some("Bearer pat-1"), r#"{"quota":500000}"#).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body_json(response).await,
        json!({
            "success": false,
            "message": "支付、兑换码、订阅计划和邀请返利功能已禁用。管理员需先确认合规声明后方可启用。",
        }),
        "compliance gate uses Go's i18n literal and carries no data"
    );
    assert_eq!(
        stored_quota(&db, 1).await,
        (2_000_000, 0),
        "a rejected gate must not move any balance"
    );

    // Confirmed site: the transfer now runs. Go `IsPaymentComplianceConfirmed`
    // is a two-part gate — `compliance_confirmed == true` AND
    // `compliance_terms_version == "v1"` (payment_compliance.go writes both
    // keys in `ConfirmPaymentCompliance`), and the missing terms version alone
    // keeps the gate shut, so both options have to be flipped here.
    seed_option(&db, "payment_setting.compliance_confirmed", "true").await;
    seed_option(&db, "payment_setting.compliance_terms_version", "v1").await;

    // ---- quota: the raw internal amount moves across --------------------
    seed_option(&db, "general_setting.custom_currency_exchange_rate", "1").await;
    let response = send_transfer(&app, Some("Bearer pat-1"), r#"{"quota":500000}"#).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body_json(response).await,
        // Go `CtxApiSuccessI18n(c, MsgUserTransferSuccess, nil)`.
        json!({"success": true, "message": "划转成功", "data": null}),
    );
    assert_eq!(stored_quota(&db, 1).await, (1_500_000, 500_000));

    // ---- quota_display beats quota, and converts through QuotaPerUnit ----
    // 1 USD with the 500000 default unit is exactly 500000 internal.
    let response = send_transfer(
        &app,
        Some("Bearer pat-1"),
        r#"{"quota":1,"quota_display":1.0}"#,
    )
    .await;
    assert_eq!(
        body_json(response).await,
        json!({"success": true, "message": "划转成功", "data": null}),
    );
    assert_eq!(
        stored_quota(&db, 1).await,
        (1_000_000, 1_000_000),
        "quota_display=1.0 wins over quota=1 and converts by QuotaPerUnit"
    );

    // A `quota_display` of 0 is absent, so the raw `quota` applies.
    let response = send_transfer(
        &app,
        Some("Bearer pat-1"),
        r#"{"quota":250000,"quota_display":0}"#,
    )
    .await;
    assert_eq!(
        body_json(response).await,
        json!({"success": true, "message": "划转成功", "data": null}),
    );
    assert_eq!(stored_quota(&db, 1).await, (750_000, 1_250_000));

    // ---- non-positive amount ---------------------------------------------
    // Go's `amount <= 0` branch. A non-finite `quota_display` cannot be
    // expressed in JSON at all — serde binds the zero value, which lands in
    // the same branch — so only the negative shape needs asserting here.
    let response = send_transfer(&app, Some("Bearer pat-1"), r#"{"quota":-5}"#).await;
    assert_eq!(
        body_json(response).await,
        json!({"success": false, "message": "转账数额必须大于 0"}),
    );
    // A non-JSON content type keeps the zero value (Go `UnmarshalBodyReusable`).
    let builder = Request::builder()
        .method("POST")
        .uri("/api/user/aff_transfer")
        .header(header::CONTENT_TYPE, "text/plain")
        .header(header::AUTHORIZATION, "Bearer pat-1")
        .header(header::ACCEPT_LANGUAGE, "zh-CN");
    let response = transfer_router(app.clone())
        .oneshot(builder.body(Body::from("anything")).unwrap())
        .await
        .unwrap();
    assert_eq!(
        body_json(response).await,
        json!({"success": false, "message": "转账数额必须大于 0"}),
    );
    assert_eq!(stored_quota(&db, 1).await, (750_000, 1_250_000));

    // ---- one-unit minimum ------------------------------------------------
    // 499_999 internal quota is below `QuotaPerUnit` (500_000), and
    // `{{.Min}}` is Go's `LogQuota(QuotaFromFloat(500000))` — the
    // currency-wrapped display string, not a bare number.
    let response = send_transfer(&app, Some("Bearer pat-1"), r#"{"quota":499999}"#).await;
    assert_eq!(
        body_json(response).await,
        json!({
            "success": false,
            "message": "转移额度最小为＄1.000000 额度！",
        }),
    );

    // ---- insufficient affiliate balance ---------------------------------
    let response = send_transfer(&app, Some("Bearer pat-1"), r#"{"quota":999999}"#).await;
    assert_eq!(
        body_json(response).await,
        json!({"success": false, "message": "邀请额度不足！"}),
    );
    assert_eq!(
        stored_quota(&db, 1).await,
        (750_000, 1_250_000),
        "a failed transfer must not move any balance"
    );

    // ---- drained wallet goes through the same path -----------------------
    let response = send_transfer(&app, Some("Bearer pat-1"), r#"{"quota":750000}"#).await;
    assert_eq!(
        body_json(response).await,
        json!({"success": true, "message": "划转成功", "data": null}),
    );
    assert_eq!(stored_quota(&db, 1).await, (0, 2_000_000));
    // Now the wallet is empty, so the same request hits the insufficient branch.
    let response = send_transfer(&app, Some("Bearer pat-1"), r#"{"quota":500000}"#).await;
    assert_eq!(
        body_json(response).await,
        json!({"success": false, "message": "邀请额度不足！"}),
    );

    // ---- a soft-deleted user is a missing user --------------------------
    seed_transfer_user(&db, 2, "pat-deleted", 1_000_000, 0).await;
    soft_delete(&db, 2).await;
    let response = send_transfer(&app, Some("Bearer pat-deleted"), r#"{"quota":500000}"#).await;
    assert_eq!(
        body_json(response).await,
        json!({"success": false, "message": "用户不存在"}),
    );

    // ---- authentication -------------------------------------------------
    let response = send_transfer(&app, None, r#"{"quota":500000}"#).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = send_transfer(&app, Some("Bearer not-a-token"), r#"{"quota":500000}"#).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn sqlite_aff_transfer_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    run_transfer_contract(Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn postgres_aff_transfer_contract() {
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
        "aff_transfer_{}_{}",
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
    run_transfer_contract(Database::Postgres(pool)).await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA \"{schema}\" CASCADE"
    )))
    .execute(&admin)
    .await
    .expect("drop isolated schema");
    admin.close().await;
}
