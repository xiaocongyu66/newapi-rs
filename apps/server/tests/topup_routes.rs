//! HTTP contracts for `GET /api/user/topup/info` and `GET /api/user/topup/self`.
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
    routing::get,
};
use newapi_server::{AppState, auth::user_auth, topup_http};
use newapi_storage::Database;
use serde_json::{Value, json};
use sqlx::{
    ConnectOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::SqlitePoolOptions,
};
use tower::ServiceExt;

static NEXT: AtomicU64 = AtomicU64::new(0);

const SECRET: &str = "topup-routes-fixture-secret";

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

// `DOUBLE PRECISION` works as REAL affinity on SQLite and as the native
// float8 on PostgreSQL, so one DDL serves both backends.
const TOP_UPS: &str = r#"CREATE TABLE top_ups (
    id BIGINT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    amount BIGINT NOT NULL,
    money DOUBLE PRECISION NOT NULL,
    trade_no VARCHAR(255) NOT NULL UNIQUE,
    payment_method VARCHAR(50),
    payment_provider VARCHAR(50),
    create_time BIGINT,
    complete_time BIGINT,
    status VARCHAR(20)
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
        .route("/api/user/topup/info", get(topup_http::topup_info))
        .route("/api/user/topup/self", get(topup_http::user_topups))
        .route_layer(middleware::from_fn_with_state(state.clone(), user_auth))
        .with_state(state)
}

fn state(db: &Database) -> AppState {
    // PAT authentication and both handlers read only the database.
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
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO users
                (id,username,display_name,role,status,"group",auth_version,access_token)
                VALUES ($1,'fixture','Fixture',1,1,'default',1,$2)"#,
        )
        .bind(id)
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

async fn seed_topup(db: &Database, id: i64, user_id: i64, trade_no: &str, create_time: i64) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO top_ups
                (id,user_id,amount,money,trade_no,payment_method,payment_provider,create_time,complete_time,status)
                VALUES ($1,$2,10,73.0,$3,'alipay','epay',$4,0,'success')"#,
        )
        .bind(id)
        .bind(user_id)
        .bind(trade_no)
        .bind(create_time)
        .execute(pool)
        .await
        .expect("seed topup");
    });
}

async fn send(state: &AppState, uri: &str, authorization: Option<&str>) -> Response {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(value) = authorization {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    router(state.clone())
        .oneshot(builder.body(Body::empty()).unwrap())
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

/// Business errors are HTTP 200 with the Go failure envelope.
async fn assert_business_error(response: Response, message: &str) -> Value {
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false), "{body}");
    assert_eq!(body["message"], json!(message));
    body
}

fn translated(key: &str) -> String {
    newapi_i18n::translate("en", key, std::iter::empty::<(&str, &str)>())
}

async fn run_contract(db: Database) {
    exec(&db, USERS).await;
    exec(&db, OPTIONS).await;
    exec(&db, TOP_UPS).await;
    seed_user(&db, 7, "pat-topup").await;
    seed_user(&db, 8, "pat-other").await;
    let auth = "Bearer pat-topup";
    let app = state(&db);

    // UserAuth guards both routes: no credential is 401.
    assert_eq!(
        send(&app, "/api/user/topup/info", None).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(&app, "/api/user/topup/self", None).await.status(),
        StatusCode::UNAUTHORIZED
    );

    // Empty options: Go process defaults with the compliance gate closed.
    let body = assert_success(send(&app, "/api/user/topup/info", Some(auth)).await).await;
    let data = &body["data"];
    assert_eq!(data["enable_online_topup"], json!(false));
    assert_eq!(data["enable_stripe_topup"], json!(false));
    assert_eq!(data["enable_creem_topup"], json!(false));
    assert_eq!(data["payment_compliance_confirmed"], json!(false));
    assert_eq!(data["payment_compliance_terms_version"], json!("v1"));
    assert_eq!(data["waffo_pay_methods"], Value::Null);
    assert_eq!(data["pay_methods"], json!([]));
    assert_eq!(data["min_topup"], json!(1));
    assert_eq!(data["stripe_min_topup"], json!(1));
    assert_eq!(data["amount_options"], json!([10, 20, 50, 100, 200, 500]));
    assert_eq!(data["discount"], json!({}));
    assert_eq!(data["topup_link"], json!(""));
    // Go unmarshals the "[]" default into an empty slice, rendered as [].
    assert_eq!(data["creem_products"], json!([]));

    // Compliance confirmed with Epay credentials: enablement flips and the
    // three default methods (all Epay-routed) become visible.
    seed_option(&db, "payment_setting.compliance_confirmed", "true").await;
    seed_option(&db, "payment_setting.compliance_terms_version", "v1").await;
    seed_option(&db, "PayAddress", "https://epay").await;
    seed_option(&db, "EpayId", "pid").await;
    seed_option(&db, "EpayKey", "pkey").await;
    let body = assert_success(send(&app, "/api/user/topup/info", Some(auth)).await).await;
    let data = &body["data"];
    assert_eq!(data["enable_online_topup"], json!(true));
    assert_eq!(data["payment_compliance_confirmed"], json!(true));
    assert_eq!(data["enable_redemption"], json!(true));
    let methods = data["pay_methods"].as_array().expect("pay methods");
    assert_eq!(methods.len(), 3);
    assert_eq!(methods[0]["type"], json!("alipay"));

    // Creem products: raw quota is rendered into `quota_display` (Go
    // `PopulateCreemProductDisplay`: 5,000,000 / 500,000 = 10.0) and a zero
    // render is dropped by `omitempty`.
    seed_option(&db, "CreemApiKey", "ck").await;
    seed_option(
        &db,
        "CreemProducts",
        r#"[{"productId":"p1","name":"Pack","price":10,"currency":"USD","quota":5000000},{"productId":"p2","quota":0}]"#,
    )
    .await;
    let body = assert_success(send(&app, "/api/user/topup/info", Some(auth)).await).await;
    assert_eq!(body["data"]["enable_creem_topup"], json!(true));
    let products = body["data"]["creem_products"]
        .as_array()
        .expect("creem products");
    assert_eq!(products.len(), 2);
    assert_eq!(products[0]["quota"], json!(5000000));
    assert_eq!(products[0]["quota_display"], json!(10.0));
    assert!(products[1].get("quota_display").is_none());

    // `GET /api/user/topup/self`: user filter, 30-day window, ordering.
    let now = now();
    seed_topup(&db, 1, 7, "USR7NOnew", now - 3600).await;
    seed_topup(&db, 2, 7, "USR7NOold", now - 7200).await;
    // 31 days old: outside the Go query window.
    seed_topup(&db, 3, 7, "USR7NOancient", now - 31 * 24 * 3600).await;
    // Another user's records: invisible through this route.
    seed_topup(&db, 4, 8, "USR8NOalien", now - 100).await;
    // Underscore in the trade number for the LIKE-escape check below.
    seed_topup(&db, 5, 7, "USRX7NOesc", now - 200).await;

    let body = assert_success(send(&app, "/api/user/topup/self", Some(auth)).await).await;
    let data = &body["data"];
    assert_eq!(data["page"], json!(1));
    assert_eq!(data["page_size"], json!(10));
    // Only ids 1, 2 and 5 belong to user 7 inside the window.
    assert_eq!(data["total"], json!(3));
    let items = data["items"].as_array().expect("items");
    assert_eq!(items.len(), 3);
    // Newest id first, Go `Order("id desc")`.
    assert_eq!(items[0]["id"], json!(5));
    assert_eq!(items[1]["id"], json!(2));
    assert_eq!(items[2]["id"], json!(1));
    let item = &items[2];
    assert_eq!(item["user_id"], json!(7));
    assert_eq!(item["amount"], json!(10));
    assert_eq!(item["money"], json!(73.0));
    assert_eq!(item["trade_no"], json!("USR7NOnew"));
    assert_eq!(item["payment_method"], json!("alipay"));
    assert_eq!(item["payment_provider"], json!("epay"));
    assert_eq!(item["complete_time"], json!(0));
    assert_eq!(item["status"], json!("success"));

    // Pagination: `page_size` + `p`.
    let body =
        assert_success(send(&app, "/api/user/topup/self?page_size=1&p=2", Some(auth)).await).await;
    assert_eq!(body["data"]["total"], json!(3));
    let items = body["data"]["items"].as_array().expect("items");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], json!(2));

    // Compatibility aliases and the 100 cap from Go `GetPageQuery`.
    let body = assert_success(send(&app, "/api/user/topup/self?size=1", Some(auth)).await).await;
    assert_eq!(body["data"]["page_size"], json!(1));
    let body = assert_success(send(&app, "/api/user/topup/self?ps=2", Some(auth)).await).await;
    assert_eq!(body["data"]["page_size"], json!(2));
    let body =
        assert_success(send(&app, "/api/user/topup/self?page_size=500", Some(auth)).await).await;
    assert_eq!(body["data"]["page_size"], json!(100));

    // Search: exact `trade_no` match — Go does not add % wildcards.
    let body =
        assert_success(send(&app, "/api/user/topup/self?keyword=USR7NOold", Some(auth)).await)
            .await;
    assert_eq!(body["data"]["total"], json!(1));
    assert_eq!(body["data"]["items"][0]["id"], json!(2));

    // Fuzzy search: `%25USR7NO%25` decodes to `%USR7NO%` and matches ids 1-2
    // but not `USRX7NOesc` nor the out-of-window row.
    let body = assert_success(
        send(
            &app,
            "/api/user/topup/self?keyword=%25USR7NO%25",
            Some(auth),
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["total"], json!(2));

    // The window and user filters also apply to searches.
    let body =
        assert_success(send(&app, "/api/user/topup/self?keyword=USR8NOalien", Some(auth)).await)
            .await;
    assert_eq!(body["data"]["total"], json!(0));
    assert_eq!(body["data"]["items"], json!([]));

    // `_` is escaped: `USR_7NOnew` must NOT match `USR7NOnew`-style rows as a
    // single-character wildcard; Go escapes `_` with `ESCAPE '!'`.
    let body =
        assert_success(send(&app, "/api/user/topup/self?keyword=USR_7NOnew", Some(auth)).await)
            .await;
    assert_eq!(body["data"]["total"], json!(0));
    // The literal underscore matches the seeded `USRX7NOesc` row: `USR_7NO`
    // with `_` escaped stays a literal `_` … so zero rows here as well.
    let body =
        assert_success(send(&app, "/api/user/topup/self?keyword=USRX7NOesc", Some(auth)).await)
            .await;
    assert_eq!(body["data"]["total"], json!(1));

    // Wildcard validation follows Go `SanitizeLikePattern`.
    assert_business_error(
        send(&app, "/api/user/topup/self?keyword=%25%25", Some(auth)).await,
        &translated("token.search_consecutive_wildcard"),
    )
    .await;
    assert_business_error(
        send(&app, "/api/user/topup/self?keyword=a%25", Some(auth)).await,
        &translated("token.search_keyword_too_short"),
    )
    .await;
    assert_business_error(
        send(&app, "/api/user/topup/self?keyword=%25a%25b%25", Some(auth)).await,
        &translated("token.search_wildcard_limit"),
    )
    .await;

    // Negative `p`: Go's GORM `Offset` clamps below zero, so the first page
    // renders; the reported page keeps the requested number.
    let body = assert_success(send(&app, "/api/user/topup/self?p=-1", Some(auth)).await).await;
    assert_eq!(body["data"]["page"], json!(-1));
    assert_eq!(body["data"]["items"].as_array().expect("items").len(), 3);
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[tokio::test]
async fn sqlite_topup_routes_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    run_contract(Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn postgres_topup_routes_contract() {
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
        "topup_routes_{}_{}",
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
