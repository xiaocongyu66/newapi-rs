//! HTTP contracts for the `/api/token/*` management endpoints.
//!
//! Runs only in remote CI. Every scenario uses an isolated synthetic fixture
//! (in-memory SQLite or an isolated PostgreSQL schema); no service is started.
//! The PostgreSQL test is skipped when `TEST_POSTGRES_DSN` is absent.
//!
//! Go semantics notes:
//! - Business outcomes (including another user's token) are HTTP 200 with
//!   `{success:false,message}`. `UserAuth` is the only source of 401/403.
//! - Raw keys appear only in `POST /api/token/:id/key`; every response is
//!   checked for accidental leakage.
//! - A non-`auto` token group is persisted as submitted; only `auto_groups`
//!   is validated against the user's usable groups and `GroupRatio`.

use std::sync::atomic::{AtomicU64, Ordering};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::Request,
    http::{Method, StatusCode, header},
    middleware,
    response::Response,
    routing::{get, post},
};
use newapi_identity::tokens::mask_token_key;
use newapi_server::{AppState, auth::user_auth, token_http};
use newapi_storage::Database;
use serde_json::{Value, json};
use sqlx::{
    ConnectOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::SqlitePoolOptions,
};
use tower::ServiceExt;

static NEXT: AtomicU64 = AtomicU64::new(0);

const SECRET: &str = "token-routes-fixture-secret";
const USER_A: i64 = 101;
const USER_B: i64 = 102;
const CACHE_CONTROL_VALUE: &str = "no-store, no-cache, must-revalidate, private, max-age=0";

const SQLITE_USERS: &str = r#"CREATE TABLE users (
    id BIGINT PRIMARY KEY, username TEXT, display_name TEXT,
    role BIGINT, status BIGINT, email TEXT, github_id TEXT, discord_id TEXT,
    oidc_id TEXT, wechat_id TEXT, telegram_id TEXT, "group" TEXT,
    quota BIGINT, used_quota BIGINT, request_count BIGINT, aff_code TEXT,
    aff_count BIGINT, aff_quota BIGINT, aff_history BIGINT, inviter_id BIGINT,
    linux_do_id TEXT, setting TEXT, stripe_customer TEXT, auth_version BIGINT,
    access_token TEXT, deleted_at TIMESTAMP
)"#;

const POSTGRES_USERS: &str = SQLITE_USERS;

const SQLITE_TOKENS: &str = r#"CREATE TABLE tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id BIGINT NOT NULL,
    "key" TEXT NOT NULL UNIQUE,
    status INTEGER NOT NULL DEFAULT 1,
    name TEXT NOT NULL DEFAULT '',
    created_time BIGINT NOT NULL DEFAULT 0,
    accessed_time BIGINT NOT NULL DEFAULT 0,
    expired_time BIGINT NOT NULL DEFAULT -1,
    remain_quota BIGINT NOT NULL DEFAULT 0,
    used_quota BIGINT NOT NULL DEFAULT 0,
    unlimited_quota INTEGER NOT NULL DEFAULT 0,
    model_limits_enabled INTEGER NOT NULL DEFAULT 0,
    model_limits TEXT NOT NULL DEFAULT '',
    allow_ips TEXT,
    "group" TEXT NOT NULL DEFAULT '',
    cross_group_retry INTEGER NOT NULL DEFAULT 0,
    auto_groups TEXT NOT NULL DEFAULT '',
    deleted_at TIMESTAMP
)"#;

const POSTGRES_TOKENS: &str = r#"CREATE TABLE tokens (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    "key" VARCHAR(128) NOT NULL UNIQUE,
    status INTEGER NOT NULL DEFAULT 1,
    name TEXT NOT NULL DEFAULT '',
    created_time BIGINT NOT NULL DEFAULT 0,
    accessed_time BIGINT NOT NULL DEFAULT 0,
    expired_time BIGINT NOT NULL DEFAULT -1,
    remain_quota BIGINT NOT NULL DEFAULT 0,
    used_quota BIGINT NOT NULL DEFAULT 0,
    unlimited_quota BOOLEAN NOT NULL DEFAULT FALSE,
    model_limits_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    model_limits TEXT NOT NULL DEFAULT '',
    allow_ips TEXT,
    "group" TEXT NOT NULL DEFAULT '',
    cross_group_retry BOOLEAN NOT NULL DEFAULT FALSE,
    auto_groups TEXT NOT NULL DEFAULT '',
    deleted_at TIMESTAMP
)"#;

const OPTIONS: &str = r#"CREATE TABLE options (
    "key" TEXT PRIMARY KEY, "value" TEXT
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
            "/api/token/",
            get(token_http::list_tokens)
                .post(token_http::add_token)
                .put(token_http::update_token),
        )
        .route("/api/token/search", get(token_http::search_tokens))
        .route("/api/token/auto-groups", get(token_http::token_auto_groups))
        .route(
            "/api/token/{id}",
            get(token_http::get_token).delete(token_http::delete_token),
        )
        .route("/api/token/{id}/key", post(token_http::get_token_key))
        .route_layer(middleware::from_fn_with_state(state.clone(), user_auth))
        .with_state(state)
}

fn state(db: &Database) -> AppState {
    // PAT authentication uses only the database; no SessionAuth is needed.
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

async fn setup(db: &Database) {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query(SQLITE_USERS)
                .execute(pool)
                .await
                .expect("users");
            sqlx::query(SQLITE_TOKENS)
                .execute(pool)
                .await
                .expect("tokens");
        }
        Database::Postgres(pool) => {
            sqlx::query(POSTGRES_USERS)
                .execute(pool)
                .await
                .expect("users");
            sqlx::query(POSTGRES_TOKENS)
                .execute(pool)
                .await
                .expect("tokens");
        }
    }
    exec(db, OPTIONS).await;
}

async fn reset(db: &Database) {
    exec(db, "DELETE FROM tokens").await;
    exec(db, "DELETE FROM users").await;
    exec(db, "DELETE FROM options").await;
}

async fn seed_user(db: &Database, id: i64, group: &str, pat: &str) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO users
                (id,username,display_name,role,status,"group",auth_version,access_token)
                VALUES ($1,$2,'Fixture',1,1,$3,1,$4)"#,
        )
        .bind(id)
        .bind(format!("user{id}"))
        .bind(group)
        .bind(pat)
        .execute(pool)
        .await
        .expect("seed user");
    });
}

async fn set_option(db: &Database, key: &str, value: &str) {
    backend!(db, pool, {
        sqlx::query(r#"INSERT INTO options ("key", "value") VALUES ($1, $2)"#)
            .bind(key)
            .bind(value)
            .execute(pool)
            .await
            .expect("seed option");
    });
}

#[allow(clippy::too_many_arguments)]
async fn seed_token(
    db: &Database,
    user_id: i64,
    key: &str,
    name: &str,
    status: i64,
    expired_time: i64,
    remain_quota: i64,
    unlimited_quota: bool,
    group: &str,
    auto_groups: &str,
) -> i64 {
    backend!(db, pool, {
        sqlx::query_scalar::<_, i64>(
            r#"INSERT INTO tokens
                (user_id,"key",status,name,created_time,accessed_time,expired_time,
                 remain_quota,used_quota,unlimited_quota,model_limits_enabled,
                 model_limits,allow_ips,"group",cross_group_retry,auto_groups)
                VALUES ($1,$2,$3,$4,1,1,$5,$6,0,$7,0,'','',$8,0,$9)
                RETURNING CAST(id AS BIGINT)"#,
        )
        .bind(user_id)
        .bind(key)
        .bind(status)
        .bind(name)
        .bind(expired_time)
        .bind(remain_quota)
        .bind(unlimited_quota)
        .bind(group)
        .bind(auto_groups)
        .fetch_one(pool)
        .await
        .expect("seed token")
    })
}

async fn stored_token(
    db: &Database,
    id: i64,
) -> (String, i64, i64, i64, bool, String, i64, bool, String) {
    backend!(db, pool, {
        sqlx::query_as::<_, (String, i64, i64, i64, bool, String, i64, bool, String)>(
            r#"SELECT "key", CAST(status AS BIGINT), CAST(remain_quota AS BIGINT),
                      CAST(expired_time AS BIGINT), unlimited_quota, auto_groups,
                      CAST(used_quota AS BIGINT), cross_group_retry, "group"
               FROM tokens WHERE id=$1"#,
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("stored token")
    })
}

async fn is_soft_deleted(db: &Database, id: i64) -> bool {
    backend!(db, pool, {
        sqlx::query_scalar::<_, bool>("SELECT deleted_at IS NOT NULL FROM tokens WHERE id=$1")
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("soft-delete state")
    })
}

async fn send_json(
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

fn auth(pat: &str) -> String {
    format!("Bearer {pat}")
}

fn translated(key: &str) -> String {
    newapi_i18n::translate("en", key, std::iter::empty::<(&str, &str)>())
}

fn translated_max(key: &str, max: i64) -> String {
    newapi_i18n::translate("en", key, [("Max", max.to_string())])
}

async fn assert_success(response: Response) -> Value {
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true), "{body}");
    assert_eq!(body["message"], json!(""));
    body
}

async fn assert_business_error(response: Response, expected: Option<String>) -> Value {
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false), "{body}");
    let message = body["message"].as_str().expect("translated message");
    assert!(!message.is_empty());
    if let Some(expected) = expected {
        assert_eq!(message, expected);
    }
    body
}

fn assert_disable_cache(response: &Response) {
    let headers = response.headers();
    assert_eq!(headers[header::CACHE_CONTROL], CACHE_CONTROL_VALUE);
    assert_eq!(headers[header::PRAGMA], "no-cache");
    assert_eq!(headers[header::EXPIRES], "0");
}

fn key_for(prefix: &str, value: i64) -> String {
    // 48 alphanumeric characters, matching `GenerateKey`.
    format!("{prefix}{value:0>46}")
}

fn assert_no_raw_key(body: &Value, raw_key: &str) {
    assert!(
        !body.to_string().contains(raw_key),
        "response leaked the raw token key: {body}"
    );
}

async fn run_contract(db: Database) {
    setup(&db).await;
    let app = state(&db);
    let pat_a = "pat-user-a";
    let pat_b = "pat-user-b";

    // Missing credential -> Go `ErrAuthTokenInvalid`.
    let response = send_json(&app, Method::GET, "/api/token/", None, None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = body_json(response).await;
    assert_eq!(body["code"], json!("AUTH_UNAUTHORIZED"));
    // `POST /:id/key` is behind UserAuth too; the middleware rejects first.
    let response = send_json(&app, Method::POST, "/api/token/1/key", None, None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(!response.headers().contains_key(header::CACHE_CONTROL));

    reset(&db).await;
    seed_user(&db, USER_A, "default", pat_a).await;
    seed_user(&db, USER_B, "default", pat_b).await;
    let auth_a = auth(pat_a);
    let auth_b = auth(pat_b);

    // Empty list.
    let body = assert_success(
        send_json(&app, Method::GET, "/api/token/", Some(&auth_a), None).await,
    )
    .await;
    assert_eq!(body["data"]["page"], json!(1));
    assert_eq!(body["data"]["page_size"], json!(10));
    assert_eq!(body["data"]["total"], json!(0));
    assert_eq!(body["data"]["items"], json!([]));

    // Create a finite-quota token through the display-currency field.
    let create = json!({
        "name": "first",
        "expired_time": -1,
        "remain_quota_display": 1.5,
        "unlimited_quota": false,
        "model_limits_enabled": false,
        "model_limits": "",
        "group": "default",
    });
    let body = assert_success(
        send_json(
            &app,
            Method::POST,
            "/api/token/",
            Some(&auth_a),
            Some(&create),
        )
        .await,
    )
    .await;
    assert!(body.get("data").is_none(), "AddToken has no data field");
    let first_id: i64 = backend!(&db, pool, {
        sqlx::query_scalar("SELECT CAST(id AS BIGINT) FROM tokens WHERE name='first'")
            .fetch_one(pool)
            .await
            .expect("first token id")
    });
    let (raw_key, status, remain, expired, unlimited, auto_groups, _, _, group) =
        stored_token(&db, first_id).await;
    assert_eq!(raw_key.len(), 48);
    assert_eq!(status, 1);
    assert_eq!(remain, 750_000, "1.5 * QuotaPerUnit, rounded");
    assert_eq!(expired, -1);
    assert!(!unlimited);
    assert_eq!(auto_groups, "");
    assert_eq!(group, "default");

    // A missing `expired_time` becomes the column default `-1`; unlimited
    // tokens persist the submitted raw `remain_quota` and ignore the display
    // conversion.
    let body = assert_success(
        send_json(
            &app,
            Method::POST,
            "/api/token/",
            Some(&auth_a),
            Some(&json!({
                "name": "unlimited",
                "unlimited_quota": true,
                "remain_quota": 7,
                "remain_quota_display": 999,
            })),
        )
        .await,
    )
    .await;
    assert!(body.get("data").is_none());
    let unlimited_id: i64 = backend!(&db, pool, {
        sqlx::query_scalar("SELECT CAST(id AS BIGINT) FROM tokens WHERE name='unlimited'")
            .fetch_one(pool)
            .await
            .expect("unlimited token id")
    });
    let (_, _, unlimited_remain, unlimited_expired, unlimited_flag, _, _, _, _) =
        stored_token(&db, unlimited_id).await;
    assert_eq!(unlimited_remain, 7);
    assert_eq!(unlimited_expired, -1);
    assert!(unlimited_flag);

    // Negative and oversized quotas.
    assert_business_error(
        send_json(
            &app,
            Method::POST,
            "/api/token/",
            Some(&auth_a),
            Some(&json!({"name": "negative", "remain_quota_display": -1})),
        )
        .await,
        Some(translated("token.quota_negative")),
    )
    .await;
    assert_business_error(
        send_json(
            &app,
            Method::POST,
            "/api/token/",
            Some(&auth_a),
            Some(&json!({
                "name": "n".repeat(51),
                "remain_quota_display": 0,
            })),
        )
        .await,
        Some(translated("token.name_too_long")),
    )
    .await;

    // List pagination: newest first, masked keys, aliases and caps.
    let third_key = key_for("third", 3);
    let third_id = seed_token(
        &db,
        USER_A,
        &third_key,
        "third",
        1,
        -1,
        10,
        true,
        "default",
        "",
    )
    .await;
    let body = assert_success(
        send_json(
            &app,
            Method::GET,
            "/api/token/?p=1&page_size=2",
            Some(&auth_a),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["total"], json!(3));
    assert_eq!(body["data"]["items"].as_array().unwrap().len(), 2);
    assert_eq!(body["data"]["items"][0]["id"], json!(third_id));
    assert_eq!(
        body["data"]["items"][0]["key"],
        json!(mask_token_key(&third_key))
    );
    assert_no_raw_key(&body, &third_key);
    // Alias and page-size cap.
    let body = assert_success(
        send_json(
            &app,
            Method::GET,
            "/api/token/?page_size=1000",
            Some(&auth_a),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["page_size"], json!(100));
    assert_eq!(body["data"]["items"].as_array().unwrap().len(), 3);
    let body = assert_success(
        send_json(&app, Method::GET, "/api/token/?size=2", Some(&auth_a), None).await,
    )
    .await;
    assert_eq!(body["data"]["page_size"], json!(2));
    // Page 0 falls back to 1; page_size 0 falls back to 10.
    let body = assert_success(
        send_json(
            &app,
            Method::GET,
            "/api/token/?p=0&page_size=0",
            Some(&auth_a),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["page"], json!(1));
    assert_eq!(body["data"]["page_size"], json!(10));
    // Beyond the last page: empty items, total unchanged.
    let body = assert_success(
        send_json(
            &app,
            Method::GET,
            "/api/token/?p=99&page_size=10",
            Some(&auth_a),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["total"], json!(3));
    assert_eq!(body["data"]["items"], json!([]));

    // Get by id masks the key.
    let body = assert_success(
        send_json(
            &app,
            Method::GET,
            &format!("/api/token/{first_id}"),
            Some(&auth_a),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["id"], json!(first_id));
    assert_eq!(body["data"]["key"], json!(mask_token_key(&raw_key)));
    assert_no_raw_key(&body, &raw_key);

    // Cross-user reads are a business failure, not a 403/404.
    let body = assert_business_error(
        send_json(
            &app,
            Method::GET,
            &format!("/api/token/{first_id}"),
            Some(&auth_b),
            None,
        )
        .await,
        Some(translated("common.not_found")),
    )
    .await;
    assert_no_raw_key(&body, &raw_key);
    let response = send_json(
        &app,
        Method::POST,
        &format!("/api/token/{first_id}/key"),
        Some(&auth_b),
        None,
    )
    .await;
    let body = assert_business_error(response, None).await;
    assert_no_raw_key(&body, &raw_key);
    // Cross-user delete leaves the row intact.
    let body = assert_business_error(
        send_json(
            &app,
            Method::DELETE,
            &format!("/api/token/{first_id}"),
            Some(&auth_b),
            None,
        )
        .await,
        None,
    )
    .await;
    assert_no_raw_key(&body, &raw_key);
    assert!(!is_soft_deleted(&db, first_id).await);

    // Full update: every listed field is replaced; status is kept.
    let body = assert_success(
        send_json(
            &app,
            Method::PUT,
            "/api/token/",
            Some(&auth_a),
            Some(&json!({
                "id": first_id,
                "name": "renamed",
                "expired_time": 1234567890,
                "remain_quota": 42,
                "unlimited_quota": false,
                "model_limits_enabled": true,
                "model_limits": "gpt-4",
                "allow_ips": "1.2.3.4",
                "group": "default",
                "cross_group_retry": true,
            })),
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["name"], json!("renamed"));
    assert_eq!(body["data"]["remain_quota"], json!(42));
    assert_eq!(body["data"]["model_limits"], json!("gpt-4"));
    assert_eq!(body["data"]["allow_ips"], json!("1.2.3.4"));
    assert_eq!(body["data"]["expired_time"], json!(1234567890));
    assert_eq!(body["data"]["key"], json!(mask_token_key(&raw_key)));
    assert_no_raw_key(&body, &raw_key);
    let (_, stored_status, stored_remain, _, _, _, _, stored_cross, _) =
        stored_token(&db, first_id).await;
    assert_eq!(stored_status, 1, "full update keeps the stored status");
    assert_eq!(stored_remain, 42);
    assert!(!stored_cross, "non-auto group clears cross-group retry");

    // Status-only update changes nothing else.
    let body = assert_success(
        send_json(
            &app,
            Method::PUT,
            "/api/token/?status_only=1",
            Some(&auth_a),
            Some(&json!({"id": first_id, "status": 2})),
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["status"], json!(2));
    assert_eq!(body["data"]["name"], json!("renamed"));
    let (_, stored_status, _, _, _, _, _, _, _) = stored_token(&db, first_id).await;
    assert_eq!(stored_status, 2);

    // Enabling an expired/exhausted token is rejected.
    let expired_key = key_for("expired", 4);
    let expired_id = seed_token(
        &db,
        USER_A,
        &expired_key,
        "expired",
        3,
        100,
        10,
        false,
        "default",
        "",
    )
    .await;
    assert_business_error(
        send_json(
            &app,
            Method::PUT,
            "/api/token/",
            Some(&auth_a),
            Some(&json!({"id": expired_id, "status": 1})),
        )
        .await,
        Some(translated("token.expired_cannot_enable")),
    )
    .await;
    let exhausted_key = key_for("exhausted", 5);
    let exhausted_id = seed_token(
        &db,
        USER_A,
        &exhausted_key,
        "exhausted",
        4,
        -1,
        0,
        false,
        "default",
        "",
    )
    .await;
    assert_business_error(
        send_json(
            &app,
            Method::PUT,
            "/api/token/",
            Some(&auth_a),
            Some(&json!({"id": exhausted_id, "status": 1})),
        )
        .await,
        Some(translated("token.exhausted_cannot_enable")),
    )
    .await;

    // Quota validation on update uses the raw `remain_quota`.
    assert_business_error(
        send_json(
            &app,
            Method::PUT,
            "/api/token/",
            Some(&auth_a),
            Some(&json!({"id": first_id, "remain_quota": -1})),
        )
        .await,
        Some(translated("token.quota_negative")),
    )
    .await;
    let max_quota = i64::from(i32::MAX);
    assert_business_error(
        send_json(
            &app,
            Method::PUT,
            "/api/token/",
            Some(&auth_a),
            Some(&json!({"id": first_id, "remain_quota": max_quota + 1})),
        )
        .await,
        Some(translated_max("token.quota_exceed_max", max_quota)),
    )
    .await;

    // Soft delete removes the token from list/get.
    assert_success(
        send_json(
            &app,
            Method::DELETE,
            &format!("/api/token/{third_id}"),
            Some(&auth_a),
            None,
        )
        .await,
    )
    .await;
    assert!(is_soft_deleted(&db, third_id).await);
    assert_business_error(
        send_json(
            &app,
            Method::GET,
            &format!("/api/token/{third_id}"),
            Some(&auth_a),
            None,
        )
        .await,
        Some(translated("common.not_found")),
    )
    .await;
    let body = assert_success(
        send_json(&app, Method::GET, "/api/token/", Some(&auth_a), None).await,
    )
    .await;
    assert!(!body["data"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["id"] == json!(third_id)));

    // `/key` returns the full key and the three no-cache headers. Malformed
    // ids still carry the headers because the middleware/handler wrote them.
    let response = send_json(
        &app,
        Method::POST,
        &format!("/api/token/{first_id}/key"),
        Some(&auth_a),
        None,
    )
    .await;
    assert_disable_cache(&response);
    let body = assert_success(response).await;
    assert_eq!(body["data"]["key"], json!(raw_key));
    let response = send_json(
        &app,
        Method::POST,
        "/api/token/not-a-number/key",
        Some(&auth_a),
        None,
    )
    .await;
    assert_disable_cache(&response);
    assert_business_error(response, None).await;

    // Search: name, key, `sk-` stripping, wildcard validation.
    reset(&db).await;
    seed_user(&db, USER_A, "default", pat_a).await;
    seed_user(&db, USER_B, "default", pat_b).await;
    let alpha_key = key_for("alpha", 6);
    let beta_key = key_for("beta", 7);
    let alpha_id = seed_token(
        &db,
        USER_A,
        &alpha_key,
        "alpha one",
        1,
        -1,
        0,
        true,
        "default",
        "",
    )
    .await;
    seed_token(
        &db,
        USER_A,
        &beta_key,
        "beta",
        1,
        -1,
        0,
        true,
        "default",
        "",
    )
    .await;
    seed_token(
        &db,
        USER_B,
        &key_for("other", 8),
        "alpha other",
        1,
        -1,
        0,
        true,
        "default",
        "",
    )
    .await;
    let body = assert_success(
        send_json(
            &app,
            Method::GET,
            "/api/token/search?keyword=alpha",
            Some(&auth_a),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["total"], json!(1));
    assert_eq!(body["data"]["items"][0]["id"], json!(alpha_id));
    assert_eq!(
        body["data"]["items"][0]["key"],
        json!(mask_token_key(&alpha_key))
    );
    let body = assert_success(
        send_json(
            &app,
            Method::GET,
            &format!("/api/token/search?token=sk-{alpha_key}"),
            Some(&auth_a),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["total"], json!(1));
    let body = assert_success(
        send_json(
            &app,
            Method::GET,
            "/api/token/search?keyword=al%25",
            Some(&auth_a),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["total"], json!(1));
    assert_business_error(
        send_json(
            &app,
            Method::GET,
            "/api/token/search?keyword=%25%25",
            Some(&auth_a),
            None,
        )
        .await,
        Some(translated("token.search_consecutive_wildcard")),
    )
    .await;
    assert_business_error(
        send_json(
            &app,
            Method::GET,
            "/api/token/search?keyword=a%25",
            Some(&auth_a),
            None,
        )
        .await,
        Some(translated("token.search_keyword_too_short")),
    )
    .await;
    // Go measures the fuzzy minimum in bytes, so one 3-byte CJK character
    // followed by `%` passes validation (and simply matches nothing here).
    let body = assert_success(
        send_json(
            &app,
            Method::GET,
            "/api/token/search?keyword=%E9%95%BF%25",
            Some(&auth_a),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["total"], json!(0));

    // Auto-group validation and the auto-groups endpoint.
    reset(&db).await;
    seed_user(&db, USER_A, "default", pat_a).await;
    set_option(&db, "GroupRatio", r#"{"default":1,"vip":2}"#).await;
    set_option(
        &db,
        "UserUsableGroups",
        r#"{"default":"Default","vip":"VIP"}"#,
    )
    .await;
    set_option(&db, "AutoGroups", r#"["vip","missing","default"]"#).await;
    set_option(&db, "MaxTokenAutoGroups", "2").await;
    let body = assert_success(
        send_json(
            &app,
            Method::GET,
            "/api/token/auto-groups",
            Some(&auth_a),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["groups"], json!(["vip", "default"]));
    assert_eq!(body["data"]["max_count"], json!(2));
    // Too many (checked before membership), duplicate, and unavailable.
    assert_business_error(
        send_json(
            &app,
            Method::POST,
            "/api/token/",
            Some(&auth_a),
            Some(&json!({
                "name": "too-many",
                "group": "auto",
                "auto_groups": ["default", "vip", "x"],
            })),
        )
        .await,
        None,
    )
    .await;
    assert_business_error(
        send_json(
            &app,
            Method::POST,
            "/api/token/",
            Some(&auth_a),
            Some(&json!({
                "name": "duplicate",
                "group": "auto",
                "auto_groups": ["default", "default"],
            })),
        )
        .await,
        None,
    )
    .await;
    assert_business_error(
        send_json(
            &app,
            Method::POST,
            "/api/token/",
            Some(&auth_a),
            Some(&json!({
                "name": "invalid",
                "group": "auto",
                "auto_groups": ["missing", "default"],
            })),
        )
        .await,
        None,
    )
    .await;
    // Ordered snapshot persists and is echoed as an array.
    let body = assert_success(
        send_json(
            &app,
            Method::POST,
            "/api/token/",
            Some(&auth_a),
            Some(&json!({
                "name": "auto-ok",
                "group": "auto",
                "cross_group_retry": true,
                "auto_groups": ["vip", "default"],
            })),
        )
        .await,
    )
    .await;
    assert!(body.get("data").is_none());
    let auto_id: i64 = backend!(&db, pool, {
        sqlx::query_scalar("SELECT CAST(id AS BIGINT) FROM tokens WHERE name='auto-ok'")
            .fetch_one(pool)
            .await
            .expect("auto token id")
    });
    let (_, _, _, _, _, auto_groups, _, cross, _) = stored_token(&db, auto_id).await;
    assert_eq!(auto_groups, r#"["vip","default"]"#);
    assert!(cross);
    let body = assert_success(
        send_json(
            &app,
            Method::GET,
            &format!("/api/token/{auto_id}"),
            Some(&auth_a),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["auto_groups"], json!(["vip", "default"]));

    // Update tri-state: omitted preserves; `null` clears.
    assert_success(
        send_json(
            &app,
            Method::PUT,
            "/api/token/",
            Some(&auth_a),
            Some(&json!({
                "id": auto_id,
                "name": "auto-ok",
                "status": 1,
                "unlimited_quota": true,
                "group": "auto",
                "cross_group_retry": true,
            })),
        )
        .await,
    )
    .await;
    let (_, _, _, _, _, auto_groups, _, _, _) = stored_token(&db, auto_id).await;
    assert_eq!(auto_groups, r#"["vip","default"]"#);
    assert_success(
        send_json(
            &app,
            Method::PUT,
            "/api/token/",
            Some(&auth_a),
            Some(&json!({
                "id": auto_id,
                "name": "auto-ok",
                "status": 1,
                "unlimited_quota": true,
                "group": "auto",
                "auto_groups": null,
            })),
        )
        .await,
    )
    .await;
    let (_, _, _, _, _, auto_groups, _, _, _) = stored_token(&db, auto_id).await;
    assert_eq!(auto_groups, "");

    // A non-auto group accepts any group string (Go does not validate it)
    // and discards auto-group state.
    let body = assert_success(
        send_json(
            &app,
            Method::POST,
            "/api/token/",
            Some(&auth_a),
            Some(&json!({
                "name": "non-auto",
                "group": "not-configured",
                "auto_groups": ["missing"],
                "cross_group_retry": true,
            })),
        )
        .await,
    )
    .await;
    assert!(body.get("data").is_none());
    let non_auto_id: i64 = backend!(&db, pool, {
        sqlx::query_scalar("SELECT CAST(id AS BIGINT) FROM tokens WHERE name='non-auto'")
            .fetch_one(pool)
            .await
            .expect("non-auto token id")
    });
    let (_, _, _, _, _, auto_groups, _, cross, group) = stored_token(&db, non_auto_id).await;
    assert_eq!(auto_groups, "");
    assert!(!cross);
    assert_eq!(group, "not-configured");

    // Per-user token limit from `token_setting.max_user_tokens`.
    reset(&db).await;
    seed_user(&db, USER_A, "default", pat_a).await;
    set_option(&db, "token_setting.max_user_tokens", "1").await;
    seed_token(
        &db,
        USER_A,
        &key_for("limit", 9),
        "limit",
        1,
        -1,
        0,
        true,
        "default",
        "",
    )
    .await;
    assert_business_error(
        send_json(
            &app,
            Method::POST,
            "/api/token/",
            Some(&auth_a),
            Some(&json!({"name": "overflow"})),
        )
        .await,
        None,
    )
    .await;

    // Invalid JSON is a business failure.
    let response = router(app.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/token/")
                .header(header::AUTHORIZATION, &auth_a)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{not-json"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_business_error(response, Some(translated("common.invalid_params"))).await;
}

#[tokio::test]
async fn sqlite_token_routes_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    run_contract(Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn postgres_token_routes_contract() {
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
        "token_routes_{}_{}",
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
