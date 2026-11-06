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
