//! HTTP contracts for `GET /api/user/self` and `GET /api/user/token`.
//!
//! Runs only in remote CI. Every scenario uses an isolated synthetic fixture
//! (in-memory SQLite or an isolated PostgreSQL schema); no service is started.
//! The PostgreSQL test is not skipped when `TEST_POSTGRES_DSN` is present.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode, header},
    middleware,
    response::Response,
    routing::get,
};
use newapi_config::SessionCookieSettings;
use newapi_identity::{
    AuthIdentity,
    auth_session::{AuthFence, SessionAuth},
    crypto::AuthKeys,
    sessions::NoCache,
};
use newapi_server::{AppState, auth::user_auth, self_http};
use newapi_storage::Database;
use serde_json::{Value, json};
use sqlx::{
    ConnectOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::SqlitePoolOptions,
};
use tower::ServiceExt;

static NEXT: AtomicU64 = AtomicU64::new(0);

const SECRET: &str = "self-routes-fixture-secret";
const USER_ID: i64 = 17;
const CACHE_CONTROL_VALUE: &str = "no-store, no-cache, must-revalidate, private, max-age=0";

// id allows NULL in other fixtures; here every selected column exists so the
// public profile projection is exercised end to end.
const USERS: &str = r#"CREATE TABLE users (
    id INTEGER PRIMARY KEY, username TEXT, display_name TEXT,
    role INTEGER, status INTEGER, email TEXT, github_id TEXT, discord_id TEXT,
    oidc_id TEXT, wechat_id TEXT, telegram_id TEXT, "group" TEXT,
    quota INTEGER, used_quota INTEGER, request_count INTEGER, aff_code TEXT,
    aff_count INTEGER, aff_quota INTEGER, aff_history INTEGER, inviter_id INTEGER,
    linux_do_id TEXT, setting TEXT, stripe_customer TEXT, auth_version BIGINT,
    access_token TEXT, deleted_at TIMESTAMP
)"#;

const SESSIONS: &str = r#"CREATE TABLE user_sessions (
    sid VARCHAR(64) PRIMARY KEY, user_id INTEGER NOT NULL,
    version BIGINT NOT NULL DEFAULT 1, user_auth_version BIGINT NOT NULL,
    status VARCHAR(16) NOT NULL, refresh_hash CHAR(64) NOT NULL,
    previous_refresh_hash VARCHAR(64), previous_valid_until BIGINT NOT NULL DEFAULT 0,
    login_method VARCHAR(32) NOT NULL, ip VARCHAR(64), user_agent TEXT,
    created_at BIGINT, last_active_at BIGINT NOT NULL, expires_at BIGINT NOT NULL,
    revoked_at BIGINT NOT NULL DEFAULT 0, revoked_reason VARCHAR(64)
)"#;

const CASBIN: &str = "CREATE TABLE casbin_rule (
    id INTEGER PRIMARY KEY, ptype TEXT, v0 TEXT, v1 TEXT, v2 TEXT, v3 TEXT,
    v4 TEXT, v5 TEXT
)";

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

fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/user/self", get(self_http::self_user))
        .route("/api/user/token", get(self_http::access_token))
        .route_layer(middleware::from_fn_with_state(state.clone(), user_auth))
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
}

async fn exec(db: &Database, statement: &'static str) {
    backend!(db, pool, {
        sqlx::query(statement)
            .execute(pool)
            .await
            .expect("fixture statement");
    });
}

async fn reset(db: &Database) {
    exec(db, "DELETE FROM user_sessions").await;
    exec(db, "DELETE FROM users").await;
}

async fn seed_user(db: &Database, role: i64, status: i64, auth_version: i64, pat: Option<&str>) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO users
                (id,username,display_name,role,status,"group",auth_version,access_token)
                VALUES ($1,$2,$3,$4,$5,'default',$6,$7)"#,
        )
        .bind(USER_ID)
        .bind("fixture")
        .bind("Fixture")
        .bind(role)
        .bind(status)
        .bind(auth_version)
        .bind(pat)
        .execute(pool)
        .await
        .expect("seed user");
    });
}

async fn seed_session(db: &Database, sid: &str, uv: i64, sv: i64, at: i64) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO user_sessions
                (sid,user_id,version,user_auth_version,status,refresh_hash,
                 previous_refresh_hash,previous_valid_until,login_method,ip,
                 user_agent,created_at,last_active_at,expires_at,revoked_at,revoked_reason)
                VALUES ($1,$2,$3,$4,'active','fixture-hash',NULL,0,'password','',
                        '',$5,$5,$6,0,'')"#,
        )
        .bind(sid)
        .bind(USER_ID)
        .bind(sv)
        .bind(uv)
        .bind(at)
        .bind(at + 3600)
        .execute(pool)
        .await
        .expect("seed session");
    });
}

fn jwt(sid: &str, uv: i64, sv: i64, issued_at: i64) -> String {
    AuthKeys::new(SECRET)
        .issue_access(
            &AuthIdentity {
                user_id: USER_ID,
                sid: sid.to_owned(),
                user_auth_version: uv,
                session_version: sv,
            },
            issued_at,
        )
        .expect("issue access token")
        .token
        .expose_secret()
        .to_owned()
}

async fn send(state: &AppState, path: &str, authorization: Option<&str>) -> Response {
    let mut builder = Request::builder().method("GET").uri(path);
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

fn assert_disable_cache(headers: &HeaderMap) {
    assert_eq!(headers[header::CACHE_CONTROL], CACHE_CONTROL_VALUE);
    assert_eq!(headers[header::PRAGMA], "no-cache");
    assert_eq!(headers[header::EXPIRES], "0");
}

async fn assert_auth_failure(response: Response, status: StatusCode, code: &str) {
    assert_eq!(response.status(), status);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false));
    assert_eq!(body["code"], json!(code));
    assert!(
        body["message"]
            .as_str()
            .is_some_and(|message| !message.is_empty()),
        "fixed translated message expected"
    );
}

async fn run_contract(db: Database) {
    for ddl in [USERS, SESSIONS, CASBIN] {
        exec(&db, ddl).await;
    }
    let app = state(&db);

    // Missing credential: Go `ErrAuthTokenInvalid`, never a separate branch.
    let response = send(&app, "/api/user/self", None).await;
    assert_auth_failure(response, StatusCode::UNAUTHORIZED, "AUTH_UNAUTHORIZED").await;
    // UserAuth runs before DisableCache, so its rejection carries no cache headers.
    let response = send(&app, "/api/user/token", None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(!response.headers().contains_key(header::CACHE_CONTROL));

    // Dashboard JWT success.
    reset(&db).await;
    seed_user(&db, 1, 1, 1, None).await;
    let issued_at = now();
    seed_session(&db, "sid-jwt", 1, 1, issued_at).await;
    let token = jwt("sid-jwt", 1, 1, issued_at);
    let response = send(&app, "/api/user/self", Some(&format!("Bearer {token}"))).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true));
    assert_eq!(body["message"], json!(""));
    assert_eq!(body["data"]["id"], json!(USER_ID));
    assert_eq!(body["data"]["username"], json!("fixture"));
    assert_eq!(body["data"]["display_name"], json!("Fixture"));
    assert_eq!(body["data"]["role"], json!(1));
    assert_eq!(body["data"]["status"], json!(1));
    assert_eq!(body["data"]["group"], json!("default"));
    assert_eq!(body["data"]["quota_display"], json!(0.0));
    assert_eq!(body["data"]["sidebar_modules"], json!(""));
    assert_eq!(body["data"]["permissions"]["sidebar_settings"], json!(true));
    assert_eq!(body["data"]["permissions"]["sidebar_modules"]["admin"], json!(false));
    assert_eq!(
        body["data"]["permissions"]["admin_permissions"]["system"]["settings"],
        json!(false)
    );
    for forbidden in ["password", "access_token", "auth_version", "remark"] {
        assert!(body["data"].get(forbidden).is_none(), "{forbidden}");
    }

    // Personal access token success, with and without the Bearer scheme.
    reset(&db).await;
    seed_user(&db, 1, 1, 1, Some("pat-fixture-token")).await;
    for authorization in ["Bearer pat-fixture-token", "pat-fixture-token"] {
        let response = send(&app, "/api/user/self", Some(authorization)).await;
        assert_eq!(response.status(), StatusCode::OK, "{authorization}");
    }

    // Invalid, tampered and expired dashboard tokens are all 401.
    let response = send(&app, "/api/user/self", Some("Bearer not-a-jwt")).await;
    assert_auth_failure(response, StatusCode::UNAUTHORIZED, "AUTH_UNAUTHORIZED").await;
    // Flip the final signature character deterministically while keeping the
    // three-segment dashboard marker so this exercises the internal JWT path.
    let mut tampered = token;
    let last = tampered.pop().expect("non-empty JWT");
    tampered.push(if last == 'A' { 'B' } else { 'A' });
    let response = send(&app, "/api/user/self", Some(&format!("Bearer {tampered}"))).await;
    assert_auth_failure(response, StatusCode::UNAUTHORIZED, "AUTH_UNAUTHORIZED").await;
    let expired = jwt("sid-expired", 1, 1, issued_at - 2_000);
    let response = send(&app, "/api/user/self", Some(&format!("Bearer {expired}"))).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Disabled PAT: Go authHelper answers AUTH_USER_DISABLED.
    reset(&db).await;
    seed_user(&db, 1, 0, 1, Some("pat-disabled")).await;
    let response = send(&app, "/api/user/self", Some("Bearer pat-disabled")).await;
    assert_auth_failure(response, StatusCode::UNAUTHORIZED, "AUTH_USER_DISABLED").await;

    // Soft-deleted PAT: lookup filters deleted_at, so it is invalid credential.
    reset(&db).await;
    seed_user(&db, 1, 1, 1, Some("pat-deleted")).await;
    exec(
        &db,
        "UPDATE users SET deleted_at=CAST('2026-01-01 00:00:00' AS TIMESTAMP)",
    )
    .await;
    let response = send(&app, "/api/user/self", Some("Bearer pat-deleted")).await;
    assert_auth_failure(response, StatusCode::UNAUTHORIZED, "AUTH_UNAUTHORIZED").await;

    // Soft-deleted JWT: session validation rejects it as revoked.
    reset(&db).await;
    seed_user(&db, 1, 1, 1, None).await;
    let session_at = now();
    seed_session(&db, "sid-deleted", 1, 1, session_at).await;
    exec(
        &db,
        "UPDATE users SET deleted_at=CAST('2026-01-01 00:00:00' AS TIMESTAMP)",
    )
    .await;
    let deleted_jwt = jwt("sid-deleted", 1, 1, session_at);
    let response = send(&app, "/api/user/self", Some(&format!("Bearer {deleted_jwt}"))).await;
    assert_auth_failure(response, StatusCode::UNAUTHORIZED, "AUTH_SESSION_REVOKED").await;

    // Role below common user: Go authHelper's role gate is 403.
    reset(&db).await;
    seed_user(&db, 0, 1, 1, Some("pat-guest")).await;
    let response = send(&app, "/api/user/self", Some("Bearer pat-guest")).await;
    assert_auth_failure(response, StatusCode::FORBIDDEN, "AUTH_INSUFFICIENT_PRIVILEGE").await;

    // Token issuance rotates users.access_token and disables caching.
    reset(&db).await;
    seed_user(&db, 1, 1, 1, Some("pat-before")).await;
    let response = send(&app, "/api/user/token", Some("Bearer pat-before")).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_disable_cache(response.headers());
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true));
    assert_eq!(body["message"], json!(""));
    let issued = body["data"]
        .as_str()
        .expect("issued token string")
        .to_owned();
    assert_eq!(issued.len(), 32);
    let stored: Option<String> = backend!(&db, pool, {
        sqlx::query_scalar("SELECT access_token FROM users WHERE id=$1")
            .bind(USER_ID)
            .fetch_one(pool)
            .await
            .expect("stored access token")
    });
    assert_eq!(stored.as_deref(), Some(issued.as_str()));
    // The old PAT no longer authenticates; the new one does and rotates again.
    let response = send(&app, "/api/user/self", Some("Bearer pat-before")).await;
    assert_auth_failure(response, StatusCode::UNAUTHORIZED, "AUTH_UNAUTHORIZED").await;
    let response = send(&app, "/api/user/token", Some(&format!("Bearer {issued}"))).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_disable_cache(response.headers());
    let body = body_json(response).await;
    let rotated = body["data"].as_str().expect("rotated token string");
    assert_ne!(rotated, issued.as_str());

    // Policy read failure degrades to denied permissions, matching the login
    // path (Go's empty enforcer), not to an error response.
    reset(&db).await;
    seed_user(&db, 10, 1, 1, Some("pat-admin")).await;
    exec(&db, "DROP TABLE casbin_rule").await;
    let response = send(&app, "/api/user/self", Some("Bearer pat-admin")).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true));
    assert_eq!(
        body["data"]["permissions"],
        json!({
            "sidebar_settings": false,
            "sidebar_modules": {},
            "admin_permissions": {},
        })
    );
}

#[tokio::test]
async fn sqlite_self_routes_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    run_contract(Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn postgres_self_routes_contract() {
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
        "self_routes_{}_{}",
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
