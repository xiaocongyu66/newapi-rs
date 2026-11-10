//! HTTP contracts for the lenient `TryUserAuth` middleware.
//!
//! Runs only in remote CI. Every scenario uses an isolated synthetic fixture
//! (in-memory SQLite or an isolated PostgreSQL schema); no service is started.
//! The PostgreSQL test is skipped when `TEST_POSTGRES_DSN` is absent.
//!
//! Go oracle: `apps/api/internal/security/authenticate.go:77-89`
//! (`TryUserAuth` → `classifyDashboardCredential` → `writeDashboardAuthError`).
//! The middleware never authorizes: an unparsable or unmatched credential
//! continues the request anonymously, only a *present but failing* credential
//! aborts with the fixed dashboard error mapping.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::Request,
    http::{Method, StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
    routing::get,
};
use newapi_config::SessionCookieSettings;
use newapi_identity::{
    AuthIdentity,
    auth_session::{AuthFence, SessionAuth},
    crypto::AuthKeys,
    sessions::NoCache,
    user_auth::CredentialKind,
};
use newapi_security::client_ip::ProxyPolicy;
use newapi_server::{AppState, RateLimiter, auth::try_user_auth, limit::RateLimitSettings};
use newapi_storage::Database;
use serde_json::{Value, json};
use sqlx::{
    ConnectOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::SqlitePoolOptions,
};
use tower::ServiceExt;

static NEXT: AtomicU64 = AtomicU64::new(0);

const SECRET: &str = "try-user-auth-fixture-secret";
const USER_ID: i64 = 31;

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
        .route("/api/whoami", get(whoami))
        .route_layer(middleware::from_fn_with_state(state.clone(), try_user_auth))
        .with_state(state)
}

/// Echo endpoint: the middleware is the contract under test, so the handler
/// only reports whether an authenticated identity was attached.
async fn whoami(request: Request) -> Response {
    match request
        .extensions()
        .get::<newapi_server::auth::AuthenticatedUser>()
    {
        Some(user) => Json(json!({
            "mode": "authenticated",
            "user_id": user.0.user_id,
            "credential": match user.0.credential {
                CredentialKind::DashboardSession => "session",
                CredentialKind::PersonalAccessToken => "pat",
            },
            "status": user.0.status,
        }))
        .into_response(),
        None => Json(json!({"mode": "anonymous"})).into_response(),
    }
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
        .bind_transport(
            ProxyPolicy::parse_trusted_proxies(None).expect("proxy policy"),
            RateLimiter::memory(RateLimitSettings {
                enabled: false,
                requests: 1,
                window_seconds: 60,
            }),
            512,
        )
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0)
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

async fn exec(db: &Database, statement: &'static str) {
    backend!(db, pool, {
        sqlx::query(statement)
            .execute(pool)
            .await
            .expect("fixture statement");
    });
}

async fn setup(db: &Database) {
    backend!(db, pool, {
        sqlx::query(USERS).execute(pool).await.expect("users");
        sqlx::query(SESSIONS).execute(pool).await.expect("sessions");
    });
}

async fn reset(db: &Database) {
    exec(db, "DELETE FROM user_sessions").await;
    exec(db, "DELETE FROM users").await;
}

async fn seed_user(db: &Database, status: i64, pat: &str) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO users
                (id,username,display_name,role,status,"group",auth_version,access_token)
                VALUES ($1,'fixture','Fixture',1,$2,'default',1,$3)"#,
        )
        .bind(USER_ID)
        .bind(status)
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

async fn send(state: &AppState, authorization: Option<&str>) -> Response {
    let mut builder = Request::builder().method(Method::GET).uri("/api/whoami");
    if let Some(value) = authorization {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    router(state.clone())
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn send_duplicate_headers(state: &AppState) -> Response {
    // `Builder::header` appends, so two Authorization values reach the router.
    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/whoami")
        .header(header::AUTHORIZATION, "Bearer good-pat")
        .header(header::AUTHORIZATION, "Bearer other-pat")
        .body(Body::empty())
        .unwrap();
    router(state.clone()).oneshot(request).await.unwrap()
}

async fn body_json(response: Response) -> Value {
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body");
    serde_json::from_slice(&bytes).expect("response JSON")
}

async fn assert_dashboard_failure(
    response: Response,
    status: StatusCode,
    code: &str,
    message_key: &str,
) {
    assert_eq!(response.status(), status);
    let body = body_json(response).await;
    assert_eq!(body["success"], serde_json::json!(false));
    assert_eq!(body["code"], serde_json::json!(code));
    let message = newapi_i18n::translate("en", message_key, std::iter::empty::<(&str, &str)>());
    assert_eq!(body["message"], serde_json::json!(message));
}

async fn assert_authenticated(response: Response, credential: &str) {
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["mode"], serde_json::json!("authenticated"));
    assert_eq!(body["user_id"], serde_json::json!(USER_ID));
    assert_eq!(body["credential"], serde_json::json!(credential));
}

async fn assert_anonymous(response: Response) {
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["mode"], serde_json::json!("anonymous"));
}

async fn run_contract(db: &Database) {
    setup(db).await;

    // --- unmatched（authenticate.go:154-158）：无错误，匿名继续 ---

    // No credential at all.
    let response = send(&state(db), None).await;
    assert_anonymous(response).await;

    // Unparsable scheme: Go ParseBearerCredential yields (nil, false).
    for header in ["Basic pat", "Bearer a b", ""] {
        let response = send(&state(db), Some(header)).await;
        assert_anonymous(response).await;
    }

    // Unknown PAT (Go ValidateAccessToken: record not found → (nil, nil)): the
    // request continues without an identity instead of 401.
    let response = send(&state(db), Some("Bearer no-such-pat")).await;
    assert_anonymous(response).await;

    // PAT of a soft-deleted user: GORM's default scope hides the row, so the
    // PAT is unmatched as well.
    reset(db).await;
    seed_user(db, 1, "deleted-pat").await;
    exec(
        db,
        "UPDATE users SET deleted_at=CURRENT_TIMESTAMP WHERE access_token='deleted-pat'",
    )
    .await;
    let response = send(&state(db), Some("Bearer deleted-pat")).await;
    assert_anonymous(response).await;

    // --- PAT 分支（classifyDashboardCredential，authenticate.go:170-181） ---

    // Valid PAT attaches the identity without any status/role check.
    reset(db).await;
    seed_user(db, 1, "good-pat").await;
    let response = send(&state(db), Some("Bearer good-pat")).await;
    assert_authenticated(response, "pat").await;
    // A bare credential (no Bearer) is accepted too.
    let response = send(&state(db), Some("good-pat")).await;
    assert_authenticated(response, "pat").await;

    // Banned user's PAT still authenticates: TryUserAuth never checks status.
    reset(db).await;
    seed_user(db, 2, "banned-pat").await;
    let response = send(&state(db), Some("Bearer banned-pat")).await;
    assert_authenticated(response, "pat").await;
    let body = body_json(send(&state(db), Some("Bearer banned-pat")).await).await;
    assert_eq!(body["status"], serde_json::json!(2));

    // --- dashboard JWT 分支（authenticate.go:159-169 + ValidateLoginSession） ---

    // Valid session authenticates.
    reset(db).await;
    seed_user(db, 1, "unused-pat").await;
    let session_at = now();
    seed_session(db, "sid-ok", 1, 1, session_at).await;
    let token = jwt("sid-ok", 1, 1, session_at);
    let response = send(&state(db), Some(&format!("Bearer {token}"))).await;
    assert_authenticated(response, "session").await;
    // The bare JWT form is accepted like any single-field credential.
    let response = send(&state(db), Some(&token)).await;
    assert_authenticated(response, "session").await;

    // Expired JWT: Go's writeDashboardAuthError gives 401 AUTH_TOKEN_EXPIRED
    // with MsgAuthNotLoggedIn (authenticate.go:206-207); the message envelope
    // otherwise stays the same as the unauthorized classification.
    let token = jwt("sid-ok", 1, 1, session_at - 10_000);
    let response = send(&state(db), Some(&format!("Bearer {token}"))).await;
    assert_dashboard_failure(
        response,
        StatusCode::UNAUTHORIZED,
        "AUTH_TOKEN_EXPIRED",
        "auth.not_logged_in",
    )
    .await;

    // Bad signature: ErrAuthTokenInvalid → AUTH_UNAUTHORIZED.
    let foreign = AuthKeys::new("other-fixture-secret")
        .issue_access(
            &AuthIdentity {
                user_id: USER_ID,
                sid: "sid-ok".to_owned(),
                user_auth_version: 1,
                session_version: 1,
            },
            session_at,
        )
        .expect("issue foreign token")
        .token
        .expose_secret()
        .to_owned();
    let response = send(&state(db), Some(&format!("Bearer {foreign}"))).await;
    assert_dashboard_failure(
        response,
        StatusCode::UNAUTHORIZED,
        "AUTH_UNAUTHORIZED",
        "auth.access_token_invalid",
    )
    .await;

    // Session missing entirely: ErrLoginSessionRevoked → AUTH_SESSION_REVOKED.
    let token = jwt("sid-missing", 1, 1, session_at);
    let response = send(&state(db), Some(&format!("Bearer {token}"))).await;
    assert_dashboard_failure(
        response,
        StatusCode::UNAUTHORIZED,
        "AUTH_SESSION_REVOKED",
        "auth.not_logged_in",
    )
    .await;

    // Session version mismatch: same revoked classification.
    reset(db).await;
    seed_user(db, 1, "unused-pat").await;
    seed_session(db, "sid-rotated", 1, 2, session_at).await;
    let token = jwt("sid-rotated", 1, 1, session_at);
    let response = send(&state(db), Some(&format!("Bearer {token}"))).await;
    assert_dashboard_failure(
        response,
        StatusCode::UNAUTHORIZED,
        "AUTH_SESSION_REVOKED",
        "auth.not_logged_in",
    )
    .await;

    // Banned user with a live session: Go ValidateLoginSession maps
    // user.Status != enabled to ErrLoginSessionRevoked (authenticate.go:128-130).
    reset(db).await;
    seed_user(db, 2, "unused-pat").await;
    seed_session(db, "sid-banned", 1, 1, session_at).await;
    let token = jwt("sid-banned", 1, 1, session_at);
    let response = send(&state(db), Some(&format!("Bearer {token}"))).await;
    assert_dashboard_failure(
        response,
        StatusCode::UNAUTHORIZED,
        "AUTH_SESSION_REVOKED",
        "auth.not_logged_in",
    )
    .await;

    // User vanished after a valid session: gorm.ErrRecordNotFound shares the
    // revoked branch (writeDashboardAuthError authenticate.go:210-213).
    reset(db).await;
    seed_user(db, 1, "unused-pat").await;
    seed_session(db, "sid-gone", 1, 1, session_at).await;
    exec(db, "DELETE FROM users").await;
    let token = jwt("sid-gone", 1, 1, session_at);
    let response = send(&state(db), Some(&format!("Bearer {token}"))).await;
    assert_dashboard_failure(
        response,
        StatusCode::UNAUTHORIZED,
        "AUTH_SESSION_REVOKED",
        "auth.not_logged_in",
    )
    .await;

    // Note: a second Authorization header is rejected by this port's
    // parse_authorization stance (multiple → anonymous), while Go picks the
    // first value. Both keep the request running; only the attached identity
    // differs. Asserted here so the lenient promise survives: no 4xx.
    reset(db).await;
    seed_user(db, 1, "good-pat").await;
    let response = send_duplicate_headers(&state(db)).await;
    assert_eq!(response.status(), StatusCode::OK);

    reset(db).await;
}

#[tokio::test]
async fn sqlite_try_user_auth_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    run_contract(&Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn postgres_try_user_auth_contract() {
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
        "try_user_auth_routes_{}_{}",
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
    run_contract(&Database::Postgres(pool)).await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA \"{schema}\" CASCADE"
    )))
    .execute(&admin)
    .await
    .expect("drop isolated schema");
}
