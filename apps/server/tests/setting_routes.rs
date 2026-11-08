//! HTTP contracts for `PUT /api/user/setting` (Go `UpdateUserSettingHandler`).
//!
//! Runs only in remote CI. Every scenario uses an isolated synthetic fixture
//! (in-memory SQLite or an isolated PostgreSQL schema); no service is started.
//! The PostgreSQL test is skipped when `TEST_POSTGRES_DSN` is absent.
//!
//! Go's branch order is part of the contract: each wrong field is a distinct
//! i18n key, so one generic rejection would not reproduce it. Assertions
//! therefore compare against `newapi_i18n::translate` rather than hard-coded
//! message text, which keeps the contract about *which* key a branch emits
//! instead of duplicating the catalog's wording.

use std::sync::atomic::{AtomicU64, Ordering};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode, header},
    middleware,
    response::Response,
    routing::put,
};
use newapi_identity::user_auth::{CredentialKind, UserAuthIdentity};
use newapi_server::{
    AppState,
    auth::{AuthenticatedUser, user_auth},
    setting_http,
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

const SECRET: &str = "setting-routes-fixture-secret";
const USER_ID: i64 = 17;
const ADMIN_ID: i64 = 18;

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
        .route("/api/user/setting", put(setting_http::update_user_setting))
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
            .expect("fixture statement");
    });
}

/// Seeds a user with an explicit role and stored setting.
async fn seed_user(
    db: &Database,
    user_id: i64,
    role: i64,
    pat: Option<&str>,
    setting: Option<&str>,
) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO users
                (id,username,display_name,role,status,"group",auth_version,
                 access_token,setting)
                VALUES ($1,'fixture','Fixture',$2,1,'default',1,$3,$4)"#,
        )
        .bind(user_id)
        .bind(role)
        .bind(pat)
        .bind(setting)
        .execute(pool)
        .await
        .expect("seed user");
    });
}

async fn stored_setting_of(db: &Database, user_id: i64) -> Option<String> {
    backend!(db, pool, {
        sqlx::query_scalar::<_, Option<String>>("SELECT setting FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(pool)
            .await
            .expect("stored setting")
    })
}

async fn set_setting(db: &Database, user_id: i64, setting: &str) {
    backend!(db, pool, {
        sqlx::query("UPDATE users SET setting = $1 WHERE id = $2")
            .bind(setting)
            .bind(user_id)
            .execute(pool)
            .await
            .expect("seed setting");
    });
}

async fn soft_delete_user(db: &Database, user_id: i64) {
    backend!(db, pool, {
        sqlx::query("UPDATE users SET deleted_at = CURRENT_TIMESTAMP WHERE id = $1")
            .bind(user_id)
            .execute(pool)
            .await
            .expect("soft delete user");
    });
}

async fn send(state: &AppState, authorization: Option<&str>, body: &str) -> Response {
    let mut builder = Request::builder()
        .method("PUT")
        .uri("/api/user/setting")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT_LANGUAGE, "en");
    if let Some(value) = authorization {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    router(state.clone())
        .oneshot(builder.body(Body::from(body.to_owned())).unwrap())
        .await
        .unwrap()
}

/// Sends with a forged authenticated identity so the soft-deleted row branch
/// is reachable; the real middleware would reject the same PAT earlier.
async fn send_authenticated(state: &AppState, user_id: i64, body: &str) -> Response {
    setting_http::update_user_setting(
        axum::extract::State(state.clone()),
        axum::extract::Extension(AuthenticatedUser(UserAuthIdentity {
            user_id,
            username: "fixture".to_owned(),
            role: 1,
            status: 1,
            auth_version: 1,
            group: "default".to_owned(),
            credential: CredentialKind::PersonalAccessToken,
        })),
        HeaderMap::new(),
        axum::body::Bytes::from(body.to_owned()),
    )
    .await
}

async fn body_json(response: Response) -> Value {
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body");
    serde_json::from_slice(&bytes).expect("response JSON")
}

fn translated(key: &str) -> String {
    newapi_i18n::translate("en", key, std::iter::empty::<(&str, &str)>())
}

/// Go `CtxApiSuccessI18n`: the translated message plus an explicit null `data`.
fn assert_saved() -> Value {
    json!({"success": true, "message": translated("setting.saved"), "data": null})
}

fn assert_rejected(key: &str) -> Value {
    json!({"success": false, "message": translated(key)})
}

async fn run_contract(db: Database) {
    exec(&db, USERS).await;
    let app = state(&db);

    // Go `UserAuth` guards the route: absent and invalid credentials are 401.
    let response = send(&app, None, r#"{"notify_type":"email"}"#).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = send(
        &app,
        Some("Bearer not-a-token"),
        r#"{"notify_type":"email"}"#,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    seed_user(&db, USER_ID, 1, Some("pat-setting"), None).await;
    let authorization = "Bearer pat-setting";

    // ---- binding --------------------------------------------------------
    assert_eq!(
        body_json(send(&app, Some(authorization), "{").await).await,
        assert_rejected("common.invalid_params"),
    );
    // A non-JSON content type skips parsing (Go `UnmarshalBodyReusable`) and
    // binds zero values, so it fails the notify-type check instead.
    let response = router(app.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/user/setting")
                .header(header::CONTENT_TYPE, "text/plain")
                .header(header::AUTHORIZATION, authorization)
                .header(header::ACCEPT_LANGUAGE, "en")
                .body(Body::from("not-json"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        body_json(response).await,
        assert_rejected("setting.invalid_type"),
    );

    // Go's `len(requestBody) == 0` branch short-circuits before the decoder,
    // so an empty body also binds zero values rather than erroring.
    for content_type in [None, Some("application/json")] {
        let mut builder = Request::builder()
            .method("PUT")
            .uri("/api/user/setting")
            .header(header::AUTHORIZATION, authorization)
            .header(header::ACCEPT_LANGUAGE, "en");
        if let Some(value) = content_type {
            builder = builder.header(header::CONTENT_TYPE, value);
        }
        let response = router(app.clone())
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            body_json(response).await,
            assert_rejected("setting.invalid_type"),
            "an empty body binds zero values, it is not a bind error"
        );
    }

    // An absent Content-Type is coerced to JSON by Go, so a well-formed body
    // still binds even without the header.
    let response = router(app.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/user/setting")
                .header(header::AUTHORIZATION, authorization)
                .header(header::ACCEPT_LANGUAGE, "en")
                .body(Body::from(
                    r#"{"notify_type":"email","quota_warning_threshold":5}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        body_json(response).await,
        assert_saved(),
        "an absent Content-Type coerces to JSON and binds"
    );

    // ---- notify type ----------------------------------------------------
    // Absent and unknown types share Go's single `setting.invalid_type`.
    for body in [r#"{"notify_type":"unknown"}"#, r#"{"notify_type":""}"#] {
        assert_eq!(
            body_json(send(&app, Some(authorization), body).await).await,
            assert_rejected("setting.invalid_type"),
        );
    }

    // ---- threshold ------------------------------------------------------
    // The threshold precedes every gateway branch, so a non-positive value
    // with a valid type still reports the threshold message.
    for threshold in ["0", "-1"] {
        let body = format!(r#"{{"notify_type":"email","quota_warning_threshold":{threshold}}}"#);
        assert_eq!(
            body_json(send(&app, Some(authorization), &body).await).await,
            assert_rejected("quota.threshold_gt_zero"),
        );
    }

    // ---- webhook --------------------------------------------------------
    for (body, key) in [
        (
            r#"{"notify_type":"webhook","quota_warning_threshold":5,"webhook_url":""}"#,
            "setting.webhook_empty",
        ),
        (
            r#"{"notify_type":"webhook","quota_warning_threshold":5,"webhook_url":"not a uri"}"#,
            "setting.webhook_invalid",
        ),
    ] {
        assert_eq!(
            body_json(send(&app, Some(authorization), body).await).await,
            assert_rejected(key),
        );
    }

    // ---- email ----------------------------------------------------------
    // Only an explicitly non-empty email is validated, and Go checks for "@".
    let response = send(
        &app,
        Some(authorization),
        r#"{"notify_type":"email","quota_warning_threshold":5,"notification_email":"nope"}"#,
    )
    .await;
    assert_eq!(
        body_json(response).await,
        assert_rejected("setting.email_invalid"),
    );
    // A bare "@" satisfies Go's check, so this write succeeds.
    let response = send(
        &app,
        Some(authorization),
        r#"{"notify_type":"email","quota_warning_threshold":5,"notification_email":"@"}"#,
    )
    .await;
    assert_eq!(body_json(response).await, assert_saved());

    // ---- bark -----------------------------------------------------------
    for (body, key) in [
        (
            r#"{"notify_type":"bark","quota_warning_threshold":5}"#,
            "setting.bark_url_empty",
        ),
        (
            r#"{"notify_type":"bark","quota_warning_threshold":5,"bark_url":"nope"}"#,
            "setting.bark_url_invalid",
        ),
        (
            r#"{"notify_type":"bark","quota_warning_threshold":5,"bark_url":"ftp://x.example"}"#,
            "setting.url_must_http",
        ),
    ] {
        assert_eq!(
            body_json(send(&app, Some(authorization), body).await).await,
            assert_rejected(key),
        );
    }

    // ---- gotify ---------------------------------------------------------
    for (body, key) in [
        (
            r#"{"notify_type":"gotify","quota_warning_threshold":5}"#,
            "setting.gotify_url_empty",
        ),
        (
            r#"{"notify_type":"gotify","quota_warning_threshold":5,"gotify_url":"https://g.example","gotify_token":""}"#,
            "setting.gotify_token_empty",
        ),
        (
            r#"{"notify_type":"gotify","quota_warning_threshold":5,"gotify_url":"nope","gotify_token":"tok"}"#,
            "setting.gotify_url_invalid",
        ),
        (
            r#"{"notify_type":"gotify","quota_warning_threshold":5,"gotify_url":"ftp://g.example","gotify_token":"tok"}"#,
            "setting.url_must_http",
        ),
    ] {
        assert_eq!(
            body_json(send(&app, Some(authorization), body).await).await,
            assert_rejected(key),
        );
    }

    // ---- gotify priority clamping ---------------------------------------
    // Go clamps an out-of-range priority to 5 rather than rejecting, so a
    // request that fails *only* the priority range still succeeds with 5.
    let response = send(
        &app,
        Some(authorization),
        r#"{"notify_type":"gotify","quota_warning_threshold":5,
            "gotify_url":"https://g.example","gotify_token":"tok","gotify_priority":99}"#,
    )
    .await;
    assert_eq!(body_json(response).await, assert_saved());
    let stored = stored_setting_of(&db, USER_ID)
        .await
        .expect("stored setting");
    assert_eq!(
        serde_json::from_str::<Value>(&stored).expect("setting json")["gotify_priority"],
        json!(5),
        "an out-of-range gotify_priority is clamped to 5, not rejected"
    );

    // ---- a valid write persists every field ----------------------------
    let response = send(
        &app,
        Some(authorization),
        r#"{"notify_type":"webhook","quota_warning_threshold":12.5,
            "webhook_url":"https://hooks.example/a","webhook_secret":"s3cret",
            "accept_unset_model_ratio_model":true,"record_ip_log":true}"#,
    )
    .await;
    assert_eq!(body_json(response).await, assert_saved());
    let stored = stored_setting_of(&db, USER_ID)
        .await
        .expect("stored setting");
    let stored = serde_json::from_str::<Value>(&stored).expect("setting json");
    assert_eq!(stored["notify_type"], json!("webhook"));
    assert_eq!(stored["quota_warning_threshold"], json!(12.5));
    assert_eq!(stored["webhook_url"], json!("https://hooks.example/a"));
    assert_eq!(stored["webhook_secret"], json!("s3cret"));
    // `gotify_priority` is the only field Go serializes without `omitempty`,
    // so a webhook write still carries the zero value.
    assert_eq!(stored["gotify_priority"], json!(0));
    assert_eq!(stored["accept_unset_model_ratio_model"], json!(true));
    assert_eq!(stored["record_ip_log"], json!(true));

    // `notify_type` is webhook, so the email key is never assigned and
    // `omitempty` leaves it out of the marshaled setting entirely.
    assert!(
        stored.get("notification_email").is_none(),
        "the email key is absent, not null"
    );

    // Go replaces the whole `setting` column, so the keys this handler never
    // assigns are dropped instead of merged.
    for dropped in [
        "sidebar_modules",
        "billing_preference",
        "language",
        "bark_url",
        "gotify_url",
        "gotify_token",
        "upstream_model_update_notify_enabled",
    ] {
        assert!(
            stored.get(dropped).is_none(),
            "{dropped} is dropped by a webhook write"
        );
    }

    // An empty `webhook_secret` is not carried over: Go assigns it only inside
    // the webhook branch when non-empty, so the key disappears.
    let response = send(
        &app,
        Some(authorization),
        r#"{"notify_type":"webhook","quota_warning_threshold":5,
            "webhook_url":"https://hooks.example/b"}"#,
    )
    .await;
    assert_eq!(body_json(response).await, assert_saved());
    let stored = serde_json::from_str::<Value>(
        &stored_setting_of(&db, USER_ID)
            .await
            .expect("stored setting"),
    )
    .expect("setting json");
    assert_eq!(stored["webhook_url"], json!("https://hooks.example/b"));
    assert!(
        stored.get("webhook_secret").is_none(),
        "an empty webhook_secret drops the stored key rather than keeping it"
    );

    // ---- the admin-only pointer field -----------------------------------
    // A common role preserves the stored flag even when the request sends an
    // explicit false (Go `manage_users.go:1457-1461`).
    set_setting(
        &db,
        USER_ID,
        r#"{"sidebar_modules":{"a":true},"billing_preference":"keep","language":"zh-CN","upstream_model_update_notify_enabled":true}"#,
    )
    .await;
    let response = send(
        &app,
        Some(authorization),
        r#"{"notify_type":"email","quota_warning_threshold":5,
            "upstream_model_update_notify_enabled":false}"#,
    )
    .await;
    assert_eq!(body_json(response).await, assert_saved());
    let stored = serde_json::from_str::<Value>(
        &stored_setting_of(&db, USER_ID)
            .await
            .expect("stored setting"),
    )
    .expect("setting json");
    assert_eq!(
        stored["upstream_model_update_notify_enabled"],
        json!(true),
        "a common role cannot clear the admin-only flag even when the request sends false"
    );
    // The three keys owned by `PUT /api/user/self` are not assigned by this
    // handler, so the whole-column write drops them along with everything else
    // it never set. That is Go's behavior, not a merge.
    for dropped in ["billing_preference", "language", "sidebar_modules"] {
        assert!(
            stored.get(dropped).is_none(),
            "{dropped} is dropped because the write replaces the setting column"
        );
    }
    assert_eq!(stored["notify_type"], json!("email"));
    assert_eq!(stored["quota_warning_threshold"], json!(5.0));
    // An email write with no address leaves the key unassigned entirely.
    assert!(stored.get("notification_email").is_none());

    // An admin, by contrast, adopts an explicit false and thus omits the key.
    seed_user(&db, ADMIN_ID, 100, Some("pat-admin"), None).await;
    set_setting(
        &db,
        ADMIN_ID,
        r#"{"upstream_model_update_notify_enabled":true}"#,
    )
    .await;
    let response = send(
        &app,
        Some("Bearer pat-admin"),
        r#"{"notify_type":"email","quota_warning_threshold":5,
            "upstream_model_update_notify_enabled":false}"#,
    )
    .await;
    assert_eq!(body_json(response).await, assert_saved());
    let stored = serde_json::from_str::<Value>(
        &stored_setting_of(&db, ADMIN_ID)
            .await
            .expect("stored setting"),
    )
    .expect("setting json");
    assert!(
        stored.get("upstream_model_update_notify_enabled").is_none(),
        "an admin adopting false omits the key instead of writing false"
    );

    // ---- a soft-deleted row ---------------------------------------------
    soft_delete_user(&db, USER_ID).await;
    let response = send_authenticated(
        &app,
        USER_ID,
        r#"{"notify_type":"email","quota_warning_threshold":5}"#,
    )
    .await;
    assert_eq!(
        body_json(response).await,
        assert_rejected("user.not_exists"),
        "GORM's default scope hides the soft-deleted row from the handler"
    );
}

#[tokio::test]
async fn sqlite_setting_routes_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    run_contract(Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn postgres_setting_routes_contract() {
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
        "setting_routes_{}_{}",
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
