//! HTTP contracts for `GET /api/user/groups`, `GET /api/user/self/groups`,
//! and `GET /api/user/models`.
//!
//! Runs only in remote CI. Every scenario uses an isolated synthetic fixture
//! (in-memory SQLite or an isolated PostgreSQL schema); no service is started.
//! The PostgreSQL test is skipped when `TEST_POSTGRES_DSN` is absent.

use std::{
    collections::BTreeSet,
    sync::atomic::{AtomicU64, Ordering},
};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    middleware,
    response::Response,
    routing::get,
};
use newapi_server::{AppState, auth::user_auth, groups_http};
use newapi_storage::Database;
use serde_json::{Value, json};
use sqlx::{
    ConnectOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::SqlitePoolOptions,
};
use tower::ServiceExt;

static NEXT: AtomicU64 = AtomicU64::new(0);

const SECRET: &str = "groups-routes-fixture-secret";
const USER_ID: i64 = 41;

const USERS: &str = r#"CREATE TABLE users (
    id INTEGER PRIMARY KEY, username TEXT, display_name TEXT,
    role INTEGER, status INTEGER, email TEXT, github_id TEXT, discord_id TEXT,
    oidc_id TEXT, wechat_id TEXT, telegram_id TEXT, "group" TEXT,
    quota INTEGER, used_quota INTEGER, request_count INTEGER, aff_code TEXT,
    aff_count INTEGER, aff_quota INTEGER, aff_history INTEGER, inviter_id INTEGER,
    linux_do_id TEXT, setting TEXT, stripe_customer TEXT, auth_version BIGINT,
    access_token TEXT, deleted_at TIMESTAMP
)"#;

const OPTIONS: &str = r#"CREATE TABLE options (
    "key" TEXT PRIMARY KEY, "value" TEXT
)"#;

// Go `catalog.Ability`（GORM AutoMigrate 的列类型）：主键为
// (group, model, channel_id)；tag 可空。两种后端共用同一 DDL。
const ABILITIES: &str = r#"CREATE TABLE abilities (
    "group" VARCHAR(64) NOT NULL,
    model VARCHAR(255) NOT NULL,
    channel_id INTEGER NOT NULL,
    enabled BOOLEAN NOT NULL,
    tag VARCHAR(255),
    PRIMARY KEY ("group", model, channel_id)
)"#;

macro_rules! backend {
    ($db:expr, $pool:ident, $body:block) => {
        match $db {
            Database::Sqlite($pool) => $body,
            Database::Postgres($pool) => $body,
        }
    };
}

/// `/api/user/groups` has no `UserAuth`, matching Go; the other two routes do.
fn router(state: AppState) -> Router {
    let authenticated = Router::new()
        .route("/api/user/self/groups", get(groups_http::user_groups))
        .route("/api/user/models", get(groups_http::user_models))
        .route_layer(middleware::from_fn_with_state(state.clone(), user_auth));
    Router::new()
        .route("/api/user/groups", get(groups_http::user_groups))
        .merge(authenticated)
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

async fn reset(db: &Database) {
    exec(db, "DELETE FROM options").await;
    exec(db, "DELETE FROM users").await;
    exec(db, "DELETE FROM abilities").await;
}

async fn seed_user(db: &Database, group: &str, token: &str) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO users
                (id,username,display_name,role,status,"group",auth_version,access_token)
                VALUES ($1,'fixture','Fixture',1,1,$2,1,$3)"#,
        )
        .bind(USER_ID)
        .bind(group)
        .bind(token)
        .execute(pool)
        .await
        .expect("seed user");
    });
}

async fn seed_ability(db: &Database, group: &str, model: &str, channel: i64, enabled: bool) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO abilities ("group", model, channel_id, enabled)
                VALUES ($1, $2, $3, $4)"#,
        )
        .bind(group)
        .bind(model)
        .bind(channel)
        .bind(enabled)
        .execute(pool)
        .await
        .expect("seed ability");
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

async fn update_option(db: &Database, key: &str, value: &str) {
    backend!(db, pool, {
        sqlx::query(r#"UPDATE options SET "value" = $1 WHERE "key" = $2"#)
            .bind(value)
            .bind(key)
            .execute(pool)
            .await
            .expect("update option");
    });
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

async fn assert_auth_failure(response: Response) {
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false));
    assert_eq!(body["code"], json!("AUTH_UNAUTHORIZED"));
    assert!(
        body["message"]
            .as_str()
            .is_some_and(|message| !message.is_empty()),
        "fixed translated message expected"
    );
}

fn assert_success(body: &Value) {
    assert_eq!(body["success"], json!(true));
    assert_eq!(body["message"], json!(""));
}

async fn run_contract(db: Database) {
    for ddl in [USERS, OPTIONS, ABILITIES] {
        exec(&db, ddl).await;
    }
    let app = state(&db);

    // Both self routes sit behind Go `UserAuth`.
    for path in ["/api/user/self/groups", "/api/user/models"] {
        assert_auth_failure(send(&app, path, None).await).await;
        assert_auth_failure(send(&app, path, Some("Bearer not-a-token")).await).await;
    }

    // Go defaults: GroupRatio is empty and UserUsableGroups has default/vip.
    // Because the handler iterates GroupRatio, no group entry is emitted.
    seed_user(&db, "default", "pat-default").await;
    let response = send(&app, "/api/user/groups", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_success(&body);
    assert_eq!(body["data"], json!({}));

    // `/api/user/groups` has no UserAuth in Go: even a valid PAT is ignored
    // and the user group stays empty.
    let response = send(&app, "/api/user/groups", Some("Bearer pat-default")).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["data"], json!({}));

    // `/api/user/self/groups` sees the authenticated user's group, but the
    // empty GroupRatio default still yields no entries.
    let response = send(&app, "/api/user/self/groups", Some("Bearer pat-default")).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_success(&body);
    assert_eq!(body["data"], json!({}));

    // `/api/user/models` with an empty `abilities` table returns the empty
    // list Go returns for groups without any enabled ability.
    for path in ["/api/user/models", "/api/user/models?group=default"] {
        let response = send(&app, path, Some("Bearer pat-default")).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_success(&body);
        assert_eq!(body["data"], json!([]));
    }

    // Configured options. Group settings arrive through the reload worker
    // (Go `InitOptionMap`/`SyncOptions`), so a database write is invisible
    // until the snapshot is refreshed.
    set_option(
        &db,
        "GroupRatio",
        r#"{"default":1,"vip":2,"free":0.5,"auto":9,"custom":3}"#,
    )
    .await;
    set_option(
        &db,
        "UserUsableGroups",
        r#"{"default":"默认分组","vip":"vip分组","auto":"自动分组"}"#,
    )
    .await;
    set_option(&db, "GroupGroupRatio", r#"{"vip":{"default":0.25}}"#).await;
    let response = send(&app, "/api/user/groups", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["data"], json!({}));
    app.reload(&db).await.unwrap();

    // Anonymous route: user group is empty. Only usable GroupRatio keys are
    // emitted; `auto` is appended with the literal string ratio "自动".
    let response = send(&app, "/api/user/groups", None).await;
    let body = body_json(response).await;
    let data = body["data"].as_object().expect("group object");
    assert_eq!(
        data.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        BTreeSet::from(["auto", "default", "vip"])
    );
    assert_eq!(data["default"]["ratio"].as_f64(), Some(1.0));
    assert_eq!(data["default"]["desc"], json!("默认分组"));
    assert_eq!(data["vip"]["ratio"].as_f64(), Some(2.0));
    assert_eq!(data["vip"]["desc"], json!("vip分组"));
    assert_eq!(data["auto"]["ratio"], json!("自动"));
    assert_eq!(data["auto"]["desc"], json!("自动分组"));

    // Default-group user: no group-specific override applies.
    let response = send(&app, "/api/user/self/groups", Some("Bearer pat-default")).await;
    let body = body_json(response).await;
    assert_eq!(body["data"]["default"]["ratio"].as_f64(), Some(1.0));

    // Abilities are read per request (Go resolves through the catalog on every
    // call), so a row insert is visible immediately: `group=default` selects
    // only that group, disabled rows drop out.
    seed_ability(&db, "default", "zz-default-only-model", 1, true).await;
    seed_ability(&db, "default", "zz-disabled-model", 1, false).await;
    let response = send(
        &app,
        "/api/user/models?group=default",
        Some("Bearer pat-default"),
    )
    .await;
    let body = body_json(response).await;
    assert_success(&body);
    assert_eq!(body["data"], json!(["zz-default-only-model"]));

    // A usable group returns its own models; an unusable one returns nothing.
    seed_ability(&db, "vip", "zz-vip-model", 1, true).await;
    let response = send(
        &app,
        "/api/user/models?group=vip",
        Some("Bearer pat-default"),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["data"], json!(["zz-vip-model"]));
    let response = send(
        &app,
        "/api/user/models?group=free",
        Some("Bearer pat-default"),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["data"], json!([]));

    // VIP user: GroupGroupRatio overrides the default group ratio.
    reset(&db).await;
    seed_user(&db, "vip", "pat-vip").await;
    set_option(
        &db,
        "GroupRatio",
        r#"{"default":1,"vip":2,"free":0.5,"auto":9,"custom":3}"#,
    )
    .await;
    set_option(
        &db,
        "UserUsableGroups",
        r#"{"default":"默认分组","vip":"vip分组","auto":"自动分组"}"#,
    )
    .await;
    set_option(&db, "GroupGroupRatio", r#"{"vip":{"default":0.25}}"#).await;
    app.reload(&db).await.unwrap();
    let response = send(&app, "/api/user/self/groups", Some("Bearer pat-vip")).await;
    let body = body_json(response).await;
    assert_eq!(body["data"]["default"]["ratio"].as_f64(), Some(0.25));
    assert_eq!(body["data"]["vip"]["ratio"].as_f64(), Some(2.0));
    assert_eq!(body["data"]["auto"]["ratio"], json!("自动"));

    // User group outside UserUsableGroups is appended as "用户分组"; it is
    // emitted because the same name is in GroupRatio.
    reset(&db).await;
    seed_user(&db, "custom", "pat-custom").await;
    set_option(
        &db,
        "GroupRatio",
        r#"{"default":1,"vip":2,"free":0.5,"auto":9,"custom":3}"#,
    )
    .await;
    set_option(
        &db,
        "UserUsableGroups",
        r#"{"default":"默认分组","vip":"vip分组","auto":"自动分组"}"#,
    )
    .await;
    app.reload(&db).await.unwrap();
    let response = send(&app, "/api/user/self/groups", Some("Bearer pat-custom")).await;
    let body = body_json(response).await;
    assert_eq!(body["data"]["custom"]["ratio"].as_f64(), Some(3.0));
    assert_eq!(body["data"]["custom"]["desc"], json!("用户分组"));

    // Invalid GroupRatio JSON keeps the previous snapshot value: Go
    // `types.LoadFromJsonString` (rw_map.go) decodes a local map and returns
    // early on failure, leaving the runtime map untouched (last-good).
    update_option(&db, "GroupRatio", "not json").await;
    app.reload(&db).await.unwrap();
    let response = send(&app, "/api/user/self/groups", Some("Bearer pat-custom")).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    let data = body["data"].as_object().expect("group object");
    assert_eq!(
        data.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        BTreeSet::from(["auto", "custom", "default", "vip"])
    );
    assert_eq!(data["auto"]["ratio"], json!("自动"));
    assert_eq!(data["custom"]["ratio"].as_f64(), Some(3.0));

    // The models list stays empty for a user whose groups have no abilities.
    let response = send(&app, "/api/user/models", Some("Bearer pat-custom")).await;
    let body = body_json(response).await;
    assert_success(&body);
    assert_eq!(body["data"], json!([]));

    // Go `TestGetUserModelsExpandsAutoGroupsInConfiguredOrder`:
    // `group=auto` expands the ordered AutoGroups list filtered by usability,
    // the special overlay removes `unavailable`, and models union in group
    // order with per-group dedup.
    reset(&db).await;
    seed_user(&db, "default", "pat-auto").await;
    set_option(
        &db,
        "GroupRatio",
        r#"{"default":1,"vip":1,"unavailable":1}"#,
    )
    .await;
    set_option(
        &db,
        "UserUsableGroups",
        r#"{"auto":"自动分组","default":"默认分组","unavailable":"不可用分组"}"#,
    )
    .await;
    set_option(&db, "AutoGroups", r#"["vip","default","unavailable"]"#).await;
    set_option(
        &db,
        "group_ratio_setting.group_special_usable_group",
        r#"{"default":{"+:vip":"VIP 分组","-:unavailable":""}}"#,
    )
    .await;
    app.reload(&db).await.unwrap();
    seed_ability(&db, "vip", "zz-vip-model", 1, true).await;
    seed_ability(&db, "vip", "zz-shared-model", 1, true).await;
    seed_ability(&db, "default", "zz-default-model", 2, true).await;
    seed_ability(&db, "default", "zz-shared-model", 3, true).await;
    seed_ability(&db, "unavailable", "zz-unavailable-model", 1, true).await;
    let response = send(&app, "/api/user/models?group=auto", Some("Bearer pat-auto")).await;
    let body = body_json(response).await;
    assert_eq!(
        body["data"],
        json!(["zz-shared-model", "zz-vip-model", "zz-default-model"])
    );
    // The removed group is not selectable even when named directly.
    let response = send(
        &app,
        "/api/user/models?group=unavailable",
        Some("Bearer pat-auto"),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["data"], json!([]));

    // The overlay also shapes `/api/user/self/groups`: `vip` was added by the
    // overlay and keeps its configured description.
    let response = send(&app, "/api/user/self/groups", Some("Bearer pat-auto")).await;
    let body = body_json(response).await;
    assert_eq!(body["data"]["vip"]["desc"], json!("VIP 分组"));
    assert!(
        !body["data"]
            .as_object()
            .unwrap()
            .contains_key("unavailable")
    );

    // Snapshot contract: a later option write is invisible until the next
    // reload, then takes effect. Both the base usable-groups map and the
    // overlay are withdrawn here.
    update_option(&db, "UserUsableGroups", r#"{"default":"默认分组"}"#).await;
    update_option(&db, "group_ratio_setting.group_special_usable_group", "{}").await;
    let response = send(&app, "/api/user/models?group=auto", Some("Bearer pat-auto")).await;
    let body = body_json(response).await;
    // `auto` is still usable in the stale snapshot, so the old expansion runs.
    assert_eq!(
        body["data"],
        json!(["zz-shared-model", "zz-vip-model", "zz-default-model"])
    );
    app.reload(&db).await.unwrap();
    // After the reload `auto` is no longer usable and `vip` is gone: only the
    // user's own `default` group remains selectable.
    let response = send(&app, "/api/user/models?group=auto", Some("Bearer pat-auto")).await;
    let body = body_json(response).await;
    assert_eq!(body["data"], json!([]));
    let response = send(&app, "/api/user/models?group=vip", Some("Bearer pat-auto")).await;
    let body = body_json(response).await;
    assert_eq!(body["data"], json!([]));
    let response = send(&app, "/api/user/self/groups", Some("Bearer pat-auto")).await;
    let body = body_json(response).await;
    assert!(!body["data"].as_object().unwrap().contains_key("vip"));
}

#[tokio::test]
async fn sqlite_groups_routes_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    run_contract(Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn postgres_groups_routes_contract() {
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
        "groups_routes_{}_{}",
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
