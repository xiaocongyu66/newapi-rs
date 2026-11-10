//! HTTP contracts for the `/api/user-insight/*` management endpoints.
//!
//! Runs only in remote CI. Every scenario uses an isolated synthetic fixture
//! (in-memory SQLite or an isolated PostgreSQL schema); no service is started.
//! The PostgreSQL test is skipped when `TEST_POSTGRES_DSN` is absent.
//!
//! Go semantics notes:
//! - The route group carries only `security.AdminAuth()`; 401/403 are the only
//!   non-200 outcomes in the chain, and every business result is HTTP 200 with
//!   `{success,message,data}`.
//! - The list endpoint filters on derived fields (primary category / risk
//!   level) in memory: without filters it pages in SQL; with filters it scans
//!   all profiles (capped at 20000), filters, then slices, and `total` is the
//!   post-filter count.
//! - DELETE `/:id` removes the aggregate profile row and the evidence samples;
//!   the response echoes both counts.
//! - client-ban has two scopes: global (option
//!   `user_insight_setting.blocked_clients`, deduped, capped at 200) and
//!   per-user (`user_insight_client_bans`, idempotent upsert). No session
//!   revocation or token disabling is involved.
//! - client-ban bodies go through Go `RawBody` + `Unmarshal`: JSON only,
//!   an empty body is a parameter error.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::Request,
    http::{Method, StatusCode, header},
    middleware,
    response::Response,
    routing::{get, post},
};
use newapi_server::{AppState, auth as server_auth, user_insight_http};
use newapi_storage::Database;
use serde_json::{Value, json};
use sqlx::{
    ConnectOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::SqlitePoolOptions,
};
use tower::ServiceExt;

static NEXT: AtomicU64 = AtomicU64::new(0);

const SECRET: &str = "user-insight-routes-fixture-secret";
const PAT_ADMIN: &str = "pat-user-insight-admin";
const PAT_COMMON: &str = "pat-user-insight-common";
const MSG_INVALID_PARAMS: &str = "Invalid parameters";

const USERS_SQLITE: &str = r#"CREATE TABLE users (
    id INTEGER PRIMARY KEY, username TEXT, display_name TEXT,
    role INTEGER, status INTEGER, email TEXT, github_id TEXT, discord_id TEXT,
    oidc_id TEXT, wechat_id TEXT, telegram_id TEXT, "group" TEXT,
    quota INTEGER, used_quota INTEGER, request_count INTEGER, aff_code TEXT,
    aff_count INTEGER, aff_quota INTEGER, aff_history INTEGER, inviter_id INTEGER,
    linux_do_id TEXT, setting TEXT, stripe_customer TEXT, auth_version INTEGER,
    access_token TEXT, deleted_at TIMESTAMP
)"#;

const USERS_POSTGRES: &str = r#"CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY, username TEXT, display_name TEXT,
    role BIGINT, status BIGINT, email TEXT, github_id TEXT, discord_id TEXT,
    oidc_id TEXT, wechat_id TEXT, telegram_id TEXT, "group" TEXT,
    quota BIGINT, used_quota BIGINT, request_count BIGINT, aff_code TEXT,
    aff_count BIGINT, aff_quota BIGINT, aff_history BIGINT, inviter_id INTEGER,
    linux_do_id TEXT, setting TEXT, stripe_customer TEXT, auth_version BIGINT,
    access_token TEXT, deleted_at TIMESTAMPTZ
)"#;

/// GORM AutoMigrate 后的画像表形态（整数列 default 0，JSON 明细为 TEXT）。
const PROFILES_SQLITE: &str = r#"CREATE TABLE user_insight_profiles (
    user_id INTEGER PRIMARY KEY, username TEXT NOT NULL DEFAULT '',
    first_seen_at BIGINT NOT NULL DEFAULT 0,
    last_seen_at BIGINT NOT NULL DEFAULT 0,
    total_requests INTEGER NOT NULL DEFAULT 0,
    code_requests INTEGER NOT NULL DEFAULT 0,
    roleplay_requests INTEGER NOT NULL DEFAULT 0,
    qa_requests INTEGER NOT NULL DEFAULT 0,
    translate_requests INTEGER NOT NULL DEFAULT 0,
    embedding_requests INTEGER NOT NULL DEFAULT 0,
    other_requests INTEGER NOT NULL DEFAULT 0,
    frontend_score_sum INTEGER NOT NULL DEFAULT 0,
    backend_score_sum INTEGER NOT NULL DEFAULT 0,
    infra_requests INTEGER NOT NULL DEFAULT 0,
    mobile_requests INTEGER NOT NULL DEFAULT 0,
    data_requests INTEGER NOT NULL DEFAULT 0,
    male_guess_requests INTEGER NOT NULL DEFAULT 0,
    female_guess_requests INTEGER NOT NULL DEFAULT 0,
    male_self_report_requests INTEGER NOT NULL DEFAULT 0,
    female_self_report_requests INTEGER NOT NULL DEFAULT 0,
    male_preference_requests INTEGER NOT NULL DEFAULT 0,
    female_preference_requests INTEGER NOT NULL DEFAULT 0,
    ai_female_requests INTEGER NOT NULL DEFAULT 0,
    ai_male_requests INTEGER NOT NULL DEFAULT 0,
    jailbreak_suspect INTEGER NOT NULL DEFAULT 0,
    jailbreak_likely INTEGER NOT NULL DEFAULT 0,
    jailbreak_confirmed INTEGER NOT NULL DEFAULT 0,
    jailbreak_max_score INTEGER NOT NULL DEFAULT 0,
    last_jailbreak_at BIGINT NOT NULL DEFAULT 0,
    relay_requests INTEGER NOT NULL DEFAULT 0,
    clients_json TEXT, relay_vendors_json TEXT,
    jailbreak_tags_json TEXT, languages_json TEXT
)"#;

const PROFILES_POSTGRES: &str = r#"CREATE TABLE user_insight_profiles (
    user_id INTEGER PRIMARY KEY, username TEXT NOT NULL DEFAULT '',
    first_seen_at BIGINT NOT NULL DEFAULT 0,
    last_seen_at BIGINT NOT NULL DEFAULT 0,
    total_requests INTEGER NOT NULL DEFAULT 0,
    code_requests INTEGER NOT NULL DEFAULT 0,
    roleplay_requests INTEGER NOT NULL DEFAULT 0,
    qa_requests INTEGER NOT NULL DEFAULT 0,
    translate_requests INTEGER NOT NULL DEFAULT 0,
    embedding_requests INTEGER NOT NULL DEFAULT 0,
    other_requests INTEGER NOT NULL DEFAULT 0,
    frontend_score_sum INTEGER NOT NULL DEFAULT 0,
    backend_score_sum INTEGER NOT NULL DEFAULT 0,
    infra_requests INTEGER NOT NULL DEFAULT 0,
    mobile_requests INTEGER NOT NULL DEFAULT 0,
    data_requests INTEGER NOT NULL DEFAULT 0,
    male_guess_requests INTEGER NOT NULL DEFAULT 0,
    female_guess_requests INTEGER NOT NULL DEFAULT 0,
    male_self_report_requests INTEGER NOT NULL DEFAULT 0,
    female_self_report_requests INTEGER NOT NULL DEFAULT 0,
    male_preference_requests INTEGER NOT NULL DEFAULT 0,
    female_preference_requests INTEGER NOT NULL DEFAULT 0,
    ai_female_requests INTEGER NOT NULL DEFAULT 0,
    ai_male_requests INTEGER NOT NULL DEFAULT 0,
    jailbreak_suspect INTEGER NOT NULL DEFAULT 0,
    jailbreak_likely INTEGER NOT NULL DEFAULT 0,
    jailbreak_confirmed INTEGER NOT NULL DEFAULT 0,
    jailbreak_max_score INTEGER NOT NULL DEFAULT 0,
    last_jailbreak_at BIGINT NOT NULL DEFAULT 0,
    relay_requests INTEGER NOT NULL DEFAULT 0,
    clients_json TEXT, relay_vendors_json TEXT,
    jailbreak_tags_json TEXT, languages_json TEXT
)"#;

/// Go `user_insight_client_bans`：(user_id, client) 联合主键。
const BANS: &str = r#"CREATE TABLE user_insight_client_bans (
    user_id INTEGER NOT NULL, client TEXT NOT NULL,
    created_at BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, client)
)"#;

/// Go `user_insight_samples`（只保留 DELETE 计数需要的列）。
const SAMPLES: &str = r#"CREATE TABLE user_insight_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL, byte_size BIGINT NOT NULL DEFAULT 0
)"#;

const SAMPLES_POSTGRES: &str = r#"CREATE TABLE user_insight_samples (
    id BIGSERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL, byte_size BIGINT NOT NULL DEFAULT 0
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

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0)
}

/// Go insightRoute = apiRouter.Group("/user-insight")，组级仅 AdminAuth。
fn router(state: AppState) -> Router {
    Router::new()
        .route(
            "/api/user-insight/",
            get(user_insight_http::list_user_insights)
                .post(user_insight_http::set_global_client_ban),
        )
        .route(
            "/api/user-insight",
            get(user_insight_http::list_user_insights)
                .post(user_insight_http::set_global_client_ban),
        )
        .route(
            "/api/user-insight/summary",
            get(user_insight_http::get_user_insight_summary),
        )
        .route(
            "/api/user-insight/client-catalog",
            get(user_insight_http::get_client_catalog),
        )
        .route(
            "/api/user-insight/{id}",
            get(user_insight_http::get_user_insight_detail)
                .delete(user_insight_http::purge_user_insight_handler),
        )
        .route(
            "/api/user-insight/{id}/client-ban",
            post(user_insight_http::toggle_user_client_ban_handler),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            server_auth::admin_auth,
        ))
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

async fn create_schema(db: &Database) {
    match db {
        Database::Sqlite(_) => {
            for statement in [USERS_SQLITE, PROFILES_SQLITE, BANS, SAMPLES, OPTIONS] {
                exec(db, statement).await;
            }
        }
        Database::Postgres(_) => {
            for statement in [
                USERS_POSTGRES,
                PROFILES_POSTGRES,
                BANS,
                SAMPLES_POSTGRES,
                OPTIONS,
            ] {
                exec(db, statement).await;
            }
        }
    }
}

async fn reset(db: &Database) {
    for table in [
        "user_insight_samples",
        "user_insight_client_bans",
        "user_insight_profiles",
        "options",
        "users",
    ] {
        backend!(db, pool, {
            sqlx::query(&format!("DELETE FROM {table}"))
                .execute(pool)
                .await
                .expect("reset table");
        });
    }
}

async fn seed_user(db: &Database, id: i64, username: &str, role: i64, pat: &str) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO users
                (id,username,display_name,role,status,"group",auth_version,access_token)
                VALUES ($1,$2,$3,$4,1,'default',1,$5)"#,
        )
        .bind(id)
        .bind(username)
        .bind(username)
        .bind(role)
        .bind(pat)
        .execute(pool)
        .await
        .expect("seed user");
    });
}

/// 显式插入画像行：columns 与 values 用 `json!` 表达，避免 40+ 参数方法
/// 触发 clippy `too_many_arguments`。
async fn seed_profile(db: &Database, columns: &str, values: Value) {
    let fields = values.as_object().expect("object").clone();
    let names: Vec<&str> = columns.split(',').map(str::trim).collect();
    assert_eq!(names.len(), fields.len(), "columns/values mismatch");
    let placeholders: Vec<String> = (1..=fields.len())
        .map(|index| format!("${index}"))
        .collect();
    let sql = format!(
        "INSERT INTO user_insight_profiles ({columns}) VALUES ({})",
        placeholders.join(",")
    );
    backend!(db, pool, {
        let mut query = sqlx::query(&sql);
        for name in &names {
            let value = fields.get(*name).cloned().unwrap_or(json!(0));
            match value {
                Value::Number(number) => {
                    if let Some(int) = number.as_i64() {
                        query = query.bind(int);
                    } else {
                        query = query.bind(number.as_f64().unwrap_or(0.0));
                    }
                }
                Value::String(text) => {
                    query = query.bind(text);
                }
                Value::Null => {
                    query = query.bind(Option::<String>::None);
                }
                other => panic!("unsupported seed value: {other}"),
            }
        }
        query.execute(pool).await.expect("seed profile");
    });
}

async fn seed_ban(db: &Database, user_id: i64, client: &str) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO user_insight_client_bans (user_id, client, created_at)
               VALUES ($1, $2, $3)"#,
        )
        .bind(user_id)
        .bind(client)
        .bind(now())
        .execute(pool)
        .await
        .expect("seed ban");
    });
}

async fn seed_sample(db: &Database, user_id: i64) {
    backend!(db, pool, {
        sqlx::query(r#"INSERT INTO user_insight_samples (user_id, byte_size) VALUES ($1, 64)"#)
            .bind(user_id)
            .execute(pool)
            .await
            .expect("seed sample");
    });
}

async fn count_profiles(db: &Database) -> i64 {
    backend!(db, pool, {
        sqlx::query_scalar("SELECT COUNT(*) FROM user_insight_profiles")
            .fetch_one(pool)
            .await
            .expect("count profiles")
    })
}

async fn count_samples(db: &Database) -> i64 {
    backend!(db, pool, {
        sqlx::query_scalar("SELECT COUNT(*) FROM user_insight_samples")
            .fetch_one(pool)
            .await
            .expect("count samples")
    })
}

async fn count_bans(db: &Database, user_id: i64, client: &str) -> i64 {
    backend!(db, pool, {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM user_insight_client_bans WHERE user_id = $1 AND client = $2",
        )
        .bind(user_id)
        .bind(client)
        .fetch_one(pool)
        .await
        .expect("count bans")
    })
}

async fn blocked_option(db: &Database) -> Value {
    backend!(db, pool, {
        let raw: Option<String> = sqlx::query_scalar(
            r#"SELECT value FROM options WHERE "key" = 'user_insight_setting.blocked_clients'"#,
        )
        .fetch_optional(pool)
        .await
        .expect("read option");
        raw.map(|raw| serde_json::from_str(&raw).expect("option JSON"))
            .unwrap_or(Value::Null)
    })
}

async fn send(
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

async fn send_raw(
    state: &AppState,
    method: Method,
    path: &str,
    authorization: &str,
    body: &'static [u8],
) -> Response {
    router(state.clone())
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header(header::AUTHORIZATION, authorization)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
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

async fn assert_auth_failure(response: Response, code: &str) {
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false));
    assert_eq!(body["code"], json!(code));
}

async fn assert_forbidden(response: Response) {
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false));
    assert_eq!(body["code"], json!("AUTH_INSUFFICIENT_PRIVILEGE"));
}

async fn assert_invalid_params(response: Response) {
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false));
    assert_eq!(body["message"], json!(MSG_INVALID_PARAMS));
}

async fn run_contract(db: Database) {
    create_schema(&db).await;
    reset(&db).await;
    seed_user(&db, 1, "admin-one", 10, PAT_ADMIN).await;
    seed_user(&db, 2, "common-one", 1, PAT_COMMON).await;
    let app = state(&db);
    let admin = format!("Bearer {PAT_ADMIN}");
    let common = format!("Bearer {PAT_COMMON}");

    // ---- guard chain: Go `security.AdminAuth()` only -----------------------
    assert_auth_failure(
        send(&app, Method::GET, "/api/user-insight", None, None).await,
        "AUTH_UNAUTHORIZED",
    )
    .await;
    assert_forbidden(send(&app, Method::GET, "/api/user-insight", Some(&common), None).await).await;
    assert_forbidden(
        send(
            &app,
            Method::POST,
            "/api/user-insight/client-ban",
            Some(&common),
            Some(&json!({"client": "curl", "ban": true})),
        )
        .await,
    )
    .await;

    // ---- empty site --------------------------------------------------------
    let response = send(&app, Method::GET, "/api/user-insight", Some(&admin), None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true));
    assert_eq!(body["data"]["items"], json!([]));
    assert_eq!(body["data"]["total"], json!(0));
    assert_eq!(body["data"]["page"], json!(1));
    assert_eq!(body["data"]["size"], json!(20));

    // summary on an empty site: counters all zero, clients empty object.
    let body = body_json(
        send(
            &app,
            Method::GET,
            "/api/user-insight/summary",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["success"], json!(true));
    assert_eq!(body["data"]["total_users"], json!(0));
    assert_eq!(body["data"]["clients"], json!({}));

    // detail for an absent profile: data is null.
    let body = body_json(
        send(
            &app,
            Method::GET,
            "/api/user-insight/42",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["success"], json!(true));
    assert_eq!(body["data"], Value::Null);

    // ---- fixtures: two profiles with derived-field variety -----------------
    // user 11: coder with jailbreak confirmations (risk confirmed), relay.
    seed_profile(
        &db,
        "user_id, username, first_seen_at, last_seen_at, total_requests,
         code_requests, jailbreak_confirmed, jailbreak_max_score,
         relay_requests, clients_json, frontend_score_sum, backend_score_sum",
        json!({
            "user_id": 11, "username": "dev-alice",
            "first_seen_at": 100, "last_seen_at": 900,
            "total_requests": 10, "code_requests": 10,
            "jailbreak_confirmed": 4, "jailbreak_max_score": 90,
            "relay_requests": 3,
            "clients_json": r#"[{"client":"cursor","count":7,"version":"0.4"},{"client":"ua:mybot+acme","count":3}]"#,
            "frontend_score_sum": 6, "backend_score_sum": 4,
        }),
    )
    .await;
    // user 12: roleplayer with gender self-report, no relay, last_seen newest.
    seed_profile(
        &db,
        "user_id, username, first_seen_at, last_seen_at, total_requests,
         roleplay_requests, male_self_report_requests, female_self_report_requests,
         clients_json",
        json!({
            "user_id": 12, "username": "rp-bob",
            "first_seen_at": 200, "last_seen_at": 1000,
            "total_requests": 8, "roleplay_requests": 8,
            "male_self_report_requests": 0, "female_self_report_requests": 2,
            "clients_json": r#"[{"client":"sillytavern","count":8}]"#,
        }),
    )
    .await;
    seed_user(&db, 11, "dev-alice", 1, "pat-user-11").await;
    seed_user(&db, 12, "rp-bob", 1, "pat-user-12").await;

    // ---- list: default ordering by last_seen desc, enrichment --------------
    let body =
        body_json(send(&app, Method::GET, "/api/user-insight", Some(&admin), None).await).await;
    assert_eq!(body["success"], json!(true));
    assert_eq!(body["data"]["total"], json!(2));
    let items = body["data"]["items"].as_array().expect("items");
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["user_id"], json!(12));
    assert_eq!(items[1]["user_id"], json!(11));
    // 用户状态/分组来自 users 表补齐。
    assert_eq!(items[0]["status"], json!(1));
    assert_eq!(items[0]["role"], json!(1));
    assert_eq!(items[0]["group"], json!("default"));
    assert_eq!(items[0]["display_name"], json!("rp-bob"));
    // 派生字段。
    assert_eq!(items[1]["primary_category"], json!("code"));
    assert_eq!(items[1]["primary_stack"], json!("frontend"));
    assert_eq!(items[1]["risk_level"], json!("confirmed"));
    // 性别推断：自述 2 次全一致 → female，置信度 1 封顶 0.9，basis self_report。
    assert_eq!(items[0]["guessed_gender"], json!("female"));
    assert_eq!(items[0]["gender_confidence"], json!(0.9));
    assert_eq!(items[0]["gender_basis"], json!("self_report"));
    // clients 明细保留存储顺序，version 走 omitempty。
    let clients = items[1]["clients"].as_array().expect("clients");
    assert_eq!(clients[0]["client"], json!("cursor"));
    assert_eq!(clients[0]["count"], json!(7));
    assert_eq!(clients[0]["version"], json!("0.4"));
    assert_eq!(clients[1]["client"], json!("ua:mybot+acme"));
    assert!(clients[1].get("version").is_none());
    // 无封禁记录时 disabled_clients 不出现。
    assert!(items[0].get("disabled_clients").is_none());

    // ---- list: filters -----------------------------------------------------
    // category=code 只命中 user 11。
    let body = body_json(
        send(
            &app,
            Method::GET,
            "/api/user-insight?category=code",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["total"], json!(1));
    assert_eq!(body["data"]["items"][0]["user_id"], json!(11));

    // risk=confirmed 同样只命中 user 11。
    let body = body_json(
        send(
            &app,
            Method::GET,
            "/api/user-insight?risk=confirmed",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["total"], json!(1));

    // relay_only=true 只命中 user 11。
    let body = body_json(
        send(
            &app,
            Method::GET,
            "/api/user-insight?relay_only=true",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["total"], json!(1));

    // keyword 命中用户名子串（大小写不敏感）。
    let body = body_json(
        send(
            &app,
            Method::GET,
            "/api/user-insight?keyword=DEV",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["total"], json!(1));
    assert_eq!(body["data"]["items"][0]["user_id"], json!(11));

    // keyword 命中用户 ID 字符串。
    let body = body_json(
        send(
            &app,
            Method::GET,
            "/api/user-insight?keyword=12",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["total"], json!(1));
    assert_eq!(body["data"]["items"][0]["user_id"], json!(12));

    // sort=code 按 code_requests 倒序：user 11 在前。
    let body = body_json(
        send(
            &app,
            Method::GET,
            "/api/user-insight?sort=code",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["items"][0]["user_id"], json!(11));

    // 非法 page_size 回落 20；p=0 回落 1（Go clamp 语义）。
    let body = body_json(
        send(
            &app,
            Method::GET,
            "/api/user-insight?p=0&page_size=500",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["page"], json!(1));
    assert_eq!(body["data"]["size"], json!(20));

    // ---- detail ------------------------------------------------------------
    let body = body_json(
        send(
            &app,
            Method::GET,
            "/api/user-insight/11",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["success"], json!(true));
    assert_eq!(body["data"]["user_id"], json!(11));
    assert_eq!(body["data"]["total_requests"], json!(10));

    // 非法 id：非数字与 <=0 都是参数错误（HTTP 200 + invalid_params）。
    assert_invalid_params(
        send(
            &app,
            Method::GET,
            "/api/user-insight/abc",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_invalid_params(send(&app, Method::GET, "/api/user-insight/0", Some(&admin), None).await)
        .await;

    // ---- purge -------------------------------------------------------------
    seed_sample(&db, 11).await;
    seed_sample(&db, 11).await;
    let response = send(
        &app,
        Method::DELETE,
        "/api/user-insight/11",
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true));
    assert_eq!(body["data"]["profile_deleted"], json!(true));
    assert_eq!(body["data"]["samples_deleted"], json!(2));
    assert_eq!(count_profiles(&db).await, 1);
    assert_eq!(count_samples(&db).await, 0);

    // 重复清除：画像已不存在，profile_deleted=false。
    let body = body_json(
        send(
            &app,
            Method::DELETE,
            "/api/user-insight/11",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["profile_deleted"], json!(false));
    assert_eq!(body["data"]["samples_deleted"], json!(0));

    assert_invalid_params(
        send(
            &app,
            Method::DELETE,
            "/api/user-insight/-3",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;

    // ---- client catalog ----------------------------------------------------
    let body = body_json(
        send(
            &app,
            Method::GET,
            "/api/user-insight/client-catalog",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["success"], json!(true));
    let entries = body["data"].as_array().expect("catalog");
    // 内置规则 44 条在前，顺序同 Go clientRules。
    assert_eq!(entries[0]["id"], json!("claude_code"));
    assert_eq!(entries[0]["built_in"], json!(true));
    assert_eq!(entries[0]["requests"], json!(0));
    let cursor = entries
        .iter()
        .find(|entry| entry["id"] == json!("cursor"))
        .expect("cursor entry");
    assert_eq!(cursor["kind"], json!("ide"));
    assert_eq!(cursor["requests"], json!(7));
    assert_eq!(cursor["users"], json!(1));
    let sillytavern = entries
        .iter()
        .find(|entry| entry["id"] == json!("sillytavern"))
        .expect("sillytavern entry");
    assert_eq!(sillytavern["users"], json!(1));
    // 观测到的自动发现客户端追加在后，discovered 形态 + 可读名。
    let discovered = entries.last().expect("discovered entry");
    assert_eq!(discovered["id"], json!("ua:mybot+acme"));
    assert_eq!(discovered["name"], json!("mybot (acme)"));
    assert_eq!(discovered["kind"], json!("discovered"));
    assert_eq!(discovered["built_in"], json!(false));
    assert_eq!(discovered["requests"], json!(3));
    assert_eq!(discovered["users"], json!(1));

    // ---- global client ban -------------------------------------------------
    let response = send(
        &app,
        Method::POST,
        "/api/user-insight/client-ban",
        Some(&admin),
        Some(&json!({"client": " curl ", "ban": true})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true));
    assert_eq!(body["data"]["client"], json!("curl"));
    assert_eq!(body["data"]["ban"], json!(true));
    assert_eq!(body["data"]["blocked_clients"], json!(["curl"]));
    assert_eq!(blocked_option(&db).await, json!(["curl"]));

    // 再封一个；重复封同一个是幂等集合操作。
    send(
        &app,
        Method::POST,
        "/api/user-insight/client-ban",
        Some(&admin),
        Some(&json!({"client": "opencode", "ban": true})),
    )
    .await;
    send(
        &app,
        Method::POST,
        "/api/user-insight/client-ban",
        Some(&admin),
        Some(&json!({"client": "curl", "ban": true})),
    )
    .await;
    assert_eq!(blocked_option(&db).await, json!(["curl", "opencode"]));

    // 解封只移除目标。
    let body = body_json(
        send(
            &app,
            Method::POST,
            "/api/user-insight/client-ban",
            Some(&admin),
            Some(&json!({"client": "curl", "ban": false})),
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["blocked_clients"], json!(["opencode"]));
    assert_eq!(blocked_option(&db).await, json!(["opencode"]));

    // 非法请求体：空体 / 非 JSON / 空 client / 超长 client。
    assert_invalid_params(
        send(
            &app,
            Method::POST,
            "/api/user-insight/client-ban",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_invalid_params(
        send_raw(
            &app,
            Method::POST,
            "/api/user-insight/client-ban",
            &admin,
            b"not json",
        )
        .await,
    )
    .await;
    assert_invalid_params(
        send(
            &app,
            Method::POST,
            "/api/user-insight/client-ban",
            Some(&admin),
            Some(&json!({"client": "   ", "ban": true})),
        )
        .await,
    )
    .await;
    let long_client = "c".repeat(65);
    assert_invalid_params(
        send(
            &app,
            Method::POST,
            "/api/user-insight/client-ban",
            Some(&admin),
            Some(&json!({"client": long_client, "ban": true})),
        )
        .await,
    )
    .await;

    // ---- per-user client ban ------------------------------------------------
    let response = send(
        &app,
        Method::POST,
        "/api/user-insight/12/client-ban",
        Some(&admin),
        Some(&json!({"client": "sillytavern", "ban": true})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["data"]["user_id"], json!(12));
    assert_eq!(body["data"]["client"], json!("sillytavern"));
    assert_eq!(body["data"]["ban"], json!(true));
    assert_eq!(body["data"]["disabled_clients"], json!(["sillytavern"]));
    assert_eq!(count_bans(&db, 12, "sillytavern").await, 1);

    // 幂等：重复封不新增行。
    send(
        &app,
        Method::POST,
        "/api/user-insight/12/client-ban",
        Some(&admin),
        Some(&json!({"client": "sillytavern", "ban": true})),
    )
    .await;
    assert_eq!(count_bans(&db, 12, "sillytavern").await, 1);

    // 解封后无记录：disabled_clients 是 null（Go nil slice）。
    let body = body_json(
        send(
            &app,
            Method::POST,
            "/api/user-insight/12/client-ban",
            Some(&admin),
            Some(&json!({"client": "sillytavern", "ban": false})),
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["ban"], json!(false));
    assert_eq!(body["data"]["disabled_clients"], Value::Null);
    assert_eq!(count_bans(&db, 12, "sillytavern").await, 0);

    // 非法用户 id 与非法请求体。
    assert_invalid_params(
        send(
            &app,
            Method::POST,
            "/api/user-insight/0/client-ban",
            Some(&admin),
            Some(&json!({"client": "curl", "ban": true})),
        )
        .await,
    )
    .await;
    assert_invalid_params(
        send(
            &app,
            Method::POST,
            "/api/user-insight/12/client-ban",
            Some(&admin),
            Some(&json!({"ban": true})),
        )
        .await,
    )
    .await;

    // 无封禁记录的用户的列表视图仍不携带 disabled_clients。
    seed_ban(&db, 12, "opencode").await;
    let body = body_json(
        send(
            &app,
            Method::GET,
            "/api/user-insight?keyword=rp-bob",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    let items = body["data"]["items"].as_array().expect("items");
    assert_eq!(items[0]["disabled_clients"], json!(["opencode"]));
}

#[tokio::test]
async fn sqlite_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("sqlite pool");
    run_contract(Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn postgres_contract() {
    let Ok(dsn) = std::env::var("TEST_POSTGRES_DSN") else {
        eprintln!("TEST_POSTGRES_DSN not set; skipping postgres contract");
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
        "user_insight_routes_{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA \"{schema}\"")))
        .execute(&admin)
        .await
        .expect("create isolated schema");
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
