//! `/api/channel/*` 基础 CRUD 的 HTTP 契约（Go `handle_channel.go`）。
//!
//! 仅在远端 CI 运行；每个场景都用隔离的合成 fixture（内存 SQLite 或独立
//! PostgreSQL schema），不启动服务。PostgreSQL 变体在 `TEST_POSTGRES_DSN`
//! 缺失时跳过。
//!
//! 断言对齐 Go：业务结果一律 HTTP 200 + `{"success":...}` 信封，401/403
//! 只来自鉴权链（`AdminAuth` → `RequirePermission`）；`key` 在所有响应中
//! 为空字符串（Go `Omit("key")` + 无 omitempty tag）。

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::Request,
    http::{Method, StatusCode, header},
    middleware,
    response::Response,
    routing::{delete, get, post},
};
use newapi_config::SessionCookieSettings;
use newapi_identity::{
    AuthIdentity,
    auth_session::{AuthFence, SessionAuth},
    crypto::AuthKeys,
    sessions::NoCache,
};
use newapi_security::client_ip::ProxyPolicy;
use newapi_server::{
    AppState, RateLimiter, auth::admin_auth, channel_http, limit::RateLimitSettings,
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

const SECRET: &str = "channel-routes-fixture-secret";

const USERS_SQLITE: &str = r#"CREATE TABLE users (
    id INTEGER PRIMARY KEY, username TEXT, display_name TEXT,
    role INTEGER, status INTEGER, email TEXT, github_id TEXT, discord_id TEXT,
    oidc_id TEXT, wechat_id TEXT, telegram_id TEXT, "group" TEXT,
    quota INTEGER, used_quota INTEGER, request_count INTEGER, aff_code TEXT,
    aff_count INTEGER, aff_quota INTEGER, aff_history INTEGER, inviter_id INTEGER,
    linux_do_id TEXT, setting TEXT, stripe_customer TEXT, auth_version BIGINT,
    access_token TEXT, deleted_at TIMESTAMP, password TEXT
)"#;

const USERS_POSTGRES: &str = r#"CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY, username TEXT, display_name TEXT,
    role BIGINT, status BIGINT, email TEXT, github_id TEXT, discord_id TEXT,
    oidc_id TEXT, wechat_id TEXT, telegram_id TEXT, "group" TEXT,
    quota BIGINT, used_quota BIGINT, request_count BIGINT, aff_code TEXT,
    aff_count BIGINT, aff_quota BIGINT, aff_history BIGINT, inviter_id BIGINT,
    linux_do_id TEXT, setting TEXT, stripe_customer TEXT, auth_version BIGINT,
    access_token TEXT, deleted_at TIMESTAMPTZ, password TEXT
)"#;

const SESSIONS: &str = r#"CREATE TABLE user_sessions (
    sid VARCHAR(64) PRIMARY KEY, user_id BIGINT NOT NULL,
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

const LOGS_SQLITE: &str = r#"CREATE TABLE logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
    created_at BIGINT NOT NULL, type INTEGER, content TEXT, username TEXT,
    token_name TEXT, model_name TEXT, quota INTEGER,
    prompt_tokens INTEGER, completion_tokens INTEGER, use_time INTEGER,
    is_stream INTEGER, ip TEXT, request_id VARCHAR(64), other TEXT
)"#;

const LOGS_POSTGRES: &str = r#"CREATE TABLE logs (
    id BIGSERIAL PRIMARY KEY, user_id BIGINT,
    created_at BIGINT NOT NULL, type BIGINT, content TEXT, username TEXT,
    token_name TEXT, model_name TEXT, quota BIGINT,
    prompt_tokens BIGINT, completion_tokens BIGINT, use_time BIGINT,
    is_stream BOOLEAN, ip TEXT, request_id VARCHAR(64), other TEXT
)"#;

const CHANNELS_SQLITE: &str = r#"CREATE TABLE channels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    "type" INTEGER NOT NULL DEFAULT 0,
    "key" TEXT NOT NULL,
    openai_organization TEXT, test_model TEXT,
    status INTEGER NOT NULL DEFAULT 1, name TEXT NOT NULL,
    created_time INTEGER NOT NULL DEFAULT 0, test_time INTEGER NOT NULL DEFAULT 0,
    response_time INTEGER NOT NULL DEFAULT 0, base_url TEXT NOT NULL DEFAULT '',
    other TEXT NOT NULL DEFAULT '', balance REAL NOT NULL DEFAULT 0,
    balance_updated_time INTEGER NOT NULL DEFAULT 0, models TEXT NOT NULL DEFAULT '',
    "group" VARCHAR(64) NOT NULL DEFAULT 'default', used_quota BIGINT NOT NULL DEFAULT 0,
    model_mapping TEXT, status_code_mapping VARCHAR(1024) NOT NULL DEFAULT '',
    auto_ban INTEGER DEFAULT 1, other_info TEXT NOT NULL DEFAULT '',
    tag TEXT, setting TEXT, param_override TEXT, header_override TEXT,
    remark VARCHAR(255), channel_info TEXT NOT NULL DEFAULT '{}',
    settings TEXT NOT NULL DEFAULT ''
)"#;

const CHANNELS_POSTGRES: &str = r#"CREATE TABLE channels (
    id BIGSERIAL PRIMARY KEY,
    "type" BIGINT NOT NULL DEFAULT 0,
    "key" TEXT NOT NULL,
    openai_organization TEXT, test_model TEXT,
    status BIGINT NOT NULL DEFAULT 1, name TEXT NOT NULL,
    created_time BIGINT NOT NULL DEFAULT 0, test_time BIGINT NOT NULL DEFAULT 0,
    response_time BIGINT NOT NULL DEFAULT 0, base_url TEXT NOT NULL DEFAULT '',
    other TEXT NOT NULL DEFAULT '', balance DOUBLE PRECISION NOT NULL DEFAULT 0,
    balance_updated_time BIGINT NOT NULL DEFAULT 0, models TEXT NOT NULL DEFAULT '',
    "group" VARCHAR(64) NOT NULL DEFAULT 'default', used_quota BIGINT NOT NULL DEFAULT 0,
    model_mapping TEXT, status_code_mapping VARCHAR(1024) NOT NULL DEFAULT '',
    auto_ban BIGINT DEFAULT 1, other_info TEXT NOT NULL DEFAULT '',
    tag TEXT, setting TEXT, param_override TEXT, header_override TEXT,
    remark VARCHAR(255), channel_info TEXT NOT NULL DEFAULT '{}',
    settings TEXT NOT NULL DEFAULT ''
)"#;

const ABILITIES_SQLITE: &str = r#"CREATE TABLE abilities (
    "group" VARCHAR(64) NOT NULL, model VARCHAR(255) NOT NULL,
    channel_id INTEGER NOT NULL, enabled BOOLEAN NOT NULL, tag TEXT,
    PRIMARY KEY ("group", model, channel_id)
)"#;

const ABILITIES_POSTGRES: &str = r#"CREATE TABLE abilities (
    "group" VARCHAR(64) NOT NULL, model VARCHAR(255) NOT NULL,
    channel_id BIGINT NOT NULL, enabled BOOLEAN NOT NULL, tag TEXT,
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

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0)
}

/// Go `channelRoute`：组级 `AdminAuth()`；路由级 `RequirePermission(...)`
/// 的 403/放行在 handler 入口复现（见 `channel_http::require_permission`）。
fn router(state: AppState) -> Router {
    Router::new()
        .route(
            "/api/channel/",
            get(channel_http::list_channels)
                .post(channel_http::add_channel)
                .put(channel_http::update_channel),
        )
        .route("/api/channel/search", get(channel_http::search_channels))
        .route(
            "/api/channel/disabled",
            delete(channel_http::delete_disabled_channels),
        )
        .route(
            "/api/channel/batch",
            post(channel_http::delete_channel_batch),
        )
        .route(
            "/api/channel/{id}",
            get(channel_http::get_channel).delete(channel_http::delete_channel),
        )
        .route_layer(middleware::from_fn_with_state(state.clone(), admin_auth))
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

async fn exec(db: &Database, statement: &'static str) {
    backend!(db, pool, {
        sqlx::query(statement).execute(pool).await.expect("fixture");
    });
}

async fn create_schema(db: &Database) {
    match db {
        Database::Sqlite(_) => {
            for statement in [
                USERS_SQLITE,
                SESSIONS,
                CASBIN,
                LOGS_SQLITE,
                CHANNELS_SQLITE,
                ABILITIES_SQLITE,
            ] {
                exec(db, statement).await;
            }
        }
        Database::Postgres(_) => {
            for statement in [
                USERS_POSTGRES,
                SESSIONS,
                CASBIN,
                LOGS_POSTGRES,
                CHANNELS_POSTGRES,
                ABILITIES_POSTGRES,
            ] {
                exec(db, statement).await;
            }
        }
    }
}

async fn reset(db: &Database) {
    exec(db, "DELETE FROM abilities").await;
    exec(db, "DELETE FROM channels").await;
    exec(db, "DELETE FROM logs").await;
    exec(db, "DELETE FROM casbin_rule").await;
    exec(db, "DELETE FROM user_sessions").await;
    exec(db, "DELETE FROM users").await;
}

async fn seed_user(db: &Database, id: i64, username: &str, role: i64) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO users
                (id,username,display_name,role,status,"group",auth_version)
                VALUES ($1,$2,$3,$4,1,'default',1)"#,
        )
        .bind(id)
        .bind(username)
        .bind(username)
        .bind(role)
        .execute(pool)
        .await
        .expect("seed user");
    });
}

async fn seed_session(db: &Database, sid: &str, user_id: i64, at: i64) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO user_sessions
                (sid,user_id,version,user_auth_version,status,refresh_hash,
                 login_method,created_at,last_active_at,expires_at)
                VALUES ($1,$2,1,1,'active','fixture-hash','password',$3,$3,$4)"#,
        )
        .bind(sid)
        .bind(user_id)
        .bind(at)
        .bind(at + 3600)
        .execute(pool)
        .await
        .expect("seed session");
    });
}

/// 直接种入渠道行（不经创建端点，便于构造失败/历史状态）。
/// PG 的 BIGSERIAL 不因显式 id 插入而前进；把序列推到已种 id 之后，
/// 否则经 API 创建的第一行会与种入行主键冲突（SQLite AUTOINCREMENT
/// 无此问题，直接跳过）。
async fn bump_sequences(db: &Database) {
    if let Database::Postgres(pool) = db {
        for table in ["channels", "logs"] {
            sqlx::query(sqlx::AssertSqlSafe(format!(
                r#"SELECT setval(pg_get_serial_sequence('"{table}"', 'id'),
                       COALESCE((SELECT MAX(id) FROM "{table}"), 0) + 1, false)"#
            )))
            .execute(pool)
            .await
            .expect("bump sequence");
        }
    }
}

struct SeedChannel<'a> {
    id: i64,
    channel_type: i64,
    status: i64,
    name: &'a str,
    key: &'a str,
    models: &'a str,
    group: &'a str,
    tag: Option<&'a str>,
    channel_info: &'a str,
}

async fn seed_channel(db: &Database, seed: &SeedChannel<'_>) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO channels
                (id,"type","key",status,name,models,"group",tag,channel_info,
                 settings,other,other_info,base_url,status_code_mapping,balance)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'','','','','',0)"#,
        )
        .bind(seed.id)
        .bind(seed.channel_type)
        .bind(seed.key)
        .bind(seed.status)
        .bind(seed.name)
        .bind(seed.models)
        .bind(seed.group)
        .bind(seed.tag)
        .bind(seed.channel_info)
        .execute(pool)
        .await
        .expect("seed channel");
    });
}

async fn channel_rows(db: &Database) -> Vec<(i64, String, i64)> {
    backend!(db, pool, {
        sqlx::query_as::<_, (i64, String, i64)>(
            r#"SELECT CAST(id AS BIGINT), name, CAST(status AS BIGINT) FROM channels
               ORDER BY id"#,
        )
        .fetch_all(pool)
        .await
        .expect("channel rows")
    })
}

async fn ability_rows(db: &Database, channel_id: i64) -> Vec<(String, String, bool)> {
    backend!(db, pool, {
        let rows = sqlx::query(
            r#"SELECT "group", model, enabled FROM abilities WHERE channel_id = $1
               ORDER BY "group", model"#,
        )
        .bind(channel_id)
        .fetch_all(pool)
        .await
        .expect("ability rows");
        rows.into_iter()
            .map(|row| {
                use sqlx::Row;
                (
                    row.try_get::<String, _>("group").unwrap_or_default(),
                    row.try_get::<String, _>("model").unwrap_or_default(),
                    row.try_get::<bool, _>("enabled").unwrap_or_default(),
                )
            })
            .collect()
    })
}

async fn manage_audit_contents(db: &Database) -> Vec<String> {
    backend!(db, pool, {
        sqlx::query_scalar::<_, String>("SELECT content FROM logs WHERE type = 3 ORDER BY id")
            .fetch_all(pool)
            .await
            .expect("audit rows")
    })
}

fn jwt(user_id: i64, sid: &str, at: i64) -> String {
    AuthKeys::new(SECRET)
        .issue_access(
            &AuthIdentity {
                user_id,
                sid: sid.to_owned(),
                user_auth_version: 1,
                session_version: 1,
            },
            at,
        )
        .expect("issue access token")
        .token
        .expose_secret()
        .to_owned()
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

async fn body_json(response: Response) -> Value {
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body");
    serde_json::from_slice(&bytes).expect("response JSON")
}

fn translated(key: &str) -> String {
    newapi_i18n::translate("en", key, std::iter::empty::<(&str, &str)>())
}

/// Go 的 admin 鉴权链：未认证 401（固定 code），普通用户 403。
async fn assert_auth_failures(state: &AppState, path: &str, common: &str) {
    let response = send(state, Method::GET, path, None, None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false));
    assert_eq!(body["code"], json!("AUTH_UNAUTHORIZED"));
    let response = send(state, Method::GET, path, Some(common), None).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false));
}

/// Go `common.H{"success":true,...}`：HTTP 200 + 信封。
async fn assert_success(response: Response) -> Value {
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true), "{}", body);
    body
}

async fn assert_business_error(response: Response, key: &str) -> Value {
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false), "{}", body);
    assert_eq!(body["message"], json!(translated(key)), "{}", body);
    body
}

async fn run_contract(db: Database) {
    create_schema(&db).await;
    reset(&db).await;
    seed_user(&db, 1, "admin-one", 10).await;
    seed_user(&db, 2, "root-one", 100).await;
    seed_user(&db, 3, "common-one", 1).await;
    let at = now();
    seed_session(&db, "sid-admin", 1, at).await;
    seed_session(&db, "sid-root", 2, at).await;
    seed_session(&db, "sid-common", 3, at).await;
    bump_sequences(&db).await;
    let app = state(&db);
    let admin = format!("Bearer {}", jwt(1, "sid-admin", at));
    let root = format!("Bearer {}", jwt(2, "sid-root", at));
    let common = format!("Bearer {}", jwt(3, "sid-common", at));

    // ---- 鉴权链：AdminAuth 的 401/403 -------------------------------
    assert_auth_failures(&app, "/api/channel/", &common).await;

    // ---- 列表：空库信封 -------------------------------------------
    let body =
        assert_success(send(&app, Method::GET, "/api/channel/", Some(&admin), None).await).await;
    assert_eq!(body["data"]["total"], json!(0));
    assert_eq!(body["data"]["items"], json!([]));
    assert_eq!(body["data"]["page"], json!(1));
    assert_eq!(body["data"]["page_size"], json!(10));
    assert_eq!(body["data"]["type_counts"], json!({}));

    // ---- 种入数据后的列表 / 过滤 / 排序 ----------------------------
    seed_channel(
        &db,
        &SeedChannel {
            id: 1,
            channel_type: 1,
            status: 1,
            name: "alpha",
            key: "sk-secret-list",
            models: "m1",
            group: "default,vip",
            tag: Some("beta"),
            channel_info: "{}",
        },
    )
    .await;
    seed_channel(
        &db,
        &SeedChannel {
            id: 2,
            channel_type: 41,
            status: 1,
            name: "beta",
            key: "sk-secret-list",
            models: "m2",
            group: "default",
            tag: Some("alpha"),
            channel_info: "{}",
        },
    )
    .await;
    seed_channel(
        &db,
        &SeedChannel {
            id: 3,
            channel_type: 1,
            status: 3,
            name: "gamma",
            key: "sk-secret-list",
            models: "m1",
            group: "default",
            tag: None,
            channel_info: "{}",
        },
    )
    .await;
    let body = assert_success(
        send(
            &app,
            Method::GET,
            "/api/channel/?p=1&page_size=10",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    let items = body["data"]["items"].as_array().expect("items");
    assert_eq!(items.len(), 3);
    assert_eq!(body["data"]["total"], json!(3));
    // 默认排序 id desc（Go ChannelSortOptions 的最终分支）。
    assert_eq!(items[0]["id"], json!(3));
    // key 永不出现（Go Omit("key") + 列表不读）。
    for item in items {
        assert_eq!(item["key"], json!(""));
    }
    assert_eq!(body["data"]["type_counts"], json!({"1": 2, "41": 1}));
    // 密钥不得进入响应体。
    assert!(!body.to_string().contains("sk-secret-list"));

    // status 过滤：enabled 只留 status=1；disabled 留 3。
    let body = assert_success(
        send(
            &app,
            Method::GET,
            "/api/channel/?status=enabled",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["total"], json!(2));
    let body = assert_success(
        send(
            &app,
            Method::GET,
            "/api/channel/?status=disabled",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["total"], json!(1));
    // type 过滤。
    let body = assert_success(
        send(
            &app,
            Method::GET,
            "/api/channel/?type=41",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["total"], json!(1));
    assert_eq!(body["data"]["items"][0]["id"], json!(2));
    // group 过滤（含分组的逗号列表语义）。
    let body = assert_success(
        send(
            &app,
            Method::GET,
            "/api/channel/?group=vip",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["total"], json!(1));
    assert_eq!(body["data"]["items"][0]["id"], json!(1));
    // 分页。
    let body = assert_success(
        send(
            &app,
            Method::GET,
            "/api/channel/?p=1&page_size=2",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["items"].as_array().unwrap().len(), 2);
    let body = assert_success(
        send(
            &app,
            Method::GET,
            "/api/channel/?p=2&page_size=2",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["items"].as_array().unwrap().len(), 1);
    let body = assert_success(
        send(
            &app,
            Method::GET,
            "/api/channel/?page_size=1000",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["page_size"], json!(100));
    // sort_by=name asc。
    let body = assert_success(
        send(
            &app,
            Method::GET,
            "/api/channel/?sort_by=name&sort_order=asc",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    let names: Vec<&str> = body["data"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["alpha", "beta", "gamma"]);

    // ---- 标签模式：total=标签数，items 为标签下全部渠道 ------------
    let body = assert_success(
        send(
            &app,
            Method::GET,
            "/api/channel/?tag_mode=true",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["total"], json!(2));
    assert_eq!(body["data"]["items"].as_array().unwrap().len(), 2);

    // ---- 搜索 ------------------------------------------------------
    let body = assert_success(
        send(
            &app,
            Method::GET,
            "/api/channel/search?keyword=beta",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["total"], json!(1));
    assert_eq!(body["data"]["items"].as_array().unwrap().len(), 1);
    assert_eq!(body["data"]["type_counts"], json!({"41": 1}));
    // 搜索无 page/page_size 字段。
    assert!(body["data"].get("page").is_none());
    // model 过滤 + 分组。
    let body = assert_success(
        send(
            &app,
            Method::GET,
            "/api/channel/search?model=m2",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["total"], json!(1));
    // 搜索的分页（默认 20）。
    let body = assert_success(
        send(
            &app,
            Method::GET,
            "/api/channel/search?p=1&page_size=1",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["items"].as_array().unwrap().len(), 1);

    // ---- 详情 ------------------------------------------------------
    let body =
        assert_success(send(&app, Method::GET, "/api/channel/1", Some(&admin), None).await).await;
    assert_eq!(body["data"]["name"], json!("alpha"));
    assert_eq!(body["data"]["key"], json!(""));
    assert_eq!(body["data"]["group"], json!("default,vip"));
    assert_eq!(body["data"]["tag"], json!("beta"));
    // 不存在的渠道：200 + success:false + channel.not_exists。
    let body = assert_business_error(
        send(&app, Method::GET, "/api/channel/999", Some(&admin), None).await,
        "channel.not_exists",
    )
    .await;
    assert!(body["data"].is_null() || body.get("data").is_none());
    // 非数字 id：channel.id_format_error。
    assert_business_error(
        send(
            &app,
            Method::GET,
            "/api/channel/not-a-number",
            Some(&admin),
            None,
        )
        .await,
        "channel.id_format_error",
    )
    .await;

    // ---- 创建 ------------------------------------------------------
    let body = assert_success(
        send(
            &app,
            Method::POST,
            "/api/channel/",
            Some(&admin),
            Some(&json!({
                "mode": "single",
                "channel": {
                    "type": 1,
                    "name": "created-one",
                    "key": "sk-created",
                    "models": "m1,m2",
                    "group": "default,vip",
                },
            })),
        )
        .await,
    )
    .await;
    assert!(body.get("data").is_none() || body["data"].is_null());
    let rows = channel_rows(&db).await;
    assert!(
        rows.iter()
            .any(|(id, name, _)| *id == 4 && name == "created-one")
    );
    // abilities 笛卡尔积 + 全部启用。
    let abilities = ability_rows(&db, 4).await;
    assert_eq!(
        abilities,
        vec![
            ("default".to_owned(), "m1".to_owned(), true),
            ("default".to_owned(), "m2".to_owned(), true),
            ("vip".to_owned(), "m1".to_owned(), true),
            ("vip".to_owned(), "m2".to_owned(), true),
        ]
    );
    // 创建审计。
    let audits = manage_audit_contents(&db).await;
    assert!(
        audits
            .iter()
            .any(|content| content.contains("Created channel created-one"))
    );

    // 缺 key 与非法 mode 走业务错误。
    assert_business_error(
        send(
            &app,
            Method::POST,
            "/api/channel/",
            Some(&admin),
            Some(&json!({"mode": "single", "channel": {"type": 1, "name": "x", "models": "m1"}})),
        )
        .await,
        "channel.channel_required",
    )
    .await;
    assert_business_error(
        send(
            &app,
            Method::POST,
            "/api/channel/",
            Some(&admin),
            Some(&json!({"mode": "weird", "channel": {"type": 1, "key": "k", "models": "m1"}})),
        )
        .await,
        "channel.unsupported_add_mode",
    )
    .await;
    // 非法 JSON 走 invalid params；模型名超 255 走 model_name_too_long。
    assert_business_error(
        send_raw(&app, Method::POST, "/api/channel/", &admin, b"{bad").await,
        "common.invalid_params",
    )
    .await;
    let long_model = "a".repeat(256);
    assert_business_error(
        send(
            &app,
            Method::POST,
            "/api/channel/",
            Some(&admin),
            Some(&json!({
                "mode": "single",
                "channel": {"type": 1, "key": "k", "models": long_model, "name": "x"},
            })),
        )
        .await,
        "channel.model_name_too_long",
    )
    .await;

    // batch 模式：三个 key（一个为空）建两行。
    assert_success(
        send(
            &app,
            Method::POST,
            "/api/channel/",
            Some(&admin),
            Some(&json!({
                "mode": "batch",
                "channel": {
                    "type": 1,
                    "name": "batched",
                    "key": "k1\n\nk2",
                    "models": "m1",
                    "group": "default",
                },
            })),
        )
        .await,
    )
    .await;
    let rows = channel_rows(&db).await;
    let batched: Vec<_> = rows
        .iter()
        .filter(|(_, name, _)| name == "batched")
        .collect();
    assert_eq!(batched.len(), 2);
    assert_eq!(ability_rows(&db, batched[0].0).await.len(), 1);

    // multi_to_single：一行多 key，channel_info 记录。
    assert_success(
        send(
            &app,
            Method::POST,
            "/api/channel/",
            Some(&admin),
            Some(&json!({
                "mode": "multi_to_single",
                "multi_key_mode": "polling",
                "channel": {
                    "type": 1,
                    "name": "multi",
                    "key": "mk1\nmk2",
                    "models": "m1",
                    "group": "default",
                },
            })),
        )
        .await,
    )
    .await;
    let body = assert_success(
        send(
            &app,
            Method::GET,
            "/api/channel/?type=1",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    let multi = body["data"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["name"] == "multi")
        .expect("multi channel");
    assert_eq!(multi["channel_info"]["is_multi_key"], json!(true));
    assert_eq!(multi["channel_info"]["multi_key_size"], json!(2));
    assert_eq!(multi["channel_info"]["multi_key_mode"], json!("polling"));

    // ---- 更新 ------------------------------------------------------
    // 非敏感字段（name）admin 可改；响应是重载行且 key 抹空。
    let body = assert_success(
        send(
            &app,
            Method::PUT,
            "/api/channel/",
            Some(&admin),
            Some(&json!({"id": 1, "name": "alpha-renamed", "models": "m1,m3"})),
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["name"], json!("alpha-renamed"));
    assert_eq!(body["data"]["models"], json!("m1,m3"));
    assert_eq!(body["data"]["key"], json!(""));
    let abilities = ability_rows(&db, 1).await;
    assert_eq!(
        abilities,
        vec![
            ("default".to_owned(), "m1".to_owned(), true),
            ("default".to_owned(), "m3".to_owned(), true),
            ("vip".to_owned(), "m1".to_owned(), true),
            ("vip".to_owned(), "m3".to_owned(), true),
        ]
    );

    // status 字段禁止走更新端点（Go 的 MsgInvalidParams）。
    assert_business_error(
        send(
            &app,
            Method::PUT,
            "/api/channel/",
            Some(&admin),
            Some(&json!({"id": 1, "status": 1})),
        )
        .await,
        "common.invalid_params",
    )
    .await;

    // 敏感字段（type）对 ChannelWrite-only 的 admin 是 handler 内拒绝：
    // HTTP 200 + success:false（不是 403）。
    let body = assert_business_error(
        send(
            &app,
            Method::PUT,
            "/api/channel/",
            Some(&admin),
            Some(&json!({"id": 1, "type": 41})),
        )
        .await,
        "auth.insufficient_privilege",
    )
    .await;
    assert!(body.get("code").is_none() || body["code"].is_null());

    // 授予 admin 敏感写权限后同请求放行。
    backend!(&db, pool, {
        sqlx::query("INSERT INTO casbin_rule (ptype,v0,v1,v2,v3) VALUES ('p','user:1','channel','sensitive_write','allow')")
            .execute(pool)
            .await
            .expect("grant sensitive_write");
    });
    let body = assert_success(
        send(
            &app,
            Method::PUT,
            "/api/channel/",
            Some(&admin),
            Some(&json!({"id": 1, "type": 41})),
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["type"], json!(41));
    // 更新审计记录 changed_fields。
    let audits = manage_audit_contents(&db).await;
    assert!(
        audits
            .iter()
            .any(|content| content.contains("Updated channel alpha-renamed"))
    );

    // 更新不存在的渠道。
    assert_business_error(
        send(
            &app,
            Method::PUT,
            "/api/channel/",
            Some(&admin),
            Some(&json!({"id": 999, "name": "x"})),
        )
        .await,
        "channel.not_exists",
    )
    .await;

    // ---- 删除 ------------------------------------------------------
    assert_success(send(&app, Method::DELETE, "/api/channel/4", Some(&admin), None).await).await;
    let rows = channel_rows(&db).await;
    assert!(!rows.iter().any(|(id, _, _)| *id == 4));
    assert!(ability_rows(&db, 4).await.is_empty());
    // root 也能删除（superuser 短路）。
    assert_success(send(&app, Method::DELETE, "/api/channel/2", Some(&root), None).await).await;

    // 删除审计。
    let audits = manage_audit_contents(&db).await;
    assert!(
        audits
            .iter()
            .any(|content| content.contains("Deleted channel created-one"))
    );

    // ---- 清理已禁用 --------------------------------------------------
    let body = assert_success(
        send(
            &app,
            Method::DELETE,
            "/api/channel/disabled",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"], json!(1));
    let rows = channel_rows(&db).await;
    assert!(!rows.iter().any(|(_, _, status)| *status == 3));

    // ---- 批量删除 ----------------------------------------------------
    let before = channel_rows(&db).await.len();
    let body = assert_success(
        send(
            &app,
            Method::POST,
            "/api/channel/batch",
            Some(&admin),
            Some(&json!({"ids": [3]})),
        )
        .await,
    )
    .await;
    assert_eq!(body["data"], json!(1));
    assert_eq!(channel_rows(&db).await.len(), before - 1);
    assert_business_error(
        send(
            &app,
            Method::POST,
            "/api/channel/batch",
            Some(&admin),
            Some(&json!({"ids": []})),
        )
        .await,
        "common.invalid_params",
    )
    .await;

    // ---- 权限中间件的 403 形态（admin_auth 之外、handler 内 RequirePermission）----
    // common 用户被 admin_auth 拦在 403；不重复断言。这里断言管理员的
    // 敏感写在移除授权后恢复拒绝（证明判定读取了 casbin 快照）。
    backend!(&db, pool, {
        sqlx::query("DELETE FROM casbin_rule WHERE v0 = 'user:1'")
            .execute(pool)
            .await
            .expect("revoke sensitive_write");
    });
    assert_business_error(
        send(
            &app,
            Method::PUT,
            "/api/channel/",
            Some(&admin),
            Some(&json!({"id": 1, "type": 1})),
        )
        .await,
        "auth.insufficient_privilege",
    )
    .await;
}

async fn send_raw(
    state: &AppState,
    method: Method,
    path: &str,
    authorization: &str,
    body: &[u8],
) -> Response {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, authorization)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_vec()))
        .unwrap();
    router(state.clone()).oneshot(request).await.unwrap()
}

#[tokio::test]
async fn sqlite_channel_routes_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    run_contract(Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn postgres_channel_routes_contract() {
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
        "channel_routes_{}_{}",
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
