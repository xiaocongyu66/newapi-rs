//! HTTP contracts for the `/api/log` read endpoints (admin list/search/stat,
//! self list/search/stat, channel affinity usage cache).
//!
//! Runs only in remote CI. Every scenario uses an isolated synthetic fixture
//! (in-memory SQLite or an isolated PostgreSQL schema); no service is started.
//! The PostgreSQL test is skipped when `TEST_POSTGRES_DSN` is absent.
//!
//! Go semantics notes (oracle: `apps/api/internal/usage/store_log.go`,
//! `internal/transport/handler/handle_logs.go`, `handle_affinity_cache.go`):
//! - Admin list/search order by `created_at DESC, id DESC` and join channel
//!   names from the channels table; the count is unlimited (full count).
//! - Self list/search order by `id DESC`, never fill channel names, strip
//!   `admin_info`/`audit_info` from `other`, and rewrite `id` to the in-page
//!   display sequence `start_idx + i + 1` (Go `formatUserLogs`).
//! - Both stat endpoints ignore the `type` query parameter and always
//!   aggregate `type = 2`; rpm/tpm is an independent last-60s rate query that
//!   does not apply start/end_timestamp.
//! - `GET /api/log/self/stat` lost its user scoping in Go commit 1bd571ec9
//!   (`SumUsedTokenInternal(..., "", tokenName)`), so it sums consumption
//!   tokens globally; this port replicates the observable behavior verbatim.
//! - The channel affinity usage cache write path is not ported, so the read
//!   always answers the Go cache-miss shape (echoed params, zero counters).

use std::sync::atomic::{AtomicU64, Ordering};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::Request,
    http::{Method, StatusCode, header},
    middleware,
    response::Response,
    routing::get,
};
use newapi_server::auth::{admin_auth, user_auth};
use newapi_server::{AppState, log_http};
use newapi_storage::Database;
use serde_json::{Value, json};
use sqlx::{
    ConnectOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::SqlitePoolOptions,
};
use tower::ServiceExt;

static NEXT: AtomicU64 = AtomicU64::new(0);

const SECRET: &str = "log-routes-fixture-secret";
const ADMIN_ID: i64 = 10;
const USER_A: i64 = 101;
const USER_B: i64 = 102;
const ADMIN_PAT: &str = "log-admin-pat";
const USER_A_PAT: &str = "log-user-a-pat";
const USER_B_PAT: &str = "log-user-b-pat";

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

const SQLITE_LOGS: &str = r#"CREATE TABLE logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id BIGINT NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL DEFAULT 0,
    type INTEGER NOT NULL DEFAULT 0,
    content TEXT NOT NULL DEFAULT '',
    username TEXT NOT NULL DEFAULT '',
    token_name TEXT NOT NULL DEFAULT '',
    model_name TEXT NOT NULL DEFAULT '',
    quota BIGINT NOT NULL DEFAULT 0,
    prompt_tokens BIGINT NOT NULL DEFAULT 0,
    completion_tokens BIGINT NOT NULL DEFAULT 0,
    use_time BIGINT NOT NULL DEFAULT 0,
    is_stream INTEGER NOT NULL DEFAULT 0,
    channel_id BIGINT NOT NULL DEFAULT 0,
    channel_name TEXT NOT NULL DEFAULT '',
    token_id BIGINT NOT NULL DEFAULT 0,
    "group" TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    request_id TEXT NOT NULL DEFAULT '',
    upstream_request_id TEXT NOT NULL DEFAULT '',
    other TEXT NOT NULL DEFAULT ''
)"#;

const POSTGRES_LOGS: &str = r#"CREATE TABLE logs (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL DEFAULT 0,
    type BIGINT NOT NULL DEFAULT 0,
    content TEXT NOT NULL DEFAULT '',
    username TEXT NOT NULL DEFAULT '',
    token_name TEXT NOT NULL DEFAULT '',
    model_name TEXT NOT NULL DEFAULT '',
    quota BIGINT NOT NULL DEFAULT 0,
    prompt_tokens BIGINT NOT NULL DEFAULT 0,
    completion_tokens BIGINT NOT NULL DEFAULT 0,
    use_time BIGINT NOT NULL DEFAULT 0,
    is_stream BOOLEAN NOT NULL DEFAULT FALSE,
    channel_id BIGINT NOT NULL DEFAULT 0,
    channel_name TEXT NOT NULL DEFAULT '',
    token_id BIGINT NOT NULL DEFAULT 0,
    "group" TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    request_id TEXT NOT NULL DEFAULT '',
    upstream_request_id TEXT NOT NULL DEFAULT '',
    other TEXT NOT NULL DEFAULT ''
)"#;

const SQLITE_CHANNELS: &str = r#"CREATE TABLE channels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL DEFAULT ''
)"#;

const POSTGRES_CHANNELS: &str = r#"CREATE TABLE channels (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL DEFAULT ''
)"#;

macro_rules! backend {
    ($db:expr, $pool:ident, $body:block) => {
        match $db {
            Database::Sqlite($pool) => $body,
            Database::Postgres($pool) => $body,
        }
    };
}

fn state(db: &Database) -> AppState {
    // PAT authentication uses only the database; no SessionAuth is needed.
    AppState::default().bind_runtime(db.clone(), SECRET)
}

/// Admin routes carry `admin_auth`, self routes carry `user_auth`, matching
/// the Go registration (one auth chain per route, never stacked).
fn router(state: AppState) -> Router {
    let admin = Router::new()
        .route("/api/log/", get(log_http::list_logs))
        .route("/api/log/search", get(log_http::list_logs))
        .route("/api/log/stat", get(log_http::logs_stat))
        .route(
            "/api/log/channel_affinity_usage_cache",
            get(log_http::channel_affinity_usage_cache),
        )
        .route_layer(middleware::from_fn_with_state(state.clone(), admin_auth));
    let self_routes = Router::new()
        .route("/api/log/self", get(log_http::list_user_logs))
        .route("/api/log/self/search", get(log_http::list_user_logs))
        .route("/api/log/self/stat", get(log_http::logs_self_stat))
        .route_layer(middleware::from_fn_with_state(state.clone(), user_auth));
    admin.merge(self_routes).with_state(state)
}

fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}

async fn sqlite_fixture() -> Database {
    let pool = SqlitePoolOptions::new()
        .max_connections(2)
        .connect(":memory:")
        .await
        .expect("in-memory SQLite fixture");
    Database::Sqlite(pool)
}

/// Isolated PostgreSQL schema per test run (admin_2fa_routes pattern).
async fn postgres_fixture() -> Option<Database> {
    let Ok(dsn) = std::env::var("TEST_POSTGRES_DSN") else {
        return None;
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
        "log_routes_{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
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
    Some(Database::Postgres(pool))
}

async fn setup(db: &Database) {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query(SQLITE_USERS)
                .execute(pool)
                .await
                .expect("users");
            sqlx::query(SQLITE_LOGS).execute(pool).await.expect("logs");
            sqlx::query(SQLITE_CHANNELS)
                .execute(pool)
                .await
                .expect("channels");
        }
        Database::Postgres(pool) => {
            sqlx::query(POSTGRES_USERS)
                .execute(pool)
                .await
                .expect("users");
            sqlx::query(POSTGRES_LOGS)
                .execute(pool)
                .await
                .expect("logs");
            sqlx::query(POSTGRES_CHANNELS)
                .execute(pool)
                .await
                .expect("channels");
        }
    }
}

async fn reset(db: &Database) {
    backend!(db, pool, {
        for table in ["logs", "channels", "users"] {
            sqlx::query(sqlx::AssertSqlSafe(format!("DELETE FROM {table}")))
                .execute(pool)
                .await
                .expect("reset table");
        }
    });
}

async fn seed_user(db: &Database, id: i64, role: i64, pat: &str) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO users
                (id,username,display_name,role,status,"group",auth_version,access_token)
                VALUES ($1,$2,'Fixture',$3,1,'default',1,$4)"#,
        )
        .bind(id)
        .bind(format!("user{id}"))
        .bind(role)
        .bind(pat)
        .execute(pool)
        .await
        .expect("seed user");
    });
}

async fn seed_channel(db: &Database, id: i64, name: &str) {
    backend!(db, pool, {
        sqlx::query("INSERT INTO channels (id, name) VALUES ($1, $2)")
            .bind(id)
            .bind(name)
            .execute(pool)
            .await
            .expect("seed channel");
    });
}

struct LogSeed<'a> {
    user_id: i64,
    created_at: i64,
    log_type: i64,
    token_name: &'a str,
    model_name: &'a str,
    quota: i64,
    prompt_tokens: i64,
    completion_tokens: i64,
    channel_id: i64,
    request_id: &'a str,
    other: &'a str,
}

impl<'a> LogSeed<'a> {
    fn consume(user_id: i64, created_at: i64, model_name: &'a str, quota: i64) -> Self {
        Self {
            user_id,
            created_at,
            log_type: 2,
            token_name: "seed-token",
            model_name,
            quota,
            prompt_tokens: 10,
            completion_tokens: 20,
            channel_id: 0,
            request_id: "",
            other: "{}",
        }
    }
}

async fn seed_log(db: &Database, seed: &LogSeed<'_>) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO logs
                (user_id,created_at,type,content,username,token_name,model_name,quota,
                 prompt_tokens,completion_tokens,use_time,is_stream,channel_id,
                 token_id,"group",ip,request_id,upstream_request_id,other)
                VALUES ($1,$2,$3,'seed-content','seed-user',$4,$5,$6,$7,$8,13,FALSE,$9,
                        0,'default','',$10,'',$11)"#,
        )
        .bind(seed.user_id)
        .bind(seed.created_at)
        .bind(seed.log_type)
        .bind(seed.token_name)
        .bind(seed.model_name)
        .bind(seed.quota)
        .bind(seed.prompt_tokens)
        .bind(seed.completion_tokens)
        .bind(seed.channel_id)
        .bind(seed.request_id)
        .bind(seed.other)
        .execute(pool)
        .await
        .expect("seed log");
    });
}

async fn send(state: &AppState, path: &str, pat: &str) -> Response {
    let request = Request::builder()
        .method(Method::GET)
        .uri(path)
        .header(header::AUTHORIZATION, pat)
        .body(Body::empty())
        .unwrap();
    router(state.clone()).oneshot(request).await.unwrap()
}

async fn send_anonymous(state: &AppState, path: &str) -> Response {
    let request = Request::builder()
        .method(Method::GET)
        .uri(path)
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

fn translated(key: &str) -> String {
    newapi_i18n::translate("en", key, std::iter::empty::<(&str, &str)>())
}

async fn assert_list_success(
    response: Response,
    expected_total: i64,
    expected_len: usize,
) -> Value {
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true), "list call failed: {body}");
    assert_eq!(body["message"], json!(""));
    assert_eq!(body["data"]["total"], json!(expected_total));
    assert_eq!(
        body["data"]["items"].as_array().map(Vec::len),
        Some(expected_len)
    );
    body
}

async fn run_admin_list_contract(db: &Database) {
    setup(db).await;
    let state = state(db);
    seed_user(db, ADMIN_ID, 10, ADMIN_PAT).await;
    seed_user(db, USER_A, 1, USER_A_PAT).await;

    // 非管理员命中 AdminAuth 的角色门槛：403。
    let response = send(&state, "/api/log/", USER_A_PAT).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    seed_channel(db, 7, "channel-seven").await;
    seed_log(
        db,
        &LogSeed {
            channel_id: 7,
            ..LogSeed::consume(USER_A, 1_700_000_000, "gpt-4o", 1000)
        },
    )
    .await;
    seed_log(
        db,
        &LogSeed {
            user_id: USER_B,
            ..LogSeed::consume(USER_B, 1_700_000_100, "claude-3", 2000)
        },
    )
    .await;

    // 默认分页：page 1、page_size 10；排序 created_at DESC, id DESC；渠道名
    // 由 channels 表回填（channel_id=0 的行渠道名为空串）。
    let body = assert_list_success(send(&state, "/api/log/", ADMIN_PAT).await, 2, 2).await;
    assert_eq!(body["data"]["page"], json!(1));
    assert_eq!(body["data"]["page_size"], json!(10));
    let items = body["data"]["items"].as_array().unwrap();
    assert_eq!(items[0]["model_name"], json!("claude-3"));
    assert_eq!(items[0]["channel"], json!(0));
    assert_eq!(items[0]["channel_name"], json!(""));
    assert_eq!(items[1]["model_name"], json!("gpt-4o"));
    assert_eq!(items[1]["channel_name"], json!("channel-seven"));
    assert_eq!(items[1]["quota"], json!(1000));

    // `type` 过滤（无命中时 total=0、items=[]）。
    let body = assert_list_success(send(&state, "/api/log/?type=5", ADMIN_PAT).await, 0, 0).await;
    assert_eq!(body["data"]["items"], json!([]));

    // model_name 精确匹配与 `%` 模糊匹配。
    assert_list_success(
        send(&state, "/api/log/?model_name=claude-3", ADMIN_PAT).await,
        1,
        1,
    )
    .await;
    assert_list_success(
        send(&state, "/api/log/?model_name=%25claude%25", ADMIN_PAT).await,
        1,
        1,
    )
    .await;

    // username 精确匹配（管理端独有字段）。
    assert_list_success(
        send(&state, "/api/log/?username=seed-user", ADMIN_PAT).await,
        2,
        2,
    )
    .await;
    assert_list_success(
        send(&state, "/api/log/?username=nobody", ADMIN_PAT).await,
        0,
        0,
    )
    .await;

    // channel 与 group 过滤。
    assert_list_success(send(&state, "/api/log/?channel=7", ADMIN_PAT).await, 1, 1).await;
    assert_list_success(
        send(&state, "/api/log/?group=default", ADMIN_PAT).await,
        2,
        2,
    )
    .await;
    assert_list_success(send(&state, "/api/log/?group=vip", ADMIN_PAT).await, 0, 0).await;

    // 时间窗过滤。
    assert_list_success(
        send(
            &state,
            "/api/log/?start_timestamp=1700000050&end_timestamp=1700000200",
            ADMIN_PAT,
        )
        .await,
        1,
        1,
    )
    .await;

    // 空响应过滤：other 内含 empty_response_multiplier 的行才命中。
    seed_log(
        db,
        &LogSeed {
            other: r#"{"empty_response_multiplier":1.5}"#,
            ..LogSeed::consume(USER_A, 1_700_000_200, "gpt-4o", 300)
        },
    )
    .await;
    assert_list_success(
        send(&state, "/api/log/?empty_response=1", ADMIN_PAT).await,
        1,
        1,
    )
    .await;

    // LIKE 模式校验（3 个通配符超限）→ 200 + 固定翻译文案（Go 走
    // CtxApiError 的 200 分支）。
    let response = send(&state, "/api/log/?model_name=%25%25%25x", ADMIN_PAT).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false));
    assert_eq!(
        body["message"],
        json!(translated("token.search_wildcard_limit"))
    );

    // 分页别名与封顶：p=2&size=1 取第 2 新的行；page_size=999 封顶 100。
    let body =
        assert_list_success(send(&state, "/api/log/?p=2&size=1", ADMIN_PAT).await, 3, 1).await;
    assert_eq!(body["data"]["page"], json!(2));
    assert_eq!(body["data"]["page_size"], json!(1));
    assert_eq!(body["data"]["items"][0]["model_name"], json!("claude-3"));
    let body = assert_list_success(
        send(&state, "/api/log/?page_size=999", ADMIN_PAT).await,
        3,
        3,
    )
    .await;
    assert_eq!(body["data"]["page_size"], json!(100));

    // /api/log/search 与列表同一 handler。
    assert_list_success(
        send(&state, "/api/log/search?channel=7", ADMIN_PAT).await,
        1,
        1,
    )
    .await;

    reset(db).await;
}

async fn run_self_list_contract(db: &Database) {
    setup(db).await;
    let state = state(db);
    seed_user(db, ADMIN_ID, 10, ADMIN_PAT).await;
    seed_user(db, USER_A, 1, USER_A_PAT).await;
    seed_user(db, USER_B, 1, USER_B_PAT).await;

    seed_log(
        db,
        &LogSeed {
            user_id: USER_A,
            other: r#"{"admin_info":{"k":1},"audit_info":{"r":2},"keep":"v"}"#,
            ..LogSeed::consume(USER_A, 1_700_000_000, "gpt-4o", 500)
        },
    )
    .await;
    seed_log(
        db,
        &LogSeed {
            user_id: USER_A,
            ..LogSeed::consume(USER_A, 1_700_000_500, "gpt-4o", 500)
        },
    )
    .await;
    seed_log(
        db,
        &LogSeed {
            user_id: USER_B,
            ..LogSeed::consume(USER_B, 1_700_000_300, "gpt-4o", 500)
        },
    )
    .await;

    // 自助列表按 id DESC 排序；id 重写为分页内序号（start_idx + i + 1）；
    // channel_name 恒空串；other 剥离 admin_info/audit_info；USER_B 不可见。
    let body = assert_list_success(send(&state, "/api/log/self", USER_A_PAT).await, 2, 2).await;
    let items = body["data"]["items"].as_array().unwrap();
    assert_eq!(items[0]["id"], json!(1));
    assert_eq!(items[1]["id"], json!(2));
    assert_eq!(items[0]["channel_name"], json!(""));
    assert_eq!(items[1]["channel_name"], json!(""));
    assert_eq!(items[0]["other"], json!(r#"{}"#));
    assert_eq!(items[1]["other"], json!(r#"{"keep":"v"}"#));

    // 第二页（size=1）的显示序号从 start_idx+1 起。
    let body = assert_list_success(
        send(&state, "/api/log/self?p=2&size=1", USER_A_PAT).await,
        2,
        1,
    )
    .await;
    assert_eq!(body["data"]["items"][0]["id"], json!(2));

    // username/channel 查询参数被忽略：不越权也不过滤自己。
    assert_list_success(
        send(
            &state,
            "/api/log/self?username=seed-user&channel=7",
            USER_A_PAT,
        )
        .await,
        2,
        2,
    )
    .await;

    // type 过滤 + 时间窗。
    assert_list_success(
        send(
            &state,
            "/api/log/self?type=2&start_timestamp=1700000400",
            USER_A_PAT,
        )
        .await,
        1,
        1,
    )
    .await;

    // USER_B 只看到自己的行。
    assert_list_success(send(&state, "/api/log/self", USER_B_PAT).await, 1, 1).await;

    // /api/log/self/search 与列表同一 handler。
    assert_list_success(
        send(&state, "/api/log/self/search?model_name=gpt-4o", USER_A_PAT).await,
        2,
        2,
    )
    .await;
    let response = send(
        &state,
        "/api/log/self/search?model_name=%25a%25b%25c",
        USER_A_PAT,
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false));
    assert_eq!(
        body["message"],
        json!(translated("token.search_wildcard_limit"))
    );

    // 未登录是 401（UserAuth 缺凭据）。
    let response = send_anonymous(&state, "/api/log/self").await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    reset(db).await;
}

async fn run_admin_stat_contract(db: &Database, now: i64) {
    setup(db).await;
    let state = state(db);
    seed_user(db, ADMIN_ID, 10, ADMIN_PAT).await;
    seed_user(db, USER_A, 1, USER_A_PAT).await;

    // type=1（充值）与 60 秒窗口外的消费行的差异：quota 汇总含全部 type=2，
    // rpm/tpm 只看最近 60 秒且不套用 start/end_timestamp。
    seed_log(
        db,
        &LogSeed {
            log_type: 1,
            quota: 99_999,
            ..LogSeed::consume(USER_A, now - 30, "gpt-4o", 99_999)
        },
    )
    .await;
    seed_log(
        db,
        &LogSeed {
            ..LogSeed::consume(USER_A, now - 120, "gpt-4o", 5000)
        },
    )
    .await;
    seed_log(
        db,
        &LogSeed {
            quota: 3000,
            prompt_tokens: 100,
            completion_tokens: 200,
            ..LogSeed::consume(USER_A, now - 5, "gpt-4o", 3000)
        },
    )
    .await;

    // `type=1` 参数被 Go 忽略：聚合仍只看 type=2。
    let response = send(&state, "/api/log/stat?type=1", ADMIN_PAT).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true));
    assert_eq!(body["data"]["quota"], json!(8000));
    assert_eq!(body["data"]["rpm"], json!(1));
    assert_eq!(body["data"]["tpm"], json!(300));

    // 过滤字段生效（无命中归零，rpm/tpm 同样归零）。
    let response = send(&state, "/api/log/stat?model_name=none", ADMIN_PAT).await;
    let body = body_json(response).await;
    assert_eq!(body["data"]["quota"], json!(0));
    assert_eq!(body["data"]["rpm"], json!(0));
    assert_eq!(body["data"]["tpm"], json!(0));

    // LIKE 模式校验在统计端是 400（Go 显式 Bad Request 分支）。
    let response = send(&state, "/api/log/stat?model_name=%25%25%25x", ADMIN_PAT).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false));
    assert_eq!(
        body["message"],
        json!(translated("token.search_wildcard_limit"))
    );

    reset(db).await;
}

async fn run_self_stat_contract(db: &Database, now: i64) {
    setup(db).await;
    let state = state(db);
    seed_user(db, ADMIN_ID, 10, ADMIN_PAT).await;
    seed_user(db, USER_A, 1, USER_A_PAT).await;
    seed_user(db, USER_B, 1, USER_B_PAT).await;

    // Go oracle（1bd571ec9 起丢失 user 限定）：所有 type=2 行的
    // prompt+completion 都计入，含 USER_B 的行；type=1 不计。
    seed_log(
        db,
        &LogSeed {
            log_type: 1,
            prompt_tokens: 888_888,
            ..LogSeed::consume(USER_A, now - 30, "gpt-4o", 0)
        },
    )
    .await;
    seed_log(
        db,
        &LogSeed {
            prompt_tokens: 100,
            completion_tokens: 50,
            ..LogSeed::consume(USER_A, now - 30, "gpt-4o", 0)
        },
    )
    .await;
    seed_log(
        db,
        &LogSeed {
            user_id: USER_B,
            prompt_tokens: 7,
            completion_tokens: 3,
            ..LogSeed::consume(USER_B, now - 30, "gpt-4o", 0)
        },
    )
    .await;

    let response = send(&state, "/api/log/self/stat", USER_A_PAT).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true));
    assert_eq!(body["data"]["token"], json!(160));

    // token_name 与时间窗过滤。
    let response = send(
        &state,
        "/api/log/self/stat?token_name=seed-token",
        USER_A_PAT,
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["data"]["token"], json!(160));
    let response = send(
        &state,
        &format!("/api/log/self/stat?end_timestamp={}", now - 120),
        USER_A_PAT,
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["data"]["token"], json!(0));

    // 未登录是 401。
    let response = send_anonymous(&state, "/api/log/self/stat").await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    reset(db).await;
}

async fn run_affinity_contract(db: &Database) {
    setup(db).await;
    let state = state(db);
    seed_user(db, ADMIN_ID, 10, ADMIN_PAT).await;

    // 缺 rule_name / key_fp 是 400 + Go 字面量（trim 后判空）。
    for (query, expected) in [
        ("", "missing param: rule_name"),
        ("?using_group=vip", "missing param: rule_name"),
        ("?rule_name=r", "missing param: key_fp"),
        ("?rule_name=%20", "missing param: rule_name"),
    ] {
        let response = send(
            &state,
            &format!("/api/log/channel_affinity_usage_cache{query}"),
            ADMIN_PAT,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "query: {query}");
        let body = body_json(response).await;
        assert_eq!(body["success"], json!(false));
        assert_eq!(body["message"], json!(expected));
    }

    // 缓存语义：写侧未移植，缓存恒空 → Go 未命中形态（回显 trim 后参数 +
    // 全零计数器）。
    let response = send(
        &state,
        "/api/log/channel_affinity_usage_cache?rule_name=%20rule%20&using_group=%20vip%20&key_fp=fp",
        ADMIN_PAT,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true), "list call failed: {body}");
    assert_eq!(body["message"], json!(""));
    assert_eq!(
        body["data"],
        json!({
            "rule_name": "rule",
            "using_group": "vip",
            "key_fp": "fp",
            "cached_token_rate_mode": "",
            "hit": 0,
            "total": 0,
            "window_seconds": 0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "cached_tokens": 0,
            "prompt_cache_hit_tokens": 0,
            "last_seen_at": 0,
        })
    );

    reset(db).await;
}

#[tokio::test]
async fn sqlite_log_routes_contract() {
    let db = sqlite_fixture().await;
    let now = now_seconds();
    run_admin_list_contract(&db).await;
    run_self_list_contract(&db).await;
    run_admin_stat_contract(&db, now).await;
    run_self_stat_contract(&db, now).await;
    run_affinity_contract(&db).await;
}

#[tokio::test]
async fn postgres_log_routes_contract() {
    let Some(db) = postgres_fixture().await else {
        return;
    };
    let now = now_seconds();
    run_admin_list_contract(&db).await;
    run_self_list_contract(&db).await;
    run_admin_stat_contract(&db, now).await;
    run_self_stat_contract(&db, now).await;
    run_affinity_contract(&db).await;
}
