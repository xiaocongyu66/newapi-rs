//! HTTP contracts for the four dashboard-facing QQ routes:
//! `GET /api/user/qq/bind`, `POST /api/user/qq/bind/code`,
//! `DELETE /api/user/qq/bind`, `POST /api/user/qq/panel/sync`.
//!
//! Runs only in remote CI. Every scenario uses an isolated synthetic fixture
//! (in-memory SQLite or an isolated PostgreSQL schema); no service is started.
//! The PostgreSQL test is skipped when `TEST_POSTGRES_DSN` is absent.
//!
//! Go references:
//! - `apps/api/internal/billing/manage_qqbot.go:344-411` (the four handlers)
//! - `apps/api/internal/transport/compose/register_api.go:193-197`
//!   (route chains; only `/qq/bind/code` carries `DisableCache`)
//! - `apps/api/internal/identity/qq_binding.go` (code lifecycle, unbind)
//! - `apps/api/internal/billing/qqbot_setting.go` (`qq_bot_setting` defaults)
//!
//! The test router mirrors the Go chains minus the rate limiter, exactly like
//! the other contract tests: limiters are covered by their own tests, and the
//! handler-observable behaviour is identical without them. `DisableCache` is
//! likewise omitted here (it only adds response headers, no status or body
//! change).
//!
//! Envelope shapes differ per handler and are asserted verbatim:
//! `CtxApiSuccess` routes (`GET /qq/bind`, `POST /qq/bind/code`) carry an
//! empty `message`; the hand-written `common.H` routes (`DELETE /qq/bind`,
//! `POST /qq/panel/sync`) carry a message and **no** `data` key.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
    middleware,
    response::Response,
};
use newapi_server::{
    AppState,
    auth::{admin_auth, user_auth},
    qq_bind_http, qqbot,
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

const SECRET: &str = "qq-bind-routes-fixture-secret";
const USER_ID: i64 = 7;
const ADMIN_ID: i64 = 10;
const PAT: &str = "pat-qq-bind";
const ADMIN_PAT: &str = "pat-qq-admin";

/// Go `identity.QQBinding`（`qq_binding.go:16-23`）：`user_id` 与 `open_id`
/// 都是唯一索引，`username` / `created_at` 可空。
const QQ_BINDINGS: &str = r#"CREATE TABLE qq_bindings (
    id INTEGER PRIMARY KEY,
    user_id BIGINT NOT NULL UNIQUE,
    open_id VARCHAR(128) NOT NULL UNIQUE,
    union_open_id VARCHAR(128),
    username VARCHAR(64),
    created_at BIGINT
)"#;

const QQ_BINDINGS_POSTGRES: &str = r#"CREATE TABLE qq_bindings (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL UNIQUE,
    open_id VARCHAR(128) NOT NULL UNIQUE,
    union_open_id VARCHAR(128),
    username VARCHAR(64),
    created_at BIGINT
)"#;

/// Go `identity.QQBindCode`（`qq_binding.go:30-37`）：`code` 唯一索引，
/// `used` 带 `default:false`，`expired_at` 有索引。
const QQ_BIND_CODES: &str = r#"CREATE TABLE qq_bind_codes (
    id INTEGER PRIMARY KEY,
    code VARCHAR(16) NOT NULL UNIQUE,
    user_id BIGINT NOT NULL,
    expired_at BIGINT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    created_at BIGINT
)"#;

const QQ_BIND_CODES_POSTGRES: &str = r#"CREATE TABLE qq_bind_codes (
    id BIGSERIAL PRIMARY KEY,
    code VARCHAR(16) NOT NULL UNIQUE,
    user_id BIGINT NOT NULL,
    expired_at BIGINT NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at BIGINT
)"#;

/// Go `identity.QQUnbindRecord`：主键就是 `user_id`。
const QQ_UNBIND_RECORDS: &str = r#"CREATE TABLE qq_unbind_records (
    user_id BIGINT PRIMARY KEY,
    unbind_at BIGINT NOT NULL,
    created_at BIGINT
)"#;

/// Go 硬编码文案（`manage_qqbot.go` / `qq_binding.go`），前端逐字比对。
const MSG_CHECKIN_DISABLED: &str = "QQ 签到功能未启用";
const MSG_ALREADY_BOUND: &str = "当前账号已绑定 QQ，请先解绑";
const MSG_COOLDOWN_PREFIX: &str = "解绑后需等待冷却时间才能重新绑定，剩余 ";
const MSG_COOLDOWN_SUFFIX: &str = " 秒";
const MSG_UNBOUND: &str = "解绑成功";
const MSG_PANEL_SYNCED: &str = "指令面板已同步到 QQ 平台";
const MSG_BOT_NOT_CONFIGURED: &str = "QQ 机器人未配置 AppID/AppSecret";
const MSG_PANEL_SYNC_FAILED: &str = "QQ 指令面板同步失败，请稍后重试";

/// Go `bindCodeAlphabet`：56 字符，无 0/O/o 与 1/l/I。
const BIND_CODE_ALPHABET: &str = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz";

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

macro_rules! backend {
    ($db:expr, $pool:ident, $body:block) => {
        match $db {
            Database::Sqlite($pool) => $body,
            Database::Postgres($pool) => $body,
        }
    };
}

fn router(state: AppState) -> Router {
    // 用户侧三条：`UserAuth`（限流与 DisableCache 由 `http.rs` 的生产路由器
    // 负责，契约测试不复刻，见模块注释）。
    let user = Router::new()
        .route(
            "/api/user/qq/bind",
            axum::routing::get(qq_bind_http::bind_status).delete(qq_bind_http::unbind),
        )
        .route(
            "/api/user/qq/bind/code",
            axum::routing::post(qq_bind_http::generate_bind_code),
        )
        .route_layer(middleware::from_fn_with_state(state.clone(), user_auth));
    // 管理员侧一条：Go 的注册顺序是组级 `UserAuth` → 路由级 `security.AdminAuth()`
    // → `CriticalRateLimit`；限流不在契约测试内复刻，两道鉴权都要有。
    let admin = Router::new()
        .route(
            "/api/user/qq/panel/sync",
            axum::routing::post(qq_bind_http::sync_panel),
        )
        .route_layer(middleware::from_fn_with_state(state.clone(), admin_auth))
        .route_layer(middleware::from_fn_with_state(state.clone(), user_auth));
    user.merge(admin).with_state(state)
}

fn state(db: &Database) -> AppState {
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

/// Upsert: scenarios rewrite the same keys.
async fn set_option(db: &Database, key: &str, value: &str) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO options ("key", "value") VALUES ($1, $2)
               ON CONFLICT ("key") DO UPDATE SET "value" = excluded."value""#,
        )
        .bind(key)
        .bind(value)
        .execute(pool)
        .await
        .expect("seed option");
    });
}

async fn seed_user(db: &Database, id: i64, pat: &str, role: i64) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO users
                (id,username,display_name,role,status,"group",auth_version,access_token)
                VALUES ($1,'fixture','Fixture',$2,1,'default',1,$3)"#,
        )
        .bind(id)
        .bind(role)
        .bind(pat)
        .execute(pool)
        .await
        .expect("seed user");
    });
}

/// `username` 为空串与 NULL 是两个分支：Go 的可空列都归零值空串。
async fn seed_binding(db: &Database, user_id: i64, username: Option<&str>, created_at: i64) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO qq_bindings (id,user_id,open_id,username,created_at)
               VALUES ($1,$2,$3,$4,$5)"#,
        )
        .bind(user_id)
        .bind(user_id)
        .bind(format!("OPENID-{user_id}"))
        .bind(username)
        .bind(created_at)
        .execute(pool)
        .await
        .expect("seed qq binding");
    });
}

async fn seed_code(db: &Database, user_id: i64, code: &str, used: bool, expired_at: i64) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO qq_bind_codes (code,user_id,expired_at,used,created_at)
               VALUES ($1,$2,$3,$4,$5)"#,
        )
        .bind(code)
        .bind(user_id)
        .bind(expired_at)
        .bind(used)
        .bind(1_700_000_000)
        .execute(pool)
        .await
        .expect("seed qq bind code");
    });
}

async fn seed_unbind_record(db: &Database, user_id: i64, unbind_at: i64) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO qq_unbind_records (user_id,unbind_at,created_at)
               VALUES ($1,$2,$3)"#,
        )
        .bind(user_id)
        .bind(unbind_at)
        .bind(unbind_at)
        .execute(pool)
        .await
        .expect("seed unbind record");
    });
}

/// `CAST(used AS INTEGER)`：SQLite 的 INTEGER 与 PostgreSQL 的 BOOLEAN 读成
/// 同一个整数（0/1），省一套方言分支。`expired_at` 同步 CAST 到 BIGINT：
/// Go 的 qq_bind_codes 建表用 INTEGER（INT4），PG 驱动按列类型解码 i64
/// 会报 INT4/INT8 不兼容（与 aff 余额断言同一类提升）。
async fn code_rows(db: &Database, user_id: i64) -> Vec<(String, i64, i64)> {
    backend!(db, pool, {
        sqlx::query_as::<_, (String, i64, i64)>(
            "SELECT code, CAST(used AS INTEGER), CAST(expired_at AS BIGINT) \
             FROM qq_bind_codes WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_all(pool)
        .await
        .expect("code rows")
    })
}

async fn binding_rows(db: &Database, user_id: i64) -> i64 {
    backend!(db, pool, {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM qq_bindings WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(pool)
            .await
            .expect("binding rows")
    })
}

async fn unbind_records(db: &Database, user_id: i64) -> Vec<i64> {
    backend!(db, pool, {
        sqlx::query_scalar::<_, i64>("SELECT unbind_at FROM qq_unbind_records WHERE user_id = $1")
            .bind(user_id)
            .fetch_all(pool)
            .await
            .expect("unbind records")
    })
}

async fn send(
    state: &AppState,
    method: Method,
    uri: &str,
    authorization: Option<&str>,
) -> Response {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(value) = authorization {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    router(state.clone())
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

/// 注入假 QQ 开放平台 API（与 `turnstile::InjectedVerifier` 同一约定）。
async fn send_panel(state: &AppState, api: Arc<dyn qqbot::QQBotApi>) -> Response {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri("/api/user/qq/panel/sync")
        .header(header::AUTHORIZATION, format!("Bearer {ADMIN_PAT}"))
        .body(Body::empty())
        .unwrap();
    request
        .extensions_mut()
        .insert(qqbot::InjectedQQBotApi(api));
    router(state.clone()).oneshot(request).await.unwrap()
}

async fn body_json(response: Response) -> Value {
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body");
    serde_json::from_slice(&bytes).expect("response JSON")
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Go `CtxApiSuccess` 的信封：`message` 恒为空串、必带 `data`。
async fn assert_api_success(response: Response) -> Value {
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true), "{body}");
    assert_eq!(body["message"], json!(""), "{body}");
    assert!(body.get("data").is_some(), "missing data: {body}");
    body
}

/// 手写 `common.H` 的信封：**没有** `data` 键。
async fn assert_plain_success(response: Response, message: &str) -> Value {
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true), "{body}");
    assert_eq!(body["message"], json!(message), "{body}");
    assert!(body.get("data").is_none(), "unexpected data: {body}");
    body
}

/// Go `common.CtxApiErrorMsg`：没有 `data` 键。
async fn assert_failure(response: Response, message: &str) -> Value {
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false), "{body}");
    assert_eq!(body["message"], json!(message), "{body}");
    assert!(body.get("data").is_none(), "unexpected data: {body}");
    body
}

fn assert_code_shape(code: &str) {
    assert!(
        code.starts_with('#'),
        "code must carry the # prefix: {code}"
    );
    assert_eq!(
        code.chars().count(),
        7,
        "code must be # plus six chars: {code}"
    );
    for character in code.chars().skip(1) {
        assert!(
            BIND_CODE_ALPHABET.contains(character),
            "{character} outside the bind-code alphabet"
        );
    }
}

// ---------------------------------------------------------------------------
// GET /api/user/qq/bind — Go `billing.GetQQBindStatus`
// ---------------------------------------------------------------------------

async fn run_get_contract(db: Database) {
    exec(&db, USERS).await;
    exec(&db, OPTIONS).await;
    exec(&db, qq_bindings_ddl(&db)).await;
    seed_user(&db, USER_ID, PAT, 1).await;
    let auth = format!("Bearer {PAT}");
    let app = state(&db);

    // UserAuth guards the route: no credential is 401.
    assert_eq!(
        send(&app, Method::GET, "/api/user/qq/bind", None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );

    // No options: Go process defaults (checkin off, one-hour rebind cooldown).
    assert_eq!(
        body_json(send(&app, Method::GET, "/api/user/qq/bind", Some(&auth)).await).await,
        json!({
            "success": true,
            "message": "",
            "data": {
                "qq_checkin_enabled": false,
                "bound": false,
                "rebind_cooldown_seconds": 3600,
            },
        }),
        "unbound response omits qq_username and bound_at"
    );

    // A bound user gains the two extra keys; `created_at` is echoed verbatim.
    seed_binding(&db, USER_ID, Some("杰瑞"), 1_700_000_000).await;
    let body =
        assert_api_success(send(&app, Method::GET, "/api/user/qq/bind", Some(&auth)).await).await;
    assert_eq!(body["data"]["bound"], json!(true), "{body}");
    assert_eq!(body["data"]["qq_username"], json!("杰瑞"), "{body}");
    assert_eq!(body["data"]["bound_at"], json!(1_700_000_000), "{body}");

    // NULL username decodes to the Go zero value (empty string), key stays.
    seed_binding(&db, 8, None, 0).await;
    seed_user(&db, 8, "pat-qq-bind-eight", 1).await;
    let pat_eight = "Bearer pat-qq-bind-eight";
    let body =
        assert_api_success(send(&app, Method::GET, "/api/user/qq/bind", Some(pat_eight)).await)
            .await;
    assert_eq!(body["data"]["bound"], json!(true), "{body}");
    assert_eq!(body["data"]["qq_username"], json!(""), "{body}");
    assert_eq!(body["data"]["bound_at"], json!(0), "{body}");

    // Option parsing follows `updateConfigFromMap`: ParseBool set only for
    // the bool, ParseInt→ParseFloat for the int, failure keeps the value.
    set_option(&db, "qq_bot_setting.qq_checkin_enabled", "yes").await;
    let body =
        assert_api_success(send(&app, Method::GET, "/api/user/qq/bind", Some(&auth)).await).await;
    assert_eq!(body["data"]["qq_checkin_enabled"], json!(false), "{body}");
    set_option(&db, "qq_bot_setting.qq_checkin_enabled", "TRUE").await;
    let body =
        assert_api_success(send(&app, Method::GET, "/api/user/qq/bind", Some(&auth)).await).await;
    assert_eq!(body["data"]["qq_checkin_enabled"], json!(true), "{body}");
    set_option(&db, "qq_bot_setting.rebind_cooldown_seconds", "abc").await;
    let body =
        assert_api_success(send(&app, Method::GET, "/api/user/qq/bind", Some(&auth)).await).await;
    assert_eq!(
        body["data"]["rebind_cooldown_seconds"],
        json!(3600),
        "{body}"
    );
    set_option(&db, "qq_bot_setting.rebind_cooldown_seconds", "7200.9").await;
    let body =
        assert_api_success(send(&app, Method::GET, "/api/user/qq/bind", Some(&auth)).await).await;
    assert_eq!(
        body["data"]["rebind_cooldown_seconds"],
        json!(7200),
        "{body}"
    );
    set_option(&db, "qq_bot_setting.rebind_cooldown_seconds", "0").await;
    let body =
        assert_api_success(send(&app, Method::GET, "/api/user/qq/bind", Some(&auth)).await).await;
    assert_eq!(body["data"]["rebind_cooldown_seconds"], json!(0), "{body}");
    // Another slice's keys never leak into this one.
    set_option(&db, "checkin_setting.enabled", "1").await;
    let body =
        assert_api_success(send(&app, Method::GET, "/api/user/qq/bind", Some(&auth)).await).await;
    assert_eq!(body["data"]["qq_checkin_enabled"], json!(true), "{body}");
}

fn qq_bindings_ddl(db: &Database) -> &'static str {
    match db {
        Database::Sqlite(_) => QQ_BINDINGS,
        Database::Postgres(_) => QQ_BINDINGS_POSTGRES,
    }
}

// ---------------------------------------------------------------------------
// POST /api/user/qq/bind/code — Go `billing.GenerateQQBindCode`
// ---------------------------------------------------------------------------

async fn run_code_contract(db: Database) {
    exec(&db, USERS).await;
    exec(&db, OPTIONS).await;
    exec(&db, qq_bindings_ddl(&db)).await;
    exec(&db, qq_bind_codes_ddl(&db)).await;
    exec(&db, QQ_UNBIND_RECORDS).await;
    seed_user(&db, USER_ID, PAT, 1).await;
    let auth = format!("Bearer {PAT}");
    let app = state(&db);

    assert_eq!(
        send(&app, Method::POST, "/api/user/qq/bind/code", None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );

    // The switch is checked before anything else (Go `manage_qqbot.go:368`).
    assert_failure(
        send(&app, Method::POST, "/api/user/qq/bind/code", Some(&auth)).await,
        MSG_CHECKIN_DISABLED,
    )
    .await;
    assert!(code_rows(&db, USER_ID).await.is_empty(), "门不应写库");

    set_option(&db, "qq_bot_setting.qq_checkin_enabled", "1").await;
    // Already bound users never get a code (`qq_binding.go:174-176`).
    seed_binding(&db, USER_ID, Some("杰瑞"), 1_700_000_000).await;
    assert_failure(
        send(&app, Method::POST, "/api/user/qq/bind/code", Some(&auth)).await,
        MSG_ALREADY_BOUND,
    )
    .await;
    assert!(code_rows(&db, USER_ID).await.is_empty(), "门不应写库");

    // A different user: the rebind cooldown blocks regeneration and reports
    // the remaining seconds (Go `RejectQQBindIfInCooldown`).
    seed_user(&db, 9, "pat-qq-bind-nine", 1).await;
    let auth_nine = "Bearer pat-qq-bind-nine";
    seed_unbind_record(&db, 9, now()).await;
    let body = body_json(
        send(
            &app,
            Method::POST,
            "/api/user/qq/bind/code",
            Some(auth_nine),
        )
        .await,
    )
    .await;
    assert_eq!(body["success"], json!(false), "{body}");
    let message = body["message"].as_str().expect("message");
    let digits = message
        .strip_prefix(MSG_COOLDOWN_PREFIX)
        .and_then(|rest| rest.strip_suffix(MSG_COOLDOWN_SUFFIX))
        .expect("cooldown message shape");
    let remaining: i64 = digits.parse().expect("remaining seconds");
    // 种下的解绑时间与请求内的 now 可能跨过一秒，只锁区间。
    assert!(
        (3590..=3600).contains(&remaining),
        "unexpected remaining seconds {remaining}"
    );
    assert!(code_rows(&db, 9).await.is_empty(), "冷却内不应写码");

    // Cooldown off: Go returns before even reading the unbind record.
    set_option(&db, "qq_bot_setting.rebind_cooldown_seconds", "0").await;
    let before = now();
    let body = assert_api_success(
        send(
            &app,
            Method::POST,
            "/api/user/qq/bind/code",
            Some(auth_nine),
        )
        .await,
    )
    .await;
    let after = now();
    let data = &body["data"];
    let code = data["code"].as_str().expect("code");
    assert_code_shape(code);
    let expires_in = data["expires_in"].as_i64().expect("expires_in");
    let expired_at = data["expired_at"].as_i64().expect("expired_at");
    assert!(
        (before + 295..=after + 305).contains(&expired_at),
        "expired_at {expired_at} outside the TTL window"
    );
    // `expires_in` 是 `expired_at - now`（响应时刻），所以反推出的生成时刻
    // 必须落在请求窗口内，而不是 TTL 窗口。
    assert!(
        (before..=after).contains(&(expired_at - expires_in)),
        "expires_in {expires_in} inconsistent with expired_at"
    );
    let rows = code_rows(&db, 9).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].0, code);
    assert_eq!(rows[0].1, 0, "a fresh code must stay usable");

    // Regenerating invalidates the previous code instead of stacking them
    // (`qq_binding.go:182-184`).
    let second = assert_api_success(
        send(
            &app,
            Method::POST,
            "/api/user/qq/bind/code",
            Some(auth_nine),
        )
        .await,
    )
    .await;
    let second_code = second["data"]["code"].as_str().expect("second code");
    assert_code_shape(second_code);
    let rows = code_rows(&db, 9).await;
    assert_eq!(rows.len(), 2, "{rows:?}");
    let previous = rows
        .iter()
        .find(|(stored, _, _)| stored == code)
        .expect("first row");
    assert_eq!(previous.1, 1, "the previous code must be invalidated");
    let current = rows
        .iter()
        .find(|(stored, _, _)| stored == second_code)
        .expect("second row");
    assert_eq!(current.1, 0, "the newest code must stay usable");

    // A stale (already used) row never blocks a new code: the conflict probe
    // only counts unused, unexpired codes (`qq_binding.go:196-199`).
    seed_code(&db, 9, "#StaLe1", true, 1_700_000_000).await;
    let third = assert_api_success(
        send(
            &app,
            Method::POST,
            "/api/user/qq/bind/code",
            Some(auth_nine),
        )
        .await,
    )
    .await;
    assert_code_shape(third["data"]["code"].as_str().expect("third code"));

    // 冷却开着但记录已过期：`now < allowedAt` 判负，照常放行。
    set_option(&db, "qq_bot_setting.rebind_cooldown_seconds", "3600").await;
    seed_user(&db, 11, "pat-qq-bind-eleven", 1).await;
    seed_unbind_record(&db, 11, now() - 7200).await;
    let body = assert_api_success(
        send(
            &app,
            Method::POST,
            "/api/user/qq/bind/code",
            Some("Bearer pat-qq-bind-eleven"),
        )
        .await,
    )
    .await;
    assert_code_shape(body["data"]["code"].as_str().expect("code"));
}

// ---------------------------------------------------------------------------
// DELETE /api/user/qq/bind — Go `billing.UnbindQQ`
// ---------------------------------------------------------------------------

async fn run_unbind_contract(db: Database) {
    exec(&db, USERS).await;
    exec(&db, OPTIONS).await;
    exec(&db, qq_bindings_ddl(&db)).await;
    exec(&db, qq_bind_codes_ddl(&db)).await;
    exec(&db, QQ_UNBIND_RECORDS).await;
    seed_user(&db, USER_ID, PAT, 1).await;
    let auth = format!("Bearer {PAT}");
    let app = state(&db);

    assert_eq!(
        send(&app, Method::DELETE, "/api/user/qq/bind", None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );

    // Unbinding a never-bound user succeeds: Go's deletes match zero rows
    // without error (`qq_binding.go:304-310`).
    assert_plain_success(
        send(&app, Method::DELETE, "/api/user/qq/bind", Some(&auth)).await,
        MSG_UNBOUND,
    )
    .await;
    let records = unbind_records(&db, USER_ID).await;
    assert_eq!(records.len(), 1, "解绑必须留痕，冷却才有判据");
    assert!(records[0] >= now() - 5, "unbind_at must be fresh");

    // A bound user with a used and an unused code: both codes go away with
    // the binding row, and the unbind record is upserted (not duplicated).
    seed_binding(&db, USER_ID, Some("杰瑞"), 1_700_000_000).await;
    seed_code(&db, USER_ID, "#Live01", false, now() + 300).await;
    seed_code(&db, USER_ID, "#Used01", true, now() + 300).await;
    assert_plain_success(
        send(&app, Method::DELETE, "/api/user/qq/bind", Some(&auth)).await,
        MSG_UNBOUND,
    )
    .await;
    assert_eq!(binding_rows(&db, USER_ID).await, 0);
    assert!(
        code_rows(&db, USER_ID).await.is_empty(),
        "解绑要连未使用的验证码一起清除，否则旧码还能把账号绑回来"
    );
    assert_eq!(unbind_records(&db, USER_ID).await.len(), 1);
}

// ---------------------------------------------------------------------------
// POST /api/user/qq/panel/sync — Go `billing.SyncQQPanel`
// ---------------------------------------------------------------------------

/// 记录调用序列的假 API；永不触网。字段按场景克隆，不跨 await 持锁。
#[derive(Clone, Default)]
struct FakeQQBot {
    list_error: Option<qqbot::QQBotApiError>,
    create_error: Option<qqbot::QQBotApiError>,
    calls: Arc<Mutex<Vec<String>>>,
    create_body: Arc<Mutex<Option<String>>>,
}

impl FakeQQBot {
    fn new() -> Self {
        Self::default()
    }

    fn failing_list() -> Self {
        Self {
            list_error: Some(qqbot::QQBotApiError::Transport),
            ..Self::new()
        }
    }

    fn failing_create() -> Self {
        Self {
            create_error: Some(qqbot::QQBotApiError::Decode),
            ..Self::new()
        }
    }

    fn calls(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn create_body(&self) -> Option<String> {
        self.create_body
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

impl qqbot::QQBotApi for FakeQQBot {
    fn app_access_token<'a>(
        &'a self,
        _app_id: &'a str,
        _app_secret: &'a str,
    ) -> qqbot::QQBotFuture<'a, String> {
        self.record("token");
        Box::pin(async move { Ok("fake-token".to_owned()) })
    }

    fn list_panels<'a>(
        &'a self,
        _token: &'a str,
        scope: &'a str,
    ) -> qqbot::QQBotFuture<'a, Vec<qqbot::QQPanelBrief>> {
        self.record(&format!("list:{scope}"));
        let error = self.list_error;
        Box::pin(async move {
            match error {
                Some(error) => Err(error),
                None => Ok(vec![
                    qqbot::QQPanelBrief {
                        panel_id: "panel-group-1".to_owned(),
                        scope: "group".to_owned(),
                    },
                    qqbot::QQPanelBrief {
                        panel_id: "panel-c2c-1".to_owned(),
                        scope: "c2c".to_owned(),
                    },
                ]),
            }
        })
    }

    fn delete_panel<'a>(
        &'a self,
        _token: &'a str,
        panel_id: &'a str,
    ) -> qqbot::QQBotFuture<'a, ()> {
        self.record(&format!("delete:{panel_id}"));
        Box::pin(async move { Ok(()) })
    }

    fn create_panel<'a>(
        &'a self,
        _token: &'a str,
        request: &'a qqbot::QQCreatePanelRequest,
    ) -> qqbot::QQBotFuture<'a, String> {
        self.record("create");
        *self
            .create_body
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some(serde_json::to_string(request).expect("serialize request"));
        let error = self.create_error;
        Box::pin(async move {
            match error {
                Some(error) => Err(error),
                None => Ok("panel-new".to_owned()),
            }
        })
    }
}

impl FakeQQBot {
    fn record(&self, call: &str) {
        self.calls
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(call.to_owned());
    }
}

async fn run_panel_contract(db: Database) {
    exec(&db, USERS).await;
    exec(&db, OPTIONS).await;
    seed_user(&db, USER_ID, PAT, 1).await;
    seed_user(&db, ADMIN_ID, ADMIN_PAT, 10).await;
    let app = state(&db);

    // `AdminAuth` is a full authentication at role >= 10: a common user gets
    // Go's 403 `AUTH_INSUFFICIENT_PRIVILEGE`, not a 401.
    assert_eq!(
        send(&app, Method::POST, "/api/user/qq/panel/sync", None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(
            &app,
            Method::POST,
            "/api/user/qq/panel/sync",
            Some(&format!("Bearer {PAT}"))
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );

    // Unconfigured AppID/AppSecret: Go `getClient` fails before any request.
    let fake = Arc::new(FakeQQBot::new());
    let api: Arc<dyn qqbot::QQBotApi> = fake.clone();
    assert_failure(send_panel(&app, api).await, MSG_BOT_NOT_CONFIGURED).await;
    assert!(fake.calls().is_empty(), "未配置时不得触网");

    // Configured: delete the existing group panels, then rebuild. The c2c
    // panel is left alone (Go `qqbot_service.go:784-790`).
    set_option(&db, "qq_bot_setting.app_id", "app-1").await;
    set_option(&db, "qq_bot_setting.app_secret", "secret-1").await;
    let fake = Arc::new(FakeQQBot::new());
    let api: Arc<dyn qqbot::QQBotApi> = fake.clone();
    assert_plain_success(send_panel(&app, api).await, MSG_PANEL_SYNCED).await;
    assert_eq!(
        fake.calls(),
        vec![
            "token".to_owned(),
            "list:group".to_owned(),
            "delete:panel-group-1".to_owned(),
            "create".to_owned(),
        ]
    );
    assert_eq!(
        fake.create_body().as_deref(),
        Some(
            r#"{"scope":"group","target_type":"all","panel":{"items":[{"name":"签到","desc":"领取每日额度","type":"command"}],"remark":"站内签到指令面板"}}"#
        ),
        "the rebuild request must match Go's CreatePanelRequest verbatim"
    );

    // A list failure does not abort the sync (Go logs and rebuilds).
    let fake = Arc::new(FakeQQBot::failing_list());
    let api: Arc<dyn qqbot::QQBotApi> = fake.clone();
    assert_plain_success(send_panel(&app, api).await, MSG_PANEL_SYNCED).await;
    assert_eq!(
        fake.calls(),
        vec![
            "token".to_owned(),
            "list:group".to_owned(),
            "create".to_owned()
        ]
    );

    // A create failure surfaces the fixed classification message.
    let fake = Arc::new(FakeQQBot::failing_create());
    let api: Arc<dyn qqbot::QQBotApi> = fake.clone();
    assert_failure(send_panel(&app, api).await, MSG_PANEL_SYNC_FAILED).await;
}

fn qq_bind_codes_ddl(db: &Database) -> &'static str {
    match db {
        Database::Sqlite(_) => QQ_BIND_CODES,
        Database::Postgres(_) => QQ_BIND_CODES_POSTGRES,
    }
}

#[tokio::test]
async fn sqlite_qq_bind_status_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    run_get_contract(Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn sqlite_qq_bind_code_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    run_code_contract(Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn sqlite_qq_unbind_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    run_unbind_contract(Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn sqlite_qq_panel_sync_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    run_panel_contract(Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn postgres_qq_bind_status_contract() {
    let Some(db) = postgres_fixture("qq_bind_status").await else {
        return;
    };
    run_get_contract(db).await;
}

#[tokio::test]
async fn postgres_qq_bind_code_contract() {
    let Some(db) = postgres_fixture("qq_bind_code").await else {
        return;
    };
    run_code_contract(db).await;
}

#[tokio::test]
async fn postgres_qq_unbind_contract() {
    let Some(db) = postgres_fixture("qq_unbind").await else {
        return;
    };
    run_unbind_contract(db).await;
}

#[tokio::test]
async fn postgres_qq_panel_sync_contract() {
    let Some(db) = postgres_fixture("qq_panel_sync").await else {
        return;
    };
    run_panel_contract(db).await;
}

/// 隔离的 PostgreSQL schema；`TEST_POSTGRES_DSN` 缺失时整个用例跳过。
async fn postgres_fixture(label: &str) -> Option<Database> {
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
        "qq_bind_routes_{label}_{}_{}",
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
    Some(Database::Postgres(pool))
}
