//! HTTP contracts for the `/api/redemption/*` management endpoints.
//!
//! Runs only in remote CI. Every scenario uses an isolated synthetic fixture
//! (in-memory SQLite or an isolated PostgreSQL schema); no service is started.
//! The PostgreSQL test is skipped when `TEST_POSTGRES_DSN` is absent.
//!
//! Go semantics notes:
//! - The route group carries only `security.AdminAuth()`; 401/403 are the only
//!   non-200 outcomes in the chain, and every business result is HTTP 200 with
//!   `{success,message,data}` — except `AddRedemption`'s non-finite
//!   `quota_display`, which is Go's explicit 400 + plain `"invalid quota"`.
//! - `AddRedemption` returns the generated codes as `data`; the DB row keeps
//!   the GORM column defaults (`status = 1`, `quota = 100` when the computed
//!   quota is 0) because GORM omits zero-valued defaulted columns on insert.
//! - `UpdateRedemption` writes the GORM `Select` five columns; `?status_only`
//!   (any non-empty value) changes only `status` and skips expiration
//!   validation.
//! - Deletes are soft (`deleted_at`), and `DELETE /api/redemption/invalid`
//!   counts used/disabled plus expired-enabled rows.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::Request,
    http::{Method, StatusCode, header},
    middleware,
    response::Response,
    routing::{delete, get},
};
use newapi_server::{AppState, auth as server_auth, redemption_http};
use newapi_storage::Database;
use serde_json::{Value, json};
use sqlx::{
    ConnectOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::SqlitePoolOptions,
};
use tower::ServiceExt;

static NEXT: AtomicU64 = AtomicU64::new(0);

const SECRET: &str = "redemption-routes-fixture-secret";
const PAT_ADMIN: &str = "pat-redemption-admin";
const PAT_COMMON: &str = "pat-redemption-common";
const MSG_INVALID_PARAMS: &str = "Invalid parameters";
const MSG_ID_EMPTY: &str = "ID is empty!";
const MSG_NOT_FOUND: &str = "Not found";
const MSG_COMPLIANCE_REQUIRED: &str = "Payment, redemption, subscription, and invitation reward features are disabled. The administrator must confirm compliance terms before enabling them.";
const MSG_NAME_LENGTH: &str = "Redemption code name length must be between 1-20";
const MSG_COUNT_POSITIVE: &str = "Redemption code count must be greater than 0";
const MSG_COUNT_MAX: &str = "Maximum 100 redemption codes can be generated at once";
const MSG_EXPIRE_TIME_INVALID: &str = "Expiration time cannot be earlier than current time";

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

/// GORM AutoMigrate 后的 redemption 表形态（`char(32)` 码列、`status`
/// 默认 1、`quota` 默认 100、软删除 `deleted_at`）。
const REDEMPTIONS_SQLITE: &str = r#"CREATE TABLE redemptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    "key" CHAR(32) NOT NULL UNIQUE,
    status INTEGER NOT NULL DEFAULT 1,
    name TEXT NOT NULL DEFAULT '',
    quota INTEGER NOT NULL DEFAULT 100,
    redeemed_time BIGINT NOT NULL DEFAULT 0,
    created_time BIGINT NOT NULL DEFAULT 0,
    used_user_id INTEGER NOT NULL DEFAULT 0,
    expired_time BIGINT NOT NULL DEFAULT 0,
    deleted_at TIMESTAMP
)"#;

const REDEMPTIONS_POSTGRES: &str = r#"CREATE TABLE redemptions (
    id BIGSERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    "key" CHAR(32) NOT NULL UNIQUE,
    status INTEGER NOT NULL DEFAULT 1,
    name TEXT NOT NULL DEFAULT '',
    quota INTEGER NOT NULL DEFAULT 100,
    redeemed_time BIGINT NOT NULL DEFAULT 0,
    created_time BIGINT NOT NULL DEFAULT 0,
    used_user_id INTEGER NOT NULL DEFAULT 0,
    expired_time BIGINT NOT NULL DEFAULT 0,
    deleted_at TIMESTAMPTZ
)"#;

const OPTIONS: &str = r#"CREATE TABLE options (
    "key" TEXT PRIMARY KEY, "value" TEXT
)"#;

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

/// Go redemptionRoute = apiRouter.Group("/redemption")，组级仅 AdminAuth。
fn router(state: AppState) -> Router {
    Router::new()
        .route(
            "/api/redemption/",
            get(redemption_http::list_redemptions)
                .post(redemption_http::add_redemption)
                .put(redemption_http::update_redemption),
        )
        .route(
            "/api/redemption",
            get(redemption_http::list_redemptions)
                .post(redemption_http::add_redemption)
                .put(redemption_http::update_redemption),
        )
        .route(
            "/api/redemption/search",
            get(redemption_http::search_redemptions),
        )
        .route(
            "/api/redemption/invalid",
            delete(redemption_http::delete_invalid_redemptions),
        )
        .route(
            "/api/redemption/{id}",
            get(redemption_http::get_redemption).delete(redemption_http::delete_redemption),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            server_auth::admin_auth,
        ))
        .with_state(state)
}

fn state(db: &Database) -> AppState {
    // PAT 鉴权只读数据库；与 token 路由的测试夹具一致，不装配 SessionAuth。
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
            for statement in [USERS_SQLITE, REDEMPTIONS_SQLITE, OPTIONS, LOGS_SQLITE] {
                exec(db, statement).await;
            }
        }
        Database::Postgres(_) => {
            for statement in [USERS_POSTGRES, REDEMPTIONS_POSTGRES, OPTIONS, LOGS_POSTGRES] {
                exec(db, statement).await;
            }
        }
    }
}

async fn reset(db: &Database) {
    exec(db, "DELETE FROM logs").await;
    exec(db, "DELETE FROM redemptions").await;
    exec(db, "DELETE FROM options").await;
    exec(db, "DELETE FROM users").await;
}

/// 开启 Go `IsPaymentComplianceConfirmed` 所需的两项支付合规选项；
/// 缺省夹具不写入任何选项，等价于“管理员未确认合规”。
async fn confirm_compliance(db: &Database) {
    backend!(db, pool, {
        for (key, value) in [
            ("payment_setting.compliance_confirmed", "true"),
            ("payment_setting.compliance_terms_version", "v1"),
        ] {
            sqlx::query(r#"INSERT INTO options ("key", "value") VALUES ($1, $2)"#)
                .bind(key)
                .bind(value)
                .execute(pool)
                .await
                .expect("seed option");
        }
    });
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

/// Go 生产码恒为 32 位 hex；夹具键固定 32 字符，避免 PG `char(32)`
/// 对短值尾部补格带来的解码差异。
fn fixed_key(tag: &str) -> String {
    assert!(tag.len() < 32, "seed tag must fit in 32 chars");
    format!("{tag:0>32}")
}

/// Go `Redemption` 行；显式指定 id 让分页/搜索断言不依赖自增起始值。
#[allow(clippy::too_many_arguments)]
async fn seed_redemption(
    db: &Database,
    id: i64,
    user_id: i64,
    key: &str,
    status: i64,
    name: &str,
    quota: i64,
    expired_time: i64,
) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO redemptions
                (id,user_id,"key",status,name,quota,expired_time)
                VALUES ($1,$2,$3,$4,$5,$6,$7)"#,
        )
        .bind(id)
        .bind(user_id)
        .bind(key)
        .bind(status)
        .bind(name)
        .bind(quota)
        .bind(expired_time)
        .execute(pool)
        .await
        .expect("seed redemption");
    });
}

/// 未软删行数（GORM 的默认作用域同款过滤）。
async fn redemption_count(db: &Database) -> i64 {
    backend!(db, pool, {
        sqlx::query_scalar("SELECT COUNT(*) FROM redemptions WHERE deleted_at IS NULL")
            .fetch_one(pool)
            .await
            .expect("count redemptions")
    })
}

/// `(user_id, key, status, name, quota, expired_time)` 投影。
async fn stored_rows(db: &Database) -> Vec<(i64, String, i64, String, i64, i64)> {
    backend!(db, pool, {
        sqlx::query_as::<_, (i64, String, i64, String, i64, i64)>(
            r#"SELECT CAST(user_id AS BIGINT), "key", CAST(status AS BIGINT),
                      name, CAST(quota AS BIGINT), CAST(expired_time AS BIGINT)
               FROM redemptions WHERE deleted_at IS NULL ORDER BY id"#,
        )
        .fetch_all(pool)
        .await
        .expect("read redemptions")
    })
}

async fn stored_quota(db: &Database, key: &str) -> i64 {
    backend!(db, pool, {
        sqlx::query_scalar::<_, i64>(
            r#"SELECT CAST(quota AS BIGINT) FROM redemptions WHERE "key" = $1"#,
        )
        .bind(key)
        .fetch_one(pool)
        .await
        .expect("read inserted row")
    })
}

/// 最新一条管理审计 `(content, username, user_id, other)`。
async fn latest_audit(db: &Database) -> (String, String, i64, String) {
    backend!(db, pool, {
        sqlx::query_as::<_, (String, String, i64, String)>(
            r#"SELECT content, username, CAST(user_id AS BIGINT) AS user_id, other
               FROM logs WHERE type = 3 ORDER BY id DESC LIMIT 1"#,
        )
        .fetch_one(pool)
        .await
        .expect("read audit")
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

/// 原始字节体：发 `1e400` 这类 `json!` 无法表达的 JSON 数字字面量。
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

async fn run_contract(db: Database) {
    create_schema(&db).await;
    reset(&db).await;
    seed_user(&db, 1, "admin-one", 10, PAT_ADMIN).await;
    seed_user(&db, 2, "common-one", 1, PAT_COMMON).await;
    let app = state(&db);
    let admin = format!("Bearer {PAT_ADMIN}");
    let common = format!("Bearer {PAT_COMMON}");

    // ---- guard chain: Go `security.AdminAuth()` only -----------------------
    // 无凭据：401（凭据分类失败）。
    assert_auth_failure(
        send(&app, Method::GET, "/api/redemption/", None, None).await,
        "AUTH_UNAUTHORIZED",
    )
    .await;
    // 普通用户（role=1 < 10）：403。
    assert_forbidden(send(&app, Method::GET, "/api/redemption/", Some(&common), None).await).await;

    // ---- compliance gate ---------------------------------------------------
    // 未确认合规：创建被拒（HTTP 200 + i18n 消息，无 data）。
    let body = body_json(
        send(
            &app,
            Method::POST,
            "/api/redemption/",
            Some(&admin),
            Some(&json!({"name":"gift","count":1,"quota_display":1})),
        )
        .await,
    )
    .await;
    assert_eq!(body["success"], json!(false));
    assert_eq!(body["message"], json!(MSG_COMPLIANCE_REQUIRED));
    assert!(body.get("data").is_none());
    assert_eq!(redemption_count(&db).await, 0);

    confirm_compliance(&db).await;

    // ---- AddRedemption -----------------------------------------------------
    // 超出 f64 的指数：Go encoding/json（ErrRange）与 serde_json
    // （NumberOutOfRange）都在绑定阶段失败，handler 回 invalid params。
    let body = body_json(
        send_raw(
            &app,
            Method::POST,
            "/api/redemption/",
            &admin,
            br#"{"name":"gift","count":1,"quota_display":1e400}"#,
        )
        .await,
    )
    .await;
    assert_eq!(body["success"], json!(false));
    assert_eq!(body["message"], json!(MSG_INVALID_PARAMS));

    // 名称为空或超过 20 个字符（按 rune 计数，不是字节）。
    for name in ["", "０１２３４５６７８９０１２３４５６７８９０１"] {
        let body = body_json(
            send(
                &app,
                Method::POST,
                "/api/redemption/",
                Some(&admin),
                Some(&json!({"name":name,"count":1,"quota_display":1})),
            )
            .await,
        )
        .await;
        assert_eq!(body["success"], json!(false));
        assert_eq!(body["message"], json!(MSG_NAME_LENGTH));
    }

    // count <= 0 与 > 100。
    let body = body_json(
        send(
            &app,
            Method::POST,
            "/api/redemption/",
            Some(&admin),
            Some(&json!({"name":"gift","count":0,"quota_display":1})),
        )
        .await,
    )
    .await;
    assert_eq!(body["message"], json!(MSG_COUNT_POSITIVE));
    let body = body_json(
        send(
            &app,
            Method::POST,
            "/api/redemption/",
            Some(&admin),
            Some(&json!({"name":"gift","count":101,"quota_display":1})),
        )
        .await,
    )
    .await;
    assert_eq!(body["message"], json!(MSG_COUNT_MAX));

    // 过期时间早于当前时间（0 表示不过期，合法）。
    let body = body_json(
        send(
            &app,
            Method::POST,
            "/api/redemption/",
            Some(&admin),
            Some(&json!({"name":"gift","count":1,"quota_display":1,"expired_time":now()-100})),
        )
        .await,
    )
    .await;
    assert_eq!(body["message"], json!(MSG_EXPIRE_TIME_INVALID));

    // 成功：data 为本次生成的码列表；GORM 列默认值生效（status=1）。
    let body = body_json(
        send(
            &app,
            Method::POST,
            "/api/redemption/",
            Some(&admin),
            Some(&json!({"name":"gift","count":2,"quota_display":1,"expired_time":0})),
        )
        .await,
    )
    .await;
    assert_eq!(body["success"], json!(true));
    assert_eq!(body["message"], json!(""));
    let keys = body["data"]
        .as_array()
        .expect("data is the key list")
        .clone();
    assert_eq!(keys.len(), 2);
    for key in &keys {
        let key = key.as_str().expect("key is a string");
        assert_eq!(key.len(), 32, "uuid sans dashes is 32 hex chars");
        assert!(
            key.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }
    assert_eq!(redemption_count(&db).await, 2);
    // 行内容：quota 按 USD 默认 QuotaPerUnit=500000 换算，status=1，
    // user_id 记管理员，created_time/redeemed_time 保持 Go 的 0。
    for (user_id, key, status, name, quota, expired_time) in stored_rows(&db).await {
        assert_eq!(user_id, 1);
        assert_eq!(status, 1);
        assert_eq!(name, "gift");
        assert_eq!(quota, 500_000);
        assert_eq!(expired_time, 0);
        assert!(keys.iter().any(|value| value.as_str() == Some(&key)));
    }

    // ---- 管理审计：Go `usage.RecordManageAudit(c, "redemption.create", ...)`。
    let (content, username, audit_user_id, other) = latest_audit(&db).await;
    assert_eq!(content, "redemption.create");
    assert_eq!(username, "admin-one");
    assert_eq!(audit_user_id, 1);
    assert!(other.contains("redemption.create"));
    assert!(other.contains("\"count\":2"));
    assert!(other.contains("\"name\":\"gift\""));
    assert!(other.contains("admin_info"));

    // ---- 列表（GetAllRedemptions）-----------------------------------------
    reset(&db).await;
    confirm_compliance(&db).await;
    seed_user(&db, 1, "admin-one", 10, PAT_ADMIN).await;
    seed_redemption(&db, 10, 1, &fixed_key("k10"), 1, "alpha", 500_000, 0).await;
    seed_redemption(&db, 20, 1, &fixed_key("k20"), 2, "apple", 500_000, 0).await;
    seed_redemption(&db, 30, 1, &fixed_key("k30"), 3, "beta", 250_000, 0).await;

    let body = body_json(
        send(
            &app,
            Method::GET,
            "/api/redemption/?p=1&page_size=2",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["success"], json!(true));
    let data = &body["data"];
    assert_eq!(data["page"], json!(1));
    assert_eq!(data["page_size"], json!(2));
    assert_eq!(data["total"], json!(3));
    let items = data["items"].as_array().expect("items");
    assert_eq!(items.len(), 2);
    // id 倒序；quota_display 由 API 边界换算（USD，QuotaPerUnit=500000）。
    assert_eq!(items[0]["id"], json!(30));
    assert_eq!(items[0]["quota_display"], json!(0.5));
    assert_eq!(items[1]["id"], json!(20));
    assert_eq!(items[1]["key"], json!(fixed_key("k20")));
    assert_eq!(items[0]["count"], json!(0));
    assert!(items[0].get("deleted_at").is_none());
    // 无查询参数：默认 page=1、page_size=10。
    let body =
        body_json(send(&app, Method::GET, "/api/redemption/", Some(&admin), None).await).await;
    assert_eq!(body["data"]["page"], json!(1));
    assert_eq!(body["data"]["page_size"], json!(10));
    assert_eq!(body["data"]["total"], json!(3));
    // 无尾斜杠（Fiber 非严格路由的等价形态）。
    let body =
        body_json(send(&app, Method::GET, "/api/redemption", Some(&admin), None).await).await;
    assert_eq!(body["data"]["total"], json!(3));
    // page_size 超过 100 封顶。
    let body = body_json(
        send(
            &app,
            Method::GET,
            "/api/redemption/?page_size=1000",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["page_size"], json!(100));

    // ---- 搜索（SearchRedemptions）-----------------------------------------
    // name 前缀匹配（未转义 LIKE，Go 行为）。
    let body = body_json(
        send(
            &app,
            Method::GET,
            "/api/redemption/search?keyword=ap",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["total"], json!(2));
    let items = body["data"]["items"].as_array().expect("items");
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["id"], json!(20));
    assert_eq!(items[1]["id"], json!(10));
    // 可解析为 int 的 keyword 命中 `id = ? OR name LIKE ?`（id=20）。
    let body = body_json(
        send(
            &app,
            Method::GET,
            "/api/redemption/search?keyword=20",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["total"], json!(1));
    assert_eq!(body["data"]["items"][0]["id"], json!(20));
    // 无匹配 keyword。
    let body = body_json(
        send(
            &app,
            Method::GET,
            "/api/redemption/search?keyword=nope",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["total"], json!(0));
    // 未登记的 status 值不加过滤。
    let body = body_json(
        send(
            &app,
            Method::GET,
            "/api/redemption/search?status=99",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["total"], json!(3));

    // 增补过期/未过期行覆盖 status 四个分支。
    seed_redemption(
        &db,
        40,
        1,
        &fixed_key("k40"),
        1,
        "gamma",
        500_000,
        now() - 100,
    )
    .await;
    seed_redemption(
        &db,
        50,
        1,
        &fixed_key("k50"),
        1,
        "delta",
        500_000,
        now() + 3600,
    )
    .await;
    // "2"：已禁用。
    let body = body_json(
        send(
            &app,
            Method::GET,
            "/api/redemption/search?status=2",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["total"], json!(1));
    assert_eq!(body["data"]["items"][0]["id"], json!(20));
    // "3"：已使用。
    let body = body_json(
        send(
            &app,
            Method::GET,
            "/api/redemption/search?status=3",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["total"], json!(1));
    assert_eq!(body["data"]["items"][0]["id"], json!(30));
    // "1"：启用且未过期（含 expired_time=0 永不过期）：10 与 50。
    let body = body_json(
        send(
            &app,
            Method::GET,
            "/api/redemption/search?status=1",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["total"], json!(2));
    let ids: Vec<Value> = body["data"]["items"].as_array().expect("items").to_vec();
    assert_eq!(ids[0]["id"], json!(50));
    assert_eq!(ids[1]["id"], json!(10));
    // "expired"：启用但已过 expired_time。
    let body = body_json(
        send(
            &app,
            Method::GET,
            "/api/redemption/search?status=expired",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["total"], json!(1));
    assert_eq!(body["data"]["items"][0]["id"], json!(40));
    // keyword 与 status 组合。
    let body = body_json(
        send(
            &app,
            Method::GET,
            "/api/redemption/search?keyword=ga&status=expired",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["total"], json!(1));
    assert_eq!(body["data"]["items"][0]["name"], json!("gamma"));

    // ---- GetRedemption ------------------------------------------------------
    let body =
        body_json(send(&app, Method::GET, "/api/redemption/30", Some(&admin), None).await).await;
    assert_eq!(body["success"], json!(true));
    assert_eq!(body["message"], json!(""));
    let data = &body["data"];
    assert_eq!(data["id"], json!(30));
    assert_eq!(data["key"], json!(fixed_key("k30")));
    assert_eq!(data["status"], json!(3));
    assert_eq!(data["quota"], json!(250_000));
    assert_eq!(data["quota_display"], json!(0.5));
    assert_eq!(data["count"], json!(0));
    assert!(data.get("deleted_at").is_none());
    // 不存在 / id=0 / 非法 id。
    let body = body_json(
        send(
            &app,
            Method::GET,
            "/api/redemption/9999",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["success"], json!(false));
    assert_eq!(body["message"], json!(MSG_NOT_FOUND));
    let body =
        body_json(send(&app, Method::GET, "/api/redemption/0", Some(&admin), None).await).await;
    assert_eq!(body["message"], json!(MSG_ID_EMPTY));
    let body =
        body_json(send(&app, Method::GET, "/api/redemption/abc", Some(&admin), None).await).await;
    assert_eq!(body["message"], json!(MSG_INVALID_PARAMS));

    // ---- UpdateRedemption ---------------------------------------------------
    // 全量更新：name/quota/expired_time，status 保持原值；quota 是请求体里
    // 的内部值（不经 quota_display 换算）。
    let body = body_json(
        send(
            &app,
            Method::PUT,
            "/api/redemption/",
            Some(&admin),
            Some(&json!({"id":20,"name":"renamed","quota":1000000,"expired_time":now()+7200})),
        )
        .await,
    )
    .await;
    assert_eq!(body["success"], json!(true));
    let data = &body["data"];
    assert_eq!(data["id"], json!(20));
    assert_eq!(data["name"], json!("renamed"));
    assert_eq!(data["quota"], json!(1_000_000));
    assert_eq!(data["quota_display"], json!(2.0));
    assert_eq!(data["status"], json!(2));
    assert!(data["expired_time"].as_i64().unwrap() > now());
    assert!(data.get("deleted_at").is_none());
    // status_only（任意非空值）只改 status，跳过过期校验。
    let body = body_json(
        send(
            &app,
            Method::PUT,
            "/api/redemption/?status_only=true",
            Some(&admin),
            Some(&json!({"id":20,"status":1,"expired_time":now()-1})),
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["status"], json!(1));
    assert_eq!(body["data"]["name"], json!("renamed"));
    // 空串 status_only 走全量更新：status 不在写集内，保持 1。
    let body = body_json(
        send(
            &app,
            Method::PUT,
            "/api/redemption/?status_only=",
            Some(&admin),
            Some(&json!({"id":20,"status":3})),
        )
        .await,
    )
    .await;
    assert_eq!(body["data"]["status"], json!(1));
    // 全量更新带过期时间校验（status_only 路径不校验，见上一条）。
    let body = body_json(
        send(
            &app,
            Method::PUT,
            "/api/redemption/",
            Some(&admin),
            Some(&json!({"id":20,"name":"x","quota":1,"expired_time":now()-1})),
        )
        .await,
    )
    .await;
    assert_eq!(body["message"], json!(MSG_EXPIRE_TIME_INVALID));
    // 不存在的记录 / id=0 / 非法请求体。
    let body = body_json(
        send(
            &app,
            Method::PUT,
            "/api/redemption/",
            Some(&admin),
            Some(&json!({"id":9999,"name":"x","quota":1})),
        )
        .await,
    )
    .await;
    assert_eq!(body["message"], json!(MSG_NOT_FOUND));
    let body = body_json(
        send(
            &app,
            Method::PUT,
            "/api/redemption/",
            Some(&admin),
            Some(&json!({"name":"x","quota":1})),
        )
        .await,
    )
    .await;
    assert_eq!(body["message"], json!(MSG_ID_EMPTY));
    let body = body_json(
        send(
            &app,
            Method::PUT,
            "/api/redemption/",
            Some(&admin),
            Some(&json!([1, 2])),
        )
        .await,
    )
    .await;
    assert_eq!(body["message"], json!(MSG_INVALID_PARAMS));

    // ---- DeleteRedemption ---------------------------------------------------
    let body = body_json(
        send(
            &app,
            Method::DELETE,
            "/api/redemption/10",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["success"], json!(true));
    assert_eq!(body["message"], json!(""));
    assert!(body.get("data").is_none());
    // 软删除：列表与 GET 都看不见，但行仍在表里。
    let body =
        body_json(send(&app, Method::GET, "/api/redemption/10", Some(&admin), None).await).await;
    assert_eq!(body["message"], json!(MSG_NOT_FOUND));
    let body =
        body_json(send(&app, Method::GET, "/api/redemption/", Some(&admin), None).await).await;
    assert_eq!(body["data"]["total"], json!(4));
    // 重复删除：已软删 → 未找到。
    let body = body_json(
        send(
            &app,
            Method::DELETE,
            "/api/redemption/10",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["message"], json!(MSG_NOT_FOUND));
    // id=0 与非法 id（Go 忽略 Atoi 错误，非法 id 同样落到 id 为空）。
    for id in ["0", "abc"] {
        let body = body_json(
            send(
                &app,
                Method::DELETE,
                &format!("/api/redemption/{id}"),
                Some(&admin),
                None,
            )
            .await,
        )
        .await;
        assert_eq!(body["message"], json!(MSG_ID_EMPTY));
    }

    // ---- DeleteInvalidRedemption ---------------------------------------------
    // 现存可见行：20（enabled，未过期）、30（used）、40（enabled，已过期）、
    // 50（enabled，未过期）；invalid 清理命 used + 已过期的 enabled。
    let body = body_json(
        send(
            &app,
            Method::DELETE,
            "/api/redemption/invalid",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["success"], json!(true));
    assert_eq!(body["data"], json!(2));
    // 一次清理后无残留可清。
    let body = body_json(
        send(
            &app,
            Method::DELETE,
            "/api/redemption/invalid",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(body["data"], json!(0));
    // 只剩 enabled 且未过期的 20 与 50。
    let body =
        body_json(send(&app, Method::GET, "/api/redemption/", Some(&admin), None).await).await;
    assert_eq!(body["data"]["total"], json!(2));
    let ids: Vec<Value> = body["data"]["items"].as_array().expect("items").to_vec();
    assert_eq!(ids[0]["id"], json!(50));
    assert_eq!(ids[1]["id"], json!(20));

    // ---- quota 为 0 时的 GORM 列默认值回退 ----------------------------------
    let body = body_json(
        send(
            &app,
            Method::POST,
            "/api/redemption/",
            Some(&admin),
            Some(&json!({"name":"zero","count":1,"quota_display":0})),
        )
        .await,
    )
    .await;
    assert_eq!(body["success"], json!(true));
    let key = body["data"][0].as_str().expect("generated key");
    // GORM 对带 default 标签的零值字段省略插入 → 列默认 100。
    assert_eq!(stored_quota(&db, key).await, 100);
}

#[tokio::test]
async fn sqlite_redemption_routes_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    run_contract(Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn postgres_redemption_routes_contract() {
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
        "redemption_routes_{}_{}",
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
