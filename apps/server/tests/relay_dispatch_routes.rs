//! Distribute 渠道选择 + relay 转发主链契约测试（双后端：SQLite 内存 + PG）。
//!
//! 场景（对照 Go oracle）：
//! - abilities 过滤 + route-unit 选择：不可服务渠道绝不回包
//!   （distribute_channel.go + select_route_unit.go filterCandidatesByGroup）
//! - Distribute 错误路径：token 模型限额 403、模型名缺失 400、specific
//!   channel 403/直通（distribute_channel.go:44-93）
//! - handle_relay 全链（替身 adaptor 工厂）：预扣费 → 调用 → 结算
//!   （handle_relay.go Relay：PreConsumeBilling → relayHandler → SettleBilling）
//! - 重试语义：Retryable 失败换道排除已试单元；终态 503（relay_failover.go）
//! - 错误信封形状：OpenAI / Claude 分流（handle_relay.go:113-139）
//!
//! PostgreSQL 测试在 `TEST_POSTGRES_DSN` 缺席时跳过；fixture 模式对齐
//! `subscription_admin_routes.rs`（进程级唯一 schema + search_path）。

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, StatusCode, header},
    response::Response,
};
use newapi_relay::adaptor::{Adaptor, channel_type};
use newapi_relay::dispatch::{RelayAttemptError, error_code as dispatch_error_code};
use newapi_relay::relay_info::RelayInfo;
use newapi_server::{AppState, relay_http};
use newapi_storage::Database;
use serde_json::Value;
use sqlx::{postgres::PgPoolOptions, sqlite::SqlitePoolOptions};
use tower::ServiceExt;

static NEXT_SCHEMA: AtomicU64 = AtomicU64::new(0);

const SECRET: &str = "relay-dispatch-fixture-secret";
const USER_ID: i64 = 701;
const TOKEN_KEY: &str = "relaydispatchkey";
/// 低于信任额度（Go TRUST_QUOTA = 10 × QuotaPerUnit = 5,000,000）：
/// 预扣费路径真实发生（信任旁路不触发）。
const USER_QUOTA: i64 = 100_000;

// ---------------------------------------------------------------------------
// fixture DDL
// ---------------------------------------------------------------------------

const USERS_SQLITE: &str = r#"CREATE TABLE users (
    id INTEGER PRIMARY KEY, username TEXT, display_name TEXT,
    role INTEGER, status INTEGER, email TEXT, github_id TEXT, discord_id TEXT,
    oidc_id TEXT, wechat_id TEXT, telegram_id TEXT, "group" TEXT,
    quota INTEGER, used_quota INTEGER, request_count INTEGER, aff_code TEXT,
    aff_count INTEGER, aff_quota INTEGER, aff_history INTEGER, inviter_id INTEGER,
    linux_do_id TEXT, setting TEXT, stripe_customer TEXT, auth_version INTEGER,
    access_token TEXT, password TEXT, remark TEXT, created_at BIGINT,
    last_login_at BIGINT, deleted_at TIMESTAMP
)"#;

const USERS_POSTGRES: &str = r#"CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY, username TEXT, display_name TEXT,
    role BIGINT, status BIGINT, email TEXT, github_id TEXT, discord_id TEXT,
    oidc_id TEXT, wechat_id TEXT, telegram_id TEXT, "group" TEXT,
    quota BIGINT, used_quota BIGINT, request_count BIGINT, aff_code TEXT,
    aff_count BIGINT, aff_quota BIGINT, aff_history BIGINT, inviter_id BIGINT,
    linux_do_id TEXT, setting TEXT, stripe_customer TEXT, auth_version BIGINT,
    access_token TEXT, password TEXT, remark TEXT, created_at BIGINT,
    last_login_at BIGINT, deleted_at TIMESTAMPTZ
)"#;

const TOKENS_SQLITE: &str = r#"CREATE TABLE tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id BIGINT NOT NULL,
    "key" TEXT NOT NULL UNIQUE,
    status INTEGER NOT NULL DEFAULT 1,
    name TEXT NOT NULL DEFAULT '',
    created_time BIGINT NOT NULL DEFAULT 0,
    accessed_time BIGINT NOT NULL DEFAULT 0,
    expired_time BIGINT NOT NULL DEFAULT -1,
    remain_quota BIGINT NOT NULL DEFAULT 0,
    used_quota BIGINT NOT NULL DEFAULT 0,
    unlimited_quota INTEGER NOT NULL DEFAULT 0,
    model_limits_enabled INTEGER NOT NULL DEFAULT 0,
    model_limits TEXT NOT NULL DEFAULT '',
    allow_ips TEXT,
    "group" TEXT NOT NULL DEFAULT '',
    cross_group_retry INTEGER NOT NULL DEFAULT 0,
    auto_groups TEXT NOT NULL DEFAULT '',
    deleted_at TIMESTAMP
)"#;

const TOKENS_POSTGRES: &str = r#"CREATE TABLE tokens (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    "key" VARCHAR(128) NOT NULL UNIQUE,
    status BIGINT NOT NULL DEFAULT 1,
    name TEXT NOT NULL DEFAULT '',
    created_time BIGINT NOT NULL DEFAULT 0,
    accessed_time BIGINT NOT NULL DEFAULT 0,
    expired_time BIGINT NOT NULL DEFAULT -1,
    remain_quota BIGINT NOT NULL DEFAULT 0,
    used_quota BIGINT NOT NULL DEFAULT 0,
    unlimited_quota BOOLEAN NOT NULL DEFAULT FALSE,
    model_limits_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    model_limits TEXT NOT NULL DEFAULT '',
    allow_ips TEXT,
    "group" TEXT NOT NULL DEFAULT '',
    cross_group_retry BOOLEAN NOT NULL DEFAULT FALSE,
    auto_groups TEXT NOT NULL DEFAULT '',
    deleted_at TIMESTAMP
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

const ROUTES_SQLITE: &str = r#"CREATE TABLE channel_model_routes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    public_model_alias TEXT NOT NULL,
    channel_id BIGINT NOT NULL,
    key_index BIGINT NOT NULL DEFAULT 0,
    upstream_model TEXT NOT NULL DEFAULT '',
    static_weight BIGINT NOT NULL DEFAULT 0,
    enabled BOOLEAN NOT NULL DEFAULT TRUE
)"#;

const ROUTES_POSTGRES: &str = r#"CREATE TABLE channel_model_routes (
    id BIGSERIAL PRIMARY KEY,
    public_model_alias TEXT NOT NULL,
    channel_id BIGINT NOT NULL,
    key_index BIGINT NOT NULL DEFAULT 0,
    upstream_model TEXT NOT NULL DEFAULT '',
    static_weight BIGINT NOT NULL DEFAULT 0,
    enabled BOOLEAN NOT NULL DEFAULT TRUE
)"#;

const OPTIONS: &str = r#"CREATE TABLE options (
    "key" TEXT PRIMARY KEY, "value" TEXT
)"#;

// 计费面（BillingStore）：users/tokens/channels 已覆盖；订阅判定与日志。
const SUBS_SQLITE: &str = r#"CREATE TABLE user_subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id BIGINT NOT NULL, plan_id BIGINT NOT NULL,
    amount_total BIGINT NOT NULL DEFAULT 0, amount_used BIGINT NOT NULL DEFAULT 0,
    start_time BIGINT NOT NULL DEFAULT 0, end_time BIGINT NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active', source TEXT NOT NULL DEFAULT 'order',
    last_reset_time BIGINT NOT NULL DEFAULT 0, next_reset_time BIGINT NOT NULL DEFAULT 0,
    allow_wallet_overflow INTEGER NOT NULL DEFAULT 1, updated_at BIGINT NOT NULL DEFAULT 0
)"#;

const SUBS_POSTGRES: &str = r#"CREATE TABLE user_subscriptions (
    id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL, plan_id BIGINT NOT NULL,
    amount_total BIGINT NOT NULL DEFAULT 0, amount_used BIGINT NOT NULL DEFAULT 0,
    start_time BIGINT NOT NULL DEFAULT 0, end_time BIGINT NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active', source TEXT NOT NULL DEFAULT 'order',
    last_reset_time BIGINT NOT NULL DEFAULT 0, next_reset_time BIGINT NOT NULL DEFAULT 0,
    allow_wallet_overflow BOOLEAN NOT NULL DEFAULT TRUE, updated_at BIGINT NOT NULL DEFAULT 0
)"#;

const PLANS_SQLITE: &str = r#"CREATE TABLE subscription_plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL DEFAULT '',
    quota_reset_period TEXT NOT NULL DEFAULT 'never',
    quota_reset_custom_seconds BIGINT NOT NULL DEFAULT 0,
    updated_at BIGINT NOT NULL DEFAULT 0
)"#;

const PLANS_POSTGRES: &str = r#"CREATE TABLE subscription_plans (
    id BIGSERIAL PRIMARY KEY, title TEXT NOT NULL DEFAULT '',
    quota_reset_period TEXT NOT NULL DEFAULT 'never',
    quota_reset_custom_seconds BIGINT NOT NULL DEFAULT 0,
    updated_at BIGINT NOT NULL DEFAULT 0
)"#;

const RECORDS_SQLITE: &str = r#"CREATE TABLE subscription_pre_consume_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT NOT NULL UNIQUE,
    user_id BIGINT NOT NULL, user_subscription_id BIGINT NOT NULL,
    pre_consumed BIGINT NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'consumed',
    created_at BIGINT NOT NULL DEFAULT 0, updated_at BIGINT NOT NULL DEFAULT 0
)"#;

const RECORDS_POSTGRES: &str = r#"CREATE TABLE subscription_pre_consume_records (
    id BIGSERIAL PRIMARY KEY, request_id TEXT NOT NULL UNIQUE,
    user_id BIGINT NOT NULL, user_subscription_id BIGINT NOT NULL,
    pre_consumed BIGINT NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'consumed',
    created_at BIGINT NOT NULL DEFAULT 0, updated_at BIGINT NOT NULL DEFAULT 0
)"#;

const LOGS_SQLITE: &str = r#"CREATE TABLE logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL DEFAULT 0, type INTEGER NOT NULL DEFAULT 0, content TEXT,
    username TEXT NOT NULL DEFAULT '', token_name TEXT NOT NULL DEFAULT '',
    model_name TEXT NOT NULL DEFAULT '', quota INTEGER NOT NULL DEFAULT 0,
    prompt_tokens INTEGER NOT NULL DEFAULT 0, completion_tokens INTEGER NOT NULL DEFAULT 0,
    use_time INTEGER NOT NULL DEFAULT 0, is_stream INTEGER NOT NULL DEFAULT 0,
    channel_id INTEGER NOT NULL DEFAULT 0, token_id INTEGER NOT NULL DEFAULT 0,
    "group" TEXT NOT NULL DEFAULT '', ip TEXT NOT NULL DEFAULT '',
    request_id TEXT NOT NULL DEFAULT '', upstream_request_id TEXT NOT NULL DEFAULT '',
    other TEXT
)"#;

const LOGS_POSTGRES: &str = r#"CREATE TABLE logs (
    id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL DEFAULT 0, type BIGINT NOT NULL DEFAULT 0, content TEXT,
    username TEXT NOT NULL DEFAULT '', token_name TEXT NOT NULL DEFAULT '',
    model_name TEXT NOT NULL DEFAULT '', quota BIGINT NOT NULL DEFAULT 0,
    prompt_tokens BIGINT NOT NULL DEFAULT 0, completion_tokens BIGINT NOT NULL DEFAULT 0,
    use_time BIGINT NOT NULL DEFAULT 0, is_stream BIGINT NOT NULL DEFAULT 0,
    channel_id BIGINT NOT NULL DEFAULT 0, token_id BIGINT NOT NULL DEFAULT 0,
    "group" TEXT NOT NULL DEFAULT '', ip TEXT NOT NULL DEFAULT '',
    request_id TEXT NOT NULL DEFAULT '', upstream_request_id TEXT NOT NULL DEFAULT '',
    other TEXT
)"#;

macro_rules! backend {
    ($db:expr, $pool:ident, $body:block) => {
        match $db {
            Database::Sqlite($pool) => $body,
            Database::Postgres($pool) => $body,
        }
    };
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
            for statement in [
                USERS_SQLITE,
                TOKENS_SQLITE,
                CHANNELS_SQLITE,
                ABILITIES_SQLITE,
                ROUTES_SQLITE,
                OPTIONS,
                SUBS_SQLITE,
                PLANS_SQLITE,
                RECORDS_SQLITE,
                LOGS_SQLITE,
            ] {
                exec(db, statement).await;
            }
        }
        Database::Postgres(_) => {
            for statement in [
                USERS_POSTGRES,
                TOKENS_POSTGRES,
                CHANNELS_POSTGRES,
                ABILITIES_POSTGRES,
                ROUTES_POSTGRES,
                OPTIONS,
                SUBS_POSTGRES,
                PLANS_POSTGRES,
                RECORDS_POSTGRES,
                LOGS_POSTGRES,
            ] {
                exec(db, statement).await;
            }
        }
    }
}

async fn reset(db: &Database) {
    for table in [
        "options",
        "logs",
        "subscription_pre_consume_records",
        "user_subscriptions",
        "subscription_plans",
        "channel_model_routes",
        "abilities",
        "channels",
        "tokens",
        "users",
    ] {
        backend!(db, pool, {
            // 表名来自测试常量表（非用户输入）：AssertSqlSafe 审计面。
            let sql = format!(r#"DELETE FROM "{table}""#);
            sqlx::query(sqlx::AssertSqlSafe(sql))
                .execute(pool)
                .await
                .expect("reset");
        });
    }
}

async fn seed_user(db: &Database, quota: i64, group: &str, role: i64) -> i64 {
    let id = USER_ID;
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO users
                (id,username,display_name,role,status,"group",quota,used_quota,request_count,auth_version,access_token)
                VALUES ($1,$2,'Fixture',$3,1,$4,$5,0,0,1,'')"#,
        )
        .bind(id)
        .bind(format!("user{id}"))
        .bind(role)
        .bind(group)
        .bind(quota)
        .execute(pool)
        .await
        .expect("seed user");
    });
    id
}

async fn seed_token(db: &Database, key: &str, group: &str) -> i64 {
    backend!(db, pool, {
        let id: i64 = sqlx::query_scalar(
            r#"INSERT INTO tokens
                (user_id,"key",status,name,created_time,accessed_time,expired_time,
                 remain_quota,used_quota,unlimited_quota,model_limits_enabled,
                 model_limits,allow_ips,"group",cross_group_retry,auto_groups)
                VALUES ($1,$2,1,'fixture',1,1,-1,0,0,TRUE,FALSE,'','',$3,FALSE,'')
                RETURNING id"#,
        )
        .bind(USER_ID)
        .bind(key)
        .bind(group)
        .fetch_one(pool)
        .await
        .expect("seed token");
        id
    })
}

#[allow(clippy::too_many_arguments)]
async fn seed_channel(db: &Database, id: i64, status: i64, key: &str, models: &str, groups: &str) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO channels (id,"type","key",status,name,models,"group",other_info,channel_info)
               VALUES ($1,$2,$3,$4,$5,$6,'default','','{}')"#,
        )
        .bind(id)
        .bind(channel_type::OPENAI)
        .bind(key)
        .bind(status)
        .bind(format!("channel-{id}"))
        .bind(models)
        .bind(groups)
        .execute(pool)
        .await
        .expect("seed channel");
    });
}

async fn seed_ability(db: &Database, group: &str, model: &str, channel_id: i64, enabled: bool) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO abilities ("group",model,channel_id,enabled,tag)
               VALUES ($1,$2,$3,$4,NULL)"#,
        )
        .bind(group)
        .bind(model)
        .bind(channel_id)
        .bind(enabled)
        .execute(pool)
        .await
        .expect("seed ability");
    });
}

async fn seed_route(
    db: &Database,
    alias: &str,
    channel_id: i64,
    key_index: i64,
    upstream_model: &str,
    weight: i64,
) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO channel_model_routes
               (public_model_alias,channel_id,key_index,upstream_model,static_weight,enabled)
               VALUES ($1,$2,$3,$4,$5,TRUE)"#,
        )
        .bind(alias)
        .bind(channel_id)
        .bind(key_index)
        .bind(upstream_model)
        .bind(weight)
        .execute(pool)
        .await
        .expect("seed route");
    });
}

async fn set_option(db: &Database, key: &str, value: &str) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO options ("key", "value") VALUES ($1, $2)
               ON CONFLICT ("key") DO UPDATE SET "value" = EXCLUDED."value""#,
        )
        .bind(key)
        .bind(value)
        .execute(pool)
        .await
        .expect("seed option");
    });
}

async fn user_quota_of(db: &Database, user_id: i64) -> i64 {
    backend!(db, pool, {
        sqlx::query_scalar::<_, i64>(r#"SELECT quota FROM users WHERE id = $1"#)
            .bind(user_id)
            .fetch_one(pool)
            .await
            .expect("user quota")
    })
}

async fn consume_log_count(db: &Database) -> i64 {
    backend!(db, pool, {
        sqlx::query_scalar::<_, i64>(r#"SELECT COUNT(*) FROM logs WHERE "type" = 2"#)
            .fetch_one(pool)
            .await
            .expect("log count")
    })
}

// ---------------------------------------------------------------------------
// 替身 adaptor 工厂（Adaptor trait 消费契约）
// ---------------------------------------------------------------------------

/// 替身：成功时回 OpenAI usage 形状；失败模式由 fail_first 控制前 N 次
/// 调用（channel 传输面错误 → Retryable → 换道）。记录每次调用的模型名。
struct RecordingAdaptor {
    fail_remaining: u32,
}

impl Adaptor for RecordingAdaptor {
    fn init(&mut self, _info: &RelayInfo) {}
    fn get_request_url(&self, _info: &RelayInfo) -> Result<String, String> {
        Ok("https://upstream.invalid/v1/chat/completions".to_owned())
    }
    fn setup_request_header(&self, _info: &RelayInfo) -> Vec<(String, String)> {
        vec![("authorization".to_owned(), "Bearer sk-stub".to_owned())]
    }
    fn convert_openai_request(&self, _info: &RelayInfo, request: &Value) -> Result<Value, String> {
        Ok(request.clone())
    }
    fn convert_claude_request(&self, _info: &RelayInfo, request: &Value) -> Result<Value, String> {
        // Claude 面直通：/v1/messages 契约场景要打到 do_request 层
        // （raw error passthrough + Claude 信封形状）。
        Ok(request.clone())
    }
    fn convert_gemini_request(&self, _info: &RelayInfo, _request: &Value) -> Result<Value, String> {
        Err("stub: gemini convert not implemented".to_owned())
    }
    fn convert_rerank_request(&self, _relay_mode: i32, _request: &Value) -> Result<Value, String> {
        Err("stub: rerank convert not implemented".to_owned())
    }
    fn convert_embedding_request(
        &self,
        _info: &RelayInfo,
        _request: &Value,
    ) -> Result<Value, String> {
        Err("stub: embedding convert not implemented".to_owned())
    }
    fn convert_image_request(&self, _info: &RelayInfo, _request: &Value) -> Result<Value, String> {
        Err("stub: image convert not implemented".to_owned())
    }
    fn convert_openai_responses_request(
        &self,
        _info: &RelayInfo,
        _request: &Value,
    ) -> Result<Value, String> {
        Err("stub: responses convert not implemented".to_owned())
    }
    fn do_request(&self, _info: &RelayInfo, _body: &[u8]) -> Result<Vec<u8>, String> {
        if self.fail_remaining > 0 {
            return Err("upstream 503".to_owned());
        }
        Ok(
            br#"{"id":"chatcmpl-stub","choices":[],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}"#
                .to_vec(),
        )
    }
    fn do_response(
        &self,
        _info: &mut RelayInfo,
        response: &[u8],
    ) -> Result<Value, newapi_relay::relay_info::AdaptorError> {
        serde_json::from_slice(response).map_err(|e| newapi_relay::relay_info::AdaptorError {
            status_code: 500,
            message: e.to_string(),
            code: dispatch_error_code::BAD_RESPONSE_BODY.to_owned(),
            error_type: "new_api_error".to_owned(),
            skip_retry: false,
        })
    }
    fn get_model_list(&self) -> Vec<String> {
        Vec::new()
    }
    fn get_channel_name(&self) -> String {
        "stub".to_owned()
    }
}

/// 替身工厂：脚本化前 N 次失败；调用计数与渠道绑定由并发守卫记录。
struct ScriptedFactory {
    fail_first: u32,
    calls: Mutex<Vec<String>>,
}

impl ScriptedFactory {
    fn new(fail_first: u32) -> Self {
        Self {
            fail_first,
            calls: Mutex::new(Vec::new()),
        }
    }

    fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
}

impl newapi_relay::dispatch::AdaptorFactory for ScriptedFactory {
    fn create(&self, _api_type: i32) -> Result<Box<dyn Adaptor>, RelayAttemptError> {
        let mut calls = self.calls.lock().unwrap();
        let index = calls.len() as u32;
        calls.push(format!("call-{index}"));
        Ok(Box::new(RecordingAdaptor {
            fail_remaining: if index < self.fail_first { 1 } else { 0 },
        }))
    }
}

// ---------------------------------------------------------------------------
// HTTP 工具
// ---------------------------------------------------------------------------

fn router(state: AppState) -> Router {
    relay_http::relay_routes(state.clone()).with_state(state)
}

fn state_with(db: &Database, factory: std::sync::Arc<ScriptedFactory>) -> AppState {
    AppState::default()
        .bind_runtime(db.clone(), SECRET)
        .bind_relay_adaptor_factory(factory)
}

async fn post_relay(state: &AppState, path: &str, body: &str) -> Response {
    router(state.clone())
        .oneshot(
            axum::extract::Request::builder()
                .method(Method::POST)
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer sk-{TOKEN_KEY}"))
                .body(Body::from(body.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn body_json(response: Response) -> Value {
    let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("response body");
    serde_json::from_slice(&bytes).expect("response JSON")
}

async fn run_contract(db: &Database) {
    create_schema(db).await;
    reset(db).await;

    // ── 定价确定性：倍率选项锚定（ModelRatio/CompletionRatio = 1）─────────
    // AppState 快照经 reload 装载（Go InitOptionMap/SyncOptions 同频语义）。
    set_option(db, "ModelRatio", r#"{"gpt-4":1}"#).await;
    set_option(db, "CompletionRatio", r#"{"gpt-4":1}"#).await;

    // ── Distribute 错误路径：模型名缺失 400 ──────────────────────────────
    seed_user(db, USER_QUOTA, "default", 1).await;
    seed_token(db, TOKEN_KEY, "").await;
    let state = state_with(db, std::sync::Arc::new(ScriptedFactory::new(0)));
    state.reload(db).await.expect("reload options");
    let response = post_relay(&state, "/v1/chat/completions", r#"{"messages":[]}"#).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = body_json(response).await;
    let message = body["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("Model name not specified") || message.contains("模型名称不能为空"),
        "unexpected message: {message}"
    );

    // ── Distribute：无可用渠道 503 + model_not_found（abilities fail closed）──
    let response = post_relay(&state, "/v1/chat/completions", r#"{"model":"gpt-4"}"#).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = body_json(response).await;
    assert_eq!(body["error"]["code"], "model_not_found");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("No available channel for model gpt-4 under group default")
    );

    // ── abilities 过滤 + route-unit 选择 + 全链（pre_consume → dispatch → settle）
    // 渠道 1 启用且在 abilities；渠道 2 启用但无 abilities 行（分组隔离剔除）；
    // 渠道 3 在 abilities 但已禁用（状态过滤剔除）。
    seed_channel(db, 1, 1, "sk-ch1", "gpt-4", "default").await;
    seed_channel(db, 2, 1, "sk-ch2", "gpt-4", "default").await;
    seed_channel(db, 3, 2, "sk-ch3", "gpt-4", "default").await;
    seed_ability(db, "default", "gpt-4", 1, true).await;
    seed_ability(db, "default", "gpt-4", 2, true).await;
    seed_ability(db, "default", "gpt-4", 3, true).await;
    seed_route(db, "gpt-4", 1, 0, "gpt-4", 10).await;
    seed_route(db, "gpt-4", 2, 0, "gpt-4", 10).await;
    seed_route(db, "gpt-4", 3, 0, "gpt-4", 10).await;

    let factory = std::sync::Arc::new(ScriptedFactory::new(0));
    let state = state_with(db, factory.clone());
    state.reload(db).await.expect("reload options");
    let response = post_relay(
        &state,
        "/v1/chat/completions",
        r#"{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}"#,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["id"], "chatcmpl-stub");
    assert_eq!(body["usage"]["total_tokens"], 15);
    // adaptor 调用链恰好一次（成功即返回，无重试）。
    assert_eq!(factory.call_count(), 1);

    // 结算面：usage 15 tokens（10 prompt + 5 completion × 默认 completion
    // 倍率表）× 倍率 1 × 分组倍率 1 → users.quota 减去实际消耗；预扣费的
    // 500 底价 + max_tokens 差额已由 settle 差额调整抹平。
    let quota_after = user_quota_of(db, USER_ID).await;
    let consumed = USER_QUOTA - quota_after;
    assert!(
        consumed > 0 && consumed < 200,
        "expected usage-bounded settle, got {consumed}"
    );
    // 消费日志落库（LogConsumeEnabled）。
    assert_eq!(consume_log_count(db).await, 1);

    // ── 重试语义：首次 Retryable 失败换道，第二次成功（RetryTimes=1）────
    set_option(db, "RetryTimes", "1").await;
    let factory = std::sync::Arc::new(ScriptedFactory::new(1));
    let state = state_with(db, factory.clone());
    let response = post_relay(
        &state,
        "/v1/chat/completions",
        r#"{"model":"gpt-4","messages":[]}"#,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        factory.call_count(),
        2,
        "retryable failure switches channel"
    );

    // ── 重试语义：两候选全败 → 重选无候选 → failover 终态 503 ────────────
    // RetryTimes=3：尝试 0/1 各败一候选；尝试 2 重选无候选（全排除）→
    // getChannel 失败面 terminalFailoverError（健康表未合流 → 无冷却 → 503）。
    set_option(db, "RetryTimes", "3").await;
    let factory = std::sync::Arc::new(ScriptedFactory::new(10));
    let state = state_with(db, factory.clone());
    state.reload(db).await.expect("reload options");
    let response = post_relay(
        &state,
        "/v1/chat/completions",
        r#"{"model":"gpt-4","messages":[]}"#,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = body_json(response).await;
    assert_eq!(body["error"]["code"], "get_channel_failed");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("所有路由暂时不可用"),
        "unexpected: {:?}",
        body["error"]["message"]
    );
    assert_eq!(
        factory.call_count(),
        2,
        "two candidates, then pool exhausted"
    );
    // 失败面退款：预扣费全额返还（额度停留在两次成功结算后的水位）。
    assert_eq!(user_quota_of(db, USER_ID).await, USER_QUOTA - 15 - 15);

    // ── specific channel：管理员 key-<id> 直通（非管理员在 TokenAuth 403）──
    set_option(db, "RetryTimes", "0").await;
    seed_user(db, USER_QUOTA, "default", 10).await; // admin
    seed_token(db, TOKEN_KEY, "").await;
    let factory = std::sync::Arc::new(ScriptedFactory::new(0));
    let state = state_with(db, factory.clone());
    let response = router(state.clone())
        .oneshot(
            axum::extract::Request::builder()
                .method(Method::POST)
                .uri("/v1/chat/completions")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer sk-{TOKEN_KEY}-1"))
                .body(Body::from(r#"{"model":"gpt-4"}"#.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(factory.call_count(), 1);

    // specific channel 指向禁用渠道 → 403 channel_disabled。
    let response = router(state.clone())
        .oneshot(
            axum::extract::Request::builder()
                .method(Method::POST)
                .uri("/v1/chat/completions")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer sk-{TOKEN_KEY}-3"))
                .body(Body::from(r#"{"model":"gpt-4"}"#.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = body_json(response).await;
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("channel has been disabled")
    );
    seed_user(db, USER_QUOTA, "default", 1).await; // 回到普通用户

    // ── token 模型限额：不在列表 → 403 ───────────────────────────────────
    backend!(db, pool, {
        sqlx::query(r#"UPDATE tokens SET model_limits_enabled = TRUE, model_limits = 'other-model' WHERE "key" = $1"#)
            .bind(TOKEN_KEY)
            .execute(pool)
            .await
            .expect("limit token");
    });
    let factory = std::sync::Arc::new(ScriptedFactory::new(0));
    let state = state_with(db, factory);
    let response = post_relay(
        &state,
        "/v1/chat/completions",
        r#"{"model":"gpt-4","messages":[]}"#,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = body_json(response).await;
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("no access to model gpt-4")
    );
    backend!(db, pool, {
        sqlx::query(
            r#"UPDATE tokens SET model_limits_enabled = FALSE, model_limits = '' WHERE "key" = $1"#,
        )
        .bind(TOKEN_KEY)
        .execute(pool)
        .await
        .expect("unlimit token");
    });

    // ── 未定价模型 → 400 model_price_error（管理员自用模式关闭面）────────
    seed_route(db, "unpriced-model", 1, 0, "unpriced-model", 1).await;
    seed_ability(db, "default", "unpriced-model", 1, true).await;
    let factory = std::sync::Arc::new(ScriptedFactory::new(0));
    let state = state_with(db, factory);
    state.reload(db).await.expect("reload options");
    let response = post_relay(
        &state,
        "/v1/chat/completions",
        r#"{"model":"unpriced-model","messages":[]}"#,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = body_json(response).await;
    assert_eq!(body["error"]["code"], "model_price_error");

    // ── Claude 信封形状（/v1/messages 失败 → {"type":"error",...}）────────
    // RetryTimes=0（单尝试）：渠道域失败可重试但尝试帽已尽 → 最后一次尝试
    // 的原始错误直通（Go 循环条件出口，不是 failover 包裹）。
    set_option(db, "RetryTimes", "0").await;
    let factory = std::sync::Arc::new(ScriptedFactory::new(10));
    let state = state_with(db, factory);
    state.reload(db).await.expect("reload options");
    let response = post_relay(
        &state,
        "/v1/messages",
        r#"{"model":"gpt-4","max_tokens":16,"messages":[]}"#,
    )
    .await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = body_json(response).await;
    assert_eq!(body["type"], "error");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("do request failed"),
        "unexpected: {:?}",
        body["error"]["message"]
    );
    // Claude 面：预扣费退款返还（max_tokens 16 → 预扣 516 × 倍率，失败全额退）。
    assert_eq!(user_quota_of(db, USER_ID).await, USER_QUOTA - 15 - 15);
}

#[tokio::test]
async fn sqlite_contract() {
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .expect("sqlite pool");
    run_contract(&Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn postgres_contract() {
    let Some(dsn) = std::env::var("TEST_POSTGRES_DSN")
        .ok()
        .filter(|s| !s.is_empty())
    else {
        eprintln!("TEST_POSTGRES_DSN absent; skipping postgres contract");
        return;
    };
    let schema = format!(
        "relay_dispatch_{}_{}",
        std::process::id(),
        NEXT_SCHEMA.fetch_add(1, Ordering::Relaxed)
    );
    let options = dsn
        .parse::<sqlx::postgres::PgConnectOptions>()
        .expect("pg dsn");
    let pool = PgPoolOptions::new()
        .after_connect(move |conn, _meta| {
            let schema = schema.clone();
            Box::pin(async move {
                let escaped = schema.replace('"', "\"\"");
                // schema 名为进程内合成值（非用户输入）：AssertSqlSafe 审计面。
                let create = format!(r#"CREATE SCHEMA IF NOT EXISTS "{escaped}""#);
                sqlx::query(sqlx::AssertSqlSafe(create))
                    .execute(&mut *conn)
                    .await?;
                let set_path = format!(r#"SET search_path TO "{escaped}""#);
                sqlx::query(sqlx::AssertSqlSafe(set_path))
                    .execute(&mut *conn)
                    .await?;
                Ok(())
            })
        })
        .connect_with(options)
        .await
        .expect("pg pool");
    let db = Database::Postgres(pool);
    // 共享 DDL 幂等（PG fixture 先例）：序列对齐 seed 后 setval。
    create_schema(&db).await;
    backend!(&db, pool, {
        for table in [
            "users_id_seq",
            "tokens_id_seq",
            "channels_id_seq",
            "channel_model_routes_id_seq",
            "user_subscriptions_id_seq",
            "subscription_plans_id_seq",
            "subscription_pre_consume_records_id_seq",
            "logs_id_seq",
        ] {
            // setval 序列名来自测试常量表（非用户输入）：AssertSqlSafe 审计面。
            let sql = format!(
                r#"SELECT setval('{table}', COALESCE((SELECT MAX(id) FROM "{}" ), 1))"#,
                table.strip_suffix("_id_seq").unwrap_or(table)
            );
            let _ = sqlx::query(sqlx::AssertSqlSafe(sql)).execute(pool).await;
        }
    });
    run_contract(&db).await;
}
