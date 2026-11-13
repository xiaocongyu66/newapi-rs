//! 计费核心契约测试：SQLite 内存 + PG（TEST_POSTGRES_DSN）双后端。
//!
//! 对照 Go `consume_quota_realtime_settle_test.go`（F6 不变量）、
//! `consume_quota_saturation_test.go`、`quota_reserve_test.go`、
//! `store_redemption_test.go` 的 seed 模式，与
//! `consume_text_quota_test.go` 的公式锚点。

use super::funding::{Funding, SubscriptionFunding};
use super::pricing::{PriceData, RatioSettings, StaticRatioSettings};
use super::quota_math::QUOTA_PER_UNIT;
use super::realtime::{
    QuotaInfo, TokenDetails, WssCallContext, calculate_audio_quota, post_wss_consume_quota,
    pre_wss_consume_quota,
};
use super::session::{
    ERROR_CODE_INSUFFICIENT_USER_QUOTA, RelayBillingInfo, new_billing_session, post_consume_quota,
};
use super::store::BillingStore;
use super::text_quota::{
    TextCallContext, ToolSurchargeItem, apply_empty_response_multiplier,
    calculate_text_quota_summary, is_undelivered_text_response, merge_tool_surcharge_items,
};
use super::usage::{RealtimeUsage, Usage};
use newapi_storage::Database;
use sqlx::ConnectOptions;

// ---------------------------------------------------------------------------
// 双后端 fixture
// ---------------------------------------------------------------------------

const USERS_SQLITE: &str = "CREATE TABLE users (\
     id INTEGER PRIMARY KEY, quota INTEGER NOT NULL DEFAULT 0, used_quota INTEGER NOT NULL DEFAULT 0, \
     request_count INTEGER NOT NULL DEFAULT 0, username TEXT NOT NULL DEFAULT '', \
     setting TEXT, email TEXT NOT NULL DEFAULT '')";
const USERS_PG: &str = "CREATE TABLE users (\
     id BIGINT PRIMARY KEY, quota BIGINT NOT NULL DEFAULT 0, used_quota BIGINT NOT NULL DEFAULT 0, \
     request_count BIGINT NOT NULL DEFAULT 0, username TEXT NOT NULL DEFAULT '', \
     setting TEXT, email TEXT NOT NULL DEFAULT '')";
const TOKENS_SQLITE: &str = "CREATE TABLE tokens (\
     id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, key TEXT NOT NULL UNIQUE, \
     remain_quota INTEGER NOT NULL DEFAULT 0, used_quota INTEGER NOT NULL DEFAULT 0, \
     unlimited_quota INTEGER NOT NULL DEFAULT 0, status INTEGER NOT NULL DEFAULT 1, \
     accessed_time INTEGER NOT NULL DEFAULT 0)";
const TOKENS_PG: &str = "CREATE TABLE tokens (\
     id BIGINT PRIMARY KEY, user_id BIGINT NOT NULL, key TEXT NOT NULL UNIQUE, \
     remain_quota BIGINT NOT NULL DEFAULT 0, used_quota BIGINT NOT NULL DEFAULT 0, \
     unlimited_quota BIGINT NOT NULL DEFAULT 0, status BIGINT NOT NULL DEFAULT 1, \
     accessed_time BIGINT NOT NULL DEFAULT 0)";
const CHANNELS_SQLITE: &str =
    "CREATE TABLE channels (id INTEGER PRIMARY KEY, used_quota BIGINT NOT NULL DEFAULT 0)";
const CHANNELS_PG: &str =
    "CREATE TABLE channels (id BIGINT PRIMARY KEY, used_quota BIGINT NOT NULL DEFAULT 0)";
const SUBS_SQLITE: &str = "CREATE TABLE user_subscriptions (\
     id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, plan_id INTEGER NOT NULL, \
     amount_total BIGINT NOT NULL DEFAULT 0, amount_used BIGINT NOT NULL DEFAULT 0, \
     start_time BIGINT NOT NULL DEFAULT 0, end_time BIGINT NOT NULL DEFAULT 0, \
     status TEXT NOT NULL DEFAULT 'active', source TEXT NOT NULL DEFAULT 'order', \
     last_reset_time BIGINT NOT NULL DEFAULT 0, next_reset_time BIGINT NOT NULL DEFAULT 0, \
     allow_wallet_overflow INTEGER NOT NULL DEFAULT 1, updated_at BIGINT NOT NULL DEFAULT 0)";
const SUBS_PG: &str = "CREATE TABLE user_subscriptions (\
     id BIGINT PRIMARY KEY, user_id BIGINT NOT NULL, plan_id BIGINT NOT NULL, \
     amount_total BIGINT NOT NULL DEFAULT 0, amount_used BIGINT NOT NULL DEFAULT 0, \
     start_time BIGINT NOT NULL DEFAULT 0, end_time BIGINT NOT NULL DEFAULT 0, \
     status TEXT NOT NULL DEFAULT 'active', source TEXT NOT NULL DEFAULT 'order', \
     last_reset_time BIGINT NOT NULL DEFAULT 0, next_reset_time BIGINT NOT NULL DEFAULT 0, \
     allow_wallet_overflow BIGINT NOT NULL DEFAULT 1, updated_at BIGINT NOT NULL DEFAULT 0)";
const PLANS_SQLITE: &str = "CREATE TABLE subscription_plans (\
     id INTEGER PRIMARY KEY, title TEXT NOT NULL DEFAULT '', \
     quota_reset_period TEXT NOT NULL DEFAULT 'never', quota_reset_custom_seconds BIGINT NOT NULL DEFAULT 0, \
     updated_at BIGINT NOT NULL DEFAULT 0)";
const PLANS_PG: &str = "CREATE TABLE subscription_plans (\
     id BIGINT PRIMARY KEY, title TEXT NOT NULL DEFAULT '', \
     quota_reset_period TEXT NOT NULL DEFAULT 'never', quota_reset_custom_seconds BIGINT NOT NULL DEFAULT 0, \
     updated_at BIGINT NOT NULL DEFAULT 0)";
const RECORDS_SQLITE: &str = "CREATE TABLE subscription_pre_consume_records (\
     id INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT NOT NULL UNIQUE, \
     user_id INTEGER NOT NULL, user_subscription_id INTEGER NOT NULL, \
     pre_consumed BIGINT NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'consumed', \
     created_at BIGINT NOT NULL DEFAULT 0, updated_at BIGINT NOT NULL DEFAULT 0)";
const RECORDS_PG: &str = "CREATE TABLE subscription_pre_consume_records (\
     id BIGSERIAL PRIMARY KEY, request_id TEXT NOT NULL UNIQUE, \
     user_id BIGINT NOT NULL, user_subscription_id BIGINT NOT NULL, \
     pre_consumed BIGINT NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'consumed', \
     created_at BIGINT NOT NULL DEFAULT 0, updated_at BIGINT NOT NULL DEFAULT 0)";
const LOGS_SQLITE: &str = "CREATE TABLE logs (\
     id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL DEFAULT 0, \
     created_at BIGINT NOT NULL DEFAULT 0, type INTEGER NOT NULL DEFAULT 0, content TEXT, \
     username TEXT NOT NULL DEFAULT '', token_name TEXT NOT NULL DEFAULT '', \
     model_name TEXT NOT NULL DEFAULT '', quota INTEGER NOT NULL DEFAULT 0, \
     prompt_tokens INTEGER NOT NULL DEFAULT 0, completion_tokens INTEGER NOT NULL DEFAULT 0, \
     use_time INTEGER NOT NULL DEFAULT 0, is_stream INTEGER NOT NULL DEFAULT 0, \
     channel_id INTEGER NOT NULL DEFAULT 0, token_id INTEGER NOT NULL DEFAULT 0, \
     \"group\" TEXT NOT NULL DEFAULT '', ip TEXT NOT NULL DEFAULT '', \
     request_id TEXT NOT NULL DEFAULT '', upstream_request_id TEXT NOT NULL DEFAULT '', \
     other TEXT)";
const LOGS_PG: &str = "CREATE TABLE logs (\
     id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL DEFAULT 0, \
     created_at BIGINT NOT NULL DEFAULT 0, type BIGINT NOT NULL DEFAULT 0, content TEXT, \
     username TEXT NOT NULL DEFAULT '', token_name TEXT NOT NULL DEFAULT '', \
     model_name TEXT NOT NULL DEFAULT '', quota BIGINT NOT NULL DEFAULT 0, \
     prompt_tokens BIGINT NOT NULL DEFAULT 0, completion_tokens BIGINT NOT NULL DEFAULT 0, \
     use_time BIGINT NOT NULL DEFAULT 0, is_stream BIGINT NOT NULL DEFAULT 0, \
     channel_id BIGINT NOT NULL DEFAULT 0, token_id BIGINT NOT NULL DEFAULT 0, \
     \"group\" TEXT NOT NULL DEFAULT '', ip TEXT NOT NULL DEFAULT '', \
     request_id TEXT NOT NULL DEFAULT '', upstream_request_id TEXT NOT NULL DEFAULT '', \
     other TEXT)";

async fn create_schema(db: &Database) {
    let statements: &[&str] = match db {
        Database::Sqlite(_) => &[
            USERS_SQLITE,
            TOKENS_SQLITE,
            CHANNELS_SQLITE,
            SUBS_SQLITE,
            PLANS_SQLITE,
            RECORDS_SQLITE,
            LOGS_SQLITE,
        ],
        Database::Postgres(_) => &[
            USERS_PG,
            TOKENS_PG,
            CHANNELS_PG,
            SUBS_PG,
            PLANS_PG,
            RECORDS_PG,
            LOGS_PG,
        ],
    };
    for statement in statements {
        match db {
            Database::Sqlite(pool) => {
                sqlx::query(*statement).execute(pool).await.unwrap();
            }
            Database::Postgres(pool) => {
                sqlx::query(*statement).execute(pool).await.unwrap();
            }
        }
    }
}

async fn connect_sqlite() -> Database {
    let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
    let db = Database::Sqlite(pool);
    create_schema(&db).await;
    db
}

async fn connect_postgres() -> Option<Database> {
    let Ok(dsn) = std::env::var("TEST_POSTGRES_DSN") else {
        return None;
    };
    let options: sqlx::postgres::PgConnectOptions = dsn.parse().unwrap();
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone().disable_statement_logging())
        .await
        .unwrap();
    let schema = format!("billing_session_{}", std::process::id());
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"
    )))
    .execute(&admin)
    .await
    .unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA \"{schema}\"")))
        .execute(&admin)
        .await
        .unwrap();
    let search_path = schema.clone();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .idle_timeout(None)
        .max_lifetime(None)
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
        .connect_with(options.disable_statement_logging())
        .await
        .unwrap();
    let db = Database::Postgres(pool);
    create_schema(&db).await;
    Some(db)
}

// 兼容 rust 1.99 的 AsyncFn（edition 2024 内建）不可用时退化写法：
async fn run_db_contract(db: &Database, contract: impl AsyncFn(&Database)) {
    contract(db).await;
}

macro_rules! backend_tests {
    ($($name:ident => $body:expr;)*) => {
        $(
            #[tokio::test]
            async fn $name() {
                let sqlite = connect_sqlite().await;
                run_db_contract(&sqlite, $body).await;
                if let Some(pg) = connect_postgres().await {
                    run_db_contract(&pg, $body).await;
                }
            }
        )*
    };
}

/// 测试内 SQL 执行（Database 无 pub pool 访问器，走双后端 match）。
async fn texec(db: &Database, sql: &str, binds: &[i64]) -> sqlx::Result<u64> {
    match db {
        Database::Sqlite(pool) => {
            let mut q = sqlx::query(sql);
            for b in binds {
                q = q.bind(*b);
            }
            q.execute(pool).await.map(|r| r.rows_affected())
        }
        Database::Postgres(pool) => {
            let mut q = sqlx::query(sql);
            for b in binds {
                q = q.bind(*b);
            }
            q.execute(pool).await.map(|r| r.rows_affected())
        }
    }
}

async fn seed_user(db: &Database, id: i64, quota: i64) {
    texec(
        db,
        "INSERT INTO users (id, quota) VALUES ($1, $2)",
        &[id, quota],
    )
    .await
    .unwrap();
}

async fn seed_token(db: &Database, id: i64, user_id: i64, key: &str, remain: i64, unlimited: bool) {
    let mut binds = vec![id, user_id, remain, if unlimited { 1 } else { 0 }];
    // key 是字符串：单独执行避免 binds 全 i64 的简化签名
    match db {
        Database::Sqlite(pool) => {
            sqlx::query("INSERT INTO tokens (id, user_id, key, remain_quota, unlimited_quota) VALUES ($1,$2,$3,$4,$5)")
                .bind(id).bind(user_id).bind(key).bind(remain).bind(unlimited)
                .execute(pool).await.unwrap();
        }
        Database::Postgres(pool) => {
            sqlx::query("INSERT INTO tokens (id, user_id, key, remain_quota, unlimited_quota) VALUES ($1,$2,$3,$4,$5)")
                .bind(id).bind(user_id).bind(key).bind(remain).bind(unlimited)
                .execute(pool).await.unwrap();
        }
    }
    let _ = &mut binds;
}

async fn seed_channel(db: &Database, id: i64) {
    texec(
        db,
        "INSERT INTO channels (id, used_quota) VALUES ($1, 0)",
        &[id],
    )
    .await
    .unwrap();
}

async fn channel_used(db: &Database, id: i64) -> i64 {
    tscalar(db, "SELECT used_quota FROM channels WHERE id = $1", id).await
}

async fn seed_subscription(
    db: &Database,
    id: i64,
    user_id: i64,
    total: i64,
    used: i64,
    allow_overflow: bool,
) {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query("INSERT INTO user_subscriptions (id, user_id, plan_id, amount_total, amount_used, \
             start_time, end_time, status, allow_wallet_overflow) VALUES ($1,$2,$3,$4,$5,$6,$7,'active',$8)")
                .bind(id).bind(user_id).bind(1i64).bind(total).bind(used)
                .bind(1_000_000i64).bind(9_000_000i64).bind(allow_overflow)
                .execute(pool).await.unwrap();
        }
        Database::Postgres(pool) => {
            sqlx::query("INSERT INTO user_subscriptions (id, user_id, plan_id, amount_total, amount_used, \
             start_time, end_time, status, allow_wallet_overflow) VALUES ($1,$2,$3,$4,$5,$6,$7,'active',$8)")
                .bind(id).bind(user_id).bind(1i64).bind(total).bind(used)
                .bind(1_000_000i64).bind(9_000_000i64).bind(allow_overflow)
                .execute(pool).await.unwrap();
        }
    }
    match db {
        Database::Sqlite(pool) => {
            sqlx::query("INSERT INTO subscription_plans (id, title, quota_reset_period) VALUES (1,'p','never')")
                .execute(pool).await.unwrap();
        }
        Database::Postgres(pool) => {
            sqlx::query("INSERT INTO subscription_plans (id, title, quota_reset_period) VALUES (1,'p','never')")
                .execute(pool).await.unwrap();
        }
    }
}

async fn tscalar(db: &Database, sql: &str, id: i64) -> i64 {
    match db {
        Database::Sqlite(pool) => sqlx::query_scalar::<_, i64>(sql)
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap(),
        Database::Postgres(pool) => sqlx::query_scalar::<_, i64>(sql)
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap(),
    }
}

async fn user_quota(db: &Database, id: i64) -> i64 {
    tscalar(db, "SELECT quota FROM users WHERE id = $1", id).await
}

async fn token_remain(db: &Database, id: i64) -> i64 {
    tscalar(db, "SELECT remain_quota FROM tokens WHERE id = $1", id).await
}

async fn sub_used(db: &Database, id: i64) -> i64 {
    tscalar(
        db,
        "SELECT amount_used FROM user_subscriptions WHERE id = $1",
        id,
    )
    .await
}

fn relay_info(user_id: i64, token_id: i64, token_key: &str, request_id: &str) -> RelayBillingInfo {
    RelayBillingInfo {
        user_id,
        token_id,
        token_key: token_key.to_string(),
        request_id: request_id.to_string(),
        origin_model_name: "gpt-4o".into(),
        using_group: "default".into(),
        user_group: "default".into(),
        channel_id: 1,
        billing_preference: "".into(),
        ..Default::default()
    }
}

fn ratio_settings_1to1() -> StaticRatioSettings {
    let mut settings = StaticRatioSettings::default();
    settings.group_ratios.insert("default".into(), 1.0);
    settings
        .completion_ratios
        .insert("realtime-test-model".into(), 1.0);
    settings
        .audio_ratios
        .insert("realtime-test-model".into(), 1.0);
    settings
        .audio_completion_ratios
        .insert("realtime-test-model".into(), 1.0);
    settings
        .model_ratios
        .insert("realtime-test-model".into(), 1.0);
    settings
}

fn price_data_1to1() -> PriceData {
    PriceData {
        model_ratio: 1.0,
        completion_ratio: 1.0,
        cache_ratio: 1.0,
        cache_creation_ratio: 1.0,
        group_ratio_info: super::pricing::GroupRatioInfo {
            group_ratio: 1.0,
            ..Default::default()
        },
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// 会话生命周期
// ---------------------------------------------------------------------------

backend_tests! {
    wallet_preconsume_settle_and_refund => async |db: &Database| {
        seed_user(db, 1, 100_000).await;
        seed_token(db, 11, 1, "sk-t1", 50_000, false).await;
        let store = BillingStore::new(db.clone());
        let info = relay_info(1, 11, "sk-t1", "req-w1");
        // 预扣 30000：用户 100k → 70k，令牌 50k → 20k
        let mut session = new_billing_session(&store, info, 30_000).await.expect("session");
        assert_eq!(user_quota(db, 1).await, 70_000);
        assert_eq!(token_remain(db, 11).await, 20_000);
        assert_eq!(session.get_pre_consumed_quota(), 30_000);
        assert!(session.needs_refund());
        assert_eq!(session.info.billing_source, "wallet");

        // 实际消耗 42_000：补扣 12_000
        session.settle_billing(42_000).await.expect("settle");
        assert_eq!(user_quota(db, 1).await, 58_000);
        assert_eq!(token_remain(db, 11).await, 8_000);
        assert!(!session.needs_refund(), "settled sessions must not refund");
    };

    wallet_refund_restores_quota => async |db: &Database| {
        seed_user(db, 2, 100_000).await;
        seed_token(db, 12, 2, "sk-t2", 50_000, false).await;
        let store = BillingStore::new(db.clone());
        let info = relay_info(2, 12, "sk-t2", "req-w2");
        let mut session = new_billing_session(&store, info, 30_000).await.unwrap();
        session.refund().await;
        assert_eq!(user_quota(db, 2).await, 100_000);
        assert_eq!(token_remain(db, 12).await, 50_000);
        // 幂等：二次 refund 不再多退
        session.refund().await;
        assert_eq!(user_quota(db, 2).await, 100_000);
    };

    wallet_insufficient_maps_to_quota_error => async |db: &Database| {
        seed_user(db, 3, 10_000).await;
        seed_token(db, 13, 3, "sk-t3", 50_000, false).await;
        let store = BillingStore::new(db.clone());
        let info = relay_info(3, 13, "sk-t3", "req-w3");
        let err = new_billing_session(&store, info, 30_000).await.expect_err("must fail");
        assert_eq!(err.code, ERROR_CODE_INSUFFICIENT_USER_QUOTA);
        assert_eq!(err.status, 403);
        assert!(err.no_record_error_log);
        // 原子性：未发生部分扣减
        assert_eq!(user_quota(db, 3).await, 10_000);
        assert_eq!(token_remain(db, 13).await, 50_000);
    };

    trust_bypass_skips_preconsume => async |db: &Database| {
        // user_quota=2M > trust(5M)? 不行——trust = 10*QuotaPerUnit = 5M。
        // 用 6M 用户 + unlimited token 触发旁路。
        seed_user(db, 4, 6_000_000).await;
        seed_token(db, 14, 4, "sk-t4", 0, true).await;
        let store = BillingStore::new(db.clone());
        let mut info = relay_info(4, 14, "sk-t4", "req-w4");
        info.token_unlimited = true;
        let session = new_billing_session(&store, info, 30_000).await.unwrap();
        assert!(session.get_pre_consumed_quota() == 0, "trusted bypass pre-consumes nothing");
        assert_eq!(user_quota(db, 4).await, 6_000_000);
        assert_eq!(token_remain(db, 14).await, 0);
    };

    subscription_session_preconsumes => async |db: &Database| {
        seed_user(db, 5, 0).await;
        seed_token(db, 15, 5, "sk-t5", 50_000, false).await;
        seed_subscription(db, 21, 5, 100_000, 0, true).await;
        let store = BillingStore::new(db.clone());
        let info = relay_info(5, 15, "sk-t5", "req-s1");
        let mut session = new_billing_session(&store, info, 20_000).await.unwrap();
        assert_eq!(session.info.billing_source, "subscription");
        assert_eq!(sub_used(db, 21).await, 20_000);
        assert_eq!(session.info.subscription_id, 21);
        assert_eq!(session.info.subscription_pre_consumed, 20_000);
        // 默认偏好（subscription_first）在无活跃订阅时走钱包；此处有订阅 → 走订阅。
        // 结算 15_000：返还 5_000。
        session.settle_billing(15_000).await.unwrap();
        assert_eq!(sub_used(db, 21).await, 15_000);
        assert_eq!(session.info.subscription_post_delta, -5_000);
        // 令牌跟着结算差额一起返还
        assert_eq!(token_remain(db, 15).await, 55_000);
    };

    wallet_first_falls_back_to_subscription => async |db: &Database| {
        seed_user(db, 6, 0).await;
        seed_token(db, 16, 6, "sk-t6", 50_000, false).await;
        seed_subscription(db, 22, 6, 100_000, 0, true).await;
        let store = BillingStore::new(db.clone());
        let mut info = relay_info(6, 16, "sk-t6", "req-s2");
        info.billing_preference = "wallet_first".into();
        let session = new_billing_session(&store, info, 20_000).await.unwrap();
        assert_eq!(session.info.billing_source, "subscription");
    };

    subscription_first_blocks_wallet_without_overflow => async |db: &Database| {
        seed_user(db, 7, 100_000).await;
        seed_token(db, 17, 7, "sk-t7", 50_000, false).await;
        seed_subscription(db, 23, 7, 10_000, 0, false).await;
        let store = BillingStore::new(db.clone());
        let mut info = relay_info(7, 17, "sk-t7", "req-s3");
        info.billing_preference = "subscription_first".into();
        // 订阅余量 10k < 预扣 20k，且 allow_wallet_overflow=false → 不回退钱包
        let err = new_billing_session(&store, info, 20_000).await.expect_err("blocked");
        assert_eq!(err.code, ERROR_CODE_INSUFFICIENT_USER_QUOTA);
    };

    subscription_first_overflows_to_wallet_when_allowed => async |db: &Database| {
        seed_user(db, 8, 100_000).await;
        seed_token(db, 18, 8, "sk-t8", 50_000, false).await;
        seed_subscription(db, 24, 8, 10_000, 0, true).await;
        let store = BillingStore::new(db.clone());
        let mut info = relay_info(8, 18, "sk-t8", "req-s4");
        info.billing_preference = "subscription_first".into();
        let session = new_billing_session(&store, info, 20_000).await.unwrap();
        assert_eq!(session.info.billing_source, "wallet");
    };

    reserve_tops_up_preconsume_atomically => async |db: &Database| {
        seed_user(db, 9, 100_000).await;
        seed_token(db, 19, 9, "sk-t9", 100_000, false).await;
        let store = BillingStore::new(db.clone());
        let info = relay_info(9, 19, "sk-t9", "req-w9");
        let mut session = new_billing_session(&store, info, 10_000).await.unwrap();
        session.reserve(25_000).await.expect("reserve");
        assert_eq!(session.get_pre_consumed_quota(), 25_000);
        assert_eq!(user_quota(db, 9).await, 75_000);
        assert_eq!(token_remain(db, 19).await, 75_000);
        // 结算不足额时多退（25_000 → 实际 5_000）
        session.settle_billing(5_000).await.unwrap();
        assert_eq!(user_quota(db, 9).await, 95_000);
    };

    // F6 不变量：逐次增量直扣后，累计结算只补差额，整段会话恰好付一次。
    realtime_batches_settle_once_against_cumulative_usage => async |db: &Database| {
        seed_user(db, 91, 500_000).await;
        seed_token(db, 92, 91, "sk-realtime-test", 500_000, true).await;
        seed_channel(db, 1).await;
        let store = BillingStore::new(db.clone());
        let settings = ratio_settings_1to1();
        let price = price_data_1to1();
        let mut info = relay_info(91, 92, "sk-realtime-test", "req-rt");
        info.token_unlimited = true;

        let usage = |units: i64| RealtimeUsage {
            total_tokens: 2 * units,
            input_tokens: units,
            output_tokens: units,
            input_token_details: TokenDetails { text_tokens: units, ..Default::default() },
            output_token_details: TokenDetails { text_tokens: units, ..Default::default() },
        };

        let call = WssCallContext::default();
        pre_wss_consume_quota(&store, &settings, &mut info, &price, &usage(10), &call).await.expect("batch 1");
        pre_wss_consume_quota(&store, &settings, &mut info, &price, &usage(20), &call).await.expect("batch 2");
        assert_eq!(info.realtime_charged_quota, 30);
        assert_eq!(user_quota(db, 91).await, 500_000 - 30);

        // 结算对累计用量（30 units in + 30 out = 60 quota）只补差额 30。
        let outcome = post_wss_consume_quota(
            &store, &settings, &mut info, &price,
            "realtime-test-model", &usage(30), "", None, 2_000, 1_000,
        ).await.expect("settle");
        assert_eq!(outcome.quota, 60);
        assert_eq!(user_quota(db, 91).await, 500_000 - 60, "session pays total usage exactly once");
        assert_eq!(channel_used(db, 1).await, 60);
    };

    post_consume_quota_wallet_and_token => async |db: &Database| {
        seed_user(db, 31, 100_000).await;
        seed_token(db, 32, 31, "sk-t31", 100_000, false).await;
        let store = BillingStore::new(db.clone());
        let mut info = relay_info(31, 32, "sk-t31", "req-pc");
        post_consume_quota(&store, &mut info, 7_000, 0).await.unwrap();
        assert_eq!(user_quota(db, 31).await, 93_000);
        assert_eq!(token_remain(db, 32).await, 93_000);
        // 负差额 = 退还
        post_consume_quota(&store, &mut info, -2_000, 0).await.unwrap();
        assert_eq!(user_quota(db, 31).await, 95_000);
        assert_eq!(token_remain(db, 32).await, 95_000);
        // playground 不动令牌
        let mut pg_info = relay_info(31, 32, "sk-t31", "req-pc2");
        pg_info.is_playground = true;
        post_consume_quota(&store, &mut pg_info, 3_000, 0).await.unwrap();
        assert_eq!(user_quota(db, 31).await, 92_000);
        assert_eq!(token_remain(db, 32).await, 95_000);
    };

    subscription_delta_capped_overflow_to_wallet => async |db: &Database| {
        seed_user(db, 41, 1_000).await;
        seed_subscription(db, 42, 41, 1_000, 900, true).await;
        let store = BillingStore::new(db.clone());
        // 补扣 500：订阅只剩 100，溢出 400 记钱包欠费
        let overflow = store
            .post_consume_user_subscription_delta_capped(42, 500, 2_000)
            .await
            .unwrap();
        assert_eq!(overflow, 400);
        assert_eq!(sub_used(db, 42).await, 1_000);
        // 严格版超总量整笔拒绝（不部分入账）
        let err = store
            .post_consume_user_subscription_delta(42, 500, 2_000)
            .await
            .expect_err("strict reject");
        assert!(err.message().contains("subscription used exceeds total"));
        assert_eq!(sub_used(db, 42).await, 1_000);
        // 负值钳 0
        store.post_consume_user_subscription_delta(42, -5_000, 2_000).await.unwrap();
        assert_eq!(sub_used(db, 42).await, 0);
    };

    subscription_preconsume_idempotent_by_request_id => async |db: &Database| {
        seed_user(db, 51, 0).await;
        seed_subscription(db, 52, 51, 100_000, 0, true).await;
        let store = BillingStore::new(db.clone());
        let first = store
            .pre_consume_user_subscription("req-idem", 51, 30_000, 2_000)
            .await
            .unwrap();
        assert_eq!(first.pre_consumed, 30_000);
        assert_eq!(sub_used(db, 52).await, 30_000);
        // 重放同一 requestId：不重复扣，返回原结果
        let replay = store
            .pre_consume_user_subscription("req-idem", 51, 30_000, 2_000)
            .await
            .unwrap();
        assert_eq!(replay, first);
        assert_eq!(sub_used(db, 52).await, 30_000);
        // 退款后同 requestId 拒绝
        store.refund_subscription_pre_consume("req-idem", 2_500).await.unwrap();
        assert_eq!(sub_used(db, 52).await, 0);
        let err = store
            .pre_consume_user_subscription("req-idem", 51, 30_000, 2_600)
            .await
            .expect_err("already refunded");
        assert_eq!(err.message(), "subscription pre-consume already refunded");
        // refund 幂等
        store.refund_subscription_pre_consume("req-idem", 2_700).await.unwrap();
        assert_eq!(sub_used(db, 52).await, 0);
    };

    subscription_preconsume_picks_candidate_with_room => async |db: &Database| {
        seed_user(db, 61, 0).await;
        // 第一条订阅余量不足，第二条充足 → 按 end_time asc 找到可覆盖候选
        seed_subscription(db, 62, 61, 10_000, 9_000, true).await;
        seed_subscription(db, 63, 61, 100_000, 0, true).await;
        let store = BillingStore::new(db.clone());
        let res = store
            .pre_consume_user_subscription("req-cand", 61, 20_000, 2_000)
            .await
            .unwrap();
        assert_eq!(res.user_subscription_id, 63);
        assert_eq!(sub_used(db, 63).await, 20_000);
        assert_eq!(sub_used(db, 62).await, 9_000);
    };

    // Go consume_quota_saturation_test.go 的落库面：饱和事件挂 admin_info。
    saturation_marker_nests_under_admin_info => async |db: &Database| {
        let mut other = serde_json::Map::new();
        other.insert("model_price".into(), serde_json::json!(0.004));
        super::text_quota::attach_quota_saturation(
            &mut other,
            &super::quota_math::QuotaClamp {
                op: "QuotaFromDecimal",
                kind: super::quota_math::QuotaClampKind::Overflow,
                original: 1.8e19,
                clamped: super::quota_math::MAX_QUOTA,
            },
        );
        let admin = other.get("admin_info").unwrap().as_object().unwrap();
        let sat = admin.get("quota_saturation").unwrap().as_object().unwrap();
        assert_eq!(sat.get("op").unwrap(), "QuotaFromDecimal");
        assert_eq!(sat.get("kind").unwrap(), "overflow");
        // 已有 admin_info 不被覆盖
        let mut other2 = serde_json::Map::new();
        let mut admin2 = serde_json::Map::new();
        admin2.insert("admin_username".into(), serde_json::json!("root"));
        other2.insert("admin_info".into(), serde_json::Value::Object(admin2));
        super::text_quota::attach_quota_saturation(
            &mut other2,
            &super::quota_math::QuotaClamp {
                op: "QuotaFromFloat",
                kind: super::quota_math::QuotaClampKind::Underflow,
                original: -1.8e19,
                clamped: super::quota_math::MIN_QUOTA,
            },
        );
        let admin = other2.get("admin_info").unwrap().as_object().unwrap();
        assert_eq!(admin.get("admin_username").unwrap(), "root");
        assert!(admin.get("quota_saturation").is_some());
        // 无 clamp 不挂 admin_info
        let other3 = serde_json::Map::new();
        assert!(other3.get("admin_info").is_none());
    };
}

// ---------------------------------------------------------------------------
// 纯公式契约（对照 Go consume_text_quota_test.go / quota_math_test.go）
// ---------------------------------------------------------------------------

fn base_summary() -> super::text_quota::TextQuotaSummary {
    super::text_quota::TextQuotaSummary {
        model_name: "gpt-4o".into(),
        group_ratio: 1.0,
        model_ratio: 1.0,
        completion_ratio: 1.0,
        ..Default::default()
    }
}

#[test]
fn text_quota_ratio_formula_matches_go() {
    let settings = StaticRatioSettings::default();
    let mut info = RelayBillingInfo::default();
    info.origin_model_name = "m".into();
    let price = PriceData {
        model_ratio: 1.0,
        completion_ratio: 2.0,
        cache_ratio: 0.5,
        group_ratio_info: super::pricing::GroupRatioInfo {
            group_ratio: 2.0,
            ..Default::default()
        },
        ..Default::default()
    };
    let usage = Usage {
        prompt_tokens: 1000,
        completion_tokens: 500,
        total_tokens: 1500,
        prompt_tokens_details: super::usage::InputTokenDetails {
            cached_tokens: 200,
            ..Default::default()
        },
        ..Default::default()
    };
    let call = TextCallContext {
        final_relay_format: "openai".into(),
        ..Default::default()
    };
    let summary = calculate_text_quota_summary(
        &settings,
        &mut info,
        &price,
        Some(&usage),
        &call,
        2_000,
        1_000,
    );
    // base = (1000-200) + 200*0.5 = 900；completion = 500*2 = 1000；
    // quota = (900 + 1000) * (1*2) = 3800
    assert_eq!(summary.quota, 3800);
    assert_eq!(summary.use_time_seconds, 1_000);
}

#[test]
fn text_quota_minimum_unit_when_ratio_nonzero() {
    let settings = StaticRatioSettings::default();
    let mut info = RelayBillingInfo::default();
    let price = PriceData {
        model_ratio: 1.0,
        group_ratio_info: super::pricing::GroupRatioInfo {
            group_ratio: 1.0,
            ..Default::default()
        },
        ..Default::default()
    };
    let usage = Usage {
        prompt_tokens: 1,
        completion_tokens: 0,
        total_tokens: 1,
        ..Default::default()
    };
    // token 1 * ratio 1 → 小数部分 <0.5 → 四舍五入 1；quota>0 保持
    let call = TextCallContext::default();
    let summary =
        calculate_text_quota_summary(&settings, &mut info, &price, Some(&usage), &call, 0, 0);
    assert_eq!(summary.quota, 1);
}

#[test]
fn text_quota_zero_tokens_not_billable_yields_zero() {
    let settings = StaticRatioSettings::default();
    let mut info = RelayBillingInfo::default();
    let price = PriceData {
        model_ratio: 1.0,
        group_ratio_info: super::pricing::GroupRatioInfo {
            group_ratio: 1.0,
            ..Default::default()
        },
        ..Default::default()
    };
    let call = TextCallContext::default();
    // usage 缺失时回退估计 prompt tokens；这里全部为 0
    let summary = calculate_text_quota_summary(&settings, &mut info, &price, None, &call, 0, 0);
    assert_eq!(summary.quota, 0);
    assert!(!summary.has_billable_usage());
}

#[test]
fn text_quota_saturation_records_clamp() {
    let settings = StaticRatioSettings::default();
    let mut info = RelayBillingInfo::default();
    let price = PriceData {
        model_ratio: f64::MAX / QUOTA_PER_UNIT / 1e6,
        group_ratio_info: super::pricing::GroupRatioInfo {
            group_ratio: 1e30,
            ..Default::default()
        },
        ..Default::default()
    };
    let usage = Usage {
        prompt_tokens: 1_000_000_000,
        completion_tokens: 0,
        total_tokens: 1_000_000_000,
        ..Default::default()
    };
    let call = TextCallContext::default();
    let summary =
        calculate_text_quota_summary(&settings, &mut info, &price, Some(&usage), &call, 0, 0);
    assert_eq!(summary.quota, super::quota_math::MAX_QUOTA);
    let clamp = info.quota_clamp.expect("overflow must record clamp");
    assert_eq!(clamp.kind, super::quota_math::QuotaClampKind::Overflow);
    assert_eq!(clamp.clamped, super::quota_math::MAX_QUOTA);
}

#[test]
fn tool_surcharge_merges_and_bills_per_call() {
    let items = vec![
        ToolSurchargeItem {
            name: "web_search".into(),
            count: 2,
            price: 30.0,
        },
        ToolSurchargeItem {
            name: "web_search".into(),
            count: 3,
            price: 30.0,
        },
        ToolSurchargeItem {
            name: "web_search".into(),
            count: 1,
            price: 25.0,
        },
    ];
    let merged = merge_tool_surcharge_items(items);
    // 排序 (name asc, price asc)：25 一行、30 合并 5 次
    assert_eq!(merged.len(), 2);
    assert_eq!(merged[0].price, 25.0);
    assert_eq!(merged[0].count, 1);
    assert_eq!(merged[1].price, 30.0);
    assert_eq!(merged[1].count, 5);
    // 每次调用 30 USD/1000 * group 2 * 500000 = 30000 quota
    let item = ToolSurchargeItem {
        name: "web_search".into(),
        count: 1,
        price: 30.0,
    };
    assert_eq!(
        super::text_quota::tool_surcharge_for_item(&item, 2.0),
        30.0 / 1000.0 * 2.0 * 500_000.0
    );
}

#[test]
fn empty_response_multiplier_waives_charge() {
    let mut summary = base_summary();
    summary.completion_tokens = 0;
    summary.quota = 400;
    let mut info = RelayBillingInfo::default();
    // 文本生成格式 + 客户端未断开 → 空响应，倍率 0.1
    apply_empty_response_multiplier(&mut info, &mut summary, "", "openai", false, 0.1);
    assert!(summary.empty_response_detected);
    assert!(summary.empty_response_waived);
    assert!((summary.empty_response_multiplier - 0.1).abs() < f64::EPSILON);
    assert_eq!(summary.quota, 40);
    // multiplier > 1 钳 1：按原价
    let mut summary2 = base_summary();
    summary2.completion_tokens = 0;
    summary2.quota = 400;
    apply_empty_response_multiplier(&mut info, &mut summary2, "", "openai", false, 5.0);
    assert!(summary2.empty_response_detected);
    assert!(!summary2.empty_response_waived);
    assert_eq!(summary2.quota, 400);
}

#[test]
fn empty_response_not_applied_to_non_text_formats_or_tool_calls() {
    // 图像等格式 completion=0 属正常，不豁免
    let mut summary = base_summary();
    summary.completion_tokens = 0;
    summary.quota = 400;
    let mut info = RelayBillingInfo::default();
    apply_empty_response_multiplier(&mut info, &mut summary, "", "image", false, 0.0);
    assert!(!summary.empty_response_detected);
    // 有工具附加费的请求有可消费产物，不豁免
    let mut summary2 = base_summary();
    summary2.completion_tokens = 0;
    summary2.quota = 400;
    summary2.tool_surcharge_items.push(ToolSurchargeItem {
        name: "web_search".into(),
        count: 1,
        price: 30.0,
    });
    apply_empty_response_multiplier(&mut info, &mut summary2, "", "openai", false, 0.0);
    assert!(!summary2.empty_response_detected);
    // 管理员拒绝内容不算空响应
    let mut summary3 = base_summary();
    summary3.completion_tokens = 0;
    summary3.quota = 400;
    apply_empty_response_multiplier(&mut info, &mut summary3, "policy", "openai", false, 0.0);
    assert!(!summary3.empty_response_detected);
    // 客户端断开不豁免
    let mut summary4 = base_summary();
    summary4.completion_tokens = 0;
    summary4.quota = 400;
    apply_empty_response_multiplier(&mut info, &mut summary4, "", "openai", true, 0.0);
    assert!(!summary4.empty_response_detected);
    assert!(!is_undelivered_text_response("openai", &summary4, "", true));
}

#[test]
fn audio_quota_formula_and_minimum_unit() {
    let mut settings = StaticRatioSettings::default();
    settings.completion_ratios.insert("m".into(), 2.0);
    settings.audio_ratios.insert("m".into(), 3.0);
    settings.audio_completion_ratios.insert("m".into(), 1.5);
    let info = QuotaInfo {
        input_details: TokenDetails {
            text_tokens: 100,
            audio_tokens: 10,
        },
        output_details: TokenDetails {
            text_tokens: 50,
            audio_tokens: 20,
        },
        model_name: "m".into(),
        model_ratio: 1.0,
        group_ratio: 2.0,
        ..Default::default()
    };
    // (100 + 50*2 + 10*3 + 20*3*1.5) * (1*2) = (100+100+30+90)*2 = 640
    let (quota, clamp) = calculate_audio_quota(&settings, &info);
    assert_eq!(quota, 640);
    assert!(clamp.is_none());
    // ratio 非零、结果 ≤0 → 最小计费单位 1
    let zero = QuotaInfo {
        model_name: "m".into(),
        model_ratio: 1.0,
        group_ratio: 2.0,
        ..Default::default()
    };
    let (quota, _) = calculate_audio_quota(&settings, &zero);
    assert_eq!(quota, 1);
    // UsePrice：modelPrice * QuotaPerUnit * groupRatio
    let priced = QuotaInfo {
        use_price: true,
        model_price: 0.02,
        group_ratio: 2.0,
        ..Default::default()
    };
    let (quota, _) = calculate_audio_quota(&settings, &priced);
    assert_eq!(quota, (0.02 * 500_000.0 * 2.0) as i64);
}

#[test]
fn classify_usage_path_labels() {
    use super::classify_usage_path::*;
    use super::usage::*;

    let usage = Usage {
        prompt_tokens: 10,
        completion_tokens: 5,
        billing_usage: Some(BillingUsage {
            source: SOURCE_OAI_CHAT.into(),
            semantic: SEMANTIC_OPENAI.into(),
            estimated: false,
            openai_usage: Some(Box::new(Usage {
                prompt_tokens: 10,
                completion_tokens: 5,
                ..Default::default()
            })),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert_eq!(
        usage_billing_path_for_log(false, &usage),
        USAGE_BILLING_PATH_OPENAI
    );
    let mut estimated = usage.clone();
    estimated.billing_usage.as_mut().unwrap().estimated = true;
    assert_eq!(
        usage_billing_path_for_log(false, &estimated),
        USAGE_BILLING_PATH_OPENAI_ESTIMATED
    );
    // 无 billing usage：local / upstream
    let plain = Usage::default();
    assert_eq!(
        usage_billing_path_for_log(true, &plain),
        USAGE_BILLING_PATH_LOCAL
    );
    assert_eq!(
        usage_billing_path_for_log(false, &plain),
        USAGE_BILLING_PATH_UPSTREAM
    );

    // OpenAI 语义回填：prompt/input 双向补齐 + total 求和
    let effective = effective_billing_usage(&usage);
    assert_eq!(effective.usage_semantic, SEMANTIC_OPENAI);
    assert_eq!(effective.total_tokens, 15);
    assert_eq!(effective.usage_source, SOURCE_OAI_CHAT);

    // Claude 语义转换
    let claude = Usage {
        billing_usage: Some(BillingUsage {
            source: SOURCE_CLAUDE_MESSAGES.into(),
            claude_usage: Some(super::usage::ClaudeBillingUsage {
                input_tokens: 100,
                output_tokens: 40,
                cache_read_input_tokens: 30,
                cache_creation_input_tokens: 20,
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    let effective = effective_billing_usage(&claude);
    assert_eq!(effective.usage_semantic, SEMANTIC_ANTHROPIC);
    assert_eq!(effective.prompt_tokens, 100);
    assert_eq!(effective.completion_tokens, 40);
    assert_eq!(effective.total_tokens, 140);
    assert_eq!(effective.input_tokens, 150);
    assert_eq!(effective.prompt_tokens_details.cached_tokens, 30);
    assert_eq!(effective.prompt_tokens_details.cached_creation_tokens, 20);

    // Gemini 语义转换 + total 回退求和
    let gemini = Usage {
        billing_usage: Some(BillingUsage {
            source: SOURCE_GEMINI_CHAT.into(),
            gemini_usage_metadata: Some(super::usage::GeminiUsageMetadata {
                prompt_token_count: 10,
                candidates_token_count: 5,
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    let effective = effective_billing_usage(&gemini);
    assert_eq!(effective.usage_semantic, SEMANTIC_GEMINI);
    assert_eq!(effective.prompt_tokens, 10);
    assert_eq!(effective.completion_tokens, 5);
    assert_eq!(effective.total_tokens, 15);
}

#[test]
fn violation_fee_calc() {
    assert_eq!(super::violation_fee::calc_violation_fee_quota(0.0, 1.0), 0);
    assert_eq!(super::violation_fee::calc_violation_fee_quota(0.02, 0.0), 0);
    // 0.02 * 500000 * 1 = 10000
    assert_eq!(
        super::violation_fee::calc_violation_fee_quota(0.02, 1.0),
        10_000
    );
    // groupRatio 折半
    assert_eq!(
        super::violation_fee::calc_violation_fee_quota(0.02, 0.5),
        5_000
    );
    assert!(super::violation_fee::is_violation_fee_code(
        "violation_fee.grok_csam"
    ));
    assert!(!super::violation_fee::is_violation_fee_code("other_error"));
    assert!(super::violation_fee::should_charge_violation_fee(
        "",
        "some prefix Failed check: SAFETY_CHECK_TYPE suffix",
        ""
    ));
    assert!(super::violation_fee::should_charge_violation_fee(
        super::violation_fee::ERROR_CODE_VIOLATION_FEE_GROK_CSAM,
        "",
        ""
    ));
    assert!(!super::violation_fee::should_charge_violation_fee(
        "", "clean", ""
    ));
}

#[test]
fn normalize_billing_preference_matches_go() {
    use super::session::normalize_billing_preference;
    assert_eq!(normalize_billing_preference("wallet_first"), "wallet_first");
    assert_eq!(
        normalize_billing_preference(" subscription_only "),
        "subscription_only"
    );
    assert_eq!(normalize_billing_preference("bogus"), "");
    assert_eq!(normalize_billing_preference(""), "");
}

#[test]
fn cache_creation_tokens_total_prefers_larger_source() {
    let d = super::usage::InputTokenDetails {
        cached_creation_tokens: 100,
        cache_write_tokens: 150,
        ..Default::default()
    };
    assert_eq!(d.cache_creation_tokens_total(), 150);
    let negative = super::usage::InputTokenDetails {
        cached_creation_tokens: -5,
        cache_write_tokens: 0,
        ..Default::default()
    };
    assert_eq!(negative.cache_creation_tokens_total(), 0);
}

#[test]
fn gizmo_model_names_normalized() {
    let mut extra = Vec::new();
    let model = super::text_quota::normalize_gizmo_model("gpt-4-gizmo-abc", &mut extra);
    assert_eq!(model, "gpt-4-gizmo-*");
    assert_eq!(extra, vec!["模型 gpt-4-gizmo-abc".to_string()]);
    let model = super::text_quota::normalize_gizmo_model("gpt-4o-gizmo-xyz", &mut extra);
    assert_eq!(model, "gpt-4o-gizmo-*");
    let model = super::text_quota::normalize_gizmo_model("gpt-4o", &mut extra);
    assert_eq!(model, "gpt-4o");
}

#[test]
fn funding_subscription_preconsume_matches_amount_not_parameter() {
    // Go 约定：SubscriptionFunding.PreConsume 忽略参数固定用内部 amount。
    // 枚举形态下该约定由 new_billing_session 构造时保证（amount=subConsume），
    // 此处锁定 Funding::pre_consume 的钱包分支余额语义。
    let funding = Funding::Subscription(SubscriptionFunding {
        request_id: "r".into(),
        user_id: 1,
        amount: 99,
        ..Default::default()
    });
    assert_eq!(
        funding.source(),
        super::funding::BILLING_SOURCE_SUBSCRIPTION
    );
    assert_eq!(funding.subscription_pre_consumed(), 0);
}
