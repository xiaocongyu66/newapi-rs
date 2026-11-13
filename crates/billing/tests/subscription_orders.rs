//! 订阅订单状态机的双后端契约（SQLite 内存 + 独立 PostgreSQL schema）。
//!
//! 断言对齐 Go `store_subscription.go` 的可观察契约：
//! - `ExpireSubscriptionOrder`：pending → expired（complete_time 落值）；
//!   非 pending 幂等 Ok；网关归属不符 → mismatch；订单不存在 → NotFound。
//! - `CompleteSubscriptionOrder`：pending → success + 建订阅（周期、分组
//!   升级快照）+ upsert 充值流水；重复回调幂等 `AlreadyDone`；状态非法 →
//!   StatusInvalid；购买上限 → 业务文案；provider 不符 → mismatch。
//! - `upsertSubscriptionTopUpTx`：缺行建行（status=success）、金额回写、
//!   payment_method 冲突 → mismatch。

use newapi_billing::subscription::{
    SubscriptionCompleteOutcome, SubscriptionOrderError, complete_subscription_order,
    count_user_subscriptions_by_plan, expire_subscription_order,
    get_subscription_order_by_trade_no, insert_subscription_order,
};
use newapi_storage::Database;
use sqlx::{
    ConnectOptions, Row,
    postgres::PgPoolOptions,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::str::FromStr;

// subscription_orders 列序对齐 Go AutoMigrate（setup.rs 的登记清单）。
const ORDERS_SQLITE: &str = r#"CREATE TABLE subscription_orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL DEFAULT 0,
    plan_id INTEGER NOT NULL DEFAULT 0,
    money REAL NOT NULL DEFAULT 0,
    trade_no VARCHAR(255) NOT NULL UNIQUE,
    payment_method VARCHAR(50) NOT NULL DEFAULT '',
    payment_provider VARCHAR(50) NOT NULL DEFAULT '',
    status VARCHAR(64) NOT NULL DEFAULT 'pending',
    create_time BIGINT NOT NULL DEFAULT 0,
    complete_time BIGINT NOT NULL DEFAULT 0,
    provider_payload TEXT
)"#;

const ORDERS_POSTGRES: &str = r#"CREATE TABLE subscription_orders (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL DEFAULT 0,
    plan_id BIGINT NOT NULL DEFAULT 0,
    money DOUBLE PRECISION NOT NULL DEFAULT 0,
    trade_no VARCHAR(255) NOT NULL UNIQUE,
    payment_method VARCHAR(50) NOT NULL DEFAULT '',
    payment_provider VARCHAR(50) NOT NULL DEFAULT '',
    status VARCHAR(64) NOT NULL DEFAULT 'pending',
    create_time BIGINT NOT NULL DEFAULT 0,
    complete_time BIGINT NOT NULL DEFAULT 0,
    provider_payload TEXT
)"#;

const PLANS_SQLITE: &str = r#"CREATE TABLE subscription_plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title VARCHAR(255) NOT NULL DEFAULT '',
    subtitle VARCHAR(255) NOT NULL DEFAULT '',
    price_amount DOUBLE PRECISION NOT NULL DEFAULT 0,
    currency VARCHAR(16) NOT NULL DEFAULT 'USD',
    duration_unit VARCHAR(32) NOT NULL DEFAULT 'month',
    duration_value INTEGER NOT NULL DEFAULT 1,
    custom_seconds BIGINT NOT NULL DEFAULT 0,
    enabled BOOLEAN NOT NULL DEFAULT 1,
    sort_order INTEGER NOT NULL DEFAULT 0,
    allow_balance_pay BOOLEAN,
    allow_wallet_overflow BOOLEAN,
    stripe_price_id VARCHAR(255) NOT NULL DEFAULT '',
    creem_product_id VARCHAR(255) NOT NULL DEFAULT '',
    waffo_pancake_product_id VARCHAR(255) NOT NULL DEFAULT '',
    max_purchase_per_user INTEGER NOT NULL DEFAULT 0,
    upgrade_group VARCHAR(64) NOT NULL DEFAULT '',
    downgrade_group VARCHAR(64) NOT NULL DEFAULT '',
    total_amount BIGINT NOT NULL DEFAULT 0,
    quota_reset_period VARCHAR(32) NOT NULL DEFAULT 'never',
    quota_reset_custom_seconds BIGINT NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL DEFAULT 0,
    updated_at BIGINT NOT NULL DEFAULT 0
)"#;

const PLANS_POSTGRES: &str = r#"CREATE TABLE subscription_plans (
    id BIGSERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL DEFAULT '',
    subtitle VARCHAR(255) NOT NULL DEFAULT '',
    price_amount DOUBLE PRECISION NOT NULL DEFAULT 0,
    currency VARCHAR(16) NOT NULL DEFAULT 'USD',
    duration_unit VARCHAR(32) NOT NULL DEFAULT 'month',
    duration_value BIGINT NOT NULL DEFAULT 1,
    custom_seconds BIGINT NOT NULL DEFAULT 0,
    enabled BIGINT NOT NULL DEFAULT 1,
    sort_order BIGINT NOT NULL DEFAULT 0,
    allow_balance_pay BIGINT,
    allow_wallet_overflow BIGINT,
    stripe_price_id VARCHAR(255) NOT NULL DEFAULT '',
    creem_product_id VARCHAR(255) NOT NULL DEFAULT '',
    waffo_pancake_product_id VARCHAR(255) NOT NULL DEFAULT '',
    max_purchase_per_user BIGINT NOT NULL DEFAULT 0,
    upgrade_group VARCHAR(64) NOT NULL DEFAULT '',
    downgrade_group VARCHAR(64) NOT NULL DEFAULT '',
    total_amount BIGINT NOT NULL DEFAULT 0,
    quota_reset_period VARCHAR(32) NOT NULL DEFAULT 'never',
    quota_reset_custom_seconds BIGINT NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL DEFAULT 0,
    updated_at BIGINT NOT NULL DEFAULT 0
)"#;

const USER_SUBS_SQLITE: &str = r#"CREATE TABLE user_subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL DEFAULT 0,
    plan_id INTEGER NOT NULL DEFAULT 0,
    amount_total BIGINT NOT NULL DEFAULT 0,
    amount_used BIGINT NOT NULL DEFAULT 0,
    start_time BIGINT NOT NULL DEFAULT 0,
    end_time BIGINT NOT NULL DEFAULT 0,
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    source VARCHAR(32) NOT NULL DEFAULT 'order',
    last_reset_time BIGINT NOT NULL DEFAULT 0,
    next_reset_time BIGINT NOT NULL DEFAULT 0,
    upgrade_group VARCHAR(64) NOT NULL DEFAULT '',
    prev_user_group VARCHAR(64) NOT NULL DEFAULT '',
    downgrade_group VARCHAR(64) NOT NULL DEFAULT '',
    allow_wallet_overflow BOOLEAN NOT NULL DEFAULT 1,
    created_at BIGINT NOT NULL DEFAULT 0,
    updated_at BIGINT NOT NULL DEFAULT 0
)"#;

const USER_SUBS_POSTGRES: &str = r#"CREATE TABLE user_subscriptions (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL DEFAULT 0,
    plan_id BIGINT NOT NULL DEFAULT 0,
    amount_total BIGINT NOT NULL DEFAULT 0,
    amount_used BIGINT NOT NULL DEFAULT 0,
    start_time BIGINT NOT NULL DEFAULT 0,
    end_time BIGINT NOT NULL DEFAULT 0,
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    source VARCHAR(32) NOT NULL DEFAULT 'order',
    last_reset_time BIGINT NOT NULL DEFAULT 0,
    next_reset_time BIGINT NOT NULL DEFAULT 0,
    upgrade_group VARCHAR(64) NOT NULL DEFAULT '',
    prev_user_group VARCHAR(64) NOT NULL DEFAULT '',
    downgrade_group VARCHAR(64) NOT NULL DEFAULT '',
    allow_wallet_overflow BIGINT NOT NULL DEFAULT 1,
    created_at BIGINT NOT NULL DEFAULT 0,
    updated_at BIGINT NOT NULL DEFAULT 0
)"#;

const TOPUPS_SQLITE: &str = r#"CREATE TABLE top_ups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL DEFAULT 0,
    amount BIGINT NOT NULL DEFAULT 0,
    money REAL NOT NULL DEFAULT 0,
    trade_no VARCHAR(255) NOT NULL UNIQUE,
    payment_method VARCHAR(50) NOT NULL DEFAULT '',
    payment_provider VARCHAR(50) NOT NULL DEFAULT '',
    create_time BIGINT NOT NULL DEFAULT 0,
    complete_time BIGINT NOT NULL DEFAULT 0,
    status VARCHAR(64) NOT NULL DEFAULT 'pending'
)"#;

const TOPUPS_POSTGRES: &str = r#"CREATE TABLE top_ups (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL DEFAULT 0,
    amount BIGINT NOT NULL DEFAULT 0,
    money DOUBLE PRECISION NOT NULL DEFAULT 0,
    trade_no VARCHAR(255) NOT NULL UNIQUE,
    payment_method VARCHAR(50) NOT NULL DEFAULT '',
    payment_provider VARCHAR(50) NOT NULL DEFAULT '',
    create_time BIGINT NOT NULL DEFAULT 0,
    complete_time BIGINT NOT NULL DEFAULT 0,
    status VARCHAR(64) NOT NULL DEFAULT 'pending'
)"#;

// users：契约测试的完整 fixture 列（password/remark/created_at/last_login_at
// 为 P0 既有约定）。
const USERS_SQLITE: &str = r#"CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(255) NOT NULL DEFAULT '',
    email VARCHAR(255) NOT NULL DEFAULT '',
    password VARCHAR(255) NOT NULL DEFAULT '',
    remark VARCHAR(255),
    "group" VARCHAR(64) NOT NULL DEFAULT 'default',
    quota BIGINT NOT NULL DEFAULT 0,
    deleted_at TIMESTAMP,
    created_at BIGINT NOT NULL DEFAULT 0,
    last_login_at BIGINT NOT NULL DEFAULT 0
)"#;

const USERS_POSTGRES: &str = r#"CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL DEFAULT '',
    email VARCHAR(255) NOT NULL DEFAULT '',
    password VARCHAR(255) NOT NULL DEFAULT '',
    remark VARCHAR(255),
    "group" VARCHAR(64) NOT NULL DEFAULT 'default',
    quota BIGINT NOT NULL DEFAULT 0,
    deleted_at TIMESTAMPTZ,
    created_at BIGINT NOT NULL DEFAULT 0,
    last_login_at BIGINT NOT NULL DEFAULT 0
)"#;

const NOW: i64 = 1_764_000_000; // 固定 unix 秒，规避时钟依赖

async fn execute(db: &Database, statement: &'static str) {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query(statement).execute(pool).await.unwrap();
        }
        Database::Postgres(pool) => {
            sqlx::query(statement).execute(pool).await.unwrap();
        }
    }
}

async fn create_schema(db: &Database) {
    match db {
        Database::Sqlite(_) => {
            for statement in [
                ORDERS_SQLITE,
                PLANS_SQLITE,
                USER_SUBS_SQLITE,
                TOPUPS_SQLITE,
                USERS_SQLITE,
            ] {
                execute(db, statement).await;
            }
        }
        Database::Postgres(_) => {
            for statement in [
                ORDERS_POSTGRES,
                PLANS_POSTGRES,
                USER_SUBS_POSTGRES,
                TOPUPS_POSTGRES,
                USERS_POSTGRES,
            ] {
                execute(db, statement).await;
            }
        }
    }
}

async fn seed_user(db: &Database, id: i64, group: &str) {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query("INSERT INTO users (id, username, \"group\") VALUES (?, ?, ?)")
                .bind(id)
                .bind(format!("user{id}"))
                .bind(group)
                .execute(pool)
                .await
                .unwrap();
        }
        Database::Postgres(pool) => {
            sqlx::query("INSERT INTO users (id, username, \"group\") VALUES ($1, $2, $3)")
                .bind(id)
                .bind(format!("user{id}"))
                .bind(group)
                .execute(pool)
                .await
                .unwrap();
        }
    }
}

/// 种套餐：`(id, price, upgrade_group, max_purchase, quota_reset_period,
/// duration_unit, duration_value)`。
async fn seed_plan(db: &Database, id: i64, upgrade_group: &str, max_purchase: i64) {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query(
                r#"INSERT INTO subscription_plans
                   (id, title, price_amount, duration_unit, duration_value,
                    enabled, max_purchase_per_user, upgrade_group, total_amount,
                    quota_reset_period)
                   VALUES (?, ?, 10.0, 'day', 30, 1, ?, ?, 500000, 'never')"#,
            )
            .bind(id)
            .bind(format!("plan{id}"))
            .bind(max_purchase)
            .bind(upgrade_group)
            .execute(pool)
            .await
            .unwrap();
        }
        Database::Postgres(pool) => {
            sqlx::query(
                r#"INSERT INTO subscription_plans
                   (id, title, price_amount, duration_unit, duration_value,
                    enabled, max_purchase_per_user, upgrade_group, total_amount,
                    quota_reset_period)
                   VALUES ($1, $2, 10.0, 'day', 30, 1, $3, $4, 500000, 'never')"#,
            )
            .bind(id)
            .bind(format!("plan{id}"))
            .bind(max_purchase)
            .bind(upgrade_group)
            .execute(pool)
            .await
            .unwrap();
        }
    }
}

async fn seed_order(db: &Database, trade_no: &str, provider: &str, status: &str) {
    insert_subscription_order(db, 42, 1, 10.0, trade_no, "alipay", provider, NOW)
        .await
        .unwrap();
    if status != "pending" {
        match db {
            Database::Sqlite(pool) => {
                sqlx::query("UPDATE subscription_orders SET status = $2 WHERE trade_no = $1")
                    .bind(trade_no)
                    .bind(status)
                    .execute(pool)
                    .await
                    .unwrap();
            }
            Database::Postgres(pool) => {
                sqlx::query("UPDATE subscription_orders SET status = $2 WHERE trade_no = $1")
                    .bind(trade_no)
                    .bind(status)
                    .execute(pool)
                    .await
                    .unwrap();
            }
        }
    }
}

async fn order_status(db: &Database, trade_no: &str) -> (String, i64, String) {
    match db {
        Database::Sqlite(pool) => {
            let row = sqlx::query(
                "SELECT status, complete_time, provider_payload FROM subscription_orders \
                 WHERE trade_no = $1",
            )
            .bind(trade_no)
            .fetch_one(pool)
            .await
            .unwrap();
            (
                row.get(0),
                row.get::<i64, _>(1),
                row.get::<Option<String>, _>(2).unwrap_or_default(),
            )
        }
        Database::Postgres(pool) => {
            let row = sqlx::query(
                "SELECT status, complete_time, provider_payload FROM subscription_orders \
                 WHERE trade_no = $1",
            )
            .bind(trade_no)
            .fetch_one(pool)
            .await
            .unwrap();
            (
                row.get(0),
                row.get::<i64, _>(1),
                row.get::<Option<String>, _>(2).unwrap_or_default(),
            )
        }
    }
}

async fn user_group(db: &Database, user_id: i64) -> String {
    match db {
        Database::Sqlite(pool) => sqlx::query_scalar(r#"SELECT "group" FROM users WHERE id = $1"#)
            .bind(user_id)
            .fetch_one(pool)
            .await
            .unwrap(),
        Database::Postgres(pool) => {
            sqlx::query_scalar(r#"SELECT "group" FROM users WHERE id = $1"#)
                .bind(user_id)
                .fetch_one(pool)
                .await
                .unwrap()
        }
    }
}

async fn subscription_count(db: &Database) -> i64 {
    match db {
        Database::Sqlite(pool) => sqlx::query_scalar("SELECT COUNT(*) FROM user_subscriptions")
            .fetch_one(pool)
            .await
            .unwrap(),
        Database::Postgres(pool) => sqlx::query_scalar("SELECT COUNT(*) FROM user_subscriptions")
            .fetch_one(pool)
            .await
            .unwrap(),
    }
}

async fn topup_status(db: &Database, trade_no: &str) -> Option<(String, f64, i64)> {
    match db {
        Database::Sqlite(pool) => {
            let row: Option<(String, f64, i64)> = sqlx::query_as(
                "SELECT status, money, create_time FROM top_ups WHERE trade_no = $1",
            )
            .bind(trade_no)
            .fetch_optional(pool)
            .await
            .unwrap();
            row
        }
        Database::Postgres(pool) => {
            let row: Option<(String, f64, i64)> = sqlx::query_as(
                "SELECT status, money, create_time FROM top_ups WHERE trade_no = $1",
            )
            .bind(trade_no)
            .fetch_optional(pool)
            .await
            .unwrap();
            row
        }
    }
}

// 双后端驱动：SQLite 内存库 + 独立 PG schema（TEST_POSTGRES_DSN 缺失时跳过）。
async fn postgres_db() -> Option<Database> {
    let dsn = std::env::var("TEST_POSTGRES_DSN").ok()?;
    let options: sqlx::postgres::PgConnectOptions = dsn.parse().unwrap();
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone().disable_statement_logging())
        .await
        .unwrap();
    static PG_SCHEMA_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = PG_SCHEMA_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let schema = format!(
        "sub_orders_{}_{seq}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
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
    let pool = PgPoolOptions::new()
        .max_connections(4)
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
    Some(Database::Postgres(pool))
}

async fn both_backends() -> Vec<Database> {
    let mut backends = Vec::new();
    let options = SqliteConnectOptions::from_str("sqlite::memory:")
        .unwrap()
        .disable_statement_logging();
    let pool = SqlitePoolOptions::new()
        .max_connections(4)
        .connect_with(options)
        .await
        .unwrap();
    backends.push(Database::Sqlite(pool));
    if let Some(pg) = postgres_db().await {
        backends.push(pg);
    }
    backends
}

#[tokio::test]
async fn expire_flips_pending_to_expired_and_is_idempotent() {
    for db in both_backends().await {
        create_schema(&db).await;
        seed_order(&db, "SUB1", "epay", "pending").await;

        expire_subscription_order(&db, "SUB1", "epay", NOW)
            .await
            .unwrap();
        let (status, complete_time, _) = order_status(&db, "SUB1").await;
        assert_eq!(status, "expired");
        assert_eq!(complete_time, NOW);

        // 非 pending：幂等 Ok，complete_time 不再变化。
        expire_subscription_order(&db, "SUB1", "epay", NOW + 5)
            .await
            .unwrap();
        let (_, complete_time, _) = order_status(&db, "SUB1").await;
        assert_eq!(complete_time, NOW);

        // 网关归属不符。
        seed_order(&db, "SUB2", "vmq", "pending").await;
        assert!(matches!(
            expire_subscription_order(&db, "SUB2", "epay", NOW).await,
            Err(SubscriptionOrderError::ProviderMismatch)
        ));

        // 订单不存在。
        assert!(matches!(
            expire_subscription_order(&db, "SUB-MISSING", "epay", NOW).await,
            Err(SubscriptionOrderError::NotFound)
        ));
    }
}

#[tokio::test]
async fn complete_creates_subscription_topup_and_is_idempotent() {
    for db in both_backends().await {
        create_schema(&db).await;
        seed_user(&db, 42, "default").await;
        seed_plan(&db, 1, "", 0).await;
        seed_order(&db, "SUBC1", "epay", "pending").await;

        let outcome = complete_subscription_order(&db, "SUBC1", "{\"ok\":1}", "epay", "", NOW)
            .await
            .unwrap();
        let SubscriptionCompleteOutcome::Completed(record) = outcome else {
            panic!("expected completed");
        };
        assert_eq!(record.user_id, 42);
        assert!(record.upgraded_group.is_none());
        assert_eq!(record.money, 10.0);

        let (status, complete_time, payload) = order_status(&db, "SUBC1").await;
        assert_eq!(status, "success");
        assert_eq!(complete_time, NOW);
        assert_eq!(payload, "{\"ok\":1}");

        // 订阅行：30 天后到期，source=order，amount_total 来自套餐。
        assert_eq!(subscription_count(&db).await, 1);
        match &db {
            Database::Sqlite(pool) => {
                let (end, source, total): (i64, String, i64) =
                    sqlx::query_as("SELECT end_time, source, amount_total FROM user_subscriptions")
                        .fetch_one(pool)
                        .await
                        .unwrap();
                assert_eq!(end, NOW + 30 * 86_400);
                assert_eq!(source, "order");
                assert_eq!(total, 500000);
            }
            Database::Postgres(pool) => {
                let (end, source, total): (i64, String, i64) =
                    sqlx::query_as("SELECT end_time, source, amount_total FROM user_subscriptions")
                        .fetch_one(pool)
                        .await
                        .unwrap();
                assert_eq!(end, NOW + 30 * 86_400);
                assert_eq!(source, "order");
                assert_eq!(total, 500000);
            }
        }

        // 充值流水：新建行 status=success、继承订单 create_time。
        let (status, money, create_time) = topup_status(&db, "SUBC1").await.unwrap();
        assert_eq!(status, "success");
        assert_eq!(money, 10.0);
        assert_eq!(create_time, NOW);

        // 幂等重复回调。
        let outcome = complete_subscription_order(&db, "SUBC1", "", "epay", "", NOW + 1)
            .await
            .unwrap();
        assert!(matches!(outcome, SubscriptionCompleteOutcome::AlreadyDone));
        assert_eq!(subscription_count(&db).await, 1);

        // 状态非法：expired 订单不能核销。
        seed_order(&db, "SUBC2", "epay", "expired").await;
        assert!(matches!(
            complete_subscription_order(&db, "SUBC2", "", "epay", "", NOW).await,
            Err(SubscriptionOrderError::StatusInvalid)
        ));

        // provider 不符。
        seed_order(&db, "SUBC3", "vmq", "pending").await;
        assert!(matches!(
            complete_subscription_order(&db, "SUBC3", "", "epay", "", NOW).await,
            Err(SubscriptionOrderError::ProviderMismatch)
        ));

        // 订单不存在。
        assert!(matches!(
            complete_subscription_order(&db, "SUB-MISSING", "", "epay", "", NOW).await,
            Err(SubscriptionOrderError::NotFound)
        ));
    }
}

#[tokio::test]
async fn complete_upgrades_user_group_and_snapshots_prev() {
    for db in both_backends().await {
        create_schema(&db).await;
        seed_user(&db, 42, "default").await;
        seed_plan(&db, 1, "vip", 0).await;
        seed_order(&db, "SUBG1", "epay", "pending").await;

        let outcome = complete_subscription_order(&db, "SUBG1", "", "epay", "", NOW)
            .await
            .unwrap();
        let SubscriptionCompleteOutcome::Completed(record) = outcome else {
            panic!("expected completed");
        };
        assert_eq!(record.upgraded_group.as_deref(), Some("vip"));
        assert_eq!(user_group(&db, 42).await, "vip");

        match &db {
            Database::Sqlite(pool) => {
                let (upgrade, prev): (String, String) =
                    sqlx::query_as("SELECT upgrade_group, prev_user_group FROM user_subscriptions")
                        .fetch_one(pool)
                        .await
                        .unwrap();
                assert_eq!(upgrade, "vip");
                assert_eq!(prev, "default");
            }
            Database::Postgres(pool) => {
                let (upgrade, prev): (String, String) =
                    sqlx::query_as("SELECT upgrade_group, prev_user_group FROM user_subscriptions")
                        .fetch_one(pool)
                        .await
                        .unwrap();
                assert_eq!(upgrade, "vip");
                assert_eq!(prev, "default");
            }
        }

        // 用户已在目标分组：不写 prev_user_group（Go `currentGroup != upgradeGroup`）。
        seed_user(&db, 43, "vip").await;
        insert_subscription_order(&db, 43, 1, 10.0, "SUBG2", "epay", "epay", NOW)
            .await
            .unwrap();
        let outcome = complete_subscription_order(&db, "SUBG2", "", "epay", "", NOW)
            .await
            .unwrap();
        let SubscriptionCompleteOutcome::Completed(record) = outcome else {
            panic!("expected completed");
        };
        assert!(record.upgraded_group.is_none());
    }
}

#[tokio::test]
async fn complete_enforces_purchase_limit_and_missing_plan() {
    for db in both_backends().await {
        create_schema(&db).await;
        seed_user(&db, 42, "default").await;
        seed_plan(&db, 1, "", 1).await;
        seed_order(&db, "SUBL1", "epay", "pending").await;

        complete_subscription_order(&db, "SUBL1", "", "epay", "", NOW)
            .await
            .unwrap();
        assert_eq!(
            count_user_subscriptions_by_plan(&db, 42, 1).await.unwrap(),
            1
        );

        seed_order(&db, "SUBL2", "epay", "pending").await;
        match complete_subscription_order(&db, "SUBL2", "", "epay", "", NOW).await {
            Err(SubscriptionOrderError::Business(message)) => {
                assert_eq!(message, "已达到该套餐购买上限");
            }
            other => panic!("expected purchase limit business error, got {other:?}"),
        }

        // 套餐缺失 → record not found。
        insert_subscription_order(&db, 42, 999, 10.0, "SUBL3", "epay", "epay", NOW)
            .await
            .unwrap();
        match complete_subscription_order(&db, "SUBL3", "", "epay", "", NOW).await {
            Err(SubscriptionOrderError::Business(message)) => {
                assert_eq!(message, "record not found");
            }
            other => panic!("expected plan-not-found business error, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn upsert_topup_overwrites_money_and_rejects_method_conflict() {
    for db in both_backends().await {
        create_schema(&db).await;
        seed_user(&db, 42, "default").await;
        seed_plan(&db, 1, "", 0).await;
        seed_order(&db, "SUBT1", "epay", "pending").await;
        // 预置已有充值流水（同 trade_no，金额/方式不同）。
        match &db {
            Database::Sqlite(pool) => {
                sqlx::query(
                    "INSERT INTO top_ups (user_id, amount, money, trade_no, \
                     payment_method, create_time, status) VALUES (42, 0, 5.0, $1, 'wxpay', 1, 'pending')",
                )
                .bind("SUBT1")
                .execute(pool)
                .await
                .unwrap();
            }
            Database::Postgres(pool) => {
                sqlx::query(
                    "INSERT INTO top_ups (user_id, amount, money, trade_no, \
                     payment_method, create_time, status) VALUES (42, 0, 5.0, $1, 'wxpay', 1, 'pending')",
                )
                .bind("SUBT1")
                .execute(pool)
                .await
                .unwrap();
            }
        }
        // Go：已有流水的 payment_method 非空且与订单不符 → ErrPaymentMethodMismatch。
        match complete_subscription_order(&db, "SUBT1", "", "epay", "", NOW).await {
            Err(SubscriptionOrderError::ProviderMismatch) => {}
            other => panic!("expected method mismatch, got {other:?}"),
        }
        // 方法一致 → 覆盖金额与完成时间，status=success。
        match &db {
            Database::Sqlite(pool) => {
                sqlx::query("UPDATE top_ups SET payment_method = 'alipay' WHERE trade_no = $1")
                    .bind("SUBT1")
                    .execute(pool)
                    .await
                    .unwrap();
            }
            Database::Postgres(pool) => {
                sqlx::query("UPDATE top_ups SET payment_method = 'alipay' WHERE trade_no = $1")
                    .bind("SUBT1")
                    .execute(pool)
                    .await
                    .unwrap();
            }
        }
        complete_subscription_order(&db, "SUBT1", "", "epay", "", NOW)
            .await
            .unwrap();
        let (status, money, create_time) = topup_status(&db, "SUBT1").await.unwrap();
        assert_eq!(status, "success");
        assert_eq!(money, 10.0);
        assert_eq!(create_time, 1); // 非零 create_time 保留
    }
}

#[tokio::test]
async fn order_lookup_and_empty_trade_no_follow_go() {
    for db in both_backends().await {
        create_schema(&db).await;
        seed_order(&db, "SUBQ1", "epay", "pending").await;
        let order = get_subscription_order_by_trade_no(&db, "SUBQ1")
            .await
            .unwrap();
        assert_eq!(order.user_id, 42);
        assert_eq!(order.plan_id, 1);
        assert_eq!(order.status, "pending");
        assert!(
            get_subscription_order_by_trade_no(&db, "nope")
                .await
                .is_none()
        );
        assert!(get_subscription_order_by_trade_no(&db, "").await.is_none());
        // 空 trade_no 的核销 / 过期都是 NotFound（Go `tradeNo is empty`）。
        assert!(matches!(
            complete_subscription_order(&db, "", "", "epay", "", NOW).await,
            Err(SubscriptionOrderError::NotFound)
        ));
        assert!(matches!(
            expire_subscription_order(&db, "", "epay", NOW).await,
            Err(SubscriptionOrderError::NotFound)
        ));
    }
}
