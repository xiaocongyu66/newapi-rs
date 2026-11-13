//! 订阅订单状态机：`subscription_orders` 行、Epip/VMQ/CodePay 回调核销
//! （CAS 翻转 + 建订阅 + 充值流水同步），对齐 Go `store_subscription.go`。
//!
//! Go 参考：
//! - `SubscriptionOrder`（`store_subscription.go:221-242`）：列与唯一约束
//! - `ExpireSubscriptionOrder`（`:1443-1466`）：行锁 + 网关归属 + pending→
//!   expired（非 pending 幂等返回 nil）
//! - `CompleteSubscriptionOrder`（`:1502-1579`）：事务内「锁单 → 网关归属 →
//!   幂等成功 → pending 校验 → 查套餐 → 锁用户行 → 建订阅（含分组升级）→
//!   upsert 充值流水 → CAS 翻转成功」
//! - `CreateUserSubscriptionFromPlanTx`（`:506-581`）：MaxPurchasePerUser、
//!   `calcPlanEndTime` / `calcNextResetTime`、upgrade_group 快照
//! - `upsertSubscriptionTopUpTx`（`:1467-1501`）
//! - `CountUserSubscriptionsByPlan`（`:1580-1591`）、
//!   `GetSubscriptionOrderByTradeNo`（`:1595-1604`）
//!
//! 并发语义与 `topup/gateway.rs` 同构：SQLite 单写者免行锁，PostgreSQL 发
//! `FOR UPDATE`（`dbx.LockForUpdate` 驱动分支）；最终翻转走条件 UPDATE，
//! 影响行数为 0 时重读状态区分「幂等已完成」与「状态非法」。

use newapi_storage::Database;
use sqlx::Row;

use super::period::{calc_next_reset_time, calc_plan_end_time};
use super::store::SubscriptionPlanRow;

/// Go `common.TopUpStatus*`（订阅订单复用同一组状态字面量）。
pub const STATUS_PENDING: &str = "pending";
pub const STATUS_SUCCESS: &str = "success";
pub const STATUS_EXPIRED: &str = "expired";

/// Go `SubscriptionOrder`（`store_subscription.go:221-235`）的行投影。
#[derive(Debug, Clone)]
pub struct SubscriptionOrderRow {
    pub id: i64,
    pub user_id: i64,
    pub plan_id: i64,
    pub money: f64,
    pub trade_no: String,
    pub payment_method: String,
    pub payment_provider: String,
    pub status: String,
    pub create_time: i64,
    pub complete_time: i64,
    pub provider_payload: String,
}

/// 状态机错误（对齐 Go 哨兵）。
#[derive(Debug)]
pub enum SubscriptionOrderError {
    /// Go `ErrSubscriptionOrderNotFound`（含空订单号 / 用户行不存在时折叠）。
    NotFound,
    /// Go `ErrPaymentMethodMismatch`。
    ProviderMismatch,
    /// Go `ErrSubscriptionOrderStatusInvalid`。
    StatusInvalid,
    /// Go 硬编码业务文案（套餐缺失 / 购买上限 / 周期计算失败）。
    Business(String),
    Db(sqlx::Error),
}

impl From<sqlx::Error> for SubscriptionOrderError {
    fn from(error: sqlx::Error) -> Self {
        Self::Db(error)
    }
}

/// 核销成功时带回的事务外字段（Go 的日志半边，`:1571-1577`）。
#[derive(Debug)]
pub struct SubscriptionCompleteRecord {
    pub user_id: i64,
    /// 命中分组升级（Go `upgradeGroup != ""`，触发缓存刷新的那次核销）。
    pub upgraded_group: Option<String>,
    pub plan_title: String,
    pub money: f64,
    pub payment_method: String,
}

/// Go `CompleteSubscriptionOrder` 的结果；`AlreadyDone` = 此前已完成。
#[derive(Debug)]
pub enum SubscriptionCompleteOutcome {
    AlreadyDone,
    Completed(SubscriptionCompleteRecord),
}

const ORDER_BY_TRADE_NO: &str = concat!(
    "SELECT id, user_id, plan_id, money, trade_no, payment_method, ",
    "payment_provider, status, create_time, complete_time, provider_payload ",
    "FROM subscription_orders WHERE trade_no = $1"
);

const ORDER_BY_TRADE_NO_LOCKED: &str = concat!(
    "SELECT id, user_id, plan_id, money, trade_no, payment_method, ",
    "payment_provider, status, create_time, complete_time, provider_payload ",
    "FROM subscription_orders WHERE trade_no = $1"
);

const ORDER_BY_TRADE_NO_FOR_UPDATE: &str = concat!(
    "SELECT id, user_id, plan_id, money, trade_no, payment_method, ",
    "payment_provider, status, create_time, complete_time, provider_payload ",
    "FROM subscription_orders WHERE trade_no = $1 FOR UPDATE"
);

const PLAN_BY_ID: &str = r#"
SELECT
    COALESCE(CAST(id AS BIGINT), 0),
    COALESCE(title, ''),
    COALESCE(subtitle, ''),
    COALESCE(CAST(price_amount AS DOUBLE PRECISION), 0),
    COALESCE(currency, ''),
    COALESCE(duration_unit, ''),
    COALESCE(CAST(duration_value AS BIGINT), 0),
    COALESCE(CAST(custom_seconds AS BIGINT), 0),
    COALESCE(CAST(enabled AS BIGINT), 0),
    COALESCE(CAST(sort_order AS BIGINT), 0),
    CAST(allow_balance_pay AS BIGINT),
    CAST(allow_wallet_overflow AS BIGINT),
    COALESCE(stripe_price_id, ''),
    COALESCE(creem_product_id, ''),
    COALESCE(waffo_pancake_product_id, ''),
    COALESCE(CAST(max_purchase_per_user AS BIGINT), 0),
    COALESCE(upgrade_group, ''),
    COALESCE(downgrade_group, ''),
    COALESCE(CAST(total_amount AS BIGINT), 0),
    COALESCE(quota_reset_period, ''),
    COALESCE(CAST(quota_reset_custom_seconds AS BIGINT), 0),
    COALESCE(CAST(created_at AS BIGINT), 0),
    COALESCE(CAST(updated_at AS BIGINT), 0)
FROM subscription_plans
WHERE id = $1
"#;

macro_rules! map_plan {
    ($row:expr) => {
        SubscriptionPlanRow {
            id: $row.get(0),
            title: $row.get(1),
            subtitle: $row.get(2),
            price_amount: $row.get(3),
            currency: $row.get(4),
            duration_unit: $row.get(5),
            duration_value: $row.get::<i64, _>(6) as i32,
            custom_seconds: $row.get(7),
            enabled: $row.get::<i64, _>(8) != 0,
            sort_order: $row.get::<i64, _>(9) as i32,
            allow_balance_pay: $row.get::<Option<i64>, _>(10).map(|v| v != 0),
            allow_wallet_overflow: $row.get::<Option<i64>, _>(11).map(|v| v != 0),
            stripe_price_id: $row.get(12),
            creem_product_id: $row.get(13),
            waffo_pancake_product_id: $row.get(14),
            max_purchase_per_user: $row.get::<i64, _>(15) as i32,
            upgrade_group: $row.get(16),
            downgrade_group: $row.get(17),
            total_amount: $row.get(18),
            quota_reset_period: $row.get(19),
            quota_reset_custom_seconds: $row.get(20),
            created_at: $row.get(21),
            updated_at: $row.get(22),
        }
    };
}

macro_rules! map_order {
    ($row:expr) => {
        SubscriptionOrderRow {
            id: $row.get(0),
            user_id: $row.get(1),
            plan_id: $row.get(2),
            money: $row.get(3),
            trade_no: $row.get(4),
            payment_method: $row.get(5),
            payment_provider: $row.get(6),
            status: $row.get(7),
            create_time: $row.get(8),
            complete_time: $row.get(9),
            provider_payload: $row.get(10),
        }
    };
}

/// Go `SubscriptionOrder.Insert`（`:237-242`）：`create_time` 零值时由
/// BeforeCreate 补当前秒（调用方直接传）。
pub async fn insert_subscription_order(
    db: &Database,
    user_id: i64,
    plan_id: i64,
    money: f64,
    trade_no: &str,
    payment_method: &str,
    payment_provider: &str,
    create_time: i64,
) -> Result<(), sqlx::Error> {
    let sql = concat!(
        "INSERT INTO subscription_orders (user_id, plan_id, money, trade_no, ",
        "payment_method, payment_provider, create_time, complete_time, ",
        "provider_payload, status) VALUES ($1,$2,$3,$4,$5,$6,$7,0,'',$8)"
    );
    match db {
        Database::Sqlite(pool) => {
            sqlx::query(sql)
                .bind(user_id)
                .bind(plan_id)
                .bind(money)
                .bind(trade_no)
                .bind(payment_method)
                .bind(payment_provider)
                .bind(create_time)
                .bind(STATUS_PENDING)
                .execute(pool)
                .await?;
        }
        Database::Postgres(pool) => {
            sqlx::query(sql)
                .bind(user_id)
                .bind(plan_id)
                .bind(money)
                .bind(trade_no)
                .bind(payment_method)
                .bind(payment_provider)
                .bind(create_time)
                .bind(STATUS_PENDING)
                .execute(pool)
                .await?;
        }
    }
    Ok(())
}

/// Go `GetSubscriptionOrderByTradeNo`（`:1595-1604`）：查询错误折叠为
/// `None`（与 gorm `.First` 出错返回 nil 同型）。
pub async fn get_subscription_order_by_trade_no(
    db: &Database,
    trade_no: &str,
) -> Option<SubscriptionOrderRow> {
    if trade_no.is_empty() {
        return None;
    }
    macro_rules! run {
        ($pool:expr, $kind:ty) => {{
            let row = sqlx::query::<$kind>(ORDER_BY_TRADE_NO)
                .bind(trade_no)
                .fetch_optional($pool)
                .await
                .ok()?;
            row.map(|row| map_order!(row))
        }};
    }
    match db {
        Database::Sqlite(pool) => run!(pool, sqlx::Sqlite),
        Database::Postgres(pool) => run!(pool, sqlx::Postgres),
    }
}

/// Go `CountUserSubscriptionsByPlan`（`:1580-1591`）；非法参数在 Go 返回
/// `(0, error)`，这里折叠为 0（调用侧仅用于上限比较）。
pub async fn count_user_subscriptions_by_plan(
    db: &Database,
    user_id: i64,
    plan_id: i64,
) -> Result<i64, sqlx::Error> {
    if user_id <= 0 || plan_id <= 0 {
        return Ok(0);
    }
    const SQL: &str = "SELECT COUNT(*) FROM user_subscriptions WHERE user_id = $1 AND plan_id = $2";
    match db {
        Database::Sqlite(pool) => {
            sqlx::query_scalar(SQL)
                .bind(user_id)
                .bind(plan_id)
                .fetch_one(pool)
                .await
        }
        Database::Postgres(pool) => {
            sqlx::query_scalar(SQL)
                .bind(user_id)
                .bind(plan_id)
                .fetch_one(pool)
                .await
        }
    }
}

/// Go `LockUserRow` + 软删除排除（`identity/query_users.go:46-50`）。
const LOCK_USER_SQLITE: &str = "SELECT id FROM users WHERE id = $1 AND deleted_at IS NULL";
const LOCK_USER_POSTGRES: &str =
    "SELECT id FROM users WHERE id = $1 AND deleted_at IS NULL FOR UPDATE";
const USER_GROUP: &str = r#"SELECT "group" FROM users WHERE id = $1 AND deleted_at IS NULL"#;
const SET_USER_GROUP: &str = r#"UPDATE users SET "group" = $2 WHERE id = $1"#;

const INSERT_SUBSCRIPTION: &str = r#"
INSERT INTO user_subscriptions
    (user_id, plan_id, amount_total, amount_used, start_time, end_time, status,
     source, last_reset_time, next_reset_time, upgrade_group, prev_user_group,
     downgrade_group, allow_wallet_overflow, created_at, updated_at)
VALUES ($1, $2, $3, 0, $4, $5, 'active', $6, $7, $8, $9, $10, $11, $12, $13, $13)
"#;

const TOPUP_BY_TRADE_NO: &str =
    concat!("SELECT id, payment_method, create_time FROM top_ups WHERE trade_no = $1");

const INSERT_TOPUP: &str = concat!(
    "INSERT INTO top_ups (user_id, amount, money, trade_no, payment_method, ",
    "create_time, complete_time, status) VALUES ($1, 0, $2, $3, $4, $5, $6, $7)"
);

const UPDATE_TOPUP: &str = concat!(
    "UPDATE top_ups SET money = $2, payment_method = $3, create_time = $4, ",
    "complete_time = $5, status = $6 WHERE id = $1"
);

const COMPLETE_ORDER_CAS: &str = concat!(
    "UPDATE subscription_orders SET status = $2, complete_time = $3, ",
    "provider_payload = $4, payment_method = $5 ",
    "WHERE id = $1 AND status = $6"
);

const EXPIRE_ORDER_CAS: &str =
    "UPDATE subscription_orders SET status = $2, complete_time = $3 WHERE id = $1 AND status = $4";

/// Go `ExpireSubscriptionOrder`（`:1443-1466`）：网关归属不符 → mismatch；
/// 非 pending 幂等返回 Ok；pending → expired + complete_time。
pub async fn expire_subscription_order(
    db: &Database,
    trade_no: &str,
    expected_payment_provider: &str,
    now: i64,
) -> Result<(), SubscriptionOrderError> {
    if trade_no.is_empty() {
        return Err(SubscriptionOrderError::NotFound);
    }
    macro_rules! run {
        ($pool:expr, $kind:ty, $order_sql:expr) => {{
            let mut tx = $pool.begin().await?;
            let outcome: Result<(), SubscriptionOrderError> = async {
                let row = sqlx::query::<$kind>($order_sql)
                    .bind(trade_no)
                    .fetch_optional(&mut *tx)
                    .await?;
                let Some(row) = row else {
                    return Err(SubscriptionOrderError::NotFound);
                };
                let order = map_order!(row);
                if !expected_payment_provider.is_empty()
                    && order.payment_provider != expected_payment_provider
                {
                    return Err(SubscriptionOrderError::ProviderMismatch);
                }
                if order.status != STATUS_PENDING {
                    return Ok(());
                }
                sqlx::query(EXPIRE_ORDER_CAS)
                    .bind(order.id)
                    .bind(STATUS_EXPIRED)
                    .bind(now)
                    .bind(STATUS_PENDING)
                    .execute(&mut *tx)
                    .await?;
                Ok(())
            }
            .await;
            match outcome {
                Ok(value) => {
                    tx.commit().await?;
                    Ok(value)
                }
                Err(error) => {
                    let _ = tx.rollback().await;
                    Err(error)
                }
            }
        }};
    }
    match db {
        Database::Sqlite(pool) => run!(pool, sqlx::Sqlite, ORDER_BY_TRADE_NO_LOCKED),
        Database::Postgres(pool) => run!(pool, sqlx::Postgres, ORDER_BY_TRADE_NO_FOR_UPDATE),
    }
}

/// Go `CompleteSubscriptionOrder`（`:1502-1579`）的存储半边。事务外行为
/// （分组缓存刷新、购买成功日志）由调用方依 [`SubscriptionCompleteRecord`]
/// 执行。`now` 是 unix 秒（Go `common.GetTimestamp()`）。
pub async fn complete_subscription_order(
    db: &Database,
    trade_no: &str,
    provider_payload: &str,
    expected_payment_provider: &str,
    actual_payment_method: &str,
    now: i64,
) -> Result<SubscriptionCompleteOutcome, SubscriptionOrderError> {
    if trade_no.is_empty() {
        return Err(SubscriptionOrderError::NotFound);
    }
    macro_rules! run {
        ($pool:expr, $kind:ty, $order_sql:expr, $lock_user_sql:expr) => {{
            let mut tx = $pool.begin().await?;
            let outcome: Result<SubscriptionCompleteOutcome, SubscriptionOrderError> = async {
                let row = sqlx::query::<$kind>($order_sql)
                    .bind(trade_no)
                    .fetch_optional(&mut *tx)
                    .await?;
                let Some(row) = row else {
                    return Err(SubscriptionOrderError::NotFound);
                };
                let order = map_order!(row);
                if !expected_payment_provider.is_empty()
                    && order.payment_provider != expected_payment_provider
                {
                    return Err(SubscriptionOrderError::ProviderMismatch);
                }
                if order.status == STATUS_SUCCESS {
                    return Ok(SubscriptionCompleteOutcome::AlreadyDone);
                }
                if order.status != STATUS_PENDING {
                    return Err(SubscriptionOrderError::StatusInvalid);
                }
                // Go `GetSubscriptionPlanById(order.PlanId)`：缺失即 gorm
                // record not found（事务回滚后上抛）。
                let plan_row = sqlx::query::<$kind>(PLAN_BY_ID)
                    .bind(order.plan_id)
                    .fetch_optional(&mut *tx)
                    .await?;
                let Some(plan_row) = plan_row else {
                    return Err(SubscriptionOrderError::Business(
                        "record not found".to_string(),
                    ));
                };
                let plan = map_plan!(plan_row);
                // 锁定用户行：并发完成同一用户的不同订单时，MaxPurchasePerUser
                // 检查按用户串行（Go `:1536-1540`）。
                let locked: Option<i64> = sqlx::query_scalar($lock_user_sql)
                    .bind(order.user_id)
                    .fetch_optional(&mut *tx)
                    .await?;
                if locked.is_none() {
                    return Err(SubscriptionOrderError::Business(
                        "record not found".to_string(),
                    ));
                }
                // Go `CreateUserSubscriptionFromPlanTx` 的购买上限检查。
                if plan.max_purchase_per_user > 0 {
                    let count: i64 = sqlx::query_scalar(
                        "SELECT COUNT(*) FROM user_subscriptions \
                             WHERE user_id = $1 AND plan_id = $2",
                    )
                    .bind(order.user_id)
                    .bind(plan.id)
                    .fetch_one(&mut *tx)
                    .await?;
                    if count >= i64::from(plan.max_purchase_per_user) {
                        return Err(SubscriptionOrderError::Business(
                            "已达到该套餐购买上限".to_string(),
                        ));
                    }
                }
                let end_unix =
                    calc_plan_end_time(now, &plan).map_err(SubscriptionOrderError::Business)?;
                let next_reset = calc_next_reset_time(now, &plan, end_unix);
                let last_reset = if next_reset > 0 { now } else { 0 };
                // 分组升级快照（Go `:539-553`）。
                let upgrade_group = plan.upgrade_group.trim().to_string();
                let mut prev_group = String::new();
                if !upgrade_group.is_empty() {
                    let current: Option<String> = sqlx::query_scalar(USER_GROUP)
                        .bind(order.user_id)
                        .fetch_one(&mut *tx)
                        .await?;
                    let current = current.unwrap_or_default();
                    if current != upgrade_group {
                        prev_group = current;
                        sqlx::query(SET_USER_GROUP)
                            .bind(order.user_id)
                            .bind(&upgrade_group)
                            .execute(&mut *tx)
                            .await?;
                    }
                }
                sqlx::query(INSERT_SUBSCRIPTION)
                    .bind(order.user_id)
                    .bind(plan.id)
                    .bind(plan.total_amount)
                    .bind(now)
                    .bind(end_unix)
                    .bind("order")
                    .bind(last_reset)
                    .bind(next_reset)
                    .bind(&upgrade_group)
                    .bind(&prev_group)
                    .bind(plan.downgrade_group.trim())
                    .bind(plan.allow_wallet_overflow.unwrap_or(true) as i64)
                    .bind(now)
                    .execute(&mut *tx)
                    .await?;
                // Go `upsertSubscriptionTopUpTx`（`:1467-1501`）。
                let topup: Option<(i64, Option<String>, i64)> = sqlx::query_as(TOPUP_BY_TRADE_NO)
                    .bind(&order.trade_no)
                    .fetch_optional(&mut *tx)
                    .await?;
                match topup {
                    None => {
                        sqlx::query(INSERT_TOPUP)
                            .bind(order.user_id)
                            .bind(order.money)
                            .bind(&order.trade_no)
                            .bind(&order.payment_method)
                            .bind(order.create_time)
                            .bind(now)
                            .bind(STATUS_SUCCESS)
                            .execute(&mut *tx)
                            .await?;
                    }
                    Some((topup_id, existing_method, topup_create_time)) => {
                        let existing_method = existing_method.unwrap_or_default();
                        if !existing_method.is_empty() && existing_method != order.payment_method {
                            return Err(SubscriptionOrderError::ProviderMismatch);
                        }
                        let create_time = if topup_create_time == 0 {
                            order.create_time
                        } else {
                            topup_create_time
                        };
                        sqlx::query(UPDATE_TOPUP)
                            .bind(topup_id)
                            .bind(order.money)
                            .bind(&order.payment_method)
                            .bind(create_time)
                            .bind(now)
                            .bind(STATUS_SUCCESS)
                            .execute(&mut *tx)
                            .await?;
                    }
                }
                // CAS 翻转（Go 的 `Save` 由事务 + 行锁承担同一不变量）。
                let payload = if provider_payload.is_empty() {
                    order.provider_payload.as_str()
                } else {
                    provider_payload
                };
                let actual_method = if !actual_payment_method.is_empty()
                    && order.payment_method != actual_payment_method
                {
                    actual_payment_method
                } else {
                    order.payment_method.as_str()
                };
                let updated = sqlx::query(COMPLETE_ORDER_CAS)
                    .bind(order.id)
                    .bind(STATUS_SUCCESS)
                    .bind(now)
                    .bind(payload)
                    .bind(actual_method)
                    .bind(STATUS_PENDING)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected();
                if updated == 0 {
                    // 并发竞争：重读状态区分幂等与非法。
                    let current: Option<String> =
                        sqlx::query_scalar("SELECT status FROM subscription_orders WHERE id = $1")
                            .bind(order.id)
                            .fetch_optional(&mut *tx)
                            .await?;
                    return match current.as_deref() {
                        Some(STATUS_SUCCESS) => Ok(SubscriptionCompleteOutcome::AlreadyDone),
                        _ => Err(SubscriptionOrderError::StatusInvalid),
                    };
                }
                let upgraded_group = if prev_group.is_empty() {
                    None
                } else {
                    Some(upgrade_group.clone())
                };
                Ok(SubscriptionCompleteOutcome::Completed(
                    SubscriptionCompleteRecord {
                        user_id: order.user_id,
                        upgraded_group,
                        plan_title: plan.title.clone(),
                        money: order.money,
                        payment_method: actual_method.to_owned(),
                    },
                ))
            }
            .await;
            match outcome {
                Ok(value) => {
                    tx.commit().await?;
                    Ok(value)
                }
                Err(error) => {
                    let _ = tx.rollback().await;
                    Err(error)
                }
            }
        }};
    }
    match db {
        Database::Sqlite(pool) => run!(
            pool,
            sqlx::Sqlite,
            ORDER_BY_TRADE_NO_LOCKED,
            LOCK_USER_SQLITE
        ),
        Database::Postgres(pool) => run!(
            pool,
            sqlx::Postgres,
            ORDER_BY_TRADE_NO_FOR_UPDATE,
            LOCK_USER_POSTGRES
        ),
    }
}
