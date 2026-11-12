//! 订阅管理侧的存储与状态机写入；Go `store_subscription.go` 写入函数与
//! `manage_subscription.go` admin handler 的库层。
//!
//! Go 参考：
//! - `AdminBindSubscriptionRecord`（`store_subscription.go:1414-1441`）
//! - `CreateUserSubscriptionFromPlanTx`（`store_subscription.go:506-581`）
//! - `AdminResetPlanSubscriptionsRecord` / `AdminResetUserSubscriptionsByPlanRecord`
//!   （`store_subscription.go:1321-1404`）
//! - `invalidateUserSubscriptionRecord` / `deleteUserSubscriptionRecord`
//!   （`store_subscription.go:786-857`）
//! - `downgradeUserGroupForSubscriptionTx` / `resolveSubscriptionGroupBaselineTx`
//!   （`store_subscription.go:424-504`）
//!
//! 事务边界与 Go 对齐（`pool.begin()`；SQLite 无行锁，PostgreSQL 发
//! `FOR UPDATE`，同 `dbx.LockForUpdate` 的驱动分支）。sqlx 0.9 的行类型按
//! 后端各异，行映射宏沿 `store.rs` 的文本作用域复用。

use newapi_storage::Database;
use sqlx::Row;

use super::period::{calc_next_reset_time, calc_plan_end_time};
use super::store::{SubscriptionPlanRow, SubscriptionRepository, UserSubscriptionRow};

/// Go `gorm.ErrRecordNotFound` 的对外文案（`CtxApiError` 原样透出）。
pub const MSG_RECORD_NOT_FOUND: &str = "record not found";

/// 库层错误：`NotFound` 对应 gorm record not found，`Business` 携带 Go 的
/// 硬编码业务文案，`Db` 是数据库故障（server 侧折叠为 common.database_error）。
#[derive(Debug)]
pub enum AdminError {
    NotFound,
    Business(String),
    Db(sqlx::Error),
}

impl From<sqlx::Error> for AdminError {
    fn from(error: sqlx::Error) -> Self {
        AdminError::Db(error)
    }
}

/// Go `SubscriptionPlan` 写入投影（create/update 共用）；两个 `*bool` 保留
/// 可空以复刻「nil 时不动列」的更新语义（create 侧由 server 先填默认）。
pub struct PlanWrite {
    pub title: String,
    pub subtitle: String,
    pub price_amount: f64,
    pub currency: String,
    pub duration_unit: String,
    pub duration_value: i64,
    pub custom_seconds: i64,
    pub enabled: bool,
    pub sort_order: i64,
    pub allow_balance_pay: Option<bool>,
    pub allow_wallet_overflow: Option<bool>,
    pub stripe_price_id: String,
    pub creem_product_id: String,
    pub waffo_pancake_product_id: String,
    pub max_purchase_per_user: i64,
    pub upgrade_group: String,
    pub downgrade_group: String,
    pub total_amount: i64,
    pub quota_reset_period: String,
    pub quota_reset_custom_seconds: i64,
}

/// Go `SubscriptionResetResult`（`store_subscription.go:305-313`）的 JSON
/// 形态；`plan_title` / `affected_user_ids` 带 `json:"-"`，不序列化。
pub struct SubscriptionResetResult {
    pub plan_id: i64,
    pub matched_count: i64,
    pub reset_count: i64,
    pub user_count: i64,
    pub advance_reset_time: bool,
    pub plan_title: String,
}

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

/// Go `CreateUserSubscriptionFromPlanTx` 的订阅插入；列序同
/// `user_subscriptions` 行投影。
const INSERT_SUBSCRIPTION: &str = r#"
INSERT INTO user_subscriptions
    (user_id, plan_id, amount_total, amount_used, start_time, end_time, status,
     source, last_reset_time, next_reset_time, upgrade_group, prev_user_group,
     downgrade_group, allow_wallet_overflow, created_at, updated_at)
VALUES ($1, $2, $3, 0, $4, $5, 'active', $6, $7, $8, $9, $10, $11, $12, $13, $13)
"#;

/// Go `identity.LockUserRow`（`query_users.go:46-50`）：软删除行同样被
/// GORM 作用域排除。SQLite 单写者不发 `FOR UPDATE`，PostgreSQL 发。
const LOCK_USER_SQLITE: &str = "SELECT id FROM users WHERE id = $1 AND deleted_at IS NULL";
const LOCK_USER_POSTGRES: &str =
    "SELECT id FROM users WHERE id = $1 AND deleted_at IS NULL FOR UPDATE";

const COUNT_USER_PLAN: &str =
    "SELECT COUNT(*) FROM user_subscriptions WHERE user_id = $1 AND plan_id = $2";

const USER_GROUP: &str = r#"SELECT "group" FROM users WHERE id = $1 AND deleted_at IS NULL"#;
const SET_USER_GROUP: &str = r#"UPDATE users SET "group" = $2 WHERE id = $1"#;

/// Go `adminResetPlanSubscriptionsTx` 的活动订阅选取
/// （`store_subscription.go:1358-1366`）。
macro_rules! active_subs_select {
    ($where:expr, $order:expr) => {
        concat!(
            r#"
SELECT
    COALESCE(CAST(id AS BIGINT), 0),
    COALESCE(CAST(user_id AS BIGINT), 0),
    COALESCE(CAST(plan_id AS BIGINT), 0),
    COALESCE(CAST(amount_total AS BIGINT), 0),
    COALESCE(CAST(amount_used AS BIGINT), 0),
    COALESCE(CAST(start_time AS BIGINT), 0),
    COALESCE(CAST(end_time AS BIGINT), 0),
    COALESCE(status, ''),
    COALESCE(source, ''),
    COALESCE(CAST(last_reset_time AS BIGINT), 0),
    COALESCE(CAST(next_reset_time AS BIGINT), 0),
    COALESCE(upgrade_group, ''),
    COALESCE(prev_user_group, ''),
    COALESCE(downgrade_group, ''),
    COALESCE(CAST(allow_wallet_overflow AS BIGINT), 0),
    COALESCE(CAST(created_at AS BIGINT), 0),
    COALESCE(CAST(updated_at AS BIGINT), 0)
FROM user_subscriptions
WHERE "#,
            $where,
            $order
        )
    };
}

const ACTIVE_BY_PLAN: &str = active_subs_select!(
    "plan_id = $1 AND status = 'active' AND end_time > $2",
    " ORDER BY user_id ASC, end_time ASC, id ASC"
);
const ACTIVE_BY_USER_PLAN: &str = active_subs_select!(
    "user_id = $1 AND plan_id = $2 AND status = 'active' AND end_time > $3",
    " ORDER BY end_time ASC, id ASC"
);

/// Go `resetUserSubscriptionTx`（`store_subscription.go:1405-1412`）的
/// `Save`：整行回写，这里只动受影响列。
const RESET_SUBSCRIPTION: &str = r#"
UPDATE user_subscriptions
SET amount_used = 0, last_reset_time = $2, next_reset_time = $3, updated_at = $4
WHERE id = $1
"#;

const SUBSCRIPTION_BY_ID: &str = active_subs_select!("id = $1", "");

/// Go `invalidateUserSubscriptionRecord` 的状态翻转
/// （`store_subscription.go:798-804`）。
const CANCEL_SUBSCRIPTION: &str = r#"
UPDATE user_subscriptions
SET status = 'cancelled', end_time = $2, updated_at = $2
WHERE id = $1
"#;

const DELETE_SUBSCRIPTION: &str = "DELETE FROM user_subscriptions WHERE id = $1";

/// Go `downgradeUserGroupForSubscriptionTx` 的「另一条活动升级订阅」存在性
/// 检查（`store_subscription.go:481-489`）。
const OTHER_ACTIVE_UPGRADED: &str = r#"
SELECT COUNT(*) FROM user_subscriptions
WHERE user_id = $1 AND status = 'active' AND end_time > $2
  AND id <> $3 AND upgrade_group <> ''
"#;

/// Go `resolveSubscriptionGroupBaselineTx` 的最早期授权回溯
/// （`store_subscription.go:434-443`）。
const EARLIEST_GROUP_GRANT_PREV: &str = r#"
SELECT prev_user_group FROM user_subscriptions
WHERE user_id = $1 AND upgrade_group = $2 AND prev_user_group <> ''
ORDER BY id ASC
LIMIT 1
"#;

/// 行 → [`SubscriptionPlanRow`]；列序与 `PLAN_BY_ID` / `PLANS_ALL` 一致
/// （与 `store.rs` 的同名宏同体，因 `macro_rules!` 作用域需重复声明）。
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

/// 行 → [`UserSubscriptionRow`]；列序与 `active_subs_select!` 一致（与
/// `store.rs` 的同名宏同体，因 `macro_rules!` 作用域需重复声明）。
macro_rules! map_subscription {
    ($row:expr) => {
        UserSubscriptionRow {
            id: $row.get(0),
            user_id: $row.get(1),
            plan_id: $row.get(2),
            amount_total: $row.get(3),
            amount_used: $row.get(4),
            start_time: $row.get(5),
            end_time: $row.get(6),
            status: $row.get(7),
            source: $row.get(8),
            last_reset_time: $row.get(9),
            next_reset_time: $row.get(10),
            upgrade_group: $row.get(11),
            prev_user_group: $row.get(12),
            downgrade_group: $row.get(13),
            allow_wallet_overflow: $row.get::<i64, _>(14) != 0,
            created_at: $row.get(15),
            updated_at: $row.get(16),
        }
    };
}

/// Go `resetUserSubscriptionTx`：清零已用量；`advance_reset_time` 时按套餐
/// 周期推进重置点并盖 `last_reset_time`，否则不动（Go 的 `Save` 整行回写，
/// 未提及字段本就未变）。执行器按驱动各实例化一份。
macro_rules! reset_one {
    ($tx:expr, $sub:expr, $plan:expr, $now:expr, $advance:expr) => {{
        let sub = &$sub;
        let plan = &$plan;
        let now: i64 = $now;
        let (last_reset, next_reset) = if $advance {
            let next = calc_next_reset_time(now, plan, sub.end_time);
            (if next > 0 { now } else { 0 }, next)
        } else {
            (sub.last_reset_time, sub.next_reset_time)
        };
        sqlx::query(RESET_SUBSCRIPTION)
            .bind(sub.id)
            .bind(last_reset)
            .bind(next_reset)
            .bind(now)
            .execute(&mut *$tx)
            .await?;
    }};
}

/// 在事务里复刻 `downgradeUserGroupForSubscriptionTx`
/// （`store_subscription.go:460-504`）：显式 downgrade 优先，否则沿授权链
/// 回退到用户自己的基线分组；命中时更新用户分组并返回目标（供响应
/// message）。`None` 表示无需降级。要求调用方已锁定/独占相关行。
macro_rules! downgrade_target {
    ($tx:expr, $sub:expr, $now:expr) => {{
        let sub = &$sub;
        let downgrade_group = sub.downgrade_group.trim().to_string();
        let upgrade_group = sub.upgrade_group.trim().to_string();
        let mut target: Option<String> = None;
        if !downgrade_group.is_empty() || !upgrade_group.is_empty() {
            let current: Option<String> = sqlx::query_scalar(USER_GROUP)
                .bind(sub.user_id)
                .fetch_one(&mut *$tx)
                .await?;
            let current = current.unwrap_or_default();
            // 另一条活动升级订阅存在时保持现分组（Go `:481-489`）。
            let others: i64 = sqlx::query_scalar(OTHER_ACTIVE_UPGRADED)
                .bind(sub.user_id)
                .bind($now)
                .bind(sub.id)
                .fetch_one(&mut *$tx)
                .await?;
            if others == 0 {
                let mut target_group = downgrade_group;
                if target_group.is_empty() {
                    // 授权链回溯（Go `resolveSubscriptionGroupBaselineTx:424-458`）。
                    let mut group = current.clone();
                    let mut visited = std::collections::HashSet::new();
                    while !group.is_empty() && visited.insert(group.clone()) {
                        let row: Option<Option<String>> =
                            sqlx::query_scalar(EARLIEST_GROUP_GRANT_PREV)
                                .bind(sub.user_id)
                                .bind(&group)
                                .fetch_optional(&mut *$tx)
                                .await?;
                        match row.flatten() {
                            None => break,
                            Some(prev) => {
                                let prev = prev.trim().to_string();
                                if prev.is_empty() || prev == group {
                                    break;
                                }
                                group = prev;
                            }
                        }
                    }
                    target_group = group;
                }
                if !target_group.is_empty() && target_group != current {
                    sqlx::query(SET_USER_GROUP)
                        .bind(sub.user_id)
                        .bind(&target_group)
                        .execute(&mut *$tx)
                        .await?;
                    target = Some(target_group);
                }
            }
        }
        target
    }};
}

impl SubscriptionRepository {
    /// Go `AdminListSubscriptionPlans`（`manage_subscription.go:125-141`）：
    /// 全量（含禁用），`sort_order desc, id desc`。
    pub async fn list_all_plans(&self) -> Result<Vec<SubscriptionPlanRow>, sqlx::Error> {
        const PLANS_ALL: &str = r#"
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
ORDER BY sort_order DESC, id DESC
"#;
        macro_rules! run {
            ($pool:expr, $kind:ty) => {{
                let rows = sqlx::query::<$kind>(PLANS_ALL).fetch_all($pool).await?;
                Ok(rows.iter().map(|row| map_plan!(row)).collect())
            }};
        }
        match &self.db {
            Database::Sqlite(pool) => run!(pool, sqlx::Sqlite),
            Database::Postgres(pool) => run!(pool, sqlx::Postgres),
        }
    }

    /// Go `getSubscriptionPlanByIdTx` 的无缓存形态；缺失回 `None`（gorm
    /// ErrRecordNotFound → server 侧 `record not found`）。
    pub async fn get_plan(&self, id: i64) -> Result<Option<SubscriptionPlanRow>, sqlx::Error> {
        macro_rules! run {
            ($pool:expr, $kind:ty) => {{
                let row = sqlx::query::<$kind>(PLAN_BY_ID)
                    .bind(id)
                    .fetch_optional($pool)
                    .await?;
                Ok(row.map(|row| map_plan!(row)))
            }};
        }
        match &self.db {
            Database::Sqlite(pool) => run!(pool, sqlx::Sqlite),
            Database::Postgres(pool) => run!(pool, sqlx::Postgres),
        }
    }

    /// Go `dbx.DB.Create(&plan)`（`manage_subscription.go:238`）：BeforeCreate
    /// 写入 created_at/updated_at，返回自增 id。
    pub async fn insert_plan(&self, plan: &PlanWrite, now: i64) -> Result<i64, sqlx::Error> {
        const INSERT_PLAN: &str = r#"
INSERT INTO subscription_plans
    (title, subtitle, price_amount, currency, duration_unit, duration_value,
     custom_seconds, enabled, sort_order, allow_balance_pay, allow_wallet_overflow,
     stripe_price_id, creem_product_id, waffo_pancake_product_id,
     max_purchase_per_user, upgrade_group, downgrade_group, total_amount,
     quota_reset_period, quota_reset_custom_seconds, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
        $17, $18, $19, $20, $21, $21)
RETURNING CAST(id AS BIGINT)
"#;
        macro_rules! run {
            ($pool:expr, $kind:ty) => {{
                let row = sqlx::query::<$kind>(INSERT_PLAN)
                    .bind(&plan.title)
                    .bind(&plan.subtitle)
                    .bind(plan.price_amount)
                    .bind(&plan.currency)
                    .bind(&plan.duration_unit)
                    .bind(plan.duration_value)
                    .bind(plan.custom_seconds)
                    .bind(plan.enabled)
                    .bind(plan.sort_order)
                    .bind(plan.allow_balance_pay.unwrap_or(true))
                    .bind(plan.allow_wallet_overflow.unwrap_or(true))
                    .bind(&plan.stripe_price_id)
                    .bind(&plan.creem_product_id)
                    .bind(&plan.waffo_pancake_product_id)
                    .bind(plan.max_purchase_per_user)
                    .bind(&plan.upgrade_group)
                    .bind(&plan.downgrade_group)
                    .bind(plan.total_amount)
                    .bind(&plan.quota_reset_period)
                    .bind(plan.quota_reset_custom_seconds)
                    .bind(now)
                    .fetch_one($pool)
                    .await?;
                Ok(row.get::<i64, _>(0))
            }};
        }
        match &self.db {
            Database::Sqlite(pool) => run!(pool, sqlx::Sqlite),
            Database::Postgres(pool) => run!(pool, sqlx::Postgres),
        }
    }

    /// Go `AdminUpdateSubscriptionPlan` 的 update map
    /// （`manage_subscription.go:294-317`）：全列覆盖，两个 `*bool` 为 nil 时
    /// 保持原列值（COALESCE），`updated_at` 刷新。命中零行不报错。
    pub async fn update_plan(
        &self,
        id: i64,
        plan: &PlanWrite,
        now: i64,
    ) -> Result<(), sqlx::Error> {
        const UPDATE_PLAN: &str = r#"
UPDATE subscription_plans SET
    title = $2, subtitle = $3, price_amount = $4, currency = $5,
    duration_unit = $6, duration_value = $7, custom_seconds = $8,
    enabled = $9, sort_order = $10,
    allow_balance_pay = COALESCE($11, allow_balance_pay),
    allow_wallet_overflow = COALESCE($12, allow_wallet_overflow),
    stripe_price_id = $13, creem_product_id = $14,
    waffo_pancake_product_id = $15, max_purchase_per_user = $16,
    total_amount = $17, upgrade_group = $18, downgrade_group = $19,
    quota_reset_period = $20, quota_reset_custom_seconds = $21, updated_at = $22
WHERE id = $1
"#;
        macro_rules! run {
            ($pool:expr) => {{
                sqlx::query(UPDATE_PLAN)
                    .bind(id)
                    .bind(&plan.title)
                    .bind(&plan.subtitle)
                    .bind(plan.price_amount)
                    .bind(&plan.currency)
                    .bind(&plan.duration_unit)
                    .bind(plan.duration_value)
                    .bind(plan.custom_seconds)
                    .bind(plan.enabled)
                    .bind(plan.sort_order)
                    .bind(plan.allow_balance_pay)
                    .bind(plan.allow_wallet_overflow)
                    .bind(&plan.stripe_price_id)
                    .bind(&plan.creem_product_id)
                    .bind(&plan.waffo_pancake_product_id)
                    .bind(plan.max_purchase_per_user)
                    .bind(plan.total_amount)
                    .bind(&plan.upgrade_group)
                    .bind(&plan.downgrade_group)
                    .bind(&plan.quota_reset_period)
                    .bind(plan.quota_reset_custom_seconds)
                    .bind(now)
                    .execute($pool)
                    .await?;
                Ok(())
            }};
        }
        match &self.db {
            Database::Sqlite(pool) => run!(pool),
            Database::Postgres(pool) => run!(pool),
        }
    }

    /// Go `AdminUpdateSubscriptionPlanStatus`（`manage_subscription.go:336-352`）。
    pub async fn update_plan_enabled(
        &self,
        id: i64,
        enabled: bool,
        now: i64,
    ) -> Result<(), sqlx::Error> {
        const UPDATE_STATUS: &str =
            "UPDATE subscription_plans SET enabled = $2, updated_at = $3 WHERE id = $1";
        macro_rules! run {
            ($pool:expr) => {{
                sqlx::query(UPDATE_STATUS)
                    .bind(id)
                    .bind(enabled)
                    .bind(now)
                    .execute($pool)
                    .await?;
                Ok(())
            }};
        }
        match &self.db {
            Database::Sqlite(pool) => run!(pool),
            Database::Postgres(pool) => run!(pool),
        }
    }

    /// Go `AdminBindSubscriptionRecord`（`store_subscription.go:1414-1441`）。
    /// 成功且用户分组被升级时返回响应 message（`用户分组将升级到 %s`）。
    pub async fn admin_bind(
        &self,
        user_id: i64,
        plan_id: i64,
        source: &str,
        now: i64,
    ) -> Result<Option<String>, AdminError> {
        let plan = self.get_plan(plan_id).await?.ok_or(AdminError::NotFound)?;
        macro_rules! run {
            ($pool:expr, $lock_sql:expr) => {{
                let mut tx = $pool.begin().await?;
                let outcome: Result<Option<String>, AdminError> = async {
                    // Go：先锁用户行（软删除排除），再做购买次数检查。
                    let locked: Option<i64> = sqlx::query_scalar($lock_sql)
                        .bind(user_id)
                        .fetch_optional(&mut *tx)
                        .await?;
                    if locked.is_none() {
                        return Err(AdminError::NotFound);
                    }
                    if plan.max_purchase_per_user > 0 {
                        let count: i64 = sqlx::query_scalar(COUNT_USER_PLAN)
                            .bind(user_id)
                            .bind(plan_id)
                            .fetch_one(&mut *tx)
                            .await?;
                        if count >= i64::from(plan.max_purchase_per_user) {
                            return Err(AdminError::Business("已达到该套餐购买上限".to_string()));
                        }
                    }
                    let end = calc_plan_end_time(now, &plan).map_err(AdminError::Business)?;
                    let next_reset = calc_next_reset_time(now, &plan, end);
                    let last_reset = if next_reset > 0 { now } else { 0 };
                    let upgrade_group = plan.upgrade_group.trim();
                    let mut prev_group = String::new();
                    if !upgrade_group.is_empty() {
                        let current: Option<String> = sqlx::query_scalar(USER_GROUP)
                            .bind(user_id)
                            .fetch_one(&mut *tx)
                            .await?;
                        let current = current.unwrap_or_default();
                        if current != upgrade_group {
                            prev_group = current;
                            sqlx::query(SET_USER_GROUP)
                                .bind(user_id)
                                .bind(upgrade_group)
                                .execute(&mut *tx)
                                .await?;
                        }
                    }
                    sqlx::query(INSERT_SUBSCRIPTION)
                        .bind(user_id)
                        .bind(plan.id)
                        .bind(plan.total_amount)
                        .bind(now)
                        .bind(end)
                        .bind(source)
                        .bind(last_reset)
                        .bind(next_reset)
                        .bind(upgrade_group)
                        .bind(&prev_group)
                        .bind(plan.downgrade_group.trim())
                        .bind(plan.allow_wallet_overflow.unwrap_or(true))
                        .execute(&mut *tx)
                        .await?;
                    if prev_group.is_empty() {
                        Ok(None)
                    } else {
                        Ok(Some(format!("用户分组将升级到 {}", plan.upgrade_group)))
                    }
                }
                .await;
                match outcome {
                    Ok(value) => {
                        tx.commit().await?;
                        Ok(value)
                    }
                    Err(error) => Err(error),
                }
            }};
        }
        match &self.db {
            Database::Sqlite(pool) => run!(pool, LOCK_USER_SQLITE),
            Database::Postgres(pool) => run!(pool, LOCK_USER_POSTGRES),
        }
    }

    /// Go `AdminResetPlanSubscriptionsRecord`（`store_subscription.go:1321-1337`）。
    pub async fn admin_reset_plan(
        &self,
        plan_id: i64,
        advance_reset_time: bool,
        now: i64,
    ) -> Result<SubscriptionResetResult, AdminError> {
        let plan = self.get_plan(plan_id).await?.ok_or(AdminError::NotFound)?;
        macro_rules! run {
            ($pool:expr, $kind:ty) => {{
                let mut tx = $pool.begin().await?;
                let outcome: Result<Vec<UserSubscriptionRow>, AdminError> = async {
                    let rows = sqlx::query::<$kind>(ACTIVE_BY_PLAN)
                        .bind(plan_id)
                        .bind(now)
                        .fetch_all(&mut *tx)
                        .await?;
                    let subs: Vec<UserSubscriptionRow> =
                        rows.iter().map(|row| map_subscription!(row)).collect();
                    for sub in &subs {
                        reset_one!(tx, sub, plan, now, advance_reset_time);
                    }
                    Ok(subs)
                }
                .await;
                let subs = match outcome {
                    Ok(value) => {
                        tx.commit().await?;
                        value
                    }
                    Err(error) => return Err(error),
                };
                Ok(build_reset_result(&plan, &subs, advance_reset_time))
            }};
        }
        match &self.db {
            Database::Sqlite(pool) => run!(pool, sqlx::Sqlite),
            Database::Postgres(pool) => run!(pool, sqlx::Postgres),
        }
    }

    /// Go `AdminResetUserSubscriptionsByPlanRecord`
    /// （`store_subscription.go:1340-1356`）：无活动订阅时是业务错误
    /// `该用户没有有效的此套餐订阅`。
    pub async fn admin_reset_user_plan(
        &self,
        user_id: i64,
        plan_id: i64,
        advance_reset_time: bool,
        now: i64,
    ) -> Result<SubscriptionResetResult, AdminError> {
        let plan = self.get_plan(plan_id).await?.ok_or(AdminError::NotFound)?;
        macro_rules! run {
            ($pool:expr, $kind:ty) => {{
                let mut tx = $pool.begin().await?;
                let outcome: Result<Vec<UserSubscriptionRow>, AdminError> = async {
                    let rows = sqlx::query::<$kind>(ACTIVE_BY_USER_PLAN)
                        .bind(user_id)
                        .bind(plan_id)
                        .bind(now)
                        .fetch_all(&mut *tx)
                        .await?;
                    let subs: Vec<UserSubscriptionRow> =
                        rows.iter().map(|row| map_subscription!(row)).collect();
                    if subs.is_empty() {
                        return Err(AdminError::Business(
                            "该用户没有有效的此套餐订阅".to_string(),
                        ));
                    }
                    for sub in &subs {
                        reset_one!(tx, sub, plan, now, advance_reset_time);
                    }
                    Ok(subs)
                }
                .await;
                let subs = match outcome {
                    Ok(value) => {
                        tx.commit().await?;
                        value
                    }
                    Err(error) => return Err(error),
                };
                Ok(build_reset_result(&plan, &subs, advance_reset_time))
            }};
        }
        match &self.db {
            Database::Sqlite(pool) => run!(pool, sqlx::Sqlite),
            Database::Postgres(pool) => run!(pool, sqlx::Postgres),
        }
    }

    /// Go `invalidateUserSubscriptionRecord`（`store_subscription.go:786-824`）：
    /// 置 cancelled 并立即结束，随后走降级逻辑；命中降级时返回响应 message。
    pub async fn admin_invalidate(
        &self,
        subscription_id: i64,
        now: i64,
    ) -> Result<Option<String>, AdminError> {
        macro_rules! run {
            ($pool:expr, $kind:ty) => {{
                let mut tx = $pool.begin().await?;
                let outcome: Result<Option<String>, AdminError> = async {
                    let row = sqlx::query::<$kind>(SUBSCRIPTION_BY_ID)
                        .bind(subscription_id)
                        .fetch_optional(&mut *tx)
                        .await?;
                    let Some(sub) = row.map(|row| map_subscription!(row)) else {
                        return Err(AdminError::NotFound);
                    };
                    sqlx::query(CANCEL_SUBSCRIPTION)
                        .bind(sub.id)
                        .bind(now)
                        .execute(&mut *tx)
                        .await?;
                    let target = downgrade_target!(tx, sub, now);
                    Ok(target.map(|group| format!("用户分组将回退到 {group}")))
                }
                .await;
                match outcome {
                    Ok(value) => {
                        tx.commit().await?;
                        Ok(value)
                    }
                    Err(error) => Err(error),
                }
            }};
        }
        match &self.db {
            Database::Sqlite(pool) => run!(pool, sqlx::Sqlite),
            Database::Postgres(pool) => run!(pool, sqlx::Postgres),
        }
    }

    /// Go `deleteUserSubscriptionRecord`（`store_subscription.go:831-857`）：
    /// 先降级再硬删。
    pub async fn admin_delete(
        &self,
        subscription_id: i64,
        now: i64,
    ) -> Result<Option<String>, AdminError> {
        macro_rules! run {
            ($pool:expr, $kind:ty) => {{
                let mut tx = $pool.begin().await?;
                let outcome: Result<Option<String>, AdminError> = async {
                    let row = sqlx::query::<$kind>(SUBSCRIPTION_BY_ID)
                        .bind(subscription_id)
                        .fetch_optional(&mut *tx)
                        .await?;
                    let Some(sub) = row.map(|row| map_subscription!(row)) else {
                        return Err(AdminError::NotFound);
                    };
                    let target = downgrade_target!(tx, sub, now);
                    sqlx::query(DELETE_SUBSCRIPTION)
                        .bind(sub.id)
                        .execute(&mut *tx)
                        .await?;
                    Ok(target.map(|group| format!("用户分组将回退到 {group}")))
                }
                .await;
                match outcome {
                    Ok(value) => {
                        tx.commit().await?;
                        Ok(value)
                    }
                    Err(error) => Err(error),
                }
            }};
        }
        match &self.db {
            Database::Sqlite(pool) => run!(pool, sqlx::Sqlite),
            Database::Postgres(pool) => run!(pool, sqlx::Postgres),
        }
    }
}

/// Go `buildSubscriptionResetResult`（`store_subscription.go:1648-1666`）。
fn build_reset_result(
    plan: &SubscriptionPlanRow,
    subs: &[UserSubscriptionRow],
    advance_reset_time: bool,
) -> SubscriptionResetResult {
    let mut seen = std::collections::HashSet::new();
    for sub in subs {
        seen.insert(sub.user_id);
    }
    SubscriptionResetResult {
        plan_id: plan.id,
        matched_count: subs.len() as i64,
        reset_count: subs.len() as i64,
        user_count: seen.len() as i64,
        advance_reset_time,
        plan_title: plan.title.clone(),
    }
}
