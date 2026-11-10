//! 订阅自助域的存储访问；Go `store_subscription.go` 的只读子集。
//!
//! 本端口无进程级缓存层，因此 `GetSubscriptionPlans` 直接查库（与 Go
//! handler 一致——Go 的该 handler 本身也直查 DB，plan 缓存只服务于消费路径）。
//! `user_subscriptions` 的状态机由写入方维护（Go 在支付回调与 reset 任务里
//! 翻转 status），读取端只做 `status='active' AND end_time > now` 的活性
//! 过滤，不做惰性翻转——与 Go `GetAllActiveUserSubscriptions` 逐字一致。
//!
//! sqlx 0.9 的 `ColumnIndex<usize>` 只对具体行类型实现，泛型 `R: Row` 的
//! 取列不可行；行映射由一个共享宏生成函数体，再按后端各包一层具体签名。

use newapi_storage::Database;
use sqlx::Row;

/// Go `SubscriptionPlan`（`store_subscription.go:104-155`）的行投影；
/// `gorm:"-"` 的两个 display 字段不在行上，由 server 适配层渲染时计算。
/// int 字段统一按 Go `int` 语义；`*bool` 保留可空以复刻 `NormalizeDefaults`
/// 之前的数据库原值。
pub struct SubscriptionPlanRow {
    pub id: i64,
    pub title: String,
    pub subtitle: String,
    pub price_amount: f64,
    pub currency: String,
    pub duration_unit: String,
    pub duration_value: i32,
    pub custom_seconds: i64,
    pub enabled: bool,
    pub sort_order: i32,
    pub allow_balance_pay: Option<bool>,
    pub allow_wallet_overflow: Option<bool>,
    pub stripe_price_id: String,
    pub creem_product_id: String,
    pub waffo_pancake_product_id: String,
    pub max_purchase_per_user: i32,
    pub upgrade_group: String,
    pub downgrade_group: String,
    pub total_amount: i64,
    pub quota_reset_period: String,
    pub quota_reset_custom_seconds: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Go `UserSubscription`（`store_subscription.go:249-282`）的行投影。
pub struct UserSubscriptionRow {
    pub id: i64,
    pub user_id: i64,
    pub plan_id: i64,
    pub amount_total: i64,
    pub amount_used: i64,
    pub start_time: i64,
    pub end_time: i64,
    pub status: String,
    pub source: String,
    pub last_reset_time: i64,
    pub next_reset_time: i64,
    pub upgrade_group: String,
    pub prev_user_group: String,
    pub downgrade_group: String,
    pub allow_wallet_overflow: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

/// 订阅自助域的只读存储；偏好写路径走 `identity::users` 的既有仓库。
pub struct SubscriptionRepository {
    db: Database,
}

/// Go `GetSubscriptionPlans` 的查询：`enabled = true`，按
/// `sort_order desc, id desc` 排序（`manage_subscription.go:42`）。布尔列以
/// `CAST(... AS BIGINT)` 读取以兼容 PG BOOLEAN 与 SQLite 0/1；整列读
/// BIGINT、金额读 DOUBLE PRECISION，两个后端同型。
const PLANS_ENABLED: &str = r#"
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
WHERE CAST(enabled AS BIGINT) = 1
ORDER BY sort_order DESC, id DESC
"#;

/// Go `GetAllUserSubscriptions`：全部订阅（含过期），按
/// `end_time desc, id desc`（`store_subscription.go:757-769`）。
const SUBSCRIPTIONS_ALL: &str = r#"
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
WHERE user_id = $1
ORDER BY end_time DESC, id DESC
"#;

/// Go `GetAllActiveUserSubscriptions`：在全部列之上追加
/// `status='active' AND end_time > now`（`store_subscription.go:707-720`），
/// `now` 由调用方传入 unix 秒。
const SUBSCRIPTIONS_ACTIVE: &str = r#"
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
WHERE user_id = $1 AND status = 'active' AND end_time > $2
ORDER BY end_time DESC, id DESC
"#;

/// Go `identity.GetUserSetting`（`store_users.go:1089-1123`）的 setting
/// 列读取：`.Find` 查询出错才报错，用户不存在或 NULL 都回空串。
/// 软删除用户被 GORM 默认作用域排除，这里同样排除。
const USER_SETTING: &str = "SELECT setting FROM users WHERE id = $1 AND deleted_at IS NULL";

/// 行 → [`SubscriptionPlanRow`] 的共享函数体；列序与 `PLANS_ENABLED` 一致。
/// `row.get(usize)` 的类型由目标字段推断，两个后端的行类型各自实例化。
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

/// 行 → [`UserSubscriptionRow`] 的共享函数体；列序与两个订阅 SELECT 一致。
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

impl SubscriptionRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Go `GetSubscriptionPlans`：只返回启用的套餐。
    pub async fn list_enabled_plans(&self) -> Result<Vec<SubscriptionPlanRow>, sqlx::Error> {
        macro_rules! run {
            ($pool:expr, $kind:ty) => {{
                let rows = sqlx::query::<$kind>(PLANS_ENABLED).fetch_all($pool).await?;
                Ok(rows.iter().map(|row| map_plan!(row)).collect())
            }};
        }
        match &self.db {
            Database::Sqlite(pool) => run!(pool, sqlx::Sqlite),
            Database::Postgres(pool) => run!(pool, sqlx::Postgres),
        }
    }

    /// Go `GetAllUserSubscriptions`：全部订阅（含过期），按
    /// `end_time desc, id desc`（`store_subscription.go:757-769`）。
    pub async fn all_user_subscriptions(
        &self,
        user_id: i64,
    ) -> Result<Vec<UserSubscriptionRow>, sqlx::Error> {
        macro_rules! run {
            ($pool:expr, $kind:ty) => {{
                let rows = sqlx::query::<$kind>(SUBSCRIPTIONS_ALL)
                    .bind(user_id)
                    .fetch_all($pool)
                    .await?;
                Ok(rows.iter().map(|row| map_subscription!(row)).collect())
            }};
        }
        match &self.db {
            Database::Sqlite(pool) => run!(pool, sqlx::Sqlite),
            Database::Postgres(pool) => run!(pool, sqlx::Postgres),
        }
    }

    /// Go `GetAllActiveUserSubscriptions`：`status='active' AND end_time > now`
    /// （`store_subscription.go:707-720`）。`now` 由调用方传入 unix 秒。
    pub async fn active_user_subscriptions(
        &self,
        user_id: i64,
        now: i64,
    ) -> Result<Vec<UserSubscriptionRow>, sqlx::Error> {
        macro_rules! run {
            ($pool:expr, $kind:ty) => {{
                let rows = sqlx::query::<$kind>(SUBSCRIPTIONS_ACTIVE)
                    .bind(user_id)
                    .bind(now)
                    .fetch_all($pool)
                    .await?;
                Ok(rows.iter().map(|row| map_subscription!(row)).collect())
            }};
        }
        match &self.db {
            Database::Sqlite(pool) => run!(pool, sqlx::Sqlite),
            Database::Postgres(pool) => run!(pool, sqlx::Postgres),
        }
    }

    pub async fn user_setting(&self, user_id: i64) -> Result<String, sqlx::Error> {
        match &self.db {
            Database::Sqlite(pool) => {
                let row: Option<Option<String>> = sqlx::query_scalar(USER_SETTING)
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await?;
                Ok(row.flatten().unwrap_or_default())
            }
            Database::Postgres(pool) => {
                let row: Option<Option<String>> = sqlx::query_scalar(USER_SETTING)
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await?;
                Ok(row.flatten().unwrap_or_default())
            }
        }
    }
}
