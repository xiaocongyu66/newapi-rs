//! 计费存储原语：Go `store_quota_reserve.go` 依赖的 `identity`/`dbinfra`
//! 配额函数，以及 `store_subscription.go` 的订阅消费事务（PreConsume /
//! Refund / Delta / DeltaCapped / 周期惰性重置）的移植。
//!
//! 事务体经 [`with_tx!`] 按后端各实例化一次，事务内语句用无类型
//! `sqlx::query[_as]` + executor 推断共享同一份文本；共享的事务内辅助逻辑
//! 挂在零尺寸辅助结构上按后端各写一份（sqlx 0.9 的 `ColumnIndex<usize>`
//! 不支持泛型 `R: Row`，前序切片同款约束）。
//!
//! 语义偏差（报告已注明）：
//! - Redis 配额缓存（quotacache）与批量更新队列（BatchUpdateEnabled）未随
//!   本切片移植，全部走数据库条件更新——即 Go 在 Redis 关闭时的回退分支；
//! - 行锁仅 PG 落 `FOR UPDATE`；SQLite 以单写者事务锁达成同样互斥；
//! - 时间统一由调用方传入 unix 秒（Go `common.GetTimestamp()`）。

use newapi_storage::Database;
use sqlx::Row;

use crate::subscription::period;
use crate::subscription::store::SubscriptionPlanRow;

/// Go `identity.Token` 的计费读取面。
#[derive(Debug, Clone)]
pub struct TokenRow {
    pub id: i64,
    pub user_id: i64,
    pub key: String,
    pub remain_quota: i64,
    pub unlimited_quota: bool,
    pub status: i64,
}

/// Go `SubscriptionPreConsumeResult`。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SubscriptionPreConsumeResult {
    pub user_subscription_id: i64,
    pub pre_consumed: i64,
    pub amount_total: i64,
    pub amount_used_before: i64,
    pub amount_used_after: i64,
}

/// Go `SubscriptionPlanInfo`（store_subscription.go:1300-1303）。
#[derive(Debug, Clone, PartialEq)]
pub struct SubscriptionPlanInfo {
    pub plan_id: i64,
    pub plan_title: String,
}

/// 订阅/预扣失败原因。`message()` 保持 Go 哨兵字符串逐字一致
/// （BillingSession 的分流逻辑依赖它）。
#[derive(Debug, Clone, PartialEq)]
pub enum SubscriptionError {
    /// "no active subscription"
    NoActiveSubscription,
    /// "subscription quota insufficient, need=N"
    QuotaInsufficient(i64),
    /// "subscription pre-consume already refunded"
    AlreadyRefunded,
    /// gorm ErrRecordNotFound 等查无行。
    NotFound,
    /// 参数错误（invalid userId / requestId is empty / amount must be > 0）。
    InvalidArgument(&'static str),
    /// 数据库错误。
    Db(String),
}

impl SubscriptionError {
    pub fn message(&self) -> String {
        match self {
            SubscriptionError::NoActiveSubscription => "no active subscription".into(),
            SubscriptionError::QuotaInsufficient(need) => {
                format!("subscription quota insufficient, need={need}")
            }
            SubscriptionError::AlreadyRefunded => {
                "subscription pre-consume already refunded".into()
            }
            SubscriptionError::NotFound => "record not found".into(),
            SubscriptionError::InvalidArgument(msg) => (*msg).into(),
            SubscriptionError::Db(msg) => msg.clone(),
        }
    }
}

impl std::fmt::Display for SubscriptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for SubscriptionError {}

impl From<sqlx::Error> for SubscriptionError {
    fn from(err: sqlx::Error) -> Self {
        SubscriptionError::Db(err.to_string())
    }
}

pub type SubResult<T> = Result<T, SubscriptionError>;

/// 订阅行的事务内读取投影（Go `UserSubscription` 计费字段）。
#[derive(Debug, Clone, Copy)]
struct SubRow {
    amount_total: i64,
    amount_used: i64,
    start_time: i64,
    end_time: i64,
    last_reset_time: i64,
    next_reset_time: i64,
}

/// 计费扣费/预扣存储门面（双后端）。
pub struct BillingStore {
    pub db: Database,
}

// 双后端共享 SQL：列读取一律 CAST(... AS BIGINT) / COALESCE，保持
// SQLite INTEGER 与 PG BIGINT 解码同型。
const SQL_GET_USER_QUOTA: &str =
    "SELECT COALESCE(CAST(quota AS BIGINT), 0) FROM users WHERE id = $1";
const SQL_RESERVE_USER: &str = "UPDATE users SET quota = quota - $1 WHERE id = $2 AND quota >= $1";
const SQL_INCREASE_USER: &str = "UPDATE users SET quota = quota + $1 WHERE id = $2";
const SQL_DECREASE_USER: &str = "UPDATE users SET quota = quota - $1 WHERE id = $2";
const SQL_UPDATE_USED_AND_COUNT: &str = "UPDATE users SET used_quota = used_quota + $1, request_count = request_count + 1 WHERE id = $2";
const SQL_UPDATE_CHANNEL_USED: &str =
    "UPDATE channels SET used_quota = used_quota + $1 WHERE id = $2";
const SQL_RESERVE_TOKEN: &str = "UPDATE tokens SET remain_quota = remain_quota - $1, used_quota = used_quota + $1, \
     accessed_time = $2 WHERE id = $3 AND remain_quota >= $1";
const SQL_DECREASE_TOKEN: &str = "UPDATE tokens SET remain_quota = remain_quota - $1, used_quota = used_quota + $1, \
     accessed_time = $2 WHERE id = $3";
const SQL_PERSIST_TOKEN_DELTA: &str = "UPDATE tokens SET remain_quota = remain_quota + $1, used_quota = used_quota - $1, \
     accessed_time = $2 WHERE id = $3";
const SQL_GET_TOKEN_BY_KEY: &str = "SELECT id, user_id, key, remain_quota, unlimited_quota, status FROM tokens WHERE key = $1 LIMIT 1";
const SQL_HAS_ACTIVE_SUB: &str = "SELECT COUNT(*) FROM user_subscriptions WHERE user_id = $1 AND status = 'active' AND end_time > $2";
const SQL_STRICT_SUB_COUNT: &str = "SELECT COUNT(*) FROM user_subscriptions WHERE user_id = $1 AND status = 'active' \
     AND end_time > $2 AND COALESCE(CAST(allow_wallet_overflow AS BIGINT), 0) = 0";
const SQL_PRECONSUME_REPLAY: &str = "SELECT user_subscription_id, pre_consumed, status FROM subscription_pre_consume_records \
     WHERE request_id = $1 LIMIT 1";
const SQL_PRECONSUME_DUP: &str = "SELECT user_subscription_id, status FROM subscription_pre_consume_records \
     WHERE request_id = $1 LIMIT 1";
const SQL_PRECONSUME_RECORD: &str = "SELECT user_subscription_id, pre_consumed, status FROM subscription_pre_consume_records \
     WHERE request_id = $1 LIMIT 1";
const SQL_INSERT_PRECONSUME: &str = "INSERT INTO subscription_pre_consume_records \
     (request_id, user_id, user_subscription_id, pre_consumed, status, created_at, updated_at) \
     VALUES ($1, $2, $3, $4, 'consumed', $5, $5)";
const SQL_MARK_REFUNDED: &str = "UPDATE subscription_pre_consume_records SET status = 'refunded', updated_at = $2 WHERE request_id = $1";
const SQL_UPDATE_SUB_USED: &str =
    "UPDATE user_subscriptions SET amount_used = $1, updated_at = $2 WHERE id = $3";
const SQL_UPDATE_SUB_RESET: &str = "UPDATE user_subscriptions SET amount_used = $1, last_reset_time = $2, next_reset_time = $3, \
     updated_at = $4 WHERE id = $5";
const SQL_UPDATE_SUB_SCHEDULE: &str = "UPDATE user_subscriptions SET last_reset_time = $1, next_reset_time = $2, updated_at = $3 WHERE id = $4";
const SQL_PLAN_FOR_RESET: &str = "SELECT COALESCE(quota_reset_period, ''), COALESCE(CAST(quota_reset_custom_seconds AS BIGINT), 0) \
     FROM subscription_plans WHERE id = $1";
const SQL_PLAN_INFO_BY_SUB: &str = "SELECT p.id, p.title FROM user_subscriptions s \
     JOIN subscription_plans p ON p.id = s.plan_id WHERE s.id = $1 LIMIT 1";
const SQL_FETCH_SUB: &str = "SELECT amount_total, amount_used, start_time, end_time, last_reset_time, next_reset_time \
     FROM user_subscriptions WHERE id = $1";
const SQL_SUB_CANDIDATES: &str = "SELECT id, plan_id, amount_total, amount_used FROM user_subscriptions \
     WHERE user_id = $1 AND status = 'active' AND end_time > $2 ORDER BY end_time ASC, id ASC";
const SQL_SUB_CANDIDATES_LOCK: &str = "SELECT id, plan_id, amount_total, amount_used FROM user_subscriptions \
     WHERE user_id = $1 AND status = 'active' AND end_time > $2 ORDER BY end_time ASC, id ASC FOR UPDATE";

/// 事务执行宏：同一份事务体按后端各实例化一次。`$hs`/`$hp` 是各后端的
/// 零尺寸事务辅助类型，`$h` 是同一调用点标识符，事务体内用它调用共享
/// 逻辑（`fetch_sub` / 锁读 / 惰性重置等）。
macro_rules! with_tx {
    ($db:expr, $hs_ty:ty, $hp_ty:ty, $hs_val:expr, $hp_val:expr, $tx:ident, $h:ident, $body:block) => {
        match &$db {
            Database::Sqlite(pool) => {
                let mut __tx = pool.begin().await?;
                let $h: &$hs_ty = $hs_val;
                let out = async {
                    let $tx = &mut *__tx;
                    let out = $body;
                    out
                }
                .await;
                match out {
                    Ok(value) => {
                        __tx.commit().await?;
                        Ok(value)
                    }
                    Err(err) => Err(err),
                }
            }
            Database::Postgres(pool) => {
                let mut __tx = pool.begin().await?;
                let $h: &$hp_ty = $hp_val;
                let out = async {
                    let $tx = &mut *__tx;
                    let out = $body;
                    out
                }
                .await;
                match out {
                    Ok(value) => {
                        __tx.commit().await?;
                        Ok(value)
                    }
                    Err(err) => Err(err),
                }
            }
        }
    };
}
impl BillingStore {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Go `identity.GetUserQuota(id, true)` 的 DB 分支：`.Find` 不区分
    /// "用户不存在"，缺失行回 0。
    pub async fn get_user_quota(&self, user_id: i64) -> SubResult<i64> {
        let quota: i64 = match &self.db {
            Database::Sqlite(pool) => sqlx::query_scalar(SQL_GET_USER_QUOTA)
                .bind(user_id)
                .fetch_optional(pool)
                .await?
                .unwrap_or(0),
            Database::Postgres(pool) => sqlx::query_scalar(SQL_GET_USER_QUOTA)
                .bind(user_id)
                .fetch_optional(pool)
                .await?
                .unwrap_or(0),
        };
        Ok(quota)
    }

    /// Go `TryReserveUserQuota`（store_quota_reserve.go:76-114）Redis 关闭回退
    /// 分支：负数报错、0 直接成功、`quota >= ?` 条件原子预扣。
    pub async fn try_reserve_user_quota(&self, user_id: i64, quota: i64) -> SubResult<bool> {
        if quota < 0 {
            return Err(SubscriptionError::InvalidArgument("quota 不能为负数！"));
        }
        if quota == 0 {
            return Ok(true);
        }
        let n = match &self.db {
            Database::Sqlite(pool) => sqlx::query(SQL_RESERVE_USER)
                .bind(quota)
                .bind(user_id)
                .execute(pool)
                .await?
                .rows_affected(),
            Database::Postgres(pool) => sqlx::query(SQL_RESERVE_USER)
                .bind(quota)
                .bind(user_id)
                .execute(pool)
                .await?
                .rows_affected(),
        };
        Ok(n == 1)
    }

    /// Go `persistUserQuotaDelta`（直写分支，store_quota_reserve.go:18-40）：
    /// 扣减方向要求 `quota + delta >= 0`，加额方向无条件；行必须存在。
    pub async fn persist_user_quota_delta(&self, user_id: i64, delta: i64) -> SubResult<()> {
        let (sql, guarded) = if delta < 0 {
            (
                "UPDATE users SET quota = quota + $1 WHERE id = $2 AND quota + $1 >= 0",
                true,
            )
        } else {
            ("UPDATE users SET quota = quota + $1 WHERE id = $2", false)
        };
        let _ = guarded;
        let n = match &self.db {
            Database::Sqlite(pool) => sqlx::query(sql)
                .bind(delta)
                .bind(user_id)
                .execute(pool)
                .await?
                .rows_affected(),
            Database::Postgres(pool) => sqlx::query(sql)
                .bind(delta)
                .bind(user_id)
                .execute(pool)
                .await?
                .rows_affected(),
        };
        if n != 1 {
            return Err(SubscriptionError::NotFound);
        }
        Ok(())
    }

    /// Go `identity.IncreaseUserQuota`（DB 分支）：`quota += N`，非幂等。
    pub async fn increase_user_quota(&self, user_id: i64, quota: i64) -> SubResult<()> {
        match &self.db {
            Database::Sqlite(pool) => {
                sqlx::query(SQL_INCREASE_USER)
                    .bind(quota)
                    .bind(user_id)
                    .execute(pool)
                    .await?;
            }
            Database::Postgres(pool) => {
                sqlx::query(SQL_INCREASE_USER)
                    .bind(quota)
                    .bind(user_id)
                    .execute(pool)
                    .await?;
            }
        }
        Ok(())
    }

    /// Go `identity.DecreaseUserQuota`（DB 分支）：`quota -= N`（可扣成负数，
    /// 欠费语义）。
    pub async fn decrease_user_quota(&self, user_id: i64, quota: i64) -> SubResult<()> {
        match &self.db {
            Database::Sqlite(pool) => {
                sqlx::query(SQL_DECREASE_USER)
                    .bind(quota)
                    .bind(user_id)
                    .execute(pool)
                    .await?;
            }
            Database::Postgres(pool) => {
                sqlx::query(SQL_DECREASE_USER)
                    .bind(quota)
                    .bind(user_id)
                    .execute(pool)
                    .await?;
            }
        }
        Ok(())
    }

    /// Go `identity.UpdateUserUsedQuotaAndRequestCount`（直写分支）。
    pub async fn update_user_used_quota_and_request_count(
        &self,
        user_id: i64,
        quota: i64,
    ) -> SubResult<()> {
        match &self.db {
            Database::Sqlite(pool) => {
                sqlx::query(SQL_UPDATE_USED_AND_COUNT)
                    .bind(quota)
                    .bind(user_id)
                    .execute(pool)
                    .await?;
            }
            Database::Postgres(pool) => {
                sqlx::query(SQL_UPDATE_USED_AND_COUNT)
                    .bind(quota)
                    .bind(user_id)
                    .execute(pool)
                    .await?;
            }
        }
        Ok(())
    }

    /// Go `catalog.UpdateChannelUsedQuota`。渠道表属 catalog 切片，本函数仅
    /// 服务计费路径的记账写入（与 Go billing 包内调用点一致）。
    pub async fn update_channel_used_quota(&self, channel_id: i64, quota: i64) -> SubResult<()> {
        match &self.db {
            Database::Sqlite(pool) => {
                sqlx::query(SQL_UPDATE_CHANNEL_USED)
                    .bind(quota)
                    .bind(channel_id)
                    .execute(pool)
                    .await?;
            }
            Database::Postgres(pool) => {
                sqlx::query(SQL_UPDATE_CHANNEL_USED)
                    .bind(quota)
                    .bind(channel_id)
                    .execute(pool)
                    .await?;
            }
        }
        Ok(())
    }

    /// Go `TryReserveTokenQuota`（store_quota_reserve.go:115-160）Redis 关闭
    /// 回退分支。unlimited 跳过余额检查但仍走 DecreaseTokenQuota 记账。
    pub async fn try_reserve_token_quota(
        &self,
        token_id: i64,
        quota: i64,
        unlimited: bool,
        now: i64,
    ) -> SubResult<bool> {
        if quota < 0 {
            return Err(SubscriptionError::InvalidArgument("quota 不能为负数！"));
        }
        if quota == 0 {
            return Ok(true);
        }
        if unlimited {
            self.decrease_token_quota(token_id, quota, now).await?;
            return Ok(true);
        }
        let n = match &self.db {
            Database::Sqlite(pool) => sqlx::query(SQL_RESERVE_TOKEN)
                .bind(quota)
                .bind(now)
                .bind(token_id)
                .execute(pool)
                .await?
                .rows_affected(),
            Database::Postgres(pool) => sqlx::query(SQL_RESERVE_TOKEN)
                .bind(quota)
                .bind(now)
                .bind(token_id)
                .execute(pool)
                .await?
                .rows_affected(),
        };
        Ok(n == 1)
    }

    /// Go `persistTokenQuotaDelta`（直写分支）。
    pub async fn persist_token_quota_delta(
        &self,
        token_id: i64,
        delta: i64,
        now: i64,
    ) -> SubResult<()> {
        let n = match &self.db {
            Database::Sqlite(pool) => sqlx::query(SQL_PERSIST_TOKEN_DELTA)
                .bind(delta)
                .bind(now)
                .bind(token_id)
                .execute(pool)
                .await?
                .rows_affected(),
            Database::Postgres(pool) => sqlx::query(SQL_PERSIST_TOKEN_DELTA)
                .bind(delta)
                .bind(now)
                .bind(token_id)
                .execute(pool)
                .await?
                .rows_affected(),
        };
        if n != 1 {
            return Err(SubscriptionError::NotFound);
        }
        Ok(())
    }

    /// Go `identity.increaseTokenQuota`（DB 分支）：remain + N / used - N。
    pub async fn increase_token_quota(&self, token_id: i64, quota: i64, now: i64) -> SubResult<()> {
        match &self.db {
            Database::Sqlite(pool) => {
                sqlx::query(SQL_PERSIST_TOKEN_DELTA)
                    .bind(quota)
                    .bind(now)
                    .bind(token_id)
                    .execute(pool)
                    .await?;
            }
            Database::Postgres(pool) => {
                sqlx::query(SQL_PERSIST_TOKEN_DELTA)
                    .bind(quota)
                    .bind(now)
                    .bind(token_id)
                    .execute(pool)
                    .await?;
            }
        }
        Ok(())
    }

    /// Go `identity.decreaseTokenQuota`（DB 分支）：remain - N / used + N
    /// （无余额条件，unlimited 也不拒绝）。
    pub async fn decrease_token_quota(&self, token_id: i64, quota: i64, now: i64) -> SubResult<()> {
        match &self.db {
            Database::Sqlite(pool) => {
                sqlx::query(SQL_DECREASE_TOKEN)
                    .bind(quota)
                    .bind(now)
                    .bind(token_id)
                    .execute(pool)
                    .await?;
            }
            Database::Postgres(pool) => {
                sqlx::query(SQL_DECREASE_TOKEN)
                    .bind(quota)
                    .bind(now)
                    .bind(token_id)
                    .execute(pool)
                    .await?;
            }
        }
        Ok(())
    }

    /// Go `identity.GetTokenByKey`（DB 分支）；令牌不存在回 None
    /// （Go 返回 gorm.ErrRecordNotFound，由调用方区分）。
    pub async fn get_token_by_key(&self, key: &str) -> SubResult<Option<TokenRow>> {
        let row = match &self.db {
            Database::Sqlite(pool) => sqlx::query(SQL_GET_TOKEN_BY_KEY)
                .bind(key)
                .fetch_optional(pool)
                .await?
                .map(|row| TokenRow {
                    id: row.get::<i64, _>(0),
                    user_id: row.get::<i64, _>(1),
                    key: row.get::<String, _>(2),
                    remain_quota: row.get::<i64, _>(3),
                    unlimited_quota: row.get::<i64, _>(4) != 0,
                    status: row.get::<i64, _>(5),
                }),
            Database::Postgres(pool) => sqlx::query(SQL_GET_TOKEN_BY_KEY)
                .bind(key)
                .fetch_optional(pool)
                .await?
                .map(|row| TokenRow {
                    id: row.get::<i64, _>(0),
                    user_id: row.get::<i64, _>(1),
                    key: row.get::<String, _>(2),
                    remain_quota: row.get::<i64, _>(3),
                    unlimited_quota: row.get::<i64, _>(4) != 0,
                    status: row.get::<i64, _>(5),
                }),
        };
        Ok(row)
    }

    /// Go `HasActiveUserSubscription`（store_subscription.go:724-739）。
    pub async fn has_active_user_subscription(&self, user_id: i64, now: i64) -> SubResult<bool> {
        if user_id <= 0 {
            return Err(SubscriptionError::InvalidArgument("invalid userId"));
        }
        let count: i64 = match &self.db {
            Database::Sqlite(pool) => {
                sqlx::query_scalar(SQL_HAS_ACTIVE_SUB)
                    .bind(user_id)
                    .bind(now)
                    .fetch_one(pool)
                    .await?
            }
            Database::Postgres(pool) => {
                sqlx::query_scalar(SQL_HAS_ACTIVE_SUB)
                    .bind(user_id)
                    .bind(now)
                    .fetch_one(pool)
                    .await?
            }
        };
        Ok(count > 0)
    }

    /// Go `UserActiveSubscriptionsAllowWalletOverflow`（store_subscription.go:741-756）：
    /// 任一活跃订阅 `allow_wallet_overflow = false` 即阻断回退。
    pub async fn active_subscriptions_allow_wallet_overflow(
        &self,
        user_id: i64,
        now: i64,
    ) -> SubResult<bool> {
        if user_id <= 0 {
            return Err(SubscriptionError::InvalidArgument("invalid userId"));
        }
        let count: i64 = match &self.db {
            Database::Sqlite(pool) => {
                sqlx::query_scalar(SQL_STRICT_SUB_COUNT)
                    .bind(user_id)
                    .bind(now)
                    .fetch_one(pool)
                    .await?
            }
            Database::Postgres(pool) => {
                sqlx::query_scalar(SQL_STRICT_SUB_COUNT)
                    .bind(user_id)
                    .bind(now)
                    .fetch_one(pool)
                    .await?
            }
        };
        Ok(count == 0)
    }

    /// Go `PreConsumeUserSubscription`（store_subscription.go:1036-1136）：
    /// 事务内 request_id 幂等重放 -> 活跃订阅（end_time asc, id asc）逐个
    /// 惰性重置 + 余量检查 -> 落记录并累加 used。
    pub async fn pre_consume_user_subscription(
        &self,
        request_id: &str,
        user_id: i64,
        amount: i64,
        now: i64,
    ) -> SubResult<SubscriptionPreConsumeResult> {
        if user_id <= 0 {
            return Err(SubscriptionError::InvalidArgument("invalid userId"));
        }
        if request_id.trim().is_empty() {
            return Err(SubscriptionError::InvalidArgument("requestId is empty"));
        }
        if amount <= 0 {
            return Err(SubscriptionError::InvalidArgument("amount must be > 0"));
        }
        let mut result = SubscriptionPreConsumeResult::default();
        let outcome: Result<(), SubscriptionError> =
            with_tx!(self.db, SqliteTx, PgTx, &SqliteTx, &PgTx, tx, txh, {
                // 1) request_id 幂等重放
                let existing: Option<(i64, i64, String)> = sqlx::query_as(SQL_PRECONSUME_REPLAY)
                    .bind(request_id)
                    .fetch_optional(&mut **tx)
                    .await?;
                if let Some((sub_id, pre_consumed, status)) = existing {
                    if status == "refunded" {
                        return Err(SubscriptionError::AlreadyRefunded);
                    }
                    let row = txh.fetch_sub(tx, sub_id).await?;
                    result.user_subscription_id = sub_id;
                    result.pre_consumed = pre_consumed;
                    result.amount_total = row.amount_total;
                    result.amount_used_before = row.amount_used;
                    result.amount_used_after = row.amount_used;
                    return Ok(());
                }

                // 2) 活跃订阅候选（PG 加 FOR UPDATE；SQLite 单写者事务已互斥）
                let candidates: Vec<(i64, i64, i64, i64)> =
                    txh.sub_candidates(tx, user_id, now).await?;
                if candidates.is_empty() {
                    return Err(SubscriptionError::NoActiveSubscription);
                }
                for (sub_id, plan_id, amount_total, amount_used) in candidates {
                    // Go：候选先跑 maybeResetUserSubscriptionWithPlanTx
                    let (amount_total, amount_used) = txh
                        .maybe_reset(tx, sub_id, plan_id, amount_total, amount_used, now)
                        .await?;
                    let mut used = amount_used;
                    if amount_total > 0 {
                        let remain = amount_total - used;
                        if remain < amount {
                            continue;
                        }
                    }
                    let insert = sqlx::query(SQL_INSERT_PRECONSUME)
                        .bind(request_id)
                        .bind(user_id)
                        .bind(sub_id)
                        .bind(amount)
                        .bind(now)
                        .execute(&mut **tx)
                        .await;
                    if let Err(err) = insert {
                        // 唯一索引冲突 → 幂等重放（Go First(&dup) 分支）
                        let dup: Option<(i64, String)> = sqlx::query_as(SQL_PRECONSUME_DUP)
                            .bind(request_id)
                            .fetch_optional(&mut **tx)
                            .await?;
                        if let Some((dup_sub, dup_status)) = dup {
                            if dup_status == "refunded" {
                                return Err(SubscriptionError::AlreadyRefunded);
                            }
                            let row = txh.fetch_sub(tx, dup_sub).await?;
                            result.user_subscription_id = dup_sub;
                            result.pre_consumed = amount;
                            result.amount_total = row.amount_total;
                            result.amount_used_before = row.amount_used;
                            result.amount_used_after = row.amount_used;
                            return Ok(());
                        }
                        return Err(err.into());
                    }
                    used += amount;
                    sqlx::query(SQL_UPDATE_SUB_USED)
                        .bind(used)
                        .bind(now)
                        .bind(sub_id)
                        .execute(&mut **tx)
                        .await?;
                    result.user_subscription_id = sub_id;
                    result.pre_consumed = amount;
                    result.amount_total = amount_total;
                    result.amount_used_before = amount_used;
                    result.amount_used_after = used;
                    return Ok(());
                }
                Err(SubscriptionError::QuotaInsufficient(amount))
            });
        outcome?;
        Ok(result)
    }

    /// Go `RefundSubscriptionPreConsume`（store_subscription.go:1140-1161）：
    /// request_id 幂等；同事务内加回订阅额度并翻转状态。
    pub async fn refund_subscription_pre_consume(
        &self,
        request_id: &str,
        now: i64,
    ) -> SubResult<()> {
        if request_id.trim().is_empty() {
            return Err(SubscriptionError::InvalidArgument("requestId is empty"));
        }
        let outcome: Result<(), SubscriptionError> =
            with_tx!(self.db, SqliteTx, PgTx, &SqliteTx, &PgTx, tx, txh, {
                let record: Option<(i64, i64, String)> = sqlx::query_as(SQL_PRECONSUME_RECORD)
                    .bind(request_id)
                    .fetch_optional(&mut **tx)
                    .await?;
                let Some((sub_id, pre_consumed, status)) = record else {
                    return Err(SubscriptionError::NotFound);
                };
                if status == "refunded" {
                    return Ok(());
                }
                if pre_consumed <= 0 {
                    sqlx::query(SQL_MARK_REFUNDED)
                        .bind(request_id)
                        .bind(now)
                        .execute(&mut **tx)
                        .await?;
                    return Ok(());
                }
                txh.post_consume_delta(tx, sub_id, -pre_consumed, now)
                    .await?;
                sqlx::query(SQL_MARK_REFUNDED)
                    .bind(request_id)
                    .bind(now)
                    .execute(&mut **tx)
                    .await?;
                Ok(())
            });
        outcome
    }

    /// Go `PostConsumeUserSubscriptionDelta`（store_subscription.go:1224-1233）。
    pub async fn post_consume_user_subscription_delta(
        &self,
        sub_id: i64,
        delta: i64,
        now: i64,
    ) -> SubResult<()> {
        if delta == 0 {
            return Ok(());
        }
        let outcome: Result<(), SubscriptionError> =
            with_tx!(self.db, SqliteTx, PgTx, &SqliteTx, &PgTx, tx, txh, {
                txh.post_consume_delta(tx, sub_id, delta, now).await
            });
        outcome
    }

    /// Go `PostConsumeUserSubscriptionDeltaCapped`（store_subscription.go:1267-1297）：
    /// 交付后补扣，订阅装不下的溢出部分返回给调用方记钱包欠费。
    pub async fn post_consume_user_subscription_delta_capped(
        &self,
        sub_id: i64,
        delta: i64,
        now: i64,
    ) -> SubResult<i64> {
        if sub_id <= 0 {
            return Err(SubscriptionError::InvalidArgument(
                "invalid userSubscriptionId",
            ));
        }
        if delta <= 0 {
            return Err(SubscriptionError::InvalidArgument("delta must be positive"));
        }
        let mut overflow = 0i64;
        let outcome: Result<(), SubscriptionError> =
            with_tx!(self.db, SqliteTx, PgTx, &SqliteTx, &PgTx, tx, txh, {
                let row = txh.fetch_sub_locked(tx, sub_id).await?;
                let mut new_used = row.amount_used + delta;
                if row.amount_total > 0 && new_used > row.amount_total {
                    overflow = new_used - row.amount_total;
                    new_used = row.amount_total;
                }
                sqlx::query(SQL_UPDATE_SUB_USED)
                    .bind(new_used)
                    .bind(now)
                    .bind(sub_id)
                    .execute(&mut **tx)
                    .await?;
                Ok(())
            });
        outcome?;
        Ok(overflow)
    }

    /// Go `GetSubscriptionPlanInfoByUserSubscriptionId`（store_subscription.go:1298-1313；
    /// 进程缓存未移植，直查）。
    pub async fn subscription_plan_info(
        &self,
        sub_id: i64,
    ) -> SubResult<Option<SubscriptionPlanInfo>> {
        if sub_id <= 0 {
            return Err(SubscriptionError::InvalidArgument(
                "invalid userSubscriptionId",
            ));
        }
        let row: Option<(i64, String)> = match &self.db {
            Database::Sqlite(pool) => {
                sqlx::query_as(SQL_PLAN_INFO_BY_SUB)
                    .bind(sub_id)
                    .fetch_optional(pool)
                    .await?
            }
            Database::Postgres(pool) => {
                sqlx::query_as(SQL_PLAN_INFO_BY_SUB)
                    .bind(sub_id)
                    .fetch_optional(pool)
                    .await?
            }
        };
        Ok(row.map(|(plan_id, plan_title)| SubscriptionPlanInfo {
            plan_id,
            plan_title,
        }))
    }
}

/// 事务内共享辅助逻辑。sqlx 0.9 泛型 `R: Row` 取列不可行，按后端各实例化
/// 一份同文本实现；由 [`with_tx!`] 的 `$h` 参数分派。
struct SqliteTx;

impl SqliteTx {
    async fn fetch_sub(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        sub_id: i64,
    ) -> SubResult<SubRow> {
        let row: (i64, i64, i64, i64, i64, i64) = sqlx::query_as(SQL_FETCH_SUB)
            .bind(sub_id)
            .fetch_one(&mut **tx)
            .await?;
        Ok(SubRow {
            amount_total: row.0,
            amount_used: row.1,
            start_time: row.2,
            end_time: row.3,
            last_reset_time: row.4,
            next_reset_time: row.5,
        })
    }

    async fn fetch_sub_locked(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        sub_id: i64,
    ) -> SubResult<SubRow> {
        // SQLite 单写者事务内读即一致快照，无独立行锁语法。
        self.fetch_sub(tx, sub_id).await
    }

    async fn sub_candidates(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        user_id: i64,
        now: i64,
    ) -> SubResult<Vec<(i64, i64, i64, i64)>> {
        let rows: Vec<(i64, i64, i64, i64)> = sqlx::query_as(SQL_SUB_CANDIDATES)
            .bind(user_id)
            .bind(now)
            .fetch_all(&mut **tx)
            .await?;
        Ok(rows)
    }

    /// Go `postConsumeUserSubscriptionDeltaTx`（store_subscription.go:1236-1265）：
    /// 锁行、`newUsed < 0` 钳 0、严格版超总量整笔拒绝。
    async fn post_consume_delta(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        sub_id: i64,
        delta: i64,
        now: i64,
    ) -> SubResult<()> {
        if sub_id <= 0 {
            return Err(SubscriptionError::InvalidArgument(
                "invalid userSubscriptionId",
            ));
        }
        if delta == 0 {
            return Ok(());
        }
        let row = self.fetch_sub_locked(tx, sub_id).await?;
        let mut new_used = row.amount_used + delta;
        if new_used < 0 {
            new_used = 0;
        }
        if row.amount_total > 0 && new_used > row.amount_total {
            return Err(SubscriptionError::Db(format!(
                "subscription used exceeds total, used={} total={}",
                new_used, row.amount_total
            )));
        }
        sqlx::query(SQL_UPDATE_SUB_USED)
            .bind(new_used)
            .bind(now)
            .bind(sub_id)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    /// Go `maybeResetUserSubscriptionWithPlanTx`（store_subscription.go:999-1033）：
    /// 到期（或从未排程）且周期 ≠ never 时按计划推进重置点，越过 now 的
    /// 周期全部归零 used。
    async fn maybe_reset(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        sub_id: i64,
        plan_id: i64,
        amount_total: i64,
        amount_used: i64,
        now: i64,
    ) -> SubResult<(i64, i64)> {
        let row = self.fetch_sub(tx, sub_id).await?;
        if row.next_reset_time > 0 && row.next_reset_time > now {
            return Ok((amount_total, amount_used));
        }
        let plan_row: (String, i64) = sqlx::query_as(SQL_PLAN_FOR_RESET)
            .bind(plan_id)
            .fetch_one(&mut **tx)
            .await?;
        let plan = plan_row_for_reset(&plan_row.0, plan_row.1);
        if period::normalize_reset_period(&plan.quota_reset_period) == "never" {
            return Ok((amount_total, amount_used));
        }
        let mut base = row.last_reset_time;
        if base <= 0 {
            base = row.start_time;
        }
        let mut next = period::calc_next_reset_time(base, &plan, row.end_time);
        let mut advanced = false;
        while next > 0 && next <= now {
            advanced = true;
            base = next;
            next = period::calc_next_reset_time(base, &plan, row.end_time);
        }
        if !advanced {
            if row.next_reset_time == 0 && next > 0 {
                sqlx::query(SQL_UPDATE_SUB_SCHEDULE)
                    .bind(base)
                    .bind(next)
                    .bind(now)
                    .bind(sub_id)
                    .execute(&mut **tx)
                    .await?;
            }
            return Ok((amount_total, amount_used));
        }
        sqlx::query(SQL_UPDATE_SUB_RESET)
            .bind(0i64)
            .bind(base)
            .bind(next)
            .bind(now)
            .bind(sub_id)
            .execute(&mut **tx)
            .await?;
        Ok((amount_total, 0))
    }
}

/// PG 变体：候选 SELECT 与订阅行读取追加 `FOR UPDATE`。
struct PgTx;

impl PgTx {
    async fn fetch_sub(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        sub_id: i64,
    ) -> SubResult<SubRow> {
        let row: (i64, i64, i64, i64, i64, i64) = sqlx::query_as(SQL_FETCH_SUB)
            .bind(sub_id)
            .fetch_one(&mut **tx)
            .await?;
        Ok(SubRow {
            amount_total: row.0,
            amount_used: row.1,
            start_time: row.2,
            end_time: row.3,
            last_reset_time: row.4,
            next_reset_time: row.5,
        })
    }

    async fn fetch_sub_locked(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        sub_id: i64,
    ) -> SubResult<SubRow> {
        let row: (i64, i64, i64, i64, i64, i64) =
            sqlx::query_as(sqlx::AssertSqlSafe(format!("{SQL_FETCH_SUB} FOR UPDATE")))
                .bind(sub_id)
                .fetch_one(&mut **tx)
                .await?;
        Ok(SubRow {
            amount_total: row.0,
            amount_used: row.1,
            start_time: row.2,
            end_time: row.3,
            last_reset_time: row.4,
            next_reset_time: row.5,
        })
    }

    async fn sub_candidates(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        user_id: i64,
        now: i64,
    ) -> SubResult<Vec<(i64, i64, i64, i64)>> {
        let rows: Vec<(i64, i64, i64, i64)> = sqlx::query_as(SQL_SUB_CANDIDATES_LOCK)
            .bind(user_id)
            .bind(now)
            .fetch_all(&mut **tx)
            .await?;
        Ok(rows)
    }

    async fn post_consume_delta(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        sub_id: i64,
        delta: i64,
        now: i64,
    ) -> SubResult<()> {
        if sub_id <= 0 {
            return Err(SubscriptionError::InvalidArgument(
                "invalid userSubscriptionId",
            ));
        }
        if delta == 0 {
            return Ok(());
        }
        let row = self.fetch_sub_locked(tx, sub_id).await?;
        let mut new_used = row.amount_used + delta;
        if new_used < 0 {
            new_used = 0;
        }
        if row.amount_total > 0 && new_used > row.amount_total {
            return Err(SubscriptionError::Db(format!(
                "subscription used exceeds total, used={} total={}",
                new_used, row.amount_total
            )));
        }
        sqlx::query(SQL_UPDATE_SUB_USED)
            .bind(new_used)
            .bind(now)
            .bind(sub_id)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    async fn maybe_reset(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        sub_id: i64,
        plan_id: i64,
        amount_total: i64,
        amount_used: i64,
        now: i64,
    ) -> SubResult<(i64, i64)> {
        let row = self.fetch_sub(tx, sub_id).await?;
        if row.next_reset_time > 0 && row.next_reset_time > now {
            return Ok((amount_total, amount_used));
        }
        let plan_row: (String, i64) = sqlx::query_as(SQL_PLAN_FOR_RESET)
            .bind(plan_id)
            .fetch_one(&mut **tx)
            .await?;
        let plan = plan_row_for_reset(&plan_row.0, plan_row.1);
        if period::normalize_reset_period(&plan.quota_reset_period) == "never" {
            return Ok((amount_total, amount_used));
        }
        let mut base = row.last_reset_time;
        if base <= 0 {
            base = row.start_time;
        }
        let mut next = period::calc_next_reset_time(base, &plan, row.end_time);
        let mut advanced = false;
        while next > 0 && next <= now {
            advanced = true;
            base = next;
            next = period::calc_next_reset_time(base, &plan, row.end_time);
        }
        if !advanced {
            if row.next_reset_time == 0 && next > 0 {
                sqlx::query(SQL_UPDATE_SUB_SCHEDULE)
                    .bind(base)
                    .bind(next)
                    .bind(now)
                    .bind(sub_id)
                    .execute(&mut **tx)
                    .await?;
            }
            return Ok((amount_total, amount_used));
        }
        sqlx::query(SQL_UPDATE_SUB_RESET)
            .bind(0i64)
            .bind(base)
            .bind(next)
            .bind(now)
            .bind(sub_id)
            .execute(&mut **tx)
            .await?;
        Ok((amount_total, 0))
    }
}

fn plan_row_for_reset(period_str: &str, custom_seconds: i64) -> SubscriptionPlanRow {
    SubscriptionPlanRow {
        id: 0,
        title: String::new(),
        subtitle: String::new(),
        price_amount: 0.0,
        currency: String::new(),
        duration_unit: String::new(),
        duration_value: 0,
        custom_seconds: 0,
        enabled: true,
        sort_order: 0,
        allow_balance_pay: None,
        allow_wallet_overflow: None,
        stripe_price_id: String::new(),
        creem_product_id: String::new(),
        waffo_pancake_product_id: String::new(),
        max_purchase_per_user: 0,
        upgrade_group: String::new(),
        downgrade_group: String::new(),
        total_amount: 0,
        quota_reset_period: period_str.to_string(),
        quota_reset_custom_seconds: custom_seconds,
        created_at: 0,
        updated_at: 0,
    }
}
