//! Storage access for the checkin read slice.
//!
//! Go references:
//! - `apps/api/internal/billing/store_checkin.go` (`GetUserCheckinRecords`,
//!   `GetUserCheckinStats`, `HasCheckedInToday`)
//! - `apps/api/internal/billing/qq_checkin.go` (`HasQQCheckedInToday`,
//!   `GetUserQQCheckinRecords`)
//! - `apps/api/internal/billing/do_checkin_setting.go` (process defaults)
//! - `apps/api/internal/settings/config.go:163-271` (`updateConfigFromMap`)
//!
//! Both tables carry no `gorm.DeletedAt` (`store_checkin.go:18-24`,
//! `qq_checkin.go:18-26`), so no query filters `deleted_at`.
//!
//! ## Backend split
//!
//! `sqlx::Executor` is not implemented across database kinds, so each backend
//! match arm instantiates [`checkin_stats!`] with its own pool — the same shape
//! as `topup/store.rs`. The fixed statements use `$1`-style placeholders, which
//! both drivers accept (see `topup/store.rs` constants and `self_http.rs`).

use std::collections::BTreeMap;

use newapi_storage::Database;
use sqlx::Row;

use super::CheckinSettings;
use super::datetime::today;
use crate::go_options::{parse_bool, parse_int};

/// Go `store_checkin.go:26-30` `CheckinRecord` 的原始两列；`quota_awarded_display`
/// 由 HTTP 适配层换算（billing 不依赖 identity）。
#[derive(Clone, Debug, PartialEq)]
pub struct CheckinRecord {
    pub checkin_date: String,
    pub quota_awarded: i64,
}

/// Go `GetUserCheckinStats` 返回的 map 字段（`store_checkin.go:308-315`）；
/// 展示值不在本层计算。`total_quota` / `total_checkins` 已是全时段求和，
/// `checkin_count` 是合并后本月记录数。
#[derive(Clone, Debug, PartialEq)]
pub struct CheckinStats {
    pub total_quota: i64,
    pub total_checkins: i64,
    pub checkin_count: i64,
    pub checked_in_today: bool,
    pub records: Vec<CheckinRecord>,
}

/// Go `UserCheckin` 失败时回给客户端的固定文案分类（`store_checkin.go:170-236`）。
/// Go 直接 `errors.New(...)`，这里把同样的分承担当到适配层翻译，SQL 文本不外泄。
///
/// 事务**之前**的预判失败不在这里：`already_checked_today` 直接回
/// `sqlx::Error`，由适配层折叠为 `common.database_error`（仓库既有约定，
/// 见 `admin_twofa_http` / `aff_routes`）。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckinError {
    /// 「今日已签到」——事务内锁行后的重判发现已签。
    AlreadyCheckedToday,
    /// 「签到失败，请稍后重试」——锁行、重判查询、签到插入任一失败。
    RetryLater,
    /// 「签到失败：更新额度出错」——额度 UPDATE 失败。
    QuotaUpdateFailed,
}

pub struct CheckinRepository {
    db: Database,
}

/// Go `checkinSetting` 里本切片读取的选项键（`do_checkin_setting.go:11-26` 的
/// json tag）。`show_bind_code_card` 只被资料页读取，本 crate 不加载。
pub(super) const KEY_ENABLED: &str = "checkin_setting.enabled";
pub(super) const KEY_MIN_QUOTA: &str = "checkin_setting.min_quota";
pub(super) const KEY_MAX_QUOTA: &str = "checkin_setting.max_quota";
pub(super) const KEY_SINGLE_PLATFORM_ONLY: &str = "checkin_setting.single_platform_only";
pub(super) const KEY_REQUIRE_QQ_BOUND: &str = "checkin_setting.require_qq_bound";
pub(super) const OPTION_KEYS: [&str; 5] = [
    KEY_ENABLED,
    KEY_MIN_QUOTA,
    KEY_MAX_QUOTA,
    KEY_SINGLE_PLATFORM_ONLY,
    KEY_REQUIRE_QQ_BOUND,
];

impl CheckinSettings {
    /// Go `ConfigManager.LoadFromDB` 的 `checkin_setting` 分片：缺行保留默认，
    /// 坏行保留默认（`updateConfigFromMap` 的 `continue`），与 topup 的
    /// 「数值解析失败覆盖为 0」语义**不同**，勿照抄。
    pub async fn load(db: &Database) -> Result<Self, sqlx::Error> {
        let rows = load_option_rows(db).await?;
        let mut settings = Self::default();
        for key in OPTION_KEYS {
            if let Some(value) = rows.get(key) {
                apply_option(&mut settings, key, value);
            }
        }
        Ok(settings)
    }
}

/// The placeholder list is spelled per backend because the two drivers do not
/// share a marker for a fixed `IN` list (same split as `quota_display/store.rs`).
async fn load_option_rows(db: &Database) -> Result<BTreeMap<&'static str, String>, sqlx::Error> {
    let rows: Vec<(String, Option<String>)> = match db {
        Database::Sqlite(pool) => {
            sqlx::query_as(
                "SELECT \"key\", \"value\" FROM \"options\" \
                 WHERE \"key\" IN (?, ?, ?, ?, ?)",
            )
            .bind(KEY_ENABLED)
            .bind(KEY_MIN_QUOTA)
            .bind(KEY_MAX_QUOTA)
            .bind(KEY_SINGLE_PLATFORM_ONLY)
            .bind(KEY_REQUIRE_QQ_BOUND)
            .fetch_all(pool)
            .await?
        }
        Database::Postgres(pool) => {
            sqlx::query_as(
                "SELECT \"key\", \"value\" FROM \"options\" \
                 WHERE \"key\" IN ($1, $2, $3, $4, $5)",
            )
            .bind(KEY_ENABLED)
            .bind(KEY_MIN_QUOTA)
            .bind(KEY_MAX_QUOTA)
            .bind(KEY_SINGLE_PLATFORM_ONLY)
            .bind(KEY_REQUIRE_QQ_BOUND)
            .fetch_all(pool)
            .await?
        }
    };
    // Go 的选项应用对 SQL NULL 按空字符串处理；NULL 不是这里的错误分支。
    Ok(rows
        .into_iter()
        .filter_map(|(key, value)| {
            OPTION_KEYS
                .iter()
                .find(|candidate| **candidate == key)
                .map(|candidate| (*candidate, value.unwrap_or_default()))
        })
        .collect())
}

/// Go `updateConfigFromMap` 的 bool / int 分支：解析失败 `continue`，即**保留
/// 当前值**（初次加载即 [`CheckinSettings::default`]）。两个解析器与
/// [`crate::go_options`] 共用，QQ 机器人分片走同一套应用语义。
pub(super) fn apply_option(settings: &mut CheckinSettings, key: &str, value: &str) {
    match key {
        KEY_ENABLED => {
            if let Some(parsed) = parse_bool(value) {
                settings.enabled = parsed;
            }
        }
        KEY_SINGLE_PLATFORM_ONLY => {
            if let Some(parsed) = parse_bool(value) {
                settings.single_platform_only = parsed;
            }
        }
        KEY_REQUIRE_QQ_BOUND => {
            if let Some(parsed) = parse_bool(value) {
                settings.require_qq_bound = parsed;
            }
        }
        KEY_MIN_QUOTA => {
            if let Some(parsed) = parse_int(value) {
                settings.min_quota = parsed;
            }
        }
        KEY_MAX_QUOTA => {
            if let Some(parsed) = parse_int(value) {
                settings.max_quota = parsed;
            }
        }
        _ => {}
    }
}

macro_rules! decode_checkin {
    ($row:expr) => {{
        let row = $row;
        CheckinRecord {
            checkin_date: row.try_get::<String, _>("checkin_date")?,
            quota_awarded: row.try_get::<i64, _>("quota_awarded")?,
        }
    }};
}

/// Go `GetUserCheckinStats` 的整段读取；每个后端用各自的池实例化一次。
///
/// `$pool` 之后依次是 user_id、起止日期（`month-01` / `month-31`）、today 与
/// 单平台开关（调用方从 [`CheckinSettings`] 读入；Go 在函数体内读进程配置，
/// 语义等价——两侧都存在读取与读取之间的配置变化窗口）。
macro_rules! checkin_stats {
    ($pool:expr, $user_id:expr, $start_date:expr, $end_date:expr, $today:expr, $single_platform_only:expr) => {{
        // 显式类型注解同时完成 `&String → &str` 的 deref 强制转换。
        let user_id: i64 = $user_id;
        let start_date: &str = $start_date;
        let end_date: &str = $end_date;
        let today: &str = $today;
        let single_platform_only: bool = $single_platform_only;

        // Go `GetUserCheckinRecords`：本月网页签到，日期降序（字符串）。
        let mut records: Vec<CheckinRecord> = Vec::new();
        for row in sqlx::query(WEB_RECORDS_SQL)
            .bind(user_id)
            .bind(start_date)
            .bind(end_date)
            .fetch_all($pool)
            .await?
        {
            records.push(decode_checkin!(row));
        }

        // 单平台模式下 QQ 记录并入网页日历与统计（`store_checkin.go:268-291`）。
        let mut qq_total_checkins: i64 = 0;
        let mut qq_total_quota: i64 = 0;
        if single_platform_only {
            for row in sqlx::query(QQ_RECORDS_SQL)
                .bind(user_id)
                .bind(start_date)
                .bind(end_date)
                .fetch_all($pool)
                .await?
            {
                records.push(decode_checkin!(row));
            }
            // Go `sort.Slice`：按 checkin_date 降序（字符串比较），两侧各自已有序。
            records.sort_by(|left, right| right.checkin_date.cmp(&left.checkin_date));
            // Go 全时段统计：仅按 user_id，无日期过滤。
            let qq = sqlx::query(QQ_TOTAL_SQL).bind(user_id).fetch_one($pool).await?;
            qq_total_checkins = qq.try_get::<i64, _>(0)?;
            qq_total_quota = qq.try_get::<i64, _>(1)?;
        }

        // Go `HasCheckedInTodayAnyPlatform`：先网页后 QQ，任一命中即 true；
        // 非单平台模式只看网页（`alreadyCheckedToday` 的单渠道分支）。
        let web_today = sqlx::query_scalar::<_, i64>(WEB_TODAY_SQL)
            .bind(user_id)
            .bind(today)
            .fetch_one($pool)
            .await?;
        let mut checked_in_today = web_today > 0;
        if single_platform_only && !checked_in_today {
            let qq_today = sqlx::query_scalar::<_, i64>(QQ_TODAY_SQL)
                .bind(user_id)
                .bind(today)
                .fetch_one($pool)
                .await?;
            checked_in_today = qq_today > 0;
        }

        // Go 全时段统计（`store_checkin.go:305-306`）。
        let web = sqlx::query(WEB_TOTAL_SQL).bind(user_id).fetch_one($pool).await?;
        let total_checkins = web.try_get::<i64, _>(0)?.saturating_add(qq_total_checkins);
        let total_quota = web.try_get::<i64, _>(1)?.saturating_add(qq_total_quota);

        Ok::<CheckinStats, sqlx::Error>(CheckinStats {
            total_quota,
            total_checkins,
            checkin_count: records.len() as i64,
            checked_in_today,
            records,
        })
    }};
}

/// 把一个事务里的「锁行 → 重判 → 插入 → 加额度」展开成两个驱动各自的形式。
/// 语句与占位符都一样，只有 `FOR UPDATE` 与池类型不同，所以按驱动取一次锁语句。
macro_rules! checkin_transaction {
    ($pool:expr, $user_id:expr, $today:expr, $quota_awarded:expr, $created_at:expr,
     $single_platform_only:expr, $row_lock:expr, $lock_sql:expr) => {{
        // 显式类型注解完成 `&String → &str` 的强制转换。
        let user_id: i64 = $user_id;
        let today: &str = $today;
        let quota_awarded: i64 = $quota_awarded;
        let created_at: i64 = $created_at;
        let single_platform_only: bool = $single_platform_only;
        let row_lock: bool = $row_lock;
        let lock_sql: &str = $lock_sql;

        let mut tx = $pool.begin().await.map_err(|_| CheckinError::RetryLater)?;
        let outcome: Result<(), CheckinError> = async {
            // 步骤 1：锁用户行直到事务结束（SQLite 跳过）。Go 用 `Take`，行不存在
            // 即 `ErrRecordNotFound` → "签到失败，请稍后重试"；`fetch_one` 与之
            // 同形，`fetch_optional` 会把 `Ok(None)` 当作成功继续往下走。
            if row_lock {
                if sqlx::query(lock_sql)
                    .bind(user_id)
                    .fetch_one(&mut *tx)
                    .await
                    .is_err()
                {
                    return Err(CheckinError::RetryLater);
                }
            }
            // 步骤 2：锁后重判今日是否已签到。Go 这里调的是 `alreadyCheckedToday`
            // （`store_checkin.go:179` / `:221`），单平台模式下**跨两表**——这一步
            // 才是拦截双发的权威判据：唯一约束只挡同渠道重复，挡不住跨渠道双发。
            let web_today = sqlx::query(WEB_TODAY_SQL)
                .bind(user_id)
                .bind(today)
                .fetch_one(&mut *tx)
                .await;
            let web_today = match web_today {
                Ok(row) => row.try_get::<i64, _>(0).unwrap_or(0),
                Err(_) => return Err(CheckinError::RetryLater),
            };
            if web_today > 0 {
                return Err(CheckinError::AlreadyCheckedToday);
            }
            if single_platform_only {
                let qq_today = sqlx::query(QQ_TODAY_SQL)
                    .bind(user_id)
                    .bind(today)
                    .fetch_one(&mut *tx)
                    .await;
                let qq_today = match qq_today {
                    Ok(row) => row.try_get::<i64, _>(0).unwrap_or(0),
                    Err(_) => return Err(CheckinError::RetryLater),
                };
                if qq_today > 0 {
                    return Err(CheckinError::AlreadyCheckedToday);
                }
            }
            // 步骤 3：创建签到记录。唯一约束 (user_id, checkin_date) 兜底并发重复。
            let inserted = sqlx::query(INSERT_CHECKIN_SQL)
                .bind(user_id)
                .bind(today)
                .bind(quota_awarded)
                .bind(created_at)
                .execute(&mut *tx)
                .await;
            if inserted.is_err() {
                return Err(CheckinError::RetryLater);
            }
            // 步骤 4：在同一个事务内增加额度。
            let incremented = sqlx::query(INCREMENT_QUOTA_SQL)
                .bind(quota_awarded)
                .bind(user_id)
                .execute(&mut *tx)
                .await;
            if incremented.is_err() {
                return Err(CheckinError::QuotaUpdateFailed);
            }
            Ok(())
        }
        .await;
        match outcome {
            Ok(()) => {
                tx.commit().await.map_err(|_| CheckinError::RetryLater)?;
                Ok(())
            }
            Err(error) => {
                // 回滚失败同样只归为重试类：客户端文案不变，日志已在各步骤外。
                let _ = tx.rollback().await;
                Err(error)
            }
        }
    }};
}

impl CheckinRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Go `alreadyCheckedToday(dbx.DB, userId, false)`（`store_checkin.go:76-85`）。
    /// 单平台模式跨两张表：先看 `checkins`，未签再看 `qq_checkins`；非单平台
    /// 模式只读 `checkins`。这是**打开事务前的预判**，真正的拦截在
    /// [`CheckinRepository::checkin`] 内重判。
    pub async fn already_checked_today(
        &self,
        user_id: i64,
        single_platform_only: bool,
    ) -> Result<bool, sqlx::Error> {
        let today = today();
        let web_today = self.count_today(user_id, &today, WEB_TODAY_SQL).await?;
        if web_today || !single_platform_only {
            return Ok(web_today);
        }
        self.count_today(user_id, &today, QQ_TODAY_SQL).await
    }

    /// Go `countTodayCheckin`（`store_checkin.go:58-71`）：COUNT 只回 0/1 之有。
    async fn count_today(
        &self,
        user_id: i64,
        today: &str,
        sql: &'static str,
    ) -> Result<bool, sqlx::Error> {
        let count = match &self.db {
            Database::Sqlite(pool) => {
                sqlx::query_scalar::<_, i64>(sql)
                    .bind(user_id)
                    .bind(today)
                    .fetch_one(pool)
                    .await?
            }
            Database::Postgres(pool) => {
                sqlx::query_scalar::<_, i64>(sql)
                    .bind(user_id)
                    .bind(today)
                    .fetch_one(pool)
                    .await?
            }
        };
        Ok(count > 0)
    }

    /// Go `UserCheckin`（`store_checkin.go:135-247`）：先预判，再在一个事务里
    /// 「锁用户行 → 重判 → 插签到 → 加额度」。
    ///
    /// Go 在 SQLite 上跳过 `lockUserForCheckin`（`dbx.LockForUpdate` 对该库不发
    /// `FOR UPDATE`），PostgreSQL/MySQL 发；MySQL 不在本端支持范围内，因此只有
    /// PostgreSQL 走行锁。两个驱动都保留事务内重判，这是拦截双发的权威判据；
    /// 重判在单平台模式下跨 `checkins` / `qq_checkins` 两表，与预判同一套规则。
    pub async fn checkin(
        &self,
        user_id: i64,
        quota_awarded: i64,
        single_platform_only: bool,
    ) -> Result<(), CheckinError> {
        let today = today();
        let created_at = unix_seconds();
        match &self.db {
            Database::Sqlite(pool) => {
                checkin_transaction!(
                    pool,
                    user_id,
                    &today,
                    quota_awarded,
                    created_at,
                    single_platform_only,
                    false,
                    LOCK_USER_SQLITE
                )
            }
            Database::Postgres(pool) => {
                checkin_transaction!(
                    pool,
                    user_id,
                    &today,
                    quota_awarded,
                    created_at,
                    single_platform_only,
                    true,
                    LOCK_USER_POSTGRES
                )
            }
        }
    }

    /// Go `GetUserCheckinStats(userId, month)`：`month` 只用于拼
    /// `month-01` / `month-31` 的字符串区间（Go 同样不做格式校验，越界文本
    /// 匹配不到任何行）。
    pub async fn user_stats(
        &self,
        user_id: i64,
        month: &str,
        single_platform_only: bool,
    ) -> Result<CheckinStats, sqlx::Error> {
        let start_date = format!("{month}-01");
        let end_date = format!("{month}-31");
        let today = today();
        match &self.db {
            Database::Sqlite(pool) => {
                checkin_stats!(
                    pool,
                    user_id,
                    &start_date,
                    &end_date,
                    &today,
                    single_platform_only
                )
            }
            Database::Postgres(pool) => {
                checkin_stats!(
                    pool,
                    user_id,
                    &start_date,
                    &end_date,
                    &today,
                    single_platform_only
                )
            }
        }
    }
}

/// `$1` 占位符两个驱动都接受（见 `topup/store.rs` 的常量 SQL 与本仓
/// `self_http.rs` 的 SQLite `$1` 直用）。PostgreSQL 的 `SUM(bigint)` 产出
/// `numeric`，sqlx 无法把它解码成 `i64`，因此显式 `CAST` 回 `BIGINT`；
/// SQLite 接受同名 `CAST` 且整列 SUM 本就在 INTEGER 亲和类型内。
const WEB_RECORDS_SQL: &str = "SELECT checkin_date, quota_awarded FROM checkins \
     WHERE user_id = $1 AND checkin_date >= $2 AND checkin_date <= $3 \
     ORDER BY checkin_date DESC";

const QQ_RECORDS_SQL: &str = "SELECT checkin_date, quota_awarded FROM qq_checkins \
     WHERE user_id = $1 AND checkin_date >= $2 AND checkin_date <= $3 \
     ORDER BY checkin_date DESC";

const WEB_TOTAL_SQL: &str = "SELECT COUNT(*), CAST(COALESCE(SUM(quota_awarded), 0) AS BIGINT) \
     FROM checkins WHERE user_id = $1";

const QQ_TOTAL_SQL: &str = "SELECT COUNT(*), CAST(COALESCE(SUM(quota_awarded), 0) AS BIGINT) \
     FROM qq_checkins WHERE user_id = $1";

const WEB_TODAY_SQL: &str =
    "SELECT COUNT(*) FROM checkins WHERE user_id = $1 AND checkin_date = $2";

const QQ_TODAY_SQL: &str =
    "SELECT COUNT(*) FROM qq_checkins WHERE user_id = $1 AND checkin_date = $2";

/// Go `lockUserForCheckin`（`store_checkin.go:161-167`）：把用户行锁到事务结束，
/// 让网页与 QQ 两个并发入口在同一行上串行。`dbx.LockForUpdate` 在 SQLite 上不发
/// `FOR UPDATE`（单写者模型本身串行写），PostgreSQL/MySQL 发。
const LOCK_USER_POSTGRES: &str = "SELECT id FROM users WHERE id = $1 FOR UPDATE";
const LOCK_USER_SQLITE: &str = "SELECT id FROM users WHERE id = $1";

/// Go `tx.Create(checkin)`（`store_checkin.go:190`）：唯一约束
/// (user_id, checkin_date) 是并发重复签到的兜底。`id` 自增，`created_at` 是秒。
const INSERT_CHECKIN_SQL: &str = "INSERT INTO checkins \
     (user_id, checkin_date, quota_awarded, created_at) VALUES ($1, $2, $3, $4)";

/// Go `Update("quota", gorm.Expr("quota + ?", quotaAwarded))`
/// （`store_checkin.go:195-198`）。GORM 的 `Updates` 匹配零行不报错。
const INCREMENT_QUOTA_SQL: &str = "UPDATE users SET quota = quota + $1 WHERE id = $2";

/// Go `time.Now().Unix()`（秒）。
fn unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or_default()
}

/// Go `evaluateDailyCheckin` 的额度区间钳制与随机（`store_checkin.go:111-128`）：
/// 负数下限钳到 0，倒序区间把上限抬到下限，区间相等时不调用随机源。
///
/// Go 用 `math/rand` 全局源，这里用零依赖的 xorshift——两者都不是密码学随机，
/// 复刻的是「落在区间内且随请求变化」这一可观察属性。种子混入时钟纳秒与一个
/// 进程级单调计数器：单靠纳秒不够——实测 `as_nanos()` 在紧密相邻的两次调用里
/// 会出现相同末几位，会让同一进程内的相邻签到拿到同一个额度。
pub fn random_quota(min_quota: i64, max_quota: i64) -> i64 {
    let min_quota = min_quota.max(0);
    let max_quota = max_quota.max(min_quota);
    if max_quota == min_quota {
        return min_quota;
    }
    // `max - min + 1` 在 min=0 / max=i64::MAX 时溢出。Go 的
    // `rand.Intn(n)` 对 `n <= 0` 是 panic；这里 debug 同样 panic、release
    // 则回绕。**故意不加钳制**：钳住会让两侧对同一份非法配置给出不同结果，
    // 而运营真把 interval 配成 i64::MAX 的概率极低。若将来要收紧，应当同时
    // 改 Go 侧（或新增共用的 option 校验），不要单侧钳。
    let span = (max_quota - min_quota + 1) as u64;
    let mut state = random_seed();
    // xorshift64*：零状态、非密码学，但对相邻种子发散得足够快。
    let step = |mut value: u64| {
        value ^= value >> 12;
        value ^= value << 25;
        value ^= value >> 27;
        value.wrapping_mul(0x2545_F491_4F6C_DD1D)
    };
    state = step(state | 1);
    // 多走一步，让仅差一位的种子也落到显著不同的输出。
    let drawn = step(state);
    min_quota.saturating_add((drawn % span) as i64)
}

/// 时钟纳秒 ⊕ 进程级单调计数器。计数器保证同一纳秒内的多次调用仍拿到不同种子。
fn random_seed() -> u64 {
    static TICK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos() as u64)
        .unwrap_or_default();
    let tick = TICK.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    nanos ^ tick.wrapping_mul(0x9E37_79B9_7F4A_7C15)
}
