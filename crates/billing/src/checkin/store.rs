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

pub struct CheckinRepository {
    db: Database,
}

/// Go `checkinSetting` 里本切片读取的四个选项键（`do_checkin_setting.go:11-26`
/// 的 json tag）；`require_qq_bound` / `show_bind_code_card` 只影响 POST 与
/// 资料页，`GetCheckinStatus` 不读。
pub(super) const KEY_ENABLED: &str = "checkin_setting.enabled";
pub(super) const KEY_MIN_QUOTA: &str = "checkin_setting.min_quota";
pub(super) const KEY_MAX_QUOTA: &str = "checkin_setting.max_quota";
pub(super) const KEY_SINGLE_PLATFORM_ONLY: &str = "checkin_setting.single_platform_only";
pub(super) const OPTION_KEYS: [&str; 4] = [
    KEY_ENABLED,
    KEY_MIN_QUOTA,
    KEY_MAX_QUOTA,
    KEY_SINGLE_PLATFORM_ONLY,
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
                 WHERE \"key\" IN (?, ?, ?, ?)",
            )
            .bind(KEY_ENABLED)
            .bind(KEY_MIN_QUOTA)
            .bind(KEY_MAX_QUOTA)
            .bind(KEY_SINGLE_PLATFORM_ONLY)
            .fetch_all(pool)
            .await?
        }
        Database::Postgres(pool) => {
            sqlx::query_as(
                "SELECT \"key\", \"value\" FROM \"options\" \
                 WHERE \"key\" IN ($1, $2, $3, $4)",
            )
            .bind(KEY_ENABLED)
            .bind(KEY_MIN_QUOTA)
            .bind(KEY_MAX_QUOTA)
            .bind(KEY_SINGLE_PLATFORM_ONLY)
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
/// 当前值**（初次加载即 [`CheckinSettings::default`]）。
pub(super) fn apply_option(settings: &mut CheckinSettings, key: &str, value: &str) {
    match key {
        KEY_ENABLED => {
            if let Some(parsed) = parse_go_bool(value) {
                settings.enabled = parsed;
            }
        }
        KEY_SINGLE_PLATFORM_ONLY => {
            if let Some(parsed) = parse_go_bool(value) {
                settings.single_platform_only = parsed;
            }
        }
        KEY_MIN_QUOTA => {
            if let Some(parsed) = parse_go_int(value) {
                settings.min_quota = parsed;
            }
        }
        KEY_MAX_QUOTA => {
            if let Some(parsed) = parse_go_int(value) {
                settings.max_quota = parsed;
            }
        }
        _ => {}
    }
}

/// Go `strconv.ParseBool` 的接受集合；集合外一律视为解析失败。
fn parse_go_bool(value: &str) -> Option<bool> {
    match value {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

/// Go `strconv.ParseInt(v, 10, 64)`，失败退回 `strconv.ParseFloat` 再截断
/// （`config.go:210-220`）；两者都失败保留当前值。非有限的浮点文本（`NaN`/
/// `Inf`）Go 的 `int64(float64)` 是未定义转换，这里按 Rust `as` 的饱和语义
/// （NaN → 0），真实配置行不会出现。
fn parse_go_int(value: &str) -> Option<i64> {
    value
        .parse::<i64>()
        .ok()
        .or_else(|| value.parse::<f64>().ok().map(|float| float as i64))
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

impl CheckinRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
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
