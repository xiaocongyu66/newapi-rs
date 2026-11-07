//! Checkin read slice: `GET /api/user/checkin` → Go `billing.GetCheckinStatus`.
//!
//! Go references:
//! - `apps/api/internal/billing/do_checkin.go:15-45` (`GetCheckinStatus`)
//! - `apps/api/internal/billing/store_checkin.go:250-316`
//!   (`GetUserCheckinStats`)
//! - `apps/api/internal/billing/qq_checkin.go:43-62`
//!   (`HasCheckedInTodayAnyPlatform`, `GetUserQQCheckinRecords`)
//! - `apps/api/internal/billing/do_checkin_setting.go:29-36` (process defaults)
//! - `apps/api/internal/settings/config.go:163-271` (`updateConfigFromMap`:
//!   bool `ParseBool` / int `ParseInt`→`ParseFloat`, failure **keeps** the
//!   current value — unlike the top-up store's zero-overwrite semantics)
//!
//! ## Scope
//!
//! Read-only: the POST check-in action (`DoCheckin`) is a later slice. Both
//! tables (`checkins`, `qq_checkins`) have no `gorm.DeletedAt`, so no query
//! here filters `deleted_at`. Month strings are used verbatim in the Go
//! range predicates (`month + "-01"` / `month + "-31"`); Go never validates
//! the format, and neither does this slice.
//!
//! JSON serialization of the HTTP shape (including the display currency
//! rendering through `newapi_identity::self_user::QuotaDisplaySettings`)
//! belongs to the server adapter; this crate does not depend on identity.

mod datetime;
mod store;

pub use datetime::{current_month, today};
pub use store::{CheckinRecord, CheckinRepository, CheckinStats};

/// Go `billing.CheckinSetting` 中本切片读取的字段；缺省与
/// `do_checkin_setting.go:29-36` 逐字一致。`require_qq_bound` 与
/// `show_bind_code_card` 只被 POST 与资料页读取，此处不加载。
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CheckinSettings {
    pub enabled: bool,
    pub min_quota: i64,
    pub max_quota: i64,
    /// 缺省 true：网页与 QQ 任一渠道签过即算今日已签到，统计与判定跨两表。
    pub single_platform_only: bool,
}

impl Default for CheckinSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            min_quota: 1_000,
            max_quota: 10_000,
            single_platform_only: true,
        }
    }
}

#[cfg(test)]
mod tests;
