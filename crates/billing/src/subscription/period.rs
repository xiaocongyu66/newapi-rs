//! 订阅周期换算：Go `store_subscription.go` 的 `calcPlanEndTime` /
//! `calcNextResetTime` / `NormalizeResetPeriod` 的纯函数移植。
//!
//! 时区语义与 `crates/billing/src/checkin/datetime.rs` 一致：Go 用进程本地
//! 时区对齐日界（`time.Date(..., base.Location())`），Rust std 无本地时区，
//! 读显式偏移（`SUBSCRIPTION_TZ_OFFSET_MINUTES` 优先，其次 Go 部署清单的
//! `TZ` 映射），缺省按 `TZ=Asia/Shanghai` 的 +480 分钟。

use super::store::SubscriptionPlanRow;

/// 缺少可识别偏移时的回退：Go 部署清单统一 `TZ=Asia/Shanghai`。
const FALLBACK_OFFSET_MINUTES: i64 = 480;
const MIN_OFFSET_MINUTES: i64 = -720;
const MAX_OFFSET_MINUTES: i64 = 840;

/// Go 部署清单出现过的 `TZ` 名称 → 偏移；未登记返回 `None`。
fn tz_name_offset(value: &str) -> Option<i64> {
    match value.trim() {
        "Asia/Shanghai" | "Asia/Chongqing" | "Asia/Taipei" => Some(480),
        "" | "UTC" | "Etc/UTC" | "Universal" | "Zulu" => Some(0),
        _ => None,
    }
}

/// 进程本地时区偏移（分钟）。
pub fn tz_offset_minutes() -> i64 {
    if let Ok(raw) = std::env::var("SUBSCRIPTION_TZ_OFFSET_MINUTES")
        && let Ok(minutes) = raw.trim().parse::<i64>()
    {
        return minutes.clamp(MIN_OFFSET_MINUTES, MAX_OFFSET_MINUTES);
    }
    match std::env::var("TZ").as_deref() {
        Ok(value) => tz_name_offset(value).unwrap_or(FALLBACK_OFFSET_MINUTES),
        Err(_) => FALLBACK_OFFSET_MINUTES,
    }
}

/// Howard Hinnant `days_from_civil`：`(年, 月, 日)` → 自 1970-01-01 的天数。
/// 月允许越界（如 13 → 次年 1 月），与 Go `AddDate` 的归一化一致。
pub fn days_from_civil(mut year: i64, mut month: i64, day: i64) -> i64 {
    year += (month - 1).div_euclid(12);
    month = (month - 1).rem_euclid(12) + 1;
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let year_of_era = y - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// `days_from_civil` 的逆运算：天数 → `(年, 月, 日)`。
pub fn civil_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    (year + i64::from(month <= 2), month, day)
}

/// 该月最后一天（Go `AddDate` 的月尾钳制目标）。
fn last_day_of_month(year: i64, month: i64) -> i64 {
    let next = days_from_civil(year, month + 1, 1);
    next - days_from_civil(year, month, 1)
}

/// Go `NormalizeResetPeriod`（`store_subscription.go:342-352`）：修剪后仅
/// 接受 daily/weekly/monthly/custom，其余（含 never、空串）回 `never`。
pub fn normalize_reset_period(period: &str) -> String {
    let trimmed = period.trim();
    match trimmed {
        "daily" | "weekly" | "monthly" | "custom" => trimmed.to_string(),
        _ => "never".to_string(),
    }
}

/// Go `calcPlanEndTime`（`store_subscription.go:321-340`）的错误文案。
pub fn calc_plan_end_time(start: i64, plan: &SubscriptionPlanRow) -> Result<i64, String> {
    if plan.duration_value <= 0 && plan.duration_unit != "custom" {
        return Err("duration_value must be > 0".to_string());
    }
    match plan.duration_unit.as_str() {
        "year" | "month" => {
            // Go `AddDate`：本地时区的民用日历加法，月尾钳制。
            let offset = tz_offset_minutes() * 60;
            let local = start + offset;
            let day = local.div_euclid(86_400);
            let second_of_day = local - day * 86_400;
            let (year, month, day_of_month) = civil_from_days(day);
            let (new_year, new_month) = if plan.duration_unit == "year" {
                (year + i64::from(plan.duration_value), month)
            } else {
                (year, month + i64::from(plan.duration_value))
            };
            let clamped_day = day_of_month.min(last_day_of_month(new_year, new_month));
            Ok(
                (days_from_civil(new_year, new_month, clamped_day) * 86_400 + second_of_day)
                    - offset,
            )
        }
        "day" => Ok(start + i64::from(plan.duration_value) * 86_400),
        "hour" => Ok(start + i64::from(plan.duration_value) * 3_600),
        "custom" => {
            if plan.custom_seconds <= 0 {
                return Err("custom_seconds must be > 0".to_string());
            }
            Ok(start + plan.custom_seconds)
        }
        other => Err(format!("invalid duration_unit: {other}")),
    }
}

/// Go `calcNextResetTime`（`store_subscription.go:354-402`）。`end_unix` 为
/// 订阅结束时间（0 表示未知）；下一个重置点越过结束时间时回 0。
pub fn calc_next_reset_time(base: i64, plan: &SubscriptionPlanRow, end_unix: i64) -> i64 {
    let period = normalize_reset_period(&plan.quota_reset_period);
    if period == "never" {
        return 0;
    }
    let offset = tz_offset_minutes() * 60;
    let next = match period.as_str() {
        "daily" | "weekly" | "monthly" => {
            let local = base + offset;
            let day = local.div_euclid(86_400);
            let next_day = match period.as_str() {
                "daily" => day + 1,
                "weekly" => {
                    // Go：Monday=1..Sunday=7，对齐下一个周一 00:00。
                    let weekday = (day + 4).rem_euclid(7); // 1970-01-01 是周四
                    let weekday = if weekday == 0 { 7 } else { weekday };
                    day + (8 - weekday)
                }
                _ => {
                    let (year, month, _) = civil_from_days(day);
                    days_from_civil(year, month + 1, 1)
                }
            };
            next_day * 86_400 - offset
        }
        "custom" => {
            if plan.quota_reset_custom_seconds <= 0 {
                return 0;
            }
            base + plan.quota_reset_custom_seconds
        }
        _ => return 0,
    };
    if end_unix > 0 && next > end_unix {
        return 0;
    }
    next
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(
        unit: &str,
        value: i32,
        reset: &str,
        custom: i64,
        reset_custom: i64,
    ) -> SubscriptionPlanRow {
        SubscriptionPlanRow {
            id: 1,
            title: String::new(),
            subtitle: String::new(),
            price_amount: 0.0,
            currency: "USD".into(),
            duration_unit: unit.into(),
            duration_value: value,
            custom_seconds: custom,
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
            quota_reset_period: reset.into(),
            quota_reset_custom_seconds: reset_custom,
            created_at: 0,
            updated_at: 0,
        }
    }

    #[test]
    fn days_from_civil_round_trips() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2026, 11, 7), 20_765);
        assert_eq!(civil_from_days(20_765), (2026, 11, 7));
        // 月越界归一化：2026-13-01 = 2027-01-01。
        assert_eq!(days_from_civil(2026, 13, 1), days_from_civil(2027, 1, 1));
    }

    #[test]
    fn plan_end_matches_go_add_date() {
        // 2026-01-31 12:00 UTC + 1 month → 2026-02-28 12:00（UTC 偏移 0 下）。
        let start = days_from_civil(2026, 1, 31) * 86_400 + 43_200;
        let plan = plan("month", 1, "never", 0, 0);
        std::env::set_var("SUBSCRIPTION_TZ_OFFSET_MINUTES", "0");
        assert_eq!(
            calc_plan_end_time(start, &plan).unwrap(),
            days_from_civil(2026, 2, 28) * 86_400 + 43_200
        );
        // +1 year on a leap day: 2024-02-29 → 2025-02-28.
        let start = days_from_civil(2024, 2, 29) * 86_400;
        let plan = plan("year", 1, "never", 0, 0);
        assert_eq!(
            calc_plan_end_time(start, &plan).unwrap(),
            days_from_civil(2025, 2, 28) * 86_400
        );
        // day/hour/custom are absolute additions.
        let plan = plan("day", 30, "never", 0, 0);
        assert_eq!(
            calc_plan_end_time(1_000, &plan).unwrap(),
            1_000 + 30 * 86_400
        );
        let plan = plan("custom", 0, "never", 3_600, 0);
        assert_eq!(calc_plan_end_time(1_000, &plan).unwrap(), 4_600);
        // Invalid units mirror the Go messages.
        let plan = plan("week", 1, "never", 0, 0);
        assert_eq!(
            calc_plan_end_time(0, &plan).unwrap_err(),
            "invalid duration_unit: week"
        );
        let plan = plan("month", 0, "never", 0, 0);
        assert_eq!(
            calc_plan_end_time(0, &plan).unwrap_err(),
            "duration_value must be > 0"
        );
        let plan = plan("custom", 0, "never", 0, 0);
        assert_eq!(
            calc_plan_end_time(0, &plan).unwrap_err(),
            "custom_seconds must be > 0"
        );
    }

    #[test]
    fn next_reset_aligns_like_go() {
        std::env::set_var("SUBSCRIPTION_TZ_OFFSET_MINUTES", "0");
        // 2026-11-07 是周六。daily → 周日 00:00。
        let saturday = days_from_civil(2026, 11, 7) * 86_400 + 100;
        let p = plan("month", 1, "daily", 0, 0);
        assert_eq!(
            calc_next_reset_time(saturday, &p, 0),
            days_from_civil(2026, 11, 8) * 86_400
        );
        // weekly：周六(6) → 下一个周一。
        let p = plan("month", 1, "weekly", 0, 0);
        assert_eq!(
            calc_next_reset_time(saturday, &p, 0),
            days_from_civil(2026, 11, 9) * 86_400
        );
        // weekly：周一 → 下一个周一（7 天后）。
        let monday = days_from_civil(2026, 11, 9) * 86_400;
        assert_eq!(
            calc_next_reset_time(monday, &p, 0),
            days_from_civil(2026, 11, 16) * 86_400
        );
        // monthly：11 月任意时刻 → 12-01 00:00。
        let p = plan("month", 1, "monthly", 0, 0);
        assert_eq!(
            calc_next_reset_time(saturday, &p, 0),
            days_from_civil(2026, 12, 1) * 86_400
        );
        // 越过结束时间 → 0。
        assert_eq!(calc_next_reset_time(saturday, &p, saturday + 1), 0);
        // custom / never。
        let p = plan("month", 1, "custom", 0, 90);
        assert_eq!(calc_next_reset_time(1_000, &p, 0), 1_090);
        let p = plan("month", 1, "never", 0, 0);
        assert_eq!(calc_next_reset_time(1_000, &p, 0), 0);
        assert_eq!(calc_next_reset_time(1_000, &p, 2_000), 0);
    }

    #[test]
    fn reset_period_normalizes_like_go() {
        assert_eq!(normalize_reset_period(" daily "), "daily");
        assert_eq!(normalize_reset_period("never"), "never");
        assert_eq!(normalize_reset_period(""), "never");
        assert_eq!(normalize_reset_period("bogus"), "never");
    }
}
