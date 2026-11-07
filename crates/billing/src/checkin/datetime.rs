//! 民用日期换算：Go `time.Now()` 的 `YYYY-MM` 月与 `YYYY-MM-DD` 日字符串。
//!
//! Go 用 `time.Now().Format("2006-01")` / `Format("2006-01-02")`
//! （`do_checkin.go:23`、`store_checkin.go:48`），即**进程本地时区**；服务的
//! 容器镜像不设 `TZ`，本地时区即 UTC。`Cargo.lock` 没有 `chrono`/`time`
//! （本切片不允许改锁文件），因此这里用 `std::time::SystemTime` 取 Unix 秒后，
//! 按 Howard Hinnant `days_from_civil` 的逆运算转 UTC 民用日期——与
//! `crates/identity/src/audit.rs`、`crates/identity/src/two_fa/totp.rs` 的
//! 既有做法一致，不引入日期 crate。

/// Go `time.Now().Format("2006-01-02")`（UTC）。
pub fn today() -> String {
    let (year, month, day) = civil_from_epoch(now_seconds());
    format!("{year:04}-{month:02}-{day:02}")
}

/// Go `time.Now().Format("2006-01")`（UTC）。
pub fn current_month() -> String {
    let (year, month, _) = civil_from_epoch(now_seconds());
    format!("{year:04}-{month:02}")
}

/// Unix 秒；`SystemTime` 早于 epoch 时取 0（退化为 1970，Go 侧不可达）。
fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn civil_from_epoch(epoch: i64) -> (i64, i64, i64) {
    civil_from_days(epoch.div_euclid(86_400))
}

/// Howard Hinnant `days_from_civil` 的逆运算：返回 `(年, 月, 日)`。
fn civil_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchors_match_known_civil_dates() {
        // 1970-01-01 00:00:00 UTC。
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // 2026-01-01 = 1767225600（以 2020-01-01 = 1577836800 与闰年推算）。
        assert_eq!(civil_from_epoch(1_767_225_600), (2026, 1, 1));
        // 2026-11-07 00:00:00 UTC = 1794009600。
        assert_eq!(civil_from_epoch(1_794_009_600), (2026, 11, 7));
        // 2000-02-29：闰日必须仍然成立。
        assert_eq!(civil_from_epoch(951_782_400), (2000, 2, 29));
    }

    #[test]
    fn the_day_boundary_uses_floor_division() {
        // 2026-11-07 23:59:59 UTC 仍是 11-07。
        assert_eq!(civil_from_epoch(1_794_009_600 + 86_399), (2026, 11, 7));
        // epoch 前一天的负秒数向下取整到 1969-12-31。
        assert_eq!(civil_from_epoch(-1), (1969, 12, 31));
    }

    #[test]
    fn month_and_day_are_zero_padded() {
        // 格式化路径本身：2026-01-05、2026-11-07。
        let (year, month, day) = civil_from_epoch(1_794_009_600 - 306 * 86_400);
        assert_eq!((year, month, day), (2026, 1, 5));
        assert_eq!(format!("{year:04}-{month:02}"), "2026-01");
        assert_eq!(format!("{year:04}-{month:02}-{day:02}"), "2026-01-05");
    }
}
