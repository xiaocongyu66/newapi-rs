//! 民用日期换算：Go `time.Now()` 的 `YYYY-MM` 月与 `YYYY-MM-DD` 日字符串。
//!
//! Go 用 `time.Now().Format("2006-01")` / `Format("2006-01-02")`
//! （`do_checkin.go:23`、`store_checkin.go:48`），即**进程本地时区**。Go 的
//! 部署清单一致设置 `TZ=Asia/Shanghai`（`deploy/docker-compose.yml:35`、
//! `docker-compose.dev.yml:37`、`deploy/k8s/new-api-master.yaml:54`、
//! `new-api-worker.yaml:91`，`deploy/README.md:78` 有表格说明），因此日界是
//! **UTC+8**，不是 UTC。
//!
//! Rust std 没有本地时区感知的民用日换算，而 `Cargo.lock` 不含
//! `chrono`/`time`（本切片不允许改锁文件），所以这里不解析完整 tzdata，而是
//! 读一个显式偏移：`CHECKIN_TZ_OFFSET_MINUTES` 优先，其次 Go 约定的 `TZ`
//! 常见值，缺省按 Go 部署清单的 +480 分钟。偏移单位是分钟，`now_seconds()`
//! 加偏移后再做 `days_from_civil` 逆运算——与
//! `crates/identity/src/audit.rs`、`crates/identity/src/two_fa/totp.rs` 的
//! 既有做法一致，且不引入日期 crate。

/// 缺少可识别的偏移时，按 Go 部署清单的 `TZ=Asia/Shanghai` 取 +8 小时。
///
/// 即：`TZ` 设成未登记的值（如 `America/New_York`）时回退 +480 而非保守的 0。
/// 理由是 Go 的参考部署只用 `Asia/Shanghai`，回退到 0 会让日界差 8 小时、
/// 比差 11-13 小时更糟；且该分支已打 `tracing::warn!` 留痕。要支持其它时区，
/// 在 [`tz_name_offset`] 里补条目，而不是改这里。
const FALLBACK_OFFSET_MINUTES: i64 = 480;
/// 偏移的合法范围：Go 的 `LoadLocation` 实际只覆盖 UTC-12 到 UTC+14。
const MIN_OFFSET_MINUTES: i64 = -720;
const MAX_OFFSET_MINUTES: i64 = 840;

/// Go `time.Now().Format("2006-01-02")`（进程本地时区，见模块注释）。
pub fn today() -> String {
    let (year, month, day) = civil_from_epoch(now_seconds());
    format!("{year:04}-{month:02}-{day:02}")
}

/// Go `time.Now().Format("2006-01")`（同上）。
pub fn current_month() -> String {
    let (year, month, _) = civil_from_epoch(now_seconds());
    format!("{year:04}-{month:02}")
}

/// Unix 秒，已叠加本地时区偏移；`SystemTime` 早于 epoch 时取 0（退化为 1970，
/// Go 侧不可达）。
fn now_seconds() -> i64 {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    seconds + tz_offset_minutes() * 60
}

/// 本地时区偏移（分钟）。`CHECKIN_TZ_OFFSET_MINUTES` 显式优先，其次按 Go 部署
/// 清单里出现过的 `TZ` 值映射；其它值记一条告警并回退到 +480。
fn tz_offset_minutes() -> i64 {
    if let Ok(raw) = std::env::var("CHECKIN_TZ_OFFSET_MINUTES")
        && let Ok(minutes) = raw.trim().parse::<i64>()
    {
        return minutes.clamp(MIN_OFFSET_MINUTES, MAX_OFFSET_MINUTES);
    }
    match std::env::var("TZ").as_deref() {
        Ok(value) => tz_name_offset(value).unwrap_or_else(|| {
            tracing::warn!(
                event = "checkin_timezone_unrecognized",
                value = value,
                fallback_minutes = FALLBACK_OFFSET_MINUTES,
                "unrecognized TZ value; checkin uses Go's default +8 day boundary"
            );
            FALLBACK_OFFSET_MINUTES
        }),
        Err(_) => FALLBACK_OFFSET_MINUTES,
    }
}

/// Go 部署清单出现过的 `TZ` 名称 → 偏移；未登记返回 `None` 交给调用方告警。
fn tz_name_offset(value: &str) -> Option<i64> {
    match value.trim() {
        // Go 的部署默认（compose / k8s / README 表格一致）。
        "Asia/Shanghai" | "Asia/Chongqing" | "Asia/Taipei" => Some(480),
        // `TZ` 为空串或显式的 UTC 变体都不偏移。
        "" | "UTC" | "Etc/UTC" | "Universal" | "Zulu" => Some(0),
        _ => None,
    }
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

    /// Go 部署设 `TZ=Asia/Shanghai`，日界是 UTC+8：UTC 2026-11-08 16:00 整
    /// 跨到次日（`TZ=Asia/Shanghai go run` 实测确认）。
    #[test]
    fn the_shanghai_day_boundary_matches_go() {
        // 上海日界 = UTC 16:00。`time.Date(2026,11,8,16,0,0,0,UTC).Unix()` = 1794153600，
        // 减一秒是 15:59:59。
        const BOUNDARY: i64 = 1_794_153_600;
        let shanghai = |epoch: i64| civil_from_epoch(epoch + 480 * 60);
        // UTC 2026-11-08 15:59:59 = 上海 23:59:59，仍算 11-08。
        assert_eq!(shanghai(BOUNDARY - 1), (2026, 11, 8));
        // UTC 2026-11-08 16:00:00 = 上海 11-09 00:00:00，已跨日。
        assert_eq!(shanghai(BOUNDARY), (2026, 11, 9));
        // 日界两侧的中段两个方向都要成立。
        assert_eq!(shanghai(BOUNDARY - 8 * 3_600), (2026, 11, 8));
        assert_eq!(shanghai(BOUNDARY + 3_600), (2026, 11, 9));
    }

    /// `TZ` 取 Go 部署清单里出现过的值；其它值回退到 +480。
    #[test]
    fn the_tz_env_var_maps_the_go_deployment_values() {
        assert_eq!(tz_name_offset("Asia/Shanghai"), Some(480));
        assert_eq!(tz_name_offset("Asia/Chongqing"), Some(480));
        assert_eq!(tz_name_offset("Asia/Taipei"), Some(480));
        assert_eq!(tz_name_offset("UTC"), Some(0));
        assert_eq!(tz_name_offset("Etc/UTC"), Some(0));
        // 四周空格与空串都被当作不偏移（`TZ` 在 Go 里为空时 `LoadLocation("")`
        // 返回 UTC）。
        assert_eq!(tz_name_offset("  UTC  "), Some(0));
        assert_eq!(tz_name_offset(""), Some(0));
        // 未登记的时区名：调用方告警并回退，这里不得猜一个偏移。
        assert_eq!(tz_name_offset("America/New_York"), None);
        assert_eq!(tz_name_offset("Local"), None);
    }

    /// 偏移来源的优先级与钳制，用纯函数复刻 `tz_offset_minutes` 的两条规则，
    /// 不碰进程环境变量（并行 `#[test]` 共享同一份环境，`set_var` 会互相干扰）。
    #[test]
    fn explicit_offset_parsing_matches_the_env_var_rule() {
        let parse = |raw: &str| raw.trim().parse::<i64>().ok();
        assert_eq!(parse("480").map(|m| m.clamp(-720, 840)), Some(480));
        assert_eq!(parse("330").map(|m| m.clamp(-720, 840)), Some(330));
        assert_eq!(parse("0").map(|m| m.clamp(-720, 840)), Some(0));
        assert_eq!(parse("abc"), None);
        // 超出 ±14h 被钳住，而不是照单全收。
        assert_eq!(parse("9999").map(|m| m.clamp(-720, 840)), Some(840));
        assert_eq!(parse("-9999").map(|m| m.clamp(-720, 840)), Some(-720));
    }
}
