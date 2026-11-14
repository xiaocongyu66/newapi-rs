//! Monitor settings ported from Go
//! `apps/api/internal/ops/configure_monitor_setting.go`.
//!
//! Contract (oracle `/root/newapi`, read-only):
//! - `MonitorSetting` (`configure_monitor_setting.go:9-13`): three fields with
//!   json tags `auto_test_channel_enabled` / `auto_test_channel_minutes` /
//!   `channel_test_mode`; registered as `monitor_setting` (`:30`).
//! - Process defaults (`:22-26`): disabled, 10 minutes, `scheduled_all`.
//! - `GetMonitorSetting` (`:33-54`): the `CHANNEL_TEST_FREQUENCY` env var, when
//!   present and a positive integer, force-enables scheduled testing at that
//!   period; `CHANNEL_TEST_ENABLED` (when present and a valid
//!   `strconv.ParseBool` value) overrides the switch; an invalid
//!   `channel_test_mode` snaps back to `scheduled_all`.
//! - `UpdateAndSync`-style option loads go through the settings registry's
//!   `updateConfigFromMap`: bool via `strconv.ParseBool`, float via
//!   `ParseInt`→`ParseFloat`, failure **keeps** the current value
//!   (`settings/config.go:163-271`).
//!
//! The consumers (the scheduled channel-test runner and its auto-ban /
//! passive-recovery modes) belong to the catalog health slice; this module
//! fixes the settings contract they will read.

use newapi_storage::Database;

/// Go `ops.ChannelTestMode*` constants (`configure_monitor_setting.go:15-19`).
pub const CHANNEL_TEST_MODE_SCHEDULED_ALL: &str = "scheduled_all";
pub const CHANNEL_TEST_MODE_AUTO_BAN_ONLY: &str = "auto_ban_only";
pub const CHANNEL_TEST_MODE_PASSIVE_RECOVERY: &str = "passive_recovery";

/// Option keys of the registered `monitor_setting` (json tags).
pub const MONITOR_AUTO_TEST_ENABLED_OPTION: &str = "monitor_setting.auto_test_channel_enabled";
pub const MONITOR_AUTO_TEST_MINUTES_OPTION: &str = "monitor_setting.auto_test_channel_minutes";
pub const MONITOR_CHANNEL_TEST_MODE_OPTION: &str = "monitor_setting.channel_test_mode";

/// Go `ops.MonitorSetting` (`configure_monitor_setting.go:9-13`) with the
/// process defaults of `:22-26`.
#[derive(Clone, Debug, PartialEq)]
pub struct MonitorSetting {
    pub auto_test_channel_enabled: bool,
    pub auto_test_channel_minutes: f64,
    pub channel_test_mode: String,
}

impl Default for MonitorSetting {
    fn default() -> Self {
        Self {
            auto_test_channel_enabled: false,
            auto_test_channel_minutes: 10.0,
            channel_test_mode: CHANNEL_TEST_MODE_SCHEDULED_ALL.to_owned(),
        }
    }
}

impl MonitorSetting {
    /// Go `GetMonitorSetting` (`configure_monitor_setting.go:33-54`) minus the
    /// in-place mutation: env overrides apply on top of the loaded values and
    /// an unknown mode snaps back to `scheduled_all`.
    pub fn with_env_overrides(
        mut self,
        channel_test_frequency: Option<&str>,
        channel_test_enabled: Option<&str>,
    ) -> Self {
        if let Some(frequency) = channel_test_frequency
            && let Ok(frequency) = frequency.parse::<i64>()
            && frequency > 0
        {
            self.auto_test_channel_enabled = true;
            self.auto_test_channel_minutes = frequency as f64;
            self.channel_test_mode = CHANNEL_TEST_MODE_SCHEDULED_ALL.to_owned();
        }
        if let Some(enabled) = channel_test_enabled
            && let Ok(parsed) = parse_strconv_bool(enabled)
        {
            self.auto_test_channel_enabled = parsed;
        }
        if !matches!(
            self.channel_test_mode.as_str(),
            CHANNEL_TEST_MODE_AUTO_BAN_ONLY | CHANNEL_TEST_MODE_PASSIVE_RECOVERY
        ) {
            self.channel_test_mode = CHANNEL_TEST_MODE_SCHEDULED_ALL.to_owned();
        }
        self
    }
}

/// Go `strconv.ParseBool`'s exact accepted spellings (no trimming — Go parses
/// the raw env var / option value); the settings registry's bool loader keeps
/// the current value on any other spelling.
fn parse_strconv_bool(value: &str) -> Result<bool, std::str::ParseBoolError> {
    value.parse()
}

async fn read_option(db: &Database, key: &str) -> Option<String> {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query_scalar::<_, String>("SELECT value FROM options WHERE \"key\" = ?")
                .bind(key)
                .fetch_optional(pool)
                .await
                .ok()
                .flatten()
        }
        Database::Postgres(pool) => {
            sqlx::query_scalar::<_, String>("SELECT value FROM options WHERE \"key\" = $1")
                .bind(key)
                .fetch_optional(pool)
                .await
                .ok()
                .flatten()
        }
    }
}

/// Loads the three option rows with `updateConfigFromMap` semantics: a failed
/// parse keeps the current value; missing rows likewise. Environment
/// overrides are the caller's job (`GetMonitorSetting` reads them live).
pub async fn load_monitor_setting(db: &Database) -> MonitorSetting {
    let mut setting = MonitorSetting::default();
    if let Some(raw) = read_option(db, MONITOR_AUTO_TEST_ENABLED_OPTION).await
        && let Ok(parsed) = parse_strconv_bool(&raw)
    {
        setting.auto_test_channel_enabled = parsed;
    }
    if let Some(raw) = read_option(db, MONITOR_AUTO_TEST_MINUTES_OPTION).await {
        // Go: ParseInt→ParseFloat, failure keeps the current value.
        if let Ok(minutes) = raw.trim().parse::<f64>() {
            setting.auto_test_channel_minutes = minutes;
        }
    }
    if let Some(raw) = read_option(db, MONITOR_CHANNEL_TEST_MODE_OPTION).await
        && matches!(
            raw.trim(),
            CHANNEL_TEST_MODE_AUTO_BAN_ONLY
                | CHANNEL_TEST_MODE_PASSIVE_RECOVERY
                | CHANNEL_TEST_MODE_SCHEDULED_ALL
        )
    {
        setting.channel_test_mode = raw.trim().to_owned();
    }
    setting
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_configure_monitor_setting_go() {
        let setting = MonitorSetting::default();
        assert!(!setting.auto_test_channel_enabled);
        assert!((setting.auto_test_channel_minutes - 10.0).abs() < 1e-9);
        assert_eq!(setting.channel_test_mode, CHANNEL_TEST_MODE_SCHEDULED_ALL);
        assert_eq!(CHANNEL_TEST_MODE_AUTO_BAN_ONLY, "auto_ban_only");
        assert_eq!(CHANNEL_TEST_MODE_PASSIVE_RECOVERY, "passive_recovery");
    }

    #[test]
    fn env_overrides_follow_get_monitor_setting() {
        let base = MonitorSetting::default();
        // CHANNEL_TEST_FREQUENCY=5 force-enables scheduled_all at 5 minutes.
        let overridden = base.clone().with_env_overrides(Some("5"), None);
        assert!(overridden.auto_test_channel_enabled);
        assert!((overridden.auto_test_channel_minutes - 5.0).abs() < 1e-9);
        assert_eq!(
            overridden.channel_test_mode,
            CHANNEL_TEST_MODE_SCHEDULED_ALL
        );
        // A non-positive or unparseable frequency is ignored.
        let ignored = base.clone().with_env_overrides(Some("0"), None);
        assert!(!ignored.auto_test_channel_enabled);
        let ignored = base.clone().with_env_overrides(Some("abc"), None);
        assert!(!ignored.auto_test_channel_enabled);
        // CHANNEL_TEST_ENABLED overrides the switch after the frequency arm.
        let disabled = base.clone().with_env_overrides(Some("5"), Some("false"));
        assert!(!disabled.auto_test_channel_enabled);
        assert!((disabled.auto_test_channel_minutes - 5.0).abs() < 1e-9);
        // ParseBool spellings accepted; invalid spellings ignored.
        let enabled = base.clone().with_env_overrides(None, Some("1"));
        assert!(enabled.auto_test_channel_enabled);
        let kept = base.clone().with_env_overrides(None, Some("yes"));
        assert!(!kept.auto_test_channel_enabled);
        // Invalid mode snaps back to scheduled_all; valid ones survive.
        let snapped = base
            .clone()
            .with_env_overrides(None, None)
            .with_env_overrides(None, None);
        assert_eq!(snapped.channel_test_mode, CHANNEL_TEST_MODE_SCHEDULED_ALL);
        let kept_mode = MonitorSetting {
            channel_test_mode: CHANNEL_TEST_MODE_PASSIVE_RECOVERY.to_owned(),
            ..base.clone()
        }
        .with_env_overrides(None, None);
        assert_eq!(
            kept_mode.channel_test_mode,
            CHANNEL_TEST_MODE_PASSIVE_RECOVERY
        );
    }
}
