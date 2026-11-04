use std::time::Duration;

pub const DEFAULT_ENABLED: bool = false;
pub const DEFAULT_TTL_SECONDS: i64 = 300;
pub const DEFAULT_MAX_ENTRIES: i64 = 1_000;
pub const DEFAULT_MAX_BODY_SIZE: i64 = 256 * 1024;

/// Raw runtime configuration, mirroring the upstream option-backed values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    pub enabled: bool,
    pub ttl_seconds: i64,
    pub max_entries: i64,
    /// Zero disables the body-size bound; negative values fall back to the
    /// default, matching the upstream normalisation.
    pub max_body_size: i64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: DEFAULT_ENABLED,
            ttl_seconds: DEFAULT_TTL_SECONDS,
            max_entries: DEFAULT_MAX_ENTRIES,
            max_body_size: DEFAULT_MAX_BODY_SIZE,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ConfigSnapshot {
    pub enabled: bool,
    pub ttl: Duration,
    pub max_entries: usize,
    pub max_body_size: i64,
}

impl ConfigSnapshot {
    /// Non-positive TTL/entry caps and negative body caps fall back to the
    /// upstream defaults instead of disabling the cache silently.
    pub fn from_raw(next: Config) -> Self {
        let default = Config::default();
        let ttl_seconds = if next.ttl_seconds <= 0 {
            default.ttl_seconds
        } else {
            next.ttl_seconds
        };
        let max_entries = if next.max_entries <= 0 {
            default.max_entries
        } else {
            next.max_entries
        };
        let max_body_size = if next.max_body_size < 0 {
            default.max_body_size
        } else {
            next.max_body_size
        };
        Self {
            enabled: next.enabled,
            ttl: Duration::from_secs(ttl_seconds as u64),
            max_entries: usize::try_from(max_entries).unwrap_or(usize::MAX),
            max_body_size,
        }
    }
}
