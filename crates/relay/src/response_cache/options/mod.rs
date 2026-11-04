//! Option-system wiring for the response cache. These rules mirror the
//! upstream settings package: the enable flag is the exact string `"true"`,
//! numeric knobs use `Atoi` semantics (invalid input becomes 0), and the
//! save-time validator only accepts non-negative integers.

use super::Config;

pub const ENABLED_OPTION: &str = "ResponseCacheEnabled";
pub const TTL_SECONDS_OPTION: &str = "ResponseCacheTtlSeconds";
pub const MAX_ENTRIES_OPTION: &str = "ResponseCacheMaxEntries";
pub const MAX_BODY_SIZE_OPTION: &str = "ResponseCacheMaxBodySize";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OptionError;

impl std::fmt::Display for OptionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("response cache option must be a non-negative integer")
    }
}

impl std::error::Error for OptionError {}

fn atoi(value: &str) -> i64 {
    value.parse().unwrap_or(0)
}

/// Save-time validation. Unknown keys are not this module's concern.
pub fn validate_option(key: &str, value: &str) -> Result<(), OptionError> {
    match key {
        TTL_SECONDS_OPTION | MAX_ENTRIES_OPTION | MAX_BODY_SIZE_OPTION => {
            match value.parse::<i64>() {
                Ok(number) if number >= 0 => Ok(()),
                _ => Err(OptionError),
            }
        }
        _ => Ok(()),
    }
}

/// Apply one hot-reloaded option. Unknown keys are ignored, matching the
/// upstream `ApplyOption` fallthrough.
pub fn apply_option(config: &mut Config, key: &str, value: &str) {
    match key {
        ENABLED_OPTION => config.enabled = value == "true",
        TTL_SECONDS_OPTION => config.ttl_seconds = atoi(value),
        MAX_ENTRIES_OPTION => config.max_entries = atoi(value),
        MAX_BODY_SIZE_OPTION => config.max_body_size = atoi(value),
        _ => {}
    }
}

#[cfg(test)]
mod tests;
