//! Single-node in-memory response cache. Ported from the upstream Go behavior:
//! opt-in, deterministic non-streaming requests only, keyed by
//! `sha256(model || 0x00 || canonical_request_json)`.

mod config;
mod eligibility;
mod facade;
mod key;
mod options;
mod store;

pub use config::{
    Config, DEFAULT_ENABLED, DEFAULT_MAX_BODY_SIZE, DEFAULT_MAX_ENTRIES, DEFAULT_TTL_SECONDS,
};
pub use eligibility::{Eligibility, eligible};
pub use facade::{
    SettleKind, response_cache_build_key, response_cache_eligible, response_cache_settle_kind,
};
pub use key::key;
pub use options::{
    ENABLED_OPTION, MAX_BODY_SIZE_OPTION, MAX_ENTRIES_OPTION, OptionError, TTL_SECONDS_OPTION,
    apply_option, validate_option,
};
pub use store::{
    Payload, Stats, clear, config, get, put, record_hit, record_miss, set_config, stats,
};

#[cfg(test)]
mod tests;
