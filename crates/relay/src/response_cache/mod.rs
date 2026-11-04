//! Single-node in-memory response cache. Ported from the upstream Go behavior:
//! opt-in, deterministic non-streaming requests only, keyed by
//! `sha256(model || 0x00 || canonical_request_json)`.

mod config;
mod key;
mod store;

pub use config::{
    Config, DEFAULT_ENABLED, DEFAULT_MAX_BODY_SIZE, DEFAULT_MAX_ENTRIES, DEFAULT_TTL_SECONDS,
};
pub use key::key;
pub use store::{
    Payload, Stats, clear, config, get, put, record_hit, record_miss, set_config, stats,
};

#[cfg(test)]
mod tests;
