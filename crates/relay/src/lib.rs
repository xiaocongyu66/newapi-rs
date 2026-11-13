//! Relay domain: protocol-adjacent policies such as the response cache and
//! channel system prompts. No HTTP or database access lives here.

#![forbid(unsafe_code)]

pub mod adaptor;
pub mod adaptor_common;
pub mod adaptors;
pub mod channel_prompt;
pub mod classify_billing;
pub mod client_ban;
pub mod insight_client;
pub mod normalize_relay_values;
pub mod param_override;
pub mod relay_info;
pub mod relay_mode;
pub mod response_cache;
