//! Relay domain: protocol-adjacent policies such as the response cache and
//! channel system prompts. No HTTP or database access lives here.

#![forbid(unsafe_code)]

pub mod channel_prompt;
pub mod response_cache;
