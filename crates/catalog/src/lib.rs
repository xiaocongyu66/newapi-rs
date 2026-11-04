//! Catalog domain: channels, models, groups, and public option snapshots.
//! Relay policies live in `newapi-relay`; billing rules live in
//! `newapi-billing`.

#![forbid(unsafe_code)]

pub mod public_config;

pub use public_config::PublicConfig;
