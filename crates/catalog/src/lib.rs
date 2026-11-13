//! Catalog domain: channels, models, groups, and public option snapshots.
//! Relay policies live in `newapi-relay`; billing rules live in
//! `newapi-billing`.

#![forbid(unsafe_code)]

pub mod abilities;
pub mod affinity;
pub mod auth_settings;
pub mod channels;
pub mod email_settings;
pub mod gateway_revision;
pub mod group_settings;
pub mod models;
pub mod outbox_publisher;
pub mod public_config;
pub mod registration_settings;

pub use auth_settings::AuthSettings;
pub use public_config::PublicConfig;
