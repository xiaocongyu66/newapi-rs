//! Billing domain. This crate owns billing semantics, including the legacy
//! option migration rules; it does not own the catalog's options storage
//! table, which is accessed through the shared storage connection.

#![forbid(unsafe_code)]

pub mod billing_options;
pub mod billing_session;
pub mod checkin;
mod go_options;
pub mod qq_bot;
pub mod quota_display;
pub mod redemption;
pub mod subscription;
pub mod topup;
