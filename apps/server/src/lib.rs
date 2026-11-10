//! P1 composition and HTTP boundary; business SQL belongs to catalog.
// `GET /api/status` builds one `json!` literal with 90+ fields, which exceeds
// the default macro recursion limit (serde_json expands per element).
#![recursion_limit = "256"]

pub mod admin_twofa_http;
pub mod aff_http;
pub mod amount_http;
pub mod auth;
pub mod body_bind;
pub mod boundary_mw;
pub mod channel_http;
pub mod checkin_http;
pub mod custom_oauth_http;
pub mod gateway_http;
mod global_limit;
pub mod groups_http;
mod http;
pub mod limit;
pub mod limit_email;
pub mod limit_redis;
mod login_http;
pub mod oauth_bindings_http;
pub mod passkey_http;
pub mod qq_bind_http;
pub mod qqbot;
pub mod readonly_http;
pub mod redemption_http;
pub mod register_http;
pub mod request_lang;
pub mod reset_http;
pub mod self_http;
pub mod setting_http;
pub mod setup_http;
mod state;
pub mod status;
pub mod subscription_http;
pub mod token_http;
pub mod topup_http;
pub mod turnstile;
pub mod twofa_http;
pub mod verification_http;
mod web_limit;

pub use http::{MAX_BODY_BYTES, router};
pub use state::{AppState, RateLimitUnavailable, RateLimiter, reload_loop};

/// Install before startup. The default panic hook prints arbitrary payloads and
/// source context; neither belongs in production logs.
pub fn install_safe_panic_hook() {
    std::panic::set_hook(Box::new(|_| {
        tracing::error!(event = "panic", "internal task failed");
    }));
}

/// Only fixed classifications may cross the logging boundary.
pub fn database_error_class(error: &sqlx::Error) -> &'static str {
    match error {
        sqlx::Error::PoolClosed => "pool_closed",
        sqlx::Error::PoolTimedOut => "pool_timeout",
        sqlx::Error::Database(_) => "database",
        sqlx::Error::Io(_) => "io",
        _ => "database_operation",
    }
}
