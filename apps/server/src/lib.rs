//! P1 composition and HTTP boundary; business SQL belongs to catalog.
pub mod auth;
pub mod boundary_mw;
mod http;
pub mod limit;
pub mod limit_redis;
mod login_http;
pub mod request_lang;
mod state;
pub mod turnstile;

pub use http::{MAX_BODY_BYTES, router};
pub use state::{AppState, reload_loop};

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
