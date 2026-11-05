//! Authentication option snapshot.
//!
//! Unlike [`crate::public_config::PublicConfig`] this snapshot carries a
//! credential (`TurnstileSecretKey`), so it deliberately does not implement
//! `Serialize`, and its custom `Debug` redacts the secret. Nothing here reads
//! the database per HTTP request; [`AuthSettings::load`] is called by the
//! owner of the runtime snapshot.

use std::fmt;

use newapi_storage::Database;

mod store;

/// Typed view of the options used by login, registration, and password reset.
///
/// Defaults mirror the Go runtime defaults seeded before any persisted row is
/// applied.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthSettings {
    pub password_login_enabled: bool,
    pub password_register_enabled: bool,
    pub email_verification_enabled: bool,
    pub turnstile_check_enabled: bool,
    pub register_enabled: bool,
    pub turnstile_site_key: String,
    pub turnstile_secret_key: String,
}

impl Default for AuthSettings {
    fn default() -> Self {
        // Go: internal/common/constants.go:64-72 and
        // internal/settings/settings.go:242-243.
        Self {
            password_login_enabled: true,
            password_register_enabled: true,
            email_verification_enabled: false,
            turnstile_check_enabled: false,
            register_enabled: true,
            turnstile_site_key: String::new(),
            turnstile_secret_key: String::new(),
        }
    }
}

impl fmt::Debug for AuthSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The Turnstile secret must never reach logs through a derived Debug.
        f.debug_struct("AuthSettings")
            .field("password_login_enabled", &self.password_login_enabled)
            .field("password_register_enabled", &self.password_register_enabled)
            .field(
                "email_verification_enabled",
                &self.email_verification_enabled,
            )
            .field("turnstile_check_enabled", &self.turnstile_check_enabled)
            .field("register_enabled", &self.register_enabled)
            .field("turnstile_site_key", &self.turnstile_site_key)
            .field("turnstile_secret_key", &"[REDACTED]")
            .finish()
    }
}

impl AuthSettings {
    /// Fetch all authentication keys in one statement and return a complete
    /// replacement. Missing rows retain the corresponding `previous` value;
    /// SQL NULL is an error rather than a silent default. The caller publishes
    /// only successful results and owns readiness changes.
    pub async fn load(db: &Database, previous: &Self) -> Result<Self, sqlx::Error> {
        store::load(db, previous).await
    }
}
