//! Public options snapshot. No HTTP request performs a database read here.

use newapi_storage::Database;
use serde::Serialize;

mod store;

#[derive(Clone, Default, Serialize)]
pub struct PublicConfig {
    pub notice: String,
    pub about: String,
    pub home_page_content: String,
    pub user_agreement: String,
    pub privacy_policy: String,
    /// Go `channel.SelfUseModeEnabled`：options 键 `SelfUseModeEnabled` 为
    /// "true" 时启用，缺失/其它值按 Go `value == "true"` 判定为 false。
    pub self_use_mode_enabled: bool,
    /// Go `channel.DemoSiteEnabled`，解析语义同上。
    pub demo_site_enabled: bool,
}

impl PublicConfig {
    /// Fetch only public keys in one statement and return a complete
    /// replacement. Missing rows retain the last value; SQL NULL and invalid
    /// types are errors. The caller publishes only successful results and owns
    /// readiness changes.
    pub async fn load(db: &Database, previous: &Self) -> Result<Self, sqlx::Error> {
        store::load(db, previous).await
    }
}
