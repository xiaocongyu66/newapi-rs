//! Public options snapshot. No HTTP request performs a database read here.

use newapi_storage::Database;
use serde::Serialize;

pub mod billing_options;
pub mod channel_prompt;
pub mod response_cache;

pub use billing_options::{
    BillingSettingRecord, LegacyBillingRecord, MergeError, MergePlan, PlanStep,
    plan_billing_options_merge,
};
pub use channel_prompt::{ChannelPromptError, ChannelPromptSettings};
pub use response_cache::{
    CacheEligibilityError, CacheKey, CacheScope, ResponseCacheConfig, ResponseCacheConfigError,
    ResponseCacheRequest,
};

const KEYS: [&str; 5] = [
    "Notice",
    "About",
    "HomePageContent",
    "legal.user_agreement",
    "legal.privacy_policy",
];

#[derive(Clone, Default, Serialize)]
pub struct PublicConfig {
    pub notice: String,
    pub about: String,
    pub home_page_content: String,
    pub user_agreement: String,
    pub privacy_policy: String,
}

impl PublicConfig {
    /// Fetch only public keys in one statement and return a complete replacement.
    /// Missing rows retain the last value; SQL NULL and invalid types are errors.
    /// The caller publishes only successful results and owns readiness changes.
    pub async fn load(db: &Database, previous: &Self) -> Result<Self, sqlx::Error> {
        // Decode all rows before touching even the private replacement snapshot.
        let rows: Vec<(String, Option<String>)> = match db {
            Database::Sqlite(pool) => {
                sqlx::query_as(
                    "SELECT \"key\", \"value\" FROM \"options\" \
                     WHERE \"key\" IN (?, ?, ?, ?, ?)",
                )
                .bind(KEYS[0])
                .bind(KEYS[1])
                .bind(KEYS[2])
                .bind(KEYS[3])
                .bind(KEYS[4])
                .fetch_all(pool)
                .await?
            }
            Database::Postgres(pool) => {
                sqlx::query_as(
                    "SELECT \"key\", \"value\" FROM \"options\" \
                     WHERE \"key\" IN ($1, $2, $3, $4, $5)",
                )
                .bind(KEYS[0])
                .bind(KEYS[1])
                .bind(KEYS[2])
                .bind(KEYS[3])
                .bind(KEYS[4])
                .fetch_all(pool)
                .await?
            }
        };
        let rows = rows
            .into_iter()
            .map(|(key, value)| {
                value
                    .map(|value| (key, value))
                    .ok_or_else(|| sqlx::Error::ColumnDecode {
                        index: "value".to_owned(),
                        source: Box::new(sqlx::error::UnexpectedNullError),
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut next = previous.clone();
        for (key, value) in rows {
            match key.as_str() {
                "Notice" => next.notice = value,
                "About" => next.about = value,
                "HomePageContent" => next.home_page_content = value,
                "legal.user_agreement" => next.user_agreement = value,
                "legal.privacy_policy" => next.privacy_policy = value,
                _ => {}
            }
        }
        Ok(next)
    }
}
