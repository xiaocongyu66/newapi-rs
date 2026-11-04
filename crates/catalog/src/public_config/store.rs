use newapi_storage::Database;

use super::PublicConfig;

const KEYS: [&str; 5] = [
    "Notice",
    "About",
    "HomePageContent",
    "legal.user_agreement",
    "legal.privacy_policy",
];

pub(super) async fn load(
    db: &Database,
    previous: &PublicConfig,
) -> Result<PublicConfig, sqlx::Error> {
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
