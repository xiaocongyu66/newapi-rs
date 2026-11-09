use newapi_storage::Database;

use super::EmailSettings;

const KEYS: [&str; 4] = [
    "EmailDomainRestrictionEnabled",
    "EmailDomainWhitelist",
    "EmailAliasRestrictionEnabled",
    "EmailFormatRegex",
];

pub(super) async fn load(
    db: &Database,
    previous: &EmailSettings,
) -> Result<EmailSettings, sqlx::Error> {
    // Decode all rows before touching even the private replacement snapshot.
    let rows: Vec<(String, Option<String>)> = match db {
        Database::Sqlite(pool) => {
            sqlx::query_as(
                "SELECT \"key\", \"value\" FROM \"options\" \
                 WHERE \"key\" IN (?, ?, ?, ?)",
            )
            .bind(KEYS[0])
            .bind(KEYS[1])
            .bind(KEYS[2])
            .bind(KEYS[3])
            .fetch_all(pool)
            .await?
        }
        Database::Postgres(pool) => {
            sqlx::query_as(
                "SELECT \"key\", \"value\" FROM \"options\" \
                 WHERE \"key\" IN ($1, $2, $3, $4)",
            )
            .bind(KEYS[0])
            .bind(KEYS[1])
            .bind(KEYS[2])
            .bind(KEYS[3])
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
            "EmailDomainRestrictionEnabled" => {
                next.email_domain_restriction_enabled = parse_bool(&value);
            }
            "EmailAliasRestrictionEnabled" => {
                next.email_alias_restriction_enabled = parse_bool(&value);
            }
            "EmailDomainWhitelist" => {
                next.email_domain_whitelist = EmailSettings::split_whitelist(&value);
            }
            // 每行一条规则；空文本产生空列表（=不限制）。
            "EmailFormatRegex" => {
                next.email_format_regex_rules = EmailSettings::split_regex_rules(&value);
            }
            _ => {}
        }
    }
    Ok(next)
}

/// Go `ApplyOption` 的 `boolValue := value == "true"`（settings.go:372）。
fn parse_bool(value: &str) -> bool {
    value == "true"
}
