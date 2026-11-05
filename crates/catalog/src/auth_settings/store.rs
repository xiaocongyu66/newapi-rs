use newapi_storage::Database;

use super::AuthSettings;

const KEYS: [&str; 7] = [
    "PasswordLoginEnabled",
    "PasswordRegisterEnabled",
    "EmailVerificationEnabled",
    "TurnstileCheckEnabled",
    "RegisterEnabled",
    "TurnstileSiteKey",
    "TurnstileSecretKey",
];

pub(super) async fn load(
    db: &Database,
    previous: &AuthSettings,
) -> Result<AuthSettings, sqlx::Error> {
    // Decode all rows before touching even the private replacement snapshot.
    let rows: Vec<(String, Option<String>)> = match db {
        Database::Sqlite(pool) => {
            sqlx::query_as(
                "SELECT \"key\", \"value\" FROM \"options\" \
                 WHERE \"key\" IN (?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(KEYS[0])
            .bind(KEYS[1])
            .bind(KEYS[2])
            .bind(KEYS[3])
            .bind(KEYS[4])
            .bind(KEYS[5])
            .bind(KEYS[6])
            .fetch_all(pool)
            .await?
        }
        Database::Postgres(pool) => {
            sqlx::query_as(
                "SELECT \"key\", \"value\" FROM \"options\" \
                 WHERE \"key\" IN ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(KEYS[0])
            .bind(KEYS[1])
            .bind(KEYS[2])
            .bind(KEYS[3])
            .bind(KEYS[4])
            .bind(KEYS[5])
            .bind(KEYS[6])
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
            "PasswordLoginEnabled" => next.password_login_enabled = parse_bool(&value),
            "PasswordRegisterEnabled" => next.password_register_enabled = parse_bool(&value),
            "EmailVerificationEnabled" => next.email_verification_enabled = parse_bool(&value),
            "TurnstileCheckEnabled" => next.turnstile_check_enabled = parse_bool(&value),
            "RegisterEnabled" => next.register_enabled = parse_bool(&value),
            // Empty strings are valid configured values, not "missing".
            "TurnstileSiteKey" => next.turnstile_site_key = value,
            "TurnstileSecretKey" => next.turnstile_secret_key = value,
            _ => {}
        }
    }
    Ok(next)
}

/// Go's `ApplyOption` computes `boolValue := value == "true"` (settings.go:372),
/// so every other string (including `"1"`, `"TRUE"`, and `""`) is false.
fn parse_bool(value: &str) -> bool {
    value == "true"
}
