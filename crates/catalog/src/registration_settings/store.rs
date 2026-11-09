use newapi_storage::Database;

use super::RegistrationSettings;

const KEYS: [&str; 3] = ["QuotaForNewUser", "QuotaForInviter", "QuotaForInvitee"];

pub(super) async fn load(
    db: &Database,
    previous: &RegistrationSettings,
) -> Result<RegistrationSettings, sqlx::Error> {
    let rows: Vec<(String, Option<String>)> = match db {
        Database::Sqlite(pool) => {
            sqlx::query_as(
                "SELECT \"key\", \"value\" FROM \"options\" \
                 WHERE \"key\" IN (?, ?, ?)",
            )
            .bind(KEYS[0])
            .bind(KEYS[1])
            .bind(KEYS[2])
            .fetch_all(pool)
            .await?
        }
        Database::Postgres(pool) => {
            sqlx::query_as(
                "SELECT \"key\", \"value\" FROM \"options\" \
                 WHERE \"key\" IN ($1, $2, $3)",
            )
            .bind(KEYS[0])
            .bind(KEYS[1])
            .bind(KEYS[2])
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
    let mut next = *previous;
    for (key, value) in rows {
        // Go `strconv.Atoi(value)`：非法值按 0（错误被吞），负数原样保留；
        // 与 Go 一致不做 trim（" 10 " 解析失败 → 0）。
        let parsed = value.parse::<i64>().unwrap_or(0);
        match key.as_str() {
            "QuotaForNewUser" => next.quota_for_new_user = parsed,
            "QuotaForInviter" => next.quota_for_inviter = parsed,
            "QuotaForInvitee" => next.quota_for_invitee = parsed,
            _ => {}
        }
    }
    Ok(next)
}
