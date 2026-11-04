use std::collections::BTreeMap;

use newapi_storage::Database;

use super::merge::{
    BILLING_EXPR_TARGET_KEY, BILLING_MODE_TARGET_KEY, LEGACY_BILLING_EXPR_OPTION_KEY,
    LEGACY_BILLING_MODE_OPTION_KEY, drop_empty_map_entries, merge_maps, parse_string_map_option,
};

/// Fixed, value-free startup failure. SQL and row contents are never exposed.
#[derive(Debug)]
pub struct BillingOptionsMigrationError {
    pub failed_steps: Vec<&'static str>,
}

impl std::fmt::Display for BillingOptionsMigrationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("billing options migration failed")
    }
}

impl std::error::Error for BillingOptionsMigrationError {}

#[derive(Debug)]
enum StepError {
    Database,
    Encode,
}

impl From<sqlx::Error> for StepError {
    fn from(_: sqlx::Error) -> Self {
        Self::Database
    }
}

/// Copy `ModelBillingMode` and `ModelBillingExpr` into the flattened
/// `billing_setting.*` keys. Each key runs in its own transaction; a failure
/// in one does not partially commit that key, and both are attempted.
///
/// Malformed legacy rows and malformed target rows are logged and skipped,
/// matching upstream startup behavior. Legacy rows are deliberately retained.
pub async fn migrate_legacy_billing_options(
    db: &Database,
) -> Result<(), BillingOptionsMigrationError> {
    let mut failed_steps = Vec::new();
    for (step, target_key, legacy_key) in [
        (
            "billing mode",
            BILLING_MODE_TARGET_KEY,
            LEGACY_BILLING_MODE_OPTION_KEY,
        ),
        (
            "billing expression",
            BILLING_EXPR_TARGET_KEY,
            LEGACY_BILLING_EXPR_OPTION_KEY,
        ),
    ] {
        let result = match db {
            Database::Sqlite(pool) => migrate_pair_sqlite(pool, target_key, legacy_key).await,
            Database::Postgres(pool) => migrate_pair_postgres(pool, target_key, legacy_key).await,
        };
        if result.is_err() {
            tracing::error!(
                event = "billing_options_migration_failed",
                step,
                "billing options migration step failed"
            );
            failed_steps.push(step);
        }
    }
    if failed_steps.is_empty() {
        Ok(())
    } else {
        Err(BillingOptionsMigrationError { failed_steps })
    }
}

async fn migrate_pair_sqlite(
    pool: &sqlx::SqlitePool,
    target_key: &str,
    legacy_key: &str,
) -> Result<(), StepError> {
    let mut transaction = pool.begin().await?;
    let legacy_value = read_legacy_sqlite(&mut transaction, legacy_key).await?;
    let Some(legacy_value) = legacy_value else {
        transaction.commit().await?;
        return Ok(());
    };
    let Some(legacy_map) = prepare_legacy_map(legacy_key, &legacy_value) else {
        transaction.commit().await?;
        return Ok(());
    };
    let target_row = sqlx::query_as::<_, (String, String)>(
        "SELECT \"key\", \"value\" FROM \"options\" WHERE \"key\" = ?",
    )
    .bind(target_key)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some((target_map, target_exists)) = prepare_target_map(target_key, target_row) else {
        transaction.commit().await?;
        return Ok(());
    };
    let merged = merge_maps(&legacy_map, &target_map);
    if merged.len() == target_map.len() {
        transaction.commit().await?;
        return Ok(());
    }
    let encoded = serde_json::to_string(&merged).map_err(|_| StepError::Encode)?;
    if target_exists {
        sqlx::query("UPDATE \"options\" SET \"value\" = ? WHERE \"key\" = ?")
            .bind(&encoded)
            .bind(target_key)
            .execute(&mut *transaction)
            .await?;
    } else {
        sqlx::query("INSERT INTO \"options\" (\"key\", \"value\") VALUES (?, ?)")
            .bind(target_key)
            .bind(&encoded)
            .execute(&mut *transaction)
            .await?;
    }
    transaction.commit().await?;
    Ok(())
}

async fn migrate_pair_postgres(
    pool: &sqlx::PgPool,
    target_key: &str,
    legacy_key: &str,
) -> Result<(), StepError> {
    let mut transaction = pool.begin().await?;
    let legacy_value = read_legacy_postgres(&mut transaction, legacy_key).await?;
    let Some(legacy_value) = legacy_value else {
        transaction.commit().await?;
        return Ok(());
    };
    let Some(legacy_map) = prepare_legacy_map(legacy_key, &legacy_value) else {
        transaction.commit().await?;
        return Ok(());
    };
    // Lock the target row so the read-modify-write serialises against option
    // writes committed by other instances during startup.
    let target_row = sqlx::query_as::<_, (String, String)>(
        "SELECT \"key\", \"value\" FROM \"options\" WHERE \"key\" = $1 FOR UPDATE",
    )
    .bind(target_key)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some((target_map, target_exists)) = prepare_target_map(target_key, target_row) else {
        transaction.commit().await?;
        return Ok(());
    };
    let merged = merge_maps(&legacy_map, &target_map);
    if merged.len() == target_map.len() {
        transaction.commit().await?;
        return Ok(());
    }
    let encoded = serde_json::to_string(&merged).map_err(|_| StepError::Encode)?;
    if target_exists {
        sqlx::query("UPDATE \"options\" SET \"value\" = $1 WHERE \"key\" = $2")
            .bind(&encoded)
            .bind(target_key)
            .execute(&mut *transaction)
            .await?;
    } else {
        sqlx::query("INSERT INTO \"options\" (\"key\", \"value\") VALUES ($1, $2)")
            .bind(target_key)
            .bind(&encoded)
            .execute(&mut *transaction)
            .await?;
    }
    transaction.commit().await?;
    Ok(())
}

async fn read_legacy_sqlite(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    legacy_key: &str,
) -> Result<Option<String>, sqlx::Error> {
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT \"key\", \"value\" FROM \"options\" WHERE \"key\" = ?")
            .bind(legacy_key)
            .fetch_optional(&mut **transaction)
            .await?;
    Ok(row.map(|(_, value)| value))
}

async fn read_legacy_postgres(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    legacy_key: &str,
) -> Result<Option<String>, sqlx::Error> {
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT \"key\", \"value\" FROM \"options\" WHERE \"key\" = $1")
            .bind(legacy_key)
            .fetch_optional(&mut **transaction)
            .await?;
    Ok(row.map(|(_, value)| value))
}

fn prepare_legacy_map(legacy_key: &str, legacy_value: &str) -> Option<BTreeMap<String, String>> {
    let mut map = match parse_string_map_option(legacy_value) {
        Ok(map) => map,
        Err(_) => {
            tracing::error!(
                event = "billing_options_invalid_legacy",
                key = legacy_key,
                "legacy billing option skipped"
            );
            return None;
        }
    };
    drop_empty_map_entries(&mut map);
    if map.is_empty() {
        return None;
    }
    Some(map)
}

fn prepare_target_map(
    target_key: &str,
    row: Option<(String, String)>,
) -> Option<(BTreeMap<String, String>, bool)> {
    match row {
        None => Some((BTreeMap::new(), false)),
        Some((_, value)) if value.trim().is_empty() => Some((BTreeMap::new(), true)),
        Some((_, value)) => match parse_string_map_option(&value) {
            Ok(map) => Some((map, true)),
            Err(_) => {
                tracing::error!(
                    event = "billing_options_invalid_target",
                    key = target_key,
                    "target billing option left unchanged"
                );
                None
            }
        },
    }
}
