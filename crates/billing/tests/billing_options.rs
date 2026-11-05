//! Remote-only integration contract for the legacy billing option migration.

use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use newapi_billing::billing_options::{
    LEGACY_BILLING_EXPR_OPTION_KEY, LEGACY_BILLING_MODE_OPTION_KEY, migrate_legacy_billing_options,
};
use newapi_storage::Database;
use sqlx::{
    postgres::PgPoolOptions,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "newapi-billing-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).expect("create unique fixture directory");
        Self(path)
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const MODE_TARGET: &str = "billing_setting.billing_mode";
const EXPR_TARGET: &str = "billing_setting.billing_expr";

async fn execute(db: &Database, sql: &'static str) {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query(sql).execute(pool).await.unwrap();
        }
        Database::Postgres(pool) => {
            sqlx::query(sql).execute(pool).await.unwrap();
        }
    }
}

async fn put_option(db: &Database, key: &str, value: &str) {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query(
                "INSERT INTO options (\"key\", \"value\") VALUES (?, ?) \
                 ON CONFLICT(\"key\") DO UPDATE SET \"value\" = excluded.\"value\"",
            )
            .bind(key)
            .bind(value)
            .execute(pool)
            .await
            .unwrap();
        }
        Database::Postgres(pool) => {
            sqlx::query(
                "INSERT INTO options (\"key\", \"value\") VALUES ($1, $2) \
                 ON CONFLICT(\"key\") DO UPDATE SET \"value\" = excluded.\"value\"",
            )
            .bind(key)
            .bind(value)
            .execute(pool)
            .await
            .unwrap();
        }
    }
}

async fn option(db: &Database, key: &str) -> Option<String> {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query_scalar("SELECT \"value\" FROM options WHERE \"key\" = ?")
                .bind(key)
                .fetch_optional(pool)
                .await
                .unwrap()
        }
        Database::Postgres(pool) => {
            sqlx::query_scalar("SELECT \"value\" FROM options WHERE \"key\" = $1")
                .bind(key)
                .fetch_optional(pool)
                .await
                .unwrap()
        }
    }
}

async fn delete_option(db: &Database, key: &str) {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query("DELETE FROM options WHERE \"key\" = ?")
                .bind(key)
                .execute(pool)
                .await
                .unwrap();
        }
        Database::Postgres(pool) => {
            sqlx::query("DELETE FROM options WHERE \"key\" = $1")
                .bind(key)
                .execute(pool)
                .await
                .unwrap();
        }
    }
}

async fn source_is_initialized(db: &Database) {
    execute(
        db,
        "CREATE TEMP TABLE options (\"key\" TEXT PRIMARY KEY, \"value\" TEXT NOT NULL)",
    )
    .await;
}

async fn contract(db: &Database) {
    source_is_initialized(db).await;

    put_option(
        db,
        LEGACY_BILLING_MODE_OPTION_KEY,
        r#"{"gpt-4o":"legacy","legacy-only":"mode"}"#,
    )
    .await;
    put_option(db, MODE_TARGET, r#"{"gpt-4o":"target"}"#).await;
    put_option(
        db,
        LEGACY_BILLING_EXPR_OPTION_KEY,
        r#"{"gpt-4o":"expr-legacy","expr-only":"expr","empty":""}"#,
    )
    .await;
    put_option(db, EXPR_TARGET, r#"{"gpt-4o":"expr-target"}"#).await;

    migrate_legacy_billing_options(db)
        .await
        .expect("well-formed migration");

    let mode = option(db, MODE_TARGET).await.expect("mode target");
    assert!(mode.contains("\"gpt-4o\":\"target\""), "target must win");
    assert!(
        mode.contains("\"legacy-only\":\"mode\""),
        "missing legacy copied"
    );
    let expr = option(db, EXPR_TARGET).await.expect("expr target");
    assert!(
        expr.contains("\"gpt-4o\":\"expr-target\""),
        "target must win"
    );
    assert!(
        expr.contains("\"expr-only\":\"expr\""),
        "missing legacy copied"
    );
    assert!(!expr.contains("\"empty\""), "empty legacy value dropped");

    // Legacy rows are retained for rollback.
    assert_eq!(
        option(db, LEGACY_BILLING_MODE_OPTION_KEY).await.as_deref(),
        Some(r#"{"gpt-4o":"legacy","legacy-only":"mode"}"#)
    );
    assert_eq!(
        option(db, LEGACY_BILLING_EXPR_OPTION_KEY).await.as_deref(),
        Some(r#"{"gpt-4o":"expr-legacy","expr-only":"expr","empty":""}"#)
    );

    // Idempotent second run.
    migrate_legacy_billing_options(db)
        .await
        .expect("idempotent second run");
    assert_eq!(
        option(db, MODE_TARGET).await.as_deref(),
        Some(mode.as_str())
    );
    assert_eq!(
        option(db, EXPR_TARGET).await.as_deref(),
        Some(expr.as_str())
    );

    // Malformed legacy data is logged and skipped, never fatal.
    put_option(db, LEGACY_BILLING_MODE_OPTION_KEY, "not json").await;
    migrate_legacy_billing_options(db)
        .await
        .expect("malformed legacy is skipped");
    assert_eq!(
        option(db, MODE_TARGET).await.as_deref(),
        Some(mode.as_str())
    );
    assert_eq!(
        option(db, LEGACY_BILLING_MODE_OPTION_KEY).await.as_deref(),
        Some("not json"),
        "malformed legacy row stays for manual recovery"
    );

    // Malformed target data is never overwritten by legacy data.
    put_option(db, LEGACY_BILLING_MODE_OPTION_KEY, r#"{"new":"value"}"#).await;
    put_option(db, MODE_TARGET, "not json").await;
    migrate_legacy_billing_options(db)
        .await
        .expect("malformed target is skipped");
    assert_eq!(option(db, MODE_TARGET).await.as_deref(), Some("not json"));

    // Missing target row is created.
    delete_option(db, MODE_TARGET).await;
    migrate_legacy_billing_options(db)
        .await
        .expect("missing target is created");
    assert_eq!(
        option(db, MODE_TARGET).await.as_deref(),
        Some(r#"{"new":"value"}"#)
    );

    // Missing legacy row is a no-op.
    delete_option(db, LEGACY_BILLING_MODE_OPTION_KEY).await;
    migrate_legacy_billing_options(db)
        .await
        .expect("missing legacy is a no-op");
    assert_eq!(
        option(db, MODE_TARGET).await.as_deref(),
        Some(r#"{"new":"value"}"#)
    );

    // A JSON null target is an empty map in Go, so legacy data fills it.
    put_option(
        db,
        LEGACY_BILLING_MODE_OPTION_KEY,
        r#"{"from-null":"value"}"#,
    )
    .await;
    put_option(db, MODE_TARGET, "null").await;
    migrate_legacy_billing_options(db)
        .await
        .expect("null target merges");
    assert_eq!(
        option(db, MODE_TARGET).await.as_deref(),
        Some(r#"{"from-null":"value"}"#)
    );

    // A target write failure rolls the whole key back.
    put_option(db, LEGACY_BILLING_MODE_OPTION_KEY, r#"{"another":"value"}"#).await;
    put_option(db, MODE_TARGET, r#"{"current":"value"}"#).await;
    install_failure_trigger(db).await;
    let error = migrate_legacy_billing_options(db)
        .await
        .expect_err("forced write failure");
    assert_eq!(error.failed_steps, vec!["billing mode"]);
    drop_failure_trigger(db).await;
    assert_eq!(
        option(db, MODE_TARGET).await.as_deref(),
        Some(r#"{"current":"value"}"#),
        "failed transaction must not partially commit"
    );

    db.close().await;
}

async fn install_failure_trigger(db: &Database) {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query(
                "CREATE TRIGGER billing_options_fail BEFORE UPDATE ON options \
                 WHEN NEW.\"key\" = 'billing_setting.billing_mode' \
                 BEGIN SELECT RAISE(ABORT, 'forced failure'); END",
            )
            .execute(pool)
            .await
            .unwrap();
        }
        Database::Postgres(pool) => {
            sqlx::query(
                "CREATE FUNCTION pg_temp.billing_options_fail() RETURNS trigger \
                 LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced failure'; END $$",
            )
            .execute(pool)
            .await
            .unwrap();
            // EXECUTE PROCEDURE stays a valid trigger alias across the
            // supported 14-17 range.
            sqlx::query(
                "CREATE TRIGGER billing_options_fail BEFORE UPDATE ON options \
                 FOR EACH ROW WHEN (NEW.\"key\" = 'billing_setting.billing_mode') \
                 EXECUTE PROCEDURE pg_temp.billing_options_fail()",
            )
            .execute(pool)
            .await
            .unwrap();
        }
    }
}

async fn drop_failure_trigger(db: &Database) {
    match db {
        // SQLite drops a trigger by name only; `ON table` is PostgreSQL syntax.
        Database::Sqlite(pool) => {
            sqlx::query("DROP TRIGGER billing_options_fail")
                .execute(pool)
                .await
                .unwrap();
        }
        Database::Postgres(pool) => {
            sqlx::query("DROP TRIGGER billing_options_fail ON options")
                .execute(pool)
                .await
                .unwrap();
        }
    }
}

#[tokio::test]
async fn sqlite_billing_options_contract() {
    let directory = Directory::new();
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .idle_timeout(None)
        .max_lifetime(None)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(directory.0.join("fixture.db"))
                .create_if_missing(true),
        )
        .await
        .unwrap();
    contract(&Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn postgres_billing_options_contract() {
    let dsn = std::env::var("TEST_POSTGRES_DSN")
        .expect("TEST_POSTGRES_DSN is required; run this test in GitHub Actions");
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .idle_timeout(None)
        .max_lifetime(None)
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET search_path TO pg_temp")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&dsn)
        .await
        .unwrap_or_else(|_| panic!("PostgreSQL test connection failed"));
    contract(&Database::Postgres(pool)).await;
}
