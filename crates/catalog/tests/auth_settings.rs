use newapi_catalog::AuthSettings;
use newapi_storage::Database;
use sqlx::{
    postgres::PgPoolOptions,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};

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

async fn insert(db: &Database, key: &str, value: Option<&str>) {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query("INSERT INTO options (\"key\", \"value\") VALUES (?, ?)")
                .bind(key)
                .bind(value)
                .execute(pool)
                .await
                .unwrap();
        }
        Database::Postgres(pool) => {
            sqlx::query("INSERT INTO options (\"key\", \"value\") VALUES ($1, $2)")
                .bind(key)
                .bind(value)
                .execute(pool)
                .await
                .unwrap();
        }
    }
}

async fn update(db: &Database, key: &str, value: &str) {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query("UPDATE options SET \"value\" = ? WHERE \"key\" = ?")
                .bind(value)
                .bind(key)
                .execute(pool)
                .await
                .unwrap();
        }
        Database::Postgres(pool) => {
            sqlx::query("UPDATE options SET \"value\" = $1 WHERE \"key\" = $2")
                .bind(value)
                .bind(key)
                .execute(pool)
                .await
                .unwrap();
        }
    }
}

// Runs unchanged against both real SQLx backends, including failure paths.
async fn contract(db: &Database) {
    let default = AuthSettings::default();

    // Go seeds these defaults before applying any persisted row:
    // internal/common/constants.go:64-72, internal/settings/settings.go:242-243.
    assert!(default.password_login_enabled);
    assert!(default.password_register_enabled);
    assert!(!default.email_verification_enabled);
    assert!(!default.turnstile_check_enabled);
    assert!(default.register_enabled);
    assert!(default.turnstile_site_key.is_empty());
    assert!(default.turnstile_secret_key.is_empty());

    // A missing options table is an error, not a silent set of defaults.
    assert!(AuthSettings::load(db, &default).await.is_err());

    execute(
        db,
        "CREATE TEMP TABLE options (\"key\" TEXT PRIMARY KEY, \"value\" TEXT)",
    )
    .await;

    // No rows at all still yields the Go defaults.
    let empty = AuthSettings::load(db, &default).await.unwrap();
    assert_eq!(empty, default);

    // Persisted booleans are applied verbatim; strings keep their exact value.
    insert(db, "PasswordLoginEnabled", Some("true")).await;
    insert(db, "PasswordRegisterEnabled", Some("false")).await;
    insert(db, "EmailVerificationEnabled", Some("true")).await;
    insert(db, "TurnstileCheckEnabled", Some("true")).await;
    insert(db, "RegisterEnabled", Some("false")).await;
    insert(db, "TurnstileSiteKey", Some("site-key")).await;
    insert(db, "TurnstileSecretKey", Some("secret-key")).await;

    let explicit = AuthSettings::load(db, &default).await.unwrap();
    assert!(explicit.password_login_enabled);
    assert!(!explicit.password_register_enabled);
    assert!(explicit.email_verification_enabled);
    assert!(explicit.turnstile_check_enabled);
    assert!(!explicit.register_enabled);
    assert_eq!(explicit.turnstile_site_key, "site-key");
    assert_eq!(explicit.turnstile_secret_key, "secret-key");

    // Go uses `value == "true"` (settings.go:372), so "1", "TRUE", "yes", "",
    // and " true" are all false. Each is applied over a true previous value to
    // prove the stored value wins.
    for value in ["1", "TRUE", "yes", "", " true"] {
        for key in [
            "PasswordLoginEnabled",
            "PasswordRegisterEnabled",
            "EmailVerificationEnabled",
            "TurnstileCheckEnabled",
            "RegisterEnabled",
        ] {
            update(db, key, value).await;
        }
        let loaded = AuthSettings::load(db, &explicit).await.unwrap();
        assert!(!loaded.password_login_enabled, "value={value:?}");
        assert!(!loaded.password_register_enabled, "value={value:?}");
        assert!(!loaded.email_verification_enabled, "value={value:?}");
        assert!(!loaded.turnstile_check_enabled, "value={value:?}");
        assert!(!loaded.register_enabled, "value={value:?}");
        // Untouched string keys keep their configured values.
        assert_eq!(loaded.turnstile_site_key, "site-key");
        assert_eq!(loaded.turnstile_secret_key, "secret-key");
    }

    // An explicitly configured empty string is a legal value, not a missing row.
    update(db, "TurnstileSiteKey", "").await;
    update(db, "TurnstileSecretKey", "").await;
    let cleared = AuthSettings::load(db, &explicit).await.unwrap();
    assert!(cleared.turnstile_site_key.is_empty());
    assert!(cleared.turnstile_secret_key.is_empty());

    // A missing row retains the previous snapshot value, which is what allows
    // hot reloads to replace only the rows that still exist.
    update(db, "EmailVerificationEnabled", "true").await;
    let before_delete = AuthSettings::load(db, &default).await.unwrap();
    assert!(before_delete.email_verification_enabled);
    execute(
        db,
        "DELETE FROM options WHERE \"key\" = 'EmailVerificationEnabled'",
    )
    .await;
    let kept = AuthSettings::load(db, &before_delete).await.unwrap();
    assert!(kept.email_verification_enabled);
    let fresh = AuthSettings::load(db, &default).await.unwrap();
    assert!(!fresh.email_verification_enabled);

    // SQL NULL in the value column is a decode error and does not mutate the
    // caller's previous snapshot.
    update(db, "TurnstileSecretKey", "secret-key").await;
    let stable = AuthSettings::load(db, &default).await.unwrap();
    assert_eq!(stable.turnstile_secret_key, "secret-key");
    execute(
        db,
        "UPDATE options SET \"value\" = NULL WHERE \"key\" = 'TurnstileSecretKey'",
    )
    .await;
    assert!(AuthSettings::load(db, &stable).await.is_err());
    assert_eq!(stable.turnstile_secret_key, "secret-key");

    // Debug output must redact the secret.
    update(db, "TurnstileSecretKey", "super-secret-turnstile").await;
    let loaded = AuthSettings::load(db, &default).await.unwrap();
    let debug = format!("{loaded:?}");
    assert!(!debug.contains("super-secret-turnstile"));
    assert!(debug.contains("[REDACTED]"));

    // A dropped table or a closed pool surfaces an error rather than stale data.
    execute(db, "DROP TABLE options").await;
    assert!(AuthSettings::load(db, &stable).await.is_err());
    db.close().await;
    assert!(AuthSettings::load(db, &stable).await.is_err());
}

#[tokio::test]
async fn sqlite_auth_settings_contract() {
    // One in-memory connection owns the temporary table for the whole contract.
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .idle_timeout(None)
        .max_lifetime(None)
        .connect_with(SqliteConnectOptions::new().in_memory(true))
        .await
        .unwrap();
    contract(&Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn postgres_auth_settings_contract() {
    let dsn = std::env::var("TEST_POSTGRES_DSN")
        .expect("TEST_POSTGRES_DSN is required; run this test in GitHub Actions");
    // Exactly one persistent connection owns its temporary table. Search only
    // pg_temp so no existing public.options is read or modified by fixtures.
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
