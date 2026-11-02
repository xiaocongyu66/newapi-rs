use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use newapi_catalog::PublicConfig;
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
            "newapi-catalog-{}-{}",
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

async fn execute(db: &Database, sql: &str) {
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

fn fields(config: &PublicConfig) -> [&str; 5] {
    [
        &config.notice,
        &config.about,
        &config.home_page_content,
        &config.user_agreement,
        &config.privacy_policy,
    ]
}

// Runs unchanged against both real SQLx backends, including failure paths.
async fn contract(db: &Database) {
    let default = PublicConfig::default();
    assert_eq!(fields(&default), [""; 5]);
    assert!(PublicConfig::load(db, &default).await.is_err());
    execute(
        db,
        "CREATE TEMP TABLE options (\"key\" TEXT PRIMARY KEY, \"value\" TEXT)",
    )
    .await;
    let empty = PublicConfig::load(db, &default).await.unwrap();
    assert_eq!(fields(&empty), [""; 5]);

    // NULL sensitive values would fail decoding if the loader read all options.
    insert(db, "SMTPPassword", None).await;
    insert(db, "UserAgreement", Some("wrong legacy key")).await;
    insert(db, "PrivacyPolicy", Some("wrong legacy key")).await;
    insert(db, "notice", Some("wrong case")).await;
    insert(db, "Notice' OR 1=1 --", Some("not a public key")).await;
    let isolated = PublicConfig::load(db, &default).await.unwrap();
    assert_eq!(fields(&isolated), [""; 5]);

    let expected = [
        "  公告\n<script>not interpreted</script>  ",
        "",
        "https://example.test/home?x='quoted'&y=1",
        "# 使用协议\n\n原文保持",
        " \t\n",
    ];
    for (key, value) in [
        "Notice",
        "About",
        "HomePageContent",
        "legal.user_agreement",
        "legal.privacy_policy",
    ]
    .into_iter()
    .zip(expected)
    {
        insert(db, key, Some(value)).await;
    }
    let loaded = PublicConfig::load(db, &default).await.unwrap();
    assert_eq!(fields(&loaded), expected);
    assert_eq!(fields(&default), [""; 5]);

    execute(db, "DELETE FROM options WHERE \"key\" = 'Notice'").await;
    let deleted = PublicConfig::load(db, &loaded).await.unwrap();
    assert_eq!(fields(&deleted), expected);
    let restarted = PublicConfig::load(db, &default).await.unwrap();
    assert_eq!(restarted.notice, "");
    insert(db, "Notice", Some("")).await;
    let cleared = PublicConfig::load(db, &deleted).await.unwrap();
    assert_eq!(cleared.notice, "");

    execute(db, "UPDATE options SET \"value\" = 'new' WHERE \"key\" = 'Notice'").await;
    execute(db, "UPDATE options SET \"value\" = NULL WHERE \"key\" = 'About'").await;
    assert!(PublicConfig::load(db, &loaded).await.is_err());
    assert_eq!(fields(&loaded), expected);
    execute(db, "DROP TABLE options").await;
    assert!(PublicConfig::load(db, &loaded).await.is_err());
    assert_eq!(fields(&loaded), expected);

    // A wrongly typed old schema must not silently stringify values.
    execute(
        db,
        "CREATE TEMP TABLE options (\"key\" TEXT PRIMARY KEY, \"value\" INTEGER)",
    )
    .await;
    execute(db, "INSERT INTO options (\"key\", \"value\") VALUES ('Notice', 42)").await;
    assert!(PublicConfig::load(db, &loaded).await.is_err());
    assert_eq!(fields(&loaded), expected);
    execute(db, "DROP TABLE options").await;
    db.close().await;
    assert!(PublicConfig::load(db, &loaded).await.is_err());
    assert_eq!(fields(&loaded), expected);
}

#[tokio::test]
async fn sqlite_public_config_contract() {
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
async fn postgres_public_config_contract() {
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
