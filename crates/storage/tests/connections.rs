use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use newapi_storage::Database;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "newapi-storage-{}-{}",
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

#[tokio::test]
async fn unsupported_schemes_fail_without_echoing_input() {
    for dsn in [
        "mysql://private:secret@host/db",
        "file:private.db",
        "private.db",
        "",
    ] {
        let Err(error) = Database::connect(dsn).await else {
            panic!("unsupported scheme accepted");
        };
        assert!(matches!(error, sqlx::Error::Configuration(_)));
        assert!(!error.to_string().contains("private"));
        assert!(!error.to_string().contains("secret"));
    }
}

#[tokio::test]
async fn sqlite_missing_file_is_never_created_even_when_dsn_requests_creation() {
    let directory = Directory::new();
    let file = directory.0.join("absent.db");
    for suffix in ["", "?mode=rwc"] {
        let dsn = format!("sqlite://{}{suffix}", file.display());
        assert!(Database::connect(&dsn).await.is_err());
        assert!(!file.exists());
    }
}

#[tokio::test]
async fn sqlite_existing_file_connects_without_creating_schema_and_closes_clones() {
    let directory = Directory::new();
    let file = directory.0.join("existing.db");
    let fixture = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&file)
                .create_if_missing(true),
        )
        .await
        .expect("create test-only database");
    fixture.close().await;
    let db = Database::connect(&format!("sqlite://{}", file.display()))
        .await
        .expect("connect existing SQLite fixture");
    let Database::Sqlite(pool) = db.clone() else {
        panic!("wrong backend");
    };
    let tables: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_master WHERE type = 'table'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(tables, 0);
    db.close().await;
    assert!(pool.is_closed());
    assert!(sqlx::query("SELECT 1").execute(&pool).await.is_err());
}

#[tokio::test]
async fn postgres_connects_with_both_schemes_and_closes_clones() {
    let dsn = std::env::var("TEST_POSTGRES_DSN")
        .expect("TEST_POSTGRES_DSN is required; run this test in GitHub Actions");
    let suffix = dsn
        .strip_prefix("postgres:")
        .or_else(|| dsn.strip_prefix("postgresql:"))
        .expect("TEST_POSTGRES_DSN must be PostgreSQL");
    for scheme in ["postgres:", "postgresql:"] {
        let db = Database::connect(&format!("{scheme}{suffix}"))
            .await
            .unwrap_or_else(|_| panic!("PostgreSQL test connection failed"));
        let Database::Postgres(pool) = db.clone() else {
            panic!("wrong backend");
        };
        let value: i32 = sqlx::query_scalar("SELECT 1")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(value, 1);
        db.close().await;
        assert!(pool.is_closed());
    }
}
