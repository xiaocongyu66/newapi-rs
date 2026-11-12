//! SMTP 配额存储契约（双后端）。Go oracle：
//! `internal/mailer/quota_store.go` + `quota_usage.go`（表 smtp_quota_usage）。

use std::sync::atomic::{AtomicU64, Ordering};

use newapi_mailer::quota::{DbQuotaStore, QuotaStore, quota_day};
use newapi_storage::Database;
use sqlx::{
    ConnectOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::SqlitePoolOptions,
};

static NEXT: AtomicU64 = AtomicU64::new(0);

const SQLITE_DDL: &str = r#"CREATE TABLE IF NOT EXISTS smtp_quota_usage (
    account TEXT NOT NULL,
    day TEXT NOT NULL,
    used BIGINT NOT NULL DEFAULT 0,
    updated_at BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (account, day)
)"#;

const POSTGRES_DDL: &str = r#"CREATE TABLE IF NOT EXISTS smtp_quota_usage (
    account TEXT NOT NULL,
    day TEXT NOT NULL,
    used BIGINT NOT NULL DEFAULT 0,
    updated_at BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (account, day)
)"#;

async fn sqlite_fixture() -> Database {
    let pool = SqlitePoolOptions::new()
        .max_connections(2)
        .connect(":memory:")
        .await
        .expect("sqlite fixture");
    sqlx::query(SQLITE_DDL).execute(&pool).await.expect("ddl");
    Database::Sqlite(pool)
}

async fn postgres_fixture() -> Option<Database> {
    let Ok(dsn) = std::env::var("TEST_POSTGRES_DSN") else {
        return None;
    };
    let options: PgConnectOptions = dsn
        .parse()
        .expect("invalid PostgreSQL fixture config")
        .disable_statement_logging();
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone())
        .await
        .expect("connect PostgreSQL fixture");
    let schema = format!(
        "smtp_quota_{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA \"{schema}\"")))
        .execute(&admin)
        .await
        .expect("create isolated schema");
    let search_path = schema.clone();
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .after_connect(move |connection, _| {
            let path = search_path.clone();
            Box::pin(async move {
                sqlx::query("SELECT set_config('search_path', $1, false)")
                    .bind(path)
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect_with(options)
        .await
        .expect("connect isolated PostgreSQL pool");
    sqlx::query(POSTGRES_DDL).execute(&pool).await.expect("ddl");
    Some(Database::Postgres(pool))
}

async fn contract(db: Database) {
    let store = DbQuotaStore::new(db);
    assert_eq!(store.used_today("a@b.c").await.unwrap(), 0, "无行视为 0");
    store.record_use("a@b.c").await.unwrap();
    store.record_use("a@b.c").await.unwrap();
    assert_eq!(store.used_today("a@b.c").await.unwrap(), 2);
    assert_eq!(
        store.used_today("other@b.c").await.unwrap(),
        0,
        "按账号隔离"
    );
}

#[tokio::test]
async fn quota_store_sqlite_contract() {
    contract(sqlite_fixture().await).await;
}

#[tokio::test]
async fn quota_store_postgres_contract() {
    let Some(db) = postgres_fixture().await else {
        eprintln!("TEST_POSTGRES_DSN absent; PostgreSQL half skipped");
        return;
    };
    contract(db).await;
}

#[tokio::test]
async fn noop_store_mirrors_nil_store_in_go() {
    let store = newapi_mailer::quota::NoopQuotaStore;
    assert_eq!(store.used_today("x").await.unwrap(), 0);
    store.record_use("x").await.unwrap();
    assert_eq!(store.used_today("x").await.unwrap(), 0);
}

#[test]
fn quota_day_shape_is_a_calendar_date() {
    let day = quota_day();
    let parts: Vec<&str> = day.split('-').collect();
    assert_eq!(parts.len(), 3);
    assert!(parts[0].len() == 4 && parts[1].len() == 2 && parts[2].len() == 2);
}
