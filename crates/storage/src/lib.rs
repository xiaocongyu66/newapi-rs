//! Connection lifecycle only: schema and domain queries belong to their owners.

use std::{str::FromStr, time::Duration};

use sqlx::{
    ConnectOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};

/// Shared, bounded pools. Cloning does not create another pool.
#[derive(Clone)]
pub enum Database {
    Sqlite(sqlx::SqlitePool),
    Postgres(sqlx::PgPool),
}

impl Database {
    /// Connect to an existing database without creating files or running migrations.
    ///
    /// No DSN or underlying connection error is logged here. Callers must log a
    /// fixed error category rather than formatting SQLx errors, which can contain
    /// database-controlled text or connection details.
    pub async fn connect(dsn: &str) -> Result<Self, sqlx::Error> {
        if dsn.starts_with("sqlite:") {
            let options = SqliteConnectOptions::from_str(dsn)?
                .create_if_missing(false)
                // 对齐原 Go 默认 `_busy_timeout=30000`：写锁竞争应等待，
                // 而不是立即把并发会话写成 Storage 失败。
                .busy_timeout(Duration::from_secs(30))
                .disable_statement_logging();
            let pool = SqlitePoolOptions::new()
                .max_connections(5)
                .acquire_timeout(Duration::from_secs(10))
                .connect_with(options)
                .await?;
            Ok(Self::Sqlite(pool))
        } else if dsn.starts_with("postgres:") || dsn.starts_with("postgresql:") {
            let options = PgConnectOptions::from_str(dsn)?.disable_statement_logging();
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .acquire_timeout(Duration::from_secs(10))
                .connect_with(options)
                .await?;
            Ok(Self::Postgres(pool))
        } else {
            Err(sqlx::Error::Configuration(
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "unsupported database scheme; expected sqlite, postgres, or postgresql",
                )
                .into(),
            ))
        }
    }

    /// Close this pool and all its clones after borrowed connections are returned.
    pub async fn close(&self) {
        match self {
            Self::Sqlite(pool) => pool.close().await,
            Self::Postgres(pool) => pool.close().await,
        }
    }
}
