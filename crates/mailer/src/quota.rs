//! 按账号的当日发送计数（Go `internal/mailer/quota_store.go`）。
//!
//! 语义：UTC+8 日历日为一窗；数据库行是唯一事实来源（重启重放计数而不是
//! 清零），进程内缓存只是读加速——本端口省略读缓存，直接查库（Go 的
//! HybridCache 内存面在单进程内只省一次主键查询）。

use chrono::{FixedOffset, Utc};
use newapi_storage::Database;

/// Go `quotaZone = time.FixedZone("CST", 8*60*60)`。
fn quota_zone() -> FixedOffset {
    FixedOffset::east_opt(8 * 60 * 60).expect("UTC+8 is a valid offset")
}

/// Go `quotaDay`：`2006-01-02` 格式的 UTC+8 日历日。
pub fn quota_day() -> String {
    Utc::now()
        .with_timezone(&quota_zone())
        .format("%Y-%m-%d")
        .to_string()
}

/// Go `common/email_quota.go` 的 `SMTPQuotaStore` 端口（DB 实现）。
#[async_trait::async_trait]
#[allow(clippy::double_must_use)] // async_trait 把 Future 装箱后 must_use 语义重复。
pub trait QuotaStore: Send + Sync {
    /// 账号今日已发送次数。
    async fn used_today(&self, account: &str) -> Result<i64, String>;
    /// 记一次成功发送。
    async fn record_use(&self, account: &str) -> Result<(), String>;
}

/// 数据库实现（Go `internal/mailer/quota_store.go` 的 `store`）。
pub struct DbQuotaStore {
    db: Database,
}

impl DbQuotaStore {
    pub fn new(db: Database) -> Self {
        Self { db }
    }
}

#[async_trait::async_trait]
impl QuotaStore for DbQuotaStore {
    /// Go `UsedToday`（quota_store.go:31-53）：无行视为 0。
    async fn used_today(&self, account: &str) -> Result<i64, String> {
        let day = quota_day();
        match &self.db {
            Database::Sqlite(pool) => {
                let used: Option<i64> = sqlx::query_scalar(
                    "SELECT used FROM smtp_quota_usage WHERE account = ?1 AND day = ?2",
                )
                .bind(account)
                .bind(&day)
                .fetch_optional(pool)
                .await
                .map_err(|error| format!("failed to read SMTP quota for {account}: {error}"))?;
                Ok(used.unwrap_or(0))
            }
            Database::Postgres(pool) => {
                let used: Option<i64> = sqlx::query_scalar(
                    "SELECT used FROM smtp_quota_usage WHERE account = $1 AND day = $2",
                )
                .bind(account)
                .bind(&day)
                .fetch_optional(pool)
                .await
                .map_err(|error| format!("failed to read SMTP quota for {account}: {error}"))?;
                Ok(used.unwrap_or(0))
            }
        }
    }

    /// Go `RecordUse`（quota_store.go:56-88）：单条原子 UPDATE；无行时
    /// INSERT 首行，INSERT 撞并发后再补一次 UPDATE。
    async fn record_use(&self, account: &str) -> Result<(), String> {
        let day = quota_day();
        let now = Utc::now().timestamp();
        let bump_err =
            |error: sqlx::Error| format!("failed to record SMTP quota for {account}: {error}");
        let updated = match &self.db {
            Database::Sqlite(pool) => sqlx::query(
                "UPDATE smtp_quota_usage SET used = used + 1, updated_at = ?1 \
                 WHERE account = ?2 AND day = ?3",
            )
            .bind(now)
            .bind(account)
            .bind(&day)
            .execute(pool)
            .await
            .map_err(bump_err)?
            .rows_affected(),
            Database::Postgres(pool) => sqlx::query(
                "UPDATE smtp_quota_usage SET used = used + 1, updated_at = $1 \
                 WHERE account = $2 AND day = $3",
            )
            .bind(now)
            .bind(account)
            .bind(&day)
            .execute(pool)
            .await
            .map_err(bump_err)?
            .rows_affected(),
        };
        if updated > 0 {
            return Ok(());
        }
        // 并发首发明兜底：先 INSERT，撞唯一键再补一次 UPDATE（Go 同形）。
        match &self.db {
            Database::Sqlite(pool) => {
                if sqlx::query(
                    "INSERT INTO smtp_quota_usage (account, day, used, updated_at) \
                     VALUES (?1, ?2, 1, ?3)",
                )
                .bind(account)
                .bind(&day)
                .bind(now)
                .execute(pool)
                .await
                .is_err()
                {
                    sqlx::query(
                        "UPDATE smtp_quota_usage SET used = used + 1, updated_at = ?1 \
                         WHERE account = ?2 AND day = ?3",
                    )
                    .bind(now)
                    .bind(account)
                    .bind(&day)
                    .execute(pool)
                    .await
                    .map_err(bump_err)?;
                }
            }
            Database::Postgres(pool) => {
                if sqlx::query(
                    "INSERT INTO smtp_quota_usage (account, day, used, updated_at) \
                     VALUES ($1, $2, 1, $3)",
                )
                .bind(account)
                .bind(&day)
                .bind(now)
                .execute(pool)
                .await
                .is_err()
                {
                    sqlx::query(
                        "UPDATE smtp_quota_usage SET used = used + 1, updated_at = $1 \
                         WHERE account = $2 AND day = $3",
                    )
                    .bind(now)
                    .bind(account)
                    .bind(&day)
                    .execute(pool)
                    .await
                    .map_err(bump_err)?;
                }
            }
        }
        Ok(())
    }
}

/// 无库计数（Go `smtpQuotaStore == nil` 时 UsedToday 恒 0、RecordUse 恒 ok）。
pub struct NoopQuotaStore;

#[async_trait::async_trait]
impl QuotaStore for NoopQuotaStore {
    async fn used_today(&self, _account: &str) -> Result<i64, String> {
        Ok(0)
    }

    async fn record_use(&self, _account: &str) -> Result<(), String> {
        Ok(())
    }
}
