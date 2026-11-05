//! 登录路径使用的 2FA 读取、TOTP/备用码校验与失败锁定。
//!
//! 表结构严格对齐 Go `identity.TwoFA` / `identity.TwoFABackupCode` 的
//! GORM 列名：`two_fas`、`two_fa_backup_codes`。时间列在数据库中是
//! timestamp，Rust 边界统一转换为调用方提供的 Unix 秒。

use std::fmt;

use newapi_storage::Database;
use sqlx::Row;

use crate::crypto;
use crate::two_fa::totp::{
    format_go_time, normalize_backup_code, normalize_numeric_code, validate_totp_code,
};

/// Go `common.MaxFailAttempts`。
pub const MAX_FAIL_ATTEMPTS: i64 = 5;
/// Go `common.LockoutDuration`（秒）。
pub const LOCKOUT_SECONDS: i64 = 300;
/// Go `IncrementFailedAttempts` 的 CAS 重试上限。
const MAX_UPDATE_RETRIES: u32 = 5;

/// 固定文案错误；不携带验证码、哈希、密钥或数据库错误文本。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TwoFaError {
    /// Go “验证码或备用码不正确”：格式非法，或 TOTP 失败后备用码格式非法。
    Invalid,
    /// Go “验证码或备用码错误，请重试”：格式正确但验证失败。
    Incorrect,
    /// Go 锁定文案；`until` 为解锁时间（Unix 秒）。
    Locked { until: i64 },
    /// Go “用户未启用2FA”。
    NotEnabled,
    /// Go `GetTwoFAByUserId` 对 0 用户 ID 的错误。
    InvalidUser,
    /// Go “更新2FA失败次数冲突，请重试”。
    AttemptsConflict,
    /// 固定存储错误文本，绝不转述 SQLx/GORM 错误。
    Unavailable,
}

impl fmt::Display for TwoFaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 诊断文本不面向客户端；客户端文案统一由 [`TwoFaError::client_message`]
        // 生成，避免 UI 文案散落在仓储层。
        formatter.write_str(match self {
            Self::Invalid => "2FA code format is invalid",
            Self::Incorrect => "2FA code is incorrect",
            Self::Locked { .. } => "2FA is temporarily locked",
            Self::NotEnabled => "2FA is not enabled",
            Self::InvalidUser => "user id must not be empty",
            Self::AttemptsConflict => "2FA failed-attempt update conflict",
            Self::Unavailable => "2FA storage is unavailable",
        })
    }
}

impl TwoFaError {
    /// 客户端文案：统一从 `newapi-i18n` 目录解析，本模块不内联任何用户文本。
    ///
    /// Go 在这些分支上直接返回硬编码中文（`manage_twofa.go`、
    /// `store_twofa.go`），不查 i18n。Rust 实现把所有文案收进
    /// `crates/i18n/locales/`：zh-CN 条目与 Go 逐字一致以保持兼容，
    /// zh-TW/en 为本地化增益。`lang` 由调用方经
    /// [`newapi_i18n::resolve_language`] 解析。
    pub fn client_message(&self, lang: &str) -> String {
        let plain =
            |key: &str| newapi_i18n::translate(lang, key, std::iter::empty::<(&str, &str)>());
        match self {
            Self::Invalid => plain("twofa.code_invalid"),
            Self::Incorrect => plain("twofa.code_incorrect"),
            Self::Locked { until } => newapi_i18n::translate(
                lang,
                "twofa.locked_until",
                [("Until", format_go_time(*until))],
            ),
            Self::NotEnabled => plain("twofa.not_enabled"),
            Self::InvalidUser => plain("twofa.user_id_empty"),
            Self::AttemptsConflict => plain("twofa.attempts_conflict"),
            // Go handler 对存储错误直接返回 err.Error()；Rust 不转述 SQL 文本。
            Self::Unavailable => plain("common.database_error"),
        }
    }
}

impl std::error::Error for TwoFaError {}

/// 2FA 记录快照；secret 保持明文（与 Go 存储一致），但 Debug 必须脱敏。
#[derive(Clone, PartialEq, Eq)]
pub struct TwoFa {
    pub id: i64,
    pub user_id: i64,
    pub secret: String,
    pub is_enabled: bool,
    pub failed_attempts: i64,
    pub locked_until: Option<i64>,
    pub last_used_at: Option<i64>,
}

impl TwoFa {
    /// Go `IsLocked`：`locked_until` 非空且 `now < locked_until`。
    pub fn is_locked(&self, now: i64) -> bool {
        matches!(self.locked_until, Some(until) if now < until)
    }
}

impl fmt::Debug for TwoFa {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TwoFa")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("secret", &"<redacted>")
            .field("is_enabled", &self.is_enabled)
            .field("failed_attempts", &self.failed_attempts)
            .field("locked_until", &self.locked_until)
            .field("last_used_at", &self.last_used_at)
            .finish()
    }
}

#[derive(Clone)]
pub struct TwoFaRepository {
    database: Database,
}

impl TwoFaRepository {
    pub fn new(database: Database) -> Self {
        Self { database }
    }

    /// Go `GetTwoFAByUserId`：未设置返回 `None`，数据库错误返回 `Unavailable`。
    pub async fn by_user_id(&self, user_id: i64) -> Result<Option<TwoFa>, TwoFaError> {
        if user_id == 0 {
            return Err(TwoFaError::InvalidUser);
        }
        match &self.database {
            Database::Sqlite(pool) => {
                let row = sqlx::query(SQLITE_SELECT_BY_USER)
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(|_| TwoFaError::Unavailable)?;
                row.map(decode_sqlite_two_fa).transpose()
            }
            Database::Postgres(pool) => {
                let row = sqlx::query(POSTGRES_SELECT_BY_USER)
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(|_| TwoFaError::Unavailable)?;
                row.map(decode_postgres_two_fa).transpose()
            }
        }
    }

    /// Go `ValidateBackupCode`：格式非法返回 `Invalid`；未命中返回 `Ok(false)`；
    /// 命中后条件更新 `is_used=false`，只有影响 1 行才算成功（并发唯一赢家）。
    pub async fn validate_backup_code(
        &self,
        user_id: i64,
        code: &str,
        now: i64,
    ) -> Result<bool, TwoFaError> {
        let Some(normalized) = normalize_backup_code(code) else {
            return Err(TwoFaError::Invalid);
        };
        let codes: Vec<(i64, String)> = match &self.database {
            Database::Sqlite(pool) => {
                let rows = sqlx::query(SELECT_BACKUP_CODES)
                    .bind(user_id)
                    .bind(false)
                    .fetch_all(pool)
                    .await
                    .map_err(|_| TwoFaError::Unavailable)?;
                rows.iter()
                    .map(|row| {
                        let id: i64 = row.try_get("id").map_err(|_| TwoFaError::Unavailable)?;
                        let code_hash: String = row
                            .try_get("code_hash")
                            .map_err(|_| TwoFaError::Unavailable)?;
                        Ok((id, code_hash))
                    })
                    .collect::<Result<Vec<_>, TwoFaError>>()?
            }
            Database::Postgres(pool) => {
                let rows = sqlx::query(SELECT_BACKUP_CODES)
                    .bind(user_id)
                    .bind(false)
                    .fetch_all(pool)
                    .await
                    .map_err(|_| TwoFaError::Unavailable)?;
                rows.iter()
                    .map(|row| {
                        let id: i64 = row.try_get("id").map_err(|_| TwoFaError::Unavailable)?;
                        let code_hash: String = row
                            .try_get("code_hash")
                            .map_err(|_| TwoFaError::Unavailable)?;
                        Ok((id, code_hash))
                    })
                    .collect::<Result<Vec<_>, TwoFaError>>()?
            }
        };

        for (id, code_hash) in codes {
            if !crypto::verify_password(normalized.as_bytes(), &code_hash).unwrap_or(false) {
                continue;
            }
            let affected = match &self.database {
                Database::Sqlite(pool) => sqlx::query(SQLITE_MARK_BACKUP_CODE_USED)
                    .bind(now)
                    .bind(id)
                    .execute(pool)
                    .await
                    .map_err(|_| TwoFaError::Unavailable)?
                    .rows_affected(),
                Database::Postgres(pool) => sqlx::query(POSTGRES_MARK_BACKUP_CODE_USED)
                    .bind(now)
                    .bind(id)
                    .execute(pool)
                    .await
                    .map_err(|_| TwoFaError::Unavailable)?
                    .rows_affected(),
            };
            return Ok(affected == 1);
        }
        Ok(false)
    }

    /// Go `Verify2FALogin` 的 TOTP/备用码分派与失败计数逻辑。
    ///
    /// 顺序：锁定检查 → （格式合法时）TOTP → 锁定复检 → 备用码。
    /// 非法格式不增加失败次数；格式正确但错误会累加；成功清零并写 last_used_at。
    pub async fn validate_login_code(
        &self,
        user_id: i64,
        code: &str,
        now: i64,
    ) -> Result<(), TwoFaError> {
        let mut two_fa = match self.by_user_id(user_id).await? {
            Some(two_fa) if two_fa.is_enabled => two_fa,
            _ => return Err(TwoFaError::NotEnabled),
        };

        if let Some(until) = two_fa.locked_until.filter(|until| now < *until) {
            return Err(TwoFaError::Locked { until });
        }

        let mut verified = false;
        if let Some(numeric) = normalize_numeric_code(code) {
            if validate_totp_code(&two_fa.secret, &numeric, now) {
                verified = true;
            } else {
                self.increment_failed_attempts(&mut two_fa, now).await?;
            }
        }

        if !verified {
            // Go 的备用码分支在读取备用码前再次检查锁定；第 5 次 TOTP 失败
            // 刚触发锁定时，响应是锁定文案而不是格式文案。
            if let Some(until) = two_fa.locked_until.filter(|until| now < *until) {
                return Err(TwoFaError::Locked { until });
            }
            if !self.validate_backup_code(user_id, code, now).await? {
                self.increment_failed_attempts(&mut two_fa, now).await?;
                return Err(TwoFaError::Incorrect);
            }
        }

        // Go 在成功后记录日志而不再把 usage 更新错误返回给调用方。
        let _ = self.reset_usage(two_fa.id, now).await;
        Ok(())
    }

    /// Go `IncrementFailedAttempts`：先读当前值，再以
    /// `failed_attempts` + 未锁定条件做 CAS；冲突最多重试 5 次。
    async fn increment_failed_attempts(
        &self,
        two_fa: &mut TwoFa,
        now: i64,
    ) -> Result<(), TwoFaError> {
        for _ in 0..MAX_UPDATE_RETRIES {
            let Some((current_failed, current_locked)) = self.read_attempt_state(two_fa.id).await?
            else {
                return Err(TwoFaError::Unavailable);
            };

            if matches!(current_locked, Some(until) if now < until) {
                two_fa.failed_attempts = current_failed;
                two_fa.locked_until = current_locked;
                return Ok(());
            }

            let next_failed = current_failed + 1;
            let next_locked = if next_failed >= MAX_FAIL_ATTEMPTS {
                Some(now + LOCKOUT_SECONDS)
            } else {
                current_locked
            };

            let affected = match &self.database {
                Database::Sqlite(pool) => sqlx::query(SQLITE_CAS_ATTEMPTS)
                    .bind(next_failed)
                    .bind(next_locked)
                    .bind(now)
                    .bind(two_fa.id)
                    .bind(current_failed)
                    .execute(pool)
                    .await
                    .map_err(|_| TwoFaError::Unavailable)?
                    .rows_affected(),
                Database::Postgres(pool) => sqlx::query(POSTGRES_CAS_ATTEMPTS)
                    .bind(next_failed)
                    .bind(next_locked)
                    .bind(now)
                    .bind(two_fa.id)
                    .bind(current_failed)
                    .execute(pool)
                    .await
                    .map_err(|_| TwoFaError::Unavailable)?
                    .rows_affected(),
            };

            if affected == 1 {
                two_fa.failed_attempts = next_failed;
                two_fa.locked_until = next_locked;
                return Ok(());
            }
        }
        Err(TwoFaError::AttemptsConflict)
    }

    async fn read_attempt_state(&self, id: i64) -> Result<Option<(i64, Option<i64>)>, TwoFaError> {
        match &self.database {
            Database::Sqlite(pool) => {
                let row = sqlx::query(SQLITE_SELECT_ATTEMPTS)
                    .bind(id)
                    .fetch_optional(pool)
                    .await
                    .map_err(|_| TwoFaError::Unavailable)?;
                row.map(|row| {
                    let failed_attempts: i64 = row
                        .try_get("failed_attempts")
                        .map_err(|_| TwoFaError::Unavailable)?;
                    let locked_epoch: Option<i64> = row
                        .try_get("locked_epoch")
                        .map_err(|_| TwoFaError::Unavailable)?;
                    Ok((failed_attempts, locked_epoch))
                })
                .transpose()
            }
            Database::Postgres(pool) => {
                let row = sqlx::query(POSTGRES_SELECT_ATTEMPTS)
                    .bind(id)
                    .fetch_optional(pool)
                    .await
                    .map_err(|_| TwoFaError::Unavailable)?;
                row.map(|row| {
                    let failed_attempts: i64 = row
                        .try_get("failed_attempts")
                        .map_err(|_| TwoFaError::Unavailable)?;
                    let locked_epoch: Option<i64> = row
                        .try_get("locked_epoch")
                        .map_err(|_| TwoFaError::Unavailable)?;
                    Ok((failed_attempts, locked_epoch))
                })
                .transpose()
            }
        }
    }

    async fn reset_usage(&self, id: i64, now: i64) -> Result<(), TwoFaError> {
        match &self.database {
            Database::Sqlite(pool) => {
                sqlx::query(SQLITE_RESET_USAGE)
                    .bind(now)
                    .bind(id)
                    .execute(pool)
                    .await
                    .map_err(|_| TwoFaError::Unavailable)?;
            }
            Database::Postgres(pool) => {
                sqlx::query(POSTGRES_RESET_USAGE)
                    .bind(now)
                    .bind(id)
                    .execute(pool)
                    .await
                    .map_err(|_| TwoFaError::Unavailable)?;
            }
        }
        Ok(())
    }
}

fn decode_sqlite_two_fa(row: sqlx::sqlite::SqliteRow) -> Result<TwoFa, TwoFaError> {
    Ok(TwoFa {
        id: row.try_get("id").map_err(|_| TwoFaError::Unavailable)?,
        user_id: row
            .try_get("user_id")
            .map_err(|_| TwoFaError::Unavailable)?,
        secret: row.try_get("secret").map_err(|_| TwoFaError::Unavailable)?,
        is_enabled: row
            .try_get("is_enabled")
            .map_err(|_| TwoFaError::Unavailable)?,
        failed_attempts: row
            .try_get("failed_attempts")
            .map_err(|_| TwoFaError::Unavailable)?,
        locked_until: row
            .try_get("locked_epoch")
            .map_err(|_| TwoFaError::Unavailable)?,
        last_used_at: row
            .try_get("used_epoch")
            .map_err(|_| TwoFaError::Unavailable)?,
    })
}

fn decode_postgres_two_fa(row: sqlx::postgres::PgRow) -> Result<TwoFa, TwoFaError> {
    Ok(TwoFa {
        id: row.try_get("id").map_err(|_| TwoFaError::Unavailable)?,
        user_id: row
            .try_get("user_id")
            .map_err(|_| TwoFaError::Unavailable)?,
        secret: row.try_get("secret").map_err(|_| TwoFaError::Unavailable)?,
        is_enabled: row
            .try_get("is_enabled")
            .map_err(|_| TwoFaError::Unavailable)?,
        failed_attempts: row
            .try_get("failed_attempts")
            .map_err(|_| TwoFaError::Unavailable)?,
        locked_until: row
            .try_get("locked_epoch")
            .map_err(|_| TwoFaError::Unavailable)?,
        last_used_at: row
            .try_get("used_epoch")
            .map_err(|_| TwoFaError::Unavailable)?,
    })
}

const SQLITE_SELECT_BY_USER: &str = "SELECT id, user_id, secret, is_enabled, failed_attempts, \
    CASE WHEN locked_until IS NULL THEN NULL ELSE CAST(strftime('%s', locked_until) AS INTEGER) END AS locked_epoch, \
    CASE WHEN last_used_at IS NULL THEN NULL ELSE CAST(strftime('%s', last_used_at) AS INTEGER) END AS used_epoch \
    FROM two_fas WHERE user_id = $1 AND deleted_at IS NULL ORDER BY id LIMIT 1";

const POSTGRES_SELECT_BY_USER: &str = "SELECT id, user_id, secret, is_enabled, failed_attempts, \
    CASE WHEN locked_until IS NULL THEN NULL ELSE CAST(EXTRACT(EPOCH FROM locked_until) AS BIGINT) END AS locked_epoch, \
    CASE WHEN last_used_at IS NULL THEN NULL ELSE CAST(EXTRACT(EPOCH FROM last_used_at) AS BIGINT) END AS used_epoch \
    FROM two_fas WHERE user_id = $1 AND deleted_at IS NULL ORDER BY id LIMIT 1";

const SQLITE_SELECT_ATTEMPTS: &str = "SELECT failed_attempts, \
    CASE WHEN locked_until IS NULL THEN NULL ELSE CAST(strftime('%s', locked_until) AS INTEGER) END AS locked_epoch \
    FROM two_fas WHERE id = $1 AND deleted_at IS NULL";

const POSTGRES_SELECT_ATTEMPTS: &str = "SELECT failed_attempts, \
    CASE WHEN locked_until IS NULL THEN NULL ELSE CAST(EXTRACT(EPOCH FROM locked_until) AS BIGINT) END AS locked_epoch \
    FROM two_fas WHERE id = $1 AND deleted_at IS NULL";

const SQLITE_CAS_ATTEMPTS: &str = "UPDATE two_fas SET failed_attempts = $1, \
    locked_until = datetime($2, 'unixepoch'), updated_at = datetime($3, 'unixepoch') \
    WHERE id = $4 AND failed_attempts = $5 \
    AND (locked_until IS NULL OR CAST(strftime('%s', locked_until) AS INTEGER) <= $3) \
    AND deleted_at IS NULL";

const POSTGRES_CAS_ATTEMPTS: &str = "UPDATE two_fas SET failed_attempts = $1, \
    locked_until = to_timestamp($2::BIGINT), updated_at = to_timestamp($3::BIGINT) \
    WHERE id = $4 AND failed_attempts = $5 \
    AND (locked_until IS NULL OR locked_until <= to_timestamp($3::BIGINT)) \
    AND deleted_at IS NULL";

const SQLITE_RESET_USAGE: &str = "UPDATE two_fas SET failed_attempts = 0, locked_until = NULL, \
    last_used_at = datetime($1, 'unixepoch'), updated_at = datetime($1, 'unixepoch') \
    WHERE id = $2 AND deleted_at IS NULL";

const POSTGRES_RESET_USAGE: &str = "UPDATE two_fas SET failed_attempts = 0, locked_until = NULL, \
    last_used_at = to_timestamp($1::BIGINT), updated_at = to_timestamp($1::BIGINT) \
    WHERE id = $2 AND deleted_at IS NULL";

const SELECT_BACKUP_CODES: &str = "SELECT id, code_hash FROM two_fa_backup_codes \
    WHERE user_id = $1 AND is_used = $2 AND deleted_at IS NULL ORDER BY id";

const SQLITE_MARK_BACKUP_CODE_USED: &str = "UPDATE two_fa_backup_codes SET is_used = 1, \
    used_at = datetime($1, 'unixepoch') WHERE id = $2 AND is_used = 0 AND deleted_at IS NULL";

const POSTGRES_MARK_BACKUP_CODE_USED: &str = "UPDATE two_fa_backup_codes SET is_used = TRUE, \
    used_at = to_timestamp($1::BIGINT) WHERE id = $2 AND is_used = FALSE AND deleted_at IS NULL";
