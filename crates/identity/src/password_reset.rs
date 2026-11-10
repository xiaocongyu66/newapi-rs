//! `POST /api/user/reset` 的身份域部分：按唯一邮箱重置密码。
//!
//! Go 参考：`identity.ResetPassword` → `identity.ResetUserPasswordByEmail`
//! → `GetUniqueUserByEmail`（`apps/api/internal/identity/verify_email.go`
//! 与 `store_users_lifecycle.go`）。本模块不做 HTTP、验证码缓存或会话处理。
//!
//! 与 Go 对齐的要点：
//! - 邮箱先做 `strings.ToLower(strings.TrimSpace(...))` 归一化；
//! - 只匹配未软删除（GORM 默认作用域）的用户，`LOWER(email)` 不区分大小写；
//! - 命中 0 条为 `EmailNotFound`，命中 2 条及以上为 `EmailAmbiguous`；
//! - 密码以 bcrypt(cost 10) 写入，并在同一事务内递增 `auth_version`
//!   （NULL/0 旧值从 2 起步，否则 +1）。
//!
//! 已确认的移植缺口（不伪造）：Go 还会 `PublishUserAuthCache`，Rust 目前
//! 没有用户缓存发布步骤。Go 的 `RevokeAllUserSessions(userId,
//! "password_reset")`（`store_users_lifecycle.go:191-192`）由 HTTP 层
//! （`reset_http::reset_password`）在本仓储事务提交后调用
//! （`SessionAuth::revoke_all`），事务边界与 Go 对齐：撤销是独立批次，
//! 不在密码重置事务内。

use newapi_storage::Database;

use crate::crypto::{hash_password, random_uuid};

/// Go `common.GenerateVerificationCode(12)` 生成的新密码长度；字母表为
/// UUIDv4 去掉连字符后的十六进制字符（长度 0 时返回完整的 32 位）。
pub const GENERATED_PASSWORD_LENGTH: usize = 12;

/// 密码重置的固定错误分类；不携带 SQL 或底层数据库文本。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PasswordResetError {
    /// 归一化后的邮箱为空，或密码为空（Go `ResetUserPasswordByEmail` 的前置检查）。
    InvalidInput,
    EmailNotFound,
    EmailAmbiguous,
    Storage,
}

/// Go `common.GenerateVerificationCode`：UUIDv4 去掉 `-`，按请求长度截断。
/// 生产密码固定 12 位；长度超过 32 时与 Go 一样是调用方错误。
/// `None` 仅当操作系统随机源失败（Go 的 `uuid.New()` 在此处会 panic）。
pub fn generate_verification_code(length: usize) -> Option<String> {
    let dashless = random_uuid().ok()?.replace('-', "");
    if length == 0 {
        return Some(dashless);
    }
    Some(dashless[..length].to_owned())
}

/// Go `NormalizeEmail`：`strings.ToLower(strings.TrimSpace(email))`。
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

const FIND_USER_ID_BY_EMAIL: &str = "SELECT CAST(id AS BIGINT) FROM users \
    WHERE LOWER(email) = $1 AND deleted_at IS NULL LIMIT 2";
// Go `IncrementUserAuthVersionWithTx` 的版本规则：NULL/0 视为 1，再 +1。
const INCREMENT_AUTH_VERSION: &str = "UPDATE users SET auth_version = \
    CASE WHEN COALESCE(auth_version, 0) < 1 THEN 2 \
    ELSE COALESCE(auth_version, 0) + 1 END WHERE id = $1";
const UPDATE_PASSWORD: &str = "UPDATE users SET password = $1 WHERE id = $2 AND deleted_at IS NULL";

#[derive(Clone)]
pub struct PasswordResetRepository {
    db: Database,
}

impl PasswordResetRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Go `ResetUserPasswordByEmail`：唯一邮箱 → bcrypt → 事务内递增
    /// `auth_version` 并替换密码。成功时返回被重置用户的 id，供调用方在
    /// 事务提交后撤销会话（Go `RevokeAllUserSessions(id, "password_reset")`）。
    /// `password` 原文不在此模块外记录。
    pub async fn reset_by_email(
        &self,
        email: &str,
        password: &str,
    ) -> Result<i64, PasswordResetError> {
        let email = normalize_email(email);
        if email.is_empty() || password.is_empty() {
            return Err(PasswordResetError::InvalidInput);
        }
        let user_id = self.unique_user_id(&email).await?;
        // Go 在事务外散列；失败即返回，不触碰数据库。
        let password_hash = hash_password(password.as_bytes())
            .map_err(|_| PasswordResetError::Storage)?
            .expose_secret()
            .to_owned();
        match &self.db {
            Database::Sqlite(pool) => reset_sqlite(pool, user_id, &password_hash).await,
            Database::Postgres(pool) => reset_postgres(pool, user_id, &password_hash).await,
        }?;
        Ok(user_id)
    }

    /// Go `GetUniqueUserByEmail`：空邮箱、0 条、2 条及以上分别返回固定分类。
    /// 发送重置邮件端点（`SendPasswordResetEmail`）共用此判定决定是否
    /// 生成验证码并发送。
    pub async fn unique_user_id(&self, email: &str) -> Result<i64, PasswordResetError> {
        let ids: Vec<i64> = match &self.db {
            Database::Sqlite(pool) => {
                sqlx::query_scalar(FIND_USER_ID_BY_EMAIL)
                    .bind(email)
                    .fetch_all(pool)
                    .await
            }
            Database::Postgres(pool) => {
                sqlx::query_scalar(FIND_USER_ID_BY_EMAIL)
                    .bind(email)
                    .fetch_all(pool)
                    .await
            }
        }
        .map_err(|_| PasswordResetError::Storage)?;
        match ids.as_slice() {
            [] => Err(PasswordResetError::EmailNotFound),
            [id] => Ok(*id),
            _ => Err(PasswordResetError::EmailAmbiguous),
        }
    }
}

async fn reset_sqlite(
    pool: &sqlx::SqlitePool,
    user_id: i64,
    password_hash: &str,
) -> Result<(), PasswordResetError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| PasswordResetError::Storage)?;
    sqlx::query(INCREMENT_AUTH_VERSION)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| PasswordResetError::Storage)?;
    sqlx::query(UPDATE_PASSWORD)
        .bind(password_hash)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| PasswordResetError::Storage)?;
    tx.commit().await.map_err(|_| PasswordResetError::Storage)
}

async fn reset_postgres(
    pool: &sqlx::PgPool,
    user_id: i64,
    password_hash: &str,
) -> Result<(), PasswordResetError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| PasswordResetError::Storage)?;
    sqlx::query(INCREMENT_AUTH_VERSION)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| PasswordResetError::Storage)?;
    sqlx::query(UPDATE_PASSWORD)
        .bind(password_hash)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| PasswordResetError::Storage)?;
    tx.commit().await.map_err(|_| PasswordResetError::Storage)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_passwords_are_twelve_lowercase_hex_characters() {
        for _ in 0..64 {
            let password = generate_verification_code(GENERATED_PASSWORD_LENGTH)
                .expect("OS randomness in tests");
            assert_eq!(password.len(), GENERATED_PASSWORD_LENGTH);
            assert!(
                password
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            );
        }
    }

    #[test]
    fn zero_length_returns_the_full_dashless_uuid() {
        assert_eq!(
            generate_verification_code(0)
                .expect("OS randomness in tests")
                .len(),
            32
        );
    }

    #[test]
    fn email_normalization_matches_go() {
        assert_eq!(
            normalize_email("  MiXeD@Example.COM \t"),
            "mixed@example.com"
        );
        assert_eq!(normalize_email("   "), "");
    }
}
