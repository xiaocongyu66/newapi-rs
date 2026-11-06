//! 2FA 读取、TOTP/备用码校验、失败锁定与管理端点事务。
//!
//! 表结构严格对齐 Go `identity.TwoFA` / `identity.TwoFABackupCode` 的
//! GORM 列名：`two_fas`、`two_fa_backup_codes`。时间列在数据库中是
//! timestamp，Rust 边界统一转换为调用方提供的 Unix 秒。

use std::fmt;

use hmac::{Hmac, Mac};
use newapi_storage::Database;
use rand::{RngCore, rngs::OsRng};
use sha1::Sha1;
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
    /// Go `ErrTwoFAAlreadyEnabled` / “2FA已经启用”。
    AlreadyEnabled,
    /// Go “用户已存在2FA设置”。
    AlreadyExists,
    /// Go `GetUserById` 找不到待设置用户。
    UserNotFound,
    /// 待验证设置已不存在（Go `DeletePendingTwoFASetup` 的 ErrRecordNotFound）。
    SetupRequired,
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
            Self::AlreadyEnabled => "2FA is already enabled",
            Self::AlreadyExists => "2FA setup already exists",
            Self::UserNotFound => "user does not exist",
            Self::SetupRequired => "2FA setup is required",
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
            Self::AlreadyEnabled => plain("twofa.already_enabled"),
            Self::AlreadyExists => plain("twofa.already_exists"),
            Self::UserNotFound => plain("twofa.user_not_found"),
            Self::SetupRequired => plain("twofa.setup_required"),
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

/// Go `common.BackupCodeCount`。
pub const BACKUP_CODE_COUNT: usize = 4;
/// Go `common.BackupCodeLength`（不含 `XXXX-XXXX` 分隔符）。
pub const BACKUP_CODE_LENGTH: usize = 8;
/// Go `common.Get2FAIssuer()` 默认值（`common.SystemName`）。
///
/// `SystemName` option 尚未进入 catalog 快照；这里使用 Go 的编译期默认值，
/// 与 `apps/server/src/status.rs` 的 `DEFAULT_SYSTEM_NAME` 保持一致。
pub const TWO_FA_ISSUER: &str = "New API";

const TOTP_PERIOD_SECONDS: i64 = 30;
const TOTP_MODULUS: u32 = 1_000_000;
const BACKUP_CODE_CHARSET: &[u8; 36] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Go `common.GenerateTOTPSecret`：20 字节 CSPRNG 密钥的 base32（无 padding）。
///
/// pquerna/otp `totp.Generate` 的默认 `SecretSize` 为 20；返回 `None` 表示
/// 操作系统随机源不可用，由调用方映射为固定的生成失败文案。
pub fn generate_totp_secret() -> Option<String> {
    let mut bytes = [0u8; 20];
    OsRng.try_fill_bytes(&mut bytes).ok()?;
    Some(base32_encode(&bytes))
}

/// Go `common.GenerateBackupCodes`：4 个 `XXXX-XXXX`（A-Z0-9）备用码。
pub fn generate_backup_codes() -> Option<Vec<String>> {
    let mut codes = Vec::with_capacity(BACKUP_CODE_COUNT);
    for _ in 0..BACKUP_CODE_COUNT {
        let mut raw = [0u8; BACKUP_CODE_LENGTH];
        for slot in &mut raw {
            let mut byte = [0u8; 1];
            OsRng.try_fill_bytes(&mut byte).ok()?;
            // Go 对单个随机字节取模；这里保持同一分布。
            *slot = BACKUP_CODE_CHARSET[usize::from(byte[0]) % BACKUP_CODE_CHARSET.len()];
        }
        let text = std::str::from_utf8(&raw).ok()?;
        codes.push(format!("{}-{}", &text[..4], &text[4..]));
    }
    Some(codes)
}

/// Go `common.GenerateQRCodeData` 的逐字节拼接：`otpauth://totp/{issuer}:{username} ({issuer})?secret=...`
/// ——Go 不做 URL 编码，因此这里也不编码。
pub fn generate_qr_code_data(secret: &str, username: &str) -> String {
    let account = format!("{username} ({TWO_FA_ISSUER})");
    format!(
        "otpauth://totp/{TWO_FA_ISSUER}:{account}?secret={secret}&issuer={TWO_FA_ISSUER}&digits=6&period=30"
    )
}

/// 确定性 TOTP 投影（RFC 4226 截断，30 秒周期），用于测试与运维工具。
///
/// 生产校验始终走 [`validate_totp_code`]（含 ±1 步窗口）；本函数只返回
/// `now` 对应时间步的六位码，输入非法时返回 `None`。
pub fn totp_code_at(secret: &str, now: i64) -> Option<String> {
    if now < 0 {
        return None;
    }
    let key = decode_secret_base32(secret)?;
    let counter = u64::try_from(now / TOTP_PERIOD_SECONDS).ok()?;
    let mut mac = Hmac::<Sha1>::new_from_slice(&key).ok()?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[19] & 0x0f);
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    Some(format!("{:06}", binary % TOTP_MODULUS))
}

fn base32_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(BASE32_ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        output.push(BASE32_ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    output
}

// 与 `crate::two_fa::totp` 的私有解码器语义一致：大小写不敏感、无 padding、
// 忽略 `\r`/`\n`，长度余数 1/3/6 非法。
fn decode_secret_base32(secret: &str) -> Option<Vec<u8>> {
    let secret = secret.trim();
    let mut output = Vec::with_capacity(secret.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    let mut symbols: usize = 0;
    for byte in secret.bytes() {
        if byte == b'\r' || byte == b'\n' {
            continue;
        }
        let value = match byte.to_ascii_uppercase() {
            b'A'..=b'Z' => byte.to_ascii_uppercase() - b'A',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        symbols += 1;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1u32 << bits) - 1;
        }
    }
    match symbols % 8 {
        1 | 3 | 6 => None,
        _ => Some(output),
    }
}

fn hash_backup_codes(codes: &[String]) -> Result<Vec<String>, TwoFaError> {
    codes
        .iter()
        .map(|code| {
            let normalized = normalize_backup_code(code).ok_or(TwoFaError::Unavailable)?;
            crypto::hash_password(normalized.as_bytes())
                .map(|hash| hash.expose_secret().to_owned())
                .map_err(|_| TwoFaError::Unavailable)
        })
        .collect()
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

    /// Go `GetUserById` 中本切片所需的唯一列；未软删除的用户才可见。
    pub async fn username(&self, user_id: i64) -> Result<Option<String>, TwoFaError> {
        if user_id == 0 {
            return Err(TwoFaError::InvalidUser);
        }
        match &self.database {
            Database::Sqlite(pool) => sqlx::query_scalar::<_, String>(SELECT_USERNAME)
                .bind(user_id)
                .fetch_optional(pool)
                .await
                .map_err(|_| TwoFaError::Unavailable),
            Database::Postgres(pool) => sqlx::query_scalar::<_, String>(SELECT_USERNAME)
                .bind(user_id)
                .fetch_optional(pool)
                .await
                .map_err(|_| TwoFaError::Unavailable),
        }
    }

    /// Go `DeletePendingTwoFASetup`：仅删除 `is_enabled=false` 的记录；备用码与
    /// 主记录均 Unscoped 硬删除。
    pub async fn delete_pending_setup(&self, user_id: i64) -> Result<(), TwoFaError> {
        if user_id == 0 {
            return Err(TwoFaError::InvalidUser);
        }
        match &self.database {
            Database::Sqlite(pool) => {
                let mut tx = pool.begin().await.map_err(|_| TwoFaError::Unavailable)?;
                let id = select_factor_id(&mut tx, user_id, false).await?;
                let Some(id) = id else {
                    return Err(TwoFaError::SetupRequired);
                };
                hard_delete_backup_codes(&mut tx, user_id).await?;
                sqlx::query(HARD_DELETE_FACTOR_BY_ID)
                    .bind(id)
                    .execute(&mut tx)
                    .await
                    .map_err(|_| TwoFaError::Unavailable)?;
                tx.commit().await.map_err(|_| TwoFaError::Unavailable)?;
                Ok(())
            }
            Database::Postgres(pool) => {
                let mut tx = pool.begin().await.map_err(|_| TwoFaError::Unavailable)?;
                let id = select_factor_id_locked(&mut tx, user_id, false).await?;
                let Some(id) = id else {
                    return Err(TwoFaError::SetupRequired);
                };
                hard_delete_backup_codes_pg(&mut tx, user_id).await?;
                sqlx::query(HARD_DELETE_FACTOR_BY_ID)
                    .bind(id)
                    .execute(&mut tx)
                    .await
                    .map_err(|_| TwoFaError::Unavailable)?;
                tx.commit().await.map_err(|_| TwoFaError::Unavailable)?;
                Ok(())
            }
        }
    }

    /// Go `CreatePendingTwoFASetup`：先确认用户存在且没有既有记录（含软删除），
    /// 再写入 `is_enabled=false` 的待验证记录。
    pub async fn create_pending_setup(
        &self,
        user_id: i64,
        secret: &str,
        now: i64,
    ) -> Result<(), TwoFaError> {
        if user_id == 0 {
            return Err(TwoFaError::InvalidUser);
        }
        match &self.database {
            Database::Sqlite(pool) => {
                let mut tx = pool.begin().await.map_err(|_| TwoFaError::Unavailable)?;
                let existing = sqlx::query_scalar::<_, i64>(SELECT_ANY_FACTOR_ID)
                    .bind(user_id)
                    .fetch_optional(&mut tx)
                    .await
                    .map_err(|_| TwoFaError::Unavailable)?;
                if existing.is_some() {
                    return Err(TwoFaError::AlreadyExists);
                }
                let user = sqlx::query_scalar::<_, String>(SELECT_USERNAME)
                    .bind(user_id)
                    .fetch_optional(&mut tx)
                    .await
                    .map_err(|_| TwoFaError::Unavailable)?;
                if user.is_none() {
                    return Err(TwoFaError::UserNotFound);
                }
                sqlx::query(INSERT_PENDING_SQLITE)
                    .bind(user_id)
                    .bind(secret)
                    .bind(false)
                    .bind(now)
                    .execute(&mut tx)
                    .await
                    .map_err(|_| TwoFaError::Unavailable)?;
                tx.commit().await.map_err(|_| TwoFaError::Unavailable)?;
                Ok(())
            }
            Database::Postgres(pool) => {
                let mut tx = pool.begin().await.map_err(|_| TwoFaError::Unavailable)?;
                let existing = sqlx::query_scalar::<_, i64>(SELECT_ANY_FACTOR_ID)
                    .bind(user_id)
                    .fetch_optional(&mut tx)
                    .await
                    .map_err(|_| TwoFaError::Unavailable)?;
                if existing.is_some() {
                    return Err(TwoFaError::AlreadyExists);
                }
                let user = sqlx::query_scalar::<_, String>(SELECT_USERNAME)
                    .bind(user_id)
                    .fetch_optional(&mut tx)
                    .await
                    .map_err(|_| TwoFaError::Unavailable)?;
                if user.is_none() {
                    return Err(TwoFaError::UserNotFound);
                }
                sqlx::query(INSERT_PENDING_POSTGRES)
                    .bind(user_id)
                    .bind(secret)
                    .bind(false)
                    .bind(now)
                    .execute(&mut tx)
                    .await
                    .map_err(|_| TwoFaError::Unavailable)?;
                tx.commit().await.map_err(|_| TwoFaError::Unavailable)?;
                Ok(())
            }
        }
    }

    /// Go `CreatePendingTwoFASetupBackupCodes`：锁定待验证记录后软删除旧码，
    /// 再写入新码（bcrypt cost 10）。
    pub async fn create_pending_backup_codes(
        &self,
        user_id: i64,
        codes: &[String],
        now: i64,
    ) -> Result<(), TwoFaError> {
        if user_id == 0 {
            return Err(TwoFaError::InvalidUser);
        }
        let hashes = hash_backup_codes(codes)?;
        match &self.database {
            Database::Sqlite(pool) => {
                let mut tx = pool.begin().await.map_err(|_| TwoFaError::Unavailable)?;
                let pending = select_factor_id(&mut tx, user_id, false).await?;
                if pending.is_none() {
                    return Err(TwoFaError::SetupRequired);
                }
                sqlx::query(SOFT_DELETE_CODES_SQLITE)
                    .bind(user_id)
                    .bind(now)
                    .execute(&mut tx)
                    .await
                    .map_err(|_| TwoFaError::Unavailable)?;
                insert_backup_codes_sqlite(&mut tx, user_id, &hashes, now).await?;
                tx.commit().await.map_err(|_| TwoFaError::Unavailable)?;
                Ok(())
            }
            Database::Postgres(pool) => {
                let mut tx = pool.begin().await.map_err(|_| TwoFaError::Unavailable)?;
                let pending = select_factor_id_locked(&mut tx, user_id, false).await?;
                if pending.is_none() {
                    return Err(TwoFaError::SetupRequired);
                }
                sqlx::query(SOFT_DELETE_CODES_POSTGRES)
                    .bind(user_id)
                    .bind(now)
                    .execute(&mut tx)
                    .await
                    .map_err(|_| TwoFaError::Unavailable)?;
                insert_backup_codes_postgres(&mut tx, user_id, &hashes, now).await?;
                tx.commit().await.map_err(|_| TwoFaError::Unavailable)?;
                Ok(())
            }
        }
    }

    /// Go `GetUnusedBackupCodeCount`：排除已使用与软删除的备用码。
    pub async fn unused_backup_code_count(&self, user_id: i64) -> Result<i64, TwoFaError> {
        if user_id == 0 {
            return Err(TwoFaError::InvalidUser);
        }
        match &self.database {
            Database::Sqlite(pool) => sqlx::query_scalar::<_, i64>(COUNT_UNUSED_CODES)
                .bind(user_id)
                .bind(false)
                .fetch_one(pool)
                .await
                .map_err(|_| TwoFaError::Unavailable),
            Database::Postgres(pool) => sqlx::query_scalar::<_, i64>(COUNT_UNUSED_CODES)
                .bind(user_id)
                .bind(false)
                .fetch_one(pool)
                .await
                .map_err(|_| TwoFaError::Unavailable),
        }
    }

    /// Go `EnableWithAuthVersion`：同一事务内启用待验证记录并递增
    /// `users.auth_version`，返回递增后的版本供会话轮换使用。
    pub async fn enable_with_auth_version(
        &self,
        user_id: i64,
        now: i64,
    ) -> Result<i64, TwoFaError> {
        if user_id == 0 {
            return Err(TwoFaError::InvalidUser);
        }
        match &self.database {
            Database::Sqlite(pool) => {
                let mut tx = pool.begin().await.map_err(|_| TwoFaError::Unavailable)?;
                let id = select_factor_id(&mut tx, user_id, false).await?;
                let Some(id) = id else {
                    return Err(TwoFaError::AlreadyEnabled);
                };
                let next = bump_auth_version_sqlite(&mut tx, user_id).await?;
                let affected = sqlx::query(UPDATE_ENABLE_SQLITE)
                    .bind(true)
                    .bind(now)
                    .bind(id)
                    .bind(false)
                    .execute(&mut tx)
                    .await
                    .map_err(|_| TwoFaError::Unavailable)?
                    .rows_affected();
                if affected != 1 {
                    return Err(TwoFaError::AlreadyEnabled);
                }
                tx.commit().await.map_err(|_| TwoFaError::Unavailable)?;
                Ok(next)
            }
            Database::Postgres(pool) => {
                let mut tx = pool.begin().await.map_err(|_| TwoFaError::Unavailable)?;
                let id = select_factor_id_locked(&mut tx, user_id, false).await?;
                let Some(id) = id else {
                    return Err(TwoFaError::AlreadyEnabled);
                };
                let next = bump_auth_version_postgres(&mut tx, user_id).await?;
                let affected = sqlx::query(UPDATE_ENABLE_POSTGRES)
                    .bind(true)
                    .bind(now)
                    .bind(id)
                    .bind(false)
                    .execute(&mut tx)
                    .await
                    .map_err(|_| TwoFaError::Unavailable)?
                    .rows_affected();
                if affected != 1 {
                    return Err(TwoFaError::AlreadyEnabled);
                }
                tx.commit().await.map_err(|_| TwoFaError::Unavailable)?;
                Ok(next)
            }
        }
    }

    /// Go `DisableTwoFAWithAuthVersion`：同一事务内硬删除 2FA 记录与备用码，
    /// 并递增 `users.auth_version`。
    pub async fn disable_with_auth_version(
        &self,
        user_id: i64,
        _now: i64,
    ) -> Result<i64, TwoFaError> {
        if user_id == 0 {
            return Err(TwoFaError::InvalidUser);
        }
        match &self.database {
            Database::Sqlite(pool) => {
                let mut tx = pool.begin().await.map_err(|_| TwoFaError::Unavailable)?;
                let id = select_factor_id(&mut tx, user_id, true).await?;
                let Some(id) = id else {
                    return Err(TwoFaError::NotEnabled);
                };
                let next = bump_auth_version_sqlite(&mut tx, user_id).await?;
                hard_delete_backup_codes(&mut tx, user_id).await?;
                sqlx::query(HARD_DELETE_FACTOR_BY_ID)
                    .bind(id)
                    .execute(&mut tx)
                    .await
                    .map_err(|_| TwoFaError::Unavailable)?;
                tx.commit().await.map_err(|_| TwoFaError::Unavailable)?;
                Ok(next)
            }
            Database::Postgres(pool) => {
                let mut tx = pool.begin().await.map_err(|_| TwoFaError::Unavailable)?;
                let id = select_factor_id_locked(&mut tx, user_id, true).await?;
                let Some(id) = id else {
                    return Err(TwoFaError::NotEnabled);
                };
                let next = bump_auth_version_postgres(&mut tx, user_id).await?;
                hard_delete_backup_codes_pg(&mut tx, user_id).await?;
                sqlx::query(HARD_DELETE_FACTOR_BY_ID)
                    .bind(id)
                    .execute(&mut tx)
                    .await
                    .map_err(|_| TwoFaError::Unavailable)?;
                tx.commit().await.map_err(|_| TwoFaError::Unavailable)?;
                Ok(next)
            }
        }
    }

    /// Go `ReplaceBackupCodesWithAuthVersion`：锁定已启用记录，递增
    /// `users.auth_version`，软删除旧码并写入新码。
    pub async fn replace_backup_codes_with_auth_version(
        &self,
        user_id: i64,
        codes: &[String],
        now: i64,
    ) -> Result<i64, TwoFaError> {
        if user_id == 0 {
            return Err(TwoFaError::InvalidUser);
        }
        let hashes = hash_backup_codes(codes)?;
        match &self.database {
            Database::Sqlite(pool) => {
                let mut tx = pool.begin().await.map_err(|_| TwoFaError::Unavailable)?;
                let id = select_factor_id(&mut tx, user_id, true).await?;
                if id.is_none() {
                    return Err(TwoFaError::NotEnabled);
                }
                let next = bump_auth_version_sqlite(&mut tx, user_id).await?;
                sqlx::query(SOFT_DELETE_CODES_SQLITE)
                    .bind(user_id)
                    .bind(now)
                    .execute(&mut tx)
                    .await
                    .map_err(|_| TwoFaError::Unavailable)?;
                insert_backup_codes_sqlite(&mut tx, user_id, &hashes, now).await?;
                tx.commit().await.map_err(|_| TwoFaError::Unavailable)?;
                Ok(next)
            }
            Database::Postgres(pool) => {
                let mut tx = pool.begin().await.map_err(|_| TwoFaError::Unavailable)?;
                let id = select_factor_id_locked(&mut tx, user_id, true).await?;
                if id.is_none() {
                    return Err(TwoFaError::NotEnabled);
                }
                let next = bump_auth_version_postgres(&mut tx, user_id).await?;
                sqlx::query(SOFT_DELETE_CODES_POSTGRES)
                    .bind(user_id)
                    .bind(now)
                    .execute(&mut tx)
                    .await
                    .map_err(|_| TwoFaError::Unavailable)?;
                insert_backup_codes_postgres(&mut tx, user_id, &hashes, now).await?;
                tx.commit().await.map_err(|_| TwoFaError::Unavailable)?;
                Ok(next)
            }
        }
    }

    /// Go `Disable2FA` 的校验顺序：锁定 → （数字格式合法时）TOTP → 复检锁定
    /// → 备用码。与登录路径不同，增量失败计数/用量更新的错误在 Go 中被吞掉。
    pub async fn validate_disable_code(
        &self,
        user_id: i64,
        code: &str,
        numeric_code: Option<&str>,
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
        if let Some(numeric) = numeric_code {
            if validate_totp_code(&two_fa.secret, numeric, now) {
                verified = true;
            } else {
                let _ = self.increment_failed_attempts(&mut two_fa, now).await;
            }
        }

        if !verified {
            if let Some(until) = two_fa.locked_until.filter(|until| now < *until) {
                return Err(TwoFaError::Locked { until });
            }
            if !self.validate_backup_code(user_id, code, now).await? {
                let _ = self.increment_failed_attempts(&mut two_fa, now).await;
                return Err(TwoFaError::Incorrect);
            }
        }

        // Go 在成功后只记日志，不把 usage 更新错误返回给调用方。
        let _ = self.reset_usage(two_fa.id, now).await;
        Ok(())
    }

    /// Go `ValidateTOTPAndUpdateUsage`：仅 TOTP（备用码重新生成端点），带锁定
    /// 与失败计数语义；计数/用量更新失败不改变响应。
    pub async fn validate_totp_management(
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
        if !validate_totp_code(&two_fa.secret, code, now) {
            let _ = self.increment_failed_attempts(&mut two_fa, now).await;
            return Err(TwoFaError::Incorrect);
        }
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

async fn select_factor_id(
    tx: &mut sqlx::SqliteConnection,
    user_id: i64,
    is_enabled: bool,
) -> Result<Option<i64>, TwoFaError> {
    sqlx::query_scalar::<_, i64>(SELECT_FACTOR_ID)
        .bind(user_id)
        .bind(is_enabled)
        .fetch_optional(&mut tx)
        .await
        .map_err(|_| TwoFaError::Unavailable)
}

async fn select_factor_id_locked(
    tx: &mut sqlx::PgConnection,
    user_id: i64,
    is_enabled: bool,
) -> Result<Option<i64>, TwoFaError> {
    sqlx::query_scalar::<_, i64>(SELECT_FACTOR_ID_LOCKED)
        .bind(user_id)
        .bind(is_enabled)
        .fetch_optional(&mut tx)
        .await
        .map_err(|_| TwoFaError::Unavailable)
}

async fn hard_delete_backup_codes(
    tx: &mut sqlx::SqliteConnection,
    user_id: i64,
) -> Result<(), TwoFaError> {
    sqlx::query(HARD_DELETE_BACKUP_CODES)
        .bind(user_id)
        .execute(&mut tx)
        .await
        .map(|_| ())
        .map_err(|_| TwoFaError::Unavailable)
}

async fn hard_delete_backup_codes_pg(
    tx: &mut sqlx::PgConnection,
    user_id: i64,
) -> Result<(), TwoFaError> {
    sqlx::query(HARD_DELETE_BACKUP_CODES)
        .bind(user_id)
        .execute(&mut tx)
        .await
        .map(|_| ())
        .map_err(|_| TwoFaError::Unavailable)
}

async fn insert_backup_codes_sqlite(
    tx: &mut sqlx::SqliteConnection,
    user_id: i64,
    hashes: &[String],
    now: i64,
) -> Result<(), TwoFaError> {
    for hash in hashes {
        sqlx::query(INSERT_BACKUP_CODE_SQLITE)
            .bind(user_id)
            .bind(hash)
            .bind(false)
            .bind(now)
            .execute(&mut tx)
            .await
            .map_err(|_| TwoFaError::Unavailable)?;
    }
    Ok(())
}

async fn insert_backup_codes_postgres(
    tx: &mut sqlx::PgConnection,
    user_id: i64,
    hashes: &[String],
    now: i64,
) -> Result<(), TwoFaError> {
    for hash in hashes {
        sqlx::query(INSERT_BACKUP_CODE_POSTGRES)
            .bind(user_id)
            .bind(hash)
            .bind(false)
            .bind(now)
            .execute(&mut tx)
            .await
            .map_err(|_| TwoFaError::Unavailable)?;
    }
    Ok(())
}

// Go `IncrementUserAuthVersionWithTx`：NULL/0 旧版本从 1 起步；更新后在同一
// 事务内读回递增后的版本。未使用 RETURNING，保持 SQLite/PostgreSQL 同一形状。
async fn bump_auth_version_sqlite(
    tx: &mut sqlx::SqliteConnection,
    user_id: i64,
) -> Result<i64, TwoFaError> {
    let affected = sqlx::query(BUMP_AUTH_VERSION)
        .bind(user_id)
        .execute(&mut tx)
        .await
        .map_err(|_| TwoFaError::Unavailable)?
        .rows_affected();
    if affected != 1 {
        return Err(TwoFaError::UserNotFound);
    }
    sqlx::query_scalar::<_, i64>(SELECT_AUTH_VERSION_UNSCOPED)
        .bind(user_id)
        .fetch_one(&mut tx)
        .await
        .map_err(|_| TwoFaError::Unavailable)
}

async fn bump_auth_version_postgres(
    tx: &mut sqlx::PgConnection,
    user_id: i64,
) -> Result<i64, TwoFaError> {
    let affected = sqlx::query(BUMP_AUTH_VERSION)
        .bind(user_id)
        .execute(&mut tx)
        .await
        .map_err(|_| TwoFaError::Unavailable)?
        .rows_affected();
    if affected != 1 {
        return Err(TwoFaError::UserNotFound);
    }
    sqlx::query_scalar::<_, i64>(SELECT_AUTH_VERSION_UNSCOPED)
        .bind(user_id)
        .fetch_one(&mut tx)
        .await
        .map_err(|_| TwoFaError::Unavailable)
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

const SELECT_USERNAME: &str = "SELECT username FROM users WHERE id = $1 AND deleted_at IS NULL";

const SELECT_ANY_FACTOR_ID: &str = "SELECT id FROM two_fas WHERE user_id = $1 ORDER BY id LIMIT 1";

const SELECT_FACTOR_ID: &str = "SELECT id FROM two_fas \
    WHERE user_id = $1 AND is_enabled = $2 AND deleted_at IS NULL ORDER BY id LIMIT 1";

const SELECT_FACTOR_ID_LOCKED: &str = "SELECT id FROM two_fas \
    WHERE user_id = $1 AND is_enabled = $2 AND deleted_at IS NULL ORDER BY id LIMIT 1 FOR UPDATE";

const INSERT_PENDING_SQLITE: &str = "INSERT INTO two_fas \
    (user_id, secret, is_enabled, failed_attempts, created_at, updated_at) \
    VALUES ($1, $2, $3, 0, datetime($4, 'unixepoch'), datetime($4, 'unixepoch'))";

const INSERT_PENDING_POSTGRES: &str = "INSERT INTO two_fas \
    (user_id, secret, is_enabled, failed_attempts, created_at, updated_at) \
    VALUES ($1, $2, $3, 0, to_timestamp($4::BIGINT), to_timestamp($4::BIGINT))";

const SOFT_DELETE_CODES_SQLITE: &str = "UPDATE two_fa_backup_codes \
    SET deleted_at = datetime($2, 'unixepoch') \
    WHERE user_id = $1 AND deleted_at IS NULL";

const SOFT_DELETE_CODES_POSTGRES: &str = "UPDATE two_fa_backup_codes \
    SET deleted_at = to_timestamp($2::BIGINT) \
    WHERE user_id = $1 AND deleted_at IS NULL";

const HARD_DELETE_BACKUP_CODES: &str = "DELETE FROM two_fa_backup_codes WHERE user_id = $1";

const HARD_DELETE_FACTOR_BY_ID: &str = "DELETE FROM two_fas WHERE id = $1";

const INSERT_BACKUP_CODE_SQLITE: &str = "INSERT INTO two_fa_backup_codes \
    (user_id, code_hash, is_used, created_at) \
    VALUES ($1, $2, $3, datetime($4, 'unixepoch'))";

const INSERT_BACKUP_CODE_POSTGRES: &str = "INSERT INTO two_fa_backup_codes \
    (user_id, code_hash, is_used, created_at) \
    VALUES ($1, $2, $3, to_timestamp($4::BIGINT))";

const COUNT_UNUSED_CODES: &str = "SELECT COUNT(*) FROM two_fa_backup_codes \
    WHERE user_id = $1 AND is_used = $2 AND deleted_at IS NULL";

const UPDATE_ENABLE_SQLITE: &str = "UPDATE two_fas SET is_enabled = $1, failed_attempts = 0, \
    locked_until = NULL, updated_at = datetime($2, 'unixepoch') \
    WHERE id = $3 AND is_enabled = $4 AND deleted_at IS NULL";

const UPDATE_ENABLE_POSTGRES: &str = "UPDATE two_fas SET is_enabled = $1, failed_attempts = 0, \
    locked_until = NULL, updated_at = to_timestamp($2::BIGINT) \
    WHERE id = $3 AND is_enabled = $4 AND deleted_at IS NULL";

const BUMP_AUTH_VERSION: &str = "UPDATE users SET auth_version = \
    CASE WHEN COALESCE(auth_version, 0) < 1 THEN 2 ELSE COALESCE(auth_version, 0) + 1 END \
    WHERE id = $1";

const SELECT_AUTH_VERSION_UNSCOPED: &str =
    "SELECT CAST(auth_version AS BIGINT) FROM users WHERE id = $1";

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
