//! `passkey_credentials` 表的存储边界：Go `passkey_credential.go` 的移植。
//!
//! 列名、可空性与唯一索引与 Go GORM 模型（schema-inventory）逐项一致：
//! user_id 与 credential_id 各自唯一；Go 的 upsert/delete 一律 `Unscoped()`
//! 硬删除，deleted_at 列因此从不被业务写入，但查询保留 `deleted_at IS NULL`
//! 的 GORM 默认作用域。attestation/attachment/aaguid/user_present 等 Go 列
//! 无法从 webauthn-rs 的 safe wrapper 完整重建（见模块级差异说明）：
//! 注册侧写入实际可得的字段，重建侧按存储值原样还原。

use base64::{Engine, engine::general_purpose};
use newapi_storage::Database;
use sqlx::Row;

use crate::passkey::cose;

/// Go `IncrementUserAuthVersionWithTx`（与 two_fa 仓储同一 SQL）。
const BUMP_AUTH_VERSION: &str = "UPDATE users SET auth_version = \
    CASE WHEN COALESCE(auth_version, 0) < 1 THEN 2 ELSE COALESCE(auth_version, 0) + 1 END \
    WHERE id = $1";
const SELECT_AUTH_VERSION_UNSCOPED: &str =
    "SELECT CAST(auth_version AS BIGINT) FROM users WHERE id = $1";

/// 读取列投影：整数一律 CAST 到 BIGINT，时间一律投影为 epoch 秒，
/// 与 auth_flows 仓储的双后端约定一致。拼接出的语句只含固定常量片段、
/// 不含任何请求数据，按工作区既有约定经 `AssertSqlSafe` 声明人工审计。
pub const ASSERTION_STATE_COLUMNS_SQLITE: &str = "id, CAST(user_id AS BIGINT) AS user_id, \
    credential_id, public_key, attestation_type, aaguid, \
    CAST(sign_count AS BIGINT) AS sign_count, \
    CAST(clone_warning AS INTEGER) AS clone_warning, \
    CAST(user_present AS INTEGER) AS user_present, \
    CAST(user_verified AS INTEGER) AS user_verified, \
    CAST(backup_eligible AS INTEGER) AS backup_eligible, \
    CAST(backup_state AS INTEGER) AS backup_state, \
    transports, attachment, \
    CAST(strftime('%s', last_used_at) AS BIGINT) AS last_used_at, \
    CAST(strftime('%s', created_at) AS BIGINT) AS created_at, \
    CAST(strftime('%s', updated_at) AS BIGINT) AS updated_at";

pub const ASSERTION_STATE_COLUMNS_POSTGRES: &str = "id, CAST(user_id AS BIGINT) AS user_id, \
    credential_id, public_key, attestation_type, aaguid, \
    CAST(sign_count AS BIGINT) AS sign_count, \
    clone_warning, user_present, user_verified, backup_eligible, backup_state, \
    transports, attachment, \
    CAST(EXTRACT(EPOCH FROM last_used_at) AS BIGINT) AS last_used_at, \
    CAST(EXTRACT(EPOCH FROM created_at) AS BIGINT) AS created_at, \
    CAST(EXTRACT(EPOCH FROM updated_at) AS BIGINT) AS updated_at";

/// 固定分类；不携带 SQL 或数据库文本（Go 的 SysLog 分支同样不转述）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasskeyStoreError {
    /// Go `ErrPasskeyNotFound`。
    NotFound,
    Storage,
}

impl std::fmt::Display for PasskeyStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotFound => "passkey credential not found",
            Self::Storage => "passkey credential storage failure",
        })
    }
}

impl std::error::Error for PasskeyStoreError {}

impl From<sqlx::Error> for PasskeyStoreError {
    fn from(_: sqlx::Error) -> Self {
        Self::Storage
    }
}

impl From<cose::CoseError> for PasskeyStoreError {
    fn from(_: cose::CoseError) -> Self {
        Self::Storage
    }
}

/// `passkey_credentials` 的权威记录；last_used_at 为 epoch 秒（可空）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasskeyCredential {
    pub id: i64,
    pub user_id: i64,
    /// base64(STD) 编码的凭据 ID（Go 同为 StdEncoding）。
    pub credential_id: String,
    /// base64(STD) 编码的 COSE 公钥原始 CBOR 字节。
    pub public_key: String,
    pub attestation_type: Option<String>,
    /// base64(STD) 编码的 AAGUID；webauthn-rs 不暴露，注册恒为空串。
    pub aaguid: String,
    pub sign_count: u32,
    pub clone_warning: bool,
    pub user_present: bool,
    pub user_verified: bool,
    pub backup_eligible: bool,
    pub backup_state: bool,
    /// JSON 数组文本（`["internal","hybrid"]`），空表示无传输方式。
    pub transports: String,
    pub attachment: Option<String>,
    pub last_used_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// 注册/重建凭据所需的可变字段；user_id 由仓储方法显式传入。
#[derive(Clone, Debug)]
pub struct StoredCredential {
    pub credential_id: Vec<u8>,
    /// COSE 公钥原始 CBOR 字节。
    pub public_key: Vec<u8>,
    pub attestation_format: String,
    pub counter: u32,
    pub user_verified: bool,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub transports: Vec<String>,
    /// `platform` / `cross-platform`；Go 从注册响应的 authenticatorAttachment 取。
    pub attachment: Option<String>,
}

/// 断言（登录/二次验证）成功后需要持久化的状态（`AuthenticationResult` 的
/// 存储子集）；按方法参数包传入以回避 clippy 方法参数上限。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssertionOutcome {
    pub counter: u32,
    pub user_verified: bool,
    pub backup_eligible: bool,
    pub backup_state: bool,
}

fn decode_sqlite(row: &sqlx::sqlite::SqliteRow) -> Result<PasskeyCredential, PasskeyStoreError> {
    Ok(PasskeyCredential {
        id: row.try_get("id")?,
        user_id: row.try_get("user_id")?,
        credential_id: row
            .try_get::<Option<String>, _>("credential_id")?
            .unwrap_or_default(),
        public_key: row
            .try_get::<Option<String>, _>("public_key")?
            .unwrap_or_default(),
        attestation_type: row.try_get("attestation_type")?,
        aaguid: row
            .try_get::<Option<String>, _>("aaguid")?
            .unwrap_or_default(),
        sign_count: row.try_get::<Option<i64>, _>("sign_count")?.unwrap_or(0) as u32,
        clone_warning: row
            .try_get::<Option<bool>, _>("clone_warning")?
            .unwrap_or(false),
        user_present: row
            .try_get::<Option<bool>, _>("user_present")?
            .unwrap_or(false),
        user_verified: row
            .try_get::<Option<bool>, _>("user_verified")?
            .unwrap_or(false),
        backup_eligible: row
            .try_get::<Option<bool>, _>("backup_eligible")?
            .unwrap_or(false),
        backup_state: row
            .try_get::<Option<bool>, _>("backup_state")?
            .unwrap_or(false),
        transports: row
            .try_get::<Option<String>, _>("transports")?
            .unwrap_or_default(),
        attachment: row.try_get("attachment")?,
        last_used_at: row.try_get("last_used_at")?,
        created_at: row.try_get::<Option<i64>, _>("created_at")?.unwrap_or(0),
        updated_at: row.try_get::<Option<i64>, _>("updated_at")?.unwrap_or(0),
    })
}

fn decode_postgres(row: &sqlx::postgres::PgRow) -> Result<PasskeyCredential, PasskeyStoreError> {
    Ok(PasskeyCredential {
        id: row.try_get("id")?,
        user_id: row.try_get("user_id")?,
        credential_id: row
            .try_get::<Option<String>, _>("credential_id")?
            .unwrap_or_default(),
        public_key: row
            .try_get::<Option<String>, _>("public_key")?
            .unwrap_or_default(),
        attestation_type: row.try_get("attestation_type")?,
        aaguid: row
            .try_get::<Option<String>, _>("aaguid")?
            .unwrap_or_default(),
        sign_count: row.try_get::<Option<i64>, _>("sign_count")?.unwrap_or(0) as u32,
        clone_warning: row
            .try_get::<Option<bool>, _>("clone_warning")?
            .unwrap_or(false),
        user_present: row
            .try_get::<Option<bool>, _>("user_present")?
            .unwrap_or(false),
        user_verified: row
            .try_get::<Option<bool>, _>("user_verified")?
            .unwrap_or(false),
        backup_eligible: row
            .try_get::<Option<bool>, _>("backup_eligible")?
            .unwrap_or(false),
        backup_state: row
            .try_get::<Option<bool>, _>("backup_state")?
            .unwrap_or(false),
        transports: row
            .try_get::<Option<String>, _>("transports")?
            .unwrap_or_default(),
        attachment: row.try_get("attachment")?,
        last_used_at: row.try_get("last_used_at")?,
        created_at: row.try_get::<Option<i64>, _>("created_at")?.unwrap_or(0),
        updated_at: row.try_get::<Option<i64>, _>("updated_at")?.unwrap_or(0),
    })
}

#[derive(Clone)]
pub struct PasskeyCredentialRepository {
    db: Database,
}

impl PasskeyCredentialRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Go `GetPasskeyByUserID`：未找到返回 `NotFound`，其余错误归 `Storage`。
    pub async fn by_user_id(
        &self,
        user_id: i64,
    ) -> Result<Option<PasskeyCredential>, PasskeyStoreError> {
        match &self.db {
            Database::Sqlite(pool) => {
                let row = sqlx::query(sqlx::AssertSqlSafe(format!(
                    "SELECT {ASSERTION_STATE_COLUMNS_SQLITE} \
                     FROM passkey_credentials WHERE user_id=$1 AND deleted_at IS NULL"
                )))
                .bind(user_id)
                .fetch_optional(pool)
                .await?;
                Ok(row.as_ref().map(decode_sqlite).transpose()?)
            }
            Database::Postgres(pool) => {
                let row = sqlx::query(sqlx::AssertSqlSafe(format!(
                    "SELECT {ASSERTION_STATE_COLUMNS_POSTGRES} \
                     FROM passkey_credentials WHERE user_id=$1 AND deleted_at IS NULL"
                )))
                .bind(user_id)
                .fetch_optional(pool)
                .await?;
                Ok(row.as_ref().map(decode_postgres).transpose()?)
            }
        }
    }

    /// Go `GetPasskeyByCredentialID`：按凭据 ID 原始字节（base64 STD 比较）。
    pub async fn by_credential_id(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<PasskeyCredential>, PasskeyStoreError> {
        let encoded = general_purpose::STANDARD.encode(credential_id);
        match &self.db {
            Database::Sqlite(pool) => {
                let row = sqlx::query(sqlx::AssertSqlSafe(format!(
                    "SELECT {ASSERTION_STATE_COLUMNS_SQLITE} \
                     FROM passkey_credentials WHERE credential_id=$1 AND deleted_at IS NULL"
                )))
                .bind(&encoded)
                .fetch_optional(pool)
                .await?;
                Ok(row.as_ref().map(decode_sqlite).transpose()?)
            }
            Database::Postgres(pool) => {
                let row = sqlx::query(sqlx::AssertSqlSafe(format!(
                    "SELECT {ASSERTION_STATE_COLUMNS_POSTGRES} \
                     FROM passkey_credentials WHERE credential_id=$1 AND deleted_at IS NULL"
                )))
                .bind(&encoded)
                .fetch_optional(pool)
                .await?;
                Ok(row.as_ref().map(decode_postgres).transpose()?)
            }
        }
    }

    /// Go `UpsertPasskeyCredentialWithAuthVersion`：同事务内递增
    /// `users.auth_version`（返回递增后版本）、硬删除旧凭据、写入新凭据。
    /// Go 随后的 `PublishUserAuthCache` 尚未移植（全栈一致的已知缺口）。
    pub async fn upsert_with_auth_version(
        &self,
        user_id: i64,
        stored: &StoredCredential,
        now: i64,
    ) -> Result<i64, PasskeyStoreError> {
        if user_id <= 0 {
            return Err(PasskeyStoreError::NotFound);
        }
        match &self.db {
            Database::Sqlite(pool) => {
                let mut tx = pool.begin().await?;
                let next = bump_auth_version_sqlite(&mut tx, user_id).await?;
                sqlx::query("DELETE FROM passkey_credentials WHERE user_id=$1")
                    .bind(user_id)
                    .execute(&mut *tx)
                    .await?;
                insert_credential_sqlite(&mut tx, user_id, stored, now).await?;
                tx.commit().await?;
                Ok(next)
            }
            Database::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                let next = bump_auth_version_postgres(&mut tx, user_id).await?;
                sqlx::query("DELETE FROM passkey_credentials WHERE user_id=$1")
                    .bind(user_id)
                    .execute(&mut *tx)
                    .await?;
                insert_credential_postgres(&mut tx, user_id, stored, now).await?;
                tx.commit().await?;
                Ok(next)
            }
        }
    }

    /// Go `DeletePasskeyByUserIDWithAuthVersion`：先锁行确认存在，同事务递增
    /// `users.auth_version` 后硬删除；影响行数不为 1 即 `NotFound`。
    /// Go 随后的 `PublishUserAuthCache` 尚未移植（全栈一致的已知缺口）。
    pub async fn delete_with_auth_version(&self, user_id: i64) -> Result<i64, PasskeyStoreError> {
        if user_id <= 0 {
            return Err(PasskeyStoreError::NotFound);
        }
        match &self.db {
            Database::Sqlite(pool) => {
                let mut tx = pool.begin().await?;
                let exists = sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM passkey_credentials \
                     WHERE user_id=$1 AND deleted_at IS NULL",
                )
                .bind(user_id)
                .fetch_one(&mut *tx)
                .await?;
                if exists == 0 {
                    return Err(PasskeyStoreError::NotFound);
                }
                let next = bump_auth_version_sqlite(&mut tx, user_id).await?;
                let affected = sqlx::query(
                    "DELETE FROM passkey_credentials WHERE user_id=$1 AND deleted_at IS NULL",
                )
                .bind(user_id)
                .execute(&mut *tx)
                .await?
                .rows_affected();
                if affected != 1 {
                    return Err(PasskeyStoreError::NotFound);
                }
                tx.commit().await?;
                Ok(next)
            }
            Database::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                let locked = sqlx::query_scalar::<_, i64>(
                    "SELECT id FROM passkey_credentials \
                     WHERE user_id=$1 AND deleted_at IS NULL FOR UPDATE",
                )
                .bind(user_id)
                .fetch_optional(&mut *tx)
                .await?;
                if locked.is_none() {
                    return Err(PasskeyStoreError::NotFound);
                }
                let next = bump_auth_version_postgres(&mut tx, user_id).await?;
                let affected = sqlx::query(
                    "DELETE FROM passkey_credentials WHERE user_id=$1 AND deleted_at IS NULL",
                )
                .bind(user_id)
                .execute(&mut *tx)
                .await?
                .rows_affected();
                if affected != 1 {
                    return Err(PasskeyStoreError::NotFound);
                }
                tx.commit().await?;
                Ok(next)
            }
        }
    }

    /// Go `UpdatePasskeyAssertionState`：仅写断言产生的字段（计数器、标志、
    /// last_used_at），注册身份字段不可变。clone_warning 按计数器回退判定
    /// （counter>0 且不大于旧值即疑似克隆），与 go-webauthn 在校验期计算的
    /// 语义一致。影响行数不为 1 即 `NotFound`。
    pub async fn update_assertion_state(
        &self,
        user_id: i64,
        credential_id: &[u8],
        outcome: &AssertionOutcome,
        now: i64,
    ) -> Result<(), PasskeyStoreError> {
        if user_id <= 0 || credential_id.is_empty() {
            return Err(PasskeyStoreError::NotFound);
        }
        let encoded = general_purpose::STANDARD.encode(credential_id);
        match &self.db {
            Database::Sqlite(pool) => {
                let affected = sqlx::query(
                    "UPDATE passkey_credentials SET sign_count=$1, clone_warning=\
                     CASE WHEN ($7 > 0 AND $7 <= CAST(sign_count AS BIGINT)) THEN 1 ELSE 0 END,\
                     user_verified=$2, backup_eligible=$3, backup_state=$4,\
                     last_used_at=datetime($5,'unixepoch'), updated_at=datetime($5,'unixepoch')\
                     WHERE user_id=$6 AND credential_id=$8 AND deleted_at IS NULL",
                )
                .bind(outcome.counter as i64)
                .bind(outcome.user_verified)
                .bind(outcome.backup_eligible)
                .bind(outcome.backup_state)
                .bind(now)
                .bind(user_id)
                .bind(outcome.counter as i64)
                .bind(&encoded)
                .execute(pool)
                .await?
                .rows_affected();
                if affected != 1 {
                    return Err(PasskeyStoreError::NotFound);
                }
                Ok(())
            }
            Database::Postgres(pool) => {
                let affected = sqlx::query(
                    "UPDATE passkey_credentials SET sign_count=$1, clone_warning=\
                     ($7 > 0 AND $7 <= CAST(sign_count AS BIGINT)),\
                     user_verified=$2, backup_eligible=$3, backup_state=$4,\
                     last_used_at=to_timestamp($5::BIGINT), updated_at=to_timestamp($5::BIGINT)\
                     WHERE user_id=$6 AND credential_id=$8 AND deleted_at IS NULL",
                )
                .bind(outcome.counter as i64)
                .bind(outcome.user_verified)
                .bind(outcome.backup_eligible)
                .bind(outcome.backup_state)
                .bind(now)
                .bind(user_id)
                .bind(outcome.counter as i64)
                .bind(&encoded)
                .execute(pool)
                .await?
                .rows_affected();
                if affected != 1 {
                    return Err(PasskeyStoreError::NotFound);
                }
                Ok(())
            }
        }
    }
}

async fn bump_auth_version_sqlite(
    tx: &mut sqlx::SqliteConnection,
    user_id: i64,
) -> Result<i64, PasskeyStoreError> {
    let affected = sqlx::query(BUMP_AUTH_VERSION)
        .bind(user_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if affected != 1 {
        return Err(PasskeyStoreError::NotFound);
    }
    let version: i64 = sqlx::query_scalar(SELECT_AUTH_VERSION_UNSCOPED)
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;
    Ok(version)
}

async fn bump_auth_version_postgres(
    tx: &mut sqlx::PgConnection,
    user_id: i64,
) -> Result<i64, PasskeyStoreError> {
    let affected = sqlx::query(BUMP_AUTH_VERSION)
        .bind(user_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if affected != 1 {
        return Err(PasskeyStoreError::NotFound);
    }
    let version: i64 = sqlx::query_scalar(SELECT_AUTH_VERSION_UNSCOPED)
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;
    Ok(version)
}

fn transports_json(transports: &[String]) -> String {
    if transports.is_empty() {
        return String::new();
    }
    serde_json::to_string(transports).unwrap_or_default()
}

async fn insert_credential_sqlite(
    tx: &mut sqlx::SqliteConnection,
    user_id: i64,
    stored: &StoredCredential,
    now: i64,
) -> Result<(), PasskeyStoreError> {
    sqlx::query(
        "INSERT INTO passkey_credentials (user_id, credential_id, public_key, \
         attestation_type, aaguid, sign_count, clone_warning, user_present, \
         user_verified, backup_eligible, backup_state, transports, attachment, \
         last_used_at, created_at, updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NULL,\
         datetime($14,'unixepoch'),datetime($14,'unixepoch'))",
    )
    .bind(user_id)
    .bind(general_purpose::STANDARD.encode(&stored.credential_id))
    .bind(general_purpose::STANDARD.encode(&stored.public_key))
    .bind(&stored.attestation_format)
    .bind("")
    .bind(stored.counter as i64)
    .bind(0_i64)
    .bind(0_i64)
    .bind(stored.user_verified)
    .bind(stored.backup_eligible)
    .bind(stored.backup_state)
    .bind(transports_json(&stored.transports))
    .bind(stored.attachment.as_deref().unwrap_or(""))
    .bind(now)
    .execute(&mut *tx)
    .await?;
    Ok(())
}

async fn insert_credential_postgres(
    tx: &mut sqlx::PgConnection,
    user_id: i64,
    stored: &StoredCredential,
    now: i64,
) -> Result<(), PasskeyStoreError> {
    sqlx::query(
        "INSERT INTO passkey_credentials (user_id, credential_id, public_key, \
         attestation_type, aaguid, sign_count, clone_warning, user_present, \
         user_verified, backup_eligible, backup_state, transports, attachment, \
         last_used_at, created_at, updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NULL,\
         to_timestamp($14::BIGINT),to_timestamp($14::BIGINT))",
    )
    .bind(user_id)
    .bind(general_purpose::STANDARD.encode(&stored.credential_id))
    .bind(general_purpose::STANDARD.encode(&stored.public_key))
    .bind(&stored.attestation_format)
    .bind("")
    .bind(stored.counter as i64)
    .bind(false)
    .bind(false)
    .bind(stored.user_verified)
    .bind(stored.backup_eligible)
    .bind(stored.backup_state)
    .bind(transports_json(&stored.transports))
    .bind(stored.attachment.as_deref().unwrap_or(""))
    .bind(now)
    .execute(&mut *tx)
    .await?;
    Ok(())
}

impl PasskeyCredential {
    /// 重建 verify/login 所需的 `webauthn_rs::prelude::Credential`。
    ///
    /// webauthn-rs 的 safe wrapper 不公开 `RegisteredExtensions` 与
    /// `AuthenticatorTransport` 类型名，因此经 `serde_json::Value` 组装修复
    /// CredentialV5 的字段（`extensions` 全部 `#[serde(default)]`、
    /// `transports` 的未知名条目经 `#[serde(other)]` 归入 Unknown）。
    /// 公钥按存储的 COSE CBOR 字节解析后走 COSEKey 的 JSON 形状；
    /// attestation 与 registration_policy 不参与断言校验，按可重建值填入
    /// （attestation 为 `ParsedAttestation` 的默认形态 `data/metadata` 均为
    /// `None`；Go 亦不持久化注册期 UV 策略，默认 preferred 与其一致）。
    pub fn to_webauthn_credential(
        &self,
    ) -> Result<webauthn_rs::prelude::Credential, PasskeyStoreError> {
        let public_key = general_purpose::STANDARD
            .decode(&self.public_key)
            .map_err(|_| PasskeyStoreError::Storage)?;
        let credential_id = general_purpose::STANDARD
            .decode(&self.credential_id)
            .map_err(|_| PasskeyStoreError::Storage)?;
        let cred = cose::decode_cose_key(&public_key)?;
        let cred_json = serde_json::to_value(&cred).map_err(|_| PasskeyStoreError::Storage)?;
        let transports = if self.transports.trim().is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_str(&self.transports).unwrap_or(serde_json::Value::Null)
        };
        let attestation_format = self
            .attestation_type
            .as_deref()
            .filter(|value| {
                matches!(
                    *value,
                    "none"
                        | "packed"
                        | "tpm"
                        | "android-key"
                        | "android-safetynet"
                        | "fido-u2f"
                        | "apple"
                )
            })
            .unwrap_or("none");
        let json = serde_json::json!({
            "cred_id": general_purpose::URL_SAFE_NO_PAD.encode(credential_id),
            "cred": cred_json,
            "counter": self.sign_count,
            "transports": transports,
            "user_verified": self.user_verified,
            "backup_eligible": self.backup_eligible,
            "backup_state": self.backup_state,
            "registration_policy": "preferred",
            "extensions": {},
            "attestation": {"data": "None", "metadata": "None"},
            "attestation_format": attestation_format,
        });
        serde_json::from_value::<webauthn_rs::prelude::Credential>(json)
            .map_err(|_| PasskeyStoreError::Storage)
    }
}
