//! 密码注册所需的用户创建、邀请码查询与邮箱验证码缓存。
//!
//! Go 参考：`identity.Register` → `User.Insert`（
//! `apps/api/internal/identity/store_users.go`）与
//! `common/verification.go`。本模块不做 HTTP、鉴权或会话处理。

use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
    time::Instant,
};

use newapi_storage::Database;
use rand::Rng;
use sqlx::{PgPool, SqlitePool};

/// Go `User.Insert` 写入的默认 `setting`：`SetSetting(dto.UserSetting{})` 的
/// 序列化结果。`GotifyPriority` 没有 `omitempty`，所以空设置不是空字符串。
pub const DEFAULT_USER_SETTING: &str = r#"{"gotify_priority":0}"#;

const VERIFICATION_VALID_SECONDS: u64 = 600;
const VERIFICATION_MAP_MAX_SIZE: usize = 10;

/// Go `common.EmailVerificationPurpose`：注册邮箱验证码。
pub const EMAIL_VERIFICATION_PURPOSE: &str = "v";

/// 密码重置验证码的用途。Go 使用 `common.PasswordResetPurpose`（值为 `"r"`）；
/// 本移植按既定接口约定使用独立的 `"p"`，与 `"v"` 互不影响。
/// 阶段化端点（发送重置邮件）必须复用该常量。
pub const PASSWORD_RESET_PURPOSE: &str = "p";

struct VerificationEntry {
    code: String,
    stored_at: Instant,
}

fn verification_map() -> &'static Mutex<HashMap<String, VerificationEntry>> {
    static MAP: OnceLock<Mutex<HashMap<String, VerificationEntry>>> = OnceLock::new();
    MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Go 把验证码存放在 `purpose + key` 下；同样拼接可避免不同用途互相覆盖。
fn verification_key(purpose: &str, key: &str) -> String {
    format!("{purpose}{key}")
}

/// Go `RegisterVerificationCodeWithKey`：写入任意用途的验证码，进程内保存
/// 10 分钟；超过 10 项时清理已过期的条目。
pub fn register_verification_code(purpose: &str, key: &str, code: &str) {
    let mut map = verification_map()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    map.insert(
        verification_key(purpose, key),
        VerificationEntry {
            code: code.to_owned(),
            stored_at: Instant::now(),
        },
    );
    if map.len() > VERIFICATION_MAP_MAX_SIZE {
        let now = Instant::now();
        map.retain(|_, entry| {
            now.duration_since(entry.stored_at).as_secs() < VERIFICATION_VALID_SECONDS
        });
    }
}

/// Go `VerifyCodeWithKey`：只读校验任意用途的验证码，过期或不存在均返回
/// false，验证成功后也不删除（删除是调用方的显式步骤）。
pub fn verify_verification_code(purpose: &str, key: &str, code: &str) -> bool {
    let map = verification_map()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    map.get(&verification_key(purpose, key))
        .is_some_and(|entry| {
            entry.stored_at.elapsed().as_secs() < VERIFICATION_VALID_SECONDS && entry.code == code
        })
}

/// Go `DeleteKey`：仅在成功后显式消费验证码。
pub fn delete_verification_code(purpose: &str, key: &str) {
    let mut map = verification_map()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    map.remove(&verification_key(purpose, key));
}

/// Go `RegisterVerificationCodeWithKey` 的邮箱用途（purpose `"v"`）等价实现。
/// 邮箱发送端点尚未移植；注册流程与后续端点共享此进程内缓存。
pub fn register_email_verification_code(email: &str, code: &str) {
    register_verification_code(EMAIL_VERIFICATION_PURPOSE, email, code);
}

/// Go `VerifyCodeWithKey(email, code, EmailVerificationPurpose)`：只读校验，
/// 过期或不存在均返回 false，验证成功后也不删除（与 Go 一致）。
pub fn verify_email_verification_code(email: &str, code: &str) -> bool {
    verify_verification_code(EMAIL_VERIFICATION_PURPOSE, email, code)
}

/// 已校验并散列的注册草稿；不实现 Debug 或序列化。
pub struct NewUser {
    pub username: String,
    pub password_hash: String,
    pub display_name: String,
    pub email: String,
    pub inviter_id: i64,
    pub created_at: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationError {
    EmailTaken,
    Storage,
}

const AFF_CODE_OWNER: &str = "SELECT CAST(id AS BIGINT) FROM users \
    WHERE aff_code = $1 AND deleted_at IS NULL ORDER BY id LIMIT 1";
const EMAIL_TAKEN: &str = "SELECT EXISTS(SELECT 1 FROM users WHERE LOWER(email) = $1)";
const NAME_TAKEN: &str = "SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)";
const NAME_OR_EMAIL_TAKEN: &str =
    "SELECT EXISTS(SELECT 1 FROM users WHERE username = $1 OR LOWER(email) = $2)";
const EMAIL_LOCK: &str = "SELECT pg_advisory_xact_lock(hashtext($1))";

// 显式填写 Go 零值；`access_token` 缺省即 NULL，`group`/`status`/`role` 与
// Go 默认一致。`RETURNING` 同时适用于 SQLite 3.35+ 与 PostgreSQL。
const INSERT_USER: &str = r#"
INSERT INTO users (
    username,password,display_name,role,status,email,github_id,discord_id,
    oidc_id,wechat_id,telegram_id,quota,used_quota,request_count,"group",
    aff_code,aff_count,aff_quota,aff_history,inviter_id,deleted_at,
    linux_do_id,setting,remark,stripe_customer,created_at,last_login_at,auth_version
) VALUES (
    $1,$2,$3,1,1,$4,'','','','','',0,0,0,'default',
    $5,0,0,0,$6,NULL,'',$7,'','',$8,0,1
)
RETURNING CAST(id AS BIGINT)
"#;

/// Go `GetRandomString(4)` 的字母表：小写、大写、数字各 26/26/10 个。
/// 生成 4 位邀请码；唯一索引冲突与 Go 一样作为存储错误上抛。
fn random_aff_code() -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    (0..4)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

#[derive(Clone)]
pub struct RegistrationRepository {
    db: Database,
}

impl RegistrationRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Go `GetUserIdByAffCode`：按邀请码查活跃用户；空码或未命中返回 `None`。
    pub async fn aff_code_owner(&self, aff_code: &str) -> Result<Option<i64>, sqlx::Error> {
        if aff_code.is_empty() {
            return Ok(None);
        }
        match &self.db {
            Database::Sqlite(pool) => {
                sqlx::query_scalar(AFF_CODE_OWNER)
                    .bind(aff_code)
                    .fetch_optional(pool)
                    .await
            }
            Database::Postgres(pool) => {
                sqlx::query_scalar(AFF_CODE_OWNER)
                    .bind(aff_code)
                    .fetch_optional(pool)
                    .await
            }
        }
    }

    /// Go `EnsureEmailAvailable`/`emailQuery`：未软删过滤，空邮箱总是可用。
    pub async fn email_taken(&self, email: &str) -> Result<bool, sqlx::Error> {
        if email.is_empty() {
            return Ok(false);
        }
        match &self.db {
            Database::Sqlite(pool) => {
                sqlx::query_scalar(EMAIL_TAKEN)
                    .bind(email)
                    .fetch_one(pool)
                    .await
            }
            Database::Postgres(pool) => {
                sqlx::query_scalar(EMAIL_TAKEN)
                    .bind(email)
                    .fetch_one(pool)
                    .await
            }
        }
    }

    /// Go `CheckUserExistOrDeleted`：`Unscoped`，软删用户名同样占用；邮箱为空
    /// 时只比较用户名，否则同时比较不区分大小写的邮箱。
    pub async fn username_or_email_taken(
        &self,
        username: &str,
        email: &str,
    ) -> Result<bool, sqlx::Error> {
        match &self.db {
            Database::Sqlite(pool) if email.is_empty() => {
                sqlx::query_scalar(NAME_TAKEN)
                    .bind(username)
                    .fetch_one(pool)
                    .await
            }
            Database::Sqlite(pool) => {
                sqlx::query_scalar(NAME_OR_EMAIL_TAKEN)
                    .bind(username)
                    .bind(email)
                    .fetch_one(pool)
                    .await
            }
            Database::Postgres(pool) if email.is_empty() => {
                sqlx::query_scalar(NAME_TAKEN)
                    .bind(username)
                    .fetch_one(pool)
                    .await
            }
            Database::Postgres(pool) => {
                sqlx::query_scalar(NAME_OR_EMAIL_TAKEN)
                    .bind(username)
                    .bind(email)
                    .fetch_one(pool)
                    .await
            }
        }
    }

    /// Go `User.Insert`：事务内邮箱互斥、散列后的密码、随机邀请码与 Go 默认
    /// 字段。PostgreSQL 先取按规范化邮箱的事务级 advisory lock，与 Go
    /// `withNormalizedEmailLock` 一致；SQLite 由单写者模型串行化。
    pub async fn create(&self, user: NewUser) -> Result<i64, RegistrationError> {
        let aff_code = random_aff_code();
        match &self.db {
            Database::Sqlite(pool) => sqlite_create(pool, &user, &aff_code).await,
            Database::Postgres(pool) => postgres_create(pool, &user, &aff_code).await,
        }
    }
}

async fn sqlite_create(
    pool: &SqlitePool,
    user: &NewUser,
    aff_code: &str,
) -> Result<i64, RegistrationError> {
    let mut tx = pool.begin().await.map_err(|_| RegistrationError::Storage)?;
    if !user.email.is_empty() {
        let taken: bool = sqlx::query_scalar(EMAIL_TAKEN)
            .bind(&user.email)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| RegistrationError::Storage)?;
        if taken {
            return Err(RegistrationError::EmailTaken);
        }
    }
    let id: i64 = sqlx::query_scalar(INSERT_USER)
        .bind(&user.username)
        .bind(&user.password_hash)
        .bind(&user.display_name)
        .bind(&user.email)
        .bind(aff_code)
        .bind(user.inviter_id)
        .bind(DEFAULT_USER_SETTING)
        .bind(user.created_at)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| RegistrationError::Storage)?;
    tx.commit().await.map_err(|_| RegistrationError::Storage)?;
    Ok(id)
}

async fn postgres_create(
    pool: &PgPool,
    user: &NewUser,
    aff_code: &str,
) -> Result<i64, RegistrationError> {
    let mut tx = pool.begin().await.map_err(|_| RegistrationError::Storage)?;
    if !user.email.is_empty() {
        sqlx::query(EMAIL_LOCK)
            .bind(&user.email)
            .execute(&mut *tx)
            .await
            .map_err(|_| RegistrationError::Storage)?;
        let taken: bool = sqlx::query_scalar(EMAIL_TAKEN)
            .bind(&user.email)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| RegistrationError::Storage)?;
        if taken {
            return Err(RegistrationError::EmailTaken);
        }
    }
    let id: i64 = sqlx::query_scalar(INSERT_USER)
        .bind(&user.username)
        .bind(&user.password_hash)
        .bind(&user.display_name)
        .bind(&user.email)
        .bind(aff_code)
        .bind(user.inviter_id)
        .bind(DEFAULT_USER_SETTING)
        .bind(user.created_at)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| RegistrationError::Storage)?;
    tx.commit().await.map_err(|_| RegistrationError::Storage)?;
    Ok(id)
}
