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

use crate::audit::record_system_log;
use crate::self_user::QuotaDisplaySettings;
use crate::users::UserSetting;

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
    /// Go `User.Insert` 在写库前赋的 `common.QuotaForNewUser`（默认 0）。
    pub quota: i64,
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
// Go 默认一致；quota 取 `NewUser.quota`（Go `User.Insert` 写入
// `common.QuotaForNewUser`）。`RETURNING` 同时适用于 SQLite 3.35+ 与 PG。
const INSERT_USER: &str = r#"
INSERT INTO users (
    username,password,display_name,role,status,email,github_id,discord_id,
    oidc_id,wechat_id,telegram_id,quota,used_quota,request_count,"group",
    aff_code,aff_count,aff_quota,aff_history,inviter_id,deleted_at,
    linux_do_id,setting,remark,stripe_customer,created_at,last_login_at,auth_version
) VALUES (
    $1,$2,$3,1,1,$4,'','','','','',$9,0,0,'default',
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
        .bind(user.quota)
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
        .bind(user.quota)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| RegistrationError::Storage)?;
    tx.commit().await.map_err(|_| RegistrationError::Storage)?;
    Ok(id)
}

// ---------------------------------------------------------------------------
// 注册收尾：Go `User.finishInsert`（store_users.go:573-603）
// ---------------------------------------------------------------------------

/// Go `common.RoleAdminUser`（constants.go:193）。
const ROLE_ADMIN_USER: i64 = 10;
/// Go `common.RoleRootUser`（constants.go:194）。
const ROLE_ROOT_USER: i64 = 100;

const CREATED_USER: &str = "SELECT CAST(role AS BIGINT) AS role, setting FROM users \
    WHERE id = $1 AND deleted_at IS NULL";
const FINISH_UPDATE_SETTING: &str = "UPDATE users SET setting = $1 \
    WHERE id = $2 AND deleted_at IS NULL";
const INCREASE_QUOTA: &str = "UPDATE users SET quota = quota + $1 \
    WHERE id = $2 AND deleted_at IS NULL";
const INVITE_USER: &str = "UPDATE users SET aff_count = aff_count + 1, \
    aff_quota = aff_quota + $1, aff_history = aff_history + $1 \
    WHERE id = $2 AND deleted_at IS NULL";
const INVITE_USER_COUNT_ONLY: &str = "UPDATE users SET aff_count = aff_count + 1 \
    WHERE id = $1 AND deleted_at IS NULL";
const INVITER_USERNAME: &str = "SELECT username FROM users WHERE id = $1 AND deleted_at IS NULL";

/// Go `finishInsert` 消费的选项快照；由 handler 逐请求从 options 表装载。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinishInsertSettings {
    /// Go `common.QuotaForNewUser`（默认 0，>0 才写赠送日志）。
    pub quota_for_new_user: i64,
    /// Go `common.QuotaForInvitee`（默认 0，>0 才给被邀请人加额度）。
    pub quota_for_invitee: i64,
    /// Go `common.QuotaForInviter`（默认 0，>0 才给邀请人加邀请额度）。
    pub quota_for_inviter: i64,
    /// Go `isPaymentComplianceConfirmed`：合规门未确认时整段邀请奖励跳过。
    pub payment_compliance_confirmed: bool,
}

/// 一次注册收尾的完整输入；收敛参数，避免过宽签名。
pub struct FinishInsert<'a> {
    pub user_id: i64,
    pub username: &'a str,
    pub inviter_id: i64,
    pub settings: &'a FinishInsertSettings,
    /// Go `logger.LogQuota` 的格式化设置（`OnFormatQuota` 钩子）。
    pub display: &'a QuotaDisplaySettings,
    pub now: i64,
}

/// Go `generateDefaultSidebarConfigForRole`（store_users.go:201-260）：
/// chat/console/personal 三个区域所有角色都有；admin 区域按角色给，
/// 管理员 `setting:false`、超级管理员 `setting:true`，普通用户没有
/// admin 区域。返回序列化后的 JSON 字符串（Go 的 `common.Marshal`）；
/// 两处都按键序输出（Go 的 map marshal 排序键，serde_json 默认 BTreeMap
/// 同样排序），字符串逐字对齐。序列化失败时与 Go 一样返回空字符串
/// （`Marshal` 失败分支，实际不可达）。
pub fn default_sidebar_config_for_role(role: i64) -> String {
    let chat = serde_json::json!({
        "enabled": true,
        "playground": true,
        "chat": true,
    });
    let console = serde_json::json!({
        "enabled": true,
        "detail": true,
        "token": true,
        "log": true,
        "midjourney": true,
        "task": true,
    });
    let personal = serde_json::json!({
        "enabled": true,
        "topup": true,
        "personal": true,
    });
    let admin = if role == ROLE_ADMIN_USER {
        Some(serde_json::json!({
            "enabled": true,
            "channel": true,
            "models": true,
            "redemption": true,
            "user": true,
            "setting": false,
        }))
    } else if role == ROLE_ROOT_USER {
        Some(serde_json::json!({
            "enabled": true,
            "channel": true,
            "models": true,
            "redemption": true,
            "user": true,
            "setting": true,
        }))
    } else {
        None
    };
    let mut config = serde_json::Map::new();
    config.insert("chat".to_owned(), chat);
    config.insert("console".to_owned(), console);
    config.insert("personal".to_owned(), personal);
    if let Some(admin) = admin {
        config.insert("admin".to_owned(), admin);
    }
    serde_json::to_string(&serde_json::Value::Object(config)).unwrap_or_default()
}

impl RegistrationRepository {
    /// Go `User.finishInsert`：侧栏初始化 → 新用户额度日志 → 邀请人奖励。
    /// 与 Go 一致，所有步骤都是 best-effort：失败只 `tracing::warn`，
    /// 不影响已成功的用户创建，也不向 handler 传播错误（Go 用
    /// `SysLog` / 忽略 `_ =`）。
    ///
    /// Go 的 `createdUser.Update(false)` 是整结构回写，但其落库结果只
    /// 对 `setting` 列有变化（其余列被重写回等值）；这里做等价的目标列
    /// 更新，避免读快照期间的并发覆盖。Go 另有的 `updateUserCache`
    /// 缓存同步：Rust 尚无用户缓存（与 `password_reset` 模块的登记一致），
    /// 不补。
    pub async fn finish_insert(&self, input: FinishInsert<'_>) {
        // ---- 1. 按角色初始化侧栏（Go 按 username 重查用户取角色；
        // 这里 id 由 Insert 直接返回，等价）----
        match self.created_user(input.user_id).await {
            Ok(Some((role, setting_raw))) => {
                let sidebar = default_sidebar_config_for_role(role);
                if !sidebar.is_empty() {
                    let mut setting = UserSetting::from_json(&setting_raw);
                    setting.sidebar_modules = sidebar;
                    let updated = setting.to_json();
                    if let Err(error) = self.update_setting(input.user_id, &updated).await {
                        tracing::warn!(
                            event = "register_sidebar_persist_failed",
                            category = crate::audit::error_category(&error),
                            "failed to persist sidebar initialization"
                        );
                    }
                }
            }
            Ok(None) => tracing::warn!(
                event = "register_sidebar_lookup_failed",
                "created user row not found for sidebar initialization"
            ),
            Err(error) => tracing::warn!(
                event = "register_sidebar_lookup_failed",
                category = crate::audit::error_category(&error),
                "created user row lookup failed"
            ),
        }

        // ---- 2. 新用户注册赠送 ----
        if input.settings.quota_for_new_user > 0 {
            let content = format!(
                "新用户注册赠送 {}",
                input
                    .display
                    .format_quota(input.settings.quota_for_new_user, true)
            );
            record_system_log(&self.db, input.user_id, input.username, &content, input.now).await;
        }

        // ---- 3. 邀请人奖励（合规门未确认整段跳过）----
        if input.inviter_id != 0 && input.settings.payment_compliance_confirmed {
            if input.settings.quota_for_invitee > 0 {
                if let Err(error) = self
                    .increase_quota(input.user_id, input.settings.quota_for_invitee)
                    .await
                {
                    tracing::warn!(
                        event = "register_invitee_quota_failed",
                        category = crate::audit::error_category(&error),
                        "failed to grant invitee quota"
                    );
                }
                let content = format!(
                    "使用邀请码赠送 {}",
                    input
                        .display
                        .format_quota(input.settings.quota_for_invitee, true)
                );
                record_system_log(&self.db, input.user_id, input.username, &content, input.now)
                    .await;
            }
            let quota_reward = input.settings.quota_for_inviter > 0;
            if quota_reward {
                // Go 的 RecordLog 内部按 id 反查 username；缺失/软删用户
                // 得到空串（Find 不报错），这里同样以空串落库。
                let inviter_username = self.username_by_id(input.inviter_id).await;
                let content = format!(
                    "邀请用户赠送 {}",
                    input
                        .display
                        .format_quota(input.settings.quota_for_inviter, true)
                );
                record_system_log(
                    &self.db,
                    input.inviter_id,
                    inviter_username.as_deref().unwrap_or(""),
                    &content,
                    input.now,
                )
                .await;
            }
            let amount = if quota_reward {
                input.settings.quota_for_inviter
            } else {
                0
            };
            if let Err(error) = self.invite_user(input.inviter_id, amount).await {
                tracing::warn!(
                    event = "register_invite_record_failed",
                    category = crate::audit::error_category(&error),
                    "failed to record invite"
                );
            }
        }
    }

    /// Go `finishInsert` 的用户重查：取角色（决定 admin 区域）与当前
    /// setting（部分采用解析，与 `User.GetSetting` 一致）。
    async fn created_user(&self, user_id: i64) -> Result<Option<(i64, String)>, sqlx::Error> {
        let row: Option<(Option<i64>, Option<String>)> = match &self.db {
            Database::Sqlite(pool) => {
                sqlx::query_as(CREATED_USER)
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await?
            }
            Database::Postgres(pool) => {
                sqlx::query_as(CREATED_USER)
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await?
            }
        };
        Ok(row.map(|(role, setting)| (role.unwrap_or_default(), setting.unwrap_or_default())))
    }

    async fn update_setting(&self, user_id: i64, setting: &str) -> Result<(), sqlx::Error> {
        match &self.db {
            Database::Sqlite(pool) => {
                sqlx::query(FINISH_UPDATE_SETTING)
                    .bind(setting)
                    .bind(user_id)
                    .execute(pool)
                    .await
            }
            Database::Postgres(pool) => {
                sqlx::query(FINISH_UPDATE_SETTING)
                    .bind(setting)
                    .bind(user_id)
                    .execute(pool)
                    .await
            }
        }
        .map(|_| ())
    }

    /// Go `IncreaseUserQuota(id, quota, true)` 的直接分支：行级
    /// `quota = quota + n`；Go 的异步缓存递增在 Rust 无用户缓存实现，
    /// 与模块头注释一致，不补。
    async fn increase_quota(&self, user_id: i64, quota: i64) -> Result<(), sqlx::Error> {
        match &self.db {
            Database::Sqlite(pool) => {
                sqlx::query(INCREASE_QUOTA)
                    .bind(quota)
                    .bind(user_id)
                    .execute(pool)
                    .await
            }
            Database::Postgres(pool) => {
                sqlx::query(INCREASE_QUOTA)
                    .bind(quota)
                    .bind(user_id)
                    .execute(pool)
                    .await
            }
        }
        .map(|_| ())
    }

    /// Go `inviteUser`：`aff_count` 总是 +1；仅当邀请额度奖励实际发放
    /// （amount > 0）时 `aff_quota`/`aff_history` 同步增长。Go 用
    /// `gorm.Expr` 按条件加入列；amount == 0 时等价于只更新 aff_count。
    async fn invite_user(&self, inviter_id: i64, amount: i64) -> Result<(), sqlx::Error> {
        match &self.db {
            Database::Sqlite(pool) if amount > 0 => {
                sqlx::query(INVITE_USER)
                    .bind(amount)
                    .bind(inviter_id)
                    .execute(pool)
                    .await
            }
            Database::Sqlite(pool) => {
                sqlx::query(INVITE_USER_COUNT_ONLY)
                    .bind(inviter_id)
                    .execute(pool)
                    .await
            }
            Database::Postgres(pool) if amount > 0 => {
                sqlx::query(INVITE_USER)
                    .bind(amount)
                    .bind(inviter_id)
                    .execute(pool)
                    .await
            }
            Database::Postgres(pool) => {
                sqlx::query(INVITE_USER_COUNT_ONLY)
                    .bind(inviter_id)
                    .execute(pool)
                    .await
            }
        }
        .map(|_| ())
    }

    async fn username_by_id(&self, user_id: i64) -> Option<String> {
        let row: Option<(Option<String>,)> = match &self.db {
            Database::Sqlite(pool) => sqlx::query_as(INVITER_USERNAME)
                .bind(user_id)
                .fetch_optional(pool)
                .await
                .ok()?,
            Database::Postgres(pool) => sqlx::query_as(INVITER_USERNAME)
                .bind(user_id)
                .fetch_optional(pool)
                .await
                .ok()?,
        };
        row.and_then(|(username,)| username)
    }
}

#[cfg(test)]
mod finish_insert_tests {
    use super::*;

    #[test]
    fn sidebar_config_for_common_user_has_no_admin_region() {
        let config = default_sidebar_config_for_role(1);
        let value: serde_json::Value = serde_json::from_str(&config).unwrap();
        assert_eq!(
            value["chat"],
            serde_json::json!({"enabled": true, "playground": true, "chat": true})
        );
        assert_eq!(
            value["console"],
            serde_json::json!({"enabled": true, "detail": true, "token": true, "log": true, "midjourney": true, "task": true})
        );
        assert_eq!(
            value["personal"],
            serde_json::json!({"enabled": true, "topup": true, "personal": true})
        );
        assert!(value.get("admin").is_none());
    }

    #[test]
    fn sidebar_config_admin_region_differs_by_role() {
        let admin = default_sidebar_config_for_role(ROLE_ADMIN_USER);
        let value: serde_json::Value = serde_json::from_str(&admin).unwrap();
        assert_eq!(value["admin"]["setting"], serde_json::json!(false));
        assert_eq!(value["admin"]["enabled"], serde_json::json!(true));

        let root = default_sidebar_config_for_role(ROLE_ROOT_USER);
        let value: serde_json::Value = serde_json::from_str(&root).unwrap();
        assert_eq!(value["admin"]["setting"], serde_json::json!(true));
    }

    #[test]
    fn sidebar_config_keys_are_sorted_like_go_map_marshal() {
        let config = default_sidebar_config_for_role(ROLE_ROOT_USER);
        // Go 的 encoding/json 对 map 按键排序：admin,chat,console,personal。
        assert_eq!(
            config,
            r#"{"admin":{"channel":true,"enabled":true,"models":true,"redemption":true,"setting":true,"user":true},"chat":{"chat":true,"enabled":true,"playground":true},"console":{"console":true,"detail":true,"enabled":true,"log":true,"midjourney":true,"task":true},"personal":{"enabled":true,"personal":true,"topup":true}}"#
        );
    }
}
