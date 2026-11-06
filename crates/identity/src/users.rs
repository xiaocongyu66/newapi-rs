//! 初始化投影与用户公开原始资料仓储；不是鉴权服务或完整 SelfUser DTO。

use newapi_storage::Database;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::Row;

/// Go buildSelfUserData 所需的公开原始列，不含凭据、管理员备注或派生展示。
/// setting 保持原文；权限、侧栏及额度展示由后续 API 边界组装。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserProfile {
    pub id: i64,
    pub username: String,
    pub display_name: String,
    pub role: i64,
    pub status: i64,
    pub email: String,
    pub github_id: String,
    pub discord_id: String,
    pub oidc_id: String,
    pub wechat_id: String,
    pub telegram_id: String,
    pub group: String,
    pub quota: i64,
    pub used_quota: i64,
    pub request_count: i64,
    pub aff_code: String,
    pub aff_count: i64,
    pub aff_quota: i64,
    pub aff_history_quota: i64,
    pub inviter_id: i64,
    pub linux_do_id: String,
    pub setting: String,
    pub stripe_customer: String,
    /// Go `User.AuthVersion`：登录签发会话前必须核对；NULL 旧行按 0。
    pub auth_version: i64,
}

// 固定白名单，禁止 SELECT *。PG 的旧 INTEGER 列也显式提升为 i64。
const PROFILE_BY_ID: &str = r#"
SELECT CAST(id AS BIGINT) AS id, username, display_name,
    CAST(role AS BIGINT) AS role, CAST(status AS BIGINT) AS status,
    email, github_id, discord_id, oidc_id, wechat_id, telegram_id, "group",
    CAST(quota AS BIGINT) AS quota, CAST(used_quota AS BIGINT) AS used_quota,
    CAST(request_count AS BIGINT) AS request_count, aff_code,
    CAST(aff_count AS BIGINT) AS aff_count, CAST(aff_quota AS BIGINT) AS aff_quota,
    CAST(aff_history AS BIGINT) AS aff_history_quota,
    CAST(inviter_id AS BIGINT) AS inviter_id, linux_do_id, setting, stripe_customer,
    CAST(auth_version AS BIGINT) AS auth_version
FROM users WHERE id = $1 AND deleted_at IS NULL
"#;

// 两驱动分别展开类型化解码；旧库可空列对齐 Go struct 的零值，非 NULL 不改写。
macro_rules! profile {
    ($row:expr) => {{
        let row = $row;
        UserProfile {
            id: row.try_get("id")?,
            username: row
                .try_get::<Option<String>, _>("username")?
                .unwrap_or_default(),
            display_name: row
                .try_get::<Option<String>, _>("display_name")?
                .unwrap_or_default(),
            role: row.try_get::<Option<i64>, _>("role")?.unwrap_or_default(),
            status: row.try_get::<Option<i64>, _>("status")?.unwrap_or_default(),
            email: row
                .try_get::<Option<String>, _>("email")?
                .unwrap_or_default(),
            github_id: row
                .try_get::<Option<String>, _>("github_id")?
                .unwrap_or_default(),
            discord_id: row
                .try_get::<Option<String>, _>("discord_id")?
                .unwrap_or_default(),
            oidc_id: row
                .try_get::<Option<String>, _>("oidc_id")?
                .unwrap_or_default(),
            wechat_id: row
                .try_get::<Option<String>, _>("wechat_id")?
                .unwrap_or_default(),
            telegram_id: row
                .try_get::<Option<String>, _>("telegram_id")?
                .unwrap_or_default(),
            group: row
                .try_get::<Option<String>, _>("group")?
                .unwrap_or_default(),
            quota: row.try_get::<Option<i64>, _>("quota")?.unwrap_or_default(),
            used_quota: row
                .try_get::<Option<i64>, _>("used_quota")?
                .unwrap_or_default(),
            request_count: row
                .try_get::<Option<i64>, _>("request_count")?
                .unwrap_or_default(),
            aff_code: row
                .try_get::<Option<String>, _>("aff_code")?
                .unwrap_or_default(),
            aff_count: row
                .try_get::<Option<i64>, _>("aff_count")?
                .unwrap_or_default(),
            aff_quota: row
                .try_get::<Option<i64>, _>("aff_quota")?
                .unwrap_or_default(),
            aff_history_quota: row
                .try_get::<Option<i64>, _>("aff_history_quota")?
                .unwrap_or_default(),
            inviter_id: row
                .try_get::<Option<i64>, _>("inviter_id")?
                .unwrap_or_default(),
            linux_do_id: row
                .try_get::<Option<String>, _>("linux_do_id")?
                .unwrap_or_default(),
            setting: row
                .try_get::<Option<String>, _>("setting")?
                .unwrap_or_default(),
            stripe_customer: row
                .try_get::<Option<String>, _>("stripe_customer")?
                .unwrap_or_default(),
            auth_version: row
                .try_get::<Option<i64>, _>("auth_version")?
                .unwrap_or_default(),
        }
    }};
}

#[derive(Clone)]
pub struct UserProfileRepository {
    db: Database,
}

impl UserProfileRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// 仅按 ID 读取未软删除的资料，不检查角色、状态或会话，不授予访问权限。
    /// 调用方必须先鉴权；SQLx 错误原样返回，不应直接记录其可能敏感的文本。
    pub async fn by_id(&self, user_id: i64) -> Result<Option<UserProfile>, sqlx::Error> {
        match &self.db {
            Database::Sqlite(pool) => {
                let row = sqlx::query::<sqlx::Sqlite>(PROFILE_BY_ID)
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await?;
                row.map(|row| Ok(profile!(row))).transpose()
            }
            Database::Postgres(pool) => {
                let row = sqlx::query::<sqlx::Postgres>(PROFILE_BY_ID)
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await?;
                row.map(|row| Ok(profile!(row))).transpose()
            }
        }
    }
}

/// 仅供初始化判断；不包含密码、令牌、邮箱及权限展示。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootPresence {
    pub exists: bool,
}

/// 已由调用方校验并散列的凭据，不实现 Debug 或序列化。
/// 调用方负责 bcrypt cost10、原密码字节限制及确认密码检查。
pub struct RootDraft {
    pub username: String,
    pub password_hash: String,
}

pub(crate) const USER_COLUMNS: &str = "id,username,password,display_name,role,status,email,github_id,discord_id,oidc_id,wechat_id,telegram_id,access_token,quota,used_quota,request_count,group,aff_code,aff_count,aff_quota,aff_history,inviter_id,deleted_at,linux_do_id,setting,remark,stripe_customer,created_at,last_login_at,auth_version";

pub(crate) const ROOT_EXISTS: &str =
    "SELECT EXISTS(SELECT 1 FROM users WHERE role = 100 AND deleted_at IS NULL)";

// 显式填写 Go 零值，避免旧库缺少默认值时落入 NULL；不覆盖既有账户。
pub(crate) const INSERT_ROOT: &str = r#"
INSERT INTO users (
    username,password,display_name,role,status,email,github_id,discord_id,
    oidc_id,wechat_id,telegram_id,access_token,quota,used_quota,request_count,
    "group",aff_code,aff_count,aff_quota,aff_history,inviter_id,deleted_at,
    linux_do_id,setting,remark,stripe_customer,created_at,last_login_at,auth_version
) VALUES (
    $1,$2,'Root User',100,1,'','','','','','',NULL,100000000,0,0,
    'default','',0,0,0,0,NULL,'','','','',$3,0,1
)"#;

/// 登录所需的最小凭据投影；不实现 Debug 或序列化。
/// 读取不验证密码、不判定账号状态，也不授予访问权限。
pub struct LoginCredential {
    pub user_id: i64,
    pub password_hash: String,
    pub status: i64,
    pub auth_version: i64,
    pub username: String,
}

// 与 Go ValidateAndFill 一致：用户名或邮箱均可登录，GORM First 的主键顺序作为并列时的稳定选择。
const LOGIN_CREDENTIAL_BY_LOGIN: &str = "SELECT CAST(id AS BIGINT),username,password,CAST(status AS BIGINT),CAST(auth_version AS BIGINT) FROM users WHERE (username=$1 OR email=$1) AND deleted_at IS NULL ORDER BY id LIMIT 1";

#[derive(Clone)]
pub struct LoginCredentialRepository {
    db: Database,
}

impl LoginCredentialRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// 按用户名或邮箱读取原始凭据；保留数据库等值比较语义，不修剪输入。
    /// SQLx 错误原样传播；调用方不得直接记录可能敏感的错误文本。
    pub async fn by_username_or_email(
        &self,
        username: &str,
    ) -> Result<Option<LoginCredential>, sqlx::Error> {
        let row = match &self.db {
            Database::Sqlite(pool) => {
                sqlx::query_as::<
                    sqlx::Sqlite,
                    (
                        Option<i64>,
                        Option<String>,
                        Option<String>,
                        Option<i64>,
                        Option<i64>,
                    ),
                >(LOGIN_CREDENTIAL_BY_LOGIN)
                .bind(username)
                .fetch_optional(pool)
                .await?
            }
            Database::Postgres(pool) => {
                sqlx::query_as::<
                    sqlx::Postgres,
                    (
                        Option<i64>,
                        Option<String>,
                        Option<String>,
                        Option<i64>,
                        Option<i64>,
                    ),
                >(LOGIN_CREDENTIAL_BY_LOGIN)
                .bind(username)
                .fetch_optional(pool)
                .await?
            }
        };
        row.map(|(user_id, username, password_hash, status, auth_version)| {
            let missing = |column: &str| sqlx::Error::ColumnDecode {
                index: column.to_owned(),
                source: Box::new(sqlx::error::UnexpectedNullError),
            };
            Ok(LoginCredential {
                user_id: user_id.ok_or_else(|| missing("id"))?,
                password_hash: password_hash.ok_or_else(|| missing("password"))?,
                status: status.ok_or_else(|| missing("status"))?,
                auth_version: auth_version.ok_or_else(|| missing("auth_version"))?,
                username: username.ok_or_else(|| missing("username"))?,
            })
        })
        .transpose()
    }
}

/// Go `dto.UserSetting` 的 JSON 形状。字段顺序、`omitempty` 语义与 Go 一致：
/// 零值字符串/数字/布尔省略，`gotify_priority` 始终输出。
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct UserSetting {
    #[serde(skip_serializing_if = "is_default")]
    pub notify_type: String,
    #[serde(skip_serializing_if = "is_default")]
    pub quota_warning_threshold: f64,
    #[serde(skip_serializing_if = "is_default")]
    pub webhook_url: String,
    #[serde(skip_serializing_if = "is_default")]
    pub webhook_secret: String,
    #[serde(skip_serializing_if = "is_default")]
    pub notification_email: String,
    #[serde(skip_serializing_if = "is_default")]
    pub bark_url: String,
    #[serde(skip_serializing_if = "is_default")]
    pub gotify_url: String,
    #[serde(skip_serializing_if = "is_default")]
    pub gotify_token: String,
    pub gotify_priority: i64,
    #[serde(skip_serializing_if = "is_default")]
    pub upstream_model_update_notify_enabled: bool,
    #[serde(skip_serializing_if = "is_default")]
    pub accept_unset_model_ratio_model: bool,
    #[serde(skip_serializing_if = "is_default")]
    pub record_ip_log: bool,
    #[serde(skip_serializing_if = "is_default")]
    pub sidebar_modules: String,
    #[serde(skip_serializing_if = "is_default")]
    pub billing_preference: String,
    #[serde(skip_serializing_if = "is_default")]
    pub language: String,
}

fn is_default<T: Default + PartialEq>(value: &T) -> bool {
    *value == T::default()
}

impl UserSetting {
    /// Go `User.GetSetting`：无法解析时记录日志并使用零值设置，不部分采用。
    /// `encoding/json` 把 null 视为目标字段的零值，因此先剔除 null 键再解码，
    /// 非 null 的类型错误才整体回退为零值设置。
    pub fn from_json(raw: &str) -> Self {
        let Ok(Value::Object(mut object)) = serde_json::from_str::<Value>(raw) else {
            return Self::default();
        };
        object.retain(|_, value| !value.is_null());
        serde_json::from_value(Value::Object(object)).unwrap_or_default()
    }

    /// Go `json.Marshal(dto.UserSetting)`；结构与字段均为可序列化原语。
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("user setting is always serializable")
    }
}

/// 用户资料/会话改写的固定分类；不携带数据库错误文本。
pub enum UserMutationError {
    NotFound,
    SessionInactive,
    Storage(sqlx::Error),
}

impl From<sqlx::Error> for UserMutationError {
    fn from(error: sqlx::Error) -> Self {
        Self::Storage(error)
    }
}

/// Go `AdvanceUserSessionAuthVersion` 的输入；会话版本与用户版本都必须匹配。
pub struct SessionAdvance<'a> {
    pub user_id: i64,
    pub sid: &'a str,
    pub expected_session_version: i64,
    pub expected_user_auth_version: i64,
    pub next_user_auth_version: i64,
    pub now: i64,
}

/// 会话公开投影；与 Go `LoginSessionView` 字段一一对应（`current` 由调用方设定）。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionProjection {
    pub sid: String,
    pub login_method: String,
    pub ip: String,
    pub user_agent: String,
    pub created_at: i64,
    pub last_active_at: i64,
    pub expires_at: i64,
}

const UPDATE_SETTING: &str = "UPDATE users SET setting=$1 WHERE id=$2 AND deleted_at IS NULL";
const SELECT_PASSWORD: &str =
    "SELECT COALESCE(password, '') AS password FROM users WHERE id=$1 AND deleted_at IS NULL";
const UPDATE_PROFILE: &str = r"
UPDATE users SET
    username = CASE WHEN $1 = '' THEN username ELSE $1 END,
    display_name = CASE WHEN $2 = '' THEN display_name ELSE $2 END
WHERE id = $3 AND deleted_at IS NULL
";
const UPDATE_PASSWORD: &str = r"
UPDATE users SET
    password = $1,
    username = CASE WHEN $2 = '' THEN username ELSE $2 END,
    display_name = CASE WHEN $3 = '' THEN display_name ELSE $3 END,
    auth_version = CASE WHEN COALESCE(auth_version, 0) < 1 THEN 2 ELSE COALESCE(auth_version, 0) + 1 END
WHERE id = $4 AND deleted_at IS NULL
";
const SELECT_AUTH_VERSION: &str = "SELECT CAST(auth_version AS BIGINT) AS auth_version FROM users WHERE id=$1 AND deleted_at IS NULL";
const ADVANCE_SESSION: &str = r"
UPDATE user_sessions SET
    version = version + 1,
    user_auth_version = $1,
    last_active_at = $2
WHERE sid = $3 AND user_id = $4 AND status = 'active' AND expires_at > $2
    AND version = $5 AND user_auth_version = $6
";
const SELECT_SESSION_VIEW: &str = r"
SELECT sid, COALESCE(login_method, ''), COALESCE(ip, ''), COALESCE(user_agent, ''),
    COALESCE(CAST(created_at AS BIGINT), 0),
    COALESCE(CAST(last_active_at AS BIGINT), 0),
    COALESCE(CAST(expires_at AS BIGINT), 0)
FROM user_sessions WHERE sid = $1
";
// Go `User.Delete` 在软删除前用 Unscoped 递增版本；NULL/0 旧值从 1 起步。
const BUMP_AUTH_VERSION: &str = r"
UPDATE users SET auth_version =
    CASE WHEN COALESCE(auth_version, 0) < 1 THEN 2 ELSE COALESCE(auth_version, 0) + 1 END
WHERE id = $1
";
const DELETE_QQ_BINDING: &str = "DELETE FROM qq_bindings WHERE user_id = $1";
const SOFT_DELETE_USER: &str =
    "UPDATE users SET deleted_at = CURRENT_TIMESTAMP WHERE id = $1 AND deleted_at IS NULL";
const REVOKE_ALL_SESSIONS: &str = r"
UPDATE user_sessions SET status = 'revoked', revoked_at = $1, revoked_reason = 'user_deleted'
WHERE user_id = $2 AND status = 'active' AND expires_at > $1
";

impl UserProfileRepository {
    /// Go `UpdateUserSetting`：GORM 的 `Updates` 对零行匹配也不报错。
    pub async fn update_setting(&self, user_id: i64, setting: &str) -> Result<(), sqlx::Error> {
        match &self.db {
            Database::Sqlite(pool) => {
                sqlx::query(UPDATE_SETTING)
                    .bind(setting)
                    .bind(user_id)
                    .execute(pool)
                    .await?;
            }
            Database::Postgres(pool) => {
                sqlx::query(UPDATE_SETTING)
                    .bind(setting)
                    .bind(user_id)
                    .execute(pool)
                    .await?;
            }
        }
        Ok(())
    }

    /// Go `GetUserById(id, true)` 的密码列；行不存在为 `None`，NULL 密码为 `Some("")`。
    pub async fn password_hash(&self, user_id: i64) -> Result<Option<String>, sqlx::Error> {
        let password = match &self.db {
            Database::Sqlite(pool) => {
                sqlx::query_scalar::<_, String>(SELECT_PASSWORD)
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await?
            }
            Database::Postgres(pool) => {
                sqlx::query_scalar::<_, String>(SELECT_PASSWORD)
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await?
            }
        };
        Ok(password)
    }

    /// Go `cleanUser.Update(false)`：`Updates(struct)` 跳过零值，空用户名/昵称不覆盖。
    pub async fn update_profile(
        &self,
        user_id: i64,
        username: &str,
        display_name: &str,
    ) -> Result<(), UserMutationError> {
        let affected = match &self.db {
            Database::Sqlite(pool) => sqlx::query(UPDATE_PROFILE)
                .bind(username)
                .bind(display_name)
                .bind(user_id)
                .execute(pool)
                .await?
                .rows_affected(),
            Database::Postgres(pool) => sqlx::query(UPDATE_PROFILE)
                .bind(username)
                .bind(display_name)
                .bind(user_id)
                .execute(pool)
                .await?
                .rows_affected(),
        };
        if affected == 0 {
            return Err(UserMutationError::NotFound);
        }
        Ok(())
    }

    /// Go `UpdateWithTx(tx, true)`：同一事务写密码、非空用户名/昵称并递增 `auth_version`。
    /// 返回递增后的版本；密码原文不经过本函数。
    pub async fn update_password(
        &self,
        user_id: i64,
        password_hash: &str,
        username: &str,
        display_name: &str,
    ) -> Result<i64, UserMutationError> {
        match &self.db {
            Database::Sqlite(pool) => {
                let mut tx = pool.begin().await?;
                let affected = sqlx::query(UPDATE_PASSWORD)
                    .bind(password_hash)
                    .bind(username)
                    .bind(display_name)
                    .bind(user_id)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected();
                if affected == 0 {
                    return Err(UserMutationError::NotFound);
                }
                let version = sqlx::query_scalar::<_, i64>(SELECT_AUTH_VERSION)
                    .bind(user_id)
                    .fetch_one(&mut *tx)
                    .await?;
                tx.commit().await?;
                Ok(version)
            }
            Database::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                let affected = sqlx::query(UPDATE_PASSWORD)
                    .bind(password_hash)
                    .bind(username)
                    .bind(display_name)
                    .bind(user_id)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected();
                if affected == 0 {
                    return Err(UserMutationError::NotFound);
                }
                let version = sqlx::query_scalar::<_, i64>(SELECT_AUTH_VERSION)
                    .bind(user_id)
                    .fetch_one(&mut *tx)
                    .await?;
                tx.commit().await?;
                Ok(version)
            }
        }
    }

    /// Go `AdvanceUserSessionAuthVersion`：仅当会话仍活跃且版本匹配时前进一代。
    pub async fn advance_session_auth_version(
        &self,
        input: SessionAdvance<'_>,
    ) -> Result<SessionProjection, UserMutationError> {
        if input.user_id <= 0
            || input.sid.is_empty()
            || input.expected_session_version <= 0
            || input.expected_user_auth_version <= 0
            || input.next_user_auth_version <= input.expected_user_auth_version
        {
            return Err(UserMutationError::SessionInactive);
        }
        match &self.db {
            Database::Sqlite(pool) => advance_session_sqlite(pool, &input).await,
            Database::Postgres(pool) => advance_session_postgres(pool, &input).await,
        }
    }

    /// Go `User.Delete`：递增版本、解绑 QQ、软删除并撤销所有活跃会话。
    /// 用户缓存失效尚未移植（当前认证路径直接读库），不伪造缓存写入。
    pub async fn soft_delete(&self, user_id: i64, now: i64) -> Result<(), UserMutationError> {
        if user_id <= 0 {
            return Err(UserMutationError::NotFound);
        }
        match &self.db {
            Database::Sqlite(pool) => soft_delete_sqlite(pool, user_id, now).await,
            Database::Postgres(pool) => soft_delete_postgres(pool, user_id, now).await,
        }
    }
}

async fn advance_session_sqlite(
    pool: &sqlx::SqlitePool,
    input: &SessionAdvance<'_>,
) -> Result<SessionProjection, UserMutationError> {
    let mut tx = pool.begin().await?;
    let affected = sqlx::query(ADVANCE_SESSION)
        .bind(input.next_user_auth_version)
        .bind(input.now)
        .bind(input.sid)
        .bind(input.user_id)
        .bind(input.expected_session_version)
        .bind(input.expected_user_auth_version)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if affected == 0 {
        return Err(UserMutationError::SessionInactive);
    }
    let row =
        sqlx::query_as::<_, (String, String, String, String, i64, i64, i64)>(SELECT_SESSION_VIEW)
            .bind(input.sid)
            .fetch_one(&mut *tx)
            .await?;
    tx.commit().await?;
    Ok(SessionProjection {
        sid: row.0,
        login_method: row.1,
        ip: row.2,
        user_agent: row.3,
        created_at: row.4,
        last_active_at: row.5,
        expires_at: row.6,
    })
}

async fn advance_session_postgres(
    pool: &sqlx::PgPool,
    input: &SessionAdvance<'_>,
) -> Result<SessionProjection, UserMutationError> {
    let mut tx = pool.begin().await?;
    let affected = sqlx::query(ADVANCE_SESSION)
        .bind(input.next_user_auth_version)
        .bind(input.now)
        .bind(input.sid)
        .bind(input.user_id)
        .bind(input.expected_session_version)
        .bind(input.expected_user_auth_version)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if affected == 0 {
        return Err(UserMutationError::SessionInactive);
    }
    let row =
        sqlx::query_as::<_, (String, String, String, String, i64, i64, i64)>(SELECT_SESSION_VIEW)
            .bind(input.sid)
            .fetch_one(&mut *tx)
            .await?;
    tx.commit().await?;
    Ok(SessionProjection {
        sid: row.0,
        login_method: row.1,
        ip: row.2,
        user_agent: row.3,
        created_at: row.4,
        last_active_at: row.5,
        expires_at: row.6,
    })
}

async fn soft_delete_sqlite(
    pool: &sqlx::SqlitePool,
    user_id: i64,
    now: i64,
) -> Result<(), UserMutationError> {
    let mut tx = pool.begin().await?;
    let affected = sqlx::query(BUMP_AUTH_VERSION)
        .bind(user_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if affected == 0 {
        return Err(UserMutationError::NotFound);
    }
    sqlx::query(DELETE_QQ_BINDING)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(SOFT_DELETE_USER)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(REVOKE_ALL_SESSIONS)
        .bind(now)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

async fn soft_delete_postgres(
    pool: &sqlx::PgPool,
    user_id: i64,
    now: i64,
) -> Result<(), UserMutationError> {
    let mut tx = pool.begin().await?;
    let affected = sqlx::query(BUMP_AUTH_VERSION)
        .bind(user_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if affected == 0 {
        return Err(UserMutationError::NotFound);
    }
    sqlx::query(DELETE_QQ_BINDING)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(SOFT_DELETE_USER)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(REVOKE_ALL_SESSIONS)
        .bind(now)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

// --- Affiliate code (`GET /api/user/aff`) -------------------------------

/// Go `common.GetRandomString(4)` alphabet: lowercase, uppercase, digits.
const AFF_CODE_CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const AFF_CODE_LENGTH: usize = 4;
/// Bounded re-read after losing a conditional claim race.
const AFF_CODE_CLAIM_ATTEMPTS: usize = 4;

const SELECT_AFF_CODE: &str = "SELECT aff_code FROM users WHERE id = $1 AND deleted_at IS NULL";

// Claim only an unset code. Concurrent readers never overwrite a code that
// another request already persisted, removing the lost-update window in Go's
// read-modify-write `User.Update`.
const CLAIM_AFF_CODE: &str = r"
UPDATE users SET aff_code = $1
WHERE id = $2 AND deleted_at IS NULL
    AND (aff_code IS NULL OR aff_code = '')
";

/// Fixed classification for affiliate-code reads/writes; never carries SQL text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AffCodeError {
    /// No active (non soft-deleted) user row exists.
    NotFound,
    /// The code could not be written to or read back from storage.
    Storage,
}

/// Go `common.GetRandomString(4)` for affiliate codes.
pub fn generate_aff_code() -> String {
    use rand::Rng;

    let mut rng = rand::thread_rng();
    (0..AFF_CODE_LENGTH)
        .map(|_| char::from(AFF_CODE_CHARSET[rng.gen_range(0..AFF_CODE_CHARSET.len())]))
        .collect()
}

impl UserProfileRepository {
    /// Read the affiliate code of an active user. `Ok(None)` means the row
    /// exists but the column is NULL/empty; [`AffCodeError::NotFound`] means no
    /// active row (soft-deleted users included, matching Go GORM's default
    /// scope in `GetUserById`).
    pub async fn aff_code(&self, user_id: i64) -> Result<Option<String>, AffCodeError> {
        let stored = match &self.db {
            Database::Sqlite(pool) => sqlx::query_scalar::<_, Option<String>>(SELECT_AFF_CODE)
                .bind(user_id)
                .fetch_optional(pool)
                .await
                .map_err(|_| AffCodeError::Storage)?,
            Database::Postgres(pool) => sqlx::query_scalar::<_, Option<String>>(SELECT_AFF_CODE)
                .bind(user_id)
                .fetch_optional(pool)
                .await
                .map_err(|_| AffCodeError::Storage)?,
        };
        match stored {
            Some(Some(code)) if !code.is_empty() => Ok(Some(code)),
            Some(_) => Ok(None),
            None => Err(AffCodeError::NotFound),
        }
    }

    /// Go `GetAffCode`: return the persisted code, or generate and persist a
    /// 4-character code when the column is empty. The conditional update makes
    /// concurrent claims safe: exactly one writer wins and every caller then
    /// reads the winner's value.
    pub async fn ensure_aff_code(&self, user_id: i64) -> Result<String, AffCodeError> {
        for _ in 0..AFF_CODE_CLAIM_ATTEMPTS {
            if let Some(code) = self.aff_code(user_id).await? {
                return Ok(code);
            }
            let candidate = generate_aff_code();
            if self.claim_aff_code(user_id, &candidate).await? == 1 {
                return Ok(candidate);
            }
        }
        match self.aff_code(user_id).await? {
            Some(code) => Ok(code),
            None => Err(AffCodeError::Storage),
        }
    }

    async fn claim_aff_code(&self, user_id: i64, code: &str) -> Result<u64, AffCodeError> {
        let affected = match &self.db {
            Database::Sqlite(pool) => sqlx::query(CLAIM_AFF_CODE)
                .bind(code)
                .bind(user_id)
                .execute(pool)
                .await
                .map_err(|_| AffCodeError::Storage)?
                .rows_affected(),
            Database::Postgres(pool) => sqlx::query(CLAIM_AFF_CODE)
                .bind(code)
                .bind(user_id)
                .execute(pool)
                .await
                .map_err(|_| AffCodeError::Storage)?
                .rows_affected(),
        };
        Ok(affected)
    }
}

#[cfg(test)]
mod aff_code_tests {
    use super::*;

    #[test]
    fn generated_aff_codes_are_four_alphanumeric_characters() {
        for _ in 0..64 {
            let code = generate_aff_code();
            assert_eq!(code.len(), AFF_CODE_LENGTH);
            assert!(code.bytes().all(|byte| byte.is_ascii_alphanumeric()));
        }
    }
}
