//! 初始化投影与用户公开原始资料仓储；不是鉴权服务或完整 SelfUser DTO。

use newapi_storage::Database;
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
    CAST(inviter_id AS BIGINT) AS inviter_id, linux_do_id, setting, stripe_customer
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
