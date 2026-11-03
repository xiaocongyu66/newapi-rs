//! Dashboard UserAuth 的 DB-only 边界；不解析 header、JWT、会话或 relay API key。

use newapi_storage::Database;

/// 会话验证与 session-only gate 由调用方执行；PAT 不代表浏览器会话。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialKind {
    DashboardSession,
    PersonalAccessToken,
}

/// 当前权威用户快照，不包含凭证原文、hash 或伪造的 SID。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserAuthIdentity {
    pub user_id: i64,
    pub username: String,
    pub role: i64,
    pub status: i64,
    pub auth_version: i64,
    pub group: String,
    pub credential: CredentialKind,
}

/// 固定分类，不携带数据库错误文本或凭证。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserAuthError {
    InvalidCredential,
    UserDisabled,
    UserInvalid,
    InsufficientRole,
    Storage,
}

impl From<sqlx::Error> for UserAuthError {
    fn from(_: sqlx::Error) -> Self {
        Self::Storage
    }
}

/// 仅授权已有身份；未匹配凭证由调用方映射为 InvalidCredential。
/// 与 Go 顺序一致：状态、最低角色、用户信息；不额外施加会话版本规则。
pub fn authorize(auth: &UserAuthIdentity, min_role: i64) -> Result<(), UserAuthError> {
    if auth.status != 1 {
        return Err(UserAuthError::UserDisabled);
    }
    if auth.role < min_role {
        return Err(UserAuthError::InsufficientRole);
    }
    if auth.user_id <= 0
        || auth.username.trim().is_empty()
        || !matches!(auth.role, 0 | 1 | 10 | 100)
    {
        return Err(UserAuthError::UserInvalid);
    }
    Ok(())
}

// 固定白名单；group 是 SQL 关键字，必须引用。旧 PG INTEGER 列提升为 i64。
const BY_TOKEN: &str = r#"SELECT CAST(id AS BIGINT),username,CAST(role AS BIGINT),CAST(status AS BIGINT),CAST(auth_version AS BIGINT),"group" FROM users WHERE access_token=$1 AND deleted_at IS NULL"#;

#[derive(Clone)]
pub struct PersonalAccessTokenRepository {
    db: Database,
}

impl PersonalAccessTokenRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// 裸 PAT 按数据库等值比较绑定 users.access_token，不修剪或验证格式。
    /// 不匹配返回 None；匹配行的必需列 NULL 失败关闭；SQLx 错误原样传播。
    /// 调用方不得直接打印可能含有敏感数据的数据库错误。
    pub async fn by_token(&self, token: &str) -> Result<Option<UserAuthIdentity>, sqlx::Error> {
        let row = match &self.db {
            Database::Sqlite(pool) => {
                sqlx::query_as::<
                    sqlx::Sqlite,
                    (
                        Option<i64>,
                        Option<String>,
                        Option<i64>,
                        Option<i64>,
                        Option<i64>,
                        Option<String>,
                    ),
                >(BY_TOKEN)
                .bind(token)
                .fetch_optional(pool)
                .await?
            }
            Database::Postgres(pool) => {
                sqlx::query_as::<
                    sqlx::Postgres,
                    (
                        Option<i64>,
                        Option<String>,
                        Option<i64>,
                        Option<i64>,
                        Option<i64>,
                        Option<String>,
                    ),
                >(BY_TOKEN)
                .bind(token)
                .fetch_optional(pool)
                .await?
            }
        };
        row.map(|(user_id, username, role, status, auth_version, group)| {
            let missing = |column: &str| sqlx::Error::ColumnDecode {
                index: column.to_owned(),
                source: Box::new(sqlx::error::UnexpectedNullError),
            };
            Ok(UserAuthIdentity {
                user_id: user_id.ok_or_else(|| missing("id"))?,
                username: username.ok_or_else(|| missing("username"))?,
                role: role.ok_or_else(|| missing("role"))?,
                status: status.ok_or_else(|| missing("status"))?,
                auth_version: auth_version.ok_or_else(|| missing("auth_version"))?,
                group: group.ok_or_else(|| missing("group"))?,
                credential: CredentialKind::PersonalAccessToken,
            })
        })
        .transpose()
    }
}
