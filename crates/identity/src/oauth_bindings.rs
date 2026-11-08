//! 自定义 OAuth 用户绑定仓储：Go `identity/bind_oauth.go`（`UserOAuthBinding`）、
//! `identity/resolve_oauth_provider.go`（`CustomOAuthProvider`）与
//! `identity/bind_custom_oauth.go` 的 `buildUserOAuthBindingsResponse`。
//!
//! 只落地四个 OAuth 绑定端点所需的读写：按用户列出绑定（连同提供商标本）、
//! 删除单条绑定。提供商自身的增删改查属于另一个切片，不在此实现。
//!
//! 与 Go 的语义对齐点：
//! - 绑定表的读取错误让整个请求失败（Go `CtxApiError`）；**单个**提供商的
//!   读取失败（含记录不存在）只静默跳过该条绑定，请求仍成功。
//! - 解绑对零行匹配同样返回成功：Go 的 GORM `Delete` 不把 `rows_affected == 0`
//!   当错误，这里也不把行数传播给调用方。

use serde::Serialize;

use newapi_storage::Database;

/// Go `UserOAuthBindingResponse`（`bind_custom_oauth.go:39-45`）。
/// 字段名与 Go JSON tag 逐字一致；不含绑定行自身的 id/created_at。
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct UserOAuthBindingView {
    pub provider_id: i64,
    pub provider_name: String,
    pub provider_slug: String,
    pub provider_icon: String,
    pub provider_user_id: String,
}

/// Go `GetUserOAuthBindingsByUserId`（`bind_oauth.go:25-29`）。
///
/// Go 的 GORM `Find` 没有 `ORDER BY`，行序由数据库自行决定；这里固定 `id ASC`，
/// 让响应顺序在两个后端上可复现（PG 的堆序不等于插入序，不给顺序的契约断言会偶发）。
const BINDINGS_BY_USER: &str = r#"
SELECT CAST(provider_id AS BIGINT) AS provider_id, provider_user_id
FROM user_oauth_bindings WHERE user_id = $1 ORDER BY id ASC
"#;

/// Go `GetCustomOAuthProviderById`（`resolve_oauth_provider.go:89-96`）。
/// 只取响应用到的三个字符串列；旧库可空列对齐 Go 结构体的零值（`""`）。
const PROVIDER_BRIEF: &str = "SELECT name, slug, icon FROM custom_oauth_providers WHERE id = $1";

/// Go `DeleteUserOAuthBinding`（`bind_oauth.go:133-136`）：
/// `dbx.DB.Where("user_id = ? AND provider_id = ?", ...).Delete(&UserOAuthBinding{})`。
const DELETE_BINDING: &str =
    "DELETE FROM user_oauth_bindings WHERE user_id = $1 AND provider_id = $2";

// 两驱动分别展开类型化解码；单一语句同时服务两个后端，只有类型注解不同。
macro_rules! backend {
    ($db:expr, $pool:ident, $body:block) => {
        match $db {
            Database::Sqlite($pool) => $body,
            Database::Postgres($pool) => $body,
        }
    };
}

#[derive(Clone)]
pub struct OAuthBindingRepository {
    db: Database,
}

impl OAuthBindingRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Go `GetUserById` 之外的读取只服务已鉴权调用方；本函数不判定权限。
    ///
    /// Go 对每条绑定单独 `GetCustomOAuthProviderById`：`err != nil`（不区分
    /// 记录不存在与存储故障）就 `continue` 静默跳过该条绑定。这里复现同一
    /// 可观察行为——只有绑定表自身的读取失败才让请求失败；提供商侧故障只
    /// 丢掉这一条，并记一条分类告警（Go 不打日志，但告警不改变响应）。
    pub async fn views_for_user(
        &self,
        user_id: i64,
    ) -> Result<Vec<UserOAuthBindingView>, sqlx::Error> {
        let bindings = backend!(&self.db, pool, {
            sqlx::query_as::<_, (i64, Option<String>)>(BINDINGS_BY_USER)
                .bind(user_id)
                .fetch_all(pool)
                .await?
        });
        let mut views = Vec::with_capacity(bindings.len());
        for (provider_id, provider_user_id) in bindings {
            match self.provider_brief(provider_id).await {
                Ok(Some(brief)) => views.push(UserOAuthBindingView {
                    provider_id,
                    provider_name: brief.name,
                    provider_slug: brief.slug,
                    provider_icon: brief.icon,
                    provider_user_id: provider_user_id.unwrap_or_default(),
                }),
                // Go 的 `err != nil → continue`：缺失与被删提供商都不出现在响应里。
                Ok(None) => continue,
                Err(error) => {
                    tracing::warn!(
                        event = "oauth_binding_provider_lookup_failed",
                        category = provider_error_category(&error),
                        provider_id,
                        "provider lookup failed; Go skips this binding"
                    );
                    continue;
                }
            }
        }
        Ok(views)
    }

    /// Go `GetCustomOAuthProviderById` 的响应投影：`Ok(None)` 表示提供商不存在，
    /// 行内可空字符串列取 Go 零值；存储故障原样传播，由调用方决定跳过或失败。
    async fn provider_brief(&self, provider_id: i64) -> Result<Option<ProviderBrief>, sqlx::Error> {
        let row = backend!(&self.db, pool, {
            sqlx::query_as::<_, (Option<String>, Option<String>, Option<String>)>(PROVIDER_BRIEF)
                .bind(provider_id)
                .fetch_optional(pool)
                .await?
        });
        Ok(row.map(|(name, slug, icon)| ProviderBrief {
            name: name.unwrap_or_default(),
            slug: slug.unwrap_or_default(),
            icon: icon.unwrap_or_default(),
        }))
    }

    /// Go `DeleteUserOAuthBinding`：零行匹配不是错误（解绑不存在的绑定同样成功）。
    /// 返回删除行数仅供测试与调用方观察，不参与响应分支。
    pub async fn delete(&self, user_id: i64, provider_id: i64) -> Result<u64, sqlx::Error> {
        let affected = backend!(&self.db, pool, {
            sqlx::query(DELETE_BINDING)
                .bind(user_id)
                .bind(provider_id)
                .execute(pool)
                .await?
                .rows_affected()
        });
        Ok(affected)
    }
}

/// 提供商响应所需的三个字符串列；不携带密钥或端点配置。
struct ProviderBrief {
    name: String,
    slug: String,
    icon: String,
}

/// 只记录固定分类，不转述可能含 SQL 文本的驱动错误。
fn provider_error_category(error: &sqlx::Error) -> &'static str {
    match error {
        sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed => "pool",
        sqlx::Error::Io(_) | sqlx::Error::WorkerCrashed => "io",
        _ => "database",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statements_are_static_and_parameterized() {
        // 两条语句必须是 'static 且仅含 $n 占位符，避免把用户输入拼进 SQL。
        assert!(BINDINGS_BY_USER.contains("user_id = $1"));
        assert!(PROVIDER_BRIEF.contains("id = $1"));
        assert!(DELETE_BINDING.contains("user_id = $1 AND provider_id = $2"));
    }
}
