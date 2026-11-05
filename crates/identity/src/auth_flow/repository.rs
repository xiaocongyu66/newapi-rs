//! `auth_flows` 的创建、只读校验、原子消费与过期清理。
//!
//! Go 的 expires_at/created_at/consumed_at 是 `time.Time`（datetime 列），
//! 因此所有时间以 Unix 秒传入，但在 SQL 中按时间戳绑定，并以 epoch 表达式
//! 读回；绝不把 BIGINT 直接写入这些列。
use newapi_storage::Database;
use sqlx::{QueryBuilder, Row};

use super::{
    AuthFlow, AuthFlowError, AuthFlowMatch, CreateAuthFlow, auth_flow_key, generate_token,
    token_hash,
};
use crate::SecretString;

/// Go `AuthFlowDefaultCleanupRetention`：24 小时。
const CLEANUP_RETENTION_SECONDS: i64 = 24 * 60 * 60;

// 仅模块内固定列白名单；所有业务值必须绑定。时间列按 epoch 秒投影，
// 保持与调用方的 Unix 秒契约一致。
const COLUMNS_SQLITE: &str = "id,token_hash,purpose,CAST(user_id AS BIGINT) AS user_id,session_id,payload,CAST(strftime('%s',expires_at) AS INTEGER) AS expires_at,CAST(strftime('%s',consumed_at) AS INTEGER) AS consumed_at,CAST(strftime('%s',created_at) AS INTEGER) AS created_at";
const COLUMNS_POSTGRES: &str = "id,token_hash,purpose,CAST(user_id AS BIGINT) AS user_id,session_id,payload,CAST(EXTRACT(EPOCH FROM expires_at) AS BIGINT) AS expires_at,CAST(EXTRACT(EPOCH FROM consumed_at) AS BIGINT) AS consumed_at,CAST(EXTRACT(EPOCH FROM created_at) AS BIGINT) AS created_at";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Dialect {
    Sqlite,
    Postgres,
}

impl Dialect {
    fn columns(self) -> &'static str {
        match self {
            Self::Sqlite => COLUMNS_SQLITE,
            Self::Postgres => COLUMNS_POSTGRES,
        }
    }
}

macro_rules! backend {
    ($db:expr, $pool:ident, $dialect:ident, $body:block) => {
        match $db {
            Database::Sqlite($pool) => {
                let $dialect = Dialect::Sqlite;
                $body
            }
            Database::Postgres($pool) => {
                let $dialect = Dialect::Postgres;
                $body
            }
        }
    };
}

/// 绑定 Unix 秒，但在 SQL 中转换为数据库时间戳。
macro_rules! push_timestamp {
    ($query:expr, $dialect:expr, $seconds:expr) => {{
        if $dialect == Dialect::Postgres {
            $query.push("to_timestamp(");
            $query.push_bind($seconds as f64);
            $query.push(")");
        } else {
            $query.push("datetime(");
            $query.push_bind($seconds as f64);
            $query.push(",'unixepoch')");
        }
    }};
}

macro_rules! record {
    ($row:expr) => {{
        let row = $row;
        AuthFlow {
            id: row.try_get("id")?,
            // Go 列是 char(64)；PG 可能按 bpchar 语义补齐/返回空格。
            token_hash: row.try_get::<String, _>("token_hash")?.trim().to_owned(),
            purpose: row.try_get("purpose")?,
            user_id: row.try_get::<Option<i64>, _>("user_id")?.unwrap_or(0),
            session_id: row
                .try_get::<Option<String>, _>("session_id")?
                .unwrap_or_default(),
            payload: row
                .try_get::<Option<String>, _>("payload")?
                .unwrap_or_default(),
            expires_at: row.try_get("expires_at")?,
            consumed_at: row.try_get::<Option<i64>, _>("consumed_at")?,
            created_at: row.try_get::<Option<i64>, _>("created_at")?.unwrap_or(0),
        }
    }};
}

/// 持有数据库连接池与 HMAC key；key 不实现 Debug。
#[derive(Clone)]
pub struct AuthFlowRepository {
    db: Database,
    key: Vec<u8>,
}

impl AuthFlowRepository {
    /// key 必须是 `auth_flow_key(session_secret)` 的结果，以保持与 Go 字节一致。
    pub fn new(db: Database, key: impl Into<Vec<u8>>) -> Self {
        Self {
            db,
            key: key.into(),
        }
    }

    pub fn from_session_secret(db: Database, session_secret: &str) -> Self {
        Self::new(db, auth_flow_key(session_secret))
    }

    /// 对应 Go `CreateAuthFlow`：只校验 purpose 非空与未过期，单条 INSERT，
    /// 不去重也不撤销旧 flow。返回原始 token 与只含 hash 的记录。
    pub async fn create(
        &self,
        input: CreateAuthFlow,
        now: i64,
    ) -> Result<(SecretString, AuthFlow), AuthFlowError> {
        // Go 只对 purpose 做 TrimSpace 判定，落库仍是原始字符串。
        if input.purpose.trim().is_empty() || input.expires_at <= now {
            return Err(AuthFlowError::Invalid);
        }
        let raw = generate_token()?;
        let hash = token_hash(&self.key, raw.expose_secret());
        let flow = backend!(&self.db, pool, dialect, {
            let mut insert = QueryBuilder::new(
                "INSERT INTO auth_flows (token_hash,purpose,user_id,session_id,payload,expires_at,consumed_at,created_at) VALUES (",
            );
            insert
                .push_bind(&hash)
                .push(",")
                .push_bind(&input.purpose)
                .push(",")
                .push_bind(input.user_id)
                .push(",")
                .push_bind(&input.session_id)
                .push(",")
                .push_bind(&input.payload)
                .push(",");
            push_timestamp!(insert, dialect, input.expires_at);
            insert.push(",NULL,");
            push_timestamp!(insert, dialect, now);
            insert.push(")");
            insert.build().execute(pool).await?;
            // token_hash 唯一；插入后按摘要读取数据库生成的 id 与权威行。
            let mut query = QueryBuilder::new("SELECT ");
            query
                .push(dialect.columns())
                .push(" FROM auth_flows WHERE token_hash=")
                .push_bind(hash.as_str());
            let row = query
                .build()
                .fetch_optional(pool)
                .await?
                .ok_or(AuthFlowError::Storage)?;
            Ok::<AuthFlow, AuthFlowError>(record!(row))
        })?;
        Ok((raw, flow))
    }

    /// 对应 Go `GetAuthFlow`：只读且不加锁，不消费。
    pub async fn get(
        &self,
        token: &str,
        matching: AuthFlowMatch<'_>,
        now: i64,
    ) -> Result<AuthFlow, AuthFlowError> {
        if token.is_empty() || matching.purpose.is_empty() {
            return Err(AuthFlowError::Invalid);
        }
        let hash = token_hash(&self.key, token);
        backend!(&self.db, pool, dialect, {
            let mut query = QueryBuilder::new("SELECT ");
            query
                .push(dialect.columns())
                .push(" FROM auth_flows WHERE token_hash=")
                .push_bind(hash.as_str())
                .push(" AND purpose=")
                .push_bind(matching.purpose);
            if matching.user_id != 0 {
                query.push(" AND user_id=").push_bind(matching.user_id);
            }
            if !matching.session_id.is_empty() {
                query
                    .push(" AND session_id=")
                    .push_bind(matching.session_id);
            }
            let row = query.build().fetch_optional(pool).await?;
            let Some(row) = row else {
                return Err(AuthFlowError::Invalid);
            };
            let flow = record!(row);
            // Go 顺序：先判已消费，再判过期。
            if flow.consumed_at.is_some() {
                return Err(AuthFlowError::Consumed);
            }
            if flow.expires_at <= now {
                return Err(AuthFlowError::Expired);
            }
            Ok(flow)
        })
    }

    /// 对应 Go `ConsumeAuthFlow`：单条条件 UPDATE 的原子写保证唯一赢家，
    /// 未命中后重读按 Go 顺序分类（已消费优先于过期）。SQLite 的
    /// BEGIN DEFERRED 快照会让并发读者同时通过预检查，因此不能用
    /// 读后写；PG 的 UPDATE 行锁语义与此一致。
    pub async fn consume(
        &self,
        token: &str,
        matching: AuthFlowMatch<'_>,
        now: i64,
    ) -> Result<AuthFlow, AuthFlowError> {
        if token.is_empty() || matching.purpose.is_empty() {
            return Err(AuthFlowError::Invalid);
        }
        let hash = token_hash(&self.key, token);
        backend!(&self.db, pool, dialect, {
            let mut update = QueryBuilder::new("UPDATE auth_flows SET consumed_at=");
            push_timestamp!(update, dialect, now);
            update
                .push(" WHERE token_hash=")
                .push_bind(hash.as_str())
                .push(" AND purpose=")
                .push_bind(matching.purpose);
            if matching.user_id != 0 {
                update.push(" AND user_id=").push_bind(matching.user_id);
            }
            if !matching.session_id.is_empty() {
                update
                    .push(" AND session_id=")
                    .push_bind(matching.session_id);
            }
            update.push(" AND consumed_at IS NULL AND expires_at>");
            push_timestamp!(update, dialect, now);
            let affected = update.build().execute(pool).await?.rows_affected();
            if affected == 1 {
                let mut query = QueryBuilder::new("SELECT ");
                query
                    .push(dialect.columns())
                    .push(" FROM auth_flows WHERE token_hash=")
                    .push_bind(hash.as_str());
                let row = query.build().fetch_optional(pool).await?;
                let mut flow = row.map(record!).transpose()?.ok_or(AuthFlowError::Storage)?;
                flow.consumed_at = Some(now);
                return Ok(flow);
            }
            // 未命中：重读区分无效、已消费与过期，保持 Go 判定顺序。
            let mut query = QueryBuilder::new("SELECT ");
            query
                .push(dialect.columns())
                .push(" FROM auth_flows WHERE token_hash=")
                .push_bind(hash.as_str())
                .push(" AND purpose=")
                .push_bind(matching.purpose);
            if matching.user_id != 0 {
                query.push(" AND user_id=").push_bind(matching.user_id);
            }
            if !matching.session_id.is_empty() {
                query
                    .push(" AND session_id=")
                    .push_bind(matching.session_id);
            }
            let row = query.build().fetch_optional(pool).await?;
            let Some(row) = row else {
                return Err(AuthFlowError::Invalid);
            };
            let flow = record!(row);
            if flow.consumed_at.is_some() {
                return Err(AuthFlowError::Consumed);
            }
            if flow.expires_at <= now {
                return Err(AuthFlowError::Expired);
            }
            Err(AuthFlowError::Consumed)
        })
    }

    /// 对应 Go `DeleteExpiredAuthFlows`：删除过期或已消费超过 24 小时的记录。
    pub async fn delete_expired(&self, now: i64) -> Result<u64, AuthFlowError> {
        let cutoff = now
            .checked_sub(CLEANUP_RETENTION_SECONDS)
            .ok_or(AuthFlowError::Invalid)?;
        backend!(&self.db, pool, dialect, {
            let mut delete = QueryBuilder::new("DELETE FROM auth_flows WHERE expires_at<");
            push_timestamp!(delete, dialect, cutoff);
            delete.push(" OR (consumed_at IS NOT NULL AND consumed_at<");
            push_timestamp!(delete, dialect, cutoff);
            delete.push(")");
            let result = delete.build().execute(pool).await?;
            Ok(result.rows_affected())
        })
    }
}
