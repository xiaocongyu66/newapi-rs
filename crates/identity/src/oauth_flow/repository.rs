//! OAuth/Telegram 用途的 `auth_flows` 读写：与 [`crate::auth_flow`] 仓储
//! 同 key、同 token 格式，但携带 Go `AuthFlow` 模型的 `provider` / `intent`
//! 两个可空列（`run_authflow.go:44-45`）。
//!
//! 不复用那个仓储的原因：`CreateAuthFlow`/`AuthFlowMatch` 的固定形状没有
//! 这两列，而 2FA/passkey 切片的调用方不需要它们；这里独立维护列投影，
//! HMAC key 与 token 生成完全共用（`crate::auth_flow::token`）。
//!
//! 另含：
//! - `claim_assertion`（Go `ClaimExternalAuthAssertion`，`run_authflow.go:125`）
//!   与事务内变体；
//! - `consume_telegram_bind`（Go `TelegramBind` 的
//!   `ConsumeAuthFlowWithAction`，`bind_telegram.go:140-200`）：消费 flow、
//!   断言防重放、会话活性校验、external_identity_claims 认领与
//!   `users.telegram_id` 条件更新在同一事务提交。
//!
//! 时间约定同 [`crate::auth_flow`]：调用方传 Unix 秒；`auth_flows` 的
//! expires_at/created_at/consumed_at 是数据库时间戳列（SQLite DATETIME、
//! PG TIMESTAMPTZ），SQL 中以 `datetime($n,'unixepoch')` / `to_timestamp($n)`
//! 互转，绝不把 BIGINT 直接写进这些列。

use newapi_storage::Database;
use sqlx::{QueryBuilder, Row};

use crate::SecretString;
use crate::auth_flow::token::{generate_token, token_hash};

use super::{PURPOSE_TELEGRAM_ASSERTION, TelegramFlowError};

/// 按后端展开同一方法体；`pool` 是正确类型的池引用，泛型在臂内解出。
/// 宏必须先于使用点定义（macro_rules 是文本顺序敏感的）。
macro_rules! backend {
    ($db:expr, $pool:ident, $body:block) => {
        match $db {
            Database::Sqlite($pool) => $body,
            Database::Postgres($pool) => $body,
        }
    };
}

/// Go `ClaimExternalAuthAssertionWithTx`（`run_authflow.go:134-158`）：
/// `token_hash = HMAC("external:"+purpose+":"+assertion)`，唯一索引冲突即
/// 已消费。SQLite 的 `INSERT OR IGNORE` 与 PG 的 `ON CONFLICT DO NOTHING`
/// 等价，都以 rows_affected 区分；时间列仍走时间戳表达式。展开为具体
/// 后端代码——泛型执行器上的 f64/tuple 绑定无法对任意 `DB: Database`
/// 成立。
macro_rules! claim_assertion_body {
    ($executor:expr, $dialect:expr, $purpose:expr, $assertion:expr, $expires_at:expr, $now:expr, $key:expr) => {{
        let purpose: &str = $purpose.trim();
        let assertion: &str = $assertion.trim();
        if purpose.is_empty() || assertion.is_empty() || $expires_at <= $now {
            return Err(TelegramFlowError::InvalidRequest);
        }
        let hash = token_hash($key, &format!("external:{purpose}:{assertion}"));
        let affected: u64 = if $dialect == Dialect::Postgres {
            sqlx::query(
                "INSERT INTO auth_flows (token_hash,purpose,provider,intent,user_id,session_id,payload,expires_at,consumed_at,created_at) \
                 VALUES ($1,$2,NULL,NULL,0,'','',to_timestamp($3),to_timestamp($4),to_timestamp($4)) \
                 ON CONFLICT (token_hash) DO NOTHING",
            )
            .bind(&hash)
            .bind(purpose)
            .bind($expires_at as f64)
            .bind($now as f64)
            .execute($executor)
            .await?
            .rows_affected()
        } else {
            sqlx::query(
                "INSERT OR IGNORE INTO auth_flows (token_hash,purpose,provider,intent,user_id,session_id,payload,expires_at,consumed_at,created_at) \
                 VALUES ($1,$2,NULL,NULL,0,'','',datetime($3,'unixepoch'),datetime($4,'unixepoch'),datetime($4,'unixepoch'))",
            )
            .bind(&hash)
            .bind(purpose)
            .bind($expires_at as f64)
            .bind($now as f64)
            .execute($executor)
            .await?
            .rows_affected()
        };
        if affected != 1 {
            return Err(TelegramFlowError::InvalidRequest);
        }
        Ok::<(), TelegramFlowError>(())
    }};
}

/// 绑定 Unix 秒，但在 SQL 中转换为数据库时间戳（与 auth_flow 仓储同一形状）。
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Dialect {
    Sqlite,
    Postgres,
}

impl Dialect {
    fn of(db: &Database) -> Self {
        match db {
            Database::Sqlite(_) => Self::Sqlite,
            Database::Postgres(_) => Self::Postgres,
        }
    }
    fn columns(self) -> &'static str {
        // 固定列投影：同列名，时间列按 epoch 秒读出；SQLite 老库的
        // INTEGER 列显式提升 BIGINT。
        match self {
            Self::Sqlite => {
                "id,purpose,provider,intent,CAST(user_id AS BIGINT) AS user_id,session_id,payload,CAST(strftime('%s',expires_at) AS INTEGER) AS expires_at,CAST(strftime('%s',consumed_at) AS INTEGER) AS consumed_at"
            }
            Self::Postgres => {
                "id,purpose,provider,intent,CAST(user_id AS BIGINT) AS user_id,session_id,payload,CAST(EXTRACT(EPOCH FROM expires_at) AS BIGINT) AS expires_at,CAST(EXTRACT(EPOCH FROM consumed_at) AS BIGINT) AS consumed_at"
            }
        }
    }
}

/// 通用行投影；两个后端的别名一致。
fn record_flow<R: sqlx::Row>(row: R) -> Result<OAuthFlow, sqlx::Error> {
    Ok(OAuthFlow {
        id: row.try_get("id")?,
        purpose: row.try_get("purpose")?,
        provider: row
            .try_get::<Option<String>, _>("provider")?
            .unwrap_or_default(),
        intent: row
            .try_get::<Option<String>, _>("intent")?
            .unwrap_or_default(),
        user_id: row.try_get::<Option<i64>, _>("user_id")?.unwrap_or(0),
        session_id: row
            .try_get::<Option<String>, _>("session_id")?
            .unwrap_or_default(),
        payload: row
            .try_get::<Option<String>, _>("payload")?
            .unwrap_or_default(),
        expires_at: row.try_get("expires_at")?,
        consumed_at: row.try_get::<Option<i64>, _>("consumed_at")?,
    })
}

/// Go `AuthFlow` 的行投影；`user_id` 为 0 / `session_id` 为空串表示匿名
/// 登录 flow（Go 零值语义）。不派生 Debug，避免 payload 入日志。
#[derive(Clone, PartialEq, Eq)]
pub struct OAuthFlow {
    pub id: i64,
    pub purpose: String,
    pub provider: String,
    pub intent: String,
    pub user_id: i64,
    pub session_id: String,
    pub payload: String,
    pub expires_at: i64,
    pub consumed_at: Option<i64>,
}

/// 创建输入；`provider` / `intent` 对应 Go `AuthFlowCreate` 的两个可选列。
pub struct CreateOAuthFlow {
    pub purpose: &'static str,
    pub provider: String,
    pub intent: String,
    pub user_id: i64,
    pub session_id: String,
    pub payload: String,
    pub expires_at: i64,
}

/// 查询/消费绑定；空串字段与 0 表示不追加该过滤条件（Go 的零值语义）。
#[derive(Clone, Debug, Default)]
pub struct OAuthFlowMatch<'a> {
    pub purpose: &'a str,
    pub provider: &'a str,
    pub intent: &'a str,
    pub user_id: i64,
    pub session_id: &'a str,
}

/// 追加 `provider` / `intent` / `user_id` / `session_id` 的非零值过滤。
fn push_optional_match<'a, DB: sqlx::Database>(
    query: &mut QueryBuilder<'a, DB>,
    matching: &OAuthFlowMatch<'a>,
) {
    if !matching.provider.is_empty() {
        query.push(" AND provider=").push_bind(matching.provider);
    }
    if !matching.intent.is_empty() {
        query.push(" AND intent=").push_bind(matching.intent);
    }
    if matching.user_id != 0 {
        query.push(" AND user_id=").push_bind(matching.user_id);
    }
    if !matching.session_id.is_empty() {
        query
            .push(" AND session_id=")
            .push_bind(matching.session_id);
    }
}

/// 持有连接池与 auth-flow HMAC key；key 不实现 Debug。
#[derive(Clone)]
pub struct OAuthFlowRepository {
    db: Database,
    key: Vec<u8>,
}

impl OAuthFlowRepository {
    /// key 必须与 [`crate::auth_flow`] 的 key 一致（`auth_flow_key(secret)`）。
    pub fn new(db: Database, key: impl Into<Vec<u8>>) -> Self {
        Self {
            db,
            key: key.into(),
        }
    }

    /// Go `CreateAuthFlow`：purpose 非空且未过期即插入，返回原始 token。
    /// `expires_at <= now` 与空 purpose 归为 FlowInvalid（Go
    /// `ErrAuthFlowInvalid`；HTTP 层三个 flow 错误同码）。
    pub async fn create(
        &self,
        input: CreateOAuthFlow,
        now: i64,
    ) -> Result<SecretString, TelegramFlowError> {
        if input.purpose.trim().is_empty() || input.expires_at <= now {
            return Err(TelegramFlowError::FlowInvalid);
        }
        let raw = generate_token()?;
        let hash = token_hash(&self.key, raw.expose_secret());
        let dialect = Dialect::of(&self.db);
        backend!(&self.db, pool, {
            let mut insert = QueryBuilder::new(
                "INSERT INTO auth_flows (token_hash,purpose,provider,intent,user_id,session_id,payload,expires_at,consumed_at,created_at) VALUES (",
            );
            insert
                .push_bind(hash.as_str())
                .push(",")
                .push_bind(input.purpose)
                .push(",")
                .push_bind(&input.provider)
                .push(",")
                .push_bind(&input.intent)
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
        });
        Ok(raw)
    }

    /// Go `GetAuthFlow`：只读校验，已消费优先于过期判定。三个 Go 错误码
    /// （Invalid/Expired/Consumed）在 HTTP 层同码（Telegram:
    /// `TELEGRAM_BIND_FLOW_INVALID`；OAuth: `oauth.state_invalid`），
    /// 统一折叠为 [`TelegramFlowError::FlowInvalid`]。
    pub async fn get(
        &self,
        token: &str,
        matching: OAuthFlowMatch<'_>,
        now: i64,
    ) -> Result<OAuthFlow, TelegramFlowError> {
        if token.is_empty() || matching.purpose.is_empty() {
            return Err(TelegramFlowError::FlowInvalid);
        }
        let hash = token_hash(&self.key, token);
        let flow = self.fetch_flow(&hash, &matching).await?;
        classify_existing(flow, now)
    }

    /// Go `ConsumeAuthFlow`：条件 UPDATE 的原子消费，唯一赢家读回。
    pub async fn consume(
        &self,
        token: &str,
        matching: OAuthFlowMatch<'_>,
        now: i64,
    ) -> Result<OAuthFlow, TelegramFlowError> {
        if token.is_empty() || matching.purpose.is_empty() {
            return Err(TelegramFlowError::FlowInvalid);
        }
        let hash = token_hash(&self.key, token);
        let affected = self.consume_update(&hash, &matching, now).await?;
        if affected == 1 {
            let mut flow = self
                .fetch_flow(&hash, &matching)
                .await?
                .ok_or(TelegramFlowError::Storage)?;
            flow.consumed_at = Some(now);
            return Ok(flow);
        }
        // 未命中：重读区分不存在与已存在但不可消费；对 HTTP 层等价。
        let existing = self.fetch_flow(&hash, &matching).await?;
        match existing {
            None => Err(TelegramFlowError::FlowInvalid),
            Some(flow) => classify_existing(flow, now),
        }
    }

    /// Go `ClaimExternalAuthAssertion`（非事务变体）：断言防重放的独立提交。
    pub async fn claim_assertion(
        &self,
        assertion: &str,
        expires_at: i64,
        now: i64,
    ) -> Result<(), TelegramFlowError> {
        let dialect = Dialect::of(&self.db);
        let key = self.key.as_slice();
        backend!(&self.db, pool, {
            claim_assertion_body!(
                pool,
                dialect,
                PURPOSE_TELEGRAM_ASSERTION,
                assertion,
                expires_at,
                now,
                key
            )
        })
    }

    /// Go `TelegramBind` 的事务主体：消费 flow → 断言防重放 → 用户/会话/
    /// 外部身份/绑定列的检查与更新，全部在一个数据库事务内提交或回滚。
    /// SQLite 用 `BEGIN IMMEDIATE` 保证读改写原子；PG 用默认隔离 +
    /// `FOR UPDATE` 行锁（Go `LockForUpdate`）。事务随 `Err` 提前返回由
    /// sqlx 安排回滚（与 setup 切片同一约定）。
    pub async fn consume_telegram_bind(
        &self,
        token: &str,
        matching: OAuthFlowMatch<'_>,
        telegram_id: &str,
        assertion: &str,
        assertion_expires_at: i64,
        now: i64,
    ) -> Result<String, TelegramFlowError> {
        if token.is_empty() || matching.purpose.is_empty() {
            return Err(TelegramFlowError::FlowInvalid);
        }
        let hash = token_hash(&self.key, token);
        let key = self.key.as_slice();
        match &self.db {
            Database::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                let outcome = telegram_bind_body!(
                    &mut *tx,
                    Dialect::Sqlite,
                    key,
                    hash.as_str(),
                    &matching,
                    telegram_id,
                    assertion,
                    assertion_expires_at,
                    now
                );
                match outcome {
                    Ok(value) => {
                        tx.commit().await?;
                        Ok(value)
                    }
                    Err(error) => Err(error),
                }
            }
            Database::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                let outcome = telegram_bind_body!(
                    &mut *tx,
                    Dialect::Postgres,
                    key,
                    hash.as_str(),
                    &matching,
                    telegram_id,
                    assertion,
                    assertion_expires_at,
                    now
                );
                match outcome {
                    Ok(value) => {
                        tx.commit().await?;
                        Ok(value)
                    }
                    Err(error) => Err(error),
                }
            }
        }
    }

    /// 按 token 摘要 + 匹配条件读单条 flow；不存在返回 `None`。
    async fn fetch_flow(
        &self,
        hash: &str,
        matching: &OAuthFlowMatch<'_>,
    ) -> Result<Option<OAuthFlow>, TelegramFlowError> {
        let dialect = Dialect::of(&self.db);
        let row = backend!(&self.db, pool, {
            let mut query = QueryBuilder::new("SELECT ");
            query
                .push(dialect.columns())
                .push(" FROM auth_flows WHERE token_hash=")
                .push_bind(hash)
                .push(" AND purpose=")
                .push_bind(matching.purpose);
            push_optional_match(&mut query, matching);
            query.build().fetch_optional(pool).await?
        });
        row.map(record_flow).transpose().map_err(sqlx::Error::into)
    }

    /// Go 的条件 UPDATE：`consumed_at = now WHERE … AND consumed_at IS NULL
    /// AND expires_at > now`。返回命中行数。
    async fn consume_update(
        &self,
        hash: &str,
        matching: &OAuthFlowMatch<'_>,
        now: i64,
    ) -> Result<u64, TelegramFlowError> {
        let dialect = Dialect::of(&self.db);
        let affected = backend!(&self.db, pool, {
            let mut update = QueryBuilder::new("UPDATE auth_flows SET consumed_at=");
            push_timestamp!(update, dialect, now);
            update
                .push(" WHERE token_hash=")
                .push_bind(hash)
                .push(" AND purpose=")
                .push_bind(matching.purpose);
            push_optional_match(&mut update, matching);
            update.push(" AND consumed_at IS NULL AND expires_at>");
            push_timestamp!(update, dialect, now);
            update.build().execute(pool).await?.rows_affected()
        });
        Ok(affected)
    }
}

/// Go 的分类顺序：已消费优先于过期；不存在（上游已判）不经过这里。
fn classify_existing(flow: OAuthFlow, now: i64) -> Result<OAuthFlow, TelegramFlowError> {
    if flow.consumed_at.is_some() {
        return Err(TelegramFlowError::FlowInvalid);
    }
    if flow.expires_at <= now {
        return Err(TelegramFlowError::FlowInvalid);
    }
    Ok(flow)
}

/// Go `TelegramBind` 的事务闭包体（`bind_telegram.go:144-199`）：消费 flow →
/// 断言防重放 → 用户/会话/外部身份/绑定列的检查与更新。按宏展开成具体
/// 后端代码；PG 分支在 flow 读取上追加 `FOR UPDATE`（Go `LockForUpdate`），
/// SQLite 单写者天然串行。
macro_rules! telegram_bind_body {
    ($executor:expr, $dialect:expr, $key:expr, $hash:expr, $matching:expr, $telegram_id:expr, $assertion:expr, $assertion_expires_at:expr, $now:expr) => {{
        // 1. 锁定并读取 flow（Go `LockForUpdate` + First；匹配条件绑定
        // purpose/user/session，provider/intent 不参与 Telegram 用途）。
        let mut select = QueryBuilder::new("SELECT ");
        select
            .push($dialect.columns())
            .push(" FROM auth_flows WHERE token_hash=")
            .push_bind($hash)
            .push(" AND purpose=")
            .push_bind($matching.purpose);
        if $matching.user_id != 0 {
            select.push(" AND user_id=").push_bind($matching.user_id);
        }
        if !$matching.session_id.is_empty() {
            select
                .push(" AND session_id=")
                .push_bind($matching.session_id);
        }
        if $dialect == Dialect::Postgres {
            select.push(" FOR UPDATE");
        }
        let row = select
            .build()
            .fetch_optional($executor)
            .await?
            .ok_or(TelegramFlowError::FlowInvalid)?;
        let flow = record_flow(row)?;
        if flow.consumed_at.is_some() {
            return Err(TelegramFlowError::FlowInvalid);
        }
        if flow.expires_at <= $now {
            return Err(TelegramFlowError::FlowInvalid);
        }
        // 2. 条件消费（id + consumed_at IS NULL + 未过期）。
        let mut update = QueryBuilder::new("UPDATE auth_flows SET consumed_at=");
        push_timestamp!(update, $dialect, $now);
        update
            .push(" WHERE id=")
            .push_bind(flow.id)
            .push(" AND consumed_at IS NULL AND expires_at>");
        push_timestamp!(update, $dialect, $now);
        let affected = update.build().execute($executor).await?.rows_affected();
        if affected != 1 {
            return Err(TelegramFlowError::FlowInvalid);
        }
        // 3. 断言防重放（Go 闭包第一步）。
        claim_assertion_body!(
            $executor,
            $dialect,
            PURPOSE_TELEGRAM_ASSERTION,
            $assertion,
            $assertion_expires_at,
            $now,
            $key
        )?;
        // 4. 用户行（软删即不存在；Go 的 First 带软删过滤）。
        let user: Option<(i64, i64, i64)> = sqlx::query_as(
            "SELECT CAST(id AS BIGINT), CAST(status AS BIGINT), CAST(auth_version AS BIGINT) \
             FROM users WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(flow.user_id)
        .fetch_optional($executor)
        .await?;
        let Some((user_id, status, auth_version)) = user else {
            return Err(TelegramFlowError::UserDeleted);
        };
        if status != 1 {
            return Err(TelegramFlowError::UserDisabled);
        }
        // 5. 会话活性（Go 的 UserSession 检查；status 是字符串 "active"）。
        let session: Option<(String, i64, i64, i64)> = sqlx::query_as(
            "SELECT status, CAST(revoked_at AS BIGINT), CAST(expires_at AS BIGINT), \
             CAST(user_auth_version AS BIGINT) \
             FROM user_sessions WHERE sid = $1 AND user_id = $2",
        )
        .bind(&flow.session_id)
        .bind(flow.user_id)
        .fetch_optional($executor)
        .await?;
        let Some((session_status, revoked_at, session_expires_at, session_auth_version)) = session
        else {
            return Err(TelegramFlowError::SessionInvalid);
        };
        if session_status != "active"
            || revoked_at != 0
            || session_expires_at <= $now
            || session_auth_version != auth_version
        {
            return Err(TelegramFlowError::SessionInvalid);
        }
        // 6. 目标用户的 Telegram 槽位必须为空。
        let current: Option<String> =
            sqlx::query_scalar("SELECT telegram_id FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_optional($executor)
                .await?
                .unwrap_or_default();
        if !current.is_empty() {
            return Err(TelegramFlowError::AlreadyBound);
        }
        // 7. external_identity_claims 认领（Go `ClaimExternalIdentityWithTx`）：
        // 幂等映射复用，竞争 subject/用户拒绝；所有权以回读判定，不信任
        // rows_affected（两个数据库的冲突语义不同）。
        let insert = if $dialect == Dialect::Postgres {
            "INSERT INTO external_identity_claims (provider,subject,user_id,created_at) \
             VALUES ($1,$2,$3,to_timestamp($4)) ON CONFLICT DO NOTHING"
        } else {
            "INSERT OR IGNORE INTO external_identity_claims (provider,subject,user_id,created_at) \
             VALUES ($1,$2,$3,datetime($4,'unixepoch'))"
        };
        sqlx::query(insert)
            .bind("telegram")
            .bind($telegram_id)
            .bind(user_id)
            .bind($now as f64)
            .execute($executor)
            .await?;
        let subject_owner: Option<i64> = sqlx::query_scalar(
            "SELECT CAST(user_id AS BIGINT) FROM external_identity_claims \
             WHERE provider = $1 AND subject = $2",
        )
        .bind("telegram")
        .bind($telegram_id)
        .fetch_optional($executor)
        .await?;
        if subject_owner != Some(user_id) {
            return Err(TelegramFlowError::AlreadyBound);
        }
        let user_claim: Option<String> = sqlx::query_scalar(
            "SELECT subject FROM external_identity_claims WHERE provider = $1 AND user_id = $2",
        )
        .bind("telegram")
        .bind(user_id)
        .fetch_optional($executor)
        .await?;
        match user_claim {
            Some(claim) if claim == $telegram_id => {}
            _ => return Err(TelegramFlowError::AlreadyBound),
        }
        // 8. 条件更新绑定列（status / auth_version / telegram_id 三重守卫）。
        let result = sqlx::query(
            "UPDATE users SET telegram_id = $1 \
             WHERE id = $2 AND status = 1 AND auth_version = $3 AND telegram_id = ''",
        )
        .bind($telegram_id)
        .bind(user_id)
        .bind(auth_version)
        .execute($executor)
        .await?;
        if result.rows_affected() != 1 {
            return Err(TelegramFlowError::AlreadyBound);
        }
        Ok::<String, TelegramFlowError>($telegram_id.to_owned())
    }};
}
