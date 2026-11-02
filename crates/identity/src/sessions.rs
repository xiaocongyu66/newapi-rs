//! 仅数据库会话仓储，不迁移、不签发令牌、不读取缓存，尚未开放 HTTP。
//! 时间均为调用方传入的 Unix 秒。开启缓存时必须接真实共享 deny fence，
//! 并在 access/refresh 前检查用户缓存安全栅栏；本模块不是完整缓存认证服务。
//! IP/UA 字节截断跨 UTF-8 字符的兼容策略尚未批准，显式返回
//! MetadataEncodingUnsupported，不冒充原 Go 的 Invalid 或数据库错误。
use std::future::Future;

use newapi_storage::Database;
use sqlx::Row;
use subtle::ConstantTimeEq;

const LIFETIME: i64 = 30 * 86400;
const COLUMNS: &str = "sid,CAST(user_id AS BIGINT) AS user_id,version,user_auth_version,status,refresh_hash,previous_refresh_hash,previous_valid_until,login_method,ip,user_agent,created_at,last_active_at,expires_at,revoked_at,revoked_reason";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionError {
    Invalid,
    NotFound,
    Inactive,
    UserSecurityChanged,
    ActiveLimit,
    IssuanceLimit,
    /// Rust String 尚不能承载 Go 字节截断产生的非法 UTF-8；禁止直接映射 HTTP 400。
    MetadataEncodingUnsupported,
    /// 仅 SQLite 已知 BUSY/LOCKED 错误；不包含 PG、连接池超时或一般存储失败。
    DatabaseBusy,
    Storage,
    Fence,
}
impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Invalid => "invalid session input",
            Self::NotFound => "session not found",
            Self::Inactive => "session inactive",
            Self::UserSecurityChanged => "user security changed",
            Self::ActiveLimit => "active session limit",
            Self::IssuanceLimit => "session issuance limit",
            Self::MetadataEncodingUnsupported => "session metadata byte encoding is not supported",
            Self::DatabaseBusy => "session SQLite database is busy or locked",
            Self::Storage => "session storage failure",
            Self::Fence => "session deny fence failure",
        })
    }
}
impl std::error::Error for SessionError {}
impl From<sqlx::Error> for SessionError {
    fn from(error: sqlx::Error) -> Self {
        if let sqlx::Error::Database(db_error) = &error {
            // 先按实际驱动类型收窄，绝不能把 PG SQLSTATE 当 SQLite 数字码。
            if let Some(sqlite) = db_error.try_downcast_ref::<sqlx::sqlite::SqliteError>() {
                use sqlx::error::DatabaseError;
                // 明确白名单，不匹配错误文本，也不接受任意低八位相同的未知扩展码。
                // BUSY / LOCKED / BUSY_RECOVERY / BUSY_SNAPSHOT / BUSY_TIMEOUT /
                // LOCKED_SHAREDCACHE / LOCKED_VTAB。
                if matches!(
                    sqlite.code().as_deref(),
                    Some("5" | "6" | "261" | "517" | "773" | "262" | "518")
                ) {
                    return Self::DatabaseBusy;
                }
            }
        }
        // 不在此自动重试；约束、解码、I/O、连接池及所有 PG 错误保持 Storage。
        Self::Storage
    }
}

/// 小写十六进制 HMAC-SHA256 摘要，不是 refresh 明文；禁止 Debug/Serialize。
#[derive(Clone)]
pub struct RefreshHash(String);
impl RefreshHash {
    pub fn from_lower_hex(value: String) -> Result<Self, SessionError> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(SessionError::Invalid);
        }
        Ok(Self(value))
    }
    fn matches(&self, stored: &str) -> bool {
        bool::from(self.0.as_bytes().ct_eq(stored.as_bytes()))
    }
}

/// 可公开的元数据；不含 refresh 材料，fence 同样只能接收此投影。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionMetadata {
    pub sid: String,
    pub user_id: i64,
    pub version: i64,
    pub user_auth_version: i64,
    pub status: String,
    pub login_method: String,
    pub ip: String,
    pub user_agent: String,
    pub created_at: i64,
    pub last_active_at: i64,
    pub expires_at: i64,
    pub revoked_at: i64,
    pub revoked_reason: String,
}
impl SessionMetadata {
    fn active(&self, now: i64) -> bool {
        self.status == "active" && self.revoked_at == 0 && self.expires_at > now
    }
}

/// 权威数据库记录；私有 hash 仅可比较，不能打印或序列化。
pub struct SessionRecord {
    pub metadata: SessionMetadata,
    refresh_hash: String,
    previous_refresh_hash: String,
    previous_valid_until: i64,
}
impl SessionRecord {
    pub fn current_hash_matches(&self, hash: &RefreshHash) -> bool {
        hash.matches(&self.refresh_hash)
    }
}

/// 返回 Ok 前必须发布共享 revoking deny；失败不得静默降级到 NoCache。
/// 终态写失败在提交后单独报告；调用方必须记录，但不能当作数据库回滚。
/// SQL 失败不得移除 pending fence，应保留有界 deny TTL。
pub trait RevocationFence: Send + Sync {
    fn revoking(
        &self,
        session: &SessionMetadata,
        now: i64,
        reason: &str,
    ) -> impl Future<Output = Result<(), SessionError>> + Send;
    fn revoked(
        &self,
        session: &SessionMetadata,
        now: i64,
    ) -> impl Future<Output = Result<(), SessionError>> + Send;
}

/// 仅在整个部署明确禁用 Redis/会话缓存时显式选择。
/// 不提供默认 fence，真实适配失败时也不自动回退。
pub struct NoCache {
    _private: (),
}
impl NoCache {
    pub fn explicitly_disabled() -> Self {
        Self { _private: () }
    }
}
impl RevocationFence for NoCache {
    async fn revoking(&self, _: &SessionMetadata, _: i64, _: &str) -> Result<(), SessionError> {
        Ok(())
    }
    async fn revoked(&self, _: &SessionMetadata, _: i64) -> Result<(), SessionError> {
        Ok(())
    }
}

pub struct CreateSession {
    pub sid: String,
    pub user_id: i64,
    pub expected_auth_version: Option<i64>,
    pub refresh_hash: RefreshHash,
    pub login_method: String,
    pub ip: String,
    pub user_agent: String,
}
#[derive(Clone, Copy)]
pub struct SessionLimits {
    pub active: i64,
    pub issued: i64,
    pub issuance_window: i64,
}
impl Default for SessionLimits {
    fn default() -> Self {
        Self {
            active: 50,
            issued: 100,
            issuance_window: 86400,
        }
    }
}

pub enum RefreshOutcome {
    Rotated(SessionRecord),
    /// 仅当服务推导的确定性 next hash 匹配记录时，才允许幂等收敛。
    PreviousWithinGrace(SessionRecord),
    Reused(RevokeReport),
    /// 认证失败；携带安全变更撤销操作的实际提交状态。
    UserSecurityChanged(RevokeReport),
}
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RevokeReport {
    pub revoked_count: u64,
    pub terminal_fence_failures: u64,
}
#[derive(Debug)]
pub struct BatchFailure {
    pub committed: RevokeReport,
    pub error: SessionError,
}

// 静态 SQL 的 $ 参数由两驱动支持；动态查询用 QueryBuilder 生成绑定占位符。
// 分别展开类型化查询，不引入 sqlx::Any 或额外连接池。
macro_rules! backend {
    ($db:expr, $pool:ident, $body:block) => {
        match $db {
            Database::Sqlite($pool) => $body,
            Database::Postgres($pool) => $body,
        }
    };
}
macro_rules! record {
    ($r:expr) => {{
        let r = $r;
        SessionRecord {
            metadata: SessionMetadata {
                sid: r.try_get("sid")?,
                user_id: r.try_get("user_id")?,
                version: r.try_get("version")?,
                user_auth_version: r.try_get("user_auth_version")?,
                status: r.try_get("status")?,
                login_method: r.try_get("login_method")?,
                ip: r.try_get::<Option<String>, _>("ip")?.unwrap_or_default(),
                user_agent: r
                    .try_get::<Option<String>, _>("user_agent")?
                    .unwrap_or_default(),
                created_at: r
                    .try_get::<Option<i64>, _>("created_at")?
                    .unwrap_or_default(),
                last_active_at: r.try_get("last_active_at")?,
                expires_at: r.try_get("expires_at")?,
                revoked_at: r.try_get("revoked_at")?,
                revoked_reason: r
                    .try_get::<Option<String>, _>("revoked_reason")?
                    .unwrap_or_default(),
            },
            refresh_hash: r.try_get::<String, _>("refresh_hash")?.trim().to_owned(),
            previous_refresh_hash: r
                .try_get::<Option<String>, _>("previous_refresh_hash")?
                .unwrap_or_default()
                .trim()
                .to_owned(),
            previous_valid_until: r.try_get("previous_valid_until")?,
        }
    }};
}

#[derive(Clone)]
pub struct SessionRepository {
    db: Database,
}
impl SessionRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub async fn authoritative(&self, sid: &str) -> Result<Option<SessionRecord>, SessionError> {
        if sid.is_empty() {
            return Err(SessionError::Invalid);
        }
        backend!(&self.db, pool, {
            // 列仅来自模块内固定白名单；所有业务值必须绑定。
            let mut query = sqlx::QueryBuilder::new("SELECT ");
            query
                .push(COLUMNS)
                .push(" FROM user_sessions WHERE sid=")
                .push_bind(sid);
            match query.build().fetch_optional(pool).await? {
                Some(row) => Ok(Some(record!(row))),
                None => Ok(None),
            }
        })
    }

    async fn user_version(&self, user_id: i64) -> Result<i64, SessionError> {
        backend!(&self.db, pool, {
            sqlx::query_scalar::<_, i64>("SELECT auth_version FROM users WHERE id=$1 AND status=1 AND deleted_at IS NULL AND auth_version>0")
                .bind(user_id).fetch_optional(pool).await?
                .ok_or(SessionError::UserSecurityChanged)
        })
    }

    /// 保留 Go 的先计数再插入语义，不保证并发硬上限。
    /// 不暗中引入新 schema 或用户锁策略。
    pub async fn create(
        &self,
        input: CreateSession,
        limits: SessionLimits,
        now: i64,
    ) -> Result<SessionRecord, SessionError> {
        if input.user_id <= 0
            || input.sid.is_empty()
            || input.sid.len() > 64
            || now <= 0
            || limits.active <= 0
            || limits.issued <= 0
            || limits.issuance_window <= 0
        {
            return Err(SessionError::Invalid);
        }
        let expires = now.checked_add(LIFETIME).ok_or(SessionError::Invalid)?;
        let since = now
            .checked_sub(limits.issuance_window)
            .ok_or(SessionError::Invalid)?;
        let uv = self.user_version(input.user_id).await?;
        if input.expected_auth_version.is_some_and(|v| v != uv) {
            return Err(SessionError::UserSecurityChanged);
        }
        let method = input.login_method.trim();
        let method = if method.is_empty() { "unknown" } else { method };
        if method.len() > 32 {
            return Err(SessionError::Invalid);
        }
        let ip = truncate_bytes(&input.ip, 64)?;
        let ua = truncate_bytes(&input.user_agent, 512)?;
        backend!(&self.db, pool, {
            let active: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_sessions WHERE user_id=$1 AND status='active' AND expires_at>$2")
                .bind(input.user_id).bind(now).fetch_one(pool).await?;
            if active >= limits.active {
                return Err(SessionError::ActiveLimit);
            }
            let issued: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM user_sessions WHERE user_id=$1 AND created_at>$2",
            )
            .bind(input.user_id)
            .bind(since)
            .fetch_one(pool)
            .await?;
            if issued >= limits.issued {
                return Err(SessionError::IssuanceLimit);
            }
            sqlx::query("INSERT INTO user_sessions (sid,user_id,version,user_auth_version,status,refresh_hash,previous_refresh_hash,previous_valid_until,login_method,ip,user_agent,created_at,last_active_at,expires_at,revoked_at,revoked_reason) VALUES ($1,$2,1,$3,'active',$4,'',0,$5,$6,$7,$8,$8,$9,0,'')")
                .bind(&input.sid).bind(input.user_id).bind(uv).bind(&input.refresh_hash.0)
                .bind(method).bind(ip).bind(ua).bind(now).bind(expires).execute(pool).await?;
        });
        self.authoritative(&input.sid)
            .await?
            .ok_or(SessionError::NotFound)
    }

    pub async fn validate_access(
        &self,
        user_id: i64,
        sid: &str,
        sv: i64,
        uv: i64,
        now: i64,
    ) -> Result<SessionRecord, SessionError> {
        if user_id <= 0 || sv <= 0 || uv <= 0 {
            return Err(SessionError::Invalid);
        }
        let row = self
            .authoritative(sid)
            .await?
            .ok_or(SessionError::NotFound)?;
        let m = &row.metadata;
        if m.user_id != user_id || !m.active(now) || m.version != sv || m.user_auth_version != uv {
            return Err(SessionError::Inactive);
        }
        if self.user_version(user_id).await? != uv {
            return Err(SessionError::UserSecurityChanged);
        }
        Ok(row)
    }

    /// 最多三次非事务读/CAS；version 不增加，绝对到期时间不延长。
    /// 未知 hash 不触发 deny fence 或撤销。
    /// 调用方进入前检查用户缓存栅栏；这里始终核对 SQL 当前用户。
    pub async fn rotate<F: RevocationFence>(
        &self,
        fence: &F,
        user_id: i64,
        sid: &str,
        presented: &RefreshHash,
        next: &RefreshHash,
        now: i64,
    ) -> Result<RefreshOutcome, SessionError> {
        if user_id <= 0 || now <= 0 || presented.matches(&next.0) {
            return Err(SessionError::Invalid);
        }
        let grace = now.checked_add(30).ok_or(SessionError::Invalid)?;
        for _ in 0..3 {
            let mut row = self
                .authoritative(sid)
                .await?
                .ok_or(SessionError::NotFound)?;
            if row.metadata.user_id != user_id || !row.metadata.active(now) {
                return Err(SessionError::Inactive);
            }
            let is_current = row.current_hash_matches(presented);
            let is_previous = presented.matches(&row.previous_refresh_hash);
            // 即使用户安全状态变更，也不能让未知 secret 触发 SID 撤销。
            if !is_current && !is_previous {
                return Err(SessionError::Invalid);
            }
            match self.user_version(user_id).await {
                Ok(uv) if uv == row.metadata.user_auth_version => {}
                Ok(_) | Err(SessionError::UserSecurityChanged) => {
                    let report = self
                        .revoke(fence, user_id, sid, "user_security_changed", now)
                        .await?;
                    return Ok(RefreshOutcome::UserSecurityChanged(report));
                }
                Err(e) => return Err(e),
            }
            if is_current {
                let affected = backend!(&self.db, pool, {
                    sqlx::query("UPDATE user_sessions SET previous_refresh_hash=refresh_hash,previous_valid_until=$1,refresh_hash=$2,last_active_at=$3 WHERE sid=$4 AND user_id=$5 AND status='active' AND revoked_at=0 AND expires_at>$3 AND refresh_hash=$6")
                        .bind(grace).bind(&next.0).bind(now).bind(sid).bind(user_id).bind(&presented.0)
                        .execute(pool).await?.rows_affected()
                });
                if affected == 0 {
                    continue;
                }
                row.previous_refresh_hash = row.refresh_hash;
                row.previous_valid_until = grace;
                row.refresh_hash = next.0.clone();
                row.metadata.last_active_at = now;
                return Ok(RefreshOutcome::Rotated(row));
            }
            if now <= row.previous_valid_until {
                return Ok(RefreshOutcome::PreviousWithinGrace(row));
            }
            // 此处不能 CAS hash：并发轮换后整个泄露会话仍须撤销。
            return Ok(RefreshOutcome::Reused(
                self.revoke(fence, user_id, sid, "refresh_reuse", now)
                    .await?,
            ));
        }
        Err(SessionError::Invalid)
    }

    /// 候选读取 → pending fence → 事务重读 → 提交 → 终态 fence。
    pub async fn revoke<F: RevocationFence>(
        &self,
        fence: &F,
        user_id: i64,
        sid: &str,
        reason: &str,
        now: i64,
    ) -> Result<RevokeReport, SessionError> {
        validate_revoke(user_id, reason, now)?;
        let Some(row) = self.authoritative(sid).await? else {
            return Ok(RevokeReport::default());
        };
        if row.metadata.user_id != user_id || !row.metadata.active(now) {
            return Ok(RevokeReport::default());
        }
        fence.revoking(&row.metadata, now, reason).await?;
        let changed = self
            .revoke_fenced_batch(&[row.metadata], user_id, reason, now)
            .await?;
        Ok(finalize(fence, changed, now).await)
    }

    /// 仅凭 cookie 登出：先在事务内验证摘要，再发布 fence。
    /// 仅持有 SID 不能获得撤销权限。
    pub async fn revoke_by_refresh<F: RevocationFence>(
        &self,
        fence: &F,
        sid: &str,
        presented: &RefreshHash,
        reason: &str,
        now: i64,
    ) -> Result<RevokeReport, SessionError> {
        if sid.is_empty() || now <= 0 || reason.len() > 64 {
            return Err(SessionError::Invalid);
        }
        let lock = if matches!(self.db, Database::Postgres(_)) {
            " FOR UPDATE"
        } else {
            ""
        };
        let changed = backend!(&self.db, pool, {
            let mut tx = pool.begin().await?;
            let mut query = sqlx::QueryBuilder::new("SELECT ");
            query
                .push(COLUMNS)
                .push(" FROM user_sessions WHERE sid=")
                .push_bind(sid)
                .push(lock);
            let row = query.build().fetch_optional(&mut *tx).await?;
            let mut changed = Vec::new();
            if let Some(row) = row {
                let row = record!(row);
                let authorized = row.current_hash_matches(presented)
                    || (now <= row.previous_valid_until
                        && presented.matches(&row.previous_refresh_hash));
                if row.metadata.active(now) && authorized {
                    let mut m = row.metadata;
                    fence.revoking(&m, now, reason).await?;
                    let n = sqlx::query("UPDATE user_sessions SET status='revoked',revoked_at=$1,revoked_reason=$2 WHERE sid=$3 AND user_id=$4 AND status='active' AND revoked_at=0 AND expires_at>$1")
                        .bind(now).bind(reason).bind(sid).bind(m.user_id).execute(&mut *tx).await?.rows_affected();
                    if n == 1 {
                        m.status = "revoked".into();
                        m.revoked_at = now;
                        m.revoked_reason = reason.into();
                        changed.push(m);
                    }
                }
            }
            tx.commit().await?;
            changed
        });
        Ok(finalize(fence, changed, now).await)
    }

    // 私有方法：不暴露绕过 fence 的高层撤销入口。
    async fn revoke_fenced_batch(
        &self,
        candidates: &[SessionMetadata],
        user_id: i64,
        reason: &str,
        now: i64,
    ) -> Result<Vec<SessionMetadata>, SessionError> {
        let lock = if matches!(self.db, Database::Postgres(_)) {
            " FOR UPDATE"
        } else {
            ""
        };
        backend!(&self.db, pool, {
            let mut tx = pool.begin().await?;
            let mut changed = Vec::new();
            for candidate in candidates {
                let mut query = sqlx::QueryBuilder::new("SELECT ");
                query
                    .push(COLUMNS)
                    .push(" FROM user_sessions WHERE sid=")
                    .push_bind(&candidate.sid)
                    .push(" AND user_id=")
                    .push_bind(user_id)
                    .push(lock);
                let row = query.build().fetch_optional(&mut *tx).await?;
                let Some(row) = row else {
                    continue;
                };
                let mut m = record!(row).metadata;
                if !m.active(now) {
                    continue;
                }
                let n = sqlx::query("UPDATE user_sessions SET status='revoked',revoked_at=$1,revoked_reason=$2 WHERE sid=$3 AND user_id=$4 AND status='active' AND revoked_at=0 AND expires_at>$1")
                    .bind(now).bind(reason).bind(&m.sid).bind(user_id).execute(&mut *tx).await?.rows_affected();
                if n == 1 {
                    m.status = "revoked".into();
                    m.revoked_at = now;
                    m.revoked_reason = reason.into();
                    changed.push(m);
                }
            }
            tx.commit().await?;
            Ok(changed)
        })
    }

    pub async fn list(
        &self,
        user_id: i64,
        current_sid: &str,
        now: i64,
    ) -> Result<Vec<SessionMetadata>, SessionError> {
        let uv = self.user_version(user_id).await?;
        backend!(&self.db, pool, {
            let mut query = sqlx::QueryBuilder::new("SELECT ");
            query
                .push(COLUMNS)
                .push(" FROM user_sessions WHERE user_id=")
                .push_bind(user_id)
                .push(" AND user_auth_version=")
                .push_bind(uv)
                .push(" AND status='active' AND expires_at>")
                .push_bind(now)
                .push(" ORDER BY CASE WHEN sid=")
                .push_bind(current_sid)
                .push(" THEN 0 ELSE 1 END,last_active_at DESC,created_at DESC LIMIT 100");
            let rows = query.build().fetch_all(pool).await?;
            let mut out = Vec::with_capacity(rows.len());
            for row in rows {
                out.push(record!(row).metadata);
            }
            Ok(out)
        })
    }

    pub async fn revoke_others<F: RevocationFence>(
        &self,
        fence: &F,
        user_id: i64,
        current_sid: &str,
        reason: &str,
        now: i64,
    ) -> Result<RevokeReport, BatchFailure> {
        let mut total = RevokeReport::default();
        let result: Result<(), SessionError> = async {
            validate_revoke(user_id, reason, now)?;
            if current_sid.is_empty() {
                return Err(SessionError::Invalid);
            }
            loop {
                let candidates: Vec<SessionMetadata> = backend!(&self.db, pool, {
                    let mut query = sqlx::QueryBuilder::new("SELECT ");
                    query
                        .push(COLUMNS)
                        .push(" FROM user_sessions WHERE user_id=")
                        .push_bind(user_id)
                        .push(" AND sid<>")
                        .push_bind(current_sid)
                        .push(" AND status='active' AND revoked_at=0 AND expires_at>")
                        .push_bind(now)
                        .push(" ORDER BY sid LIMIT 500");
                    let rows = query.build().fetch_all(pool).await?;
                    let mut out = Vec::with_capacity(rows.len());
                    for row in rows {
                        out.push(record!(row).metadata);
                    }
                    out
                });
                if candidates.is_empty() {
                    break;
                }
                for m in &candidates {
                    fence.revoking(m, now, reason).await?;
                }
                let changed = self
                    .revoke_fenced_batch(&candidates, user_id, reason, now)
                    .await?;
                let report = finalize(fence, changed, now).await;
                total.revoked_count += report.revoked_count;
                total.terminal_fence_failures += report.terminal_fence_failures;
            }
            Ok(())
        }
        .await;
        match result {
            Ok(()) => Ok(total),
            Err(error) => Err(BatchFailure {
                committed: total,
                error,
            }),
        }
    }
}

fn validate_revoke(user_id: i64, reason: &str, now: i64) -> Result<(), SessionError> {
    if user_id <= 0 || now <= 0 || reason.len() > 64 {
        Err(SessionError::Invalid)
    } else {
        Ok(())
    }
}
async fn finalize<F: RevocationFence>(
    fence: &F,
    changed: Vec<SessionMetadata>,
    now: i64,
) -> RevokeReport {
    let mut report = RevokeReport {
        revoked_count: changed.len() as u64,
        terminal_fence_failures: 0,
    };
    for m in changed {
        if fence.revoked(&m, now).await.is_err() {
            report.terminal_fence_failures += 1;
        }
    }
    report
}

// 静态证据（原仓只读）：authenticate.go:378–383 先 TrimSpace 再 value[:max]；
// :84–102 将该 string 交给 session_store.go:155 的 GORM Create，无字符修复。
// dbinfra/open_db.go:77–85 使用 pgx 简单协议 / glebarez SQLite。
// pgx v5.10.0 internal/sanitize/sanitize.go 的 QuoteString 逐字节保留非引号；
// UTF8 编码的 PG 会拒绝截断后的非法序列（其他服务端编码不能直接类推）。
// glebarez/go-sqlite v1.21.2 sqlite.go:1163–1169 用 CString 和 len(value)
// 调 sqlite3_bind_text，SQLite 可保留此类字节，不等价于 PG 拒绝。
// 当前 String 投影无法无损承载它：暂报明确未支持，不退回字符边界、不替换 U+FFFD。
// 此临时门禁不是 Go 兼容结论；远程 fixture 验证原始字节和两库差异，HTTP 保持关闭。
fn truncate_bytes(value: &str, max: usize) -> Result<&str, SessionError> {
    let value = value.trim();
    let end = value.len().min(max);
    value
        .get(..end)
        .ok_or(SessionError::MetadataEncodingUnsupported)
}
