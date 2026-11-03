//! 浏览器会话的刷新与注销编排；不伪造用户资料，不记录原始凭证。
//! 时间由调用方注入，撤销必须经过显式 fence，失败不得降级为无缓存。
use std::sync::atomic::{AtomicU64, Ordering};

use newapi_storage::Database;

use crate::crypto::{AuthKeys, RefreshCredential};
use crate::session_cache::RedisSessionCache;
use crate::sessions::{
    NoCache, RefreshHash, RefreshOutcome, RevocationFence, SessionError, SessionRecord,
    SessionRepository,
};
use crate::{AuthIdentity, SecretString};

/// 只包含公开会话视图所需字段，不含 refresh 材料。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionView {
    pub sid: String,
    pub current: bool,
    pub login_method: String,
    pub ip: String,
    pub user_agent: String,
    pub created_at: i64,
    pub last_active_at: i64,
    pub expires_at: i64,
}

/// 访问令牌原文不实现 Debug；HTTP 层只投影 token 与过期时间。
pub struct RefreshResult {
    pub access_token: SecretString,
    pub access_expires_at: i64,
    pub access_identity: AuthIdentity,
    pub session: SessionView,
    pub refresh_token: SecretString,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionAuthError {
    RefreshInvalid,
    SessionMismatch,
    SessionRevoked,
    /// 缺失会话标识；HTTP 层映射为 400 AUTH_SESSION_ID_REQUIRED。
    SessionIdRequired,
    BatchFailed {
        committed_count: u64,
        error: SessionError,
    },
    /// 同代首发已轮换；客户端需重新读取 Cookie 后再试。
    Race,
    Storage(SessionError),
}

impl From<SessionError> for SessionAuthError {
    fn from(error: SessionError) -> Self {
        match error {
            SessionError::Invalid => Self::RefreshInvalid,
            SessionError::NotFound | SessionError::Inactive => Self::SessionRevoked,
            other => Self::Storage(other),
        }
    }
}

/// 运行期可选的撤销栅栏；Redis 不可用时不会静默退化为无缓存。
pub enum AuthFence {
    Disabled(NoCache),
    /// 装箱避免与空变体产生巨大的枚举尺寸差异。
    Redis(Box<RedisSessionCache>),
}

impl RevocationFence for AuthFence {
    async fn revoking(
        &self,
        session: &crate::sessions::SessionMetadata,
        now: i64,
        reason: &str,
    ) -> Result<(), SessionError> {
        match self {
            Self::Disabled(fence) => fence.revoking(session, now, reason).await,
            Self::Redis(fence) => fence.revoking(session, now, reason).await,
        }
    }

    async fn revoked(
        &self,
        session: &crate::sessions::SessionMetadata,
        now: i64,
    ) -> Result<(), SessionError> {
        match self {
            Self::Disabled(fence) => fence.revoked(session, now).await,
            Self::Redis(fence) => fence.revoked(session, now).await,
        }
    }
}

/// 无缓存部署的默认组合；接入共享缓存时必须传入真实 fence。
pub struct SessionAuth<F: RevocationFence> {
    repository: SessionRepository,
    keys: AuthKeys,
    fence: F,
    terminal_fence_failures: AtomicU64,
}

impl SessionAuth<AuthFence> {
    /// 生产入口：fence 由启动配置决定，Redis 连接失败时不得回退为无缓存。
    pub fn with_fence(db: Database, keys: AuthKeys, fence: AuthFence) -> Self {
        Self::new(db, keys, fence)
    }
}

impl SessionAuth<NoCache> {
    /// 仅在明确禁用 Redis/会话缓存时使用；不隐藏缺少跨实例撤销这一事实。
    pub fn without_cache(db: Database, keys: AuthKeys) -> Self {
        Self::new(db, keys, NoCache::explicitly_disabled())
    }
}

impl<F: RevocationFence> SessionAuth<F> {
    pub fn new(db: Database, keys: AuthKeys, fence: F) -> Self {
        Self {
            repository: SessionRepository::new(db),
            keys,
            fence,
            terminal_fence_failures: AtomicU64::new(0),
        }
    }

    pub fn terminal_fence_failures(&self) -> u64 {
        self.terminal_fence_failures.load(Ordering::Relaxed)
    }

    fn observe_revoke(&self, report: &crate::sessions::RevokeReport) {
        self.terminal_fence_failures
            .fetch_add(report.terminal_fence_failures, Ordering::Relaxed);
        if report.terminal_fence_failures > 0 {
            tracing::error!(
                target: "newapi_identity::auth_session",
                event = "terminal_fence_failure",
                failures = report.terminal_fence_failures,
                "已提交会话撤销的终态缓存写入失败"
            );
        }
    }

    /// 与原 Go 一致：确认会话与当前用户版本后，确定性推导下一代 refresh。
    /// 宽限期内重放只有在库内 next hash 与推导值一致时才允许幂等收敛。
    pub async fn refresh(
        &self,
        raw_refresh_token: &str,
        expected_sid: Option<&str>,
        now: i64,
    ) -> Result<RefreshResult, SessionAuthError> {
        let credential = RefreshCredential::parse(raw_refresh_token)
            .map_err(|_| SessionAuthError::RefreshInvalid)?;
        if let Some(expected) = expected_sid.map(str::trim).filter(|v| !v.is_empty())
            && expected != credential.sid()
        {
            return Err(SessionAuthError::SessionMismatch);
        }
        let presented = hash(&self.keys, credential.secret());
        let next = self.keys.next_refresh(&credential);
        let next_hash = hash(&self.keys, next.secret());
        // 先从权威行取用户；rotate 仍会再次重读并核对用户版本。
        let user_id = match self.repository.authoritative(credential.sid()).await? {
            Some(record) => record.metadata.user_id,
            None => return Err(SessionAuthError::SessionRevoked),
        };
        match self
            .repository
            .rotate(
                &self.fence,
                user_id,
                credential.sid(),
                &presented,
                &next_hash,
                now,
            )
            .await
        {
            Ok(RefreshOutcome::Rotated(record)) => self.issue(record, &next, now),
            Ok(RefreshOutcome::PreviousWithinGrace(record)) => {
                if !record.current_hash_matches(&next_hash) {
                    return Err(SessionAuthError::Race);
                }
                self.issue(record, &next, now)
            }
            Ok(RefreshOutcome::Reused(report))
            | Ok(RefreshOutcome::UserSecurityChanged(report)) => {
                self.observe_revoke(&report);
                Err(SessionAuthError::SessionRevoked)
            }
            Err(error) => Err(error.into()),
        }
    }

    /// 注销是幂等操作：不存在、已失效或 hash 不匹配的令牌与原 Go 一样返回成功。
    pub async fn logout(
        &self,
        raw_refresh_token: Option<&str>,
        expected_sid: Option<&str>,
        now: i64,
    ) -> Result<(), SessionAuthError> {
        let Some(raw) = raw_refresh_token else {
            return Ok(());
        };
        let Ok(credential) = RefreshCredential::parse(raw) else {
            return Ok(());
        };
        if let Some(expected) = expected_sid.map(str::trim).filter(|v| !v.is_empty())
            && expected != credential.sid()
        {
            return Err(SessionAuthError::SessionMismatch);
        }
        if self
            .repository
            .authoritative(credential.sid())
            .await?
            .is_none()
        {
            return Ok(());
        }
        let presented = hash(&self.keys, credential.secret());
        match self
            .repository
            .revoke_by_refresh(&self.fence, credential.sid(), &presented, "logout", now)
            .await
        {
            Ok(report) => {
                self.observe_revoke(&report);
                Ok(())
            }
            Err(SessionError::Invalid | SessionError::NotFound | SessionError::Inactive) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// 解析访问令牌并核对当前数据库会话；失败一律视为不可认证。
    pub async fn identify(
        &self,
        raw_access: &str,
        now: i64,
    ) -> Result<AuthIdentity, SessionAuthError> {
        let identity = self.parse_access(raw_access, now)?;
        self.validate(&identity, now).await?;
        Ok(identity)
    }

    pub fn parse_access(
        &self,
        raw_access: &str,
        now: i64,
    ) -> Result<AuthIdentity, SessionAuthError> {
        self.keys
            .parse_access(raw_access, now)
            .map_err(|_| SessionAuthError::SessionRevoked)
    }

    /// 按已验签访问令牌绑定的用户与 SID 注销，不依赖会话仍活跃。
    pub async fn revoke_session(
        &self,
        identity: &AuthIdentity,
        now: i64,
    ) -> Result<(), SessionAuthError> {
        self.repository
            .revoke(&self.fence, identity.user_id, &identity.sid, "logout", now)
            .await
            .map(|report| self.observe_revoke(&report))
            .map_err(SessionAuthError::from)
    }

    /// 撤销指定会话；仅当确实撤销了活跃会话时返回 true。
    /// 不存在的会话不是错误，由调用方映射为 404。
    pub async fn revoke_sid(
        &self,
        identity: &AuthIdentity,
        sid: &str,
        now: i64,
    ) -> Result<bool, SessionAuthError> {
        let sid = sid.trim();
        if sid.is_empty() {
            return Err(SessionAuthError::SessionIdRequired);
        }
        let report = self
            .repository
            .revoke(&self.fence, identity.user_id, sid, "user_revoked", now)
            .await
            .map_err(SessionAuthError::from)?;
        self.observe_revoke(&report);
        Ok(report.revoked_count > 0)
    }

    /// 撤销当前会话以外的活跃会话；批次可能部分成功，累计进度如实返回。
    pub async fn revoke_others(
        &self,
        identity: &AuthIdentity,
        now: i64,
    ) -> Result<u64, SessionAuthError> {
        match self
            .repository
            .revoke_others(&self.fence, identity.user_id, &identity.sid, "user_revoked_others", now)
            .await
        {
            Ok(report) => {
                self.observe_revoke(&report);
                Ok(report.revoked_count)
            }
            Err(failure) => {
                self.observe_revoke(&failure.committed);
                Err(SessionAuthError::BatchFailed {
                    committed_count: failure.committed.revoked_count,
                    error: failure.error,
                })
            }
        }
    }

    /// 会话列表；current 由传入的当前 SID 决定，不硬编码为 true。
    pub async fn sessions(
        &self,
        identity: &AuthIdentity,
        now: i64,
    ) -> Result<Vec<SessionView>, SessionAuthError> {
        let records = self
            .repository
            .list(identity.user_id, &identity.sid, now)
            .await
            .map_err(SessionAuthError::from)?;
        Ok(records
            .into_iter()
            .map(|metadata| SessionView {
                sid: metadata.sid.clone(),
                current: metadata.sid == identity.sid,
                login_method: metadata.login_method,
                ip: metadata.ip,
                user_agent: metadata.user_agent,
                created_at: metadata.created_at,
                last_active_at: metadata.last_active_at,
                expires_at: metadata.expires_at,
            })
            .collect())
    }

    /// 访问令牌验签之后仍必须调用；只信任 SQL 当前会话与用户版本。
    pub async fn validate(
        &self,
        identity: &AuthIdentity,
        now: i64,
    ) -> Result<SessionView, SessionAuthError> {
        let record = self
            .repository
            .validate_access(
                identity.user_id,
                &identity.sid,
                identity.session_version,
                identity.user_auth_version,
                now,
            )
            .await
            .map_err(SessionAuthError::from)?;
        Ok(session_view(&record))
    }

    // 宽限期内放行不会更新 last_active_at，因此签发时间必须显式使用调用方当前时间。
    fn issue(
        &self,
        record: SessionRecord,
        next: &RefreshCredential,
        now: i64,
    ) -> Result<RefreshResult, SessionAuthError> {
        let identity = AuthIdentity {
            user_id: record.metadata.user_id,
            sid: record.metadata.sid.clone(),
            user_auth_version: record.metadata.user_auth_version,
            session_version: record.metadata.version,
        };
        let token = self
            .keys
            .issue_access(&identity, now)
            .map_err(|_| SessionAuthError::Storage(SessionError::Storage))?;
        Ok(RefreshResult {
            access_token: token.token,
            access_expires_at: token.expires_at,
            access_identity: identity,
            session: session_view(&record),
            refresh_token: next.raw(),
        })
    }
}

fn hash(keys: &AuthKeys, secret: &str) -> RefreshHash {
    RefreshHash::from_lower_hex(keys.refresh_hash(secret).expose_secret().to_owned())
        .expect("HMAC-SHA256 hex is always a valid digest")
}

fn session_view(record: &SessionRecord) -> SessionView {
    SessionView {
        sid: record.metadata.sid.clone(),
        current: true,
        login_method: record.metadata.login_method.clone(),
        ip: record.metadata.ip.clone(),
        user_agent: record.metadata.user_agent.clone(),
        created_at: record.metadata.created_at,
        last_active_at: record.metadata.last_active_at,
        expires_at: record.metadata.expires_at,
    }
}
