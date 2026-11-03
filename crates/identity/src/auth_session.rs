//! 浏览器会话的刷新与注销编排；不伪造用户资料，不记录原始凭证。
//! 时间由调用方注入，撤销必须经过显式 fence，失败不得降级为无缓存。
use newapi_storage::Database;

use crate::crypto::{AuthKeys, RefreshCredential};
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

/// 无缓存部署的默认组合；接入共享缓存时必须传入真实 fence。
pub struct SessionAuth<F: RevocationFence> {
    repository: SessionRepository,
    keys: AuthKeys,
    fence: F,
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
        if let Some(expected) = expected_sid.map(str::trim).filter(|v| !v.is_empty()) {
            if expected != credential.sid() {
                return Err(SessionAuthError::SessionMismatch);
            }
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
            Ok(RefreshOutcome::Reused(_)) | Ok(RefreshOutcome::UserSecurityChanged(_)) => {
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
        if let Some(expected) = expected_sid.map(str::trim).filter(|v| !v.is_empty()) {
            if expected != credential.sid() {
                return Err(SessionAuthError::SessionMismatch);
            }
        }
        if self.repository.authoritative(credential.sid()).await?.is_none() {
            return Ok(());
        }
        let presented = hash(&self.keys, credential.secret());
        match self
            .repository
            .revoke_by_refresh(&self.fence, credential.sid(), &presented, "logout", now)
            .await
        {
            Ok(_) => Ok(()),
            Err(SessionError::Invalid | SessionError::NotFound | SessionError::Inactive) => Ok(()),
            Err(error) => Err(error.into()),
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
