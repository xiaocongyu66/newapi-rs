//! 共享 Redis 会话缓存；不承担用户认证栅栏，也不直接访问数据库。
//! 调用方必须在权威读取或修改前捕获期限；命中拒绝态绝不能回源放行。
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 连接建立（含握手）及每次完整命令的有限上限。
pub const IO_TIMEOUT: Duration = Duration::from_secs(2);

fn system_now_ms() -> Result<i64, CacheError> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| CacheError::Invalid)?;
    i64::try_from(elapsed.as_millis()).map_err(|_| CacheError::Invalid)
}

use hmac::{Hmac, Mac};
use redis::aio::MultiplexedConnection;
use sha2::Sha256;

use crate::sessions::{RevocationFence, SessionError, SessionMetadata};

/// 不携带 Redis 原始错误、连接 URL 或秘密，允许安全记录分类。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheError {
    Invalid,
    Unavailable,
    Protocol,
    Inactive,
}

fn redis_error(error: redis::RedisError) -> CacheError {
    if error.is_io_error() || error.is_timeout() {
        CacheError::Unavailable
    } else {
        CacheError::Protocol
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CacheRead {
    Miss,
    /// 格式错误允许权威回源，但不是认证成功。
    InvalidEntry,
    /// 包括撤销、过期及未知状态；禁止回源放行。
    Denied,
    Active(SessionMetadata),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FillOutcome {
    Stored,
    /// 必须重新确认数据库的身份、活跃、到期、会话版本及用户版本。
    Stale,
}

/// 字段私有，避免调用方随意延长已捕获窗口。
#[derive(Clone, Copy)]
pub struct ActiveDeadline {
    captured_ms: i64,
    deadline_ms: i64,
}

/// 不实现 Debug，避免泄漏 HMAC 密钥或连接配置。
pub struct RedisSessionCache {
    connection: MultiplexedConnection,
    key_mac: Hmac<Sha256>,
    window_ms: i64,
    clock: Arc<dyn Fn() -> Result<i64, CacheError> + Send + Sync>,
}

// 版本使用十进制字符串比较，避免 Lua 浮点数丢失 i64 高位。
// 先检查拒绝态和版本，再原子替换白名单字段，清除历史残留秘密字段。
const WRITE: &str = r#"
local status = redis.call('HGET', KEYS[1], 'Status')
local version = redis.call('HGET', KEYS[1], 'Version')
if ARGV[5] == 'active' and (status == 'revoking' or status == 'revoked') then
    return 0
end
if version then
    if not string.match(version, '^%d+$') then return 0 end
    version = string.gsub(version, '^0+', '')
    if #version > #ARGV[3] or (#version == #ARGV[3] and version > ARGV[3]) then
        return 0
    end
end
redis.call('DEL', KEYS[1])
redis.call('HSET', KEYS[1],
    'SID', ARGV[1], 'UserID', ARGV[2], 'Version', ARGV[3],
    'UserAuthVersion', ARGV[4], 'Status', ARGV[5],
    'LoginMethod', ARGV[6], 'IP', ARGV[7], 'UserAgent', ARGV[8],
    'CreatedAt', ARGV[9], 'LastActiveAt', ARGV[10], 'ExpiresAt', ARGV[11],
    'RevokedAt', ARGV[12], 'RevokedReason', ARGV[13], 'CacheSchema', '1')
if ARGV[5] == 'active' then
    redis.call('PEXPIREAT', KEYS[1], ARGV[14])
else
    redis.call('PEXPIRE', KEYS[1], ARGV[14])
end
return 1
"#;

impl RedisSessionCache {
    /// 连接及握手整体限时，失败不会隐式切换为无缓存模式。
    pub async fn connect(url: &str, secret: &[u8], cache_seconds: i64) -> Result<Self, CacheError> {
        let client = redis::Client::open(url).map_err(redis_error)?;
        let connection = tokio::time::timeout(IO_TIMEOUT, client.get_multiplexed_async_connection())
            .await
            .map_err(|_| CacheError::Unavailable)?
            .map_err(redis_error)?;
        Self::from_connection(connection, secret, cache_seconds)
    }

    pub fn from_connection(
        connection: MultiplexedConnection,
        secret: &[u8],
        cache_seconds: i64,
    ) -> Result<Self, CacheError> {
        if secret.is_empty() {
            return Err(CacheError::Invalid);
        }
        let seconds = if cache_seconds <= 0 { 60 } else { cache_seconds };
        let window_ms = seconds.checked_mul(1000).ok_or(CacheError::Invalid)?;
        let mut key = b"user-session-cache-v1:".to_vec();
        key.extend_from_slice(secret);
        let key_mac = Hmac::<Sha256>::new_from_slice(&key).map_err(|_| CacheError::Invalid)?;
        Ok(Self { connection, key_mac, window_ms, clock: Arc::new(system_now_ms) })
    }

    /// 注入发布时毫秒时钟；与 fence 参数的业务审计秒时间相互独立。
    /// 生产默认使用系统时间；测试可捕获原子时钟，不允许返回过期的业务时间。
    pub fn with_clock<F>(mut self, clock: F) -> Self
    where
        F: Fn() -> Result<i64, CacheError> + Send + Sync + 'static,
    {
        self.clock = Arc::new(clock);
        self
    }

    pub fn cache_key(&self, sid: &str) -> String {
        let mut mac = self.key_mac.clone();
        mac.update(sid.as_bytes());
        let bytes = mac.finalize().into_bytes();
        let mut key = String::from("auth:session:");
        const HEX: &[u8] = b"0123456789abcdef";
        for byte in bytes {
            key.push(HEX[(byte >> 4) as usize] as char);
            key.push(HEX[(byte & 15) as usize] as char);
        }
        key
    }

    /// 必须紧邻权威数据库操作之前调用；时间单位为 Unix 毫秒。
    pub fn capture_deadline(&self, now_ms: i64) -> Result<ActiveDeadline, CacheError> {
        if now_ms <= 0 {
            return Err(CacheError::Invalid);
        }
        Ok(ActiveDeadline {
            captured_ms: now_ms,
            deadline_ms: now_ms.checked_add(self.window_ms).ok_or(CacheError::Invalid)?,
        })
    }

    /// 读故障可由调用方回源；Denied 不属于故障，不能用通用回源处理吞掉。
    pub async fn read(&self, sid: &str, now_ms: i64) -> Result<CacheRead, CacheError> {
        if sid.is_empty() || now_ms <= 0 {
            return Err(CacheError::Invalid);
        }
        let mut connection = self.connection.clone();
        // 一次读取同一快照，禁止先整体解码 UTF-8 或另发命令查询状态。
        let fields: HashMap<Vec<u8>, Vec<u8>> = tokio::time::timeout(IO_TIMEOUT, async {
            redis::cmd("HGETALL")
                .arg(self.cache_key(sid))
                .query_async(&mut connection)
                .await
        })
        .await
        .map_err(|_| CacheError::Unavailable)?
        .map_err(redis_error)?;
        if fields.is_empty() {
            return Ok(CacheRead::Miss);
        }
        // Go 元数据可能含非法 UTF-8；墓碑不能被任意其他字段的解码失败绕过。
        if fields.get(b"Status".as_slice()).is_some_and(|status| {
            status.as_slice() == b"revoking" || status.as_slice() == b"revoked"
        }) {
            return Ok(CacheRead::Denied);
        }
        let fields: Result<HashMap<String, String>, _> = fields.into_iter()
            .map(|(key, value)| Ok((String::from_utf8(key)?, String::from_utf8(value)?)))
            .collect::<Result<_, std::string::FromUtf8Error>>();
        let Ok(fields) = fields else {
            return Ok(CacheRead::InvalidEntry);
        };
        let Some(m) = decode(&fields, sid) else {
            return Ok(CacheRead::InvalidEntry);
        };
        if m.status != "active" || m.revoked_at != 0 || m.expires_at <= now_ms / 1000 {
            return Ok(CacheRead::Denied);
        }
        Ok(CacheRead::Active(m))
    }

    /// now_ms 是写前时间；completed_now 必须在 await 返回后提供当前 Unix 毫秒。
    /// 闭包允许固定测试时钟，不允许复用写前时间冒充写后采样。
    pub async fn fill_active<F>(
        &self,
        session: &SessionMetadata,
        deadline: ActiveDeadline,
        now_ms: i64,
        completed_now: F,
    ) -> Result<FillOutcome, CacheError>
    where
        F: FnOnce() -> i64 + Send,
    {
        validate(session)?;
        if now_ms < deadline.captured_ms
            || deadline.deadline_ms - deadline.captured_ms > self.window_ms
        {
            return Err(CacheError::Invalid);
        }
        if session.status != "active" || session.revoked_at != 0 {
            return Err(CacheError::Inactive);
        }
        let expires = session.expires_at.checked_mul(1000).ok_or(CacheError::Invalid)?;
        if expires <= now_ms {
            return Err(CacheError::Inactive);
        }
        let end = expires.min(deadline.deadline_ms);
        if end <= now_ms {
            return Ok(FillOutcome::Stale);
        }
        self.write(session, end).await?;
        let completed = completed_now();
        if completed < now_ms {
            return Err(CacheError::Invalid);
        }
        if completed >= expires {
            return Err(CacheError::Inactive);
        }
        if completed >= deadline.deadline_ms {
            return Ok(FillOutcome::Stale);
        }
        Ok(FillOutcome::Stored)
    }

    async fn write(&self, m: &SessionMetadata, expiration: i64) -> Result<(), CacheError> {
        let mut connection = self.connection.clone();
        // 限制整个脚本调用，包括首次缺少脚本时的加载及重试；外部连接同样受限。
        let result: i64 = tokio::time::timeout(IO_TIMEOUT, async {
            redis::Script::new(WRITE)
                .key(self.cache_key(&m.sid))
                .arg(&m.sid).arg(m.user_id).arg(m.version).arg(m.user_auth_version)
                .arg(&m.status).arg(&m.login_method).arg(&m.ip).arg(&m.user_agent)
                .arg(m.created_at).arg(m.last_active_at).arg(m.expires_at)
                .arg(m.revoked_at).arg(&m.revoked_reason).arg(expiration)
                .invoke_async(&mut connection)
                .await
        })
        .await
        .map_err(|_| CacheError::Unavailable)?
        .map_err(redis_error)?;
        match result {
            1 => Ok(()),
            0 => Err(CacheError::Inactive),
            _ => Err(CacheError::Protocol),
        }
    }

    async fn deny(&self, m: &SessionMetadata, now: i64) -> Result<(), CacheError> {
        validate(m)?;
        if now <= 0 {
            return Err(CacheError::Invalid);
        }
        // now 只用于业务审计及输入校验，不能作为已延迟发布的 TTL 起点。
        let published_ms = (self.clock)()?;
        if published_ms <= 0 {
            return Err(CacheError::Invalid);
        }
        let remaining = m.expires_at.checked_mul(1000)
            .and_then(|expiry| expiry.checked_sub(published_ms)).ok_or(CacheError::Invalid)?;
        let ttl = remaining.min(self.window_ms);
        self.write(m, if ttl <= 0 { 1000 } else { ttl }).await
    }
}

impl RevocationFence for RedisSessionCache {
    async fn revoking(&self, session: &SessionMetadata, now: i64, reason: &str) -> Result<(), SessionError> {
        let mut m = session.clone();
        m.status = "revoking".into();
        m.revoked_at = now;
        m.revoked_reason = reason.into();
        self.deny(&m, now).await.map_err(|_| SessionError::Fence)
    }

    async fn revoked(&self, session: &SessionMetadata, now: i64) -> Result<(), SessionError> {
        let mut m = session.clone();
        m.status = "revoked".into();
        self.deny(&m, now).await.map_err(|_| SessionError::Fence)
    }
}

fn validate(m: &SessionMetadata) -> Result<(), CacheError> {
    if m.sid.is_empty() || m.user_id <= 0 || m.version <= 0 || m.user_auth_version <= 0 {
        Err(CacheError::Invalid)
    } else {
        Ok(())
    }
}

fn decode(f: &HashMap<String, String>, sid: &str) -> Option<SessionMetadata> {
    if f.get("CacheSchema")? != "1" || f.get("SID")? != sid || f.len() != 14 {
        return None;
    }
    let m = SessionMetadata {
        sid: f.get("SID")?.clone(),
        user_id: f.get("UserID")?.parse().ok()?,
        version: f.get("Version")?.parse().ok()?,
        user_auth_version: f.get("UserAuthVersion")?.parse().ok()?,
        status: f.get("Status")?.clone(),
        login_method: f.get("LoginMethod")?.clone(),
        ip: f.get("IP")?.clone(),
        user_agent: f.get("UserAgent")?.clone(),
        created_at: f.get("CreatedAt")?.parse().ok()?,
        last_active_at: f.get("LastActiveAt")?.parse().ok()?,
        expires_at: f.get("ExpiresAt")?.parse().ok()?,
        revoked_at: f.get("RevokedAt")?.parse().ok()?,
        revoked_reason: f.get("RevokedReason")?.clone(),
    };
    validate(&m).ok()?;
    Some(m)
}
