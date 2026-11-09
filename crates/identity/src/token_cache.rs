//! 令牌 Redis 缓存：键派生、失效栅栏与冷初始化，对齐 Go
//! `apps/api/internal/identity/track_token_cache.go` 与
//! `quotacache.TokenKey` 的 Redis 表达。
//!
//! 缓存键是令牌原文的 HMAC（明文键绝不进 Redis），失效先立 10 秒栅栏再删
//! 哈希：栅栏自然到期，使持有预变更快照的并发读者无法在变更落库后把旧值
//! 重新写回缓存。读路径只在哈希不存在时初始化；已存在的热哈希仅续 TTL，
//! 因为原子预扣可能已把更靠前的余额写进哈希，快照绝不能覆盖任何字段。

use std::collections::HashMap;
use std::sync::Arc;

use hmac::{Hmac, Mac};
use redis::aio::MultiplexedConnection;
use sha2::Sha256;

use crate::tokens::TokenRecord;

/// 连接建立（含握手）及每次完整命令的有限上限。
pub const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Go `TokenCacheFenceSeconds`：栅栏必须长于一次变更的数据库写入加上在途
/// 读者的「读库到回填」间隙；栅栏不随提交删除，自然到期。
pub const TOKEN_CACHE_FENCE_SECONDS: i64 = 10;

const KEY_PREFIX: &str = "token:";
const FENCE_PREFIX: &str = "token:fence:";

// 与 Go `CacheInitToken` 的脚本逐字一致：KEYS[1]=哈希，KEYS[2]=栅栏，
// ARGV[1..16]=令牌字段，ARGV[17]=TTL 秒。返回 0=被栅栏拦截，1=完成初始化，
// 2=哈希已存在仅续期。
const INIT_SCRIPT: &str = r#"
if redis.call('EXISTS', KEYS[2]) == 1 then
  return 0
end
if redis.call('EXISTS', KEYS[1]) == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[17])
  return 2
end
redis.call('HSET', KEYS[1],
  'Id', ARGV[1], 'UserId', ARGV[2], 'Status', ARGV[3], 'Name', ARGV[4],
  'CreatedTime', ARGV[5], 'AccessedTime', ARGV[6], 'ExpiredTime', ARGV[7],
  'UnlimitedQuota', ARGV[8], 'ModelLimitsEnabled', ARGV[9], 'ModelLimits', ARGV[10],
  'AllowIps', ARGV[11], 'Group', ARGV[12], 'CrossGroupRetry', ARGV[13],
  'AutoGroups', ARGV[14], 'RemainQuota', ARGV[15], 'UsedQuota', ARGV[16])
redis.call('EXPIRE', KEYS[1], ARGV[17])
return 1
"#;

/// 不携带 Redis 原始错误、连接 URL 或令牌明文，允许安全记录分类。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenCacheError {
    Invalid,
    Unavailable,
    Protocol,
}

impl std::fmt::Display for TokenCacheError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::Invalid => "token cache invalid argument",
            Self::Unavailable => "token cache unavailable",
            Self::Protocol => "token cache protocol error",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for TokenCacheError {}

/// Go `CacheInitToken` 的返回值。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenCacheInit {
    /// 变更栅栏存在，跳过发布（Go 返回 0）。
    Blocked,
    /// 冷哈希初始化完成（Go 返回 1）。
    Initialized,
    /// 哈希已存在，仅续 TTL（Go 返回 2）。
    Refreshed,
}

/// HMAC key 为 Go 的 `CryptoSecret`；不实现 Debug，避免泄漏密钥或连接配置。
pub struct RedisTokenCache {
    connection: MultiplexedConnection,
    key_mac: Hmac<Sha256>,
    /// Go `tokenCacheTTLSeconds`，构造时已保证正数。
    ttl_seconds: i64,
}

impl RedisTokenCache {
    /// 连接及握手整体限时；未配置 Redis 时调用方根本不会构造本类型。
    pub async fn connect(
        url: &str,
        secret: &[u8],
        cache_seconds: i64,
    ) -> Result<Arc<Self>, TokenCacheError> {
        let client = redis::Client::open(url).map_err(|_| TokenCacheError::Invalid)?;
        let connection =
            tokio::time::timeout(IO_TIMEOUT, client.get_multiplexed_async_connection())
                .await
                .map_err(|_| TokenCacheError::Unavailable)?
                .map_err(|_| TokenCacheError::Unavailable)?;
        Ok(Arc::new(Self::from_connection(
            connection,
            secret,
            cache_seconds,
        )?))
    }

    /// 由已有连接构造；测试与生产入口共用键派生与 TTL 规则。
    pub fn from_connection(
        connection: MultiplexedConnection,
        secret: &[u8],
        cache_seconds: i64,
    ) -> Result<Self, TokenCacheError> {
        // Go 在两者都未设置时使用每进程随机 UUID；服务入口同样保证此处绝不
        // 传入空密钥（未配置时回退进程级随机 SESSION_SECRET）。
        if secret.is_empty() {
            return Err(TokenCacheError::Invalid);
        }
        let ttl_seconds = if cache_seconds <= 0 {
            60
        } else {
            cache_seconds
        };
        let key_mac =
            Hmac::<Sha256>::new_from_slice(secret).map_err(|_| TokenCacheError::Invalid)?;
        Ok(Self {
            connection,
            key_mac,
            ttl_seconds,
        })
    }

    /// Go `quotacache.TokenKey`：`token:` + HMAC-SHA256(CryptoSecret, 明文) 的十六进制。
    pub fn cache_key(&self, key: &str) -> String {
        let mut digest = String::from(KEY_PREFIX);
        self.push_hex_hmac(key, &mut digest);
        digest
    }

    /// Go `getTokenCacheFenceKey`：与数据键同摘要、前缀 `token:fence:`。
    pub fn fence_key(&self, key: &str) -> String {
        let mut digest = String::from(FENCE_PREFIX);
        self.push_hex_hmac(key, &mut digest);
        digest
    }

    fn push_hex_hmac(&self, key: &str, out: &mut String) {
        let mut mac = self.key_mac.clone();
        mac.update(key.as_bytes());
        let bytes = mac.finalize().into_bytes();
        const HEX: &[u8] = b"0123456789abcdef";
        for byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 15) as usize] as char);
        }
    }

    fn ttl_seconds(&self) -> i64 {
        self.ttl_seconds
    }

    /// Go `InvalidateTokenCacheForMutation`：变更写入数据库之前调用——
    /// 先立栅栏再删哈希，使读者既不能继续命中旧值，也不能回填旧快照。
    pub async fn invalidate_for_mutation(&self, key: &str) -> Result<(), TokenCacheError> {
        if key.is_empty() {
            return Ok(());
        }
        let mut connection = self.connection.clone();
        let fence = self.fence_key(key);
        let _: () = tokio::time::timeout(
            IO_TIMEOUT,
            redis::cmd("SET")
                .arg(&fence)
                .arg(1)
                .arg("EX")
                .arg(TOKEN_CACHE_FENCE_SECONDS)
                .query_async(&mut connection),
        )
        .await
        .map_err(|_| TokenCacheError::Unavailable)?
        .map_err(|_| TokenCacheError::Unavailable)?;
        let _: () = tokio::time::timeout(
            IO_TIMEOUT,
            redis::cmd("DEL")
                .arg(self.cache_key(key))
                .query_async(&mut connection),
        )
        .await
        .map_err(|_| TokenCacheError::Unavailable)?
        .map_err(|_| TokenCacheError::Unavailable)?;
        Ok(())
    }

    /// Go `invalidateTokensCache`：逐键失效，空键跳过，只回报第一个错误。
    pub async fn invalidate_many(&self, keys: &[String]) -> Result<(), TokenCacheError> {
        let mut first_error = None;
        for key in keys {
            if key.is_empty() {
                continue;
            }
            if let Err(error) = self.invalidate_for_mutation(key).await
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Go `CacheInitToken`：栅栏存在时放弃；哈希已存在仅续 TTL，绝不覆盖。
    pub async fn init(&self, token: &TokenRecord) -> Result<TokenCacheInit, TokenCacheError> {
        let allow_ips = token.allow_ips.as_deref().unwrap_or("");
        let mut connection = self.connection.clone();
        let result: i64 = tokio::time::timeout(
            IO_TIMEOUT,
            redis::Script::new(INIT_SCRIPT)
                .key(self.cache_key(&token.key))
                .key(self.fence_key(&token.key))
                .arg(token.id)
                .arg(token.user_id)
                .arg(token.status)
                .arg(&token.name)
                .arg(token.created_time)
                .arg(token.accessed_time)
                .arg(token.expired_time)
                .arg(bool_arg(token.unlimited_quota))
                .arg(bool_arg(token.model_limits_enabled))
                .arg(&token.model_limits)
                .arg(allow_ips)
                .arg(&token.group)
                .arg(bool_arg(token.cross_group_retry))
                .arg(&token.auto_groups)
                .arg(token.remain_quota)
                .arg(token.used_quota)
                .arg(self.ttl_seconds())
                .invoke_async(&mut connection),
        )
        .await
        .map_err(|_| TokenCacheError::Unavailable)?
        .map_err(cache_error)?;
        match result {
            0 => Ok(TokenCacheInit::Blocked),
            1 => Ok(TokenCacheInit::Initialized),
            2 => Ok(TokenCacheInit::Refreshed),
            _ => Err(TokenCacheError::Protocol),
        }
    }

    /// Go `CacheGetTokenByKey`：读取整张哈希；不完整哈希（如仅配额字段）视为
    /// 未命中。调用方决定连接错误是回源还是直接失败——Go 的读路径一律回源。
    pub async fn get_by_key(&self, key: &str) -> Result<Option<TokenRecord>, TokenCacheError> {
        if key.is_empty() {
            return Err(TokenCacheError::Invalid);
        }
        let mut connection = self.connection.clone();
        let fields: HashMap<String, String> = tokio::time::timeout(
            IO_TIMEOUT,
            redis::cmd("HGETALL")
                .arg(self.cache_key(key))
                .query_async(&mut connection),
        )
        .await
        .map_err(|_| TokenCacheError::Unavailable)?
        .map_err(cache_error)?;
        if fields.is_empty() {
            return Ok(None);
        }
        let Some(token) = decode_cached_token(&fields, key) else {
            // Go 的 `RedisHGetObj` 解析失败与 `Id <= 0` 都是错误，读路径一律回源。
            return Ok(None);
        };
        Ok(Some(token))
    }
}

fn bool_arg(value: bool) -> &'static str {
    // Go `strconv.FormatBool` 的恰好两种输出。
    if value { "true" } else { "false" }
}

fn cache_error(error: redis::RedisError) -> TokenCacheError {
    if error.is_io_error() || error.is_timeout() {
        TokenCacheError::Unavailable
    } else {
        TokenCacheError::Protocol
    }
}

/// Go `RedisHGetObj` 对 `Token` 结构体的逐字段回填：哈希里缺的字段保持零值，
/// 任何存在字段解析失败都视为整哈希不可用（Go 的 decode 错误）；`Id` 缺失
/// 或非正（不完整哈希）同样返回 `None`。`AllowIps` 空串对应 Go 的 nil 指针。
fn decode_cached_token(fields: &HashMap<String, String>, key: &str) -> Option<TokenRecord> {
    let id = field_i64(fields, "Id")?;
    if id <= 0 {
        // Go `CacheGetTokenByKey` 的「token cache is incomplete」。
        return None;
    }
    Some(TokenRecord {
        id,
        user_id: field_i64(fields, "UserId")?,
        key: key.to_owned(),
        status: field_i64(fields, "Status")?,
        name: field_string(fields, "Name"),
        created_time: field_i64(fields, "CreatedTime")?,
        accessed_time: field_i64(fields, "AccessedTime")?,
        expired_time: field_i64(fields, "ExpiredTime")?,
        remain_quota: field_i64(fields, "RemainQuota")?,
        used_quota: field_i64(fields, "UsedQuota")?,
        unlimited_quota: field_bool(fields, "UnlimitedQuota")?,
        model_limits_enabled: field_bool(fields, "ModelLimitsEnabled")?,
        model_limits: field_string(fields, "ModelLimits"),
        allow_ips: match fields.get("AllowIps") {
            Some(value) if !value.is_empty() => Some(value.clone()),
            _ => None,
        },
        group: field_string(fields, "Group"),
        cross_group_retry: field_bool(fields, "CrossGroupRetry")?,
        auto_groups: field_string(fields, "AutoGroups"),
    })
}

/// 缺失字段是 Go 的零值（整数 0）；存在但不可解析触发整哈希拒绝（Go 的错误）。
fn field_i64(fields: &HashMap<String, String>, name: &str) -> Option<i64> {
    match fields.get(name) {
        None => Some(0),
        Some(value) => value.parse::<i64>().ok(),
    }
}

fn field_string(fields: &HashMap<String, String>, name: &str) -> String {
    fields.get(name).cloned().unwrap_or_default()
}

/// 缺失字段是 false（Go 零值）；`strconv.ParseBool` 不接受的值触发整哈希拒绝。
fn field_bool(fields: &HashMap<String, String>, name: &str) -> Option<bool> {
    match fields.get(name) {
        None => Some(false),
        Some(value) => match value.as_str() {
            "1" | "t" | "T" | "TRUE" | "True" | "true" => Some(true),
            "0" | "f" | "F" | "FALSE" | "False" | "false" => Some(false),
            _ => None,
        },
    }
}
