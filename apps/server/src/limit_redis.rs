//! Redis fixed-window rate limiter ported from Go's
//! `apps/api/internal/transport/middleware/limit_rate.go`.
//!
//! The Lua script performs increment, expiry and the admission decision in one
//! atomic call. It deliberately keeps Go's fixed-window behavior: traffic at a
//! window boundary can burst up to twice the configured limit. Redis also
//! reports the real remaining TTL, so a rejection carries a more precise
//! `Retry-After` than the in-memory limiter.

use redis::{ErrorKind, Script, aio::MultiplexedConnection};

const NAMESPACE: &str = "rateLimit:v2";

// Must stay semantically identical to Go's `redisFixedWindowScript`.
const SCRIPT: &str = r#"
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[2])
end
local ttl = redis.call('TTL', KEYS[1])
if ttl < 0 then
  redis.call('EXPIRE', KEYS[1], ARGV[2])
  ttl = redis.call('TTL', KEYS[1])
end
if count > tonumber(ARGV[1]) then
  return {0, count, ttl}
end
return {1, count, ttl}
"#;

/// Admission decision for one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RateLimitVerdict {
    Allowed,
    Rejected { retry_after: i64 },
}

/// Fixed error classifications only. Neither `Display` nor `Debug` carries the
/// Redis URL, the client IP, or the underlying Redis error text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RedisLimitError {
    Connection,
    Script,
    Value,
}

impl std::fmt::Display for RedisLimitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Connection => "redis rate limit connection error",
            Self::Script => "redis rate limit script error",
            Self::Value => "redis rate limit value error",
        })
    }
}

impl std::error::Error for RedisLimitError {}

/// Fixed-window limiter backed by a multiplexed Redis connection.
pub struct RedisRateLimiter {
    connection: MultiplexedConnection,
    namespace: &'static str,
}

impl RedisRateLimiter {
    pub async fn connect(url: &str) -> Result<Self, RedisLimitError> {
        let client = redis::Client::open(url).map_err(|_| RedisLimitError::Connection)?;
        let connection = client
            .get_multiplexed_async_connection()
            .await
            .map_err(|_| RedisLimitError::Connection)?;
        Ok(Self {
            connection,
            namespace: NAMESPACE,
        })
    }

    /// Builds the same IP key as Go's `redisIPRateLimitKey`.
    pub fn key(&self, mark: &str, client_ip: &str) -> String {
        format!("{}:ip:{mark}:{client_ip}", self.namespace)
    }

    /// Builds the same user key as Go's `redisUserRateLimitKey`.
    pub fn user_key(&self, mark: &str, user_id: i64) -> String {
        format!("{}:user:{mark}:{user_id}", self.namespace)
    }

    /// Records one request and decides whether it is admitted.
    pub async fn check(
        &self,
        mark: &str,
        client_ip: &str,
        max_requests: i64,
        duration_seconds: i64,
    ) -> Result<RateLimitVerdict, RedisLimitError> {
        self.take(self.key(mark, client_ip), max_requests, duration_seconds)
            .await
    }

    /// Go `UserCriticalRateLimit`: same window, keyed by user ID.
    pub async fn check_user(
        &self,
        mark: &str,
        user_id: i64,
        max_requests: i64,
        duration_seconds: i64,
    ) -> Result<RateLimitVerdict, RedisLimitError> {
        self.take(self.user_key(mark, user_id), max_requests, duration_seconds)
            .await
    }

    async fn take(
        &self,
        key: String,
        max_requests: i64,
        duration_seconds: i64,
    ) -> Result<RateLimitVerdict, RedisLimitError> {
        if max_requests <= 0 || duration_seconds <= 0 {
            return Err(RedisLimitError::Value);
        }
        // MultiplexedConnection 的克隆共享同一连接池，避免为并发请求加互斥锁。
        let mut connection = self.connection.clone();
        let (allowed, _count, ttl): (i64, i64, i64) = Script::new(SCRIPT)
            .key(key)
            .arg(max_requests)
            .arg(duration_seconds)
            .invoke_async(&mut connection)
            .await
            .map_err(classify)?;
        if allowed == 1 {
            Ok(RateLimitVerdict::Allowed)
        } else {
            Ok(RateLimitVerdict::Rejected {
                retry_after: ttl.max(1),
            })
        }
    }
}

fn classify(error: redis::RedisError) -> RedisLimitError {
    if error.is_io_error() || error.is_timeout() {
        RedisLimitError::Connection
    } else if error.kind() == ErrorKind::TypeError {
        RedisLimitError::Value
    } else {
        RedisLimitError::Script
    }
}
