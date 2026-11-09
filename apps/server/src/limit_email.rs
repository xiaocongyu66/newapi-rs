//! `EmailVerificationRateLimit`：Go
//! `apps/api/internal/transport/middleware/limit_email_verification.go` 的移植。
//!
//! 与关键路径限流（`limit.rs`/`limit_redis.rs`）无关的独立限流器：固定
//! 2 次/30 秒窗口，键按客户端 IP 派生，且**不受任何限流开关影响**
//! （Go 的 `EmailVerificationRateLimit` 没有 enabled 分支）。
//!
//! 与关键路径限流的另外两点差异同样复刻：
//! - Redis 后端故障时 Go 回退到内存限流（关键路径是 500 + Abort）；
//! - 拒绝响应是 429 + JSON 信封（`{"success":false,"message":...}`），
//!   不是裸 429，也不带 Retry-After 头。两条路径的文案不同：
//!   Redis 带剩余秒数，内存是固定“请稍后再试”。

use crate::limit::{RateLimitSettings, SlidingWindowLimiter};
use crate::limit_redis::{RateLimitVerdict, RedisRateLimiter};

/// Go `EmailVerificationRateLimitMark`。
pub const EMAIL_VERIFICATION_MARK: &str = "EV";
/// Go `EmailVerificationMaxRequests`：30 秒内最多 2 次。
pub const EMAIL_VERIFICATION_MAX_REQUESTS: i64 = 2;
/// Go `EmailVerificationDuration`：30 秒窗口。
pub const EMAIL_VERIFICATION_DURATION: i64 = 30;

/// Go 的内存路径拒绝文案（逐字）；Redis 路径文案在
/// [`rejection_message`] 内以内联格式化生成。
pub const REJECT_MESSAGE_MEMORY: &str = "发送过于频繁，请稍后再试";

/// 限流判定结果；由调用方翻译成 429 响应。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmailLimitDecision {
    Allowed,
    /// Redis 固定窗口拒绝，附 TTL（Go 取 `ttlSeconds`，非正数回退 30）。
    RejectedWithWait(i64),
    /// 内存滑动窗口拒绝（Go 的 `memoryEmailVerificationRateLimiter` 分支）。
    RejectedMemory,
}

/// 邮箱验证码限流器：内存后端始终在位（Go 在中间件构造时就
/// `inMemoryRateLimiter.Init` 保持回退可用），Redis 可选。
pub struct EmailVerificationLimiter {
    memory: SlidingWindowLimiter,
    redis: Option<RedisRateLimiter>,
}

impl EmailVerificationLimiter {
    /// 无 Redis 部署的构造：Go 的 `common.RedisEnabled == false` 分支。
    pub fn memory_only() -> Self {
        Self {
            memory: SlidingWindowLimiter::new(go_settings()),
            redis: None,
        }
    }

    /// 配置 Redis 的构造；Redis 故障自动回退内存。
    pub fn with_redis(redis: RedisRateLimiter) -> Self {
        Self {
            memory: SlidingWindowLimiter::new(go_settings()),
            redis: Some(redis),
        }
    }

    /// Go `redisEmailVerificationRateLimiter` + `memoryEmailVerificationRateLimiter`
    /// 的完整判定。内存键是 `EmailVerificationRateLimitMark + ":" + ip`
    /// （limit_email_verification.go:46），与关键路径的 `mark + ip` 不同。
    pub async fn check(&self, client_ip: &str, now: i64) -> EmailLimitDecision {
        let memory_key = format!("{EMAIL_VERIFICATION_MARK}:{client_ip}");
        let Some(redis) = self.redis.as_ref() else {
            return self.memory_check(&memory_key, now);
        };
        match redis
            .check(
                EMAIL_VERIFICATION_MARK,
                client_ip,
                EMAIL_VERIFICATION_MAX_REQUESTS,
                EMAIL_VERIFICATION_DURATION,
            )
            .await
        {
            Ok(RateLimitVerdict::Allowed) => EmailLimitDecision::Allowed,
            Ok(RateLimitVerdict::Rejected { retry_after }) => {
                EmailLimitDecision::RejectedWithWait(retry_after)
            }
            // Go 的 Redis 故障分支：回退内存限流，不是 500。
            Err(_) => self.memory_check(&memory_key, now),
        }
    }

    fn memory_check(&self, key: &str, now: i64) -> EmailLimitDecision {
        let (allowed, _) = self.memory.check(key, now);
        if allowed {
            EmailLimitDecision::Allowed
        } else {
            EmailLimitDecision::RejectedMemory
        }
    }
}

fn go_settings() -> RateLimitSettings {
    RateLimitSettings {
        enabled: true,
        requests: EMAIL_VERIFICATION_MAX_REQUESTS,
        window_seconds: EMAIL_VERIFICATION_DURATION,
    }
}

/// 把判定翻译成 Go 的响应文案。Redis 路径的秒数取 TTL，非正数回退
/// 窗口长度（`limit_email_verification.go:33-36`）。
pub fn rejection_message(decision: EmailLimitDecision) -> String {
    match decision {
        EmailLimitDecision::RejectedWithWait(wait_seconds) => {
            let wait_seconds = if wait_seconds > 0 {
                wait_seconds
            } else {
                EMAIL_VERIFICATION_DURATION
            };
            format!("发送过于频繁，请等待 {wait_seconds} 秒后再试")
        }
        EmailLimitDecision::RejectedMemory => REJECT_MESSAGE_MEMORY.to_owned(),
        EmailLimitDecision::Allowed => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_constants_match_the_go_source() {
        assert_eq!(EMAIL_VERIFICATION_MARK, "EV");
        assert_eq!(EMAIL_VERIFICATION_MAX_REQUESTS, 2);
        assert_eq!(EMAIL_VERIFICATION_DURATION, 30);
    }

    #[tokio::test]
    async fn memory_limiter_admits_two_then_rejects_inside_thirty_seconds() {
        let limiter = EmailVerificationLimiter::memory_only();
        let now = 1_000;
        assert_eq!(
            limiter.check("203.0.113.9", now).await,
            EmailLimitDecision::Allowed
        );
        assert_eq!(
            limiter.check("203.0.113.9", now).await,
            EmailLimitDecision::Allowed
        );
        // 第三次仍在 30 秒窗口内：拒绝。
        assert_eq!(
            limiter.check("203.0.113.9", now).await,
            EmailLimitDecision::RejectedMemory
        );
        // 窗口滑出 oldest 后放行（Go `InMemoryRateLimiter.Request`）。
        assert_eq!(
            limiter.check("203.0.113.9", now + 30).await,
            EmailLimitDecision::Allowed
        );
    }

    #[tokio::test]
    async fn memory_keys_are_isolated_per_ip_and_scoped_to_the_ev_mark() {
        let limiter = EmailVerificationLimiter::memory_only();
        let now = 1_000;
        for _ in 0..3 {
            let _ = limiter.check("203.0.113.9", now).await;
        }
        // 另一个 IP 独立计数，EV 与 CT 的键空间也由前缀隔开。
        assert_eq!(
            limiter.check("198.51.100.7", now).await,
            EmailLimitDecision::Allowed
        );
    }

    #[test]
    fn messages_match_go_verbatim() {
        assert_eq!(
            rejection_message(EmailLimitDecision::RejectedWithWait(12)),
            "发送过于频繁，请等待 12 秒后再试"
        );
        assert_eq!(
            rejection_message(EmailLimitDecision::RejectedWithWait(0)),
            "发送过于频繁，请等待 30 秒后再试"
        );
        assert_eq!(
            rejection_message(EmailLimitDecision::RejectedMemory),
            "发送过于频繁，请稍后再试"
        );
    }
}
