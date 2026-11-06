//! Integration tests against a real Redis. `TEST_REDIS_URL` is mandatory; these
//! tests never fall back to an in-memory limiter or skip.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use newapi_server::limit_redis::{RateLimitVerdict, RedisRateLimiter};
use redis::aio::MultiplexedConnection;

fn redis_url() -> String {
    std::env::var("TEST_REDIS_URL")
        .expect("redis rate limit tests require TEST_REDIS_URL; skipping is not allowed")
}

async fn limiter() -> RedisRateLimiter {
    RedisRateLimiter::connect(&redis_url())
        .await
        .unwrap_or_else(|_| panic!("must connect to the configured test Redis"))
}

async fn control() -> MultiplexedConnection {
    let client = redis::Client::open(redis_url().as_str())
        .unwrap_or_else(|_| panic!("TEST_REDIS_URL must be a valid Redis URL"));
    client
        .get_multiplexed_async_connection()
        .await
        .unwrap_or_else(|_| panic!("must establish a control connection to Redis"))
}

fn unique_mark() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after the Unix epoch")
        .as_nanos();
    format!(
        "test-{}-{nanos}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

async fn check(
    limiter: &mut RedisRateLimiter,
    mark: &str,
    client_ip: &str,
    max_requests: i64,
    duration_seconds: i64,
) -> RateLimitVerdict {
    limiter
        .check(mark, client_ip, max_requests, duration_seconds)
        .await
        .unwrap_or_else(|_| panic!("rate limit check must succeed"))
}

async fn exists(connection: &mut MultiplexedConnection, key: &str) -> i64 {
    redis::cmd("EXISTS")
        .arg(key)
        .query_async(connection)
        .await
        .unwrap_or_else(|_| panic!("EXISTS must succeed for key {key}"))
}

async fn ttl(connection: &mut MultiplexedConnection, key: &str) -> i64 {
    redis::cmd("TTL")
        .arg(key)
        .query_async(connection)
        .await
        .unwrap_or_else(|_| panic!("TTL must succeed for key {key}"))
}

async fn cleanup(connection: &mut MultiplexedConnection, key: &str) {
    let _: i64 = redis::cmd("DEL")
        .arg(key)
        .query_async(connection)
        .await
        .unwrap_or_else(|_| panic!("DEL must succeed for key {key}"));
}

#[tokio::test]
async fn admits_first_n_then_rejects_with_remaining_ttl() {
    let mut limiter = limiter().await;
    let mut control = control().await;
    let mark = unique_mark();
    let ip = "192.0.2.10";
    let duration = 30;
    let key = limiter.key(&mark, ip);
    assert_eq!(key, format!("rateLimit:v2:ip:{mark}:{ip}"));
    for attempt in 1..=3 {
        assert_eq!(
            check(&mut limiter, &mark, ip, 3, duration).await,
            RateLimitVerdict::Allowed,
            "attempt {attempt} must be admitted"
        );
    }
    match check(&mut limiter, &mark, ip, 3, duration).await {
        RateLimitVerdict::Rejected { retry_after } => {
            assert!(
                retry_after > 0 && retry_after <= duration,
                "retry_after {retry_after} must fall in (0, {duration}]"
            );
        }
        RateLimitVerdict::Allowed => panic!("attempt 4 must be rejected"),
    }
    assert_eq!(exists(&mut control, &key).await, 1, "key {key} must exist");
    let remaining = ttl(&mut control, &key).await;
    assert!(
        remaining > 0 && remaining <= duration,
        "ttl {remaining} for key {key} must be positive"
    );
    cleanup(&mut control, &key).await;
}

#[tokio::test]
async fn expired_window_admits_again() {
    let mut limiter = limiter().await;
    let mut control = control().await;
    let mark = unique_mark();
    let ip = "192.0.2.11";
    let key = limiter.key(&mark, ip);
    assert_eq!(
        check(&mut limiter, &mark, ip, 1, 1).await,
        RateLimitVerdict::Allowed
    );
    match check(&mut limiter, &mark, ip, 1, 1).await {
        RateLimitVerdict::Rejected { retry_after } => {
            assert!(
                retry_after > 0 && retry_after <= 1,
                "retry_after {retry_after} must be one second"
            );
        }
        RateLimitVerdict::Allowed => panic!("second request inside the window must be rejected"),
    }
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    assert_eq!(
        check(&mut limiter, &mark, ip, 1, 1).await,
        RateLimitVerdict::Allowed,
        "an expired fixed window must admit again"
    );
    cleanup(&mut control, &key).await;
}

#[tokio::test]
async fn marks_and_ips_are_isolated() {
    let mut limiter = limiter().await;
    let mut control = control().await;
    let mark_a = unique_mark();
    let mark_b = unique_mark();
    let ip_a = "192.0.2.12";
    let ip_b = "192.0.2.13";
    let duration = 30;
    assert_eq!(
        check(&mut limiter, &mark_a, ip_a, 1, duration).await,
        RateLimitVerdict::Allowed
    );
    assert!(matches!(
        check(&mut limiter, &mark_a, ip_a, 1, duration).await,
        RateLimitVerdict::Rejected { .. }
    ));
    assert_eq!(
        check(&mut limiter, &mark_b, ip_a, 1, duration).await,
        RateLimitVerdict::Allowed,
        "a different mark must have its own window"
    );
    assert_eq!(
        check(&mut limiter, &mark_a, ip_b, 1, duration).await,
        RateLimitVerdict::Allowed,
        "a different client IP must have its own window"
    );
    cleanup(&mut control, &limiter.key(&mark_a, ip_a)).await;
    cleanup(&mut control, &limiter.key(&mark_b, ip_a)).await;
    cleanup(&mut control, &limiter.key(&mark_a, ip_b)).await;
}

#[tokio::test]
async fn key_uses_go_namespace_and_ip_layout() {
    let mut limiter = limiter().await;
    let mut control = control().await;
    let mark = unique_mark();
    let ip = "198.51.100.7";
    let key = limiter.key(&mark, ip);
    assert_eq!(key, format!("rateLimit:v2:ip:{mark}:{ip}"));
    assert_eq!(
        check(&mut limiter, &mark, ip, 5, 30).await,
        RateLimitVerdict::Allowed
    );
    assert_eq!(
        exists(&mut control, &key).await,
        1,
        "Go key layout must exist in Redis: {key}"
    );
    let remaining = ttl(&mut control, &key).await;
    assert!(remaining > 0, "ttl for key {key} must be positive");
    cleanup(&mut control, &key).await;
}
