//! In-memory sliding-window rate limiter ported from the Go backend's
//! `CriticalRateLimit` middleware (`common.InMemoryRateLimiter.Request`).
//!
//! Semantics preserved from Go (apps/api/internal/common/rate-limit.go):
//! - a key's first request creates its timestamp queue and is admitted;
//! - while the queue holds fewer than `requests` entries, requests append and pass;
//! - once full, a request passes only when `now - oldest >= window_seconds`,
//!   which pops the oldest timestamp and appends the new one; otherwise it is
//!   rejected with `Retry-After = window_seconds` (the conservative in-memory
//!   value used by Go's `memoryRateLimiter`/`writeRateLimited`).
//! - when disabled, Go's `CriticalRateLimit` returns `defNext` without ever
//!   touching the store, so `check` admits without recording any state.
//!
//! Clock readings are injected by the caller (Unix seconds, matching Go's
//! `time.Now().Unix()`) so the limiter stays deterministic and testable.
//!
//! Memory reclamation: Go runs a background `clearExpiredItems` goroutine that
//! deletes keys whose newest timestamp is older than the expiration duration;
//! it never participates in an admission decision. We instead sweep lazily when
//! the map exceeds `MAX_TRACKED_KEYS`, deleting keys idle for more than one
//! full window. That is decision-equivalent to Go's cleaner in the shipped
//! configuration (expiration == window, per Go's `constants.go` note that rate
//! limits "shouldn't [be] larger then RateLimitKeyExpirationDuration"): after a
//! key is dropped, the next request hits the miss branch and passes; had the
//! key survived, every queued timestamp would already satisfy
//! `now - oldest >= window`, so the same request would also pass (possibly
//! after popping stale entries, converging to the same admitted state).

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, PoisonError};

/// Upper bound on tracked keys before a lazy sweep runs. Only a memory guard;
/// it never changes admission outcomes for keys touched within a window.
const MAX_TRACKED_KEYS: usize = 65_536;

/// Settings mirroring Go's `CRITICAL_RATE_LIMIT_ENABLE` /
/// `CRITICAL_RATE_LIMIT` / `CRITICAL_RATE_LIMIT_DURATION` environment variables.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimitSettings {
    pub enabled: bool,
    pub requests: i64,
    pub window_seconds: i64,
}

impl RateLimitSettings {
    /// Defaults from Go's `initRateLimitVariables` (init.go): enabled, 20
    /// requests per 1200-second window.
    pub const fn go_defaults() -> Self {
        Self {
            enabled: true,
            requests: 20,
            window_seconds: 1_200,
        }
    }
}

/// Sliding-window timestamp-queue limiter; the caller owns key derivation
/// (Go uses `mark + c.ClientIP()`), so this type stays transport-agnostic.
pub struct SlidingWindowLimiter {
    settings: RateLimitSettings,
    windows: Mutex<HashMap<String, VecDeque<i64>>>,
}

impl SlidingWindowLimiter {
    pub fn new(settings: RateLimitSettings) -> Self {
        Self {
            settings,
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// Admits or rejects one request at `now` (Unix seconds) for `key`.
    /// Returns `(allowed, retry_after_seconds)`; the second value is the full
    /// window on a rejection (Go's conservative in-memory hint) and `0` on
    /// admission, where Go never reports a retry hint.
    pub fn check(&self, key: &str, now: i64) -> (bool, i64) {
        if !self.settings.enabled {
            return (true, 0);
        }
        let mut windows = self.windows.lock().unwrap_or_else(PoisonError::into_inner);
        if windows.len() >= MAX_TRACKED_KEYS {
            Self::sweep(&mut windows, now, self.settings.window_seconds);
        }
        match windows.get_mut(key) {
            Some(queue) => {
                if (queue.len() as i64) < self.settings.requests {
                    queue.push_back(now);
                    (true, 0)
                } else if queue
                    .front()
                    .is_some_and(|oldest| now - *oldest >= self.settings.window_seconds)
                {
                    queue.pop_front();
                    queue.push_back(now);
                    (true, 0)
                } else {
                    (false, self.settings.window_seconds)
                }
            }
            // Go's store-miss branch appends and returns true without any
            // limit check, so a brand-new key is always admitted.
            None => {
                windows.insert(key.to_owned(), VecDeque::from([now]));
                (true, 0)
            }
        }
    }

    /// Drops keys whose newest timestamp is more than one window old,
    /// mirroring the deletion predicate of Go's `clearExpiredItems`.
    fn sweep(windows: &mut HashMap<String, VecDeque<i64>>, now: i64, window_seconds: i64) {
        windows.retain(|_, queue| {
            queue
                .back()
                .is_some_and(|newest| now - *newest <= window_seconds)
        });
    }

    #[cfg(test)]
    fn tracked_keys(&self) -> usize {
        self.windows
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter(requests: i64, window_seconds: i64) -> SlidingWindowLimiter {
        SlidingWindowLimiter::new(RateLimitSettings {
            enabled: true,
            requests,
            window_seconds,
        })
    }

    #[test]
    fn go_defaults_match_init_go() {
        assert_eq!(
            RateLimitSettings::go_defaults(),
            RateLimitSettings {
                enabled: true,
                requests: 20,
                window_seconds: 1_200,
            }
        );
    }

    #[test]
    fn admits_upto_max_then_rejects_within_window() {
        let limiter = limiter(3, 10);
        let cases = [
            // (now, expected allowed, expected retry-after)
            (0, true, 0),   // first request creates the queue
            (1, true, 0),   // below max
            (2, true, 0),   // exactly max
            (5, false, 10), // max+1-th inside window: rejected
            (9, false, 10), // now - oldest == 9 < 10: still rejected
        ];
        for (now, allowed, retry_after) in cases {
            assert_eq!(
                limiter.check("ct:1.2.3.4", now),
                (allowed, retry_after),
                "t={now}"
            );
        }
    }

    #[test]
    fn pops_oldest_exactly_when_expired_at_boundary() {
        let limiter = limiter(3, 10);
        for now in [0, 1, 2] {
            assert_eq!(limiter.check("k", now), (true, 0));
        }
        // now - oldest == duration: pass and evict timestamp 0 -> queue [1,2,10].
        assert_eq!(limiter.check("k", 10), (true, 0));
        // Without the pop the front would still be 0 and this would pass again;
        // rejection proves the oldest entry was removed.
        assert_eq!(limiter.check("k", 10), (false, 10));
        // Front is now 1: boundary hit again at 11.
        assert_eq!(limiter.check("k", 11), (true, 0));
    }

    #[test]
    fn non_contiguous_timestamps_use_sliding_window() {
        let limiter = limiter(2, 100);
        assert_eq!(limiter.check("k", 1_000), (true, 0));
        assert_eq!(limiter.check("k", 1_050), (true, 0));
        assert_eq!(limiter.check("k", 1_060), (false, 100));
        // 1_100 - 1_000 >= 100: pop the old timestamp.
        assert_eq!(limiter.check("k", 1_100), (true, 0));
        // Queue is [1_050, 1_100]: 1_100 - 1_050 < 100.
        assert_eq!(limiter.check("k", 1_100), (false, 100));
        assert_eq!(limiter.check("k", 1_150), (true, 0));
    }

    #[test]
    fn disabled_always_admits_and_records_nothing() {
        let limiter = SlidingWindowLimiter::new(RateLimitSettings {
            enabled: false,
            requests: 1,
            window_seconds: 1,
        });
        for now in 0..100 {
            assert_eq!(limiter.check("ct:1.2.3.4", now), (true, 0));
        }
        assert_eq!(limiter.tracked_keys(), 0);
    }

    #[test]
    fn keys_are_isolated() {
        let limiter = limiter(1, 10);
        assert_eq!(limiter.check("ct:a", 0), (true, 0));
        assert_eq!(limiter.check("ct:a", 5), (false, 10));
        assert_eq!(limiter.check("ct:b", 5), (true, 0));
        assert_eq!(limiter.check("ct:b", 5), (false, 10));
    }
}
