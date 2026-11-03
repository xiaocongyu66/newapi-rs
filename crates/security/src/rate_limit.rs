//! 纯内存固定窗口限流器，不接入 HTTP、持久化或分布式共享存储。
//! 调用方显式提供 `Instant`，便于在不休眠的情况下验证窗口边界。
//! 所有状态由互斥锁保护，锁中毒后恢复内部状态继续判定。

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// 最多保存的 key 数量；未到期的桶不会因容量压力被淘汰。
pub const MAX_KEYS: usize = 10_000;

/// key 的最大 UTF-8 字节长度；超长 key 在复制或访问状态前被拒绝。
pub const MAX_KEY_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    /// 本次放行；`retry_after` 为当前窗口的剩余时间。
    Allowed { retry_after: Duration },
    /// 配额耗尽、容量不足或输入无效；`retry_after` 永不超过窗口长度。
    /// 容量不足时返回完整窗口长度；无效输入不会因等待而变为有效。
    Limited { retry_after: Duration },
}

struct WindowState {
    start: Instant,
    count: u32,
}

struct State {
    windows: HashMap<String, WindowState>,
    capacity_exceeded: bool,
}

pub struct RateLimiter {
    per_window: u32,
    window: Duration,
    state: Mutex<State>,
}

impl RateLimiter {
    /// 零窗口保持构造接口可用，但其所有检查均拒绝且不保存桶。
    pub fn new(per_window: u32, window: Duration) -> Self {
        Self {
            per_window,
            window,
            state: Mutex::new(State {
                windows: HashMap::new(),
                capacity_exceeded: false,
            }),
        }
    }

    /// 在同一把锁内完成窗口推进和配额消耗，并发调用不会重复放行超限请求。
    pub fn check(&self, key: &str, now: Instant) -> Decision {
        // 无效输入直接拒绝，不加锁、不复制 key，也不创建桶。
        if key.len() > MAX_KEY_BYTES || self.window.is_zero() {
            return Decision::Limited {
                retry_after: self.window,
            };
        }

        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = state.windows.get_mut(key) {
            return consume(entry, self.per_window, self.window, now);
        }

        if state.windows.len() >= MAX_KEYS {
            state.capacity_exceeded = true;
            state.windows.retain(|_, entry| {
                now.saturating_duration_since(entry.start) < self.window
            });
            if state.windows.len() >= MAX_KEYS {
                return Decision::Limited {
                    retry_after: self.window,
                };
            }
        }

        let mut entry = WindowState {
            start: now,
            count: 0,
        };
        let decision = consume(&mut entry, self.per_window, self.window, now);
        state.windows.insert(key.to_owned(), entry);
        if state.windows.len() >= MAX_KEYS {
            state.capacity_exceeded = true;
        }
        decision
    }

    /// 桶数量是否曾触及容量上限；到期回收后仍保留此标志。
    pub fn capacity_exceeded(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .capacity_exceeded
    }
}

fn consume(
    entry: &mut WindowState,
    per_window: u32,
    window: Duration,
    now: Instant,
) -> Decision {
    if now.saturating_duration_since(entry.start) >= window {
        entry.start = now;
        entry.count = 0;
    }
    let retry_after = window.saturating_sub(now.saturating_duration_since(entry.start));
    if entry.count < per_window {
        entry.count += 1;
        Decision::Allowed { retry_after }
    } else {
        Decision::Limited { retry_after }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    const WINDOW: Duration = Duration::from_secs(1);

    #[test]
    fn allows_configured_quota_then_limits() {
        let limiter = RateLimiter::new(3, WINDOW);
        let now = Instant::now();
        for _ in 0..3 {
            assert!(matches!(
                limiter.check("key", now),
                Decision::Allowed { .. }
            ));
        }
        match limiter.check("key", now) {
            Decision::Limited { retry_after } => assert!(retry_after <= WINDOW),
            Decision::Allowed { .. } => panic!("配额耗尽后仍被放行"),
        }
    }

    #[test]
    fn window_slides_at_boundary() {
        let limiter = RateLimiter::new(1, WINDOW);
        let start = Instant::now();
        assert!(matches!(
            limiter.check("key", start),
            Decision::Allowed { .. }
        ));

        let almost = start + WINDOW - Duration::from_millis(1);
        match limiter.check("key", almost) {
            Decision::Limited { retry_after } => {
                assert!(retry_after <= WINDOW);
                assert!(retry_after > Duration::ZERO);
            }
            Decision::Allowed { .. } => panic!("窗口未重置时不应放行"),
        }

        let boundary = start + WINDOW;
        assert!(matches!(
            limiter.check("key", boundary),
            Decision::Allowed { .. }
        ));
    }

    #[test]
    fn different_keys_are_isolated() {
        let limiter = RateLimiter::new(1, WINDOW);
        let now = Instant::now();
        assert!(matches!(
            limiter.check("first", now),
            Decision::Allowed { .. }
        ));
        assert!(matches!(
            limiter.check("first", now),
            Decision::Limited { .. }
        ));
        assert!(matches!(
            limiter.check("second", now),
            Decision::Allowed { .. }
        ));
        assert!(matches!(
            limiter.check("second", now),
            Decision::Limited { .. }
        ));
    }

    #[test]
    fn full_capacity_preserves_existing_budgets() {
        let limiter = RateLimiter::new(2, WINDOW);
        let now = Instant::now();
        assert!(!limiter.capacity_exceeded());
        for index in 0..MAX_KEYS {
            assert!(matches!(
                limiter.check(&format!("key-{index}"), now),
                Decision::Allowed { .. }
            ));
        }
        assert!(limiter.capacity_exceeded());
        assert!(matches!(
            limiter.check("key-0", now),
            Decision::Allowed { .. }
        ));

        for index in 0..16 {
            assert_eq!(
                limiter.check(&format!("overflow-{index}"), now),
                Decision::Limited {
                    retry_after: WINDOW,
                }
            );
            assert!(matches!(
                limiter.check("key-0", now),
                Decision::Limited { .. }
            ));
        }
        // 容量压力也不能阻止已有 key 消耗剩余预算。
        assert!(matches!(
            limiter.check("key-1", now),
            Decision::Allowed { .. }
        ));
        let state = limiter.state.lock().expect("状态锁可用");
        assert_eq!(state.windows.len(), MAX_KEYS);
        assert!(!state.windows.contains_key("overflow-0"));
    }

    #[test]
    fn full_capacity_reclaims_only_expired_buckets() {
        let limiter = RateLimiter::new(1, WINDOW);
        let start = Instant::now();
        for index in 0..MAX_KEYS - 1 {
            assert!(matches!(
                limiter.check(&format!("expired-{index}"), start),
                Decision::Allowed { .. }
            ));
        }
        let later = start + Duration::from_millis(500);
        assert!(matches!(
            limiter.check("active", later),
            Decision::Allowed { .. }
        ));
        let boundary = start + WINDOW;
        assert!(matches!(
            limiter.check("new", boundary),
            Decision::Allowed { .. }
        ));
        assert!(matches!(
            limiter.check("active", boundary),
            Decision::Limited { .. }
        ));
        assert!(limiter.capacity_exceeded());
        let state = limiter.state.lock().expect("状态锁可用");
        assert_eq!(state.windows.len(), 2);
        assert!(!state.windows.contains_key("expired-0"));
        assert!(state.windows.contains_key("active"));
        assert!(state.windows.contains_key("new"));
    }

    #[test]
    fn oversized_key_is_rejected_without_allocating_state() {
        let limiter = RateLimiter::new(1, WINDOW);
        let bytes = [b'x'; MAX_KEY_BYTES + 1];
        let key = std::str::from_utf8(&bytes).expect("ASCII key");
        let now = Instant::now();
        // 持锁调用仍可返回，证明拒绝路径在访问状态之前；输入本身位于栈上。
        let state = limiter.state.lock().expect("状态锁可用");
        assert_eq!(state.windows.capacity(), 0);
        for _ in 0..2 {
            assert_eq!(
                limiter.check(key, now),
                Decision::Limited {
                    retry_after: WINDOW,
                }
            );
        }
        assert!(state.windows.is_empty());
        assert_eq!(state.windows.capacity(), 0);
        assert!(!state.capacity_exceeded);
        drop(state);

        // 上限按字节计算，恰好达到上限的 key 仍然有效。
        let boundary_key = std::str::from_utf8(&bytes[..MAX_KEY_BYTES]).expect("ASCII key");
        assert!(matches!(
            limiter.check(boundary_key, now),
            Decision::Allowed { .. }
        ));
        let unicode_key = "界".repeat(MAX_KEY_BYTES / 3 + 1);
        assert!(unicode_key.len() > MAX_KEY_BYTES);
        assert!(matches!(
            limiter.check(&unicode_key, now),
            Decision::Limited { .. }
        ));
        assert_eq!(limiter.state.lock().expect("状态锁可用").windows.len(), 1);
    }

    #[test]
    fn zero_window_fails_closed_without_creating_buckets() {
        let limiter = RateLimiter::new(3, Duration::ZERO);
        let start = Instant::now();
        for now in [start, start, start + WINDOW] {
            for key in ["first", "second"] {
                assert_eq!(
                    limiter.check(key, now),
                    Decision::Limited {
                        retry_after: Duration::ZERO,
                    }
                );
            }
        }
        let state = limiter.state.lock().expect("状态锁可用");
        assert!(state.windows.is_empty());
        assert_eq!(state.windows.capacity(), 0);
    }

    #[test]
    fn retry_after_never_exceeds_window() {
        let limiter = RateLimiter::new(1, WINDOW);
        let start = Instant::now();
        match limiter.check("key", start) {
            Decision::Allowed { retry_after } => assert!(retry_after <= WINDOW),
            Decision::Limited { .. } => panic!("首次请求应放行"),
        }
        for milliseconds in [0, 1, 500, 999] {
            let now = start + Duration::from_millis(milliseconds);
            match limiter.check("key", now) {
                Decision::Limited { retry_after } => assert!(retry_after <= WINDOW),
                Decision::Allowed { .. } => panic!("窗口内不应放行"),
            }
        }
    }

    #[test]
    fn zero_quota_always_limits() {
        let limiter = RateLimiter::new(0, WINDOW);
        let now = Instant::now();
        match limiter.check("key", now) {
            Decision::Limited { retry_after } => assert_eq!(retry_after, WINDOW),
            Decision::Allowed { .. } => panic!("零配额不应放行"),
        }
    }

    #[test]
    fn concurrent_checks_do_not_over_allow() {
        let limiter = Arc::new(RateLimiter::new(16, Duration::from_secs(60)));
        let now = Instant::now();
        let mut handles = Vec::new();
        for _ in 0..8 {
            let limiter = Arc::clone(&limiter);
            handles.push(thread::spawn(move || {
                let mut allowed = 0;
                for _ in 0..32 {
                    if matches!(limiter.check("shared", now), Decision::Allowed { .. }) {
                        allowed += 1;
                    }
                }
                allowed
            }));
        }
        let allowed: usize = handles
            .into_iter()
            .map(|handle| handle.join().expect("工作线程不应崩溃"))
            .sum();
        assert_eq!(allowed, 16);
    }

    #[test]
    fn poisoned_lock_still_serves() {
        let limiter = Arc::new(RateLimiter::new(1, WINDOW));
        let poisoned = Arc::clone(&limiter);
        let result = thread::spawn(move || {
            let _guard = poisoned.state.lock().expect("状态锁可用");
            panic!("故意让状态锁中毒");
        })
        .join();
        assert!(result.is_err());
        assert!(matches!(
            limiter.check("key", Instant::now()),
            Decision::Allowed { .. }
        ));
    }
}
