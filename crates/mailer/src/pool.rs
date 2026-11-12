//! 多账号发送池（Go `internal/common/email_pool.go`）。
//!
//! 选择语义（Go `SenderPool.Send` + `ordered`）：有剩余配额的账号中，
//! 优先级最小层先用、层内按自增游标轮转，被拒后逐层回退；全部配额耗尽时
//! 返回 Go 同文错误。

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};

use newapi_identity::email::{EmailError, EmailSender, OutgoingMessage, SMTP_NOT_CONFIGURED};

use crate::config::SmtpAccountConfig;
use crate::quota::QuotaStore;

/// Go `EmailSender` 端口 + 池选择所需的账号元数据。生产实现是
/// [`crate::smtp::LettreSmtpSender`]；测试用替身。
pub trait PoolSender: EmailSender {
    fn config(&self) -> &SmtpAccountConfig;
}

/// Go `smtpSendCursor`（email_pool.go:22）：层内轮转游标。
static SEND_CURSOR: AtomicU32 = AtomicU32::new(0);

struct PoolEntry {
    sender: Arc<dyn PoolSender>,
}

/// Go `SenderPool`。
pub struct SenderPool {
    senders: Vec<PoolEntry>,
    quota: Arc<dyn QuotaStore>,
}

/// Go `SenderPool.Send` 的错误文案（email_pool.go:74-79）。
pub const ALL_ACCOUNTS_EXHAUSTED: &str = "所有 SMTP 账号均已达到当日发送额度";

impl SenderPool {
    /// Go `NewSenderPool`：`factory` 在生产里构造 lettre 发送器，测试里
    /// 构造替身——对应 Go 的 `newSMTPSender(config)`。
    pub fn new(
        configs: Vec<SmtpAccountConfig>,
        quota: Arc<dyn QuotaStore>,
        factory: &dyn Fn(&SmtpAccountConfig) -> Arc<dyn PoolSender>,
    ) -> Self {
        let senders = configs
            .into_iter()
            .map(|config| PoolEntry {
                sender: factory(&config),
            })
            .collect();
        Self { senders, quota }
    }

    pub fn is_empty(&self) -> bool {
        self.senders.is_empty()
    }

    /// Go `ordered`（email_pool.go:131-176）：配额未耗尽者按优先级稳定
    /// 排序，顶层（同 priority）按游标轮转，之后接其余层。
    async fn ordered(&self) -> Vec<Arc<dyn PoolSender>> {
        let mut entries: Vec<(Arc<dyn PoolSender>, i64)> = Vec::new();
        for entry in &self.senders {
            let config = entry.sender.config();
            let used = match self.quota.used_today(&config.account).await {
                Ok(used) => used,
                // Go `Status()` 读配额失败只 SysError 并按 0 处理
                // （email_smtp_sender.go:40-45），选择不被单次读失败打断。
                Err(error) => {
                    tracing::warn!(
                        event = "smtp_quota_read_failed",
                        account = %config.account,
                        "failed to read SMTP quota: {error}"
                    );
                    0
                }
            };
            if config.daily_limit <= 0 || used < config.daily_limit {
                entries.push((entry.sender.clone(), config.priority));
            }
        }
        if entries.is_empty() {
            return Vec::new();
        }
        // 稳定排序（Go sort.SliceStable）。
        entries.sort_by_key(|(sender, _)| sender.config().priority);
        let top_priority = entries[0].1;
        let tier_end = entries
            .iter()
            .position(|(_, priority)| *priority != top_priority)
            .unwrap_or(entries.len());
        let mut ordered: Vec<Arc<dyn PoolSender>> = Vec::with_capacity(entries.len());
        if tier_end > 1 {
            // Go：offset = (Add(1)-1) % len(tier)——fetch_add 的旧值即
            // Add(1)-1；游标 0 的首次发送落在第一个账号上。
            let cursor = SEND_CURSOR.fetch_add(1, AtomicOrdering::Relaxed);
            let offset = cursor as usize % tier_end;
            for index in 0..tier_end {
                ordered.push(entries[(offset + index) % tier_end].0.clone());
            }
        } else {
            ordered.push(entries[0].0.clone());
        }
        for (sender, _) in entries.iter().skip(tier_end) {
            ordered.push(sender.clone());
        }
        ordered
    }

    /// Go `SenderPool.Send`（email_pool.go:70-95）：成功后计配额（不限量
    /// 账号不计，省一次写库），失败则回退下一账号。
    pub async fn send(&self, message: &OutgoingMessage<'_>) -> Result<(), EmailError> {
        let ordered = self.ordered().await;
        if ordered.is_empty() {
            return Err(EmailError(if self.senders.is_empty() {
                SMTP_NOT_CONFIGURED.to_owned()
            } else {
                ALL_ACCOUNTS_EXHAUSTED.to_owned()
            }));
        }
        let mut last_error: Option<EmailError> = None;
        for sender in ordered {
            let config = sender.config();
            match sender.send(message).await {
                Ok(()) => {
                    // Go：dailyLimit > 0 才计配额；失败只 SysError，不影响发送结果。
                    if config.daily_limit > 0
                        && let Err(error) = self.quota.record_use(&config.account).await
                    {
                        tracing::warn!(
                            event = "smtp_quota_record_failed",
                            account = %config.account,
                            "failed to record SMTP quota: {error}"
                        );
                    }
                    return Ok(());
                }
                Err(error) => {
                    tracing::warn!(
                        event = "smtp_send_failed",
                        account = %config.account,
                        server = %config.server,
                        port = config.port,
                        "failed to send email through account: {error}"
                    );
                    last_error = Some(error);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| EmailError(ALL_ACCOUNTS_EXHAUSTED.to_owned())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct StubSender {
        config: SmtpAccountConfig,
        calls: Mutex<u32>,
        fail: bool,
    }

    impl StubSender {
        fn new(priority: i64, daily_limit: i64, account: &str, fail: bool) -> Arc<Self> {
            Arc::new(Self {
                config: SmtpAccountConfig {
                    account: account.to_owned(),
                    priority,
                    daily_limit,
                    ..SmtpAccountConfig::default()
                },
                calls: Mutex::new(0),
                fail,
            })
        }
    }

    impl EmailSender for StubSender {
        fn send<'a>(
            &'a self,
            _message: &OutgoingMessage<'a>,
        ) -> newapi_identity::email::SendFuture<'a> {
            Box::pin(async move {
                *self.calls.lock().unwrap() += 1;
                if self.fail {
                    Err(EmailError("stub failure".to_owned()))
                } else {
                    Ok(())
                }
            })
        }
    }

    impl PoolSender for StubSender {
        fn config(&self) -> &SmtpAccountConfig {
            &self.config
        }
    }

    #[derive(Default)]
    struct MemoryQuota {
        used: Mutex<std::collections::HashMap<String, i64>>,
    }

    #[async_trait::async_trait]
    impl QuotaStore for MemoryQuota {
        async fn used_today(&self, account: &str) -> Result<i64, String> {
            Ok(*self.used.lock().unwrap().get(account).unwrap_or(&0))
        }

        async fn record_use(&self, account: &str) -> Result<(), String> {
            *self
                .used
                .lock()
                .unwrap()
                .entry(account.to_owned())
                .or_insert(0) += 1;
            Ok(())
        }
    }

    /// EmailError purposely lacks Debug（identity 端口文档），unwrap/expect
    /// 不可用；测试用 match 提取。
    fn ok(result: Result<(), EmailError>) {
        if let Err(error) = result {
            panic!("send failed: {error}");
        }
    }

    fn message() -> OutgoingMessage<'static> {
        OutgoingMessage {
            subject: "s",
            receiver: "r@example.com",
            content: "<p>c</p>",
        }
    }

    fn factory(_config: &SmtpAccountConfig) -> Arc<dyn PoolSender> {
        unreachable!("factory replaced by stubs")
    }

    fn pool_with(senders: Vec<Arc<StubSender>>, quota: Arc<MemoryQuota>) -> SenderPool {
        SenderPool {
            senders: senders
                .into_iter()
                .map(|sender| PoolEntry { sender })
                .collect(),
            quota,
        }
    }

    #[tokio::test]
    async fn lowest_priority_tier_sends_first() {
        let low = StubSender::new(1, 0, "low", false);
        let high = StubSender::new(5, 0, "high", false);
        let pool = pool_with(
            vec![high.clone(), low.clone()],
            Arc::new(MemoryQuota::default()),
        );
        ok(pool.send(&message()).await);
        assert_eq!(*low.calls.lock().unwrap(), 1);
        assert_eq!(*high.calls.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn failure_falls_through_to_next_tier() {
        let failing = StubSender::new(1, 0, "fail", true);
        let fallback = StubSender::new(2, 0, "ok", false);
        let pool = pool_with(
            vec![failing.clone(), fallback.clone()],
            Arc::new(MemoryQuota::default()),
        );
        ok(pool.send(&message()).await);
        assert_eq!(*failing.calls.lock().unwrap(), 1);
        assert_eq!(*fallback.calls.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn quota_gate_skips_exhausted_accounts() {
        let quota = Arc::new(MemoryQuota::default());
        quota.used.lock().unwrap().insert("full".to_owned(), 10);
        let full = StubSender::new(1, 10, "full", false);
        let spare = StubSender::new(2, 0, "spare", false);
        let pool = pool_with(vec![full.clone(), spare.clone()], quota);
        ok(pool.send(&message()).await);
        assert_eq!(*full.calls.lock().unwrap(), 0);
        assert_eq!(*spare.calls.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn exhausted_pool_reports_the_go_message() {
        let quota = Arc::new(MemoryQuota::default());
        quota.used.lock().unwrap().insert("full".to_owned(), 10);
        let full = StubSender::new(1, 10, "full", false);
        let pool = pool_with(vec![full], quota);
        let error = match pool.send(&message()).await {
            Ok(()) => panic!("expected exhaustion error"),
            Err(error) => error,
        };
        assert_eq!(error.to_string(), ALL_ACCOUNTS_EXHAUSTED);
    }

    #[tokio::test]
    async fn all_exhausted_without_any_limit_records_success() {
        // 不限量账号发送成功后不写配额（Go smtpRecordQuotaUse 的
        // dailyLimit <= 0 短路）。
        let quota = Arc::new(MemoryQuota::default());
        let free = StubSender::new(1, 0, "free", false);
        let pool = pool_with(vec![free.clone()], quota.clone());
        ok(pool.send(&message()).await);
        assert!(quota.used.lock().unwrap().is_empty());
        assert_eq!(*free.calls.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn empty_pool_reports_unconfigured() {
        let pool = SenderPool::new(Vec::new(), Arc::new(MemoryQuota::default()), &factory);
        let error = match pool.send(&message()).await {
            Ok(()) => panic!("expected unconfigured error"),
            Err(error) => error,
        };
        assert_eq!(error.to_string(), SMTP_NOT_CONFIGURED);
    }

    #[tokio::test]
    async fn top_tier_rotates_then_falls_back() {
        let a = StubSender::new(1, 0, "a", true);
        let b = StubSender::new(1, 0, "b", false);
        let c = StubSender::new(2, 0, "c", false);
        let pool = pool_with(
            vec![a.clone(), b.clone(), c.clone()],
            Arc::new(MemoryQuota::default()),
        );
        // 游标 0：offset = (0-1) wrapping % 2 —— 首次发送仍命中顶层某个
        // 账号（Go 注释：cursor 为 0 的首次发送必须落在第一个账号上，即
        // wrapping 后仍有效轮转）。两次发送应覆盖 a、b 各一次。
        let _ = pool.send(&message()).await;
        let _ = pool.send(&message()).await;
        let a_calls = *a.calls.lock().unwrap();
        let b_calls = *b.calls.lock().unwrap();
        assert_eq!(a_calls + b_calls, 2, "top tier served both sends");
    }
}
