//! Go `internal/relay/common/classify_billing.go` 的移植：计费会话端口。
//!
//! `BillingSettler` 由 billing 切片实现，存储在 RelayInfo 上以避免循环引用。
//! 计费调用点（consume_*_quota）在 dispatch 切片接线；本切片只定义 trait。

/// Go `BillingSettler`（classify_billing.go）。
pub trait BillingSettler {
    /// Go `Settle(actualQuota)`：delta = actualQuota - preConsumedQuota，
    /// 同时调整资金来源（钱包/订阅）与令牌额度。
    fn settle(&mut self, actual_quota: i64) -> Result<(), String>;

    /// Go `Refund(c)`：退还全部预扣费额度，幂等安全；Go 通过 gopool 异步执行，
    /// Rust 侧由实现方决定执行模型。
    fn refund(&mut self);

    /// Go `NeedsRefund()`：存在未结算且未退款的预扣状态。
    fn needs_refund(&self) -> bool;

    /// Go `GetPreConsumedQuota()`：实际预扣的额度值（信任用户可能为 0）。
    fn get_pre_consumed_quota(&self) -> i64;

    /// Go `Reserve(targetQuota)`：预扣补到目标值；目标不高于当前则不动。
    fn reserve(&mut self, target_quota: i64) -> Result<(), String>;
}

/// dispatch 切片接线计费时的端口调用点形状：Go `billing.PostTextConsumeQuota` /
/// `billing.PostAudioConsumeQuota` 的抽象。billing 切片注入替身。
pub trait BillingConsumePort {
    /// Go `PostTextConsumeQuota(c, info, usage, extra)`。
    fn post_text_consume_quota(&self, info: &crate::relay_info::RelayInfo, usage_json: &str);
    /// Go `PostAudioConsumeQuota(c, info, usage, key)`。
    fn post_audio_consume_quota(
        &self,
        info: &crate::relay_info::RelayInfo,
        usage_json: &str,
        key: &str,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeSettler {
        pre_consumed: i64,
        settled: bool,
        refunded: bool,
    }

    impl BillingSettler for FakeSettler {
        fn settle(&mut self, actual_quota: i64) -> Result<(), String> {
            let _ = actual_quota;
            self.settled = true;
            Ok(())
        }
        fn refund(&mut self) {
            self.refunded = true;
        }
        fn needs_refund(&self) -> bool {
            !self.settled && !self.refunded
        }
        fn get_pre_consumed_quota(&self) -> i64 {
            self.pre_consumed
        }
        fn reserve(&mut self, target_quota: i64) -> Result<(), String> {
            if target_quota > self.pre_consumed {
                self.pre_consumed = target_quota;
            }
            Ok(())
        }
    }

    #[test]
    fn settler_lifecycle_contract() {
        let mut s = FakeSettler {
            pre_consumed: 10,
            ..Default::default()
        };
        assert!(s.needs_refund());
        assert!(s.settle(30).is_ok());
        assert!(!s.needs_refund());
        assert!(s.reserve(5).is_ok());
        assert_eq!(s.get_pre_consumed_quota(), 10); // 不高于当前不动
        assert!(s.reserve(50).is_ok());
        assert_eq!(s.get_pre_consumed_quota(), 50);
        s.refund();
        assert!(!s.needs_refund());
    }
}
