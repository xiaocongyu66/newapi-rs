//! 资金来源抽象：Go `resolve_funding_source.go` 的 WalletFunding /
//! SubscriptionFunding 移植。Rust 侧用枚举替代 Go 接口（实现固定为两个，
//! 无动态注册需求）；`pre_consume`/`settle`/`refund` 语义逐字对齐。

use super::store::{BillingStore, SubscriptionError};

/// Go `settlecore.BillingSource*` 常量。
pub const BILLING_SOURCE_WALLET: &str = "wallet";
pub const BILLING_SOURCE_SUBSCRIPTION: &str = "subscription";

/// Go `ErrInsufficientWalletQuota`：钱包原子预扣失败（余额不足），未发生
/// 任何扣减。BillingSession 据此映射为 insufficient_user_quota，使
/// wallet_first 等偏好可回退到订阅。
#[derive(Debug, Clone, PartialEq)]
pub struct InsufficientWalletQuota;

impl InsufficientWalletQuota {
    pub fn message(&self) -> &'static str {
        "wallet quota insufficient"
    }
}

/// Go `WalletFunding`。
#[derive(Debug, Clone, Default)]
pub struct WalletFunding {
    pub user_id: i64,
    /// 实际预扣的用户额度。
    pub consumed: i64,
}

/// Go `SubscriptionFunding`。
#[derive(Debug, Clone, Default)]
pub struct SubscriptionFunding {
    pub request_id: String,
    pub user_id: i64,
    pub model_name: String,
    /// 预扣的订阅额度（subConsume）；PreConsume 忽略参数固定用它。
    pub amount: i64,
    pub subscription_id: i64,
    pub pre_consumed: i64,
    /// PreConsume 成功后填充，供 RelayInfo 同步使用。
    pub amount_total: i64,
    pub amount_used_after: i64,
    pub plan_id: i64,
    pub plan_title: String,
}

/// Go `FundingSource` 接口的枚举形态。
#[derive(Debug, Clone)]
pub enum Funding {
    Wallet(WalletFunding),
    Subscription(SubscriptionFunding),
}

impl Default for Funding {
    fn default() -> Self {
        Funding::Wallet(WalletFunding::default())
    }
}

impl Funding {
    /// Go `FundingSource.Source()`。
    pub fn source(&self) -> &'static str {
        match self {
            Funding::Wallet(_) => BILLING_SOURCE_WALLET,
            Funding::Subscription(_) => BILLING_SOURCE_SUBSCRIPTION,
        }
    }

    /// Go `WalletFunding.PreConsume` / `SubscriptionFunding.PreConsume`。
    /// 订阅分支忽略 `amount` 参数，固定用内部 `amount`（Go 同款约定）。
    pub async fn pre_consume(
        &mut self,
        store: &BillingStore,
        amount: i64,
        now: i64,
    ) -> Result<(), PreConsumeFailure> {
        match self {
            Funding::Wallet(w) => {
                if amount <= 0 {
                    return Ok(());
                }
                let reserved = store
                    .try_reserve_user_quota(w.user_id, amount)
                    .await
                    .map_err(PreConsumeFailure::Store)?;
                if !reserved {
                    return Err(PreConsumeFailure::InsufficientWallet(
                        InsufficientWalletQuota,
                    ));
                }
                w.consumed = amount;
                Ok(())
            }
            Funding::Subscription(s) => {
                let res = store
                    .pre_consume_user_subscription(&s.request_id, s.user_id, s.amount, now)
                    .await
                    .map_err(PreConsumeFailure::Subscription)?;
                s.subscription_id = res.user_subscription_id;
                s.pre_consumed = res.pre_consumed;
                s.amount_total = res.amount_total;
                s.amount_used_after = res.amount_used_after;
                // 获取订阅计划信息（Go：出错静默跳过）
                if let Ok(Some(info)) = store.subscription_plan_info(s.subscription_id).await {
                    s.plan_id = info.plan_id;
                    s.plan_title = info.plan_title;
                }
                Ok(())
            }
        }
    }

    /// Go `WalletFunding.Settle` / `SubscriptionFunding.Settle`：正数补扣、
    /// 负数退还。订阅正差额走 capped 版本：订阅先吃满剩余额度，溢出部分
    /// 记钱包欠费（余额可为负）。
    pub async fn settle(
        &self,
        store: &BillingStore,
        delta: i64,
        now: i64,
    ) -> Result<(), SubscriptionError> {
        match self {
            Funding::Wallet(w) => {
                if delta == 0 {
                    return Ok(());
                }
                if delta > 0 {
                    store.decrease_user_quota(w.user_id, delta).await
                } else {
                    store.increase_user_quota(w.user_id, -delta).await
                }
            }
            Funding::Subscription(s) => {
                if delta == 0 {
                    return Ok(());
                }
                if delta < 0 {
                    return store
                        .post_consume_user_subscription_delta(s.subscription_id, delta, now)
                        .await;
                }
                let overflow = store
                    .post_consume_user_subscription_delta_capped(s.subscription_id, delta, now)
                    .await?;
                if overflow > 0 {
                    // Go SysError 日志后由调用方处置；这里直接记钱包欠费，
                    // 与 WalletFunding.Settle 的欠费语义一致。
                    store.decrease_user_quota(s.user_id, overflow).await?;
                }
                Ok(())
            }
        }
    }

    /// Go `WalletFunding.Refund` / `SubscriptionFunding.Refund`。订阅退款有
    /// requestId 幂等保护；钱包 `IncreaseUserQuota` 非幂等（不能重试）。
    pub async fn refund(&self, store: &BillingStore, now: i64) -> Result<(), SubscriptionError> {
        match self {
            Funding::Wallet(w) => {
                if w.consumed <= 0 {
                    return Ok(());
                }
                store.increase_user_quota(w.user_id, w.consumed).await
            }
            Funding::Subscription(s) => {
                if s.pre_consumed <= 0 {
                    return Ok(());
                }
                // Go refundWithRetry：3 次重试、200ms*(i+1) 退避；Rust 调用方
                // 在请求上下文内同步重试（ tokio sleep 可用）。
                let mut last_err = None;
                for attempt in 0..3u32 {
                    match store
                        .refund_subscription_pre_consume(&s.request_id, now)
                        .await
                    {
                        Ok(()) => return Ok(()),
                        Err(err) => last_err = Some(err),
                    }
                    if attempt < 2 {
                        tokio::time::sleep(std::time::Duration::from_millis(
                            200 * (attempt as u64 + 1),
                        ))
                        .await;
                    }
                }
                Err(last_err.expect("loop ran at least once"))
            }
        }
    }

    /// Go `BillingSession.needsRefundLocked` 的订阅分支：tokenConsumed=0 时
    /// 订阅仍可能预扣了额度。
    pub fn subscription_pre_consumed(&self) -> i64 {
        match self {
            Funding::Wallet(_) => 0,
            Funding::Subscription(s) => s.pre_consumed,
        }
    }
}

/// PreConsume 的失败原因（Go 用 error + 字符串匹配分流，这里显式化）。
#[derive(Debug, Clone, PartialEq)]
pub enum PreConsumeFailure {
    InsufficientWallet(InsufficientWalletQuota),
    Subscription(SubscriptionError),
    Store(SubscriptionError),
}

impl PreConsumeFailure {
    pub fn message(&self) -> String {
        match self {
            PreConsumeFailure::InsufficientWallet(e) => e.message().to_string(),
            PreConsumeFailure::Subscription(e) => e.message(),
            PreConsumeFailure::Store(e) => e.message(),
        }
    }
}
