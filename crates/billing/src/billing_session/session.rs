//! 统一计费会话：Go `open_billing_session.go`（1-458 行）与
//! `settle_billing_delta.go` 的 PreConsumeBilling / SettleBilling /
//! settlecore.PostConsumeQuotaWithResult 移植。
//!
//! 会话生命周期：preConsume（信任旁路 → 令牌预扣 → 资金来源预扣，原子回滚）
//! → Reserve（发送前补充预扣）→ Settle（按实际消耗差额结算）→ Refund
//! （失败返还预扣，幂等）。Rust 无共享可变 RelayInfo，`sync_relay_info` 的
//! 兼容字段直接挂在会话内的 [`RelayBillingInfo`] 上，relay 入口切片经
//! [`BillingSession::info`] 读取。

use serde_json::{Map, Value};

use super::funding::{
    BILLING_SOURCE_SUBSCRIPTION, BILLING_SOURCE_WALLET, Funding, InsufficientWalletQuota,
    PreConsumeFailure, SubscriptionFunding, WalletFunding,
};
use super::quota_math::QuotaClamp;
use super::store::{BillingStore, SubscriptionError};

/// Go `types.NewAPIError` 的计费面：错误码、HTTP 状态码与重试控制。
#[derive(Debug, Clone, PartialEq)]
pub struct BillingApiError {
    pub code: &'static str,
    pub status: u16,
    pub message: String,
    pub skip_retry: bool,
    pub no_record_error_log: bool,
}

impl BillingApiError {
    fn new(code: &'static str, status: u16, message: impl Into<String>) -> Self {
        Self {
            code,
            status,
            message: message.into(),
            skip_retry: true,
            no_record_error_log: false,
        }
    }

    fn with_no_record(mut self) -> Self {
        self.no_record_error_log = true;
        self
    }
}

// Go `types.ErrorCode*` 计费相关码。
pub const ERROR_CODE_INVALID_REQUEST: &str = "invalid_request";
pub const ERROR_CODE_MODEL_PRICE_ERROR: &str = "model_price_error";
pub const ERROR_CODE_QUERY_DATA_ERROR: &str = "query_data_error";
pub const ERROR_CODE_UPDATE_DATA_ERROR: &str = "update_data_error";
pub const ERROR_CODE_INSUFFICIENT_USER_QUOTA: &str = "insufficient_user_quota";
pub const ERROR_CODE_PRE_CONSUME_TOKEN_QUOTA_FAILED: &str = "pre_consume_token_quota_failed";

/// Go `NormalizeBillingPreference`（common/billing.go）：未识别值回
/// subscription_first 语义（工厂 default 分支）。
pub fn normalize_billing_preference(raw: &str) -> &str {
    let v = raw.trim();
    match v {
        "subscription_only" | "wallet_only" | "wallet_first" | "subscription_first" => v,
        _ => "",
    }
}

/// RelayInfo 中计费会话读写的字段投影。relay 入口切片负责从真实 RelayInfo
/// 构造/回填（接口约定见交付报告）。
#[derive(Debug, Clone, Default)]
pub struct RelayBillingInfo {
    pub user_id: i64,
    pub token_id: i64,
    pub token_key: String,
    pub is_playground: bool,
    /// 异步任务必须预扣全额，不允许信任旁路。
    pub force_pre_consume: bool,
    pub token_unlimited: bool,
    /// Go `c.GetInt("token_quota")`。
    pub token_quota: i64,
    /// 钱包路径由工厂回填（Go `relayInfo.UserQuota = userQuota`）。
    pub user_quota: i64,
    /// Go `relayInfo.UserSetting.BillingPreference`。
    pub billing_preference: String,
    pub request_id: String,
    pub origin_model_name: String,
    pub using_group: String,
    pub user_group: String,
    /// Go `relayInfo.ChannelMeta.ChannelId`。
    pub channel_id: i64,
    /// Go `ctx.GetString("token_name")` 与日志画像：调用方显式传入。
    pub token_name: String,
    pub username: String,
    pub is_stream: bool,
    /// Go `relayInfo.PriceData.GroupRatioInfo.GroupRatio`（违规费计算读取）。
    pub group_ratio: f64,
    // ---- 会话同步的兼容字段（Go syncRelayInfo）----
    pub billing_source: &'static str,
    pub final_pre_consumed_quota: i64,
    pub subscription_id: i64,
    pub subscription_pre_consumed: i64,
    pub subscription_post_delta: i64,
    pub subscription_amount_total: i64,
    pub subscription_amount_used_after_pre_consume: i64,
    pub subscription_plan_id: i64,
    pub subscription_plan_title: String,
    /// 请求期间首次额度饱和事件（noteQuotaClamp，首个非空胜出）。
    pub quota_clamp: Option<QuotaClamp>,
    /// 实时（WSS）增量已直扣的累计额度，结算时扣除。
    pub realtime_charged_quota: i64,
}

/// Go `BillingSession`。
pub struct BillingSession<'a> {
    store: &'a BillingStore,
    pub info: RelayBillingInfo,
    funding: Funding,
    /// 实际预扣额度（信任用户可能为 0）。
    pre_consumed_quota: i64,
    /// 令牌额度实际扣减量。
    token_consumed: i64,
    /// 发送前补充预扣的额度（订阅退款时需要单独回滚）。
    extra_reserved: i64,
    trusted: bool,
    /// funding.Settle 已成功，资金来源已提交。
    funding_settled: bool,
    /// Settle 全部完成（资金 + 令牌）。
    settled: bool,
    refunded: bool,
}

impl<'a> BillingSession<'a> {
    /// Go `BillingSession.Settle`：资金来源与令牌额度分两步提交；若资金来源
    /// 已提交但令牌调整失败，标记 fundingSettled 防止 Refund 误退资金。
    pub async fn settle(&mut self, actual_quota: i64) -> Result<(), BillingApiError> {
        if self.settled {
            return Ok(());
        }
        let delta = actual_quota - self.pre_consumed_quota;
        if delta == 0 {
            self.settled = true;
            return Ok(());
        }
        // 1) 调整资金来源（仅在尚未提交时执行，防止重复调用）
        if !self.funding_settled {
            self.funding
                .settle(self.store, delta, unix_now())
                .await
                .map_err(|e| {
                    BillingApiError::new(ERROR_CODE_UPDATE_DATA_ERROR, 500, e.message())
                })?;
            self.funding_settled = true;
        }
        // 2) 调整令牌额度
        let mut token_err = None;
        if !self.info.is_playground {
            let result = if delta > 0 {
                self.store
                    .decrease_token_quota(self.info.token_id, delta, unix_now())
                    .await
            } else {
                self.store
                    .increase_token_quota(self.info.token_id, -delta, unix_now())
                    .await
            };
            if let Err(err) = result {
                // 资金来源已提交，令牌调整失败只能记录日志；标记 settled
                // 防止 Refund 误退资金
                token_err = Some(err.to_string());
            }
        }
        // 3) 更新订阅 PostDelta（用于日志）
        if self.funding.source() == BILLING_SOURCE_SUBSCRIPTION {
            self.info.subscription_post_delta += delta;
        }
        self.settled = true;
        match token_err {
            Some(msg) => Err(BillingApiError::new(
                ERROR_CODE_UPDATE_DATA_ERROR,
                500,
                format!("error adjusting token quota after funding settled: {msg}"),
            )),
            None => Ok(()),
        }
    }

    /// Go `SettleBilling`（settle_billing_delta.go:44-79）的会话分支：
    /// 按实际消耗与预扣差额结算；额度通知（checkAndSendQuotaNotify /
    /// checkAndSendSubscriptionQuotaNotify）依赖 mailer 切片，未随本切片移植。
    pub async fn settle_billing(&mut self, actual_quota: i64) -> Result<(), BillingApiError> {
        let pre_consumed = self.pre_consumed_quota;
        let delta = actual_quota - pre_consumed;
        if delta > 0 {
            tracing::info!(
                "预扣费后补扣费：{}（实际消耗：{}，预扣费：{}）",
                format_quota(delta),
                format_quota(actual_quota),
                format_quota(pre_consumed)
            );
        } else if delta < 0 {
            tracing::info!(
                "预扣费后返还扣费：{}（实际消耗：{}，预扣费：{}）",
                format_quota(-delta),
                format_quota(actual_quota),
                format_quota(pre_consumed)
            );
        } else {
            tracing::info!(
                "预扣费与实际消耗一致，无需调整：{}（按次计费）",
                format_quota(actual_quota)
            );
        }
        self.settle(actual_quota).await
    }

    /// Go `BillingSession.Refund`：退还所有预扣费，幂等安全。Go 经 gopool
    /// 异步执行；Rust 为 async fn，由调用方决定是否 spawn。
    pub async fn refund(&mut self) {
        if self.settled || self.refunded || !self.needs_refund() {
            return;
        }
        self.refunded = true;

        let is_playground = self.info.is_playground;
        let token_consumed = self.token_consumed;
        let extra_reserved = self.extra_reserved;
        let subscription_id = self.info.subscription_id;

        // 1) 退还资金来源
        if let Err(err) = self.funding.refund(self.store, unix_now()).await {
            tracing::error!("error refunding billing source: {}", err.message());
        }
        if extra_reserved > 0
            && self.funding.source() == BILLING_SOURCE_SUBSCRIPTION
            && subscription_id > 0
        {
            if let Err(err) = self
                .store
                .post_consume_user_subscription_delta(subscription_id, -extra_reserved, unix_now())
                .await
            {
                tracing::error!(
                    "error refunding subscription extra reserved quota: {}",
                    err.message()
                );
            }
        }
        // 2) 退还令牌额度
        if token_consumed > 0 && !is_playground {
            if let Err(err) = self
                .store
                .increase_token_quota(self.info.token_id, token_consumed, unix_now())
                .await
            {
                tracing::error!("error refunding token quota: {err}");
            }
        }
    }

    /// Go `NeedsRefund`：是否存在需要退还的预扣状态。fundingSettled 时资金
    /// 来源已提交结算，不能再退预扣费。
    pub fn needs_refund(&self) -> bool {
        if self.settled || self.refunded || self.funding_settled {
            return false;
        }
        if self.token_consumed > 0 {
            return true;
        }
        self.funding.subscription_pre_consumed() > 0
    }

    /// Go `GetPreConsumedQuota`。
    pub fn get_pre_consumed_quota(&self) -> i64 {
        self.pre_consumed_quota
    }

    pub fn funding_source(&self) -> &'static str {
        self.funding.source()
    }

    /// Go `BillingSession.Reserve`：发送前补充预扣（先资金来源后令牌，
    /// 令牌失败回滚资金来源）。
    pub async fn reserve(&mut self, target_quota: i64) -> Result<(), BillingApiError> {
        if self.settled || self.refunded || self.trusted || target_quota <= self.pre_consumed_quota
        {
            return Ok(());
        }
        let delta = target_quota - self.pre_consumed_quota;
        if delta <= 0 {
            return Ok(());
        }
        self.reserve_funding(delta).await?;
        if let Err(err) = self.reserve_token(delta).await {
            self.rollback_funding_reserve(delta).await;
            return Err(err);
        }
        self.pre_consumed_quota += delta;
        self.token_consumed += delta;
        self.extra_reserved += delta;
        self.sync_relay_info();
        Ok(())
    }

    /// Go `preConsume`：信任检查 → 令牌预扣 → 资金来源预扣，任一步失败
    /// 原子回滚已完成的步骤。
    async fn pre_consume(&mut self, quota: i64) -> Result<(), BillingApiError> {
        let mut effective_quota = quota;
        if self.should_trust() {
            self.trusted = true;
            effective_quota = 0;
        }
        // 1) 预扣令牌额度
        if effective_quota > 0 {
            if let Err(err) = pre_consume_token_quota(self.store, &self.info, effective_quota).await
            {
                return Err(BillingApiError::new(
                    ERROR_CODE_PRE_CONSUME_TOKEN_QUOTA_FAILED,
                    403,
                    err,
                )
                .with_no_record());
            }
            self.token_consumed = effective_quota;
        }
        // 2) 预扣资金来源
        if let Err(err) = self
            .funding
            .pre_consume(self.store, effective_quota, unix_now())
            .await
        {
            // 预扣费失败，回滚令牌额度
            if self.token_consumed > 0 && !self.info.is_playground {
                if let Err(rollback_err) = self
                    .store
                    .increase_token_quota(self.info.token_id, self.token_consumed, unix_now())
                    .await
                {
                    tracing::error!(
                        "error rolling back token quota (userId={}, tokenId={}, amount={}, fundingErr={}): {rollback_err}",
                        self.info.user_id,
                        self.info.token_id,
                        self.token_consumed,
                        err.message()
                    );
                }
                self.token_consumed = 0;
            }
            return Err(match err {
                PreConsumeFailure::InsufficientWallet(_) => {
                    let user_quota = self
                        .store
                        .get_user_quota(self.info.user_id)
                        .await
                        .unwrap_or(0);
                    BillingApiError::new(
                        ERROR_CODE_INSUFFICIENT_USER_QUOTA,
                        403,
                        format!("用户额度不足, 剩余额度: {}", format_quota(user_quota)),
                    )
                    .with_no_record()
                }
                PreConsumeFailure::Subscription(sub_err) => {
                    let msg = sub_err.message();
                    if msg.contains("no active subscription")
                        || msg.contains("subscription quota insufficient")
                    {
                        BillingApiError::new(
                            ERROR_CODE_INSUFFICIENT_USER_QUOTA,
                            403,
                            format!("订阅额度不足或未配置订阅: {msg}"),
                        )
                        .with_no_record()
                    } else {
                        BillingApiError::new(ERROR_CODE_UPDATE_DATA_ERROR, 500, msg)
                    }
                }
                PreConsumeFailure::Store(store_err) => {
                    BillingApiError::new(ERROR_CODE_UPDATE_DATA_ERROR, 500, store_err.message())
                }
            });
        }
        self.pre_consumed_quota = effective_quota;
        self.sync_relay_info();
        Ok(())
    }

    /// Go `reserveFunding`：钱包全额无条件扣减（余额不足部分记欠费，与
    /// 结算补扣语义一致）；订阅走严格增量。
    async fn reserve_funding(&mut self, delta: i64) -> Result<(), BillingApiError> {
        match &mut self.funding {
            Funding::Wallet(w) => {
                self.store
                    .decrease_user_quota(w.user_id, delta)
                    .await
                    .map_err(|e| {
                        BillingApiError::new(ERROR_CODE_UPDATE_DATA_ERROR, 500, e.to_string())
                    })?;
                w.consumed += delta;
                Ok(())
            }
            Funding::Subscription(s) => self
                .store
                .post_consume_user_subscription_delta(s.subscription_id, delta, unix_now())
                .await
                .map_err(|e| {
                    BillingApiError::new(
                        ERROR_CODE_INSUFFICIENT_USER_QUOTA,
                        403,
                        format!("订阅额度不足或未配置订阅: {}", e.message()),
                    )
                    .with_no_record()
                }),
        }
    }

    /// Go `rollbackFundingReserve`。
    async fn rollback_funding_reserve(&mut self, delta: i64) {
        match &self.funding {
            Funding::Wallet(w) => {
                if let Err(err) = self.store.increase_user_quota(w.user_id, delta).await {
                    tracing::error!("error rolling back wallet funding reserve: {err}");
                }
            }
            Funding::Subscription(s) => {
                if let Err(err) = self
                    .store
                    .post_consume_user_subscription_delta(s.subscription_id, -delta, unix_now())
                    .await
                {
                    tracing::error!(
                        "error rolling back subscription funding reserve: {}",
                        err.message()
                    );
                }
            }
        }
        // Go WalletFunding.consumed -= delta 的记账在 reserveFunding 失败路径
        // 不回退（与 Go 一致：rollback 仅用于令牌失败后整次 reserve 放弃）。
    }

    /// Go `reserveToken`。
    async fn reserve_token(&mut self, delta: i64) -> Result<(), BillingApiError> {
        if delta <= 0 || self.info.is_playground {
            return Ok(());
        }
        pre_consume_token_quota(self.store, &self.info, delta)
            .await
            .map_err(|err| {
                BillingApiError::new(ERROR_CODE_PRE_CONSUME_TOKEN_QUOTA_FAILED, 403, err)
                    .with_no_record()
            })
    }

    /// Go `shouldTrust`：统一信任额度检查，适用于钱包和订阅。订阅不能启用
    /// 信任旁路（预扣一致性约束，见 Go 注释）。
    fn should_trust(&self) -> bool {
        if self.info.force_pre_consume {
            return false;
        }
        let trust_quota = super::quota_math::TRUST_QUOTA;
        if trust_quota <= 0 {
            return false;
        }
        let mut token_trusted = self.info.token_unlimited;
        if !token_trusted {
            token_trusted = self.info.token_quota > trust_quota;
        }
        if !token_trusted {
            return false;
        }
        match self.funding.source() {
            BILLING_SOURCE_WALLET => self.info.user_quota > trust_quota,
            _ => false,
        }
    }

    /// Go `syncRelayInfo`：把会话状态同步到 RelayBillingInfo 的兼容字段上。
    fn sync_relay_info(&mut self) {
        self.info.final_pre_consumed_quota = self.pre_consumed_quota;
        self.info.billing_source = self.funding.source();
        if let Funding::Subscription(sub) = &self.funding {
            self.info.subscription_id = sub.subscription_id;
            self.info.subscription_pre_consumed = sub.pre_consumed + self.extra_reserved;
            self.info.subscription_post_delta = 0;
            self.info.subscription_amount_total = sub.amount_total;
            self.info.subscription_amount_used_after_pre_consume =
                sub.amount_used_after + self.extra_reserved;
            self.info.subscription_plan_id = sub.plan_id;
            self.info.subscription_plan_title = sub.plan_title.clone();
        } else {
            self.info.subscription_id = 0;
            self.info.subscription_pre_consumed = 0;
        }
    }
}

/// Go `PreConsumeTokenQuota`（consume_quota_realtime.go:409-429）：
/// 原子预扣令牌额度（检查与扣减同一操作）。
pub async fn pre_consume_token_quota(
    store: &BillingStore,
    info: &RelayBillingInfo,
    quota: i64,
) -> Result<(), String> {
    if quota < 0 {
        return Err("quota 不能为负数！".into());
    }
    if info.is_playground {
        return Ok(());
    }
    let reserved = store
        .try_reserve_token_quota(info.token_id, quota, info.token_unlimited, unix_now())
        .await
        .map_err(|e| e.message())?;
    if !reserved {
        let mut remain_quota = 0;
        if let Ok(Some(token)) = store.get_token_by_key(&info.token_key).await {
            remain_quota = token.remain_quota;
        }
        return Err(format!(
            "token quota is not enough, token remain quota: {}, need quota: {}",
            format_quota(remain_quota),
            format_quota(quota)
        ));
    }
    Ok(())
}

/// 额度展示：Go `logger.FormatQuota` 的数值面（quota / QuotaPerUnit，两位小数
/// 去尾零由展示层处理；会话错误消息里沿用 Go 的裸数值格式）。
pub fn format_quota(quota: i64) -> String {
    let value = quota as f64 / super::quota_math::QUOTA_PER_UNIT;
    if value == value.trunc() {
        format!("{}", value as i64)
    } else {
        format!("{value}")
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Go `NewBillingSession`：根据用户计费偏好创建会话，处理
/// subscription_first / wallet_first 回退。会话内部持有 [`RelayBillingInfo`]
/// 的同步副本；成功后调用方经 `session.info` 读取最新字段。
pub async fn new_billing_session<'a>(
    store: &'a BillingStore,
    info: RelayBillingInfo,
    pre_consumed_quota: i64,
) -> Result<BillingSession<'a>, BillingApiError> {
    let pref = normalize_billing_preference(&info.billing_preference).to_string();

    match pref.as_str() {
        "subscription_only" => try_subscription(store, info, pre_consumed_quota).await,
        "wallet_only" => try_wallet(store, info, pre_consumed_quota).await,
        "wallet_first" => match try_wallet(store, info.clone(), pre_consumed_quota).await {
            Err(err) if err.code == ERROR_CODE_INSUFFICIENT_USER_QUOTA => {
                try_subscription(store, info, pre_consumed_quota).await
            }
            other => other,
        },
        // subscription_first 与 default
        _ => {
            let has_sub = store
                .has_active_user_subscription(info.user_id, unix_now())
                .await
                .map_err(|e| BillingApiError::new(ERROR_CODE_QUERY_DATA_ERROR, 500, e.message()))?;
            if !has_sub {
                return try_wallet(store, info, pre_consumed_quota).await;
            }
            match try_subscription(store, info.clone(), pre_consumed_quota).await {
                Err(err) if err.code == ERROR_CODE_INSUFFICIENT_USER_QUOTA => {
                    // 仅当用户的活跃订阅允许钱包回退时才回退到钱包，否则
                    // 返回订阅额度不足错误
                    let allow_overflow = store
                        .active_subscriptions_allow_wallet_overflow(info.user_id, unix_now())
                        .await
                        .map_err(|e| {
                            BillingApiError::new(ERROR_CODE_QUERY_DATA_ERROR, 500, e.message())
                        })?;
                    if allow_overflow {
                        return try_wallet(store, info, pre_consumed_quota).await;
                    }
                    Err(err)
                }
                other => other,
            }
        }
    }
}

/// Go `tryWallet` 闭包：钱包路径需要先检查用户额度。
async fn try_wallet<'a>(
    store: &'a BillingStore,
    mut info: RelayBillingInfo,
    pre_consumed_quota: i64,
) -> Result<BillingSession<'a>, BillingApiError> {
    let user_quota = store
        .get_user_quota(info.user_id)
        .await
        .map_err(|e| BillingApiError::new(ERROR_CODE_QUERY_DATA_ERROR, 500, e.to_string()))?;
    if user_quota <= 0 {
        return Err(BillingApiError::new(
            ERROR_CODE_INSUFFICIENT_USER_QUOTA,
            403,
            format!("用户额度不足, 剩余额度: {}", format_quota(user_quota)),
        )
        .with_no_record());
    }
    if user_quota - pre_consumed_quota < 0 {
        return Err(BillingApiError::new(
            ERROR_CODE_INSUFFICIENT_USER_QUOTA,
            403,
            format!(
                "预扣费额度失败, 用户剩余额度: {}, 需要预扣费额度: {}",
                format_quota(user_quota),
                format_quota(pre_consumed_quota)
            ),
        )
        .with_no_record());
    }
    info.user_quota = user_quota;
    let mut session = BillingSession {
        store,
        info: info.clone(),
        funding: Funding::Wallet(WalletFunding {
            user_id: info.user_id,
            consumed: 0,
        }),
        pre_consumed_quota: 0,
        token_consumed: 0,
        extra_reserved: 0,
        trusted: false,
        funding_settled: false,
        settled: false,
        refunded: false,
    };
    session.funding = Funding::Wallet(WalletFunding {
        user_id: info.user_id,
        consumed: 0,
    });
    session.pre_consume(pre_consumed_quota).await?;
    Ok(session)
}

/// Go `trySubscription` 闭包。
async fn try_subscription<'a>(
    store: &'a BillingStore,
    info: RelayBillingInfo,
    pre_consumed_quota: i64,
) -> Result<BillingSession<'a>, BillingApiError> {
    // 必须传 subConsume 而非 preConsumedQuota，保证 SubscriptionFunding
    // amount、preConsume 参数和 FinalPreConsumedQuota 三者一致，
    // 避免订阅多扣费。
    let mut sub_consume = pre_consumed_quota;
    if sub_consume <= 0 {
        sub_consume = 1;
    }
    let mut session = BillingSession {
        store,
        funding: Funding::Subscription(SubscriptionFunding {
            request_id: info.request_id.clone(),
            user_id: info.user_id,
            model_name: info.origin_model_name.clone(),
            amount: sub_consume,
            ..Default::default()
        }),
        info,
        pre_consumed_quota: 0,
        token_consumed: 0,
        extra_reserved: 0,
        trusted: false,
        funding_settled: false,
        settled: false,
        refunded: false,
    };
    session.pre_consume(sub_consume).await?;
    Ok(session)
}

/// Go `PreConsumeBilling`（settle_billing_delta.go:15-36）：入口校验 +
/// 创建会话。Rust 侧会话由调用方持有（无 RelayInfo.Billing 挂载点）。
pub async fn pre_consume_billing<'a>(
    store: &'a BillingStore,
    mut info: RelayBillingInfo,
    pre_consumed_quota: i64,
) -> Result<BillingSession<'a>, BillingApiError> {
    if let Some(clamp) = &info.quota_clamp {
        return Err(BillingApiError::new(
            ERROR_CODE_MODEL_PRICE_ERROR,
            400,
            clamp_error_message(clamp),
        ));
    }
    if pre_consumed_quota < 0 {
        return Err(BillingApiError::new(
            ERROR_CODE_MODEL_PRICE_ERROR,
            400,
            format!("pre-consume quota cannot be negative: {pre_consumed_quota}"),
        ));
    }
    new_billing_session(store, info, pre_consumed_quota).await
}

/// Go `(*QuotaClamp).Error()`。
pub fn clamp_error_message(clamp: &QuotaClamp) -> String {
    format!(
        "quota conversion ({}) {}: original={}, clamped={}",
        clamp.op,
        clamp.kind.as_str(),
        clamp.original,
        clamp.clamped
    )
}

/// Go `settlecore.PostConsumeQuotaWithResult`。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PostConsumeQuotaResult {
    pub funding_applied: bool,
    pub token_applied: bool,
}

pub async fn post_consume_quota_with_result(
    store: &BillingStore,
    info: &mut RelayBillingInfo,
    quota: i64,
    _pre_consumed_quota: i64,
) -> Result<PostConsumeQuotaResult, SubscriptionError> {
    post_consume_quota_with_result_inner(store, info, quota, _pre_consumed_quota).await
}

/// 邮件低额提醒（Go checkAndSendQuotaNotify）依赖 mailer 切片，此处仅返回
/// 结果并保留 `pre_consumed_quota` 参数位置（Go sendEmail 分支的调用方语义）。
pub async fn post_consume_quota(
    store: &BillingStore,
    info: &mut RelayBillingInfo,
    quota: i64,
    pre_consumed_quota: i64,
) -> Result<(), SubscriptionError> {
    post_consume_quota_with_result(store, info, quota, pre_consumed_quota)
        .await
        .map(|_| ())
}

async fn post_consume_quota_with_result_inner(
    store: &BillingStore,
    info: &mut RelayBillingInfo,
    quota: i64,
    _pre_consumed_quota: i64,
) -> Result<PostConsumeQuotaResult, SubscriptionError> {
    let mut result = PostConsumeQuotaResult::default();
    // 1) Consume from wallet quota OR subscription item
    if info.billing_source == BILLING_SOURCE_SUBSCRIPTION {
        if info.subscription_id == 0 {
            return Err(SubscriptionError::Db("subscription id is missing".into()));
        }
        let delta = quota;
        if delta != 0 {
            store
                .post_consume_user_subscription_delta(info.subscription_id, delta, unix_now())
                .await?;
            info.subscription_post_delta += delta;
        }
    } else if quota > 0 {
        store.decrease_user_quota(info.user_id, quota).await?;
    } else {
        store.increase_user_quota(info.user_id, -quota).await?;
    }
    result.funding_applied = true;

    if !info.is_playground {
        if quota > 0 {
            store
                .decrease_token_quota(info.token_id, quota, unix_now())
                .await?;
        } else {
            store
                .increase_token_quota(info.token_id, -quota, unix_now())
                .await?;
        }
        result.token_applied = true;
    }
    Ok(result)
}

/// Go `SettleBilling`（settle_billing_delta.go:80-90）无会话回退分支：
/// 按 FinalPreConsumedQuota 差额走旧 PostConsumeQuota 路径（按次计费兼容）。
/// 会话结算走 [`BillingSession::settle_billing`]。
pub async fn settle_billing(
    store: &BillingStore,
    info: &mut RelayBillingInfo,
    actual_quota: i64,
) -> Result<(), BillingApiError> {
    let quota_delta = actual_quota - info.final_pre_consumed_quota;
    if quota_delta != 0 {
        post_consume_quota(store, info, quota_delta, info.final_pre_consumed_quota)
            .await
            .map_err(|e| BillingApiError::new(ERROR_CODE_UPDATE_DATA_ERROR, 500, e.message()))?;
    }
    Ok(())
}

/// `other` map 构造帮助（日志写侧接口约定：调用方传入基础 map）。
pub fn empty_other() -> Map<String, Value> {
    Map::new()
}

/// Go `InsufficientWalletQuota` 消息（供外部分流）。
pub fn insufficient_wallet_message() -> &'static str {
    InsufficientWalletQuota.message()
}
