//! 实时（WSS/audio）扣费：Go `consume_quota_realtime.go` 的
//! calculateAudioQuota / PreWssConsumeQuota / PostWssConsumeQuota /
//! PostAudioConsumeQuota 移植。
//!
//! F6 不变量（consume_quota_realtime_settle_test.go）：response.done 逐次
//! 增量由 PreWssConsumeQuota 直扣并记入 `realtime_charged_quota`；最终
//! PostWssConsumeQuota 对累计用量结算时扣除这部分，整段会话恰好支付一次。

use super::pricing::{PriceData, RatioSettings};
use super::quota_math::{QUOTA_PER_UNIT, QuotaClamp, quota_from_decimal_checked};
use super::session::{RelayBillingInfo, post_consume_quota_with_result};
use super::store::{BillingStore, SubscriptionError};
use super::text_quota::{log_quota, note_quota_clamp};
use super::usage::RealtimeUsage;

/// Go `TokenDetails`（consume_quota_realtime.go:30-33）。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TokenDetails {
    pub text_tokens: i64,
    pub audio_tokens: i64,
}

/// Go `QuotaInfo`（consume_quota_realtime.go:35-43）。
#[derive(Debug, Clone, Default)]
pub struct QuotaInfo {
    pub input_details: TokenDetails,
    pub output_details: TokenDetails,
    pub model_name: String,
    pub use_price: bool,
    pub model_price: f64,
    pub model_ratio: f64,
    pub group_ratio: f64,
}

/// Go `calculateAudioQuota`（consume_quota_realtime.go:53-90）。
/// UsePrice 时按次计费（modelPrice * QuotaPerUnit * groupRatio）；否则
/// text_in + text_out*completion + audio_in*audioRatio
/// + audio_out*audioRatio*audioCompletion，整体乘 (groupRatio*modelRatio)；
/// ratio 非零且结果 ≤0 时取最小计费单位 1。
pub fn calculate_audio_quota(
    settings: &dyn RatioSettings,
    info: &QuotaInfo,
) -> (i64, Option<QuotaClamp>) {
    if info.use_price {
        let quota = info.model_price * QUOTA_PER_UNIT * info.group_ratio;
        return quota_from_decimal_checked(quota);
    }

    let completion_ratio = settings.completion_ratio(&info.model_name);
    let audio_ratio = settings.audio_ratio(&info.model_name);
    let audio_completion_ratio = settings.audio_completion_ratio(&info.model_name);
    let group_ratio = info.group_ratio;
    let model_ratio = info.model_ratio;
    let ratio = group_ratio * model_ratio;

    let mut quota = 0.0f64;
    quota += info.input_details.text_tokens as f64;
    quota += info.output_details.text_tokens as f64 * completion_ratio;
    quota += info.input_details.audio_tokens as f64 * audio_ratio;
    quota += info.output_details.audio_tokens as f64 * audio_ratio * audio_completion_ratio;
    quota *= ratio;

    // ratio 非零且额度 ≤0 时取 1（最小计费单位）
    if ratio != 0.0 && quota <= 0.0 {
        quota = 1.0;
    }
    quota_from_decimal_checked(quota)
}

/// Go `PreWssConsumeQuota`（consume_quota_realtime.go:92-169）的输入。
#[derive(Debug, Clone, Default)]
pub struct WssCallContext {
    /// Go `ctx.GetString("token_name")`（PostWSS 用）。
    pub token_name: String,
    /// Go ContextKeyAutoGroup：自动分组最终组（存在则覆盖 UsingGroup）。
    pub auto_group: Option<String>,
}

/// Go `PreWssConsumeQuota`：会话中途增量预校验 + 直扣。
/// `info.realtime_charged_quota` 累加本笔，供最终结算扣除。
pub async fn pre_wss_consume_quota(
    store: &BillingStore,
    settings: &dyn RatioSettings,
    info: &mut RelayBillingInfo,
    price_data: &PriceData,
    usage: &RealtimeUsage,
    call: &WssCallContext,
) -> Result<(), String> {
    if price_data.use_price {
        return Ok(());
    }
    // 订阅资金来源不占钱包额度；按钱包预校验会把订阅余额充足、
    // 钱包为 0 的用户在会话中途误拒。
    let from_subscription = info.billing_source == "subscription";
    let mut user_quota = 0i64;
    if !from_subscription {
        user_quota = store
            .get_user_quota(info.user_id)
            .await
            .map_err(|e| e.message())?;
    }

    let token_key = info
        .token_key
        .strip_prefix("sk-")
        .unwrap_or(&info.token_key)
        .to_string();
    let token = store
        .get_token_by_key(&token_key)
        .await
        .map_err(|e| e.message())?
        .ok_or_else(|| "token not found".to_string())?;

    let model_name = info.origin_model_name.clone();
    let mut group_ratio = settings.group_ratio(&info.using_group);
    let (model_ratio, _) = settings.model_ratio(&model_name);

    if let Some(auto_group) = &call.auto_group {
        group_ratio = settings.group_ratio(auto_group);
        info.using_group = auto_group.clone();
    }

    let mut actual_group_ratio = group_ratio;
    if let Some(user_group_ratio) = settings.group_group_ratio(&info.user_group, &info.using_group)
    {
        actual_group_ratio = user_group_ratio;
    }

    let quota_info = QuotaInfo {
        input_details: TokenDetails {
            text_tokens: usage.input_token_details.text_tokens,
            audio_tokens: usage.input_token_details.audio_tokens,
        },
        output_details: TokenDetails {
            text_tokens: usage.output_token_details.text_tokens,
            audio_tokens: usage.output_token_details.audio_tokens,
        },
        model_name: model_name.clone(),
        use_price: price_data.use_price,
        model_price: price_data.model_price,
        model_ratio,
        group_ratio: actual_group_ratio,
    };

    let (quota, clamp) = calculate_audio_quota(settings, &quota_info);
    note_quota_clamp(info, clamp);

    if !from_subscription && user_quota < quota {
        return Err(format!(
            "user quota is not enough, user quota: {}, need quota: {}",
            log_quota(user_quota),
            log_quota(quota)
        ));
    }

    if !token.unlimited_quota && token.remain_quota < quota {
        return Err(format!(
            "token quota is not enough, token remain quota: {}, need quota: {}",
            log_quota(token.remain_quota),
            log_quota(quota)
        ));
    }

    let result = post_consume_quota_with_result(store, info, quota, 0)
        .await
        .map_err(|e| e.message())?;
    let _ = result;
    // 记账：这笔增量已从资金来源直扣。最终 PostWssConsumeQuota 对累计
    // 用量结算时必须扣除这部分，否则同一 token 量被扣两次。
    info.realtime_charged_quota += quota;
    Ok(())
}

/// Go `PostWssConsumeQuota` / `PostAudioConsumeQuota` 共享的结算语义：
/// 计算配额（可选分层覆盖）、零 token 记日志不扣费、SettleBilling、
/// RecordConsumeLog。返回 summary 供日志写侧组装（other map 由调用方按
/// GenerateWssOtherInfo/GenerateAudioOtherInfo 扩展——usage 域未移植）。
pub struct RealtimeSettleOutcome {
    pub quota: i64,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub use_time_seconds: i64,
    pub log_content: String,
    pub model_name: String,
    pub zero_usage: bool,
}

/// Go `PostWssConsumeQuota`（consume_quota_realtime.go:171-275）核心：
/// 返回结算结果；分层覆盖经 `tiered_quota` 注入（Go TryTieredSettle 的
/// relay 侧形态）。
#[allow(clippy::too_many_arguments)]
pub async fn post_wss_consume_quota(
    store: &BillingStore,
    settings: &dyn RatioSettings,
    info: &mut RelayBillingInfo,
    price_data: &PriceData,
    model_name: &str,
    usage: &RealtimeUsage,
    extra_content: &str,
    tiered_quota: Option<i64>,
    now: i64,
    start_time: i64,
) -> Result<RealtimeSettleOutcome, SubscriptionError> {
    let use_time_seconds = now - start_time;
    let quota_info = QuotaInfo {
        input_details: TokenDetails {
            text_tokens: usage.input_token_details.text_tokens,
            audio_tokens: usage.input_token_details.audio_tokens,
        },
        output_details: TokenDetails {
            text_tokens: usage.output_token_details.text_tokens,
            audio_tokens: usage.output_token_details.audio_tokens,
        },
        model_name: model_name.to_string(),
        use_price: price_data.use_price,
        model_price: price_data.model_price,
        model_ratio: price_data.model_ratio,
        group_ratio: price_data.group_ratio(),
    };

    let (mut quota, clamp) = calculate_audio_quota(settings, &quota_info);
    note_quota_clamp(info, clamp);
    if let Some(tiered) = tiered_quota {
        quota = tiered;
    }

    let total_tokens = usage.total_tokens;
    let mut log_content = if !price_data.use_price {
        format!(
            "模型倍率 {:.2}，补全倍率 {:.2}，音频倍率 {:.2}，音频补全倍率 {:.2}，分组倍率 {:.2}",
            price_data.model_ratio,
            settings.completion_ratio(model_name),
            settings.audio_ratio(&info.origin_model_name),
            settings.audio_completion_ratio(model_name),
            price_data.group_ratio()
        )
    } else {
        format!(
            "模型价格 {:.2}，分组倍率 {:.2}",
            price_data.model_price,
            price_data.group_ratio()
        )
    };

    let mut zero_usage = false;
    if total_tokens == 0 {
        // 这里必然发生了错误；不能直接返回，可能需要退还预扣费
        quota = 0;
        log_content += "（可能是上游超时）";
        zero_usage = true;
    } else {
        store
            .update_user_used_quota_and_request_count(info.user_id, quota)
            .await?;
        store
            .update_channel_used_quota(channel_id_of(info), quota)
            .await?;
    }

    // 累计用量中，response.done 逐次增量已由 PreWssConsumeQuota 直扣；
    // 结算只补差额。负值表示分层定价等事后更便宜，退回多扣部分。
    let settle_quota = quota - info.realtime_charged_quota;
    super::session::settle_billing(store, info, settle_quota)
        .await
        .map_err(|e| SubscriptionError::Db(e.message))?;

    if !extra_content.is_empty() {
        log_content += ", ";
        log_content += extra_content;
    }
    Ok(RealtimeSettleOutcome {
        quota,
        prompt_tokens: usage.input_tokens,
        completion_tokens: usage.output_tokens,
        use_time_seconds,
        log_content,
        model_name: model_name.to_string(),
        zero_usage,
    })
}

/// Go `PostAudioConsumeQuota`（consume_quota_realtime.go:298-407）核心：
/// 与 WSS 同构但 usage 走 dto.Usage 的 details，且无 realtime_charged 差额。
#[allow(clippy::too_many_arguments)]
pub async fn post_audio_consume_quota(
    store: &BillingStore,
    settings: &dyn RatioSettings,
    info: &mut RelayBillingInfo,
    price_data: &PriceData,
    usage: &super::usage::Usage,
    extra_content: &str,
    tiered_quota: Option<i64>,
    now: i64,
    start_time: i64,
) -> Result<RealtimeSettleOutcome, SubscriptionError> {
    let use_time_seconds = now - start_time;
    let quota_info = QuotaInfo {
        input_details: TokenDetails {
            text_tokens: usage.prompt_tokens_details.text_tokens,
            audio_tokens: usage.prompt_tokens_details.audio_tokens,
        },
        output_details: TokenDetails {
            text_tokens: usage.completion_token_details.text_tokens,
            audio_tokens: usage.completion_token_details.audio_tokens,
        },
        model_name: info.origin_model_name.clone(),
        use_price: price_data.use_price,
        model_price: price_data.model_price,
        model_ratio: price_data.model_ratio,
        group_ratio: price_data.group_ratio(),
    };

    let (mut quota, clamp) = calculate_audio_quota(settings, &quota_info);
    note_quota_clamp(info, clamp);
    if let Some(tiered) = tiered_quota {
        quota = tiered;
    }

    let total_tokens = usage.total_tokens;
    let mut log_content = if !price_data.use_price {
        format!(
            "模型倍率 {:.2}，补全倍率 {:.2}，音频倍率 {:.2}，音频补全倍率 {:.2}，分组倍率 {:.2}",
            price_data.model_ratio,
            settings.completion_ratio(&info.origin_model_name),
            settings.audio_ratio(&info.origin_model_name),
            settings.audio_completion_ratio(&info.origin_model_name),
            price_data.group_ratio()
        )
    } else {
        format!(
            "模型价格 {:.2}，分组倍率 {:.2}",
            price_data.model_price,
            price_data.group_ratio()
        )
    };

    let mut zero_usage = false;
    if total_tokens == 0 {
        quota = 0;
        log_content += "（可能是上游超时）";
        zero_usage = true;
    } else {
        store
            .update_user_used_quota_and_request_count(info.user_id, quota)
            .await?;
        store
            .update_channel_used_quota(channel_id_of(info), quota)
            .await?;
    }

    super::session::settle_billing(store, info, quota)
        .await
        .map_err(|e| SubscriptionError::Db(e.message))?;

    if !extra_content.is_empty() {
        log_content += ", ";
        log_content += extra_content;
    }
    Ok(RealtimeSettleOutcome {
        quota,
        prompt_tokens: usage.prompt_tokens,
        completion_tokens: usage.completion_tokens,
        use_time_seconds,
        log_content,
        model_name: info.origin_model_name.clone(),
        zero_usage,
    })
}

/// RelayInfo.ChannelMeta.ChannelId 的投影（Go 经嵌入指针读取）。
fn channel_id_of(info: &RelayBillingInfo) -> i64 {
    info.channel_id
}
