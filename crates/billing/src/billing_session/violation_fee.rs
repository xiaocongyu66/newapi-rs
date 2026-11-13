//! 违规费：Go `charge_violation_fee.go`（1-165 行）移植。Grok 安全违规
//! （CSAM 标记）在正常流程结束后加收一笔费用；费额 = 配置金额 ×
//! QuotaPerUnit × groupRatio，四舍五入取整。
//!
//! Grok 设置端口 [`GrokFeeSettings`] 由调用方注入（settings 域切片提供生产
//! 实现）；错误归一化只处理消息字符串形态（NewAPIError 类型属 relay/types
//! 切片，接口约定见交付报告）。

use super::quota_math::{QUOTA_PER_UNIT, quota_from_float_checked};
use super::store::{BillingStore, SubscriptionError};
use super::text_quota::log_quota;

/// Go `ViolationFeeCodePrefix`。
pub const VIOLATION_FEE_CODE_PREFIX: &str = "violation_fee.";
/// Go `CSAMViolationMarker`。
pub const CSAM_VIOLATION_MARKER: &str = "Failed check: SAFETY_CHECK_TYPE";
/// Go `ContentViolatesUsageMarker`。
pub const CONTENT_VIOLATES_USAGE_MARKER: &str = "Content violates usage guidelines";
/// Go `types.ErrorCodeViolationFeeGrokCSAM`。
pub const ERROR_CODE_VIOLATION_FEE_GROK_CSAM: &str = "violation_fee.grok_csam";

/// Grok 费用设置端口（Go `model_setting.GetGrokSettings()` 计费字段）。
#[derive(Debug, Clone, Copy, Default)]
pub struct GrokFeeSettings {
    pub violation_deduction_enabled: bool,
    pub violation_deduction_amount: f64,
}

/// Go `IsViolationFeeCode`（charge_violation_fee.go:26-28）。
pub fn is_violation_fee_code(code: &str) -> bool {
    code.starts_with(VIOLATION_FEE_CODE_PREFIX)
}

/// Go `HasCSAMViolationMarker`（charge_violation_fee.go:30-39）的字符串形态：
/// 检查错误消息与其 OpenAI 错体消息两处标记。
pub fn has_csam_violation_marker(err_message: &str, openai_message: &str) -> bool {
    err_message.contains(CSAM_VIOLATION_MARKER)
        || err_message.contains(CONTENT_VIOLATES_USAGE_MARKER)
        || openai_message.contains(CSAM_VIOLATION_MARKER)
        || openai_message.contains(CONTENT_VIOLATES_USAGE_MARKER)
}

/// Go `shouldChargeViolationFee`（charge_violation_fee.go:73-82）：错误码即
/// grok_csam，或消息带安全标记（未归一化时的兜底）。
pub fn should_charge_violation_fee(
    err_code: &str,
    err_message: &str,
    openai_message: &str,
) -> bool {
    err_code == ERROR_CODE_VIOLATION_FEE_GROK_CSAM
        || has_csam_violation_marker(err_message, openai_message)
}

/// Go `calcViolationFeeQuota`（charge_violation_fee.go:84-100）：
/// amount/groupRatio 任一 ≤0 回 0；乘积四舍五入后仍 ≤0 回 0。
pub fn calc_violation_fee_quota(amount: f64, group_ratio: f64) -> i64 {
    if amount <= 0.0 {
        return 0;
    }
    if group_ratio <= 0.0 {
        return 0;
    }
    let (quota, clamp) = quota_from_float_checked(amount * QUOTA_PER_UNIT * group_ratio);
    if clamp.is_some() {
        // Go Round(0).IntPart() 对饱和值同样是 MaxInt32；保持一致即可
        return quota;
    }
    if quota <= 0 {
        return 0;
    }
    quota
}

/// Go `ChargeViolationFeeIfNeeded` 的输入（NewAPIError 的计费读取面）。
#[derive(Debug, Clone, Default)]
pub struct ViolationFeeInput<'a> {
    pub err_code: &'a str,
    pub err_message: &'a str,
    pub openai_message: &'a str,
    pub status_code: u16,
    pub upstream_error_type: &'a str,
    pub upstream_error_code: String,
}

/// Go `ChargeViolationFeeIfNeeded`（charge_violation_fee.go:104-165）：
/// 正常流程结束后按 Grok 费用设置加收，写 consume 日志并返回是否计费成功。
/// 额度展示字段（fee_quota_display）由 quota_display 切片提供快照时再补——
/// 当前写 0（Go QuotaToDisplayAmount 依赖全局展示配置）。
#[allow(clippy::too_many_arguments)]
pub async fn charge_violation_fee_if_needed(
    store: &BillingStore,
    info: &mut super::session::RelayBillingInfo,
    input: &ViolationFeeInput<'_>,
    grok: &GrokFeeSettings,
    token_name: &str,
    now: i64,
    start_time: i64,
    other_base: &serde_json::Map<String, serde_json::Value>,
) -> Result<bool, SubscriptionError> {
    if !should_charge_violation_fee(input.err_code, input.err_message, input.openai_message) {
        return Ok(false);
    }
    if !grok.violation_deduction_enabled {
        return Ok(false);
    }
    let group_ratio = info_group_ratio(info);
    let fee_quota = calc_violation_fee_quota(grok.violation_deduction_amount, group_ratio);
    if fee_quota <= 0 {
        return Ok(false);
    }

    // Go PostConsumeQuota(relayInfo, feeQuota, 0, true)：sendEmail 通知分支
    // 依赖 mailer 切片，未随本切片移植。
    super::session::post_consume_quota(store, info, fee_quota, 0)
        .await
        .map_err(|e| SubscriptionError::Db(e.message))?;

    store
        .update_user_used_quota_and_request_count(info.user_id, fee_quota)
        .await?;
    store
        .update_channel_used_quota(info.channel_id, fee_quota)
        .await?;

    let use_time_seconds = now - start_time;
    let mut other = other_base.clone();
    other.insert("violation_fee".into(), serde_json::json!(true));
    other.insert(
        "violation_fee_code".into(),
        serde_json::json!(ERROR_CODE_VIOLATION_FEE_GROK_CSAM),
    );
    other.insert("fee_quota".into(), serde_json::json!(fee_quota));
    other.insert(
        "fee_quota_display".into(),
        serde_json::json!(fee_quota as f64 / QUOTA_PER_UNIT),
    );
    other.insert(
        "base_amount".into(),
        serde_json::json!(grok.violation_deduction_amount),
    );
    other.insert("group_ratio".into(), serde_json::json!(group_ratio));
    other.insert("status_code".into(), serde_json::json!(input.status_code));
    other.insert(
        "upstream_error_type".into(),
        serde_json::json!(input.upstream_error_type),
    );
    other.insert(
        "upstream_error_code".into(),
        serde_json::json!(input.upstream_error_code),
    );
    other.insert(
        "violation_fee_marker".into(),
        serde_json::json!(CSAM_VIOLATION_MARKER),
    );

    let params = newapi_usage::store_log::RecordConsumeLogParams {
        channel_id: info.channel_id,
        prompt_tokens: 0,
        completion_tokens: 0,
        model_name: info.origin_model_name.clone(),
        token_name: token_name.to_string(),
        quota: fee_quota,
        content: "Violation fee charged".into(),
        token_id: info.token_id,
        use_time_seconds,
        is_stream: info.is_stream,
        group: info.using_group.clone(),
        other,
    };
    let context = newapi_usage::store_log::ConsumeLogContext {
        user_id: info.user_id,
        username: info.username.clone(),
        request_id: info.request_id.clone(),
        upstream_request_id: String::new(),
        record_ip: false,
        client_ip: String::new(),
        consume_enabled: true,
        data_export_enabled: false,
        node_name: String::new(),
    };
    newapi_usage::store_log::record_consume_log(&store.db, &context, &params).await?;
    Ok(true)
}

fn info_group_ratio(info: &super::session::RelayBillingInfo) -> f64 {
    info.group_ratio
}

/// 费额展示帮助（日志诊断用）。
pub fn format_fee(quota: i64) -> String {
    log_quota(quota)
}
