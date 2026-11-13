//! 文本扣费：Go `consume_text_quota.go`（1-652 行）核心路径移植。
//!
//! 范围：textQuotaSummary 计算（token 分桶 + 倍率公式 + 最小计费单位 1 +
//! 工具调用附加费 + 空响应豁免）、OpenRouter 缓存写反推、gizmo 模型名归一。
//! 分层计费（TieredBillingSnapshot）与 route-stats 采样依赖 relay 侧状态，
//! 留给 relay 入口切片（接口约定见交付报告）；分层结果可在事后经
//! [`apply_tiered_override`] 覆盖 summary 配额。
//!
//! 语义偏差：Go 用 decimal 精确运算，本移植 f64 直算（见 quota_math.rs）。

use serde_json::{Map, Value, json};

use super::classify_usage_path::effective_billing_usage;
use super::pricing::{PriceData, RatioSettings, has_custom_model_ratio};
use super::quota_math::{
    QUOTA_PER_UNIT, QuotaClamp, quota_from_decimal_checked, quota_from_float_checked,
    round_half_away_from_zero,
};
use super::session::RelayBillingInfo;
use super::usage::{
    BUILD_IN_TOOL_GOOGLE_SEARCH, BUILD_IN_TOOL_WEB_SEARCH, BUILD_IN_TOOL_WEB_SEARCH_PREVIEW,
    InputTokenDetails,
};

/// 单条可计费工具调用行（Go `ToolSurchargeItem`）。
#[derive(Debug, Clone, PartialEq)]
pub struct ToolSurchargeItem {
    pub name: String,
    pub count: i64,
    pub price: f64,
}

/// Go `textQuotaSummary` 的移植（去掉 tiered 相关字段，见模块头）。
#[derive(Debug, Clone, Default)]
pub struct TextQuotaSummary {
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub total_tokens: i64,
    pub cache_tokens: i64,
    pub cache_creation_tokens: i64,
    pub cache_creation_tokens_5m: i64,
    pub cache_creation_tokens_1h: i64,
    pub image_tokens: i64,
    pub audio_tokens: i64,
    pub model_name: String,
    pub token_name: String,
    pub use_time_seconds: i64,
    pub completion_ratio: f64,
    pub cache_ratio: f64,
    pub image_ratio: f64,
    pub model_ratio: f64,
    pub group_ratio: f64,
    pub model_price: f64,
    pub cache_creation_ratio: f64,
    pub cache_creation_ratio_5m: f64,
    pub cache_creation_ratio_1h: f64,
    pub quota: i64,
    pub is_claude_usage_semantic: bool,
    pub usage_semantic: String,
    pub audio_input_price: f64,
    pub tool_surcharge_items: Vec<ToolSurchargeItem>,
    /// 工具附加费总额（quota 单位）。
    pub tool_call_surcharge_quota: f64,
    pub empty_response_detected: bool,
    pub empty_response_waived: bool,
    pub empty_response_multiplier: f64,
}

impl TextQuotaSummary {
    /// Go `hasBillableUsage`：零 token 请求仍可能经工具附加费计费。
    pub fn has_billable_usage(&self) -> bool {
        self.total_tokens > 0 || self.tool_call_surcharge_quota != 0.0
    }
}

/// Go `cacheWriteTokensTotal`（consume_text_quota.go:84-93）。
pub fn cache_write_tokens_total(summary: &TextQuotaSummary) -> i64 {
    if summary.cache_creation_tokens_5m > 0 || summary.cache_creation_tokens_1h > 0 {
        let split = summary.cache_creation_tokens_5m + summary.cache_creation_tokens_1h;
        if summary.cache_creation_tokens > split {
            return summary.cache_creation_tokens;
        }
        return split;
    }
    summary.cache_creation_tokens
}

/// Go `isLegacyClaudeDerivedOpenAIUsage`（consume_text_quota.go:95-106）。
/// `final_relay_format` 为 Go `GetFinalRequestRelayFormat()` 的字符串形态。
pub fn is_legacy_claude_derived_openai_usage(
    final_relay_format: &str,
    usage: &super::usage::Usage,
) -> bool {
    if final_relay_format == "claude" {
        return false;
    }
    if !usage.usage_source.is_empty() || !usage.usage_semantic.is_empty() {
        return false;
    }
    usage.claude_cache_creation_5m_tokens > 0 || usage.claude_cache_creation_1h_tokens > 0
}

/// Go `collectToolSurchargeItem`（consume_text_quota.go:108-121）。
fn collect_tool_surcharge_item(
    items: Vec<ToolSurchargeItem>,
    settings: &dyn RatioSettings,
    name: &str,
    count: i64,
    model_name: &str,
) -> Vec<ToolSurchargeItem> {
    if count <= 0 {
        return items;
    }
    let price = settings.tool_price(name, model_name);
    if price <= 0.0 || price.is_nan() || price.is_infinite() {
        return items;
    }
    let mut items = items;
    items.push(ToolSurchargeItem {
        name: name.to_string(),
        count,
        price,
    });
    items
}

/// Go `mergeToolSurchargeItems`（consume_text_quota.go:123-151）：按
/// (name asc, price asc) 排序后合并同 name+price 项，计数 i64 饱和。
pub fn merge_tool_surcharge_items(items: Vec<ToolSurchargeItem>) -> Vec<ToolSurchargeItem> {
    if items.is_empty() {
        return Vec::new();
    }
    let mut items = items;
    items.sort_by(|a, b| {
        if a.name == b.name {
            a.price
                .partial_cmp(&b.price)
                .unwrap_or(std::cmp::Ordering::Equal)
        } else {
            a.name.cmp(&b.name)
        }
    });
    let mut merged: Vec<ToolSurchargeItem> = Vec::with_capacity(items.len());
    for item in items {
        if let Some(last) = merged.last_mut() {
            if last.name == item.name && last.price == item.price {
                let sum = last.count.saturating_add(item.count);
                last.count = sum;
                continue;
            }
        }
        merged.push(item);
    }
    merged
}

/// Go `calculateTextToolCallSurcharge`（consume_text_quota.go:153-194）的输入。
#[derive(Debug, Clone, Default)]
pub struct ToolCallContext {
    /// Go `relayInfo.ResponsesUsageInfo.BuiltInTools`：`(name, call_count)`。
    pub builtin_tools: Vec<(String, i64)>,
    /// Go `ctx.GetInt("claude_web_search_requests")`。
    pub claude_web_search_requests: i64,
    /// Go `ctx.GetBool("gemini_google_search_call")`。
    pub gemini_google_search_call: bool,
    /// Go `relayInfo.RelayMode != RelayModeResponses`。
    pub is_responses_mode: bool,
}

/// 每次调用花费 = price * count / 1000 * groupRatio * QuotaPerUnit。
pub fn tool_surcharge_for_item(item: &ToolSurchargeItem, group_ratio: f64) -> f64 {
    item.price * item.count as f64 / 1000.0 * group_ratio * QUOTA_PER_UNIT
}

/// Go `calculateTextToolCallSurcharge`。计算结果写入
/// `summary.tool_surcharge_items` / `tool_call_surcharge_quota`。
pub fn calculate_text_tool_call_surcharge(
    summary: &mut TextQuotaSummary,
    settings: &dyn RatioSettings,
    tools: &ToolCallContext,
) -> f64 {
    let group_ratio = summary.group_ratio;
    let mut items: Vec<ToolSurchargeItem> = Vec::new();
    for (name, count) in &tools.builtin_tools {
        items = collect_tool_surcharge_item(items, settings, name, *count, &summary.model_name);
    }
    if !tools.is_responses_mode && summary.model_name.ends_with("search-preview") {
        items = collect_tool_surcharge_item(
            items,
            settings,
            BUILD_IN_TOOL_WEB_SEARCH_PREVIEW,
            1,
            &summary.model_name,
        );
    }
    items = collect_tool_surcharge_item(
        items,
        settings,
        BUILD_IN_TOOL_WEB_SEARCH,
        tools.claude_web_search_requests,
        &summary.model_name,
    );
    if tools.gemini_google_search_call {
        items = collect_tool_surcharge_item(
            items,
            settings,
            BUILD_IN_TOOL_GOOGLE_SEARCH,
            1,
            &summary.model_name,
        );
    }
    let merged = merge_tool_surcharge_items(items);
    let mut surcharge = 0.0f64;
    for item in &merged {
        surcharge += tool_surcharge_for_item(item, group_ratio);
    }
    summary.tool_surcharge_items = merged;
    summary.tool_call_surcharge_quota = surcharge;
    surcharge
}

/// Go `noteQuotaClamp`（consume_text_quota.go:199-206）：首个非空 clamp 胜出。
pub fn note_quota_clamp(info: &mut RelayBillingInfo, clamp: Option<QuotaClamp>) {
    if let Some(clamp) = clamp {
        if info.quota_clamp.is_none() {
            info.quota_clamp = Some(clamp);
        }
    }
}

/// Go `usageSemanticFromUsage`（consume_text_quota.go:461-469）。
pub fn usage_semantic_from_usage(
    final_relay_format: &str,
    usage: Option<&super::usage::Usage>,
) -> String {
    if let Some(usage) = usage {
        if !usage.usage_semantic.is_empty() {
            return usage.usage_semantic.clone();
        }
    }
    if final_relay_format == "claude" {
        return "anthropic".into();
    }
    "openai".into()
}

/// Go `calculateTextQuotaSummary` 的调用面输入（ctx / relayInfo 的读取字段）。
#[derive(Debug, Clone, Default)]
pub struct TextCallContext {
    /// Go `ctx.GetString("token_name")`。
    pub token_name: String,
    pub tools: ToolCallContext,
    /// Go `relayInfo.GetFinalRequestRelayFormat()`。
    pub final_relay_format: String,
    /// Go `relayInfo.GetEstimatePromptTokens()`（usage 缺失时的回退）。
    pub estimate_prompt_tokens: i64,
    /// Go `relayInfo.ChannelType == ChannelTypeOpenRouter`。
    pub is_open_router_channel: bool,
    /// 计费设置（Go `GetQuotaSetting()`）。
    pub empty_response_multiplier: f64,
    /// Go `relaycommon.StreamEndReasonClientGone`（true = 客户端断开）。
    pub stream_end_client_gone: bool,
}

/// Go `calculateTextQuotaSummary`（consume_text_quota.go:236-390）。
/// 传入的 usage 应已由 [`effective_billing_usage`] 重映射。
pub fn calculate_text_quota_summary(
    settings: &dyn RatioSettings,
    info: &mut RelayBillingInfo,
    price_data: &PriceData,
    usage: Option<&super::usage::Usage>,
    call: &TextCallContext,
    now: i64,
    start_time: i64,
) -> TextQuotaSummary {
    let mut summary = TextQuotaSummary {
        model_name: info.origin_model_name.clone(),
        token_name: call.token_name.clone(),
        use_time_seconds: now - start_time,
        completion_ratio: price_data.completion_ratio,
        cache_ratio: price_data.cache_ratio,
        image_ratio: price_data.image_ratio,
        model_ratio: price_data.model_ratio,
        group_ratio: price_data.group_ratio(),
        model_price: price_data.model_price,
        cache_creation_ratio: price_data.cache_creation_ratio,
        cache_creation_ratio_5m: price_data.cache_creation_5m_ratio,
        cache_creation_ratio_1h: price_data.cache_creation_1h_ratio,
        usage_semantic: usage_semantic_from_usage(&call.final_relay_format, usage),
        ..Default::default()
    };
    summary.is_claude_usage_semantic = summary.usage_semantic == "anthropic";

    let default_usage = super::usage::Usage {
        prompt_tokens: call.estimate_prompt_tokens,
        completion_tokens: 0,
        total_tokens: call.estimate_prompt_tokens,
        ..Default::default()
    };
    let usage = usage.unwrap_or(&default_usage);

    summary.prompt_tokens = usage.prompt_tokens;
    summary.completion_tokens = usage.completion_tokens;
    summary.total_tokens = usage.prompt_tokens + usage.completion_tokens;
    summary.cache_tokens = usage.prompt_tokens_details.cached_tokens;
    summary.cache_creation_tokens = usage.prompt_tokens_details.cache_creation_tokens_total();
    summary.cache_creation_tokens_5m = usage.claude_cache_creation_5m_tokens;
    summary.cache_creation_tokens_1h = usage.claude_cache_creation_1h_tokens;
    summary.image_tokens = usage.prompt_tokens_details.image_tokens;
    summary.audio_tokens = usage.prompt_tokens_details.audio_tokens;
    let legacy_claude_derived =
        is_legacy_claude_derived_openai_usage(&call.final_relay_format, usage);
    let is_open_router_claude_billing =
        call.is_open_router_channel && summary.is_claude_usage_semantic;

    if is_open_router_claude_billing {
        summary.prompt_tokens -= summary.cache_tokens;
        let is_using_custom_settings = price_data.use_price
            || has_custom_model_ratio(settings, &summary.model_name, price_data.model_ratio);
        if summary.cache_creation_tokens == 0
            && price_data.cache_creation_ratio != 1.0
            && usage.cost != 0.0
            && !is_using_custom_settings
        {
            let maybe = calc_open_router_cache_create_tokens(usage, price_data);
            if maybe >= 0 && summary.prompt_tokens >= maybe {
                summary.cache_creation_tokens = maybe;
            }
        }
        summary.prompt_tokens -= summary.cache_creation_tokens;
    }

    let prompt_tokens = summary.prompt_tokens as f64;
    let cache_tokens = summary.cache_tokens as f64;
    let image_tokens = summary.image_tokens as f64;
    let audio_tokens = summary.audio_tokens as f64;
    let completion_tokens = summary.completion_tokens as f64;
    let cache_creation_tokens = summary.cache_creation_tokens as f64;

    let ratio = summary.model_ratio * summary.group_ratio;
    calculate_text_tool_call_surcharge(&mut summary, settings, &call.tools);

    let mut audio_input_quota = 0.0f64;
    if !price_data.use_price {
        let mut base_tokens = prompt_tokens;
        let mut cached_tokens_with_ratio = 0.0f64;
        if cache_tokens != 0.0 {
            if !summary.is_claude_usage_semantic && !legacy_claude_derived {
                base_tokens -= cache_tokens;
            }
            cached_tokens_with_ratio = cache_tokens * summary.cache_ratio;
        }

        let mut cached_creation_tokens_with_ratio = 0.0f64;
        let has_split_cache_creation_tokens =
            summary.cache_creation_tokens_5m > 0 || summary.cache_creation_tokens_1h > 0;
        if cache_creation_tokens != 0.0 || has_split_cache_creation_tokens {
            if !summary.is_claude_usage_semantic && !legacy_claude_derived {
                base_tokens -= cache_creation_tokens;
                cached_creation_tokens_with_ratio =
                    cache_creation_tokens * summary.cache_creation_ratio;
            } else {
                let mut remaining = summary.cache_creation_tokens
                    - summary.cache_creation_tokens_5m
                    - summary.cache_creation_tokens_1h;
                if remaining < 0 {
                    remaining = 0;
                }
                cached_creation_tokens_with_ratio = remaining as f64 * summary.cache_creation_ratio;
                cached_creation_tokens_with_ratio +=
                    summary.cache_creation_tokens_5m as f64 * summary.cache_creation_ratio_5m;
                cached_creation_tokens_with_ratio +=
                    summary.cache_creation_tokens_1h as f64 * summary.cache_creation_ratio_1h;
            }
        }

        let mut image_tokens_with_ratio = 0.0f64;
        if image_tokens != 0.0 {
            base_tokens -= image_tokens;
            image_tokens_with_ratio = image_tokens * summary.image_ratio;
        }

        if audio_tokens != 0.0 {
            summary.audio_input_price =
                settings.gemini_input_audio_price_per_million(&summary.model_name);
            if summary.audio_input_price > 0.0 {
                base_tokens -= audio_tokens;
                audio_input_quota = summary.audio_input_price / 1_000_000.0
                    * audio_tokens
                    * summary.group_ratio
                    * QUOTA_PER_UNIT;
            }
        }

        // OpenAI cache-write 上报未调整的前缀计数，cached + cache_write 可超
        // prompt 且余量为负；钳 0 防止重叠变成负基数计费。
        if base_tokens < 0.0 {
            base_tokens = 0.0;
        }

        let prompt_quota = base_tokens
            + cached_tokens_with_ratio
            + image_tokens_with_ratio
            + cached_creation_tokens_with_ratio;
        let completion_quota = completion_tokens * summary.completion_ratio;
        let mut quota_decimal = (prompt_quota + completion_quota) * ratio;
        quota_decimal += audio_input_quota;
        quota_decimal = price_data.apply_other_ratios(quota_decimal);
        quota_decimal += summary.tool_call_surcharge_quota;

        if ratio != 0.0 && quota_decimal <= 0.0 {
            quota_decimal = 1.0;
        }
        let (quota, clamp) = quota_from_decimal_checked(quota_decimal);
        summary.quota = quota;
        note_quota_clamp(info, clamp);
    } else {
        let mut quota_decimal = price_data.model_price * QUOTA_PER_UNIT * summary.group_ratio;
        quota_decimal += audio_input_quota;
        quota_decimal = price_data.apply_other_ratios(quota_decimal);
        quota_decimal += summary.tool_call_surcharge_quota;
        let (quota, clamp) = quota_from_decimal_checked(quota_decimal);
        summary.quota = quota;
        note_quota_clamp(info, clamp);
    }

    if !summary.has_billable_usage() {
        summary.quota = 0;
    } else if ratio != 0.0 && summary.quota == 0 {
        summary.quota = 1;
    }

    summary
}

/// Go `isTextGenerationFormat`（consume_text_quota.go:397-407）。
/// format 字符串与 relaykit RelayFormat 的名字一一对应。
pub fn is_text_generation_format(format: &str) -> bool {
    matches!(
        format,
        "openai" | "claude" | "gemini" | "openai-responses" | "openai-responses-compaction"
    )
}

/// Go `isUndeliveredTextResponse`（consume_text_quota.go:414-428）。
pub fn is_undelivered_text_response(
    final_relay_format: &str,
    summary: &TextQuotaSummary,
    admin_reject_reason: &str,
    stream_end_client_gone: bool,
) -> bool {
    if !is_text_generation_format(final_relay_format) {
        return false;
    }
    if summary.completion_tokens != 0 {
        return false;
    }
    if !summary.tool_surcharge_items.is_empty() {
        return false;
    }
    if !admin_reject_reason.is_empty() {
        return false;
    }
    !stream_end_client_gone
}

/// Go `applyEmptyResponseMultiplier`（consume_text_quota.go:435-459）。
pub fn apply_empty_response_multiplier(
    info: &mut RelayBillingInfo,
    summary: &mut TextQuotaSummary,
    admin_reject_reason: &str,
    final_relay_format: &str,
    stream_end_client_gone: bool,
    configured_multiplier: f64,
) {
    if !is_undelivered_text_response(
        final_relay_format,
        summary,
        admin_reject_reason,
        stream_end_client_gone,
    ) {
        return;
    }
    summary.empty_response_detected = true;
    let mut multiplier = configured_multiplier;
    if multiplier.is_nan() || multiplier < 0.0 {
        multiplier = 0.0;
    }
    if multiplier > 1.0 {
        multiplier = 1.0;
    }
    summary.empty_response_multiplier = multiplier;
    if multiplier < 1.0 && summary.quota > 0 {
        let (scaled, clamp) = quota_from_float_checked(summary.quota as f64 * multiplier);
        note_quota_clamp(info, clamp);
        summary.quota = scaled;
        summary.empty_response_waived = true;
    }
}

/// 分层计费覆盖：relay 入口切片执行 Go TryTieredSettle 后调用，把
/// `composeTieredTextQuota`（consume_text_quota.go:208-231）的加和语义套到
/// summary 上（饱和到 int32 并记录 clamp）。无附加费时直接采用分层配额。
pub fn apply_tiered_override(
    info: &mut RelayBillingInfo,
    summary: &mut TextQuotaSummary,
    tiered_quota: i64,
    tiered_actual_quota_before_group: f64,
    group_ratio: f64,
) {
    if summary.tool_call_surcharge_quota == 0.0 {
        summary.quota = tiered_quota;
        return;
    }
    let (quota, clamp) = quota_from_decimal_checked(
        round_half_away_from_zero(tiered_actual_quota_before_group * group_ratio)
            + summary.tool_call_surcharge_quota,
    );
    note_quota_clamp(info, clamp);
    summary.quota = quota;
}

/// Go `CalcOpenRouterCacheCreateTokens`（consume_quota_realtime.go:277-296）。
pub fn calc_open_router_cache_create_tokens(
    usage: &super::usage::Usage,
    price_data: &PriceData,
) -> i64 {
    if price_data.cache_creation_ratio == 1.0 {
        return 0;
    }
    let quota_price = price_data.model_ratio / QUOTA_PER_UNIT;
    let prompt_cache_create_price = quota_price * price_data.cache_creation_ratio;
    let prompt_cache_read_price = quota_price * price_data.cache_ratio;
    let completion_price = quota_price * price_data.completion_ratio;

    let cost = usage.cost;
    let total_prompt_tokens = usage.prompt_tokens as f64;
    let completion_tokens = usage.completion_tokens as f64;
    let prompt_cache_read_tokens = usage.prompt_tokens_details.cached_tokens as f64;

    let denom = prompt_cache_create_price - quota_price;
    if denom == 0.0 {
        // Go int() 对 ±Inf/NaN 的饱和在 quota_from_float 里处理
        return quota_from_float_checked(
            (cost - total_prompt_tokens * quota_price
                + prompt_cache_read_tokens * (quota_price - prompt_cache_read_price)
                - completion_tokens * completion_price)
                / denom,
        )
        .0;
    }
    quota_from_float_checked(
        (cost - total_prompt_tokens * quota_price
            + prompt_cache_read_tokens * (quota_price - prompt_cache_read_price)
            - completion_tokens * completion_price)
            / denom,
    )
    .0
}

/// Go `appendToolSurchargeLogInfo`（consume_text_quota.go:36-41）。
pub fn append_tool_surcharge_log_info(other: &mut Map<String, Value>, items: &[ToolSurchargeItem]) {
    if items.is_empty() {
        return;
    }
    let arr: Vec<Value> = items
        .iter()
        .map(|item| {
            json!({
                "name": item.name,
                "count": item.count,
                "price": item.price,
            })
        })
        .collect();
    other.insert("tool_surcharges".into(), Value::Array(arr));
}

/// Go PostTextConsumeQuota 的 `other` 字段组装（571-616 行）：在调用方提供
/// 的基础 map（Go GenerateTextOtherInfo / GenerateClaudeOtherInfo，属 usage
/// 域，未随本切片移植）上追加计费明细。
#[allow(clippy::too_many_arguments)]
pub fn append_text_consume_other_fields(
    other: &mut Map<String, Value>,
    summary: &TextQuotaSummary,
    origin_usage: Option<&super::usage::Usage>,
    final_relay_format: &str,
    is_local_count_tokens: bool,
    admin_reject_reason: &str,
    group_special_ratio: f64,
) {
    let _ = group_special_ratio;
    if summary.is_claude_usage_semantic {
        other.insert("usage_semantic".into(), json!("anthropic"));
    }
    super::classify_usage_path::append_usage_billing_path_for_log(
        other,
        is_local_count_tokens,
        origin_usage.unwrap_or(&super::usage::Usage::default()),
    );
    if !admin_reject_reason.is_empty() {
        other.insert("reject_reason".into(), json!(admin_reject_reason));
    }
    if summary.empty_response_detected {
        other.insert(
            "empty_response_multiplier".into(),
            json!(summary.empty_response_multiplier),
        );
        if summary.empty_response_waived {
            other.insert("empty_response_waived".into(), json!(true));
        }
    }
    if summary.image_tokens != 0 {
        other.insert("image".into(), json!(true));
        other.insert("image_ratio".into(), json!(summary.image_ratio));
        other.insert("image_output".into(), json!(summary.image_tokens));
    }
    append_tool_surcharge_log_info(other, &summary.tool_surcharge_items);
    if summary.audio_input_price > 0.0 && summary.audio_tokens > 0 {
        other.insert("audio_input_seperate_price".into(), json!(true));
        other.insert(
            "audio_input_token_count".into(),
            json!(summary.audio_tokens),
        );
        other.insert("audio_input_price".into(), json!(summary.audio_input_price));
    }
    if summary.cache_creation_tokens > 0 {
        other.insert(
            "cache_creation_tokens".into(),
            json!(summary.cache_creation_tokens),
        );
        other.insert(
            "cache_creation_ratio".into(),
            json!(summary.cache_creation_ratio),
        );
    }
    if summary.cache_creation_tokens_5m > 0 {
        other.insert(
            "cache_creation_tokens_5m".into(),
            json!(summary.cache_creation_tokens_5m),
        );
        other.insert(
            "cache_creation_ratio_5m".into(),
            json!(summary.cache_creation_ratio_5m),
        );
    }
    if summary.cache_creation_tokens_1h > 0 {
        other.insert(
            "cache_creation_tokens_1h".into(),
            json!(summary.cache_creation_tokens_1h),
        );
        other.insert(
            "cache_creation_ratio_1h".into(),
            json!(summary.cache_creation_ratio_1h),
        );
    }
    let cache_write_tokens = cache_write_tokens_total(summary);
    if cache_write_tokens > 0 {
        other.insert("cache_write_tokens".into(), json!(cache_write_tokens));
    }
    if final_relay_format != "claude" {
        if let Some(usage) = origin_usage {
            if !usage.usage_source.is_empty() && usage.input_tokens > 0 {
                other.insert("input_tokens_total".into(), json!(usage.input_tokens));
            }
        }
    }
}

/// 供调用方在 other.admin_info 下挂 quota_saturation（Go
/// usage.AttachQuotaSaturation 的形状，consume_quota_saturation_test.go）。
pub fn attach_quota_saturation(other: &mut Map<String, Value>, clamp: &QuotaClamp) {
    let admin_info = other
        .entry("admin_info")
        .or_insert_with(|| Value::Object(Map::new()));
    if !admin_info.is_object() {
        *admin_info = Value::Object(Map::new());
    }
    if let Value::Object(admin) = admin_info {
        admin.insert("quota_saturation".into(), Value::Object(clamp.audit_map()));
    }
}

/// Go PostTextConsumeQuota 的日志 content 组装（503-533 行）：工具附加费
/// 说明、空响应说明、音频花费说明、无计费信息说明。
pub fn build_text_log_extra_content(
    summary: &TextQuotaSummary,
    mut extra_content: Vec<String>,
) -> Vec<String> {
    for item in &summary.tool_surcharge_items {
        let q = tool_surcharge_for_item(item, summary.group_ratio);
        extra_content.push(format!(
            "{} 调用 {} 次，调用花费 {}",
            item.name,
            item.count,
            log_quota(super::quota_math::quota_from_float(q))
        ));
    }
    if summary.empty_response_detected {
        if summary.empty_response_waived && summary.empty_response_multiplier > 0.0 {
            extra_content.push(format!(
                "上游返回空响应，按 {} 倍率扣费",
                summary.empty_response_multiplier
            ));
        } else if summary.empty_response_waived {
            extra_content.push("上游返回空响应，费用已豁免".into());
        } else {
            extra_content.push("上游返回空响应，按原价扣费".into());
        }
    }
    if summary.audio_input_price > 0.0 && summary.audio_tokens > 0 {
        let q = summary.audio_input_price / 1_000_000.0
            * summary.audio_tokens as f64
            * summary.group_ratio
            * QUOTA_PER_UNIT;
        extra_content.push(format!(
            "Audio Input 花费 {}",
            log_quota(super::quota_math::quota_from_float(q))
        ));
    }
    extra_content
}

/// Go `logger.LogQuota` 的数值面。
pub fn log_quota(quota: i64) -> String {
    format!("${:.6}", quota as f64 / QUOTA_PER_UNIT)
}

/// Go PostTextConsumeQuota 的 gizmo 模型名归一（543-551 行）。
pub fn normalize_gizmo_model(model: &str, extra_content: &mut Vec<String>) -> String {
    if let Some(stripped) = model.strip_prefix("gpt-4-gizmo") {
        if stripped.starts_with('-') || model != "gpt-4-gizmo" {
            extra_content.push(format!("模型 {model}"));
            return "gpt-4-gizmo-*".into();
        }
    }
    if let Some(_stripped) = model.strip_prefix("gpt-4o-gizmo") {
        extra_content.push(format!("模型 {model}"));
        return "gpt-4o-gizmo-*".into();
    }
    model.to_string()
}

/// 输入 token 细分帮助（测试/调用方）。
pub fn input_details_from(usage: &super::usage::Usage) -> InputTokenDetails {
    usage.prompt_tokens_details.clone()
}
