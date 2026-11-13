//! 用量路径分类：Go `classify_usage_path.go`（1-202 行）的逐字移植。
//!
//! 从 `billing_usage` 包装里还原出真正的计费用量（OpenAI/Claude/Gemini 三种
//! 语义），并产出日志用的 `usage_billing_path` 标签。字符串比较一律大小写
//! 不敏感（Go `strings.EqualFold`）。

use serde_json::{Map, Value};

use super::usage::{
    BillingUsage, InputTokenDetails, SEMANTIC_ANTHROPIC, SEMANTIC_GEMINI, SEMANTIC_OPENAI,
    SOURCE_CLAUDE_MESSAGES, SOURCE_GEMINI_CHAT, SOURCE_OAI_CHAT, SOURCE_OAI_RESPONSES, Usage,
};

pub const USAGE_BILLING_PATH_LOCAL: &str = "local";
pub const USAGE_BILLING_PATH_UPSTREAM: &str = "upstream";
pub const USAGE_BILLING_PATH_OPENAI: &str = "billing-usage-openai";
pub const USAGE_BILLING_PATH_OPENAI_ESTIMATED: &str = "billing-usage-openai-estimated";
pub const USAGE_BILLING_PATH_ANTHROPIC: &str = "billing-usage-anthropic";
pub const USAGE_BILLING_PATH_ANTHROPIC_ESTIMATED: &str = "billing-usage-anthropic-estimated";
pub const USAGE_BILLING_PATH_GEMINI: &str = "billing-usage-gemini";
pub const USAGE_BILLING_PATH_GEMINI_ESTIMATED: &str = "billing-usage-gemini-estimated";

/// Go `effectiveBillingUsage`（classify_usage_path.go:20-25）。
pub fn effective_billing_usage(usage: &Usage) -> Usage {
    if let Some(billing_usage) = usage_from_billing_usage(usage) {
        return billing_usage;
    }
    usage.clone()
}

/// Go `usageBillingPathForLog`（classify_usage_path.go:27-55）。
pub fn usage_billing_path_for_log(is_local_count_tokens: bool, usage: &Usage) -> &'static str {
    let Some(effective_usage) = usage_from_billing_usage(usage) else {
        return if is_local_count_tokens {
            USAGE_BILLING_PATH_LOCAL
        } else {
            USAGE_BILLING_PATH_UPSTREAM
        };
    };
    let estimated = usage.billing_usage.as_ref().is_some_and(|b| b.estimated);
    match effective_usage.usage_semantic.as_str() {
        SEMANTIC_OPENAI => {
            if estimated {
                USAGE_BILLING_PATH_OPENAI_ESTIMATED
            } else {
                USAGE_BILLING_PATH_OPENAI
            }
        }
        SEMANTIC_ANTHROPIC => {
            if estimated {
                USAGE_BILLING_PATH_ANTHROPIC_ESTIMATED
            } else {
                USAGE_BILLING_PATH_ANTHROPIC
            }
        }
        SEMANTIC_GEMINI => {
            if estimated {
                USAGE_BILLING_PATH_GEMINI_ESTIMATED
            } else {
                USAGE_BILLING_PATH_GEMINI
            }
        }
        _ => USAGE_BILLING_PATH_UPSTREAM,
    }
}

/// Go `appendUsageBillingPathForLog`（classify_usage_path.go:57-67）：
/// 写入 `other.admin_info.usage_billing_path`，`admin_info` 不存在则创建。
pub fn append_usage_billing_path_for_log(
    other: &mut Map<String, Value>,
    is_local_count_tokens: bool,
    usage: &Usage,
) {
    let path = usage_billing_path_for_log(is_local_count_tokens, usage);
    let admin_info = other
        .entry("admin_info")
        .or_insert_with(|| Value::Object(Map::new()));
    if !admin_info.is_object() {
        *admin_info = Value::Object(Map::new());
    }
    if let Value::Object(admin) = admin_info {
        admin.insert("usage_billing_path".into(), Value::String(path.into()));
    }
}

/// Go `usageFromBillingUsage`（classify_usage_path.go:69-97）。
pub fn usage_from_billing_usage(usage: &Usage) -> Option<Usage> {
    let billing_usage = usage.billing_usage.as_ref()?;
    let source = billing_usage.source.trim();
    let semantic = billing_usage.semantic.trim();

    if billing_usage.openai_usage.is_some()
        && (source.eq_ignore_ascii_case(SOURCE_OAI_CHAT)
            || source.eq_ignore_ascii_case(SOURCE_OAI_RESPONSES)
            || semantic.eq_ignore_ascii_case(SEMANTIC_OPENAI))
    {
        return Some(usage_from_openai_billing_usage(billing_usage));
    }

    if billing_usage.claude_usage.is_some()
        && (source.eq_ignore_ascii_case(SOURCE_CLAUDE_MESSAGES)
            || semantic.eq_ignore_ascii_case(SEMANTIC_ANTHROPIC))
    {
        return Some(usage_from_claude_billing_usage(billing_usage));
    }

    if billing_usage.gemini_usage_metadata.is_some()
        && (source.eq_ignore_ascii_case(SOURCE_GEMINI_CHAT)
            || semantic.eq_ignore_ascii_case(SEMANTIC_GEMINI))
    {
        return Some(usage_from_gemini_billing_usage(billing_usage));
    }

    None
}

/// Go `usageFromOpenAIBillingUsage`（classify_usage_path.go:99-120）：
/// prompt/completion 与 input/output 双向补齐，total 缺失时求和。
pub fn usage_from_openai_billing_usage(billing_usage: &BillingUsage) -> Usage {
    let mut usage = (**billing_usage.openai_usage.as_ref().expect("checked caller")).clone();
    if usage.prompt_tokens == 0 && usage.input_tokens > 0 {
        usage.prompt_tokens = usage.input_tokens;
    }
    if usage.completion_tokens == 0 && usage.output_tokens > 0 {
        usage.completion_tokens = usage.output_tokens;
    }
    if usage.input_tokens == 0 && usage.prompt_tokens > 0 {
        usage.input_tokens = usage.prompt_tokens;
    }
    if usage.output_tokens == 0 && usage.completion_tokens > 0 {
        usage.output_tokens = usage.completion_tokens;
    }
    if usage.total_tokens == 0 {
        usage.total_tokens = usage.prompt_tokens + usage.completion_tokens;
    }
    usage.usage_semantic = SEMANTIC_OPENAI.to_string();
    usage.usage_source = billing_usage.source.clone();
    usage.billing_usage = Some(billing_usage.clone());
    usage
}

/// Go `usageFromClaudeBillingUsage`（classify_usage_path.go:122-148）。
pub fn usage_from_claude_billing_usage(billing_usage: &BillingUsage) -> Usage {
    let claude = billing_usage.claude_usage.as_ref().expect("checked caller");
    let mut cache_creation_5m = claude.cache_creation_5m_tokens;
    if cache_creation_5m == 0 {
        cache_creation_5m = claude.claude_cache_creation_5m_tokens;
    }
    let mut cache_creation_1h = claude.cache_creation_1h_tokens;
    if cache_creation_1h == 0 {
        cache_creation_1h = claude.claude_cache_creation_1h_tokens;
    }

    let mut usage = Usage {
        prompt_tokens: claude.input_tokens,
        completion_tokens: claude.output_tokens,
        total_tokens: claude.input_tokens + claude.output_tokens,
        input_tokens: claude.input_tokens
            + claude.cache_read_input_tokens
            + claude.cache_creation_input_tokens,
        output_tokens: claude.output_tokens,
        usage_semantic: SEMANTIC_ANTHROPIC.to_string(),
        usage_source: SOURCE_CLAUDE_MESSAGES.to_string(),
        billing_usage: Some(billing_usage.clone()),
        claude_cache_creation_5m_tokens: cache_creation_5m,
        claude_cache_creation_1h_tokens: cache_creation_1h,
        ..Default::default()
    };
    usage.prompt_tokens_details = InputTokenDetails {
        cached_tokens: claude.cache_read_input_tokens,
        cached_creation_tokens: claude.cache_creation_input_tokens,
        ..Default::default()
    };
    usage
}

/// Go `usageFromGeminiBillingUsage`（classify_usage_path.go:150-190）。
pub fn usage_from_gemini_billing_usage(billing_usage: &BillingUsage) -> Usage {
    let metadata = billing_usage
        .gemini_usage_metadata
        .as_ref()
        .expect("checked caller");
    let prompt_tokens = metadata.prompt_token_count + metadata.tool_use_prompt_token_count;
    let mut usage = Usage {
        prompt_tokens,
        completion_tokens: metadata.candidates_token_count + metadata.thoughts_token_count,
        total_tokens: metadata.total_token_count,
        usage_semantic: SEMANTIC_GEMINI.to_string(),
        usage_source: SOURCE_GEMINI_CHAT.to_string(),
        billing_usage: Some(billing_usage.clone()),
        ..Default::default()
    };
    usage.completion_token_details.reasoning_tokens = metadata.thoughts_token_count;
    usage.prompt_tokens_details.cached_tokens = metadata.cached_content_token_count;

    for detail in &metadata.prompt_tokens_details {
        add_gemini_input_token_detail(&mut usage.prompt_tokens_details, detail);
    }
    for detail in &metadata.tool_use_prompt_tokens_details {
        add_gemini_input_token_detail(&mut usage.prompt_tokens_details, detail);
    }
    for detail in &metadata.candidates_tokens_details {
        match detail.modality.as_str() {
            "IMAGE" => usage.completion_token_details.image_tokens += detail.token_count,
            "AUDIO" => usage.completion_token_details.audio_tokens += detail.token_count,
            "TEXT" => usage.completion_token_details.text_tokens += detail.token_count,
            _ => {}
        }
    }

    if usage.total_tokens == 0 {
        usage.total_tokens = usage.prompt_tokens + usage.completion_tokens;
    } else if usage.completion_tokens <= 0 {
        usage.completion_tokens = usage.total_tokens - usage.prompt_tokens;
    }
    if usage.prompt_tokens > 0
        && usage.prompt_tokens_details.text_tokens == 0
        && usage.prompt_tokens_details.audio_tokens == 0
    {
        usage.prompt_tokens_details.text_tokens = usage.prompt_tokens;
    }
    usage
}

/// Go `addGeminiInputTokenDetail`（classify_usage_path.go:192-201）。
fn add_gemini_input_token_detail(
    details: &mut InputTokenDetails,
    detail: &super::usage::GeminiModalityTokenCount,
) {
    match detail.modality.as_str() {
        "AUDIO" => details.audio_tokens += detail.token_count,
        "IMAGE" => details.image_tokens += detail.token_count,
        "TEXT" => details.text_tokens += detail.token_count,
        _ => {}
    }
}
