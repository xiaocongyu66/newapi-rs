//! Go `internal/relay/common/estimate_tokens.go` + `summarize_usage.go` +
//! `dto.Usage`（openai_response.go:223-267）的移植：适配器层计费用量结构与
//! 本地 token 估算。

use serde::{Deserialize, Serialize};

/// Go `dto.InputTokenDetails`（openai_response.go:256-267）。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct InputTokenDetails {
    #[serde(rename = "cached_tokens")]
    pub cached_tokens: i64,
    #[serde(rename = "cached_creation_tokens", skip_serializing_if = "is_zero")]
    pub cached_creation_tokens: i64,
    #[serde(rename = "cache_write_tokens", skip_serializing_if = "is_zero")]
    pub cache_write_tokens: i64,
    #[serde(rename = "text_tokens")]
    pub text_tokens: i64,
    #[serde(rename = "audio_tokens")]
    pub audio_tokens: i64,
    #[serde(rename = "image_tokens")]
    pub image_tokens: i64,
}

/// Go `dto.OutputTokenDetails`（同文件，reasoning/text/image/audio）。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OutputTokenDetails {
    #[serde(rename = "reasoning_tokens", skip_serializing_if = "is_zero")]
    pub reasoning_tokens: i64,
    #[serde(rename = "text_tokens", skip_serializing_if = "is_zero")]
    pub text_tokens: i64,
    #[serde(rename = "audio_tokens", skip_serializing_if = "is_zero")]
    pub audio_tokens: i64,
    #[serde(rename = "image_tokens", skip_serializing_if = "is_zero")]
    pub image_tokens: i64,
}

fn is_zero(value: &i64) -> bool {
    *value == 0
}

/// Go `dto.Usage`（openai_response.go:223-244）。`billing_usage` 以原始 JSON
/// 透传——结算语义归 billing 切片所有。
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Usage {
    #[serde(rename = "prompt_tokens")]
    pub prompt_tokens: i64,
    #[serde(rename = "completion_tokens")]
    pub completion_tokens: i64,
    #[serde(rename = "total_tokens")]
    pub total_tokens: i64,
    #[serde(rename = "prompt_cache_hit_tokens", skip_serializing_if = "is_zero")]
    pub prompt_cache_hit_tokens: i64,
    #[serde(rename = "usage_semantic", skip_serializing_if = "String::is_empty")]
    pub usage_semantic: String,
    #[serde(rename = "usage_source", skip_serializing_if = "String::is_empty")]
    pub usage_source: String,
    #[serde(rename = "billing_usage", skip_serializing_if = "Option::is_none")]
    pub billing_usage: Option<serde_json::Value>,
    #[serde(rename = "prompt_tokens_details")]
    pub prompt_tokens_details: InputTokenDetails,
    #[serde(rename = "completion_tokens_details")]
    pub completion_token_details: OutputTokenDetails,
    #[serde(rename = "input_tokens")]
    pub input_tokens: i64,
    #[serde(rename = "output_tokens")]
    pub output_tokens: i64,
    #[serde(
        rename = "input_tokens_details",
        skip_serializing_if = "Option::is_none"
    )]
    pub input_tokens_details: Option<InputTokenDetails>,
    #[serde(
        rename = "claude_cache_creation_5_m_tokens",
        skip_serializing_if = "is_zero"
    )]
    pub claude_cache_creation_5m_tokens: i64,
    #[serde(
        rename = "claude_cache_creation_1_h_tokens",
        skip_serializing_if = "is_zero"
    )]
    pub claude_cache_creation_1h_tokens: i64,
    #[serde(rename = "cost", skip_serializing_if = "Option::is_none")]
    pub cost: Option<serde_json::Value>,
}

/// Go `dto.ClaudeUsage`（claude.go:551-562）。
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClaudeUsage {
    #[serde(rename = "input_tokens")]
    pub input_tokens: i64,
    #[serde(rename = "cache_creation_input_tokens")]
    pub cache_creation_input_tokens: i64,
    #[serde(rename = "cache_read_input_tokens")]
    pub cache_read_input_tokens: i64,
    #[serde(rename = "output_tokens")]
    pub output_tokens: i64,
    #[serde(rename = "cache_creation", skip_serializing_if = "Option::is_none")]
    pub cache_creation: Option<ClaudeCacheCreationUsage>,
    #[serde(
        rename = "claude_cache_creation_5_m_tokens",
        skip_serializing_if = "is_zero"
    )]
    pub claude_cache_creation_5m_tokens: i64,
    #[serde(
        rename = "claude_cache_creation_1_h_tokens",
        skip_serializing_if = "is_zero"
    )]
    pub claude_cache_creation_1h_tokens: i64,
    #[serde(rename = "server_tool_use", skip_serializing_if = "Option::is_none")]
    pub server_tool_use: Option<ClaudeServerToolUse>,
    #[serde(rename = "billing_usage", skip_serializing_if = "Option::is_none")]
    pub billing_usage: Option<serde_json::Value>,
}

/// Go `dto.ClaudeCacheCreationUsage`。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClaudeCacheCreationUsage {
    #[serde(rename = "ephemeral_5m_input_tokens", skip_serializing_if = "is_zero")]
    pub ephemeral_5m_input_tokens: i64,
    #[serde(rename = "ephemeral_1h_input_tokens", skip_serializing_if = "is_zero")]
    pub ephemeral_1h_input_tokens: i64,
}

/// Go `dto.ClaudeServerToolUse`。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClaudeServerToolUse {
    #[serde(rename = "web_search_requests")]
    pub web_search_requests: i64,
}

impl ClaudeUsage {
    /// Go `ClaudeUsage.GetCacheCreation5mTokens`：CacheCreation 缺省时回退到
    /// 顶层 5m 字段。
    pub fn get_cache_creation_5m_tokens(&self) -> i64 {
        match &self.cache_creation {
            Some(cache) => cache.ephemeral_5m_input_tokens,
            None => self.claude_cache_creation_5m_tokens,
        }
    }

    /// Go `ClaudeUsage.GetCacheCreation1hTokens`。
    pub fn get_cache_creation_1h_tokens(&self) -> i64 {
        match &self.cache_creation {
            Some(cache) => cache.ephemeral_1h_input_tokens,
            None => self.claude_cache_creation_1h_tokens,
        }
    }
}

/// Go `dto.HasClaudeUsageTokens`（billing_usage.go:33-52）。
pub fn has_claude_usage_tokens(usage: Option<&ClaudeUsage>) -> bool {
    let Some(usage) = usage else {
        return false;
    };
    if usage.input_tokens != 0
        || usage.output_tokens != 0
        || usage.cache_creation_input_tokens != 0
        || usage.cache_read_input_tokens != 0
        || usage.claude_cache_creation_5m_tokens != 0
        || usage.claude_cache_creation_1h_tokens != 0
    {
        return true;
    }
    if let Some(cache) = &usage.cache_creation
        && (cache.ephemeral_5m_input_tokens != 0 || cache.ephemeral_1h_input_tokens != 0)
    {
        return true;
    }
    false
}

/// Go `dto.HasOpenAIUsageTokens`（billing_usage.go:63-99）。
pub fn has_openai_usage_tokens(usage: &Usage) -> bool {
    if usage.prompt_tokens != 0
        || usage.completion_tokens != 0
        || usage.total_tokens != 0
        || usage.input_tokens != 0
        || usage.output_tokens != 0
        || usage.prompt_cache_hit_tokens != 0
        || usage.claude_cache_creation_5m_tokens != 0
        || usage.claude_cache_creation_1h_tokens != 0
    {
        return true;
    }
    let p = &usage.prompt_tokens_details;
    if p.cached_tokens != 0
        || p.cached_creation_tokens != 0
        || p.cache_write_tokens != 0
        || p.text_tokens != 0
        || p.image_tokens != 0
        || p.audio_tokens != 0
    {
        return true;
    }
    let c = &usage.completion_token_details;
    if c.reasoning_tokens != 0 || c.text_tokens != 0 || c.image_tokens != 0 || c.audio_tokens != 0 {
        return true;
    }
    usage.input_tokens_details.is_some()
}

/// Go `dto.HasGeminiUsageMetadataTokens`（billing_usage.go:190-214）。
pub fn has_gemini_usage_metadata_tokens(metadata: Option<&GeminiUsageMetadata>) -> bool {
    let Some(metadata) = metadata else {
        return false;
    };
    if metadata.prompt_token_count != 0
        || metadata.tool_use_prompt_token_count != 0
        || metadata.candidates_token_count != 0
        || metadata.total_token_count != 0
        || metadata.thoughts_token_count != 0
        || metadata.cached_content_token_count != 0
    {
        return true;
    }
    metadata
        .prompt_tokens_details
        .iter()
        .any(|detail| detail.token_count != 0)
}

/// Go `dto.GeminiUsageMetadata`（gemini.go:502-513）。
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GeminiUsageMetadata {
    #[serde(rename = "promptTokenCount")]
    pub prompt_token_count: i64,
    #[serde(rename = "toolUsePromptTokenCount")]
    pub tool_use_prompt_token_count: i64,
    #[serde(rename = "candidatesTokenCount")]
    pub candidates_token_count: i64,
    #[serde(rename = "totalTokenCount")]
    pub total_token_count: i64,
    #[serde(rename = "thoughtsTokenCount")]
    pub thoughts_token_count: i64,
    #[serde(rename = "cachedContentTokenCount")]
    pub cached_content_token_count: i64,
    #[serde(rename = "promptTokensDetails")]
    pub prompt_tokens_details: Vec<GeminiPromptTokensDetails>,
    #[serde(rename = "toolUsePromptTokensDetails")]
    pub tool_use_prompt_tokens_details: Vec<GeminiPromptTokensDetails>,
    #[serde(rename = "candidatesTokensDetails")]
    pub candidates_tokens_details: Vec<GeminiPromptTokensDetails>,
    #[serde(rename = "billing_usage", skip_serializing_if = "Option::is_none")]
    pub billing_usage: Option<serde_json::Value>,
}

/// Go `dto.GeminiPromptTokensDetails`。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GeminiPromptTokensDetails {
    #[serde(rename = "modality")]
    pub modality: String,
    #[serde(rename = "tokenCount")]
    pub token_count: i64,
}

/// Go `dto.BillingUsage` 的来源/语义常量（billing_usage.go:4-11）。
pub mod billing_usage {
    pub const SOURCE_CLAUDE_MESSAGES: &str = "claude_messages";
    pub const SOURCE_GEMINI_CHAT: &str = "gemini_chat";
    pub const SOURCE_OAI_CHAT: &str = "oai_chat";
    pub const SEMANTIC_ANTHROPIC: &str = "anthropic";
    pub const SEMANTIC_GEMINI: &str = "gemini";
    pub const SEMANTIC_OPENAI: &str = "openai";
}

/// Go `dto.NewClaudeMessagesBillingUsage`（billing_usage.go:23-31）：无 token 时
/// 返回 None。
pub fn new_claude_messages_billing_usage(usage: Option<&ClaudeUsage>) -> Option<serde_json::Value> {
    if !has_claude_usage_tokens(usage) {
        return None;
    }
    let usage = usage?;
    Some(serde_json::json!({
        "source": billing_usage::SOURCE_CLAUDE_MESSAGES,
        "semantic": billing_usage::SEMANTIC_ANTHROPIC,
        "claude_usage": usage,
    }))
}

/// Go `dto.NewGeminiChatBillingUsage` / `newGeminiChatBillingUsage(metadata, false)`。
pub fn new_gemini_chat_billing_usage(
    metadata: Option<&GeminiUsageMetadata>,
) -> Option<serde_json::Value> {
    new_gemini_chat_billing_usage_inner(metadata, false)
}

/// Go `dto.NewEstimatedGeminiChatBillingUsage`（billing_usage.go:110-124）。
pub fn new_estimated_gemini_chat_billing_usage(usage: &Usage) -> Option<serde_json::Value> {
    let total_tokens = if usage.total_tokens == 0 {
        usage.prompt_tokens + usage.completion_tokens
    } else {
        usage.total_tokens
    };
    new_gemini_chat_billing_usage_inner(
        Some(&GeminiUsageMetadata {
            prompt_token_count: usage.prompt_tokens,
            candidates_token_count: usage.completion_tokens,
            total_token_count: total_tokens,
            ..GeminiUsageMetadata::default()
        }),
        true,
    )
}

fn new_gemini_chat_billing_usage_inner(
    metadata: Option<&GeminiUsageMetadata>,
    estimated: bool,
) -> Option<serde_json::Value> {
    if !has_gemini_usage_metadata_tokens(metadata) {
        return None;
    }
    let mut body = serde_json::json!({
        "source": billing_usage::SOURCE_GEMINI_CHAT,
        "semantic": billing_usage::SEMANTIC_GEMINI,
        "estimated": estimated,
        "gemini_usage_metadata": metadata,
    });
    if !estimated {
        // Go 的非 estimated 路径不写 estimated 字段（omitempty 风格保持一致）。
        body.as_object_mut()
            .expect("json! always produces an object")
            .remove("estimated");
    }
    Some(body)
}

/// Go `relaycommon.ValidUsage`（summarize_usage.go:32-34）。
pub fn valid_usage(usage: &Usage) -> bool {
    usage.prompt_tokens != 0 || usage.completion_tokens != 0
}

/// Go `relaycommon.CountTextToken`（count_tokens.go:400-411）。
///
/// 已知偏差：Go 对 OpenAI 文本模型走 tiktoken 精确编码，纯 crate 不引入
/// tiktoken 依赖，统一走 [`estimate_token_by_model`] 估算（Go 对非 OpenAI
/// 模型同样使用该估算，权重表逐字移植）。
pub fn count_text_token(text: &str, model: &str) -> i64 {
    if text.is_empty() {
        return 0;
    }
    estimate_token_by_model(model, text)
}

/// Go `common.EstimateTokenByModel`（estimate_tokens.go:216-230）。
pub fn estimate_token_by_model(model: &str, text: &str) -> i64 {
    if text.is_empty() {
        return 0;
    }
    let model = model.to_lowercase();
    if model.contains("gemini") {
        estimate_token(Provider::Gemini, text)
    } else if model.contains("claude") {
        estimate_token(Provider::Claude, text)
    } else {
        estimate_token(Provider::OpenAI, text)
    }
}

/// Go `relaycommon.ResponseText2Usage`（summarize_usage.go:23-30）：置
/// `local_count_tokens` 上下文并返回估算 usage。
pub fn response_text_2_usage(
    sink: &mut dyn crate::adaptor_common::ClientSink,
    response_text: &str,
    model_name: &str,
    prompt_tokens: i64,
) -> Usage {
    sink.set_context("local_count_tokens", serde_json::Value::Bool(true));
    let completion_tokens = estimate_token_by_model(model_name, response_text);
    Usage {
        prompt_tokens,
        completion_tokens,
        total_tokens: prompt_tokens + completion_tokens,
        ..Usage::default()
    }
}

/// Go `relaycommon.ResponseText2Usage` 的无上下文变体（纯计算）。
pub fn response_text_2_usage_pure(
    response_text: &str,
    model_name: &str,
    prompt_tokens: i64,
) -> Usage {
    let completion_tokens = estimate_token_by_model(model_name, response_text);
    Usage {
        prompt_tokens,
        completion_tokens,
        total_tokens: prompt_tokens + completion_tokens,
        ..Usage::default()
    }
}

/// Go `common.Provider`（estimate_tokens.go:13-18）。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Provider {
    OpenAI,
    Gemini,
    Claude,
}

/// Go `multipliers`（estimate_tokens.go:20-58 的权重表，逐字对齐）。
struct Multipliers {
    word: f64,
    number: f64,
    cjk: f64,
    symbol: f64,
    math_symbol: f64,
    url_delim: f64,
    at_sign: f64,
    emoji: f64,
    newline: f64,
    space: f64,
    base_pad: i64,
}

const GEMINI_MULTIPLIERS: Multipliers = Multipliers {
    word: 1.15,
    number: 2.8,
    cjk: 0.68,
    symbol: 0.38,
    math_symbol: 1.05,
    url_delim: 1.2,
    at_sign: 2.5,
    emoji: 1.08,
    newline: 1.15,
    space: 0.2,
    base_pad: 0,
};

const CLAUDE_MULTIPLIERS: Multipliers = Multipliers {
    word: 1.13,
    number: 1.63,
    cjk: 1.21,
    symbol: 0.4,
    math_symbol: 4.52,
    url_delim: 1.26,
    at_sign: 2.82,
    emoji: 2.6,
    newline: 0.89,
    space: 0.39,
    base_pad: 0,
};

const OPENAI_MULTIPLIERS: Multipliers = Multipliers {
    word: 1.02,
    number: 1.55,
    cjk: 0.85,
    symbol: 0.4,
    math_symbol: 2.68,
    url_delim: 1.0,
    at_sign: 2.0,
    emoji: 2.12,
    newline: 0.5,
    space: 0.42,
    base_pad: 0,
};

fn get_multipliers(provider: Provider) -> &'static Multipliers {
    match provider {
        Provider::Gemini => &GEMINI_MULTIPLIERS,
        Provider::Claude => &CLAUDE_MULTIPLIERS,
        Provider::OpenAI => &OPENAI_MULTIPLIERS,
    }
}

/// Go `EstimateToken`（estimate_tokens.go:85-158）：按权重状态机估算。
pub fn estimate_token(provider: Provider, text: &str) -> i64 {
    let m = get_multipliers(provider);
    let mut count: f64 = 0.0;

    #[derive(Clone, Copy, PartialEq)]
    enum WordType {
        None,
        Latin,
        Number,
    }
    let mut current_word_type = WordType::None;

    for r in text.chars() {
        // 1. 空白字符
        if r.is_whitespace() {
            current_word_type = WordType::None;
            if r == '\n' || r == '\t' {
                count += m.newline;
            } else {
                count += m.space;
            }
            continue;
        }

        // 2. CJK 按字符计费
        if is_cjk(r) {
            current_word_type = WordType::None;
            count += m.cjk;
            continue;
        }

        // 3. Emoji
        if is_emoji(r) {
            current_word_type = WordType::None;
            count += m.emoji;
            continue;
        }

        // 4. 拉丁字母/数字（单词切分）
        if r.is_alphabetic() || r.is_numeric() {
            let new_type = if r.is_numeric() {
                WordType::Number
            } else {
                WordType::Latin
            };
            if current_word_type == WordType::None || current_word_type != new_type {
                if new_type == WordType::Number {
                    count += m.number;
                } else {
                    count += m.word;
                }
                current_word_type = new_type;
            }
            continue;
        }

        // 5. 标点/特殊符号
        current_word_type = WordType::None;
        if is_math_symbol(r) {
            count += m.math_symbol;
        } else if r == '@' {
            count += m.at_sign;
        } else if is_url_delim(r) {
            count += m.url_delim;
        } else {
            count += m.symbol;
        }
    }

    count.ceil() as i64 + m.base_pad
}

/// Go `isCJK`：汉字 + 日文假名 + 韩文音节。
fn is_cjk(r: char) -> bool {
    // unicode.Han
    let han = matches!(r as u32,
        0x2E80..=0x2EFF | 0x2F00..=0x2FDF | 0x3000..=0x303F | 0x31C0..=0x31EF
        | 0x3200..=0x32FF | 0x3400..=0x4DBF | 0x4E00..=0x9FFF | 0xF900..=0xFAFF
        | 0x20000..=0x2A6DF | 0x2A700..=0x2EBEF | 0x2F800..=0x2FA1F);
    han || (0x3040..=0x30FF).contains(&(r as u32)) || (0xAC00..=0xD7A3).contains(&(r as u32))
}

/// Go `isEmoji`：Unicode 表情区段。
fn is_emoji(r: char) -> bool {
    let c = r as u32;
    (0x1F300..=0x1F9FF).contains(&c)
        || (0x2600..=0x26FF).contains(&c)
        || (0x2700..=0x27BF).contains(&c)
        || (0x1F600..=0x1F64F).contains(&c)
        || (0x1FA00..=0x1FAFF).contains(&c)
}

/// Go `isMathSymbol`：数学符号集合 + 三个数学 Unicode 区段。
fn is_math_symbol(r: char) -> bool {
    const MATH_SYMBOLS: &str =
        "∑∫∂√∞≤≥≠≈±×÷∈∉∋∌⊂⊃⊆⊇∪∩∧∨¬∀∃∄∅∆∇∝∟∠∡∢°′″‴⁺⁻⁼⁽⁾ⁿ₀₁₂₃₄₅₆₇₈₉₊₋₌₍₎²³¹⁴⁵⁶⁷⁸⁹⁰";
    if MATH_SYMBOLS.contains(r) {
        return true;
    }
    let c = r as u32;
    (0x2200..=0x22FF).contains(&c)
        || (0x2A00..=0x2AFF).contains(&c)
        || (0x1D400..=0x1D7FF).contains(&c)
}

/// Go `isURLDelim`。
fn is_url_delim(r: char) -> bool {
    "/:?&=;#%".contains(r)
}
