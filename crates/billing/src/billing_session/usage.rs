//! 用量数据形状端口：`relaykit/dto` 中 `Usage` / `BillingUsage` / `RealtimeUsage`
//! 在计费路径上被读取的字段子集（Go `openai_response.go:223-283`、
//! `realtime.go:40-46`）。relay 入口切片负责从真实 DTO 填充这些结构；
//! 计费核心只消费本形状，字段名与 Go JSON tag 一一对应。

use serde_json::{Map, Value};

/// Go `dto.InputTokenDetails`（openai_response.go:256-267）。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct InputTokenDetails {
    pub cached_tokens: i64,
    pub cached_creation_tokens: i64,
    pub cache_write_tokens: i64,
    pub text_tokens: i64,
    pub audio_tokens: i64,
    pub image_tokens: i64,
}

impl InputTokenDetails {
    /// Go `InputTokenDetails.CacheCreationTokensTotal`（openai_response.go:269-284）：
    /// 两个 cache-write 来源取大者，负值钳到 0。
    pub fn cache_creation_tokens_total(&self) -> i64 {
        let mut total = self.cached_creation_tokens;
        if self.cache_write_tokens > total {
            total = self.cache_write_tokens;
        }
        if total < 0 {
            return 0;
        }
        total
    }
}

/// Go `dto.OutputTokenDetails`（text/audio/image/reasoning 细分）。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct OutputTokenDetails {
    pub text_tokens: i64,
    pub audio_tokens: i64,
    pub image_tokens: i64,
    pub reasoning_tokens: i64,
}

/// Go `dto.Usage`（openai_response.go:223-244）计费读取面。
#[derive(Debug, Clone, Default)]
pub struct Usage {
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub total_tokens: i64,
    pub usage_semantic: String,
    pub usage_source: String,
    pub billing_usage: Option<BillingUsage>,
    pub prompt_tokens_details: InputTokenDetails,
    pub completion_token_details: OutputTokenDetails,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub claude_cache_creation_5m_tokens: i64,
    pub claude_cache_creation_1h_tokens: i64,
    /// Go `Cost any`：OpenRouter 真实成本（美元），仅 float64 形态参与计费。
    pub cost: f64,
}

/// Go `dto.BillingUsage` 的计费读取面（classify_usage_path.go 的输入）。
#[derive(Debug, Clone, Default)]
pub struct BillingUsage {
    pub source: String,
    pub semantic: String,
    pub estimated: bool,
    pub openai_usage: Option<Box<Usage>>,
    pub claude_usage: Option<ClaudeBillingUsage>,
    pub gemini_usage_metadata: Option<GeminiUsageMetadata>,
}

/// Go `dto.ClaudeBillingUsage` 的计费读取面。
#[derive(Debug, Clone, Default)]
pub struct ClaudeBillingUsage {
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cache_read_input_tokens: i64,
    pub cache_creation_input_tokens: i64,
    /// `GetCacheCreation5mTokens()`（server_tools 计算值）；为 0 时回退原始字段。
    pub cache_creation_5m_tokens: i64,
    /// Go `ClaudeCacheCreation5mTokens` 原始字段。
    pub claude_cache_creation_5m_tokens: i64,
    pub cache_creation_1h_tokens: i64,
    pub claude_cache_creation_1h_tokens: i64,
}

/// Go `dto.GeminiUsageMetadata` 的计费读取面。
#[derive(Debug, Clone, Default)]
pub struct GeminiUsageMetadata {
    pub prompt_token_count: i64,
    pub candidates_token_count: i64,
    pub total_token_count: i64,
    pub thoughts_token_count: i64,
    pub tool_use_prompt_token_count: i64,
    pub cached_content_token_count: i64,
    pub prompt_tokens_details: Vec<GeminiModalityTokenCount>,
    pub tool_use_prompt_tokens_details: Vec<GeminiModalityTokenCount>,
    pub candidates_tokens_details: Vec<GeminiModalityTokenCount>,
}

/// Go `dto.GeminiPromptTokensDetails`：`(modality, token_count)`。
#[derive(Debug, Clone, Default)]
pub struct GeminiModalityTokenCount {
    pub modality: String,
    pub token_count: i64,
}

/// Go `dto.RealtimeUsage`（realtime.go:40-46）。
#[derive(Debug, Clone, Default)]
pub struct RealtimeUsage {
    pub total_tokens: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub input_token_details: InputTokenDetails,
    pub output_token_details: OutputTokenDetails,
}

/// 内置工具计费项名称。Go `dto.BuildInTool*` 常量。
pub const BUILD_IN_TOOL_WEB_SEARCH: &str = "web_search";
pub const BUILD_IN_TOOL_WEB_SEARCH_PREVIEW: &str = "web_search_preview";
pub const BUILD_IN_TOOL_GOOGLE_SEARCH: &str = "google_search";

/// 计费语义 / 来源常量（Go `dto.BillingUsageSemantic*` / `BillingUsageSource*`）。
pub const SEMANTIC_OPENAI: &str = "openai";
pub const SEMANTIC_ANTHROPIC: &str = "anthropic";
pub const SEMANTIC_GEMINI: &str = "gemini";
pub const SOURCE_OAI_CHAT: &str = "oaichat";
pub const SOURCE_OAI_RESPONSES: &str = "oairesponses";
pub const SOURCE_CLAUDE_MESSAGES: &str = "claudemessages";
pub const SOURCE_GEMINI_CHAT: &str = "geminichat";

/// 把增强字段写进日志 `other` map 的帮助函数（与 Go 键名一致）。
pub fn other_insert(other: &mut Map<String, Value>, key: &str, value: Value) {
    other.insert(key.to_string(), value);
}
