//! Go `internal/relay/common/build_relay_info.go` 的移植（核心字段与构建路径）。
//!
//! 契约要点：
//! - 字段全集见 [`RelayInfo`]；Go 嵌入结构（ThinkingContentInfo、TokenCountMeta、
//!   ChannelMeta 等）在 Rust 中平铺/Option 化。
//! - `genBaseRelayInfo` 从上下文快照 [`RelayInfoInput`] 构建，token 分组为空时
//!   回退用户分组；`/pg` 前缀改写为 `/v1`。
//! - 各 `GenRelayInfo*` 构造器逐一对齐，含 ShouldIncludeUsage / ClaudeConvertInfo
//!   等格式特有初值。
//! - `RequestConversionChain` 语义：初始 = `[RelayFormat]`；append 去重尾部；
//!   `GetFinalRequestRelayFormat` 回退链尾 → RelayFormat。

use serde::{Deserialize, Serialize};

/// Go `types.RelayFormat`（relaykit）使用的格式串；Rust 侧直接以字符串常量
/// 表示，与 Go 契约逐字一致。
pub mod relay_format {
    pub const OPENAI: &str = "openai";
    pub const OPENAI_AUDIO: &str = "openai_audio";
    pub const OPENAI_IMAGE: &str = "openai_image";
    pub const OPENAI_REALTIME: &str = "openai_realtime";
    pub const CLAUDE: &str = "claude";
    pub const RERANK: &str = "rerank";
    pub const GEMINI: &str = "gemini";
    pub const EMBEDDING: &str = "embedding";
    pub const OPENAI_RESPONSES: &str = "openai_responses";
    pub const OPENAI_RESPONSES_COMPACTION: &str = "openai_responses_compaction";
    pub const OPENAI_ALPHA_SEARCH: &str = "openai_alpha_search";
    pub const TASK: &str = "task";
    pub const MJ_PROXY: &str = "mjproxy";
}

/// Go `convmeta.LastMessageType*` 常量。
pub mod last_message_type {
    pub const NONE: &str = "none";
    pub const TEXT: &str = "text";
    pub const TOOLS: &str = "tools";
    pub const THINKING: &str = "thinking";
}

/// Go `RelayInfo` 中与客户端识别无关的核心字段（build_relay_info.go:91-202 的
/// 平铺移植）。计费/订阅/流状态等运行时字段由各消费切片持有，此处保留
/// 预扣费与重试字段以便端口契约完整。
#[derive(Clone, Debug, Default)]
pub struct RelayInfo {
    pub token_id: i64,
    pub token_key: String,
    /// 令牌指定分组；为空表示使用用户分组（genBaseRelayInfo 语义）。
    pub token_group: String,
    pub user_id: i64,
    /// 使用的分组（auto 跨分组重试时会变动）。
    pub using_group: String,
    /// 用户所在分组。
    pub user_group: String,
    pub token_unlimited: bool,
    /// Unix 毫秒；Go 用 time.Time，纯 crate 内以时间戳表示。
    pub start_time_ms: i64,
    /// Unix 毫秒；初值 = start_time - 1000（Go 的 -1 秒回退值）。
    pub first_response_time_ms: i64,
    pub is_first_response: bool,
    pub is_stream: bool,
    pub is_gemini_batch_embedding: bool,
    pub is_playground: bool,
    pub realtime_charged_quota: i64,
    pub relay_mode: i32,
    pub origin_model_name: String,
    pub request_url_path: String,
    /// 归一化后的请求头（去空白值、TrimSpace，Go cloneRequestHeaders）。
    pub request_headers: Vec<(String, String)>,
    pub should_include_usage: bool,
    pub disable_ping: bool,
    pub input_audio_format: String,
    pub output_audio_format: String,
    pub is_first_request: bool,
    pub audio_usage: bool,
    pub reasoning_effort: String,
    pub user_email: String,
    pub user_quota: i64,
    pub user_setting_raw: serde_json::Value,
    pub relay_format: String,
    pub send_response_count: i64,
    pub received_response_count: i64,
    pub final_pre_consumed_quota: i64,
    /// true 时禁用计费会话的信任额度旁路（异步任务锁定全额）。
    pub force_pre_consume: bool,
    /// "" 或 "wallet" => 钱包；"subscription" => 订阅。
    pub billing_source: String,
    pub subscription_id: i64,
    pub subscription_pre_consumed: i64,
    pub subscription_post_delta: i64,
    pub subscription_plan_id: i64,
    pub subscription_plan_title: String,
    /// 幂等预扣费/退款使用的请求 ID。
    pub request_id: String,
    pub is_claude_beta_query: bool,
    pub is_channel_test: bool,
    pub retry_index: i32,
    /// 上一次失败错误摘要（Go *types.NewAPIError 的运行时简化）。
    pub last_error: Option<LastErrorSummary>,
    pub runtime_headers_override: Vec<(String, String)>,
    pub use_runtime_headers_override: bool,
    pub param_override_audit: Vec<String>,

    pub request_conversion_chain: Vec<String>,
    pub final_request_relay_format: String,

    // ---- 嵌入结构平铺 ----
    /// ThinkingContentInfo.IsFirstThinkingContent。
    pub is_first_thinking_content: bool,
    /// ThinkingContentInfo.SendLastThinkingContent。
    pub send_last_thinking_content: bool,
    /// ThinkingContentInfo.HasSentThinkingContent。
    pub has_sent_thinking_content: bool,
    /// TokenCountMeta.estimatePromptTokens。
    pub estimate_prompt_tokens: i64,
    /// RerankerInfo（Rerank 格式专属）。
    pub reranker_documents: Option<serde_json::Value>,
    pub reranker_return_documents: bool,
    /// ResponsesUsageInfo.BuiltInTools：tool type → (call_count, search_context_size)。
    pub responses_builtin_tools: Vec<BuiltInToolInfo>,
    /// ClaudeConvertInfo.LastMessagesType。
    pub claude_last_messages_type: Option<String>,

    // ---- ChannelMeta ----
    pub channel_meta: Option<ChannelMeta>,
}

/// Go `LastErrorSummary` 占位：ParamOverride 上下文的 `last_error` 字段来源。
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LastErrorSummary {
    pub status_code: i32,
    pub message: String,
    pub code: String,
    pub error_type: String,
    pub skip_retry: bool,
}

/// Go `BuildInToolInfo`（build_relay_info.go:56-60）。
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BuiltInToolInfo {
    pub tool_name: String,
    pub call_count: i64,
    pub search_context_size: String,
}

/// Go `ChannelMeta`（build_relay_info.go:66-84）。
#[derive(Clone, Debug, Default)]
pub struct ChannelMeta {
    pub channel_type: i32,
    pub channel_id: i64,
    pub channel_is_multi_key: bool,
    pub channel_multi_key_index: i64,
    pub channel_base_url: String,
    pub api_type: i32,
    pub api_version: String,
    pub api_key: String,
    pub organization: String,
    pub channel_create_time: i64,
    pub param_override: serde_json::Value,
    pub headers_override: serde_json::Value,
    pub channel_setting: serde_json::Value,
    pub channel_other_settings: serde_json::Value,
    pub upstream_model_name: String,
    pub is_model_mapped: bool,
    pub support_stream_options: bool,
}

/// 上下文快照：Go `genBaseRelayInfo` 从 contract.Context 读取的键集合。
/// 服务装配层负责把真实请求上下文折叠成此结构。
#[derive(Clone, Debug, Default)]
pub struct RelayInfoInput {
    pub token_group: String,
    pub user_group: String,
    pub request_start_time_ms: i64,
    pub request_id: String,
    pub user_id: i64,
    pub using_group: String,
    pub user_quota: i64,
    pub user_email: String,
    pub origin_model_name: String,
    pub token_id: i64,
    pub token_key: String,
    pub token_unlimited: bool,
    pub path: String,
    pub request_uri: String,
    pub request_headers: Vec<(String, String)>,
    pub estimated_tokens: i64,
    pub user_setting_raw: serde_json::Value,
    /// Go `c.GetInt("relay_mode")` 兜底。
    pub relay_mode_fallback: i32,
    /// 请求体是否声明流式（Go `request.IsStream(...)`）。
    pub is_stream: bool,
}

/// Go `genBaseRelayInfo`（build_relay_info.go:494-581）。
pub fn gen_base_relay_info(input: &RelayInfoInput) -> RelayInfo {
    // 当令牌分组为空时，表示使用用户分组。
    let token_group = if input.token_group.is_empty() {
        input.user_group.clone()
    } else {
        input.token_group.clone()
    };

    let start_time_ms = if input.request_start_time_ms == 0 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or_default()
    } else {
        input.request_start_time_ms
    };

    let mut relay_mode = crate::relay_mode::path_to_relay_mode(&input.path);
    if relay_mode == crate::relay_mode::RELAY_MODE_UNKNOWN {
        relay_mode = input.relay_mode_fallback;
    }

    let mut request_url_path = input.request_uri.clone();
    let is_playground = input.path.starts_with("/pg");
    if is_playground {
        request_url_path = request_url_path
            .strip_prefix("/pg")
            .unwrap_or(&request_url_path)
            .to_owned();
        request_url_path = format!("/v1{request_url_path}");
    }

    RelayInfo {
        request_id: if input.request_id.is_empty() {
            // Go common.NewRequestId() 生成 32 位随机 hex；此处由服务层注入，
            // 纯构建器仅保留空串占位以免引入随机性依赖。
            String::new()
        } else {
            input.request_id.clone()
        },
        user_id: input.user_id,
        using_group: input.using_group.clone(),
        user_group: input.user_group.clone(),
        user_quota: input.user_quota,
        user_email: input.user_email.clone(),
        origin_model_name: input.origin_model_name.clone(),
        token_id: input.token_id,
        token_key: input.token_key.clone(),
        token_unlimited: input.token_unlimited,
        token_group,
        is_first_response: true,
        relay_mode,
        request_url_path,
        request_headers: clone_request_headers(&input.request_headers),
        is_stream: input.is_stream,
        start_time_ms,
        // Go: startTime.Add(-time.Second)。
        first_response_time_ms: start_time_ms - 1000,
        is_first_thinking_content: true,
        send_last_thinking_content: false,
        estimate_prompt_tokens: input.estimated_tokens,
        is_playground,
        user_setting_raw: input.user_setting_raw.clone(),
        ..RelayInfo::default()
    }
}

/// Go `cloneRequestHeaders`（build_relay_info.go:583-603）：TrimSpace，去空值；
/// 全空时返回空 Vec。
fn clone_request_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(k, v)| (k.clone(), v.trim().to_owned()))
        .filter(|(_, v)| !v.is_empty())
        .collect()
}

/// Go `GenRelayInfoOpenAI`。
pub fn gen_relay_info_openai(input: &RelayInfoInput) -> RelayInfo {
    let mut info = gen_base_relay_info(input);
    info.relay_format = relay_format::OPENAI.to_owned();
    info
}

/// Go `GenRelayInfoOpenAIAudio`。
pub fn gen_relay_info_openai_audio(input: &RelayInfoInput) -> RelayInfo {
    let mut info = gen_base_relay_info(input);
    info.relay_format = relay_format::OPENAI_AUDIO.to_owned();
    info
}

/// Go `GenRelayInfoImage`。
pub fn gen_relay_info_image(input: &RelayInfoInput) -> RelayInfo {
    let mut info = gen_base_relay_info(input);
    info.relay_format = relay_format::OPENAI_IMAGE.to_owned();
    info
}

/// Go `GenRelayInfoWs`。
pub fn gen_relay_info_ws(input: &RelayInfoInput) -> RelayInfo {
    let mut info = gen_base_relay_info(input);
    info.relay_format = relay_format::OPENAI_REALTIME.to_owned();
    info.input_audio_format = "pcm16".to_owned();
    info.output_audio_format = "pcm16".to_owned();
    info.is_first_request = true;
    info
}

/// Go `GenRelayInfoClaude`。
pub fn gen_relay_info_claude(input: &RelayInfoInput) -> RelayInfo {
    let mut info = gen_base_relay_info(input);
    info.relay_format = relay_format::CLAUDE.to_owned();
    info.should_include_usage = false;
    info.claude_last_messages_type = Some(last_message_type::NONE.to_owned());
    info.is_claude_beta_query = false; // query beta=true 由装配层传入
    info
}

/// Go `GenRelayInfoClaude` 的 beta 查询参数变体。
pub fn gen_relay_info_claude_with_beta(input: &RelayInfoInput, beta: bool) -> RelayInfo {
    let mut info = gen_relay_info_claude(input);
    info.is_claude_beta_query = beta;
    info
}

/// Go `GenRelayInfoRerank`。
pub fn gen_relay_info_rerank(
    input: &RelayInfoInput,
    documents: serde_json::Value,
    return_documents: bool,
) -> RelayInfo {
    let mut info = gen_base_relay_info(input);
    info.relay_mode = crate::relay_mode::RELAY_MODE_RERANK;
    info.relay_format = relay_format::RERANK.to_owned();
    info.reranker_documents = Some(documents);
    info.reranker_return_documents = return_documents;
    info
}

/// Go `GenRelayInfoEmbedding`。
pub fn gen_relay_info_embedding(input: &RelayInfoInput) -> RelayInfo {
    let mut info = gen_base_relay_info(input);
    info.relay_format = relay_format::EMBEDDING.to_owned();
    info
}

/// Go `GenRelayInfoGemini`。
pub fn gen_relay_info_gemini(input: &RelayInfoInput) -> RelayInfo {
    let mut info = gen_base_relay_info(input);
    info.relay_format = relay_format::GEMINI.to_owned();
    info.should_include_usage = false;
    info
}

/// Go `GenRelayInfoResponses`：内置工具表按 `tools[].type` 建，web_search_preview
/// 的 search_context_size 缺省 "medium"。
pub fn gen_relay_info_responses(input: &RelayInfoInput, tools: &[serde_json::Value]) -> RelayInfo {
    let mut info = gen_base_relay_info(input);
    info.relay_mode = crate::relay_mode::RELAY_MODE_RESPONSES;
    info.relay_format = relay_format::OPENAI_RESPONSES.to_owned();
    for tool in tools {
        let Some(tool_type) = tool.get("type").and_then(|v| v.as_str()) else {
            continue;
        };
        let mut entry = BuiltInToolInfo {
            tool_name: tool_type.to_owned(),
            ..BuiltInToolInfo::default()
        };
        if tool_type == "web_search_preview" {
            let size = tool
                .get("search_context_size")
                .and_then(|v| v.as_str())
                .unwrap_or("medium");
            if size.is_empty() {
                entry.search_context_size = "medium".to_owned();
            } else {
                entry.search_context_size = size.to_owned();
            }
        }
        info.responses_builtin_tools.push(entry);
    }
    info
}

/// Go `GenRelayInfoResponsesCompaction`。
pub fn gen_relay_info_responses_compaction(input: &RelayInfoInput) -> RelayInfo {
    let mut info = gen_base_relay_info(input);
    if info.relay_mode == crate::relay_mode::RELAY_MODE_UNKNOWN {
        info.relay_mode = crate::relay_mode::RELAY_MODE_RESPONSES_COMPACT;
    }
    info.relay_format = relay_format::OPENAI_RESPONSES_COMPACTION.to_owned();
    info
}

/// Go `GenRelayInfoAlphaSearch`。
pub fn gen_relay_info_alpha_search(input: &RelayInfoInput) -> RelayInfo {
    let mut info = gen_base_relay_info(input);
    if info.relay_mode == crate::relay_mode::RELAY_MODE_UNKNOWN {
        info.relay_mode = crate::relay_mode::RELAY_MODE_ALPHA_SEARCH;
    }
    info.relay_format = relay_format::OPENAI_ALPHA_SEARCH.to_owned();
    info.responses_builtin_tools.push(BuiltInToolInfo {
        tool_name: "web_search_preview".to_owned(),
        ..BuiltInToolInfo::default()
    });
    info
}

/// Go `GenRelayInfo` 的 Task/MjProxy 分支。
pub fn gen_relay_info_task(input: &RelayInfoInput) -> RelayInfo {
    let mut info = gen_base_relay_info(input);
    info.relay_format = relay_format::TASK.to_owned();
    info
}

pub fn gen_relay_info_mj_proxy(input: &RelayInfoInput) -> RelayInfo {
    let mut info = gen_base_relay_info(input);
    info.relay_format = relay_format::MJ_PROXY.to_owned();
    info
}

/// Go `GenRelayInfo`（build_relay_info.go:605-664）的分派入口。返回
/// `ErrUnsupportedRelayFormat` 表示 Go 的 default 分支。
#[derive(Debug, PartialEq)]
pub struct UnsupportedRelayFormat;

/// Go `types.NewAPIError` 的适配器层简化：DoResponse 失败携带的协议错误摘要。
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AdaptorError {
    pub status_code: i32,
    pub message: String,
    pub code: String,
    pub error_type: String,
    pub skip_retry: bool,
}

pub fn gen_relay_info(
    relay_format: &str,
    input: &RelayInfoInput,
    request_payload: &serde_json::Value,
) -> Result<RelayInfo, UnsupportedRelayFormat> {
    let mut info = match relay_format {
        f if f == relay_format::OPENAI => gen_relay_info_openai(input),
        f if f == relay_format::OPENAI_AUDIO => gen_relay_info_openai_audio(input),
        f if f == relay_format::OPENAI_IMAGE => gen_relay_info_image(input),
        f if f == relay_format::OPENAI_REALTIME => gen_relay_info_ws(input),
        f if f == relay_format::CLAUDE => gen_relay_info_claude(input),
        f if f == relay_format::RERANK => gen_relay_info_rerank(
            input,
            request_payload
                .get("documents")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
            request_payload
                .get("return_documents")
                .and_then(|v| v.as_bool())
                .unwrap_or(true),
        ),
        f if f == relay_format::GEMINI => gen_relay_info_gemini(input),
        f if f == relay_format::EMBEDDING => gen_relay_info_embedding(input),
        f if f == relay_format::OPENAI_RESPONSES => {
            let tools = request_payload
                .get("tools")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            gen_relay_info_responses(input, &tools)
        }
        f if f == relay_format::OPENAI_RESPONSES_COMPACTION => {
            gen_relay_info_responses_compaction(input)
        }
        f if f == relay_format::OPENAI_ALPHA_SEARCH => gen_relay_info_alpha_search(input),
        f if f == relay_format::TASK => gen_relay_info_task(input),
        f if f == relay_format::MJ_PROXY => gen_relay_info_mj_proxy(input),
        _ => return Err(UnsupportedRelayFormat),
    };
    info.init_request_conversion_chain();
    Ok(info)
}

impl RelayInfo {
    /// Go `InitRequestConversionChain`。
    pub fn init_request_conversion_chain(&mut self) {
        if !self.request_conversion_chain.is_empty() || self.relay_format.is_empty() {
            return;
        }
        self.request_conversion_chain = vec![self.relay_format.clone()];
    }

    /// Go `AppendRequestConversion`：空格式忽略；链为空时初始化；与尾部相同去重。
    pub fn append_request_conversion(&mut self, format: &str) {
        if format.is_empty() {
            return;
        }
        if self.request_conversion_chain.is_empty() {
            self.request_conversion_chain = vec![format.to_owned()];
            return;
        }
        if self.request_conversion_chain.last() == Some(&format.to_owned()) {
            return;
        }
        self.request_conversion_chain.push(format.to_owned());
    }

    /// Go `GetFinalRequestRelayFormat`：显式 → 链尾 → RelayFormat。
    pub fn get_final_request_relay_format(&self) -> String {
        if !self.final_request_relay_format.is_empty() {
            return self.final_request_relay_format.clone();
        }
        if let Some(last) = self.request_conversion_chain.last() {
            return last.clone();
        }
        self.relay_format.clone()
    }

    /// Go `SetEstimatePromptTokens` / `GetEstimatePromptTokens`。
    pub fn set_estimate_prompt_tokens(&mut self, tokens: i64) {
        self.estimate_prompt_tokens = tokens;
    }

    pub fn get_estimate_prompt_tokens(&self) -> i64 {
        self.estimate_prompt_tokens
    }

    /// Go `SetFirstResponseTime`：仅首次生效。
    pub fn set_first_response_time(&mut self, now_ms: i64) {
        if self.is_first_response {
            self.first_response_time_ms = now_ms;
            self.is_first_response = false;
        }
    }

    /// Go `HasSendResponse`。
    pub fn has_send_response(&self) -> bool {
        self.first_response_time_ms > self.start_time_ms
    }

    /// Go `SetReasoningEffort`（TrimSpace）。
    pub fn set_reasoning_effort(&mut self, effort: &str) {
        self.reasoning_effort = effort.trim().to_owned();
    }

    /// Go `InitChannelMeta`：从渠道上下文快照构建 ChannelMeta。API 版本对
    /// Azure / Vertex 有专门来源（服务层传入 api_version）。
    pub fn init_channel_meta(&mut self, snapshot: ChannelMetaSnapshot) {
        let mut meta = ChannelMeta {
            channel_type: snapshot.channel_type,
            api_type: snapshot.api_type,
            api_version: snapshot.api_version,
            param_override: snapshot.param_override,
            headers_override: snapshot.headers_override,
            channel_setting: snapshot.channel_setting,
            channel_other_settings: snapshot.channel_other_settings,
            upstream_model_name: snapshot.upstream_model_name,
            ..ChannelMeta::default()
        };
        if snapshot.pass_through_request_enabled
            || meta
                .channel_setting
                .get("pass_through_body_enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        {
            self.reasoning_effort = String::new();
        }
        meta.support_stream_options = stream_supported_channels(meta.channel_type);
        self.channel_meta = Some(meta);
    }
}

/// `init_channel_meta` 的输入快照（避免 10 参数函数，见 clippy::too_many_arguments）。
pub struct ChannelMetaSnapshot {
    pub channel_type: i32,
    pub api_type: i32,
    pub api_version: String,
    pub upstream_model_name: String,
    pub param_override: serde_json::Value,
    pub headers_override: serde_json::Value,
    pub channel_setting: serde_json::Value,
    pub channel_other_settings: serde_json::Value,
    pub pass_through_request_enabled: bool,
}

/// Go `streamSupportedChannels`（build_relay_info.go:347-370）。
pub fn stream_supported_channels(channel_type: i32) -> bool {
    use crate::adaptor::channel_type as ct;
    matches!(
        channel_type,
        ct::OPENAI
            | ct::ANTHROPIC
            | ct::AWS
            | ct::GEMINI
            | ct::CLOUDFLARE
            | ct::AZURE
            | ct::VOLC_ENGINE
            | ct::OLLAMA
            | ct::XAI
            | ct::DEEP_SEEK
            | ct::BAIDU_V2
            | ct::ZHIPU_V4
            | ct::ALI
            | ct::SUBMODEL
            | ct::CODEX
            | ct::MOONSHOT
            | ct::MINI_MAX
            | ct::SILICON_FLOW
            | ct::ADVANCED_CUSTOM
            | ct::SUB2API
            | ct::NEW_API
            | ct::TENCENT
    )
}

/// Go `RemoveDisabledFields`（build_relay_info.go:1001-1072）：按渠道 other
/// settings 与透传开关删除敏感/计费字段。
pub fn remove_disabled_fields(
    json_data: &mut serde_json::Value,
    channel_other_settings: &serde_json::Value,
    channel_pass_through_enabled: bool,
    pass_through_request_enabled: bool,
) {
    if pass_through_request_enabled || channel_pass_through_enabled {
        return;
    }
    let Some(obj) = json_data.as_object_mut() else {
        return;
    };
    let allow = |key: &str| {
        channel_other_settings
            .get(key)
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    };
    if !allow("allow_service_tier") {
        obj.remove("service_tier");
    }
    if !allow("allow_inference_geo") {
        obj.remove("inference_geo");
    }
    if !allow("allow_speed") {
        obj.remove("speed");
    }
    if allow("disable_store") {
        obj.remove("store");
    }
    if !allow("allow_safety_identifier") {
        obj.remove("safety_identifier");
    }
    if !allow("allow_include_obfuscation")
        && let Some(stream_options) = obj
            .get_mut("stream_options")
            .and_then(|v| v.as_object_mut())
    {
        stream_options.remove("include_obfuscation");
        if stream_options.is_empty() {
            obj.remove("stream_options");
        }
    }
}

/// Go `RemoveGeminiDisabledFields`（build_relay_info.go:1095-1135）：删除
/// functionResponse / function_response 的 id 字段。
pub fn remove_gemini_disabled_fields(json_data: &mut serde_json::Value, enabled: bool) {
    if !enabled {
        return;
    }
    let Some(contents) = json_data.get_mut("contents").and_then(|v| v.as_array_mut()) else {
        return;
    };
    for content in contents.iter_mut() {
        let Some(parts) = content.get_mut("parts").and_then(|v| v.as_array_mut()) else {
            continue;
        };
        for part in parts.iter_mut() {
            if let Some(obj) = part.as_object_mut() {
                if let Some(fr) = obj
                    .get_mut("functionResponse")
                    .and_then(|v| v.as_object_mut())
                {
                    fr.remove("id");
                }
                if let Some(fr) = obj
                    .get_mut("function_response")
                    .and_then(|v| v.as_object_mut())
                {
                    fr.remove("id");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn input(path: &str, uri: &str) -> RelayInfoInput {
        RelayInfoInput {
            path: path.to_owned(),
            request_uri: uri.to_owned(),
            user_group: "default".to_owned(),
            ..RelayInfoInput::default()
        }
    }

    #[test]
    fn token_group_falls_back_to_user_group() {
        let info = gen_base_relay_info(&input("/v1/chat/completions", "/v1/chat/completions"));
        assert_eq!(info.token_group, "default");
        assert_eq!(
            info.relay_mode,
            crate::relay_mode::RELAY_MODE_CHAT_COMPLETIONS
        );
        assert!(info.is_first_response);
        // first_response_time = start - 1s
        assert_eq!(info.first_response_time_ms, info.start_time_ms - 1000);
    }

    #[test]
    fn playground_rewrites_url() {
        let info = gen_base_relay_info(&input("/pg/chat/completions", "/pg/chat/completions"));
        assert!(info.is_playground);
        assert_eq!(info.request_url_path, "/v1/chat/completions");
    }

    #[test]
    fn claude_info_disables_usage() {
        let info = gen_relay_info_claude(&input("/v1/messages", "/v1/messages"));
        assert!(!info.should_include_usage);
        assert_eq!(
            info.claude_last_messages_type.as_deref(),
            Some(last_message_type::NONE)
        );
    }

    #[test]
    fn responses_builtin_tools_default_context_size() {
        let tools = vec![json!({"type": "web_search_preview"})];
        let info = gen_relay_info_responses(&input("/v1/responses", "/v1/responses"), &tools);
        assert_eq!(info.responses_builtin_tools.len(), 1);
        assert_eq!(
            info.responses_builtin_tools[0].search_context_size,
            "medium"
        );
    }

    #[test]
    fn conversion_chain_semantics() {
        let mut info = gen_relay_info(
            relay_format::OPENAI,
            &input("/v1/chat/completions", "/v1/chat/completions"),
            &json!({}),
        )
        .unwrap();
        assert_eq!(info.request_conversion_chain, vec!["openai"]);
        info.append_request_conversion("claude");
        info.append_request_conversion("claude"); // 去重
        assert_eq!(info.request_conversion_chain, vec!["openai", "claude"]);
        assert_eq!(info.get_final_request_relay_format(), "claude");
        info.final_request_relay_format = "gemini".to_owned();
        assert_eq!(info.get_final_request_relay_format(), "gemini");
    }

    #[test]
    fn gen_relay_info_rejects_unknown_format() {
        let result = gen_relay_info("bogus", &input("/x", "/x"), &json!({}));
        assert!(matches!(result, Err(UnsupportedRelayFormat)));
    }

    #[test]
    fn first_response_time_only_once() {
        let mut info = gen_base_relay_info(&input("/v1/chat/completions", "/v1/chat/completions"));
        info.set_first_response_time(1000);
        assert!(info.has_send_response());
        info.set_first_response_time(2000);
        assert_eq!(info.first_response_time_ms, 1000);
    }

    #[test]
    fn remove_disabled_fields_defaults() {
        let mut body = json!({
            "service_tier": "flex",
            "safety_identifier": "u1",
            "store": true,
            "stream_options": {"include_obfuscation": true, "include_usage": true}
        });
        remove_disabled_fields(&mut body, &json!({}), false, false);
        assert!(body.get("service_tier").is_none());
        assert!(body.get("safety_identifier").is_none());
        assert_eq!(body["store"], true); // store 默认透传
        let so = body["stream_options"].as_object().unwrap();
        assert!(so.contains_key("include_usage"));
        assert!(!so.contains_key("include_obfuscation"));
    }

    #[test]
    fn remove_disabled_fields_respects_pass_through() {
        let mut body = json!({"service_tier": "flex"});
        remove_disabled_fields(&mut body, &json!({}), true, false);
        assert_eq!(body["service_tier"], "flex");
    }

    #[test]
    fn stream_supported_channels_set() {
        use crate::adaptor::channel_type as ct;
        assert!(stream_supported_channels(ct::OPENAI));
        assert!(!stream_supported_channels(ct::PALM));
        assert!(!stream_supported_channels(999_999));
    }
}
