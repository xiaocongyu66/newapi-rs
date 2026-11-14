//! Go `relaykit/relayconvert/internal/claude_messages/to_oai_chat_resp.go` 的
//! 移植子集（三大适配器外呼所需）。Claude DTO（dto/claude.go）以 serde 结构
//! 落地，只取适配器触摸的字段；wire 命名逐字对齐。

use super::usage::{self, ClaudeCacheCreationUsage, ClaudeUsage, Usage};
use serde::Deserialize;

/// Go `reasonmap.ClaudeStopReasonToOpenAIFinishReason`。
pub fn stop_reason_claude_to_openai(stop_reason: &str) -> String {
    match stop_reason.to_lowercase().as_str() {
        "stop_sequence" => "stop".to_owned(),
        "end_turn" => "stop".to_owned(),
        "max_tokens" => "length".to_owned(),
        "tool_use" => "tool_calls".to_owned(),
        "refusal" => "content_filter".to_owned(),
        _ => stop_reason.to_owned(),
    }
}

/// Go `dto.ClaudeError`。
#[derive(Clone, Debug, Default, Deserialize)]
pub struct ClaudeErrorBody {
    #[serde(default)]
    pub r#type: String,
    #[serde(default)]
    pub message: String,
}

/// Go `dto.ClaudeMediaMessage`（dto/claude.go 响应块）。
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct ClaudeMediaMessage {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub source: Option<serde_json::Value>,
    #[serde(default)]
    pub stop_reason: Option<String>,
    #[serde(rename = "partial_json", default)]
    pub partial_json: Option<String>,
    #[serde(default)]
    pub thinking: Option<String>,
    #[serde(default)]
    pub signature: String,
    #[serde(default)]
    pub delta: String,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub input: serde_json::Value,
    #[serde(default)]
    pub content: String,
    #[serde(rename = "tool_use_id", default)]
    pub tool_use_id: String,
}

/// Go `dto.ClaudeResponse`（流事件与终响应共用形态）。
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct ClaudeResponse {
    #[serde(default)]
    pub id: String,
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub content: Vec<ClaudeMediaMessage>,
    #[serde(default)]
    pub completion: String,
    #[serde(rename = "stop_reason", default)]
    pub stop_reason: Option<String>,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub error: Option<ClaudeErrorBody>,
    #[serde(default)]
    pub usage: Option<ClaudeUsage>,
    #[serde(default)]
    pub index: Option<i64>,
    #[serde(rename = "content_block", default)]
    pub content_block: Option<ClaudeMediaMessage>,
    #[serde(default)]
    pub delta: Option<ClaudeDelta>,
    #[serde(default)]
    pub message: Option<Box<ClaudeResponse>>,
}

/// Go `dto.ClaudeMediaMessage` 的 delta 形态（流事件 delta 字段）。
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct ClaudeDelta {
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub stop_reason: Option<String>,
    #[serde(rename = "partial_json", default)]
    pub partial_json: Option<String>,
    #[serde(default)]
    pub thinking: Option<String>,
    #[serde(default)]
    pub signature: String,
}

impl ClaudeMediaMessage {
    /// Go `ClaudeMediaMessage.GetText`：Text 指针优先，回退 Content。
    pub fn get_text(&self) -> String {
        if let Some(text) = &self.text {
            return text.clone();
        }
        self.content.clone()
    }
}

impl ClaudeResponse {
    /// Go `ClaudeResponse.GetClaudeError`：error.type 非空才返回。
    pub fn get_claude_error(&self) -> Option<&ClaudeErrorBody> {
        match &self.error {
            Some(err) if !err.r#type.is_empty() => Some(err),
            _ => None,
        }
    }
}

/// Go `relayconvert.ClaudeResponseInfo`（to_oai_chat_resp.go:16-23）。
#[derive(Debug, Default)]
pub struct ClaudeResponseInfo {
    pub response_id: String,
    pub created: i64,
    pub model: String,
    pub response_text: String,
    pub usage: Usage,
    pub done: bool,
}

/// chat.completion.chunk 单个 choice 的 delta 形态（适配器输出用）。
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct StreamChoiceDelta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(rename = "reasoning_content", skip_serializing_if = "Option::is_none")]
    pub reasoning_content: Option<String>,
    #[serde(rename = "tool_calls", skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCallResponse>>,
}

/// Go `dto.ToolCallResponse`（适配器需要的子集）。
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct ToolCallResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<i64>,
    #[serde(default)]
    pub id: String,
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub function: FunctionResponse,
}

/// Go `dto.FunctionResponse`。
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct FunctionResponse {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub arguments: String,
}

/// Go `dto.ChatCompletionsStreamResponse`（适配器需要的子集）。
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct ChatCompletionsStreamResponse {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub object: String,
    #[serde(default)]
    pub created: i64,
    #[serde(default)]
    pub model: String,
    #[serde(rename = "system_fingerprint", skip_serializing_if = "Option::is_none")]
    pub system_fingerprint: Option<String>,
    #[serde(default)]
    pub choices: Vec<StreamChoice>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<Usage>,
}

/// Go `dto.ChatCompletionsStreamResponseChoice`。
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct StreamChoice {
    #[serde(default)]
    pub index: i64,
    #[serde(default)]
    pub delta: StreamChoiceDelta,
    #[serde(rename = "finish_reason", skip_serializing_if = "Option::is_none")]
    pub finish_reason: Option<String>,
}

impl ChatCompletionsStreamResponse {
    /// Go `IsToolCall`：任一 choice 携带 tool_calls。
    pub fn is_tool_call(&self) -> bool {
        self.choices.iter().any(|choice| {
            choice
                .delta
                .tool_calls
                .as_ref()
                .is_some_and(|t| !t.is_empty())
        })
    }

    /// Go `IsFinished`：任一 choice 携带非空 finish_reason。
    pub fn is_finished(&self) -> bool {
        self.choices
            .iter()
            .any(|choice| choice.finish_reason.as_ref().is_some_and(|f| !f.is_empty()))
    }

    /// Go `Copy`：深拷贝（Rust derive Clone 已足够，这里语义占位）。
    pub fn copy(&self) -> Self {
        self.clone()
    }

    /// Go `ClearToolCalls`：清空所有 choice 的 tool_calls。
    pub fn clear_tool_calls(&mut self) {
        for choice in &mut self.choices {
            choice.delta.tool_calls = None;
        }
    }
}

/// Go `StreamResponseClaude2OpenAI`（to_oai_chat_resp.go:35-131）：Claude 流
/// 事件 → OpenAI chat.completion.chunk。非转换事件返回 None（Go nil）。
pub fn stream_response_claude_2_openai(
    claude_response: &ClaudeResponse,
) -> Option<ChatCompletionsStreamResponse> {
    let mut response = ChatCompletionsStreamResponse {
        object: "chat.completion.chunk".to_owned(),
        model: claude_response.model.clone(),
        ..ChatCompletionsStreamResponse::default()
    };
    let mut tools: Vec<ToolCallResponse> = Vec::new();
    let fc_idx = claude_response.index.unwrap_or(0);
    let mut choice = StreamChoice::default();

    if claude_response.kind == "message_start" {
        if let Some(message) = &claude_response.message {
            response.id = message.id.clone();
            response.model = message.model.clone();
        }
        choice.delta.content = Some(String::new());
        choice.delta.role = Some("assistant".to_owned());
    } else if claude_response.kind == "content_block_start" {
        if let Some(block) = &claude_response.content_block {
            if block.kind == "text"
                && let Some(text) = &block.text
            {
                choice.delta.content = Some(text.clone());
            }
            if block.kind == "tool_use" {
                tools.push(ToolCallResponse {
                    index: Some(fc_idx),
                    id: block.id.clone(),
                    kind: "function".to_owned(),
                    function: FunctionResponse {
                        name: block.name.clone(),
                        arguments: String::new(),
                    },
                });
            }
        } else {
            return None;
        }
    } else if claude_response.kind == "content_block_delta" {
        if let Some(delta) = &claude_response.delta {
            choice.delta.content = delta.text.clone();
            match delta.kind.as_str() {
                "input_json_delta" => {
                    tools.push(ToolCallResponse {
                        kind: "function".to_owned(),
                        index: Some(fc_idx),
                        function: FunctionResponse {
                            arguments: delta.partial_json.clone().unwrap_or_default(),
                            ..FunctionResponse::default()
                        },
                    });
                }
                "signature_delta" => {
                    choice.delta.reasoning_content = Some("\n".to_owned());
                }
                "thinking_delta" => {
                    choice.delta.reasoning_content = delta.thinking.clone();
                }
                _ => {}
            }
        }
    } else if claude_response.kind == "message_delta" {
        if let Some(delta) = &claude_response.delta
            && let Some(stop_reason) = &delta.stop_reason
        {
            let finish_reason = stop_reason_claude_to_openai(stop_reason);
            if finish_reason != "null" {
                choice.finish_reason = Some(finish_reason);
            }
        }
    } else {
        // message_stop 与未知事件 → nil
        return None;
    }

    if !tools.is_empty() {
        choice.delta.content = None;
        choice.delta.tool_calls = Some(tools);
    }
    response.choices.push(choice);
    Some(response)
}

/// Go `ResponseClaude2OpenAI`（to_oai_chat_resp.go:134-200）：Claude 终响应
/// → OpenAI chat.completion。返回 (response, )——Go 里 id 缺省时用
/// `chatcmpl-<uuid>`；调用方传入 id 生成器。
pub fn response_claude_2_openai(
    claude_response: &ClaudeResponse,
    fallback_uuid: impl FnOnce() -> String,
    timestamp: i64,
) -> serde_json::Value {
    let mut full_text_response = serde_json::json!({
        "id": claude_response.id.clone(),
        "object": "chat.completion",
        "created": timestamp,
        "model": claude_response.model.clone(),
    });
    if claude_response.id.is_empty() {
        full_text_response["id"] =
            serde_json::Value::String(format!("chatcmpl-{}", fallback_uuid()));
    }

    let mut response_text: Option<String> = None;
    let mut response_thinking = String::new();
    if !claude_response.content.is_empty() {
        response_text = Some(claude_response.content[0].get_text());
        if let Some(thinking) = &claude_response.content[0].thinking {
            response_thinking = thinking.clone();
        }
    }
    let mut tools: Vec<ToolCallResponse> = Vec::new();
    let mut thinking_content = String::new();

    for message in &claude_response.content {
        match message.kind.as_str() {
            "tool_use" => {
                let args = serde_json::to_string(&message.input).unwrap_or_default();
                tools.push(ToolCallResponse {
                    id: message.id.clone(),
                    kind: "function".to_owned(),
                    function: FunctionResponse {
                        name: message.name.clone(),
                        arguments: args,
                    },
                    ..ToolCallResponse::default()
                });
            }
            "thinking" => {
                if let Some(thinking) = &message.thinking {
                    thinking_content = thinking.clone();
                }
            }
            "text" => {
                response_text = Some(message.get_text());
            }
            _ => {}
        }
    }

    let mut message_obj = serde_json::json!({"role": "assistant"});
    if let Some(text) = &response_text {
        message_obj["content"] = serde_json::Value::String(text.clone());
    }
    if !response_thinking.is_empty() {
        message_obj["reasoning_content"] = serde_json::Value::String(response_thinking);
    }
    if !tools.is_empty() {
        message_obj["tool_calls"] = serde_json::to_value(&tools).unwrap_or_default();
    }
    if !thinking_content.is_empty() {
        message_obj["reasoning_content"] = serde_json::Value::String(thinking_content);
    }
    let choice = serde_json::json!({
        "index": 0,
        "message": message_obj,
        "finish_reason": stop_reason_claude_to_openai(&claude_response.stop_reason.clone().unwrap_or_default()),
    });
    full_text_response["choices"] = serde_json::Value::Array(vec![choice]);
    full_text_response
}

/// Go `sharedclaude.NormalizeCacheCreationSplit`：聚合值缺省时归入 5m。
pub fn normalize_cache_creation_split(
    total_tokens: i64,
    tokens_5m: i64,
    tokens_1h: i64,
) -> (i64, i64) {
    if tokens_5m == 0 && tokens_1h == 0 && total_tokens > 0 {
        return (total_tokens, 0);
    }
    (tokens_5m, tokens_1h)
}

/// Go `cacheCreationTokensForOpenAIUsage`（to_oai_chat_resp.go:68-82）。
fn cache_creation_tokens_for_openai_usage(usage: &Usage) -> i64 {
    let split = usage.claude_cache_creation_5m_tokens + usage.claude_cache_creation_1h_tokens;
    if split == 0 {
        return usage.prompt_tokens_details.cached_creation_tokens;
    }
    if usage.prompt_tokens_details.cached_creation_tokens > split {
        return usage.prompt_tokens_details.cached_creation_tokens;
    }
    split
}

/// Go `buildOpenAIStyleUsageFromClaudeUsage`（to_oai_chat_resp.go:85-116）：
/// anthropic 语义 usage → openai 语义（prompt 并入 cache 读/写，写侧双字段
/// 暴露）。
pub fn build_openai_style_usage_from_claude_usage(usage: &Usage) -> Usage {
    let mut clone = usage.clone();
    let (tokens_5m, tokens_1h) = normalize_cache_creation_split(
        usage.prompt_tokens_details.cached_creation_tokens,
        usage.claude_cache_creation_5m_tokens,
        usage.claude_cache_creation_1h_tokens,
    );
    clone.claude_cache_creation_5m_tokens = tokens_5m;
    clone.claude_cache_creation_1h_tokens = tokens_1h;
    let cache_creation_tokens = cache_creation_tokens_for_openai_usage(usage);
    clone.prompt_tokens_details.cache_write_tokens = cache_creation_tokens;
    let total_input_tokens =
        usage.prompt_tokens + usage.prompt_tokens_details.cached_tokens + cache_creation_tokens;
    clone.prompt_tokens = total_input_tokens;
    clone.input_tokens = total_input_tokens;
    clone.total_tokens = total_input_tokens + usage.completion_tokens;
    clone.usage_semantic = "openai".to_owned();
    clone.usage_source = "anthropic".to_owned();
    clone
}

/// Go `UsageFromClaudeUsage` / `UsageFromClaudeAPIUsage` 的合并入口：claude
/// 原始 usage → openai 语义 usage。
pub fn usage_from_claude_usage(usage: &Usage) -> Usage {
    build_openai_style_usage_from_claude_usage(usage)
}

/// Go `claudeBillingUsageFromSemanticUsage`（to_oai_chat_resp.go:119-145）。
pub fn claude_billing_usage_from_semantic_usage(usage: &Usage) -> Option<serde_json::Value> {
    let (tokens_5m, tokens_1h) = normalize_cache_creation_split(
        usage.prompt_tokens_details.cached_creation_tokens,
        usage.claude_cache_creation_5m_tokens,
        usage.claude_cache_creation_1h_tokens,
    );
    let claude_usage = ClaudeUsage {
        input_tokens: usage.prompt_tokens,
        cache_creation_input_tokens: usage.prompt_tokens_details.cached_creation_tokens,
        cache_read_input_tokens: usage.prompt_tokens_details.cached_tokens,
        output_tokens: usage.completion_tokens,
        cache_creation: if tokens_5m > 0 || tokens_1h > 0 {
            Some(ClaudeCacheCreationUsage {
                ephemeral_5m_input_tokens: tokens_5m,
                ephemeral_1h_input_tokens: tokens_1h,
            })
        } else {
            None
        },
        ..ClaudeUsage::default()
    };
    usage::new_claude_messages_billing_usage(Some(&claude_usage))
}

/// Go `BuildMessageDeltaPatchUsage`（to_oai_chat_resp.go:148-186）。
pub fn build_message_delta_patch_usage(
    claude_response: Option<&ClaudeResponse>,
    claude_info: Option<&ClaudeResponseInfo>,
) -> ClaudeUsage {
    let mut usage = ClaudeUsage::default();
    if let Some(response) = claude_response
        && let Some(response_usage) = &response.usage
    {
        usage = response_usage.clone();
    }

    let Some(claude_info) = claude_info else {
        return usage;
    };

    if usage.input_tokens == 0 && claude_info.usage.prompt_tokens > 0 {
        usage.input_tokens = claude_info.usage.prompt_tokens;
    }
    if usage.cache_read_input_tokens == 0
        && claude_info.usage.prompt_tokens_details.cached_tokens > 0
    {
        usage.cache_read_input_tokens = claude_info.usage.prompt_tokens_details.cached_tokens;
    }
    if usage.cache_creation_input_tokens == 0
        && claude_info
            .usage
            .prompt_tokens_details
            .cached_creation_tokens
            > 0
    {
        usage.cache_creation_input_tokens = claude_info
            .usage
            .prompt_tokens_details
            .cached_creation_tokens;
    }
    let (mut cache_creation_5m, mut cache_creation_1h) = match &usage.cache_creation {
        Some(cache) => (
            cache.ephemeral_5m_input_tokens,
            cache.ephemeral_1h_input_tokens,
        ),
        None => (
            claude_info.usage.claude_cache_creation_5m_tokens,
            claude_info.usage.claude_cache_creation_1h_tokens,
        ),
    };
    (cache_creation_5m, cache_creation_1h) = normalize_cache_creation_split(
        usage.cache_creation_input_tokens,
        cache_creation_5m,
        cache_creation_1h,
    );
    if usage.cache_creation.is_none() && (cache_creation_5m > 0 || cache_creation_1h > 0) {
        usage.cache_creation = Some(ClaudeCacheCreationUsage::default());
    }
    if let Some(cache) = &mut usage.cache_creation {
        cache.ephemeral_5m_input_tokens = cache_creation_5m;
        cache.ephemeral_1h_input_tokens = cache_creation_1h;
    }
    usage
}

/// Go `PatchClaudeMessageDeltaUsageData`（to_oai_chat_resp.go:167-183）：
/// message_delta 流事件的 usage 字段补洞——本地非零且上游缺失/为零才写入。
pub fn patch_claude_message_delta_usage_data(data: &str, usage: Option<&ClaudeUsage>) -> String {
    let Some(usage) = usage else {
        return data.to_owned();
    };
    if data.is_empty() {
        return data.to_owned();
    }
    let mut patched = data.to_owned();
    patched = set_message_delta_usage_int(&patched, "usage.input_tokens", usage.input_tokens);
    patched = set_message_delta_usage_int(
        &patched,
        "usage.cache_read_input_tokens",
        usage.cache_read_input_tokens,
    );
    patched = set_message_delta_usage_int(
        &patched,
        "usage.cache_creation_input_tokens",
        usage.cache_creation_input_tokens,
    );
    if let Some(cache) = &usage.cache_creation {
        patched = set_message_delta_usage_int(
            &patched,
            "usage.cache_creation.ephemeral_5m_input_tokens",
            cache.ephemeral_5m_input_tokens,
        );
        patched = set_message_delta_usage_int(
            &patched,
            "usage.cache_creation.ephemeral_1h_input_tokens",
            cache.ephemeral_1h_input_tokens,
        );
    }
    patched
}

fn set_message_delta_usage_int(data: &str, path: &str, local_value: i64) -> String {
    if local_value <= 0 {
        return data.to_owned();
    }
    let Ok(mut root) = serde_json::from_str::<serde_json::Value>(data) else {
        return data.to_owned();
    };
    // gjson: 上游已有非零值则不动。
    if let Some(existing) = get_json_path(&root, path)
        && let Some(as_int) = existing.as_i64()
        && as_int > 0
    {
        return data.to_owned();
    }
    // sjson.Set：路径不存在时创建中间对象；中间节点非对象时覆盖为对象。
    if !set_json_path(
        &mut root,
        path,
        serde_json::Value::Number(local_value.into()),
    ) {
        return data.to_owned();
    }
    serde_json::to_string(&root).unwrap_or_else(|_| data.to_owned())
}

/// gjson 风格的点路径读取（仅 object key 链）。
pub(crate) fn get_json_path<'a>(
    root: &'a serde_json::Value,
    path: &str,
) -> Option<&'a serde_json::Value> {
    let mut current = root;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

/// sjson 风格的点路径写入；中间节点缺省/非对象时替换为对象。
pub(crate) fn set_json_path(
    root: &mut serde_json::Value,
    path: &str,
    value: serde_json::Value,
) -> bool {
    let segments: Vec<&str> = path.split('.').collect();
    let mut current = root;
    for (i, segment) in segments.iter().enumerate() {
        if i == segments.len() - 1 {
            match current {
                serde_json::Value::Object(obj) => {
                    obj.insert((*segment).to_owned(), value);
                    return true;
                }
                other => {
                    *other = serde_json::json!({ *segment: value });
                    return true;
                }
            }
        }
        if !current.is_object() {
            *current = serde_json::Value::Object(serde_json::Map::new());
        }
        let obj = match current.as_object_mut() {
            Some(obj) => obj,
            None => return false,
        };
        current = obj
            .entry((*segment).to_owned())
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    }
    false
}

/// Go `FormatClaudeResponseInfo`（to_oai_chat_resp.go:186-256）：累计
/// usage/response_text，oaiResponse 非空时同步 id/created/model。返回 false
/// 表示事件类型被忽略。
pub fn format_claude_response_info(
    claude_response: &ClaudeResponse,
    oai_response: Option<&mut ChatCompletionsStreamResponse>,
    claude_info: &mut ClaudeResponseInfo,
) -> bool {
    if claude_response.kind == "message_start" {
        if let Some(message) = &claude_response.message {
            claude_info.response_id = message.id.clone();
            claude_info.model = message.model.clone();
            if let Some(message_usage) = &message.usage {
                claude_info.usage.usage_semantic = "anthropic".to_owned();
                claude_info.usage.prompt_tokens = message_usage.input_tokens;
                claude_info.usage.prompt_tokens_details.cached_tokens =
                    message_usage.cache_read_input_tokens;
                claude_info
                    .usage
                    .prompt_tokens_details
                    .cached_creation_tokens = message_usage.cache_creation_input_tokens;
                claude_info.usage.claude_cache_creation_5m_tokens =
                    message_usage.get_cache_creation_5m_tokens();
                claude_info.usage.claude_cache_creation_1h_tokens =
                    message_usage.get_cache_creation_1h_tokens();
                claude_info.usage.completion_tokens = message_usage.output_tokens;
                claude_info.usage.billing_usage =
                    claude_billing_usage_from_semantic_usage(&claude_info.usage);
            }
        }
    } else if claude_response.kind == "content_block_delta" {
        if let Some(delta) = &claude_response.delta {
            if let Some(text) = &delta.text {
                claude_info.response_text.push_str(text);
            }
            if let Some(thinking) = &delta.thinking {
                claude_info.response_text.push_str(thinking);
            }
        }
    } else if claude_response.kind == "message_delta" {
        if let Some(usage) = &claude_response.usage {
            claude_info.usage.usage_semantic = "anthropic".to_owned();
            if usage.input_tokens > 0 {
                claude_info.usage.prompt_tokens = usage.input_tokens;
            }
            if usage.cache_read_input_tokens > 0 {
                claude_info.usage.prompt_tokens_details.cached_tokens =
                    usage.cache_read_input_tokens;
            }
            if usage.cache_creation_input_tokens > 0 {
                claude_info
                    .usage
                    .prompt_tokens_details
                    .cached_creation_tokens = usage.cache_creation_input_tokens;
            }
            let cache_5m = usage.get_cache_creation_5m_tokens();
            if cache_5m > 0 {
                claude_info.usage.claude_cache_creation_5m_tokens = cache_5m;
            }
            let cache_1h = usage.get_cache_creation_1h_tokens();
            if cache_1h > 0 {
                claude_info.usage.claude_cache_creation_1h_tokens = cache_1h;
            }
            if usage.output_tokens > 0 {
                claude_info.usage.completion_tokens = usage.output_tokens;
            }
            claude_info.usage.total_tokens =
                claude_info.usage.prompt_tokens + claude_info.usage.completion_tokens;
            claude_info.usage.billing_usage =
                claude_billing_usage_from_semantic_usage(&claude_info.usage);
        }
        claude_info.done = true;
    } else if claude_response.kind != "content_block_start" {
        return false;
    }
    if let Some(oai_response) = oai_response {
        oai_response.id = claude_info.response_id.clone();
        oai_response.created = claude_info.created;
        oai_response.model = claude_info.model.clone();
    }
    true
}

/// Go `dto.OpenAITextResponse` 适配器子集（chat.completion 终响应）。
#[derive(Clone, Debug, Default, serde::Serialize)]
#[serde(default)]
pub struct OpenAiTextResponse {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub object: String,
    #[serde(default)]
    pub created: i64,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub choices: Vec<OpenAiTextChoice>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<Usage>,
}

/// Go `dto.OpenAITextResponseChoice` 适配器子集。
#[derive(Clone, Debug, Default, serde::Serialize)]
#[serde(default)]
pub struct OpenAiTextChoice {
    #[serde(default)]
    pub index: i64,
    #[serde(default)]
    pub message: OpenAiMessage,
    #[serde(rename = "finish_reason", skip_serializing_if = "Option::is_none")]
    pub finish_reason: Option<String>,
}

/// Go `dto.Message` 适配器子集。
#[derive(Clone, Debug, Default, serde::Serialize)]
#[serde(default)]
pub struct OpenAiMessage {
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub content: String,
    #[serde(rename = "reasoning_content", skip_serializing_if = "Option::is_none")]
    pub reasoning_content: Option<String>,
    #[serde(rename = "tool_calls", skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCallResponse>>,
}

/// Go 上游 OpenAI 错误体（dto.OpenAIError）。
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct OpenAiErrorBody {
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub r#type: String,
    #[serde(default)]
    pub param: String,
    #[serde(default)]
    pub code: serde_json::Value,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

/// Go `dto.SimpleResponse` 适配器子集（image/audio 路径的 usage 载体）。
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct SimpleResponse {
    #[serde(default)]
    pub error: Option<OpenAiErrorBody>,
    #[serde(default)]
    pub usage: Usage,
}

impl SimpleResponse {
    /// Go `SimpleResponse.GetOpenAIError`：error.type 非空才返回。
    pub fn get_openai_error(&self) -> Option<&OpenAiErrorBody> {
        match &self.error {
            Some(err) if !err.r#type.is_empty() => Some(err),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adaptor_common::usage::InputTokenDetails;
    use serde_json::json;

    // Go TestPatchClaudeMessageDeltaUsageDataPreserveUnknownFields。
    #[test]
    fn patch_message_delta_preserves_unknown_fields() {
        let original = r#"{"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":53},"vendor_meta":{"trace_id":"trace_001"}}"#;
        let usage = ClaudeUsage {
            input_tokens: 100,
            cache_read_input_tokens: 30,
            cache_creation_input_tokens: 50,
            ..ClaudeUsage::default()
        };
        let patched = patch_claude_message_delta_usage_data(original, Some(&usage));
        let root: serde_json::Value = serde_json::from_str(&patched).unwrap();
        assert_eq!(root["type"], "message_delta");
        assert_eq!(root["delta"]["stop_reason"], "end_turn");
        assert_eq!(root["vendor_meta"]["trace_id"], "trace_001");
        assert_eq!(root["usage"]["output_tokens"], 53);
        assert_eq!(root["usage"]["input_tokens"], 100);
        assert_eq!(root["usage"]["cache_read_input_tokens"], 30);
        assert_eq!(root["usage"]["cache_creation_input_tokens"], 50);
    }

    // Go TestPatchClaudeMessageDeltaUsageDataZeroValueChecks。
    #[test]
    fn patch_message_delta_zero_value_checks() {
        let original = r#"{"type":"message_delta","usage":{"output_tokens":53,"input_tokens":9,"cache_read_input_tokens":0}}"#;
        let usage = ClaudeUsage {
            input_tokens: 100,
            cache_read_input_tokens: 30,
            cache_creation_input_tokens: 0,
            ..ClaudeUsage::default()
        };
        let patched = patch_claude_message_delta_usage_data(original, Some(&usage));
        let root: serde_json::Value = serde_json::from_str(&patched).unwrap();
        assert_eq!(root["usage"]["input_tokens"], 9);
        assert_eq!(root["usage"]["cache_read_input_tokens"], 30);
        // 本地值为 0 → 不写入（sjson 语义）。
        assert!(root["usage"].get("cache_creation_input_tokens").is_none());
    }

    // Go TestBuildMessageDeltaPatchUsage 三分支。
    #[test]
    fn build_message_delta_patch_usage_merges_missing_fields() {
        let claude_response = ClaudeResponse {
            usage: Some(ClaudeUsage {
                output_tokens: 53,
                ..ClaudeUsage::default()
            }),
            ..ClaudeResponse::default()
        };
        let claude_info = ClaudeResponseInfo {
            usage: Usage {
                prompt_tokens: 100,
                prompt_tokens_details: InputTokenDetails {
                    cached_tokens: 30,
                    cached_creation_tokens: 50,
                    ..InputTokenDetails::default()
                },
                claude_cache_creation_5m_tokens: 10,
                claude_cache_creation_1h_tokens: 20,
                ..Usage::default()
            },
            ..ClaudeResponseInfo::default()
        };
        let usage = build_message_delta_patch_usage(Some(&claude_response), Some(&claude_info));
        assert_eq!(usage.input_tokens, 100);
        assert_eq!(usage.cache_read_input_tokens, 30);
        assert_eq!(usage.cache_creation_input_tokens, 50);
        assert_eq!(usage.output_tokens, 53);
        let cache = usage.cache_creation.expect("cache creation merged");
        assert_eq!(cache.ephemeral_5m_input_tokens, 30);
        assert_eq!(cache.ephemeral_1h_input_tokens, 20);
    }

    #[test]
    fn build_message_delta_patch_usage_keeps_upstream_non_zero() {
        let claude_response = ClaudeResponse {
            usage: Some(ClaudeUsage {
                input_tokens: 9,
                cache_read_input_tokens: 7,
                cache_creation_input_tokens: 6,
                ..ClaudeUsage::default()
            }),
            ..ClaudeResponse::default()
        };
        let claude_info = ClaudeResponseInfo {
            usage: Usage {
                prompt_tokens: 100,
                prompt_tokens_details: InputTokenDetails {
                    cached_tokens: 30,
                    cached_creation_tokens: 50,
                    ..InputTokenDetails::default()
                },
                ..Usage::default()
            },
            ..ClaudeResponseInfo::default()
        };
        let usage = build_message_delta_patch_usage(Some(&claude_response), Some(&claude_info));
        assert_eq!(usage.input_tokens, 9);
        assert_eq!(usage.cache_read_input_tokens, 7);
        assert_eq!(usage.cache_creation_input_tokens, 6);
    }

    #[test]
    fn build_message_delta_patch_usage_defaults_split_to_5m() {
        let claude_response = ClaudeResponse {
            usage: Some(ClaudeUsage {
                output_tokens: 53,
                cache_creation_input_tokens: 50,
                ..ClaudeUsage::default()
            }),
            ..ClaudeResponse::default()
        };
        let claude_info = ClaudeResponseInfo {
            usage: Usage {
                prompt_tokens_details: InputTokenDetails {
                    cached_creation_tokens: 50,
                    ..InputTokenDetails::default()
                },
                ..Usage::default()
            },
            ..ClaudeResponseInfo::default()
        };
        let usage = build_message_delta_patch_usage(Some(&claude_response), Some(&claude_info));
        let cache = usage.cache_creation.expect("aggregate defaults to 5m");
        assert_eq!(cache.ephemeral_5m_input_tokens, 50);
        assert_eq!(cache.ephemeral_1h_input_tokens, 0);
    }

    // StopReasonClaudeToOpenAI。
    #[test]
    fn stop_reason_mapping() {
        assert_eq!(stop_reason_claude_to_openai("end_turn"), "stop");
        assert_eq!(stop_reason_claude_to_openai("stop_sequence"), "stop");
        assert_eq!(stop_reason_claude_to_openai("max_tokens"), "length");
        assert_eq!(stop_reason_claude_to_openai("tool_use"), "tool_calls");
        assert_eq!(stop_reason_claude_to_openai("refusal"), "content_filter");
        assert_eq!(stop_reason_claude_to_openai("pause_turn"), "pause_turn");
    }

    // StreamResponseClaude2OpenAI：message_start / tool_use / thinking_delta /
    // message_delta finish_reason / message_stop nil。
    #[test]
    fn stream_claude_to_openai_message_start() {
        let event = ClaudeResponse {
            kind: "message_start".to_owned(),
            message: Some(Box::new(ClaudeResponse {
                id: "msg_1".to_owned(),
                model: "claude-3-7-sonnet-20250219".to_owned(),
                ..ClaudeResponse::default()
            })),
            ..ClaudeResponse::default()
        };
        let response = stream_response_claude_2_openai(&event).expect("converted");
        assert_eq!(response.object, "chat.completion.chunk");
        assert_eq!(response.id, "msg_1");
        assert_eq!(response.model, "claude-3-7-sonnet-20250219");
        let choice = &response.choices[0];
        assert_eq!(choice.delta.role.as_deref(), Some("assistant"));
        assert_eq!(choice.delta.content.as_deref(), Some(""));
    }

    #[test]
    fn stream_claude_to_openai_tool_use_start() {
        let event = ClaudeResponse {
            kind: "content_block_start".to_owned(),
            index: Some(2),
            content_block: Some(ClaudeMediaMessage {
                kind: "tool_use".to_owned(),
                id: "toolu_1".to_owned(),
                name: "get_weather".to_owned(),
                ..ClaudeMediaMessage::default()
            }),
            ..ClaudeResponse::default()
        };
        let response = stream_response_claude_2_openai(&event).expect("converted");
        let choice = &response.choices[0];
        let tools = choice.delta.tool_calls.as_ref().expect("tool calls");
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].index, Some(2));
        assert_eq!(tools[0].id, "toolu_1");
        assert_eq!(tools[0].function.name, "get_weather");
        assert_eq!(tools[0].function.arguments, "");
        // 工具块清空 content。
        assert!(choice.delta.content.is_none());
    }

    #[test]
    fn stream_claude_to_openai_thinking_delta() {
        let event = ClaudeResponse {
            kind: "content_block_delta".to_owned(),
            delta: Some(ClaudeDelta {
                kind: "thinking_delta".to_owned(),
                thinking: Some("reasoning...".to_owned()),
                ..ClaudeDelta::default()
            }),
            ..ClaudeResponse::default()
        };
        let response = stream_response_claude_2_openai(&event).expect("converted");
        let choice = &response.choices[0];
        assert_eq!(
            choice.delta.reasoning_content.as_deref(),
            Some("reasoning...")
        );
    }

    #[test]
    fn stream_claude_to_openai_message_delta_finish() {
        let event = ClaudeResponse {
            kind: "message_delta".to_owned(),
            delta: Some(ClaudeDelta {
                stop_reason: Some("max_tokens".to_owned()),
                ..ClaudeDelta::default()
            }),
            ..ClaudeResponse::default()
        };
        let response = stream_response_claude_2_openai(&event).expect("converted");
        assert_eq!(response.choices[0].finish_reason.as_deref(), Some("length"));
    }

    #[test]
    fn stream_claude_to_openai_message_stop_is_nil() {
        let event = ClaudeResponse {
            kind: "message_stop".to_owned(),
            ..ClaudeResponse::default()
        };
        assert!(stream_response_claude_2_openai(&event).is_none());
        let unknown = ClaudeResponse {
            kind: "ping".to_owned(),
            ..ClaudeResponse::default()
        };
        assert!(stream_response_claude_2_openai(&unknown).is_none());
    }

    // ResponseClaude2OpenAI：text + tool_use + thinking。
    #[test]
    fn response_claude_to_openai_full() {
        let claude = ClaudeResponse {
            id: "msg_9".to_owned(),
            kind: "message".to_owned(),
            model: "claude-3-5-sonnet-20241022".to_owned(),
            stop_reason: Some("tool_use".to_owned()),
            content: vec![
                ClaudeMediaMessage {
                    kind: "thinking".to_owned(),
                    thinking: Some("deep thought".to_owned()),
                    ..ClaudeMediaMessage::default()
                },
                ClaudeMediaMessage {
                    kind: "text".to_owned(),
                    text: Some("hello".to_owned()),
                    ..ClaudeMediaMessage::default()
                },
                ClaudeMediaMessage {
                    kind: "tool_use".to_owned(),
                    id: "toolu_9".to_owned(),
                    name: "search".to_owned(),
                    input: json!({"q": "rust"}),
                    ..ClaudeMediaMessage::default()
                },
            ],
            ..ClaudeResponse::default()
        };
        let response = response_claude_2_openai(&claude, || "uuid".to_owned(), 1234);
        assert_eq!(response["id"], "msg_9");
        assert_eq!(response["object"], "chat.completion");
        assert_eq!(response["created"], 1234);
        assert_eq!(response["model"], "claude-3-5-sonnet-20241022");
        let choice = &response["choices"][0];
        assert_eq!(choice["finish_reason"], "tool_calls");
        assert_eq!(choice["message"]["content"], "hello");
        assert_eq!(choice["message"]["reasoning_content"], "deep thought");
        assert_eq!(
            choice["message"]["tool_calls"][0]["function"]["name"],
            "search"
        );
        assert_eq!(
            choice["message"]["tool_calls"][0]["function"]["arguments"],
            r#"{"q":"rust"}"#
        );
    }

    // buildOpenAIStyleUsageFromClaudeUsage：prompt 并入 cache 读/写。
    #[test]
    fn openai_style_usage_from_claude_usage() {
        let usage = Usage {
            prompt_tokens: 100,
            completion_tokens: 53,
            prompt_tokens_details: InputTokenDetails {
                cached_tokens: 30,
                cached_creation_tokens: 50,
                ..InputTokenDetails::default()
            },
            ..Usage::default()
        };
        let mapped = build_openai_style_usage_from_claude_usage(&usage);
        // total input = prompt + cached + cache_creation
        assert_eq!(mapped.prompt_tokens, 100 + 30 + 50);
        assert_eq!(mapped.input_tokens, 100 + 30 + 50);
        assert_eq!(mapped.prompt_tokens_details.cache_write_tokens, 50);
        assert_eq!(mapped.total_tokens, 100 + 30 + 50 + 53);
        assert_eq!(mapped.usage_semantic, "openai");
        assert_eq!(mapped.usage_source, "anthropic");
    }

    // FormatClaudeResponseInfo：message_start usage 捕获 + message_delta done。
    #[test]
    fn format_claude_response_info_lifecycle() {
        let mut info = ClaudeResponseInfo {
            created: 999,
            ..ClaudeResponseInfo::default()
        };
        let message_start = ClaudeResponse {
            kind: "message_start".to_owned(),
            message: Some(Box::new(ClaudeResponse {
                id: "msg_1".to_owned(),
                model: "claude-sonnet-4-5".to_owned(),
                usage: Some(ClaudeUsage {
                    input_tokens: 25,
                    cache_read_input_tokens: 5,
                    cache_creation_input_tokens: 3,
                    output_tokens: 1,
                    ..ClaudeUsage::default()
                }),
                ..ClaudeResponse::default()
            })),
            ..ClaudeResponse::default()
        };
        assert!(format_claude_response_info(&message_start, None, &mut info));
        assert_eq!(info.response_id, "msg_1");
        assert_eq!(info.model, "claude-sonnet-4-5");
        assert_eq!(info.usage.prompt_tokens, 25);
        assert_eq!(info.usage.prompt_tokens_details.cached_tokens, 5);
        assert_eq!(info.usage.usage_semantic, "anthropic");
        assert!(info.usage.billing_usage.is_some());

        let delta = ClaudeResponse {
            kind: "content_block_delta".to_owned(),
            delta: Some(ClaudeDelta {
                text: Some("answer".to_owned()),
                ..ClaudeDelta::default()
            }),
            ..ClaudeResponse::default()
        };
        assert!(format_claude_response_info(&delta, None, &mut info));
        assert_eq!(info.response_text, "answer");

        let message_delta = ClaudeResponse {
            kind: "message_delta".to_owned(),
            usage: Some(ClaudeUsage {
                output_tokens: 42,
                ..ClaudeUsage::default()
            }),
            ..ClaudeResponse::default()
        };
        assert!(format_claude_response_info(&message_delta, None, &mut info));
        assert!(info.done);
        assert_eq!(info.usage.completion_tokens, 42);
        assert_eq!(info.usage.total_tokens, 25 + 42);

        let unknown = ClaudeResponse {
            kind: "ping".to_owned(),
            ..ClaudeResponse::default()
        };
        assert!(!format_claude_response_info(&unknown, None, &mut info));
    }

    // sjson/gjson 语义：中间节点为 null 时覆盖为对象。
    #[test]
    fn set_json_path_replaces_non_object_intermediates() {
        let mut root = json!({"usage": null});
        assert!(set_json_path(
            &mut root,
            "usage.input_tokens",
            serde_json::Value::Number(7.into())
        ));
        assert_eq!(root["usage"]["input_tokens"], 7);
    }
}
