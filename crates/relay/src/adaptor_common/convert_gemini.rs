//! Go `relaykit/relayconvert/internal/gemini_chat/to_oai_chat_resp.go` 的移植
//! 子集：Gemini usageMetadata → Usage、Gemini 响应 → OpenAI chat 响应（流与
//! 终态）。Gemini DTO 字段名逐字对齐（camelCase wire 形态）。

use super::usage::{self, GeminiPromptTokensDetails, GeminiUsageMetadata, Usage};
use serde::Deserialize;

/// Go `dto.GeminiInlineData`（gemini.go:201-204，含 snake_case 回退）。
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct GeminiInlineData {
    #[serde(alias = "mime_type", default)]
    pub mime_type: String,
    #[serde(default)]
    pub data: String,
}

/// Go `dto.GeminiFileData`（gemini.go:261-264）。
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct GeminiFileData {
    #[serde(default)]
    pub mime_type: String,
    #[serde(rename = "fileUri", alias = "file_uri", default)]
    pub file_uri: String,
}

/// Go `dto.FunctionCall`（gemini.go:237-240）。
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct GeminiFunctionCall {
    #[serde(rename = "name", default)]
    pub function_name: String,
    #[serde(default)]
    pub arguments: serde_json::Value,
}

/// Go `dto.GeminiPartExecutableCode`。
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct GeminiPartExecutableCode {
    #[serde(default)]
    pub language: String,
    #[serde(default)]
    pub code: String,
}

/// Go `dto.GeminiPartCodeExecutionResult`。
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct GeminiPartCodeExecutionResult {
    #[serde(default)]
    pub output: String,
}

/// Go `dto.GeminiPart`（gemini.go:266-279）。
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct GeminiPart {
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub thought: bool,
    #[serde(rename = "inlineData", alias = "inline_data", default)]
    pub inline_data: Option<GeminiInlineData>,
    #[serde(rename = "functionCall", alias = "function_call", default)]
    pub function_call: Option<GeminiFunctionCall>,
    #[serde(rename = "thoughtSignature", default)]
    pub thought_signature: Option<serde_json::Value>,
    #[serde(rename = "functionResponse", alias = "function_response", default)]
    pub function_response: Option<serde_json::Value>,
    #[serde(rename = "mediaResolution", default)]
    pub media_resolution: Option<serde_json::Value>,
    #[serde(rename = "videoMetadata", default)]
    pub video_metadata: Option<serde_json::Value>,
    #[serde(rename = "fileData", alias = "file_data", default)]
    pub file_data: Option<GeminiFileData>,
    #[serde(rename = "executableCode", default)]
    pub executable_code: Option<GeminiPartExecutableCode>,
    #[serde(rename = "codeExecutionResult", default)]
    pub code_execution_result: Option<GeminiPartCodeExecutionResult>,
}

/// Go `dto.GeminiChatContent`（gemini.go:308-311）。
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct GeminiChatContent {
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub parts: Vec<GeminiPart>,
}

/// Go `dto.GeminiGroundingMetadata`（gemini.go:445-447）。
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct GeminiGroundingMetadata {
    #[serde(rename = "webSearchQueries", default)]
    pub web_search_queries: Vec<String>,
}

/// Go `dto.GeminiChatPromptFeedback`（gemini.go:454-457）。
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct GeminiChatPromptFeedback {
    #[serde(rename = "safetyRatings", default)]
    pub safety_ratings: Vec<serde_json::Value>,
    #[serde(rename = "blockReason", default)]
    pub block_reason: Option<String>,
}

/// Go `dto.GeminiChatCandidate`（gemini.go 同文件）。
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct GeminiChatCandidate {
    #[serde(default)]
    pub content: GeminiChatContent,
    #[serde(rename = "finishReason", default)]
    pub finish_reason: Option<String>,
    #[serde(default)]
    pub index: i64,
    #[serde(rename = "groundingMetadata", default)]
    pub grounding_metadata: Option<GeminiGroundingMetadata>,
}

/// Go `dto.GeminiChatResponse`（gemini.go:459-464，unmarshal 记录
/// usageMetadata 是否出现）。
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct GeminiChatResponse {
    #[serde(default)]
    pub candidates: Vec<GeminiChatCandidate>,
    #[serde(rename = "promptFeedback", default)]
    pub prompt_feedback: Option<GeminiChatPromptFeedback>,
    #[serde(rename = "usageMetadata", default)]
    pub usage_metadata: Option<GeminiUsageMetadata>,
    #[serde(skip)]
    pub has_usage_metadata: bool,
}

impl GeminiChatResponse {
    /// Go 自定义 UnmarshalJSON 的 has_usage_metadata 副作用。
    pub fn from_json(data: &[u8]) -> Result<Self, serde_json::Error> {
        let response: GeminiChatResponse = serde_json::from_slice(data)?;
        let has_usage_metadata = serde_json::from_slice::<serde_json::Value>(data)
            .ok()
            .and_then(|v| v.get("usageMetadata").map(|_| ()))
            .is_some();
        Ok(GeminiChatResponse {
            has_usage_metadata,
            ..response
        })
    }

    /// Go `GetUsageMetadata`：出现才返回引用（Rust 直接 Option）。
    pub fn get_usage_metadata(&self) -> Option<&GeminiUsageMetadata> {
        self.usage_metadata.as_ref()
    }
}

/// Go `geminichat.UsageFromGeminiMetadata`（to_oai_chat_resp.go:14-68）。
pub fn usage_from_gemini_metadata(
    metadata: Option<&GeminiUsageMetadata>,
    fallback_prompt_tokens: i64,
) -> Option<Usage> {
    let Some(metadata) = metadata else {
        if fallback_prompt_tokens <= 0 {
            return None;
        }
        return Some(Usage {
            prompt_tokens: fallback_prompt_tokens,
            prompt_tokens_details: crate::adaptor_common::usage::InputTokenDetails {
                text_tokens: fallback_prompt_tokens,
                ..crate::adaptor_common::usage::InputTokenDetails::default()
            },
            ..Usage::default()
        });
    };

    let mut prompt_tokens = metadata.prompt_token_count + metadata.tool_use_prompt_token_count;
    if prompt_tokens <= 0 && fallback_prompt_tokens > 0 {
        prompt_tokens = fallback_prompt_tokens;
    }

    let mut usage = Usage {
        prompt_tokens,
        completion_tokens: metadata.candidates_token_count + metadata.thoughts_token_count,
        total_tokens: metadata.total_token_count,
        billing_usage: metadata.billing_usage.clone(),
        ..Usage::default()
    };
    if usage.billing_usage.is_none() {
        usage.billing_usage = usage::new_gemini_chat_billing_usage(Some(metadata));
    }
    usage.completion_token_details.reasoning_tokens = metadata.thoughts_token_count;
    usage.prompt_tokens_details.cached_tokens = metadata.cached_content_token_count;

    for detail in metadata
        .prompt_tokens_details
        .iter()
        .chain(metadata.tool_use_prompt_tokens_details.iter())
    {
        apply_prompt_detail(&mut usage.prompt_tokens_details, detail);
    }
    for detail in &metadata.candidates_tokens_details {
        match detail.modality.as_str() {
            "IMAGE" => usage.completion_token_details.image_tokens += detail.token_count,
            "AUDIO" => usage.completion_token_details.audio_tokens += detail.token_count,
            "TEXT" => usage.completion_token_details.text_tokens += detail.token_count,
            _ => {}
        }
    }

    if usage.total_tokens > 0 && usage.completion_tokens <= 0 {
        usage.completion_tokens = usage.total_tokens - usage.prompt_tokens;
    }
    if usage.prompt_tokens > 0
        && usage.prompt_tokens_details.text_tokens == 0
        && usage.prompt_tokens_details.audio_tokens == 0
    {
        usage.prompt_tokens_details.text_tokens = usage.prompt_tokens;
    }
    Some(usage)
}

fn apply_prompt_detail(
    details: &mut super::usage::InputTokenDetails,
    detail: &GeminiPromptTokensDetails,
) {
    match detail.modality.as_str() {
        "AUDIO" => details.audio_tokens += detail.token_count,
        "IMAGE" => details.image_tokens += detail.token_count,
        "TEXT" => details.text_tokens += detail.token_count,
        _ => {}
    }
}

/// Go `types.FinishReason*` 常量（finish reason 字符串）。
pub mod finish_reason {
    pub const STOP: &str = "stop";
    pub const LENGTH: &str = "length";
    pub const CONTENT_FILTER: &str = "content_filter";
    pub const TOOL_CALLS: &str = "tool_calls";
}

/// Go `geminiResponseToolCall`（to_oai_chat_resp.go:369-383）。
fn gemini_response_tool_call(part: &GeminiPart) -> Option<super::convert_claude::ToolCallResponse> {
    let call = part.function_call.as_ref()?;
    let args = serde_json::to_string(&call.arguments).ok()?;
    Some(super::convert_claude::ToolCallResponse {
        id: format!("call_{}", crate::adaptor_common::random_uuid()),
        kind: "function".to_owned(),
        function: super::convert_claude::FunctionResponse {
            arguments: args,
            name: call.function_name.clone(),
        },
        ..super::convert_claude::ToolCallResponse::default()
    })
}

/// OpenAI chat.completion 终响应（geminichat.ResponseGeminiChat2OpenAI 输出
/// 形状）。这里直接以 [`super::convert_claude::OpenAiTextResponse`] 承载。
pub type GeminiOpenAiTextResponse = super::convert_claude::OpenAiTextResponse;

/// Go `ResponseGeminiChat2OpenAI`（to_oai_chat_resp.go:76-188）：Gemini 终响应
/// → OpenAI chat.completion。
pub fn response_gemini_chat_2_openai(
    id: &str,
    created: i64,
    response: &GeminiChatResponse,
) -> GeminiOpenAiTextResponse {
    let mut full_text_response = GeminiOpenAiTextResponse {
        id: id.to_owned(),
        object: "chat.completion".to_owned(),
        created,
        ..GeminiOpenAiTextResponse::default()
    };
    let mut is_tool_call = false;
    for candidate in &response.candidates {
        let mut choice = super::convert_claude::OpenAiTextChoice {
            index: candidate.index,
            message: super::convert_claude::OpenAiMessage {
                role: "assistant".to_owned(),
                ..Default::default()
            },
            finish_reason: Some(finish_reason::STOP.to_owned()),
        };
        let mut tool_calls: Vec<super::convert_claude::ToolCallResponse> = Vec::new();
        if !candidate.content.parts.is_empty() {
            let mut content = String::new();
            let mut appended = 0usize;
            let mut write_sep = |content: &mut String| {
                if appended > 0 {
                    content.push('\n');
                }
                appended += 1;
            };
            for part in &candidate.content.parts {
                if let Some(inline) = &part.inline_data {
                    write_sep(&mut content);
                    if inline.mime_type.starts_with("image") {
                        content.push_str(&format!(
                            "![image](data:{};base64,{})",
                            inline.mime_type, inline.data
                        ));
                    } else {
                        content.push_str(&format!(
                            "[media](data:{};base64,{})",
                            inline.mime_type, inline.data
                        ));
                    }
                } else if part.function_call.is_some() {
                    choice.finish_reason = Some(finish_reason::TOOL_CALLS.to_owned());
                    if let Some(call) = gemini_response_tool_call(part) {
                        tool_calls.push(call);
                    }
                } else if part.thought {
                    choice.message.reasoning_content = Some(part.text.clone());
                } else if let Some(code) = &part.executable_code {
                    write_sep(&mut content);
                    content.push_str("```");
                    content.push_str(&code.language);
                    content.push('\n');
                    content.push_str(&code.code);
                    content.push_str("\n```");
                } else if let Some(result) = &part.code_execution_result {
                    write_sep(&mut content);
                    content.push_str("```output\n");
                    content.push_str(&result.output);
                    content.push_str("\n```");
                } else if part.text != "\n" {
                    write_sep(&mut content);
                    content.push_str(&part.text);
                }
            }
            if !tool_calls.is_empty() {
                choice.message.tool_calls = Some(tool_calls.clone());
                is_tool_call = true;
            }
            choice.message.content = content;
        }
        if let Some(finish) = &candidate.finish_reason {
            choice.finish_reason = Some(match finish.as_str() {
                "STOP" => finish_reason::STOP.to_owned(),
                "MAX_TOKENS" => finish_reason::LENGTH.to_owned(),
                _ => finish_reason::CONTENT_FILTER.to_owned(), // SAFETY/RECITATION/BLOCKLIST/PROHIBITED_CONTENT/SPII/OTHER/默认
            });
        }
        if is_tool_call {
            choice.finish_reason = Some(finish_reason::TOOL_CALLS.to_owned());
        }
        full_text_response.choices.push(choice);
    }
    full_text_response
}

/// Go `StreamResponseGeminiChat2OpenAI`（to_oai_chat_resp.go:191-283）：返回
/// (chunk, isStop)。
pub fn stream_response_gemini_chat_2_openai(
    gemini_response: &GeminiChatResponse,
) -> (
    Option<super::convert_claude::ChatCompletionsStreamResponse>,
    bool,
) {
    let mut choices: Vec<super::convert_claude::StreamChoice> = Vec::new();
    let mut is_stop = false;
    for candidate in &gemini_response.candidates {
        // Go 在本地把 STOP 置 nil：isStop 标记后按无 finish_reason 处理，
        // choice 依旧产出。
        let candidate_finish = match &candidate.finish_reason {
            Some(finish) if finish == "STOP" => {
                is_stop = true;
                None
            }
            other => other.clone(),
        };
        let mut choice = super::convert_claude::StreamChoice {
            index: candidate.index,
            ..Default::default()
        };
        let mut content = String::new();
        let mut appended = 0usize;
        let mut write_sep = |content: &mut String| {
            if appended > 0 {
                content.push('\n');
            }
            appended += 1;
        };
        let mut is_tools = false;
        let mut is_thought = false;
        if let Some(finish) = &candidate_finish {
            choice.finish_reason = Some(match finish.as_str() {
                "STOP" => finish_reason::STOP.to_owned(),
                "MAX_TOKENS" => finish_reason::LENGTH.to_owned(),
                _ => finish_reason::CONTENT_FILTER.to_owned(),
            });
        }
        let mut tool_calls: Vec<super::convert_claude::ToolCallResponse> = Vec::new();
        for part in &candidate.content.parts {
            if let Some(inline) = &part.inline_data {
                if inline.mime_type.starts_with("image") {
                    write_sep(&mut content);
                    content.push_str(&format!(
                        "![image](data:{};base64,{})",
                        inline.mime_type, inline.data
                    ));
                }
            } else if part.function_call.is_some() {
                is_tools = true;
                if let Some(mut tool) = gemini_response_tool_call(part) {
                    tool.index = Some(tool_calls.len() as i64);
                    tool_calls.push(tool);
                }
            } else if part.thought {
                is_thought = true;
                write_sep(&mut content);
                content.push_str(&part.text);
            } else if let Some(code) = &part.executable_code {
                write_sep(&mut content);
                content.push_str("```");
                content.push_str(&code.language);
                content.push('\n');
                content.push_str(&code.code);
                content.push_str("\n```\n");
            } else if let Some(result) = &part.code_execution_result {
                write_sep(&mut content);
                content.push_str("```output\n");
                content.push_str(&result.output);
                content.push_str("\n```\n");
            } else if part.text != "\n" {
                write_sep(&mut content);
                content.push_str(&part.text);
            }
        }
        if is_thought {
            choice.delta.reasoning_content = Some(content.clone());
            choice.delta.content = None;
        } else {
            choice.delta.content = Some(content.clone());
        }
        if !tool_calls.is_empty() {
            choice.delta.tool_calls = Some(tool_calls);
        }
        if is_tools {
            choice.finish_reason = Some(finish_reason::TOOL_CALLS.to_owned());
        }
        choices.push(choice);
    }

    let response = super::convert_claude::ChatCompletionsStreamResponse {
        object: "chat.completion.chunk".to_owned(),
        choices,
        ..Default::default()
    };
    (Some(response), is_stop)
}
