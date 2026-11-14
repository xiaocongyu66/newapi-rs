//! Go `internal/relay/channel/openai/` 的移植（adaptor.go / relay-openai.go /
//! handle_stream_format.go / usage.go / stream_observe.go / audio.go /
//! relay_image.go / constant.go）。
//!
//! 契约要点：
//! - `GetRequestURL`：realtime wss/ws 改写、Azure（api-version / deployments /
//!   responses+compact / realtime deployment / 点号裁剪）、Custom `{model}`
//!   占位、default 分支的 claude/gemini 格式走 `/v1/chat/completions`。
//! - `SetupRequestHeader`：Azure `api-key`、OpenAI `OpenAI-Organization`、
//!   Header Override 的 Authorization 保护、realtime Sec-WebSocket-Protocol、
//!   OpenRouter referer/title。
//! - `ConvertOpenAIRequest`：OpenRouter usage/thinking 适配、o 系 / gpt-5
//!   参数归零与 effort 后缀迁移、developer 角色改写。
//! - 流式（`OaiStreamHandler`）：#426 前导块持有转发策略、fast-path 观察器、
//!   #394 截断守卫、音频模型倒数第二块 usage 提取。
//! - 非流（`OpenaiHandler`）：OpenRouter enterprise 解包、error/空 choices
//!   折叠、usage 回退估算、usage post-processing（DeepSeek / Zhipu v4 /
//!   Moonshot / llama.cpp cache 字段迁移）。
//!
//! 已知偏差：
//! - relayconvert 的 openai→claude / openai→gemini 响应转换走
//!   `relayconvert_*_seam` 占位（registry 面归转换切片），相关分支返回错误。
//! - realtime websocket 外呼（DoWssRequest）归服务装配层，trait 分支返回错误。
//! - TTS 非 pcm 格式的音频时长解析（Go `common.GetAudioDuration`）未移植，
//!   统一走尺寸回退分支。

use crate::adaptor::Adaptor as _;
use crate::adaptor::channel_type as ct;
use crate::adaptor_common::convert_claude::{
    ChatCompletionsStreamResponse, SimpleResponse, ToolCallResponse,
};
use crate::adaptor_common::usage::{self, Usage, estimate_token_by_model, valid_usage};
use crate::adaptor_common::{
    ClientSink, DoResponseOutcome, OutboundResponse, OutboundTransport, RequestContext,
    StreamEndReason, error_code, get_full_request_url, new_error, new_openai_error,
    setup_api_request_header, timestamp_now, with_openai_error, with_skip_retry,
};
use crate::relay_info::{AdaptorError, RelayInfo, build_in_call, relay_format};
use crate::relay_mode as relay_constant;
use serde_json::{Value, json};
use std::future::Future;
use std::pin::Pin;

// ---- 常量 ------------------------------------------------------------------

/// Go `openai.ModelList`（constant.go:3-76）。
pub const MODEL_LIST: &[&str] = &[
    "gpt-3.5-turbo",
    "gpt-3.5-turbo-0613",
    "gpt-3.5-turbo-1106",
    "gpt-3.5-turbo-0125",
    "gpt-3.5-turbo-16k",
    "gpt-3.5-turbo-16k-0613",
    "gpt-3.5-turbo-instruct",
    "gpt-3.5-turbo-instruct-0914",
    "gpt-4",
    "gpt-4-0613",
    "gpt-4-1106-preview",
    "gpt-4-0125-preview",
    "gpt-4-32k",
    "gpt-4-32k-0613",
    "gpt-4-turbo-preview",
    "gpt-4-turbo",
    "gpt-4-turbo-2024-04-09",
    "gpt-4-vision-preview",
    "chatgpt-4o-latest",
    "gpt-4o",
    "gpt-4o-2024-05-13",
    "gpt-4o-2024-08-06",
    "gpt-4o-2024-11-20",
    "gpt-4o-transcribe",
    "gpt-4o-transcribe-diarize",
    "gpt-4o-search-preview",
    "gpt-4o-search-preview-2025-03-11",
    "gpt-4o-mini",
    "gpt-4o-mini-2024-07-18",
    "gpt-4o-mini-transcribe",
    "gpt-4o-mini-transcribe-2025-03-20",
    "gpt-4o-mini-transcribe-2025-12-15",
    "gpt-4o-mini-tts",
    "gpt-4o-mini-tts-2025-03-20",
    "gpt-4o-mini-tts-2025-12-15",
    "gpt-4o-mini-search-preview",
    "gpt-4o-mini-search-preview-2025-03-11",
    "gpt-4.5-preview",
    "gpt-4.5-preview-2025-02-27",
    "gpt-4.1",
    "gpt-4.1-2025-04-14",
    "gpt-4.1-mini",
    "gpt-4.1-mini-2025-04-14",
    "gpt-4.1-nano",
    "gpt-4.1-nano-2025-04-14",
    "o1",
    "o1-2024-12-17",
    "o1-preview",
    "o1-preview-2024-09-12",
    "o1-mini",
    "o1-mini-2024-09-12",
    "o1-pro",
    "o1-pro-2025-03-19",
    "o3-mini",
    "o3-mini-2025-01-31",
    "o3-mini-high",
    "o3-mini-2025-01-31-high",
    "o3-mini-low",
    "o3-mini-2025-01-31-low",
    "o3-mini-medium",
    "o3-mini-2025-01-31-medium",
    "o3",
    "o3-2025-04-16",
    "o3-pro",
    "o3-pro-2025-06-10",
    "o3-deep-research",
    "o3-deep-research-2025-06-26",
    "o4-mini",
    "o4-mini-2025-04-16",
    "o4-mini-deep-research",
    "o4-mini-deep-research-2025-06-26",
    "gpt-5",
    "gpt-5-2025-08-07",
    "gpt-5-chat-latest",
    "gpt-5-mini",
    "gpt-5-mini-2025-08-07",
    "gpt-5-nano",
    "gpt-5-nano-2025-08-07",
    "gpt-5-codex",
    "gpt-5-pro",
    "gpt-5-pro-2025-10-06",
    "gpt-5-search-api",
    "gpt-5-search-api-2025-10-14",
    "gpt-5.1",
    "gpt-5.1-2025-11-13",
    "gpt-5.1-chat-latest",
    "gpt-5.1-codex",
    "gpt-5.1-codex-mini",
    "gpt-5.1-codex-max",
    "gpt-5.2",
    "gpt-5.2-2025-12-11",
    "gpt-5.2-chat-latest",
    "gpt-5.2-pro",
    "gpt-5.2-pro-2025-12-11",
    "gpt-5.2-codex",
    "gpt-5.3-chat-latest",
    "gpt-5.3-codex",
    "gpt-5.4",
    "gpt-5.4-2026-03-05",
    "gpt-5.4-pro",
    "gpt-5.4-pro-2026-03-05",
    "gpt-4o-audio-preview",
    "gpt-4o-audio-preview-2024-10-01",
    "gpt-4o-audio-preview-2024-12-17",
    "gpt-4o-audio-preview-2025-06-03",
    "gpt-4o-realtime-preview",
    "gpt-4o-realtime-preview-2024-10-01",
    "gpt-4o-realtime-preview-2024-12-17",
    "gpt-4o-realtime-preview-2025-06-03",
    "gpt-4o-mini-realtime-preview",
    "gpt-4o-mini-realtime-preview-2024-12-17",
    "gpt-4o-mini-audio-preview",
    "gpt-4o-mini-audio-preview-2024-12-17",
    "gpt-audio",
    "gpt-audio-2025-08-28",
    "gpt-audio-mini",
    "gpt-audio-mini-2025-10-06",
    "gpt-audio-mini-2025-12-15",
    "gpt-audio-1.5",
    "gpt-realtime",
    "gpt-realtime-2025-08-28",
    "gpt-realtime-mini",
    "gpt-realtime-mini-2025-10-06",
    "gpt-realtime-mini-2025-12-15",
    "gpt-realtime-1.5",
    "gpt-realtime-2",
    "gpt-realtime-2.1",
    "gpt-realtime-2.1-mini",
    "gpt-realtime-whisper",
    "gpt-realtime-translate",
    "text-embedding-ada-002",
    "text-embedding-3-small",
    "text-embedding-3-large",
    "text-curie-001",
    "text-babbage-001",
    "text-ada-001",
    "text-moderation-latest",
    "text-moderation-stable",
    "omni-moderation-latest",
    "omni-moderation-2024-09-26",
    "text-davinci-edit-001",
    "davinci-002",
    "babbage-002",
    "dall-e-2",
    "dall-e-3",
    "gpt-image-1",
    "gpt-image-1-mini",
    "gpt-image-1.5",
    "chatgpt-image-latest",
    "whisper-1",
    "tts-1",
    "tts-1-1106",
    "tts-1-hd",
    "tts-1-hd-1106",
    "computer-use-preview",
    "computer-use-preview-2025-03-11",
    "sora-2",
    "sora-2-pro",
];

/// Go `openai.ChannelName`。
pub const CHANNEL_NAME: &str = "openai";

/// Go `ai360.ModelList`（constants.go：nil 切片）。
pub const AI360_MODEL_LIST: &[&str] = &[];
/// Go `ai360.ChannelName`。
pub const AI360_CHANNEL_NAME: &str = "ai360";
/// Go `lingyiwanwu.ModelList`（constrants.go）。
pub const LINGYIWANWU_MODEL_LIST: &[&str] = &[
    "yi-large",
    "yi-medium",
    "yi-vision",
    "yi-medium-200k",
    "yi-spark",
    "yi-large-rag",
    "yi-large-turbo",
    "yi-large-preview",
    "yi-large-rag-preview",
];
/// Go `lingyiwanwu.ChannelName`。
pub const LINGYIWANWU_CHANNEL_NAME: &str = "lingyiwanwu";
/// Go `xinference.ModelList`（constant.go）。
pub const XINFERENCE_MODEL_LIST: &[&str] = &["bge-reranker-v2-m3", "jina-reranker-v2"];
/// Go `xinference.ChannelName`。
pub const XINFERENCE_CHANNEL_NAME: &str = "xinference";
/// Go `openrouter.ModelList`（constant.go：空）。
pub const OPENROUTER_MODEL_LIST: &[&str] = &[];
/// Go `openrouter.ChannelName`。
pub const OPENROUTER_CHANNEL_NAME: &str = "openrouter";

// ---- reasoning 后缀（billing/trim_reasoning_suffix.go → kit reasoning/suffix.go）--

/// Go `OpenAIEffortSuffixes`。
pub const OPENAI_EFFORT_SUFFIXES: &[&str] =
    &["-high", "-minimal", "-low", "-medium", "-none", "-xhigh"];
/// Go `EffortSuffixes`。
pub const EFFORT_SUFFIXES: &[&str] = &["-max", "-xhigh", "-high", "-medium", "-low", "-minimal"];

/// Go `TrimEffortSuffixWithSuffixes`：返回 (base_model, level, found)。
pub fn trim_effort_suffix_with_suffixes(
    model_name: &str,
    suffixes: &[&str],
) -> (String, String, bool) {
    for suffix in suffixes {
        if let Some(base) = model_name.strip_suffix(suffix) {
            return (
                base.to_owned(),
                suffix.trim_start_matches('-').to_owned(),
                true,
            );
        }
    }
    (model_name.to_owned(), String::new(), false)
}

/// Go `TrimEffortSuffix`。
pub fn trim_effort_suffix(model_name: &str) -> (String, String, bool) {
    trim_effort_suffix_with_suffixes(model_name, EFFORT_SUFFIXES)
}

/// Go `ParseOpenAIReasoningEffortFromModelSuffix`：返回 (effort, origin_model)。
pub fn parse_openai_reasoning_effort_from_model_suffix(model_name: &str) -> (String, String) {
    let (base_model, effort, ok) =
        trim_effort_suffix_with_suffixes(model_name, OPENAI_EFFORT_SUFFIXES);
    if !ok {
        return (String::new(), model_name.to_owned());
    }
    (effort, base_model)
}

/// Go `dto.IsOpenAIReasoningOModel`。
pub fn is_openai_reasoning_o_model(model_name: &str) -> bool {
    model_name.starts_with("o1") || model_name.starts_with("o3") || model_name.starts_with("o4")
}

/// Go `dto.IsOpenAIGPT5Model`。
pub fn is_openai_gpt5_model(model_name: &str) -> bool {
    model_name.starts_with("gpt-5")
}

/// Go `model_setting.ShouldPreserveThinkingSuffix`（manage_models.go:284-295）。
pub fn should_preserve_thinking_suffix(info: &RelayInfo, model_name: &str) -> bool {
    let target = model_name.trim();
    if target.is_empty() {
        return false;
    }
    info.global_model_settings
        .thinking_model_blacklist
        .iter()
        .any(|entry| entry.trim() == target)
}

// ---- 适配器 ----------------------------------------------------------------

/// Go `openai.Adaptor`。
#[derive(Debug, Default)]
pub struct OpenAiAdaptor {
    /// Go `a.ChannelType`（Init 时从 info 拷贝）。
    pub channel_type: i32,
    /// Go `a.ResponseFormat`（ConvertAudioRequest 时捕获，STT handler 使用）。
    pub response_format: String,
}

impl OpenAiAdaptor {
    pub fn new() -> Self {
        Self::default()
    }
}

fn is_json_request(client_headers: &[(String, String)]) -> bool {
    crate::adaptor_common::header_value(client_headers, "content-type")
        .starts_with("application/json")
}

fn channel_other_str(info: &RelayInfo, key: &str) -> String {
    info.channel_other_settings()
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned()
}

fn headers_override_has_authorization(info: &RelayInfo) -> bool {
    info.headers_override().as_object().is_some_and(|map| {
        map.keys()
            .any(|key| key.eq_ignore_ascii_case("Authorization"))
    })
}

fn remove_field(request: &mut Value, field: &str) {
    if let Some(obj) = request.as_object_mut() {
        obj.remove(field);
    }
}

fn field_is_empty_object(request: &Value, field: &str) -> bool {
    request
        .get(field)
        .map(|v| !v.is_object() || v.as_object().is_none_or(|o| o.is_empty()))
        .unwrap_or(true)
}

/// relayconvert registry 请求转换 seam：claude/gemini → openai 请求的深度
/// 转换（消息/工具/思考字段重写）归转换切片。
fn relayconvert_request_seam() -> String {
    "relayconvert: request conversion registry not ported yet (separate slice)".to_owned()
}

/// relayconvert registry 响应转换 seam。
fn relayconvert_response_seam(target: &str) -> String {
    format!(
        "relayconvert: response conversion registry for {target} not ported yet (separate slice)"
    )
}

impl crate::adaptor::Adaptor for OpenAiAdaptor {
    /// Go `Init`（adaptor.go:90-101）。
    fn init(&mut self, info: &mut RelayInfo) {
        self.channel_type = info.channel_type();
        if info.thinking_to_content() {
            info.is_first_thinking_content = true;
            info.send_last_thinking_content = false;
            info.has_sent_thinking_content = false;
        }
    }

    /// Go `GetRequestURL`（adaptor.go:103-179）。
    fn get_request_url(&self, info: &mut RelayInfo) -> Result<String, String> {
        if info.relay_mode == relay_constant::RELAY_MODE_REALTIME {
            let base_url = info.channel_base_url();
            if let Some(stripped) = base_url.strip_prefix("https://") {
                info.set_channel_base_url(format!("wss://{stripped}"));
            } else if let Some(stripped) = base_url.strip_prefix("http://") {
                info.set_channel_base_url(format!("ws://{stripped}"));
            }
        }
        let channel_type = info.channel_type();
        let base_url = info.channel_base_url();
        match channel_type {
            ct::AZURE => {
                let mut api_version = info.api_version();
                if api_version.is_empty() {
                    api_version = crate::adaptor_common::AZURE_DEFAULT_API_VERSION.to_owned();
                }
                let path_without_query = info
                    .request_url_path
                    .split('?')
                    .next()
                    .unwrap_or(&info.request_url_path)
                    .to_owned();
                let request_url = format!("{path_without_query}?api-version={api_version}");
                let mut task = request_url
                    .strip_prefix("/v1/")
                    .unwrap_or(&request_url)
                    .to_owned();

                if info.relay_format == relay_format::CLAUDE {
                    task = task.strip_prefix("messages").unwrap_or(&task).to_owned();
                    task = format!("chat/completions{task}");
                }

                // 特殊处理 responses API（包含 compact）
                if info.relay_mode == relay_constant::RELAY_MODE_RESPONSES
                    || info.relay_mode == relay_constant::RELAY_MODE_RESPONSES_COMPACT
                {
                    let mut responses_api_version = "preview".to_owned();

                    let mut sub_url = "/openai/v1/responses".to_owned();
                    if base_url.contains("cognitiveservices.azure.com") {
                        sub_url = "/openai/responses".to_owned();
                        responses_api_version = api_version;
                    }

                    let azure_override = channel_other_str(info, "azure_responses_version");
                    if !azure_override.is_empty() {
                        responses_api_version = azure_override;
                    }

                    if info.relay_mode == relay_constant::RELAY_MODE_RESPONSES_COMPACT {
                        sub_url = format!("{sub_url}/compact");
                    }

                    let request_url = format!("{sub_url}?api-version={responses_api_version}");
                    return Ok(get_full_request_url(&base_url, &request_url, channel_type));
                }

                let mut model = info.upstream_model_name();
                // 2025年5月10日后创建的渠道不移除.
                if info.channel_create_time() < crate::adaptor_common::AZURE_NO_REMOVE_DOT_TIME {
                    model = model.replace('.', "");
                }
                // https://github.com/songquanpeng/one-api/issues/67
                let mut request_url = format!("/openai/deployments/{model}/{task}");
                if info.relay_mode == relay_constant::RELAY_MODE_REALTIME {
                    request_url =
                        format!("/openai/realtime?deployment={model}&api-version={api_version}");
                }
                Ok(get_full_request_url(&base_url, &request_url, channel_type))
            }
            ct::CUSTOM => {
                let url = base_url.replace("{model}", &info.upstream_model_name());
                Ok(url)
            }
            _ => {
                if (info.relay_format == relay_format::CLAUDE
                    || info.relay_format == relay_format::GEMINI)
                    && info.relay_mode != relay_constant::RELAY_MODE_RESPONSES
                    && info.relay_mode != relay_constant::RELAY_MODE_RESPONSES_COMPACT
                {
                    return Ok(format!("{base_url}/v1/chat/completions"));
                }
                Ok(get_full_request_url(
                    &base_url,
                    &info.request_url_path,
                    channel_type,
                ))
            }
        }
    }

    /// Go `SetupRequestHeader`（adaptor.go:181-243）。
    fn setup_request_header(
        &self,
        info: &RelayInfo,
        client_headers: &[(String, String)],
    ) -> Result<Vec<(String, String)>, String> {
        let mut headers = setup_api_request_header(
            info,
            client_headers,
            info.relay_mode == relay_constant::RELAY_MODE_AUDIO_TRANSCRIPTION
                || info.relay_mode == relay_constant::RELAY_MODE_AUDIO_TRANSLATION,
            info.relay_mode == relay_constant::RELAY_MODE_REALTIME,
        );
        let channel_type = info.channel_type();
        if channel_type == ct::AZURE {
            headers.push(("api-key".to_owned(), info.api_key()));
            return Ok(headers);
        }
        if channel_type == ct::OPENAI && !info.organization().is_empty() {
            headers.push(("OpenAI-Organization".to_owned(), info.organization()));
        }
        let has_auth_override = headers_override_has_authorization(info);
        if info.relay_mode == relay_constant::RELAY_MODE_REALTIME {
            let legacy_realtime_beta = info.upstream_model_name().contains("-realtime-preview");
            let swp = crate::adaptor_common::header_value(client_headers, "sec-websocket-protocol");
            if !swp.is_empty() {
                let mut items = vec![
                    "realtime".to_owned(),
                    format!("openai-insecure-api-key.{}", info.api_key()),
                ];
                if legacy_realtime_beta {
                    items.push("openai-beta.realtime-v1".to_owned());
                }
                headers.push(("Sec-WebSocket-Protocol".to_owned(), items.join(",")));
            } else {
                if legacy_realtime_beta {
                    headers.push(("openai-beta".to_owned(), "realtime=v1".to_owned()));
                }
                if !has_auth_override {
                    headers.push((
                        "Authorization".to_owned(),
                        format!("Bearer {}", info.api_key()),
                    ));
                }
            }
        } else if !has_auth_override {
            headers.push((
                "Authorization".to_owned(),
                format!("Bearer {}", info.api_key()),
            ));
        }
        if channel_type == ct::OPEN_ROUTER {
            let has_referer = headers
                .iter()
                .any(|(key, _)| key.eq_ignore_ascii_case("HTTP-Referer"));
            if !has_referer {
                headers.push((
                    "HTTP-Referer".to_owned(),
                    "https://www.newapi.ai".to_owned(),
                ));
            }
            let has_title = headers
                .iter()
                .any(|(key, _)| key.eq_ignore_ascii_case("X-OpenRouter-Title"));
            if !has_title {
                headers.push(("X-OpenRouter-Title".to_owned(), "New API".to_owned()));
            }
        }
        Ok(headers)
    }

    /// Go `ConvertOpenAIRequest`（adaptor.go:245-368）。
    fn convert_openai_request(
        &self,
        info: &mut RelayInfo,
        request: &Value,
    ) -> Result<Value, String> {
        let mut request = request.clone();
        let channel_type = info.channel_type();
        if channel_type != ct::OPENAI && channel_type != ct::AZURE {
            remove_field(&mut request, "stream_options");
        }
        if channel_type == ct::OPEN_ROUTER {
            if field_is_empty_object(&request, "usage") {
                request["usage"] = json!({"include": true});
            }
            // 适配 OpenRouter 的 thinking 后缀
            let upstream_model = info.upstream_model_name();
            if !should_preserve_thinking_suffix(info, &info.origin_model_name)
                && upstream_model.ends_with("-thinking")
            {
                let new_model = upstream_model.trim_end_matches("-thinking").to_owned();
                info.set_upstream_model_name(new_model.clone());
                request["model"] = json!(new_model);
                if field_is_empty_object(&request, "reasoning") {
                    let reasoning_effort = request
                        .get("reasoning_effort")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let mut reasoning = json!({"enabled": true});
                    if !reasoning_effort.is_empty() && reasoning_effort != "none" {
                        reasoning["effort"] = json!(reasoning_effort);
                    }
                    request["reasoning"] = reasoning;
                }
                // 清空多余的ReasoningEffort
                remove_field(&mut request, "reasoning_effort");
            } else {
                if field_is_empty_object(&request, "reasoning") {
                    // 适配 OpenAI 的 ReasoningEffort 格式
                    let reasoning_effort = request
                        .get("reasoning_effort")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if !reasoning_effort.is_empty() {
                        let mut reasoning = json!({"enabled": true});
                        if reasoning_effort != "none" {
                            reasoning["effort"] = json!(reasoning_effort);
                            request["reasoning"] = reasoning;
                        }
                    }
                }
                remove_field(&mut request, "reasoning_effort");
            }

            // https://docs.anthropic.com/en/api/openai-sdk#extended-thinking-support
            let upstream_model = info.upstream_model_name();
            let thinking_present = request
                .get("thinking")
                .map(|t| !t.is_null())
                .unwrap_or(false);
            if thinking_present && upstream_model.starts_with("anthropic") {
                let thinking_type = request
                    .get("thinking")
                    .and_then(|t| t.get("type"))
                    .and_then(|t| t.as_str())
                    .unwrap_or("");
                if thinking_type == "enabled" {
                    let budget_tokens = request
                        .get("thinking")
                        .and_then(|t| t.get("budget_tokens"))
                        .and_then(|t| t.as_i64());
                    let Some(budget_tokens) = budget_tokens else {
                        return Err("BudgetTokens is nil when thinking is enabled".to_owned());
                    };
                    request["reasoning"] = json!({"enabled": true, "max_tokens": budget_tokens});
                }
                remove_field(&mut request, "thinking");
            }
        }
        let upstream_model = info.upstream_model_name();
        let is_o_model = is_openai_reasoning_o_model(&upstream_model);
        let is_gpt5_model = is_openai_gpt5_model(&upstream_model);
        if is_o_model || is_gpt5_model {
            let max_completion_tokens = request
                .get("max_completion_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let max_tokens = request
                .get("max_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            if max_completion_tokens == 0 && max_tokens != 0 {
                request["max_completion_tokens"] = json!(max_tokens);
                remove_field(&mut request, "max_tokens");
            }

            if is_o_model {
                remove_field(&mut request, "temperature");
            }

            // gpt-5系列模型适配 归零不再支持的参数
            if is_gpt5_model {
                remove_field(&mut request, "temperature");
                remove_field(&mut request, "top_p");
                remove_field(&mut request, "logprobs");
            }

            // 转换模型推理力度后缀
            let (effort, origin_model) =
                parse_openai_reasoning_effort_from_model_suffix(&upstream_model);
            if !effort.is_empty() {
                request["reasoning_effort"] = json!(effort);
                info.set_upstream_model_name(origin_model.clone());
                request["model"] = json!(origin_model);
            }

            let effort_now = request
                .get("reasoning_effort")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            info.set_reasoning_effort(effort_now);

            // o系列模型developer适配（o1-mini除外）
            let upstream_model = info.upstream_model_name();
            if !upstream_model.starts_with("o1-mini")
                && !upstream_model.starts_with("o1-preview")
                && let Some(messages) = request.get_mut("messages").and_then(|m| m.as_array_mut())
                && let Some(first) = messages.first_mut()
                && first.get("role").and_then(|r| r.as_str()) == Some("system")
            {
                //修改第一个Message的内容，将system改为developer
                first["role"] = json!("developer");
            }
        }

        Ok(request)
    }

    /// Go `ConvertClaudeRequest`（adaptor.go:54-88）。
    fn convert_claude_request(
        &self,
        info: &mut RelayInfo,
        request: &Value,
    ) -> Result<Value, String> {
        // Go: relaycommon.ConvertRequest(c, info, RelayFormatOpenAI, request) ——
        // claude→openai 请求转换引擎（relayconvert registry）归转换切片。
        let _ = (info, request);
        Err(relayconvert_request_seam())
    }

    /// Go `ConvertGeminiRequest`（adaptor.go:42-52）。
    fn convert_gemini_request(
        &self,
        info: &mut RelayInfo,
        request: &Value,
    ) -> Result<Value, String> {
        // Go: relaycommon.ConvertRequest(..., RelayFormatOpenAI, geminiRequest) ——
        // gemini→openai 请求转换归 relayconvert 切片。
        let _ = (info, request);
        Err(relayconvert_request_seam())
    }

    /// Go `ConvertRerankRequest`（adaptor.go:370-372）。
    fn convert_rerank_request(&self, _relay_mode: i32, request: &Value) -> Result<Value, String> {
        Ok(request.clone())
    }

    /// Go `ConvertEmbeddingRequest`（adaptor.go:374-376）。
    fn convert_embedding_request(
        &self,
        _info: &mut RelayInfo,
        request: &Value,
    ) -> Result<Value, String> {
        Ok(request.clone())
    }

    /// Go `ConvertImageRequest`（adaptor.go:444-579）。
    fn convert_image_request(
        &self,
        info: &mut RelayInfo,
        request: &Value,
        multipart: Option<&crate::adaptor_common::ParsedMultipartForm>,
    ) -> Result<crate::adaptor_common::ConvertedRequestBody, String> {
        if info.relay_mode == relay_constant::RELAY_MODE_IMAGES_EDITS {
            let content_type = info
                .request_headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case("content-type"))
                .map(|(_, value)| value.as_str())
                .unwrap_or("");
            if content_type.starts_with("application/json") {
                return Ok(crate::adaptor_common::ConvertedRequestBody::Json(
                    request.clone(),
                ));
            }
            let Some(multipart) = multipart else {
                return Err("no multipart form data found".to_owned());
            };
            let assembled = build_image_edit_multipart(multipart, request)?;
            return Ok(crate::adaptor_common::ConvertedRequestBody::Multipart {
                body: assembled.body,
                content_type: assembled.content_type,
            });
        }
        Ok(crate::adaptor_common::ConvertedRequestBody::Json(
            request.clone(),
        ))
    }

    /// Go `ConvertOpenAIResponsesRequest`（adaptor.go:608-625）。
    fn convert_openai_responses_request(
        &self,
        info: &mut RelayInfo,
        request: &Value,
    ) -> Result<Value, String> {
        let mut request = request.clone();
        let model = request
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let (effort, origin_model) = parse_openai_reasoning_effort_from_model_suffix(&model);
        if !effort.is_empty() {
            if request
                .get("reasoning")
                .map(|r| r.is_null())
                .unwrap_or(true)
            {
                request["reasoning"] = json!({"effort": effort});
            } else {
                request["reasoning"]["effort"] = json!(effort);
            }
            request["model"] = json!(origin_model);
        }
        let effort_value = request
            .get("reasoning")
            .and_then(|r| r.get("effort"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !effort_value.is_empty() {
            info.set_reasoning_effort(effort_value);
        }
        Ok(request)
    }

    /// Go `ConvertAudioRequest`（adaptor.go:378-442）。
    fn convert_audio_request(
        &self,
        info: &mut RelayInfo,
        request: &Value,
        multipart: Option<&crate::adaptor_common::ParsedMultipartForm>,
    ) -> Result<crate::adaptor_common::ConvertedRequestBody, String> {
        let response_format = request
            .get("response_format")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        // Go: a.ResponseFormat = request.ResponseFormat（trait &self 限制下平铺到
        // info.audio_response_format，STT/TTS handler 共用）。
        info.audio_response_format = response_format;
        if info.relay_mode == relay_constant::RELAY_MODE_AUDIO_SPEECH {
            // Go: common.Marshal(request) —— AudioRequest 整体序列化。
            return Ok(crate::adaptor_common::ConvertedRequestBody::Json(
                request.clone(),
            ));
        }
        let Some(multipart) = multipart else {
            return Err("error parsing multipart form: missing form".to_owned());
        };
        let assembled = build_audio_multipart(multipart, request)
            .ok_or_else(|| "file is required".to_owned())?;
        Ok(crate::adaptor_common::ConvertedRequestBody::Multipart {
            body: assembled.body,
            content_type: assembled.content_type,
        })
    }

    /// Go `DoRequest`（adaptor.go:627-637）：form / realtime / api 分派。
    fn do_request<'a>(
        &'a self,
        info: &'a mut RelayInfo,
        context: &'a RequestContext<'_>,
        request_body: &'a [u8],
        transport: &'a dyn OutboundTransport,
    ) -> Pin<Box<dyn Future<Output = Result<OutboundResponse, AdaptorError>> + Send + 'a>> {
        Box::pin(async move {
            if info.relay_mode == relay_constant::RELAY_MODE_AUDIO_TRANSCRIPTION
                || info.relay_mode == relay_constant::RELAY_MODE_AUDIO_TRANSLATION
                || (info.relay_mode == relay_constant::RELAY_MODE_IMAGES_EDITS
                    && !is_json_request(context.client_headers))
            {
                self.do_form_request(info, context, request_body, transport)
                    .await
            } else if info.relay_mode == relay_constant::RELAY_MODE_REALTIME {
                Err(new_error(
                    "realtime websocket dial is owned by the server assembly (DoWssRequest)",
                    error_code::BAD_RESPONSE,
                ))
            } else {
                self.do_api_request(info, context, request_body, transport)
                    .await
            }
        })
    }

    /// Go `DoResponse`（adaptor.go:639-673）。
    fn do_response(
        &self,
        info: &mut RelayInfo,
        response: &mut OutboundResponse,
        sink: &mut dyn ClientSink,
    ) -> DoResponseOutcome {
        match info.relay_mode {
            relay_constant::RELAY_MODE_AUDIO_SPEECH => DoResponseOutcome::ok(openai_tts_handler(
                info,
                response,
                sink,
                &self.response_format,
            )),
            relay_constant::RELAY_MODE_AUDIO_TRANSLATION
            | relay_constant::RELAY_MODE_AUDIO_TRANSCRIPTION => {
                match openai_stt_handler(info, response, sink) {
                    Ok(usage) => DoResponseOutcome::ok(usage),
                    Err(err) => DoResponseOutcome::error(Usage::default(), err),
                }
            }
            relay_constant::RELAY_MODE_IMAGES_GENERATIONS
            | relay_constant::RELAY_MODE_IMAGES_EDITS => {
                if info.is_stream {
                    openai_image_stream_handler(info, response, sink)
                } else {
                    openai_image_handler(info, response, sink)
                }
            }
            relay_constant::RELAY_MODE_RERANK => {
                // Go: common_handler.RerankHandler —— 通用 rerank 面归共享切片；
                // openai 渠道 rerank 为逐字节透传。
                openai_passthrough_handler(info, response, sink)
            }
            relay_constant::RELAY_MODE_RESPONSES => {
                if info.is_stream {
                    oai_responses_stream_handler(info, response, sink)
                } else {
                    oai_responses_handler(info, response, sink)
                }
            }
            relay_constant::RELAY_MODE_RESPONSES_COMPACT => {
                oai_responses_compaction_handler(info, response, sink)
            }
            _ => {
                if info.is_stream {
                    oai_stream_handler(info, response, sink)
                } else {
                    openai_handler(info, response, sink)
                }
            }
        }
    }

    /// Go `GetModelList`（adaptor.go:675-690）。
    fn get_model_list(&self) -> Vec<String> {
        match self.channel_type {
            ct::CHANNEL_TYPE_360 => AI360_MODEL_LIST.iter().map(|s| (*s).to_owned()).collect(),
            ct::LING_YI_WAN_WU => LINGYIWANWU_MODEL_LIST
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            ct::XINFERENCE => XINFERENCE_MODEL_LIST
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            ct::OPEN_ROUTER => OPENROUTER_MODEL_LIST
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            _ => MODEL_LIST.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    /// Go `GetChannelName`（adaptor.go:692-707）。
    fn get_channel_name(&self) -> String {
        match self.channel_type {
            ct::CHANNEL_TYPE_360 => AI360_CHANNEL_NAME.to_owned(),
            ct::LING_YI_WAN_WU => LINGYIWANWU_CHANNEL_NAME.to_owned(),
            ct::XINFERENCE => XINFERENCE_CHANNEL_NAME.to_owned(),
            ct::OPEN_ROUTER => OPENROUTER_CHANNEL_NAME.to_owned(),
            _ => CHANNEL_NAME.to_owned(),
        }
    }
}

impl OpenAiAdaptor {
    /// Go `DoApiRequest`（api_request.go:324-352）形态。
    fn do_api_request<'a>(
        &'a self,
        info: &'a mut RelayInfo,
        context: &'a RequestContext<'_>,
        request_body: &'a [u8],
        transport: &'a dyn OutboundTransport,
    ) -> Pin<Box<dyn Future<Output = Result<OutboundResponse, AdaptorError>> + Send + 'a>> {
        Box::pin(async move {
            let url = self.get_request_url(info).map_err(|err| {
                new_error(
                    format!("get request url failed: {err}"),
                    error_code::BAD_RESPONSE,
                )
            })?;
            let headers = self
                .setup_request_header(info, context.client_headers)
                .map_err(|err| {
                    new_error(
                        format!("setup request header failed: {err}"),
                        error_code::BAD_RESPONSE,
                    )
                })?;
            let request = crate::adaptor_common::build_api_request(
                info,
                context,
                url,
                headers,
                request_body.to_vec(),
            )?;
            transport
                .execute(request)
                .await
                .map_err(|err| new_error(err, error_code::DO_REQUEST_FAILED))
        })
    }

    /// Go `DoFormRequest`（api_request.go:354-384）：Content-Type 保留客户端
    /// multipart boundary。
    fn do_form_request<'a>(
        &'a self,
        info: &'a mut RelayInfo,
        context: &'a RequestContext<'_>,
        request_body: &'a [u8],
        transport: &'a dyn OutboundTransport,
    ) -> Pin<Box<dyn Future<Output = Result<OutboundResponse, AdaptorError>> + Send + 'a>> {
        Box::pin(async move {
            let url = self.get_request_url(info).map_err(|err| {
                new_error(
                    format!("get request url failed: {err}"),
                    error_code::BAD_RESPONSE,
                )
            })?;
            let mut headers = vec![(
                "Content-Type".to_owned(),
                crate::adaptor_common::header_value(context.client_headers, "content-type")
                    .to_owned(),
            )];
            let base = self
                .setup_request_header(info, context.client_headers)
                .map_err(|err| {
                    new_error(
                        format!("setup request header failed: {err}"),
                        error_code::BAD_RESPONSE,
                    )
                })?;
            for (key, value) in base {
                if key.eq_ignore_ascii_case("Content-Type") {
                    continue;
                }
                headers.push((key, value));
            }
            let request = crate::adaptor_common::build_api_request(
                info,
                context,
                url,
                headers,
                request_body.to_vec(),
            )?;
            transport
                .execute(request)
                .await
                .map_err(|err| new_error(err, error_code::DO_REQUEST_FAILED))
        })
    }
}

// ---- multipart 装配 --------------------------------------------------------

/// Go `ConvertAudioRequest` 的非 speech 分支（adaptor.go:387-441）：所有表单
/// 字段 + 首个 `file` 文件件。
pub fn build_audio_multipart(
    form: &crate::adaptor_common::ParsedMultipartForm,
    request: &Value,
) -> Option<AssembledMultipart> {
    let model = request
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    let mut builder = MultipartBuilder::new();
    builder.write_field("model", &model);
    for (key, value) in &form.fields {
        if key == "model" {
            continue;
        }
        builder.write_field(key, value);
    }
    let file = form.files.iter().find(|part| part.field_name == "file")?;
    builder.write_form_file("file", &file.filename, &file.content_type, &file.bytes);
    Some(builder.finish())
}

/// Go `ConvertImageRequest` 的 IMAGES_EDITS multipart 分支（adaptor.go:451-574）。
pub fn build_image_edit_multipart(
    form: &crate::adaptor_common::ParsedMultipartForm,
    request: &Value,
) -> Result<AssembledMultipart, String> {
    let model = request
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    let mut builder = MultipartBuilder::new();
    builder.write_field("model", &model);
    // 写入所有非文件字段
    for (key, value) in &form.fields {
        if key == "model" {
            continue;
        }
        builder.write_field(key, value);
    }

    if form.files.is_empty() {
        return Err("no multipart form data found".to_owned());
    }

    // image 字段解析：`image` → `image[]` → 任意 `image[` 前缀字段。
    let standard: Vec<&crate::adaptor_common::MultipartFilePart> = form
        .files
        .iter()
        .filter(|part| part.field_name == "image")
        .collect();
    let image_files: Vec<&crate::adaptor_common::MultipartFilePart> = if !standard.is_empty() {
        standard
    } else {
        let bracketed: Vec<&crate::adaptor_common::MultipartFilePart> = form
            .files
            .iter()
            .filter(|part| part.field_name == "image[]")
            .collect();
        if !bracketed.is_empty() {
            bracketed
        } else {
            let array_images: Vec<&crate::adaptor_common::MultipartFilePart> = form
                .files
                .iter()
                .filter(|part| part.field_name.starts_with("image["))
                .collect();
            if array_images.is_empty() {
                return Err("image is required".to_owned());
            }
            array_images
        }
    };

    let multiple = image_files.len() > 1;
    for file in &image_files {
        let field_name = if multiple { "image[]" } else { "image" };
        let mime = detect_image_mime_type(&file.filename);
        builder.write_form_file_with_mime(field_name, &file.filename, &mime, &file.bytes);
    }

    // mask 文件（第一个）
    if let Some(mask) = form.files.iter().find(|part| part.field_name == "mask") {
        let mime = detect_image_mime_type(&mask.filename);
        builder.write_form_file_with_mime("mask", &mask.filename, &mime, &mask.bytes);
    }

    Ok(builder.finish())
}

/// 装配结果（multipart 体 + Content-Type）。
#[derive(Clone, Debug)]
pub struct AssembledMultipart {
    pub body: Vec<u8>,
    pub content_type: String,
}

/// Go `mime/multipart.Writer` 的最小实现（边界行/字段件/文件件/Closure）。
struct MultipartBuilder {
    boundary: String,
    body: Vec<u8>,
}

impl MultipartBuilder {
    fn new() -> Self {
        Self {
            boundary: crate::adaptor_common::random_uuid(),
            body: Vec::new(),
        }
    }

    fn write_field(&mut self, name: &str, value: &str) {
        self.body
            .extend_from_slice(format!("--{}\r\n", self.boundary).as_bytes());
        self.body.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
        );
        self.body.extend_from_slice(value.as_bytes());
        self.body.extend_from_slice(b"\r\n");
    }

    fn write_form_file(&mut self, name: &str, filename: &str, content_type: &str, bytes: &[u8]) {
        self.write_form_file_with_mime(name, filename, content_type, bytes);
    }

    fn write_form_file_with_mime(&mut self, name: &str, filename: &str, mime: &str, bytes: &[u8]) {
        self.body
            .extend_from_slice(format!("--{}\r\n", self.boundary).as_bytes());
        self.body.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\n")
                .as_bytes(),
        );
        let content_type = if mime.is_empty() {
            "application/octet-stream"
        } else {
            mime
        };
        self.body
            .extend_from_slice(format!("Content-Type: {content_type}\r\n\r\n").as_bytes());
        self.body.extend_from_slice(bytes);
        self.body.extend_from_slice(b"\r\n");
    }

    fn finish(self) -> AssembledMultipart {
        let mut body = self.body;
        body.extend_from_slice(format!("--{}--\r\n", self.boundary).as_bytes());
        AssembledMultipart {
            body,
            content_type: format!("multipart/form-data; boundary={}", self.boundary),
        }
    }
}

/// Go `detectImageMimeType`（adaptor.go:589-606）。
pub fn detect_image_mime_type(filename: &str) -> String {
    let ext = filename
        .rsplit_once('.')
        .map(|(_, e)| format!(".{}", e.to_lowercase()))
        .unwrap_or_default();
    match ext.as_str() {
        ".jpg" | ".jpeg" => "image/jpeg".to_owned(),
        ".png" => "image/png".to_owned(),
        ".webp" => "image/webp".to_owned(),
        _ => {
            if ext.starts_with(".jp") {
                "image/jpeg".to_owned()
            } else {
                "image/png".to_owned()
            }
        }
    }
}

// ---- usage post-processing（usage.go） --------------------------------------

/// Go `applyUsagePostProcessing`（usage.go:10-51）。
pub fn apply_usage_post_processing(info: &RelayInfo, usage: &mut Usage, response_body: &[u8]) {
    match info.channel_type() {
        ct::DEEP_SEEK => {
            if usage.prompt_tokens_details.cached_tokens == 0 && usage.prompt_cache_hit_tokens != 0
            {
                usage.prompt_tokens_details.cached_tokens = usage.prompt_cache_hit_tokens;
            }
        }
        ct::ZHIPU_V4 => {
            if usage.prompt_tokens_details.cached_tokens == 0 {
                if let Some(input_details) = &usage.input_tokens_details
                    && input_details.cached_tokens > 0
                {
                    usage.prompt_tokens_details.cached_tokens = input_details.cached_tokens;
                } else if let Some(cached) = extract_cached_tokens_from_body(response_body) {
                    usage.prompt_tokens_details.cached_tokens = cached;
                } else if usage.prompt_cache_hit_tokens > 0 {
                    usage.prompt_tokens_details.cached_tokens = usage.prompt_cache_hit_tokens;
                }
            }
        }
        ct::MOONSHOT => {
            if usage.prompt_tokens_details.cached_tokens == 0 {
                if let Some(input_details) = &usage.input_tokens_details
                    && input_details.cached_tokens > 0
                {
                    usage.prompt_tokens_details.cached_tokens = input_details.cached_tokens;
                } else if let Some(cached) = extract_moonshot_cached_tokens_from_body(response_body)
                {
                    usage.prompt_tokens_details.cached_tokens = cached;
                } else if let Some(cached) = extract_cached_tokens_from_body(response_body) {
                    usage.prompt_tokens_details.cached_tokens = cached;
                } else if usage.prompt_cache_hit_tokens > 0 {
                    usage.prompt_tokens_details.cached_tokens = usage.prompt_cache_hit_tokens;
                }
            }
        }
        ct::OPENAI => {
            if usage.prompt_tokens_details.cached_tokens == 0
                && let Some(cached) = extract_llama_cached_tokens_from_body(response_body)
            {
                usage.prompt_tokens_details.cached_tokens = cached;
            }
        }
        _ => {}
    }
}

/// Go `extractCachedTokensFromBody`。
fn extract_cached_tokens_from_body(body: &[u8]) -> Option<i64> {
    if body.is_empty() {
        return None;
    }
    let payload: Value = serde_json::from_slice(body).ok()?;
    let usage = payload.get("usage")?;
    if let Some(cached) = usage
        .get("prompt_tokens_details")
        .and_then(|d| d.get("cached_tokens"))
        && !cached.is_null()
    {
        return cached.as_i64();
    }
    if let Some(cached) = usage.get("cached_tokens")
        && !cached.is_null()
    {
        return cached.as_i64();
    }
    if let Some(cached) = usage.get("prompt_cache_hit_tokens")
        && !cached.is_null()
    {
        return cached.as_i64();
    }
    None
}

/// Go `extractMoonshotCachedTokensFromBody`：`choices[].usage.cached_tokens`。
fn extract_moonshot_cached_tokens_from_body(body: &[u8]) -> Option<i64> {
    if body.is_empty() {
        return None;
    }
    let payload: Value = serde_json::from_slice(body).ok()?;
    for choice in payload.get("choices")?.as_array()? {
        if let Some(cached) = choice
            .get("usage")
            .and_then(|u| u.get("cached_tokens"))
            .and_then(|v| v.as_i64())
            && cached > 0
        {
            return Some(cached);
        }
    }
    None
}

/// Go `extractLlamaCachedTokensFromBody`：`timings.cache_n`。
fn extract_llama_cached_tokens_from_body(body: &[u8]) -> Option<i64> {
    if body.is_empty() {
        return None;
    }
    let payload: Value = serde_json::from_slice(body).ok()?;
    payload
        .get("timings")
        .and_then(|t| t.get("cache_n"))
        .and_then(|v| v.as_i64())
}

// ---- 流式处理（relay-openai.go / stream_observe.go / handle_stream_format.go）--

/// Go `streamObserver`：fast-path 逐块观察（不改写转发字节）。
#[derive(Debug, Default)]
struct StreamObserver {
    relay_mode: i32,
    response_text: String,
    tool_count: i64,
    tool_names: Vec<String>,
    seen_tool_call: std::collections::HashSet<String>,
    saw_finish_reason: bool,
    usage: Option<Usage>,
}

impl StreamObserver {
    fn new(relay_mode: i32) -> Self {
        Self {
            relay_mode,
            ..Default::default()
        }
    }

    /// Go `observe`。
    fn observe(&mut self, data: &str) {
        if data.is_empty() {
            return;
        }
        let Ok(root) = serde_json::from_str::<Value>(data) else {
            return;
        };
        if !root.is_object() {
            return;
        }
        if let Some(usage_value) = root.get("usage")
            && usage_value.is_object()
            && let Ok(parsed) = serde_json::from_value::<Usage>(usage_value.clone())
            && valid_usage(&parsed)
        {
            self.usage = Some(parsed);
        }

        match self.relay_mode {
            relay_constant::RELAY_MODE_CHAT_COMPLETIONS => {
                self.read_chat_choices(root.get("choices"));
            }
            relay_constant::RELAY_MODE_COMPLETIONS => {
                if let Some(choices) = root.get("choices").and_then(|c| c.as_array()) {
                    for choice in choices {
                        self.response_text
                            .push_str(choice.get("text").and_then(|t| t.as_str()).unwrap_or(""));
                        if let Some(finish) = choice.get("finish_reason").and_then(|f| f.as_str())
                            && !finish.is_empty()
                        {
                            self.saw_finish_reason = true;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// Go `readChatChoices`。
    fn read_chat_choices(&mut self, choices: Option<&Value>) {
        let Some(choices) = choices.and_then(|c| c.as_array()) else {
            return;
        };
        for choice in choices {
            if let Some(finish) = choice.get("finish_reason").and_then(|f| f.as_str())
                && !finish.is_empty()
            {
                self.saw_finish_reason = true;
            }
            let delta = choice.get("delta");
            self.response_text.push_str(
                delta
                    .and_then(|d| d.get("content"))
                    .and_then(|c| c.as_str())
                    .unwrap_or(""),
            );
            self.response_text.push_str(&delta_reasoning(delta));

            let Some(tool_calls) = delta
                .and_then(|d| d.get("tool_calls"))
                .and_then(|t| t.as_array())
            else {
                continue;
            };
            if tool_calls.len() as i64 > self.tool_count {
                self.tool_count = tool_calls.len() as i64;
            }
            let choice_index = choice.get("index").and_then(|i| i.as_i64()).unwrap_or(0);
            for (i, tc) in tool_calls.iter().enumerate() {
                let function = tc.get("function");
                let name = function
                    .and_then(|f| f.get("name"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("");
                self.response_text.push_str(name);
                self.response_text.push_str(
                    function
                        .and_then(|f| f.get("arguments"))
                        .and_then(|a| a.as_str())
                        .unwrap_or(""),
                );
                if name.is_empty() {
                    continue;
                }
                let tool_index = tc
                    .get("index")
                    .and_then(|idx| idx.as_i64())
                    .unwrap_or(i as i64);
                let key = tool_call_key(choice_index, tool_index);
                if self.seen_tool_call.contains(&key) {
                    continue;
                }
                self.seen_tool_call.insert(key);
                self.tool_names.push(name.to_owned());
            }
        }
    }
}

/// Go `deltaReasoning`：reasoning_content 优先（null 视为缺失），回退 reasoning。
fn delta_reasoning(delta: Option<&Value>) -> String {
    let Some(delta) = delta else {
        return String::new();
    };
    if let Some(reasoning_content) = delta.get("reasoning_content")
        && !reasoning_content.is_null()
        && let Some(text) = reasoning_content.as_str()
    {
        return text.to_owned();
    }
    delta
        .get("reasoning")
        .and_then(|r| r.as_str())
        .unwrap_or("")
        .to_owned()
}

fn tool_call_key(choice_index: i64, tool_index: i64) -> String {
    format!("{choice_index}-{tool_index}")
}

/// Go `canCopyAndObserve`（stream_observe.go:161-174）。
fn can_copy_and_observe(info: &RelayInfo) -> bool {
    if info.relay_format != relay_format::OPENAI {
        return false;
    }
    if info.force_format() || info.thinking_to_content() {
        return false;
    }
    match info.relay_mode {
        relay_constant::RELAY_MODE_CHAT_COMPLETIONS | relay_constant::RELAY_MODE_COMPLETIONS => {}
        _ => return false,
    }
    !info.upstream_model_name().to_lowercase().contains("audio")
}

/// Go `chunkHasVisibleDelta`（handle_stream_format.go:251-271）。
fn chunk_has_visible_delta(data: &str) -> bool {
    let Ok(root) = serde_json::from_str::<Value>(data) else {
        return false;
    };
    let Some(choices) = root.get("choices").and_then(|c| c.as_array()) else {
        return false;
    };
    for choice in choices {
        if !choice
            .get("text")
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .is_empty()
        {
            return true;
        }
        let delta = choice.get("delta");
        if !delta
            .and_then(|d| d.get("content"))
            .and_then(|c| c.as_str())
            .unwrap_or("")
            .is_empty()
        {
            return true;
        }
        if !delta_reasoning(delta).is_empty() {
            return true;
        }
        if let Some(tool_calls) = delta
            .and_then(|d| d.get("tool_calls"))
            .and_then(|t| t.as_array())
            && !tool_calls.is_empty()
        {
            return true;
        }
    }
    false
}

/// Go `sendStreamData`（relay-openai.go:23-102）：think-to-content 转换。
fn send_stream_data(
    info: &mut RelayInfo,
    sink: &mut dyn ClientSink,
    data: &str,
    force_format: bool,
    think_to_content: bool,
) -> Result<(), String> {
    if data.is_empty() {
        return Ok(());
    }
    if !force_format && !think_to_content {
        return sink.string_data(data);
    }
    let last_stream_response: ChatCompletionsStreamResponse =
        serde_json::from_str(data).map_err(|err| err.to_string())?;

    if !think_to_content {
        return sink
            .object_data(&serde_json::to_value(&last_stream_response).map_err(|e| e.to_string())?);
    }

    let mut has_thinking_content = false;
    let mut has_content = false;
    let mut thinking_content = String::new();
    for choice in &last_stream_response.choices {
        if choice
            .delta
            .reasoning_content
            .as_ref()
            .is_some_and(|r| !r.is_empty())
        {
            has_thinking_content = true;
            let reasoning = choice.delta.reasoning_content.clone().unwrap_or_default();
            thinking_content.push_str(&reasoning);
        }
        if choice
            .delta
            .content
            .as_ref()
            .is_some_and(|content| !content.is_empty())
        {
            has_content = true;
        }
    }

    // Handle think to content conversion
    if info.is_first_thinking_content && has_thinking_content {
        let mut response = last_stream_response.clone();
        for choice in &mut response.choices {
            choice.delta.content = Some(format!("<think>\n{thinking_content}"));
            choice.delta.reasoning_content = None;
        }
        info.is_first_thinking_content = false;
        info.has_sent_thinking_content = true;
        return sink.object_data(&serde_json::to_value(&response).map_err(|e| e.to_string())?);
    }

    if last_stream_response.choices.is_empty() {
        return sink
            .object_data(&serde_json::to_value(&last_stream_response).map_err(|e| e.to_string())?);
    }

    // Handle transition from thinking to content
    if has_content && !info.send_last_thinking_content && info.has_sent_thinking_content {
        let mut response = last_stream_response.clone();
        for choice in &mut response.choices {
            choice.delta.content = Some("\n</think>\n".to_owned());
            choice.delta.reasoning_content = None;
        }
        info.send_last_thinking_content = true;
        let _ = sink.object_data(&serde_json::to_value(&response).map_err(|e| e.to_string())?);
    }

    // Convert reasoning content to regular content if any
    let mut converted = last_stream_response;
    for choice in &mut converted.choices {
        if choice
            .delta
            .reasoning_content
            .as_ref()
            .is_some_and(|r| !r.is_empty())
        {
            let reasoning = choice.delta.reasoning_content.clone().unwrap_or_default();
            choice.delta.content = Some(reasoning);
            choice.delta.reasoning_content = None;
        } else if !has_thinking_content && !has_content {
            choice.delta.reasoning_content = None;
        }
    }

    sink.object_data(&serde_json::to_value(&converted).map_err(|e| e.to_string())?)
}

/// Go `HandleStreamFormat`（handle_stream_format.go:22-34）。
pub fn handle_stream_format(
    info: &mut RelayInfo,
    sink: &mut dyn ClientSink,
    data: &str,
    force_format: bool,
    think_to_content: bool,
) -> Result<(), String> {
    info.send_response_count += 1;
    match info.relay_format.as_str() {
        f if f == relay_format::OPENAI => {
            send_stream_data(info, sink, data, force_format, think_to_content)
        }
        f if f == relay_format::CLAUDE => {
            let _ = (info, sink, data);
            Err(relayconvert_response_seam("claude"))
        }
        f if f == relay_format::GEMINI => {
            let _ = (info, sink, data);
            Err(relayconvert_response_seam("gemini"))
        }
        _ => Ok(()),
    }
}

/// Go `processTokenData`（handle_stream_format.go:113-134）：累计文本 + 判断
/// finish_reason 是否出现。
fn process_token_data(
    relay_mode: i32,
    data: &str,
    response_text: &mut String,
    tool_count: &mut i64,
) -> Result<bool, String> {
    match relay_mode {
        relay_constant::RELAY_MODE_CHAT_COMPLETIONS => {
            let stream_response: ChatCompletionsStreamResponse =
                serde_json::from_str(data).map_err(|err| err.to_string())?;
            let finished = stream_response.is_finished();
            process_stream_response(&stream_response, response_text, tool_count);
            Ok(finished)
        }
        relay_constant::RELAY_MODE_COMPLETIONS => {
            let stream_response: Value =
                serde_json::from_str(data).map_err(|err| err.to_string())?;
            if let Some(choices) = stream_response.get("choices").and_then(|c| c.as_array()) {
                for choice in choices {
                    response_text
                        .push_str(choice.get("text").and_then(|t| t.as_str()).unwrap_or(""));
                }
                for choice in choices {
                    if let Some(finish) = choice.get("finish_reason").and_then(|f| f.as_str())
                        && !finish.is_empty()
                    {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }
        _ => Ok(false),
    }
}

/// Go `ProcessStreamResponse`。
fn process_stream_response(
    stream_response: &ChatCompletionsStreamResponse,
    response_text: &mut String,
    tool_count: &mut i64,
) {
    for choice in &stream_response.choices {
        response_text.push_str(choice.delta.content.as_deref().unwrap_or(""));
        response_text.push_str(choice.delta.reasoning_content.as_deref().unwrap_or(""));
        if let Some(tool_calls) = &choice.delta.tool_calls {
            if tool_calls.len() as i64 > *tool_count {
                *tool_count = tool_calls.len() as i64;
            }
            for tool in tool_calls {
                response_text.push_str(&tool.function.name);
                response_text.push_str(&tool.function.arguments);
            }
        }
    }
}

/// Go `collectStreamFunctionCallNames`（relay-openai.go:321-344）。
fn collect_stream_function_call_names(
    data: &str,
    seen: &mut std::collections::HashSet<String>,
    names: &mut Vec<String>,
) {
    let Ok(stream_response) = serde_json::from_str::<ChatCompletionsStreamResponse>(data) else {
        return;
    };
    for choice in &stream_response.choices {
        for (i, tc) in choice.delta.tool_calls.iter().flatten().enumerate() {
            let name = tc.function.name.clone();
            if name.is_empty() {
                continue;
            }
            let tool_idx = tc.index.unwrap_or(i as i64);
            let key = format!("{}-{}", choice.index, tool_idx);
            if seen.contains(&key) {
                continue;
            }
            seen.insert(key);
            names.push(name);
        }
    }
}

/// Go `handleLastResponse`（handle_stream_format.go:142-162）。
#[allow(clippy::too_many_arguments)]
fn handle_last_response(
    last_stream_data: &str,
    response_id: &mut String,
    create_at: &mut i64,
    system_fingerprint: &mut String,
    model: &mut String,
    usage: &mut Usage,
    contain_stream_usage: &mut bool,
) -> Result<(), String> {
    let last_stream_response: ChatCompletionsStreamResponse =
        serde_json::from_str(last_stream_data).map_err(|err| err.to_string())?;
    *response_id = last_stream_response.id.clone();
    *create_at = last_stream_response.created;
    *system_fingerprint = last_stream_response
        .system_fingerprint
        .clone()
        .unwrap_or_default();
    *model = last_stream_response.model.clone();
    if let Some(last_usage) = &last_stream_response.usage
        && valid_usage(last_usage)
    {
        *contain_stream_usage = true;
        *usage = last_usage.clone();
    }
    Ok(())
}

/// Go `HandleFinalResponse`（handle_stream_format.go:164-239）的 OpenAI 分支
/// （Claude/Gemini 分支需要 relayconvert，返回 seam 错误并被调用方吞掉——与
/// Go 的 SysLog + return 一致）。
#[allow(clippy::too_many_arguments)]
fn handle_final_response(
    info: &RelayInfo,
    sink: &mut dyn ClientSink,
    response_id: &str,
    create_at: i64,
    model: &str,
    system_fingerprint: &str,
    usage: &Usage,
    contain_stream_usage: bool,
) {
    match info.relay_format.as_str() {
        f if f == relay_format::OPENAI => {
            if info.should_include_usage && !contain_stream_usage {
                let mut response = json!({
                    "id": response_id,
                    "object": "chat.completion.chunk",
                    "created": create_at,
                    "model": model,
                    "choices": [],
                    "usage": usage,
                });
                if !system_fingerprint.is_empty() {
                    response["system_fingerprint"] = json!(system_fingerprint);
                }
                let _ = sink.object_data(&response);
            }
            sink.done();
        }
        _ => {
            // claude / gemini 格式走 relayconvert seam（Go: SysLog + return）。
        }
    }
}

/// Go `streamTruncated`（relay-openai.go:307-319）。
fn stream_truncated(
    info: &RelayInfo,
    saw_finish_reason: bool,
    end_reason: StreamEndReason,
) -> bool {
    if info.relay_format != relay_format::OPENAI {
        return false;
    }
    if saw_finish_reason {
        return false;
    }
    !matches!(
        end_reason,
        StreamEndReason::Done | StreamEndReason::ClientGone
    )
}

fn forward_chunk(info: &mut RelayInfo, sink: &mut dyn ClientSink, data: &str, fast_path: bool) {
    if fast_path {
        info.send_response_count += 1;
        let _ = sink.string_data(data);
        return;
    }
    if let Err(err) = handle_stream_format(
        info,
        sink,
        data,
        info.force_format(),
        info.thinking_to_content(),
    ) {
        let _ = err; // Go: common.SysLog("error handling stream format: ...")
    }
}

/// Go `OaiStreamHandler`（relay-openai.go:104-296）。
pub fn oai_stream_handler(
    info: &mut RelayInfo,
    response: &mut OutboundResponse,
    sink: &mut dyn ClientSink,
) -> DoResponseOutcome {
    let mut model = info.upstream_model_name();
    let mut response_id = String::new();
    let mut create_at: i64 = 0;
    let mut system_fingerprint = String::new();
    let mut contain_stream_usage = false;
    let mut response_text = String::new();
    let mut tool_count: i64 = 0;
    let mut usage = Usage::default();
    let mut last_stream_data = String::new();
    let mut second_last_stream_data = String::new();
    let mut seen_stream_tool_calls: std::collections::HashSet<String> = Default::default();
    let mut stream_function_call_names: Vec<String> = Vec::new();
    let mut saw_finish_reason = false;

    let is_audio_model = model.to_lowercase().contains("audio");

    let fast_path = can_copy_and_observe(info);
    let mut observer = if fast_path {
        Some(StreamObserver::new(info.relay_mode))
    } else {
        None
    };

    let (payloads, end_reason) = crate::adaptor_common::scan_sse_response(response);

    let mut held_chunk = String::new();
    let mut saw_visible_chunk = false;
    for data in payloads {
        if data.is_empty() {
            continue;
        }
        // 对音频模型，保存倒数第二个stream data
        if is_audio_model && !last_stream_data.is_empty() {
            second_last_stream_data = last_stream_data.clone();
        }
        last_stream_data = data.clone();

        // #426 forward policy：元数据前导块持有；首个可见块先冲刷再转发，
        // 其后（含尾部 usage-only 块）即时转发。
        if !saw_visible_chunk {
            if chunk_has_visible_delta(&data) {
                if !held_chunk.is_empty() {
                    let held = held_chunk.clone();
                    held_chunk.clear();
                    forward_chunk(info, sink, &held, fast_path);
                }
                forward_chunk(info, sink, &data, fast_path);
                saw_visible_chunk = true;
            } else {
                held_chunk = data.clone(); // latest preamble wins
            }
        } else {
            forward_chunk(info, sink, &data, fast_path);
        }

        if let Some(observer) = observer.as_mut() {
            observer.observe(&data);
            continue;
        }
        collect_stream_function_call_names(
            &data,
            &mut seen_stream_tool_calls,
            &mut stream_function_call_names,
        );
        match process_token_data(info.relay_mode, &data, &mut response_text, &mut tool_count) {
            Ok(finished) => {
                if finished {
                    saw_finish_reason = true;
                }
            }
            Err(_err) => {
                // Go: logger.LogError("error processing stream token data: ...")
            }
        }
    }

    if let Some(observer) = &observer {
        saw_finish_reason = observer.saw_finish_reason;
        tool_count = observer.tool_count;
        stream_function_call_names = observer.tool_names.clone();
        response_text.push_str(&observer.response_text);
    }

    // 对音频模型，从倒数第二个stream data中提取usage信息
    if is_audio_model
        && !second_last_stream_data.is_empty()
        && let Ok(stream_resp) =
            serde_json::from_str::<ChatCompletionsStreamResponse>(&second_last_stream_data)
        && let Some(second_usage) = &stream_resp.usage
        && valid_usage(second_usage)
    {
        usage = second_usage.clone();
        contain_stream_usage = true;
    }

    // #394：上游未声明终止（无 finish_reason 且无 [DONE]）时按截断失败。
    if stream_truncated(info, saw_finish_reason, end_reason) {
        let mut api_err = new_openai_error(
            format!(
                "upstream stream closed before a finish_reason was received (received={})",
                info.received_response_count
            ),
            error_code::BAD_RESPONSE,
            502,
        );
        if info.has_send_response() {
            // 已有可见块出站：状态行已消耗，改为流内 error 事件并终止。
            api_err = with_skip_retry(api_err);
            let error_event = json!({
                "error": {
                    "message": api_err.message,
                    "type": api_err.code,
                    "code": api_err.code,
                }
            });
            let _ = sink.object_data(&error_event);
        }
        return DoResponseOutcome::error(Usage::default(), api_err);
    }

    // 处理最后的响应（提取 usage / responseId 等；所有 chunk 已即时转发）。
    if !last_stream_data.is_empty() {
        let _ = handle_last_response(
            &last_stream_data,
            &mut response_id,
            &mut create_at,
            &mut system_fingerprint,
            &mut model,
            &mut usage,
            &mut contain_stream_usage,
        );
    }

    // 干净结束但无可见 token：冲刷持有的前导块。
    if !held_chunk.is_empty() {
        let held = held_chunk.clone();
        forward_chunk(info, sink, &held, fast_path);
    }

    if !contain_stream_usage
        && fast_path
        && let Some(observer_usage) = observer.as_ref().and_then(|o| o.usage.clone())
    {
        // handleLastResponse 只看最后一块；usage 出现在更早块的场景从观察器取。
        usage = observer_usage;
        contain_stream_usage = true;
    }

    if !contain_stream_usage {
        usage = usage::response_text_2_usage(
            sink,
            &response_text,
            &info.upstream_model_name(),
            info.get_estimate_prompt_tokens(),
        );
        usage.completion_tokens += tool_count * 7;
    }

    apply_usage_post_processing(info, &mut usage, last_stream_data.as_bytes());

    for name in &stream_function_call_names {
        info.count_billable_tool_call(build_in_call::FUNCTION_CALL, name);
    }

    handle_final_response(
        info,
        sink,
        &response_id,
        create_at,
        &model,
        &system_fingerprint,
        &usage,
        contain_stream_usage,
    );

    DoResponseOutcome::ok(usage)
}

// ---- 非流处理（OpenaiHandler） ---------------------------------------------

/// Go `dto.Message.StringContent()`：string content 或数组文本拼接。
fn message_string_content(message: &Value) -> String {
    match message.get("content") {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(parts)) => parts
            .iter()
            .filter_map(|part| part.get("text").and_then(|t| t.as_str()))
            .collect::<Vec<_>>()
            .join(""),
        _ => String::new(),
    }
}

/// Go `OpenaiHandler`（relay-openai.go:346-470）。
pub fn openai_handler(
    info: &mut RelayInfo,
    response: &mut OutboundResponse,
    sink: &mut dyn ClientSink,
) -> DoResponseOutcome {
    let status = response.status;
    let mut response_body = match response.read_full_body() {
        Ok(body) => body,
        Err(err) => return DoResponseOutcome::error(Usage::default(), err),
    };

    // OpenRouter enterprise 解包。
    if info.channel_type() == ct::OPEN_ROUTER && info.is_openrouter_enterprise() {
        match serde_json::from_slice::<Value>(&response_body) {
            Ok(enterprise) => {
                let success = enterprise
                    .get("success")
                    .and_then(|s| s.as_bool())
                    .unwrap_or(false);
                if success {
                    response_body =
                        serde_json::to_vec(enterprise.get("data").unwrap_or(&Value::Null))
                            .unwrap_or_default();
                } else {
                    return DoResponseOutcome::error(
                        Usage::default(),
                        new_openai_error(
                            "openrouter response success=false",
                            error_code::BAD_RESPONSE_BODY,
                            500,
                        ),
                    );
                }
            }
            Err(err) => {
                return DoResponseOutcome::error(
                    Usage::default(),
                    new_openai_error(err.to_string(), error_code::BAD_RESPONSE_BODY, 500),
                );
            }
        }
    }

    let simple_response: Value = match serde_json::from_slice(&response_body) {
        Ok(parsed) => parsed,
        Err(err) => {
            return DoResponseOutcome::error(
                Usage::default(),
                new_openai_error(err.to_string(), error_code::BAD_RESPONSE_BODY, 500),
            );
        }
    };

    // error.type 非空 → 上游错误折叠（Go: types.WithOpenAIError）。
    if let Some(oai_error) = simple_response
        .get("error")
        .and_then(|e| {
            serde_json::from_value::<crate::adaptor_common::convert_claude::OpenAiErrorBody>(
                e.clone(),
            )
            .ok()
        })
        .filter(|e| !e.r#type.is_empty())
    {
        return DoResponseOutcome::error(Usage::default(), with_openai_error(&oai_error, status));
    }

    // 200 + 空 choices 折叠为可重试错误（不稳定转售商伪装成功）。
    let choices_empty = simple_response
        .get("choices")
        .and_then(|c| c.as_array())
        .map(|c| c.is_empty())
        .unwrap_or(true);
    if choices_empty {
        return DoResponseOutcome::error(
            Usage::default(),
            new_openai_error(
                "upstream returned 200 with empty choices",
                error_code::EMPTY_RESPONSE,
                500,
            ),
        );
    }

    let choices = simple_response
        .get("choices")
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default();

    // content_filter 标记。
    for choice in &choices {
        if choice.get("finish_reason").and_then(|f| f.as_str()) == Some("content_filter") {
            sink.set_context(
                "admin_reject_reason",
                json!("openai_finish_reason=content_filter"),
            );
            break;
        }
    }

    // 工具调用计费统计。
    for choice in &choices {
        for tc in choice
            .get("message")
            .and_then(|m| m.get("tool_calls"))
            .and_then(|t| t.as_array())
            .into_iter()
            .flatten()
        {
            let name = tc
                .get("function")
                .and_then(|f| f.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("");
            info.count_billable_tool_call(build_in_call::FUNCTION_CALL, name);
        }
    }

    let force_format = info.force_format();

    // usage 回退估算。
    let mut usage: Usage =
        serde_json::from_value(simple_response.get("usage").cloned().unwrap_or(Value::Null))
            .unwrap_or_default();
    let mut usage_modified = false;
    if usage.prompt_tokens == 0 {
        let mut completion_tokens = usage.completion_tokens;
        if completion_tokens == 0 {
            for choice in &choices {
                let content = choice
                    .get("message")
                    .map(message_string_content)
                    .unwrap_or_default();
                let reasoning = choice
                    .get("message")
                    .and_then(|m| m.get("reasoning_content"))
                    .and_then(|r| r.as_str())
                    .unwrap_or("");
                completion_tokens += estimate_token_by_model(
                    &info.upstream_model_name(),
                    &format!("{content}{reasoning}"),
                );
            }
        }
        usage = Usage {
            prompt_tokens: info.get_estimate_prompt_tokens(),
            completion_tokens,
            total_tokens: info.get_estimate_prompt_tokens() + completion_tokens,
            ..Usage::default()
        };
        usage_modified = true;
    }

    apply_usage_post_processing(info, &mut usage, &response_body);

    match info.relay_format.as_str() {
        f if f == relay_format::OPENAI => {
            if usage_modified {
                let mut body_map = simple_response.clone();
                body_map["usage"] = serde_json::to_value(&usage).unwrap_or_default();
                response_body = serde_json::to_vec(&body_map).unwrap_or_default();
            }
            if force_format {
                // Go: Marshal(simpleResponse) DTO 重排。这里保持原始字节面
                // （DTO 归一化归转换切片），force_format 的语义由 usage 补齐
                // 与字段清洗承担。
            }
        }
        f if f == relay_format::CLAUDE => {
            let _ = &simple_response;
            return DoResponseOutcome::error(
                Usage::default(),
                new_error(
                    relayconvert_response_seam("claude"),
                    error_code::BAD_RESPONSE_BODY,
                ),
            );
        }
        f if f == relay_format::GEMINI => {
            return DoResponseOutcome::error(
                Usage::default(),
                new_error(
                    relayconvert_response_seam("gemini"),
                    error_code::BAD_RESPONSE_BODY,
                ),
            );
        }
        _ => {}
    }

    sink.send_bytes(status, "application/json", &response_body);
    DoResponseOutcome::ok(usage)
}

/// Go `common_handler.RerankHandler` 的适配器侧占位：openai 渠道 rerank 透传
/// （rerank 通用面归共享切片）。
fn openai_passthrough_handler(
    _info: &mut RelayInfo,
    response: &mut OutboundResponse,
    sink: &mut dyn ClientSink,
) -> DoResponseOutcome {
    let body = match response.read_full_body() {
        Ok(body) => body,
        Err(err) => return DoResponseOutcome::error(Usage::default(), err),
    };
    sink.send_bytes(response.status, "application/json", &body);
    DoResponseOutcome::ok(Usage::default())
}

// ---- audio（audio.go） ------------------------------------------------------

/// Go `OpenaiTTSHandler`（audio.go:21-123）。
pub fn openai_tts_handler(
    info: &mut RelayInfo,
    response: &mut OutboundResponse,
    sink: &mut dyn ClientSink,
    response_format: &str,
) -> Usage {
    let prompt_tokens = info.get_estimate_prompt_tokens();
    let mut usage = Usage {
        prompt_tokens,
        total_tokens: prompt_tokens,
        ..Usage::default()
    };

    // 上游 header 透传（ShouldCopyUpstreamHeader 策略由装配层实现）。
    for (key, value) in &response.headers {
        sink.set_header(key, value);
    }
    sink.send_bytes(response.status, response.header("content-type"), &[]);

    if info.is_stream {
        let (payloads, _end) = crate::adaptor_common::scan_sse_response(response);
        for data in payloads {
            if data.contains("usage")
                && let Ok(simple) = serde_json::from_str::<SimpleResponse>(&data)
                && simple.usage.total_tokens != 0
            {
                usage.prompt_tokens = simple.usage.input_tokens;
                usage.completion_tokens = simple.usage.output_tokens;
                usage.total_tokens = simple.usage.total_tokens;
            }
            let _ = sink.string_data(&data);
        }
        return usage;
    }

    sink.set_context("local_count_tokens", Value::Bool(true));
    let body_bytes = match response.read_full_body() {
        Ok(bytes) => bytes,
        Err(_) => return usage,
    };
    sink.send_bytes(200, response.header("content-type"), &body_bytes);

    // 音频时长 → token：pcm 走采样率精确计算（24000Hz/16bit/单声道），其余走
    // 尺寸回退（每 KB ≈ 1 token）。非 pcm 元数据解析未移植（见模块头偏差）。
    let audio_format = if !info.audio_response_format.is_empty() {
        info.audio_response_format.as_str()
    } else {
        response_format
    };
    usage.prompt_tokens_details.text_tokens = usage.prompt_tokens;
    let duration: Option<f64> = if audio_format == "pcm" {
        const SAMPLE_RATE: f64 = 24000.0;
        const BYTES_PER_SAMPLE: f64 = 2.0;
        const CHANNELS: f64 = 1.0;
        Some(body_bytes.len() as f64 / (SAMPLE_RATE * BYTES_PER_SAMPLE * CHANNELS))
    } else {
        None
    };
    match duration {
        Some(duration) if duration > 0.0 => {
            // ceil(duration) / 60.0 * 1000，即每分钟 1000 tokens。
            // Go QuotaRound（math.Round 半值远离零），非截断。
            let completion_tokens = (duration.ceil() / 60.0 * 1000.0).round() as i64;
            usage.completion_tokens = completion_tokens;
            usage.completion_token_details.audio_tokens = completion_tokens;
        }
        _ => {
            let size_in_kb = body_bytes.len() as f64 / 1000.0;
            let estimated_tokens = size_in_kb.ceil() as i64;
            usage.completion_tokens = estimated_tokens;
            usage.completion_token_details.audio_tokens = estimated_tokens;
        }
    }
    usage.total_tokens = usage.prompt_tokens + usage.completion_tokens;
    usage
}

/// Go `OpenaiSTTHandler`（audio.go:125-156）。
pub fn openai_stt_handler(
    info: &mut RelayInfo,
    response: &mut OutboundResponse,
    sink: &mut dyn ClientSink,
) -> Result<Usage, AdaptorError> {
    let response_body = response.read_full_body()?;
    sink.send_bytes(
        response.status,
        response.header("content-type"),
        &response_body,
    );

    if let Ok(response_data) = serde_json::from_slice::<SimpleResponse>(&response_body)
        && response_data.usage.total_tokens > 0
    {
        let mut usage = response_data.usage;
        if usage.prompt_tokens == 0 {
            usage.prompt_tokens = usage.input_tokens;
        }
        if usage.completion_tokens == 0 {
            usage.completion_tokens = usage.output_tokens;
        }
        return Ok(usage);
    }

    let prompt_tokens = info.get_estimate_prompt_tokens();
    Ok(Usage {
        prompt_tokens,
        total_tokens: prompt_tokens,
        ..Usage::default()
    })
}

// ---- image（relay_image.go） ------------------------------------------------

/// Go `normalizeOpenAIUsage`（relay_image.go:70-91）：Images usage 形态映射。
pub fn normalize_openai_usage(usage: &mut Usage) {
    if usage.input_tokens != 0 {
        usage.prompt_tokens = usage.input_tokens;
    }
    if usage.output_tokens != 0 {
        usage.completion_tokens = usage.output_tokens;
    }
    if let Some(input_details) = usage.input_tokens_details {
        usage.prompt_tokens_details.cached_tokens = input_details.cached_tokens;
        usage.prompt_tokens_details.cached_creation_tokens = input_details.cached_creation_tokens;
        usage.prompt_tokens_details.cache_write_tokens = input_details.cache_write_tokens;
        usage.prompt_tokens_details.image_tokens = input_details.image_tokens;
        usage.prompt_tokens_details.text_tokens = input_details.text_tokens;
        usage.prompt_tokens_details.audio_tokens = input_details.audio_tokens;
    }
    if usage.total_tokens == 0 {
        usage.total_tokens = usage.prompt_tokens + usage.completion_tokens;
    }
}

/// Go `updateOpenAIImageCount`（relay_image.go:25-30）。Go 检查
/// `info.PriceData.UsePrice`（pricing 切片面），由调用方传 `use_price`。
pub fn update_openai_image_count(info: &mut RelayInfo, count: i64, use_price: bool) {
    // dto.MaxImageN = 10
    if !use_price || count <= 0 || count > 10 {
        return;
    }
    info.add_other_ratio("n", count as f64);
}

/// Go `OpenaiImageHandler`（relay_image.go:34-60）。
pub fn openai_image_handler(
    info: &mut RelayInfo,
    response: &mut OutboundResponse,
    sink: &mut dyn ClientSink,
) -> DoResponseOutcome {
    let status = response.status;
    let response_body = match response.read_full_body() {
        Ok(body) => body,
        Err(err) => return DoResponseOutcome::error(Usage::default(), err),
    };
    let usage_resp: SimpleResponse = match serde_json::from_slice(&response_body) {
        Ok(parsed) => parsed,
        Err(err) => {
            return DoResponseOutcome::error(
                Usage::default(),
                new_openai_error(err.to_string(), error_code::BAD_RESPONSE_BODY, 500),
            );
        }
    };
    if let Some(oai_error) = usage_resp.get_openai_error() {
        return DoResponseOutcome::error(Usage::default(), with_openai_error(oai_error, status));
    }

    let image_count = serde_json::from_slice::<Value>(&response_body)
        .ok()
        .and_then(|v| {
            v.get("data")
                .and_then(|d| d.as_array())
                .map(|a| a.len() as i64)
        })
        .unwrap_or(0);
    update_openai_image_count(info, image_count, false);

    sink.send_bytes(status, "application/json", &response_body);

    let mut usage = usage_resp.usage;
    normalize_openai_usage(&mut usage);
    apply_usage_post_processing(info, &mut usage, &response_body);
    DoResponseOutcome::ok(usage)
}

/// Go `isOpenAIImageStreamErrorEvent`（relay_image.go:190-203）。
fn is_openai_image_stream_error_event(data: &[u8]) -> bool {
    let Ok(payload) = serde_json::from_slice::<Value>(data) else {
        return false;
    };
    let payload_type = payload
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("")
        .trim()
        .to_lowercase();
    let has_error = payload.get("error").map(|e| !e.is_null()).unwrap_or(false);
    payload_type == "error" || payload_type == "upstream_error" || has_error
}

/// Go `extractOpenAIImageStreamErrorMessage`（relay_image.go:205-233）。
fn extract_openai_image_stream_error_message(data: &[u8]) -> String {
    let fallback = "upstream image stream returned error event".to_owned();
    let Ok(payload) = serde_json::from_slice::<Value>(data) else {
        return fallback;
    };
    if let Some(message) = payload
        .get("message")
        .and_then(|m| m.as_str())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
    {
        return message;
    }
    if let Some(error) = payload.get("error")
        && !error.is_null()
    {
        if let Some(message) = error
            .get("message")
            .and_then(|m| m.as_str())
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
        {
            return message;
        }
        let raw = error.to_string();
        let raw = raw.trim().to_owned();
        if !raw.is_empty() && raw != "null" {
            return raw;
        }
    }
    fallback
}

/// Go `writeOpenaiImageStreamChunk`（relay_image.go:174-183）。
fn write_openai_image_stream_chunk(sink: &mut dyn ClientSink, data: &[u8]) -> Result<(), String> {
    let payload: Value = serde_json::from_slice(data).unwrap_or(Value::Null);
    let event_name = payload
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("")
        .trim()
        .to_owned();
    if !event_name.is_empty() {
        return sink.response_chunk_data(&event_name, &String::from_utf8_lossy(data));
    }
    sink.string_data(&String::from_utf8_lossy(data))
}

/// Go `OpenaiImageStreamHandler`（relay_image.go:93-169）。
pub fn openai_image_stream_handler(
    info: &mut RelayInfo,
    response: &mut OutboundResponse,
    sink: &mut dyn ClientSink,
) -> DoResponseOutcome {
    let content_type = response.header("content-type").to_lowercase();
    if !(200..300).contains(&response.status) {
        return openai_image_handler(info, response, sink);
    }
    if !content_type.contains("text/event-stream") {
        return openai_image_json_as_stream_handler(info, response, sink);
    }

    let mut usage = Usage::default();
    let mut last_stream_data: Vec<u8> = Vec::new();
    let mut completed_images: i64 = 0;

    let (payloads, end_reason) = crate::adaptor_common::scan_sse_response(response);
    for raw in payloads {
        let raw_bytes = raw.into_bytes();
        last_stream_data = raw_bytes.clone();
        if is_openai_image_stream_error_event(&raw_bytes) {
            // Go: sr.Error(msg) —— 软错误记录，结束原因由 scanner 裁决。
            let _soft_error = extract_openai_image_stream_error_message(&raw_bytes);
        }
        if let Ok(chunk) = serde_json::from_slice::<Value>(&raw_bytes) {
            if let Some(usage_value) = chunk.get("usage")
                && let Ok(mut chunk_usage) = serde_json::from_value::<Usage>(usage_value.clone())
            {
                normalize_openai_usage(&mut chunk_usage);
                if valid_usage(&chunk_usage) {
                    usage = chunk_usage;
                }
            }
            let chunk_type = chunk.get("type").and_then(|t| t.as_str()).unwrap_or("");
            if chunk_type == "image_generation.completed" || chunk_type == "image_edit.completed" {
                completed_images += 1;
            }
        }
        if write_openai_image_stream_chunk(sink, &raw_bytes).is_err() {
            return DoResponseOutcome::ok(usage);
        }
    }

    // 扫描器消费了上游 [DONE]；重发以让客户端仍收到终止 sentinel。
    if end_reason == StreamEndReason::Done {
        sink.done();
    }

    apply_usage_post_processing(info, &mut usage, &last_stream_data);
    // 上游正常结束（done/eof）才信任 completed 计数；客户端中止保 n 不减，
    // 但已完成数超过记录 n 时按更高实际值计费。
    let upstream_finished =
        end_reason == StreamEndReason::Done || end_reason == StreamEndReason::Eof;
    let requested_n = info.other_ratio("n").unwrap_or(1.0);
    if upstream_finished || completed_images as f64 > requested_n {
        update_openai_image_count(info, completed_images, false);
    }
    DoResponseOutcome::ok(usage)
}

/// Go `openaiImageJSONAsStreamHandler`（relay_image.go:235-330）：JSON 响应
/// 按 SSE image_generation.completed 事件重播。
fn openai_image_json_as_stream_handler(
    info: &mut RelayInfo,
    response: &mut OutboundResponse,
    sink: &mut dyn ClientSink,
) -> DoResponseOutcome {
    let status = response.status;
    let response_body = match response.read_full_body() {
        Ok(body) => body,
        Err(err) => return DoResponseOutcome::error(Usage::default(), err),
    };
    let usage_resp: SimpleResponse = match serde_json::from_slice(&response_body) {
        Ok(parsed) => parsed,
        Err(err) => {
            return DoResponseOutcome::error(
                Usage::default(),
                new_openai_error(err.to_string(), error_code::BAD_RESPONSE_BODY, 500),
            );
        }
    };
    if let Some(oai_error) = usage_resp.get_openai_error() {
        return DoResponseOutcome::error(Usage::default(), with_openai_error(oai_error, status));
    }
    let mut usage = usage_resp.usage;
    normalize_openai_usage(&mut usage);
    apply_usage_post_processing(info, &mut usage, &response_body);

    let root: Value = serde_json::from_slice(&response_body).unwrap_or(Value::Null);
    let image_count = root
        .get("data")
        .and_then(|d| d.as_array())
        .map(|a| a.len() as i64)
        .unwrap_or(0);
    update_openai_image_count(info, image_count, false);

    sink.set_event_stream_headers();

    let mut created = root.get("created").and_then(|c| c.as_i64()).unwrap_or(0);
    if created == 0 {
        created = timestamp_now();
    }
    info.set_first_response_time(timestamp_now() * 1000);

    let valid = valid_usage(&usage);
    let usage_json = if valid {
        serde_json::to_value(&usage).ok()
    } else {
        None
    };

    if let Some(images) = root.get("data").and_then(|d| d.as_array()) {
        for image in images {
            // b64_json 最后写：Go 为避免重拷贝大块；serde_json 重建对象同理。
            let mut payload = json!({
                "type": "image_generation.completed",
                "created_at": created,
            });
            if let Some(usage_json) = &usage_json {
                payload["usage"] = usage_json.clone();
            }
            for field in ["url", "revised_prompt", "b64_json"] {
                if let Some(value) = image.get(field)
                    && let Some(text) = value.as_str()
                    && !text.is_empty()
                {
                    payload[field] = json!(text);
                }
            }
            let data = serde_json::to_string(&payload).unwrap_or_default();
            if sink
                .response_chunk_data("image_generation.completed", &data)
                .is_err()
            {
                return DoResponseOutcome::ok(usage);
            }
        }
    }
    if sink.string_data("[DONE]").is_err() {
        return DoResponseOutcome::ok(usage);
    }
    info.received_response_count += image_count;
    DoResponseOutcome::ok(usage)
}

// ---- responses（relay_responses.go） ----------------------------------------

/// Go `dto.ResponsesStreamResponse` 适配器子集。
#[derive(Clone, Debug, Default, serde::Deserialize)]
#[serde(default)]
struct ResponsesStreamResponse {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    delta: String,
    #[serde(default)]
    response: Option<Value>,
    #[serde(default)]
    item: Option<Value>,
}

#[derive(Clone, Copy, Debug, Default, serde::Deserialize)]
#[serde(default)]
struct InputTokenDetailsAlias {
    #[serde(rename = "cached_tokens")]
    cached_tokens: i64,
    #[serde(rename = "cache_write_tokens")]
    cache_write_tokens: i64,
}

/// Go `OaiResponsesHandler`（relay_responses.go:20-73）。
pub fn oai_responses_handler(
    info: &mut RelayInfo,
    response: &mut OutboundResponse,
    sink: &mut dyn ClientSink,
) -> DoResponseOutcome {
    let status = response.status;
    let response_body = match response.read_full_body() {
        Ok(body) => body,
        Err(err) => return DoResponseOutcome::error(Usage::default(), err),
    };
    let responses_response: Value = match serde_json::from_slice(&response_body) {
        Ok(parsed) => parsed,
        Err(err) => {
            return DoResponseOutcome::error(
                Usage::default(),
                new_openai_error(err.to_string(), error_code::BAD_RESPONSE_BODY, 500),
            );
        }
    };
    if let Some(oai_error) = responses_response
        .get("error")
        .and_then(|e| {
            serde_json::from_value::<crate::adaptor_common::convert_claude::OpenAiErrorBody>(
                e.clone(),
            )
            .ok()
        })
        .filter(|e| !e.r#type.is_empty())
    {
        return DoResponseOutcome::error(Usage::default(), with_openai_error(&oai_error, status));
    }

    sink.send_bytes(status, "application/json", &response_body);

    let mut usage = Usage::default();
    if let Some(resp_usage) = responses_response.get("usage") {
        usage.prompt_tokens = resp_usage
            .get("input_tokens")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        usage.completion_tokens = resp_usage
            .get("output_tokens")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        usage.total_tokens = resp_usage
            .get("total_tokens")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        if let Some(details) = resp_usage.get("input_tokens_details")
            && let Ok(alias) = serde_json::from_value::<InputTokenDetailsAlias>(details.clone())
        {
            usage.prompt_tokens_details.cached_tokens = alias.cached_tokens;
            usage.prompt_tokens_details.cache_write_tokens = alias.cache_write_tokens;
        }
    }
    // 统计实际工具调用（非工具声明）。
    for output in responses_response
        .get("output")
        .and_then(|o| o.as_array())
        .into_iter()
        .flatten()
    {
        let output_type = output.get("type").and_then(|t| t.as_str()).unwrap_or("");
        match output_type {
            "web_search_call" => {
                info.count_billable_tool_call(build_in_call::WEB_SEARCH_CALL, "");
            }
            "file_search_call" => {
                info.count_billable_tool_call(build_in_call::FILE_SEARCH_CALL, "");
            }
            "function_call" => {
                let name = output.get("name").and_then(|n| n.as_str()).unwrap_or("");
                info.count_billable_tool_call(build_in_call::FUNCTION_CALL, name);
            }
            _ => {}
        }
    }
    DoResponseOutcome::ok(usage)
}

/// Go `OaiResponsesStreamHandler`（relay_responses.go:75-178）。image counter
/// 计费面（ImageGenerationCallCounter）归 pricing 切片，这里保留 usage 聚合
/// 与工具计数契约。
pub fn oai_responses_stream_handler(
    info: &mut RelayInfo,
    response: &mut OutboundResponse,
    sink: &mut dyn ClientSink,
) -> DoResponseOutcome {
    let mut usage = Usage::default();
    let mut response_text = String::new();

    let (payloads, _end_reason) = crate::adaptor_common::scan_sse_response(response);
    for data in payloads {
        let stream_response: ResponsesStreamResponse = match serde_json::from_str(&data) {
            Ok(parsed) => parsed,
            Err(_err) => continue, // Go: logger.LogError + sr.Error
        };
        let _ = sink.response_chunk_data(&stream_response.kind, &data);
        match stream_response.kind.as_str() {
            "response.completed" | "response.done" => {
                if let Some(resp) = &stream_response.response
                    && let Some(resp_usage) = resp.get("usage")
                {
                    let input_tokens = resp_usage
                        .get("input_tokens")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0);
                    let output_tokens = resp_usage
                        .get("output_tokens")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0);
                    let total_tokens = resp_usage
                        .get("total_tokens")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0);
                    if input_tokens != 0 {
                        usage.prompt_tokens = input_tokens;
                    }
                    if output_tokens != 0 {
                        usage.completion_tokens = output_tokens;
                    }
                    if total_tokens != 0 {
                        usage.total_tokens = total_tokens;
                    }
                    if let Some(details) = resp_usage.get("input_tokens_details")
                        && let Ok(alias) =
                            serde_json::from_value::<InputTokenDetailsAlias>(details.clone())
                    {
                        usage.prompt_tokens_details.cached_tokens = alias.cached_tokens;
                        usage.prompt_tokens_details.cache_write_tokens = alias.cache_write_tokens;
                    }
                }
            }
            "response.output_text.delta" => {
                response_text.push_str(&stream_response.delta);
            }
            "response.output_item.done" => {
                if let Some(item) = &stream_response.item {
                    let item_type = item.get("type").and_then(|t| t.as_str()).unwrap_or("");
                    match item_type {
                        "web_search_call" => {
                            info.count_billable_tool_call(build_in_call::WEB_SEARCH_CALL, "");
                        }
                        "file_search_call" => {
                            info.count_billable_tool_call(build_in_call::FILE_SEARCH_CALL, "");
                        }
                        "function_call" => {
                            let name = item.get("name").and_then(|n| n.as_str()).unwrap_or("");
                            info.count_billable_tool_call(build_in_call::FUNCTION_CALL, name);
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    if usage.completion_tokens == 0 && !response_text.is_empty() {
        // 非正常结束，使用输出文本的 token 数量。
        usage.completion_tokens =
            estimate_token_by_model(&info.upstream_model_name(), &response_text);
    }
    if usage.prompt_tokens == 0 && usage.completion_tokens != 0 {
        usage.prompt_tokens = info.get_estimate_prompt_tokens();
    }
    usage.total_tokens = usage.prompt_tokens + usage.completion_tokens;
    DoResponseOutcome::ok(usage)
}

/// Go `OaiResponsesCompactionHandler`（relay_responses_compact.go）：compact
/// 响应透传 + usage 提取（input/output/total tokens + input_tokens_details）。
pub fn oai_responses_compaction_handler(
    _info: &mut RelayInfo,
    response: &mut OutboundResponse,
    sink: &mut dyn ClientSink,
) -> DoResponseOutcome {
    let status = response.status;
    let response_body = match response.read_full_body() {
        Ok(body) => body,
        Err(err) => return DoResponseOutcome::error(Usage::default(), err),
    };
    let root: Value = match serde_json::from_slice(&response_body) {
        Ok(parsed) => parsed,
        Err(err) => {
            return DoResponseOutcome::error(
                Usage::default(),
                new_openai_error(err.to_string(), error_code::BAD_RESPONSE_BODY, 500),
            );
        }
    };
    if let Some(oai_error) = root
        .get("error")
        .and_then(|e| {
            serde_json::from_value::<crate::adaptor_common::convert_claude::OpenAiErrorBody>(
                e.clone(),
            )
            .ok()
        })
        .filter(|e| !e.r#type.is_empty())
    {
        return DoResponseOutcome::error(Usage::default(), with_openai_error(&oai_error, status));
    }
    sink.send_bytes(status, "application/json", &response_body);
    let mut usage = Usage::default();
    if let Some(resp_usage) = root.get("usage") {
        usage.prompt_tokens = resp_usage
            .get("input_tokens")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        usage.completion_tokens = resp_usage
            .get("output_tokens")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        usage.total_tokens = resp_usage
            .get("total_tokens")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        if let Some(details) = resp_usage.get("input_tokens_details")
            && let Ok(alias) = serde_json::from_value::<InputTokenDetailsAlias>(details.clone())
        {
            usage.prompt_tokens_details.cached_tokens = alias.cached_tokens;
            usage.prompt_tokens_details.cache_write_tokens = alias.cache_write_tokens;
        }
    }
    DoResponseOutcome::ok(usage)
}

// ---- 工具调用响应再导出（测试与 claude/gemini 适配器共用） ----------------------

pub use crate::adaptor_common::convert_claude::ToolCallResponse as OpenAiToolCallResponse;

/// Go `dto.ToolCallResponse` 的 SetIndex。
pub fn tool_call_set_index(tool: &mut ToolCallResponse, index: i64) {
    tool.index = Some(index);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adaptor_common::{OutboundRequest, OutboundResponseBody, OutboundTransport};
    use std::sync::Mutex;

    // ---- 测试替身（参照 external_pay_http.rs 的 transport 注入形态） ----------

    /// 捕获外呼请求并回放固定响应的 transport 替身。
    struct StubTransport {
        status: i32,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        captured: Mutex<Vec<OutboundRequest>>,
    }

    impl StubTransport {
        fn with_json(status: i32, body: &str) -> Self {
            Self {
                status,
                headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
                body: body.as_bytes().to_vec(),
                captured: Mutex::new(Vec::new()),
            }
        }
    }

    impl OutboundTransport for StubTransport {
        fn execute<'a>(
            &'a self,
            request: OutboundRequest,
        ) -> Pin<Box<dyn Future<Output = Result<OutboundResponse, String>> + Send + 'a>> {
            self.captured.lock().expect("poisoned").push(request);
            let status = self.status;
            let headers = self.headers.clone();
            let body = self.body.clone();
            Box::pin(async move {
                Ok(OutboundResponse {
                    status,
                    headers,
                    body: OutboundResponseBody::Full(body),
                })
            })
        }
    }

    /// 捕获客户端写出的 sink 替身。
    #[derive(Default)]
    struct StubSink {
        sse_lines: Vec<String>,
        bytes: Vec<(i32, String, Vec<u8>)>,
        json: Vec<(i32, Value)>,
        headers: Vec<(String, String)>,
        context: Vec<(String, Value)>,
    }

    impl ClientSink for StubSink {
        fn set_event_stream_headers(&mut self) {
            self.headers
                .push(("Content-Type".to_owned(), "text/event-stream".to_owned()));
            self.headers
                .push(("Cache-Control".to_owned(), "no-cache".to_owned()));
            self.headers
                .push(("X-Accel-Buffering".to_owned(), "no".to_owned()));
        }
        fn render_sse(&mut self, data: &str) -> Result<(), String> {
            self.sse_lines.push(data.to_owned());
            Ok(())
        }
        fn send_json(&mut self, status: i32, body: &Value) {
            self.json.push((status, body.clone()));
        }
        fn send_bytes(&mut self, status: i32, content_type: &str, body: &[u8]) {
            self.bytes
                .push((status, content_type.to_owned(), body.to_vec()));
        }
        fn set_header(&mut self, key: &str, value: &str) {
            self.headers.push((key.to_owned(), value.to_owned()));
        }
        fn set_context(&mut self, key: &str, value: Value) {
            self.context.push((key.to_owned(), value));
        }
        fn get_context_string(&self, key: &str) -> String {
            self.context
                .iter()
                .find(|(existing, _)| existing == key)
                .and_then(|(_, value)| value.as_str())
                .unwrap_or("")
                .to_owned()
        }
    }

    fn info_with_model(model: &str) -> RelayInfo {
        let mut info = RelayInfo {
            relay_format: relay_format::OPENAI.to_owned(),
            relay_mode: relay_constant::RELAY_MODE_CHAT_COMPLETIONS,
            ..RelayInfo::default()
        };
        info.init_channel_meta(crate::relay_info::ChannelMetaSnapshot {
            channel_type: ct::OPENAI,
            api_type: crate::adaptor::api_type::OPENAI,
            api_version: String::new(),
            upstream_model_name: model.to_owned(),
            param_override: Value::Null,
            headers_override: Value::Null,
            channel_setting: Value::Null,
            channel_other_settings: Value::Null,
            pass_through_request_enabled: false,
        });
        info
    }

    // ---- GetRequestURL 契约 ----------------------------------------------------

    // Go adaptor.go:115-178 default 分支：RequestURLPath 原样拼接。
    #[test]
    fn get_request_url_default_chat() {
        let mut info = info_with_model("gpt-4o");
        info.request_url_path = "/v1/chat/completions".to_owned();
        info.channel_meta.as_mut().expect("meta").channel_base_url =
            "https://api.openai.com".to_owned();
        let adaptor = OpenAiAdaptor::new();
        assert_eq!(
            adaptor.get_request_url(&mut info).expect("url"),
            "https://api.openai.com/v1/chat/completions"
        );
    }

    // Go default 分支：claude/gemini 格式（非 responses）改走 /v1/chat/completions。
    #[test]
    fn get_request_url_claude_format_forces_chat_completions() {
        let mut info = info_with_model("claude-3-5-sonnet-20241022");
        info.relay_format = relay_format::CLAUDE.to_owned();
        info.request_url_path = "/v1/messages".to_owned();
        info.channel_meta.as_mut().expect("meta").channel_base_url =
            "https://api.openai.com".to_owned();
        let adaptor = OpenAiAdaptor::new();
        assert_eq!(
            adaptor.get_request_url(&mut info).expect("url"),
            "https://api.openai.com/v1/chat/completions"
        );
    }

    // Go Azure 分支：deployments + api-version + 点号裁剪（2025-05-10 前）。
    #[test]
    fn get_request_url_azure_removes_dots_for_old_channels() {
        let mut info = info_with_model("gpt-4.1-mini");
        info.request_url_path = "/v1/chat/completions".to_owned();
        let meta = info.channel_meta.as_mut().expect("meta");
        meta.channel_type = ct::AZURE;
        meta.channel_base_url = "https://x.openai.azure.com".to_owned();
        meta.channel_create_time = 1_000_000;
        let adaptor = OpenAiAdaptor::new();
        assert_eq!(
            adaptor.get_request_url(&mut info).expect("url"),
            "https://x.openai.azure.com/openai/deployments/gpt41mini/chat/completions?api-version=2025-04-01-preview"
        );
    }

    // Go Azure 分支：2025-05-10 后创建的渠道保留点号。
    #[test]
    fn get_request_url_azure_keeps_dots_for_new_channels() {
        let mut info = info_with_model("gpt-4.1-mini");
        info.request_url_path = "/v1/chat/completions".to_owned();
        let meta = info.channel_meta.as_mut().expect("meta");
        meta.channel_type = ct::AZURE;
        meta.channel_base_url = "https://x.openai.azure.com".to_owned();
        meta.channel_create_time = crate::adaptor_common::AZURE_NO_REMOVE_DOT_TIME;
        let adaptor = OpenAiAdaptor::new();
        assert_eq!(
            adaptor.get_request_url(&mut info).expect("url"),
            "https://x.openai.azure.com/openai/deployments/gpt-4.1-mini/chat/completions?api-version=2025-04-01-preview"
        );
    }

    // Go Azure responses 分支：subUrl + responsesApiVersion + compact。
    #[test]
    fn get_request_url_azure_responses_compact() {
        let mut info = info_with_model("gpt-4o");
        info.relay_mode = relay_constant::RELAY_MODE_RESPONSES_COMPACT;
        let meta = info.channel_meta.as_mut().expect("meta");
        meta.channel_type = ct::AZURE;
        meta.channel_base_url = "https://x.openai.azure.com".to_owned();
        let adaptor = OpenAiAdaptor::new();
        assert_eq!(
            adaptor.get_request_url(&mut info).expect("url"),
            "https://x.openai.azure.com/openai/v1/responses/compact?api-version=preview"
        );
    }

    // Go Custom 分支：{model} 占位替换。
    #[test]
    fn get_request_url_custom_model_placeholder() {
        let mut info = info_with_model("gpt-4o");
        info.request_url_path = "/v1/chat/completions".to_owned();
        info.channel_meta.as_mut().expect("meta").channel_base_url =
            "https://proxy.example.com/{model}/v1".to_owned();
        info.channel_meta.as_mut().expect("meta").channel_type = ct::CUSTOM;
        assert_eq!(
            adaptor.get_request_url(&mut info).expect("url"),
            "https://proxy.example.com/gpt-4o/v1"
        );
    }

    // Go realtime 分支：https→wss 改写 + deployment realtime URL。
    #[test]
    fn get_request_url_realtime_rewrites_scheme() {
        let mut info = info_with_model("gpt-4o-realtime-preview");
        info.relay_mode = relay_constant::RELAY_MODE_REALTIME;
        info.request_url_path = "/v1/realtime".to_owned();
        info.channel_meta.as_mut().expect("meta").channel_base_url =
            "https://api.openai.com".to_owned();
        // Go realtime deployment URL 只在 Azure 分支产出。
        info.channel_meta.as_mut().expect("meta").channel_type = ct::AZURE;
        let adaptor = OpenAiAdaptor::new();
        let url = adaptor.get_request_url(&mut info).expect("url");
        assert!(url.starts_with("wss://api.openai.com/openai/realtime?deployment=gpt-4o-realtime-preview&api-version=2025-04-01-preview"), "{url}");
    }

    // ---- SetupRequestHeader 契约 ----------------------------------------------

    #[test]
    fn setup_header_bearer_auth() {
        let mut info = info_with_model("gpt-4o");
        info.channel_meta.as_mut().expect("meta").api_key = "sk-x".to_owned();
        let adaptor = OpenAiAdaptor::new();
        let headers = adaptor
            .setup_request_header(
                &info,
                &[("Content-Type".to_owned(), "application/json".to_owned())],
            )
            .expect("headers");
        assert!(headers.contains(&("Authorization".to_owned(), "Bearer sk-x".to_owned())));
        assert!(headers.contains(&("Content-Type".to_owned(), "application/json".to_owned())));
    }

    #[test]
    fn setup_header_azure_api_key_and_organization() {
        // Azure：api-key，无 Authorization。
        let mut info = info_with_model("gpt-4o");
        info.channel_meta.as_mut().expect("meta").channel_type = ct::AZURE;
        info.channel_meta.as_mut().expect("meta").api_key = "az-key".to_owned();
        let adaptor = OpenAiAdaptor::new();
        let headers = adaptor.setup_request_header(&info, &[]).expect("headers");
        assert!(headers.contains(&("api-key".to_owned(), "az-key".to_owned())));
        assert!(!headers.iter().any(|(key, _)| key == "Authorization"));

        // OpenAI + organization：OpenAI-Organization。
        let mut info = info_with_model("gpt-4o");
        info.channel_meta.as_mut().expect("meta").organization = "org-1".to_owned();
        info.channel_meta.as_mut().expect("meta").api_key = "sk".to_owned();
        let adaptor = OpenAiAdaptor::new();
        let headers = adaptor.setup_request_header(&info, &[]).expect("headers");
        assert!(headers.contains(&("OpenAI-Organization".to_owned(), "org-1".to_owned())));
    }

    #[test]
    fn setup_header_openrouter_defaults() {
        let mut info = info_with_model("anthropic/claude-3.5-sonnet");
        info.channel_meta.as_mut().expect("meta").channel_type = ct::OPEN_ROUTER;
        info.channel_meta.as_mut().expect("meta").api_key = "sk".to_owned();
        let adaptor = OpenAiAdaptor::new();
        let headers = adaptor.setup_request_header(&info, &[]).expect("headers");
        assert!(headers.contains(&(
            "HTTP-Referer".to_owned(),
            "https://www.newapi.ai".to_owned()
        )));
        assert!(headers.contains(&("X-OpenRouter-Title".to_owned(), "New API".to_owned())));
    }

    // ---- ConvertOpenAIRequest 契约 --------------------------------------------

    // o 系模型：max_tokens → max_completion_tokens；temperature 清除；system →
    // developer；effort 后缀迁移。
    #[test]
    fn convert_openai_request_o_model() {
        let mut info = info_with_model("o3-mini-high");
        let request = json!({
            "model": "o3-mini-high",
            "messages": [{"role": "system", "content": "be nice"}, {"role": "user", "content": "hi"}],
            "max_tokens": 100,
            "temperature": 0.7,
        });
        let converted = OpenAiAdaptor::new()
            .convert_openai_request(&mut info, &request)
            .expect("converted");
        assert_eq!(info.upstream_model_name(), "o3-mini"); // 后缀迁移
        assert_eq!(converted["model"], "o3-mini");
        assert_eq!(converted["max_completion_tokens"], 100);
        assert!(converted.get("max_tokens").is_none());
        assert!(converted.get("temperature").is_none());
        assert_eq!(converted["reasoning_effort"], "high");
        assert_eq!(converted["messages"][0]["role"], "developer");
        assert_eq!(info.reasoning_effort, "high");
    }

    // gpt-5：temperature/top_p/logprobs 归零。
    #[test]
    fn convert_openai_request_gpt5() {
        let mut info = info_with_model("gpt-5");
        let request = json!({
            "model": "gpt-5",
            "messages": [{"role": "system", "content": "be nice"}],
            "temperature": 0.7,
            "top_p": 0.9,
            "logprobs": true,
        });
        let converted = OpenAiAdaptor::new()
            .convert_openai_request(&mut info, &request)
            .expect("converted");
        assert!(converted.get("temperature").is_none());
        assert!(converted.get("top_p").is_none());
        assert!(converted.get("logprobs").is_none());
        // gpt-5 不改 developer（Go 仅 o 系分支里改）——实际上 system→developer
        // 在 o/gpt5 共同分支内，gpt-5 也走。
        assert_eq!(converted["messages"][0]["role"], "developer");
    }

    // OpenRouter：usage.include 缺省、reasoning_effort → reasoning 对象、
    // stream_options 清除（非 openai/azure 渠道）。
    #[test]
    fn convert_openai_request_openrouter() {
        let mut info = info_with_model("anthropic/claude-3.7-sonnet");
        info.channel_meta.as_mut().expect("meta").channel_type = ct::OPEN_ROUTER;
        let request = json!({
            "model": "anthropic/claude-3.7-sonnet",
            "messages": [{"role": "user", "content": "hi"}],
            "stream": true,
            "stream_options": {"include_usage": true},
            "reasoning_effort": "medium",
        });
        let converted = OpenAiAdaptor::new()
            .convert_openai_request(&mut info, &request)
            .expect("converted");
        assert_eq!(converted["usage"]["include"], true);
        assert!(converted.get("stream_options").is_none());
        assert!(converted.get("reasoning_effort").is_none());
        assert_eq!(converted["reasoning"]["enabled"], true);
        assert_eq!(converted["reasoning"]["effort"], "medium");
    }

    // OpenRouter thinking 后缀：-thinking 裁剪 + reasoning.enabled。
    #[test]
    fn convert_openai_request_openrouter_thinking_suffix() {
        let mut info = info_with_model("anthropic/claude-3.7-sonnet-thinking");
        info.channel_meta.as_mut().expect("meta").channel_type = ct::OPEN_ROUTER;
        let request = json!({
            "model": "anthropic/claude-3.7-sonnet-thinking",
            "messages": [{"role": "user", "content": "hi"}],
        });
        let converted = OpenAiAdaptor::new()
            .convert_openai_request(&mut info, &request)
            .expect("converted");
        assert_eq!(info.upstream_model_name(), "anthropic/claude-3.7-sonnet");
        assert_eq!(converted["model"], "anthropic/claude-3.7-sonnet");
        assert_eq!(converted["reasoning"]["enabled"], true);
        assert!(converted["reasoning"].get("effort").is_none());
    }

    // OpenRouter anthropic THINKING → reasoning(max_tokens)。
    #[test]
    fn convert_openai_request_openrouter_thinking_budget() {
        let mut info = info_with_model("anthropic/claude-3.7-sonnet");
        info.channel_meta.as_mut().expect("meta").channel_type = ct::OPEN_ROUTER;
        let request = json!({
            "model": "anthropic/claude-3.7-sonnet",
            "messages": [{"role": "user", "content": "hi"}],
            "thinking": {"type": "enabled", "budget_tokens": 1024},
        });
        let converted = OpenAiAdaptor::new()
            .convert_openai_request(&mut info, &request)
            .expect("converted");
        assert_eq!(converted["reasoning"]["max_tokens"], 1024);
        assert!(converted.get("thinking").is_none());
    }

    // ConvertOpenAIResponsesRequest：effort 后缀 → reasoning.effort。
    #[test]
    fn convert_responses_request_effort_suffix() {
        let mut info = info_with_model("gpt-5");
        let request = json!({"model": "gpt-5.2-high", "input": []});
        let converted = OpenAiAdaptor::new()
            .convert_openai_responses_request(&mut info, &request)
            .expect("converted");
        assert_eq!(converted["model"], "gpt-5.2");
        assert_eq!(converted["reasoning"]["effort"], "high");
        assert_eq!(info.reasoning_effort, "high");
    }

    // ---- DoRequest 契约（stub transport） -------------------------------------

    /// 纯 std 阻塞轮询器（Waker::noop；crate 禁 unsafe）。
    fn run<F: Future>(f: F) -> F::Output {
        use std::task::{Context, Poll, Waker};
        let mut pinned = std::pin::pin!(f);
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        loop {
            match pinned.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[test]
    fn do_request_posts_to_url_with_headers() {
        let mut info = info_with_model("gpt-4o");
        info.request_url_path = "/v1/chat/completions".to_owned();
        info.channel_meta.as_mut().expect("meta").channel_base_url =
            "https://api.openai.com".to_owned();
        info.channel_meta.as_mut().expect("meta").api_key = "sk-test".to_owned();
        let transport = StubTransport::with_json(200, "{}");
        let client_headers = [("Content-Type".to_owned(), "application/json".to_owned())];
        let context = RequestContext {
            client_headers: &client_headers,
            method: "POST",
        };
        let adaptor = OpenAiAdaptor::new();
        let response = run(adaptor.do_request(&mut info, &context, b"{}".as_slice(), &transport))
            .expect("response");
        assert_eq!(response.status, 200);
        let captured = transport.captured.lock().expect("poisoned");
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].method, "POST");
        assert_eq!(
            captured[0].url,
            "https://api.openai.com/v1/chat/completions"
        );
        assert!(
            captured[0]
                .headers
                .contains(&("Authorization".to_owned(), "Bearer sk-test".to_owned()))
        );
        assert_eq!(captured[0].body, b"{}".to_vec());
    }

    // ---- OpenaiHandler 契约（upstream_contract_test.go） ----------------------

    // Go TestNonStreamingChatRelayReturnsUpstreamJSON：上游 JSON 原样转发 +
    // usage 上浮。
    #[test]
    fn non_stream_chat_forwards_upstream_json() {
        let payload = r#"{"id":"chatcmpl-9","object":"chat.completion","created":10,"model":"gpt-4","choices":[{"index":0,"message":{"role":"assistant","content":"Hello"},"finish_reason":"stop"}],"usage":{"prompt_tokens":9,"completion_tokens":2,"total_tokens":11}}"#;
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body: OutboundResponseBody::Full(payload.as_bytes().to_vec()),
        };
        let mut info = info_with_model("gpt-4");
        let mut sink = StubSink::default();
        let outcome = openai_handler(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_none());
        assert_eq!(outcome.usage.prompt_tokens, 9);
        assert_eq!(outcome.usage.completion_tokens, 2);
        assert_eq!(outcome.usage.total_tokens, 11);
        let (status, content_type, body) = &sink.bytes[0];
        assert_eq!(*status, 200);
        assert_eq!(content_type, "application/json");
        let forwarded: Value = serde_json::from_slice(body).expect("json");
        assert_eq!(forwarded["id"], "chatcmpl-9");
    }

    // Go TestNonStreamingChatRelayRejectsMalformedUpstreamJSON。
    #[test]
    fn non_stream_chat_rejects_malformed_json() {
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(b"{\"id\":\"x\",\"choices\":".to_vec()),
        };
        let mut info = info_with_model("gpt-4");
        let mut sink = StubSink::default();
        let outcome = openai_handler(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_some());
        assert!(sink.bytes.is_empty(), "garbage must not be forwarded");
    }

    // Go TestNonStreamingChatRelayRejectsEmptyChoices：200 + 空 choices 折叠为
    // empty_response 可重试错误，不转发。
    #[test]
    fn non_stream_chat_rejects_empty_choices() {
        let payload = r#"{"id":"chatcmpl-empty","object":"chat.completion","created":11,"model":"gpt-4","choices":[],"usage":{"prompt_tokens":14,"completion_tokens":0,"total_tokens":14}}"#;
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(payload.as_bytes().to_vec()),
        };
        let mut info = info_with_model("gpt-4");
        let mut sink = StubSink::default();
        let outcome = openai_handler(&mut info, &mut response, &mut sink);
        let err = outcome.error.expect("error expected");
        assert_eq!(err.code, "empty_response");
        assert!(
            sink.bytes.is_empty(),
            "empty-choice responses must not be forwarded"
        );
    }

    // 上游 error.type 非空 → WithOpenAIError 折叠。
    #[test]
    fn non_stream_chat_folds_upstream_error() {
        let payload = r#"{"error":{"message":"quota exceeded","type":"insufficient_quota","code":"insufficient_quota"}}"#;
        let mut response = OutboundResponse {
            status: 429,
            headers: vec![],
            body: OutboundResponseBody::Full(payload.as_bytes().to_vec()),
        };
        let mut info = info_with_model("gpt-4");
        let mut sink = StubSink::default();
        let outcome = openai_handler(&mut info, &mut response, &mut sink);
        let err = outcome.error.expect("error expected");
        assert_eq!(err.code, "insufficient_quota");
        assert_eq!(err.status_code, 429);
    }

    // usage 缺失 → 回退估算（prompt=estimate, completion=本地计数）。
    #[test]
    fn non_stream_chat_usage_fallback_estimation() {
        let payload = r#"{"id":"x","object":"chat.completion","created":1,"model":"gpt-4","choices":[{"index":0,"message":{"role":"assistant","content":"hello world"},"finish_reason":"stop"}]}"#;
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(payload.as_bytes().to_vec()),
        };
        let mut info = info_with_model("gpt-4");
        info.set_estimate_prompt_tokens(21);
        let mut sink = StubSink::default();
        let outcome = openai_handler(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_none());
        assert_eq!(outcome.usage.prompt_tokens, 21);
        assert!(outcome.usage.completion_tokens > 0);
        assert_eq!(
            outcome.usage.total_tokens,
            21 + outcome.usage.completion_tokens
        );
        // usage 回写进转发体。
        let (_, _, body) = &sink.bytes[0];
        let forwarded: Value = serde_json::from_slice(body).expect("json");
        assert_eq!(forwarded["usage"]["prompt_tokens"], 21);
    }

    // content_filter → admin_reject_reason。
    #[test]
    fn non_stream_chat_marks_content_filter() {
        let payload = r#"{"id":"x","object":"chat.completion","created":1,"model":"gpt-4","choices":[{"index":0,"message":{"role":"assistant","content":"x"},"finish_reason":"content_filter"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(payload.as_bytes().to_vec()),
        };
        let mut info = info_with_model("gpt-4");
        let mut sink = StubSink::default();
        let outcome = openai_handler(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_none());
        assert!(
            sink.context
                .iter()
                .any(|(key, value)| key == "admin_reject_reason"
                    && value == &json!("openai_finish_reason=content_filter"))
        );
    }

    // ---- OaiStreamHandler 契约 -----------------------------------------------

    // Go TestStreamingChatRelayForwardsUpstreamSSEBytes：逐帧 data: 前缀 +
    // 终止 [DONE]。
    #[test]
    fn stream_chat_forwards_sse_bytes_and_done() {
        let chunks = [
            "data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Hel\"}}]}\n\n",
            "data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"lo\"}}]}\n\n",
            "data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
            "data: [DONE]\n\n",
        ];
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(chunks.concat().into_bytes()),
        };
        let mut info = info_with_model("gpt-4");
        info.is_stream = true;
        let mut sink = StubSink::default();
        let outcome = oai_stream_handler(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_none());
        let body = sink.sse_lines.join("");
        for frame in body.trim_end_matches("\n\n").split("\n\n") {
            assert!(
                frame.starts_with("data: "),
                "frame missing data prefix: {frame:?}"
            );
        }
        assert!(body.contains("\"content\":\"Hel\""));
        assert!(body.contains("\"content\":\"lo\""));
        assert!(body.contains("\"finish_reason\":\"stop\""));
        assert!(
            body.ends_with("data: [DONE]\n\n"),
            "must end with DONE sentinel, tail {:?}",
            &body[body.len().saturating_sub(32)..]
        );
    }

    // Go TestStreamingChatRelayAggregatesUpstreamUsage。
    #[test]
    fn stream_chat_aggregates_upstream_usage() {
        let chunks = [
            "data: {\"id\":\"chatcmpl-2\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\n",
            "data: {\"id\":\"chatcmpl-2\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4\",\"choices\":[],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":7,\"total_tokens\":18}}\n\n",
            "data: [DONE]\n\n",
        ];
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(chunks.concat().into_bytes()),
        };
        let mut info = info_with_model("gpt-4");
        info.is_stream = true;
        let mut sink = StubSink::default();
        let outcome = oai_stream_handler(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_none());
        assert_eq!(outcome.usage.prompt_tokens, 11);
        assert_eq!(outcome.usage.completion_tokens, 7);
        assert_eq!(outcome.usage.total_tokens, 18);
    }

    // #426 前导块持有：上游在可见输出前死亡时客户端字节面干净；首可见块先
    // 冲刷前导块。
    #[test]
    fn stream_chat_holds_preamble_until_visible_delta() {
        let chunks = [
            "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"\"}}]}\n\n",
            "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\n",
            "data: [DONE]\n\n",
        ];
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(chunks.concat().into_bytes()),
        };
        let mut info = info_with_model("gpt-4");
        info.is_stream = true;
        let mut sink = StubSink::default();
        let outcome = oai_stream_handler(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_none());
        // 首帧（不可见前导）在第二帧（可见）之前冲刷，顺序保持。
        assert!(sink.sse_lines.len() >= 2);
        assert!(sink.sse_lines[0].contains("\"role\":\"assistant\""));
        assert!(sink.sse_lines[1].contains("\"content\":\"hi\""));
    }

    // #394 截断守卫：无 finish_reason 且无 [DONE] → 失败而非伪造完成。
    #[test]
    fn stream_chat_truncated_without_finish_reason() {
        let chunks = [
            "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"partial answer\"}}]}\n\n",
        ];
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(chunks.concat().into_bytes()),
        };
        let mut info = info_with_model("gpt-4");
        info.is_stream = true;
        let mut sink = StubSink::default();
        let outcome = oai_stream_handler(&mut info, &mut response, &mut sink);
        let err = outcome.error.expect("truncated stream must fail");
        assert_eq!(err.code, "bad_response");
        assert_eq!(err.status_code, 502);
        // 未满足 has_send_response → 不发送流内 error 事件（可见块仍已转发）。
        assert!(!sink.sse_lines.iter().any(|line| line.contains("\"error\"")));
    }

    // 截断但已有可见块出站 → skip_retry + 流内 error 事件。
    #[test]
    fn stream_chat_truncated_after_visible_chunks_is_skip_retry() {
        let chunks = [
            "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"partial\"}}]}\n\n",
            "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" answer\"}}]}\n\n",
        ];
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(chunks.concat().into_bytes()),
        };
        let mut info = info_with_model("gpt-4");
        info.is_stream = true;
        // has_send_response 由 first_response_time > start_time 判定；模拟已有
        // 出站块。
        info.start_time_ms = 1000;
        info.first_response_time_ms = 2000;
        info.is_first_response = false;
        let mut sink = StubSink::default();
        let outcome = oai_stream_handler(&mut info, &mut response, &mut sink);
        let err = outcome.error.expect("truncated stream must fail");
        assert!(err.skip_retry);
        // 流内 error 事件。
        assert!(sink.sse_lines.iter().any(|line| line.contains("\"error\"")));
    }

    // 无 usage → 本地估算 + 工具调用补偿（tool_count * 7）。
    #[test]
    fn stream_chat_local_usage_estimation_with_tool_bonus() {
        let chunks = [
            "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hello\"}}]}\n\n",
            "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" world\"}}]}\n\n",
            "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
            "data: [DONE]\n\n",
        ];
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(chunks.concat().into_bytes()),
        };
        let mut info = info_with_model("gpt-4");
        info.is_stream = true;
        info.set_estimate_prompt_tokens(5);
        let mut sink = StubSink::default();
        let outcome = oai_stream_handler(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_none());
        assert_eq!(outcome.usage.prompt_tokens, 5);
        assert!(outcome.usage.completion_tokens > 0);
    }

    // 流式工具调用名计费（slow path / fast path 双路径）。
    #[test]
    fn stream_chat_counts_tool_call_names() {
        let chunks = [
            "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"get_weather\",\"arguments\":\"{}\"}}]}}]}\n\n",
            "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
            "data: [DONE]\n\n",
        ];
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(chunks.concat().into_bytes()),
        };
        let mut info = info_with_model("gpt-4");
        info.is_stream = true;
        let mut sink = StubSink::default();
        let outcome = oai_stream_handler(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_none());
        assert!(info
            .billable_tool_calls
            .iter()
            .any(|call| call.kind == build_in_call::FUNCTION_CALL && call.name == "get_weather"));
    }

    // usage post-processing：DeepSeek prompt_cache_hit_tokens → cached_tokens。
    #[test]
    fn usage_post_processing_deepseek() {
        let mut info = info_with_model("deepseek-chat");
        info.channel_meta.as_mut().expect("meta").channel_type = ct::DEEP_SEEK;
        let mut usage = Usage {
            prompt_tokens: 100,
            prompt_cache_hit_tokens: 80,
            ..Usage::default()
        };
        apply_usage_post_processing(&info, &mut usage, b"");
        assert_eq!(usage.prompt_tokens_details.cached_tokens, 80);
    }

    // Moonshot：choices[].usage.cached_tokens 非标准位提取。
    #[test]
    fn usage_post_processing_moonshot() {
        let mut info = info_with_model("moonshot-v1");
        info.channel_meta.as_mut().expect("meta").channel_type = ct::MOONSHOT;
        let mut usage = Usage::default();
        let body = br#"{"choices":[{"usage":{"cached_tokens":111}}]}"#;
        apply_usage_post_processing(&info, &mut usage, body);
        assert_eq!(usage.prompt_tokens_details.cached_tokens, 111);
    }

    // detectImageMimeType。
    #[test]
    fn image_mime_detection() {
        assert_eq!(detect_image_mime_type("a.png"), "image/png");
        assert_eq!(detect_image_mime_type("a.jpg"), "image/jpeg");
        assert_eq!(detect_image_mime_type("a.JPEG"), "image/jpeg");
        assert_eq!(detect_image_mime_type("a.webp"), "image/webp");
        // ".jxl" 前缀非 ".jp"，走 png 兜底（Go detectImageMimeType）。
        assert_eq!(detect_image_mime_type("a.jXL"), "image/png");
        assert_eq!(detect_image_mime_type("a.bmp"), "image/png");
        assert_eq!(detect_image_mime_type("noext"), "image/png");
    }

    // image edit multipart：多 image 字段 → image[]；mask 件。
    #[test]
    fn image_edit_multipart_assembly() {
        let form = crate::adaptor_common::ParsedMultipartForm {
            fields: vec![("prompt".to_owned(), "edit this".to_owned())],
            files: vec![
                crate::adaptor_common::MultipartFilePart {
                    field_name: "image".to_owned(),
                    filename: "in.png".to_owned(),
                    content_type: "image/png".to_owned(),
                    bytes: vec![1, 2, 3],
                },
                crate::adaptor_common::MultipartFilePart {
                    field_name: "image".to_owned(),
                    filename: "in2.png".to_owned(),
                    content_type: "image/png".to_owned(),
                    bytes: vec![4, 5],
                },
            ],
        };
        let request = json!({"model": "gpt-image-1"});
        let assembled = build_image_edit_multipart(&form, &request).expect("assembled");
        let body = String::from_utf8(assembled.body).expect("utf8");
        assert!(body.contains("name=\"model\""));
        assert!(body.contains("name=\"prompt\""));
        // 多图 → image[] 字段名。
        assert!(body.contains("name=\"image[]\""));
        assert!(body.contains("filename=\"in.png\""));
        assert!(body.contains("filename=\"in2.png\""));
        assert!(
            assembled
                .content_type
                .starts_with("multipart/form-data; boundary=")
        );
    }

    // image edit multipart：缺 image 件报错。
    #[test]
    fn image_edit_multipart_requires_image() {
        let form = crate::adaptor_common::ParsedMultipartForm {
            fields: vec![],
            files: vec![crate::adaptor_common::MultipartFilePart {
                field_name: "mask".to_owned(),
                filename: "m.png".to_owned(),
                content_type: "image/png".to_owned(),
                bytes: vec![1],
            }],
        };
        let request = json!({"model": "gpt-image-1"});
        let err = build_image_edit_multipart(&form, &request).expect_err("image required");
        assert_eq!(err, "image is required");
    }

    // audio multipart：字段 + file 件；缺 file 报错。
    #[test]
    fn audio_multipart_assembly() {
        let form = crate::adaptor_common::ParsedMultipartForm {
            fields: vec![("language".to_owned(), "en".to_owned())],
            files: vec![crate::adaptor_common::MultipartFilePart {
                field_name: "file".to_owned(),
                filename: "a.mp3".to_owned(),
                content_type: "audio/mpeg".to_owned(),
                bytes: vec![9, 9],
            }],
        };
        let request = json!({"model": "whisper-1"});
        let assembled = build_audio_multipart(&form, &request).expect("assembled");
        let body = String::from_utf8(assembled.body).expect("utf8");
        assert!(body.contains("name=\"model\""));
        assert!(body.contains("name=\"language\""));
        assert!(body.contains("name=\"file\""));
        assert!(body.contains("filename=\"a.mp3\""));
    }

    // STT handler：usage 提取 + input/output 回填。
    #[test]
    fn stt_handler_usage_extraction() {
        let payload =
            r#"{"text":"hi","usage":{"total_tokens":30,"input_tokens":10,"output_tokens":20}}"#;
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(payload.as_bytes().to_vec()),
        };
        let mut info = info_with_model("whisper-1");
        info.set_estimate_prompt_tokens(5);
        let mut sink = StubSink::default();
        let usage = openai_stt_handler(&mut info, &mut response, &mut sink).expect("usage");
        assert_eq!(usage.prompt_tokens, 10);
        assert_eq!(usage.completion_tokens, 20);
        assert_eq!(usage.total_tokens, 30);
    }

    // TTS pcm 时长计费：24000Hz/16bit/单声道。
    #[test]
    fn tts_handler_pcm_duration() {
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(vec![0u8; 24000 * 2]), // 恰好 1 秒
        };
        let mut info = info_with_model("tts-1");
        info.set_estimate_prompt_tokens(12);
        info.audio_response_format = "pcm".to_owned();
        let mut sink = StubSink::default();
        let usage = openai_tts_handler(&mut info, &mut response, &mut sink, "pcm");
        assert_eq!(usage.prompt_tokens, 12);
        // 1s → ceil(1/60*1000) = 17
        assert_eq!(
            usage.completion_tokens,
            (1.0f64 / 60.0 * 1000.0).ceil() as i64
        );
        assert_eq!(
            usage.completion_token_details.audio_tokens,
            usage.completion_tokens
        );
    }

    // imagen/gemini/claude 格式响应转换 seam：明确错误而非静默丢格式。
    #[test]
    fn non_stream_chat_claude_format_seam_error() {
        let payload = r#"{"id":"x","object":"chat.completion","created":1,"model":"gpt-4","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(payload.as_bytes().to_vec()),
        };
        let mut info = info_with_model("gpt-4");
        info.relay_format = relay_format::CLAUDE.to_owned();
        let mut sink = StubSink::default();
        let outcome = openai_handler(&mut info, &mut response, &mut sink);
        let err = outcome.error.expect("seam error");
        assert!(err.message.contains("relayconvert"), "{}", err.message);
    }

    // OpenRouter enterprise 解包。
    #[test]
    fn non_stream_chat_openrouter_enterprise_unwrap() {
        let payload = r#"{"success":true,"data":{"id":"x","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4}}}"#;
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(payload.as_bytes().to_vec()),
        };
        let mut info = info_with_model("gpt-4");
        info.channel_meta.as_mut().expect("meta").channel_type = ct::OPEN_ROUTER;
        info.channel_meta
            .as_mut()
            .expect("meta")
            .channel_other_settings = json!({"openrouter_enterprise": true});
        let mut sink = StubSink::default();
        let outcome = openai_handler(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_none());
        assert_eq!(outcome.usage.prompt_tokens, 3);
        let (_, _, body) = &sink.bytes[0];
        let forwarded: Value = serde_json::from_slice(body).expect("json");
        assert_eq!(forwarded["id"], "x"); // data 解包后转发
    }

    // model list / channel name 按渠道类型分派。
    #[test]
    fn model_list_and_channel_names_by_channel_type() {
        let mut adaptor = OpenAiAdaptor::new();
        assert_eq!(adaptor.get_channel_name(), "openai");
        assert!(adaptor.get_model_list().contains(&"gpt-4o".to_owned()));

        adaptor.channel_type = ct::OPEN_ROUTER;
        assert_eq!(adaptor.get_channel_name(), "openrouter");
        assert!(adaptor.get_model_list().is_empty());

        adaptor.channel_type = ct::LING_YI_WAN_WU;
        assert_eq!(adaptor.get_channel_name(), "lingyiwanwu");
        assert!(adaptor.get_model_list().contains(&"yi-large".to_owned()));

        adaptor.channel_type = ct::XINFERENCE;
        assert_eq!(adaptor.get_channel_name(), "xinference");

        adaptor.channel_type = ct::CHANNEL_TYPE_360;
        assert_eq!(adaptor.get_channel_name(), "ai360");
        assert!(adaptor.get_model_list().is_empty());
    }

    // reasoning 后缀解析（billing/trim_reasoning_suffix.go）。
    #[test]
    fn effort_suffix_parsing() {
        let (effort, model) = parse_openai_reasoning_effort_from_model_suffix("gpt-5.2-minimal");
        assert_eq!(effort, "minimal");
        assert_eq!(model, "gpt-5.2");
        let (effort, model) = parse_openai_reasoning_effort_from_model_suffix("o4-mini-xhigh");
        assert_eq!(effort, "xhigh");
        assert_eq!(model, "o4-mini");
        let (effort, model) = parse_openai_reasoning_effort_from_model_suffix("gpt-4o");
        assert_eq!(effort, "");
        assert_eq!(model, "gpt-4o");
    }

    // DoResponse 分派：stream → OaiStreamHandler，非 stream → OpenaiHandler。
    #[test]
    fn do_response_dispatch() {
        let adaptor = OpenAiAdaptor::new();
        // 非流
        let mut info = info_with_model("gpt-4");
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(
                br#"{"id":"x","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.to_vec(),
            ),
        };
        let mut sink = StubSink::default();
        let outcome = adaptor.do_response(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_none());
        assert_eq!(outcome.usage.total_tokens, 2);

        // 流
        let mut info = info_with_model("gpt-4");
        info.is_stream = true;
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(
                b"data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n".to_vec(),
            ),
        };
        let mut sink = StubSink::default();
        let outcome = adaptor.do_response(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_none());
        assert!(sink.sse_lines.iter().any(|line| line.contains("[DONE]")));
    }
}
