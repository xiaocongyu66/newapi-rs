//! Go `internal/relay/channel/gemini/` 的移植（adaptor.go / relay-gemini.go /
//! relay-gemini-native.go / constant.go）。
//!
//! 契约要点：
//! - URL：thinking 后缀裁剪（`-thinking-<budget>` / `-thinking` /
//!   `-nothinking` / effort 后缀）、version 设置查找、imagen `:predict`、
//!   embedding `:embedContent` / `:batchEmbedContents`、
//!   `:generateContent` / `:streamGenerateContent?alt=sse`（Gemini 原生流式
//!   禁 ping）。
//! - Header：`x-goog-api-key`。
//! - ConvertGeminiRequest：首条 content 缺省 role=user；YouTube fileData 缺
//!   mime → video/webm。
//! - ConvertImageRequest：仅 imagen 模型；size→aspectRatio 映射；quality→
//!   imageSize（hd/high/2K → 2K，其余 1K）。
//! - ConvertEmbeddingRequest：恒为 batch 请求（requests[]），新模型支持
//!   outputDimensionality。
//! - 流式（GeminiChatStreamHandler）：openai 格式输出，tool call id→index
//!   映射、首响应空块、tool_calls 首块复制、stop 响应。
//! - 非流（GeminiChatHandler）：空 candidates → prompt_blocked /
//!   empty_response 折叠（按 RelayFormat 决定信封）；usage 优先 metadata，
//!   缺失本地估算。
//! - imagen 计费：每图固定 258 tokens。
//!
//! 已知偏差：
//! - RelayModeResponses 的 Gemini handlers（GeminiResponsesHandler /
//!   GeminiResponsesStreamHandler）依赖 chat→responses 状态机（relayconvert
//!   oaichat），走 seam 错误。
//! - openai→gemini / claude→gemini 的**请求**转换归转换切片 seam。

use crate::adaptor_common::convert_gemini::{
    GeminiChatResponse, finish_reason, response_gemini_chat_2_openai,
    stream_response_gemini_chat_2_openai, usage_from_gemini_metadata,
};
use crate::adaptor_common::usage::{self, Usage, new_estimated_gemini_chat_billing_usage};
use crate::adaptor_common::{
    ClientSink, DoResponseOutcome, OutboundResponse, OutboundTransport, RequestContext, error_code,
    new_error, new_openai_error, timestamp_now,
};
use crate::relay_info::{AdaptorError, RelayInfo, relay_format};
use crate::relay_mode as relay_constant;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

// ---- 常量 ------------------------------------------------------------------

/// Go `gemini.ModelList`（constant.go:3-34）。
pub const MODEL_LIST: &[&str] = &[
    // stable version
    "gemini-2.5-flash",
    "gemini-2.5-pro",
    "gemini-2.0-flash",
    "gemini-2.0-flash-001",
    "gemini-2.0-flash-lite-001",
    "gemini-2.0-flash-lite",
    "gemini-2.5-flash-lite",
    "gemini-3-pro-image",
    "gemini-3.1-flash-image",
    // latest version
    "gemini-flash-latest",
    "gemini-flash-lite-latest",
    "gemini-pro-latest",
    "gemini-2.5-flash-native-audio-latest",
    // preview version
    "gemini-2.5-flash-preview-tts",
    "gemini-2.5-pro-preview-tts",
    "gemini-2.5-flash-image",
    "gemini-2.5-flash-lite-preview-09-2025",
    "gemini-3-pro-preview",
    "gemini-3-flash-preview",
    "gemini-3.1-pro-preview",
    "gemini-3.1-pro-preview-customtools",
    "gemini-3.1-flash-lite-preview",
    "gemini-3-pro-image-preview",
    "nano-banana-pro-preview",
    "gemini-3.1-flash-image-preview",
    "gemini-robotics-er-1.5-preview",
    "gemini-2.5-computer-use-preview-10-2025",
    "deep-research-pro-preview-12-2025",
    "gemini-2.5-flash-native-audio-preview-09-2025",
    "gemini-2.5-flash-native-audio-preview-12-2025",
    // gemma models
    "gemma-3-1b-it",
    "gemma-3-4b-it",
    "gemma-3-12b-it",
    "gemma-3-27b-it",
    "gemma-3n-e4b-it",
    "gemma-3n-e2b-it",
    // embedding models
    "gemini-embedding-001",
    "gemini-embedding-2-preview",
    // imagen models
    "imagen-4.0-generate-001",
    "imagen-4.0-ultra-generate-001",
    "imagen-4.0-fast-generate-001",
    // veo models
    "veo-2.0-generate-001",
    "veo-3.0-generate-001",
    "veo-3.0-fast-generate-001",
    "veo-3.1-generate-preview",
    "veo-3.1-fast-generate-preview",
    // other models
    "aqa",
];

/// Go `gemini.SafetySettingList`。
pub const SAFETY_SETTING_LIST: &[&str] = &[
    "HARM_CATEGORY_HARASSMENT",
    "HARM_CATEGORY_HATE_SPEECH",
    "HARM_CATEGORY_SEXUALLY_EXPLICIT",
    "HARM_CATEGORY_DANGEROUS_CONTENT",
];

/// Go `gemini.ChannelName`。
pub const CHANNEL_NAME: &str = "google gemini";

// ---- 适配器 ----------------------------------------------------------------

/// Go `gemini.Adaptor`。
#[derive(Debug, Default)]
pub struct GeminiAdaptor;

impl GeminiAdaptor {
    pub fn new() -> Self {
        Self
    }
}

/// Go `model_setting.GetGeminiVersionSetting`（manage_models.go:268-273）。
fn get_gemini_version_setting(info: &RelayInfo, model: &str) -> String {
    info.global_model_settings
        .gemini_version_settings
        .get(model)
        .cloned()
        .or_else(|| {
            info.global_model_settings
                .gemini_version_settings
                .get("default")
                .cloned()
        })
        .unwrap_or_default()
}

/// Go `reasoning.TrimEffortSuffix` 已在 openai 模块实现；这里复用。
use crate::adaptors::openai::trim_effort_suffix;

/// Go `ShouldPreserveThinkingSuffix` 已在 openai 模块实现；这里复用。
use crate::adaptors::openai::should_preserve_thinking_suffix;

impl crate::adaptor::Adaptor for GeminiAdaptor {
    /// Go `Init`（adaptor.go:130-132）：空实现。
    fn init(&mut self, _info: &mut RelayInfo) {}

    /// Go `GetRequestURL`（adaptor.go:134-175）。
    fn get_request_url(&self, info: &mut RelayInfo) -> Result<String, String> {
        let upstream_model = info.upstream_model_name();
        if info.global_model_settings.gemini_thinking_adapter_enabled
            && !should_preserve_thinking_suffix(info, &info.origin_model_name)
        {
            // 新增逻辑：处理 -thinking-<budget> 格式
            if upstream_model.contains("-thinking-") {
                let base = upstream_model
                    .split("-thinking-")
                    .next()
                    .unwrap_or("")
                    .to_owned();
                info.set_upstream_model_name(base);
            } else if upstream_model.ends_with("-thinking") {
                // 旧的适配
                info.set_upstream_model_name(
                    upstream_model.trim_end_matches("-thinking").to_owned(),
                );
            } else if upstream_model.ends_with("-nothinking") {
                info.set_upstream_model_name(
                    upstream_model.trim_end_matches("-nothinking").to_owned(),
                );
            } else {
                let (base_model, level, ok) = trim_effort_suffix(&upstream_model);
                if ok && !level.is_empty() {
                    info.set_upstream_model_name(base_model);
                }
            }
        }

        let upstream_model = info.upstream_model_name();
        let version = get_gemini_version_setting(info, &upstream_model);
        let base_url = info.channel_base_url();

        if upstream_model.starts_with("imagen") {
            return Ok(format!(
                "{base_url}/{version}/models/{upstream_model}:predict"
            ));
        }

        if upstream_model.starts_with("text-embedding")
            || upstream_model.starts_with("embedding")
            || upstream_model.starts_with("gemini-embedding")
        {
            let action = if info.is_gemini_batch_embedding {
                "batchEmbedContents"
            } else {
                "embedContent"
            };
            return Ok(format!(
                "{base_url}/{version}/models/{upstream_model}:{action}"
            ));
        }

        let mut action = "generateContent".to_owned();
        if info.is_stream {
            action = "streamGenerateContent?alt=sse".to_owned();
            if info.relay_mode == relay_constant::RELAY_MODE_GEMINI {
                info.disable_ping = true;
            }
        }
        Ok(format!(
            "{base_url}/{version}/models/{upstream_model}:{action}"
        ))
    }

    /// Go `SetupRequestHeader`（adaptor.go:177-181）。
    fn setup_request_header(
        &self,
        info: &RelayInfo,
        client_headers: &[(String, String)],
    ) -> Result<Vec<(String, String)>, String> {
        let mut headers = crate::adaptor_common::setup_api_request_header(
            info,
            client_headers,
            info.relay_mode == relay_constant::RELAY_MODE_AUDIO_TRANSCRIPTION
                || info.relay_mode == relay_constant::RELAY_MODE_AUDIO_TRANSLATION,
            info.relay_mode == relay_constant::RELAY_MODE_REALTIME,
        );
        headers.push(("x-goog-api-key".to_owned(), info.api_key()));
        Ok(headers)
    }

    /// Go `ConvertGeminiRequest`（adaptor.go:27-45）。
    fn convert_gemini_request(
        &self,
        _info: &mut RelayInfo,
        request: &Value,
    ) -> Result<Value, String> {
        let mut request = request.clone();
        if let Some(contents) = request
            .get_mut("contents")
            .and_then(|c| c.as_array_mut())
            .filter(|c| !c.is_empty())
        {
            if let Some(first) = contents.first_mut()
                && first
                    .get("role")
                    .and_then(|r| r.as_str())
                    .unwrap_or("")
                    .is_empty()
            {
                first["role"] = json!("user");
            }
            for content in contents.iter_mut() {
                let Some(parts) = content.get_mut("parts").and_then(|p| p.as_array_mut()) else {
                    continue;
                };
                for part in parts.iter_mut() {
                    let Some(obj) = part.as_object_mut() else {
                        continue;
                    };
                    let has_file_data = obj
                        .get("fileData")
                        .or_else(|| obj.get("file_data"))
                        .is_some_and(|f| !f.is_null());
                    if !has_file_data {
                        continue;
                    }
                    let file_data = obj.entry("fileData").or_insert_with(|| json!({}));
                    if let Some(fd) = file_data.as_object_mut() {
                        let mime = fd.get("mimeType").and_then(|m| m.as_str()).unwrap_or("");
                        let file_uri = fd.get("fileUri").and_then(|u| u.as_str()).unwrap_or("");
                        if mime.is_empty() && file_uri.contains("www.youtube.com") {
                            fd.insert("mimeType".to_owned(), json!("video/webm"));
                        }
                    }
                }
            }
        }
        Ok(request)
    }

    /// Go `ConvertClaudeRequest`（adaptor.go:47-57）。
    fn convert_claude_request(
        &self,
        _info: &mut RelayInfo,
        _request: &Value,
    ) -> Result<Value, String> {
        // Go: relayconvert.ConvertRequest(..., RelayFormatGemini, req)。
        Err("relayconvert: request conversion registry not ported yet (separate slice)".to_owned())
    }

    /// Go `ConvertOpenAIRequest`（adaptor.go:183-192）。
    fn convert_openai_request(
        &self,
        _info: &mut RelayInfo,
        _request: &Value,
    ) -> Result<Value, String> {
        // Go: relayconvert.ConvertRequest(..., RelayFormatGemini, request)。
        Err("relayconvert: request conversion registry not ported yet (separate slice)".to_owned())
    }

    /// Go `ConvertRerankRequest`（adaptor.go:194-196）。
    fn convert_rerank_request(&self, _relay_mode: i32, _request: &Value) -> Result<Value, String> {
        Ok(Value::Null)
    }

    /// Go `ConvertEmbeddingRequest`（adaptor.go:198-240）。
    fn convert_embedding_request(
        &self,
        info: &mut RelayInfo,
        request: &Value,
    ) -> Result<Value, String> {
        let input = request.get("input").ok_or("input is required")?;
        let inputs = parse_embedding_input(input)?;
        if inputs.is_empty() {
            return Err("input is empty".to_owned());
        }
        // 恒为 batch 请求，端点必须走 batchEmbedContents。
        info.is_gemini_batch_embedding = true;
        let upstream_model = info.upstream_model_name();
        let mut gemini_requests: Vec<Value> = Vec::with_capacity(inputs.len());
        for input in &inputs {
            let mut gemini_request = json!({
                "model": format!("models/{upstream_model}"),
                "content": {
                    "parts": [{"text": input}],
                },
            });
            // 新模型（2024 后）支持 OutputDimensionality。
            if matches!(
                upstream_model.as_str(),
                "text-embedding-004" | "gemini-embedding-exp-03-07" | "gemini-embedding-001"
            ) {
                let dimensions = request
                    .get("dimensions")
                    .and_then(|d| d.as_i64())
                    .unwrap_or(0);
                if dimensions > 0 {
                    gemini_request["outputDimensionality"] = json!(dimensions);
                }
            }
            gemini_requests.push(gemini_request);
        }
        Ok(json!({"requests": gemini_requests}))
    }

    /// Go `ConvertImageRequest`（adaptor.go:64-128）。
    fn convert_image_request(
        &self,
        info: &mut RelayInfo,
        request: &Value,
        _multipart: Option<&crate::adaptor_common::ParsedMultipartForm>,
    ) -> Result<crate::adaptor_common::ConvertedRequestBody, String> {
        if !info.upstream_model_name().starts_with("imagen") {
            return Err(
                "not supported model for image generation, only imagen models are supported"
                    .to_owned(),
            );
        }

        // convert size to aspect ratio but allow user to specify aspect ratio
        let mut aspect_ratio = "1:1".to_owned(); // default aspect ratio
        let size = request
            .get("size")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .trim()
            .to_owned();
        if !size.is_empty() {
            if size.contains(':') {
                aspect_ratio = size;
            } else {
                match size.as_str() {
                    "256x256" | "512x512" | "1024x1024" => aspect_ratio = "1:1".to_owned(),
                    "1536x1024" => aspect_ratio = "3:2".to_owned(),
                    "1024x1536" => aspect_ratio = "2:3".to_owned(),
                    "1024x1792" => aspect_ratio = "9:16".to_owned(),
                    "1792x1024" => aspect_ratio = "16:9".to_owned(),
                    _ => {}
                }
            }
        }

        let prompt = request.get("prompt").and_then(|p| p.as_str()).unwrap_or("");
        let n = request.get("n").and_then(|v| v.as_u64()).unwrap_or(1);
        let mut parameters = json!({
            "sampleCount": n,
            "aspectRatio": aspect_ratio,
            "personGeneration": "allow_adult", // default allow adult
        });

        // Set imageSize when quality parameter is specified（Standard/Ultra）。
        let quality = request
            .get("quality")
            .and_then(|q| q.as_str())
            .unwrap_or("")
            .to_owned();
        if !quality.is_empty() {
            let image_size = match quality.as_str() {
                "hd" | "high" => "2K",
                "2K" => "2K",
                // standard/medium/low/auto/1K 与未知值 → 1K
                _ => "1K",
            };
            parameters["imageSize"] = json!(image_size);
        }

        let gemini_request = json!({
            "instances": [{"prompt": prompt}],
            "parameters": parameters,
        });
        Ok(crate::adaptor_common::ConvertedRequestBody::Json(
            gemini_request,
        ))
    }

    /// Go `ConvertOpenAIResponsesRequest`（adaptor.go:242-256）。
    fn convert_openai_responses_request(
        &self,
        _info: &mut RelayInfo,
        _request: &Value,
    ) -> Result<Value, String> {
        // Go: relayconvert.ConvertRequest(..., RelayFormatGemini, &request)。
        Err("relayconvert: request conversion registry not ported yet (separate slice)".to_owned())
    }

    /// Go `ConvertAudioRequest`（adaptor.go:59-62）。
    fn convert_audio_request(
        &self,
        _info: &mut RelayInfo,
        _request: &Value,
        _multipart: Option<&crate::adaptor_common::ParsedMultipartForm>,
    ) -> Result<crate::adaptor_common::ConvertedRequestBody, String> {
        Err("not implemented".to_owned())
    }

    /// Go `DoRequest`（adaptor.go:258-260）。
    fn do_request<'a>(
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

    /// Go `DoResponse`（adaptor.go:262-299）。
    fn do_response(
        &self,
        info: &mut RelayInfo,
        response: &mut OutboundResponse,
        sink: &mut dyn ClientSink,
    ) -> DoResponseOutcome {
        if info.relay_mode == relay_constant::RELAY_MODE_RESPONSES {
            // Go: GeminiResponsesHandler / GeminiResponsesStreamHandler ——
            // chat→responses 状态机（relayconvert oaichat）归转换切片。
            let usage = build_usage_from_gemini_response(info, &GeminiChatResponse::default());
            return DoResponseOutcome::error(
                usage,
                new_error(
                    "relayconvert: chat→responses stream state machine not ported yet (separate slice)",
                    error_code::BAD_RESPONSE,
                ),
            );
        }

        if info.relay_mode == relay_constant::RELAY_MODE_GEMINI {
            let path = &info.request_url_path;
            if path.contains(":embedContent") || path.contains(":batchEmbedContents") {
                return native_gemini_embedding_handler(info, response, sink);
            }
            if info.is_stream {
                return gemini_text_generation_stream_handler(info, response, sink);
            }
            return gemini_text_generation_handler(info, response, sink);
        }

        if info.upstream_model_name().starts_with("imagen") {
            return gemini_image_handler(info, response, sink);
        }

        let upstream_model = info.upstream_model_name();
        if upstream_model.starts_with("text-embedding")
            || upstream_model.starts_with("embedding")
            || upstream_model.starts_with("gemini-embedding")
        {
            return gemini_embedding_handler(info, response, sink);
        }

        if info.is_stream {
            gemini_chat_stream_handler(info, response, sink)
        } else {
            gemini_chat_handler(info, response, sink)
        }
    }

    /// Go `GetModelList`。
    fn get_model_list(&self) -> Vec<String> {
        MODEL_LIST.iter().map(|s| (*s).to_owned()).collect()
    }

    /// Go `GetChannelName`。
    fn get_channel_name(&self) -> String {
        CHANNEL_NAME.to_owned()
    }
}

/// Go `request.ParseInput`（dto.EmbeddingRequest）：string / array。
fn parse_embedding_input(input: &Value) -> Result<Vec<String>, String> {
    match input {
        Value::String(text) => Ok(vec![text.clone()]),
        Value::Array(items) => Ok(items
            .iter()
            .filter_map(|item| item.as_str().map(|s| s.to_owned()))
            .collect()),
        _ => Err("input is required".to_owned()),
    }
}

// ---- usage 聚合（relay-gemini.go:25-116） -----------------------------------

/// Go `patchGeminiZeroCompletionUsage`（relay-gemini.go:45-62）：上游 metadata
/// 可计费但 completion 为零且确实有输出时本地估算补齐。
fn patch_gemini_zero_completion_usage(
    info: &mut RelayInfo,
    usage: &mut Usage,
    response_text: &str,
    image_count: i64,
) {
    if usage.completion_tokens > 0 {
        return;
    }
    if response_text.is_empty() && image_count == 0 {
        return;
    }
    let estimated = usage::response_text_2_usage_pure(
        response_text,
        &info.upstream_model_name(),
        usage.prompt_tokens,
    );
    usage.completion_tokens = estimated.completion_tokens;
    if image_count != 0 && usage.completion_tokens == 0 {
        usage.completion_tokens = image_count * 1400;
    }
    usage.total_tokens = usage.prompt_tokens + usage.completion_tokens;
    // 覆盖 metadata 推导的 billing usage：结算侧优先 BillingUsage。
    usage.billing_usage = new_estimated_gemini_chat_billing_usage(usage);
}

/// Go `geminiResponseUsageText`（relay-gemini.go:64-77）。
fn gemini_response_usage_text(response: &GeminiChatResponse) -> String {
    let mut text = String::new();
    for candidate in &response.candidates {
        for part in &candidate.content.parts {
            if !part.text.is_empty() {
                text.push_str(&part.text);
            }
        }
    }
    text
}

/// Go `markGeminiGoogleSearchCall`（relay-gemini.go:79-89）。
fn mark_gemini_google_search_call(sink: &mut dyn ClientSink, response: &GeminiChatResponse) {
    for candidate in &response.candidates {
        if let Some(grounding) = &candidate.grounding_metadata
            && !grounding.web_search_queries.is_empty()
        {
            sink.set_context("gemini_google_search_call", json!(true));
            return;
        }
    }
}

/// Go `geminiResponseInlineImageCount`（relay-gemini.go:103-116）。
fn gemini_response_inline_image_count(response: &GeminiChatResponse) -> i64 {
    let mut count = 0;
    for candidate in &response.candidates {
        for part in &candidate.content.parts {
            if let Some(inline) = &part.inline_data
                && !inline.mime_type.is_empty()
            {
                count += 1;
            }
        }
    }
    count
}

/// Go `buildUsageFromGeminiResponse`（relay-gemini.go:91-101）。
pub fn build_usage_from_gemini_response(
    info: &mut RelayInfo,
    response: &GeminiChatResponse,
) -> Usage {
    let metadata = response.get_usage_metadata();
    if crate::adaptor_common::usage::has_gemini_usage_metadata_tokens(metadata) {
        let mut usage = usage_from_gemini_metadata(metadata, info.get_estimate_prompt_tokens())
            .unwrap_or_default();
        let text = gemini_response_usage_text(response);
        let image_count = gemini_response_inline_image_count(response);
        patch_gemini_zero_completion_usage(info, &mut usage, &text, image_count);
        return usage;
    }
    let mut usage = usage::response_text_2_usage_pure(
        &gemini_response_usage_text(response),
        &info.upstream_model_name(),
        info.get_estimate_prompt_tokens(),
    );
    usage.billing_usage = new_estimated_gemini_chat_billing_usage(&usage);
    usage
}

/// Go `attachEstimatedGeminiBillingUsage`（relay-gemini.go:33-38）。
fn attach_estimated_gemini_billing_usage(usage: &mut Usage) {
    if usage.billing_usage.is_none() {
        usage.billing_usage = new_estimated_gemini_chat_billing_usage(usage);
    }
}

// ---- 流式处理（relay-gemini.go:147-311） ------------------------------------

/// Go `geminiStreamHandler` 的数据面：逐块回调 + usage 统计。
pub struct GeminiStreamStats {
    pub usage: Usage,
    pub image_count: i64,
    pub has_billable_usage_metadata: bool,
    pub response_text: String,
}

/// Go `geminiStreamHandler`（relay-gemini.go:147-207）。回调返回 false 时停止
/// （Go sr.Stop）。这里回调以 `&GeminiChatResponse` 形式提供。
pub fn gemini_stream_handler(
    info: &mut RelayInfo,
    response: &mut OutboundResponse,
    sink: &mut dyn ClientSink,
    mut callback: impl FnMut(&mut RelayInfo, &mut dyn ClientSink, &str, &GeminiChatResponse) -> bool,
) -> (GeminiStreamStats, Option<crate::relay_info::AdaptorError>) {
    let mut stats = GeminiStreamStats {
        usage: Usage::default(),
        image_count: 0,
        has_billable_usage_metadata: false,
        response_text: String::new(),
    };
    let (payloads, _end_reason) = crate::adaptor_common::scan_sse_response(response);
    for data in &payloads {
        let gemini_response = match GeminiChatResponse::from_json(data.as_bytes()) {
            Ok(parsed) => parsed,
            Err(err) => {
                return (
                    stats,
                    Some(new_error(
                        format!("unmarshal: {err}"),
                        error_code::BAD_RESPONSE_BODY,
                    )),
                );
            }
        };

        if gemini_response.candidates.is_empty()
            && let Some(prompt_feedback) = &gemini_response.prompt_feedback
            && let Some(block_reason) = &prompt_feedback.block_reason
        {
            sink.set_context(
                "admin_reject_reason",
                json!(format!("gemini_block_reason={block_reason}")),
            );
        }

        mark_gemini_google_search_call(sink, &gemini_response);

        // 统计图片数量 + 文本
        for candidate in &gemini_response.candidates {
            for part in &candidate.content.parts {
                if let Some(inline) = &part.inline_data
                    && !inline.mime_type.is_empty()
                {
                    stats.image_count += 1;
                }
                if !part.text.is_empty() {
                    stats.response_text.push_str(&part.text);
                }
            }
        }

        // 更新使用量统计
        let metadata = gemini_response.get_usage_metadata();
        if crate::adaptor_common::usage::has_gemini_usage_metadata_tokens(metadata) {
            let mapped = usage_from_gemini_metadata(metadata, info.get_estimate_prompt_tokens())
                .unwrap_or_default();
            stats.usage = mapped;
            stats.has_billable_usage_metadata = true;
        }

        if !callback(info, sink, data, &gemini_response) {
            return (
                stats,
                Some(new_error(
                    "gemini callback stopped",
                    error_code::BAD_RESPONSE,
                )),
            );
        }
    }

    if !stats.has_billable_usage_metadata {
        if info.received_response_count > 0 {
            stats.usage = usage::response_text_2_usage_pure(
                &stats.response_text,
                &info.upstream_model_name(),
                info.get_estimate_prompt_tokens(),
            );
        } else {
            stats.usage = Usage::default();
        }
        if stats.image_count != 0 && stats.usage.completion_tokens == 0 {
            stats.usage.completion_tokens = stats.image_count * 1400;
            stats.usage.total_tokens = stats.usage.prompt_tokens + stats.usage.completion_tokens;
            sink.set_context("local_count_tokens", json!(true));
        }
        attach_estimated_gemini_billing_usage(&mut stats.usage);
    } else {
        let text = stats.response_text.clone();
        let image_count = stats.image_count;
        patch_gemini_zero_completion_usage(info, &mut stats.usage, &text, image_count);
    }

    (stats, None)
}

/// Go `handleStream`（relay-gemini.go:126-136）：openai.HandleStreamFormat。
fn handle_stream(
    info: &mut RelayInfo,
    sink: &mut dyn ClientSink,
    resp: &Value,
) -> Result<(), String> {
    let stream_data = serde_json::to_string(resp).map_err(|err| err.to_string())?;
    crate::adaptors::openai::handle_stream_format(
        info,
        sink,
        &stream_data,
        info.force_format(),
        info.thinking_to_content(),
    )
}

/// Go `GeminiChatStreamHandler`（relay-gemini.go:209-311）。
pub fn gemini_chat_stream_handler(
    info: &mut RelayInfo,
    response: &mut OutboundResponse,
    sink: &mut dyn ClientSink,
) -> DoResponseOutcome {
    let id = format!("chatcmpl-{}", info.request_id);
    let create_at = timestamp_now();
    let mut finish_reason = finish_reason::STOP.to_owned();
    let mut tool_call_index_by_choice: BTreeMap<i64, BTreeMap<String, i64>> = BTreeMap::new();
    let mut next_tool_call_index_by_choice: BTreeMap<i64, i64> = BTreeMap::new();

    let (stats, err) = gemini_stream_handler(
        info,
        response,
        sink,
        |info, sink, _data, gemini_response| {
            let (response_value, is_stop) = stream_response_gemini_chat_2_openai(gemini_response);
            let Some(mut response) = response_value else {
                return true;
            };

            response.id = id.clone();
            response.created = create_at;
            response.model = info.upstream_model_name();
            if response.is_tool_call() {
                finish_reason = finish_reason::TOOL_CALLS.to_owned();
                if info.relay_format == relay_format::CLAUDE {
                    for choice in &mut response.choices {
                        choice.finish_reason = None;
                    }
                }
            }
            for choice in &mut response.choices {
                let choice_key = choice.index;
                for tool in choice.delta.tool_calls.iter_mut().flatten() {
                    if tool.id.is_empty() {
                        continue;
                    }
                    let index_by_id = tool_call_index_by_choice.entry(choice_key).or_default();
                    if let Some(idx) = index_by_id.get(&tool.id) {
                        tool.index = Some(*idx);
                        continue;
                    }
                    let idx = next_tool_call_index_by_choice
                        .entry(choice_key)
                        .or_insert(0);
                    let current = *idx;
                    *idx += 1;
                    index_by_id.insert(tool.id.clone(), current);
                    tool.index = Some(current);
                }
            }

            if info.send_response_count == 0 {
                // send first response
                let mut empty_response = json!({
                    "id": id.clone(),
                    "object": "chat.completion.chunk",
                    "created": create_at,
                    "model": info.upstream_model_name(),
                    "choices": [{"index": 0, "delta": {"role": "assistant", "content": ""}}],
                });
                if response.is_tool_call() {
                    let empty_choices = empty_response
                        .get_mut("choices")
                        .and_then(|c| c.as_array_mut());
                    let tool_calls = response
                        .choices
                        .first()
                        .and_then(|c| c.delta.tool_calls.clone());
                    if let (Some(choices), Some(tool_calls)) = (empty_choices, tool_calls)
                        && let Some(first) = choices.first_mut()
                    {
                        let copied: Vec<Value> = tool_calls
                            .iter()
                            .map(|tool| {
                                let mut value = serde_json::to_value(tool).unwrap_or_default();
                                if let Some(function) = value.get_mut("function") {
                                    function["arguments"] = json!("");
                                }
                                value
                            })
                            .collect();
                        first["delta"]["tool_calls"] = Value::Array(copied);
                    }
                    finish_reason = finish_reason::TOOL_CALLS.to_owned();
                    if handle_stream(info, sink, &empty_response).is_err() {
                        // Go: logger.LogError
                    }
                    response.clear_tool_calls();
                    if response.is_finished()
                        && let Some(choice) = response.choices.first_mut()
                    {
                        choice.finish_reason = None;
                    }
                } else if handle_stream(info, sink, &empty_response).is_err() {
                    // Go: logger.LogError
                }
            }

            let response_value = serde_json::to_value(&response).unwrap_or(Value::Null);
            if handle_stream(info, sink, &response_value).is_err() {
                // Go: logger.LogError
            }
            if is_stop && info.relay_format != relay_format::CLAUDE {
                let stop_response = json!({
                    "id": id.clone(),
                    "object": "chat.completion.chunk",
                    "created": create_at,
                    "model": info.upstream_model_name(),
                    "choices": [{"index": 0, "delta": {}, "finish_reason": finish_reason}],
                });
                let _ = handle_stream(info, sink, &stop_response);
            }
            true
        },
    );
    if let Some(err) = err {
        return DoResponseOutcome::error(stats.usage, err);
    }

    // Go: handleFinalStream —— openai.HandleFinalResponse(containStreamUsage=false)。
    if info.relay_format == relay_format::CLAUDE {
        // Go: ClaudeConvertInfo 未 done 时用 stop 响应代替 final usage；该响应经
        // relayconvert 转 claude 事件（seam），openai chunk 不直接出站。
        let _stop = json!({
            "id": id.clone(),
            "object": "chat.completion.chunk",
            "created": create_at,
            "model": info.upstream_model_name(),
            "choices": [{"index": 0, "delta": {}, "finish_reason": finish_reason}],
            "usage": stats.usage.clone(),
        });
    } else {
        // openai 格式：ShouldIncludeUsage 且无 stream usage 时发 final usage 块。
        if info.should_include_usage {
            let response = json!({
                "id": id.clone(),
                "object": "chat.completion.chunk",
                "created": create_at,
                "model": info.upstream_model_name(),
                "choices": [],
                "usage": stats.usage.clone(),
            });
            let _ = sink.object_data(&response);
        }
        sink.done();
    }
    DoResponseOutcome::ok(stats.usage)
}

// ---- 非流处理（relay-gemini.go:313-435） ------------------------------------

/// Go `GeminiChatHandler`（relay-gemini.go:313-390）。
pub fn gemini_chat_handler(
    info: &mut RelayInfo,
    response: &mut OutboundResponse,
    sink: &mut dyn ClientSink,
) -> DoResponseOutcome {
    let response_body = match response.read_full_body() {
        Ok(body) => body,
        Err(err) => return DoResponseOutcome::error(Usage::default(), err),
    };
    let gemini_response = match GeminiChatResponse::from_json(&response_body) {
        Ok(parsed) => parsed,
        Err(err) => {
            return DoResponseOutcome::error(
                Usage::default(),
                new_openai_error(err.to_string(), error_code::BAD_RESPONSE_BODY, 500),
            );
        }
    };
    mark_gemini_google_search_call(sink, &gemini_response);
    if gemini_response.candidates.is_empty() {
        let usage = build_usage_from_gemini_response(info, &gemini_response);

        let (message, code, status) = if let Some(prompt_feedback) =
            &gemini_response.prompt_feedback
            && let Some(block_reason) = &prompt_feedback.block_reason
        {
            sink.set_context(
                "admin_reject_reason",
                json!(format!("gemini_block_reason={block_reason}")),
            );
            (
                format!("request blocked by Gemini API: {block_reason}"),
                error_code::PROMPT_BLOCKED,
                400,
            )
        } else {
            sink.set_context("admin_reject_reason", json!("gemini_empty_candidates"));
            (
                "empty response from Gemini API".to_owned(),
                error_code::EMPTY_RESPONSE,
                500,
            )
        };
        let api_error = new_openai_error(message, code, status);

        match info.relay_format.as_str() {
            f if f == relay_format::CLAUDE => {
                sink.send_json(
                    api_error.status_code,
                    &json!({
                        "type": "error",
                        "error": {
                            "type": api_error.code,
                            "message": api_error.message,
                        },
                    }),
                );
            }
            _ => {
                sink.send_json(
                    api_error.status_code,
                    &json!({
                        "error": {
                            "message": api_error.message,
                            "type": api_error.code,
                            "code": api_error.code,
                        },
                    }),
                );
            }
        }
        return DoResponseOutcome::ok(usage);
    }
    let mut full_text_response = response_gemini_chat_2_openai(
        &format!("chatcmpl-{}", info.request_id),
        timestamp_now(),
        &gemini_response,
    );
    full_text_response.model = info.upstream_model_name();
    let usage = build_usage_from_gemini_response(info, &gemini_response);
    full_text_response.usage = Some(usage.clone());

    match info.relay_format.as_str() {
        f if f == relay_format::OPENAI => {
            let body = serde_json::to_vec(&full_text_response)
                .map_err(|err| new_error(err.to_string(), error_code::BAD_RESPONSE_BODY));
            match body {
                Ok(body) => {
                    sink.send_bytes(response.status, "application/json", &body);
                    DoResponseOutcome::ok(usage)
                }
                Err(err) => DoResponseOutcome::error(Usage::default(), err),
            }
        }
        f if f == relay_format::CLAUDE => {
            // Go: relayconvert.ConvertResponse(..., RelayFormatClaude, ...)。
            DoResponseOutcome::error(
                usage,
                new_error(
                    "relayconvert: response conversion registry not ported yet (separate slice)",
                    error_code::BAD_RESPONSE_BODY,
                ),
            )
        }
        f if f == relay_format::GEMINI => {
            // 原样透传。
            sink.send_bytes(response.status, "application/json", &response_body);
            DoResponseOutcome::ok(usage)
        }
        _ => {
            sink.send_bytes(response.status, "application/json", &response_body);
            DoResponseOutcome::ok(usage)
        }
    }
}

/// Go `GeminiEmbeddingHandler`（relay-gemini.go:392-435）。
pub fn gemini_embedding_handler(
    info: &mut RelayInfo,
    response: &mut OutboundResponse,
    sink: &mut dyn ClientSink,
) -> DoResponseOutcome {
    let response_body = match response.read_full_body() {
        Ok(body) => body,
        Err(err) => return DoResponseOutcome::error(Usage::default(), err),
    };
    let gemini_response: Value = match serde_json::from_slice(&response_body) {
        Ok(parsed) => parsed,
        Err(err) => {
            return DoResponseOutcome::error(
                Usage::default(),
                new_openai_error(err.to_string(), error_code::BAD_RESPONSE_BODY, 500),
            );
        }
    };
    let embeddings = gemini_response
        .get("embeddings")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default();

    let mut openai_response = json!({
        "object": "list",
        "data": [],
        "model": info.upstream_model_name(),
    });
    for (i, embedding) in embeddings.iter().enumerate() {
        if let Some(data) = openai_response["data"].as_array_mut() {
            data.push(json!({
                "object": "embedding",
                "embedding": embedding.get("values").cloned().unwrap_or(Value::Null),
                "index": i,
            }));
        }
    }

    // Google 未明确 embedding 计费口径，按 openai 输入 token 口径本地估算。
    let usage = usage::response_text_2_usage_pure(
        "",
        &info.upstream_model_name(),
        info.get_estimate_prompt_tokens(),
    );
    openai_response["usage"] = serde_json::to_value(&usage).unwrap_or_default();

    let body = serde_json::to_vec(&openai_response).unwrap_or_default();
    sink.send_bytes(response.status, "application/json", &body);
    DoResponseOutcome::ok(usage)
}

/// Go `GeminiImageHandler`（relay-gemini.go:437-488）：imagen 计费每图固定
/// 258 tokens。
pub fn gemini_image_handler(
    info: &mut RelayInfo,
    response: &mut OutboundResponse,
    sink: &mut dyn ClientSink,
) -> DoResponseOutcome {
    let _ = info;
    let status = response.status;
    let response_body = match response.read_full_body() {
        Ok(body) => body,
        Err(err) => return DoResponseOutcome::error(Usage::default(), err),
    };
    let gemini_response: Value = match serde_json::from_slice(&response_body) {
        Ok(parsed) => parsed,
        Err(err) => {
            return DoResponseOutcome::error(
                Usage::default(),
                new_openai_error(err.to_string(), error_code::BAD_RESPONSE_BODY, 500),
            );
        }
    };

    let predictions = gemini_response
        .get("predictions")
        .and_then(|p| p.as_array())
        .cloned()
        .unwrap_or_default();
    if predictions.is_empty() {
        return DoResponseOutcome::error(
            Usage::default(),
            new_openai_error("no images generated", error_code::BAD_RESPONSE_BODY, 500),
        );
    }

    let mut data: Vec<Value> = Vec::new();
    for prediction in &predictions {
        let filtered = prediction
            .get("raiFilteredReason")
            .and_then(|r| r.as_str())
            .unwrap_or("");
        if !filtered.is_empty() {
            continue; // skip filtered image
        }
        data.push(json!({
            "b64_json": prediction
                .get("bytesBase64Encoded")
                .cloned()
                .unwrap_or(Value::Null),
        }));
    }

    let openai_response = json!({
        "created": timestamp_now(),
        "data": data,
    });
    let body = serde_json::to_vec(&openai_response).unwrap_or_default();
    sink.set_header("Content-Type", "application/json");
    sink.send_bytes(status, "application/json", &body);

    // 每张生成图固定 258 tokens。
    const IMAGE_TOKENS: i64 = 258;
    let generated_images = openai_response
        .get("data")
        .and_then(|d| d.as_array())
        .map(|a| a.len() as i64)
        .unwrap_or(0);
    let usage = Usage {
        prompt_tokens: IMAGE_TOKENS * generated_images,
        total_tokens: IMAGE_TOKENS * generated_images,
        ..Usage::default()
    };
    DoResponseOutcome::ok(usage)
}

// ---- 原生（relay-gemini-native.go） ----------------------------------------

/// Go `GeminiTextGenerationHandler`（relay-gemini-native.go:20-48）：原生
/// Gemini 格式透传。
pub fn gemini_text_generation_handler(
    info: &mut RelayInfo,
    response: &mut OutboundResponse,
    sink: &mut dyn ClientSink,
) -> DoResponseOutcome {
    let response_body = match response.read_full_body() {
        Ok(body) => body,
        Err(err) => return DoResponseOutcome::error(Usage::default(), err),
    };
    let gemini_response = match GeminiChatResponse::from_json(&response_body) {
        Ok(parsed) => parsed,
        Err(err) => {
            return DoResponseOutcome::error(
                Usage::default(),
                new_openai_error(err.to_string(), error_code::BAD_RESPONSE_BODY, 500),
            );
        }
    };
    if gemini_response.candidates.is_empty()
        && let Some(prompt_feedback) = &gemini_response.prompt_feedback
        && let Some(block_reason) = &prompt_feedback.block_reason
    {
        sink.set_context(
            "admin_reject_reason",
            json!(format!("gemini_block_reason={block_reason}")),
        );
    }
    let usage = build_usage_from_gemini_response(info, &gemini_response);
    sink.send_bytes(response.status, "application/json", &response_body);
    DoResponseOutcome::ok(usage)
}

/// Go `NativeGeminiEmbeddingHandler`（relay-gemini-native.go:50-79）。
pub fn native_gemini_embedding_handler(
    info: &mut RelayInfo,
    response: &mut OutboundResponse,
    sink: &mut dyn ClientSink,
) -> DoResponseOutcome {
    let response_body = match response.read_full_body() {
        Ok(body) => body,
        Err(err) => return DoResponseOutcome::error(Usage::default(), err),
    };
    // batch / single 两种响应形态分别校验（Go 分别 Unmarshal）。
    if info.is_gemini_batch_embedding {
        #[derive(Default, serde::Deserialize)]
        #[serde(default)]
        #[allow(dead_code)]
        struct BatchResponse {
            #[serde(rename = "embeddings", default)]
            embeddings: Vec<Value>,
        }
        if let Err(err) = serde_json::from_slice::<BatchResponse>(&response_body) {
            return DoResponseOutcome::error(
                Usage::default(),
                new_openai_error(err.to_string(), error_code::BAD_RESPONSE_BODY, 500),
            );
        }
    } else {
        #[derive(Default, serde::Deserialize)]
        #[serde(default)]
        #[allow(dead_code)]
        struct SingleResponse {
            #[serde(rename = "embedding", default)]
            embedding: Option<Value>,
        }
        if let Err(err) = serde_json::from_slice::<SingleResponse>(&response_body) {
            return DoResponseOutcome::error(
                Usage::default(),
                new_openai_error(err.to_string(), error_code::BAD_RESPONSE_BODY, 500),
            );
        }
    }
    let usage = usage::response_text_2_usage_pure(
        "",
        &info.upstream_model_name(),
        info.get_estimate_prompt_tokens(),
    );
    sink.send_bytes(response.status, "application/json", &response_body);
    DoResponseOutcome::ok(usage)
}

/// Go `GeminiTextGenerationStreamHandler`（relay-gemini-native.go:81-93）：
/// 原生 Gemini 流式逐块透传。
pub fn gemini_text_generation_stream_handler(
    info: &mut RelayInfo,
    response: &mut OutboundResponse,
    sink: &mut dyn ClientSink,
) -> DoResponseOutcome {
    sink.set_event_stream_headers();
    let (stats, err) = gemini_stream_handler(
        info,
        response,
        sink,
        |_info, sink, data, _gemini_response| sink.string_data(data).is_ok(),
    );
    if let Some(err) = err {
        return DoResponseOutcome::error(stats.usage, err);
    }
    DoResponseOutcome::ok(stats.usage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adaptor::Adaptor as _;
    use crate::adaptor_common::{OutboundRequest, OutboundResponseBody, OutboundTransport};
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    struct StubTransport {
        captured: Mutex<Vec<OutboundRequest>>,
    }

    impl StubTransport {
        fn new() -> Self {
            Self {
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
            Box::pin(async move {
                Ok(OutboundResponse {
                    status: 200,
                    headers: vec![],
                    body: OutboundResponseBody::Full(b"{}".to_vec()),
                })
            })
        }
    }

    #[derive(Default)]
    struct StubSink {
        sse_lines: Vec<String>,
        bytes: Vec<(i32, String, Vec<u8>)>,
        json: Vec<(i32, Value)>,
        context: Vec<(String, Value)>,
        #[allow(dead_code)]
        headers_set: Vec<(String, String)>,
    }

    impl ClientSink for StubSink {
        fn set_event_stream_headers(&mut self) {}
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
            self.headers_set.push((key.to_owned(), value.to_owned()));
        }
        fn set_context(&mut self, key: &str, value: Value) {
            self.context.push((key.to_owned(), value));
        }
        fn get_context_string(&self, _key: &str) -> String {
            String::new()
        }
    }

    fn gemini_info(model: &str) -> RelayInfo {
        let mut info = RelayInfo {
            relay_format: relay_format::GEMINI.to_owned(),
            ..RelayInfo::default()
        };
        info.init_channel_meta(crate::relay_info::ChannelMetaSnapshot {
            channel_type: crate::adaptor::channel_type::GEMINI,
            api_type: crate::adaptor::api_type::GEMINI,
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

    // GetRequestURL：generateContent / streamGenerateContent?alt=sse。
    #[test]
    fn get_request_url_generate_content() {
        let mut info = gemini_info("gemini-2.5-flash");
        info.channel_meta.as_mut().expect("meta").channel_base_url =
            "https://generativelanguage.googleapis.com".to_owned();
        info.channel_meta
            .as_mut()
            .expect("meta")
            .upstream_model_name = "gemini-2.5-flash".to_owned();
        info.request_url_path = "/v1beta/models/gemini-2.5-flash:generateContent".to_owned();
        let adaptor = GeminiAdaptor::new();
        assert_eq!(
            adaptor.get_request_url(&mut info).expect("url"),
            "https://generativelanguage.googleapis.com//models/gemini-2.5-flash:generateContent"
        );
    }

    // thinking 后缀裁剪（thinking adapter 开启时）。
    #[test]
    fn get_request_url_thinking_suffix_trim() {
        let mut info = gemini_info("gemini-2.5-flash-thinking");
        info.global_model_settings.gemini_thinking_adapter_enabled = true;
        info.channel_meta.as_mut().expect("meta").channel_base_url =
            "https://gen.example.com".to_owned();
        let adaptor = GeminiAdaptor::new();
        let url = adaptor.get_request_url(&mut info).expect("url");
        assert_eq!(info.upstream_model_name(), "gemini-2.5-flash");
        assert!(
            url.contains("//models/gemini-2.5-flash:generateContent"),
            "{url}"
        );
    }

    // budget 后缀（-thinking-8192）。
    #[test]
    fn get_request_url_thinking_budget_suffix_trim() {
        let mut info = gemini_info("gemini-2.5-pro-thinking-8192");
        info.global_model_settings.gemini_thinking_adapter_enabled = true;
        info.channel_meta.as_mut().expect("meta").channel_base_url =
            "https://gen.example.com".to_owned();
        let adaptor = GeminiAdaptor::new();
        let _ = adaptor.get_request_url(&mut info).expect("url");
        assert_eq!(info.upstream_model_name(), "gemini-2.5-pro");
    }

    // -nothinking 后缀。
    #[test]
    fn get_request_url_nothinking_suffix_trim() {
        let mut info = gemini_info("gemini-2.5-flash-nothinking");
        info.global_model_settings.gemini_thinking_adapter_enabled = true;
        info.channel_meta.as_mut().expect("meta").channel_base_url =
            "https://gen.example.com".to_owned();
        let adaptor = GeminiAdaptor::new();
        let _ = adaptor.get_request_url(&mut info).expect("url");
        assert_eq!(info.upstream_model_name(), "gemini-2.5-flash");
    }

    // effort 后缀裁剪（-high 等）。
    #[test]
    fn get_request_url_effort_suffix_trim() {
        let mut info = gemini_info("gemini-2.5-flash-high");
        info.global_model_settings.gemini_thinking_adapter_enabled = true;
        info.channel_meta.as_mut().expect("meta").channel_base_url =
            "https://gen.example.com".to_owned();
        let adaptor = GeminiAdaptor::new();
        let _ = adaptor.get_request_url(&mut info).expect("url");
        assert_eq!(info.upstream_model_name(), "gemini-2.5-flash");
    }

    // imagen :predict。
    #[test]
    fn get_request_url_imagen_predict() {
        let mut info = gemini_info("imagen-4.0-generate-001");
        info.channel_meta.as_mut().expect("meta").channel_base_url =
            "https://gen.example.com".to_owned();
        let adaptor = GeminiAdaptor::new();
        assert_eq!(
            adaptor.get_request_url(&mut info).expect("url"),
            "https://gen.example.com//models/imagen-4.0-generate-001:predict"
        );
    }

    // embedding :embedContent / batch :batchEmbedContents。
    #[test]
    fn get_request_url_embedding() {
        let mut info = gemini_info("gemini-embedding-001");
        info.channel_meta.as_mut().expect("meta").channel_base_url =
            "https://gen.example.com".to_owned();
        let adaptor = GeminiAdaptor::new();
        assert_eq!(
            adaptor.get_request_url(&mut info).expect("url"),
            "https://gen.example.com//models/gemini-embedding-001:embedContent"
        );

        info.is_gemini_batch_embedding = true;
        assert_eq!(
            adaptor.get_request_url(&mut info).expect("url"),
            "https://gen.example.com//models/gemini-embedding-001:batchEmbedContents"
        );
    }

    // version 设置注入 URL。
    #[test]
    fn get_request_url_version_setting() {
        let mut info = gemini_info("gemini-2.5-flash");
        info.global_model_settings
            .gemini_version_settings
            .insert("default".to_owned(), "v1beta".to_owned());
        info.channel_meta.as_mut().expect("meta").channel_base_url =
            "https://gen.example.com".to_owned();
        let adaptor = GeminiAdaptor::new();
        assert_eq!(
            adaptor.get_request_url(&mut info).expect("url"),
            "https://gen.example.com/v1beta/models/gemini-2.5-flash:generateContent"
        );
    }

    // SetupRequestHeader：x-goog-api-key。
    #[test]
    fn setup_headers() {
        let mut info = gemini_info("gemini-2.5-flash");
        info.channel_meta.as_mut().expect("meta").api_key = "goog-key".to_owned();
        let adaptor = GeminiAdaptor::new();
        let headers = adaptor
            .setup_request_header(
                &info,
                &[("Content-Type".to_owned(), "application/json".to_owned())],
            )
            .expect("headers");
        assert!(headers.contains(&("x-goog-api-key".to_owned(), "goog-key".to_owned())));
        assert!(headers.contains(&("Content-Type".to_owned(), "application/json".to_owned())));
    }

    // ConvertGeminiRequest：首条 role=user 缺省 + YouTube fileData mime 补齐。
    #[test]
    fn convert_gemini_request_role_and_youtube_mime() {
        let mut info = gemini_info("gemini-2.5-flash");
        let request = json!({
            "contents": [
                {"parts": [{"text": "describe"}]},
                {"role": "user", "parts": [
                    {"fileData": {"fileUri": "https://www.youtube.com/watch?v=x"}},
                    {"fileData": {"mimeType": "video/mp4", "fileUri": "https://example.com/a.mp4"}}
                ]}
            ]
        });
        let converted = GeminiAdaptor::new()
            .convert_gemini_request(&mut info, &request)
            .expect("converted");
        assert_eq!(converted["contents"][0]["role"], "user");
        assert_eq!(
            converted["contents"][1]["parts"][0]["fileData"]["mimeType"],
            "video/webm"
        );
        assert_eq!(
            converted["contents"][1]["parts"][1]["fileData"]["mimeType"],
            "video/mp4"
        );
    }

    // ConvertImageRequest：size→aspectRatio + quality→imageSize。
    #[test]
    fn convert_image_request_aspect_ratio_and_quality() {
        let mut info = gemini_info("imagen-4.0-generate-001");
        let adaptor = GeminiAdaptor::new();
        // 1792x1024 → 16:9；quality hd → 2K。
        let request = json!({"model": "imagen-4.0-generate-001", "prompt": "a cat", "size": "1792x1024", "quality": "hd", "n": 2});
        let converted = adaptor
            .convert_image_request(&mut info, &request, None)
            .expect("converted");
        let crate::adaptor_common::ConvertedRequestBody::Json(body) = converted else {
            panic!("expected json body");
        };
        assert_eq!(body["parameters"]["aspectRatio"], "16:9");
        assert_eq!(body["parameters"]["sampleCount"], 2);
        assert_eq!(body["parameters"]["personGeneration"], "allow_adult");
        assert_eq!(body["parameters"]["imageSize"], "2K");
        assert_eq!(body["instances"][0]["prompt"], "a cat");

        // 用户显式 aspect ratio 优先。
        let request = json!({"prompt": "x", "size": "4:3"});
        let converted = adaptor
            .convert_image_request(&mut info, &request, None)
            .expect("converted");
        let crate::adaptor_common::ConvertedRequestBody::Json(body) = converted else {
            panic!("expected json body");
        };
        assert_eq!(body["parameters"]["aspectRatio"], "4:3");
    }

    // ConvertImageRequest：非 imagen 模型拒绝。
    #[test]
    fn convert_image_request_rejects_non_imagen() {
        let mut info = gemini_info("gemini-2.5-flash");
        let adaptor = GeminiAdaptor::new();
        let request = json!({"prompt": "x"});
        let err = adaptor
            .convert_image_request(&mut info, &request, None)
            .expect_err("rejected");
        assert!(err.contains("only imagen models"), "{err}");
    }

    // ConvertEmbeddingRequest：恒为 batch 请求 + dimensions 支持。
    #[test]
    fn convert_embedding_request_batch() {
        let mut info = gemini_info("gemini-embedding-001");
        let adaptor = GeminiAdaptor::new();
        let request = json!({"input": ["hello", "world"], "dimensions": 768});
        let converted = adaptor
            .convert_embedding_request(&mut info, &request)
            .expect("converted");
        assert!(info.is_gemini_batch_embedding);
        let requests = converted["requests"].as_array().expect("requests");
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0]["model"], "models/gemini-embedding-001");
        assert_eq!(requests[0]["outputDimensionality"], 768);

        // 不支持 dimensions 的模型不写入。
        let mut info = gemini_info("text-moderation-latest");
        let request = json!({"input": "single"});
        let converted = adaptor
            .convert_embedding_request(&mut info, &request)
            .expect("converted");
        assert!(
            converted["requests"][0]
                .get("outputDimensionality")
                .is_none()
        );

        // 空 input 报错。
        let mut info = gemini_info("gemini-embedding-001");
        let request = json!({});
        assert!(
            adaptor
                .convert_embedding_request(&mut info, &request)
                .is_err()
        );
    }

    // DoRequest：URL + headers + body 经 transport。
    #[test]
    fn do_request_contract() {
        let mut info = gemini_info("gemini-2.5-flash");
        info.channel_meta.as_mut().expect("meta").channel_base_url =
            "https://gen.example.com".to_owned();
        info.channel_meta.as_mut().expect("meta").api_key = "goog".to_owned();
        let transport = StubTransport::new();
        let adaptor = GeminiAdaptor::new();
        let client_headers = [("Content-Type".to_owned(), "application/json".to_owned())];
        let context = RequestContext {
            client_headers: &client_headers,
            method: "POST",
        };
        let future = adaptor.do_request(&mut info, &context, b"{}".as_slice(), &transport);
        let response = {
            use std::task::{Context as TaskContext, Poll, Wake, Waker};
            struct NoopWaker;
            impl Wake for NoopWaker {
                fn wake(self: Arc<Self>) {}
                fn wake_by_ref(self: &Arc<Self>) {}
            }
            let mut pinned = std::pin::pin!(future);
            let waker = Waker::from(Arc::new(NoopWaker));
            let mut cx = TaskContext::from_waker(&waker);
            loop {
                if let Poll::Ready(v) = pinned.as_mut().poll(&mut cx) {
                    break v.expect("response");
                }
                std::thread::yield_now();
            }
        };
        assert_eq!(response.status, 200);
        let captured = transport.captured.lock().expect("poisoned");
        assert!(captured[0].url.contains(":generateContent"));
        assert!(
            captured[0]
                .headers
                .contains(&("x-goog-api-key".to_owned(), "goog".to_owned()))
        );
    }

    // 非流：usage metadata → usage；空 candidates → prompt_blocked 折叠（claude
    // 信封）/ empty_response（openai 信封）。
    #[test]
    fn chat_handler_empty_candidates_blocked() {
        let payload = br#"{"promptFeedback": {"blockReason": "SAFETY"}}"#;
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(payload.to_vec()),
        };
        let mut info = gemini_info("gemini-2.5-flash");
        let mut sink = StubSink::default();
        let outcome = gemini_chat_handler(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_none()); // Go: 返回 (&usage, nil)，错误经 c.JSON 写出
        let (status, body) = &sink.json[0];
        assert_eq!(*status, 400);
        assert_eq!(body["error"]["type"], "prompt_blocked");
        assert!(
            sink.context
                .iter()
                .any(|(key, value)| key == "admin_reject_reason"
                    && value == &json!("gemini_block_reason=SAFETY"))
        );
    }

    #[test]
    fn chat_handler_empty_candidates_claude_envelope() {
        let payload = br#"{"promptFeedback": {"blockReason": "SAFETY"}}"#;
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(payload.to_vec()),
        };
        let mut info = gemini_info("gemini-2.5-flash");
        info.relay_format = relay_format::CLAUDE.to_owned();
        let mut sink = StubSink::default();
        let _ = gemini_chat_handler(&mut info, &mut response, &mut sink);
        let (status, body) = &sink.json[0];
        assert_eq!(*status, 400);
        assert_eq!(body["type"], "error");
        assert_eq!(body["error"]["type"], "prompt_blocked");
    }

    #[test]
    fn chat_handler_empty_candidates_no_feedback() {
        let payload = br#"{}"#;
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(payload.to_vec()),
        };
        let mut info = gemini_info("gemini-2.5-flash");
        let mut sink = StubSink::default();
        let outcome = gemini_chat_handler(&mut info, &mut response, &mut sink);
        let (status, body) = &sink.json[0];
        assert_eq!(*status, 500);
        assert_eq!(body["error"]["type"], "empty_response");
        assert!(outcome.error.is_none());
    }

    // 非流成功：gemini → openai 转换（文本 + functionCall → tool_calls）。
    #[test]
    fn chat_handler_openai_format_conversion() {
        let payload = br#"{"candidates":[{"content":{"parts":[{"text":"Hello"}],"role":"model"},"finishReason":"STOP","index":0}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":5,"totalTokenCount":15}}"#;
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(payload.to_vec()),
        };
        let mut info = gemini_info("gemini-2.5-flash");
        info.relay_format = relay_format::OPENAI.to_owned();
        info.set_estimate_prompt_tokens(10);
        let mut sink = StubSink::default();
        let outcome = gemini_chat_handler(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_none());
        assert_eq!(outcome.usage.prompt_tokens, 10);
        assert_eq!(outcome.usage.completion_tokens, 5);
        assert_eq!(outcome.usage.total_tokens, 15);
        let (_, _, body) = &sink.bytes[0];
        let forwarded: Value = serde_json::from_slice(body).expect("json");
        assert_eq!(forwarded["object"], "chat.completion");
        assert_eq!(forwarded["choices"][0]["message"]["content"], "Hello");
        assert_eq!(forwarded["choices"][0]["finish_reason"], "stop");
        assert_eq!(forwarded["model"], "gemini-2.5-flash");
    }

    // functionCall → tool_calls + finish_reason=tool_calls。
    #[test]
    fn chat_handler_tool_call_conversion() {
        let payload = br#"{"candidates":[{"content":{"parts":[{"functionCall":{"name":"get_weather","args":{"city":"sf"}}}],"role":"model"},"finishReason":"STOP","index":0}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":5,"totalTokenCount":15}}"#;
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(payload.to_vec()),
        };
        let mut info = gemini_info("gemini-2.5-flash");
        info.relay_format = relay_format::OPENAI.to_owned();
        let mut sink = StubSink::default();
        let outcome = gemini_chat_handler(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_none());
        let (_, _, body) = &sink.bytes[0];
        let forwarded: Value = serde_json::from_slice(body).expect("json");
        let tools = forwarded["choices"][0]["message"]["tool_calls"]
            .as_array()
            .expect("tools");
        assert_eq!(tools[0]["function"]["name"], "get_weather");
        assert!(tools[0]["id"].as_str().expect("id").starts_with("call_"));
        assert_eq!(forwarded["choices"][0]["finish_reason"], "tool_calls");
    }

    // inlineData 图片 → markdown data URI。
    #[test]
    fn chat_handler_inline_image_markdown() {
        let payload = br#"{"candidates":[{"content":{"parts":[{"inlineData":{"mimeType":"image/png","data":"aGk="}}],"role":"model"},"finishReason":"STOP","index":0}],"usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":0,"totalTokenCount":1}}"#;
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(payload.to_vec()),
        };
        let mut info = gemini_info("gemini-2.5-flash");
        info.relay_format = relay_format::OPENAI.to_owned();
        let mut sink = StubSink::default();
        let outcome = gemini_chat_handler(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_none());
        let (_, _, body) = &sink.bytes[0];
        let forwarded: Value = serde_json::from_slice(body).expect("json");
        assert_eq!(
            forwarded["choices"][0]["message"]["content"],
            "![image](data:image/png;base64,aGk=)"
        );
    }

    // finishReason MAX_TOKENS → length。
    #[test]
    fn chat_handler_finish_reason_mapping() {
        let payload = br#"{"candidates":[{"content":{"parts":[{"text":"x"}],"role":"model"},"finishReason":"MAX_TOKENS","index":0}],"usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":1,"totalTokenCount":2}}"#;
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(payload.to_vec()),
        };
        let mut info = gemini_info("gemini-2.5-flash");
        info.relay_format = relay_format::OPENAI.to_owned();
        let mut sink = StubSink::default();
        let outcome = gemini_chat_handler(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_none());
        let (_, _, body) = &sink.bytes[0];
        let forwarded: Value = serde_json::from_slice(body).expect("json");
        assert_eq!(forwarded["choices"][0]["finish_reason"], "length");
    }

    // gemini 原生格式（RelayFormatGemini）→ 原样透传。
    #[test]
    fn chat_handler_gemini_format_passthrough() {
        let payload = br#"{"candidates":[{"content":{"parts":[{"text":"Hello"}],"role":"model"},"finishReason":"STOP","index":0}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":5,"totalTokenCount":15}}"#;
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(payload.to_vec()),
        };
        let mut info = gemini_info("gemini-2.5-flash");
        info.relay_format = relay_format::GEMINI.to_owned();
        let mut sink = StubSink::default();
        let outcome = gemini_chat_handler(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_none());
        let (_, _, body) = &sink.bytes[0];
        let forwarded: Value = serde_json::from_slice(body).expect("json");
        assert!(forwarded.get("candidates").is_some(), "raw passthrough");
        assert!(forwarded.get("object").is_none(), "not openai-shaped");
    }

    // metadata 缺失 → 本地估算（ResponseText2Usage）+ estimated billing usage。
    #[test]
    fn chat_handler_usage_fallback_estimation() {
        let payload = br#"{"candidates":[{"content":{"parts":[{"text":"hello world how are you"}],"role":"model"},"finishReason":"STOP","index":0}]}"#;
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(payload.to_vec()),
        };
        let mut info = gemini_info("gemini-2.5-flash");
        info.relay_format = relay_format::OPENAI.to_owned();
        info.set_estimate_prompt_tokens(7);
        let mut sink = StubSink::default();
        let outcome = gemini_chat_handler(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_none());
        assert_eq!(outcome.usage.prompt_tokens, 7);
        assert!(outcome.usage.completion_tokens > 0);
        assert!(outcome.usage.billing_usage.is_some());
        assert_eq!(
            outcome.usage.billing_usage.as_ref().expect("billing")["estimated"],
            json!(true)
        );
    }

    // imagen handler：258 tokens/图 + raiFilteredReason 跳过。
    #[test]
    fn image_handler_fixed_token_count() {
        let payload = br#"{"predictions":[{"bytesBase64Encoded":"QUJD","mimeType":"image/png"},{"raiFilteredReason":"blocked"}]}"#;
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(payload.to_vec()),
        };
        let mut info = gemini_info("imagen-4.0-generate-001");
        let mut sink = StubSink::default();
        let outcome = gemini_image_handler(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_none());
        // 1 张有效图（filtered 跳过）→ 258 tokens。
        assert_eq!(outcome.usage.prompt_tokens, 258);
        assert_eq!(outcome.usage.total_tokens, 258);
        let (_, _, body) = &sink.bytes[0];
        let forwarded: Value = serde_json::from_slice(body).expect("json");
        assert_eq!(forwarded["data"].as_array().expect("data").len(), 1);
    }

    // predictions 空 → no images generated 错误。
    #[test]
    fn image_handler_no_predictions_error() {
        let payload = br#"{"predictions":[]}"#;
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(payload.to_vec()),
        };
        let mut info = gemini_info("imagen-4.0-generate-001");
        let mut sink = StubSink::default();
        let outcome = gemini_image_handler(&mut info, &mut response, &mut sink);
        let err = outcome.error.expect("error");
        assert!(err.message.contains("no images generated"));
    }

    // embedding handler：GeminiBatchEmbeddingResponse → OpenAI list。
    #[test]
    fn embedding_handler_openai_list() {
        let payload = br#"{"embeddings":[{"values":[0.1,0.2]},{"values":[0.3,0.4]}]}"#;
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(payload.to_vec()),
        };
        let mut info = gemini_info("gemini-embedding-001");
        info.set_estimate_prompt_tokens(4);
        let mut sink = StubSink::default();
        let outcome = gemini_embedding_handler(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_none());
        assert_eq!(outcome.usage.prompt_tokens, 4);
        let (_, _, body) = &sink.bytes[0];
        let forwarded: Value = serde_json::from_slice(body).expect("json");
        assert_eq!(forwarded["object"], "list");
        assert_eq!(forwarded["model"], "gemini-embedding-001");
        assert_eq!(forwarded["data"][0]["object"], "embedding");
        assert_eq!(forwarded["data"][0]["index"], 0);
    }

    // 原生 embedding handler（RelayModeGemini + embedContent）。
    #[test]
    fn native_embedding_handler_dispatch() {
        let payload = br#"{"embedding":{"values":[0.1,0.2]}}"#;
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(payload.to_vec()),
        };
        let mut info = gemini_info("text-embedding-004");
        info.relay_mode = relay_constant::RELAY_MODE_GEMINI;
        info.request_url_path = "/v1beta/models/text-embedding-004:embedContent".to_owned();
        let mut sink = StubSink::default();
        let adaptor = GeminiAdaptor::new();
        let outcome = adaptor.do_response(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_none());
        // 原样透传。
        let (_, _, body) = &sink.bytes[0];
        let forwarded: Value = serde_json::from_slice(body).expect("json");
        assert!(forwarded.get("embedding").is_some());
    }

    // 原生文本生成透传（RelayModeGemini 非流式）。
    #[test]
    fn native_text_generation_passthrough() {
        let payload = br#"{"candidates":[{"content":{"parts":[{"text":"Hello"}],"role":"model"},"finishReason":"STOP","index":0}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":5,"totalTokenCount":15}}"#;
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(payload.to_vec()),
        };
        let mut info = gemini_info("gemini-2.5-flash");
        info.relay_mode = relay_constant::RELAY_MODE_GEMINI;
        info.request_url_path = "/v1beta/models/gemini-2.5-flash:generateContent".to_owned();
        let mut sink = StubSink::default();
        let adaptor = GeminiAdaptor::new();
        let outcome = adaptor.do_response(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_none());
        assert_eq!(outcome.usage.total_tokens, 15);
        let (_, _, body) = &sink.bytes[0];
        let forwarded: Value = serde_json::from_slice(body).expect("json");
        assert!(forwarded.get("candidates").is_some());
    }

    // 流式（openai 格式）：gemini 流 → openai chunk + 工具 index 映射 + stop。
    #[test]
    fn chat_stream_handler_openai_format() {
        let chunks = concat!(
            "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"Hel\"}],\"role\":\"model\"},\"index\":0}]}\n\n",
            "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"lo\"}],\"role\":\"model\"},\"finishReason\":\"STOP\",\"index\":0}]}\n\n",
        );
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(chunks.as_bytes().to_vec()),
        };
        let mut info = gemini_info("gemini-2.5-flash");
        info.relay_format = relay_format::OPENAI.to_owned();
        info.set_estimate_prompt_tokens(3);
        let mut sink = StubSink::default();
        let outcome = gemini_chat_stream_handler(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_none());
        // 首 chunk：空 delta（role assistant）→ 转换 chunk 带 content。
        assert!(
            sink.sse_lines
                .iter()
                .any(|line| line.contains("\"content\":\"Hel\""))
        );
        assert!(
            sink.sse_lines
                .iter()
                .any(|line| line.contains("\"content\":\"lo\""))
        );
        // STOP → 终态 stop chunk。
        assert!(
            sink.sse_lines
                .iter()
                .any(|line| line.contains("\"finish_reason\":\"stop\""))
        );
        // 终态 usage chunk + [DONE]。
        assert!(
            sink.sse_lines
                .iter()
                .any(|line| line.contains("\"choices\":[]") && line.contains("\"usage\""))
        );
        assert!(
            sink.sse_lines
                .iter()
                .any(|line| line.contains("data: [DONE]"))
        );
    }

    // 流式（claude 格式）：STOP 时不发 stop chunk（Go 分支），终态 stop 带 usage。
    #[test]
    fn chat_stream_handler_claude_format_suppresses_stop_chunk() {
        let chunks = concat!(
            "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"hi\"}],\"role\":\"model\"},\"finishReason\":\"STOP\",\"index\":0}]}\n\n",
        );
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(chunks.as_bytes().to_vec()),
        };
        let mut info = gemini_info("gemini-2.5-flash");
        info.relay_format = relay_format::CLAUDE.to_owned();
        info.set_estimate_prompt_tokens(1);
        let mut sink = StubSink::default();
        let outcome = gemini_chat_stream_handler(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_none());
        // 无 [DONE]（claude 格式由上层转换收尾）。
        assert!(!sink.sse_lines.iter().any(|line| line.contains("[DONE]")));
    }

    // 流式 tool_calls 首块复制：首个空响应带 tool_calls 骨架（arguments 空）。
    #[test]
    fn chat_stream_handler_first_chunk_tool_skeleton() {
        let chunks = concat!(
            "data: {\"candidates\":[{\"content\":{\"parts\":[{\"functionCall\":{\"name\":\"get_weather\",\"args\":{\"city\":\"sf\"}}}],\"role\":\"model\"},\"index\":0}]}\n\n",
            "data: {\"candidates\":[{\"content\":{\"parts\":[],\"role\":\"model\"},\"finishReason\":\"STOP\",\"index\":0}]}\n\n",
        );
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(chunks.as_bytes().to_vec()),
        };
        let mut info = gemini_info("gemini-2.5-flash");
        info.relay_format = relay_format::OPENAI.to_owned();
        info.set_estimate_prompt_tokens(1);
        let mut sink = StubSink::default();
        let outcome = gemini_chat_stream_handler(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_none());
        // 首 chunk（空响应）复制 tool_calls（arguments 置空）。
        assert!(
            sink.sse_lines
                .iter()
                .any(|line| line.contains("\"tool_calls\"") && line.contains("\"arguments\":\"\""))
        );
        // finish_reason = tool_calls。
        assert!(
            sink.sse_lines
                .iter()
                .any(|line| line.contains("\"finish_reason\":\"tool_calls\""))
        );
    }

    // 零 completion patch：metadata prompt-only + 有文本 → 本地补 completion。
    #[test]
    fn usage_zero_completion_patch() {
        let payload = br#"{"candidates":[{"content":{"parts":[{"text":"some output text"}],"role":"model"},"index":0}],"usageMetadata":{"promptTokenCount":10,"totalTokenCount":10}}"#;
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(payload.to_vec()),
        };
        let mut info = gemini_info("gemini-2.5-flash");
        info.relay_format = relay_format::OPENAI.to_owned();
        info.set_estimate_prompt_tokens(10);
        let mut sink = StubSink::default();
        let outcome = gemini_chat_handler(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_none());
        assert!(
            outcome.usage.completion_tokens > 0,
            "zero completion patched"
        );
        assert_eq!(
            outcome.usage.total_tokens,
            outcome.usage.prompt_tokens + outcome.usage.completion_tokens
        );
        // patch 后 billing usage 重估（estimated）。
        assert_eq!(
            outcome.usage.billing_usage.as_ref().expect("billing")["estimated"],
            json!(true)
        );
    }

    // google search grounding → 上下文标记。
    #[test]
    fn google_search_call_marking() {
        let payload = br#"{"candidates":[{"content":{"parts":[{"text":"result"}],"role":"model"},"groundingMetadata":{"webSearchQueries":["rust idioms"]},"finishReason":"STOP","index":0}],"usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":1,"totalTokenCount":2}}"#;
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(payload.to_vec()),
        };
        let mut info = gemini_info("gemini-2.5-flash");
        info.relay_format = relay_format::OPENAI.to_owned();
        let mut sink = StubSink::default();
        let outcome = gemini_chat_handler(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_none());
        assert!(
            sink.context
                .iter()
                .any(|(key, value)| key == "gemini_google_search_call" && value == &json!(true))
        );
    }

    // DoResponse 分派：imagen / embedding / stream / native。
    #[test]
    fn do_response_dispatch() {
        let adaptor = GeminiAdaptor::new();
        // imagen
        let mut info = gemini_info("imagen-4.0-generate-001");
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(
                br#"{"predictions":[{"bytesBase64Encoded":"QQ=="}]}"#.to_vec(),
            ),
        };
        let mut sink = StubSink::default();
        let outcome = adaptor.do_response(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_none());
        assert_eq!(outcome.usage.prompt_tokens, 258);

        // 非流 chat（openai 格式）
        let mut info = gemini_info("gemini-2.5-flash");
        info.relay_format = relay_format::OPENAI.to_owned();
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(br#"{"candidates":[{"content":{"parts":[{"text":"x"}],"role":"model"},"finishReason":"STOP","index":0}],"usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":1,"totalTokenCount":2}}"#.to_vec()),
        };
        let mut sink = StubSink::default();
        let outcome = adaptor.do_response(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_none());
        assert_eq!(outcome.usage.total_tokens, 2);
    }

    // model list / channel name。
    #[test]
    fn model_list_and_channel_name() {
        let adaptor = GeminiAdaptor::new();
        assert_eq!(adaptor.get_channel_name(), "google gemini");
        let models = adaptor.get_model_list();
        assert!(models.contains(&"gemini-2.5-flash".to_owned()));
        assert!(models.contains(&"imagen-4.0-generate-001".to_owned()));
        assert!(models.contains(&"gemini-embedding-001".to_owned()));
    }

    // SafetySettingList 常量。
    #[test]
    fn safety_settings() {
        assert!(SAFETY_SETTING_LIST.contains(&"HARM_CATEGORY_HARASSMENT"));
        assert_eq!(SAFETY_SETTING_LIST.len(), 4);
    }
}
