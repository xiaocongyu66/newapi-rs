//! Go `internal/relay/channel/claude/` 的移植（adaptor.go / relay-claude.go /
//! constants.go）。
//!
//! 契约要点：
//! - URL：`{base}/v1/messages`；`IsClaudeBetaQuery` 或渠道
//!   `claude_beta_query` 设置时追加 `?beta=true`。
//! - Header：`x-api-key`、`anthropic-version`（客户端头优先，缺省
//!   `2023-06-01`）、`anthropic-beta`（客户端透传）+ Claude 设置表头合并。
//! - 流式：`message_start` 捕获 usage/model，`message_delta` 补洞 usage
//!   patch（pass-through 关闭时），refusal stop_reason 标记，tool_use 计费。
//! - 非流：usage → anthropic 语义 + BillingUsage；openai 格式输出经
//!   claude→openai 转换子集。
//!
//! 已知偏差：openai→claude 的**请求**转换（Go `relayconvert.ConvertRequest`）
//! 归转换切片 seam；本适配器原生 claude→openai **响应**/流事件转换子集已移植。

use crate::adaptor_common::convert_claude::{
    ClaudeResponse, ClaudeResponseInfo, build_message_delta_patch_usage,
    build_openai_style_usage_from_claude_usage, format_claude_response_info,
    patch_claude_message_delta_usage_data, response_claude_2_openai,
    stream_response_claude_2_openai,
};
use crate::adaptor_common::usage::{
    Usage, new_claude_messages_billing_usage, response_text_2_usage,
};

use crate::adaptor_common::{
    ClientSink, DoResponseOutcome, OutboundResponse, OutboundTransport, RequestContext, error_code,
    new_error, timestamp_now, with_claude_error,
};
use crate::relay_info::{AdaptorError, RelayInfo, build_in_call, relay_format};
use crate::relay_mode as relay_constant;
use serde_json::{Value, json};
use std::future::Future;
use std::pin::Pin;

// ---- 常量 ------------------------------------------------------------------

/// Go `claude.ModelList`（constants.go:3-43）。
pub const MODEL_LIST: &[&str] = &[
    "claude-3-sonnet-20240229",
    "claude-3-opus-20240229",
    "claude-3-haiku-20240307",
    "claude-3-5-haiku-20241022",
    "claude-haiku-4-5-20251001",
    "claude-3-5-sonnet-20240620",
    "claude-3-5-sonnet-20241022",
    "claude-3-7-sonnet-20250219",
    "claude-3-7-sonnet-20250219-thinking",
    "claude-sonnet-4-20250514",
    "claude-sonnet-4-20250514-thinking",
    "claude-opus-4-20250514",
    "claude-opus-4-20250514-thinking",
    "claude-opus-4-1-20250805",
    "claude-opus-4-1-20250805-thinking",
    "claude-sonnet-4-5-20250929",
    "claude-sonnet-4-5-20250929-thinking",
    "claude-opus-4-5-20251101",
    "claude-opus-4-5-20251101-thinking",
    "claude-opus-4-6",
    "claude-opus-4-6-max",
    "claude-opus-4-6-high",
    "claude-opus-4-6-medium",
    "claude-opus-4-6-low",
    "claude-sonnet-4-6",
    "claude-opus-4-7",
    "claude-opus-4-7-max",
    "claude-opus-4-7-xhigh",
    "claude-opus-4-7-high",
    "claude-opus-4-7-medium",
    "claude-opus-4-7-low",
    "claude-opus-4-7-thinking",
    "claude-opus-4-8",
    "claude-opus-4-8-max",
    "claude-opus-4-8-xhigh",
    "claude-opus-4-8-high",
    "claude-opus-4-8-medium",
    "claude-opus-4-8-low",
    "claude-opus-4-8-thinking",
];

/// Go `claude.ChannelName`。
pub const CHANNEL_NAME: &str = "claude";

// ---- 适配器 ----------------------------------------------------------------

/// Go `claude.Adaptor`。
#[derive(Debug, Default)]
pub struct ClaudeAdaptor;

impl ClaudeAdaptor {
    pub fn new() -> Self {
        Self
    }
}

/// Go `shouldAppendClaudeBetaQuery`（adaptor.go:60-71）。
fn should_append_claude_beta_query(info: &RelayInfo) -> bool {
    if info.is_claude_beta_query {
        return true;
    }
    info.claude_beta_query_channel_setting()
}

/// Go `CommonClaudeHeadersOperation`（adaptor.go:73-80）：客户端
/// anthropic-beta 透传 + Claude 设置表头合并。
fn common_claude_headers_operation(
    info: &RelayInfo,
    client_headers: &[(String, String)],
    headers: &mut Vec<(String, String)>,
) {
    let anthropic_beta = crate::adaptor_common::header_value(client_headers, "anthropic-beta");
    if !anthropic_beta.is_empty() {
        set_header(headers, "anthropic-beta", anthropic_beta);
    }
    // Go: model_setting.GetClaudeSettings().WriteHeaders(info.OriginModelName, req)。
    let origin_model = &info.origin_model_name;
    if let Some(model_headers) = info
        .global_model_settings
        .claude_headers_settings
        .get(origin_model.as_str())
    {
        for (header_key, header_values) in model_headers {
            // 归并去重：现有头值 + 配置值，逗号连接。
            let mut merged: Vec<String> = Vec::new();
            let mut seen: std::collections::HashSet<String> = Default::default();
            let push_value =
                |value: &str,
                 merged: &mut Vec<String>,
                 seen: &mut std::collections::HashSet<String>| {
                    for item in value.split(',') {
                        let item = item.trim();
                        if item.is_empty() || seen.contains(item) {
                            continue;
                        }
                        seen.insert(item.to_owned());
                        merged.push(item.to_owned());
                    }
                };
            for (_, existing) in headers
                .iter()
                .filter(|(key, _)| key.eq_ignore_ascii_case(header_key))
            {
                push_value(existing, &mut merged, &mut seen);
            }
            for value in header_values {
                push_value(value, &mut merged, &mut seen);
            }
            if merged.is_empty() {
                continue;
            }
            set_header(headers, header_key, &merged.join(","));
        }
    }
}

fn set_header(headers: &mut Vec<(String, String)>, key: &str, value: &str) {
    if let Some(existing) = headers
        .iter_mut()
        .find(|(existing_key, _)| existing_key.eq_ignore_ascii_case(key))
    {
        existing.1 = value.to_owned();
    } else {
        headers.push((key.to_owned(), value.to_owned()));
    }
}

/// Go `maybeMarkClaudeRefusal`（relay-claude.go:21-28）。
fn maybe_mark_claude_refusal(sink: &mut dyn ClientSink, stop_reason: &str) {
    if stop_reason.eq_ignore_ascii_case("refusal") {
        sink.set_context("admin_reject_reason", json!("claude_stop_reason=refusal"));
    }
}

/// Go `countClaudeStreamBillableTools`（relay-claude.go:131-146）。
fn count_claude_stream_billable_tools(
    info: &mut RelayInfo,
    sink: &mut dyn ClientSink,
    claude_response: &ClaudeResponse,
) {
    if claude_response.kind == "content_block_start"
        && let Some(block) = &claude_response.content_block
        && block.kind == "tool_use"
    {
        info.count_billable_tool_call(build_in_call::TOOL_USE, &block.name);
    }
    if claude_response.kind == "message_delta"
        && let Some(usage) = &claude_response.usage
        && let Some(server_tool_use) = &usage.server_tool_use
        && server_tool_use.web_search_requests > 0
    {
        sink.set_context(
            "claude_web_search_requests",
            json!(server_tool_use.web_search_requests),
        );
    }
}

/// Go `shouldSkipClaudeMessageDeltaUsagePatch`（relay-claude.go:63-71）。
fn should_skip_claude_message_delta_usage_patch(info: &RelayInfo) -> bool {
    if info.global_model_settings.pass_through_request_enabled {
        return true;
    }
    info.pass_through_body_enabled()
}

/// Go `HandleStreamResponseData`（relay-claude.go:81-129）。
pub fn handle_stream_response_data(
    info: &mut RelayInfo,
    sink: &mut dyn ClientSink,
    claude_info: &mut ClaudeResponseInfo,
    data: &str,
) -> Result<(), AdaptorError> {
    let mut claude_response: ClaudeResponse = serde_json::from_str(data)
        .map_err(|err| new_error(err.to_string(), error_code::BAD_RESPONSE_BODY))?;
    if let Some(claude_error) = claude_response.get_claude_error() {
        return Err(with_claude_error(claude_error, 500));
    }
    if let Some(stop_reason) = &claude_response.stop_reason {
        maybe_mark_claude_refusal(sink, stop_reason);
    }
    if let Some(delta) = &claude_response.delta
        && let Some(stop_reason) = &delta.stop_reason
    {
        maybe_mark_claude_refusal(sink, stop_reason);
    }
    if info.relay_format == relay_format::CLAUDE {
        format_claude_response_info(&claude_response, None, claude_info);

        // Go: data = patchClaudeMessageDeltaUsageData(...) —— 补洞后的帧载荷。
        let mut forward = data.to_owned();
        if claude_response.kind == "message_start" {
            // message_start, 获取usage
            if let Some(message) = &claude_response.message {
                info.set_upstream_model_name(message.model.clone());
            }
        } else if claude_response.kind == "message_delta" {
            // 确保 message_delta 的 usage 包含完整的 input_tokens 和 cache 相关
            // 字段（AWS Bedrock 等上游缺字段）。
            if !should_skip_claude_message_delta_usage_patch(info) {
                let patch =
                    build_message_delta_patch_usage(Some(&claude_response), Some(claude_info));
                forward = patch_claude_message_delta_usage_data(data, Some(&patch));
                claude_response = serde_json::from_str(&forward).unwrap_or(claude_response);
            }
        }
        count_claude_stream_billable_tools(info, sink, &claude_response);
        // Go: helper.ClaudeChunkData(c, claudeResponse, data)。
        sink.claude_chunk_data(&claude_response.kind, &forward);
    } else if info.relay_format == relay_format::OPENAI {
        let response = stream_response_claude_2_openai(&claude_response);

        let Some(mut response) = response else {
            return Ok(()); // Go: !FormatClaudeResponseInfo 时跳过；nil 响应事件忽略
        };
        if !format_claude_response_info(&claude_response, Some(&mut response), claude_info) {
            return Ok(());
        }

        count_claude_stream_billable_tools(info, sink, &claude_response);

        // Go: logger.LogError on failure —— sink 错误面为 Result，吞掉与 Go 一致。
        let _ = sink.object_data(&serde_json::to_value(&response).unwrap_or_default());
    }
    Ok(())
}

/// Go `HandleStreamFinalResponse`（relay-claude.go:148-187）。
pub fn handle_stream_final_response(
    info: &mut RelayInfo,
    sink: &mut dyn ClientSink,
    claude_info: &mut ClaudeResponseInfo,
) {
    if claude_info.usage.completion_tokens == 0 || !claude_info.done {
        // 只补缺失字段，不整份覆盖——保留 message_start 已拿到的 cache 字段。
        let fallback = response_text_2_usage(
            sink,
            &claude_info.response_text,
            &info.upstream_model_name(),
            info.get_estimate_prompt_tokens(),
        );
        if claude_info.usage.completion_tokens == 0
            || (!claude_info.done
                && fallback.completion_tokens > claude_info.usage.completion_tokens)
        {
            claude_info.usage.completion_tokens = fallback.completion_tokens;
        }
        if claude_info.usage.prompt_tokens == 0 {
            claude_info.usage.prompt_tokens = fallback.prompt_tokens;
        }
        claude_info.usage.total_tokens =
            claude_info.usage.prompt_tokens + claude_info.usage.completion_tokens;
    }
    claude_info.usage.usage_semantic = "anthropic".to_owned();
    if claude_info.usage.billing_usage.is_none() {
        claude_info.usage.billing_usage = new_claude_messages_billing_usage(Some(
            &build_message_delta_patch_usage(None, Some(claude_info)),
        ));
    }

    if info.relay_format == relay_format::CLAUDE {
        // Go: 空分支。
    } else if info.relay_format == relay_format::OPENAI {
        if info.should_include_usage {
            let openai_usage = build_openai_style_usage_from_claude_usage(&claude_info.usage);
            let response = json!({
                "id": claude_info.response_id,
                "object": "chat.completion.chunk",
                "created": claude_info.created,
                "model": claude_info.model,
                "choices": [],
                "usage": openai_usage,
            });
            let _ = sink.object_data(&response);
        }
        sink.done();
    }
}

/// Go `ClaudeStreamHandler`（relay-claude.go:189-210）。
pub fn claude_stream_handler(
    info: &mut RelayInfo,
    response: &mut OutboundResponse,
    sink: &mut dyn ClientSink,
) -> DoResponseOutcome {
    let mut claude_info = ClaudeResponseInfo {
        response_id: format!("chatcmpl-{}", info.request_id),
        created: timestamp_now(),
        model: info.upstream_model_name(),
        response_text: String::new(),
        usage: Usage::default(),
        done: false,
    };
    let (payloads, _end_reason) = crate::adaptor_common::scan_sse_response(response);
    for data in payloads {
        if let Err(err) = handle_stream_response_data(info, sink, &mut claude_info, &data) {
            return DoResponseOutcome::error(Usage::default(), err);
        }
    }

    handle_stream_final_response(info, sink, &mut claude_info);
    DoResponseOutcome::ok(claude_info.usage)
}

/// Go `HandleClaudeResponseData`（relay-claude.go:212-261）。
pub fn handle_claude_response_data(
    info: &mut RelayInfo,
    sink: &mut dyn ClientSink,
    claude_info: &mut ClaudeResponseInfo,
    data: &[u8],
) -> Result<Vec<u8>, AdaptorError> {
    let claude_response: ClaudeResponse = serde_json::from_slice(data)
        .map_err(|err| new_error(err.to_string(), error_code::BAD_RESPONSE_BODY))?;
    if let Some(claude_error) = claude_response.get_claude_error() {
        return Err(with_claude_error(claude_error, 500));
    }
    if let Some(stop_reason) = &claude_response.stop_reason {
        maybe_mark_claude_refusal(sink, stop_reason);
    }
    if let Some(usage) = &claude_response.usage {
        claude_info.usage.prompt_tokens = usage.input_tokens;
        claude_info.usage.completion_tokens = usage.output_tokens;
        claude_info.usage.total_tokens = usage.input_tokens + usage.output_tokens;
        claude_info.usage.usage_semantic = "anthropic".to_owned();
        claude_info.usage.billing_usage = new_claude_messages_billing_usage(Some(usage));
        claude_info.usage.prompt_tokens_details.cached_tokens = usage.cache_read_input_tokens;
        claude_info
            .usage
            .prompt_tokens_details
            .cached_creation_tokens = usage.cache_creation_input_tokens;
        claude_info.usage.claude_cache_creation_5m_tokens = usage.get_cache_creation_5m_tokens();
        claude_info.usage.claude_cache_creation_1h_tokens = usage.get_cache_creation_1h_tokens();
    }
    let response_data: Vec<u8> = match info.relay_format.as_str() {
        f if f == relay_format::OPENAI => {
            let openai_response = response_claude_2_openai(
                &claude_response,
                crate::adaptor_common::random_uuid,
                timestamp_now(),
            );
            let mut openai_response = to_text_response_value(openai_response);
            openai_response["usage"] = serde_json::to_value(
                build_openai_style_usage_from_claude_usage(&claude_info.usage),
            )
            .unwrap_or_default();
            serde_json::to_vec(&openai_response)
                .map_err(|err| new_error(err.to_string(), error_code::BAD_RESPONSE_BODY))?
        }
        f if f == relay_format::CLAUDE => data.to_vec(),
        _ => Vec::new(),
    };

    if let Some(usage) = &claude_response.usage
        && let Some(server_tool_use) = &usage.server_tool_use
        && server_tool_use.web_search_requests > 0
    {
        sink.set_context(
            "claude_web_search_requests",
            json!(server_tool_use.web_search_requests),
        );
    }

    for block in &claude_response.content {
        if block.kind == "tool_use" {
            info.count_billable_tool_call(build_in_call::TOOL_USE, &block.name);
        }
    }
    Ok(response_data)
}

/// `ResponseClaude2OpenAI` 输出 → wire Value（OpenAiTextResponse 形状）。
fn to_text_response_value(response: serde_json::Value) -> Value {
    response
}

/// Go `ClaudeHandler`（relay-claude.go:263-283）。
pub fn claude_handler(
    info: &mut RelayInfo,
    response: &mut OutboundResponse,
    sink: &mut dyn ClientSink,
) -> DoResponseOutcome {
    let mut claude_info = ClaudeResponseInfo {
        response_id: format!("chatcmpl-{}", info.request_id),
        created: timestamp_now(),
        model: info.upstream_model_name(),
        response_text: String::new(),
        usage: Usage::default(),
        done: false,
    };
    let response_body = match response.read_full_body() {
        Ok(body) => body,
        Err(err) => return DoResponseOutcome::error(Usage::default(), err),
    };
    let response_data =
        match handle_claude_response_data(info, sink, &mut claude_info, &response_body) {
            Ok(data) => data,
            Err(err) => return DoResponseOutcome::error(Usage::default(), err),
        };
    sink.send_bytes(response.status, "application/json", &response_data);
    DoResponseOutcome::ok(claude_info.usage)
}

impl crate::adaptor::Adaptor for ClaudeAdaptor {
    /// Go `Init`（adaptor.go:41-42）：空实现。
    fn init(&mut self, _info: &mut RelayInfo) {}

    /// Go `GetRequestURL`（adaptor.go:44-58）。
    fn get_request_url(&self, info: &mut RelayInfo) -> Result<String, String> {
        let request_url = format!("{}/v1/messages", info.channel_base_url());
        if !should_append_claude_beta_query(info) {
            return Ok(request_url);
        }
        let mut parsed = url::Url::parse(&request_url).map_err(|err| err.to_string())?;
        parsed.query_pairs_mut().append_pair("beta", "true");
        Ok(parsed.to_string())
    }

    /// Go `SetupRequestHeader`（adaptor.go:82-92）。
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
        headers.push(("x-api-key".to_owned(), info.api_key()));
        let mut anthropic_version =
            crate::adaptor_common::header_value(client_headers, "anthropic-version").to_owned();
        if anthropic_version.is_empty() {
            anthropic_version = "2023-06-01".to_owned();
        }
        headers.push(("anthropic-version".to_owned(), anthropic_version));
        common_claude_headers_operation(info, client_headers, &mut headers);
        Ok(headers)
    }

    /// Go `ConvertOpenAIRequest`（adaptor.go:94-103）。
    fn convert_openai_request(
        &self,
        _info: &mut RelayInfo,
        _request: &Value,
    ) -> Result<Value, String> {
        // Go: relayconvert.ConvertRequest(..., RelayFormatClaude, ...)。
        Err("relayconvert: request conversion registry not ported yet (separate slice)".to_owned())
    }

    /// Go `ConvertClaudeRequest`（adaptor.go:27-29）：恒等。
    fn convert_claude_request(
        &self,
        _info: &mut RelayInfo,
        request: &Value,
    ) -> Result<Value, String> {
        Ok(request.clone())
    }

    /// Go `ConvertGeminiRequest`（adaptor.go:22-25）。
    fn convert_gemini_request(
        &self,
        _info: &mut RelayInfo,
        _request: &Value,
    ) -> Result<Value, String> {
        Err("not implemented".to_owned())
    }

    /// Go `ConvertRerankRequest`（adaptor.go:105-107）。
    fn convert_rerank_request(&self, _relay_mode: i32, _request: &Value) -> Result<Value, String> {
        Ok(Value::Null)
    }

    /// Go `ConvertEmbeddingRequest`（adaptor.go:109-112）。
    fn convert_embedding_request(
        &self,
        _info: &mut RelayInfo,
        _request: &Value,
    ) -> Result<Value, String> {
        Err("not implemented".to_owned())
    }

    /// Go `ConvertImageRequest`（adaptor.go:36-39）。
    fn convert_image_request(
        &self,
        _info: &mut RelayInfo,
        _request: &Value,
        _multipart: Option<&crate::adaptor_common::ParsedMultipartForm>,
    ) -> Result<crate::adaptor_common::ConvertedRequestBody, String> {
        Err("not implemented".to_owned())
    }

    /// Go `ConvertOpenAIResponsesRequest`（adaptor.go:114-117）。
    fn convert_openai_responses_request(
        &self,
        _info: &mut RelayInfo,
        _request: &Value,
    ) -> Result<Value, String> {
        Err("not implemented".to_owned())
    }

    /// Go `ConvertAudioRequest`（adaptor.go:31-34）。
    fn convert_audio_request(
        &self,
        _info: &mut RelayInfo,
        _request: &Value,
        _multipart: Option<&crate::adaptor_common::ParsedMultipartForm>,
    ) -> Result<crate::adaptor_common::ConvertedRequestBody, String> {
        Err("not implemented".to_owned())
    }

    /// Go `DoRequest`（adaptor.go:119-121）。
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

    /// Go `DoResponse`（adaptor.go:123-130）。
    fn do_response(
        &self,
        info: &mut RelayInfo,
        response: &mut OutboundResponse,
        sink: &mut dyn ClientSink,
    ) -> DoResponseOutcome {
        info.final_request_relay_format = relay_format::CLAUDE.to_owned();
        if info.is_stream {
            claude_stream_handler(info, response, sink)
        } else {
            claude_handler(info, response, sink)
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

/// Go `UsageSemantic` 常量复述（claude 侧恒 anthropic）。
pub const USAGE_SEMANTIC_ANTHROPIC: &str = "anthropic";

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
        json: Vec<(i32, Value)>,
        bytes: Vec<(i32, String, Vec<u8>)>,
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

    fn claude_info() -> RelayInfo {
        let mut info = RelayInfo {
            relay_format: relay_format::CLAUDE.to_owned(),
            ..RelayInfo::default()
        };
        info.init_channel_meta(crate::relay_info::ChannelMetaSnapshot {
            channel_type: crate::adaptor::channel_type::ANTHROPIC,
            api_type: crate::adaptor::api_type::ANTHROPIC,
            api_version: String::new(),
            upstream_model_name: "claude-3-5-sonnet-20241022".to_owned(),
            param_override: Value::Null,
            headers_override: Value::Null,
            channel_setting: Value::Null,
            channel_other_settings: Value::Null,
            pass_through_request_enabled: false,
        });
        info
    }

    // Go GetRequestURL：/v1/messages + beta query。
    #[test]
    fn get_request_url_messages() {
        let mut info = claude_info();
        info.channel_meta.as_mut().expect("meta").channel_base_url =
            "https://api.anthropic.com".to_owned();
        let adaptor = ClaudeAdaptor::new();
        assert_eq!(
            adaptor.get_request_url(&mut info).expect("url"),
            "https://api.anthropic.com/v1/messages"
        );
    }

    #[test]
    fn get_request_url_beta_query() {
        let mut info = claude_info();
        info.is_claude_beta_query = true;
        info.channel_meta.as_mut().expect("meta").channel_base_url =
            "https://api.anthropic.com".to_owned();
        let adaptor = ClaudeAdaptor::new();
        assert_eq!(
            adaptor.get_request_url(&mut info).expect("url"),
            "https://api.anthropic.com/v1/messages?beta=true"
        );
    }

    // 渠道设置 claude_beta_query 触发 beta query。
    #[test]
    fn get_request_url_beta_query_from_channel_setting() {
        let mut info = claude_info();
        info.channel_meta
            .as_mut()
            .expect("meta")
            .channel_other_settings = json!({"claude_beta_query": true});
        info.channel_meta.as_mut().expect("meta").channel_base_url =
            "https://api.anthropic.com".to_owned();
        let adaptor = ClaudeAdaptor::new();
        let url = adaptor.get_request_url(&mut info).expect("url");
        assert!(url.contains("beta=true"), "{url}");
    }

    // SetupRequestHeader：x-api-key / anthropic-version 缺省 / 客户端透传。
    #[test]
    fn setup_headers() {
        let mut info = claude_info();
        info.channel_meta.as_mut().expect("meta").api_key = "sk-ant".to_owned();
        let adaptor = ClaudeAdaptor::new();
        let headers = adaptor.setup_request_header(&info, &[]).expect("headers");
        assert!(headers.contains(&("x-api-key".to_owned(), "sk-ant".to_owned())));
        assert!(headers.contains(&("anthropic-version".to_owned(), "2023-06-01".to_owned())));

        // 客户端 anthropic-version / anthropic-beta 透传。
        let client = vec![
            ("anthropic-version".to_owned(), "2024-10-22".to_owned()),
            ("anthropic-beta".to_owned(), "prompt-caching".to_owned()),
        ];
        let headers = adaptor
            .setup_request_header(&info, &client)
            .expect("headers");
        assert!(headers.contains(&("anthropic-version".to_owned(), "2024-10-22".to_owned())));
        assert!(headers.contains(&("anthropic-beta".to_owned(), "prompt-caching".to_owned())));
    }

    // Claude 设置表头合并（model_setting WriteHeaders 语义：合并去重逗号拼接）。
    #[test]
    fn setup_headers_settings_merge() {
        let mut info = claude_info();
        info.origin_model_name = "claude-sonnet-4-5".to_owned();
        info.channel_meta.as_mut().expect("meta").api_key = "sk".to_owned();
        info.global_model_settings.claude_headers_settings.insert(
            "claude-sonnet-4-5".to_owned(),
            vec![(
                "anthropic-beta".to_owned(),
                vec!["interleaved-thinking".to_owned()],
            )],
        );
        let adaptor = ClaudeAdaptor::new();
        let client = vec![("anthropic-beta".to_owned(), "prompt-caching".to_owned())];
        let headers = adaptor
            .setup_request_header(&info, &client)
            .expect("headers");
        let beta = headers
            .iter()
            .find(|(key, _)| key == "anthropic-beta")
            .map(|(_, value)| value.clone())
            .expect("beta header");
        assert_eq!(beta, "prompt-caching,interleaved-thinking");
    }

    // DoRequest：URL + headers + body 经 transport。
    #[test]
    fn do_request_contract() {
        let mut info = claude_info();
        info.channel_meta.as_mut().expect("meta").channel_base_url =
            "https://api.anthropic.com".to_owned();
        info.channel_meta.as_mut().expect("meta").api_key = "sk-ant".to_owned();
        let transport = StubTransport::new();
        let adaptor = ClaudeAdaptor::new();
        let client_headers = [("Content-Type".to_owned(), "application/json".to_owned())];
        let context = RequestContext {
            client_headers: &client_headers,
            method: "POST",
        };
        // 阻塞轮询器（std::task::Wake 安全 Waker）。
        let future = adaptor.do_request(&mut info, &context, b"{}".as_slice(), &transport);
        let response = {
            use std::task::{Context as TaskContext, Poll, Waker};
            let mut pinned = std::pin::pin!(future);
            let waker = Waker::noop();
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
        assert_eq!(captured[0].url, "https://api.anthropic.com/v1/messages");
        assert!(
            captured[0]
                .headers
                .contains(&("x-api-key".to_owned(), "sk-ant".to_owned()))
        );
    }

    // 非流：usage 捕获（input/output/cache/5m1h）+ BillingUsage + tool_use 计费
    // + claude 格式透传。
    #[test]
    fn claude_handler_captures_usage_passthrough() {
        let payload = br#"{"id":"msg_1","type":"message","role":"assistant","model":"claude-3-5-sonnet-20241022","stop_reason":"end_turn","content":[{"type":"text","text":"hi"}],"usage":{"input_tokens":25,"output_tokens":7,"cache_read_input_tokens":5,"cache_creation_input_tokens":3}}"#;
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(payload.to_vec()),
        };
        let mut info = claude_info();
        let mut sink = StubSink::default();
        let outcome = claude_handler(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_none());
        assert_eq!(outcome.usage.prompt_tokens, 25);
        assert_eq!(outcome.usage.completion_tokens, 7);
        assert_eq!(outcome.usage.total_tokens, 32);
        assert_eq!(outcome.usage.usage_semantic, "anthropic");
        assert_eq!(outcome.usage.prompt_tokens_details.cached_tokens, 5);
        assert_eq!(
            outcome.usage.prompt_tokens_details.cached_creation_tokens,
            3
        );
        assert!(outcome.usage.billing_usage.is_some());
        // claude 格式 → 原始字节透传。
        let (_, _, body) = &sink.bytes[0];
        assert!(String::from_utf8_lossy(body).contains("\"msg_1\""));
    }

    // 非流 openai 格式：claude → openai 转换（id/object/finish_reason/tool_use）。
    #[test]
    fn claude_handler_openai_format_conversion() {
        let payload = br#"{"id":"msg_2","type":"message","role":"assistant","model":"claude-3-5-sonnet-20241022","stop_reason":"tool_use","content":[{"type":"text","text":"thinking about it"},{"type":"tool_use","id":"toolu_1","name":"get_weather","input":{"city":"sf"}}],"usage":{"input_tokens":10,"output_tokens":4}}"#;
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(payload.to_vec()),
        };
        let mut info = claude_info();
        info.relay_format = relay_format::OPENAI.to_owned();
        info.should_include_usage = true;
        let mut sink = StubSink::default();
        let outcome = claude_handler(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_none());
        let (_, _, body) = &sink.bytes[0];
        let forwarded: Value = serde_json::from_slice(body).expect("json");
        assert_eq!(forwarded["object"], "chat.completion");
        assert_eq!(forwarded["choices"][0]["finish_reason"], "tool_calls");
        assert_eq!(
            forwarded["choices"][0]["message"]["content"],
            "thinking about it"
        );
        assert_eq!(
            forwarded["choices"][0]["message"]["tool_calls"][0]["id"],
            "toolu_1"
        );
        // openai 语义 usage：prompt 并入 cache 读/写。
        assert_eq!(forwarded["usage"]["usage_semantic"], "openai");
        assert_eq!(forwarded["usage"]["prompt_tokens"], 14); // 10 + 0 + 0 (无 cache)
        // tool_use 计费统计。
        assert!(
            info.billable_tool_calls
                .iter()
                .any(|call| call.kind == build_in_call::TOOL_USE && call.name == "get_weather")
        );
    }

    // 上游 claude 错误体折叠。
    #[test]
    fn claude_handler_folds_upstream_error() {
        let payload =
            br#"{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}"#;
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(payload.to_vec()),
        };
        let mut info = claude_info();
        let mut sink = StubSink::default();
        let outcome = claude_handler(&mut info, &mut response, &mut sink);
        let err = outcome.error.expect("error");
        assert_eq!(err.code, "overloaded_error");
        assert_eq!(err.error_type, "claude_error");
    }

    // refusal stop_reason → admin_reject_reason。
    #[test]
    fn claude_handler_marks_refusal() {
        let payload = br#"{"id":"msg_3","type":"message","role":"assistant","model":"claude-3-5-sonnet-20241022","stop_reason":"refusal","content":[],"usage":{"input_tokens":1,"output_tokens":1}}"#;
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(payload.to_vec()),
        };
        let mut info = claude_info();
        let mut sink = StubSink::default();
        let outcome = claude_handler(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_none());
        assert!(
            sink.context
                .iter()
                .any(|(key, value)| key == "admin_reject_reason"
                    && value == &json!("claude_stop_reason=refusal"))
        );
    }

    // 流式（claude 格式）：message_start → usage 捕获 + model 更新；
    // message_delta → usage 补洞 patch；转发帧保留 event: 类型行。
    #[test]
    fn claude_stream_handler_patch_and_passthrough() {
        let chunks = concat!(
            "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"model\":\"claude-sonnet-4-5\",\"usage\":{\"input_tokens\":25,\"output_tokens\":1}}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\n\n",
            "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":53}}\n\n",
            "data: {\"type\":\"message_stop\"}\n\n",
        );
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(chunks.as_bytes().to_vec()),
        };
        let mut info = claude_info();
        let mut sink = StubSink::default();
        let outcome = claude_stream_handler(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_none());
        assert_eq!(outcome.usage.prompt_tokens, 25);
        assert_eq!(outcome.usage.completion_tokens, 53);
        assert_eq!(outcome.usage.total_tokens, 25 + 53);
        // 上游 model 更新。
        assert_eq!(info.upstream_model_name(), "claude-sonnet-4-5");
        // 补洞：message_delta 帧带 input_tokens=25（上游缺失）。
        assert!(
            sink.sse_lines
                .iter()
                .any(|line| line.contains("\"input_tokens\":25") && line.contains("message_delta"))
        );
        // event: 类型行保留。
        assert!(
            sink.sse_lines
                .iter()
                .any(|line| line.starts_with("event: message_start"))
        );
    }

    // 流式 pass-through 开启 → 不打补丁。
    #[test]
    fn claude_stream_handler_skips_patch_on_pass_through() {
        let chunks = concat!(
            "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"model\":\"m\",\"usage\":{\"input_tokens\":25}}}\n\n",
            "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":53}}\n\n",
        );
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(chunks.as_bytes().to_vec()),
        };
        let mut info = claude_info();
        info.channel_meta.as_mut().expect("meta").channel_setting =
            json!({"pass_through_body_enabled": true});
        let mut sink = StubSink::default();
        let outcome = claude_stream_handler(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_none());
        // 上游帧未被补洞（input_tokens 不被写入 message_delta 帧）。
        assert!(
            !sink
                .sse_lines
                .iter()
                .any(|line| line.contains("message_delta") && line.contains("\"input_tokens\":25"))
        );
    }

    // 流式 openai 格式：claude 事件 → openai chunk。
    #[test]
    fn claude_stream_handler_openai_format() {
        let chunks = concat!(
            "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"model\":\"claude-sonnet-4-5\"}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\n\n",
            "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":7}}\n\n",
        );
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(chunks.as_bytes().to_vec()),
        };
        let mut info = claude_info();
        info.relay_format = relay_format::OPENAI.to_owned();
        let mut sink = StubSink::default();
        let outcome = claude_stream_handler(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_none());
        // openai chunk 形态：object=chat.completion.chunk、delta.content。
        assert!(
            sink.sse_lines
                .iter()
                .any(|line| line.contains("\"object\":\"chat.completion.chunk\"")
                    && line.contains("\"content\":\"hello\""))
        );
        // 终止 [DONE]（openai 格式 HandleStreamFinalResponse）。
        assert!(
            sink.sse_lines
                .iter()
                .any(|line| line.contains("data: [DONE]"))
        );
    }

    // 流式 thinking_delta → reasoning_content。
    #[test]
    fn claude_stream_handler_thinking_to_reasoning() {
        let chunks = concat!(
            "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"model\":\"m\"}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"hmm\"}}\n\n",
        );
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(chunks.as_bytes().to_vec()),
        };
        let mut info = claude_info();
        info.relay_format = relay_format::OPENAI.to_owned();
        let mut sink = StubSink::default();
        let outcome = claude_stream_handler(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_none());
        assert!(
            sink.sse_lines
                .iter()
                .any(|line| line.contains("\"reasoning_content\":\"hmm\""))
        );
    }

    // 流式 openai 格式 + ShouldIncludeUsage → 终态 usage chunk。
    #[test]
    fn claude_stream_handler_final_usage_chunk() {
        let chunks = concat!(
            "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"model\":\"m\",\"usage\":{\"input_tokens\":11}}}\n\n",
            "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":5}}\n\n",
        );
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Full(chunks.as_bytes().to_vec()),
        };
        let mut info = claude_info();
        info.relay_format = relay_format::OPENAI.to_owned();
        info.should_include_usage = true;
        let mut sink = StubSink::default();
        let outcome = claude_stream_handler(&mut info, &mut response, &mut sink);
        assert!(outcome.error.is_none());
        // 终态 usage chunk（choices 空 + usage）。
        assert!(
            sink.sse_lines
                .iter()
                .any(|line| line.contains("\"choices\":[]") && line.contains("\"usage\""))
        );
    }

    // ConvertClaudeRequest 恒等；其他转换为 not implemented。
    #[test]
    fn convert_identity_and_not_implemented() {
        let mut info = claude_info();
        let adaptor = ClaudeAdaptor::new();
        let request = json!({"model": "claude-3-5-sonnet-20241022", "max_tokens": 100});
        let converted = adaptor
            .convert_claude_request(&mut info, &request)
            .expect("identity");
        assert_eq!(converted, request);
        assert!(adaptor.convert_openai_request(&mut info, &request).is_err());
        assert!(adaptor.convert_gemini_request(&mut info, &request).is_err());
        assert!(
            adaptor
                .convert_embedding_request(&mut info, &request)
                .is_err()
        );
        assert!(
            adaptor
                .convert_audio_request(&mut info, &request, None)
                .is_err()
        );
    }

    // model list / channel name。
    #[test]
    fn model_list_and_channel_name() {
        let adaptor = ClaudeAdaptor::new();
        assert_eq!(adaptor.get_channel_name(), "claude");
        let models = adaptor.get_model_list();
        assert!(models.contains(&"claude-3-5-sonnet-20241022".to_owned()));
        assert!(models.contains(&"claude-opus-4-8".to_owned()));
    }
}
