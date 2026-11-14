//! 三大核心 channel 适配器（openai / claude / gemini）外呼共享基建，后续
//! 45 个适配器按需复用。
//!
//! Go 对照：
//! - `internal/relay/common/normalize_relay_values.go:26` `GetFullRequestURL`
//! - `internal/relay/channel/api_request.go` `SetupApiRequestHeader` /
//!   `processHeaderOverride` / `DoApiRequest` / `DoFormRequest`
//! - `internal/relay/helper/write_sse_response.go` + `internal/gateway/write_sse.go`
//!   的客户端写出语义（`ClientSink` 端口）
//! - `relaykit/types/error.go` 错误折叠（`NewOpenAIError` / `WithOpenAIError` /
//!   `WithClaudeError`，错误码字符串逐字对齐）
//!
//! 外呼经 [`OutboundTransport`] 注入（生产 reqwest、测试替身），客户端写出经
//! [`ClientSink`] 注入——纯 crate 不持有 HTTP/连接状态。

pub mod convert_claude;
pub mod convert_gemini;
pub mod usage;

pub use usage::{
    ClaudeCacheCreationUsage, ClaudeServerToolUse, ClaudeUsage, GeminiPromptTokensDetails,
    GeminiUsageMetadata, InputTokenDetails, OutputTokenDetails, Usage, estimate_token,
    estimate_token_by_model, response_text_2_usage, response_text_2_usage_pure, valid_usage,
};

use std::future::Future;
use std::pin::Pin;

use crate::relay_info::{AdaptorError, RelayInfo};

/// Go `constant.AzureDefaultAPIVersion`（common/init.go:190 环境缺省）。
pub const AZURE_DEFAULT_API_VERSION: &str = "2025-04-01-preview";
/// Go `constant.AzureNoRemoveDotTime`（constant/azure.go:5）：
/// 2025-05-10T00:00:00Z 的 Unix 秒。
pub const AZURE_NO_REMOVE_DOT_TIME: i64 = 1746835200;

/// Go `types.ErrorCode*` 字符串（error.go:80-92 等）。
pub mod error_code {
    pub const BAD_RESPONSE: &str = "bad_response";
    pub const BAD_RESPONSE_BODY: &str = "bad_response_body";
    pub const READ_RESPONSE_BODY_FAILED: &str = "read_response_body_failed";
    pub const EMPTY_RESPONSE: &str = "empty_response";
    pub const PROMPT_BLOCKED: &str = "prompt_blocked";
    pub const DO_REQUEST_FAILED: &str = "do_request_failed";
    pub const JSON_MARSHAL_FAILED: &str = "json_marshal_failed";
    pub const CHANNEL_HEADER_OVERRIDE_INVALID: &str = "channel:header_override_invalid";
}

/// Go `types.ErrorType*`（error.go:15-27 附近）。
pub mod error_type {
    pub const NEW_API: &str = "new_api_error";
    pub const OPENAI: &str = "openai_error";
    pub const CLAUDE: &str = "claude_error";
}

/// Go `NewOpenAIError(err, errorCode, statusCode)`：错误信封 type/code 取错误码。
pub fn new_openai_error(
    message: impl Into<String>,
    error_code: &str,
    status_code: i32,
) -> AdaptorError {
    AdaptorError {
        status_code,
        message: message.into(),
        code: error_code.to_owned(),
        error_type: error_type::OPENAI.to_owned(),
        skip_retry: false,
    }
}

/// Go `NewError(err, errorCode)`（500）。
pub fn new_error(message: impl Into<String>, error_code: &str) -> AdaptorError {
    new_openai_error(message, error_code, 500)
}

/// Go `NewError(err, errorCode, statusCode)` 变体（状态码显式）。
pub fn new_error_with_status(
    message: impl Into<String>,
    error_code: &str,
    status_code: i32,
) -> AdaptorError {
    new_openai_error(message, error_code, status_code)
}

/// Go `WithOpenAIError(openAIError, statusCode)`：上游错误透传折叠；type 缺省
/// `upstream_error`，code 缺省 `unknown_error`。
pub fn with_openai_error(
    openai_error: &convert_claude::OpenAiErrorBody,
    status_code: i32,
) -> AdaptorError {
    let code = match &openai_error.code {
        serde_json::Value::String(code) => code.clone(),
        serde_json::Value::Null => "unknown_error".to_owned(),
        other => other.to_string(),
    };
    let error_type = if openai_error.r#type.is_empty() {
        "upstream_error".to_owned()
    } else {
        openai_error.r#type.clone()
    };
    AdaptorError {
        status_code,
        message: openai_error.message.clone(),
        code,
        error_type,
        skip_retry: false,
    }
}

/// Go `WithClaudeError(claudeError, statusCode)`。
pub fn with_claude_error(
    claude_error: &convert_claude::ClaudeErrorBody,
    status_code: i32,
) -> AdaptorError {
    let error_type = if claude_error.r#type.is_empty() {
        "upstream_error".to_owned()
    } else {
        claude_error.r#type.clone()
    };
    AdaptorError {
        status_code,
        message: claude_error.message.clone(),
        code: error_type.clone(),
        error_type: error_type::CLAUDE.to_owned(),
        skip_retry: false,
    }
}

/// Go `types.ErrOptionWithSkipRetry` 语义。
pub fn with_skip_retry(mut err: AdaptorError) -> AdaptorError {
    err.skip_retry = true;
    err
}

/// Go `GetFullRequestURL`（normalize_relay_values.go:26-40）：Cloudflare
/// AI gateway 前缀按渠道裁剪 path 前缀。
pub fn get_full_request_url(base_url: &str, request_url: &str, channel_type: i32) -> String {
    let mut full_request_url = format!("{base_url}{request_url}");
    if base_url.starts_with("https://gateway.ai.cloudflare.com") {
        use crate::adaptor::channel_type as ct;
        match channel_type {
            ct::OPENAI => {
                full_request_url = format!(
                    "{base_url}{}",
                    request_url.strip_prefix("/v1").unwrap_or(request_url)
                );
            }
            ct::AZURE => {
                full_request_url = format!(
                    "{base_url}{}",
                    request_url
                        .strip_prefix("/openai/deployments")
                        .unwrap_or(request_url)
                );
            }
            _ => {}
        }
    }
    full_request_url
}

/// Go `SetupApiRequestHeader`（api_request.go:51-63）产出的基础 header 集合。
/// 音频（multipart）与 realtime（websocket）分支不设置。
pub fn setup_api_request_header(
    info: &RelayInfo,
    client_headers: &[(String, String)],
    is_audio_relay_mode: bool,
    is_realtime: bool,
) -> Vec<(String, String)> {
    if is_audio_relay_mode || is_realtime {
        return Vec::new();
    }
    let content_type = header_value(client_headers, "content-type");
    let accept = header_value(client_headers, "accept");
    let mut headers = Vec::new();
    if !content_type.is_empty() {
        headers.push(("Content-Type".to_owned(), content_type.to_owned()));
    }
    let accept = if accept.is_empty() && info.is_stream {
        "text/event-stream"
    } else {
        accept
    };
    if !accept.is_empty() {
        headers.push(("Accept".to_owned(), accept.to_owned()));
    }
    headers
}

/// 大小写不敏感的 header 读取。
pub fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> &'a str {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
        .unwrap_or("")
}

/// 大小写不敏感的 header 存在性检查。
pub fn has_header_ignore_case(headers: &[(String, String)], name: &str) -> bool {
    headers
        .iter()
        .any(|(key, _)| key.eq_ignore_ascii_case(name))
}

/// 请求上下文供 header override / 客户端写出使用的统一入口。
/// Go 侧是 `contract.Context`；这里折叠为只读快照 + sink。
pub struct RequestContext<'a> {
    /// Go `c.Header(...)` 的客户端请求头快照。
    pub client_headers: &'a [(String, String)],
    /// Go `c.Method()`。
    pub method: &'a str,
}

/// Go `processHeaderOverride`（api_request.go:196-305）：header 透传规则
/// （`*` / `re:` / `regex:`）+ 占位符（`{api_key}` / `{client_header:name}`）。
/// 已知偏差：session affinity 头（session_affinity.go）随会话亲和切片移植。
pub fn process_header_override(
    info: &RelayInfo,
    context: &RequestContext<'_>,
) -> Result<Vec<(String, String)>, AdaptorError> {
    let mut header_override: std::collections::BTreeMap<String, String> = Default::default();

    let override_source =
        crate::param_override::sanitize_header_override_map(&effective_header_override(info));
    let override_source = override_source.as_object().cloned().unwrap_or_default();

    let mut pass_all = false;
    let mut passthrough_regex: Vec<regex::Regex> = Vec::new();
    if !info.is_channel_test {
        for key in override_source.keys() {
            let key = key.trim().to_lowercase();
            if key.is_empty() {
                continue;
            }
            if key == "*" {
                pass_all = true;
                continue;
            }
            let pattern = if let Some(rest) = key.strip_prefix("re:") {
                rest.trim().to_owned()
            } else if let Some(rest) = key.strip_prefix("regex:") {
                rest.trim().to_owned()
            } else {
                continue;
            };
            if pattern.is_empty() {
                return Err(new_error(
                    format!("header passthrough regex pattern is empty: \"{key}\""),
                    error_code::CHANNEL_HEADER_OVERRIDE_INVALID,
                ));
            }
            let compiled = regex::Regex::new(&pattern).map_err(|err| {
                new_error(err.to_string(), error_code::CHANNEL_HEADER_OVERRIDE_INVALID)
            })?;
            passthrough_regex.push(compiled);
        }
    }

    if pass_all || !passthrough_regex.is_empty() {
        for (name, value) in context.client_headers {
            if should_skip_passthrough_header(name) {
                continue;
            }
            if !pass_all && !passthrough_regex.iter().any(|re| re.is_match(name)) {
                continue;
            }
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            header_override.insert(name.trim().to_lowercase(), value.to_owned());
        }
    }

    for (key, value) in &override_source {
        if is_header_passthrough_rule_key(key) {
            continue;
        }
        let key = key.trim().to_lowercase();
        if key.is_empty() {
            continue;
        }
        let Some(raw) = value.as_str() else {
            return Err(new_error(
                "header override value must be a string",
                error_code::CHANNEL_HEADER_OVERRIDE_INVALID,
            ));
        };
        if info.is_channel_test && raw.trim().starts_with("{client_header:") {
            continue;
        }
        let (resolved, include) =
            apply_header_override_placeholders(raw, context, &info_channel_api_key(info))?;
        if !include {
            continue;
        }
        header_override.insert(key, resolved);
    }
    Ok(header_override.into_iter().collect())
}

fn info_channel_api_key(info: &RelayInfo) -> String {
    info.channel_meta
        .as_ref()
        .map(|meta| meta.api_key.clone())
        .unwrap_or_default()
}

/// Go `GetEffectiveHeaderOverride`（apply_param_override.go:482-490）。
fn effective_header_override(info: &RelayInfo) -> serde_json::Value {
    if info.use_runtime_headers_override {
        let runtime: serde_json::Map<String, serde_json::Value> = info
            .runtime_headers_override
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
            .collect();
        return serde_json::Value::Object(runtime);
    }
    info.channel_meta
        .as_ref()
        .map(|meta| meta.headers_override.clone())
        .unwrap_or(serde_json::Value::Null)
}

/// Go `applyHeaderOverridePlaceholders`（api_request.go:150-184）。
fn apply_header_override_placeholders(
    template: &str,
    context: &RequestContext<'_>,
    api_key: &str,
) -> Result<(String, bool), AdaptorError> {
    const CLIENT_HEADER_PREFIX: &str = "{client_header:";
    let trimmed = template.trim();
    if let Some(after_prefix) = trimmed.strip_prefix(CLIENT_HEADER_PREFIX) {
        if !after_prefix.ends_with('}') {
            return Err(new_error(
                format!("client_header placeholder must be the full value: \"{template}\""),
                error_code::CHANNEL_HEADER_OVERRIDE_INVALID,
            ));
        }
        let name = after_prefix[..after_prefix.len() - 1].trim();
        if name.is_empty() {
            return Err(new_error(
                format!("client_header placeholder name is empty: \"{template}\""),
                error_code::CHANNEL_HEADER_OVERRIDE_INVALID,
            ));
        }
        let client_value = header_value(context.client_headers, name);
        if client_value.trim().is_empty() {
            return Ok((String::new(), false));
        }
        return Ok((client_value.to_owned(), true));
    }
    let mut template = template.to_owned();
    if template.contains("{api_key}") {
        template = template.replace("{api_key}", api_key);
    }
    if template.trim().is_empty() {
        return Ok((String::new(), false));
    }
    Ok((template, true))
}

/// Go `isHeaderPassthroughRuleKey`（api_request.go:126-136）：`*` / `re:` /
/// `regex:` 前缀（与 param_override.rs 的同名内部函数语义一致）。
fn is_header_passthrough_rule_key(key: &str) -> bool {
    let key = key.trim().to_lowercase();
    if key.is_empty() {
        return false;
    }
    key == "*" || key.starts_with("re:") || key.starts_with("regex:")
}

/// Go `passthroughSkipHeaderNamesLower`（api_request.go:73-100）。
fn should_skip_passthrough_header(name: &str) -> bool {
    const SKIP: &[&str] = &[
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "cookie",
        "host",
        "content-length",
        "accept-encoding",
        "authorization",
        "x-api-key",
        "x-goog-api-key",
        "sec-websocket-key",
        "sec-websocket-version",
        "sec-websocket-extensions",
    ];
    let name = name.trim().to_lowercase();
    if name.is_empty() {
        return true;
    }
    SKIP.contains(&name.as_str())
}

// ---- 外呼端口 ---------------------------------------------------------------

/// 完整外呼请求（Go `http.Request` 的适配器层子集）。
#[derive(Clone, Debug, Default)]
pub struct OutboundRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// 上游响应体：一次性全量，或逐块流（SSE / TTS 透传）。
pub enum OutboundResponseBody {
    Full(Vec<u8>),
    Stream(Box<dyn ByteStream + Send>),
}

impl std::fmt::Debug for OutboundResponseBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutboundResponseBody::Full(bytes) => write!(f, "Full({} bytes)", bytes.len()),
            OutboundResponseBody::Stream(_) => f.write_str("Stream(..)"),
        }
    }
}

/// 上游响应（Go `http.Response` 的适配器层子集）。
#[derive(Debug)]
pub struct OutboundResponse {
    pub status: i32,
    pub headers: Vec<(String, String)>,
    pub body: OutboundResponseBody,
}

impl OutboundResponse {
    pub fn header(&self, name: &str) -> &str {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
            .unwrap_or("")
    }

    /// 读取全量 body（流式响应会耗尽迭代器）。
    pub fn read_full_body(&mut self) -> Result<Vec<u8>, AdaptorError> {
        match &mut self.body {
            OutboundResponseBody::Full(bytes) => Ok(bytes.clone()),
            OutboundResponseBody::Stream(stream) => {
                let mut buffer = Vec::new();
                while let Some(chunk) = stream.next_chunk() {
                    match chunk {
                        Ok(bytes) => buffer.extend_from_slice(&bytes),
                        Err(err) => {
                            return Err(new_error(err, error_code::READ_RESPONSE_BODY_FAILED));
                        }
                    }
                }
                Ok(buffer)
            }
        }
    }
}

/// 上游响应体字节流端口（生产 reqwest bytes_stream，测试替身逐块喂入）。
pub trait ByteStream: Send {
    /// 下一个字节块；None 表示 EOF。
    fn next_chunk(&mut self) -> Option<Result<Vec<u8>, String>>;
}

/// 外呼传输端口（参照 `apps/server/src/external_pay_http.rs` 的注入形态：
/// 生产 reqwest 实现，测试替身捕获请求并回放响应）。
pub trait OutboundTransport: Send + Sync {
    fn execute<'a>(
        &'a self,
        request: OutboundRequest,
    ) -> Pin<Box<dyn Future<Output = Result<OutboundResponse, String>> + Send + 'a>>;
}

// ---- 客户端写出端口 ---------------------------------------------------------

/// Go `contract.Context` 的客户端写出面（gateway/write_sse.go 语义）。
pub trait ClientSink: Send {
    /// Go `helper.SetEventStreamHeaders`（幂等由实现方保证）。
    fn set_event_stream_headers(&mut self);
    /// Go `gateway.RenderSSE`：原样写一行 SSE（调用方自带 `data: ` 框架）。
    fn render_sse(&mut self, data: &str) -> Result<(), String>;
    /// Go `helper.StringData`：`data: {str}\n\n`（空串跳过）。
    fn string_data(&mut self, data: &str) -> Result<(), String> {
        if data.is_empty() {
            return Ok(());
        }
        self.render_sse(&format!("data: {data}\n\n"))
    }
    /// Go `helper.ObjectData`：marshal 后走 string_data。
    fn object_data(&mut self, value: &serde_json::Value) -> Result<(), String> {
        let json = serde_json::to_string(value).map_err(|err| err.to_string())?;
        self.string_data(&json)
    }
    /// Go `helper.Done`：`data: [DONE]\n\n`。
    fn done(&mut self) {
        let _ = self.string_data("[DONE]");
    }
    /// Go `gateway.ClaudeData`：`event: {type}\n` + `data: {json}`。
    fn claude_data(&mut self, event_type: &str, payload: &serde_json::Value) -> Result<(), String> {
        let json = serde_json::to_string(payload).map_err(|err| err.to_string())?;
        self.render_sse(&format!("event: {event_type}\n"))?;
        self.render_sse(&format!("data: {json}"))
    }
    /// Go `gateway.ClaudeChunkData`：`event: {type}\n` + `data: {data}\n`。
    fn claude_chunk_data(&mut self, event_type: &str, data: &str) {
        let _ = self.render_sse(&format!("event: {event_type}\n"));
        if !data.is_empty() {
            let _ = self.render_sse(&format!("data: {data}\n"));
        }
    }
    /// Go `gateway.ResponseChunkData`：`event: {type}\n` + `data: {data}`。
    fn response_chunk_data(&mut self, event_type: &str, data: &str) -> Result<(), String> {
        self.render_sse(&format!("event: {event_type}\n"))?;
        if !data.is_empty() {
            self.render_sse(&format!("data: {data}"))?;
        }
        Ok(())
    }
    /// Go `c.JSON(status, body)`。
    fn send_json(&mut self, status: i32, body: &serde_json::Value);
    /// Go `c.Data(status, contentType, body)` / `egress.IOCopyBytesGracefully`。
    fn send_bytes(&mut self, status: i32, content_type: &str, body: &[u8]);
    /// Go `c.SetHeader`。
    fn set_header(&mut self, key: &str, value: &str);
    /// Go `c.Set(key, value)`。
    fn set_context(&mut self, key: &str, value: serde_json::Value);
    /// Go `c.GetString(key)`。
    fn get_context_string(&self, key: &str) -> String;
}

// ---- SSE 解析 ---------------------------------------------------------------

/// Go `helper.StreamScannerHandler` 的数据面：把上游响应体拆成 `data:` 载荷
/// 序列。返回 (载荷列表, 是否收到 `[DONE]`)。多行 data 以 `\n` 连接（SSE 规范）。
pub fn parse_sse_data_payloads(body: &[u8]) -> (Vec<String>, bool) {
    let text = String::from_utf8_lossy(body);
    let mut payloads = Vec::new();
    let mut saw_done = false;
    let mut pending: Vec<String> = Vec::new();
    let mut saw_any_event = false;

    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            if saw_any_event {
                let payload = pending.join("\n");
                if payload == "[DONE]" {
                    saw_done = true;
                } else {
                    payloads.push(payload);
                }
                pending.clear();
                saw_any_event = false;
            }
            continue;
        }
        if let Some(data) = line.strip_prefix("data:") {
            saw_any_event = true;
            pending.push(data.strip_prefix(' ').unwrap_or(data).to_owned());
        }
        // `event:` 行与注释行仅影响框架实现，载荷消费方只读 data。
    }
    if saw_any_event {
        let payload = pending.join("\n");
        if payload == "[DONE]" {
            saw_done = true;
        } else {
            payloads.push(payload);
        }
    }
    (payloads, saw_done)
}

/// Go `streamTruncated`（relay-openai.go:307-319）的结束原因输入。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamEndReason {
    /// 扫描器消费到 `data: [DONE]`。
    Done,
    /// 上游正常 EOF。
    Eof,
    /// 客户端断开。
    ClientGone,
    /// 上游异常中断（网络错误/超时）。
    Error,
}

/// 逐块流式扫描：把 [`OutboundResponseBody::Stream`] 折叠为 SSE 载荷序列 +
/// 结束原因。全量 body 直接走 [`parse_sse_data_payloads`]。
pub fn scan_sse_response(response: &mut OutboundResponse) -> (Vec<String>, StreamEndReason) {
    match &mut response.body {
        OutboundResponseBody::Full(bytes) => {
            let (payloads, saw_done) = parse_sse_data_payloads(bytes);
            let reason = if saw_done {
                StreamEndReason::Done
            } else {
                StreamEndReason::Eof
            };
            (payloads, reason)
        }
        OutboundResponseBody::Stream(stream) => {
            let mut payloads = Vec::new();
            let mut buffer: Vec<u8> = Vec::new();
            let mut reason = StreamEndReason::Eof;
            loop {
                match stream.next_chunk() {
                    Some(Ok(chunk)) => buffer.extend_from_slice(&chunk),
                    Some(Err(_)) => {
                        reason = StreamEndReason::Error;
                        break;
                    }
                    None => break,
                }
            }
            let (parsed, saw_done) = parse_sse_data_payloads(&buffer);
            payloads.extend(parsed);
            if saw_done {
                reason = StreamEndReason::Done;
            }
            (payloads, reason)
        }
    }
}

// ---- 适配器层共享装配 -------------------------------------------------------

/// 客户端侧已解析的 multipart 表单（Go `*multipart.Form` 的适配器子集）。
/// 文件字节由服务装配层物化为内存块——流式文件面属装配层职责。
#[derive(Clone, Debug, Default)]
pub struct ParsedMultipartForm {
    pub fields: Vec<(String, String)>,
    pub files: Vec<MultipartFilePart>,
}

/// Go `*multipart.FileHeader` 的适配器子集。
#[derive(Clone, Debug, Default)]
pub struct MultipartFilePart {
    pub field_name: String,
    pub filename: String,
    pub content_type: String,
    pub bytes: Vec<u8>,
}

/// `ConvertAudioRequest` / `ConvertImageRequest` 的返回：JSON 体或已装配的
/// multipart 体（含 Content-Type boundary）。
#[derive(Clone, Debug)]
pub enum ConvertedRequestBody {
    Json(serde_json::Value),
    Multipart { body: Vec<u8>, content_type: String },
}

/// Go `DoResponse` 的返回：(usage, *NewAPIError) 并存形态。
#[derive(Clone, Debug, Default)]
pub struct DoResponseOutcome {
    pub usage: Usage,
    pub error: Option<AdaptorError>,
}

impl DoResponseOutcome {
    pub fn ok(usage: Usage) -> Self {
        Self { usage, error: None }
    }

    pub fn error(usage: Usage, error: AdaptorError) -> Self {
        Self {
            usage,
            error: Some(error),
        }
    }
}

/// Go `channel.DoApiRequest`（api_request.go:324-352）的 Rust 形态：适配器
/// 提供 URL 与 header 组装，本函数完成 header override 合并并生成外呼请求。
/// 外呼本身由调用方交给 [`OutboundTransport`]。
pub fn build_api_request(
    info: &mut RelayInfo,
    context: &RequestContext<'_>,
    url: String,
    mut adaptor_headers: Vec<(String, String)>,
    body: Vec<u8>,
) -> Result<OutboundRequest, AdaptorError> {
    let header_override = process_header_override(info, context)?;
    // Go: applyHeaderOverrideToRequest —— override 覆盖同名 header（Host 特殊，
    // Rust 侧保留为 header 项，由 transport 决定是否提升为 :authority）。
    for (key, value) in header_override {
        if let Some(existing) = adaptor_headers
            .iter_mut()
            .find(|(existing_key, _)| existing_key.eq_ignore_ascii_case(&key))
        {
            existing.1 = value;
        } else {
            adaptor_headers.push((key, value));
        }
    }
    Ok(OutboundRequest {
        method: context.method.to_owned(),
        url,
        headers: adaptor_headers,
        body,
    })
}

/// Go `egress` 上游请求 id 透传：`X-Upstream-Request-Id` 上下文。
pub fn capture_upstream_request_id(sink: &mut dyn ClientSink, response: &OutboundResponse) {
    if let Some(value) = response
        .headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("x-oneapi-request-id"))
        .map(|(_, value)| value.clone())
        && !value.is_empty()
    {
        sink.set_context("X-Upstream-Request-Id", serde_json::Value::String(value));
    }
}

/// 随机 UUID（Go kitutil.GetUUID 的 hex 形态）。纯 crate 无 rand 依赖，
/// 以时间+计数器拼装，仅供转换层 id 生成（`call_` / `chatcmpl-` 前缀）。
pub fn random_uuid() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mixed = now ^ (counter << 32) ^ (counter.wrapping_mul(0x9E3779B97F4A7C15));
    format!("{mixed:032x}")
}

/// Go `kitutil.GetTimestamp`。
pub fn timestamp_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Go GetFullRequestURL：普通拼接 + Cloudflare gateway 前缀裁剪。
    #[test]
    fn full_request_url_plain_and_cloudflare() {
        use crate::adaptor::channel_type as ct;
        assert_eq!(
            get_full_request_url("https://api.openai.com", "/v1/chat/completions", ct::OPENAI),
            "https://api.openai.com/v1/chat/completions"
        );
        assert_eq!(
            get_full_request_url(
                "https://gateway.ai.cloudflare.com/v1/account/openai",
                "/v1/chat/completions",
                ct::OPENAI
            ),
            "https://gateway.ai.cloudflare.com/v1/account/openai/chat/completions"
        );
        assert_eq!(
            get_full_request_url(
                "https://gateway.ai.cloudflare.com/v1/account/azure",
                "/openai/deployments/gpt-4/chat/completions",
                ct::AZURE
            ),
            "https://gateway.ai.cloudflare.com/v1/account/azure/gpt-4/chat/completions"
        );
    }

    // SetupApiRequestHeader：audio/realtime 为空；流式缺 Accept 补 text/event-stream。
    #[test]
    fn api_request_header_defaults() {
        let info = RelayInfo {
            is_stream: true,
            ..RelayInfo::default()
        };
        let client = vec![("Content-Type".to_owned(), "application/json".to_owned())];
        let headers = setup_api_request_header(&info, &client, false, false);
        assert!(headers.contains(&("Content-Type".to_owned(), "application/json".to_owned())));
        assert!(headers.contains(&("Accept".to_owned(), "text/event-stream".to_owned())));

        // 客户端已有 Accept 时不覆盖。
        let client_with_accept = vec![
            ("Content-Type".to_owned(), "application/json".to_owned()),
            ("Accept".to_owned(), "application/json".to_owned()),
        ];
        let headers = setup_api_request_header(&info, &client_with_accept, false, false);
        assert!(headers.contains(&("Accept".to_owned(), "application/json".to_owned())));

        // audio / realtime 分支为空。
        assert!(setup_api_request_header(&info, &client, true, false).is_empty());
        assert!(setup_api_request_header(&info, &client, false, true).is_empty());
    }

    // processHeaderOverride：占位符替换 + 透传规则 + 排除表。
    #[test]
    fn header_override_placeholders_and_passthrough() {
        let info = RelayInfo {
            channel_meta: Some(crate::relay_info::ChannelMeta {
                api_key: "sk-chan".to_owned(),
                headers_override: json!({
                    "X-Custom": "{api_key}-suffix",
                    "*": "",
                    "authorization": "override",
                }),
                ..crate::relay_info::ChannelMeta::default()
            }),
            ..RelayInfo::default()
        };
        let context = RequestContext {
            client_headers: &[
                ("X-Trace".to_owned(), "trace-1".to_owned()),
                ("Authorization".to_owned(), "Bearer client".to_owned()),
                ("Cookie".to_owned(), "session=1".to_owned()),
            ],
            method: "POST",
        };
        let headers = process_header_override(&info, &context).expect("override ok");
        let find = |name: &str| {
            headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.clone())
        };
        assert_eq!(find("x-custom").as_deref(), Some("sk-chan-suffix"));
        // 透传：X-Trace 进、Cookie（skip 表）不进。
        assert_eq!(find("x-trace").as_deref(), Some("trace-1"));
        assert!(find("cookie").is_none());
        // 显式 override 覆盖透传/默认。
        assert_eq!(find("authorization").as_deref(), Some("override"));
    }

    #[test]
    fn header_override_client_header_placeholder() {
        let info = RelayInfo {
            channel_meta: Some(crate::relay_info::ChannelMeta {
                headers_override: json!({"X-Session": "{client_header:x-session-id}"}),
                ..crate::relay_info::ChannelMeta::default()
            }),
            ..RelayInfo::default()
        };
        let context = RequestContext {
            client_headers: &[("X-Session-Id".to_owned(), "abc123".to_owned())],
            method: "POST",
        };
        let headers = process_header_override(&info, &context).expect("override ok");
        assert_eq!(
            headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case("x-session"))
                .map(|(_, value)| value.clone())
                .as_deref(),
            Some("abc123")
        );
    }

    #[test]
    fn header_override_invalid_regex_errors() {
        let info = RelayInfo {
            channel_meta: Some(crate::relay_info::ChannelMeta {
                headers_override: json!({"re:([": ""}),
                ..crate::relay_info::ChannelMeta::default()
            }),
            ..RelayInfo::default()
        };
        let context = RequestContext {
            client_headers: &[],
            method: "POST",
        };
        let err = process_header_override(&info, &context).expect_err("invalid regex");
        assert_eq!(err.code, error_code::CHANNEL_HEADER_OVERRIDE_INVALID);
    }

    // SSE 解析：data 前缀、空行分帧、[DONE] sentinel、多行 data。
    #[test]
    fn sse_parsing() {
        let body = b"data: {\"a\":1}\n\ndata: {\"b\":2}\n\ndata: [DONE]\n\n";
        let (payloads, saw_done) = parse_sse_data_payloads(body);
        assert_eq!(
            payloads,
            vec!["{\"a\":1}".to_owned(), "{\"b\":2}".to_owned()]
        );
        assert!(saw_done);

        let (payloads, saw_done) = parse_sse_data_payloads(b"data: one\ndata: two\n\n");
        assert_eq!(payloads, vec!["one\ntwo".to_owned()]);
        assert!(!saw_done);

        // event 行与注释被忽略。
        let (payloads, _) = parse_sse_data_payloads(b"event: message\ndata: x\n: keepalive\n\n");
        assert_eq!(payloads, vec!["x".to_owned()]);
    }

    // EstimateTokenByModel / EstimateToken：与 Go 权重表逐字对齐的形状检查。
    #[test]
    fn token_estimation_shape() {
        use crate::adaptor_common::usage::{Provider, estimate_token, estimate_token_by_model};
        assert_eq!(estimate_token(Provider::OpenAI, ""), 0);
        // "hello world"：2 word + 1 space → 1.02+0.42+1.02 = 2.46 → ceil = 3
        assert_eq!(estimate_token(Provider::OpenAI, "hello world"), 3);
        // CJK 按字计费：3 个汉字 → ceil(0.85*3)=3
        assert_eq!(estimate_token(Provider::OpenAI, "你好界"), 3);
        assert_eq!(
            estimate_token(Provider::Gemini, "你好界"),
            (0.68_f64 * 3.0).ceil() as i64
        ); // ceil(2.04)=3
        assert_eq!(
            estimate_token_by_model("gemini-2.5-flash", "abc"),
            estimate_token(Provider::Gemini, "abc")
        );
        assert_eq!(
            estimate_token_by_model("claude-3-5-sonnet", "abc"),
            estimate_token(Provider::Claude, "abc")
        );
        assert_eq!(
            estimate_token_by_model("gpt-4o", "abc"),
            estimate_token(Provider::OpenAI, "abc")
        );
    }

    // ValidUsage / response_text_2_usage。
    #[test]
    fn usage_helpers() {
        use crate::adaptor_common::usage::{response_text_2_usage_pure, valid_usage};
        assert!(!valid_usage(&Usage::default()));
        let usage = response_text_2_usage_pure("hello world", "gpt-4o", 10);
        assert_eq!(usage.prompt_tokens, 10);
        assert_eq!(usage.completion_tokens, 3);
        assert_eq!(usage.total_tokens, 13);
        assert!(valid_usage(&usage));
    }

    // 错误折叠：WithOpenAIError / WithClaudeError 语义。
    #[test]
    fn error_envelopes() {
        let oai = crate::adaptor_common::convert_claude::OpenAiErrorBody {
            message: "boom".to_owned(),
            r#type: String::new(),
            code: json!("insufficient_quota"),
            ..Default::default()
        };
        let err = with_openai_error(&oai, 429);
        assert_eq!(err.code, "insufficient_quota");
        assert_eq!(err.error_type, "upstream_error"); // Go: type 缺省 upstream_error
        assert_eq!(err.status_code, 429);
        assert_eq!(err.message, "boom");

        let claude = crate::adaptor_common::convert_claude::ClaudeErrorBody {
            r#type: "overloaded_error".to_owned(),
            message: "Overloaded".to_owned(),
        };
        let err = with_claude_error(&claude, 500);
        assert_eq!(err.code, "overloaded_error");
        assert_eq!(err.error_type, error_type::CLAUDE);

        let err = with_skip_retry(new_openai_error("x", error_code::BAD_RESPONSE, 502));
        assert!(err.skip_retry);
    }

    // OutboundResponse::read_full_body 对流体的折叠。
    #[test]
    fn outbound_response_stream_read() {
        struct Chunked(Vec<Vec<u8>>);
        impl ByteStream for Chunked {
            fn next_chunk(&mut self) -> Option<Result<Vec<u8>, String>> {
                if self.0.is_empty() {
                    None
                } else {
                    Some(Ok(self.0.remove(0)))
                }
            }
        }
        let mut response = OutboundResponse {
            status: 200,
            headers: vec![],
            body: OutboundResponseBody::Stream(Box::new(Chunked(vec![
                b"data: a\n\n".to_vec(),
                b"data: [DONE]\n\n".to_vec(),
            ]))),
        };
        let (payloads, reason) = scan_sse_response(&mut response);
        assert_eq!(payloads, vec!["a".to_owned()]);
        assert_eq!(reason, StreamEndReason::Done);
    }
}
