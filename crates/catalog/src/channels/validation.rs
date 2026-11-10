//! 渠道创建/更新的校验与请求体解析（Go `validateChannel` +
//! `Channel.ValidateSettings`，以及 `AddChannel` 的密钥模式解析）。
//!
//! Go 参考：
//! - `transport/handler/handle_channel.go`：`validateChannel`、
//!   `AddChannelRequest`、`getVertexArrayKeys`、模式分支
//! - `catalog/store_channel.go`：`ValidateSettings`、`GetBaseURL`
//! - `relaykit/dto/channel_settings.go`：`ChannelSettings`、
//!   `ChannelOtherSettings`、`AdvancedCustomConfig.Validate` 及其校验链
//! - `common/proxy_url.go`：`ParseProxyURLStrict`
//!
//! 所有失败返回 Go 的**原始错误文本**（handler 层把它们折叠成 i18n 消息，
//! 见 `channel_http`）；不在此模块决定响应形态。

use std::collections::BTreeMap;

use serde::Deserialize;

use super::store::{
    CHANNEL_TYPE_ADVANCED_CUSTOM, CHANNEL_TYPE_CODEX, CHANNEL_TYPE_NEW_API, CHANNEL_TYPE_VERTEX_AI,
    ChannelInfo,
};

/// Go `validateChannel` 的失败分类；HTTP 边界按分类取 i18n 键。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValidationError {
    /// `渠道额外设置[channel setting] 格式错误：%s` 的内部明细。
    Settings(String),
    /// `channel cannot be empty`（渠道为空或 key 为空）。
    ChannelOrKeyEmpty,
    /// `模型名称过长: %s`（仅创建路径）。
    ModelNameTooLong(String),
    /// `New API channel base URL cannot be empty`。
    NewApiBaseUrlRequired,
    /// `部署地区不能为空`。
    VertexRegionRequired,
    /// `部署地区必须是标准的Json格式，例如{...}`。
    VertexRegionFormat,
    /// `部署地区必须包含default字段`。
    VertexRegionDefault,
    /// `Codex key must be a valid JSON object`。
    CodexKeyFormat,
    /// `Codex key JSON must include access_token`。
    CodexAccessTokenRequired,
    /// `Codex key JSON must include account_id`。
    CodexAccountIdRequired,
}

/// Go `dto.ChannelSettings`（`channel_settings.go:22-44`）。
///
/// 全字段解码以复现 Go `json.Unmarshal` 的类型严格性（类型不匹配即为
/// 绑定错误）；校验路径只关心 proxy / http_protocol / http2_connection_shards。
#[derive(Debug, Default, Deserialize)]
#[allow(dead_code)]
pub struct ChannelSettings {
    force_format: Option<bool>,
    thinking_to_content: Option<bool>,
    bypass_proxy: Option<bool>,
    proxy: Option<String>,
    pass_through_body_enabled: Option<bool>,
    session_affinity_enabled: Option<bool>,
    system_prompt: Option<String>,
    system_prompt_override: Option<bool>,
    system_prompt_models: Option<BTreeMap<String, String>>,
    system_prompt_preset: Option<String>,
    http_protocol: Option<String>,
    http2_connection_shards: Option<i64>,
}

/// Go `dto.ChannelOtherSettings`（`channel_settings.go:96-125`）。
#[derive(Debug, Default, Deserialize)]
#[allow(dead_code)]
pub struct ChannelOtherSettings {
    azure_responses_version: Option<String>,
    vertex_key_type: Option<String>,
    openrouter_enterprise: Option<bool>,
    claude_beta_query: Option<bool>,
    allow_service_tier: Option<bool>,
    allow_inference_geo: Option<bool>,
    allow_speed: Option<bool>,
    allow_safety_identifier: Option<bool>,
    disable_store: Option<bool>,
    allow_include_obfuscation: Option<bool>,
    disable_task_polling_sleep: Option<bool>,
    aws_key_type: Option<String>,
    upstream_model_update_check_enabled: Option<bool>,
    upstream_model_update_auto_sync_enabled: Option<bool>,
    upstream_model_update_last_check_time: Option<i64>,
    upstream_model_update_last_detected_models: Option<Vec<String>>,
    upstream_model_update_last_removed_models: Option<Vec<String>>,
    upstream_model_update_ignored_models: Option<Vec<String>>,
    advanced_custom: Option<AdvancedCustomConfig>,
}

/// Go `dto.AdvancedCustomConfig`：`advanced_routes` 列表。
#[derive(Clone, Debug, Default, Deserialize)]
pub struct AdvancedCustomConfig {
    #[serde(default, rename = "advanced_routes")]
    pub routes: Vec<AdvancedCustomRoute>,
}

/// Go `dto.AdvancedCustomRoute`。
#[derive(Clone, Debug, Default, Deserialize)]
pub struct AdvancedCustomRoute {
    #[serde(default)]
    pub incoming_path: String,
    #[serde(default)]
    pub upstream_path: String,
    #[serde(default)]
    pub converter: String,
    #[serde(default)]
    pub models: Vec<String>,
    #[serde(default)]
    pub auth: Option<AdvancedCustomRouteAuth>,
}

/// Go `dto.AdvancedCustomRouteAuth`。
#[derive(Clone, Debug, Default, Deserialize)]
pub struct AdvancedCustomRouteAuth {
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub value: String,
}

/// Go `common.ParseProxyURLStrict`（`proxy_url.go:12-80`）的判定子集：
/// 空串通过；scheme ∈ {http,https,socks5,socks5h,sing-box}（无 `://`
/// 时 Go `url.Parse` 仍成功，scheme 为空/整体 opaque，同样被白名单拒绝）；
/// host 非空（含 userinfo 时取 `@` 之后的部分）；端口为空或 1..=65535
/// （非数字端口被 Go 的 `URL.Port()` 视为空串，放行）；不得含 query、
/// fragment 或非根路径。
///
/// 与 Go 的差异：Go `url.Parse` 还会拒绝少数畸形输入（如非法 IPv6 括号、
/// 控制字符），这里按判定子集接受。返回 Go 的错误文本。
pub fn proxy_url_error(raw: &str) -> Option<&'static str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    // scheme：取 '://' 之前的全部；没有 '://' 时按空 scheme 处理，
    // 由白名单拒绝（对齐 Go 对 "localhost" / "host:8080" 的处理）。
    let (scheme, rest) = match trimmed.split_once("://") {
        Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
        None => (String::new(), trimmed),
    };
    if !matches!(
        scheme.as_str(),
        "http" | "https" | "socks5" | "socks5h" | "sing-box"
    ) {
        return Some("proxy URL must use http, https, socks5, socks5h, or a sing-box scheme");
    }
    // authority 是不含 query/fragment 的最长前缀；去掉 userinfo 得 host 部分。
    let authority = rest.split(['?', '#']).next().unwrap_or("");
    let host_with_port = match authority.rsplit_once('@') {
        Some((_, host)) => host,
        None => authority,
    };
    if host_with_port.is_empty() {
        return Some("proxy URL must include a host");
    }
    // 端口：IPv6 字面量取 ']' 之后的 ':'；否则取最后一个 ':' 之后的部分。
    let port = if let Some(end) = host_with_port.find(']') {
        host_with_port[end..].strip_prefix("]:")
    } else {
        host_with_port.rsplit_once(':').map(|(_, port)| port)
    };
    if let Some(port) = port
        && !port.is_empty()
    {
        // 数字端口超范围才拒绝；非数字端口被 Go 视为无端口，放行。
        if let Ok(value) = port.parse::<u32>()
            && value > 65535
        {
            return Some("proxy URL must include a valid port");
        }
    }
    let remainder = &rest[authority.len()..];
    if remainder.contains('?') {
        return Some("proxy URL must not include a query");
    }
    if remainder.contains('#') {
        return Some("proxy URL must not include a fragment");
    }
    let path = remainder.split(['?', '#']).next().unwrap_or("");
    if !path.is_empty() && path != "/" {
        return Some("proxy URL must not include a path");
    }
    None
}

/// Go `ChannelSettings.ValidateHTTPTransport`（`channel_settings.go:77-93`）。
fn http_transport_error(settings: &ChannelSettings) -> Option<String> {
    let protocol = settings
        .http_protocol
        .as_deref()
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    if !matches!(protocol.as_str(), "" | "auto" | "http1") {
        return Some(format!(
            "invalid http_protocol: {}",
            settings.http_protocol.as_deref().unwrap_or_default()
        ));
    }
    let shards = settings.http2_connection_shards.unwrap_or(0);
    if !(0..=8).contains(&shards) {
        return Some(format!("invalid http2_connection_shards: {shards}"));
    }
    if protocol == "http1" && shards > 1 {
        return Some("http2_connection_shards must be 1 when http_protocol is http1".to_owned());
    }
    None
}

/// Go `AdvancedCustomConfig.Validate`（`channel_settings.go:384-449`）
/// 及其校验链（`validateAdvancedCustomRouteModels`、
/// `validateAdvancedCustomUpstreamTarget`、`IsAdvancedCustomConverterAllowed`、
/// `validateAdvancedCustomConverterPath`、`validateAdvancedCustomRouteAuth`）。
pub fn advanced_custom_error(config: &AdvancedCustomConfig) -> Option<String> {
    if config.routes.is_empty() {
        return Some("advanced_custom requires at least one route".to_owned());
    }
    const MODEL_LIST_PATH: &str = "/v1/models";
    struct PathState {
        catch_all_index: Option<usize>,
        model_indexes: BTreeMap<String, usize>,
    }
    let mut paths: BTreeMap<String, PathState> = BTreeMap::new();
    let mut model_list_route_index: Option<usize> = None;
    for (index, route) in config.routes.iter().enumerate() {
        let incoming_path = route.incoming_path.trim();
        let upstream_path = route.upstream_path.trim();
        let converter = route.converter.trim();
        if incoming_path.is_empty() {
            return Some(format!(
                "advanced_custom.advanced_routes[{index}].incoming_path is required"
            ));
        }
        if !incoming_path.starts_with('/') {
            return Some(format!(
                "advanced_custom.advanced_routes[{index}].incoming_path must start with /"
            ));
        }
        if incoming_path.contains('?') {
            return Some(format!(
                "advanced_custom.advanced_routes[{index}].incoming_path must not include query"
            ));
        }
        if incoming_path == MODEL_LIST_PATH {
            if let Some(previous) = model_list_route_index {
                return Some(format!(
                    "advanced_custom.advanced_routes[{index}] duplicates the /v1/models route at advanced_routes[{previous}]"
                ));
            }
            model_list_route_index = Some(index);
            let normalized = normalize_models(&route.models);
            if !normalized.is_empty() {
                return Some(format!(
                    "advanced_custom.advanced_routes[{index}].models must be empty for /v1/models"
                ));
            }
            if converter != "none" {
                return Some(format!(
                    "advanced_custom.advanced_routes[{index}].converter must be none for /v1/models"
                ));
            }
            if upstream_path.contains("{model}") {
                return Some(format!(
                    "advanced_custom.advanced_routes[{index}].upstream_path must not contain {{model}} for /v1/models"
                ));
            }
        }
        // validateAdvancedCustomRouteModels
        let state = paths
            .entry(incoming_path.to_owned())
            .or_insert_with(|| PathState {
                catch_all_index: None,
                model_indexes: BTreeMap::new(),
            });
        let normalized = normalize_models(&route.models);
        if normalized.is_empty() {
            if state.catch_all_index.is_some() {
                return Some(format!(
                    "advanced_custom.advanced_routes[{index}].models catch-all already exists for incoming_path: {incoming_path}"
                ));
            }
            state.catch_all_index = Some(index);
        } else {
            if state.catch_all_index.is_some() {
                return Some(format!(
                    "advanced_custom.advanced_routes[{index}].models catch-all route must be last for incoming_path: {incoming_path}"
                ));
            }
            let mut seen_in_route = std::collections::HashSet::new();
            for model in &normalized {
                if let Some(pattern) = model.strip_prefix("re:") {
                    if pattern.is_empty() {
                        return Some(format!(
                            "advanced_custom.advanced_routes[{index}].models regex is empty for incoming_path {incoming_path}: {model}"
                        ));
                    }
                    // Go `regexp.Compile(pattern)`：非法正则即失败。Rust 正则
                    // 语法与 Go（RE2）等价；编译失败复现同一错误文本。
                    if regex_lite_compile(pattern).is_none() {
                        return Some(format!(
                            "advanced_custom.advanced_routes[{index}].models regex is invalid for incoming_path {incoming_path}: {model}"
                        ));
                    }
                }
                if !seen_in_route.insert(model.clone()) {
                    return Some(format!(
                        "advanced_custom.advanced_routes[{index}].models contains duplicate model for incoming_path {incoming_path}: {model}"
                    ));
                }
                if let Some(existing) = state.model_indexes.get(model) {
                    return Some(format!(
                        "advanced_custom.advanced_routes[{index}].models overlaps with advanced_routes[{existing}] for incoming_path {incoming_path}: {model}"
                    ));
                }
                state.model_indexes.insert(model.clone(), index);
            }
        }
        if upstream_path.is_empty() {
            return Some(format!(
                "advanced_custom.advanced_routes[{index}].upstream_path is required"
            ));
        }
        // validateAdvancedCustomUpstreamTarget
        if upstream_path.starts_with('/') {
            if upstream_path.starts_with("//") {
                return Some(format!(
                    "advanced_custom.advanced_routes[{index}].upstream_path must be a full URL or a path starting with /"
                ));
            }
        } else {
            let scheme_end = upstream_path.find("://");
            let scheme_ok = scheme_end
                .map(|end| {
                    let scheme = &upstream_path[..end];
                    scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")
                })
                .unwrap_or(false);
            let host_ok = match scheme_end {
                Some(end) => {
                    let rest = &upstream_path[end + 3..];
                    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
                    !host.is_empty()
                }
                None => false,
            };
            if !scheme_ok || !host_ok {
                return Some(format!(
                    "advanced_custom.advanced_routes[{index}].upstream_path must be a full URL or a path starting with /"
                ));
            }
        }
        if !is_converter_allowed(converter) {
            return Some(format!(
                "advanced_custom.advanced_routes[{index}].converter is not registered: {converter}"
            ));
        }
        if let Some(error) = converter_path_error(index, incoming_path, converter) {
            return Some(error);
        }
        if let Some(auth) = route.auth.as_ref() {
            if let Some(error) = route_auth_error(index, auth) {
                return Some(error);
            }
        }
    }
    None
}

/// `normalizeAdvancedCustomRouteModels`：trim 后丢空。
fn normalize_models(models: &[String]) -> Vec<String> {
    models
        .iter()
        .map(|model| model.trim())
        .filter(|model| !model.is_empty())
        .map(|model| model.to_owned())
        .collect()
}

/// 一个极简的 Go（RE2 语法）正则合法性探针：只做语法层面的括号配对与
/// 转义序列检查，足以复现 Go `regexp.Compile` 对常见非法输入的拒绝，
/// 不引入 regex crate 依赖（catalog 目前没有）。`None` = 视为非法。
fn regex_lite_compile(pattern: &str) -> Option<()> {
    let mut depth = 0i32;
    let mut escape = false;
    let mut char_class = false;
    for ch in pattern.chars() {
        if escape {
            escape = false;
            continue;
        }
        match ch {
            '\\' => escape = true,
            '[' if !char_class => char_class = true,
            ']' if char_class => char_class = false,
            '(' if !char_class => depth += 1,
            ')' if !char_class => {
                depth -= 1;
                if depth < 0 {
                    return None;
                }
            }
            _ => {}
        }
    }
    if escape || char_class || depth != 0 {
        return None;
    }
    Some(())
}

/// Go `IsAdvancedCustomConverterAllowed`（`channel_settings.go:368-382`）。
fn is_converter_allowed(converter: &str) -> bool {
    matches!(
        converter,
        "none"
            | "anthropic_messages_to_openai_chat_completions"
            | "openai_chat_completions_to_anthropic_messages"
            | "openai_chat_completions_to_openai_responses"
            | "openai_responses_to_openai_chat_completions"
            | "openai_responses_to_gemini_generate_content"
            | "gemini_generate_content_to_openai_chat_completions"
            | "openai_chat_completions_to_gemini_generate_content"
    )
}

/// Go `validateAdvancedCustomConverterPath`（`channel_settings.go:543-578`）。
fn converter_path_error(index: usize, incoming_path: &str, converter: &str) -> Option<String> {
    if incoming_path == "/v1/alpha/search" {
        if converter == "none" {
            return None;
        }
        return Some(format!(
            "advanced_custom.advanced_routes[{index}].converter does not match incoming_path: {converter}"
        ));
    }
    let path_ok = match converter {
        "none" => true,
        "anthropic_messages_to_openai_chat_completions" => incoming_path == "/v1/messages",
        "openai_chat_completions_to_anthropic_messages"
        | "openai_chat_completions_to_openai_responses"
        | "openai_chat_completions_to_gemini_generate_content" => {
            incoming_path == "/v1/chat/completions"
        }
        "openai_responses_to_openai_chat_completions"
        | "openai_responses_to_gemini_generate_content" => incoming_path == "/v1/responses",
        "gemini_generate_content_to_openai_chat_completions" => {
            incoming_path.contains(":generateContent")
                || incoming_path.contains(":streamGenerateContent")
        }
        _ => false,
    };
    if path_ok {
        None
    } else {
        Some(format!(
            "advanced_custom.advanced_routes[{index}].converter does not match incoming_path: {converter}"
        ))
    }
}

/// Go `validateAdvancedCustomRouteAuth`（`channel_settings.go:579-601`）。
fn route_auth_error(index: usize, auth: &AdvancedCustomRouteAuth) -> Option<String> {
    let kind = auth.kind.trim();
    match kind {
        "none" => None,
        "header" | "query" => {
            if auth.name.trim().is_empty() {
                return Some(format!(
                    "advanced_custom.advanced_routes[{index}].auth.name is required"
                ));
            }
            if auth.value.trim().is_empty() {
                return Some(format!(
                    "advanced_custom.advanced_routes[{index}].auth.value is required"
                ));
            }
            None
        }
        _ => Some(format!(
            "advanced_custom.advanced_routes[{index}].auth.type is invalid: {}",
            auth.kind
        )),
    }
}

/// Go `Channel.ValidateSettings`（`store_channel.go:1164-1200`）。返回内部
/// 错误文本（调用方包上“渠道额外设置[channel setting] 格式错误：”前缀）；
/// `Err` 的文本来自 Go 的 unmarshal/校验错误（请求体派生，不含渠道密钥）。
fn validate_settings_detail(
    setting: &Option<String>,
    other_settings: &str,
    channel_type: i64,
) -> Result<(), String> {
    if let Some(setting) = setting.as_deref()
        && !setting.is_empty()
    {
        let parsed: ChannelSettings =
            serde_json::from_str(setting).map_err(|error| error.to_string())?;
        if let Some(error) = proxy_url_error(parsed.proxy.as_deref().unwrap_or_default()) {
            return Err(format!("invalid channel proxy: {error}"));
        }
        if let Some(error) = http_transport_error(&parsed) {
            return Err(error);
        }
    }
    if !other_settings.is_empty() {
        let parsed: ChannelOtherSettings =
            serde_json::from_str(other_settings).map_err(|error| error.to_string())?;
        if channel_type == CHANNEL_TYPE_ADVANCED_CUSTOM && parsed.advanced_custom.is_none() {
            return Err("advanced_custom is required".to_owned());
        }
        if let Some(config) = parsed.advanced_custom.as_ref() {
            if let Some(error) = advanced_custom_error(config) {
                return Err(error);
            }
            // `UpstreamModelUpdateCheckEnabled` 为真时必须有 /v1/models 路由
            // （`store_channel.go:1195-1199`）。
            if parsed.upstream_model_update_check_enabled == Some(true)
                && !config
                    .routes
                    .iter()
                    .any(|route| route.incoming_path.trim() == "/v1/models")
            {
                return Err(
                    "advanced custom channels require a /v1/models route when upstream \
                     model update checks are enabled"
                        .to_owned(),
                );
            }
        }
    }
    Ok(())
}

/// Go `validateChannel`（`handle_channel.go:460-525`）。
///
/// `channel` 已是解码后的输入形态；`is_add` 对应 Go 的 `isAdd`。
/// `base_url` 为请求里的 `base_url`（`GetBaseURL` 的 nil→"" 分支在外部处理，
/// 校验只关心空白判定——New API 类型的内置 base URL 恰为空串）。
pub fn validate_channel(
    channel_type: i64,
    base_url: &Option<String>,
    key: &str,
    models: &str,
    other: &str,
    setting: &Option<String>,
    other_settings: &str,
    is_add: bool,
) -> Result<(), ValidationError> {
    if let Err(detail) = validate_settings_detail(setting, other_settings, channel_type) {
        return Err(ValidationError::Settings(detail));
    }
    if channel_type == CHANNEL_TYPE_NEW_API
        && base_url
            .as_deref()
            .map(str::trim)
            .unwrap_or_default()
            .is_empty()
    {
        return Err(ValidationError::NewApiBaseUrlRequired);
    }
    if is_add && key.is_empty() {
        return Err(ValidationError::ChannelOrKeyEmpty);
    }
    if is_add {
        // Go 遍历 `GetModels()`：`strings.Split(strings.Trim(models, ","), ",")`。
        for model in models.trim_matches(',').split(',') {
            if model.len() > 255 {
                return Err(ValidationError::ModelNameTooLong(model.to_owned()));
            }
        }
    }
    if channel_type == CHANNEL_TYPE_VERTEX_AI {
        if other.is_empty() {
            return Err(ValidationError::VertexRegionRequired);
        }
        let map: BTreeMap<String, serde_json::Value> =
            serde_json::from_str(other).map_err(|_| ValidationError::VertexRegionFormat)?;
        if map.get("default").is_none() {
            return Err(ValidationError::VertexRegionDefault);
        }
    }
    if channel_type == CHANNEL_TYPE_CODEX && (is_add || !key.trim().is_empty()) {
        let trimmed = key.trim();
        if !trimmed.starts_with('{') {
            return Err(ValidationError::CodexKeyFormat);
        }
        let map: BTreeMap<String, serde_json::Value> =
            serde_json::from_str(trimmed).map_err(|_| ValidationError::CodexKeyFormat)?;
        if non_empty_string(map.get("access_token")).is_none() {
            return Err(ValidationError::CodexAccessTokenRequired);
        }
        if non_empty_string(map.get("account_id")).is_none() {
            return Err(ValidationError::CodexAccountIdRequired);
        }
    }
    Ok(())
}

fn non_empty_string(value: Option<&serde_json::Value>) -> Option<&str> {
    value
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

/// `AddChannelRequest`（`handle_channel.go:559-564`）的外层字段；
/// `channel` 缺失或 `null` 即 Go 的 nil 指针。
#[derive(Debug, Default, Deserialize)]
pub struct AddChannelRequest {
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub multi_key_mode: Option<String>,
    #[serde(default)]
    pub batch_add_set_key_prefix_2_name: Option<bool>,
    #[serde(default)]
    pub channel: Option<super::store::ChannelInput>,
}

/// 密钥模式解析的失败（Go 的 `getVertexArrayKeys` 与模式分支错误）。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyParseError {
    /// `不支持的添加模式`。
    UnsupportedMode,
    /// `批量添加 Vertex AI 必须使用标准的JsonArray格式...`。
    VertexArrayFormat,
    /// `批量添加 Vertex AI 的 keys 不能为空`。
    VertexArrayEmpty,
}

/// 模式解析结果：落到 `channels` 行的密钥列表（一行一个 key 的批量模式，
/// 或单行多 key 的合并模式），以及 `multi_to_single` 需要写入的
/// `channel_info`。
pub struct ParsedKeys {
    pub keys: Vec<String>,
    pub channel_info: Option<ChannelInfo>,
}

/// Go `AddChannel` 的模式分支（`handle_channel.go:617-667`）。
///
/// `vertex_api_key` 为真表示 `settings.vertex_key_type == "api_key"`，
/// 此时 Vertex AI 也走普通换行切分（`dto.VertexKeyTypeAPIKey` 分支）。
pub fn parse_keys(
    mode: &Option<String>,
    key: &str,
    vertex_api_key: bool,
    is_vertex: bool,
    request_multi_key_mode: &Option<String>,
    channel_info: &Option<ChannelInfo>,
) -> Result<ParsedKeys, KeyParseError> {
    let mut info = channel_info.clone().unwrap_or_default();
    match mode.as_deref() {
        Some("multi_to_single") => {
            info.is_multi_key = true;
            info.multi_key_mode = request_multi_key_mode.clone().unwrap_or_default();
            if is_vertex && !vertex_api_key {
                let array = vertex_array_keys(key)?;
                info.multi_key_size = array.len() as i64;
                Ok(ParsedKeys {
                    keys: vec![array.join("\n")],
                    channel_info: Some(info),
                })
            } else {
                let clean: Vec<String> = key
                    .split('\n')
                    .filter(|line| !line.is_empty())
                    .map(|line| line.trim().to_owned())
                    .collect();
                info.multi_key_size = clean.len() as i64;
                Ok(ParsedKeys {
                    keys: vec![clean.join("\n")],
                    channel_info: Some(info),
                })
            }
        }
        Some("batch") => {
            if is_vertex && !vertex_api_key {
                let array = vertex_array_keys(key)?;
                Ok(ParsedKeys {
                    keys: array,
                    channel_info: Some(info),
                })
            } else {
                Ok(ParsedKeys {
                    keys: key.split('\n').map(str::to_owned).collect(),
                    channel_info: Some(info),
                })
            }
        }
        Some("single") => Ok(ParsedKeys {
            keys: vec![key.to_owned()],
            channel_info: Some(info),
        }),
        _ => Err(KeyParseError::UnsupportedMode),
    }
}

/// Go `getVertexArrayKeys`（`handle_channel.go:566-596`）：JSON 数组，元素
/// 为字符串时 trim，其余元素序列化回 JSON 文本；空结果报错。
fn vertex_array_keys(key: &str) -> Result<Vec<String>, KeyParseError> {
    let array: Vec<serde_json::Value> =
        serde_json::from_str(key).map_err(|_| KeyParseError::VertexArrayFormat)?;
    let mut clean = Vec::with_capacity(array.len());
    for value in array {
        match value {
            serde_json::Value::String(string) => clean.push(string.trim().to_owned()),
            other => clean.push(other.to_string()),
        }
    }
    if clean.is_empty() {
        return Err(KeyParseError::VertexArrayEmpty);
    }
    Ok(clean)
}

/// `settings`（`ChannelOtherSettings` JSON 文本）是否声明 Vertex API Key
/// 模式：`vertex_key_type == "api_key"`（缺省视为 `"json"`）。
pub fn vertex_uses_api_key(other_settings: &str) -> bool {
    if other_settings.is_empty() {
        return false;
    }
    let parsed: ChannelOtherSettings = match serde_json::from_str(other_settings) {
        Ok(parsed) => parsed,
        Err(_) => return false,
    };
    parsed.vertex_key_type.as_deref() == Some("api_key")
}
