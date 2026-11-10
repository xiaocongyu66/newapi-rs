//! `/api/models*` 模型管理端 HTTP 适配。
//!
//! Go 参考：
//! - `transport/compose/register_api.go:32`（`GET /api/models`，
//!   `UserAuth` → `DashboardListModels`）与 `:450-462`（`modelsRoute`
//!   组，组级 `AdminAuth()`，九条路由）
//! - `transport/handler/handle_model.go`（`DashboardListModels`：静态
//!   `channelId2Models` 目录，见 `newapi_catalog::models::dashboard`）
//! - `transport/handler/handle_missing_models.go`（`GetMissingModels`）
//! - `transport/handler/handle_model_meta.go` → `ops/manage_model_metadata.go`
//!   （List/Search/Get/Create/Update/Delete 六条）
//! - `transport/handler/handle_model_sync.go`（`SyncUpstreamModels` /
//!   `SyncUpstreamPreview`：上游目录拉取、缺失补建、字段覆盖与冲突预览）
//!
//! 与 Go 的响应契约：
//! - 全部业务结果 HTTP 200 + `{"success":bool,"message":...}` 信封；401/403
//!   只来自鉴权链（`modelsRoute` 组只有 `AdminAuth()`，无 RequirePermission）。
//!   两处例外逐字对齐 Go：`GET /api/models` 与 `GET /api/models/missing` 的
//!   成功体是 `{"success":true,"data":...}`，没有 `message` 键。
//! - 删除成功是 `{"success":true,"message":"","data":null}`（Go
//!   `CtxApiSuccess(c, nil)`）。
//! - `vendor_counts` 是 `map[int64]int64`（JSON 字符串键），查询失败时为
//!   `null`（Go 忽略该错误、nil map 序列化为 null）。
//! - preview 的 `missing`/`conflicts` 在为空时是 `null`（Go 声明
//!   `var missing []string` 零值 nil 的序列化），非空时才是数组；sync 的
//!   三个列表 Go 用 `make(..., 0)` 初始化，恒为数组。
//!
//! 与 Go 的已知差异（安全约定，同 `channel_http`）：
//! - Go 把数据库/上游网络错误原文放进 `message`；Rust 回固定 i18n 文案，
//!   错误类别只进日志（`database_error_class` / fetch 类别）。
//! - 上游 fetch 的 ETag/304 进程内缓存（Go `etagCache`/`bodyCache`）未移植，
//!   该缓存对外不可观察。
//! - `BindJSON` 部分解码：Go 的 json.Unmarshal 在类型不匹配时保留已解码
//!   字段，serde 整体回退零值；同步请求体绑定失败 Go 一律忽略错误继续
//!   （`_ = c.BindJSON`），这里同样回退默认值继续。
//!
//! 范围裁剪（后续切片）：
//! - `enrichModels` 的 `enable_groups`/`quota_types`/`matched_models`/
//!   `matched_count` 与规则模型的 `bound_channels` 并集来自定价缓存
//!   （`store_pricing.go`），缓存未移植 → 一律空/省略；精确模型的
//!   `endpoints` 按空缓存语义填充 `"[]"`（Go `common.Marshal([])` 的结果）。
//! - `RefreshPricing` 无对应物（同上）。
//! - `MutateGatewayRouting` 路由修订号不实现（见 `channels/store.rs` 同一
//!   决定），models 行写入保持 Go 的单变更原子语义。

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::OnceLock;
use std::time::Duration;

use axum::{
    Json,
    body::to_bytes,
    extract::{Path, Request, State},
    http::{HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use newapi_catalog::abilities::enabled_models;
use newapi_catalog::models::{
    BoundChannel, ModelInput, ModelRepository, ModelRow, NAME_RULE_EXACT, NewModel, choose_status,
    contains_field, parse_status_filter, parse_sync_filter,
};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::AppState;
use crate::http::{MAX_BODY_BYTES, now_seconds};

const MSG_INVALID_PARAMS: &str = "common.invalid_params";
const MSG_NOT_EXISTS: &str = "model.not_exists";
const MSG_ID_FORMAT: &str = "model.id_format_error";
const MSG_NAME_EMPTY: &str = "model.name_empty";
const MSG_NAME_EXISTS: &str = "model.name_exists";
const MSG_ID_MISSING: &str = "model.id_missing";
const MSG_LIST_FAILED: &str = "model.get_list_failed";
const MSG_UPSTREAM_FAILED: &str = "model.get_failed";
const MSG_SAVE_FAILED: &str = "model.save_failed";

/// Go `handle_model_sync.go:25` 的默认上游目录。
pub const DEFAULT_UPSTREAM_BASE: &str = "https://basellm.github.io/llm-metadata";
/// Go `newHTTPClient` 的单请求超时（`SYNC_HTTP_TIMEOUT_SECONDS` 缺省 10）。
const DEFAULT_CLIENT_TIMEOUT_SECONDS: i64 = 10;
/// Go handler 上下文的整体超时（同环境变量，缺省 15）。
const DEFAULT_HANDLER_TIMEOUT_SECONDS: i64 = 15;
/// Go `fetchJSON` 的重试次数（`SYNC_HTTP_RETRY` 缺省 3）。
const DEFAULT_HTTP_RETRY: i64 = 3;
/// Go `fetchJSON` 的响应体上限（`SYNC_HTTP_MAX_MB` 缺省 10）。
const DEFAULT_HTTP_MAX_MB: i64 = 10;

// ---------------------------------------------------------------------------
// 上游拉取端口（对齐 `turnstile` 的 `Verifier` 模式：生产实现走共享
// reqwest 客户端，测试注入假实现）
// ---------------------------------------------------------------------------

/// 拉取失败分类；错误原文只进日志，不进响应（Go 会把 `resp.Status` 等原文
/// 拼进 message，Rust 侧按安全约定收敛为固定文案）。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamFetchError {
    /// DNS、连接、TLS 或请求发送失败。
    Transport,
    /// 非 2xx 状态（Go 同样按可重试错误处理）。
    Status,
    /// 响应体超过上限（Go 用 `io.LimitReader` 截断后多半解析失败，这里
    /// 显式成类）。
    BodyTooLarge,
    /// 响应体既不是 `{success,message,data}` 信封也不是数组。
    Decode,
}

impl UpstreamFetchError {
    fn category(self) -> &'static str {
        match self {
            Self::Transport => "transport",
            Self::Status => "status",
            Self::BodyTooLarge => "body_too_large",
            Self::Decode => "decode",
        }
    }
}

pub type UpstreamFetchFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<u8>, UpstreamFetchError>> + Send + 'a>>;

/// 上游目录拉取端口：一次 GET 返回响应体字节。
pub trait UpstreamFetch: Send + Sync {
    fn fetch<'a>(&'a self, url: &'a str) -> UpstreamFetchFuture<'a>;
}

/// 生产实现：共享 `reqwest` 客户端 + Go `fetchJSON` 的重试/退避/体积上限。
#[derive(Clone, Copy, Debug, Default)]
pub struct HttpUpstream;

impl UpstreamFetch for HttpUpstream {
    fn fetch<'a>(&'a self, url: &'a str) -> UpstreamFetchFuture<'a> {
        Box::pin(async move {
            let attempts = env_i64("SYNC_HTTP_RETRY", DEFAULT_HTTP_RETRY).max(1);
            let max_bytes =
                (env_i64("SYNC_HTTP_MAX_MB", DEFAULT_HTTP_MAX_MB).max(1) << 20) as usize;
            let Some(client) = upstream_client() else {
                return Err(UpstreamFetchError::Transport);
            };
            let mut last_error = UpstreamFetchError::Transport;
            for attempt in 0..attempts {
                match fetch_once(client, url, max_bytes).await {
                    Ok(body) => return Ok(body),
                    Err(error) => last_error = error,
                }
                // Go：baseDelay(200ms) << attempt + 0..150ms 抖动。抖动用
                // 时钟纳秒近似（无 rand 依赖）。
                let backoff = 200u64 << attempt.min(6);
                let jitter = (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|value| value.subsec_nanos() % 150)
                    .unwrap_or(0)) as u64;
                tokio::time::sleep(Duration::from_millis(backoff + jitter)).await;
            }
            Err(last_error)
        })
    }
}

async fn fetch_once<'a>(
    client: &'a reqwest::Client,
    url: &'a str,
    max_bytes: usize,
) -> Result<Vec<u8>, UpstreamFetchError> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|_| UpstreamFetchError::Transport)?;
    if !response.status().is_success() {
        // Go 对非 200/304 也按可重试错误处理（resp.Status 文本）。
        return Err(UpstreamFetchError::Status);
    }
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(UpstreamFetchError::BodyTooLarge);
    }
    let mut body: Vec<u8> = Vec::new();
    let mut response = response;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| UpstreamFetchError::Transport)?
    {
        if body.len() + chunk.len() > max_bytes {
            return Err(UpstreamFetchError::BodyTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn upstream_client() -> Option<&'static reqwest::Client> {
    static CLIENT: OnceLock<Option<reqwest::Client>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            crate::turnstile::install_crypto_provider();
            let timeout = Duration::from_secs(
                env_i64("SYNC_HTTP_TIMEOUT_SECONDS", DEFAULT_CLIENT_TIMEOUT_SECONDS).max(1) as u64,
            );
            reqwest::Client::builder().timeout(timeout).build().ok()
        })
        .as_ref()
}

/// Go `common.GetEnvOrDefault`：缺省或非法值回落默认。
fn env_i64(key: &str, default: i64) -> i64 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.trim().parse::<i64>().ok())
        .unwrap_or(default)
}

/// Go `getUpstreamURLs`：base 取 `SYNC_UPSTREAM_BASE`（缺省
/// [`DEFAULT_UPSTREAM_BASE`]）后去尾部 `/`，locale 判定见
/// [`upstream_urls_for`]。
pub fn upstream_urls(locale: &str) -> (String, String) {
    let base =
        std::env::var("SYNC_UPSTREAM_BASE").unwrap_or_else(|_| DEFAULT_UPSTREAM_BASE.to_owned());
    upstream_urls_for(&base, locale)
}

/// Go `getUpstreamURLs` + `normalizeLocale` 的纯函数化。
///
/// locale 判定逐字复刻 Go 的怪癖：先 `ToLower(TrimSpace)` 再与**大小写
/// 敏感**的 `{"en","zh-CN","zh-TW","ja"}` 全等比较——小写后的输入不可能
/// 等于 `zh-CN`/`zh-TW` 字面量，因此只有全小写的 `en`/`ja`（以及恰为
/// `zh-CN` 字面但已被小写化的不可能输入）命中 i18n 路径，其余（含
/// `zh-CN`）落到默认目录。
pub(crate) fn upstream_urls_for(base: &str, locale: &str) -> (String, String) {
    let base = base.trim_end_matches('/');
    let normalized = locale.trim().to_ascii_lowercase();
    let localized = matches!(normalized.as_str(), "en" | "zh-CN" | "zh-TW" | "ja");
    if localized {
        (
            format!("{base}/api/i18n/{normalized}/newapi/models.json"),
            format!("{base}/api/i18n/{normalized}/newapi/vendors.json"),
        )
    } else {
        (
            format!("{base}/api/newapi/models.json"),
            format!("{base}/api/newapi/vendors.json"),
        )
    }
}

// ---------------------------------------------------------------------------
// 上游目录结构（Go `upstreamEnvelope` / `upstreamModel` / `upstreamVendor`）
// ---------------------------------------------------------------------------

/// Go `upstreamEnvelope`：字段全可缺省，`success`/`message` 仅参与 Go 的
/// 空值归一、不影响行为（fetch 不检查它们），这里只用于“信封 vs 数组”
/// 的形态判定。
#[derive(Deserialize)]
#[serde(bound(deserialize = "T: serde::de::DeserializeOwned"))]
#[allow(dead_code)]
struct UpstreamEnvelope<T> {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    data: Option<Vec<T>>,
}

/// Go `upstreamModel`。字段用 `Option` 复刻 Go 的 null 容忍（`null` 与缺失
/// 同为零值），类型不匹配仍然整体解码失败。
#[derive(Clone, Debug, Default, Deserialize)]
pub struct UpstreamModel {
    #[serde(default)]
    description: Option<String>,
    /// Go `json.RawMessage`：接受任意 JSON，值本身不参与同步语义。
    #[serde(default)]
    #[allow(dead_code)]
    endpoints: Option<Value>,
    #[serde(default)]
    icon: Option<String>,
    #[serde(rename = "model_name", default)]
    model_name: Option<String>,
    #[serde(default)]
    name_rule: Option<i64>,
    #[serde(default)]
    status: Option<i64>,
    #[serde(default)]
    tags: Option<String>,
    #[serde(rename = "vendor_name", default)]
    vendor_name: Option<String>,
}

impl UpstreamModel {
    pub fn model_name(&self) -> &str {
        self.model_name.as_deref().unwrap_or("")
    }
    pub fn description(&self) -> &str {
        self.description.as_deref().unwrap_or("")
    }
    pub fn icon(&self) -> &str {
        self.icon.as_deref().unwrap_or("")
    }
    pub fn tags(&self) -> &str {
        self.tags.as_deref().unwrap_or("")
    }
    pub fn vendor_name(&self) -> &str {
        self.vendor_name.as_deref().unwrap_or("")
    }
    pub fn name_rule(&self) -> i64 {
        self.name_rule.unwrap_or(0)
    }
    pub fn status(&self) -> i64 {
        self.status.unwrap_or(0)
    }
}

/// Go `upstreamVendor`。
#[derive(Clone, Debug, Default, Deserialize)]
pub struct UpstreamVendor {
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    icon: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    status: Option<i64>,
}

impl UpstreamVendor {
    pub fn name(&self) -> &str {
        self.name.as_deref().unwrap_or("")
    }
    pub fn description(&self) -> &str {
        self.description.as_deref().unwrap_or("")
    }
    pub fn icon(&self) -> &str {
        self.icon.as_deref().unwrap_or("")
    }
    pub fn status(&self) -> i64 {
        self.status.unwrap_or(0)
    }
}

/// Go `fetchJSON` 的解码：信封优先，退回纯数组；字面 `null` 按 Go 的零值
/// 信封语义视为空列表（encoding/json 对 null 是无操作，serde 会报错，需
/// 显式分流）。信封的 `success:false` 不影响结果（Go 不检查）。
pub(crate) fn parse_upstream<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
) -> Result<Vec<T>, UpstreamFetchError> {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Err(UpstreamFetchError::Decode);
    }
    if serde_json::from_slice::<serde_json::Value>(bytes).is_ok_and(|envelope| envelope.is_null()) {
        return Ok(Vec::new());
    }
    if let Ok(envelope) = serde_json::from_slice::<UpstreamEnvelope<T>>(bytes) {
        return Ok(envelope.data.unwrap_or_default());
    }
    if let Ok(list) = serde_json::from_slice::<Vec<T>>(bytes) {
        return Ok(list);
    }
    Err(UpstreamFetchError::Decode)
}

/// Go `coalesce`（`handle_model_sync.go:481`）：空白字符串回落到空串。
fn coalesce_str(value: &str) -> String {
    if !value.trim().is_empty() {
        return value.to_owned();
    }
    String::new()
}

// ---------------------------------------------------------------------------
// 同步请求体（Go `syncRequest` / `overwriteField`）
// ---------------------------------------------------------------------------

/// Go `overwriteField`。
#[derive(Clone, Debug, Default, Deserialize)]
pub struct OverwriteField {
    #[serde(rename = "model_name", default)]
    pub model_name: Option<String>,
    #[serde(default)]
    pub fields: Vec<String>,
}

impl OverwriteField {
    pub fn model_name(&self) -> &str {
        self.model_name.as_deref().unwrap_or("")
    }
}

/// Go `syncRequest`：绑定失败/空体回退零值（Go `_ = c.BindJSON(&req)`）。
#[derive(Clone, Debug, Default, Deserialize)]
pub struct SyncRequest {
    #[serde(default)]
    pub overwrite: Vec<OverwriteField>,
    #[serde(default)]
    pub locale: Option<String>,
}

impl SyncRequest {
    pub fn locale(&self) -> &str {
        self.locale.as_deref().unwrap_or("")
    }
}

// ---------------------------------------------------------------------------
// 查询参数（与 `channel_http` 同语义的本地副本：`+` 为空格、`%XX` 按字节解码）
// ---------------------------------------------------------------------------

fn query_pairs(uri: &Uri) -> Vec<(String, String)> {
    let Some(query) = uri.query() else {
        return Vec::new();
    };
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (percent_decode(key), percent_decode(value))
        })
        .collect()
}

fn query_value(pairs: &[(String, String)], key: &str) -> Option<String> {
    pairs
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.clone())
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                match (hex_value(bytes[index + 1]), hex_value(bytes[index + 2])) {
                    (Some(high), Some(low)) => {
                        out.push(high * 16 + low);
                        index += 3;
                    }
                    _ => {
                        out.push(b'%');
                        index += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Go `common.GetPageQuery`（`page_info.go:36`）：`p`/`page_size` 优先，
/// `ps`/`size` 兼容，页大小缺省 10、上限 100；负值如实透传（Go 不做
/// page_size 下限钳制，负 LIMIT 的差异由数据库报错路径承接）。
pub fn go_page_info(pairs: &[(String, String)]) -> (i64, i64) {
    let mut page = parse_i64(query_value(pairs, "p").as_deref()).unwrap_or(0);
    let mut page_size = parse_i64(query_value(pairs, "page_size").as_deref()).unwrap_or(0);
    if page < 1 {
        // Go 的兼容分支：重新读一次 `p`，非零才用（与首次解析相同值）。
        let compat = parse_i64(query_value(pairs, "p").as_deref()).unwrap_or(0);
        page = if compat != 0 { compat } else { 1 };
    }
    if page_size == 0 {
        if let Some(value) = parse_i64(query_value(pairs, "ps").as_deref())
            && value != 0
        {
            page_size = value;
        }
        if page_size == 0
            && let Some(value) = parse_i64(query_value(pairs, "size").as_deref())
            && value != 0
        {
            page_size = value;
        }
        if page_size == 0 {
            page_size = 10;
        }
    }
    if page_size > 100 {
        page_size = 100;
    }
    (page, page_size)
}

/// Go `strconv.Atoi`：可选符号加十进制数字，无空白。
fn parse_i64(value: Option<&str>) -> Option<i64> {
    value.and_then(|value| value.parse::<i64>().ok())
}

// ---------------------------------------------------------------------------
// 响应组装
// ---------------------------------------------------------------------------

fn success_with_message(data: Value) -> Response {
    Json(json!({"success": true, "message": "", "data": data})).into_response()
}

/// Go `common.H{"success": true, "data": ...}`（无 `message` 键）：
/// `GET /api/models` 与 `GET /api/models/missing` 的形态。
fn success_bare(data: Value) -> Response {
    Json(json!({"success": true, "data": data})).into_response()
}

fn api_error(headers: &HeaderMap, key: &str) -> Response {
    Json(json!({
        "success": false,
        "message": translate(headers, key),
    }))
    .into_response()
}

/// Go `handle_model_sync.go:326` 的上游失败体：固定文案 + locale +
/// 两个来源 URL（Go 额外拼接的错误原文按安全约定收敛进日志）。
fn upstream_error(
    headers: &HeaderMap,
    key: &str,
    locale: &str,
    models_url: &str,
    vendors_url: &str,
) -> Response {
    Json(json!({
        "success": false,
        "message": translate(headers, key),
        "locale": locale,
        "source_urls": {"models_url": models_url, "vendors_url": vendors_url},
    }))
    .into_response()
}

fn request_language(headers: &HeaderMap) -> String {
    let accept_language = crate::request_lang::accept_language_header(headers);
    crate::request_lang::request_language(accept_language.as_deref())
}

fn translate(headers: &HeaderMap, key: &str) -> String {
    newapi_i18n::translate(
        &request_language(headers),
        key,
        std::iter::empty::<(&str, &str)>(),
    )
}

/// Go `Model` 的 JSON 形态（键集与 omitempty 语义逐字对齐）：
/// `description`/`icon`/`tags`/`vendor_id`/`endpoints`/`bound_channels`
/// 为空时省略；`status`/`sync_official`/`created_time`/`updated_time`/
/// `name_rule` 恒在。`enable_groups`/`quota_types`/`matched_models`/
/// `matched_count` 属定价缓存裁剪，恒省略。
pub(crate) fn model_value(row: &ModelRow, bound_channels: Option<&[BoundChannel]>) -> Value {
    let mut object = Map::new();
    object.insert("id".to_owned(), json!(row.id));
    object.insert("model_name".to_owned(), json!(row.model_name));
    if !row.description.is_empty() {
        object.insert("description".to_owned(), json!(row.description));
    }
    if !row.icon.is_empty() {
        object.insert("icon".to_owned(), json!(row.icon));
    }
    if !row.tags.is_empty() {
        object.insert("tags".to_owned(), json!(row.tags));
    }
    if row.vendor_id != 0 {
        object.insert("vendor_id".to_owned(), json!(row.vendor_id));
    }
    if !row.endpoints.is_empty() {
        object.insert("endpoints".to_owned(), json!(row.endpoints));
    }
    object.insert("status".to_owned(), json!(row.status));
    object.insert("sync_official".to_owned(), json!(row.sync_official));
    object.insert("created_time".to_owned(), json!(row.created_time));
    object.insert("updated_time".to_owned(), json!(row.updated_time));
    if let Some(channels) = bound_channels
        && !channels.is_empty()
    {
        object.insert(
            "bound_channels".to_owned(),
            json!(
                channels
                    .iter()
                    .map(|channel| json!({"name": channel.name, "type": channel.channel_type}))
                    .collect::<Vec<_>>()
            ),
        );
    }
    object.insert("name_rule".to_owned(), json!(row.name_rule));
    Value::Object(object)
}

/// `enrichModels` 的可行化版本：绑定渠道批量查询失败按 Go 的吞错语义
/// （`channelsByModel, _ :=`）继续，只是不带 `bound_channels`。精确模型
/// （name_rule=0）的 `endpoints` 为空时按空定价缓存语义填 `"[]"`。
async fn enriched_values(repo: &ModelRepository, rows: &[ModelRow]) -> Vec<Value> {
    let exact: Vec<String> = rows
        .iter()
        .filter(|row| row.name_rule == NAME_RULE_EXACT)
        .map(|row| row.model_name.clone())
        .collect();
    let bound = match repo.bound_channels_by_models(&exact).await {
        Ok(map) => map,
        Err(error) => {
            tracing::warn!(
                event = "model_bound_channels_load_failed",
                category = crate::database_error_class(&error),
                "model bound channels load failed"
            );
            BTreeMap::new()
        }
    };
    rows.iter()
        .map(|row| {
            let mut enriched = row.clone();
            let mut bound_channels = None;
            if row.name_rule == NAME_RULE_EXACT {
                if enriched.endpoints.is_empty() {
                    enriched.endpoints = "[]".to_owned();
                }
                if let Some(channels) = bound.get(&row.model_name) {
                    bound_channels = Some(channels.as_slice());
                }
            }
            model_value(&enriched, bound_channels)
        })
        .collect()
}

/// Go `GetVendorModelCounts` 的 JSON 形态：`map[int64]int64` → 字符串键
/// 对象；空表是 `{}`。
fn vendor_counts_value(counts: &[(i64, i64)]) -> Value {
    let mut object = Map::new();
    for (vendor_id, count) in counts {
        object.insert(vendor_id.to_string(), json!(count));
    }
    Value::Object(object)
}

/// 请求体绑定的 `ModelInput` → 用于回显响应的行（Go 返回 `&m`：绑定值 +
/// 后填的时间戳）。`created_time`/`updated_time` 只随请求体回显
/// （`update` 的 `Select(...)` 不写这两列）。
fn input_row(input: &ModelInput, updated_time: i64) -> ModelRow {
    ModelRow {
        id: input.id.unwrap_or(0),
        model_name: input.model_name.clone().unwrap_or_default(),
        description: input.description.clone().unwrap_or_default(),
        icon: input.icon.clone().unwrap_or_default(),
        tags: input.tags.clone().unwrap_or_default(),
        vendor_id: input.vendor_id.unwrap_or(0),
        endpoints: input.endpoints.clone().unwrap_or_default(),
        status: input.status.unwrap_or(0),
        sync_official: input.sync_official.unwrap_or(0),
        created_time: input.created_time.unwrap_or(0),
        updated_time,
        name_rule: input.name_rule.unwrap_or(0),
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /api/models`：Go `DashboardListModels`（`UserAuth`）。静态目录，
/// 不触库；成功体没有 `message` 键。
pub async fn dashboard_models() -> Response {
    success_bare(newapi_catalog::models::dashboard::dashboard_models())
}

/// `GET /api/models/meta`：Go `ops.ListModels`。
pub async fn list_models(State(state): State<AppState>, headers: HeaderMap, uri: Uri) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let pairs = query_pairs(&uri);
    let (page, page_size) = go_page_info(&pairs);
    let status = parse_status_filter(&query_value(&pairs, "status").unwrap_or_default());
    let sync_official =
        parse_sync_filter(&query_value(&pairs, "sync_official").unwrap_or_default());
    let repository = ModelRepository::new(db);
    let (rows, total) = match repository
        .search(
            "",
            "",
            status,
            sync_official,
            (page - 1) * page_size,
            page_size,
        )
        .await
    {
        Ok(result) => result,
        Err(error) => {
            tracing::warn!(
                event = "model_list_failed",
                category = crate::database_error_class(&error),
                "model list query failed"
            );
            return api_error(&headers, MSG_LIST_FAILED);
        }
    };
    let items = enriched_values(&repository, &rows).await;
    // Go `vendorCounts, _ :=`：计数失败以 null 呈现，不影响整体成功。
    let vendor_counts = match repository.vendor_counts().await {
        Ok(counts) => vendor_counts_value(&counts),
        Err(error) => {
            tracing::warn!(
                event = "model_vendor_counts_failed",
                category = crate::database_error_class(&error),
                "model vendor counts failed"
            );
            Value::Null
        }
    };
    Json(json!({
        "success": true,
        "message": "",
        "data": {
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size,
            "vendor_counts": vendor_counts,
        }
    }))
    .into_response()
}

/// `GET /api/models/search`：Go `ops.SearchModels`（keyword + vendor 过滤，
/// 其余同列表）。响应形态与列表完全一致。
pub async fn search_models(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let pairs = query_pairs(&uri);
    let (page, page_size) = go_page_info(&pairs);
    let keyword = query_value(&pairs, "keyword").unwrap_or_default();
    let vendor = query_value(&pairs, "vendor").unwrap_or_default();
    let status = parse_status_filter(&query_value(&pairs, "status").unwrap_or_default());
    let sync_official =
        parse_sync_filter(&query_value(&pairs, "sync_official").unwrap_or_default());
    let repository = ModelRepository::new(db);
    let (rows, total) = match repository
        .search(
            &keyword,
            &vendor,
            status,
            sync_official,
            (page - 1) * page_size,
            page_size,
        )
        .await
    {
        Ok(result) => result,
        Err(error) => {
            tracing::warn!(
                event = "model_search_failed",
                category = crate::database_error_class(&error),
                "model search query failed"
            );
            return api_error(&headers, MSG_LIST_FAILED);
        }
    };
    let items = enriched_values(&repository, &rows).await;
    let vendor_counts = match repository.vendor_counts().await {
        Ok(counts) => vendor_counts_value(&counts),
        Err(error) => {
            tracing::warn!(
                event = "model_vendor_counts_failed",
                category = crate::database_error_class(&error),
                "model vendor counts failed"
            );
            Value::Null
        }
    };
    Json(json!({
        "success": true,
        "message": "",
        "data": {
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size,
            "vendor_counts": vendor_counts,
        }
    }))
    .into_response()
}

/// `GET /api/models/{id}`：Go `ops.GetModel`。
pub async fn get_model(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(id) = id.parse::<i64>() else {
        return api_error(&headers, MSG_ID_FORMAT);
    };
    let repository = ModelRepository::new(db);
    let row = match repository.by_id(id).await {
        Ok(Some(row)) => row,
        Ok(None) => return api_error(&headers, MSG_NOT_EXISTS),
        Err(error) => {
            tracing::warn!(
                event = "model_get_failed",
                category = crate::database_error_class(&error),
                "model get query failed"
            );
            return api_error(&headers, MSG_NOT_EXISTS);
        }
    };
    let items = enriched_values(&repository, std::slice::from_ref(&row)).await;
    success_with_message(items.into_iter().next().unwrap_or(Value::Null))
}

/// `POST /api/models/`：Go `ops.CreateModel`。
pub async fn create_model(State(state): State<AppState>, request: Request) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let (parts, body) = request.into_parts();
    let headers = parts.headers;
    let body = match to_bytes(body, MAX_BODY_BYTES).await {
        Ok(body) => body,
        Err(_) => return api_error(&headers, MSG_INVALID_PARAMS),
    };
    let input: ModelInput = match crate::body_bind::bind_body(&headers, &body) {
        Ok(input) => input,
        Err(()) => return api_error(&headers, MSG_INVALID_PARAMS),
    };
    let model_name = input.model_name.clone().unwrap_or_default();
    if model_name.is_empty() {
        return api_error(&headers, MSG_NAME_EMPTY);
    }
    let repository = ModelRepository::new(db);
    match repository.is_name_duplicated(0, &model_name).await {
        Ok(true) => return api_error(&headers, MSG_NAME_EXISTS),
        Ok(false) => {}
        Err(error) => {
            tracing::warn!(
                event = "model_dup_check_failed",
                category = crate::database_error_class(&error),
                "model duplicate check failed"
            );
            return api_error(&headers, MSG_SAVE_FAILED);
        }
    }
    let now = now_seconds();
    let new_model = NewModel {
        id: input.id,
        model_name,
        description: input.description.clone().unwrap_or_default(),
        icon: input.icon.clone().unwrap_or_default(),
        tags: input.tags.clone().unwrap_or_default(),
        vendor_id: input.vendor_id.unwrap_or(0),
        endpoints: input.endpoints.clone().unwrap_or_default(),
        status: input.status.unwrap_or(0),
        sync_official: input.sync_official.unwrap_or(0),
        name_rule: input.name_rule.unwrap_or(0),
    };
    let id = match repository.insert(&new_model, now).await {
        Ok(id) => id,
        Err(error) => {
            tracing::warn!(
                event = "model_insert_failed",
                category = crate::database_error_class(&error),
                "model insert failed"
            );
            return api_error(&headers, MSG_SAVE_FAILED);
        }
    };
    // Go 返回 `&m`：绑定值 + 新 id + 两个时间戳（insertWithTx 覆写）；
    // 无富化。
    let mut row = input_row(&input, now);
    row.id = id;
    row.created_time = now;
    success_with_message(model_value(&row, None))
}

/// `PUT /api/models/`：Go `ops.UpdateModel`（`?status_only=true` 只改
/// status 且不触碰 updated_time）。
pub async fn update_model(State(state): State<AppState>, request: Request) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let (parts, body) = request.into_parts();
    let headers = parts.headers;
    let pairs = query_pairs(&parts.uri);
    let status_only = query_value(&pairs, "status_only").as_deref() == Some("true");
    let body = match to_bytes(body, MAX_BODY_BYTES).await {
        Ok(body) => body,
        Err(_) => return api_error(&headers, MSG_INVALID_PARAMS),
    };
    let input: ModelInput = match crate::body_bind::bind_body(&headers, &body) {
        Ok(input) => input,
        Err(()) => return api_error(&headers, MSG_INVALID_PARAMS),
    };
    let id = input.id.unwrap_or(0);
    if id == 0 {
        return api_error(&headers, MSG_ID_MISSING);
    }
    let repository = ModelRepository::new(db);
    if status_only {
        if let Err(error) = repository
            .update_status(id, input.status.unwrap_or(0))
            .await
        {
            tracing::warn!(
                event = "model_update_status_failed",
                category = crate::database_error_class(&error),
                "model status update failed"
            );
            return api_error(&headers, MSG_SAVE_FAILED);
        }
        // Go 返回 `&m`，updated_time 不变。
        return success_with_message(model_value(&input_row(&input, 0), None));
    }
    let model_name = input.model_name.clone().unwrap_or_default();
    match repository.is_name_duplicated(id, &model_name).await {
        Ok(true) => return api_error(&headers, MSG_NAME_EXISTS),
        Ok(false) => {}
        Err(error) => {
            tracing::warn!(
                event = "model_dup_check_failed",
                category = crate::database_error_class(&error),
                "model duplicate check failed"
            );
            return api_error(&headers, MSG_SAVE_FAILED);
        }
    }
    let now = now_seconds();
    if let Err(error) = repository.update(&input, now).await {
        tracing::warn!(
            event = "model_update_failed",
            category = crate::database_error_class(&error),
            "model update failed"
        );
        return api_error(&headers, MSG_SAVE_FAILED);
    }
    // Go 返回 `&m`（updated_time 已刷新）；行不存在也是 0 行成功。
    success_with_message(model_value(&input_row(&input, now), None))
}

/// `DELETE /api/models/{id}`：Go `ops.DeleteModel`（先 `First` 校验存在，
/// 再软删除）。
pub async fn delete_model(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(id) = id.parse::<i64>() else {
        return api_error(&headers, MSG_ID_FORMAT);
    };
    let repository = ModelRepository::new(db);
    match repository.by_id(id).await {
        Ok(Some(_)) => {}
        Ok(None) => return api_error(&headers, MSG_NOT_EXISTS),
        Err(error) => {
            tracing::warn!(
                event = "model_get_failed",
                category = crate::database_error_class(&error),
                "model get query failed"
            );
            return api_error(&headers, MSG_NOT_EXISTS);
        }
    }
    if let Err(error) = repository.soft_delete(id, now_seconds()).await {
        tracing::warn!(
            event = "model_delete_failed",
            category = crate::database_error_class(&error),
            "model delete failed"
        );
        return api_error(&headers, MSG_SAVE_FAILED);
    }
    // Go `CtxApiSuccess(c, nil)`：data 显式为 null。
    Json(json!({"success": true, "message": "", "data": null})).into_response()
}

/// `GET /api/models/missing`：Go `handler.GetMissingModels`（成功体没有
/// `message` 键）。
pub async fn missing_models(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match missing_models_list(&db).await {
        Ok(missing) => success_bare(json!(missing)),
        Err(error) => {
            tracing::warn!(
                event = "model_missing_failed",
                category = crate::database_error_class(&error),
                "missing models query failed"
            );
            api_error(&headers, MSG_LIST_FAILED)
        }
    }
}

/// Go `channelpkg.GetMissingModels` 的可失败版本（abilities 读取与
/// models 表比对都会错；HTTP 层负责折叠）。
async fn missing_models_list(db: &newapi_storage::Database) -> Result<Vec<String>, sqlx::Error> {
    let enabled = enabled_models(db).await?;
    ModelRepository::new(db.clone())
        .missing_models(&enabled)
        .await
}

/// Go `ensureVendorID`（`handle_model_sync.go:237`）：缓存 → 按名查询 →
/// 补建（补建失败缓存 0，后续同名不再重试——Go 的 vendorIDCache 语义）。
async fn ensure_vendor(
    repository: &ModelRepository,
    vendor_name: &str,
    vendor_by_name: &BTreeMap<String, UpstreamVendor>,
    cache: &mut BTreeMap<String, i64>,
    created_vendors: &mut i64,
    now: i64,
) -> i64 {
    if vendor_name.is_empty() {
        return 0;
    }
    if let Some(id) = cache.get(vendor_name) {
        return *id;
    }
    if let Ok(Some(id)) = repository.vendor_id_by_name(vendor_name).await {
        cache.insert(vendor_name.to_owned(), id);
        return id;
    }
    let upstream = vendor_by_name.get(vendor_name);
    let description = upstream.map(|vendor| vendor.description()).unwrap_or("");
    let icon = upstream
        .map(|vendor| coalesce_str(vendor.icon()))
        .unwrap_or_default();
    let status = upstream
        .map(|vendor| choose_status(vendor.status(), 1))
        .unwrap_or(1);
    match repository
        .insert_vendor(vendor_name, description, &icon, status, now)
        .await
    {
        Ok(id) => {
            *created_vendors += 1;
            cache.insert(vendor_name.to_owned(), id);
            id
        }
        Err(_) => {
            cache.insert(vendor_name.to_owned(), 0);
            0
        }
    }
}

/// preview 的冲突字段计算（Go `SyncUpstreamPreview` 第 4 步的纯函数化）。
/// `local`/`upstream` 值：文本字段带原值（比较时两侧 trim），vendor 用名称，
/// `name_rule`/`status` 是整数（status 的 upstream 是上游原始值，不经过
/// `chooseStatus`）。
pub fn conflicts_for(
    locals: &[ModelRow],
    model_by_name: &BTreeMap<String, UpstreamModel>,
    vendor_names: &BTreeMap<i64, String>,
) -> Vec<Value> {
    let mut items = Vec::new();
    for local in locals {
        let Some(upstream) = model_by_name.get(&local.model_name) else {
            continue;
        };
        let mut fields: Vec<Value> = Vec::new();
        let mut push_field = |field: &str, local_value: Value, upstream_value: Value| {
            fields.push(json!({"field": field, "local": local_value, "upstream": upstream_value}));
        };
        if local.description.trim() != upstream.description().trim() {
            push_field(
                "description",
                json!(local.description),
                json!(upstream.description()),
            );
        }
        if local.icon.trim() != upstream.icon().trim() {
            push_field("icon", json!(local.icon), json!(upstream.icon()));
        }
        if local.tags.trim() != upstream.tags().trim() {
            push_field("tags", json!(local.tags), json!(upstream.tags()));
        }
        // vendor 对比使用名称（vendor_id=0 或未知 → 空名）。
        let local_vendor = vendor_names
            .get(&local.vendor_id)
            .map(String::as_str)
            .unwrap_or("");
        if local_vendor.trim() != upstream.vendor_name().trim() {
            push_field("vendor", json!(local_vendor), json!(upstream.vendor_name()));
        }
        if local.name_rule != upstream.name_rule() {
            push_field(
                "name_rule",
                json!(local.name_rule),
                json!(upstream.name_rule()),
            );
        }
        if local.status != choose_status(upstream.status(), local.status) {
            push_field("status", json!(local.status), json!(upstream.status()));
        }
        if !fields.is_empty() {
            items.push(json!({"model_name": local.model_name, "fields": fields}));
        }
    }
    items
}

/// Go 的 `var missing []string` / `var conflicts []conflictItem` 序列化：
/// 空为 `null`，非空为数组。
fn nil_when_empty(items: Vec<Value>) -> Value {
    if items.is_empty() {
        Value::Null
    } else {
        json!(items)
    }
}

/// `POST /api/models/sync_upstream`：Go `SyncUpstreamModels`。
pub async fn sync_upstream(State(state): State<AppState>, request: Request) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let (parts, body) = request.into_parts();
    let headers = parts.headers;
    let body = match to_bytes(body, MAX_BODY_BYTES).await {
        Ok(body) => body,
        Err(_) => return api_error(&headers, MSG_INVALID_PARAMS),
    };
    // Go 的整体上下文超时（15s）套住两次上游拉取。
    let deadline = Duration::from_secs(
        env_i64("SYNC_HTTP_TIMEOUT_SECONDS", DEFAULT_HANDLER_TIMEOUT_SECONDS).max(1) as u64,
    );
    match tokio::time::timeout(
        deadline,
        sync_upstream_with(&db, &headers, &body, &HttpUpstream),
    )
    .await
    {
        Ok(response) => response,
        Err(_) => api_error(&headers, MSG_UPSTREAM_FAILED),
    }
}

/// [`sync_upstream`] 的可注入实现（测试从外部传假 fetcher）。
pub async fn sync_upstream_with(
    db: &newapi_storage::Database,
    headers: &HeaderMap,
    body: &[u8],
    fetcher: &dyn UpstreamFetch,
) -> Response {
    // Go `_ = c.BindJSON(&req)`：绑定失败回退零值继续。
    let request = crate::body_bind::bind_body::<SyncRequest>(headers, body).unwrap_or_default();
    let locale = request.locale().to_owned();
    let (models_url, vendors_url) = upstream_urls(&locale);
    let repository = ModelRepository::new(db.clone());

    let missing = match missing_models_list(db).await {
        Ok(missing) => missing,
        Err(error) => {
            tracing::warn!(
                event = "model_missing_failed",
                category = crate::database_error_class(&error),
                "missing models query failed"
            );
            return api_error(headers, MSG_LIST_FAILED);
        }
    };

    // 既无缺失模型也无覆盖请求：不请求上游，直接返回零结果。
    if missing.is_empty() && request.overwrite.is_empty() {
        return success_with_message(sync_data(
            0,
            0,
            0,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            &locale,
            &models_url,
            &vendors_url,
        ));
    }

    let (vendors_result, models_result) =
        tokio::join!(fetcher.fetch(&vendors_url), fetcher.fetch(&models_url));
    let models = match models_result.and_then(|body| parse_upstream::<UpstreamModel>(&body)) {
        Ok(models) => models,
        Err(error) => {
            tracing::warn!(
                event = "upstream_models_fetch_failed",
                category = error.category(),
                "upstream models fetch failed"
            );
            return upstream_error(
                headers,
                MSG_UPSTREAM_FAILED,
                &locale,
                &models_url,
                &vendors_url,
            );
        }
    };
    // vendor 失败不拦截（Go 同样忽略 vendorsEnv 的错误）。
    let vendors = match vendors_result.and_then(|body| parse_upstream::<UpstreamVendor>(&body)) {
        Ok(vendors) => vendors,
        Err(error) => {
            tracing::warn!(
                event = "upstream_vendors_fetch_failed",
                category = error.category(),
                "upstream vendors fetch failed"
            );
            Vec::new()
        }
    };

    // Go 的 map 装配是“后者覆盖前者”（同名条目最后一条生效）。
    let mut vendor_by_name: BTreeMap<String, UpstreamVendor> = BTreeMap::new();
    for vendor in vendors {
        if !vendor.name().is_empty() {
            vendor_by_name.insert(vendor.name().to_owned(), vendor);
        }
    }
    let mut model_by_name: BTreeMap<String, UpstreamModel> = BTreeMap::new();
    for model in models {
        if !model.model_name().is_empty() {
            model_by_name.insert(model.model_name().to_owned(), model);
        }
    }

    let now = now_seconds();
    let mut created_models: i64 = 0;
    let mut created_vendors: i64 = 0;
    let mut updated_models: i64 = 0;
    let mut skipped: Vec<String> = Vec::new();
    let mut created_list: Vec<String> = Vec::new();
    let mut updated_list: Vec<String> = Vec::new();
    let mut vendor_cache: BTreeMap<String, i64> = BTreeMap::new();

    // 1) 缺失补建：上游没有的名字跳过；本地已有且 sync_official=0 的跳过；
    //    创建出来的模型 sync_official 恒为 0（Go 的 insertWithTx 会把未设
    //    字段的零值强制写回，这是可观察行为）。
    for name in &missing {
        let Some(upstream) = model_by_name.get(name) else {
            skipped.push(name.clone());
            continue;
        };
        match repository.by_name(name).await {
            Ok(Some(existing)) if existing.sync_official == 0 => {
                #[cfg(test)]
                eprintln!(
                    "models sync skipped {name}: local row with sync_official=0 (id {})",
                    existing.id
                );
                skipped.push(name.clone());
                continue;
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(
                    event = "model_lookup_failed",
                    category = crate::database_error_class(&error),
                    "model lookup failed during sync"
                );
                skipped.push(name.clone());
                continue;
            }
        }
        let vendor_id = ensure_vendor(
            &repository,
            upstream.vendor_name(),
            &vendor_by_name,
            &mut vendor_cache,
            &mut created_vendors,
            now,
        )
        .await;
        let new_model = NewModel {
            id: None,
            model_name: name.clone(),
            description: upstream.description().to_owned(),
            icon: upstream.icon().to_owned(),
            tags: upstream.tags().to_owned(),
            vendor_id,
            endpoints: String::new(),
            status: choose_status(upstream.status(), 1),
            sync_official: 0,
            name_rule: upstream.name_rule(),
        };
        match repository.insert(&new_model, now).await {
            Ok(_) => {
                created_models += 1;
                created_list.push(name.clone());
            }
            Err(error) => {
                #[cfg(test)]
                eprintln!("models sync insert failed for {name}: {error}");
                tracing::warn!(
                    event = "model_sync_insert_failed",
                    category = crate::database_error_class(&error),
                    "model insert failed during sync"
                );
                skipped.push(name.clone());
            }
        }
    }

    // 2) 覆盖更新：只碰 sync_official <> 0 的本地模型；tx.Save 全列覆写且
    //    不刷新 updated_time；保存失败 Go 吞错（无计数）。
    for overwrite in &request.overwrite {
        let name = overwrite.model_name();
        let Some(upstream) = model_by_name.get(name) else {
            continue;
        };
        let Ok(Some(mut local)) = repository.by_name(name).await else {
            continue;
        };
        if local.sync_official == 0 {
            continue;
        }
        let new_vendor_id = ensure_vendor(
            &repository,
            upstream.vendor_name(),
            &vendor_by_name,
            &mut vendor_cache,
            &mut created_vendors,
            now,
        )
        .await;
        let mut need_update = false;
        if contains_field(&overwrite.fields, "description") {
            local.description = upstream.description().to_owned();
            need_update = true;
        }
        if contains_field(&overwrite.fields, "icon") {
            local.icon = upstream.icon().to_owned();
            need_update = true;
        }
        if contains_field(&overwrite.fields, "tags") {
            local.tags = upstream.tags().to_owned();
            need_update = true;
        }
        if contains_field(&overwrite.fields, "vendor") {
            local.vendor_id = new_vendor_id;
            need_update = true;
        }
        if contains_field(&overwrite.fields, "name_rule") {
            local.name_rule = upstream.name_rule();
            need_update = true;
        }
        if contains_field(&overwrite.fields, "status") {
            local.status = choose_status(upstream.status(), local.status);
            need_update = true;
        }
        if !need_update {
            continue;
        }
        if repository.save_all(&local).await.is_ok() {
            updated_models += 1;
            updated_list.push(name.to_owned());
        }
    }

    success_with_message(sync_data(
        created_models,
        created_vendors,
        updated_models,
        skipped,
        created_list,
        updated_list,
        &locale,
        &models_url,
        &vendors_url,
    ))
}

/// sync 成功体的 `data`（键集对齐 Go）。
#[allow(clippy::too_many_arguments)]
fn sync_data(
    created_models: i64,
    created_vendors: i64,
    updated_models: i64,
    skipped_models: Vec<String>,
    created_list: Vec<String>,
    updated_list: Vec<String>,
    locale: &str,
    models_url: &str,
    vendors_url: &str,
) -> Value {
    json!({
        "created_models": created_models,
        "created_vendors": created_vendors,
        "updated_models": updated_models,
        "skipped_models": skipped_models,
        "created_list": created_list,
        "updated_list": updated_list,
        "source": {"locale": locale, "models_url": models_url, "vendors_url": vendors_url},
    })
}

/// `GET /api/models/sync_upstream/preview`：Go `SyncUpstreamPreview`。
pub async fn sync_upstream_preview(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    // Go 的整体上下文超时（15s）套住两次上游拉取。
    let deadline = Duration::from_secs(
        env_i64("SYNC_HTTP_TIMEOUT_SECONDS", DEFAULT_HANDLER_TIMEOUT_SECONDS).max(1) as u64,
    );
    match tokio::time::timeout(
        deadline,
        sync_upstream_preview_with(&db, &headers, &uri, &HttpUpstream),
    )
    .await
    {
        Ok(response) => response,
        Err(_) => api_error(&headers, MSG_UPSTREAM_FAILED),
    }
}

/// [`sync_upstream_preview`] 的可注入实现。
pub async fn sync_upstream_preview_with(
    db: &newapi_storage::Database,
    headers: &HeaderMap,
    uri: &Uri,
    fetcher: &dyn UpstreamFetch,
) -> Response {
    let pairs = query_pairs(uri);
    let locale = query_value(&pairs, "locale").unwrap_or_default();
    let (models_url, vendors_url) = upstream_urls(&locale);
    let repository = ModelRepository::new(db.clone());

    let (vendors_result, models_result) =
        tokio::join!(fetcher.fetch(&vendors_url), fetcher.fetch(&models_url));
    let models = match models_result.and_then(|body| parse_upstream::<UpstreamModel>(&body)) {
        Ok(models) => models,
        Err(error) => {
            tracing::warn!(
                event = "upstream_models_fetch_failed",
                category = error.category(),
                "upstream models fetch failed"
            );
            return upstream_error(
                headers,
                MSG_UPSTREAM_FAILED,
                &locale,
                &models_url,
                &vendors_url,
            );
        }
    };
    let vendors = match vendors_result.and_then(|body| parse_upstream::<UpstreamVendor>(&body)) {
        Ok(vendors) => vendors,
        Err(error) => {
            tracing::warn!(
                event = "upstream_vendors_fetch_failed",
                category = error.category(),
                "upstream vendors fetch failed"
            );
            Vec::new()
        }
    };

    let mut vendor_by_name: BTreeMap<String, UpstreamVendor> = BTreeMap::new();
    for vendor in vendors {
        if !vendor.name().is_empty() {
            vendor_by_name.insert(vendor.name().to_owned(), vendor);
        }
    }
    let mut model_by_name: BTreeMap<String, UpstreamModel> = BTreeMap::new();
    let mut upstream_names: Vec<String> = Vec::new();
    for model in models {
        if !model.model_name().is_empty() {
            upstream_names.push(model.model_name().to_owned());
            model_by_name.insert(model.model_name().to_owned(), model);
        }
    }

    // 本地 syncable 模型；查询失败 Go 吞错（`_ =`）→ 空列表。
    let locals = match repository.by_names_syncable(&upstream_names).await {
        Ok(locals) => locals,
        Err(error) => {
            tracing::warn!(
                event = "model_locals_load_failed",
                category = crate::database_error_class(&error),
                "local models load failed during preview"
            );
            Vec::new()
        }
    };

    // vendor 名称映射；错误同样吞掉。
    let vendor_ids: Vec<i64> = locals
        .iter()
        .filter(|local| local.vendor_id != 0)
        .map(|local| local.vendor_id)
        .collect();
    let vendor_names = match repository.vendor_names_by_ids(&vendor_ids).await {
        Ok(names) => names,
        Err(error) => {
            tracing::warn!(
                event = "vendor_names_load_failed",
                category = crate::database_error_class(&error),
                "vendor names load failed during preview"
            );
            BTreeMap::new()
        }
    };

    // 缺失 ∩ 上游（Go `missingList, _ :=` 吞错 → 空）。
    let missing_list = missing_models_list(db).await.unwrap_or_default();
    let missing: Vec<Value> = missing_list
        .into_iter()
        .filter(|name| model_by_name.contains_key(name))
        .map(Value::String)
        .collect();

    let conflicts = conflicts_for(&locals, &model_by_name, &vendor_names);
    Json(json!({
        "success": true,
        "message": "",
        "data": {
            "missing": nil_when_empty(missing),
            "conflicts": nil_when_empty(conflicts),
            "source": {"locale": locale, "models_url": models_url, "vendors_url": vendors_url},
        }
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// 纯函数单元测试（不触库、不路由）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_urls_localized_paths_only_for_exact_matches() {
        // Go 的怪癖：先 ToLower 再大小写敏感全等，zh-CN/zh-TW 永远走默认路径。
        let (models, vendors) = upstream_urls_for(DEFAULT_UPSTREAM_BASE, "zh-CN");
        assert_eq!(
            models,
            format!("{DEFAULT_UPSTREAM_BASE}/api/newapi/models.json")
        );
        assert_eq!(
            vendors,
            format!("{DEFAULT_UPSTREAM_BASE}/api/newapi/vendors.json")
        );
        let (models, _) = upstream_urls_for(DEFAULT_UPSTREAM_BASE, "en");
        assert_eq!(
            models,
            format!("{DEFAULT_UPSTREAM_BASE}/api/i18n/en/newapi/models.json")
        );
        let (models, _) = upstream_urls_for(DEFAULT_UPSTREAM_BASE, "  JA ");
        assert_eq!(
            models,
            format!("{DEFAULT_UPSTREAM_BASE}/api/i18n/ja/newapi/models.json")
        );
        let (models, _) = upstream_urls_for(DEFAULT_UPSTREAM_BASE, "");
        assert_eq!(
            models,
            format!("{DEFAULT_UPSTREAM_BASE}/api/newapi/models.json")
        );
    }

    #[test]
    fn upstream_urls_trim_base() {
        let (models, _) = upstream_urls_for("http://example.test/dir/", "en");
        assert_eq!(
            models,
            "http://example.test/dir/api/i18n/en/newapi/models.json"
        );
        let (models, _) = upstream_urls_for("http://example.test", "");
        assert_eq!(models, "http://example.test/api/newapi/models.json");
    }

    #[test]
    fn parse_upstream_accepts_envelope_array_and_null() {
        let envelope = br#"{"success":true,"message":"","data":[{"model_name":"a"}]}"#;
        let parsed = parse_upstream::<UpstreamModel>(envelope).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].model_name(), "a");
        // success:false 不影响结果（Go 不检查该字段）。
        let envelope = br#"{"success":false,"message":"x","data":[{"model_name":"b"}]}"#;
        assert_eq!(parse_upstream::<UpstreamModel>(envelope).unwrap().len(), 1);
        let array = br#"[{"model_name":"c","status":null}]"#;
        let parsed = parse_upstream::<UpstreamModel>(array).unwrap();
        assert_eq!(parsed[0].status(), 0);
        // Go：null 解码为零值信封 → 空数据。
        assert!(parse_upstream::<UpstreamModel>(b"null").unwrap().is_empty());
        assert_eq!(
            parse_upstream::<UpstreamModel>(b"not json").unwrap_err(),
            UpstreamFetchError::Decode
        );
        assert_eq!(
            parse_upstream::<UpstreamModel>(b"").unwrap_err(),
            UpstreamFetchError::Decode
        );
        // 类型不匹配整体失败（Go json.Unmarshal 的中止语义）。
        assert_eq!(
            parse_upstream::<UpstreamModel>(br#"{"data":[{"status":"x"}]}"#).unwrap_err(),
            UpstreamFetchError::Decode
        );
    }

    #[test]
    fn go_page_info_defaults_compat_and_cap() {
        assert_eq!(go_page_info(&[]), (1, 10));
        let pairs = vec![
            ("p".to_owned(), "3".to_owned()),
            ("page_size".to_owned(), "7".to_owned()),
        ];
        assert_eq!(go_page_info(&pairs), (3, 7));
        let pairs = vec![
            ("ps".to_owned(), "5".to_owned()),
            ("size".to_owned(), "9".to_owned()),
        ];
        assert_eq!(go_page_info(&pairs), (1, 5));
        let pairs = vec![("size".to_owned(), "9".to_owned())];
        assert_eq!(go_page_info(&pairs), (1, 9));
        let pairs = vec![("page_size".to_owned(), "500".to_owned())];
        assert_eq!(go_page_info(&pairs), (1, 100));
        // 负值如实透传（Go 不做下限钳制）。
        let pairs = vec![
            ("p".to_owned(), "-2".to_owned()),
            ("page_size".to_owned(), "-5".to_owned()),
        ];
        assert_eq!(go_page_info(&pairs), (-2, -5));
    }

    #[test]
    fn status_and_sync_filters_match_go() {
        assert_eq!(parse_status_filter(""), None);
        assert_eq!(parse_status_filter(" all "), None);
        assert_eq!(parse_status_filter("ENABLED"), Some(1));
        assert_eq!(parse_status_filter("1"), Some(1));
        assert_eq!(parse_status_filter("disabled"), Some(0));
        assert_eq!(parse_status_filter("0"), Some(0));
        assert_eq!(parse_status_filter("42"), Some(42));
        assert_eq!(parse_status_filter("bogus"), None);
        assert_eq!(parse_sync_filter("YES"), Some(1));
        assert_eq!(parse_sync_filter("no"), Some(0));
        assert_eq!(parse_sync_filter("zz"), None);
    }

    #[test]
    fn choose_status_falls_back_like_go() {
        assert_eq!(choose_status(0, 2), 2);
        assert_eq!(choose_status(3, 2), 3);
        assert_eq!(choose_status(0, 0), 1);
    }

    #[test]
    fn contains_field_is_trim_insensitive() {
        assert!(contains_field(&["Description".to_owned()], "description"));
        assert!(contains_field(&[" description ".to_owned()], "DESCRIPTION"));
        assert!(!contains_field(&["icons".to_owned()], "icon"));
    }

    #[test]
    fn model_value_matches_go_omitempty() {
        let row = ModelRow {
            id: 7,
            model_name: "gpt-x".to_owned(),
            description: "d".to_owned(),
            icon: String::new(),
            tags: String::new(),
            vendor_id: 0,
            endpoints: String::new(),
            status: 0,
            sync_official: 0,
            created_time: 100,
            updated_time: 200,
            name_rule: 0,
        };
        let value = model_value(&row, None);
        assert_eq!(value["id"], json!(7));
        assert_eq!(value["model_name"], json!("gpt-x"));
        assert_eq!(value["description"], json!("d"));
        assert!(value.get("icon").is_none());
        assert!(value.get("tags").is_none());
        assert!(value.get("vendor_id").is_none());
        assert!(value.get("endpoints").is_none());
        assert_eq!(value["status"], json!(0));
        assert_eq!(value["sync_official"], json!(0));
        assert_eq!(value["created_time"], json!(100));
        assert_eq!(value["updated_time"], json!(200));
        assert_eq!(value["name_rule"], json!(0));
        assert!(value.get("bound_channels").is_none());

        let bound = vec![BoundChannel {
            name: "ch-a".to_owned(),
            channel_type: 1,
        }];
        let mut enriched = row.clone();
        enriched.endpoints = "[]".to_owned();
        enriched.vendor_id = 3;
        let value = model_value(&enriched, Some(&bound));
        assert_eq!(value["endpoints"], json!("[]"));
        assert_eq!(value["vendor_id"], json!(3));
        assert_eq!(
            value["bound_channels"],
            json!([{"name": "ch-a", "type": 1}])
        );
        // 空绑定列表同样省略（Go nil/empty slice omitempty）。
        let value = model_value(&enriched, Some(&[]));
        assert!(value.get("bound_channels").is_none());
    }

    #[test]
    fn conflicts_for_trims_and_keeps_raw_status() {
        let upstream = UpstreamModel {
            description: Some(" up ".to_owned()),
            icon: Some("icon".to_owned()),
            model_name: Some("m1".to_owned()),
            name_rule: Some(1),
            status: Some(0),
            tags: Some(String::new()),
            vendor_name: Some("OpenAI".to_owned()),
            endpoints: None,
        };
        let model_by_name = BTreeMap::from([("m1".to_owned(), upstream)]);
        let local = ModelRow {
            id: 1,
            model_name: "m1".to_owned(),
            description: "up".to_owned(),
            icon: "icon".to_owned(),
            tags: String::new(),
            vendor_id: 5,
            endpoints: String::new(),
            status: 1,
            sync_official: 1,
            created_time: 0,
            updated_time: 0,
            name_rule: 1,
        };
        let vendor_names = BTreeMap::from([(5, "OpenAI".to_owned())]);
        // 全部一致（trim 后）→ 空冲突。
        assert!(
            conflicts_for(std::slice::from_ref(&local), &model_by_name, &vendor_names).is_empty()
        );
        // status：local=1、upstream=0 → choose(0,1)=1 一致；upstream 值取原始 0。
        let mut local = local;
        local.description = "different".to_owned();
        local.vendor_id = 0;
        let conflicts = conflicts_for(&[local], &model_by_name, &BTreeMap::new());
        assert_eq!(conflicts.len(), 1);
        let fields = conflicts[0]["fields"].as_array().unwrap();
        assert_eq!(fields[0]["field"], json!("description"));
        assert_eq!(fields[1]["field"], json!("vendor"));
        assert_eq!(fields[1]["local"], json!(""));
        assert_eq!(fields[1]["upstream"], json!("OpenAI"));
        assert_eq!(fields.len(), 2);
    }

    #[test]
    fn conflicts_skip_models_missing_upstream() {
        let local = ModelRow {
            model_name: "unknown".to_owned(),
            ..ModelRow::default()
        };
        assert!(conflicts_for(&[local], &BTreeMap::new(), &BTreeMap::new()).is_empty());
    }

    #[test]
    fn query_pairs_decode_plus_and_percent() {
        let uri: Uri = "/api/models/search?keyword=a+b%20c&vendor=1"
            .parse()
            .unwrap();
        let pairs = query_pairs(&uri);
        assert_eq!(query_value(&pairs, "keyword").as_deref(), Some("a b c"));
        assert_eq!(query_value(&pairs, "vendor").as_deref(), Some("1"));
        assert!(query_value(&pairs, "missing").is_none());
    }

    #[test]
    fn sync_request_defaults_on_empty_body() {
        let headers = HeaderMap::new();
        let request = crate::body_bind::bind_body::<SyncRequest>(&headers, b"").unwrap();
        assert!(request.overwrite.is_empty());
        assert_eq!(request.locale(), "");
    }
}
