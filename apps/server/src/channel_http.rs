//! `/api/channel/*` 基础 CRUD 的 HTTP 适配。
//!
//! Go 参考：
//! - `transport/handler/handle_channel.go`：`GetAllChannels`、`SearchChannels`、
//!   `GetChannel`、`AddChannel`、`UpdateChannel`、`DeleteChannel`、
//!   `DeleteDisabledChannel`、`DeleteChannelBatch`
//! - `transport/handler/handle_channel_authz.go`：敏感字段判定与字段分类表
//! - `transport/compose/register_channels.go`：`AdminAuth()` 组级鉴权 +
//!   路由级 `RequirePermission(...)`（handler 内的敏感写升级为
//!   `CtxApiErrorI18n`，即 HTTP 200 `success:false`；中间件拒绝是 403）
//!
//! 与 Go 的响应契约：
//! - 全部业务结果 HTTP 200 + `{"success":bool,"message":...}` 信封；
//!   401/403 只来自鉴权链。
//! - 列表/搜索/详情路径不读 `key` 列（Go `Omit("key")`），响应里 `key`
//!   固定为空字符串（JSON tag 无 omitempty）。
//! - 更新成功返回重载的渠道行，`key` 置空（Go `channel.Key = ""`）。
//! - Go 的中文/英文裸消息在此经 `newapi_i18n` 翻译，键值见
//!   `crates/i18n/locales/*`（zh 目录保留 Go 原文字面量）。
//!
//! 范围裁剪（后续切片）：渠道缓存刷新（`InitChannelCache`）、代理客户端
//! 失效（`egress`）、网关路由版本号与 `channel_model_routes`/健康表联动
//! 不在本切片；审计按 Go 写入 `logs`（`channel.*` 动作）。

use std::collections::BTreeMap;

use axum::{
    Json,
    body::to_bytes,
    extract::{ConnectInfo, Extension, Path, Request, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use newapi_catalog::channels::{
    self, CHANNEL_STATUS_ENABLED, CHANNEL_TYPE_VERTEX_AI, ChannelInfo, ChannelInput,
    ChannelListFilter, ChannelPatch, ChannelRepository, ChannelRow, ChannelSort, KeyParseError,
    MASKED_CHANNEL_KEY, StatusFilter, ValidationError,
};
use newapi_identity::{
    audit::{AuditOperator, record_manage_audit_with_params},
    policy::{CasbinRuleRepository, Permission, can},
    self_user::QuotaDisplaySettings,
};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::AppState;
use crate::auth::AuthenticatedUser;
use crate::http::{MAX_BODY_BYTES, now_seconds, request_ip};

/// Go `policy.Permission{Resource: ResourceChannel, Action: ActionRead}`。
const CHANNEL_READ: Permission = Permission {
    resource: "channel",
    action: "read",
};
/// Go `policy.Permission{...ActionWrite}`。
const CHANNEL_WRITE: Permission = Permission {
    resource: "channel",
    action: "write",
};
/// Go `policy.Permission{...ActionSensitiveWrite}`。
const CHANNEL_SENSITIVE_WRITE: Permission = Permission {
    resource: "channel",
    action: "sensitive_write",
};

const MSG_INVALID_PARAMS: &str = "common.invalid_params";
const MSG_DATABASE_ERROR: &str = "common.database_error";
const MSG_INSUFFICIENT_PRIVILEGE: &str = "auth.insufficient_privilege";
const MSG_NOT_EXISTS: &str = "channel.not_exists";
const MSG_ID_FORMAT: &str = "channel.id_format_error";
const MSG_LIST_FAILED: &str = "channel.get_list_failed";
const MSG_COUNT_FAILED: &str = "channel.get_count_failed";
const MSG_TAGS_FAILED: &str = "channel.get_tags_failed";
const MSG_TAG_COUNT_FAILED: &str = "channel.get_tag_count_failed";
const MSG_TAG_CHANNELS_FAILED: &str = "channel.get_tag_channels_failed";
const MSG_TYPE_COUNTS_FAILED: &str = "channel.get_type_counts_failed";
const MSG_SEARCH_FAILED: &str = "channel.query_failed";
const MSG_CHANNEL_REQUIRED: &str = "channel.channel_required";
const MSG_MODEL_TOO_LONG: &str = "channel.model_name_too_long";
const MSG_UNSUPPORTED_MODE: &str = "channel.unsupported_add_mode";
const MSG_NEW_API_BASE_URL: &str = "channel.new_api_base_url_required";
const MSG_SETTING_INVALID: &str = "channel.setting_invalid";
const MSG_VERTEX_REGION_REQUIRED: &str = "channel.deployment_region_required";
const MSG_VERTEX_REGION_FORMAT: &str = "channel.deployment_region_format";
const MSG_VERTEX_REGION_DEFAULT: &str = "channel.deployment_region_default";
const MSG_CODEX_FORMAT: &str = "channel.codex_key_format";
const MSG_CODEX_ACCESS_TOKEN: &str = "channel.codex_key_access_token_required";
const MSG_CODEX_ACCOUNT_ID: &str = "channel.codex_key_account_id_required";
const MSG_APPEND_PARSE_FAILED: &str = "channel.append_key_parse_failed";

/// Go `policy.Can`：策略读取失败按 Go 的 nil enforcer 路径拒绝。
async fn permission_allowed(
    state: &AppState,
    user: &AuthenticatedUser,
    permission: Permission,
) -> bool {
    let Some(db) = state.db() else {
        return false;
    };
    match can(
        &CasbinRuleRepository::new(db),
        user.0.user_id,
        user.0.role as i32,
        permission,
    )
    .await
    {
        Ok(allowed) => allowed,
        Err(error) => {
            tracing::warn!(
                event = "channel_policy_load_failed",
                category = crate::database_error_class(&error),
                "channel policy load failed; denying"
            );
            false
        }
    }
}

/// Go 路由级 `security.RequirePermission`：403 + `success:false` + i18n 消息。
async fn require_permission(
    state: &AppState,
    user: &AuthenticatedUser,
    permission: Permission,
    headers: &HeaderMap,
) -> Result<(), Response> {
    if permission_allowed(state, user, permission).await {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "success": false,
                "message": translate(headers, MSG_INSUFFICIENT_PRIVILEGE),
            })),
        )
            .into_response())
    }
}

/// Go `common.GetPageQuery`：`p`/`page_size` 与 `ps`/`size` 兼容别名，
/// 上限 100，缺省 10（`common.ItemsPerPage`）。
fn go_page_info(query: &ChannelQuery) -> (i64, i64) {
    let mut page = parse_i64(query.p.as_deref()).unwrap_or(0);
    let mut page_size = parse_i64(query.page_size.as_deref()).unwrap_or(0);
    if page < 1 {
        let compat = parse_i64(query.p.as_deref()).unwrap_or(0);
        page = if compat != 0 { compat } else { 1 };
    }
    if page_size == 0 {
        if let Some(value) = parse_i64(query.ps.as_deref())
            && value != 0
        {
            page_size = value;
        }
        if page_size == 0
            && let Some(value) = parse_i64(query.size.as_deref())
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

/// Go/axum 查询解码（`+` 为空格、`%XX` 按字节解码），与
/// `token_http::query_pairs` 同语义。
fn query_pairs(uri: &axum::http::Uri) -> Vec<(String, String)> {
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

/// 列表/搜索共用的查询参数。
#[derive(Debug, Default)]
struct ChannelQuery {
    p: Option<String>,
    page_size: Option<String>,
    ps: Option<String>,
    size: Option<String>,
    keyword: Option<String>,
    group: Option<String>,
    model: Option<String>,
    status: Option<String>,
    type_: Option<String>,
    sort_by: Option<String>,
    sort_order: Option<String>,
    tag_mode: Option<String>,
}

fn channel_query(uri: &axum::http::Uri) -> ChannelQuery {
    let pairs = query_pairs(uri);
    let get = |key: &str| {
        pairs
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.clone())
    };
    ChannelQuery {
        p: get("p"),
        page_size: get("page_size"),
        ps: get("ps"),
        size: get("size"),
        keyword: get("keyword"),
        group: get("group"),
        model: get("model"),
        status: get("status"),
        type_: get("type"),
        sort_by: get("sort_by"),
        sort_order: get("sort_order"),
        tag_mode: get("tag_mode"),
    }
}

/// Go `parseStatusFilter`。
fn status_filter(raw: &Option<String>) -> StatusFilter {
    match raw
        .as_deref()
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("enabled") | Some("1") => StatusFilter::Enabled,
        Some("disabled") | Some("0") => StatusFilter::Disabled,
        _ => StatusFilter::All,
    }
}

/// Go 的 `typeFilter`：非空且 `Atoi` 成功才生效，其余（含非法值）为 -1。
fn type_filter(raw: &Option<String>) -> Option<i64> {
    raw.as_deref()
        .filter(|v| !v.is_empty())
        .and_then(|v| v.parse::<i64>().ok())
}

fn sort(query: &ChannelQuery) -> ChannelSort {
    // `id_sort` 与默认值在 Go 里都落到 `id desc`，无需单独解析。
    channels::store::resolve_sort(
        query.sort_by.as_deref().unwrap_or(""),
        query.sort_order.as_deref().unwrap_or(""),
    )
}

/// `GET /api/channel/`：Go `GetAllChannels`。
///
/// 响应 `data`：`items` / `total` / `page` / `page_size` / `type_counts`；
/// 标签模式的 `total` 是标签数量，`items` 为这些标签下的全部渠道。
pub async fn list_channels(
    State(state): State<AppState>,
    Extension(admin_user): Extension<AuthenticatedUser>,
    uri: axum::http::Uri,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if let Err(response) = require_permission(&state, &admin_user, CHANNEL_READ, &headers).await {
        return response;
    }
    let query = channel_query(&uri);
    let (page, page_size) = go_page_info(&query);
    let group = channels::store::normalize_group_filter(query.group.as_deref().unwrap_or(""));
    let status = status_filter(&query.status);
    let type_ = type_filter(&query.type_);
    let sort = sort(&query);
    let tag_mode = channels::store::parse_go_bool(query.tag_mode.as_deref());
    let repository = ChannelRepository::new(db);
    let filter = ChannelListFilter {
        group: group.clone(),
        status,
        channel_type: type_,
    };

    let mut channels: Vec<ChannelRow> = Vec::new();
    let total = if tag_mode {
        let tags = match repository
            .tags(&filter, (page - 1) * page_size, page_size)
            .await
        {
            Ok(tags) => tags,
            Err(error) => return database_error(&headers, &error, MSG_TAGS_FAILED),
        };
        let total = match repository.count_tags(&filter).await {
            Ok(total) => total,
            Err(error) => return database_error(&headers, &error, MSG_TAG_COUNT_FAILED),
        };
        for tag in &tags {
            if tag.is_empty() {
                continue;
            }
            match repository.list_by_tag(&filter, tag, sort).await {
                Ok(rows) => channels.extend(rows),
                Err(error) => return database_error(&headers, &error, MSG_TAG_CHANNELS_FAILED),
            }
        }
        total
    } else {
        let total = match repository.count(&filter).await {
            Ok(total) => total,
            Err(error) => return database_error(&headers, &error, MSG_COUNT_FAILED),
        };
        match repository
            .list(&filter, sort, (page - 1) * page_size, page_size)
            .await
        {
            Ok(rows) => channels = rows,
            Err(error) => return database_error(&headers, &error, MSG_LIST_FAILED),
        }
        total
    };

    // `type_counts` 固定不含 type 过滤（Go 传 -1）。
    let type_counts = match repository.type_counts(&group, status).await {
        Ok(counts) => counts,
        Err(error) => return database_error(&headers, &error, MSG_TYPE_COUNTS_FAILED),
    };

    let display = state.quota_display();
    let items: Vec<Value> = channels
        .iter()
        .map(|row| channel_json(clear_channel_info(row), &display))
        .collect();
    Json(json!({
        "success": true,
        "message": "",
        "data": {
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size,
            "type_counts": type_counts_json(&type_counts),
        }
    }))
    .into_response()
}

/// `GET /api/channel/search`：Go `SearchChannels`。
///
/// 响应 `data` 只有 `items` / `total` / `type_counts`（无 page/page_size），
/// 分页在内存切片，默认 page_size 20（无 100 上限）。
pub async fn search_channels(
    State(state): State<AppState>,
    Extension(admin_user): Extension<AuthenticatedUser>,
    uri: axum::http::Uri,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if let Err(response) = require_permission(&state, &admin_user, CHANNEL_READ, &headers).await {
        return response;
    }
    let query = channel_query(&uri);
    let repository = ChannelRepository::new(db);
    let group = channels::store::normalize_group_filter(query.group.as_deref().unwrap_or(""));
    let status = status_filter(&query.status);
    let type_ = type_filter(&query.type_);
    let sort = sort(&query);
    let tag_mode = channels::store::parse_go_bool(query.tag_mode.as_deref());
    let keyword = query.keyword.clone().unwrap_or_default();
    let model = query.model.clone().unwrap_or_default();

    let mut channels: Vec<ChannelRow> = if tag_mode {
        let tags = match repository.search_tags(&keyword, &group, &model).await {
            Ok(tags) => tags,
            Err(error) => return database_error(&headers, &error, MSG_SEARCH_FAILED),
        };
        let mut rows = Vec::new();
        // 标签模式下的渠道查询不带 status/type 过滤（Go 传 -1），过滤在
        // 内存完成。
        let tag_filter = ChannelListFilter {
            group: group.clone(),
            status: StatusFilter::All,
            channel_type: None,
        };
        for tag in &tags {
            if tag.is_empty() {
                continue;
            }
            match repository.list_by_tag(&tag_filter, tag, sort).await {
                Ok(rows_for_tag) => rows.extend(rows_for_tag),
                Err(error) => return database_error(&headers, &error, MSG_SEARCH_FAILED),
            }
        }
        rows
    } else {
        match repository.search(&keyword, &group, &model, sort).await {
            Ok(rows) => rows,
            Err(error) => return database_error(&headers, &error, MSG_SEARCH_FAILED),
        }
    };

    // 内存 status 过滤（两种模式共用）。
    channels.retain(|row| match status {
        StatusFilter::Enabled => row.status == CHANNEL_STATUS_ENABLED,
        StatusFilter::Disabled => row.status != CHANNEL_STATUS_ENABLED,
        StatusFilter::All => true,
    });

    // type_counts 先于 type 过滤累计（Go 的顺序）。
    let mut type_counts: BTreeMap<i64, i64> = BTreeMap::new();
    for row in &channels {
        *type_counts.entry(row.channel_type).or_default() += 1;
    }
    if let Some(type_) = type_ {
        channels.retain(|row| row.channel_type == type_);
    }

    let total = channels.len() as i64;
    let mut page = parse_i64(query.p.as_deref()).unwrap_or(1);
    let mut page_size = parse_i64(query.page_size.as_deref()).unwrap_or(20);
    if page < 1 {
        page = 1;
    }
    if page_size <= 0 {
        page_size = 20;
    }
    let start = ((page - 1) * page_size).clamp(0, total);
    let end = (start + page_size).min(total);
    let paged = &channels[start as usize..end as usize];

    let display = state.quota_display();
    let items: Vec<Value> = paged
        .iter()
        .map(|row| channel_json(clear_channel_info(row), &display))
        .collect();
    Json(json!({
        "success": true,
        "message": "",
        "data": {
            "items": items,
            "total": total,
            "type_counts": type_counts_json(
                &type_counts.iter().map(|(k, v)| (*k, *v)).collect::<Vec<_>>()
            ),
        }
    }))
    .into_response()
}

/// `GET /api/channel/:id`：Go `GetChannel`。
pub async fn get_channel(
    State(state): State<AppState>,
    Extension(admin_user): Extension<AuthenticatedUser>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if let Err(response) = require_permission(&state, &admin_user, CHANNEL_READ, &headers).await {
        return response;
    }
    let repository = ChannelRepository::new(db);
    let Ok(id) = id.parse::<i64>() else {
        return api_error(&headers, MSG_ID_FORMAT);
    };
    match repository.by_id(id, false).await {
        Ok(Some(row)) => Json(json!({
            "success": true,
            "message": "",
            "data": channel_json(clear_channel_info(&row), &state.quota_display()),
        }))
        .into_response(),
        Ok(None) => api_error(&headers, MSG_NOT_EXISTS),
        Err(error) => database_error(&headers, &error, MSG_DATABASE_ERROR),
    }
}

/// `PUT /api/channel/`：Go `UpdateChannel`。
pub async fn update_channel(
    State(state): State<AppState>,
    Extension(admin_user): Extension<AuthenticatedUser>,
    request: Request,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let (parts, body) = request.into_parts();
    let headers = parts.headers;
    let peer = parts
        .extensions
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0);
    if let Err(response) = require_permission(&state, &admin_user, CHANNEL_WRITE, &headers).await {
        return response;
    }
    let body = match to_bytes(body, MAX_BODY_BYTES).await {
        Ok(body) => body,
        Err(_) => return api_error(&headers, MSG_INVALID_PARAMS),
    };
    // Go 用 `RawBody` + `Unmarshal`（纯 JSON，不做 Content-Type 分发）：
    // `null` 解码为零值，空体/非法 JSON 是错误。
    let Some((input, raw)) = parse_update_body(&body) else {
        return api_error(&headers, MSG_INVALID_PARAMS);
    };
    if raw.contains_key("status") {
        return api_error(&headers, MSG_INVALID_PARAMS);
    }
    let id = input.channel.id.unwrap_or(0);
    let channel_type = input.channel.channel_type.unwrap_or(0);
    if let Err(error) =
        channels::validation::validate_channel(&channels::validation::ChannelValidationInput {
            channel_type,
            base_url: &input.channel.base_url,
            key: input.channel.key.as_deref().unwrap_or(""),
            models: input.channel.models.as_deref().unwrap_or(""),
            other: input.channel.other.as_deref().unwrap_or(""),
            setting: &input.channel.setting,
            other_settings: input.channel.settings.as_deref().unwrap_or(""),
            is_add: false,
        })
    {
        return validation_error(&headers, error);
    }
    let repository = ChannelRepository::new(db.clone());
    let origin = match repository.by_id(id, true).await {
        Ok(Some(origin)) => origin,
        Ok(None) => return api_error(&headers, MSG_NOT_EXISTS),
        Err(error) => return database_error(&headers, &error, MSG_DATABASE_ERROR),
    };
    // 敏感字段修改要求 ChannelSensitiveWrite：Go 在 handler 内用
    // `CtxApiErrorI18n` 升级，失败是 HTTP 200 `success:false`（区别于路由级
    // 中间件的 403）。
    if channel_has_sensitive_changes(&raw, &input, &origin)
        && !permission_allowed(&state, &admin_user, CHANNEL_SENSITIVE_WRITE).await
    {
        return Json(json!({
            "success": false,
            "message": translate(&headers, MSG_INSUFFICIENT_PRIVILEGE),
        }))
        .into_response();
    }
    let mut patch = input.channel.patch();
    // 多 key 渠道的密钥追加模式。
    if input.key_mode.as_deref() == Some("append")
        && origin.channel_info.is_multi_key
        && !origin.key.is_empty()
    {
        let vertex_api_key = channels::validation::vertex_uses_api_key(
            input.channel.settings.as_deref().unwrap_or(""),
        );
        match append_keys(
            &origin.key,
            input.channel.key.as_deref().unwrap_or(""),
            channel_type == CHANNEL_TYPE_VERTEX_AI && !vertex_api_key,
        ) {
            Ok(joined) => patch.key = Some(joined),
            Err(error) => {
                return api_error_args(
                    &headers,
                    MSG_APPEND_PARSE_FAILED,
                    &[("Detail", key_parse_detail(&headers, &error))],
                );
            }
        }
    }
    let info = resolve_update_channel_info(&origin, &patch, &input.multi_key_mode);
    let channel_info = channels::store::patch_channel_info(&info);
    let updated = match repository.update(id, &patch, channel_info).await {
        Ok(Some(updated)) => updated,
        Ok(None) => return api_error(&headers, MSG_NOT_EXISTS),
        Err(error) => return database_error(&headers, &error, MSG_DATABASE_ERROR),
    };

    let client_ip = request_ip(&state, &headers, peer);
    let now = now_seconds();
    let mut params = Map::new();
    params.insert("id".to_owned(), json!(id));
    params.insert("name".to_owned(), json!(updated.name));
    params.insert(
        "changed_fields".to_owned(),
        json!(changed_fields(&updated, &origin)),
    );
    record_audit(&db, &admin_user, "channel.update", params, &client_ip, now).await;

    let mut response = updated;
    response.key = MASKED_CHANNEL_KEY.to_owned();
    Json(json!({
        "success": true,
        "message": "",
        "data": channel_json(clear_channel_info(&response), &state.quota_display()),
    }))
    .into_response()
}

/// `DELETE /api/channel/:id`：Go `DeleteChannel`（硬删，含能力行）。
pub async fn delete_channel(
    State(state): State<AppState>,
    Extension(admin_user): Extension<AuthenticatedUser>,
    Path(id): Path<String>,
    request: Request,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let (parts, _body) = request.into_parts();
    let headers = parts.headers;
    let peer = parts
        .extensions
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0);
    if let Err(response) =
        require_permission(&state, &admin_user, CHANNEL_SENSITIVE_WRITE, &headers).await
    {
        return response;
    }
    // Go 忽略 Atoi 错误，非法 id 变成 0，后续照常“成功”删除空集。
    let id = id.parse::<i64>().unwrap_or(0);
    let repository = ChannelRepository::new(db.clone());
    let existing = repository.by_id(id, false).await.unwrap_or(None);
    let channel_name = existing
        .as_ref()
        .map(|row| row.name.clone())
        .unwrap_or_default();
    match repository.delete_by_id(id).await {
        Ok(()) => {}
        Err(error) => return database_error(&headers, &error, MSG_DATABASE_ERROR),
    }
    let client_ip = request_ip(&state, &headers, peer);
    let now = now_seconds();
    let mut params = Map::new();
    params.insert("id".to_owned(), json!(id));
    params.insert("name".to_owned(), json!(channel_name));
    record_audit(&db, &admin_user, "channel.delete", params, &client_ip, now).await;
    success(None)
}

/// `DELETE /api/channel/disabled`：Go `DeleteDisabledChannel`。
pub async fn delete_disabled_channels(
    State(state): State<AppState>,
    Extension(admin_user): Extension<AuthenticatedUser>,
    request: Request,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let (parts, _body) = request.into_parts();
    let headers = parts.headers;
    let peer = parts
        .extensions
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0);
    if let Err(response) =
        require_permission(&state, &admin_user, CHANNEL_SENSITIVE_WRITE, &headers).await
    {
        return response;
    }
    let repository = ChannelRepository::new(db.clone());
    let rows = match repository.delete_disabled().await {
        Ok(rows) => rows,
        Err(error) => return database_error(&headers, &error, MSG_DATABASE_ERROR),
    };
    let client_ip = request_ip(&state, &headers, peer);
    let now = now_seconds();
    let mut params = Map::new();
    params.insert("count".to_owned(), json!(rows));
    record_audit(
        &db,
        &admin_user,
        "channel.delete_disabled",
        params,
        &client_ip,
        now,
    )
    .await;
    success(Some(json!(rows)))
}

/// `POST /api/channel/batch`：Go `DeleteChannelBatch`（按 ids 删除）。
pub async fn delete_channel_batch(
    State(state): State<AppState>,
    Extension(admin_user): Extension<AuthenticatedUser>,
    request: Request,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let (parts, body) = request.into_parts();
    let headers = parts.headers;
    let peer = parts
        .extensions
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0);
    if let Err(response) =
        require_permission(&state, &admin_user, CHANNEL_SENSITIVE_WRITE, &headers).await
    {
        return response;
    }
    let body = match to_bytes(body, MAX_BODY_BYTES).await {
        Ok(body) => body,
        Err(_) => return api_error(&headers, MSG_INVALID_PARAMS),
    };
    // Go 的 ChannelBatch 只认 ids（tag 字段解析后被忽略）；绑定失败与
    // 空 ids 同为 invalid params。
    let Some(request) = parse_batch_body(&body) else {
        return api_error(&headers, MSG_INVALID_PARAMS);
    };
    if request.ids.is_empty() {
        return api_error(&headers, MSG_INVALID_PARAMS);
    }
    let repository = ChannelRepository::new(db.clone());
    let count = match repository.delete_by_ids(&request.ids).await {
        Ok(count) => count,
        Err(error) => return database_error(&headers, &error, MSG_DATABASE_ERROR),
    };
    let client_ip = request_ip(&state, &headers, peer);
    let now = now_seconds();
    let mut params = Map::new();
    params.insert("count".to_owned(), json!(count));
    record_audit(
        &db,
        &admin_user,
        "channel.delete_batch",
        params,
        &client_ip,
        now,
    )
    .await;
    success(Some(json!(count)))
}

/// `POST /api/channel/`：Go `AddChannel`。
pub async fn add_channel(
    State(state): State<AppState>,
    Extension(admin_user): Extension<AuthenticatedUser>,
    request: Request,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let (parts, body) = request.into_parts();
    let headers = parts.headers;
    let peer = parts
        .extensions
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0);
    if let Err(response) =
        require_permission(&state, &admin_user, CHANNEL_SENSITIVE_WRITE, &headers).await
    {
        return response;
    }
    let body = match to_bytes(body, MAX_BODY_BYTES).await {
        Ok(body) => body,
        Err(_) => return api_error(&headers, MSG_INVALID_PARAMS),
    };
    let request = match crate::body_bind::bind_body::<channels::AddChannelRequest>(&headers, &body)
    {
        Ok(request) => request,
        Err(()) => return api_error(&headers, MSG_INVALID_PARAMS),
    };
    let Some(channel) = request.channel.as_ref() else {
        return api_error(&headers, MSG_CHANNEL_REQUIRED);
    };
    let channel_type = channel.channel_type.unwrap_or(0);
    let key = channel.key.clone().unwrap_or_default();
    let models = channel.models.clone().unwrap_or_default();
    let other = channel.other.clone().unwrap_or_default();
    let other_settings = channel.settings.clone().unwrap_or_default();
    if let Err(error) =
        channels::validation::validate_channel(&channels::validation::ChannelValidationInput {
            channel_type,
            base_url: &channel.base_url,
            key: &key,
            models: &models,
            other: &other,
            setting: &channel.setting,
            other_settings: &other_settings,
            is_add: true,
        })
    {
        return validation_error(&headers, error);
    }
    // Go 的 `mode` 分支；非法 mode 报“不支持的添加模式”。
    let parsed = match channels::validation::parse_keys(
        &request.mode,
        &key,
        channels::validation::vertex_uses_api_key(&other_settings),
        channel_type == CHANNEL_TYPE_VERTEX_AI,
        &request.multi_key_mode,
        &channel.channel_info,
    ) {
        Ok(parsed) => parsed,
        Err(error) => {
            return api_error(
                &headers,
                match error {
                    KeyParseError::UnsupportedMode => MSG_UNSUPPORTED_MODE,
                    KeyParseError::VertexArrayFormat => "channel.batch_vertex_format",
                    KeyParseError::VertexArrayEmpty => "channel.batch_vertex_empty",
                },
            );
        }
    };
    let now = now_seconds();
    let key_count = parsed.keys.len();
    let mut channels_to_insert = Vec::with_capacity(key_count);
    let base_name = channel.name.clone().unwrap_or_default();
    for key in parsed.keys {
        if key.is_empty() {
            continue;
        }
        let mut local = channel.clone();
        local.key = Some(key.clone());
        if request.batch_add_set_key_prefix_2_name == Some(true) && key_count > 1 {
            let prefix: String = key.chars().take(8).collect();
            local.name = Some(format!("{base_name} {prefix}"));
        }
        channels_to_insert
            .push(local.into_new_channel(now, parsed.channel_info.clone().unwrap_or_default()));
    }
    let count = channels_to_insert.len() as i64;
    let repository = ChannelRepository::new(db.clone());
    if let Err(error) = repository.insert_channels(channels_to_insert).await {
        return database_error(&headers, &error, MSG_DATABASE_ERROR);
    }
    let client_ip = request_ip(&state, &headers, peer);
    let mut params = Map::new();
    params.insert("name".to_owned(), json!(base_name));
    params.insert("type".to_owned(), json!(channel_type));
    params.insert("count".to_owned(), json!(count));
    record_audit(&db, &admin_user, "channel.create", params, &client_ip, now).await;
    success(None)
}

// ---- 请求体解析 ---------------------------------------------------------

/// Go `PatchChannel`（嵌入 `Channel` + `multi_key_mode` + `key_mode`）。
#[derive(Debug, Default, Deserialize)]
struct PatchInput {
    #[serde(default, flatten)]
    channel: ChannelInput,
    #[serde(default)]
    multi_key_mode: Option<String>,
    #[serde(default)]
    key_mode: Option<String>,
}

/// Go `ChannelBatch`：批量删除请求体只认 `ids`。
#[derive(Debug, Default, Deserialize)]
struct ChannelBatchInput {
    #[serde(default)]
    ids: Vec<i64>,
}

/// `null` 是 Go 的零值；非对象顶层与类型错误是绑定失败。
fn parse_update_body(body: &[u8]) -> Option<(PatchInput, Map<String, Value>)> {
    let value: Value = serde_json::from_slice(body).ok()?;
    match value {
        Value::Null => Some((PatchInput::default(), Map::new())),
        Value::Object(object) => {
            let input: PatchInput = serde_json::from_value(Value::Object(object.clone())).ok()?;
            Some((input, object))
        }
        _ => None,
    }
}

fn parse_batch_body(body: &[u8]) -> Option<ChannelBatchInput> {
    let value: Value = serde_json::from_slice(body).ok()?;
    match value {
        Value::Null => Some(ChannelBatchInput::default()),
        Value::Object(_) => serde_json::from_value(value).ok(),
        _ => None,
    }
}

// ---- 敏感字段判定（Go `channelHasSensitiveChanges`） ---------------------

fn channel_has_sensitive_changes(
    raw: &Map<String, Value>,
    input: &PatchInput,
    origin: &ChannelRow,
) -> bool {
    let get = |key: &str| raw.contains_key(key);
    if get("type") && input.channel.channel_type.unwrap_or(0) != origin.channel_type {
        return true;
    }
    if get("key") {
        let new_key = input.channel.key.clone().unwrap_or_default();
        if !new_key.is_empty() && new_key != origin.key {
            return true;
        }
    }
    if get("base_url") && input.channel.base_url != origin.base_url {
        return true;
    }
    if get("openai_organization") && input.channel.openai_organization != origin.openai_organization
    {
        return true;
    }
    if get("header_override") && input.channel.header_override != origin.header_override {
        return true;
    }
    if get("param_override") && input.channel.param_override != origin.param_override {
        return true;
    }
    if get("setting") && input.channel.setting != origin.setting {
        return true;
    }
    if get("other") && input.channel.other.clone().unwrap_or_default() != origin.other {
        return true;
    }
    if get("settings") && input.channel.settings.clone().unwrap_or_default() != origin.settings {
        return true;
    }
    if get("key_mode") && input.key_mode.is_some() {
        return true;
    }
    // 失败兜底：未知字段一律按敏感处理（Go 的 fail-closed 分支）。
    for key in raw.keys() {
        if is_sensitive_field(key) || is_operational_field(key) || is_read_only_field(key) {
            continue;
        }
        if is_non_sensitive_field(key) {
            continue;
        }
        return true;
    }
    false
}

fn is_sensitive_field(key: &str) -> bool {
    matches!(
        key,
        "type"
            | "key"
            | "base_url"
            | "openai_organization"
            | "header_override"
            | "param_override"
            | "setting"
            | "other"
            | "settings"
            | "key_mode"
    )
}

fn is_operational_field(key: &str) -> bool {
    matches!(key, "status")
}

fn is_read_only_field(key: &str) -> bool {
    matches!(
        key,
        "created_time"
            | "test_time"
            | "response_time"
            | "balance"
            | "balance_updated_time"
            | "used_quota"
            | "used_quota_display"
    )
}

fn is_non_sensitive_field(key: &str) -> bool {
    matches!(
        key,
        "id" | "test_model"
            | "name"
            | "models"
            | "group"
            | "model_mapping"
            | "status_code_mapping"
            | "auto_ban"
            | "other_info"
            | "tag"
            | "remark"
            | "channel_info"
            | "multi_key_mode"
    )
}

/// Go `updateWithTx` 的 `channel_info` 处理：保留 origin，叠加请求显式
/// 给出的 `multi_key_mode`；多 key 渠道按最终 key 列表重算 size 并裁剪
/// 越界 key 的状态。
fn resolve_update_channel_info(
    origin: &ChannelRow,
    patch: &ChannelPatch,
    multi_key_mode: &Option<String>,
) -> ChannelInfo {
    let mut info = origin.channel_info.clone();
    if let Some(mode) = multi_key_mode
        && !mode.is_empty()
    {
        info.multi_key_mode = mode.clone();
    }
    if info.is_multi_key {
        let key_str = patch
            .key
            .as_deref()
            .filter(|key| !key.is_empty())
            .unwrap_or(&origin.key);
        let trimmed = key_str.trim();
        let keys: Vec<String> = if trimmed.is_empty() {
            Vec::new()
        } else if trimmed.starts_with('[') {
            match serde_json::from_str::<Vec<Value>>(trimmed) {
                Ok(array) => array.into_iter().map(|value| value.to_string()).collect(),
                Err(_) => split_key_lines(key_str),
            }
        } else {
            split_key_lines(key_str)
        };
        info.multi_key_size = keys.len() as i64;
        if let Some(status_list) = info.multi_key_status_list.as_mut() {
            status_list.retain(|index, _| *index < info.multi_key_size);
        }
    }
    info
}

fn split_key_lines(key: &str) -> Vec<String> {
    key.trim_matches('\n')
        .split('\n')
        .map(str::to_owned)
        .collect()
}

/// Go 更新的 `key_mode == "append"`：现有 key 列表去重后追加密钥。
fn append_keys(
    origin_key: &str,
    new_key: &str,
    vertex_json: bool,
) -> Result<String, KeyParseError> {
    let trimmed_origin = origin_key.trim();
    let mut existing: Vec<String> = if trimmed_origin.starts_with('[') {
        match serde_json::from_str::<Vec<Value>>(trimmed_origin) {
            Ok(array) => array.into_iter().map(|value| value.to_string()).collect(),
            Err(_) => split_key_lines(origin_key),
        }
    } else {
        split_key_lines(origin_key)
    };
    let mut new_keys: Vec<String> = if vertex_json {
        if new_key.trim().starts_with('[') {
            vertex_array_keys(new_key)?
        } else {
            vec![new_key.to_owned()]
        }
    } else {
        new_key
            .split('\n')
            .map(str::trim)
            .filter(|key| !key.is_empty())
            .map(str::to_owned)
            .collect()
    };
    // 去重：以 trim 后的值比对（Go 的 seen map 语义）。
    let mut seen: std::collections::HashSet<String> = existing
        .iter()
        .map(|key| key.trim().to_owned())
        .filter(|key| !key.is_empty())
        .collect();
    let mut deduped = Vec::new();
    for key in new_keys.drain(..) {
        let normalized = key.trim().to_owned();
        if normalized.is_empty() || !seen.insert(normalized) {
            continue;
        }
        deduped.push(key);
    }
    existing.extend(deduped);
    Ok(existing.join("\n"))
}

fn vertex_array_keys(key: &str) -> Result<Vec<String>, KeyParseError> {
    let array: Vec<Value> =
        serde_json::from_str(key).map_err(|_| KeyParseError::VertexArrayFormat)?;
    let mut clean = Vec::with_capacity(array.len());
    for value in array {
        match value {
            Value::String(string) => clean.push(string.trim().to_owned()),
            other => clean.push(other.to_string()),
        }
    }
    if clean.is_empty() {
        return Err(KeyParseError::VertexArrayEmpty);
    }
    Ok(clean)
}

fn key_parse_detail(headers: &HeaderMap, error: &KeyParseError) -> String {
    let key = match error {
        KeyParseError::VertexArrayFormat => "channel.batch_vertex_format",
        KeyParseError::VertexArrayEmpty => "channel.batch_vertex_empty",
        KeyParseError::UnsupportedMode => return String::new(),
    };
    translate(headers, key)
}

/// Go 审计的 changed_fields：models/group/type/base_url/key 五项。
fn changed_fields(updated: &ChannelRow, origin: &ChannelRow) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if updated.models != origin.models {
        fields.push("models");
    }
    if updated.group != origin.group {
        fields.push("group");
    }
    if updated.channel_type != origin.channel_type {
        fields.push("type");
    }
    if updated.base_url != origin.base_url {
        fields.push("base_url");
    }
    if !updated.key.is_empty() && updated.key != origin.key {
        fields.push("key");
    }
    fields
}

async fn record_audit(
    db: &newapi_storage::Database,
    user: &AuthenticatedUser,
    action: &str,
    params: Map<String, Value>,
    ip: &str,
    now: i64,
) {
    let auth_method = match user.0.credential {
        newapi_identity::user_auth::CredentialKind::DashboardSession => "session",
        newapi_identity::user_auth::CredentialKind::PersonalAccessToken => "access_token",
    };
    record_manage_audit_with_params(
        db,
        &AuditOperator {
            user_id: user.0.user_id,
            username: &user.0.username,
            role: user.0.role,
            auth_method,
        },
        action,
        0,
        Some(&params),
        ip,
        now,
    )
    .await;
}

// ---- 响应组装 -----------------------------------------------------------

/// Go `clearChannelInfo`：多 key 渠道抹掉禁用原因/时间（脱敏内部状态）。
fn clear_channel_info(row: &ChannelRow) -> ChannelRow {
    let mut row = row.clone();
    if row.channel_info.is_multi_key {
        row.channel_info.multi_key_disabled_reason = None;
        row.channel_info.multi_key_disabled_time = None;
    }
    row
}

/// `channelpkg.Channel` 的 JSON 形态（字段集与 Go 序列化一致；键序按
/// serde_json 默认排序，与既有切片一致）。
fn channel_json(row: ChannelRow, display: &QuotaDisplaySettings) -> Value {
    let ChannelRow {
        id,
        channel_type,
        key,
        openai_organization,
        test_model,
        status,
        name,
        created_time,
        test_time,
        response_time,
        base_url,
        other,
        balance,
        balance_updated_time,
        models,
        group,
        used_quota,
        model_mapping,
        status_code_mapping,
        auto_ban,
        other_info,
        tag,
        setting,
        param_override,
        header_override,
        remark,
        channel_info,
        settings,
    } = row;
    json!({
        "id": id,
        "type": channel_type,
        "key": key,
        "openai_organization": openai_organization,
        "test_model": test_model,
        "status": status,
        "name": name,
        "created_time": created_time,
        "test_time": test_time,
        "response_time": response_time,
        "base_url": base_url,
        "other": other,
        "balance": balance,
        "balance_updated_time": balance_updated_time,
        "models": models,
        "group": group,
        "used_quota": used_quota,
        "used_quota_display": display.to_display(used_quota),
        "model_mapping": model_mapping,
        "status_code_mapping": status_code_mapping,
        "auto_ban": auto_ban,
        "other_info": other_info,
        "tag": tag,
        "setting": setting,
        "param_override": param_override,
        "header_override": header_override,
        "remark": remark,
        "channel_info": channel_info_json(&channel_info),
        "settings": settings,
    })
}

fn channel_info_json(info: &ChannelInfo) -> Value {
    let multi_key_status_list = match &info.multi_key_status_list {
        Some(map) => json!(map),
        None => Value::Null,
    };
    let mut object = Map::new();
    object.insert("is_multi_key".to_owned(), json!(info.is_multi_key));
    object.insert("multi_key_size".to_owned(), json!(info.multi_key_size));
    object.insert("multi_key_status_list".to_owned(), multi_key_status_list);
    if let Some(reason) = &info.multi_key_disabled_reason {
        object.insert("multi_key_disabled_reason".to_owned(), json!(reason));
    }
    if let Some(time) = &info.multi_key_disabled_time {
        object.insert("multi_key_disabled_time".to_owned(), json!(time));
    }
    object.insert(
        "multi_key_polling_index".to_owned(),
        json!(info.multi_key_polling_index),
    );
    object.insert("multi_key_mode".to_owned(), json!(info.multi_key_mode));
    Value::Object(object)
}

fn type_counts_json(counts: &[(i64, i64)]) -> Value {
    let mut object = Map::new();
    for (channel_type, count) in counts {
        object.insert(channel_type.to_string(), json!(count));
    }
    Value::Object(object)
}

fn success(data: Option<Value>) -> Response {
    match data {
        Some(data) => Json(json!({ "success": true, "message": "", "data": data })).into_response(),
        None => Json(json!({ "success": true, "message": "" })).into_response(),
    }
}

fn api_error(headers: &HeaderMap, key: &str) -> Response {
    Json(json!({
        "success": false,
        "message": translate(headers, key),
    }))
    .into_response()
}

fn api_error_args(headers: &HeaderMap, key: &str, args: &[(&str, String)]) -> Response {
    Json(json!({
        "success": false,
        "message": translate_args(headers, key, args),
    }))
    .into_response()
}

fn validation_error(headers: &HeaderMap, error: ValidationError) -> Response {
    match error {
        ValidationError::Settings(detail) => {
            api_error_args(headers, MSG_SETTING_INVALID, &[("Detail", detail)])
        }
        ValidationError::ChannelOrKeyEmpty => api_error(headers, MSG_CHANNEL_REQUIRED),
        ValidationError::ModelNameTooLong(model) => {
            api_error_args(headers, MSG_MODEL_TOO_LONG, &[("Model", model)])
        }
        ValidationError::NewApiBaseUrlRequired => api_error(headers, MSG_NEW_API_BASE_URL),
        ValidationError::VertexRegionRequired => api_error(headers, MSG_VERTEX_REGION_REQUIRED),
        ValidationError::VertexRegionFormat => api_error(headers, MSG_VERTEX_REGION_FORMAT),
        ValidationError::VertexRegionDefault => api_error(headers, MSG_VERTEX_REGION_DEFAULT),
        ValidationError::CodexKeyFormat => api_error(headers, MSG_CODEX_FORMAT),
        ValidationError::CodexAccessTokenRequired => api_error(headers, MSG_CODEX_ACCESS_TOKEN),
        ValidationError::CodexAccountIdRequired => api_error(headers, MSG_CODEX_ACCOUNT_ID),
    }
}

fn database_error(headers: &HeaderMap, error: &sqlx::Error, key: &str) -> Response {
    tracing::warn!(
        event = "channel_database_operation_failed",
        category = crate::database_error_class(error),
        "channel database operation failed"
    );
    api_error(headers, key)
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

fn translate_args(headers: &HeaderMap, key: &str, args: &[(&str, String)]) -> String {
    newapi_i18n::translate(
        &request_language(headers),
        key,
        args.iter().map(|(name, value)| (*name, value.as_str())),
    )
}

/// 单元测试：不触库的纯契约函数。
#[cfg(test)]
mod tests {
    use super::*;
    use newapi_catalog::channels::ChannelInput;

    fn patch_input(json: &str) -> (PatchInput, Map<String, Value>) {
        parse_update_body(json.as_bytes()).expect("update body")
    }

    fn origin() -> ChannelRow {
        ChannelRow {
            id: 1,
            channel_type: 1,
            key: "sk-origin".to_owned(),
            openai_organization: None,
            test_model: None,
            status: 1,
            name: "c1".to_owned(),
            created_time: 0,
            test_time: 0,
            response_time: 0,
            base_url: Some("https://a.example".to_owned()),
            other: String::new(),
            balance: 0.0,
            balance_updated_time: 0,
            models: "m1".to_owned(),
            group: "default".to_owned(),
            used_quota: 0,
            model_mapping: None,
            status_code_mapping: None,
            auto_ban: Some(1),
            other_info: String::new(),
            tag: None,
            setting: None,
            param_override: None,
            header_override: None,
            remark: None,
            channel_info: ChannelInfo::default(),
            settings: String::new(),
        }
    }

    #[test]
    fn null_body_is_the_go_zero_value() {
        let (input, raw) = patch_input("null");
        assert!(input.channel.id.is_none());
        assert!(!raw.contains_key("status"));
    }

    #[test]
    fn non_object_body_is_rejected() {
        assert!(parse_update_body(b"[]").is_none());
        assert!(parse_update_body(b"").is_none());
        assert!(parse_update_body(br#"{"name":"x"}"#).is_some());
    }

    #[test]
    fn sensitive_changes_match_go_classification() {
        let (input, raw) = patch_input(r#"{"name":"renamed"}"#);
        assert!(!channel_has_sensitive_changes(&raw, &input, &origin()));

        let (input, raw) = patch_input(r#"{"type":2}"#);
        assert!(channel_has_sensitive_changes(&raw, &input, &origin()));

        // 同值不算变更。
        let (input, raw) = patch_input(r#"{"type":1}"#);
        assert!(!channel_has_sensitive_changes(&raw, &input, &origin()));

        let (input, raw) = patch_input(r#"{"key":"sk-new"}"#);
        assert!(channel_has_sensitive_changes(&raw, &input, &origin()));

        let (input, raw) = patch_input(r#"{"key":""}"#);
        assert!(!channel_has_sensitive_changes(&raw, &input, &origin()));

        let (input, raw) = patch_input(r#"{"key_mode":"append"}"#);
        assert!(channel_has_sensitive_changes(&raw, &input, &origin()));

        // fail-closed：未知字段按敏感处理。
        let (input, raw) = patch_body_with_extra();
        assert!(channel_has_sensitive_changes(&raw, &input, &origin()));

        // 只读字段与非敏感字段不触发。
        let (input, raw) = patch_input(r#"{"created_time":5,"used_quota":7,"models":"m2"}"#);
        assert!(!channel_has_sensitive_changes(&raw, &input, &origin()));
    }

    fn patch_body_with_extra() -> (PatchInput, Map<String, Value>) {
        patch_input(r#"{"future_field":1}"#)
    }

    #[test]
    fn patch_skips_zero_value_fields() {
        let input: ChannelInput = serde_json::from_str(r#"{"name":"","models":"m2"}"#).unwrap();
        let patch = input.patch();
        assert!(patch.name.is_none());
        assert_eq!(patch.models.as_deref(), Some("m2"));
    }

    #[test]
    fn page_info_defaults_and_caps() {
        let query = ChannelQuery::default();
        assert_eq!(go_page_info(&query), (1, 10));
        let mut query = ChannelQuery::default();
        query.p = Some("3".to_owned());
        query.page_size = Some("20".to_owned());
        assert_eq!(go_page_info(&query), (3, 20));
        query.page_size = Some("1000".to_owned());
        assert_eq!(go_page_info(&query).1, 100);
    }

    #[test]
    fn status_filter_parses_go_values() {
        assert_eq!(
            status_filter(&Some("enabled".into())),
            StatusFilter::Enabled
        );
        assert_eq!(status_filter(&Some("1".into())), StatusFilter::Enabled);
        assert_eq!(
            status_filter(&Some("disabled".into())),
            StatusFilter::Disabled
        );
        assert_eq!(status_filter(&Some("0".into())), StatusFilter::Disabled);
        assert_eq!(status_filter(&None), StatusFilter::All);
        assert_eq!(status_filter(&Some("other".into())), StatusFilter::All);
    }

    #[test]
    fn info_resolves_multi_key_size() {
        let mut origin = origin();
        origin.channel_info.is_multi_key = true;
        let patch = ChannelPatch {
            key: Some("k1\nk2\nk3".to_owned()),
            ..ChannelPatch::default()
        };
        let info = resolve_update_channel_info(&origin, &patch, &None);
        assert_eq!(info.multi_key_size, 3);
        assert!(info.multi_key_status_list.is_none());

        // 空 key 回退到 origin 的 key 列表。
        let patch = ChannelPatch::default();
        let info = resolve_update_channel_info(&origin, &patch, &None);
        assert_eq!(info.multi_key_size, 1);

        // mode 覆盖。
        let info = resolve_update_channel_info(&origin, &patch, &Some("random".to_owned()));
        assert_eq!(info.multi_key_mode, "random");
    }

    #[test]
    fn append_keys_deduplicates() {
        let joined = append_keys("origin-key\nsecond-key", "second-key\nthird", false).unwrap();
        assert_eq!(joined, "origin-key\nsecond-key\nthird");
        // 顶点 JSON 数组分支。
        let joined = append_keys("[\"a\",\"b\"]", "[\"b\",\"c\"]", true).unwrap();
        assert_eq!(joined, "\"a\"\n\"b\"\n\"c\"");
    }

    #[test]
    fn type_counts_serialize_with_string_keys() {
        let counts = vec![(1, 3), (41, 2)];
        let value = type_counts_json(&counts);
        assert_eq!(value["1"], json!(3));
        assert_eq!(value["41"], json!(2));
    }
}
