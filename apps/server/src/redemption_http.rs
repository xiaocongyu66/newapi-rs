//! `/api/redemption/*` 管理端 HTTP 适配器。
//!
//! Go references:
//! - `apps/api/internal/billing/redeem_code.go`：`GetAllRedemptions`、
//!   `SearchRedemptions`、`GetRedemption`、`AddRedemption`、`UpdateRedemption`、
//!   `DeleteRedemption`、`DeleteInvalidRedemption`
//! - `apps/api/internal/billing/store_redemption.go` / `purge_redemptions.go`
//! - `apps/api/internal/transport/compose/register_api.go:386-396`：路由组
//!   `apiRouter.Group("/redemption")`，组级只挂 `security.AdminAuth()`，
//!   无限流、无 `DisableCache`；401/403 只能来自该中间件。
//!
//! 契约要点（Go 是 oracle）：
//! - 除 `AddRedemption` 的非有限 `quota_display`（Go 显式写 HTTP 400 + 纯文本
//!   "invalid quota"）外，所有业务结果都是 HTTP 200 + `{success,message}`
//!   包裹；`message` 走 i18n 键翻译，不回显数据库文本。
//! - `AddRedemption` 的 `data` 是本次生成的码列表；中途插入失败返回已生成
//!   的部分 `keys` 并附 `redemption.create_failed`。
//! - `UpdateRedemption` 的 `?status_only` 为任意非空值时只改 status
//!   （空串/缺省走全量更新），响应 `data` 为更新后的整条记录。
//! - 兑换码是凭据：管理端响应按 Go 契约返回明文 key，但 tracing 只写固定
//!   事件名与错误分类，不写 key 与 SQL 文本。
//! - 兑换的消费链路（topup 时核销）不在本切片。

use axum::{
    Json,
    body::{Bytes, to_bytes},
    extract::{Extension, Path, Request, State},
    http::{HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use newapi_billing::redemption::{
    NewRedemption, RedemptionRecord, RedemptionRepository, RedemptionStatusFilter,
    RedemptionUpdate, generate_redemption_key,
};
use newapi_billing::topup::TopUpSettings;
use newapi_identity::{
    self_user::QuotaDisplaySettings, tokens::quota_from_display, user_auth::CredentialKind,
};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::AppState;
use crate::auth::AuthenticatedUser;

const MSG_INVALID_PARAMS: &str = "common.invalid_params";
const MSG_ID_EMPTY: &str = "common.id_empty";
const MSG_NOT_FOUND: &str = "common.not_found";
const MSG_DATABASE_ERROR: &str = "common.database_error";
const MSG_COMPLIANCE_REQUIRED: &str = "payment.compliance_required";
const MSG_NAME_LENGTH: &str = "redemption.name_length";
const MSG_COUNT_POSITIVE: &str = "redemption.count_positive";
const MSG_COUNT_MAX: &str = "redemption.count_max";
const MSG_CREATE_FAILED: &str = "redemption.create_failed";
const MSG_EXPIRE_TIME_INVALID: &str = "redemption.expire_time_invalid";

/// Go `AddRedemption` 对非有限额度的硬回应：HTTP 400 + 未翻译字面量。
const MSG_INVALID_QUOTA: &str = "invalid quota";
/// Go `GetPageQuery` 接受 `p`/`page_size` 与 `ps`/`size` 兼容别名；
/// 未知查询键忽略。`keyword`/`status` 用于 search，`status_only` 用于 PUT。
#[derive(Debug, Default)]
struct RedemptionPageQuery {
    p: Option<String>,
    page_size: Option<String>,
    ps: Option<String>,
    size: Option<String>,
    keyword: Option<String>,
    status: Option<String>,
    status_only: Option<String>,
}

/// Go/axum 查询串解码对齐（无 axum query feature）：`+` 为空格、`%XX` 解一字节。
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

fn page_query(uri: &Uri) -> RedemptionPageQuery {
    let pairs = query_pairs(uri);
    let get = |key: &str| {
        pairs
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.clone())
    };
    RedemptionPageQuery {
        p: get("p"),
        page_size: get("page_size"),
        ps: get("ps"),
        size: get("size"),
        keyword: get("keyword"),
        status: get("status"),
        status_only: get("status_only"),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PageInfo {
    page: i64,
    page_size: i64,
    offset: i64,
}

/// Go `strconv.Atoi`：可选符号加十进制数字，无空白。
fn parse_i64(value: Option<&str>) -> Option<i64> {
    value.and_then(|value| value.parse::<i64>().ok())
}

fn page_info(query: &RedemptionPageQuery) -> PageInfo {
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
    PageInfo {
        page,
        page_size,
        offset: page.saturating_sub(1).saturating_mul(page_size),
    }
}

/// Go `c.BindJSON(&redemption)`： redemption 结构体的全部 JSON 字段。
/// 缺省与 JSON `null` 都是零值；类型不匹配是绑定错误。
/// `count` 只在 POST 体里有意义（`gorm:"-:all"`）；`user_id`/`key`/
/// `redeemed_time`/`created_time`/`used_user_id` 仅参与绑定以复刻 Go 的
/// 类型校验，管理端 handler 不读取（`status` 由 status_only 写入）。
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
#[allow(dead_code)]
struct RedemptionRequest {
    id: Option<i64>,
    user_id: Option<i64>,
    key: Option<String>,
    status: Option<i64>,
    name: Option<String>,
    quota: Option<i64>,
    /// 提交侧的展示金额，POST 时换算为内部 quota（Go
    /// `QuotaFromDisplayAmount`）；PUT 不用它。
    quota_display: Option<f64>,
    redeemed_time: Option<i64>,
    created_time: Option<i64>,
    used_user_id: Option<i64>,
    count: Option<i64>,
    expired_time: Option<i64>,
}

/// Go `c.BindJSON` 的端口边界：空体/未知 Content-Type 保持零值（不是错误），
/// `null` 是零值，非对象顶层与类型错误是绑定失败。
fn parse_redemption_request(headers: &HeaderMap, body: &[u8]) -> Option<RedemptionRequest> {
    let value = crate::body_bind::bind_body::<Value>(headers, body).ok()?;
    match value {
        Value::Null => Some(RedemptionRequest::default()),
        Value::Object(object) => serde_json::from_value(Value::Object(object)).ok(),
        _ => None,
    }
}

/// `GET /api/redemption/` → Go `billing.GetAllRedemptions`。
pub async fn list_redemptions(
    State(state): State<AppState>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let info = page_info(&page_query(&uri));
    let repository = RedemptionRepository::new(db);
    let (redemptions, total) = match repository.list_all(info.offset, info.page_size).await {
        Ok(result) => result,
        Err(error) => return database_error(&headers, &error),
    };
    let display = state.quota_display();
    let items: Vec<Value> = redemptions
        .iter()
        .map(|record| redemption_json(record, &display))
        .collect();
    Json(json!({
        "success": true,
        "message": "",
        "data": {
            "page": info.page,
            "page_size": info.page_size,
            "total": total,
            "items": items,
        },
    }))
    .into_response()
}

/// `GET /api/redemption/search` → Go `billing.SearchRedemptions`。
pub async fn search_redemptions(
    State(state): State<AppState>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let query = page_query(&uri);
    let info = page_info(&query);
    let keyword = query.keyword.unwrap_or_default();
    let status = RedemptionStatusFilter::from_query(&query.status.unwrap_or_default());
    let repository = RedemptionRepository::new(db);
    let (redemptions, total) = match repository
        .search(
            &keyword,
            status,
            info.offset,
            info.page_size,
            crate::http::now_seconds(),
        )
        .await
    {
        Ok(result) => result,
        Err(error) => return database_error(&headers, &error),
    };
    let display = state.quota_display();
    let items: Vec<Value> = redemptions
        .iter()
        .map(|record| redemption_json(record, &display))
        .collect();
    Json(json!({
        "success": true,
        "message": "",
        "data": {
            "page": info.page,
            "page_size": info.page_size,
            "total": total,
            "items": items,
        },
    }))
    .into_response()
}

/// `GET /api/redemption/:id` → Go `billing.GetRedemption`。
/// Go 的 `strconv.Atoi` 失败回显原始错误文本，本端口按既有约定折叠为
/// `common.invalid_params`；`id 为空！` 与 `record not found` 同理映射为
/// 固定 i18n 键，不转述数据库文本。
pub async fn get_redemption(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(id) = id.parse::<i64>() else {
        return api_error(&headers, MSG_INVALID_PARAMS);
    };
    if id == 0 {
        return api_error(&headers, MSG_ID_EMPTY);
    }
    let repository = RedemptionRepository::new(db);
    match repository.by_id(id).await {
        Ok(Some(record)) => success(Some(redemption_json(&record, &state.quota_display()))),
        Ok(None) => api_error(&headers, MSG_NOT_FOUND),
        Err(error) => database_error(&headers, &error),
    }
}

/// `POST /api/redemption/` → Go `billing.AddRedemption`：合规门 → 校验 →
/// 逐条生成 UUIDv4 码并插入；`data` 为本次生成的码列表。
pub async fn add_redemption(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    request: Request,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let (parts, body) = request.into_parts();
    let headers = parts.headers;
    let peer = parts
        .extensions
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0);
    let body = match to_bytes(body, crate::http::MAX_BODY_BYTES).await {
        Ok(body) => body,
        Err(_) => return api_error(&headers, MSG_INVALID_PARAMS),
    };
    let now = crate::http::now_seconds();

    // Go `IsPaymentComplianceConfirmed`：读进程内 paymentSetting；这里按
    // 当前快照判定，选项读取失败也判定为未确认（故障关闭，与 Go 读不到
    // 合规标记时的默认 false 同向）。
    let compliant = match TopUpSettings::load(&db).await {
        Ok(settings) => settings.payment_compliance_confirmed(),
        Err(error) => {
            tracing::warn!(
                event = "redemption_compliance_load_failed",
                category = crate::database_error_class(&error),
                "redemption compliance settings load failed"
            );
            false
        }
    };
    if !compliant {
        return api_error(&headers, MSG_COMPLIANCE_REQUIRED);
    }

    let Some(request) = parse_redemption_request(&headers, &body) else {
        return api_error(&headers, MSG_INVALID_PARAMS);
    };
    let quota_display = request.quota_display.unwrap_or(0.0);
    if !quota_display.is_finite() {
        // Go 的唯一非 200 分支：显式 400 + 未翻译字面量（含 NaN/Inf）。
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"success": false, "message": MSG_INVALID_QUOTA})),
        )
            .into_response();
    }
    let name = request.name.unwrap_or_default();
    let name_len = name.chars().count();
    if name_len == 0 || name_len > 20 {
        // Go `utf8.RuneCountInString`：按字符数计，不是字节数。
        return api_error(&headers, MSG_NAME_LENGTH);
    }
    let count = request.count.unwrap_or(0);
    if count <= 0 {
        return api_error(&headers, MSG_COUNT_POSITIVE);
    }
    if count > 100 {
        return api_error(&headers, MSG_COUNT_MAX);
    }
    let expired_time = request.expired_time.unwrap_or(0);
    if expired_time != 0 && expired_time < now {
        return api_error(&headers, MSG_EXPIRE_TIME_INVALID);
    }

    let display = state.quota_display();
    let quota = quota_from_display(quota_display, &display);
    let repository = RedemptionRepository::new(db.clone());
    let mut keys: Vec<String> = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let Some(key) = generate_redemption_key() else {
            return create_failure(&headers, &keys);
        };
        let new = NewRedemption {
            user_id: auth_user.0.user_id,
            key: key.clone(),
            name: name.clone(),
            quota,
            expired_time,
        };
        if let Err(error) = repository.insert(&new).await {
            tracing::warn!(
                event = "redemption_insert_failed",
                category = crate::database_error_class(&error),
                "failed to insert redemption"
            );
            // Go：已生成的部分随失败响应返回，已插入的行保留。
            return create_failure(&headers, &keys);
        }
        keys.push(key);
    }

    // Go `usage.RecordManageAudit(c, "redemption.create", ...)`：审计写失败
    // 仅告警，不改变成功响应。
    let auth_method = match auth_user.0.credential {
        CredentialKind::DashboardSession => "session",
        CredentialKind::PersonalAccessToken => "access_token",
    };
    let mut params = Map::new();
    params.insert("name".to_owned(), json!(name));
    params.insert("count".to_owned(), json!(count));
    // Go `logger.LogQuota`：带币种符号与“ 额度”后缀的展示串。
    params.insert("quota".to_owned(), json!(display.format_quota(quota, true)));
    let client_ip = crate::http::request_ip(&state, &headers, peer);
    newapi_identity::audit::record_manage_audit_with_params(
        &db,
        &newapi_identity::audit::AuditOperator {
            user_id: auth_user.0.user_id,
            username: &auth_user.0.username,
            role: auth_user.0.role,
            auth_method,
        },
        "redemption.create",
        0,
        Some(&params),
        &client_ip,
        now,
    )
    .await;

    success(Some(json!(keys)))
}

/// `PUT /api/redemption/` → Go `billing.UpdateRedemption`。
/// `?status_only` 非空时只写 status；否则写 name/quota/expired_time
/// （quota 是请求体里的内部值，不由 quota_display 换算）。响应 `data`
/// 为更新后的整条记录（内存值，quota_display 重算）。
pub async fn update_redemption(
    State(state): State<AppState>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let query = page_query(&uri);
    let Some(request) = parse_redemption_request(&headers, &body) else {
        return api_error(&headers, MSG_INVALID_PARAMS);
    };
    // Go `c.Query("status_only")`：任意非空值都走 status-only 更新。
    let status_only = query
        .status_only
        .as_deref()
        .is_some_and(|value| !value.is_empty());
    let id = request.id.unwrap_or(0);
    let repository = RedemptionRepository::new(db);
    let existing = match repository.by_id(id).await {
        Ok(Some(record)) => record,
        Ok(None) => {
            return api_error(&headers, if id == 0 { MSG_ID_EMPTY } else { MSG_NOT_FOUND });
        }
        Err(error) => return database_error(&headers, &error),
    };
    let mut updated = existing;
    if status_only {
        updated.status = request.status.unwrap_or(0);
    } else {
        let expired_time = request.expired_time.unwrap_or(0);
        if expired_time != 0 && expired_time < crate::http::now_seconds() {
            return api_error(&headers, MSG_EXPIRE_TIME_INVALID);
        }
        // Go 的注释：“If you add more fields, please also update
        // redemption.Update()”——全量更新只覆盖这三列，status 保持原值。
        updated.name = request.name.unwrap_or_default();
        updated.quota = request.quota.unwrap_or(0);
        updated.expired_time = expired_time;
    }
    let update = RedemptionUpdate {
        name: updated.name.clone(),
        status: updated.status,
        quota: updated.quota,
        redeemed_time: updated.redeemed_time,
        expired_time: updated.expired_time,
    };
    if let Err(error) = repository.update(id, &update).await {
        return database_error(&headers, &error);
    }
    success(Some(redemption_json(&updated, &state.quota_display())))
}

/// `DELETE /api/redemption/:id` → Go `billing.DeleteRedemption`。
/// Go 忽略 `strconv.Atoi` 的错误（非法 id 变 0），先查后软删。
pub async fn delete_redemption(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let id = id.parse::<i64>().unwrap_or(0);
    if id == 0 {
        return api_error(&headers, MSG_ID_EMPTY);
    }
    let repository = RedemptionRepository::new(db);
    match repository.by_id(id).await {
        Ok(Some(_)) => {}
        Ok(None) => return api_error(&headers, MSG_NOT_FOUND),
        Err(error) => return database_error(&headers, &error),
    }
    match repository.soft_delete(id).await {
        Ok(()) => success(None),
        Err(error) => database_error(&headers, &error),
    }
}

/// `DELETE /api/redemption/invalid` → Go `billing.DeleteInvalidRedemption`。
/// 软删除 used/disabled 与已过期的 enabled 码，`data` 为命中行数。
pub async fn delete_invalid_redemptions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let repository = RedemptionRepository::new(db);
    match repository.delete_invalid(crate::http::now_seconds()).await {
        Ok(rows) => success(Some(json!(rows))),
        Err(error) => database_error(&headers, &error),
    }
}

/// Go `Redemption` 的 JSON 序列化：字段与 Go 结构体一一对应
/// （`quota_display` 由 `AfterFind` 在 API 边界换算；`count` 是
/// `gorm:"-:all"` 的瞬态字段，DB 记录恒为 0）。
fn redemption_json(record: &RedemptionRecord, display: &QuotaDisplaySettings) -> Value {
    json!({
        "id": record.id,
        "user_id": record.user_id,
        "key": record.key,
        "status": record.status,
        "name": record.name,
        "quota": record.quota,
        "quota_display": display.to_display(record.quota),
        "redeemed_time": record.redeemed_time,
        "created_time": record.created_time,
        "used_user_id": record.used_user_id,
        "count": 0,
        "expired_time": record.expired_time,
    })
}

/// Go `AddRedemption` 的中途失败：`redemption.create_failed` + 已生成的码。
fn create_failure(headers: &HeaderMap, keys: &[String]) -> Response {
    Json(json!({
        "success": false,
        "message": translate(headers, MSG_CREATE_FAILED),
        "data": keys,
    }))
    .into_response()
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

fn database_error(headers: &HeaderMap, error: &sqlx::Error) -> Response {
    tracing::warn!(
        event = "redemption_database_operation_failed",
        category = crate::database_error_class(error),
        "redemption database operation failed"
    );
    Json(json!({
        "success": false,
        "message": translate(headers, MSG_DATABASE_ERROR),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_info_matches_go_defaults_and_aliases() {
        let empty = page_info(&RedemptionPageQuery::default());
        assert_eq!(
            empty,
            PageInfo {
                page: 1,
                page_size: 10,
                offset: 0
            }
        );
        let explicit = page_info(&RedemptionPageQuery {
            p: Some("3".to_owned()),
            page_size: Some("20".to_owned()),
            ..RedemptionPageQuery::default()
        });
        assert_eq!(
            explicit,
            PageInfo {
                page: 3,
                page_size: 20,
                offset: 40
            }
        );
        // `ps` then `size` compatibility aliases.
        assert_eq!(
            page_info(&RedemptionPageQuery {
                p: Some("0".to_owned()),
                ps: Some("5".to_owned()),
                ..RedemptionPageQuery::default()
            })
            .page_size,
            5
        );
        assert_eq!(
            page_info(&RedemptionPageQuery {
                size: Some("7".to_owned()),
                ..RedemptionPageQuery::default()
            })
            .page_size,
            7
        );
        // Page size is capped at 100; page 0 falls back to 1.
        assert_eq!(
            page_info(&RedemptionPageQuery {
                page_size: Some("1000".to_owned()),
                ..RedemptionPageQuery::default()
            })
            .page_size,
            100
        );
    }

    #[test]
    fn request_null_and_missing_fields_are_the_go_zero_value() {
        let headers = HeaderMap::new();
        assert!(parse_redemption_request(&headers, b"null").is_some());
        // 空体与未知 Content-Type 是零值，不是错误（Go 的 Bind 边界）。
        assert!(parse_redemption_request(&headers, b"").is_some());
        let request = parse_redemption_request(&headers, br#"{}"#).unwrap();
        assert_eq!(request.count, None);
        assert_eq!(request.name, None);
    }

    #[test]
    fn request_rejects_non_object_and_mismatched_types() {
        let headers = HeaderMap::new();
        assert!(parse_redemption_request(&headers, b"[]").is_none());
        assert!(parse_redemption_request(&headers, b"{").is_none());
        // Go：count 是 int，浮点/字符串类型不匹配。
        assert!(parse_redemption_request(&headers, br#"{"count":1.5}"#).is_none());
        assert!(parse_redemption_request(&headers, br#"{"count":"3"}"#).is_none());
        assert_eq!(
            parse_redemption_request(&headers, br#"{"count":3}"#)
                .unwrap()
                .count,
            Some(3)
        );
    }

    #[test]
    fn redemption_json_carries_every_go_field() {
        let record = RedemptionRecord {
            id: 7,
            user_id: 2,
            key: "abcd1234abcd1234abcd1234abcd1234".to_owned(),
            status: 1,
            name: "gift".to_owned(),
            quota: 500_000,
            redeemed_time: 0,
            created_time: 0,
            used_user_id: 0,
            expired_time: 0,
        };
        let display = QuotaDisplaySettings {
            quota_per_unit: 500_000.0,
            kind: newapi_identity::self_user::QuotaDisplayKind::Usd,
        };
        let body = redemption_json(&record, &display);
        assert_eq!(body["id"], json!(7));
        assert_eq!(body["key"], json!("abcd1234abcd1234abcd1234abcd1234"));
        assert_eq!(body["quota"], json!(500_000));
        assert_eq!(body["quota_display"], json!(1.0));
        assert_eq!(body["count"], json!(0));
        assert_eq!(body["expired_time"], json!(0));
        assert!(body.get("deleted_at").is_none());
    }
}
