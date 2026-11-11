//! 用户管理端七路由的 HTTP 适配（Go `identity/manage_users.go` 管理通路）：
//! `GET /api/user/`（GetAllUsers）、`GET /api/user/:id`（GetUser）、
//! `POST /api/user/`（CreateUser）、`PUT /api/user/`（UpdateUser）、
//! `DELETE /api/user/:id`（DeleteUser）、`GET /api/user/search`
//! （SearchUsersHandler）、`POST /api/user/manage`（ManageUser）。
//!
//! Go 参考：
//! - `apps/api/internal/identity/manage_users.go:329-402`（GetAllUsers/
//!   SearchUsersHandler/GetUser）、`manage_users.go:625-700`（UpdateUser）、
//!   `manage_users.go:910-940`（DeleteUser）、`manage_users.go:963-1019`
//!   （CreateUser）、`manage_users.go:1037-1258`（ManageUser）、
//!   `manage_users.go:374-376`（canManageTargetRole）
//! - `apps/api/internal/identity/store_users.go:341-408`（SearchUsers）、
//!   `store_users.go:612-778`（InsertWithTx/EditWithTx/UpdateWithTx）、
//!   `store_users_lifecycle.go:23-78`（listAllUsers/HardDeleteUserById）
//! - `apps/api/internal/identity/policy/override.go:41-120`（用户级覆盖写库）
//! - `apps/api/internal/transport/compose/register_api.go:204-218`（adminRoute：
//!   组级仅 `security.AdminAuth()`，无 DisableCache、无限流；401/403 只来自
//!   鉴权链，业务结果一律 HTTP 200 + `success` 信封）
//!
//! 与 Go 的响应契约：
//! - 列表/搜索 `data` 为 `PageInfo`：`page`/`page_size`/`total`/`items`。
//! - 每行是 Go `User` 结构的 JSON（`Omit("password","access_token")` 后
//!   `password`/`original_password`/`verification_code` 为空串，口令哈希与
//!   PAT 永不回显）；`remark` 带 `omitempty`，空串时缺键；`DeletedAt` 无
//!   json tag，按既有移植约定（token 列表）不输出。
//! - `GET /:id` 额外带 `admin_permissions`（capabilities 矩阵，永不缺键）与
//!   `qq_open_id`（omitempty）。
//! - 会话副作用逐条对照 Go：UpdateUser 在 auth_version 递增后
//!   `RevokeAllUserSessions(id, "admin_user_update")`（manage_users.go:682）；
//!   ManageUser demote 走 `"admin_demote"`（manage_users.go:1219）；其余
//!   enable/disable/promote 经 `User.Update` 的 `"user_security_changed"`；
//!   manage delete 经 `User.Delete` 的软删除（Rust 复用
//!   `UserProfileRepository::soft_delete`，撤销原因同为 `user_deleted`）；
//!   `DELETE /:id` 硬删用户行与会话行（Go 不再单独撤销）。
//!   `PublishUserAuthCache`/`InvalidateUserTokensCache` 的用户缓存部分：
//!   Rust 尚无用户缓存（登记缺口）；令牌缓存按 `AppState::token_cache`
//!   尽力失效，失败仅告警。`policy.ReloadPolicy` 无内存 enforcer，等价
//!   为无操作。enable 的 `runUserUnbanHook`（进程内自动封禁标记）未移植。
//!
//! Go 的 `CtxApiError` 原文回显（record not found、strconv 错误、SQL 文本）
//! 在此按既有约定收敛为固定分类：记录缺失 → `user.not_exists`，存储失败 →
//! `common.database_error`，路径参数解析失败 → `common.invalid_params`；
//! Go 硬编码的中文字面量（`id 为空！`、`无效的额度数值`）与
//! `only root can update admin permissions` 逐字返回。

use std::net::SocketAddr;

use axum::{
    Json,
    body::to_bytes,
    extract::{ConnectInfo, Extension, Path, Request, State},
    http::{HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use newapi_billing::topup::TopUpSettings;
use newapi_catalog::registration_settings::RegistrationSettings;
use newapi_identity::{
    admin_users::{
        AdminCreateInput, AdminEditInput, AdminEditOutcome, AdminManageError, AdminPermissionError,
        AdminUserRepository, AdminUserRow, PermissionOverrides, ROLE_ROOT_USER, resolve_sort,
    },
    audit::{AuditOperator, record_manage_audit_with_params},
    crypto::hash_password,
    policy::{CasbinRuleRepository, capabilities, denied_permissions},
    registration::{FinishInsert, FinishInsertSettings, RegistrationRepository},
    self_user::QuotaDisplaySettings,
    tokens::quota_from_display,
    two_fa::can_manage_target_role,
    user_auth::CredentialKind,
    users::{UserMutationError, UserProfileRepository},
};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::AppState;
use crate::auth::AuthenticatedUser;
use crate::http::{MAX_BODY_BYTES, now_seconds, request_ip};

const MSG_INVALID_PARAMS: &str = "common.invalid_params";
const MSG_DATABASE_ERROR: &str = "common.database_error";
const MSG_INPUT_INVALID: &str = "user.input_invalid";
const MSG_NOT_EXISTS: &str = "user.not_exists";
const MSG_EXISTS: &str = "user.exists";
const MSG_NO_PERMISSION_SAME_LEVEL: &str = "user.no_permission_same_level";
const MSG_NO_PERMISSION_HIGHER_LEVEL: &str = "user.no_permission_higher_level";
const MSG_CANNOT_CREATE_HIGHER_LEVEL: &str = "user.cannot_create_higher_level";
const MSG_CANNOT_DISABLE_ROOT: &str = "user.cannot_disable_root_user";
const MSG_CANNOT_DELETE_ROOT: &str = "user.cannot_delete_root_user";
const MSG_ADMIN_CANNOT_PROMOTE: &str = "user.admin_cannot_promote";
const MSG_ALREADY_ROOT: &str = "user.already_root";
const MSG_ALREADY_COMMON: &str = "user.already_common";
const MSG_CANNOT_DEMOTE_SELF: &str = "user.cannot_demote_self";
const MSG_QUOTA_CHANGE_ZERO: &str = "user.quota_change_zero";

/// Go `GetUserById(0)` 的硬编码中文（`store_users.go:411-413`），
/// 由 `GetUser`/`DeleteUser` 的 id==0 分支经 `CtxApiError` 原文回显。
const MSG_ID_EMPTY_ERROR: &str = "id 为空！";
/// Go `ManageUser` add_quota 的硬编码中文（`manage_users.go:1142`）。
const MSG_INVALID_QUOTA_VALUE: &str = "无效的额度数值";
/// Go `updateAdminPermissionsForUserInTx` 的固定错误文本
/// （`manage_users.go:1029`），经 `CtxApiError` 原文回显。
const MSG_ONLY_ROOT_PERMISSIONS: &str = "only root can update admin permissions";

/// Go `common.ItemsPerPage`（`common/constants.go:61`）。
const ITEMS_PER_PAGE: i64 = 10;
/// Go `common.GetPageQuery` 的 page_size 上限。
const MAX_PAGE_SIZE: i64 = 100;

/// Go `User.Password` 的空值占位，仅用于让 validator 通过。
const PASSWORD_PLACEHOLDER: &str = "$I_LOVE_U";

/// Go `User` 绑定形状（管理端创建/更新共用）。只保留参与校验、写库与
/// 覆盖判定的字段；其余字段解码后丢弃（Go BindJSON 同样忽略未知键）。
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct UserPayload {
    id: i64,
    username: String,
    password: String,
    display_name: String,
    role: i64,
    email: String,
    remark: String,
    group: String,
    admin_permissions: Option<PermissionOverrides>,
}

/// Go `ManageRequest`（`manage_users.go:1037-1046`）。
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ManageRequest {
    id: i64,
    action: String,
    value: i64,
    value_display: f64,
    mode: String,
}

/// 列表/搜索共用的查询参数。
#[derive(Debug, Default)]
struct AdminUserQuery {
    p: Option<String>,
    page_size: Option<String>,
    ps: Option<String>,
    size: Option<String>,
    keyword: Option<String>,
    group: Option<String>,
    role: Option<String>,
    status: Option<String>,
    sort_by: Option<String>,
    sort_order: Option<String>,
}

/// Go/axum 查询解码（`+` 为空格、`%XX` 按字节解码），与
/// `token_http::query_pairs` 同语义。
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

fn admin_user_query(uri: &Uri) -> AdminUserQuery {
    let pairs = query_pairs(uri);
    let get = |key: &str| {
        pairs
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.clone())
    };
    AdminUserQuery {
        p: get("p"),
        page_size: get("page_size"),
        ps: get("ps"),
        size: get("size"),
        keyword: get("keyword"),
        group: get("group"),
        role: get("role"),
        status: get("status"),
        sort_by: get("sort_by"),
        sort_order: get("sort_order"),
    }
}

/// Go `strconv.Atoi`：可选符号加十进制数字，无空白。
fn parse_i64(value: Option<&str>) -> Option<i64> {
    value.and_then(|value| value.parse::<i64>().ok())
}

/// Go `SearchUsersHandler` 的 role/status 解析：空串与非整数都不过滤。
fn parse_optional_int(value: &Option<String>) -> Option<i64> {
    value
        .as_deref()
        .filter(|value| !value.is_empty())
        .and_then(|value| value.parse::<i64>().ok())
}

/// Go `common.GetPageQuery`：`p`/`page_size` 与 `ps`/`size` 兼容别名，
/// 上限 100，缺省 10；负值与 Go 一样原样保留。
fn go_page_info(query: &AdminUserQuery) -> (i64, i64) {
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
            page_size = ITEMS_PER_PAGE;
        }
    }
    if page_size > MAX_PAGE_SIZE {
        page_size = MAX_PAGE_SIZE;
    }
    (page, page_size)
}

/// Go `Validate.Struct` 标签的字段级错误文本
/// （`register_http::field_error` 同形）。
fn field_error(field: &str, tag: &str) -> String {
    format!("Key: 'User.{field}' Error:Field validation for '{field}' failed on the '{tag}' tag")
}

/// Go `Validate.Struct(&user)`：username/display_name max 20、password
/// 8..20（空值经 9 字符占位通过）、email max 50、remark max 255；按
/// struct 字段序收集，`\n` 连接（validator `Error()` 形状）。
fn validation_error(request: &UserPayload) -> Option<String> {
    let mut errors: Vec<String> = Vec::new();
    if request.username.chars().count() > 20 {
        errors.push(field_error("Username", "max"));
    }
    let password = if request.password.is_empty() {
        PASSWORD_PLACEHOLDER
    } else {
        request.password.as_str()
    };
    let password_length = password.chars().count();
    if password_length < 8 {
        errors.push(field_error("Password", "min"));
    }
    if password_length > 20 {
        errors.push(field_error("Password", "max"));
    }
    if request.display_name.chars().count() > 20 {
        errors.push(field_error("DisplayName", "max"));
    }
    if request.email.chars().count() > 50 {
        errors.push(field_error("Email", "max"));
    }
    if request.remark.chars().count() > 255 {
        errors.push(field_error("Remark", "max"));
    }
    (!errors.is_empty()).then(|| errors.join("\n"))
}

/// Go `User` 结构的 JSON（`Omit("password","access_token")` 语义）：
/// 口令/PAT 相关键恒为空串，`remark` omitempty，无 json tag 的
/// `DeletedAt`/`AuthVersion` 不输出（后者本就是 `json:"-"`）。
fn admin_user_json(row: &AdminUserRow, display: &QuotaDisplaySettings) -> Value {
    let mut object = Map::new();
    object.insert("id".to_owned(), json!(row.id));
    object.insert("username".to_owned(), json!(row.username));
    object.insert("password".to_owned(), json!(""));
    object.insert("original_password".to_owned(), json!(""));
    object.insert("display_name".to_owned(), json!(row.display_name));
    object.insert("role".to_owned(), json!(row.role));
    object.insert("status".to_owned(), json!(row.status));
    object.insert("email".to_owned(), json!(row.email));
    object.insert("github_id".to_owned(), json!(row.github_id));
    object.insert("discord_id".to_owned(), json!(row.discord_id));
    object.insert("oidc_id".to_owned(), json!(row.oidc_id));
    object.insert("wechat_id".to_owned(), json!(row.wechat_id));
    object.insert("telegram_id".to_owned(), json!(row.telegram_id));
    object.insert("verification_code".to_owned(), json!(""));
    object.insert("quota".to_owned(), json!(row.quota));
    object.insert("used_quota".to_owned(), json!(row.used_quota));
    object.insert(
        "quota_display".to_owned(),
        json!(display.to_display(row.quota)),
    );
    object.insert(
        "used_quota_display".to_owned(),
        json!(display.to_display(row.used_quota)),
    );
    object.insert(
        "aff_quota_display".to_owned(),
        json!(display.to_display(row.aff_quota)),
    );
    object.insert(
        "aff_history_quota_display".to_owned(),
        json!(display.to_display(row.aff_history_quota)),
    );
    object.insert("request_count".to_owned(), json!(row.request_count));
    object.insert("group".to_owned(), json!(row.group));
    object.insert("aff_code".to_owned(), json!(row.aff_code));
    object.insert("aff_count".to_owned(), json!(row.aff_count));
    object.insert("aff_quota".to_owned(), json!(row.aff_quota));
    object.insert("aff_history_quota".to_owned(), json!(row.aff_history_quota));
    object.insert("inviter_id".to_owned(), json!(row.inviter_id));
    object.insert("linux_do_id".to_owned(), json!(row.linux_do_id));
    object.insert("setting".to_owned(), json!(row.setting));
    if !row.remark.is_empty() {
        object.insert("remark".to_owned(), json!(row.remark));
    }
    object.insert("stripe_customer".to_owned(), json!(row.stripe_customer));
    object.insert("created_at".to_owned(), json!(row.created_at));
    object.insert("last_login_at".to_owned(), json!(row.last_login_at));
    Value::Object(object)
}

/// Go `User{Role, Status}` 零值结构的管理响应 `data`：除角色/状态外全部
/// 为 Go 零值（`remark` omitempty 缺键）。
fn clear_user_json(role: i64, status: i64) -> Value {
    json!({
        "id": 0,
        "username": "",
        "password": "",
        "original_password": "",
        "display_name": "",
        "role": role,
        "status": status,
        "email": "",
        "github_id": "",
        "discord_id": "",
        "oidc_id": "",
        "wechat_id": "",
        "telegram_id": "",
        "verification_code": "",
        "quota": 0,
        "used_quota": 0,
        "quota_display": 0.0,
        "used_quota_display": 0.0,
        "aff_quota_display": 0.0,
        "aff_history_quota_display": 0.0,
        "request_count": 0,
        "group": "",
        "aff_code": "",
        "aff_count": 0,
        "aff_quota": 0,
        "aff_history_quota": 0,
        "inviter_id": 0,
        "linux_do_id": "",
        "setting": "",
        "stripe_customer": "",
        "created_at": 0,
        "last_login_at": 0,
    })
}

fn language(headers: &HeaderMap) -> String {
    crate::request_lang::request_language(
        crate::request_lang::accept_language_header(headers).as_deref(),
    )
}

fn translate(headers: &HeaderMap, key: &str) -> String {
    newapi_i18n::translate(&language(headers), key, std::iter::empty::<(&str, &str)>())
}

fn translate_args<I, K, V>(headers: &HeaderMap, key: &str, args: I) -> String
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: std::fmt::Display,
{
    newapi_i18n::translate(&language(headers), key, args)
}

fn api_error(headers: &HeaderMap, key: &str) -> Response {
    Json(json!({
        "success": false,
        "message": translate(headers, key),
    }))
    .into_response()
}

fn api_error_args<I, K, V>(headers: &HeaderMap, key: &str, args: I) -> Response
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: std::fmt::Display,
{
    Json(json!({
        "success": false,
        "message": translate_args(headers, key, args),
    }))
    .into_response()
}

/// Go 的硬编码字面量分支：逐字返回，不经 i18n。
fn api_error_literal(message: &str) -> Response {
    Json(json!({
        "success": false,
        "message": message,
    }))
    .into_response()
}

fn database_error(headers: &HeaderMap, error: &sqlx::Error) -> Response {
    // 诊断：输出原始错误文本以定位双后端差异（不进入对外响应）。
    tracing::warn!(
        event = "admin_users_database_operation_failed",
        category = crate::database_error_class(error),
        detail = %error,
        "admin user database operation failed"
    );
    api_error(headers, MSG_DATABASE_ERROR)
}

fn success_response() -> Response {
    Json(json!({"success": true, "message": ""})).into_response()
}

fn success_with_data(data: Value) -> Response {
    Json(json!({"success": true, "message": "", "data": data})).into_response()
}

fn audit_operator(admin_user: &AuthenticatedUser) -> AuditOperator<'_> {
    AuditOperator {
        user_id: admin_user.0.user_id,
        username: &admin_user.0.username,
        role: admin_user.0.role,
        auth_method: match admin_user.0.credential {
            CredentialKind::DashboardSession => "session",
            CredentialKind::PersonalAccessToken => "access_token",
        },
    }
}

/// Go `InvalidateUserTokensCache` 的缓存段：尽力失效，失败仅告警
/// （Go 的 SysLog 分支），不影响响应。
async fn invalidate_token_cache(state: &AppState, keys: &[String]) {
    if keys.is_empty() {
        return;
    }
    let Some(cache) = state.token_cache() else {
        return;
    };
    if let Err(error) = cache.invalidate_many(keys).await {
        tracing::warn!(
            event = "admin_user_token_cache_invalidate_failed",
            category = "redis",
            "failed to invalidate token cache after admin user mutation"
        );
        let _ = error;
    }
}

/// `GET /api/user/`：Go `GetAllUsers`（Unscoped 全量 + 分页/排序）。
pub async fn list_users(
    State(state): State<AppState>,
    Extension(_admin_user): Extension<AuthenticatedUser>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let query = admin_user_query(&uri);
    let (page, page_size) = go_page_info(&query);
    let offset = page.saturating_sub(1).saturating_mul(page_size);
    let sort = resolve_sort(
        query.sort_by.as_deref().unwrap_or(""),
        query.sort_order.as_deref().unwrap_or(""),
    );
    match AdminUserRepository::new(db)
        .list(offset, page_size, sort)
        .await
    {
        Ok((rows, total)) => {
            let display = state.quota_display();
            let items: Vec<Value> = rows
                .iter()
                .map(|row| admin_user_json(row, &display))
                .collect();
            Json(json!({
                "success": true,
                "message": "",
                "data": {
                    "page": page,
                    "page_size": page_size,
                    "total": total,
                    "items": items,
                },
            }))
            .into_response()
        }
        Err(error) => database_error(&headers, &error),
    }
}

/// `GET /api/user/search`：Go `SearchUsersHandler`。
pub async fn search_users(
    State(state): State<AppState>,
    Extension(_admin_user): Extension<AuthenticatedUser>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let query = admin_user_query(&uri);
    let (page, page_size) = go_page_info(&query);
    let offset = page.saturating_sub(1).saturating_mul(page_size);
    let sort = resolve_sort(
        query.sort_by.as_deref().unwrap_or(""),
        query.sort_order.as_deref().unwrap_or(""),
    );
    let role = parse_optional_int(&query.role);
    let status = parse_optional_int(&query.status);
    match AdminUserRepository::new(db)
        .search(
            query.keyword.as_deref().unwrap_or(""),
            query.group.as_deref().unwrap_or(""),
            role,
            status,
            offset,
            page_size,
            sort,
        )
        .await
    {
        Ok((rows, total)) => {
            let display = state.quota_display();
            let items: Vec<Value> = rows
                .iter()
                .map(|row| admin_user_json(row, &display))
                .collect();
            Json(json!({
                "success": true,
                "message": "",
                "data": {
                    "page": page,
                    "page_size": page_size,
                    "total": total,
                    "items": items,
                },
            }))
            .into_response()
        }
        Err(error) => database_error(&headers, &error),
    }
}

/// `GET /api/user/:id`：Go `GetUser`。
pub async fn get_user(
    State(state): State<AppState>,
    Extension(admin_user): Extension<AuthenticatedUser>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    // Go `strconv.Atoi` 失败原文回显；Rust 收敛为固定分类。
    let Ok(user_id) = id.parse::<i64>() else {
        return api_error(&headers, MSG_INVALID_PARAMS);
    };
    // Go `GetUserById(0, false)` 的硬编码文案。
    if user_id == 0 {
        return api_error_literal(MSG_ID_EMPTY_ERROR);
    }
    let repository = AdminUserRepository::new(db.clone());
    let target = match repository.admin_by_id(user_id).await {
        Ok(Some(target)) => target,
        Ok(None) => return api_error(&headers, MSG_NOT_EXISTS),
        Err(error) => return database_error(&headers, &error),
    };
    if !can_manage_target_role(admin_user.0.role, target.role) {
        return api_error(&headers, MSG_NO_PERMISSION_SAME_LEVEL);
    }
    // Go `policy.Capabilities(user.Id, user.Role)`：从不失败，策略不可读
    // 时按空 enforcer 语义降级（root 全真，其余全假）。
    let admin_permissions = match capabilities(
        &CasbinRuleRepository::new(db.clone()),
        target.id,
        target.role as i32,
    )
    .await
    {
        Ok(permissions) => permissions,
        Err(error) => {
            tracing::warn!(
                event = "admin_user_capabilities_load_failed",
                category = crate::database_error_class(&error),
                "admin user capability load failed; denying all permissions"
            );
            denied_permissions(target.role as i32).admin_permissions
        }
    };
    let mut data = admin_user_json(&target, &state.quota_display());
    if let Some(object) = data.as_object_mut() {
        object.insert(
            "admin_permissions".to_owned(),
            serde_json::to_value(&admin_permissions).unwrap_or_else(|_| json!({})),
        );
        // Go `user.QQOpenID, _ = IsQQBoundByUserId(user.Id)`：未绑定为空串，
        // omitempty 后缺键。
        if let Some(open_id) = repository.qq_open_id(user_id).await {
            object.insert("qq_open_id".to_owned(), json!(open_id));
        }
    }
    success_with_data(data)
}

/// Go `finishInsert` 的选项快照装载（`register_http::load_finish_insert_settings`
/// 同形）：读取失败按 Go 的零值默认继续。
async fn load_finish_insert_settings(state: &AppState) -> FinishInsertSettings {
    let mut settings = FinishInsertSettings {
        quota_for_new_user: 0,
        quota_for_invitee: 0,
        quota_for_inviter: 0,
        payment_compliance_confirmed: false,
    };
    let Some(db) = state.db() else {
        return settings;
    };
    match RegistrationSettings::load(&db, &RegistrationSettings::default()).await {
        Ok(registration) => {
            settings.quota_for_new_user = registration.quota_for_new_user;
            settings.quota_for_invitee = registration.quota_for_invitee;
            settings.quota_for_inviter = registration.quota_for_inviter;
        }
        Err(error) => tracing::warn!(
            event = "admin_user_registration_settings_load_failed",
            category = crate::database_error_class(&error),
            "registration settings load failed; skipping quota rewards"
        ),
    }
    match TopUpSettings::load(&db).await {
        Ok(topup) => settings.payment_compliance_confirmed = topup.payment_compliance_confirmed(),
        Err(error) => tracing::warn!(
            event = "admin_user_compliance_check_failed",
            category = crate::database_error_class(&error),
            "payment compliance load failed; treating as unconfirmed"
        ),
    }
    settings
}

/// `POST /api/user/`：Go `CreateUser`。
pub async fn create_user(
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
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0);
    let client_ip = request_ip(&state, &headers, peer);
    let now = now_seconds();

    let body = match to_bytes(body, MAX_BODY_BYTES).await {
        Ok(body) => body,
        Err(_) => return api_error(&headers, MSG_INVALID_PARAMS),
    };
    let payload = match crate::body_bind::bind_body::<UserPayload>(&headers, &body) {
        Ok(payload) => payload,
        Err(()) => return api_error(&headers, MSG_INVALID_PARAMS),
    };
    // Go：`err != nil || user.Username == "" || user.Password == ""`。
    let username = payload.username.trim().to_owned();
    if username.is_empty() || payload.password.is_empty() {
        return api_error(&headers, MSG_INVALID_PARAMS);
    }
    if let Some(error) = validation_error(&payload) {
        return api_error_args(&headers, MSG_INPUT_INVALID, [("Error", error)]);
    }
    let display_name = if payload.display_name.is_empty() {
        username.clone()
    } else {
        payload.display_name.clone()
    };
    if payload.role >= admin_user.0.role {
        return api_error(&headers, MSG_CANNOT_CREATE_HIGHER_LEVEL);
    }
    // Go：`CheckUserExistOrDeleted`（含软删除行）在插入前拦截重名。
    let repository = AdminUserRepository::new(db.clone());
    match repository.username_exists(&username).await {
        Ok(true) => return api_error(&headers, MSG_EXISTS),
        Ok(false) => {}
        Err(error) => return database_error(&headers, &error),
    }
    let password_hash = match hash_password(payload.password.as_bytes()) {
        Ok(hash) => hash.expose_secret().to_owned(),
        Err(_) => return api_error(&headers, MSG_DATABASE_ERROR),
    };
    let finish_settings = load_finish_insert_settings(&state).await;
    // Go：GORM `default:1` 让零值 role 落库为普通用户（JSON 缺省 role=0 时
    // 插入语句省略该列，数据库默认值生效）。
    let role = if payload.role == 0 { 1 } else { payload.role };
    let input = AdminCreateInput {
        username: &username,
        password_hash: &password_hash,
        display_name: &display_name,
        role,
        quota: finish_settings.quota_for_new_user,
        created_at: now,
        operator_role: admin_user.0.role,
        permissions: payload.admin_permissions.as_ref(),
    };
    let user_id = match repository.create(&input).await {
        Ok(user_id) => user_id,
        Err(AdminPermissionError::OnlyRootCanUpdate) => {
            return api_error_literal(MSG_ONLY_ROOT_PERMISSIONS);
        }
        Err(AdminPermissionError::Storage(error)) => {
            return database_error(&headers, &error);
        }
    };
    // Go `cleanUser.FinishInsert(0)`：侧栏初始化与新用户赠送日志；
    // 全部 best-effort，不改变响应。
    let display = state.quota_display();
    RegistrationRepository::new(db.clone())
        .finish_insert(FinishInsert {
            user_id,
            username: &username,
            inviter_id: 0,
            settings: &finish_settings,
            display: &display,
            now,
        })
        .await;
    let mut params = Map::new();
    params.insert("username".to_owned(), json!(username));
    params.insert("role".to_owned(), json!(payload.role));
    record_manage_audit_with_params(
        &db,
        &audit_operator(&admin_user),
        "user.create",
        user_id,
        Some(&params),
        &client_ip,
        now,
    )
    .await;
    success_response()
}

/// `PUT /api/user/`：Go `UpdateUser`。
pub async fn update_user(
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
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0);
    let client_ip = request_ip(&state, &headers, peer);
    let now = now_seconds();

    let body = match to_bytes(body, MAX_BODY_BYTES).await {
        Ok(body) => body,
        Err(_) => return api_error(&headers, MSG_INVALID_PARAMS),
    };
    let payload = match crate::body_bind::bind_body::<UserPayload>(&headers, &body) {
        Ok(payload) => payload,
        Err(()) => return api_error(&headers, MSG_INVALID_PARAMS),
    };
    // Go：`err != nil || updatedUser.Id == 0`。
    if payload.id == 0 {
        return api_error(&headers, MSG_INVALID_PARAMS);
    }
    let username = payload.username.trim().to_owned();
    if username.is_empty() {
        return api_error(&headers, MSG_INVALID_PARAMS);
    }
    // Go 的占位符往返：空密码经 `$I_LOVE_U` 过校验后回滚为空串。
    if let Some(error) = validation_error(&payload) {
        return api_error_args(&headers, MSG_INPUT_INVALID, [("Error", error)]);
    }
    let password = if payload.password == PASSWORD_PLACEHOLDER {
        String::new()
    } else {
        payload.password.clone()
    };
    let repository = AdminUserRepository::new(db.clone());
    let origin = match repository.admin_by_id(payload.id).await {
        Ok(Some(origin)) => origin,
        Ok(None) => return api_error(&headers, MSG_NOT_EXISTS),
        Err(error) => return database_error(&headers, &error),
    };
    // Go：角色不可经 PUT 修改；请求角色非 guest 且与原值不同即拒绝。
    if payload.role != 0 && payload.role != origin.role {
        return api_error(&headers, MSG_INVALID_PARAMS);
    }
    if !can_manage_target_role(admin_user.0.role, origin.role) {
        return api_error(&headers, MSG_NO_PERMISSION_HIGHER_LEVEL);
    }
    let update_password = !password.is_empty();
    let password_hash = if update_password {
        match hash_password(password.as_bytes()) {
            Ok(hash) => Some(hash.expose_secret().to_owned()),
            Err(_) => return api_error(&headers, MSG_DATABASE_ERROR),
        }
    } else {
        None
    };
    let input = AdminEditInput {
        user_id: payload.id,
        username: &username,
        display_name: &payload.display_name,
        group: &payload.group,
        remark: &payload.remark,
        password_hash: password_hash.as_deref(),
        operator_role: admin_user.0.role,
        target_role: origin.role,
        permissions: payload.admin_permissions.as_ref(),
    };
    match repository.edit(&input).await {
        // Go：`updatedUser.AuthVersion > originUser.AuthVersion` 时撤销全部
        // 会话（原因 `admin_user_update`），失败即请求失败（更新已提交）。
        Ok(AdminEditOutcome::AuthVersionAdvanced { next_auth_version }) => {
            if next_auth_version > origin.auth_version
                && let Err(response) = revoke_after_admin_change(
                    &state,
                    payload.id,
                    "admin_user_update",
                    now,
                    &headers,
                )
                .await
            {
                return *response;
            }
        }
        Ok(AdminEditOutcome::Unchanged) => {}
        Err(AdminPermissionError::OnlyRootCanUpdate) => {
            return api_error_literal(MSG_ONLY_ROOT_PERMISSIONS);
        }
        Err(AdminPermissionError::Storage(error)) => {
            return database_error(&headers, &error);
        }
    }
    let mut params = Map::new();
    params.insert("username".to_owned(), json!(origin.username));
    params.insert("id".to_owned(), json!(payload.id));
    record_manage_audit_with_params(
        &db,
        &audit_operator(&admin_user),
        "user.update",
        payload.id,
        Some(&params),
        &client_ip,
        now,
    )
    .await;
    success_response()
}

/// `DELETE /api/user/:id`：Go `DeleteUser`（硬删除）。
pub async fn delete_user(
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
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0);
    let client_ip = request_ip(&state, &headers, peer);
    let now = now_seconds();

    let Ok(user_id) = id.parse::<i64>() else {
        return api_error(&headers, MSG_INVALID_PARAMS);
    };
    if user_id == 0 {
        return api_error_literal(MSG_ID_EMPTY_ERROR);
    }
    let repository = AdminUserRepository::new(db.clone());
    let origin = match repository.admin_by_id(user_id).await {
        Ok(Some(origin)) => origin,
        Ok(None) => return api_error(&headers, MSG_NOT_EXISTS),
        Err(error) => return database_error(&headers, &error),
    };
    // Go：`myRole <= originUser.Role` 拒绝——必须严格更高。
    if admin_user.0.role <= origin.role {
        return api_error(&headers, MSG_NO_PERMISSION_HIGHER_LEVEL);
    }
    let keys = match repository.hard_delete(user_id).await {
        Ok(keys) => keys,
        Err(error) => return database_error(&headers, &error),
    };
    invalidate_token_cache(&state, &keys).await;
    let mut params = Map::new();
    params.insert("username".to_owned(), json!(origin.username));
    params.insert("id".to_owned(), json!(origin.id));
    record_manage_audit_with_params(
        &db,
        &audit_operator(&admin_user),
        "user.delete",
        origin.id,
        Some(&params),
        &client_ip,
        now,
    )
    .await;
    success_response()
}

/// Go `RevokeAllUserSessions` 的固定失败收敛：撤销失败即请求失败
/// （`CtxApiError`），但写库结果已提交。
async fn revoke_after_admin_change(
    state: &AppState,
    user_id: i64,
    reason: &str,
    now: i64,
    headers: &HeaderMap,
) -> Result<(), Box<Response>> {
    let Some(auth) = state.auth() else {
        return Err(Box::new(api_error(headers, MSG_DATABASE_ERROR)));
    };
    match auth.revoke_all(user_id, reason, now).await {
        Ok(_) => Ok(()),
        Err(error) => {
            tracing::warn!(
                event = "admin_user_session_revoke_failed",
                reason,
                "failed to revoke user sessions after admin change"
            );
            let _ = error;
            Err(Box::new(api_error(headers, MSG_DATABASE_ERROR)))
        }
    }
}

/// `POST /api/user/manage`：Go `ManageUser`。
pub async fn manage_user(
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
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0);
    let client_ip = request_ip(&state, &headers, peer);
    let now = now_seconds();

    let body = match to_bytes(body, MAX_BODY_BYTES).await {
        Ok(body) => body,
        Err(_) => return api_error(&headers, MSG_INVALID_PARAMS),
    };
    let req = match crate::body_bind::bind_body::<ManageRequest>(&headers, &body) {
        Ok(req) => req,
        Err(()) => return api_error(&headers, MSG_INVALID_PARAMS),
    };
    let repository = AdminUserRepository::new(db.clone());
    // Go：Unscoped 读取目标；id==0 时 GORM struct 条件为空，按主键取第一行。
    let target = match repository.manage_target(req.id).await {
        Ok(Some(target)) => target,
        Ok(None) => return api_error(&headers, MSG_NOT_EXISTS),
        Err(error) => return database_error(&headers, &error),
    };
    if !can_manage_target_role(admin_user.0.role, target.role) {
        return api_error(&headers, MSG_NO_PERMISSION_HIGHER_LEVEL);
    }

    match req.action.as_str() {
        // Go：disable 先置状态再检查 root；因在写库前返回，顺序不影响结果。
        "disable" => {
            if target.role == ROLE_ROOT_USER {
                return api_error(&headers, MSG_CANNOT_DISABLE_ROOT);
            }
            apply_status_or_role(
                &state,
                &admin_user,
                &db,
                &headers,
                &client_ip,
                now,
                &target,
                Some(2),
                None,
            )
            .await
        }
        "enable" => {
            apply_status_or_role(
                &state,
                &admin_user,
                &db,
                &headers,
                &client_ip,
                now,
                &target,
                Some(1),
                None,
            )
            .await
        }
        "delete" => {
            if target.role == ROLE_ROOT_USER {
                return api_error(&headers, MSG_CANNOT_DELETE_ROOT);
            }
            // Go `user.Delete()`：递增版本、解绑 QQ、软删除并撤销全部会话。
            if let Err(error) = UserProfileRepository::new(db.clone())
                .soft_delete(target.id, now)
                .await
            {
                return mutation_error_response(&headers, error);
            }
            // Go：删除后清理该用户令牌缓存（失败仅 SysLog）。
            match repository.token_keys(target.id).await {
                Ok(keys) => invalidate_token_cache(&state, &keys).await,
                Err(error) => {
                    tracing::warn!(
                        event = "admin_user_token_keys_load_failed",
                        category = crate::database_error_class(&error),
                        "failed to load token keys for cache invalidation"
                    );
                }
            }
            let mut params = Map::new();
            params.insert("action".to_owned(), json!("delete"));
            params.insert("username".to_owned(), json!(target.username));
            params.insert("id".to_owned(), json!(target.id));
            record_manage_audit_with_params(
                &db,
                &audit_operator(&admin_user),
                "user.manage",
                target.id,
                Some(&params),
                &client_ip,
                now,
            )
            .await;
            success_response()
        }
        "promote" => {
            if admin_user.0.role != ROLE_ROOT_USER {
                return api_error(&headers, MSG_ADMIN_CANNOT_PROMOTE);
            }
            let new_role = match target.role {
                1 => 10,
                10 => 100,
                _ => return api_error(&headers, MSG_ALREADY_ROOT),
            };
            apply_status_or_role(
                &state,
                &admin_user,
                &db,
                &headers,
                &client_ip,
                now,
                &target,
                None,
                Some(new_role),
            )
            .await
        }
        "demote" => {
            if admin_user.0.role != ROLE_ROOT_USER {
                return api_error(&headers, MSG_ADMIN_CANNOT_PROMOTE);
            }
            if target.role == ROLE_ROOT_USER && target.id == admin_user.0.user_id {
                return api_error(&headers, MSG_CANNOT_DEMOTE_SELF);
            }
            let new_role = match target.role {
                ROLE_ROOT_USER => 10,
                10 => 1,
                _ => return api_error(&headers, MSG_ALREADY_COMMON),
            };
            // Go：同一事务内 UpdateWithTx + ClearUserAuthorizationInTx，
            // 之后 PublishUserAuthCache + RevokeAllUserSessions("admin_demote")。
            if let Err(error) = repository.demote(target.id, new_role).await {
                return manage_error_response(&headers, error);
            }
            if let Err(response) =
                revoke_after_admin_change(&state, target.id, "admin_demote", now, &headers).await
            {
                return *response;
            }
            match repository.token_keys(target.id).await {
                Ok(keys) => invalidate_token_cache(&state, &keys).await,
                Err(error) => {
                    tracing::warn!(
                        event = "admin_user_token_keys_load_failed",
                        category = crate::database_error_class(&error),
                        "failed to load token keys for cache invalidation"
                    );
                }
            }
            let mut params = Map::new();
            params.insert("action".to_owned(), json!("demote"));
            params.insert("username".to_owned(), json!(target.username));
            params.insert("id".to_owned(), json!(target.id));
            record_manage_audit_with_params(
                &db,
                &audit_operator(&admin_user),
                "user.manage",
                target.id,
                Some(&params),
                &client_ip,
                now,
            )
            .await;
            success_with_data(clear_user_json(new_role, target.status))
        }
        "add_quota" => {
            let mut quota_value = req.value;
            if req.value_display != 0.0 {
                if !req.value_display.is_finite() {
                    return api_error_literal(MSG_INVALID_QUOTA_VALUE);
                }
                quota_value = quota_from_display(req.value_display, &state.quota_display());
            }
            match req.mode.as_str() {
                "add" => {
                    if quota_value <= 0 {
                        return api_error(&headers, MSG_QUOTA_CHANGE_ZERO);
                    }
                    if let Err(error) = repository.increase_quota(target.id, quota_value).await {
                        return database_error(&headers, &error);
                    }
                    quota_audit(
                        &state,
                        &admin_user,
                        &db,
                        &client_ip,
                        now,
                        &target,
                        "user.quota_add",
                        quota_value,
                    )
                    .await;
                }
                "subtract" => {
                    if quota_value <= 0 {
                        return api_error(&headers, MSG_QUOTA_CHANGE_ZERO);
                    }
                    if let Err(error) = repository.decrease_quota(target.id, quota_value).await {
                        return database_error(&headers, &error);
                    }
                    quota_audit(
                        &state,
                        &admin_user,
                        &db,
                        &client_ip,
                        now,
                        &target,
                        "user.quota_subtract",
                        quota_value,
                    )
                    .await;
                }
                "override" => {
                    let old_quota = target.quota;
                    if let Err(error) = repository.override_quota(target.id, quota_value).await {
                        return database_error(&headers, &error);
                    }
                    let display = state.quota_display();
                    let mut params = Map::new();
                    params.insert(
                        "from".to_owned(),
                        json!(display.format_quota(old_quota, true)),
                    );
                    params.insert(
                        "to".to_owned(),
                        json!(display.format_quota(quota_value, true)),
                    );
                    record_manage_audit_with_params(
                        &db,
                        &audit_operator(&admin_user),
                        "user.quota_override",
                        target.id,
                        Some(&params),
                        &client_ip,
                        now,
                    )
                    .await;
                }
                _ => return api_error(&headers, MSG_INVALID_PARAMS),
            }
            success_response()
        }
        _ => api_error(&headers, MSG_INVALID_PARAMS),
    }
}

/// Go enable/disable/promote 的公共尾部（`manage_users.go:1223-1256`）：
/// `User.Update(false)` → auth_version 递增时撤销全部会话（原因
/// `user_security_changed`）→ enable 的 unban 钩子（未移植）→ 令牌缓存
/// 失效 → `user.manage` 审计 → 返回 `{role, status}` 零值结构。
#[allow(clippy::too_many_arguments)]
async fn apply_status_or_role(
    state: &AppState,
    admin_user: &AuthenticatedUser,
    db: &newapi_storage::Database,
    headers: &HeaderMap,
    client_ip: &str,
    now: i64,
    target: &AdminUserRow,
    status: Option<i64>,
    role: Option<i64>,
) -> Response {
    let action = if status.is_some() {
        if status == Some(2) {
            "disable"
        } else {
            "enable"
        }
    } else {
        "promote"
    };
    // Go `UpdateWithTx` 的 authChanged：角色/状态实际变化才递增版本。
    let bump = match (status, role) {
        (Some(status), None) => status != target.status,
        (None, Some(role)) => role != 0 && role != target.role,
        _ => false,
    };
    let repository = AdminUserRepository::new(db.clone());
    match repository
        .apply_manage_update(target.id, status, role, bump)
        .await
    {
        Ok(next_auth_version) => {
            if let Some(next_auth_version) = next_auth_version
                && next_auth_version > target.auth_version
                && let Err(response) = revoke_after_admin_change(
                    state,
                    target.id,
                    "user_security_changed",
                    now,
                    headers,
                )
                .await
            {
                return *response;
            }
        }
        Err(error) => return manage_error_response(headers, error),
    }
    // Go `runUserUnbanHook`：进程内自动封禁标记清理，未移植（登记缺口）。
    match repository.token_keys(target.id).await {
        Ok(keys) => invalidate_token_cache(state, &keys).await,
        Err(error) => {
            tracing::warn!(
                event = "admin_user_token_keys_load_failed",
                category = crate::database_error_class(&error),
                "failed to load token keys for cache invalidation"
            );
        }
    }
    let mut params = Map::new();
    params.insert("action".to_owned(), json!(action));
    params.insert("username".to_owned(), json!(target.username));
    params.insert("id".to_owned(), json!(target.id));
    record_manage_audit_with_params(
        db,
        &audit_operator(admin_user),
        "user.manage",
        target.id,
        Some(&params),
        client_ip,
        now,
    )
    .await;
    let effective_role = role.unwrap_or(target.role);
    let effective_status = status.unwrap_or(target.status);
    success_with_data(clear_user_json(effective_role, effective_status))
}

/// Go add/subtract 的审计（`manage_users.go:1158-1172`）：quota 参数为
/// `logger.LogQuota` 的展示字符串。
#[allow(clippy::too_many_arguments)]
async fn quota_audit(
    state: &AppState,
    admin_user: &AuthenticatedUser,
    db: &newapi_storage::Database,
    client_ip: &str,
    now: i64,
    target: &AdminUserRow,
    action: &str,
    quota_value: i64,
) {
    let display = state.quota_display();
    let mut params = Map::new();
    params.insert(
        "quota".to_owned(),
        json!(display.format_quota(quota_value, true)),
    );
    record_manage_audit_with_params(
        db,
        &audit_operator(admin_user),
        action,
        target.id,
        Some(&params),
        client_ip,
        now,
    )
    .await;
}

fn mutation_error_response(headers: &HeaderMap, error: UserMutationError) -> Response {
    if let UserMutationError::Storage(sqlx_error) = error {
        return database_error(headers, &sqlx_error);
    }
    api_error(headers, MSG_DATABASE_ERROR)
}

/// Go `UpdateWithTx` 的 scoped `First` 失败原文回显
/// （`record not found`）；Rust 收敛为固定分类。
fn manage_error_response(headers: &HeaderMap, error: AdminManageError) -> Response {
    match error {
        AdminManageError::NotFound => api_error(headers, MSG_DATABASE_ERROR),
        AdminManageError::Storage(sqlx_error) => database_error(headers, &sqlx_error),
    }
}
