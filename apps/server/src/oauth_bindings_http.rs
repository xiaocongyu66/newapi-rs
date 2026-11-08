//! OAuth 绑定端点适配层：Go `identity.GetUserOAuthBindings` /
//! `UnbindCustomOAuth` / `GetUserOAuthBindingsByAdmin` / `UnbindCustomOAuthByAdmin`
//! （`apps/api/internal/identity/bind_custom_oauth.go:467-582`）。
//!
//! ## 路由链（`register_api.go:200-212`）
//!
//! - `GET /api/user/oauth/bindings`、`DELETE /api/user/oauth/bindings/:provider_id`
//!   挂 `selfRoute` 的 `UserAuth()`，无限流、无 `DisableCache`；
//! - `GET /api/user/:id/oauth/bindings`、`DELETE /api/user/:id/oauth/bindings/:provider_id`
//!   挂 `adminRoute` 的 `AdminAuth()`（`userRoute` 自身无组级中间件），同样
//!   无 `DisableCache`、无限流。
//!
//! 四条路由都不写缓存头，本端口也不写。
//!
//! ## 响应契约（逐条对齐 Go 手写 `common.H`）
//!
//! - 两条 GET 成功：`{"success": true, "message": "", "data": [...]}`，`data`
//!   恒为数组（Go `make(..., 0, len)` 空集合也序列化成 `[]` 而非 `null`）；
//! - self 解绑成功：`{"success": true, "message": "解绑成功"}`，**无** `data` 键；
//! - admin 解绑成功：`{"success": true, "message": "success"}`（Go 用了英文
//!   字面量而非 self 线的“解绑成功”），同样 **无** `data` 键；
//! - 失败一律 HTTP 200 + `{"success": false, "message": ...}`，无 `data`、无 `code`。
//!
//! 以下文案是 Go 的硬编码字面量（不走 i18n，前端按字面量比对），逐字返回：
//! `无效的提供商 ID`、`解绑成功`、`invalid user id`、`no permission`、
//! `invalid provider id`、`success`、`id 为空！`（`GetUserById` 的前置错误）。
//!
//! ## 与 Go 的两处有意分歧（均为“不泄漏数据库文本”的端口既有约定）
//!
//! 1. Go 在 `GetUserById` 失败时 `CtxApiError(c, err)` 原样回显
//!    GORM 的 `record not found`；本端口用固定 i18n 键 `user.not_exists`，
//!    与 `aff_http` / `setting_http` 对同一 Go 分支的处理一致。
//! 2. Go 的存储错误同样原文回显；本端口折叠为 `common.database_error`，
//!    SQL 文本不外泄。
//!
//! ## 审计
//!
//! 只有 admin DELETE 会落审计：Go `authHelper` 仅在
//! `minRole >= RoleAdminUser` 时用 `beginAdminAudit` 捕获响应，而
//! `beginAdminAudit` 又只捕获写方法（`audit_access.go:74-81`）。因此
//! 两个 self 路由（`UserAuth`，minRole=1）与 admin GET（读方法）都不写日志；
//! admin DELETE 的 handler 自己没有埋点，由 `finishAdminAudit` 兜底记录一条
//! `action = "user.oauth_unbind"`（`auditRouteActions`，`audit_access.go:21`）
//! 的管理审计，**与业务成败无关**——`no permission`、`invalid user id` 等
//! 失败也照样落库，区别只在 `other.audit_info.success`。
//! 401/403 由 `AdminAuth` 在进入 handler 前中断，不产生审计。
//!
//! 本端口把兜底审计内联进 handler：`success` 直接取自分支结果（等价 Go 解析
//! 响应体的 `success` 字段；这些响应恒为 HTTP 200），落库在返回前 await
//! （Go 丢进 `gopool.Go`）——可观察结果同为一行 `type=3` 的日志，失败仅告警。
//!
//! Go 的 `userId := c.GetInt("id")` + `未登录` 分支在本端口不可达：
//! `user_auth` 中的 `authorize` 已拒绝 `user_id <= 0`（`UserInvalid` → 401）。

use std::net::SocketAddr;

use axum::{
    Json,
    extract::{ConnectInfo, Extension, Path, Request, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use newapi_identity::{
    audit::{AuditOperator, RouteAudit, record_route_audit},
    oauth_bindings::OAuthBindingRepository,
    two_fa::can_manage_target_role,
    user_auth::{CredentialKind, UserAuthIdentity},
    users::UserProfileRepository,
};
use newapi_storage::Database;
use serde_json::json;

use crate::AppState;
use crate::auth::AuthenticatedUser;

/// Go `bind_custom_oauth.go:531`：self 解绑的 `strconv.Atoi` 失败（硬编码中文）。
const MSG_INVALID_PROVIDER_ID: &str = "无效的提供商 ID";
/// Go `bind_custom_oauth.go:544`：self 解绑成功（硬编码中文，无 data）。
const MSG_UNBOUND: &str = "解绑成功";
/// Go `bind_custom_oauth.go:491` / `:550`：admin 两条路由的 `Atoi(id)` 失败
///（硬编码英文）。
const MSG_INVALID_USER_ID: &str = "invalid user id";
/// Go `bind_custom_oauth.go:503` / `:562`：`canManageTargetRole` 拒绝（硬编码英文）。
const MSG_NO_PERMISSION: &str = "no permission";
/// Go `bind_custom_oauth.go:569`：admin 解绑的 `Atoi(providerId)` 失败（硬编码英文）。
const MSG_INVALID_PROVIDER_ID_ADMIN: &str = "invalid provider id";
/// Go `bind_custom_oauth.go:580`：admin 解绑成功（硬编码英文，无 data）。
const MSG_UNBOUND_ADMIN: &str = "success";
/// Go `GetUserById`（`store_users.go:411-413`）：id 为 0 时查库前的硬编码文案。
const MSG_USER_ID_EMPTY: &str = "id 为空！";
/// 目标用户不存在。Go 回显 GORM 的 `record not found`；本端口不泄漏数据库文本，
/// 沿用 `aff_http` / `setting_http` 对同一 Go 分支的分类键。
const MSG_USER_NOT_FOUND: &str = "user.not_exists";
/// Go `CtxApiError` 对存储错误的原文回显；Rust 分类替代。
const MSG_DATABASE_ERROR: &str = "common.database_error";

/// Go `auditRouteActions`（`security/audit_access.go:21`）登记的兜底 action。
const AUDIT_ACTION: &str = "user.oauth_unbind";
/// Go `c.FullPath()` 的注册路由模板（冒号风格与 Go 一致，落库内容不变）。
const ADMIN_UNBIND_ROUTE: &str = "/api/user/:id/oauth/bindings/:provider_id";

/// Go `GetUserOAuthBindings`（`bind_custom_oauth.go:467-485`）。
pub async fn user_bindings(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match OAuthBindingRepository::new(db)
        .views_for_user(auth_user.0.user_id)
        .await
    {
        Ok(views) => Json(json!({
            "success": true,
            "message": "",
            "data": views,
        }))
        .into_response(),
        Err(error) => {
            tracing::warn!(
                event = "oauth_bindings_list_failed",
                category = crate::database_error_class(&error),
                "oauth binding list read failed"
            );
            api_error(&headers, MSG_DATABASE_ERROR)
        }
    }
}

/// Go `UnbindCustomOAuth`（`bind_custom_oauth.go:521-544`）。
///
/// 顺序即契约：先解析 `provider_id`，再删除。GORM 的 `Delete` 对零行匹配不报错，
/// 所以解绑一条不存在的绑定同样返回成功（仓储层同样不把行数当错误）。
pub async fn unbind(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    Path(provider_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    // Go `strconv.Atoi`：可选符号加十进制数字；溢出与非法字符同一分支。
    let Ok(provider_id) = provider_id.parse::<i64>() else {
        return api_error_literal(MSG_INVALID_PROVIDER_ID);
    };
    match OAuthBindingRepository::new(db)
        .delete(auth_user.0.user_id, provider_id)
        .await
    {
        Ok(_) => api_success(MSG_UNBOUND),
        Err(error) => {
            tracing::warn!(
                event = "oauth_unbind_failed",
                category = crate::database_error_class(&error),
                "oauth binding delete failed"
            );
            api_error(&headers, MSG_DATABASE_ERROR)
        }
    }
}

/// Go `GetUserOAuthBindingsByAdmin`（`bind_custom_oauth.go:487-518`）。
///
/// 顺序即契约：`Atoi(id)` → `GetUserById` → `canManageTargetRole` → 组装绑定。
pub async fn admin_user_bindings(
    State(state): State<AppState>,
    Extension(admin_user): Extension<AuthenticatedUser>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(user_id) = user_id.parse::<i64>() else {
        return api_error_literal(MSG_INVALID_USER_ID);
    };
    // Go `GetUserById(0, false)` 在查库前就以固定文案失败。
    if user_id == 0 {
        return api_error_literal(MSG_USER_ID_EMPTY);
    }
    // Go `GetUserById(userId, false)`：GORM 软删除作用域排除已删除用户。
    let target = match UserProfileRepository::new(db.clone()).by_id(user_id).await {
        Ok(Some(target)) => target,
        Ok(None) => return api_error(&headers, MSG_USER_NOT_FOUND),
        Err(error) => return database_error(&headers, &error),
    };
    // Go `canManageTargetRole(myRole, targetUser.Role)`。
    if !can_manage_target_role(admin_user.0.role, target.role) {
        return api_error_literal(MSG_NO_PERMISSION);
    }
    match OAuthBindingRepository::new(db)
        .views_for_user(user_id)
        .await
    {
        Ok(views) => Json(json!({
            "success": true,
            "message": "",
            "data": views,
        }))
        .into_response(),
        Err(error) => database_error(&headers, &error),
    }
}

/// Go `UnbindCustomOAuthByAdmin`（`bind_custom_oauth.go:546-582`）。
///
/// 顺序即契约：`Atoi(id)` → `GetUserById` → `canManageTargetRole` →
/// `Atoi(providerId)` → 删除。角色检查**先于**提供商 ID 解析：无权限时即使
/// `provider_id` 是非法文本，返回的也是 `no permission`。
///
/// 兜底审计在分支判定之后统一写入（见模块注释的“审计”一节）。
pub async fn admin_unbind(
    State(state): State<AppState>,
    Extension(admin_user): Extension<AuthenticatedUser>,
    Path((user_id_text, provider_id_text)): Path<(String, String)>,
    request: Request,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let (parts, _body) = request.into_parts();
    let peer = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0);
    let path = parts.uri.path().to_owned();
    let headers = parts.headers;
    let client_ip = crate::http::request_ip(&state, &headers, peer);
    let now = crate::http::now_seconds();

    let outcome = unbind_flow(&db, &admin_user.0, &user_id_text, &provider_id_text).await;
    let (response, success) = respond(&headers, outcome);

    // Go `finishAdminAudit`：只要请求到达 handler（`AdminAuth` 已通过），
    // 无论业务成败都记录一条，`success` 取自响应体。
    record_route_audit(
        &db,
        RouteAudit {
            operator: &AuditOperator {
                user_id: admin_user.0.user_id,
                username: &admin_user.0.username,
                role: admin_user.0.role,
                auth_method: auth_method(admin_user.0.credential),
            },
            action: AUDIT_ACTION,
            method: "DELETE",
            route: ADMIN_UNBIND_ROUTE,
            path: &path,
            status: 200,
            success,
            route_params: vec![("id", user_id_text), ("provider_id", provider_id_text)],
            ip: &client_ip,
            now,
        },
    )
    .await;
    response
}

/// admin 解绑的业务判定；只移动文本与身份，不写响应、不写审计。
async fn unbind_flow(
    db: &Database,
    operator: &UserAuthIdentity,
    user_id_text: &str,
    provider_id_text: &str,
) -> UnbindOutcome {
    let Ok(user_id) = user_id_text.parse::<i64>() else {
        return UnbindOutcome::InvalidUserId;
    };
    if user_id == 0 {
        return UnbindOutcome::UserIdEmpty;
    }
    let target = match UserProfileRepository::new(db.clone()).by_id(user_id).await {
        Ok(Some(target)) => target,
        Ok(None) => return UnbindOutcome::UserNotFound,
        Err(error) => {
            tracing::warn!(
                event = "oauth_unbind_target_read_failed",
                category = crate::database_error_class(&error),
                "admin oauth unbind target lookup failed"
            );
            return UnbindOutcome::Database;
        }
    };
    if !can_manage_target_role(operator.role, target.role) {
        return UnbindOutcome::NoPermission;
    }
    let Ok(provider_id) = provider_id_text.parse::<i64>() else {
        return UnbindOutcome::InvalidProviderId;
    };
    match OAuthBindingRepository::new(db.clone())
        .delete(user_id, provider_id)
        .await
    {
        Ok(()) => UnbindOutcome::Unbound,
        Err(error) => {
            tracing::warn!(
                event = "oauth_admin_unbind_failed",
                category = crate::database_error_class(&error),
                "admin oauth binding delete failed"
            );
            UnbindOutcome::Database
        }
    }
}

/// 业务分支的固定分类；不携带数据库错误文本或凭证。
enum UnbindOutcome {
    InvalidUserId,
    UserIdEmpty,
    UserNotFound,
    Database,
    NoPermission,
    InvalidProviderId,
    Unbound,
}

/// Go `common.H` 成功体；返回是否成功，供兜底审计的 `success` 字段使用。
fn respond(headers: &HeaderMap, outcome: UnbindOutcome) -> (Response, bool) {
    match outcome {
        UnbindOutcome::Unbound => (api_success(MSG_UNBOUND_ADMIN), true),
        UnbindOutcome::InvalidUserId => (api_error_literal(MSG_INVALID_USER_ID), false),
        UnbindOutcome::UserIdEmpty => (api_error_literal(MSG_USER_ID_EMPTY), false),
        UnbindOutcome::UserNotFound => (api_error(headers, MSG_USER_NOT_FOUND), false),
        UnbindOutcome::Database => (api_error(headers, MSG_DATABASE_ERROR), false),
        UnbindOutcome::NoPermission => (api_error_literal(MSG_NO_PERMISSION), false),
        UnbindOutcome::InvalidProviderId => {
            (api_error_literal(MSG_INVALID_PROVIDER_ID_ADMIN), false)
        }
    }
}

fn auth_method(credential: CredentialKind) -> &'static str {
    // Go `auditAuthMethod`（`write_audit.go:76-81`）。
    match credential {
        CredentialKind::DashboardSession => "session",
        CredentialKind::PersonalAccessToken => "access_token",
    }
}

/// Go 手写成功体：`{"success": true, "message": ...}`，无 data 键。
fn api_success(message: &'static str) -> Response {
    Json(json!({
        "success": true,
        "message": message,
    }))
    .into_response()
}

/// Go 的硬编码字面量分支：逐字返回，不经 i18n（前端按字面量比对）。
fn api_error_literal(message: &str) -> Response {
    Json(json!({
        "success": false,
        "message": message,
    }))
    .into_response()
}

/// Go `CtxApiErrorI18n` 风格的分类替代：按请求语言解析固定键。
fn api_error(headers: &HeaderMap, key: &str) -> Response {
    Json(json!({
        "success": false,
        "message": translate(headers, key),
    }))
    .into_response()
}

fn database_error(headers: &HeaderMap, error: &sqlx::Error) -> Response {
    tracing::warn!(
        event = "oauth_bindings_database_operation_failed",
        category = crate::database_error_class(error),
        "oauth bindings database operation failed"
    );
    api_error(headers, MSG_DATABASE_ERROR)
}

fn translate(headers: &HeaderMap, key: &str) -> String {
    let accept_language = crate::request_lang::accept_language_header(headers);
    let language = crate::request_lang::request_language(accept_language.as_deref());
    newapi_i18n::translate(&language, key, std::iter::empty::<(&str, &str)>())
}
