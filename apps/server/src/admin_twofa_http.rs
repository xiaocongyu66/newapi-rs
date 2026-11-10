//! Admin 2FA HTTP adapters: `GET /api/user/2fa/stats` and
//! `DELETE /api/user/:id/2fa`.
//!
//! Go references:
//! - `apps/api/internal/identity/manage_twofa.go:526-591` (`Admin2FAStats`,
//!   `AdminDisable2FA`)
//! - `apps/api/internal/identity/store_twofa.go:400-424` (`GetTwoFAStats`)
//! - `apps/api/internal/identity/manage_users.go:374-376`
//!   (`canManageTargetRole`)
//! - `apps/api/internal/transport/compose/register_api.go:221-223`
//!   (`adminRoute` = `userRoute` 的 `UserAuth` 之后再挂 `security.AdminAuth()`，
//!   两条路由均无 `DisableCache`)
//!
//! 与用户侧 `twofa_http` 的差异：本模块的四个业务消息是 Go 硬编码的中文字面量
//! （`common.H{"message": "..."}`，不走 i18n），前端按字面量比对，因此逐字返回。
//! 其余两个分类分支（目标用户不存在、存储故障）在 Go 走
//! `common.CtxApiError`（原文直接回显数据库错误文本）；Rust 不泄漏 SQL，
//! 沿用本域既有分类消息。`enabled_rate` 是 Go `fmt.Sprintf("%.1f%%", ...)`
//! 的字符串结果。
//!
//! Go 在禁用成功后还会 `RevokeAllUserSessions(userId, "admin_twofa_disabled")`
//! （`manage_twofa.go:580-583`）与 `writeManageAudit(c, userId,
//! "user.2fa_disable", nil)`：前者把该用户全部活跃会话行即时置 revoked
//! （会话列表随即不再显示），由本模块在禁用事务提交后调用
//! `SessionAuth::revoke_all` 完成；失败按 Go `common.CtxApiError` 的端口
//! 分类回 200 success:false + common.database_error（此时审计不写，与
//! Go 的调用顺序一致）。后者由 `newapi_identity::audit::record_manage_audit`
//! 写入，失败仅告警。

use std::net::SocketAddr;

use axum::{
    Json,
    extract::{ConnectInfo, Extension, Path, Request, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use newapi_identity::{
    audit::AuditOperator,
    two_fa::{TwoFaError, TwoFaRepository, can_manage_target_role},
    user_auth::CredentialKind,
    users::UserProfileRepository,
};
use serde_json::json;

use crate::AppState;
use crate::auth::AuthenticatedUser;

/// Go `manage_twofa.go:546`：`strconv.Atoi` 失败。
const MSG_ID_FORMAT_ERROR: &str = "用户ID格式错误";
/// Go `GetUserById`（`store_users.go:411-413`）：id 为 0 时的前置错误，
/// 与 `Atoi` 失败一样是硬编码中文。
const MSG_ID_EMPTY_ERROR: &str = "id 为空！";
/// Go `manage_twofa.go:563`：`canManageTargetRole` 拒绝。
const MSG_ROLE_INSUFFICIENT: &str = "无权操作同级或更高级用户的2FA设置";
/// Go `manage_twofa.go:573`：`ErrTwoFANotEnabled`。
const MSG_NOT_ENABLED: &str = "用户未启用2FA";
/// Go `manage_twofa.go:589`：成功消息（无 `data`）。
const MSG_ADMIN_DISABLED: &str = "用户2FA已被强制禁用";
/// Go `CtxApiError` 的 Rust 分类替代（不泄漏 SQL 文本）。
const MSG_DATABASE_ERROR: &str = "common.database_error";
/// 目标用户不存在时的 Rust 分类替代（Go 回显 `record not found`）。
const MSG_USER_NOT_FOUND: &str = "twofa.user_not_found";

/// Go `Admin2FAStats`：两个 COUNT 聚合，200 包裹，无缓存头。
pub async fn admin_stats(
    State(state): State<AppState>,
    Extension(_admin_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match TwoFaRepository::new(db).admin_stats().await {
        Ok(stats) => Json(json!({
            "success": true,
            "message": "",
            "data": {
                "total_users": stats.total_users,
                "enabled_users": stats.enabled_users,
                "enabled_rate": stats.enabled_rate,
            },
        }))
        .into_response(),
        Err(_) => {
            // `admin_stats` 的唯一失败分类是 `TwoFaError::Unavailable`；仓储层
            // 不转述 SQL 文本，这里同样只记固定事件名。
            tracing::warn!(
                event = "twofa_admin_stats_failed",
                "2FA admin stats query failed"
            );
            api_error(&headers, MSG_DATABASE_ERROR)
        }
    }
}

/// Go `AdminDisable2FA`：管理员强制禁用，无需密码/验证码。
pub async fn admin_disable(
    State(state): State<AppState>,
    Extension(admin_user): Extension<AuthenticatedUser>,
    Path(user_id): Path<String>,
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
    let headers = parts.headers;
    let client_ip = crate::http::request_ip(&state, &headers, peer);
    let now = crate::http::now_seconds();

    // Go `strconv.Atoi`：可选符号加十进制数字；溢出与非法字符同一分支。
    let Ok(user_id) = user_id.parse::<i64>() else {
        return api_error_literal(MSG_ID_FORMAT_ERROR);
    };
    // Go `GetUserById(0, false)` 在查库前就以固定文案失败。
    if user_id == 0 {
        return api_error_literal(MSG_ID_EMPTY_ERROR);
    }

    // Go `GetUserById(userId, false)`：GORM 软删除作用域排除已删除用户。
    let target = match UserProfileRepository::new(db.clone()).by_id(user_id).await {
        Ok(Some(target)) => target,
        Ok(None) => return api_error(&headers, MSG_USER_NOT_FOUND),
        Err(error) => return database_error(&headers, &error),
    };

    // Go `canManageTargetRole(myRole, targetUser.Role)`。
    if !can_manage_target_role(admin_user.0.role, target.role) {
        return api_error_literal(MSG_ROLE_INSUFFICIENT);
    }

    // Go `DisableTwoFAWithAuthVersion`：同一事务硬删除因子/备用码并递增
    // `users.auth_version`（旧令牌随即被版本检查拒绝，但活跃会话行要靠
    // 下面的撤销批次立即失效）。
    match TwoFaRepository::new(db.clone())
        .disable_with_auth_version(user_id, now)
        .await
    {
        // The returned auth version is only needed by the session-rotation
        // path; the admin response does not expose it.
        Ok(_next_auth_version) => {}
        Err(TwoFaError::NotEnabled) => return api_error_literal(MSG_NOT_ENABLED),
        Err(error) => return two_fa_error_response(&headers, error),
    }

    // Go `manage_twofa.go:580-583`：禁用事务提交后撤销该用户全部活跃会话
    // （`RevokeAllUserSessions(userId, "admin_twofa_disabled")`），失败回
    // `common.CtxApiError`——Rust 沿用本端口分类，且不写审计（Go 在撤销
    // 失败时直接返回，`writeManageAudit` 不会执行）。
    let Some(auth) = state.auth() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if let Err(error) = auth.revoke_all(user_id, "admin_twofa_disabled", now).await {
        tracing::warn!(
            event = "admin_twofa_session_revoke_failed",
            error = ?error,
            "admin 2FA session revoke failed"
        );
        return api_error(&headers, MSG_DATABASE_ERROR);
    }

    // Go `writeManageAudit(c, userId, "user.2fa_disable", nil)`：失败仅告警。
    let auth_method = match admin_user.0.credential {
        CredentialKind::DashboardSession => "session",
        CredentialKind::PersonalAccessToken => "access_token",
    };
    newapi_identity::audit::record_manage_audit(
        &db,
        &AuditOperator {
            user_id: admin_user.0.user_id,
            username: &admin_user.0.username,
            role: admin_user.0.role,
            auth_method,
        },
        "user.2fa_disable",
        user_id,
        &client_ip,
        now,
    )
    .await;

    Json(json!({
        "success": true,
        "message": MSG_ADMIN_DISABLED,
    }))
    .into_response()
}

/// Go `common.CtxApiError` 的 Rust 分类替代：固定文案，不转述数据库错误。
fn database_error(headers: &HeaderMap, error: &sqlx::Error) -> Response {
    tracing::warn!(
        event = "admin_twofa_database_operation_failed",
        category = crate::database_error_class(error),
        "admin 2FA database operation failed"
    );
    api_error(headers, MSG_DATABASE_ERROR)
}

fn api_error(headers: &HeaderMap, key: &str) -> Response {
    Json(json!({
        "success": false,
        "message": translate(headers, key),
    }))
    .into_response()
}

/// Go 的硬编码中文分支：逐字返回，不经 i18n（前端按字面量比对）。
fn api_error_literal(message: &str) -> Response {
    Json(json!({
        "success": false,
        "message": message,
    }))
    .into_response()
}

fn two_fa_error_response(headers: &HeaderMap, error: TwoFaError) -> Response {
    let language = request_language(headers);
    Json(json!({
        "success": false,
        "message": error.client_message(&language),
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
