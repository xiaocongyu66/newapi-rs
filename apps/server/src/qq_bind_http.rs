//! 五条 QQ 路由的 HTTP 适配层：Go `apps/api/internal/billing/manage_qqbot.go`
//! 的 `GetQQBindStatus` / `GenerateQQBindCode` / `UnbindQQ` / `SyncQQPanel`
//! （第五条 `ConsumeQQBindCode` 由 QQ webhook 事件驱动，不在本切片）。
//!
//! Go 参考：
//! - `manage_qqbot.go:344-363`（`GetQQBindStatus`）
//! - `manage_qqbot.go:365-385`（`GenerateQQBindCode`）
//! - `manage_qqbot.go:387-399`（`UnbindQQ`）
//! - `manage_qqbot.go:401-411`（`SyncQQPanel`）
//! - `apps/api/internal/transport/compose/register_api.go:193-197`（路由注册
//!   与中间件差异）
//! - `apps/api/internal/identity/qq_binding.go`（绑定码与解绑存储）
//! - `apps/api/internal/billing/qqbot_setting.go`（`qq_bot_setting` 分片）
//!
//! ## 信封
//!
//! 走 `common.CtxApiSuccess` 的两条（bind 状态、生成验证码）是
//! `{"success":true,"message":"","data":{...}}`——**message 恒为空串**；
//! `UnbindQQ` 与 `SyncQQPanel` 是手写 `common.H`，只有
//! `{"success":true,"message":"..."}`，**没有 data 字段**；失败一律
//! `{"success":false,"message":...}`（`common.CtxApiErrorMsg`），没有 data。
//!
//! ## 与 Go 的差异
//!
//! - 文案全部是 Go 硬编码的中文字面量（不走 i18n，前端逐字比较），这里逐字
//!   保留；只有数据库故障按仓库约定折叠为 `common.database_error`（i18n）。
//! - `UnbindQQ` 成功后的 `usage.RecordLog(userId, LogTypeSystem, "已解绑 QQ
//!   账号")` 写 P7/P8 才归属的 `logs` 表，与 `checkin` 切片同样的理由缺席，
//!   不改变响应。
//! - `SyncQQPanel` 的远端失败文案不回显（Go 会把 QQ 平台的响应体拼进
//!   `err.Error()`）；见 `crate::qqbot` 的模块注释。

use axum::{
    Json,
    extract::{Extension, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use newapi_billing::qq_bot::QQBotSettings;
use newapi_identity::qq_bind::{QQBindCodeError, QQBindingRepository, QQUnbindError};
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::AuthenticatedUser;
use crate::qqbot::{InjectedQQBotApi, QQBotApi, SyncPanelError, sync_command_panel};

/// Go `manage_qqbot.go:369` `common.CtxApiErrorMsg(c, "QQ 签到功能未启用")`。
const MSG_CHECKIN_DISABLED: &str = "QQ 签到功能未启用";
/// Go `identity/qq_binding.go:175`。
const MSG_ALREADY_BOUND: &str = "当前账号已绑定 QQ，请先解绑";
/// Go `identity/qq_binding.go:165` `fmt.Errorf` 的前缀/后缀；中间是剩余秒数。
const MSG_COOLDOWN_PREFIX: &str = "解绑后需等待冷却时间才能重新绑定，剩余 ";
const MSG_COOLDOWN_SUFFIX: &str = " 秒";
/// Go `identity/qq_binding.go:207`。
const MSG_GENERATE_FAILED: &str = "验证码生成失败，请稍后重试";
/// Go `manage_qqbot.go:395-397` 手写 `common.H` 的 message。
const MSG_UNBOUND: &str = "解绑成功";
/// Go `manage_qqbot.go:407-409` 手写 `common.H` 的 message。
const MSG_PANEL_SYNCED: &str = "指令面板已同步到 QQ 平台";
/// Go `identity/qq_binding.go:302`。
const MSG_EMPTY_USER_ID: &str = "id 为空！";
/// Go `qqbot_service.go:38` `getClient`。
const MSG_BOT_NOT_CONFIGURED: &str = "QQ 机器人未配置 AppID/AppSecret";
/// Go 的远端失败文案（含远端响应体）在本端口替换为固定分类文案。
const MSG_PANEL_SYNC_FAILED: &str = "QQ 指令面板同步失败，请稍后重试";
const MSG_DATABASE_ERROR: &str = "common.database_error";

/// `GET /api/user/qq/bind` → Go `billing.GetQQBindStatus`。
///
/// Go 顺序：读 `id` → `GetQQBotSetting()` → `GetQQBindingByUserId`。
/// 该接口在 Go 侧永不失败（绑定查询出错也按未绑定），唯一的失败分支是
/// 本端口的配置读取故障。
pub async fn bind_status(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let settings = match QQBotSettings::load(&db).await {
        Ok(settings) => settings,
        Err(error) => return database_error(&headers, &error),
    };
    let repository = QQBindingRepository::new(db);
    let binding = repository.bind_status(auth_user.0.user_id).await;
    // Go `common.CtxApiSuccess`：`message` 恒为空串；`qq_username` 与
    // `bound_at` 只在已绑定时出现（Go 手动往 `common.H` 里插键）。
    let mut data = serde_json::Map::new();
    data.insert(
        "qq_checkin_enabled".to_owned(),
        json!(settings.qq_checkin_enabled),
    );
    data.insert("bound".to_owned(), json!(binding.is_some()));
    data.insert(
        "rebind_cooldown_seconds".to_owned(),
        json!(settings.rebind_cooldown_seconds),
    );
    if let Some(binding) = &binding {
        data.insert("qq_username".to_owned(), json!(binding.username));
        data.insert("bound_at".to_owned(), json!(binding.bound_at));
    }
    Json(json!({
        "success": true,
        "message": "",
        "data": Value::Object(data),
    }))
    .into_response()
}

/// `POST /api/user/qq/bind/code` → Go `billing.GenerateQQBindCode`。
///
/// 顺序即契约：先查 `QQCheckinEnabled` 开关，再走 `CreateQQBindCode` 的
/// 「已绑定 → 冷却 → 作废旧码 → 生成」。
pub async fn generate_bind_code(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let settings = match QQBotSettings::load(&db).await {
        Ok(settings) => settings,
        Err(error) => return database_error(&headers, &error),
    };
    if !settings.qq_checkin_enabled {
        return rejected(MSG_CHECKIN_DISABLED);
    }
    let repository = QQBindingRepository::new(db);
    match repository
        .create_bind_code(auth_user.0.user_id, settings.rebind_cooldown_seconds)
        .await
    {
        Ok(code) => {
            // Go `int(time.Until(time.Unix(bindCode.ExpiredAt, 0)).Seconds())`：
            // 浮点秒截断；这里直接算整秒差，同一时刻下即剩余 TTL。
            Json(json!({
                "success": true,
                "message": "",
                "data": {
                    "code": code.code,
                    "expired_at": code.expired_at,
                    "expires_in": code.expired_at - crate::http::now_seconds(),
                },
            }))
            .into_response()
        }
        Err(error) => bind_code_error(&headers, &error),
    }
}

/// `DELETE /api/user/qq/bind` → Go `billing.UnbindQQ`。
///
/// Go 的成功体是手写 `common.H`：只有 `success` 与 `message`，**没有 data**。
pub async fn unbind(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let repository = QQBindingRepository::new(db);
    match repository.delete_binding(auth_user.0.user_id).await {
        // Go `usage.RecordLog(userId, LogTypeSystem, "已解绑 QQ 账号")` 不在
        // 本端口（logs 表归属 P7/P8），响应不变。
        Ok(()) => Json(json!({
            "success": true,
            "message": MSG_UNBOUND,
        }))
        .into_response(),
        Err(error) => {
            let message = match error {
                QQUnbindError::EmptyUserId => MSG_EMPTY_USER_ID.to_owned(),
                QQUnbindError::Database => translate(&headers, MSG_DATABASE_ERROR),
            };
            Json(json!({
                "success": false,
                "message": message,
            }))
            .into_response()
        }
    }
}

/// `POST /api/user/qq/panel/sync` → Go `billing.SyncQQPanel`。
///
/// 鉴权是 `security.AdminAuth()`（完整鉴权 + role >= 10），不是
/// `UserAuth` + 角色检查，因此路由层直接挂 `admin_auth`；handler 拿到的
/// 扩展在这里只是被 `SyncQQPanel` 忽略（Go 也不读用户身份）。
///
/// 传输走 [`crate::qqbot`] 的端口：测试用请求扩展注入假 API，缺省用真实
/// HTTP 实现（与 `turnstile` 的注入约定一致）。
pub async fn sync_panel(
    State(state): State<AppState>,
    Extension(_auth_user): Extension<AuthenticatedUser>,
    injected: Option<Extension<InjectedQQBotApi>>,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let settings = match QQBotSettings::load(&db).await {
        Ok(settings) => settings,
        Err(error) => return database_error(&headers, &error),
    };
    let default_api = crate::qqbot::HttpQQBotApi;
    // 与 `checkin_http` 的 `InjectedVerifier` 同一手法：借 *本地的* `injected`
    // 绑定（match arm 里的 newtype 是临时量，活不过 arm 的右括号，E0597），
    // 再经 `&*extension.0` 把 `Arc<dyn QQBotApi>` 解引用成 `&dyn QQBotApi`；
    // 缺省实现由 `unwrap_or` 的具体形参做一次 unsizing 强制转换。
    let api: &dyn QQBotApi = injected
        .as_ref()
        .map(|extension| &*extension.0)
        .unwrap_or(&default_api);
    match sync_command_panel(api, &settings.app_id, &settings.app_secret).await {
        Ok(()) => Json(json!({
            "success": true,
            "message": MSG_PANEL_SYNCED,
        }))
        .into_response(),
        Err(SyncPanelError::NotConfigured) => rejected(MSG_BOT_NOT_CONFIGURED),
        Err(SyncPanelError::ApiUnavailable) => rejected(MSG_PANEL_SYNC_FAILED),
    }
}

/// Go `CreateQQBindCode` 各失败分支的逐字文案；数据库故障折叠为 i18n 键。
fn bind_code_error(headers: &HeaderMap, error: &QQBindCodeError) -> Response {
    let message = match error {
        QQBindCodeError::AlreadyBound => MSG_ALREADY_BOUND.to_owned(),
        QQBindCodeError::Cooldown { remaining_seconds } => {
            format!("{MSG_COOLDOWN_PREFIX}{remaining_seconds}{MSG_COOLDOWN_SUFFIX}")
        }
        QQBindCodeError::GenerateFailed => MSG_GENERATE_FAILED.to_owned(),
        QQBindCodeError::Database => translate(headers, MSG_DATABASE_ERROR),
    };
    rejected(&message)
}

fn rejected(message: &str) -> Response {
    Json(json!({
        "success": false,
        "message": message,
    }))
    .into_response()
}

fn database_error(headers: &HeaderMap, error: &sqlx::Error) -> Response {
    tracing::warn!(
        event = "qq_bind_database_operation_failed",
        category = crate::database_error_class(error),
        "QQ bind database operation failed"
    );
    rejected(&translate(headers, MSG_DATABASE_ERROR))
}

fn translate(headers: &HeaderMap, key: &str) -> String {
    let accept_language = crate::request_lang::accept_language_header(headers);
    let language = crate::request_lang::request_language(accept_language.as_deref());
    newapi_i18n::translate(&language, key, std::iter::empty::<(&str, &str)>())
}
