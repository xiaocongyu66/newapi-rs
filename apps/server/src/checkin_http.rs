//! `/api/user/checkin` 适配层 → Go `billing.GetCheckinStatus` /
//! `billing.DoCheckin`。
//!
//! Go 参考：
//! - `apps/api/internal/billing/do_checkin.go:15-45`（`GetCheckinStatus`）
//! - `apps/api/internal/billing/do_checkin.go:48-87`（`DoCheckin`）
//! - `apps/api/internal/billing/store_checkin.go:97-130`
//!   （`evaluateDailyCheckin`）、`:135-247`（`UserCheckin`）
//! - `apps/api/internal/transport/compose/register_api.go:190-191`：GET 在
//!   `selfRoute` 组内纯 `UserAuth`；POST 同组但多挂
//!   `middleware.TurnstileCheck()`。两者都无限流、无 DisableCache。
//!
//! ## 信封
//!
//! Go 手写 `common.H`：GET 成功是 `{"success": true, "data": {...}}`——**没有
//! message 字段**；POST 成功是手写 `common.H`（`do_checkin.go:79-86`），与
//! `CtxApiSuccessI18n` 恰好同形，因此也是
//! `{"success": true, "message": "签到成功", "data": {...}}`——**有 message**。
//! 失败一律 `{"success": false, "message": ...}`，没有 data 字段。
//!
//! 未启用与 QQ 未绑定的文案是硬编码中文（不走 i18n，前端逐字比较）；POST 的
//! 未绑定拒绝体还额外带 `"code": "qq_not_bound"`。数据库错误与其他端点一致地
//! 折叠为 `common.database_error`，SQL 文本不外泄。
//!
//! ## Go 的两个副作用在本端口缺席（均已在 `crates/billing/src/checkin` 记录）
//!
//! - `quotacache.IncrUser`：本端口尚无额度缓存层（P6）。
//! - `usage.RecordLog`：写 P7/P8 才归属的 `logs` 表。两者都不改变响应，
//!   因此 HTTP 可观察行为一致。

use axum::{
    Json,
    extract::{Extension, State},
    http::{HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use newapi_billing::checkin::{
    CheckinError, CheckinRecord, CheckinRepository, CheckinSettings, CheckinStats, current_month,
    random_quota,
};
use newapi_identity::self_user::QuotaDisplaySettings;
use newapi_identity::users::UserProfileRepository;
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::AuthenticatedUser;

/// Go `do_checkin.go:18` `common.CtxApiErrorMsg(c, "签到功能未启用")`。
const MSG_DISABLED: &str = "签到功能未启用";
const MSG_DATABASE_ERROR: &str = "common.database_error";

/// Go `do_checkin.go:63-66`：QQ 未绑定的拒绝体，带 `code`。
const CODE_QQ_NOT_BOUND: &str = "qq_not_bound";
const MSG_QQ_NOT_BOUND: &str = "请先绑定 QQ 账号后再签到";
/// Go `do_checkin.go:79-86` 手写 `common.H`，与 `CtxApiSuccessI18n` 恰好同形
///（都带 message），但不是走翻译管线的那个 helper。
const MSG_CHECKED_IN: &str = "签到成功";
/// Go `store_checkin.go:108` / `:186` `errors.New` 的固定文案。
const MSG_ALREADY_CHECKED_TODAY: &str = "今日已签到";
/// Go `store_checkin.go:177` / `:182` / `:192`：锁行、重判、插入失败的统一文案。
const MSG_CHECKIN_RETRY_LATER: &str = "签到失败，请稍后重试";
/// Go `store_checkin.go:197`。
const MSG_QUOTA_UPDATE_FAILED: &str = "签到失败：更新额度出错";

/// `GET /api/user/checkin` → Go `billing.GetCheckinStatus`。
pub async fn checkin_status(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let settings = match CheckinSettings::load(&db).await {
        Ok(settings) => settings,
        Err(error) => return database_error(&headers, &error),
    };
    if !settings.enabled {
        return Json(json!({
            "success": false,
            "message": MSG_DISABLED,
        }))
        .into_response();
    }
    let month = month_query(&uri).unwrap_or_else(current_month);
    let repository = CheckinRepository::new(db);
    let stats = match repository
        .user_stats(auth_user.0.user_id, &month, settings.single_platform_only)
        .await
    {
        Ok(stats) => stats,
        Err(error) => return database_error(&headers, &error),
    };
    let display = state.quota_display();
    Json(json!({
        "success": true,
        "data": checkin_data(&settings, &stats, display),
    }))
    .into_response()
}

/// `POST /api/user/checkin` → Go `billing.DoCheckin`（`do_checkin.go:48-87`）。
///
/// 顺序即契约：Turnstile → 启用开关 → QQ 绑定门 → 预判与随机 → 事务内
/// 锁行+重判+写库。Go 的 Turnstile 是路由中间件（在 handler 之前），本端口
/// 内联到 handler 顶部，可观察结果等价：都是 200 + JSON 且不触达写路径。
pub async fn do_checkin(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    injected_verifier: Option<Extension<crate::turnstile::InjectedVerifier>>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if let Some(response) = turnstile_gate(
        &state,
        &uri,
        &headers,
        injected_verifier.as_ref().map(|extension| &extension.0),
    )
    .await
    {
        return response;
    }
    let settings = match CheckinSettings::load(&db).await {
        Ok(settings) => settings,
        Err(error) => return database_error(&headers, &error),
    };
    if !settings.enabled {
        return Json(json!({
            "success": false,
            "message": MSG_DISABLED,
        }))
        .into_response();
    }
    let user_id = auth_user.0.user_id;
    let repository = UserProfileRepository::new(db.clone());
    // Go `do_checkin.go:58-68`：开启后才要求 QQ 绑定；`IsQQBoundByUserId`
    // 对查询错误一律算未绑定。
    if settings.require_qq_bound && !repository.is_qq_bound(user_id).await {
        return Json(json!({
            "success": false,
            "code": CODE_QQ_NOT_BOUND,
            "message": MSG_QQ_NOT_BOUND,
        }))
        .into_response();
    }
    let checkins = CheckinRepository::new(db);
    // Go `evaluateDailyCheckin` 的事务前预判：单平台模式跨两表，否则只看
    // `checkins`。查询失败按仓库约定折叠，不外泄 SQL 文本。
    match checkins
        .already_checked_today(user_id, settings.single_platform_only)
        .await
    {
        Ok(true) => {
            return Json(json!({
                "success": false,
                "message": MSG_ALREADY_CHECKED_TODAY,
            }))
            .into_response();
        }
        Ok(false) => {}
        Err(error) => return database_error(&headers, &error),
    }
    let quota_awarded = random_quota(settings.min_quota, settings.max_quota);
    // Go `UserCheckin`：事务内锁用户行 → 重判 → 插签到 → 加额度。
    match checkins
        .checkin(user_id, quota_awarded, settings.single_platform_only)
        .await
    {
        Ok(()) => {}
        Err(CheckinError::AlreadyCheckedToday) => {
            return Json(json!({
                "success": false,
                "message": MSG_ALREADY_CHECKED_TODAY,
            }))
            .into_response();
        }
        Err(CheckinError::RetryLater) => {
            return Json(json!({
                "success": false,
                "message": MSG_CHECKIN_RETRY_LATER,
            }))
            .into_response();
        }
        Err(CheckinError::QuotaUpdateFailed) => {
            return Json(json!({
                "success": false,
                "message": MSG_QUOTA_UPDATE_FAILED,
            }))
            .into_response();
        }
    }
    let display = state.quota_display();
    // Go `usage.RecordLog(userId, LogTypeSystem, "用户签到，获得额度 %s")` 与
    // `quotacache.IncrUser` 都不改变响应；见模块注释。
    Json(json!({
        "success": true,
        "message": MSG_CHECKED_IN,
        "data": {
            "quota_awarded": quota_awarded,
            "quota_awarded_display": display.to_display(quota_awarded),
        },
    }))
    .into_response()
}

/// Go `middleware.TurnstileCheck()`（`check_turnstile.go:15-63`）。
///
/// 与 `login_http` / `register_http` 的中间件同一套构件：未启用、或 token 为空时
/// **不调用** siteverify（`turnstile::decide` 在读到 verifier 之前就短路）；
/// 开启且有 token 时用请求扩展里注入的替身，缺省用共享 HTTP 客户端。
///
/// `remote_ip` 传 `None`：Go 用 `c.ClientIP()`，而本端口的 `selfRoute` 组没有
/// ClientIp 中间件（login/register 那两条匿名路由才有）。这只影响 siteverify
/// 的可选 `remoteip` 参数，不改变启用与否的判定。
async fn turnstile_gate(
    state: &AppState,
    uri: &Uri,
    headers: &HeaderMap,
    injected: Option<&crate::turnstile::InjectedVerifier>,
) -> Option<Response> {
    let auth = state.auth_settings();
    if !auth.turnstile_check_enabled {
        return None;
    }
    let token = crate::turnstile::query_token(uri.query());
    let decision = if token.is_none() {
        // token 缺失时 `decide` 直接判 `token_empty`，secret 不会被读取。
        crate::turnstile::decide(
            true,
            token.as_deref(),
            &auth.turnstile_secret_key,
            None,
            None,
        )
        .await
    } else {
        let http = crate::turnstile::HttpVerifier;
        let verifier: &dyn crate::turnstile::Verifier = match injected {
            Some(injected) => injected.0.as_ref(),
            None => &http,
        };
        crate::turnstile::decide(
            true,
            token.as_deref(),
            &auth.turnstile_secret_key,
            None,
            Some(verifier),
        )
        .await
    };
    let key = decision.rejection_key()?;
    Some(
        Json(json!({
            "success": false,
            "message": translate(headers, key),
        }))
        .into_response(),
    )
}

/// Go `do_checkin.go:36-43` 的 `data` 对象，字段逐字一致。
fn checkin_data(
    settings: &CheckinSettings,
    stats: &CheckinStats,
    display: QuotaDisplaySettings,
) -> Value {
    json!({
        "enabled": settings.enabled,
        "min_quota": settings.min_quota,
        // Go `QuotaToDisplayAmount` 复用 identity 的同一条算术。
        "min_quota_display": display.to_display(settings.min_quota),
        "max_quota": settings.max_quota,
        "max_quota_display": display.to_display(settings.max_quota),
        "stats": stats_data(stats, display),
    })
}

/// Go `GetUserCheckinStats` 返回的 map：累计量先加总再换算展示值。
fn stats_data(stats: &CheckinStats, display: QuotaDisplaySettings) -> Value {
    let records: Vec<Value> = stats
        .records
        .iter()
        .map(|record| record_data(record, display))
        .collect();
    json!({
        "total_quota": stats.total_quota,
        "total_quota_display": display.to_display(stats.total_quota),
        "total_checkins": stats.total_checkins,
        "checkin_count": stats.checkin_count,
        "checked_in_today": stats.checked_in_today,
        "records": records,
    })
}

/// Go `CheckinRecord`：不含 `id` / `user_id`。
fn record_data(record: &CheckinRecord, display: QuotaDisplaySettings) -> Value {
    json!({
        "checkin_date": record.checkin_date,
        "quota_awarded": record.quota_awarded,
        "quota_awarded_display": display.to_display(record.quota_awarded),
    })
}

/// Go `c.DefaultQuery("month", ...)`：缺键或空值都回退当前月。其它查询键
/// 忽略，`month` 不做格式校验（Go 同样原样拼进字符串区间）。
fn month_query(uri: &Uri) -> Option<String> {
    let query = uri.query()?;
    let value = query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == "month")
        .map(|(_, value)| percent_decode(value))?;
    if value.is_empty() { None } else { Some(value) }
}

/// Go `url.ParseQuery` 的最小还原：`+` 是空格、`%XX` 解一个字节。
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

fn database_error(headers: &HeaderMap, error: &sqlx::Error) -> Response {
    tracing::warn!(
        event = "checkin_database_operation_failed",
        category = crate::database_error_class(error),
        "checkin database operation failed"
    );
    Json(json!({
        "success": false,
        "message": translate(headers, MSG_DATABASE_ERROR),
    }))
    .into_response()
}

fn translate(headers: &HeaderMap, key: &str) -> String {
    let accept_language = crate::request_lang::accept_language_header(headers);
    let language = crate::request_lang::request_language(accept_language.as_deref());
    newapi_i18n::translate(&language, key, std::iter::empty::<(&str, &str)>())
}
