//! `GET /api/user/checkin` 只读适配层 → Go `billing.GetCheckinStatus`。
//!
//! Go 参考：
//! - `apps/api/internal/billing/do_checkin.go:15-45`
//! - `apps/api/internal/transport/compose/register_api.go:190`（`selfRoute`
//!   组内纯 `UserAuth`，无限流、无 DisableCache；POST 由后续切片实现）
//!
//! ## 信封
//!
//! Go 手写 `common.H`：成功是 `{"success": true, "data": {...}}`——**没有
//! message 字段**；未启用与统计失败走 `common.CtxApiErrorMsg` 的裸失败信封
//! `{"success": false, "message": ...}`——**没有 data 字段**。适配层逐字复刻。
//!
//! 未启用的文案是硬编码中文（不走 i18n，前端逐字比较）。数据库错误与其他
//! 只读端点一致地折叠为 `common.database_error`，SQL 文本不外泄。

use axum::{
    Json,
    extract::{Extension, State},
    http::{HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use newapi_billing::checkin::{
    CheckinRecord, CheckinRepository, CheckinSettings, CheckinStats, current_month,
};
use newapi_identity::self_user::QuotaDisplaySettings;
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::AuthenticatedUser;

/// Go `do_checkin.go:18` `common.CtxApiErrorMsg(c, "签到功能未启用")`。
const MSG_DISABLED: &str = "签到功能未启用";
const MSG_DATABASE_ERROR: &str = "common.database_error";

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
