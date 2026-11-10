//! `/api/subscription/*` 自助侧 HTTP 适配层 → Go `billing` 的三条用户路由。
//!
//! Go 参考：
//! - `apps/api/internal/billing/manage_subscription.go:35-54`
//!   （`GetSubscriptionPlans`）
//! - `apps/api/internal/billing/manage_subscription.go:56-78`
//!   （`GetSubscriptionSelf`）
//! - `apps/api/internal/billing/manage_subscription.go:80-101`
//!   （`UpdateSubscriptionPreference`）
//! - `apps/api/internal/transport/compose/register_api.go:257-263`：三者在
//!   `/api/subscription` 组内纯 `UserAuth`，无限流、无 Turnstile、无
//!   DisableCache。
//!
//! ## 信封
//!
//! 全部走 Go `CtxApiSuccess` / `CtxApiError*`：成功
//! `{"success": true, "message": "", "data": ...}`；业务失败 HTTP 200 +
//! `{"success": false, "message": ...}`。`UpdateSubscriptionPreference` 的
//! 绑定失败文案是 Go 硬编码中文 `"参数错误"`（不走 i18n）；软删除用户触发
//! gorm `record not found`，按 Go `CtxApiError` 原样透出该文案。数据库错误
//! 文本不外泄，折叠为翻译后的 `common.database_error`。
//!
//! ## 支付合规门（plans）
//!
//! Go `GetSubscriptionPlans` 顶部 `IsPaymentComplianceConfirmed()`（
//! `pay_subscription.go:53-55`）未确认时**直接返回空列表**（200 成功信封），
//! 不查库。`self` 与 `preference` 无此门。合规判定复用
//! `TopUpSettings::load` + `payment_compliance_confirmed()`（与 topup 切片
//! 同一实现，读 `payment_setting.compliance_confirmed` /
//! `payment_setting.compliance_terms_version`）。
//!
//! ## 偏好写路径
//!
//! Go：`GetUserById(userId, true)` → `user.GetSetting()`（解析 setting JSON，
//! 坏行部分采用）→ 覆写 `BillingPreference` → `json.Marshal` **整体回写**
//! （未知名段因此被丢弃——`UserSetting::from_json`/`to_json` 的往返语义已
//! 复刻该行为）→ `UpdateUserSetting`。

use axum::{
    Json,
    body::to_bytes,
    extract::{Extension, Request, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use newapi_billing::subscription::{
    SubscriptionPlanRow, SubscriptionRepository, UserSubscriptionRow, normalize_billing_preference,
};
use newapi_billing::topup::TopUpSettings;
use newapi_identity::self_user::QuotaDisplaySettings;
use newapi_identity::users::{UserProfileRepository, UserSetting};
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::AuthenticatedUser;

/// Go `manage_subscription.go:84` `CtxApiErrorMsg(c, "参数错误")`。
const MSG_INVALID_PARAMS: &str = "参数错误";
/// Go `identity.GetUserById` 的 gorm `ErrRecordNotFound` 文案，经
/// `CtxApiError` 原样透出。
const MSG_RECORD_NOT_FOUND: &str = "record not found";
const MSG_DATABASE_ERROR: &str = "common.database_error";

/// `GET /api/subscription/plans` → Go `billing.GetSubscriptionPlans`。
pub async fn plans(
    State(state): State<AppState>,
    Extension(_auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    // Go：合规未确认 → 直接空列表（`manage_subscription.go:36-39`）。
    let settings = match TopUpSettings::load(&db).await {
        Ok(settings) => settings,
        Err(error) => return database_error(&headers, &error),
    };
    if !settings.payment_compliance_confirmed() {
        return success(json!([]));
    }
    let repository = SubscriptionRepository::new(db);
    let plans = match repository.list_enabled_plans().await {
        Ok(plans) => plans,
        Err(error) => return database_error(&headers, &error),
    };
    let display = state.quota_display();
    let data: Vec<Value> = plans
        .iter()
        .map(|plan| plan_dto_json(plan, &display))
        .collect();
    success(json!(data))
}

/// `GET /api/subscription/self` → Go `billing.GetSubscriptionSelf`。
///
/// Go 对两条订阅查询的失败**不报错**：各自吞错回空数组
///（`manage_subscription.go:62-71`）；偏好读取同样吞错回零值。只有整体
/// 不可用（连接池关闭等）才走数据库错误分类。
pub async fn self_subscriptions(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let user_id = auth_user.0.user_id;
    let repository = SubscriptionRepository::new(db);
    // Go `identity.GetUserSetting(userId, false)`：setting 缺失/NULL/查询空
    // 都回零值，再经 NormalizeBillingPreference 归一化。
    let preference = match repository.user_setting(user_id).await {
        Ok(setting) => {
            normalize_billing_preference(&UserSetting::from_json(&setting).billing_preference)
        }
        Err(error) => return database_error(&headers, &error),
    };
    let now = now_seconds();
    // Go 吞错回空数组（`manage_subscription.go:62-71`）：查询失败不改变
    // HTTP 结果，只在有 `Vec` 类型标注时用 `unwrap_or_default` 落空列表。
    let active: Vec<_> = repository
        .active_user_subscriptions(user_id, now)
        .await
        .unwrap_or_default();
    let all: Vec<_> = repository
        .all_user_subscriptions(user_id)
        .await
        .unwrap_or_default();
    let display = state.quota_display();
    success(json!({
        "billing_preference": preference,
        "subscriptions": active.iter().map(|sub| summary_json(sub, &display)).collect::<Vec<Value>>(),
        "all_subscriptions": all.iter().map(|sub| summary_json(sub, &display)).collect::<Vec<Value>>(),
    }))
}

/// `PUT /api/subscription/self/preference` → Go
/// `billing.UpdateSubscriptionPreference`。
///
/// 请求体 `{"billing_preference": "..."}`；绑定失败（Go `BindJSON`）是
/// `"参数错误"`——但空体/未知 Content-Type 是零值不是错误
///（`body_bind` 的 Go 语义），缺字段/空串经归一化落 `subscription_first`。
pub async fn update_preference(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    request: Request,
) -> Response {
    let (parts, body) = request.into_parts();
    let headers = parts.headers;
    let bytes = match to_bytes(body, crate::http::MAX_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => return invalid_params(),
    };
    let Ok(parsed) = crate::body_bind::bind_body::<Value>(&headers, &bytes) else {
        return invalid_params();
    };
    let requested = parsed
        .get("billing_preference")
        .and_then(Value::as_str)
        .unwrap_or("");
    let preference = normalize_billing_preference(requested);
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let user_id = auth_user.0.user_id;
    let repository = UserProfileRepository::new(db);
    // Go `GetUserById(userId, true)`：软删除或不存在 → gorm record not found。
    let Some(profile) = (match repository.by_id(user_id).await {
        Ok(profile) => profile,
        Err(error) => return database_error(&headers, &error),
    }) else {
        return Json(json!({"success": false, "message": MSG_RECORD_NOT_FOUND})).into_response();
    };
    // Go `user.GetSetting()` + `UpdateUserSetting`：解析 → 覆写 → 整体回写。
    let mut setting = UserSetting::from_json(&profile.setting);
    setting.billing_preference = preference.clone();
    if let Err(error) = repository.update_setting(user_id, &setting.to_json()).await {
        return database_error(&headers, &error);
    }
    success(json!({"billing_preference": preference}))
}

/// Go `saturateQuota`（`common/quota_math.go:72-86`）去掉日志副作用后的纯算术：
/// NaN 归零、饱和到 int32 边界，否则向零截断。
fn quota_from_float(value: f64) -> i64 {
    if value.is_nan() {
        return 0;
    }
    if value >= i32::MAX as f64 {
        return i32::MAX as i64;
    }
    if value <= i32::MIN as f64 {
        return i32::MIN as i64;
    }
    value.trunc() as i64
}

/// Go `QuotaToDisplayAmount64`（`register_option_hooks.go:194-203`）：int64
/// 先饱和到 int32 再渲染，防止订阅额度溢出 32 位额度列的展示语义。
fn display_amount(quota: i64, display: &QuotaDisplaySettings) -> f64 {
    let clamped = quota.clamp(i32::MIN as i64, i32::MAX as i64);
    display.to_display(clamped)
}

/// Go `SubscriptionPlan.AfterFind` + `NormalizeDefaults` 的 JSON 形态：
/// 逐字段对照 `store_subscription.go:104-155` 的 json 标签；`gorm:"-"` 的
/// `total_amount_display` / `balance_cost_display` 由本函数填充。
///
/// - `total_amount_display = QuotaToDisplayAmount(TotalAmount)`（`AfterFind`
///   里是 int→int64 直转，**没有** int32 饱和，与订阅实例的 64 变体不同）。
/// - `balance_cost_display =
///   QuotaToDisplayAmount(QuotaFromFloat(PriceAmount * QuotaPerUnit))`。
/// - 两个 `*bool` 经 `NormalizeDefaults` 后必非 null（nil → true）。
fn plan_json(plan: &SubscriptionPlanRow, display: &QuotaDisplaySettings) -> Value {
    let total_amount_display = display.to_display(plan.total_amount);
    let balance_cost_display =
        display.to_display(quota_from_float(plan.price_amount * display.quota_per_unit));
    json!({
        "id": plan.id,
        "title": plan.title,
        "subtitle": plan.subtitle,
        "price_amount": plan.price_amount,
        "currency": plan.currency,
        "duration_unit": plan.duration_unit,
        "duration_value": plan.duration_value,
        "custom_seconds": plan.custom_seconds,
        "enabled": plan.enabled,
        "sort_order": plan.sort_order,
        "allow_balance_pay": plan.allow_balance_pay.unwrap_or(true),
        "allow_wallet_overflow": plan.allow_wallet_overflow.unwrap_or(true),
        "stripe_price_id": plan.stripe_price_id,
        "creem_product_id": plan.creem_product_id,
        "waffo_pancake_product_id": plan.waffo_pancake_product_id,
        "max_purchase_per_user": plan.max_purchase_per_user,
        "upgrade_group": plan.upgrade_group,
        "downgrade_group": plan.downgrade_group,
        "total_amount": plan.total_amount,
        "total_amount_display": total_amount_display,
        "balance_cost_display": balance_cost_display,
        "quota_reset_period": plan.quota_reset_period,
        "quota_reset_custom_seconds": plan.quota_reset_custom_seconds,
        "created_at": plan.created_at,
        "updated_at": plan.updated_at,
    })
}

/// Go `SubscriptionPlanDTO`：`{"plan": plan_json}` 包一层。
fn plan_dto_json(plan: &SubscriptionPlanRow, display: &QuotaDisplaySettings) -> Value {
    json!({ "plan": plan_json(plan, display) })
}

/// Go `UserSubscription.AfterFind` 的 JSON 形态：逐字段对照
/// `store_subscription.go:249-282` 的 json 标签。`amount_*_display` 走
/// `QuotaToDisplayAmount64`（int32 饱和），`allow_wallet_overflow` 为普通
/// bool（Go 零值 false）。
fn subscription_json(sub: &UserSubscriptionRow, display: &QuotaDisplaySettings) -> Value {
    json!({
        "id": sub.id,
        "user_id": sub.user_id,
        "plan_id": sub.plan_id,
        "amount_total": sub.amount_total,
        "amount_used": sub.amount_used,
        "amount_total_display": display_amount(sub.amount_total, display),
        "amount_used_display": display_amount(sub.amount_used, display),
        "start_time": sub.start_time,
        "end_time": sub.end_time,
        "status": sub.status,
        "source": sub.source,
        "last_reset_time": sub.last_reset_time,
        "next_reset_time": sub.next_reset_time,
        "upgrade_group": sub.upgrade_group,
        "prev_user_group": sub.prev_user_group,
        "downgrade_group": sub.downgrade_group,
        "allow_wallet_overflow": sub.allow_wallet_overflow,
        "created_at": sub.created_at,
        "updated_at": sub.updated_at,
    })
}

/// Go `SubscriptionSummary`：`{"subscription": {...}}` 包一层
///（`buildSubscriptionSummaries` 保证非空指针）。
fn summary_json(sub: &UserSubscriptionRow, display: &QuotaDisplaySettings) -> Value {
    json!({ "subscription": subscription_json(sub, display) })
}

fn invalid_params() -> Response {
    Json(json!({"success": false, "message": MSG_INVALID_PARAMS})).into_response()
}

fn success(data: Value) -> Response {
    Json(json!({
        "success": true,
        "message": "",
        "data": data,
    }))
    .into_response()
}

fn database_error(headers: &HeaderMap, error: &sqlx::Error) -> Response {
    tracing::warn!(
        event = "subscription_database_operation_failed",
        category = crate::database_error_class(error),
        "subscription database operation failed"
    );
    let accept_language = crate::request_lang::accept_language_header(headers);
    let language = crate::request_lang::request_language(accept_language.as_deref());
    Json(json!({
        "success": false,
        "message": newapi_i18n::translate(&language, MSG_DATABASE_ERROR, std::iter::empty::<(&str, &str)>()),
    }))
    .into_response()
}

fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
