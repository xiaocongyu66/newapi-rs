//! `/api/subscription/admin/*` 管理侧 HTTP 适配层 → Go `billing` 的 11 条
//! admin 路由（`register_api.go:272-287`，组内仅 `security.AdminAuth()`，
//! 无限流、无 DisableCache）。
//!
//! Go 参考：
//! - `apps/api/internal/billing/manage_subscription.go:125-141`
//!   （`AdminListSubscriptionPlans`）
//! - `:143-244`（`AdminCreateSubscriptionPlan`）
//! - `:246-330`（`AdminUpdateSubscriptionPlan`）
//! - `:332-352`（`AdminUpdateSubscriptionPlanStatus`，PATCH）
//! - `:354-381`（`AdminBindSubscription`）
//! - `:386-404`（`AdminListUserSubscriptions`）
//! - `:433-460`（`AdminCreateUserSubscription`）
//! - `:462-486`（`AdminResetUserSubscriptionsByPlan`）
//! - `:488-514`（`AdminResetPlanSubscriptions`）
//! - `:516-531`（`AdminInvalidateUserSubscription`）
//! - `:533-548`（`AdminDeleteUserSubscription`）
//!
//! ## 信封
//!
//! 与自助侧一致：成功 `{"success": true, "message": "", "data": ...}`；
//! 业务失败 HTTP 200 + `{"success": false, "message": ...}`。Go 的硬编码
//! 中文文案逐字透出（`参数错误`、`套餐标题不能为空` 等）；gorm
//! `record not found` 原样透出；数据库错误折叠为翻译后的
//! `common.database_error`。`CtxApiSuccess(c, nil)` → `data: null`。
//!
//! ## 合规门
//!
//! 创建/更新套餐、bind、用户订阅创建走 `RequirePaymentCompliance`
//! （`payment_compliance.go:20-27`）：未确认时回 i18n 键
//! `payment.compliance_required`（`CtxApiErrorI18n`）。列表、PATCH 状态、
//! 两条 reset、invalidate、delete 无此门（与 Go handler 逐条对照）。
//!
//! ## 副作用裁剪
//!
//! Go 的 `InvalidateSubscriptionPlanCache`（进程内 plan 缓存）、用户分组
//! 缓存刷新（`refreshSubscriptionUserGroupCache`）、`RecordManageAudit`
//! 审计与重置用户日志在无缓存/无审计域的端口上不可观察，均不移植；分组
//! 状态机本身（users."group" 写入）完整复刻。

use axum::{
    Json,
    body::to_bytes,
    extract::{Extension, Request, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use newapi_billing::subscription::{
    AdminError, MSG_RECORD_NOT_FOUND, PlanWrite, SubscriptionPlanRow, SubscriptionRepository,
    SubscriptionResetResult, UserSubscriptionRow, normalize_reset_period,
};
use newapi_billing::topup::TopUpSettings;
use newapi_identity::self_user::QuotaDisplaySettings;
use newapi_identity::tokens::quota_from_display;
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::AuthenticatedUser;

/// Go `manage_subscription.go` 的硬编码文案（`CtxApiErrorMsg` 逐字透出）。
const MSG_INVALID_PARAMS: &str = "参数错误";
const MSG_INVALID_ID: &str = "无效的ID";
const MSG_INVALID_USER_ID: &str = "无效的用户ID";
const MSG_INVALID_SUB_ID: &str = "无效的订阅ID";
const MSG_TITLE_REQUIRED: &str = "套餐标题不能为空";
const MSG_PRICE_NEGATIVE: &str = "价格不能为负数";
const MSG_PRICE_TOO_HIGH: &str = "价格不能超过9999";
const MSG_MAX_PURCHASE_NEGATIVE: &str = "购买上限不能为负数";
const MSG_TOTAL_DISPLAY_INVALID: &str = "无效的总额度数值";
const MSG_TOTAL_NEGATIVE: &str = "总额度不能为负数";
const MSG_UPGRADE_GROUP_MISSING: &str = "升级分组不存在";
const MSG_DOWNGRADE_GROUP_MISSING: &str = "降级分组不存在";
const MSG_RESET_CUSTOM_SECONDS: &str = "自定义重置周期需大于0秒";
const MSG_FREE_PLAN_LIMIT: &str = "免费赠送额度或升级权益的套餐必须设置每用户购买上限";
const MSG_DATABASE_ERROR: &str = "common.database_error";
const MSG_COMPLIANCE_REQUIRED: &str = "payment.compliance_required";

/// Go `strconv.Atoi(c.Param("id"))`：解析失败一律 0，再由 `<= 0` 校验拦截。
fn parse_path_id(raw: &str) -> i64 {
    raw.trim().parse::<i64>().unwrap_or(0)
}

/// Go `requirePaymentCompliance`：`None` = 放行，`Some` = 已写响应。
async fn require_payment_compliance(state: &AppState, headers: &HeaderMap) -> Option<Response> {
    let Some(db) = state.db() else {
        return Some(StatusCode::SERVICE_UNAVAILABLE.into_response());
    };
    let settings = match TopUpSettings::load(&db).await {
        Ok(settings) => settings,
        Err(error) => return Some(database_error(headers, &error)),
    };
    if settings.payment_compliance_confirmed() {
        return None;
    }
    Some(api_error(headers, MSG_COMPLIANCE_REQUIRED))
}

/// Go `AdminUpsertSubscriptionPlanRequest` 的 JSON 绑定：字段全部 `Option`
/// 以复刻 Go 对缺失/`null` 的零值容忍；类型不匹配仍走绑定错误 → `参数错误`。
#[derive(Default, serde::Deserialize)]
struct PlanInput {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    subtitle: Option<String>,
    #[serde(default)]
    price_amount: Option<f64>,
    #[serde(default)]
    currency: Option<String>,
    #[serde(default)]
    duration_unit: Option<String>,
    #[serde(default)]
    duration_value: Option<i64>,
    #[serde(default)]
    custom_seconds: Option<i64>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    sort_order: Option<i64>,
    #[serde(default)]
    allow_balance_pay: Option<bool>,
    #[serde(default)]
    allow_wallet_overflow: Option<bool>,
    #[serde(default)]
    stripe_price_id: Option<String>,
    #[serde(default)]
    creem_product_id: Option<String>,
    #[serde(default)]
    waffo_pancake_product_id: Option<String>,
    #[serde(default)]
    max_purchase_per_user: Option<i64>,
    #[serde(default)]
    upgrade_group: Option<String>,
    #[serde(default)]
    downgrade_group: Option<String>,
    #[serde(default)]
    total_amount: Option<i64>,
    #[serde(default)]
    total_amount_display: Option<f64>,
    #[serde(default)]
    quota_reset_period: Option<String>,
    #[serde(default)]
    quota_reset_custom_seconds: Option<i64>,
}

#[derive(Default, serde::Deserialize)]
struct PlanEnvelope {
    #[serde(default)]
    plan: Option<PlanInput>,
}

/// Go create/update 共用的字段级默认与校验。create（`manage_subscription.go
/// :150-228`）与 update（`:258-288`）的差异只有 create 先把 `*bool` 空值补
/// 默认 true、update 不补（nil 不动列）——这里由 `default_pointers` 区分。
/// 返回 `Err(文案)` 时逐字透出。
#[allow(clippy::too_many_arguments)]
fn validate_and_resolve(
    input: &PlanInput,
    display: &QuotaDisplaySettings,
    group_known: impl Fn(&str) -> bool,
    default_pointers: bool,
) -> Result<PlanWrite, &'static str> {
    let title = input.title.clone().unwrap_or_default();
    if title.trim().is_empty() {
        return Err(MSG_TITLE_REQUIRED);
    }
    let price_amount = input.price_amount.unwrap_or_default();
    if !(price_amount >= 0.0) {
        return Err(MSG_PRICE_NEGATIVE);
    }
    if price_amount > 9999.0 {
        return Err(MSG_PRICE_TOO_HIGH);
    }
    let max_purchase_per_user = input.max_purchase_per_user.unwrap_or_default();
    if max_purchase_per_user < 0 {
        return Err(MSG_MAX_PURCHASE_NEGATIVE);
    }
    // 非有限展示额度是 Go 的显式校验（NaN/Inf → 无效的总额度数值）；
    // `QuotaFromDisplayAmount` 自身对非有限输入回 0（此处不可达）。
    let mut total_amount = input.total_amount.unwrap_or_default();
    let total_display = input.total_amount_display.unwrap_or_default();
    if total_display != 0.0 {
        if !total_display.is_finite() {
            return Err(MSG_TOTAL_DISPLAY_INVALID);
        }
        total_amount = quota_from_display(total_display, display);
    }
    if total_amount < 0 {
        return Err(MSG_TOTAL_NEGATIVE);
    }
    let upgrade_group = input
        .upgrade_group
        .as_deref()
        .unwrap_or_default()
        .trim()
        .to_string();
    if !upgrade_group.is_empty() && !group_known(&upgrade_group) {
        return Err(MSG_UPGRADE_GROUP_MISSING);
    }
    let downgrade_group = input
        .downgrade_group
        .as_deref()
        .unwrap_or_default()
        .trim()
        .to_string();
    if !downgrade_group.is_empty() && !group_known(&downgrade_group) {
        return Err(MSG_DOWNGRADE_GROUP_MISSING);
    }
    let quota_reset_period =
        normalize_reset_period(input.quota_reset_period.as_deref().unwrap_or_default());
    if quota_reset_period == "custom" && input.quota_reset_custom_seconds.unwrap_or_default() <= 0 {
        return Err(MSG_RESET_CUSTOM_SECONDS);
    }
    // Go `validateFreePlanPurchaseLimit`（`store_subscription.go:213-231`）。
    let grants_valuable = total_amount > 0 || !upgrade_group.is_empty();
    let allow_balance_pay = input.allow_balance_pay;
    let self_serve_free = match allow_balance_pay {
        Some(false) => true,
        _ => price_amount <= 0.0,
    };
    if max_purchase_per_user <= 0 && grants_valuable && self_serve_free {
        return Err(MSG_FREE_PLAN_LIMIT);
    }
    Ok(PlanWrite {
        title,
        subtitle: input.subtitle.clone().unwrap_or_default(),
        price_amount,
        currency: match input.currency.as_deref() {
            Some(currency) if !currency.is_empty() => currency.to_string(),
            _ => "USD".to_string(),
        },
        duration_unit: match input.duration_unit.as_deref() {
            Some(unit) if !unit.is_empty() => unit.to_string(),
            _ => "month".to_string(),
        },
        duration_value: {
            let value = input.duration_value.unwrap_or_default();
            if value <= 0 && input.duration_unit.as_deref().unwrap_or_default() != "custom" {
                1
            } else {
                value
            }
        },
        custom_seconds: input.custom_seconds.unwrap_or_default(),
        enabled: input.enabled.unwrap_or_default(),
        sort_order: input.sort_order.unwrap_or_default(),
        allow_balance_pay: allow_balance_pay.or(if default_pointers { Some(true) } else { None }),
        allow_wallet_overflow: input.allow_wallet_overflow.or(if default_pointers {
            Some(true)
        } else {
            None
        }),
        stripe_price_id: input.stripe_price_id.clone().unwrap_or_default(),
        creem_product_id: input.creem_product_id.clone().unwrap_or_default(),
        waffo_pancake_product_id: input.waffo_pancake_product_id.clone().unwrap_or_default(),
        max_purchase_per_user,
        upgrade_group,
        downgrade_group,
        total_amount,
        quota_reset_period,
        quota_reset_custom_seconds: input.quota_reset_custom_seconds.unwrap_or_default(),
    })
}

/// 请求体绑定：Go `BindJSON` 失败 → `参数错误`；空体/未知 Content-Type 是
/// 零值（`body_bind` 的 Go 语义），由后续 title 等校验接管。
async fn bind_body_value<T: serde::de::DeserializeOwned + Default>(
    request: Request,
) -> Result<T, Response> {
    let (parts, body) = request.into_parts();
    let bytes = match to_bytes(body, crate::http::MAX_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => return Err(invalid_params()),
    };
    match crate::body_bind::bind_body::<T>(&parts.headers, &bytes) {
        Ok(value) => Ok(value),
        Err(_) => Err(invalid_params()),
    }
}

fn invalid_params() -> Response {
    Json(json!({"success": false, "message": MSG_INVALID_PARAMS})).into_response()
}

fn literal_error(message: &str) -> Response {
    Json(json!({"success": false, "message": message})).into_response()
}

fn success_json(data: Value) -> Response {
    Json(json!({"success": true, "message": "", "data": data})).into_response()
}

fn success_null() -> Response {
    Json(json!({"success": true, "message": "", "data": null})).into_response()
}

/// Go `CtxApiSuccess(c, H{"message": msg})`：message 包在 data 里。
fn success_message(message: Option<String>) -> Response {
    let data = match message {
        Some(message) => json!({"message": message}),
        None => Value::Null,
    };
    success_json(data)
}

fn api_error(headers: &HeaderMap, key: &str) -> Response {
    let accept_language = crate::request_lang::accept_language_header(headers);
    let language = crate::request_lang::request_language(accept_language.as_deref());
    Json(json!({
        "success": false,
        "message": newapi_i18n::translate(&language, key, std::iter::empty::<(&str, &str)>()),
    }))
    .into_response()
}

fn database_error(headers: &HeaderMap, error: &sqlx::Error) -> Response {
    tracing::warn!(
        event = "subscription_admin_database_operation_failed",
        category = crate::database_error_class(error),
        "subscription admin database operation failed"
    );
    api_error(headers, MSG_DATABASE_ERROR)
}

/// Go `CtxApiError`（`transport.go:53-58`）：库层错误原样透出文案；数据库
/// 故障折叠为 `common.database_error`。
fn admin_error(headers: &HeaderMap, error: AdminError) -> Response {
    match error {
        AdminError::NotFound => literal_error(MSG_RECORD_NOT_FOUND),
        AdminError::Business(message) => literal_error(&message),
        AdminError::Db(error) => database_error(headers, &error),
    }
}

/// Go `SubscriptionPlan.AfterFind` + `NormalizeDefaults` 的 JSON 形态
/// （字段与自助侧 `subscription_http::plan_json` 一致）。
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

/// Go `saturateQuota` 的纯算术（NaN 归零、int32 饱和、向零截断）。
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

/// Go `SubscriptionPlanDTO`：`{"plan": ...}` 包一层。
fn plan_dto_json(plan: &SubscriptionPlanRow, display: &QuotaDisplaySettings) -> Value {
    json!({ "plan": plan_json(plan, display) })
}

/// Go `UserSubscription.AfterFind` 的 JSON 形态（`amount_*_display` 走 int32
/// 饱和的 64 位渲染）。
fn subscription_json(sub: &UserSubscriptionRow, display: &QuotaDisplaySettings) -> Value {
    let total = sub.amount_total.clamp(i32::MIN as i64, i32::MAX as i64);
    let used = sub.amount_used.clamp(i32::MIN as i64, i32::MAX as i64);
    json!({
        "id": sub.id,
        "user_id": sub.user_id,
        "plan_id": sub.plan_id,
        "amount_total": sub.amount_total,
        "amount_used": sub.amount_used,
        "amount_total_display": display.to_display(total),
        "amount_used_display": display.to_display(used),
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

/// Go `SubscriptionSummary`：`{"subscription": ...}` 包一层。
fn summary_json(sub: &UserSubscriptionRow, display: &QuotaDisplaySettings) -> Value {
    json!({ "subscription": subscription_json(sub, display) })
}

/// Go `SubscriptionResetResult` 的 JSON 形态（`plan_title` 带 `json:"-"`）。
fn reset_result_json(result: &SubscriptionResetResult) -> Value {
    json!({
        "plan_id": result.plan_id,
        "matched_count": result.matched_count,
        "reset_count": result.reset_count,
        "user_count": result.user_count,
        "advance_reset_time": result.advance_reset_time,
    })
}

/// `POST /api/subscription/admin/plans` → Go `AdminCreateSubscriptionPlan`。
///
/// 响应 `data` 是回显的套餐（Go `CtxApiSuccess(c, req.Plan)`——Create 不触发
/// `AfterFind`，所以 `total_amount_display` / `balance_cost_display` 是零值
/// 而非换算结果，id / created_at / updated_at 为落库值）。
pub async fn admin_create_plan(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthenticatedUser>,
    headers: HeaderMap,
    mut request: Request,
) -> Response {
    if let Some(response) = require_payment_compliance(&state, &headers).await {
        return response;
    }
    let envelope: PlanEnvelope = match bind_body_value(request).await {
        Ok(envelope) => envelope,
        Err(response) => return response,
    };
    let input = envelope.plan.unwrap_or_default();
    let display = state.quota_display();
    let group_ratio = state.group_settings().group_ratio;
    let plan = match validate_and_resolve(
        &input,
        &display,
        |group| group_ratio.contains_key(group),
        true,
    ) {
        Ok(plan) => plan,
        Err(message) => return literal_error(message),
    };
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let repository = SubscriptionRepository::new(db);
    let now = now_seconds();
    let id = match repository.insert_plan(&plan, now).await {
        Ok(id) => id,
        Err(error) => return database_error(&headers, &error),
    };
    success_json(json!({
        "id": id,
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
        "total_amount_display": 0.0,
        "balance_cost_display": 0.0,
        "quota_reset_period": plan.quota_reset_period,
        "quota_reset_custom_seconds": plan.quota_reset_custom_seconds,
        "created_at": now,
        "updated_at": now,
    }))
}

/// `PUT /api/subscription/admin/plans/{id}` → Go `AdminUpdateSubscriptionPlan`。
/// 部分更新语义：`allow_balance_pay` / `allow_wallet_overflow` 缺省时不动列，
/// 其余列整体覆盖（Go update map）。
pub async fn admin_update_plan(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthenticatedUser>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    mut request: Request,
) -> Response {
    let id = parse_path_id(&id);
    if id <= 0 {
        return literal_error(MSG_INVALID_ID);
    }
    if let Some(response) = require_payment_compliance(&state, &headers).await {
        return response;
    }
    let envelope: PlanEnvelope = match bind_body_value(request).await {
        Ok(envelope) => envelope,
        Err(response) => return response,
    };
    let input = envelope.plan.unwrap_or_default();
    let display = state.quota_display();
    let group_ratio = state.group_settings().group_ratio;
    let plan = match validate_and_resolve(
        &input,
        &display,
        |group| group_ratio.contains_key(group),
        false,
    ) {
        Ok(plan) => plan,
        Err(message) => return literal_error(message),
    };
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let repository = SubscriptionRepository::new(db);
    if let Err(error) = repository.update_plan(id, &plan, now_seconds()).await {
        return database_error(&headers, &error);
    }
    success_null()
}

#[derive(Default, serde::Deserialize)]
struct StatusEnvelope {
    #[serde(default)]
    enabled: Option<bool>,
}

/// `PATCH /api/subscription/admin/plans/{id}` → Go
/// `AdminUpdateSubscriptionPlanStatus`。
pub async fn admin_update_plan_status(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthenticatedUser>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    mut request: Request,
) -> Response {
    let id = parse_path_id(&id);
    if id <= 0 {
        return literal_error(MSG_INVALID_ID);
    }
    if let Some(response) = require_payment_compliance(&state, &headers).await {
        return response;
    }
    let envelope: StatusEnvelope = match bind_body_value(request).await {
        Ok(envelope) => envelope,
        Err(response) => return response,
    };
    let Some(enabled) = envelope.enabled else {
        return literal_error(MSG_INVALID_PARAMS);
    };
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let repository = SubscriptionRepository::new(db);
    if let Err(error) = repository
        .update_plan_enabled(id, enabled, now_seconds())
        .await
    {
        return database_error(&headers, &error);
    }
    success_null()
}

#[derive(Default, serde::Deserialize)]
struct BindEnvelope {
    #[serde(default)]
    user_id: Option<i64>,
    #[serde(default)]
    plan_id: Option<i64>,
}

#[derive(Default, serde::Deserialize)]
struct UserSubscriptionEnvelope {
    #[serde(default)]
    plan_id: Option<i64>,
}

#[derive(Default, serde::Deserialize)]
struct ResetEnvelope {
    #[serde(default)]
    plan_id: Option<i64>,
    #[serde(default)]
    advance_reset_time: Option<bool>,
}

/// `POST /api/subscription/admin/bind` → Go `AdminBindSubscription`。
pub async fn admin_bind(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthenticatedUser>,
    headers: HeaderMap,
    mut request: Request,
) -> Response {
    if let Some(response) = require_payment_compliance(&state, &headers).await {
        return response;
    }
    let envelope: BindEnvelope = match bind_body_value(request).await {
        Ok(envelope) => envelope,
        Err(response) => return response,
    };
    let user_id = envelope.user_id.unwrap_or_default();
    let plan_id = envelope.plan_id.unwrap_or_default();
    if user_id <= 0 || plan_id <= 0 {
        return literal_error(MSG_INVALID_PARAMS);
    }
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let repository = SubscriptionRepository::new(db);
    match repository
        .admin_bind(user_id, plan_id, "admin", now_seconds())
        .await
    {
        Ok(message) => success_message(message),
        Err(error) => admin_error(&headers, error),
    }
}

/// `GET /api/subscription/admin/users/{id}/subscriptions` → Go
/// `AdminListUserSubscriptions`（含过期，`end_time desc, id desc`）。
pub async fn admin_list_user_subscriptions(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthenticatedUser>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    let user_id = parse_path_id(&id);
    if user_id <= 0 {
        return literal_error(MSG_INVALID_USER_ID);
    }
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let repository = SubscriptionRepository::new(db);
    let subs = match repository.all_user_subscriptions(user_id).await {
        Ok(subs) => subs,
        Err(error) => return database_error(&headers, &error),
    };
    let display = state.quota_display();
    let data: Vec<Value> = subs.iter().map(|sub| summary_json(sub, &display)).collect();
    success_json(json!(data))
}

/// `POST /api/subscription/admin/users/{id}/subscriptions` → Go
/// `AdminCreateUserSubscription`（无支付的 bind）。
pub async fn admin_create_user_subscription(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthenticatedUser>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    mut request: Request,
) -> Response {
    if let Some(response) = require_payment_compliance(&state, &headers).await {
        return response;
    }
    let user_id = parse_path_id(&id);
    if user_id <= 0 {
        return literal_error(MSG_INVALID_USER_ID);
    }
    let envelope: UserSubscriptionEnvelope = match bind_body_value(request).await {
        Ok(envelope) => envelope,
        Err(response) => return response,
    };
    let plan_id = envelope.plan_id.unwrap_or_default();
    if plan_id <= 0 {
        return literal_error(MSG_INVALID_PARAMS);
    }
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let repository = SubscriptionRepository::new(db);
    match repository
        .admin_bind(user_id, plan_id, "admin", now_seconds())
        .await
    {
        Ok(message) => success_message(message),
        Err(error) => admin_error(&headers, error),
    }
}

/// Go `resolveAdvanceResetTime`：缺省 true。
fn resolve_advance_reset_time(value: Option<bool>) -> bool {
    value.unwrap_or(true)
}

/// `POST /api/subscription/admin/users/{id}/subscriptions/reset` → Go
/// `AdminResetUserSubscriptionsByPlan`（无合规门）。
pub async fn admin_reset_user_subscriptions(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthenticatedUser>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    mut request: Request,
) -> Response {
    let user_id = parse_path_id(&id);
    if user_id <= 0 {
        return literal_error(MSG_INVALID_USER_ID);
    }
    let envelope: ResetEnvelope = match bind_body_value(request).await {
        Ok(envelope) => envelope,
        Err(response) => return response,
    };
    let plan_id = envelope.plan_id.unwrap_or_default();
    if plan_id <= 0 {
        return literal_error(MSG_INVALID_PARAMS);
    }
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let repository = SubscriptionRepository::new(db);
    let advance = resolve_advance_reset_time(envelope.advance_reset_time);
    match repository
        .admin_reset_user_plan(user_id, plan_id, advance, now_seconds())
        .await
    {
        Ok(result) => success_json(reset_result_json(&result)),
        Err(error) => admin_error(&headers, error),
    }
}

/// `POST /api/subscription/admin/plans/{id}/subscriptions/reset` → Go
/// `AdminResetPlanSubscriptions`（无合规门）。
pub async fn admin_reset_plan_subscriptions(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthenticatedUser>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    mut request: Request,
) -> Response {
    let plan_id = parse_path_id(&id);
    if plan_id <= 0 {
        return literal_error(MSG_INVALID_ID);
    }
    let envelope: ResetEnvelope = match bind_body_value(request).await {
        Ok(envelope) => envelope,
        Err(response) => return response,
    };
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let repository = SubscriptionRepository::new(db);
    let advance = resolve_advance_reset_time(envelope.advance_reset_time);
    match repository
        .admin_reset_plan(plan_id, advance, now_seconds())
        .await
    {
        Ok(result) => success_json(reset_result_json(&result)),
        Err(error) => admin_error(&headers, error),
    }
}

/// `POST /api/subscription/admin/user_subscriptions/{id}/invalidate` → Go
/// `AdminInvalidateUserSubscription`（无合规门）。
pub async fn admin_invalidate_subscription(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthenticatedUser>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    let subscription_id = parse_path_id(&id);
    if subscription_id <= 0 {
        return literal_error(MSG_INVALID_SUB_ID);
    }
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let repository = SubscriptionRepository::new(db);
    match repository
        .admin_invalidate(subscription_id, now_seconds())
        .await
    {
        Ok(message) => success_message(message),
        Err(error) => admin_error(&headers, error),
    }
}

/// `DELETE /api/subscription/admin/user_subscriptions/{id}` → Go
/// `AdminDeleteUserSubscription`（无合规门）。
pub async fn admin_delete_subscription(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthenticatedUser>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    let subscription_id = parse_path_id(&id);
    if subscription_id <= 0 {
        return literal_error(MSG_INVALID_SUB_ID);
    }
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let repository = SubscriptionRepository::new(db);
    match repository
        .admin_delete(subscription_id, now_seconds())
        .await
    {
        Ok(message) => success_message(message),
        Err(error) => admin_error(&headers, error),
    }
}

fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
