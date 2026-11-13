//! 订阅支付（epay / vmq / codepay）HTTP 适配层：
//! `POST /api/subscription/{epay,vmq,codepay}/pay`、
//! `GET|POST /api/subscription/{epay,vmq}/notify`（codepay 同）、
//! `GET /api/subscription/epay/return`。
//!
//! Go references:
//! - `apps/api/internal/billing/pay_subscription.go`（`findPayMethod` /
//!   `payMethodGateway` / `GetCallbackAddress`）
//! - `apps/api/internal/billing/subscription_payment_epay.go`
//! - `apps/api/internal/billing/subscription_payment_vmq.go`
//! - `apps/api/internal/billing/subscription_payment_codepay.go`
//! - `apps/api/internal/transport/compose/register_api.go:258-270,291-296`
//!   （pay 在 subscriptionRoute（UserAuth + CriticalRateLimit）；notify/return
//!   匿名挂 apiRouter 直下）
//!
//! 回调端点恒 200，体为字面 `"success"` / `"fail"`（Go `c.String`）。
//! 订单状态机复用 `newapi_billing::subscription::orders` 的事务。

use std::collections::BTreeMap;

use axum::{
    Json,
    body::Bytes,
    extract::{Extension, State},
    http::{HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use newapi_billing::subscription::{
    complete_subscription_order, count_user_subscriptions_by_plan,
    get_subscription_order_by_trade_no, insert_subscription_order,
};
use newapi_billing::topup::{
    TopUpSettings, codepay_sign, constant_time_eq, epay_sign, gateway_pay_type_code, now_seconds,
    random_string, vmq_create_sign, vmq_notify_sign,
};
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::AuthenticatedUser;
use crate::gateway_http::{
    callback_addresses, notify_params, parses_as_json, payment_return_path, query_escape,
};

// ---- 错误文案（Go 硬编码中文，`CtxApiErrorMsg` 的 `{"success":false,...}`）--

const MSG_BAD_REQUEST: &str = "参数错误";
const MSG_PLAN_DISABLED: &str = "套餐未启用";
const MSG_PLAN_PRICE_TOO_LOW: &str = "套餐金额过低";
const MSG_PAY_METHOD_MISSING: &str = "支付方式不存在";
const MSG_PAY_METHOD_UNSUPPORTED: &str = "不支持的支付方式";
const MSG_PURCHASE_LIMIT: &str = "已达到该套餐购买上限";
const MSG_CALLBACK_CONFIG_ERROR: &str = "回调地址配置错误";
const MSG_PAY_CONFIG_MISSING: &str = "当前管理员未配置支付信息";
const MSG_ORDER_CREATE_FAILED: &str = "创建订单失败";
const MSG_PAY_START_FAILED: &str = "拉起支付失败";

fn api_error(message: &str) -> Response {
    Json(json!({"success": false, "message": message})).into_response()
}

fn api_error_owned(message: String) -> Response {
    api_error(&message)
}

/// Go `CtxApiError(c, err)`：错误原文透出（gorm 文案）。
fn api_error_from_db(error: &sqlx::Error) -> Response {
    api_error_owned(error.to_string())
}

fn text_body(body: &'static str) -> Response {
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        body,
    )
        .into_response()
}

/// Go `c.Redirect(http.StatusFound, url)`。
fn redirect_found(location: &str) -> Response {
    let mut response = StatusCode::FOUND.into_response();
    if let Ok(value) = axum::http::HeaderValue::from_str(location) {
        response
            .headers_mut()
            .insert(axum::http::header::LOCATION, value);
    }
    response
}

/// Go `RequirePaymentCompliance`：未确认 → `CtxApiErrorI18n` 的
/// `payment.compliance_required`。
fn compliance_gate(settings: &TopUpSettings, headers: &HeaderMap) -> Result<(), Response> {
    #![allow(clippy::result_large_err)]
    if settings.payment_compliance_confirmed() {
        return Ok(());
    }
    let accept_language = crate::request_lang::accept_language_header(headers);
    let language = crate::request_lang::request_language(accept_language.as_deref());
    Err(Json(json!({
        "success": false,
        "message": newapi_i18n::translate(&language, "payment.compliance_required", std::iter::empty::<(&str, &str)>()),
    }))
    .into_response())
}

/// Go `SubscriptionEpayPayRequest` 等三个绑定（非 JSON / 空体绑定零值）。
#[derive(Default)]
struct SubscriptionPayRequest {
    plan_id: i64,
    payment_method: String,
}

fn bind_subscription_pay(headers: &HeaderMap, body: &[u8]) -> Result<SubscriptionPayRequest, ()> {
    if !parses_as_json(headers) || body.is_empty() {
        return Ok(SubscriptionPayRequest::default());
    }
    let parsed: Value = serde_json::from_slice(body).map_err(|_| ())?;
    let Some(object) = parsed.as_object() else {
        return Ok(SubscriptionPayRequest::default());
    };
    let mut request = SubscriptionPayRequest::default();
    match object.get("plan_id") {
        None | Some(Value::Null) => {}
        Some(value) => request.plan_id = value.as_i64().ok_or(())?,
    }
    match object.get("payment_method") {
        None | Some(Value::Null) => {}
        Some(value) => request.payment_method = value.as_str().ok_or(())?.to_owned(),
    }
    Ok(request)
}

/// Go `payMethodGateway`：缺失/空网关按 Epay。
fn gateway_of(method: &Value) -> &'static str {
    match method.get("gateway").map(Value::as_str) {
        Some("vmq") => "vmq",
        Some("codepay") => "codepay",
        _ => "epay",
    }
}

/// Go `findPayMethod(methodType, gateway)`（原始 `PayMethods` 配置，不受
/// 合规门过滤——与 `gateway_http` 同一读取面）。
fn find_pay_method<'a>(
    settings: &'a TopUpSettings,
    method_type: &str,
    gateway: &str,
) -> Option<&'a Value> {
    settings.pay_methods.as_deref()?.iter().find(|method| {
        method.get("type").map(Value::as_str) == Some(method_type) && gateway_of(method) == gateway
    })
}

/// Go `GetSubscriptionPlanById` + 启用/最低价校验（三个入口同构前置）。
/// 成功返回套餐行；业务失败已写好错误响应。
struct PlanContext {
    plan: newapi_billing::subscription::SubscriptionPlanRow,
}

async fn subscription_plan_context(
    db: &newapi_storage::Database,
    request: &SubscriptionPayRequest,
) -> Result<PlanContext, Response> {
    #![allow(clippy::result_large_err)]
    if request.plan_id <= 0 {
        return Err(api_error(MSG_BAD_REQUEST));
    }
    let repository = newapi_billing::subscription::SubscriptionRepository::new(db.clone());
    let plan = match repository.get_plan(request.plan_id).await {
        Ok(Some(plan)) => plan,
        Ok(None) => return Err(api_error("record not found")),
        Err(error) => return Err(api_error_from_db(&error)),
    };
    if !plan.enabled {
        return Err(api_error(MSG_PLAN_DISABLED));
    }
    if plan.price_amount < 0.01 {
        return Err(api_error(MSG_PLAN_PRICE_TOO_LOW));
    }
    Ok(PlanContext { plan })
}

/// Go `MaxPurchasePerUser` 门槛（三个入口同构，失败文案硬编码）。
async fn purchase_limit_gate(
    db: &newapi_storage::Database,
    user_id: i64,
    plan: &newapi_billing::subscription::SubscriptionPlanRow,
) -> Result<(), Response> {
    #![allow(clippy::result_large_err)]
    if plan.max_purchase_per_user <= 0 {
        return Ok(());
    }
    let count = count_user_subscriptions_by_plan(db, user_id, plan.id)
        .await
        .map_err(|error| api_error_from_db(&error))?;
    if count >= i64::from(plan.max_purchase_per_user) {
        return Err(api_error(MSG_PURCHASE_LIMIT));
    }
    Ok(())
}

async fn insert_order_and_respond(
    db: &newapi_storage::Database,
    user_id: i64,
    plan: &newapi_billing::subscription::SubscriptionPlanRow,
    trade_no: &str,
    payment_method: &str,
    provider: &str,
    url: Value,
    event: &str,
) -> Response {
    let create_time = now_seconds();
    if let Err(error) = insert_subscription_order(
        db,
        user_id,
        plan.id,
        plan.price_amount,
        trade_no,
        payment_method,
        provider,
        create_time,
    )
    .await
    {
        tracing::warn!(
            event = "subscription_order_create_failed",
            category = crate::database_error_class(&error),
            trade_no = %trade_no,
            "subscription order create failed"
        );
        // VMQ/CodePay 走 CtxApiError（原文），Epay 走 CtxApiErrorMsg。
        return if provider == "epay" {
            api_error(MSG_ORDER_CREATE_FAILED)
        } else {
            api_error_from_db(&error)
        };
    }
    tracing::info!(event = %event, trade_no = %trade_no, "subscription order created");
    Json(json!({"message": "success", "data": {"trade_no": trade_no}, "url": url})).into_response()
}

/// Go `subscription_orders` 的 epay 回调核销共享段（notify 与 return 共用）。
async fn complete_epay_order(
    db: &newapi_storage::Database,
    params: &BTreeMap<String, String>,
) -> Result<(), ()> {
    let trade_no = params.get("out_trade_no").cloned().unwrap_or_default();
    if trade_no.is_empty() {
        return Err(());
    }
    // Go `common.GetJsonString(verifyInfo)`：verifyInfo 是参数映射 + 验签
    // 结果的 JSON；provider_payload 只落库不再读回，这里落参数映射本身。
    let payload = serde_json::to_string(params).unwrap_or_default();
    let actual_method = params.get("type").map(String::as_str).unwrap_or("");
    match complete_subscription_order(
        db,
        &trade_no,
        &payload,
        "epay",
        actual_method,
        now_seconds(),
    )
    .await
    {
        Ok(_) => Ok(()),
        Err(_) => Err(()),
    }
}

/// `POST /api/subscription/epay/pay` → Go `billing.SubscriptionRequestEpay`。
pub async fn subscription_request_epay(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let settings = match TopUpSettings::load(&db).await {
        Ok(settings) => settings,
        Err(_) => return api_error(MSG_BAD_REQUEST),
    };
    if let Err(response) = compliance_gate(&settings, &headers) {
        return response;
    }
    let request = match bind_subscription_pay(&headers, &body) {
        Ok(request) => request,
        Err(()) => return api_error(MSG_BAD_REQUEST),
    };
    if request.plan_id <= 0 {
        return api_error(MSG_BAD_REQUEST);
    }
    let plan = match subscription_plan_context(&db, &request).await {
        Ok(context) => context.plan,
        Err(response) => return response,
    };
    if find_pay_method(&settings, &request.payment_method, "epay").is_none() {
        return api_error(MSG_PAY_METHOD_MISSING);
    }
    if let Err(response) = purchase_limit_gate(&db, auth_user.0.user_id, &plan).await {
        return response;
    }

    let addresses = callback_addresses(&db).await;
    let notify_url = format!("{}/api/subscription/epay/notify", addresses.callback);
    let return_url = format!("{}/api/subscription/epay/return", addresses.callback);
    let trade_no = format!(
        "SUBUSR{}NO{}{}",
        auth_user.0.user_id,
        random_string(6),
        now_seconds()
    );

    if settings.pay_address.is_empty()
        || settings.epay_id.is_empty()
        || settings.epay_key.is_empty()
    {
        return api_error(MSG_PAY_CONFIG_MISSING);
    }
    let money_str = format!("{:.2}", plan.price_amount);
    let mut params: BTreeMap<String, String> = BTreeMap::new();
    params.insert("pid".to_owned(), settings.epay_id.clone());
    params.insert("type".to_owned(), request.payment_method.clone());
    params.insert("out_trade_no".to_owned(), trade_no.clone());
    params.insert("notify_url".to_owned(), notify_url);
    params.insert("name".to_owned(), format!("SUB:{}", plan.title));
    params.insert("money".to_owned(), money_str);
    params.insert("device".to_owned(), "pc".to_owned());
    params.insert("return_url".to_owned(), return_url);
    let sign = epay_sign(&params, &settings.epay_key);
    params.insert("sign".to_owned(), sign);
    params.insert("sign_type".to_owned(), "MD5".to_owned());
    let uri = format!("{}/submit.php", settings.pay_address.trim_end_matches('/'));

    insert_order_and_respond(
        &db,
        auth_user.0.user_id,
        &plan,
        &trade_no,
        &request.payment_method,
        "epay",
        Value::String(uri),
        "subscription_epay_order_created",
    )
    .await
}

/// `GET|POST /api/subscription/epay/notify` → Go `billing.SubscriptionEpayNotify`。
pub async fn subscription_epay_notify(
    State(state): State<AppState>,
    method: axum::http::Method,
    uri: Uri,
    _headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(db) = state.db() else {
        return text_body("fail");
    };
    let settings = match TopUpSettings::load(&db).await {
        Ok(settings) => settings,
        Err(_) => return text_body("fail"),
    };
    // Go：只查 `GetEpayClient() == nil`（凭证门）。
    if settings.pay_address.is_empty()
        || settings.epay_id.is_empty()
        || settings.epay_key.is_empty()
    {
        return text_body("fail");
    }
    let params = match notify_params(method == axum::http::Method::POST, &uri, &body) {
        Ok(params) => params,
        Err(()) => return text_body("fail"),
    };
    if params.is_empty() {
        return text_body("fail");
    }
    let sign = params.get("sign").cloned().unwrap_or_default();
    // go-epay `Verify`：普通相等（与 Go 逐字一致，非定时安全）。
    if sign != epay_sign(&params, &settings.epay_key) {
        return text_body("fail");
    }
    if params.get("trade_status").map(String::as_str) != Some("TRADE_SUCCESS") {
        return text_body("fail");
    }
    if complete_epay_order(&db, &params).await.is_err() {
        return text_body("fail");
    }
    text_body("success")
}

/// `GET /api/subscription/epay/return` → Go `billing.SubscriptionEpayReturn`。
pub async fn subscription_epay_return(
    State(state): State<AppState>,
    method: axum::http::Method,
    uri: Uri,
    _headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(db) = state.db() else {
        return redirect_found("/wallet?pay=fail");
    };
    let settings = match TopUpSettings::load(&db).await {
        Ok(settings) => settings,
        Err(_) => return redirect_found("/wallet?pay=fail"),
    };
    let fail = || redirect_found("/wallet?pay=fail");
    if settings.pay_address.is_empty()
        || settings.epay_id.is_empty()
        || settings.epay_key.is_empty()
    {
        return fail();
    }
    let params = match notify_params(method == axum::http::Method::POST, &uri, &body) {
        Ok(params) => params,
        Err(()) => return fail(),
    };
    if params.is_empty() {
        return fail();
    }
    let sign = params.get("sign").cloned().unwrap_or_default();
    if sign != epay_sign(&params, &settings.epay_key) {
        return fail();
    }
    let addresses = callback_addresses(&db).await;
    if params.get("trade_status").map(String::as_str) == Some("TRADE_SUCCESS") {
        if complete_epay_order(&db, &params).await.is_err() {
            return fail();
        }
        return redirect_found(&payment_return_path(
            &addresses.server,
            "/wallet?pay=success",
        ));
    }
    redirect_found(&payment_return_path(
        &addresses.server,
        "/wallet?pay=pending",
    ))
}

/// `POST /api/subscription/vmq/pay` → Go `billing.SubscriptionRequestVmqPay`。
pub async fn subscription_request_vmq_pay(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let settings = match TopUpSettings::load(&db).await {
        Ok(settings) => settings,
        Err(_) => return api_error(MSG_BAD_REQUEST),
    };
    if let Err(response) = compliance_gate(&settings, &headers) {
        return response;
    }
    if settings.vmq_address.trim().is_empty() || settings.vmq_key.trim().is_empty() {
        return api_error(MSG_PAY_CONFIG_MISSING);
    }
    let request = match bind_subscription_pay(&headers, &body) {
        Ok(request) => request,
        Err(()) => return api_error(MSG_BAD_REQUEST),
    };
    if request.plan_id <= 0 {
        return api_error(MSG_BAD_REQUEST);
    }
    let plan = match subscription_plan_context(&db, &request).await {
        Ok(context) => context.plan,
        Err(response) => return response,
    };
    let Some(method) = find_pay_method(&settings, &request.payment_method, "vmq") else {
        return api_error(MSG_PAY_METHOD_MISSING);
    };
    let Some(type_code) =
        gateway_pay_type_code("vmq", method.get("type").map(Value::as_str).unwrap_or(""))
    else {
        return api_error(MSG_PAY_METHOD_UNSUPPORTED);
    };
    if let Err(response) = purchase_limit_gate(&db, auth_user.0.user_id, &plan).await {
        return response;
    }

    let addresses = callback_addresses(&db).await;
    let return_url = payment_return_path(&addresses.server, "/wallet?pay=pending");
    let notify_url = format!("{}/api/subscription/vmq/notify", addresses.callback);
    let trade_no = format!(
        "SUBVMQUSR{}NO{}{}",
        auth_user.0.user_id,
        random_string(6),
        now_seconds()
    );
    let price_str = format!("{:.2}", plan.price_amount);
    let sign = vmq_create_sign(&trade_no, "sub", type_code, &price_str, &settings.vmq_key);
    let vmq_url = format!(
        "{}/createOrder?payId={}&param={}&type={}&price={}&notifyUrl={}&returnUrl={}&sign={}&isHtml=1",
        settings.vmq_address.trim_end_matches('/'),
        query_escape(&trade_no),
        query_escape("sub"),
        query_escape(type_code),
        query_escape(&price_str),
        query_escape(&notify_url),
        query_escape(&return_url),
        query_escape(&sign),
    );

    insert_order_and_respond(
        &db,
        auth_user.0.user_id,
        &plan,
        &trade_no,
        &request.payment_method,
        "vmq",
        Value::String(vmq_url),
        "subscription_vmq_order_created",
    )
    .await
}

/// `GET|POST /api/subscription/vmq/notify` → Go `billing.SubscriptionVmqNotify`。
pub async fn subscription_vmq_notify(
    State(state): State<AppState>,
    method: axum::http::Method,
    uri: Uri,
    _headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(db) = state.db() else {
        return text_body("fail");
    };
    let settings = match TopUpSettings::load(&db).await {
        Ok(settings) => settings,
        Err(_) => return text_body("fail"),
    };
    // Go `isVmqWebhookEnabled`：仅凭证门。
    if settings.vmq_address.trim().is_empty() || settings.vmq_key.trim().is_empty() {
        return text_body("fail");
    }
    let params = match notify_params(method == axum::http::Method::POST, &uri, &body) {
        Ok(params) => params,
        Err(()) => return text_body("fail"),
    };
    if params.is_empty() {
        return text_body("fail");
    }
    let sign = params.get("sign").cloned().unwrap_or_default();
    let expected = vmq_notify_sign(
        params.get("payId").map(String::as_str).unwrap_or_default(),
        params.get("param").map(String::as_str).unwrap_or_default(),
        params.get("type").map(String::as_str).unwrap_or_default(),
        params.get("price").map(String::as_str).unwrap_or_default(),
        params
            .get("reallyPrice")
            .map(String::as_str)
            .unwrap_or_default(),
        &settings.vmq_key,
    );
    if !constant_time_eq(&sign, &expected) {
        return text_body("fail");
    }
    let trade_no = params.get("payId").cloned().unwrap_or_default();
    if trade_no.is_empty() {
        return text_body("fail");
    }
    // Go `GetSubscriptionOrderByTradeNo`：缺失/网关不符都 fail。
    let Some(order) = get_subscription_order_by_trade_no(&db, &trade_no).await else {
        return text_body("fail");
    };
    if order.payment_provider != "vmq" {
        return text_body("fail");
    }
    // 金额比对（Go `:169-186`）：票价 2 位小数精确相等；实付差 ≤ 0.10 元。
    let order_cents = (order.money * 100.0).round() as i128;
    let Some(notify_cents) =
        newapi_billing::topup::round2_cents(params.get("price").map(String::as_str).unwrap_or(""))
    else {
        return text_body("fail");
    };
    if notify_cents != order_cents {
        return text_body("fail");
    }
    let really = params.get("reallyPrice").map(String::as_str).unwrap_or("");
    if !really.is_empty() {
        let Some(paid_cents) = newapi_billing::topup::round2_cents(really) else {
            return text_body("fail");
        };
        if (paid_cents - order_cents).abs() > 10 {
            return text_body("fail");
        }
    }
    let payload = serde_json::to_string(&params).unwrap_or_default();
    match complete_subscription_order(&db, &trade_no, &payload, "vmq", "", now_seconds()).await {
        Ok(_) => text_body("success"),
        Err(_) => text_body("fail"),
    }
}

/// `POST /api/subscription/codepay/pay` → Go `billing.SubscriptionRequestCodePayPay`。
pub async fn subscription_request_codepay_pay(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let settings = match TopUpSettings::load(&db).await {
        Ok(settings) => settings,
        Err(_) => return api_error(MSG_BAD_REQUEST),
    };
    if let Err(response) = compliance_gate(&settings, &headers) {
        return response;
    }
    if settings.codepay_address.trim().is_empty()
        || settings.codepay_id.trim().is_empty()
        || settings.codepay_key.trim().is_empty()
    {
        return api_error(MSG_PAY_CONFIG_MISSING);
    }
    let request = match bind_subscription_pay(&headers, &body) {
        Ok(request) => request,
        Err(()) => return api_error(MSG_BAD_REQUEST),
    };
    if request.plan_id <= 0 {
        return api_error(MSG_BAD_REQUEST);
    }
    let plan = match subscription_plan_context(&db, &request).await {
        Ok(context) => context.plan,
        Err(response) => return response,
    };
    let Some(method) = find_pay_method(&settings, &request.payment_method, "codepay") else {
        return api_error(MSG_PAY_METHOD_MISSING);
    };
    let Some(type_code) = gateway_pay_type_code(
        "codepay",
        method.get("type").map(Value::as_str).unwrap_or(""),
    ) else {
        return api_error(MSG_PAY_METHOD_UNSUPPORTED);
    };
    if let Err(response) = purchase_limit_gate(&db, auth_user.0.user_id, &plan).await {
        return response;
    }

    let addresses = callback_addresses(&db).await;
    let return_url = payment_return_path(&addresses.server, "/wallet?pay=pending");
    let notify_url = format!("{}/api/subscription/codepay/notify", addresses.callback);
    let trade_no = format!(
        "SUBCPUSR{}NO{}{}",
        auth_user.0.user_id,
        random_string(6),
        now_seconds()
    );
    let price_str = format!("{:.2}", plan.price_amount);

    let mut cp_params: BTreeMap<String, String> = BTreeMap::new();
    cp_params.insert("id".to_owned(), settings.codepay_id.clone());
    cp_params.insert("type".to_owned(), type_code.to_owned());
    cp_params.insert("price".to_owned(), price_str);
    cp_params.insert("pay_id".to_owned(), trade_no.clone());
    cp_params.insert("param".to_owned(), "sub".to_owned());
    cp_params.insert("notify_url".to_owned(), notify_url);
    cp_params.insert("return_url".to_owned(), return_url);
    let sign = codepay_sign(&cp_params, &settings.codepay_key);
    // Go：key 升序拼 query（不含 sign），sign 恒最后。
    let mut query: Vec<String> = cp_params
        .iter()
        .map(|(key, value)| format!("{key}={}", query_escape(value)))
        .collect();
    query.sort();
    query.push(format!("sign={}", query_escape(&sign)));
    let codepay_url = format!(
        "{}/creat_order/?{}",
        settings.codepay_address.trim_end_matches('/'),
        query.join("&")
    );

    insert_order_and_respond(
        &db,
        auth_user.0.user_id,
        &plan,
        &trade_no,
        &request.payment_method,
        "codepay",
        Value::String(codepay_url),
        "subscription_codepay_order_created",
    )
    .await
}

/// `GET|POST /api/subscription/codepay/notify` → Go `billing.SubscriptionCodePayNotify`。
pub async fn subscription_codepay_notify(
    State(state): State<AppState>,
    method: axum::http::Method,
    uri: Uri,
    _headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(db) = state.db() else {
        return text_body("fail");
    };
    let settings = match TopUpSettings::load(&db).await {
        Ok(settings) => settings,
        Err(_) => return text_body("fail"),
    };
    if settings.codepay_address.trim().is_empty()
        || settings.codepay_id.trim().is_empty()
        || settings.codepay_key.trim().is_empty()
    {
        return text_body("fail");
    }
    let params = match notify_params(method == axum::http::Method::POST, &uri, &body) {
        Ok(params) => params,
        Err(()) => return text_body("fail"),
    };
    if params.is_empty() {
        return text_body("fail");
    }
    if params
        .get("pay_no")
        .map(|value| value.trim().is_empty())
        .unwrap_or(true)
    {
        return text_body("fail");
    }
    let sign = params.get("sign").cloned().unwrap_or_default();
    if !constant_time_eq(&sign, &codepay_sign(&params, &settings.codepay_key)) {
        return text_body("fail");
    }
    let trade_no = params.get("pay_id").cloned().unwrap_or_default();
    if trade_no.is_empty() {
        return text_body("fail");
    }
    let Some(order) = get_subscription_order_by_trade_no(&db, &trade_no).await else {
        return text_body("fail");
    };
    if order.payment_provider != "codepay" {
        return text_body("fail");
    }
    let order_cents = (order.money * 100.0).round() as i128;
    let Some(notify_cents) =
        newapi_billing::topup::round2_cents(params.get("price").map(String::as_str).unwrap_or(""))
    else {
        return text_body("fail");
    };
    if notify_cents != order_cents {
        return text_body("fail");
    }
    let payload = serde_json::to_string(&params).unwrap_or_default();
    match complete_subscription_order(&db, &trade_no, &payload, "codepay", "", now_seconds()).await
    {
        Ok(_) => text_body("success"),
        Err(_) => text_body("fail"),
    }
}

// 引用说明：金额换算不涉及订阅域，未复用 waffo 切片的 QuotaPerUnit 常量。
