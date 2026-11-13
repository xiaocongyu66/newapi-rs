//! 外呼支付网关（Stripe / Creem / Waffo / Waffo Pancake）的支付发起与
//! webhook 回调 HTTP 适配器。
//!
//! Go references:
//! - `apps/api/internal/billing/topup_stripe.go`（`RequestStripePay`、
//!   `StripeWebhook`、`fulfillOrder`、`genStripeLink`、`GetChargedAmount`）
//! - `apps/api/internal/billing/topup_creem.go`（`RequestCreemPay`、
//!   `CreemWebhook`、`genCreemLink`、`verifyCreemSignature`）
//! - `apps/api/internal/billing/topup_waffo.go`（`RequestWaffoPay`、
//!   `WaffoWebhook`、`sendWaffoWebhookResponse`）
//! - `apps/api/internal/billing/topup_waffo_pancake.go`（
//!   `RequestWaffoPancakePay`、`WaffoPancakeWebhook`）
//! - `apps/api/internal/billing/call_waffo_pancake.go`（
//!   `CreateWaffoPancakeCheckoutSession`、`ResolveWaffoPancakeTradeNo`、
//!   `verifyWaffoPancakeEventStore/Money`）
//! - SDK：`stripe-go/v81 webhook.ConstructEventWithOptions`（`t=,v1=` HMAC、
//!   300 秒容差、timing-safe）、`waffo-go`（RSA PKCS#1v15 SHA-256 请求签名
//!   与响应验签、`/order/create`、webhook 回信）、`waffo-pancake-sdk-go`
//!   （`X-Waffo-Signature` 的 `t=,v1=`、内置 test/prod 公钥、5 分钟容差）
//! - 路由：`register_api.go:115-120`（webhook 匿名 + 体上限）、
//!   `:170-176`（selfRoute：UserAuth + CriticalRateLimit）
//!
//! 外呼全部经 trait 端口注入（[`StripeTransport`] / [`CreemTransport`] /
//! [`WaffoTransport`] / [`PancakeCheckoutTransport`]），测试注入替身，生产
//! 走 reqwest 实现。订单状态机复用 `newapi_billing::topup` 的 CAS 事务。
//!
//! 已知偏差：无。订阅订单状态机已移植（`newapi_billing::subscription::orders`），
//! webhook 在 Go 中的「先试订阅订单」分支按 Go 语义补全——Stripe / Creem 先
//! `complete_subscription_order`（`ErrSubscriptionOrderNotFound` 等价于订单
//! 不存在才落回充值核销），Pancake 的 `WAFFO_PANCAKE_SUB-` 前缀走订阅订单
//! 解析 + 核销。

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::{
    Json,
    body::Bytes,
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use base64::Engine;
use newapi_billing::subscription::{
    SubscriptionCompleteOutcome, SubscriptionOrderError, complete_subscription_order,
    expire_subscription_order, get_subscription_order_by_trade_no,
};
use newapi_billing::topup::{
    ExternalQuotaSource, ExternalRechargeParams, ExternalUserUpdate, PROVIDER_CREEM,
    PROVIDER_STRIPE, PROVIDER_WAFFO, PROVIDER_WAFFO_PANCAKE, STATUS_EXPIRED, STATUS_FAILED,
    STATUS_PENDING, TopUpQuotaRejection, TopUpSettings, base62_string, check_capacity,
    insert_topup, recharge_external_top_up, set_topup_status, sha1_hex, stripe_pay_units,
    update_pending_top_up_status, validate_credited_quota, validate_top_up_quota,
    waffo_pancake_pay_money, waffo_pay_money,
};
use newapi_identity::self_user::QuotaDisplayKind;
use newapi_identity::users::UserProfileRepository;
use rsa::pkcs8::DecodePublicKey;
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::AuthenticatedUser;
use crate::gateway_http::{callback_addresses, parses_as_json, payment_return_path, query_escape};

type PancakePayFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, crate::pancake::PancakeError>> + Send + 'a>>;

type CreemFuture<'a> = Pin<Box<dyn Future<Output = Result<(String, String), String>> + Send + 'a>>;

type WaffoFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(String, String, Value), String>> + Send + 'a>>;

// ---- 错误文案（Go 硬编码中文/英文字面量） --------------------------------

const MSG_BAD_REQUEST: &str = "参数错误";
const MSG_UNSUPPORTED_METHOD: &str = "不支持的支付渠道";
const MSG_USER_MISSING: &str = "用户不存在";
const MSG_ORDER_CREATE_FAILED: &str = "创建订单失败";
const MSG_PAY_START_FAILED: &str = "拉起支付失败";
const MSG_PAY_CONFIG_ERROR: &str = "支付配置错误";
const MSG_AMOUNT_TOO_SMALL: &str = "充值金额过低";
const MSG_PLEASE_SELECT_PRODUCT: &str = "请选择产品";
const MSG_PRODUCT_CONFIG_ERROR: &str = "产品配置错误";
const MSG_PRODUCT_NOT_FOUND: &str = "产品不存在";
const MSG_PAY_METHOD_UNSUPPORTED: &str = "不支持的支付方式";
const MSG_WAFFO_NOT_ENABLED: &str = "Waffo 支付未启用";
const MSG_PANCAKE_CONFIG_INCOMPLETE: &str = "Waffo Pancake 配置不完整";

fn msg_below_minimum(minimum: i64) -> String {
    format!("充值数量不能小于 {minimum}")
}

/// Go `common.H{"message": "error", "data": ...}`（HTTP 200）。
fn pay_error(message: impl Into<Value>) -> Response {
    Json(json!({"message": "error", "data": message.into()})).into_response()
}

fn pay_error_str(message: &str) -> Response {
    pay_error(message.to_owned())
}

/// Go `common.H{"message": <text>, "data": 10}`（Stripe 最小/最大值分支）。
fn pay_error_message_field(message: String) -> Response {
    Json(json!({"message": message, "data": 10})).into_response()
}

fn text_response(status: StatusCode, body: &'static str) -> Response {
    (
        status,
        [(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        body,
    )
        .into_response()
}

/// Go `randstr.String` 的 `time.Now().UnixMilli()`。
fn now_millis() -> i128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i128
}

/// Waffo SDK `utils.GetCurrentTimestamp`：UTC `2006-01-02T15:04:05.000Z`。
fn waffo_timestamp() -> String {
    let millis = now_millis();
    let secs = (millis / 1000) as i64;
    let millis_part = (millis % 1000) as i64;
    let (year, month, day, hour, minute, second) = utc_parts(secs);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis_part:03}Z")
}

/// UTC 六元组（纯算术，供毫秒精度时间戳使用）。
fn utc_parts(secs: i64) -> (i64, i64, i64, i64, i64, i64) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (hour, minute, second) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // civil_from_days（Howard Hinnant 算法）。
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d, hour, minute, second)
}

// ---------------------------------------------------------------------------
// 绑定辅助（Go c.BindJSON 的零值回退语义）
// ---------------------------------------------------------------------------

#[derive(Default)]
struct StripePayRequest {
    amount: i64,
    payment_method: String,
    success_url: String,
    cancel_url: String,
}

fn bind_stripe_request(headers: &HeaderMap, body: &[u8]) -> Result<StripePayRequest, ()> {
    if !parses_as_json(headers) || body.is_empty() {
        return Ok(StripePayRequest::default());
    }
    let parsed: Value = serde_json::from_slice(body).map_err(|_| ())?;
    let Some(object) = parsed.as_object() else {
        return Ok(StripePayRequest::default());
    };
    let mut request = StripePayRequest::default();
    match object.get("amount") {
        None | Some(Value::Null) => {}
        Some(value) => request.amount = value.as_i64().ok_or(())?,
    }
    for (field, target) in [
        ("payment_method", &mut request.payment_method),
        ("success_url", &mut request.success_url),
        ("cancel_url", &mut request.cancel_url),
    ] {
        match object.get(field) {
            None | Some(Value::Null) => {}
            Some(value) => *target = value.as_str().ok_or(())?.to_owned(),
        }
    }
    Ok(request)
}

/// Go `WaffoPayRequest`。
#[derive(Default)]
struct WaffoPayRequest {
    amount: i64,
    pay_method_index: Option<i64>,
    pay_method_type: String,
    pay_method_name: String,
}

fn bind_waffo_request(headers: &HeaderMap, body: &[u8]) -> Result<WaffoPayRequest, ()> {
    if !parses_as_json(headers) || body.is_empty() {
        return Ok(WaffoPayRequest::default());
    }
    let parsed: Value = serde_json::from_slice(body).map_err(|_| ())?;
    let Some(object) = parsed.as_object() else {
        return Ok(WaffoPayRequest::default());
    };
    let mut request = WaffoPayRequest::default();
    match object.get("amount") {
        None | Some(Value::Null) => {}
        Some(value) => request.amount = value.as_i64().ok_or(())?,
    }
    // Go `*int`：JSON null 保持 nil，非整数（含字符串）绑定失败。
    match object.get("pay_method_index") {
        None | Some(Value::Null) => {}
        Some(value) => request.pay_method_index = Some(value.as_i64().ok_or(())?),
    }
    for (field, target) in [
        ("pay_method_type", &mut request.pay_method_type),
        ("pay_method_name", &mut request.pay_method_name),
    ] {
        match object.get(field) {
            None | Some(Value::Null) => {}
            Some(value) => *target = value.as_str().ok_or(())?.to_owned(),
        }
    }
    Ok(request)
}

/// Go `CreemPayRequest`。
#[derive(Default)]
struct CreemPayRequest {
    product_id: String,
    payment_method: String,
}

fn bind_creem_request(headers: &HeaderMap, body: &[u8]) -> Result<CreemPayRequest, ()> {
    if !parses_as_json(headers) || body.is_empty() {
        return Ok(CreemPayRequest::default());
    }
    let parsed: Value = serde_json::from_slice(body).map_err(|_| ())?;
    let Some(object) = parsed.as_object() else {
        return Ok(CreemPayRequest::default());
    };
    let mut request = CreemPayRequest::default();
    for (field, target) in [
        ("product_id", &mut request.product_id),
        ("payment_method", &mut request.payment_method),
    ] {
        match object.get(field) {
            None | Some(Value::Null) => {}
            Some(value) => *target = value.as_str().ok_or(())?.to_owned(),
        }
    }
    Ok(request)
}

// ---------------------------------------------------------------------------
// 注入式外呼端口
// ---------------------------------------------------------------------------

/// Stripe Checkout Session 外呼能力；生产实现走
/// `https://api.stripe.com/v1/checkout/sessions`（Bearer 鉴权、表单编码）。
pub trait StripeTransport: Send + Sync {
    fn create_checkout_session<'a>(
        &'a self,
        api_secret: &'a str,
        params: &'a StripeCheckoutParams,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>>;
}

/// Go `genStripeLink` 的 `stripe.CheckoutSessionParams` 形状（仅实际使用的
/// 字段）。
pub struct StripeCheckoutParams {
    pub client_reference_id: String,
    pub success_url: String,
    pub cancel_url: String,
    pub price_id: String,
    pub quantity: i64,
    pub promotion_codes_enabled: bool,
    pub customer_id: String,
    pub customer_email: String,
}

#[derive(Clone)]
pub struct InjectedStripeTransport(pub Arc<dyn StripeTransport>);

/// Creem checkout 外呼能力；返回 `(checkout_url, id)`。
pub trait CreemTransport: Send + Sync {
    fn create_checkout<'a>(
        &'a self,
        api_key: &'a str,
        test_mode: bool,
        request: &'a CreemCheckoutRequest,
    ) -> CreemFuture<'a>;
}

/// Go `CreemCheckoutRequest`。
pub struct CreemCheckoutRequest {
    pub product_id: String,
    pub request_id: String,
    pub email: String,
    pub metadata_username: String,
    pub metadata_reference_id: String,
    pub metadata_product_name: String,
    pub metadata_quota: String,
}

#[derive(Clone)]
pub struct InjectedCreemTransport(pub Arc<dyn CreemTransport>);

/// Waffo SDK 凭证快照（环境相关的四元组 + 商户号）。
#[derive(Clone, Debug, Default)]
pub struct WaffoCreds {
    pub api_key: String,
    pub private_key: String,
    pub public_cert: String,
    pub merchant_id: String,
    pub sandbox: bool,
}

/// Waffo 订单创建外呼能力；实现内完成 RSA 请求签名、响应验签与信封解析，
/// 返回 `(code, msg, data)` 原始三元组（`code == "0"` 即业务成功）。
pub trait WaffoTransport: Send + Sync {
    fn create_order<'a>(&'a self, creds: &'a WaffoCreds, body: &'a Value) -> WaffoFuture<'a>;
}

#[derive(Clone)]
pub struct InjectedWaffoTransport(pub Arc<dyn WaffoTransport>);

/// Waffo Pancake 结账会话外呼能力（认证模式：先发 buyer session token，
/// 再建结账会话，URL 拼 `#token=` 片段）。
pub trait PancakeCheckoutTransport: Send + Sync {
    fn create_authenticated_checkout<'a>(
        &'a self,
        merchant_id: &'a str,
        private_key: &'a str,
        params: &'a PancakeCheckoutParams,
    ) -> PancakePayFuture<'a, PancakeCheckoutSession>;
}

pub struct PancakeCheckoutParams {
    pub product_id: String,
    pub buyer_identity: String,
    pub buyer_email: String,
    pub price_amount: String,
    pub expires_in_seconds: i64,
    pub order_merchant_external_id: String,
}

#[derive(Clone)]
pub struct PancakeCheckoutSession {
    pub session_id: String,
    pub checkout_url: String,
    pub expires_at: String,
    pub token: String,
    pub token_expires_at: String,
}

#[derive(Clone)]
pub struct InjectedPancakeCheckoutTransport(pub Arc<dyn PancakeCheckoutTransport>);

// ---------------------------------------------------------------------------
// 生产传输实现
// ---------------------------------------------------------------------------

/// Stripe 生产传输：`POST /v1/checkout/sessions`，表单编码 + Bearer。
#[derive(Clone, Copy, Debug, Default)]
pub struct HttpStripeTransport;

impl StripeTransport for HttpStripeTransport {
    fn create_checkout_session<'a>(
        &'a self,
        api_secret: &'a str,
        params: &'a StripeCheckoutParams,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
        Box::pin(async move {
            let client = external_client().ok_or_else(|| "transport unavailable".to_owned())?;
            // stripe-go 的 `url.Values.Encode`：与 `query_escape` 同为 `+` 空格。
            let mut form: Vec<(String, String)> = vec![
                (
                    "client_reference_id".to_owned(),
                    params.client_reference_id.clone(),
                ),
                ("success_url".to_owned(), params.success_url.clone()),
                ("cancel_url".to_owned(), params.cancel_url.clone()),
                ("line_items[0][price]".to_owned(), params.price_id.clone()),
                (
                    "line_items[0][quantity]".to_owned(),
                    params.quantity.to_string(),
                ),
                ("mode".to_owned(), "payment".to_owned()),
                (
                    "allow_promotion_codes".to_owned(),
                    params.promotion_codes_enabled.to_string(),
                ),
            ];
            if params.customer_id.is_empty() {
                if !params.customer_email.is_empty() {
                    form.push(("customer_email".to_owned(), params.customer_email.clone()));
                }
                form.push(("customer_creation".to_owned(), "always".to_owned()));
            } else {
                form.push(("customer".to_owned(), params.customer_id.clone()));
            }
            let body = form
                .iter()
                .map(|(key, value)| format!("{key}={}", query_escape(value)))
                .collect::<Vec<_>>()
                .join("&");
            let response = client
                .post("https://api.stripe.com/v1/checkout/sessions")
                .header(
                    reqwest::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .header(
                    reqwest::header::AUTHORIZATION,
                    format!("Bearer {api_secret}"),
                )
                .body(body)
                .send()
                .await
                .map_err(|error| error.to_string())?;
            let status = response.status();
            let raw = response.bytes().await.map_err(|error| error.to_string())?;
            let parsed: Value = serde_json::from_slice(&raw).map_err(|error| error.to_string())?;
            if !status.is_success() {
                // stripe-go `stripe.Error`：优先取 `error.message`。
                let message = parsed
                    .get("error")
                    .and_then(|error| error.get("message"))
                    .and_then(Value::as_str)
                    .unwrap_or("stripe request failed");
                return Err(message.to_owned());
            }
            let url = parsed
                .get("url")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            if url.is_empty() {
                return Err("stripe response has no url".to_owned());
            }
            Ok(url)
        })
    }
}

/// Creem 生产传输：`https://api.creem.io/v1/checkouts`（测试模式
/// `test-api.creem.io`），`x-api-key` 头。
#[derive(Clone, Copy, Debug, Default)]
pub struct HttpCreemTransport;

impl CreemTransport for HttpCreemTransport {
    fn create_checkout<'a>(
        &'a self,
        api_key: &'a str,
        test_mode: bool,
        request: &'a CreemCheckoutRequest,
    ) -> CreemFuture<'a> {
        Box::pin(async move {
            let client = external_client().ok_or_else(|| "transport unavailable".to_owned())?;
            let api_url = if test_mode {
                "https://test-api.creem.io/v1/checkouts"
            } else {
                "https://api.creem.io/v1/checkouts"
            };
            let body = json!({
                "product_id": request.product_id,
                "request_id": request.request_id,
                "customer": {"email": request.email},
                "metadata": {
                    "username": request.metadata_username,
                    "reference_id": request.metadata_reference_id,
                    "product_name": request.metadata_product_name,
                    "quota": request.metadata_quota,
                },
            });
            let response = client
                .post(api_url)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .header("x-api-key", api_key)
                .json(&body)
                .send()
                .await
                .map_err(|error| error.to_string())?;
            let status = response.status().as_u16();
            let raw = response.bytes().await.map_err(|error| error.to_string())?;
            if status / 100 != 2 {
                return Err(format!("Creem API http status {status} "));
            }
            let parsed: Value = serde_json::from_slice(&raw).map_err(|error| error.to_string())?;
            let checkout_url = parsed
                .get("checkout_url")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            if checkout_url.is_empty() {
                return Err("Creem API resp no checkout url ".to_owned());
            }
            let id = parsed
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            Ok((checkout_url, id))
        })
    }
}

/// Waffo 生产传输：`/order/create`（Sandbox / Production 基址随凭证切换），
/// RSA 请求签名 + 可选响应验签。
#[derive(Clone, Copy, Debug, Default)]
pub struct HttpWaffoTransport;

const WAFFO_API_VERSION: &str = "1.0.0";
const WAFFO_SDK_VERSION: &str = "waffo-go/1.3.2";
const WAFFO_SANDBOX_BASE_URL: &str = "https://api-sandbox.waffo.com/api/v1";
const WAFFO_PRODUCTION_BASE_URL: &str = "https://api.waffo.com/api/v1";

impl WaffoTransport for HttpWaffoTransport {
    fn create_order<'a>(&'a self, creds: &'a WaffoCreds, body: &'a Value) -> WaffoFuture<'a> {
        Box::pin(async move {
            let client = external_client().ok_or_else(|| "transport unavailable".to_owned())?;
            let body_text = body.to_string();
            let key = crate::pancake::parse_private_key(&creds.private_key)
                .map_err(|_| "invalid private key".to_owned())?;
            let signature = crate::pancake::sign_pkcs1_sha256(&key, body_text.as_bytes())
                .map_err(|_| "sign request".to_owned())?;
            let base_url = if creds.sandbox {
                WAFFO_SANDBOX_BASE_URL
            } else {
                WAFFO_PRODUCTION_BASE_URL
            };
            let response = client
                .post(format!("{base_url}/order/create"))
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .header("X-API-KEY", &creds.api_key)
                .header("X-SIGNATURE", signature)
                .header("X-API-VERSION", WAFFO_API_VERSION)
                .header("X-SDK-VERSION", WAFFO_SDK_VERSION)
                .body(body_text)
                .send()
                .await
                .map_err(|error| error.to_string())?;
            let response_signature = response
                .headers()
                .get("X-SIGNATURE")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let raw = response.bytes().await.map_err(|error| error.to_string())?;
            // Go SDK：响应携带签名头时先验签再解析。
            if let Some(signature) = response_signature
                && !waffo_verify(&raw, &signature, &creds.public_cert)
            {
                return Err("response signature verification failed".to_owned());
            }
            let parsed: Value = serde_json::from_slice(&raw).map_err(|error| error.to_string())?;
            let code = parsed
                .get("code")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let message = parsed
                .get("msg")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let data = parsed.get("data").cloned().unwrap_or(Value::Null);
            Ok((code, message, data))
        })
    }
}

/// Waffo Pancake 生产传输（复用 `pancake.rs` 的 RSA 签名与信封解析）。
#[derive(Clone, Copy, Debug, Default)]
pub struct HttpPancakeCheckoutTransport;

impl PancakeCheckoutTransport for HttpPancakeCheckoutTransport {
    fn create_authenticated_checkout<'a>(
        &'a self,
        merchant_id: &'a str,
        private_key: &'a str,
        params: &'a PancakeCheckoutParams,
    ) -> PancakePayFuture<'a, PancakeCheckoutSession> {
        Box::pin(async move {
            // 两个调用相互独立（Go 并发执行）；任一失败即整体失败。
            let token_body = json!({
                "productId": params.product_id,
                "buyerIdentity": params.buyer_identity,
            })
            .to_string();
            let token_data = crate::pancake::signed_post_data(
                merchant_id,
                private_key,
                "/v1/actions/auth/issue-session-token",
                &token_body,
            )
            .await?;
            let token = token_data
                .as_ref()
                .and_then(|data| data.get("token"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let token_expires_at = token_data
                .as_ref()
                .and_then(|data| data.get("expiresAt"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            if token.is_empty() {
                return Err(crate::pancake::PancakeError(
                    "issue session token: empty token".to_owned(),
                ));
            }

            let mut session_body = json!({
                "productId": params.product_id,
                "currency": "USD",
                "priceSnapshot": {
                    "amount": params.price_amount,
                    "taxCategory": "saas",
                },
                "expiresInSeconds": params.expires_in_seconds,
                "orderMerchantExternalId": params.order_merchant_external_id,
            });
            if !params.buyer_email.is_empty() {
                session_body["buyerEmail"] = Value::String(params.buyer_email.clone());
            }
            let session_data = crate::pancake::signed_post_data(
                merchant_id,
                private_key,
                "/v1/actions/checkout/create-session",
                &session_body.to_string(),
            )
            .await?;
            let session_id = session_data
                .as_ref()
                .and_then(|data| data.get("sessionId"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let checkout_url = session_data
                .as_ref()
                .and_then(|data| data.get("checkoutUrl"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let expires_at = session_data
                .as_ref()
                .and_then(|data| data.get("expiresAt"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            if session_id.is_empty() || checkout_url.is_empty() {
                return Err(crate::pancake::PancakeError(
                    "Waffo Pancake returned empty checkout session".to_owned(),
                ));
            }
            Ok(PancakeCheckoutSession {
                checkout_url: format!("{checkout_url}#token={token}"),
                session_id,
                expires_at,
                token,
                token_expires_at,
            })
        })
    }
}

/// 共享外呼 reqwest 客户端（30 秒超时，对齐 Go 的 `http.Client{Timeout: 30s}`）。
fn external_client() -> Option<&'static reqwest::Client> {
    static CLIENT: std::sync::OnceLock<Option<reqwest::Client>> = std::sync::OnceLock::new();
    CLIENT
        .get_or_init(|| {
            crate::turnstile::install_crypto_provider();
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .ok()
        })
        .as_ref()
}

// ---------------------------------------------------------------------------
// RSA 验签（Waffo 与 Waffo Pancake webhook 共用）
// ---------------------------------------------------------------------------

/// Waffo SDK `utils.Verify`：base64 SPKI 公钥 + base64 PKCS#1v15 签名。
fn waffo_verify(data: &[u8], signature: &str, base64_public_key: &str) -> bool {
    let Ok(der) = base64::engine::general_purpose::STANDARD.decode(base64_public_key.trim()) else {
        return false;
    };
    let Ok(key) = rsa::RsaPublicKey::from_public_key_der(&der) else {
        return false;
    };
    rsa_pkcs1_verify(&key, data, signature)
}

/// Pancake SDK `signing.VerifySignature`：`t.payload` + base64 签名。
fn pancake_verify(signature_input: &str, signature: &str, key: &rsa::RsaPublicKey) -> bool {
    rsa_pkcs1_verify(key, signature_input.as_bytes(), signature)
}

fn rsa_pkcs1_verify(key: &rsa::RsaPublicKey, data: &[u8], signature: &str) -> bool {
    use rsa::pkcs1v15::VerifyingKey;
    use rsa::signature::Verifier;
    let Ok(signature) = base64::engine::general_purpose::STANDARD.decode(signature.trim()) else {
        return false;
    };
    let Ok(signature) = rsa::pkcs1v15::Signature::try_from(signature.as_slice()) else {
        return false;
    };
    VerifyingKey::<rsa::sha2::Sha256>::new(key.clone())
        .verify(data, &signature)
        .is_ok()
}

/// Pancake SDK `signing.NormalizePublicKey` + `ParsePublicKey`：PEM /
/// 字面 `\n` / 裸 base64（按 SPKI 处理）。
fn parse_pancake_public_key(raw: &str) -> Result<rsa::RsaPublicKey, ()> {
    let normalized = raw.replace("\\n", "\n").replace("\r\n", "\n");
    let normalized = normalized.trim();
    const HEADER: &str = "-----BEGIN PUBLIC KEY-----";
    const FOOTER: &str = "-----END PUBLIC KEY-----";
    let body: String = normalized
        .replace(HEADER, "")
        .replace(FOOTER, "")
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    if body.is_empty() {
        return Err(());
    }
    let der = base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .map_err(|_| ())?;
    rsa::RsaPublicKey::from_public_key_der(&der).map_err(|_| ())
}

/// Pancake SDK 内置公钥（`webhooks.go` 逐字节镜像）。
const PANCAKE_BUILTIN_TEST_PUBLIC_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxnmRY6yMMA3lVqmAU6ZG
b1sjL/+r/z6E+ZjkXaDAKiqOhk9rpazni0bNsGXwmftTPk9jy2wn+j6JHODD/WH/
SCnSfvKkLIjy4Hk7BuCgB174C0ydan7J+KgXLkOwgCAxxB68t2tezldwo74ZpXgn
F49opzMvQ9prEwIAWOE+kV9iK6gx/AckSMtHIHpUesoPDkldpmFHlB2qpf1vsFTZ
5kD6DmGl+2GIVK01aChy2lk8pLv0yUMu18v44sLkO5M44TkGPJD9qG09wrvVG2wp
OTVCn1n5pP8P+HRLcgzbUB3OlZVfdFurn6EZwtyL4ZD9kdkQ4EZE/9inKcp3c1h4
xwIDAQAB
-----END PUBLIC KEY-----"#;

const PANCAKE_BUILTIN_PROD_PUBLIC_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz+xApdTIb4ua+DgZKQ54
iBsD82ybyhGCLRETONW4Jgbb3A8DUM1LqBk6r/CmTOCHqLalTQHNigvP3R5zkDNX
iRJz6gA4MJ/+8K0+mnEE2RISQzN+Qu65TNd6svb+INm/kMaftY4uIXr6y6kchtTJ
dwnQhcKdAL2v7h7IFnkVelQsKxDdb2PqX8xX/qwd01iXvMcpCCaXovUwZsxH2QN5
ZKBTseJivbhUeyJCco4fdUyxOMHe2ybCVhyvim2uxAl1nkvL5L8RCWMCAV55LLo0
9OhmLahz/DYNu13YLVP6dvIT09ZFBYU6Owj1NxdinTynlJCFS9VYwBgmftosSE1U
dwIDAQAB
-----END PUBLIC KEY-----"#;

/// Pancake `DefaultWebhookToleranceMS`：5 分钟。
const PANCAKE_WEBHOOK_TOLERANCE_MS: i64 = 5 * 60 * 1000;

/// Go `resolveKeyForEnv`（config keys 恒为空 → 环境变量 → 内置键）。
fn pancake_webhook_key(env: &str) -> Result<rsa::RsaPublicKey, ()> {
    let per_env = match env {
        "test" => std::env::var("WAFFO_WEBHOOK_TEST_PUBLIC_KEY"),
        _ => std::env::var("WAFFO_WEBHOOK_PROD_PUBLIC_KEY"),
    };
    let raw = match per_env {
        Ok(value) if !value.is_empty() => value,
        _ => match std::env::var("WAFFO_WEBHOOK_PUBLIC_KEY") {
            Ok(value) if !value.is_empty() => value,
            _ => {
                if env == "test" {
                    PANCAKE_BUILTIN_TEST_PUBLIC_KEY.to_owned()
                } else {
                    PANCAKE_BUILTIN_PROD_PUBLIC_KEY.to_owned()
                }
            }
        },
    };
    parse_pancake_public_key(&raw)
}

// ---------------------------------------------------------------------------
// Stripe
// ---------------------------------------------------------------------------

/// Go `ValidateRedirectURL`：http/https + 可信域名（含子域）白名单。
/// 可信域名来自 `TRUSTED_REDIRECT_DOMAINS` 环境变量（逗号分隔，小写归一）。
fn validate_redirect_url(raw_url: &str) -> Result<(), ()> {
    let parsed = match url_parse(raw_url) {
        Some(parsed) => parsed,
        None => return Err(()),
    };
    if parsed.scheme != "http" && parsed.scheme != "https" {
        return Err(());
    }
    let domain = parsed.host.to_lowercase();
    let trusted = std::env::var("TRUSTED_REDIRECT_DOMAINS").unwrap_or_default();
    for candidate in trusted.split(',') {
        let trusted_domain = candidate.trim().to_lowercase();
        if trusted_domain.is_empty() {
            continue;
        }
        if domain == trusted_domain || domain.ends_with(&format!(".{trusted_domain}")) {
            return Ok(());
        }
    }
    Err(())
}

/// Go `url.Parse` 的最小复刻：scheme + host 提取（忽略端口、userinfo、
/// path/query/fragment）。格式非法返回 `None`。
struct ParsedUrl {
    scheme: String,
    host: String,
}

fn url_parse(raw: &str) -> Option<ParsedUrl> {
    let (scheme, rest) = raw.split_once("://")?;
    if scheme.is_empty()
        || !scheme.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
        })
    {
        return None;
    }
    if scheme.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        return None;
    }
    // 去掉 path/query/fragment，再剥 userinfo。
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = match authority.rsplit_once('@') {
        Some((_, host)) => host,
        None => authority,
    };
    // IPv6 字面量 `[::1]:8080`。
    let host = if let Some(stripped) = host.strip_prefix('[') {
        stripped.split(']').next()?
    } else {
        host.split(':').next().unwrap_or_default()
    };
    if host.is_empty() {
        return None;
    }
    Some(ParsedUrl {
        scheme: scheme.to_owned(),
        host: host.to_owned(),
    })
}

/// Stripe `Stripe-Signature` 验签（`webhook.ConstructEventWithOptions`）：
/// `t=<unix>,v1=<hex>[,v1=...]`，`HMAC-SHA256(secret, "{t}.{payload}")`，
/// 任一 v1 命中即通过，300 秒容差（`IgnoreTolerance=false`）。
fn verify_stripe_signature(
    payload: &[u8],
    header: &str,
    secret: &str,
) -> Result<(), StripeVerifyError> {
    use ring::hmac;
    if header.is_empty() {
        return Err(StripeVerifyError::NotSigned);
    }
    let mut timestamp: Option<i64> = None;
    let mut signatures: Vec<Vec<u8>> = Vec::new();
    for pair in header.split(',') {
        let Some((key, value)) = pair.split_once('=') else {
            return Err(StripeVerifyError::InvalidHeader);
        };
        match key {
            "t" => {
                timestamp = Some(
                    value
                        .parse::<i64>()
                        .map_err(|_| StripeVerifyError::InvalidHeader)?,
                );
            }
            "v1" => {
                if let Ok(signature) = hex_decode(value) {
                    signatures.push(signature);
                }
            }
            _ => {}
        }
    }
    if signatures.is_empty() {
        return Err(StripeVerifyError::NoValidSignature);
    }
    let timestamp = timestamp.ok_or(StripeVerifyError::InvalidHeader)?;
    let now = newapi_billing::topup::now_seconds();
    if now - timestamp > 300 {
        return Err(StripeVerifyError::TooOld);
    }
    let key = hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
    let mut signed = Vec::with_capacity(payload.len() + 21);
    signed.extend_from_slice(timestamp.to_string().as_bytes());
    signed.push(b'.');
    signed.extend_from_slice(payload);
    for signature in &signatures {
        if hmac::verify(&key, &signed, signature).is_ok() {
            return Ok(());
        }
    }
    Err(StripeVerifyError::NoValidSignature)
}

#[derive(Debug, PartialEq, Eq)]
enum StripeVerifyError {
    NotSigned,
    InvalidHeader,
    NoValidSignature,
    TooOld,
}

fn hex_decode(input: &str) -> Result<Vec<u8>, ()> {
    if !input.len().is_multiple_of(2) {
        return Err(());
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(input.len() / 2);
    for index in (0..bytes.len()).step_by(2) {
        let high = hex_value(bytes[index]).ok_or(())?;
        let low = hex_value(bytes[index + 1]).ok_or(())?;
        out.push(high * 16 + low);
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// `POST /api/user/stripe/pay` → Go `billing.RequestStripePay`。
pub async fn request_stripe_pay(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    injected: Option<Extension<InjectedStripeTransport>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(request) = bind_stripe_request(&headers, &body) else {
        return pay_error_str(MSG_BAD_REQUEST);
    };
    if request.payment_method != "stripe" {
        return pay_error_str(MSG_UNSUPPORTED_METHOD);
    }
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let settings = match TopUpSettings::load(&db).await {
        Ok(settings) => settings,
        Err(error) => {
            tracing::warn!(
                event = "stripe_pay_settings_load_failed",
                category = crate::database_error_class(&error),
                "stripe pay settings load failed"
            );
            return pay_error_str(MSG_BAD_REQUEST);
        }
    };
    // Go `getStripeMinTopup`：TOKENS 展示下按 `int(QuotaPerUnit)` 放大。
    let display = state.quota_display();
    let tokens = display.kind == QuotaDisplayKind::Tokens;
    let quota_per_unit = display.quota_per_unit;
    let mut minimum = settings.stripe_min_topup;
    if tokens {
        minimum = (i128::from(minimum) * i128::from(quota_per_unit as i64)) as i64;
    }
    if request.amount < minimum {
        return pay_error_message_field(msg_below_minimum(minimum));
    }
    if request.amount > 10_000 {
        return pay_error_message_field("充值数量不能大于 10000".to_owned());
    }
    if !request.success_url.is_empty() && validate_redirect_url(&request.success_url).is_err() {
        // 注意状态码：Go 是 400 而非 200。
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "message": "支付成功重定向URL不在可信任域名列表中",
                "data": "",
            })),
        )
            .into_response();
    }
    if !request.cancel_url.is_empty() && validate_redirect_url(&request.cancel_url).is_err() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "message": "支付取消重定向URL不在可信任域名列表中",
                "data": "",
            })),
        )
            .into_response();
    }
    let profile = match UserProfileRepository::new(db.clone())
        .by_id(auth_user.0.user_id)
        .await
    {
        Ok(Some(profile)) => profile,
        _ => return pay_error_str(MSG_USER_MISSING),
    };
    // Go `GetChargedAmount`：分组倍率 0 → 1。
    let ratio = newapi_billing::topup::topup_group_ratio(&settings, &profile.group);
    let ratio = if ratio == 0.0 { 1.0 } else { ratio };
    let charged_money = request.amount as f64 * ratio;
    // Go `rejectInvalidCreditedQuota(decimal(chargedMoney) × QuotaPerUnit)`。
    let credited = credited_quota_f64(charged_money, quota_per_unit);
    if let Err(rejection) = validate_credited_quota(credited) {
        return pay_error_str(rejection.message());
    }
    if let Err(rejection) = check_capacity(credited, profile.quota) {
        return pay_error_str(rejection.message());
    }
    // 分组倍率与折扣必须体现在 Checkout 的 Quantity 上。
    let pay_units = stripe_pay_units(&settings, request.amount, &profile.group);
    let reference = format!(
        "new-api-ref-{}-{}-{}",
        auth_user.0.user_id,
        now_millis(),
        base62_string(4)
    );
    let trade_no = format!("ref_{}", sha1_hex(&reference));
    let addresses = callback_addresses(&db).await;
    let params = StripeCheckoutParams {
        client_reference_id: trade_no.clone(),
        success_url: if request.success_url.is_empty() {
            payment_return_path(&addresses.server, "/usage-logs")
        } else {
            request.success_url.clone()
        },
        cancel_url: if request.cancel_url.is_empty() {
            payment_return_path(&addresses.server, "/wallet")
        } else {
            request.cancel_url.clone()
        },
        price_id: settings.stripe_price_id.clone(),
        quantity: pay_units,
        promotion_codes_enabled: settings.stripe_promotion_codes_enabled,
        customer_id: profile.stripe_customer.clone(),
        customer_email: if profile.stripe_customer.is_empty() {
            profile.email.clone()
        } else {
            String::new()
        },
    };
    // Go `genStripeLink`：密钥必须以 sk_ / rk_ 开头。
    if !settings.stripe_api_secret.starts_with("sk_")
        && !settings.stripe_api_secret.starts_with("rk_")
    {
        return pay_error_str(MSG_PAY_START_FAILED);
    }
    let transport: &dyn StripeTransport = match injected.as_ref() {
        Some(injected) => injected.0.0.as_ref(),
        None => &HttpStripeTransport,
    };
    let pay_link = match transport
        .create_checkout_session(&settings.stripe_api_secret, &params)
        .await
    {
        Ok(link) => link,
        Err(error) => {
            tracing::warn!(
                event = "stripe_checkout_failed",
                user_id = auth_user.0.user_id,
                trade_no = %trade_no,
                error = %error,
                "Stripe 创建 Checkout Session 失败"
            );
            return pay_error_str(MSG_PAY_START_FAILED);
        }
    };
    // Amount 记录 Checkout 实际计价的单位数；Money 记录分组倍率换算后的金额。
    if let Err(error) = insert_topup(
        &db,
        auth_user.0.user_id,
        pay_units,
        charged_money,
        &trade_no,
        "stripe",
        PROVIDER_STRIPE,
    )
    .await
    {
        tracing::warn!(
            event = "stripe_order_create_failed",
            category = crate::database_error_class(&error),
            trade_no = %trade_no,
            "Stripe 创建充值订单失败"
        );
        return pay_error_str(MSG_ORDER_CREATE_FAILED);
    }
    tracing::info!(event = "stripe_order_created", trade_no = %trade_no, "Stripe 充值订单创建成功");
    Json(json!({
        "message": "success",
        "data": {"pay_link": pay_link},
    }))
    .into_response()
}

/// Go `decimal.NewFromFloat(money).Mul(QuotaPerUnit)` → `QuotaFromDecimalStrict`
/// 前的十进制额度值（与回调核销的 `quota_from_product_f64` 同一换算口径）。
fn credited_quota_f64(money: f64, quota_per_unit: f64) -> i64 {
    let product = money * quota_per_unit;
    if !product.is_finite() {
        return 0;
    }
    product.round() as i64
}

// ---------------------------------------------------------------------------
// Creem
// ---------------------------------------------------------------------------

/// `POST /api/user/creem/pay` → Go `billing.RequestCreemPay`。
pub async fn request_creem_pay(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    injected: Option<Extension<InjectedCreemTransport>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(request) = bind_creem_request(&headers, &body) else {
        return pay_error_str(MSG_BAD_REQUEST);
    };
    if request.payment_method != "creem" {
        return pay_error_str(MSG_UNSUPPORTED_METHOD);
    }
    if request.product_id.is_empty() {
        return pay_error_str(MSG_PLEASE_SELECT_PRODUCT);
    }
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let settings = match TopUpSettings::load(&db).await {
        Ok(settings) => settings,
        Err(error) => {
            tracing::warn!(
                event = "creem_pay_settings_load_failed",
                category = crate::database_error_class(&error),
                "creem pay settings load failed"
            );
            return pay_error_str(MSG_BAD_REQUEST);
        }
    };
    let Some(products) = settings.creem_products() else {
        return pay_error_str(MSG_PRODUCT_CONFIG_ERROR);
    };
    let Some(product) = products
        .iter()
        .find(|product| product.product_id == request.product_id)
    else {
        return pay_error_str(MSG_PRODUCT_NOT_FOUND);
    };
    // Go `rejectInvalidCreditedQuota` 内部读用户余额（容量预检），此处先取
    // 用户行再校验：缺失用户的拒绝文案与 Go 的 GetTopUpQuota 容量错误同源。
    let profile = match UserProfileRepository::new(db.clone())
        .by_id(auth_user.0.user_id)
        .await
    {
        Ok(Some(profile)) => profile,
        _ => return pay_error_str(MSG_USER_MISSING),
    };
    if let Err(rejection) = validate_credited_quota(product.quota) {
        return pay_error_str(rejection.message());
    }
    if let Err(rejection) = check_capacity(product.quota, profile.quota) {
        return pay_error_str(rejection.message());
    }
    let reference = format!(
        "creem-api-ref-{}-{}-{}",
        auth_user.0.user_id,
        now_millis(),
        base62_string(4)
    );
    let trade_no = format!("ref_{}", sha1_hex(&reference));
    if let Err(error) = insert_topup(
        &db,
        auth_user.0.user_id,
        product.quota,
        product.price,
        &trade_no,
        "creem",
        PROVIDER_CREEM,
    )
    .await
    {
        tracing::warn!(
            event = "creem_order_create_failed",
            category = crate::database_error_class(&error),
            trade_no = %trade_no,
            "Creem 创建充值订单失败"
        );
        return pay_error_str(MSG_ORDER_CREATE_FAILED);
    }
    let checkout_request = CreemCheckoutRequest {
        product_id: product.product_id.clone(),
        request_id: trade_no.clone(),
        email: profile.email.clone(),
        metadata_username: profile.username.clone(),
        metadata_reference_id: trade_no.clone(),
        metadata_product_name: product.name.clone(),
        metadata_quota: product.quota.to_string(),
    };
    // Go `genCreemLink`：密钥未配置直接失败（订单已建、保持 pending）。
    if settings.creem_api_key.is_empty() {
        return pay_error_str(MSG_PAY_START_FAILED);
    }
    let transport: &dyn CreemTransport = match injected.as_ref() {
        Some(injected) => injected.0.0.as_ref(),
        None => &HttpCreemTransport,
    };
    match transport
        .create_checkout(
            &settings.creem_api_key,
            settings.creem_test_mode,
            &checkout_request,
        )
        .await
    {
        Ok((checkout_url, _id)) => {
            tracing::info!(event = "creem_order_created", trade_no = %trade_no, "Creem 充值订单创建成功");
            Json(json!({
                "message": "success",
                "data": {
                    "checkout_url": checkout_url,
                    "order_id": trade_no,
                },
            }))
            .into_response()
        }
        Err(error) => {
            tracing::warn!(
                event = "creem_checkout_failed",
                trade_no = %trade_no,
                error = %error,
                "Creem 创建支付链接失败"
            );
            pay_error_str(MSG_PAY_START_FAILED)
        }
    }
}

// ---------------------------------------------------------------------------
// Waffo
// ---------------------------------------------------------------------------

/// Go `getWaffoSDK` 的凭证解析与校验（`config.ConfigBuilder.Build`）。
fn waffo_creds(settings: &TopUpSettings) -> Result<WaffoCreds, ()> {
    let (api_key, private_key, public_cert) = if settings.waffo_sandbox {
        (
            &settings.waffo_sandbox_api_key,
            &settings.waffo_sandbox_private_key,
            &settings.waffo_sandbox_public_cert,
        )
    } else {
        (
            &settings.waffo_api_key,
            &settings.waffo_private_key,
            &settings.waffo_public_cert,
        )
    };
    if api_key.trim().is_empty() || private_key.trim().is_empty() || public_cert.trim().is_empty() {
        return Err(());
    }
    // Build 阶段校验私钥/公钥格式（PKCS#8 / SPKI）。
    if crate::pancake::parse_private_key(private_key).is_err() {
        return Err(());
    }
    if parse_spki_public_key(public_cert).is_err() {
        return Err(());
    }
    Ok(WaffoCreds {
        api_key: api_key.clone(),
        private_key: private_key.clone(),
        public_cert: public_cert.clone(),
        merchant_id: settings.waffo_merchant_id.clone(),
        sandbox: settings.waffo_sandbox,
    })
}

/// base64 SPKI 公钥解析（Go `utils.ValidatePublicKey`）。
fn parse_spki_public_key(public_key: &str) -> Result<rsa::RsaPublicKey, ()> {
    let der = base64::engine::general_purpose::STANDARD
        .decode(public_key.trim())
        .map_err(|_| ())?;
    rsa::RsaPublicKey::from_public_key_der(&der).map_err(|_| ())
}

/// Go `zeroDecimalCurrencies`。
fn is_zero_decimal_currency(currency: &str) -> bool {
    matches!(currency, "IDR" | "JPY" | "KRW" | "VND")
}

/// Go `formatWaffoAmount`。
fn format_waffo_amount(amount: f64, currency: &str) -> String {
    if is_zero_decimal_currency(currency) {
        format!("{amount:.0}")
    } else {
        format!("{amount:.2}")
    }
}

/// Go `getWaffoCurrency`。
fn waffo_currency(settings: &TopUpSettings) -> String {
    if !settings.waffo_currency.is_empty() {
        settings.waffo_currency.clone()
    } else {
        "USD".to_owned()
    }
}

/// Go `buildWaffoTopUpGoodsInfo`。
fn waffo_goods_name(amount: i64) -> String {
    format!("Recharge {amount} credits")
}

fn waffo_app_name() -> String {
    // Go `common.SystemName`；SystemName option 尚未进运行时快照（P3 待办，
    // 见 status.rs 同样的默认值处理），暂取 Go 常量默认。
    "New API".to_owned()
}

/// Go `getWaffoUserEmail`。
fn waffo_user_email(user_id: i64) -> String {
    format!("{user_id}@examples.com")
}

/// Go `CreateOrderData.FetchRedirectURL`。
fn waffo_redirect_url(order_action: &str) -> String {
    if order_action.is_empty() {
        return String::new();
    }
    let Ok(action) = serde_json::from_str::<Value>(order_action) else {
        return String::new();
    };
    let action_type = action
        .get("actionType")
        .and_then(Value::as_str)
        .unwrap_or("");
    let deeplink = action
        .get("deeplinkUrl")
        .and_then(Value::as_str)
        .unwrap_or("");
    if action_type == "DEEPLINK" && !deeplink.is_empty() {
        return deeplink.to_owned();
    }
    action
        .get("webUrl")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}

/// `POST /api/user/waffo/pay` → Go `billing.RequestWaffoPay`。
pub async fn request_waffo_pay(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    injected: Option<Extension<InjectedWaffoTransport>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let settings = match TopUpSettings::load(&db).await {
        Ok(settings) => settings,
        Err(error) => {
            tracing::warn!(
                event = "waffo_pay_settings_load_failed",
                category = crate::database_error_class(&error),
                "waffo pay settings load failed"
            );
            return pay_error_str(MSG_BAD_REQUEST);
        }
    };
    if !settings.waffo_enabled {
        return pay_error_str(MSG_WAFFO_NOT_ENABLED);
    }
    let Ok(request) = bind_waffo_request(&headers, &body) else {
        return pay_error_str(MSG_BAD_REQUEST);
    };
    let minimum = settings.waffo_min_topup;
    if request.amount < minimum {
        return pay_error(msg_below_minimum(minimum));
    }
    let display = state.quota_display();
    let tokens = display.kind == QuotaDisplayKind::Tokens;
    let quota_per_unit = display.quota_per_unit;
    let profile = match UserProfileRepository::new(db.clone())
        .by_id(auth_user.0.user_id)
        .await
    {
        Ok(Some(profile)) => profile,
        _ => return pay_error_str(MSG_USER_MISSING),
    };
    // Go `rejectInvalidTopUpQuota`：额度换算 + 钱包容量预检。
    let credited = match validate_top_up_quota(&settings, request.amount, tokens, quota_per_unit) {
        Ok(credited) => credited,
        Err(TopUpQuotaRejection::ExceedsMax(max)) => {
            return pay_error(format!("单笔充值数量不能大于 {max}"));
        }
        Err(TopUpQuotaRejection::InvalidQuota) => return pay_error_str("充值数量无效"),
    };
    if let Err(rejection) = check_capacity(credited, profile.quota) {
        return pay_error_str(rejection.message());
    }
    // 支付方式解析：优先索引，其次旧字段（须在服务端列表内）。
    let methods = settings.waffo_pay_methods.parse_waffo_methods();
    let mut resolved_type = String::new();
    let mut resolved_name = String::new();
    if let Some(index) = request.pay_method_index {
        if index < 0 || index >= methods.len() as i64 {
            tracing::warn!(
                event = "waffo_pay_method_index_invalid",
                user_id = auth_user.0.user_id,
                pay_method_index = index,
                "Waffo 支付方式索引无效"
            );
            return pay_error_str(MSG_PAY_METHOD_UNSUPPORTED);
        }
        let method = &methods[index as usize];
        resolved_type = method.pay_method_type.clone();
        resolved_name = method.pay_method_name.clone();
    } else if !request.pay_method_type.is_empty() {
        let matched = methods.iter().any(|method| {
            method.pay_method_type == request.pay_method_type
                && method.pay_method_name == request.pay_method_name
        });
        if !matched {
            tracing::warn!(
                event = "waffo_pay_method_invalid",
                user_id = auth_user.0.user_id,
                "Waffo 支付方式无效"
            );
            return pay_error_str(MSG_PAY_METHOD_UNSUPPORTED);
        }
        resolved_type = request.pay_method_type.clone();
        resolved_name = request.pay_method_name.clone();
    }
    let pay_money = waffo_pay_money(
        &settings,
        request.amount,
        &profile.group,
        tokens,
        quota_per_unit,
    );
    if pay_money < 0.01 {
        return pay_error_str(MSG_AMOUNT_TOO_SMALL);
    }
    let merchant_order_id = format!(
        "WAFFO-{}-{}-{}",
        auth_user.0.user_id,
        now_millis(),
        newapi_billing::topup::random_string(6)
    );
    // TOKENS 模式下归一化 Amount（存等价美元/CNY 数量）。
    let mut amount = request.amount;
    if tokens {
        amount = (request.amount as f64 / quota_per_unit) as i64;
        if amount < 1 {
            amount = 1;
        }
    }
    if let Err(error) = insert_topup(
        &db,
        auth_user.0.user_id,
        amount,
        pay_money,
        &merchant_order_id,
        "waffo",
        PROVIDER_WAFFO,
    )
    .await
    {
        tracing::warn!(
            event = "waffo_order_create_failed",
            category = crate::database_error_class(&error),
            trade_no = %merchant_order_id,
            "Waffo 创建充值订单失败"
        );
        return pay_error_str(MSG_ORDER_CREATE_FAILED);
    }
    let creds = match waffo_creds(&settings) {
        Ok(creds) => creds,
        Err(()) => {
            let _ = set_topup_status(&db, &merchant_order_id, STATUS_FAILED).await;
            return pay_error_str(MSG_PAY_CONFIG_ERROR);
        }
    };
    let addresses = callback_addresses(&db).await;
    let notify_url = if settings.waffo_notify_url.is_empty() {
        format!("{}/api/waffo/webhook", addresses.callback)
    } else {
        settings.waffo_notify_url.clone()
    };
    let return_url = if settings.waffo_return_url.is_empty() {
        payment_return_path(&addresses.server, "/wallet?show_history=true")
    } else {
        settings.waffo_return_url.clone()
    };
    let currency = waffo_currency(&settings);
    let mut body = json!({
        "paymentRequestId": merchant_order_id,
        "merchantOrderId": merchant_order_id,
        "orderAmount": format_waffo_amount(pay_money, &currency),
        "orderCurrency": currency,
        "orderDescription": waffo_goods_name(request.amount),
        "orderRequestedAt": waffo_timestamp(),
        "notifyUrl": notify_url,
        "merchantInfo": {},
        "userInfo": {
            "userId": auth_user.0.user_id.to_string(),
            "userEmail": waffo_user_email(auth_user.0.user_id),
            "userTerminal": "WEB",
        },
        "paymentInfo": {
            "productName": "ONE_TIME_PAYMENT",
        },
        "goodsInfo": {
            "goodsName": waffo_goods_name(request.amount),
            "appName": waffo_app_name(),
        },
        "successRedirectUrl": return_url,
        "failedRedirectUrl": return_url,
    });
    if !creds.merchant_id.is_empty() {
        body["merchantInfo"]["merchantId"] = Value::String(creds.merchant_id.clone());
    }
    if !resolved_type.is_empty() {
        body["paymentInfo"]["payMethodType"] = Value::String(resolved_type.clone());
    }
    if !resolved_name.is_empty() {
        body["paymentInfo"]["payMethodName"] = Value::String(resolved_name.clone());
    }
    let transport: &dyn WaffoTransport = match injected.as_ref() {
        Some(injected) => injected.0.0.as_ref(),
        None => &HttpWaffoTransport,
    };
    let (code, message, data) = match transport.create_order(&creds, &body).await {
        Ok(result) => result,
        Err(error) => {
            tracing::warn!(
                event = "waffo_order_upstream_failed",
                trade_no = %merchant_order_id,
                error = %error,
                "Waffo 创建订单失败"
            );
            let _ = set_topup_status(&db, &merchant_order_id, STATUS_FAILED).await;
            return pay_error_str(MSG_PAY_START_FAILED);
        }
    };
    if code != "0" {
        tracing::warn!(
            event = "waffo_order_business_failed",
            trade_no = %merchant_order_id,
            code = %code,
            message = %message,
            "Waffo 创建订单业务失败"
        );
        let _ = set_topup_status(&db, &merchant_order_id, STATUS_FAILED).await;
        return pay_error_str(MSG_PAY_START_FAILED);
    }
    let order_action = data
        .get("orderAction")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let mut payment_url = waffo_redirect_url(&order_action);
    if payment_url.is_empty() {
        payment_url = order_action;
    }
    tracing::info!(event = "waffo_order_created", trade_no = %merchant_order_id, "Waffo 充值订单创建成功");
    Json(json!({
        "message": "success",
        "data": {
            "payment_url": payment_url,
            "order_id": merchant_order_id,
        },
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// Waffo Pancake
// ---------------------------------------------------------------------------

/// Go `WaffoPancakeBuyerIdentityFromUserID`。
fn pancake_buyer_identity(user_id: i64) -> String {
    format!("new-api-user-{user_id}")
}

/// Go `formatWaffoPancakeAmount`（`decimal.StringFixed(2)`：halve-even 进位，
/// 2 位定点渲染）。
fn format_pancake_amount(pay_money: f64) -> String {
    format!("{pay_money:.2}")
}

/// Go 十进制等值比较（`decimal.NewFromString(a).Equal(b)`）：忽略尾零与
/// 记法差异（"10.00" == "10.0"），非法输入视为不等。
fn decimal_eq(a: &str, b: &str) -> bool {
    match (parse_decimal(a), parse_decimal(b)) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
}

/// 十进制字符串 → 归一化（去尾零）的 `(负号, 整数位, 小数位)` 三元组。
fn parse_decimal(input: &str) -> Option<(bool, String, String)> {
    let input = input.trim();
    let (negative, digits) = match input.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, input.strip_prefix('+').unwrap_or(input)),
    };
    let (int_part, frac_part) = match digits.split_once('.') {
        Some((int_part, frac_part)) => (int_part, frac_part),
        None => (digits, ""),
    };
    if int_part.is_empty() && frac_part.is_empty() {
        return None;
    }
    if !int_part.bytes().all(|byte| byte.is_ascii_digit())
        || !frac_part.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let int_part = int_part.trim_start_matches('0').to_owned();
    let mut frac_part = frac_part.trim_end_matches('0').to_owned();
    if frac_part.is_empty() {
        frac_part = "0".to_owned();
    }
    Some((negative, int_part, frac_part))
}

/// Go `getWaffoPancakeBuyerEmail`。
fn pancake_buyer_email(profile: &newapi_identity::users::UserProfile) -> String {
    profile.email.trim().to_owned()
}

/// `POST /api/user/waffo-pancake/pay` → Go `billing.RequestWaffoPancakePay`。
pub async fn request_waffo_pancake_pay(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    injected: Option<Extension<InjectedPancakeCheckoutTransport>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let settings = match TopUpSettings::load(&db).await {
        Ok(settings) => settings,
        Err(error) => {
            tracing::warn!(
                event = "pancake_pay_settings_load_failed",
                category = crate::database_error_class(&error),
                "pancake pay settings load failed"
            );
            return pay_error_str(MSG_BAD_REQUEST);
        }
    };
    if !settings.is_waffo_pancake_topup_enabled() {
        return pay_error_str(MSG_PANCAKE_CONFIG_INCOMPLETE);
    }
    let Ok(request) = bind_amount_only(&headers, &body) else {
        return pay_error_str(MSG_BAD_REQUEST);
    };
    let minimum = settings.waffo_pancake_min_topup;
    if request.amount < minimum {
        return pay_error(msg_below_minimum(minimum));
    }
    let display = state.quota_display();
    let tokens = display.kind == QuotaDisplayKind::Tokens;
    let quota_per_unit = display.quota_per_unit;
    let profile = match UserProfileRepository::new(db.clone())
        .by_id(auth_user.0.user_id)
        .await
    {
        Ok(Some(profile)) => profile,
        _ => return pay_error_str(MSG_USER_MISSING),
    };
    let credited = match validate_top_up_quota(&settings, request.amount, tokens, quota_per_unit) {
        Ok(credited) => credited,
        Err(TopUpQuotaRejection::ExceedsMax(max)) => {
            return pay_error(format!("单笔充值数量不能大于 {max}"));
        }
        Err(TopUpQuotaRejection::InvalidQuota) => return pay_error_str("充值数量无效"),
    };
    if let Err(rejection) = check_capacity(credited, profile.quota) {
        return pay_error_str(rejection.message());
    }
    let pay_money = waffo_pancake_pay_money(
        &settings,
        request.amount,
        &profile.group,
        tokens,
        quota_per_unit,
    );
    if pay_money < 0.01 {
        return pay_error_str(MSG_AMOUNT_TOO_SMALL);
    }
    let trade_no = format!(
        "WAFFO_PANCAKE-{}-{}-{}",
        auth_user.0.user_id,
        now_millis(),
        newapi_billing::topup::random_string(6)
    );
    // Go `normalizeWaffoPancakeTopUpAmount`：TOKENS 模式下 decimal 截断。
    let mut amount = request.amount;
    if tokens {
        amount = (request.amount as f64 / quota_per_unit).trunc() as i64;
        if amount < 1 {
            amount = 1;
        }
    }
    if let Err(error) = insert_topup(
        &db,
        auth_user.0.user_id,
        amount,
        pay_money,
        &trade_no,
        "waffo_pancake",
        PROVIDER_WAFFO_PANCAKE,
    )
    .await
    {
        tracing::warn!(
            event = "pancake_order_create_failed",
            category = crate::database_error_class(&error),
            trade_no = %trade_no,
            "Waffo Pancake 创建充值订单失败"
        );
        return pay_error_str(MSG_ORDER_CREATE_FAILED);
    }
    let params = PancakeCheckoutParams {
        product_id: settings.waffo_pancake_product_id.clone(),
        buyer_identity: pancake_buyer_identity(auth_user.0.user_id),
        buyer_email: pancake_buyer_email(&profile),
        price_amount: format_pancake_amount(pay_money),
        expires_in_seconds: 45 * 60,
        order_merchant_external_id: trade_no.clone(),
    };
    let transport: &dyn PancakeCheckoutTransport = match injected.as_ref() {
        Some(injected) => injected.0.0.as_ref(),
        None => &HttpPancakeCheckoutTransport,
    };
    match transport
        .create_authenticated_checkout(
            &settings.waffo_pancake_merchant_id,
            &settings.waffo_pancake_private_key,
            &params,
        )
        .await
    {
        Ok(session) => {
            tracing::info!(event = "pancake_order_created", trade_no = %trade_no, "Waffo Pancake 充值订单创建成功");
            Json(json!({
                "message": "success",
                "data": {
                    "checkout_url": session.checkout_url,
                    "session_id": session.session_id,
                    "expires_at": session.expires_at,
                    "order_id": trade_no,
                    "token": session.token,
                    "token_expires_at": session.token_expires_at,
                },
            }))
            .into_response()
        }
        Err(error) => {
            tracing::warn!(
                event = "pancake_checkout_failed",
                trade_no = %trade_no,
                error = %error.0,
                "Waffo Pancake 创建结账会话失败"
            );
            let _ = set_topup_status(&db, &trade_no, STATUS_FAILED).await;
            pay_error_str(MSG_PAY_START_FAILED)
        }
    }
}

/// Go `WaffoPancakePayRequest`：仅 `amount` 一个字段。
fn bind_amount_only(headers: &HeaderMap, body: &[u8]) -> Result<AmountOnlyRequest, ()> {
    if !parses_as_json(headers) || body.is_empty() {
        return Ok(AmountOnlyRequest::default());
    }
    let parsed: Value = serde_json::from_slice(body).map_err(|_| ())?;
    let Some(object) = parsed.as_object() else {
        return Ok(AmountOnlyRequest::default());
    };
    let mut request = AmountOnlyRequest::default();
    match object.get("amount") {
        None | Some(Value::Null) => {}
        Some(value) => request.amount = value.as_i64().ok_or(())?,
    }
    Ok(request)
}

#[derive(Default)]
struct AmountOnlyRequest {
    amount: i64,
}

// ---------------------------------------------------------------------------
// Webhooks
// ---------------------------------------------------------------------------

/// Stripe 事件体（仅本切片使用的字段）。`amount_total` / `currency` 为
/// Go `event.GetObjectValue(...)` 的履约载荷字段。
#[derive(Default)]
struct StripeEvent {
    event_type: String,
    customer: String,
    client_reference_id: String,
    status: String,
    payment_status: String,
    amount_total: String,
    currency: String,
}

fn parse_stripe_event(payload: &[u8]) -> Option<StripeEvent> {
    let parsed: Value = serde_json::from_slice(payload).ok()?;
    let object = parsed.get("data")?.get("object")?;
    Some(StripeEvent {
        event_type: parsed
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        customer: object
            .get("customer")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        client_reference_id: object
            .get("client_reference_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        status: object
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        payment_status: object
            .get("payment_status")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        amount_total: object
            .get("amount_total")
            .map(|value| match value {
                Value::String(text) => text.clone(),
                other => other.to_string(),
            })
            .unwrap_or_default(),
        currency: object
            .get("currency")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
    })
}

/// Stripe 履约的永久失败判定（Go `isPermanentFulfillmentError`）。
fn stripe_permanent_error(error: &newapi_billing::topup::RechargeError) -> bool {
    use newapi_billing::topup::RechargeError as Error;
    matches!(
        error,
        Error::NotFound
            | Error::StatusInvalid
            | Error::ProviderMismatch
            | Error::InvalidQuota
            | Error::QuotaLimitExceeded
    )
}

/// Go `fulfillOrder` 的订阅订单半边（`topup_stripe.go:294-312`）：先试订阅
/// 核销（载荷为 customer + amount_total + currency + event_type 的 JSON）；
/// `ErrSubscriptionOrderNotFound` 等价于订单不存在 → 返回 `Ok(false)` 落回
/// 充值核销。永久失败（网关不符/状态非法）记 warn 后返回 `Ok(true)`
/// （让 Stripe 停止重投）；其余错误上抛等待重试。
async fn fulfill_subscription_order(
    db: &newapi_storage::Database,
    trade_no: &str,
    provider: &str,
    customer: &str,
    amount_total: &str,
    currency: &str,
    event_type: &str,
) -> Result<bool, SubscriptionOrderError> {
    let payload = json!({
        "customer": customer,
        "amount_total": amount_total,
        "currency": currency.to_uppercase(),
        "event_type": event_type,
    })
    .to_string();
    match complete_subscription_order(db, trade_no, &payload, provider, "", now_seconds()).await {
        Ok(outcome) => Ok(matches!(outcome, SubscriptionCompleteOutcome::Completed(_))),
        Err(SubscriptionOrderError::NotFound) => Ok(false),
        Err(error) => {
            if matches!(
                error,
                SubscriptionOrderError::ProviderMismatch | SubscriptionOrderError::StatusInvalid
            ) {
                tracing::warn!(
                    trade_no = %trade_no,
                    error = %error,
                    "订阅订单永久失败，不再重试"
                );
                Ok(true)
            } else {
                tracing::error!(
                    trade_no = %trade_no,
                    error = %error,
                    "订阅订单处理失败，等待重试"
                );
                Err(error)
            }
        }
    }
}

/// Go `fulfillOrder`（订阅订单半边先行，充值半边兜底）。
async fn stripe_fulfill_order(
    db: &newapi_storage::Database,
    event: &StripeEvent,
    quota_per_unit: f64,
    event_type: &str,
    amount_total: &str,
    currency: &str,
) -> Result<(), ()> {
    if event.client_reference_id.is_empty() {
        tracing::warn!(
            event = "stripe_fulfill_missing_trade_no",
            "Stripe 完成订单时缺少订单号"
        );
        return Ok(());
    }
    // Go：`LockOrder` 之后先试订阅订单（`topup_stripe.go:301`）。进程内锁
    // 只是优化，正确性由订单状态机的事务 + CAS 承担。
    match fulfill_subscription_order(
        db,
        &event.client_reference_id,
        PROVIDER_STRIPE,
        &event.customer,
        amount_total,
        currency,
        event_type,
    )
    .await
    {
        Ok(true) => {
            tracing::info!(
                trade_no = %event.client_reference_id,
                event_type = %event_type,
                "Stripe 订阅订单处理成功"
            );
            return Ok(());
        }
        Ok(false) => {}
        // 订阅订单可重试失败：与充值侧同型（上抛 → webhook 回 5xx 重投）。
        Err(_) => return Err(()),
    }
    // Go `Recharge`：额度来自订单行的 `Money × QuotaPerUnit`
    // （`QuotaFromDecimalStrict` → decimal `Round(0)` 后取整），`amount_total`
    // 仅进日志。
    let outcome = recharge_external_top_up(
        db,
        ExternalRechargeParams {
            trade_no: &event.client_reference_id,
            expected_provider: PROVIDER_STRIPE,
            quota_source: ExternalQuotaSource::MoneyTimesUnit,
            quota_per_unit,
            computed_quota: 0,
            idempotent_success: false,
            user_update: ExternalUserUpdate::StripeCustomer(&event.customer),
        },
    )
    .await;
    match outcome {
        Ok(_) => Ok(()),
        Err(error) => {
            if stripe_permanent_error(&error) {
                tracing::warn!(
                    trade_no = %event.client_reference_id,
                    "Stripe 充值永久失败，不再重试"
                );
                return Ok(());
            }
            tracing::error!(
                trade_no = %event.client_reference_id,
                "Stripe 充值处理失败，等待重试"
            );
            let _ = error;
            Err(())
        }
    }
}

/// `POST /api/stripe/webhook` → Go `billing.StripeWebhook`。
pub async fn stripe_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let settings = match TopUpSettings::load(&db).await {
        Ok(settings) => settings,
        Err(error) => {
            tracing::warn!(
                event = "stripe_webhook_settings_load_failed",
                category = crate::database_error_class(&error),
                "stripe webhook settings load failed"
            );
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    if !settings.is_stripe_topup_enabled() {
        tracing::warn!(
            event = "stripe_webhook_disabled",
            "Stripe webhook 被拒绝 reason=webhook_disabled"
        );
        return StatusCode::FORBIDDEN.into_response();
    }
    let signature = headers
        .get("Stripe-Signature")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if let Err(error) = verify_stripe_signature(&body, signature, &settings.stripe_webhook_secret) {
        tracing::warn!(event = "stripe_webhook_verify_failed", reason = ?error, "Stripe webhook 验签失败");
        return StatusCode::BAD_REQUEST.into_response();
    }
    let Some(event) = parse_stripe_event(&body) else {
        // Go：验签成功但 JSON 解析失败 → 400。
        tracing::warn!(
            event = "stripe_webhook_parse_failed",
            "Stripe webhook 解析失败"
        );
        return StatusCode::BAD_REQUEST.into_response();
    };
    let display = state.quota_display();
    let fulfill = match event.event_type.as_str() {
        "checkout.session.completed" => {
            if event.status != "complete" {
                tracing::warn!(trade_no = %event.client_reference_id, "Stripe checkout.completed 状态异常，忽略处理");
                None
            } else if event.payment_status != "paid" {
                tracing::info!(trade_no = %event.client_reference_id, "Stripe Checkout 支付未完成，等待异步结果");
                None
            } else {
                Some(true)
            }
        }
        "checkout.session.async_payment_succeeded" => Some(true),
        "checkout.session.async_payment_failed" => {
            if event.client_reference_id.is_empty() {
                tracing::warn!("Stripe 异步支付失败事件缺少订单号");
                None
            } else if let Err(error) = update_pending_top_up_status(
                &db,
                &event.client_reference_id,
                PROVIDER_STRIPE,
                STATUS_FAILED,
            )
            .await
            {
                // Go：更新失败只记日志，恒 200。
                let _ = error;
                None
            } else {
                tracing::info!(trade_no = %event.client_reference_id, "Stripe 充值订单已标记为失败");
                None
            }
        }
        "checkout.session.expired" => {
            if event.status != "expired" {
                tracing::warn!(trade_no = %event.client_reference_id, "Stripe checkout.expired 状态异常，忽略处理");
                None
            } else if event.client_reference_id.is_empty() {
                tracing::warn!("Stripe checkout.expired 缺少订单号");
                None
            } else {
                // Go：先试订阅订单过期（`topup_stripe.go:356-362`），NotFound
                // 等价于订阅订单不存在 → 落回充值订单过期。
                match expire_subscription_order(
                    &db,
                    &event.client_reference_id,
                    PROVIDER_STRIPE,
                    newapi_billing::topup::now_seconds(),
                )
                .await
                {
                    Ok(()) => {
                        tracing::info!(trade_no = %event.client_reference_id, "Stripe 订阅订单已过期");
                        None
                    }
                    Err(SubscriptionOrderError::NotFound) => {
                        match update_pending_top_up_status(
                            &db,
                            &event.client_reference_id,
                            PROVIDER_STRIPE,
                            STATUS_EXPIRED,
                        )
                        .await
                        {
                            Ok(()) => {
                                tracing::info!(trade_no = %event.client_reference_id, "Stripe 充值订单已过期");
                                None
                            }
                            Err(newapi_billing::topup::RechargeError::NotFound) => {
                                tracing::warn!(trade_no = %event.client_reference_id, "Stripe 充值订单不存在，无法标记过期");
                                None
                            }
                            Err(_) => None,
                        }
                    }
                    Err(_) => None,
                }
            }
        }
        _ => {
            tracing::info!(event_type = %event.event_type, "Stripe webhook 忽略事件");
            None
        }
    };
    if fulfill == Some(true)
        && let Err(_error) = stripe_fulfill_order(
            &db,
            &event,
            display.quota_per_unit,
            &event.event_type,
            &event.amount_total,
            &event.currency,
        )
        .await
    {
        tracing::error!(event_type = %event.event_type, "Stripe webhook 履约失败，返回 5xx 等待重试");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    StatusCode::OK.into_response()
}

/// `POST /api/creem/webhook` → Go `billing.CreemWebhook`。
pub async fn creem_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let settings = match TopUpSettings::load(&db).await {
        Ok(settings) => settings,
        Err(error) => {
            tracing::warn!(
                event = "creem_webhook_settings_load_failed",
                category = crate::database_error_class(&error),
                "creem webhook settings load failed"
            );
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    if !settings.is_creem_topup_enabled() || settings.creem_webhook_secret.trim().is_empty() {
        tracing::warn!(
            event = "creem_webhook_disabled",
            "Creem webhook 被拒绝 reason=webhook_disabled"
        );
        return StatusCode::FORBIDDEN.into_response();
    }
    let signature = headers
        .get("creem-signature")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if signature.is_empty() {
        tracing::warn!(
            event = "creem_webhook_missing_signature",
            "Creem webhook 缺少签名"
        );
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if !verify_creem_signature(&body, signature, &settings.creem_webhook_secret) {
        tracing::warn!(
            event = "creem_webhook_verify_failed",
            "Creem webhook 验签失败"
        );
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let event: Value = match serde_json::from_slice(&body) {
        Ok(event) => event,
        Err(_) => {
            tracing::warn!(
                event = "creem_webhook_parse_failed",
                "Creem webhook 解析失败"
            );
            return StatusCode::BAD_REQUEST.into_response();
        }
    };
    let event_type = event
        .get("eventType")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    if event_type != "checkout.completed" {
        tracing::info!(event_type = %event_type, "Creem webhook 忽略事件");
        return StatusCode::OK.into_response();
    }
    let object = event.get("object").cloned().unwrap_or(Value::Null);
    let order = object.get("order").cloned().unwrap_or(Value::Null);
    let customer = object.get("customer").cloned().unwrap_or(Value::Null);
    let request_id = object
        .get("request_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let order_id = order
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let order_status = order
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    if order_status != "paid" {
        tracing::info!(request_id = %request_id, order_id = %order_id, "Creem 订单状态未支付，忽略处理");
        return StatusCode::OK.into_response();
    }
    if request_id.is_empty() {
        tracing::warn!(event_id = ?event.get("id"), order_id = %order_id, "Creem webhook 缺少 request_id");
        return StatusCode::BAD_REQUEST.into_response();
    }
    // Go：先试订阅订单核销（`topup_creem.go:322-331`）。NotFound 等价于订阅
    // 订单不存在 → 落回充值核销；其余错误 5xx（Creem 会重投）。
    match complete_subscription_order(
        &db,
        &request_id,
        &event.to_string(),
        PROVIDER_CREEM,
        "",
        newapi_billing::topup::now_seconds(),
    )
    .await
    {
        Ok(_) => {
            tracing::info!(
                trade_no = %request_id,
                creem_order_id = %order_id,
                "Creem 订阅订单处理成功"
            );
            return StatusCode::OK.into_response();
        }
        Err(SubscriptionOrderError::NotFound) => {}
        Err(_) => {
            tracing::error!(
                trade_no = %request_id,
                creem_order_id = %order_id,
                "Creem 订阅订单处理失败"
            );
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }
    // 订单类型门：只处理一次性付款（充值）。
    let order_type = order
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    if order_type != "onetime" {
        tracing::info!(request_id = %request_id, order_id = %order_id, order_type = %order_type, "Creem 暂不支持该订单类型，忽略处理");
        return StatusCode::OK.into_response();
    }
    let display = state.quota_display();
    // 本地订单存在性与状态门（Go `GetTopUpByTradeNo` + 非即失败）。
    // Go `GetTopUpByTradeNo`：查询错误折叠为 nil（订单不存在 → 400）。
    let existing = lookup_topup(&db, &request_id).await.unwrap_or(None);
    let Some(existing) = existing else {
        tracing::warn!(trade_no = %request_id, creem_order_id = %order_id, "Creem 充值订单不存在");
        return StatusCode::BAD_REQUEST.into_response();
    };
    if existing.status != STATUS_PENDING {
        tracing::info!(trade_no = %request_id, status = %existing.status, "Creem 充值订单状态非 pending，忽略处理");
        return StatusCode::OK.into_response();
    }
    let customer_email = customer
        .get("email")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let update = if customer_email.is_empty() {
        tracing::warn!(trade_no = %request_id, creem_order_id = %order_id, "Creem 回调客户邮箱为空");
        ExternalUserUpdate::None
    } else {
        ExternalUserUpdate::EmailIfEmpty(&customer_email)
    };
    match recharge_external_top_up(
        &db,
        ExternalRechargeParams {
            trade_no: &request_id,
            expected_provider: PROVIDER_CREEM,
            quota_source: ExternalQuotaSource::AmountRaw,
            quota_per_unit: display.quota_per_unit,
            computed_quota: 0,
            idempotent_success: false,
            user_update: update,
        },
    )
    .await
    {
        Ok(_) => {
            tracing::info!(trade_no = %request_id, creem_order_id = %order_id, "Creem 充值成功");
            StatusCode::OK.into_response()
        }
        Err(error) => {
            tracing::error!(trade_no = %request_id, creem_order_id = %order_id, "Creem 充值处理失败");
            let _ = error;
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Go `verifyCreemSignature`：HMAC-SHA256 十六进制串的常量时间比较；
/// secret 未配置时 test_mode 放行、否则拒绝。
fn verify_creem_signature(payload: &[u8], signature: &str, secret: &str) -> bool {
    if secret.is_empty() {
        return false;
    }
    use ring::hmac;
    let key = hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
    let expected = hex_encode(hmac::sign(&key, payload).as_ref());
    newapi_billing::topup::constant_time_eq(signature, &expected)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// 本地订单行快照（webhook 处理的读侧）。
struct TopupSnapshot {
    status: String,
}

async fn lookup_topup(
    db: &newapi_storage::Database,
    trade_no: &str,
) -> Result<Option<TopupSnapshot>, sqlx::Error> {
    let row: Option<(Option<String>,)> = match db {
        newapi_storage::Database::Sqlite(pool) => {
            sqlx::query_as("SELECT status FROM top_ups WHERE trade_no = $1")
                .bind(trade_no)
                .fetch_optional(pool)
                .await?
        }
        newapi_storage::Database::Postgres(pool) => {
            sqlx::query_as("SELECT status FROM top_ups WHERE trade_no = $1")
                .bind(trade_no)
                .fetch_optional(pool)
                .await?
        }
    };
    Ok(row.map(|(status,)| TopupSnapshot {
        status: status.unwrap_or_default(),
    }))
}

/// `POST /api/waffo/webhook` → Go `billing.WaffoWebhook`。
pub async fn waffo_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let settings = match TopUpSettings::load(&db).await {
        Ok(settings) => settings,
        Err(error) => {
            tracing::warn!(
                event = "waffo_webhook_settings_load_failed",
                category = crate::database_error_class(&error),
                "waffo webhook settings load failed"
            );
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    if !settings.is_waffo_topup_enabled() {
        tracing::warn!(
            event = "waffo_webhook_disabled",
            "Waffo webhook 被拒绝 reason=webhook_disabled"
        );
        return StatusCode::FORBIDDEN.into_response();
    }
    let creds = match waffo_creds(&settings) {
        Ok(creds) => creds,
        Err(()) => {
            tracing::error!(
                event = "waffo_webhook_sdk_init_failed",
                "Waffo webhook SDK 初始化失败"
            );
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let signature = headers
        .get("X-SIGNATURE")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !waffo_verify(&body, signature, &creds.public_cert) {
        tracing::warn!(
            event = "waffo_webhook_verify_failed",
            "Waffo webhook 验签失败"
        );
        return StatusCode::BAD_REQUEST.into_response();
    }
    let parsed: Value = match serde_json::from_slice(&body) {
        Ok(parsed) => parsed,
        Err(_) => {
            return waffo_signed_response(&creds, false, "invalid payload");
        }
    };
    let event_type = parsed
        .get("eventType")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    if event_type != "PAYMENT_NOTIFICATION" {
        tracing::info!(event_type = %event_type, "Waffo webhook 忽略事件");
        return waffo_signed_response(&creds, true, "");
    }
    let result = parsed.get("result").cloned().unwrap_or(Value::Null);
    let order_status = result
        .get("orderStatus")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let merchant_order_id = result
        .get("merchantOrderId")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    if order_status != "PAY_SUCCESS" {
        tracing::info!(trade_no = %merchant_order_id, order_status = %order_status, "Waffo 订单状态非成功，忽略充值");
        // 终态失败订单标记为 failed，避免永远停在 pending。
        if !merchant_order_id.is_empty()
            && let Err(error) =
                update_pending_top_up_status(&db, &merchant_order_id, PROVIDER_WAFFO, STATUS_FAILED)
                    .await
        {
            use newapi_billing::topup::RechargeError as Error;
            if !matches!(error, Error::NotFound | Error::StatusInvalid) {
                tracing::error!(trade_no = %merchant_order_id, "Waffo 标记失败订单状态失败");
            }
        }
        return waffo_signed_response(&creds, true, "");
    }
    match recharge_external_top_up(
        &db,
        ExternalRechargeParams {
            trade_no: &merchant_order_id,
            expected_provider: PROVIDER_WAFFO,
            quota_source: ExternalQuotaSource::AmountTimesUnit,
            quota_per_unit: waffo_quota_per_unit(&state),
            computed_quota: 0,
            idempotent_success: true,
            user_update: ExternalUserUpdate::None,
        },
    )
    .await
    {
        Ok(_) => {
            tracing::info!(trade_no = %merchant_order_id, "Waffo 充值成功");
            waffo_signed_response(&creds, true, "")
        }
        Err(error) => {
            tracing::error!(trade_no = %merchant_order_id, "Waffo 充值处理失败");
            waffo_signed_response(&creds, false, &waffo_error_text(&error))
        }
    }
}

/// Go：`RechargeWaffo` 失败统一折叠为「充值失败，请稍后重试」。
fn waffo_error_text(error: &newapi_billing::topup::RechargeError) -> String {
    let _ = error;
    "充值失败，请稍后重试".to_owned()
}

/// Go `sendWaffoWebhookResponse`：`X-SIGNATURE` + `{"message": ...}`，恒 200。
fn waffo_signed_response(creds: &WaffoCreds, success: bool, _message: &str) -> Response {
    let body = if success {
        json!({"message": "success"}).to_string()
    } else {
        json!({"message": "failed"}).to_string()
    };
    let signature = crate::pancake::parse_private_key(&creds.private_key)
        .and_then(|key| {
            crate::pancake::sign_pkcs1_sha256(&key, body.as_bytes()).map_err(|_| "sign".to_owned())
        })
        .unwrap_or_default();
    (
        StatusCode::OK,
        [
            (
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("application/json"),
            ),
            (
                axum::http::header::HeaderName::from_static("x-signature"),
                axum::http::HeaderValue::from_str(&signature)
                    .unwrap_or(axum::http::HeaderValue::from_static("")),
            ),
        ],
        body,
    )
        .into_response()
}

/// `POST /api/waffo-pancake/webhook/:env` → Go `billing.WaffoPancakeWebhook`。
pub async fn waffo_pancake_webhook(
    State(state): State<AppState>,
    Path(env): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let settings = match TopUpSettings::load(&db).await {
        Ok(settings) => settings,
        Err(error) => {
            tracing::warn!(
                event = "pancake_webhook_settings_load_failed",
                category = crate::database_error_class(&error),
                "pancake webhook settings load failed"
            );
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    if !settings.is_waffo_pancake_topup_enabled() {
        tracing::warn!(
            event = "pancake_webhook_disabled",
            "Waffo Pancake webhook 被拒绝 reason=webhook_disabled"
        );
        return text_response(StatusCode::FORBIDDEN, "webhook disabled");
    }
    let expected_env = env.trim();
    if expected_env != "test" && expected_env != "prod" {
        tracing::warn!(env = %expected_env, "Waffo Pancake webhook 路径环境段无效");
        return text_response(StatusCode::NOT_FOUND, "unknown env");
    }
    let signature = headers
        .get("X-Waffo-Signature")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let event = match verify_pancake_webhook(&body, signature) {
        Ok(event) => event,
        Err(error) => {
            tracing::warn!(env = %expected_env, error = %error, "Waffo Pancake webhook 验签失败");
            return text_response(StatusCode::UNAUTHORIZED, "invalid signature");
        }
    };
    if !event.mode.trim().eq_ignore_ascii_case(expected_env) {
        tracing::error!(
            expected = %expected_env,
            actual_mode = %event.mode,
            event_id = %event.event_id,
            "Waffo Pancake webhook 环境不匹配"
        );
        return text_response(StatusCode::OK, "OK");
    }
    if event.event_type != "order.completed" {
        tracing::info!(event_type = %event.event_type, "Waffo Pancake webhook 忽略事件");
        return text_response(StatusCode::OK, "OK");
    }
    let raw_trade_no = event.order_merchant_external_id.trim().to_owned();
    if raw_trade_no.starts_with("WAFFO_PANCAKE_SUB-") {
        // Go：按订阅订单解析（店铺绑定 + 归属 + 买家身份 + 金额），核销订阅
        // 订单（`topup_waffo_pancake.go:482-506`）。
        let trade_no = match resolve_pancake_subscription_trade_no(&db, &event, &settings).await {
            Ok(trade_no) => trade_no,
            Err(error) => {
                tracing::error!(
                    event_id = %event.event_id,
                    order_id = %event.order_id,
                    buyer_identity = %event.merchant_provided_buyer_identity,
                    error = %error,
                    "Waffo Pancake webhook 订阅订单解析失败"
                );
                return text_response(StatusCode::OK, "OK");
            }
        };
        return match complete_subscription_order(
            &db,
            &trade_no,
            &String::from_utf8_lossy(&body),
            PROVIDER_WAFFO_PANCAKE,
            "",
            newapi_billing::topup::now_seconds(),
        )
        .await
        {
            Ok(_) => {
                tracing::info!(
                    trade_no = %trade_no,
                    event_id = %event.event_id,
                    order_id = %event.order_id,
                    "Waffo Pancake 订阅完成"
                );
                text_response(StatusCode::OK, "OK")
            }
            Err(_) => {
                tracing::error!(
                    trade_no = %trade_no,
                    event_id = %event.event_id,
                    order_id = %event.order_id,
                    "Waffo Pancake 订阅完成失败"
                );
                text_response(StatusCode::INTERNAL_SERVER_ERROR, "retry")
            }
        };
    }
    let trade_no = match resolve_pancake_trade_no(&db, &event, &settings).await {
        Ok(trade_no) => trade_no,
        Err(error) => {
            tracing::error!(
                event_id = %event.event_id,
                order_id = %event.order_id,
                buyer_identity = %event.merchant_provided_buyer_identity,
                error = %error,
                "Waffo Pancake webhook 订单解析失败"
            );
            return text_response(StatusCode::OK, "OK");
        }
    };
    match recharge_external_top_up(
        &db,
        ExternalRechargeParams {
            trade_no: &trade_no,
            expected_provider: PROVIDER_WAFFO_PANCAKE,
            quota_source: ExternalQuotaSource::AmountTimesUnit,
            quota_per_unit: waffo_quota_per_unit(&state),
            computed_quota: 0,
            idempotent_success: true,
            user_update: ExternalUserUpdate::None,
        },
    )
    .await
    {
        Ok(_) => {
            tracing::info!(trade_no = %trade_no, event_id = %event.event_id, "Waffo Pancake 充值成功");
            text_response(StatusCode::OK, "OK")
        }
        Err(_) => {
            tracing::error!(trade_no = %trade_no, event_id = %event.event_id, "Waffo Pancake 充值处理失败");
            text_response(StatusCode::INTERNAL_SERVER_ERROR, "retry")
        }
    }
}

/// Pancake webhook 事件（仅本切片使用的字段）。
struct PancakeWebhookEvent {
    event_type: String,
    event_id: String,
    mode: String,
    order_id: String,
    store_id: String,
    order_merchant_external_id: String,
    merchant_provided_buyer_identity: String,
    amount: String,
    currency: String,
}

/// Go `VerifyConfiguredWaffoPancakeWebhook`（`t=,v1=` 签名头 + 内置双钥
/// 自动探测 + 5 分钟毫秒容差）。
fn verify_pancake_webhook(
    payload: &[u8],
    signature_header: &str,
) -> Result<PancakeWebhookEvent, String> {
    if signature_header.is_empty() {
        return Err("missing X-Waffo-Signature header".to_owned());
    }
    let mut timestamp = String::new();
    let mut signature = String::new();
    for pair in signature_header.split(',') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        match key.trim() {
            "t" => timestamp = value.trim().to_owned(),
            "v1" => signature = value.trim().to_owned(),
            _ => {}
        }
    }
    if timestamp.is_empty() || signature.is_empty() {
        return Err("malformed X-Waffo-Signature header: missing t or v1".to_owned());
    }
    let Ok(sent_at) = timestamp.parse::<i64>() else {
        return Err("invalid timestamp in X-Waffo-Signature header".to_owned());
    };
    let now_ms = now_millis() as i64;
    if (now_ms - sent_at).abs() > PANCAKE_WEBHOOK_TOLERANCE_MS {
        return Err(
            "webhook timestamp outside tolerance window (possible replay attack)".to_owned(),
        );
    }
    let signature_input = format!("{timestamp}.{}", String::from_utf8_lossy(payload));
    let prod_key =
        pancake_webhook_key("prod").map_err(|_| "resolve webhook public key (prod)".to_owned())?;
    if !pancake_verify(&signature_input, &signature, &prod_key) {
        let test_key = pancake_webhook_key("test")
            .map_err(|_| "resolve webhook public key (test)".to_owned())?;
        if !pancake_verify(&signature_input, &signature, &test_key) {
            return Err("invalid webhook signature (tried both prod and test keys)".to_owned());
        }
    }
    let parsed: Value = serde_json::from_slice(payload)
        .map_err(|error| format!("decode webhook event: {error}"))?;
    let data = parsed.get("data").cloned().unwrap_or(Value::Null);
    Ok(PancakeWebhookEvent {
        event_type: parsed
            .get("eventType")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        event_id: parsed
            .get("eventId")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        mode: parsed
            .get("mode")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        order_id: data
            .get("orderId")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        store_id: parsed
            .get("storeId")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        order_merchant_external_id: data
            .get("orderMerchantExternalId")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        merchant_provided_buyer_identity: data
            .get("merchantProvidedBuyerIdentity")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        amount: data
            .get("amount")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        currency: data
            .get("currency")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
    })
}

/// Go `ResolveWaffoPancakeSubscriptionTradeNo`（`call_waffo_pancake.go:285-314`）：
/// 店铺绑定 + 订阅订单归属 + 买家身份 + 金额/币种校验。
async fn resolve_pancake_subscription_trade_no(
    db: &newapi_storage::Database,
    event: &PancakeWebhookEvent,
    settings: &TopUpSettings,
) -> Result<String, String> {
    let trade_no = event.order_merchant_external_id.trim().to_owned();
    if trade_no.is_empty() {
        return Err("missing webhook orderMerchantExternalId".to_owned());
    }
    let expected_store = settings.waffo_pancake_store_id.trim().to_owned();
    if !expected_store.is_empty() && event.store_id.trim() != expected_store {
        return Err(format!(
            "waffo pancake store mismatch for tradeNo={trade_no}: expected={expected_store:?} actual={:?}",
            event.store_id.trim()
        ));
    }
    let Some(order) = get_subscription_order_by_trade_no(db, &trade_no).await else {
        return Err(format!(
            "waffo pancake subscription order not found for tradeNo={trade_no}"
        ));
    };
    if order.payment_provider != PROVIDER_WAFFO_PANCAKE {
        return Err(format!(
            "waffo pancake subscription order not found for tradeNo={trade_no}"
        ));
    }
    let expected_identity = pancake_buyer_identity(order.user_id);
    let actual_identity = event.merchant_provided_buyer_identity.trim().to_owned();
    if actual_identity != expected_identity {
        return Err(format!(
            "waffo pancake buyer identity mismatch for subscription tradeNo={trade_no}: expected={expected_identity:?} actual={actual_identity:?}"
        ));
    }
    let expected_amount = format_pancake_amount(order.money);
    let actual_amount = event.amount.trim().to_owned();
    if actual_amount.is_empty() {
        return Err(format!(
            "waffo pancake event missing amount for tradeNo={trade_no}"
        ));
    }
    if !decimal_eq(&expected_amount, &actual_amount) {
        return Err(format!(
            "waffo pancake amount mismatch for tradeNo={trade_no}: expected={expected_amount} actual={actual_amount} currency={:?}",
            event.currency
        ));
    }
    if !event.currency.trim().eq_ignore_ascii_case("USD") {
        return Err(format!(
            "waffo pancake currency mismatch for tradeNo={trade_no}: expected=USD actual={:?}",
            event.currency.trim()
        ));
    }
    Ok(trade_no)
}

/// Go `ResolveWaffoPancakeTradeNo`：店铺绑定 + 订单归属 + 买家身份 + 金额。
async fn resolve_pancake_trade_no(
    db: &newapi_storage::Database,
    event: &PancakeWebhookEvent,
    settings: &TopUpSettings,
) -> Result<String, String> {
    let trade_no = event.order_merchant_external_id.trim().to_owned();
    if trade_no.is_empty() {
        return Err("missing webhook orderMerchantExternalId".to_owned());
    }
    let expected_store = settings.waffo_pancake_store_id.trim().to_owned();
    if !expected_store.is_empty() && event.store_id.trim() != expected_store {
        return Err(format!(
            "waffo pancake store mismatch for tradeNo={trade_no}: expected={expected_store:?} actual={:?}",
            event.store_id.trim()
        ));
    }
    let Some(row) = lookup_pancake_topup(db, &trade_no)
        .await
        .map_err(|_| "waffo pancake order lookup failed".to_owned())?
    else {
        return Err(format!(
            "waffo pancake order not found for tradeNo={trade_no}"
        ));
    };
    let (user_id, money, provider) = row;
    if provider != PROVIDER_WAFFO_PANCAKE {
        return Err(format!(
            "waffo pancake order not found for tradeNo={trade_no}"
        ));
    }
    let expected_identity = pancake_buyer_identity(user_id);
    let actual_identity = event.merchant_provided_buyer_identity.trim().to_owned();
    if actual_identity != expected_identity {
        return Err(format!(
            "waffo pancake buyer identity mismatch for tradeNo={trade_no}: expected={expected_identity:?} actual={actual_identity:?}"
        ));
    }
    let expected_amount = format_pancake_amount(money);
    let actual_amount = event.amount.trim().to_owned();
    if actual_amount.is_empty() {
        return Err(format!(
            "waffo pancake event missing amount for tradeNo={trade_no}"
        ));
    }
    if !decimal_eq(&expected_amount, &actual_amount) {
        return Err(format!(
            "waffo pancake amount mismatch for tradeNo={trade_no}: expected={expected_amount} actual={actual_amount} currency={:?}",
            event.currency
        ));
    }
    if !event.currency.trim().eq_ignore_ascii_case("USD") {
        return Err(format!(
            "waffo pancake currency mismatch for tradeNo={trade_no}: expected=USD actual={:?}",
            event.currency.trim()
        ));
    }
    Ok(trade_no)
}

/// 订单行读取：`(user_id, money, payment_provider)`。
async fn lookup_pancake_topup(
    db: &newapi_storage::Database,
    trade_no: &str,
) -> Result<Option<(i64, f64, String)>, sqlx::Error> {
    let row: Option<(Option<i64>, Option<f64>, Option<String>)> = match db {
        newapi_storage::Database::Sqlite(pool) => {
            sqlx::query_as(
                "SELECT user_id, money, payment_provider FROM top_ups WHERE trade_no = $1",
            )
            .bind(trade_no)
            .fetch_optional(pool)
            .await?
        }
        newapi_storage::Database::Postgres(pool) => {
            sqlx::query_as(
                "SELECT user_id, money, payment_provider FROM top_ups WHERE trade_no = $1",
            )
            .bind(trade_no)
            .fetch_optional(pool)
            .await?
        }
    };
    Ok(row.map(|(user_id, money, provider)| {
        (
            user_id.unwrap_or_default(),
            money.unwrap_or_default(),
            provider.unwrap_or_default(),
        )
    }))
}

// ---------------------------------------------------------------------------
// Waffo 支付方式解析（Go `GetWaffoPayMethods`）
// ---------------------------------------------------------------------------

/// Go `QuotaPerUnit` 默认值（`common/constants.go:23`，$0.002 / 1K tokens）。
pub(crate) const GO_QUOTA_PER_UNIT: f64 = 500_000.0;

/// 回调核销用的 QuotaPerUnit：QuotaPerUnit option 的运行时值（quota_display
/// 快照携带），0/非法回落 Go 常量。
fn waffo_quota_per_unit(state: &AppState) -> f64 {
    let qpu = state.quota_display().quota_per_unit;
    if qpu > 0.0 { qpu } else { GO_QUOTA_PER_UNIT }
}

trait WaffoMethodsExt {
    fn parse_waffo_methods(&self) -> Vec<newapi_billing::topup::WaffoPayMethod>;
}

impl WaffoMethodsExt for String {
    fn parse_waffo_methods(&self) -> Vec<newapi_billing::topup::WaffoPayMethod> {
        if self.trim().is_empty() {
            return Vec::new();
        }
        serde_json::from_str::<Option<Vec<newapi_billing::topup::WaffoPayMethod>>>(self)
            .ok()
            .flatten()
            .unwrap_or_default()
    }
}
