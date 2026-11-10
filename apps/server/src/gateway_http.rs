//! 支付发起与网关回调 HTTP 适配器：
//! `POST /api/user/{pay,vmq/pay,codepay/pay,topup}`、
//! `GET|POST /api/user/{epay,vmq,codepay}/notify`、
//! `POST /api/user/topup/complete`（管理员补单）。
//!
//! Go references:
//! - `apps/api/internal/billing/topup_api.go`（`RequestEpay`、`RequestVmqPay`、
//!   `RequestCodePayPay`、`EpayNotify`、`VmqNotify`、`CodePayNotify`、
//!   `AdminCompleteTopUp`、`getPayMoney`、`getMinTopup`）
//! - `apps/api/internal/identity/manage_users.go`（`TopUp`：兑换码核销入口）
//! - `apps/api/internal/transport/compose/register_api.go:138-178,209`
//!   （路由与中间件：notify 三条挂在 `userRoute` 直下 **匿名可打**，仅带
//!   匿名体上限；pay/topup 在 `selfRoute`（UserAuth + CriticalRateLimit）；
//!   `topup/complete` 在 `adminRoute`（仅 AdminAuth））
//!
//! 回调端点恒返回 HTTP 200，响应体为字面 `"success"` / `"fail"`，由网关
//! 据此决定是否重投。所有业务失败分支与 Go 一致地返回 200 + "fail"。

use std::collections::BTreeMap;
use std::sync::LazyLock;

use axum::{
    Json,
    body::Bytes,
    extract::{Extension, Request, State},
    http::{HeaderMap, StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Response},
};
use newapi_billing::topup::{
    PayMethod, RechargeError, RechargeOutcome, RechargeParams, TopUpQuotaRejection, TopUpSettings,
    check_capacity, codepay_sign, constant_time_eq, epay_sign, gateway_pay_type_code, insert_topup,
    manual_complete_top_up, now_seconds, pay_money, random_string, recharge_top_up,
    record_topup_log, redeem, validate_top_up_quota, vmq_create_sign, vmq_notify_sign,
};
use newapi_identity::self_user::QuotaDisplayKind;
use newapi_identity::users::UserProfileRepository;
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::AuthenticatedUser;

/// Go `userRoute` 下的匿名回调端点：仅挂匿名请求体上限（读运行时配置）。
pub async fn notify_body_limit(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    crate::boundary_mw::anonymous_body_limit(state.anonymous_body_limit(), request, next).await
}

// ---- 充值入口与兑换的进程内互斥（Go `LockOrder` / `getTopUpLock`）--------
//
// Go 自己注明进程内锁只是优化，正确性由数据库 CAS 保证；这里保留
// user-topup 的 TryLock 语义（用户级并发兑换返回「处理中」），订单级锁由
// 事务内条件 UPDATE 承担（见 `gateway.rs` 模块注释）。

static TOPUP_USER_LOCKS: LazyLock<tokio::sync::Mutex<std::collections::HashSet<i64>>> =
    LazyLock::new(|| tokio::sync::Mutex::new(std::collections::HashSet::new()));

// ---- 错误文案（Go 硬编码中文字面量，前端逐字比对） ------------------------

const MSG_BAD_REQUEST: &str = "参数错误";
const MSG_GROUP_FAILED: &str = "获取用户分组失败";
const MSG_AMOUNT_TOO_SMALL: &str = "充值金额过低";
const MSG_PAY_CONFIG_MISSING: &str = "当前管理员未配置支付信息";
const MSG_PAY_METHOD_MISSING: &str = "支付方式不存在";
const MSG_PAY_METHOD_UNSUPPORTED: &str = "不支持的支付方式";
const MSG_LAUNCH_FAILED: &str = "拉起支付失败";
const MSG_ORDER_CREATE_FAILED: &str = "创建订单失败";
const MSG_BAD_TRADE_NO: &str = "参数错误";

fn msg_below_minimum(minimum: i64) -> String {
    format!("充值数量不能小于 {minimum}")
}

/// Go `common.H{"message": "error", "data": ...}`（HTTP 200）。
fn pay_error(message: String) -> Response {
    Json(json!({"message": "error", "data": message})).into_response()
}

fn pay_error_static(message: &str) -> Response {
    pay_error(message.to_owned())
}

fn text_body(body: &str) -> Response {
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        body.to_owned(),
    )
        .into_response()
}

/// Go `url.QueryEscape`：字母数字与 `-_.~` 保留，空格 → `+`，其余按 UTF-8
/// 百分号转义（大写十六进制）。
fn query_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// 表单/查询串解析（`+` 为空格、`%XX` 转义），重复键取首现值（Go
/// `PostForm(t)` / `Query(t)` 的取值语义）。
fn parse_urlencoded(input: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for pair in input.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode(key);
        if !map.contains_key(&key) {
            map.insert(key, percent_decode(value));
        }
    }
    map
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

/// Go `EpayRequest` / `AmountRequest` 的绑定：非 JSON 或空体绑定零值。
#[derive(Default)]
struct PayRequest {
    amount: i64,
    payment_method: String,
}

fn bind_pay_request(headers: &HeaderMap, body: &[u8]) -> Result<PayRequest, ()> {
    if !parses_as_json(headers) || body.is_empty() {
        return Ok(PayRequest::default());
    }
    let parsed: Value = serde_json::from_slice(body).map_err(|_| ())?;
    let Some(object) = parsed.as_object() else {
        return Ok(PayRequest::default());
    };
    let mut request = PayRequest::default();
    match object.get("amount") {
        None | Some(Value::Null) => {}
        Some(value) => request.amount = value.as_i64().ok_or(())?,
    }
    match object.get("payment_method") {
        None | Some(Value::Null) => {}
        Some(value) => request.payment_method = value.as_str().ok_or(())?.to_owned(),
    }
    Ok(request)
}

fn parses_as_json(headers: &HeaderMap) -> bool {
    match headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    {
        None | Some("") => true,
        Some(value) => value
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .eq_ignore_ascii_case("application/json"),
    }
}

/// Go `GetCallbackAddress` + `PaymentReturnURL`：回调地址可被
/// `CustomCallbackAddress` 覆盖，回跳地址始终基于 `ServerAddress`。
struct CallbackAddresses {
    callback: String,
    server: String,
}

async fn callback_addresses(db: &newapi_storage::Database) -> CallbackAddresses {
    const DEFAULT_SERVER: &str = "http://localhost:3000";
    let rows: Vec<(String, Option<String>)> = match db {
        newapi_storage::Database::Sqlite(pool) => {
            sqlx::query_as(r#"SELECT "key", "value" FROM options WHERE "key" IN ($1, $2)"#)
                .bind("ServerAddress")
                .bind("CustomCallbackAddress")
                .fetch_all(pool)
                .await
        }
        newapi_storage::Database::Postgres(pool) => {
            sqlx::query_as(r#"SELECT "key", "value" FROM options WHERE "key" IN ($1, $2)"#)
                .bind("ServerAddress")
                .bind("CustomCallbackAddress")
                .fetch_all(pool)
                .await
        }
    }
    .unwrap_or_default();
    let mut server = DEFAULT_SERVER.to_owned();
    let mut custom = String::new();
    for (key, value) in rows {
        match key.as_str() {
            "ServerAddress" => {
                if let Some(value) = value
                    && !value.is_empty()
                {
                    server = value;
                }
            }
            "CustomCallbackAddress" => custom = value.unwrap_or_default(),
            _ => {}
        }
    }
    CallbackAddresses {
        callback: if custom.is_empty() {
            server.clone()
        } else {
            custom
        },
        server,
    }
}

/// Go `paymentReturnPath(suffix)`：`TrimRight(ServerAddress, "/") + suffix`。
fn payment_return_path(server: &str, suffix: &str) -> String {
    format!("{}{suffix}", server.trim_end_matches('/'))
}

/// Go `findPayMethod(methodType, gateway)`：`type` 与网关同时匹配。
fn find_pay_method<'a>(
    settings: &'a TopUpSettings,
    method_type: &str,
    gateway: &str,
) -> Option<&'a PayMethod> {
    settings.pay_methods.as_deref()?.iter().find(|method| {
        method.get("type").map(String::as_str) == Some(method_type) && gateway_of(method) == gateway
    })
}

/// Go `payMethodGateway`：缺失/空网关按 Epay。
fn gateway_of(method: &PayMethod) -> &'static str {
    match method.get("gateway").map(String::as_str) {
        Some("vmq") => "vmq",
        Some("codepay") => "codepay",
        _ => "epay",
    }
}

/// Go `getMinTopup`：TOKENS 展示下按 `QuotaPerUnit` 放大（与 amount_http
/// 同一换算口径）。
fn min_topup(settings: &TopUpSettings, tokens: bool, quota_per_unit: f64) -> i64 {
    let minimum = settings.min_topup;
    if tokens {
        (i128::from(minimum) * i128::from(quota_per_unit as i64)) as i64
    } else {
        minimum
    }
}

/// Go `RequestEpay` 等三个入口的公共前置：最小值、额度、分组、金额。
/// 返回 `(pay_money, profile)` 或已写好的错误响应。
struct PayContext {
    pay_money: f64,
    profile: newapi_identity::users::UserProfile,
}

async fn pay_context(
    state: &AppState,
    db: &newapi_storage::Database,
    user_id: i64,
    request: &PayRequest,
) -> Result<PayContext, Response> {
    let settings = match TopUpSettings::load(db).await {
        Ok(settings) => settings,
        Err(error) => {
            tracing::warn!(
                event = "pay_settings_load_failed",
                category = crate::database_error_class(&error),
                "pay settings load failed"
            );
            return Err(pay_error_static(MSG_BAD_REQUEST));
        }
    };
    let display = state.quota_display();
    let tokens = display.kind == QuotaDisplayKind::Tokens;
    let quota_per_unit = display.quota_per_unit;

    let minimum = min_topup(&settings, tokens, quota_per_unit);
    if request.amount < minimum {
        return Err(pay_error(msg_below_minimum(minimum)));
    }
    // Go `rejectInvalidTopUpQuota`：额度换算 + 钱包容量预检。
    let credited = match validate_top_up_quota(&settings, request.amount, tokens, quota_per_unit) {
        Ok(credited) => credited,
        Err(TopUpQuotaRejection::ExceedsMax(max)) => {
            return Err(pay_error(format!("单笔充值数量不能大于 {max}")));
        }
        Err(TopUpQuotaRejection::InvalidQuota) => {
            return Err(pay_error_static("充值数量无效"));
        }
    };
    let profile = match UserProfileRepository::new(db.clone()).by_id(user_id).await {
        Ok(Some(profile)) => profile,
        Ok(None) => return Err(pay_error_static(MSG_GROUP_FAILED)),
        Err(error) => {
            tracing::warn!(
                event = "pay_user_lookup_failed",
                category = crate::database_error_class(&error),
                "pay user lookup failed"
            );
            return Err(pay_error_static(MSG_GROUP_FAILED));
        }
    };
    if let Err(rejection) = check_capacity(credited, profile.quota) {
        return Err(pay_error_static(rejection.message()));
    }
    let money = pay_money(
        &settings,
        request.amount,
        &profile.group,
        tokens,
        quota_per_unit,
    );
    if money < 0.01 {
        return Err(pay_error_static(MSG_AMOUNT_TOO_SMALL));
    }
    Ok(PayContext {
        pay_money: money,
        profile,
    })
}

/// Go 侧 TOKENS 展示下的订单金额归一化：`amount / QuotaPerUnit` 截断。
fn normalized_amount(request_amount: i64, tokens: bool, quota_per_unit: f64) -> i64 {
    if tokens {
        let units = (request_amount as f64 / quota_per_unit).trunc();
        if units < 1.0 { 1 } else { units as i64 }
    } else {
        request_amount
    }
}

/// `POST /api/user/pay` → Go `billing.RequestEpay`。
pub async fn request_epay(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(request) = bind_pay_request(&headers, &body) else {
        return pay_error_static(MSG_BAD_REQUEST);
    };
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    // Go：先查最小值再查 client 是否配置（顺序无观察差异），此处按 Go 顺序。
    let context = match pay_context(&state, &db, auth_user.0.user_id, &request).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let settings = match TopUpSettings::load(&db).await {
        Ok(settings) => settings,
        Err(error) => {
            tracing::warn!(
                event = "pay_settings_load_failed",
                category = crate::database_error_class(&error),
                "pay settings load failed"
            );
            return pay_error_static(MSG_BAD_REQUEST);
        }
    };
    if settings.pay_address.is_empty()
        || settings.epay_id.is_empty()
        || settings.epay_key.is_empty()
    {
        return pay_error_static(MSG_PAY_CONFIG_MISSING);
    }
    if find_pay_method(&settings, &request.payment_method, "epay").is_none() {
        return pay_error_static(MSG_PAY_METHOD_MISSING);
    }
    let addresses = callback_addresses(&db).await;
    let trade_no = format!(
        "USR{}NO{}{}",
        auth_user.0.user_id,
        random_string(6),
        now_seconds()
    );
    let display = state.quota_display();
    let notify_url = format!("{}/api/user/epay/notify", addresses.callback);
    let return_url = payment_return_path(&addresses.server, "/usage-logs");

    // go-epay `Purchase`：参数加签 + `/submit.php` 跳转地址。
    let money_str = format!("{:.2}", context.pay_money);
    let mut params: BTreeMap<String, String> = BTreeMap::new();
    params.insert("pid".to_owned(), settings.epay_id.clone());
    params.insert("type".to_owned(), request.payment_method.clone());
    params.insert("out_trade_no".to_owned(), trade_no.clone());
    params.insert("notify_url".to_owned(), notify_url);
    params.insert("name".to_owned(), format!("TUC{}", request.amount));
    params.insert("money".to_owned(), money_str);
    params.insert("device".to_owned(), "pc".to_owned());
    params.insert("return_url".to_owned(), return_url);
    let sign = epay_sign(&params, &settings.epay_key);
    params.insert("sign".to_owned(), sign);
    params.insert("sign_type".to_owned(), "MD5".to_owned());
    let uri = format!("{}/submit.php", settings.pay_address.trim_end_matches('/'));

    let amount = normalized_amount(
        request.amount,
        display.kind == QuotaDisplayKind::Tokens,
        display.quota_per_unit,
    );
    if let Err(error) = insert_topup(
        &db,
        auth_user.0.user_id,
        amount,
        context.pay_money,
        &trade_no,
        &request.payment_method,
        "epay",
    )
    .await
    {
        tracing::warn!(
            event = "epay_order_create_failed",
            category = crate::database_error_class(&error),
            trade_no = %trade_no,
            "epay order create failed"
        );
        return pay_error_static(MSG_ORDER_CREATE_FAILED);
    }
    tracing::info!(event = "epay_order_created", trade_no = %trade_no, "epay order created");
    Json(json!({"message": "success", "data": params, "url": uri})).into_response()
}

/// Go `RequestVmqPay` / `RequestCodePayPay` 入口的合规与凭证门。
fn gateway_entry_gate(settings: &TopUpSettings, gateway: &str) -> Result<(), Response> {
    let compliant = settings.payment_compliance_confirmed();
    let configured = match gateway {
        "vmq" => !settings.vmq_address.trim().is_empty() && !settings.vmq_key.trim().is_empty(),
        "codepay" => {
            !settings.codepay_address.trim().is_empty()
                && !settings.codepay_id.trim().is_empty()
                && !settings.codepay_key.trim().is_empty()
        }
        _ => false,
    };
    if !compliant || !configured {
        return Err(pay_error_static(MSG_PAY_CONFIG_MISSING));
    }
    Ok(())
}

/// Go `findPayMethod` + `gatewayPayTypeCode`（金额校验之后调用）。
fn resolve_pay_type(
    settings: &TopUpSettings,
    gateway: &str,
    request_method: &str,
) -> Result<&'static str, Response> {
    let Some(method) = find_pay_method(settings, request_method, gateway) else {
        return Err(pay_error_static(MSG_PAY_METHOD_MISSING));
    };
    let method_type = method.get("type").cloned().unwrap_or_default();
    gateway_pay_type_code(gateway, &method_type)
        .ok_or_else(|| pay_error_static(MSG_PAY_METHOD_UNSUPPORTED))
}

/// `POST /api/user/vmq/pay` → Go `billing.RequestVmqPay`。
pub async fn request_vmq_pay(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(request) = bind_pay_request(&headers, &body) else {
        return pay_error_static(MSG_BAD_REQUEST);
    };
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let settings = match TopUpSettings::load(&db).await {
        Ok(settings) => settings,
        Err(error) => {
            tracing::warn!(
                event = "pay_settings_load_failed",
                category = crate::database_error_class(&error),
                "pay settings load failed"
            );
            return pay_error_static(MSG_BAD_REQUEST);
        }
    };
    if let Err(response) = gateway_entry_gate(&settings, "vmq") {
        return response;
    }
    let context = match pay_context(&state, &db, auth_user.0.user_id, &request).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let type_code = match resolve_pay_type(&settings, "vmq", &request.payment_method) {
        Ok(type_code) => type_code,
        Err(response) => return response,
    };
    let addresses = callback_addresses(&db).await;
    let trade_no = format!(
        "VMQUSR{}NO{}{}",
        auth_user.0.user_id,
        random_string(6),
        now_seconds()
    );
    let display = state.quota_display();
    let notify_url = format!("{}/api/user/vmq/notify", addresses.callback);
    let return_url = payment_return_path(&addresses.server, "/usage-logs");
    let price_str = format!("{:.2}", context.pay_money);
    let sign = vmq_create_sign(&trade_no, "topup", type_code, &price_str, &settings.vmq_key);
    let vmq_url = format!(
        "{}/createOrder?payId={}&param={}&type={}&price={}&notifyUrl={}&returnUrl={}&sign={}&isHtml=1",
        settings.vmq_address.trim_end_matches('/'),
        query_escape(&trade_no),
        query_escape("topup"),
        query_escape(type_code),
        query_escape(&price_str),
        query_escape(&notify_url),
        query_escape(&return_url),
        query_escape(&sign),
    );
    let amount = normalized_amount(
        request.amount,
        display.kind == QuotaDisplayKind::Tokens,
        display.quota_per_unit,
    );
    if let Err(error) = insert_topup(
        &db,
        auth_user.0.user_id,
        amount,
        context.pay_money,
        &trade_no,
        &request.payment_method,
        "vmq",
    )
    .await
    {
        tracing::warn!(
            event = "vmq_order_create_failed",
            category = crate::database_error_class(&error),
            trade_no = %trade_no,
            "vmq order create failed"
        );
        return pay_error_static(MSG_ORDER_CREATE_FAILED);
    }
    tracing::info!(event = "vmq_order_created", trade_no = %trade_no, "vmq order created");
    Json(json!({
        "message": "success",
        "data": {"trade_no": trade_no},
        "url": vmq_url,
    }))
    .into_response()
}

/// `POST /api/user/codepay/pay` → Go `billing.RequestCodePayPay`。
pub async fn request_codepay_pay(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(request) = bind_pay_request(&headers, &body) else {
        return pay_error_static(MSG_BAD_REQUEST);
    };
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let settings = match TopUpSettings::load(&db).await {
        Ok(settings) => settings,
        Err(error) => {
            tracing::warn!(
                event = "pay_settings_load_failed",
                category = crate::database_error_class(&error),
                "pay settings load failed"
            );
            return pay_error_static(MSG_BAD_REQUEST);
        }
    };
    if let Err(response) = gateway_entry_gate(&settings, "codepay") {
        return response;
    }
    let context = match pay_context(&state, &db, auth_user.0.user_id, &request).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let type_code = match resolve_pay_type(&settings, "codepay", &request.payment_method) {
        Ok(type_code) => type_code,
        Err(response) => return response,
    };
    let addresses = callback_addresses(&db).await;
    let trade_no = format!(
        "CPUSR{}NO{}{}",
        auth_user.0.user_id,
        random_string(6),
        now_seconds()
    );
    let display = state.quota_display();
    let notify_url = format!("{}/api/user/codepay/notify", addresses.callback);
    let return_url = payment_return_path(&addresses.server, "/usage-logs");
    let price_str = format!("{:.2}", context.pay_money);

    let mut cp_params: BTreeMap<String, String> = BTreeMap::new();
    cp_params.insert("id".to_owned(), settings.codepay_id.clone());
    cp_params.insert("type".to_owned(), type_code.to_owned());
    cp_params.insert("price".to_owned(), price_str);
    cp_params.insert("pay_id".to_owned(), trade_no.clone());
    cp_params.insert("param".to_owned(), "topup".to_owned());
    cp_params.insert("notify_url".to_owned(), notify_url);
    cp_params.insert("return_url".to_owned(), return_url);
    let sign = codepay_sign(&cp_params, &settings.codepay_key);
    // Go：key 升序拼 query（不含 sign），sign 恒排在最后。
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

    let amount = normalized_amount(
        request.amount,
        display.kind == QuotaDisplayKind::Tokens,
        display.quota_per_unit,
    );
    if let Err(error) = insert_topup(
        &db,
        auth_user.0.user_id,
        amount,
        context.pay_money,
        &trade_no,
        &request.payment_method,
        "codepay",
    )
    .await
    {
        tracing::warn!(
            event = "codepay_order_create_failed",
            category = crate::database_error_class(&error),
            trade_no = %trade_no,
            "codepay order create failed"
        );
        return pay_error_static(MSG_ORDER_CREATE_FAILED);
    }
    tracing::info!(event = "codepay_order_created", trade_no = %trade_no, "codepay order created");
    Json(json!({
        "message": "success",
        "data": {"trade_no": trade_no},
        "url": codepay_url,
    }))
    .into_response()
}

// ---- 回调端点 -------------------------------------------------------------

/// 回调参数：POST 只取 form 体（Go `PostFormValues`，form 解析失败视为空 →
/// "fail"），GET 只取 query（Go `QueryValues`）。
fn notify_params(is_post: bool, uri: &Uri, body: &Bytes) -> Result<BTreeMap<String, String>, ()> {
    if is_post {
        let raw = std::str::from_utf8(body.as_ref()).map_err(|_| ())?;
        Ok(parse_urlencoded(raw))
    } else {
        Ok(query_pairs_map(uri.query().unwrap_or_default()))
    }
}

/// `GET|POST /api/user/epay/notify` → Go `billing.EpayNotify`。
pub async fn epay_notify(
    State(state): State<AppState>,
    method: axum::http::Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let _ = notify_params;
    let Some(db) = state.db() else {
        return text_body("fail");
    };
    let settings = match TopUpSettings::load(&db).await {
        Ok(settings) => settings,
        Err(error) => {
            tracing::warn!(
                event = "epay_notify_settings_load_failed",
                category = crate::database_error_class(&error),
                "epay notify settings load failed"
            );
            return text_body("fail");
        }
    };
    // Go `isEpayWebhookEnabled` = `isEpayTopUpEnabled`（合规 + 凭证 + 方式>0）。
    if !settings.is_epay_topup_enabled() {
        tracing::warn!(
            event = "epay_webhook_disabled",
            "epay webhook rejected: disabled"
        );
        return text_body("fail");
    }
    let params = match notify_params(method == axum::http::Method::POST, &uri, &body) {
        Ok(params) => params,
        Err(()) => {
            tracing::warn!(
                event = "epay_notify_form_parse_failed",
                "epay notify form parse failed"
            );
            return text_body("fail");
        }
    };
    if params.is_empty() {
        return text_body("fail");
    }
    let sign = params.get("sign").cloned().unwrap_or_default();
    let expected = epay_sign(&params, &settings.epay_key);
    // go-epay `Verify`：普通相等（与 Go 逐字一致，非定时安全）。
    if sign != expected {
        tracing::warn!(
            event = "epay_notify_verify_failed",
            "epay notify verify failed"
        );
        return text_body("fail");
    }
    let trade_no = params.get("out_trade_no").cloned().unwrap_or_default();
    if trade_no.is_empty() {
        return text_body("fail");
    }
    let trade_status = params.get("trade_status").cloned().unwrap_or_default();
    if trade_status != "TRADE_SUCCESS" {
        tracing::info!(event = "epay_notify_ignored", trade_status = %trade_status, "epay notify ignored");
        return text_body("success");
    }
    let display = state.quota_display();
    let outcome = recharge_top_up(
        &db,
        RechargeParams {
            trade_no: &trade_no,
            expected_provider: "epay",
            actual_payment_method: params.get("type").map(String::as_str),
            notify_price: None,
            paid_amount: None,
            paid_tolerance_cents: 0,
            quota_per_unit: display.quota_per_unit,
        },
    )
    .await;
    match outcome {
        Ok(outcome) => {
            if let RechargeOutcome::Completed(record) = &outcome {
                record_topup_log(
                    &db,
                    record.user_id,
                    &format!(
                        "使用在线充值成功，充值金额: {}，支付金额：{:.6}",
                        display.to_display(record.quota_added),
                        record.money
                    ),
                    "",
                    &record.payment_method,
                    "epay",
                )
                .await;
            }
            text_body("success")
        }
        Err(error) => {
            log_recharge_failure("epay", &trade_no, &error);
            text_body("fail")
        }
    }
}

fn query_pairs_map(query: &str) -> BTreeMap<String, String> {
    parse_urlencoded(query)
}

/// `GET|POST /api/user/vmq/notify` → Go `billing.VmqNotify`。
pub async fn vmq_notify(
    State(state): State<AppState>,
    method: axum::http::Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(db) = state.db() else {
        return text_body("fail");
    };
    let settings = match TopUpSettings::load(&db).await {
        Ok(settings) => settings,
        Err(error) => {
            tracing::warn!(
                event = "vmq_notify_settings_load_failed",
                category = crate::database_error_class(&error),
                "vmq notify settings load failed"
            );
            return text_body("fail");
        }
    };
    // Go `isVmqWebhookEnabled`：仅凭证门（不含合规与方式数）。
    if settings.vmq_address.trim().is_empty() || settings.vmq_key.trim().is_empty() {
        tracing::warn!(
            event = "vmq_webhook_disabled",
            "vmq webhook rejected: disabled"
        );
        return text_body("fail");
    }
    let params = match notify_params(method == axum::http::Method::POST, &uri, &body) {
        Ok(params) => params,
        Err(()) => {
            tracing::warn!(
                event = "vmq_notify_form_parse_failed",
                "vmq notify form parse failed"
            );
            return text_body("fail");
        }
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
        tracing::warn!(
            event = "vmq_notify_verify_failed",
            "vmq notify verify failed"
        );
        return text_body("fail");
    }
    let trade_no = params.get("payId").cloned().unwrap_or_default();
    if trade_no.is_empty() {
        return text_body("fail");
    }
    let display = state.quota_display();
    let outcome = recharge_top_up(
        &db,
        RechargeParams {
            trade_no: &trade_no,
            expected_provider: "vmq",
            actual_payment_method: None,
            notify_price: params.get("price").map(String::as_str),
            paid_amount: params.get("reallyPrice").map(String::as_str),
            paid_tolerance_cents: 10, // Go：0.10 元
            quota_per_unit: display.quota_per_unit,
        },
    )
    .await;
    match outcome {
        Ok(outcome) => {
            if let RechargeOutcome::Completed(record) = &outcome {
                record_topup_log(
                    &db,
                    record.user_id,
                    &format!(
                        "使用在线充值成功，充值金额: {}，支付金额：{:.6}",
                        display.to_display(record.quota_added),
                        record.money
                    ),
                    "",
                    &record.payment_method,
                    "vmq",
                )
                .await;
            }
            text_body("success")
        }
        Err(error) => {
            log_recharge_failure("vmq", &trade_no, &error);
            text_body("fail")
        }
    }
}

/// `GET|POST /api/user/codepay/notify` → Go `billing.CodePayNotify`。
pub async fn codepay_notify(
    State(state): State<AppState>,
    method: axum::http::Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(db) = state.db() else {
        return text_body("fail");
    };
    let settings = match TopUpSettings::load(&db).await {
        Ok(settings) => settings,
        Err(error) => {
            tracing::warn!(
                event = "codepay_notify_settings_load_failed",
                category = crate::database_error_class(&error),
                "codepay notify settings load failed"
            );
            return text_body("fail");
        }
    };
    // Go `isCodePayWebhookEnabled`：仅凭证门。
    if settings.codepay_address.trim().is_empty()
        || settings.codepay_id.trim().is_empty()
        || settings.codepay_key.trim().is_empty()
    {
        tracing::warn!(
            event = "codepay_webhook_disabled",
            "codepay webhook rejected: disabled"
        );
        return text_body("fail");
    }
    let params = match notify_params(method == axum::http::Method::POST, &uri, &body) {
        Ok(params) => params,
        Err(()) => {
            tracing::warn!(
                event = "codepay_notify_form_parse_failed",
                "codepay notify form parse failed"
            );
            return text_body("fail");
        }
    };
    if params.is_empty() {
        return text_body("fail");
    }
    if params
        .get("pay_no")
        .map(|value| value.trim().is_empty())
        .unwrap_or(true)
    {
        tracing::warn!(
            event = "codepay_notify_missing_pay_no",
            "codepay notify missing pay_no"
        );
        return text_body("fail");
    }
    let sign = params.get("sign").cloned().unwrap_or_default();
    let expected = codepay_sign(&params, &settings.codepay_key);
    if !constant_time_eq(&sign, &expected) {
        tracing::warn!(
            event = "codepay_notify_verify_failed",
            "codepay notify verify failed"
        );
        return text_body("fail");
    }
    let trade_no = params.get("pay_id").cloned().unwrap_or_default();
    if trade_no.is_empty() {
        return text_body("fail");
    }
    let display = state.quota_display();
    let outcome = recharge_top_up(
        &db,
        RechargeParams {
            trade_no: &trade_no,
            expected_provider: "codepay",
            actual_payment_method: None,
            notify_price: params.get("price").map(String::as_str),
            paid_amount: None,
            paid_tolerance_cents: 0,
            quota_per_unit: display.quota_per_unit,
        },
    )
    .await;
    match outcome {
        Ok(outcome) => {
            if let RechargeOutcome::Completed(record) = &outcome {
                record_topup_log(
                    &db,
                    record.user_id,
                    &format!(
                        "使用在线充值成功，充值金额: {}，支付金额：{:.6}",
                        display.to_display(record.quota_added),
                        record.money
                    ),
                    "",
                    &record.payment_method,
                    "codepay",
                )
                .await;
            }
            text_body("success")
        }
        Err(error) => {
            log_recharge_failure("codepay", &trade_no, &error);
            text_body("fail")
        }
    }
}

fn log_recharge_failure(
    gateway: &str,
    trade_no: &str,
    error: &newapi_billing::topup::RechargeError,
) {
    match error {
        newapi_billing::topup::RechargeError::NotFound => {
            tracing::warn!(event = "topup_order_missing", gateway = %gateway, trade_no = %trade_no, "topup order not found");
        }
        newapi_billing::topup::RechargeError::ProviderMismatch => {
            tracing::warn!(event = "topup_provider_mismatch", gateway = %gateway, trade_no = %trade_no, "topup provider mismatch");
        }
        newapi_billing::topup::RechargeError::StatusInvalid => {
            tracing::warn!(event = "topup_status_invalid", gateway = %gateway, trade_no = %trade_no, "topup status invalid");
        }
        newapi_billing::topup::RechargeError::AmountMismatch => {
            tracing::warn!(event = "topup_amount_mismatch", gateway = %gateway, trade_no = %trade_no, "topup amount mismatch");
        }
        newapi_billing::topup::RechargeError::InvalidQuota
        | newapi_billing::topup::RechargeError::UserMissing
        | newapi_billing::topup::RechargeError::QuotaLimitExceeded
        | newapi_billing::topup::RechargeError::Storage(_) => {
            tracing::error!(event = "topup_recharge_failed", gateway = %gateway, trade_no = %trade_no, "topup recharge failed");
        }
    }
}

// ---- 兑换与补单 -----------------------------------------------------------

/// `POST /api/user/topup` → Go `identity.TopUp`（兑换码核销）。
pub async fn topup_redeem(
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
        Err(error) => {
            tracing::warn!(
                event = "topup_redeem_settings_load_failed",
                category = crate::database_error_class(&error),
                "topup redeem settings load failed"
            );
            return api_i18n_error(&headers, "payment.compliance_required");
        }
    };
    if !settings.payment_compliance_confirmed() {
        return api_i18n_error(&headers, "payment.compliance_required");
    }
    let request: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(error) => {
            // Go `CtxApiError(c, err)`：绑定错误原文。
            return api_plain_error(&headers, &error.to_string());
        }
    };
    let key = request
        .get("key")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    // Go `getTopUpLock(id).TryLock()`：同一用户并发兑换直接拒绝。
    {
        let mut locks = TOPUP_USER_LOCKS.lock().await;
        if !locks.insert(auth_user.0.user_id) {
            return api_i18n_error(&headers, "user.topup_processing");
        }
    }
    let result = redeem(&db, &key, auth_user.0.user_id).await;
    {
        let mut locks = TOPUP_USER_LOCKS.lock().await;
        locks.remove(&auth_user.0.user_id);
    }
    match result {
        Ok(quota) => {
            let display = state.quota_display();
            Json(json!({
                "success": true,
                "message": "",
                "data": {
                    "quota": quota,
                    "quota_display": display.to_display(quota),
                },
            }))
            .into_response()
        }
        Err(_) => {
            // 不向用户暴露细分原因（反枚举），与 Go 一致。
            tracing::error!(
                event = "topup_redeem_failed",
                user_id = auth_user.0.user_id,
                "failed to redeem key"
            );
            api_i18n_error(&headers, "redeem.failed")
        }
    }
}

/// `POST /api/user/topup/complete` → Go `billing.AdminCompleteTopUp`。
pub async fn admin_topup_complete(
    State(state): State<AppState>,
    Extension(_auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let request: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => return api_plain_error(&headers, MSG_BAD_TRADE_NO),
    };
    let trade_no = request
        .get("trade_no")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if trade_no.is_empty() {
        return api_plain_error(&headers, MSG_BAD_TRADE_NO);
    }
    let display = state.quota_display();
    match manual_complete_top_up(&db, &trade_no, display.quota_per_unit).await {
        Ok(record) => {
            if record.quota_added > 0 {
                record_topup_log(
                    &db,
                    record.user_id,
                    &format!(
                        "管理员补单成功，充值金额: {}，支付金额：{:.6}",
                        display.to_display(record.quota_added),
                        record.money
                    ),
                    "",
                    &record.payment_method,
                    "admin",
                )
                .await;
            }
            Json(json!({"success": true, "message": "", "data": null})).into_response()
        }
        Err(error) => {
            // Go `CtxApiError(c, err)`：管理员可见真实错误文案。
            let message = match error {
                newapi_billing::topup::RechargeError::NotFound => "充值订单不存在".to_owned(),
                newapi_billing::topup::RechargeError::StatusInvalid => {
                    "订单状态不是待支付，无法补单".to_owned()
                }
                _ => "充值失败，请稍后重试".to_owned(),
            };
            tracing::error!(event = "admin_topup_complete_failed", trade_no = %trade_no, "admin topup complete failed");
            api_plain_error(&headers, &message)
        }
    }
}

fn api_i18n_error(headers: &HeaderMap, key: &str) -> Response {
    Json(json!({
        "success": false,
        "message": translate(headers, key),
    }))
    .into_response()
}

fn api_plain_error(headers: &HeaderMap, message: &str) -> Response {
    Json(json!({
        "success": false,
        "message": message,
    }))
    .into_response()
}

fn translate(headers: &HeaderMap, key: &str) -> String {
    let accept_language = crate::request_lang::accept_language_header(headers);
    let language = crate::request_lang::request_language(accept_language.as_deref());
    newapi_i18n::translate(&language, key, std::iter::empty::<(&str, &str)>())
}
