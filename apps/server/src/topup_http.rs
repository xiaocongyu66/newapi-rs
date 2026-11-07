//! `/api/user/topup/*` read HTTP adapters.
//!
//! Go references:
//! - `apps/api/internal/billing/topup_api.go` (`GetTopUpInfo`,
//!   `GetUserTopUps`)
//! - `apps/api/internal/transport/compose/register_api.go:165-166` (routes:
//!   plain `UserAuth`, no rate-limit middleware)
//!
//! Every business outcome is HTTP 200 with the Go envelope; only the
//! `UserAuth` middleware produces 401/403. Database error text never reaches
//! the client: storage faults collapse to the translated
//! `common.database_error` message.

use axum::{
    Json,
    extract::{Extension, State},
    http::{HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use newapi_billing::topup::{TopUpRecord, TopUpRepository, TopUpSettings};
use newapi_identity::{self_user::QuotaDisplaySettings, tokens::sanitize_like_pattern};
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::AuthenticatedUser;

const MSG_DATABASE_ERROR: &str = "common.database_error";

/// `GET /api/user/topup/info` → Go `billing.GetTopUpInfo`.
pub async fn topup_info(
    State(state): State<AppState>,
    Extension(_auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let settings = match TopUpSettings::load(&db).await {
        Ok(settings) => settings,
        Err(error) => return database_error(&headers, &error),
    };
    let display = state.quota_display();
    Json(json!({
        "success": true,
        "message": "",
        "data": topup_info_data(&settings, display),
    }))
    .into_response()
}

/// The `data` object of Go `GetTopUpInfo`, field for field.
fn topup_info_data(settings: &TopUpSettings, display: QuotaDisplaySettings) -> Value {
    json!({
        "enable_online_topup": settings.is_epay_topup_enabled(),
        "enable_vmq_topup": settings.is_vmq_topup_enabled(),
        "enable_codepay_topup": settings.is_codepay_topup_enabled(),
        "enable_stripe_topup": settings.is_stripe_topup_enabled(),
        "enable_creem_topup": settings.is_creem_topup_enabled(),
        "enable_waffo_topup": settings.is_waffo_topup_enabled(),
        "enable_waffo_pancake_topup": settings.is_waffo_pancake_topup_enabled(),
        "enable_redemption": settings.payment_compliance_confirmed(),
        "payment_compliance_confirmed": settings.payment_compliance_confirmed(),
        "payment_compliance_terms_version": newapi_billing::topup::COMPLIANCE_TERMS_VERSION,
        "waffo_pay_methods": settings.waffo_pay_methods_value(),
        "creem_products": creem_products_json(settings, display),
        "pay_methods": settings.effective_pay_methods(),
        "min_topup": settings.min_topup,
        "stripe_min_topup": settings.stripe_min_topup,
        "waffo_min_topup": settings.waffo_min_topup,
        "waffo_pancake_min_topup": settings.waffo_pancake_min_topup,
        "amount_options": settings.amount_options,
        "discount": settings.amount_discount,
        "topup_link": settings.topup_link,
    })
}

/// Go `creem_products`: parse the raw option, fill the `quota_display`
/// sibling, and fall back to `null` on a malformed value. Go's
/// `PopulateCreemProductDisplay` saturates int64 quota to the int32 range
/// before rendering, and `omitempty` drops a zero `quota_display`.
fn creem_products_json(settings: &TopUpSettings, display: QuotaDisplaySettings) -> Value {
    match settings.creem_products() {
        Some(mut products) => {
            for product in &mut products {
                let clamped = product
                    .quota
                    .clamp(i64::from(i32::MIN), i64::from(i32::MAX));
                let rendered = display.to_display(clamped);
                product.quota_display = (rendered != 0.0).then_some(rendered);
            }
            json!(products)
        }
        None => Value::Null,
    }
}

/// `GET /api/user/topup/self` → Go `billing.GetUserTopUps`.
pub async fn user_topups(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let query = page_query(&uri);
    let info = page_info(&query);
    let repository = TopUpRepository::new(db);
    // Go `topUpQueryCutoff()`: the query window is 30 days of history.
    let cutoff = now_seconds() - newapi_billing::topup::USER_TOPUP_WINDOW_SECONDS;
    let keyword = query.keyword.clone().unwrap_or_default();
    let result = if keyword.is_empty() {
        repository
            .query_user(auth_user.0.user_id, cutoff, info.page_size, info.offset)
            .await
    } else {
        let pattern = match sanitize_like_pattern(&keyword) {
            Ok(pattern) => pattern,
            Err(error) => {
                return api_error(&headers, error.message_key());
            }
        };
        repository
            .search_user(
                auth_user.0.user_id,
                cutoff,
                &pattern,
                info.page_size,
                info.offset,
            )
            .await
    };
    let (records, total) = match result {
        Ok(result) => result,
        Err(error) => return database_error(&headers, &error),
    };
    let items: Vec<Value> = records.iter().map(topup_record_json).collect();
    Json(json!({
        "success": true,
        "message": "",
        "data": {
            "page": info.page,
            "page_size": info.page_size,
            "total": total,
            "items": items,
        },
    }))
    .into_response()
}

/// Go `billing.TopUp` JSON shape: every exported column, snake_case.
fn topup_record_json(record: &TopUpRecord) -> Value {
    json!({
        "id": record.id,
        "user_id": record.user_id,
        "amount": record.amount,
        "money": record.money,
        "trade_no": record.trade_no,
        "payment_method": record.payment_method,
        "payment_provider": record.payment_provider,
        "create_time": record.create_time,
        "complete_time": record.complete_time,
        "status": record.status,
    })
}

/// Go `common.GetPageQuery` accepts `p`, `page_size`, and the `ps`/`size`
/// compatibility aliases; unknown query keys are ignored.
struct TopUpPageQuery {
    p: Option<String>,
    page_size: Option<String>,
    ps: Option<String>,
    size: Option<String>,
    keyword: Option<String>,
}

struct TopUpPageInfo {
    page: i64,
    page_size: i64,
    offset: i64,
}

/// Go/axum query decoding parity without the axum `query` feature:
/// `+` is a space and `%XX` decodes one byte.
fn query_pairs(uri: &Uri) -> Vec<(String, String)> {
    let Some(query) = uri.query() else {
        return Vec::new();
    };
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (percent_decode(key), percent_decode(value))
        })
        .collect()
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

fn page_query(uri: &Uri) -> TopUpPageQuery {
    let pairs = query_pairs(uri);
    let get = |key: &str| {
        pairs
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.clone())
    };
    TopUpPageQuery {
        p: get("p"),
        page_size: get("page_size"),
        ps: get("ps"),
        size: get("size"),
        keyword: get("keyword"),
    }
}

/// Go `strconv.Atoi`: optional sign plus decimal digits, no whitespace.
fn parse_i64(value: Option<&str>) -> Option<i64> {
    value.and_then(|value| value.parse::<i64>().ok())
}

fn page_info(query: &TopUpPageQuery) -> TopUpPageInfo {
    let mut page = parse_i64(query.p.as_deref()).unwrap_or(0);
    let mut page_size = parse_i64(query.page_size.as_deref()).unwrap_or(0);
    if page < 1 {
        let compat = parse_i64(query.p.as_deref()).unwrap_or(0);
        page = if compat != 0 { compat } else { 1 };
    }
    if page_size == 0 {
        if let Some(value) = parse_i64(query.ps.as_deref())
            && value != 0
        {
            page_size = value;
        }
        if page_size == 0
            && let Some(value) = parse_i64(query.size.as_deref())
            && value != 0
        {
            page_size = value;
        }
        if page_size == 0 {
            page_size = 10;
        }
    }
    if page_size > 100 {
        page_size = 100;
    }
    // Go clamps a negative start index: `Offset` rejects offsets below zero
    // and every database backend rejects negative LIMIT/OFFSET bindings.
    let offset = page.saturating_sub(1).saturating_mul(page_size).max(0);
    TopUpPageInfo {
        page,
        page_size,
        offset,
    }
}

fn api_error(headers: &HeaderMap, key: &str) -> Response {
    Json(json!({
        "success": false,
        "message": translate(headers, key),
    }))
    .into_response()
}

fn database_error(headers: &HeaderMap, error: &sqlx::Error) -> Response {
    tracing::warn!(
        event = "topup_database_operation_failed",
        category = crate::database_error_class(error),
        "topup database operation failed"
    );
    api_error(headers, MSG_DATABASE_ERROR)
}

fn translate(headers: &HeaderMap, key: &str) -> String {
    let accept_language = crate::request_lang::accept_language_header(headers);
    let language = crate::request_lang::request_language(accept_language.as_deref());
    newapi_i18n::translate(&language, key, std::iter::empty::<(&str, &str)>())
}

fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
