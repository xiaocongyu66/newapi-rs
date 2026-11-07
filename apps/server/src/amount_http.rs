//! Top-up amount quoting HTTP adapters:
//! `POST /api/user/{amount,stripe/amount,waffo/amount,waffo-pancake/amount}`.
//!
//! Go references:
//! - `apps/api/internal/billing/topup_api.go:898` (`RequestAmount`),
//!   `:185-300` (`getPayMoney`, `getTopUpQuota`, `getMaxTopUpAmount`,
//!   `validateTopUpQuota`, `rejectInvalidTopUpQuota`)
//! - `apps/api/internal/billing/topup_stripe.go:44-65,436-500`
//!   (`StripeAdaptor.RequestAmount`, `getStripePayMoney`, `stripePayUnits`,
//!   `getStripeCreditedQuota`, `getStripeMinTopup`)
//! - `apps/api/internal/billing/topup_waffo.go:110` (`RequestWaffoAmount`),
//!   `:87-98` (`getWaffoPayMoney`)
//! - `apps/api/internal/billing/topup_waffo_pancake.go:21`
//!   (`RequestWaffoPancakeAmount`), `:50-70` (`getWaffoPancakePayMoney`)
//! - `apps/api/internal/billing/store_topup.go:63-90`
//!   (`topUpQuotaMaxCurrent`, `ValidateTopUpQuotaCapacity`)
//!
//! ## Envelope
//!
//! These four endpoints do **not** use `CtxApiSuccess`: they write a raw
//! `common.H{"message": ..., "data": ...}`, so the wire shape has no
//! `success` field at all, `message` is the literal `"success"`/`"error"`
//! (never a translated message), and `data` is the price string. Every error
//! branch is a hard-coded Chinese literal (or, for the two wallet-capacity
//! sentinels, Go's `errors.New` English text) — none of them go through i18n,
//! and the front-end compares them verbatim.
//!
//! Success: `{"message":"success","data":"<price>"}`.
//! Failure: `{"message":"error","data":"<literal>"}`.

use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use newapi_billing::topup::{
    TopUpQuotaRejection, check_capacity, pay_money, stripe_credited_quota, stripe_pay_money,
    validate_credited_quota, validate_top_up_quota, waffo_pancake_pay_money, waffo_pay_money,
};
use newapi_identity::{self_user::QuotaDisplayKind, users::UserProfileRepository};
use serde_json::json;

use crate::AppState;
use crate::auth::AuthenticatedUser;

/// Go `topup_api.go:903`: `c.BindJSON` failure.
const MSG_BAD_REQUEST: &str = "参数错误";
/// Go `topup_api.go:915`: `identity.GetUserGroup` failure.
const MSG_GROUP_FAILED: &str = "获取用户分组失败";
/// Go `getPayMoney`'s callers: `payMoney <= 0.01`.
const MSG_AMOUNT_TOO_SMALL: &str = "充值金额过低";
/// Go `topup_stripe.go:53`: the hard-coded Stripe ceiling.
const MSG_STRIPE_MAX: &str = "充值数量不能大于 10000";
/// Go `topup_stripe.go:49`: the shared minimum-topup message, interpolated
/// with the gateway's own minimum.
fn msg_below_minimum(minimum: i64) -> String {
    format!("充值数量不能小于 {minimum}")
}

/// Go `stconv.FormatFloat(payMoney, 'f', 2, 64)`.
fn price_string(pay_money: f64) -> String {
    format!("{pay_money:.2}")
}

/// Go `common.H{"message": "success", "data": <price>}`.
fn quote_success(pay_money: f64) -> Response {
    Json(json!({"message": "success", "data": price_string(pay_money)})).into_response()
}

/// Go `common.H{"message": "error", "data": <literal>}`.
fn quote_error(message: String) -> Response {
    Json(json!({"message": "error", "data": message})).into_response()
}

fn quote_error_static(message: &str) -> Response {
    quote_error(message.to_owned())
}

/// `POST /api/user/amount` → Go `billing.RequestAmount`.
pub async fn request_amount(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    body: Bytes,
    headers: HeaderMap,
) -> Response {
    let Ok(request) = bind_amount(&headers, &body) else {
        return quote_error_static(MSG_BAD_REQUEST);
    };
    quote(
        &state,
        &headers,
        auth_user.0.user_id,
        &request,
        Kind::Amount,
    )
    .await
}

/// `POST /api/user/stripe/amount` → Go
/// `billing.RequestStripeAmount` → `stripeAdaptor.RequestAmount`.
pub async fn request_stripe_amount(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    body: Bytes,
    headers: HeaderMap,
) -> Response {
    let Ok(request) = bind_amount(&headers, &body) else {
        return quote_error_static(MSG_BAD_REQUEST);
    };
    quote(
        &state,
        &headers,
        auth_user.0.user_id,
        &request,
        Kind::Stripe,
    )
    .await
}

/// `POST /api/user/waffo/amount` → Go `billing.RequestWaffoAmount`.
pub async fn request_waffo_amount(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    body: Bytes,
    headers: HeaderMap,
) -> Response {
    let Ok(request) = bind_amount(&headers, &body) else {
        return quote_error_static(MSG_BAD_REQUEST);
    };
    quote(&state, &headers, auth_user.0.user_id, &request, Kind::Waffo).await
}

/// `POST /api/user/waffo-pancake/amount` → Go
/// `billing.RequestWaffoPancakeAmount`.
pub async fn request_waffo_pancake_amount(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    body: Bytes,
    headers: HeaderMap,
) -> Response {
    let Ok(request) = bind_amount(&headers, &body) else {
        return quote_error_static(MSG_BAD_REQUEST);
    };
    quote(
        &state,
        &headers,
        auth_user.0.user_id,
        &request,
        Kind::WaffoPancake,
    )
    .await
}

/// The gateway whose quote is being produced.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Amount,
    Stripe,
    Waffo,
    WaffoPancake,
}

impl Kind {
    /// Go's per-gateway minimum-topup option.
    fn min_topup(self, settings: &newapi_billing::topup::TopUpSettings) -> i64 {
        match self {
            Self::Amount => settings.min_topup,
            Self::Stripe => settings.stripe_min_topup,
            Self::Waffo => settings.waffo_min_topup,
            Self::WaffoPancake => settings.waffo_pancake_min_topup,
        }
    }
}

/// Go `RequestAmount`'s body: a single `amount` field. Like
/// `reset_http::bind`, a non-JSON content type or an empty body binds the
/// zero value, so a body-less POST behaves like `amount = 0`.
#[derive(Default)]
struct AmountRequest {
    amount: i64,
}

fn bind_amount(headers: &HeaderMap, body: &[u8]) -> Result<AmountRequest, ()> {
    if !parses_as_json(headers) || body.is_empty() {
        return Ok(AmountRequest::default());
    }
    let parsed: serde_json::Value = serde_json::from_slice(body).map_err(|_| ())?;
    // Go's `json.Unmarshal` into `int64` accepts any JSON number that fits;
    // a float with a fractional part, a string, or `null` fails the bind or
    // leaves the zero value. Go treats `null` as "leave the field alone"
    // (zero) rather than an error.
    match parsed.as_object() {
        None if parsed.is_null() => Ok(AmountRequest::default()),
        None => Err(()),
        Some(object) => match object.get("amount") {
            None | Some(serde_json::Value::Null) => Ok(AmountRequest::default()),
            Some(value) => value
                .as_i64()
                .map(|amount| AmountRequest { amount })
                .ok_or(()),
        },
    }
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

/// The shared body of all four `Request*Amount` handlers.
async fn quote(
    state: &AppState,
    headers: &HeaderMap,
    user_id: i64,
    request: &AmountRequest,
    kind: Kind,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };

    // ---- 1. minimum top-up ---------------------------------------------
    // Go reads `MinTopUp`-style options plus the group ratio in one place; the
    // Rust snapshot loader returns both, and a NULL option row keeps the Go
    // default rather than failing.
    let settings = match newapi_billing::topup::TopUpSettings::load(&db).await {
        Ok(settings) => settings,
        Err(error) => {
            tracing::warn!(
                event = "amount_quote_settings_failed",
                category = crate::database_error_class(&error),
                "amount quote settings load failed"
            );
            return quote_error_static(MSG_BAD_REQUEST);
        }
    };
    let display = state.quota_display();
    let tokens = display.kind == QuotaDisplayKind::Tokens;
    let quota_per_unit = display.quota_per_unit;

    // Stripe scales its minimum by `QuotaPerUnit` in TOKENS mode
    // (`getStripeMinTopup`); the Waffo family does not.
    let min_topup = kind.min_topup(&settings);
    let min_topup = if tokens && kind == Kind::Stripe {
        // Go multiplies by `int(common.QuotaPerUnit)`; a non-integral unit is
        // not a configurable state, so the same truncation applies.
        (i128::from(min_topup) * i128::from(quota_per_unit as i64)) as i64
    } else {
        min_topup
    };
    if request.amount < min_topup {
        return quote_error(msg_below_minimum(min_topup));
    }

    // Stripe's additional hard ceiling (`topup_stripe.go:51-54`).
    if kind == Kind::Stripe && request.amount > 10_000 {
        return quote_error_static(MSG_STRIPE_MAX);
    }

    // ---- 2. quota validation -------------------------------------------
    // Go `rejectInvalidTopUpQuota(c, id, amount)` runs *before* the group
    // lookup, so a request with an invalid quota never reads the user row.
    // Stripe validates the *credited* quota (amount x ratio x quota-per-unit)
    // and never calls `ValidateTopUpQuotaCapacity` on the wallet; the other
    // three share `validateTopUpQuota` + the capacity check.
    if kind == Kind::Stripe {
        // Stripe reads the group first (`topup_stripe.go:52`), so the group
        // ratio has to be resolved before the quota product can be formed.
        let profile = match load_profile(&db, headers, user_id).await {
            Ok(Some(profile)) => profile,
            Ok(None) => return lookup_failure(headers),
            Err(rejection) => return rejection,
        };
        let credited =
            stripe_credited_quota(&settings, request.amount, &profile.group, quota_per_unit);
        // Go's Stripe path validates this product through `validateCreditedQuota`
        // and reports it with the same two literals, then skips the wallet
        // capacity check entirely.
        if let Err(rejection) = validate_credited_quota(credited) {
            return quote_error_static(rejection.message());
        }
        return finish(&settings, &profile, request, kind, tokens, quota_per_unit);
    }

    let credited = match validate_top_up_quota(&settings, request.amount, tokens, quota_per_unit) {
        Ok(credited) => credited,
        Err(TopUpQuotaRejection::ExceedsMax(max)) => {
            return quote_error(format!("单笔充值数量不能大于 {max}"));
        }
        Err(TopUpQuotaRejection::InvalidQuota) => {
            return quote_error_static("充值数量无效");
        }
    };

    // ---- 3. group + wallet capacity --------------------------------------
    // Go `identity.GetUserGroup(id, true)` (and `ReadUserQuota` for the
    // capacity check); a missing row is the group-failure literal.
    let profile = match load_profile(&db, headers, user_id).await {
        Ok(Some(profile)) => profile,
        Ok(None) => return lookup_failure(headers),
        Err(rejection) => return rejection,
    };
    if let Err(rejection) = check_capacity(credited, profile.quota) {
        return quote_error_static(rejection.message());
    }
    finish(&settings, &profile, request, kind, tokens, quota_per_unit)
}

/// Go `identity.GetUserGroup(id, true)` + `identity.ReadUserQuota`: one
/// row read supplies both the group and the wallet balance.
async fn load_profile(
    db: &newapi_storage::Database,
    headers: &HeaderMap,
    user_id: i64,
) -> Result<Option<newapi_identity::users::UserProfile>, Response> {
    match UserProfileRepository::new(db.clone()).by_id(user_id).await {
        Ok(profile) => Ok(profile),
        Err(error) => Err(database_failure(headers, &error)),
    }
}

/// The shared `payMoney <= 0.01` rejection and the success envelope.
fn finish(
    settings: &newapi_billing::topup::TopUpSettings,
    profile: &newapi_identity::users::UserProfile,
    request: &AmountRequest,
    kind: Kind,
    tokens: bool,
    quota_per_unit: f64,
) -> Response {
    let pay_money = match kind {
        Kind::Amount => pay_money(
            settings,
            request.amount,
            &profile.group,
            tokens,
            quota_per_unit,
        ),
        Kind::Stripe => stripe_pay_money(
            settings,
            request.amount,
            &profile.group,
            tokens,
            quota_per_unit,
        ),
        Kind::Waffo => waffo_pay_money(
            settings,
            request.amount,
            &profile.group,
            tokens,
            quota_per_unit,
        ),
        Kind::WaffoPancake => waffo_pancake_pay_money(
            settings,
            request.amount,
            &profile.group,
            tokens,
            quota_per_unit,
        ),
    };
    if pay_money <= 0.01 {
        return quote_error_static(MSG_AMOUNT_TOO_SMALL);
    }
    quote_success(pay_money)
}

fn lookup_failure(headers: &HeaderMap) -> Response {
    tracing::warn!(
        event = "amount_quote_user_lookup_failed",
        "amount quote user lookup failed"
    );
    quote_error_static(MSG_GROUP_FAILED)
}

fn database_failure(headers: &HeaderMap, error: &sqlx::Error) -> Response {
    tracing::warn!(
        event = "amount_quote_database_operation_failed",
        category = crate::database_error_class(error),
        "amount quote database operation failed"
    );
    quote_error_static(MSG_GROUP_FAILED)
}
