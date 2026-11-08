//! `GET /api/user/aff` and `POST /api/user/aff_transfer` HTTP adapters.
//!
//! Go references:
//! - `apps/api/internal/identity/manage_users.go` (`GetAffCode`,
//!   `TransferAffQuota`)
//! - `apps/api/internal/identity/store_users.go` (`TransferAffQuotaToQuota`)
//! - `apps/api/internal/billing/register_option_hooks.go` (`formatQuota`)
//! - `apps/api/internal/transport/compose/register_api.go` (route wiring)
//!
//! Both routes sit inside the `UserAuth` group with no `DisableCache`; this
//! module therefore relies on [`crate::auth::user_auth`] and writes no cache
//! headers. Every outcome is HTTP 200.
//!
//! Go surfaces `err.Error()` verbatim on the affiliate code write and
//! interpolates the raw error into `user.transfer_failed`; this port maps both
//! to fixed translated messages so no SQL or database text can reach the
//! client. The three strings Go authors directly (`无效的转账数值`,
//! `转账数额必须大于 0`, `邀请额度不足！`) are reproduced as-is because they are
//! authored literals, not database output.

use axum::{
    Json,
    body::Bytes,
    extract::{Extension, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use newapi_billing::topup::TopUpSettings;
use newapi_identity::{
    tokens::{quota_from_display, quota_from_float},
    users::{AffCodeError, AffTransferError, UserProfileRepository},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::AuthenticatedUser;

const MSG_DATABASE_ERROR: &str = "common.database_error";
const MSG_USER_NOT_FOUND: &str = "user.not_exists";
const MSG_COMPLIANCE_REQUIRED: &str = "payment.compliance_required";
const MSG_TRANSFER_QUOTA_MINIMUM: &str = "user.transfer_quota_minimum";
const MSG_TRANSFER_SUCCESS: &str = "user.transfer_success";
const MSG_TRANSFER_FAILED: &str = "user.transfer_failed";
/// Go's authored literals: `common.CtxApiErrorMsg` texts, not i18n keys.
const MSG_INVALID_AMOUNT: &str = "无效的转账数值";
const MSG_AMOUNT_MUST_BE_POSITIVE: &str = "转账数额必须大于 0";
const MSG_INSUFFICIENT: &str = "邀请额度不足！";

/// Go `GetAffCode`: read the caller's affiliate code, generating and persisting
/// one when it is empty. `GetUserById(id, true)` in Go means "select all
/// columns", not "ignore cache": it is a direct row read that GORM's default
/// scope filters to `deleted_at IS NULL`, so soft-deleted users behave like
/// missing users.
pub async fn aff_code(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match UserProfileRepository::new(db)
        .ensure_aff_code(auth_user.0.user_id)
        .await
    {
        Ok(code) => Json(success_body(&code)).into_response(),
        Err(error) => {
            if matches!(error, AffCodeError::Storage) {
                tracing::warn!(
                    event = "aff_code_persist_failed",
                    "affiliate code read or write failed"
                );
            }
            Json(error_body(&translate(&headers, error_message_key(error)))).into_response()
        }
    }
}

/// Fixed i18n keys for [`AffCodeError`]; the storage variant deliberately
/// carries no SQL text.
pub fn error_message_key(error: AffCodeError) -> &'static str {
    match error {
        AffCodeError::NotFound => MSG_USER_NOT_FOUND,
        AffCodeError::Storage => MSG_DATABASE_ERROR,
    }
}

/// Go `identity.TransferAffQuotaRequest` (`manage_users.go:432-440`).
///
/// `quota_display` beats `quota` when it is non-zero, exactly like Go's
/// `if tran.QuotaDisplay != 0`, so a `quota_display` of `0` means "absent"
/// rather than "transfer nothing".
#[derive(Deserialize, Default)]
struct TransferAffQuotaRequest {
    #[serde(default)]
    quota: i64,
    #[serde(default)]
    quota_display: f64,
}

/// Go `identity.TransferAffQuota` (`manage_users.go:443-474`).
///
/// Route chain (Go `register_api.go:179`):
/// `UserAuth` → `UserCriticalRateLimit("aff-transfer")` →
/// `RequirePaymentComplianceMiddleware` → handler. The port has no per-key
/// critical limiter yet, so only the compliance gate is reproduced inline
/// here; the group already carries `user_auth`, and the gate must run before
/// the transfer exactly as the middleware ordering does.
pub async fn transfer_aff_quota(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    // Go's `RequirePaymentComplianceMiddleware`, inline because no other route
    // uses it yet: an unconfirmed compliance gate never reaches the transfer.
    let settings = match TopUpSettings::load(&db).await {
        Ok(settings) => settings,
        Err(error) => return database_error(&headers, &error),
    };
    if !settings.payment_compliance_confirmed() {
        return Json(error_body(&translate(&headers, MSG_COMPLIANCE_REQUIRED))).into_response();
    }

    let request = bind_transfer(&headers, &body);
    // Go reads `quota` and overrides it from `quota_display` only when the
    // latter is non-zero, so the two never have to be reconciled.
    let amount = if request.quota_display != 0.0 {
        if !request.quota_display.is_finite() {
            return Json(error_body(MSG_INVALID_AMOUNT)).into_response();
        }
        quota_from_display(request.quota_display, &state.quota_display())
    } else {
        request.quota
    };
    if amount <= 0 {
        return Json(error_body(MSG_AMOUNT_MUST_BE_POSITIVE)).into_response();
    }
    // Go's minimum guard is `float64(quota) < common.QuotaPerUnit`, and its
    // message interpolates Go's `logger.LogQuota(QuotaFromFloat(QuotaPerUnit))`
    // — the currency-wrapped one-unit string, not a bare number.
    let display = state.quota_display();
    let quota_per_unit = display.quota_per_unit;
    if quota_per_unit > 0.0 && (amount as f64) < quota_per_unit {
        let minimum = quota_from_float(quota_per_unit);
        let minimum = display.format_quota(minimum, true);
        return Json(error_body(&translate_with(
            &headers,
            MSG_TRANSFER_QUOTA_MINIMUM,
            [("Min", minimum)],
        )))
        .into_response();
    }

    match UserProfileRepository::new(db)
        .transfer_aff_quota(auth_user.0.user_id, amount)
        .await
    {
        Ok(()) => Json(success_body_translated(&translate(
            &headers,
            MSG_TRANSFER_SUCCESS,
        )))
        .into_response(),
        Err(AffTransferError::Insufficient) => Json(error_body(MSG_INSUFFICIENT)).into_response(),
        Err(AffTransferError::NotFound) => {
            Json(error_body(&translate(&headers, MSG_USER_NOT_FOUND))).into_response()
        }
        Err(AffTransferError::InvalidAmount) => {
            // Unreachable here: `amount <= 0` is already rejected above, so
            // this only guards the repository invariant for direct callers.
            Json(error_body(MSG_AMOUNT_MUST_BE_POSITIVE)).into_response()
        }
        Err(AffTransferError::Storage) => {
            tracing::warn!(
                event = "aff_transfer_failed",
                "affiliate quota transfer failed"
            );
            // Go interpolates the raw error into `user.transfer_failed`; the
            // port substitutes the fixed storage literal so no SQL or database
            // text reaches the client.
            Json(error_body(&translate_with(
                &headers,
                MSG_TRANSFER_FAILED,
                [("Error", MSG_DATABASE_ERROR)],
            )))
            .into_response()
        }
    }
}

/// Go `common.H{"success": true, "message": "", "data": ...}`.
pub fn success_body(code: &str) -> Value {
    json!({
        "success": true,
        "message": "",
        "data": code,
    })
}

/// Go `common.CtxApiSuccessI18n(c, MsgUserTransferSuccess, nil)`
/// (`common/transport.go:87-93`): the message carries the *translated* success
/// text and `data` is present as `null`, unlike the bare `CtxApiSuccess`
/// envelope that leaves the message empty.
pub fn success_body_translated(message: &str) -> Value {
    json!({
        "success": true,
        "message": message,
        "data": null,
    })
}

/// Go `c.UnmarshalBodyReusable`: a non-JSON content type or an empty body
/// keeps the zero value, so only malformed JSON is a bind error.
fn bind_transfer(headers: &HeaderMap, body: &[u8]) -> TransferAffQuotaRequest {
    fn parses_as_json(headers: &HeaderMap) -> bool {
        headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(';')
                    .next()
                    .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("application/json"))
            })
    }
    if !parses_as_json(headers) || body.is_empty() {
        return TransferAffQuotaRequest::default();
    }
    serde_json::from_slice(body).unwrap_or_default()
}

/// Go `CtxApiError*` error shape: HTTP 200 plus a message.
pub fn error_body(message: &str) -> Value {
    json!({
        "success": false,
        "message": message,
    })
}

fn translate(headers: &HeaderMap, key: &str) -> String {
    let accept_language = crate::request_lang::accept_language_header(headers);
    let language = crate::request_lang::request_language(accept_language.as_deref());
    newapi_i18n::translate(&language, key, std::iter::empty::<(&str, &str)>())
}

/// Same as [`translate`] but with template arguments, for Go's
/// `CtxApiErrorI18n(c, key, map[string]any{...})` calls.
fn translate_with<I, K, V>(headers: &HeaderMap, key: &str, args: I) -> String
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: std::fmt::Display,
{
    let accept_language = crate::request_lang::accept_language_header(headers);
    let language = crate::request_lang::request_language(accept_language.as_deref());
    newapi_i18n::translate(&language, key, args)
}

/// Go collapses a settings read failure into `common.database_error`; the raw
/// SQL text is never surfaced.
fn database_error(headers: &HeaderMap, error: &sqlx::Error) -> Response {
    tracing::warn!(
        event = "aff_transfer_settings_failed",
        "top-up settings read for the affiliate transfer failed: {error}"
    );
    Json(error_body(&translate(headers, MSG_DATABASE_ERROR))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_envelope_wraps_the_code_as_a_string() {
        assert_eq!(
            success_body("Ab3d"),
            json!({"success": true, "message": "", "data": "Ab3d"})
        );
    }

    #[test]
    fn error_envelope_matches_go_shape() {
        assert_eq!(
            error_body("User does not exist"),
            json!({"success": false, "message": "User does not exist"})
        );
    }

    #[test]
    fn aff_code_errors_map_to_fixed_keys() {
        assert_eq!(
            error_message_key(AffCodeError::NotFound),
            MSG_USER_NOT_FOUND
        );
        assert_eq!(error_message_key(AffCodeError::Storage), MSG_DATABASE_ERROR);
    }
}
