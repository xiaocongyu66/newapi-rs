//! `GET /api/user/aff` HTTP adapter.
//!
//! Go references:
//! - `apps/api/internal/identity/manage_users.go` (`GetAffCode`)
//! - `apps/api/internal/transport/compose/register_api.go` (route wiring)
//!
//! The route sits inside the `UserAuth` group with no `DisableCache`; this
//! module therefore relies on [`crate::auth::user_auth`] and writes no cache
//! headers. Both outcomes are HTTP 200. Go returns `err.Error()` on a failed
//! code write; this port maps the failure to a fixed translated message so no
//! SQL or database text can reach the client.

use axum::{
    Json,
    extract::{Extension, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use newapi_identity::users::{AffCodeError, UserProfileRepository};
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::AuthenticatedUser;

const MSG_DATABASE_ERROR: &str = "common.database_error";
const MSG_USER_NOT_FOUND: &str = "user.not_exists";

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

/// Go `common.H{"success": true, "message": "", "data": ...}`.
pub fn success_body(code: &str) -> Value {
    json!({
        "success": true,
        "message": "",
        "data": code,
    })
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
