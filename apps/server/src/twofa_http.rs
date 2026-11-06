//! `/api/user/2fa/*` management HTTP adapters.
//!
//! Go references:
//! - `apps/api/internal/identity/manage_twofa.go` (`Get2FAStatus`, `Setup2FA`,
//!   `Enable2FA`, `Disable2FA`, `RegenerateBackupCodes`)
//! - `apps/api/internal/identity/store_twofa.go` (transactions)
//! - `apps/api/internal/transport/compose/register_api.go:183-187`
//!
//! Every handler answers HTTP 200 with the Go envelope; only the `UserAuth`
//! middleware produces 401/403. `GET /status` has no `DisableCache`; the four
//! POST routes write the three no-cache headers for every business outcome.
//! Secrets, TOTP values and backup codes never enter a log line.

use axum::{
    Json,
    body::Bytes,
    extract::{Extension, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use newapi_identity::{
    AuthIdentity,
    crypto::AuthKeys,
    two_fa::{
        TwoFaError, TwoFaRepository, generate_backup_codes, generate_qr_code_data,
        generate_totp_secret, totp::validate_totp_code,
    },
    user_auth::CredentialKind,
    users::{SessionAdvance, UserMutationError, UserProfileRepository},
};
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::{AuthCredential, AuthenticatedUser, parse_authorization};
use crate::boundary_mw::disable_cache_headers;

const MSG_DATABASE_ERROR: &str = "common.database_error";
const MSG_INVALID_REQUEST: &str = "twofa.invalid_request";
// Go 在这些分支返回裸错误文本 `当前认证方式不支持安全验证`；对应 key 尚未落地
// 于 locale 文件，沿用 `self_http` 的既有分类。
const MSG_SESSION_REQUIRED: &str = "auth.session_required";

const MSG_SETUP_ALREADY_ENABLED: &str = "twofa.setup_already_enabled";
const MSG_ALREADY_ENABLED: &str = "twofa.already_enabled";
const MSG_ALREADY_EXISTS: &str = "twofa.already_exists";
const MSG_USER_NOT_FOUND: &str = "twofa.user_not_found";
const MSG_SETUP_REQUIRED: &str = "twofa.setup_required";
const MSG_NOT_ENABLED: &str = "twofa.not_enabled";
const MSG_CODE_INCORRECT: &str = "twofa.code_incorrect";
const MSG_CODE_LENGTH: &str = "twofa.code_length";
const MSG_CODE_NUMERIC: &str = "twofa.code_numeric";
const MSG_SECRET_GENERATE_FAILED: &str = "twofa.secret_generate_failed";
const MSG_BACKUP_GENERATE_FAILED: &str = "twofa.backup_generate_failed";
const MSG_BACKUP_SAVE_FAILED: &str = "twofa.backup_save_failed";
const MSG_SETUP_SUCCESS: &str = "twofa.setup_success";
const MSG_ENABLE_SUCCESS: &str = "twofa.enable_success";
const MSG_DISABLE_SUCCESS: &str = "twofa.disable_success";
const MSG_BACKUP_REGENERATED: &str = "twofa.backup_regenerated";

/// Go `Get2FAStatus`: no body, no cache headers. `backup_codes_remaining` is
/// present only for enabled factors whose count query succeeded.
pub async fn status(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let repository = TwoFaRepository::new(db);
    let user_id = auth_user.0.user_id;
    let now = crate::http::now_seconds();
    let record = match repository.by_user_id(user_id).await {
        Ok(record) => record,
        Err(error) => return two_fa_error_response(&headers, error),
    };
    let mut data = json!({
        "enabled": false,
        "locked": false,
    });
    if let Some(record) = record {
        data["enabled"] = json!(record.is_enabled);
        data["locked"] = json!(record.is_locked(now));
        if record.is_enabled {
            match repository.unused_backup_code_count(user_id).await {
                Ok(count) => data["backup_codes_remaining"] = json!(count),
                Err(_) => {
                    tracing::warn!(
                        event = "twofa_backup_count_failed",
                        "2FA backup code count failed"
                    );
                }
            }
        }
    }
    Json(json!({
        "success": true,
        "message": "",
        "data": data,
    }))
    .into_response()
}

/// Go `Setup2FA`: delete an existing pending setup, generate a TOTP secret and
/// four backup codes, persist the pending factor, return secret + otpauth URI +
/// plaintext backup codes exactly once.
pub async fn setup(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
) -> Response {
    let mut response = setup_inner(&state, &auth_user, &headers).await;
    disable_cache_headers(&mut response);
    response
}

async fn setup_inner(
    state: &AppState,
    auth_user: &AuthenticatedUser,
    headers: &HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let repository = TwoFaRepository::new(db);
    let user_id = auth_user.0.user_id;
    let now = crate::http::now_seconds();

    let existing = match repository.by_user_id(user_id).await {
        Ok(existing) => existing,
        Err(error) => return two_fa_error_response(headers, error),
    };
    if let Some(record) = &existing {
        if record.is_enabled {
            return api_error(headers, MSG_SETUP_ALREADY_ENABLED);
        }
        // Go `DeletePendingTwoFASetup` hard-deletes both the pending factor and
        // its backup codes before a replacement is created.
        if repository.delete_pending_setup(user_id).await.is_err() {
            return api_error(headers, MSG_DATABASE_ERROR);
        }
    }

    let username = match repository.username(user_id).await {
        Ok(Some(username)) => username,
        Ok(None) => return api_error(headers, MSG_USER_NOT_FOUND),
        Err(error) => return two_fa_error_response(headers, error),
    };

    let Some(secret) = generate_totp_secret() else {
        tracing::warn!(
            event = "twofa_secret_generate_failed",
            "2FA TOTP secret generation failed"
        );
        return api_error(headers, MSG_SECRET_GENERATE_FAILED);
    };
    let Some(backup_codes) = generate_backup_codes() else {
        tracing::warn!(
            event = "twofa_backup_generate_failed",
            "2FA backup code generation failed"
        );
        return api_error(headers, MSG_BACKUP_GENERATE_FAILED);
    };
    let qr_code_data = generate_qr_code_data(&secret, &username);

    match repository.create_pending_setup(user_id, &secret, now).await {
        Ok(()) => {}
        Err(TwoFaError::AlreadyExists) => return api_error(headers, MSG_ALREADY_EXISTS),
        Err(TwoFaError::UserNotFound) => return api_error(headers, MSG_USER_NOT_FOUND),
        Err(error) => return two_fa_error_response(headers, error),
    }
    if repository
        .create_pending_backup_codes(user_id, &backup_codes, now)
        .await
        .is_err()
    {
        tracing::warn!(
            event = "twofa_backup_save_failed",
            "2FA backup code persistence failed"
        );
        return api_error(headers, MSG_BACKUP_SAVE_FAILED);
    }

    Json(json!({
        "success": true,
        "message": translate(headers, MSG_SETUP_SUCCESS),
        "data": {
            "secret": secret,
            "qr_code_data": qr_code_data,
            "backup_codes": backup_codes,
        },
    }))
    .into_response()
}

/// Go `Enable2FA`: TOTP-only validation (no lock/failure accounting), then an
/// atomic enable + auth-version bump and current-session rotation.
pub async fn enable(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let mut response = enable_inner(&state, &auth_user, &headers, &body).await;
    disable_cache_headers(&mut response);
    response
}

async fn enable_inner(
    state: &AppState,
    auth_user: &AuthenticatedUser,
    headers: &HeaderMap,
    body: &[u8],
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Some(code) = parse_code(body) else {
        return api_error(headers, MSG_INVALID_REQUEST);
    };
    let repository = TwoFaRepository::new(db);
    let user_id = auth_user.0.user_id;
    let now = crate::http::now_seconds();

    let two_fa = match repository.by_user_id(user_id).await {
        Ok(Some(two_fa)) => two_fa,
        Ok(None) => return api_error(headers, MSG_SETUP_REQUIRED),
        Err(error) => return two_fa_error_response(headers, error),
    };
    if two_fa.is_enabled {
        return api_error(headers, MSG_ALREADY_ENABLED);
    }
    let clean = match validate_numeric_code(&code) {
        Ok(clean) => clean,
        Err(NumericCodeError::Length) => return api_error(headers, MSG_CODE_LENGTH),
        Err(NumericCodeError::NotNumeric) => return api_error(headers, MSG_CODE_NUMERIC),
    };
    if !validate_totp_code(&two_fa.secret, &clean, now) {
        return api_error(headers, MSG_CODE_INCORRECT);
    }

    let Some(identity) = session_identity(state, auth_user, headers, now) else {
        return api_error(headers, MSG_SESSION_REQUIRED);
    };
    let next_version = match repository.enable_with_auth_version(user_id, now).await {
        Ok(version) => version,
        Err(TwoFaError::AlreadyEnabled) => return api_error(headers, MSG_ALREADY_ENABLED),
        Err(error) => return two_fa_error_response(headers, error),
    };
    let data = match rotate_session(state, &identity, next_version, now).await {
        Ok(data) => data,
        Err(error) => return rotation_response(headers, error),
    };
    Json(json!({
        "success": true,
        "message": translate(headers, MSG_ENABLE_SUCCESS),
        "data": data,
    }))
    .into_response()
}

/// Go `Disable2FA`: TOTP or backup-code validation with lock/failure accounting,
/// then an atomic delete + auth-version bump and current-session rotation.
pub async fn disable(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let mut response = disable_inner(&state, &auth_user, &headers, &body).await;
    disable_cache_headers(&mut response);
    response
}

async fn disable_inner(
    state: &AppState,
    auth_user: &AuthenticatedUser,
    headers: &HeaderMap,
    body: &[u8],
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Some(code) = parse_code(body) else {
        return api_error(headers, MSG_INVALID_REQUEST);
    };
    let repository = TwoFaRepository::new(db);
    let user_id = auth_user.0.user_id;
    let now = crate::http::now_seconds();
    // Go only attempts TOTP when `ValidateNumericCode` succeeded; a malformed
    // numeric input still falls through to the backup-code branch.
    let numeric = validate_numeric_code(&code).ok();
    match repository
        .validate_disable_code(user_id, &code, numeric.as_deref(), now)
        .await
    {
        Ok(()) => {}
        Err(TwoFaError::NotEnabled) => return api_error(headers, MSG_NOT_ENABLED),
        Err(error) => return two_fa_error_response(headers, error),
    }

    let Some(identity) = session_identity(state, auth_user, headers, now) else {
        return api_error(headers, MSG_SESSION_REQUIRED);
    };
    let next_version = match repository.disable_with_auth_version(user_id, now).await {
        Ok(version) => version,
        Err(TwoFaError::NotEnabled) => return api_error(headers, MSG_NOT_ENABLED),
        Err(error) => return two_fa_error_response(headers, error),
    };
    let data = match rotate_session(state, &identity, next_version, now).await {
        Ok(data) => data,
        Err(error) => return rotation_response(headers, error),
    };
    Json(json!({
        "success": true,
        "message": translate(headers, MSG_DISABLE_SUCCESS),
        "data": data,
    }))
    .into_response()
}

/// Go `RegenerateBackupCodes`: TOTP-only validation, replace codes and bump the
/// auth version in one transaction, return the new plaintext codes once.
pub async fn backup_codes(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let mut response = backup_codes_inner(&state, &auth_user, &headers, &body).await;
    disable_cache_headers(&mut response);
    response
}

async fn backup_codes_inner(
    state: &AppState,
    auth_user: &AuthenticatedUser,
    headers: &HeaderMap,
    body: &[u8],
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Some(code) = parse_code(body) else {
        return api_error(headers, MSG_INVALID_REQUEST);
    };
    let repository = TwoFaRepository::new(db);
    let user_id = auth_user.0.user_id;
    let now = crate::http::now_seconds();

    match repository.by_user_id(user_id).await {
        Ok(Some(two_fa)) if two_fa.is_enabled => {}
        Ok(_) => return api_error(headers, MSG_NOT_ENABLED),
        Err(error) => return two_fa_error_response(headers, error),
    }
    let clean = match validate_numeric_code(&code) {
        Ok(clean) => clean,
        Err(NumericCodeError::Length) => return api_error(headers, MSG_CODE_LENGTH),
        Err(NumericCodeError::NotNumeric) => return api_error(headers, MSG_CODE_NUMERIC),
    };
    if let Err(error) = repository
        .validate_totp_management(user_id, &clean, now)
        .await
    {
        return two_fa_error_response(headers, error);
    }

    let Some(backup_codes) = generate_backup_codes() else {
        tracing::warn!(
            event = "twofa_backup_generate_failed",
            "2FA backup code generation failed"
        );
        return api_error(headers, MSG_BACKUP_GENERATE_FAILED);
    };
    let Some(identity) = session_identity(state, auth_user, headers, now) else {
        return api_error(headers, MSG_SESSION_REQUIRED);
    };
    let next_version = match repository
        .replace_backup_codes_with_auth_version(user_id, &backup_codes, now)
        .await
    {
        Ok(version) => version,
        Err(_) => {
            // Go logs the underlying error and always answers the fixed message.
            tracing::warn!(
                event = "twofa_backup_save_failed",
                "2FA backup code replacement failed"
            );
            return api_error(headers, MSG_BACKUP_SAVE_FAILED);
        }
    };
    let mut data = match rotate_session(state, &identity, next_version, now).await {
        Ok(data) => data,
        Err(error) => return rotation_response(headers, error),
    };
    data["backup_codes"] = json!(backup_codes);
    Json(json!({
        "success": true,
        "message": translate(headers, MSG_BACKUP_REGENERATED),
        "data": data,
    }))
    .into_response()
}

/// Go `AdvanceCurrentSessionToUserVersion` + `authRotationData`: advance the
/// presented browser session, revoke the other sessions and issue a fresh
/// access token against the post-mutation auth version.
async fn rotate_session(
    state: &AppState,
    identity: &AuthIdentity,
    next_user_auth_version: i64,
    now: i64,
) -> Result<Value, RotationError> {
    let Some(db) = state.db() else {
        return Err(RotationError::Unavailable);
    };
    if next_user_auth_version <= identity.user_auth_version {
        return Err(RotationError::Database);
    }
    let Some(session_version) = identity.session_version.checked_add(1) else {
        return Err(RotationError::Database);
    };
    let projection = match UserProfileRepository::new(db)
        .advance_session_auth_version(SessionAdvance {
            user_id: identity.user_id,
            sid: &identity.sid,
            expected_session_version: identity.session_version,
            expected_user_auth_version: identity.user_auth_version,
            next_user_auth_version,
            now,
        })
        .await
    {
        Ok(projection) => projection,
        Err(error) => {
            if let UserMutationError::Storage(error) = &error {
                tracing::warn!(
                    event = "twofa_session_advance_failed",
                    category = crate::database_error_class(error),
                    "2FA session advance failed"
                );
            }
            return Err(RotationError::Database);
        }
    };
    let Some(auth) = state.auth() else {
        return Err(RotationError::Database);
    };
    if auth.revoke_others(identity, now).await.is_err() {
        tracing::warn!(
            event = "twofa_session_revoke_failed",
            "2FA other-session revoke failed"
        );
        return Err(RotationError::Database);
    }
    let Some(keys) = session_keys(state) else {
        return Err(RotationError::Database);
    };
    let new_identity = AuthIdentity {
        user_id: identity.user_id,
        sid: identity.sid.clone(),
        user_auth_version: next_user_auth_version,
        session_version,
    };
    let issued = match keys.issue_access(&new_identity, now) {
        Ok(issued) => issued,
        Err(_) => return Err(RotationError::Database),
    };
    Ok(json!({
        "access_token": issued.token.expose_secret(),
        "token_type": "Bearer",
        "access_expires_at": issued.expires_at,
        "session": {
            "sid": projection.sid,
            "current": true,
            "login_method": projection.login_method,
            "ip": projection.ip,
            "user_agent": projection.user_agent,
            "created_at": projection.created_at,
            "last_active_at": projection.last_active_at,
            "expires_at": projection.expires_at,
        },
    }))
}

/// Go `authtoken.ReadSessionAuthIdentity`: only a dashboard JWT carries a
/// session; a personal access token is not a browser session.
fn session_identity(
    state: &AppState,
    auth_user: &AuthenticatedUser,
    headers: &HeaderMap,
    now: i64,
) -> Option<AuthIdentity> {
    if auth_user.0.credential != CredentialKind::DashboardSession {
        return None;
    }
    let credential = parse_authorization(headers).ok()?;
    let token = match credential {
        AuthCredential::Bearer(token) | AuthCredential::Raw(token) => token,
    };
    let identity = state.auth()?.parse_access(&token, now).ok()?;
    (identity.user_id == auth_user.0.user_id).then_some(identity)
}

/// `AppState::flow_key` is `auth-flow-v1:` + `SESSION_SECRET`, the same secret
/// the access-token signer derives from.
fn session_keys(state: &AppState) -> Option<AuthKeys> {
    let secret = state.flow_key()?.strip_prefix(b"auth-flow-v1:")?;
    std::str::from_utf8(secret).ok().map(AuthKeys::new)
}

/// Small error shape for [`rotate_session`]; avoids a large `Result` error.
#[derive(Clone, Copy)]
enum RotationError {
    Unavailable,
    Database,
}

fn rotation_response(headers: &HeaderMap, error: RotationError) -> Response {
    match error {
        RotationError::Unavailable => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        RotationError::Database => api_error(headers, MSG_DATABASE_ERROR),
    }
}

#[derive(Clone, Copy)]
enum NumericCodeError {
    Length,
    NotNumeric,
}

/// Go `common.ValidateNumericCode`: remove ASCII spaces, require six bytes and
/// `strconv.Atoi` acceptance (which permits a leading `+`/`-`).
fn validate_numeric_code(code: &str) -> Result<String, NumericCodeError> {
    let cleaned: String = code.chars().filter(|character| *character != ' ').collect();
    if cleaned.len() != 6 {
        return Err(NumericCodeError::Length);
    }
    if cleaned.parse::<i64>().is_err() {
        return Err(NumericCodeError::NotNumeric);
    }
    Ok(cleaned)
}

/// Go `BindJSON` + `binding:"required"` on `code`: any parse failure, missing
/// field, wrong type or empty string is the fixed "参数错误" branch.
fn parse_code(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let code = value.get("code")?.as_str()?.to_owned();
    (!code.is_empty()).then_some(code)
}

fn two_fa_error_response(headers: &HeaderMap, error: TwoFaError) -> Response {
    let language = request_language(headers);
    Json(json!({
        "success": false,
        "message": error.client_message(&language),
    }))
    .into_response()
}

fn api_error(headers: &HeaderMap, key: &str) -> Response {
    Json(json!({
        "success": false,
        "message": translate(headers, key),
    }))
    .into_response()
}

fn request_language(headers: &HeaderMap) -> String {
    let accept_language = crate::request_lang::accept_language_header(headers);
    crate::request_lang::request_language(accept_language.as_deref())
}

fn translate(headers: &HeaderMap, key: &str) -> String {
    newapi_i18n::translate(
        &request_language(headers),
        key,
        std::iter::empty::<(&str, &str)>(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_code_validation_matches_go_atoi_semantics() {
        assert_eq!(
            validate_numeric_code(" 123 456 ").ok().as_deref(),
            Some("123456")
        );
        // Go `Atoi` accepts a leading sign; TOTP validation later rejects it.
        assert!(validate_numeric_code("+12345").is_ok());
        assert!(validate_numeric_code("-12345").is_ok());
        assert!(matches!(
            validate_numeric_code("12345"),
            Err(NumericCodeError::Length)
        ));
        assert!(matches!(
            validate_numeric_code("12a456"),
            Err(NumericCodeError::NotNumeric)
        ));
    }

    #[test]
    fn body_parsing_requires_a_non_empty_string_code() {
        assert_eq!(
            parse_code(br#"{"code":"123456"}"#).as_deref(),
            Some("123456")
        );
        assert_eq!(
            parse_code(br#"{"code":"123456","flow_token":"x"}"#).as_deref(),
            Some("123456")
        );
        assert_eq!(parse_code(br#"{"code":""}"#), None);
        assert_eq!(parse_code(br#"{"code":123456}"#), None);
        assert_eq!(parse_code(br#"{"flow_token":"x"}"#), None);
        assert_eq!(parse_code(b"null"), None);
        assert_eq!(parse_code(b"[]"), None);
        assert_eq!(parse_code(b""), None);
    }
}
