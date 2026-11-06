//! `GET /api/setup` and `POST /api/setup` — port of Go `ops.GetSetup` and
//! `ops.PostSetup` (`/root/newapi/apps/api/internal/ops/configure_system.go`).
//!
//! Route wiring is owned by the composition slice:
//! - `GET /api/setup` is registered without middleware (Go `register_api.go:27`);
//! - `POST /api/setup` is wrapped only by [`setup_body_limit`] (Go line 28).
//!
//! Business results always use HTTP 200, matching `common.H`. The schema gate
//! from `docs/p2-setup-contract.md` answers 503 `setup.schema_not_ready` when
//! the database is missing tables/columns or cannot be read; it never falls
//! back to "not installed" and never leaks SQL text.

use axum::{
    Json,
    body::Bytes,
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use newapi_identity::{
    crypto::hash_password,
    setup::{CompleteSetup, SetupDatabaseKind, SetupError, SetupInspection, SetupRepository},
    users::RootDraft,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;

/// Go `len(req.Username) > 12`: UTF-8 byte length, not character count.
const MAX_USERNAME_BYTES: usize = 12;
/// Go `len(req.Password) < 8`: UTF-8 byte length.
const MIN_PASSWORD_BYTES: usize = 8;

/// Go `SetupRequest`; missing fields keep the Go zero value.
#[derive(Deserialize, Default)]
struct SetupRequest {
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    #[serde(default, rename = "confirmPassword")]
    confirm_password: String,
    #[serde(default, rename = "SelfUseModeEnabled")]
    self_use_mode_enabled: bool,
    #[serde(default, rename = "DemoSiteEnabled")]
    demo_site_enabled: bool,
}

/// Go `GetSetup` response data. Once the setup record exists both later fields
/// stay at their zero value; otherwise they report the live root/database.
pub fn setup_body(inspection: &SetupInspection) -> Value {
    let (root_init, database_type) = if inspection.initialized {
        (false, "")
    } else {
        (
            inspection.root.exists,
            match inspection.database_kind {
                SetupDatabaseKind::Sqlite => "sqlite",
                SetupDatabaseKind::Postgres => "postgres",
            },
        )
    };
    json!({
        "success": true,
        "data": {
            "status": inspection.initialized,
            "root_init": root_init,
            "database_type": database_type,
        },
    })
}

/// Go `GetSetup`: HTTP 200 with no `message` field.
pub async fn inspect(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let lang = language(&headers);
    let Some(repository) = repository(&state) else {
        return error_response(&lang, SetupError::Unavailable);
    };
    match repository.inspect().await {
        Ok(inspection) => Json(setup_body(&inspection)).into_response(),
        Err(error) => error_response(&lang, error),
    }
}

/// Go `PostSetup`: already-initialized check, body binding, credential
/// validation (only while no root exists), then the transactional completion.
pub async fn complete(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let lang = language(&headers);
    let Some(repository) = repository(&state) else {
        return error_response(&lang, SetupError::Unavailable);
    };
    let inspection = match repository.inspect().await {
        Ok(inspection) => inspection,
        Err(error) => return error_response(&lang, error),
    };
    // Go checks `constant.Setup` before binding the body.
    if inspection.initialized {
        return error_response(&lang, SetupError::AlreadyInitialized);
    }
    let request = match bind_request(&headers, &body) {
        Ok(request) => request,
        Err(()) => return error_response(&lang, SetupError::InvalidInput),
    };
    let root_exists = inspection.root.exists;
    if let Some(key) = validate_credentials(&request, root_exists) {
        return response(&lang, StatusCode::OK, false, key);
    }
    let root = if root_exists {
        // An existing root is never overwritten.
        None
    } else {
        match hash_password(request.password.as_bytes()) {
            Ok(hash) => Some(RootDraft {
                username: request.username,
                password_hash: hash.expose_secret().to_owned(),
            }),
            // Go hashes inside the transaction; a bcrypt failure is reported
            // through the same "create administrator" branch.
            Err(_) => return error_response(&lang, SetupError::RootCreationFailed),
        }
    };
    let input = CompleteSetup {
        root,
        version: env!("CARGO_PKG_VERSION").to_owned(),
        initialized_at: crate::http::now_seconds(),
        self_use_mode_enabled: request.self_use_mode_enabled,
        demo_site_enabled: request.demo_site_enabled,
    };
    match repository.complete(input).await {
        Ok(_) => response(&lang, StatusCode::OK, true, "setup.success"),
        Err(error) => error_response(&lang, error),
    }
}

/// Go `AnonymousRequestBodyLimit` (only `POST /api/setup` uses it). Reuses the
/// already-ported boundary middleware; a zero configured limit disables it.
pub async fn setup_body_limit(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    crate::boundary_mw::anonymous_body_limit(state.anonymous_body_limit(), request, next).await
}

fn repository(state: &AppState) -> Option<SetupRepository> {
    state.db().map(SetupRepository::new)
}

/// Go validation order, applied only while no root user exists.
fn validate_credentials(request: &SetupRequest, root_exists: bool) -> Option<&'static str> {
    if root_exists {
        return None;
    }
    if request.username.len() > MAX_USERNAME_BYTES {
        return Some("setup.username_too_long");
    }
    if request.password != request.confirm_password {
        return Some("setup.password_mismatch");
    }
    if request.password.len() < MIN_PASSWORD_BYTES {
        return Some("setup.password_too_short");
    }
    None
}

/// Go `UnmarshalBodyReusable`: only `application/json` (parameters allowed) or
/// a missing/empty Content-Type is decoded. Other content types are skipped and
/// a zero-length body leaves the target at its zero value.
fn bind_request(headers: &HeaderMap, body: &[u8]) -> Result<SetupRequest, ()> {
    if !parses_as_json(headers) || body.is_empty() {
        return Ok(SetupRequest::default());
    }
    serde_json::from_slice(body).map_err(|_| ())
}

fn parses_as_json(headers: &HeaderMap) -> bool {
    match headers
        .get(header::CONTENT_TYPE)
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

/// Fixed HTTP classification. Both schema and database failures answer 503
/// with the contract's single "schema not ready" message; everything else is a
/// business result at HTTP 200.
fn error_outcome(error: SetupError) -> (StatusCode, &'static str) {
    match error {
        SetupError::SchemaNotReady | SetupError::Unavailable => {
            (StatusCode::SERVICE_UNAVAILABLE, "setup.schema_not_ready")
        }
        SetupError::AlreadyInitialized => (StatusCode::OK, "setup.already_initialized"),
        SetupError::InvalidInput => (StatusCode::OK, "setup.invalid_request"),
        // Go reports every setup-transaction failure through the one
        // "create administrator account" branch.
        SetupError::RootCreationFailed | SetupError::SetupSaveFailed => {
            (StatusCode::OK, "setup.root_account_creation_failed")
        }
        // Go distinguishes self-use/demo option failures; the identity error
        // does not carry which write failed, so this stays the generic key.
        SetupError::ModeSaveFailed => (StatusCode::OK, "setup.mode_save_failed"),
    }
}

fn error_response(lang: &str, error: SetupError) -> Response {
    let (status, key) = error_outcome(error);
    response(lang, status, false, key)
}

fn response(lang: &str, status: StatusCode, success: bool, key: &str) -> Response {
    let message = newapi_i18n::translate(lang, key, std::iter::empty::<(&str, &str)>());
    (status, Json(json!({ "success": success, "message": message }))).into_response()
}

fn language(headers: &HeaderMap) -> String {
    crate::request_lang::request_language(
        crate::request_lang::accept_language_header(headers).as_deref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use newapi_identity::users::RootPresence;

    fn inspection(initialized: bool, root: bool, kind: SetupDatabaseKind) -> SetupInspection {
        SetupInspection {
            initialized,
            root: RootPresence { exists: root },
            database_kind: kind,
        }
    }

    fn request(username: &str, password: &str, confirm: &str) -> SetupRequest {
        SetupRequest {
            username: username.to_owned(),
            password: password.to_owned(),
            confirm_password: confirm.to_owned(),
            ..SetupRequest::default()
        }
    }

    #[test]
    fn initialized_body_zeroes_root_and_database_fields() {
        let body = setup_body(&inspection(true, true, SetupDatabaseKind::Postgres));
        assert_eq!(body["success"], true);
        assert!(body.get("message").is_none());
        assert_eq!(body["data"]["status"], true);
        assert_eq!(body["data"]["root_init"], false);
        assert_eq!(body["data"]["database_type"], "");
    }

    #[test]
    fn uninitialized_body_reports_root_and_database() {
        let sqlite = setup_body(&inspection(false, true, SetupDatabaseKind::Sqlite));
        assert_eq!(sqlite["data"]["status"], false);
        assert_eq!(sqlite["data"]["root_init"], true);
        assert_eq!(sqlite["data"]["database_type"], "sqlite");

        let postgres = setup_body(&inspection(false, false, SetupDatabaseKind::Postgres));
        assert_eq!(postgres["data"]["root_init"], false);
        assert_eq!(postgres["data"]["database_type"], "postgres");
    }

    #[test]
    fn credentials_follow_go_byte_length_order() {
        // 5 CJK characters are 15 UTF-8 bytes, so Go's `len > 12` rejects them.
        let long = request(
            "管理员管理员管理员管理员管理员",
            "secret123",
            "secret123",
        );
        assert_eq!(
            validate_credentials(&long, false),
            Some("setup.username_too_long")
        );
        assert_eq!(
            validate_credentials(&request("管理员", "secret123", "secret124"), false),
            Some("setup.password_mismatch")
        );
        assert_eq!(
            validate_credentials(&request("管理员", "1234567", "1234567"), false),
            Some("setup.password_too_short")
        );
        assert_eq!(
            validate_credentials(&request("管理员", "secret123", "secret123"), false),
            None
        );
        // An existing root skips every credential check, including empty ones.
        assert_eq!(validate_credentials(&request("", "", ""), true), None);
    }

    #[test]
    fn error_classification_is_fixed_and_translated() {
        let cases = [
            (SetupError::SchemaNotReady, StatusCode::SERVICE_UNAVAILABLE),
            (SetupError::Unavailable, StatusCode::SERVICE_UNAVAILABLE),
            (SetupError::AlreadyInitialized, StatusCode::OK),
            (SetupError::InvalidInput, StatusCode::OK),
            (SetupError::RootCreationFailed, StatusCode::OK),
            (SetupError::SetupSaveFailed, StatusCode::OK),
            (SetupError::ModeSaveFailed, StatusCode::OK),
        ];
        for (error, status) in cases {
            assert_eq!(error_outcome(error).0, status, "{error:?}");
            let (_, key) = error_outcome(error);
            assert_ne!(
                newapi_i18n::translate("zh-CN", key, std::iter::empty::<(&str, &str)>()),
                key,
                "missing catalog key {key}"
            );
        }
    }

    #[test]
    fn root_account_creation_message_matches_go_verbatim() {
        assert_eq!(
            newapi_i18n::translate(
                "zh-CN",
                "setup.root_account_creation_failed",
                std::iter::empty::<(&str, &str)>(),
            ),
            "创建管理员账号失败"
        );
    }
}
