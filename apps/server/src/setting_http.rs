//! `PUT /api/user/setting` HTTP adapter — Go `identity.UpdateUserSettingHandler`
//! (`apps/api/internal/identity/manage_users.go:1365-1504`).
//!
//! Route chain (Go `register_api.go:180`): the `selfRoute` group carries
//! `UserAuth` and this route adds nothing, so no cache headers are written and
//! no critical limiter distinguishes it.
//!
//! Every outcome is HTTP 200. Go validates in a fixed order — bind, notify
//! type, threshold, then the per-type gateway fields — and each failure is a
//! distinct i18n key rather than one generic message, so the branch order is
//! part of the contract. Only after validation does Go read the user row, so
//! an invalid body never reaches storage.
//!
//! Go builds a fresh `dto.UserSetting` and marshals it over the whole
//! `setting` column (`store_users.go:185`), so the write replaces the stored
//! JSON instead of merging into it: keys the handler never assigns —
//! `sidebar_modules`, `billing_preference`, `language`, plus the gateway
//! fields of the notify types not chosen — disappear. Those three belong to
//! `PUT /api/user/self`, which reads the setting back before overwriting.

use axum::{
    Json,
    body::Bytes,
    extract::{Extension, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use newapi_identity::users::{UserProfileRepository, UserSetting};
use serde::Deserialize;
use serde_json::json;

use crate::AppState;
use crate::auth::{AuthenticatedUser, ROLE_ADMIN_USER};

const MSG_INVALID_PARAMS: &str = "common.invalid_params";
const MSG_USER_NOT_FOUND: &str = "user.not_exists";
const MSG_INVALID_TYPE: &str = "setting.invalid_type";
const MSG_THRESHOLD_GT_ZERO: &str = "quota.threshold_gt_zero";
const MSG_WEBHOOK_EMPTY: &str = "setting.webhook_empty";
const MSG_WEBHOOK_INVALID: &str = "setting.webhook_invalid";
const MSG_EMAIL_INVALID: &str = "setting.email_invalid";
const MSG_BARK_URL_EMPTY: &str = "setting.bark_url_empty";
const MSG_BARK_URL_INVALID: &str = "setting.bark_url_invalid";
const MSG_GOTIFY_URL_EMPTY: &str = "setting.gotify_url_empty";
const MSG_GOTIFY_TOKEN_EMPTY: &str = "setting.gotify_token_empty";
const MSG_GOTIFY_URL_INVALID: &str = "setting.gotify_url_invalid";
const MSG_URL_MUST_HTTP: &str = "setting.url_must_http";
const MSG_UPDATE_FAILED: &str = "common.update_failed";
const MSG_DATABASE_ERROR: &str = "common.database_error";
const MSG_SAVED: &str = "setting.saved";

/// Go `dto.NotifyType*` (`apps/api/internal/dto`).
const NOTIFY_EMAIL: &str = "email";
const NOTIFY_WEBHOOK: &str = "webhook";
const NOTIFY_BARK: &str = "bark";
const NOTIFY_GOTIFY: &str = "gotify";

/// Go's `GotifyPriority` clamp: Go replaces an out-of-range value with 5
/// rather than rejecting the request.
const GOTIFY_PRIORITY_FALLBACK: i64 = 5;
const GOTIFY_PRIORITY_MIN: i64 = 0;
const GOTIFY_PRIORITY_MAX: i64 = 10;

/// Go `identity.UpdateUserSettingRequest` (`manage_users.go:1350-1363`).
///
/// Only `upstream_model_update_notify_enabled` is a pointer in Go, because
/// "absent" and "explicitly false" differ for it: the value is preserved from
/// the stored settings unless the field is present *and* the caller is an
/// admin. Every other field is overwritten wholesale.
#[derive(Debug, Default, Deserialize)]
struct UpdateUserSettingRequest {
    #[serde(default)]
    notify_type: String,
    #[serde(default)]
    quota_warning_threshold: f64,
    #[serde(default)]
    webhook_url: String,
    #[serde(default)]
    webhook_secret: String,
    #[serde(default)]
    notification_email: String,
    #[serde(default)]
    bark_url: String,
    #[serde(default)]
    gotify_url: String,
    #[serde(default)]
    gotify_token: String,
    #[serde(default)]
    gotify_priority: i64,
    #[serde(default)]
    upstream_model_update_notify_enabled: Option<bool>,
    #[serde(default)]
    accept_unset_model_ratio_model: bool,
    #[serde(default)]
    record_ip_log: bool,
}

/// Go `identity.UpdateUserSettingHandler`.
pub async fn update_user_setting(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let request = match bind(&headers, &body) {
        Ok(request) => request,
        Err(()) => return rejected(&headers, MSG_INVALID_PARAMS),
    };
    // Go validates the notify type first, then the threshold, then only the
    // gateway fields the chosen type actually uses.
    if !matches!(
        request.notify_type.as_str(),
        NOTIFY_EMAIL | NOTIFY_WEBHOOK | NOTIFY_BARK | NOTIFY_GOTIFY
    ) {
        return rejected(&headers, MSG_INVALID_TYPE);
    }
    if request.quota_warning_threshold <= 0.0 {
        return rejected(&headers, MSG_THRESHOLD_GT_ZERO);
    }
    if request.notify_type == NOTIFY_WEBHOOK {
        if request.webhook_url.is_empty() {
            return rejected(&headers, MSG_WEBHOOK_EMPTY);
        }
        if !is_request_uri(&request.webhook_url) {
            return rejected(&headers, MSG_WEBHOOK_INVALID);
        }
    }
    if request.notify_type == NOTIFY_EMAIL && !request.notification_email.is_empty() {
        // Go checks only for "@", not a full RFC 5322 address.
        if !request.notification_email.contains('@') {
            return rejected(&headers, MSG_EMAIL_INVALID);
        }
    }
    if request.notify_type == NOTIFY_BARK {
        if request.bark_url.is_empty() {
            return rejected(&headers, MSG_BARK_URL_EMPTY);
        }
        if !is_request_uri(&request.bark_url) {
            return rejected(&headers, MSG_BARK_URL_INVALID);
        }
        if !is_http_url(&request.bark_url) {
            return rejected(&headers, MSG_URL_MUST_HTTP);
        }
    }
    if request.notify_type == NOTIFY_GOTIFY {
        if request.gotify_url.is_empty() {
            return rejected(&headers, MSG_GOTIFY_URL_EMPTY);
        }
        if request.gotify_token.is_empty() {
            return rejected(&headers, MSG_GOTIFY_TOKEN_EMPTY);
        }
        if !is_request_uri(&request.gotify_url) {
            return rejected(&headers, MSG_GOTIFY_URL_INVALID);
        }
        if !is_http_url(&request.gotify_url) {
            return rejected(&headers, MSG_URL_MUST_HTTP);
        }
    }

    // Go reads the user only after validation succeeded, so an invalid body
    // never touches storage. Go surfaces `err.Error()` ("record not found")
    // here; the port uses the fixed translated key, matching the convention in
    // `admin_twofa_http`, so no database text reaches the client.
    let repository = UserProfileRepository::new(db);
    let profile = match repository.by_id(auth_user.0.user_id).await {
        Ok(Some(profile)) => profile,
        Ok(None) => return rejected(&headers, MSG_USER_NOT_FOUND),
        Err(error) => {
            tracing::warn!(
                event = "user_setting_read_failed",
                "user row read for the settings update failed: {error}"
            );
            return rejected(&headers, MSG_DATABASE_ERROR);
        }
    };
    let existing = UserSetting::from_json(&profile.setting);
    let notify_type = request.notify_type;
    let webhook = notify_type == NOTIFY_WEBHOOK;
    let email = notify_type == NOTIFY_EMAIL;
    let bark = notify_type == NOTIFY_BARK;
    let gotify = notify_type == NOTIFY_GOTIFY;

    let settings = UserSetting {
        notify_type,
        quota_warning_threshold: request.quota_warning_threshold,
        upstream_model_update_notify_enabled: upstream_notify(
            existing.upstream_model_update_notify_enabled,
            profile.role,
            request.upstream_model_update_notify_enabled,
        ),
        accept_unset_model_ratio_model: request.accept_unset_model_ratio_model,
        record_ip_log: request.record_ip_log,
        webhook_url: gateway(webhook, request.webhook_url),
        webhook_secret: gateway(webhook, request.webhook_secret),
        notification_email: gateway(email, request.notification_email),
        bark_url: gateway(bark, request.bark_url),
        gotify_url: gateway(gotify, request.gotify_url),
        gotify_token: gateway(gotify, request.gotify_token),
        gotify_priority: if gotify {
            clamp_gotify_priority(request.gotify_priority)
        } else {
            0
        },
        // Go never assigns these three, so `omitempty` drops them from the
        // marshaled setting and the column write replaces rather than merges.
        // `PUT /api/user/self` owns them through its read-modify-write
        // branches; this endpoint's whole-column update is allowed to clear
        // them, which is exactly what the Go backend does today.
        sidebar_modules: String::new(),
        billing_preference: String::new(),
        language: String::new(),
    };

    if let Err(error) = repository
        .update_setting(profile.id, &settings.to_json())
        .await
    {
        tracing::warn!(
            event = "user_setting_write_failed",
            "user settings write failed: {error}"
        );
        return rejected(&headers, MSG_UPDATE_FAILED);
    }
    Json(json!({
        "success": true,
        "message": translate(&headers, MSG_SAVED),
        "data": null,
    }))
    .into_response()
}

/// Go only adopts `upstream_model_update_notify_enabled` when the request
/// carries the field *and* the caller's role is at or above admin; otherwise
/// the stored value survives (`manage_users.go:1457-1461`).
fn upstream_notify(existing: bool, role: i64, requested: Option<bool>) -> bool {
    if role >= ROLE_ADMIN_USER {
        if let Some(value) = requested {
            return value;
        }
    }
    existing
}

/// Go assigns a gateway field only inside the branch of the chosen notify
/// type; any other type leaves it zero so `omitempty` drops the key.
fn gateway(active: bool, value: String) -> String {
    if active { value } else { String::new() }
}

/// Go clamps an out-of-range `GotifyPriority` to 5 instead of failing.
fn clamp_gotify_priority(priority: i64) -> i64 {
    if priority < GOTIFY_PRIORITY_MIN || priority > GOTIFY_PRIORITY_MAX {
        GOTIFY_PRIORITY_FALLBACK
    } else {
        priority
    }
}

/// Go `url.ParseRequestURI`, which runs in Go's "via request" mode and is
/// deliberately permissive: a valid scheme, any absolute path, and even the
/// bare `*` all parse. The scheme grammar, the leading `*`/`/` forms, and the
/// percent-escape checks are the parts that decide accept/reject for user
/// input, so those are reproduced.
///
/// Deliberately **not** reproduced: `parseHost`'s authority validation
/// (url.go:625-666) plus `unescape(encodeHost)` (url.go:202-249). Go rejects a
/// space or `\` inside the host, a non-ASCII `%`-escape such as `%50`, an
/// unclosed `[` IPv6 literal, and a non-numeric `:port`, none of which this
/// function detects. The known divergence is one-way: a URL Go rejects is
/// accepted and stored here, never the reverse, so a configured endpoint can
/// only fail to receive pushes rather than mis-parse. Porting it faithfully
/// means the `shouldEscape(encodeHost)` table plus IPv6 zone handling, whose
/// risk of rejecting a URL Go accepts outweighs the benefit; if a rejected
/// webhook ever matters, `checkin_http`-style validation is where to add it.
fn is_request_uri(value: &str) -> bool {
    // Go's `stringContainsCTLByte`: a control byte anywhere is fatal.
    if value.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return false;
    }
    if value == "*" || value.starts_with('/') {
        return !has_invalid_escape(value);
    }
    // An absolute URI: `getscheme` needs a leading letter and then only
    // alphanumerics or `+`/`-`/`.` before the colon, so "1http://x" and
    // ":noscheme" fail while an empty remainder ("mailto:") is fine.
    let Some((scheme, rest)) = value.split_once(':') else {
        return false;
    };
    if !scheme.starts_with(|character: char| character.is_ascii_alphabetic())
        || !scheme.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
        })
    {
        return false;
    }
    // An opaque remainder ("foo:bar") skips the escape checks; an authority or
    // path form ("foo:/bar", "foo://bar") is unescaped by Go.
    !rest.starts_with('/') || !has_invalid_escape(value)
}

/// Go's `parse` cuts the query at the first `?` (url.go:537) and only unescapes
/// the path ahead of it. `ParseRequestURI` goes straight to `parse` — it never
/// calls `setFragment` (that belongs to `Parse`, url.go:485) — so anything
/// after `?`, including any `#fragment`, is neither unescaped nor validated.
fn has_invalid_escape(value: &str) -> bool {
    let path = value.split_once('?').map_or(value, |(path, _)| path);
    has_malformed_escape(path)
}

/// Go's `unescape`: `%` must be followed by two hexadecimal digits.
fn has_malformed_escape(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            index += 1;
            continue;
        }
        let is_hex = |offset: usize| bytes.get(index + offset).is_some_and(u8::is_ascii_hexdigit);
        if !is_hex(1) || !is_hex(2) {
            return true;
        }
        index += 3;
    }
    false
}

/// Go `strings.HasPrefix(url, "https://") || strings.HasPrefix(url, "http://")`.
fn is_http_url(value: &str) -> bool {
    value.starts_with("https://") || value.starts_with("http://")
}

/// Go `c.BindJSON`; a non-JSON content type or an empty body binds the zero
/// value, and only malformed JSON is a bind error.
///
/// Go coerces an absent `Content-Type` to `application/json`
/// (`common/gin.go:116-121`) and matches with `strings.HasPrefix`, so a body
/// sent without the header still decodes. The sibling ports in this crate skip
/// that coercion; this endpoint follows Go because the coercion is load-bearing
/// here (a bodyless PUT must not be reported as a bind error either way).
fn bind(headers: &HeaderMap, body: &[u8]) -> Result<UpdateUserSettingRequest, ()> {
    fn parses_as_json(headers: &HeaderMap) -> bool {
        // `Context.ContentType()` strips `;`-separated parameters and trims.
        let content_type = headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.split(';').next().unwrap_or(value).trim().to_owned())
            .unwrap_or_default();
        let content_type = if content_type.is_empty() {
            "application/json".to_owned()
        } else {
            content_type
        };
        content_type.starts_with("application/json")
    }
    if !parses_as_json(headers) || body.is_empty() {
        return Ok(UpdateUserSettingRequest::default());
    }
    serde_json::from_slice(body).map_err(|_| ())
}

fn translate(headers: &HeaderMap, key: &str) -> String {
    let accept_language = crate::request_lang::accept_language_header(headers);
    let language = crate::request_lang::request_language(accept_language.as_deref());
    newapi_i18n::translate(&language, key, std::iter::empty::<(&str, &str)>())
}

/// Go `CtxApiErrorI18n`: HTTP 200 with `{success:false, message}` and no
/// `data` member.
fn rejected(headers: &HeaderMap, key: &str) -> Response {
    Json(json!({
        "success": false,
        "message": translate(headers, key),
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each expectation was produced by running Go's
    /// `url.ParseRequestURI` (go1.24.4) over the same input, so this pins the
    /// port against upstream rather than against itself.
    #[test]
    fn request_uri_matches_go() {
        let accepted = [
            "https://hooks.example/a",
            "http://x.example",
            "ftp://x.example",
            "//example.com/p",
            "foo:bar",
            "http://",
            "javascript:alert(1)",
            "mailto:a@b.c",
            "mailto:",
            "x:",
            "/just/path",
            "/",
            "//",
            "/a b",
            "/a:b",
            "*",
            "HTTPS://UPPER.example",
            "http://例え.jp",
            "a+b.s-c://d",
            "a:b c",
            "foo:%zz",
            "http://h/x%2Fy",
            "/x?q=%zz",
            // `ParseRequestURI` never calls `setFragment`, so everything after
            // the first `?` — including any `#fragment` — escapes validation.
            "https://hooks.example/a?x=1#f%zz",
            "https://h/a?s=%zz",
            "https://h/a?x=%zz",
            "foo:bar#%zz",
            "mailto:a@b#c%zz",
        ];
        for value in accepted {
            assert!(is_request_uri(value), "{value:?} should parse");
        }

        let rejected = [
            "",
            "not a uri",
            "nope",
            "1http://x",
            ":noscheme",
            "foo bar:baz",
            "?query=1",
            "#frag",
            "%zz",
            "/%zz",
            "/a%",
            "/a%2",
            "/a%zz",
            "//h/%zz",
            "http://host/%zz",
            "http://h/%2",
            "/x#%zz",
            // A malformed escape *before* the `?` still fails: the cut happens
            // before validation, so it is the path that is checked.
            "https://h/a%zz?x=1",
            "*\u{0}",
            "a:b\u{0}c",
            "https://a\tb",
            "http://h/\u{7f}",
        ];
        for value in rejected {
            assert!(!is_request_uri(value), "{value:?} should not parse");
        }
    }

    /// Pins the one documented divergence: Go's `parseHost` rejects a space or
    /// a backslash inside the authority, while this port does not. The check is
    /// one-way (Go rejects, the port accepts), so these inputs stay accepted
    /// until authority validation is ported — see [`is_request_uri`].
    #[test]
    fn authority_validation_is_a_known_one_way_gap() {
        for value in ["https://a b/c", "https://a\\b", "http://%50/x"] {
            assert!(
                is_request_uri(value),
                "{value:?} is accepted by design; Go would reject it"
            );
        }
    }

    #[test]
    fn gotify_priority_clamps_like_go() {
        for priority in -1..=11 {
            let expected = if (0..=10).contains(&priority) {
                priority
            } else {
                GOTIFY_PRIORITY_FALLBACK
            };
            assert_eq!(clamp_gotify_priority(priority), expected);
        }
    }

    #[test]
    fn admin_only_flag_needs_an_admin_and_a_present_field() {
        // A common role keeps the stored value whatever the request sends.
        assert!(upstream_notify(true, 1, Some(false)));
        assert!(upstream_notify(false, 1, Some(true)));
        // An admin adopts the field, so absence still preserves.
        assert!(!upstream_notify(false, ROLE_ADMIN_USER, Some(false)));
        assert!(upstream_notify(true, ROLE_ADMIN_USER, None));
        // The boundary is `>=`, not `>`: role 9 cannot clear the stored flag
        // even when the request explicitly sends false.
        assert!(upstream_notify(true, ROLE_ADMIN_USER - 1, Some(false)));
        assert!(!upstream_notify(false, ROLE_ADMIN_USER - 1, Some(false)));
    }
}
