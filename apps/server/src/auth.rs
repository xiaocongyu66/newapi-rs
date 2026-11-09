//! Dashboard authentication boundary: reusable `UserAuth` middleware, the
//! role gate behind Go `AdminAuth`, and the two lenient middlewares
//! `TryUserAuth` / `TokenAuthReadOnly`.
//!
//! Go reference: `apps/api/internal/security/authenticate.go`
//! (`classifyDashboardCredential` + `authHelper`). Credential classification
//! tries a dashboard JWT first, then a personal access token. Failure status,
//! fixed code and message key follow Go; token, SQL and database error text
//! never reach the client or the logs.

use axum::{
    Json,
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    middleware::Next,
    response::{IntoResponse, Response},
};
use newapi_identity::{
    AuthError, CredentialKind as DashboardCredential,
    auth_session::SessionAuthError,
    login::USER_STATUS_ENABLED,
    tokens::{TOKEN_STATUS_DISABLED, TokenRepository, classify_dashboard},
    user_auth::{
        CredentialKind, PersonalAccessTokenRepository, UserAuthError, UserAuthIdentity, authorize,
    },
    users::UserProfileRepository,
};
use serde_json::json;

use crate::AppState;

/// Go `common.RoleCommonUser`.
pub const ROLE_COMMON_USER: i64 = 1;

/// Go `common.RoleAdminUser`（`common/constants.go:193`）：`AdminAuth` 的
/// 最低角色（`security.AdminAuth` → `authHelper(c, RoleAdminUser)`）。
pub const ROLE_ADMIN_USER: i64 = 10;

const MSG_ACCESS_TOKEN_INVALID: &str = "auth.access_token_invalid";
const MSG_NOT_LOGGED_IN: &str = "auth.not_logged_in";
const MSG_USER_BANNED: &str = "auth.user_banned";
const MSG_USER_INFO_INVALID: &str = "auth.user_info_invalid";
const MSG_INSUFFICIENT_PRIVILEGE: &str = "auth.insufficient_privilege";
const MSG_DATABASE_ERROR: &str = "common.database_error";
const MSG_TOKEN_NOT_PROVIDED: &str = "token.not_provided";
const MSG_TOKEN_INVALID: &str = "token.invalid";
const MSG_TOKEN_STATUS_UNAVAILABLE: &str = "token.status_unavailable";

/// Authenticated dashboard identity available to handlers after [`user_auth`].
#[derive(Clone, Debug)]
pub struct AuthenticatedUser(pub UserAuthIdentity);

/// One fixed authentication failure; the message is an i18n key resolved per
/// request so no caller can smuggle database or credential text into a body.
struct AuthFailure {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}

impl AuthFailure {
    fn new(status: StatusCode, code: &'static str, message: &'static str) -> Self {
        Self {
            status,
            code,
            message,
        }
    }
}

/// Reusable Go `UserAuth`: dashboard JWT first, then `users.access_token`.
/// On success the request carries an [`AuthenticatedUser`] extension. This
/// middleware must run before `DisableCache`; its failures carry no cache
/// headers, matching the Go registration order.
pub async fn user_auth(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let language = request_language(&request);
    let credential = match parse_authorization(request.headers()) {
        Ok(AuthCredential::Bearer(token) | AuthCredential::Raw(token)) => token,
        // Missing or malformed input is Go `ErrAuthTokenInvalid`, not a
        // separate "not logged in" branch.
        Err(_) => return render_auth_failure(invalid_credential(), &language),
    };
    let now = crate::http::now_seconds();
    match authenticate(&state, &credential, ROLE_COMMON_USER, now).await {
        Ok(user) => {
            request.extensions_mut().insert(user);
            next.run(request).await
        }
        Err(failure) => render_auth_failure(failure, &language),
    }
}

/// Gate an already authenticated user on a minimum role value, returning the
/// fixed status/code pair (`AUTH_INSUFFICIENT_PRIVILEGE` is 403). Go orders the
/// checks status, role, then user info; [`authorize`] keeps that order.
pub fn require_role(
    user: &AuthenticatedUser,
    min_role: i64,
) -> Result<(), (StatusCode, &'static str)> {
    authorize(&user.0, min_role).map_err(map_user_auth_error)
}

/// Go `security.AdminAuth()`（`security/authenticate.go:97-101`：
/// `authHelper(c, common.RoleAdminUser)`），挂在 `adminRoute` 上
/// （`transport/compose/register_api.go:204-205`；`userRoute` 本身没有组级
/// 中间件，所以 admin 链只有这一道）。
///
/// 与 [`user_auth`] 同为完整鉴权（凭据分类 → 账号状态 → 角色 → 用户信息），
/// 差别只在最低角色：`role < 10` → HTTP 403 `AUTH_INSUFFICIENT_PRIVILEGE`
/// （Go `authenticate.go:54-57`），因此 guest（role 0）与普通用户（role 1）
/// 都拿到与 Go 一致的 403，而不是 `UserAuth` 的 401。
pub async fn admin_auth(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let language = request_language(&request);
    let credential = match parse_authorization(request.headers()) {
        Ok(AuthCredential::Bearer(token) | AuthCredential::Raw(token)) => token,
        Err(_) => return render_auth_failure(invalid_credential(), &language),
    };
    let now = crate::http::now_seconds();
    match authenticate(&state, &credential, ROLE_ADMIN_USER, now).await {
        Ok(user) => {
            request.extensions_mut().insert(user);
            next.run(request).await
        }
        Err(failure) => render_auth_failure(failure, &language),
    }
}

/// Go `security.TryUserAuth`（`security/authenticate.go:77-89`）：宽松尝试认证，
/// 失败不阻断请求。凭据分类与完整鉴权同源（`classifyDashboardCredential`），
/// 但不做任何状态/角色/用户信息授权：
/// - 无凭据或不可解析的凭据 → unmatched 且无错误，匿名继续（`authenticate.go:154-158`）；
/// - dashboard JWT 解析/会话校验失败 → 按 `writeDashboardAuthError` 终止；
/// - PAT 查无此行（含软删除用户）同样落到 unmatched，匿名继续；
/// - 成功时写入 [`AuthenticatedUser`] 扩展，供后续 handler 使用。
pub async fn try_user_auth(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let language = request_language(&request);
    let Ok(AuthCredential::Bearer(credential) | AuthCredential::Raw(credential)) =
        parse_authorization(request.headers())
    else {
        // Go 的 unmatched 分支带 nil error：不写上下文，直接 c.Next()。
        return next.run(request).await;
    };
    let now = crate::http::now_seconds();
    match resolve_optional_identity(&state, &credential, now).await {
        Ok(Some(user)) => {
            request.extensions_mut().insert(user);
            next.run(request).await
        }
        // Go `ValidateAccessToken` 查无此行返回 (nil, nil)（store_users.go:1039-1041），
        // classifyDashboardCredential 把它归为 unmatched：请求继续，仅无鉴权上下文。
        Ok(None) => next.run(request).await,
        Err(failure) => render_auth_failure(failure, &language),
    }
}

/// Go `classifyDashboardCredential` 的 TryUserAuth 变体：只解析与验证，不做
/// 授权判定。返回 `Ok(None)` 表示 unmatched（匿名），返回 `Err` 表示
/// `writeDashboardAuthError` 要终止的那个失败分支（`authenticate.go:205-220`）。
async fn resolve_optional_identity(
    state: &AppState,
    credential: &str,
    now: i64,
) -> Result<Option<AuthenticatedUser>, AuthFailure> {
    let Some(db) = state.db() else {
        return Err(internal_failure());
    };
    match classify_dashboard(credential) {
        DashboardCredential::InternalDashboard => {
            let Some(auth) = state.auth() else {
                return Err(internal_failure());
            };
            let identity = match auth.parse_access(credential, now) {
                Ok(identity) => identity,
                // Go `ParseAccessToken` 区分过期与无效（authtoken.go:208/210），
                // writeDashboardAuthError 分别给出 AUTH_TOKEN_EXPIRED 与 AUTH_UNAUTHORIZED。
                Err(AuthError::Expired) => return Err(token_expired()),
                Err(_) => return Err(invalid_credential()),
            };
            match auth.validate(&identity, now).await {
                Ok(_) => {}
                Err(SessionAuthError::Storage(_))
                | Err(SessionAuthError::BatchFailed { .. })
                | Err(SessionAuthError::Fence) => {
                    tracing::warn!(
                        event = "dashboard_session_storage_error",
                        "dashboard session validation failed"
                    );
                    return Err(internal_failure());
                }
                Err(_) => return Err(session_revoked()),
            }
            let profile = match UserProfileRepository::new(db.clone())
                .by_id(identity.user_id)
                .await
            {
                Ok(Some(profile)) => profile,
                // Go `ValidateLoginSession` 把用户消失映射为 ErrLoginSessionRevoked
                // （authenticate.go:124-127），writeDashboardAuthError 归 401。
                Ok(None) => return Err(session_revoked()),
                Err(error) => {
                    tracing::warn!(
                        event = "dashboard_user_lookup_failed",
                        category = crate::database_error_class(&error),
                        "dashboard user lookup failed"
                    );
                    return Err(internal_failure());
                }
            };
            // Go `ValidateLoginSession`：用户未启用同样归 ErrLoginSessionRevoked
            // （authenticate.go:128-130），因此 TryUserAuth 的 JWT 分支拒绝封禁用户。
            if profile.status != USER_STATUS_ENABLED {
                return Err(session_revoked());
            }
            Ok(Some(AuthenticatedUser(UserAuthIdentity {
                user_id: profile.id,
                username: profile.username,
                role: profile.role,
                status: profile.status,
                auth_version: profile.auth_version,
                group: profile.group,
                credential: CredentialKind::DashboardSession,
            })))
        }
        DashboardCredential::Opaque => {
            match PersonalAccessTokenRepository::new(db.clone())
                .by_token(credential)
                .await
            {
                // PAT 分支不检查用户状态：封禁用户的 PAT 仍写入鉴权上下文，
                // 由下游 handler 自行裁决（与 Go authenticate.go:170-181 一致）。
                Ok(Some(user)) => Ok(Some(AuthenticatedUser(user))),
                Ok(None) => Ok(None),
                Err(error) => {
                    tracing::warn!(
                        event = "dashboard_pat_lookup_failed",
                        category = crate::database_error_class(&error),
                        "dashboard PAT lookup failed"
                    );
                    Err(internal_failure())
                }
            }
        }
    }
}

/// Go `security.TokenAuthReadOnly`（`security/authenticate.go:267-342`）：只读
/// 查询接口的宽松令牌认证。只验证令牌 key 是否存在，不检查令牌状态（显式禁用
/// 除外）、过期时间与额度；仍检查用户是否被封禁。失败响应体只有 success 与
/// message，没有 code 字段（Go 用 `c.JSON` 而非 `writeDashboardAuthError`）。
pub async fn token_auth_read_only(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let language = request_language(&request);
    let Some(db) = state.db() else {
        return readonly_failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            MSG_DATABASE_ERROR,
            &language,
        );
    };
    let key = match request.headers().get(AUTHORIZATION) {
        None => {
            return readonly_failure(StatusCode::UNAUTHORIZED, MSG_TOKEN_NOT_PROVIDED, &language);
        }
        Some(value) => match value.to_str() {
            // Go 的空 header 检查是 `key == ""`，等同于 missing。
            Ok(raw) if raw.is_empty() => {
                return readonly_failure(
                    StatusCode::UNAUTHORIZED,
                    MSG_TOKEN_NOT_PROVIDED,
                    &language,
                );
            }
            // 原始 key 查询（Go authenticate.go:273-287）：只剥这两种大小写的
            // Bearer 前缀与 sk- 前缀，且只取首个 `-` 之前的部分。
            Ok(raw) => readonly_key(raw),
            // 非 UTF-8 字节永远匹配不到已存储的 key，等同 Go 的查无此行。
            Err(_) => {
                return readonly_failure(StatusCode::UNAUTHORIZED, MSG_TOKEN_INVALID, &language);
            }
        },
    };
    let token = match TokenRepository::new(db.clone()).by_key(&key).await {
        Ok(Some(token)) => token,
        // Go `gorm.ErrRecordNotFound` → 401 token.invalid（authenticate.go:291-295）。
        Ok(None) => {
            return readonly_failure(StatusCode::UNAUTHORIZED, MSG_TOKEN_INVALID, &language);
        }
        Err(error) => {
            tracing::warn!(
                event = "token_readonly_lookup_failed",
                category = crate::database_error_class(&error),
                "TokenAuthReadOnly token lookup failed"
            );
            return readonly_failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                MSG_DATABASE_ERROR,
                &language,
            );
        }
    };
    // 只拒绝显式禁用的令牌；过期(3)/耗尽(4)等状态继续放行（authenticate.go:307-316）。
    if token.status == TOKEN_STATUS_DISABLED {
        return readonly_failure(
            StatusCode::UNAUTHORIZED,
            MSG_TOKEN_STATUS_UNAVAILABLE,
            &language,
        );
    }
    match UserProfileRepository::new(db).by_id(token.user_id).await {
        Ok(Some(profile)) => {
            if profile.status != USER_STATUS_ENABLED {
                return readonly_failure(StatusCode::FORBIDDEN, MSG_USER_BANNED, &language);
            }
            request.extensions_mut().insert(ReadOnlyTokenIdentity {
                user_id: token.user_id,
                token_id: token.id,
                token_key: token.key,
            });
            next.run(request).await
        }
        // Go `GetUserCache` 的任何错误（含用户消失）统一 500（authenticate.go:318-327）。
        Ok(None) => readonly_failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            MSG_DATABASE_ERROR,
            &language,
        ),
        Err(error) => {
            tracing::warn!(
                event = "token_readonly_user_lookup_failed",
                category = crate::database_error_class(&error),
                "TokenAuthReadOnly user lookup failed"
            );
            readonly_failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                MSG_DATABASE_ERROR,
                &language,
            )
        }
    }
}

/// Go authenticate.go:282-287 的 key 规整：Bearer/bearer 前缀 + TrimSpace、
/// 去 sk- 前缀、首个 `-` 之前的部分。
fn readonly_key(raw: &str) -> String {
    let stripped = match raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
    {
        Some(rest) => rest.trim(),
        None => raw,
    };
    let stripped = stripped.strip_prefix("sk-").unwrap_or(stripped);
    stripped.split('-').next().unwrap_or_default().to_owned()
}

/// [`TokenAuthReadOnly`] 写入请求的令牌身份（Go `c.Set` 的 id/token_id/
/// token_key，authenticate.go:337-339）。token_key 是凭据，Debug 输出打码。
#[derive(Clone)]
pub struct ReadOnlyTokenIdentity {
    pub user_id: i64,
    pub token_id: i64,
    pub token_key: String,
}

impl std::fmt::Debug for ReadOnlyTokenIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadOnlyTokenIdentity")
            .field("user_id", &self.user_id)
            .field("token_id", &self.token_id)
            .field("token_key", &"<redacted>")
            .finish()
    }
}

/// Go `TokenAuthReadOnly` 的失败响应格式：`{success, message}`，无 code。
fn readonly_failure(status: StatusCode, message_key: &str, language: &str) -> Response {
    let message = newapi_i18n::translate(language, message_key, std::iter::empty::<(&str, &str)>());
    (
        status,
        Json(json!({
            "success": false,
            "message": message,
        })),
    )
        .into_response()
}

fn token_expired() -> AuthFailure {
    AuthFailure::new(
        StatusCode::UNAUTHORIZED,
        "AUTH_TOKEN_EXPIRED",
        MSG_NOT_LOGGED_IN,
    )
}

async fn authenticate(
    state: &AppState,
    credential: &str,
    min_role: i64,
    now: i64,
) -> Result<AuthenticatedUser, AuthFailure> {
    let Some(db) = state.db() else {
        return Err(internal_failure());
    };
    match classify_dashboard(credential) {
        DashboardCredential::InternalDashboard => {
            authenticate_dashboard(state, &db, credential, min_role, now).await
        }
        DashboardCredential::Opaque => authenticate_pat(&db, credential, min_role).await,
    }
}

async fn authenticate_dashboard(
    state: &AppState,
    db: &newapi_storage::Database,
    credential: &str,
    min_role: i64,
    now: i64,
) -> Result<AuthenticatedUser, AuthFailure> {
    let Some(auth) = state.auth() else {
        return Err(internal_failure());
    };
    // Split parse and session validation so a revoked session keeps Go's
    // AUTH_SESSION_REVOKED classification. Both helper methods deliberately
    // collapse the underlying detail; no credential text is ever formatted.
    let identity = match auth.parse_access(credential, now) {
        Ok(identity) => identity,
        Err(_) => return Err(invalid_credential()),
    };
    match auth.validate(&identity, now).await {
        Ok(_) => {}
        Err(SessionAuthError::Storage(_))
        | Err(SessionAuthError::BatchFailed { .. })
        | Err(SessionAuthError::Fence) => {
            tracing::warn!(
                event = "dashboard_session_storage_error",
                "dashboard session validation failed"
            );
            return Err(internal_failure());
        }
        Err(_) => return Err(session_revoked()),
    }
    let profile = match UserProfileRepository::new(db.clone())
        .by_id(identity.user_id)
        .await
    {
        Ok(Some(profile)) => profile,
        // Go `ValidateLoginSession` maps a vanished user to session revoked.
        Ok(None) => return Err(session_revoked()),
        Err(error) => {
            tracing::warn!(
                event = "dashboard_user_lookup_failed",
                category = crate::database_error_class(&error),
                "dashboard user lookup failed"
            );
            return Err(internal_failure());
        }
    };
    authorize_user(
        UserAuthIdentity {
            user_id: profile.id,
            username: profile.username,
            role: profile.role,
            status: profile.status,
            auth_version: profile.auth_version,
            group: profile.group,
            credential: CredentialKind::DashboardSession,
        },
        min_role,
    )
}

async fn authenticate_pat(
    db: &newapi_storage::Database,
    credential: &str,
    min_role: i64,
) -> Result<AuthenticatedUser, AuthFailure> {
    match PersonalAccessTokenRepository::new(db.clone())
        .by_token(credential)
        .await
    {
        Ok(Some(user)) => authorize_user(user, min_role),
        // Go `ValidateAccessToken` returning no row (including soft-deleted
        // users) falls through to `ErrAuthTokenInvalid`.
        Ok(None) => Err(invalid_credential()),
        Err(error) => {
            tracing::warn!(
                event = "dashboard_pat_lookup_failed",
                category = crate::database_error_class(&error),
                "dashboard PAT lookup failed"
            );
            Err(internal_failure())
        }
    }
}

fn authorize_user(user: UserAuthIdentity, min_role: i64) -> Result<AuthenticatedUser, AuthFailure> {
    match authorize(&user, min_role) {
        Ok(()) => Ok(AuthenticatedUser(user)),
        Err(error) => Err(user_auth_failure(error)),
    }
}

fn user_auth_failure(error: UserAuthError) -> AuthFailure {
    match error {
        UserAuthError::InvalidCredential => invalid_credential(),
        UserAuthError::UserDisabled => AuthFailure::new(
            StatusCode::UNAUTHORIZED,
            "AUTH_USER_DISABLED",
            MSG_USER_BANNED,
        ),
        UserAuthError::UserInvalid => AuthFailure::new(
            StatusCode::UNAUTHORIZED,
            "AUTH_USER_INVALID",
            MSG_USER_INFO_INVALID,
        ),
        UserAuthError::InsufficientRole => AuthFailure::new(
            StatusCode::FORBIDDEN,
            "AUTH_INSUFFICIENT_PRIVILEGE",
            MSG_INSUFFICIENT_PRIVILEGE,
        ),
        UserAuthError::Storage => internal_failure(),
    }
}

fn invalid_credential() -> AuthFailure {
    AuthFailure::new(
        StatusCode::UNAUTHORIZED,
        "AUTH_UNAUTHORIZED",
        MSG_ACCESS_TOKEN_INVALID,
    )
}

fn session_revoked() -> AuthFailure {
    AuthFailure::new(
        StatusCode::UNAUTHORIZED,
        "AUTH_SESSION_REVOKED",
        MSG_NOT_LOGGED_IN,
    )
}

fn internal_failure() -> AuthFailure {
    AuthFailure::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "AUTH_INTERNAL_ERROR",
        MSG_DATABASE_ERROR,
    )
}

fn request_language(request: &Request) -> String {
    let accept_language = crate::request_lang::accept_language_header(request.headers());
    crate::request_lang::request_language(accept_language.as_deref())
}

fn render_auth_failure(failure: AuthFailure, language: &str) -> Response {
    let message = newapi_i18n::translate(
        language,
        failure.message,
        std::iter::empty::<(&str, &str)>(),
    );
    (
        failure.status,
        Json(json!({
            "success": false,
            "code": failure.code,
            "message": message,
        })),
    )
        .into_response()
}

/// Untrusted opaque input. Deliberately implements neither Debug nor Serialize.
pub enum AuthCredential {
    Bearer(String),
    Raw(String),
}

pub type ParsedCredential = AuthCredential;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthHeaderError {
    Missing,
    Empty,
    Unsupported,
    Multiple,
}

// Go strings.Fields/TrimSpace use unicode.IsSpace, not just the ASCII space.
fn go_space(c: char) -> bool {
    matches!(c, '\t'..='\r' | ' ' | '\u{85}' | '\u{a0}' | '\u{1680}'
        | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}'
        | '\u{205f}' | '\u{3000}')
}

/// Classify a single Authorization value without interpreting its secret.
///
/// Scheme recognition and separator whitespace follow Go's Fields semantics.
/// Unlike Fields, the token remainder is never trimmed or reconstructed: internal
/// and trailing whitespace remain part of the credential. A bare single-field
/// credential also retains its original bytes (including surrounding whitespace).
/// Comma-combined values and repeated Bearer schemes are rejected, not selected.
/// Successful parsing proves neither credential validity nor browser-session use.
pub fn parse_authorization(headers: &HeaderMap) -> Result<ParsedCredential, AuthHeaderError> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let value = values.next().ok_or(AuthHeaderError::Missing)?;
    if values.next().is_some() {
        return Err(AuthHeaderError::Multiple);
    }
    let original = value.to_str().map_err(|_| AuthHeaderError::Unsupported)?;
    let header = original.trim_start_matches(go_space);
    if header.is_empty() {
        return Err(AuthHeaderError::Empty);
    }
    // Authorization is not a list-valued header; never choose one combined value.
    if header.contains(',') {
        return Err(AuthHeaderError::Multiple);
    }
    let mut fields = header.split(go_space).filter(|part| !part.is_empty());
    let first = fields.next().ok_or(AuthHeaderError::Empty)?;
    if first.eq_ignore_ascii_case("Bearer") {
        let token = header[first.len()..].trim_start_matches(go_space);
        if token.is_empty() {
            return Err(AuthHeaderError::Empty);
        }
        if token
            .split(go_space)
            .any(|part| part.eq_ignore_ascii_case("Bearer"))
        {
            return Err(AuthHeaderError::Multiple);
        }
        return Ok(AuthCredential::Bearer(token.to_owned()));
    }
    if fields.next().is_some() {
        return Err(AuthHeaderError::Unsupported);
    }
    Ok(AuthCredential::Raw(original.to_owned()))
}

/// Fixed public codes only; never expose database details or credential values.
pub fn map_user_auth_error(error: UserAuthError) -> (StatusCode, &'static str) {
    match error {
        UserAuthError::InvalidCredential => (StatusCode::UNAUTHORIZED, "AUTH_UNAUTHORIZED"),
        UserAuthError::UserDisabled => (StatusCode::UNAUTHORIZED, "AUTH_USER_DISABLED"),
        UserAuthError::UserInvalid => (StatusCode::UNAUTHORIZED, "AUTH_USER_INVALID"),
        UserAuthError::InsufficientRole => (StatusCode::FORBIDDEN, "AUTH_INSUFFICIENT_PRIVILEGE"),
        UserAuthError::Storage => (StatusCode::INTERNAL_SERVER_ERROR, "AUTH_INTERNAL_ERROR"),
    }
}

/// Call only with a previously authenticated identity's authoritative kind.
/// A valid PAT is not unauthorized; it only fails this separate session gate.
pub fn require_session(kind: CredentialKind) -> Result<(), (StatusCode, &'static str)> {
    match kind {
        CredentialKind::DashboardSession => Ok(()),
        CredentialKind::PersonalAccessToken => {
            Err((StatusCode::FORBIDDEN, "AUTH_SESSION_REQUIRED"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        headers
    }

    // No Debug bound, even on failing assertions; credentials never enter panic text.
    fn assert_credential(value: &str, bearer: bool, expected: &str) {
        let parsed = match parse_authorization(&headers(value)) {
            Ok(parsed) => parsed,
            Err(_) => panic!("expected parsed credential"),
        };
        let (is_bearer, token) = match parsed {
            AuthCredential::Bearer(token) => (true, token),
            AuthCredential::Raw(token) => (false, token),
        };
        assert!(is_bearer == bearer, "unexpected credential kind");
        assert!(token == expected, "credential bytes changed");
    }

    fn assert_error(headers: &HeaderMap, expected: AuthHeaderError) {
        match parse_authorization(headers) {
            Err(error) => assert_eq!(error, expected),
            Ok(_) => panic!("expected header classification error"),
        }
    }

    #[test]
    fn bearer_scheme_is_case_insensitive_and_tokens_are_opaque() {
        for scheme in ["Bearer", "BEARER", "bearer", "bEaReR"] {
            assert_credential(&format!("{scheme} opaque.+/="), true, "opaque.+/=");
        }
        assert_credential(
            "Bearer eyJhbGci.opaque.signature",
            true,
            "eyJhbGci.opaque.signature",
        );
        assert_credential(
            "eyJhbGci.opaque.signature",
            false,
            "eyJhbGci.opaque.signature",
        );
        assert_credential("opaque.+/=", false, "opaque.+/=");
    }

    #[test]
    fn scheme_separators_follow_go_but_token_bytes_are_preserved() {
        assert_credential(
            " \tBEARER\t \topaque +/=.\tend  ",
            true,
            "opaque +/=.\tend  ",
        );
        assert_credential("Bearer opaque  ", true, "opaque  ");
        assert_credential("  opaque.+/=\t", false, "  opaque.+/=\t");
        assert_credential("Bearerish", false, "Bearerish");
    }

    #[test]
    fn absent_empty_and_unsupported_headers_are_distinct() {
        assert_error(&HeaderMap::new(), AuthHeaderError::Missing);
        for value in ["", " \t ", "Bearer", "bearer \t"] {
            assert_error(&headers(value), AuthHeaderError::Empty);
        }
        for value in ["Basic abc", "Digest abc", "Token abc", "opaque another"] {
            assert_error(&headers(value), AuthHeaderError::Unsupported);
        }
        let mut invalid = HeaderMap::new();
        invalid.insert(
            AUTHORIZATION,
            HeaderValue::from_bytes(b"Bearer \xff").unwrap(),
        );
        assert_error(&invalid, AuthHeaderError::Unsupported);
    }

    #[test]
    fn duplicate_and_combined_headers_and_schemes_are_rejected() {
        let mut duplicate = headers("Bearer first");
        duplicate.append(AUTHORIZATION, HeaderValue::from_static("Bearer second"));
        assert_error(&duplicate, AuthHeaderError::Multiple);
        let mut duplicate_empty = headers("");
        duplicate_empty.append(AUTHORIZATION, HeaderValue::from_static("opaque"));
        assert_error(&duplicate_empty, AuthHeaderError::Multiple);
        for value in [
            "Bearer first, Bearer second",
            "first,second",
            "Bearer Bearer second",
            "Bearer bearer",
            "Bearer first BEARER second",
        ] {
            assert_error(&headers(value), AuthHeaderError::Multiple);
        }
    }

    #[test]
    fn diagnostic_path_contains_only_fixed_error_classes() {
        let input = headers("Basic never-log-this-secret");
        let diagnostic = match parse_authorization(&input) {
            Err(error) => format!("{error:?}"),
            Ok(_) => panic!("expected unsupported scheme"),
        };
        assert_eq!(diagnostic, "Unsupported");
        assert!(!diagnostic.contains("never-log-this-secret"));
        // AuthCredential intentionally has no Debug/Serialize implementation;
        // callers cannot format a successful Result with Debug accidentally.
    }

    #[test]
    fn user_auth_errors_have_fixed_status_and_code() {
        for (error, status, code) in [
            (
                UserAuthError::InvalidCredential,
                StatusCode::UNAUTHORIZED,
                "AUTH_UNAUTHORIZED",
            ),
            (
                UserAuthError::UserDisabled,
                StatusCode::UNAUTHORIZED,
                "AUTH_USER_DISABLED",
            ),
            (
                UserAuthError::UserInvalid,
                StatusCode::UNAUTHORIZED,
                "AUTH_USER_INVALID",
            ),
            (
                UserAuthError::InsufficientRole,
                StatusCode::FORBIDDEN,
                "AUTH_INSUFFICIENT_PRIVILEGE",
            ),
            (
                UserAuthError::Storage,
                StatusCode::INTERNAL_SERVER_ERROR,
                "AUTH_INTERNAL_ERROR",
            ),
        ] {
            assert_eq!(map_user_auth_error(error), (status, code));
        }
    }

    #[test]
    fn pat_is_forbidden_only_by_the_separate_session_gate() {
        assert_eq!(require_session(CredentialKind::DashboardSession), Ok(()));
        assert_eq!(
            require_session(CredentialKind::PersonalAccessToken),
            Err((StatusCode::FORBIDDEN, "AUTH_SESSION_REQUIRED")),
        );
        assert_eq!(
            map_user_auth_error(UserAuthError::InvalidCredential).0,
            StatusCode::UNAUTHORIZED,
        );
    }
}
