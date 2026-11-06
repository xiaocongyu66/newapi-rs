//! `GET /api/user/self` and `GET /api/user/token` HTTP adapters.
//!
//! Go references:
//! - `apps/api/internal/identity/manage_users.go` (`GetSelf`, `buildSelfUserData`,
//!   `GenerateAccessToken`)
//! - `apps/api/internal/transport/compose/register_api.go` (route wiring)
//!
//! Authentication is provided by [`crate::auth::user_auth`]; this module only
//! assembles the response, rotates `users.access_token`, and suppresses cache
//! for the token endpoint. Database text and raw credentials never appear in a
//! response or a log line.

use std::collections::BTreeMap;

use axum::{
    Json,
    body::Bytes,
    extract::{Extension, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use newapi_identity::{
    AuthIdentity,
    crypto::{AuthKeys, RefreshCredential, hash_password, verify_password},
    login::orchestrate::assemble_self_user,
    policy::{CasbinRuleRepository, denied_permissions, self_user_permissions},
    self_user::{Permissions, QuotaDisplaySettings},
    users::{SessionAdvance, UserMutationError, UserProfile, UserProfileRepository, UserSetting},
};
use newapi_storage::Database;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::{AuthCredential, AuthenticatedUser, parse_authorization};
use crate::boundary_mw::disable_cache_headers;

const MSG_DATABASE_ERROR: &str = "common.database_error";
const MSG_GENERATE_FAILED: &str = "common.generate_failed";
const MSG_UUID_DUPLICATE: &str = "common.uuid_duplicate";
const MSG_INVALID_PARAMS: &str = "common.invalid_params";
const MSG_INVALID_INPUT: &str = "common.invalid_input";
const MSG_UPDATE_SUCCESS: &str = "common.update_success";
const MSG_UPDATE_FAILED: &str = "common.update_failed";
const MSG_PASSWORD_UNSET: &str = "user.password_unset";
const MSG_ORIGINAL_PASSWORD_ERROR: &str = "user.original_password_error";
const MSG_CANNOT_DELETE_ROOT_USER: &str = "user.cannot_delete_root_user";
// Go 在该分支返回裸错误文本 `当前认证方式不支持安全验证`；对应 i18n key 尚不存在。
const MSG_SESSION_REQUIRED: &str = "auth.session_required";

/// Go `common.RoleRootUser`.
const ROLE_ROOT_USER: i64 = 100;
/// Go `User.Password` 的空值占位，仅用于让 validator 通过。
const PASSWORD_PLACEHOLDER: &str = "$I_LOVE_U";

/// Go `identity.User` 的请求 JSON 形状。只为复刻 `encoding/json` 的类型错误与
/// `validate` 标签；实际写库字段仅用户名、密码、昵称。
#[allow(dead_code)]
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct UpdateSelfRequest {
    id: Option<i64>,
    username: Option<String>,
    password: Option<String>,
    original_password: Option<String>,
    display_name: Option<String>,
    role: Option<i64>,
    status: Option<i64>,
    email: Option<String>,
    github_id: Option<String>,
    discord_id: Option<String>,
    oidc_id: Option<String>,
    wechat_id: Option<String>,
    telegram_id: Option<String>,
    verification_code: Option<String>,
    quota: Option<i64>,
    used_quota: Option<i64>,
    quota_display: Option<f64>,
    used_quota_display: Option<f64>,
    aff_quota_display: Option<f64>,
    aff_history_quota_display: Option<f64>,
    request_count: Option<i64>,
    group: Option<String>,
    aff_code: Option<String>,
    aff_count: Option<i64>,
    aff_quota: Option<i64>,
    aff_history_quota: Option<i64>,
    inviter_id: Option<i64>,
    linux_do_id: Option<String>,
    setting: Option<String>,
    remark: Option<String>,
    stripe_customer: Option<String>,
    created_at: Option<i64>,
    last_login_at: Option<i64>,
    admin_permissions: Option<BTreeMap<String, BTreeMap<String, bool>>>,
    qq_open_id: Option<String>,
}

/// Go `UpdateSelf`: setting/language branches, profile update, and password
/// rotation. Every business outcome is HTTP 200 with the Go envelope; the
/// `DisableCache` headers are written here for all outcomes.
pub async fn update_self(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let mut response = update_self_inner(&state, &auth_user, &headers, &body).await;
    disable_cache_headers(&mut response);
    response
}

/// Go `DeleteSelf`: soft delete, auth-version bump, session revocation. The Go
/// route has no `DisableCache`, so no cache headers are written.
pub async fn delete_self(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let repository = UserProfileRepository::new(db.clone());
    let role = match repository.by_id(auth_user.0.user_id).await {
        Ok(Some(profile)) => profile.role,
        // Go ignores this lookup error and fails later in the delete
        // transaction; the fixed database classification is equivalent and
        // never leaks SQL text.
        _ => return api_error(&headers, MSG_DATABASE_ERROR),
    };
    if role == ROLE_ROOT_USER {
        return api_error(&headers, MSG_CANNOT_DELETE_ROOT_USER);
    }
    match repository
        .soft_delete(auth_user.0.user_id, crate::http::now_seconds())
        .await
    {
        Ok(()) => Json(json!({"success": true, "message": ""})).into_response(),
        Err(error) => mutation_error_response(&headers, error),
    }
}

async fn update_self_inner(
    state: &AppState,
    auth_user: &AuthenticatedUser,
    headers: &HeaderMap,
    body: &[u8],
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let value: Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(_) => return api_error(headers, MSG_INVALID_PARAMS),
    };
    // Go `json.Unmarshal(null, &map)` succeeds with a nil map; every other
    // non-object top level is an unmarshal error.
    let object = match value {
        Value::Null => serde_json::Map::new(),
        Value::Object(object) => object,
        _ => return api_error(headers, MSG_INVALID_PARAMS),
    };
    let repository = UserProfileRepository::new(db.clone());
    if let Some(modules) = object.get("sidebar_modules") {
        return update_setting_field(
            &repository,
            headers,
            auth_user.0.user_id,
            SettingField::SidebarModules,
            modules,
        )
        .await;
    }
    if let Some(language) = object.get("language") {
        return update_setting_field(
            &repository,
            headers,
            auth_user.0.user_id,
            SettingField::Language,
            language,
        )
        .await;
    }
    let request: UpdateSelfRequest = match serde_json::from_value(Value::Object(object)) {
        Ok(request) => request,
        Err(_) => return api_error(headers, MSG_INVALID_PARAMS),
    };
    if !validate_update_request(&request) {
        return api_error(headers, MSG_INVALID_INPUT);
    }
    let username = request.username.unwrap_or_default();
    let display_name = request.display_name.unwrap_or_default();
    let password = request.password.unwrap_or_default();
    // Go rolls the placeholder back to empty, so a literal "$I_LOVE_U" cannot
    // change the password either.
    let password = if password == PASSWORD_PLACEHOLDER {
        String::new()
    } else {
        password
    };
    let original_password = request.original_password.unwrap_or_default();
    if password.is_empty() {
        return match repository
            .update_profile(auth_user.0.user_id, &username, &display_name)
            .await
        {
            Ok(()) => Json(json!({"success": true, "message": ""})).into_response(),
            Err(error) => mutation_error_response(headers, error),
        };
    }
    update_password(
        state,
        &repository,
        auth_user,
        headers,
        &original_password,
        &username,
        &display_name,
        &password,
    )
    .await
}

#[derive(Clone, Copy)]
enum SettingField {
    SidebarModules,
    Language,
}

async fn update_setting_field(
    repository: &UserProfileRepository,
    headers: &HeaderMap,
    user_id: i64,
    field: SettingField,
    value: &Value,
) -> Response {
    let profile = match repository.by_id(user_id).await {
        Ok(Some(profile)) => profile,
        _ => return api_error(headers, MSG_DATABASE_ERROR),
    };
    let mut setting = UserSetting::from_json(&profile.setting);
    // Go only assigns string values; any other JSON type still rewrites the
    // unchanged settings object and reports success.
    if let Some(text) = value.as_str() {
        match field {
            SettingField::SidebarModules => setting.sidebar_modules = text.to_owned(),
            SettingField::Language => setting.language = text.to_owned(),
        }
    }
    if repository
        .update_setting(user_id, &setting.to_json())
        .await
        .is_err()
    {
        return api_error(headers, MSG_UPDATE_FAILED);
    }
    Json(json!({
        "success": true,
        "message": translate(headers, MSG_UPDATE_SUCCESS),
        "data": Value::Null,
    }))
    .into_response()
}

/// Go `Validate.Struct(&user)` tags: username/display_name max 20, password
/// 8..20 (the empty-value placeholder is 9 characters), email max 50,
/// remark max 255. Go counts Unicode code points.
fn validate_update_request(request: &UpdateSelfRequest) -> bool {
    let password = request.password.as_deref().unwrap_or_default();
    let password = if password.is_empty() {
        PASSWORD_PLACEHOLDER
    } else {
        password
    };
    let within = |value: &str, max: usize| value.chars().count() <= max;
    within(request.username.as_deref().unwrap_or_default(), 20)
        && (8..=20).contains(&password.chars().count())
        && within(request.display_name.as_deref().unwrap_or_default(), 20)
        && within(request.email.as_deref().unwrap_or_default(), 50)
        && within(request.remark.as_deref().unwrap_or_default(), 255)
}

#[allow(clippy::too_many_arguments)]
async fn update_password(
    state: &AppState,
    repository: &UserProfileRepository,
    auth_user: &AuthenticatedUser,
    headers: &HeaderMap,
    original_password: &str,
    username: &str,
    display_name: &str,
    password: &str,
) -> Response {
    let user_id = auth_user.0.user_id;
    let stored = match repository.password_hash(user_id).await {
        Ok(Some(stored)) => stored,
        _ => return api_error(headers, MSG_DATABASE_ERROR),
    };
    if stored.is_empty() {
        return api_error(headers, MSG_PASSWORD_UNSET);
    }
    // Go `ValidatePasswordAndHash` collapses every bcrypt failure to false.
    if !matches!(
        verify_password(original_password.as_bytes(), &stored),
        Ok(true)
    ) {
        return api_error(headers, MSG_ORIGINAL_PASSWORD_ERROR);
    }
    let now = crate::http::now_seconds();
    let Some(identity) = request_session_identity(state, headers, user_id, now) else {
        return api_error(headers, MSG_SESSION_REQUIRED);
    };
    let password_hash = match hash_password(password.as_bytes()) {
        Ok(hash) => hash,
        Err(_) => return api_error(headers, MSG_DATABASE_ERROR),
    };
    let next_version = match repository
        .update_password(
            user_id,
            password_hash.expose_secret(),
            username,
            display_name,
        )
        .await
    {
        Ok(version) => version,
        Err(error) => return mutation_error_response(headers, error),
    };
    // Go `AdvanceCurrentSessionToUserVersion` rejects a cache/row state that
    // did not actually advance past the presented version.
    if next_version <= identity.user_auth_version {
        return api_error(headers, MSG_DATABASE_ERROR);
    }
    let projection = match repository
        .advance_session_auth_version(SessionAdvance {
            user_id,
            sid: &identity.sid,
            expected_session_version: identity.session_version,
            expected_user_auth_version: identity.user_auth_version,
            next_user_auth_version: next_version,
            now,
        })
        .await
    {
        Ok(projection) => projection,
        Err(error) => return mutation_error_response(headers, error),
    };
    let Some(auth) = state.auth() else {
        return api_error(headers, MSG_DATABASE_ERROR);
    };
    if auth.revoke_others(&identity, now).await.is_err() {
        return api_error(headers, MSG_DATABASE_ERROR);
    }
    let Some(keys) = session_keys(state) else {
        return api_error(headers, MSG_DATABASE_ERROR);
    };
    let new_identity = AuthIdentity {
        user_id,
        sid: identity.sid,
        user_auth_version: next_version,
        session_version: identity.session_version + 1,
    };
    let issued = match keys.issue_access(&new_identity, now) {
        Ok(issued) => issued,
        Err(_) => return api_error(headers, MSG_DATABASE_ERROR),
    };
    Json(json!({
        "success": true,
        "message": "",
        "data": {
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
        },
    }))
    .into_response()
}

/// Recover the validated session identity from the request's dashboard JWT.
/// A personal access token is not a browser session, exactly like Go
/// `ReadSessionAuthIdentity` returning false.
fn request_session_identity(
    state: &AppState,
    headers: &HeaderMap,
    user_id: i64,
    now: i64,
) -> Option<AuthIdentity> {
    let credential = parse_authorization(headers).ok()?;
    let token = match credential {
        AuthCredential::Bearer(token) | AuthCredential::Raw(token) => token,
    };
    let identity = state.auth()?.parse_access(&token, now).ok()?;
    (identity.user_id == user_id).then_some(identity)
}

/// `AppState::flow_key` is `auth-flow-v1:` + `SESSION_SECRET`; the access-token
/// signer derives from the same secret. Missing keys fail closed.
fn session_keys(state: &AppState) -> Option<AuthKeys> {
    let secret = state.flow_key()?.strip_prefix(b"auth-flow-v1:")?;
    std::str::from_utf8(secret).ok().map(AuthKeys::new)
}

fn mutation_error_response(headers: &HeaderMap, error: UserMutationError) -> Response {
    if let UserMutationError::Storage(sqlx_error) = error {
        tracing::warn!(
            event = "self_user_mutation_failed",
            category = crate::database_error_class(&sqlx_error),
            "self user mutation failed"
        );
    }
    api_error(headers, MSG_DATABASE_ERROR)
}

/// `users.access_token` is `CHAR(32)` upstream; keep generated tokens inside
/// that width. The generator reuses the OsRng-backed credential helper so the
/// server crate needs no extra randomness dependency.
const ACCESS_TOKEN_LEN: usize = 32;

/// Go `GetSelf`: `buildSelfUserData` flat profile plus the permissions object.
/// Capabilities use the authenticated role, exactly like Go's override of the
/// row-derived permissions with `c.Role`.
pub async fn self_user(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let user_id = auth_user.0.user_id;
    let profile = match UserProfileRepository::new(db.clone()).by_id(user_id).await {
        Ok(Some(profile)) => profile,
        Ok(None) => return api_error(&headers, MSG_DATABASE_ERROR),
        Err(error) => {
            tracing::warn!(
                event = "self_profile_load_failed",
                category = crate::database_error_class(&error),
                "self profile load failed"
            );
            return api_error(&headers, MSG_DATABASE_ERROR);
        }
    };
    let permissions = match self_user_permissions(
        &CasbinRuleRepository::new(db),
        user_id,
        auth_user.0.role as i32,
    )
    .await
    {
        Ok(permissions) => permissions,
        Err(error) => {
            // Go `Capabilities()` never returns an error: an unreadable
            // policy behaves like an empty enforcer and denies everything.
            tracing::warn!(
                event = "self_permissions_load_failed",
                category = crate::database_error_class(&error),
                "self permission load failed; denying all permissions"
            );
            denied_permissions(auth_user.0.role as i32)
        }
    };
    match self_user_body(profile, permissions, state.quota_display()) {
        Ok(body) => Json(body).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// Go `GenerateAccessToken`: rotate the caller's personal access token and
/// return the new opaque value. `DisableCache` applies to every outcome,
/// including the Go `CtxApiError*` style HTTP 200 error bodies.
pub async fn access_token(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
) -> Response {
    let mut response = match state.db() {
        Some(db) => match rotate_access_token(&db, auth_user.0.user_id).await {
            Ok(token) => Json(success_body(Value::String(token))).into_response(),
            Err(error) => {
                Json(error_body(&translate(&headers, error.message_key()))).into_response()
            }
        },
        None => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    disable_cache_headers(&mut response);
    response
}

/// Pure Go `buildSelfUserData` assembly. Kept separate so the response shape is
/// testable without routing or a database.
pub fn self_user_body(
    profile: UserProfile,
    permissions: Permissions,
    display: QuotaDisplaySettings,
) -> Result<Value, serde_json::Error> {
    let user = assemble_self_user(profile, permissions, display);
    Ok(success_body(serde_json::to_value(user)?))
}

/// Go `common.H{"success": true, "message": "", "data": ...}`.
pub fn success_body(data: Value) -> Value {
    json!({
        "success": true,
        "message": "",
        "data": data,
    })
}

/// Go `CtxApiError*` / `CtxApiSuccess` error shape: HTTP 200 plus a message.
pub fn error_body(message: &str) -> Value {
    json!({
        "success": false,
        "message": message,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TokenError {
    Generate,
    Duplicate,
    Storage,
}

impl TokenError {
    fn message_key(self) -> &'static str {
        match self {
            Self::Generate => MSG_GENERATE_FAILED,
            Self::Duplicate => MSG_UUID_DUPLICATE,
            Self::Storage => MSG_DATABASE_ERROR,
        }
    }
}

async fn rotate_access_token(db: &Database, user_id: i64) -> Result<String, TokenError> {
    let token = generate_access_token().ok_or(TokenError::Generate)?;
    // Go checks uniqueness before updating and returns the duplicate message
    // without retrying.
    if access_token_exists(db, &token).await.map_err(|error| {
        tracing::warn!(
            event = "access_token_duplicate_check_failed",
            category = crate::database_error_class(&error),
            "access token uniqueness check failed"
        );
        TokenError::Storage
    })? {
        return Err(TokenError::Duplicate);
    }
    let affected = update_access_token(db, user_id, &token)
        .await
        .map_err(|error| {
            tracing::warn!(
                event = "access_token_update_failed",
                category = crate::database_error_class(&error),
                "access token update failed"
            );
            TokenError::Storage
        })?;
    // Go `UpdateUserAccessToken` treats zero affected rows as not found and
    // reports it through `CtxApiError`; the Rust boundary keeps only the fixed
    // database-error classification.
    if affected == 0 {
        return Err(TokenError::Storage);
    }
    Ok(token)
}

fn generate_access_token() -> Option<String> {
    let credential = RefreshCredential::generate().ok()?;
    let token: String = credential.secret().chars().take(ACCESS_TOKEN_LEN).collect();
    (token.len() == ACCESS_TOKEN_LEN).then_some(token)
}

async fn access_token_exists(db: &Database, token: &str) -> Result<bool, sqlx::Error> {
    let count: i64 = match db {
        Database::Sqlite(pool) => {
            sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE access_token=$1")
                .bind(token)
                .fetch_one(pool)
                .await?
        }
        Database::Postgres(pool) => {
            sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE access_token=$1")
                .bind(token)
                .fetch_one(pool)
                .await?
        }
    };
    Ok(count != 0)
}

async fn update_access_token(db: &Database, user_id: i64, token: &str) -> Result<u64, sqlx::Error> {
    let affected = match db {
        Database::Sqlite(pool) => sqlx::query("UPDATE users SET access_token=$1 WHERE id=$2")
            .bind(token)
            .bind(user_id)
            .execute(pool)
            .await?
            .rows_affected(),
        Database::Postgres(pool) => sqlx::query("UPDATE users SET access_token=$1 WHERE id=$2")
            .bind(token)
            .bind(user_id)
            .execute(pool)
            .await?
            .rows_affected(),
    };
    Ok(affected)
}

fn translate(headers: &HeaderMap, key: &str) -> String {
    let accept_language = crate::request_lang::accept_language_header(headers);
    let language = crate::request_lang::request_language(accept_language.as_deref());
    newapi_i18n::translate(&language, key, std::iter::empty::<(&str, &str)>())
}

fn api_error(headers: &HeaderMap, key: &str) -> Response {
    Json(error_body(&translate(headers, key))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use newapi_identity::self_user::QuotaDisplayKind;
    use serde_json::json;

    fn profile() -> UserProfile {
        UserProfile {
            id: 7,
            username: "fixture".into(),
            display_name: "Fixture".into(),
            role: 1,
            status: 1,
            email: String::new(),
            github_id: String::new(),
            discord_id: String::new(),
            oidc_id: String::new(),
            wechat_id: String::new(),
            telegram_id: String::new(),
            group: "default".into(),
            quota: 500_000,
            used_quota: 0,
            request_count: 0,
            aff_code: String::new(),
            aff_count: 0,
            aff_quota: 0,
            aff_history_quota: 0,
            inviter_id: 0,
            linux_do_id: String::new(),
            setting: r#"{"sidebar_modules":"personal"}"#.into(),
            stripe_customer: String::new(),
            auth_version: 1,
        }
    }

    #[test]
    fn self_body_flattens_profile_and_keeps_permissions_separate() {
        let body = self_user_body(
            profile(),
            denied_permissions(1),
            QuotaDisplaySettings {
                quota_per_unit: 500_000.0,
                kind: QuotaDisplayKind::Usd,
            },
        )
        .expect("serialize self body");
        assert_eq!(body["success"], json!(true));
        assert_eq!(body["message"], json!(""));
        assert_eq!(body["data"]["id"], json!(7));
        assert_eq!(body["data"]["quota_display"], json!(1.0));
        assert_eq!(body["data"]["sidebar_modules"], json!("personal"));
        // Go 普通用户的降级形状：可设置侧栏、管理员区域关闭，权限矩阵
        // 保持完整但全部为 false。
        let permissions = &body["data"]["permissions"];
        assert_eq!(permissions["sidebar_settings"], json!(true));
        assert_eq!(permissions["sidebar_modules"], json!({"admin": false}));
        let matrix = permissions["admin_permissions"]
            .as_object()
            .expect("resource matrix");
        assert!(!matrix.is_empty());
        for (resource, actions) in matrix {
            for (action, allowed) in actions.as_object().expect("actions") {
                assert_eq!(allowed, &json!(false), "{resource}.{action}");
            }
        }
        for forbidden in ["password", "access_token", "auth_version", "remark"] {
            assert!(body["data"].get(forbidden).is_none(), "{forbidden}");
        }
    }

    #[test]
    fn envelopes_match_go_shapes() {
        assert_eq!(
            success_body(json!("opaque")),
            json!({"success": true, "message": "", "data": "opaque"})
        );
        assert_eq!(
            error_body("failed"),
            json!({"success": false, "message": "failed"})
        );
    }

    #[test]
    fn generated_access_token_fits_the_column_width() {
        let token = generate_access_token().expect("OS randomness");
        assert_eq!(token.len(), ACCESS_TOKEN_LEN);
        assert!(token.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    fn request(password: &str) -> UpdateSelfRequest {
        UpdateSelfRequest {
            password: Some(password.to_owned()),
            ..UpdateSelfRequest::default()
        }
    }

    #[test]
    fn password_validation_matches_go_runes_and_placeholder() {
        // Empty password validates through the 9-character placeholder.
        assert!(validate_update_request(&UpdateSelfRequest::default()));
        assert!(validate_update_request(&request("$I_LOVE_U")));
        assert!(!validate_update_request(&request("short")));
        assert!(validate_update_request(&request("12345678")));
        assert!(validate_update_request(&request("12345678901234567890")));
        assert!(!validate_update_request(&request("123456789012345678901")));
    }

    #[test]
    fn profile_field_limits_match_go_validate_tags() {
        let mut value = UpdateSelfRequest {
            username: Some("u".repeat(20)),
            ..UpdateSelfRequest::default()
        };
        assert!(validate_update_request(&value));
        value.username = Some("u".repeat(21));
        assert!(!validate_update_request(&value));
        value.username = None;
        value.display_name = Some("d".repeat(20));
        assert!(validate_update_request(&value));
        value.display_name = Some("d".repeat(21));
        assert!(!validate_update_request(&value));
        value.display_name = None;
        value.email = Some("e".repeat(50));
        assert!(validate_update_request(&value));
        value.email = Some("e".repeat(51));
        assert!(!validate_update_request(&value));
        value.email = None;
        value.remark = Some("r".repeat(255));
        assert!(validate_update_request(&value));
        value.remark = Some("r".repeat(256));
        assert!(!validate_update_request(&value));
    }
}
