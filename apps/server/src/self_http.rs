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

use axum::{
    Json,
    extract::{Extension, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use newapi_identity::{
    crypto::RefreshCredential,
    login::orchestrate::assemble_self_user,
    policy::{CasbinRuleRepository, denied_permissions, self_user_permissions},
    self_user::{Permissions, QuotaDisplaySettings},
    users::{UserProfile, UserProfileRepository},
};
use newapi_storage::Database;
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::AuthenticatedUser;
use crate::boundary_mw::disable_cache_headers;

const MSG_DATABASE_ERROR: &str = "common.database_error";
const MSG_GENERATE_FAILED: &str = "common.generate_failed";
const MSG_UUID_DUPLICATE: &str = "common.uuid_duplicate";

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
}
