//! `POST /api/user/reset` — port of Go `identity.ResetPassword`
//! (`/root/newapi/apps/api/internal/identity/verify_email.go:133`).
//!
//! Route chain (Go `transport/compose/register_api.go:101`):
//! `CriticalRateLimit("CT")` → `AnonymousRequestBodyLimit` → handler.
//! There is no `UserAuth`, no `DisableCache` and no `TurnstileCheck`.
//!
//! Every business result is HTTP 200 with `{success,message}`; success also
//! carries `data` with the generated plaintext password. Storage failures
//! collapse to `common.database_error` and never expose SQL text.

use std::net::SocketAddr;

use axum::{
    Json,
    body::Bytes,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use newapi_identity::{
    password_reset::{
        GENERATED_PASSWORD_LENGTH, PasswordResetError, PasswordResetRepository,
        generate_verification_code, normalize_email,
    },
    registration::{PASSWORD_RESET_PURPOSE, delete_verification_code, verify_verification_code},
};
use serde::Deserialize;
use serde_json::json;

use crate::AppState;

/// Go `identity.PasswordResetRequest`（字段名即 JSON 键）。
#[derive(Deserialize, Default)]
struct ResetRequest {
    #[serde(default)]
    email: String,
    #[serde(default)]
    token: String,
}

/// Go `ResetPassword`：绑定 → 归一化 → 空值检查 → 验证码校验 → 生成新密码 →
/// 唯一邮箱重置 → 成功后删除验证码。验证码在用户查找失败时同样保留（与 Go
/// 一致：删除只发生在整条重置成功之后）。
pub async fn reset_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(repository) = state.db().map(PasswordResetRepository::new) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let request = match bind(&headers, &body) {
        Ok(request) => request,
        Err(()) => return invalid_params(&headers),
    };
    let email = normalize_email(&request.email);
    if email.is_empty() || request.token.is_empty() {
        return invalid_params(&headers);
    }
    if !verify_verification_code(PASSWORD_RESET_PURPOSE, &email, &request.token) {
        return rejected(translate(&headers, "user.password_reset_link_invalid"));
    }

    let password = generate_verification_code(GENERATED_PASSWORD_LENGTH);
    match repository.reset_by_email(&email, &password).await {
        Ok(()) => {
            // Go 仅在成功后 `DeleteKey`，验证码因此是一次性的。
            delete_verification_code(PASSWORD_RESET_PURPOSE, &email);
            Json(json!({
                "success": true,
                "message": "",
                "data": password,
            }))
            .into_response()
        }
        // Go 对缺失/歧义邮箱统一返回“链接非法”，不泄露账号是否存在。
        Err(PasswordResetError::EmailNotFound | PasswordResetError::EmailAmbiguous) => {
            rejected(translate(&headers, "user.password_reset_link_invalid"))
        }
        Err(PasswordResetError::InvalidInput | PasswordResetError::Storage) => {
            rejected(translate(&headers, "common.database_error"))
        }
    }
}

/// 重置路由中间件，按 Go 注册顺序复刻：
/// `CriticalRateLimit("CT")` → 匿名体上限。该路由没有 Turnstile，也没有
/// `DisableCache`，因此拒绝响应不带缓存头。
pub async fn reset_guard(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0);
    let ip = request_ip(&state, request.headers(), peer);
    match state
        .check_rate_limit("CT", &ip, crate::http::now_seconds())
        .await
    {
        Ok(None) => {}
        Ok(Some(retry_after)) => {
            let mut response = StatusCode::TOO_MANY_REQUESTS.into_response();
            if retry_after > 0
                && let Ok(value) = HeaderValue::from_str(&retry_after.to_string())
            {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            return response;
        }
        // Go 的 Redis 故障分支：500 + Abort。
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    crate::boundary_mw::anonymous_body_limit(state.anonymous_body_limit(), request, next).await
}

/// Go `UnmarshalBodyReusable`：非 JSON Content-Type 跳过解析并保持零值；
/// 空体保持零值；只有 JSON 解析失败才报绑定错误（与 register/login 移植一致，
/// 对外固定为 `common.invalid_params`）。
fn bind(headers: &HeaderMap, body: &[u8]) -> Result<ResetRequest, ()> {
    if !parses_as_json(headers) || body.is_empty() {
        return Ok(ResetRequest::default());
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

fn request_ip(state: &AppState, headers: &HeaderMap, peer: Option<SocketAddr>) -> String {
    let forwarded_for = joined_header(headers, header::HeaderName::from_static("x-forwarded-for"));
    let real_ip = joined_header(headers, header::HeaderName::from_static("x-real-ip"));
    state.client_ip(
        peer.map(|address| address.ip()),
        forwarded_for.as_deref(),
        real_ip.as_deref(),
    )
}

/// 对齐 fasthttp `Peek`：重复头的多个值按逗号合并。
fn joined_header(headers: &HeaderMap, name: header::HeaderName) -> Option<String> {
    let mut values = headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok());
    let first = values.next()?;
    Some(values.fold(first.to_owned(), |mut acc, value| {
        acc.push_str(", ");
        acc.push_str(value);
        acc
    }))
}

fn translate(headers: &HeaderMap, key: &str) -> String {
    let language = crate::request_lang::request_language(
        crate::request_lang::accept_language_header(headers).as_deref(),
    );
    newapi_i18n::translate(&language, key, std::iter::empty::<(&str, &str)>())
}

fn invalid_params(headers: &HeaderMap) -> Response {
    rejected(translate(headers, "common.invalid_params"))
}

fn rejected(message: String) -> Response {
    Json(json!({ "success": false, "message": message })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_json_or_empty_bodies_stay_at_zero_values() {
        assert!(
            bind(&HeaderMap::new(), b"")
                .expect("empty body")
                .email
                .is_empty()
        );
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        assert!(
            bind(&headers, br#"{"email":"a@example.com","token":"t"}"#)
                .expect("non-JSON is skipped")
                .email
                .is_empty()
        );
        assert!(bind(&HeaderMap::new(), b"{").is_err());
    }

    #[test]
    fn go_verbatim_messages() {
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT_LANGUAGE, HeaderValue::from_static("zh-CN"));
        assert_eq!(translate(&headers, "common.invalid_params"), "无效的参数");
        assert_eq!(
            translate(&headers, "user.password_reset_link_invalid"),
            "重置链接非法或已过期"
        );
    }
}
