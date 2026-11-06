//! `POST /api/user/register` — port of Go `identity.Register`
//! (`/root/newapi/apps/api/internal/identity/manage_users.go:209`).
//!
//! Route chain (Go `transport/compose/register_api.go:129`):
//! `CriticalRateLimit("CT")` → `AnonymousRequestBodyLimit` →
//! `TurnstileCheck` → handler. Register has no `DisableCache`, so neither the
//! guard's rejections nor the handler's responses carry cache headers.
//!
//! Every business result is HTTP 200 with `{success,message}`. Database text
//! never reaches the client; storage failures collapse to
//! `common.database_error`.
//!
//! Deliberate gaps, reported rather than faked:
//! - `GENERATE_DEFAULT_TOKEN` has no Rust configuration yet, so no default
//!   token is created (Go defaults this switch to off).
//! - Go's post-create `finishInsert` sidebar initialization is not ported;
//!   `setting` keeps the value `User.Insert` itself writes.

use std::net::SocketAddr;

use axum::{
    Json,
    body::{Body, Bytes, to_bytes},
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use newapi_identity::{
    crypto::hash_password,
    registration::{
        NewUser, RegistrationError, RegistrationRepository, verify_email_verification_code,
    },
};
use serde::Deserialize;
use serde_json::json;

use crate::AppState;
use crate::login_http::ClientIp;

/// Go `UserNameMaxLength = 20`（validator `max` 按字符/符文计数）。
const MAX_USERNAME_CHARS: usize = 20;
/// Go `User.Password` 的 `validate:"min=8,max=20"`。
const MIN_PASSWORD_CHARS: usize = 8;
const MAX_PASSWORD_CHARS: usize = 20;
/// Go `User.Email` 的 `validate:"max=50"`。
const MAX_EMAIL_CHARS: usize = 50;
/// Go `User.DisplayName` 的 `validate:"max=20"`。
const MAX_DISPLAY_NAME_CHARS: usize = 20;
/// Go `User.Remark` 的 `validate:"max=255"`。
const MAX_REMARK_CHARS: usize = 255;

/// Go `User` 的 JSON 绑定字段（snake_case，无自定义 tag）。`role`/`status`
/// 等字段虽可绑定，但注册只采用用户名、密码、邮箱、验证码与邀请码。
#[derive(Deserialize, Default)]
struct RegisterRequest {
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    verification_code: String,
    #[serde(default)]
    aff_code: String,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    remark: String,
}

impl RegisterRequest {
    /// Go `strings.TrimSpace(user.Username)` + `NormalizeEmail`。邮箱在开关
    /// 关闭时同样归一化/校验，随后才被忽略。
    fn normalize(&mut self) {
        self.username = self.username.trim().to_owned();
        self.email = self.email.trim().to_lowercase();
    }
}

/// Go `Validate.Struct(&User)` 的字段顺序与 `go-playground/validator` 文案。
/// `User` 的校验 tag 只覆盖 Username/Password/DisplayName/Email/Remark。
fn validation_error(request: &RegisterRequest) -> Option<String> {
    let mut errors = Vec::new();
    if request.username.chars().count() > MAX_USERNAME_CHARS {
        errors.push(field_error("Username", "max"));
    }
    let password_chars = request.password.chars().count();
    if password_chars < MIN_PASSWORD_CHARS {
        errors.push(field_error("Password", "min"));
    }
    if password_chars > MAX_PASSWORD_CHARS {
        errors.push(field_error("Password", "max"));
    }
    if request.display_name.chars().count() > MAX_DISPLAY_NAME_CHARS {
        errors.push(field_error("DisplayName", "max"));
    }
    if request.email.chars().count() > MAX_EMAIL_CHARS {
        errors.push(field_error("Email", "max"));
    }
    if request.remark.chars().count() > MAX_REMARK_CHARS {
        errors.push(field_error("Remark", "max"));
    }
    (!errors.is_empty()).then(|| errors.join("\n"))
}

fn field_error(field: &str, tag: &str) -> String {
    format!("Key: 'User.{field}' Error:Field validation for '{field}' failed on the '{tag}' tag")
}

/// Go `Register`：开关 → 绑定 → 归一化/校验 → 邮箱验证 → 唯一性 → 邀请人 →
/// 创建。`state.auth_settings()` 是请求开始时的一致快照。
pub async fn register(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let settings = state.auth_settings();
    if !settings.register_enabled {
        return rejected(translate(&headers, "user.register_disabled"));
    }
    if !settings.password_register_enabled {
        return rejected(translate(&headers, "user.password_register_disabled"));
    }
    let Some(repository) = repository(&state) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let mut request = match bind(&headers, &body) {
        Ok(request) => request,
        Err(()) => return invalid_params(&headers),
    };
    request.normalize();
    if request.username.is_empty() {
        return invalid_params(&headers);
    }
    if let Some(error) = validation_error(&request) {
        return rejected(translate_args(
            &headers,
            "user.input_invalid",
            [("Error", error)],
        ));
    }

    let email_verification = settings.email_verification_enabled;
    if email_verification {
        if request.email.is_empty() || request.verification_code.is_empty() {
            return rejected(translate(&headers, "user.email_verification_required"));
        }
        if !verify_email_verification_code(&request.email, &request.verification_code) {
            return rejected(translate(&headers, "user.verification_code_error"));
        }
        match repository.email_taken(&request.email).await {
            Ok(false) => {}
            Ok(true) => return rejected(translate(&headers, "user.email_already_taken")),
            Err(_) => return rejected(translate(&headers, "common.database_error")),
        }
    }

    let email_for_exist_check = if email_verification {
        request.email.as_str()
    } else {
        ""
    };
    match repository
        .username_or_email_taken(&request.username, email_for_exist_check)
        .await
    {
        Ok(false) => {}
        Ok(true) => return rejected(translate(&headers, "user.exists")),
        Err(_) => return rejected(translate(&headers, "common.database_error")),
    }

    // Go `GetUserIdByAffCode` 的错误被忽略，未命中即 `inviterId=0`。
    let inviter_id = match repository.aff_code_owner(&request.aff_code).await {
        Ok(Some(id)) => id,
        Ok(None) | Err(_) => 0,
    };

    let password_hash = match hash_password(request.password.as_bytes()) {
        Ok(hash) => hash.expose_secret().to_owned(),
        // Go 在事务内散列并走 `CtxApiError`；这里同样对外只报固定分类。
        Err(_) => return rejected(translate(&headers, "common.database_error")),
    };
    let email = if email_verification {
        request.email.clone()
    } else {
        String::new()
    };
    let draft = NewUser {
        username: request.username.clone(),
        password_hash,
        display_name: request.username,
        email,
        inviter_id,
        created_at: crate::http::now_seconds(),
    };
    match repository.create(draft).await {
        Ok(_) => success(),
        Err(RegistrationError::EmailTaken) => {
            rejected(translate(&headers, "user.email_already_taken"))
        }
        Err(RegistrationError::Storage) => rejected(translate(&headers, "common.database_error")),
    }
}

/// 注册路由中间件，按 Go 注册顺序复刻：
/// `CriticalRateLimit("CT")` → 匿名体上限 → `TurnstileCheck`。
/// 注册路由没有 `DisableCache`，因此任何拒绝都不带缓存头。
pub async fn register_guard(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0);
    let ip = request_ip(&state, request.headers(), peer);
    let now = crate::http::now_seconds();
    match state.check_rate_limit("CT", &ip, now).await {
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
    match read_limited_body(state.anonymous_body_limit(), request).await {
        Err(status) => status.into_response(),
        Ok(mut request) => {
            // Go 的 `TurnstileCheck` 位于体限制之后：关闭检查或空 token 时
            // 不构造/调用传输层；开启且有 token 时使用共享 HTTP 客户端。
            let auth = state.auth_settings();
            let enabled = auth.turnstile_check_enabled;
            let token = crate::turnstile::query_token(request.uri().query());
            let decision = if !enabled || token.is_none() {
                crate::turnstile::decide(enabled, token.as_deref(), "", None, None).await
            } else {
                let injected = request
                    .extensions()
                    .get::<crate::turnstile::InjectedVerifier>()
                    .cloned();
                let http = crate::turnstile::HttpVerifier;
                let verifier: &dyn crate::turnstile::Verifier = match injected.as_ref() {
                    Some(injected) => injected.0.as_ref(),
                    None => &http,
                };
                crate::turnstile::decide(
                    true,
                    token.as_deref(),
                    &auth.turnstile_secret_key,
                    Some(ip.as_str()),
                    Some(verifier),
                )
                .await
            };
            request.extensions_mut().insert(ClientIp(ip));
            match decision.rejection_key() {
                Some(key) => rejected(translate(request.headers(), key)),
                None => next.run(request).await,
            }
        }
    }
}

/// Go `AnonymousRequestBodyLimit`：先看声明的 Content-Length，再以
/// `limit + 1` 预算读取实际体；超限返回裸 413。`limit == 0` 为未启用。
async fn read_limited_body(limit: usize, request: Request) -> Result<Request, StatusCode> {
    if limit == 0 {
        return Ok(request);
    }
    let declared = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if declared.is_some_and(|declared| declared > limit as u64) {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    if declared.is_none_or(|declared| declared == 0) {
        return Ok(request);
    }
    let (parts, body) = request.into_parts();
    match to_bytes(body, limit.saturating_add(1)).await {
        Ok(bytes) if bytes.len() <= limit => Ok(Request::from_parts(parts, Body::from(bytes))),
        Ok(_) | Err(_) => Err(StatusCode::PAYLOAD_TOO_LARGE),
    }
}

/// Go `UnmarshalBodyReusable`：非 JSON Content-Type 或空体保持零值；只有声明
/// 为 JSON 且解析失败才报绑定错误。
fn bind(headers: &HeaderMap, body: &[u8]) -> Result<RegisterRequest, ()> {
    if !parses_as_json(headers) || body.is_empty() {
        return Ok(RegisterRequest::default());
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

fn repository(state: &AppState) -> Option<RegistrationRepository> {
    state.db().map(RegistrationRepository::new)
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

fn language(headers: &HeaderMap) -> String {
    crate::request_lang::request_language(
        crate::request_lang::accept_language_header(headers).as_deref(),
    )
}

fn translate(headers: &HeaderMap, key: &str) -> String {
    newapi_i18n::translate(&language(headers), key, std::iter::empty::<(&str, &str)>())
}

fn translate_args<I, K, V>(headers: &HeaderMap, key: &str, args: I) -> String
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: std::fmt::Display,
{
    newapi_i18n::translate(&language(headers), key, args)
}

fn invalid_params(headers: &HeaderMap) -> Response {
    rejected(translate(headers, "common.invalid_params"))
}

fn rejected(message: String) -> Response {
    Json(json!({ "success": false, "message": message })).into_response()
}

fn success() -> Response {
    Json(json!({ "success": true, "message": "" })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(username: &str, password: &str) -> RegisterRequest {
        RegisterRequest {
            username: username.to_owned(),
            password: password.to_owned(),
            ..RegisterRequest::default()
        }
    }

    #[test]
    fn username_validation_uses_char_count_not_bytes() {
        // 20 个 CJK 字符是 60 字节，但 Go validator 按符文计数放行。
        let twenty = "用".repeat(20);
        assert_eq!(validation_error(&request(&twenty, "secret123")), None);
        let twenty_one = "用".repeat(21);
        assert_eq!(
            validation_error(&request(&twenty_one, "secret123")),
            Some(field_error("Username", "max")),
        );
    }

    #[test]
    fn password_bounds_match_the_struct_tags() {
        assert_eq!(
            validation_error(&request("user", "1234567")),
            Some(field_error("Password", "min")),
        );
        assert_eq!(
            validation_error(&request("user", &"x".repeat(21))),
            Some(field_error("Password", "max")),
        );
        assert_eq!(validation_error(&request("user", &"x".repeat(20))), None);
    }

    #[test]
    fn multiple_failures_join_in_struct_field_order() {
        let mut request = request(&"u".repeat(21), "short");
        request.email = format!("{}@example.com", "e".repeat(40));
        assert_eq!(
            validation_error(&request),
            Some(
                [
                    field_error("Username", "max"),
                    field_error("Password", "min"),
                    field_error("Email", "max"),
                ]
                .join("\n")
            ),
        );
    }

    #[test]
    fn normalized_username_and_email_follow_go() {
        let mut request = RegisterRequest {
            username: " \tfixture \n".to_owned(),
            email: "  MiXeD@Example.COM ".to_owned(),
            ..RegisterRequest::default()
        };
        request.normalize();
        assert_eq!(request.username, "fixture");
        assert_eq!(request.email, "mixed@example.com");
    }

    #[test]
    fn non_json_or_empty_bodies_stay_at_zero_values() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        let parsed = bind(&headers, br#"{"username":"user","password":"secret123"}"#)
            .expect("skip is not an error");
        assert!(parsed.username.is_empty());
        assert!(
            bind(&HeaderMap::new(), b"")
                .expect("empty body")
                .username
                .is_empty()
        );
        assert!(bind(&HeaderMap::new(), b"{").is_err());
    }

    #[test]
    fn translated_messages_match_go_verbatim() {
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT_LANGUAGE, HeaderValue::from_static("zh-CN"));
        assert_eq!(
            translate(&headers, "user.register_disabled"),
            "管理员关闭了新用户注册"
        );
        assert_eq!(
            translate(&headers, "user.password_register_disabled"),
            "管理员关闭了通过密码进行注册，请使用第三方账户验证的形式进行注册",
        );
        assert_eq!(translate(&headers, "user.exists"), "用户名已存在，或已注销");
        assert_eq!(
            translate(&headers, "user.email_verification_required"),
            "管理员开启了邮箱验证，请输入邮箱地址和验证码",
        );
        assert_eq!(translate(&headers, "common.invalid_params"), "无效的参数");
    }
}
