//! 登录端点的 HTTP 适配：`POST /api/user/login` 与 `/api/user/login/2fa`。
//!
//! 只做协议解析、中间件顺序与响应定型；业务顺序在
//! `newapi_identity::login::orchestrate`（Go `Login`/`Verify2FALogin` 复刻）。

use std::net::SocketAddr;

use axum::{
    Json,
    body::{Body, Bytes, to_bytes},
    extract::{ConnectInfo, Extension, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use newapi_identity::login::orchestrate::{
    LoginFailure, LoginResponse, LoginService, MSG_LOGIN_DISABLED, assemble_self_user,
};
use serde::Deserialize;
use serde_json::json;

use crate::AppState;
use crate::boundary_mw::{disable_cache_headers, fill_disable_cache_headers};

/// Go `common.BindJSON`：Content-Type 非 JSON（且非空）时跳过解析，目标保持
/// 零值，handler 随后以“参数错误”拒绝。空 Content-Type 按 JSON 处理。
#[derive(Deserialize)]
struct LoginRequest {
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
}

#[derive(Deserialize)]
struct TwoFaRequest {
    #[serde(default)]
    code: String,
    #[serde(default)]
    flow_token: String,
}

/// 中间件解析出的客户端 IP，供 handler 复用（避免重复信任链计算）。
#[derive(Clone)]
pub struct ClientIp(pub String);

fn user_agent(headers: &HeaderMap) -> String {
    headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

/// 对齐 fasthttp `Peek`：重复头的多个值按逗号合并，解析器再按逗号切分。
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

fn request_ip(state: &AppState, headers: &HeaderMap, peer: Option<SocketAddr>) -> String {
    let forwarded_for = joined_header(headers, header::HeaderName::from_static("x-forwarded-for"));
    let real_ip = joined_header(headers, header::HeaderName::from_static("x-real-ip"));
    state.client_ip(
        peer.map(|address| address.ip()),
        forwarded_for.as_deref(),
        real_ip.as_deref(),
    )
}

/// Go `UnmarshalBodyReusable` 的 Content-Type 分支：仅 `application/json`
/// （可带参数）或缺失/空头按 JSON 解析。
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

/// 解析请求体；`None` 表示 Content-Type 不按 JSON 处理（Go 的 skip 分支）。
fn bind<T: serde::de::DeserializeOwned>(headers: &HeaderMap, body: &[u8]) -> Result<Option<T>, ()> {
    if !parses_as_json(headers) {
        return Ok(None);
    }
    serde_json::from_slice::<T>(body).map(Some).map_err(|_| ())
}

fn invalid_params(headers: &HeaderMap) -> Response {
    rejected(translate(headers, "common.invalid_params"))
}

fn translate(headers: &HeaderMap, key: &str) -> String {
    let lang = crate::request_lang::request_language(
        crate::request_lang::accept_language_header(headers).as_deref(),
    );
    newapi_i18n::translate(&lang, key, std::iter::empty::<(&str, &str)>())
}

fn rejected(message: String) -> Response {
    Json(json!({ "success": false, "message": message })).into_response()
}

fn unavailable() -> Response {
    let mut response = StatusCode::SERVICE_UNAVAILABLE.into_response();
    disable_cache_headers(&mut response);
    response
}

/// 登录路由中间件，按 Go 注册顺序复刻：
/// `CriticalRateLimit` → `DisableCache` → `AnonymousRequestBodyLimit` →
/// `TurnstileCheck` → handler。因此 429 不带 no-cache 头，而 413、Turnstile
/// 拒绝与 handler 响应都带。
pub async fn login_guard(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0);
    let ip = request_ip(&state, request.headers(), peer);
    let now = crate::http::now_seconds();
    // Go `mark` 为 "CT"：内存键是 mark + ClientIP，Redis 键另由 limiter 组装。
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
        // Go 的 Redis 故障分支：500 + Abort，且位于 DisableCache 之前。
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    request.extensions_mut().insert(ClientIp(ip.clone()));
    let mut response = match read_limited_body(state.anonymous_body_limit(), request).await {
        Err(status) => status.into_response(),
        Ok(request) => {
            // Go 的 TurnstileCheck 位于体限制之后、handler 之前。Go 只在
            // `/api/user/login` 注册 TurnstileCheck，`/login/2fa` 不受其约束。
            let auth = state.auth_settings();
            let enabled = auth.turnstile_check_enabled && request.uri().path() == "/api/user/login";
            let token = crate::turnstile::query_token(request.uri().query());
            let decision = if !enabled || token.is_none() {
                // Disabled checks and empty tokens must not construct or call
                // any verifier, so no siteverify request can be issued.
                crate::turnstile::decide(enabled, token.as_deref(), "", None, None).await
            } else {
                // Tests and embedders can replace the transport through a
                // request extension; production uses the shared HTTP client.
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
            match decision.rejection_key() {
                Some(key) => rejected(translate(request.headers(), key)),
                None => next.run(request).await,
            }
        }
    };
    // 与 Go 的“先 SetHeader 再 Next”一致：成功响应的 `no-store` 不被覆盖。
    fill_disable_cache_headers(&mut response);
    response
}

/// 复刻 Go `AnonymousRequestBodyLimit`：先看声明的 Content-Length，再以
/// `limit + 1` 预算读取实际体；超限返回裸 413（无 JSON 包）。`limit == 0`
/// 在 Go 中是“未启用”，这里同样不设限。passkey 登录路由同用此函数。
pub(crate) async fn read_limited_body(
    limit: usize,
    request: Request,
) -> Result<Request, StatusCode> {
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

pub async fn login(
    State(state): State<AppState>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(service) = login_service(&state) else {
        return unavailable();
    };
    // Go 在 BindJSON 之前先检查密码登录开关。
    if !state.auth_settings().password_login_enabled {
        let message = translate(&headers, MSG_LOGIN_DISABLED);
        return rejected(message);
    }
    let parsed: LoginRequest = match bind(&headers, &body) {
        Ok(Some(parsed)) => parsed,
        Ok(None) | Err(()) => return invalid_params(&headers),
    };
    let lang = crate::request_lang::request_language(
        crate::request_lang::accept_language_header(&headers).as_deref(),
    );
    let outcome = service
        .login(
            &parsed.username,
            &parsed.password,
            true,
            &lang,
            &ip,
            &user_agent(&headers),
            crate::http::now_seconds(),
        )
        .await;
    render(&state, outcome, &headers)
}

pub async fn login_two_fa(
    State(state): State<AppState>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(service) = login_service(&state) else {
        return unavailable();
    };
    let parsed: TwoFaRequest = match bind(&headers, &body) {
        Ok(Some(parsed)) => parsed,
        Ok(None) | Err(()) => return invalid_params(&headers),
    };
    let lang = crate::request_lang::request_language(
        crate::request_lang::accept_language_header(&headers).as_deref(),
    );
    let outcome = service
        .login_with_2fa(
            &parsed.flow_token,
            &parsed.code,
            &lang,
            &ip,
            &user_agent(&headers),
            crate::http::now_seconds(),
        )
        .await;
    render(&state, outcome, &headers)
}

fn login_service(state: &AppState) -> Option<LoginService> {
    let auth = state.auth_arc()?;
    let db = state.db()?;
    let flow_key = state.flow_key()?.to_vec();
    Some(LoginService::new(auth, db, flow_key))
}

/// Go 的响应定型。`LoginFailure::Storage` 在 Go 里是 `CtxApiError(err)`（200 +
/// 错误文本）；Rust 不以数据库文本作为客户端文案，落到固定分类。
/// passkey 登录（`SetupLogin` 等价路径）复用此定型。
pub(crate) fn render(
    state: &AppState,
    outcome: Result<LoginResponse, LoginFailure>,
    headers: &HeaderMap,
) -> Response {
    let response = match outcome {
        Ok(response) => response,
        Err(LoginFailure::Storage) => {
            return rejected(translate(headers, "common.database_error"));
        }
        Err(LoginFailure::Message(key)) => return rejected(translate(headers, key)),
        Err(LoginFailure::Session(error)) => {
            let (status, code) = newapi_identity::login::orchestrate::session_error_code(&error);
            return session_error(status, code);
        }
    };
    match response {
        LoginResponse::Success(success) => {
            let display = state.quota_display();
            let self_user = assemble_self_user(success.profile, success.permissions, display);
            let Ok(user) = serde_json::to_value(&self_user) else {
                return session_error(500, "AUTH_INTERNAL_ERROR");
            };
            let session_expires_at = success.bundle.session.expires_at;
            let session = crate::http::SessionBody::from(success.bundle.session);
            let Ok(session) = serde_json::to_value(session) else {
                return session_error(500, "AUTH_INTERNAL_ERROR");
            };
            let body = json!({
                "message": "",
                "success": true,
                "data": {
                    "access_token": success.bundle.access_token.expose_secret(),
                    "token_type": "Bearer",
                    "access_expires_at": success.bundle.access_expires_at,
                    "session": session,
                    "user": user,
                }
            });
            let max_age = session_expires_at.saturating_sub(crate::http::now_seconds());
            let mut response = Json(body).into_response();
            crate::http::set_cookie(
                &mut response,
                success.bundle.refresh_token.expose_secret(),
                session_expires_at,
                max_age,
                state.session_cookie().secure,
            );
            // Go `setAuthNoStore` 覆盖 DisableCache 设置的 Cache-Control。
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        LoginResponse::Pending2fa {
            message,
            flow_token,
            expires_at,
        } => Json(json!({
            "success": true,
            "message": message,
            "data": {
                "require_2fa": true,
                "flow_token": flow_token.expose_secret(),
                "expires_at": expires_at,
            }
        }))
        .into_response(),
        LoginResponse::Rejected { message } => rejected(message),
        LoginResponse::Session { status, code } => session_error(status, code),
    }
}

fn session_error(status: u16, code: &'static str) -> Response {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut response = (
        status,
        Json(json!({
            "success": false,
            "code": code,
            "message": status.canonical_reason().unwrap_or("error"),
        })),
    )
        .into_response();
    disable_cache_headers(&mut response);
    response
}
