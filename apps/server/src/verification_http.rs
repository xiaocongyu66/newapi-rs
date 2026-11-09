//! `GET /api/verification` 与 `GET /api/reset_password` —— Go
//! `identity.SendEmailVerification` / `identity.SendPasswordResetEmail`
//! （`apps/api/internal/identity/verify_email.go`）。
//!
//! 路由链（`transport/compose/register_api.go:99-100`）：
//! - `/api/verification`：`EmailVerificationRateLimit("EV")` →
//!   `TurnstileCheck()` → handler；无 UserAuth、无 DisableCache、无体上限。
//! - `/api/reset_password`：`CriticalRateLimit("CT")` → `TurnstileCheck()`
//!   → handler；同样三无。
//!
//! 邮件发送经 `newapi_identity::email::EmailSender` 端口；当前默认实现
//! 复刻未配置 SMTP 的 Go 部署（`email.go:163-169`）：恒返回逐字错误
//! `"SMTP 服务器未配置"`。此时验证码**已生成并存储**（Go 先存后发），
//! 且**不删除**（发送失败不回滚），限流配额也已在中间件阶段消耗——
//! 这些副作用在无 SMTP 下是唯一可观察的契约面，由测试钉住。

use std::net::SocketAddr;

use axum::{
    Json,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use newapi_catalog::email_settings::EmailSettings;
use newapi_identity::email::{EmailSender, OutgoingMessage, UnconfiguredEmailSender};
use newapi_identity::password_reset::PasswordResetRepository;
use newapi_identity::registration::{
    EMAIL_VERIFICATION_PURPOSE, PASSWORD_RESET_PURPOSE, RegistrationRepository,
    register_verification_code,
};
use serde_json::json;

use crate::AppState;
use crate::limit_email::{EmailLimitDecision, rejection_message};
use crate::login_http::ClientIp;
use crate::turnstile::Verifier;

/// Go `common.SystemName` 默认 `"New API"`（constants.go:16）；SystemName
/// option 快照尚未进入 catalog（见 status.rs 与 two_fa 仓储的同样决定）。
const DEFAULT_SYSTEM_NAME: &str = "New API";

/// Go `egress.ServerAddress` 初始值 `"http://localhost:3000"`
/// （fetch_url.go:36）；egress 未移植，与 status.rs 同样使用编译期默认。
const DEFAULT_SERVER_ADDRESS: &str = "http://localhost:3000";

/// Go `common.VerificationValidMinutes`（verification.go:24）：固定 10，
/// 没有选项同步路径。
const VERIFICATION_VALID_MINUTES: i64 = 10;

/// Go `SendEmailVerification`（verify_email.go:22-97）。
///
/// Go 的分支顺序逐一复刻：校验 → `@` 拆分 → 域名白名单 → 别名限制 →
/// 格式正则 → 邮箱占用 → 生成并存储验证码 → 发送。前四条拒绝使用
/// 固定文案（非 i18n key），后三条走 i18n。
pub async fn send_email_verification(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    let email = newapi_identity::password_reset::normalize_email(&query_param(
        request.uri().query(),
        "email",
    ));
    // Go `common.Validate.Var(email, "required,email")`。
    if email.is_empty() || !validator_email(&email) {
        return rejected(translate(&headers, "common.invalid_params"));
    }
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        // Go：`strings.Split` 得到的不是 2 段（验证器放行的地址不会到这）。
        return Json(json!({
            "success": false,
            "message": "无效的邮箱地址",
        }))
        .into_response();
    }
    let local = parts[0];
    let domain = parts[1];
    let settings = match email_settings(&state).await {
        Ok(settings) => settings,
        Err(response) => return response,
    };
    if settings.email_domain_restriction_enabled {
        let allowed = settings
            .email_domain_whitelist
            .iter()
            .any(|allowed| allowed == domain);
        if !allowed {
            return Json(json!({
                "success": false,
                "message": "The administrator has enabled the email domain name whitelist, and your email address is not allowed due to special symbols or it's not in the whitelist.",
            }))
            .into_response();
        }
    }
    if settings.email_alias_restriction_enabled && (local.contains('+') || local.contains('.')) {
        return Json(json!({
            "success": false,
            "message": "管理员已启用邮箱地址别名限制，您的邮箱地址由于包含特殊符号而被拒绝。",
        }))
        .into_response();
    }
    if !settings.email_format_regex_rules.is_empty() && !email_format_rejected(&settings, &email) {
        return rejected(translate(&headers, "user.email_format_rejected"));
    }
    let Some(repository) = state.db().map(RegistrationRepository::new) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    // Go `IsEmailAlreadyTaken`：数据库错误同样落到 false（继续向下执行），
    // 与 `err == nil && count > 0` 一致。
    match repository.email_taken(&email).await {
        Ok(true) => return rejected(translate(&headers, "user.email_already_taken")),
        Ok(false) => {}
        Err(error) => tracing::warn!(
            event = "verification_email_taken_check_failed",
            category = crate::database_error_class(&error),
            "email taken check failed"
        ),
    }
    // Go：先生成并存储验证码，再尝试发送；发送失败不删除、不回滚。
    let Some(code) =
        newapi_identity::password_reset::generate_verification_code(VERIFICATION_CODE_LENGTH)
    else {
        return rejected(translate(&headers, "common.database_error"));
    };
    register_verification_code(EMAIL_VERIFICATION_PURPOSE, &email, &code);
    let subject = format!("{DEFAULT_SYSTEM_NAME}邮箱验证邮件");
    let content = format!(
        "<p>您好，你正在进行{DEFAULT_SYSTEM_NAME}邮箱验证。</p>\
         <p>您的验证码为: <strong>{code}</strong></p>\
         <p>验证码 {VERIFICATION_VALID_MINUTES} 分钟内有效，如果不是本人操作，请忽略。</p>"
    );
    let message = OutgoingMessage {
        subject: &subject,
        receiver: &email,
        content: &content,
    };
    // SMTP 传输留 P7（integrations.mail）；未配置实现恒失败，错误文案
    // 逐字进 message（Go `CtxApiError`）。
    match UnconfiguredEmailSender.send(&message).await {
        Ok(()) => Json(json!({ "success": true, "message": "" })).into_response(),
        Err(error) => {
            Json(json!({ "success": false, "message": error.to_string() })).into_response()
        }
    }
}

/// Go `SendPasswordResetEmail`（verify_email.go:103-129）。
///
/// 用户存在性不泄露：无论邮箱是否存在/歧义/数据库错误，响应都是
/// `{"success":true,"message":""}`。只有唯一匹配才会生成验证码、
/// 存储并尝试发送；发送失败只记日志（Go 的 `LogError`）。
pub async fn send_password_reset_email(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    let email = newapi_identity::password_reset::normalize_email(&query_param(
        request.uri().query(),
        "email",
    ));
    if email.is_empty() || !validator_email(&email) {
        return rejected(translate(&headers, "common.invalid_params"));
    }
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let repository = PasswordResetRepository::new(db);
    match repository.unique_user_id(&email).await {
        Ok(_) => {
            // Go：32 位完整 UUID 作为 token，存入 purpose "p"（对齐
            // registration.rs 的 PASSWORD_RESET_PURPOSE 常量）。
            let Some(code) =
                newapi_identity::password_reset::generate_verification_code(RESET_TOKEN_LENGTH)
            else {
                return rejected(translate(&headers, "common.database_error"));
            };
            register_verification_code(PASSWORD_RESET_PURPOSE, &email, &code);
            let link = format!("{DEFAULT_SERVER_ADDRESS}/user/reset?email={email}&token={code}");
            let subject = format!("{DEFAULT_SYSTEM_NAME}密码重置");
            let content = format!(
                "<p>您好，你正在进行{DEFAULT_SYSTEM_NAME}密码重置。</p>\
                 <p>点击 <a href='{link}'>此处</a> 进行密码重置。</p>\
                 <p>如果链接无法点击，请尝试点击下面的链接或将其复制到浏览器中打开：<br> {link} </p>\
                 <p>重置链接 {VERIFICATION_VALID_MINUTES} 分钟内有效，如果不是本人操作，请忽略。</p>"
            );
            let message = OutgoingMessage {
                subject: &subject,
                receiver: &email,
                content: &content,
            };
            // P7 的 SMTP 实现接入前，发送恒失败；Go 只记日志、不回滚
            // 已存储的验证码。
            if let Err(error) = UnconfiguredEmailSender.send(&message).await {
                tracing::error!(
                    event = "password_reset_email_failed",
                    message = %error,
                    "failed to send password reset email"
                );
            }
        }
        // Go：`EmailNotFound` 静默跳过；其余（歧义、数据库错误）记
        // LogWarn。Go 对空邮箱返回 ErrEmailNotFound，InvalidInput 同样
        // 归入静默分支。
        Err(newapi_identity::password_reset::PasswordResetError::EmailNotFound)
        | Err(newapi_identity::password_reset::PasswordResetError::InvalidInput) => {}
        Err(error) => tracing::warn!(
            event = "password_reset_lookup_failed",
            error = ?error,
            "skip password reset email"
        ),
    }
    Json(json!({ "success": true, "message": "" })).into_response()
}

/// Go `GenerateVerificationCode(6)`：6 位注册验证码。
const VERIFICATION_CODE_LENGTH: usize = 6;
/// Go `GenerateVerificationCode(0)`：32 位完整重置 token。
const RESET_TOKEN_LENGTH: usize = 0;

/// `/api/verification` 路由中间件，按 Go 注册顺序复刻：
/// `EmailVerificationRateLimit("EV")` → `TurnstileCheck()`。无体上限、
/// 无 DisableCache。EV 拒绝是 429 + JSON 信封（带消息），且无
/// Retry-After 头——与 CriticalRateLimit 的裸 429 不同。
pub async fn verification_guard(
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
    match state.check_email_verification_rate_limit(&ip, now).await {
        None | Some(EmailLimitDecision::Allowed) => {}
        Some(decision) => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({
                    "success": false,
                    "message": rejection_message(decision),
                })),
            )
                .into_response();
        }
    }
    turnstile_gate(&state, request, next).await
}

/// `/api/reset_password` 路由中间件，按 Go 注册顺序复刻：
/// `CriticalRateLimit("CT")` → `TurnstileCheck()`。无体上限、无
/// DisableCache。CT 拒绝复用 Go 的 `writeRateLimited`：裸 429 +
/// Retry-After 头、无 JSON 体。
pub async fn reset_password_guard(
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
    turnstile_gate(&state, request, next).await
}

/// Go `TurnstileCheck`（check_turnstile.go:15-50）：读 query 的
/// `turnstile`，空 token / 校验失败 / 传输失败都拒绝（fail closed）；
/// 开关关闭时直通。复用 register_http 同款注入槽。
async fn turnstile_gate(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let auth = state.auth_settings();
    let enabled = auth.turnstile_check_enabled;
    let token = crate::turnstile::query_token(request.uri().query());
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0);
    let ip = request_ip(&state, request.headers(), peer);
    let decision = if !enabled || token.is_none() {
        crate::turnstile::decide(enabled, token.as_deref(), "", None, None).await
    } else {
        let injected = request
            .extensions()
            .get::<crate::turnstile::InjectedVerifier>()
            .cloned();
        let http = crate::turnstile::HttpVerifier;
        let verifier: &dyn Verifier = match injected.as_ref() {
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
        None => {
            let mut request = request;
            request.extensions_mut().insert(ClientIp(ip));
            next.run(request).await
        }
    }
}

/// fasthttp `Args.Peek` 语义：取第一个匹配键的值，
/// `application/x-www-form-urlencoded` 解码（`+`→空格、`%XX`→字节），
/// 非法转移保持字面（fasthttp 行为）。与 `turnstile::query_token` 同款，
/// 因后者为 turnstile 专用而在此各取所需，未共用私有解码器。
fn query_param(query: Option<&str>, name: &str) -> String {
    let Some(query) = query else {
        return String::new();
    };
    for pair in query.split('&') {
        let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        if decode_component(raw_key) == name {
            return decode_component(raw_value);
        }
    }
    String::new()
}

fn decode_component(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' => {
                let high = bytes.get(index + 1).copied().and_then(hex_value);
                let low = bytes.get(index + 2).copied().and_then(hex_value);
                match (high, low) {
                    (Some(high), Some(low)) => {
                        decoded.push((high << 4) | low);
                        index += 3;
                    }
                    // fasthttp：不完整的非十六进制转义保持字面。
                    _ => {
                        decoded.push(b'%');
                        index += 1;
                    }
                }
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// go-playground/validator v10.20.0 `email` 规则的 ASCII 近似
/// （`regexes.go` 的 emailRegexString 未逐字移植）。覆盖常见邮箱：
/// local 为点分隔原子、domain 至少两段、末段以字母开头；允许的原子字符
/// 为 `[A-Za-z0-9!#$%&'*+\-/=?^_\`{|}~]`。与 Go 的差异：非 ASCII
/// 邮箱（Go 的 Unicode 区间）在此判为非法——这类输入随后的占用检查
/// 与 SMTP 未配置错误仍会拦截，响应 message 不同（invalid_params 而非
/// 发送失败），已在交付说明登记。
fn validator_email(email: &str) -> bool {
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    if local.is_empty()
        || domain.is_empty()
        || domain.contains('@')
        || local
            .split('.')
            .any(|atom| atom.is_empty() || !atom.bytes().all(is_atom_char))
    {
        return false;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 || labels.iter().any(|label| !label_ok(label)) {
        return false;
    }
    // Go 正则的末段以字母开头。
    labels
        .last()
        .is_some_and(|label| label.starts_with(|c: char| c.is_ascii_alphabetic()))
}

fn is_atom_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'/'
                | b'='
                | b'?'
                | b'^'
                | b'_'
                | b'`'
                | b'{'
                | b'|'
                | b'}'
                | b'~'
        )
}

/// Go 域名段：单字符必须为字母数字；多字符须字母数字首尾，
/// 中间允许 `-`/`.`/`~`。
fn label_ok(label: &str) -> bool {
    let bytes = label.as_bytes();
    match bytes.len() {
        0 => false,
        1 => bytes[0].is_ascii_alphanumeric(),
        _ => {
            bytes[0].is_ascii_alphanumeric()
                && bytes[bytes.len() - 1].is_ascii_alphanumeric()
                && bytes[1..bytes.len() - 1]
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'~'))
        }
    }
}

/// Go 的 `EmailFormatRegexCompiled` 匹配（verify_email.go:64-76）：
/// 任一规则命中即放行。Cargo.lock 未锁定 `regex`，本端口无正则引擎；
/// 配置了规则时按“未命中”处理会错误拒绝全部注册，因此保守放行并
/// 记警告，与 Go 未配置该选项的默认行为一致。正则引擎随 P7
/// （`integrations.mail` 或依赖锁刷新）落地后补齐。
fn email_format_rejected(_settings: &EmailSettings, _email: &str) -> bool {
    tracing::warn!(
        event = "email_format_regex_unsupported",
        "EmailFormatRegex is configured but no regex engine is linked; failing open"
    );
    false
}

async fn email_settings(state: &AppState) -> Result<EmailSettings, Response> {
    let Some(db) = state.db() else {
        return Err(StatusCode::SERVICE_UNAVAILABLE.into_response());
    };
    match EmailSettings::load(&db, &EmailSettings::default()).await {
        Ok(settings) => Ok(settings),
        Err(error) => {
            tracing::warn!(
                event = "email_settings_load_failed",
                category = crate::database_error_class(&error),
                "email settings load failed"
            );
            Err(StatusCode::SERVICE_UNAVAILABLE.into_response())
        }
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

fn language(headers: &HeaderMap) -> String {
    crate::request_lang::request_language(
        crate::request_lang::accept_language_header(headers).as_deref(),
    )
}

fn translate(headers: &HeaderMap, key: &str) -> String {
    newapi_i18n::translate(&language(headers), key, std::iter::empty::<(&str, &str)>())
}

fn rejected(message: String) -> Response {
    Json(json!({ "success": false, "message": message })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_param_reads_the_first_value_like_fasthttp_peek() {
        assert_eq!(query_param(Some("email=a@b.com"), "email"), "a@b.com");
        assert_eq!(
            query_param(Some("email=a@b.com&email=second"), "email"),
            "a@b.com"
        );
        assert_eq!(query_param(Some("email="), "email"), "");
        assert_eq!(query_param(Some(""), "email"), "");
        assert_eq!(query_param(None, "email"), "");
        assert_eq!(query_param(Some("email"), "email"), "");
        assert_eq!(query_param(Some("a=1&b=2"), "email"), "");
    }

    #[test]
    fn query_param_decodes_form_encoding() {
        assert_eq!(
            query_param(Some("email=user%40example.com"), "email"),
            "user@example.com"
        );
        assert_eq!(
            query_param(Some("email=mi+xed@mail.com"), "email"),
            "mi xed@mail.com"
        );
        assert_eq!(query_param(Some("email=%E4%B8%AD"), "email"), "中");
        assert_eq!(query_param(Some("email=a%ZZ"), "email"), "a%ZZ");
    }

    #[test]
    fn validator_email_accepts_common_addresses() {
        for valid in [
            "user@example.com",
            "USER@EXAMPLE.COM",
            "a@b.c",
            "first.last@example.com",
            "name+tag@sub.example.com",
            "user_name-99@my-site.co",
        ] {
            assert!(validator_email(valid), "{valid} should be valid");
        }
    }

    #[test]
    fn validator_email_rejects_clearly_malformed_addresses() {
        for invalid in [
            "",
            "notanemail",
            "a@b",
            "a@1.2", // 末段必须字母开头
            ".user@example.com",
            "user.@example.com",
            "fi..rst@example.com",
            "user@example..com",
            "user@-example.com",
            "user@example-.com",
        ] {
            assert!(!validator_email(invalid), "{invalid} should be invalid");
        }
    }

    #[test]
    fn go_verbatim_messages_are_not_translated() {
        // 校验中段的两条固定文案直接进 message，不经 i18n。
        let body = serde_json::to_string(&json!({
            "success": false,
            "message": "无效的邮箱地址"
        }))
        .unwrap();
        assert!(body.contains("无效的邮箱地址"));
    }
}
