//! OAuth 登录/绑定八条路由的 HTTP 适配层：Go
//! `transport/handler/handle_oauth.go`（`GenerateOAuthCode` / `HandleOAuth`）、
//! `identity/bind_wechat.go`、`identity/bind_telegram.go` 与
//! `identity/manage_users.go` 的 `EmailBind`。
//!
//! ## 路由链（`register_api.go:103-112`，逐条复刻）
//!
//! | 路由 | Go 链 |
//! |---|---|
//! | `POST /api/oauth/state` | CT → NC → TryUserAuth → 匿名体上限 → handler |
//! | `POST /api/oauth/email/bind` | UserAuth → CT → handler（无 NC） |
//! | `GET  /api/oauth/wechat` | CT → NC → handler |
//! | `POST /api/oauth/wechat/bind` | UserAuth → CT → handler（无 NC） |
//! | `GET  /api/oauth/telegram/login` | CT → NC → handler |
//! | `POST /api/oauth/telegram/bind/start` | UserAuth → CT → NC → handler |
//! | `GET  /api/oauth/telegram/bind/:flow_token` | CT → NC → handler（302） |
//! | `GET  /api/oauth/:provider` | CT → NC → TryUserAuth → handler |
//!
//! ## 响应契约要点
//!
//! - state 成功：`{"success":true,"message":"","data":{"flow_token","expires_at"}}`；
//! - 登录成功与密码登录同一 auth bundle 形状（Go `SetupLogin`），带
//!   refresh cookie 与 `no-store`；绑定成功：message=i18n
//!   `oauth.bind_success`、`data={"action":"bind"}`；
//! - 未知提供商是 **HTTP 400**（唯一非 200 的 JSON 失败）；state 无效是
//!   **HTTP 403**（`oauth.state_invalid`）；Telegram 登录的重放拒绝是
//!   **HTTP 403**；其余业务失败一律 200 + success=false；
//! - Telegram 绑定回调全部 302 到 `/oauth/telegram?...`，错误以
//!   `error_code` 区分（Go `bind_telegram.go:30-37` 常量）。
//!
//! ## 与 Go 的有意分歧
//!
//! 1. 微信服务器调用失败/返回失败时 Go 透传远端文本；本端口按仓库固定
//!    分类约定折叠（与 `qq_bind` / `custom_oauth` 立场一致）。
//! 2. `LinuxDO` 的 redirect_uri 用请求 Host 头（Go `c.Host()`），明文
//!    scheme（与 passkey 切片的传输立场一致）。
//! 3. Go 在 `CtxApiError(err)` 透传存储错误文本；本端口折叠为
//!    `common.database_error`。

use std::sync::{Arc, OnceLock};

use axum::{
    Json,
    body::Bytes,
    extract::{Extension, Path, RawQuery, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use newapi_identity::custom_oauth::CustomOAuthRepository;
use newapi_identity::login::orchestrate::{
    LoginFailure, LoginResponse, LoginService, LoginSuccess,
};
use newapi_identity::oauth_flow::providers::{
    OAuthUser, OutboundError, OutboundFuture, OutboundRequest, OutboundResponse, OutboundTransport,
    ProviderError, ResolvedProvider, query_encode_into,
};
use newapi_identity::oauth_flow::{
    self, OAuthFlowError, TelegramFlowError,
    repository::OAuthFlowRepository,
    store::{CreateUserError, EmailBindError, OAuthUserStore},
};
use newapi_identity::user_auth::CredentialKind;
use newapi_identity::users::UserProfile;
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::{AuthCredential, AuthenticatedUser, parse_authorization};
// 生产路由由 critical_guard 注入 ClientIp；测试路由器无该守护，
// 这里重导出同一类型供集成测试直接插入请求扩展。
pub use crate::login_http::ClientIp;

/// Go `oauthAuthFlowTTL`（10 分钟）/ `telegramBindFlowTTL`（5 分钟）。
const OAUTH_TTL: i64 = oauth_flow::OAUTH_FLOW_TTL_SECONDS;
const TELEGRAM_TTL: i64 = oauth_flow::TELEGRAM_BIND_TTL_SECONDS;

/// Go 硬编码中文文案（不走 i18n，前端逐字比较），逐字保留。
const MSG_WECHAT_DISABLED: &str = "管理员未开启通过微信登录以及注册";
const MSG_WECHAT_CODE_INVALID: &str = "验证码错误或已过期";
const MSG_WECHAT_USER_DELETED: &str = "用户已注销";
const MSG_WECHAT_REGISTER_DISABLED: &str = "管理员关闭了新用户注册";
const MSG_WECHAT_BANNED: &str = "用户已被封禁";
const MSG_WECHAT_ALREADY_BOUND: &str = "该微信账号已被绑定";
const MSG_WECHAT_UNAVAILABLE: &str = "微信服务器连接失败";
const MSG_WECHAT_INVALID_REQUEST: &str = "无效的请求";
const MSG_TELEGRAM_DISABLED: &str = "管理员未开启通过 Telegram 登录以及注册";
const MSG_TELEGRAM_INVALID: &str = "无效的请求";
const MSG_TELEGRAM_REPLAYED: &str = "该登录凭据已被使用";
const MSG_TELEGRAM_NOT_BOUND: &str = "该 Telegram 账户未绑定";
const MSG_BIND_NEEDS_LOGIN: &str = "绑定操作需要登录";
const MSG_NOT_LOGGED_IN: &str = "未登录";
const MSG_NOT_AUTHENTICATED: &str = "not authenticated";
const MSG_EMAIL_INVALID_BODY: &str = "invalid request body";
/// Go `CtxApiError(err)` 的存储错误：本端口折叠为固定 i18n 键。
const MSG_DATABASE_ERROR: &str = "common.database_error";

/// Telegram 绑定回调错误码（Go `bind_telegram.go:30-37`）。
const T_BIND_DISABLED: &str = "TELEGRAM_BIND_DISABLED";
const T_BIND_INVALID_REQUEST: &str = "TELEGRAM_BIND_INVALID_REQUEST";
const T_BIND_FLOW_INVALID: &str = "TELEGRAM_BIND_FLOW_INVALID";
const T_BIND_SESSION_INVALID: &str = "TELEGRAM_BIND_SESSION_INVALID";
const T_BIND_ALREADY_BOUND: &str = "TELEGRAM_BIND_ALREADY_BOUND";
const T_BIND_USER_DELETED: &str = "TELEGRAM_BIND_USER_DELETED";
const T_BIND_USER_DISABLED: &str = "TELEGRAM_BIND_USER_DISABLED";

// ---------------------------------------------------------------------------
// 出站传输（微信 / 提供商 HTTP）
// ---------------------------------------------------------------------------

/// 进程级共享客户端；构造失败按 Transport 归类（与 `qqbot::qq_client`
/// 同一处理）。
fn outbound_client() -> Option<&'static reqwest::Client> {
    static CLIENT: OnceLock<Option<reqwest::Client>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            crate::turnstile::install_crypto_provider();
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(20))
                .build()
                .ok()
        })
        .as_ref()
}

/// 生产实现：共享 reqwest 客户端。
#[derive(Clone, Copy, Debug, Default)]
pub struct HttpOAuthTransport;

impl OutboundTransport for HttpOAuthTransport {
    fn send(&self, request: OutboundRequest) -> OutboundFuture<'_> {
        Box::pin(async move {
            let client = outbound_client().ok_or(OutboundError::Transport)?;
            let method = if request.method == "GET" {
                reqwest::Method::GET
            } else {
                reqwest::Method::POST
            };
            let mut builder = client.request(method, &request.url);
            if let Some(body) = request.body {
                builder = builder.body(body);
            }
            if let Some(content_type) = request.content_type {
                builder = builder.header(reqwest::header::CONTENT_TYPE, content_type);
            }
            if let Some(authorization) = request.authorization {
                builder = builder.header(reqwest::header::AUTHORIZATION, authorization);
            }
            if let Some(accept) = request.accept {
                builder = builder.header(reqwest::header::ACCEPT, accept);
            }
            let response = builder.send().await.map_err(|_| OutboundError::Transport)?;
            let status = response.status().as_u16();
            // Go 逐家读全量响应体；1 MiB 封顶防御恶意长流（与 discovery
            // 切片同一策略）。
            let body = read_capped(response).await?;
            Ok(OutboundResponse { status, body })
        })
    }
}

async fn read_capped(mut response: reqwest::Response) -> Result<String, OutboundError> {
    const MAX: usize = 1024 * 1024;
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| OutboundError::Transport)?
    {
        if body.len().saturating_add(chunk.len()) > MAX {
            return Err(OutboundError::Transport);
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).map_err(|_| OutboundError::Transport)
}

/// 请求扩展缝：测试替换真实传输（与 `InjectedQQBotApi` 同一约定）。
#[derive(Clone)]
pub struct InjectedOAuthTransport(pub Arc<dyn OutboundTransport>);

/// 从请求扩展取传输；缺省用真实 HTTP 实现。
fn transport_of(injected: Option<&InjectedOAuthTransport>) -> &dyn OutboundTransport {
    static HTTP: HttpOAuthTransport = HttpOAuthTransport;
    match injected {
        Some(wrapper) => wrapper.0.as_ref(),
        None => &HTTP,
    }
}

// ---------------------------------------------------------------------------
// 共享小件
// ---------------------------------------------------------------------------

fn translate(headers: &HeaderMap, key: &str) -> String {
    translate_args(headers, key, std::iter::empty::<(&str, &str)>())
}

fn translate_args<I, K, V>(headers: &HeaderMap, key: &str, args: I) -> String
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: std::fmt::Display,
{
    let lang = crate::request_lang::request_language(
        crate::request_lang::accept_language_header(headers).as_deref(),
    );
    newapi_i18n::translate(&lang, key, args)
}

fn rejected(message: String) -> Response {
    Json(json!({ "success": false, "message": message })).into_response()
}

fn success_data(data: Value) -> Response {
    Json(json!({ "success": true, "message": "", "data": data })).into_response()
}

fn storage_error(headers: &HeaderMap) -> Response {
    rejected(translate(headers, MSG_DATABASE_ERROR))
}

fn invalid_params(headers: &HeaderMap) -> Response {
    rejected(translate(headers, "common.invalid_params"))
}

fn unavailable() -> Response {
    StatusCode::SERVICE_UNAVAILABLE.into_response()
}

fn unauthorized(headers: &HeaderMap, message: &str) -> Response {
    let _ = headers;
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "success": false, "message": message })),
    )
        .into_response()
}

fn forbidden(headers: &HeaderMap) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "success": false,
            "message": translate(headers, "oauth.state_invalid"),
        })),
    )
        .into_response()
}

fn redirect(location: &str) -> Response {
    let mut response = StatusCode::FOUND.into_response();
    if let Ok(value) = header::HeaderValue::from_str(location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
}

/// 解析查询串为多值对（Go `c.QueryValues()`）：保留重复键供签名校验。
fn query_values(query: Option<&str>) -> Vec<(String, Vec<String>)> {
    let Some(query) = query else {
        return Vec::new();
    };
    let mut pairs: Vec<(String, Vec<String>)> = Vec::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode(key);
        let value = percent_decode(value);
        if let Some(entry) = pairs.iter_mut().find(|(existing, _)| *existing == key) {
            entry.1.push(value);
        } else {
            pairs.push((key, vec![value]));
        }
    }
    pairs
}

/// Go `url.QueryUnescape` 的宽容解码（+ 转空格、%XX）。
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let high = (bytes[index + 1] as char).to_digit(16);
                let low = (bytes[index + 2] as char).to_digit(16);
                match (high, low) {
                    (Some(high), Some(low)) => {
                        out.push((high * 16 + low) as u8);
                        index += 3;
                    }
                    _ => {
                        out.push(b'%');
                        index += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Go `BindJSON` 的 Content-Type 分支：仅 JSON（或缺失）解析；目标缺字段
/// 保留零值。
fn bind_json<T: serde::de::DeserializeOwned>(headers: &HeaderMap, body: &[u8]) -> Option<T> {
    let parses = match headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    {
        None | Some("") => true,
        Some(value) => value
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .eq_ignore_ascii_case("application/json"),
    };
    if !parses {
        // Go：跳过解析，目标保持零值 → 后续按参数错误拒绝。
        return None;
    }
    serde_json::from_slice(body).ok()
}

fn first_value(pairs: &[(String, Vec<String>)], key: &str) -> Option<String> {
    pairs
        .iter()
        .find(|(existing, _)| existing == key)
        .and_then(|(_, values)| values.first().cloned())
}

fn host_header(headers: &HeaderMap) -> String {
    headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

/// 加载 OAuth 设置；数据库故障折叠为 `Err(())`（Go 的进程内存读取不会
/// 失败，这是端口边界）。
async fn settings_of(
    db: &newapi_storage::Database,
) -> Result<newapi_identity::oauth_flow::settings::OAuthSettings, ()> {
    newapi_identity::oauth_flow::settings::OAuthSettings::load(db)
        .await
        .map_err(|_| ())
}

fn flow_repo(state: &AppState) -> Option<OAuthFlowRepository> {
    let db = state.db()?;
    let key = state.flow_key()?.to_vec();
    Some(OAuthFlowRepository::new(db, key))
}

fn login_service(state: &AppState) -> Option<LoginService> {
    let auth = state.auth_arc()?;
    let db = state.db()?;
    let flow_key = state.flow_key()?.to_vec();
    Some(LoginService::new(auth, db, flow_key))
}

/// Go `SetupLogin` 的响应定型（复用密码登录渲染：bundle + cookie +
/// no-store）。
fn render_login(
    state: &AppState,
    outcome: Result<LoginSuccess, LoginFailure>,
    headers: &HeaderMap,
) -> Response {
    crate::login_http::render(
        state,
        outcome.map(|success| LoginResponse::Success(Box::new(success))),
        headers,
    )
}

/// Go `SetupLogin` 的会话签发（login_method 进审计行）。
async fn setup_login(
    state: &AppState,
    user_id: i64,
    method: &str,
    ip: &str,
    headers: &HeaderMap,
) -> Response {
    let Some(login) = login_service(state) else {
        return unavailable();
    };
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let outcome = login
        .complete_session(user_id, method, ip, &user_agent, crate::http::now_seconds())
        .await;
    if let Err(failure) = &outcome {
        eprintln!("[oauth-debug] complete_session({method}): {failure:?}");
    }
    render_login(state, outcome, headers)
}

/// TryUserAuth 场景下从请求头解析出的会话身份（Go
/// `ReadSessionAuthIdentity`：完整鉴权身份 + SID）。
fn session_identity(
    state: &AppState,
    headers: &HeaderMap,
    now: i64,
) -> Option<newapi_identity::AuthIdentity> {
    let credential = match parse_authorization(headers) {
        Ok(AuthCredential::Bearer(token) | AuthCredential::Raw(token)) => token,
        Err(_) => return None,
    };
    let identity = state.auth()?.parse_access(&credential, now).ok()?;
    Some(identity)
}

/// provider 是否在注册集合：内置四家恒注册（Go `init()`），其余 slug
/// 现读 custom 行（存在即注册，与 Go 注册表删除后查不到一致）。
async fn provider_registered(db: &newapi_storage::Database, name: &str) -> bool {
    if matches!(name, "github" | "discord" | "linuxdo" | "oidc") {
        return true;
    }
    if name.is_empty() {
        return false;
    }
    match CustomOAuthRepository::new(db.clone()).list().await {
        Ok(rows) => rows.iter().any(|row| row.slug == name),
        Err(_) => false,
    }
}

/// 按 slug 读 custom 行（Go `GetCustomOAuthProviderBySlug`）。
async fn custom_by_slug(
    db: &newapi_storage::Database,
    slug: &str,
) -> Option<newapi_identity::custom_oauth::CustomOAuthProviderRecord> {
    let rows = CustomOAuthRepository::new(db.clone()).list().await.ok()?;
    rows.into_iter().find(|row| row.slug == slug)
}

// ---------------------------------------------------------------------------
// POST /api/oauth/state — Go GenerateOAuthCode
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize, Default)]
struct OAuthStateRequest {
    #[serde(default)]
    provider: String,
    #[serde(default)]
    intent: String,
    #[serde(default)]
    aff: String,
}

pub async fn oauth_state(
    State(state): State<AppState>,
    Extension(ClientIp(_ip)): Extension<ClientIp>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(db) = state.db() else {
        return unavailable();
    };
    // settings 读取成功性校验（与 Go 选项读取失败一致折叠为存储错误）；
    // state 生成不消费具体开关值。
    if settings_of(&db).await.is_err() {
        return storage_error(&headers);
    }
    let Some(flow) = flow_repo(&state) else {
        return unavailable();
    };
    let request: OAuthStateRequest = match bind_json(&headers, &body) {
        Some(request) => request,
        None => return invalid_params(&headers),
    };
    let provider = request.provider.trim();
    let intent = request.intent.trim();
    let aff = request.aff.trim();
    // Go：provider 注册集合、intent 白名单、aff ≤32、bind 不带 aff。
    if !provider_registered(&db, provider).await
        || (intent != oauth_flow::INTENT_LOGIN && intent != oauth_flow::INTENT_BIND)
        || aff.chars().count() > 32
        || (intent == oauth_flow::INTENT_BIND && !aff.is_empty())
    {
        return invalid_params(&headers);
    }
    let now = crate::http::now_seconds();
    let (user_id, session_id) = if intent == oauth_flow::INTENT_BIND {
        // Go：`ReadSessionAuthIdentity` —— 无完整鉴权身份即 401 固定文案。
        match session_identity(&state, &headers, now) {
            Some(identity) => (identity.user_id, identity.sid),
            None => return unauthorized(&headers, MSG_BIND_NEEDS_LOGIN),
        }
    } else {
        (0, String::new())
    };
    let payload = json!({ "affiliate_code": aff }).to_string();
    let token = match flow
        .create(
            oauth_flow::repository::CreateOAuthFlow {
                purpose: oauth_flow::PURPOSE_OAUTH,
                provider: provider.to_owned(),
                intent: intent.to_owned(),
                user_id,
                session_id: session_id.clone(),
                payload,
                expires_at: now + OAUTH_TTL,
            },
            now,
        )
        .await
    {
        Ok(token) => token,
        Err(TelegramFlowError::Storage) => return storage_error(&headers),
        Err(_) => return invalid_params(&headers),
    };
    success_data(json!({
        "flow_token": token.expose_secret(),
        "expires_at": now + OAUTH_TTL,
    }))
}

// ---------------------------------------------------------------------------
// GET /api/oauth/:provider — Go HandleOAuth
// ---------------------------------------------------------------------------

pub async fn handle_provider(
    State(state): State<AppState>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    injected: Option<Extension<InjectedOAuthTransport>>,
    RawQuery(query): RawQuery,
    Path(provider): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return unavailable();
    };
    let Ok(settings) = settings_of(&db).await else {
        return storage_error(&headers);
    };
    let Some(flow) = flow_repo(&state) else {
        return unavailable();
    };
    let custom = custom_by_slug(&db, &provider).await;
    let Some(resolved) = ResolvedProvider::resolve(&provider, &settings, custom.as_ref())
        .map(|resolved| resolved.with_redirect_host(&host_header(&headers)))
    else {
        // Go：未知提供商是唯一的 400 失败。
        let mut response = Json(json!({
            "success": false,
            "message": translate(&headers, "oauth.unknown_provider"),
        }))
        .into_response();
        *response.status_mut() = StatusCode::BAD_REQUEST;
        return response;
    };
    let pairs = query_values(query.as_deref());
    let state_token = first_value(&pairs, "state").unwrap_or_default();
    let now = crate::http::now_seconds();
    // Go 1：state 校验（purpose + provider）。
    let pending = match flow
        .get(
            &state_token,
            oauth_flow::repository::OAuthFlowMatch {
                purpose: oauth_flow::PURPOSE_OAUTH,
                provider: &provider,
                ..Default::default()
            },
            now,
        )
        .await
    {
        Ok(pending) => pending,
        Err(TelegramFlowError::Storage) => return storage_error(&headers),
        Err(_) => return forbidden(&headers),
    };
    // Go 2：绑定 intent 必须携带创建 flow 的同一会话。
    let bind_session = if pending.intent == oauth_flow::INTENT_BIND {
        match session_identity(&state, &headers, now) {
            Some(identity)
                if identity.user_id == pending.user_id && identity.sid == pending.session_id =>
            {
                Some(identity)
            }
            _ => return forbidden(&headers),
        }
    } else if pending.intent == oauth_flow::INTENT_LOGIN {
        None
    } else {
        return invalid_params(&headers);
    };
    // Go 3：IsEnabled。
    if !resolved.enabled {
        return rejected(translate_args(
            &headers,
            "oauth.not_enabled",
            [("Provider", resolved.name.clone())],
        ));
    }
    // Go 4：提供商错误分支（消费 state 后回显 error_description）。
    if let Some(error_code) = first_value(&pairs, "error").filter(|value| !value.is_empty()) {
        if flow
            .consume(
                &state_token,
                oauth_flow::repository::OAuthFlowMatch {
                    purpose: oauth_flow::PURPOSE_OAUTH,
                    provider: &provider,
                    intent: &pending.intent,
                    ..Default::default()
                },
                now,
            )
            .await
            .is_err()
        {
            return forbidden(&headers);
        }
        let description = first_value(&pairs, "error_description")
            .filter(|value| !value.is_empty())
            .unwrap_or(error_code);
        return rejected(description);
    }
    let code = first_value(&pairs, "code").unwrap_or_default();
    let transport = transport_of(injected.as_deref());
    if pending.intent == oauth_flow::INTENT_BIND {
        return bind_flow(
            &state,
            &flow,
            &resolved,
            &pending,
            &state_token,
            &code,
            transport,
            &headers,
            bind_session.as_ref().map(|identity| identity.user_id),
        )
        .await;
    }
    // ---- 登录分支（Go 5-9 段）----
    let oauth_user = match sign_in_user(&resolved, &code, transport).await {
        Ok(user) => user,
        Err(error) => return provider_failure(&headers, error),
    };
    if flow
        .consume(
            &state_token,
            oauth_flow::repository::OAuthFlowMatch {
                purpose: oauth_flow::PURPOSE_OAUTH,
                provider: &provider,
                intent: oauth_flow::INTENT_LOGIN,
                ..Default::default()
            },
            now,
        )
        .await
        .is_err()
    {
        return forbidden(&headers);
    }
    // payload 里的 aff 邀请码（Go oauthFlowPayload）。
    let affiliate_code = serde_json::from_str::<Value>(&pending.payload)
        .ok()
        .and_then(|payload| {
            payload
                .get("affiliate_code")
                .and_then(|value| value.as_str())
                .map(str::to_owned)
        })
        .unwrap_or_default();
    let store = OAuthUserStore::new(db.clone());
    match find_or_create_user(&state, &store, &resolved, &oauth_user, &affiliate_code).await {
        Ok(user) => {
            // Go 8：状态检查。
            if user.status != 1 {
                return rejected(translate(&headers, "oauth.user_banned"));
            }
            setup_login(&state, user.id, &format!("oauth:{provider}"), &ip, &headers).await
        }
        Err(OAuthFlowError::UserDeleted) => rejected(translate(&headers, "oauth.user_deleted")),
        Err(OAuthFlowError::RegistrationDisabled) => {
            rejected(translate(&headers, "user.register_disabled"))
        }
        Err(OAuthFlowError::EmailTaken) => {
            rejected(translate(&headers, "user.email_already_taken"))
        }
        Err(error) => {
            eprintln!("[oauth-debug] find_or_create_user: {error:?}");
            storage_error(&headers)
        }
    }
}

/// 绑定分支（Go `handleOAuthBind`，`handle_oauth.go:227-290`）。
#[allow(clippy::too_many_arguments)]
async fn bind_flow(
    state: &AppState,
    flow: &OAuthFlowRepository,
    resolved: &ResolvedProvider,
    pending: &oauth_flow::repository::OAuthFlow,
    state_token: &str,
    code: &str,
    transport: &dyn OutboundTransport,
    headers: &HeaderMap,
    user_id: Option<i64>,
) -> Response {
    let Some(db) = state.db() else {
        return unavailable();
    };
    // Go：exchange + userinfo。
    let oauth_user = match sign_in_user(resolved, code, transport).await {
        Ok(user) => user,
        Err(error) => return provider_failure(headers, error),
    };
    // Go：占用检查先于消费（新 id 与 legacy id 都查）。
    let store = OAuthUserStore::new(db.clone());
    let already_bound = match bind_taken(&store, resolved, &oauth_user).await {
        Ok(already_bound) => already_bound,
        Err(_) => return storage_error(headers),
    };
    if already_bound {
        return rejected(translate_args(
            headers,
            "oauth.already_bound",
            [("Provider", resolved.name.clone())],
        ));
    }
    // Go：消费 flow（purpose/provider/intent/user/session 全匹配）。
    let Some(user_id) = user_id else {
        return forbidden(headers);
    };
    if flow
        .consume(
            state_token,
            oauth_flow::repository::OAuthFlowMatch {
                purpose: oauth_flow::PURPOSE_OAUTH,
                provider: &pending.provider,
                intent: oauth_flow::INTENT_BIND,
                user_id,
                session_id: &pending.session_id,
            },
            crate::http::now_seconds(),
        )
        .await
        .is_err()
    {
        return forbidden(headers);
    }
    // Go：generic 走 user_oauth_bindings，内置走绑定列。
    let outcome = if resolved.bind_column.is_empty() {
        store
            .update_custom_binding(user_id, resolved.custom_id, &oauth_user.provider_user_id)
            .await
    } else {
        store
            .update_bind_column(user_id, resolved.bind_column, &oauth_user.provider_user_id)
            .await
    };
    match outcome {
        Ok(()) => Json(json!({
            "success": true,
            "message": translate(headers, "oauth.bind_success"),
            "data": { "action": "bind" },
        }))
        .into_response(),
        Err(_) => storage_error(headers),
    }
}

/// Go `IsUserIDTaken` + legacy id（`handle_oauth.go:244-254`）。
async fn bind_taken(
    store: &OAuthUserStore,
    resolved: &ResolvedProvider,
    oauth_user: &OAuthUser,
) -> Result<bool, ()> {
    if resolved.bind_column.is_empty() {
        store
            .custom_binding_taken(resolved.custom_id, &oauth_user.provider_user_id)
            .await
            .map_err(|_| ())
    } else if store
        .bind_id_taken(resolved.bind_column, &oauth_user.provider_user_id)
        .await
        .map_err(|_| ())?
    {
        Ok(true)
    } else if !oauth_user.legacy_id.is_empty() {
        store
            .bind_id_taken(resolved.bind_column, &oauth_user.legacy_id)
            .await
            .map_err(|_| ())
    } else {
        Ok(false)
    }
}

async fn sign_in_user(
    resolved: &ResolvedProvider,
    code: &str,
    transport: &dyn OutboundTransport,
) -> Result<OAuthUser, ProviderError> {
    let token = resolved.exchange_token(code, transport).await?;
    resolved.get_user_info(&token, transport).await
}

/// Go `handleOAuthError` 的错误翻译（`handle_oauth.go:452-467`）。
fn provider_failure(headers: &HeaderMap, error: ProviderError) -> Response {
    match error {
        ProviderError::InvalidCode => rejected(translate(headers, "oauth.invalid_code")),
        ProviderError::ConnectFailed(provider) => rejected(translate_args(
            headers,
            "oauth.connect_failed",
            [("Provider", provider)],
        )),
        ProviderError::TokenFailed(provider) => rejected(translate_args(
            headers,
            "oauth.token_failed",
            [("Provider", provider)],
        )),
        ProviderError::UserInfoEmpty(provider) => rejected(translate_args(
            headers,
            "oauth.user_info_empty",
            [("Provider", provider)],
        )),
        ProviderError::GetUserFailed(provider) => rejected(translate_args(
            headers,
            "oauth.get_user_error",
            [("Provider", provider)],
        )),
        ProviderError::TrustLevel => rejected(translate(headers, "oauth.trust_level_low")),
        ProviderError::Denied(message) => rejected(message),
    }
}

// ---------------------------------------------------------------------------
// 用户查找 / 创建（Go findOrCreateOAuthUser，handle_oauth.go:293-430）
// ---------------------------------------------------------------------------

async fn find_or_create_user(
    state: &AppState,
    store: &OAuthUserStore,
    resolved: &ResolvedProvider,
    oauth_user: &OAuthUser,
    affiliate_code: &str,
) -> Result<UserProfile, OAuthFlowError> {
    let Some(db) = state.db() else {
        return Err(OAuthFlowError::Storage);
    };
    // 1. 新 id 已占用 → 直接登录；行缺失（软删）= 已注销。
    let taken = bind_taken(store, resolved, oauth_user)
        .await
        .map_err(|_| OAuthFlowError::Storage)?;
    if taken {
        return user_by_provider(store, resolved, oauth_user)
            .await
            .ok_or(OAuthFlowError::UserDeleted);
    }
    // 2. legacy id 迁移（GitHub login → 数字 id）；迁移失败仅记日志。
    if !oauth_user.legacy_id.is_empty() && !resolved.bind_column.is_empty() {
        let legacy_taken = store
            .bind_id_taken(resolved.bind_column, &oauth_user.legacy_id)
            .await
            .map_err(OAuthFlowError::from)?;
        if legacy_taken
            && let Some(user) = user_by_provider(
                store,
                resolved,
                &OAuthUser {
                    provider_user_id: oauth_user.legacy_id.clone(),
                    ..OAuthUser::default()
                },
            )
            .await
        {
            tracing::warn!(
                event = "oauth_legacy_id_migrated",
                user_id = user.id,
                "migrating legacy provider id to the new id"
            );
            let _ = store
                .update_github_id(user.id, &oauth_user.provider_user_id)
                .await;
            return Ok(user);
        }
    }
    // 3. 注册开关（Go common.RegisterEnabled → catalog 快照）。
    if !state.auth_settings().register_enabled {
        return Err(OAuthFlowError::RegistrationDisabled);
    }
    // 4. 用户名：prefix + (max+1)；oauth 用户名未被占用且 ≤20 字符时优先。
    let max_user_id = store.max_user_id().await.map_err(OAuthFlowError::from)?;
    let mut username = format!("{}{}", resolved.prefix, max_user_id + 1);
    if !oauth_user.username.is_empty()
        && oauth_user.username.chars().count() <= 20
        && !store
            .username_taken(&oauth_user.username)
            .await
            .map_err(OAuthFlowError::from)?
    {
        username = oauth_user.username.clone();
    }
    // 5. 显示名回退链。
    let display_name = if !oauth_user.display_name.is_empty() {
        oauth_user.display_name.clone()
    } else if !oauth_user.username.is_empty() {
        oauth_user.username.clone()
    } else {
        format!("{} User", resolved.name)
    };
    // 6. 邮箱可用性（normalize + exclude 0）。
    let email = oauth_user.email.trim().to_lowercase();
    if !email.is_empty() {
        let available = store
            .email_available(&email, 0)
            .await
            .map_err(OAuthFlowError::from)?;
        if !available {
            return Err(OAuthFlowError::EmailTaken);
        }
    }
    // 7. 邀请人。
    let inviter_id = store.aff_code_owner(affiliate_code).await.unwrap_or(0);
    // 8. quota 取 QuotaForNewUser（Go InsertWithTx 写 common.QuotaForNewUser）。
    let finish = finish_settings(state).await;
    // 9. 事务创建（用户行 + 绑定）。
    let user_id = store
        .create_oauth_user(
            &newapi_identity::oauth_flow::store::NewOAuthUser {
                username: &username,
                display_name: &display_name,
                email: &email,
                bind_column: resolved.bind_column,
                provider_user_id: &oauth_user.provider_user_id,
                custom_provider_id: resolved.custom_id,
                inviter_id,
                quota: finish.quota_for_new_user,
                created_at: crate::http::now_seconds(),
            },
            &newapi_identity::oauth_flow::store::random_aff_code(),
            newapi_identity::registration::DEFAULT_USER_SETTING,
        )
        .await
        .map_err(|error| match error {
            CreateUserError::EmailTaken => OAuthFlowError::EmailTaken,
            CreateUserError::Storage => OAuthFlowError::Storage,
        })?;
    // 10. 提交后收尾（侧栏初始化 / 赠送日志 / 邀请奖励）。
    let display = state.quota_display();
    newapi_identity::registration::RegistrationRepository::new(db.clone())
        .finish_insert(newapi_identity::registration::FinishInsert {
            user_id,
            username: &username,
            inviter_id,
            settings: &finish,
            display: &display,
            now: crate::http::now_seconds(),
        })
        .await;
    user_by_provider(store, resolved, oauth_user)
        .await
        .ok_or(OAuthFlowError::Storage)
}

async fn user_by_provider(
    store: &OAuthUserStore,
    resolved: &ResolvedProvider,
    oauth_user: &OAuthUser,
) -> Option<UserProfile> {
    if resolved.bind_column.is_empty() {
        store
            .user_by_custom_binding(resolved.custom_id, &oauth_user.provider_user_id)
            .await
            .ok()
            .flatten()
    } else {
        store
            .user_by_bind_column(resolved.bind_column, &oauth_user.provider_user_id)
            .await
            .ok()
            .flatten()
    }
}

/// Go `finishInsert` 的选项快照（复用注册切片的装载逻辑）。
pub(crate) async fn finish_settings(
    state: &AppState,
) -> newapi_identity::registration::FinishInsertSettings {
    let mut settings = newapi_identity::registration::FinishInsertSettings {
        quota_for_new_user: 0,
        quota_for_invitee: 0,
        quota_for_inviter: 0,
        payment_compliance_confirmed: false,
    };
    let Some(db) = state.db() else {
        return settings;
    };
    if let Ok(registration) = newapi_catalog::registration_settings::RegistrationSettings::load(
        &db,
        &newapi_catalog::registration_settings::RegistrationSettings::default(),
    )
    .await
    {
        settings.quota_for_new_user = registration.quota_for_new_user;
        settings.quota_for_invitee = registration.quota_for_invitee;
        settings.quota_for_inviter = registration.quota_for_inviter;
    }
    if let Ok(topup) = newapi_billing::topup::TopUpSettings::load(&db).await {
        settings.payment_compliance_confirmed = topup.payment_compliance_confirmed();
    }
    settings
}

// ---------------------------------------------------------------------------
// GET /api/oauth/wechat — Go WeChatAuth
// ---------------------------------------------------------------------------

pub async fn wechat_login(
    State(state): State<AppState>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    injected: Option<Extension<InjectedOAuthTransport>>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return unavailable();
    };
    let Ok(settings) = settings_of(&db).await else {
        return storage_error(&headers);
    };
    if !settings.wechat_auth_enabled {
        return rejected(MSG_WECHAT_DISABLED.to_owned());
    }
    let pairs = query_values(query.as_deref());
    let code = first_value(&pairs, "code").unwrap_or_default();
    let transport = transport_of(injected.as_deref());
    let wechat_id = match wechat_id_by_code(&settings, &code, transport).await {
        Ok(wechat_id) => wechat_id,
        Err(message) => return rejected(message),
    };
    let store = OAuthUserStore::new(db.clone());
    let existing = match store.wechat_id_taken(&wechat_id).await {
        Ok(existing) => existing,
        Err(_) => return storage_error(&headers),
    };
    let user = if existing {
        match store.user_by_bind_column("wechat_id", &wechat_id).await {
            Ok(Some(user)) => user,
            Ok(None) => return rejected(MSG_WECHAT_USER_DELETED.to_owned()),
            Err(_) => return storage_error(&headers),
        }
    } else {
        if !state.auth_settings().register_enabled {
            return rejected(MSG_WECHAT_REGISTER_DISABLED.to_owned());
        }
        match create_wechat_user(&state, &store, &wechat_id).await {
            Ok(user) => user,
            Err(error) => {
                eprintln!("[oauth-debug] create_wechat_user: {error:?}");
                return storage_error(&headers);
            }
        }
    };
    if user.status != 1 {
        return rejected(MSG_WECHAT_BANNED.to_owned());
    }
    let _ = ip;
    setup_login(&state, user.id, "wechat", &ip, &headers).await
}

/// Go `WeChatAuth` 的注册分支：`wechat_<max+1>` / "WeChat User"。
async fn create_wechat_user(
    state: &AppState,
    store: &OAuthUserStore,
    wechat_id: &str,
) -> Result<UserProfile, CreateUserError> {
    let max = store
        .max_user_id()
        .await
        .map_err(|_| CreateUserError::Storage)?;
    let username = format!("wechat_{}", max + 1);
    let finish = finish_settings(state).await;
    let user_id = store
        .create_wechat_user(
            &username,
            "WeChat User",
            wechat_id,
            finish.quota_for_new_user,
            crate::http::now_seconds(),
            &newapi_identity::oauth_flow::store::random_aff_code(),
            newapi_identity::registration::DEFAULT_USER_SETTING,
        )
        .await?;
    let Some(db) = state.db() else {
        return Err(CreateUserError::Storage);
    };
    // 收尾（侧栏/日志/奖励）与密码注册同形。
    let display = state.quota_display();
    newapi_identity::registration::RegistrationRepository::new(db.clone())
        .finish_insert(newapi_identity::registration::FinishInsert {
            user_id,
            username: &username,
            inviter_id: 0,
            settings: &finish,
            display: &display,
            now: crate::http::now_seconds(),
        })
        .await;
    store
        .user_by_id(user_id)
        .await
        .map_err(|_| CreateUserError::Storage)?
        .ok_or(CreateUserError::Storage)
}

/// Go `getWeChatIdByCode`：微信服务器换取 wechat id。远端文本不透传
/// （固定分类折叠，见模块注释）。
async fn wechat_id_by_code(
    settings: &newapi_identity::oauth_flow::settings::OAuthSettings,
    code: &str,
    transport: &dyn OutboundTransport,
) -> Result<String, String> {
    if code.is_empty() {
        return Err(MSG_WECHAT_CODE_INVALID.to_owned());
    }
    let mut url = String::new();
    url.push_str(settings.wechat_server_address.trim_end_matches('/'));
    url.push_str("/api/wechat/user?code=");
    query_encode_into(&mut url, code);
    let response = transport
        .send(OutboundRequest {
            method: "GET",
            url,
            body: None,
            content_type: None,
            authorization: (!settings.wechat_server_token.is_empty())
                .then(|| settings.wechat_server_token.clone()),
            accept: Some("application/json"),
        })
        .await
        .map_err(|_| MSG_WECHAT_UNAVAILABLE.to_owned())?;
    #[derive(serde::Deserialize, Default)]
    struct WeChatResponse {
        #[serde(default)]
        success: bool,
        // Go 把远端 message 透传给用户；本仓库统一折叠为固定文案，
        // 该字段仅为完整反序列化保留。
        #[allow(dead_code)]
        #[serde(default)]
        message: String,
        #[serde(default)]
        data: String,
    }
    let _ = &response;
    let parsed: WeChatResponse =
        serde_json::from_str(&response.body).map_err(|_| MSG_WECHAT_UNAVAILABLE.to_owned())?;
    if !parsed.success {
        return Err(MSG_WECHAT_UNAVAILABLE.to_owned());
    }
    if parsed.data.is_empty() {
        return Err(MSG_WECHAT_CODE_INVALID.to_owned());
    }
    Ok(parsed.data)
}

// ---------------------------------------------------------------------------
// POST /api/oauth/wechat/bind — Go WeChatBind
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize, Default)]
struct WeChatBindRequest {
    #[serde(default)]
    code: String,
}

pub async fn wechat_bind(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    injected: Option<Extension<InjectedOAuthTransport>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(db) = state.db() else {
        return unavailable();
    };
    let Ok(settings) = settings_of(&db).await else {
        return storage_error(&headers);
    };
    if !settings.wechat_auth_enabled {
        return rejected(MSG_WECHAT_DISABLED.to_owned());
    }
    let request: WeChatBindRequest = match bind_json(&headers, &body) {
        Some(request) => request,
        None => return rejected(MSG_WECHAT_INVALID_REQUEST.to_owned()),
    };
    let transport = transport_of(injected.as_deref());
    let wechat_id = match wechat_id_by_code(&settings, &request.code, transport).await {
        Ok(wechat_id) => wechat_id,
        Err(message) => return rejected(message),
    };
    let store = OAuthUserStore::new(db.clone());
    match store.wechat_id_taken(&wechat_id).await {
        Ok(true) => return rejected(MSG_WECHAT_ALREADY_BOUND.to_owned()),
        Ok(false) => {}
        Err(_) => return storage_error(&headers),
    }
    if auth_user.0.user_id == 0 {
        return unauthorized(&headers, MSG_NOT_LOGGED_IN);
    }
    match store
        .update_bind_column(auth_user.0.user_id, "wechat_id", &wechat_id)
        .await
    {
        Ok(()) => Json(json!({ "success": true, "message": "" })).into_response(),
        Err(_) => storage_error(&headers),
    }
}

// ---------------------------------------------------------------------------
// POST /api/oauth/email/bind — Go EmailBind（manage_users.go:1265-1303）
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize, Default)]
struct EmailBindRequest {
    #[serde(default)]
    email: String,
    #[serde(default)]
    code: String,
}

pub async fn email_bind(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(db) = state.db() else {
        return unavailable();
    };
    let request: EmailBindRequest = match bind_json(&headers, &body) {
        Some(request) => request,
        None => return rejected(MSG_EMAIL_INVALID_BODY.to_owned()),
    };
    // Go：`NormalizeEmail`（trim + lowercase）。
    let email = request.email.trim().to_lowercase();
    if !newapi_identity::registration::verify_email_verification_code(&email, &request.code) {
        return rejected(translate(&headers, "user.verification_code_error"));
    }
    if auth_user.0.user_id == 0 {
        return unauthorized(&headers, MSG_NOT_AUTHENTICATED);
    }
    let store = OAuthUserStore::new(db.clone());
    // Go `FillUserById`：行缺失走 CtxApiError（存储分类折叠）。
    if store
        .user_by_id(auth_user.0.user_id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return storage_error(&headers);
    }
    match store.bind_email(auth_user.0.user_id, &email).await {
        Ok(()) => Json(json!({ "success": true, "message": "" })).into_response(),
        Err(EmailBindError::EmailTaken) => {
            rejected(translate(&headers, "user.email_already_taken"))
        }
        Err(_) => storage_error(&headers),
    }
}

// ---------------------------------------------------------------------------
// POST /api/oauth/telegram/bind/start — Go TelegramBindStart
// ---------------------------------------------------------------------------

pub async fn telegram_bind_start(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return unavailable();
    };
    let Ok(settings) = settings_of(&db).await else {
        return storage_error(&headers);
    };
    if !settings.telegram_oauth_enabled {
        return rejected(MSG_TELEGRAM_DISABLED.to_owned());
    }
    let Some(flow) = flow_repo(&state) else {
        return unavailable();
    };
    if auth_user.0.user_id == 0 || auth_user.0.credential != CredentialKind::DashboardSession {
        return unauthorized(&headers, MSG_NOT_LOGGED_IN);
    }
    let now = crate::http::now_seconds();
    // SID 取自当前会话（Go ReadSessionAuthIdentity.SessionID）。
    let sid = match session_identity(&state, &headers, now) {
        Some(identity) => identity.sid,
        None => return unauthorized(&headers, MSG_NOT_LOGGED_IN),
    };
    let token = match flow
        .create(
            oauth_flow::repository::CreateOAuthFlow {
                purpose: oauth_flow::PURPOSE_TELEGRAM_BIND,
                provider: String::new(),
                intent: String::new(),
                user_id: auth_user.0.user_id,
                session_id: sid,
                payload: String::new(),
                expires_at: now + TELEGRAM_TTL,
            },
            now,
        )
        .await
    {
        Ok(token) => token,
        Err(TelegramFlowError::Storage) => return storage_error(&headers),
        Err(_) => return rejected(MSG_TELEGRAM_INVALID.to_owned()),
    };
    let flow_token = token.expose_secret().to_owned();
    success_data(json!({
        "flow_token": flow_token,
        "callback_url": format!("/api/oauth/telegram/bind/{flow_token}"),
        "expires_at": now + TELEGRAM_TTL,
    }))
}

// ---------------------------------------------------------------------------
// GET /api/oauth/telegram/bind/:flow_token — Go TelegramBind（302 回调）
// ---------------------------------------------------------------------------

pub async fn telegram_bind(
    State(state): State<AppState>,
    Extension(ClientIp(_ip)): Extension<ClientIp>,
    injected: Option<Extension<InjectedOAuthTransport>>,
    RawQuery(query): RawQuery,
    Path(flow_token): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return unavailable();
    };
    let Ok(settings) = settings_of(&db).await else {
        return storage_error(&headers);
    };
    if !settings.telegram_oauth_enabled {
        return bind_redirect(&flow_token, T_BIND_DISABLED);
    }
    let pairs = query_values(query.as_deref());
    let _ = injected;
    let now = crate::http::now_seconds();
    // 1. 签名校验（纯函数，Go verifyTelegramAuthorization）。
    let telegram_id = match oauth_flow::telegram::verify_telegram_authorization(
        &pairs,
        &settings.telegram_bot_token,
        now,
    ) {
        Ok(telegram_id) => telegram_id,
        Err(_) => return bind_redirect(&flow_token, T_BIND_INVALID_REQUEST),
    };
    let Some(flow) = flow_repo(&state) else {
        return unavailable();
    };
    // 2. flow 预读（Go GetAuthFlow）。
    let pending = match flow
        .get(
            &flow_token,
            oauth_flow::repository::OAuthFlowMatch {
                purpose: oauth_flow::PURPOSE_TELEGRAM_BIND,
                ..Default::default()
            },
            now,
        )
        .await
    {
        Ok(pending) => pending,
        Err(TelegramFlowError::Storage) => return storage_error(&headers),
        Err(_) => return bind_redirect(&flow_token, T_BIND_FLOW_INVALID),
    };
    // 3. 会话引用预校验（Go ValidateSessionReference 的错误码细分）。
    match session_reference(db, &pending).await {
        SessionReference::Valid => {}
        SessionReference::UserDeleted => return bind_redirect(&flow_token, T_BIND_USER_DELETED),
        SessionReference::UserDisabled => return bind_redirect(&flow_token, T_BIND_USER_DISABLED),
        SessionReference::Invalid => return bind_redirect(&flow_token, T_BIND_SESSION_INVALID),
        SessionReference::Storage => return storage_error(&headers),
    }
    // 4. 断言防重放窗校验（Go telegramAuthorizationClaim）。
    let (assertion, assertion_expires_at) =
        match oauth_flow::telegram::telegram_authorization_claim(&pairs, now) {
            Ok(claim) => claim,
            Err(_) => return bind_redirect(&flow_token, T_BIND_INVALID_REQUEST),
        };
    // 5. 事务：消费 + 断言 + 认领 + 绑定列。
    match flow
        .consume_telegram_bind(
            &flow_token,
            oauth_flow::repository::OAuthFlowMatch {
                purpose: oauth_flow::PURPOSE_TELEGRAM_BIND,
                user_id: pending.user_id,
                session_id: &pending.session_id,
                ..Default::default()
            },
            &telegram_id,
            &assertion,
            assertion_expires_at,
            now,
        )
        .await
    {
        Ok(_) => {
            let mut location = String::from("/oauth/telegram?telegram_bind=success&flow_token=");
            query_encode_into(&mut location, &flow_token);
            redirect(&location)
        }
        Err(TelegramFlowError::Storage) => storage_error(&headers),
        Err(TelegramFlowError::InvalidRequest) => {
            bind_redirect(&flow_token, T_BIND_INVALID_REQUEST)
        }
        Err(TelegramFlowError::FlowInvalid) => bind_redirect(&flow_token, T_BIND_FLOW_INVALID),
        Err(TelegramFlowError::SessionInvalid) => {
            bind_redirect(&flow_token, T_BIND_SESSION_INVALID)
        }
        Err(TelegramFlowError::AlreadyBound) => bind_redirect(&flow_token, T_BIND_ALREADY_BOUND),
        Err(TelegramFlowError::UserDeleted) => bind_redirect(&flow_token, T_BIND_USER_DELETED),
        Err(TelegramFlowError::UserDisabled) => bind_redirect(&flow_token, T_BIND_USER_DISABLED),
        Err(TelegramFlowError::AssertionReplayed) => {
            bind_redirect(&flow_token, T_BIND_INVALID_REQUEST)
        }
        Err(TelegramFlowError::Disabled) => bind_redirect(&flow_token, T_BIND_DISABLED),
    }
}

/// Go `telegramBindFailure`：302 到固定错误页。
fn bind_redirect(flow_token: &str, error_code: &str) -> Response {
    let mut location = String::from("/oauth/telegram?telegram_bind=error&flow_token=");
    query_encode_into(&mut location, flow_token);
    location.push_str("&error_code=");
    query_encode_into(&mut location, error_code);
    redirect(&location)
}

/// Go `ValidateSessionReference` 的预校验分类。
enum SessionReference {
    Valid,
    Invalid,
    UserDeleted,
    UserDisabled,
    Storage,
}

/// 预校验：用户存在且启用、会话 active/未撤销/未过期/auth_version 一致。
/// 用户缺失优先（Go 的 USER_DELETED），禁用次之。
async fn session_reference(
    db: newapi_storage::Database,
    pending: &oauth_flow::repository::OAuthFlow,
) -> SessionReference {
    if pending.user_id <= 0 || pending.session_id.trim().is_empty() {
        return SessionReference::Invalid;
    }
    let user: Result<Option<(i64, i64)>, sqlx::Error> = match &db {
        newapi_storage::Database::Sqlite(pool) => {
            sqlx::query_as(
                "SELECT CAST(status AS BIGINT), CAST(auth_version AS BIGINT) FROM users \
             WHERE id = $1 AND deleted_at IS NULL",
            )
            .bind(pending.user_id)
            .fetch_optional(pool)
            .await
        }
        newapi_storage::Database::Postgres(pool) => {
            sqlx::query_as(
                "SELECT CAST(status AS BIGINT), CAST(auth_version AS BIGINT) FROM users \
             WHERE id = $1 AND deleted_at IS NULL",
            )
            .bind(pending.user_id)
            .fetch_optional(pool)
            .await
        }
    };
    let user = match user {
        Ok(user) => user,
        Err(_) => return SessionReference::Storage,
    };
    let Some((status, auth_version)) = user else {
        return SessionReference::UserDeleted;
    };
    if status != 1 {
        return SessionReference::UserDisabled;
    }
    let session: Result<Option<(String, i64, i64, i64)>, sqlx::Error> = match &db {
        newapi_storage::Database::Sqlite(pool) => {
            sqlx::query_as(
                "SELECT status, CAST(revoked_at AS BIGINT), CAST(expires_at AS BIGINT), \
             CAST(user_auth_version AS BIGINT) FROM user_sessions \
             WHERE sid = $1 AND user_id = $2",
            )
            .bind(&pending.session_id)
            .bind(pending.user_id)
            .fetch_optional(pool)
            .await
        }
        newapi_storage::Database::Postgres(pool) => {
            sqlx::query_as(
                "SELECT status, CAST(revoked_at AS BIGINT), CAST(expires_at AS BIGINT), \
             CAST(user_auth_version AS BIGINT) FROM user_sessions \
             WHERE sid = $1 AND user_id = $2",
            )
            .bind(&pending.session_id)
            .bind(pending.user_id)
            .fetch_optional(pool)
            .await
        }
    };
    let session = match session {
        Ok(session) => session,
        Err(_) => return SessionReference::Storage,
    };
    let Some((session_status, revoked_at, expires_at, session_auth_version)) = session else {
        return SessionReference::Invalid;
    };
    if session_status != "active"
        || revoked_at != 0
        || expires_at <= crate::http::now_seconds()
        || session_auth_version != auth_version
    {
        return SessionReference::Invalid;
    }
    SessionReference::Valid
}

// ---------------------------------------------------------------------------
// GET /api/oauth/telegram/login — Go TelegramLogin
// ---------------------------------------------------------------------------

pub async fn telegram_login(
    State(state): State<AppState>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    // telegram_login 不发起出站调用；transport 注入仅供其它 handler 使用。
    #[allow(unused_variables)] injected: Option<Extension<InjectedOAuthTransport>>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return unavailable();
    };
    let Ok(settings) = settings_of(&db).await else {
        return storage_error(&headers);
    };
    if !settings.telegram_oauth_enabled {
        return rejected(MSG_TELEGRAM_DISABLED.to_owned());
    }
    let pairs = query_values(query.as_deref());
    let now = crate::http::now_seconds();
    let telegram_id = match oauth_flow::telegram::verify_telegram_authorization(
        &pairs,
        &settings.telegram_bot_token,
        now,
    ) {
        Ok(telegram_id) => telegram_id,
        Err(_) => return rejected(MSG_TELEGRAM_INVALID.to_owned()),
    };
    let store = OAuthUserStore::new(db.clone());
    let user = match store.user_by_telegram_id(&telegram_id).await {
        Ok(Some(user)) => user,
        // Go：FillUserByTelegramId 的错误文本（"该 Telegram 账户未绑定"）。
        Ok(None) => return rejected(MSG_TELEGRAM_NOT_BOUND.to_owned()),
        Err(_) => return storage_error(&headers),
    };
    let Some(flow) = flow_repo(&state) else {
        return unavailable();
    };
    let (assertion, assertion_expires_at) =
        match oauth_flow::telegram::telegram_authorization_claim(&pairs, now) {
            Ok(claim) => claim,
            Err(_) => return rejected(MSG_TELEGRAM_INVALID.to_owned()),
        };
    if flow
        .claim_assertion(&assertion, assertion_expires_at, now)
        .await
        .is_err()
    {
        // Go：重放拒绝是 403 + 固定文案。
        let mut response = rejected(MSG_TELEGRAM_REPLAYED.to_owned());
        *response.status_mut() = StatusCode::FORBIDDEN;
        return response;
    }
    let _ = ip;
    setup_login(&state, user.id, "telegram", &ip, &headers).await
}
