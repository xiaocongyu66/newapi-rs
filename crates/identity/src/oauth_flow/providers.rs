//! OAuth 提供商的解析与出站交互：Go `security/oauth` 包的四个内置实现
//! （`github.go` / `discord.go` / `linuxdo.go` / `oidc.go`）、
//! `generic.go` 的自定义提供商实现，以及 `registry.go` 的解析语义。
//!
//! ## 与 Go 注册表的差异
//!
//! Go 维护进程内注册表（启动装载 custom 表、管理端 CRUD 同步增删）。
//! 本端口按请求解析：内置 slug 查快照，自定义 slug 现读
//! `custom_oauth_providers` 行——行存在即"已注册"（无论 enabled，对应
//! Go 的 IsEnabled=false 分支），行不存在即"未知提供商"（Go 的注册表
//! 在删除后同样查不到）。可观察行为一致。
//!
//! ## 出站传输
//!
//! 所有 provider 的 token 交换与用户信息请求都经 [`OutboundTransport`]，
//! 测试可注入（与 `turnstile::Verifier` / `qqbot::QQBotApi` 同一约定）。
//! 错误不携带 URL、响应体或 secret；客户端与日志只看分类与提供商显示名。

use serde::Deserialize;

/// 出站请求的最小描述；`body` 已按目标服务编码（JSON 或表单）。
pub struct OutboundRequest {
    pub method: &'static str,
    pub url: String,
    pub body: Option<String>,
    pub content_type: Option<&'static str>,
    pub authorization: Option<String>,
    pub accept: Option<&'static str>,
}

/// 出站响应的最小投影。
pub struct OutboundResponse {
    pub status: u16,
    pub body: String,
}

/// 出站调用失败分类；不携带远端文本。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutboundError {
    /// 连接、TLS、超时或响应体读取失败。
    Transport,
}

pub type OutboundFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<OutboundResponse, OutboundError>> + Send + 'a>,
>;

/// OAuth 出站端口；实现不得把 URL 或响应体塞进错误载荷。
pub trait OutboundTransport: Send + Sync {
    fn send(&self, request: OutboundRequest) -> OutboundFuture<'_>;
}

/// 提供商交互失败的固定分类；`provider` 只携带 i18n 模板参数（提供商
/// 显示名），绝不携带密钥或响应体。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderError {
    /// Go `NewOAuthError(MsgOAuthInvalidCode)`：code 为空。
    InvalidCode,
    /// Go `MsgOAuthConnectFailed`。
    ConnectFailed(String),
    /// Go `MsgOAuthTokenFailed`。
    TokenFailed(String),
    /// Go `MsgOAuthUserInfoEmpty`。
    UserInfoEmpty(String),
    /// Go `MsgOAuthGetUserErr`。
    GetUserFailed(String),
    /// LinuxDO 信任等级不足（Go `TrustLevelError`）。
    TrustLevel,
    /// 自定义提供商访问策略拒绝（Go `AccessDeniedError`，直传文案）。
    Denied(String),
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("oauth provider interaction failed")
    }
}

impl std::error::Error for ProviderError {}

/// Go `OAuthToken` 的最小投影；用户信息请求只需要这两个字段。
pub struct ProviderToken {
    pub access_token: String,
    pub token_type: String,
}

/// Go `OAuthUser`：`legacy_id` 仅 GitHub 提供（login → 数字 id 迁移）。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OAuthUser {
    pub provider_user_id: String,
    pub username: String,
    pub display_name: String,
    pub email: String,
    pub legacy_id: String,
}

/// 解析后的提供商视图：HTTP 编排层只需要这些行为。
#[derive(Clone, Debug)]
pub struct ResolvedProvider {
    /// Go `GetName()`：i18n 模板参数使用。
    pub name: String,
    /// 用户表绑定列（内置四家）；generic 返回空串（绑定住在
    /// user_oauth_bindings）。Go `ProviderUserIDColumn()`。
    pub bind_column: &'static str,
    /// 自动生成用户名前缀。Go `GetProviderPrefix()`。
    pub prefix: String,
    /// custom_oauth_providers 的行 id；内置提供商为 0。
    pub custom_id: i64,
    /// Go `IsEnabled()`。
    pub enabled: bool,
    kind: ProviderKind,
}

#[derive(Clone, Debug)]
enum ProviderKind {
    GitHub {
        client_id: String,
        client_secret: String,
    },
    Discord {
        client_id: String,
        client_secret: String,
        redirect_uri: String,
    },
    LinuxDo {
        client_id: String,
        client_secret: String,
        minimum_trust_level: i64,
        token_endpoint: String,
        user_endpoint: String,
        redirect_uri: String,
    },
    Oidc {
        client_id: String,
        client_secret: String,
        token_endpoint: String,
        user_info_endpoint: String,
        redirect_uri: String,
    },
    Generic {
        client_id: String,
        client_secret: String,
        token_endpoint: String,
        user_info_endpoint: String,
        redirect_uri: String,
        auth_style: i64,
        user_id_field: String,
        username_field: String,
        display_name_field: String,
        email_field: String,
        access_policy: String,
        access_denied_message: String,
    },
}

impl ResolvedProvider {
    /// LinuxDO 的 redirect_uri 在 Go 里按请求 Host 现算
    /// （`linuxdo.go:56-61`：scheme 来自 `c.IsTLS()`、host 来自
    /// `c.Host()`）。本端口终结的传输恒为明文，scheme 固定 http；
    /// 编排层在拿到 Host 头后调用本方法回填。
    pub fn with_redirect_host(mut self, host: &str) -> Self {
        if let ProviderKind::LinuxDo { redirect_uri, .. } = &mut self.kind {
            *redirect_uri = format!("http://{host}/api/oauth/linuxdo");
        }
        self
    }

    /// Go `GetProvider(name)`（`registry.go:42-46`）+ 四个内置 `init()`
    /// 注册：slug 固定为 `github` / `discord` / `linuxdo` / `oidc`；
    /// 其它 slug 现读 custom 行（存在即注册，enabled 决定可用性）。
    pub fn resolve(
        name: &str,
        settings: &crate::oauth_flow::settings::OAuthSettings,
        custom: Option<&crate::custom_oauth::CustomOAuthProviderRecord>,
    ) -> Option<Self> {
        let kind = match name {
            "github" => ProviderKind::GitHub {
                client_id: settings.github_client_id.clone(),
                client_secret: settings.github_client_secret.clone(),
            },
            "discord" => ProviderKind::Discord {
                client_id: settings.discord_client_id.clone(),
                client_secret: settings.discord_client_secret.clone(),
                // Go `discord.go:58`：`%s/oauth/discord`（egress ServerAddress）。
                redirect_uri: format!(
                    "{}/oauth/discord",
                    settings.server_address.trim_end_matches('/')
                ),
            },
            "linuxdo" => ProviderKind::LinuxDo {
                // Go `GetEnvOrDefaultString`：每次调用读环境。
                token_endpoint: env_or(
                    "LINUX_DO_TOKEN_ENDPOINT",
                    "https://connect.linux.do/oauth2/token",
                ),
                user_endpoint: env_or(
                    "LINUX_DO_USER_ENDPOINT",
                    "https://connect.linux.do/api/user",
                ),
                client_id: settings.linuxdo_client_id.clone(),
                client_secret: settings.linuxdo_client_secret.clone(),
                minimum_trust_level: settings.linuxdo_minimum_trust_level,
                // Go `linuxdo.go:61`：`%s://%s/api/oauth/linuxdo`，host 取
                // 请求 Host 头（Go `c.Host()`），不是 ServerAddress；本端口
                // 终结的传输恒为明文（与 passkey 切片同一立场），scheme
                // 固定 http。真实值由编排层经 `with_redirect_host` 注入。
                redirect_uri: String::new(),
            },
            "oidc" => ProviderKind::Oidc {
                client_id: settings.oidc_client_id.clone(),
                client_secret: settings.oidc_client_secret.clone(),
                token_endpoint: settings.oidc_token_endpoint.clone(),
                user_info_endpoint: settings.oidc_user_info_endpoint.clone(),
                // Go `oidc.go:60`：`%s/oauth/oidc`。
                redirect_uri: format!(
                    "{}/oauth/oidc",
                    settings.server_address.trim_end_matches('/')
                ),
            },
            slug => {
                let custom = custom?;
                ProviderKind::Generic {
                    client_id: custom.client_id.clone(),
                    client_secret: custom.client_secret.clone(),
                    token_endpoint: custom.token_endpoint.clone(),
                    user_info_endpoint: custom.user_info_endpoint.clone(),
                    // Go `generic.go:97`：`%s/oauth/%s`。
                    redirect_uri: format!(
                        "{}/oauth/{slug}",
                        settings.server_address.trim_end_matches('/')
                    ),
                    auth_style: custom.auth_style,
                    user_id_field: custom.user_id_field.clone(),
                    username_field: custom.username_field.clone(),
                    display_name_field: custom.display_name_field.clone(),
                    email_field: custom.email_field.clone(),
                    access_policy: custom.access_policy.clone(),
                    access_denied_message: custom.access_denied_message.clone(),
                }
            }
        };
        let (name, enabled, custom_id, bind_column, prefix) = match &kind {
            ProviderKind::GitHub { .. } => (
                "GitHub",
                settings.github_oauth_enabled,
                0,
                "github_id",
                "github_",
            ),
            ProviderKind::Discord { .. } => (
                "Discord",
                settings.discord_enabled,
                0,
                "discord_id",
                "discord_",
            ),
            ProviderKind::LinuxDo { .. } => (
                "Linux DO",
                settings.linuxdo_oauth_enabled,
                0,
                "linux_do_id",
                "linuxdo_",
            ),
            ProviderKind::Oidc { .. } => {
                // Go `GetEffectiveDisplayName`：trim 后非空才用配置值。
                let display = settings.oidc_display_name.trim();
                (
                    if display.is_empty() { "OIDC" } else { display },
                    settings.oidc_enabled,
                    0,
                    "oidc_id",
                    "oidc_",
                )
            }
            ProviderKind::Generic { .. } => (
                custom.map(|row| row.name.as_str()).unwrap_or_default(),
                custom.is_some_and(|row| row.enabled),
                custom.map(|row| row.id).unwrap_or_default(),
                "",
                "",
            ),
        };
        Some(Self {
            name: name.to_owned(),
            bind_column,
            prefix: prefix.to_owned(),
            custom_id,
            enabled,
            kind,
        })
    }

    /// Go `ExchangeToken`：code → access token。请求形状逐字对齐：
    /// GitHub 是 JSON 体 + `Accept: application/json`；Discord/OIDC 是
    /// 表单体；LinuxDO 是表单体 + Basic 头；generic 按 auth_style。
    pub async fn exchange_token(
        &self,
        code: &str,
        transport: &dyn OutboundTransport,
    ) -> Result<ProviderToken, ProviderError> {
        if code.is_empty() {
            return Err(ProviderError::InvalidCode);
        }
        let request = match &self.kind {
            ProviderKind::GitHub {
                client_id,
                client_secret,
            } => OutboundRequest {
                method: "POST",
                url: "https://github.com/login/oauth/access_token".to_owned(),
                // Go `github.go:54-58`：`map[string]string` 序列化。
                body: Some(
                    serde_json::json!({
                        "client_id": client_id,
                        "client_secret": client_secret,
                        "code": code,
                    })
                    .to_string(),
                ),
                content_type: Some("application/json"),
                authorization: None,
                accept: Some("application/json"),
            },
            ProviderKind::Discord {
                client_id,
                client_secret,
                redirect_uri,
            } => OutboundRequest {
                method: "POST",
                url: "https://discord.com/api/v10/oauth2/token".to_owned(),
                body: Some(form(&[
                    ("client_id", client_id),
                    ("client_secret", client_secret),
                    ("code", code),
                    ("grant_type", "authorization_code"),
                    ("redirect_uri", redirect_uri),
                ])),
                content_type: Some("application/x-www-form-urlencoded"),
                authorization: None,
                accept: Some("application/json"),
            },
            ProviderKind::LinuxDo {
                client_id,
                client_secret,
                token_endpoint,
                redirect_uri,
                ..
            } => OutboundRequest {
                method: "POST",
                url: token_endpoint.clone(),
                body: Some(form(&[
                    ("grant_type", "authorization_code"),
                    ("code", code),
                    ("redirect_uri", redirect_uri),
                ])),
                content_type: Some("application/x-www-form-urlencoded"),
                // Go：Basic(client_id:client_secret)。
                authorization: Some(basic(client_id, client_secret)),
                accept: Some("application/json"),
            },
            ProviderKind::Oidc {
                client_id,
                client_secret,
                token_endpoint,
                redirect_uri,
                ..
            } => OutboundRequest {
                method: "POST",
                url: token_endpoint.clone(),
                body: Some(form(&[
                    ("client_id", client_id),
                    ("client_secret", client_secret),
                    ("code", code),
                    ("grant_type", "authorization_code"),
                    ("redirect_uri", redirect_uri),
                ])),
                content_type: Some("application/x-www-form-urlencoded"),
                authorization: None,
                accept: Some("application/json"),
            },
            ProviderKind::Generic {
                client_id,
                client_secret,
                token_endpoint,
                redirect_uri,
                auth_style,
                ..
            } => {
                // Go `generic.go:104-129`：auto/params 把凭据放进表单
                // （auto 默认 params），header 风格（2）放 Basic。
                let (authorization, credentials_in_form) = if *auth_style == 2 {
                    (Some(basic(client_id, client_secret)), false)
                } else {
                    (None, true)
                };
                let mut pairs = vec![
                    ("grant_type", "authorization_code"),
                    ("code", code),
                    ("redirect_uri", redirect_uri.as_str()),
                ];
                if credentials_in_form {
                    pairs.push(("client_id", client_id));
                    pairs.push(("client_secret", client_secret));
                }
                OutboundRequest {
                    method: "POST",
                    url: token_endpoint.clone(),
                    body: Some(form(&pairs)),
                    content_type: Some("application/x-www-form-urlencoded"),
                    authorization,
                    accept: Some("application/json"),
                }
            }
        };
        let response = transport
            .send(request)
            .await
            .map_err(|_| ProviderError::ConnectFailed(self.name.clone()))?;
        decode_token_response(&response, &self.name, self.custom_id != 0)
    }

    /// Go `GetUserInfo`：access token → 提供商用户投影。
    pub async fn get_user_info(
        &self,
        token: &ProviderToken,
        transport: &dyn OutboundTransport,
    ) -> Result<OAuthUser, ProviderError> {
        let (request, parser) = match &self.kind {
            ProviderKind::GitHub { .. } => (
                OutboundRequest {
                    method: "GET",
                    url: "https://api.github.com/user".to_owned(),
                    body: None,
                    content_type: None,
                    authorization: Some(bearer(&token.access_token)),
                    accept: Some("application/json"),
                },
                UserInfoParser::GitHub,
            ),
            ProviderKind::Discord { .. } => (
                OutboundRequest {
                    method: "GET",
                    url: "https://discord.com/api/v10/users/@me".to_owned(),
                    body: None,
                    content_type: None,
                    authorization: Some(bearer(&token.access_token)),
                    accept: Some("application/json"),
                },
                UserInfoParser::Discord,
            ),
            ProviderKind::LinuxDo {
                user_endpoint,
                minimum_trust_level,
                ..
            } => (
                OutboundRequest {
                    method: "GET",
                    url: user_endpoint.clone(),
                    body: None,
                    content_type: None,
                    authorization: Some(bearer(&token.access_token)),
                    accept: Some("application/json"),
                },
                UserInfoParser::LinuxDo {
                    minimum_trust_level: *minimum_trust_level,
                },
            ),
            ProviderKind::Oidc {
                user_info_endpoint, ..
            } => (
                OutboundRequest {
                    method: "GET",
                    url: user_info_endpoint.clone(),
                    body: None,
                    content_type: None,
                    authorization: Some(bearer(&token.access_token)),
                    accept: Some("application/json"),
                },
                UserInfoParser::Oidc,
            ),
            ProviderKind::Generic {
                user_info_endpoint,
                user_id_field,
                username_field,
                display_name_field,
                email_field,
                access_policy,
                access_denied_message,
                ..
            } => (
                // Go `generic.go:211-213`：Authorization 头的 token type
                // 归一化（空 / Bearer → Bearer，其它原样）。
                OutboundRequest {
                    method: "GET",
                    url: user_info_endpoint.clone(),
                    body: None,
                    content_type: None,
                    authorization: Some(format!(
                        "{} {}",
                        normalize_token_type(&token.token_type),
                        token.access_token
                    )),
                    accept: Some("application/json"),
                },
                UserInfoParser::Generic {
                    user_id_field: user_id_field.clone(),
                    username_field: username_field.clone(),
                    display_name_field: display_name_field.clone(),
                    email_field: email_field.clone(),
                    access_policy: access_policy.clone(),
                    access_denied_message: access_denied_message.clone(),
                },
            ),
        };
        let response = transport
            .send(request)
            .await
            .map_err(|_| ProviderError::ConnectFailed(self.name.clone()))?;
        parser.parse(&response, self)
    }
}

/// 各家用户信息响应的解析分支；形状差异都收口在这里。
enum UserInfoParser {
    GitHub,
    Discord,
    LinuxDo {
        minimum_trust_level: i64,
    },
    Oidc,
    Generic {
        user_id_field: String,
        username_field: String,
        display_name_field: String,
        email_field: String,
        access_policy: String,
        access_denied_message: String,
    },
}

impl UserInfoParser {
    fn parse(
        &self,
        response: &OutboundResponse,
        provider: &ResolvedProvider,
    ) -> Result<OAuthUser, ProviderError> {
        match self {
            Self::GitHub => {
                // Go `github.go:126-134`：非 200 → MsgOAuthGetUserErr。
                if response.status != 200 {
                    return Err(ProviderError::GetUserFailed(provider.name.clone()));
                }
                let user: GitHubUser =
                    serde_json::from_str(&response.body).map_err(json_decode_error)?;
                // Go：id==0 或 login 空 → MsgOAuthUserInfoEmpty。
                if user.id == 0 || user.login.is_empty() {
                    return Err(ProviderError::UserInfoEmpty(provider.name.clone()));
                }
                Ok(OAuthUser {
                    provider_user_id: user.id.to_string(),
                    username: user.login.clone(),
                    display_name: user.name,
                    email: user.email,
                    // Go：`Extra["legacy_id"] = login`（旧 login → 数字 id 迁移）。
                    legacy_id: user.login,
                })
            }
            Self::Discord => {
                if response.status != 200 {
                    return Err(ProviderError::GetUserFailed(provider.name.clone()));
                }
                let user: DiscordUser =
                    serde_json::from_str(&response.body).map_err(json_decode_error)?;
                if user.id.is_empty() || user.username.is_empty() {
                    return Err(ProviderError::UserInfoEmpty(provider.name.clone()));
                }
                Ok(OAuthUser {
                    provider_user_id: user.id,
                    username: user.username,
                    // Go：`global_name`，可能为空。
                    display_name: user.global_name,
                    email: String::new(),
                    legacy_id: String::new(),
                })
            }
            Self::LinuxDo {
                minimum_trust_level,
            } => {
                let user: LinuxDoUser =
                    serde_json::from_str(&response.body).map_err(json_decode_error)?;
                if user.id == 0 {
                    return Err(ProviderError::UserInfoEmpty(provider.name.clone()));
                }
                if user.trust_level < *minimum_trust_level {
                    return Err(ProviderError::TrustLevel);
                }
                Ok(OAuthUser {
                    provider_user_id: user.id.to_string(),
                    username: user.username,
                    display_name: user.name,
                    email: String::new(),
                    legacy_id: String::new(),
                })
            }
            Self::Oidc => {
                if response.status != 200 {
                    return Err(ProviderError::GetUserFailed(provider.name.clone()));
                }
                let user: OidcUser =
                    serde_json::from_str(&response.body).map_err(json_decode_error)?;
                // Go：sub 或 email 为空都算失败。
                if user.sub.is_empty() || user.email.is_empty() {
                    return Err(ProviderError::UserInfoEmpty(provider.name.clone()));
                }
                Ok(OAuthUser {
                    provider_user_id: user.sub,
                    username: user.preferred_username,
                    display_name: user.name,
                    email: user.email,
                    legacy_id: String::new(),
                })
            }
            Self::Generic {
                user_id_field,
                username_field,
                display_name_field,
                email_field,
                access_policy,
                access_denied_message,
            } => {
                if response.status != 200 {
                    // Go `generic.go:227-230`：非 200 → MsgOAuthGetUserErr。
                    return Err(ProviderError::GetUserFailed(provider.name.clone()));
                }
                let value: serde_json::Value =
                    serde_json::from_str(&response.body).map_err(json_decode_error)?;
                // Go：字符串路径读空时回退 Raw 去引号（数字 id 的主路径）。
                let mut provider_user_id = string_at(&value, user_id_field);
                if provider_user_id.is_empty() {
                    provider_user_id = raw_at(&value, user_id_field);
                }
                if provider_user_id.is_empty() {
                    return Err(ProviderError::UserInfoEmpty(provider.name.clone()));
                }
                // Go `generic.go:266-280`：访问策略评估，拒绝即直传文案。
                if !access_policy.trim().is_empty() {
                    let failure = evaluate_access_policy(&value, access_policy.trim());
                    if let Some(failure) = failure {
                        return Err(ProviderError::Denied(render_denied(
                            access_denied_message,
                            &provider.name,
                            &value,
                            &failure,
                        )));
                    }
                }
                Ok(OAuthUser {
                    provider_user_id,
                    username: string_at(&value, username_field),
                    display_name: string_at(&value, display_name_field),
                    email: string_at(&value, email_field),
                    legacy_id: String::new(),
                })
            }
        }
    }
}

/// Go 的解码失败统一归 GetUserFailed 分类（Go `CtxApiError(err)` 的
/// 原始文本本端口不透传）。
fn json_decode_error(_: serde_json::Error) -> ProviderError {
    ProviderError::GetUserFailed(String::from("decode"))
}

// ---------------------------------------------------------------------------
// 出站载荷编码
// ---------------------------------------------------------------------------

/// Go `url.Values.Encode` 的转义（QueryEscape）；键序由调用点数组固定，
/// 目标服务器只看键值对。
fn form(pairs: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (index, (key, value)) in pairs.iter().enumerate() {
        if index > 0 {
            out.push('&');
        }
        query_encode_into(&mut out, key);
        out.push('=');
        query_encode_into(&mut out, value);
    }
    out
}

/// Go `url.QueryEscape`：未保留字符原样，空格转 `+`，其余 `%XX` 大写。
pub fn query_encode_into(out: &mut String, value: &str) {
    for &byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(byte));
            }
            b' ' => out.push('+'),
            _ => {
                out.push('%');
                out.push_str(&format!("{byte:02X}"));
            }
        }
    }
}

/// Go `url.QueryEscape` 的反向解码（generic 表单回退分支用）。
pub(crate) fn query_decode(value: &str) -> String {
    let bytes = value.as_bytes();
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

fn basic(client_id: &str, client_secret: &str) -> String {
    use base64::Engine;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{client_secret}"))
    )
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_owned())
}

/// Go `normalizeAuthorizationTokenType`（`generic.go:325-331`）。
fn normalize_token_type(token_type: &str) -> String {
    let trimmed = token_type.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("Bearer") {
        "Bearer".to_owned()
    } else {
        trimmed.to_owned()
    }
}

// ---------------------------------------------------------------------------
// token / 用户信息响应解码
// ---------------------------------------------------------------------------

#[derive(Default, Deserialize)]
struct TokenResponse {
    #[serde(default)]
    access_token: String,
    #[serde(default)]
    token_type: String,
}

/// 解析 token 响应；`form_fallback`（generic）在 JSON 解析失败时按
/// 表单解析（Go `generic.go:167-177` 的 GitHub 式回退）。
fn decode_token_response(
    response: &OutboundResponse,
    provider_name: &str,
    form_fallback: bool,
) -> Result<ProviderToken, ProviderError> {
    let parsed: Option<TokenResponse> = match serde_json::from_str(&response.body) {
        Ok(parsed) => Some(parsed),
        Err(_) if form_fallback => {
            let mut parsed = TokenResponse::default();
            for pair in response.body.split('&') {
                if let Some((key, value)) = pair.split_once('=') {
                    match key {
                        "access_token" => parsed.access_token = query_decode(value),
                        "token_type" => parsed.token_type = query_decode(value),
                        _ => {}
                    }
                }
            }
            Some(parsed)
        }
        // Go：解码失败走 `CtxApiError(err)`（原始文本）；本端口按仓库
        // 约定折叠为 TokenFailed 分类。
        Err(_) => None,
    };
    let Some(parsed) = parsed else {
        return Err(ProviderError::TokenFailed(provider_name.to_owned()));
    };
    if parsed.access_token.is_empty() {
        // Go：空 token → MsgOAuthTokenFailed。
        return Err(ProviderError::TokenFailed(provider_name.to_owned()));
    }
    Ok(ProviderToken {
        access_token: parsed.access_token,
        token_type: parsed.token_type,
    })
}

#[derive(Default, Deserialize)]
struct GitHubUser {
    #[serde(default)]
    id: i64,
    #[serde(default)]
    login: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    email: String,
}

#[derive(Default, Deserialize)]
struct DiscordUser {
    #[serde(default)]
    id: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    global_name: String,
}

#[derive(Default, Deserialize)]
struct LinuxDoUser {
    #[serde(default)]
    id: i64,
    #[serde(default)]
    username: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    trust_level: i64,
}

#[derive(Default, Deserialize)]
struct OidcUser {
    #[serde(default)]
    sub: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    preferred_username: String,
}

// ---------------------------------------------------------------------------
// generic 的点路径读取与访问策略
// ---------------------------------------------------------------------------

/// Go `gjson.Get(body, path).String()`：点路径逐段下钻对象；数字/布尔按
/// JSON 文本转字符串，字符串原样。
fn string_at(value: &serde_json::Value, path: &str) -> String {
    let Some(target) = navigate(value, path) else {
        return String::new();
    };
    match target {
        serde_json::Value::String(text) => text.clone(),
        serde_json::Value::Number(number) => number.to_string(),
        serde_json::Value::Bool(flag) => flag.to_string(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Go 的数字 id 回退：`gjson.Result.Raw` 去引号。
fn raw_at(value: &serde_json::Value, path: &str) -> String {
    let Some(target) = navigate(value, path) else {
        return String::new();
    };
    match target {
        serde_json::Value::String(text) => text.trim_matches('"').to_owned(),
        other => other.to_string(),
    }
}

/// 点路径下钻：`data.user.id` 逐段取对象字段；数组段按索引下钻。
fn navigate<'a>(value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut current = value;
    for segment in path.split('.') {
        match current {
            serde_json::Value::Object(map) => current = map.get(segment)?,
            serde_json::Value::Array(items) => {
                let index: usize = segment.parse().ok()?;
                current = items.get(index)?;
            }
            _ => return None,
        }
    }
    Some(current)
}

/// Go `evaluateAccessPolicy` 的判定输出；只保留渲染拒绝文案需要的字段。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyFailure {
    pub field: String,
    pub op: String,
    pub expected: serde_json::Value,
}

/// 解析并评估访问策略；`None` = 放行。
fn evaluate_access_policy(value: &serde_json::Value, raw: &str) -> Option<PolicyFailure> {
    let policy: serde_json::Value = serde_json::from_str(raw).ok()?;
    let logic = policy
        .get("logic")
        .and_then(|item| item.as_str())
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| "and".to_owned());
    let conditions = policy
        .get("conditions")
        .and_then(|item| item.as_array())
        .cloned()
        .unwrap_or_default();
    let groups = policy
        .get("groups")
        .and_then(|item| item.as_array())
        .cloned()
        .unwrap_or_default();
    if conditions.is_empty() && groups.is_empty() {
        return None;
    }
    if logic == "or" {
        // Go：任一通过即放行；全部失败回首个失败。
        let mut first_failure = None;
        for condition in &conditions {
            match evaluate_condition(value, condition) {
                None => return None,
                Some(failure) if first_failure.is_none() => first_failure = Some(failure),
                Some(_) => {}
            }
        }
        for group in &groups {
            match evaluate_access_policy(value, &group.to_string()) {
                None => return None,
                Some(failure) if first_failure.is_none() => first_failure = Some(failure),
                Some(_) => {}
            }
        }
        return first_failure;
    }
    for condition in &conditions {
        if let Some(failure) = evaluate_condition(value, condition) {
            return Some(failure);
        }
    }
    for group in &groups {
        if let Some(failure) = evaluate_access_policy(value, &group.to_string()) {
            return Some(failure);
        }
    }
    None
}

/// Go `evaluateAccessCondition`：op 归一化（trim + 小写）后分发。
fn evaluate_condition(
    value: &serde_json::Value,
    condition: &serde_json::Value,
) -> Option<PolicyFailure> {
    let field = condition.get("field")?.as_str()?.trim().to_owned();
    let op = condition
        .get("op")
        .and_then(|item| item.as_str())
        .map(|text| text.trim().to_ascii_lowercase())?;
    let expected = condition
        .get("value")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let target = navigate(value, &field);
    let outcome = match op.as_str() {
        "exists" => target.is_some(),
        "not_exists" => target.is_none(),
        "eq" => compare(target, &expected) == Some(std::cmp::Ordering::Equal),
        "ne" => compare(target, &expected) != Some(std::cmp::Ordering::Equal),
        "gt" => compare(target, &expected) == Some(std::cmp::Ordering::Greater),
        "gte" => matches!(
            compare(target, &expected),
            Some(std::cmp::Ordering::Greater | std::cmp::Ordering::Equal)
        ),
        "lt" => compare(target, &expected) == Some(std::cmp::Ordering::Less),
        "lte" => matches!(
            compare(target, &expected),
            Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal)
        ),
        "in" => expected.as_array().is_some_and(|list| {
            list.iter()
                .any(|item| compare(target, item) == Some(std::cmp::Ordering::Equal))
        }),
        "not_in" => !expected.as_array().is_some_and(|list| {
            list.iter()
                .any(|item| compare(target, item) == Some(std::cmp::Ordering::Equal))
        }),
        "contains" => contains(target, &expected),
        "not_contains" => !contains(target, &expected),
        _ => false,
    };
    (!outcome).then_some(PolicyFailure {
        field,
        op,
        expected,
    })
}

/// Go `compareAny`：先按数值比较，失败退回字符串字典序。
fn compare(
    left: Option<&serde_json::Value>,
    right: &serde_json::Value,
) -> Option<std::cmp::Ordering> {
    let left = left?;
    if let (Some(a), Some(b)) = (as_f64(left), as_f64(right)) {
        return a.partial_cmp(&b);
    }
    let a = text_of(left);
    let b = text_of(right);
    Some(a.cmp(&b))
}

/// Go `containsValue`：字符串包含或数组等值成员。
fn contains(target: Option<&serde_json::Value>, expected: &serde_json::Value) -> bool {
    match target {
        Some(serde_json::Value::String(text)) => text.contains(&text_of(expected)),
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .any(|item| compare(Some(item), expected) == Some(std::cmp::Ordering::Equal)),
        _ => false,
    }
}

fn as_f64(value: &serde_json::Value) -> Option<f64> {
    match value {
        serde_json::Value::Number(number) => number.as_f64(),
        serde_json::Value::String(text) => text.trim().parse::<f64>().ok(),
        _ => None,
    }
}

fn text_of(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text.trim().to_owned(),
        other => other.to_string().trim().to_owned(),
    }
}

/// Go `renderAccessDeniedMessage`：模板变量替换（`{{provider}}` /
/// `{{field}}` / `{{op}}` / `{{required}}` / `{{current}}`）与
/// `{{current.path}}` / `{{required.path}}` 表达式；空模板用默认文案。
fn render_denied(
    template: &str,
    provider_name: &str,
    value: &serde_json::Value,
    failure: &PolicyFailure,
) -> String {
    const DEFAULT_MESSAGE: &str =
        "Access denied: your account does not meet this provider's access requirements.";
    let mut message = template.trim().to_owned();
    if message.is_empty() {
        return DEFAULT_MESSAGE.to_owned();
    }
    for (key, replacement) in [
        ("{{provider}}", provider_name.to_owned()),
        ("{{field}}", failure.field.clone()),
        ("{{op}}", failure.op.clone()),
        ("{{required}}", text_of(&failure.expected)),
        ("{{current}}", current_text(value, &failure.field)),
    ] {
        message = message.replace(key, &replacement);
    }
    message = replace_expression(&message, "current", |path| string_at(value, &path));
    message = replace_expression(&message, "required", |path| {
        (path == failure.field)
            .then(|| text_of(&failure.expected))
            .unwrap_or_default()
    });
    message.trim().to_owned()
}

/// 当前值文案；路径缺失为空串。
fn current_text(value: &serde_json::Value, path: &str) -> String {
    navigate(value, path)
        .map(|target| match target {
            serde_json::Value::String(text) => text.clone(),
            other => other.to_string(),
        })
        .unwrap_or_default()
}

/// Go 的 `\{\{(current|required)\.([^}]+)\}\}` 正则替换；路径 trim。
fn replace_expression(message: &str, namespace: &str, render: impl Fn(String) -> String) -> String {
    // 前缀是 `{{` + namespace + `.`；用 concat 避开字面量大括号转义。
    let prefix = String::from("{{") + namespace + ".";
    let mut out = String::with_capacity(message.len());
    let mut rest = message;
    while let Some(start) = rest.find(&prefix) {
        out.push_str(&rest[..start]);
        let tail = &rest[start + prefix.len()..];
        let Some(end) = tail.find("}}") else {
            out.push_str(&rest[start..]);
            rest = "";
            break;
        };
        let path = tail[..end].trim().to_owned();
        out.push_str(&render(path));
        rest = &tail[end + 2..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_encode_matches_go_url_query_escape() {
        let mut out = String::new();
        query_encode_into(&mut out, "a b");
        assert_eq!(out, "a+b");
        let mut out = String::new();
        query_encode_into(&mut out, "a/b?c=d");
        assert_eq!(out, "a%2Fb%3Fc%3Dd");
        let mut out = String::new();
        query_encode_into(&mut out, "中");
        assert_eq!(out, "%E4%B8%AD");
        let mut out = String::new();
        query_encode_into(&mut out, "a-_.~");
        assert_eq!(out, "a-_.~");
    }

    #[test]
    fn dotted_path_navigation() {
        let value: serde_json::Value =
            serde_json::from_str(r#"{"data":{"user":{"id":42,"tags":["a"]}}}"#).unwrap();
        assert_eq!(string_at(&value, "data.user.id"), "42");
        assert_eq!(string_at(&value, "data.user.tags.0"), "a");
        assert_eq!(string_at(&value, "data.missing"), "");
    }

    #[test]
    fn access_policy_and_or_branches() {
        let value: serde_json::Value =
            serde_json::from_str(r#"{"email":"a@b","level":3}"#).unwrap();
        // and：全过 → 放行。
        assert_eq!(
            evaluate_access_policy(
                &value,
                r#"{"logic":"and","conditions":[{"field":"email","op":"eq","value":"a@b"},{"field":"level","op":"gte","value":2}]}"#
            ),
            None
        );
        // and：一败 → 失败。
        assert!(evaluate_access_policy(
            &value,
            r#"{"logic":"and","conditions":[{"field":"email","op":"eq","value":"a@b"},{"field":"level","op":"lt","value":2}]}"#
        )
        .is_some());
        // or：任一过 → 放行。
        assert_eq!(
            evaluate_access_policy(
                &value,
                r#"{"logic":"or","conditions":[{"field":"email","op":"eq","value":"x"},{"field":"level","op":"gte","value":2}]}"#
            ),
            None
        );
        // exists / not_exists / in / not_in / contains。
        assert_eq!(
            evaluate_access_policy(
                &value,
                r#"{"conditions":[{"field":"level","op":"exists"}]}"#
            ),
            None
        );
        assert!(
            evaluate_access_policy(
                &value,
                r#"{"conditions":[{"field":"missing","op":"not_exists"}]}"#
            )
            .is_none()
        );
        assert_eq!(
            evaluate_access_policy(
                &value,
                r#"{"conditions":[{"field":"level","op":"in","value":[1,3]}]}"#
            ),
            None
        );
        assert!(
            evaluate_access_policy(
                &value,
                r#"{"conditions":[{"field":"level","op":"not_in","value":[3]}]}"#
            )
            .is_some()
        );
        assert!(
            evaluate_access_policy(
                &value,
                r#"{"conditions":[{"field":"email","op":"contains","value":"a@"}]}"#
            )
            .is_none()
        );
        // 嵌套组：or 组整体作为一个条件。
        assert_eq!(
            evaluate_access_policy(
                &value,
                r#"{"logic":"and","conditions":[{"field":"email","op":"eq","value":"a@b"}],"groups":[{"logic":"or","conditions":[{"field":"level","op":"lt","value":1},{"field":"level","op":"gt","value":1}]}]}"#
            ),
            None
        );
    }

    #[test]
    fn denied_message_rendering() {
        let value: serde_json::Value =
            serde_json::from_str(r#"{"email":"a@b","level":3}"#).unwrap();
        let failure = PolicyFailure {
            field: "level".to_owned(),
            op: "lt".to_owned(),
            expected: serde_json::json!(5),
        };
        let message = render_denied(
            "needs level {{required}} at {{provider}}, current {{current.level}}",
            "Corp SSO",
            &value,
            &failure,
        );
        assert_eq!(message, "needs level 5 at Corp SSO, current 3");
        // 空模板回默认文案。
        assert_eq!(
            render_denied("  ", "X", &value, &failure),
            "Access denied: your account does not meet this provider's access requirements."
        );
        // required.path 只在命中字段时替换。
        let message = render_denied(
            "{{required.level}}|{{required.email}}",
            "X",
            &value,
            &failure,
        );
        assert_eq!(message, "5|");
    }

    #[test]
    fn normalize_token_type_matches_go() {
        assert_eq!(normalize_token_type(""), "Bearer");
        assert_eq!(normalize_token_type("Bearer"), "Bearer");
        assert_eq!(normalize_token_type("bearer"), "Bearer");
        assert_eq!(normalize_token_type(" MAC "), "MAC");
    }

    #[test]
    fn token_response_form_fallback() {
        let response = OutboundResponse {
            status: 200,
            body: "access_token=abc&token_type=bearer".to_owned(),
        };
        let token = decode_token_response(&response, "Custom", true).expect("form fallback");
        assert_eq!(token.access_token, "abc");
        assert_eq!(token.token_type, "bearer");
        // JSON 响应正常解析。
        let response = OutboundResponse {
            status: 200,
            body: r#"{"access_token":"t","token_type":"Bearer"}"#.to_owned(),
        };
        let token = decode_token_response(&response, "X", false).expect("json");
        assert_eq!(token.access_token, "t");
        // 空 token → TokenFailed。
        let response = OutboundResponse {
            status: 200,
            body: "{}".to_owned(),
        };
        assert!(decode_token_response(&response, "X", false).is_err());
    }

    #[test]
    fn query_decode_round_trip() {
        assert_eq!(query_decode("a+b"), "a b");
        assert_eq!(query_decode("%E4%B8%AD"), "中");
        assert_eq!(query_decode("a%zz"), "a%zz");
    }
}
