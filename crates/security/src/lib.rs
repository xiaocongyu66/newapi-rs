//! 安全前置纯决策，不实现认证、撤销存储或完整权限策略。
//! 输入必须由服务装配层从权威身份快照转换，禁止直接采用请求中的角色。
//! 角色通过不代表细粒度权限通过；真正权限端口仍须接入策略快照求值。

use std::net::IpAddr;

use ipnet::IpNet;
use url::Url;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(i32)]
pub enum Role {
    User = 1,
    Admin = 10,
    Root = 100,
}

impl TryFrom<i32> for Role {
    type Error = Denial;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::User),
            10 => Ok(Self::Admin),
            100 => Ok(Self::Root),
            _ => Err(Denial::InvalidUser),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialKind {
    DashboardSession,
    PersonalAccessToken,
    RelayApiKey,
    RefreshToken,
    SecurityProof,
    LoginFlow,
}

/// 不携带密钥；有效性、版本及撤销由身份域在每次调用前核验。
pub struct AuthContext<'a> {
    pub user_id: i64,
    pub username: &'a str,
    pub role: Role,
    pub user_enabled: bool,
    pub credential: CredentialKind,
    pub session_id: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Denial {
    InvalidUser,
    UserDisabled,
    WrongCredential,
    InsufficientRole,
    BrowserSessionRequired,
    InvalidApiKey,
    ApiKeyDisabled,
    ApiKeyExpired,
    ApiKeyExhausted,
    InvalidIpPolicy,
    IpForbidden,
    OriginForbidden,
}

fn check_user(auth: &AuthContext<'_>) -> Result<(), Denial> {
    if !auth.user_enabled {
        return Err(Denial::UserDisabled);
    }
    if auth.user_id <= 0 || auth.username.trim().is_empty() {
        return Err(Denial::InvalidUser);
    }
    Ok(())
}

/// 仅管理面角色门槛，不是卡斯宾权限判定。
pub fn authorize_role(auth: &AuthContext<'_>, minimum: Role) -> Result<(), Denial> {
    check_user(auth)?;
    if !matches!(
        auth.credential,
        CredentialKind::DashboardSession | CredentialKind::PersonalAccessToken
    ) {
        return Err(Denial::WrongCredential);
    }
    if auth.credential == CredentialKind::DashboardSession
        && auth.session_id.is_none_or(|sid| sid.trim().is_empty())
    {
        return Err(Denial::BrowserSessionRequired);
    }
    if auth.role < minimum {
        return Err(Denial::InsufficientRole);
    }
    Ok(())
}

pub fn require_browser_session(auth: &AuthContext<'_>) -> Result<(), Denial> {
    authorize_role(auth, Role::User)?;
    if auth.credential != CredentialKind::DashboardSession {
        return Err(Denial::BrowserSessionRequired);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApiKeyMode {
    ReadOnly,
    Full,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApiKeyStatus {
    Enabled,
    Disabled,
    Expired,
    Exhausted,
}

/// 身份域须拒绝未知数据库状态，并在调用后负责必要的状态持久化。
pub struct ApiKeyGrant<'a> {
    pub owner_id: i64,
    pub deleted: bool,
    pub status: ApiKeyStatus,
    pub expires_at: i64,
    pub unlimited_quota: bool,
    pub remaining_quota: i64,
    /// 每项为一个地址或网段，数据库文本拆分由桥接层保持旧格式。
    pub allowed_ips: &'a [&'a str],
}

/// 只读路径不检查期限、额度和来源限制，但明确禁用仍必须拒绝。
/// 完整路径只返回判定，不扣费，也不修改数据库状态。
pub fn check_api_key(
    auth: &AuthContext<'_>,
    grant: &ApiKeyGrant<'_>,
    mode: ApiKeyMode,
    now: i64,
    client_ip: IpAddr,
) -> Result<(), Denial> {
    if auth.credential != CredentialKind::RelayApiKey {
        return Err(Denial::WrongCredential);
    }
    check_user(auth)?;
    if grant.deleted || grant.owner_id != auth.user_id {
        return Err(Denial::InvalidApiKey);
    }
    if grant.status == ApiKeyStatus::Disabled {
        return Err(Denial::ApiKeyDisabled);
    }
    if mode == ApiKeyMode::ReadOnly {
        return Ok(());
    }
    match grant.status {
        ApiKeyStatus::Expired => return Err(Denial::ApiKeyExpired),
        ApiKeyStatus::Exhausted => return Err(Denial::ApiKeyExhausted),
        ApiKeyStatus::Enabled => {}
        ApiKeyStatus::Disabled => return Err(Denial::ApiKeyDisabled),
    }
    if grant.expires_at != -1 && grant.expires_at < now {
        return Err(Denial::ApiKeyExpired);
    }
    if !grant.unlimited_quota && grant.remaining_quota <= 0 {
        return Err(Denial::ApiKeyExhausted);
    }
    check_ip_allowlist(grant.allowed_ips, client_ip)
}

/// 非空配置中任一非法项均拒绝，不能因前面的匹配项而跳过解析错误。
pub fn check_ip_allowlist(entries: &[&str], client_ip: IpAddr) -> Result<(), Denial> {
    let mut matched = entries.is_empty();
    for entry in entries {
        let entry = entry.trim();
        let contains = if let Ok(address) = entry.parse::<IpAddr>() {
            address == client_ip
        } else {
            entry
                .parse::<IpNet>()
                .map_err(|_| Denial::InvalidIpPolicy)?
                .contains(&client_ip)
        };
        matched |= contains;
    }
    if matched {
        Ok(())
    } else {
        Err(Denial::IpForbidden)
    }
}

/// 必须保留所有头值；非法字节由传输层拒绝，不能先取首值或丢弃。
/// 真实传输协议取自连接，不提供任何转发头入口。
pub struct OriginRequest<'a> {
    pub secure_cookie: bool,
    pub transport_tls: bool,
    pub host_headers: &'a [&'a str],
    pub origin_headers: &'a [&'a str],
    pub referer_headers: &'a [&'a str],
    pub trusted_urls: &'a [&'a str],
}

#[derive(Eq, PartialEq)]
struct Origin {
    scheme: String,
    host: String,
    port: u16,
}

fn parse_origin(value: &str, referer: bool) -> Result<Origin, Denial> {
    // 拒绝解析器可能自动修复的控制字符、反斜杠及多值拼接。
    if value.is_empty()
        || value.chars().any(|c| c.is_whitespace() || c.is_control())
        || value.contains(['\\', ',', '@'])
    {
        return Err(Denial::OriginForbidden);
    }
    let url = Url::parse(value).map_err(|_| Denial::OriginForbidden)?;
    if !matches!(url.scheme(), "http" | "https")
        || value
            .split_once("://")
            .is_none_or(|(_, authority)| authority.is_empty() || authority.starts_with('/'))
        || !url.username().is_empty()
        || url.password().is_some()
        || (!referer
            && (url.path() != "/" || url.query().is_some() || url.fragment().is_some()))
    {
        return Err(Denial::OriginForbidden);
    }
    Ok(Origin {
        scheme: url.scheme().to_owned(),
        host: url.host_str().ok_or(Denial::OriginForbidden)?.to_owned(),
        port: url.port_or_known_default().ok_or(Denial::OriginForbidden)?,
    })
}

pub fn check_session_origin(request: &OriginRequest<'_>) -> Result<(), Denial> {
    if !request.secure_cookie {
        return Ok(());
    }
    if request.origin_headers.len() > 1 || request.referer_headers.len() > 1 {
        return Err(Denial::OriginForbidden);
    }
    let candidate = match request.origin_headers {
        [origin] => parse_origin(origin, false)?,
        [] => match request.referer_headers {
            [referer] => parse_origin(referer, true)?,
            _ => return Err(Denial::OriginForbidden),
        },
        _ => return Err(Denial::OriginForbidden),
    };
    let [host] = request.host_headers else {
        return Err(Denial::OriginForbidden);
    };
    if host.is_empty() || host.contains(['/', '?', '#']) {
        return Err(Denial::OriginForbidden);
    }
    let scheme = if request.transport_tls { "https" } else { "http" };
    let local = parse_origin(&format!("{scheme}://{host}"), false)?;
    if candidate == local {
        return Ok(());
    }
    for trusted in request.trusted_urls {
        if candidate == parse_origin(trusted, true)? {
            return Ok(());
        }
    }
    Err(Denial::OriginForbidden)
}
