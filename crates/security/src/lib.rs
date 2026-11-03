//! 安全前置纯决策，不实现认证、撤销存储或完整权限策略。
//! 输入必须由服务装配层从权威身份快照转换，禁止直接采用请求中的角色。
//! 角色通过不代表细粒度权限通过；真正权限端口仍须接入策略快照求值。

pub mod rate_limit;

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
    port: String,
}

// 按旧实现校验转义，不能让浏览器式解析器先消除点段。
fn unescape(value: &str, host: bool) -> Result<String, Denial> {
    let mut bytes = Vec::with_capacity(value.len());
    let mut input = value.bytes();
    while let Some(byte) = input.next() {
        if byte == b'%' {
            let high = input.next().and_then(|b| char::from(b).to_digit(16));
            let low = input.next().and_then(|b| char::from(b).to_digit(16));
            let (Some(high), Some(low)) = (high, low) else {
                return Err(Denial::OriginForbidden);
            };
            let decoded = (high * 16 + low) as u8;
            if host && decoded < 128 && decoded != b'%' {
                return Err(Denial::OriginForbidden);
            }
            bytes.push(decoded);
        } else {
            bytes.push(byte);
        }
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn allowed_host_character(c: char) -> bool {
    !c.is_ascii() || c.is_ascii_alphanumeric() || "!$&'()*+,-.:;=[]_~<>\"%".contains(c)
}

fn parse_origin(value: &str, referer: bool) -> Result<Origin, Denial> {
    let value = value.trim();
    if value.is_empty() || value.bytes().any(|b| b < 32 || b == 127) {
        return Err(Denial::OriginForbidden);
    }
    let (scheme, remainder) = value.split_once("://").ok_or(Denial::OriginForbidden)?;
    let scheme = scheme.to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https") {
        return Err(Denial::OriginForbidden);
    }
    let boundary = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    let (authority, suffix) = remainder.split_at(boundary);
    // 仅检查权限段的用户信息；路径与查询中的邮箱和逗号不是用户信息。
    if authority.is_empty()
        || authority.contains('@')
        || !authority.chars().all(allowed_host_character)
    {
        return Err(Denial::OriginForbidden);
    }
    // 仍使用成熟解析器检查网址结构，但不采用其主机、端口或路径规范化结果。
    // 占位主机避免引入原实现没有的数字地址、国际域名和端口范围限制。
    Url::parse(&format!("{scheme}://origin.invalid{suffix}"))
        .map_err(|_| Denial::OriginForbidden)?;
    let (before_fragment, fragment) = suffix.split_once('#').unwrap_or((suffix, ""));
    let (path, query) = before_fragment
        .split_once('?')
        .unwrap_or((before_fragment, ""));
    let path = unescape(path, false)?;
    let fragment = unescape(fragment, false)?;
    if !referer && (!matches!(path.as_str(), "" | "/") || !query.is_empty() || !fragment.is_empty())
    {
        return Err(Denial::OriginForbidden);
    }
    let (hostname, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let end = bracketed.rfind(']').ok_or(Denial::OriginForbidden)?;
        let (hostname, rest) = bracketed.split_at(end);
        let rest = &rest[1..];
        let port = if rest.is_empty() {
            ""
        } else {
            rest.strip_prefix(':').ok_or(Denial::OriginForbidden)?
        };
        (hostname, port)
    } else {
        authority.rsplit_once(':').unwrap_or((authority, ""))
    };
    if !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Denial::OriginForbidden);
    }
    let hostname = if authority.starts_with('[') {
        if let Some((address, zone)) = hostname.split_once("%25") {
            let zone = unescape(zone, false)?;
            if !zone.chars().all(|c| c == ' ' || allowed_host_character(c)) {
                return Err(Denial::OriginForbidden);
            }
            format!("{}%{zone}", unescape(address, true)?)
        } else {
            unescape(hostname, true)?
        }
    } else {
        unescape(hostname, true)?
    };
    if referer {
        // 旧来源页分支先解析，再将已解码的权限段交给来源规范化函数。
        let host = if authority.starts_with('[') {
            format!("[{hostname}]")
        } else {
            hostname
        };
        return parse_origin(&format!("{scheme}://{host}:{port}"), false);
    }
    let hostname = hostname.to_lowercase();
    if hostname.is_empty() || hostname.contains('*') {
        return Err(Denial::OriginForbidden);
    }
    // 保留原始数字地址和端口文本，只折叠旧实现明确处理的默认端口。
    let port = if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
        ""
    } else {
        port
    };
    Ok(Origin {
        scheme,
        host: hostname,
        port: port.to_owned(),
    })
}

/// 规范化可信来源，仅接受纯 `scheme://host[:port]`（不含路径、查询或用户信息）。
/// 供配置校验使用；与运行期 Origin 校验共用同一套严格解析。
pub fn normalize_origin(raw: &str) -> Result<String, Denial> {
    let origin = parse_origin(raw, false)?;
    let host = if origin.host.contains(':') {
        format!("[{}]", origin.host)
    } else {
        origin.host
    };
    Ok(if origin.port.is_empty() {
        format!("{}://{host}", origin.scheme)
    } else {
        format!("{}://{host}:{}", origin.scheme, origin.port)
    })
}

pub fn check_session_origin(request: &OriginRequest<'_>) -> Result<(), Denial> {
    if !request.secure_cookie {
        return Ok(());
    }
    let candidate = match request.origin_headers {
        [origin] if !origin.contains(',') => parse_origin(origin, false)?,
        [] => match request.referer_headers {
            [referer] => parse_origin(referer, true)?,
            _ => return Err(Denial::OriginForbidden),
        },
        _ => return Err(Denial::OriginForbidden),
    };
    let [host] = request.host_headers else {
        return Err(Denial::OriginForbidden);
    };
    let scheme = if request.transport_tls {
        "https"
    } else {
        "http"
    };
    if parse_origin(&format!("{scheme}://{host}"), false).is_ok_and(|local| candidate == local) {
        return Ok(());
    }
    for trusted in request.trusted_urls {
        if candidate == parse_origin(trusted, false)? {
            return Ok(());
        }
    }
    Err(Denial::OriginForbidden)
}
