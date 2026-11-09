//! RP（rp_id / origin）推导与 WebAuthn 实例构建：
//! Go `passkey_webauthn.go`（`BuildWebAuthn`）的移植。
//!
//! 契约表即 Go `passkey_webauthn_test.go`：转发头（X-Forwarded-Proto/Host、
//! Forwarded）完全不参与推导——IsTLS 只反映传输层 TLS，Host 只取实际 Host
//! 头；配置的 Origins（逗号分隔）优先，http origin 在未允许不安全时直接
//! 拒绝；自动推导保留端口于 origin、剥离端口于 rp_id；localhost/127.0.0.1
//! 豁免 HTTPS 要求；空 Host 回退 ServerAddress 的 Host（scheme 仍取传输层）。

use std::time::Duration;

use webauthn_rs::prelude::{Url, Webauthn, WebauthnBuilder};

use crate::passkey::ceremony::Ceremony;
use crate::passkey::settings::PasskeySettings;

/// Go 的注册/登录超时：2 分钟（`TimeoutsConfig`，Enforce=true）。
pub const CEREMONY_TIMEOUT: Duration = Duration::from_secs(120);

/// 请求的传输层事实：Host 头与 TLS 状态。转发头不参与（Go 同样如此）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportFacts {
    pub host: String,
    pub is_tls: bool,
}

/// RP 推导的固定错误分类；`message()` 复现 Go 的字面报错（含替换值）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RpError {
    InsecureOrigin(String),
    HttpsOnly(String),
    OriginUndetermined {
        host: String,
        server_address: String,
    },
    NoOrigin,
    /// Go 的 `BuildWebAuthn` 在 rp_id 不是 origin 的有效域名时报底层库错误
    /// （如裸 IPv6）；Rust 固定分类文案替代库文本。
    Configuration,
    InvalidOrigin(String),
}

impl RpError {
    /// 复现 Go handler 经 `CtxApiError` 返回的 `err.Error()` 文案。
    pub fn message(&self) -> String {
        match self {
            Self::InsecureOrigin(origin) => {
                format!("Passkey 不允许使用不安全的 Origin: {origin}")
            }
            Self::HttpsOnly(accessed) => format!(
                "Passkey 仅支持 HTTPS，当前访问: {accessed}，请在 Passkey 设置中允许不安全 Origin 或配置 HTTPS"
            ),
            Self::OriginUndetermined {
                host,
                server_address,
            } => format!(
                "无法确定 Passkey 的 Origin，请在系统设置或 Passkey 设置中指定。当前 Host: '{host}', ServerAddress: '{server_address}'"
            ),
            Self::NoOrigin => "Passkey 未配置 Origin，无法推导 RPID".to_owned(),
            Self::Configuration => "Passkey 配置无效，请检查 RP ID 与 Origin 设置".to_owned(),
            Self::InvalidOrigin(origin) => format!("无法解析 Passkey 的 Origin: {origin}"),
        }
    }
}

impl std::fmt::Display for RpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for RpError {}

/// Go `resolveOrigins`：配置 Origins 优先，过滤后为空则走自动推导。
pub fn resolve_origins(
    host: &str,
    is_tls: bool,
    settings: &PasskeySettings,
    server_address: &str,
) -> Result<Vec<String>, RpError> {
    let origins_str = settings.origins.trim();
    if !origins_str.is_empty() {
        let mut origins = Vec::new();
        for origin in origins_str.split(',') {
            let trimmed = origin.trim();
            if trimmed.is_empty() {
                continue;
            }
            if !settings.allow_insecure_origin
                && trimmed.to_ascii_lowercase().starts_with("http://")
            {
                return Err(RpError::InsecureOrigin(trimmed.to_owned()));
            }
            origins.push(trimmed.to_owned());
        }
        if !origins.is_empty() {
            return Ok(origins);
        }
    }
    auto_detect(host, is_tls, settings, server_address)
}

/// Go `resolveOrigins` 的 autoDetect 分支。
fn auto_detect(
    host: &str,
    is_tls: bool,
    settings: &PasskeySettings,
    server_address: &str,
) -> Result<Vec<String>, RpError> {
    let scheme = if is_tls { "https" } else { "http" };
    if scheme == "http"
        && !settings.allow_insecure_origin
        && host != "localhost"
        && host != "127.0.0.1"
        && !host.starts_with("127.0.0.1:")
        && !host.starts_with("localhost:")
    {
        return Err(RpError::HttpsOnly(format!("{scheme}://{host}")));
    }
    let mut host = host.to_owned();
    if host.is_empty() && !server_address.trim().is_empty() {
        if let Some(parsed) = Url::parse(server_address.trim()).ok() {
            // Go 取 `parsed.Host`（含端口）。
            if let Some(parsed_host) = parsed.host_str() {
                host = match parsed.port() {
                    Some(port) => format!("{parsed_host}:{port}"),
                    None => parsed_host.to_owned(),
                };
            }
        }
    }
    if host.is_empty() {
        return Err(RpError::OriginUndetermined {
            host,
            server_address: server_address.to_owned(),
        });
    }
    Ok(vec![format!("{scheme}://{host}")])
}

/// Go `hostWithoutPort`：`net.SplitHostPort` 的成功分支剥端口，失败（裸
/// IPv6 等）保留原串。
fn host_without_port(host: &str) -> String {
    let host = host.trim();
    if host.contains(':') {
        if let Some(rest) = host.strip_prefix('[')
            && let Some(end) = rest.find("]:")
        {
            return rest[..end].to_owned();
        }
        // 无括号的 host:port（单冒号）剥端口；裸 IPv6（多冒号）按 Go 保留原串。
        if host.matches(':').count() == 1 {
            return host.split(':').next().unwrap_or(host).to_owned();
        }
    }
    host.to_owned()
}

/// Go `resolveRPID`：配置优先，否则从首个 origin 的 Host（剥端口）推导。
pub fn resolve_rp_id(settings: &PasskeySettings, origins: &[String]) -> Result<String, RpError> {
    let configured = settings.rp_id.trim();
    if !configured.is_empty() {
        return Ok(host_without_port(configured));
    }
    if origins.is_empty() {
        return Err(RpError::NoOrigin);
    }
    let parsed = Url::parse(&origins[0]).map_err(|_| RpError::InvalidOrigin(origins[0].clone()))?;
    let host_with_port = match parsed.port() {
        Some(port) => format!("{}:{port}", parsed.host_str().unwrap_or("")),
        None => parsed.host_str().unwrap_or("").to_owned(),
    };
    Ok(host_without_port(&host_with_port))
}

/// Go `BuildWebAuthn`：settings + 传输事实 → 可用 origin/rp_id → Webauthn。
pub fn build_ceremony(
    settings: &PasskeySettings,
    facts: &TransportFacts,
    server_address: &str,
) -> Result<Ceremony, RpError> {
    let origins = resolve_origins(&facts.host, facts.is_tls, settings, server_address)?;
    let rp_id = resolve_rp_id(settings, &origins)?;
    let display_name = settings.effective_rp_display_name().to_owned();
    let primary =
        Url::parse(&origins[0]).map_err(|_| RpError::InvalidOrigin(origins[0].clone()))?;
    let mut builder = WebauthnBuilder::new(&rp_id, &primary).map_err(|_| RpError::Configuration)?;
    for extra in &origins[1..] {
        let url = Url::parse(extra).map_err(|_| RpError::InvalidOrigin(extra.clone()))?;
        builder = builder.append_allowed_origin(&url);
    }
    builder = builder.rp_name(&display_name).timeout(CEREMONY_TIMEOUT);
    let webauthn = builder.build().map_err(|_| RpError::Configuration)?;
    Ok(Ceremony::new(webauthn))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::passkey::settings::PasskeySettings;

    /// Go `pinPasskeySettings` 等价：直接固定 settings，不经
    /// `GetPasskeySettings` 的 ServerAddress 派生（推导表断言的是输入本身）。
    fn settings(enabled: bool) -> PasskeySettings {
        PasskeySettings {
            enabled,
            ..PasskeySettings::default()
        }
    }

    fn facts(host: &str, is_tls: bool) -> TransportFacts {
        TransportFacts {
            host: host.to_owned(),
            is_tls,
        }
    }

    #[test]
    fn configured_origins_win_and_derive_rp_from_the_first() {
        let mut settings = settings(true);
        settings.origins = "https://a.example.com:9443, https://b.example.com".into();
        let origins = resolve_origins("panel.example.com", true, &settings, "").unwrap();
        assert_eq!(
            origins,
            ["https://a.example.com:9443", "https://b.example.com"]
        );
        assert_eq!(resolve_rp_id(&settings, &origins).unwrap(), "a.example.com");
    }

    #[test]
    fn configured_rp_id_drops_the_port() {
        let mut settings = settings(true);
        settings.rp_id = "example.com:8443".into();
        let origins = resolve_origins("panel.example.com", true, &settings, "").unwrap();
        assert_eq!(resolve_rp_id(&settings, &origins).unwrap(), "example.com");
    }

    #[test]
    fn http_origin_is_refused_without_the_insecure_flag() {
        let mut settings = settings(true);
        settings.origins = "http://a.example.com".into();
        let error = resolve_origins("panel.example.com", true, &settings, "").unwrap_err();
        assert_eq!(
            error.message(),
            "Passkey 不允许使用不安全的 Origin: http://a.example.com"
        );
    }

    #[test]
    fn configured_origins_collapsing_to_empty_fall_back_to_the_request() {
        let mut settings = settings(true);
        settings.origins = " , ".into();
        let origins = resolve_origins("panel.example.com", true, &settings, "").unwrap();
        assert_eq!(origins, ["https://panel.example.com"]);
        assert_eq!(
            resolve_rp_id(&settings, &origins).unwrap(),
            "panel.example.com"
        );
    }

    #[test]
    fn auto_detect_keeps_the_port_in_origin_and_drops_it_from_rp_id() {
        let origins = resolve_origins("example.com:8443", true, &settings(true), "").unwrap();
        assert_eq!(origins, ["https://example.com:8443"]);
        assert_eq!(
            resolve_rp_id(&settings(true), &origins).unwrap(),
            "example.com"
        );
    }

    #[test]
    fn tls_on_an_origin_form_target_still_resolves_as_https() {
        let origins = resolve_origins("example.com", true, &settings(true), "").unwrap();
        assert_eq!(origins, ["https://example.com"]);
    }

    #[test]
    fn plain_http_is_refused_unless_insecure_or_loopback() {
        let error = resolve_origins("example.com", false, &settings(true), "").unwrap_err();
        assert_eq!(
            error.message(),
            "Passkey 仅支持 HTTPS，当前访问: http://example.com，请在 Passkey 设置中允许不安全 Origin 或配置 HTTPS"
        );
        // loopback 豁免。
        let origins = resolve_origins("127.0.0.1:3000", false, &settings(true), "").unwrap();
        assert_eq!(origins, ["http://127.0.0.1:3000"]);
        let origins = resolve_origins("localhost:3000", false, &settings(true), "").unwrap();
        assert_eq!(origins, ["http://localhost:3000"]);
        // 允许不安全 origin 时放行。
        let mut insecure = settings(true);
        insecure.allow_insecure_origin = true;
        let origins = resolve_origins("example.com", false, &insecure, "").unwrap();
        assert_eq!(origins, ["http://example.com"]);
    }

    #[test]
    fn empty_host_falls_back_to_server_address_but_never_the_scheme() {
        // scheme 来自传输层（http）；空 Host 在 loopback 豁免检查里即失败，
        // 与 ServerAddress 是否 https 无关（Go 同序）。
        let error = resolve_origins("", false, &settings(true), "https://fallback.example.com")
            .unwrap_err();
        assert!(matches!(error, RpError::HttpsOnly(_)));
        // 允许不安全后走到 ServerAddress 回退：Host 来自回退地址，scheme 仍 http。
        let mut insecure = settings(true);
        insecure.allow_insecure_origin = true;
        let origins =
            resolve_origins("", false, &insecure, "https://fallback.example.com").unwrap();
        assert_eq!(origins, ["http://fallback.example.com"]);
        let origins =
            resolve_origins("", false, &insecure, "http://fallback.example.com:7000").unwrap();
        assert_eq!(origins, ["http://fallback.example.com:7000"]);
        // 两者皆空时给出 Go 的诊断文案。
        let error = resolve_origins("", false, &insecure, "").unwrap_err();
        assert!(matches!(error, RpError::OriginUndetermined { .. }));
        assert_eq!(
            error.message(),
            "无法确定 Passkey 的 Origin，请在系统设置或 Passkey 设置中指定。当前 Host: '', ServerAddress: ''"
        );
    }

    #[test]
    fn build_rejects_a_bare_ipv6_rp_id_like_go() {
        let error =
            build_ceremony(&settings(true), &facts("[2001:db8::1]:8443", true), "").unwrap_err();
        assert!(matches!(error, RpError::Configuration), "{error:?}");
    }

    #[test]
    fn build_accepts_bracketed_ipv6_with_a_configured_rp_id() {
        let mut settings = settings(true);
        settings.rp_id = "example.com".into();
        build_ceremony(&settings, &facts("[2001:db8::1]:8443", true), "").unwrap();
    }

    #[test]
    fn localhost_auto_detect_builds_a_usable_ceremony() {
        build_ceremony(&settings(true), &facts("localhost:3000", false), "").unwrap();
    }
}
