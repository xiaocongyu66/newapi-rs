//! Startup configuration. Errors contain variable names, never their values.
use std::{env, fmt, time::Duration};

// Deliberately no Debug/Serialize: the DSN and session secret may be sensitive.
#[derive(Clone)]
pub struct Config {
    dsn: String,
    session_secret: Option<String>,
    pub port: u16,
    pub sync_frequency: Duration,
    /// 浏览器刷新 Cookie 的安全设置；来源列表已规范化。
    pub session_cookie: SessionCookieSettings,
    /// 可选 Redis；设置后连接失败必须终止启动，不得静默关闭跨实例撤销。
    redis_url: Option<String>,
    /// 登录等关键路径限流；对应 Go `CriticalRateLimit` 的三个环境变量。
    pub critical_rate_limit_enabled: bool,
    pub critical_rate_limit_requests: i64,
    pub critical_rate_limit_duration_seconds: i64,
    /// 令牌搜索限流；对应 Go `SearchRateLimit` 的三个环境变量。
    pub search_rate_limit_enabled: bool,
    pub search_rate_limit_requests: i64,
    pub search_rate_limit_duration_seconds: i64,
    /// 全局 API 限流；对应 Go `GlobalAPIRateLimit` 的三个环境变量。
    pub global_api_rate_limit_enabled: bool,
    pub global_api_rate_limit_requests: i64,
    pub global_api_rate_limit_duration_seconds: i64,
    /// 全局 Web 限流；对应 Go `GlobalWebRateLimit` 的三个环境变量。
    pub global_web_rate_limit_enabled: bool,
    pub global_web_rate_limit_requests: i64,
    pub global_web_rate_limit_duration_seconds: i64,
    /// 原样保留 `TRUSTED_PROXIES`；解析（默认 CIDR 与 `none`）在
    /// `newapi_security::client_ip`，解析失败必须终止启动。
    pub trusted_proxies: Option<String>,
    /// `ANONYMOUS_REQUEST_BODY_LIMIT_KB`；负数回退默认 512KB。
    pub anonymous_request_body_limit_kb: i64,
    /// Go `common.CryptoSecret`：`CRYPTO_SECRET` 未设置或为空时回退 `SESSION_SECRET`。
    crypto_secret: Option<String>,
}

/// `secure` 对应原 `SESSION_COOKIE_SECURE`；启用时来源列表非空。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionCookieSettings {
    pub secure: bool,
    pub trusted_origins: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigError {
    variable: &'static str,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid {} configuration", self.variable)
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|name| match env::var(name) {
            Ok(value) => Ok(Some(value)),
            Err(env::VarError::NotPresent) => Ok(None),
            Err(env::VarError::NotUnicode(_)) => Err(ConfigError { variable: name }),
        })
    }

    /// Injectable environment lookup avoids process-global mutation in tests.
    pub fn from_lookup(
        mut lookup: impl FnMut(&'static str) -> Result<Option<String>, ConfigError>,
    ) -> Result<Self, ConfigError> {
        let dsn = match lookup("SQL_DSN")?.filter(|value| !value.is_empty()) {
            Some(dsn) => {
                let valid_scheme = ["sqlite:", "postgres:", "postgresql:"]
                    .iter()
                    .any(|prefix| dsn.starts_with(prefix) && dsn.len() > prefix.len());
                if !valid_scheme || dsn.chars().any(char::is_control) {
                    return Err(ConfigError {
                        variable: "SQL_DSN",
                    });
                }
                dsn
            }
            None => {
                let path = lookup("SQLITE_PATH")?.unwrap_or_else(|| "newapi.db".into());
                // Reject URI metacharacters rather than interpreting a path as DSN options.
                if path.trim().is_empty()
                    || path.chars().any(char::is_control)
                    || path.contains(['?', '#'])
                    || path == ":memory:"
                {
                    return Err(ConfigError {
                        variable: "SQLITE_PATH",
                    });
                }
                format!("sqlite:{path}")
            }
        };
        let port = positive_integer(lookup("PORT")?, "PORT", 3001, u16::MAX as u64)? as u16;
        // A bounded interval also avoids Instant overflow in the reload scheduler.
        let seconds = positive_integer(
            lookup("SYNC_FREQUENCY")?,
            "SYNC_FREQUENCY",
            60,
            u32::MAX as u64,
        )?;
        // Go 将空值视为未设置；拒绝其已知的不安全默认串，避免静默沿用示例密钥。
        let session_secret = match lookup("SESSION_SECRET")? {
            Some(value) if value.is_empty() => None,
            Some(value) => {
                if value == "random_string" || value.chars().any(char::is_control) {
                    return Err(ConfigError {
                        variable: "SESSION_SECRET",
                    });
                }
                Some(value)
            }
            None => None,
        };
        // Go `init.go`：`CRYPTO_SECRET` 非空则用之，否则回退 `SESSION_SECRET`
        // （两者皆未设置时 Go 留下每进程随机 UUID，由服务入口生成随机密钥替代）。
        let crypto_secret = match lookup("CRYPTO_SECRET")? {
            Some(value) if !value.is_empty() => Some(value),
            _ => session_secret.clone(),
        };
        let session_cookie = session_cookie_settings(
            lookup("SESSION_COOKIE_SECURE")?,
            lookup("SESSION_COOKIE_TRUSTED_URL")?,
        )?;
        let redis_url = match lookup("REDIS_CONN_STRING")?.filter(|value| !value.is_empty()) {
            Some(url) => {
                let valid = ["redis://", "rediss://"]
                    .iter()
                    .any(|prefix| url.starts_with(prefix) && url.len() > prefix.len());
                if !valid || url.chars().any(char::is_control) {
                    return Err(ConfigError {
                        variable: "REDIS_CONN_STRING",
                    });
                }
                Some(url)
            }
            None => None,
        };
        // Go 的 GetEnvOrDefault*：enable 解析失败保留默认；数值沿用本仓库
        // positive_integer 的严格校验（比 Go 的 Atoi 更严，非法值直接拒绝启动）。
        let critical_rate_limit_enabled =
            bool_with_default(lookup("CRITICAL_RATE_LIMIT_ENABLE")?, true);
        let critical_rate_limit_requests = positive_integer(
            lookup("CRITICAL_RATE_LIMIT")?,
            "CRITICAL_RATE_LIMIT",
            20,
            i64::MAX as u64,
        )? as i64;
        let critical_rate_limit_duration_seconds = positive_integer(
            lookup("CRITICAL_RATE_LIMIT_DURATION")?,
            "CRITICAL_RATE_LIMIT_DURATION",
            1_200,
            i64::MAX as u64,
        )? as i64;
        // Go `initRateLimitVariables` 的 SearchRateLimit*：默认 10/60。
        let search_rate_limit_enabled =
            bool_with_default(lookup("SEARCH_RATE_LIMIT_ENABLE")?, true);
        let search_rate_limit_requests = positive_integer(
            lookup("SEARCH_RATE_LIMIT")?,
            "SEARCH_RATE_LIMIT",
            10,
            i64::MAX as u64,
        )? as i64;
        let search_rate_limit_duration_seconds = positive_integer(
            lookup("SEARCH_RATE_LIMIT_DURATION")?,
            "SEARCH_RATE_LIMIT_DURATION",
            60,
            i64::MAX as u64,
        )? as i64;
        // Go `initRateLimitVariables` 的 GlobalApiRateLimit*：默认 360/180。
        let global_api_rate_limit_enabled =
            bool_with_default(lookup("GLOBAL_API_RATE_LIMIT_ENABLE")?, true);
        let global_api_rate_limit_requests = positive_integer(
            lookup("GLOBAL_API_RATE_LIMIT")?,
            "GLOBAL_API_RATE_LIMIT",
            360,
            i64::MAX as u64,
        )? as i64;
        let global_api_rate_limit_duration_seconds = positive_integer(
            lookup("GLOBAL_API_RATE_LIMIT_DURATION")?,
            "GLOBAL_API_RATE_LIMIT_DURATION",
            180,
            i64::MAX as u64,
        )? as i64;
        // Go `initRateLimitVariables` 的 GlobalWebRateLimit*：默认 120/180。
        let global_web_rate_limit_enabled =
            bool_with_default(lookup("GLOBAL_WEB_RATE_LIMIT_ENABLE")?, true);
        let global_web_rate_limit_requests = positive_integer(
            lookup("GLOBAL_WEB_RATE_LIMIT")?,
            "GLOBAL_WEB_RATE_LIMIT",
            120,
            i64::MAX as u64,
        )? as i64;
        let global_web_rate_limit_duration_seconds = positive_integer(
            lookup("GLOBAL_WEB_RATE_LIMIT_DURATION")?,
            "GLOBAL_WEB_RATE_LIMIT_DURATION",
            180,
            i64::MAX as u64,
        )? as i64;
        // Go `GetEnvOrDefault`：未设置或空值用默认，非法数值同样回退默认并告警。
        let anonymous_request_body_limit_kb =
            integer_with_default(lookup("ANONYMOUS_REQUEST_BODY_LIMIT_KB")?, 512);
        Ok(Self {
            dsn,
            session_secret,
            port,
            sync_frequency: Duration::from_secs(seconds),
            session_cookie,
            redis_url,
            critical_rate_limit_enabled,
            critical_rate_limit_requests,
            critical_rate_limit_duration_seconds,
            search_rate_limit_enabled,
            search_rate_limit_requests,
            search_rate_limit_duration_seconds,
            global_api_rate_limit_enabled,
            global_api_rate_limit_requests,
            global_api_rate_limit_duration_seconds,
            global_web_rate_limit_enabled,
            global_web_rate_limit_requests,
            global_web_rate_limit_duration_seconds,
            trusted_proxies: lookup("TRUSTED_PROXIES")?,
            anonymous_request_body_limit_kb,
            crypto_secret,
        })
    }

    pub fn dsn(&self) -> &str {
        &self.dsn
    }

    /// 未配置时返回 None；调用方负责生成进程级随机密钥并记录警告。
    pub fn session_secret(&self) -> Option<&str> {
        self.session_secret.as_deref()
    }

    /// Go `common.CryptoSecret`：两者都未设置时返回 None，由调用方生成进程级
    /// 随机密钥（等价 Go 的随机 UUID 默认值）。
    pub fn crypto_secret(&self) -> Option<&str> {
        self.crypto_secret.as_deref()
    }

    pub fn redis_url(&self) -> Option<&str> {
        self.redis_url.as_deref()
    }
}

/// 对齐原实现的组合约束：Secure=false 时不允许可信来源；
/// Secure=true 时必须提供至少一个可规范化为 https 的来源。
fn session_cookie_settings(
    secure: Option<String>,
    trusted: Option<String>,
) -> Result<SessionCookieSettings, ConfigError> {
    let secure = secure.unwrap_or_default();
    let trusted = trusted.unwrap_or_default();
    let secure = secure.trim();
    let trusted = trusted.trim();
    if secure.is_empty() || secure.eq_ignore_ascii_case("false") {
        if !trusted.is_empty() {
            return Err(ConfigError {
                variable: "SESSION_COOKIE_TRUSTED_URL",
            });
        }
        return Ok(SessionCookieSettings {
            secure: false,
            trusted_origins: Vec::new(),
        });
    }
    if !secure.eq_ignore_ascii_case("true") {
        return Err(ConfigError {
            variable: "SESSION_COOKIE_SECURE",
        });
    }
    if trusted.is_empty() {
        return Err(ConfigError {
            variable: "SESSION_COOKIE_TRUSTED_URL",
        });
    }
    let mut trusted_origins = Vec::new();
    for entry in trusted.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            return Err(ConfigError {
                variable: "SESSION_COOKIE_TRUSTED_URL",
            });
        }
        let origin = newapi_security::normalize_origin(entry).map_err(|_| ConfigError {
            variable: "SESSION_COOKIE_TRUSTED_URL",
        })?;
        if !origin.starts_with("https://") {
            return Err(ConfigError {
                variable: "SESSION_COOKIE_TRUSTED_URL",
            });
        }
        trusted_origins.push(origin);
    }
    Ok(SessionCookieSettings {
        secure: true,
        trusted_origins,
    })
}

/// 对齐 Go `GetEnvOrDefaultBool`：空值视为未设置，非法值按 `strconv.ParseBool`
/// 的失败语义保留默认（Go 打印错误后回退），不阻断启动。
fn bool_with_default(value: Option<String>, default: bool) -> bool {
    // Exact token set of Go's strconv.ParseBool (case-sensitive).
    const TRUE_TOKENS: [&str; 6] = ["1", "t", "T", "TRUE", "true", "True"];
    const FALSE_TOKENS: [&str; 6] = ["0", "f", "F", "FALSE", "false", "False"];
    match value.as_deref() {
        Some("") | None => default,
        Some(raw) if TRUE_TOKENS.contains(&raw) => true,
        Some(raw) if FALSE_TOKENS.contains(&raw) => false,
        Some(_) => default,
    }
}

/// 对齐 Go `GetEnvOrDefault`（int）：空值/非法值都回退默认，负数原样保留
/// （业务层再按各自规则处理，例如请求体上限的负数回退）。
fn integer_with_default(value: Option<String>, default: i64) -> i64 {
    match value {
        Some(raw) if !raw.is_empty() => raw.parse().unwrap_or(default),
        _ => default,
    }
}

fn positive_integer(
    value: Option<String>,
    variable: &'static str,
    default: u64,
    maximum: u64,
) -> Result<u64, ConfigError> {
    let Some(value) = value else {
        return Ok(default);
    };
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ConfigError { variable });
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|number| (1..=maximum).contains(number))
        .ok_or(ConfigError { variable })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(values: &[(&str, &str)]) -> Result<Config, ConfigError> {
        Config::from_lookup(|name| {
            Ok(values
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned()))
        })
    }

    #[test]
    fn defaults_and_sqlite_path() {
        let default = config(&[]).unwrap();
        assert_eq!(default.port, 3001);
        assert_eq!(default.sync_frequency, Duration::from_secs(60));
        assert_eq!(default.dsn(), "sqlite:newapi.db");
        let configured = config(&[("SQL_DSN", ""), ("SQLITE_PATH", "/tmp/旧库.db")]).unwrap();
        assert_eq!(configured.dsn(), "sqlite:/tmp/旧库.db");
    }

    #[test]
    fn explicit_dsn_wins_without_reading_unused_path() {
        for dsn in [
            "sqlite:/tmp/old.db",
            "postgres://user:secret@localhost/test",
            "postgresql://user:secret@localhost/test",
        ] {
            let value = config(&[("SQL_DSN", dsn), ("SQLITE_PATH", "?")]).unwrap();
            assert_eq!(value.dsn(), dsn);
        }
    }

    #[test]
    fn rejects_unsupported_and_malformed_configuration_without_echoing_values() {
        for (name, value) in [
            ("SQL_DSN", "mysql://user:secret@localhost/test"),
            ("SQL_DSN", "secret"),
            ("SQL_DSN", "postgres:"),
            ("SQL_DSN", "sqlite:secret\n"),
            ("PORT", "0"),
            ("PORT", "65536"),
            ("PORT", "-1"),
            ("PORT", " 3001"),
            ("PORT", "+3001"),
            ("PORT", ""),
            ("SYNC_FREQUENCY", "0"),
            ("SYNC_FREQUENCY", "-1"),
            ("SYNC_FREQUENCY", "1.5"),
            ("SYNC_FREQUENCY", "18446744073709551616"),
            ("SQLITE_PATH", ""),
            ("SQLITE_PATH", "old.db?mode=rwc"),
            ("SQLITE_PATH", ":memory:"),
            ("REDIS_CONN_STRING", "redis:"),
            ("REDIS_CONN_STRING", "http://localhost:6379"),
            ("REDIS_CONN_STRING", "redis://localhost\n:6379"),
        ] {
            let error = config(&[(name, value)]).err().unwrap();
            assert_eq!(error.to_string(), format!("invalid {name} configuration"));
            assert!(!format!("{error:?}").contains("secret"));
        }
    }

    #[test]
    fn accepts_numeric_bounds() {
        let value = config(&[("PORT", "65535"), ("SYNC_FREQUENCY", "1")]).unwrap();
        assert_eq!(value.port, 65535);
        assert_eq!(value.sync_frequency, Duration::from_secs(1));
    }

    #[test]
    fn session_cookie_defaults_to_insecure_without_trusted_origins() {
        let value = config(&[]).unwrap();
        assert_eq!(value.session_secret(), None);
        assert_eq!(
            value.session_cookie,
            SessionCookieSettings {
                secure: false,
                trusted_origins: Vec::new()
            }
        );
    }

    #[test]
    fn secure_session_cookie_requires_and_normalizes_https_origins() {
        let value = config(&[
            ("SESSION_COOKIE_SECURE", "true"),
            (
                "SESSION_COOKIE_TRUSTED_URL",
                " https://Example.COM:443 , https://console.example.org ",
            ),
        ])
        .unwrap();
        assert_eq!(
            value.session_cookie,
            SessionCookieSettings {
                secure: true,
                trusted_origins: vec![
                    "https://example.com".into(),
                    "https://console.example.org".into(),
                ],
            }
        );
    }

    #[test]
    fn rejects_inconsistent_or_insecure_session_cookie_settings() {
        for (secure, trusted) in [
            ("true", ""),
            ("true", "http://example.com"),
            ("true", "https://example.com, "),
            ("true", "https://*.example.com"),
            ("false", "https://example.com"),
            ("yes", "https://example.com"),
        ] {
            assert!(
                config(&[
                    ("SESSION_COOKIE_SECURE", secure),
                    ("SESSION_COOKIE_TRUSTED_URL", trusted),
                ])
                .is_err(),
                "accepted secure={secure} trusted={trusted}"
            );
        }
    }

    #[test]
    fn rejects_the_known_insecure_default_session_secret() {
        let error = config(&[("SESSION_SECRET", "random_string")])
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "invalid SESSION_SECRET configuration");
        assert_eq!(
            config(&[("SESSION_SECRET", "a-random-secret-value")])
                .unwrap()
                .session_secret(),
            Some("a-random-secret-value")
        );
    }

    #[test]
    fn crypto_secret_falls_back_to_session_secret_like_go() {
        // Go `init.go`：CRYPTO_SECRET 非空优先；空值或未设置回退 SESSION_SECRET。
        assert_eq!(
            config(&[
                ("SESSION_SECRET", "a-random-secret-value"),
                ("CRYPTO_SECRET", "dedicated")
            ])
            .unwrap()
            .crypto_secret(),
            Some("dedicated")
        );
        assert_eq!(
            config(&[
                ("SESSION_SECRET", "a-random-secret-value"),
                ("CRYPTO_SECRET", "")
            ])
            .unwrap()
            .crypto_secret(),
            Some("a-random-secret-value")
        );
        assert_eq!(
            config(&[("SESSION_SECRET", "a-random-secret-value")])
                .unwrap()
                .crypto_secret(),
            Some("a-random-secret-value")
        );
        assert_eq!(config(&[]).unwrap().crypto_secret(), None);
    }

    #[test]
    fn critical_rate_limit_defaults_match_go() {
        let value = config(&[]).unwrap();
        assert!(value.critical_rate_limit_enabled);
        assert_eq!(value.critical_rate_limit_requests, 20);
        assert_eq!(value.critical_rate_limit_duration_seconds, 1_200);
    }

    #[test]
    fn critical_rate_limit_accepts_explicit_values() {
        let value = config(&[
            ("CRITICAL_RATE_LIMIT_ENABLE", "false"),
            ("CRITICAL_RATE_LIMIT", "5"),
            ("CRITICAL_RATE_LIMIT_DURATION", "60"),
        ])
        .unwrap();
        assert!(!value.critical_rate_limit_enabled);
        assert_eq!(value.critical_rate_limit_requests, 5);
        assert_eq!(value.critical_rate_limit_duration_seconds, 60);
        // Go's strconv.ParseBool accepts these exact tokens.
        for (token, expected) in [
            ("true", true),
            ("TRUE", true),
            ("True", true),
            ("t", true),
            ("T", true),
            ("1", true),
            ("false", false),
            ("FALSE", false),
            ("False", false),
            ("f", false),
            ("F", false),
            ("0", false),
        ] {
            assert_eq!(
                config(&[("CRITICAL_RATE_LIMIT_ENABLE", token)])
                    .unwrap()
                    .critical_rate_limit_enabled,
                expected,
                "token {token}"
            );
        }
    }

    #[test]
    fn critical_rate_limit_falls_back_or_rejects_invalid_values() {
        // Go's GetEnvOrDefaultBool keeps the default on unparseable values.
        for token in ["yes", "True r", "2", "  true", "true "] {
            assert!(
                config(&[("CRITICAL_RATE_LIMIT_ENABLE", token)])
                    .unwrap()
                    .critical_rate_limit_enabled,
                "token {token} should keep the true default"
            );
        }
        // An empty enable value is unset, like os.Getenv() == "".
        assert!(
            config(&[("CRITICAL_RATE_LIMIT_ENABLE", "")])
                .unwrap()
                .critical_rate_limit_enabled
        );
        // Numbers use this repo's strict positive_integer, not Go's lenient
        // Atoi: empty, zero, negatives and non-numerics all reject startup.
        for (name, value) in [
            ("CRITICAL_RATE_LIMIT", ""),
            ("CRITICAL_RATE_LIMIT", "0"),
            ("CRITICAL_RATE_LIMIT", "-1"),
            ("CRITICAL_RATE_LIMIT", "1.5"),
            ("CRITICAL_RATE_LIMIT_DURATION", "0"),
            ("CRITICAL_RATE_LIMIT_DURATION", "abc"),
        ] {
            let error = config(&[(name, value)]).err().unwrap();
            assert_eq!(error.to_string(), format!("invalid {name} configuration"));
        }
    }

    #[test]
    fn global_api_rate_limit_defaults_match_go() {
        let value = config(&[]).unwrap();
        assert!(value.global_api_rate_limit_enabled);
        assert_eq!(value.global_api_rate_limit_requests, 360);
        assert_eq!(value.global_api_rate_limit_duration_seconds, 180);
    }

    #[test]
    fn global_api_rate_limit_accepts_explicit_values() {
        let value = config(&[
            ("GLOBAL_API_RATE_LIMIT_ENABLE", "false"),
            ("GLOBAL_API_RATE_LIMIT", "50"),
            ("GLOBAL_API_RATE_LIMIT_DURATION", "30"),
        ])
        .unwrap();
        assert!(!value.global_api_rate_limit_enabled);
        assert_eq!(value.global_api_rate_limit_requests, 50);
        assert_eq!(value.global_api_rate_limit_duration_seconds, 30);
        // Go's strconv.ParseBool accepts these exact tokens.
        for (token, expected) in [
            ("true", true),
            ("TRUE", true),
            ("True", true),
            ("t", true),
            ("T", true),
            ("1", true),
            ("false", false),
            ("FALSE", false),
            ("False", false),
            ("f", false),
            ("F", false),
            ("0", false),
        ] {
            assert_eq!(
                config(&[("GLOBAL_API_RATE_LIMIT_ENABLE", token)])
                    .unwrap()
                    .global_api_rate_limit_enabled,
                expected,
                "token {token}"
            );
        }
    }

    #[test]
    fn global_api_rate_limit_falls_back_or_rejects_invalid_values() {
        // Go's GetEnvOrDefaultBool keeps the default on unparseable values.
        for token in ["yes", "True r", "2", "  true", "true "] {
            assert!(
                config(&[("GLOBAL_API_RATE_LIMIT_ENABLE", token)])
                    .unwrap()
                    .global_api_rate_limit_enabled,
                "token {token} should keep the true default"
            );
        }
        // An empty enable value is unset, like os.Getenv() == "".
        assert!(
            config(&[("GLOBAL_API_RATE_LIMIT_ENABLE", "")])
                .unwrap()
                .global_api_rate_limit_enabled
        );
        // Numbers use this repo's strict positive_integer, not Go's lenient
        // Atoi: empty, zero, negatives and non-numerics all reject startup.
        for (name, value) in [
            ("GLOBAL_API_RATE_LIMIT", ""),
            ("GLOBAL_API_RATE_LIMIT", "0"),
            ("GLOBAL_API_RATE_LIMIT", "-1"),
            ("GLOBAL_API_RATE_LIMIT", "1.5"),
            ("GLOBAL_API_RATE_LIMIT_DURATION", "0"),
            ("GLOBAL_API_RATE_LIMIT_DURATION", "abc"),
        ] {
            let error = config(&[(name, value)]).err().unwrap();
            assert_eq!(error.to_string(), format!("invalid {name} configuration"));
        }
    }

    #[test]
    fn global_web_rate_limit_defaults_match_go() {
        let value = config(&[]).unwrap();
        assert!(value.global_web_rate_limit_enabled);
        assert_eq!(value.global_web_rate_limit_requests, 120);
        assert_eq!(value.global_web_rate_limit_duration_seconds, 180);
    }

    #[test]
    fn global_web_rate_limit_accepts_explicit_values() {
        let value = config(&[
            ("GLOBAL_WEB_RATE_LIMIT_ENABLE", "false"),
            ("GLOBAL_WEB_RATE_LIMIT", "50"),
            ("GLOBAL_WEB_RATE_LIMIT_DURATION", "30"),
        ])
        .unwrap();
        assert!(!value.global_web_rate_limit_enabled);
        assert_eq!(value.global_web_rate_limit_requests, 50);
        assert_eq!(value.global_web_rate_limit_duration_seconds, 30);
        // Go's strconv.ParseBool accepts these exact tokens.
        for (token, expected) in [
            ("true", true),
            ("TRUE", true),
            ("True", true),
            ("t", true),
            ("T", true),
            ("1", true),
            ("false", false),
            ("FALSE", false),
            ("False", false),
            ("f", false),
            ("F", false),
            ("0", false),
        ] {
            assert_eq!(
                config(&[("GLOBAL_WEB_RATE_LIMIT_ENABLE", token)])
                    .unwrap()
                    .global_web_rate_limit_enabled,
                expected,
                "token {token}"
            );
        }
    }

    #[test]
    fn global_web_rate_limit_falls_back_or_rejects_invalid_values() {
        // Go's GetEnvOrDefaultBool keeps the default on unparseable values.
        for token in ["yes", "True r", "2", "  true", "true "] {
            assert!(
                config(&[("GLOBAL_WEB_RATE_LIMIT_ENABLE", token)])
                    .unwrap()
                    .global_web_rate_limit_enabled,
                "token {token} should keep the true default"
            );
        }
        // An empty enable value is unset, like os.Getenv() == "".
        assert!(
            config(&[("GLOBAL_WEB_RATE_LIMIT_ENABLE", "")])
                .unwrap()
                .global_web_rate_limit_enabled
        );
        // Numbers use this repo's strict positive_integer, not Go's lenient
        // Atoi: empty, zero, negatives and non-numerics all reject startup.
        for (name, value) in [
            ("GLOBAL_WEB_RATE_LIMIT", ""),
            ("GLOBAL_WEB_RATE_LIMIT", "0"),
            ("GLOBAL_WEB_RATE_LIMIT", "-1"),
            ("GLOBAL_WEB_RATE_LIMIT", "1.5"),
            ("GLOBAL_WEB_RATE_LIMIT_DURATION", "0"),
            ("GLOBAL_WEB_RATE_LIMIT_DURATION", "abc"),
        ] {
            let error = config(&[(name, value)]).err().unwrap();
            assert_eq!(error.to_string(), format!("invalid {name} configuration"));
        }
    }

    #[test]
    fn anonymous_body_limit_follows_go_get_env_or_default() {
        assert_eq!(config(&[]).unwrap().anonymous_request_body_limit_kb, 512);
        assert_eq!(
            config(&[("ANONYMOUS_REQUEST_BODY_LIMIT_KB", "64")])
                .unwrap()
                .anonymous_request_body_limit_kb,
            64
        );
        // Go keeps negatives; the byte-limit helper falls back to 512KB.
        assert_eq!(
            config(&[("ANONYMOUS_REQUEST_BODY_LIMIT_KB", "-1")])
                .unwrap()
                .anonymous_request_body_limit_kb,
            -1
        );
        // Empty and unparseable values both take the default, never fail startup.
        for value in ["", "abc", "1.5", " 64"] {
            assert_eq!(
                config(&[("ANONYMOUS_REQUEST_BODY_LIMIT_KB", value)])
                    .unwrap()
                    .anonymous_request_body_limit_kb,
                512,
                "value {value:?}"
            );
        }
    }

    #[test]
    fn trusted_proxies_are_preserved_for_security_parsing() {
        assert_eq!(config(&[]).unwrap().trusted_proxies, None);
        assert_eq!(
            config(&[("TRUSTED_PROXIES", "none")])
                .unwrap()
                .trusted_proxies
                .as_deref(),
            Some("none")
        );
        // An empty value is retained here; the parser maps it to the default list.
        assert_eq!(
            config(&[("TRUSTED_PROXIES", "")])
                .unwrap()
                .trusted_proxies
                .as_deref(),
            Some("")
        );
    }

    #[test]
    fn redis_url_is_optional_but_validated_when_present() {
        assert_eq!(config(&[]).unwrap().redis_url(), None);
        assert_eq!(
            config(&[("REDIS_CONN_STRING", "rediss://cache.example:6380")])
                .unwrap()
                .redis_url(),
            Some("rediss://cache.example:6380")
        );
    }
}
