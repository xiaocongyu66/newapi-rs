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
        Ok(Self {
            dsn,
            session_secret,
            port,
            sync_frequency: Duration::from_secs(seconds),
            session_cookie,
            redis_url,
        })
    }

    pub fn dsn(&self) -> &str {
        &self.dsn
    }

    /// 未配置时返回 None；调用方负责生成进程级随机密钥并记录警告。
    pub fn session_secret(&self) -> Option<&str> {
        self.session_secret.as_deref()
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
