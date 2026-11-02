//! Startup configuration. Errors contain variable names, never their values.
use std::{env, fmt, time::Duration};

// Deliberately no Debug/Serialize: the DSN may contain credentials.
#[derive(Clone)]
pub struct Config {
    dsn: String,
    pub port: u16,
    pub sync_frequency: Duration,
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
        Ok(Self {
            dsn,
            port,
            sync_frequency: Duration::from_secs(seconds),
        })
    }

    pub fn dsn(&self) -> &str {
        &self.dsn
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
}
