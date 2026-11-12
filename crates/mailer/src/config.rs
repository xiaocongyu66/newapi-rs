//! Go `email_pool.go:22-62` 的账号配置与池解析。

use serde::Deserialize;

/// Go `SMTPAccountConfig`（email_pool.go:22-49）。JSON 键名按 Go tag。
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct SmtpAccountConfig {
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub port: i64,
    #[serde(default)]
    pub account: String,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub from: String,
    #[serde(rename = "ssl", default)]
    pub ssl_enabled: bool,
    #[serde(rename = "starttls", default)]
    pub starttls: bool,
    /// UTC+8 日历日内单账号发送上限；0 = 不限量。
    #[serde(rename = "dailyLimit", default)]
    pub daily_limit: i64,
    #[serde(default)]
    pub priority: i64,
}

/// Go `ParseSMTPAccountPoolJSON`（email_pool.go:44-62）。空值不是错误。
/// 错误文案逐字复刻（Go `fmt.Errorf` 字面量）。
pub fn parse_smtp_account_pool_json(value: &str) -> Result<Vec<SmtpAccountConfig>, String> {
    if value.trim().is_empty() {
        return Ok(Vec::new());
    }
    let pool: Vec<SmtpAccountConfig> = serde_json::from_str(value)
        .map_err(|_| "SMTPAccountPool must be a JSON array of accounts".to_owned())?;
    for (index, account) in pool.iter().enumerate() {
        if account.server.is_empty() || account.account.is_empty() || account.port <= 0 {
            return Err(format!(
                "SMTPAccountPool entry {index} requires server, account and a positive port"
            ));
        }
        if account.daily_limit < 0 || account.priority < 0 {
            return Err(format!(
                "SMTPAccountPool entry {index} needs non-negative dailyLimit and priority"
            ));
        }
    }
    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_value_is_not_an_error() {
        assert!(parse_smtp_account_pool_json("").unwrap().is_empty());
        assert!(parse_smtp_account_pool_json("   ").unwrap().is_empty());
    }

    #[test]
    fn non_array_is_rejected_verbatim() {
        let error = parse_smtp_account_pool_json("{\"server\":\"s\"}").unwrap_err();
        assert_eq!(error, "SMTPAccountPool must be a JSON array of accounts");
    }

    #[test]
    fn entry_requires_server_account_and_positive_port() {
        let error = parse_smtp_account_pool_json(r#"[{"server":"s","account":"a"}]"#).unwrap_err();
        assert_eq!(
            error,
            "SMTPAccountPool entry 0 requires server, account and a positive port"
        );
    }

    #[test]
    fn negative_limits_are_rejected() {
        let error = parse_smtp_account_pool_json(
            r#"[{"server":"s","account":"a","port":465,"dailyLimit":-1}]"#,
        )
        .unwrap_err();
        assert_eq!(
            error,
            "SMTPAccountPool entry 0 needs non-negative dailyLimit and priority"
        );
    }

    #[test]
    fn full_entry_round_trips() {
        let pool = parse_smtp_account_pool_json(
            r#"[{"server":"smtp.example.com","port":465,"account":"a@b.c","token":"t","from":"f@b.c","ssl":true,"starttls":false,"dailyLimit":100,"priority":1}]"#,
        )
        .unwrap();
        assert_eq!(
            pool,
            vec![SmtpAccountConfig {
                server: "smtp.example.com".to_owned(),
                port: 465,
                account: "a@b.c".to_owned(),
                token: "t".to_owned(),
                from: "f@b.c".to_owned(),
                ssl_enabled: true,
                starttls: false,
                daily_limit: 100,
                priority: 1,
            }]
        );
    }
}
