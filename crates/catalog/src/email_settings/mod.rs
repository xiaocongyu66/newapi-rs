//! 邮箱限制选项快照。
//!
//! Go 参考：`apps/api/internal/common/constants.go:74-83`（默认值）与
//! `apps/api/internal/settings/settings.go:392-395/468-477`（选项应用）。
//! `SendEmailVerification`（`identity/verify_email.go:22`）按以下顺序消费
//! 这些开关：域名白名单 → 别名限制 → 格式正则。本快照只承载这四个键，
//! `SystemName`/`ServerAddress`/`VerificationValidMinutes` 在 Go 中分别来自
//! egress/common 的包级变量，由各端点按编译期默认值处理。
//!
//! 与 `GroupSettings` 相同，handler 逐请求 `load`；缺席的行保留默认值，
//! SQL NULL 是错误而非静默默认（与 `AuthSettings` 一致）。

use newapi_storage::Database;

mod store;

/// Go `common.EmailDomainWhitelist` 的 9 个默认域名（constants.go:78-88）。
pub const DEFAULT_DOMAIN_WHITELIST: [&str; 9] = [
    "gmail.com",
    "163.com",
    "126.com",
    "qq.com",
    "outlook.com",
    "hotmail.com",
    "icloud.com",
    "yahoo.com",
    "foxmail.com",
];

/// 邮箱验证端点读取的限制选项。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmailSettings {
    /// Go `common.EmailDomainRestrictionEnabled`（默认 false）。
    pub email_domain_restriction_enabled: bool,
    /// Go `common.EmailDomainWhitelist`：选项值按逗号拆分。
    /// `strings.Split("", ",")` 得到 `[""]`，空字符串行同样复刻。
    pub email_domain_whitelist: Vec<String>,
    /// Go `common.EmailAliasRestrictionEnabled`（默认 false）。
    pub email_alias_restriction_enabled: bool,
    /// `common.EmailFormatRegex` 去除首尾空白后每行一条的规则文本；
    /// 空列表表示未配置（不限制）。
    pub email_format_regex_rules: Vec<String>,
}

impl Default for EmailSettings {
    fn default() -> Self {
        Self {
            email_domain_restriction_enabled: false,
            email_domain_whitelist: DEFAULT_DOMAIN_WHITELIST
                .iter()
                .map(|domain| (*domain).to_owned())
                .collect(),
            email_alias_restriction_enabled: false,
            email_format_regex_rules: Vec::new(),
        }
    }
}

impl EmailSettings {
    /// 一次性读取四个键并返回完整替换。缺失行保留 `previous` 对应字段；
    /// SQL NULL 是错误。
    pub async fn load(db: &Database, previous: &Self) -> Result<Self, sqlx::Error> {
        store::load(db, previous).await
    }

    /// `settings.go:468-470`：`strings.Split(value, ",")`。
    fn split_whitelist(value: &str) -> Vec<String> {
        value.split(',').map(str::to_owned).collect()
    }

    /// `settings.go:471-484`：按行拆分，去掉首尾空白后丢弃空行。
    /// Go 在应用选项时即编译每条规则（失败记 SysError 后跳过）；本快照
    /// 只保留规则文本，编译与跳过处置推迟到匹配时（见 apps/server 的
    /// `email_format_rejected`）。
    fn split_regex_rules(value: &str) -> Vec<String> {
        value
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_go_seed_values() {
        let defaults = EmailSettings::default();
        assert!(!defaults.email_domain_restriction_enabled);
        assert!(!defaults.email_alias_restriction_enabled);
        assert!(defaults.email_format_regex_rules.is_empty());
        assert_eq!(
            defaults.email_domain_whitelist,
            [
                "gmail.com",
                "163.com",
                "126.com",
                "qq.com",
                "outlook.com",
                "hotmail.com",
                "icloud.com",
                "yahoo.com",
                "foxmail.com",
            ]
        );
    }

    #[test]
    fn whitelist_split_matches_go_strings_split() {
        assert_eq!(
            EmailSettings::split_whitelist("a.com,b.com"),
            vec!["a.com", "b.com"]
        );
        // Go 的 strings.Split("", ",") 返回 [""]，空值不是空列表。
        assert_eq!(EmailSettings::split_whitelist(""), vec![""]);
        assert_eq!(EmailSettings::split_whitelist("a.com"), vec!["a.com"]);
    }

    #[test]
    fn regex_rules_are_trimmed_per_line() {
        assert_eq!(
            EmailSettings::split_regex_rules(" @a\\.com$ \n\n  ^b@ \t"),
            vec!["@a\\.com$", "^b@"]
        );
        assert!(EmailSettings::split_regex_rules("  \n ").is_empty());
    }
}
