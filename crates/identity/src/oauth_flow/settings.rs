//! OAuth/绑定流程的 options 快照：Go `common/constants.go` 的进程变量、
//! `security/configure_discord.go` / `configure_oidc.go` 的注册配置分片，
//! 以及 `egress.ServerAddress`（generic/Discord/OIDC redirect 前缀）。
//!
//! ## 键与应用语义（逐字对 Go）
//!
//! - 四个开关（`GitHubOAuthEnabled` / `LinuxDOOAuthEnabled` /
//!   `WeChatAuthEnabled` / `TelegramOAuthEnabled`）与凭据键走
//!   `settings.ApplyOption` 的旧式 switch：bool 即 `value == "true"`
//!   （`settings.go:372-391`），int 即 `strconv.Atoi`（失败保留 0 默认，
//!   `settings.go:549-550`），string 原样覆盖（空串是合法配置值）。
//! - `discord.*` / `oidc.*` 走 `handleConfigUpdate` → `updateConfigFromMap`
//!   反射路径（`settings/config.go:163-271`）：bool 用 `strconv.ParseBool`
//!   （失败 continue 保留当前值），string 原样覆盖。键是 `discord.enabled`
//!   / `oidc.client_id` 这样的分片键。
//! - `ServerAddress` 经 egress hook 应用（`egress/register_option_hooks.go:23`），
//!   缺失时进程初值 `http://localhost:3000`。
//!
//! Go 的进程变量由启动灌入 + SyncOptions 周期刷新；Rust 侧无分片级
//! 快照加载点，按请求现读（与 `checkin` / `qq_bot` 分片同一约定），
//! 可观察行为一致。

use newapi_storage::Database;

/// Go `egress.ServerAddress` 初值（`egress/fetch_url.go:36`）。
pub const DEFAULT_SERVER_ADDRESS: &str = "http://localhost:3000";

/// 一次解析的全部快照；secret 字段不实现 Debug。
#[derive(Clone, Default)]
pub struct OAuthSettings {
    pub github_oauth_enabled: bool,
    pub linuxdo_oauth_enabled: bool,
    pub wechat_auth_enabled: bool,
    pub telegram_oauth_enabled: bool,
    pub github_client_id: String,
    pub github_client_secret: String,
    pub linuxdo_client_id: String,
    pub linuxdo_client_secret: String,
    pub linuxdo_minimum_trust_level: i64,
    pub telegram_bot_token: String,
    pub wechat_server_address: String,
    pub wechat_server_token: String,
    pub discord_enabled: bool,
    pub discord_client_id: String,
    pub discord_client_secret: String,
    pub oidc_enabled: bool,
    pub oidc_display_name: String,
    pub oidc_client_id: String,
    pub oidc_client_secret: String,
    pub oidc_token_endpoint: String,
    pub oidc_user_info_endpoint: String,
    pub server_address: String,
}

impl std::fmt::Debug for OAuthSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthSettings")
            .field("github_oauth_enabled", &self.github_oauth_enabled)
            .field("linuxdo_oauth_enabled", &self.linuxdo_oauth_enabled)
            .field("wechat_auth_enabled", &self.wechat_auth_enabled)
            .field("telegram_oauth_enabled", &self.telegram_oauth_enabled)
            .field("github_client_id", &self.github_client_id)
            .field("github_client_secret", &"[REDACTED]")
            .field("linuxdo_client_id", &self.linuxdo_client_id)
            .field("linuxdo_client_secret", &"[REDACTED]")
            .field(
                "linuxdo_minimum_trust_level",
                &self.linuxdo_minimum_trust_level,
            )
            .field("telegram_bot_token", &"[REDACTED]")
            .field("wechat_server_address", &self.wechat_server_address)
            .field("wechat_server_token", &"[REDACTED]")
            .field("discord_enabled", &self.discord_enabled)
            .field("discord_client_id", &self.discord_client_id)
            .field("discord_client_secret", &"[REDACTED]")
            .field("oidc_enabled", &self.oidc_enabled)
            .field("oidc_display_name", &self.oidc_display_name)
            .field("oidc_client_id", &self.oidc_client_id)
            .field("oidc_client_secret", &"[REDACTED]")
            .field("oidc_token_endpoint", &self.oidc_token_endpoint)
            .field("oidc_user_info_endpoint", &self.oidc_user_info_endpoint)
            .field("server_address", &self.server_address)
            .finish()
    }
}

/// `KEYS` 的 22 个占位符（? 形式；SQLite 兼容 $n，但保持与键序一致）。
const LOAD_SQL_SQLITE: &str = r#"SELECT "key", "value" FROM "options" WHERE "key" IN (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#;

/// `KEYS` 的 22 个占位符（$n 形式）。
const LOAD_SQL_POSTGRES: &str = r#"SELECT "key", "value" FROM "options" WHERE "key" IN ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)"#;

impl OAuthSettings {
    /// 现读 options 表；缺行保留 Go 默认（开关 false、凭据空串、
    /// ServerAddress 进程初值）。
    pub async fn load(db: &Database) -> Result<Self, sqlx::Error> {
        const KEYS: [&str; 22] = [
            "GitHubOAuthEnabled",
            "LinuxDOOAuthEnabled",
            "WeChatAuthEnabled",
            "TelegramOAuthEnabled",
            "GitHubClientId",
            "GitHubClientSecret",
            "LinuxDOClientId",
            "LinuxDOClientSecret",
            "LinuxDOMinimumTrustLevel",
            "TelegramBotToken",
            "WeChatServerAddress",
            "WeChatServerToken",
            "discord.enabled",
            "discord.client_id",
            "discord.client_secret",
            "oidc.enabled",
            "oidc.display_name",
            "oidc.client_id",
            "oidc.client_secret",
            "oidc.token_endpoint",
            "oidc.user_info_endpoint",
            "ServerAddress",
        ];
        // 两个后端各用静态字面量（sqlx 的 SqlSafeStr 只接受 'static；
        // 占位符与 KEYS 逐一一对应）。
        let mut rows: Vec<(String, Option<String>)> = match db {
            Database::Sqlite(pool) => {
                let mut query = sqlx::query_as::<_, (String, Option<String>)>(LOAD_SQL_SQLITE);
                for key in KEYS {
                    query = query.bind(key);
                }
                query.fetch_all(pool).await?
            }
            Database::Postgres(pool) => {
                let mut query = sqlx::query_as::<_, (String, Option<String>)>(LOAD_SQL_POSTGRES);
                for key in KEYS {
                    query = query.bind(key);
                }
                query.fetch_all(pool).await?
            }
        };
        // Go：缺键 continue；NULL 按空串应用（字符串分支的 SetString）。
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        let mut settings = Self {
            server_address: DEFAULT_SERVER_ADDRESS.to_owned(),
            ..Self::default()
        };
        for (key, value) in rows {
            let value = value.unwrap_or_default();
            apply(&mut settings, &key, &value);
        }
        Ok(settings)
    }
}

/// 两条应用路径的分发；分支顺序对齐 Go 的 ApplyOption / 反射路径。
fn apply(settings: &mut OAuthSettings, key: &str, value: &str) {
    match key {
        // 旧式 switch：bool 只认 "true"。
        "GitHubOAuthEnabled" => settings.github_oauth_enabled = value == "true",
        "LinuxDOOAuthEnabled" => settings.linuxdo_oauth_enabled = value == "true",
        "WeChatAuthEnabled" => settings.wechat_auth_enabled = value == "true",
        "TelegramOAuthEnabled" => settings.telegram_oauth_enabled = value == "true",
        // 字符串原样覆盖。
        "GitHubClientId" => settings.github_client_id = value.to_owned(),
        "GitHubClientSecret" => settings.github_client_secret = value.to_owned(),
        "LinuxDOClientId" => settings.linuxdo_client_id = value.to_owned(),
        "LinuxDOClientSecret" => settings.linuxdo_client_secret = value.to_owned(),
        // Go：`strconv.Atoi`，失败保留 0（`settings.go:549-550`）。
        "LinuxDOMinimumTrustLevel" => {
            if let Ok(parsed) = value.parse::<i64>() {
                settings.linuxdo_minimum_trust_level = parsed;
            }
        }
        "TelegramBotToken" => settings.telegram_bot_token = value.to_owned(),
        "WeChatServerAddress" => settings.wechat_server_address = value.to_owned(),
        "WeChatServerToken" => settings.wechat_server_token = value.to_owned(),
        // egress hook：原样覆盖。
        "ServerAddress" => settings.server_address = value.to_owned(),
        // 反射路径：bool 用 ParseBool（失败 continue），string 原样。
        "discord.enabled" => {
            if let Some(parsed) = parse_reflect_bool(value) {
                settings.discord_enabled = parsed;
            }
        }
        "discord.client_id" => settings.discord_client_id = value.to_owned(),
        "discord.client_secret" => settings.discord_client_secret = value.to_owned(),
        "oidc.enabled" => {
            if let Some(parsed) = parse_reflect_bool(value) {
                settings.oidc_enabled = parsed;
            }
        }
        "oidc.display_name" => settings.oidc_display_name = value.to_owned(),
        "oidc.client_id" => settings.oidc_client_id = value.to_owned(),
        "oidc.client_secret" => settings.oidc_client_secret = value.to_owned(),
        "oidc.token_endpoint" => settings.oidc_token_endpoint = value.to_owned(),
        "oidc.user_info_endpoint" => settings.oidc_user_info_endpoint = value.to_owned(),
        _ => {}
    }
}

/// Go `strconv.ParseBool` 的接受集合（`config.go:191-196`）。
fn parse_reflect_bool(value: &str) -> Option<bool> {
    match value {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn switch_semantics_follow_go_apply_option() {
        let mut settings = OAuthSettings::default();
        apply(&mut settings, "GitHubOAuthEnabled", "true");
        assert!(settings.github_oauth_enabled);
        apply(&mut settings, "GitHubOAuthEnabled", "TRUE");
        // 旧式 switch 只认小写 "true"。
        assert!(!settings.github_oauth_enabled);
        apply(&mut settings, "LinuxDOMinimumTrustLevel", "2");
        assert_eq!(settings.linuxdo_minimum_trust_level, 2);
        apply(&mut settings, "LinuxDOMinimumTrustLevel", "abc");
        assert_eq!(settings.linuxdo_minimum_trust_level, 2);
        apply(&mut settings, "LinuxDOMinimumTrustLevel", "0");
        assert_eq!(settings.linuxdo_minimum_trust_level, 0);
    }

    #[test]
    fn reflect_semantics_follow_parse_bool() {
        let mut settings = OAuthSettings::default();
        apply(&mut settings, "discord.enabled", "TRUE");
        // 反射路径用 ParseBool，接受全大写。
        assert!(settings.discord_enabled);
        apply(&mut settings, "discord.enabled", "yes");
        assert!(settings.discord_enabled);
        apply(&mut settings, "oidc.enabled", "0");
        assert!(!settings.oidc_enabled);
    }

    #[test]
    fn server_address_defaults_to_egress_initial() {
        let settings = OAuthSettings::default();
        assert!(settings.server_address.is_empty());
        let mut settings = settings;
        apply(&mut settings, "ServerAddress", "https://api.example.com");
        assert_eq!(settings.server_address, "https://api.example.com");
    }
}
