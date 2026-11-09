//! Passkey 设置快照：Go `identity/passkey_settings.go`（类型）与
//! `security/configure_passkey.go`（注册 + ServerAddress 派生）合并移植。
//!
//! Go 把设置注册到 options 表的 `passkey` 键（JSON 结构体），读取侧
//! `GetPasskeySettings` 在 RPID 为空时从 `ServerAddress` 的 URL Host 派生、
//! Origins 为空或字面 `"[]"` 时回填 ServerAddress。本模块按请求实时读取两行
//! options（`passkey` 与 `ServerAddress`），与 Go 的进程内注册表相比只是
//! 缓存时机不同，派生规则逐行对齐。

use newapi_storage::Database;
use serde::{Deserialize, Serialize};

/// Go `egress.ServerAddress` 初始值（`fetch_url.go:36`）。
pub const DEFAULT_SERVER_ADDRESS: &str = "http://localhost:3000";
/// Go `common.SystemName` 默认（`constants.go:16`）。
pub const DEFAULT_RP_DISPLAY_NAME: &str = "New API";
/// Go passkey 默认的 UserVerification（`configure_passkey.go:20`）。
pub const DEFAULT_USER_VERIFICATION: &str = "preferred";

/// options 表的键名，与 Go `settings.GlobalConfig.Register("passkey", ...)` 一致。
const OPTION_KEY_PASSKEY: &str = "passkey";
const OPTION_KEY_SERVER_ADDRESS: &str = "ServerAddress";

/// Go `identity.PasskeySettings`；字段名即持久化 JSON 的键名。
/// `#[serde(default)]` 复现 Go `json.Unmarshal` 对缺省键留零值的语义（Go 的
/// settings 注册表以已注册默认值起步，前端可只存部分字段）。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PasskeySettings {
    pub enabled: bool,
    pub rp_display_name: String,
    pub rp_id: String,
    /// 逗号分隔的 origin 列表，空表示自动推导。
    pub origins: String,
    pub allow_insecure_origin: bool,
    /// `required` / `preferred` / `discouraged`，空退回 `preferred`。
    pub user_verification: String,
    /// `platform` / `cross-platform`，空表示不限制。
    pub attachment_preference: String,
}

/// 固定分类；不携带 SQL 或 option 原文。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettingsError {
    Storage,
}

impl std::fmt::Display for SettingsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("passkey settings storage failure")
    }
}

impl std::error::Error for SettingsError {}

impl From<sqlx::Error> for SettingsError {
    fn from(_: sqlx::Error) -> Self {
        Self::Storage
    }
}

#[derive(Clone)]
pub struct PasskeySettingsRepository {
    db: Database,
}

impl PasskeySettingsRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// 读取 `passkey` 与 `ServerAddress` 两行 options：
    /// - `passkey` 行缺失或 JSON 非法 → Go 保持已注册默认值的语义（default）；
    /// - ServerAddress 缺失 → Go 的进程初始值（DEFAULT_SERVER_ADDRESS）。
    pub async fn load(&self) -> Result<(PasskeySettings, String), SettingsError> {
        let sql = r#"SELECT "key", "value" FROM options WHERE "key" IN ($1, $2)"#;
        let rows: Vec<(String, Option<String>)> = match &self.db {
            Database::Sqlite(pool) => {
                sqlx::query_as(sql)
                    .bind(OPTION_KEY_PASSKEY)
                    .bind(OPTION_KEY_SERVER_ADDRESS)
                    .fetch_all(pool)
                    .await?
            }
            Database::Postgres(pool) => {
                sqlx::query_as(sql)
                    .bind(OPTION_KEY_PASSKEY)
                    .bind(OPTION_KEY_SERVER_ADDRESS)
                    .fetch_all(pool)
                    .await?
            }
        };
        let mut settings = PasskeySettings::default();
        let mut server_address = DEFAULT_SERVER_ADDRESS.to_owned();
        for (key, value) in rows {
            match (key.as_str(), value) {
                (OPTION_KEY_PASSKEY, Some(value)) => {
                    // Go 的 settings 注册表反序列化失败时保留既有默认值。
                    if let Ok(parsed) = serde_json::from_str::<PasskeySettings>(&value) {
                        settings = parsed;
                    }
                }
                (OPTION_KEY_SERVER_ADDRESS, Some(value)) => server_address = value,
                _ => {}
            }
        }
        Ok((settings, server_address))
    }
}

impl PasskeySettings {
    /// Go `GetPasskeySettings` 的读取侧派生：RPID 空且 ServerAddress 非空时
    /// 取其 URL Host（解析失败回退原串），Origins 空或 `"[]"` 时回填
    /// ServerAddress。返回派生后的有效视图，不改动持久化值。
    pub fn resolve(&self, server_address: &str) -> PasskeySettings {
        let mut effective = self.clone();
        let address = server_address.trim();
        if effective.rp_id.trim().is_empty() && !address.is_empty() {
            effective.rp_id = host_of(address).unwrap_or_else(|| address.to_owned());
        }
        if effective.origins.trim().is_empty() || effective.origins.trim() == "[]" {
            effective.origins = address.to_owned();
        }
        effective
    }

    /// Go `BuildWebAuthn` 的 RPDisplayName：trim 后为空回退 SystemName。
    pub fn effective_rp_display_name(&self) -> &str {
        let name = self.rp_display_name.trim();
        if name.is_empty() {
            DEFAULT_RP_DISPLAY_NAME
        } else {
            name
        }
    }

    /// Go `protocol.UserVerificationRequirement(settings.UserVerification)`，
    /// 空串退回 `preferred`（`passkey_webauthn.go:46-48`）。
    pub fn effective_user_verification(&self) -> &str {
        let value = self.user_verification.trim();
        if value.is_empty() {
            DEFAULT_USER_VERIFICATION
        } else {
            value
        }
    }
}

/// 对应 Go `url.Parse(serverAddr).Host`：解析失败时 Go 回退到原串。
/// `Url` 取 webauthn-rs prelude 的再导出（`url::Url` 同一类型）。
fn host_of(address: &str) -> Option<String> {
    let parsed = webauthn_rs::prelude::Url::parse(address.trim()).ok()?;
    let host = parsed.host_str()?;
    match parsed.port() {
        Some(port) => Some(format!("{host}:{port}")),
        None => Some(host.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_go_seed() {
        let settings = PasskeySettings::default();
        assert!(!settings.enabled);
        assert_eq!(settings.user_verification, "");
        assert_eq!(settings.effective_user_verification(), "preferred");
        assert_eq!(
            settings.effective_rp_display_name(),
            DEFAULT_RP_DISPLAY_NAME
        );
    }

    #[test]
    fn server_address_derives_like_go_getter() {
        let settings = PasskeySettings::default();
        let effective = settings.resolve("https://newapi.pro");
        assert_eq!(effective.rp_id, "newapi.pro");
        assert_eq!(effective.origins, "https://newapi.pro");
        // 带 port 的派生（Go 取 parsed.Host，含端口）。
        let effective = settings.resolve("http://localhost:3000");
        assert_eq!(effective.rp_id, "localhost:3000");
        assert_eq!(effective.origins, "http://localhost:3000");
        // 已配置的 RPID/Origins 不被覆盖。
        let configured = PasskeySettings {
            rp_id: "example.com".into(),
            origins: "https://a.example.com".into(),
            ..PasskeySettings::default()
        };
        let effective = configured.resolve("https://other.example.com");
        assert_eq!(effective.rp_id, "example.com");
        assert_eq!(effective.origins, "https://a.example.com");
        // Origins 为字面 "[]" 时回填（Go 的防御分支）。
        let empty_list = PasskeySettings {
            origins: "[]".into(),
            ..PasskeySettings::default()
        };
        let effective = empty_list.resolve("https://newapi.pro");
        assert_eq!(effective.origins, "https://newapi.pro");
    }
}
