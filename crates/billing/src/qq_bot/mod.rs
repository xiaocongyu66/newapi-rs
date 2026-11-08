//! QQ 机器人配置分片：Go `apps/api/internal/billing/qqbot_setting.go`
//! （`settings.GlobalConfig.Register("qq_bot_setting", &qqBotSetting)`）。
//!
//! 只加载本切片（五条 QQ HTTP 路由）读取的四个键：`qq_checkin_enabled`、
//! `rebind_cooldown_seconds`、`app_id`、`app_secret`。`QQBotSetting` 的其余
//! 几十个字段（掉落、红包、转账、诱饵……）属于尚未移植的 QQ 机器人事件切片，
//! 这里不读也不落默认值——缺行即 Go 结构体缺省，与 `updateConfigFromMap` 的
//! 「缺键 `continue`」一致。
//!
//! 解析语义与 [`crate::checkin`] 分片共用 [`crate::go_options`]：bool 走
//! `strconv.ParseBool`，int 走 `ParseInt`→`ParseFloat` 截断，失败**保留当前
//! 值**（首次加载即 [`QQBotSettings::default`]，与 `qqbot_setting.go:194-272`
//! 的进程缺省逐字一致）。
//!
//! Go 每次 `GetQQBotSetting()` 还会把冷却值同步进 identity 的全局变量
//! （`qqbot_setting.go:280`）；本端口把值显式传给
//! [`newapi_identity::qq_bind::QQBindingRepository::create_bind_code`]，
//! 不引入进程级可变全局。

use newapi_storage::Database;

use crate::go_options::{parse_bool, parse_int};

/// Go `QQBotSetting.QQCheckinEnabled` 的选项键（json tag 即键后缀；
/// `settings.go:680` 按前缀切分，键为 `qq_bot_setting.<字段>`）。
pub const KEY_CHECKIN_ENABLED: &str = "qq_bot_setting.qq_checkin_enabled";
/// Go `QQBotSetting.RebindCooldownSeconds`：解绑后多少秒内禁止重新绑定，
/// <=0 关闭冷却（`identity.RejectQQBindIfInCooldown`）。
pub const KEY_REBIND_COOLDOWN_SECONDS: &str = "qq_bot_setting.rebind_cooldown_seconds";
/// Go `QQBotSetting.AppID`。
pub const KEY_APP_ID: &str = "qq_bot_setting.app_id";
/// Go `QQBotSetting.AppSecret`。
pub const KEY_APP_SECRET: &str = "qq_bot_setting.app_secret";

const OPTION_KEYS: [&str; 4] = [
    KEY_CHECKIN_ENABLED,
    KEY_REBIND_COOLDOWN_SECONDS,
    KEY_APP_ID,
    KEY_APP_SECRET,
];

/// Go `billing.QQBotSetting` 中本切片读取的四个字段。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QQBotSettings {
    pub qq_checkin_enabled: bool,
    pub rebind_cooldown_seconds: i64,
    pub app_id: String,
    pub app_secret: String,
}

impl Default for QQBotSettings {
    fn default() -> Self {
        Self {
            qq_checkin_enabled: false,
            // Go `qqbot_setting.go:203-204`：默认 1 小时重绑冷却。
            rebind_cooldown_seconds: 3600,
            app_id: String::new(),
            app_secret: String::new(),
        }
    }
}

impl QQBotSettings {
    /// Go `GetQQBotSetting()` 的等价物。Go 侧是进程内结构体 + 定期 reload；
    /// 本端口尚无配置快照的分片级加载点，因此每次现读，可观察结果一致
    /// （配置变更在下一次请求即生效）。`checkin` 分片同样现读，见
    /// `crates/billing/src/checkin/store.rs` 的 `load_option_rows`。
    pub async fn load(db: &Database) -> Result<Self, sqlx::Error> {
        let rows = load_option_rows(db).await?;
        let mut settings = Self::default();
        for (key, value) in rows {
            apply_option(&mut settings, key, value);
        }
        Ok(settings)
    }
}

async fn load_option_rows(db: &Database) -> Result<Vec<(&'static str, String)>, sqlx::Error> {
    let rows: Vec<(String, Option<String>)> = match db {
        Database::Sqlite(pool) => {
            sqlx::query_as(
                "SELECT \"key\", \"value\" FROM \"options\" \
                 WHERE \"key\" IN (?, ?, ?, ?)",
            )
            .bind(OPTION_KEYS[0])
            .bind(OPTION_KEYS[1])
            .bind(OPTION_KEYS[2])
            .bind(OPTION_KEYS[3])
            .fetch_all(pool)
            .await?
        }
        Database::Postgres(pool) => {
            sqlx::query_as(
                "SELECT \"key\", \"value\" FROM \"options\" \
                 WHERE \"key\" IN ($1, $2, $3, $4)",
            )
            .bind(OPTION_KEYS[0])
            .bind(OPTION_KEYS[1])
            .bind(OPTION_KEYS[2])
            .bind(OPTION_KEYS[3])
            .fetch_all(pool)
            .await?
        }
    };
    // Go 的选项应用对 SQL NULL 按空字符串处理；NULL 不是这里的错误分支
    // （与 checkin 的 `load_option_rows` 同一约定）。
    Ok(rows
        .into_iter()
        .filter_map(|(key, value)| {
            OPTION_KEYS
                .iter()
                .find(|candidate| **candidate == key)
                .map(|candidate| (*candidate, value.unwrap_or_default()))
        })
        .collect())
}

/// Go `updateConfigFromMap` 的字段分支：bool / int 失败即 `continue`
/// （保留当前值），string 原样覆盖——「空串」是合法配置值而非缺失。
pub(super) fn apply_option(settings: &mut QQBotSettings, key: &str, value: &str) {
    match key {
        KEY_CHECKIN_ENABLED => {
            if let Some(parsed) = parse_bool(value) {
                settings.qq_checkin_enabled = parsed;
            }
        }
        KEY_REBIND_COOLDOWN_SECONDS => {
            if let Some(parsed) = parse_int(value) {
                settings.rebind_cooldown_seconds = parsed;
            }
        }
        KEY_APP_ID => settings.app_id = value.to_owned(),
        KEY_APP_SECRET => settings.app_secret = value.to_owned(),
        _ => {}
    }
}

#[cfg(test)]
mod tests;
