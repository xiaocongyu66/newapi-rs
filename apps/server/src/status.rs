//! `GET /api/status` — 移植 Go `handler.GetStatus`
//! （`/root/newapi/apps/api/internal/transport/handler/handle_misc.go:40-175`）。
//!
//! 诚实默认值台账（硬性约束：未实现功能不得标为启用、不得伪造数据）：
//! - 真实值：数据源已存在于 `AppState` 快照（`PublicConfig`、`AuthSettings`、
//!   `QuotaDisplay`）的字段——登录/注册开关、Turnstile、法务文本联动、额度展示类型。
//! - Go 运行时默认值：子系统未移植（billing 细节 P7、security/oauth P3+、
//!   usage 控制台 P3、egress/安装向导未排期）的字段，逐一对照 Go 源码中
//!   “未配置任何 option 时”的取值；每字段注释标注 Go 出处与补齐阶段。
//!
//! Go 的 `common.H` 是 `map[string]any`，JSON 字段顺序不保证；此处用
//! `serde_json::Value`，测试断言一律按 key 取值，不依赖顺序。

use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{Json, extract::State};
use newapi_identity::self_user::QuotaDisplayKind;
use serde_json::{Value, json};

use crate::AppState;

/// Go `common.StartTime = time.Now().Unix()`（`constants.go:14`）：进程启动时刻，单位秒。
fn start_time() -> i64 {
    static START: OnceLock<i64> = OnceLock::new();
    *START.get_or_init(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs() as i64)
            .unwrap_or_default()
    })
}

// ---- Go 运行时默认值常量（子系统未移植；逐条注明出处） ----

/// Go `billing/pay_subscription.go:73` `USDExchangeRate`。until P7。
const DEFAULT_USD_EXCHANGE_RATE: f64 = 7.3;
/// Go `billing/pay_subscription.go:71` `Price`。until P7。
const DEFAULT_PRICE: f64 = 7.3;
/// Go `billing/pay_subscription.go:167` `StripeUnitPrice`。until P7。
const DEFAULT_STRIPE_UNIT_PRICE: f64 = 8.0;
/// Go `billing.GeneralSetting` 默认（`manage_subscription.go:606-614`）：
/// `CustomCurrencyExchangeRate: 1.0`、`AmountName: ""`、`AmountUnit: "usd"`
/// （`AmountUnitEffective` 对 "usd" 原样返回）。until P7。
const DEFAULT_CUSTOM_CURRENCY_EXCHANGE_RATE: f64 = 1.0;
const DEFAULT_AMOUNT_NAME: &str = "";
const DEFAULT_AMOUNT_UNIT: &str = "usd";
/// Go `GeneralSetting.DocsLink` 默认。until P7。
const DEFAULT_DOCS_LINK: &str = "https://docs.newapi.pro";
/// Go `common.SystemName` 默认（`constants.go:16`）。until P3（options 快照扩展）。
const DEFAULT_SYSTEM_NAME: &str = "New API";
/// Go `egress.ServerAddress` 初始值（`fetch_url.go:36`）；无 ServerAddress
/// option 行时 Go 就输出这个值。until egress 移植。
const DEFAULT_SERVER_ADDRESS: &str = "http://localhost:3000";
/// Go `usage.GetConsoleSetting()` 默认四项全为 true（`configure_perf.go:74-83`）。
/// until P3（usage 控制台面板）。
const DEFAULT_API_INFO_ENABLED: bool = true;
const DEFAULT_UPTIME_KUMA_ENABLED: bool = true;
const DEFAULT_ANNOUNCEMENTS_ENABLED: bool = true;
const DEFAULT_FAQ_ENABLED: bool = true;
/// Go passkey 默认（`security/configure_passkey.go:13-21`）；`RPID`/`Origins`
/// 由 `GetPasskeySettings` 从 `ServerAddress` 派生（同文件 28-43 行）：
/// `url.Parse("http://localhost:3000").Host == "localhost:3000"`，
/// `Origins` 直接取 `ServerAddress`。`RPDisplayName` 取 `common.SystemName`
/// 默认值。until security 移植。
const DEFAULT_PASSKEY_RP_DISPLAY_NAME: &str = DEFAULT_SYSTEM_NAME;
const DEFAULT_PASSKEY_RP_ID: &str = "localhost:3000";
const DEFAULT_PASSKEY_ORIGINS: &str = DEFAULT_SERVER_ADDRESS;
const DEFAULT_PASSKEY_USER_VERIFICATION: &str = "preferred";
/// Go `OIDCSettings.GetEffectiveDisplayName()` 空配置回退字面量 "OIDC"
/// （`security/configure_oidc.go:35-40`）。until security/oauth 移植。
const DEFAULT_OIDC_DISPLAY_NAME: &str = "OIDC";

/// Go `usage.Chats` 初始值（`configure_perf.go:15-46`）；未配置 Chats option 时
/// Go 就输出这份列表。until P3（usage 子系统）。
fn default_chats() -> Value {
    json!([
        {"Cherry Studio": "cherrystudio://providers/api-keys?v=1&data={cherryConfig}"},
        {"AionUI": "aionui://provider/add?v=1&data={aionuiConfig}"},
        {"流畅阅读": "fluentread"},
        {"CC Switch": "ccswitch"},
        {"DeepChat": "deepchat://provider/install?v=1&data={deepchatConfig}"},
        {"Lobe Chat 官方示例": "https://chat-preview.lobehub.com/?settings={\"keyVaults\":{\"openai\":{\"apiKey\":\"{key}\",\"baseURL\":\"{address}/v1\"}}}"},
        {"AI as Workspace": "https://aiaw.app/set-provider?provider={\"type\":\"openai\",\"settings\":{\"apiKey\":\"{key}\",\"baseURL\":\"{address}/v1\",\"compatibility\":\"strict\"}}"},
        {"AMA 问天": "ama://set-api-key?server={address}&key={key}"},
        {"OpenCat": "opencat://team/join?domain={address}&token={key}"}
    ])
}

/// 构造 `data` 对象及其外层信封；纯构造、无 IO，供 handler 与测试共用。
pub fn status_body(state: &AppState) -> Value {
    let public = state.snapshot();
    let auth = state.auth_settings();
    let display = state.quota_display();

    // 真实值（`QuotaDisplay` 快照，billing crate 已移植）。Go
    // `billing.GetQuotaDisplayType()` / `IsCurrencyDisplay()`。
    let (quota_display_type, display_in_currency) = match display.kind {
        QuotaDisplayKind::Usd => ("USD", true),
        QuotaDisplayKind::Cny { .. } => ("CNY", true),
        QuotaDisplayKind::Custom { .. } => ("CUSTOM", true),
        QuotaDisplayKind::Tokens => ("TOKENS", false),
    };
    // 快照保真度：`QuotaDisplaySettings` 只在 CNY kind 携带 usd 汇率、只在
    // CUSTOM kind 携带自定义汇率；其余 kind 对应的原始 option 值不在快照视图内，
    // 输出 Go 默认值而不是猜测（P4：暴露原始 QuotaDisplay 后可全类型取真实值）。
    let usd_exchange_rate = match display.kind {
        QuotaDisplayKind::Cny { usd_exchange_rate } => usd_exchange_rate,
        _ => DEFAULT_USD_EXCHANGE_RATE,
    };
    let custom_currency_exchange_rate = match display.kind {
        QuotaDisplayKind::Custom { rate } => rate,
        _ => DEFAULT_CUSTOM_CURRENCY_EXCHANGE_RATE,
    };

    let mut body = json!({
        // Go `common.Version` 由 ldflags/VERSION 环境变量注入；Rust 取 crate
        // 版本（无 "v" 前缀），注入格式差异见交付报告。
        "version": env!("CARGO_PKG_VERSION"),
        // Go `common.StartTime`。
        "start_time": start_time(),
        // 真实值：AuthSettings 快照。
        "email_verification": auth.email_verification_enabled, // Go common.EmailVerificationEnabled
        // GitHub/Discord/LinuxDo/Telegram/WeChat OAuth 未移植；Go 未配置默认值。
        "github_oauth": false,               // Go common.GitHubOAuthEnabled (constants.go:67)
        "github_client_id": "",              // Go common.GitHubClientId (constants.go:120)
        "discord_oauth": false,              // Go security.GetDiscordSettings().Enabled 零值
        "discord_client_id": "",             // Go security DiscordSettings 零值
        "linuxdo_oauth": false,              // Go common.LinuxDOOAuthEnabled (constants.go:68)
        "linuxdo_client_id": "",             // Go common.LinuxDOClientId (constants.go:122)
        "linuxdo_minimum_trust_level": 0,    // Go common.LinuxDOMinimumTrustLevel (constants.go:124)
        "telegram_oauth": false,             // Go common.TelegramOAuthEnabled (constants.go:70)
        "telegram_bot_name": "",             // Go common.TelegramBotName (constants.go:134)
        // Go 硬编码 "default"。
        "theme": "default",
        // Go OptionMap["ThemeCustomization"] 种子为空串（settings.go:276）；
        // catalog 快照暂无此 key（后续项：P3 扩展 PublicConfig）。
        "theme_customization": "",
        // Go common.SystemName 默认；SystemName option 尚未进 catalog 快照。until P3。
        "system_name": DEFAULT_SYSTEM_NAME,
        "logo": "",                          // Go common.Logo 默认 (constants.go:18)
        "footer_html": "",                   // Go common.Footer 默认 (constants.go:17)
        "wechat_qrcode": "",                 // Go common.WeChatAccountQRCodeImageURL (constants.go:128)
        "wechat_login": false,               // Go common.WeChatAuthEnabled (constants.go:69)
        // Go egress.ServerAddress 初始值；egress 未移植。until egress 移植。
        "server_address": DEFAULT_SERVER_ADDRESS,
        // 真实值：AuthSettings 快照。
        "turnstile_check": auth.turnstile_check_enabled,
        "turnstile_site_key": auth.turnstile_site_key.clone(),
        // Go billing.GeneralSetting 默认；billing general_setting 未移植。until P7。
        "docs_link": DEFAULT_DOCS_LINK,
        // 真实值：QuotaDisplay 快照（display_type → 三字段）。
        "display_in_currency": display_in_currency,
        "quota_display_type": quota_display_type,
        "custom_currency_symbol": "", // Go GeneralSetting.CustomCurrencySymbol 零值。until P7。
        "custom_currency_exchange_rate": custom_currency_exchange_rate,
        "amount_name": DEFAULT_AMOUNT_NAME, // Go GeneralSetting 默认。until P7。
        "amount_unit": DEFAULT_AMOUNT_UNIT, // Go AmountUnitEffective() 默认。until P7。
        // Go QuotaForInviter/QuotaForInvitee 默认 0（constants.go:137-138），
        // QuotaToDisplayAmount(0) 对四种展示类型均为 0。until P7。
        "inviter_reward_display": 0.0,
        "invitee_reward_display": 0.0,
        // Go common 常量默认（constants.go:27-33）。until P3（options 快照扩展）。
        "display_group_ratio_table": false,
        "enable_drawing": true,   // Go common.DrawingEnabled (constants.go:28)
        "enable_task": true,      // Go common.TaskEnabled (constants.go:29)
        "enable_data_export": true, // Go common.DataExportEnabled (constants.go:30)
        "data_export_default_time": "hour", // Go common.DataExportDefaultTime (constants.go:32)
        "default_collapse_sidebar": false,  // Go common.DefaultCollapseSidebar (constants.go:33)
        "mj_notify_enabled": false, // Go usage.MjNotifyEnabled (configure_perf.go:98)。until P3。
        "chats": default_chats(),   // Go usage.Chats 默认列表。until P3。
        // Go catalog/manage_channels.go:12,15 与 resolve_group.go:74 默认。until P3。
        "demo_site_enabled": false,
        "self_use_mode_enabled": false,
        "default_use_auto_group": false,
        // 真实值：AuthSettings 快照。
        "register_enabled": auth.register_enabled,
        "password_login_enabled": auth.password_login_enabled,
        "password_register_enabled": auth.password_register_enabled,
        // Go billing 进程级变量默认（pay_subscription.go:71-73,167）。until P7。
        "usd_exchange_rate": usd_exchange_rate,
        "price": DEFAULT_PRICE,
        "stripe_unit_price": DEFAULT_STRIPE_UNIT_PRICE,
        // Go usage.GetConsoleSetting() 默认全 true（configure_perf.go:74-83）。until P3。
        "api_info_enabled": DEFAULT_API_INFO_ENABLED,
        "uptime_kuma_enabled": DEFAULT_UPTIME_KUMA_ENABLED,
        "announcements_enabled": DEFAULT_ANNOUNCEMENTS_ENABLED,
        "faq_enabled": DEFAULT_FAQ_ENABLED,
        // Go OptionMap 读取；catalog 快照暂无这些 key（后续项），Go 空 map
        // 读取语义即空串。until P3。
        "HeaderNavModules": "",
        "SidebarModulesAdmin": "",
        // Go security OIDC/Passkey 未移植；零值 + 派生默认。
        "oidc_enabled": false,                       // Go defaultOIDCSettings 零值
        "oidc_client_id": "",                        // Go OIDCSettings 零值
        "oidc_authorization_endpoint": "",           // Go OIDCSettings 零值
        "oidc_display_name": DEFAULT_OIDC_DISPLAY_NAME, // GetEffectiveDisplayName 回退
        "passkey_login": false,                      // Go defaultPasskeySettings.Enabled
        "passkey_display_name": DEFAULT_PASSKEY_RP_DISPLAY_NAME,
        "passkey_rp_id": DEFAULT_PASSKEY_RP_ID,
        "passkey_origins": DEFAULT_PASSKEY_ORIGINS,
        "passkey_allow_insecure": false,
        "passkey_user_verification": DEFAULT_PASSKEY_USER_VERIFICATION,
        "passkey_attachment": "",
        // Go constant.Setup（setup.go:3）默认 false；安装向导未移植，恒为 false。
        "setup": false,
        // 真实值：PublicConfig 快照 → Go legalSetting 联动语义
        // （`UserAgreement != ""` / `PrivacyPolicy != ""`，handle_misc.go:124-125）。
        "user_agreement_enabled": !public.user_agreement.is_empty(),
        "privacy_policy_enabled": !public.privacy_policy.is_empty(),
        // Go billing.GetCheckinSetting().Enabled 默认 false（do_checkin_setting.go:30）。until P7。
        "checkin_enabled": false,
        // Go billing.GetQuotaSetting().EmptyResponseMultiplier 默认 0.1
        // （consume_quota_setting.go:13）。until P7。
        "empty_response_multiplier": 0.1,
    });

    // Go 按 enabled 才注入可选内容（handle_misc.go:131-139）。启用位为 Go 默认
    // true，而内容子系统未移植——Go 的 `getJSONList("")` 同样是空数组，因此
    // 此处注入空数组与 Go 未配置状态逐字节一致。P3 填充真实内容。
    // `uptime_kuma_enabled` 在 Go 中只输出开关，不注入内容（无对应 data key）。
    let data = body.as_object_mut().expect("json! literal must be a map");
    if DEFAULT_API_INFO_ENABLED {
        data.insert("api_info".to_owned(), json!([]));
    }
    if DEFAULT_ANNOUNCEMENTS_ENABLED {
        data.insert("announcements".to_owned(), json!([]));
    }
    if DEFAULT_FAQ_ENABLED {
        data.insert("faq".to_owned(), json!([]));
    }
    // Go 仅在存在已启用自定义 OAuth provider 时注入该 key；子系统未移植恒为空
    // （`oauth.GetEnabledCustomProviders()` 无数据来源），因此与 Go 空态一致：
    // 不输出该字段。until security/oauth 移植。

    json!({
        "success": true,
        "message": "",
        "data": data,
    })
}

/// HTTP 入口；由主控在 `http.rs` 注册为 `get(crate::status::handle)`。
/// Go 该路由不挂 `DisableCache`，故此处不设缓存头；`c.JSON` → `Json`（200 +
/// application/json）。
pub async fn handle(State(state): State<AppState>) -> Json<Value> {
    Json(status_body(&state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use newapi_storage::Database;

    /// 建最小 options 表并注入 key/value，走真实 `AppState::initialize`，
    /// 让快照注入在单测里可验证（与 state.rs 测试同款形状）。
    async fn state_with_options(options: &[(&str, &str)]) -> AppState {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(r#"CREATE TABLE options ("key" TEXT PRIMARY KEY, "value" TEXT)"#)
            .execute(&pool)
            .await
            .unwrap();
        for &(key, value) in options {
            sqlx::query(r#"INSERT INTO options ("key", "value") VALUES (?, ?)"#)
                .bind(key)
                .bind(value)
                .execute(&pool)
                .await
                .unwrap();
        }
        let db = Database::Sqlite(pool);
        AppState::initialize(&db).await.unwrap()
    }

    fn default_data() -> Value {
        status_body(&AppState::default())
    }

    #[test]
    fn envelope_has_exactly_three_contract_keys() {
        let body = default_data();
        let envelope = body.as_object().unwrap();
        assert_eq!(envelope.len(), 3);
        assert_eq!(envelope["success"], Value::Bool(true));
        assert_eq!(envelope["message"], Value::String(String::new()));
        assert!(envelope["data"].is_object());
    }

    #[test]
    fn default_data_matches_go_runtime_defaults() {
        let data = default_data()["data"].clone();
        // 版本与主题：version 非空、与 crate 版本一致；theme 硬编码 default。
        assert_eq!(
            data["version"],
            Value::String(env!("CARGO_PKG_VERSION").into())
        );
        assert_eq!(data["theme"], "default");
        assert!(data["start_time"].as_i64().unwrap() > 0);
        // AuthSettings 默认（password 开、email 关、turnstile 关）。
        assert_eq!(data["email_verification"], Value::Bool(false));
        assert_eq!(data["password_login_enabled"], Value::Bool(true));
        assert_eq!(data["password_register_enabled"], Value::Bool(true));
        assert_eq!(data["register_enabled"], Value::Bool(true));
        assert_eq!(data["turnstile_check"], Value::Bool(false));
        assert_eq!(data["turnstile_site_key"], "");
        // PublicConfig 空串 → 法务联动为 false。
        assert_eq!(data["user_agreement_enabled"], Value::Bool(false));
        assert_eq!(data["privacy_policy_enabled"], Value::Bool(false));
        // 未移植 OAuth / 安全子系统全为禁用默认。
        for key in [
            "github_oauth",
            "discord_oauth",
            "linuxdo_oauth",
            "telegram_oauth",
            "wechat_login",
            "oidc_enabled",
            "passkey_login",
            "setup",
            "checkin_enabled",
            "demo_site_enabled",
            "self_use_mode_enabled",
            "default_use_auto_group",
            "display_group_ratio_table",
            "default_collapse_sidebar",
            "mj_notify_enabled",
        ] {
            assert_eq!(
                data[key],
                Value::Bool(false),
                "{key} must default to disabled"
            );
        }
        assert_eq!(data["oidc_display_name"], "OIDC");
        assert_eq!(data["passkey_user_verification"], "preferred");
        // QuotaDisplay 默认 = USD 展示。
        assert_eq!(data["quota_display_type"], "USD");
        assert_eq!(data["display_in_currency"], Value::Bool(true));
        assert_eq!(data["usd_exchange_rate"], 7.3);
        assert_eq!(data["custom_currency_exchange_rate"], 1.0);
        // usage 控制台开关 Go 默认全 true，且注入空数组内容。
        for key in [
            "api_info_enabled",
            "uptime_kuma_enabled",
            "announcements_enabled",
            "faq_enabled",
        ] {
            assert_eq!(
                data[key],
                Value::Bool(true),
                "{key} defaults to enabled in Go"
            );
        }
        assert_eq!(data["api_info"], json!([]));
        assert_eq!(data["announcements"], json!([]));
        assert_eq!(data["faq"], json!([]));
        // 子系统默认值台账抽查。
        assert_eq!(data["server_address"], "http://localhost:3000");
        assert_eq!(data["system_name"], "New API");
        assert_eq!(data["docs_link"], "https://docs.newapi.pro");
        assert_eq!(data["price"], 7.3);
        assert_eq!(data["stripe_unit_price"], 8.0);
        assert_eq!(data["amount_unit"], "usd");
        assert_eq!(data["data_export_default_time"], "hour");
        assert_eq!(data["enable_drawing"], Value::Bool(true));
        assert_eq!(data["enable_task"], Value::Bool(true));
        assert_eq!(data["enable_data_export"], Value::Bool(true));
        assert_eq!(data["empty_response_multiplier"], 0.1);
        assert_eq!(data["chats"], default_chats());
        // Go 仅在自定义 provider 非空时注入该 key；此处必须缺席。
        assert!(data.get("custom_oauth_providers").is_none());
    }

    #[test]
    fn start_time_is_stable_across_calls() {
        assert_eq!(start_time(), start_time());
    }

    #[tokio::test]
    async fn snapshot_values_pass_through_to_status_body() {
        let state = state_with_options(&[
            ("PasswordLoginEnabled", "false"),
            ("EmailVerificationEnabled", "true"),
            ("RegisterEnabled", "false"),
            ("TurnstileCheckEnabled", "true"),
            ("TurnstileSiteKey", "site-key-123"),
            ("legal.user_agreement", "the terms"),
            ("general_setting.quota_display_type", "TOKENS"),
        ])
        .await;
        let data = status_body(&state)["data"].clone();
        // AuthSettings 真实值透传（缺 privacy_policy 行 → 仍为 false）。
        assert_eq!(data["password_login_enabled"], Value::Bool(false));
        assert_eq!(data["email_verification"], Value::Bool(true));
        assert_eq!(data["register_enabled"], Value::Bool(false));
        assert_eq!(data["turnstile_check"], Value::Bool(true));
        assert_eq!(data["turnstile_site_key"], "site-key-123");
        // PublicConfig 非空 → 联动为 true；缺失/空仍为 false。
        assert_eq!(data["user_agreement_enabled"], Value::Bool(true));
        assert_eq!(data["privacy_policy_enabled"], Value::Bool(false));
        // QuotaDisplay 真实值：TOKENS → 非货币展示。
        assert_eq!(data["quota_display_type"], "TOKENS");
        assert_eq!(data["display_in_currency"], Value::Bool(false));
    }

    #[tokio::test]
    async fn cny_display_reports_snapshot_exchange_rate() {
        let state = state_with_options(&[
            ("general_setting.quota_display_type", "CNY"),
            ("USDExchangeRate", "6.5"),
        ])
        .await;
        let data = status_body(&state)["data"].clone();
        assert_eq!(data["quota_display_type"], "CNY");
        assert_eq!(data["display_in_currency"], Value::Bool(true));
        // CNY 快照携带汇率 → 输出真实值而不是 7.3 默认。
        assert_eq!(data["usd_exchange_rate"], 6.5);
    }
}
