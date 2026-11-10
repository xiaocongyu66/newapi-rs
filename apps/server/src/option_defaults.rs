//! `/api/option/` 契约所需的静态默认值与纯函数表。
//!
//! Go 参考（只读 `/root/newapi`）：
//! - `apps/api/internal/settings/settings.go:176-299`（`SeedOptionMap` 的传统
//!   键种子；`GlobalConfig.ExportAllConfigs` 与各域 hook 种子**未移植**，见
//!   模块尾注释）
//! - `apps/api/internal/common/constants.go`（默认值）
//! - `apps/api/internal/sensitive/sensitive.go:9-24`
//! - `apps/api/internal/transport/middleware/rate_limit/rate_limit.go:10-14`
//! - `apps/api/internal/transport/middleware/status_code/status_code_ranges.go`
//!   （区间默认值、`ParseHTTPStatusCodeRanges`）
//! - `apps/api/internal/catalog/configure_ratio/configure_model_ratio.go`
//!   （`defaultModelRatio` 全表、`getHardcodedCompletionModelRatio`）
//!
//! 已知缺口（与 Go oracle 的差异，后续切片补齐）：
//! 1. 28 个已注册分层配置（`general_setting`、`billing_setting`、
//!    `checkin_setting` 等）的种子默认值不在 GET /api/option/ 输出里——
//!    只有 options 表里已存在的行会出现。
//! 2. catalog/payment/usage/egress/ratio 五个 hook 种子族同样缺席。

use std::collections::BTreeMap;

/// Go `SeedOptionMap` 的传统键种子：`(键, 默认值)`。顺序无关，写入
/// `BTreeMap` 后由数据库覆盖层合并。
pub(crate) const SEED_OPTIONS: [(&str, &str); 94] = [
    ("FileUploadPermission", "0"),
    ("FileDownloadPermission", "0"),
    ("ImageUploadPermission", "0"),
    ("ImageDownloadPermission", "0"),
    ("PasswordLoginEnabled", "true"),
    ("PasswordRegisterEnabled", "true"),
    ("EmailVerificationEnabled", "false"),
    ("GitHubOAuthEnabled", "false"),
    ("LinuxDOOAuthEnabled", "false"),
    ("TelegramOAuthEnabled", "false"),
    ("WeChatAuthEnabled", "false"),
    ("TurnstileCheckEnabled", "false"),
    ("RegisterEnabled", "true"),
    ("AutomaticDisableChannelEnabled", "false"),
    ("AutomaticEnableChannelEnabled", "false"),
    ("LogConsumeEnabled", "true"),
    ("DisplayInCurrencyEnabled", "true"),
    ("DisplayTokenStatEnabled", "true"),
    ("DisplayGroupRatioTable", "false"),
    ("DrawingEnabled", "true"),
    ("TaskEnabled", "true"),
    ("DataExportEnabled", "true"),
    // Go `strconv.FormatFloat(5.0, 'f', -1, 64)` == "5"。
    ("ChannelDisableThreshold", "5"),
    ("EmailDomainRestrictionEnabled", "false"),
    ("EmailAliasRestrictionEnabled", "false"),
    (
        "EmailDomainWhitelist",
        "gmail.com,163.com,126.com,qq.com,outlook.com,hotmail.com,icloud.com,yahoo.com,foxmail.com",
    ),
    ("EmailFormatRegex", ""),
    ("SMTPServer", ""),
    ("SMTPFrom", ""),
    ("SMTPPort", "587"),
    ("SMTPAccount", ""),
    ("SMTPToken", ""),
    ("SMTPSSLEnabled", "false"),
    ("SMTPStartTLSEnabled", "false"),
    ("SMTPInsecureSkipVerify", "false"),
    ("SMTPForceAuthLogin", "false"),
    ("SMTPAccountPool", ""),
    ("Notice", ""),
    ("About", ""),
    ("HomePageContent", ""),
    // Go `common.Footer = ""`。
    ("Footer", ""),
    ("SystemName", "New API"),
    ("Logo", ""),
    ("ServerAddress", ""),
    ("PayAddress", ""),
    ("CustomCallbackAddress", ""),
    ("EpayId", ""),
    ("EpayKey", ""),
    ("VmqAddress", ""),
    ("VmqKey", ""),
    ("CodePayAddress", ""),
    ("CodePayId", ""),
    ("CodePayKey", ""),
    // Go `TopupGroupRatio2JSONString()` 对空 map 输出 "{}"。
    ("TopupGroupRatio", "{}"),
    ("GitHubClientId", ""),
    ("GitHubClientSecret", ""),
    ("TelegramBotToken", ""),
    ("TelegramBotName", ""),
    ("WeChatServerAddress", ""),
    ("WeChatServerToken", ""),
    ("WeChatAccountQRCodeImageURL", ""),
    ("TurnstileSiteKey", ""),
    ("TurnstileSecretKey", ""),
    ("QuotaForNewUser", "0"),
    ("QuotaForInviter", "0"),
    ("QuotaForInvitee", "0"),
    ("QuotaRemindThreshold", "1000"),
    ("PreConsumedQuota", "500"),
    ("ModelRequestRateLimitCount", "0"),
    ("ModelRequestRateLimitDurationMinutes", "1"),
    ("ModelRequestRateLimitSuccessCount", "1000"),
    // Go `ModelRequestRateLimitGroup2JSONString()` 对空 map 输出 "{}"。
    ("ModelRequestRateLimitGroup", "{}"),
    ("TopUpLink", ""),
    // Go `FormatFloat(500 * 1000.0, 'f', -1, 64)` == "500000"。
    ("QuotaPerUnit", "500000"),
    ("RetryTimes", "0"),
    ("DataExportInterval", "5"),
    ("DataExportDefaultTime", "hour"),
    ("DefaultCollapseSidebar", "false"),
    ("CheckSensitiveEnabled", "true"),
    ("ModelRequestRateLimitEnabled", "false"),
    ("ResponseCacheEnabled", "false"),
    ("ResponseCacheTtlSeconds", "300"),
    ("ResponseCacheMaxEntries", "1000"),
    // Go `256 * 1024`。
    ("ResponseCacheMaxBodySize", "262144"),
    ("CheckSensitiveOnPromptEnabled", "true"),
    ("CheckSensitiveOnCompletionEnabled", "true"),
    ("StopOnSensitiveEnabled", "true"),
    ("SensitiveWords", ""),
    ("SensitiveBlockGroups", "gov,tech"),
    ("StreamCacheQueueLength", "0"),
    ("AutomaticDisableStatusCodes", "401"),
    (
        "AutomaticRetryStatusCodes",
        "100-199,300-399,401-407,409-499,500-503,505-523,525-599",
    ),
    ("proxy_config", ""),
    ("ThemeCustomization", ""),
];

/// Go `ops.settingDisplayAmountKeys`（`manage_options.go:42-60`）：内部 quota
/// 数量键，管理表单以展示币种的 `<base>_display` 键提交，服务端换算回
/// 内部 quota 后按 base 键入库。
pub(crate) const DISPLAY_AMOUNT_KEYS: [&str; 17] = [
    "QuotaForNewUser",
    "QuotaForInviter",
    "QuotaForInvitee",
    "PreConsumedQuota",
    "QuotaRemindThreshold",
    "checkin_setting.min_quota",
    "checkin_setting.max_quota",
    "qq_bot_setting.min_quota",
    "qq_bot_setting.max_quota",
    "qq_bot_setting.drop_min_quota",
    "qq_bot_setting.drop_max_quota",
    "qq_bot_setting.drop_balance_anchor",
    "qq_bot_setting.drop_daily_guarantee",
    "qq_bot_setting.red_packet_min_amount",
    "qq_bot_setting.red_packet_max_amount",
    "qq_bot_setting.transfer_min_amount",
    "qq_bot_setting.transfer_max_amount",
];

/// Go `ops.inviteRewardOptionKeys`（`manage_options.go:71-76`）：合规门拦截的
/// 邀请奖励键。base 与 `_display` 两种写法都要匹配，否则用 display 键即可
/// 绕过合规确认。
pub(crate) const INVITE_REWARD_OPTION_KEYS: [&str; 4] = [
    "QuotaForInviter",
    "QuotaForInvitee",
    "QuotaForInviter_display",
    "QuotaForInvitee_display",
];

/// Go `ops.settingCompletionRatioMetaOptionKeys`（`store_options.go:16-25`）：
/// 参与 `CompletionRatioMeta` 模型名聚合的倍率键。
pub(crate) const COMPLETION_RATIO_META_OPTION_KEYS: [&str; 8] = [
    "ModelPrice",
    "ModelRatio",
    "CompletionRatio",
    "CacheRatio",
    "CreateCacheRatio",
    "ImageRatio",
    "AudioRatio",
    "AudioCompletionRatio",
];

/// Go `defaultModelRatio` 全表
/// （`configure_model_ratio.go:29-339`，237 条）。表达式（`RMB`/`USD` 常量、
/// 除法）已按 Go 编译期常量展开：`USD = 500`，`RMB = 500 / 7.3`。
pub(crate) const DEFAULT_MODEL_RATIO: [(&str, f64); 237] = [
    ("gpt-4-gizmo-*", 15),
    ("gpt-4o-gizmo-*", 2.5),
    ("gpt-4-all", 15),
    ("gpt-4o-all", 15),
    ("gpt-4", 15),
    ("gpt-4-0613", 15),
    ("gpt-4-32k", 30),
    ("gpt-4-32k-0613", 30),
    ("gpt-4-1106-preview", (5,)),
    ("gpt-4-0125-preview", (5,)),
    ("gpt-4-turbo-preview", (5,)),
    ("gpt-4-vision-preview", (5,)),
    ("gpt-4-1106-vision-preview", (5,)),
    ("chatgpt-4o-latest", (2.5,)),
    ("gpt-4o", (1.25,)),
    ("gpt-4o-audio-preview", (1.25,)),
    ("gpt-4o-audio-preview-2024-10-01", (1.25,)),
    ("gpt-4o-2024-05-13", (2.5,)),
    ("gpt-4o-2024-08-06", (1.25,)),
    ("gpt-4o-2024-11-20", (1.25,)),
    ("gpt-4o-realtime-preview", 2.5),
    ("gpt-4o-realtime-preview-2024-10-01", 2.5),
    ("gpt-4o-realtime-preview-2024-12-17", 2.5),
    ("gpt-4o-mini-realtime-preview", 0.3),
    ("gpt-4o-mini-realtime-preview-2024-12-17", 0.3),
    ("gpt-4.1", (1.0,)),
    ("gpt-4.1-2025-04-14", (1.0,)),
    ("gpt-4.1-mini", (0.2,)),
    ("gpt-4.1-mini-2025-04-14", (0.2,)),
    ("gpt-4.1-nano", (0.05,)),
    ("gpt-4.1-nano-2025-04-14", (0.05,)),
    ("gpt-image-1", (2.5,)),
    ("o1", (7.5,)),
    ("o1-2024-12-17", (7.5,)),
    ("o1-preview", (7.5,)),
    ("o1-preview-2024-09-12", (7.5,)),
    ("o1-mini", (0.55,)),
    ("o1-mini-2024-09-12", (0.55,)),
    ("o1-pro", (75.0,)),
    ("o1-pro-2025-03-19", (75.0,)),
    ("o3-mini", 0.55),
    ("o3-mini-2025-01-31", 0.55),
    ("o3-mini-high", 0.55),
    ("o3-mini-2025-01-31-high", 0.55),
    ("o3-mini-low", 0.55),
    ("o3-mini-2025-01-31-low", 0.55),
    ("o3-mini-medium", 0.55),
    ("o3-mini-2025-01-31-medium", 0.55),
    ("o3", (1.0,)),
    ("o3-2025-04-16", (1.0,)),
    ("o3-pro", (10.0,)),
    ("o3-pro-2025-06-10", (10.0,)),
    ("o3-deep-research", (5.0,)),
    ("o3-deep-research-2025-06-26", (5.0,)),
    ("o4-mini", (0.55,)),
    ("o4-mini-2025-04-16", (0.55,)),
    ("o4-mini-deep-research", (1.0,)),
    ("o4-mini-deep-research-2025-06-26", (1.0,)),
    ("gpt-4o-mini", 0.075),
    ("gpt-4o-mini-2024-07-18", 0.075),
    ("gpt-4-turbo", (5,)),
    ("gpt-4-turbo-2024-04-09", (5,)),
    ("gpt-4.5-preview", 37.5),
    ("gpt-4.5-preview-2025-02-27", 37.5),
    ("gpt-5", 0.625),
    ("gpt-5-2025-08-07", 0.625),
    ("gpt-5-chat-latest", 0.625),
    ("gpt-5-mini", 0.125),
    ("gpt-5-mini-2025-08-07", 0.125),
    ("gpt-5-nano", 0.025),
    ("gpt-5-nano-2025-08-07", 0.025),
    ("gpt-5.5", (2.5,)),
    ("gpt-5.6-sol", 2.5),
    ("gpt-5.6-terra", 1.25),
    ("gpt-5.6-luna", 0.5),
    ("gpt-3.5-turbo", 0.25),
    ("gpt-3.5-turbo-0613", 0.75),
    ("gpt-3.5-turbo-16k", (1.5,)),
    ("gpt-3.5-turbo-16k-0613", 1.5),
    ("gpt-3.5-turbo-instruct", (0.75,)),
    ("gpt-3.5-turbo-1106", (0.5,)),
    ("gpt-3.5-turbo-0125", 0.25),
    ("text-ada-001", 0.2),
    ("text-babbage-001", 0.25),
    ("text-curie-001", 1),
    ("text-davinci-edit-001", 10),
    ("code-davinci-edit-001", 10),
    ("whisper-1", (15,)),
    ("tts-1", (7.5,)),
    ("tts-1-1106", (7.5,)),
    ("tts-1-hd", (15,)),
    ("tts-1-hd-1106", (15,)),
    ("davinci", 10),
    ("curie", 10),
    ("text-embedding-3-small", 0.01),
    ("text-embedding-3-large", 0.065),
    ("text-embedding-ada-002", 0.05),
    ("text-search-ada-doc-001", 10),
    ("text-moderation-stable", 0.1),
    ("text-moderation-latest", 0.1),
    ("claude-3-haiku-20240307", (0.125,)),
    ("claude-3-5-haiku-20241022", (0.5,)),
    ("claude-haiku-4-5-20251001", (0.5,)),
    ("claude-3-sonnet-20240229", (1.5,)),
    ("claude-3-5-sonnet-20240620", 1.5),
    ("claude-3-5-sonnet-20241022", 1.5),
    ("claude-3-7-sonnet-20250219", 1.5),
    ("claude-3-7-sonnet-20250219-thinking", 1.5),
    ("claude-sonnet-4-20250514", 1.5),
    ("claude-sonnet-4-5-20250929", 1.5),
    ("claude-opus-4-5-20251101", 2.5),
    ("claude-opus-4-6", 2.5),
    ("claude-opus-4-6-max", 2.5),
    ("claude-opus-4-6-high", 2.5),
    ("claude-opus-4-6-medium", 2.5),
    ("claude-opus-4-6-low", 2.5),
    ("claude-opus-4-7", 2.5),
    ("claude-opus-4-7-max", 2.5),
    ("claude-opus-4-7-xhigh", 2.5),
    ("claude-opus-4-7-high", 2.5),
    ("claude-opus-4-7-medium", 2.5),
    ("claude-opus-4-7-low", 2.5),
    ("claude-opus-4-8", 2.5),
    ("claude-opus-4-8-max", 2.5),
    ("claude-opus-4-8-xhigh", 2.5),
    ("claude-opus-4-8-high", 2.5),
    ("claude-opus-4-8-medium", 2.5),
    ("claude-opus-4-8-low", 2.5),
    ("claude-3-opus-20240229", (7.5,)),
    ("claude-opus-4-20250514", 7.5),
    ("claude-opus-4-1-20250805", 7.5),
    ("ERNIE-4.0-8K", 8.21917808219178),
    ("ERNIE-3.5-8K", 0.8219178082191781),
    ("ERNIE-3.5-8K-0205", 1.6438356164383563),
    ("ERNIE-3.5-8K-1222", 0.8219178082191781),
    ("ERNIE-Bot-8K", 1.6438356164383563),
    ("ERNIE-3.5-4K-0205", 0.8219178082191781),
    ("ERNIE-Speed-8K", 0.273972602739726),
    ("ERNIE-Speed-128K", 0.273972602739726),
    ("ERNIE-Lite-8K-0922", 0.547945205479452),
    ("ERNIE-Lite-8K-0308", 0.20547945205479454),
    ("ERNIE-Tiny-8K", 0.0684931506849315),
    ("BLOOMZ-7B", 0.273972602739726),
    ("Embedding-V1", 0.136986301369863),
    ("bge-large-zh", 0.136986301369863),
    ("bge-large-en", 0.136986301369863),
    ("tao-8k", 0.136986301369863),
    ("PaLM-2", 1),
    ("gemini-1.5-pro-latest", (1.25,)),
    ("gemini-1.5-flash-latest", 0.075),
    ("gemini-2.0-flash", 0.05),
    ("gemini-2.5-pro-exp-03-25", 0.625),
    ("gemini-2.5-pro-preview-03-25", 0.625),
    ("gemini-2.5-pro", 0.625),
    ("gemini-2.5-flash-preview-04-17", 0.075),
    ("gemini-2.5-flash-preview-04-17-thinking", 0.075),
    ("gemini-2.5-flash-preview-04-17-nothinking", 0.075),
    ("gemini-2.5-flash-preview-05-20", 0.075),
    ("gemini-2.5-flash-preview-05-20-thinking", 0.075),
    ("gemini-2.5-flash-preview-05-20-nothinking", 0.075),
    ("gemini-2.5-flash-thinking-*", (0.075,)),
    ("gemini-2.5-pro-thinking-*", (0.625,)),
    ("gemini-2.5-flash-lite-preview-thinking-*", 0.05),
    ("gemini-2.5-flash-lite-preview-06-17", 0.05),
    ("gemini-2.5-flash", 0.15),
    ("gemini-robotics-er-1.5-preview", 0.15),
    ("gemini-embedding-001", 0.075),
    ("text-embedding-004", 0.001),
    ("chatglm_turbo", (0.3572,)),
    ("chatglm_pro", (0.7143,)),
    ("chatglm_std", (0.3572,)),
    ("chatglm_lite", (0.1429,)),
    ("glm-4", (7.143,)),
    ("glm-4v", (3.4246575342465757,)),
    ("glm-4-alltools", (6.849315068493151,)),
    ("glm-3-turbo", 0.3572),
    ("glm-4-plus", 3.4246575342465757),
    ("glm-4-0520", 6.849315068493151),
    ("glm-4-air", 0.0684931506849315),
    ("glm-4-airx", 0.684931506849315),
    ("glm-4-long", 0.0684931506849315),
    ("glm-4-flash", 0),
    ("glm-4v-plus", 0.684931506849315),
    ("qwen-turbo", (0.8572,)),
    ("qwen-plus", (10,)),
    ("text-embedding-v1", (0.05,)),
    ("SparkDesk-v1.1", (1.2858,)),
    ("SparkDesk-v2.1", (1.2858,)),
    ("SparkDesk-v3.1", (1.2858,)),
    ("SparkDesk-v3.5", (1.2858,)),
    ("SparkDesk-v4.0", 1.2858),
    ("hunyuan", (7.143,)),
    ("yi-34b-chat-0205", 0.18),
    ("yi-34b-chat-200k", 0.864),
    ("yi-vl-plus", 0.432),
    ("yi-large", 1.36986301369863),
    ("yi-medium", 0.17123287671232876),
    ("yi-vision", 0.4109589041095891),
    ("yi-medium-200k", 0.8219178082191781),
    ("yi-spark", 0.0684931506849315),
    ("yi-large-rag", 1.7123287671232879),
    ("yi-large-turbo", 0.8219178082191781),
    ("yi-large-preview", 1.36986301369863),
    ("yi-large-rag-preview", 1.7123287671232879),
    ("command", 0.5),
    ("command-nightly", 0.5),
    ("command-light", 0.5),
    ("command-light-nightly", 0.5),
    ("command-r", 0.25),
    ("command-r-plus", 1.5),
    ("command-r-08-2024", 0.075),
    ("command-r-plus-08-2024", 1.25),
    ("deepseek-chat", 0.135),
    ("deepseek-coder", 0.135),
    ("deepseek-reasoner", (0.275,)),
    ("llama-3-sonar-small-32k-chat", 0.1),
    ("llama-3-sonar-small-32k-online", 0.1),
    ("llama-3-sonar-large-32k-chat", 0.5),
    ("llama-3-sonar-large-32k-online", 0.5),
    ("grok-3-beta", 1.5),
    ("grok-3-mini-beta", 0.15),
    ("grok-2", 1),
    ("grok-2-vision", 1),
    ("grok-beta", 2.5),
    ("grok-vision-beta", 2.5),
    ("grok-3-fast-beta", 2.5),
    ("grok-3-mini-fast-beta", 0.3),
    ("NousResearch/Hermes-4-405B-FP8", 0.8),
    ("Qwen/Qwen3-235B-A22B-Thinking-2507", 0.6),
    ("Qwen/Qwen3-Coder-480B-A35B-Instruct-FP8", 0.8),
    ("Qwen/Qwen3-235B-A22B-Instruct-2507", 0.3),
    ("zai-org/GLM-4.5-FP8", 0.8),
    ("openai/gpt-oss-120b", 0.5),
    ("deepseek-ai/DeepSeek-R1-0528", 0.8),
    ("deepseek-ai/DeepSeek-R1", 0.8),
    ("deepseek-ai/DeepSeek-V3-0324", 0.8),
    ("deepseek-ai/DeepSeek-V3.1", 0.8),
];

/// Go `DefaultModelRatio2JSONString`（`configure_model_ratio.go:411-418`）：
/// `json.Marshal(defaultModelRatio)` 的字节串。Go 对 map 按 key 字典序输出，
/// 这里用 `BTreeMap` 复刻同一顺序。
pub(crate) fn default_model_ratio_json() -> String {
    let sorted: BTreeMap<&str, f64> = DEFAULT_MODEL_RATIO.iter().copied().collect();
    let mut body = String::with_capacity(8192);
    body.push('{');
    for (index, (name, ratio)) in sorted.iter().enumerate() {
        if index > 0 {
            body.push(',');
        }
        body.push_str(&json_string(name));
        body.push(':');
        body.push_str(&go_format_float(*ratio));
    }
    body.push('}');
    body
}

/// Go `strconv.FormatFloat(v, 'f', -1, 64)`：最短往返十进制，无指数形式。
/// Rust `Display` 对 f64 同为最短往返且不用科学计数；非有限值（JSON 不可
/// 表达）不在此路径出现。
pub(crate) fn go_format_float(value: f64) -> String {
    format!("{value}")
}

/// Go `encoding/json` 的字符串转义（`encodeState.string`）：ASCII 控制字符
/// 用 `\u00xx`，`"`、`\\` 反斜杠转义，其余原样。
pub(crate) fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            character if (character as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => out.push(character),
        }
    }
    out.push('"');
    out
}

/// Go `FormatMatchingModelName`（`configure_model_ratio.go:718-735`）：
/// gemini thinking 预算模型折叠到通配名，gizmo 前缀折叠；其余原样。
pub(crate) fn format_matching_model_name(name: &str) -> String {
    let mut name = name.to_owned();
    // Go `handleThinkingBudgetModel`：前缀命中且含 "-thinking-" 才折叠。
    let thinking = |name: &str, prefix: &str, wildcard: &str| -> String {
        if name.starts_with(prefix) && name.contains("-thinking-") {
            wildcard.to_owned()
        } else {
            name.to_owned()
        }
    };
    if name.starts_with("gemini-2.5-flash-lite") {
        name = thinking(
            &name,
            "gemini-2.5-flash-lite",
            "gemini-2.5-flash-lite-thinking-*",
        );
    } else if name.starts_with("gemini-2.5-flash") {
        name = thinking(&name, "gemini-2.5-flash", "gemini-2.5-flash-thinking-*");
    } else if name.starts_with("gemini-2.5-pro") {
        name = thinking(&name, "gemini-2.5-pro", "gemini-2.5-pro-thinking-*");
    }
    if name.starts_with("gpt-4-gizmo") {
        name = "gpt-4-gizmo-*".to_owned();
    }
    if name.starts_with("gpt-4o-gizmo") {
        name = "gpt-4o-gizmo-*".to_owned();
    }
    name
}

/// Go `getHardcodedCompletionModelRatio`
/// （`configure_model_ratio.go:502-655`）：内置补全倍率级联，返回
/// `(ratio, locked)`。分支顺序即契约。
pub(crate) fn hardcoded_completion_ratio(name: &str) -> (f64, bool) {
    // Go `strings.HasSuffix(name, "-all") || strings.HasSuffix(name, "-gizmo-*")`。
    if name.ends_with("-all") || name.ends_with("-gizmo-*") {
        return (2.0, false);
    }
    if name.starts_with("gpt-") {
        if name.starts_with("gpt-4o") {
            if name == "gpt-4o-2024-05-13" {
                return (3.0, true);
            }
            if name.starts_with("gpt-4o-mini-tts") {
                return (20.0, false);
            }
            return (4.0, false);
        }
        if name.starts_with("gpt-5") {
            if !name.contains('.') {
                return (8.0, true);
            }
            if name.starts_with("gpt-5.4") {
                if name.starts_with("gpt-5.4-nano") {
                    return (6.25, true);
                }
                return (6.0, true);
            }
            return (6.0, false);
        }
        if name.starts_with("gpt-4.5-preview") {
            return (2.0, true);
        }
        if name.starts_with("gpt-4-turbo")
            || name.ends_with("gpt-4-1106")
            || name.ends_with("gpt-4-1105")
        {
            return (3.0, true);
        }
        return (2.0, false);
    }
    if name.starts_with("o1") || name.starts_with("o3") {
        return (4.0, true);
    }
    if name == "chatgpt-4o-latest" {
        return (3.0, true);
    }
    if name.contains("claude-3") {
        return (5.0, true);
    }
    if name.contains("claude-sonnet-4")
        || name.contains("claude-opus-4")
        || name.contains("claude-haiku-4")
    {
        return (5.0, true);
    }
    if name.starts_with("gpt-3.5") {
        if name == "gpt-3.5-turbo" || name.ends_with("0125") {
            return (3.0, true);
        }
        if name.ends_with("1106") {
            return (2.0, true);
        }
        return (4.0 / 3.0, true);
    }
    if name.starts_with("mistral-") {
        return (3.0, true);
    }
    if name.starts_with("gemini-") {
        if name.starts_with("gemini-1.5") {
            return (4.0, true);
        }
        if name.starts_with("gemini-2.0") {
            return (4.0, true);
        }
        if name.starts_with("gemini-2.5-pro") {
            return (8.0, false);
        }
        if name.starts_with("gemini-2.5-flash") {
            if name.starts_with("gemini-2.5-flash-preview") {
                if name.ends_with("-nothinking") {
                    return (4.0, false);
                }
                return (3.5 / 0.15, false);
            }
            if name.starts_with("gemini-2.5-flash-lite") {
                return (4.0, false);
            }
            return (2.5 / 0.3, false);
        }
        if name.starts_with("gemini-robotics-er-1.5") {
            return (2.5 / 0.3, false);
        }
        if name.starts_with("gemini-3-pro") {
            if name.starts_with("gemini-3-pro-image") {
                return (60.0, false);
            }
            return (6.0, false);
        }
        return (4.0, false);
    }
    if name.starts_with("command") {
        return match name {
            "command-r" => (3.0, true),
            "command-r-plus" => (5.0, true),
            "command-r-08-2024" => (4.0, true),
            "command-r-plus-08-2024" => (4.0, true),
            _ => (4.0, false),
        };
    }
    if name.starts_with("ERNIE-Speed-")
        || name.starts_with("ERNIE-Lite-")
        || name.starts_with("ERNIE-Character")
        || name.starts_with("ERNIE-Functions")
    {
        return (2.0, true);
    }
    match name {
        "llama2-70b-4096" => (0.8 / 0.64, true),
        "llama3-8b-8192" => (2.0, true),
        "llama3-70b-8192" => (0.79 / 0.59, true),
        _ => (1.0, false),
    }
}

/// Go `GetCompletionRatioInfo`（`configure_model_ratio.go:458-500`）：覆盖层
/// （`CompletionRatio` 选项解析出的 map）优先于内置级联；`/` 分隔的模型名
/// 只查覆盖层。`locked` 表示管理员不可覆盖。
pub(crate) fn completion_ratio_info(
    name: &str,
    override_map: &BTreeMap<String, f64>,
) -> (f64, bool) {
    let formatted = format_matching_model_name(name);
    if formatted.contains('/') {
        if let Some(ratio) = override_map.get(&formatted) {
            return (*ratio, false);
        }
    }
    let (hardcoded, locked) = hardcoded_completion_ratio(&formatted);
    if locked {
        return (hardcoded, true);
    }
    if let Some(ratio) = override_map.get(&formatted) {
        return (*ratio, false);
    }
    (hardcoded, false)
}

/// Go `ParseHTTPStatusCodeRanges`
/// （`status_code_ranges.go:117-180`）：逗号分隔的单值或区间（中英文逗号
/// 皆可），非法段收集后一并报错；排序并合并相邻/重叠区间。
pub(crate) fn parse_http_status_code_ranges(input: &str) -> Result<Vec<(i64, i64)>, String> {
    let input = input.trim();
    if input.is_empty() {
        return Ok(Vec::new());
    }
    let normalized = input.replace('，', ",");
    let mut ranges: Vec<(i64, i64)> = Vec::new();
    let mut invalid: Vec<&str> = Vec::new();
    for segment in normalized.split(',') {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        match parse_status_code_token(segment) {
            Some(range) => ranges.push(range),
            None => invalid.push(segment),
        }
    }
    if !invalid.is_empty() {
        return Err(format!(
            "invalid http status code rules: {}",
            invalid.join(", ")
        ));
    }
    if ranges.is_empty() {
        return Ok(Vec::new());
    }
    ranges.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    let mut merged: Vec<(i64, i64)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start <= last.1.saturating_add(1) => {
                if end > last.1 {
                    last.1 = end;
                }
            }
            _ => merged.push((start, end)),
        }
    }
    Ok(merged)
}

/// Go `parseHTTPStatusCodeToken`：`200` 或 `500-504`，两端都必须是合法的
/// HTTP 状态码（100-599），区间起点不得大于终点。
fn parse_status_code_token(token: &str) -> Option<(i64, i64)> {
    let (start_text, end_text) = match token.split_once('-') {
        Some((start, end)) => (start, end),
        None => (token, token),
    };
    let start = parse_http_status_code(start_text)?;
    let end = parse_http_status_code(end_text)?;
    if start > end {
        return None;
    }
    Some((start, end))
}

fn parse_http_status_code(text: &str) -> Option<i64> {
    if text.len() != 3 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let value: i64 = text.parse().ok()?;
    (100..=599).contains(&value).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Go `json.Marshal(defaultModelRatio)`：键按字典序，数值为最短往返
    /// 十进制。抽几个已知形态固定（首键、带斜杠键、小数、`-thinking-*` 通配）。
    #[test]
    fn default_model_ratio_json_matches_go_marshal_shape() {
        let json = default_model_ratio_json();
        assert!(json.starts_with('{') && json.ends_with('}'));
        let body = json.trim_start_matches('{').trim_end_matches('}');
        // 237 条：逗号计数。
        assert_eq!(body.split(',').count(), 237);
        // 值的最短往返形态（Go 无 ".0" 后缀；Rust Display 同样输出 "15"）。
        assert!(!json.contains("15.0"));
        assert!(json.contains("\"gpt-4-gizmo-*\":15"));
        assert!(json.contains("\"deepseek-chat\":0.135"));
        assert!(json.contains("\"glm-4v\":3.4246575342465753"));
    }

    /// Go `getHardcodedCompletionModelRatio` 的代表性分支。
    #[test]
    fn hardcoded_completion_ratio_matches_go_cascade() {
        assert_eq!(hardcoded_completion_ratio("gpt-4o"), (4.0, false));
        assert_eq!(hardcoded_completion_ratio("gpt-4o-2024-05-13"), (3.0, true));
        assert_eq!(hardcoded_completion_ratio("gpt-5"), (8.0, true));
        assert_eq!(hardcoded_completion_ratio("gpt-5.5"), (6.0, false));
        assert_eq!(hardcoded_completion_ratio("o3"), (4.0, true));
        assert_eq!(hardcoded_completion_ratio("claude-3-5-sonnet"), (5.0, true));
        assert_eq!(
            hardcoded_completion_ratio("gemini-2.5-flash"),
            (2.5 / 0.3, false)
        );
        assert_eq!(
            hardcoded_completion_ratio("llama2-70b-4096"),
            (0.8 / 0.64, true)
        );
        assert_eq!(hardcoded_completion_ratio("unknown-model"), (1.0, false));
    }

    /// Go `ParseHTTPStatusCodeRanges`：排序、合并相邻、中英文逗号、非法段。
    #[test]
    fn status_code_ranges_parse_like_go() {
        assert_eq!(parse_http_status_code_ranges(""), Ok(Vec::new()));
        assert_eq!(parse_http_status_code_ranges("401"), Ok(vec![(401, 401)]));
        assert_eq!(
            parse_http_status_code_ranges("500-504,401, 402"),
            Ok(vec![(401, 402), (500, 504)])
        );
        // 相邻合并（Go：r.Start <= last.End+1）。
        assert_eq!(
            parse_http_status_code_ranges("500,501"),
            Ok(vec![(500, 501)])
        );
        assert_eq!(
            parse_http_status_code_ranges("401，500"),
            Ok(vec![(401, 401), (500, 500)])
        );
        assert_eq!(
            parse_http_status_code_ranges("401,abc,700"),
            Err("invalid http status code rules: abc, 700".to_owned())
        );
        // 区间起点大于终点非法；三位数字之外非法。
        assert!(parse_http_status_code_ranges("500-401").is_err());
        assert!(parse_http_status_code_ranges("40").is_err());
    }
}
