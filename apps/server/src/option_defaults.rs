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

// DEFAULT_MODEL_RATIO / format_matching_model_name / hardcoded_completion_ratio
// 已迁移到 `newapi_catalog::ratio_settings`（定价引擎切片），此处 re-export
// 保持既有调用点与测试不变。
pub(crate) use newapi_catalog::ratio_settings::{
    DEFAULT_MODEL_RATIO, format_matching_model_name, hardcoded_completion_ratio,
};

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

/// Go `GetCompletionRatioInfo`（`configure_model_ratio.go:458-500`）：覆盖层
/// （`CompletionRatio` 选项解析出的 map）优先于内置级联；`/` 分隔的模型名
/// 只查覆盖层。`locked` 表示管理员不可覆盖。
pub(crate) fn completion_ratio_info(
    name: &str,
    override_map: &BTreeMap<String, f64>,
) -> (f64, bool) {
    let formatted = format_matching_model_name(name);
    if formatted.contains('/')
        && let Some(ratio) = override_map.get(&formatted)
    {
        return (*ratio, false);
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
        assert!(json.contains("\"glm-4v\":3.4246575342465757"));
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
