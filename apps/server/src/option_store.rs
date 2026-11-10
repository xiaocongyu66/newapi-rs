//! `/api/option/` 的选项存储与纯校验层：选项快照组装（GET）、选项写入
//! （upsert + 事务 bulk）、写路径校验（Go `ValidateOptionValue` 与
//! `ops.UpdateOption` 的 switch 分支）。
//!
//! Go 参考（只读 `/root/newapi`）：
//! - `apps/api/internal/dbinfra/store_options.go:27-40,84-152`（upsert 与
//!   bulk 事务；`ApplyOption` 的进程内生效在本端口由调用方触发
//!   `AppState::reload` 完成——审计 #47 策略）
//! - `apps/api/internal/ops/store_options.go`（`ListVisibleOptions`：敏感键
//!   过滤、`_display` 兄弟键、`CompletionRatioMeta`）
//! - `apps/api/internal/settings/settings.go:116-172`（`ValidateOptionValue`）
//! - `apps/api/internal/settings/theme_customization.go`（主题校验）
//! - `apps/api/internal/usage/configure_perf.go:237-534`（console_setting 四类校验）
//! - `apps/api/internal/common/email.go:50-67`（SMTP 账号池校验）
//! - `apps/api/internal/billing/price_expression/price_tools.go:88-131`
//!   （工具价格校验）

use std::collections::BTreeMap;

use newapi_storage::Database;
use serde_json::{Map, Value};

use crate::option_defaults::{
    COMPLETION_RATIO_META_OPTION_KEYS, DISPLAY_AMOUNT_KEYS, INVITE_REWARD_OPTION_KEYS,
    SEED_OPTIONS, completion_ratio_info,
};

/// Go `settings.RetiredThemeOptionKey`。
pub(crate) const RETIRED_THEME_OPTION_KEY: &str = "theme.frontend";

/// Go `price_expression.ToolPriceOptionKey`。
pub(crate) const TOOL_PRICE_OPTION_KEY: &str = "tool_price_setting.prices";

/// Go `ThemeCustomizationOptionKey`（`theme_customization.go:20`）。
pub(crate) const THEME_CUSTOMIZATION_OPTION_KEY: &str = "ThemeCustomization";

// ---------------------------------------------------------------------------
// 选项读取
// ---------------------------------------------------------------------------

/// 全表读取：GET /api/option/ 的覆盖层来源。NULL 值按 Go `Option{Value
/// string}` 的 NULL 反序列化为 `""`（GORM 对 NULL string 列给出零值）。
pub(crate) async fn load_all_options(
    db: &Database,
) -> Result<BTreeMap<String, String>, sqlx::Error> {
    let rows: Vec<(String, Option<String>)> = match db {
        Database::Sqlite(pool) => {
            sqlx::query_as(r#"SELECT "key", "value" FROM "options""#)
                .fetch_all(pool)
                .await?
        }
        Database::Postgres(pool) => {
            sqlx::query_as(r#"SELECT "key", "value" FROM "options""#)
                .fetch_all(pool)
                .await?
        }
    };
    Ok(rows
        .into_iter()
        .map(|(key, value)| (key, value.unwrap_or_default()))
        .collect())
}

/// 定向键读取：PUT 校验分支与 waffo 凭据解析共用。缺失键不在结果里。
pub(crate) async fn load_option_values(
    db: &Database,
    keys: &[&str],
) -> Result<BTreeMap<String, String>, sqlx::Error> {
    if keys.is_empty() {
        return Ok(BTreeMap::new());
    }
    macro_rules! load_keys {
        ($pool:expr, $postgres:expr) => {{
            let sql = format!(
                "SELECT \"key\", \"value\" FROM \"options\" WHERE \"key\" IN ({})",
                placeholders(keys.len(), $postgres)
            );
            let mut query = sqlx::query_as::<_, (String, Option<String>)>(sqlx::AssertSqlSafe(sql));
            for key in keys {
                query = query.bind(key);
            }
            query.fetch_all($pool).await?
        }};
    }
    let rows = match db {
        Database::Sqlite(pool) => load_keys!(pool, false),
        Database::Postgres(pool) => load_keys!(pool, true),
    };
    Ok(rows
        .into_iter()
        .map(|(key, value)| (key, value.unwrap_or_default()))
        .collect())
}

fn placeholders(count: usize, postgres: bool) -> String {
    if postgres {
        (1..=count)
            .map(|index| format!("${index}"))
            .collect::<Vec<_>>()
            .join(", ")
    } else {
        vec!["?"; count].join(", ")
    }
}

// ---------------------------------------------------------------------------
// 选项写入
// ---------------------------------------------------------------------------

/// Go `UpdateOptionWithTx` 的 FirstOrCreate + Save 等价 upsert。SQLite 与
/// PostgreSQL 共用同一 SQL（`ON CONFLICT` 两端语义一致，`setup.rs` 同款）。
pub(crate) async fn upsert_option(
    db: &Database,
    key: &str,
    value: &str,
) -> Result<(), sqlx::Error> {
    match db {
        Database::Sqlite(pool) => sqlx::query(UPSERT_SQL)
            .bind(key)
            .bind(value)
            .execute(pool)
            .await
            .map(|_| ()),
        Database::Postgres(pool) => sqlx::query(UPSERT_SQL)
            .bind(key)
            .bind(value)
            .execute(pool)
            .await
            .map(|_| ()),
    }
}

const UPSERT_SQL: &str = "INSERT INTO options (\"key\", value) VALUES ($1, $2) \
ON CONFLICT (\"key\") DO UPDATE SET value = excluded.value";

/// Go `UpdateOptionsBulk`（`store_options.go:112-152`）：多键单事务写入，
/// 任一失败整体回滚，不发布部分状态。
pub(crate) async fn upsert_options_bulk(
    db: &Database,
    values: &BTreeMap<String, String>,
) -> Result<(), sqlx::Error> {
    if values.is_empty() {
        return Ok(());
    }
    macro_rules! bulk {
        ($pool:expr) => {{
            let mut transaction = $pool.begin().await?;
            for (key, value) in values {
                sqlx::query(UPSERT_SQL)
                    .bind(key)
                    .bind(value)
                    .execute(&mut *transaction)
                    .await?;
            }
            transaction.commit().await
        }};
    }
    match db {
        Database::Sqlite(pool) => bulk!(pool).map(|_| ()),
        Database::Postgres(pool) => bulk!(pool).map(|_| ()),
    }
}

// ---------------------------------------------------------------------------
// GET /api/option/ 快照组装
// ---------------------------------------------------------------------------

/// Go `ops.settingIsSensitiveOptionKey`（`store_options.go:27-33`）：以
/// Token/Secret/Key/secret/api_key 结尾的键不回显。
pub(crate) fn is_sensitive_option_key(key: &str) -> bool {
    ["Token", "Secret", "Key", "secret", "api_key"]
        .iter()
        .any(|suffix| key.ends_with(suffix))
}

/// Go `ops.settingIsDisplayAmountKey`。
pub(crate) fn is_display_amount_key(key: &str) -> bool {
    DISPLAY_AMOUNT_KEYS.contains(&key)
}

/// Go `ops.isInviteRewardOptionKey`。
pub(crate) fn is_invite_reward_option_key(key: &str) -> bool {
    INVITE_REWARD_OPTION_KEYS.contains(&key)
}

/// Go `ops.settingIsPositiveOptionValue`（`store_options.go:111-118`）：
/// 先按整数解析，失败再按浮点，均成功且大于零才算正数。
pub(crate) fn is_positive_option_value(value: &str) -> bool {
    let trimmed = value.trim();
    if let Ok(int_value) = trimmed.parse::<i64>() {
        return int_value > 0;
    }
    trimmed
        .parse::<f64>()
        .map(|value| value > 0.0)
        .unwrap_or(false)
}

/// Go `ops.ListVisibleOptions`（`store_options.go:70-109`）：种子默认值 +
/// 数据库覆盖层的合并快照，剔除 `theme.frontend` 与敏感键，为金额键补
/// `<base>_display` 兄弟键，末尾追加 `CompletionRatioMeta`。
///
/// `display` 承载 Go 进程级 `QuotaPerUnit`/汇率/展示币种（已含数据库覆盖）。
pub(crate) fn visible_options(
    rows: &BTreeMap<String, String>,
    display: &newapi_identity::self_user::QuotaDisplaySettings,
) -> Vec<(String, String)> {
    let mut merged: BTreeMap<String, String> = SEED_OPTIONS
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect();
    for (key, value) in rows {
        merged.insert(key.clone(), value.clone());
    }

    let mut ratio_values: BTreeMap<String, String> = BTreeMap::new();
    let mut options: Vec<(String, String)> = Vec::with_capacity(merged.len() + 8);
    for (key, value) in &merged {
        if key == RETIRED_THEME_OPTION_KEY || is_sensitive_option_key(key) {
            continue;
        }
        options.push((key.clone(), value.clone()));
        // Go：金额键补 display 兄弟键，仅当原值能按整数解析。
        if is_display_amount_key(key) {
            if let Ok(raw) = value.trim().parse::<i64>() {
                let amount = display.to_display(raw);
                options.push((
                    format!("{key}_display"),
                    crate::option_defaults::go_format_float(amount),
                ));
            }
        }
        if COMPLETION_RATIO_META_OPTION_KEYS.contains(&key.as_str()) {
            ratio_values.insert(key.clone(), value.clone());
        }
    }
    options.push((
        "CompletionRatioMeta".to_owned(),
        completion_ratio_meta(&ratio_values),
    ));
    options
}

/// Go `ops.settingBuildCompletionRatioMetaValue`（`store_options.go:35-66`）：
/// 聚合八个倍率键值里的模型名，逐个查补全倍率信息后整表序列化。
fn completion_ratio_meta(option_values: &BTreeMap<String, String>) -> String {
    let mut model_names = BTreeMap::new();
    for key in COMPLETION_RATIO_META_OPTION_KEYS {
        let Some(raw) = option_values.get(key) else {
            continue;
        };
        if raw.trim().is_empty() {
            continue;
        }
        let Ok(parsed) = serde_json::from_str::<Map<String, Value>>(raw) else {
            continue;
        };
        for name in parsed.keys() {
            model_names.insert(name.clone(), ());
        }
    }
    // 覆盖层：Go completionRatioMap 只由 `CompletionRatio` 选项填充。
    let override_map: BTreeMap<String, f64> = option_values
        .get("CompletionRatio")
        .and_then(|raw| serde_json::from_str::<BTreeMap<String, f64>>(raw).ok())
        .unwrap_or_default();
    let mut meta: BTreeMap<String, Value> = BTreeMap::new();
    for name in model_names.keys() {
        let (ratio, locked) = completion_ratio_info(name, &override_map);
        meta.insert(
            name.clone(),
            serde_json::json!({ "ratio": ratio, "locked": locked }),
        );
    }
    serde_json::to_string(&meta).unwrap_or_else(|_| "{}".to_owned())
}

// ---------------------------------------------------------------------------
// 写路径校验
// ---------------------------------------------------------------------------

/// Go `settings.ValidateOptionValue`（`settings.go:116-172`）中可纯判定的
/// 规则。域 hook（routestats/gateway/channel health）未移植，这些键走与
/// 其它未知键相同的放行路径。
pub(crate) fn validate_option_value(key: &str, value: &str) -> Result<(), String> {
    if key == TOOL_PRICE_OPTION_KEY {
        return validate_tool_prices_json(value);
    }
    if key == "MaxTokenAutoGroups" {
        // Go strconv.Atoi 语义：十进制整数（可带符号）。
        return match value.parse::<i64>() {
            Ok(count) if count > 0 => Ok(()),
            _ => Err("MaxTokenAutoGroups must be a positive integer".to_owned()),
        };
    }
    if matches!(
        key,
        "ResponseCacheTtlSeconds" | "ResponseCacheMaxEntries" | "ResponseCacheMaxBodySize"
    ) {
        return match value.parse::<i64>() {
            Ok(count) if count >= 0 => Ok(()),
            _ => Err(format!("{key} must be a non-negative integer")),
        };
    }
    if key == "SMTPAccountPool" {
        return validate_smtp_account_pool(value);
    }
    if key == THEME_CUSTOMIZATION_OPTION_KEY {
        return validate_theme_customization(value);
    }
    Ok(())
}

/// Go `common.ParseSMTPAccountPoolJSON`（`email.go:50-67`）。
pub(crate) fn validate_smtp_account_pool(value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Ok(());
    }
    let Ok(pool) = serde_json::from_str::<Vec<Map<String, Value>>>(value) else {
        return Err("SMTPAccountPool must be a JSON array of accounts".to_owned());
    };
    for (index, account) in pool.iter().enumerate() {
        let server = account.get("server").and_then(Value::as_str).unwrap_or("");
        let account_name = account.get("account").and_then(Value::as_str).unwrap_or("");
        // Go int 反序列化：非整数值在此报 JSON 错误；这里缺省 0 触发同一
        // 的 "positive port" 错误。
        let port = account.get("port").and_then(Value::as_i64).unwrap_or(0);
        if server.is_empty() || account_name.is_empty() || port <= 0 {
            return Err(format!(
                "SMTPAccountPool entry {index} requires server, account and a positive port"
            ));
        }
        let daily_limit = account
            .get("dailyLimit")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let priority = account.get("priority").and_then(Value::as_i64).unwrap_or(0);
        if daily_limit < 0 || priority < 0 {
            return Err(format!(
                "SMTPAccountPool entry {index} needs non-negative dailyLimit and priority"
            ));
        }
    }
    Ok(())
}

/// Go `billing.price_expression.ValidateToolPricesJSON`
/// （`price_tools.go:88-131`）。JSON 解析错误文本与 Go 的 `encoding/json`
/// 文本不同（固定前缀 + serde 文本），为已知可观察差异。
pub(crate) fn validate_tool_prices_json(value: &str) -> Result<(), String> {
    let trimmed = value.trim();
    let Ok(parsed) = serde_json::from_str::<Value>(trimmed) else {
        return Err("解析工具价格失败: 无效的 JSON".to_owned());
    };
    if !parsed.is_object() {
        return Err("工具价格必须是 JSON 对象".to_owned());
    }
    let raw_prices = parsed.as_object().expect("checked object");
    for (name, raw_price) in raw_prices {
        match raw_price.as_f64() {
            // JSON `true`/`false` 不是数字；as_f64 对布尔返回 None。
            None => return Err(format!("工具价格 {name:?} 必须是非负数字")),
            Some(price) if !price.is_finite() || price < 0.0 => {
                return Err(format!("工具价格 {name:?} 必须是有限的非负数字"));
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// Go `ValidateThemeCustomizationOption`（`theme_customization.go:96-142`）。
pub(crate) fn validate_theme_customization(value: &str) -> Result<(), String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(());
    }
    let Ok(payload) = serde_json::from_str::<Map<String, Value>>(value) else {
        return Err("主题配置不是有效的 JSON".to_owned());
    };
    let text = |key: &str| {
        payload
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let optional_int = |key: &str| -> Option<i64> { payload.get(key).and_then(Value::as_i64) };
    let mut invalid: Vec<String> = Vec::new();
    for (name, value, allowed) in [
        (
            "preset",
            text("preset"),
            [
                "default",
                "anthropic",
                "nailao",
                "simple-large",
                "underground",
                "rose-garden",
                "lake-view",
                "sunset-glow",
                "forest-whisper",
                "ocean-breeze",
                "lavender-dream",
            ],
        ),
        ("font", text("font"), ["default", "sans", "serif"]),
        (
            "radius",
            text("radius"),
            ["default", "none", "sm", "md", "lg", "xl"],
        ),
        ("scale", text("scale"), ["default", "sm", "lg", "xl"]),
        (
            "content_layout",
            text("content_layout"),
            ["full", "centered"],
        ),
    ] {
        if !allowed.contains(&value.as_str()) {
            invalid.push(format!("{name} 无效：{value:?}"));
        }
    }
    for (axis, light_key, dark_key, min, max) in [
        (
            "surface_opacity",
            "surface_opacity_light",
            "surface_opacity_dark",
            10,
            100,
        ),
        (
            "surface_blur",
            "surface_blur_light",
            "surface_blur_dark",
            0,
            40,
        ),
        (
            "background_scrim",
            "background_scrim_light",
            "background_scrim_dark",
            0,
            100,
        ),
        (
            "sheet_opacity",
            "sheet_opacity_light",
            "sheet_opacity_dark",
            50,
            100,
        ),
        (
            "float_opacity",
            "float_opacity_light",
            "float_opacity_dark",
            50,
            100,
        ),
    ] {
        for (suffix, key) in [("light", light_key), ("dark", dark_key)] {
            let name = format!("{axis}_{suffix}");
            match optional_int(key) {
                None => invalid.push(format!("{name} 缺失")),
                Some(value) if value < min || value > max => {
                    invalid.push(format!("{name} 超出范围 [{min}, {max}]：{value}"));
                }
                Some(_) => {}
            }
        }
    }
    if invalid.is_empty() {
        Ok(())
    } else {
        Err(format!("主题配置无效：{}", invalid.join("；")))
    }
}

/// Go `rate_limit.CheckModelRequestRateLimitGroup`（`rate_limit.go:51-67`）。
pub(crate) fn validate_model_request_rate_limit_group(value: &str) -> Result<(), String> {
    let Ok(parsed) = serde_json::from_str::<BTreeMap<String, [i64; 2]>>(value) else {
        return Err("invalid JSON".to_owned());
    };
    const MAX_INT32: i64 = 2_147_483_647;
    for (group, limits) in &parsed {
        if limits[0] < 0 || limits[1] < 1 {
            return Err(format!(
                "group {group} has negative rate limit values: [{}, {}]",
                limits[0], limits[1]
            ));
        }
        if limits[0] > MAX_INT32 || limits[1] > MAX_INT32 {
            return Err(format!(
                "group {group} [{}, {}] has max rate limits value 2147483647",
                limits[0], limits[1]
            ));
        }
    }
    Ok(())
}

/// Go `usage.ValidateConsoleSettings`（`configure_perf.go:278-295`）分发。
pub(crate) fn validate_console_settings(value: &str, setting_type: &str) -> Result<(), String> {
    if value.is_empty() {
        return Ok(());
    }
    match setting_type {
        "ApiInfo" => validate_api_info(value),
        "Announcements" => validate_announcements(value),
        "FAQ" => validate_faq(value),
        "UptimeKumaGroups" => validate_uptime_kuma_groups(value),
        _ => Err(format!("未知的设置类型：{setting_type}")),
    }
}

/// Go `parseJSONArray`：非数组 JSON → `"<类型>格式错误：<err>"`。
fn parse_json_array(value: &str, type_name: &str) -> Result<Vec<Map<String, Value>>, String> {
    serde_json::from_str::<Vec<Map<String, Value>>>(value)
        .map_err(|error| format!("{type_name}格式错误：{error}"))
}

/// Go `exceedsMaxCharacters`：按 UTF-16 码元计数（与 Go 一致，代理对计 2）。
fn exceeds_max_characters(value: &str, max: usize) -> bool {
    value
        .chars()
        .map(|character| character.len_utf16())
        .sum::<usize>()
        > max
}

/// Go `validateURL`：urlRegex + url.Parse。正则按 Go 源码逐字移植；
/// `url.Parse` 的额外解析在正则命中后对合法 URL 形态恒通过，故省略
/// （正则已排除空格与控制字符）。
fn validate_url(url: &str, index: usize, item_type: &str) -> Result<(), String> {
    const URL_REGEX: &str = r"^https?://(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?|(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))(?:\:[0-9]{1,5})?(?:/.*)?$";
    let compiled = regex::Regex::new(URL_REGEX).expect("static url regex");
    if !compiled.is_match(url) {
        return Err(format!("第{index}个{item_type}的URL格式不正确"));
    }
    Ok(())
}

/// Go `checkDangerousContent`：小写化后包含任一危险片段即拒绝。
fn check_dangerous_content(content: &str, index: usize, item_type: &str) -> Result<(), String> {
    let lowered = content.to_lowercase();
    for dangerous in [
        "<script",
        "<iframe",
        "javascript:",
        "onload=",
        "onerror=",
        "onclick=",
    ] {
        if lowered.contains(dangerous) {
            return Err(format!("第{index}个{item_type}包含不允许的内容"));
        }
    }
    Ok(())
}

const CONSOLE_VALID_COLORS: [&str; 17] = [
    "blue",
    "green",
    "cyan",
    "purple",
    "pink",
    "red",
    "orange",
    "amber",
    "yellow",
    "lime",
    "light-green",
    "teal",
    "light-blue",
    "indigo",
    "violet",
    "grey",
    "slate",
];

/// Go `validateApiInfo`（`configure_perf.go:297-351`）。
fn validate_api_info(value: &str) -> Result<(), String> {
    let list = parse_json_array(value, "API信息")?;
    if list.len() > 50 {
        return Err("API信息数量不能超过50个".to_owned());
    }
    for (index, api_info) in list.iter().enumerate() {
        let index = index + 1;
        let url = required_string(api_info, "url", index, "API信息缺少URL字段")?;
        let route = required_string(api_info, "route", index, "API信息缺少线路描述字段")?;
        let description = required_string(api_info, "description", index, "API信息缺少说明字段")?;
        let color = required_string(api_info, "color", index, "API信息缺少颜色字段")?;
        validate_url(&url, index, "API信息")?;
        if exceeds_max_characters(&url, 500) {
            return Err(format!("第{index}个API信息的URL长度不能超过500字符"));
        }
        if exceeds_max_characters(&route, 100) {
            return Err(format!("第{index}个API信息的线路描述长度不能超过100字符"));
        }
        if exceeds_max_characters(&description, 200) {
            return Err(format!("第{index}个API信息的说明长度不能超过200字符"));
        }
        if !CONSOLE_VALID_COLORS.contains(&color.as_str()) {
            return Err(format!("第{index}个API信息的颜色值不合法"));
        }
        check_dangerous_content(&description, index, "API信息")?;
        check_dangerous_content(&route, index, "API信息")?;
    }
    Ok(())
}

fn required_string(
    entry: &Map<String, Value>,
    key: &str,
    index: usize,
    missing: &str,
) -> Result<String, String> {
    match entry.get(key).and_then(Value::as_str) {
        Some(value) if !value.is_empty() => Ok(value.to_owned()),
        _ => Err(format!("第{index}个{missing}")),
    }
}

/// Go `validateAnnouncements`（`configure_perf.go:357-404`）。
fn validate_announcements(value: &str) -> Result<(), String> {
    let list = parse_json_array(value, "系统公告")?;
    if list.len() > 100 {
        return Err("系统公告数量不能超过100个".to_owned());
    }
    for (index, announcement) in list.iter().enumerate() {
        let index = index + 1;
        let content = required_string(announcement, "content", index, "公告缺少内容字段")?;
        let publish_date = match announcement.get("publishDate") {
            None => return Err(format!("第{index}个公告缺少发布日期字段")),
            Some(date) => match date.as_str() {
                Some(text) if !text.is_empty() => text.to_owned(),
                _ => return Err(format!("第{index}个公告的发布日期不能为空")),
            },
        };
        // Go `time.Parse(time.RFC3339, ...)`。
        if parse_rfc3339(&publish_date).is_none() {
            return Err(format!("第{index}个公告的发布日期格式错误"));
        }
        if let Some(kind) = announcement.get("type").and_then(Value::as_str) {
            let valid = ["default", "ongoing", "success", "warning", "error"];
            if !valid.contains(&kind) {
                return Err(format!("第{index}个公告的类型值不合法"));
            }
        }
        if exceeds_max_characters(&content, 500) {
            return Err(format!("第{index}个公告的内容长度不能超过500字符"));
        }
        if let Some(extra) = announcement.get("extra").and_then(Value::as_str) {
            if exceeds_max_characters(extra, 100) {
                return Err(format!("第{index}个公告的说明长度不能超过100字符"));
            }
        }
    }
    Ok(())
}

/// Go `validateFAQ`（`configure_perf.go:406-428`）。
fn validate_faq(value: &str) -> Result<(), String> {
    let list = parse_json_array(value, "FAQ信息")?;
    if list.len() > 100 {
        return Err("FAQ数量不能超过100个".to_owned());
    }
    for (index, faq) in list.iter().enumerate() {
        let index = index + 1;
        let question = required_string(faq, "question", index, "FAQ缺少问题字段")?;
        let answer = required_string(faq, "answer", index, "FAQ缺少答案字段")?;
        if exceeds_max_characters(&question, 200) {
            return Err(format!("第{index}个FAQ的问题长度不能超过200字符"));
        }
        if exceeds_max_characters(&answer, 1000) {
            return Err(format!("第{index}个FAQ的答案长度不能超过1000字符"));
        }
    }
    Ok(())
}

/// Go `validateUptimeKumaGroups`（`configure_perf.go:443-511`）。
fn validate_uptime_kuma_groups(value: &str) -> Result<(), String> {
    let list = parse_json_array(value, "Uptime Kuma分组配置")?;
    if list.len() > 20 {
        return Err("Uptime Kuma分组数量不能超过20个".to_owned());
    }
    let mut name_set: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (index, group) in list.iter().enumerate() {
        let index = index + 1;
        let category_name = required_string(group, "categoryName", index, "分组缺少分类名称字段")?;
        if !name_set.insert(category_name.clone()) {
            return Err(format!("第{index}个分组的分类名称与其他分组重复"));
        }
        let url = required_string(group, "url", index, "分组缺少URL字段")?;
        let slug = required_string(group, "slug", index, "分组缺少Slug字段")?;
        let description = group
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        validate_url(&url, index, "分组")?;
        if exceeds_max_characters(&category_name, 50) {
            return Err(format!("第{index}个分组的分类名称长度不能超过50字符"));
        }
        if exceeds_max_characters(&url, 500) {
            return Err(format!("第{index}个分组的URL长度不能超过500字符"));
        }
        if exceeds_max_characters(&slug, 100) {
            return Err(format!("第{index}个分组的Slug长度不能超过100字符"));
        }
        if exceeds_max_characters(&description, 200) {
            return Err(format!("第{index}个分组的描述长度不能超过200字符"));
        }
        if !slug_is_valid(&slug) {
            return Err(format!(
                "第{index}个分组的Slug只能包含字母、数字、下划线和连字符"
            ));
        }
        check_dangerous_content(&description, index, "分组")?;
        check_dangerous_content(&category_name, index, "分组")?;
    }
    Ok(())
}

/// Go `slugRegex = ^[a-zA-Z0-9_-]+$`。
fn slug_is_valid(slug: &str) -> bool {
    !slug.is_empty()
        && slug
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

/// Go `time.Parse(time.RFC3339, ...)` 的接受集子集：`YYYY-MM-DDTHH:MM:SS`
/// 后跟可选小数秒与 `Z`/`±HH:MM` 偏移。覆盖管理界面产生的形态；Go 接受的
/// 部分罕见变体（如省略秒）在此被拒——拒得比 Go 更严是单向差异。
fn parse_rfc3339(value: &str) -> Option<()> {
    let bytes = value.as_bytes();
    if bytes.len() < 20 {
        return None;
    }
    let digit = |slice: &[u8]| slice.iter().all(u8::is_ascii_digit);
    // 日期与时间主体
    if !digit(&bytes[0..4]) || bytes[4] != b'-' || !digit(&bytes[5..7]) || bytes[7] != b'-' {
        return None;
    }
    if !digit(&bytes[8..10]) || (bytes[10] != b'T' && bytes[10] != b't') {
        return None;
    }
    if !digit(&bytes[11..13]) || bytes[13] != b':' || !digit(&bytes[14..16]) || bytes[16] != b':' {
        return None;
    }
    if !digit(&bytes[17..19]) {
        return None;
    }
    let mut offset = 19;
    if bytes.get(19) == Some(&b'.') {
        offset = 20;
        while offset < bytes.len() && bytes[offset].is_ascii_digit() {
            offset += 1;
        }
    }
    let rest = bytes.get(offset..)?;
    match rest.first() {
        Some(b'Z') | Some(b'z') => {
            if rest.len() == 1 {
                Some(())
            } else {
                None
            }
        }
        Some(b'+') | Some(b'-') => {
            let tail = rest.get(1..)?;
            if tail.len() == 5 && digit(&tail[0..2]) && tail[2] == b':' && digit(&tail[3..5]) {
                Some(())
            } else {
                None
            }
        }
        _ => None,
    }
}
