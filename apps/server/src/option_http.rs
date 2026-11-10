//! 选项/系统设置管理端（12 路由）HTTP 适配器。
//!
//! Go 参考（只读 `/root/newapi`）：
//! - `apps/api/internal/transport/compose/register_api.go:298-312`（路由组：
//!   `AdminAuth()` + `RequirePermission(policy.SystemSettings)`，无限流、
//!   无 DisableCache）
//! - `apps/api/internal/ops/manage_options.go`（`GetOptions`/`UpdateOption`）
//! - `apps/api/internal/ops/store_options.go`（`ListVisibleOptions`）
//! - `apps/api/internal/dbinfra/store_options.go:84-105`（`UpdateOption`：
//!   校验 → 事务 upsert → **ApplyOption 本进程立即生效**；本端口以写后强制
//!   `AppState::reload` 等价，审计 #47 策略）
//! - `apps/api/internal/billing/payment_compliance.go`（`ConfirmPaymentCompliance`）
//! - `apps/api/internal/billing/topup_waffo_pancake.go`（waffo-pancake 五端点）
//! - `apps/api/internal/transport/handler/handle_affinity_cache.go`、
//!   `handle_smtp_pool.go`、`handle_pricing.go`（`ResetModelRatio`）
//! - `apps/api/internal/security/audit_access.go`（写路径兜底审计：
//!   payment_compliance/reset_ratio/clear_affinity_cache 为固定 action，
//!   waffo-pancake 落 `generic`；PUT /api/option/ 手动埋 `option.update`）
//!
//! 子系统边界（与 Go oracle 的已知差异，后续切片补齐）：
//! - 频道亲和缓存未移植：GET 统计的 `total/unknown` 恒为 0，按规则清空的
//!   `deleted` 恒为 0（等价 Go 全新安装的空缓存形态）；`by_rule_name` 与
//!   校验语义按配置真实解析。
//! - SMTP 发送池未移植：状态端点按 `SMTPAccountPool` 选项的配置字段回显，
//!   用量为零（等价 Go 进程刚启动未发信的形态）。
//! - `geo_block_setting.enabled` 的 geoip 预下载门未移植（该子系统整体缺席，
//!   选项为惰性键）。

use std::collections::BTreeMap;

use axum::{
    Json,
    body::Bytes,
    extract::{Extension, Request, State},
    http::{HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use newapi_billing::topup::TopUpSettings;
use newapi_identity::audit::{
    AuditOperator, RouteAudit, record_manage_audit_with_params, record_route_audit,
};
use newapi_identity::policy::{CasbinRuleRepository, SYSTEM_SETTINGS, can};
use newapi_identity::tokens::quota_from_display;
use newapi_identity::user_auth::CredentialKind;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::AuthenticatedUser;
use crate::option_store::{
    is_display_amount_key, is_invite_reward_option_key, is_positive_option_value, load_all_options,
    load_option_values, upsert_option, upsert_options_bulk, validate_console_settings,
    validate_model_request_rate_limit_group, validate_option_value, validate_tool_prices_json,
    visible_options,
};
use crate::pancake::{
    HttpPancakeTransport, InjectedPancakeTransport, PairOutcome, PancakeTransport,
    WaffoPancakeCatalog,
};

/// Go 固定文案：`common.CtxApiErrorMsg` 的字面量（不经 i18n）。
const MSG_INVALID_PARAMS_BIND: &str = "无效的参数";
const MSG_COMPLIANCE_FIELDS_FORBIDDEN: &str = "合规确认字段不允许通过通用设置接口修改";
const MSG_INVALID_AMOUNT: &str = "无效的金额数值";
const MSG_SESSION_ONLY: &str =
    "This operation requires dashboard session authentication. API access token is not allowed.";
const MSG_CONFIRM_REQUIRED: &str = "请确认合规声明";
const MSG_BAD_PARAMS: &str = "参数错误";
const MSG_RESET_RATIO_SUCCESS: &str = "重置模型倍率成功";
const MSG_CREDITS_NOT_CONFIGURED: &str = "Waffo Pancake 凭证未配置";
const MSG_CATALOG_FETCH_FAILED: &str = "拉取目录失败";
const MSG_SAVE_FAILED: &str = "保存配置失败";
const MSG_PLAN_NAME_REQUIRED: &str = "套餐名称不能为空";
const MSG_PLAN_AMOUNT_REQUIRED: &str = "套餐价格不能为空";
const MSG_PANCAKE_NOT_BOUND: &str = "Waffo Pancake 未完成配置，请先在支付设置中完成网关绑定";
const MSG_PRODUCT_CREATE_FAILED: &str = "创建套餐产品失败";
const MSG_PRODUCT_LIST_FAILED: &str = "拉取产品列表失败";
const MSG_AFFINITY_RULE_REQUIRED: &str = "缺少参数：rule_name，或使用 all=true 清空全部";
const MSG_AFFINITY_UNKNOWN_RULE: &str = "未知规则名称";
const MSG_AFFINITY_RULE_NO_INCLUDE: &str = "该规则未启用 include_rule_name，无法按规则清空缓存";

/// i18n 键。
const MSG_COMPLIANCE_REQUIRED: &str = "payment.compliance_required";
const MSG_INSUFFICIENT_PRIVILEGE: &str = "auth.insufficient_privilege";
const MSG_DATABASE_ERROR: &str = "common.database_error";

/// Go `ops.UpdateOption` 的 JSON 请求体。
#[derive(Debug, Default, Deserialize)]
struct OptionUpdateRequest {
    #[serde(default)]
    key: String,
    #[serde(default)]
    value: Value,
}

/// Go `security.RequirePermission(policy.SystemSettings)` 的路由级中间件
/// （与 `custom_oauth_http::require_system_settings` 同一形态：拒绝路径先
/// 补写方法的兜底审计，再回 403 `auth.insufficient_privilege`，无 `code`）。
pub async fn require_system_settings(
    State(state): State<AppState>,
    request: Request,
    next: axum::middleware::Next,
) -> Response {
    let Some(user) = request.extensions().get::<AuthenticatedUser>().cloned() else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let allowed = match can(
        &CasbinRuleRepository::new(db.clone()),
        user.0.user_id,
        // Go 的系统角色与 Rust 策略求值同为小整数域（0/1/10/100）。
        user.0.role as i32,
        SYSTEM_SETTINGS,
    )
    .await
    {
        Ok(allowed) => allowed,
        Err(error) => {
            tracing::warn!(
                event = "option_policy_read_failed",
                category = crate::database_error_class(&error),
                "option policy lookup failed"
            );
            // Go 的空 enforcer 同样拒绝，不把 DB 故障放行成越权。
            false
        }
    };
    if allowed {
        return next.run(request).await;
    }
    // 拒绝路径：写方法的兜底审计（本切片路由只有 POST/PUT/DELETE）。
    let (parts, _body) = request.into_parts();
    let method = parts.method.clone();
    let path = parts.uri.path().to_owned();
    let headers = parts.headers.clone();
    let success = false;
    match (method.as_str(), path.as_str()) {
        ("POST", "/api/option/payment_compliance") => {
            record_option_route_audit(
                &state,
                &user,
                &headers,
                "POST",
                "/api/option/payment_compliance",
                "option.payment_compliance",
                403,
                success,
            )
            .await;
        }
        ("POST", "/api/option/rest_model_ratio") => {
            record_option_route_audit(
                &state,
                &user,
                &headers,
                "POST",
                "/api/option/rest_model_ratio",
                "option.reset_ratio",
                403,
                success,
            )
            .await;
        }
        ("DELETE", "/api/option/channel_affinity_cache") => {
            record_option_route_audit(
                &state,
                &user,
                &headers,
                "DELETE",
                "/api/option/channel_affinity_cache",
                "option.clear_affinity_cache",
                403,
                success,
            )
            .await;
        }
        ("POST", "/api/option/waffo-pancake/pair") => {
            record_option_route_audit(
                &state,
                &user,
                &headers,
                "POST",
                "/api/option/waffo-pancake/pair",
                "generic",
                403,
                success,
            )
            .await;
        }
        ("POST", "/api/option/waffo-pancake/save") => {
            record_option_route_audit(
                &state,
                &user,
                &headers,
                "POST",
                "/api/option/waffo-pancake/save",
                "generic",
                403,
                success,
            )
            .await;
        }
        ("POST", "/api/option/waffo-pancake/subscription-product") => {
            record_option_route_audit(
                &state,
                &user,
                &headers,
                "POST",
                "/api/option/waffo-pancake/subscription-product",
                "generic",
                403,
                success,
            )
            .await;
        }
        _ => {}
    }
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "success": false,
            "message": translate(&headers, MSG_INSUFFICIENT_PRIVILEGE),
        })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// GET /api/option/
// ---------------------------------------------------------------------------

/// Go `ops.GetOptions`：可见选项快照，`data` 为 `{key, value}` 数组
/// （Go map 迭代无序，这里按键字典序输出）。
pub async fn get_options(
    State(state): State<AppState>,
    Extension(_auth_user): Extension<AuthenticatedUser>,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let rows = match load_all_options(&db).await {
        Ok(rows) => rows,
        Err(_) => {
            return Json(json!({
                "success": false,
                "message": translate_static(MSG_DATABASE_ERROR),
            }))
            .into_response();
        }
    };
    // Go 读取进程级 QuotaPerUnit/汇率/展示币种；这里读快照（启动与 reload
    // 同频刷新，含数据库覆盖）。
    let display = state.quota_display();
    let options = visible_options(&rows, &display);
    let data: Vec<Value> = options
        .into_iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect();
    Json(json!({
        "success": true,
        "message": "",
        "data": data,
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// PUT /api/option/
// ---------------------------------------------------------------------------

/// Go `ops.UpdateOption`。顺序即契约：bind → 值串化 → 合规门 →
/// `payment_setting.compliance_` 拦截 → 逐键校验 switch → `_display` 归一 →
/// `ValidateOptionValue` → 事务 upsert → **强制 reload** → 手动审计。
pub async fn update_option(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    // Go gin `BindJSON`：空体是 EOF 绑定错误。
    if body.is_empty() {
        return Json(json!({
            "success": false,
            "message": MSG_INVALID_PARAMS_BIND,
        }))
        .into_response();
    }
    let request: OptionUpdateRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => {
            return Json(json!({
                "success": false,
                "message": MSG_INVALID_PARAMS_BIND,
            }))
            .into_response();
        }
    };
    let value = coerce_option_value(&request.value);
    let key = request.key;

    // 合规门必须在 `_display` 键归一之前匹配（manage_options.go:103-111）。
    if is_invite_reward_option_key(&key) && is_positive_option_value(&value) {
        let settings = match TopUpSettings::load(&db).await {
            Ok(settings) => settings,
            Err(_) => return database_error_json(),
        };
        if !settings.payment_compliance_confirmed() {
            return rejected_i18n(&headers, MSG_COMPLIANCE_REQUIRED);
        }
    }
    if key.starts_with("payment_setting.compliance_") {
        return Json(json!({
            "success": false,
            "message": MSG_COMPLIANCE_FIELDS_FORBIDDEN,
        }))
        .into_response();
    }

    if let Some(response) = validate_key_switch(&db, &key, &value).await {
        return response;
    }

    // 金额键归一：`<base>_display` 换算为内部 quota 后按 base 键入库
    // （manage_options.go:353-367）。
    let display = state.quota_display();
    let (key, value) = match normalize_display_amount(&key, &value, &display) {
        Ok(pair) => pair,
        Err(message) => {
            return Json(json!({
                "success": false,
                "message": message,
            }))
            .into_response();
        }
    };

    if let Err(message) = validate_option_value(&key, &value) {
        return Json(json!({
            "success": false,
            "message": message,
        }))
        .into_response();
    }

    if upsert_option(&db, &key, &value).await.is_err() {
        // Go `CtxApiError(c, err)` 透传 err.Error()（含 SQL 文本）；本端口
        // 按既有约定脱敏为固定键。
        return database_error_json();
    }

    // 审计 #47：Go 的 UpdateOption 写库后立即 ApplyOption（本进程生效），
    // 本端口以一次强制 reload 等价——管理员改动即刻可见，不等 60 秒轮询。
    // 失败语义对齐 Go：写库已发生但响应仍为失败（reload 读库失败按
    // 固定键脱敏，定时 reload worker 会兜底重试）。
    if let Err(error) = state.reload(&db).await {
        tracing::warn!(
            category = crate::database_error_class(&error),
            "option post-write reload failed"
        );
        return database_error_json();
    }

    // 出于安全考虑只记录被修改的配置项名称，不记录配置值（manage_options.go:374-376）。
    let mut params = serde_json::Map::new();
    params.insert("key".to_owned(), json!(key));
    record_manage_audit_with_params(
        &db,
        &audit_operator(&auth_user),
        "option.update",
        0,
        Some(&params),
        &request_ip(&state, &headers),
        crate::http::now_seconds(),
    )
    .await;

    Json(json!({
        "success": true,
        "message": "",
    }))
    .into_response()
}

/// Go 的值串化（`manage_options.go:93-102`）：bool 走 Interface2String，
/// 数字按 float64 走 `FormatFloat('f', -1, 64)`，字符串原样，null 得空串。
/// 对象/数组在 Go 里走 `fmt %v`（`map[a:1]` 形态）——管理界面不会提交该
/// 形态，这里以 JSON 文本落库（单向差异，管理页不可达）。
fn coerce_option_value(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::Bool(true) => "true".to_owned(),
        Value::Bool(false) => "false".to_owned(),
        Value::Number(number) => match number.as_f64() {
            Some(float) => crate::option_defaults::go_format_float(float),
            None => number.to_string(),
        },
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// `_display` 金额归一：解析失败/非有限 → Go 的 "无效的金额数值"；
/// 展示币种金额按 Go `QuotaFromDisplayAmount` 换算为内部 quota。
fn normalize_display_amount(
    key: &str,
    value: &str,
    display: &newapi_identity::self_user::QuotaDisplaySettings,
) -> Result<(String, String), String> {
    if let Some(base) = key.strip_suffix("_display")
        && is_display_amount_key(base)
    {
        let amount: f64 = value
            .trim()
            .parse()
            .map_err(|_| MSG_INVALID_AMOUNT.to_owned())?;
        if !amount.is_finite() {
            return Err(MSG_INVALID_AMOUNT.to_owned());
        }
        return Ok((
            base.to_owned(),
            quota_from_display(amount, display).to_string(),
        ));
    }
    Ok((key.to_owned(), value.to_owned()))
}

/// Go `UpdateOption` 的逐键校验 switch（`manage_options.go:116-352`）。
/// 返回 `Some(response)` 表示校验失败并已构造响应。
async fn validate_key_switch(
    db: &newapi_storage::Database,
    key: &str,
    value: &str,
) -> Option<Response> {
    let fail = |message: &str| -> Option<Response> {
        Some(
            Json(json!({
                "success": false,
                "message": message,
            }))
            .into_response(),
        )
    };
    // 需要 DB 选项值的分支一次性读取。
    let guard_keys = [
        "GitHubClientId",
        "discord.client_id",
        "oidc.client_id",
        "LinuxDOClientId",
        "EmailDomainWhitelist",
        "WeChatServerAddress",
        "TurnstileSiteKey",
        "TelegramBotToken",
    ];
    let needs_db = matches!(
        key,
        "GitHubOAuthEnabled"
            | "discord.enabled"
            | "oidc.enabled"
            | "LinuxDOOAuthEnabled"
            | "EmailDomainRestrictionEnabled"
            | "WeChatAuthEnabled"
            | "TurnstileCheckEnabled"
            | "TelegramOAuthEnabled"
    );
    let options = if needs_db {
        match load_option_values(db, &guard_keys).await {
            Ok(options) => options,
            Err(_) => return Some(database_error_json()),
        }
    } else {
        BTreeMap::new()
    };
    let option_value = |name: &str| -> String {
        options
            .get(name)
            .cloned()
            .unwrap_or_else(|| seed_default(name))
    };
    match key {
        // geo_block_setting.enabled：geoip 子系统未移植（文档头差异声明）。
        "geo_block_setting.enabled" => None,
        "GitHubOAuthEnabled" => {
            if value == "true" && option_value("GitHubClientId").is_empty() {
                return fail(
                    "无法启用 GitHub OAuth，请先填入 GitHub Client Id 以及 GitHub Client Secret！",
                );
            }
            None
        }
        "discord.enabled" => {
            if value == "true" && option_value("discord.client_id").is_empty() {
                return fail(
                    "无法启用 Discord OAuth，请先填入 Discord Client Id 以及 Discord Client Secret！",
                );
            }
            None
        }
        "oidc.enabled" => {
            if value == "true" && option_value("oidc.client_id").is_empty() {
                return fail(
                    "无法启用 OIDC 登录，请先填入 OIDC Client Id 以及 OIDC Client Secret！",
                );
            }
            None
        }
        "LinuxDOOAuthEnabled" => {
            if value == "true" && option_value("LinuxDOClientId").is_empty() {
                return fail(
                    "无法启用 LinuxDO OAuth，请先填入 LinuxDO Client Id 以及 LinuxDO Client Secret！",
                );
            }
            None
        }
        "EmailDomainRestrictionEnabled" => {
            if value == "true" {
                // Go `strings.Split(value, ",")` 永不产生空切片（"" 得 [""]），
                // 因此该守卫只对程序化置空的进程状态生效；这里复刻同一判定。
                let whitelist = option_value("EmailDomainWhitelist");
                if whitelist.is_empty() && !options.contains_key("EmailDomainWhitelist") {
                    return fail("无法启用邮箱域名限制，请先填入限制的邮箱域名！");
                }
            }
            None
        }
        "EmailFormatRegex" => {
            if !value.is_empty() {
                for (index, line) in value.split('\n').enumerate() {
                    let rule = line.trim();
                    if rule.is_empty() {
                        continue;
                    }
                    if let Err(error) = regex::Regex::new(rule) {
                        return fail(&format!(
                            "邮箱格式限制正则第 {} 行无效：{}",
                            index + 1,
                            error
                        ));
                    }
                }
            }
            None
        }
        "WeChatAuthEnabled" => {
            if value == "true" && option_value("WeChatServerAddress").is_empty() {
                return fail("无法启用微信登录，请先填入微信登录相关配置信息！");
            }
            None
        }
        "TurnstileCheckEnabled" => {
            if value == "true" && option_value("TurnstileSiteKey").is_empty() {
                return fail("无法启用 Turnstile 校验，请先填入 Turnstile 校验相关配置信息！");
            }
            None
        }
        "TelegramOAuthEnabled" => {
            if value == "true" && option_value("TelegramBotToken").is_empty() {
                return fail("无法启用 Telegram OAuth，请先填入 Telegram Bot Token！");
            }
            None
        }
        "theme.frontend" => {
            if value != "default" {
                return fail("Classic 前端已移除，主题只能设置为 default");
            }
            None
        }
        "GroupRatio" => match validate_group_ratio(value) {
            Ok(()) => None,
            Err(message) => fail(&message),
        },
        "gemini.safety_settings" => match validate_gemini_safety_settings(value) {
            Ok(()) => None,
            Err(message) => fail(&message),
        },
        "claude.default_max_tokens" => match validate_claude_default_max_tokens(value) {
            Ok(()) => None,
            Err(message) => fail(&message),
        },
        key if key == crate::option_store::TOOL_PRICE_OPTION_KEY => {
            match validate_tool_prices_json(value) {
                Ok(()) => None,
                Err(message) => fail(&message),
            }
        }
        "ImageRatio" => apply_ratio_json(value, "图片倍率设置失败"),
        "AudioRatio" => apply_ratio_json(value, "音频倍率设置失败"),
        "AudioCompletionRatio" => apply_ratio_json(value, "音频补全倍率设置失败"),
        "CreateCacheRatio" => apply_ratio_json(value, "缓存创建倍率设置失败"),
        "ModelRequestRateLimitGroup" => match validate_model_request_rate_limit_group(value) {
            Ok(()) => None,
            Err(message) => fail(&message),
        },
        "AutomaticDisableStatusCodes" | "AutomaticRetryStatusCodes" => {
            match crate::option_defaults::parse_http_status_code_ranges(value) {
                Ok(_) => None,
                Err(message) => fail(&message),
            }
        }
        "console_setting.api_info" => match validate_console_settings(value, "ApiInfo") {
            Ok(()) => None,
            Err(message) => fail(&message),
        },
        "console_setting.announcements" => {
            match validate_console_settings(value, "Announcements") {
                Ok(()) => None,
                Err(message) => fail(&message),
            }
        }
        "console_setting.faq" => match validate_console_settings(value, "FAQ") {
            Ok(()) => None,
            Err(message) => fail(&message),
        },
        "console_setting.uptime_kuma_groups" => {
            match validate_console_settings(value, "UptimeKumaGroups") {
                Ok(()) => None,
                Err(message) => fail(&message),
            }
        }
        _ => None,
    }
}

/// Go `ratio_setting.CheckGroupRatio`（`configure_group_ratio.go:92-103`）。
fn validate_group_ratio(value: &str) -> Result<(), String> {
    let parsed: BTreeMap<String, f64> =
        serde_json::from_str(value).map_err(|_| "GroupRatio 格式错误".to_owned())?;
    for (name, ratio) in &parsed {
        if *ratio < 0.0 {
            return Err(format!("group ratio must be not less than 0: {name}"));
        }
    }
    Ok(())
}

/// Go `model_setting.ValidateGeminiSafetySettings`
/// （`manage_models.go:249-266`）。
fn validate_gemini_safety_settings(value: &str) -> Result<(), String> {
    let Ok(settings) = serde_json::from_str::<BTreeMap<String, String>>(value) else {
        return Err("Gemini safety settings must be a JSON string map".to_owned());
    };
    const VALID: [&str; 6] = [
        "OFF",
        "BLOCK_NONE",
        "BLOCK_ONLY_HIGH",
        "BLOCK_MEDIUM_AND_ABOVE",
        "BLOCK_LOW_AND_ABOVE",
        "HARM_BLOCK_THRESHOLD_UNSPECIFIED",
    ];
    for (category, threshold) in &settings {
        if threshold.is_empty() {
            continue;
        }
        if !VALID.contains(&threshold.as_str()) {
            return Err(format!(
                "invalid Gemini safety threshold {threshold:?} for {category:?}"
            ));
        }
    }
    Ok(())
}

/// Go `model_setting.ValidateClaudeDefaultMaxTokens`
/// （`manage_models.go:216-230`）。
fn validate_claude_default_max_tokens(value: &str) -> Result<(), String> {
    let settings: BTreeMap<String, i64> = serde_json::from_str(value).map_err(|_| {
        "Claude default max tokens must be a JSON map of model to integer".to_owned()
    })?;
    for (model, max_tokens) in &settings {
        if *max_tokens < 0 {
            return Err(format!(
                "negative Claude default max_tokens {max_tokens} for {model:?}"
            ));
        }
    }
    Ok(())
}

/// Go `ratio_setting.UpdateXRatioByJSONString` 的校验语义：解析
/// `map[string]float64`，失败时 `"<前缀>: " + err`。
fn apply_ratio_json(value: &str, prefix: &str) -> Option<Response> {
    match serde_json::from_str::<BTreeMap<String, f64>>(value) {
        Ok(_) => None,
        Err(_) => Some(
            Json(json!({
                "success": false,
                "message": format!("{prefix}: 无效的 JSON"),
            }))
            .into_response(),
        ),
    }
}

/// 缺行时的种子默认值（对齐 Go 的 OptionMap 种子语义）。
fn seed_default(key: &str) -> String {
    crate::option_defaults::SEED_OPTIONS
        .iter()
        .find(|(name, _)| *name == key)
        .map(|(_, value)| (*value).to_owned())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// GET /api/option/channel_affinity_cache
// ---------------------------------------------------------------------------

/// Go `ChannelAffinitySetting` 的端口子集（`track_affinity_setting.go:11-41`）。
#[derive(Clone, Debug, Deserialize)]
struct ChannelAffinityRule {
    #[serde(default)]
    name: String,
    #[serde(default, rename = "include_rule_name")]
    include_rule_name: bool,
}

#[derive(Clone, Debug, Deserialize)]
struct ChannelAffinitySetting {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default = "default_max_entries")]
    max_entries: i64,
    #[serde(default)]
    rules: Vec<ChannelAffinityRule>,
}

fn default_true() -> bool {
    true
}

fn default_max_entries() -> i64 {
    100_000
}

impl Default for ChannelAffinitySetting {
    fn default() -> Self {
        // Go `channelAffinitySetting` 字面量（track_affinity_setting.go:135-151）：
        // enabled/switch_on_success 为 true，max_entries 100000，两条内置规则。
        Self {
            enabled: true,
            max_entries: 100_000,
            rules: vec![
                ChannelAffinityRule {
                    name: "codex cli trace".to_owned(),
                    include_rule_name: true,
                },
                ChannelAffinityRule {
                    name: "claude cli trace".to_owned(),
                    include_rule_name: true,
                },
            ],
        }
    }
}

/// Go `GetChannelAffinityCacheStats`（`track_affinity.go:109-193`）的空缓存
/// 形态：亲和缓存本体未移植，键计数恒为 0；`by_rule_name` 与容量来自配置。
pub async fn affinity_cache_stats(
    State(state): State<AppState>,
    Extension(_auth_user): Extension<AuthenticatedUser>,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let setting = load_affinity_setting(&db).await;
    let by_rule_name: BTreeMap<String, i64> = setting
        .rules
        .iter()
        .filter(|rule| !rule.name.trim().is_empty() && rule.include_rule_name)
        .map(|rule| (rule.name.clone(), 0))
        .collect();
    // cachex 容量：setting.MaxEntries（<=0 回退 100000），算法 LRU。
    let capacity = if setting.max_entries > 0 {
        setting.max_entries
    } else {
        100_000
    };
    Json(json!({
        "success": true,
        "message": "",
        "data": {
            "enabled": setting.enabled,
            "total": 0,
            "unknown": 0,
            "by_rule_name": by_rule_name,
            "cache_capacity": capacity,
            "cache_algo": "lru",
        },
    }))
    .into_response()
}

/// Go `ClearChannelAffinityCache`（`handle_affinity_cache.go:21-61`）：
/// `all=true` 清空全部；否则 `rule_name` 必填且必须命中已配置规则。
/// 亲和缓存本体未移植，删除计数恒为 0。
pub async fn clear_affinity_cache(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let all = query_value(&uri, "all").trim().to_owned();
    let rule_name = query_value(&uri, "rule_name").trim().to_owned();
    let setting = load_affinity_setting(&db).await;

    if all == "true" {
        // Go：keys 数量即 deleted；空缓存为 0。
        record_affinity_route_audit(&state, &auth_user, &headers, 200, true);
        return Json(json!({
            "success": true,
            "message": "",
            "data": { "deleted": 0 },
        }))
        .into_response();
    }
    if rule_name.is_empty() {
        record_affinity_route_audit(&state, &auth_user, &headers, 400, false);
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "message": MSG_AFFINITY_RULE_REQUIRED })),
        )
            .into_response();
    }
    let matched = setting
        .rules
        .iter()
        .find(|rule| rule.name.trim() == rule_name);
    let Some(rule) = matched else {
        record_affinity_route_audit(&state, &auth_user, &headers, 400, false);
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "message": MSG_AFFINITY_UNKNOWN_RULE })),
        )
            .into_response();
    };
    if !rule.include_rule_name {
        record_affinity_route_audit(&state, &auth_user, &headers, 400, false);
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "message": MSG_AFFINITY_RULE_NO_INCLUDE })),
        )
            .into_response();
    }
    record_affinity_route_audit(&state, &auth_user, &headers, 200, true);
    Json(json!({
        "success": true,
        "message": "",
        "data": { "deleted": 0 },
    }))
    .into_response()
}

/// Go 兜底审计：`DELETE /api/option/channel_affinity_cache` →
/// `option.clear_affinity_cache`。400 分支同样落审计（Go 的
/// finishAdminAudit 不区分业务成败）。
async fn record_affinity_route_audit(
    state: &AppState,
    auth_user: &AuthenticatedUser,
    headers: &HeaderMap,
    status: u16,
    success: bool,
) {
    record_option_route_audit(
        state,
        auth_user,
        headers,
        "DELETE",
        "/api/option/channel_affinity_cache",
        "option.clear_affinity_cache",
        status,
        success,
    )
    .await;
}

/// Go `GetChannelAffinitySetting` 的选项读取：`channel_affinity_setting`
/// JSON，缺失/畸形回退内置默认。
async fn load_affinity_setting(db: &newapi_storage::Database) -> ChannelAffinitySetting {
    let values = load_option_values(db, &["channel_affinity_setting"])
        .await
        .unwrap_or_default();
    match values.get("channel_affinity_setting") {
        Some(raw) if !raw.trim().is_empty() => serde_json::from_str(raw).unwrap_or_default(),
        _ => ChannelAffinitySetting::default(),
    }
}

// ---------------------------------------------------------------------------
// GET /api/option/smtp_pool_status
// ---------------------------------------------------------------------------

/// Go `GetSMTPPoolStatus`（`handle_smtp_pool.go`）+ `SenderStatus`
/// （`common/email_sender.go:15-27`）。发送池与配额存储未移植：配置字段
/// 按选项回显，用量为零（等价进程刚启动未发信）。`SMTPAccountPool` 为空
/// 时 senders 为空数组。
pub async fn smtp_pool_status(
    State(state): State<AppState>,
    Extension(_auth_user): Extension<AuthenticatedUser>,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let values = match load_option_values(&db, &["SMTPAccountPool"]).await {
        Ok(values) => values,
        Err(_) => return database_error_json(),
    };
    let pool_text = values
        .get("SMTPAccountPool")
        .map(String::as_str)
        .unwrap_or("");
    let mut senders: Vec<Value> = Vec::new();
    let mut sent_today: i64 = 0;
    let mut remaining_today: i64 = 0;
    if let Ok(accounts) =
        serde_json::from_str::<Vec<serde_json::Map<String, Value>>>(pool_text.trim())
    {
        for account in accounts {
            let daily_limit = account
                .get("dailyLimit")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            // 无配额记录时 Go 的 usedToday=0、remainingToday=dailyLimit。
            let remaining = daily_limit.max(0);
            senders.push(json!({
                "account": account.get("account").and_then(Value::as_str).unwrap_or(""),
                "server": account.get("server").and_then(Value::as_str).unwrap_or(""),
                "port": account.get("port").and_then(Value::as_i64).unwrap_or(0),
                "from": account.get("from").and_then(Value::as_str).unwrap_or(""),
                "priority": account.get("priority").and_then(Value::as_i64).unwrap_or(0),
                "dailyLimit": daily_limit,
                "usedToday": 0,
                "remainingToday": remaining,
                "lastSentAt": "0001-01-01T00:00:00Z",
                "lastError": "",
                "lastErrorAt": "0001-01-01T00:00:00Z",
            }));
            sent_today += 0;
            if daily_limit > 0 {
                remaining_today += remaining;
            }
        }
    }
    Json(json!({
        "success": true,
        "message": "",
        "data": {
            "senders": senders,
            "sentToday": sent_today,
            "remainingToday": remaining_today,
        },
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// POST /api/option/rest_model_ratio
// ---------------------------------------------------------------------------

/// Go `ops.ResetModelRatio`（`manage_model_metadata.go:407-427`）：写默认
/// `ModelRatio` 表 + 应用。本端口写库后强制 reload（audit #47）。
pub async fn reset_model_ratio(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let default_str = crate::option_defaults::default_model_ratio_json();
    if upsert_option(&db, "ModelRatio", &default_str)
        .await
        .is_err()
    {
        record_option_route_audit(
            &state,
            &auth_user,
            &headers,
            "POST",
            "/api/option/rest_model_ratio",
            "option.reset_ratio",
            200,
            false,
        )
        .await;
        return database_error_json();
    }
    if let Err(error) = state.reload(&db).await {
        tracing::warn!(
            category = crate::database_error_class(&error),
            "model ratio reset reload failed"
        );
        record_option_route_audit(
            &state,
            &auth_user,
            &headers,
            "POST",
            "/api/option/rest_model_ratio",
            "option.reset_ratio",
            200,
            false,
        )
        .await;
        return database_error_json();
    }
    record_option_route_audit(
        &state,
        &auth_user,
        &headers,
        "POST",
        "/api/option/rest_model_ratio",
        "option.reset_ratio",
        200,
        true,
    )
    .await;
    Json(json!({
        "success": true,
        "message": MSG_RESET_RATIO_SUCCESS,
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// POST /api/option/payment_compliance
// ---------------------------------------------------------------------------

/// Go `billing.ConfirmPaymentCompliance`（`payment_compliance.go:28-80`）。
pub async fn confirm_payment_compliance(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    // Go：access token 一律 403。
    if auth_user.0.credential == CredentialKind::PersonalAccessToken {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "success": false, "message": MSG_SESSION_ONLY })),
        )
            .into_response();
    }
    #[derive(Deserialize)]
    struct PaymentComplianceRequest {
        #[serde(default)]
        confirmed: bool,
    }
    let request: PaymentComplianceRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => {
            return Json(json!({ "success": false, "message": MSG_BAD_PARAMS })).into_response();
        }
    };
    if !request.confirmed {
        return Json(json!({ "success": false, "message": MSG_CONFIRM_REQUIRED })).into_response();
    }

    let now = crate::http::now_seconds();
    let user_id = auth_user.0.user_id;
    let client_ip = request_ip(&state, &headers);
    let updates: [(&str, String); 5] = [
        ("payment_setting.compliance_confirmed", "true".to_owned()),
        (
            "payment_setting.compliance_terms_version",
            COMPLIANCE_TERMS_VERSION.to_owned(),
        ),
        ("payment_setting.compliance_confirmed_at", now.to_string()),
        (
            "payment_setting.compliance_confirmed_by",
            user_id.to_string(),
        ),
        ("payment_setting.compliance_confirmed_ip", client_ip.clone()),
    ];
    // Go 逐键 UpdateOption（各自校验+应用）；这里事务 bulk 一次落库，
    // 失败即整体回滚（Go 的单键失败路径在中途失败时已写入前序键——本端口
    // 的原子性更强，可观察差异只在数据库故障场景）。
    let bulk: BTreeMap<String, String> = updates
        .iter()
        .map(|(key, value)| ((*key).to_owned(), value.clone()))
        .collect();
    if let Err(error) = upsert_options_bulk(&db, &bulk).await {
        tracing::warn!(
            category = crate::database_error_class(&error),
            "payment compliance write failed"
        );
        record_option_route_audit(
            &state,
            &auth_user,
            &headers,
            "POST",
            "/api/option/payment_compliance",
            "option.payment_compliance",
            200,
            false,
        )
        .await;
        return database_error_json();
    }
    if let Err(error) = state.reload(&db).await {
        tracing::warn!(
            category = crate::database_error_class(&error),
            "payment compliance reload failed"
        );
        record_option_route_audit(
            &state,
            &auth_user,
            &headers,
            "POST",
            "/api/option/payment_compliance",
            "option.payment_compliance",
            200,
            false,
        )
        .await;
        return database_error_json();
    }
    tracing::info!(
        "payment compliance confirmed user_id={user_id} ip={client_ip} terms_version={COMPLIANCE_TERMS_VERSION} confirmed_at={now}"
    );
    record_option_route_audit(
        &state,
        &auth_user,
        &headers,
        "POST",
        "/api/option/payment_compliance",
        "option.payment_compliance",
        200,
        true,
    )
    .await;
    Json(json!({
        "success": true,
        "message": "",
        "data": {
            "confirmed": true,
            "terms_version": COMPLIANCE_TERMS_VERSION,
            "confirmed_at": now,
            "confirmed_by": user_id,
        },
    }))
    .into_response()
}

/// Go `billing.CurrentComplianceTermsVersion`。
const COMPLIANCE_TERMS_VERSION: &str = "v1";

// ---------------------------------------------------------------------------
// waffo-pancake 五端点
// ---------------------------------------------------------------------------

/// Go `resolveWaffoPancakeAdminCreds`：请求里两段都为空时回退持久化凭据。
async fn resolve_waffo_creds(
    db: &newapi_storage::Database,
    body_merchant_id: &str,
    body_private_key: &str,
) -> Result<(String, String), sqlx::Error> {
    let merchant = body_merchant_id.trim();
    let private_key = body_private_key.trim();
    if merchant.is_empty() && private_key.is_empty() {
        let values =
            load_option_values(db, &["WaffoPancakeMerchantID", "WaffoPancakePrivateKey"]).await?;
        return Ok((
            values
                .get("WaffoPancakeMerchantID")
                .cloned()
                .unwrap_or_default(),
            values
                .get("WaffoPancakePrivateKey")
                .cloned()
                .unwrap_or_default(),
        ));
    }
    Ok((merchant.to_owned(), private_key.to_owned()))
}

/// Go `billing.ListWaffoPancakeCatalog`（`topup_waffo_pancake.go:217-236`）。
/// 凭据来自查询参数（空则回退持久化），目录拉取兼作凭据探测。
pub async fn waffo_catalog(
    State(state): State<AppState>,
    Extension(_auth_user): Extension<AuthenticatedUser>,
    uri: Uri,
    _headers: HeaderMap,
    injected: Option<Extension<InjectedPancakeTransport>>,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let merchant_id = query_value(&uri, "merchant_id");
    let private_key = query_value(&uri, "private_key");
    let (merchant_id, private_key) =
        match resolve_waffo_creds(&db, &merchant_id, &private_key).await {
            Ok(pair) => pair,
            Err(_) => return waffo_error(MSG_CATALOG_FETCH_FAILED),
        };
    if merchant_id.trim().is_empty() || private_key.trim().is_empty() {
        return waffo_error(MSG_CREDITS_NOT_CONFIGURED);
    }
    let transport: &dyn PancakeTransport = match injected.as_ref() {
        Some(injected) => injected.0.0.as_ref(),
        None => &HttpPancakeTransport,
    };
    match transport.catalog(&merchant_id, &private_key).await {
        Ok(catalog) => Json(json!({ "message": "success", "data": catalog })).into_response(),
        Err(error) => {
            tracing::warn!("Waffo Pancake 拉取店铺与产品目录失败 error={:?}", error.0);
            waffo_error(MSG_CATALOG_FETCH_FAILED)
        }
    }
}

/// Go `billing.CreateWaffoPancakePair`（`topup_waffo_pancake.go:167-212`）。
/// 请求体可选（Go 按 ContentLength 判断），凭据解析同 catalog。
pub async fn waffo_pair(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
    injected: Option<Extension<InjectedPancakeTransport>>,
    body: Bytes,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    #[derive(Deserialize, Default)]
    struct CreateWaffoPancakePairRequest {
        #[serde(default)]
        merchant_id: String,
        #[serde(default)]
        private_key: String,
        #[serde(default)]
        return_url: String,
    }
    let request: CreateWaffoPancakePairRequest = if body.is_empty() {
        CreateWaffoPancakePairRequest::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(_) => return waffo_error(MSG_BAD_PARAMS),
        }
    };
    let (merchant_id, private_key) =
        match resolve_waffo_creds(&db, &request.merchant_id, &request.private_key).await {
            Ok(pair) => pair,
            Err(_) => return waffo_error(MSG_BAD_PARAMS),
        };
    if merchant_id.trim().is_empty() || private_key.trim().is_empty() {
        return waffo_error(MSG_CREDITS_NOT_CONFIGURED);
    }
    let transport: &dyn PancakeTransport = match injected.as_ref() {
        Some(injected) => injected.0.0.as_ref(),
        None => &HttpPancakeTransport,
    };
    let route = "/api/option/waffo-pancake/pair";
    let (response, success) = match transport
        .create_pair(&merchant_id, &private_key, &request.return_url)
        .await
    {
        Ok(PairOutcome::Complete(result)) => (
            Json(json!({
                "message": "success",
                "data": {
                    "store_id": result.store_id,
                    "store_name": result.store_name,
                    "product_id": result.product_id,
                    "product_name": result.product_name,
                },
            }))
            .into_response(),
            true,
        ),
        Ok(PairOutcome::OrphanStore {
            store_id,
            store_name,
            error,
        }) => {
            tracing::warn!(
                "Waffo Pancake 创建店铺与产品失败 orphan_store=true store_id={store_id:?} error={error:?}"
            );
            (
                Json(json!({
                    "message": "error",
                    "data": {
                        "error": error,
                        "store_id": store_id,
                        "store_name": store_name,
                        "orphan_store": true,
                    },
                }))
                .into_response(),
                false,
            )
        }
        Ok(PairOutcome::Failed(error)) => {
            tracing::warn!("Waffo Pancake 创建店铺与产品失败 orphan_store=false error={error:?}");
            (
                Json(json!({
                    "message": "error",
                    "data": { "error": error },
                }))
                .into_response(),
                false,
            )
        }
        Err(error) => {
            tracing::warn!("Waffo Pancake 创建店铺与产品失败 error={:?}", error.0);
            (waffo_error(MSG_BAD_PARAMS), false)
        }
    };
    // Go 兜底审计：waffo-pancake 路由未登记 action，落 generic。
    record_option_route_audit(
        &state, &auth_user, &headers, "POST", route, "generic", 200, success,
    )
    .await;
    response
}

/// Go `billing.SaveWaffoPancake`（`topup_waffo_pancake.go:121-149`）→
/// `SaveWaffoPancakeConfig`（`call_waffo_pancake.go:457-492`）：五字段
/// 原子落库，空私钥视为保留现有值；唯一写 OptionMap 的 waffo 端点。
pub async fn waffo_save(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    #[derive(Deserialize, Default)]
    struct SaveWaffoPancakeRequest {
        #[serde(default)]
        merchant_id: String,
        #[serde(default)]
        private_key: String,
        #[serde(default)]
        return_url: String,
        #[serde(default)]
        store_id: String,
        #[serde(default)]
        product_id: String,
    }
    let request: SaveWaffoPancakeRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return waffo_error(MSG_BAD_PARAMS),
    };
    let merchant_id = request.merchant_id.trim();
    let store_id = request.store_id.trim();
    let product_id = request.product_id.trim();
    if merchant_id.is_empty() || store_id.is_empty() || product_id.is_empty() {
        tracing::warn!(
            "Waffo Pancake 保存配置失败 store_id={store_id:?} product_id={product_id:?} error=\"merchant id, store id, and product id are required to save\""
        );
        record_option_route_audit(
            &state,
            &auth_user,
            &headers,
            "POST",
            "/api/option/waffo-pancake/save",
            "generic",
            200,
            false,
        )
        .await;
        return waffo_error(MSG_SAVE_FAILED);
    }
    let mut values: BTreeMap<String, String> = BTreeMap::new();
    values.insert("WaffoPancakeMerchantID".to_owned(), merchant_id.to_owned());
    values.insert(
        "WaffoPancakeReturnURL".to_owned(),
        request.return_url.trim().to_owned(),
    );
    values.insert("WaffoPancakeStoreID".to_owned(), store_id.to_owned());
    values.insert("WaffoPancakeProductID".to_owned(), product_id.to_owned());
    let private_key = request.private_key.trim();
    if !private_key.is_empty() {
        values.insert("WaffoPancakePrivateKey".to_owned(), private_key.to_owned());
    }
    if let Err(error) = upsert_options_bulk(&db, &values).await {
        tracing::warn!(
            category = crate::database_error_class(&error),
            "waffo pancake save failed"
        );
        record_option_route_audit(
            &state,
            &auth_user,
            &headers,
            "POST",
            "/api/option/waffo-pancake/save",
            "generic",
            200,
            false,
        )
        .await;
        return waffo_error(MSG_SAVE_FAILED);
    }
    if let Err(error) = state.reload(&db).await {
        tracing::warn!(
            category = crate::database_error_class(&error),
            "waffo pancake save reload failed"
        );
        record_option_route_audit(
            &state,
            &auth_user,
            &headers,
            "POST",
            "/api/option/waffo-pancake/save",
            "generic",
            200,
            false,
        )
        .await;
        return waffo_error(MSG_SAVE_FAILED);
    }
    record_option_route_audit(
        &state,
        &auth_user,
        &headers,
        "POST",
        "/api/option/waffo-pancake/save",
        "generic",
        200,
        true,
    )
    .await;
    Json(json!({
        "message": "success",
        "data": {
            "product_id": product_id,
            "store_id": store_id,
        },
    }))
    .into_response()
}

/// Go `billing.CreateWaffoPancakeSubscriptionProduct`
/// （`topup_waffo_pancake.go:248-295`）：以持久化凭据 + StoreID 为套餐
/// 铸品（实际是 OnetimeProduct + 发布）。
pub async fn waffo_subscription_product(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
    injected: Option<Extension<InjectedPancakeTransport>>,
    body: Bytes,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    #[derive(Deserialize, Default)]
    struct CreateWaffoPancakeSubscriptionProductRequest {
        #[serde(default)]
        name: String,
        #[serde(default)]
        amount: String,
    }
    let request: CreateWaffoPancakeSubscriptionProductRequest = if body.is_empty() {
        CreateWaffoPancakeSubscriptionProductRequest::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(_) => return waffo_error(MSG_BAD_PARAMS),
        }
    };
    if request.name.trim().is_empty() {
        return waffo_error(MSG_PLAN_NAME_REQUIRED);
    }
    if request.amount.trim().is_empty() {
        return waffo_error(MSG_PLAN_AMOUNT_REQUIRED);
    }
    let (merchant_id, private_key) = match resolve_waffo_creds(&db, "", "").await {
        Ok(pair) => pair,
        Err(_) => return waffo_error(MSG_BAD_PARAMS),
    };
    let values =
        match load_option_values(&db, &["WaffoPancakeStoreID", "WaffoPancakeReturnURL"]).await {
            Ok(values) => values,
            Err(_) => return waffo_error(MSG_BAD_PARAMS),
        };
    let store_id = values
        .get("WaffoPancakeStoreID")
        .map(String::as_str)
        .unwrap_or("")
        .trim()
        .to_owned();
    let return_url = values
        .get("WaffoPancakeReturnURL")
        .cloned()
        .unwrap_or_default();
    if merchant_id.trim().is_empty() || private_key.trim().is_empty() || store_id.is_empty() {
        return waffo_error(MSG_PANCAKE_NOT_BOUND);
    }
    let transport: &dyn PancakeTransport = match injected.as_ref() {
        Some(injected) => injected.0.0.as_ref(),
        None => &HttpPancakeTransport,
    };
    let (response, success) = match transport
        .create_product(
            &merchant_id,
            &private_key,
            &store_id,
            request.name.trim(),
            request.amount.trim(),
            &return_url,
        )
        .await
    {
        Ok(product_id) => (
            Json(json!({
                "message": "success",
                "data": {
                    "product_id": product_id,
                    "product_name": request.name.trim(),
                    "store_id": store_id,
                },
            }))
            .into_response(),
            true,
        ),
        Err(error) => {
            tracing::warn!(
                "Waffo Pancake 创建套餐产品失败 store_id={store_id:?} name={:?} amount={:?} error={:?}",
                request.name.trim(),
                request.amount.trim(),
                error.0
            );
            (waffo_error(MSG_PRODUCT_CREATE_FAILED), false)
        }
    };
    record_option_route_audit(
        &state,
        &auth_user,
        &headers,
        "POST",
        "/api/option/waffo-pancake/subscription-product",
        "generic",
        200,
        success,
    )
    .await;
    response
}

/// Go `billing.ListWaffoPancakeSubscriptionProductOptions`
/// （`topup_waffo_pancake.go:300-329`）：持久化店铺下的 OnetimeProducts，
/// 供订阅套餐下拉。
pub async fn waffo_subscription_product_options(
    State(state): State<AppState>,
    Extension(_auth_user): Extension<AuthenticatedUser>,
    _headers: HeaderMap,
    injected: Option<Extension<InjectedPancakeTransport>>,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let (merchant_id, private_key) = match resolve_waffo_creds(&db, "", "").await {
        Ok(pair) => pair,
        Err(_) => return waffo_error(MSG_BAD_PARAMS),
    };
    let values = match load_option_values(&db, &["WaffoPancakeStoreID"]).await {
        Ok(values) => values,
        Err(_) => return waffo_error(MSG_BAD_PARAMS),
    };
    let store_id = values
        .get("WaffoPancakeStoreID")
        .map(String::as_str)
        .unwrap_or("")
        .trim()
        .to_owned();
    if merchant_id.trim().is_empty() || private_key.trim().is_empty() || store_id.is_empty() {
        return waffo_error(MSG_PANCAKE_NOT_BOUND);
    }
    let transport: &dyn PancakeTransport = match injected.as_ref() {
        Some(injected) => injected.0.0.as_ref(),
        None => &HttpPancakeTransport,
    };
    let catalog: WaffoPancakeCatalog = match transport.catalog(&merchant_id, &private_key).await {
        Ok(catalog) => catalog,
        Err(error) => {
            tracing::warn!(
                "Waffo Pancake 拉取订阅产品列表失败 store_id={store_id:?} error={:?}",
                error.0
            );
            return waffo_error(MSG_PRODUCT_LIST_FAILED);
        }
    };
    let products = catalog
        .stores
        .iter()
        .find(|store| store.id == store_id)
        .map(|store| store.onetime_products.clone())
        .unwrap_or_default();
    Json(json!({
        "message": "success",
        "data": {
            "store_id": store_id,
            "products": products,
        },
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// 共用小件
// ---------------------------------------------------------------------------

/// `{message: "error", data: <固定文案>}` 的 waffo 信封（HTTP 200）。
fn waffo_error(message: &str) -> Response {
    Json(json!({ "message": "error", "data": message })).into_response()
}

/// Go 兜底审计（写方法、AdminAuth 组、handler 未手动埋点）。三个固定
/// action 之外（waffo-pancake 写路径）落 `generic`。Go 把写入丢进
/// `gopool.Go`，但响应与写入的可观察顺序无保证；本端口内联 `await`，
/// 保证 handler 返回前审计已落库（测试断言依赖该顺序）。失败仅告警。
async fn record_option_route_audit(
    state: &AppState,
    auth_user: &AuthenticatedUser,
    headers: &HeaderMap,
    method: &'static str,
    route: &'static str,
    action: &'static str,
    status: u16,
    success: bool,
) {
    let Some(db) = state.db() else {
        return;
    };
    let operator = audit_operator(auth_user);
    let ip = request_ip(state, headers);
    record_route_audit(
        &db,
        RouteAudit {
            operator: &operator,
            action,
            method,
            route,
            path: route,
            status,
            success,
            route_params: Vec::new(),
            ip: &ip,
            now: crate::http::now_seconds(),
        },
    )
    .await;
}

/// Go `auditAuthMethod`：PAT → `access_token`，会话 → `session`。
fn audit_operator(user: &AuthenticatedUser) -> AuditOperator<'_> {
    AuditOperator {
        user_id: user.0.user_id,
        username: &user.0.username,
        role: user.0.role,
        auth_method: match user.0.credential {
            CredentialKind::DashboardSession => "session",
            CredentialKind::PersonalAccessToken => "access_token",
        },
    }
}

fn request_ip(state: &AppState, headers: &HeaderMap) -> String {
    crate::http::request_ip(state, headers, None)
}

/// 固定键的 200 失败 envelope（数据库故障脱敏约定；故障分支不经 i18n
/// 请求上下文，按默认语言呈现）。
fn database_error_json() -> Response {
    Json(json!({
        "success": false,
        "message": translate_static(MSG_DATABASE_ERROR),
    }))
    .into_response()
}

fn rejected_i18n(headers: &HeaderMap, key: &str) -> Response {
    Json(json!({
        "success": false,
        "message": translate(headers, key),
    }))
    .into_response()
}

fn translate(headers: &HeaderMap, key: &str) -> String {
    let accept_language = crate::request_lang::accept_language_header(headers);
    let language = crate::request_lang::request_language(accept_language.as_deref());
    newapi_i18n::translate(&language, key, std::iter::empty::<(&str, &str)>())
}

/// 无请求头上下文时的英文翻译（数据库错误等故障分支，Go 走 CtxApiError
/// 原文；这里以默认语言固定键呈现）。
fn translate_static(key: &str) -> String {
    newapi_i18n::translate(
        newapi_i18n::DEFAULT_LANG,
        key,
        std::iter::empty::<(&str, &str)>(),
    )
}

/// Go `c.Query(key)`：fasthttp `Args.Peek` 语义——重复键取首值，解码按
/// `application/x-www-form-urlencoded`（`+` 为空格，`%XX` 按字节；不完整
/// 或非法转义保持原样）。复用 `turnstile` 模块的同款解码实现。
fn query_value(uri: &axum::http::Uri, key: &str) -> String {
    let query = uri.query().unwrap_or("");
    for pair in query.split('&') {
        let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        if crate::turnstile::decode_query_component(raw_key) == key {
            return crate::turnstile::decode_query_component(raw_value);
        }
    }
    String::new()
}
