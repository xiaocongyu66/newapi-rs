//! `GET /api/pricing` HTTP 适配（Go `ops.GetPricing`，
//! `manage_model_metadata.go:366-405`；路由
//! `transport/compose/register_api.go:48`）。
//!
//! Go 中间件是 `HeaderNavModuleAuth("pricing")`：`HeaderNavModules` 选项里
//! `pricing` 模块的 enabled/requireAuth 门（`gate_header_nav.go:105-124`）。
//! 缺省（空/非法/缺键）= enabled 且不要求登录 → `TryUserAuth` 宽松认证
//! （匿名可见，带凭据则补用户分组上下文）。Rust 侧以 `try_user_auth` 层 +
//! handler 内的门检查逐字复刻。
//!
//! 响应键与 Go 完全一致：`success`、`data`（按用户可用分组过滤后的
//! `Pricing` 列表）、`vendors`、`group_ratio`（GroupGroupRatio 覆盖后裁剪到
//! 可用分组）、`usable_group`、`supported_endpoint`、`auto_groups`、
//! `pricing_version`（Go 硬编码 `a42d372ccf0b5dd13ecf71203521f9d2`）。
//!
//! 定价数据来自 `newapi_catalog::pricing` 全局缓存（1 分钟 TTL，Go
//! `GetPricing` 同语义）；分组面来自 `AppState::group_settings()` 快照。

use std::collections::BTreeMap;

use axum::{
    Extension, Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::{Map, Value, json};

use crate::AppState;
use crate::auth::AuthenticatedUser;

/// Go `GetPricing` 响应里的硬编码版本串
/// （`manage_model_metadata.go:403`）。
const API_PRICING_VERSION: &str = "a42d372ccf0b5dd13ecf71203521f9d2";

/// Go `filterPricingByUsableGroups`（`manage_model_metadata.go:188-210`）：
/// `enable_groups` 含 `all` 的条目恒可见；否则任一启用分组在用户可用集合
/// 内才可见。空可用集合 → 全部过滤（Go 返回空切片）。
fn filter_pricing_by_usable_groups(
    pricing: &[newapi_catalog::pricing::Pricing],
    usable_group: &BTreeMap<String, String>,
) -> Vec<newapi_catalog::pricing::Pricing> {
    if pricing.is_empty() {
        return Vec::new();
    }
    if usable_group.is_empty() {
        return Vec::new();
    }
    pricing
        .iter()
        .filter(|item| {
            item.enable_groups
                .iter()
                .any(|group| group == "all" || usable_group.contains_key(group))
        })
        .cloned()
        .collect()
}

/// Go `parseHeaderNavBool`（`gate_header_nav.go:82-103`）的布尔分支子集：
/// JSON 门值只可能是 bool（`serde_json` 反序列化后的 Map 值）。
fn parse_header_nav_bool(value: &Value, fallback: bool) -> bool {
    match value {
        Value::Bool(v) => *v,
        Value::String(v) => match v.trim().to_ascii_lowercase().as_str() {
            "true" | "1" => true,
            "false" | "0" => false,
            _ => fallback,
        },
        Value::Number(v) if v.as_f64() == Some(1.0) => true,
        Value::Number(v) if v.as_f64() == Some(0.0) => false,
        _ => fallback,
    }
}

/// Go `parseHeaderNavAccess`（`gate_header_nav.go:40-80`）：返回
/// `(enabled, require_auth)`。
fn parse_header_nav_access(raw: Option<&Value>) -> (bool, bool) {
    let fallback = (true, false);
    let Some(Value::Object(object)) = raw else {
        return fallback;
    };
    let mut access = fallback;
    if let Some(enabled) = object.get("enabled") {
        access.0 = parse_header_nav_bool(enabled, fallback.0);
    }
    if let Some(require_auth) = object.get("requireAuth") {
        access.1 = parse_header_nav_bool(require_auth, fallback.1);
    }
    access
}

/// Go `getHeaderNavAccess`（`gate_header_nav.go:18-38`）：读 `options` 表的
/// `HeaderNavModules`，JSON 解析失败回退默认（Go 读 OptionMap 内存缓存；
/// Rust 侧直接查库，单键 SELECT 的代价与 Go 的内存读同量级）。
async fn header_nav_access(db: &newapi_storage::Database) -> (bool, bool) {
    let raw: Option<(String,)> = match db {
        newapi_storage::Database::Sqlite(pool) => {
            sqlx::query_as("SELECT value FROM options WHERE key = ?")
                .bind("HeaderNavModules")
                .fetch_optional(pool)
                .await
                .unwrap_or(None)
        }
        newapi_storage::Database::Postgres(pool) => {
            sqlx::query_as("SELECT value FROM options WHERE key = $1")
                .bind("HeaderNavModules")
                .fetch_optional(pool)
                .await
                .unwrap_or(None)
        }
    };
    let Some((raw,)) = raw else {
        return (true, false);
    };
    if raw.trim().is_empty() {
        return (true, false);
    }
    let parsed: Option<Value> = serde_json::from_str(raw.trim()).ok();
    let module = parsed.as_ref().and_then(|value| value.get("pricing"));
    parse_header_nav_access(module)
}

/// Go `security.UserAuth` 失败体（`writeDashboardAuthError` 的
/// `AUTH_UNAUTHORIZED` 形态）：401 + JSON 信封。
fn user_auth_failure() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "success": false,
            "message": "无权进行此操作，未登录且未提供 access token",
        })),
    )
        .into_response()
}

/// `GET /api/pricing`：Go `ops.GetPricing`。认证扩展由路由层的
/// `try_user_auth` 写入（Go `HeaderNavModuleAuth("pricing")` 缺省走
/// `TryUserAuth`）；`requireAuth` 门在此 handler 内判定。
pub async fn get_pricing(
    State(state): State<AppState>,
    authenticated: Option<Extension<AuthenticatedUser>>,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let (enabled, require_auth) = header_nav_access(&db).await;
    if !enabled {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "success": false,
                "message": "pricing is disabled",
            })),
        )
            .into_response();
    }
    // Go：`userId, exists := c.Get("id")`；requireAuth 门缺用户时
    // `security.UserAuth()` 以 401 终止（`gate_header_nav.go:117-119`）。
    let user_group = match authenticated {
        Some(Extension(user)) => user.0.group.clone(),
        None if require_auth => return user_auth_failure(),
        None => String::new(),
    };

    let group_settings = state.group_settings();
    let ratio_settings = state.ratio_settings();
    let snapshot =
        match newapi_catalog::pricing::get_pricing(&db, &ratio_settings, &group_settings).await {
            Ok(snapshot) => snapshot,
            Err(error) => {
                tracing::warn!(
                    event = "pricing_load_failed",
                    category = crate::database_error_class(&error),
                    "pricing load failed"
                );
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
        };

    let mut group_ratio: BTreeMap<String, f64> = group_settings.group_ratio.clone();
    let usable_group = group_settings.user_usable_groups(&user_group);
    for group in group_settings.group_ratio.keys() {
        if let Some(per_user) = group_settings
            .group_group_ratio
            .get(&user_group)
            .and_then(|ratios| ratios.get(group))
        {
            group_ratio.insert(group.clone(), *per_user);
        }
    }
    let filtered = filter_pricing_by_usable_groups(&snapshot.pricing, &usable_group);
    // Go：可用集合之外的 group_ratio 键被删除（`manage_model_metadata.go:389-393`）。
    let group_ratio: BTreeMap<String, f64> = group_ratio
        .into_iter()
        .filter(|(group, _)| usable_group.contains_key(group))
        .collect();

    let data: Vec<Value> = filtered
        .iter()
        .map(|item| serde_json::to_value(item).unwrap_or(Value::Null))
        .collect();
    let vendors: Vec<Value> = snapshot
        .vendors
        .iter()
        .map(|vendor| serde_json::to_value(vendor).unwrap_or(Value::Null))
        .collect();
    let supported_endpoint: Map<String, Value> = snapshot
        .supported_endpoint_map
        .iter()
        .map(|(endpoint, info)| {
            (
                endpoint.clone(),
                json!({"path": info.path, "method": info.method}),
            )
        })
        .collect();

    Json(json!({
        "success": true,
        "data": data,
        "vendors": vendors,
        "group_ratio": group_ratio,
        "usable_group": usable_group,
        "supported_endpoint": supported_endpoint,
        "auto_groups": group_settings.user_auto_group(&user_group),
        "pricing_version": API_PRICING_VERSION,
    }))
    .into_response()
}
