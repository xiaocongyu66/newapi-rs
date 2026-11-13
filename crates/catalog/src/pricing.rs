//! 定价缓存（`store_pricing.go` 477 行的移植）：`Pricing`/`PricingVendor`
//! 结构、端点类型推断、供应商默认映射、全局缓存（1 分钟 TTL + 强制刷新 +
//! 失效）与高并发快速映射（`modelEnableGroups`/`modelQuotaTypeMap`）。
//!
//! Go 参考（`/root/newapi/apps/api/internal/catalog`）：
//! - `store_pricing.go`：`GetPricing`/`InvalidatePricingCache`/`GetVendors`/
//!   `GetModelSupportEndpointTypes`/`updatePricing`/`GetSupportedEndpointMap`
//! - `store_pricing_refresh.go`：`RefreshPricing`（绕过 TTL 的强制刷新）
//! - `store_pricing_default.go`：`initDefaultVendorMapping`/
//!   `getOrCreateVendor`（缓存重建时按模型名补建默认供应商行）
//! - `store_model_extra.go`：`GetModelEnableGroups`/`GetModelQuotaTypes`
//! - `common/endpoint_type.go` + `common/endpoint_defaults.go` +
//!   `common/model.go`：渠道类型 → 端点类型与默认 path/method
//! - `store_ability.go:32-40`：`GetAllEnableAbilityWithChannels`
//!
//! 与 Go 语义的登记差异（Go 依赖 map 随机迭代序）：
//! - 能力行按 `(model, channel_id, "group")` 排序后重建，端点/分组列表顺序
//!   确定（Go 每次重建顺序随机；`supported_endpoint_types` 的“第一个端点
//!   优先”语义在同渠道类型序列内保持，与 Go 一致）。
//! - `pricing` 数组按 `model_name` 字典序输出（Go map 迭代随机）。
//! - `enable_groups` 去重后按字典序输出（Go `types.Set.Items()` 随机）。
//!
//! 缓存失效与网关修订号**不**挂钩：Go 定价缓存是独立的时间 TTL +
//! 显式失效机制（`InvalidatePricingCache` 由渠道缓存桥与
//! `settings.OnBillingSettingChanged` 触发），照搬。

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use newapi_storage::Database;
use serde::Serialize;
use sqlx::Row;

use crate::group_settings::GroupSettings;
use crate::ratio_settings::RatioSettings;

/// Go `Pricing.PricingVersion` 常量（`store_pricing.go:416`）：挂在重建后的
/// 第一个条目上。
const PRICING_VERSION: &str = "5a90f2b86c08bd983a9a2e6d66c255f4eaef9c4bc934386d2b6ae84ef0ff1f1f";

/// Go `GetPricing` 的 TTL：1 分钟。
const PRICING_TTL: Duration = Duration::from_secs(60);

/// 端点类型字符串（Go `relaykit/types.EndpointType`）。
pub mod endpoint_type {
    pub const OPENAI: &str = "openai";
    pub const OPENAI_RESPONSE: &str = "openai-response";
    pub const OPENAI_RESPONSE_COMPACT: &str = "openai-response-compact";
    pub const OPENAI_ALPHA_SEARCH: &str = "openai-alpha-search";
    pub const ANTHROPIC: &str = "anthropic";
    pub const GEMINI: &str = "gemini";
    pub const JINA_RERANK: &str = "jina-rerank";
    pub const IMAGE_GENERATION: &str = "image-generation";
    pub const EMBEDDINGS: &str = "embeddings";
    pub const OPENAI_VIDEO: &str = "openai-video";
}

/// 渠道类型常量（Go `constant/channel.go`）。
mod channel_type {
    pub const ANTHROPIC: i64 = 14;
    pub const OPEN_ROUTER: i64 = 20;
    pub const GEMINI: i64 = 24;
    pub const AWS: i64 = 33;
    pub const JINA: i64 = 38;
    pub const VERTEX_AI: i64 = 41;
    pub const XAI: i64 = 48;
    pub const SORA: i64 = 55;
    pub const CODEX: i64 = 57;
    pub const ADVANCED_CUSTOM: i64 = 58;
    pub const SUB2API: i64 = 59;
    pub const NEW_API: i64 = 60;
}

/// Go `common.EndpointInfo`（`endpoint_defaults.go:12-16`）：path/method
/// 为动态串（自定义端点覆盖）。
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EndpointInfo {
    pub path: String,
    pub method: String,
}

/// Go `defaultEndpointInfoMap`（`endpoint_defaults.go:23-33`）。
pub fn default_endpoint_info(endpoint: &str) -> Option<EndpointInfo> {
    let (path, method) = match endpoint {
        endpoint_type::OPENAI => ("/v1/chat/completions", "POST"),
        endpoint_type::OPENAI_RESPONSE => ("/v1/responses", "POST"),
        endpoint_type::OPENAI_RESPONSE_COMPACT => ("/v1/responses/compact", "POST"),
        endpoint_type::OPENAI_ALPHA_SEARCH => ("/v1/alpha/search", "POST"),
        endpoint_type::ANTHROPIC => ("/v1/messages", "POST"),
        endpoint_type::GEMINI => ("/v1beta/models/{model}:generateContent", "POST"),
        endpoint_type::JINA_RERANK => ("/v1/rerank", "POST"),
        endpoint_type::IMAGE_GENERATION => ("/v1/images/generations", "POST"),
        endpoint_type::EMBEDDINGS => ("/v1/embeddings", "POST"),
        _ => return None,
    };
    Some(EndpointInfo {
        path: path.to_owned(),
        method: method.to_owned(),
    })
}

/// Go `OpenAIResponseOnlyModels`（`common/model.go:8-12`）：子串包含匹配。
const OPENAI_RESPONSE_ONLY_MODELS: [&str; 3] =
    ["o3-pro", "o3-deep-research", "o4-mini-deep-research"];

/// Go `ImageGenerationModels`（`common/model.go:13-20`）：子串包含匹配，
/// `prefix:` 条目改为前缀匹配；整体小写化后比较。
const IMAGE_GENERATION_MODELS: [&str; 6] = [
    "dall-e-3",
    "dall-e-2",
    "gpt-image-1",
    "prefix:imagen-",
    "flux-",
    "flux.1-",
];

/// Go `IsOpenAIResponseOnlyModel`（`common/model.go:29-36`）。
pub fn is_openai_response_only_model(model_name: &str) -> bool {
    OPENAI_RESPONSE_ONLY_MODELS
        .iter()
        .any(|m| model_name.contains(m))
}

/// Go `IsImageGenerationModel`（`common/model.go:38-49`）。
pub fn is_image_generation_model(model_name: &str) -> bool {
    let model_name = model_name.to_ascii_lowercase();
    for m in IMAGE_GENERATION_MODELS {
        if let Some(prefix) = m.strip_prefix("prefix:") {
            if model_name.starts_with(prefix) {
                return true;
            }
        } else if model_name.contains(m) {
            return true;
        }
    }
    false
}

/// Go `GetEndpointTypesByChannelType`（`common/endpoint_type.go:6-60`）。
pub fn get_endpoint_types_by_channel_type(
    channel_type: i64,
    model_name: &str,
) -> Vec<&'static str> {
    let mut endpoints: Vec<&'static str> = match channel_type {
        channel_type::JINA => vec![endpoint_type::JINA_RERANK],
        channel_type::AWS | channel_type::ANTHROPIC => {
            vec![endpoint_type::ANTHROPIC, endpoint_type::OPENAI]
        }
        channel_type::VERTEX_AI | channel_type::GEMINI => {
            vec![endpoint_type::GEMINI, endpoint_type::OPENAI]
        }
        channel_type::OPEN_ROUTER => vec![endpoint_type::OPENAI],
        channel_type::XAI => vec![endpoint_type::OPENAI, endpoint_type::OPENAI_RESPONSE],
        channel_type::SORA => vec![endpoint_type::OPENAI_VIDEO],
        channel_type::SUB2API | channel_type::NEW_API => vec![
            endpoint_type::OPENAI,
            endpoint_type::OPENAI_RESPONSE,
            endpoint_type::OPENAI_RESPONSE_COMPACT,
            endpoint_type::ANTHROPIC,
            endpoint_type::GEMINI,
            endpoint_type::OPENAI_ALPHA_SEARCH,
        ],
        channel_type::CODEX => vec![
            endpoint_type::OPENAI_RESPONSE,
            endpoint_type::OPENAI_RESPONSE_COMPACT,
            endpoint_type::OPENAI_ALPHA_SEARCH,
        ],
        _ => {
            if is_openai_response_only_model(model_name) {
                vec![endpoint_type::OPENAI_RESPONSE]
            } else {
                vec![endpoint_type::OPENAI]
            }
        }
    };
    if is_image_generation_model(model_name) {
        // Go：加到最前。
        endpoints.insert(0, endpoint_type::IMAGE_GENERATION);
    }
    endpoints
}

// ---------------------------------------------------------------------------
// Advanced Custom（渠道类型 58）端点推断
// ---------------------------------------------------------------------------

/// Go `dto.AdvancedCustomRoute` 的只读子集（`channels::validation` 已有完整
/// 结构，这里直接复用其反序列化结果）。
use crate::channels::validation::AdvancedCustomConfig;

/// Go `advancedCustomEndpointTypeFromIncomingPath`
/// （`channel_settings.go:263-292`）。
fn advanced_custom_endpoint_type_from_incoming_path(path: &str) -> Option<&'static str> {
    match path {
        "/v1/chat/completions" => Some(endpoint_type::OPENAI),
        "/v1/responses" => Some(endpoint_type::OPENAI_RESPONSE),
        "/v1/responses/compact" => Some(endpoint_type::OPENAI_RESPONSE_COMPACT),
        "/v1/alpha/search" => Some(endpoint_type::OPENAI_ALPHA_SEARCH),
        "/v1/messages" => Some(endpoint_type::ANTHROPIC),
        "/v1/rerank" => Some(endpoint_type::JINA_RERANK),
        "/v1/images/generations" => Some(endpoint_type::IMAGE_GENERATION),
        "/v1/embeddings" => Some(endpoint_type::EMBEDDINGS),
        _ => {
            if path.starts_with("/v1beta/models/")
                && (path.contains(":generateContent") || path.contains(":streamGenerateContent"))
            {
                Some(endpoint_type::GEMINI)
            } else {
                None
            }
        }
    }
}

/// Go `matchAdvancedCustomRouteModelRule`（`channel_settings.go:328-345`）：
/// `re:` 前缀走正则（Go `MatchString` 非锚定），否则精确相等。正则编译失败
/// 视为不匹配（Go 缓存 nil 后不命中）。
fn match_advanced_custom_route_model_rule(rule: &str, model: &str) -> bool {
    match rule.strip_prefix("re:") {
        Some(pattern) if !pattern.is_empty() => regex::Regex::new(pattern)
            .map(|re| re.is_match(model))
            .unwrap_or(false),
        Some(_) => false,
        None => rule == model,
    }
}

/// Go `matchAdvancedCustomRouteModel`（`channel_settings.go:296-307`）：
/// 空列表是 catch-all。
fn match_advanced_custom_route_models(models: &[String], model: &str) -> bool {
    let normalized: Vec<&str> = models
        .iter()
        .map(|m| m.trim())
        .filter(|m| !m.is_empty())
        .collect();
    if normalized.is_empty() {
        return true;
    }
    normalized
        .iter()
        .any(|rule| match_advanced_custom_route_model_rule(rule, model))
}

/// Go `AdvancedCustomConfig.SupportedEndpointTypesForModel`
/// （`channel_settings.go:239-261`）。
pub fn advanced_custom_supported_endpoint_types(
    config: &AdvancedCustomConfig,
    model: &str,
) -> Vec<&'static str> {
    let model = model.trim();
    let mut endpoints: Vec<&'static str> = Vec::with_capacity(config.routes.len());
    let mut seen = BTreeSet::new();
    for route in &config.routes {
        if !match_advanced_custom_route_models(&route.models, model) {
            continue;
        }
        let Some(endpoint) =
            advanced_custom_endpoint_type_from_incoming_path(route.incoming_path.trim())
        else {
            continue;
        };
        if seen.insert(endpoint) {
            endpoints.push(endpoint);
        }
    }
    endpoints
}

/// Go `getPricingEndpointTypesForAbility`（`store_pricing.go:117-125`）：
/// 类型 58 渠道走 advanced_custom 路由配置（无配置回落原生推断），其余走
/// 渠道类型映射。
fn pricing_endpoint_types_for_ability(
    ability: &AbilityWithChannel,
    advanced_custom_configs: &BTreeMap<i64, AdvancedCustomConfig>,
) -> Vec<&'static str> {
    if ability.channel_type != channel_type::ADVANCED_CUSTOM {
        return get_endpoint_types_by_channel_type(ability.channel_type, &ability.model);
    }
    if let Some(config) = advanced_custom_configs.get(&ability.channel_id) {
        return advanced_custom_supported_endpoint_types(config, &ability.model);
    }
    get_endpoint_types_by_channel_type(ability.channel_type, &ability.model)
}

// ---------------------------------------------------------------------------
// 数据结构与全局缓存
// ---------------------------------------------------------------------------

/// Go `Pricing`（`store_pricing.go:25-46`），JSON 契约逐字对齐。
#[derive(Clone, Debug, Default, Serialize)]
pub struct Pricing {
    #[serde(rename = "model_name")]
    pub model_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub icon: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub tags: String,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub vendor_id: i64,
    #[serde(rename = "quota_type")]
    pub quota_type: i64,
    #[serde(rename = "model_ratio")]
    pub model_ratio: f64,
    #[serde(rename = "model_price")]
    pub model_price: f64,
    /// Go 固定空串（`OwnerBy` 无赋值点）。
    #[serde(rename = "owner_by")]
    pub owner_by: String,
    #[serde(rename = "completion_ratio")]
    pub completion_ratio: f64,
    #[serde(rename = "cache_ratio", skip_serializing_if = "Option::is_none")]
    pub cache_ratio: Option<f64>,
    #[serde(rename = "create_cache_ratio", skip_serializing_if = "Option::is_none")]
    pub create_cache_ratio: Option<f64>,
    #[serde(rename = "image_ratio", skip_serializing_if = "Option::is_none")]
    pub image_ratio: Option<f64>,
    #[serde(rename = "audio_ratio", skip_serializing_if = "Option::is_none")]
    pub audio_ratio: Option<f64>,
    #[serde(
        rename = "audio_completion_ratio",
        skip_serializing_if = "Option::is_none"
    )]
    pub audio_completion_ratio: Option<f64>,
    #[serde(rename = "enable_groups")]
    pub enable_groups: Vec<String>,
    #[serde(rename = "supported_endpoint_types")]
    pub supported_endpoint_types: Vec<String>,
    #[serde(rename = "billing_mode", skip_serializing_if = "String::is_empty")]
    pub billing_mode: String,
    #[serde(rename = "billing_expr", skip_serializing_if = "String::is_empty")]
    pub billing_expr: String,
    #[serde(rename = "pricing_version", skip_serializing_if = "String::is_empty")]
    pub pricing_version: String,
}

/// Go `PricingVendor`（`store_pricing.go:48-53`）。
#[derive(Clone, Debug, Serialize)]
pub struct PricingVendor {
    pub id: i64,
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub icon: String,
}

/// Go `AbilityWithChannel`（`store_ability.go`）的读视图。
#[derive(Clone, Debug)]
pub struct AbilityWithChannel {
    pub group: String,
    pub model: String,
    pub channel_id: i64,
    pub channel_type: i64,
}

/// Go `Model`（`store_model_meta.go:20-36`）的定价重建读视图。
#[derive(Clone, Debug, Default)]
pub struct ModelMeta {
    pub model_name: String,
    pub description: String,
    pub icon: String,
    pub tags: String,
    pub vendor_id: i64,
    pub endpoints: String,
    pub status: i64,
    pub name_rule: i64,
}

/// Go `NameRule*`（`store_model_meta.go:8-13`）。
pub const NAME_RULE_EXACT: i64 = 0;
pub const NAME_RULE_PREFIX: i64 = 1;
pub const NAME_RULE_CONTAINS: i64 = 2;
pub const NAME_RULE_SUFFIX: i64 = 3;

/// 一次重建产出的不可变快照。`Arc` 共享，读路径零拷贝。
#[derive(Default)]
pub struct PricingSnapshot {
    pub pricing: Vec<Pricing>,
    pub vendors: Vec<PricingVendor>,
    /// Go `supportedEndpointMap`（`store_pricing.go:321-357`）。
    pub supported_endpoint_map: BTreeMap<String, EndpointInfo>,
    /// Go `modelSupportEndpointTypes`。
    pub model_support_endpoint_types: BTreeMap<String, Vec<String>>,
    /// Go `modelEnableGroups`。
    pub model_enable_groups: BTreeMap<String, Vec<String>>,
    /// Go `modelQuotaTypeMap`。
    pub model_quota_type_map: BTreeMap<String, i64>,
}

impl PricingSnapshot {
    /// Go `GetModelSupportEndpointTypes`（`store_pricing.go:105-115`）。
    pub fn model_support_endpoint_types(&self, model: &str) -> Vec<String> {
        if model.is_empty() {
            return Vec::new();
        }
        self.model_support_endpoint_types
            .get(model)
            .cloned()
            .unwrap_or_default()
    }

    /// Go `GetModelEnableGroups`（`store_model_extra.go:3-17`）。
    pub fn model_enable_groups(&self, model_name: &str) -> Vec<String> {
        if model_name.is_empty() {
            return Vec::new();
        }
        self.model_enable_groups
            .get(model_name)
            .cloned()
            .unwrap_or_default()
    }

    /// Go `GetModelQuotaTypes`（`store_model_extra.go:21-32`）：单元素列表。
    pub fn model_quota_types(&self, model_name: &str) -> Vec<i64> {
        match self.model_quota_type_map.get(model_name) {
            Some(quota) => vec![*quota],
            None => Vec::new(),
        }
    }
}

/// Go `OnResolveTieredBilling`（`store_pricing.go:23`）：计费域注册的阶梯
/// 计费解析钩子。未注册 = 无阶梯计费（Go nil 等价）。
pub type TieredBillingResolver = fn(model: &str) -> Option<(String, String)>;

static TIERED_BILLING_RESOLVER: Mutex<Option<TieredBillingResolver>> = Mutex::new(None);

pub fn register_tiered_billing_resolver(resolver: Option<TieredBillingResolver>) {
    *TIERED_BILLING_RESOLVER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = resolver;
}

struct CacheState {
    snapshot: Option<std::sync::Arc<PricingSnapshot>>,
    refreshed_at: Option<Instant>,
    /// Go `lastGroupRatioGapAudit`：同一缺失集合只告警一次。
    last_group_ratio_gap_audit: String,
}

static CACHE: Mutex<CacheState> = Mutex::new(CacheState {
    snapshot: None,
    refreshed_at: None,
    last_group_ratio_gap_audit: String::new(),
});

fn cache_lock() -> std::sync::MutexGuard<'static, CacheState> {
    CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Go `vendor_id,omitempty` 的 i64 零值判定。
fn is_zero_i64(value: &i64) -> bool {
    *value == 0
}

/// Go `InvalidatePricingCache`（`store_pricing.go:87-94`）。
pub fn invalidate_pricing_cache() {
    let mut state = cache_lock();
    state.snapshot = None;
    state.refreshed_at = None;
}

/// Go `common.ContainsTopupGroupRatio` 的键集读取：`TopupGroupRatio` 选项是
/// `map[string]float64` JSON；空/缺失/非法 → 空集。
fn parse_topup_group_keys(raw: Option<String>) -> BTreeSet<String> {
    let Some(raw) = raw else {
        return BTreeSet::new();
    };
    let Ok(parsed) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(raw.trim())
    else {
        return BTreeSet::new();
    };
    parsed.keys().cloned().collect()
}

/// Go `RefreshPricing`（`store_pricing_refresh.go:6-14`）：绕过 TTL 强制
/// 重建。重建失败（DB 错误）向上传播，调用方按 Go 的日志-吞错语义自行决定
/// （HTTP 边界回 503，符合仓库“不编造数据”约定）。
pub async fn refresh_pricing(
    db: &Database,
    ratios: &RatioSettings,
    groups: &GroupSettings,
) -> Result<std::sync::Arc<PricingSnapshot>, sqlx::Error> {
    let snapshot = std::sync::Arc::new(update_pricing(db, ratios, groups).await?);
    let mut state = cache_lock();
    state.snapshot = Some(std::sync::Arc::clone(&snapshot));
    state.refreshed_at = Some(Instant::now());
    Ok(snapshot)
}

/// Go `GetPricing`（`store_pricing.go:73-85`）：TTL 过期或缓存为空时重建
/// （double check 在互斥锁内天然完成）。重建失败传播错误（Go 记日志返回
/// 旧缓存；Rust 侧按仓库约定不编造空快照）。
pub async fn get_pricing(
    db: &Database,
    ratios: &RatioSettings,
    groups: &GroupSettings,
) -> Result<std::sync::Arc<PricingSnapshot>, sqlx::Error> {
    {
        let state = cache_lock();
        if let (Some(snapshot), Some(at)) = (&state.snapshot, state.refreshed_at)
            && at.elapsed() <= PRICING_TTL
        {
            return Ok(std::sync::Arc::clone(snapshot));
        }
    }
    // Go：重建失败记日志并返回旧缓存（updatePricing 保持旧值）；无旧缓存
    // 时错误向上传播。
    if let Err(error) = refresh_pricing(db, ratios, groups).await {
        tracing::warn!(
            event = "pricing_rebuild_failed",
            "pricing rebuild failed; keeping previous cache"
        );
        let state = cache_lock();
        if let Some(snapshot) = &state.snapshot {
            return Ok(std::sync::Arc::clone(snapshot));
        }
        return Err(error);
    }
    let state = cache_lock();
    Ok(std::sync::Arc::clone(
        state
            .snapshot
            .as_ref()
            .expect("refresh_pricing populated cache"),
    ))
}

/// Go `GetVendors`（`store_pricing.go:97-103`）：必要时先触发刷新。
pub async fn vendors(
    db: &Database,
    ratios: &RatioSettings,
    groups: &GroupSettings,
) -> Result<Vec<PricingVendor>, sqlx::Error> {
    Ok(get_pricing(db, ratios, groups).await?.vendors.clone())
}

// ---------------------------------------------------------------------------
// 重建
// ---------------------------------------------------------------------------

/// Go `GetAllEnableAbilityWithChannels`（`store_ability.go:32-40`）：启用
/// 能力左连渠道类型。排序约定见模块注释（Go 依赖扫描序）。
async fn all_enable_abilities_with_channels(
    db: &Database,
) -> Result<Vec<AbilityWithChannel>, sqlx::Error> {
    match db {
        Database::Sqlite(pool) => {
            let rows = sqlx::query(
                "SELECT a.\"group\" AS grp, a.model, a.channel_id, \
                 COALESCE(c.\"type\", 0) AS channel_type \
                 FROM abilities a LEFT JOIN channels c ON a.channel_id = c.id \
                 WHERE a.enabled = ? \
                 ORDER BY a.model, a.channel_id, a.\"group\"",
            )
            .bind(true)
            .fetch_all(pool)
            .await?;
            Ok(rows
                .into_iter()
                .map(|row| AbilityWithChannel {
                    group: row.try_get("grp").unwrap_or_default(),
                    model: row.try_get("model").unwrap_or_default(),
                    channel_id: row.try_get("channel_id").unwrap_or_default(),
                    channel_type: row.try_get("channel_type").unwrap_or_default(),
                })
                .collect())
        }
        Database::Postgres(pool) => {
            let rows = sqlx::query(
                "SELECT a.\"group\" AS grp, a.model, a.channel_id, \
                 COALESCE(c.\"type\", 0) AS channel_type \
                 FROM abilities a LEFT JOIN channels c ON a.channel_id = c.id \
                 WHERE a.enabled = $1 \
                 ORDER BY a.model, a.channel_id, a.\"group\"",
            )
            .bind(true)
            .fetch_all(pool)
            .await?;
            Ok(rows
                .into_iter()
                .map(|row| AbilityWithChannel {
                    group: row.try_get("grp").unwrap_or_default(),
                    model: row.try_get("model").unwrap_or_default(),
                    channel_id: row.try_get("channel_id").unwrap_or_default(),
                    channel_type: row.try_get("channel_type").unwrap_or_default(),
                })
                .collect())
        }
    }
}

/// Go `store_pricing_default.go` 的默认供应商规则（数组化保证确定性；Go 是
/// map，迭代序随机，存在多 pattern 命中时 Go 结果不定——这里取数组序）。
const DEFAULT_VENDOR_RULES: [(&str, &str); 30] = [
    ("gpt", "OpenAI"),
    ("dall-e", "OpenAI"),
    ("whisper", "OpenAI"),
    ("o1", "OpenAI"),
    ("o3", "OpenAI"),
    ("claude", "Anthropic"),
    ("gemini", "Google"),
    ("moonshot", "Moonshot"),
    ("kimi", "Moonshot"),
    ("chatglm", "智谱"),
    ("glm-", "智谱"),
    ("qwen", "阿里巴巴"),
    ("deepseek", "DeepSeek"),
    ("abab", "MiniMax"),
    ("minimax", "MiniMax"),
    ("ernie", "百度"),
    ("spark", "讯飞"),
    ("hunyuan", "腾讯"),
    ("command", "Cohere"),
    ("@cf/", "Cloudflare"),
    ("360", "360"),
    ("yi", "零一万物"),
    ("jina", "Jina"),
    ("mistral", "Mistral"),
    ("grok", "xAI"),
    ("llama", "Meta"),
    ("doubao", "字节跳动"),
    ("kling", "快手"),
    ("jimeng", "即梦"),
    ("vidu", "Vidu"),
];

/// Go `defaultVendorIcons`（`store_pricing_default.go:33-59`）。
fn default_vendor_icon(vendor_name: &str) -> &'static str {
    match vendor_name {
        "OpenAI" => "OpenAI",
        "Anthropic" => "Claude.Color",
        "Google" => "Gemini.Color",
        "Moonshot" => "Moonshot",
        "智谱" => "Zhipu.Color",
        "阿里巴巴" => "Qwen.Color",
        "DeepSeek" => "DeepSeek.Color",
        "MiniMax" => "Minimax.Color",
        "百度" => "Wenxin.Color",
        "讯飞" => "Spark.Color",
        "腾讯" => "Hunyuan.Color",
        "Cohere" => "Cohere.Color",
        "Cloudflare" => "Cloudflare.Color",
        "360" => "Ai360.Color",
        "零一万物" => "Yi.Color",
        "Jina" => "Jina",
        "Mistral" => "Mistral.Color",
        "xAI" => "XAI",
        "Meta" => "Ollama",
        "字节跳动" => "Doubao.Color",
        "快手" => "Kling.Color",
        "即梦" => "Jimeng.Color",
        "Vidu" => "Vidu",
        "微软" => "AzureAI",
        "Microsoft" => "AzureAI",
        "Azure" => "AzureAI",
        _ => "",
    }
}

/// Go `getOrCreateVendor`（`store_pricing_default.go:100-127`）：按名查找，
/// 缺失则插入（经 `mutate_routing!`，与 Go `Vendor.Insert` 一致推进修订号）。
async fn get_or_create_vendor(
    db: &Database,
    vendors: &mut BTreeMap<i64, VendorRow>,
    vendor_name: &str,
    now: i64,
) -> Result<i64, sqlx::Error> {
    for (id, vendor) in vendors.iter() {
        if vendor.name == vendor_name {
            return Ok(*id);
        }
    }
    let icon = default_vendor_icon(vendor_name);
    let id: i64 = crate::mutate_routing!(db, conn, {
        sqlx::query_scalar(
            "INSERT INTO vendors (name, icon, status, created_time, updated_time) \
             VALUES ($1, $2, $3, $4, $5) RETURNING id",
        )
        .bind(vendor_name)
        .bind(icon)
        .bind(1i64)
        .bind(now)
        .bind(now)
        .fetch_one(&mut *conn)
        .await
    })?;
    vendors.insert(
        id,
        VendorRow {
            id,
            name: vendor_name.to_owned(),
            description: String::new(),
            icon: icon.to_owned(),
        },
    );
    Ok(id)
}

#[derive(Clone, Debug)]
struct VendorRow {
    id: i64,
    name: String,
    description: String,
    icon: String,
}

/// Go `initDefaultVendorMapping`（`store_pricing_default.go:72-97`）：为
/// abilities 中没有元数据的模型补建供应商映射（必要时落库新供应商）。
async fn init_default_vendor_mapping(
    db: &Database,
    meta_map: &mut BTreeMap<String, ModelMeta>,
    vendors: &mut BTreeMap<i64, VendorRow>,
    abilities: &[AbilityWithChannel],
    now: i64,
) -> Result<(), sqlx::Error> {
    for ability in abilities {
        if meta_map.contains_key(&ability.model) {
            continue;
        }
        let model_lower = ability.model.to_ascii_lowercase();
        let mut vendor_id = 0i64;
        for (pattern, vendor_name) in DEFAULT_VENDOR_RULES {
            if model_lower.contains(pattern) {
                vendor_id = get_or_create_vendor(db, vendors, vendor_name, now).await?;
                break;
            }
        }
        meta_map.insert(
            ability.model.clone(),
            ModelMeta {
                model_name: ability.model.clone(),
                vendor_id,
                status: 1,
                name_rule: NAME_RULE_EXACT,
                ..Default::default()
            },
        );
    }
    Ok(())
}

/// Go `groupRatioCoverageGaps`（`store_pricing.go:441-459`）：abilities 引用
/// 的分组中，`GroupRatio` 与 `TopupGroupRatio` 缺失键的告警集合。
fn group_ratio_coverage_gaps(
    all_groups: &BTreeSet<String>,
    groups: &GroupSettings,
    topup_groups: &BTreeSet<String>,
) -> (Vec<String>, Vec<String>) {
    let missing_ratio: Vec<String> = all_groups
        .iter()
        .filter(|g| !groups.group_ratio.contains_key(*g))
        .cloned()
        .collect();
    let missing_topup: Vec<String> = all_groups
        .iter()
        .filter(|g| !topup_groups.contains(*g))
        .cloned()
        .collect();
    (missing_ratio, missing_topup)
}

/// Go `auditGroupRatioCoverage`（`store_pricing.go:466-477`）：同一缺失集合
/// 只告警一次。调用方持有缓存锁（重建路径内）。
fn audit_group_ratio_coverage(
    state: &mut CacheState,
    model_groups: &BTreeMap<String, BTreeSet<String>>,
    groups: &GroupSettings,
    topup_groups: &BTreeSet<String>,
) {
    let mut all_groups = BTreeSet::new();
    for set in model_groups.values() {
        all_groups.extend(set.iter().cloned());
    }
    let (missing_ratio, missing_topup) =
        group_ratio_coverage_gaps(&all_groups, groups, topup_groups);
    let key = format!("{missing_ratio:?}|{missing_topup:?}");
    if key == state.last_group_ratio_gap_audit {
        return;
    }
    state.last_group_ratio_gap_audit = key.clone();
    if missing_ratio.is_empty() && missing_topup.is_empty() {
        return;
    }
    tracing::warn!(
        event = "group_ratio_coverage_gap",
        missing_ratio = ?missing_ratio,
        missing_topup = ?missing_topup,
        "group ratio coverage gap: GroupRatio/TopupGroupRatio missing entries silently bill/credit at ratio 1"
    );
}

/// Go `updatePricing`（`store_pricing.go:180-430`）。任何 DB 错误直接向上
/// 传播（Go 记日志保持旧缓存；见 `refresh_pricing` 注释）。
async fn update_pricing(
    db: &Database,
    ratios: &RatioSettings,
    groups: &GroupSettings,
) -> Result<PricingSnapshot, sqlx::Error> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let abilities = all_enable_abilities_with_channels(db).await?;

    // 模型元数据 + 规则列表（Go store_pricing.go:188-237）。
    let rows: Vec<ModelMeta> = match db {
        Database::Sqlite(pool) => sqlx::query_as(
            "SELECT model_name, COALESCE(description, '') AS description, \
             COALESCE(icon, '') AS icon, COALESCE(tags, '') AS tags, \
             COALESCE(vendor_id, 0) AS vendor_id, COALESCE(endpoints, '') AS endpoints, \
             COALESCE(status, 0) AS status, COALESCE(name_rule, 0) AS name_rule \
             FROM models WHERE deleted_at IS NULL",
        )
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(
            |row: (String, String, String, String, i64, String, i64, i64)| ModelMeta {
                model_name: row.0,
                description: row.1,
                icon: row.2,
                tags: row.3,
                vendor_id: row.4,
                endpoints: row.5,
                status: row.6,
                name_rule: row.7,
            },
        )
        .collect(),
        Database::Postgres(pool) => sqlx::query_as(
            "SELECT model_name, COALESCE(description, '') AS description, \
             COALESCE(icon, '') AS icon, COALESCE(tags, '') AS tags, \
             COALESCE(vendor_id, 0)::BIGINT AS vendor_id, COALESCE(endpoints, '') AS endpoints, \
             COALESCE(status, 0)::BIGINT AS status, COALESCE(name_rule, 0)::BIGINT AS name_rule \
             FROM models WHERE deleted_at IS NULL",
        )
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(
            |row: (String, String, String, String, i64, String, i64, i64)| ModelMeta {
                model_name: row.0,
                description: row.1,
                icon: row.2,
                tags: row.3,
                vendor_id: row.4,
                endpoints: row.5,
                status: row.6,
                name_rule: row.7,
            },
        )
        .collect(),
    };
    let mut meta_map: BTreeMap<String, ModelMeta> = BTreeMap::new();
    let mut rules: Vec<ModelMeta> = Vec::new();
    for meta in rows {
        if meta.name_rule == NAME_RULE_EXACT {
            meta_map.insert(meta.model_name.clone(), meta);
        } else {
            rules.push(meta);
        }
    }

    // 规则模型匹配（Go store_pricing.go:210-237）：精确名未占位的 abilities
    // 模型按 prefix/suffix/contains 命中第一条规则；Go 按 allMeta 顺序迭代，
    // 先到先得。
    for rule in &rules {
        for ability in &abilities {
            let matched = match rule.name_rule {
                NAME_RULE_PREFIX => ability.model.starts_with(&rule.model_name),
                NAME_RULE_SUFFIX => ability.model.ends_with(&rule.model_name),
                NAME_RULE_CONTAINS => ability.model.contains(&rule.model_name),
                _ => false,
            };
            if matched && !meta_map.contains_key(&ability.model) {
                meta_map.insert(ability.model.clone(), rule.clone());
            }
        }
    }

    // 供应商（Go store_pricing.go:239-245）。
    let vendor_rows: Vec<VendorRow> = match db {
        Database::Sqlite(pool) => sqlx::query(
            "SELECT id, name, COALESCE(description, '') AS description, \
             COALESCE(icon, '') AS icon FROM vendors WHERE deleted_at IS NULL",
        )
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|row| VendorRow {
            id: row.try_get("id").unwrap_or_default(),
            name: row.try_get("name").unwrap_or_default(),
            description: row.try_get("description").unwrap_or_default(),
            icon: row.try_get("icon").unwrap_or_default(),
        })
        .collect(),
        Database::Postgres(pool) => sqlx::query(
            "SELECT id, name, COALESCE(description, '') AS description, \
             COALESCE(icon, '') AS icon FROM vendors WHERE deleted_at IS NULL",
        )
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|row| VendorRow {
            id: row.try_get("id").unwrap_or_default(),
            name: row.try_get("name").unwrap_or_default(),
            description: row.try_get("description").unwrap_or_default(),
            icon: row.try_get("icon").unwrap_or_default(),
        })
        .collect(),
    };
    let mut vendors: BTreeMap<i64, VendorRow> =
        vendor_rows.into_iter().map(|v| (v.id, v)).collect();

    init_default_vendor_mapping(db, &mut meta_map, &mut vendors, &abilities, now).await?;

    // 构建对前端友好的供应商列表（Go store_pricing.go:250-259）。
    let vendors_list: Vec<PricingVendor> = vendors
        .values()
        .map(|v| PricingVendor {
            id: v.id,
            name: v.name.clone(),
            description: v.description.clone(),
            icon: v.icon.clone(),
        })
        .collect();

    // 模型 → 启用分组集合（Go store_pricing.go:261-270）。
    let mut model_groups_map: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for ability in &abilities {
        model_groups_map
            .entry(ability.model.clone())
            .or_default()
            .insert(ability.group.clone());
    }

    // 端点推断（Go store_pricing.go:274-288）。
    let advanced_custom_configs = load_pricing_advanced_custom_configs(db, &abilities).await?;
    let mut model_support_endpoints_str: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for ability in &abilities {
        let endpoints = model_support_endpoints_str
            .entry(ability.model.clone())
            .or_default();
        for channel_endpoint in
            pricing_endpoint_types_for_ability(ability, &advanced_custom_configs)
        {
            if !endpoints.iter().any(|e| e == channel_endpoint) {
                endpoints.push(channel_endpoint.to_owned());
            }
        }
    }

    // 模型自定义端点追加（Go store_pricing.go:290-308）。
    for (model_name, meta) in &meta_map {
        if meta.endpoints.trim().is_empty() {
            continue;
        }
        let Ok(raw) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(
            meta.endpoints.trim(),
        ) else {
            continue;
        };
        let endpoints = model_support_endpoints_str
            .entry(model_name.clone())
            .or_default();
        for (key, value) in &raw {
            match value {
                serde_json::Value::String(_) | serde_json::Value::Object(_)
                    if !key.is_empty() && !endpoints.iter().any(|e| e == key) =>
                {
                    endpoints.push(key.clone());
                }
                _ => {}
            }
        }
    }

    // 全局端点默认信息（Go store_pricing.go:320-331）。
    let mut supported_endpoint_map: BTreeMap<String, EndpointInfo> = BTreeMap::new();
    for endpoints in model_support_endpoints_str.values() {
        for endpoint in endpoints {
            if let Some(info) = default_endpoint_info(endpoint)
                && !supported_endpoint_map.contains_key(endpoint)
            {
                supported_endpoint_map.insert(endpoint.clone(), info);
            }
        }
    }
    // 自定义端点覆盖默认（Go store_pricing.go:332-357）。
    for meta in meta_map.values() {
        if meta.endpoints.trim().is_empty() {
            continue;
        }
        let Ok(raw) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(
            meta.endpoints.trim(),
        ) else {
            continue;
        };
        for (key, value) in &raw {
            match value {
                serde_json::Value::String(path) => {
                    supported_endpoint_map.insert(
                        key.clone(),
                        EndpointInfo {
                            path: path.clone(),
                            method: "POST".to_owned(),
                        },
                    );
                }
                serde_json::Value::Object(object) => {
                    let mut info = EndpointInfo {
                        path: String::new(),
                        method: "POST".to_owned(),
                    };
                    if let Some(serde_json::Value::String(path)) = object.get("path") {
                        info.path = path.clone();
                    }
                    if let Some(serde_json::Value::String(method)) = object.get("method") {
                        info.method = method.to_ascii_uppercase();
                    }
                    supported_endpoint_map.insert(key.clone(), info);
                }
                _ => {}
            }
        }
    }

    // 分组覆盖率审计（Go store_pricing.go:272）；TopupGroupRatio 选项键集
    // 一次性读取（Go `common.ContainsTopupGroupRatio` 读全局 map）。
    let topup_groups: BTreeSet<String> = match db {
        Database::Sqlite(pool) => {
            let value: Option<(String,)> =
                sqlx::query_as("SELECT value FROM options WHERE key = ?")
                    .bind("TopupGroupRatio")
                    .fetch_optional(pool)
                    .await?;
            parse_topup_group_keys(value.map(|(v,)| v))
        }
        Database::Postgres(pool) => {
            let value: Option<(String,)> =
                sqlx::query_as("SELECT value FROM options WHERE key = $1")
                    .bind("TopupGroupRatio")
                    .fetch_optional(pool)
                    .await?;
            parse_topup_group_keys(value.map(|(v,)| v))
        }
    };
    {
        let mut state = cache_lock();
        audit_group_ratio_coverage(&mut state, &model_groups_map, groups, &topup_groups);
    }

    // pricing 行（Go store_pricing.go:359-412）。
    let mut pricing: Vec<Pricing> = Vec::with_capacity(model_groups_map.len());
    for (model, group_set) in &model_groups_map {
        let mut item = Pricing {
            model_name: model.clone(),
            enable_groups: group_set.iter().cloned().collect(),
            supported_endpoint_types: model_support_endpoints_str
                .get(model)
                .cloned()
                .unwrap_or_default(),
            owner_by: String::new(),
            ..Default::default()
        };
        if let Some(meta) = meta_map.get(model) {
            // 禁用模型不返回给前端（Go store_pricing.go:369-371）。
            if meta.status != 1 {
                continue;
            }
            item.description = meta.description.clone();
            item.icon = meta.icon.clone();
            item.tags = meta.tags.clone();
            item.vendor_id = meta.vendor_id;
        }
        if let Some(model_price) = ratios.get_model_price(model) {
            item.model_price = model_price;
            item.quota_type = 1;
        } else {
            let (model_ratio, _, _) = ratios.get_model_ratio(model);
            item.model_ratio = model_ratio;
            item.completion_ratio = ratios.get_completion_ratio(model);
            item.quota_type = 0;
        }
        item.cache_ratio = ratios.get_cache_ratio(model);
        item.create_cache_ratio = ratios.get_create_cache_ratio(model);
        item.image_ratio = ratios.get_image_ratio(model);
        if ratios.contains_audio_ratio(model) {
            item.audio_ratio = Some(ratios.get_audio_ratio(model));
        }
        if ratios.contains_audio_completion_ratio(model) {
            item.audio_completion_ratio = Some(ratios.get_audio_completion_ratio(model));
        }
        let resolver = TIERED_BILLING_RESOLVER
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(tiered) = resolver.as_ref().and_then(|resolve| resolve(model))
            && !tiered.1.trim().is_empty()
        {
            item.billing_mode = tiered.0;
            item.billing_expr = tiered.1;
        }
        pricing.push(item);
    }
    // Go：非空时第一个条目挂 PricingVersion（顺序随机 → 这里挂在字典序
    // 首个模型上，值域一致）。
    if let Some(first) = pricing.first_mut() {
        first.pricing_version = PRICING_VERSION.to_owned();
    }

    // 高并发快速映射（Go store_pricing.go:419-427）：enable_groups/quota
    // 只来自 pricing（禁用模型被跳过）；端点映射来自重建阶段的全部模型
    // （Go `modelSupportEndpointTypes` 在跳过禁用模型之前构建）。
    let mut model_enable_groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut model_quota_type_map: BTreeMap<String, i64> = BTreeMap::new();
    for item in &pricing {
        model_enable_groups.insert(item.model_name.clone(), item.enable_groups.clone());
        model_quota_type_map.insert(item.model_name.clone(), item.quota_type);
    }
    let model_support_endpoint_types = model_support_endpoints_str.clone();

    Ok(PricingSnapshot {
        pricing,
        vendors: vendors_list,
        supported_endpoint_map,
        model_support_endpoint_types,
        model_enable_groups,
        model_quota_type_map,
    })
}

/// Go `loadPricingAdvancedCustomConfigs`（`store_pricing.go:135-171`）：
/// 为类型 58 渠道直接读 `other_settings`（Go 走渠道内存缓存桥 + 回落
/// `CacheGetChannel`；Rust 渠道缓存未移植，直接查库，语义等价——渠道行
/// 由写路径经 `mutate_routing!` 提交，读一致性由 DB 保证）。
async fn load_pricing_advanced_custom_configs(
    db: &Database,
    abilities: &[AbilityWithChannel],
) -> Result<BTreeMap<i64, AdvancedCustomConfig>, sqlx::Error> {
    let mut channel_ids: Vec<i64> = Vec::new();
    let mut seen = BTreeSet::new();
    for ability in abilities {
        if ability.channel_type != channel_type::ADVANCED_CUSTOM {
            continue;
        }
        if seen.insert(ability.channel_id) {
            channel_ids.push(ability.channel_id);
        }
    }
    if channel_ids.is_empty() {
        return Ok(BTreeMap::new());
    }
    let mut configs = BTreeMap::new();
    for channel_id in channel_ids {
        let row: Option<(String,)> = match db {
            Database::Sqlite(pool) => {
                sqlx::query_as("SELECT COALESCE(other, '') FROM channels WHERE id = ?")
                    .bind(channel_id)
                    .fetch_optional(pool)
                    .await?
            }
            Database::Postgres(pool) => {
                sqlx::query_as("SELECT COALESCE(other, '') FROM channels WHERE id = $1")
                    .bind(channel_id)
                    .fetch_optional(pool)
                    .await?
            }
        };
        let Some((other,)) = row else {
            tracing::warn!(
                event = "pricing_advanced_custom_channel_missing",
                channel_id,
                "advanced custom channel row missing for pricing rebuild"
            );
            continue;
        };
        // Go `channel.GetOtherSettings().AdvancedCustom`：`other` 列是
        // ChannelOtherSettings JSON，`advanced_custom` 字段可缺省。
        if other.trim().is_empty() {
            continue;
        }
        let Ok(parsed) = serde_json::from_str::<OtherSettingsPricing>(other.trim()) else {
            continue;
        };
        if let Some(config) = parsed.advanced_custom {
            configs.insert(channel_id, config);
        }
    }
    Ok(configs)
}

/// `channels.other` 列的定价读视图（Go `dto.ChannelOtherSettings` 中仅
/// `advanced_custom` 字段被本模块消费；serde 忽略未知字段）。
#[derive(serde::Deserialize)]
struct OtherSettingsPricing {
    #[serde(default)]
    advanced_custom: Option<AdvancedCustomConfig>,
}
