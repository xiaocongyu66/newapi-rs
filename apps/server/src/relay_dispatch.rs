//! Distribute 渠道选择 + relay 转发主链（Go `distribute_channel.go` +
//! `handle_relay.go` 的 `Relay` 主链骨架）。
//!
//! 契约要点：
//! - **Distribute 过滤顺序**（distribute_channel.go:35-199）：specific
//!   channel 指定 → token 模型限额 → 模型名必填 → 渠道亲和（未移植，见
//!   交付报告遗留）→ [`newapi_relay::channel_select`] 选择器（abilities
//!   过滤 + route units + 权重抽样）→ [`setup_context_for_selected_channel`]
//!   绑定渠道 → 成功后记账亲和（同上，未移植）。错误信封：
//!   400 invalid_request / 403 模型权限 / 503 model_not_found。
//! - **选择器公式**：候选 = `channel_model_routes`（alias 启用行，归一化
//!   别名兜底）∩ `abilities`（group, alias, enabled；fail closed）∩ 渠道
//!   启用 + key 可用 + 排除集。权重语义：`static_weight` 加权抽样（负权重
//!   退化为 0，全零退化为均匀——Go `p2cWeight` 的先验面）；P2C 决斗、慢
//!   启动 ramp 与冷却 faint recall 属健康切片，见遗留。
//! - **主链时序**（handle_relay.go `Relay`）：请求校验 → GenRelayInfo →
//!   估价（ModelPriceHelper 投影）→ `PreConsumeBilling`（免费模型跳过）→
//!   重试环 { 渠道 → adaptor 调用链 → 成功结算返回 / 失败分类→排除→换道 }
//!   → 终态错误信封（按 relay_format 分 OpenAI / Claude 形状）。
//! - **重试语义**：尝试帽 = RetryTimes + 1（mono MaxAttempts）；
//!   `classify_attempt` 决定换道资格（Retryable/Throttled/FatalSwitchable
//!   标记 tried，Fatal 直通）；specific channel 不重试；暂存的渠道域 4xx
//!   在池耗尽时直通（Go relayFailoverExhausted 面）。
//! - adaptor 调用点走 [`newapi_relay::adaptor::Adaptor`] trait（工厂注入，
//!   替身见契约测试）；真实外呼实现由 channel-adapter 切片合流。

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value};
use sqlx::Row;
use std::sync::atomic::{AtomicU64, Ordering};

use newapi_billing::billing_session::pricing::{
    GroupRatioInfo, PriceData, RatioSettings as BillingRatioSettings,
};
use newapi_billing::billing_session::quota_math::{QUOTA_PER_UNIT, quota_from_float_checked};
use newapi_billing::billing_session::session::{
    BillingApiError, RelayBillingInfo, pre_consume_billing,
};
use newapi_billing::billing_session::store::BillingStore;
use newapi_billing::billing_session::text_quota::{
    TextCallContext, TextQuotaSummary, calculate_text_quota_summary,
};
use newapi_billing::billing_session::usage::Usage;
use newapi_catalog::channels::store::{CHANNEL_STATUS_ENABLED, ChannelRepository, ChannelRow};
use newapi_catalog::group_settings::GroupSettings;
use newapi_catalog::ratio_settings::{RatioSettings, format_matching_model_name};
use newapi_relay::adaptor::{channel_type as channel_type_const, channel_type_to_api_type};
use newapi_relay::channel_select::{
    AutoGroupConfig, AutoGroupState, ExcludeRoutes, GroupRouteLookup, RouteKey, SelectError,
    SelectParams, SelectedRoute,
};
use newapi_relay::dispatch::{
    RelayAttemptError, RelayAttemptKind, classify_attempt, should_retry, terminal_failover_error,
};
use newapi_relay::relay_info::relay_format;
use newapi_relay::relay_info::{ChannelMetaSnapshot, RelayInfo};
use newapi_relay::relay_mode as relay_mode_consts;

use crate::AppState;
use crate::relay_http::{RelayTokenIdentity, abort_with_openai_message};

/// Go `common.PreConsumedQuota = 500`（constants.go:143）。
const PRE_CONSUMED_QUOTA: i64 = 500;

/// Go `common.RetryTimes` 选项读取（settings.go:589-590；读取失败回退出厂
/// 默认 0）。
async fn load_retry_times(db: &newapi_storage::Database) -> i32 {
    const SQL: &str = r#"SELECT "value" FROM "options" WHERE "key" = 'RetryTimes'"#;
    let raw: Option<String> = match db {
        newapi_storage::Database::Sqlite(pool) => sqlx::query_scalar(SQL)
            .fetch_optional(pool)
            .await
            .ok()
            .flatten(),
        newapi_storage::Database::Postgres(pool) => sqlx::query_scalar(SQL)
            .fetch_optional(pool)
            .await
            .ok()
            .flatten(),
    };
    raw.and_then(|v| v.trim().parse::<i32>().ok()).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// 模型请求抽取（Go getModelRequest 的已路由路径投影）
// ---------------------------------------------------------------------------

/// Go `getModelRequest` 的输出投影。`relay_mode` 覆盖值对应 Go
/// `c.Set("relay_mode")`（GenRelayInfo 的 relay_mode_fallback 输入）。
#[derive(Debug, Default)]
pub struct ModelRequest {
    pub model: String,
    pub relay_mode_override: Option<i32>,
}

/// Go `extractModelNameFromGeminiPath`（distribute_channel.go:534-557）。
pub fn extract_model_name_from_gemini_path(path: &str) -> String {
    const MODELS_PREFIX: &str = "/models/";
    let Some(models_index) = path.find(MODELS_PREFIX) else {
        return String::new();
    };
    let start = models_index + MODELS_PREFIX.len();
    if start >= path.len() {
        return String::new();
    }
    let rest = &path[start..];
    match rest.find(':') {
        None => rest.to_owned(),
        Some(colon) => rest[..colon].to_owned(),
    }
}

/// Go `getModelRequest`（distribute_channel.go:280-444）中本切片路由表内
/// 路径的投影。Midjourney/Suno/video 任务抽取属任务切片；multipart 表单
/// 主体（transcriptions）不在骨架路由内。
pub fn model_request_from(path: &str, payload: &Value) -> ModelRequest {
    let mut request = ModelRequest::default();
    let mut model = payload
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();

    if path.starts_with("/v1beta/models/") || path.starts_with("/v1/models/") {
        request.relay_mode_override = Some(relay_mode_consts::RELAY_MODE_GEMINI);
        let gemini_model = extract_model_name_from_gemini_path(path);
        if !gemini_model.is_empty() {
            model = gemini_model;
        }
    }
    if path.starts_with("/v1/moderations") && model.is_empty() {
        model = "text-moderation-stable".to_owned();
    }
    if path.starts_with("/v1/images/generations") && model.is_empty() {
        model = "dall-e".to_owned();
    }
    if path.starts_with("/v1/images/edits") && model.is_empty() {
        model = "dall-e-2".to_owned();
    }
    if path.starts_with("/v1/audio/speech") && model.is_empty() {
        model = "tts-1".to_owned();
        request.relay_mode_override = Some(relay_mode_consts::RELAY_MODE_AUDIO_SPEECH);
    } else if path.starts_with("/v1/audio/translations") {
        if model.is_empty() {
            model = "whisper-1".to_owned();
        }
        request.relay_mode_override = Some(relay_mode_consts::RELAY_MODE_AUDIO_TRANSLATION);
    } else if path.starts_with("/v1/audio/transcriptions") {
        if model.is_empty() {
            model = "whisper-1".to_owned();
        }
        request.relay_mode_override = Some(relay_mode_consts::RELAY_MODE_AUDIO_TRANSCRIPTION);
    }
    if path.starts_with("/v1/responses/compact") && !model.is_empty() {
        model = newapi_catalog::ratio_settings::with_compact_model_suffix(&model);
    }
    request.model = model;
    request
}

// ---------------------------------------------------------------------------
// DB 查找：abilities 过滤 + route units（Go getCandidatesFromDB +
// filterCandidatesByGroup + filterCandidatesByChannelStatusAndKey）
// ---------------------------------------------------------------------------

/// 候选行投影（Go `routeCandidate`）。
#[derive(Clone, Debug)]
struct RouteCandidate {
    route_id: i64,
    channel_id: i64,
    key_index: i64,
    upstream_model: String,
    static_weight: i64,
}

/// Go `getCandidatesFromDB`：alias 启用 route rows。
async fn route_candidates(
    db: &newapi_storage::Database,
    alias: &str,
) -> Result<Vec<RouteCandidate>, sqlx::Error> {
    // 手工行投影（sqlx 无 derive 宏面；对齐 channels/store.rs 的具现约定）。
    struct Row {
        id: i64,
        channel_id: i64,
        key_index: i64,
        upstream_model: String,
        static_weight: i64,
    }
    fn row_of(row: &sqlx::sqlite::SqliteRow) -> Result<Row, sqlx::Error> {
        Ok(Row {
            id: row.try_get("id")?,
            channel_id: row.try_get("channel_id")?,
            key_index: row.try_get("key_index")?,
            upstream_model: row.try_get("upstream_model")?,
            static_weight: row.try_get("static_weight")?,
        })
    }
    fn row_of_pg(row: &sqlx::postgres::PgRow) -> Result<Row, sqlx::Error> {
        Ok(Row {
            id: row.try_get("id")?,
            channel_id: row.try_get("channel_id")?,
            key_index: row.try_get("key_index")?,
            upstream_model: row.try_get("upstream_model")?,
            static_weight: row.try_get("static_weight")?,
        })
    }
    let rows: Vec<Row> = match db {
        newapi_storage::Database::Sqlite(pool) => sqlx::query(
            "SELECT id, channel_id, key_index, upstream_model, static_weight \
             FROM channel_model_routes WHERE public_model_alias = ? AND enabled = 1",
        )
        .bind(alias)
        .fetch_all(pool)
        .await?
        .iter()
        .map(row_of)
        .collect::<Result<Vec<Row>, sqlx::Error>>()?,
        newapi_storage::Database::Postgres(pool) => sqlx::query(
            "SELECT id, channel_id, key_index, upstream_model, static_weight \
             FROM channel_model_routes WHERE public_model_alias = $1 AND enabled = TRUE",
        )
        .bind(alias)
        .fetch_all(pool)
        .await?
        .iter()
        .map(row_of_pg)
        .collect::<Result<Vec<Row>, sqlx::Error>>()?,
    };
    Ok(rows
        .into_iter()
        .map(|r| RouteCandidate {
            route_id: r.id,
            channel_id: r.channel_id,
            key_index: r.key_index,
            upstream_model: r.upstream_model,
            static_weight: r.static_weight,
        })
        .collect())
}

/// Go `allowedChannelsForGroupAlias`（abilities 权威，fail closed：未知
/// 分组 / 未知别名 / 空集合 → 无候选）。
async fn allowed_channels_for_group_alias(
    db: &newapi_storage::Database,
    group: &str,
    alias: &str,
) -> Result<Vec<i64>, sqlx::Error> {
    if group.is_empty() || alias.is_empty() {
        return Ok(Vec::new());
    }
    let ids: Vec<i64> = match db {
        newapi_storage::Database::Sqlite(pool) => {
            sqlx::query_scalar(
                "SELECT channel_id FROM abilities \
                 WHERE \"group\" = ? AND model = ? AND enabled = 1",
            )
            .bind(group)
            .bind(alias)
            .fetch_all(pool)
            .await?
        }
        newapi_storage::Database::Postgres(pool) => {
            sqlx::query_scalar(
                "SELECT channel_id FROM abilities \
                 WHERE \"group\" = $1 AND model = $2 AND enabled = TRUE",
            )
            .bind(group)
            .bind(alias)
            .fetch_all(pool)
            .await?
        }
    };
    Ok(ids)
}

/// Go `isKeyEnabled`（select_route_unit.go:198-214）：单 key 渠道仅
/// index 0；多 key 按 status_list（缺省启用）。
fn is_key_enabled(channel: &ChannelRow, key_index: i64) -> bool {
    if !channel.channel_info.is_multi_key {
        return key_index == 0;
    }
    let key_count = channel.key.split('\n').filter(|k| !k.is_empty()).count() as i64;
    if key_index < 0 || key_index >= key_count {
        return false;
    }
    channel
        .channel_info
        .multi_key_status_list
        .as_ref()
        .and_then(|list| list.get(&key_index))
        .map(|status| *status == CHANNEL_STATUS_ENABLED)
        .unwrap_or(true)
}

/// Go `GetNextEnabledKeyForIndex` 的 key 明文提取。
fn key_at_index(channel: &ChannelRow, key_index: i64) -> Option<String> {
    if !channel.channel_info.is_multi_key {
        return if key_index == 0 && !channel.key.is_empty() {
            Some(channel.key.clone())
        } else {
            None
        };
    }
    channel
        .key
        .split('\n')
        .filter(|k| !k.is_empty())
        .nth(key_index.max(0) as usize)
        .map(|k| k.to_owned())
}

/// 抽样随机源：xorshift64*（时间 + 原子计数播种）。分布质量足以支撑权重
/// 抽样；不引入新的 rand 生产依赖，测试不依赖具体值。
fn next_uniform() -> f64 {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(1);
    let mut state = now
        ^ SEQ
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_mul(0x9E3779B97F4A7C15);
    if state == 0 {
        state = 0x9E3779B97F4A7C15;
    }
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    let value = state.wrapping_mul(0x2545F4914F6CDD1D);
    (value >> 11) as f64 / (1u64 << 53) as f64
}

/// Go `pickWeightedIndex`（selector_p2c.go:360-380）：累计加权抽样（有放回）；
/// 尾部回退镜像 mono 的 float 累计误差护栏，零先验候选不进常规决斗。
fn pick_weighted_index(weights: &[f64]) -> usize {
    let total: f64 = weights.iter().sum();
    let mut running = next_uniform() * total;
    for (index, weight) in weights.iter().enumerate() {
        running -= weight;
        if running < 0.0 {
            return index;
        }
    }
    (0..weights.len())
        .rev()
        .find(|&i| weights[i] > 0.0)
        .unwrap_or(weights.len().saturating_sub(1))
}

/// Go `p2cWeight` 先验面：非负静态权重，负值退化为 0 先验。
fn prior_weight(static_weight: i64) -> f64 {
    if static_weight > 0 {
        static_weight as f64
    } else {
        0.0
    }
}

/// Go `SelectRouteUnit` 的 DB 路径（Rust 侧无渠道内存镜像，直查库）。
/// 候选管线与 Go 一致：别名归一化兜底 → abilities 过滤（fail closed）→
/// 渠道状态 / key / 排除过滤 → 权重抽样。健康选择面（P2C 决斗 / 慢启动 /
/// faint recall）随健康切片合流。
///
/// 查询错误吞掉（Go `getCandidatesFromDB` / `filterCandidatesByGroup` 的
/// `return nil` 面）：DB 故障落"无候选"而不是上抛——与 Go 的无渠道契约
/// 一致（日志照记，`Ok(None)` 让上层走 503 model_not_found 信封）。
pub async fn select_route_unit_db(
    db: &newapi_storage::Database,
    group: &str,
    alias: &str,
    exclude: &ExcludeRoutes,
) -> Result<Option<(SelectedRoute, ChannelRow)>, sqlx::Error> {
    match select_route_unit_db_inner(db, group, alias, exclude).await {
        Ok(selection) => Ok(selection),
        Err(error) => {
            tracing::warn!(
                event = "route_unit_lookup_failed",
                group = group,
                alias = alias,
                category = crate::database_error_class(&error),
                "failed to load route candidates: {error}"
            );
            Ok(None)
        }
    }
}

async fn select_route_unit_db_inner(
    db: &newapi_storage::Database,
    group: &str,
    alias: &str,
    exclude: &ExcludeRoutes,
) -> Result<Option<(SelectedRoute, ChannelRow)>, sqlx::Error> {
    let mut candidates = route_candidates(db, alias).await?;
    if candidates.is_empty() {
        // Go SelectRouteUnit 的归一化别名兜底（gpts / thinking-* 等）。
        let normalized = format_matching_model_name(alias);
        if normalized != alias {
            candidates = route_candidates(db, &normalized).await?;
        }
    }
    if candidates.is_empty() {
        return Ok(None);
    }

    let allowed: std::collections::HashSet<i64> =
        allowed_channels_for_group_alias(db, group, alias)
            .await?
            .into_iter()
            .collect();
    candidates.retain(|candidate| allowed.contains(&candidate.channel_id));
    if candidates.is_empty() {
        return Ok(None);
    }

    let repository = ChannelRepository::new(db.clone());
    let mut eligible: Vec<(RouteCandidate, ChannelRow)> = Vec::new();
    let mut loaded: std::collections::HashMap<i64, Option<ChannelRow>> =
        std::collections::HashMap::new();
    for candidate in candidates {
        let channel = match loaded.get(&candidate.channel_id) {
            Some(cached) => cached.clone(),
            None => {
                let row = repository.by_id(candidate.channel_id, true).await?;
                loaded.insert(candidate.channel_id, row.clone());
                row
            }
        };
        let Some(channel) = channel else {
            continue; // 渠道不在库：跳过（Go channelsIDM miss 行为）
        };
        if channel.status != CHANNEL_STATUS_ENABLED {
            continue;
        }
        if !is_key_enabled(&channel, candidate.key_index) {
            continue;
        }
        let key = RouteKey {
            channel_id: candidate.channel_id,
            key_index: candidate.key_index,
            model: alias.to_owned(),
        };
        if exclude.contains(&key) {
            continue;
        }
        eligible.push((candidate, channel));
    }
    if eligible.is_empty() {
        return Ok(None);
    }

    let weights: Vec<f64> = eligible
        .iter()
        .map(|(candidate, _)| prior_weight(candidate.static_weight))
        .collect();
    let winner = pick_weighted_index(&weights);
    let (candidate, channel) = eligible.remove(winner);
    let key = key_at_index(&channel, candidate.key_index).unwrap_or_default();
    Ok(Some((
        SelectedRoute {
            route_id: candidate.route_id,
            group: group.to_owned(),
            alias: alias.to_owned(),
            channel_id: candidate.channel_id,
            key_index: candidate.key_index,
            key,
            upstream_model: candidate.upstream_model,
        },
        channel,
    )))
}

/// Go `SelectedRouteFromChannel`（specific channel / 锁定回放路径）：
/// 无 P2C 抽取，按 (channel, alias) 定位 route row 做归属。
pub async fn selected_route_from_channel(
    db: &newapi_storage::Database,
    channel: &ChannelRow,
    alias: &str,
    group: &str,
) -> Result<SelectedRoute, SelectError> {
    let (key, key_index) = if channel.channel_info.is_multi_key {
        let status_list = channel.channel_info.multi_key_status_list.clone();
        channel
            .key
            .split('\n')
            .filter(|k| !k.is_empty())
            .enumerate()
            .find(|(index, _)| {
                let index = *index as i64;
                status_list
                    .as_ref()
                    .and_then(|list| list.get(&index))
                    .map(|status| *status == CHANNEL_STATUS_ENABLED)
                    .unwrap_or(true)
            })
            .map(|(index, key)| (key.to_owned(), index as i64))
            .ok_or_else(|| SelectError::Lookup("channel:no_available_key".to_owned()))?
    } else if channel.key.is_empty() {
        return Err(SelectError::Lookup("channel:no_available_key".to_owned()));
    } else {
        (channel.key.clone(), 0)
    };

    // 定位 route row（EWMA 归属面；无行 → route_id 0，upstream = alias）。
    let rows = route_candidates(db, alias).await.unwrap_or_default();
    let matched = rows
        .iter()
        .find(|row| row.channel_id == channel.id && row.key_index == key_index);
    Ok(SelectedRoute {
        route_id: matched.map(|row| row.route_id).unwrap_or(0),
        group: group.to_owned(),
        alias: alias.to_owned(),
        channel_id: channel.id,
        key_index,
        key,
        upstream_model: matched
            .map(|row| row.upstream_model.clone())
            .unwrap_or_else(|| alias.to_owned()),
    })
}

// ---------------------------------------------------------------------------
// Distribute（Go Distribute 中间件的选择面）
// ---------------------------------------------------------------------------

/// Distribute 的选择结果：路由 + 渠道行 + 选择面路径。
pub struct DistributedChannel {
    pub route: SelectedRoute,
    pub channel: ChannelRow,
    /// Go ContextKeyRoutePath：specific / weighted。
    pub route_path: &'static str,
}

/// Go `SetupContextForSelectedChannel`（distribute_channel.go:467-529）的
/// RelayInfo 面：渠道绑定进 ChannelMeta。proxy 节点选择、亲和覆盖模板等
/// 独立切片未合流，见交付报告遗留。
pub fn setup_context_for_selected_channel(
    info: &mut RelayInfo,
    route: &SelectedRoute,
    channel: &ChannelRow,
    model_name: &str,
) {
    info.origin_model_name = model_name.to_owned();
    let (api_type, _) = channel_type_to_api_type(channel.channel_type as i32);
    // Go switch(channel.Type)：api_version / region / plugin / bot_id 均取
    // channel.Other 原文，按渠道类型落到 api_version（其余用途归适配器切片）。
    let api_version = match channel.channel_type as i32 {
        channel_type_const::AZURE
        | channel_type_const::XUNFEI
        | channel_type_const::GEMINI
        | channel_type_const::CLOUDFLARE
        | channel_type_const::MOKA_AI
        | channel_type_const::VERTEX_AI
        | channel_type_const::ALI
        | channel_type_const::COZE => channel.other.clone(),
        _ => String::new(),
    };
    info.init_channel_meta(ChannelMetaSnapshot {
        channel_type: channel.channel_type as i32,
        api_type,
        api_version,
        upstream_model_name: route.upstream_model.clone(),
        param_override: parse_json_or_null(channel.param_override.as_deref()),
        headers_override: parse_json_or_null(channel.header_override.as_deref()),
        channel_setting: parse_json_or_null(channel.setting.as_deref()),
        channel_other_settings: parse_json_or_null(Some(channel.other_info.as_str())),
        pass_through_request_enabled: false,
    });
}

fn parse_json_or_null(raw: Option<&str>) -> Value {
    match raw {
        Some(text) if !text.trim().is_empty() => serde_json::from_str(text).unwrap_or(Value::Null),
        _ => Value::Null,
    }
}

/// auto 分组的单分组查找（异步 DB 面，[`GroupRouteLookup`] 实现）。
struct DbGroupLookup<'a> {
    db: &'a newapi_storage::Database,
    alias: &'a str,
    exclude: &'a ExcludeRoutes,
}

impl GroupRouteLookup for DbGroupLookup<'_> {
    async fn lookup_route(
        &mut self,
        group: &str,
        _priority_retry: i32,
    ) -> Result<Option<SelectedRoute>, SelectError> {
        // route-unit 模型下重试参数只作 API 兼容保留（Go SelectRouteUnit
        // `_ = retry`），无优先级层降。DB 错误已在 select_route_unit_db
        // 按 Go 语义吞成"无候选"，这里不会再有 Err 路径（防御面保留枚举）。
        let route = match select_route_unit_db(self.db, group, self.alias, self.exclude).await {
            Ok(pair) => pair.map(|(route, _channel)| route),
            Err(error) => return Err(SelectError::Lookup(error.to_string())),
        };
        Ok(route)
    }
}

/// Go `Distribute` 的选择段（distribute_channel.go:35-199）：specific
/// channel → token 模型限额 → 模型名必填 → 选择器。亲和优先面未移植
/// （依赖 affinity 缓存切片）。错误以响应形式返回（Go abort）。
pub async fn distribute_select(
    state: &AppState,
    db: &newapi_storage::Database,
    identity: &RelayTokenIdentity,
    path: &str,
    model: &str,
    request_id: &str,
    language: &str,
) -> Result<DistributedChannel, Box<Response>> {
    let group_settings: GroupSettings = state.group_settings();

    // ── specific channel 指定（管理员 key-<id> 语法，distribute_channel.go:44-66）
    if let Some(specific_id) = identity.specific_channel_id.as_deref() {
        let Ok(id) = specific_id.parse::<i64>() else {
            return Err(Box::new(abort_with_openai_message(
                StatusCode::BAD_REQUEST,
                &newapi_i18n::translate(
                    language,
                    "distributor.invalid_channel_id",
                    std::iter::empty::<(&str, &str)>(),
                ),
                "",
                request_id,
            )));
        };
        let repository = ChannelRepository::new(db.clone());
        let channel = repository.by_id(id, true).await.map_err(|_| {
            abort_with_openai_message(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database operation failed",
                "",
                request_id,
            )
        })?;
        let Some(channel) = channel else {
            return Err(Box::new(abort_with_openai_message(
                StatusCode::BAD_REQUEST,
                &newapi_i18n::translate(
                    language,
                    "distributor.invalid_channel_id",
                    std::iter::empty::<(&str, &str)>(),
                ),
                "",
                request_id,
            )));
        };
        if channel.status != CHANNEL_STATUS_ENABLED {
            return Err(Box::new(abort_with_openai_message(
                StatusCode::FORBIDDEN,
                &newapi_i18n::translate(
                    language,
                    "distributor.channel_disabled",
                    std::iter::empty::<(&str, &str)>(),
                ),
                "",
                request_id,
            )));
        }
        let route = selected_route_from_channel(db, &channel, model, &identity.using_group)
            .await
            .map_err(|_| {
                abort_with_openai_message(
                    StatusCode::BAD_REQUEST,
                    &newapi_i18n::translate(
                        language,
                        "distributor.invalid_channel_id",
                        std::iter::empty::<(&str, &str)>(),
                    ),
                    "",
                    request_id,
                )
            })?;
        return Ok(DistributedChannel {
            route,
            channel,
            route_path: "specific",
        });
    }

    // ── token 模型限额（distribute_channel.go:69-87）────────────────────
    if identity.token_model_limit_enabled {
        let limit: std::collections::HashSet<String> = identity
            .token_model_limit
            .split(',')
            .map(|item| item.trim().to_owned())
            .filter(|item| !item.is_empty())
            .collect();
        if limit.is_empty() {
            // 限额开着但列表为空：全部模型拒绝（Go tokenModelLimit 缺失臂）。
            return Err(Box::new(abort_with_openai_message(
                StatusCode::FORBIDDEN,
                &newapi_i18n::translate(
                    language,
                    "distributor.token_no_model_access",
                    std::iter::empty::<(&str, &str)>(),
                ),
                "",
                request_id,
            )));
        }
        let match_name = format_matching_model_name(model); // gpts / thinking-* 匹配
        if !limit.contains(&match_name) && !limit.contains(model) {
            let message = newapi_i18n::translate(
                language,
                "distributor.token_model_forbidden",
                [("Model", model.to_owned())],
            );
            return Err(Box::new(abort_with_openai_message(
                StatusCode::FORBIDDEN,
                &message,
                "",
                request_id,
            )));
        }
    }

    // ── 模型名必填（distribute_channel.go:89-93）────────────────────────
    if model.is_empty() {
        return Err(Box::new(abort_with_openai_message(
            StatusCode::BAD_REQUEST,
            &newapi_i18n::translate(
                language,
                "distributor.model_name_required",
                std::iter::empty::<(&str, &str)>(),
            ),
            "",
            request_id,
        )));
    }

    // ── 渠道选择（distribute_channel.go:156-184）────────────────────────
    let using_group = identity.using_group.clone();
    let mut params = SelectParams::new(&using_group, model, path);
    let mut walk = AutoGroupState::default();
    let auto_groups = if using_group == "auto" {
        // Go GetRequestAutoGroups：token 快照存在（含空）为显式快照，
        // 否则继承全局 Auto 列表。
        if identity.token_auto_groups_set {
            group_settings.filter_user_token_auto_groups(
                &identity.user_group,
                &identity.token_auto_groups,
                identity.max_token_auto_groups,
            )
        } else {
            group_settings.user_auto_group(&identity.user_group)
        }
    } else {
        Vec::new()
    };
    let config = AutoGroupConfig {
        auto_groups,
        cross_group_retry: identity.token_cross_group_retry,
        retry_times: load_retry_times(db).await,
    };
    // 排除集克隆给查找端口：游走要 &mut params（retry 态），排除集在
    // 选择段内不可变（重试环的排除在主链另持一份）。
    let exclude_for_lookup = params.exclude_routes.clone();
    let mut lookup = DbGroupLookup {
        db,
        alias: model,
        exclude: &exclude_for_lookup,
    };
    let (route, selected_group) = newapi_relay::channel_select::cache_get_random_satisfied_channel(
        &mut walk,
        &mut params,
        &config,
        &mut lookup,
    )
    .await
    .map_err(|error| channel_error_response(&error, &using_group, model, language, request_id))?;

    let Some(route) = route else {
        // Go route==nil 分支：503 + model_not_found（auto 显示分组包裹）。
        let show_group = if using_group == "auto" {
            format!("auto({selected_group})")
        } else {
            using_group.clone()
        };
        let message = newapi_i18n::translate(
            language,
            "distributor.no_available_channel",
            [("Group", show_group), ("Model", model.to_owned())],
        );
        return Err(Box::new(abort_with_openai_message(
            StatusCode::SERVICE_UNAVAILABLE,
            &message,
            "model_not_found",
            request_id,
        )));
    };

    // 渠道行复取（带 key）以绑定上下文（Go SetupContextForSelectedChannel 前
    // CacheGetChannel）。查找刚写过该行，失败即 DB 一致性缺陷。
    let repository = ChannelRepository::new(db.clone());
    let channel = repository
        .by_id(route.channel_id, true)
        .await
        .map_err(|_| {
            abort_with_openai_message(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database operation failed",
                "",
                request_id,
            )
        })?;
    let Some(channel) = channel else {
        return Err(Box::new(abort_with_openai_message(
            StatusCode::SERVICE_UNAVAILABLE,
            &newapi_i18n::translate(
                language,
                "distributor.no_available_channel",
                std::iter::empty::<(&str, &str)>(),
            ),
            "model_not_found",
            request_id,
        )));
    };
    Ok(DistributedChannel {
        route,
        channel,
        route_path: "weighted",
    })
}

fn channel_error_response(
    error: &SelectError,
    group: &str,
    model: &str,
    language: &str,
    request_id: &str,
) -> Response {
    let show_group = if group == "auto" {
        format!("auto({group})")
    } else {
        group.to_owned()
    };
    let message = newapi_i18n::translate(
        language,
        "distributor.get_channel_failed",
        [
            ("Group", show_group),
            ("Model", model.to_owned()),
            ("Error", error.message()),
        ],
    );
    abort_with_openai_message(
        StatusCode::SERVICE_UNAVAILABLE,
        &message,
        "model_not_found",
        request_id,
    )
}

// ---------------------------------------------------------------------------
// 定价（Go helper.ModelPriceHelper 的非分层路径投影）
// ---------------------------------------------------------------------------

/// catalog `RatioSettings` 快照 + `GroupSettings` → billing
/// [`BillingRatioSettings`] 端口适配（计费核心的读取面约定）。
struct CatalogRatioAdapter {
    ratios: RatioSettings,
    groups: GroupSettings,
    user_group: String,
    using_group: String,
}

impl BillingRatioSettings for CatalogRatioAdapter {
    fn completion_ratio(&self, model: &str) -> f64 {
        self.ratios.get_completion_ratio(model)
    }
    fn audio_ratio(&self, model: &str) -> f64 {
        self.ratios.get_audio_ratio(model)
    }
    fn audio_completion_ratio(&self, model: &str) -> f64 {
        self.ratios.get_audio_completion_ratio(model)
    }
    fn group_ratio(&self, group: &str) -> f64 {
        self.groups.user_group_ratio(&self.user_group, group)
    }
    fn model_ratio(&self, model: &str) -> (f64, bool) {
        let (ratio, found, _match_name) = self.ratios.get_model_ratio(model);
        (ratio, found)
    }
    fn group_group_ratio(&self, user_group: &str, group: &str) -> Option<f64> {
        self.groups
            .group_group_ratio
            .get(user_group)
            .and_then(|ratios| ratios.get(group))
            .copied()
    }
    fn default_model_ratio(&self, _model: &str) -> Option<f64> {
        None // has_custom_model_ratio 审计面：出厂默认表归 pricing 切片
    }
    fn tool_price(&self, _tool: &str, _model: &str) -> f64 {
        0.0
    }
    fn gemini_input_audio_price_per_million(&self, _model: &str) -> f64 {
        0.0
    }
}

/// Go `ModelPriceHelper`（compute_price.go:70-181）的非分层路径输出。
struct ModelEstimate {
    price_data: PriceData,
    pre_consumed_quota: i64,
    free_model: bool,
}

fn model_price_helper(
    adapter: &CatalogRatioAdapter,
    model: &str,
    prompt_tokens: i64,
    max_tokens: i64,
) -> Result<ModelEstimate, RelayAttemptError> {
    let (model_price, use_price) = match adapter.ratios.get_model_price(model) {
        Some(price) => (price, true),
        None => (0.0, false),
    };
    let mut group_ratio_info = GroupRatioInfo {
        group_ratio: adapter.group_ratio(&adapter.using_group),
        ..GroupRatioInfo::default()
    };
    if let Some(special) = adapter.group_group_ratio(&adapter.user_group, &adapter.using_group) {
        group_ratio_info.group_special_ratio = special;
        group_ratio_info.group_ratio = special;
        group_ratio_info.has_special_ratio = true;
    }

    let mut estimate = ModelEstimate {
        price_data: PriceData::default(),
        pre_consumed_quota: 0,
        free_model: false,
    };

    if use_price {
        // 按价路径（compute_price.go:123-127, 164-174）。
        let quota_to_pre_consume = model_price * QUOTA_PER_UNIT * group_ratio_info.group_ratio;
        let (quota, clamp) = quota_from_float_checked(quota_to_pre_consume);
        if clamp.is_some() {
            return Err(model_price_overflow_error(model));
        }
        estimate.pre_consumed_quota = quota;
        // 免费判定（compute_price.go:130-146）：组倍率或价格 0 不预扣。
        if group_ratio_info.group_ratio == 0.0 || model_price == 0.0 {
            estimate.pre_consumed_quota = 0;
            estimate.free_model = true;
        }
        estimate.price_data = PriceData {
            model_price,
            model_ratio: 0.0,
            completion_ratio: adapter.ratios.get_completion_ratio(model),
            cache_ratio: adapter.ratios.get_cache_ratio(model).unwrap_or(1.0),
            cache_creation_ratio: adapter.ratios.get_create_cache_ratio(model).unwrap_or(1.0),
            cache_creation_5m_ratio: adapter.ratios.get_create_cache_ratio(model).unwrap_or(1.0),
            cache_creation_1h_ratio: adapter.ratios.get_create_cache_ratio(model).unwrap_or(1.0)
                * (6.0 / 3.75),
            image_ratio: adapter.ratios.get_image_ratio(model).unwrap_or(1.0),
            audio_ratio: adapter.ratios.get_audio_ratio(model),
            audio_completion_ratio: adapter.ratios.get_audio_completion_ratio(model),
            use_price: true,
            group_ratio_info,
            other_ratios: std::collections::HashMap::new(),
        };
        return Ok(estimate);
    }

    // 按倍率路径（compute_price.go:91-122）。
    let mut pre_consumed_tokens = prompt_tokens.max(PRE_CONSUMED_QUOTA);
    if max_tokens != 0 {
        pre_consumed_tokens += max_tokens;
    }
    let (model_ratio, found) = adapter.model_ratio(model);
    if !found {
        return Err(RelayAttemptError::new(
            400,
            "model_price_error",
            format!(
                "模型 {model} 的价格尚未由管理员配置，暂时无法使用，请联系站点管理员开启该模型；\
                 Model {model} has not been priced by the administrator yet. Please contact the site administrator to enable this model."
            ),
        ));
    }
    let ratio = model_ratio * group_ratio_info.group_ratio;
    let (quota, clamp) = quota_from_float_checked(pre_consumed_tokens as f64 * ratio);
    if clamp.is_some() {
        return Err(model_price_overflow_error(model));
    }
    estimate.pre_consumed_quota = quota;
    if group_ratio_info.group_ratio == 0.0 || model_ratio == 0.0 {
        estimate.pre_consumed_quota = 0;
        estimate.free_model = true;
    }
    estimate.price_data = PriceData {
        model_price,
        model_ratio,
        completion_ratio: adapter.ratios.get_completion_ratio(model),
        cache_ratio: adapter.ratios.get_cache_ratio(model).unwrap_or(1.0),
        cache_creation_ratio: adapter.ratios.get_create_cache_ratio(model).unwrap_or(1.0),
        cache_creation_5m_ratio: adapter.ratios.get_create_cache_ratio(model).unwrap_or(1.0),
        cache_creation_1h_ratio: adapter.ratios.get_create_cache_ratio(model).unwrap_or(1.0)
            * (6.0 / 3.75),
        image_ratio: adapter.ratios.get_image_ratio(model).unwrap_or(1.0),
        audio_ratio: adapter.ratios.get_audio_ratio(model),
        audio_completion_ratio: adapter.ratios.get_audio_completion_ratio(model),
        use_price: false,
        group_ratio_info,
        other_ratios: std::collections::HashMap::new(),
    };
    Ok(estimate)
}

fn model_price_overflow_error(model: &str) -> RelayAttemptError {
    RelayAttemptError::new(
        400,
        "model_price_error",
        format!("quota conversion overflow for model {model}"),
    )
}

// ---------------------------------------------------------------------------
// 用量解析（do_response 产物的计费读取面）
// ---------------------------------------------------------------------------

/// OpenAI / Claude 两种 usage 形状的读取（Go dto 层的计费读取面投影；
/// 完整 usage 语义随适配器切片补齐）。
fn usage_from_body(body: &Value) -> Usage {
    let usage = body.get("usage").cloned().unwrap_or(Value::Null);
    let get_i64 = |key: &str| usage.get(key).and_then(|v| v.as_i64()).unwrap_or(0);
    let prompt_tokens = get_i64("prompt_tokens").max(get_i64("input_tokens"));
    let completion_tokens = get_i64("completion_tokens").max(get_i64("output_tokens"));
    let total_tokens = get_i64("total_tokens").max(prompt_tokens + completion_tokens);
    Usage {
        prompt_tokens,
        completion_tokens,
        total_tokens,
        ..Usage::default()
    }
}

// ---------------------------------------------------------------------------
// 主链（Go handle_relay.go Relay）
// ---------------------------------------------------------------------------

/// 主链输入快照（relay_http 入口折叠 Request 后传入）。
pub struct RelayChainInput {
    pub relay_format: &'static str,
    pub request_id: String,
    pub language: String,
    pub identity: RelayTokenIdentity,
    pub path: String,
    pub payload: Value,
}

/// 主链结果：直接可写的响应。
pub async fn relay_chain(state: AppState, input: RelayChainInput) -> Response {
    let request_id = input.request_id.clone();
    let language = input.language.clone();
    let relay_format_static = input.relay_format;
    let Some(db) = state.db() else {
        return abort_with_openai_message(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database is not configured",
            "",
            &request_id,
        );
    };

    let model_request = model_request_from(&input.path, &input.payload);
    let fallback_mode = model_request
        .relay_mode_override
        .unwrap_or(relay_mode_consts::RELAY_MODE_UNKNOWN);
    let is_stream = input
        .payload
        .get("stream")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // ── Distribute（specific channel → 限额 → 选择）──────────────────────
    let distributed = match distribute_select(
        &state,
        &db,
        &input.identity,
        &input.path,
        &model_request.model,
        &request_id,
        &language,
    )
    .await
    {
        Ok(distributed) => distributed,
        Err(response) => return *response,
    };

    let input_snapshot = newapi_relay::relay_info::RelayInfoInput {
        token_group: input.identity.token_group.clone(),
        user_group: input.identity.user_group.clone(),
        request_start_time_ms: 0,
        request_id: request_id.clone(),
        user_id: input.identity.user_id,
        using_group: input.identity.using_group.clone(),
        user_quota: input.identity.token_remain_quota,
        user_email: String::new(),
        origin_model_name: model_request.model.clone(),
        token_id: input.identity.token_id,
        token_key: input.identity.token_key.clone(),
        token_unlimited: input.identity.token_unlimited_quota,
        path: input.path.clone(),
        request_uri: input.path.clone(),
        request_headers: Vec::new(),
        estimated_tokens: 0,
        user_setting_raw: Value::Null,
        relay_mode_fallback: fallback_mode,
        is_stream,
    };
    let mut info = match newapi_relay::relay_info::gen_relay_info(
        relay_format_static,
        &input_snapshot,
        &input.payload,
    ) {
        Ok(info) => info,
        Err(_) => {
            return abort_with_openai_message(
                StatusCode::BAD_REQUEST,
                "invalid relay format",
                "",
                &request_id,
            );
        }
    };
    info.append_request_conversion(relay_format_static);
    let start_time_ms = info.start_time_ms;

    // ── 估价（handle_relay.go:179-191 的 ratio 面）───────────────────────
    let ratios: RatioSettings = state.ratio_settings();
    let adapter = CatalogRatioAdapter {
        ratios,
        groups: state.group_settings(),
        user_group: input.identity.user_group.clone(),
        using_group: input.identity.using_group.clone(),
    };
    let max_tokens = input
        .payload
        .get("max_completion_tokens")
        .and_then(|v| v.as_u64())
        .or_else(|| input.payload.get("max_tokens").and_then(|v| v.as_u64()))
        .unwrap_or(0) as i64;
    let estimate = match model_price_helper(&adapter, &model_request.model, 0, max_tokens) {
        Ok(estimate) => estimate,
        Err(error) => {
            return write_error_envelope(relay_format_static, &error, &request_id, &language);
        }
    };

    // ── 渠道绑定（第一次尝试的渠道；Go InitChannelMeta 在 getChannel 后写，
    // 这里的绑定先于预扣费以让 RelayBillingInfo.channel_id 有值）───────────
    let initial = distributed;
    setup_context_for_selected_channel(
        &mut info,
        &initial.route,
        &initial.channel,
        &model_request.model,
    );

    // ── 预扣费（handle_relay.go:195-202；免费模型跳过）────────────────────
    let billing_store = BillingStore::new(db.clone());
    let mut billing_info = RelayBillingInfo {
        user_id: input.identity.user_id,
        token_id: input.identity.token_id,
        token_key: input.identity.token_key.clone(),
        is_playground: false,
        force_pre_consume: false,
        token_unlimited: input.identity.token_unlimited_quota,
        token_quota: input.identity.token_remain_quota,
        user_quota: 0,
        billing_preference: String::new(),
        request_id: request_id.clone(),
        origin_model_name: model_request.model.clone(),
        using_group: input.identity.using_group.clone(),
        user_group: input.identity.user_group.clone(),
        channel_id: initial.route.channel_id,
        token_name: input.identity.token_name.clone(),
        username: input.identity.username.clone(),
        is_stream,
        group_ratio: estimate.price_data.group_ratio(),
        ..RelayBillingInfo::default()
    };

    // Option<BillingSession> 的生命周期问题：会话借BillingStore，
    // Option::take 后由调用点立即使用（Rust 侧会话不挂 RelayInfo）。
    let mut session = if estimate.free_model {
        None
    } else {
        match pre_consume_billing(
            &billing_store,
            billing_info.clone(),
            estimate.pre_consumed_quota,
        )
        .await
        {
            Ok(opened) => Some(opened),
            Err(error) => {
                return write_billing_error_envelope(
                    relay_format_static,
                    &error,
                    &request_id,
                    &language,
                );
            }
        }
    };

    // ── 重试环（handle_relay.go:246-495 的骨架面）────────────────────────
    // 终态语义（Go）：
    // - 尝试帽耗尽后退出循环（retry > RetryTimes）→ 最后一次尝试的原始错误
    //   直通（不是 failover 包裹）；
    // - 重选无候选（getChannel 失败）→ terminalFailoverError 包裹
    //   （暂存 4xx 直通 / 冷却 504+Retry-After / 无冷却 503）。
    let retry_times = load_retry_times(&db).await;
    let max_attempts = retry_times + 1;
    let mut exclude = ExcludeRoutes::new();
    let mut stashed: Option<RelayAttemptError> = None;
    let mut last_error: Option<RelayAttemptError> = None;
    let mut attempt: i32 = 0;
    let mut terminal: Option<RelayAttemptError> = None;
    let mut outcome: Option<newapi_relay::dispatch::AdaptorOutcome> = None;
    let mut used_channels: Vec<i64> = Vec::new();
    let mut settled_channel_id: Option<i64> = None;

    let mut current: Option<DistributedChannel> = Some(initial);

    loop {
        if attempt >= max_attempts {
            // Go 循环条件出口：最后尝试错误直通。
            terminal = Some(last_error.unwrap_or_else(|| terminal_failover_error(None, None, 0)));
            break;
        }
        let Some(DistributedChannel { route, .. }) = current.take() else {
            // 重试换道：排除已试 route unit 后重选（Go getChannel 的
            // ChannelMeta 非空分支）。无候选 → failover 终态包裹。
            match select_route_unit_db(
                &db,
                &input.identity.using_group,
                &model_request.model,
                &exclude,
            )
            .await
            {
                Ok(Some((route, channel))) => {
                    setup_context_for_selected_channel(
                        &mut info,
                        &route,
                        &channel,
                        &model_request.model,
                    );
                    current = Some(DistributedChannel {
                        route,
                        channel,
                        route_path: "weighted",
                    });
                    continue;
                }
                Ok(None) => {
                    terminal = Some(terminal_failover_error(None, stashed.take(), 0));
                }
                Err(error) => {
                    terminal = Some(RelayAttemptError::new(
                        503,
                        "get_channel_failed",
                        format!(
                            "获取分组 {} 下模型 {} 的可用渠道失败（retry）: {error}",
                            input.identity.using_group, model_request.model
                        ),
                    ));
                }
            }
            break;
        };

        used_channels.push(route.channel_id);
        exclude.mark_tried(route.route_key());

        // ── adaptor 调用链（Go relayHandler 分发表 → helper → adaptor）────
        let factory = state.adaptor_factory();
        let dispatch_result = newapi_relay::dispatch::run_adaptor_dispatch(
            factory.as_ref(),
            &mut info,
            &input.payload,
        );

        match dispatch_result {
            Ok(adaptor_outcome) => {
                settled_channel_id = Some(route.channel_id);
                outcome = Some(adaptor_outcome);
                break;
            }
            Err(error) => {
                last_error = Some(error.clone());
                let kind = classify_attempt(Some(&error));
                match kind {
                    RelayAttemptKind::Retryable | RelayAttemptKind::Throttled => {
                        stashed = None;
                    }
                    RelayAttemptKind::FatalSwitchable => {
                        stashed = Some(error.clone());
                    }
                    RelayAttemptKind::Fatal | RelayAttemptKind::Done => {
                        terminal = Some(error);
                        break;
                    }
                }
                // 换道资格 AND 管理员范围（shouldRetry）：specific channel
                // 不重试（Go specific_channel_id 短路）。
                let may_retry = input.identity.specific_channel_id.is_none()
                    && should_retry(Some(&error), retry_times);
                if !may_retry {
                    terminal = Some(error);
                    break;
                }
                attempt += 1;
            }
        }
    }

    // ── 结算 / 退款（handle_relay.go:204-213 defer 面）────────────────────
    if let (Some(outcome), Some(channel_id)) = (outcome.as_ref(), settled_channel_id) {
        let usage = usage_from_body(&outcome.body);
        let summary = calculate_text_quota_summary(
            &adapter,
            &mut billing_info,
            &estimate.price_data,
            Some(&usage),
            &TextCallContext {
                token_name: input.identity.token_name.clone(),
                tools: Default::default(),
                final_relay_format: info.get_final_request_relay_format(),
                estimate_prompt_tokens: info.get_estimate_prompt_tokens(),
                is_open_router_channel: false,
                empty_response_multiplier: 0.0,
                stream_end_client_gone: false,
            },
            now_seconds(),
            start_time_ms / 1000,
        );
        // 分层计费覆盖（Go TryTieredSettle）属分层表达式计费切片，未合流：
        // 非分层路径直接采用 summary.quota。
        if let Some(session) = session.as_mut()
            && let Err(error) = session.settle_billing(summary.quota).await
        {
            tracing::error!(
                event = "settle_billing_failed",
                request_id = request_id,
                "settle billing failed: {}",
                error.message
            );
        }
        record_consume_log_quiet(
            &db,
            &input.identity,
            &model_request.model,
            channel_id,
            &summary,
            &request_id,
            start_time_ms,
        )
        .await;
        // 成功回写（Go handler 直接写响应体）。
        let status = StatusCode::from_u16(outcome.status).unwrap_or(StatusCode::OK);
        return (status, axum::Json(outcome.body.clone())).into_response();
    }

    // 失败：退款（Go relayInfo.Billing.Refund 幂等）。
    if let Some(session) = session.as_mut() {
        session.refund().await;
    }
    let error = terminal.unwrap_or_else(|| terminal_failover_error(None, None, 0));
    tracing::warn!(
        event = "relay_error",
        request_id = request_id,
        used_channels = ?used_channels,
        "relay error: {}",
        error.message
    );
    write_error_envelope(relay_format_static, &error, &request_id, &language)
}

// ---------------------------------------------------------------------------
// 日志写侧（Go RecordConsumeLog 的接线）
// ---------------------------------------------------------------------------

/// Go 经 gopool 异步执行；Rust 骨架同步等待（写失败只记 warning，不影响
/// 响应）。契约测试写后即读，内联 await 免除竞态。
async fn record_consume_log_quiet(
    db: &newapi_storage::Database,
    identity: &RelayTokenIdentity,
    model_name: &str,
    channel_id: i64,
    summary: &TextQuotaSummary,
    request_id: &str,
    start_time_ms: i64,
) {
    let params = newapi_usage::store_log::RecordConsumeLogParams {
        channel_id,
        prompt_tokens: summary.prompt_tokens,
        completion_tokens: summary.completion_tokens,
        model_name: model_name.to_owned(),
        token_name: summary.token_name.clone(),
        quota: summary.quota,
        content: format!(
            "模型倍率 {}，分组倍率 {}",
            summary.model_ratio, summary.group_ratio
        ),
        token_id: identity.token_id,
        use_time_seconds: (now_millis() - start_time_ms) / 1000,
        is_stream: false,
        group: identity.using_group.clone(),
        other: Map::new(),
    };
    let context = newapi_usage::store_log::ConsumeLogContext {
        user_id: identity.user_id,
        username: identity.username.clone(),
        request_id: request_id.to_owned(),
        consume_enabled: true,
        ..Default::default()
    };
    if let Err(error) = newapi_usage::store_log::record_consume_log(db, &context, &params).await {
        tracing::warn!("failed to record consume log: {error}");
    }
}

fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// 错误信封（Go handle_relay.go:113-139 defer 面的形状分流）
// ---------------------------------------------------------------------------

/// 错误信封按 relay_format 分形状：OpenAI `{"error": {...}}` /
/// Claude `{"type":"error","error":{...}}`。request id 追加（Go
/// `MessageWithRequestId`）。
pub fn write_error_envelope(
    relay_format: &str,
    error: &RelayAttemptError,
    request_id: &str,
    _language: &str,
) -> Response {
    let message = if request_id.is_empty() {
        error.message.clone()
    } else {
        format!("{} (request id: {request_id})", error.message)
    };
    let status =
        StatusCode::from_u16(error.status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    if relay_format == relay_format::CLAUDE {
        (
            status,
            axum::Json(serde_json::json!({
                "type": "error",
                "error": {
                    "type": "new_api_error",
                    "message": message,
                }
            })),
        )
            .into_response()
    } else {
        (
            status,
            axum::Json(serde_json::json!({
                "error": {
                    "message": message,
                    "type": "new_api_error",
                    "code": error.code,
                }
            })),
        )
            .into_response()
    }
}

fn write_billing_error_envelope(
    relay_format: &str,
    error: &BillingApiError,
    request_id: &str,
    language: &str,
) -> Response {
    let attempt_error = RelayAttemptError::new(error.status, error.code, error.message.clone());
    write_error_envelope(relay_format, &attempt_error, request_id, language)
}
