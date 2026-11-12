//! 亲和缓存写侧（Go `internal/catalog/track_affinity.go` 的缓存面移植）。
//!
//! 移植范围：
//! - `HybridCache` 的内存面语义（`cachex/hybrid_cache.go` +
//!   `namespace.go` 的 `FullKey` 幂等键）：LRU + 每条 TTL + 容量上限。
//! - 渠道亲和主缓存：`RecordChannelAffinity`（:800-825）、
//!   `GetPreferredChannelByAffinity` 的缓存命中段（:656-664）、
//!   `ClearChannelAffinityCacheAll/ByRuleName`（:159-195）、
//!   `GetChannelAffinityCacheStats`（:108-155）。
//! - 用量缓存计数器：`ChannelAffinityUsageCacheCounters`、
//!   `observeChannelAffinityUsageCache`（:846-905）的计数语义、
//!   `GetChannelAffinityUsageCacheStats`（:776-810）。
//!
//! 有意偏差（登记为遗留）：
//! - Redis 面（`cachex.HybridCache` 的 redisEnabled 分支）未移植，缓存为
//!   单进程内存；Go 无 Redis 时同为单进程内存，行为只在多副本部署下有差。
//! - `GetPreferredChannelByAffinity` 的规则匹配段（model/path 正则、
//!   key source 提取、gjson/headers）属 relay 数据面，未移植；本模块提供
//!   缓存原语与按 cache key 的读写。
//! - `GetChannelAffinityStatsContext`（:483-509，从请求上下文取 meta）依赖
//!   `contract.Context`，未移植。

use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use serde::Serialize;
use sha1::{Digest, Sha1};

/// Go `track_affinity.go:32-33`。
pub const CHANNEL_AFFINITY_CACHE_NAMESPACE: &str = "new-api:channel_affinity:v1";
pub const CHANNEL_AFFINITY_USAGE_CACHE_STATS_NAMESPACE: &str =
    "new-api:channel_affinity_usage_cache_stats:v1";

// ---------------------------------------------------------------------------
// 设置（Go track_affinity_setting.go 的写侧相关字段）
// ---------------------------------------------------------------------------

/// Go `ChannelAffinityRule` 中影响缓存键结构与统计的规则字段。
#[derive(Debug, Clone, Default)]
pub struct ChannelAffinityRule {
    pub name: String,
    pub include_rule_name: bool,
    pub include_model_name: bool,
    pub include_using_group: bool,
}

/// Go `ChannelAffinitySetting`（track_affinity_setting.go:30-37）。
#[derive(Debug, Clone, Default)]
pub struct ChannelAffinitySetting {
    pub enabled: bool,
    pub max_entries: i64,
    pub default_ttl_seconds: i64,
    pub rules: Vec<ChannelAffinityRule>,
}

impl ChannelAffinitySetting {
    /// Go `track_affinity_setting.go:112-153` 默认值（只保留写侧字段）。
    pub fn default_setting() -> Self {
        Self {
            enabled: true,
            max_entries: 100_000,
            default_ttl_seconds: 3600,
            rules: vec![
                ChannelAffinityRule {
                    name: "codex cli trace".to_owned(),
                    include_rule_name: true,
                    include_model_name: false,
                    include_using_group: true,
                },
                ChannelAffinityRule {
                    name: "claude cli trace".to_owned(),
                    include_rule_name: true,
                    include_model_name: false,
                    include_using_group: true,
                },
            ],
        }
    }
}

static SETTING: RwLock<Option<ChannelAffinitySetting>> = RwLock::new(None);

/// Go `GetChannelAffinitySetting`（track_affinity_setting.go:156-158）。
pub fn get_channel_affinity_setting() -> ChannelAffinitySetting {
    SETTING
        .read()
        .expect("channel affinity setting")
        .clone()
        .unwrap_or_else(ChannelAffinitySetting::default_setting)
}

/// 测试/选项接线：替换全局设置（Go 通过 settings.GlobalConfig.Register）。
pub fn set_channel_affinity_setting(setting: ChannelAffinitySetting) {
    *SETTING.write().expect("channel affinity setting") = Some(setting);
}

fn effective_capacity(max_entries: i64) -> usize {
    if max_entries <= 0 {
        100_000
    } else {
        max_entries as usize
    }
}

fn effective_default_ttl(default_ttl_seconds: i64) -> Duration {
    let seconds = if default_ttl_seconds <= 0 {
        3600
    } else {
        default_ttl_seconds
    };
    Duration::from_secs(seconds as u64)
}

// ---------------------------------------------------------------------------
// TTL + LRU 缓存（Go cachex.HybridCache 的内存面 + hot.LRU）
// ---------------------------------------------------------------------------

struct CacheEntry<V> {
    value: V,
    expires_at: Option<Instant>,
    last_used: u64,
}

struct CacheInner<V> {
    map: HashMap<String, CacheEntry<V>>,
    /// `last_used -> key`，LRU 驱逐从最小顺位开始。
    order: BTreeMap<u64, String>,
    seq: u64,
}

/// 带 TTL 与 LRU 驱逐的进程内缓存。容量与 Go `hot.LRU` 对齐：超出容量时
/// 先清过期，仍超则按最近最少使用驱逐。
pub struct TtlLruCache<V> {
    namespace: &'static str,
    capacity: usize,
    inner: Mutex<CacheInner<V>>,
}

impl<V: Clone> TtlLruCache<V> {
    pub fn new(namespace: &'static str, capacity: usize) -> Self {
        Self {
            namespace,
            capacity: capacity.max(1),
            inner: Mutex::new(CacheInner {
                map: HashMap::new(),
                order: BTreeMap::new(),
                seq: 0,
            }),
        }
    }

    /// Go `cachex.Namespace.FullKey`（namespace.go:17-29）：幂等——已是
    /// 命名空间前缀的键原样返回，其余补前缀。
    pub fn full_key(&self, key: &str) -> String {
        let key = key.trim();
        if key.is_empty() {
            return String::new();
        }
        let prefix = format!("{}:", self.namespace);
        if key.starts_with(&prefix) {
            return key.to_owned();
        }
        format!("{}{}", prefix, key.trim_start_matches(':'))
    }

    fn expired(entry: &CacheEntry<V>, now: Instant) -> bool {
        entry.expires_at.is_some_and(|at| at <= now)
    }

    /// Go `HybridCache.Get`。命中刷新 LRU 顺位；过期视为未命中并清除。
    pub fn get(&self, key: &str) -> Option<V> {
        let full = self.full_key(key);
        if full.is_empty() {
            return None;
        }
        let mut inner = self.inner.lock().expect("affinity cache");
        let now = Instant::now();
        let expired_seq = match inner.map.get(&full) {
            Some(entry) if Self::expired(entry, now) => Some(entry.last_used),
            Some(_) => None,
            None => return None,
        };
        if let Some(seq) = expired_seq {
            inner.order.remove(&seq);
            inner.map.remove(&full);
            return None;
        }
        let (seq_before, value) = {
            let entry = inner.map.get(&full)?;
            (entry.last_used, entry.value.clone())
        };
        // 刷新顺位：旧 seq 出、新 seq 入。
        inner.seq += 1;
        let seq_new = inner.seq;
        inner.order.remove(&seq_before);
        inner.order.insert(seq_new, full.clone());
        if let Some(entry) = inner.map.get_mut(&full) {
            entry.last_used = seq_new;
        }
        Some(value)
    }

    /// Go `HybridCache.SetWithTTL`。
    pub fn set_with_ttl(&self, key: &str, value: V, ttl: Duration) {
        let full = self.full_key(key);
        if full.is_empty() {
            return;
        }
        let mut inner = self.inner.lock().expect("affinity cache");
        let now = Instant::now();
        if let Some(old) = inner.map.remove(&full) {
            inner.order.remove(&old.last_used);
        }
        inner.seq += 1;
        let seq = inner.seq;
        inner.order.insert(seq, full.clone());
        inner.map.insert(
            full,
            CacheEntry {
                value,
                expires_at: Some(now + ttl),
                last_used: seq,
            },
        );
        while inner.map.len() > self.capacity && !inner.order.is_empty() {
            if !Self::evict_one(&mut inner, now) {
                break;
            }
        }
    }

    /// 清过期；仍超容量则驱逐最久未用的一条。返回是否驱逐了条目。
    fn evict_one(inner: &mut CacheInner<V>, now: Instant) -> bool {
        let expired: Vec<(u64, String)> = inner
            .map
            .iter()
            .filter(|(_, e)| Self::expired(e, now))
            .map(|(k, e)| (e.last_used, k.clone()))
            .collect();
        for (seq, key) in expired {
            inner.map.remove(&key);
            inner.order.remove(&seq);
        }
        if inner.map.is_empty() {
            return false;
        }
        let Some((_seq, key)) = inner.order.pop_first() else {
            return false;
        };
        inner.map.remove(&key);
        true
    }

    /// Go `HybridCache.Keys`：返回未过期的完整键（含命名空间前缀），
    /// 按 LRU 顺位输出。
    pub fn keys(&self) -> Vec<String> {
        let inner = self.inner.lock().expect("affinity cache");
        let now = Instant::now();
        inner
            .order
            .values()
            .filter(|key| inner.map.get(*key).is_some_and(|e| !Self::expired(e, now)))
            .cloned()
            .collect()
    }

    /// Go `HybridCache.DeleteMany`：返回每个键是否实际删除。
    pub fn delete_many(&self, keys: &[String]) -> Vec<bool> {
        let mut inner = self.inner.lock().expect("affinity cache");
        keys.iter()
            .map(|key| {
                let full = self.full_key(key);
                if full.is_empty() {
                    return false;
                }
                match inner.map.remove(&full) {
                    Some(entry) => {
                        inner.order.remove(&entry.last_used);
                        true
                    }
                    None => false,
                }
            })
            .collect()
    }

    /// Go `cache.DeleteByPrefix`：删除完整键命中前缀的条目，返回条数。
    pub fn delete_by_prefix(&self, prefix: &str) -> usize {
        let full_prefix = self.full_key(prefix);
        if full_prefix.is_empty() {
            return 0;
        }
        let mut inner = self.inner.lock().expect("affinity cache");
        let matched: Vec<(u64, String)> = inner
            .map
            .iter()
            .filter(|(key, _)| key.starts_with(&full_prefix))
            .map(|(key, e)| (e.last_used, key.clone()))
            .collect();
        let deleted = matched.len();
        for (seq, key) in matched {
            inner.map.remove(&key);
            inner.order.remove(&seq);
        }
        deleted
    }

    /// 条目数（含未过期与已过期未清的；Go 的 janitor 同为惰性清理）。
    pub fn len(&self) -> usize {
        self.inner.lock().expect("affinity cache").map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 测试辅助：按完整键取值（不刷新顺位）。
    pub fn peek(&self, key: &str) -> Option<V> {
        let full = self.full_key(key);
        let inner = self.inner.lock().expect("affinity cache");
        inner
            .map
            .get(&full)
            .filter(|e| !Self::expired(e, Instant::now()))
            .map(|e| e.value.clone())
    }
}

// ---------------------------------------------------------------------------
// 渠道亲和主缓存
// ---------------------------------------------------------------------------

fn channel_affinity_cache() -> &'static TtlLruCache<i64> {
    static CACHE: OnceLock<TtlLruCache<i64>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let setting = get_channel_affinity_setting();
        TtlLruCache::new(
            CHANNEL_AFFINITY_CACHE_NAMESPACE,
            effective_capacity(setting.max_entries),
        )
    })
}

/// Go `buildChannelAffinityCacheKeySuffix`（track_affinity.go:269-286）。
pub fn build_channel_affinity_cache_key_suffix(
    rule: &ChannelAffinityRule,
    model_name: &str,
    using_group: &str,
    affinity_value: &str,
) -> String {
    let mut parts: Vec<&str> = Vec::with_capacity(4);
    if rule.include_rule_name && !rule.name.is_empty() {
        parts.push(&rule.name);
    }
    if rule.include_model_name && !model_name.is_empty() {
        parts.push(model_name);
    }
    if rule.include_using_group && !using_group.is_empty() {
        parts.push(using_group);
    }
    parts.push(affinity_value);
    parts.join(":")
}

/// Go `affinityFingerprint`（track_affinity.go:510-518）：SHA1 前 8 位 hex。
pub fn affinity_fingerprint(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    let digest = Sha1::digest(value.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
    hex.chars().take(8).collect()
}

/// Go `buildChannelAffinityKeyHint`（track_affinity.go:520-531）。
pub fn build_channel_affinity_key_hint(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let flattened = trimmed.replace(['\n', '\r'], " ");
    if flattened.len() <= 12 {
        return flattened;
    }
    // Go 按 byte 切：s[:4] + "..." + s[len-4:]。
    let bytes = flattened.as_bytes();
    let head = String::from_utf8_lossy(&bytes[..4]);
    let tail = String::from_utf8_lossy(&bytes[bytes.len() - 4..]);
    format!("{}...{}", head, tail)
}

/// Go `RecordChannelAffinity`（track_affinity.go:800-825）的缓存写段：
/// `cacheKey` 为调用方组装的键（可带或不带命名空间前缀，FullKey 幂等），
/// TTL <= 0 时回退设置默认值，再兜底 3600。
pub fn record_channel_affinity(cache_key: &str, ttl_seconds: i64, channel_id: i64) {
    if channel_id <= 0 || cache_key.trim().is_empty() {
        return;
    }
    let setting = get_channel_affinity_setting();
    if !setting.enabled {
        return;
    }
    let ttl_seconds = if ttl_seconds <= 0 {
        if setting.default_ttl_seconds <= 0 {
            3600
        } else {
            setting.default_ttl_seconds
        }
    } else {
        ttl_seconds
    };
    channel_affinity_cache().set_with_ttl(
        cache_key,
        channel_id,
        Duration::from_secs(ttl_seconds as u64),
    );
}

/// Go `GetPreferredChannelByAffinity` 的缓存命中段（track_affinity.go:656-664）。
pub fn get_preferred_channel_by_affinity(cache_key_suffix: &str) -> Option<i64> {
    channel_affinity_cache().get(cache_key_suffix)
}

/// Go `ClearChannelAffinityCacheAll`（track_affinity.go:158-172）。
pub fn clear_channel_affinity_cache_all() -> usize {
    let cache = channel_affinity_cache();
    let keys = cache.keys();
    if !keys.is_empty() {
        cache.delete_many(&keys);
    }
    keys.len()
}

/// Go `ClearChannelAffinityCacheByRuleName`（track_affinity.go:174-195）。
/// 错误文案逐字复刻（Go `fmt.Errorf` 字面量）。
pub fn clear_channel_affinity_cache_by_rule_name(rule_name: &str) -> Result<usize, String> {
    let rule_name = rule_name.trim();
    if rule_name.is_empty() {
        return Err("rule_name 不能为空".to_owned());
    }
    let setting = get_channel_affinity_setting();
    let matched = setting
        .rules
        .iter()
        .find(|rule| rule.name.trim() == rule_name);
    let Some(rule) = matched else {
        return Err("未知规则名称".to_owned());
    };
    if !rule.include_rule_name {
        return Err("该规则未启用 include_rule_name，无法按规则清空缓存".to_owned());
    }
    Ok(channel_affinity_cache().delete_by_prefix(rule_name))
}

/// Go `ChannelAffinityCacheStats`（track_affinity.go:64-71）。
#[derive(Debug, Clone, Default, Serialize)]
pub struct ChannelAffinityCacheStats {
    pub enabled: bool,
    pub total: i64,
    pub unknown: i64,
    pub by_rule_name: std::collections::BTreeMap<String, i64>,
    pub cache_capacity: i64,
    pub cache_algo: String,
}

/// Go `GetChannelAffinityCacheStats`（track_affinity.go:108-155）。
pub fn get_channel_affinity_cache_stats() -> ChannelAffinityCacheStats {
    let setting = get_channel_affinity_setting();
    let mut rule_by_name: std::collections::HashMap<String, &ChannelAffinityRule> =
        std::collections::HashMap::new();
    for rule in &setting.rules {
        let name = rule.name.trim();
        if name.is_empty() || !rule.include_rule_name {
            continue;
        }
        rule_by_name.insert(name.to_owned(), rule);
    }
    let mut by_rule_name: std::collections::BTreeMap<String, i64> =
        rule_by_name.keys().map(|name| (name.clone(), 0)).collect();

    let cache = channel_affinity_cache();
    let keys = cache.keys();
    let mut total: i64 = 0;
    let mut unknown: i64 = 0;
    let prefix = format!("{}:", CHANNEL_AFFINITY_CACHE_NAMESPACE);
    for key in &keys {
        total += 1;
        let Some(rest) = key.strip_prefix(&prefix) else {
            unknown += 1;
            continue;
        };
        let parts: Vec<&str> = rest.split(':').collect();
        if parts.len() < 2 {
            unknown += 1;
            continue;
        }
        let Some(rule) = rule_by_name.get(parts[0]) else {
            unknown += 1;
            continue;
        };
        if rule.include_model_name && parts.len() < 3 {
            unknown += 1;
            continue;
        }
        if rule.include_using_group {
            let min_parts = if rule.include_model_name { 4 } else { 3 };
            if parts.len() < min_parts {
                unknown += 1;
                continue;
            }
        }
        *by_rule_name.entry(parts[0].to_owned()).or_insert(0) += 1;
    }

    ChannelAffinityCacheStats {
        enabled: setting.enabled,
        total,
        unknown,
        by_rule_name,
        cache_capacity: effective_capacity(setting.max_entries) as i64,
        cache_algo: "LRU".to_owned(),
    }
}

// ---------------------------------------------------------------------------
// 用量缓存计数器（Go :734-905）
// ---------------------------------------------------------------------------

/// Go `cacheTokenRateMode*` 常量（track_affinity.go:57-61）。
pub const CACHE_TOKEN_RATE_MODE_CACHED_OVER_PROMPT: &str = "cached_over_prompt";
pub const CACHE_TOKEN_RATE_MODE_CACHED_OVER_PROMPT_PLUS_CACHED: &str =
    "cached_over_prompt_plus_cached";
pub const CACHE_TOKEN_RATE_MODE_MIXED: &str = "mixed";

/// Go `ChannelAffinityUsageCacheCounters`（track_affinity.go:746-757）。
#[derive(Debug, Clone, Default)]
pub struct ChannelAffinityUsageCacheCounters {
    pub cached_token_rate_mode: String,
    pub hit: i64,
    pub total: i64,
    pub window_seconds: i64,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub total_tokens: i64,
    pub cached_tokens: i64,
    pub prompt_cache_hit_tokens: i64,
    pub last_seen_at: i64,
}

/// Go `ChannelAffinityUsageCacheStats`（track_affinity.go:722-741），JSON
/// 键名按 Go tag；读端点（log_http 的 affinity handler）直接序列化它。
#[derive(Debug, Clone, Default, Serialize)]
pub struct ChannelAffinityUsageCacheStats {
    pub rule_name: String,
    pub using_group: String,
    #[serde(rename = "key_fp")]
    pub key_fp: String,
    pub cached_token_rate_mode: String,
    pub hit: i64,
    pub total: i64,
    pub window_seconds: i64,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub total_tokens: i64,
    pub cached_tokens: i64,
    pub prompt_cache_hit_tokens: i64,
    pub last_seen_at: i64,
}

/// Go `ChannelAffinityStatsContext`（track_affinity.go:74-80）。
#[derive(Debug, Clone, Default)]
pub struct ChannelAffinityStatsContext {
    pub rule_name: String,
    pub using_group: String,
    pub key_fp: String,
    pub ttl_seconds: i64,
}

fn usage_cache() -> &'static TtlLruCache<ChannelAffinityUsageCacheCounters> {
    static CACHE: OnceLock<TtlLruCache<ChannelAffinityUsageCacheCounters>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let setting = get_channel_affinity_setting();
        TtlLruCache::new(
            CHANNEL_AFFINITY_USAGE_CACHE_STATS_NAMESPACE,
            effective_capacity(setting.max_entries),
        )
    })
}

/// Go `channelAffinityUsageCacheEntryKey`（track_affinity.go:939-950）：
/// `\n` 连接，rule_name 与 key_fp 必填。
pub fn channel_affinity_usage_cache_entry_key(
    rule_name: &str,
    using_group: &str,
    key_fp: &str,
) -> String {
    let rule_name = rule_name.trim();
    let using_group = using_group.trim();
    let key_fp = key_fp.trim();
    if rule_name.is_empty() || key_fp.is_empty() {
        return String::new();
    }
    format!("{}\n{}\n{}", rule_name, using_group, key_fp)
}

/// Go `normalizeCachedTokenRateMode`（track_affinity.go:907-917）。
pub fn normalize_cached_token_rate_mode(mode: &str) -> Option<&'static str> {
    match mode {
        CACHE_TOKEN_RATE_MODE_CACHED_OVER_PROMPT => Some(CACHE_TOKEN_RATE_MODE_CACHED_OVER_PROMPT),
        CACHE_TOKEN_RATE_MODE_CACHED_OVER_PROMPT_PLUS_CACHED => {
            Some(CACHE_TOKEN_RATE_MODE_CACHED_OVER_PROMPT_PLUS_CACHED)
        }
        CACHE_TOKEN_RATE_MODE_MIXED => Some(CACHE_TOKEN_RATE_MODE_MIXED),
        _ => None,
    }
}

/// 一次用量观察（Go `usageCacheSignals`/`usagePromptTokens` 等的计算结果
/// 由调用方从 dto.Usage 提炼；relay 数据面未移植）。
#[derive(Debug, Clone, Copy, Default)]
pub struct UsageObservation {
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub total_tokens: i64,
    pub cached_tokens: i64,
    pub prompt_cache_hit_tokens: i64,
}

impl UsageObservation {
    /// Go `usageCacheSignals` 的 hit 判定（track_affinity.go:952-977）。
    pub fn hit(&self) -> bool {
        self.cached_tokens > 0 || self.prompt_cache_hit_tokens > 0
    }
}

/// Go `observeChannelAffinityUsageCache`（track_affinity.go:846-905）：
/// `total` 恒 +1，hit 判定后累加各 token 计数并刷新 `last_seen_at`；
/// rate mode 首见固化，异见转 `mixed`。TTL <= 0 时整个观察被吞。
pub fn observe_channel_affinity_usage_cache(
    stats_ctx: &ChannelAffinityStatsContext,
    observation: &UsageObservation,
    cached_token_rate_mode: &str,
) {
    let entry_key = channel_affinity_usage_cache_entry_key(
        &stats_ctx.rule_name,
        &stats_ctx.using_group,
        &stats_ctx.key_fp,
    );
    if entry_key.is_empty() {
        return;
    }
    let window_seconds = stats_ctx.ttl_seconds;
    if window_seconds <= 0 {
        return;
    }
    let cache = usage_cache();
    let mut next = cache.get(&entry_key).unwrap_or_default();
    if let Some(mode) = normalize_cached_token_rate_mode(cached_token_rate_mode) {
        if next.cached_token_rate_mode.is_empty() {
            next.cached_token_rate_mode = mode.to_owned();
        } else if next.cached_token_rate_mode != mode
            && next.cached_token_rate_mode != CACHE_TOKEN_RATE_MODE_MIXED
        {
            next.cached_token_rate_mode = CACHE_TOKEN_RATE_MODE_MIXED.to_owned();
        }
    }
    next.total += 1;
    if observation.hit() {
        next.hit += 1;
    }
    next.window_seconds = window_seconds;
    next.last_seen_at = chrono_now();
    next.cached_tokens += observation.cached_tokens;
    next.prompt_cache_hit_tokens += observation.prompt_cache_hit_tokens;
    next.prompt_tokens += observation.prompt_tokens;
    next.completion_tokens += observation.completion_tokens;
    next.total_tokens += observation.total_tokens;
    cache.set_with_ttl(&entry_key, next, Duration::from_secs(window_seconds as u64));
}

/// Go `GetChannelAffinityUsageCacheStats`（track_affinity.go:776-810）：
/// 未命中回显三个入参、计数器全零。
pub fn get_channel_affinity_usage_cache_stats(
    rule_name: &str,
    using_group: &str,
    key_fp: &str,
) -> ChannelAffinityUsageCacheStats {
    let rule_name = rule_name.trim();
    let using_group = using_group.trim();
    let key_fp = key_fp.trim();
    let echo = ChannelAffinityUsageCacheStats {
        rule_name: rule_name.to_owned(),
        using_group: using_group.to_owned(),
        key_fp: key_fp.to_owned(),
        ..ChannelAffinityUsageCacheStats::default()
    };
    let entry_key = channel_affinity_usage_cache_entry_key(rule_name, using_group, key_fp);
    if entry_key.is_empty() {
        return echo;
    }
    match usage_cache().get(&entry_key) {
        Some(counters) => ChannelAffinityUsageCacheStats {
            rule_name: rule_name.to_owned(),
            using_group: using_group.to_owned(),
            key_fp: key_fp.to_owned(),
            cached_token_rate_mode: counters.cached_token_rate_mode,
            hit: counters.hit,
            total: counters.total,
            window_seconds: counters.window_seconds,
            prompt_tokens: counters.prompt_tokens,
            completion_tokens: counters.completion_tokens,
            total_tokens: counters.total_tokens,
            cached_tokens: counters.cached_tokens,
            prompt_cache_hit_tokens: counters.prompt_cache_hit_tokens,
            last_seen_at: counters.last_seen_at,
        },
        None => echo,
    }
}

/// 测试辅助：替换全局缓存（重新以当前设置容量重建）。
pub fn reset_caches_for_test() {
    // OnceLock 全局不可替换；测试通过独立 TtlLruCache 实例覆盖原语，
    // 全局面只依赖设置读取，此处清空设置覆盖即可。
    *SETTING.write().expect("channel affinity setting") = None;
}

fn chrono_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs() as i64
}
