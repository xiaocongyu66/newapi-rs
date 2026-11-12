//! 亲和缓存原语契约（Go `internal/catalog/track_affinity.go` 写侧 +
//! `cachex` 的内存面语义）。纯进程内测试，不依赖数据库。

use std::sync::Mutex;
use std::time::Duration;

use newapi_catalog::affinity::{
    self, ChannelAffinityRule, ChannelAffinitySetting, ChannelAffinityStatsContext, TtlLruCache,
    UsageObservation,
};

/// 依赖全局缓存的测试在同一进程内并发运行（cargo 的测试线程模型），
/// 必须串行化才能钉住全局状态断言。
static GLOBAL_CACHE_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn full_key_is_idempotent_like_go_namespace() {
    let cache: TtlLruCache<i64> = TtlLruCache::new("ns:v1", 10);
    assert_eq!(cache.full_key("k"), "ns:v1:k");
    assert_eq!(cache.full_key("ns:v1:k"), "ns:v1:k");
    assert_eq!(cache.full_key(":k"), "ns:v1:k");
    assert_eq!(cache.full_key(""), "");
}

#[test]
fn set_get_round_trip_and_ttl_expiry() {
    let cache: TtlLruCache<i64> = TtlLruCache::new("ns:v1", 10);
    cache.set_with_ttl("a", 1, Duration::from_millis(50));
    assert_eq!(cache.get("a"), Some(1));
    // Go SetWithTTL(key) 与 Get(suffix) 命中同一全键（FullKey 幂等）。
    assert_eq!(cache.get("ns:v1:a"), Some(1));
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(cache.get("a"), None, "TTL 过期视为未命中");
}

#[test]
fn lru_eviction_respects_capacity() {
    let cache: TtlLruCache<i64> = TtlLruCache::new("ns:v1", 2);
    cache.set_with_ttl("a", 1, Duration::from_secs(60));
    cache.set_with_ttl("b", 2, Duration::from_secs(60));
    assert_eq!(cache.get("a"), Some(1), "刷新 a 的顺位");
    cache.set_with_ttl("c", 3, Duration::from_secs(60));
    assert_eq!(cache.get("b"), None, "b 是最久未用，先被驱逐");
    assert_eq!(cache.get("a"), Some(1));
    assert_eq!(cache.get("c"), Some(3));
}

#[test]
fn delete_many_and_by_prefix() {
    let cache: TtlLruCache<i64> = TtlLruCache::new("ns:v1", 10);
    cache.set_with_ttl("rule:dev:v", 1, Duration::from_secs(60));
    cache.set_with_ttl("rule:prod:v", 2, Duration::from_secs(60));
    cache.set_with_ttl("other:x", 3, Duration::from_secs(60));
    assert_eq!(
        cache.delete_by_prefix("rule"),
        2,
        "Go DeleteByPrefix 命中完整键前缀"
    );
    assert_eq!(cache.get("rule:dev:v"), None);
    assert_eq!(cache.get("other:x"), Some(3));
    assert_eq!(
        cache.delete_many(&["other:x".to_owned(), "absent".to_owned()]),
        [true, false]
    );
}

#[test]
fn fingerprint_is_sha1_prefix_8() {
    // Go sha1("hello") = aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d。
    assert_eq!(affinity::affinity_fingerprint("hello"), "aaf4c61d");
    assert_eq!(affinity::affinity_fingerprint(""), "");
}

#[test]
fn key_hint_truncates_like_go() {
    assert_eq!(affinity::build_channel_affinity_key_hint("short"), "short");
    let long = "abcdefghijklmnop";
    assert_eq!(
        affinity::build_channel_affinity_key_hint(long),
        "abcd...mnop"
    );
    // Go 按 byte 切：多字节头尾截断可能出现半字符。
    assert_eq!(
        affinity::build_channel_affinity_key_hint("0123456789abcde"),
        "0123...bcde"
    );
}

#[test]
fn key_suffix_order_follows_the_rule_flags() {
    let rule = ChannelAffinityRule {
        name: "r".to_owned(),
        include_rule_name: true,
        include_model_name: false,
        include_using_group: true,
    };
    assert_eq!(
        affinity::build_channel_affinity_cache_key_suffix(&rule, "model", "grp", "val"),
        "r:grp:val"
    );
    let plain = ChannelAffinityRule::default();
    assert_eq!(
        affinity::build_channel_affinity_cache_key_suffix(&plain, "model", "grp", "val"),
        "val"
    );
}

#[tokio::test]
async fn record_channel_affinity_uses_setting_ttl_fallback() {
    let _guard = GLOBAL_CACHE_LOCK.lock().expect("global cache lock");
    affinity::reset_caches_for_test();
    affinity::set_channel_affinity_setting(ChannelAffinitySetting {
        enabled: true,
        max_entries: 10,
        default_ttl_seconds: 2,
        rules: vec![],
    });
    affinity::record_channel_affinity("rule:dev:v", 0, 7);
    assert_eq!(
        affinity::get_preferred_channel_by_affinity("rule:dev:v"),
        Some(7)
    );
    // channel_id <= 0 与空键被吞（Go RecordChannelAffinity 的 guard）。
    affinity::record_channel_affinity("rule:x", 10, 0);
    assert_eq!(affinity::get_preferred_channel_by_affinity("rule:x"), None);
    affinity::reset_caches_for_test();
}

#[tokio::test]
async fn clear_all_and_by_rule_name() {
    let _guard = GLOBAL_CACHE_LOCK.lock().expect("global cache lock");
    affinity::reset_caches_for_test();
    affinity::set_channel_affinity_setting(ChannelAffinitySetting {
        enabled: true,
        max_entries: 10,
        default_ttl_seconds: 60,
        rules: vec![
            ChannelAffinityRule {
                name: "codex cli trace".to_owned(),
                include_rule_name: true,
                ..ChannelAffinityRule::default()
            },
            ChannelAffinityRule {
                name: "no-include".to_owned(),
                include_rule_name: false,
                ..ChannelAffinityRule::default()
            },
        ],
    });
    affinity::record_channel_affinity("codex cli trace:grp:v", 60, 1);
    affinity::record_channel_affinity("no-include:v", 60, 2);
    affinity::record_channel_affinity("unrelated:v", 60, 3);
    assert_eq!(
        affinity::clear_channel_affinity_cache_by_rule_name("no-include").unwrap_err(),
        "该规则未启用 include_rule_name，无法按规则清空缓存"
    );
    assert_eq!(
        affinity::clear_channel_affinity_cache_by_rule_name("missing").unwrap_err(),
        "未知规则名称"
    );
    assert_eq!(
        affinity::clear_channel_affinity_cache_by_rule_name("  ").unwrap_err(),
        "rule_name 不能为空"
    );
    assert_eq!(
        affinity::clear_channel_affinity_cache_by_rule_name("codex cli trace").unwrap(),
        1
    );
    assert_eq!(
        affinity::get_preferred_channel_by_affinity("codex cli trace:grp:v"),
        None
    );
    assert_eq!(affinity::clear_channel_affinity_cache_all(), 2);
    assert_eq!(
        affinity::get_preferred_channel_by_affinity("no-include:v"),
        None
    );
    affinity::reset_caches_for_test();
}

#[tokio::test]
async fn cache_stats_classifies_rule_names_and_unknown() {
    let _guard = GLOBAL_CACHE_LOCK.lock().expect("global cache lock");
    affinity::reset_caches_for_test();
    affinity::set_channel_affinity_setting(ChannelAffinitySetting {
        enabled: true,
        max_entries: 10,
        default_ttl_seconds: 60,
        rules: vec![ChannelAffinityRule {
            name: "codex cli trace".to_owned(),
            include_rule_name: true,
            include_using_group: true,
            ..ChannelAffinityRule::default()
        }],
    });
    affinity::record_channel_affinity("codex cli trace:grp:v1", 60, 1);
    affinity::record_channel_affinity("codex cli trace:grp:v2", 60, 2);
    affinity::record_channel_affinity("nosuchrule:v", 60, 3);
    affinity::record_channel_affinity("codex cli trace:v4", 60, 4); // 缺 group → unknown
    let stats = affinity::get_channel_affinity_cache_stats();
    assert!(stats.enabled);
    assert_eq!(stats.total, 4);
    assert_eq!(stats.unknown, 2);
    assert_eq!(stats.by_rule_name.get("codex cli trace"), Some(&2));
    assert_eq!(stats.cache_capacity, 10);
    assert_eq!(stats.cache_algo, "LRU");
    affinity::reset_caches_for_test();
}

#[tokio::test]
async fn usage_counters_observe_and_mixed_mode() {
    let _guard = GLOBAL_CACHE_LOCK.lock().expect("global cache lock");
    affinity::reset_caches_for_test();
    let ctx = ChannelAffinityStatsContext {
        rule_name: "codex cli trace".to_owned(),
        using_group: "grp".to_owned(),
        key_fp: "aaf4c61d".to_owned(),
        ttl_seconds: 60,
    };
    let observation = UsageObservation {
        prompt_tokens: 100,
        completion_tokens: 10,
        total_tokens: 110,
        cached_tokens: 50,
        prompt_cache_hit_tokens: 0,
    };
    affinity::observe_channel_affinity_usage_cache(&ctx, &observation, "cached_over_prompt");
    affinity::observe_channel_affinity_usage_cache(
        &ctx,
        &observation,
        "cached_over_prompt_plus_cached",
    );
    let stats =
        affinity::get_channel_affinity_usage_cache_stats("codex cli trace", "grp", "aaf4c61d");
    assert_eq!(stats.rule_name, "codex cli trace");
    assert_eq!(stats.key_fp, "aaf4c61d");
    assert_eq!(stats.cached_token_rate_mode, "mixed");
    assert_eq!(stats.total, 2);
    assert_eq!(stats.hit, 2);
    assert_eq!(stats.window_seconds, 60);
    assert_eq!(stats.prompt_tokens, 200);
    assert_eq!(stats.completion_tokens, 20);
    assert_eq!(stats.total_tokens, 220);
    assert_eq!(stats.cached_tokens, 100);
    assert!(stats.last_seen_at > 0);
    affinity::reset_caches_for_test();
}

#[tokio::test]
async fn usage_counters_miss_echoes_params_with_zeroes() {
    let _guard = GLOBAL_CACHE_LOCK.lock().expect("global cache lock");
    affinity::reset_caches_for_test();
    let stats = affinity::get_channel_affinity_usage_cache_stats("r", "g", "fp");
    assert_eq!(stats.rule_name, "r");
    assert_eq!(stats.using_group, "g");
    assert_eq!(stats.key_fp, "fp");
    assert_eq!(stats.total, 0);
    assert_eq!(stats.window_seconds, 0);
    // rule_name 或 key_fp 为空：Go entryKey 为空，读恒回显零值。
    let stats = affinity::get_channel_affinity_usage_cache_stats("", "g", "fp");
    assert_eq!(stats.total, 0);
    affinity::reset_caches_for_test();
}

#[tokio::test]
async fn usage_observation_requires_positive_ttl_window() {
    let _guard = GLOBAL_CACHE_LOCK.lock().expect("global cache lock");
    affinity::reset_caches_for_test();
    let ctx = ChannelAffinityStatsContext {
        rule_name: "r".to_owned(),
        using_group: String::new(),
        key_fp: "fp".to_owned(),
        ttl_seconds: 0,
    };
    affinity::observe_channel_affinity_usage_cache(
        &ctx,
        &UsageObservation::default(),
        "cached_over_prompt",
    );
    let stats = affinity::get_channel_affinity_usage_cache_stats("r", "", "fp");
    assert_eq!(stats.total, 0, "Go windowSeconds <= 0 直接吞掉观察");
    affinity::reset_caches_for_test();
}

#[test]
fn normalize_mode_rejects_unknown() {
    assert!(affinity::normalize_cached_token_rate_mode("cached_over_prompt").is_some());
    assert!(affinity::normalize_cached_token_rate_mode("mixed").is_some());
    assert!(affinity::normalize_cached_token_rate_mode("nonsense").is_none());
}
