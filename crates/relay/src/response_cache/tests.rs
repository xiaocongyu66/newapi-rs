use std::sync::Mutex;

use super::{
    Config, Eligibility, Payload, clear, eligible, get, key, put, record_hit, record_miss,
    set_config, stats,
};

// The store is process-global, matching the upstream package state. Serialise
// tests so one case cannot observe another's entries.
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn reset(config: Config) -> std::sync::MutexGuard<'static, ()> {
    let guard = TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    clear();
    super::store::reset_for_test(config);
    guard
}

fn config(enabled: bool, ttl: i64, entries: i64, body: i64) -> Config {
    Config {
        enabled,
        ttl_seconds: ttl,
        max_entries: entries,
        max_body_size: body,
    }
}

#[test]
fn key_is_deterministic_and_discriminates() {
    let a = key(br#"{"model":"gpt-4o"}"#, "gpt-4o");
    let b = key(br#"{"model":"gpt-4o"}"#, "gpt-4o");
    let c = key(br#"{"model":"gpt-4o","messages":[]}"#, "gpt-4o");
    let d = key(br#"{"model":"gpt-4o"}"#, "gpt-4o-mini");
    assert_eq!(a, b);
    assert_ne!(a, c);
    assert_ne!(a, d);
}

#[test]
fn put_get_round_trip_and_copy_isolation() {
    let _guard = reset(config(true, 60, 10, 1024));
    let cache_key = key(b"{}", "m");
    let mut body = br#"{"choices":[{"message":{"content":"hi"}}]}"#.to_vec();
    let usage = br#"{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}"#.to_vec();
    assert!(put(
        &cache_key,
        Payload {
            status: 200,
            content_type: "application/json".to_owned(),
            body: body.clone(),
            usage_json: usage.clone(),
        },
        1024
    ));

    body[0] = b'X';
    let got = get(&cache_key).expect("cached payload");
    assert_eq!(got.status, 200);
    assert_eq!(got.content_type, "application/json");
    assert_eq!(got.body, br#"{"choices":[{"message":{"content":"hi"}}]}"#);

    let mut returned = got;
    returned.body[1] = b'Y';
    returned.usage_json[0] = b'Y';
    let again = get(&cache_key).expect("cached payload");
    assert_eq!(again.body, br#"{"choices":[{"message":{"content":"hi"}}]}"#);
    assert_eq!(again.usage_json, usage);
}

#[test]
fn put_refused_when_disabled_or_oversized() {
    let _guard = reset(config(false, 60, 10, 1024));
    let cache_key = key(b"{}", "m");
    assert!(!put(
        &cache_key,
        Payload {
            status: 200,
            content_type: String::new(),
            body: b"{}".to_vec(),
            usage_json: Vec::new(),
        },
        1024
    ));

    set_config(config(true, 60, 10, 8));
    assert!(!put(
        &cache_key,
        Payload {
            status: 200,
            content_type: String::new(),
            body: br#"{"too":"long"}"#.to_vec(),
            usage_json: Vec::new(),
        },
        8
    ));
    assert!(get(&cache_key).is_none());
}

#[test]
fn expiry_and_clear() {
    let _guard = reset(config(true, 1, 10, 1024));
    let cache_key = key(b"{}", "m");
    assert!(put(
        &cache_key,
        Payload {
            status: 200,
            content_type: String::new(),
            body: b"{}".to_vec(),
            usage_json: Vec::new(),
        },
        1024
    ));
    assert!(get(&cache_key).is_some());

    super::store::expire_for_test(&cache_key);
    assert!(get(&cache_key).is_none());
    assert_eq!(stats().entries, 0);

    assert!(put(
        &cache_key,
        Payload {
            status: 200,
            content_type: String::new(),
            body: b"{}".to_vec(),
            usage_json: Vec::new(),
        },
        1024
    ));
    clear();
    assert!(get(&cache_key).is_none());
}

#[test]
fn eviction_respects_max_entries() {
    let _guard = reset(config(true, 60, 3, 1024));
    let keys: Vec<String> = (0..5)
        .map(|i| key(format!(r#"{{"i":{i}}}"#).as_bytes(), "m"))
        .collect();
    for cache_key in &keys {
        assert!(put(
            cache_key,
            Payload {
                status: 200,
                content_type: String::new(),
                body: b"{}".to_vec(),
                usage_json: Vec::new(),
            },
            1024
        ));
    }
    assert_eq!(stats().entries, 3);
    for (index, cache_key) in keys.iter().enumerate() {
        let present = get(cache_key).is_some();
        assert_eq!(present, index >= 2, "key {index} eviction mismatch");
    }
}

#[test]
fn disabling_resets_store_and_never_resurrects() {
    let _guard = reset(config(true, 60, 10, 1024));
    let cache_key = key(b"{}", "m");
    assert!(put(
        &cache_key,
        Payload {
            status: 200,
            content_type: String::new(),
            body: b"{}".to_vec(),
            usage_json: Vec::new(),
        },
        1024
    ));
    set_config(config(false, 60, 10, 1024));
    assert_eq!(stats().entries, 0);
    set_config(config(true, 60, 10, 1024));
    assert!(get(&cache_key).is_none());
}

#[test]
fn get_short_circuits_when_disabled() {
    let _guard = reset(config(true, 60, 10, 1024));
    let cache_key = key(b"{}", "m");
    assert!(put(
        &cache_key,
        Payload {
            status: 200,
            content_type: String::new(),
            body: b"{}".to_vec(),
            usage_json: Vec::new(),
        },
        1024
    ));
    // Mirror a hot toggle that flips enabled without a store reset.
    super::store::reset_for_test(config(false, 60, 10, 1024));
    assert!(get(&cache_key).is_none());
    assert_eq!(stats().entries, 0);
}

#[test]
fn stats_counters() {
    let _guard = reset(config(true, 60, 10, 1024));
    record_hit();
    record_hit();
    record_miss();
    let stats = stats();
    assert_eq!(stats.hits, 2);
    assert_eq!(stats.misses, 1);
    assert_eq!(stats.entries, 0);
}

fn eligible_request() -> Eligibility {
    Eligibility {
        chat_completions_mode: true,
        openai_relay_format: true,
        cache_enabled: true,
        ..Eligibility::default()
    }
}

#[test]
fn eligibility_accepts_only_the_deterministic_openai_path() {
    assert!(eligible(eligible_request()));
}

#[test]
fn eligibility_rejects_each_upstream_exclusion() {
    let cases: [(&str, Eligibility); 10] = [
        (
            "non-chat-completions",
            Eligibility {
                chat_completions_mode: false,
                ..eligible_request()
            },
        ),
        (
            "non-openai-format",
            Eligibility {
                openai_relay_format: false,
                ..eligible_request()
            },
        ),
        (
            "pass-through-body",
            Eligibility {
                pass_through_body_enabled: true,
                ..eligible_request()
            },
        ),
        (
            "pass-through-request",
            Eligibility {
                pass_through_request_enabled: true,
                ..eligible_request()
            },
        ),
        (
            "channel-system-prompt",
            Eligibility {
                channel_system_prompt_present: true,
                ..eligible_request()
            },
        ),
        (
            "param-override",
            Eligibility {
                param_override_present: true,
                ..eligible_request()
            },
        ),
        (
            "channel-other-settings",
            Eligibility {
                channel_other_settings_present: true,
                ..eligible_request()
            },
        ),
        (
            "cache-disabled",
            Eligibility {
                cache_enabled: false,
                ..eligible_request()
            },
        ),
        (
            "streaming",
            Eligibility {
                stream: true,
                ..eligible_request()
            },
        ),
        (
            "non-zero-temperature",
            Eligibility {
                temperature_nonzero: true,
                ..eligible_request()
            },
        ),
    ];
    for (name, input) in cases {
        assert!(!eligible(input), "{name} must be ineligible");
    }
    let tooling = Eligibility {
        tooling_present: true,
        ..eligible_request()
    };
    assert!(!eligible(tooling), "tooling requests must be ineligible");
}

#[test]
fn non_positive_limits_fall_back_to_defaults() {
    let _guard = reset(config(true, 0, 0, -5));
    let current = super::config();
    assert_eq!(current.ttl_seconds, 300);
    assert_eq!(current.max_entries, 1000);
    assert_eq!(current.max_body_size, 256 * 1024);
}
