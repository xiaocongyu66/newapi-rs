use newapi_catalog::response_cache::*;

#[test]
fn defaults_match_go_constants_and_zero_body_limit_is_unbounded() {
    let config = ResponseCacheConfig::default();
    assert!(!config.enabled);
    assert_eq!(config.ttl.as_secs(), 300);
    assert_eq!(config.max_entries, 1000);
    assert_eq!(config.max_body_size, 256 * 1024);
    assert!(ResponseCacheConfig::new(false, 300, 1000, 0).is_ok());
}

#[test]
fn validation_uses_fixed_error_and_rejects_zero_ttl_or_entries() {
    for result in [
        ResponseCacheConfig::new(false, 0, 1000, 1),
        ResponseCacheConfig::new(false, 1, 0, 1),
    ] {
        let error = result.unwrap_err();
        assert_eq!(error.to_string(), "invalid response cache configuration");
        assert!(!format!("{error:?}").contains("secret"));
    }
}

fn request<'a>(
    user_scope: CacheScope<'a>,
    channel_scope: CacheScope<'a>,
) -> ResponseCacheRequest<'a> {
    ResponseCacheRequest {
        method: "POST",
        streaming: false,
        system_prompt: Some("system"),
        preset: Some("preset"),
        user_scope,
        channel_scope,
    }
}

#[test]
fn eligibility_requires_non_streaming_complete_material_and_authenticated_scopes() {
    assert!(
        request(
            CacheScope::Unauthenticated,
            CacheScope::Authenticated("channel-id")
        )
        .cache_key()
        .is_err()
    );
    assert!(
        request(
            CacheScope::Authenticated("user-id"),
            CacheScope::Unauthenticated
        )
        .cache_key()
        .is_err()
    );
    assert!(
        request(
            CacheScope::Authenticated("user-id"),
            CacheScope::Authenticated("channel-id")
        )
        .cache_key()
        .is_ok()
    );
    assert!(
        ResponseCacheRequest {
            streaming: true,
            ..request(
                CacheScope::Authenticated("u"),
                CacheScope::Authenticated("c")
            )
        }
        .cache_key()
        .is_err()
    );
    assert!(
        ResponseCacheRequest {
            system_prompt: None,
            preset: None,
            ..request(
                CacheScope::Authenticated("u"),
                CacheScope::Authenticated("c")
            )
        }
        .cache_key()
        .is_err()
    );
}

#[test]
fn key_changes_with_method_material_and_scopes_without_exposing_values() {
    let base = request(
        CacheScope::Authenticated("user-secret"),
        CacheScope::Authenticated("channel-secret"),
    )
    .cache_key()
    .unwrap();
    let changed_method = ResponseCacheRequest {
        method: "GET",
        ..request(
            CacheScope::Authenticated("user-secret"),
            CacheScope::Authenticated("channel-secret"),
        )
    }
    .cache_key()
    .unwrap();
    let changed_prompt = ResponseCacheRequest {
        system_prompt: Some("other"),
        ..request(
            CacheScope::Authenticated("user-secret"),
            CacheScope::Authenticated("channel-secret"),
        )
    }
    .cache_key()
    .unwrap();
    let changed_user = request(
        CacheScope::Authenticated("other-user"),
        CacheScope::Authenticated("channel-secret"),
    )
    .cache_key()
    .unwrap();
    let changed_channel = request(
        CacheScope::Authenticated("user-secret"),
        CacheScope::Authenticated("other-channel"),
    )
    .cache_key()
    .unwrap();
    assert_ne!(base, changed_method);
    assert_ne!(base, changed_prompt);
    assert_ne!(base, changed_user);
    assert_ne!(base, changed_channel);
    assert!(!format!("{base:?}").contains("user-secret"));
    assert!(!format!("{base:?}").contains("channel-secret"));
}
