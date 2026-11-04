use super::{
    ENABLED_OPTION, MAX_BODY_SIZE_OPTION, MAX_ENTRIES_OPTION, TTL_SECONDS_OPTION, apply_option,
    validate_option,
};
use crate::response_cache::Config;

#[test]
fn enabled_requires_the_exact_upstream_string() {
    let mut config = Config::default();
    apply_option(&mut config, ENABLED_OPTION, "true");
    assert!(config.enabled);
    apply_option(&mut config, ENABLED_OPTION, "TRUE");
    assert!(!config.enabled, "Go compares the literal string \"true\"");
    apply_option(&mut config, ENABLED_OPTION, "1");
    assert!(!config.enabled);
}

#[test]
fn numeric_options_use_atoi_semantics() {
    let mut config = Config::default();
    apply_option(&mut config, TTL_SECONDS_OPTION, "120");
    apply_option(&mut config, MAX_ENTRIES_OPTION, "50");
    apply_option(&mut config, MAX_BODY_SIZE_OPTION, "1024");
    assert_eq!(config.ttl_seconds, 120);
    assert_eq!(config.max_entries, 50);
    assert_eq!(config.max_body_size, 1024);

    // Go's strconv.Atoi returns 0 on syntax errors; no whitespace trimming.
    apply_option(&mut config, TTL_SECONDS_OPTION, " 120");
    apply_option(&mut config, MAX_ENTRIES_OPTION, "abc");
    apply_option(&mut config, MAX_BODY_SIZE_OPTION, "");
    assert_eq!(config.ttl_seconds, 0);
    assert_eq!(config.max_entries, 0);
    assert_eq!(config.max_body_size, 0);
}

#[test]
fn save_time_validation_accepts_non_negative_integers_only() {
    for key in [TTL_SECONDS_OPTION, MAX_ENTRIES_OPTION, MAX_BODY_SIZE_OPTION] {
        assert!(validate_option(key, "0").is_ok());
        assert!(validate_option(key, "+5").is_ok());
        assert!(validate_option(key, "-1").is_err());
        assert!(validate_option(key, "abc").is_err());
        assert!(validate_option(key, " 5").is_err());
    }
    // The enable flag has no save-time numeric validation.
    assert!(validate_option(ENABLED_OPTION, "anything").is_ok());
}

#[test]
fn unknown_options_are_ignored() {
    let mut config = Config::default();
    apply_option(&mut config, "SomeOtherOption", "1");
    assert_eq!(config, Config::default());
}
