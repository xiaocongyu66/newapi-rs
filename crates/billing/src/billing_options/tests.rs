use std::collections::BTreeMap;

use super::{drop_empty_map_entries, merge_maps, parse_string_map_option};

fn map(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
    entries
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

#[test]
fn target_values_win_over_legacy_values() {
    let legacy = map(&[("gpt-4o", "legacy"), ("only-legacy", "kept")]);
    let target = map(&[("gpt-4o", "target")]);
    let merged = merge_maps(&legacy, &target);
    assert_eq!(merged.get("gpt-4o").map(String::as_str), Some("target"));
    assert_eq!(merged.get("only-legacy").map(String::as_str), Some("kept"));
}

#[test]
fn empty_legacy_values_are_dropped() {
    let mut legacy = map(&[("empty", ""), ("kept", "value")]);
    drop_empty_map_entries(&mut legacy);
    assert!(!legacy.contains_key("empty"));
    assert_eq!(legacy.get("kept").map(String::as_str), Some("value"));
}

#[test]
fn malformed_option_values_are_rejected_without_values_in_error() {
    let error = parse_string_map_option("not json").expect_err("malformed map");
    assert!(!error.to_string().contains("not json"));
    assert!(parse_string_map_option("").is_err());
    // Go's json.Unmarshal accepts null as a nil map, i.e. "configured empty".
    assert_eq!(
        parse_string_map_option("null").expect("null map"),
        BTreeMap::new()
    );
    assert_eq!(
        parse_string_map_option(" null ").expect("null map"),
        BTreeMap::new()
    );
}

#[test]
fn parsing_preserves_map_entries() {
    let parsed = parse_string_map_option(r#"{"a":"1","b":""}"#).expect("valid map");
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed.get("a").map(String::as_str), Some("1"));
    assert_eq!(parsed.get("b").map(String::as_str), Some(""));
}

#[test]
fn merge_length_matches_target_when_legacy_adds_nothing() {
    let legacy = map(&[("model", "legacy")]);
    let target = map(&[("model", "target")]);
    let merged = merge_maps(&legacy, &target);
    assert_eq!(merged.len(), target.len());
    assert_eq!(merged.get("model").map(String::as_str), Some("target"));
}
