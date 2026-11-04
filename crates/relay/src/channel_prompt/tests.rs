use std::collections::BTreeMap;

use super::{
    ChannelSettings, PRESET_SILLY_TAVERN, PRESET_TAVERN_CARD, get_preset, is_valid_preset,
};

#[test]
fn model_prompt_precedes_preset_and_channel_prompt() {
    let mut settings = ChannelSettings {
        system_prompt: Some("channel prompt".to_owned()),
        system_prompt_preset: Some(PRESET_SILLY_TAVERN.to_owned()),
        ..ChannelSettings::default()
    };
    settings
        .system_prompt_models
        .insert("model-a".to_owned(), "model prompt".to_owned());

    assert_eq!(settings.resolve_system_prompt("model-a"), "model prompt");
    assert_eq!(
        settings.resolve_system_prompt("model-b"),
        get_preset(PRESET_SILLY_TAVERN)
    );
}

#[test]
fn preset_precedes_channel_prompt_and_unknown_preset_falls_through() {
    let mut settings = ChannelSettings {
        system_prompt: Some("channel prompt".to_owned()),
        system_prompt_preset: Some(PRESET_TAVERN_CARD.to_owned()),
        ..ChannelSettings::default()
    };
    assert_eq!(
        settings.resolve_system_prompt("model"),
        get_preset(PRESET_TAVERN_CARD)
    );

    settings.system_prompt_preset = Some("not-a-preset".to_owned());
    assert_eq!(settings.resolve_system_prompt("model"), "channel prompt");
}

#[test]
fn empty_model_entry_falls_through() {
    let mut settings = ChannelSettings {
        system_prompt: Some("channel prompt".to_owned()),
        ..ChannelSettings::default()
    };
    settings
        .system_prompt_models
        .insert("model".to_owned(), String::new());
    assert_eq!(settings.resolve_system_prompt("model"), "channel prompt");
}

#[test]
fn missing_prompt_resolves_to_empty_string() {
    let settings = ChannelSettings::default();
    assert_eq!(settings.resolve_system_prompt("model"), "");
}

#[test]
fn preset_lookup_is_closed_and_content_is_embedded() {
    assert!(is_valid_preset(PRESET_SILLY_TAVERN));
    assert!(is_valid_preset(PRESET_TAVERN_CARD));
    assert!(!is_valid_preset("../../etc/passwd"));
    assert!(!get_preset(PRESET_SILLY_TAVERN).is_empty());
    assert!(get_preset(PRESET_TAVERN_CARD).len() > 1000);
    assert_eq!(get_preset(""), "");
    assert_eq!(get_preset("unknown"), "");
}

#[test]
fn settings_deserialize_upstream_field_names() {
    let settings: ChannelSettings = serde_json::from_str(
        r#"{"system_prompt":"fallback","system_prompt_models":{"m":"per-model"},"system_prompt_preset":"tavern_card"}"#,
    )
    .expect("upstream JSON shape");
    assert_eq!(settings.resolve_system_prompt("m"), "per-model");
    assert!(settings.system_prompt_models.contains_key("m"));
    assert_eq!(settings.system_prompt_models.len(), 1);
    let _: &BTreeMap<String, String> = &settings.system_prompt_models;
}
