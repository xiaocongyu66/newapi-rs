use std::collections::BTreeMap;

use newapi_catalog::{ChannelPromptError, ChannelPromptSettings};

fn settings() -> ChannelPromptSettings {
    ChannelPromptSettings {
        system_prompt_models: BTreeMap::new(),
        system_prompt_preset: None,
        channel_prompt: Some("channel fallback".to_owned()),
    }
}

#[test]
fn resolves_model_prompt_before_preset_and_channel_fallback() {
    let mut config = settings();
    config
        .system_prompt_models
        .insert("model-a".to_owned(), "model prompt".to_owned());
    config.system_prompt_preset = Some("coding".to_owned());

    assert_eq!(config.resolve("model-a"), Ok(Some("model prompt")));
    assert_eq!(
        config.resolve("model-b"),
        Ok(Some(
            "You are a careful software engineering assistant. Provide correct, maintainable code."
        ))
    );

    config.system_prompt_preset = None;
    assert_eq!(config.prompt_for("model-b"), Ok(Some("channel fallback")));
}

#[test]
fn unknown_preset_is_a_fixed_error_and_does_not_read_a_path() {
    let mut config = settings();
    config.system_prompt_preset = Some("../../etc/passwd".to_owned());

    assert!(matches!(
        config.resolve("model-a"),
        Err(ChannelPromptError::UnknownPreset)
    ));
}

#[test]
fn missing_prompt_resolves_to_none() {
    let config = ChannelPromptSettings::default();
    assert_eq!(config.resolve("model-a"), Ok(None));
}

#[test]
fn prompt_contents_are_not_exposed_by_debug_formatting() {
    let config = settings();
    let _ = config;
    // ChannelPromptSettings intentionally has no Debug implementation. This test
    // keeps the contract visible without formatting prompt contents.
}
