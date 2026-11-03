use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Channel-level system-prompt settings. Prompt contents are intentionally not
/// formatted or logged by this crate.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct ChannelPromptSettings {
    #[serde(default)]
    pub system_prompt_models: BTreeMap<String, String>,
    #[serde(default)]
    pub system_prompt_preset: Option<String>,
    #[serde(default)]
    pub channel_prompt: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ChannelPromptError {
    UnknownPreset,
}

impl ChannelPromptSettings {
    /// Resolve a prompt using model, then the fixed built-in preset, then the
    /// channel fallback. No filesystem or user-provided path is consulted.
    pub fn resolve(&self, model: &str) -> Result<Option<&str>, ChannelPromptError> {
        if let Some(prompt) = self.system_prompt_models.get(model) {
            return Ok(Some(prompt.as_str()));
        }

        if let Some(preset) = self.system_prompt_preset.as_deref() {
            return builtin_preset(preset)
                .map(Some)
                .ok_or(ChannelPromptError::UnknownPreset);
        }

        Ok(self.channel_prompt.as_deref())
    }

    /// Alias suitable for callers that describe resolution as lookup.
    pub fn prompt_for(&self, model: &str) -> Result<Option<&str>, ChannelPromptError> {
        self.resolve(model)
    }
}

// This is deliberately a closed, compile-time whitelist. Preset names never
// become paths, so configuration cannot cause arbitrary file reads.
fn builtin_preset(name: &str) -> Option<&'static str> {
    match name {
        "default" => Some("You are a helpful, accurate assistant."),
        "coding" => Some("You are a careful software engineering assistant. Provide correct, maintainable code."),
        "reasoning" => Some("You are a rigorous reasoning assistant. State assumptions and check conclusions."),
        _ => None,
    }
}
