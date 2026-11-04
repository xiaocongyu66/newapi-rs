//! Channel-level system prompt resolution. Priority matches the upstream
//! behavior: per-model prompt, then built-in preset, then channel prompt.
//! Unknown presets fall through; they never read a caller-supplied path.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

mod presets;

pub use presets::{PRESET_SILLY_TAVERN, PRESET_TAVERN_CARD, get_preset, is_valid_preset};

#[cfg(test)]
mod tests;

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct ChannelSettings {
    #[serde(default)]
    pub system_prompt: Option<String>,
    #[serde(default)]
    pub system_prompt_models: BTreeMap<String, String>,
    #[serde(default)]
    pub system_prompt_preset: Option<String>,
}

impl ChannelSettings {
    /// Effective prompt for `model_name`. An empty per-model entry and an
    /// unknown/empty preset both fall through, matching the upstream `!= ""`
    /// checks.
    pub fn resolve_system_prompt(&self, model_name: &str) -> &str {
        if let Some(prompt) = self.system_prompt_models.get(model_name)
            && !prompt.is_empty()
        {
            return prompt;
        }
        if let Some(name) = self.system_prompt_preset.as_deref()
            && !name.is_empty()
        {
            let prompt = presets::get_preset(name);
            if !prompt.is_empty() {
                return prompt;
            }
        }
        self.system_prompt.as_deref().unwrap_or("")
    }
}
