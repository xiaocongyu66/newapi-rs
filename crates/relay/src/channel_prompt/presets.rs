//! Compile-time preset table. Preset names never become filesystem paths, so
//! configuration cannot cause arbitrary file reads.

pub const PRESET_SILLY_TAVERN: &str = "silly_tavern";
pub const PRESET_TAVERN_CARD: &str = "tavern_card";

const SILLY_TAVERN_PROMPT: &str = include_str!("../../presets/silly_tavern.txt");
const TAVERN_CARD_PROMPT: &str = include_str!("../../presets/tavern_card.txt");

/// Empty name or unknown preset resolves to `""`, matching upstream `Get`.
pub fn get_preset(name: &str) -> &'static str {
    match name {
        PRESET_SILLY_TAVERN => SILLY_TAVERN_PROMPT,
        PRESET_TAVERN_CARD => TAVERN_CARD_PROMPT,
        _ => "",
    }
}

pub fn is_valid_preset(name: &str) -> bool {
    matches!(name, PRESET_SILLY_TAVERN | PRESET_TAVERN_CARD)
}
