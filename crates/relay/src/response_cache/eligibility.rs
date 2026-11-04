/// Inputs that decide whether a relay request may be served from, or stored
/// into, the response cache. Ported gate-for-gate from the upstream relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Eligibility {
    pub chat_completions_mode: bool,
    pub openai_relay_format: bool,
    pub pass_through_body_enabled: bool,
    pub pass_through_request_enabled: bool,
    /// A channel system prompt rewrites the messages after the key is built.
    pub channel_system_prompt_present: bool,
    /// Param overrides rewrite the wire body after the key is built.
    pub param_override_present: bool,
    /// Non-empty channel other-settings change disabled-field removal.
    pub channel_other_settings_present: bool,
    pub cache_enabled: bool,
    pub stream: bool,
    /// Only `temperature == 0` is deterministic; an absent value is allowed.
    pub temperature_nonzero: bool,
    /// Tools, functions, tool choice, function call, or web search.
    pub tooling_present: bool,
}

impl Default for Eligibility {
    fn default() -> Self {
        Self {
            chat_completions_mode: false,
            openai_relay_format: false,
            pass_through_body_enabled: false,
            pass_through_request_enabled: false,
            channel_system_prompt_present: false,
            param_override_present: false,
            channel_other_settings_present: false,
            cache_enabled: false,
            stream: false,
            temperature_nonzero: false,
            tooling_present: false,
        }
    }
}

/// Conservative eligibility: every exclusion below must be false.
pub fn eligible(input: Eligibility) -> bool {
    input.chat_completions_mode
        && input.openai_relay_format
        && !input.pass_through_body_enabled
        && !input.pass_through_request_enabled
        && !input.channel_system_prompt_present
        && !input.param_override_present
        && !input.channel_other_settings_present
        && input.cache_enabled
        && !input.stream
        && !input.temperature_nonzero
        && !input.tooling_present
}
