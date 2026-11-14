//! Conversion-context contract between format converters and the hosting
//! application. Ported from the upstream Go `relaykit/relayconvert/convmeta`
//! package (meta.go:1-216, options.go:1-80).
//!
//! [`ConvMeta`] is the only view of the relay session that format converters
//! may use; the host's `RelayInfo` implements it. [`MetaValues`] is a
//! plain-struct implementation for tests and non-`RelayInfo` hosts.

use serde::{Deserialize, Serialize};

pub mod format;

pub use format::{
    RequestKind, append_request_conversion_from_request, guess_relay_format_from_request,
    guess_relay_format_from_request_kind,
};

/// Relay format strings (Go `types.RelayFormat`). Re-uses the constants from
/// `relay_info::relay_format` to keep one source of truth.
pub use crate::relay_info::relay_format as formats;

/// Go `convmeta.LastMessageType*` constants (meta.go:65-70).
pub mod last_message_type {
    pub const NONE: &str = "none";
    pub const TEXT: &str = "text";
    pub const TOOLS: &str = "tools";
    pub const THINKING: &str = "thinking";
}

/// Mutable state for OpenAI chat → Claude Messages stream conversion.
/// Go `convmeta.ClaudeConvertInfo` (meta.go:54-70).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ClaudeConvertInfo {
    pub last_messages_type: String,
    pub index: i64,
    pub finish_reason: String,
    pub done: bool,
    pub tool_call_base_index: i64,
    pub tool_call_max_index_offset: i64,
}

impl ClaudeConvertInfo {
    /// Go initializes `LastMessagesType: LastMessageTypeNone` on creation.
    pub fn new() -> Self {
        Self {
            last_messages_type: last_message_type::NONE.to_owned(),
            ..Default::default()
        }
    }
}

/// The only view of the relay session that format converters may use.
/// Go `convmeta.Meta` (meta.go:18-50).
pub trait ConvMeta {
    fn get_origin_model_name(&self) -> &str;
    fn get_upstream_model_name(&self) -> &str;
    /// Whether upstream channel information is attached; converters use it to
    /// decide if `get_upstream_model_name` is meaningful.
    fn has_channel_meta(&self) -> bool;
    fn get_channel_id(&self) -> i64;
    fn get_channel_type(&self) -> i32;
    fn get_is_stream(&self) -> bool;
    fn get_reasoning_effort(&self) -> &str;
    /// Records the effort level a converter derived from a model-name suffix
    /// so downstream billing/logging can see it.
    fn set_reasoning_effort(&mut self, effort: &str);
    fn get_estimate_prompt_tokens(&self) -> i64;
    /// Lazily creates and returns the mutable OpenAI→Claude stream conversion
    /// state; the same instance must be returned for the lifetime of one
    /// streaming session.
    fn ensure_claude_convert_info(&mut self) -> &mut ClaudeConvertInfo;
    /// Shared downstream-chunk counter (the host may also increment it).
    fn get_send_response_count(&self) -> i64;
    fn incr_send_response_count(&mut self);
    /// Records a hop in the request format chain.
    fn append_request_conversion(&mut self, format: &str);
    /// Request-scoped conversion options snapshot. Never `None`.
    fn conv_options(&self) -> &ConvOptions;
    fn conv_options_mut(&mut self) -> &mut ConvOptions;
}

/// Nil-safe accessors for optional Meta values (converters are often called
/// with a default Meta in tests and compat shims). Go convmeta meta.go:195-215.
pub fn upstream_model_name(meta: &dyn ConvMeta) -> &str {
    if !meta.has_channel_meta() {
        return "";
    }
    meta.get_upstream_model_name()
}

/// Go `ChannelTypeOf` (meta.go:202-207).
pub fn channel_type_of(meta: &dyn ConvMeta) -> i32 {
    if !meta.has_channel_meta() {
        return 0;
    }
    meta.get_channel_type()
}

/// Per-request snapshot of host configuration that converters consult.
/// Go `convmeta.Options` (options.go:7-57). Function hooks become boolean
/// gates + caller-provided tables in the Rust port (see module docs on
/// [`ClaudeOptions::default_max_tokens_for`] and
/// [`GeminiOptions::safety_setting_for`]).
#[derive(Clone, Debug, Default)]
pub struct ConvOptions {
    pub claude: ClaudeOptions,
    pub gemini: GeminiOptions,
    /// Marks the upstream as OpenRouter's OpenAI-compatible surface, which
    /// accepts extra fields (reasoning config, cache_control on system parts)
    /// that converters emit only for that dialect.
    pub open_router_dialect: bool,
}

#[derive(Clone, Debug, Default)]
pub struct ClaudeOptions {
    /// Turns `-thinking`-suffixed OpenAI model names into Claude
    /// extended-thinking requests.
    pub thinking_adapter_enabled: bool,
    /// Sizes thinking budget_tokens as a fraction of max_tokens when the
    /// adapter fires.
    pub thinking_adapter_budget_tokens_percentage: f64,
}

impl ClaudeOptions {
    /// Go `(*ClaudeOptions).DefaultMaxTokensFor` (options.go:59-64). The Go
    /// hook (`DefaultMaxTokens func(modelName) int`) becomes a caller-supplied
    /// fallback: `None` here means "no hook / no value supplied".
    pub fn default_max_tokens_for(&self, default_max_tokens: Option<i64>) -> Option<i64> {
        default_max_tokens
    }
}

#[derive(Clone, Debug, Default)]
pub struct GeminiOptions {
    /// Maps -thinking/-nothinking/effort suffixes to Gemini thinkingConfig.
    pub thinking_adapter_enabled: bool,
    /// Sizes thinkingBudget as a fraction of maxOutputTokens when the adapter
    /// fires.
    pub thinking_adapter_budget_tokens_percentage: f64,
    /// Attaches thoughtSignature bypass values to function-call parts.
    pub function_call_thought_signature_enabled: bool,
}

impl GeminiOptions {
    /// Go `(*GeminiOptions).SupportsImagineModel`: the Go function hook is
    /// resolved by the caller (host model tables); `supports_imagine` carries
    /// the resolved answer into converter logic.
    pub fn supports_imagine_model(supports_imagine: bool) -> bool {
        supports_imagine
    }

    /// Go `(*GeminiOptions).SafetySettingFor`: `None` means no
    /// safetySettings are attached; `Some("")` means the hook returned empty
    /// (also treated as no settings by converters).
    pub fn safety_setting_for(safety_setting: Option<&str>) -> &str {
        safety_setting.unwrap_or("")
    }
}

impl ConvOptions {
    /// Go `(*Options).ShouldPreserveThinkingSuffix` (options.go:77-79).
    pub fn should_preserve_thinking_suffix(&self, _model_name: &str) -> bool {
        // The Go hook (`PreserveThinkingSuffix func(string) bool`) is resolved
        // by the host before entering converter logic; the default is "never
        // preserve".
        false
    }
}

/// Plain-struct Meta implementation for tests and non-`RelayInfo` hosts.
/// Go `convmeta.Values` (meta.go:74-190).
#[derive(Clone, Debug, Default)]
pub struct MetaValues {
    pub origin_model_name: String,
    pub upstream_model_name: String,
    pub channel_meta_attached: bool,
    pub channel_id: i64,
    pub channel_type: i32,
    pub is_stream: bool,
    pub reasoning_effort: String,
    pub estimate_prompt_tokens: i64,
    pub claude_convert_info: Option<ClaudeConvertInfo>,
    pub send_response_count: i64,
    pub conversion_chain: Vec<String>,
    pub options: Option<ConvOptions>,
}

impl ConvMeta for MetaValues {
    fn get_origin_model_name(&self) -> &str {
        &self.origin_model_name
    }

    fn get_upstream_model_name(&self) -> &str {
        &self.upstream_model_name
    }

    fn has_channel_meta(&self) -> bool {
        self.channel_meta_attached
    }

    fn get_channel_id(&self) -> i64 {
        self.channel_id
    }

    fn get_channel_type(&self) -> i32 {
        self.channel_type
    }

    fn get_is_stream(&self) -> bool {
        self.is_stream
    }

    fn get_reasoning_effort(&self) -> &str {
        &self.reasoning_effort
    }

    fn set_reasoning_effort(&mut self, effort: &str) {
        self.reasoning_effort = effort.to_owned();
    }

    fn get_estimate_prompt_tokens(&self) -> i64 {
        self.estimate_prompt_tokens
    }

    fn ensure_claude_convert_info(&mut self) -> &mut ClaudeConvertInfo {
        self.claude_convert_info
            .get_or_insert_with(ClaudeConvertInfo::new)
    }

    fn get_send_response_count(&self) -> i64 {
        self.send_response_count
    }

    fn incr_send_response_count(&mut self) {
        self.send_response_count += 1;
    }

    fn append_request_conversion(&mut self, format: &str) {
        if format.is_empty() {
            return;
        }
        if let Some(last) = self.conversion_chain.last()
            && last == format
        {
            return;
        }
        self.conversion_chain.push(format.to_owned());
    }

    fn conv_options(&self) -> &ConvOptions {
        // Go ConvOptions() on a nil Values returns a fresh empty snapshot;
        // the shared EMPTY instance is never mutated through this shared ref.
        static EMPTY: std::sync::OnceLock<ConvOptions> = std::sync::OnceLock::new();
        self.options
            .as_ref()
            .unwrap_or_else(|| EMPTY.get_or_init(ConvOptions::default))
    }

    fn conv_options_mut(&mut self) -> &mut ConvOptions {
        self.options.get_or_insert_with(ConvOptions::default)
    }
}

/// JSON round-trip support (Go tests marshal Options in fixture comparisons);
/// function hooks do not survive serialization by design.
impl Serialize for ConvOptions {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ConvOptions", 6)?;
        state.serialize_field(
            "claude.thinking_adapter_enabled",
            &self.claude.thinking_adapter_enabled,
        )?;
        state.serialize_field(
            "claude.thinking_adapter_budget_tokens_percentage",
            &self.claude.thinking_adapter_budget_tokens_percentage,
        )?;
        state.serialize_field(
            "gemini.thinking_adapter_enabled",
            &self.gemini.thinking_adapter_enabled,
        )?;
        state.serialize_field(
            "gemini.thinking_adapter_budget_tokens_percentage",
            &self.gemini.thinking_adapter_budget_tokens_percentage,
        )?;
        state.serialize_field(
            "gemini.function_call_thought_signature_enabled",
            &self.gemini.function_call_thought_signature_enabled,
        )?;
        state.serialize_field("open_router_dialect", &self.open_router_dialect)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for ConvOptions {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            #[serde(default)]
            claude_thinking_adapter_enabled: bool,
            #[serde(default)]
            claude_thinking_adapter_budget_tokens_percentage: f64,
            #[serde(default)]
            gemini_thinking_adapter_enabled: bool,
            #[serde(default)]
            gemini_thinking_adapter_budget_tokens_percentage: f64,
            #[serde(default)]
            gemini_function_call_thought_signature_enabled: bool,
            #[serde(default)]
            open_router_dialect: bool,
        }
        let raw = Raw::deserialize(deserializer)?;
        Ok(ConvOptions {
            claude: ClaudeOptions {
                thinking_adapter_enabled: raw.claude_thinking_adapter_enabled,
                thinking_adapter_budget_tokens_percentage: raw
                    .claude_thinking_adapter_budget_tokens_percentage,
            },
            gemini: GeminiOptions {
                thinking_adapter_enabled: raw.gemini_thinking_adapter_enabled,
                thinking_adapter_budget_tokens_percentage: raw
                    .gemini_thinking_adapter_budget_tokens_percentage,
                function_call_thought_signature_enabled: raw
                    .gemini_function_call_thought_signature_enabled,
            },
            open_router_dialect: raw.open_router_dialect,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Go convmeta/meta_test.go: nil-receiver safety collapses into default
    /// construction in Rust; the contract kept is the dedup-on-append chain.
    #[test]
    fn append_request_conversion_dedups_tail() {
        let mut values = MetaValues::default();
        values.append_request_conversion(formats::OPENAI);
        values.append_request_conversion(formats::OPENAI_RESPONSES);
        values.append_request_conversion(formats::OPENAI_RESPONSES);
        assert_eq!(
            values.conversion_chain,
            vec![
                formats::OPENAI.to_owned(),
                formats::OPENAI_RESPONSES.to_owned()
            ]
        );
        values.append_request_conversion("");
        assert_eq!(values.conversion_chain.len(), 2);
    }

    #[test]
    fn ensure_claude_convert_info_seeds_none() {
        let mut values = MetaValues::default();
        let info = values.ensure_claude_convert_info();
        assert_eq!(info.last_messages_type, last_message_type::NONE);
    }

    #[test]
    fn options_default_disables_every_adaptation() {
        let options = ConvOptions::default();
        assert!(!options.claude.thinking_adapter_enabled);
        assert!(!options.gemini.thinking_adapter_enabled);
        assert!(!options.open_router_dialect);
        assert!(!options.should_preserve_thinking_suffix("gpt-5"));
        assert_eq!(GeminiOptions::safety_setting_for(None), "");
    }
}
