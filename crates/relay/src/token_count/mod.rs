//! Token counting cluster. Ports of the upstream Go
//! `internal/relay/common/` token-counting files:
//! - [`estimate_tokens`] — heuristic char-class estimator (estimate_tokens.go).
//! - [`tokenize_text`] — tiktoken routing for OpenAI text models
//!   (tokenize_text.go + count_tokens.go's CountTextToken).
//! - [`count_tokens`] — request token estimation incl. image tile/patch
//!   pricing and realtime events (count_tokens.go).
//! - [`count_tool_usage`] — billable tool call counting (count_tool_usage.go).
//! - [`summarize_usage`] — ResponseText2Usage / ValidUsage (summarize_usage.go).
//! - [`quota`] — the quota-math subset the counting paths need (the
//!   authoritative copy lives in newapi-billing).

pub mod count_tokens;
pub mod count_tool_usage;
pub mod estimate_tokens;
pub mod quota;
pub mod summarize_usage;
pub mod tokenize_text;

pub use count_tokens::{
    AudioDurationResolver, CountSwitches, EstimateInputs, FileDataResolver, FileMeta,
    LocalFileResolver, RealtimeEventInput, TokenCountMeta, audio_relay_mode,
    count_audio_token_input, count_audio_token_output, count_token_input, count_token_realtime,
    estimate_request_token, file_type, get_image_token, realtime_event, token_type,
};
pub use count_tool_usage::{
    BillableToolContext, ImageGenerationCallCounter, MAX_IMAGE_N, ResponsesOutputInput,
    build_in_call, build_in_tool, count_billable_tool_call, delete_tool_price_for_test,
    get_tool_price_for_model, increment_billable_tool_call, is_non_billable_responses_status,
    set_tool_price_for_test,
};
pub use estimate_tokens::{
    Multipliers, Provider, estimate_token, estimate_token_by_model, get_multipliers,
};
pub use summarize_usage::{response_text_2_usage, valid_usage};
pub use tokenize_text::{count_text_token, init_token_encoders, is_openai_text_model};
