//! Request conversion cluster. Ports of the upstream Go
//! `relaykit/relayconvert` request pipeline:
//! - [`dto`] — chat wire-shape accessors (relaykit/dto/openai_request.go).
//! - [`oai_chat_to_responses`] — the chat→responses request converter
//!   (internal/oai_chat/to_oai_responses_req.go).
//! - [`oai_responses_prepare`] — Gemini-target preprocessing
//!   (internal/oai_responses/to_gemini_chat_req_preprocess.go).
//! - [`registry`] — converter registry and the three dispatch entry points
//!   (request_registry.go).

pub mod dto;
pub mod oai_chat_to_responses;
pub mod oai_responses_prepare;
pub mod registry;
pub mod token_meta;

pub use dto::{
    ChatMessage, MediaContent, ToolCall, content_type, get_system_role_name, is_openai_gpt5_model,
    is_openai_reasoning_o_model, is_qwen_thinking_budget_model,
};
pub use oai_chat_to_responses::{
    ConvertError, apply_qwen_thinking_budget_guard, chat_completions_request_to_responses_request,
};
pub use oai_responses_prepare::prepare_openai_responses_request;
pub use registry::{
    RequestConverterQuality, RequestConverterSpec, RequestResult, RequestStep, convert_request,
    convert_request_by_id, convert_request_via, converter_id, lookup_request_converter,
};
pub use token_meta::{
    CountMeta, MediaInput, chat_request_token_count_meta, responses_request_token_count_meta,
};
