//! Relay-format guessing over wire-format request JSON. Ported from the
//! upstream Go `relaykit/relayconvert/convmeta/format.go` (type switch) and
//! `internal/relay/common/convert_request.go` (23-line delegating entry).
//!
//! The Go oracle dispatches on the concrete DTO type (*dto.GeneralOpenAIRequest
//! etc.); the Rust port keeps the same shape contract over `serde_json::Value`
//! plus an optional request-kind marker, because the host request pipeline
//! parses wire JSON into DTO-shaped values (field names drive the guess).

use serde_json::Value;

/// The request kinds the Go type switch recognizes. `GuessRelayFormatFromRequest`
/// is a total function over these.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestKind {
    GeneralOpenAI,
    OpenAIResponses,
    Claude,
    GeminiChat,
    Embedding,
    Rerank,
    OpenAIImage,
    Audio,
}

impl RequestKind {
    /// Go convmeta/format.go:10-31 — the exact format string per DTO type.
    pub fn relay_format(self) -> &'static str {
        match self {
            RequestKind::GeneralOpenAI => crate::relay_info::relay_format::OPENAI,
            RequestKind::OpenAIResponses => crate::relay_info::relay_format::OPENAI_RESPONSES,
            RequestKind::Claude => crate::relay_info::relay_format::CLAUDE,
            RequestKind::GeminiChat => crate::relay_info::relay_format::GEMINI,
            RequestKind::Embedding => crate::relay_info::relay_format::EMBEDDING,
            RequestKind::Rerank => crate::relay_info::relay_format::RERANK,
            RequestKind::OpenAIImage => crate::relay_info::relay_format::OPENAI_IMAGE,
            RequestKind::Audio => crate::relay_info::relay_format::OPENAI_AUDIO,
        }
    }
}

/// Go `convmeta.GuessRelayFormatFromRequest`. `None` mirrors the Go
/// `("", false)` for unrecognized request types. The `request` value is kept
/// in the signature for call-shape parity with the Go oracle; the kind marker
/// drives the mapping.
pub fn guess_relay_format_from_request(
    _request: &Value,
    kind: Option<RequestKind>,
) -> Option<&'static str> {
    kind.map(|k| k.relay_format())
}

/// Go `relay/common.AppendRequestConversionFromRequest` (convert_request.go:
/// 14-23): on a recognized request format, record the hop on the meta. A nil
/// info / unrecognized request is a no-op, matching the Go early returns.
pub fn append_request_conversion_from_request<M: crate::convmeta::ConvMeta>(
    info: Option<&mut M>,
    request: &Value,
    kind: Option<RequestKind>,
) {
    let info = match info {
        Some(info) => info,
        None => return,
    };
    if let Some(format) = guess_relay_format_from_request(request, kind) {
        info.append_request_conversion(format);
    }
}

/// Go `relay/common.GuessRelayFormatFromRequest` delegating alias
/// (convert_request.go:10-12).
pub fn guess_relay_format_from_request_kind(kind: RequestKind) -> &'static str {
    kind.relay_format()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::convmeta::MetaValues;

    fn kind_of(format: &str) -> Option<RequestKind> {
        Some(match format {
            "openai" => RequestKind::GeneralOpenAI,
            "openai_responses" => RequestKind::OpenAIResponses,
            "claude" => RequestKind::Claude,
            "gemini" => RequestKind::GeminiChat,
            "embedding" => RequestKind::Embedding,
            "rerank" => RequestKind::Rerank,
            "openai_image" => RequestKind::OpenAIImage,
            "openai_audio" => RequestKind::Audio,
            _ => return None,
        })
    }

    /// Go convert_request.go delegation: every recognized request type maps to
    /// its format; unknown shapes return false.
    #[test]
    fn guess_relay_format_table_matches_go_type_switch() {
        let request = serde_json::json!({"model": "gpt-test"});
        for (kind, want) in [
            ("openai", "openai"),
            ("openai_responses", "openai_responses"),
            ("claude", "claude"),
            ("gemini", "gemini"),
            ("embedding", "embedding"),
            ("rerank", "rerank"),
            ("openai_image", "openai_image"),
            ("openai_audio", "openai_audio"),
        ] {
            assert_eq!(
                guess_relay_format_from_request(&request, kind_of(kind)),
                Some(want),
            );
        }
        assert_eq!(guess_relay_format_from_request(&request, None), None);
    }

    /// Go AppendRequestConversionFromRequest: nil info → no-op; unknown
    /// request → no-op.
    #[test]
    fn append_request_conversion_from_request_gates() {
        let request = serde_json::json!({"model": "gpt-test"});
        let mut info = MetaValues::default();
        append_request_conversion_from_request(Some(&mut info), &request, None);
        assert!(info.conversion_chain.is_empty());

        append_request_conversion_from_request(
            Some(&mut info),
            &request,
            Some(RequestKind::OpenAIResponses),
        );
        assert_eq!(info.conversion_chain, vec!["openai_responses".to_owned()]);

        // Go: nil info must not panic (early return).
        let none: Option<&mut MetaValues> = None;
        append_request_conversion_from_request(none, &request, Some(RequestKind::OpenAIResponses));
    }

    #[test]
    fn kind_alias_matches_format() {
        assert_eq!(
            guess_relay_format_from_request_kind(RequestKind::GeneralOpenAI),
            crate::relay_info::relay_format::OPENAI
        );
    }
}
