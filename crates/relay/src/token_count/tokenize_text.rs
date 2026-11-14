//! tiktoken-backed token counting for OpenAI text models. Port of the
//! upstream Go `internal/relay/common/tokenize_text.go` (lines 1-63) plus the
//! `CountTextToken` routing from `count_tokens.go` (399-411).
//!
//! tiktoken semantics (deviations registered in the slice report):
//! - Go library: tiktoken-go/tokenizer v0.6.2 (`tokenizer.ForModel` +
//!   `codec.NewCl100kBase()` default). Rust: tiktoken-rs 0.12.1
//!   (`CoreBPE::encode_ordinary`), which matches Go `codec.Count`: regex
//!   split + BPE merge with NO special-token recognition.
//! - The model routing table below is the Go oracle's exact table
//!   (tokenizer.go ForModel + modelPrefixToEncoding). tiktoken-rs's own
//!   `bpe_for_model` routing is deliberately NOT used: the Go oracle falls
//!   back to cl100k for models tiktoken-go does not know (gpt-5*, gpt-4.1*,
//!   o3, o4-mini...), and billing parity requires the same counts.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use tiktoken_rs::CoreBPE;

/// Encoding names (Go tokenizer.Encoding constants). Not `Copy` because it
/// is only matched by reference in the tables; derives keep the test
/// `matches!` assertions working.
#[derive(Clone, Copy, Debug)]
enum Encoding {
    Cl100kBase,
    O200kBase,
    P50kBase,
    R50kBase,
    P50kEdit,
}

/// Go `tokenizer.ForModel` exact-model table (tokenizer.go:121-157).
fn encoding_for_exact_model(model: &str) -> Option<Encoding> {
    match model {
        "o1-preview" | "o1-mini" | "gpt-4o" | "o3-mini" => Some(Encoding::O200kBase),
        "gpt-4" | "gpt-3.5" | "gpt-3.5-turbo" | "text-embedding-ada-002" => {
            Some(Encoding::Cl100kBase)
        }
        "text-davinci-003" | "text-davinci-002" | "code-davinci-001" | "code-davinci-002"
        | "code-cushman-002" | "code-cushman-001" | "davinci-codex" | "cushman-codex" => {
            Some(Encoding::P50kBase)
        }
        "text-davinci-001"
        | "text-curie-001"
        | "text-babbage-001"
        | "text-ada-001"
        | "davinci"
        | "curie"
        | "babbage"
        | "ada"
        | "text-similarity-davinci-001"
        | "text-similarity-curie-001"
        | "text-similarity-babbage-001"
        | "text-similarity-ada-001"
        | "text-search-davinci-doc-001"
        | "text-search-curie-doc-001"
        | "text-search-ada-doc-001"
        | "text-search-babbage-doc-001"
        | "code-search-babbage-code-001"
        | "code-search-ada-code-001" => Some(Encoding::R50kBase),
        "text-davinci-edit-001" | "code-davinci-edit-001" => Some(Encoding::P50kEdit),
        _ => None,
    }
}

/// Go `modelPrefixToEncoding` (tokenizer.go:160-172).
fn encoding_for_model_prefix(model: &str) -> Option<Encoding> {
    const PREFIXES: &[(&str, EncodingForPrefix)] = &[
        ("o1-", EncodingForPrefix::O200k),
        ("chatgpt-4o-", EncodingForPrefix::O200k),
        ("gpt-4o-", EncodingForPrefix::O200k),
        ("gpt-4-", EncodingForPrefix::Cl100k),
        ("gpt-3.5-turbo-", EncodingForPrefix::Cl100k),
        ("gpt-35-turbo-", EncodingForPrefix::Cl100k),
        ("ft:gpt-4", EncodingForPrefix::Cl100k),
        ("ft:gpt-3.5-turbo", EncodingForPrefix::Cl100k),
        ("ft:davinci-002", EncodingForPrefix::Cl100k),
        ("ft:babbage-002", EncodingForPrefix::Cl100k),
    ];
    // Go iterates a map — order is nondeterministic but no key in the table is
    // a prefix of another, so any order resolves identically.
    for (prefix, encoding) in PREFIXES {
        if model.starts_with(prefix) {
            return Some(match *encoding {
                EncodingForPrefix::O200k => Encoding::O200kBase,
                EncodingForPrefix::Cl100k => Encoding::Cl100kBase,
            });
        }
    }
    None
}

#[derive(Clone, Copy)]
enum EncodingForPrefix {
    O200k,
    Cl100k,
}

/// Go `tokenizer.ForModel`: exact match, then prefix match, else error.
fn for_model(model: &str) -> Option<Encoding> {
    encoding_for_exact_model(model).or_else(|| encoding_for_model_prefix(model))
}

fn bpe_for_encoding(encoding: Encoding) -> &'static CoreBPE {
    static CL100K: OnceLock<CoreBPE> = OnceLock::new();
    static O200K: OnceLock<CoreBPE> = OnceLock::new();
    static P50K: OnceLock<CoreBPE> = OnceLock::new();
    static R50K: OnceLock<CoreBPE> = OnceLock::new();
    static P50K_EDIT: OnceLock<CoreBPE> = OnceLock::new();
    match encoding {
        Encoding::Cl100kBase => {
            CL100K.get_or_init(|| tiktoken_rs::cl100k_base().expect("cl100k_base"))
        }
        Encoding::O200kBase => O200K.get_or_init(|| tiktoken_rs::o200k_base().expect("o200k_base")),
        Encoding::P50kBase => P50K.get_or_init(|| tiktoken_rs::p50k_base().expect("p50k_base")),
        Encoding::R50kBase => R50K.get_or_init(|| tiktoken_rs::r50k_base().expect("r50k_base")),
        Encoding::P50kEdit => {
            P50K_EDIT.get_or_init(|| tiktoken_rs::p50k_edit().expect("p50k_edit"))
        }
    }
}

/// Go `defaultTokenEncoder` (tokenize_text.go:12,22-24): cl100k base.
fn default_token_encoder() -> &'static CoreBPE {
    static DEFAULT: OnceLock<CoreBPE> = OnceLock::new();
    DEFAULT.get_or_init(|| tiktoken_rs::cl100k_base().expect("cl100k_base default"))
}

/// Go `tokenEncoderMap` + `getTokenEncoder` (tokenize_text.go:15-55): models
/// that resolve through `ForModel` get their codec cached per model; failures
/// fall back to the cl100k default (and the fallback itself is cached so the
/// failure lookup does not repeat).
fn get_token_encoder(model: &str) -> &'static CoreBPE {
    static CACHE: OnceLock<Mutex<HashMap<String, &'static CoreBPE>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(encoder) = guard.get(model) {
        return encoder;
    }
    let encoder = match for_model(model) {
        Some(encoding) => bpe_for_encoding(encoding),
        None => default_token_encoder(),
    };
    guard.insert(model.to_owned(), encoder);
    encoder
}

/// Go `getTokenNum` (tokenize_text.go:57-63): Count with errors swallowed.
fn get_token_num(encoder: &CoreBPE, text: &str) -> i64 {
    if text.is_empty() {
        return 0;
    }
    encoder.encode_ordinary(text).len() as i64
}

/// Go `common.IsOpenAITextModel` (internal/common/model.go:51-59): lowercase
/// model containing any of gpt-, o1, o3, o4, chatgpt.
pub fn is_openai_text_model(model_name: &str) -> bool {
    let model_name = model_name.to_lowercase();
    ["gpt-", "o1", "o3", "o4", "chatgpt"]
        .iter()
        .any(|m| model_name.contains(m))
}

/// Go `CountTextToken` (count_tokens.go:399-411): OpenAI text models go
/// through the tokenizer, everything else through the heuristic estimator.
pub fn count_text_token(text: &str, model: &str) -> i64 {
    if text.is_empty() {
        return 0;
    }
    if is_openai_text_model(model) {
        get_token_num(get_token_encoder(model), text)
    } else {
        super::estimate_tokens::estimate_token_by_model(model, text)
    }
}

/// Go `InitTokenEncoders` (tokenize_text.go:20-25): the Go side needs an
/// explicit warm-up because an uninitialized default encoder nil-panics; the
/// Rust port initializes lazily. The function exists so startup call sites
/// can still force the encoders to load (and fail fast on a broken vocab).
pub fn init_token_encoders() {
    let _ = default_token_encoder();
    let _ = bpe_for_encoding(Encoding::Cl100kBase);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Go tokenize_text_test.go:52-60 — after init, an unknown OpenAI model
    /// name counts positively through the cl100k fallback.
    #[test]
    fn count_text_token_falls_back_without_panic_after_init() {
        const UNKNOWN_OPENAI_MODEL: &str = "gpt-5-chat";
        // Pin the premise: the Go oracle's ForModel rejects this name (no
        // exact match, no prefix hit), so the fallback is a live path.
        assert!(for_model(UNKNOWN_OPENAI_MODEL).is_none());
        assert!(is_openai_text_model(UNKNOWN_OPENAI_MODEL));

        let got = count_text_token("hello world", UNKNOWN_OPENAI_MODEL);
        assert!(got > 0, "want a positive token count, got {got}");
    }

    /// Known models route to their encodings (Go tokenizer.go:121-157).
    #[test]
    fn for_model_table() {
        assert!(matches!(for_model("gpt-4o"), Some(Encoding::O200kBase)));
        assert!(matches!(for_model("o1-preview"), Some(Encoding::O200kBase)));
        assert!(matches!(for_model("o1-mini"), Some(Encoding::O200kBase)));
        assert!(matches!(for_model("o3-mini"), Some(Encoding::O200kBase)));
        assert!(matches!(for_model("gpt-4"), Some(Encoding::Cl100kBase)));
        assert!(matches!(
            for_model("gpt-3.5-turbo"),
            Some(Encoding::Cl100kBase)
        ));
        assert!(matches!(
            for_model("text-embedding-ada-002"),
            Some(Encoding::Cl100kBase)
        ));
        assert!(matches!(
            for_model("text-davinci-003"),
            Some(Encoding::P50kBase)
        ));
        assert!(matches!(for_model("davinci"), Some(Encoding::R50kBase)));
        assert!(matches!(
            for_model("text-davinci-edit-001"),
            Some(Encoding::P50kEdit)
        ));
        assert!(for_model("gpt-5-chat").is_none());
    }

    /// Prefix routing (Go modelPrefixToEncoding, tokenizer.go:160-172).
    #[test]
    fn for_model_prefixes() {
        assert!(matches!(
            for_model("gpt-4o-mini"),
            Some(Encoding::O200kBase)
        ));
        assert!(matches!(
            for_model("chatgpt-4o-latest"),
            Some(Encoding::O200kBase)
        ));
        assert!(matches!(
            for_model("gpt-4-0314"),
            Some(Encoding::Cl100kBase)
        ));
        assert!(matches!(
            for_model("gpt-3.5-turbo-0301"),
            Some(Encoding::Cl100kBase)
        ));
        assert!(matches!(
            for_model("gpt-35-turbo-16k"),
            Some(Encoding::Cl100kBase)
        ));
        assert!(matches!(
            for_model("o1-2024-12-17"),
            Some(Encoding::O200kBase)
        ));
        assert!(matches!(
            for_model("ft:gpt-4o-2024:x"),
            Some(Encoding::Cl100kBase)
        ));
        // gpt-5/gpt-4.1 prefixes are NOT in the Go table → cl100k fallback.
        assert!(for_model("gpt-5").is_none());
        assert!(for_model("gpt-4.1-mini").is_none());
    }

    /// IsOpenAITextModel membership (internal/common/model.go:51-59).
    #[test]
    fn openai_text_model_membership() {
        assert!(is_openai_text_model("gpt-4o"));
        assert!(is_openai_text_model("GPT-5"));
        assert!(is_openai_text_model("o1"));
        assert!(is_openai_text_model("o3-mini"));
        assert!(is_openai_text_model("o4-mini"));
        assert!(is_openai_text_model("chatgpt-4o-latest"));
        assert!(!is_openai_text_model("claude-3"));
        assert!(!is_openai_text_model("gemini-1.5"));
        assert!(!is_openai_text_model(""));
    }

    /// Non-OpenAI models route to the heuristic estimator
    /// (count_tokens.go:407-410).
    #[test]
    fn non_openai_models_use_heuristic() {
        assert_eq!(
            count_text_token("hello world", "claude-3"),
            super::super::estimate_tokens::estimate_token_by_model("claude-3", "hello world")
        );
    }

    /// Empty text → 0 for any model (count_tokens.go:401-403).
    #[test]
    fn empty_text_is_zero() {
        assert_eq!(count_text_token("", "gpt-4o"), 0);
        assert_eq!(count_text_token("", "claude-3"), 0);
    }

    /// The tokenizer produces the well-known cl100k count for a stable
    /// sentence; guards against a silent encoding swap.
    #[test]
    fn cl100k_reference_count() {
        // "hello world" encodes to 2 cl100k tokens (hello +  world).
        assert_eq!(count_text_token("hello world", "gpt-5-chat"), 2);
    }

    /// o200k routing for gpt-4o differs from cl100k on multi-byte input;
    /// both engines must load and count positively.
    #[test]
    fn o200k_path_counts() {
        let got = count_text_token("hello world", "gpt-4o");
        assert!(got > 0);
    }

    /// init_token_encoders is idempotent (Go main.go calls it once; the Rust
    /// OnceLock tolerates repeats).
    #[test]
    fn init_is_idempotent() {
        init_token_encoders();
        init_token_encoders();
    }
}
