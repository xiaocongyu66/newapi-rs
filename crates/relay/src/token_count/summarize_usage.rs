//! Usage summarization. Port of the upstream Go
//! `internal/relay/common/summarize_usage.go` (lines 1-34).

use serde_json::{Map, Value};

use super::estimate_tokens;

/// Go `(*RelayInfo)`-side builtin tool store alias: the usage helpers below
/// operate on the Usage JSON object (Go `dto.Usage`).
pub type UsageObject = Map<String, Value>;

/// Go `ResponseText2Usage` (summarize_usage.go:23-30). The Go function sets
/// `constant.ContextKeyLocalCountTokens` on the request context; the Rust
/// port returns the flag alongside the usage so the host pipeline can store
/// it. `usage.prompt_tokens = promptTokens`,
/// `completion_tokens = EstimateTokenByModel(modeName, responseText)`,
/// `total_tokens = prompt + completion`.
pub fn response_text_2_usage(
    response_text: &str,
    mode_name: &str,
    prompt_tokens: i64,
) -> (Value, bool) {
    let completion_tokens = estimate_tokens::estimate_token_by_model(mode_name, response_text);
    let mut usage = Map::new();
    usage.insert("prompt_tokens".into(), Value::from(prompt_tokens));
    usage.insert("completion_tokens".into(), Value::from(completion_tokens));
    usage.insert(
        "total_tokens".into(),
        Value::from(prompt_tokens + completion_tokens),
    );
    (Value::Object(usage), true)
}

/// Go `ValidUsage` (summarize_usage.go:32-34): non-nil usage with a non-zero
/// prompt or completion count.
pub fn valid_usage(usage: Option<&Value>) -> bool {
    let Some(usage) = usage else { return false };
    let prompt = usage
        .get("prompt_tokens")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let completion = usage
        .get("completion_tokens")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    prompt != 0 || completion != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Go summarize_usage.go:23-30 — completion estimate and totals.
    #[test]
    fn response_text_2_usage_computes_totals() {
        let (usage, local_flag) = response_text_2_usage("hello world", "gpt-4o", 10);
        assert!(local_flag);
        let prompt = usage["prompt_tokens"].as_i64().unwrap();
        let completion = usage["completion_tokens"].as_i64().unwrap();
        let total = usage["total_tokens"].as_i64().unwrap();
        assert_eq!(prompt, 10);
        assert_eq!(
            completion,
            estimate_tokens::estimate_token_by_model("gpt-4o", "hello world")
        );
        assert_eq!(total, prompt + completion);
    }

    /// Go summarize_usage.go:32-34.
    #[test]
    fn valid_usage_rules() {
        assert!(!valid_usage(None));
        assert!(!valid_usage(Some(
            &json!({"prompt_tokens": 0, "completion_tokens": 0})
        )));
        assert!(valid_usage(Some(
            &json!({"prompt_tokens": 1, "completion_tokens": 0})
        )));
        assert!(valid_usage(Some(
            &json!({"prompt_tokens": 0, "completion_tokens": 1})
        )));
        // Missing fields read as zero.
        assert!(!valid_usage(Some(&json!({}))));
    }
}
