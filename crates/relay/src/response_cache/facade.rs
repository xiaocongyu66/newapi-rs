//! Relay-level response cache facade. Port of the upstream Go
//! `internal/relay/response_cache.go` (lines 23-195): eligibility input
//! extraction from a chat request, volatile-field-stripped key building, and
//! the settle classification. The store itself is `response_cache::store`
//! (the prior slice's port of `internal/responsecache`).
//!
//! Go's `responseCacheReplay` / `responseCacheSettle` write to the HTTP
//! stream and call `billing.PostAudioConsumeQuota` /
//! `billing.PostTextConsumeQuota`; those host boundaries are represented by
//! the settle classification returned here (audio vs text) — the transport
//! and billing slices own the actual writes.

use serde_json::{Map, Value};

use super::key::key;

/// RelayInfo / global inputs that gate cache eligibility (Go reads these
/// off RelayInfo and the option-backed globals inside `responseCacheEligible`).
#[derive(Clone, Debug)]
pub struct EligibilityContext<'a> {
    /// Go `info.RelayMode == relayconstant.RelayModeChatCompletions`.
    pub relay_mode_chat_completions: bool,
    /// Go `info.RelayFormat == types.RelayFormatOpenAI`.
    pub relay_format_openai: bool,
    /// Go `info.ChannelSetting` wire object.
    pub channel_setting: &'a Value,
    /// Go `info.ChannelOtherSettings` wire object.
    pub channel_other_settings: &'a Value,
    /// Go `len(info.ParamOverride) > 0`.
    pub param_override_present: bool,
    /// Go `model_setting.GetGlobalSettings().PassThroughRequestEnabled`.
    pub pass_through_request_enabled: bool,
    /// Go `common.ResponseCacheEnabled`.
    pub response_cache_enabled: bool,
}

/// Go `responseCacheEligible` (response_cache.go:41-102) evaluated directly
/// on the chat request wire object.
pub fn response_cache_eligible(ctx: &EligibilityContext<'_>, request: &Value) -> bool {
    if !ctx.relay_mode_chat_completions {
        return false;
    }
    // Only OpenAI-format output is cached: the replay hardcodes the OpenAI
    // JSON content type.
    if !ctx.relay_format_openai {
        return false;
    }
    // Pass-through channels forward the raw provider body; exclude them.
    let pass_through_body_enabled = ctx
        .channel_setting
        .get("pass_through_body_enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if pass_through_body_enabled || ctx.pass_through_request_enabled {
        return false;
    }
    // Channel-level mutations change the response after this eligibility
    // point but are not part of the cache key. Exclude for safety.
    let system_prompt = ctx
        .channel_setting
        .get("system_prompt")
        .and_then(Value::as_str)
        .unwrap_or("");
    if !system_prompt.is_empty() || ctx.param_override_present {
        return false;
    }
    // ChannelOtherSettings influences RemoveDisabledFields; treat as
    // ineligible whenever the raw JSON representation is non-empty
    // (Go marshals and checks `len(b) > 2` — "{}" means no settings).
    let has_other_settings = match ctx.channel_other_settings {
        Value::Object(map) => !map.is_empty(),
        Value::Null => false,
        _ => true,
    };
    if has_other_settings {
        return false;
    }
    if !ctx.response_cache_enabled {
        return false;
    }
    // Streaming replays chunk boundaries; v1 caches only buffered bodies.
    if request
        .get("stream")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return false;
    }
    // temperature > 0 is non-deterministic.
    if let Some(temperature) = request.get("temperature")
        && temperature.as_f64().unwrap_or(0.0) != 0.0
    {
        return false;
    }
    // Tool/web-search requests bill per-call surcharges; a hit never parses
    // one, so it would undercharge.
    let has_tools = request.get("tools").is_some_and(|v| !v.is_null());
    let has_functions = request.get("functions").is_some_and(|v| !v.is_null());
    let has_tool_choice = request.get("tool_choice").is_some_and(|v| !v.is_null());
    let has_function_call = request.get("function_call").is_some_and(|v| !v.is_null());
    let has_web_search = request
        .get("web_search_options")
        .is_some_and(|v| !v.is_null());
    if has_tools || has_functions || has_tool_choice || has_function_call || has_web_search {
        return false;
    }
    true
}

/// Go `responseCacheBuildKey` (response_cache.go:109-126): shallow-strip the
/// volatile fields, marshal, hash with the upstream model name.
pub fn response_cache_build_key(
    request: &Value,
    upstream_model_name: &str,
) -> Result<String, String> {
    let Some(map) = request.as_object() else {
        return Err("request is not an object".to_owned());
    };
    let mut norm = Map::new();
    const VOLATILE: &[&str] = &[
        "stream",
        "user",
        "logit_bias",
        "metadata",
        "safety_identifier",
        "thinking_budget",
        "enable_thinking",
    ];
    for (k, v) in map {
        if VOLATILE.contains(&k.as_str()) {
            continue;
        }
        norm.insert(k.clone(), v.clone());
    }
    let canonical = serde_json::to_vec(&Value::Object(norm))
        .map_err(|e| format!("marshal normalized request: {e}"))?;
    Ok(key(&canonical, upstream_model_name))
}

/// Settle classification mirroring the audio/text dispatch in
/// `responseCacheSettle` (response_cache.go:178-195). The transport/billing
/// slices map `Audio` to `PostAudioConsumeQuota` and `Text` to
/// `PostTextConsumeQuota`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettleKind {
    /// usage.CompletionTokenDetails.AudioTokens > 0 ||
    /// usage.PromptTokensDetails.AudioTokens > 0.
    Audio,
    /// TextHelper's default branch.
    Text,
}

/// Parse the cached usage JSON and classify the settle path. `None` mirrors
/// the Go early returns (empty usage JSON or unmarshal failure → settle
/// nothing).
pub fn response_cache_settle_kind(usage_json: &[u8]) -> Option<SettleKind> {
    if usage_json.is_empty() {
        return None;
    }
    let usage: Value = match serde_json::from_slice(usage_json) {
        Ok(usage) => usage,
        Err(_) => return None,
    };
    let prompt_audio = usage
        .get("prompt_tokens_details")
        .and_then(|d| d.get("audio_tokens"))
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let completion_audio = usage
        .get("completion_tokens_details")
        .and_then(|d| d.get("audio_tokens"))
        .and_then(Value::as_i64)
        .unwrap_or(0);
    if completion_audio > 0 || prompt_audio > 0 {
        Some(SettleKind::Audio)
    } else {
        Some(SettleKind::Text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn base_request() -> Value {
        json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "hi"}],
        })
    }

    fn eligible_ctx<'a>(
        relay_mode_chat_completions: bool,
        relay_format_openai: bool,
        channel_setting: &'a Value,
        channel_other_settings: &'a Value,
        param_override_present: bool,
        pass_through_request_enabled: bool,
        response_cache_enabled: bool,
    ) -> EligibilityContext<'a> {
        EligibilityContext {
            relay_mode_chat_completions,
            relay_format_openai,
            channel_setting,
            channel_other_settings,
            param_override_present,
            pass_through_request_enabled,
            response_cache_enabled,
        }
    }

    /// Go response_cache.go:41-102 — the full gate chain.
    #[test]
    fn eligibility_gate_chain() {
        let request = base_request();
        let cs = json!({});
        let cos = json!({});
        let ctx = eligible_ctx(true, true, &cs, &cos, false, false, true);
        assert!(response_cache_eligible(&ctx, &request));

        // Non-chat mode / non-OpenAI format.
        assert!(!response_cache_eligible(
            &eligible_ctx(false, true, &cs, &cos, false, false, true),
            &request
        ));
        assert!(!response_cache_eligible(
            &eligible_ctx(true, false, &cs, &cos, false, false, true),
            &request
        ));
        // Pass-through body / request.
        let cs_passthrough = json!({"pass_through_body_enabled": true});
        assert!(!response_cache_eligible(
            &eligible_ctx(true, true, &cs_passthrough, &cos, false, false, true),
            &request
        ));
        assert!(!response_cache_eligible(
            &eligible_ctx(true, true, &cs, &cos, false, true, true),
            &request
        ));
        // Channel system prompt / param override.
        let cs_prompt = json!({"system_prompt": "be nice"});
        assert!(!response_cache_eligible(
            &eligible_ctx(true, true, &cs_prompt, &cos, false, false, true),
            &request
        ));
        assert!(!response_cache_eligible(
            &eligible_ctx(true, true, &cs, &cos, true, false, true),
            &request
        ));
        // Channel other settings present.
        let cos_other = json!({"disable_store": true});
        assert!(!response_cache_eligible(
            &eligible_ctx(true, true, &cs, &cos_other, false, false, true),
            &request
        ));
        // Cache disabled.
        assert!(!response_cache_eligible(
            &eligible_ctx(true, true, &cs, &cos, false, false, false),
            &request
        ));
        // Streaming.
        let streaming = json!({"stream": true, "messages": []});
        assert!(!response_cache_eligible(&ctx, &streaming));
        // Nonzero temperature.
        let warm = json!({"temperature": 0.7, "messages": []});
        assert!(!response_cache_eligible(&ctx, &warm));
        // Explicit zero temperature is deterministic → eligible.
        let zero = json!({"temperature": 0, "messages": []});
        assert!(response_cache_eligible(&ctx, &zero));
        // Tooling present.
        for field in [
            "tools",
            "functions",
            "tool_choice",
            "function_call",
            "web_search_options",
        ] {
            let mut req = serde_json::Map::new();
            req.insert(field.to_owned(), json!([{"type": "function"}]));
            let req = Value::Object(req);
            assert!(!response_cache_eligible(&ctx, &req), "{field}");
        }
    }

    /// Go response_cache.go:109-126 — volatile fields stripped before hashing.
    #[test]
    fn build_key_strips_volatile_fields() {
        let request = json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "hi"}],
            "stream": true,
            "user": "u1",
            "logit_bias": {"50256": -100},
            "metadata": {"k": "v"},
            "safety_identifier": "sid",
            "thinking_budget": 128,
            "enable_thinking": true,
        });
        let key_a = response_cache_build_key(&request, "gpt-4o").expect("key");

        let stripped = base_request();
        let key_b = response_cache_build_key(&stripped, "gpt-4o").expect("key");
        assert_eq!(key_a, key_b, "volatile fields must not change the key");

        // Different body / model → different key (Go responsecache_test.go).
        let different = json!({"model": "gpt-4o", "messages": [{"role": "user", "content": "ho"}]});
        assert_ne!(
            key_a,
            response_cache_build_key(&different, "gpt-4o").unwrap()
        );
        assert_ne!(
            key_a,
            response_cache_build_key(&stripped, "gpt-4o-mini").unwrap()
        );
    }

    /// Go response_cache.go:178-195 — settle classification.
    #[test]
    fn settle_classification() {
        // Empty usage JSON → settle nothing.
        assert_eq!(response_cache_settle_kind(b""), None);
        // Unmarshalable → settle nothing.
        assert_eq!(response_cache_settle_kind(b"not json"), None);
        // Audio tokens in either detail → audio path.
        let audio_usage = json!({
            "prompt_tokens": 10,
            "completion_tokens": 5,
            "completion_tokens_details": {"audio_tokens": 2},
        });
        assert_eq!(
            response_cache_settle_kind(audio_usage.to_string().as_bytes()),
            Some(SettleKind::Audio)
        );
        let audio_usage_prompt = json!({
            "prompt_tokens": 10,
            "prompt_tokens_details": {"audio_tokens": 3},
        });
        assert_eq!(
            response_cache_settle_kind(audio_usage_prompt.to_string().as_bytes()),
            Some(SettleKind::Audio)
        );
        // Plain text usage → text path.
        let text_usage = json!({"prompt_tokens": 10, "completion_tokens": 5});
        assert_eq!(
            response_cache_settle_kind(text_usage.to_string().as_bytes()),
            Some(SettleKind::Text)
        );
    }

    /// Key format: hex sha256 over model || 0x00 || canonical JSON.
    #[test]
    fn key_is_hex_sha256() {
        let key = response_cache_build_key(&base_request(), "gpt-4o").expect("key");
        assert_eq!(key.len(), 64);
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
