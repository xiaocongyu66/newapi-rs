//! OpenAI Responses request preprocessing for Gemini-target conversions.
//! Port of the upstream Go
//! `relaykit/relayconvert/internal/oai_responses/to_gemini_chat_req_preprocess.go`
//! (lines 1-102): filter the tools list down to `function` entries and drop
//! custom_tool_call/output pairs from the input.

use serde_json::Value;

/// Error shape mirrors the Go error text (unmarshal failures surface raw).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareError(pub String);

fn get_json_type(raw: &Value) -> &'static str {
    match raw {
        Value::Object(_) => "object",
        Value::Array(_) => "array",
        Value::String(_) => "string",
        Value::Bool(_) => "boolean",
        Value::Null => "null",
        Value::Number(_) => "number",
    }
}

fn raw_present(raw: &Value) -> bool {
    // Go geminiRawJSONPresent: empty raw is "absent"; Value::Null models both
    // the Go nil raw and literal null here, and both read as absent.
    get_json_type(raw) != "null"
}

fn interface2_string(value: &Value) -> String {
    // Go kitutil.Interface2String: strings as-is, numbers via %v, others via
    // fmt %v. On JSON values this reduces to strings verbatim and everything
    // else through compact JSON (Go's %v on map[string]any prints map[...] —
    // the only Go call sites feed string-typed fields, where both agree).
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Go `PrepareOpenAIResponsesRequest` (to_gemini_chat_req_preprocess.go:20-34).
pub fn prepare_openai_responses_request(request: Value) -> Result<Value, PrepareError> {
    let Some(map) = request.as_object() else {
        return Ok(request);
    };
    let mut map = map.clone();

    map.insert(
        "tools".to_owned(),
        filter_gemini_responses_tools(map.get("tools"))?,
    );
    map.insert(
        "input".to_owned(),
        filter_gemini_responses_input(map.get("input"))?,
    );
    Ok(Value::Object(map))
}

/// Go `filterGeminiResponsesTools` (to_gemini_chat_req_preprocess.go:36-57).
fn filter_gemini_responses_tools(raw: Option<&Value>) -> Result<Value, PrepareError> {
    let Some(raw) = raw else {
        return Ok(Value::Null);
    };
    if !raw_present(raw) || get_json_type(raw) != "array" {
        return Ok(raw.clone());
    }
    let Some(tools) = raw.as_array() else {
        return Err(PrepareError("unmarshal tools failed".to_owned()));
    };

    let filtered: Vec<Value> = tools
        .iter()
        .filter(|tool| {
            let type_value = tool.get("type").map(interface2_string).unwrap_or_default();
            type_value.trim() == "function"
        })
        .cloned()
        .collect();
    if filtered.is_empty() {
        return Ok(Value::Null);
    }
    Ok(Value::Array(filtered))
}

/// Go `filterGeminiResponsesInput` (to_gemini_chat_req_preprocess.go:59-93).
fn filter_gemini_responses_input(raw: Option<&Value>) -> Result<Value, PrepareError> {
    let Some(raw) = raw else {
        return Ok(Value::Null);
    };
    if !raw_present(raw) || get_json_type(raw) != "array" {
        return Ok(raw.clone());
    }
    let Some(items) = raw.as_array() else {
        return Err(PrepareError("unmarshal input failed".to_owned()));
    };

    // Collect call_ids of skipped custom_tool_call items.
    let mut skipped_custom_call_ids: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    for item in items {
        let item_type = item
            .get("type")
            .map(interface2_string)
            .unwrap_or_default()
            .trim()
            .to_owned();
        if item_type != "custom_tool_call" {
            continue;
        }
        let call_id = item
            .get("call_id")
            .map(interface2_string)
            .unwrap_or_default()
            .trim()
            .to_owned();
        if !call_id.is_empty() {
            skipped_custom_call_ids.insert(call_id);
        }
    }

    let mut filtered: Vec<Value> = Vec::with_capacity(items.len());
    for item in items {
        let item_type = item
            .get("type")
            .map(interface2_string)
            .unwrap_or_default()
            .trim()
            .to_owned();
        match item_type.as_str() {
            "custom_tool_call" | "custom_tool_call_output" => continue,
            "function_call_output" => {
                let call_id = item
                    .get("call_id")
                    .map(interface2_string)
                    .unwrap_or_default()
                    .trim()
                    .to_owned();
                if skipped_custom_call_ids.contains(&call_id) {
                    continue;
                }
            }
            _ => {}
        }
        filtered.push(item.clone());
    }

    Ok(Value::Array(filtered))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Go to_gemini_chat_req_preprocess.go:36-57: non-function tools dropped,
    /// empty result → null.
    #[test]
    fn filters_tools_to_function_type() {
        let request = json!({
            "model": "gpt-test",
            "tools": [
                {"type": "function", "name": "lookup"},
                {"type": "web_search"},
            ],
        });
        let got = prepare_openai_responses_request(request).expect("prepare");
        assert_eq!(
            got["tools"],
            json!([{"type": "function", "name": "lookup"}])
        );

        let request = json!({
            "model": "gpt-test",
            "tools": [{"type": "web_search"}],
        });
        let got = prepare_openai_responses_request(request).expect("prepare");
        assert!(got.get("tools").is_none() || got["tools"].is_null());
    }

    /// Go to_gemini_chat_req_preprocess.go:59-93: custom_tool_call/output
    /// pairs removed, including their function_call_output by call_id.
    #[test]
    fn filters_custom_tool_calls_and_their_outputs() {
        let request = json!({
            "model": "gpt-test",
            "input": [
                {"type": "message", "role": "user", "content": "hi"},
                {"type": "custom_tool_call", "call_id": "c1", "name": "tool"},
                {"type": "custom_tool_call_output", "call_id": "c1", "output": "x"},
                {"type": "function_call_output", "call_id": "c1", "output": "y"},
                {"type": "function_call_output", "call_id": "c2", "output": "keep"},
            ],
        });
        let got = prepare_openai_responses_request(request).expect("prepare");
        let input = got["input"].as_array().expect("array");
        assert_eq!(input.len(), 2);
        assert_eq!(input[0]["type"], json!("message"));
        assert_eq!(input[1]["call_id"], json!("c2"));
    }

    /// Non-array input/tools pass through untouched (raw_present check).
    #[test]
    fn non_array_fields_pass_through() {
        let request = json!({
            "model": "gpt-test",
            "input": "plain text",
            "tools": Value::Null,
        });
        let got = prepare_openai_responses_request(request.clone()).expect("prepare");
        assert_eq!(got, request);
    }
}
