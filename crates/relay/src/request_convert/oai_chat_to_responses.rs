//! OpenAI Chat Completions → OpenAI Responses request conversion. Verbatim
//! port of the upstream Go
//! `relaykit/relayconvert/internal/oai_chat/to_oai_responses_req.go` (lines
//! 14-414), the converter behind registry ID
//! `openai_chat_completions_to_openai_responses`.

use serde_json::{Map, Value};

use super::dto::{self, ChatMessage, content_type, parse_chat_message};

/// Error shape mirrors the Go error strings verbatim (the registry surfaces
/// them to the request pipeline unchanged).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConvertError(pub String);

impl std::fmt::Display for ConvertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConvertError {}

fn err(message: impl Into<String>) -> ConvertError {
    ConvertError(message.into())
}

/// Go `normalizeChatImageURLToString` (to_oai_responses_req.go:14-36): string
/// passthrough; `{url: "..."}` → the url string; anything else unchanged.
fn normalize_chat_image_url_to_string(value: Value) -> Value {
    match value {
        Value::String(s) => Value::String(s),
        Value::Object(ref map) => {
            if let Some(url) = map.get("url").and_then(Value::as_str)
                && !url.is_empty()
            {
                return Value::String(url.to_owned());
            }
            value
        }
        other => other,
    }
}

/// Go `convertChatResponseFormatToResponsesText` (to_oai_responses_req.go:
/// 38-74). `None` when the request has no usable response_format.
fn convert_chat_response_format_to_responses_text(
    response_format: Option<&Value>,
) -> Option<Value> {
    let raw = response_format?;
    let Some(map) = raw.as_object() else {
        return None;
    };
    let format_type = map.get("type").and_then(Value::as_str).unwrap_or("").trim();
    if format_type.is_empty() {
        return None;
    }

    let mut format = Map::new();
    format.insert("type".to_owned(), Value::String(format_type.to_owned()));

    if format_type == "json_schema" && map.get("json_schema").is_some_and(|v| !v.is_null()) {
        if let Some(chat_schema) = map.get("json_schema").and_then(Value::as_object) {
            for (key, value) in chat_schema {
                if key == "type" {
                    continue;
                }
                format.insert(key.clone(), value.clone());
            }

            // Move nested json_schema entries up, then drop the wrapper.
            if let Some(nested) = format
                .get("json_schema")
                .and_then(Value::as_object)
                .cloned()
            {
                for (key, value) in nested {
                    format.entry(key).or_insert(value);
                }
                format.remove("json_schema");
            }
        } else {
            format.insert("json_schema".to_owned(), map["json_schema"].clone());
        }
    }

    Some(serde_json::json!({ "format": format }))
}

/// Go `ChatCompletionsRequestToResponsesRequest` (to_oai_responses_req.go:
/// 76-414). `request` is the chat-completions wire object.
pub fn chat_completions_request_to_responses_request(
    request: &Value,
) -> Result<Value, ConvertError> {
    let Some(chat) = request.as_object() else {
        return Err(err("request is nil"));
    };
    let model = chat.get("model").and_then(Value::as_str).unwrap_or("");
    if model.is_empty() {
        return Err(err("model is required"));
    }
    let n = chat.get("n").and_then(Value::as_i64).unwrap_or(1);
    if n > 1 {
        return Err(err("n>1 is not supported in responses compatibility mode"));
    }

    let mut instructions_parts: Vec<String> = Vec::new();
    let mut input_items: Vec<Value> = Vec::with_capacity(
        chat.get("messages")
            .and_then(Value::as_array)
            .map_or(0, Vec::len),
    );

    let messages = chat
        .get("messages")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for raw_message in &messages {
        let message = parse_chat_message(raw_message);
        let role = message.role.trim().to_owned();
        if role.is_empty() {
            continue;
        }

        if role == "tool" || role == "function" {
            let call_id = message.tool_call_id.trim().to_owned();

            let output: Value = match message.content.as_ref() {
                None => Value::String(String::new()),
                Some(content) if message.is_string_content() => content.clone(),
                Some(content) => Value::String(content.to_string()),
            };

            if call_id.is_empty() {
                input_items.push(serde_json::json!({
                    "role": "user",
                    "content": format!("[tool_output_missing_call_id] {}", json_display(&output)),
                }));
                continue;
            }

            input_items.push(serde_json::json!({
                "type": "function_call_output",
                "call_id": call_id,
                "output": output,
            }));
            continue;
        }

        // Prefer mapping system/developer messages into `instructions`.
        if role == "system" || role == "developer" {
            if message.content.is_none() {
                continue;
            }
            if message.is_string_content() {
                let text = message.string_content().trim().to_owned();
                if !text.is_empty() {
                    instructions_parts.push(text);
                }
                continue;
            }
            let mut combined = String::new();
            for part in message.parse_content() {
                if part.kind == content_type::TEXT && !part.text.trim().is_empty() {
                    if !combined.is_empty() {
                        combined.push('\n');
                    }
                    combined.push_str(&part.text);
                }
            }
            let text = combined.trim().to_owned();
            if !text.is_empty() {
                instructions_parts.push(text);
            }
            continue;
        }

        let mut item = Map::new();
        item.insert("role".to_owned(), Value::String(role.clone()));

        let Some(content) = message.content.as_ref() else {
            item.insert("content".to_owned(), Value::String(String::new()));
            input_items.push(Value::Object(item));
            append_assistant_function_calls(&mut input_items, &message);
            continue;
        };

        if message.is_string_content() {
            item.insert("content".to_owned(), content.clone());
            input_items.push(Value::Object(item));
            append_assistant_function_calls(&mut input_items, &message);
            continue;
        }

        let parts = message.parse_content();
        let mut content_parts: Vec<Value> = Vec::with_capacity(parts.len());
        for part in &parts {
            match part.kind.as_str() {
                content_type::TEXT => {
                    let text_kind = if role == "assistant" {
                        "output_text"
                    } else {
                        "input_text"
                    };
                    content_parts.push(serde_json::json!({
                        "type": text_kind,
                        "text": part.text,
                    }));
                }
                content_type::IMAGE_URL => {
                    let image = part.image_url.clone().unwrap_or(Value::Null);
                    content_parts.push(serde_json::json!({
                        "type": "input_image",
                        "image_url": normalize_chat_image_url_to_string(image),
                    }));
                }
                content_type::INPUT_AUDIO => {
                    content_parts.push(serde_json::json!({
                        "type": "input_audio",
                        "input_audio": part.input_audio.clone().unwrap_or(Value::Null),
                    }));
                }
                content_type::FILE => {
                    content_parts.push(serde_json::json!({
                        "type": "input_file",
                        "file": part.file.clone().unwrap_or(Value::Null),
                    }));
                }
                content_type::VIDEO_URL => {
                    content_parts.push(serde_json::json!({
                        "type": "input_video",
                        "video_url": part.video_url.clone().unwrap_or(Value::Null),
                    }));
                }
                other => {
                    content_parts.push(serde_json::json!({ "type": other }));
                }
            }
        }
        item.insert("content".to_owned(), Value::Array(content_parts));
        input_items.push(Value::Object(item));

        append_assistant_function_calls(&mut input_items, &message);
    }

    let mut out = Map::new();
    out.insert("model".to_owned(), Value::String(model.to_owned()));
    out.insert("input".to_owned(), Value::Array(input_items));

    if !instructions_parts.is_empty() {
        let instructions = instructions_parts.join("\n\n");
        out.insert("instructions".to_owned(), Value::String(instructions));
    }

    if let Some(tools) = chat.get("tools").filter(|v| !v.is_null()) {
        let mut converted: Vec<Value> = Vec::new();
        if let Some(tool_list) = tools.as_array() {
            for tool in tool_list {
                let tool_type = tool.get("type").and_then(Value::as_str).unwrap_or("");
                if tool_type == "function" {
                    converted.push(serde_json::json!({
                        "type": "function",
                        "name": tool.get("function").and_then(|f| f.get("name")).cloned().unwrap_or(Value::Null),
                        "description": tool.get("function").and_then(|f| f.get("description")).cloned().unwrap_or(Value::Null),
                        "parameters": tool.get("function").and_then(|f| f.get("parameters")).cloned().unwrap_or(Value::Null),
                    }));
                } else {
                    // Best-effort: keep original tool shape for unknown types.
                    match tool {
                        Value::Object(map) if !map.is_empty() => {
                            converted.push(Value::Object(map.clone()))
                        }
                        _ => converted.push(serde_json::json!({ "type": tool_type })),
                    }
                }
            }
        }
        out.insert("tools".to_owned(), Value::Array(converted));
    }

    if let Some(tool_choice) = chat.get("tool_choice").filter(|v| !v.is_null()) {
        out.insert("tool_choice".to_owned(), convert_tool_choice(tool_choice));
    }

    if let Some(parallel) = chat.get("parallel_tool_calls").filter(|v| !v.is_null()) {
        out.insert("parallel_tool_calls".to_owned(), parallel.clone());
    }

    if let Some(text) = convert_chat_response_format_to_responses_text(chat.get("response_format"))
    {
        out.insert("text".to_owned(), text);
    }

    let max_tokens = chat.get("max_tokens").and_then(Value::as_u64).unwrap_or(0);
    let max_completion_tokens = chat
        .get("max_completion_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let has_any_max = chat.get("max_tokens").is_some_and(|v| !v.is_null())
        || chat
            .get("max_completion_tokens")
            .is_some_and(|v| !v.is_null());
    if has_any_max {
        out.insert(
            "max_output_tokens".to_owned(),
            Value::Number(serde_json::Number::from(
                max_tokens.max(max_completion_tokens),
            )),
        );
    }

    if let Some(stream) = chat.get("stream").filter(|v| !v.is_null()) {
        out.insert("stream".to_owned(), stream.clone());
    }
    if let Some(temperature) = chat.get("temperature").filter(|v| !v.is_null()) {
        out.insert("temperature".to_owned(), temperature.clone());
    }
    if let Some(top_p) = chat.get("top_p").filter(|v| !v.is_null()) {
        out.insert("top_p".to_owned(), top_p.clone());
    }
    if let Some(frequency) = chat.get("frequency_penalty").filter(|v| !v.is_null()) {
        out.insert("frequency_penalty".to_owned(), frequency.clone());
    }
    if let Some(presence) = chat.get("presence_penalty").filter(|v| !v.is_null()) {
        out.insert("presence_penalty".to_owned(), presence.clone());
    }
    if let Some(user) = chat.get("user").filter(|v| !v.is_null()) {
        out.insert("user".to_owned(), user.clone());
    }
    if let Some(store) = chat.get("store").filter(|v| !v.is_null()) {
        out.insert("store".to_owned(), store.clone());
    }
    if let Some(metadata) = chat.get("metadata").filter(|v| !v.is_null()) {
        out.insert("metadata".to_owned(), metadata.clone());
    }
    if let Some(enable_thinking) = chat.get("enable_thinking").filter(|v| !v.is_null()) {
        out.insert("enable_thinking".to_owned(), enable_thinking.clone());
    }
    if let Some(thinking_budget) = chat.get("thinking_budget").filter(|v| !v.is_null()) {
        out.insert("thinking_budget".to_owned(), thinking_budget.clone());
    }

    let reasoning_effort = chat
        .get("reasoning_effort")
        .and_then(Value::as_str)
        .unwrap_or("");
    if !reasoning_effort.is_empty() {
        out.insert(
            "reasoning".to_owned(),
            serde_json::json!({"effort": reasoning_effort, "summary": "detailed"}),
        );
    }

    Ok(Value::Object(out))
}

/// Go `AppendAssistantFunctionCalls` inline loop (to_oai_responses_req.go:
/// 163-182, 190-209, 255-274): assistant messages emit one `function_call`
/// input item per parseable tool call, skipping empty ids, non-function
/// types, and empty names.
fn append_assistant_function_calls(input_items: &mut Vec<Value>, message: &ChatMessage) {
    for tool_call in message.parse_tool_calls() {
        if tool_call.id.trim().is_empty() {
            continue;
        }
        if !tool_call.kind.is_empty() && tool_call.kind != "function" {
            continue;
        }
        let name = tool_call.function_name.trim();
        if name.is_empty() {
            continue;
        }
        input_items.push(serde_json::json!({
            "type": "function_call",
            "call_id": tool_call.id,
            "name": name,
            "arguments": tool_call.function_arguments,
        }));
    }
}

/// Go tool_choice branch (to_oai_responses_req.go:316-351): strings pass
/// through; `{type: "function"}` objects flatten to `{type, name}` when a
/// name is reachable (top-level `name` or `function.name`); everything else
/// passes through unchanged.
fn convert_tool_choice(tool_choice: &Value) -> Value {
    match tool_choice {
        Value::String(_) => tool_choice.clone(),
        Value::Object(map) if map.get("type").and_then(Value::as_str) == Some("function") => {
            if let Some(name) = map
                .get("name")
                .and_then(Value::as_str)
                .filter(|n| !n.is_empty())
            {
                serde_json::json!({"type": "function", "name": name})
            } else if let Some(function) = map.get("function").and_then(Value::as_object) {
                if let Some(name) = function
                    .get("name")
                    .and_then(Value::as_str)
                    .filter(|n| !n.is_empty())
                {
                    serde_json::json!({"type": "function", "name": name})
                } else {
                    tool_choice.clone()
                }
            } else {
                tool_choice.clone()
            }
        }
        _ => tool_choice.clone(),
    }
}

/// Go `fmt.Sprintf("%v", value)` fallback for non-string tool outputs.
fn json_display(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Go `(*GeneralOpenAIRequest).MarshalJSON` (openai_request.go:156-161):
/// `thinking_budget` is dropped unless the model is a Qwen thinking-budget
/// model. The Rust port applies the same guard to any converted responses
/// request before it is marshaled for the wire.
pub fn apply_qwen_thinking_budget_guard(request: &mut Value) {
    let Some(map) = request.as_object_mut() else {
        return;
    };
    let model = map.get("model").and_then(Value::as_str).unwrap_or("");
    if !dto::is_qwen_thinking_budget_model(model) {
        map.remove("thinking_budget");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Go to_oai_responses_req_test.go:15-40.
    #[test]
    fn instructions_tools_and_tool_round_trip() {
        let request = json!({
            "model": "gpt-test",
            "n": 1,
            "messages": [
                {"role": "system", "content": "system rules"},
                {"role": "developer", "content": "developer rules"},
                {"role": "user", "content": [
                    {"type": "text", "text": "look"},
                    {"type": "image_url", "image_url": {"url": "https://example.test/a.png"}},
                ]},
                {
                    "role": "assistant",
                    "content": "partial text",
                    "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "lookup", "arguments": "{\"q\":\"x\"}"}}],
                },
                {"role": "tool", "tool_call_id": "call_1", "content": "tool result"},
            ],
        });

        let got = chat_completions_request_to_responses_request(&request).expect("convert");
        assert_eq!(got["model"], json!("gpt-test"));
        assert_eq!(
            got["instructions"],
            json!("system rules\n\ndeveloper rules")
        );
        let input = got["input"].as_array().expect("input array");
        assert_eq!(input[0]["content"][1]["type"], json!("input_image"));
        assert_eq!(input[2]["type"], json!("function_call"));
        assert_eq!(input[2]["call_id"], json!("call_1"));
        assert_eq!(input[3]["type"], json!("function_call_output"));
    }

    // Go to_oai_responses_req_test.go:42-76.
    #[test]
    fn qwen_thinking_budget_preserved_with_guard() {
        for (budget, want) in [(json!(128), 128i64), (json!(0), 0i64)] {
            let request = json!({
                "model": "qwen-plus",
                "enable_thinking": true,
                "thinking_budget": budget,
                "messages": [{"role": "user", "content": "hello"}],
            });
            let mut got = chat_completions_request_to_responses_request(&request).expect("convert");
            assert_eq!(got["thinking_budget"], budget);
            apply_qwen_thinking_budget_guard(&mut got);
            assert_eq!(got["enable_thinking"], json!(true));
            let value = got["thinking_budget"]
                .as_i64()
                .expect("thinking_budget int");
            assert_eq!(value, want);
        }
    }

    /// Guard on a non-Qwen model must drop the budget (Go MarshalJSON).
    #[test]
    fn qwen_thinking_budget_dropped_for_non_qwen_model() {
        let request = json!({
            "model": "gpt-test",
            "thinking_budget": 128,
            "messages": [{"role": "user", "content": "hello"}],
        });
        let mut got = chat_completions_request_to_responses_request(&request).expect("convert");
        apply_qwen_thinking_budget_guard(&mut got);
        assert!(got.get("thinking_budget").is_none());
    }

    // Go to_oai_responses_req_test.go:78-85.
    #[test]
    fn rejects_multiple_choices() {
        let err = chat_completions_request_to_responses_request(&json!({
            "model": "gpt-test",
            "n": 2,
        }))
        .expect_err("n>1 must fail");
        assert!(err.0.contains("n>1"));
    }

    // Go to_oai_responses_req_test.go:87-130.
    #[test]
    fn preserves_penalties() {
        let got = chat_completions_request_to_responses_request(&json!({
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "hello"}],
            "frequency_penalty": 0.5,
            "presence_penalty": 1.5,
        }))
        .expect("convert");
        assert_eq!(got["frequency_penalty"], json!(0.5));
        assert_eq!(got["presence_penalty"], json!(1.5));

        let got = chat_completions_request_to_responses_request(&json!({
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "hello"}],
            "frequency_penalty": 0.0,
            "presence_penalty": 0.0,
        }))
        .expect("convert");
        assert_eq!(got["frequency_penalty"], json!(0.0));
        assert_eq!(got["presence_penalty"], json!(0.0));

        let got = chat_completions_request_to_responses_request(&json!({
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "hello"}],
        }))
        .expect("convert");
        assert!(got.get("frequency_penalty").is_none());
        assert!(got.get("presence_penalty").is_none());
    }

    // Golden fixture request/openai_to_openai_responses.golden.json.
    #[test]
    fn golden_openai_to_openai_responses() {
        let request = json!({
            "model": "gpt-test",
            "max_tokens": 1024,
            "stream": true,
            "messages": [
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": [
                    {"type": "text", "text": "What is in this image?"},
                    {"type": "image_url", "image_url": {"url": "https://example.com/cat.png", "detail": "high"}},
                ]},
                {"role": "assistant", "tool_calls": [{"id": "call_abc", "type": "function", "function": {"name": "get_weather", "arguments": "{\"city\":\"Paris\"}"}}]},
                {"role": "tool", "tool_call_id": "call_abc", "content": "15 degrees"},
                {"role": "user", "content": "Summarize."},
            ],
            "tools": [{"type": "function", "function": {"name": "get_weather", "description": "Get weather by city", "parameters": {"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]}}}],
            "tool_choice": "auto",
        });

        let got = chat_completions_request_to_responses_request(&request).expect("convert");
        assert_eq!(
            got,
            json!({
                "model": "gpt-test",
                "input": [
                    {"role": "user", "content": [
                        {"type": "input_text", "text": "What is in this image?"},
                        {"type": "input_image", "image_url": "https://example.com/cat.png"},
                    ]},
                    {"role": "assistant", "content": ""},
                    {"type": "function_call", "call_id": "call_abc", "name": "get_weather", "arguments": "{\"city\":\"Paris\"}"},
                    {"type": "function_call_output", "call_id": "call_abc", "output": "15 degrees"},
                    {"role": "user", "content": "Summarize."},
                ],
                "instructions": "You are a helpful assistant.",
                "max_output_tokens": 1024,
                "stream": true,
                "tool_choice": "auto",
                "tools": [
                    {"type": "function", "name": "get_weather", "description": "Get weather by city", "parameters": {"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]}},
                ],
            })
        );
    }

    /// Assistant tool-call emission skips empty ids, non-function types, and
    /// empty names (Go inline loop conditions).
    #[test]
    fn assistant_function_call_filtering() {
        let request = json!({
            "model": "gpt-test",
            "messages": [
                {"role": "assistant", "tool_calls": [
                    {"id": "  ", "type": "function", "function": {"name": "a", "arguments": "{}"}},
                    {"id": "call_2", "type": "custom", "function": {"name": "b", "arguments": "{}"}},
                    {"id": "call_3", "type": "function", "function": {"name": "  ", "arguments": "{}"}},
                    {"id": "call_4", "type": "function", "function": {"name": "ok", "arguments": "{\"x\":1}"}},
                ]},
            ],
        });
        let got = chat_completions_request_to_responses_request(&request).expect("convert");
        let input = got["input"].as_array().expect("array");
        // Only the message item plus the one valid function_call survive.
        assert_eq!(input.len(), 2);
        assert_eq!(input[0]["role"], json!("assistant"));
        assert_eq!(input[1]["type"], json!("function_call"));
        assert_eq!(input[1]["name"], json!("ok"));
    }

    /// Tool messages without call_id become user text with the marker prefix
    /// (Go to_oai_responses_req.go:112-118).
    #[test]
    fn tool_output_missing_call_id_marker() {
        let request = json!({
            "model": "gpt-test",
            "messages": [
                {"role": "tool", "tool_call_id": "", "content": "orphan result"},
            ],
        });
        let got = chat_completions_request_to_responses_request(&request).expect("convert");
        let input = got["input"].as_array().expect("array");
        assert_eq!(input[0]["role"], json!("user"));
        assert_eq!(
            input[0]["content"],
            json!("[tool_output_missing_call_id] orphan result")
        );
    }

    /// Tool choice flattening: {type:function, function:{name}} → {type:function, name}
    /// (Go to_oai_responses_req.go:327-349).
    #[test]
    fn tool_choice_function_flattening() {
        let request = json!({
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "hi"}],
            "tool_choice": {"type": "function", "function": {"name": "lookup"}},
        });
        let got = chat_completions_request_to_responses_request(&request).expect("convert");
        assert_eq!(
            got["tool_choice"],
            json!({"type": "function", "name": "lookup"})
        );

        let request = json!({
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "hi"}],
            "tool_choice": {"type": "function", "name": "direct"},
        });
        let got = chat_completions_request_to_responses_request(&request).expect("convert");
        assert_eq!(
            got["tool_choice"],
            json!({"type": "function", "name": "direct"})
        );

        let request = json!({
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "hi"}],
            "tool_choice": {"type": "web_search_preview"},
        });
        let got = chat_completions_request_to_responses_request(&request).expect("convert");
        assert_eq!(got["tool_choice"], json!({"type": "web_search_preview"}));
    }

    /// reasoning_effort → reasoning{effort, summary: detailed}
    /// (Go to_oai_responses_req.go:406-411).
    #[test]
    fn reasoning_effort_maps_to_reasoning_object() {
        let request = json!({
            "model": "gpt-test",
            "reasoning_effort": "high",
            "messages": [{"role": "user", "content": "hi"}],
        });
        let got = chat_completions_request_to_responses_request(&request).expect("convert");
        assert_eq!(
            got["reasoning"],
            json!({"effort": "high", "summary": "detailed"})
        );
    }

    /// Response format conversion incl. json_schema flattening
    /// (Go to_oai_responses_req.go:38-74).
    #[test]
    fn response_format_json_schema_flattening() {
        let request = json!({
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "hi"}],
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "out",
                    "strict": true,
                    "schema": {"type": "object"},
                },
            },
        });
        let got = chat_completions_request_to_responses_request(&request).expect("convert");
        assert_eq!(
            got["text"],
            json!({"format": {"type": "json_schema", "name": "out", "strict": true, "schema": {"type": "object"}}})
        );

        let request = json!({
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "hi"}],
            "response_format": {"type": "json_object"},
        });
        let got = chat_completions_request_to_responses_request(&request).expect("convert");
        assert_eq!(got["text"], json!({"format": {"type": "json_object"}}));

        let request = json!({
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "hi"}],
        });
        let got = chat_completions_request_to_responses_request(&request).expect("convert");
        assert!(got.get("text").is_none());
    }

    /// Go entry guards: nil request / empty model (to_oai_responses_req.go:
    /// 77-82).
    #[test]
    fn entry_guards() {
        assert_eq!(
            chat_completions_request_to_responses_request(&Value::Null)
                .unwrap_err()
                .0,
            "request is nil"
        );
        assert_eq!(
            chat_completions_request_to_responses_request(&json!({"messages": []}))
                .unwrap_err()
                .0,
            "model is required"
        );
    }
}
