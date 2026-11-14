//! Typed accessors over the chat-completions wire shape. The Go oracle works
//! on `dto.GeneralOpenAIRequest` / `dto.Message` / `dto.MediaContent`
//! (relaykit/dto/openai_request.go); the Rust conversion layer operates on
//! `serde_json::Value` with these helpers so converted output keeps the exact
//! wire field sets and the omitempty semantics.

use serde_json::Value;

pub mod content_type {
    /// Go dto ContentType* constants (openai_request.go:452-457).
    pub const TEXT: &str = "text";
    pub const IMAGE_URL: &str = "image_url";
    pub const INPUT_AUDIO: &str = "input_audio";
    pub const FILE: &str = "file";
    pub const VIDEO_URL: &str = "video_url";
}

/// A media content part (Go `dto.MediaContent`, openai_request.go:316-330).
/// `image_url` / `input_audio` / `file` / `video_url` keep their raw JSON so
/// unknown upstream shapes survive a parse→convert→marshal round trip.
#[derive(Clone, Debug, PartialEq)]
pub struct MediaContent {
    pub kind: String,
    pub text: String,
    pub image_url: Option<Value>,
    pub input_audio: Option<Value>,
    pub file: Option<Value>,
    pub video_url: Option<Value>,
}

impl MediaContent {
    /// Go `(*MessageImageUrl)` extraction via `GetImageMedia` — the url string
    /// normalized out of either a bare string or `{url, detail}` object.
    pub fn image_url_string(&self) -> Option<String> {
        let raw = self.image_url.as_ref()?;
        match raw {
            Value::String(s) => Some(s.clone()),
            Value::Object(map) => map.get("url").and_then(Value::as_str).map(str::to_owned),
            _ => None,
        }
    }

    /// Go `(*MediaContent).GetImageMedia` detail field (parse-time default
    /// "high" is applied by `parse_content`, not here).
    pub fn image_detail(&self) -> Option<String> {
        match self.image_url.as_ref()? {
            Value::Object(map) => map.get("detail").and_then(Value::as_str).map(str::to_owned),
            _ => None,
        }
    }
}

/// A parsed tool call (Go `dto.ToolCallRequest`, openai_request.go:255-267).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ToolCall {
    pub id: String,
    pub kind: String,
    pub function_name: String,
    pub function_arguments: String,
}

/// A parsed chat message (Go `dto.Message`, openai_request.go:303-313).
/// `content` keeps the raw JSON so string/array distinction is preserved.
#[derive(Clone, Debug, Default)]
pub struct ChatMessage {
    pub role: String,
    pub content: Option<Value>,
    pub name: Option<String>,
    pub tool_calls: Option<Value>,
    pub tool_call_id: String,
}

impl ChatMessage {
    /// Go `(*Message).IsStringContent` — exactly a JSON string.
    pub fn is_string_content(&self) -> bool {
        matches!(self.content, Some(Value::String(_)))
    }

    /// Go `(*Message).StringContent`: string → itself; array → concatenated
    /// `text` fields of the `type == "text"` items; anything else → "".
    pub fn string_content(&self) -> String {
        match self.content.as_ref() {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Array(items)) => {
                let mut out = String::new();
                for item in items {
                    let Some(map) = item.as_object() else {
                        continue;
                    };
                    if map.get("type").and_then(Value::as_str) != Some(content_type::TEXT) {
                        continue;
                    }
                    if let Some(text) = map.get("text").and_then(Value::as_str) {
                        out.push_str(text);
                    }
                }
                out
            }
            _ => String::new(),
        }
    }

    /// Go `(*Message).ParseContent` (openai_request.go:573-701). String content
    /// becomes a single text part; array items are interpreted per their
    /// `type` field, mirroring the Go per-type extraction rules including the
    /// image detail "high" default and the file field spellings.
    pub fn parse_content(&self) -> Vec<MediaContent> {
        let Some(content) = self.content.as_ref() else {
            return Vec::new();
        };
        match content {
            Value::String(s) => vec![MediaContent {
                kind: content_type::TEXT.to_owned(),
                text: s.clone(),
                image_url: None,
                input_audio: None,
                file: None,
                video_url: None,
            }],
            Value::Array(items) => {
                let mut out = Vec::new();
                for item in items {
                    let Some(map) = item.as_object() else {
                        continue;
                    };
                    let Some(kind) = map.get("type").and_then(Value::as_str) else {
                        continue;
                    };
                    match kind {
                        content_type::TEXT => {
                            if let Some(text) = map.get("text").and_then(Value::as_str) {
                                out.push(MediaContent {
                                    kind: content_type::TEXT.to_owned(),
                                    text: text.to_owned(),
                                    image_url: None,
                                    input_audio: None,
                                    file: None,
                                    video_url: None,
                                });
                            }
                        }
                        content_type::IMAGE_URL => {
                            // Go builds MessageImageUrl{Detail: "high"} then
                            // overlays url/detail from string or object.
                            let mut url = String::new();
                            let mut detail = "high".to_owned();
                            match map.get("image_url") {
                                Some(Value::String(s)) => url = s.clone(),
                                Some(Value::Object(image)) => {
                                    if let Some(d) = image.get("detail").and_then(Value::as_str) {
                                        detail = d.to_owned();
                                    }
                                    if let Some(u) = image.get("url").and_then(Value::as_str) {
                                        url = u.to_owned();
                                    }
                                }
                                _ => {}
                            }
                            out.push(MediaContent {
                                kind: content_type::IMAGE_URL.to_owned(),
                                text: String::new(),
                                image_url: Some(serde_json::json!({"url": url, "detail": detail})),
                                input_audio: None,
                                file: None,
                                video_url: None,
                            });
                        }
                        content_type::INPUT_AUDIO => {
                            if let Some(Value::Object(audio)) = map.get("input_audio")
                                && let (Some(data), Some(format)) = (
                                    audio.get("data").and_then(Value::as_str),
                                    audio.get("format").and_then(Value::as_str),
                                )
                            {
                                out.push(MediaContent {
                                    kind: content_type::INPUT_AUDIO.to_owned(),
                                    text: String::new(),
                                    image_url: None,
                                    input_audio: Some(serde_json::json!({
                                        "data": data,
                                        "format": format,
                                    })),
                                    file: None,
                                    video_url: None,
                                });
                            }
                        }
                        content_type::FILE => {
                            if let Some(Value::Object(file)) = map.get("file") {
                                if let Some(file_id) = file.get("file_id").and_then(Value::as_str) {
                                    out.push(MediaContent {
                                        kind: content_type::FILE.to_owned(),
                                        text: String::new(),
                                        image_url: None,
                                        input_audio: None,
                                        file: Some(serde_json::json!({"file_id": file_id})),
                                        video_url: None,
                                    });
                                } else if let (Some(file_name), Some(file_data)) = (
                                    file.get("filename").and_then(Value::as_str),
                                    file.get("file_data").and_then(Value::as_str),
                                ) {
                                    out.push(MediaContent {
                                        kind: content_type::FILE.to_owned(),
                                        text: String::new(),
                                        image_url: None,
                                        input_audio: None,
                                        file: Some(serde_json::json!({
                                            "filename": file_name,
                                            "file_data": file_data,
                                        })),
                                        video_url: None,
                                    });
                                }
                            }
                        }
                        content_type::VIDEO_URL => {
                            if let Some(url) = map.get("video_url").and_then(Value::as_str) {
                                out.push(MediaContent {
                                    kind: content_type::VIDEO_URL.to_owned(),
                                    text: String::new(),
                                    image_url: None,
                                    input_audio: None,
                                    file: None,
                                    video_url: Some(serde_json::json!({"url": url})),
                                });
                            }
                        }
                        _ => {}
                    }
                }
                out
            }
            _ => Vec::new(),
        }
    }

    /// Go `(*Message).ParseToolCalls` — a raw array decode; malformed arrays
    /// yield an empty result (errors swallowed, matching Go).
    pub fn parse_tool_calls(&self) -> Vec<ToolCall> {
        let Some(Value::Array(items)) = self.tool_calls.as_ref() else {
            return Vec::new();
        };
        items
            .iter()
            .filter_map(|item| {
                let map = item.as_object()?;
                Some(ToolCall {
                    id: map
                        .get("id")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    kind: map
                        .get("type")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    function_name: map
                        .get("function")
                        .and_then(|f| f.get("name"))
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    function_arguments: map
                        .get("function")
                        .and_then(|f| f.get("arguments"))
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                })
            })
            .collect()
    }

    /// Go `(*Message).SetToolCalls` marshal round trip.
    pub fn set_tool_calls(&mut self, calls: Vec<ToolCall>) {
        self.tool_calls = Some(
            serde_json::to_value(
                calls
                    .iter()
                    .map(|call| {
                        serde_json::json!({
                            "id": call.id,
                            "type": call.kind,
                            "function": {
                                "name": call.function_name,
                                "arguments": call.function_arguments,
                            },
                        })
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap_or(Value::Array(Vec::new())),
        );
    }

    /// Go `(*Message).SetStringContent`.
    pub fn set_string_content(&mut self, content: &str) {
        self.content = Some(Value::String(content.to_owned()));
    }
}

/// Parse a wire message object into [`ChatMessage`], preserving the raw
/// content JSON (Go unmarshals into `dto.Message` whose Content is `any`).
pub fn parse_chat_message(raw: &Value) -> ChatMessage {
    let Some(map) = raw.as_object() else {
        return ChatMessage::default();
    };
    ChatMessage {
        role: map
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        content: map.get("content").cloned(),
        name: map.get("name").and_then(Value::as_str).map(str::to_owned),
        tool_calls: map.get("tool_calls").cloned(),
        tool_call_id: map
            .get("tool_call_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
    }
}

/// Go `IsQwenThinkingBudgetModel` (openai_request.go:234-240).
pub fn is_qwen_thinking_budget_model(model_name: &str) -> bool {
    let normalized = model_name.trim().to_lowercase();
    normalized.starts_with("qwen")
        || normalized.contains("/qwen")
        || normalized.starts_with("qwq")
        || normalized.contains("/qwq")
}

/// Go `IsOpenAIReasoningOModel` (openai_request.go:225-229): o1/o3/o4 prefixes.
pub fn is_openai_reasoning_o_model(model_name: &str) -> bool {
    model_name.starts_with("o1") || model_name.starts_with("o3") || model_name.starts_with("o4")
}

/// Go `IsOpenAIGPT5Model` (openai_request.go:230-232).
pub fn is_openai_gpt5_model(model_name: &str) -> bool {
    model_name.starts_with("gpt-5")
}

/// Go `(*GeneralOpenAIRequest).GetSystemRoleName` (openai_request.go:242-251).
pub fn get_system_role_name(model_name: &str) -> &str {
    if is_openai_reasoning_o_model(model_name) {
        if !model_name.starts_with("o1-mini") && !model_name.starts_with("o1-preview") {
            return "developer";
        }
    } else if is_openai_gpt5_model(model_name) {
        return "developer";
    }
    "system"
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Go openai_request.go:234-240.
    #[test]
    fn qwen_thinking_budget_detection() {
        assert!(is_qwen_thinking_budget_model("qwen-plus"));
        assert!(is_qwen_thinking_budget_model("QWEN2.5"));
        assert!(is_qwen_thinking_budget_model("dashscope/qwen3-max"));
        assert!(is_qwen_thinking_budget_model(" qwq-32b "));
        assert!(is_qwen_thinking_budget_model(
            "deepseek-ai/DeepSeek-R1/qwen"
        ));
        assert!(!is_qwen_thinking_budget_model("gpt-5"));
        assert!(!is_qwen_thinking_budget_model("qwq"));
    }

    /// Go openai_request.go:242-251.
    #[test]
    fn system_role_name_table() {
        assert_eq!(get_system_role_name("gpt-4o"), "system");
        assert_eq!(get_system_role_name("gpt-5"), "developer");
        assert_eq!(get_system_role_name("o3-mini"), "developer");
        assert_eq!(get_system_role_name("o1-mini"), "system");
        assert_eq!(get_system_role_name("o1-preview"), "system");
        assert_eq!(get_system_role_name("o1"), "developer");
        assert_eq!(get_system_role_name("claude-3"), "system");
    }

    /// Go `(*Message).StringContent` array branch (openai_request.go:373-392).
    #[test]
    fn string_content_concatenates_text_parts() {
        let message = ChatMessage {
            role: "user".into(),
            content: Some(serde_json::json!([
                {"type": "text", "text": "hello "},
                {"type": "image_url", "image_url": {"url": "https://x/y.png"}},
                {"type": "text", "text": "world"},
            ])),
            ..Default::default()
        };
        assert_eq!(message.string_content(), "hello world");
        assert!(!message.is_string_content());

        let plain = ChatMessage {
            role: "user".into(),
            content: Some(Value::String("plain".into())),
            ..Default::default()
        };
        assert_eq!(plain.string_content(), "plain");
        assert!(plain.is_string_content());

        let empty = ChatMessage::default();
        assert_eq!(empty.string_content(), "");
    }

    /// Go `(*Message).ParseContent` image branch: detail defaults to "high",
    /// object form wins over string form.
    #[test]
    fn parse_content_image_url_shapes() {
        let string_form = ChatMessage {
            content: Some(serde_json::json!([
                {"type": "image_url", "image_url": "https://x/y.png"}
            ])),
            ..Default::default()
        };
        let parts = string_form.parse_content();
        assert_eq!(parts.len(), 1);
        assert_eq!(
            parts[0].image_url_string().as_deref(),
            Some("https://x/y.png")
        );
        assert_eq!(parts[0].image_detail().as_deref(), Some("high"));

        let object_form = ChatMessage {
            content: Some(serde_json::json!([
                {"type": "image_url", "image_url": {"url": "https://x/z.png", "detail": "low"}}
            ])),
            ..Default::default()
        };
        let parts = object_form.parse_content();
        assert_eq!(parts[0].image_detail().as_deref(), Some("low"));
    }

    /// Go `(*Message).ParseContent` audio/file branches keep field spellings.
    #[test]
    fn parse_content_audio_and_file() {
        let message = ChatMessage {
            content: Some(serde_json::json!([
                {"type": "input_audio", "input_audio": {"data": "QUJD", "format": "wav"}},
                {"type": "file", "file": {"file_id": "file-1"}},
                {"type": "file", "file": {"filename": "a.pdf", "file_data": "base64"}},
                {"type": "video_url", "video_url": "https://x/v.mp4"},
                {"type": "unknown_kind"},
            ])),
            ..Default::default()
        };
        let parts = message.parse_content();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0].kind, "input_audio");
        assert_eq!(
            parts[0].input_audio,
            Some(serde_json::json!({"data": "QUJD", "format": "wav"}))
        );
        assert_eq!(
            parts[1].file,
            Some(serde_json::json!({"file_id": "file-1"}))
        );
        assert_eq!(
            parts[2].file,
            Some(serde_json::json!({"filename": "a.pdf", "file_data": "base64"}))
        );
        assert_eq!(
            parts[3].video_url,
            Some(serde_json::json!({"url": "https://x/v.mp4"}))
        );
    }

    /// Go `(*Message).ParseToolCalls`: non-array / malformed → empty.
    #[test]
    fn parse_tool_calls_array_only() {
        let mut message = ChatMessage::default();
        assert!(message.parse_tool_calls().is_empty());
        message.set_tool_calls(vec![ToolCall {
            id: "call_1".into(),
            kind: "function".into(),
            function_name: "lookup".into(),
            function_arguments: "{\"q\":1}".into(),
        }]);
        let calls = message.parse_tool_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].function_name, "lookup");
    }
}
