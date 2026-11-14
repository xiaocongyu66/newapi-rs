//! Token-count metadata builders. Port of the upstream Go
//! `(*GeneralOpenAIRequest).GetTokenCountMeta` and
//! `(*OpenAIResponsesRequest).GetTokenCountMeta` (relaykit/dto/
//! openai_request.go:119-202 and 907-964) plus `ParseInput`
//! (openai_request.go:284-301 / 1010-1097). These feed
//! `token_count::estimate_request_token` and the sensitive-word sanitizer.

use serde_json::Value;

use super::count_tokens::FileMeta;
use super::dto::{ChatMessage, content_type, parse_chat_message};
use super::tokenize_text;

/// Go `types.TokenCountMeta` projection (request_meta.go:20-32).
#[derive(Clone, Debug, Default)]
pub struct CountMeta {
    pub token_type: String,
    pub combine_text: String,
    pub tools_count: i64,
    pub name_count: i64,
    pub messages_count: i64,
    pub files: Vec<FileMeta>,
    pub max_tokens: i64,
}

/// Go `types.TokenType` constants (request_meta.go:15-17).
pub mod token_kind {
    pub const TEXT_NUMBER: &str = "text_number";
    pub const TOKENIZER: &str = "tokenizer";
    pub const IMAGE: &str = "image";
}

/// Go `(*GeneralOpenAIRequest).ParseInput` (openai_request.go:284-301):
/// string → one entry; array → the string items.
pub fn parse_chat_input(request: &Value) -> Vec<String> {
    let Some(input) = request.get("input") else {
        return Vec::new();
    };
    match input {
        Value::String(s) => vec![s.clone()],
        Value::Array(items) => items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

/// Go `(*GeneralOpenAIRequest).GetTokenCountMeta` (openai_request.go:119-202).
pub fn chat_request_token_count_meta(request: &Value) -> CountMeta {
    let mut meta = CountMeta::default();
    let mut texts: Vec<String> = Vec::new();
    let mut files: Vec<FileMeta> = Vec::new();

    if let Some(prompt) = request.get("prompt").filter(|v| !v.is_null()) {
        match prompt {
            Value::String(s) => texts.push(s.clone()),
            Value::Array(items) => {
                for item in items {
                    if let Some(s) = item.as_str() {
                        texts.push(s.to_owned());
                    }
                }
            }
            other => texts.push(display_go_value(other)),
        }
    }

    if request.get("input").is_some_and(|v| !v.is_null()) {
        texts.extend(parse_chat_input(request));
    }

    let max_tokens = request
        .get("max_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let max_completion_tokens = request
        .get("max_completion_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    meta.max_tokens = max_completion_tokens.max(max_tokens) as i64;

    if let Some(messages) = request.get("messages").and_then(Value::as_array) {
        for raw in messages {
            meta.messages_count += 1;
            let message = parse_chat_message(raw);
            texts.push(message.role.clone());
            if message.content.is_some() {
                if let Some(name) = message.name.as_deref() {
                    meta.name_count += 1;
                    texts.push(name.to_owned());
                }
                for part in message.parse_content() {
                    let source = media_content_file_source(&part);
                    if let Some((data, is_url)) = source {
                        let mut file = FileMeta {
                            source: Some(data),
                            source_is_url: is_url,
                            ..Default::default()
                        };
                        match part.kind.as_str() {
                            content_type::IMAGE_URL => {
                                file.file_type = super::count_tokens::file_type::IMAGE.to_owned();
                                if let Some(detail) = part.image_detail() {
                                    file.detail = detail;
                                }
                            }
                            content_type::INPUT_AUDIO => {
                                file.file_type = super::count_tokens::file_type::AUDIO.to_owned();
                            }
                            content_type::FILE => {
                                file.file_type = super::count_tokens::file_type::FILE.to_owned();
                            }
                            content_type::VIDEO_URL => {
                                file.file_type = super::count_tokens::file_type::VIDEO.to_owned();
                            }
                            _ => {}
                        }
                        files.push(file);
                    } else if part.kind == content_type::TEXT {
                        texts.push(part.text.clone());
                    }
                }
            }
        }
    }

    if let Some(tools) = request.get("tools").and_then(Value::as_array) {
        for tool in tools {
            meta.tools_count += 1;
            let function = tool.get("function");
            if let Some(name) = function.and_then(|f| f.get("name")).and_then(Value::as_str) {
                texts.push(name.to_owned());
            }
            if let Some(description) = function
                .and_then(|f| f.get("description"))
                .and_then(Value::as_str)
                && !description.is_empty()
            {
                texts.push(description.to_owned());
            }
            if let Some(parameters) = function
                .and_then(|f| f.get("parameters"))
                .filter(|v| !v.is_null())
            {
                texts.push(display_go_value(parameters));
            }
        }
    }

    meta.combine_text = texts.join("\n");
    meta.files = files;
    meta
}

/// Go `(*OpenAIResponsesRequest).ParseInput` (openai_request.go:1010-1097):
/// string input → one input_text; array input → per-item extraction of
/// input_text / input_image / input_file.
pub fn parse_responses_input(request: &Value) -> Vec<MediaInput> {
    let Some(input) = request.get("input").filter(|v| !v.is_null()) else {
        return Vec::new();
    };
    if get_json_type(input) == "string" {
        return vec![MediaInput {
            kind: "input_text".to_owned(),
            text: input.as_str().unwrap_or_default().to_owned(),
            file_url: String::new(),
            image_url: String::new(),
            detail: String::new(),
        }];
    }
    if get_json_type(input) != "array" {
        return Vec::new();
    }
    let mut out = Vec::new();
    let Some(inputs) = input.as_array() else {
        return out;
    };
    for input_item in inputs {
        // Input objects carry an optional content field.
        let Some(content) = input_item.get("content") else {
            continue;
        };
        match get_json_type(content) {
            "string" => out.push(MediaInput {
                kind: "input_text".to_owned(),
                text: content.as_str().unwrap_or_default().to_owned(),
                file_url: String::new(),
                image_url: String::new(),
                detail: String::new(),
            }),
            "array" => {
                let Some(items) = content.as_array() else {
                    continue;
                };
                for item in items {
                    let Some(map) = item.as_object() else {
                        continue;
                    };
                    let Some(kind) = map.get("type").and_then(Value::as_str) else {
                        continue;
                    };
                    match kind {
                        "input_text" => out.push(MediaInput {
                            kind: "input_text".to_owned(),
                            text: map
                                .get("text")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_owned(),
                            file_url: String::new(),
                            image_url: String::new(),
                            detail: String::new(),
                        }),
                        "input_image" => {
                            let image_url = match map.get("image_url") {
                                Some(Value::String(s)) => s.clone(),
                                Some(Value::Object(obj)) => obj
                                    .get("url")
                                    .and_then(Value::as_str)
                                    .unwrap_or_default()
                                    .to_owned(),
                                _ => String::new(),
                            };
                            out.push(MediaInput {
                                kind: "input_image".to_owned(),
                                text: String::new(),
                                file_url: String::new(),
                                image_url,
                                detail: map
                                    .get("detail")
                                    .and_then(Value::as_str)
                                    .unwrap_or_default()
                                    .to_owned(),
                            });
                        }
                        "input_file" => {
                            let file_url = match map.get("file_url") {
                                Some(Value::String(s)) => s.clone(),
                                Some(Value::Object(obj)) => obj
                                    .get("url")
                                    .and_then(Value::as_str)
                                    .unwrap_or_default()
                                    .to_owned(),
                                _ => String::new(),
                            };
                            out.push(MediaInput {
                                kind: "input_file".to_owned(),
                                text: String::new(),
                                file_url,
                                image_url: String::new(),
                                detail: String::new(),
                            });
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// Go `MediaInput` (openai_request.go:997-1003).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct MediaInput {
    pub kind: String,
    pub text: String,
    pub file_url: String,
    pub image_url: String,
    pub detail: String,
}

/// Go `(*OpenAIResponsesRequest).GetTokenCountMeta` (openai_request.go:907-964).
pub fn responses_request_token_count_meta(request: &Value) -> CountMeta {
    let mut files: Vec<FileMeta> = Vec::new();
    let mut texts: Vec<String> = Vec::new();

    if request.get("input").is_some_and(|v| !v.is_null()) {
        for input in parse_responses_input(request) {
            if input.kind == "input_image" {
                if !input.image_url.is_empty() {
                    files.push(FileMeta {
                        file_type: super::count_tokens::file_type::IMAGE.to_owned(),
                        source: Some(input.image_url.clone()),
                        source_is_url: is_url_source(&input.image_url),
                        detail: input.detail.clone(),
                        ..Default::default()
                    });
                }
            } else if input.kind == "input_file" && !input.file_url.is_empty() {
                files.push(FileMeta {
                    file_type: super::count_tokens::file_type::FILE.to_owned(),
                    source: Some(input.file_url.clone()),
                    source_is_url: is_url_source(&input.file_url),
                    ..Default::default()
                });
            } else {
                texts.push(input.text);
            }
        }
    }

    for field in [
        "instructions",
        "metadata",
        "text",
        "tool_choice",
        "prompt",
        "tools",
    ] {
        if let Some(raw) = request.get(field).filter(|v| !v.is_null())
            && !raw.is_null()
        {
            // Go checks len(raw) > 0 on json.RawMessage; a non-null JSON value
            // always has bytes.
            texts.push(raw.to_string());
        }
    }

    CountMeta {
        combine_text: texts.join("\n"),
        files,
        max_tokens: request
            .get("max_output_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0) as i64,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------

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

fn is_url_source(data: &str) -> bool {
    data.starts_with("http://") || data.starts_with("https://")
}

/// Go `(*MediaContent).ToFileSource` (openai_request.go:391-424): returns
/// (data, is_url) or None when the part carries no usable media. The Go
/// audio branch derives `audio/<format>` as the mime hint for
/// `NewFileSourceFromData`; that hint is consumed by the host file loader,
/// not by token counting, so the Rust port drops it.
fn media_content_file_source(part: &super::dto::MediaContent) -> Option<(String, bool)> {
    match part.kind.as_str() {
        content_type::IMAGE_URL => {
            let url = part.image_url_string()?;
            if url.is_empty() {
                return None;
            }
            Some((url, is_url_source(&url)))
        }
        content_type::INPUT_AUDIO => {
            let Some(Value::Object(audio)) = part.input_audio.as_ref() else {
                return None;
            };
            let data = audio.get("data").and_then(Value::as_str).unwrap_or("");
            if data.is_empty() {
                return None;
            }
            Some((data.to_owned(), is_url_source(data)))
        }
        content_type::FILE => {
            let Some(Value::Object(file)) = part.file.as_ref() else {
                return None;
            };
            let data = file.get("file_data").and_then(Value::as_str).unwrap_or("");
            if data.is_empty() {
                return None;
            }
            Some((data.to_owned(), is_url_source(data)))
        }
        content_type::VIDEO_URL => {
            let Some(Value::Object(video)) = part.video_url.as_ref() else {
                return None;
            };
            let url = video.get("url").and_then(Value::as_str).unwrap_or("");
            if url.is_empty() {
                return None;
            }
            Some((url.to_owned(), is_url_source(url)))
        }
        _ => None,
    }
}

/// Go `fmt.Sprintf("%v", value)` over JSON values.
fn display_go_value(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => {
            if *b {
                "true".to_owned()
            } else {
                "false".to_owned()
            }
        }
        Value::Null => "<nil>".to_owned(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Go openai_request.go:119-202 — text/tool/file collection and counts.
    #[test]
    fn chat_request_token_count_meta_shape() {
        let request = json!({
            "model": "gpt-4o",
            "max_tokens": 100,
            "messages": [
                {"role": "system", "content": "rules"},
                {"role": "user", "name": "alice", "content": [
                    {"type": "text", "text": "look"},
                    {"type": "image_url", "image_url": {"url": "https://a.b/x.png", "detail": "low"}},
                ]},
                {"role": "assistant", "content": "hi"},
            ],
            "tools": [{"type": "function", "function": {"name": "lookup", "description": "finds", "parameters": {"type": "object"}}}],
        });
        let meta = chat_request_token_count_meta(&request);
        assert_eq!(meta.messages_count, 3);
        assert_eq!(meta.name_count, 1);
        assert_eq!(meta.tools_count, 1);
        assert_eq!(meta.max_tokens, 100);
        assert_eq!(meta.files.len(), 1);
        assert_eq!(meta.files[0].file_type, "image");
        assert_eq!(meta.files[0].detail, "low");
        assert_eq!(meta.files[0].source.as_deref(), Some("https://a.b/x.png"));
        assert!(meta.files[0].source_is_url);

        // CombineText joins role/name/texts/tool fields with \n in order.
        let expected_parts = [
            "gpt-4o", // no — prompt/input absent; first text is role
        ];
        let _ = expected_parts;
        assert!(meta.combine_text.contains("system"));
        assert!(meta.combine_text.contains("rules"));
        assert!(meta.combine_text.contains("look"));
        assert!(meta.combine_text.contains("lookup"));
        assert!(meta.combine_text.contains("finds"));
        // Tool parameters formatted into the text.
        assert!(meta.combine_text.contains("{\"type\":\"object\"}"));
    }

    /// Go openai_request.go:284-301 — chat ParseInput.
    #[test]
    fn parse_chat_input_shapes() {
        let request = json!({"input": "solo"});
        assert_eq!(parse_chat_input(&request), vec!["solo".to_owned()]);
        let request = json!({"input": ["a", 1, "b"]});
        assert_eq!(
            parse_chat_input(&request),
            vec!["a".to_owned(), "b".to_owned()]
        );
        let request = json!({});
        assert!(parse_chat_input(&request).is_empty());
    }

    /// Go openai_request.go:1010-1097 — responses ParseInput.
    #[test]
    fn parse_responses_input_shapes() {
        let request = json!({"input": "plain"});
        let inputs = parse_responses_input(&request);
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].kind, "input_text");
        assert_eq!(inputs[0].text, "plain");

        let request = json!({"input": [
            {"type": "message", "role": "user", "content": [
                {"type": "input_text", "text": "hi"},
                {"type": "input_image", "image_url": "https://a.b/i.png"},
                {"type": "input_image", "image_url": {"url": "https://a.b/j.png", "detail": "auto"}},
                {"type": "input_file", "file_url": "https://a.b/f.pdf"},
            ]},
            {"type": "message", "role": "user", "content": "string content"},
        ]});
        let inputs = parse_responses_input(&request);
        assert_eq!(inputs.len(), 5);
        assert_eq!(inputs[0].kind, "input_text");
        assert_eq!(inputs[0].text, "hi");
        assert_eq!(inputs[1].image_url, "https://a.b/i.png");
        assert_eq!(inputs[2].image_url, "https://a.b/j.png");
        assert_eq!(inputs[2].detail, "auto");
        assert_eq!(inputs[3].kind, "input_file");
        assert_eq!(inputs[3].file_url, "https://a.b/f.pdf");
        assert_eq!(inputs[4].text, "string content");
    }

    /// Go openai_request.go:907-964 — responses meta collects images/files
    /// and raw-JSON text fields.
    #[test]
    fn responses_request_token_count_meta_shape() {
        let request = json!({
            "model": "gpt-5",
            "instructions": "be nice",
            "input": [
                {"type": "message", "role": "user", "content": [
                    {"type": "input_text", "text": "hi"},
                    {"type": "input_image", "image_url": "https://a.b/i.png", "detail": "high"},
                ]},
            ],
            "tools": [{"type": "function", "name": "lookup"}],
            "max_output_tokens": 256,
        });
        let meta = responses_request_token_count_meta(&request);
        assert_eq!(meta.max_tokens, 256);
        assert_eq!(meta.files.len(), 1);
        assert_eq!(meta.files[0].file_type, "image");
        assert_eq!(meta.files[0].detail, "high");
        assert!(meta.combine_text.contains("hi"));
        assert!(meta.combine_text.contains("be nice"));
        // Raw JSON tools serialized.
        assert!(meta.combine_text.contains("lookup"));
    }

    /// Base64 media (non-URL) sources stay base64 sources
    /// (types.NewFileSourceFromData semantics).
    #[test]
    fn base64_media_sources() {
        let request = json!({
            "model": "gpt-4o",
            "messages": [
                {"role": "user", "content": [
                    {"type": "input_audio", "input_audio": {"data": "QUJD", "format": "wav"}},
                    {"type": "file", "file": {"file_data": "aGVsbG8="}},
                ]},
            ],
        });
        let meta = chat_request_token_count_meta(&request);
        assert_eq!(meta.files.len(), 2);
        assert_eq!(meta.files[0].file_type, "audio");
        assert!(!meta.files[0].source_is_url);
        assert_eq!(meta.files[1].file_type, "file");
        assert!(!meta.files[1].source_is_url);
    }

    /// Estimate-token integration: the chat meta feeds
    /// token_count::estimate_request_token with the OpenAI overhead.
    #[test]
    fn meta_feeds_estimate() {
        use crate::token_count::{CountSwitches, EstimateInputs, LocalFileResolver};
        let request = json!({
            "model": "gpt-5-chat",
            "messages": [{"role": "user", "content": "hello world"}],
        });
        let mut meta = chat_request_token_count_meta(&request);
        let text_tokens = tokenize_text::count_text_token(&meta.combine_text, "gpt-5-chat");
        let inputs = EstimateInputs {
            relay_format: crate::relay_info::relay_format::OPENAI.to_owned(),
            original_model: "gpt-5-chat".into(),
            ..Default::default()
        };
        let got = super::super::count_tokens::estimate_request_token(
            &mut meta_to_count_meta(&meta),
            &inputs,
            CountSwitches::default(),
            &LocalFileResolver,
            None,
        )
        .unwrap();
        // messages_count=1 → +3, plus the constant +3.
        assert_eq!(got, text_tokens + 1 * 3 + 3);
    }

    fn meta_to_count_meta(meta: &CountMeta) -> super::super::count_tokens::TokenCountMeta {
        super::super::count_tokens::TokenCountMeta {
            token_type: meta.token_type.clone(),
            combine_text: meta.combine_text.clone(),
            tools_count: meta.tools_count,
            name_count: meta.name_count,
            messages_count: meta.messages_count,
            files: meta.files.clone(),
            max_tokens: meta.max_tokens,
        }
    }
}
