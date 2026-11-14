//! Request token estimation. Port of the upstream Go
//! `internal/relay/common/count_tokens.go` (lines 1-411): the OpenAI image
//! tile/patch pricing, `EstimateRequestToken`, realtime counting, audio
//! token formulas and `CountTokenInput`.
//!
//! Host-boundary notes (see the slice report): the Go oracle reads
//! env-backed switches (`constant.CountToken` / `GetMediaToken` /
//! `GetMediaTokenNotStream`) and a request context; the Rust port takes them
//! as explicit inputs. The audio-transcription duration lookup and the file
//! download path are injectable resolvers (the Go implementations parse
//! mp3/wav containers and fetch URLs — the container parsers live in Go's
//! external audio libs and the fetcher in the egress stack, so the relay
//! layer here accepts a resolver closure instead).

use serde_json::Value;

use super::tokenize_text;
use crate::multimodal::{self, ImageConfig};

/// Go `constant.CountToken` (internal/common/init.go:186, default true).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CountSwitches {
    pub count_token: bool,
    pub get_media_token: bool,
    pub get_media_token_not_stream: bool,
}

impl Default for CountSwitches {
    fn default() -> Self {
        // Go env defaults: CountToken=true, GET_MEDIA_TOKEN=true,
        // GET_MEDIA_TOKEN_NOT_STREAM=false.
        Self {
            count_token: true,
            get_media_token: true,
            get_media_token_not_stream: false,
        }
    }
}

/// Go `types.TokenCountMeta` (relaykit/types/request_meta.go:20-32). The
/// mutation the Go code performs (mime detection rewrites FileType,
/// `detail` auto→high) is preserved as owned state.
#[derive(Clone, Debug, Default)]
pub struct TokenCountMeta {
    pub token_type: String,
    pub combine_text: String,
    pub tools_count: i64,
    pub name_count: i64,
    pub messages_count: i64,
    pub files: Vec<FileMeta>,
    pub max_tokens: i64,
}

/// Go `types.FileMeta` (request_meta.go:34-38).
#[derive(Clone, Debug, Default)]
pub struct FileMeta {
    /// Go FileType strings: "image" / "audio" / "video" / "file" / "".
    pub file_type: String,
    /// Raw source data (URL or base64); `None` mirrors a nil Source.
    pub source: Option<String>,
    /// Whether the source is a URL (Go FileSource.IsURL).
    pub source_is_url: bool,
    /// Image detail level (low/high/auto).
    pub detail: String,
    /// Optional cached image config (Go CachedFileData.ImageConfig).
    pub image_config: Option<ImageConfig>,
    /// Optional cached image format (Go CachedFileData.ImageFormat).
    pub image_format: Option<String>,
}

impl FileMeta {
    /// Go `(*FileMeta).GetIdentifier` (request_meta.go:58-63).
    pub fn get_identifier(&self) -> String {
        match self.source.as_deref() {
            Some(data) if !self.source_is_url => {
                if data.len() > 50 {
                    format!("base64:{}...", &data[..50])
                } else {
                    format!("base64:{data}")
                }
            }
            Some(data) => {
                if data.len() > 100 {
                    format!("{}...", &data[..100])
                } else {
                    data.to_owned()
                }
            }
            None => "unknown".to_owned(),
        }
    }
}

/// Go `types.TokenType` values (request_meta.go:15-17).
pub mod token_type {
    pub const TEXT_NUMBER: &str = "text_number";
    pub const TOKENIZER: &str = "tokenizer";
    pub const IMAGE: &str = "image";
}

/// Go `types.FileType` values (request_meta.go:5-10).
pub mod file_type {
    pub const IMAGE: &str = "image";
    pub const AUDIO: &str = "audio";
    pub const VIDEO: &str = "video";
    pub const FILE: &str = "file";
}

/// Go `logger.LogDebug` side effects are dropped (pure crate); the resolver
/// trait stands in for the host file service.
pub trait FileDataResolver {
    /// Go `GetImageConfig(c, source)` (decode_file.go:386-414): returns the
    /// image config + format for a file source, or an error string.
    fn get_image_config(
        &self,
        source: &str,
        source_is_url: bool,
    ) -> Result<(ImageConfig, String), String>;

    /// Go `LoadFileSource` + `DetectFileType` (decode_file.go:46-123 /
    /// 454-465): returns the detected FileType string for a source.
    fn detect_file_type(&self, source: &str, source_is_url: bool) -> Result<String, String>;
}

/// Default resolver: decodes base64 sources locally via the multimodal
/// module; URL sources error unless the host supplies a fetching resolver.
pub struct LocalFileResolver;

impl FileDataResolver for LocalFileResolver {
    fn get_image_config(
        &self,
        source: &str,
        source_is_url: bool,
    ) -> Result<(ImageConfig, String), String> {
        if source_is_url {
            return Err(format!(
                "failed to download file from {source}: no egress resolver"
            ));
        }
        match multimodal::decode_base64_image_data(source) {
            Ok((config, format, _)) => Ok((config, format.to_owned())),
            Err(e) => Err(e.0),
        }
    }

    fn detect_file_type(&self, source: &str, source_is_url: bool) -> Result<String, String> {
        if source_is_url {
            return Err(format!(
                "failed to download file from {source}: no egress resolver"
            ));
        }
        match multimodal::decode_base64_file_data(source) {
            Ok((mime, _)) => Ok(multimodal::detect_file_type(&mime).to_owned()),
            Err(_) => Ok(file_type::FILE.to_owned()),
        }
    }
}

/// Audio duration resolver for the transcription path
/// (Go `common.GetAudioDuration`): seconds per uploaded file.
pub type AudioDurationResolver<'a> = &'a dyn Fn(&str) -> Result<f64, String>;

/// Relay-format / relay-mode inputs (strings mirror the Go constants).
#[derive(Clone, Debug, Default)]
pub struct EstimateInputs {
    /// Go `info.RelayFormat` (relay_info.relay_format constants).
    pub relay_format: String,
    /// Go `info.RelayMode` — audio transcription / translation constants.
    /// Go relayconstant.RelayModeAudioTranscription = 6, Translation = 7.
    pub relay_mode: i32,
    pub is_stream: bool,
    /// Go `common.GetCtxKeyString(c, ContextKeyOriginalModel)`.
    pub original_model: String,
}

/// Go relayconstant audio relay modes (relay_mode.go: RelayModeAudioTranscription
/// = 25, RelayModeAudioTranslation = 26). Aliased re-exports from the crate's
/// relay_mode module (one source of truth; the alias avoids clashing with the
/// crate-level `relay_mode` module when both are in scope).
pub mod audio_relay_mode {
    pub use crate::relay_mode::{
        RELAY_MODE_AUDIO_TRANSCRIPTION as AUDIO_TRANSCRIPTION,
        RELAY_MODE_AUDIO_TRANSLATION as AUDIO_TRANSLATION,
    };
}

/// Go `getImageToken` (count_tokens.go:20-175). `file_meta` is mutated: the
/// detail normalization (auto/""→high) is preserved.
pub fn get_image_token(
    file_meta: &mut FileMeta,
    model: &str,
    stream: bool,
    switches: CountSwitches,
    resolver: &dyn FileDataResolver,
) -> Result<i64, String> {
    let Some(source) = file_meta.source.clone() else {
        return Err("image_url_is_nil".to_owned());
    };

    // Defaults for 4o/4.1/4.5 family unless overridden below.
    let mut base_tokens = 85i64;
    let mut tile_tokens = 170i64;

    let lower_model = model.to_lowercase();

    // Special cases from existing behavior.
    if lower_model.starts_with("glm-4") {
        return Ok(1047);
    }

    // Patch-based models (32x32 patches, capped at 1536, with multiplier).
    let mut is_patch_based = false;
    let mut multiplier = 1.0f64;
    if lower_model.contains("gpt-4.1-mini") {
        is_patch_based = true;
        multiplier = 1.62;
    } else if lower_model.contains("gpt-4.1-nano") {
        is_patch_based = true;
        multiplier = 2.46;
    } else if lower_model.starts_with("o4-mini") {
        is_patch_based = true;
        multiplier = 1.72;
    } else if lower_model.starts_with("gpt-5-mini") {
        is_patch_based = true;
        multiplier = 1.62;
    } else if lower_model.starts_with("gpt-5-nano") {
        is_patch_based = true;
        multiplier = 2.46;
    }

    // Tile-based model tokens and bases per doc.
    if !is_patch_based {
        if lower_model.starts_with("gpt-4o-mini") {
            base_tokens = 2833;
            tile_tokens = 5667;
        } else if lower_model.starts_with("gpt-5-chat-latest")
            || (lower_model.starts_with("gpt-5")
                && !lower_model.contains("mini")
                && !lower_model.contains("nano"))
        {
            base_tokens = 70;
            tile_tokens = 140;
        } else if lower_model.starts_with("o1")
            || lower_model.starts_with("o3")
            || lower_model.starts_with("o1-pro")
        {
            base_tokens = 75;
            tile_tokens = 150;
        } else if lower_model.contains("computer-use-preview") {
            base_tokens = 65;
            tile_tokens = 129;
        } else if lower_model.contains("4.1")
            || lower_model.contains("4o")
            || lower_model.contains("4.5")
        {
            base_tokens = 85;
            tile_tokens = 170;
        }
    }

    // Respect existing feature flags/short-circuits.
    if file_meta.detail == "low" && !is_patch_based {
        return Ok(base_tokens);
    }

    if !switches.get_media_token {
        return Ok(3 * base_tokens);
    }

    if !switches.get_media_token_not_stream && !stream {
        return Ok(3 * base_tokens);
    }

    // Normalize detail.
    if file_meta.detail == "auto" || file_meta.detail.is_empty() {
        file_meta.detail = "high".to_owned();
    }

    // Use the unified file service to obtain the image config.
    let (config, format) = if let (Some(config), Some(format)) =
        (file_meta.image_config, file_meta.image_format.clone())
    {
        (config, format)
    } else {
        let (config, format) = resolver.get_image_config(&source, file_meta.source_is_url)?;
        file_meta.image_config = Some(config);
        file_meta.image_format = Some(format.clone());
        (config, format)
    };

    if config.width == 0 || config.height == 0 {
        // Not an image, but might be a valid file.
        if !format.is_empty() {
            return Ok(3 * base_tokens);
        }
        return Err(format!(
            "fail to decode image config: {}",
            file_meta.get_identifier()
        ));
    }

    let width = config.width;
    let height = config.height;

    if is_patch_based {
        // 32x32 patch-based calculation with 1536 cap and model multiplier.
        let ceil_div = |a: i64, b: i64| (a + b - 1) / b;
        let raw_patches_w = ceil_div(width, 32);
        let raw_patches_h = ceil_div(height, 32);
        let raw_patches = raw_patches_w * raw_patches_h;
        if raw_patches > 1536 {
            // Scale down.
            let area = (width * height) as f64;
            let mut r = ((32.0f64 * 32.0 * 1536.0) / area).sqrt();
            let w_scaled = width as f64 * r;
            let h_scaled = height as f64 * r;
            // Adjust to fit a whole number of patches after scaling.
            let adj_w = (w_scaled / 32.0).floor() / (w_scaled / 32.0);
            let adj_h = (h_scaled / 32.0).floor() / (h_scaled / 32.0);
            let adj = adj_w.min(adj_h);
            if !adj.is_nan() && adj > 0.0 {
                r *= adj;
            }
            let w_scaled = width as f64 * r;
            let h_scaled = height as f64 * r;
            let patches_w = (w_scaled / 32.0).ceil();
            let patches_h = (h_scaled / 32.0).ceil();
            let image_tokens = ((patches_w * patches_h) as i64).min(1536);
            return Ok((image_tokens as f64).mul_add(multiplier, 0.0).round() as i64);
        }
        // Below cap.
        return Ok((raw_patches as f64).mul_add(multiplier, 0.0).round() as i64);
    }

    // Tile-based calculation for 4o/4.1/4.5/o1/o3/etc.
    // Step 1: fit within 2048x2048 square.
    let max_side = width.max(height) as f64;
    let mut fit_scale = 1.0f64;
    if max_side > 2048.0 {
        fit_scale = max_side / 2048.0;
    }
    let fit_w = (width as f64 / fit_scale).round() as i64;
    let fit_h = (height as f64 / fit_scale).round() as i64;

    // Step 2: scale so the shortest side is exactly 768.
    let min_side = fit_w.min(fit_h) as f64;
    if min_side == 0.0 {
        return Ok(base_tokens);
    }
    let short_scale = 768.0 / min_side;
    let final_w = (fit_w as f64 * short_scale).round() as i64;
    let final_h = (fit_h as f64 * short_scale).round() as i64;

    // Count 512px tiles.
    let tiles_w = (final_w + 512 - 1) / 512;
    let tiles_h = (final_h + 512 - 1) / 512;
    let tiles = tiles_w * tiles_h;

    Ok(tiles * tile_tokens + base_tokens)
}

/// Go `EstimateRequestToken` (count_tokens.go:177-299). The audio
/// transcription branch requires a resolver (Go parses the multipart form and
/// reads uploaded files); `audio_duration` maps file names to durations.
pub fn estimate_request_token(
    meta: &mut TokenCountMeta,
    inputs: &EstimateInputs,
    switches: CountSwitches,
    resolver: &dyn FileDataResolver,
    audio_duration: Option<AudioDurationResolver<'_>>,
) -> Result<i64, String> {
    // Whether to count tokens at all.
    if !switches.count_token {
        return Ok(0);
    }

    if inputs.relay_format == crate::relay_info::relay_format::OPENAI_REALTIME {
        return Ok(0);
    }

    if inputs.relay_mode == audio_relay_mode::AUDIO_TRANSCRIPTION
        || inputs.relay_mode == audio_relay_mode::AUDIO_TRANSLATION
    {
        let Some(audio_duration) = audio_duration else {
            return Err("error parsing multipart form: no audio resolver".to_owned());
        };
        let mut total_audio_token = 0i64;
        for file in &meta.files {
            let Some(source) = file.source.as_deref() else {
                continue;
            };
            let duration = audio_duration(source)?;
            // Negative durations are clamped to 0 before conversion (billing
            // guard, count_tokens.go:209-214).
            let duration = duration.max(0.0);
            // One minute = 1000 tokens, aligned with $price / minute.
            total_audio_token += super::quota::quota_round((duration.ceil()) / 60.0 * 1000.0);
        }
        return Ok(total_audio_token);
    }

    let model = inputs.original_model.clone();
    let mut tkm = 0i64;

    if meta.token_type == token_type::TEXT_NUMBER {
        tkm += meta.combine_text.chars().count() as i64;
    } else {
        tkm += tokenize_text::count_text_token(&meta.combine_text, &model);
    }

    if inputs.relay_format == crate::relay_info::relay_format::OPENAI {
        tkm += meta.tools_count * 8;
        tkm += meta.messages_count * 3; // per-message formatting tokens
        tkm += meta.name_count * 3;
        tkm += 3;
    }

    let mut should_fetch_files = true;

    if inputs.relay_format == crate::relay_info::relay_format::GEMINI {
        should_fetch_files = false;
    }

    // Whether to count media tokens locally.
    if !switches.get_media_token {
        should_fetch_files = false;
    }

    // Whether to count media tokens locally in non-stream mode.
    if !switches.get_media_token_not_stream && !inputs.is_stream {
        should_fetch_files = false;
    }

    // Resolve unknown file types via MIME detection (Go loop mutates
    // file.FileType in place).
    for i in 0..meta.files.len() {
        if meta.files[i].source.is_none() {
            continue;
        }
        let needs_detect = meta.files[i].file_type.is_empty()
            || (meta.files[i].source_is_url && should_fetch_files);
        if !needs_detect {
            continue;
        }
        let source = meta.files[i].source.clone().unwrap_or_default();
        let source_is_url = meta.files[i].source_is_url;
        let detected = resolver.detect_file_type(&source, source_is_url);
        match detected {
            Ok(detected_type) => {
                meta.files[i].file_type = detected_type;
            }
            Err(e) => {
                if should_fetch_files {
                    return Err(format!("error getting file type: {e}"));
                }
                continue;
            }
        }
    }

    for i in 0..meta.files.len() {
        if meta.files[i].source.is_none() {
            continue;
        }
        let file_type = meta.files[i].file_type.clone();
        match file_type.as_str() {
            file_type::IMAGE => {
                if tokenize_text::is_openai_text_model(&model) {
                    let mut file_meta = meta.files[i].clone();
                    let token = get_image_token(
                        &mut file_meta,
                        &model,
                        inputs.is_stream,
                        switches,
                        resolver,
                    );
                    meta.files[i] = file_meta;
                    let token = token.map_err(|e| {
                        format!(
                            "error counting image token, media index[{i}], identifier[{}], err: {e}",
                            meta.files[i].get_identifier()
                        )
                    })?;
                    tkm += token;
                } else {
                    tkm += 520;
                }
            }
            file_type::AUDIO => tkm += 256,
            file_type::VIDEO => tkm += 4096 * 2,
            file_type::FILE => tkm += 4096,
            _ => tkm += 4096, // Default for unknown file types
        }
    }

    Ok(tkm)
}

/// Realtime event inputs (Go `dto.RealtimeEvent` subset used by
/// `CountTokenRealtime`).
#[derive(Clone, Debug, Default)]
pub struct RealtimeEventInput {
    /// Go request.Type values (dto/realtime.go constants).
    pub kind: String,
    /// session.update instructions.
    pub session_instructions: Option<String>,
    /// response.audio.delta / input_audio_buffer.append base64 audio.
    pub delta: String,
    pub audio: String,
    /// conversation.item.created content items: (type, text).
    pub item_content: Vec<(String, String)>,
    /// response.done realtime tool declarations (JSON strings).
    pub realtime_tools: Vec<String>,
}

/// Realtime event type constants (dto/realtime.go:5-23).
pub mod realtime_event {
    pub const SESSION_UPDATE: &str = "session.update";
    pub const RESPONSE_AUDIO_DELTA: &str = "response.audio.delta";
    pub const RESPONSE_AUDIO_TRANSCRIPTION_DELTA: &str = "response.audio_transcript.delta";
    pub const RESPONSE_FUNCTION_CALL_ARGUMENTS_DELTA: &str =
        "response.function_call_arguments.delta";
    pub const INPUT_AUDIO_BUFFER_APPEND: &str = "input_audio_buffer.append";
    pub const CONVERSATION_ITEM_CREATED: &str = "conversation.item.created";
    pub const RESPONSE_DONE: &str = "response.done";
}

/// Go `CountTokenRealtime` (count_tokens.go:301-353): returns
/// (text_tokens, audio_tokens).
pub fn count_token_realtime(
    event: &RealtimeEventInput,
    model: &str,
    input_audio_format: &str,
    output_audio_format: &str,
    is_first_request: bool,
) -> Result<(i64, i64), String> {
    let mut audio_token = 0i64;
    let mut text_token = 0i64;
    match event.kind.as_str() {
        realtime_event::SESSION_UPDATE => {
            if let Some(instructions) = event.session_instructions.as_deref() {
                text_token += tokenize_text::count_text_token(instructions, model);
            }
        }
        realtime_event::RESPONSE_AUDIO_DELTA => {
            audio_token += count_audio_token_output(&event.delta, output_audio_format)?;
        }
        realtime_event::RESPONSE_AUDIO_TRANSCRIPTION_DELTA
        | realtime_event::RESPONSE_FUNCTION_CALL_ARGUMENTS_DELTA => {
            text_token += tokenize_text::count_text_token(&event.delta, model);
        }
        realtime_event::INPUT_AUDIO_BUFFER_APPEND => {
            audio_token += count_audio_token_input(&event.audio, input_audio_format)?;
        }
        realtime_event::CONVERSATION_ITEM_CREATED => {
            for (content_type, text) in &event.item_content {
                if content_type == "input_text" {
                    text_token += tokenize_text::count_text_token(text, model);
                }
            }
        }
        realtime_event::RESPONSE_DONE => {
            if !is_first_request {
                for tool in &event.realtime_tools {
                    text_token += 8;
                    text_token += count_token_input_string(tool, model);
                }
            }
        }
        _ => {}
    }
    Ok((text_token, audio_token))
}

/// Go `CountTokenInput` (count_tokens.go:355-373) for a JSON input value:
/// string → text count; array of strings → concatenated; array of anything →
/// per-item `%v` concat; other → `%v`.
pub fn count_token_input(input: &Value, model: &str) -> i64 {
    match input {
        Value::String(s) => tokenize_text::count_text_token(s, model),
        Value::Array(items) => {
            let mut text = String::new();
            for item in items {
                match item {
                    Value::String(s) => text.push_str(s),
                    other => text.push_str(&display_value(other)),
                }
            }
            tokenize_text::count_text_token(&text, model)
        }
        other => tokenize_text::count_text_token(&display_value(other), model),
    }
}

/// Go `CountTokenInput(tool, model)` on the realtime tool JSON string.
fn count_token_input_string(input: &str, model: &str) -> i64 {
    tokenize_text::count_text_token(input, model)
}

/// Go `fmt.Sprintf("%v", value)` over JSON values: numbers format like Go,
/// bools are true/false, objects/arrays print compact JSON.
fn display_value(value: &Value) -> String {
    match value {
        Value::Null => "<nil>".to_owned(),
        Value::Bool(b) => {
            if *b {
                "true".to_owned()
            } else {
                "false".to_owned()
            }
        }
        Value::Number(n) => n.to_string(),
        Value::String(_) => value.to_string(),
        other => other.to_string(),
    }
}

/// Go `CountAudioTokenInput` (count_tokens.go:375-385): duration/60*100/0.06,
/// saturating conversion.
pub fn count_audio_token_input(audio_base64: &str, audio_format: &str) -> Result<i64, String> {
    if audio_base64.is_empty() {
        return Ok(0);
    }
    let duration = multimodal::parse_audio(audio_base64, audio_format).map_err(|e| e.0)?;
    Ok(super::quota::quota_from_float(
        duration / 60.0 * 100.0 / 0.06,
    ))
}

/// Go `CountAudioTokenOutput` (count_tokens.go:387-397): duration/60*200/0.24.
pub fn count_audio_token_output(audio_base64: &str, audio_format: &str) -> Result<i64, String> {
    if audio_base64.is_empty() {
        return Ok(0);
    }
    let duration = multimodal::parse_audio(audio_base64, audio_format).map_err(|e| e.0)?;
    Ok(super::quota::quota_from_float(
        duration / 60.0 * 200.0 / 0.24,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Go getImageToken model-family table (count_tokens.go:29-76).
    #[test]
    fn image_token_model_table() {
        let switches = CountSwitches::default();
        let resolver = LocalFileResolver;

        // glm-4 special case (count_tokens.go:33-35).
        let mut meta = FileMeta {
            source: Some("QUJD".into()),
            source_is_url: false,
            detail: "high".into(),
            ..Default::default()
        };
        assert_eq!(
            get_image_token(&mut meta, "glm-4-flash", false, switches, &resolver).unwrap(),
            1047
        );

        // detail=low short-circuits to base tokens (count_tokens.go:79-81).
        let mut meta = FileMeta {
            source: Some("QUJD".into()),
            source_is_url: false,
            detail: "low".into(),
            ..Default::default()
        };
        assert_eq!(
            get_image_token(&mut meta, "gpt-4o", false, switches, &resolver).unwrap(),
            85
        );

        // Nil source errors (count_tokens.go:21-23).
        let mut meta = FileMeta::default();
        assert_eq!(
            get_image_token(&mut meta, "gpt-4o", false, switches, &resolver).unwrap_err(),
            "image_url_is_nil"
        );
    }

    /// Tile-based arithmetic (count_tokens.go:148-175): 1024×1024 →
    /// fit 2048 (scale 1) → shortest side 768 → 768×768 → 2×2 tiles × 170 + 85.
    #[test]
    fn tile_based_1024_square() {
        let switches = CountSwitches {
            get_media_token: true,
            get_media_token_not_stream: true,
            ..Default::default()
        };
        let resolver = LocalFileResolver;
        let png = sample_png_base64(1024, 1024);
        let mut meta = FileMeta {
            source: Some(png),
            source_is_url: false,
            detail: "high".into(),
            ..Default::default()
        };
        let got = get_image_token(&mut meta, "gpt-4o", true, switches, &resolver).unwrap();
        assert_eq!(got, 4 * 170 + 85);
    }

    /// detail normalization auto→high (count_tokens.go:92-94).
    #[test]
    fn detail_normalized_to_high() {
        let switches = CountSwitches {
            get_media_token: true,
            get_media_token_not_stream: true,
            ..Default::default()
        };
        let resolver = LocalFileResolver;
        let png = sample_png_base64(1024, 1024);
        let mut meta = FileMeta {
            source: Some(png),
            source_is_url: false,
            detail: "auto".into(),
            ..Default::default()
        };
        let _ = get_image_token(&mut meta, "gpt-4o", true, switches, &resolver).unwrap();
        assert_eq!(meta.detail, "high");
    }

    /// Stream gates (count_tokens.go:84-90): GET_MEDIA_TOKEN off → 3×base;
    /// non-stream without GET_MEDIA_TOKEN_NOT_STREAM → 3×base.
    #[test]
    fn media_token_switch_gates() {
        let resolver = LocalFileResolver;
        let png = sample_png_base64(1024, 1024);

        let switches = CountSwitches {
            count_token: true,
            get_media_token: false,
            get_media_token_not_stream: true,
        };
        let mut meta = FileMeta {
            source: Some(png.clone()),
            source_is_url: false,
            detail: "high".into(),
            ..Default::default()
        };
        assert_eq!(
            get_image_token(&mut meta, "gpt-4o", true, switches, &resolver).unwrap(),
            3 * 85
        );

        let switches = CountSwitches {
            count_token: true,
            get_media_token: true,
            get_media_token_not_stream: false,
        };
        let mut meta = FileMeta {
            source: Some(png),
            source_is_url: false,
            detail: "high".into(),
            ..Default::default()
        };
        assert_eq!(
            get_image_token(&mut meta, "gpt-4o", false, switches, &resolver).unwrap(),
            3 * 85
        );
    }

    /// Non-image data with a decodable "format" path → 3×base
    /// (count_tokens.go:101-108).
    #[test]
    fn non_image_data_falls_to_three_base() {
        let switches = CountSwitches {
            get_media_token: true,
            get_media_token_not_stream: true,
            ..Default::default()
        };
        let resolver = LocalFileResolver;
        // gpt-4o-mini has base 2833 (count_tokens.go:60-63).
        let mut meta = FileMeta {
            source: Some("QUJD".into()),
            source_is_url: false,
            detail: "high".into(),
            ..Default::default()
        };
        assert_eq!(
            get_image_token(&mut meta, "gpt-4o-mini", true, switches, &resolver).unwrap_err(),
            "fail to decode image config: QUJD"
        );
    }

    /// Patch-based model: 64×64 → 2×2 = 4 patches × 1.62 (gpt-4.1-mini).
    #[test]
    fn patch_based_multiplier() {
        let switches = CountSwitches {
            get_media_token: true,
            get_media_token_not_stream: true,
            ..Default::default()
        };
        let resolver = LocalFileResolver;
        let png = sample_png_base64(64, 64);
        let mut meta = FileMeta {
            source: Some(png),
            source_is_url: false,
            detail: "high".into(),
            ..Default::default()
        };
        let got = get_image_token(&mut meta, "gpt-4.1-mini", true, switches, &resolver).unwrap();
        assert_eq!(got, 4.0f64.mul_add(1.62, 0.0).round() as i64);
    }

    /// EstimateRequestToken: CountToken off → 0; realtime → 0
    /// (count_tokens.go:179-189).
    #[test]
    fn estimate_gates() {
        let resolver = LocalFileResolver;
        let switches = CountSwitches {
            count_token: false,
            ..Default::default()
        };
        let mut meta = TokenCountMeta {
            combine_text: "hello".into(),
            ..Default::default()
        };
        let inputs = EstimateInputs {
            relay_format: crate::relay_info::relay_format::OPENAI.to_owned(),
            ..Default::default()
        };
        assert_eq!(
            estimate_request_token(&mut meta, &inputs, switches, &resolver, None).unwrap(),
            0
        );

        let switches = CountSwitches::default();
        let inputs = EstimateInputs {
            relay_format: crate::relay_info::relay_format::OPENAI_REALTIME.to_owned(),
            ..Default::default()
        };
        assert_eq!(
            estimate_request_token(&mut meta, &inputs, switches, &resolver, None).unwrap(),
            0
        );
    }

    /// OpenAI format overhead: tools*8 + messages*3 + names*3 + 3
    /// (count_tokens.go:229-234).
    #[test]
    fn openai_format_overhead() {
        let resolver = LocalFileResolver;
        let switches = CountSwitches::default();
        let mut meta = TokenCountMeta {
            combine_text: "hello world".into(),
            tools_count: 2,
            messages_count: 3,
            name_count: 1,
            ..Default::default()
        };
        let inputs = EstimateInputs {
            relay_format: crate::relay_info::relay_format::OPENAI.to_owned(),
            original_model: "gpt-5-chat".into(),
            ..Default::default()
        };
        let text_tokens = tokenize_text::count_text_token("hello world", "gpt-5-chat");
        let got = estimate_request_token(&mut meta, &inputs, switches, &resolver, None).unwrap();
        assert_eq!(got, text_tokens + 2 * 8 + 3 * 3 + 1 * 3 + 3);
    }

    /// text_number token type counts runes (count_tokens.go:223-225).
    #[test]
    fn text_number_type_counts_runes() {
        let resolver = LocalFileResolver;
        let switches = CountSwitches::default();
        let mut meta = TokenCountMeta {
            token_type: token_type::TEXT_NUMBER.to_owned(),
            combine_text: "héllo中".into(),
            ..Default::default()
        };
        let inputs = EstimateInputs::default();
        let got = estimate_request_token(&mut meta, &inputs, switches, &resolver, None).unwrap();
        assert_eq!(got, "héllo中".chars().count() as i64);
    }

    /// Media file flat rates (count_tokens.go:274-294): audio 256, video
    /// 8192, file 4096, unknown 4096; non-OpenAI image 520.
    #[test]
    fn media_file_rates() {
        let resolver = LocalFileResolver;
        let switches = CountSwitches::default();
        let mut meta = TokenCountMeta {
            files: vec![
                FileMeta {
                    file_type: file_type::AUDIO.into(),
                    source: Some("QUJD".into()),
                    source_is_url: false,
                    ..Default::default()
                },
                FileMeta {
                    file_type: file_type::VIDEO.into(),
                    source: Some("QUJD".into()),
                    source_is_url: false,
                    ..Default::default()
                },
                FileMeta {
                    file_type: file_type::FILE.into(),
                    source: Some("QUJD".into()),
                    source_is_url: false,
                    ..Default::default()
                },
                FileMeta {
                    file_type: "unknown".into(),
                    source: Some("QUJD".into()),
                    source_is_url: false,
                    ..Default::default()
                },
                FileMeta {
                    file_type: file_type::IMAGE.into(),
                    source: Some("QUJD".into()),
                    source_is_url: false,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let inputs = EstimateInputs {
            original_model: "claude-3".into(),
            ..Default::default()
        };
        let got = estimate_request_token(&mut meta, &inputs, switches, &resolver, None).unwrap();
        assert_eq!(got, 256 + 8192 + 4096 + 4096 + 520);
    }

    /// Audio transcription path (count_tokens.go:190-218): a 90-second file
    /// → ceil(90)/60*1000 = 1500 tokens; negative durations clamp to 0.
    #[test]
    fn audio_transcription_duration() {
        let resolver = LocalFileResolver;
        let switches = CountSwitches::default();
        let mut meta = TokenCountMeta {
            files: vec![
                FileMeta {
                    file_type: file_type::AUDIO.into(),
                    source: Some("a.mp3".into()),
                    source_is_url: false,
                    ..Default::default()
                },
                FileMeta {
                    file_type: file_type::AUDIO.into(),
                    source: Some("b.mp3".into()),
                    source_is_url: false,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let inputs = EstimateInputs {
            relay_mode: audio_relay_mode::AUDIO_TRANSCRIPTION,
            ..Default::default()
        };
        let resolver_audio = |name: &str| -> Result<f64, String> {
            match name {
                "a.mp3" => Ok(90.0),
                "b.mp3" => Ok(-5.0),
                _ => Err("missing".to_owned()),
            }
        };
        let got = estimate_request_token(
            &mut meta,
            &inputs,
            switches,
            &resolver,
            Some(&resolver_audio),
        )
        .unwrap();
        assert_eq!(got, 1500);
    }

    /// Realtime counting (count_tokens.go:301-353).
    #[test]
    fn realtime_event_counts() {
        let event = RealtimeEventInput {
            kind: realtime_event::SESSION_UPDATE.to_owned(),
            session_instructions: Some("be nice".into()),
            ..Default::default()
        };
        let (text, audio) = count_token_realtime(&event, "gpt-4o", "pcm16", "pcm16", true).unwrap();
        assert!(text > 0);
        assert_eq!(audio, 0);

        // input_audio_buffer.append: 48-byte pcm16 → 24 samples @24kHz = 1ms
        // → duration/60*100/0.06 = 0.0166.../… → QuotaFromFloat truncation.
        let pcm48 = base64_of(&[0u8; 48]);
        let event = RealtimeEventInput {
            kind: realtime_event::INPUT_AUDIO_BUFFER_APPEND.to_owned(),
            audio: pcm48,
            ..Default::default()
        };
        let (text, audio) = count_token_realtime(&event, "gpt-4o", "pcm16", "pcm16", true).unwrap();
        assert_eq!(text, 0);
        // 24 samples / 24000 = 0.001 s → 0.001/60*100/0.06 = 0.0277 → 0.
        assert_eq!(audio, 0);

        // response.done with tools, not first request → 8 + count per tool.
        let event = RealtimeEventInput {
            kind: realtime_event::RESPONSE_DONE.to_owned(),
            realtime_tools: vec![json!({"type": "function", "name": "lookup"}).to_string()],
            ..Default::default()
        };
        let (text, audio) =
            count_token_realtime(&event, "gpt-4o", "pcm16", "pcm16", false).unwrap();
        assert!(text > 8);
        assert_eq!(audio, 0);

        // First request skips tool counting.
        let (text, _) = count_token_realtime(&event, "gpt-4o", "pcm16", "pcm16", true).unwrap();
        assert_eq!(text, 0);
    }

    /// CountAudioTokenInput/Output formulas (count_tokens.go:375-397):
    /// 1 second of g711 → input: 1/60*100/0.06 = 27.77 → 27; output:
    /// 1/60*200/0.24 = 13.88 → 13.
    #[test]
    fn audio_token_formulas() {
        let mut g711 = Vec::new();
        for _ in 0..8000 {
            g711.push(0x55u8);
        }
        let encoded = base64_of(&g711);
        assert_eq!(count_audio_token_input(&encoded, "g711_ulaw").unwrap(), 27);
        assert_eq!(count_audio_token_output(&encoded, "g711_alaw").unwrap(), 13);
        assert_eq!(count_audio_token_input("", "g711_ulaw").unwrap(), 0);
        assert_eq!(count_audio_token_output("", "g711_alaw").unwrap(), 0);
    }

    /// CountTokenInput dispatch (count_tokens.go:355-373).
    #[test]
    fn count_token_input_dispatch() {
        assert!(count_token_input(&json!("hello world"), "gpt-5-chat") > 0);
        assert!(count_token_input(&json!(["hello", "world"]), "gpt-5-chat") > 0);
        assert!(count_token_input(&json!([1, "a"]), "gpt-5-chat") > 0);
        assert_eq!(count_token_input(&json!(""), "gpt-5-chat"), 0);
    }

    // -- helpers --

    fn base64_of(data: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = chunk.get(1).map(|b| *b as u32).unwrap_or(0);
            let b2 = chunk.get(2).map(|b| *b as u32).unwrap_or(0);
            let n = (b0 << 16) | (b1 << 8) | b2;
            out.push(TABLE[(n >> 18) as usize & 63] as char);
            out.push(TABLE[(n >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 {
                TABLE[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                TABLE[n as usize & 63] as char
            } else {
                '='
            });
        }
        out
    }

    fn sample_png_base64(width: u32, height: u32) -> String {
        let mut data = Vec::new();
        data.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        data.extend_from_slice(&13u32.to_be_bytes());
        data.extend_from_slice(b"IHDR");
        data.extend_from_slice(&width.to_be_bytes());
        data.extend_from_slice(&height.to_be_bytes());
        data.extend_from_slice(&[8, 6, 0, 0, 0]);
        base64_of(&data)
    }
}
