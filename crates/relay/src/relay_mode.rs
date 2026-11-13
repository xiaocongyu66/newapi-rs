//! Go `internal/relay/constant/relay_mode.go` 的移植：路径 → RelayMode 映射。
//!
//! 常量序号与 Go 的 iota 完全一致；`Path2RelayMode` 的判定顺序（前缀优先级）
//! 是契约的一部分，不得重排。

/// Go `RelayModeUnknown = iota`（0）。
pub const RELAY_MODE_UNKNOWN: i32 = 0;
pub const RELAY_MODE_CHAT_COMPLETIONS: i32 = 1;
pub const RELAY_MODE_COMPLETIONS: i32 = 2;
pub const RELAY_MODE_EMBEDDINGS: i32 = 3;
pub const RELAY_MODE_MODERATIONS: i32 = 4;
pub const RELAY_MODE_IMAGES_GENERATIONS: i32 = 5;
pub const RELAY_MODE_IMAGES_EDITS: i32 = 6;
pub const RELAY_MODE_EDITS: i32 = 7;
pub const RELAY_MODE_MIDJOURNEY_IMAGINE: i32 = 8;
pub const RELAY_MODE_MIDJOURNEY_DESCRIBE: i32 = 9;
pub const RELAY_MODE_MIDJOURNEY_BLEND: i32 = 10;
pub const RELAY_MODE_MIDJOURNEY_CHANGE: i32 = 11;
pub const RELAY_MODE_MIDJOURNEY_SIMPLE_CHANGE: i32 = 12;
pub const RELAY_MODE_MIDJOURNEY_NOTIFY: i32 = 13;
pub const RELAY_MODE_MIDJOURNEY_TASK_FETCH: i32 = 14;
pub const RELAY_MODE_MIDJOURNEY_TASK_IMAGE_SEED: i32 = 15;
pub const RELAY_MODE_MIDJOURNEY_TASK_FETCH_BY_CONDITION: i32 = 16;
pub const RELAY_MODE_MIDJOURNEY_ACTION: i32 = 17;
pub const RELAY_MODE_MIDJOURNEY_MODAL: i32 = 18;
pub const RELAY_MODE_MIDJOURNEY_SHORTEN: i32 = 19;
pub const RELAY_MODE_SWAP_FACE: i32 = 20;
pub const RELAY_MODE_MIDJOURNEY_UPLOAD: i32 = 21;
pub const RELAY_MODE_MIDJOURNEY_VIDEO: i32 = 22;
pub const RELAY_MODE_MIDJOURNEY_EDITS: i32 = 23;
pub const RELAY_MODE_AUDIO_SPEECH: i32 = 24;
pub const RELAY_MODE_AUDIO_TRANSCRIPTION: i32 = 25;
pub const RELAY_MODE_AUDIO_TRANSLATION: i32 = 26;
pub const RELAY_MODE_SUNO_FETCH: i32 = 27;
pub const RELAY_MODE_SUNO_FETCH_BY_ID: i32 = 28;
pub const RELAY_MODE_SUNO_SUBMIT: i32 = 29;
pub const RELAY_MODE_VIDEO_FETCH_BY_ID: i32 = 30;
pub const RELAY_MODE_VIDEO_SUBMIT: i32 = 31;
pub const RELAY_MODE_RERANK: i32 = 32;
pub const RELAY_MODE_RESPONSES: i32 = 33;
pub const RELAY_MODE_REALTIME: i32 = 34;
pub const RELAY_MODE_GEMINI: i32 = 35;
pub const RELAY_MODE_RESPONSES_COMPACT: i32 = 36;
pub const RELAY_MODE_ALPHA_SEARCH: i32 = 37;

/// Go `Path2RelayMode`（relay_mode.go:59-94）：判定顺序逐条对齐。
/// 重复分支体（embeddings 前缀/后缀、mj change/simple-change）与 Go 逐字
/// 对齐，是契约的一部分——clippy::if_same_then_else 允许豁免。
#[allow(clippy::if_same_then_else)]
pub fn path_to_relay_mode(path: &str) -> i32 {
    if path.starts_with("/v1/chat/completions") || path.starts_with("/pg/chat/completions") {
        RELAY_MODE_CHAT_COMPLETIONS
    } else if path.starts_with("/v1/completions") {
        RELAY_MODE_COMPLETIONS
    } else if path.starts_with("/v1/embeddings") {
        RELAY_MODE_EMBEDDINGS
    } else if path.ends_with("embeddings") {
        RELAY_MODE_EMBEDDINGS
    } else if path.starts_with("/v1/moderations") {
        RELAY_MODE_MODERATIONS
    } else if path.starts_with("/v1/images/generations") {
        RELAY_MODE_IMAGES_GENERATIONS
    } else if path.starts_with("/v1/images/edits") {
        RELAY_MODE_IMAGES_EDITS
    } else if path.starts_with("/v1/edits") {
        RELAY_MODE_EDITS
    } else if path.starts_with("/v1/responses/compact") {
        RELAY_MODE_RESPONSES_COMPACT
    } else if path.starts_with("/v1/responses") {
        RELAY_MODE_RESPONSES
    } else if path.starts_with("/v1/alpha/search") {
        RELAY_MODE_ALPHA_SEARCH
    } else if path.starts_with("/v1/audio/speech") {
        RELAY_MODE_AUDIO_SPEECH
    } else if path.starts_with("/v1/audio/transcriptions") {
        RELAY_MODE_AUDIO_TRANSCRIPTION
    } else if path.starts_with("/v1/audio/translations") {
        RELAY_MODE_AUDIO_TRANSLATION
    } else if path.starts_with("/v1/rerank") {
        RELAY_MODE_RERANK
    } else if path.starts_with("/v1/realtime") {
        RELAY_MODE_REALTIME
    } else if path.starts_with("/v1beta/models") || path.starts_with("/v1/models") {
        RELAY_MODE_GEMINI
    } else if path.starts_with("/mj") {
        path_to_relay_mode_midjourney(path)
    } else {
        RELAY_MODE_UNKNOWN
    }
}

/// Go `Path2RelayModeMidjourney`（relay_mode.go:97-127）。
/// `/mj/submit/change` 与 `/mj/submit/simple-change` 同映射一个 RelayMode，
/// 与 Go 逐字对齐（clippy::if_same_then_else 契约豁免）。
#[allow(clippy::if_same_then_else)]
pub fn path_to_relay_mode_midjourney(path: &str) -> i32 {
    if path.ends_with("/mj/submit/action") {
        RELAY_MODE_MIDJOURNEY_ACTION
    } else if path.ends_with("/mj/submit/modal") {
        RELAY_MODE_MIDJOURNEY_MODAL
    } else if path.ends_with("/mj/submit/shorten") {
        RELAY_MODE_MIDJOURNEY_SHORTEN
    } else if path.ends_with("/mj/insight-face/swap") {
        RELAY_MODE_SWAP_FACE
    } else if path.ends_with("/submit/upload-discord-images") {
        RELAY_MODE_MIDJOURNEY_UPLOAD
    } else if path.ends_with("/mj/submit/imagine") {
        RELAY_MODE_MIDJOURNEY_IMAGINE
    } else if path.ends_with("/mj/submit/video") {
        RELAY_MODE_MIDJOURNEY_VIDEO
    } else if path.ends_with("/mj/submit/edits") {
        RELAY_MODE_MIDJOURNEY_EDITS
    } else if path.ends_with("/mj/submit/blend") {
        RELAY_MODE_MIDJOURNEY_BLEND
    } else if path.ends_with("/mj/submit/describe") {
        RELAY_MODE_MIDJOURNEY_DESCRIBE
    } else if path.ends_with("/mj/notify") {
        RELAY_MODE_MIDJOURNEY_NOTIFY
    } else if path.ends_with("/mj/submit/change") {
        RELAY_MODE_MIDJOURNEY_CHANGE
    } else if path.ends_with("/mj/submit/simple-change") {
        RELAY_MODE_MIDJOURNEY_CHANGE
    } else if path.ends_with("/fetch") {
        RELAY_MODE_MIDJOURNEY_TASK_FETCH
    } else if path.ends_with("/image-seed") {
        RELAY_MODE_MIDJOURNEY_TASK_IMAGE_SEED
    } else if path.ends_with("/list-by-condition") {
        RELAY_MODE_MIDJOURNEY_TASK_FETCH_BY_CONDITION
    } else {
        RELAY_MODE_UNKNOWN
    }
}

/// Go `Path2RelaySuno`（relay_mode.go:130-138）。
pub fn path_to_relay_suno(method: &str, path: &str) -> i32 {
    if method == "POST" && path.ends_with("/fetch") {
        RELAY_MODE_SUNO_FETCH
    } else if method == "GET" && path.contains("/fetch/") {
        RELAY_MODE_SUNO_FETCH_BY_ID
    } else if path.contains("/submit/") {
        RELAY_MODE_SUNO_SUBMIT
    } else {
        RELAY_MODE_UNKNOWN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_completions_paths() {
        assert_eq!(
            path_to_relay_mode("/v1/chat/completions"),
            RELAY_MODE_CHAT_COMPLETIONS
        );
        assert_eq!(
            path_to_relay_mode("/pg/chat/completions"),
            RELAY_MODE_CHAT_COMPLETIONS
        );
        assert_eq!(
            path_to_relay_mode("/v1/completions"),
            RELAY_MODE_COMPLETIONS
        );
    }

    #[test]
    fn responses_compact_beats_responses() {
        // /v1/responses/compact 必须先于 /v1/responses 判定。
        assert_eq!(
            path_to_relay_mode("/v1/responses/compact"),
            RELAY_MODE_RESPONSES_COMPACT
        );
        assert_eq!(path_to_relay_mode("/v1/responses"), RELAY_MODE_RESPONSES);
    }

    #[test]
    fn gemini_and_models_paths() {
        assert_eq!(path_to_relay_mode("/v1/models"), RELAY_MODE_GEMINI);
        assert_eq!(
            path_to_relay_mode("/v1beta/models/gemini-pro:generateContent"),
            RELAY_MODE_GEMINI
        );
        // /v1/engines/m/embeddings 走 ends_with("embeddings") 分支。
        assert_eq!(
            path_to_relay_mode("/v1/engines/x/embeddings"),
            RELAY_MODE_EMBEDDINGS
        );
    }

    #[test]
    fn audio_paths() {
        assert_eq!(
            path_to_relay_mode("/v1/audio/speech"),
            RELAY_MODE_AUDIO_SPEECH
        );
        assert_eq!(
            path_to_relay_mode("/v1/audio/transcriptions"),
            RELAY_MODE_AUDIO_TRANSCRIPTION
        );
        assert_eq!(
            path_to_relay_mode("/v1/audio/translations"),
            RELAY_MODE_AUDIO_TRANSLATION
        );
    }

    #[test]
    fn midjourney_suffixes() {
        assert_eq!(
            path_to_relay_mode("/mj/submit/imagine"),
            RELAY_MODE_MIDJOURNEY_IMAGINE
        );
        assert_eq!(
            path_to_relay_mode("/fast/mj/submit/imagine"),
            RELAY_MODE_MIDJOURNEY_IMAGINE
        );
        assert_eq!(
            path_to_relay_mode("/mj/submit/simple-change"),
            RELAY_MODE_MIDJOURNEY_CHANGE
        );
        assert_eq!(
            path_to_relay_mode("/mj/task/abc/fetch"),
            RELAY_MODE_MIDJOURNEY_TASK_FETCH
        );
        assert_eq!(path_to_relay_mode("/mj"), RELAY_MODE_UNKNOWN);
    }

    #[test]
    fn suno_paths() {
        assert_eq!(
            path_to_relay_suno("POST", "/suno/fetch"),
            RELAY_MODE_SUNO_FETCH
        );
        assert_eq!(
            path_to_relay_suno("GET", "/suno/fetch/abc"),
            RELAY_MODE_SUNO_FETCH_BY_ID
        );
        assert_eq!(
            path_to_relay_suno("POST", "/suno/submit/music"),
            RELAY_MODE_SUNO_SUBMIT
        );
        assert_eq!(
            path_to_relay_suno("GET", "/suno/submit/x"),
            RELAY_MODE_SUNO_SUBMIT
        );
    }
}
