//! ratio 设置面：`ModelRatio`/`ModelPrice`/`CompletionRatio`/`CacheRatio`/
//! `CreateCacheRatio`/`ImageRatio`/`AudioRatio`/`AudioCompletionRatio` 八个
//! 选项的默认表、选项覆盖解析与查询函数。
//!
//! Go 参考（`/root/newapi/apps/api/internal/catalog/configure_ratio`）：
//! - `configure_model_ratio.go`：默认表、`GetModelPrice`/`GetModelRatio`/
//!   `GetCompletionRatio`、`FormatMatchingModelName`、
//!   `getHardcodedCompletionModelRatio`、compact 后缀折叠
//! - `configure_cache_ratio.go`：缓存倍率默认表与查询
//! - `register_option_hooks.go`：`applyRatioOption`（选项 JSON 整体替换
//!   运行时 map；解析失败时 Go `SyncOptions` 记日志并保留旧 map）
//!
//! 契约要点（与 Go 一致）：
//! - 选项值是**整体替换**（`RWMap.LoadFromJsonString`），不是按键合并；
//!   首次装载前运行时 map = 内置默认表（Go `InitRatioSettings`）。
//! - `GetModelRatio` 未命中时回 `(37.5, SelfUseModeEnabled)`；compact 后缀
//!   模型回退到 `*-openai-compact` 通配键。
//! - `GetCompletionRatio` 的级联：`/` 分隔模型只查覆盖层 → 硬编码（locked
//!   则强制）→ 覆盖层 → 硬编码缺省。
//! - `GetCacheRatio`/`GetCreateCacheRatio`/`GetImageRatio` 未命中回
//!   `(缺省值, false)`；audio 两个查询未命中回 1。
//!
//! Go 全局 RWMap 的对应物是 [`RatioSettings`] 快照：与 `GroupSettings` 同
//! 约定（`AppState` 启动与 reload worker 装载，handler/缓存只读）。

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};

// ---------------------------------------------------------------------------
// 常量与默认表
// ---------------------------------------------------------------------------

/// Go `CompactModelSuffix`（`compact_suffix.go:7`）。
pub const COMPACT_MODEL_SUFFIX: &str = "-openai-compact";
/// Go `CompactWildcardModelKey`。
pub const COMPACT_WILDCARD_MODEL_KEY: &str = "*-openai-compact";

/// Go `SelfUseModeEnabled`（`configure_model_ratio.go:19`）。
static SELF_USE_MODE_ENABLED: AtomicBool = AtomicBool::new(false);

/// Go `SelfUseModeEnabled` 读写（Go 由 manage_channels 在
/// `applyOperationSetting` 里同步；Rust 由 option 域写入时置位）。
pub fn self_use_mode_enabled() -> bool {
    SELF_USE_MODE_ENABLED.load(Ordering::Relaxed)
}

pub fn set_self_use_mode_enabled(enabled: bool) {
    SELF_USE_MODE_ENABLED.store(enabled, Ordering::Relaxed);
}

/// Go `defaultModelRatio`（`configure_model_ratio.go:29-273`）：237 条内置
/// 模型倍率（原迁移自 `apps/server/src/option_defaults.rs`，键值一致）。
pub const DEFAULT_MODEL_RATIO: [(&str, f64); 237] = [
    ("gpt-4-gizmo-*", 15.0),
    ("gpt-4o-gizmo-*", 2.5),
    ("gpt-4-all", 15.0),
    ("gpt-4o-all", 15.0),
    ("gpt-4", 15.0),
    ("gpt-4-0613", 15.0),
    ("gpt-4-32k", 30.0),
    ("gpt-4-32k-0613", 30.0),
    ("gpt-4-1106-preview", 5.0),
    ("gpt-4-0125-preview", 5.0),
    ("gpt-4-turbo-preview", 5.0),
    ("gpt-4-vision-preview", 5.0),
    ("gpt-4-1106-vision-preview", 5.0),
    ("chatgpt-4o-latest", 2.5),
    ("gpt-4o", 1.25),
    ("gpt-4o-audio-preview", 1.25),
    ("gpt-4o-audio-preview-2024-10-01", 1.25),
    ("gpt-4o-2024-05-13", 2.5),
    ("gpt-4o-2024-08-06", 1.25),
    ("gpt-4o-2024-11-20", 1.25),
    ("gpt-4o-realtime-preview", 2.5),
    ("gpt-4o-realtime-preview-2024-10-01", 2.5),
    ("gpt-4o-realtime-preview-2024-12-17", 2.5),
    ("gpt-4o-mini-realtime-preview", 0.3),
    ("gpt-4o-mini-realtime-preview-2024-12-17", 0.3),
    ("gpt-4.1", 1.0),
    ("gpt-4.1-2025-04-14", 1.0),
    ("gpt-4.1-mini", 0.2),
    ("gpt-4.1-mini-2025-04-14", 0.2),
    ("gpt-4.1-nano", 0.05),
    ("gpt-4.1-nano-2025-04-14", 0.05),
    ("gpt-image-1", 2.5),
    ("o1", 7.5),
    ("o1-2024-12-17", 7.5),
    ("o1-preview", 7.5),
    ("o1-preview-2024-09-12", 7.5),
    ("o1-mini", 0.55),
    ("o1-mini-2024-09-12", 0.55),
    ("o1-pro", 75.0),
    ("o1-pro-2025-03-19", 75.0),
    ("o3-mini", 0.55),
    ("o3-mini-2025-01-31", 0.55),
    ("o3-mini-high", 0.55),
    ("o3-mini-2025-01-31-high", 0.55),
    ("o3-mini-low", 0.55),
    ("o3-mini-2025-01-31-low", 0.55),
    ("o3-mini-medium", 0.55),
    ("o3-mini-2025-01-31-medium", 0.55),
    ("o3", 1.0),
    ("o3-2025-04-16", 1.0),
    ("o3-pro", 10.0),
    ("o3-pro-2025-06-10", 10.0),
    ("o3-deep-research", 5.0),
    ("o3-deep-research-2025-06-26", 5.0),
    ("o4-mini", 0.55),
    ("o4-mini-2025-04-16", 0.55),
    ("o4-mini-deep-research", 1.0),
    ("o4-mini-deep-research-2025-06-26", 1.0),
    ("gpt-4o-mini", 0.075),
    ("gpt-4o-mini-2024-07-18", 0.075),
    ("gpt-4-turbo", 5.0),
    ("gpt-4-turbo-2024-04-09", 5.0),
    ("gpt-4.5-preview", 37.5),
    ("gpt-4.5-preview-2025-02-27", 37.5),
    ("gpt-5", 0.625),
    ("gpt-5-2025-08-07", 0.625),
    ("gpt-5-chat-latest", 0.625),
    ("gpt-5-mini", 0.125),
    ("gpt-5-mini-2025-08-07", 0.125),
    ("gpt-5-nano", 0.025),
    ("gpt-5-nano-2025-08-07", 0.025),
    ("gpt-5.5", 2.5),
    ("gpt-5.6-sol", 2.5),
    ("gpt-5.6-terra", 1.25),
    ("gpt-5.6-luna", 0.5),
    ("gpt-3.5-turbo", 0.25),
    ("gpt-3.5-turbo-0613", 0.75),
    ("gpt-3.5-turbo-16k", 1.5),
    ("gpt-3.5-turbo-16k-0613", 1.5),
    ("gpt-3.5-turbo-instruct", 0.75),
    ("gpt-3.5-turbo-1106", 0.5),
    ("gpt-3.5-turbo-0125", 0.25),
    ("text-ada-001", 0.2),
    ("text-babbage-001", 0.25),
    ("text-curie-001", 1.0),
    ("text-davinci-edit-001", 10.0),
    ("code-davinci-edit-001", 10.0),
    ("whisper-1", 15.0),
    ("tts-1", 7.5),
    ("tts-1-1106", 7.5),
    ("tts-1-hd", 15.0),
    ("tts-1-hd-1106", 15.0),
    ("davinci", 10.0),
    ("curie", 10.0),
    ("text-embedding-3-small", 0.01),
    ("text-embedding-3-large", 0.065),
    ("text-embedding-ada-002", 0.05),
    ("text-search-ada-doc-001", 10.0),
    ("text-moderation-stable", 0.1),
    ("text-moderation-latest", 0.1),
    ("claude-3-haiku-20240307", 0.125),
    ("claude-3-5-haiku-20241022", 0.5),
    ("claude-haiku-4-5-20251001", 0.5),
    ("claude-3-sonnet-20240229", 1.5),
    ("claude-3-5-sonnet-20240620", 1.5),
    ("claude-3-5-sonnet-20241022", 1.5),
    ("claude-3-7-sonnet-20250219", 1.5),
    ("claude-3-7-sonnet-20250219-thinking", 1.5),
    ("claude-sonnet-4-20250514", 1.5),
    ("claude-sonnet-4-5-20250929", 1.5),
    ("claude-opus-4-5-20251101", 2.5),
    ("claude-opus-4-6", 2.5),
    ("claude-opus-4-6-max", 2.5),
    ("claude-opus-4-6-high", 2.5),
    ("claude-opus-4-6-medium", 2.5),
    ("claude-opus-4-6-low", 2.5),
    ("claude-opus-4-7", 2.5),
    ("claude-opus-4-7-max", 2.5),
    ("claude-opus-4-7-xhigh", 2.5),
    ("claude-opus-4-7-high", 2.5),
    ("claude-opus-4-7-medium", 2.5),
    ("claude-opus-4-7-low", 2.5),
    ("claude-opus-4-8", 2.5),
    ("claude-opus-4-8-max", 2.5),
    ("claude-opus-4-8-xhigh", 2.5),
    ("claude-opus-4-8-high", 2.5),
    ("claude-opus-4-8-medium", 2.5),
    ("claude-opus-4-8-low", 2.5),
    ("claude-3-opus-20240229", 7.5),
    ("claude-opus-4-20250514", 7.5),
    ("claude-opus-4-1-20250805", 7.5),
    ("ERNIE-4.0-8K", 8.21917808219178),
    ("ERNIE-3.5-8K", 0.8219178082191781),
    ("ERNIE-3.5-8K-0205", 1.6438356164383563),
    ("ERNIE-3.5-8K-1222", 0.8219178082191781),
    ("ERNIE-Bot-8K", 1.6438356164383563),
    ("ERNIE-3.5-4K-0205", 0.8219178082191781),
    ("ERNIE-Speed-8K", 0.273972602739726),
    ("ERNIE-Speed-128K", 0.273972602739726),
    ("ERNIE-Lite-8K-0922", 0.547945205479452),
    ("ERNIE-Lite-8K-0308", 0.20547945205479454),
    ("ERNIE-Tiny-8K", 0.0684931506849315),
    ("BLOOMZ-7B", 0.273972602739726),
    ("Embedding-V1", 0.136986301369863),
    ("bge-large-zh", 0.136986301369863),
    ("bge-large-en", 0.136986301369863),
    ("tao-8k", 0.136986301369863),
    ("PaLM-2", 1.0),
    ("gemini-1.5-pro-latest", 1.25),
    ("gemini-1.5-flash-latest", 0.075),
    ("gemini-2.0-flash", 0.05),
    ("gemini-2.5-pro-exp-03-25", 0.625),
    ("gemini-2.5-pro-preview-03-25", 0.625),
    ("gemini-2.5-pro", 0.625),
    ("gemini-2.5-flash-preview-04-17", 0.075),
    ("gemini-2.5-flash-preview-04-17-thinking", 0.075),
    ("gemini-2.5-flash-preview-04-17-nothinking", 0.075),
    ("gemini-2.5-flash-preview-05-20", 0.075),
    ("gemini-2.5-flash-preview-05-20-thinking", 0.075),
    ("gemini-2.5-flash-preview-05-20-nothinking", 0.075),
    ("gemini-2.5-flash-thinking-*", 0.075),
    ("gemini-2.5-pro-thinking-*", 0.625),
    ("gemini-2.5-flash-lite-preview-thinking-*", 0.05),
    ("gemini-2.5-flash-lite-preview-06-17", 0.05),
    ("gemini-2.5-flash", 0.15),
    ("gemini-robotics-er-1.5-preview", 0.15),
    ("gemini-embedding-001", 0.075),
    ("text-embedding-004", 0.001),
    ("chatglm_turbo", 0.3572),
    ("chatglm_pro", 0.7143),
    ("chatglm_std", 0.3572),
    ("chatglm_lite", 0.1429),
    ("glm-4", 7.143),
    ("glm-4v", 3.4246575342465757),
    ("glm-4-alltools", 6.849315068493151),
    ("glm-3-turbo", 0.3572),
    ("glm-4-plus", 3.4246575342465757),
    ("glm-4-0520", 6.849315068493151),
    ("glm-4-air", 0.0684931506849315),
    ("glm-4-airx", 0.684931506849315),
    ("glm-4-long", 0.0684931506849315),
    ("glm-4-flash", 0.0),
    ("glm-4v-plus", 0.684931506849315),
    ("qwen-turbo", 0.8572),
    ("qwen-plus", 10.0),
    ("text-embedding-v1", 0.05),
    ("SparkDesk-v1.1", 1.2858),
    ("SparkDesk-v2.1", 1.2858),
    ("SparkDesk-v3.1", 1.2858),
    ("SparkDesk-v3.5", 1.2858),
    ("SparkDesk-v4.0", 1.2858),
    ("hunyuan", 7.143),
    ("yi-34b-chat-0205", 0.18),
    ("yi-34b-chat-200k", 0.864),
    ("yi-vl-plus", 0.432),
    ("yi-large", 1.36986301369863),
    ("yi-medium", 0.17123287671232876),
    ("yi-vision", 0.4109589041095891),
    ("yi-medium-200k", 0.8219178082191781),
    ("yi-spark", 0.0684931506849315),
    ("yi-large-rag", 1.7123287671232879),
    ("yi-large-turbo", 0.8219178082191781),
    ("yi-large-preview", 1.36986301369863),
    ("yi-large-rag-preview", 1.7123287671232879),
    ("command", 0.5),
    ("command-nightly", 0.5),
    ("command-light", 0.5),
    ("command-light-nightly", 0.5),
    ("command-r", 0.25),
    ("command-r-plus", 1.5),
    ("command-r-08-2024", 0.075),
    ("command-r-plus-08-2024", 1.25),
    ("deepseek-chat", 0.135),
    ("deepseek-coder", 0.135),
    ("deepseek-reasoner", 0.275),
    ("llama-3-sonar-small-32k-chat", 0.1),
    ("llama-3-sonar-small-32k-online", 0.1),
    ("llama-3-sonar-large-32k-chat", 0.5),
    ("llama-3-sonar-large-32k-online", 0.5),
    ("grok-3-beta", 1.5),
    ("grok-3-mini-beta", 0.15),
    ("grok-2", 1.0),
    ("grok-2-vision", 1.0),
    ("grok-beta", 2.5),
    ("grok-vision-beta", 2.5),
    ("grok-3-fast-beta", 2.5),
    ("grok-3-mini-fast-beta", 0.3),
    ("NousResearch/Hermes-4-405B-FP8", 0.8),
    ("Qwen/Qwen3-235B-A22B-Thinking-2507", 0.6),
    ("Qwen/Qwen3-Coder-480B-A35B-Instruct-FP8", 0.8),
    ("Qwen/Qwen3-235B-A22B-Instruct-2507", 0.3),
    ("zai-org/GLM-4.5-FP8", 0.8),
    ("openai/gpt-oss-120b", 0.5),
    ("deepseek-ai/DeepSeek-R1-0528", 0.8),
    ("deepseek-ai/DeepSeek-R1", 0.8),
    ("deepseek-ai/DeepSeek-V3-0324", 0.8),
    ("deepseek-ai/DeepSeek-V3.1", 0.8),
];

/// Go `defaultModelPrice`（`configure_model_ratio.go:275-307`）。
const DEFAULT_MODEL_PRICE: [(&str, f64); 31] = [
    ("suno_music", 0.1),
    ("suno_lyrics", 0.01),
    ("dall-e-3", 0.04),
    ("imagen-3.0-generate-002", 0.03),
    ("black-forest-labs/flux-1.1-pro", 0.04),
    ("gpt-4-gizmo-*", 0.1),
    ("mj_video", 0.8),
    ("mj_imagine", 0.1),
    ("mj_edits", 0.1),
    ("mj_variation", 0.1),
    ("mj_reroll", 0.1),
    ("mj_blend", 0.1),
    ("mj_modal", 0.1),
    ("mj_zoom", 0.1),
    ("mj_shorten", 0.1),
    ("mj_high_variation", 0.1),
    ("mj_low_variation", 0.1),
    ("mj_pan", 0.1),
    ("mj_inpaint", 0.0),
    ("mj_custom_zoom", 0.0),
    ("mj_describe", 0.05),
    ("mj_upscale", 0.05),
    ("swap_face", 0.05),
    ("mj_upload", 0.05),
    ("sora-2", 0.3),
    ("sora-2-pro", 0.5),
    ("gpt-4o-mini-tts", 0.3),
    ("veo-3.0-generate-001", 0.4),
    ("veo-3.0-fast-generate-001", 0.15),
    ("veo-3.1-generate-preview", 0.4),
    ("veo-3.1-fast-generate-preview", 0.15),
];

/// Go `defaultCompletionRatio`（`configure_model_ratio.go:331-336`）。
const DEFAULT_COMPLETION_RATIO: [(&str, f64); 4] = [
    ("gpt-4-gizmo-*", 2.0),
    ("gpt-4o-gizmo-*", 3.0),
    ("gpt-4-all", 2.0),
    ("gpt-image-1", 8.0),
];

/// Go `defaultImageRatio`（`configure_model_ratio.go:654-656`）。
const DEFAULT_IMAGE_RATIO: [(&str, f64); 1] = [("gpt-image-1", 2.0)];

/// Go `defaultAudioRatio`（`configure_model_ratio.go:309-315`）。
const DEFAULT_AUDIO_RATIO: [(&str, f64); 5] = [
    ("gpt-4o-audio-preview", 16.0),
    ("gpt-4o-mini-audio-preview", 66.67),
    ("gpt-4o-realtime-preview", 8.0),
    ("gpt-4o-mini-realtime-preview", 16.67),
    ("gpt-4o-mini-tts", 25.0),
];

/// Go `defaultAudioCompletionRatio`（`configure_model_ratio.go:317-325`）。
const DEFAULT_AUDIO_COMPLETION_RATIO: [(&str, f64); 7] = [
    ("gpt-4o-realtime", 2.0),
    ("gpt-4o-mini-realtime", 2.0),
    ("gpt-4o-mini-tts", 1.0),
    ("tts-1", 0.0),
    ("tts-1-hd", 0.0),
    ("tts-1-1106", 0.0),
    ("tts-1-hd-1106", 0.0),
];

/// Go `defaultCacheRatio`（`configure_cache_ratio.go:7-81`）。
const DEFAULT_CACHE_RATIO: [(&str, f64); 73] = [
    ("gemini-3-flash-preview", 0.1),
    ("gemini-3-pro-preview", 0.1),
    ("gemini-3.1-pro-preview", 0.1),
    ("gpt-4", 0.5),
    ("o1", 0.5),
    ("o1-2024-12-17", 0.5),
    ("o1-preview-2024-09-12", 0.5),
    ("o1-preview", 0.5),
    ("o1-mini-2024-09-12", 0.5),
    ("o1-mini", 0.5),
    ("o3-mini", 0.5),
    ("o3-mini-2025-01-31", 0.5),
    ("gpt-4o-2024-11-20", 0.5),
    ("gpt-4o-2024-08-06", 0.5),
    ("gpt-4o", 0.5),
    ("gpt-4o-mini-2024-07-18", 0.5),
    ("gpt-4o-mini", 0.5),
    ("gpt-4o-realtime-preview", 0.5),
    ("gpt-4o-mini-realtime-preview", 0.5),
    ("gpt-4.5-preview", 0.5),
    ("gpt-4.5-preview-2025-02-27", 0.5),
    ("gpt-4.1", 0.25),
    ("gpt-4.1-mini", 0.25),
    ("gpt-4.1-nano", 0.25),
    ("gpt-5", 0.1),
    ("gpt-5-2025-08-07", 0.1),
    ("gpt-5-chat-latest", 0.1),
    ("gpt-5-mini", 0.1),
    ("gpt-5-mini-2025-08-07", 0.1),
    ("gpt-5-nano", 0.1),
    ("gpt-5-nano-2025-08-07", 0.1),
    ("deepseek-chat", 0.25),
    ("deepseek-reasoner", 0.25),
    ("deepseek-coder", 0.25),
    ("claude-3-sonnet-20240229", 0.1),
    ("claude-3-opus-20240229", 0.1),
    ("claude-3-haiku-20240307", 0.1),
    ("claude-3-5-haiku-20241022", 0.1),
    ("claude-haiku-4-5-20251001", 0.1),
    ("claude-3-5-sonnet-20240620", 0.1),
    ("claude-3-5-sonnet-20241022", 0.1),
    ("claude-3-7-sonnet-20250219", 0.1),
    ("claude-3-7-sonnet-20250219-thinking", 0.1),
    ("claude-sonnet-4-20250514", 0.1),
    ("claude-sonnet-4-20250514-thinking", 0.1),
    ("claude-opus-4-20250514", 0.1),
    ("claude-opus-4-20250514-thinking", 0.1),
    ("claude-opus-4-1-20250805", 0.1),
    ("claude-opus-4-1-20250805-thinking", 0.1),
    ("claude-sonnet-4-5-20250929", 0.1),
    ("claude-sonnet-4-5-20250929-thinking", 0.1),
    ("claude-opus-4-5-20251101", 0.1),
    ("claude-opus-4-5-20251101-thinking", 0.1),
    ("claude-opus-4-6", 0.1),
    ("claude-opus-4-6-thinking", 0.1),
    ("claude-opus-4-6-max", 0.1),
    ("claude-opus-4-6-high", 0.1),
    ("claude-opus-4-6-medium", 0.1),
    ("claude-opus-4-6-low", 0.1),
    ("claude-opus-4-7", 0.1),
    ("claude-opus-4-7-thinking", 0.1),
    ("claude-opus-4-7-max", 0.1),
    ("claude-opus-4-7-xhigh", 0.1),
    ("claude-opus-4-7-high", 0.1),
    ("claude-opus-4-7-medium", 0.1),
    ("claude-opus-4-7-low", 0.1),
    ("claude-opus-4-8", 0.1),
    ("claude-opus-4-8-thinking", 0.1),
    ("claude-opus-4-8-max", 0.1),
    ("claude-opus-4-8-xhigh", 0.1),
    ("claude-opus-4-8-high", 0.1),
    ("claude-opus-4-8-medium", 0.1),
    ("claude-opus-4-8-low", 0.1),
];

/// Go `defaultCreateCacheRatio`（`configure_cache_ratio.go:83-126`）。
const DEFAULT_CREATE_CACHE_RATIO: [(&str, f64); 42] = [
    ("gpt-5.6-sol", 1.25),
    ("gpt-5.6-terra", 1.25),
    ("gpt-5.6-luna", 1.25),
    ("claude-3-sonnet-20240229", 1.25),
    ("claude-3-opus-20240229", 1.25),
    ("claude-3-haiku-20240307", 1.25),
    ("claude-3-5-haiku-20241022", 1.25),
    ("claude-haiku-4-5-20251001", 1.25),
    ("claude-3-5-sonnet-20240620", 1.25),
    ("claude-3-5-sonnet-20241022", 1.25),
    ("claude-3-7-sonnet-20250219", 1.25),
    ("claude-3-7-sonnet-20250219-thinking", 1.25),
    ("claude-sonnet-4-20250514", 1.25),
    ("claude-sonnet-4-20250514-thinking", 1.25),
    ("claude-opus-4-20250514", 1.25),
    ("claude-opus-4-20250514-thinking", 1.25),
    ("claude-opus-4-1-20250805", 1.25),
    ("claude-opus-4-1-20250805-thinking", 1.25),
    ("claude-sonnet-4-5-20250929", 1.25),
    ("claude-sonnet-4-5-20250929-thinking", 1.25),
    ("claude-opus-4-5-20251101", 1.25),
    ("claude-opus-4-5-20251101-thinking", 1.25),
    ("claude-opus-4-6", 1.25),
    ("claude-opus-4-6-thinking", 1.25),
    ("claude-opus-4-6-max", 1.25),
    ("claude-opus-4-6-high", 1.25),
    ("claude-opus-4-6-medium", 1.25),
    ("claude-opus-4-6-low", 1.25),
    ("claude-opus-4-7", 1.25),
    ("claude-opus-4-7-thinking", 1.25),
    ("claude-opus-4-7-max", 1.25),
    ("claude-opus-4-7-xhigh", 1.25),
    ("claude-opus-4-7-high", 1.25),
    ("claude-opus-4-7-medium", 1.25),
    ("claude-opus-4-7-low", 1.25),
    ("claude-opus-4-8", 1.25),
    ("claude-opus-4-8-thinking", 1.25),
    ("claude-opus-4-8-max", 1.25),
    ("claude-opus-4-8-xhigh", 1.25),
    ("claude-opus-4-8-high", 1.25),
    ("claude-opus-4-8-medium", 1.25),
    ("claude-opus-4-8-low", 1.25),
];

// ---------------------------------------------------------------------------
// 纯函数：模型名折叠与硬编码补全倍率
// ---------------------------------------------------------------------------

/// Go `FormatMatchingModelName`（`configure_model_ratio.go:718-735`）：
/// gemini thinking 预算模型折叠到通配名，gizmo 前缀折叠；其余原样。
pub fn format_matching_model_name(name: &str) -> String {
    let mut name = name.to_owned();
    // Go `handleThinkingBudgetModel`：前缀命中且含 "-thinking-" 才折叠。
    let thinking = |name: &str, prefix: &str, wildcard: &str| -> String {
        if name.starts_with(prefix) && name.contains("-thinking-") {
            wildcard.to_owned()
        } else {
            name.to_owned()
        }
    };
    if name.starts_with("gemini-2.5-flash-lite") {
        name = thinking(
            &name,
            "gemini-2.5-flash-lite",
            "gemini-2.5-flash-lite-thinking-*",
        );
    } else if name.starts_with("gemini-2.5-flash") {
        name = thinking(&name, "gemini-2.5-flash", "gemini-2.5-flash-thinking-*");
    } else if name.starts_with("gemini-2.5-pro") {
        name = thinking(&name, "gemini-2.5-pro", "gemini-2.5-pro-thinking-*");
    }
    if name.starts_with("gpt-4-gizmo") {
        name = "gpt-4-gizmo-*".to_owned();
    }
    if name.starts_with("gpt-4o-gizmo") {
        name = "gpt-4o-gizmo-*".to_owned();
    }
    name
}

/// Go `getHardcodedCompletionModelRatio`
/// （`configure_model_ratio.go:491-620`）：内置补全倍率级联，返回
/// `(ratio, locked)`。分支顺序即契约。
pub fn hardcoded_completion_ratio(name: &str) -> (f64, bool) {
    if name.ends_with("-all") || name.ends_with("-gizmo-*") {
        return (2.0, false);
    }
    if name.starts_with("gpt-") {
        if name.starts_with("gpt-4o") {
            if name == "gpt-4o-2024-05-13" {
                return (3.0, true);
            }
            if name.starts_with("gpt-4o-mini-tts") {
                return (20.0, false);
            }
            return (4.0, false);
        }
        if name.starts_with("gpt-5") {
            if !name.contains('.') {
                return (8.0, true);
            }
            if name.starts_with("gpt-5.4") {
                if name.starts_with("gpt-5.4-nano") {
                    return (6.25, true);
                }
                return (6.0, true);
            }
            return (6.0, false);
        }
        if name.starts_with("gpt-4.5-preview") {
            return (2.0, true);
        }
        if name.starts_with("gpt-4-turbo")
            || name.ends_with("gpt-4-1106")
            || name.ends_with("gpt-4-1105")
        {
            return (3.0, true);
        }
        return (2.0, false);
    }
    if name.starts_with("o1") || name.starts_with("o3") {
        return (4.0, true);
    }
    if name == "chatgpt-4o-latest" {
        return (3.0, true);
    }
    if name.contains("claude-3")
        || name.contains("claude-sonnet-4")
        || name.contains("claude-opus-4")
        || name.contains("claude-haiku-4")
    {
        return (5.0, true);
    }
    if name.starts_with("gpt-3.5") {
        if name == "gpt-3.5-turbo" || name.ends_with("0125") {
            return (3.0, true);
        }
        if name.ends_with("1106") {
            return (2.0, true);
        }
        return (4.0 / 3.0, true);
    }
    if name.starts_with("mistral-") {
        return (3.0, true);
    }
    if name.starts_with("gemini-") {
        if name.starts_with("gemini-1.5") || name.starts_with("gemini-2.0") {
            return (4.0, true);
        } else if name.starts_with("gemini-2.5-pro") {
            return (8.0, false);
        } else if name.starts_with("gemini-2.5-flash") {
            if name.starts_with("gemini-2.5-flash-preview") {
                if name.ends_with("-nothinking") {
                    return (4.0, false);
                }
                return (3.5 / 0.15, false);
            }
            if name.starts_with("gemini-2.5-flash-lite") {
                return (4.0, false);
            }
            return (2.5 / 0.3, false);
        } else if name.starts_with("gemini-robotics-er-1.5") {
            return (2.5 / 0.3, false);
        } else if name.starts_with("gemini-3-pro") {
            if name.starts_with("gemini-3-pro-image") {
                return (60.0, false);
            }
            return (6.0, false);
        }
        return (4.0, false);
    }
    if name.starts_with("command") {
        return match name {
            "command-r" => (3.0, true),
            "command-r-plus" => (5.0, true),
            "command-r-08-2024" => (4.0, true),
            "command-r-plus-08-2024" => (4.0, true),
            _ => (4.0, false),
        };
    }
    if name.starts_with("ERNIE-Speed-")
        || name.starts_with("ERNIE-Lite-")
        || name.starts_with("ERNIE-Character")
        || name.starts_with("ERNIE-Functions")
    {
        return (2.0, true);
    }
    match name {
        "llama2-70b-4096" => (0.8 / 0.64, true),
        "llama3-8b-8192" => (2.0, true),
        "llama3-70b-8192" => (0.79 / 0.59, true),
        _ => (1.0, false),
    }
}

/// Go `GetCompletionRatioInfo`（`configure_model_ratio.go:458-490`）：覆盖层
/// （`CompletionRatio` 选项解析出的 map）优先于内置级联；`/` 分隔的模型名
/// 只查覆盖层。返回 `(ratio, locked)`。
pub fn completion_ratio_info(name: &str, override_map: &BTreeMap<String, f64>) -> (f64, bool) {
    let formatted = format_matching_model_name(name);
    if formatted.contains('/')
        && let Some(ratio) = override_map.get(&formatted)
    {
        return (*ratio, false);
    }
    let (hardcoded, locked) = hardcoded_completion_ratio(&formatted);
    if locked {
        return (hardcoded, true);
    }
    if let Some(ratio) = override_map.get(&formatted) {
        return (*ratio, false);
    }
    (hardcoded, false)
}

/// Go `WithCompactModelSuffix`（`compact_suffix.go:10-14`）。
pub fn with_compact_model_suffix(model_name: &str) -> String {
    if model_name.ends_with(COMPACT_MODEL_SUFFIX) {
        model_name.to_owned()
    } else {
        format!("{model_name}{COMPACT_MODEL_SUFFIX}")
    }
}

// ---------------------------------------------------------------------------
// RatioSettings 快照
// ---------------------------------------------------------------------------

/// Go 八个 ratio RWMap 的快照结构。`load` 之前 = 内置默认表
/// （Go `InitRatioSettings`）。
#[derive(Clone, Debug, PartialEq)]
pub struct RatioSettings {
    pub model_price: BTreeMap<String, f64>,
    pub model_ratio: BTreeMap<String, f64>,
    pub completion_ratio: BTreeMap<String, f64>,
    pub cache_ratio: BTreeMap<String, f64>,
    pub create_cache_ratio: BTreeMap<String, f64>,
    pub image_ratio: BTreeMap<String, f64>,
    pub audio_ratio: BTreeMap<String, f64>,
    pub audio_completion_ratio: BTreeMap<String, f64>,
}

fn map_from_table(table: &[(&str, f64)]) -> BTreeMap<String, f64> {
    table.iter().map(|(k, v)| ((*k).to_owned(), *v)).collect()
}

/// Go `LoadFromJsonString` 的解析语义：整体替换；JSON 非法或含非数值条目
/// 时返回 `None`（调用方保留旧 map）。
fn parse_ratio_json(raw: &str) -> Option<BTreeMap<String, f64>> {
    let parsed: serde_json::Map<String, serde_json::Value> = serde_json::from_str(raw).ok()?;
    let mut map = BTreeMap::new();
    for (key, value) in parsed {
        let ratio = value.as_f64()?;
        map.insert(key, ratio);
    }
    Some(map)
}

impl RatioSettings {
    /// Go `InitRatioSettings`：全部默认表。
    pub fn defaults() -> Self {
        Self {
            model_price: map_from_table(&DEFAULT_MODEL_PRICE),
            model_ratio: map_from_table(&DEFAULT_MODEL_RATIO),
            completion_ratio: map_from_table(&DEFAULT_COMPLETION_RATIO),
            cache_ratio: map_from_table(&DEFAULT_CACHE_RATIO),
            create_cache_ratio: map_from_table(&DEFAULT_CREATE_CACHE_RATIO),
            image_ratio: map_from_table(&DEFAULT_IMAGE_RATIO),
            audio_ratio: map_from_table(&DEFAULT_AUDIO_RATIO),
            audio_completion_ratio: map_from_table(&DEFAULT_AUDIO_COMPLETION_RATIO),
        }
    }

    /// Go `applyRatioOption`（`register_option_hooks.go:26-45`）：选项键 →
    /// 对应 map 整体替换。键不认识时是 no-op；JSON 解析失败返回 `false`
    /// （调用方保留旧值并记日志），成功返回 `true`。
    pub fn apply_option(&mut self, key: &str, value: &str) -> bool {
        let Some(parsed) = parse_ratio_json(value) else {
            return false;
        };
        match key {
            "ModelRatio" => self.model_ratio = parsed,
            "ModelPrice" => self.model_price = parsed,
            "CompletionRatio" => self.completion_ratio = parsed,
            "CacheRatio" => self.cache_ratio = parsed,
            "CreateCacheRatio" => self.create_cache_ratio = parsed,
            "ImageRatio" => self.image_ratio = parsed,
            "AudioRatio" => self.audio_ratio = parsed,
            "AudioCompletionRatio" => self.audio_completion_ratio = parsed,
            _ => {}
        }
        true
    }

    /// 从 `options` 表装载八个 ratio 键。约定与 [`crate::group_settings`] 一致：
    /// 缺失行保留 `previous`（首次装载 `previous` = 默认表，对齐 Go 首次
    /// seed 用默认 map 的序列化值）；行值 JSON 解析失败同样保留 `previous`
    /// （Go `SyncOptions` 对 apply 错误记日志、运行时 map 保持 last-good）。
    pub async fn load(db: &newapi_storage::Database, previous: &Self) -> Result<Self, sqlx::Error> {
        const KEYS: [&str; 8] = [
            "ModelRatio",
            "ModelPrice",
            "CompletionRatio",
            "CacheRatio",
            "CreateCacheRatio",
            "ImageRatio",
            "AudioRatio",
            "AudioCompletionRatio",
        ];
        let mut next = previous.clone();
        let rows: Vec<(String, String)> = match db {
            newapi_storage::Database::Sqlite(pool) => {
                sqlx::query_as(
                    "SELECT key, value FROM options WHERE key IN (?, ?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(KEYS[0])
                .bind(KEYS[1])
                .bind(KEYS[2])
                .bind(KEYS[3])
                .bind(KEYS[4])
                .bind(KEYS[5])
                .bind(KEYS[6])
                .bind(KEYS[7])
                .fetch_all(pool)
                .await?
            }
            newapi_storage::Database::Postgres(pool) => {
                sqlx::query_as("SELECT key, value FROM options WHERE key = ANY($1::TEXT[])")
                    .bind(KEYS)
                    .fetch_all(pool)
                    .await?
            }
        };
        for (key, value) in rows {
            // Go：解析失败 → 日志 + 保留旧 map；这里静默保留（reload 边界
            // 已有 category 日志）。
            let _ = next.apply_option(&key, &value);
        }
        Ok(next)
    }

    /// Go `GetModelPrice`（`configure_model_ratio.go:359-381`）：compact
    /// 后缀折叠到通配键；未命中 `None`（Go `(-1, false)`）。
    pub fn get_model_price(&self, name: &str) -> Option<f64> {
        let name = format_matching_model_name(name);
        if let Some(price) = self.model_price.get(&name) {
            return Some(*price);
        }
        if name.ends_with(COMPACT_MODEL_SUFFIX) {
            return self.model_price.get(COMPACT_WILDCARD_MODEL_KEY).copied();
        }
        None
    }

    /// Go `GetModelRatio`（`configure_model_ratio.go:395-409`）：返回
    /// `(ratio, found, formatted_name)`；未命中 compact 折叠；仍未命中回
    /// `(37.5, self_use_mode_enabled)`。
    pub fn get_model_ratio(&self, name: &str) -> (f64, bool, String) {
        let name = format_matching_model_name(name);
        if let Some(ratio) = self.model_ratio.get(&name) {
            return (*ratio, true, name.clone());
        }
        if name.ends_with(COMPACT_MODEL_SUFFIX)
            && let Some(ratio) = self.model_ratio.get(COMPACT_WILDCARD_MODEL_KEY)
        {
            return (*ratio, true, name);
        }
        (37.5, self_use_mode_enabled(), name)
    }

    /// Go `GetCompletionRatio`（`configure_model_ratio.go:435-451`）。
    pub fn get_completion_ratio(&self, name: &str) -> f64 {
        completion_ratio_info(name, &self.completion_ratio).0
    }

    /// Go `GetCacheRatio`（`configure_cache_ratio.go:159-165`）：未命中
    /// `None`（Go `(1, false)`）。
    pub fn get_cache_ratio(&self, name: &str) -> Option<f64> {
        self.cache_ratio.get(name).copied()
    }

    /// Go `GetCreateCacheRatio`（`configure_cache_ratio.go:167-173`）。
    pub fn get_create_cache_ratio(&self, name: &str) -> Option<f64> {
        self.create_cache_ratio.get(name).copied()
    }

    /// Go `GetImageRatio`（`configure_model_ratio.go:669-675`）。
    pub fn get_image_ratio(&self, name: &str) -> Option<f64> {
        self.image_ratio.get(name).copied()
    }

    /// Go `ContainsAudioRatio`（`configure_model_ratio.go:638-642`）。
    pub fn contains_audio_ratio(&self, name: &str) -> bool {
        self.audio_ratio
            .contains_key(&format_matching_model_name(name))
    }

    /// Go `GetAudioRatio`（`configure_model_ratio.go:622-628`）：未命中 1。
    pub fn get_audio_ratio(&self, name: &str) -> f64 {
        self.audio_ratio
            .get(&format_matching_model_name(name))
            .copied()
            .unwrap_or(1.0)
    }

    /// Go `ContainsAudioCompletionRatio`。
    pub fn contains_audio_completion_ratio(&self, name: &str) -> bool {
        self.audio_completion_ratio
            .contains_key(&format_matching_model_name(name))
    }

    /// Go `GetAudioCompletionRatio`：未命中 1。
    pub fn get_audio_completion_ratio(&self, name: &str) -> f64 {
        self.audio_completion_ratio
            .get(&format_matching_model_name(name))
            .copied()
            .unwrap_or(1.0)
    }
}

impl Default for RatioSettings {
    fn default() -> Self {
        Self::defaults()
    }
}
