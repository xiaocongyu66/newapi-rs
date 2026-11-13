//! 定价数据端口：`types.PriceData`（Go `types/price_data.go:16-33`）的移植 +
//! 倍率设置读取端口 [`RatioSettings`]。
//!
//! 接口约定（与 pricing 切片的对接点）：
//! - pricing 缓存切片合流后应产出 [`PriceData`]（字段语义与 Go 完全一致），
//!   并实现 [`RatioSettings`] 从其缓存读取各倍率；
//! - 在那之前，测试与上层可用 [`StaticRatioSettings`] 注入固定倍率；
//! - [`PriceData::apply_other_ratios`] 复刻 Go `ApplyOtherRatiosToDecimal`：
//!   仅乘有效（>0 且非 +Inf）且 ≠1 的倍率。

use std::collections::HashMap;

/// Go `types.GroupRatioInfo`。
#[derive(Debug, Clone, Default)]
pub struct GroupRatioInfo {
    pub group_ratio: f64,
    pub group_special_ratio: f64,
    pub has_special_ratio: bool,
}

/// Go `types.PriceData`（计费读取面）。
#[derive(Debug, Clone, Default)]
pub struct PriceData {
    pub model_price: f64,
    pub model_ratio: f64,
    pub completion_ratio: f64,
    pub cache_ratio: f64,
    pub cache_creation_ratio: f64,
    pub cache_creation_5m_ratio: f64,
    pub cache_creation_1h_ratio: f64,
    pub image_ratio: f64,
    pub audio_ratio: f64,
    pub audio_completion_ratio: f64,
    pub use_price: bool,
    pub group_ratio_info: GroupRatioInfo,
    /// Go 私有 `otherRatios`：经 AddOtherRatio 注入的附加倍率。
    pub other_ratios: HashMap<String, f64>,
}

fn is_valid_other_ratio(ratio: f64) -> bool {
    ratio > 0.0 && !ratio.is_infinite() && ratio != f64::INFINITY
}

impl PriceData {
    pub fn group_ratio(&self) -> f64 {
        self.group_ratio_info.group_ratio
    }

    /// Go `OtherRatioMultiplier`：有效且 ≠1 的倍率乘积。
    pub fn other_ratio_multiplier(&self) -> f64 {
        let mut multiplier = 1.0;
        for ratio in self.other_ratios.values() {
            if is_valid_other_ratio(*ratio) && *ratio != 1.0 {
                multiplier *= *ratio;
            }
        }
        multiplier
    }

    /// Go `ApplyOtherRatiosToFloat`。
    pub fn apply_other_ratios_to_float(&self, value: f64) -> f64 {
        value * self.other_ratio_multiplier()
    }

    /// Go `ApplyOtherRatiosToDecimal`：逐个乘有效倍率（跳过 1.0）。
    pub fn apply_other_ratios(&self, value: f64) -> f64 {
        let mut value = value;
        for ratio in self.other_ratios.values() {
            if is_valid_other_ratio(*ratio) && *ratio != 1.0 {
                value *= ratio;
            }
        }
        value
    }
}

/// 倍率设置读取端口。对应 Go `ratio_setting.Get*` 全局函数族 +
/// `price_expression.GetToolPriceForModel` / `GetGeminiInputAudioPricePerMillionTokens`。
///
/// pricing 切片合流后由其缓存实现；缺省语义见各方法文档。
pub trait RatioSettings: Send + Sync {
    /// Go `GetCompletionRatio(modelName)`。
    fn completion_ratio(&self, model: &str) -> f64;
    /// Go `GetAudioRatio(modelName)`。
    fn audio_ratio(&self, model: &str) -> f64;
    /// Go `GetAudioCompletionRatio(modelName)`。
    fn audio_completion_ratio(&self, model: &str) -> f64;
    /// Go `GetGroupRatio(group)`。
    fn group_ratio(&self, group: &str) -> f64;
    /// Go `GetModelRatio(modelName)` 的 `(ratio, found)`。
    fn model_ratio(&self, model: &str) -> (f64, bool);
    /// Go `GetGroupGroupRatio(userGroup, group)`：用户分组专属倍率，未配置回 None。
    fn group_group_ratio(&self, user_group: &str, group: &str) -> Option<f64>;
    /// Go `GetDefaultModelRatioMap()[modelName]`：出厂默认倍率，用于判定
    /// 当前倍率是否被用户自定义过（`has_custom_model_ratio`）。
    fn default_model_ratio(&self, model: &str) -> Option<f64>;
    /// Go `price_expression.GetToolPriceForModel(name, modelName)`：每次调用的美元价。
    fn tool_price(&self, tool: &str, model: &str) -> f64;
    /// Go `price_expression.GetGeminiInputAudioPricePerMillionTokens(modelName)`。
    fn gemini_input_audio_price_per_million(&self, model: &str) -> f64;
}

/// 测试替身：HashMap 驱动的固定倍率。生产实现随 pricing 切片提供。
#[derive(Debug, Clone, Default)]
pub struct StaticRatioSettings {
    pub completion_ratios: HashMap<String, f64>,
    pub audio_ratios: HashMap<String, f64>,
    pub audio_completion_ratios: HashMap<String, f64>,
    pub group_ratios: HashMap<String, f64>,
    pub model_ratios: HashMap<String, f64>,
    pub default_model_ratios: HashMap<String, f64>,
    pub group_group_ratios: HashMap<(String, String), f64>,
    pub tool_prices: HashMap<(String, String), f64>,
    pub gemini_audio_prices: HashMap<String, f64>,
    /// 查缺时的回退值（对齐 Go 各 Get* 的缺省分支）。
    pub fallback_completion_ratio: f64,
    pub fallback_audio_ratio: f64,
    pub fallback_audio_completion_ratio: f64,
    pub fallback_group_ratio: f64,
}

impl RatioSettings for StaticRatioSettings {
    fn completion_ratio(&self, model: &str) -> f64 {
        self.completion_ratios
            .get(model)
            .copied()
            .unwrap_or(self.fallback_completion_ratio)
    }
    fn audio_ratio(&self, model: &str) -> f64 {
        self.audio_ratios
            .get(model)
            .copied()
            .unwrap_or(self.fallback_audio_ratio)
    }
    fn audio_completion_ratio(&self, model: &str) -> f64 {
        self.audio_completion_ratios
            .get(model)
            .copied()
            .unwrap_or(self.fallback_audio_completion_ratio)
    }
    fn group_ratio(&self, group: &str) -> f64 {
        self.group_ratios
            .get(group)
            .copied()
            .unwrap_or(self.fallback_group_ratio)
    }
    fn model_ratio(&self, model: &str) -> (f64, bool) {
        match self.model_ratios.get(model) {
            Some(v) => (*v, true),
            None => (0.0, false),
        }
    }
    fn group_group_ratio(&self, user_group: &str, group: &str) -> Option<f64> {
        self.group_group_ratios
            .get(&(user_group.to_string(), group.to_string()))
            .copied()
    }
    fn default_model_ratio(&self, model: &str) -> Option<f64> {
        self.default_model_ratios.get(model).copied()
    }
    fn tool_price(&self, tool: &str, model: &str) -> f64 {
        self.tool_prices
            .get(&(tool.to_string(), model.to_string()))
            .copied()
            .unwrap_or(0.0)
    }
    fn gemini_input_audio_price_per_million(&self, model: &str) -> f64 {
        self.gemini_audio_prices.get(model).copied().unwrap_or(0.0)
    }
}

/// Go `hasCustomModelRatio`（consume_quota_realtime.go:45-51）：
/// 不在默认表内，或当前倍率 ≠ 默认值，即视为自定义。
pub fn has_custom_model_ratio(
    settings: &dyn RatioSettings,
    model: &str,
    current_ratio: f64,
) -> bool {
    match settings.default_model_ratio(model) {
        None => true,
        Some(default) => current_ratio != default,
    }
}
