//! 计费设置：Go `consume_quota_setting.go`（1-23 行）。
//!
//! Go 注册到全局配置管理器（settings.GlobalConfig.Register）；Rust 侧由
//! config 切片的 options 管线注入，这里只承载字段与默认值。

/// Go `QuotaSetting`。
#[derive(Debug, Clone, PartialEq)]
pub struct QuotaSetting {
    /// 是否对免费模型启用预消耗。
    pub enable_free_model_pre_consume: bool,
    /// 空响应扣费倍率（0-1），0 表示全额豁免。
    pub empty_response_multiplier: f64,
}

impl Default for QuotaSetting {
    fn default() -> Self {
        Self {
            enable_free_model_pre_consume: true,
            empty_response_multiplier: 0.1,
        }
    }
}

impl QuotaSetting {
    /// Go `GetQuotaSetting().EmptyResponseMultiplier` 的 clamp 语义在
    /// [`crate::billing_session::text_quota::apply_empty_response_multiplier`]
    /// 内执行（NaN/<0 → 0，>1 → 1）。
    pub fn effective_empty_response_multiplier(&self) -> f64 {
        let mut m = self.empty_response_multiplier;
        if m.is_nan() || m < 0.0 {
            m = 0.0;
        }
        if m > 1.0 {
            m = 1.0;
        }
        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_go_process_defaults() {
        let settings = QuotaSetting::default();
        assert!(settings.enable_free_model_pre_consume);
        assert!((settings.empty_response_multiplier - 0.1).abs() < f64::EPSILON);
        assert!((settings.effective_empty_response_multiplier() - 0.1).abs() < f64::EPSILON);
    }
}
