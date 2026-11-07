//! 额度展示快照：对应 Go `billing.QuotaToDisplayAmount` 读取的三项配置。
//!
//! Go 的 hook 读取进程级变量（`common.QuotaPerUnit`、
//! `billing.USDExchangeRate`、`generalSetting.QuotaDisplayType`）；Rust 无
//! 进程级可变配置，这里把它们收敛为随公共配置一起刷新的不可变快照。
//! 渲染算术保持 Go 的分支语义（`newapi_identity::self_user` 的
//! `QuotaDisplaySettings` 只做纯算术，本模块只负责从 options 行解析出它）。

use newapi_storage::Database;

mod store;

/// Go `common.QuotaPerUnit` 默认值（`constants.go:23`）。
const DEFAULT_QUOTA_PER_UNIT: f64 = 500_000.0;
/// Go `billing.USDExchangeRate` 默认值（`pay_subscription.go:73`）。
const DEFAULT_USD_EXCHANGE_RATE: f64 = 7.3;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum QuotaDisplayType {
    Usd,
    Cny,
    Custom,
    Tokens,
}

/// 渲染额度展示值所需的配置；缺失行保留 `previous`，与其余快照一致。
#[derive(Clone, Debug, PartialEq)]
pub struct QuotaDisplay {
    pub quota_per_unit: f64,
    pub usd_exchange_rate: f64,
    pub display_type: QuotaDisplayType,
    /// general_setting.custom_currency_exchange_rate（默认 1.0）。
    pub custom_rate: f64,
    /// general_setting.custom_currency_symbol；`formatQuota` falls back to
    /// "¤" when the option row is present but empty.
    pub custom_currency_symbol: String,
}

impl Default for QuotaDisplay {
    fn default() -> Self {
        Self {
            quota_per_unit: DEFAULT_QUOTA_PER_UNIT,
            usd_exchange_rate: DEFAULT_USD_EXCHANGE_RATE,
            display_type: QuotaDisplayType::Usd,
            custom_rate: 1.0,
            custom_currency_symbol: String::new(),
        }
    }
}

impl QuotaDisplay {
    /// 读取选项并返回完整替换；NULL 行是错误而不是静默默认。
    pub async fn load(db: &Database, previous: &Self) -> Result<Self, sqlx::Error> {
        store::load(db, previous).await
    }
}

#[cfg(test)]
mod tests;
