use std::collections::BTreeMap;

use newapi_storage::Database;

use super::{QuotaDisplay, QuotaDisplayType};

pub(super) const QUOTA_PER_UNIT: &str = "QuotaPerUnit";
pub(super) const USD_EXCHANGE_RATE: &str = "USDExchangeRate";
pub(super) const DISPLAY_TYPE: &str = "general_setting.quota_display_type";
pub(super) const CUSTOM_RATE: &str = "general_setting.custom_currency_exchange_rate";
pub(super) const KEYS: [&str; 4] = [
    QUOTA_PER_UNIT,
    USD_EXCHANGE_RATE,
    DISPLAY_TYPE,
    CUSTOM_RATE,
];

pub(super) async fn load(
    db: &Database,
    previous: &QuotaDisplay,
) -> Result<QuotaDisplay, sqlx::Error> {
    let rows: Vec<(String, Option<String>)> = match db {
        Database::Sqlite(pool) => sqlx::query_as(
            "SELECT \"key\", \"value\" FROM \"options\" \
             WHERE \"key\" IN (?, ?, ?, ?)",
        )
        .bind(KEYS[0])
        .bind(KEYS[1])
        .bind(KEYS[2])
        .bind(KEYS[3])
        .fetch_all(pool)
        .await?,
        Database::Postgres(pool) => sqlx::query_as(
            "SELECT \"key\", \"value\" FROM \"options\" \
             WHERE \"key\" IN ($1, $2, $3, $4)",
        )
        .bind(KEYS[0])
        .bind(KEYS[1])
        .bind(KEYS[2])
        .bind(KEYS[3])
        .fetch_all(pool)
        .await?,
    };
    // Go 的选项应用对 SQL NULL 按空字符串处理；NULL 不是这里的错误分支。
    let values: BTreeMap<&'static str, String> = rows
        .into_iter()
        .filter_map(|(key, value)| {
            KEYS.iter()
                .find(|candidate| **candidate == key)
                .map(|candidate| (*candidate, value.unwrap_or_default()))
        })
        .collect();
    Ok(apply(&values, previous))
}

/// 纯解析：行存在但无法解析时保留旧值（Go `ParseFloat` 忽略错误）；
/// 行不存在时保留快照既有值（初始即默认值）。
pub(super) fn apply(values: &BTreeMap<&'static str, String>, previous: &QuotaDisplay) -> QuotaDisplay {
    let mut next = *previous;
    if let Some(value) = parse_float(values, QUOTA_PER_UNIT) {
        next.quota_per_unit = value;
    }
    if let Some(value) = parse_float(values, USD_EXCHANGE_RATE) {
        next.usd_exchange_rate = value;
    }
    if let Some(value) = values.get(DISPLAY_TYPE) {
        // Go 接受任意字符串，QuotaToDisplayAmount 的 default 分支等同 USD。
        next.display_type = match value.as_str() {
            "CNY" => QuotaDisplayType::Cny,
            "CUSTOM" => QuotaDisplayType::Custom,
            "TOKENS" => QuotaDisplayType::Tokens,
            _ => QuotaDisplayType::Usd,
        };
    }
    if let Some(value) = parse_float(values, CUSTOM_RATE) {
        next.custom_rate = value;
    }
    next
}

pub(super) fn parse_float(values: &BTreeMap<&'static str, String>, key: &str) -> Option<f64> {
    values
        .get(key)?
        .parse::<f64>()
        .ok()
        .filter(|value| value.is_finite())
}
