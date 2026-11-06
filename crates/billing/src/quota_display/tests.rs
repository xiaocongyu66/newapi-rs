use std::collections::BTreeMap;

use super::QuotaDisplay;
use super::store::{CUSTOM_RATE, DISPLAY_TYPE, QUOTA_PER_UNIT, USD_EXCHANGE_RATE, apply};

fn values(pairs: &[(&'static str, &str)]) -> BTreeMap<&'static str, String> {
    pairs
        .iter()
        .map(|(key, value)| (*key, (*value).to_owned()))
        .collect()
}

#[test]
fn defaults_match_go_process_defaults() {
    let display = QuotaDisplay::default();
    assert_eq!(display.quota_per_unit, 500_000.0);
    assert_eq!(display.usd_exchange_rate, 7.3);
    assert_eq!(display.display_type, super::QuotaDisplayType::Usd);
    assert_eq!(display.custom_rate, 1.0);
    // 空选项集不改变任何默认值。
    assert_eq!(apply(&values(&[]), &display), display);
}

#[test]
fn display_types_map_like_the_go_switch() {
    for (raw, expected) in [
        ("USD", super::QuotaDisplayType::Usd),
        ("CNY", super::QuotaDisplayType::Cny),
        ("CUSTOM", super::QuotaDisplayType::Custom),
        ("TOKENS", super::QuotaDisplayType::Tokens),
        // Go 的 switch default 分支等同 USD，未知字符串不落空。
        ("", super::QuotaDisplayType::Usd),
        ("EUR", super::QuotaDisplayType::Usd),
    ] {
        let applied = apply(&values(&[(DISPLAY_TYPE, raw)]), &QuotaDisplay::default());
        assert_eq!(applied.display_type, expected, "raw value {raw:?}");
    }
}

#[test]
fn unparseable_float_options_keep_previous_value() {
    let previous = QuotaDisplay::default();
    // Go `ParseFloat` 错误被忽略：行存在但值非法时保留旧值。
    let applied = apply(
        &values(&[
            (QUOTA_PER_UNIT, "abc"),
            (USD_EXCHANGE_RATE, ""),
            (CUSTOM_RATE, "NaN"),
        ]),
        &previous,
    );
    assert_eq!(applied.quota_per_unit, previous.quota_per_unit);
    assert_eq!(applied.usd_exchange_rate, previous.usd_exchange_rate);
    assert_eq!(applied.custom_rate, previous.custom_rate);

    let applied = apply(
        &values(&[
            (QUOTA_PER_UNIT, "1000000"),
            (USD_EXCHANGE_RATE, "7.25"),
            (CUSTOM_RATE, "0.5"),
        ]),
        &previous,
    );
    assert_eq!(applied.quota_per_unit, 1_000_000.0);
    assert_eq!(applied.usd_exchange_rate, 7.25);
    assert_eq!(applied.custom_rate, 0.5);
}
