use super::CheckinSettings;
use super::store::{
    KEY_ENABLED, KEY_MAX_QUOTA, KEY_MIN_QUOTA, KEY_SINGLE_PLATFORM_ONLY, apply_option,
};

fn apply(pairs: &[(&str, &str)]) -> CheckinSettings {
    let mut settings = CheckinSettings::default();
    for (key, value) in pairs {
        apply_option(&mut settings, key, value);
    }
    settings
}

#[test]
fn defaults_match_go_process_defaults() {
    let settings = CheckinSettings::default();
    assert!(!settings.enabled);
    assert_eq!(settings.min_quota, 1_000);
    assert_eq!(settings.max_quota, 10_000);
    assert!(settings.single_platform_only);
    // 空选项集不改变任何默认值（Go `len(configMap) > 0` 前置同样为空转默认）。
    assert_eq!(apply(&[]), settings);
}

#[test]
fn bool_options_follow_strconv_parsebool() {
    for raw in ["1", "t", "T", "TRUE", "true", "True"] {
        assert!(
            apply(&[(KEY_ENABLED, raw)]).enabled,
            "{raw} should parse true"
        );
    }
    for raw in ["0", "f", "F", "FALSE", "false", "False"] {
        assert!(
            !apply(&[(KEY_ENABLED, raw)]).enabled,
            "{raw} should parse false"
        );
    }
    // Go `ParseBool` 集合之外：保留当前值（首次加载即默认 false）。
    for raw in ["yes", "no", "on", "off", "", "2"] {
        assert!(
            !apply(&[(KEY_ENABLED, raw)]).enabled,
            "{raw} must keep the default"
        );
    }
}

#[test]
fn int_options_keep_the_default_when_unparseable() {
    // Go `updateConfigFromMap` 的 int 分支：两者都失败才 `continue`。
    assert_eq!(apply(&[(KEY_MIN_QUOTA, "abc")]).min_quota, 1_000);
    assert_eq!(apply(&[(KEY_MIN_QUOTA, "")]).min_quota, 1_000);
    assert_eq!(apply(&[(KEY_MAX_QUOTA, "12x")]).max_quota, 10_000);
    // 区间本身不受钳制：钳制只发生在 POST 的 `evaluateDailyCheckin`。
    assert_eq!(apply(&[(KEY_MIN_QUOTA, "-5")]).min_quota, -5);
    assert_eq!(apply(&[(KEY_MAX_QUOTA, "0")]).max_quota, 0);
}

#[test]
fn int_options_fall_back_to_parsefloat_truncation() {
    // Go `strconv.ParseInt` 失败后退回 `ParseFloat` 再 `int64()` 截断。
    assert_eq!(apply(&[(KEY_MIN_QUOTA, "2000.9")]).min_quota, 2_000);
    assert_eq!(apply(&[(KEY_MIN_QUOTA, "-2000.9")]).min_quota, -2_000);
    assert_eq!(apply(&[(KEY_MIN_QUOTA, "1500")]).min_quota, 1_500);
}

#[test]
fn a_bad_row_keeps_the_value_a_good_row_set() {
    // 同一加载周期内坏行不得把已应用的好值冲掉（Go 逐字段 `continue`）。
    let settings = apply(&[
        (KEY_MIN_QUOTA, "500"),
        (KEY_MAX_QUOTA, "not-a-number"),
        (KEY_SINGLE_PLATFORM_ONLY, "0"),
    ]);
    assert_eq!(settings.min_quota, 500);
    assert_eq!(settings.max_quota, 10_000);
    assert!(!settings.single_platform_only);
}
