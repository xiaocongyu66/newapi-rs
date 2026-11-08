use super::CheckinSettings;
use super::store::{
    KEY_ENABLED, KEY_MAX_QUOTA, KEY_MIN_QUOTA, KEY_REQUIRE_QQ_BOUND, KEY_SINGLE_PLATFORM_ONLY,
    apply_option, random_quota,
};
use super::{CheckinError, CheckinRepository, today};

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

#[test]
fn require_qq_bound_defaults_false_and_parses_like_the_other_bools() {
    // Go `do_checkin_setting.go:34` 的缺省。
    assert!(!CheckinSettings::default().require_qq_bound);
    for raw in ["1", "t", "T", "TRUE", "true", "True"] {
        assert!(
            apply(&[(KEY_REQUIRE_QQ_BOUND, raw)]).require_qq_bound,
            "{raw} should parse true"
        );
    }
    for raw in ["0", "f", "F", "FALSE", "false", "False"] {
        assert!(
            !apply(&[(KEY_REQUIRE_QQ_BOUND, raw)]).require_qq_bound,
            "{raw} should parse false"
        );
    }
    // 集合外保留当前值（Go `ParseBool` 失败的 `continue`）。
    for raw in ["yes", "no", "on", "off", "", "2"] {
        assert!(
            !apply(&[(KEY_REQUIRE_QQ_BOUND, raw)]).require_qq_bound,
            "{raw} should keep the default"
        );
    }
}

#[test]
fn random_quota_clamps_the_range_like_go() {
    // 相等区间不产生随机：Go 直接返回 min_quota。
    assert_eq!(random_quota(7777, 7777), 7777);
    // 负数下限钳到 0（Go `if minQuota < 0`）。
    assert_eq!(random_quota(-500, 0), 0);
    assert_eq!(random_quota(-500, -1), 0);
    // 反向区间把上限抬到下限（Go `if maxQuota < minQuota`）。
    assert_eq!(random_quota(3000, 1000), 3000);
    // 宽度区间的取值必须落在闭区间内；与 Go 一样不是密码学随机，只验范围。
    for min in [0, 1, 7, 1_000] {
        for max in [min, min + 1, min + 100, 10_000] {
            let awarded = random_quota(min, max);
            assert!(
                (min..=max).contains(&awarded),
                "award {awarded} outside [{min}, {max}]"
            );
        }
    }
}

/// 事务内重判必须跨 `qq_checkins`（Go `store_checkin.go:179` 调
/// `alreadyCheckedToday`，单平台模式下跨两表）。`already_checked_today` 的
/// 预判已跨表，所以这条测试直接打 `checkin()`：`checkins` 空、`qq_checkins`
/// 有今日行，单平台模式下必须报已签到且不写任何行。
#[tokio::test]
async fn the_in_transaction_recheck_covers_qq_checkins() {
    let pool = sqlx::SqlitePool::connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite");
    sqlx::query("CREATE TABLE users (id INTEGER PRIMARY KEY, quota INTEGER NOT NULL)")
        .execute(&pool)
        .await
        .expect("users");
    sqlx::query(
        "CREATE TABLE checkins (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, \
         checkin_date TEXT NOT NULL, quota_awarded INTEGER NOT NULL, created_at INTEGER)",
    )
    .execute(&pool)
    .await
    .expect("checkins");
    sqlx::query(
        "CREATE TABLE qq_checkins (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, \
         checkin_date TEXT NOT NULL, quota_awarded INTEGER NOT NULL, open_id TEXT, \
         group_open_id TEXT, created_at INTEGER)",
    )
    .execute(&pool)
    .await
    .expect("qq_checkins");
    sqlx::query("INSERT INTO users (id, quota) VALUES (1, 100)")
        .execute(&pool)
        .await
        .expect("seed user");
    // 今日只有 QQ 侧一行；`checkins` 为空。
    sqlx::query(
        "INSERT INTO qq_checkins (id, user_id, checkin_date, quota_awarded) \
         VALUES (1, 1, $1, 123)",
    )
    .bind(today())
    .execute(&pool)
    .await
    .expect("seed qq checkin");

    let repository = CheckinRepository::new(newapi_storage::Database::Sqlite(pool.clone()));
    let outcome = repository.checkin(1, 7_777, true).await;
    assert_eq!(
        outcome,
        Err(CheckinError::AlreadyCheckedToday),
        "a QQ row for today must block the web channel under single-platform"
    );
    // 拒绝时不得留下任何 `checkins` 行，也不得改额度。
    let web_rows: i64 =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM checkins WHERE user_id = 1")
            .fetch_one(&pool)
            .await
            .expect("web rows");
    assert_eq!(web_rows, 0);
    let quota: i64 = sqlx::query_scalar::<_, i64>("SELECT quota FROM users WHERE id = 1")
        .fetch_one(&pool)
        .await
        .expect("quota");
    assert_eq!(quota, 100);
}
