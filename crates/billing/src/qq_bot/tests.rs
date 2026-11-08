use super::QQBotSettings;
use super::{
    KEY_APP_ID, KEY_APP_SECRET, KEY_CHECKIN_ENABLED, KEY_REBIND_COOLDOWN_SECONDS, apply_option,
};
use newapi_storage::Database;
use sqlx::sqlite::SqlitePoolOptions;

fn apply(pairs: &[(&str, &str)]) -> QQBotSettings {
    let mut settings = QQBotSettings::default();
    for (key, value) in pairs {
        apply_option(&mut settings, key, value);
    }
    settings
}

#[test]
fn defaults_match_go_struct_defaults() {
    let settings = QQBotSettings::default();
    assert!(!settings.qq_checkin_enabled);
    // Go `qqbot_setting.go:204`：1 小时重绑冷却是进程缺省，不是 0。
    assert_eq!(settings.rebind_cooldown_seconds, 3600);
    assert!(settings.app_id.is_empty());
    assert!(settings.app_secret.is_empty());
    // 空选项集不改变任何默认值（Go `len(configMap) > 0` 前置同样为空转默认）。
    assert_eq!(apply(&[]), settings);
}

#[test]
fn checkin_enabled_follows_strconv_parsebool() {
    for raw in ["1", "t", "T", "TRUE", "true", "True"] {
        assert!(
            apply(&[(KEY_CHECKIN_ENABLED, raw)]).qq_checkin_enabled,
            "{raw} should parse true"
        );
    }
    for raw in ["0", "f", "F", "FALSE", "false", "False"] {
        assert!(
            !apply(&[(KEY_CHECKIN_ENABLED, raw)]).qq_checkin_enabled,
            "{raw} should parse false"
        );
    }
    // Go `ParseBool` 集合之外：保留当前值（首次加载即默认 false）。
    for raw in ["yes", "no", "on", "off", "", "2"] {
        assert!(
            !apply(&[(KEY_CHECKIN_ENABLED, raw)]).qq_checkin_enabled,
            "{raw} must keep the default"
        );
    }
}

#[test]
fn rebind_cooldown_keeps_the_default_when_unparseable() {
    // int 分支同样「失败保留当前值」，与 topup 的零覆盖语义不同。
    assert_eq!(
        apply(&[(KEY_REBIND_COOLDOWN_SECONDS, "abc")]).rebind_cooldown_seconds,
        3600
    );
    assert_eq!(
        apply(&[(KEY_REBIND_COOLDOWN_SECONDS, "")]).rebind_cooldown_seconds,
        3600
    );
    // `ParseInt` 失败后退回 `ParseFloat` 再截断。
    assert_eq!(
        apply(&[(KEY_REBIND_COOLDOWN_SECONDS, "7200.9")]).rebind_cooldown_seconds,
        7200
    );
    // 0 是合法值：关闭冷却。
    assert_eq!(
        apply(&[(KEY_REBIND_COOLDOWN_SECONDS, "0")]).rebind_cooldown_seconds,
        0
    );
    assert_eq!(
        apply(&[(KEY_REBIND_COOLDOWN_SECONDS, "-1")]).rebind_cooldown_seconds,
        -1
    );
}

#[test]
fn credentials_are_overwritten_including_empty_strings() {
    let configured = apply(&[(KEY_APP_ID, "app-1"), (KEY_APP_SECRET, "secret-1")]);
    assert_eq!(configured.app_id, "app-1");
    assert_eq!(configured.app_secret, "secret-1");
    // 空串是合法配置值，不是「缺失」——原样覆盖后 getClient 判未配置。
    let cleared = apply(&[(KEY_APP_ID, ""), (KEY_APP_SECRET, "")]);
    assert!(cleared.app_id.is_empty());
    assert!(cleared.app_secret.is_empty());
}

#[tokio::test]
async fn load_reads_only_the_four_keys_and_keeps_defaults_otherwise() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    sqlx::query(r#"CREATE TABLE options ("key" TEXT PRIMARY KEY, "value" TEXT)"#)
        .execute(&pool)
        .await
        .expect("options table");
    // 另一分片的键不干扰本分片（Go 按 `qq_bot_setting.` 前缀收集）。
    sqlx::query(r#"INSERT INTO options ("key", "value") VALUES ('checkin_setting.enabled', '1')"#)
        .execute(&pool)
        .await
        .expect("seed unrelated option");
    let db = Database::Sqlite(pool.clone());
    assert_eq!(
        QQBotSettings::load(&db).await.expect("load"),
        QQBotSettings::default()
    );

    sqlx::query(
        r#"INSERT INTO options ("key", "value") VALUES
           ('qq_bot_setting.qq_checkin_enabled', 'true'),
           ('qq_bot_setting.rebind_cooldown_seconds', '7200'),
           ('qq_bot_setting.app_id', 'app-9'),
           ('qq_bot_setting.app_secret', 'secret-9')"#,
    )
    .execute(&pool)
    .await
    .expect("seed qq bot options");
    let settings = QQBotSettings::load(&db).await.expect("load with rows");
    assert!(settings.qq_checkin_enabled);
    assert_eq!(settings.rebind_cooldown_seconds, 7200);
    assert_eq!(settings.app_id, "app-9");
    assert_eq!(settings.app_secret, "secret-9");
}
