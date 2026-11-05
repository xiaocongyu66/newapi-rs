//! Contract tests derived from the upstream Go implementation and locale files.

use newapi_i18n::{
    LanguageContext, is_supported, normalize_lang, parse_accept_language, resolve_language, t,
    translate,
};

fn assert_translation(lang: &str, key: &str, expected: &str) {
    assert_eq!(t(lang, key), expected);
}

#[test]
fn translates_common_and_login_keys_in_every_language() {
    assert_translation("en", "common.invalid_params", "Invalid parameters");
    assert_translation("zh-CN", "common.invalid_params", "无效的参数");
    assert_translation("zh-TW", "common.invalid_params", "無效的參數");

    let en = "Unauthorized, not logged in and no access token provided";
    assert_translation("en", "auth.not_logged_in", en);
    let zh_cn = "无权进行此操作，未登录且未提供 access token";
    assert_translation("zh-CN", "auth.not_logged_in", zh_cn);
    let zh_tw = "無權進行此操作，未登入且未提供 access token";
    assert_translation("zh-TW", "auth.not_logged_in", zh_tw);

    assert_translation(
        "en",
        "user.username_or_password_empty",
        "Username or password is empty",
    );
    assert_translation(
        "zh-CN",
        "user.username_or_password_empty",
        "用户名或密码为空",
    );
    assert_translation(
        "zh-TW",
        "user.username_or_password_empty",
        "使用者名或密碼為空",
    );

    let disabled = "Password login has been disabled by administrator";
    assert_translation("en", "user.password_login_disabled", disabled);
    assert_translation(
        "zh-CN",
        "user.password_login_disabled",
        "管理员关闭了密码登录",
    );
    assert_translation(
        "zh-TW",
        "user.password_login_disabled",
        "管理員關閉了密碼登錄",
    );

    let two_factor = "Please enter two-factor authentication code";
    assert_translation("en", "user.require_2fa", two_factor);
    assert_translation("zh-CN", "user.require_2fa", "请输入两步验证码");
    assert_translation("zh-TW", "user.require_2fa", "請輸入雙重驗證碼");
}

#[test]
fn unknown_keys_return_the_key() {
    assert_eq!(t("en", "missing.key"), "missing.key");
    assert_eq!(t("zh-CN", "missing.key"), "missing.key");
    assert_eq!(t("zh-TW", "missing.key"), "missing.key");
    assert_eq!(translate("en", "missing.key", [("Max", 10)]), "missing.key");
}

#[test]
fn catalogs_have_no_cross_language_fallback() {
    // Present in both Chinese catalogs but absent from en.yaml.
    let zh_cn = "普通管理员用户无法提升其他用户为管理员";
    assert_translation("zh-CN", "user.admin_cannot_promote", zh_cn);
    let zh_tw = "普通管理員使用者無法提升其他使用者為管理員";
    assert_translation("zh-TW", "user.admin_cannot_promote", zh_tw);
    assert_translation(
        "en",
        "user.admin_cannot_promote",
        "user.admin_cannot_promote",
    );
}

#[test]
fn normalize_lang_matches_upstream_prefix_rules() {
    let cases = [
        ("zh-CN", "zh-CN"),
        ("ZH-CN", "zh-CN"),
        ("zh-Hans", "zh-CN"),
        ("zh-Hant", "zh-CN"),
        ("zh-Hant-TW", "zh-CN"),
        ("zh-HK", "zh-CN"),
        ("zh", "zh-CN"),
        ("zh-TW", "zh-TW"),
        ("zh-tw-x", "zh-TW"),
        ("ZH-tw;q=0.9", "zh-TW"),
        ("  zh-TW  ", "zh-TW"),
        ("en", "en"),
        ("EN-us", "en"),
        ("en_US", "en"),
        ("", "en"),
        ("fr", "en"),
        ("de-DE", "en"),
    ];
    for (input, expected) in cases {
        assert_eq!(normalize_lang(input), expected, "input: {input:?}");
    }
}

#[test]
fn is_supported_normalizes_before_checking() {
    for lang in ["zh-CN", "zh-TW", "en", "zh-Hant", "en-US", "fr", ""] {
        assert!(
            is_supported(lang),
            "expected normalized support for {lang:?}"
        );
    }
}

#[test]
fn parse_accept_language_uses_only_the_first_entry() {
    assert_eq!(parse_accept_language(""), "en");
    assert_eq!(parse_accept_language("zh-CN,zh;q=0.9,en;q=0.8"), "zh-CN");
    assert_eq!(parse_accept_language("zh-TW;q=0.9,zh-CN;q=0.8"), "zh-TW");
    assert_eq!(parse_accept_language("ZH-TW;q=0.9,en"), "zh-TW");
    assert_eq!(parse_accept_language("en-US,en;q=0.9"), "en");
    assert_eq!(parse_accept_language("fr-FR,en;q=0.9"), "en");
    assert_eq!(parse_accept_language("zh-Hant,zh-TW;q=0.9"), "zh-CN");
    assert_eq!(parse_accept_language("  zh-CN ; q=0.9 "), "zh-CN");
    assert_eq!(parse_accept_language(";q=0.9,zh-CN"), "en");
    assert_eq!(parse_accept_language(",zh-CN"), "en");
}

#[test]
fn resolve_language_follows_upstream_priority() {
    let all_sources = LanguageContext {
        user_setting_language: Some("zh-TW"),
        user_id_language: Some("zh-CN"),
        middleware_language: Some("en"),
        accept_language: Some("en-US,en;q=0.9"),
    };
    assert_eq!(resolve_language(all_sources), "zh-TW");

    let user_id = LanguageContext {
        user_id_language: Some("zh-CN"),
        middleware_language: Some("zh-TW"),
        accept_language: Some("en"),
        ..LanguageContext::default()
    };
    assert_eq!(resolve_language(user_id), "zh-CN");

    let empty_setting = LanguageContext {
        user_setting_language: Some(""),
        user_id_language: Some("zh-TW"),
        middleware_language: Some("zh-CN"),
        ..LanguageContext::default()
    };
    assert_eq!(resolve_language(empty_setting), "zh-TW");

    let middleware = LanguageContext {
        user_setting_language: Some(""),
        user_id_language: Some(""),
        middleware_language: Some("zh-CN"),
        accept_language: Some("en"),
    };
    assert_eq!(resolve_language(middleware), "zh-CN");

    let accept = LanguageContext {
        middleware_language: Some(""),
        accept_language: Some("zh-TW,en;q=0.9"),
        ..LanguageContext::default()
    };
    assert_eq!(resolve_language(accept), "zh-TW");

    assert_eq!(resolve_language(LanguageContext::default()), "en");
}

#[test]
fn resolve_language_normalizes_before_returning() {
    let han = LanguageContext {
        user_setting_language: Some("zh-Hant"),
        ..LanguageContext::default()
    };
    assert_eq!(resolve_language(han), "zh-CN");

    // An unsupported non-empty setting still normalizes to en and therefore
    // wins before lower-priority sources, as upstream IsSupported does.
    let unsupported = LanguageContext {
        user_setting_language: Some("fr"),
        middleware_language: Some("zh-CN"),
        ..LanguageContext::default()
    };
    assert_eq!(resolve_language(unsupported), "en");

    // Upstream checks only for the empty string, not for whitespace.
    let whitespace = LanguageContext {
        middleware_language: Some("   "),
        accept_language: Some("zh-CN"),
        ..LanguageContext::default()
    };
    assert_eq!(resolve_language(whitespace), "en");
}

#[test]
fn translate_substitutes_catalog_placeholders() {
    let translated = translate("en", "rate_limit.reached", [("Max", 10), ("Minutes", 5)]);
    let expected = "You have reached the request limit: maximum 10 requests in 5 minutes";
    assert_eq!(translated, expected);

    let translated = translate("zh-CN", "rate_limit.reached", [("Max", 10), ("Minutes", 5)]);
    let expected = "您已达到请求数限制：5分钟内最多请求10次";
    assert_eq!(translated, expected);

    let translated = translate("zh-TW", "rate_limit.reached", [("Max", 10), ("Minutes", 5)]);
    let expected = "您已達到請求數限制：5分鐘內最多請求10次";
    assert_eq!(translated, expected);

    let translated = translate(
        "en",
        "token.exhausted",
        [("Prefix", "abc"), ("Suffix", "xyz")],
    );
    let expected = "This token quota is exhausted TokenStatusExhausted[sk-abc***xyz]";
    assert_eq!(translated, expected);

    let translated = translate(
        "zh-CN",
        "token.exhausted",
        [("Prefix", "abc"), ("Suffix", "xyz")],
    );
    let expected = "该令牌额度已用尽 TokenStatusExhausted[sk-abc***xyz]";
    assert_eq!(translated, expected);

    let translated = translate("en", "common.batch_too_many", [("Max", 100)]);
    let expected = "Too many items in batch request, maximum is 100";
    assert_eq!(translated, expected);
}

#[test]
fn t_without_args_rejects_template_messages_like_nil_data() {
    assert_eq!(t("en", "rate_limit.reached"), "rate_limit.reached");
    assert_eq!(t("zh-CN", "token.exhausted"), "token.exhausted");
    assert_eq!(t("en", "common.invalid_params"), "Invalid parameters");
}

#[test]
fn language_aliases_select_the_normalized_catalog() {
    assert_eq!(t("ZH-tw", "common.unauthorized"), "未授權");
    assert_eq!(t("zh-Hant", "common.unauthorized"), "未授权");
    assert_eq!(t("fr", "common.unauthorized"), "Unauthorized");
    let translated = translate("fr", "common.batch_too_many", [("Max", 3)]);
    assert_eq!(translated, "Too many items in batch request, maximum is 3");
}
