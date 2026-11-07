//! Option-loading contracts for the top-up read model: Go process defaults,
//! `applyPaymentOption` fallbacks, and `UpdatePayMethodsByJsonString`
//! validation.

use std::collections::BTreeMap;

use newapi_billing::topup::TopUpSettings;
use newapi_storage::Database;
use sqlx::sqlite::SqlitePoolOptions;

async fn settings_with(options: &[(&str, &str)]) -> TopUpSettings {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    sqlx::query(r#"CREATE TABLE options ("key" TEXT PRIMARY KEY, "value" TEXT)"#)
        .execute(&pool)
        .await
        .expect("create options");
    for &(key, value) in options {
        sqlx::query("INSERT INTO options (\"key\", \"value\") VALUES ($1, $2)")
            .bind(key)
            .bind(value)
            .execute(&pool)
            .await
            .expect("seed option");
    }
    TopUpSettings::load(&Database::Sqlite(pool))
        .await
        .expect("load settings")
}

#[tokio::test]
async fn empty_options_keep_go_process_defaults() {
    let settings = settings_with(&[]).await;
    assert_eq!(
        settings.amount_options,
        Some(vec![10, 20, 50, 100, 200, 500])
    );
    assert_eq!(settings.amount_discount, Some(BTreeMap::new()));
    assert_eq!(settings.min_topup, 1);
    assert_eq!(settings.stripe_min_topup, 1);
    assert_eq!(settings.price, 7.3);
    assert_eq!(settings.creem_products, "[]");
    assert_eq!(settings.waffo_pay_methods, "[]");
    assert!(!settings.payment_compliance_confirmed());
    // Go default `PayMethods`: three configured methods.
    let methods = settings.effective_pay_methods();
    assert!(methods.is_empty(), "compliance gate hides all methods");
    assert_eq!(
        settings.pay_methods.as_deref().map(|methods| methods.len()),
        Some(3)
    );
}

#[tokio::test]
async fn malformed_numeric_options_follow_the_go_apply_path() {
    // Go numeric applies fall back to zero; reflective applies keep the
    // previous value; `strconv.ParseBool` rejects malformed spellings.
    let settings = settings_with(&[
        ("MinTopUp", "abc"),
        ("Price", ""),
        ("payment_setting.amount_options", "not json"),
        ("payment_setting.compliance_confirmed", "maybe"),
    ])
    .await;
    assert_eq!(settings.min_topup, 0);
    assert_eq!(settings.price, 0.0);
    // Reflective unmarshal error: the default slice survives.
    assert_eq!(settings.amount_options.as_ref().map(Vec::len), Some(6));
    assert!(!settings.compliance_confirmed);
}

#[tokio::test]
async fn json_null_stores_nil_collections() {
    let settings = settings_with(&[
        ("payment_setting.amount_options", "null"),
        ("payment_setting.amount_discount", "null"),
        ("PayMethods", "null"),
    ])
    .await;
    assert_eq!(settings.amount_options, None);
    assert_eq!(settings.amount_discount, None);
    assert_eq!(settings.pay_methods, None);
    assert!(settings.effective_pay_methods().is_empty());
}

#[tokio::test]
async fn invalid_pay_method_gateway_keeps_the_previous_list() {
    // Go `UpdatePayMethodsByJsonString` validates every gateway before
    // accepting the list; one invalid entry rejects the whole update.
    let settings = settings_with(&[(
        "PayMethods",
        r#"[{"name":"ok","type":"alipay"},{"name":"bad","type":"stripe","gateway":"vmq"}]"#,
    )])
    .await;
    assert_eq!(
        settings.pay_methods.as_deref().map(|methods| methods.len()),
        Some(3)
    );
}

#[tokio::test]
async fn gateway_configuration_gates_the_enablement_flags() {
    let settings = settings_with(&[
        ("payment_setting.compliance_confirmed", "true"),
        ("payment_setting.compliance_terms_version", "v1"),
        ("PayAddress", "https://epay"),
        ("EpayId", " id "),
        ("EpayKey", "key"),
        ("StripeApiSecret", "secret"),
        ("StripeWebhookSecret", "hook"),
        ("StripePriceId", "price"),
        ("StripeMinTopUp", "5"),
        ("CreemApiKey", "ck"),
        ("CreemProducts", r#"[{"productId":"p1","quota":5000000}]"#),
    ])
    .await;
    assert!(settings.is_epay_topup_enabled());
    assert!(settings.is_stripe_topup_enabled());
    assert!(settings.is_creem_topup_enabled());
    assert!(!settings.is_vmq_topup_enabled());
    // Default methods carry no gateway: all three are Epay-routed, and
    // Stripe is appended once with a string min_topup.
    let methods = settings.effective_pay_methods();
    assert_eq!(methods.len(), 4);
    assert_eq!(methods[3].get("type").map(String::as_str), Some("stripe"));
    assert_eq!(methods[3].get("min_topup").map(String::as_str), Some("5"));
}

#[tokio::test]
async fn stale_compliance_terms_version_disables_everything() {
    let settings = settings_with(&[
        ("payment_setting.compliance_confirmed", "true"),
        ("payment_setting.compliance_terms_version", "v0"),
    ])
    .await;
    assert!(!settings.payment_compliance_confirmed());
    assert!(!settings.is_epay_topup_enabled());
    assert!(!settings.is_creem_topup_enabled());
}

#[tokio::test]
async fn creem_products_parse_matches_go_fallbacks() {
    let valid = settings_with(&[("CreemProducts", r#"[{"productId":"a","quota":10}]"#)]).await;
    assert_eq!(
        valid.creem_products().map(|products| products.len()),
        Some(1)
    );

    let null = settings_with(&[("CreemProducts", "null")]).await;
    assert_eq!(null.creem_products(), None);

    let malformed = settings_with(&[("CreemProducts", "{")]).await;
    assert_eq!(malformed.creem_products(), None);
}

#[tokio::test]
async fn waffo_pay_methods_value_tracks_the_waffo_flag() {
    let disabled = settings_with(&[("WaffoPayMethods", r#"[{"name":"card"}]"#)]).await;
    assert!(disabled.waffo_pay_methods_value().is_null());

    let enabled = settings_with(&[
        ("payment_setting.compliance_confirmed", "true"),
        ("payment_setting.compliance_terms_version", "v1"),
        ("WaffoEnabled", "true"),
        ("WaffoApiKey", "ak"),
        ("WaffoPrivateKey", "pk"),
        ("WaffoPublicCert", "cert"),
        (
            "WaffoPayMethods",
            r#"[{"name":"card","payMethodType":"card"}]"#,
        ),
    ])
    .await;
    assert!(enabled.is_waffo_topup_enabled());
    let value = enabled.waffo_pay_methods_value();
    assert_eq!(value[0]["payMethodType"], serde_json::json!("card"));

    let malformed = settings_with(&[
        ("payment_setting.compliance_confirmed", "true"),
        ("payment_setting.compliance_terms_version", "v1"),
        ("WaffoEnabled", "true"),
        ("WaffoApiKey", "ak"),
        ("WaffoPrivateKey", "pk"),
        ("WaffoPublicCert", "cert"),
        ("WaffoPayMethods", "garbage"),
    ])
    .await;
    assert_eq!(malformed.waffo_pay_methods_value(), serde_json::json!([]));
}
