//! Top-up read model: typed option loading and per-user top-up records.
//!
//! Go references:
//! - `apps/api/internal/billing/topup_api.go` (`GetTopUpInfo`,
//!   `GetUserTopUps`)
//! - `apps/api/internal/billing/pay_subscription.go` (payment settings and
//!   `PayMethods`)
//! - `apps/api/internal/billing/payment_webhook_availability.go` (gateway
//!   enablement)
//! - `apps/api/internal/billing/register_option_hooks.go` (option keys and
//!   apply semantics)
//! - `apps/api/internal/billing/store_topup.go` (`QueryUserTopUps`,
//!   `SearchUserTopUps`)
//! - `apps/api/internal/billing/topup_api.go` (`RequestAmount`,
//!   `getPayMoney`, `validateTopUpQuota`)
//!
//! The module is read-only: it parses storage rows into the Go process
//! defaults, filters configured payment methods exactly like the Go handler,
//! and reads a user's top-up history. JSON serialization of the HTTP shape
//! belongs to the server adapter.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

mod gateway;
mod quote;
mod store;

pub use gateway::{
    ExternalQuotaSource, ExternalRechargeParams, ExternalUserUpdate, PROVIDER_CODEPAY,
    PROVIDER_CREEM, PROVIDER_EPAY, PROVIDER_STRIPE, PROVIDER_VMQ, PROVIDER_WAFFO,
    PROVIDER_WAFFO_PANCAKE, RechargeError, RechargeOutcome, RechargeParams, RechargeRecord,
    RedeemFailed, STATUS_EXPIRED, STATUS_FAILED, STATUS_PENDING, STATUS_SUCCESS, base62_string,
    codepay_sign, constant_time_eq, epay_sign, gateway_pay_type_code, insert_topup,
    manual_complete_top_up, md5_hex, now_seconds, random_string, recharge_external_top_up,
    recharge_top_up, record_topup_log, redeem, round2_cents, set_topup_status, sha1_hex,
    update_pending_top_up_status, vmq_create_sign, vmq_notify_sign,
};

pub use quote::{
    CreditedQuotaRejection, TopUpQuotaRejection, amount_discount, check_capacity,
    max_top_up_amount, pay_money, stripe_credited_quota, stripe_pay_money, stripe_pay_units,
    top_up_quota, topup_group_ratio, validate_credited_quota, validate_top_up_quota,
    waffo_pancake_pay_money, waffo_pay_money,
};
pub use store::{TopUpRecord, TopUpRepository, USER_TOPUP_WINDOW_SECONDS};

/// Go `billing.CurrentComplianceTermsVersion`.
pub const COMPLIANCE_TERMS_VERSION: &str = "v1";

/// Go `paymentSetting.AmountOptions` default.
pub const DEFAULT_AMOUNT_OPTIONS: [i64; 6] = [10, 20, 50, 100, 200, 500];

/// Go `PayMethods` stores `[]map[string]string`; every value is a JSON string,
/// including `min_topup`.
pub type PayMethod = BTreeMap<String, String>;

fn default_pay_methods() -> Vec<PayMethod> {
    [
        vec![
            ("name".to_owned(), "支付宝".to_owned()),
            ("icon".to_owned(), "SiAlipay".to_owned()),
            ("type".to_owned(), "alipay".to_owned()),
        ],
        vec![
            ("name".to_owned(), "微信".to_owned()),
            ("icon".to_owned(), "SiWechat".to_owned()),
            ("type".to_owned(), "wxpay".to_owned()),
        ],
        vec![
            ("name".to_owned(), "自定义1".to_owned()),
            ("icon".to_owned(), "LuCreditCard".to_owned()),
            ("type".to_owned(), "custom1".to_owned()),
            ("min_topup".to_owned(), "50".to_owned()),
        ],
    ]
    .into_iter()
    .map(|pairs| pairs.into_iter().collect())
    .collect()
}

/// Input shape of `GET /api/user/topup/info` after option parsing.
///
/// `None` is reserved for JSON `null` values that Go stores as a nil slice or
/// nil map; a missing or malformed row keeps the preceding (default) value.
#[derive(Clone, Debug, PartialEq)]
pub struct TopUpSettings {
    pub amount_options: Option<Vec<i64>>,
    pub amount_discount: Option<BTreeMap<i64, f64>>,
    /// `payment_setting.compliance_confirmed`.
    pub compliance_confirmed: bool,
    /// `payment_setting.compliance_terms_version`.
    pub compliance_terms_version: String,
    pub min_topup: i64,
    pub stripe_min_topup: i64,
    pub waffo_min_topup: i64,
    pub waffo_pancake_min_topup: i64,
    pub price: f64,
    /// Go `StripePromotionCodesEnabled`（`pay_subscription.go:169`，option
    /// `StripePromotionCodesEnabled`）。
    pub stripe_promotion_codes_enabled: bool,
    /// Go `StripeUnitPrice`（`pay_subscription.go:168`，option `StripeUnitPrice`）。
    pub stripe_unit_price: f64,
    /// Go `WaffoUnitPrice`（`pay_subscription.go:189`，option `WaffoUnitPrice`）。
    pub waffo_unit_price: f64,
    /// Go `WaffoPancakeUnitPrice`（`pay_subscription.go:233`，option
    /// `WaffoPancakeUnitPrice`）。
    pub waffo_pancake_unit_price: f64,
    /// Go `common.GetTopupGroupRatio` 的进程级 map：`TopupGroupRatio` option
    /// 的 JSON `<group, ratio>` 快照；缺失的 group 由查询方兜底为 1。
    pub topup_group_ratio: Option<BTreeMap<String, f64>>,
    pub pay_methods: Option<Vec<PayMethod>>,
    pub pay_address: String,
    pub epay_id: String,
    pub epay_key: String,
    pub stripe_api_secret: String,
    pub stripe_webhook_secret: String,
    pub stripe_price_id: String,
    pub creem_api_key: String,
    /// Go `CreemWebhookSecret`（`pay_subscription.go:19`，option `CreemWebhookSecret`）。
    pub creem_webhook_secret: String,
    /// Go `CreemTestMode`（`pay_subscription.go:18`，option `CreemTestMode`）。
    pub creem_test_mode: bool,
    /// Raw JSON string, exactly like Go `CreemProducts`.
    pub creem_products: String,
    pub waffo_enabled: bool,
    pub waffo_api_key: String,
    pub waffo_private_key: String,
    pub waffo_public_cert: String,
    pub waffo_sandbox_public_cert: String,
    pub waffo_sandbox_api_key: String,
    pub waffo_sandbox_private_key: String,
    pub waffo_sandbox: bool,
    /// Go `WaffoMerchantId`（option `WaffoMerchantId`）。
    pub waffo_merchant_id: String,
    /// Go `WaffoCurrency`（option `WaffoCurrency`，空回落 `USD`）。
    pub waffo_currency: String,
    /// Go `WaffoNotifyUrl`（option `WaffoNotifyUrl`）。
    pub waffo_notify_url: String,
    /// Go `WaffoReturnUrl`（option `WaffoReturnUrl`）。
    pub waffo_return_url: String,
    pub waffo_pancake_merchant_id: String,
    pub waffo_pancake_private_key: String,
    pub waffo_pancake_product_id: String,
    /// Go `WaffoPancakeStoreID`（option `WaffoPancakeStoreID`）。
    pub waffo_pancake_store_id: String,
    /// Raw JSON string, exactly like Go `WaffoPayMethods`.
    pub waffo_pay_methods: String,
    pub vmq_address: String,
    pub vmq_key: String,
    pub codepay_address: String,
    pub codepay_id: String,
    pub codepay_key: String,
    pub topup_link: String,
}

impl Default for TopUpSettings {
    fn default() -> Self {
        Self {
            amount_options: Some(DEFAULT_AMOUNT_OPTIONS.to_vec()),
            amount_discount: Some(BTreeMap::new()),
            compliance_confirmed: false,
            compliance_terms_version: String::new(),
            min_topup: 1,
            stripe_min_topup: 1,
            waffo_min_topup: 1,
            waffo_pancake_min_topup: 1,
            price: 7.3,
            stripe_promotion_codes_enabled: false,
            stripe_unit_price: 8.0,
            waffo_unit_price: 1.0,
            waffo_pancake_unit_price: 1.0,
            topup_group_ratio: Some(BTreeMap::new()),
            pay_methods: Some(default_pay_methods()),
            pay_address: String::new(),
            epay_id: String::new(),
            epay_key: String::new(),
            stripe_api_secret: String::new(),
            stripe_webhook_secret: String::new(),
            stripe_price_id: String::new(),
            creem_api_key: String::new(),
            creem_webhook_secret: String::new(),
            creem_test_mode: false,
            creem_products: "[]".to_owned(),
            waffo_enabled: false,
            waffo_api_key: String::new(),
            waffo_private_key: String::new(),
            waffo_public_cert: String::new(),
            waffo_sandbox_public_cert: String::new(),
            waffo_sandbox_api_key: String::new(),
            waffo_sandbox_private_key: String::new(),
            waffo_sandbox: false,
            waffo_merchant_id: String::new(),
            waffo_currency: String::new(),
            waffo_notify_url: String::new(),
            waffo_return_url: String::new(),
            waffo_pancake_merchant_id: String::new(),
            waffo_pancake_private_key: String::new(),
            waffo_pancake_product_id: String::new(),
            waffo_pancake_store_id: String::new(),
            waffo_pay_methods: "[]".to_owned(),
            vmq_address: String::new(),
            vmq_key: String::new(),
            codepay_address: String::new(),
            codepay_id: String::new(),
            codepay_key: String::new(),
            topup_link: String::new(),
        }
    }
}

/// Go `GetWaffoPayMethods` result element.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(default)]
pub struct WaffoPayMethod {
    pub name: String,
    pub icon: String,
    #[serde(rename = "payMethodType")]
    pub pay_method_type: String,
    #[serde(rename = "payMethodName")]
    pub pay_method_name: String,
}

/// Go `CreemProduct`; `quota_display` is filled by the API boundary and
/// omitted when it is zero (`omitempty`).
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(default)]
pub struct CreemProduct {
    #[serde(rename = "productId")]
    pub product_id: String,
    pub name: String,
    pub price: f64,
    pub currency: String,
    pub quota: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota_display: Option<f64>,
}

/// Go `payMethodGateway`: a missing or empty gateway means Epay.
fn pay_method_gateway(method: &PayMethod) -> &'static str {
    match method.get("gateway").map(String::as_str) {
        Some("vmq") => "vmq",
        Some("codepay") => "codepay",
        _ => "epay",
    }
}

fn trimmed_nonempty(value: &str) -> bool {
    !value.trim().is_empty()
}

impl TopUpSettings {
    /// Go `IsPaymentComplianceConfirmed`.
    pub fn payment_compliance_confirmed(&self) -> bool {
        self.compliance_confirmed && self.compliance_terms_version == COMPLIANCE_TERMS_VERSION
    }

    fn is_epay_webhook_configured(&self) -> bool {
        trimmed_nonempty(&self.pay_address)
            && trimmed_nonempty(&self.epay_id)
            && trimmed_nonempty(&self.epay_key)
    }

    fn is_vmq_gateway_configured(&self) -> bool {
        trimmed_nonempty(&self.vmq_address) && trimmed_nonempty(&self.vmq_key)
    }

    fn is_codepay_gateway_configured(&self) -> bool {
        trimmed_nonempty(&self.codepay_address)
            && trimmed_nonempty(&self.codepay_id)
            && trimmed_nonempty(&self.codepay_key)
    }

    fn count_pay_methods_by_gateway(&self, gateway: &str) -> usize {
        self.pay_methods
            .as_deref()
            .unwrap_or_default()
            .iter()
            .filter(|method| pay_method_gateway(method) == gateway)
            .count()
    }

    /// Go `isEpayTopUpEnabled`.
    pub fn is_epay_topup_enabled(&self) -> bool {
        self.payment_compliance_confirmed()
            && self.is_epay_webhook_configured()
            && self.count_pay_methods_by_gateway("epay") > 0
    }

    /// Go `isVmqTopUpEnabled`.
    pub fn is_vmq_topup_enabled(&self) -> bool {
        self.payment_compliance_confirmed()
            && self.is_vmq_gateway_configured()
            && self.count_pay_methods_by_gateway("vmq") > 0
    }

    /// Go `isCodePayTopUpEnabled`.
    pub fn is_codepay_topup_enabled(&self) -> bool {
        self.payment_compliance_confirmed()
            && self.is_codepay_gateway_configured()
            && self.count_pay_methods_by_gateway("codepay") > 0
    }

    /// Go `isStripeTopUpEnabled`.
    pub fn is_stripe_topup_enabled(&self) -> bool {
        self.payment_compliance_confirmed()
            && trimmed_nonempty(&self.stripe_api_secret)
            && trimmed_nonempty(&self.stripe_webhook_secret)
            && trimmed_nonempty(&self.stripe_price_id)
    }

    /// Go `isCreemTopUpEnabled`.
    pub fn is_creem_topup_enabled(&self) -> bool {
        if !self.payment_compliance_confirmed() {
            return false;
        }
        let products = self.creem_products.trim();
        trimmed_nonempty(&self.creem_api_key) && !products.is_empty() && products != "[]"
    }

    /// Go `isWaffoTopUpEnabled`.
    pub fn is_waffo_topup_enabled(&self) -> bool {
        self.payment_compliance_confirmed()
            && self.waffo_enabled
            && self.is_waffo_webhook_configured()
    }

    fn is_waffo_webhook_configured(&self) -> bool {
        if self.waffo_sandbox {
            return trimmed_nonempty(&self.waffo_sandbox_api_key)
                && trimmed_nonempty(&self.waffo_sandbox_private_key)
                && trimmed_nonempty(&self.waffo_sandbox_public_cert);
        }
        trimmed_nonempty(&self.waffo_api_key)
            && trimmed_nonempty(&self.waffo_private_key)
            && trimmed_nonempty(&self.waffo_public_cert)
    }

    /// Go `isWaffoPancakeTopUpEnabled`.
    pub fn is_waffo_pancake_topup_enabled(&self) -> bool {
        self.payment_compliance_confirmed()
            && trimmed_nonempty(&self.waffo_pancake_merchant_id)
            && trimmed_nonempty(&self.waffo_pancake_private_key)
            && trimmed_nonempty(&self.waffo_pancake_product_id)
    }

    /// Go `GetTopUpInfo` `pay_methods`: configured methods are filtered by
    /// their gateway credentials, then Stripe, Waffo Pancake and Waffo are
    /// appended when enabled and not already present.
    pub fn effective_pay_methods(&self) -> Vec<PayMethod> {
        let mut methods = if self.payment_compliance_confirmed() {
            self.pay_methods
                .as_deref()
                .unwrap_or_default()
                .iter()
                .filter(|method| match pay_method_gateway(method) {
                    "vmq" => self.is_vmq_gateway_configured(),
                    "codepay" => self.is_codepay_gateway_configured(),
                    _ => self.is_epay_webhook_configured(),
                })
                .cloned()
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };

        if self.is_stripe_topup_enabled() && !has_pay_method_type(&methods, "stripe") {
            methods.push(appended_method(
                "Stripe",
                "stripe",
                "#635BFF",
                self.stripe_min_topup,
            ));
        }
        if self.is_waffo_pancake_topup_enabled() && !has_pay_method_type(&methods, "waffo_pancake")
        {
            methods.push(appended_method(
                "Waffo Pancake",
                "waffo_pancake",
                "#F97316",
                self.waffo_pancake_min_topup,
            ));
        }
        if self.is_waffo_topup_enabled() && !has_pay_method_type(&methods, "waffo") {
            methods.push(appended_method(
                "Waffo (Global Payment)",
                "waffo",
                "#3B82F6",
                self.waffo_min_topup,
            ));
        }
        methods
    }

    /// Go `waffo_pay_methods` field: `null` when Waffo is disabled, otherwise
    /// the parsed `WaffoPayMethods` option. Empty or malformed JSON yields an
    /// empty array, and JSON `null` stays `null`.
    pub fn waffo_pay_methods_value(&self) -> Value {
        if !self.is_waffo_topup_enabled() {
            return Value::Null;
        }
        parse_waffo_pay_methods(&self.waffo_pay_methods)
    }

    /// Go `creem_products` field: parse the raw option, or `None` for both an
    /// invalid value and JSON `null`.
    pub fn creem_products(&self) -> Option<Vec<CreemProduct>> {
        match serde_json::from_str::<Option<Vec<CreemProduct>>>(&self.creem_products) {
            Ok(products) => products,
            Err(_) => {
                tracing::error!(
                    event = "creem_products_parse_failed",
                    "creem products config parse failed"
                );
                None
            }
        }
    }
}

fn has_pay_method_type(methods: &[PayMethod], expected: &str) -> bool {
    methods
        .iter()
        .any(|method| method.get("type").map(String::as_str) == Some(expected))
}

fn appended_method(name: &str, kind: &str, color: &str, min_topup: i64) -> PayMethod {
    [
        ("name".to_owned(), name.to_owned()),
        ("type".to_owned(), kind.to_owned()),
        ("color".to_owned(), color.to_owned()),
        ("min_topup".to_owned(), min_topup.to_string()),
    ]
    .into_iter()
    .collect()
}

fn parse_waffo_pay_methods(raw: &str) -> Value {
    if raw.is_empty() {
        return json!([]);
    }
    match serde_json::from_str::<Option<Vec<WaffoPayMethod>>>(raw) {
        Ok(Some(methods)) => serde_json::to_value(methods).unwrap_or_else(|_| json!([])),
        Ok(None) => Value::Null,
        Err(_) => json!([]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn method(pairs: &[(&str, &str)]) -> PayMethod {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn compliant() -> TopUpSettings {
        TopUpSettings {
            compliance_confirmed: true,
            compliance_terms_version: COMPLIANCE_TERMS_VERSION.to_owned(),
            ..TopUpSettings::default()
        }
    }

    #[test]
    fn default_pay_methods_match_go_seed() {
        let methods = default_pay_methods();
        assert_eq!(methods.len(), 3);
        assert_eq!(methods[0].get("type").map(String::as_str), Some("alipay"));
        assert_eq!(methods[1].get("type").map(String::as_str), Some("wxpay"));
        assert_eq!(methods[2].get("min_topup").map(String::as_str), Some("50"));
    }

    #[test]
    fn gateway_filter_uses_configured_credentials() {
        let mut settings = compliant();
        settings.pay_address = "https://epay".into();
        settings.epay_id = "id".into();
        settings.epay_key = "key".into();
        settings.vmq_address = "https://vmq".into();
        settings.vmq_key = "key".into();
        settings.pay_methods = Some(vec![
            method(&[("name", "a"), ("type", "alipay")]),
            method(&[("name", "v"), ("type", "wxpay"), ("gateway", "vmq")]),
            method(&[("name", "c"), ("type", "wxpay"), ("gateway", "codepay")]),
        ]);
        let methods = settings.effective_pay_methods();
        let types = methods
            .iter()
            .map(|method| method.get("name").map(String::as_str).unwrap_or(""))
            .collect::<Vec<_>>();
        assert_eq!(types, vec!["a", "v"]);
        assert!(settings.is_epay_topup_enabled());
        assert!(settings.is_vmq_topup_enabled());
        assert!(!settings.is_codepay_topup_enabled());
    }

    #[test]
    fn stripe_is_appended_once_and_keeps_string_min_topup() {
        let mut settings = compliant();
        settings.stripe_api_secret = "secret".into();
        settings.stripe_webhook_secret = "hook".into();
        settings.stripe_price_id = "price".into();
        settings.stripe_min_topup = 2;
        let methods = settings.effective_pay_methods();
        assert_eq!(methods.len(), 1);
        assert_eq!(methods[0].get("type").map(String::as_str), Some("stripe"));
        assert_eq!(methods[0].get("min_topup").map(String::as_str), Some("2"));

        settings.pay_methods = Some(vec![method(&[("name", "Card"), ("type", "stripe")])]);
        settings.pay_address = "https://epay".into();
        settings.epay_id = "id".into();
        settings.epay_key = "key".into();
        let methods = settings.effective_pay_methods();
        assert_eq!(methods.len(), 1);
        assert_eq!(methods[0].get("name").map(String::as_str), Some("Card"));
    }

    #[test]
    fn compliance_gate_empties_every_method() {
        // The compliance gate must stay closed here, so this fixture keeps
        // the `default()` compliance state while configuring credentials via
        // struct-update syntax: Rust 2024 forbids assigning fields to a value
        // still typed as `Default::default()`.
        let settings = TopUpSettings {
            stripe_api_secret: "secret".into(),
            stripe_webhook_secret: "hook".into(),
            stripe_price_id: "price".into(),
            ..TopUpSettings::default()
        };
        assert!(settings.effective_pay_methods().is_empty());
        assert!(!settings.is_stripe_topup_enabled());
        assert!(settings.waffo_pay_methods_value().is_null());
    }
}
