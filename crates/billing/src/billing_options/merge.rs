//! Pure map semantics for the legacy billing option migration.

use std::collections::BTreeMap;

pub const LEGACY_BILLING_MODE_OPTION_KEY: &str = "ModelBillingMode";
pub const LEGACY_BILLING_EXPR_OPTION_KEY: &str = "ModelBillingExpr";

pub const BILLING_MODE_TARGET_KEY: &str = "billing_setting.billing_mode";
pub const BILLING_EXPR_TARGET_KEY: &str = "billing_setting.billing_expr";

/// Parse the stored JSON object as a string map. A malformed value is an error
/// the caller must classify as "skip, keep the row".
pub fn parse_string_map_option(value: &str) -> Result<BTreeMap<String, String>, serde_json::Error> {
    serde_json::from_str(value)
}

/// An empty value is "not configured" at runtime, so importing it would only
/// pollute the flattened map.
pub fn drop_empty_map_entries(map: &mut BTreeMap<String, String>) {
    map.retain(|_, value| !value.is_empty());
}

/// Target values are newer and always win; legacy models absent from the
/// target are copied over.
pub fn merge_maps(
    legacy: &BTreeMap<String, String>,
    target: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut merged = legacy.clone();
    for (model, value) in target {
        merged.insert(model.clone(), value.clone());
    }
    merged
}
