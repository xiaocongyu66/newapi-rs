//! Legacy `ModelBillingMode` / `ModelBillingExpr` option migration.
//!
//! Upstream stores each billing map under a legacy top-level option key and
//! copies it into the flattened `billing_setting.*` key at startup. Target
//! values win, empty legacy entries are dropped, legacy rows are kept for
//! rollback, and malformed rows are logged and skipped rather than aborting
//! startup.

mod executor;
mod merge;

pub use executor::{BillingOptionsMigrationError, migrate_legacy_billing_options};
pub use merge::{
    LEGACY_BILLING_EXPR_OPTION_KEY, LEGACY_BILLING_MODE_OPTION_KEY, drop_empty_map_entries,
    merge_maps, parse_string_map_option,
};

#[cfg(test)]
mod tests;
