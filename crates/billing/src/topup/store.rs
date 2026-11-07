//! Storage access for the top-up read endpoints.
//!
//! Go references:
//! - `apps/api/internal/billing/register_option_hooks.go` (`applyPaymentOption`)
//! - `apps/api/internal/settings/config.go` (`payment_setting.*` reflection
//!   application)
//! - `apps/api/internal/billing/store_topup.go` (queries)
//!
//! All reads are typed: a missing row keeps the seeded Go default, while a
//! malformed row follows the Go apply path (numeric fields fall back to zero,
//! reflective fields keep the previous value, and `PayMethods` keeps the
//! existing list when validation fails).

use std::collections::BTreeMap;

use newapi_storage::Database;
use serde::Serialize;
use sqlx::Row;

use super::{PayMethod, TopUpSettings};

/// Go `topUpQueryWindowSeconds`: 30 days.
pub const USER_TOPUP_WINDOW_SECONDS: i64 = 30 * 24 * 60 * 60;

/// Every option read by `GetTopUpInfo`. Missing rows keep
/// [`TopUpSettings::default`].
const OPTION_KEYS: [&str; 36] = [
    "payment_setting.amount_options",
    "payment_setting.amount_discount",
    "payment_setting.compliance_confirmed",
    "payment_setting.compliance_terms_version",
    "MinTopUp",
    "StripeMinTopUp",
    "WaffoMinTopUp",
    "WaffoPancakeMinTopUp",
    "Price",
    "PayMethods",
    "PayAddress",
    "EpayId",
    "EpayKey",
    "StripeApiSecret",
    "StripeWebhookSecret",
    "StripePriceId",
    "CreemApiKey",
    "CreemProducts",
    "WaffoEnabled",
    "WaffoApiKey",
    "WaffoPrivateKey",
    "WaffoPublicCert",
    "WaffoSandboxPublicCert",
    "WaffoSandboxApiKey",
    "WaffoSandboxPrivateKey",
    "WaffoSandbox",
    "WaffoPancakeMerchantID",
    "WaffoPancakePrivateKey",
    "WaffoPancakeProductID",
    "WaffoPayMethods",
    "VmqAddress",
    "VmqKey",
    "CodePayAddress",
    "CodePayId",
    "CodePayKey",
    "TopUpLink",
];

impl TopUpSettings {
    /// Read all payment options in one query. A failing query is returned to
    /// the adapter, which classifies it without exposing SQL text.
    pub async fn load(db: &Database) -> Result<Self, sqlx::Error> {
        let rows = load_option_rows(db).await?;
        let mut settings = Self::default();
        for key in OPTION_KEYS {
            if let Some(value) = rows.get(key) {
                apply_option(&mut settings, key, value);
            }
        }
        Ok(settings)
    }
}

async fn load_option_rows(db: &Database) -> Result<BTreeMap<String, String>, sqlx::Error> {
    let rows = match db {
        Database::Sqlite(pool) => load_options(pool, false).await?,
        Database::Postgres(pool) => load_options(pool, true).await?,
    };
    Ok(rows
        .into_iter()
        .map(|(key, value)| (key, value.unwrap_or_default()))
        .collect())
}

/// The placeholder list is built per backend, so the statement is dynamic;
/// the text itself is a fixed template over `OPTION_KEYS` with every key
/// bound as a parameter. `Executor` is not implemented across database
/// kinds, so each backend calls this with its own pool.
async fn load_options<DB>(
    pool: &sqlx::Pool<DB>,
    postgres: bool,
) -> Result<Vec<(String, Option<String>)>, sqlx::Error>
where
    DB: sqlx::Database,
    (String, Option<String>): for<'row> sqlx::FromRow<'row, DB::Row>,
{
    let placeholders = placeholders(OPTION_KEYS.len(), postgres);
    let sql =
        format!("SELECT \"key\", \"value\" FROM \"options\" WHERE \"key\" IN ({placeholders})");
    let mut query = sqlx::query_as::<_, (String, Option<String>)>(sqlx::AssertSqlSafe(sql));
    for key in OPTION_KEYS {
        query = query.bind(key);
    }
    query.fetch_all(pool).await
}

fn placeholders(count: usize, postgres: bool) -> String {
    if postgres {
        (1..=count)
            .map(|index| format!("${index}"))
            .collect::<Vec<_>>()
            .join(", ")
    } else {
        vec!["?"; count].join(", ")
    }
}

/// Go `applyPaymentOption` plus the reflective `payment_setting.*` apply path.
fn apply_option(settings: &mut TopUpSettings, key: &str, value: &str) {
    match key {
        "payment_setting.amount_options" => {
            // Go reflection unmarshals into []int; an error keeps the previous
            // slice, while JSON `null` stores a nil slice.
            if let Ok(parsed) = serde_json::from_str::<Option<Vec<i64>>>(value) {
                settings.amount_options = parsed;
            }
        }
        "payment_setting.amount_discount" => {
            if let Ok(parsed) = serde_json::from_str::<Option<BTreeMap<i64, f64>>>(value) {
                settings.amount_discount = parsed;
            }
        }
        "payment_setting.compliance_confirmed" => {
            // Go `strconv.ParseBool`; an invalid value keeps the previous flag.
            if let Some(parsed) = parse_go_bool(value) {
                settings.compliance_confirmed = parsed;
            }
        }
        "payment_setting.compliance_terms_version" => {
            settings.compliance_terms_version = value.to_owned();
        }
        "MinTopUp" => settings.min_topup = parse_int_or_zero(value),
        "StripeMinTopUp" => settings.stripe_min_topup = parse_int_or_zero(value),
        "WaffoMinTopUp" => settings.waffo_min_topup = parse_int_or_zero(value),
        "WaffoPancakeMinTopUp" => settings.waffo_pancake_min_topup = parse_int_or_zero(value),
        "Price" => settings.price = value.parse::<f64>().unwrap_or(0.0),
        "PayMethods" => apply_pay_methods(settings, value),
        "PayAddress" => settings.pay_address = value.to_owned(),
        "EpayId" => settings.epay_id = value.to_owned(),
        "EpayKey" => settings.epay_key = value.to_owned(),
        "StripeApiSecret" => settings.stripe_api_secret = value.to_owned(),
        "StripeWebhookSecret" => settings.stripe_webhook_secret = value.to_owned(),
        "StripePriceId" => settings.stripe_price_id = value.to_owned(),
        "CreemApiKey" => settings.creem_api_key = value.to_owned(),
        "CreemProducts" => settings.creem_products = value.to_owned(),
        "WaffoEnabled" => settings.waffo_enabled = value == "true",
        "WaffoApiKey" => settings.waffo_api_key = value.to_owned(),
        "WaffoPrivateKey" => settings.waffo_private_key = value.to_owned(),
        "WaffoPublicCert" => settings.waffo_public_cert = value.to_owned(),
        "WaffoSandboxPublicCert" => settings.waffo_sandbox_public_cert = value.to_owned(),
        "WaffoSandboxApiKey" => settings.waffo_sandbox_api_key = value.to_owned(),
        "WaffoSandboxPrivateKey" => settings.waffo_sandbox_private_key = value.to_owned(),
        "WaffoSandbox" => settings.waffo_sandbox = value == "true",
        "WaffoPancakeMerchantID" => settings.waffo_pancake_merchant_id = value.to_owned(),
        "WaffoPancakePrivateKey" => settings.waffo_pancake_private_key = value.to_owned(),
        "WaffoPancakeProductID" => settings.waffo_pancake_product_id = value.to_owned(),
        "WaffoPayMethods" => settings.waffo_pay_methods = value.to_owned(),
        "VmqAddress" => settings.vmq_address = value.to_owned(),
        "VmqKey" => settings.vmq_key = value.to_owned(),
        "CodePayAddress" => settings.codepay_address = value.to_owned(),
        "CodePayId" => settings.codepay_id = value.to_owned(),
        "CodePayKey" => settings.codepay_key = value.to_owned(),
        "TopUpLink" => settings.topup_link = value.to_owned(),
        _ => {}
    }
}

/// Go `UpdatePayMethodsByJsonString`: parse `[]map[string]string`, validate the
/// gateway, and keep the existing list on any error.
fn apply_pay_methods(settings: &mut TopUpSettings, value: &str) {
    let Ok(parsed) = serde_json::from_str::<Option<Vec<PayMethod>>>(value) else {
        return;
    };
    let valid = match &parsed {
        Some(methods) => methods.iter().all(pay_method_gateway_is_valid),
        None => true,
    };
    if valid {
        settings.pay_methods = parsed;
    }
}

fn pay_method_gateway_is_valid(method: &PayMethod) -> bool {
    match method.get("gateway").map(String::as_str) {
        None | Some("") | Some("epay") => true,
        Some("vmq") | Some("codepay") => {
            matches!(
                method.get("type").map(String::as_str),
                Some("alipay" | "wxpay")
            )
        }
        Some(_) => false,
    }
}

fn parse_int_or_zero(value: &str) -> i64 {
    value.parse::<i64>().unwrap_or(0)
}

/// Go `strconv.ParseBool` accepted spellings.
fn parse_go_bool(value: &str) -> Option<bool> {
    match value {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

/// Go `billing.TopUp` JSON shape. No field is hidden: the Go struct exports
/// every column, including the payment provider and trade number.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct TopUpRecord {
    pub id: i64,
    pub user_id: i64,
    pub amount: i64,
    pub money: f64,
    pub trade_no: String,
    pub payment_method: String,
    pub payment_provider: String,
    pub create_time: i64,
    pub complete_time: i64,
    pub status: String,
}

pub struct TopUpRepository {
    db: Database,
}

macro_rules! decode_topup {
    ($row:expr) => {{
        let row = $row;
        TopUpRecord {
            id: row.try_get::<Option<i64>, _>("id")?.unwrap_or_default(),
            user_id: row
                .try_get::<Option<i64>, _>("user_id")?
                .unwrap_or_default(),
            amount: row.try_get::<Option<i64>, _>("amount")?.unwrap_or_default(),
            money: row.try_get::<Option<f64>, _>("money")?.unwrap_or_default(),
            trade_no: row
                .try_get::<Option<String>, _>("trade_no")?
                .unwrap_or_default(),
            payment_method: row
                .try_get::<Option<String>, _>("payment_method")?
                .unwrap_or_default(),
            payment_provider: row
                .try_get::<Option<String>, _>("payment_provider")?
                .unwrap_or_default(),
            create_time: row
                .try_get::<Option<i64>, _>("create_time")?
                .unwrap_or_default(),
            complete_time: row
                .try_get::<Option<i64>, _>("complete_time")?
                .unwrap_or_default(),
            status: row
                .try_get::<Option<String>, _>("status")?
                .unwrap_or_default(),
        }
    }};
}

/// Shared count/list body over an open transaction; each backend instantiates
/// it with its own `Transaction<'_, DB>` because `Executor` is not implemented
/// across database kinds.
macro_rules! topup_query {
    (
        $transaction:expr,
        $count:expr, [$($count_bind:expr),*],
        $list:expr, [$($list_bind:expr),*]
    ) => {{
        let mut count = sqlx::query_scalar::<_, i64>($count);
        $(count = count.bind($count_bind);)*
        let total = count.fetch_one(&mut **$transaction).await?;
        let mut list = sqlx::query($list);
        $(list = list.bind($list_bind);)*
        let rows = list.fetch_all(&mut **$transaction).await?;
        let mut records = Vec::with_capacity(rows.len());
        for row in rows {
            records.push(decode_topup!(row));
        }
        Ok::<(Vec<TopUpRecord>, i64), sqlx::Error>((records, total))
    }};
}

impl TopUpRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Go `QueryUserTopUps`: count and page in one transaction, newest id
    /// first, restricted to the 30-day window.
    pub async fn query_user(
        &self,
        user_id: i64,
        cutoff: i64,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<TopUpRecord>, i64), sqlx::Error> {
        match &self.db {
            Database::Sqlite(pool) => {
                let mut transaction = pool.begin().await?;
                let result = topup_query!(
                    &mut transaction,
                    USER_COUNT_SQL,
                    [user_id, cutoff],
                    USER_LIST_SQL,
                    [user_id, cutoff, limit, offset]
                );
                transaction.commit().await?;
                result
            }
            Database::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                let result = topup_query!(
                    &mut transaction,
                    USER_COUNT_SQL,
                    [user_id, cutoff],
                    USER_LIST_SQL,
                    [user_id, cutoff, limit, offset]
                );
                transaction.commit().await?;
                result
            }
        }
    }

    /// Go `SearchUserTopUps`: exact `trade_no` LIKE search with Go's `!`
    /// escape and the same 30-day window. Go caps the count with
    /// `.Limit(searchTopUpCountHardLimit)`, but GORM emits that LIMIT beside
    /// the aggregate and never truncates the single count row, so Go's total
    /// is in fact uncapped; this count matches that behavior.
    pub async fn search_user(
        &self,
        user_id: i64,
        cutoff: i64,
        pattern: &str,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<TopUpRecord>, i64), sqlx::Error> {
        match &self.db {
            Database::Sqlite(pool) => {
                let mut transaction = pool.begin().await?;
                let result = topup_query!(
                    &mut transaction,
                    SEARCH_COUNT_SQL,
                    [user_id, cutoff, pattern],
                    SEARCH_LIST_SQL,
                    [user_id, cutoff, pattern, limit, offset]
                );
                transaction.commit().await?;
                result
            }
            Database::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                let result = topup_query!(
                    &mut transaction,
                    SEARCH_COUNT_SQL,
                    [user_id, cutoff, pattern],
                    SEARCH_LIST_SQL,
                    [user_id, cutoff, pattern, limit, offset]
                );
                transaction.commit().await?;
                result
            }
        }
    }
}

const USER_COUNT_SQL: &str =
    "SELECT COUNT(*) FROM top_ups WHERE user_id = $1 AND create_time >= $2";

const USER_LIST_SQL: &str = concat!(
    "SELECT id, user_id, amount, money, trade_no, payment_method, ",
    "payment_provider, create_time, complete_time, status FROM top_ups ",
    "WHERE user_id = $1 AND create_time >= $2 ORDER BY id DESC LIMIT $3 OFFSET $4"
);

const SEARCH_COUNT_SQL: &str = concat!(
    "SELECT COUNT(*) FROM top_ups ",
    "WHERE user_id = $1 AND create_time >= $2 AND trade_no LIKE $3 ESCAPE '!'"
);

const SEARCH_LIST_SQL: &str = concat!(
    "SELECT id, user_id, amount, money, trade_no, payment_method, ",
    "payment_provider, create_time, complete_time, status FROM top_ups ",
    "WHERE user_id = $1 AND create_time >= $2 AND trade_no LIKE $3 ESCAPE '!' ",
    "ORDER BY id DESC LIMIT $4 OFFSET $5"
);
