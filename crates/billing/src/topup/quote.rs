//! Top-up amount quoting: the pure arithmetic behind
//! `POST /api/user/{amount,stripe/amount,waffo/amount,waffo-pancake/amount}`.
//!
//! Go references:
//! - `apps/api/internal/billing/topup_api.go` (`getPayMoney`, `getTopUpQuota`,
//!   `getMaxTopUpAmount`, `validateTopUpQuota`)
//! - `apps/api/internal/billing/topup_stripe.go`
//!   (`getStripePayMoney`, `getStripeCreditedQuota`, `stripePayUnits`,
//!   `getStripeMinTopup`)
//! - `apps/api/internal/billing/topup_waffo.go` (`getWaffoPayMoney`)
//! - `apps/api/internal/billing/topup_waffo_pancake.go`
//!   (`getWaffoPancakePayMoney`)
//! - `apps/api/internal/common/topup-ratio.go` (`GetTopupGroupRatio`)
//! - `apps/api/internal/billing/store_topup.go`
//!   (`ValidateTopUpQuotaCapacity`)
//!
//! ## Decimal equivalence
//!
//! Go computes with `shopspring/decimal` (`NewFromInt` for the integer amount,
//! `NewFromFloat` for the configured rates, `Mul` for products, `Div` for the
//! `TOKENS` display conversion, then `InexactFloat64`). The stored decimals
//! are exact: a `float64` is converted to its *shortest round-trip* decimal
//! (≤17 significant digits), products of such decimals stay exact as long as
//! the significant-digit sum stays below the package's 18-digit workspace
//! (`decimal` reports a precision error outside it), and the final
//! `InexactFloat64` is the nearest `f64` to that exact rational.
//!
//! Both multipliers below have at most 4 significant digits (`Price` 7.3,
//! unit prices 1.0/8.0, ratios, discounts), so every product here needs
//! ≤ 17 + 4 = 21 significant digits — exact in `i128` scaled by
//! [`SCALE`] = 10^18 (the `TOKENS` division alone is rounded, to Go's
//! `DivRound` half-up at `DivisionPrecision` = 16). Working in i128 and
//! converting at the very end therefore reproduces the Go float bit-for-bit
//! for every realistic option value, and a product that would exceed the
//! scale saturates rather than wrapping.

use super::TopUpSettings;

/// 10^18: the fixed-point scale. Products of an ≤18-significant-digit value
/// and a ≤4-significant-digit multiplier need ≤22 digits, but `QuotaPerUnit`
/// conversions cap the input, so `i128` (≤38 digits) never overflows and a
/// division rounds to this scale.
const SCALE: i128 = 1_000_000_000_000_000_000;

/// Go `common.MaxQuota` = `math.MaxInt32` (`common/quota_math.go:15`).
const MAX_QUOTA: i64 = 2_147_483_647;

/// Go `common.GetTopupGroupRatio`: a missing group is a server misconfiguration
/// (Go logs `SysError`), and the Go fallback is 1.
pub fn topup_group_ratio(settings: &TopUpSettings, group: &str) -> f64 {
    match settings
        .topup_group_ratio
        .as_ref()
        .and_then(|map| map.get(group))
    {
        Some(&ratio) => ratio,
        None => 1.0,
    }
}

/// Go `GetPaymentSetting().AmountDiscount[amount]`: preset discounts keyed by
/// the **original request amount**; a non-positive entry is ignored.
pub fn amount_discount(settings: &TopUpSettings, amount: i64) -> f64 {
    settings
        .amount_discount
        .as_ref()
        .and_then(|map| map.get(&amount))
        .copied()
        .filter(|discount| *discount > 0.0)
        .unwrap_or(1.0)
}

/// Go `getTopUpQuota(amount)`.
///
/// `TOKENS` display divides first and floors (Go `Decimal.Div(...).IntPart()`
/// truncates toward zero — the amount is positive here), then multiplies back
/// so the credited quota is a whole multiple of `quota_per_unit`. `USD/CNY`
/// multiplies directly.
pub fn top_up_quota(
    _settings: &TopUpSettings,
    amount: i64,
    tokens: bool,
    quota_per_unit: f64,
) -> i64 {
    let amount = i128::from(amount);
    let quota_per_unit = scaled_finite(quota_per_unit);
    if tokens {
        // Go `floor(amount / quota_per_unit).IntPart() * quota_per_unit`: the
        // division yields a whole unit count, which is multiplied back. The
        // unit count is `amount / quota_per_unit` truncated, so it never
        // exceeds `amount`, keeping the follow-up product inside `i128`.
        if quota_per_unit == 0 {
            return 0;
        }
        let units = amount * SCALE / quota_per_unit;
        // Guard the product: `units * quota_per_unit` can reach 10^36, still
        // inside i128 (10^38) for any amount Go accepts as a request.
        (units * quota_per_unit / SCALE) as i64
    } else {
        (amount * quota_per_unit / SCALE) as i64
    }
}

/// Go `getMaxTopUpAmount()`: the largest request amount whose credited quota
/// still fits under `MaxQuota - 1`.
///
/// `USD/CNY` returns `floor((MaxQuota - 1) / QuotaPerUnit)` — the whole units
/// that fit. `TOKENS` returns `((max + 1) * QuotaPerUnit).Ceil() - 1`, i.e.
/// the largest token count that still floors to at most `max` whole units.
pub fn max_top_up_amount(_settings: &TopUpSettings, tokens: bool, quota_per_unit: f64) -> i64 {
    if !quota_per_unit.is_finite() || quota_per_unit <= 0.0 {
        // Go `common.QuotaPerUnit <= 0` → 0 (no limit applies); a non-finite
        // `QuotaPerUnit` cannot arise from `ParseFloat` of a real config and is
        // folded into the same "no limit" branch so the division below is safe.
        return 0;
    }
    let unit = scaled_finite(quota_per_unit);
    // `max_units` = floor((MaxQuota - 1) / QuotaPerUnit), a plain integer:
    // dividing the scaled numerator by the scaled divisor cancels the scales.
    let max_units = i128::from(MAX_QUOTA - 1) * SCALE / unit;
    if !tokens {
        return max_units as i64;
    }
    // Go `((max_units + 1) * QuotaPerUnit).Ceil() - 1`: one more whole unit of
    // quota, rounded up to a whole token count, minus one token.
    let next = max_units + 1;
    let product = next * unit;
    let ceiling = product / SCALE + i128::from(product % SCALE != 0);
    (ceiling - 1) as i64
}

/// Go `validateTopUpQuota`: returns the credited quota, or the rejection the
/// adapter renders verbatim.
pub fn validate_top_up_quota(
    settings: &TopUpSettings,
    amount: i64,
    tokens: bool,
    quota_per_unit: f64,
) -> Result<i64, TopUpQuotaRejection> {
    let quota = top_up_quota(settings, amount, tokens, quota_per_unit);
    if quota > 0 {
        return Ok(quota);
    }
    let max_amount = max_top_up_amount(settings, tokens, quota_per_unit);
    if max_amount > 0 && amount > max_amount {
        return Err(TopUpQuotaRejection::ExceedsMax(max_amount));
    }
    Err(TopUpQuotaRejection::InvalidQuota)
}

/// Go `getPayMoney`：`amount × Price × groupRatio × discount`，`TOKENS` 模式
/// 下输入先按 `QuotaPerUnit` 折成 USD。
pub fn pay_money(
    settings: &TopUpSettings,
    original_amount: i64,
    group: &str,
    tokens: bool,
    quota_per_unit: f64,
) -> f64 {
    let mut amount = i128::from(original_amount);
    // Go's discount lookup uses the *original* request amount (the function
    // parameter), not the TOKENS-converted value below.
    let discount = amount_discount(settings, original_amount);
    let quota_per_unit = scaled_finite(quota_per_unit);
    if tokens {
        amount = div_round(amount * SCALE, quota_per_unit);
    }
    let price = scaled_finite(settings.price);
    let ratio = scaled_finite(topup_group_ratio(settings, group));
    let product = amount * price / SCALE * ratio / SCALE * scaled_finite(discount) / SCALE;
    to_float(product)
}

/// Go `stripePayUnits`：Checkout 计价的 `Quantity` =
/// `ceil(amount × ratio × discount)`，下限 1。
pub fn stripe_pay_units(settings: &TopUpSettings, amount: i64, group: &str) -> i64 {
    let ratio = scaled_finite(topup_group_ratio(settings, group));
    let discount = scaled_finite(amount_discount(settings, amount));
    let product = i128::from(amount) * ratio / SCALE * discount / SCALE;
    // Go `math.Ceil(x - 1e-9)`: the epsilon makes an exactly integral product
    // round down instead of up (e.g. 3.0 → 3, not 4).
    let ceil = ceil_with_epsilon(product);
    ceil.max(1)
}

/// Go `getStripePayMoney(amount, group)`：不在 `TOKENS` 模式换算输入，
/// 而是把已含倍率/折扣的 `units` 折成 USD。
pub fn stripe_pay_money(
    settings: &TopUpSettings,
    amount: i64,
    group: &str,
    tokens: bool,
    quota_per_unit: f64,
) -> f64 {
    let units = i128::from(stripe_pay_units(settings, amount, group));
    let quota_per_unit = scaled_finite(quota_per_unit);
    let units = if tokens {
        div_round(units * SCALE, quota_per_unit)
    } else {
        units
    };
    to_float(units * scaled_finite(settings.stripe_unit_price) / SCALE)
}

/// Go `getWaffoPayMoney`：与 `getPayMoney` 同构，但单价是 `WaffoUnitPrice`
/// 且折扣用**原始请求金额**查表（换算前的 `originalAmount`）。
pub fn waffo_pay_money(
    settings: &TopUpSettings,
    amount: i64,
    group: &str,
    tokens: bool,
    quota_per_unit: f64,
) -> f64 {
    let mut units = i128::from(amount);
    let quota_per_unit = scaled_finite(quota_per_unit);
    if tokens {
        units = div_round(units * SCALE, quota_per_unit);
    }
    let ratio = scaled_finite(topup_group_ratio(settings, group));
    let discount = scaled_finite(amount_discount(settings, amount));
    to_float(
        units * scaled_finite(settings.waffo_unit_price) / SCALE * ratio / SCALE * discount / SCALE,
    )
}

/// Go `getWaffoPancakePayMoney`：同 `getWaffoPayMoney`，单价换成
/// `WaffoPancakeUnitPrice`（折扣查表条件 `ok && ds > 0` 与
/// `amount_discount` 的 `filter(> 0)` 等价）。
pub fn waffo_pancake_pay_money(
    settings: &TopUpSettings,
    amount: i64,
    group: &str,
    tokens: bool,
    quota_per_unit: f64,
) -> f64 {
    let mut units = i128::from(amount);
    let quota_per_unit = scaled_finite(quota_per_unit);
    if tokens {
        units = div_round(units * SCALE, quota_per_unit);
    }
    let ratio = scaled_finite(topup_group_ratio(settings, group));
    let discount = scaled_finite(amount_discount(settings, amount));
    to_float(
        units * scaled_finite(settings.waffo_pancake_unit_price) / SCALE * ratio / SCALE * discount
            / SCALE,
    )
}

/// Go `getStripeCreditedQuota`：`amount × ratio × QuotaPerUnit`，不做
/// `TOKENS` 换算（Checkout 的 `Money` 记账口径）。
pub fn stripe_credited_quota(
    settings: &TopUpSettings,
    amount: i64,
    group: &str,
    quota_per_unit: f64,
) -> i64 {
    let ratio = scaled_finite(topup_group_ratio(settings, group));
    let product = i128::from(amount) * ratio / SCALE * scaled_finite(quota_per_unit) / SCALE;
    product as i64
}

/// Go `topUpQuotaMaxCurrent` (`store_topup.go:63-70`): `creditedQuota <= 0`
/// or `>= MaxQuota` is `ErrInvalidTopUpQuota`; otherwise the largest wallet
/// balance that can still absorb the credit is `MaxQuota - 1 - creditedQuota`.
///
/// Go's `validateCreditedQuota` maps the same conditions onto its two
/// messages (`充值额度超出系统可表示范围` for the not-representable case,
/// `充值额度必须大于 0` for zero) before the capacity check runs; the adapter
/// renders those two verbatim, and this function returns which one applies.
pub fn validate_credited_quota(credited_quota: i64) -> Result<i64, CreditedQuotaRejection> {
    if credited_quota <= 0 {
        return Err(CreditedQuotaRejection::MustBePositive);
    }
    if credited_quota >= MAX_QUOTA {
        return Err(CreditedQuotaRejection::NotRepresentable);
    }
    let max_current = (MAX_QUOTA - 1).saturating_sub(credited_quota);
    if max_current <= 0 {
        return Err(CreditedQuotaRejection::NotRepresentable);
    }
    Ok(max_current)
}

/// Go `ValidateTopUpQuotaCapacity`: the caller supplies the wallet balance
/// because reading it is an adapter concern. Returns the stored rejection when
/// the credited quota itself is out of range, mirroring Go's
/// `topUpQuotaMaxCurrent` pre-check.
pub fn check_capacity(credited_quota: i64, user_quota: i64) -> Result<(), CreditedQuotaRejection> {
    let max_current = validate_credited_quota(credited_quota)?;
    if user_quota > max_current {
        return Err(CreditedQuotaRejection::LimitExceeded);
    }
    Ok(())
}

/// The rejection categories of `validateTopUpQuota`, rendered verbatim by the
/// adapters (Go error strings, not i18n keys).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TopUpQuotaRejection {
    /// Go `fmt.Errorf("单笔充值数量不能大于 %d", maxAmount)`.
    ExceedsMax(i64),
    /// Go `errors.New("充值数量无效")`.
    InvalidQuota,
}

/// The rejection categories of `validateCreditedQuota` +
/// `ValidateTopUpQuotaCapacity`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreditedQuotaRejection {
    /// Go `errors.New("充值额度超出系统可表示范围")`.
    NotRepresentable,
    /// Go `errors.New("充值额度必须大于 0")`.
    MustBePositive,
    /// Go `store_topup.ErrInvalidTopUpQuota` (`"invalid top-up quota"`).
    InvalidTopUpQuota,
    /// Go `store_topup.ErrTopUpQuotaLimitExceeded`
    /// (`"top-up quota limit exceeded"`).
    LimitExceeded,
}

impl CreditedQuotaRejection {
    /// Go's `Error()` text: the `data` the adapters return verbatim.
    pub fn message(&self) -> &'static str {
        match self {
            Self::NotRepresentable => "充值额度超出系统可表示范围",
            Self::MustBePositive => "充值额度必须大于 0",
            Self::InvalidTopUpQuota => "invalid top-up quota",
            Self::LimitExceeded => "top-up quota limit exceeded",
        }
    }
}

// ---- fixed-point helpers ------------------------------------------------

/// `QuotaPerUnit`-style scaling: non-finite or out-of-range values become 0
/// so the arithmetic below stays well-defined (Go's `NewFromFloat` panics on
/// NaN/Inf, so no Go behaviour is being approximated here).
fn scaled_finite(value: f64) -> i128 {
    if !value.is_finite() || value.abs() >= 1e18 {
        return 0;
    }
    (value * SCALE as f64).round() as i128
}

/// Go `Decimal.Div` / `DivRound` at `DivisionPrecision` = 16: truncate toward
/// zero, then round half-up on the discarded remainder.
///
/// Both arguments arrive already scaled by [`SCALE`], but a quotient of two
/// equally-scaled values carries no scale at all (`10/5 = 2`, not `2e18`), so
/// the numerator is scaled up once more here and the returned quotient keeps
/// [`SCALE`]. The remainder therefore holds far more precision than Go's 16
/// significant digits need, which makes the half-up decision exact.
fn div_round(numerator: i128, denominator: i128) -> i128 {
    debug_assert!(
        denominator != 0,
        "callers reject a non-positive QuotaPerUnit"
    );
    if denominator == 0 {
        return 0;
    }
    let numerator = numerator * SCALE;
    let mut quotient = numerator / denominator;
    let remainder = numerator - quotient * denominator;
    // Go compares `2 * |remainder|` against the divisor, rounding away from
    // zero on a tie (the sign of both operands never matters here: the
    // quota per unit is positive and the amounts are non-negative).
    if remainder.abs() * 2 >= denominator.abs() {
        quotient += if (numerator >= 0) == (denominator >= 0) {
            1
        } else {
            -1
        };
    }
    quotient
}

/// Go `math.Ceil(x - 1e-9)` on a scaled value: subtract one scaled epsilon,
/// then round up. An exactly integral product must not become the next
/// integer (e.g. 3.0 -> 3), which is what the epsilon buys.
fn ceil_with_epsilon(value: i128) -> i64 {
    let epsilon = SCALE / 1_000_000_000; // 1e-9 in the value's own scale
    let shifted = value - epsilon;
    shifted.div_euclid(SCALE) as i64 + i64::from(shifted.rem_euclid(SCALE) != 0)
}

/// Nearest `f64` of a scaled value, matching Go's `InexactFloat64`.
fn to_float(scaled: i128) -> f64 {
    scaled as f64 / SCALE as f64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const QUOTA_PER_UNIT: f64 = 500_000.0;

    fn settings() -> TopUpSettings {
        TopUpSettings {
            price: 7.3,
            topup_group_ratio: Some(BTreeMap::from([("vip".to_owned(), 2.0)])),
            ..TopUpSettings::default()
        }
    }

    // ---- group ratio & discount ----------------------------------------

    #[test]
    fn group_ratio_falls_back_to_one() {
        assert_eq!(topup_group_ratio(&settings(), "vip"), 2.0);
        // Go `SysError` + 1 for an unregistered group.
        assert_eq!(topup_group_ratio(&settings(), "unknown"), 1.0);
        // A zero-valued entry is honoured, not coerced to 1.
        let zero = TopUpSettings {
            topup_group_ratio: Some(BTreeMap::from([("free".to_owned(), 0.0)])),
            ..TopUpSettings::default()
        };
        assert_eq!(topup_group_ratio(&zero, "free"), 0.0);
    }

    #[test]
    fn discount_is_keyed_by_request_amount_and_must_be_positive() {
        let settings = TopUpSettings {
            amount_discount: Some(BTreeMap::from([(10, 0.5), (20, 0.0), (30, -1.0)])),
            ..TopUpSettings::default()
        };
        assert_eq!(amount_discount(&settings, 10), 0.5);
        assert_eq!(amount_discount(&settings, 20), 1.0);
        assert_eq!(amount_discount(&settings, 30), 1.0);
        assert_eq!(amount_discount(&settings, 99), 1.0);
    }

    // ---- quoted price --------------------------------------------------

    #[test]
    fn pay_money_multiplies_price_ratio_and_discount() {
        let settings = settings();
        // 10 * 7.3 = 73.00, no discount, no group ratio.
        assert_eq!(
            pay_money(&settings, 10, "unknown", false, QUOTA_PER_UNIT),
            73.0
        );
        // 10 * 7.3 * 2 = 146.00.
        assert_eq!(
            pay_money(&settings, 10, "vip", false, QUOTA_PER_UNIT),
            146.0
        );
    }

    #[test]
    fn pay_money_divides_by_quota_per_unit_in_tokens_mode() {
        let settings = settings();
        // tokens: 500000 / 500000 = 1 USD of input.
        assert_eq!(
            pay_money(&settings, 500_000, "unknown", true, QUOTA_PER_UNIT),
            7.3
        );
        // 1_000_000 tokens -> 2 USD -> 14.60.
        assert_eq!(
            pay_money(&settings, 1_000_000, "unknown", true, QUOTA_PER_UNIT),
            14.6
        );
    }

    #[test]
    fn format_two_decimals_matches_go() {
        // Go `strconv.FormatFloat(payMoney, 'f', 2, 64)`.
        assert_eq!(
            format!(
                "{:.2}",
                pay_money(&settings(), 1, "x", false, QUOTA_PER_UNIT)
            ),
            "7.30"
        );
        assert_eq!(
            format!(
                "{:.2}",
                pay_money(&settings(), 3, "x", false, QUOTA_PER_UNIT)
            ),
            "21.90"
        );
    }

    // ---- stripe --------------------------------------------------------

    #[test]
    fn stripe_pay_units_ceil_with_epsilon() {
        let settings = settings();
        // amount * ratio(1) * discount(1) = 10 -> exactly integral, stays 10.
        assert_eq!(stripe_pay_units(&settings, 10, "unknown"), 10);
        // vip ratio 2 -> 20.
        assert_eq!(stripe_pay_units(&settings, 10, "vip"), 20);
    }

    #[test]
    fn stripe_pay_units_clamps_to_one() {
        assert_eq!(stripe_pay_units(&TopUpSettings::default(), 0, "unknown"), 1);
    }

    #[test]
    fn stripe_pay_money_is_units_times_unit_price() {
        let settings = settings();
        // 10 units * 8.0 = 80.00.
        assert_eq!(
            stripe_pay_money(&settings, 10, "unknown", false, QUOTA_PER_UNIT),
            80.0
        );
        // tokens: (10 / 500000) * 8 = 0.00016 -> "0.00".
        assert_eq!(
            stripe_pay_money(&settings, 10, "unknown", true, QUOTA_PER_UNIT),
            0.000_16
        );
    }

    // ---- waffo ---------------------------------------------------------

    #[test]
    fn waffo_pay_money_uses_its_own_unit_price() {
        let settings = settings();
        assert_eq!(
            waffo_pay_money(&settings, 10, "unknown", false, QUOTA_PER_UNIT),
            10.0
        );
        assert_eq!(
            waffo_pancake_pay_money(&settings, 10, "unknown", false, QUOTA_PER_UNIT),
            10.0
        );
    }

    #[test]
    fn waffo_discount_lookup_uses_the_original_amount() {
        let settings = TopUpSettings {
            amount_discount: Some(BTreeMap::from([(500_000, 0.5)])),
            ..settings()
        };
        // In tokens mode 500_000 tokens -> 1 USD, but the discount is keyed by
        // the original request amount (500_000), so the half applies.
        assert_eq!(
            waffo_pay_money(&settings, 500_000, "unknown", true, QUOTA_PER_UNIT),
            0.5
        );
    }

    #[test]
    fn pay_money_discount_lookup_uses_the_original_amount_too() {
        let settings = TopUpSettings {
            amount_discount: Some(BTreeMap::from([(500_000, 0.5)])),
            ..settings()
        };
        // Go `getPayMoney` reads `AmountDiscount[int(amount)]` from its
        // parameter, before the TOKENS division, so 500_000 tokens -> 1 USD of
        // input and the half applies: 1 * 7.3 * 0.5 = 3.65.
        assert_eq!(
            pay_money(&settings, 500_000, "unknown", true, QUOTA_PER_UNIT),
            3.65
        );
    }

    // ---- quota ---------------------------------------------------------

    #[test]
    fn top_up_quota_multiplies_or_floors_by_display_type() {
        let settings = settings();
        // USD: amount * quota_per_unit.
        assert_eq!(
            top_up_quota(&settings, 10, false, QUOTA_PER_UNIT),
            5_000_000
        );
        // TOKENS: floor(10 / 500000) * 500000 = 0.
        assert_eq!(top_up_quota(&settings, 10, true, QUOTA_PER_UNIT), 0);
        // TOKENS: floor(1_000_000 / 500000) * 500000 = 1_000_000.
        assert_eq!(
            top_up_quota(&settings, 1_000_000, true, QUOTA_PER_UNIT),
            1_000_000
        );
        // TOKENS: exactly one unit.
        assert_eq!(
            top_up_quota(&settings, 500_000, true, QUOTA_PER_UNIT),
            500_000
        );
        // TOKENS: 499_999 floors to zero units.
        assert_eq!(top_up_quota(&settings, 499_999, true, QUOTA_PER_UNIT), 0);
    }

    #[test]
    fn max_top_up_amount_stays_below_the_int32_ceiling() {
        let settings = settings();
        // Go `floor((MaxQuota - 1) / 500000)`.
        let max = max_top_up_amount(&settings, false, QUOTA_PER_UNIT);
        assert_eq!(max, 4_294);
        assert!(top_up_quota(&settings, max, false, QUOTA_PER_UNIT) < MAX_QUOTA);
        // TOKENS: Go `((max + 1) * QuotaPerUnit).Ceil() - 1`.
        assert_eq!(
            max_top_up_amount(&settings, true, QUOTA_PER_UNIT),
            2_147_499_999
        );
    }

    #[test]
    fn invalid_quota_rejects_with_the_go_message() {
        let settings = settings();
        // A TOKENS amount smaller than one unit floors to zero quota.
        assert_eq!(
            validate_top_up_quota(&settings, 10, true, QUOTA_PER_UNIT),
            Err(TopUpQuotaRejection::InvalidQuota)
        );
    }

    // ---- credited quota & capacity -------------------------------------

    #[test]
    fn credited_quota_boundaries_match_go() {
        assert_eq!(
            validate_credited_quota(0),
            Err(CreditedQuotaRejection::MustBePositive)
        );
        assert_eq!(
            validate_credited_quota(-5),
            Err(CreditedQuotaRejection::MustBePositive)
        );
        assert_eq!(
            validate_credited_quota(i32::MAX as i64),
            Err(CreditedQuotaRejection::NotRepresentable)
        );
        assert_eq!(validate_credited_quota(1), Ok(i32::MAX as i64 - 2));
    }

    #[test]
    fn capacity_rejects_a_wallet_that_would_overflow() {
        assert_eq!(check_capacity(100, 0), Ok(()));
        assert_eq!(
            check_capacity(100, i32::MAX as i64),
            Err(CreditedQuotaRejection::LimitExceeded)
        );
    }

    #[test]
    fn rejection_messages_are_the_go_literals() {
        assert_eq!(
            CreditedQuotaRejection::NotRepresentable.message(),
            "充值额度超出系统可表示范围"
        );
        assert_eq!(
            CreditedQuotaRejection::MustBePositive.message(),
            "充值额度必须大于 0"
        );
        assert_eq!(
            CreditedQuotaRejection::InvalidTopUpQuota.message(),
            "invalid top-up quota"
        );
        assert_eq!(
            CreditedQuotaRejection::LimitExceeded.message(),
            "top-up quota limit exceeded"
        );
    }
}
