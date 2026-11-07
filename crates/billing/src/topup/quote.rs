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
//! ## Two arithmetic dialects
//!
//! Go computes the quote in **two different ways**, and matching it means
//! matching each one:
//!
//! * **`shopspring/decimal`** — `getPayMoney`, `getWaffoPancakePayMoney`,
//!   `getTopUpQuota`, `getMaxTopUpAmount` and `getStripeCreditedQuota`. `NewFromInt`
//!   for the integer amount, `NewFromFloat` (the *shortest round-trip* decimal)
//!   for the configured rates, exact `Mul`, `Div` = `DivRound(16)` for the
//!   `TOKENS` display conversion, then `InexactFloat64` (the nearest `f64` to
//!   the exact rational). Reproduced here with `i128` fixed point at
//!   [`SCALE`] = 10^18: a scaled value always represents `value / 10^18`, and
//!   both operands of every product carry the scale, so a chain of three
//!   multipliers needs a 256-bit intermediate to avoid overflow — see
//!   [`mul_div_rem`].
//!
//! * **plain `float64`** — `stripePayUnits`, `getStripePayMoney` and
//!   `getWaffoPayMoney` do their arithmetic in `float64` with `math.Ceil`
//!   (`topup_stripe.go:475`, `topup_waffo.go:85`). Those are reproduced
//!   *directly in `f64`*: an `i128` decimal answer would differ from Go by an
//!   ulp in exactly the cases where Go's own float rounding decides the
//!   `ceil`, which is what the Checkout `Quantity` is derived from.
//!
//! The two dialects are not interchangeable, which is why the float-based
//! ones are not fed through the fixed-point helpers.

use super::TopUpSettings;

/// 10^18: the fixed-point scale. A scaled `i128` represents its value divided
/// by this, and every multiplier enters the product already scaled, so
/// `product = mul_div(accumulator, factor, SCALE)`. `i128` (≤38 digits)
/// holds both operands of such a product but not their product, hence the
/// 256-bit intermediate.
const SCALE: i128 = 1_000_000_000_000_000_000;

/// Go `decimal.DivisionPrecision` = 16: `Div` = `DivRound(d2, 16)`, so the
/// quotient carries 16 fractional digits and then rounds half away from zero.
const DIVISION_PRECISION: i128 = 10_000_000_000_000_000;

/// Go `common.MaxQuota` = `math.MaxInt32` (`common/quota_math.go:15`).
const MAX_QUOTA: i64 = 2_147_483_647;

/// Go `common.GetTopupGroupRatio`: a missing group is a server misconfiguration
/// (Go logs `SysError`), and the Go fallback is 1. A stored ratio of exactly
/// 0 is *not* replaced here — every caller applies its own
/// `if topupGroupRatio == 0 { 1 }` guard (see [`group_ratio`]).
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

/// Go's `GetTopupGroupRatio` followed by the callers' `ratio == 0 → 1` guard
/// (`topup_api.go:194`, `topup_stripe.go:440`, `topup_waffo.go:90`,
/// `topup_waffo_pancake.go:58`).
fn group_ratio(settings: &TopUpSettings, group: &str) -> f64 {
    let ratio = topup_group_ratio(settings, group);
    if ratio == 0.0 { 1.0 } else { ratio }
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
/// `TOKENS` display divides first (Go `Decimal.Div(...).IntPart()` truncates
/// toward zero — the amount is positive here) and then multiplies back, so the
/// credited quota is a whole multiple of `quota_per_unit`; `USD/CNY`
/// multiplies directly. The product runs through Go's
/// `QuotaFromDecimalStrict` (`quota_math.go:152`): round to an integer, then
/// reject anything at or above `MaxQuota`, which is why `None` means "not
/// representable" rather than a saturated number.
pub fn top_up_quota(
    _settings: &TopUpSettings,
    amount: i64,
    tokens: bool,
    quota_per_unit: f64,
) -> Option<i64> {
    let unit = scaled(quota_per_unit);
    if unit == 0 {
        // Go divides by zero here (`QuoRem` panics); the amount is unusable
        // either way, and Go's caller turns a panic into an invalid quote.
        return None;
    }
    let mut product = i128::from(amount) * SCALE;
    if tokens {
        // Go `NewFromInt(amount).Div(QuotaPerUnit).IntPart()`: 16-digit
        // rounded quotient, then truncated to the whole unit count.
        product = (div_round(product, unit) / SCALE) * SCALE;
    }
    product = mul_div(product, unit, SCALE);
    quota_from_scaled(product)
}

/// Go `getMaxTopUpAmount()`: the largest request amount whose credited quota
/// still fits under `MaxQuota - 1`.
///
/// `USD/CNY` returns `floor((MaxQuota - 1) / QuotaPerUnit)` — the whole units
/// that fit. `TOKENS` returns `((max + 1) * QuotaPerUnit).Ceil() - 1`, i.e.
/// the largest token count that still floors to at most `max` whole units.
pub fn max_top_up_amount(_settings: &TopUpSettings, tokens: bool, quota_per_unit: f64) -> i64 {
    let unit = scaled(quota_per_unit);
    if unit <= 0 {
        // Go `common.QuotaPerUnit <= 0` → 0 (no limit applies).
        return 0;
    }
    // Go `NewFromInt(MaxQuota - 1).Div(QuotaPerUnit).Floor().IntPart()`: the
    // division rounds to 16 digits first, so the floor sees Go's rounded
    // quotient — reproducing that order is what keeps the boundary exact.
    let whole = div_round(i128::from(MAX_QUOTA - 1) * SCALE, unit) / SCALE;
    if !tokens {
        return whole as i64;
    }
    // Go `(whole + 1).Mul(QuotaPerUnit).Ceil().Sub(1).IntPart()`: one more whole
    // unit of quota, rounded up to a whole token count, minus one token.
    let product = mul_div((whole + 1) * SCALE, unit, SCALE);
    (ceil_to_integer(product) - 1) as i64
}

/// Go `validateTopUpQuota`: returns the credited quota, or the rejection the
/// adapter renders verbatim. A quota Go's `QuotaFromDecimalStrict` rejects
/// behaves exactly like a zero one (`err != nil`), so both fall through to the
/// maximum-amount branch.
pub fn validate_top_up_quota(
    settings: &TopUpSettings,
    amount: i64,
    tokens: bool,
    quota_per_unit: f64,
) -> Result<i64, TopUpQuotaRejection> {
    if let Some(quota) = top_up_quota(settings, amount, tokens, quota_per_unit)
        && quota > 0
    {
        return Ok(quota);
    }
    let max_amount = max_top_up_amount(settings, tokens, quota_per_unit);
    if max_amount > 0 && amount > max_amount {
        return Err(TopUpQuotaRejection::ExceedsMax(max_amount));
    }
    Err(TopUpQuotaRejection::InvalidQuota)
}

/// Go `getPayMoney`：`amount × Price × groupRatio × discount`，`TOKENS` 模式
/// 下输入先按 `QuotaPerUnit` 折成 USD。此处是 **decimal** 口径，折扣查表用
/// **原始请求金额**（换算前的 `amount`）。
pub fn pay_money(
    settings: &TopUpSettings,
    original_amount: i64,
    group: &str,
    tokens: bool,
    quota_per_unit: f64,
) -> f64 {
    let mut amount = i128::from(original_amount) * SCALE;
    let unit = scaled(quota_per_unit);
    if tokens {
        amount = div_round(amount, unit);
    }
    let mut product = amount;
    product = mul_div(product, scaled(settings.price), SCALE);
    product = mul_div(product, scaled(group_ratio(settings, group)), SCALE);
    // Go reads `AmountDiscount[int(amount)]` from the *function parameter*,
    // before the TOKENS division, so the original request amount is the key.
    product = mul_div(
        product,
        scaled(amount_discount(settings, original_amount)),
        SCALE,
    );
    to_float(product)
}

/// Go `stripePayUnits`：Checkout 计价的 `Quantity` =
/// `ceil(amount × ratio × discount)`，下限 1。
///
/// Go 用 **float64**（`topup_stripe.go:475`），`math.Ceil(float64(amount) *
/// (ratio * discount) - 1e-9)`：倍率与折扣先在 f64 里相乘，再乘金额。这里必须
/// 照搬同一顺序，改用 decimal 会在 `ceil` 边界上差一个 ulp。
pub fn stripe_pay_units(settings: &TopUpSettings, amount: i64, group: &str) -> i64 {
    let product =
        amount as f64 * (group_ratio(settings, group) * amount_discount(settings, amount));
    // Go `math.Ceil(x - 1e-9)`: the epsilon makes an exactly integral product
    // round down instead of up (e.g. 3.0 → 3, not 4). `math.Ceil(0 - 1e-9)` is
    // `-0`, which Go's `int64(-0)` gives as 0 and then clamps to 1.
    let mut units = (product - 1e-9).ceil();
    if units < 1.0 {
        units = 1.0;
    }
    units as i64
}

/// Go `getStripePayMoney(amount, group)`：不在 `TOKENS` 模式换算输入，
/// 而是把已含倍率/折扣的 `units` 折成 USD。同样是 **float64** 口径。
pub fn stripe_pay_money(
    settings: &TopUpSettings,
    amount: i64,
    group: &str,
    tokens: bool,
    quota_per_unit: f64,
) -> f64 {
    let mut units = stripe_pay_units(settings, amount, group) as f64;
    if tokens {
        units /= quota_per_unit;
    }
    units * settings.stripe_unit_price
}

/// Go `getWaffoPayMoney`：与 `getPayMoney` 同构，但单价是 `WaffoUnitPrice`，
/// 且整条表达式都是 **float64**（`topup_waffo.go:100`）：
/// `amount × WaffoUnitPrice × ratio × discount`。折扣查表仍用**原始请求金额**
/// （换算前的 `originalAmount`）。
pub fn waffo_pay_money(
    settings: &TopUpSettings,
    amount: i64,
    group: &str,
    tokens: bool,
    quota_per_unit: f64,
) -> f64 {
    let mut value = amount as f64;
    if tokens {
        value /= quota_per_unit;
    }
    // Go's left-to-right order matters for bit equality; the discount is keyed
    // by the original request amount, before the TOKENS conversion.
    value
        * settings.waffo_unit_price
        * group_ratio(settings, group)
        * amount_discount(settings, amount)
}

/// Go `getWaffoPancakePayMoney`：同 `getPayMoney` 的 **decimal** 口径
/// （`topup_waffo_pancake.go:68`），单价换成 `WaffoPancakeUnitPrice`（折扣查表
/// 条件 `ok && ds > 0` 与 `amount_discount` 的 `filter(> 0)` 等价，且同样按
/// 原始请求金额查表）。
pub fn waffo_pancake_pay_money(
    settings: &TopUpSettings,
    amount: i64,
    group: &str,
    tokens: bool,
    quota_per_unit: f64,
) -> f64 {
    let mut units = i128::from(amount) * SCALE;
    let unit = scaled(quota_per_unit);
    if tokens {
        units = div_round(units, unit);
    }
    let mut product = units;
    product = mul_div(product, scaled(settings.waffo_pancake_unit_price), SCALE);
    product = mul_div(product, scaled(group_ratio(settings, group)), SCALE);
    product = mul_div(product, scaled(amount_discount(settings, amount)), SCALE);
    to_float(product)
}

/// Go `getStripeCreditedQuota`：`amount × ratio × QuotaPerUnit`，不做
/// `TOKENS` 换算（Checkout 的 `Money` 记账口径）。decimal 口径；调用方
/// `validateCreditedQuota` 再按 `QuotaFromDecimalStrict` 取整。
pub fn stripe_credited_quota(
    settings: &TopUpSettings,
    amount: i64,
    group: &str,
    quota_per_unit: f64,
) -> i64 {
    let mut product = i128::from(amount) * SCALE;
    product = mul_div(product, scaled(group_ratio(settings, group)), SCALE);
    product = mul_div(product, scaled(quota_per_unit), SCALE);
    // Go `QuotaFromDecimalStrict` rounds to an integer (`Round(0)`) before it
    // takes the int, so a ratio with a fractional digit still lands exactly.
    mul_div_round(product, 1, SCALE) as i64
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

/// Go `decimal.NewFromFloat`: the shortest decimal that round-trips back to
/// the same `f64` (`roundShortest`, up to 17 significant digits).
///
/// Rust's `{}` formats an `f64` with the same shortest round-trip digits, so
/// parsing those digits back gives the exact decimal rather than the
/// `f64`-rounded `value * SCALE`. Non-finite input and values whose digits do
/// not fit the scale become 0, which is also what Go's `NewFromFloat` cannot
/// represent (it panics on NaN/Inf, so no Go behaviour is approximated).
fn scaled(value: f64) -> i128 {
    if !value.is_finite() {
        return 0;
    }
    let text = format!("{value}");
    let negative = text.starts_with('-');
    let digits = text.trim_start_matches('-');
    let mut mantissa: i128 = 0;
    let mut fraction_digits: u32 = 0;
    let mut seen_point = false;
    for character in digits.chars() {
        if character == '.' {
            seen_point = true;
            continue;
        }
        let digit = match character.to_digit(10) {
            Some(digit) => digit,
            // `{}` never emits an exponent for a finite f64; anything else is
            // unusable (NaN/Inf are already rejected above).
            None => return 0,
        };
        mantissa = match mantissa
            .checked_mul(10)
            .and_then(|m| m.checked_add(i128::from(digit)))
        {
            Some(mantissa) => mantissa,
            None => return 0,
        };
        if seen_point {
            fraction_digits += 1;
        }
    }
    if fraction_digits > 18 {
        // More than the scale can hold: the value is far below any amount the
        // caller can reach, so it collapses to 0.
        return 0;
    }
    // `value = mantissa / 10^fraction_digits`, so
    // `value * SCALE = mantissa * 10^(18 - fraction_digits)`.
    match mantissa.checked_mul(10i128.pow(18 - fraction_digits)) {
        Some(result) if negative => -result,
        Some(result) => result,
        None => 0,
    }
}

/// `(a * b) / c` and its remainder, computed exactly through a 256-bit
/// intermediate: `a * b = c * q + r` with `|r| < |c|`.
///
/// Both operands of a product arrive scaled by [`SCALE`], so their product
/// needs up to 76 digits and a bare `a * b` would wrap `i128`. A `i128`
/// quotient that does not fit saturates instead of wrapping, which keeps the
/// result defined for misconfigured rates (Go would carry an exact `big.Int`).
fn mul_div_rem(a: i128, b: i128, c: i128) -> (i128, i128) {
    debug_assert!(c != 0, "callers reject a zero divisor");
    if a == 0 || b == 0 || c == 0 {
        return (0, 0);
    }
    // The quotient flips sign against the divisor, but the remainder keeps the
    // sign of the product: `a * b = c * q + r` with `|r| < |c|` and truncation
    // toward zero, so `r` carries whichever side `a * b` is on.
    let product_negative = (a < 0) != (b < 0);
    let (high, low) = mul_wide(a.unsigned_abs(), b.unsigned_abs());
    let (quotient, remainder) = div_wide(high, low, c.unsigned_abs());
    (
        saturate(quotient, product_negative != (c < 0)),
        saturate(remainder, product_negative),
    )
}

/// `(a * b) / c` truncated toward zero, exact for every operand whose product
/// overflows `i128`.
fn mul_div(a: i128, b: i128, c: i128) -> i128 {
    mul_div_rem(a, b, c).0
}

/// `(a * b) / c` rounded half away from zero, the decision Go's `DivRound`
/// makes by comparing `2 * |remainder|` with the divisor
/// (`decimal.go:648-670`).
fn mul_div_round(a: i128, b: i128, c: i128) -> i128 {
    let (quotient, remainder) = mul_div_rem(a, b, c);
    if remainder != 0 && remainder.unsigned_abs() * 2 >= c.unsigned_abs() {
        return if quotient >= 0 {
            quotient + 1
        } else {
            quotient - 1
        };
    }
    quotient
}

/// Re-applies a sign to a magnitude, saturating instead of wrapping.
fn saturate(magnitude: u128, negative: bool) -> i128 {
    match magnitude.cmp(&(i128::MAX as u128)) {
        std::cmp::Ordering::Greater => {
            if negative {
                i128::MIN
            } else {
                i128::MAX
            }
        }
        _ => {
            let magnitude = magnitude as i128;
            if negative { -magnitude } else { magnitude }
        }
    }
}

/// 128 x 128 → 256, returned as `(high, low)` so `value = high * 2^128 + low`.
fn mul_wide(a: u128, b: u128) -> (u128, u128) {
    const LOW_MASK: u128 = u64::MAX as u128;
    const HALF: usize = 64;
    let (a_low, a_high) = (a & LOW_MASK, a >> HALF);
    let (b_low, b_high) = (b & LOW_MASK, b >> HALF);
    let (ll, lh, hl, hh) = (
        a_low * b_low,
        a_low * b_high,
        a_high * b_low,
        a_high * b_high,
    );
    // `mid` accumulates the middle 64 bits and stays below 3 * 2^64, so only its
    // low half may be shifted into `low`; its high half carries into `high`.
    let mid = (ll >> HALF) + (lh & LOW_MASK) + (hl & LOW_MASK);
    let high = hh + (lh >> HALF) + (hl >> HALF) + (mid >> HALF);
    let low = ((mid & LOW_MASK) << HALF) | (ll & LOW_MASK);
    (high, low)
}

/// Bit-wise long division of the 256-bit `(high, low)` by a 128-bit divisor.
///
/// The divisor is kept below 2^127 so `remainder * 2` cannot overflow, which
/// holds for every scaled quantity this module builds (`SCALE` = 10^18 and
/// `QuotaPerUnit * SCALE` both stay far below 2^120).
fn div_wide(high: u128, low: u128, divisor: u128) -> (u128, u128) {
    debug_assert!(divisor < 1u128 << 127, "the remainder must be doublable");
    let mut quotient: u128 = 0;
    let mut overflow = false;
    let mut remainder: u128 = 0;
    for limb in [high, low] {
        for bit in (0..128).rev() {
            let bit = (limb >> bit) & 1;
            let (doubled, carry) = quotient.overflowing_mul(2);
            quotient = doubled;
            overflow |= carry;
            let shifted = (remainder << 1) | bit;
            if shifted >= divisor {
                remainder = shifted - divisor;
                let (bumped, carry) = quotient.overflowing_add(1);
                quotient = bumped;
                overflow |= carry;
            } else {
                remainder = shifted;
            }
        }
    }
    if overflow {
        return (u128::MAX, 0);
    }
    (quotient, remainder)
}

/// Go `Decimal.Div` = `DivRound(d2, DivisionPrecision = 16)`, expressed in
/// [`SCALE`] units.
///
/// Both arguments arrive SCALE-scaled, and both scales cancel, so the
/// 16-fractional-digit quotient is `n / d * 10^16` scaled back up by
/// `10^(18 - 16)`. Forming `n * 10^16` directly would overflow for any
/// realistic amount, hence [`mul_div_rem`].
fn div_round(numerator: i128, denominator: i128) -> i128 {
    if denominator == 0 {
        // Go's `QuoRem` panics on a zero divisor; the amount is unusable
        // either way, so the caller's invalid-quota branch applies.
        return 0;
    }
    // 10^16 is the 16-digit quotient's own scale, so scaling it back up to
    // `SCALE` is exactly `* 10^(18 - 16)`. A saturated quotient (a
    // misconfigured `QuotaPerUnit` next to an extreme amount) must saturate
    // again rather than wrap.
    mul_div_round(numerator, DIVISION_PRECISION, denominator).saturating_mul(100)
}

/// Go `common.QuotaFromDecimalStrict` (`quota_math.go:152`): round to an
/// integer, then reject anything at or above `MaxQuota` (Go's `saturateQuota`
/// clamps there and `strictQuota` turns the clamp into the error the callers
/// render as `充值额度超出系统可表示范围`).
fn quota_from_scaled(product: i128) -> Option<i64> {
    let quota = mul_div_round(product, 1, SCALE);
    if quota >= i128::from(MAX_QUOTA) || quota < i128::from(i32::MIN) {
        return None;
    }
    Some(quota as i64)
}

/// Go `Decimal.Ceil()` on a non-negative scaled value: the integer at or
/// above it.
fn ceil_to_integer(value: i128) -> i128 {
    let fraction = value.rem_euclid(SCALE);
    if fraction == 0 {
        value.div_euclid(SCALE)
    } else {
        value.div_euclid(SCALE) + 1
    }
}

/// Go `Decimal.InexactFloat64` (`Rat().Float64()`): the nearest `f64` to the
/// exact rational. Splitting at the integer boundary keeps the dividend exact
/// where a bare `value as f64 / SCALE as f64` would double-round.
fn to_float(scaled: i128) -> f64 {
    let whole = scaled.div_euclid(SCALE);
    let fraction = scaled.rem_euclid(SCALE);
    whole as f64 + fraction as f64 / SCALE as f64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const QUOTA_PER_UNIT: f64 = 500_000.0;

    fn settings() -> TopUpSettings {
        TopUpSettings {
            price: 7.3,
            stripe_unit_price: 8.0,
            waffo_unit_price: 1.0,
            waffo_pancake_unit_price: 1.0,
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
            Some(5_000_000)
        );
        // TOKENS: floor(10 / 500000) * 500000 = 0.
        assert_eq!(top_up_quota(&settings, 10, true, QUOTA_PER_UNIT), Some(0));
        // TOKENS: floor(1_000_000 / 500000) * 500000 = 1_000_000.
        assert_eq!(
            top_up_quota(&settings, 1_000_000, true, QUOTA_PER_UNIT),
            Some(1_000_000)
        );
        // TOKENS: exactly one unit.
        assert_eq!(
            top_up_quota(&settings, 500_000, true, QUOTA_PER_UNIT),
            Some(500_000)
        );
        // TOKENS: 499_999 floors to zero units.
        assert_eq!(
            top_up_quota(&settings, 499_999, true, QUOTA_PER_UNIT),
            Some(0)
        );
    }

    #[test]
    fn top_up_quota_rejects_a_non_representable_product() {
        let settings = settings();
        // Go `QuotaFromDecimalStrict` clamps at MaxQuota and reports an error,
        // which `validateTopUpQuota` treats like a zero quota.
        // 4_295 * 500_000 = 2_147_500_000 > MaxQuota - 1.
        assert_eq!(
            top_up_quota(&settings, 4_294, false, QUOTA_PER_UNIT),
            Some(2_147_000_000)
        );
        assert_eq!(top_up_quota(&settings, 4_295, false, QUOTA_PER_UNIT), None);
        // A non-positive `QuotaPerUnit` divides by zero in Go; the amount is
        // unusable either way.
        assert_eq!(top_up_quota(&settings, 10, true, 0.0), None);
    }

    #[test]
    fn max_top_up_amount_stays_below_the_int32_ceiling() {
        let settings = settings();
        // Go `floor((MaxQuota - 1) / 500000)`.
        let max = max_top_up_amount(&settings, false, QUOTA_PER_UNIT);
        assert_eq!(max, 4_294);
        assert!(top_up_quota(&settings, max, false, QUOTA_PER_UNIT) < Some(MAX_QUOTA));
        // TOKENS: Go `((max + 1) * QuotaPerUnit).Ceil() - 1`.
        assert_eq!(
            max_top_up_amount(&settings, true, QUOTA_PER_UNIT),
            2_147_499_999
        );
        // Go `getMaxTopUpAmount` reports no limit for a non-positive unit.
        assert_eq!(max_top_up_amount(&settings, false, 0.0), 0);
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

    // ---- fixed-point helpers ---------------------------------------------

    #[test]
    fn scaled_matches_gos_shortest_round_trip_decimal() {
        // `NewFromFloat(7.3)` is exactly 7.3, not the f64-rounded product.
        assert_eq!(scaled(7.3), 7_300_000_000_000_000_000);
        assert_eq!(scaled(0.5), 500_000_000_000_000_000);
        assert_eq!(scaled(500_000.0), 500_000_000_000_000_000_000_000);
        assert_eq!(scaled(-2.0), -2_000_000_000_000_000_000);
        assert_eq!(scaled(0.0), 0);
        assert_eq!(scaled(1.0), SCALE);
        // Unrepresentable: NaN/Inf and a value past the scale.
        assert_eq!(scaled(f64::NAN), 0);
        assert_eq!(scaled(f64::INFINITY), 0);
        assert_eq!(scaled(1e30), 0);
    }

    #[test]
    fn mul_div_survives_a_product_that_overflows_i128() {
        // 10^19 * 10^26 = 10^45, far past `i128::MAX` (1.7e38), so the 256-bit
        // intermediate is what keeps the quotient exact rather than wrapped.
        let amount = 10 * SCALE;
        let rate = 100_000_000 * SCALE;
        assert_eq!(amount.checked_mul(rate), None, "the product must overflow");
        assert_eq!(mul_div(amount, rate, SCALE), 1_000_000_000 * SCALE);
        assert_eq!(mul_div(0, rate, SCALE), 0);
        // Signs: Go's `QuoRem` keeps the remainder on the same side as the
        // quotient, so `a * b = c * q + r` holds for negative operands too.
        assert_eq!(mul_div_rem(-4, 3, 5), (-2, -2));
        assert_eq!(mul_div_rem(4, -3, -5), (2, -2));
        assert_eq!(mul_div_rem(7, 5, 2), (17, 1));
        assert_eq!(mul_div(7, 5, 2), 17);
    }

    #[test]
    fn mul_div_round_steps_away_from_zero_on_a_tie() {
        // Go's `DivRound` compares `2 * |remainder|` with the divisor and steps
        // away from zero on equality.
        assert_eq!(mul_div_round(3, 1, 2), 2);
        assert_eq!(mul_div_round(-3, 1, 2), -2);
        // 4 / 2 is exact, so the remainder must not step it up to 3.
        assert_eq!(mul_div_round(4, 1, 2), 2);
        assert_eq!(mul_div_round(-4, 1, 2), -2);
        assert_eq!(mul_div_round(9, 1, 2), 5);
        assert_eq!(mul_div_round(-9, 1, 2), -5);
        assert_eq!(mul_div_round(4, 1, 3), 1);
    }

    #[test]
    fn div_round_matches_gos_divround_at_sixteen_digits() {
        // Both operands arrive scaled, so the scales cancel.
        assert_eq!(div_round(SCALE, SCALE), SCALE);
        assert_eq!(div_round(500_000 * SCALE, 500_000 * SCALE), SCALE);
        assert_eq!(div_round(3 * SCALE, 2 * SCALE), 3 * SCALE / 2);
        // 10 / 3 rounded to 16 fractional digits, half away from zero:
        // 3.3333333333333333, which is 33_333_333_333_333_333 / 10^16, so the
        // SCALE-scaled form is that 17-digit value times 100.
        assert_eq!(
            div_round(10 * SCALE, 3 * SCALE),
            33_333_333_333_333_333 * 100
        );
        // 1 / 500000 is exact well inside 16 digits, so nothing rounds.
        assert_eq!(div_round(SCALE, 500_000 * SCALE), 2 * SCALE / 1_000_000);
        // A zero divisor is Go's panic; the caller's invalid path applies.
        assert_eq!(div_round(SCALE, 0), 0);
    }

    #[test]
    fn ceil_to_integer_rounds_up_only_for_a_fraction() {
        assert_eq!(ceil_to_integer(3 * SCALE), 3);
        assert_eq!(ceil_to_integer(3 * SCALE + 1), 4);
        assert_eq!(ceil_to_integer(SCALE - 1), 1);
        assert_eq!(ceil_to_integer(0), 0);
    }

    #[test]
    fn to_float_is_the_nearest_f64_of_the_scaled_value() {
        assert_eq!(to_float(73 * SCALE), 73.0);
        assert_eq!(to_float(7_300_000_000_000_000_000), 7.3);
        assert_eq!(to_float(146 * SCALE), 146.0);
        assert_eq!(to_float(0), 0.0);
        assert_eq!(to_float(-73 * SCALE), -73.0);
    }
}
