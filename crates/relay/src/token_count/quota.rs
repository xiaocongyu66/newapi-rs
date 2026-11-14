//! Quota math needed by the token-counting paths. The authoritative port of
//! Go `internal/common/quota_math.go` lives in `newapi-billing`
//! (`billing_session::quota_math`); this module re-implements the two
//! functions the relay layer needs so the relay crate does not depend on the
//! billing crate (the workspace DAG points billing → relay, not the reverse).
//! The semantics must stay identical — any change here is a billing change.

/// Go `common.MaxQuota` / `MinQuota`: quota columns are int32 in the DB.
pub const MAX_QUOTA: i64 = i32::MAX as i64;
pub const MIN_QUOTA: i64 = i32::MIN as i64;

/// Go `saturateQuota` (quota_math.go:72-86): NaN → 0, beyond int32 → clamped.
fn saturate_quota(value: f64) -> i64 {
    if value.is_nan() {
        return 0;
    }
    if value >= MAX_QUOTA as f64 {
        return MAX_QUOTA;
    }
    if value <= MIN_QUOTA as f64 {
        return MIN_QUOTA;
    }
    value as i64
}

/// Half-away-from-zero rounding: Go `math.Round` semantics
/// (billing_session::quota_math::round_half_away_from_zero twin).
pub fn round_half_away_from_zero(value: f64) -> f64 {
    (value + value.signum() * 0.5).trunc()
}

/// Go `QuotaFromFloat` (quota_math.go:95-101): truncate toward zero with
/// saturation.
pub fn quota_from_float(value: f64) -> i64 {
    saturate_quota(value)
}

/// Go `QuotaRound` (quota_math.go:115-122): half-away-from-zero rounding with
/// saturation.
pub fn quota_round(value: f64) -> i64 {
    saturate_quota(round_half_away_from_zero(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirrors the billing crate's quota_math tests (parity guard).
    #[test]
    fn matches_billing_quota_math() {
        assert_eq!(quota_from_float(1234.9), 1234);
        assert_eq!(quota_from_float(-1234.9), -1234);
        assert_eq!(quota_round(2.5), 3);
        assert_eq!(quota_round(-2.5), -3);
        assert_eq!(quota_from_float(f64::NAN), 0);
        assert_eq!(quota_from_float(f64::INFINITY), MAX_QUOTA);
        assert_eq!(quota_from_float(f64::NEG_INFINITY), MIN_QUOTA);
    }
}
