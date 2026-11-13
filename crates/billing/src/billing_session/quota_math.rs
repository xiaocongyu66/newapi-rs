//! 额度换算核心：Go `internal/common/quota_math.go` 的逐字移植。
//!
//! 额度列（user/token/log）在数据库里是 32 位整数，因此超界乘积必须饱和
//! 到 int32 范围，而不是回绕把扣费变退款。每次饱和都返回 [`QuotaClamp`]
//! 供调用方挂到日志 admin_info 上审计。
//!
//! 语义偏差（报告已注明）：Go 用 shopspring/decimal 做精确十进制运算，
//! 本移植用 f64 直算 + 半程远离零舍入（与 decimal `Round(0)` 一致）。
//! 价格/倍率本身是 f64 来源，误差只在舍入边界翻转上可能出现 ±1 差异；
//! pricing 切片合流后若提供 decimal 形态数据可无缝替换内部实现。

/// Go `common.MaxQuota`：配额列的 int32 上界。
pub const MAX_QUOTA: i64 = i32::MAX as i64;
/// Go `common.MinQuota`。
pub const MIN_QUOTA: i64 = i32::MIN as i64;
/// Go `common.QuotaPerUnit`（constants.go:23）：$0.002 / 1K tokens。
pub const QUOTA_PER_UNIT: f64 = 500_000.0;
/// Go `common.GetTrustQuota()`（quota.go:3-5）：10 * QuotaPerUnit。
pub const TRUST_QUOTA: i64 = (10.0 * QUOTA_PER_UNIT) as i64;

/// 饱和原因。Go `common.QuotaClampKind`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaClampKind {
    Overflow,
    Underflow,
    Nan,
}

impl QuotaClampKind {
    pub fn as_str(self) -> &'static str {
        match self {
            QuotaClampKind::Overflow => "overflow",
            QuotaClampKind::Underflow => "underflow",
            QuotaClampKind::Nan => "nan",
        }
    }
}

/// 一次额度换算饱和事件。Go `common.QuotaClamp`（quota_math.go:44-48）。
#[derive(Debug, Clone, PartialEq)]
pub struct QuotaClamp {
    pub op: &'static str,
    pub kind: QuotaClampKind,
    /// best-effort 饱和前近似值（decimal -> float64）。
    pub original: f64,
    /// 实际采用的饱和结果。
    pub clamped: i64,
}

impl QuotaClamp {
    /// Go `(*QuotaClamp).AuditMap`：admin_info.quota_saturation 的形状。
    pub fn audit_map(&self) -> serde_json::Map<String, serde_json::Value> {
        let mut map = serde_json::Map::new();
        map.insert("op".into(), serde_json::json!(self.op));
        map.insert("kind".into(), serde_json::json!(self.kind.as_str()));
        map.insert("original".into(), serde_json::json!(self.original));
        map.insert("clamped".into(), serde_json::json!(self.clamped));
        map
    }
}

/// 已舍入值 → int 的饱和转换。Go `saturateQuota`（quota_math.go:107-124）。
fn saturate_quota(value: f64, op: &'static str) -> (i64, Option<QuotaClamp>) {
    let clamp = if value.is_nan() {
        QuotaClamp {
            op,
            kind: QuotaClampKind::Nan,
            original: value,
            clamped: 0,
        }
    } else if value >= MAX_QUOTA as f64 {
        QuotaClamp {
            op,
            kind: QuotaClampKind::Overflow,
            original: value,
            clamped: MAX_QUOTA,
        }
    } else if value <= MIN_QUOTA as f64 {
        QuotaClamp {
            op,
            kind: QuotaClampKind::Underflow,
            original: value,
            clamped: MIN_QUOTA,
        }
    } else {
        return (value as i64, None);
    };
    (clamp.clamped, Some(clamp))
}

/// 半程远离零舍入：Go `math.Round` / decimal `Round(0)` 语义。
pub fn round_half_away_from_zero(value: f64) -> f64 {
    (value + value.signum() * 0.5).trunc()
}

/// Go `QuotaFromFloat`：截断取整 + 饱和。用于价格/倍率/用户可控乘积。
pub fn quota_from_float(value: f64) -> i64 {
    quota_from_float_checked(value).0
}

/// Go `QuotaFromFloatChecked`。
pub fn quota_from_float_checked(value: f64) -> (i64, Option<QuotaClamp>) {
    saturate_quota(value, "QuotaFromFloat")
}

/// Go `QuotaRound`：半程远离零舍入 + 饱和。分层计费必须用它避免 ±1 漂移。
pub fn quota_round(value: f64) -> i64 {
    quota_round_checked(value).0
}

/// Go `QuotaRoundChecked`。
pub fn quota_round_checked(value: f64) -> (i64, Option<QuotaClamp>) {
    saturate_quota(round_half_away_from_zero(value), "QuotaRound")
}

/// Go `QuotaFromDecimal`：先半程远离零舍入再饱和。
pub fn quota_from_decimal(value: f64) -> i64 {
    quota_from_decimal_checked(value).0
}

/// Go `QuotaFromDecimalChecked`。
pub fn quota_from_decimal_checked(value: f64) -> (i64, Option<QuotaClamp>) {
    saturate_quota(round_half_away_from_zero(value), "QuotaFromDecimal")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_range_values_pass_through() {
        assert_eq!(quota_from_float(1234.9), 1234);
        assert_eq!(quota_from_float(-1234.9), -1234);
        assert_eq!(quota_from_decimal(3.5), 4);
        assert_eq!(quota_from_decimal(-3.5), -4);
        assert_eq!(quota_round(2.5), 3);
        assert_eq!(quota_round(-2.5), -3);
    }

    #[test]
    fn overflow_saturates_to_int32_max() {
        let (quota, clamp) = quota_from_decimal_checked(2000.0 * 1.844_674_407_368_664_7e19);
        assert_eq!(quota, MAX_QUOTA);
        let clamp = clamp.expect("overflow must report a clamp");
        assert_eq!(clamp.op, "QuotaFromDecimal");
        assert_eq!(clamp.kind, QuotaClampKind::Overflow);
        assert_eq!(clamp.clamped, MAX_QUOTA);
        // Go quota_math_test.go:26 — +Inf 同样饱和到 MaxQuota。
        assert_eq!(quota_from_float(f64::INFINITY), MAX_QUOTA);
    }

    #[test]
    fn underflow_saturates_to_int32_min() {
        let (quota, clamp) = quota_from_decimal_checked(-1.8e19);
        assert_eq!(quota, MIN_QUOTA);
        assert_eq!(clamp.unwrap().kind, QuotaClampKind::Underflow);
    }

    #[test]
    fn nan_clamps_to_zero() {
        let (quota, clamp) = quota_from_decimal_checked(f64::NAN);
        assert_eq!(quota, 0);
        let clamp = clamp.unwrap();
        assert_eq!(clamp.kind, QuotaClampKind::Nan);
        assert_eq!(clamp.clamped, 0);
    }
}
