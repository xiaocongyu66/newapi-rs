//! 支付网关共享核心：签名、金额比对与订单核销事务。
//!
//! Go references:
//! - `apps/api/internal/billing/topup_api.go`（`vmqMd5`、`vmqCreateSign`、
//!   `vmqNotifySign`、`codepaySign`、`constantTimeCompare`、
//!   `gatewayPayTypeCode`）
//! - go-epay `github.com/Calcium-Ion/go-epay/epay`（`GenerateParams` /
//!   `Verify`：过滤 `sign`/`sign_type`/空值 → key 升序 `k=v&` 拼接 →
//!   `md5(joined+key)`）
//! - `apps/api/internal/billing/store_topup.go`（`rechargeTopUp`、
//!   `creditTopUpQuota`、`ManualCompleteTopUp`）
//! - `apps/api/internal/billing/store_redemption.go`（`Redeem`）
//!
//! ## 并发与幂等
//!
//! Go 用「进程内 `LockOrder` + 行锁（`FOR UPDATE`）+ 事务内状态校验」保证
//! 同一订单最多入账一次；进程内锁只是优化（多实例下无意义）。本移植用
//! 「事务 + 条件 UPDATE（`... AND status = 'pending'`）+ 影响行数判定」
//! 达成同一不变量：条件失败后重读状态行区分「已完成（幂等忽略）」与
//! 「状态非法」。回调金额比对逐字对齐 Go：票价按 2 位小数精确相等，实付
//! 与订单金额之差的绝对值不得超过容差。

use std::collections::BTreeMap;

use newapi_storage::Database;
use rand::Rng;
use sqlx::Row;

use super::quote::top_up_quota;

/// Go `common.TopUpStatus*`。
pub const STATUS_PENDING: &str = "pending";
pub const STATUS_SUCCESS: &str = "success";
pub const STATUS_FAILED: &str = "failed";
pub const STATUS_EXPIRED: &str = "expired";

/// Go `billing.PaymentProvider*` 常量。
pub const PROVIDER_EPAY: &str = "epay";
pub const PROVIDER_VMQ: &str = "vmq";
pub const PROVIDER_CODEPAY: &str = "codepay";
pub const PROVIDER_STRIPE: &str = "stripe";
pub const PROVIDER_CREEM: &str = "creem";
pub const PROVIDER_WAFFO: &str = "waffo";
pub const PROVIDER_WAFFO_PANCAKE: &str = "waffo_pancake";

/// Go `usage.LogTypeTopup`。
pub const LOG_TYPE_TOPUP: i64 = 1;
/// Go `common.RedemptionCodeStatusEnabled` / `Used`。
pub const REDEMPTION_ENABLED: i64 = 1;
pub const REDEMPTION_USED: i64 = 2;

/// Go `common.MaxQuota`（`common/quota_math.go:15`）。
const MAX_QUOTA: i64 = 2_147_483_647;

/// Go `constantTimeCompare`：定时安全的字符串比较。
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Go `vmqMd5`：小写十六进制 MD5。`md5` 0.8 的 API 是 `compute(bytes)` +
/// `format!("{:x}")`（`digest::Digest` 风格属于 `md-5` 0.10）。
pub fn md5_hex(input: &str) -> String {
    format!("{:x}", md5::compute(input.as_bytes()))
}

/// go-epay `GenerateParams` 的签名部分：过滤 `sign`/`sign_type`/空值，key
/// 升序拼 `k=v&...`，`md5(joined+key)`。
pub fn epay_sign(params: &BTreeMap<String, String>, key: &str) -> String {
    let mut keys: Vec<&String> = params
        .iter()
        .filter(|(k, v)| k.as_str() != "sign" && k.as_str() != "sign_type" && !v.is_empty())
        .map(|(k, _)| k)
        .collect();
    keys.sort();
    let joined = keys
        .iter()
        .map(|k| format!("{k}={}", params[*k]))
        .collect::<Vec<_>>()
        .join("&");
    md5_hex(&format!("{joined}{key}"))
}

/// Go `vmqCreateSign`：`md5(payId+param+type+price+key)`。
pub fn vmq_create_sign(
    pay_id: &str,
    param: &str,
    pay_type: &str,
    price: &str,
    key: &str,
) -> String {
    md5_hex(&format!("{pay_id}{param}{pay_type}{price}{key}"))
}

/// Go `vmqNotifySign`：`md5(payId+param+type+price+reallyPrice+key)`。
pub fn vmq_notify_sign(
    pay_id: &str,
    param: &str,
    pay_type: &str,
    price: &str,
    really_price: &str,
    key: &str,
) -> String {
    md5_hex(&format!(
        "{pay_id}{param}{pay_type}{price}{really_price}{key}"
    ))
}

/// Go `codepaySign`：全部非空参数（`sign` 除外）按 key 升序 `k=v&...`，
/// `md5(joined+key)`。值用原始（未 url 编码）字符串。
pub fn codepay_sign(params: &BTreeMap<String, String>, key: &str) -> String {
    let mut keys: Vec<&String> = params
        .iter()
        .filter(|(k, v)| k.as_str() != "sign" && !v.is_empty())
        .map(|(k, _)| k)
        .collect();
    keys.sort();
    let joined = keys
        .iter()
        .map(|k| format!("{k}={}", params[*k]))
        .collect::<Vec<_>>()
        .join("&");
    md5_hex(&format!("{joined}{key}"))
}

/// 把金额字符串解析成 2 位小数的「分」（i128），四舍五入 half away from
/// zero——Go `decimal.NewFromString(..).Round(2)` 的等价物。非法输入返回
/// `None`（Go 的解析错误分支）。
pub fn round2_cents(input: &str) -> Option<i128> {
    let input = input.trim();
    let (negative, digits) = match input.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, input.strip_prefix('+').unwrap_or(input)),
    };
    let (int_part, frac_part) = match digits.split_once('.') {
        Some((int_part, frac_part)) => (int_part, frac_part),
        None => (digits, ""),
    };
    if int_part.is_empty() && frac_part.is_empty() {
        return None;
    }
    if !int_part.bytes().all(|b| b.is_ascii_digit())
        || !frac_part.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    // shopspring `Round(2)` 是 half away from zero：第 3 位 ≥5 一律进位，
    // 其后位的取值只影响非平局场景（本实现按完整十进制值判断，等价）。
    let frac = frac_part.as_bytes();
    let third = i128::from(*frac.get(2).unwrap_or(&b'0') - b'0');
    let mut value: i128 = 0;
    for byte in int_part.bytes() {
        value = value
            .checked_mul(10)?
            .checked_add(i128::from(byte - b'0'))?;
    }
    value = value.checked_mul(100)?;
    if !frac.is_empty() {
        let first = i128::from(frac[0] - b'0');
        let second = i128::from(*frac.get(1).unwrap_or(&b'0') - b'0');
        value += first * 10 + second;
        if third >= 5 {
            value += 1;
        }
    }
    Some(if negative { -value } else { value })
}

/// Go `gatewayPayTypeCode`：VMQ 支付宝 2 / 微信 1，CodePay 支付宝 1 / 微信 3。
pub fn gateway_pay_type_code(gateway: &str, method_type: &str) -> Option<&'static str> {
    match (gateway, method_type) {
        ("vmq", "alipay") => Some("2"),
        ("vmq", "wxpay") => Some("1"),
        ("codepay", "alipay") => Some("1"),
        ("codepay", "wxpay") => Some("3"),
        _ => None,
    }
}

/// Go `common.GetRandomString(6)`：`lo.AlphanumericCharset` 上的随机串
/// （52 个字母 + 10 个数字）。
pub fn random_string(length: usize) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

/// Go `randstr.String(n)`：Base62 字符集（`0-9a-zA-Z`）。
pub fn base62_string(length: usize) -> String {
    const CHARSET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

/// Go `common.Sha1`：小写十六进制 SHA-1（仅用于非保密的引用串）。
pub fn sha1_hex(input: &str) -> String {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Go `common.GetTimestamp()`。
pub fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// 订单核销失败分类，逐条对应 Go `store_topup.go` 的哨兵错误。
#[derive(Debug)]
pub enum RechargeError {
    /// Go `ErrTopUpNotFound`（含空订单号）。
    NotFound,
    /// Go `ErrPaymentMethodMismatch`。
    ProviderMismatch,
    /// Go `ErrTopUpStatusInvalid`。
    StatusInvalid,
    /// Go `ErrPaymentAmountMismatch`。
    AmountMismatch,
    /// Go `ErrInvalidTopUpQuota`。
    InvalidQuota,
    /// Go `gorm.ErrRecordNotFound`（入账时用户行不存在）。
    UserMissing,
    /// Go `ErrTopUpQuotaLimitExceeded`。
    QuotaLimitExceeded,
    /// 其余（SQL 错误等）。
    Storage(sqlx::Error),
}

impl From<sqlx::Error> for RechargeError {
    fn from(error: sqlx::Error) -> Self {
        Self::Storage(error)
    }
}

/// 核销成功时带回的字段（事务外记日志用）。
#[derive(Debug)]
pub struct RechargeRecord {
    pub user_id: i64,
    pub quota_added: i64,
    pub money: f64,
    pub payment_method: String,
}

/// 核销结果：`AlreadyDone` = 此前已完成，本次为幂等重复回调。
#[derive(Debug)]
pub enum RechargeOutcome {
    AlreadyDone,
    Completed(RechargeRecord),
}

/// Go `rechargeTopUp` 的入参（收敛为结构体）。
pub struct RechargeParams<'a> {
    pub trade_no: &'a str,
    pub expected_provider: &'a str,
    /// 非空时更新订单的实际支付方式（Go `actualPaymentMethod`）。
    pub actual_payment_method: Option<&'a str>,
    /// 网关回调原票价（VMQ `price` / CodePay `price`）；`None` 不校验
    /// （epay）。与订单金额按 2 位小数精确相等。
    pub notify_price: Option<&'a str>,
    /// 网关实际到账金额（VMQ `reallyPrice`）；`None` 不校验。
    pub paid_amount: Option<&'a str>,
    /// `paid_amount` 与订单金额允许的最大绝对偏差（分）。
    pub paid_tolerance_cents: i128,
    /// `QuotaPerUnit`（展示配置快照）。
    pub quota_per_unit: f64,
}

const RECHARGE_SELECT: &str = concat!(
    "SELECT id, user_id, amount, money, trade_no, payment_method, ",
    "payment_provider, status FROM top_ups WHERE trade_no = $1"
);

/// Go `rechargeTopUp`：网关归属校验 + 幂等已完成 + 状态校验 + 回调金额分
/// 精度比对 + 额度入账，同一事务内完成。
pub async fn recharge_top_up(
    db: &Database,
    params: RechargeParams<'_>,
) -> Result<RechargeOutcome, RechargeError> {
    if params.trade_no.is_empty() {
        return Err(RechargeError::NotFound);
    }
    // 与 Go 同序：金额串解析失败即 AmountMismatch（事务外预解析，行为一致）。
    let notify_cents = match params.notify_price {
        Some(price) => Some(round2_cents(price).ok_or(RechargeError::AmountMismatch)?),
        None => None,
    };
    let paid_cents = match params.paid_amount {
        Some(price) => Some(round2_cents(price).ok_or(RechargeError::AmountMismatch)?),
        None => None,
    };
    match db {
        Database::Sqlite(pool) => {
            let mut tx = pool.begin().await?;
            let outcome = recharge_in_tx_sqlite(&mut tx, &params, notify_cents, paid_cents).await;
            if outcome.is_err() {
                tx.rollback().await.ok();
                return outcome;
            }
            tx.commit().await?;
            outcome
        }
        Database::Postgres(pool) => {
            let mut tx = pool.begin().await?;
            let outcome = recharge_in_tx_pg(&mut tx, &params, notify_cents, paid_cents).await;
            if outcome.is_err() {
                tx.rollback().await.ok();
                return outcome;
            }
            tx.commit().await?;
            outcome
        }
    }
}

/// 事务内共享主体；`sqlx` 的 `Executor` 不跨数据库种类，故以 `&mut`
/// 连接/事务的公共形态（`&mut SqliteConnection` / `&mut PgConnection`）
/// 由宏按后端实例化。
macro_rules! recharge_in_tx_impl {
    ($tx:expr, $params:expr, $notify_cents:expr, $paid_cents:expr) => {{
        let row = sqlx::query(RECHARGE_SELECT)
            .bind($params.trade_no)
            .fetch_optional(&mut **$tx)
            .await?;
        let Some(row) = row else {
            return Err(RechargeError::NotFound);
        };
        let order_id: i64 = row.try_get("id")?;
        let user_id: i64 = row
            .try_get::<Option<i64>, _>("user_id")?
            .unwrap_or_default();
        let amount: i64 = row.try_get::<Option<i64>, _>("amount")?.unwrap_or_default();
        let money: f64 = row.try_get::<Option<f64>, _>("money")?.unwrap_or_default();
        let payment_method: String = row
            .try_get::<Option<String>, _>("payment_method")?
            .unwrap_or_default();
        let provider: String = row
            .try_get::<Option<String>, _>("payment_provider")?
            .unwrap_or_default();
        let status: String = row
            .try_get::<Option<String>, _>("status")?
            .unwrap_or_default();

        if provider != $params.expected_provider {
            return Err(RechargeError::ProviderMismatch);
        }
        if status == STATUS_SUCCESS {
            return Ok(RechargeOutcome::AlreadyDone);
        }
        if status != STATUS_PENDING {
            return Err(RechargeError::StatusInvalid);
        }
        // Go：`orderMoney = decimal.NewFromFloat(topUp.Money).Round(2)`，
        // 票价按 2 位小数精确相等。
        let order_cents = f64_to_round2_cents(money);
        if let Some(notify_cents) = $notify_cents
            && notify_cents != order_cents
        {
            return Err(RechargeError::AmountMismatch);
        }
        // Go：`|paid.Round(2) - orderMoney| > tolerance` → 金额不符。
        if let Some(paid_cents) = $paid_cents
            && (paid_cents - order_cents).abs() > $params.paid_tolerance_cents
        {
            return Err(RechargeError::AmountMismatch);
        }
        // Go `QuotaFromDecimalStrict(Amount × QuotaPerUnit)`：复用已审计的
        // 固定点换算（`top_up_quota` 的 USD/CNY 分支，round + int32 边界）。
        let settings = super::TopUpSettings::default();
        let Some(quota_added) = top_up_quota(&settings, amount, false, $params.quota_per_unit)
        else {
            return Err(RechargeError::InvalidQuota);
        };
        if quota_added <= 0 {
            return Err(RechargeError::InvalidQuota);
        }
        // 条件翻转（CAS）：只有把 pending → success 的那笔事务才入账。
        let actual_method = $params.actual_payment_method.unwrap_or(&payment_method);
        let updated = sqlx::query(
            "UPDATE top_ups SET status = $1, complete_time = $2, payment_method = $3 \
             WHERE id = $4 AND status = $5",
        )
        .bind(STATUS_SUCCESS)
        .bind(now_seconds())
        .bind(actual_method)
        .bind(order_id)
        .bind(STATUS_PENDING)
        .execute(&mut **$tx)
        .await?
        .rows_affected();
        if updated == 0 {
            // 并发竞争：重读状态区分幂等与非法。
            let current: Option<String> =
                sqlx::query_scalar("SELECT status FROM top_ups WHERE id = $1")
                    .bind(order_id)
                    .fetch_optional(&mut **$tx)
                    .await?;
            return match current.as_deref() {
                Some(STATUS_SUCCESS) => Ok(RechargeOutcome::AlreadyDone),
                _ => Err(RechargeError::StatusInvalid),
            };
        }
        // Go `creditTopUpQuota`：上限谓词与自增放在同一条 UPDATE 里，
        // 防止两笔并发回调各自通过独立的读-检-写。
        let max_current = MAX_QUOTA - 1 - quota_added;
        let credited =
            sqlx::query("UPDATE users SET quota = quota + $1 WHERE id = $2 AND quota <= $3")
                .bind(quota_added)
                .bind(user_id)
                .bind(max_current)
                .execute(&mut **$tx)
                .await?
                .rows_affected();
        if credited == 0 {
            let exists: Option<i64> = sqlx::query_scalar("SELECT id FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_optional(&mut **$tx)
                .await?;
            return match exists {
                Some(_) => Err(RechargeError::QuotaLimitExceeded),
                None => Err(RechargeError::UserMissing),
            };
        }
        Ok(RechargeOutcome::Completed(RechargeRecord {
            user_id,
            quota_added,
            money,
            payment_method: actual_method.to_owned(),
        }))
    }};
}

async fn recharge_in_tx_sqlite(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    params: &RechargeParams<'_>,
    notify_cents: Option<i128>,
    paid_cents: Option<i128>,
) -> Result<RechargeOutcome, RechargeError> {
    recharge_in_tx_impl!(tx, params, notify_cents, paid_cents)
}

async fn recharge_in_tx_pg(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    params: &RechargeParams<'_>,
    notify_cents: Option<i128>,
    paid_cents: Option<i128>,
) -> Result<RechargeOutcome, RechargeError> {
    recharge_in_tx_impl!(tx, params, notify_cents, paid_cents)
}

/// Go `decimal.NewFromFloat(money).Round(2)` → 分。`f64` 先按十进制字面
/// 还原到 2 位再取整；_money 均来自服务端自己格式化过的 2 位小数字符串_，
/// 该路径与 Go 的 decimal Round(2) 在所有 2 位小数可表示值上一致。
fn f64_to_round2_cents(money: f64) -> i128 {
    let scaled = (money * 100.0).round();
    if !scaled.is_finite() {
        return 0;
    }
    scaled as i128
}

/// Go `ManualCompleteTopUp`：管理员补单。幂等（已成功直接返回成功），
/// quota 来源按 provider 区分：Stripe 用 `Money × QuotaPerUnit`，其余用
/// `Amount × QuotaPerUnit`。
pub async fn manual_complete_top_up(
    db: &Database,
    trade_no: &str,
    quota_per_unit: f64,
) -> Result<RechargeRecord, RechargeError> {
    if trade_no.is_empty() {
        return Err(RechargeError::NotFound);
    }
    match db {
        Database::Sqlite(pool) => {
            let mut tx = pool.begin().await?;
            let record = manual_complete_in_tx_sqlite(&mut tx, trade_no, quota_per_unit).await;
            if record.is_err() {
                tx.rollback().await.ok();
                return record;
            }
            tx.commit().await?;
            record
        }
        Database::Postgres(pool) => {
            let mut tx = pool.begin().await?;
            let record = manual_complete_in_tx_pg(&mut tx, trade_no, quota_per_unit).await;
            if record.is_err() {
                tx.rollback().await.ok();
                return record;
            }
            tx.commit().await?;
            record
        }
    }
}

macro_rules! manual_complete_in_tx_impl {
    ($tx:expr, $trade_no:expr, $quota_per_unit:expr) => {{
        let row = sqlx::query(RECHARGE_SELECT)
            .bind($trade_no)
            .fetch_optional(&mut **$tx)
            .await?;
        let Some(row) = row else {
            return Err(RechargeError::NotFound);
        };
        let order_id: i64 = row.try_get("id")?;
        let user_id: i64 = row
            .try_get::<Option<i64>, _>("user_id")?
            .unwrap_or_default();
        let amount: i64 = row.try_get::<Option<i64>, _>("amount")?.unwrap_or_default();
        let money: f64 = row.try_get::<Option<f64>, _>("money")?.unwrap_or_default();
        let payment_method: String = row
            .try_get::<Option<String>, _>("payment_method")?
            .unwrap_or_default();
        let provider: String = row
            .try_get::<Option<String>, _>("payment_provider")?
            .unwrap_or_default();
        let status: String = row
            .try_get::<Option<String>, _>("status")?
            .unwrap_or_default();
        if status == STATUS_SUCCESS {
            // Go：幂等直接返回（调用方回 success）。
            return Ok(RechargeRecord {
                user_id,
                quota_added: 0,
                money,
                payment_method,
            });
        }
        if status != STATUS_PENDING {
            return Err(RechargeError::StatusInvalid);
        }
        // Stripe 订单：Money 是经分组倍率换算后的美元数；其余订单用 Amount。
        let quota_added = if provider == PROVIDER_STRIPE {
            quota_from_product_f64(money, $quota_per_unit)
        } else {
            let settings = super::TopUpSettings::default();
            top_up_quota(&settings, amount, false, $quota_per_unit)
        }
        .ok_or(RechargeError::InvalidQuota)?;
        if quota_added <= 0 {
            return Err(RechargeError::InvalidQuota);
        }
        let updated = sqlx::query(
            "UPDATE top_ups SET status = $1, complete_time = $2 WHERE id = $3 AND status = $4",
        )
        .bind(STATUS_SUCCESS)
        .bind(now_seconds())
        .bind(order_id)
        .bind(STATUS_PENDING)
        .execute(&mut **$tx)
        .await?
        .rows_affected();
        if updated == 0 {
            return Err(RechargeError::StatusInvalid);
        }
        let max_current = MAX_QUOTA - 1 - quota_added;
        let credited =
            sqlx::query("UPDATE users SET quota = quota + $1 WHERE id = $2 AND quota <= $3")
                .bind(quota_added)
                .bind(user_id)
                .bind(max_current)
                .execute(&mut **$tx)
                .await?
                .rows_affected();
        if credited == 0 {
            let exists: Option<i64> = sqlx::query_scalar("SELECT id FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_optional(&mut **$tx)
                .await?;
            return match exists {
                Some(_) => Err(RechargeError::QuotaLimitExceeded),
                None => Err(RechargeError::UserMissing),
            };
        }
        Ok(RechargeRecord {
            user_id,
            quota_added,
            money,
            payment_method,
        })
    }};
}

async fn manual_complete_in_tx_sqlite(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    trade_no: &str,
    quota_per_unit: f64,
) -> Result<RechargeRecord, RechargeError> {
    manual_complete_in_tx_impl!(tx, trade_no, quota_per_unit)
}

async fn manual_complete_in_tx_pg(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    trade_no: &str,
    quota_per_unit: f64,
) -> Result<RechargeRecord, RechargeError> {
    manual_complete_in_tx_impl!(tx, trade_no, quota_per_unit)
}

/// Go `decimal.NewFromFloat(money).Mul(QuotaPerUnit)` → `QuotaFromDecimalStrict`。
/// Stripe 的 Money 是服务端算出的浮点美元数，round 后过 int32 边界检查。
fn quota_from_product_f64(money: f64, quota_per_unit: f64) -> Option<i64> {
    let product = money * quota_per_unit;
    if !product.is_finite() {
        return None;
    }
    let rounded = product.round();
    if rounded <= 0.0 || rounded >= f64::from(MAX_QUOTA as i32) {
        return None;
    }
    Some(rounded as i64)
}

/// Go `Redeem`：兑换码核销。任何失败都折叠为同一个「兑换失败」哨兵
/// （Go `dbinfra.ErrRedeemFailed`），不向用户暴露细分原因。
pub async fn redeem(db: &Database, key: &str, user_id: i64) -> Result<i64, RedeemFailed> {
    if key.is_empty() || user_id == 0 {
        return Err(RedeemFailed);
    }
    match db {
        Database::Sqlite(pool) => redeem_on_sqlite(pool, key, user_id).await,
        Database::Postgres(pool) => redeem_on_pg(pool, key, user_id).await,
    }
}

/// 兑换失败哨兵（Go `dbinfra.ErrRedeemFailed`）。
#[derive(Debug)]
pub struct RedeemFailed;

/// 兑换事务体：`Executor` 不跨后端，宏在每个后端上各实例化一次。
macro_rules! redeem_on_impl {
    ($pool:expr, $key:expr, $user_id:expr) => {{
        // Go `common.RandomSleep()`：0–3000ms 反枚举时序抖动。
        let jitter = rand::thread_rng().gen_range(0..3000u64);
        tokio::time::sleep(std::time::Duration::from_millis(jitter)).await;
        let mut tx = match $pool.begin().await {
            Ok(tx) => tx,
            Err(_) => return Err(RedeemFailed),
        };
        let row = sqlx::query(
            "SELECT id, quota, status, expired_time FROM redemptions \
             WHERE key = $1 AND deleted_at IS NULL",
        )
        .bind($key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| RedeemFailed)?;
        let Some(row) = row else {
            return Err(RedeemFailed);
        };
        let id: i64 = row.try_get("id").map_err(|_| RedeemFailed)?;
        let quota: i64 = row
            .try_get::<Option<i64>, _>("quota")
            .map_err(|_| RedeemFailed)?
            .unwrap_or_default();
        let status: i64 = row
            .try_get::<Option<i64>, _>("status")
            .map_err(|_| RedeemFailed)?
            .unwrap_or_default();
        let expired_time: i64 = row
            .try_get::<Option<i64>, _>("expired_time")
            .map_err(|_| RedeemFailed)?
            .unwrap_or_default();
        if status != REDEMPTION_ENABLED {
            return Err(RedeemFailed);
        }
        if expired_time != 0 && expired_time < now_seconds() {
            return Err(RedeemFailed);
        }
        // CAS：enabled → used，只有成功翻转的事务才入账。
        let flipped = sqlx::query(
            "UPDATE redemptions SET redeemed_time = $1, status = $2, used_user_id = $3 \
             WHERE id = $4 AND status = $5",
        )
        .bind(now_seconds())
        .bind(REDEMPTION_USED)
        .bind($user_id)
        .bind(id)
        .bind(REDEMPTION_ENABLED)
        .execute(&mut *tx)
        .await
        .map_err(|_| RedeemFailed)?
        .rows_affected();
        if flipped == 0 {
            return Err(RedeemFailed);
        }
        sqlx::query("UPDATE users SET quota = quota + $1 WHERE id = $2")
            .bind(quota)
            .bind($user_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| RedeemFailed)?;
        tx.commit().await.map_err(|_| RedeemFailed)?;
        Ok(quota)
    }};
}

async fn redeem_on_sqlite(
    pool: &sqlx::Pool<sqlx::Sqlite>,
    key: &str,
    user_id: i64,
) -> Result<i64, RedeemFailed> {
    redeem_on_impl!(pool, key, user_id)
}

async fn redeem_on_pg(
    pool: &sqlx::Pool<sqlx::Postgres>,
    key: &str,
    user_id: i64,
) -> Result<i64, RedeemFailed> {
    redeem_on_impl!(pool, key, user_id)
}

/// 新建充值订单（Go `TopUp.Insert`）。
pub async fn insert_topup(
    db: &Database,
    user_id: i64,
    amount: i64,
    money: f64,
    trade_no: &str,
    payment_method: &str,
    payment_provider: &str,
) -> Result<(), sqlx::Error> {
    let sql = "INSERT INTO top_ups (user_id, amount, money, trade_no, payment_method, \
               payment_provider, create_time, complete_time, status) \
               VALUES ($1,$2,$3,$4,$5,$6,$7,0,$8)";
    match db {
        Database::Sqlite(pool) => {
            sqlx::query(sql)
                .bind(user_id)
                .bind(amount)
                .bind(money)
                .bind(trade_no)
                .bind(payment_method)
                .bind(payment_provider)
                .bind(now_seconds())
                .bind(STATUS_PENDING)
                .execute(pool)
                .await?;
        }
        Database::Postgres(pool) => {
            sqlx::query(sql)
                .bind(user_id)
                .bind(amount)
                .bind(money)
                .bind(trade_no)
                .bind(payment_method)
                .bind(payment_provider)
                .bind(now_seconds())
                .bind(STATUS_PENDING)
                .execute(pool)
                .await?;
        }
    }
    Ok(())
}

/// Go `usage.RecordTopupLog` 的持久化部分：type=1 的消费日志行，`other`
/// 携带 admin_info（caller_ip / payment_method / callback_payment_method）。
pub async fn record_topup_log(
    db: &Database,
    user_id: i64,
    content: &str,
    caller_ip: &str,
    payment_method: &str,
    callback_payment_method: &str,
) {
    let admin_info = serde_json::json!({
        "caller_ip": caller_ip,
        "payment_method": payment_method,
        "callback_payment_method": callback_payment_method,
    });
    let other = serde_json::json!({ "admin_info": admin_info }).to_string();
    let username: String = match db {
        Database::Sqlite(pool) => sqlx::query_scalar("SELECT username FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(pool)
            .await
            .ok()
            .flatten()
            .unwrap_or_default(),
        Database::Postgres(pool) => sqlx::query_scalar("SELECT username FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(pool)
            .await
            .ok()
            .flatten()
            .unwrap_or_default(),
    };
    let sql = "INSERT INTO logs (user_id, created_at, type, content, username, \
               token_name, model_name, quota, prompt_tokens, completion_tokens, \
               use_time, is_stream, ip, request_id, other) \
               VALUES ($1,$2,$3,$4,$5,'','',0,0,0,0,false,$6,'',$7)";
    let now = now_seconds();
    let result = match db {
        Database::Sqlite(pool) => sqlx::query(sql)
            .bind(user_id)
            .bind(now)
            .bind(LOG_TYPE_TOPUP)
            .bind(content)
            .bind(username)
            .bind(caller_ip)
            .bind(&other)
            .execute(pool)
            .await
            .map(|_| ()),
        Database::Postgres(pool) => sqlx::query(sql)
            .bind(user_id)
            .bind(now)
            .bind(LOG_TYPE_TOPUP)
            .bind(content)
            .bind(username)
            .bind(caller_ip)
            .bind(&other)
            .execute(pool)
            .await
            .map(|_| ()),
    };
    if let Err(error) = result {
        tracing::warn!(
            event = "topup_log_write_failed",
            category = "database",
            "failed to record topup log"
        );
        let _ = error;
    }
}

// ---------------------------------------------------------------------------
// Stripe / Creem / Waffo / Waffo Pancake 的回调核销与状态翻转
// ---------------------------------------------------------------------------

/// 各网关应入账额度的来源（Go `store_topup.go` 的按 provider 分支）：
/// - `MoneyTimesUnit`：Stripe 订单 `Money × QuotaPerUnit`（`Recharge`）
/// - `AmountTimesUnit`：Waffo / Waffo Pancake 订单 `Amount × QuotaPerUnit`
/// - `AmountRaw`：Creem 订单直接用 `Amount`（`RechargeCreem`）
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExternalQuotaSource {
    MoneyTimesUnit,
    AmountTimesUnit,
    AmountRaw,
}

/// 核销成功时附带写入 users 表的字段（Go `creditTopUpQuota` 的 `updates`）：
/// - `StripeCustomer`：Stripe 回调把 customer id 写入 `stripe_customer`
/// - `EmailIfEmpty`：Creem 回调仅在用户邮箱为空时回填支付邮箱
#[derive(Clone, Copy, Debug)]
pub enum ExternalUserUpdate<'a> {
    None,
    StripeCustomer(&'a str),
    EmailIfEmpty(&'a str),
}

/// Go `Recharge` / `RechargeCreem` / `RechargeWaffo` / `RechargeWaffoPancake`
/// 的共享事务体。`idempotent_success` 对齐各网关的幂等语义：Waffo 两族对已
/// 成功订单直接返回成功（`RechargeOutcome::AlreadyDone`）；Stripe / Creem 的
/// 非 pending 状态（含已成功）返回 `StatusInvalid`，由回调端折算成永久失败
/// 或 200 忽略。
pub struct ExternalRechargeParams<'a> {
    pub trade_no: &'a str,
    pub expected_provider: &'a str,
    pub quota_source: ExternalQuotaSource,
    pub quota_per_unit: f64,
    pub idempotent_success: bool,
    pub user_update: ExternalUserUpdate<'a>,
}

/// Go `RechargeWaffo` / `RechargeWaffoPancake`：幂等成功跳过。
pub async fn recharge_external_top_up(
    db: &Database,
    params: ExternalRechargeParams<'_>,
) -> Result<RechargeOutcome, RechargeError> {
    if params.trade_no.is_empty() {
        return Err(RechargeError::NotFound);
    }
    match db {
        Database::Sqlite(pool) => {
            let mut tx = pool.begin().await?;
            let outcome =
                recharge_external_in_tx_sqlite(&mut tx, &params).await;
            if outcome.is_err() {
                tx.rollback().await.ok();
                return outcome;
            }
            tx.commit().await?;
            outcome
        }
        Database::Postgres(pool) => {
            let mut tx = pool.begin().await?;
            let outcome = recharge_external_in_tx_pg(&mut tx, &params).await;
            if outcome.is_err() {
                tx.rollback().await.ok();
                return outcome;
            }
            tx.commit().await?;
            outcome
        }
    }
}

macro_rules! recharge_external_in_tx_impl {
    ($tx:expr, $params:expr) => {{
        let row = sqlx::query(RECHARGE_SELECT)
            .bind($params.trade_no)
            .fetch_optional(&mut **$tx)
            .await?;
        let Some(row) = row else {
            return Err(RechargeError::NotFound);
        };
        let order_id: i64 = row.try_get("id")?;
        let user_id: i64 = row
            .try_get::<Option<i64>, _>("user_id")?
            .unwrap_or_default();
        let amount: i64 = row.try_get::<Option<i64>, _>("amount")?.unwrap_or_default();
        let money: f64 = row.try_get::<Option<f64>, _>("money")?.unwrap_or_default();
        let payment_method: String = row
            .try_get::<Option<String>, _>("payment_method")?
            .unwrap_or_default();
        let provider: String = row
            .try_get::<Option<String>, _>("payment_provider")?
            .unwrap_or_default();
        let status: String = row
            .try_get::<Option<String>, _>("status")?
            .unwrap_or_default();

        if provider != $params.expected_provider {
            return Err(RechargeError::ProviderMismatch);
        }
        if status == STATUS_SUCCESS {
            if $params.idempotent_success {
                return Ok(RechargeOutcome::AlreadyDone);
            }
            return Err(RechargeError::StatusInvalid);
        }
        if status != STATUS_PENDING {
            return Err(RechargeError::StatusInvalid);
        }
        let quota_added = match $params.quota_source {
            ExternalQuotaSource::MoneyTimesUnit => {
                quota_from_product_f64(money, $params.quota_per_unit)
            }
            ExternalQuotaSource::AmountTimesUnit => {
                let settings = super::TopUpSettings::default();
                top_up_quota(&settings, amount, false, $params.quota_per_unit)
            }
            ExternalQuotaSource::AmountRaw => quota_from_int_strict(amount),
        };
        let Some(quota_added) = quota_added else {
            return Err(RechargeError::InvalidQuota);
        };
        if quota_added <= 0 {
            return Err(RechargeError::InvalidQuota);
        }
        let updated = sqlx::query(
            "UPDATE top_ups SET status = $1, complete_time = $2 WHERE id = $3 AND status = $4",
        )
        .bind(STATUS_SUCCESS)
        .bind(now_seconds())
        .bind(order_id)
        .bind(STATUS_PENDING)
        .execute(&mut **$tx)
        .await?
        .rows_affected();
        if updated == 0 {
            return Err(RechargeError::StatusInvalid);
        }
        let max_current = MAX_QUOTA - 1 - quota_added;
        let credited = match $params.user_update {
            ExternalUserUpdate::None => {
                sqlx::query("UPDATE users SET quota = quota + $1 WHERE id = $2 AND quota <= $3")
                    .bind(quota_added)
                    .bind(user_id)
                    .bind(max_current)
                    .execute(&mut **$tx)
                    .await?
                    .rows_affected()
            }
            ExternalUserUpdate::StripeCustomer(customer) => {
                sqlx::query(
                    "UPDATE users SET quota = quota + $1, stripe_customer = $2 \
                     WHERE id = $3 AND quota <= $4",
                )
                .bind(quota_added)
                .bind(customer)
                .bind(user_id)
                .bind(max_current)
                .execute(&mut **$tx)
                .await?
                .rows_affected()
            }
            ExternalUserUpdate::EmailIfEmpty(email) => {
                sqlx::query(
                    "UPDATE users SET quota = quota + $1, \
                     email = CASE WHEN email IS NULL OR email = '' THEN $2 ELSE email END \
                     WHERE id = $3 AND quota <= $4",
                )
                .bind(quota_added)
                .bind(email)
                .bind(user_id)
                .bind(max_current)
                .execute(&mut **$tx)
                .await?
                .rows_affected()
            }
        };
        if credited == 0 {
            let exists: Option<i64> = sqlx::query_scalar("SELECT id FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_optional(&mut **$tx)
                .await?;
            return match exists {
                Some(_) => Err(RechargeError::QuotaLimitExceeded),
                None => Err(RechargeError::UserMissing),
            };
        }
        Ok(RechargeOutcome::Completed(RechargeRecord {
            user_id,
            quota_added,
            money,
            payment_method,
        }))
    }};
}

async fn recharge_external_in_tx_sqlite(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    params: &ExternalRechargeParams<'_>,
) -> Result<RechargeOutcome, RechargeError> {
    recharge_external_in_tx_impl!(tx, params)
}

async fn recharge_external_in_tx_pg(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    params: &ExternalRechargeParams<'_>,
) -> Result<RechargeOutcome, RechargeError> {
    recharge_external_in_tx_impl!(tx, params)
}

/// Go `common.QuotaFromDecimalStrict(decimal.NewFromInt(amount))`：整数额度
/// 的严格换算（正数且低于 int32 上限）。
fn quota_from_int_strict(amount: i64) -> Option<i64> {
    if amount <= 0 || amount >= i64::from(MAX_QUOTA as i32) {
        return None;
    }
    Some(amount)
}

/// Go `UpdatePendingTopUpStatus`：按订单号与网关把 pending 订单翻转到目标
/// 状态（过期 / 失败标记）。找不到订单、网关不符或状态非 pending 都上抛。
pub async fn update_pending_top_up_status(
    db: &Database,
    trade_no: &str,
    expected_provider: &str,
    target_status: &str,
) -> Result<(), RechargeError> {
    if trade_no.is_empty() {
        return Err(RechargeError::NotFound);
    }
    let updated = match db {
        Database::Sqlite(pool) => {
            sqlx::query(
                "UPDATE top_ups SET status = $1 WHERE trade_no = $2 \
                 AND payment_provider = $3 AND status = $4",
            )
            .bind(target_status)
            .bind(trade_no)
            .bind(expected_provider)
            .bind(STATUS_PENDING)
            .execute(pool)
            .await?
            .rows_affected()
        }
        Database::Postgres(pool) => {
            sqlx::query(
                "UPDATE top_ups SET status = $1 WHERE trade_no = $2 \
                 AND payment_provider = $3 AND status = $4",
            )
            .bind(target_status)
            .bind(trade_no)
            .bind(expected_provider)
            .bind(STATUS_PENDING)
            .execute(pool)
            .await?
            .rows_affected()
        }
    };
    if updated > 0 {
        return Ok(());
    }
    // 条件翻转失败时重读订单行区分三种哨兵错误（与 Go 的先读后写等序）。
    let row: Option<(Option<String>, Option<String>)> = match db {
        Database::Sqlite(pool) => sqlx::query_as(
            "SELECT payment_provider, status FROM top_ups WHERE trade_no = $1",
        )
        .bind(trade_no)
        .fetch_optional(pool)
        .await?,
        Database::Postgres(pool) => sqlx::query_as(
            "SELECT payment_provider, status FROM top_ups WHERE trade_no = $1",
        )
        .bind(trade_no)
        .fetch_optional(pool)
        .await?,
    };
    let Some((provider, _status)) = row else {
        return Err(RechargeError::NotFound);
    };
    if provider.as_deref() != Some(expected_provider) {
        return Err(RechargeError::ProviderMismatch);
    }
    Err(RechargeError::StatusInvalid)
}

/// Go 网关上游失败后把订单行标记为 failed（`topUp.Status = failed;
/// topUp.Update()`，按 trade_no 直接覆盖，无状态谓词）。
pub async fn set_topup_status(db: &Database, trade_no: &str, status: &str) -> Result<(), sqlx::Error> {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query("UPDATE top_ups SET status = $1 WHERE trade_no = $2")
                .bind(status)
                .bind(trade_no)
                .execute(pool)
                .await?;
        }
        Database::Postgres(pool) => {
            sqlx::query("UPDATE top_ups SET status = $1 WHERE trade_no = $2")
                .bind(status)
                .bind(trade_no)
                .execute(pool)
                .await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_matches_known_vectors() {
        assert_eq!(md5_hex(""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex("abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            md5_hex("The quick brown fox jumps over the lazy dog"),
            "9e107d9d372bb6826bd81d3542a419d6"
        );
    }

    #[test]
    fn vmq_signs_match_go_layout() {
        // 布局即 md5(payId+param+type+price+reallyPrice+key)，与已知 md5
        // 向量同源：拼接串固定，签名 = md5_hex(拼接串)。
        let sign = vmq_notify_sign("A", "B", "C", "D", "E", "F");
        assert_eq!(sign, md5_hex("ABCDEF"));
        let create = vmq_create_sign("A", "B", "C", "D", "E");
        assert_eq!(create, md5_hex("ABCDE"));
    }

    #[test]
    fn epay_sign_filters_sign_and_empty_and_sorts() {
        let mut params = BTreeMap::new();
        params.insert("sign_type".to_owned(), "MD5".to_owned());
        params.insert("money".to_owned(), "1.00".to_owned());
        params.insert("name".to_owned(), "TUC10".to_owned());
        params.insert("out_trade_no".to_owned(), "NO1".to_owned());
        params.insert("empty".to_owned(), String::new());
        let sign = epay_sign(&params, "KEY");
        let expected = md5_hex("money=1.00&name=TUC10&out_trade_no=NO1KEY");
        assert_eq!(sign, expected);
    }

    #[test]
    fn codepay_sign_skips_empty_values() {
        let mut params = BTreeMap::new();
        params.insert("b".to_owned(), "2".to_owned());
        params.insert("a".to_owned(), "1".to_owned());
        params.insert("c".to_owned(), String::new());
        let sign = codepay_sign(&params, "K");
        assert_eq!(sign, md5_hex("a=1&b=2K"));
    }

    #[test]
    fn round2_cents_parses_like_decimal_round2() {
        assert_eq!(round2_cents("1.005"), Some(101));
        assert_eq!(round2_cents("1.004"), Some(100));
        assert_eq!(round2_cents("1.00501"), Some(101));
        assert_eq!(round2_cents("0.10"), Some(10));
        assert_eq!(round2_cents("7.3"), Some(730));
        assert_eq!(round2_cents("-1.005"), Some(-101));
        assert_eq!(round2_cents("7.30"), Some(730));
        assert_eq!(round2_cents("12"), Some(1200));
        assert_eq!(round2_cents(""), None);
        assert_eq!(round2_cents("abc"), None);
        assert_eq!(round2_cents("1.2.3"), None);
    }

    #[test]
    fn constant_time_eq_behaves_like_plain_eq() {
        assert!(constant_time_eq("success", "success"));
        assert!(!constant_time_eq("success", "fail"));
        assert!(!constant_time_eq("abc", "abcd"));
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn pay_type_codes_match_go_table() {
        assert_eq!(gateway_pay_type_code("vmq", "alipay"), Some("2"));
        assert_eq!(gateway_pay_type_code("vmq", "wxpay"), Some("1"));
        assert_eq!(gateway_pay_type_code("codepay", "alipay"), Some("1"));
        assert_eq!(gateway_pay_type_code("codepay", "wxpay"), Some("3"));
        assert_eq!(gateway_pay_type_code("vmq", "custom1"), None);
        assert_eq!(gateway_pay_type_code("epay", "alipay"), None);
    }
}
