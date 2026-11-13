//! 订阅自助域：对齐 Go `apps/api/internal/billing` 的用户侧订阅读取与偏好。
//!
//! Go 参考（本切片只移植**自助侧**三条路由）：
//! - `apps/api/internal/billing/manage_subscription.go:35-101`
//!   （`GetSubscriptionPlans` / `GetSubscriptionSelf` /
//!   `UpdateSubscriptionPreference`）
//! - `apps/api/internal/billing/store_subscription.go`（`SubscriptionPlan`、
//!   `UserSubscription`、`GetAllActiveUserSubscriptions`、
//!   `GetAllUserSubscriptions`）
//! - `apps/api/internal/common/str.go:91`（`NormalizeBillingPreference`）
//!
//! 管理侧（`/api/subscription/admin/*`）在 `admin_store` / `period`；订阅订单
//! 状态机（`subscription_orders` 表、epay/vmq/codepay 回调核销）在
//! `orders`；HTTP 适配层在 `apps/server/src/subscription_pay_http.rs`。
//!
//! 表名沿用 Go GORM 约定：`subscription_plans`（自建 bootstrap DDL，
//! `bootstrap_subscription_plan.go`）、`user_subscriptions` /
//! `subscription_orders`（AutoMigrate，`register_migrations.go`）。
//!
//! 本模块只承载行投影、存储与偏好归一化；`AfterFind` 的 display 渲染
//!（`total_amount_display` 等）在 server 适配层完成——那里已依赖
//! `newapi_identity::self_user::QuotaDisplaySettings`，本 crate 不引入该边。

mod admin_store;
mod orders;
mod period;
mod store;

pub use admin_store::{AdminError, MSG_RECORD_NOT_FOUND, PlanWrite, SubscriptionResetResult};
pub use orders::{
    SubscriptionCompleteOutcome, SubscriptionCompleteRecord, SubscriptionOrderError,
    SubscriptionOrderRow, complete_subscription_order, count_user_subscriptions_by_plan,
    expire_subscription_order, get_subscription_order_by_trade_no, insert_subscription_order,
};
pub use store::{SubscriptionPlanRow, SubscriptionRepository, UserSubscriptionRow};

pub use period::{calc_next_reset_time, calc_plan_end_time, normalize_reset_period};

/// Go `common.NormalizeBillingPreference`（`common/str.go:91-100`）：
/// 修剪空白后仅接受四个合法值，其余（含空串）回退 `subscription_first`。
pub fn normalize_billing_preference(pref: &str) -> String {
    let trimmed = pref.trim();
    match trimmed {
        "subscription_first" | "wallet_first" | "subscription_only" | "wallet_only" => {
            trimmed.to_string()
        }
        _ => "subscription_first".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_billing_preference;

    #[test]
    fn preference_normalizes_like_go() {
        assert_eq!(
            normalize_billing_preference(" wallet_first "),
            "wallet_first"
        );
        assert_eq!(
            normalize_billing_preference("subscription_only"),
            "subscription_only"
        );
        assert_eq!(normalize_billing_preference(""), "subscription_first");
        assert_eq!(normalize_billing_preference("bogus"), "subscription_first");
    }
}
