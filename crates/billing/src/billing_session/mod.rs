//! 计费核心（billing session 与扣费主路径）：Go
//! `internal/billing/{open_billing_session,classify_usage_path,
//! consume_text_quota,consume_quota_realtime,consume_quota_setting,
//! charge_violation_fee}.go` 与 `settlecore` / `resolve_funding_source` /
//! `settle_billing_delta` 的移植。
//!
//! 模块划分与 Go 文件对应：
//! - [`quota_math`]   ← common/quota_math.go（额度饱和换算）
//! - [`usage`]        ← relaykit/dto 的计费读取面（端口形状）
//! - [`classify_usage_path`] ← classify_usage_path.go
//! - [`pricing`]      ← types.PriceData + ratio_setting 读取端口
//! - [`store`]        ← store_quota_reserve.go / store_subscription.go 消费事务
//! - [`funding`]      ← resolve_funding_source.go（Wallet/Subscription funding）
//! - [`session`]      ← open_billing_session.go + settle_billing_delta.go + settlecore
//! - [`text_quota`]   ← consume_text_quota.go
//! - [`realtime`]     ← consume_quota_realtime.go
//! - [`violation_fee`]← charge_violation_fee.go
//! - [`quota_setting`]← consume_quota_setting.go
//!
//! 测试替身：[`pricing::StaticRatioSettings`]（倍率/工具价 HashMap），生产
//! 实现随 pricing 切片对齐（接口约定见交付报告）。

pub mod classify_usage_path;
pub mod funding;
pub mod pricing;
pub mod quota_math;
pub mod quota_setting;
pub mod realtime;
pub mod session;
pub mod store;
pub mod text_quota;
pub mod usage;
pub mod violation_fee;

#[cfg(test)]
mod tests;
