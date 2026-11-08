//! QQ 绑定与绑定验证码的存储层：Go `apps/api/internal/identity/qq_binding.go`。
//!
//! 覆盖的 Go 入口：`GetQQBindingByUserId`（绑定状态读取）、`CreateQQBindCode`
//! （验证码生成/作废/冲突重试）、`DeleteQQBindingWithTx`（解绑连同验证码一起
//! 清理并记录解绑时间）、`GetQQUnbindRecord` 与 `RejectQQBindIfInCooldown`
//! （重绑冷却）。
//!
//! `ConsumeQQBindCode`（QQ 私信/群消息事件兑换绑定码、建立绑定）由 QQ
//! webhook 事件驱动，**不属于**本切片的五条 HTTP 路由，这里不实现；它与
//! `CreateQQBindCode` 写下的 `used` 标志联动构成「单次使用」语义，因此生成
//! 侧严格按同一套规则作废旧码（见 [`QQBindingRepository::create_bind_code`]）。
//!
//! 三张表（`qq_bindings` / `qq_bind_codes` / `qq_unbind_records`）都没有软删除
//! 列（Go 的 `AutoMigrate` 结构体无 `gorm.DeletedAt`，删除处显式 `Unscoped`），
//! 所有语句因此不带 `deleted_at` 过滤。

mod store;

pub use store::{
    BIND_CODE_ALPHABET, BIND_CODE_ATTEMPTS, BIND_CODE_LENGTH, BIND_CODE_TTL_SECONDS, QQBindCode,
    QQBindCodeError, QQBindingRepository, QQBindingView, QQUnbindError,
};

#[cfg(test)]
mod tests;
