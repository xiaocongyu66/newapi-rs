//! 2FA 登录校验原语。
//!
//! 本切片只覆盖登录路径需要的读取、TOTP/备用码校验与失败锁定；
//! setup/enable/disable/backup_codes 管理端点留给后续切片。

pub mod repository;
pub mod totp;

#[cfg(test)]
mod tests;

pub use repository::{LOCKOUT_SECONDS, MAX_FAIL_ATTEMPTS, TwoFa, TwoFaError, TwoFaRepository};
