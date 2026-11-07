//! 2FA 登录校验与管理端点原语。
//!
//! 登录路径提供读取、TOTP/备用码校验与失败锁定；管理路径提供
//! setup/enable/disable/backup_codes 的事务与密钥/备用码生成，以及
//! 管理员统计（Go `GetTwoFAStats`）与角色层级判定
//! （Go `canManageTargetRole`）。

pub mod repository;
pub mod totp;

#[cfg(test)]
mod tests;

pub use repository::{
    BACKUP_CODE_COUNT, BACKUP_CODE_LENGTH, LOCKOUT_SECONDS, MAX_FAIL_ATTEMPTS, ROLE_ROOT_USER,
    TWO_FA_ISSUER, TwoFa, TwoFaAdminStats, TwoFaError, TwoFaRepository, can_manage_target_role,
    generate_backup_codes, generate_qr_code_data, generate_totp_secret, totp_code_at,
};
