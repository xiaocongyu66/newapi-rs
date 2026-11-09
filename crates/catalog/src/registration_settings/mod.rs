//! 注册赠送额度选项快照。
//!
//! Go 参考：`common/constants.go:136-138` 的默认值（全 0）与
//! `settings/settings.go:571-576` 的选项应用（`strconv.Atoi`，非法值按
//! 0 且吞掉错误）。`User.finishInsert`（`identity/store_users.go:589-602`）
//! 消费这三个值决定“新用户注册赠送 / 使用邀请码赠送 / 邀请用户赠送”
//! 的额度与日志。
//!
//! 与其它快照一致：handler 逐请求 `load`，缺失行保留默认，SQL NULL
//! 是错误。

use newapi_storage::Database;

mod store;

/// 注册收尾（Go `finishInsert`）读取的三个额度选项，默认全 0。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistrationSettings {
    /// Go `common.QuotaForNewUser`（constants.go:136）。
    pub quota_for_new_user: i64,
    /// Go `common.QuotaForInviter`（constants.go:137）。
    pub quota_for_inviter: i64,
    /// Go `common.QuotaForInvitee`（constants.go:138）。
    pub quota_for_invitee: i64,
}

impl Default for RegistrationSettings {
    fn default() -> Self {
        Self {
            quota_for_new_user: 0,
            quota_for_inviter: 0,
            quota_for_invitee: 0,
        }
    }
}

impl RegistrationSettings {
    pub async fn load(db: &Database, previous: &Self) -> Result<Self, sqlx::Error> {
        store::load(db, previous).await
    }
}
