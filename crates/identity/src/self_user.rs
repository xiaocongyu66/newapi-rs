//! Self-user 纯数据组装；不执行鉴权、权限推导或设置解析。

use std::collections::BTreeMap;

use serde::Serialize;

use crate::users::UserProfile;

/// 仅包含 Go buildSelfUserData 的原始公开资料列与派生展示字段。
/// 展示字段使用 f64，因此不实现 Eq。
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SelfUserProfile {
    pub id: i64,
    pub username: String,
    pub display_name: String,
    pub role: i64,
    pub status: i64,
    pub email: String,
    pub github_id: String,
    pub discord_id: String,
    pub oidc_id: String,
    pub wechat_id: String,
    pub telegram_id: String,
    pub group: String,
    pub quota: i64,
    pub quota_display: f64,
    pub used_quota: i64,
    pub used_quota_display: f64,
    pub request_count: i64,
    pub aff_code: String,
    pub aff_count: i64,
    pub aff_quota: i64,
    pub aff_quota_display: f64,
    pub aff_history_quota: i64,
    pub aff_history_quota_display: f64,
    pub inviter_id: i64,
    pub linux_do_id: String,
    pub setting: String,
    pub stripe_customer: String,
    /// Go 从 user.setting JSON 提取的原始 sidebar_modules 字符串，由调用方提供。
    pub sidebar_modules: String,
}

/// 额度展示类型；汇率等运行时配置必须由调用方提供，不在此设默认值。
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum QuotaDisplayKind {
    Usd,
    Cny { usd_exchange_rate: f64 },
    Custom { rate: f64 },
    Tokens,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct QuotaDisplaySettings {
    pub quota_per_unit: f64,
    pub kind: QuotaDisplayKind,
}

impl QuotaDisplaySettings {
    /// 与 Go billing.QuotaToDisplayAmount 逐分支一致；不处理非有限结果。
    pub fn to_display(self, quota: i64) -> f64 {
        let value = quota as f64;
        match self.kind {
            QuotaDisplayKind::Usd => value / self.quota_per_unit,
            QuotaDisplayKind::Cny { usd_exchange_rate } => {
                value / self.quota_per_unit * usd_exchange_rate
            }
            QuotaDisplayKind::Custom { rate } => {
                let rate = if rate <= 0.0 { 1.0 } else { rate };
                value / self.quota_per_unit * rate
            }
            QuotaDisplayKind::Tokens => value,
        }
    }
}

/// 对齐 Go sidebar_modules 的布尔开关或模块内动作开关；不推导任何授权。
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum SidebarModulePermission {
    Enabled(bool),
    Actions(BTreeMap<String, bool>),
}

/// 必须由调用方显式提供的策略结果，不提供 Default 或自动生成权限。
/// 资源、动作和模块名称由后续策略切片定义；此处仅保留 Go 的数据形状。
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Permissions {
    pub sidebar_settings: bool,
    pub sidebar_modules: BTreeMap<String, SidebarModulePermission>,
    pub admin_permissions: BTreeMap<String, BTreeMap<String, bool>>,
}

pub struct SelfUserInput {
    pub profile: UserProfile,
    pub permissions: Permissions,
    pub display: QuotaDisplaySettings,
    pub sidebar_modules: String,
}

/// 资料平铺到响应顶层；权限始终为独立的 permissions 字段。
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SelfUser {
    #[serde(flatten)]
    pub profile: SelfUserProfile,
    pub permissions: Permissions,
}

/// 只移动原始资料与调用方的权限结果，不做归一化或角色判断。
pub fn assemble(input: SelfUserInput) -> SelfUser {
    let SelfUserInput {
        profile,
        permissions,
        display,
        sidebar_modules,
    } = input;
    SelfUser {
        profile: SelfUserProfile {
            id: profile.id,
            username: profile.username,
            display_name: profile.display_name,
            role: profile.role,
            status: profile.status,
            email: profile.email,
            github_id: profile.github_id,
            discord_id: profile.discord_id,
            oidc_id: profile.oidc_id,
            wechat_id: profile.wechat_id,
            telegram_id: profile.telegram_id,
            group: profile.group,
            quota: profile.quota,
            quota_display: display.to_display(profile.quota),
            used_quota: profile.used_quota,
            used_quota_display: display.to_display(profile.used_quota),
            request_count: profile.request_count,
            aff_code: profile.aff_code,
            aff_count: profile.aff_count,
            aff_quota: profile.aff_quota,
            aff_quota_display: display.to_display(profile.aff_quota),
            aff_history_quota: profile.aff_history_quota,
            aff_history_quota_display: display.to_display(profile.aff_history_quota),
            inviter_id: profile.inviter_id,
            linux_do_id: profile.linux_do_id,
            setting: profile.setting,
            stripe_customer: profile.stripe_customer,
            sidebar_modules,
        },
        permissions,
    }
}
