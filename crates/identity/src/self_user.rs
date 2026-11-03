//! Self-user 纯数据组装；不执行鉴权、权限推导或设置解析。

use std::collections::BTreeMap;

use serde::Serialize;

use crate::users::UserProfile;

/// 仅包含 Go buildSelfUserData 的原始公开资料列。
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
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
    pub used_quota: i64,
    pub request_count: i64,
    pub aff_code: String,
    pub aff_count: i64,
    pub aff_quota: i64,
    pub aff_history_quota: i64,
    pub inviter_id: i64,
    pub linux_do_id: String,
    pub setting: String,
    pub stripe_customer: String,
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
}

/// 资料平铺到响应顶层；权限始终为独立的 permissions 字段。
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
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
            used_quota: profile.used_quota,
            request_count: profile.request_count,
            aff_code: profile.aff_code,
            aff_count: profile.aff_count,
            aff_quota: profile.aff_quota,
            aff_history_quota: profile.aff_history_quota,
            inviter_id: profile.inviter_id,
            linux_do_id: profile.linux_do_id,
            setting: profile.setting,
            stripe_customer: profile.stripe_customer,
        },
        permissions,
    }
}
