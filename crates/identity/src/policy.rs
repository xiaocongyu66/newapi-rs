//! 权限策略只读求值：内置资源目录、角色基线规则与用户级覆盖。
//! 规则来自 `casbin_rule`，不包含策略写入、角色启用开关或 HTTP 接线。
//! 判定顺序与 Go `policy.Can` 一致：空角色拒绝、超级用户放行、未知权限拒绝、
//! 用户覆盖优先、再看角色基线；显式 deny 覆盖同主体 allow。

use std::collections::BTreeMap;

use newapi_storage::Database;

pub const ROOT_ROLE: &str = "root";
pub const ADMIN_ROLE: &str = "admin";
const ROLE_ROOT_VALUE: i32 = 100;
const ROLE_ADMIN_VALUE: i32 = 10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Permission {
    pub resource: &'static str,
    pub action: &'static str,
}

pub struct ActionDefinition {
    pub action: &'static str,
    pub default_roles: &'static [&'static str],
}

pub struct ResourceDefinition {
    pub resource: &'static str,
    pub actions: &'static [ActionDefinition],
}

pub const SYSTEM_SETTINGS: Permission = Permission {
    resource: "system",
    action: "settings",
};

/// 与 Go `registry` 静态目录一致；未登记的资源或动作一律视为未知权限。
pub const CATALOG: &[ResourceDefinition] = &[
    ResourceDefinition {
        resource: "channel",
        actions: &[
            ActionDefinition {
                action: "read",
                default_roles: &[ADMIN_ROLE],
            },
            ActionDefinition {
                action: "operate",
                default_roles: &[ADMIN_ROLE],
            },
            ActionDefinition {
                action: "write",
                default_roles: &[ADMIN_ROLE],
            },
            ActionDefinition {
                action: "sensitive_write",
                default_roles: &[],
            },
            ActionDefinition {
                action: "secret_view",
                default_roles: &[],
            },
        ],
    },
    ResourceDefinition {
        resource: "system",
        actions: &[ActionDefinition {
            action: "settings",
            default_roles: &[],
        }],
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Root,
    Admin,
}

impl Role {
    pub fn key(self) -> &'static str {
        match self {
            Self::Root => ROOT_ROLE,
            Self::Admin => ADMIN_ROLE,
        }
    }

    pub fn is_superuser(self) -> bool {
        matches!(self, Self::Root)
    }
}

/// 只接受已映射的内置角色值；其他系统角色不获得任何基线权限。
pub fn role_from_system_role(system_role: i32) -> Option<Role> {
    if system_role >= ROLE_ROOT_VALUE {
        Some(Role::Root)
    } else if system_role >= ROLE_ADMIN_VALUE {
        Some(Role::Admin)
    } else {
        None
    }
}

pub fn is_known_permission(permission: Permission) -> bool {
    CATALOG.iter().any(|resource| {
        resource.resource == permission.resource
            && resource
                .actions
                .iter()
                .any(|action| action.action == permission.action)
    })
}

pub fn user_subject(user_id: i64) -> String {
    format!("user:{user_id}")
}

pub fn role_subject(role: Role) -> String {
    format!("role:{}", role.key())
}

/// 单主体在单权限上的显式规则结果；`None` 表示没有规则。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleEffect {
    Allow,
    Deny,
}

#[derive(Clone)]
pub struct CasbinRuleRepository {
    db: Database,
}

impl CasbinRuleRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// 固定查询并绑定全部参数；空或 NULL 效果列按 Go 旧格式视为 allow。
    pub async fn subject_effect(
        &self,
        subject: &str,
        permission: Permission,
    ) -> Result<Option<RuleEffect>, sqlx::Error> {
        let rows: Vec<(Option<String>,)> = match &self.db {
            Database::Sqlite(pool) => {
                sqlx::query_as(
                    "SELECT v3 FROM casbin_rule WHERE ptype='p' AND v0=$1 AND v1=$2 AND v2=$3",
                )
                .bind(subject)
                .bind(permission.resource)
                .bind(permission.action)
                .fetch_all(pool)
                .await?
            }
            Database::Postgres(pool) => {
                sqlx::query_as(
                    "SELECT v3 FROM casbin_rule WHERE ptype='p' AND v0=$1 AND v1=$2 AND v2=$3",
                )
                .bind(subject)
                .bind(permission.resource)
                .bind(permission.action)
                .fetch_all(pool)
                .await?
            }
        };
        Ok(effect_from_rows(
            rows.iter().map(|(value,)| value.as_deref()),
        ))
    }
}

/// 任一显式 deny 即拒绝；否则存在 allow 时放行；没有规则返回 None。
fn effect_from_rows<'a>(values: impl Iterator<Item = Option<&'a str>>) -> Option<RuleEffect> {
    let mut allow = false;
    for value in values {
        match value.unwrap_or("") {
            "deny" => return Some(RuleEffect::Deny),
            "allow" | "" => allow = true,
            // 未知效果值与 Go 一致：忽略，不当作放行。
            _ => {}
        }
    }
    allow.then_some(RuleEffect::Allow)
}

pub async fn can(
    repository: &CasbinRuleRepository,
    user_id: i64,
    system_role: i32,
    permission: Permission,
) -> Result<bool, sqlx::Error> {
    let Some(role) = role_from_system_role(system_role) else {
        return Ok(false);
    };
    if role.is_superuser() {
        return Ok(true);
    }
    if !is_known_permission(permission) {
        return Ok(false);
    }
    if let Some(effect) = repository
        .subject_effect(&user_subject(user_id), permission)
        .await?
    {
        return Ok(effect == RuleEffect::Allow);
    }
    Ok(repository
        .subject_effect(&role_subject(role), permission)
        .await?
        == Some(RuleEffect::Allow))
}

/// Go `calculateUserPermissions` + `Capabilities` 的等价输出。
/// 仅角色与策略决定内容，不读取用户设置或额度。
pub async fn self_user_permissions(
    repository: &CasbinRuleRepository,
    user_id: i64,
    system_role: i32,
) -> Result<crate::self_user::Permissions, sqlx::Error> {
    use crate::self_user::{Permissions, SidebarModulePermission};

    let mut modules = std::collections::BTreeMap::new();
    let sidebar_settings = match system_role {
        ROLE_ROOT_VALUE => false,
        ROLE_ADMIN_VALUE => {
            let mut setting = std::collections::BTreeMap::new();
            setting.insert(
                "setting".to_owned(),
                can(repository, user_id, system_role, SYSTEM_SETTINGS).await?,
            );
            modules.insert(
                "admin".to_owned(),
                SidebarModulePermission::Actions(setting),
            );
            true
        }
        _ => {
            modules.insert("admin".to_owned(), SidebarModulePermission::Enabled(false));
            true
        }
    };
    Ok(Permissions {
        sidebar_settings,
        sidebar_modules: modules,
        admin_permissions: capabilities(repository, user_id, system_role).await?,
    })
}

/// 完整资源/动作矩阵；未知权限不会出现。
pub async fn capabilities(
    repository: &CasbinRuleRepository,
    user_id: i64,
    system_role: i32,
) -> Result<BTreeMap<String, BTreeMap<String, bool>>, sqlx::Error> {
    let mut result = BTreeMap::new();
    for resource in CATALOG {
        let mut actions = BTreeMap::new();
        for action in resource.actions {
            let allowed = can(
                repository,
                user_id,
                system_role,
                Permission {
                    resource: resource.resource,
                    action: action.action,
                },
            )
            .await?;
            actions.insert(action.action.to_owned(), allowed);
        }
        result.insert(resource.resource.to_owned(), actions);
    }
    Ok(result)
}
