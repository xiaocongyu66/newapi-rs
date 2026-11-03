//! 权限策略只读求值：内置资源目录、角色基线规则与用户级覆盖。
//! 规则来自 `casbin_rule`，不包含策略写入、角色启用开关或 HTTP 接线。
//! 判定顺序与 Go `policy.Can` 一致：空角色拒绝、超级用户放行、未知权限拒绝、
//! 用户覆盖优先、再看角色基线；显式 deny 覆盖同主体 allow。
//! 仅支持可直接解释的 p 行；不实现通用 CSV/Casbin，其他编码返回固定错误。

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

    /// 加载完整快照后求值，不能只过滤匹配行而遗漏使 Go 加载失败的规则。
    pub async fn subject_effect(
        &self,
        subject: &str,
        permission: Permission,
    ) -> Result<Option<RuleEffect>, sqlx::Error> {
        Ok(self.load_snapshot().await?.subject_effect(subject, permission))
    }

    async fn load_snapshot(&self) -> Result<PolicySnapshot, sqlx::Error> {
        const QUERY: &str = "SELECT ptype,v0,v1,v2,v3,v4,v5 FROM casbin_rule ORDER BY id ASC";
        let rows: Vec<StoredRule> = match &self.db {
            Database::Sqlite(pool) => sqlx::query_as(QUERY).fetch_all(pool).await?,
            Database::Postgres(pool) => sqlx::query_as(QUERY).fetch_all(pool).await?,
        };
        let mut rules = Vec::new();
        for (ptype, v0, v1, v2, v3, v4, v5) in rows {
            let ptype = ptype.unwrap_or_default();
            // Go LoadPolicyLine ignores a line beginning with '#', before CSV parsing.
            if ptype.starts_with('#') {
                continue;
            }
            // The current Go model declares only p, not g/p2/etc. Unknown types
            // fail model loading; they must never become a partial usable snapshot.
            if ptype != "p"
                || [v4, v5]
                    .iter()
                    .any(|v| !v.as_deref().unwrap_or("").is_empty())
            {
                return Err(unsupported_rule());
            }
            let fields = [v0, v1, v2, v3].map(Option::unwrap_or_default);
            if fields[..3].iter().any(String::is_empty)
                || fields.iter().any(|value| {
                    value.chars().any(|c| matches!(c, ',' | '"' | '\r' | '\n'))
                })
            {
                return Err(unsupported_rule());
            }
            // ruleToLine drops empty fields, but supplies allow for an empty
            // trailing effect. NULL scanned by Go into string is the same case.
            // For the supported unquoted fields CSV TrimLeadingSpace trims only
            // the start, not the end; whitespace-only effects become empty/allow.
            let [subject, resource, action, effect] = fields.map(|v| v.trim_start().to_owned());
            rules.push(PolicyRule {
                subject,
                resource,
                action,
                effect,
            });
        }
        Ok(PolicySnapshot { rules })
    }
}

type StoredRule = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

fn unsupported_rule() -> sqlx::Error {
    // Never include persisted subjects, resources, effects or parser input.
    sqlx::Error::Protocol("unsupported authorization policy encoding".to_owned())
}

struct PolicyRule {
    subject: String,
    resource: String,
    action: String,
    effect: String,
}

struct PolicySnapshot {
    rules: Vec<PolicyRule>,
}

impl PolicySnapshot {
    fn subject_effect(&self, subject: &str, permission: Permission) -> Option<RuleEffect> {
        effect_from_rows(
            self.rules
                .iter()
                .filter(|rule| {
                    rule.subject == subject
                        && rule.resource == permission.resource
                        && rule.action == permission.action
                })
                .map(|rule| rule.effect.as_str()),
        )
    }

    fn can(&self, user_id: i64, role: Role, permission: Permission) -> bool {
        if role.is_superuser() {
            return true;
        }
        if !is_known_permission(permission) {
            return false;
        }
        if let Some(effect) = self.subject_effect(&user_subject(user_id), permission) {
            return effect == RuleEffect::Allow;
        }
        self.subject_effect(&role_subject(role), permission) == Some(RuleEffect::Allow)
    }
}

/// 任一显式 deny 即拒绝；否则存在 allow 时放行；没有规则返回 None。
fn effect_from_rows<'a>(values: impl Iterator<Item = &'a str>) -> Option<RuleEffect> {
    let mut allow = false;
    for value in values {
        match value {
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
    Ok(repository.load_snapshot().await?.can(user_id, role, permission))
}

/// 在支持的规则编码范围内保持 Go 权限输出；不支持的编码返回错误。
/// 仅角色与策略决定内容，不读取用户设置或额度；侧栏复用同一策略快照。
pub async fn self_user_permissions(
    repository: &CasbinRuleRepository,
    user_id: i64,
    system_role: i32,
) -> Result<crate::self_user::Permissions, sqlx::Error> {
    use crate::self_user::{Permissions, SidebarModulePermission};

    let admin_permissions = capabilities(repository, user_id, system_role).await?;
    let mut modules = std::collections::BTreeMap::new();
    let sidebar_settings = match system_role {
        ROLE_ROOT_VALUE => false,
        ROLE_ADMIN_VALUE => {
            let mut setting = std::collections::BTreeMap::new();
            setting.insert(
                "setting".to_owned(),
                admin_permissions["system"]["settings"],
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
        admin_permissions,
    })
}

/// 完整资源/动作矩阵；未知权限不会出现。
pub async fn capabilities(
    repository: &CasbinRuleRepository,
    user_id: i64,
    system_role: i32,
) -> Result<BTreeMap<String, BTreeMap<String, bool>>, sqlx::Error> {
    let role = role_from_system_role(system_role);
    let snapshot = if role.is_some_and(|role| !role.is_superuser()) {
        Some(repository.load_snapshot().await?)
    } else {
        None
    };
    let mut result = BTreeMap::new();
    for resource in CATALOG {
        let mut actions = BTreeMap::new();
        for action in resource.actions {
            let permission = Permission {
                resource: resource.resource,
                action: action.action,
            };
            let allowed = match role {
                Some(Role::Root) => true,
                Some(role) => snapshot
                    .as_ref()
                    .is_some_and(|snapshot| snapshot.can(user_id, role, permission)),
                None => false,
            };
            actions.insert(action.action.to_owned(), allowed);
        }
        result.insert(resource.resource.to_owned(), actions);
    }
    Ok(result)
}
