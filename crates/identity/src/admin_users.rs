//! 管理端用户仓储（Go `identity` 域管理通路的移植）：列表/搜索取自
//! `store_users.go:SearchUsers` 与 `store_users_lifecycle.go:listAllUsers`，
//! 创建/编辑取自 `store_users.go:InsertWithTx/EditWithTx`，硬删除取自
//! `store_users_lifecycle.go:HardDeleteUserById`（`store_users.go:HardDelete`），
//! 用户级权限覆盖写库取自 `policy/override.go:SetUserPermissionsInTx` 与
//! `ClearUserPermissionsInTx`。封禁/启用/升降级走 `UpdateWithTx` 的
//! auth-version 递增语义（角色或状态实际变化时 +1）。
//!
//! 移植缺口（与 `password_reset`、`registration` 的登记一致，不伪造）：
//! Go 在这些写路径上调用的 Redis 用户缓存同步（`updateUserCache`/
//! `PublishUserAuthCache`）在本仓储不做——Rust 尚无用户缓存；令牌缓存失效
//! （`InvalidateUserTokensCache`）由 HTTP 层在提交后按 `AppState::token_cache`
//! 处理。`IncrementUserAuthVersionWithTx` 的 CAS 重试循环收敛为单条条件
//! 自增（与 `users.rs` 的 `BUMP_AUTH_VERSION` 同形）；Go 的 `policy.ReloadPolicy`
//! 在 Rust 侧无内存 enforcer，等价为无操作（判定每次直接读库）。

use std::collections::BTreeMap;

use newapi_storage::Database;
use sqlx::Row;

use crate::policy::{CATALOG, admin_baseline_allows, catalog_resource, user_subject};

/// Go `common.RoleAdminUser`（`common/constants.go:193`）。
pub const ROLE_ADMIN_USER: i64 = 10;
/// Go `common.RoleRootUser`（`common/constants.go:194`）。
pub const ROLE_ROOT_USER: i64 = 100;
/// Go `common.RoleCommonUser`（`common/constants.go:192`）。
pub const ROLE_COMMON_USER: i64 = 1;

/// 管理端用户行的宽投影：Go `User` 结构减去 `password`/`access_token`
/// （`Omit("password", "access_token")`），再加 `auth_version` 供编辑路径
/// 判定会话撤销。不含 `deleted_at`：列表/搜索虽为 Unscoped，但既有移植
/// 约定不回显无 json tag 的 `DeletedAt`（与 token 列表一致）。
#[derive(Clone, Debug, PartialEq)]
pub struct AdminUserRow {
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
    pub remark: String,
    pub stripe_customer: String,
    pub created_at: i64,
    pub last_login_at: i64,
    pub auth_version: i64,
}

macro_rules! row {
    ($r:expr) => {{
        let row = $r;
        Ok(AdminUserRow {
            id: row.try_get::<Option<i64>, _>("id")?.unwrap_or_default(),
            username: row
                .try_get::<Option<String>, _>("username")?
                .unwrap_or_default(),
            display_name: row
                .try_get::<Option<String>, _>("display_name")?
                .unwrap_or_default(),
            role: row.try_get::<Option<i64>, _>("role")?.unwrap_or_default(),
            status: row.try_get::<Option<i64>, _>("status")?.unwrap_or_default(),
            email: row
                .try_get::<Option<String>, _>("email")?
                .unwrap_or_default(),
            github_id: row
                .try_get::<Option<String>, _>("github_id")?
                .unwrap_or_default(),
            discord_id: row
                .try_get::<Option<String>, _>("discord_id")?
                .unwrap_or_default(),
            oidc_id: row
                .try_get::<Option<String>, _>("oidc_id")?
                .unwrap_or_default(),
            wechat_id: row
                .try_get::<Option<String>, _>("wechat_id")?
                .unwrap_or_default(),
            telegram_id: row
                .try_get::<Option<String>, _>("telegram_id")?
                .unwrap_or_default(),
            group: row
                .try_get::<Option<String>, _>("group")?
                .unwrap_or_default(),
            quota: row.try_get::<Option<i64>, _>("quota")?.unwrap_or_default(),
            used_quota: row
                .try_get::<Option<i64>, _>("used_quota")?
                .unwrap_or_default(),
            request_count: row
                .try_get::<Option<i64>, _>("request_count")?
                .unwrap_or_default(),
            aff_code: row
                .try_get::<Option<String>, _>("aff_code")?
                .unwrap_or_default(),
            aff_count: row
                .try_get::<Option<i64>, _>("aff_count")?
                .unwrap_or_default(),
            aff_quota: row
                .try_get::<Option<i64>, _>("aff_quota")?
                .unwrap_or_default(),
            aff_history_quota: row
                .try_get::<Option<i64>, _>("aff_history_quota")?
                .unwrap_or_default(),
            inviter_id: row
                .try_get::<Option<i64>, _>("inviter_id")?
                .unwrap_or_default(),
            linux_do_id: row
                .try_get::<Option<String>, _>("linux_do_id")?
                .unwrap_or_default(),
            setting: row
                .try_get::<Option<String>, _>("setting")?
                .unwrap_or_default(),
            remark: row
                .try_get::<Option<String>, _>("remark")?
                .unwrap_or_default(),
            stripe_customer: row
                .try_get::<Option<String>, _>("stripe_customer")?
                .unwrap_or_default(),
            created_at: row
                .try_get::<Option<i64>, _>("created_at")?
                .unwrap_or_default(),
            last_login_at: row
                .try_get::<Option<i64>, _>("last_login_at")?
                .unwrap_or_default(),
            auth_version: row
                .try_get::<Option<i64>, _>("auth_version")?
                .unwrap_or_default(),
        })
    }};
}

/// Go `userSortColumns`（`store_users.go:23-30`）白名单对应的 SQL 列名片段；
/// `group` 是保留字，按既有仓储风格加引号。
const SORT_COLUMNS: [&str; 6] = [
    "id",
    "username",
    "quota",
    "\"group\"",
    "created_at",
    "last_login_at",
];

/// Go `UserSortOptions`：白名单外回落 `id desc`，order 非 `asc` 一律 `desc`；
/// 主列非 `id` 时追加 `id DESC` 次级排序（`store_users.go:37-69`）。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdminUserSort {
    pub column: &'static str,
    pub ascending: bool,
}

/// Go `NewUserSortOptions`（`store_users.go:37-51`）。
pub fn resolve_sort(sort_by: &str, sort_order: &str) -> AdminUserSort {
    let normalized = sort_by.trim().to_ascii_lowercase();
    let known = SORT_COLUMNS
        .iter()
        .any(|column| column.trim_matches('"') == normalized);
    if !known {
        return AdminUserSort {
            column: "id",
            ascending: false,
        };
    }
    let column = SORT_COLUMNS
        .iter()
        .find(|column| column.trim_matches('"') == normalized)
        .copied()
        .unwrap_or("id");
    AdminUserSort {
        column,
        ascending: sort_order.trim().to_ascii_lowercase() == "asc",
    }
}

impl AdminUserSort {
    /// 主列 + 次级 `id DESC` 的 ORDER BY 片段；列名来自固定白名单，
    /// 不是用户输入。
    fn clause(self) -> String {
        let direction = if self.ascending { "ASC" } else { "DESC" };
        if self.column == "id" {
            format!(" ORDER BY id {direction}")
        } else {
            format!(" ORDER BY {} {}, id DESC", self.column, direction)
        }
    }
}

/// 宽投影列清单；PG 的旧 INTEGER 列显式 CAST 为 BIGINT。
const USER_SELECT: &str = r#"
SELECT CAST(id AS BIGINT) AS id, username, display_name,
    CAST(role AS BIGINT) AS role, CAST(status AS BIGINT) AS status,
    email, github_id, discord_id, oidc_id, wechat_id, telegram_id,
    "group", CAST(quota AS BIGINT) AS quota,
    CAST(used_quota AS BIGINT) AS used_quota,
    CAST(request_count AS BIGINT) AS request_count, aff_code,
    CAST(aff_count AS BIGINT) AS aff_count,
    CAST(aff_quota AS BIGINT) AS aff_quota,
    CAST(aff_history AS BIGINT) AS aff_history_quota,
    CAST(inviter_id AS BIGINT) AS inviter_id,
    linux_do_id, setting, remark, stripe_customer,
    CAST(created_at AS BIGINT) AS created_at,
    CAST(last_login_at AS BIGINT) AS last_login_at,
    CAST(auth_version AS BIGINT) AS auth_version
FROM users"#;

/// Go `listAllUsers`（`store_users_lifecycle.go:23-56`）：`Unscoped` 计数
/// 加分页读取，两步无过滤。
const LIST_COUNT: &str = "SELECT COUNT(*) FROM users";
const LIST_PAGE_TAIL: &str = " LIMIT $1 OFFSET $2";

/// Go `SearchUsers`（`store_users.go:341-408`）：Unscoped 全量；keyword 始终
/// 生成三条 LIKE（空串即 `%%`，与 Go 逐字一致），keyword 能解析为整数时
/// `id = ?` 以 `NULL OR` 形式并入；group 空串不过滤；status 为 -1 时只看
/// 软删除行，其余非空值过滤未删除且 status 相等；role 为空不过滤。
const SEARCH_BASE: &str = r#"
WHERE (id = $2 OR username LIKE $1 OR email LIKE $1 OR display_name LIKE $1)
    AND ($3 = '' OR "group" = $3)
    AND ($4 IS NULL OR ($4 = -1 AND deleted_at IS NOT NULL)
        OR (deleted_at IS NULL AND status = $4))
    AND ($5 IS NULL OR role = $5)"#;

/// Go `GetUserById(id, false)` 的宽投影版：GORM 默认作用域排除软删除行。
const BY_ID: &str = " WHERE id = $1 AND deleted_at IS NULL LIMIT 1";

/// Go `ManageUser` 的目标读取（`manage_users.go:1061`）：
/// `dbx.DB.Unscoped().Where(&user).First(&user)`。GORM 的 struct 条件只取
/// 非零字段，因此 `id == 0` 退化为无条件 `First`——按主键升序取第一行
/// （软删除行也在内）；这是 Go 的逐字行为，本仓储如实保留。
const MANAGE_TARGET_FIRST: &str = " ORDER BY id ASC LIMIT 1";

/// Go `IncrementUserAuthVersionWithTx` 的收敛形式：NULL/0 旧值从 2 起步。
const BUMP_AUTH_VERSION: &str = r"
UPDATE users SET auth_version =
    CASE WHEN COALESCE(auth_version, 0) < 1 THEN 2 ELSE COALESCE(auth_version, 0) + 1 END
WHERE id = $1";
const SELECT_AUTH_VERSION: &str =
    "SELECT CAST(auth_version AS BIGINT) AS auth_version FROM users WHERE id = $1";

/// Go `InsertWithTx`（`store_users.go:612-628`）的管理端变体：role 由请求
/// 决定，邮箱恒为空串（Go 的 `cleanUser` 只带用户名/密码/昵称/角色），
/// status=1、group='default'、quota 取 `QuotaForNewUser`、随机邀请码、
/// 默认 setting、`auth_version = 1`。`RETURNING` 对 SQLite 3.35+ 与 PG 均可。
const INSERT_ADMIN_USER: &str = r#"
INSERT INTO users (
    username,password,display_name,role,status,email,github_id,discord_id,
    oidc_id,wechat_id,telegram_id,quota,used_quota,request_count,"group",
    aff_code,aff_count,aff_quota,aff_history,inviter_id,deleted_at,
    linux_do_id,setting,remark,stripe_customer,created_at,last_login_at,auth_version
) VALUES (
    $1,$2,$3,$4,1,'','','','','','',$7,0,0,'default',
    $5,0,0,0,0,NULL,'',$8,'','',$6,0,1
)
RETURNING CAST(id AS BIGINT)"#;

/// Go `EditWithTx`（`store_users.go:743-778`）：map 形式的 `Updates` 会把
/// 四列（必要时加 password）无条件写库，零值也写。当前口令与分组先读出
/// 用于 `authChanged` 判定。
const SELECT_EDIT_STATE: &str = r#"
SELECT COALESCE("group", '') AS grp, COALESCE(password, '') AS pwd
FROM users WHERE id = $1 AND deleted_at IS NULL"#;
const EDIT_UPDATE: &str = r#"
UPDATE users SET username = $1, display_name = $2, "group" = $3, remark = $4
WHERE id = $5 AND deleted_at IS NULL"#;
const EDIT_UPDATE_PASSWORD: &str = r#"
UPDATE users SET password = $1, username = $2, display_name = $3,
    "group" = $4, remark = $5
WHERE id = $6 AND deleted_at IS NULL"#;

/// Go enable/disable/promote 的 `User.Update(false)` 通路（`store_users.go:682-721`
/// 的 `UpdateWithTx`）：仅写变化列，`authChanged` 为真时先递增 auth_version。
const UPDATE_STATUS: &str = "UPDATE users SET status = $1 WHERE id = $2 AND deleted_at IS NULL";
const UPDATE_ROLE: &str = "UPDATE users SET role = $1 WHERE id = $2 AND deleted_at IS NULL";

/// Go `IncreaseUserQuota`/`DecreaseUserQuota`（`db=true` 直连库通路，
/// `store_users.go:1126-1174`）与 `add_quota` 的 override 模式
/// （`manage_users.go:1173-1186`）：`Model(&User{})` 自带软删除作用域。
const INCREASE_QUOTA: &str =
    "UPDATE users SET quota = quota + $1 WHERE id = $2 AND deleted_at IS NULL";
const DECREASE_QUOTA: &str =
    "UPDATE users SET quota = quota - $1 WHERE id = $2 AND deleted_at IS NULL";
const OVERRIDE_QUOTA: &str = "UPDATE users SET quota = $1 WHERE id = $2 AND deleted_at IS NULL";

/// Go `HardDelete`（`store_users.go:855-890`）与
/// `deleteUserAuthenticationData`（`store_users.go:892-912`）：同一事务内
/// 递增版本、收集令牌 key、逐表硬删认证数据并硬删用户行。
const HARD_DELETE_TOKEN_KEYS: &str = r#"SELECT "key" FROM tokens WHERE user_id = $1"#;
const HARD_DELETE_TABLES: [&str; 9] = [
    "DELETE FROM external_identity_claims WHERE user_id = $1",
    "DELETE FROM two_fa_backup_codes WHERE user_id = $1",
    "DELETE FROM two_fas WHERE user_id = $1",
    "DELETE FROM user_sessions WHERE user_id = $1",
    "DELETE FROM auth_flows WHERE user_id = $1",
    "DELETE FROM passkey_credentials WHERE user_id = $1",
    "DELETE FROM tokens WHERE user_id = $1",
    "DELETE FROM qq_bindings WHERE user_id = $1",
    "DELETE FROM user_oauth_bindings WHERE user_id = $1",
];
const HARD_DELETE_USER: &str = "DELETE FROM users WHERE id = $1";

/// Go `IsQQBoundByUserId`（`qq_binding.go:121-132`）的 open_id 读取；
/// 查询失败与空值都归为未绑定。
const QQ_OPEN_ID: &str = "SELECT open_id FROM qq_bindings WHERE user_id = $1";

/// Go `ClearUserPermissionsInTx`（`policy/override.go:110-120`）按注册表
/// 资源逐个清除该用户的 p 行。
const DELETE_USER_RULE_FOR_RESOURCE: &str =
    "DELETE FROM casbin_rule WHERE ptype = 'p' AND v0 = $1 AND v1 = $2";
/// Go `SetUserPermissionsInTx` 的插入（`policy/override.go:60-70`）：
/// `OnConflict DoNothing` 与唯一索引 (ptype..v5) 对齐。
const INSERT_USER_RULE: &str = r#"
INSERT INTO casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('p', $1, $2, $3, $4, '', '')
ON CONFLICT DO NOTHING"#;

/// Go `PermissionsMap`（`policy/resolver.go`）的请求形状。
pub type PermissionOverrides = BTreeMap<String, BTreeMap<String, bool>>;

/// `updateAdminPermissionsForUserInTx`（`manage_users.go:1021-1035`）的
/// 固定失败分类；Go 在该分支返回
/// `errors.New("only root can update admin permissions")` 并由
/// `CtxApiError` 原文回显。
#[derive(Debug)]
pub enum AdminPermissionError {
    /// 请求携带 `admin_permissions` 但操作者不是 root。
    OnlyRootCanUpdate,
    /// 存储失败；不携带 SQL 文本。
    Storage(sqlx::Error),
}

impl From<sqlx::Error> for AdminPermissionError {
    fn from(error: sqlx::Error) -> Self {
        Self::Storage(error)
    }
}

/// `UpdateWithTx`（enable/disable/promote/demote）的固定失败分类：Go 的
/// scoped `First` 对软删除目标返回 ErrRecordNotFound，经 `CtxApiError`
/// 原文回显；Rust 收敛为 [`AdminManageError::NotFound`]。
#[derive(Debug)]
pub enum AdminManageError {
    NotFound,
    Storage(sqlx::Error),
}

impl From<sqlx::Error> for AdminManageError {
    fn from(error: sqlx::Error) -> Self {
        Self::Storage(error)
    }
}

/// Go `InsertWithTx` + `updateAdminPermissionsForUserInTx` 的创建输入。
/// `permissions` 为 `None` 表示请求未携带 `admin_permissions`（含显式 null）。
pub struct AdminCreateInput<'a> {
    pub username: &'a str,
    pub password_hash: &'a str,
    pub display_name: &'a str,
    pub role: i64,
    /// Go `common.QuotaForNewUser`，由 HTTP 层从注册设置装载。
    pub quota: i64,
    pub created_at: i64,
    /// Go `c.GetInt("role")`：操作者角色，参与覆盖写库的 root 判定。
    pub operator_role: i64,
    pub permissions: Option<&'a PermissionOverrides>,
}

/// Go `EditWithTx` + `updateAdminPermissionsForUserInTx` 的更新输入；
/// `password_hash` 为 `None` 表示本次不改密码。
pub struct AdminEditInput<'a> {
    pub user_id: i64,
    pub username: &'a str,
    pub display_name: &'a str,
    pub group: &'a str,
    pub remark: &'a str,
    pub password_hash: Option<&'a str>,
    pub operator_role: i64,
    pub target_role: i64,
    pub permissions: Option<&'a PermissionOverrides>,
}

/// `EditWithTx` 的结果：`AuthVersionAdvanced` 表示本次触发了 auth-version
/// 递增（密码或分组变化），HTTP 层据此撤销全部会话。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminEditOutcome {
    Unchanged,
    AuthVersionAdvanced { next_auth_version: i64 },
}

macro_rules! backend {
    ($db:expr, $pool:ident, $body:block) => {
        match $db {
            Database::Sqlite($pool) => $body,
            Database::Postgres($pool) => $body,
        }
    };
}

/// Go `UpdateWithTx` 的 scoped `First` 等价：软删除/不存在目标在此终止
/// 事务（Go 报 ErrRecordNotFound）。
const ENSURE_LIVE_ROW: &str = "SELECT 1 FROM users WHERE id = $1 AND deleted_at IS NULL";

macro_rules! tx_ensure_live_row {
    ($tx:expr, $user_id:expr) => {{
        let live: Option<i64> = sqlx::query_scalar(ENSURE_LIVE_ROW)
            .bind($user_id)
            .fetch_optional(&mut *($tx))
            .await?;
        if live.is_none() {
            return Err(AdminManageError::NotFound);
        }
    }};
}

/// 在活动事务内递增 auth_version 并回读新版本（两后端语句同形）。
macro_rules! tx_bump_auth_version {
    ($tx:expr, $user_id:expr) => {{
        sqlx::query(BUMP_AUTH_VERSION)
            .bind($user_id)
            .execute(&mut *($tx))
            .await?;
        let next: i64 = sqlx::query_scalar(SELECT_AUTH_VERSION)
            .bind($user_id)
            .fetch_one(&mut *($tx))
            .await?;
        next
    }};
}

/// Go `ClearUserPermissionsInTx`：按注册表资源逐个清除该用户的 p 行。
macro_rules! tx_clear_user_authorization {
    ($tx:expr, $user_id:expr) => {{
        let subject = user_subject($user_id);
        for resource in CATALOG {
            sqlx::query(DELETE_USER_RULE_FOR_RESOURCE)
                .bind(&subject)
                .bind(resource.resource)
                .execute(&mut *($tx))
                .await?;
        }
    }};
}

/// Go `updateAdminPermissionsForUserInTx`（`manage_users.go:1021-1035`）：
/// `permissions == None` 时仅当目标是普通用户且操作者是 root 才清除；
/// 携带覆盖时要求 root，普通用户清除、管理员按注册表基线写覆盖行
/// （`SetUserPermissionsInTx`：先删该资源旧行，再插入与基线不同的动作）。
/// 返回 `authzTouched`（Go 据此 ReloadPolicy；Rust 无内存 enforcer，等价
/// 为无操作，此处仅保留返回形状）。
macro_rules! tx_apply_permission_overrides {
    ($tx:expr, $operator_role:expr, $target_role:expr, $permissions:expr) => {{
        let touched;
        match $permissions {
            None => {
                if $target_role < ROLE_ADMIN_USER && $operator_role == ROLE_ROOT_USER {
                    tx_clear_user_authorization!($tx, $target_role);
                    touched = true;
                } else {
                    touched = false;
                }
            }
            Some(permissions) => {
                if $operator_role != ROLE_ROOT_USER {
                    return Err(AdminPermissionError::OnlyRootCanUpdate);
                }
                if $target_role < ROLE_ADMIN_USER {
                    tx_clear_user_authorization!($tx, $target_role);
                    touched = true;
                } else {
                    let subject = user_subject($target_role);
                    for (resource_name, actions) in permissions.iter() {
                        let Some(resource) = catalog_resource(resource_name) else {
                            continue;
                        };
                        sqlx::query(DELETE_USER_RULE_FOR_RESOURCE)
                            .bind(&subject)
                            .bind(resource.resource)
                            .execute(&mut *($tx))
                            .await?;
                        let mut overrides: Vec<(&str, bool)> = Vec::new();
                        for action in resource.actions {
                            let Some(desired) = actions.get(action.action) else {
                                continue;
                            };
                            let baseline = admin_baseline_allows(crate::policy::Permission {
                                resource: resource.resource,
                                action: action.action,
                            });
                            if *desired == baseline {
                                continue;
                            }
                            overrides.push((action.action, *desired));
                        }
                        overrides.sort_by_key(|(action, _)| *action);
                        for (action, allow) in overrides {
                            sqlx::query(INSERT_USER_RULE)
                                .bind(&subject)
                                .bind(resource.resource)
                                .bind(action)
                                .bind(if allow { "allow" } else { "deny" })
                                .execute(&mut *($tx))
                                .await?;
                        }
                    }
                    touched = true;
                }
            }
        }
        touched
    }};
}

/// Go `common.GetRandomString(4)` 的邀请码字母表。
fn random_aff_code() -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..4)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

#[derive(Clone)]
pub struct AdminUserRepository {
    db: Database,
}

impl AdminUserRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Go `listAllUsers`：总数加分页行，含软删除行（Unscoped）。
    pub async fn list(
        &self,
        offset: i64,
        limit: i64,
        sort: AdminUserSort,
    ) -> Result<(Vec<AdminUserRow>, i64), sqlx::Error> {
        let total: i64 = backend!(&self.db, pool, {
            sqlx::query_scalar(LIST_COUNT).fetch_one(pool).await?
        });
        // 动态部分仅为白名单排序列（SORT_COLUMNS），无注入面。
        let sql = format!("{USER_SELECT}{}{LIST_PAGE_TAIL}", sort.clause());
        // 行解码必须在 backend! 分支内完成：SqliteRow/PgRow 的类型不跨臂。
        let items: Vec<AdminUserRow> = backend!(&self.db, pool, {
            let rows = sqlx::query(sqlx::AssertSqlSafe(sql.clone()))
                .bind(limit)
                .bind(offset)
                .fetch_all(pool)
                .await?;
            rows.into_iter()
                .map(|row| row!(row))
                .collect::<Result<Vec<AdminUserRow>, sqlx::Error>>()?
        });
        Ok((items, total))
    }

    /// Go `SearchUsers`：过滤、计数、分页读，全部 Unscoped。
    pub async fn search(
        &self,
        keyword: &str,
        group: &str,
        role: Option<i64>,
        status: Option<i64>,
        offset: i64,
        limit: i64,
        sort: AdminUserSort,
    ) -> Result<(Vec<AdminUserRow>, i64), sqlx::Error> {
        let pattern = format!("%{keyword}%");
        let keyword_id = keyword.parse::<i64>().ok();
        let count_sql = format!("SELECT COUNT(*) FROM users {SEARCH_BASE}");
        let total: i64 = backend!(&self.db, pool, {
            sqlx::query_scalar(sqlx::AssertSqlSafe(count_sql.clone()))
                .bind(&pattern)
                .bind(keyword_id)
                .bind(group)
                .bind(status)
                .bind(role)
                .fetch_one(pool)
                .await?
        });
        let sql = format!(
            "{USER_SELECT} {SEARCH_BASE}{} LIMIT $6 OFFSET $7",
            sort.clause()
        );
        let items: Vec<AdminUserRow> = backend!(&self.db, pool, {
            let rows = sqlx::query(sqlx::AssertSqlSafe(sql.clone()))
                .bind(&pattern)
                .bind(keyword_id)
                .bind(group)
                .bind(status)
                .bind(role)
                .bind(limit)
                .bind(offset)
                .fetch_all(pool)
                .await?;
            rows.into_iter()
                .map(|row| row!(row))
                .collect::<Result<Vec<AdminUserRow>, sqlx::Error>>()?
        });
        Ok((items, total))
    }

    /// Go `GetUserById(id, false)` 的宽投影：软删除行不可见。
    pub async fn admin_by_id(&self, user_id: i64) -> Result<Option<AdminUserRow>, sqlx::Error> {
        let sql = format!("{USER_SELECT}{BY_ID}");
        let target: Option<AdminUserRow> = backend!(&self.db, pool, {
            sqlx::query(sqlx::AssertSqlSafe(sql.clone()))
                .bind(user_id)
                .fetch_optional(pool)
                .await?
                .map(|row| -> Result<AdminUserRow, sqlx::Error> { row!(row) })
                .transpose()?
        });
        Ok(target)
    }

    /// Go `ManageUser` 的目标读取：Unscoped；`id == 0` 时按主键取第一行
    /// （GORM struct 条件为空时的 `First` 行为）。
    pub async fn manage_target(&self, id: i64) -> Result<Option<AdminUserRow>, sqlx::Error> {
        let sql = if id == 0 {
            format!("{USER_SELECT}{MANAGE_TARGET_FIRST}")
        } else {
            format!("{USER_SELECT} WHERE id = $1 LIMIT 1")
        };
        let target: Option<AdminUserRow> = backend!(&self.db, pool, {
            let mut query = sqlx::query(sqlx::AssertSqlSafe(sql.clone()));
            if id != 0 {
                query = query.bind(id);
            }
            query
                .fetch_optional(pool)
                .await?
                .map(|row| -> Result<AdminUserRow, sqlx::Error> { row!(row) })
                .transpose()?
        });
        Ok(target)
    }

    /// Go `CreateUser` 的存储段：事务内插入用户并写用户级权限覆盖。
    /// 成功返回新用户 id；邮箱恒为空串（Go `cleanUser` 不带邮箱）。
    pub async fn create(&self, input: &AdminCreateInput<'_>) -> Result<i64, AdminPermissionError> {
        let aff_code = random_aff_code();
        let mut user_id;
        backend!(&self.db, pool, {
            let mut tx = pool.begin().await?;
            user_id = sqlx::query_scalar(INSERT_ADMIN_USER)
                .bind(input.username)
                .bind(input.password_hash)
                .bind(input.display_name)
                .bind(input.role)
                .bind(&aff_code)
                .bind(input.created_at)
                .bind(input.quota)
                .bind(crate::registration::DEFAULT_USER_SETTING)
                .fetch_one(&mut *tx)
                .await?;
            tx_apply_permission_overrides!(tx, input.operator_role, input.role, input.permissions);
            tx.commit().await?;
        });
        Ok(user_id)
    }

    /// Go `EditWithTx`（`store_users.go:743-778`）：事务内读当前口令与分组、
    /// 按需递增 auth_version、写列，并处理用户级权限覆盖。
    pub async fn edit(
        &self,
        input: &AdminEditInput<'_>,
    ) -> Result<AdminEditOutcome, AdminPermissionError> {
        backend!(&self.db, pool, {
            let mut tx = pool.begin().await?;
            let state: (Option<String>, Option<String>) = sqlx::query_as(SELECT_EDIT_STATE)
                .bind(input.user_id)
                .fetch_one(&mut *tx)
                .await?;
            let current_group = state.0.unwrap_or_default();
            let current_hash = state.1.unwrap_or_default();
            let update_password = input.password_hash.is_some();
            let auth_changed = (update_password
                && current_hash != input.password_hash.unwrap_or_default())
                || current_group != input.group;
            let next_auth_version = if auth_changed {
                tx_bump_auth_version!(tx, input.user_id)
            } else {
                0
            };
            match input.password_hash {
                Some(hash) => {
                    sqlx::query(EDIT_UPDATE_PASSWORD)
                        .bind(hash)
                        .bind(input.username)
                        .bind(input.display_name)
                        .bind(input.group)
                        .bind(input.remark)
                        .bind(input.user_id)
                        .execute(&mut *tx)
                        .await?;
                }
                None => {
                    sqlx::query(EDIT_UPDATE)
                        .bind(input.username)
                        .bind(input.display_name)
                        .bind(input.group)
                        .bind(input.remark)
                        .bind(input.user_id)
                        .execute(&mut *tx)
                        .await?;
                }
            }
            tx_apply_permission_overrides!(
                tx,
                input.operator_role,
                input.target_role,
                input.permissions
            );
            tx.commit().await?;
            Ok(if auth_changed {
                AdminEditOutcome::AuthVersionAdvanced { next_auth_version }
            } else {
                AdminEditOutcome::Unchanged
            })
        })
    }

    /// Go enable/disable/promote 的 `User.Update(false)` 通路：写列、按
    /// `authChanged` 递增 auth_version（角色或状态实际变化）。返回递增后
    /// 的版本；未递增为 `None`。
    ///
    /// Go `UpdateWithTx` 先以 GORM 默认作用域 `First` 读当前行——软删除
    /// 目标在这里以 ErrRecordNotFound 终止（事务回滚，版本不残留），由
    /// [`AdminManageError::NotFound`] 承载。
    pub async fn apply_manage_update(
        &self,
        user_id: i64,
        status: Option<i64>,
        role: Option<i64>,
        bump: bool,
    ) -> Result<Option<i64>, AdminManageError> {
        backend!(&self.db, pool, {
            let mut tx = pool.begin().await.map_err(AdminManageError::Storage)?;
            tx_ensure_live_row!(tx, user_id);
            let next_auth_version = if bump {
                Some(tx_bump_auth_version!(tx, user_id))
            } else {
                None
            };
            if let Some(status) = status {
                sqlx::query(UPDATE_STATUS)
                    .bind(status)
                    .bind(user_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(AdminManageError::Storage)?;
            }
            if let Some(role) = role {
                sqlx::query(UPDATE_ROLE)
                    .bind(role)
                    .bind(user_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(AdminManageError::Storage)?;
            }
            tx.commit().await.map_err(AdminManageError::Storage)?;
            Ok(next_auth_version)
        })
    }

    /// Go demote 的独立分支（`manage_users.go:1201-1218`）：同一事务内
    /// `UpdateWithTx` + `ClearUserAuthorizationInTx`。降级必然改变角色，
    /// auth_version 无条件递增；软删除目标同样在 scoped `First` 处失败。
    pub async fn demote(&self, user_id: i64, new_role: i64) -> Result<(), AdminManageError> {
        backend!(&self.db, pool, {
            let mut tx = pool.begin().await.map_err(AdminManageError::Storage)?;
            tx_ensure_live_row!(tx, user_id);
            tx_bump_auth_version!(tx, user_id);
            sqlx::query(UPDATE_ROLE)
                .bind(new_role)
                .bind(user_id)
                .execute(&mut *tx)
                .await
                .map_err(AdminManageError::Storage)?;
            tx_clear_user_authorization!(tx, user_id);
            tx.commit().await.map_err(AdminManageError::Storage)?;
            Ok(())
        })
    }

    /// Go `IncreaseUserQuota(id, quota, true)`：直连库加额度。
    pub async fn increase_quota(&self, user_id: i64, amount: i64) -> Result<(), sqlx::Error> {
        backend!(&self.db, pool, {
            sqlx::query(INCREASE_QUOTA)
                .bind(amount)
                .bind(user_id)
                .execute(pool)
                .await?;
            Ok(())
        })
    }

    /// Go `DecreaseUserQuota(id, quota, true)`：直连库减额度。
    pub async fn decrease_quota(&self, user_id: i64, amount: i64) -> Result<(), sqlx::Error> {
        backend!(&self.db, pool, {
            sqlx::query(DECREASE_QUOTA)
                .bind(amount)
                .bind(user_id)
                .execute(pool)
                .await?;
            Ok(())
        })
    }

    /// Go `add_quota` 的 override 模式：直接写库；钱包缓存失效由 HTTP 层
    /// 处理（Rust 尚无钱包缓存，登记为移植缺口）。
    pub async fn override_quota(&self, user_id: i64, value: i64) -> Result<(), sqlx::Error> {
        backend!(&self.db, pool, {
            sqlx::query(OVERRIDE_QUOTA)
                .bind(value)
                .bind(user_id)
                .execute(pool)
                .await?;
            Ok(())
        })
    }

    /// Go `HardDeleteUserById`（`store_users_lifecycle.go:72-78` →
    /// `store_users.go:HardDelete`）：事务内递增版本、收集令牌 key、硬删
    /// 全部认证数据与用户行。返回收集到的令牌 key（仅用于提交后的缓存
    /// 失效；不实现 Debug/序列化）。
    pub async fn hard_delete(&self, user_id: i64) -> Result<Vec<String>, sqlx::Error> {
        backend!(&self.db, pool, {
            let mut tx = pool.begin().await?;
            tx_bump_auth_version!(tx, user_id);
            let raw_keys: Vec<Option<String>> = sqlx::query_scalar(HARD_DELETE_TOKEN_KEYS)
                .bind(user_id)
                .fetch_all(&mut *tx)
                .await?;
            let keys: Vec<String> = raw_keys
                .into_iter()
                .flatten()
                .filter(|key| !key.is_empty())
                .collect();
            for statement in HARD_DELETE_TABLES {
                sqlx::query(statement)
                    .bind(user_id)
                    .execute(&mut *tx)
                    .await?;
            }
            sqlx::query(HARD_DELETE_USER)
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            Ok(keys)
        })
    }

    /// Go `InvalidateUserTokensCache` 的 key 收集段
    /// （`token_store.go:449-465`）：Unscoped 读取该用户全部令牌 key。
    /// 缓存失效本身由 HTTP 层执行；这里只提供收集。
    pub async fn token_keys(&self, user_id: i64) -> Result<Vec<String>, sqlx::Error> {
        backend!(&self.db, pool, {
            let raw_keys: Vec<Option<String>> = sqlx::query_scalar(HARD_DELETE_TOKEN_KEYS)
                .bind(user_id)
                .fetch_all(pool)
                .await?;
            let keys: Vec<String> = raw_keys
                .into_iter()
                .flatten()
                .filter(|key| !key.is_empty())
                .collect();
            Ok(keys)
        })
    }

    /// Go `IsQQBoundByUserId`：绑定行的 open_id；失败/空值归为未绑定。
    pub async fn qq_open_id(&self, user_id: i64) -> Option<String> {
        let open_id: Result<Option<Option<String>>, sqlx::Error> = backend!(&self.db, pool, {
            sqlx::query_scalar(QQ_OPEN_ID)
                .bind(user_id)
                .fetch_optional(pool)
                .await
        });
        match open_id {
            Ok(value) => value.flatten().filter(|open_id| !open_id.is_empty()),
            Err(_) => {
                tracing::warn!(
                    event = "admin_user_qq_binding_lookup_failed",
                    user_id,
                    "QQ binding lookup failed; Go treats this as unbound"
                );
                None
            }
        }
    }
}
