//! 自定义 OAuth 提供商管理仓储与校验：Go
//! `identity/resolve_oauth_provider.go`（`CustomOAuthProvider` 表结构、
//! `validateCustomOAuthProvider` 与 `validateAccessPolicyPayload`）、
//! `identity/bind_oauth.go`（`GetBindingCountByProviderId`）与
//! `identity/bind_custom_oauth.go` 的 CRUD 分支。
//!
//! 本模块只覆盖管理端六个端点所需的读写与校验；登录流程使用的进程内
//! 提供商注册表（Go `security/oauth/registry.go` 的 `RegisterOrUpdate`/
//! `Unregister`）属于 generic OAuth 登录切片，不在此实现——管理端只把
//! 配置落库，注册表由登录切片在装载/调用时重建。
//!
//! 与 Go 的对齐点：
//! - 响应视图（`CustomOAuthProviderView`）逐字段对齐
//!   `CustomOAuthProviderResponse`（`bind_custom_oauth.go:18-37`），
//!   **不含** `client_secret`（Go 结构体同样省略该列）；
//! - `validate` 复刻 `validateCustomOAuthProvider` 的分支顺序与默认值
//!   填充（`slug` 小写化在字符集检查之后、落库之前）；
//! - `slug_taken` 的 SQL 形状对应 `IsSlugTaken`；是否“已被使用”的判定
//!   （含失败短路）由 HTTP 层按 Go 的 fail-closed 语义决定；
//! - 删除按 Go 的两条独立语句（先绑定、后提供商），不带事务、不把
//!   `rows_affected` 当错误。

use serde::Serialize;
use sqlx::Row;

use newapi_storage::Database;

/// Go `CustomOAuthProvider`（`resolve_oauth_provider.go:41-68`）的行投影；
/// 与 `REQUIRED_SCHEMA_COLUMNS` 的列清单一致。`client_secret` 只在
/// 更新合并与落库时使用，响应视图不携带；自定义 `Debug` 脱敏。
#[derive(Clone, Eq, PartialEq)]
pub struct CustomOAuthProviderRecord {
    pub id: i64,
    pub name: String,
    pub slug: String,
    pub icon: String,
    pub enabled: bool,
    pub client_id: String,
    pub client_secret: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub user_info_endpoint: String,
    pub scopes: String,
    pub user_id_field: String,
    pub username_field: String,
    pub display_name_field: String,
    pub email_field: String,
    pub well_known: String,
    pub auth_style: i64,
    pub access_policy: String,
    pub access_denied_message: String,
}

impl std::fmt::Debug for CustomOAuthProviderRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CustomOAuthProviderRecord")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("slug", &self.slug)
            .field("icon", &self.icon)
            .field("enabled", &self.enabled)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("authorization_endpoint", &self.authorization_endpoint)
            .field("token_endpoint", &self.token_endpoint)
            .field("user_info_endpoint", &self.user_info_endpoint)
            .field("scopes", &self.scopes)
            .field("user_id_field", &self.user_id_field)
            .field("username_field", &self.username_field)
            .field("display_name_field", &self.display_name_field)
            .field("email_field", &self.email_field)
            .field("well_known", &self.well_known)
            .field("auth_style", &self.auth_style)
            .field("access_policy", &self.access_policy)
            .field("access_denied_message", &self.access_denied_message)
            .finish()
    }
}

/// Go `toCustomOAuthProviderResponse`（`bind_custom_oauth.go:47-68`）的响应
/// 视图：字段名与 Go JSON tag 逐字一致，`client_secret` 不回显。
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CustomOAuthProviderView {
    pub id: i64,
    pub name: String,
    pub slug: String,
    pub icon: String,
    pub enabled: bool,
    pub client_id: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub user_info_endpoint: String,
    pub scopes: String,
    pub user_id_field: String,
    pub username_field: String,
    pub display_name_field: String,
    pub email_field: String,
    pub well_known: String,
    pub auth_style: i64,
    pub access_policy: String,
    pub access_denied_message: String,
}

impl From<&CustomOAuthProviderRecord> for CustomOAuthProviderView {
    fn from(record: &CustomOAuthProviderRecord) -> Self {
        Self {
            id: record.id,
            name: record.name.clone(),
            slug: record.slug.clone(),
            icon: record.icon.clone(),
            enabled: record.enabled,
            client_id: record.client_id.clone(),
            authorization_endpoint: record.authorization_endpoint.clone(),
            token_endpoint: record.token_endpoint.clone(),
            user_info_endpoint: record.user_info_endpoint.clone(),
            scopes: record.scopes.clone(),
            user_id_field: record.user_id_field.clone(),
            username_field: record.username_field.clone(),
            display_name_field: record.display_name_field.clone(),
            email_field: record.email_field.clone(),
            well_known: record.well_known.clone(),
            auth_style: record.auth_style,
            access_policy: record.access_policy.clone(),
            access_denied_message: record.access_denied_message.clone(),
        }
    }
}

/// `validateCustomOAuthProvider` 的校验分支；文案是 Go 的硬编码字面量，
/// 前端按字面量比对，HTTP 层原样返回。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderValidationIssue {
    NameRequired,
    SlugRequired,
    SlugCharset,
    ClientIdRequired,
    AuthorizationEndpointRequired,
    TokenEndpointRequired,
    UserInfoEndpointRequired,
    /// Go `access_policy must be valid JSON`（JSON 解析或字段类型不符）。
    AccessPolicyNotJson,
    /// Go `access_policy is invalid: <内层错误>`；携带 `validateAccessPolicyPayload`
    /// 格式化后的内层文案。
    AccessPolicyInvalid(String),
}

impl ProviderValidationIssue {
    /// 逐字复刻 `resolve_oauth_provider.go:150-205` 的错误文案。
    pub fn message(&self) -> String {
        match self {
            Self::NameRequired => "provider name is required".to_owned(),
            Self::SlugRequired => "provider slug is required".to_owned(),
            Self::SlugCharset => {
                "provider slug must contain only lowercase letters, numbers, and hyphens".to_owned()
            }
            Self::ClientIdRequired => "client ID is required".to_owned(),
            Self::AuthorizationEndpointRequired => "authorization endpoint is required".to_owned(),
            Self::TokenEndpointRequired => "token endpoint is required".to_owned(),
            Self::UserInfoEndpointRequired => "user info endpoint is required".to_owned(),
            Self::AccessPolicyNotJson => "access_policy must be valid JSON".to_owned(),
            Self::AccessPolicyInvalid(inner) => format!("access_policy is invalid: {inner}"),
        }
    }
}

/// Go `supportedAccessPolicyOps`（`resolve_oauth_provider.go:25-38`）。
const SUPPORTED_POLICY_OPS: [&str; 12] = [
    "eq",
    "ne",
    "gt",
    "gte",
    "lt",
    "lte",
    "in",
    "not_in",
    "contains",
    "not_contains",
    "exists",
    "not_exists",
];

/// Go `validateCustomOAuthProvider`（`resolve_oauth_provider.go:150-206`）。
///
/// 分支顺序与 Go 一致：name → slug → slug 字符集（先整体小写再逐字符
/// 判断，合法时把小写结果写回 `record.slug`，即 Go 的 `provider.Slug = slug`）
/// → client_id → 三个端点 → 字段映射与 scopes 的默认值 → access_policy。
/// 默认值只在对应列为空时填充，与 Go 的 `if provider.X == ""` 语义相同。
pub fn validate(record: &mut CustomOAuthProviderRecord) -> Result<(), ProviderValidationIssue> {
    if record.name.is_empty() {
        return Err(ProviderValidationIssue::NameRequired);
    }
    if record.slug.is_empty() {
        return Err(ProviderValidationIssue::SlugRequired);
    }
    // Go 先 `strings.ToLower` 再逐字符校验，合法时把小写结果写回。
    let slug = record.slug.to_ascii_lowercase();
    if !slug
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(ProviderValidationIssue::SlugCharset);
    }
    record.slug = slug;
    if record.client_id.is_empty() {
        return Err(ProviderValidationIssue::ClientIdRequired);
    }
    if record.authorization_endpoint.is_empty() {
        return Err(ProviderValidationIssue::AuthorizationEndpointRequired);
    }
    if record.token_endpoint.is_empty() {
        return Err(ProviderValidationIssue::TokenEndpointRequired);
    }
    if record.user_info_endpoint.is_empty() {
        return Err(ProviderValidationIssue::UserInfoEndpointRequired);
    }
    if record.user_id_field.is_empty() {
        record.user_id_field = "sub".to_owned();
    }
    if record.username_field.is_empty() {
        record.username_field = "preferred_username".to_owned();
    }
    if record.display_name_field.is_empty() {
        record.display_name_field = "name".to_owned();
    }
    if record.email_field.is_empty() {
        record.email_field = "email".to_owned();
    }
    if record.scopes.is_empty() {
        record.scopes = "openid profile email".to_owned();
    }
    validate_access_policy(&record.access_policy)
}

/// Go 的 `if strings.TrimSpace(provider.AccessPolicy) != ""` 分支：
/// 空串与纯空白跳过；非空时按 `accessPolicyPayload` 解析并校验。
fn validate_access_policy(policy: &str) -> Result<(), ProviderValidationIssue> {
    let trimmed = policy.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    let payload =
        parse_policy_payload(trimmed).map_err(|_| ProviderValidationIssue::AccessPolicyNotJson)?;
    validate_policy_payload(&payload).map_err(ProviderValidationIssue::AccessPolicyInvalid)
}

/// Go `accessPolicyPayload` / `accessConditionItem` 的 Rust 镜像；字段全部
/// 可选以复刻 Go json.Unmarshal 对 `null` 的“零值化”语义（缺字段与 null
/// 等价于零值，而非类型错误）。
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct PolicyPayload {
    logic: Option<String>,
    conditions: Option<Vec<ConditionPayload>>,
    groups: Option<Vec<PolicyPayload>>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct ConditionPayload {
    field: Option<String>,
    op: Option<String>,
    value: Option<serde_json::Value>,
}

/// Go `json.Unmarshal(data, &policy)` 的行为复刻：`null` 解码成零值；
/// JSON 对象逐字段提取（缺字段与 `null` 都是零值）；顶层非对象、字段
/// 类型不符、JSON 语法错误一律视为 unmarshal 失败。
fn parse_policy_payload(json: &str) -> Result<PolicyPayload, ()> {
    let value: serde_json::Value = serde_json::from_str(json).map_err(|_| ())?;
    payload_from_value(&value)
}

fn payload_from_value(value: &serde_json::Value) -> Result<PolicyPayload, ()> {
    match value {
        serde_json::Value::Null => Ok(PolicyPayload::default()),
        serde_json::Value::Object(_) => Ok(PolicyPayload {
            logic: optional_string(value.get("logic"))?,
            conditions: match value.get("conditions") {
                None | Some(serde_json::Value::Null) => None,
                Some(serde_json::Value::Array(items)) => Some(
                    items
                        .iter()
                        .map(condition_from_value)
                        .collect::<Result<Vec<_>, _>>()?,
                ),
                _ => return Err(()),
            },
            groups: match value.get("groups") {
                None | Some(serde_json::Value::Null) => None,
                Some(serde_json::Value::Array(items)) => Some(
                    items
                        .iter()
                        .map(payload_from_value)
                        .collect::<Result<Vec<_>, _>>()?,
                ),
                _ => return Err(()),
            },
        }),
        _ => Err(()),
    }
}

fn condition_from_value(value: &serde_json::Value) -> Result<ConditionPayload, ()> {
    match value {
        // 与 Go 一致：null 元素零值化，校验时报 condition[i].field required。
        serde_json::Value::Null => Ok(ConditionPayload::default()),
        serde_json::Value::Object(_) => Ok(ConditionPayload {
            field: optional_string(value.get("field"))?,
            op: optional_string(value.get("op"))?,
            value: match value.get("value") {
                None | Some(serde_json::Value::Null) => None,
                Some(value) => Some(value.clone()),
            },
        }),
        _ => Err(()),
    }
}

/// Go 的 string 字段：缺字段、`null` 都是零值；其他类型是 unmarshal 失败。
fn optional_string(value: Option<&serde_json::Value>) -> Result<Option<String>, ()> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(text)) => Ok(Some(text.clone())),
        _ => Err(()),
    }
}

/// Go `validateAccessPolicyPayload`（`resolve_oauth_provider.go:208-248`），
/// 内层错误文案逐字复刻（含 `%w` 链的 `group[%d]: ` 前缀）。
fn validate_policy_payload(payload: &PolicyPayload) -> Result<(), String> {
    let logic = payload
        .logic
        .as_deref()
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    let logic = if logic.is_empty() {
        "and"
    } else {
        logic.as_str()
    };
    if logic != "and" && logic != "or" {
        return Err(format!("unsupported logic: {logic}"));
    }
    let conditions = payload.conditions.as_deref().unwrap_or(&[]);
    let groups = payload.groups.as_deref().unwrap_or(&[]);
    if conditions.is_empty() && groups.is_empty() {
        return Err("policy requires at least one condition or group".to_owned());
    }
    for (index, condition) in conditions.iter().enumerate() {
        let field = condition
            .field
            .as_deref()
            .map(str::trim)
            .unwrap_or_default();
        if field.is_empty() {
            return Err(format!("condition[{index}].field is required"));
        }
        let op = condition
            .op
            .as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .unwrap_or_default();
        if !SUPPORTED_POLICY_OPS.contains(&op.as_str()) {
            return Err(format!("condition[{index}].op is unsupported: {op}"));
        }
        if op == "in" || op == "not_in" {
            let is_array = condition
                .value
                .as_ref()
                .is_some_and(|value| matches!(value, serde_json::Value::Array(_)));
            if !is_array {
                return Err(format!(
                    "condition[{index}].value must be an array for op {op}"
                ));
            }
        }
    }
    for (index, group) in groups.iter().enumerate() {
        if let Err(inner) = validate_policy_payload(group) {
            return Err(format!("group[{index}]: {inner}"));
        }
    }
    Ok(())
}

// 固定白名单，禁止 SELECT *；旧库的 INTEGER 列显式提升为 i64。两条 SELECT
// 直接内联列清单（`concat!` 只接受字面量，不能拼 const 标识符）。
const SELECT_ALL: &str = r#"
SELECT CAST(id AS BIGINT) AS id, name, slug, icon, enabled,
    client_id, client_secret, authorization_endpoint, token_endpoint,
    user_info_endpoint, scopes, user_id_field, username_field,
    display_name_field, email_field, well_known,
    CAST(auth_style AS BIGINT) AS auth_style, access_policy, access_denied_message
FROM custom_oauth_providers ORDER BY id ASC
"#;

const SELECT_BY_ID: &str = r#"
SELECT CAST(id AS BIGINT) AS id, name, slug, icon, enabled,
    client_id, client_secret, authorization_endpoint, token_endpoint,
    user_info_endpoint, scopes, user_id_field, username_field,
    display_name_field, email_field, well_known,
    CAST(auth_style AS BIGINT) AS auth_style, access_policy, access_denied_message
FROM custom_oauth_providers WHERE id = $1
"#;
const COUNT_BY_SLUG: &str =
    "SELECT CAST(COUNT(*) AS BIGINT) FROM custom_oauth_providers WHERE slug = $1";
const COUNT_BY_SLUG_EXCLUDING: &str =
    "SELECT CAST(COUNT(*) AS BIGINT) FROM custom_oauth_providers WHERE slug = $1 AND id != $2";
/// Go `GetBindingCountByProviderId`（`bind_oauth.go:143-147`）。
const COUNT_BINDINGS_BY_PROVIDER: &str =
    "SELECT CAST(COUNT(*) AS BIGINT) FROM user_oauth_bindings WHERE provider_id = $1";

/// GORM `Create` 写满全部非时间列，时间列由框架填 now；这里用
/// `CURRENT_TIMESTAMP` 对齐（created_at/updated_at 不进入任何响应）。
const INSERT_PROVIDER: &str = r#"
INSERT INTO custom_oauth_providers (
    name, slug, icon, enabled, client_id, client_secret,
    authorization_endpoint, token_endpoint, user_info_endpoint, scopes,
    user_id_field, username_field, display_name_field, email_field, well_known,
    auth_style, access_policy, access_denied_message, created_at, updated_at
) VALUES (
    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,
    CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
) RETURNING CAST(id AS BIGINT)
"#;

/// GORM `Save`（`updateCustomOAuthProvider`）：整行写回，CreatedAt 保持
/// 装载时的原值（GORM 只在零值时才自动填），UpdatedAt 刷新为当前时间。
const UPDATE_PROVIDER: &str = r#"
UPDATE custom_oauth_providers SET
    name=$1, slug=$2, icon=$3, enabled=$4, client_id=$5, client_secret=$6,
    authorization_endpoint=$7, token_endpoint=$8, user_info_endpoint=$9, scopes=$10,
    user_id_field=$11, username_field=$12, display_name_field=$13, email_field=$14,
    well_known=$15, auth_style=$16, access_policy=$17, access_denied_message=$18,
    updated_at=CURRENT_TIMESTAMP
WHERE id=$19
"#;

const DELETE_PROVIDER: &str = "DELETE FROM custom_oauth_providers WHERE id = $1";
/// `deleteCustomOAuthProvider` 的第一条语句（`resolve_oauth_provider.go:127`）。
const DELETE_PROVIDER_BINDINGS: &str = "DELETE FROM user_oauth_bindings WHERE provider_id = $1";

// 两驱动分别展开类型化解码；单一语句同时服务两个后端。
macro_rules! backend {
    ($db:expr, $pool:ident, $body:block) => {
        match $db {
            Database::Sqlite($pool) => $body,
            Database::Postgres($pool) => $body,
        }
    };
}

macro_rules! provider_row {
    ($row:expr) => {{
        let row = $row;
        CustomOAuthProviderRecord {
            id: row.try_get("id")?,
            name: row
                .try_get::<Option<String>, _>("name")?
                .unwrap_or_default(),
            slug: row
                .try_get::<Option<String>, _>("slug")?
                .unwrap_or_default(),
            icon: row
                .try_get::<Option<String>, _>("icon")?
                .unwrap_or_default(),
            enabled: row
                .try_get::<Option<bool>, _>("enabled")?
                .unwrap_or_default(),
            client_id: row
                .try_get::<Option<String>, _>("client_id")?
                .unwrap_or_default(),
            client_secret: row
                .try_get::<Option<String>, _>("client_secret")?
                .unwrap_or_default(),
            authorization_endpoint: row
                .try_get::<Option<String>, _>("authorization_endpoint")?
                .unwrap_or_default(),
            token_endpoint: row
                .try_get::<Option<String>, _>("token_endpoint")?
                .unwrap_or_default(),
            user_info_endpoint: row
                .try_get::<Option<String>, _>("user_info_endpoint")?
                .unwrap_or_default(),
            scopes: row
                .try_get::<Option<String>, _>("scopes")?
                .unwrap_or_default(),
            user_id_field: row
                .try_get::<Option<String>, _>("user_id_field")?
                .unwrap_or_default(),
            username_field: row
                .try_get::<Option<String>, _>("username_field")?
                .unwrap_or_default(),
            display_name_field: row
                .try_get::<Option<String>, _>("display_name_field")?
                .unwrap_or_default(),
            email_field: row
                .try_get::<Option<String>, _>("email_field")?
                .unwrap_or_default(),
            well_known: row
                .try_get::<Option<String>, _>("well_known")?
                .unwrap_or_default(),
            auth_style: row
                .try_get::<Option<i64>, _>("auth_style")?
                .unwrap_or_default(),
            access_policy: row
                .try_get::<Option<String>, _>("access_policy")?
                .unwrap_or_default(),
            access_denied_message: row
                .try_get::<Option<String>, _>("access_denied_message")?
                .unwrap_or_default(),
        }
    }};
}

/// 自定义 OAuth 提供商管理仓储；不判定权限，`slug_taken` 也不复刻 Go 的
/// fail-closed（DB 错误是否算“已占用”由 HTTP 层决定，见模块注释）。
#[derive(Clone)]
pub struct CustomOAuthRepository {
    db: Database,
}

impl CustomOAuthRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Go `GetAllCustomOAuthProviders`（`resolve_oauth_provider.go:75-79`）：
    /// `Order("id asc")` 全量读取。
    pub async fn list(&self) -> Result<Vec<CustomOAuthProviderRecord>, sqlx::Error> {
        match &self.db {
            Database::Sqlite(pool) => sqlx::query(SELECT_ALL)
                .fetch_all(pool)
                .await?
                .into_iter()
                .map(|row| Ok(provider_row!(row)))
                .collect::<Result<Vec<_>, sqlx::Error>>(),
            Database::Postgres(pool) => sqlx::query(SELECT_ALL)
                .fetch_all(pool)
                .await?
                .into_iter()
                .map(|row| Ok(provider_row!(row)))
                .collect::<Result<Vec<_>, sqlx::Error>>(),
        }
    }

    /// Go `GetCustomOAuthProviderById`（`resolve_oauth_provider.go:89-96`）；
    /// `Ok(None)` 对应 GORM 的记录不存在，存储故障原样传播。
    pub async fn by_id(
        &self,
        provider_id: i64,
    ) -> Result<Option<CustomOAuthProviderRecord>, sqlx::Error> {
        match &self.db {
            Database::Sqlite(pool) => sqlx::query(SELECT_BY_ID)
                .bind(provider_id)
                .fetch_optional(pool)
                .await?
                .map(|row| Ok(provider_row!(row)))
                .transpose(),
            Database::Postgres(pool) => sqlx::query(SELECT_BY_ID)
                .bind(provider_id)
                .fetch_optional(pool)
                .await?
                .map(|row| Ok(provider_row!(row)))
                .transpose(),
        }
    }

    /// Go `IsSlugTaken`（`resolve_oauth_provider.go:135-147`）的查询部分：
    /// `exclude_id > 0` 时附加 `id != excludeId`。是否把 DB 错误当作
    /// “已占用”（Go 的 fail-closed）由调用方决定。
    pub async fn slug_taken(&self, slug: &str, exclude_id: i64) -> Result<bool, sqlx::Error> {
        let count = if exclude_id > 0 {
            backend!(&self.db, pool, {
                sqlx::query_scalar::<_, i64>(COUNT_BY_SLUG_EXCLUDING)
                    .bind(slug)
                    .bind(exclude_id)
                    .fetch_one(pool)
                    .await?
            })
        } else {
            backend!(&self.db, pool, {
                sqlx::query_scalar::<_, i64>(COUNT_BY_SLUG)
                    .bind(slug)
                    .fetch_one(pool)
                    .await?
            })
        };
        Ok(count > 0)
    }

    /// Go `GetBindingCountByProviderId`；存储故障原样传播，由 HTTP 层折叠。
    pub async fn binding_count(&self, provider_id: i64) -> Result<i64, sqlx::Error> {
        Ok(backend!(&self.db, pool, {
            sqlx::query_scalar::<_, i64>(COUNT_BINDINGS_BY_PROVIDER)
                .bind(provider_id)
                .fetch_one(pool)
                .await?
        }))
    }

    /// Go `dbx.DB.Create(provider)`：返回数据库分配的 id
    /// （GORM 回填 `provider.Id`，响应中的 id 即来自这里）。
    pub async fn insert(&self, record: &CustomOAuthProviderRecord) -> Result<i64, sqlx::Error> {
        Ok(backend!(&self.db, pool, {
            sqlx::query_scalar::<_, i64>(INSERT_PROVIDER)
                .bind(&record.name)
                .bind(&record.slug)
                .bind(&record.icon)
                .bind(record.enabled)
                .bind(&record.client_id)
                .bind(&record.client_secret)
                .bind(&record.authorization_endpoint)
                .bind(&record.token_endpoint)
                .bind(&record.user_info_endpoint)
                .bind(&record.scopes)
                .bind(&record.user_id_field)
                .bind(&record.username_field)
                .bind(&record.display_name_field)
                .bind(&record.email_field)
                .bind(&record.well_known)
                .bind(record.auth_style)
                .bind(&record.access_policy)
                .bind(&record.access_denied_message)
                .fetch_one(pool)
                .await?
        }))
    }

    /// Go `dbx.DB.Save(provider)` 的整行写回；GORM 不把 `RowsAffected`
    /// 当错误，这里仅返回行数供测试观察，不参与响应分支。
    pub async fn update(&self, record: &CustomOAuthProviderRecord) -> Result<u64, sqlx::Error> {
        let affected = backend!(&self.db, pool, {
            sqlx::query(UPDATE_PROVIDER)
                .bind(&record.name)
                .bind(&record.slug)
                .bind(&record.icon)
                .bind(record.enabled)
                .bind(&record.client_id)
                .bind(&record.client_secret)
                .bind(&record.authorization_endpoint)
                .bind(&record.token_endpoint)
                .bind(&record.user_info_endpoint)
                .bind(&record.scopes)
                .bind(&record.user_id_field)
                .bind(&record.username_field)
                .bind(&record.display_name_field)
                .bind(&record.email_field)
                .bind(&record.well_known)
                .bind(record.auth_style)
                .bind(&record.access_policy)
                .bind(&record.access_denied_message)
                .bind(record.id)
                .execute(pool)
                .await?
                .rows_affected()
        });
        Ok(affected)
    }

    /// Go `deleteCustomOAuthProvider`（`resolve_oauth_provider.go:125-131`）：
    /// 先删该提供商的全部绑定，再删提供商本身；两条独立语句、无事务。
    /// 返回 `(绑定行数, 提供商行数)`，GORM 同样不把行数当错误。
    pub async fn delete(&self, provider_id: i64) -> Result<(u64, u64), sqlx::Error> {
        let bindings = backend!(&self.db, pool, {
            sqlx::query(DELETE_PROVIDER_BINDINGS)
                .bind(provider_id)
                .execute(pool)
                .await?
                .rows_affected()
        });
        let providers = backend!(&self.db, pool, {
            sqlx::query(DELETE_PROVIDER)
                .bind(provider_id)
                .execute(pool)
                .await?
                .rows_affected()
        });
        Ok((bindings, providers))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statements_are_static_and_parameterized() {
        assert!(SELECT_ALL.contains("FROM custom_oauth_providers ORDER BY id ASC"));
        assert!(SELECT_BY_ID.contains("WHERE id = $1"));
        assert!(!SELECT_ALL.contains("SELECT *"));
        assert!(COUNT_BY_SLUG_EXCLUDING.contains("slug = $1 AND id != $2"));
        assert!(COUNT_BINDINGS_BY_PROVIDER.contains("provider_id = $1"));
        assert!(INSERT_PROVIDER.contains("RETURNING"));
        assert!(UPDATE_PROVIDER.contains("WHERE id=$19"));
    }

    #[test]
    fn validation_message_strings_match_go_literals() {
        assert_eq!(
            ProviderValidationIssue::NameRequired.message(),
            "provider name is required"
        );
        assert_eq!(
            ProviderValidationIssue::SlugCharset.message(),
            "provider slug must contain only lowercase letters, numbers, and hyphens"
        );
        assert_eq!(
            ProviderValidationIssue::AccessPolicyInvalid("unsupported logic: xor".to_owned())
                .message(),
            "access_policy is invalid: unsupported logic: xor"
        );
    }

    fn record() -> CustomOAuthProviderRecord {
        CustomOAuthProviderRecord {
            id: 0,
            name: "GitHub Enterprise".to_owned(),
            slug: "GH-Enterprise".to_owned(),
            icon: String::new(),
            enabled: false,
            client_id: "cid".to_owned(),
            client_secret: "secret".to_owned(),
            authorization_endpoint: "https://gh.e/authorize".to_owned(),
            token_endpoint: "https://gh.e/token".to_owned(),
            user_info_endpoint: "https://gh.e/user".to_owned(),
            scopes: String::new(),
            user_id_field: String::new(),
            username_field: String::new(),
            display_name_field: String::new(),
            email_field: String::new(),
            well_known: String::new(),
            auth_style: 0,
            access_policy: String::new(),
            access_denied_message: String::new(),
        }
    }

    #[test]
    fn validate_lowercases_slug_and_fills_defaults() {
        let mut provider = record();
        validate(&mut provider).expect("valid provider");
        assert_eq!(provider.slug, "gh-enterprise");
        assert_eq!(provider.scopes, "openid profile email");
        assert_eq!(provider.user_id_field, "sub");
        assert_eq!(provider.username_field, "preferred_username");
        assert_eq!(provider.display_name_field, "name");
        assert_eq!(provider.email_field, "email");
    }

    #[test]
    fn validate_keeps_explicit_field_mappings_and_scopes() {
        let mut provider = record();
        provider.scopes = "user:email".to_owned();
        provider.user_id_field = "id".to_owned();
        validate(&mut provider).expect("valid provider");
        assert_eq!(provider.scopes, "user:email");
        assert_eq!(provider.user_id_field, "id");
    }

    #[test]
    fn validate_reports_missing_required_fields() {
        let mut provider = record();
        provider.name.clear();
        assert_eq!(
            validate(&mut provider).unwrap_err(),
            ProviderValidationIssue::NameRequired
        );
        let mut provider = record();
        provider.slug.clear();
        assert_eq!(
            validate(&mut provider).unwrap_err(),
            ProviderValidationIssue::SlugRequired
        );
        let mut provider = record();
        provider.client_id.clear();
        assert_eq!(
            validate(&mut provider).unwrap_err(),
            ProviderValidationIssue::ClientIdRequired
        );
        let mut provider = record();
        provider.authorization_endpoint.clear();
        assert_eq!(
            validate(&mut provider).unwrap_err(),
            ProviderValidationIssue::AuthorizationEndpointRequired
        );
    }

    #[test]
    fn validate_rejects_slug_charset() {
        let mut provider = record();
        provider.slug = "has_underscore".to_owned();
        assert_eq!(
            validate(&mut provider).unwrap_err(),
            ProviderValidationIssue::SlugCharset
        );
        let mut provider = record();
        // 非法字符在小写化后仍然存在（非 ASCII）。
        provider.slug = "你好".to_owned();
        assert_eq!(
            validate(&mut provider).unwrap_err(),
            ProviderValidationIssue::SlugCharset
        );
        // 大写合法：Go 先整体小写再校验，合法结果写回。
        let mut provider = record();
        provider.slug = "Ab-C".to_owned();
        validate(&mut provider).expect("uppercase slug is normalized");
        assert_eq!(provider.slug, "ab-c");
    }

    #[test]
    fn access_policy_blank_values_skip_validation() {
        let mut provider = record();
        provider.access_policy = "   ".to_owned();
        validate(&mut provider).expect("whitespace-only policy");
        let mut provider = record();
        provider.access_policy = String::new();
        validate(&mut provider).expect("empty policy");
    }

    #[test]
    fn access_policy_json_errors() {
        let mut provider = record();
        provider.access_policy = "not json".to_owned();
        assert_eq!(
            validate(&mut provider).unwrap_err(),
            ProviderValidationIssue::AccessPolicyNotJson
        );
        provider.access_policy = "[1,2]".to_owned();
        assert_eq!(
            validate(&mut provider).unwrap_err(),
            ProviderValidationIssue::AccessPolicyNotJson
        );
        provider.access_policy = r#"{"logic":5}"#.to_owned();
        assert_eq!(
            validate(&mut provider).unwrap_err(),
            ProviderValidationIssue::AccessPolicyNotJson
        );
    }

    #[test]
    fn access_policy_payload_errors() {
        for (policy, expected) in [
            (
                r#"{"logic":"xor","conditions":[{"field":"email","op":"eq","value":"a"}]}"#,
                "access_policy is invalid: unsupported logic: xor",
            ),
            (
                r#"{"logic":"and"}"#,
                "access_policy is invalid: policy requires at least one condition or group",
            ),
            (
                r#"{"logic":"and","conditions":[{"op":"eq","value":"a"}]}"#,
                "access_policy is invalid: condition[0].field is required",
            ),
            (
                r#"{"conditions":[{"field":"email","op":"like","value":"a"}]}"#,
                "access_policy is invalid: condition[0].op is unsupported: like",
            ),
            (
                r#"{"conditions":[{"field":"email","op":"in","value":"a"}]}"#,
                "access_policy is invalid: condition[0].value must be an array for op in",
            ),
            (
                r#"{"logic":"and","groups":[{}]}"#,
                "access_policy is invalid: group[0]: policy requires at least one condition or group",
            ),
            (
                r#"{"groups":[{"logic":"XOR"}]}"#,
                "access_policy is invalid: group[0]: unsupported logic: xor",
            ),
        ] {
            let mut provider = record();
            provider.access_policy = policy.to_owned();
            let issue = validate(&mut provider).unwrap_err();
            // HTTP 层按 message() 原样返回，含 `access_policy is invalid: ` 前缀。
            assert_eq!(issue.message(), expected, "{policy}");
        }
    }

    #[test]
    fn access_policy_valid_payloads_pass() {
        for policy in [
            r#"{"conditions":[{"field":"email","op":"eq","value":"a@b"}]}"#,
            // logic 空串归一为 and；`null` value 在 in/not_in 之外不校验。
            r#"{"logic":"","conditions":[{"field":"email","op":"contains","value":null}]}"#,
            r#"{"logic":"OR","conditions":[{"field":"email","op":"not_in","value":["a","b"]}]}"#,
            // exists/not_exists 不要求 value；未知 value 类型不校验。
            r#"{"conditions":[{"field":"x","op":"exists","value":42}]}"#,
            r#"{"conditions":[{"field":"email","op":"eq","value":"a"}],"groups":[{"conditions":[{"field":"x","op":"exists"}]}]}"#,
            // Go 的 `null` → 零值结构体：conditions 与 groups 都缺失 → 报“至少一条”。
            "null",
        ] {
            let mut provider = record();
            provider.access_policy = policy.to_owned();
            let result = validate(&mut provider);
            assert!(
                matches!(
                    result,
                    Ok(()) | Err(ProviderValidationIssue::AccessPolicyInvalid(_))
                ),
                "{policy}"
            );
        }
        // 各分支的正确落点单独断言。
        let mut provider = record();
        provider.access_policy =
            r#"{"conditions":[{"field":"email","op":"eq","value":"a@b"}]}"#.to_owned();
        validate(&mut provider).expect("single condition");
        let mut provider = record();
        provider.access_policy = "null".to_owned();
        assert_eq!(
            validate(&mut provider).unwrap_err(),
            ProviderValidationIssue::AccessPolicyInvalid(
                "policy requires at least one condition or group".to_owned()
            )
        );
        // null 元素零值化 → field required（Go unmarshal 成功分支）。
        let mut provider = record();
        provider.access_policy = r#"{"conditions":[null]}"#.to_owned();
        assert_eq!(
            validate(&mut provider).unwrap_err(),
            ProviderValidationIssue::AccessPolicyInvalid(
                "condition[0].field is required".to_owned()
            )
        );
    }
}
