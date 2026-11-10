//! 渠道基础 CRUD 的仓储层：`channels` 行读写与 `abilities` 行联动。
//!
//! Go 参考（`/root/newapi/apps/api/internal/catalog`）：
//! - `store_channel.go`（`Channel` 记录、列表/搜索/分页/标签聚合、增删改）
//! - `store_ability.go`（`AddAbilities` / `UpdateAbilities` / 按渠道删除能力行）
//! - `transport/handler/handle_channel.go` 的 SQL 谓词（分组 LIKE、状态/类型
//!   过滤、搜索的 `(id OR name OR key OR base_url) AND models`）
//!
//! 与已有 `crate::abilities`（分组→模型只读投影）的分工：本模块拥有
//! `channels` 表的全部写路径与 `abilities` 表的**渠道维度**写路径（创建、
//! 重建、随渠道删除）；`crate::abilities` 保持只读，两者不共享可变状态。
//!
//! 已知范围裁剪（后续切片接入）：
//! - `MutateGatewayRouting` 的网关路由版本号不在此实现（catalog 尚无该机制），
//!   事务边界保持 Go 的“渠道行 + 能力行同事务提交”语义。
//! - `SyncChannelModelRoutesWithTx`（`channel_model_routes`）与
//!   `deleteUnitHealth*`（`channel_model_health`）属于路由/健康子域，本切片
//!   不触碰这两张表。
//! - `InitChannelCache` 等渠道缓存刷新没有 Rust 对应物（缓存属于后续切片）。
//!
//! 两个后端共用 `$N` 占位符（sqlx-sqlite 与 sqlx-postgres 均接受），与
//! `identity/src/oauth_bindings.rs` 的约定一致；事务内的写路径与行解码用
//! 内联宏在两个驱动上各展开一次，避免跨驱动的泛型边界样板。

use std::collections::{BTreeMap, HashSet};

use newapi_storage::Database;
use serde::{Deserialize, Serialize};
use sqlx::Row;

/// Go `common.ChannelStatusEnabled`（`constants.go:257`）。
pub const CHANNEL_STATUS_ENABLED: i64 = 1;
/// Go `common.ChannelStatusManuallyDisabled`（`constants.go:258`）。
pub const CHANNEL_STATUS_MANUALLY_DISABLED: i64 = 2;
/// Go `common.ChannelStatusAutoDisabled`（`constants.go:259`）。
pub const CHANNEL_STATUS_AUTO_DISABLED: i64 = 3;

/// Go `constant.ChannelTypeVertexAi`（`constant/channel.go`）。
pub const CHANNEL_TYPE_VERTEX_AI: i64 = 41;
/// Go `constant.ChannelTypeCodex`。
pub const CHANNEL_TYPE_CODEX: i64 = 57;
/// Go `constant.ChannelTypeAdvancedCustom`。
pub const CHANNEL_TYPE_ADVANCED_CUSTOM: i64 = 58;
/// Go `constant.ChannelTypeNewAPI`。
pub const CHANNEL_TYPE_NEW_API: i64 = 60;

/// 渠道密钥列在列表/搜索/详情路径被 Go `Omit("key")` 省略；JSON tag 无
/// omitempty，序列化时仍是空字符串。本仓储用空串表达同一“未读取”状态。
pub const MASKED_CHANNEL_KEY: &str = "";

/// Go `channelpkg.ChannelInfo`（`store_channel.go:65-73`）。
///
/// `multi_key_disabled_reason` / `multi_key_disabled_time` 带 omitempty，
/// 其余字段始终序列化（`multi_key_status_list` 为 nil 时输出 null）。
/// map 的整数键序列化为 JSON 字符串键（Go `map[int]int` 的行为）。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelInfo {
    pub is_multi_key: bool,
    pub multi_key_size: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multi_key_status_list: Option<BTreeMap<i64, i64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multi_key_disabled_reason: Option<BTreeMap<i64, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multi_key_disabled_time: Option<BTreeMap<i64, i64>>,
    pub multi_key_polling_index: i64,
    pub multi_key_mode: String,
}

/// `channels` 行的读视图。`key` 仅在按 id 全量读（`with_key = true`）与
/// 更新后重载时填充，其余查询省略该列，与 Go `Omit("key")` 一致。
#[derive(Clone, Debug, PartialEq)]
pub struct ChannelRow {
    pub id: i64,
    /// 列名 `type`。
    pub channel_type: i64,
    pub key: String,
    pub openai_organization: Option<String>,
    pub test_model: Option<String>,
    pub status: i64,
    pub name: String,
    pub created_time: i64,
    pub test_time: i64,
    pub response_time: i64,
    pub base_url: Option<String>,
    pub other: String,
    pub balance: f64,
    pub balance_updated_time: i64,
    pub models: String,
    /// 列名 `group`。
    pub group: String,
    pub used_quota: i64,
    pub model_mapping: Option<String>,
    pub status_code_mapping: Option<String>,
    pub auto_ban: Option<i64>,
    pub other_info: String,
    pub tag: Option<String>,
    pub setting: Option<String>,
    pub param_override: Option<String>,
    pub header_override: Option<String>,
    pub remark: Option<String>,
    pub channel_info: ChannelInfo,
    /// 列名 `settings`（API 字段名同为 `settings`）。
    pub settings: String,
}

/// `channel_info` 列解析。空串视为默认信息（历史行可能存空串）；
/// 非法 JSON 按查询错误上抛，对齐 Go `ChannelInfo.Scan` 传播解析失败。
fn parse_channel_info(json: &str) -> Result<ChannelInfo, sqlx::Error> {
    if json.is_empty() {
        return Ok(ChannelInfo::default());
    }
    serde_json::from_str(json)
        .map_err(|_| sqlx::Error::Decode("channel_info is not valid JSON".into()))
}

/// 行解码：`key` 列可能不在 SELECT 列表中（对应 `Omit("key")`），
/// 缺列时回退空串而不是报错。在两个驱动的具现行类型上各展开一次。
macro_rules! channel_row {
    ($row:expr) => {{
        let row = $row;
        let info_json: String = row.try_get("channel_info")?;
        ChannelRow {
            id: row.try_get::<i64, _>("id")?,
            channel_type: row.try_get::<i64, _>("type")?,
            key: row.try_get::<String, _>("key").unwrap_or_default(),
            openai_organization: row.try_get::<Option<String>, _>("openai_organization")?,
            test_model: row.try_get::<Option<String>, _>("test_model")?,
            status: row.try_get::<i64, _>("status")?,
            name: row.try_get::<String, _>("name")?,
            created_time: row.try_get::<i64, _>("created_time")?,
            test_time: row.try_get::<i64, _>("test_time")?,
            response_time: row.try_get::<i64, _>("response_time")?,
            base_url: row.try_get::<Option<String>, _>("base_url")?,
            other: row.try_get::<String, _>("other")?,
            balance: row.try_get::<f64, _>("balance")?,
            balance_updated_time: row.try_get::<i64, _>("balance_updated_time")?,
            models: row.try_get::<String, _>("models")?,
            group: row.try_get::<String, _>("group")?,
            used_quota: row.try_get::<i64, _>("used_quota")?,
            model_mapping: row.try_get::<Option<String>, _>("model_mapping")?,
            status_code_mapping: row.try_get::<Option<String>, _>("status_code_mapping")?,
            auto_ban: row.try_get::<Option<i64>, _>("auto_ban")?,
            other_info: row.try_get::<String, _>("other_info")?,
            tag: row.try_get::<Option<String>, _>("tag")?,
            setting: row.try_get::<Option<String>, _>("setting")?,
            param_override: row.try_get::<Option<String>, _>("param_override")?,
            header_override: row.try_get::<Option<String>, _>("header_override")?,
            remark: row.try_get::<Option<String>, _>("remark")?,
            channel_info: parse_channel_info(&info_json)?,
            settings: row.try_get::<String, _>("settings")?,
        }
    }};
}

/// 两驱动分别展开同一段查询体；`$pool` 在两个分支里分别是 `&SqlitePool`
/// 与 `&PgPool`（复用 `identity/oauth_bindings.rs` 的既有约定）。
macro_rules! backend {
    ($db:expr, $pool:ident, $body:block) => {
        match $db {
            Database::Sqlite($pool) => $body,
            Database::Postgres($pool) => $body,
        }
    };
}

/// 事务体展开：两个驱动各一份，失败回滚（回滚结果被忽略，保留原始错误）。
macro_rules! transactional {
    ($db:expr, $tx:ident, $body:block) => {
        match $db {
            Database::Sqlite(pool) => {
                let mut $tx = pool.begin().await?;
                let outcome: Result<_, sqlx::Error> = async { $body }.await;
                match outcome {
                    Ok(value) => {
                        $tx.commit().await?;
                        Ok(value)
                    }
                    Err(error) => {
                        let _ = $tx.rollback().await;
                        Err(error)
                    }
                }
            }
            Database::Postgres(pool) => {
                let mut $tx = pool.begin().await?;
                let outcome: Result<_, sqlx::Error> = async { $body }.await;
                match outcome {
                    Ok(value) => {
                        $tx.commit().await?;
                        Ok(value)
                    }
                    Err(error) => {
                        let _ = $tx.rollback().await;
                        Err(error)
                    }
                }
            }
        }
    };
}

/// Go `parseStatusFilter`（`handle_channel.go:59-68`）：`enabled`/`1` 只取
/// 启用，`disabled`/`0` 取全部非启用状态，其余值（含缺省）不过滤。
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum StatusFilter {
    #[default]
    All,
    Enabled,
    Disabled,
}

/// Go `NormalizeChannelGroupFilter`：trim 后空串、`all`、`null`（忽略大小写）
/// 视为不过滤。
pub fn normalize_group_filter(group: &str) -> Option<String> {
    let trimmed = group.trim();
    if trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("all")
        || trimmed.eq_ignore_ascii_case("null")
    {
        return None;
    }
    Some(trimmed.to_owned())
}

/// Go `channelGroupFilterPattern`：`!`/`%`/`_` 前置 `!` 转义后拼成
/// `%,group,%`（`ESCAPE '!'`）。
fn group_like_pattern(group: &str) -> String {
    let mut pattern = String::with_capacity(group.len() + 4);
    for byte in group.bytes() {
        match byte {
            b'!' => pattern.push_str("!!"),
            b'%' => pattern.push_str("!%"),
            b'_' => pattern.push_str("!_"),
            _ => pattern.push(byte as char),
        }
    }
    format!("%,{pattern},%")
}

/// 渠道列表过滤条件（Go `buildChannelListQuery` 的组/状态/类型三条件）。
/// `channel_type` 对应 Go 的 `typeFilter >= 0` 语义。
#[derive(Clone, Debug, Default)]
pub struct ChannelListFilter {
    /// 归一化后的分组名；`None` 不过滤。
    pub group: Option<String>,
    pub status: StatusFilter,
    /// `Some(t)` 追加 `type = t`；`None` 对应 Go 的 `-1`（不过滤）。
    pub channel_type: Option<i64>,
}

impl ChannelListFilter {
    fn has_conditions(&self) -> bool {
        self.group.is_some() || self.status != StatusFilter::All || self.channel_type.is_some()
    }

    /// 在 `WHERE` 之后追加过滤片段；`leading_and` 表示前面已有条件，
    /// 第一个条件前不再重复 `AND`（两后端共用，`push_bind` 自动编号占位符）。
    fn push_where<DB: sqlx::Database>(&self, query: &mut sqlx::QueryBuilder<DB>, leading_and: bool)
    where
        i64: sqlx::Type<DB> + for<'t> sqlx::Encode<'t, DB>,
        String: sqlx::Type<DB> + for<'t> sqlx::Encode<'t, DB>,
    {
        let mut pushed = false;
        if let Some(group) = self.group.as_deref() {
            if leading_and || pushed {
                query.push(" AND ");
            }
            query.push("(',' || \"group\" || ',') LIKE ");
            query.push_bind(group_like_pattern(group));
            query.push(" ESCAPE '!'");
            pushed = true;
        }
        match self.status {
            StatusFilter::Enabled => {
                if leading_and || pushed {
                    query.push(" AND ");
                }
                query.push("status = ");
                query.push_bind(CHANNEL_STATUS_ENABLED);
            }
            StatusFilter::Disabled => {
                if leading_and || pushed {
                    query.push(" AND ");
                }
                query.push("status <> ");
                query.push_bind(CHANNEL_STATUS_ENABLED);
            }
            StatusFilter::All => {}
        }
        if let Some(channel_type) = self.channel_type {
            if leading_and || pushed {
                query.push(" AND ");
            }
            query.push("\"type\" = ");
            query.push_bind(channel_type);
        }
    }
}

/// Go `channelpkg.ChannelSortOptions`：可排序列与方向；解析失败或未提供时
/// 一律回落到 `id desc`（`NewChannelSortOptions` 与 `Apply` 的最终分支）。
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ChannelSort {
    #[default]
    IdDesc,
    IdAsc,
    NameDesc,
    NameAsc,
    BalanceDesc,
    BalanceAsc,
    ResponseTimeDesc,
    ResponseTimeAsc,
    TestTimeDesc,
    TestTimeAsc,
}

impl ChannelSort {
    fn order_sql(self) -> &'static str {
        match self {
            Self::IdDesc => "id DESC",
            Self::IdAsc => "id ASC",
            Self::NameDesc => "name DESC",
            Self::NameAsc => "name ASC",
            Self::BalanceDesc => "balance DESC",
            Self::BalanceAsc => "balance ASC",
            Self::ResponseTimeDesc => "response_time DESC",
            Self::ResponseTimeAsc => "response_time ASC",
            Self::TestTimeDesc => "test_time DESC",
            Self::TestTimeAsc => "test_time ASC",
        }
    }
}

/// Go `NewChannelSortOptions` + `ChannelSortOptions::Apply`：未知 `sort_by`
/// 一律按默认 `id desc` 处理（`id_sort` 为真同样落在 `id desc`，合并回落）；
/// 合法 `sort_by` 配 `asc` 升序、其余降序。
pub fn resolve_sort(sort_by: &str, sort_order: &str) -> ChannelSort {
    let by = sort_by.trim().to_ascii_lowercase();
    let order = sort_order.trim().to_ascii_lowercase();
    let desc = match by.as_str() {
        "id" | "name" | "balance" | "response_time" | "test_time" => order != "asc",
        _ => return ChannelSort::IdDesc,
    };
    match (by.as_str(), desc) {
        ("id", false) => ChannelSort::IdAsc,
        ("id", true) => ChannelSort::IdDesc,
        ("name", false) => ChannelSort::NameAsc,
        ("name", true) => ChannelSort::NameDesc,
        ("balance", false) => ChannelSort::BalanceAsc,
        ("balance", true) => ChannelSort::BalanceDesc,
        ("response_time", false) => ChannelSort::ResponseTimeAsc,
        ("response_time", true) => ChannelSort::ResponseTimeDesc,
        ("test_time", false) => ChannelSort::TestTimeAsc,
        _ => ChannelSort::TestTimeDesc,
    }
}

/// Go `strconv.ParseBool`：接受 1/0 与大小写 true/false 变体，其余一律视为
/// false（Go 的第二个返回值被忽略）。
pub fn parse_go_bool(value: Option<&str>) -> bool {
    match value.map(str::trim) {
        Some("1" | "t" | "T" | "TRUE" | "true" | "True") => true,
        Some("0" | "f" | "F" | "FALSE" | "false" | "False") => false,
        _ => false,
    }
}

/// Go `common.String2Int`：解析失败回零（搜索的 `id = ?` 参数）。
pub fn string_to_i64(value: &str) -> i64 {
    value.trim().parse::<i64>().unwrap_or(0)
}

/// 列表/搜索的 SELECT 列清单（不含 `key`）：Go `Omit("key")`。
const CHANNEL_COLUMNS_NO_KEY: &str = "id, \"type\", openai_organization, test_model, status, name, \
     created_time, test_time, response_time, base_url, other, balance, balance_updated_time, \
     models, \"group\", used_quota, model_mapping, status_code_mapping, auto_ban, other_info, \
     tag, setting, param_override, header_override, remark, channel_info, settings";

/// 全量 SELECT 列清单（含 `key`）：按 id 读取与更新后重载使用。
const CHANNEL_COLUMNS_ALL: &str = "id, \"type\", \"key\", openai_organization, test_model, status, \
     name, created_time, test_time, response_time, base_url, other, balance, balance_updated_time, \
     models, \"group\", used_quota, model_mapping, status_code_mapping, auto_ban, other_info, \
     tag, setting, param_override, header_override, remark, channel_info, settings";

/// INSERT 的列清单。`test_time` / `response_time` / `balance` /
/// `balance_updated_time` 无 gorm default，零值显式写入；`base_url` /
/// `status_code_mapping` / `auto_ban` nil 与 `used_quota` 零值由
/// [`ChannelInput::into_new_channel`] 预先解析为列默认的等价值
/// （''、''、1、0），与 GORM 省略零值 default 字段的写法等价。
const CHANNEL_INSERT_COLUMNS: &str = "\"type\", \"key\", openai_organization, test_model, status, \
     name, created_time, test_time, response_time, base_url, other, balance, \
     balance_updated_time, models, \"group\", used_quota, model_mapping, status_code_mapping, \
     auto_ban, other_info, tag, setting, param_override, header_override, remark, channel_info, \
     settings";

/// Go `channelpkg.Channel` 的 JSON 绑定形态（创建/更新请求体共用）。
///
/// 所有字段可选：Go `json.Unmarshal` 对缺失与 `null` 同样给零值，只有类型
/// 不匹配才是错误，Option 字段精确复现这一行为（缺失与 `null` 都是 `None`，
/// 即 Go 的零值/nil 指针）。`used_quota_display` 是 Go 的 `gorm:"-"`
/// 计算字段：写入路径完全忽略它的值，只保留类型校验。
#[derive(Clone, Debug, Default, Deserialize)]
pub struct ChannelInput {
    pub id: Option<i64>,
    #[serde(rename = "type")]
    pub channel_type: Option<i64>,
    pub key: Option<String>,
    pub openai_organization: Option<String>,
    pub test_model: Option<String>,
    pub status: Option<i64>,
    pub name: Option<String>,
    pub created_time: Option<i64>,
    pub test_time: Option<i64>,
    pub response_time: Option<i64>,
    pub base_url: Option<String>,
    pub other: Option<String>,
    pub balance: Option<f64>,
    pub balance_updated_time: Option<i64>,
    pub models: Option<String>,
    pub group: Option<String>,
    pub used_quota: Option<i64>,
    #[allow(dead_code)]
    pub used_quota_display: Option<f64>,
    pub model_mapping: Option<String>,
    pub status_code_mapping: Option<String>,
    pub auto_ban: Option<i64>,
    pub other_info: Option<String>,
    pub tag: Option<String>,
    pub setting: Option<String>,
    pub param_override: Option<String>,
    pub header_override: Option<String>,
    pub remark: Option<String>,
    /// `channel_info` 在更新路径始终被 origin 覆盖，只参与类型校验。
    #[allow(dead_code)]
    pub channel_info: Option<ChannelInfo>,
    pub settings: Option<String>,
}

/// 创建时写入的一行（已按 GORM default 规则解析：`status` 0→1、`group`
/// 空→`default`、`base_url`/`status_code_mapping` nil→`''`、`auto_ban`
/// nil→1）。
#[derive(Clone, Debug)]
pub struct NewChannel {
    pub channel_type: i64,
    pub key: String,
    pub openai_organization: Option<String>,
    pub test_model: Option<String>,
    pub status: i64,
    pub name: String,
    pub created_time: i64,
    pub base_url: String,
    pub other: String,
    pub models: String,
    pub group: String,
    pub model_mapping: Option<String>,
    pub status_code_mapping: String,
    pub auto_ban: i64,
    pub other_info: String,
    pub tag: Option<String>,
    pub setting: Option<String>,
    pub param_override: Option<String>,
    pub header_override: Option<String>,
    pub remark: Option<String>,
    pub channel_info: ChannelInfo,
    pub settings: String,
}

/// 更新时写入的非零字段集合。
///
/// Go `tx.Model(channel).Updates(channel)` 只写**非零值**字段：普通字符串
/// 字段空串跳过（Go 零值）、`*T` 指 nil 跳过（指向零值的指针是有效写入）、
/// 整型 0 跳过。`None` 即这里的“跳过”；只有**指针**列字段的 `Some("")`
/// 是显式写入空串（普通字符串列的 `Some("")` 与 `None` 等价）。
#[derive(Clone, Debug, Default)]
pub struct ChannelPatch {
    pub channel_type: Option<i64>,
    pub key: Option<String>,
    pub openai_organization: Option<String>,
    pub test_model: Option<String>,
    pub base_url: Option<String>,
    pub name: Option<String>,
    pub other: Option<String>,
    pub models: Option<String>,
    pub group: Option<String>,
    pub model_mapping: Option<String>,
    pub status_code_mapping: Option<String>,
    pub auto_ban: Option<i64>,
    pub other_info: Option<String>,
    pub tag: Option<String>,
    pub setting: Option<String>,
    pub param_override: Option<String>,
    pub header_override: Option<String>,
    pub remark: Option<String>,
    pub settings: Option<String>,
}

impl ChannelInput {
    /// GORM `Create` 写列前的默认值解析。
    pub fn into_new_channel(self, created_time: i64, channel_info: ChannelInfo) -> NewChannel {
        let group = self.group.unwrap_or_default();
        NewChannel {
            channel_type: self.channel_type.unwrap_or(0),
            key: self.key.unwrap_or_default(),
            openai_organization: self.openai_organization,
            test_model: self.test_model,
            // gorm "default:1"：创建时不写 0，列默认把它变成 1。
            status: match self.status.unwrap_or(0) {
                0 => CHANNEL_STATUS_ENABLED,
                value => value,
            },
            name: self.name.unwrap_or_default(),
            created_time,
            base_url: self.base_url.unwrap_or_default(),
            other: self.other.unwrap_or_default(),
            models: self.models.unwrap_or_default(),
            // gorm "default:'default'"：空串走列默认。
            group: if group.is_empty() {
                "default".to_owned()
            } else {
                group
            },
            model_mapping: self.model_mapping,
            status_code_mapping: self.status_code_mapping.unwrap_or_default(),
            // gorm "default:1"：nil 指针走列默认。
            auto_ban: self.auto_ban.unwrap_or(1),
            other_info: self.other_info.unwrap_or_default(),
            tag: self.tag,
            setting: self.setting,
            param_override: self.param_override,
            header_override: self.header_override,
            remark: self.remark,
            channel_info,
            settings: self.settings.unwrap_or_default(),
        }
    }

    /// GORM `Updates(channel)` 的非零值投影。只读字段（created_time、
    /// test_time、response_time、balance、balance_updated_time、used_quota）
    /// 从不进入写集，等价于 Go `clearChannelReadOnlyFields` 的净效果。
    pub fn patch(&self) -> ChannelPatch {
        ChannelPatch {
            channel_type: self.channel_type.filter(|&value| value != 0),
            key: self.key.clone().filter(|value| !value.is_empty()),
            openai_organization: self.openai_organization.clone(),
            test_model: self.test_model.clone(),
            base_url: self.base_url.clone(),
            name: self.name.clone().filter(|value| !value.is_empty()),
            other: self.other.clone().filter(|value| !value.is_empty()),
            models: self.models.clone().filter(|value| !value.is_empty()),
            group: self.group.clone().filter(|value| !value.is_empty()),
            model_mapping: self.model_mapping.clone(),
            status_code_mapping: self.status_code_mapping.clone(),
            auto_ban: self.auto_ban,
            other_info: self.other_info.clone().filter(|value| !value.is_empty()),
            tag: self.tag.clone(),
            setting: self.setting.clone(),
            param_override: self.param_override.clone(),
            header_override: self.header_override.clone(),
            remark: self.remark.clone(),
            settings: self.settings.clone().filter(|value| !value.is_empty()),
        }
    }
}

/// GORM `Updates` 对结构体字段的处理：零值 `ChannelInfo` 被跳过，
/// 非零结构体才写 `channel_info` 列。
pub fn patch_channel_info(info: &ChannelInfo) -> Option<ChannelInfo> {
    (*info != ChannelInfo::default()).then(|| info.clone())
}

/// `abilities` 行的笛卡尔积（Go `AddAbilities` / `UpdateAbilities` 共用）：
/// `models` 与 `group` 都按 `,` 切分（不做 trim、不做空过滤，空串产生
/// `[""]`），按 `(group, model)` 去重；是否启用由调用方的 `enabled` 闭包
/// 决定（创建取渠道状态；重建额外保留被隔离的模型）。
fn ability_rows(
    models: &str,
    group: &str,
    enabled: impl Fn(&str) -> bool,
) -> Vec<(String, String, bool)> {
    let mut seen = HashSet::new();
    let mut rows = Vec::new();
    for model in models.split(',') {
        for group in group.split(',') {
            let key = (group.to_owned(), model.to_owned());
            if seen.insert(key.clone()) {
                rows.push((key.0, key.1, enabled(model)));
            }
        }
    }
    rows
}

/// INSERT 一行渠道并取回自增 id（两后端均支持 `RETURNING`）。
macro_rules! insert_channel {
    ($tx:expr, $channel:expr) => {{
        let channel: &NewChannel = $channel;
        let mut query = sqlx::QueryBuilder::new("INSERT INTO channels (");
        query.push(CHANNEL_INSERT_COLUMNS);
        query.push(") VALUES (");
        query.push_bind(channel.channel_type);
        query.push(", ");
        query.push_bind(channel.key.clone());
        query.push(", ");
        query.push_bind(channel.openai_organization.clone());
        query.push(", ");
        query.push_bind(channel.test_model.clone());
        query.push(", ");
        query.push_bind(channel.status);
        query.push(", ");
        query.push_bind(channel.name.clone());
        query.push(", ");
        query.push_bind(channel.created_time);
        query.push(", ");
        query.push_bind(0i64);
        query.push(", ");
        query.push_bind(0i64);
        query.push(", ");
        query.push_bind(channel.base_url.clone());
        query.push(", ");
        query.push_bind(channel.other.clone());
        query.push(", ");
        query.push_bind(0.0f64);
        query.push(", ");
        query.push_bind(0i64);
        query.push(", ");
        query.push_bind(channel.models.clone());
        query.push(", ");
        query.push_bind(channel.group.clone());
        query.push(", ");
        query.push_bind(0i64);
        query.push(", ");
        query.push_bind(channel.model_mapping.clone());
        query.push(", ");
        query.push_bind(channel.status_code_mapping.clone());
        query.push(", ");
        query.push_bind(channel.auto_ban);
        query.push(", ");
        query.push_bind(channel.other_info.clone());
        query.push(", ");
        query.push_bind(channel.tag.clone());
        query.push(", ");
        query.push_bind(channel.setting.clone());
        query.push(", ");
        query.push_bind(channel.param_override.clone());
        query.push(", ");
        query.push_bind(channel.header_override.clone());
        query.push(", ");
        query.push_bind(channel.remark.clone());
        query.push(", ");
        query.push_bind(serde_json::to_string(&channel.channel_info).unwrap_or_default());
        query.push(", ");
        query.push_bind(channel.settings.clone());
        query.push(") RETURNING id");
        let row = query.build().fetch_one(&mut *$tx).await?;
        row.try_get::<i64, _>("id")
    }};
}

/// Go `Channel.AddAbilities`：按 50 一批 `ON CONFLICT DO NOTHING` 写入。
macro_rules! add_abilities {
    ($tx:expr, $channel_id:expr, $models:expr, $group:expr, $enabled:expr, $tag:expr) => {{
        let channel_id: i64 = $channel_id;
        let models: &str = $models;
        let group: &str = $group;
        let tag: &Option<String> = $tag;
        let rows = ability_rows(models, group, $enabled);
        for chunk in rows.chunks(50) {
            if chunk.is_empty() {
                continue;
            }
            let mut query = sqlx::QueryBuilder::new(
                "INSERT INTO abilities (\"group\", model, channel_id, enabled, tag) VALUES ",
            );
            for (index, (group, model, enabled)) in chunk.iter().enumerate() {
                if index > 0 {
                    query.push(", ");
                }
                query.push("(");
                query.push_bind(group.clone());
                query.push(", ");
                query.push_bind(model.clone());
                query.push(", ");
                query.push_bind(channel_id);
                query.push(", ");
                query.push_bind(*enabled);
                query.push(", ");
                query.push_bind(tag.clone());
                query.push(")");
            }
            query.push(" ON CONFLICT DO NOTHING");
            query.build().execute(&mut *$tx).await?;
        }
        Ok::<(), sqlx::Error>(())
    }};
}

/// Go `Channel.UpdateAbilities`：先记下被模型级隔离（`enabled = false`）的
/// 模型，删除该渠道全部能力行，再按当前 models × groups 重建；重建行默认
/// 随渠道状态，被隔离的模型保持禁用。
macro_rules! rebuild_abilities {
    ($tx:expr, $channel:expr) => {{
        let channel: &ChannelRow = $channel;
        let mut isolated: HashSet<String> = HashSet::new();
        let rows = sqlx::query(
            "SELECT DISTINCT model FROM abilities \
             WHERE channel_id = $1 AND enabled = false",
        )
        .bind(channel.id)
        .fetch_all(&mut *$tx)
        .await?;
        for row in &rows {
            isolated.insert(row.try_get::<String, _>("model")?);
        }
        sqlx::query("DELETE FROM abilities WHERE channel_id = $1")
            .bind(channel.id)
            .execute(&mut *$tx)
            .await?;
        let id = channel.id;
        let models = channel.models.clone();
        let group = channel.group.clone();
        let tag = channel.tag.clone();
        add_abilities!(
            $tx,
            id,
            &models,
            &group,
            |model: &str| channel.status == CHANNEL_STATUS_ENABLED && !isolated.contains(model),
            &tag
        )
    }};
}

/// Go `tx.Model(channel).Updates(channel)`：只写非零字段。普通字符串字段
/// （`key`/`name`/`other`/`models`/`group`/`other_info`/`settings`）的空串
/// 与 `None` 同样跳过（Go 的零值语义）；**指针**列（`base_url`/`tag` 等）
/// 的 `Some("")` 才是显式写入空串。`channel_info` 仅在非零时写入；没有
/// 可写字段时跳过 UPDATE，直接进入重载（等价于 GORM 空更新集的空操作）。
macro_rules! apply_patch {
    ($tx:expr, $id:expr, $patch:expr, $info:expr) => {{
        let patch: &ChannelPatch = $patch;
        let info: Option<&ChannelInfo> = $info;
        let mut query = sqlx::QueryBuilder::new("UPDATE channels SET ");
        let mut pending = false;
        if let Some(value) = patch.channel_type {
            if pending {
                query.push(", ");
            }
            pending = true;
            query.push("\"type\" = ");
            query.push_bind(value);
        }
        if let Some(value) = patch.key.clone().filter(|value: &String| !value.is_empty()) {
            if pending {
                query.push(", ");
            }
            pending = true;
            query.push("\"key\" = ");
            query.push_bind(value);
        }
        if let Some(value) = patch.openai_organization.clone() {
            if pending {
                query.push(", ");
            }
            pending = true;
            query.push("openai_organization = ");
            query.push_bind(value);
        }
        if let Some(value) = patch.test_model.clone() {
            if pending {
                query.push(", ");
            }
            pending = true;
            query.push("test_model = ");
            query.push_bind(value);
        }
        if let Some(value) = patch.base_url.clone() {
            if pending {
                query.push(", ");
            }
            pending = true;
            query.push("base_url = ");
            query.push_bind(value);
        }
        if let Some(value) = patch
            .name
            .clone()
            .filter(|value: &String| !value.is_empty())
        {
            if pending {
                query.push(", ");
            }
            pending = true;
            query.push("name = ");
            query.push_bind(value);
        }
        if let Some(value) = patch
            .other
            .clone()
            .filter(|value: &String| !value.is_empty())
        {
            if pending {
                query.push(", ");
            }
            pending = true;
            query.push("other = ");
            query.push_bind(value);
        }
        if let Some(value) = patch
            .models
            .clone()
            .filter(|value: &String| !value.is_empty())
        {
            if pending {
                query.push(", ");
            }
            pending = true;
            query.push("models = ");
            query.push_bind(value);
        }
        if let Some(value) = patch
            .group
            .clone()
            .filter(|value: &String| !value.is_empty())
        {
            if pending {
                query.push(", ");
            }
            pending = true;
            query.push("\"group\" = ");
            query.push_bind(value);
        }
        if let Some(value) = patch.model_mapping.clone() {
            if pending {
                query.push(", ");
            }
            pending = true;
            query.push("model_mapping = ");
            query.push_bind(value);
        }
        if let Some(value) = patch.status_code_mapping.clone() {
            if pending {
                query.push(", ");
            }
            pending = true;
            query.push("status_code_mapping = ");
            query.push_bind(value);
        }
        if let Some(value) = patch.auto_ban {
            if pending {
                query.push(", ");
            }
            pending = true;
            query.push("auto_ban = ");
            query.push_bind(value);
        }
        if let Some(value) = patch
            .other_info
            .clone()
            .filter(|value: &String| !value.is_empty())
        {
            if pending {
                query.push(", ");
            }
            pending = true;
            query.push("other_info = ");
            query.push_bind(value);
        }
        if let Some(value) = patch.tag.clone() {
            if pending {
                query.push(", ");
            }
            pending = true;
            query.push("tag = ");
            query.push_bind(value);
        }
        if let Some(value) = patch.setting.clone() {
            if pending {
                query.push(", ");
            }
            pending = true;
            query.push("setting = ");
            query.push_bind(value);
        }
        if let Some(value) = patch.param_override.clone() {
            if pending {
                query.push(", ");
            }
            pending = true;
            query.push("param_override = ");
            query.push_bind(value);
        }
        if let Some(value) = patch.header_override.clone() {
            if pending {
                query.push(", ");
            }
            pending = true;
            query.push("header_override = ");
            query.push_bind(value);
        }
        if let Some(value) = patch.remark.clone() {
            if pending {
                query.push(", ");
            }
            pending = true;
            query.push("remark = ");
            query.push_bind(value);
        }
        if let Some(value) = patch
            .settings
            .clone()
            .filter(|value: &String| !value.is_empty())
        {
            if pending {
                query.push(", ");
            }
            pending = true;
            query.push("settings = ");
            query.push_bind(value);
        }
        if let Some(info) = info {
            if pending {
                query.push(", ");
            }
            pending = true;
            query.push("channel_info = ");
            query.push_bind(serde_json::to_string(info).unwrap_or_default());
        }
        if pending {
            query.push(" WHERE id = ");
            query.push_bind($id);
            query.build().execute(&mut *$tx).await?;
        }
        Ok::<(), sqlx::Error>(())
    }};
}

/// 更新后按 id 重载整行（含 `key`）：Go `updateWithTx` 的
/// `tx.First(channel, "id = ?", channel.Id)`。
macro_rules! reload_channel {
    ($tx:expr, $id:expr) => {{
        let mut query = sqlx::QueryBuilder::new("SELECT ");
        query.push(CHANNEL_COLUMNS_ALL);
        query.push(" FROM channels WHERE id = ");
        query.push_bind($id);
        let row = query.build().fetch_optional(&mut *$tx).await?;
        match row {
            Some(ref row) => Ok(Some(channel_row!(row))),
            None => Ok::<Option<ChannelRow>, sqlx::Error>(None),
        }
    }};
}

/// 按 id 集合删除（`IN (...)`）；表名与列名由调用方以字面量传入。
macro_rules! delete_in {
    ($tx:expr, $table:expr, $column:expr, $ids:expr) => {{
        let ids: &[i64] = $ids;
        let mut query = sqlx::QueryBuilder::new("DELETE FROM ");
        query.push($table);
        query.push(" WHERE ");
        query.push($column);
        query.push(" IN (");
        for (index, id) in ids.iter().enumerate() {
            if index > 0 {
                query.push(", ");
            }
            query.push_bind(*id);
        }
        query.push(")");
        let result = query.build().execute(&mut *$tx).await?;
        Ok::<i64, sqlx::Error>(result.rows_affected() as i64)
    }};
}

/// 渠道仓储：CRUD 写路径与列表/搜索读路径的 SQL 边界。
#[derive(Clone)]
pub struct ChannelRepository {
    db: Database,
}

impl ChannelRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub fn database(&self) -> &Database {
        &self.db
    }

    /// Go `buildChannelListQuery(...).Count(&total)`。
    pub async fn count(&self, filter: &ChannelListFilter) -> Result<i64, sqlx::Error> {
        backend!(&self.db, pool, {
            let mut query = sqlx::QueryBuilder::new("SELECT COUNT(*) AS total FROM channels");
            if filter.has_conditions() {
                query.push(" WHERE ");
                filter.push_where(&mut query, false);
            }
            let row = query.build().fetch_one(pool).await?;
            Ok(row.try_get::<i64, _>("total")?)
        })
    }

    /// Go `countQuery.Select("type, count(*) as count").Group("type")`：
    /// 类型过滤不参与（Go 固定传 `-1`），按 `type` 分组计数。
    /// Go 的 map 输出无序；这里按 `type` 升序保证响应可复现。
    pub async fn type_counts(
        &self,
        group: &Option<String>,
        status: StatusFilter,
    ) -> Result<Vec<(i64, i64)>, sqlx::Error> {
        let filter = ChannelListFilter {
            group: group.clone(),
            status,
            channel_type: None,
        };
        backend!(&self.db, pool, {
            let mut query =
                sqlx::QueryBuilder::new("SELECT \"type\", COUNT(*) AS count FROM channels");
            if filter.has_conditions() {
                query.push(" WHERE ");
                filter.push_where(&mut query, false);
            }
            query.push(" GROUP BY \"type\" ORDER BY \"type\" ASC");
            let rows = query.build().fetch_all(pool).await?;
            let mut counts = Vec::with_capacity(rows.len());
            for row in &rows {
                counts.push((
                    row.try_get::<i64, _>("type")?,
                    row.try_get::<i64, _>("count")?,
                ));
            }
            Ok(counts)
        })
    }

    /// Go `sortOptions.Apply(...).Limit(pageSize).Offset(startIdx)
    /// .Omit("key").Find(&channelData)`。
    pub async fn list(
        &self,
        filter: &ChannelListFilter,
        sort: ChannelSort,
        offset: i64,
        limit: i64,
    ) -> Result<Vec<ChannelRow>, sqlx::Error> {
        backend!(&self.db, pool, {
            let mut query = sqlx::QueryBuilder::new("SELECT ");
            query.push(CHANNEL_COLUMNS_NO_KEY);
            query.push(" FROM channels");
            if filter.has_conditions() {
                query.push(" WHERE ");
                filter.push_where(&mut query, false);
            }
            query.push(" ORDER BY ");
            query.push(sort.order_sql());
            query.push(" LIMIT ");
            query.push_bind(limit);
            query.push(" OFFSET ");
            query.push_bind(offset);
            let rows = query.build().fetch_all(pool).await?;
            let mut channels = Vec::with_capacity(rows.len());
            for row in &rows {
                channels.push(channel_row!(row));
            }
            Ok(channels)
        })
    }

    /// Go `GetPaginatedChannelTags`：过滤条件之上的 `DISTINCT tag`，按 `tag`
    /// 升序分页（`tag IS NOT NULL AND tag <> ''`）。
    pub async fn tags(
        &self,
        filter: &ChannelListFilter,
        offset: i64,
        limit: i64,
    ) -> Result<Vec<String>, sqlx::Error> {
        backend!(&self.db, pool, {
            let mut query =
                sqlx::QueryBuilder::new("SELECT DISTINCT tag FROM channels WHERE tag IS NOT NULL");
            query.push(" AND tag <> ''");
            if filter.has_conditions() {
                filter.push_where(&mut query, true);
            }
            query.push(" ORDER BY tag ASC LIMIT ");
            query.push_bind(limit);
            query.push(" OFFSET ");
            query.push_bind(offset);
            let rows = query.build().fetch_all(pool).await?;
            let mut tags = Vec::with_capacity(rows.len());
            for row in &rows {
                tags.push(row.try_get::<Option<String>, _>("tag")?.unwrap_or_default());
            }
            Ok(tags)
        })
    }

    /// Go `CountChannelTags`：过滤条件之上的 `COUNT(DISTINCT tag)`。
    pub async fn count_tags(&self, filter: &ChannelListFilter) -> Result<i64, sqlx::Error> {
        backend!(&self.db, pool, {
            let mut query = sqlx::QueryBuilder::new(
                "SELECT COUNT(DISTINCT tag) AS total FROM channels WHERE tag IS NOT NULL",
            );
            query.push(" AND tag <> ''");
            if filter.has_conditions() {
                filter.push_where(&mut query, true);
            }
            let row = query.build().fetch_one(pool).await?;
            Ok(row.try_get::<i64, _>("total")?)
        })
    }

    /// Go 标签模式下的 `buildChannelListQuery(...).Where("tag = ?")`
    /// + `sortOptions.Apply` + `Omit("key")`。
    pub async fn list_by_tag(
        &self,
        filter: &ChannelListFilter,
        tag: &str,
        sort: ChannelSort,
    ) -> Result<Vec<ChannelRow>, sqlx::Error> {
        backend!(&self.db, pool, {
            let mut query = sqlx::QueryBuilder::new("SELECT ");
            query.push(CHANNEL_COLUMNS_NO_KEY);
            query.push(" FROM channels WHERE tag = ");
            query.push_bind(tag);
            if filter.has_conditions() {
                filter.push_where(&mut query, true);
            }
            query.push(" ORDER BY ");
            query.push(sort.order_sql());
            let rows = query.build().fetch_all(pool).await?;
            let mut channels = Vec::with_capacity(rows.len());
            for row in &rows {
                channels.push(channel_row!(row));
            }
            Ok(channels)
        })
    }

    /// Go `SearchTags`（`store_channel.go:1119-1162`）：搜索谓词之上取
    /// `DISTINCT tag`（`tag <> ''` 已排除 NULL），无 `type`/`status` 过滤。
    /// Go 的子查询排序被外层 DISTINCT 消化，无可见顺序；这里按 `tag`
    /// 升序保证响应可复现。
    pub async fn search_tags(
        &self,
        keyword: &str,
        group: &Option<String>,
        model: &str,
    ) -> Result<Vec<String>, sqlx::Error> {
        backend!(&self.db, pool, {
            let mut query =
                sqlx::QueryBuilder::new("SELECT DISTINCT tag FROM channels WHERE tag <> ''");
            query.push(" AND (id = ");
            query.push_bind(string_to_i64(keyword));
            query.push(" OR name LIKE ");
            query.push_bind(format!("%{keyword}%"));
            query.push(" OR \"key\" = ");
            query.push_bind(keyword);
            query.push(" OR base_url LIKE ");
            query.push_bind(format!("%{keyword}%"));
            query.push(") AND models LIKE ");
            query.push_bind(format!("%{model}%"));
            if let Some(group) = group.as_deref() {
                query.push(" AND (',' || \"group\" || ',') LIKE ");
                query.push_bind(group_like_pattern(group));
                query.push(" ESCAPE '!'");
            }
            query.push(" ORDER BY tag ASC");
            let rows = query.build().fetch_all(pool).await?;
            let mut tags = Vec::with_capacity(rows.len());
            for row in &rows {
                tags.push(row.try_get::<Option<String>, _>("tag")?.unwrap_or_default());
            }
            Ok(tags)
        })
    }

    /// Go `SearchChannels`：`(id = ? OR name LIKE ? OR key = ? OR base_url
    /// LIKE ?) AND models LIKE ?`，叠加分组过滤，`Omit("key")`。
    pub async fn search(
        &self,
        keyword: &str,
        group: &Option<String>,
        model: &str,
        sort: ChannelSort,
    ) -> Result<Vec<ChannelRow>, sqlx::Error> {
        backend!(&self.db, pool, {
            let mut query = sqlx::QueryBuilder::new("SELECT ");
            query.push(CHANNEL_COLUMNS_NO_KEY);
            query.push(" FROM channels WHERE (id = ");
            query.push_bind(string_to_i64(keyword));
            query.push(" OR name LIKE ");
            query.push_bind(format!("%{keyword}%"));
            query.push(" OR \"key\" = ");
            query.push_bind(keyword);
            query.push(" OR base_url LIKE ");
            query.push_bind(format!("%{keyword}%"));
            query.push(") AND models LIKE ");
            query.push_bind(format!("%{model}%"));
            if let Some(group) = group.as_deref() {
                query.push(" AND (',' || \"group\" || ',') LIKE ");
                query.push_bind(group_like_pattern(group));
                query.push(" ESCAPE '!'");
            }
            query.push(" ORDER BY ");
            query.push(sort.order_sql());
            let rows = query.build().fetch_all(pool).await?;
            let mut channels = Vec::with_capacity(rows.len());
            for row in &rows {
                channels.push(channel_row!(row));
            }
            Ok(channels)
        })
    }

    /// Go `GetChannelById`：`selectAll` 决定是否读取 `key` 列。
    pub async fn by_id(&self, id: i64, with_key: bool) -> Result<Option<ChannelRow>, sqlx::Error> {
        let columns = if with_key {
            CHANNEL_COLUMNS_ALL
        } else {
            CHANNEL_COLUMNS_NO_KEY
        };
        backend!(&self.db, pool, {
            let mut query = sqlx::QueryBuilder::new("SELECT ");
            query.push(columns);
            query.push(" FROM channels WHERE id = ");
            query.push_bind(id);
            let row = query.build().fetch_optional(pool).await?;
            match row {
                Some(ref row) => Ok(Some(channel_row!(row))),
                None => Ok(None),
            }
        })
    }

    /// Go `BatchInsertChannels`：同事务逐行写入渠道，并逐行写入派生的
    /// `abilities` 行。Go 的 `chunk(50)` 只影响批次切分，单行循环写入与之
    /// 等价（自增 id 仍逐行取回，供能力行引用）。
    pub async fn insert_channels(&self, channels: Vec<NewChannel>) -> Result<(), sqlx::Error> {
        if channels.is_empty() {
            return Ok(());
        }
        let db = &self.db;
        transactional!(db, tx, {
            for channel in &channels {
                let id = insert_channel!(tx, channel)?;
                let models = channel.models.clone();
                let group = channel.group.clone();
                let tag = channel.tag.clone();
                let status = channel.status;
                add_abilities!(
                    tx,
                    id,
                    &models,
                    &group,
                    |_: &str| { status == CHANNEL_STATUS_ENABLED },
                    &tag
                )?;
            }
            Ok(())
        })
    }

    /// Go `Channel.Update`：同事务内写非零字段、写重算后的 `channel_info`、
    /// 重载整行、重建 `abilities`。重载失败（id 不存在）时整事务回滚并
    /// 返回 `None`（Go 的 `tx.First` 错误传播为 handler 错误）。
    pub async fn update(
        &self,
        id: i64,
        patch: &ChannelPatch,
        channel_info: Option<ChannelInfo>,
    ) -> Result<Option<ChannelRow>, sqlx::Error> {
        let db = &self.db;
        transactional!(db, tx, {
            apply_patch!(tx, id, patch, channel_info.as_ref())?;
            let reloaded = reload_channel!(tx, id)?;
            let Some(channel) = reloaded else {
                return Ok(None);
            };
            rebuild_abilities!(tx, &channel)?;
            Ok(Some(channel))
        })
    }

    /// Go `Channel.Delete`：硬删渠道行并删除其能力行。
    pub async fn delete_by_id(&self, id: i64) -> Result<(), sqlx::Error> {
        let db = &self.db;
        transactional!(db, tx, {
            sqlx::query("DELETE FROM channels WHERE id = $1")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM abilities WHERE channel_id = $1")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            Ok(())
        })
    }

    /// Go `DeleteDisabledChannel`：删除手动禁用与自动禁用渠道及其能力行，
    /// 返回实际删除的渠道行数。
    pub async fn delete_disabled(&self) -> Result<i64, sqlx::Error> {
        let db = &self.db;
        transactional!(db, tx, {
            sqlx::query(
                "DELETE FROM abilities WHERE channel_id IN \
                 (SELECT id FROM channels WHERE status = $1 OR status = $2)",
            )
            .bind(CHANNEL_STATUS_MANUALLY_DISABLED)
            .bind(CHANNEL_STATUS_AUTO_DISABLED)
            .execute(&mut *tx)
            .await?;
            let result = sqlx::query("DELETE FROM channels WHERE status = $1 OR status = $2")
                .bind(CHANNEL_STATUS_MANUALLY_DISABLED)
                .bind(CHANNEL_STATUS_AUTO_DISABLED)
                .execute(&mut *tx)
                .await?;
            Ok(result.rows_affected() as i64)
        })
    }

    /// Go `BatchDeleteChannels`：按 200 一批先删渠道行再删能力行，
    /// 返回实际删除的渠道行数。
    pub async fn delete_by_ids(&self, ids: &[i64]) -> Result<i64, sqlx::Error> {
        if ids.is_empty() {
            return Ok(0);
        }
        let mut deleted = 0i64;
        for chunk in ids.chunks(200) {
            deleted += backend!(&self.db, pool, {
                let mut transaction = pool.begin().await?;
                let outcome: Result<i64, sqlx::Error> = async {
                    let count = delete_in!(transaction, "channels", "id", chunk)?;
                    delete_in!(transaction, "abilities", "channel_id", chunk)?;
                    Ok(count)
                }
                .await;
                match outcome {
                    Ok(count) => {
                        transaction.commit().await?;
                        Ok(count)
                    }
                    Err(error) => {
                        let _ = transaction.rollback().await;
                        Err(error)
                    }
                }
            })?;
        }
        Ok(deleted)
    }
}
