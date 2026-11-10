//! 模型元数据（`models` 表）与供应商（`vendors` 表，仅 sync_upstream
//! 所需的最小写路径）的仓储层。
//!
//! Go 参考（`/root/newapi/apps/api/internal/catalog`）：
//! - `store_model_meta.go`：`Model` 记录、`Insert`/`Update`/`Delete`/
//!   `UpdateModelStatus`、`IsModelNameDuplicated`、`SearchModels`、
//!   `GetVendorModelCounts`、`GetBoundChannelsByModelsMap`
//! - `store_vendor_meta.go`：`Vendor` 记录与按名查询/创建（sync 上游供应商
//!   补建用；vendors 管理路由属 vendor 切片，这里不实现）
//! - `store_missing_models.go`：`GetMissingModels`（abilities 启用模型减去
//!   `models` 表已有名字）
//!
//! GORM 软删除（`deleted_at`）语义逐条复刻：本模块所有查询都带
//! `deleted_at IS NULL`，删除是写 `deleted_at` 的软删除，重名检查排除
//! 已软删行。
//!
//! 已知范围裁剪（后续切片接入）：
//! - Go 的 `Insert`/`Update`/`Delete`/`UpdateModelStatus` 都包在
//!   `MutateGatewayRouting` 事务里（行写入 + 路由修订号 bump + outbox 同事务
//!   提交）。与 channels 切片的决定一致：catalog 尚无网关修订机制，事务边界
//!   保持 Go 的“单条变更原子提交”语义，修订号不在本切片。
//! - `RefreshPricing`（定价缓存刷新）与 `enrichModels` 的
//!   `enable_groups`/`quota_types`/`matched_models`/规则模型的
//!   `bound_channels` 并集均来自定价缓存（`store_pricing.go`），缓存未移植，
//!   由 HTTP 适配层按“空缓存”语义出空值。
//!
//! 两个后端共用 `$N` 占位符（sqlx-sqlite 与 sqlx-postgres 均接受），与
//! `channels/store.rs` 的约定一致。

use std::collections::BTreeMap;

use newapi_storage::Database;
use serde::Deserialize;
use sqlx::Row;

/// Go `NameRuleExact`（`store_model_meta.go` iota：Exact=0）。
pub const NAME_RULE_EXACT: i64 = 0;
/// Go `NameRulePrefix`。
pub const NAME_RULE_PREFIX: i64 = 1;
/// Go `NameRuleContains`。
pub const NAME_RULE_CONTAINS: i64 = 2;
/// Go `NameRuleSuffix`。
pub const NAME_RULE_SUFFIX: i64 = 3;

/// `models` 行的读视图。可空列（GORM 建表未加 not null）按 Go 零值语义
/// 回落为空串/零。
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ModelRow {
    pub id: i64,
    pub model_name: String,
    pub description: String,
    pub icon: String,
    pub tags: String,
    pub vendor_id: i64,
    pub endpoints: String,
    pub status: i64,
    pub sync_official: i64,
    pub created_time: i64,
    pub updated_time: i64,
    pub name_rule: i64,
}

/// Go `channel.BoundChannel`（`store_model_meta.go:20-23`）：精确模型绑定的
/// 渠道摘要，`type` 是渠道类型。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundChannel {
    pub name: String,
    /// 列名 `type`。
    pub channel_type: i64,
}

/// Go `channel.Model` 的 JSON 绑定形态（创建/更新请求体共用）。
///
/// 所有字段可选：Go `json.Unmarshal` 对缺失与 `null` 同样给零值，只有类型
/// 不匹配才是错误（`Option` 精确复现）。`bound_channels`/`enable_groups`/
/// `quota_types`/`matched_models`/`matched_count` 是 `gorm:"-"` 计算字段，
/// 写路径忽略其值，serde 默认忽略未知字段即同一语义。
#[derive(Clone, Debug, Default, Deserialize)]
pub struct ModelInput {
    pub id: Option<i64>,
    pub model_name: Option<String>,
    pub description: Option<String>,
    pub icon: Option<String>,
    pub tags: Option<String>,
    pub vendor_id: Option<i64>,
    pub endpoints: Option<String>,
    pub status: Option<i64>,
    pub sync_official: Option<i64>,
    /// 只随响应回显（Go 的 `Update` 不写这两列；创建时被 now 覆盖）。
    #[allow(dead_code)]
    pub created_time: Option<i64>,
    #[allow(dead_code)]
    pub updated_time: Option<i64>,
    pub name_rule: Option<i64>,
}

/// 创建时写入的一行：Go `insertWithTx` 先 Create 再把 `status`/
/// `sync_official` 的**原始值**（含 0）强制写回，因此零值会覆盖列默认的
/// 1——与 channels 的 `into_new_channel`（0→1）相反，这里如实保存 0。
#[derive(Clone, Debug, Default)]
pub struct NewModel {
    /// Go `tx.Create(mi)` 对非零 id 会显式插入该主键。
    pub id: Option<i64>,
    pub model_name: String,
    pub description: String,
    pub icon: String,
    pub tags: String,
    pub vendor_id: i64,
    pub endpoints: String,
    pub status: i64,
    pub sync_official: i64,
    pub name_rule: i64,
}

/// Go `parseModelStatusFilter`（`store_model_meta.go:267`）：UI/API 状态值到
/// `models.status` 的映射；`ok=false` 表示不加该过滤。
///
/// 注意 Go 的匹配在 `ToLower(TrimSpace(...))` 之后进行，所以
/// `"ENABLED"`/`"1"` 命中而 `" Enabled "`（内部空格）不命中；数值原样透传
/// （含负数与超过 status 域的值）。
pub fn parse_status_filter(status: &str) -> Option<i64> {
    match status.trim().to_ascii_lowercase().as_str() {
        "" | "all" => None,
        "enabled" | "1" => Some(1),
        "disabled" | "0" => Some(0),
        other => other.parse::<i64>().ok(),
    }
}

/// Go `parseModelSyncFilter`（`store_model_meta.go:286`）。
pub fn parse_sync_filter(sync_official: &str) -> Option<i64> {
    match sync_official.trim().to_ascii_lowercase().as_str() {
        "" | "all" => None,
        "yes" | "1" => Some(1),
        "no" | "0" => Some(0),
        other => other.parse::<i64>().ok(),
    }
}

/// Go `chooseStatus`（`handle_model_sync.go:488`）：上游 0 表示“未指定”，
/// 回落 fallback；fallback 也是 0 时取 1。
pub fn choose_status(primary: i64, fallback: i64) -> i64 {
    if primary == 0 && fallback != 0 {
        return fallback;
    }
    if primary != 0 {
        return primary;
    }
    1
}

/// Go `containsField`（`handle_model_sync.go:471`）：大小写与首尾空白不敏感
/// 的字段名匹配。
pub fn contains_field(fields: &[String], key: &str) -> bool {
    let key = key.trim().to_ascii_lowercase();
    fields
        .iter()
        .any(|field| field.trim().to_ascii_lowercase() == key)
}

/// SELECT 列清单。`deleted_at` 不参与读取（Go `json:"-"`）。
const MODEL_COLUMNS: &str = "id, model_name, description, icon, tags, vendor_id, endpoints, \
     status, sync_official, created_time, updated_time, name_rule";

/// 行解码：可空列按 Go 零值回落。两个驱动的具现行类型各展开一次。
macro_rules! model_row {
    ($row:expr) => {{
        let row = $row;
        ModelRow {
            id: row.try_get::<i64, _>("id")?,
            model_name: row
                .try_get::<Option<String>, _>("model_name")?
                .unwrap_or_default(),
            description: row
                .try_get::<Option<String>, _>("description")?
                .unwrap_or_default(),
            icon: row
                .try_get::<Option<String>, _>("icon")?
                .unwrap_or_default(),
            tags: row
                .try_get::<Option<String>, _>("tags")?
                .unwrap_or_default(),
            vendor_id: row
                .try_get::<Option<i64>, _>("vendor_id")?
                .unwrap_or_default(),
            endpoints: row
                .try_get::<Option<String>, _>("endpoints")?
                .unwrap_or_default(),
            status: row.try_get::<Option<i64>, _>("status")?.unwrap_or_default(),
            sync_official: row
                .try_get::<Option<i64>, _>("sync_official")?
                .unwrap_or_default(),
            created_time: row
                .try_get::<Option<i64>, _>("created_time")?
                .unwrap_or_default(),
            updated_time: row
                .try_get::<Option<i64>, _>("updated_time")?
                .unwrap_or_default(),
            name_rule: row
                .try_get::<Option<i64>, _>("name_rule")?
                .unwrap_or_default(),
        }
    }};
}

macro_rules! backend {
    ($db:expr, $pool:ident, $body:block) => {
        match $db {
            Database::Sqlite($pool) => $body,
            Database::Postgres($pool) => $body,
        }
    };
}

/// 动态 WHERE 的共享构建：与 Go `SearchModels` 的谓词顺序一致
/// （keyword → vendor → status → sync_official），最后永远追加软删除范围。
fn push_conditions(
    query: &mut sqlx::QueryBuilder<'static>,
    keyword: &str,
    vendor: &str,
    status: Option<i64>,
    sync_official: Option<i64>,
) {
    query.push("deleted_at IS NULL");
    if !keyword.is_empty() {
        let like = format!("%{keyword}%");
        query.push(" AND (model_name LIKE ");
        query.push_bind(like.clone());
        query.push(" OR description LIKE ");
        query.push_bind(like.clone());
        query.push(" OR tags LIKE ");
        query.push_bind(like);
        query.push(")");
    }
    // Go：vendor 能解析成整数按 vendor_id 等值过滤；否则内联 JOIN vendors
    // 按 name LIKE 过滤（raw Joins 不带 vendors 的软删除范围，如实复刻）。
    if !vendor.is_empty() {
        match vendor.parse::<i64>() {
            Ok(id) => {
                query.push(" AND models.vendor_id = ");
                query.push_bind(id);
            }
            Err(_) => {
                query.push(" AND models.vendor_id IN (SELECT id FROM vendors WHERE name LIKE ");
                query.push_bind(format!("%{vendor}%"));
                query.push(")");
            }
        }
    }
    if let Some(value) = status {
        query.push(" AND models.status = ");
        query.push_bind(value);
    }
    if let Some(value) = sync_official {
        query.push(" AND models.sync_official = ");
        query.push_bind(value);
    }
}

/// `models` 表（及 sync 上游所需的 `vendors` 最小路径）的仓储。
pub struct ModelRepository {
    db: Database,
}

impl ModelRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub fn database(&self) -> &Database {
        &self.db
    }

    /// Go `SearchModels`：过滤 + 计数 + `ORDER BY models.id DESC` 分页。
    /// 返回 `(rows, total)`。
    pub async fn search(
        &self,
        keyword: &str,
        vendor: &str,
        status: Option<i64>,
        sync_official: Option<i64>,
        offset: i64,
        limit: i64,
    ) -> Result<(Vec<ModelRow>, i64), sqlx::Error> {
        backend!(&self.db, pool, {
            let mut count = sqlx::QueryBuilder::new("SELECT COUNT(*) AS total FROM models WHERE ");
            push_conditions(&mut count, keyword, vendor, status, sync_official);
            let total: i64 = count
                .build()
                .fetch_one(pool)
                .await?
                .try_get::<i64, _>("total")?;

            let mut query = sqlx::QueryBuilder::new("SELECT ");
            query.push(MODEL_COLUMNS);
            query.push(" FROM models WHERE ");
            push_conditions(&mut query, keyword, vendor, status, sync_official);
            query.push(" ORDER BY models.id DESC LIMIT ");
            query.push_bind(limit);
            query.push(" OFFSET ");
            query.push_bind(offset);
            let rows = query.build().fetch_all(pool).await?;
            let models = rows.iter().map(|row| model_row!(row)).collect();
            Ok((models, total))
        })
    }

    /// Go `dbx.DB.First(&m, id)`：软删除范围生效；未命中返回 `None`
    /// （HTTP 层折成 `model.not_exists`，对齐 Go 的 gorm record-not-found）。
    pub async fn by_id(&self, id: i64) -> Result<Option<ModelRow>, sqlx::Error> {
        backend!(&self.db, pool, {
            let row = sqlx::query(&format!(
                "SELECT {MODEL_COLUMNS} FROM models WHERE id = $1 AND deleted_at IS NULL"
            ))
            .bind(id)
            .fetch_optional(pool)
            .await?;
            Ok(row.map(|row| model_row!(row)))
        })
    }

    /// Go `dbx.DB.Where("model_name = ?", name).First(&existing)`：sync 路径
    /// 的按名读取（软删除范围生效）。
    pub async fn by_name(&self, name: &str) -> Result<Option<ModelRow>, sqlx::Error> {
        backend!(&self.db, pool, {
            let row = sqlx::query(&format!(
                "SELECT {MODEL_COLUMNS} FROM models WHERE model_name = $1 AND deleted_at IS NULL"
            ))
            .bind(name)
            .fetch_optional(pool)
            .await?;
            Ok(row.map(|row| model_row!(row)))
        })
    }

    /// Go preview 的 `dbx.DB.Where("model_name IN ? AND sync_official <> 0")
    /// .Find(&locals)`：错误被 Go 吞掉（`_ =`），这里上抛由调用方按 Go 的
    /// 吞错语义处理。
    pub async fn by_names_syncable(&self, names: &[String]) -> Result<Vec<ModelRow>, sqlx::Error> {
        if names.is_empty() {
            return Ok(Vec::new());
        }
        backend!(&self.db, pool, {
            let mut query = sqlx::QueryBuilder::new("SELECT ");
            query.push(MODEL_COLUMNS);
            query.push(
                " FROM models WHERE deleted_at IS NULL AND sync_official <> 0 AND model_name IN (",
            );
            let mut separated = query.separated(", ");
            for name in names {
                separated.push_bind(name);
            }
            query.push(")");
            // Go 的 Find 无 ORDER BY；按 id 升序让冲突列表顺序确定。
            query.push(" ORDER BY id ASC");
            let rows = query.build().fetch_all(pool).await?;
            Ok(rows.iter().map(|row| model_row!(row)).collect())
        })
    }

    /// Go `mi.Insert()`（`insertWithTx`）：显式写入全部列——`status`/
    /// `sync_official` 的 0 值按原始值落库（GORM 随后的 `Updates(map)` 会把
    /// 列默认改回的 1 强制覆盖为 0）；`created_time`/`updated_time` 由本层
    /// 生成（Go `common.GetTimestamp()`）。返回新 id。
    pub async fn insert(&self, model: &NewModel, now: i64) -> Result<i64, sqlx::Error> {
        backend!(&self.db, pool, {
            match model.id {
                Some(id) if id != 0 => {
                    sqlx::query_scalar(
                        "INSERT INTO models \
                         (id, model_name, description, icon, tags, vendor_id, endpoints, \
                          status, sync_official, created_time, updated_time, name_rule) \
                         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id",
                    )
                    .bind(id)
                    .bind(&model.model_name)
                    .bind(&model.description)
                    .bind(&model.icon)
                    .bind(&model.tags)
                    .bind(model.vendor_id)
                    .bind(&model.endpoints)
                    .bind(model.status)
                    .bind(model.sync_official)
                    .bind(now)
                    .bind(now)
                    .bind(model.name_rule)
                    .fetch_one(pool)
                    .await
                }
                _ => {
                    sqlx::query_scalar(
                        "INSERT INTO models \
                         (model_name, description, icon, tags, vendor_id, endpoints, \
                          status, sync_official, created_time, updated_time, name_rule) \
                         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id",
                    )
                    .bind(&model.model_name)
                    .bind(&model.description)
                    .bind(&model.icon)
                    .bind(&model.tags)
                    .bind(model.vendor_id)
                    .bind(&model.endpoints)
                    .bind(model.status)
                    .bind(model.sync_official)
                    .bind(now)
                    .bind(now)
                    .bind(model.name_rule)
                    .fetch_one(pool)
                    .await
                }
            }
        })
    }

    /// Go `mi.Update()`（`updateWithTx`）：`Select(...)` 列出的全部列**含零值**
    /// 整体覆写，`updated_time` 由本层生成。按 id 定位且带软删除范围；行
    /// 不存在时 Go 的 `Updates` 也是 0 行无错，这里同样静默。
    pub async fn update(&self, model: &ModelInput, updated_time: i64) -> Result<(), sqlx::Error> {
        let id = model.id.unwrap_or(0);
        backend!(&self.db, pool, {
            sqlx::query(
                "UPDATE models SET model_name = $1, description = $2, icon = $3, tags = $4, \
                 vendor_id = $5, endpoints = $6, status = $7, sync_official = $8, \
                 name_rule = $9, updated_time = $10 \
                 WHERE id = $11 AND deleted_at IS NULL",
            )
            .bind(model.model_name.clone().unwrap_or_default())
            .bind(model.description.clone().unwrap_or_default())
            .bind(model.icon.clone().unwrap_or_default())
            .bind(model.tags.clone().unwrap_or_default())
            .bind(model.vendor_id.unwrap_or(0))
            .bind(model.endpoints.clone().unwrap_or_default())
            .bind(model.status.unwrap_or(0))
            .bind(model.sync_official.unwrap_or(0))
            .bind(model.name_rule.unwrap_or(0))
            .bind(updated_time)
            .bind(id)
            .execute(pool)
            .await?;
            Ok(())
        })
    }

    /// Go `UpdateModelStatus`：只改 status，**不**触碰 updated_time。
    pub async fn update_status(&self, id: i64, status: i64) -> Result<(), sqlx::Error> {
        backend!(&self.db, pool, {
            sqlx::query("UPDATE models SET status = $1 WHERE id = $2 AND deleted_at IS NULL")
                .bind(status)
                .bind(id)
                .execute(pool)
                .await?;
            Ok(())
        })
    }

    /// Go `mi.Delete()`：软删除。返回是否确实删掉了行（删除前 Go 先 `First`
    /// 校验存在，这一步在 HTTP 层完成）。
    pub async fn soft_delete(&self, id: i64, deleted_at: i64) -> Result<bool, sqlx::Error> {
        backend!(&self.db, pool, {
            let result = sqlx::query(
                "UPDATE models SET deleted_at = $1 WHERE id = $2 AND deleted_at IS NULL",
            )
            .bind(deleted_at)
            .bind(id)
            .execute(pool)
            .await?;
            Ok(result.rows_affected() > 0)
        })
    }

    /// Go `IsModelNameDuplicated`：软删除范围生效，排除自身 id（id=0 时
    /// `id <> 0` 恒真）。
    pub async fn is_name_duplicated(&self, id: i64, name: &str) -> Result<bool, sqlx::Error> {
        if name.is_empty() {
            return Ok(false);
        }
        backend!(&self.db, pool, {
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM models WHERE model_name = $1 AND id <> $2 \
                 AND deleted_at IS NULL",
            )
            .bind(name)
            .bind(id)
            .fetch_one(pool)
            .await?;
            Ok(count > 0)
        })
    }

    /// Go `GetVendorModelCounts`：`vendor_id` 分组计数（含 0 组）。
    /// Go 输出 map 无序；这里按 vendor_id 升序保证响应可复现。
    pub async fn vendor_counts(&self) -> Result<Vec<(i64, i64)>, sqlx::Error> {
        backend!(&self.db, pool, {
            let rows = sqlx::query(
                "SELECT vendor_id, COUNT(*) AS count FROM models \
                 WHERE deleted_at IS NULL GROUP BY vendor_id ORDER BY vendor_id ASC",
            )
            .fetch_all(pool)
            .await?;
            let mut counts = Vec::with_capacity(rows.len());
            for row in &rows {
                counts.push((
                    row.try_get::<Option<i64>, _>("vendor_id")?
                        .unwrap_or_default(),
                    row.try_get::<i64, _>("count")?,
                ));
            }
            Ok(counts)
        })
    }

    /// Go `GetBoundChannelsByModelsMap`：`channels JOIN abilities`（启用能力
    /// 行）按模型名收集渠道摘要。Go 的 DISTINCT 顺序由扫描决定；这里按
    /// model/name/type 升序让 `bound_channels` 顺序确定。
    pub async fn bound_channels_by_models(
        &self,
        model_names: &[String],
    ) -> Result<BTreeMap<String, Vec<BoundChannel>>, sqlx::Error> {
        let mut result: BTreeMap<String, Vec<BoundChannel>> = BTreeMap::new();
        if model_names.is_empty() {
            return Ok(result);
        }
        backend!(&self.db, pool, {
            let mut query = sqlx::QueryBuilder::new(
                "SELECT DISTINCT abilities.model AS model, channels.name AS name, \
                 channels.type AS type FROM channels \
                 JOIN abilities ON abilities.channel_id = channels.id \
                 WHERE abilities.enabled = TRUE AND abilities.model IN (",
            );
            let mut separated = query.separated(", ");
            for name in model_names {
                separated.push_bind(name);
            }
            query.push(") ORDER BY model, name, type");
            let rows = query.build().fetch_all(pool).await?;
            for row in &rows {
                let model: String = row.try_get("model")?;
                let channel = BoundChannel {
                    name: row
                        .try_get::<Option<String>, _>("name")?
                        .unwrap_or_default(),
                    channel_type: row.try_get::<i64, _>("type")?,
                };
                result.entry(model).or_default().push(channel);
            }
            Ok(result)
        })
    }

    /// Go `GetMissingModels`：abilities 启用模型中 `models` 表（软删除范围
    /// 生效）没有记录的名字，保持 enabled 顺序。调用方传入
    /// `abilities::enabled_models` 的结果。
    pub async fn missing_models(&self, enabled: &[String]) -> Result<Vec<String>, sqlx::Error> {
        if enabled.is_empty() {
            return Ok(Vec::new());
        }
        backend!(&self.db, pool, {
            let mut query = sqlx::QueryBuilder::new(
                "SELECT model_name FROM models WHERE deleted_at IS NULL AND model_name IN (",
            );
            let mut separated = query.separated(", ");
            for name in enabled {
                separated.push_bind(name);
            }
            query.push(")");
            let rows = query.build().fetch_all(pool).await?;
            let existing: std::collections::HashSet<String> = rows
                .iter()
                .map(|row| row.try_get::<String, _>("model_name"))
                .collect::<Result<_, _>>()?;
            Ok(enabled
                .iter()
                .filter(|name| !existing.contains(*name))
                .cloned()
                .collect())
        })
    }

    /// Go `dbx.DB.Where("name = ?", name).First(&existing)`（vendors，
    /// 软删除范围生效）：sync 上游供应商补建的按名查询。
    pub async fn vendor_id_by_name(&self, name: &str) -> Result<Option<i64>, sqlx::Error> {
        backend!(&self.db, pool, {
            sqlx::query_scalar::<_, i64>(
                "SELECT id FROM vendors WHERE name = $1 \
                 AND deleted_at IS NULL",
            )
            .bind(name)
            .fetch_optional(pool)
            .await
        })
    }

    /// Go preview 的 `dbx.DB.Where("id IN ?", vendorIDs).Find(&dbVendors)`
    /// （软删除范围生效）：vendor id → name 映射。错误被 Go 吞掉（`_ =`），
    /// 这里上抛由调用方按吞错语义处理。
    pub async fn vendor_names_by_ids(
        &self,
        ids: &[i64],
    ) -> Result<BTreeMap<i64, String>, sqlx::Error> {
        if ids.is_empty() {
            return Ok(BTreeMap::new());
        }
        backend!(&self.db, pool, {
            let mut query = sqlx::QueryBuilder::new(
                "SELECT id, name FROM vendors WHERE deleted_at IS NULL AND id IN (",
            );
            let mut separated = query.separated(", ");
            for id in ids {
                separated.push_bind(id);
            }
            query.push(")");
            let rows = query.build().fetch_all(pool).await?;
            let mut names = BTreeMap::new();
            for row in &rows {
                names.insert(
                    row.try_get::<i64, _>("id")?,
                    row.try_get::<Option<String>, _>("name")?
                        .unwrap_or_default(),
                );
            }
            Ok(names)
        })
    }

    /// Go `v.Insert()`（vendors 最小路径）：仅 sync 需要的字段；返回新 id。
    pub async fn insert_vendor(
        &self,
        name: &str,
        description: &str,
        icon: &str,
        status: i64,
        now: i64,
    ) -> Result<i64, sqlx::Error> {
        backend!(&self.db, pool, {
            sqlx::query_scalar(
                "INSERT INTO vendors (name, description, icon, status, created_time, updated_time) \
                 VALUES ($1,$2,$3,$4,$5,$6) RETURNING id",
            )
            .bind(name)
            .bind(description)
            .bind(icon)
            .bind(status)
            .bind(now)
            .bind(now)
            .fetch_one(pool)
            .await
        })
    }

    /// Go `tx.Save(&local)`（sync overwrite 路径）：全列覆写，**包含**
    /// `updated_time` 的旧值（gorm Save 不刷新时间戳，这是 Go 的可观察行为）。
    /// 调用方传入从库里读出的行（vendor 名等字段已换算回列值）。
    pub async fn save_all(&self, row: &ModelRow) -> Result<(), sqlx::Error> {
        backend!(&self.db, pool, {
            sqlx::query(
                "UPDATE models SET model_name = $1, description = $2, icon = $3, tags = $4, \
                 vendor_id = $5, endpoints = $6, status = $7, sync_official = $8, \
                 created_time = $9, updated_time = $10, name_rule = $11 \
                 WHERE id = $12 AND deleted_at IS NULL",
            )
            .bind(&row.model_name)
            .bind(&row.description)
            .bind(&row.icon)
            .bind(&row.tags)
            .bind(row.vendor_id)
            .bind(&row.endpoints)
            .bind(row.status)
            .bind(row.sync_official)
            .bind(row.created_time)
            .bind(row.updated_time)
            .bind(row.name_rule)
            .bind(row.id)
            .execute(pool)
            .await?;
            Ok(())
        })
    }
}
