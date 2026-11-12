//! 数据看板聚合缓存（Go `internal/usage/store_usedata.go`）。
//!
//! Go 语义：`LogQuotaData` 只把小时级聚合写进进程内 map（按
//! `user/username/model/小时/group/token/channel/node` 八元组聚合
//! count/quota/token_used），落库由 `SaveQuotaDataCache` 定时器完成：
//! 命中同键行则三列累加，否则插入。

use std::collections::HashMap;
use std::sync::Mutex;

use newapi_storage::Database;
use serde_json::Value;
use sqlx::Row;

/// Go `QuotaDataLogParams`（store_usedata.go:45-56）。
#[derive(Debug, Clone, Default)]
pub struct QuotaDataLogParams {
    pub user_id: i64,
    pub username: String,
    pub model_name: String,
    pub quota: i64,
    pub created_at: i64,
    pub token_used: i64,
    pub use_group: String,
    pub token_id: i64,
    pub channel_id: i64,
    pub node_name: String,
}

/// 聚合行（Go `QuotaData` 的可写列；`id`/`quota_display` 不是写入列）。
#[derive(Debug, Clone, Default)]
pub struct QuotaDataAgg {
    pub user_id: i64,
    pub username: String,
    pub model_name: String,
    pub created_at: i64,
    pub use_group: String,
    pub token_id: i64,
    pub channel_id: i64,
    pub node_name: String,
    pub count: i64,
    pub quota: i64,
    pub token_used: i64,
}

impl QuotaDataAgg {
    /// Go `logQuotaDataCache` 的八元组键（store_usedata.go:60-70）。
    fn cache_key(&self) -> String {
        format!(
            "{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
            self.user_id,
            self.username,
            self.model_name,
            self.created_at,
            self.use_group,
            self.token_id,
            self.channel_id,
            self.node_name,
        )
    }
}

static CACHE: Mutex<Option<HashMap<String, QuotaDataAgg>>> = Mutex::new(None);

/// Go `LogQuotaData`（store_usedata.go:84-110）：时间只精确到小时。
pub fn log_quota_data(params: QuotaDataLogParams) {
    let created_at = params.created_at - params.created_at % 3600;
    let mut agg = QuotaDataAgg {
        user_id: params.user_id,
        username: params.username,
        model_name: params.model_name,
        created_at,
        use_group: params.use_group,
        token_id: params.token_id,
        channel_id: params.channel_id,
        node_name: params.node_name,
        count: 1,
        quota: params.quota,
        token_used: params.token_used,
    };
    let key = agg.cache_key();
    let mut guard = CACHE.lock().expect("quota data cache");
    let cache = guard.get_or_insert_with(HashMap::new);
    if let Some(existing) = cache.get_mut(&key) {
        existing.count += agg.count;
        existing.quota += agg.quota;
        existing.token_used += agg.token_used;
        agg = existing.clone();
    }
    cache.insert(key, agg);
}

/// 测试辅助：清空进程内缓存（Go 测试直接替换 map）。
pub fn clear_cache() {
    CACHE.lock().expect("quota data cache").take();
}

/// 当前缓存条目数（测试断言用）。
pub fn cache_len() -> usize {
    CACHE
        .lock()
        .expect("quota data cache")
        .as_ref()
        .map(HashMap::len)
        .unwrap_or(0)
}

/// Go `SaveQuotaDataCache`（store_usedata.go:113-146）：命中同键行则
/// count/quota/token_used 累加，否则插入；完成后清空缓存。
pub async fn save_quota_data_cache(db: &Database) -> Result<usize, sqlx::Error> {
    let entries: Vec<QuotaDataAgg> = {
        let mut guard = CACHE.lock().expect("quota data cache");
        match guard.take() {
            Some(cache) => cache.into_values().collect(),
            None => Vec::new(),
        }
    };
    for entry in &entries {
        upsert_quota_data(db, entry).await?;
    }
    Ok(entries.len())
}

async fn upsert_quota_data(db: &Database, entry: &QuotaDataAgg) -> Result<(), sqlx::Error> {
    const WHERE: &str = "user_id = $1 AND username = $2 AND model_name = $3 \
         AND created_at = $4 AND use_group = $5 AND token_id = $6 \
         AND channel_id = $7 AND node_name = $8";
    match db {
        Database::Sqlite(pool) => {
            // SQLite 用 ?N 占位，先按 WHERE 重排参数顺序。
            let id: Option<i64> = sqlx::query_scalar(
                "SELECT id FROM quota_data WHERE user_id = ?1 AND username = ?2 \
                 AND model_name = ?3 AND created_at = ?4 AND use_group = ?5 \
                 AND token_id = ?6 AND channel_id = ?7 AND node_name = ?8",
            )
            .bind(entry.user_id)
            .bind(&entry.username)
            .bind(&entry.model_name)
            .bind(entry.created_at)
            .bind(&entry.use_group)
            .bind(entry.token_id)
            .bind(entry.channel_id)
            .bind(&entry.node_name)
            .fetch_optional(pool)
            .await?;
            if id.is_some() {
                sqlx::query(
                    "UPDATE quota_data SET count = count + ?1, quota = quota + ?2, \
                     token_used = token_used + ?3 WHERE user_id = ?4 AND username = ?5 \
                     AND model_name = ?6 AND created_at = ?7 AND use_group = ?8 \
                     AND token_id = ?9 AND channel_id = ?10 AND node_name = ?11",
                )
                .bind(entry.count)
                .bind(entry.quota)
                .bind(entry.token_used)
                .bind(entry.user_id)
                .bind(&entry.username)
                .bind(&entry.model_name)
                .bind(entry.created_at)
                .bind(&entry.use_group)
                .bind(entry.token_id)
                .bind(entry.channel_id)
                .bind(&entry.node_name)
                .execute(pool)
                .await?;
            } else {
                sqlx::query(
                    "INSERT INTO quota_data (user_id, username, model_name, created_at, \
                     use_group, token_id, channel_id, node_name, token_used, count, quota) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                )
                .bind(entry.user_id)
                .bind(&entry.username)
                .bind(&entry.model_name)
                .bind(entry.created_at)
                .bind(&entry.use_group)
                .bind(entry.token_id)
                .bind(entry.channel_id)
                .bind(&entry.node_name)
                .bind(entry.token_used)
                .bind(entry.count)
                .bind(entry.quota)
                .execute(pool)
                .await?;
            }
        }
        Database::Postgres(pool) => {
            let existing: Option<i64> =
                sqlx::query_scalar(&format!("SELECT id FROM quota_data WHERE {WHERE}"))
                    .bind(entry.user_id)
                    .bind(&entry.username)
                    .bind(&entry.model_name)
                    .bind(entry.created_at)
                    .bind(&entry.use_group)
                    .bind(entry.token_id)
                    .bind(entry.channel_id)
                    .bind(&entry.node_name)
                    .fetch_optional(pool)
                    .await?;
            if existing.is_some() {
                sqlx::query(&format!(
                    "UPDATE quota_data SET count = count + $9, quota = quota + $10, \
                     token_used = token_used + $11 WHERE {WHERE}"
                ))
                .bind(entry.user_id)
                .bind(&entry.username)
                .bind(&entry.model_name)
                .bind(entry.created_at)
                .bind(&entry.use_group)
                .bind(entry.token_id)
                .bind(entry.channel_id)
                .bind(&entry.node_name)
                .bind(entry.count)
                .bind(entry.quota)
                .bind(entry.token_used)
                .execute(pool)
                .await?;
            } else {
                sqlx::query(
                    "INSERT INTO quota_data (user_id, username, model_name, created_at, \
                     use_group, token_id, channel_id, node_name, token_used, count, quota) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
                )
                .bind(entry.user_id)
                .bind(&entry.username)
                .bind(&entry.model_name)
                .bind(entry.created_at)
                .bind(&entry.use_group)
                .bind(entry.token_id)
                .bind(entry.channel_id)
                .bind(&entry.node_name)
                .bind(entry.token_used)
                .bind(entry.count)
                .bind(entry.quota)
                .execute(pool)
                .await?;
            }
        }
    }
    Ok(())
}

/// 契约辅助：按八元组取回聚合行。
pub async fn read_back(
    db: &Database,
    entry: &QuotaDataAgg,
) -> Result<Option<(i64, i64, i64)>, sqlx::Error> {
    let row = match db {
        Database::Sqlite(pool) => {
            sqlx::query(
                "SELECT CAST(COALESCE(SUM(count), 0) AS BIGINT) AS count, \
                 CAST(COALESCE(SUM(quota), 0) AS BIGINT) AS quota, \
                 CAST(COALESCE(SUM(token_used), 0) AS BIGINT) AS token_used \
                 FROM quota_data WHERE user_id = ?1 AND username = ?2 AND model_name = ?3 \
                 AND created_at = ?4 AND use_group = ?5 AND token_id = ?6 \
                 AND channel_id = ?7 AND node_name = ?8",
            )
            .bind(entry.user_id)
            .bind(&entry.username)
            .bind(&entry.model_name)
            .bind(entry.created_at)
            .bind(&entry.use_group)
            .bind(entry.token_id)
            .bind(entry.channel_id)
            .bind(&entry.node_name)
            .fetch_optional(pool)
            .await?
        }
        Database::Postgres(pool) => {
            sqlx::query(
                "SELECT CAST(COALESCE(SUM(count), 0) AS BIGINT) AS count, \
                 CAST(COALESCE(SUM(quota), 0) AS BIGINT) AS quota, \
                 CAST(COALESCE(SUM(token_used), 0) AS BIGINT) AS token_used \
                 FROM quota_data WHERE user_id = $1 AND username = $2 AND model_name = $3 \
                 AND created_at = $4 AND use_group = $5 AND token_id = $6 \
                 AND channel_id = $7 AND node_name = $8",
            )
            .bind(entry.user_id)
            .bind(&entry.username)
            .bind(&entry.model_name)
            .bind(entry.created_at)
            .bind(&entry.use_group)
            .bind(entry.token_id)
            .bind(entry.channel_id)
            .bind(&entry.node_name)
            .fetch_optional(pool)
            .await?
        }
    };
    let Some(row) = row else { return Ok(None) };
    let value = |name: &str| -> Result<i64, sqlx::Error> {
        match row.try_get::<Option<i64>, _>(name) {
            Ok(v) => Ok(v.unwrap_or_default()),
            Err(_) => Ok(row.try_get::<Value, _>(name)?.as_i64().unwrap_or_default()),
        }
    };
    Ok(Some((
        value("count")?,
        value("quota")?,
        value("token_used")?,
    )))
}
