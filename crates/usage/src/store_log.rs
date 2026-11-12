//! 消费日志写侧（Go `internal/usage/store_log.go:146-483` 的写函数移植）。
//!
//! 移植范围：`RecordLog`、`RecordLogWithAdminInfo`、`RecordLoginLog`、
//! `RecordOperationAuditLog`、`RecordSensitiveAuditLog`、`RecordTopupLog`、
//! `RecordErrorLog`、`RecordConsumeLog`、`RecordTaskBillingLog` 以及
//! `createLog`/`ensureLogRequestId`。写入列集合与读取端
//! （`apps/server/src/log_http.rs` 的 `LOG_COLUMNS` SELECT 白名单）一一对应。
//!
//! 有意偏差（调用方上下文不可得，Go 依赖 `contract.Context` 与包级全局）：
//! - `username`/`ip`/`request_id`/`upstream_request_id` 由调用方显式传入；
//!   Go 的 `c.GetString("username")`、`c.ClientIP()`（含
//!   `identity.GetUserSetting(...).RecordIpLog` 判定）属 relay 数据面。
//! - `RecordConsumeLog` 的 `attachInsight` 画像接线（store_log.go:383）属
//!   relay 数据面，未随本切片移植；`other` 由调用方在传入前自行补充。
//! - `identity.GetUsernameById`/`GetTokenById` 回填（`RecordLog`、
//!   `RecordTaskBillingLog`）改为调用方传入，避免本 crate 依赖 identity。

use newapi_storage::Database;
use rand::Rng;
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;

/// Go `store_log.go:95-105`：禁用 iota 的显式类型值。
pub const LOG_TYPE_UNKNOWN: i64 = 0;
pub const LOG_TYPE_TOPUP: i64 = 1;
pub const LOG_TYPE_CONSUME: i64 = 2;
pub const LOG_TYPE_MANAGE: i64 = 3;
pub const LOG_TYPE_SYSTEM: i64 = 4;
pub const LOG_TYPE_ERROR: i64 = 5;
pub const LOG_TYPE_REFUND: i64 = 6;
pub const LOG_TYPE_LOGIN: i64 = 7;
pub const LOG_TYPE_SENSITIVE: i64 = 8;

/// Go `utils.go:189-192` `GetTimeString`：UTC `YYYYMMDDHHMMSS` + 9 位纳秒。
fn get_time_string() -> String {
    let now = chrono::Utc::now();
    format!(
        "{}{:09}",
        now.format("%Y%m%d%H%M%S"),
        now.timestamp_subsec_nanos() as u64
    )
}

/// Go `utils.go:194-202` `requestIdPrefix`：Go 用 sha256(主模块路径)[:4] hex；
/// Rust 端以 crate 名等价的固定串哈希，长度与熵一致。
fn request_id_prefix() -> String {
    let digest = Sha256::digest(b"newapi-rs");
    hex(&digest[..4])
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

/// Go `str.go:30-36` `GetRandomString`：字母数字随机串。
fn get_random_string(length: usize) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

/// Go `utils.go:204-206` `NewRequestId`。
pub fn new_request_id() -> String {
    format!(
        "{}{}{}",
        get_time_string(),
        request_id_prefix(),
        get_random_string(8)
    )
}

/// Go `store_log.go:107-111` `ensureLogRequestId`：空 request_id 补默认值。
fn ensure_request_id(request_id: &mut String) {
    if request_id.is_empty() {
        *request_id = new_request_id();
    }
}

/// 一行日志的写入形态（Go `Log` 结构的可写列；`channel_name` 是 `gorm:"->"`
/// 只读字段，AutoMigrate 不建列，因此不在写入集合中）。
#[derive(Debug, Default, Clone)]
pub struct LogInsert {
    pub user_id: i64,
    pub created_at: i64,
    pub log_type: i64,
    pub content: String,
    pub username: String,
    pub token_name: String,
    pub model_name: String,
    pub quota: i64,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub use_time: i64,
    pub is_stream: bool,
    pub channel_id: i64,
    pub token_id: i64,
    pub group: String,
    pub ip: String,
    pub request_id: String,
    pub upstream_request_id: String,
    pub other: String,
}

/// Go `common.MapToJsonStr`：serde_json 的 `Map` 默认 BTreeMap，键序与 Go
/// map 序列化后的字典序一致；顶层不是对象时 Go 返回 `""`。
pub fn map_to_json_str(map: &Map<String, Value>) -> String {
    Value::Object(map.clone()).to_string()
}

/// Go `store_log.go:113-116` `createLog`。
pub async fn insert_log(db: &Database, log: &LogInsert) -> Result<(), sqlx::Error> {
    let mut log = log.clone();
    ensure_request_id(&mut log.request_id);
    match db {
        Database::Sqlite(pool) => {
            sqlx::query(
                "INSERT INTO logs (user_id, created_at, \"type\", content, username, \
                 token_name, model_name, quota, prompt_tokens, completion_tokens, \
                 use_time, is_stream, channel_id, token_id, \"group\", ip, \
                 request_id, upstream_request_id, other) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, \
                 ?15, ?16, ?17, ?18, ?19)",
            )
            .bind(log.user_id)
            .bind(log.created_at)
            .bind(log.log_type)
            .bind(&log.content)
            .bind(&log.username)
            .bind(&log.token_name)
            .bind(&log.model_name)
            .bind(log.quota)
            .bind(log.prompt_tokens)
            .bind(log.completion_tokens)
            .bind(log.use_time)
            .bind(log.is_stream)
            .bind(log.channel_id)
            .bind(log.token_id)
            .bind(&log.group)
            .bind(&log.ip)
            .bind(&log.request_id)
            .bind(&log.upstream_request_id)
            .bind(&log.other)
            .execute(pool)
            .await?;
        }
        Database::Postgres(pool) => {
            sqlx::query(
                "INSERT INTO logs (user_id, created_at, \"type\", content, username, \
                 token_name, model_name, quota, prompt_tokens, completion_tokens, \
                 use_time, is_stream, channel_id, token_id, \"group\", ip, \
                 request_id, upstream_request_id, other) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, \
                 $15, $16, $17, $18, $19)",
            )
            .bind(log.user_id)
            .bind(log.created_at)
            .bind(log.log_type)
            .bind(&log.content)
            .bind(&log.username)
            .bind(&log.token_name)
            .bind(&log.model_name)
            .bind(log.quota)
            .bind(log.prompt_tokens)
            .bind(log.completion_tokens)
            .bind(log.use_time)
            .bind(log.is_stream)
            .bind(log.channel_id)
            .bind(log.token_id)
            .bind(&log.group)
            .bind(&log.ip)
            .bind(&log.request_id)
            .bind(&log.upstream_request_id)
            .bind(&log.other)
            .execute(pool)
            .await?;
        }
    }
    Ok(())
}

/// Go `RecordConsumeLogParams`（store_log.go:359-372）。JSON 键名按 Go tag。
#[derive(Debug, Clone, Serialize)]
pub struct RecordConsumeLogParams {
    #[serde(rename = "channel_id")]
    pub channel_id: i64,
    #[serde(rename = "prompt_tokens")]
    pub prompt_tokens: i64,
    #[serde(rename = "completion_tokens")]
    pub completion_tokens: i64,
    #[serde(rename = "model_name")]
    pub model_name: String,
    #[serde(rename = "token_name")]
    pub token_name: String,
    #[serde(rename = "quota")]
    pub quota: i64,
    #[serde(rename = "content")]
    pub content: String,
    #[serde(rename = "token_id")]
    pub token_id: i64,
    #[serde(rename = "use_time_seconds")]
    pub use_time_seconds: i64,
    #[serde(rename = "is_stream")]
    pub is_stream: bool,
    #[serde(rename = "group")]
    pub group: String,
    #[serde(rename = "other")]
    pub other: Map<String, Value>,
}

impl Default for RecordConsumeLogParams {
    fn default() -> Self {
        Self {
            channel_id: 0,
            prompt_tokens: 0,
            completion_tokens: 0,
            model_name: String::new(),
            token_name: String::new(),
            quota: 0,
            content: String::new(),
            token_id: 0,
            use_time_seconds: 0,
            is_stream: false,
            group: String::new(),
            other: Map::new(),
        }
    }
}

/// 调用方上下文（Go 里来自 `contract.Context` 与包级全局开关）。
#[derive(Debug, Clone, Default)]
pub struct ConsumeLogContext {
    pub user_id: i64,
    pub username: String,
    /// `c.GetString(common.RequestIdKey)`；空则写入时补 `new_request_id()`。
    pub request_id: String,
    pub upstream_request_id: String,
    /// 已按 `RecordIpLog` 用户设定判定后的 IP：true 才会写入 `ip` 列。
    pub record_ip: bool,
    pub client_ip: String,
    /// Go `common.LogConsumeEnabled`。
    pub consume_enabled: bool,
    /// Go `common.DataExportEnabled`。
    pub data_export_enabled: bool,
    /// Go `common.NodeName`（数据看板落库用）。
    pub node_name: String,
}

/// Go `RecordConsumeLog`（store_log.go:374-439）。
///
/// 返回写入错误供调用方记日志（Go 记 `failed to record log` 后继续）；
/// `LogQuotaData` 只进内存缓存，落库由 [`usedata::save_quota_data_cache`]
/// 完成（Go `SaveQuotaDataCache` 定时器）。
pub async fn record_consume_log(
    db: &Database,
    context: &ConsumeLogContext,
    params: &RecordConsumeLogParams,
) -> Result<(), sqlx::Error> {
    if !context.consume_enabled {
        return Ok(());
    }
    let created_at = chrono::Utc::now().timestamp();
    let log = LogInsert {
        user_id: user_id_of(context),
        username: context.username.clone(),
        created_at,
        log_type: LOG_TYPE_CONSUME,
        content: params.content.clone(),
        prompt_tokens: params.prompt_tokens,
        completion_tokens: params.completion_tokens,
        token_name: params.token_name.clone(),
        model_name: params.model_name.clone(),
        quota: params.quota,
        channel_id: params.channel_id,
        token_id: params.token_id,
        use_time: params.use_time_seconds,
        is_stream: params.is_stream,
        group: params.group.clone(),
        ip: if context.record_ip {
            context.client_ip.clone()
        } else {
            String::new()
        },
        request_id: context.request_id.clone(),
        upstream_request_id: context.upstream_request_id.clone(),
        other: map_to_json_str(&params.other),
    };
    insert_log(db, &log).await?;
    if context.data_export_enabled {
        usedata::log_quota_data(usedata::QuotaDataLogParams {
            user_id: user_id_of(context),
            username: context.username.clone(),
            model_name: params.model_name.clone(),
            quota: params.quota,
            created_at,
            token_used: params.prompt_tokens + params.completion_tokens,
            use_group: params.group.clone(),
            token_id: params.token_id,
            channel_id: params.channel_id,
            node_name: context.node_name.clone(),
        });
    }
    Ok(())
}

fn user_id_of(context: &ConsumeLogContext) -> i64 {
    context.user_id
}

/// Go `RecordErrorLog`（store_log.go:313-357）：type=5，token/quota 恒 0。
pub async fn record_error_log(
    db: &Database,
    context: &ConsumeLogContext,
    channel_id: i64,
    model_name: &str,
    token_name: &str,
    content: &str,
    token_id: i64,
    use_time_seconds: i64,
    is_stream: bool,
    group: &str,
    other: &Map<String, Value>,
) -> Result<(), sqlx::Error> {
    let log = LogInsert {
        user_id: user_id_of(context),
        username: context.username.clone(),
        created_at: chrono::Utc::now().timestamp(),
        log_type: LOG_TYPE_ERROR,
        content: content.to_owned(),
        token_name: token_name.to_owned(),
        model_name: model_name.to_owned(),
        channel_id,
        token_id,
        use_time: use_time_seconds,
        is_stream,
        group: group.to_owned(),
        ip: if context.record_ip {
            context.client_ip.clone()
        } else {
            String::new()
        },
        request_id: context.request_id.clone(),
        upstream_request_id: context.upstream_request_id.clone(),
        other: map_to_json_str(other),
    };
    insert_log(db, &log).await
}

/// Go `RecordLog`（store_log.go:146-162）。`consume_enabled` 对应
/// `common.LogConsumeEnabled`（type=2 时被吞）。
pub async fn record_log(
    db: &Database,
    username: &str,
    user_id: i64,
    log_type: i64,
    content: &str,
    consume_enabled: bool,
) -> Result<(), sqlx::Error> {
    if log_type == LOG_TYPE_CONSUME && !consume_enabled {
        return Ok(());
    }
    insert_log(
        db,
        &LogInsert {
            user_id,
            username: username.to_owned(),
            created_at: chrono::Utc::now().timestamp(),
            log_type,
            content: content.to_owned(),
            ..LogInsert::default()
        },
    )
    .await
}

/// Go `RecordLogWithAdminInfo`（store_log.go:165-186）：admin_info 写入
/// `other.admin_info`，普通用户查询端（`formatUserLogs`）会剥离该键。
pub async fn record_log_with_admin_info(
    db: &Database,
    username: &str,
    user_id: i64,
    log_type: i64,
    content: &str,
    admin_info: &Map<String, Value>,
    consume_enabled: bool,
) -> Result<(), sqlx::Error> {
    if log_type == LOG_TYPE_CONSUME && !consume_enabled {
        return Ok(());
    }
    let mut other = Map::new();
    if !admin_info.is_empty() {
        other.insert("admin_info".to_owned(), Value::Object(admin_info.clone()));
    }
    insert_log(
        db,
        &LogInsert {
            user_id,
            username: username.to_owned(),
            created_at: chrono::Utc::now().timestamp(),
            log_type,
            content: content.to_owned(),
            other: map_to_json_str(&other),
            ..LogInsert::default()
        },
    )
    .await
}

/// Go `buildOpField`（store_log.go:191-199）：语言无关的操作描述，写入
/// `other.op`。`params` 为空时不带 `params` 键。
pub fn build_op_field(action: &str, params: &Map<String, Value>) -> Map<String, Value> {
    let mut op = Map::new();
    op.insert("action".to_owned(), Value::String(action.to_owned()));
    if !params.is_empty() {
        op.insert("params".to_owned(), Value::Object(params.clone()));
    }
    op
}

fn merge_extra(extra: &Map<String, Value>, op: Map<String, Value>) -> Map<String, Value> {
    let mut other: Map<String, Value> = extra.clone();
    other.insert("op".to_owned(), Value::Object(op));
    other
}

/// Go `RecordLoginLog`（store_log.go:205-223）：type=7，extra 中的键保留，
/// `op` 键后写（Go 中 op 覆盖 extra 同名键）。
pub async fn record_login_log(
    db: &Database,
    user_id: i64,
    username: &str,
    content: &str,
    ip: &str,
    action: &str,
    params: &Map<String, Value>,
    extra: &Map<String, Value>,
) -> Result<(), sqlx::Error> {
    let other = merge_extra(extra, build_op_field(action, params));
    insert_log(
        db,
        &LogInsert {
            user_id,
            username: username.to_owned(),
            created_at: chrono::Utc::now().timestamp(),
            log_type: LOG_TYPE_LOGIN,
            content: content.to_owned(),
            ip: ip.to_owned(),
            other: map_to_json_str(&other),
            ..LogInsert::default()
        },
    )
    .await
}

/// Go `RecordOperationAuditLog`（store_log.go:231-254）：type=3，
/// admin_info/audit_info 均为空对象时省键。
pub async fn record_operation_audit_log(
    db: &Database,
    log_user_id: i64,
    username: &str,
    content: &str,
    ip: &str,
    action: &str,
    params: &Map<String, Value>,
    admin_info: &Map<String, Value>,
    audit_info: &Map<String, Value>,
) -> Result<(), sqlx::Error> {
    let mut other = Map::new();
    other.insert(
        "op".to_owned(),
        Value::Object(build_op_field(action, params)),
    );
    if !admin_info.is_empty() {
        other.insert("admin_info".to_owned(), Value::Object(admin_info.clone()));
    }
    if !audit_info.is_empty() {
        other.insert("audit_info".to_owned(), Value::Object(audit_info.clone()));
    }
    insert_log(
        db,
        &LogInsert {
            user_id: log_user_id,
            username: username.to_owned(),
            created_at: chrono::Utc::now().timestamp(),
            log_type: LOG_TYPE_MANAGE,
            content: content.to_owned(),
            ip: ip.to_owned(),
            other: map_to_json_str(&other),
            ..LogInsert::default()
        },
    )
    .await
}

/// Go `RecordSensitiveAuditLog`（store_log.go:260-283）：type=8，
/// op.action 恒 `sensitive_block`。
pub async fn record_sensitive_audit_log(
    db: &Database,
    user_id: i64,
    username: &str,
    content: &str,
    ip: &str,
    params: &Map<String, Value>,
) -> Result<(), sqlx::Error> {
    let other = build_op_field("sensitive_block", params);
    insert_log(
        db,
        &LogInsert {
            user_id,
            username: username.to_owned(),
            created_at: chrono::Utc::now().timestamp(),
            log_type: LOG_TYPE_SENSITIVE,
            content: content.to_owned(),
            ip: ip.to_owned(),
            other: map_to_json_str(&other),
            ..LogInsert::default()
        },
    )
    .await
}

/// Go `RecordTopupLog` 的 admin_info 字段（store_log.go:287-294）。
#[derive(Debug, Clone, Default)]
pub struct TopupAdminInfo {
    pub server_ip: String,
    pub node_name: String,
    pub caller_ip: String,
    pub payment_method: String,
    pub callback_payment_method: String,
    pub version: String,
}

/// Go `RecordTopupLog`（store_log.go:285-311）：type=1，other 只有 admin_info。
pub async fn record_topup_log(
    db: &Database,
    user_id: i64,
    username: &str,
    content: &str,
    admin_info: &TopupAdminInfo,
) -> Result<(), sqlx::Error> {
    let mut info = Map::new();
    info.insert(
        "server_ip".to_owned(),
        Value::String(admin_info.server_ip.clone()),
    );
    info.insert(
        "node_name".to_owned(),
        Value::String(admin_info.node_name.clone()),
    );
    info.insert(
        "caller_ip".to_owned(),
        Value::String(admin_info.caller_ip.clone()),
    );
    info.insert(
        "payment_method".to_owned(),
        Value::String(admin_info.payment_method.clone()),
    );
    info.insert(
        "callback_payment_method".to_owned(),
        Value::String(admin_info.callback_payment_method.clone()),
    );
    info.insert(
        "version".to_owned(),
        Value::String(admin_info.version.clone()),
    );
    let mut other = Map::new();
    other.insert("admin_info".to_owned(), Value::Object(info));
    insert_log(
        db,
        &LogInsert {
            user_id,
            username: username.to_owned(),
            created_at: chrono::Utc::now().timestamp(),
            log_type: LOG_TYPE_TOPUP,
            content: content.to_owned(),
            other: map_to_json_str(&other),
            ..LogInsert::default()
        },
    )
    .await
}

/// Go `RecordTaskBillingLogParams`（store_log.go:441-452）。`username`/
/// `token_name` 由调用方回填（见模块头偏差说明）。
#[derive(Debug, Clone, Default)]
pub struct TaskBillingLogParams {
    pub log_type: i64,
    pub content: String,
    pub channel_id: i64,
    pub model_name: String,
    pub quota: i64,
    pub token_id: i64,
    pub group: String,
    pub other: Map<String, Value>,
    pub node_name: String,
}

/// Go `RecordTaskBillingLog`（store_log.go:454-483）。
pub async fn record_task_billing_log(
    db: &Database,
    user_id: i64,
    username: &str,
    token_name: &str,
    params: &TaskBillingLogParams,
    consume_enabled: bool,
    data_export_enabled: bool,
    default_node_name: &str,
) -> Result<(), sqlx::Error> {
    if params.log_type == LOG_TYPE_CONSUME && !consume_enabled {
        return Ok(());
    }
    let created_at = chrono::Utc::now().timestamp();
    insert_log(
        db,
        &LogInsert {
            user_id,
            username: username.to_owned(),
            created_at,
            log_type: params.log_type,
            content: params.content.clone(),
            token_name: token_name.to_owned(),
            model_name: params.model_name.clone(),
            quota: params.quota,
            channel_id: params.channel_id,
            token_id: params.token_id,
            group: params.group.clone(),
            other: map_to_json_str(&params.other),
            ..LogInsert::default()
        },
    )
    .await?;
    if params.log_type == LOG_TYPE_CONSUME && data_export_enabled {
        let node_name = if params.node_name.is_empty() {
            default_node_name.to_owned()
        } else {
            params.node_name.clone()
        };
        usedata::log_quota_data(usedata::QuotaDataLogParams {
            user_id,
            username: username.to_owned(),
            model_name: params.model_name.clone(),
            quota: params.quota,
            created_at,
            token_used: 0,
            use_group: params.group.clone(),
            token_id: params.token_id,
            channel_id: params.channel_id,
            node_name,
        });
    }
    Ok(())
}

/// 契约辅助：用读取端同列白名单取回一行，验证写入形态与读取端兼容。
pub async fn read_back(db: &Database, id: i64) -> Result<Option<LogInsert>, sqlx::Error> {
    let select = "SELECT CAST(id AS BIGINT) AS id, CAST(user_id AS BIGINT) AS user_id, \
        CAST(created_at AS BIGINT) AS created_at, CAST(\"type\" AS BIGINT) AS \"type\", \
        content, username, token_name, model_name, CAST(quota AS BIGINT) AS quota, \
        CAST(prompt_tokens AS BIGINT) AS prompt_tokens, \
        CAST(completion_tokens AS BIGINT) AS completion_tokens, \
        CAST(use_time AS BIGINT) AS use_time, is_stream, \
        CAST(channel_id AS BIGINT) AS channel_id, CAST(token_id AS BIGINT) AS token_id, \
        \"group\", ip, request_id, upstream_request_id, other FROM logs WHERE id = ";
    let row = match db {
        Database::Sqlite(pool) => {
            let sql = format!("{select}?1");
            sqlx::query(&sql).bind(id).fetch_optional(pool).await?
        }
        Database::Postgres(pool) => {
            let sql = format!("{select}$1");
            sqlx::query(&sql).bind(id).fetch_optional(pool).await?
        }
    };
    let Some(row) = row else { return Ok(None) };
    let get = |name: &str| -> Result<String, sqlx::Error> {
        Ok(row.try_get::<Option<String>, _>(name)?.unwrap_or_default())
    };
    let get_i64 = |name: &str| -> Result<i64, sqlx::Error> {
        Ok(row.try_get::<Option<i64>, _>(name)?.unwrap_or_default())
    };
    Ok(Some(LogInsert {
        user_id: get_i64("user_id")?,
        created_at: get_i64("created_at")?,
        log_type: get_i64("type")?,
        content: get("content")?,
        username: get("username")?,
        token_name: get("token_name")?,
        model_name: get("model_name")?,
        quota: get_i64("quota")?,
        prompt_tokens: get_i64("prompt_tokens")?,
        completion_tokens: get_i64("completion_tokens")?,
        use_time: get_i64("use_time")?,
        is_stream: row
            .try_get::<Option<bool>, _>("is_stream")?
            .unwrap_or_default(),
        channel_id: get_i64("channel_id")?,
        token_id: get_i64("token_id")?,
        group: get("group")?,
        ip: get("ip")?,
        request_id: get("request_id")?,
        upstream_request_id: get("upstream_request_id")?,
        other: get("other")?,
    }))
}
