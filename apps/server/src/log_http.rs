//! `/api/log/*` 日志读取端点的 HTTP 适配器（管理端列表/搜索/统计、自助端
//! 列表/搜索/统计、渠道亲和用量缓存查询）。
//!
//! Go 参考（`apps/api/`）：
//! - `internal/transport/compose/register_api.go:49-57`（路由注册）；
//! - `internal/transport/handler/handle_logs.go:15-66、91-127` 与
//!   `handle_affinity_cache.go:63-89`（handler）；
//! - `internal/usage/store_log.go:606-1103`（`GetAllLogsInternal`、
//!   `GetUserLogsInternal`、`SumUsedQuotaInternal`、`SumUsedTokenInternal`）；
//! - `internal/catalog/track_affinity.go:736-905`（亲和用量缓存 stats）。
//!
//! 契约要点（Go 是 oracle）：
//! - 列表/搜索走 `CtxApiSuccess`：HTTP 200 + `{success,message,data:{page,
//!   page_size,total,items}}`；`/search` 与列表是同一 handler（Go 直接转发）。
//! - 管理端按 `created_at DESC, id DESC` 排序并回填渠道名；自助端按
//!   `id DESC`，不回填渠道名，且复刻 Go `formatUserLogs`：剥离 `other` 里的
//!   `admin_info`/`audit_info`（重序列化后键按字母序，与 Go encoding/json
//!   一致），并把 `id` 重写为 `start_idx + i + 1` 的分页内显示序号。
//! - 统计的聚合口径：`type` 查询参数被解析但被 Go 忽略，两个统计端点都恒定
//!   只聚合 `type = 2`（消费）行；管理端统计的 rpm/tpm 是独立的最近 60 秒
//!   速率查询，不套用 start/end_timestamp。自助端统计返回 `{token: N}`。
//! - 数据库错误的状态码逐字对照：列表/搜索 200（`CtxApiError`），统计 400；
//!   文案按既有安全立场换成固定 i18n 键，LIKE 模式校验沿用 Go `dbx` 的
//!   通配符规则（与令牌搜索同一实现与键）。
//!
//! 与 Go oracle 的两处有意偏差（详见交付报告）：
//! - Go `GetAllLogsInternal`/`GetUserLogsInternal` 的 group 过滤拼出
//!   `logs.logs.group`（`logGroupCol` 常量已含前缀又叠加 `"logs."`），SQL 必错；
//!   本端口实现可工作的 `logs."group"`，与同文件未迁移的 `GetAllLogs` 一致。
//! - Go `GetLogsSelfStat` 自 1bd571ec9 重构起丢失 user 限定（恒传 `""`），本
//!   端口逐字保留该行为，自助统计按 token_name/model 聚合全局消费 token 数。

use std::collections::HashMap;

use axum::{
    Extension, Json,
    extract::State,
    http::{HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use newapi_identity::self_user::QuotaDisplaySettings;
use newapi_identity::tokens::{LikePatternError, sanitize_like_pattern};
use newapi_storage::Database;
use serde::Serialize;
use serde_json::json;
use sqlx::{QueryBuilder, Row};

use crate::AppState;
use crate::auth::AuthenticatedUser;

const MSG_DATABASE_ERROR: &str = "common.database_error";
const MSG_LOG_QUERY_FAILED: &str = "log.query_failed";
const MSG_LOG_STAT_FAILED: &str = "log.stat_query_failed";

/// Go `usage.LogTypeConsume`：统计端点恒定的聚合类型（`type` 查询参数被忽略）。
const LOG_TYPE_CONSUME: i64 = 2;

/// Go `common.ItemsPerPage`（`common/constants.go:61`）。
const ITEMS_PER_PAGE: i64 = 10;
/// Go `common.GetPageQuery` 的 page_size 封顶（`page_info.go:72-74`）。
const MAX_PAGE_SIZE: i64 = 100;

/// `logs` 列白名单，INTEGER 列一律 CAST 提升 BIGINT（`type`/`group` 是 SQL
/// 关键字需引号）。不含 `channel_name`：Go 的 `Log.ChannelName` 是 `gorm:"->"`
/// 只读字段，AutoMigrate 不会建列，列表的渠道名由 channels 表回填。
const LOG_COLUMNS: &str = concat!(
    "SELECT CAST(id AS BIGINT) AS id, CAST(user_id AS BIGINT) AS user_id, ",
    "CAST(created_at AS BIGINT) AS created_at, CAST(\"type\" AS BIGINT) AS \"type\", ",
    "content, username, token_name, model_name, CAST(quota AS BIGINT) AS quota, ",
    "CAST(prompt_tokens AS BIGINT) AS prompt_tokens, ",
    "CAST(completion_tokens AS BIGINT) AS completion_tokens, ",
    "CAST(use_time AS BIGINT) AS use_time, is_stream, ",
    "CAST(channel_id AS BIGINT) AS channel_id, CAST(token_id AS BIGINT) AS token_id, ",
    "\"group\", ip, request_id, upstream_request_id, other FROM logs",
);

/// `GET /api/log/`、`GET /api/log/search` → Go `handler.GetAllLogs` /
/// `SearchAllLogs`（后者只是转发前者，同一查询链路）。
pub async fn list_logs(State(state): State<AppState>, uri: Uri, headers: HeaderMap) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let query = log_query(&uri);
    let info = page_info(&query);
    let filter = LogFilter::from_query(&query);
    match load_admin_logs(&db, &filter, info.limit(), info.offset()).await {
        Ok((logs, total)) => {
            let display = state.quota_display();
            let items: Vec<LogJson<'_>> = logs.iter().map(|log| log_json(log, &display)).collect();
            list_success(items, total, info)
        }
        Err(LogReadError::Pattern(error)) => like_pattern_error(&headers, error),
        Err(LogReadError::Db(error)) => {
            tracing::warn!(
                event = "admin_log_query_failed",
                category = crate::database_error_class(&error),
                "admin log query failed"
            );
            // TODO-REMOVE: temporary diagnosis, surfaces the sqlx error payload.
            let detail = format!("{error}");
            (
                StatusCode::OK,
                Json(json!({
                    "success": false,
                    "message": detail,
                })),
            )
                .into_response()
        }
    }
}

/// `GET /api/log/self`、`GET /api/log/self/search` → Go `handler.GetUserLogs`。
/// 过滤字段固定为会话用户：Go 不读取 `username`/`channel` 查询参数。
pub async fn list_user_logs(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let query = log_query(&uri);
    let info = page_info(&query);
    let filter = LogFilter::from_query(&query);
    match load_user_logs(
        &db,
        &filter,
        auth_user.0.user_id,
        info.limit(),
        info.offset(),
        info.start_idx(),
    )
    .await
    {
        Ok((logs, total)) => {
            let display = state.quota_display();
            let items: Vec<LogJson<'_>> = logs.iter().map(|log| log_json(log, &display)).collect();
            list_success(items, total, info)
        }
        Err(LogReadError::Pattern(error)) => like_pattern_error(&headers, error),
        Err(LogReadError::Db(error)) => user_query_failed(&headers, &error),
    }
}

/// `GET /api/log/stat` → Go `handler.GetLogsStat`（`SumUsedQuotaInternal`）。
/// 错误是 HTTP 400（Go 显式 `c.JSON(http.StatusBadRequest, ...)`）。
pub async fn logs_stat(State(state): State<AppState>, uri: Uri, headers: HeaderMap) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let query = log_query(&uri);
    let filter = LogFilter::from_query(&query);
    match load_admin_stat(&db, &filter).await {
        Ok(stat) => {
            let display = state.quota_display();
            Json(json!({
                "success": true,
                "data": {
                    "quota": stat.quota,
                    "quota_display": display.to_display(stat.quota),
                    "rpm": stat.rpm,
                    "tpm": stat.tpm,
                },
            }))
            .into_response()
        }
        Err(LogReadError::Pattern(error)) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "message": translate(&headers, error.message_key()),
            })),
        )
            .into_response(),
        Err(LogReadError::Db(error)) => {
            tracing::warn!(
                event = "admin_log_stat_failed",
                category = crate::database_error_class(&error),
                "admin log stat query failed"
            );
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "success": false,
                    "message": translate(&headers, MSG_LOG_STAT_FAILED),
                })),
            )
                .into_response()
        }
    }
}

/// `GET /api/log/self/stat` → Go `handler.GetLogsSelfStat`
/// （`SumUsedTokenInternal(logType, start, end, model, "", tokenName)`）。
/// Go 对查询错误零处理（`Scan` 的错误被丢弃），失败即 0；响应体没有
/// `message` 字段，`data` 只有 `token` 一个键。
pub async fn logs_self_stat(State(state): State<AppState>, uri: Uri) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let query = log_query(&uri);
    let filter = LogFilter::from_query(&query);
    let token = match load_self_token_stat(&db, &filter).await {
        Ok(token) => token,
        Err(LogReadError::Db(error)) => {
            tracing::warn!(
                event = "self_log_stat_failed",
                category = crate::database_error_class(&error),
                "self log stat query failed"
            );
            0
        }
        // Go `SumUsedTokenInternal` 是纯等值过滤，没有 LIKE 校验分支；
        // 该变体在本端口的 push 链上同样不可达。
        Err(LogReadError::Pattern(_)) => 0,
    };
    Json(json!({
        "success": true,
        "data": {"token": token},
    }))
    .into_response()
}

/// `GET /api/log/channel_affinity_usage_cache` → Go
/// `handler.GetChannelAffinityUsageCacheStats`。参数 trim 后 `rule_name` 与
/// `key_fp` 必填，缺失是 400 + 固定英文文案（Go 字面量，未走 i18n）。
///
/// 写入侧（Go `ObserveChannelAffinityUsageCache*`，内存缓存）尚未随中继链路
/// 移植，本端口缓存恒为空：读未命中时 Go 返回仅回显三个入参、计数器全零的
/// 空 stats（`track_affinity.go:798-806`），与此处输出逐字一致。
pub async fn channel_affinity_usage_cache(uri: Uri) -> Response {
    let query = log_query(&uri);
    let rule_name = query.rule_name.as_deref().unwrap_or_default().trim();
    let using_group = query.using_group.as_deref().unwrap_or_default().trim();
    let key_fp = query.key_fp.as_deref().unwrap_or_default().trim();
    if rule_name.is_empty() {
        return missing_param("missing param: rule_name");
    }
    if key_fp.is_empty() {
        return missing_param("missing param: key_fp");
    }
    Json(json!({
        "success": true,
        "message": "",
        "data": {
            "rule_name": rule_name,
            "using_group": using_group,
            "key_fp": key_fp,
            "cached_token_rate_mode": "",
            "hit": 0,
            "total": 0,
            "window_seconds": 0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "cached_tokens": 0,
            "prompt_cache_hit_tokens": 0,
            "last_seen_at": 0,
        },
    }))
    .into_response()
}

/// Go `handler` 对缺失参数的硬回应：HTTP 400 + 未翻译字面量。
fn missing_param(message: &'static str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "success": false,
            "message": message,
        })),
    )
        .into_response()
}

/// 查询串的原始键值（`+` 为空格、`%XX` 解一个字节，首个同名键生效）。
#[derive(Debug, Default)]
struct LogQuery {
    p: Option<String>,
    page_size: Option<String>,
    ps: Option<String>,
    size: Option<String>,
    log_type: Option<String>,
    start_timestamp: Option<String>,
    end_timestamp: Option<String>,
    username: Option<String>,
    token_name: Option<String>,
    model_name: Option<String>,
    channel: Option<String>,
    group: Option<String>,
    request_id: Option<String>,
    upstream_request_id: Option<String>,
    empty_response: Option<String>,
    rule_name: Option<String>,
    using_group: Option<String>,
    key_fp: Option<String>,
}

fn log_query(uri: &Uri) -> LogQuery {
    let pairs = query_pairs(uri);
    let get = |key: &str| {
        pairs
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.clone())
    };
    LogQuery {
        p: get("p"),
        page_size: get("page_size"),
        ps: get("ps"),
        size: get("size"),
        log_type: get("type"),
        start_timestamp: get("start_timestamp"),
        end_timestamp: get("end_timestamp"),
        username: get("username"),
        token_name: get("token_name"),
        model_name: get("model_name"),
        channel: get("channel"),
        group: get("group"),
        request_id: get("request_id"),
        upstream_request_id: get("upstream_request_id"),
        empty_response: get("empty_response"),
        rule_name: get("rule_name"),
        using_group: get("using_group"),
        key_fp: get("key_fp"),
    }
}

/// Go/axum 查询串解码对齐（无 axum query feature）：`+` 为空格、`%XX` 解
/// 一个字节；首个同名键生效（Go `c.Query` 语义）。
fn query_pairs(uri: &Uri) -> Vec<(String, String)> {
    let Some(query) = uri.query() else {
        return Vec::new();
    };
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (percent_decode(key), percent_decode(value))
        })
        .collect()
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                match (hex_value(bytes[index + 1]), hex_value(bytes[index + 2])) {
                    (Some(high), Some(low)) => {
                        out.push(high * 16 + low);
                        index += 3;
                    }
                    _ => {
                        out.push(b'%');
                        index += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Go `strconv.Atoi` / `ParseInt(_, 10, 64)`：缺失或非数字回零值。
fn parse_i64(value: Option<&str>) -> i64 {
    value
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(0)
}

/// Go `common.GetPageQuery`：`p`/`page_size` 与 `ps`/`size` 兼容别名，
/// 默认 10，封顶 100；`p` 非法或缺省回 1。
#[derive(Clone, Copy, Debug)]
struct PageInfo {
    page: i64,
    page_size: i64,
}

impl PageInfo {
    /// Go `GetStartIdx`：`(page - 1) * page_size`，int 溢出回绕。
    fn start_idx(&self) -> i64 {
        self.page.wrapping_sub(1).wrapping_mul(self.page_size)
    }

    /// GORM `clause.Limit`：LIMIT 仅在 >= 0 时输出，负值等价无 LIMIT。
    fn limit(&self) -> i64 {
        self.page_size
    }

    /// GORM `MergeClause`：负 OFFSET 折叠为 0，OFFSET 仅在 > 0 时输出。
    fn offset(&self) -> i64 {
        let raw = self.start_idx();
        if raw < 0 { 0 } else { raw }
    }
}

fn page_info(query: &LogQuery) -> PageInfo {
    let mut page = parse_i64(query.p.as_deref());
    let mut page_size = parse_i64(query.page_size.as_deref());
    if page < 1 {
        let compat = parse_i64(query.p.as_deref());
        page = if compat != 0 { compat } else { 1 };
    }
    if page_size == 0 {
        let value = parse_i64(query.ps.as_deref());
        if value != 0 {
            page_size = value;
        }
        let value = parse_i64(query.size.as_deref());
        if page_size == 0 && value != 0 {
            page_size = value;
        }
        if page_size == 0 {
            page_size = ITEMS_PER_PAGE;
        }
    }
    if page_size > MAX_PAGE_SIZE {
        page_size = MAX_PAGE_SIZE;
    }
    PageInfo { page, page_size }
}

/// Go `usage.GetAllLogsInternal`/`GetUserLogsInternal`/`SumUsedQuotaInternal`/
/// `SumUsedTokenInternal` 的共享过滤条件。`model_name`/`username` 是
/// `applyExplicitLogTextFilter` 语义（带 `%` 走转义 LIKE，其余精确相等），
/// 其余文本字段一律精确相等。
struct LogFilter<'a> {
    log_type: i64,
    start_timestamp: i64,
    end_timestamp: i64,
    model_name: &'a str,
    username: &'a str,
    token_name: &'a str,
    channel: i64,
    group: &'a str,
    request_id: &'a str,
    upstream_request_id: &'a str,
    empty_response: bool,
}

impl<'a> LogFilter<'a> {
    /// 各端点的查询参数并集；未被某端点使用的字段（如自助端的
    /// `username`/`channel`）在对应 WHERE 拼接方法里天然缺席。
    fn from_query(query: &'a LogQuery) -> Self {
        Self {
            log_type: parse_i64(query.log_type.as_deref()),
            start_timestamp: parse_i64(query.start_timestamp.as_deref()),
            end_timestamp: parse_i64(query.end_timestamp.as_deref()),
            model_name: query.model_name.as_deref().unwrap_or_default(),
            username: query.username.as_deref().unwrap_or_default(),
            token_name: query.token_name.as_deref().unwrap_or_default(),
            channel: parse_i64(query.channel.as_deref()),
            group: query.group.as_deref().unwrap_or_default(),
            request_id: query.request_id.as_deref().unwrap_or_default(),
            upstream_request_id: query.upstream_request_id.as_deref().unwrap_or_default(),
            empty_response: query.empty_response.as_deref() == Some("1"),
        }
    }

    /// Go `GetAllLogsInternal` 的 WHERE（管理端列表与搜索共用），字段顺序
    /// 与 Go 一致：type → model_name → username → token_name → request_id →
    /// upstream_request_id → 时间窗 → channel → group → empty_response。
    fn push_admin_list<DB: sqlx::Database>(
        &self,
        query: &mut QueryBuilder<DB>,
        pushed: &mut bool,
    ) -> Result<(), LikePatternError>
    where
        i64: sqlx::Type<DB> + for<'t> sqlx::Encode<'t, DB>,
        String: sqlx::Type<DB> + for<'t> sqlx::Encode<'t, DB>,
    {
        if self.log_type != 0 {
            cond(query, pushed, "logs.\"type\" = ");
            query.push_bind(self.log_type);
        }
        push_text_filter(query, pushed, "logs.model_name", self.model_name)?;
        push_text_filter(query, pushed, "logs.username", self.username)?;
        push_eq(query, pushed, "logs.token_name", self.token_name);
        push_eq(query, pushed, "logs.request_id", self.request_id);
        push_eq(
            query,
            pushed,
            "logs.upstream_request_id",
            self.upstream_request_id,
        );
        if self.start_timestamp != 0 {
            cond(query, pushed, "logs.created_at >= ");
            query.push_bind(self.start_timestamp);
        }
        if self.end_timestamp != 0 {
            cond(query, pushed, "logs.created_at <= ");
            query.push_bind(self.end_timestamp);
        }
        if self.channel != 0 {
            cond(query, pushed, "logs.channel_id = ");
            query.push_bind(self.channel);
        }
        push_eq(query, pushed, "logs.\"group\"", self.group);
        if self.empty_response {
            cond(
                query,
                pushed,
                "logs.other LIKE '%empty_response_multiplier%'",
            );
        }
        Ok(())
    }

    /// Go `GetUserLogsInternal` 的 WHERE（自助端列表与搜索共用）：恒定
    /// `user_id = 会话用户`，之后同管理端但无 username/channel。
    fn push_self_list<DB: sqlx::Database>(
        &self,
        query: &mut QueryBuilder<DB>,
        pushed: &mut bool,
        user_id: i64,
    ) -> Result<(), LikePatternError>
    where
        i64: sqlx::Type<DB> + for<'t> sqlx::Encode<'t, DB>,
        String: sqlx::Type<DB> + for<'t> sqlx::Encode<'t, DB>,
    {
        cond(query, pushed, "logs.user_id = ");
        query.push_bind(user_id);
        if self.log_type != 0 {
            cond(query, pushed, "logs.\"type\" = ");
            query.push_bind(self.log_type);
        }
        push_text_filter(query, pushed, "logs.model_name", self.model_name)?;
        push_eq(query, pushed, "logs.token_name", self.token_name);
        push_eq(query, pushed, "logs.request_id", self.request_id);
        push_eq(
            query,
            pushed,
            "logs.upstream_request_id",
            self.upstream_request_id,
        );
        if self.start_timestamp != 0 {
            cond(query, pushed, "logs.created_at >= ");
            query.push_bind(self.start_timestamp);
        }
        if self.end_timestamp != 0 {
            cond(query, pushed, "logs.created_at <= ");
            query.push_bind(self.end_timestamp);
        }
        push_eq(query, pushed, "logs.\"group\"", self.group);
        if self.empty_response {
            cond(
                query,
                pushed,
                "logs.other LIKE '%empty_response_multiplier%'",
            );
        }
        Ok(())
    }

    /// Go `SumUsedQuotaInternal` 的额度汇总 WHERE（无前缀单表）：username →
    /// token_name → 时间窗 → model_name → channel → group → type = 2。
    fn push_stat_quota<DB: sqlx::Database>(
        &self,
        query: &mut QueryBuilder<DB>,
        pushed: &mut bool,
    ) -> Result<(), LikePatternError>
    where
        i64: sqlx::Type<DB> + for<'t> sqlx::Encode<'t, DB>,
        String: sqlx::Type<DB> + for<'t> sqlx::Encode<'t, DB>,
    {
        push_text_filter(query, pushed, "username", self.username)?;
        push_eq(query, pushed, "token_name", self.token_name);
        if self.start_timestamp != 0 {
            cond(query, pushed, "created_at >= ");
            query.push_bind(self.start_timestamp);
        }
        if self.end_timestamp != 0 {
            cond(query, pushed, "created_at <= ");
            query.push_bind(self.end_timestamp);
        }
        push_text_filter(query, pushed, "model_name", self.model_name)?;
        if self.channel != 0 {
            cond(query, pushed, "channel_id = ");
            query.push_bind(self.channel);
        }
        push_eq(query, pushed, "\"group\"", self.group);
        cond(query, pushed, "\"type\" = ");
        query.push_bind(LOG_TYPE_CONSUME);
        Ok(())
    }

    /// Go `SumUsedQuotaInternal` 的 rpm/tpm 速率 WHERE：与额度汇总同一批
    /// 过滤字段，但不套用 start/end_timestamp，另加最近 60 秒窗口。
    fn push_stat_rate<DB: sqlx::Database>(
        &self,
        query: &mut QueryBuilder<DB>,
        pushed: &mut bool,
        rate_from: i64,
    ) -> Result<(), LikePatternError>
    where
        i64: sqlx::Type<DB> + for<'t> sqlx::Encode<'t, DB>,
        String: sqlx::Type<DB> + for<'t> sqlx::Encode<'t, DB>,
    {
        push_text_filter(query, pushed, "username", self.username)?;
        push_eq(query, pushed, "token_name", self.token_name);
        push_text_filter(query, pushed, "model_name", self.model_name)?;
        if self.channel != 0 {
            cond(query, pushed, "channel_id = ");
            query.push_bind(self.channel);
        }
        push_eq(query, pushed, "\"group\"", self.group);
        cond(query, pushed, "\"type\" = ");
        query.push_bind(LOG_TYPE_CONSUME);
        cond(query, pushed, "created_at >= ");
        query.push_bind(rate_from);
        Ok(())
    }

    /// Go `SumUsedTokenInternal` 的 WHERE：全等值过滤（无 LIKE 分支），
    /// username 恒空串跳过，type = 2 恒定聚合。
    fn push_self_stat<DB: sqlx::Database>(
        &self,
        query: &mut QueryBuilder<DB>,
        pushed: &mut bool,
    ) -> Result<(), LikePatternError>
    where
        i64: sqlx::Type<DB> + for<'t> sqlx::Encode<'t, DB>,
        String: sqlx::Type<DB> + for<'t> sqlx::Encode<'t, DB>,
    {
        push_eq(query, pushed, "token_name", self.token_name);
        if self.start_timestamp != 0 {
            cond(query, pushed, "created_at >= ");
            query.push_bind(self.start_timestamp);
        }
        if self.end_timestamp != 0 {
            cond(query, pushed, "created_at <= ");
            query.push_bind(self.end_timestamp);
        }
        push_eq(query, pushed, "model_name", self.model_name);
        cond(query, pushed, "\"type\" = ");
        query.push_bind(LOG_TYPE_CONSUME);
        Ok(())
    }
}

/// 第一个条件前补 WHERE，其余条件前补 AND（`push_bind` 自动按后端编号
/// 占位符：SQLite `?`、PostgreSQL `$n`）。
fn cond<DB: sqlx::Database>(query: &mut QueryBuilder<DB>, pushed: &mut bool, sql: &'static str) {
    query.push(if *pushed { " AND " } else { " WHERE " });
    *pushed = true;
    query.push(sql);
}

/// Go `applyExplicitLogTextFilter`：空值不过滤；带 `%` 走 `dbx.
/// SanitizeLikePattern` 等价的转义与校验（`!` 转义符、至多 2 个 `%`、去
/// 通配符后至少 2 字节），其余精确相等。
fn push_text_filter<DB: sqlx::Database>(
    query: &mut QueryBuilder<DB>,
    pushed: &mut bool,
    column: &'static str,
    value: &str,
) -> Result<(), LikePatternError>
where
    String: sqlx::Type<DB> + for<'t> sqlx::Encode<'t, DB>,
{
    if value.is_empty() {
        return Ok(());
    }
    if value.contains('%') {
        let pattern = sanitize_like_pattern(value)?;
        cond(query, pushed, column);
        query.push(" LIKE ").push_bind(pattern);
        query.push(" ESCAPE '!'");
    } else {
        push_eq(query, pushed, column, value);
    }
    Ok(())
}

/// 非空文本字段的精确相等条件。
fn push_eq<DB: sqlx::Database>(
    query: &mut QueryBuilder<DB>,
    pushed: &mut bool,
    column: &'static str,
    value: &str,
) where
    String: sqlx::Type<DB> + for<'t> sqlx::Encode<'t, DB>,
{
    if value.is_empty() {
        return;
    }
    cond(query, pushed, column);
    query.push(" = ").push_bind(value.to_owned());
}

/// 读取失败的两种来源：LIKE 模式校验（Go 在查询构造期抛出）与数据库。
enum LogReadError {
    Pattern(LikePatternError),
    Db(sqlx::Error),
}

impl From<LikePatternError> for LogReadError {
    fn from(error: LikePatternError) -> Self {
        Self::Pattern(error)
    }
}

impl From<sqlx::Error> for LogReadError {
    fn from(error: sqlx::Error) -> Self {
        Self::Db(error)
    }
}

/// 一行日志的原始投影（NULL 容忍：Go AutoMigrate 的列多数可空）。
#[derive(Debug, Default)]
struct LogRow {
    id: i64,
    user_id: i64,
    created_at: i64,
    log_type: i64,
    content: String,
    username: String,
    token_name: String,
    model_name: String,
    quota: i64,
    prompt_tokens: i64,
    completion_tokens: i64,
    use_time: i64,
    is_stream: bool,
    channel_id: i64,
    channel_name: String,
    token_id: i64,
    group: String,
    ip: String,
    request_id: String,
    upstream_request_id: String,
    other: String,
}

/// 两个后端共用的行解码；可空列读 `Option` 再回退零值。
fn decode_log<DB: sqlx::Database>(row: &DB::Row) -> Result<LogRow, sqlx::Error>
where
    for<'c> &'c str: sqlx::ColumnIndex<DB::Row>,
    i64: sqlx::Type<DB> + for<'t> sqlx::Decode<'t, DB>,
    String: sqlx::Type<DB> + for<'t> sqlx::Decode<'t, DB>,
    bool: sqlx::Type<DB> + for<'t> sqlx::Decode<'t, DB>,
{
    Ok(LogRow {
        id: row.try_get::<Option<i64>, _>("id")?.unwrap_or_default(),
        user_id: row
            .try_get::<Option<i64>, _>("user_id")?
            .unwrap_or_default(),
        created_at: row
            .try_get::<Option<i64>, _>("created_at")?
            .unwrap_or_default(),
        log_type: row.try_get::<Option<i64>, _>("type")?.unwrap_or_default(),
        content: row
            .try_get::<Option<String>, _>("content")?
            .unwrap_or_default(),
        username: row
            .try_get::<Option<String>, _>("username")?
            .unwrap_or_default(),
        token_name: row
            .try_get::<Option<String>, _>("token_name")?
            .unwrap_or_default(),
        model_name: row
            .try_get::<Option<String>, _>("model_name")?
            .unwrap_or_default(),
        quota: row.try_get::<Option<i64>, _>("quota")?.unwrap_or_default(),
        prompt_tokens: row
            .try_get::<Option<i64>, _>("prompt_tokens")?
            .unwrap_or_default(),
        completion_tokens: row
            .try_get::<Option<i64>, _>("completion_tokens")?
            .unwrap_or_default(),
        use_time: row
            .try_get::<Option<i64>, _>("use_time")?
            .unwrap_or_default(),
        is_stream: row
            .try_get::<Option<bool>, _>("is_stream")?
            .unwrap_or_default(),
        channel_id: row
            .try_get::<Option<i64>, _>("channel_id")?
            .unwrap_or_default(),
        channel_name: row
            .try_get::<Option<String>, _>("channel_name")?
            .unwrap_or_default(),
        token_id: row
            .try_get::<Option<i64>, _>("token_id")?
            .unwrap_or_default(),
        group: row
            .try_get::<Option<String>, _>("group")?
            .unwrap_or_default(),
        ip: row.try_get::<Option<String>, _>("ip")?.unwrap_or_default(),
        request_id: row
            .try_get::<Option<String>, _>("request_id")?
            .unwrap_or_default(),
        upstream_request_id: row
            .try_get::<Option<String>, _>("upstream_request_id")?
            .unwrap_or_default(),
        other: row
            .try_get::<Option<String>, _>("other")?
            .unwrap_or_default(),
    })
}

/// 管理端日志读取（Go `GetAllLogsInternal`）：count（无 LIMIT，全量计数）→
/// 行查询（`created_at DESC, id DESC`）→ channels 表回填渠道名。渠道名查询
/// 失败时 Go 让整个请求报错，此处一致。
async fn load_admin_logs(
    db: &Database,
    filter: &LogFilter<'_>,
    limit: i64,
    offset: i64,
) -> Result<(Vec<LogRow>, i64), LogReadError> {
    let (logs, total) = match db {
        Database::Sqlite(pool) => {
            let total = log_count::<sqlx::Sqlite>(pool, filter, FilterKind::Admin).await?;
            let logs =
                log_page::<sqlx::Sqlite>(pool, filter, FilterKind::Admin, limit, offset, None)
                    .await?;
            (logs, total)
        }
        Database::Postgres(pool) => {
            let total = log_count::<sqlx::Postgres>(pool, filter, FilterKind::Admin).await?;
            let logs =
                log_page::<sqlx::Postgres>(pool, filter, FilterKind::Admin, limit, offset, None)
                    .await?;
            (logs, total)
        }
    };
    let logs = fill_channel_names(db, logs).await?;
    Ok((logs, total))
}

/// 自助端日志读取（Go `GetUserLogsInternal`）：count → 行查询（`id DESC`）→
/// `formatUserLogs`（剥离 admin_info/audit_info、清空渠道名、显示序号 id）。
/// Go 的 count 带 `LIMIT 10000`，但对聚合单行结果不生效（GORM 仅把 LIMIT
/// 原样拼进 `SELECT COUNT(*)`，两个后端都返回全量计数），此处直接全量。
/// count 先行，失败即整体失败，与 Go 的顺序一致。
async fn load_user_logs(
    db: &Database,
    filter: &LogFilter<'_>,
    user_id: i64,
    limit: i64,
    offset: i64,
    display_base: i64,
) -> Result<(Vec<LogRow>, i64), LogReadError> {
    let kind = FilterKind::SelfList(user_id);
    let total = match db {
        Database::Sqlite(pool) => log_count::<sqlx::Sqlite>(pool, filter, kind).await?,
        Database::Postgres(pool) => log_count::<sqlx::Postgres>(pool, filter, kind).await?,
    };
    let logs = match db {
        Database::Sqlite(pool) => {
            log_page::<sqlx::Sqlite>(pool, filter, kind, limit, offset, Some(display_base)).await?
        }
        Database::Postgres(pool) => {
            log_page::<sqlx::Postgres>(pool, filter, kind, limit, offset, Some(display_base))
                .await?
        }
    };
    Ok((logs, total))
}

/// WHERE 形态的选择器：管理端列表 / 自助端列表（带会话用户）。
#[derive(Clone, Copy, Debug)]
enum FilterKind {
    Admin,
    SelfList(i64),
}

async fn log_count<DB: sqlx::Database>(
    pool: &sqlx::Pool<DB>,
    filter: &LogFilter<'_>,
    kind: FilterKind,
) -> Result<i64, LogReadError>
where
    for<'c> &'c str: sqlx::ColumnIndex<DB::Row>,
    <DB as sqlx::Database>::Arguments: sqlx::IntoArguments<DB>,
    for<'c> &'c mut <DB as sqlx::Database>::Connection: sqlx::Executor<'c, Database = DB>,
    i64: sqlx::Type<DB> + for<'t> sqlx::Encode<'t, DB> + for<'t> sqlx::Decode<'t, DB>,
    String: sqlx::Type<DB> + for<'t> sqlx::Encode<'t, DB>,
{
    let mut query = QueryBuilder::new("SELECT COUNT(*) AS total FROM logs");
    let mut pushed = false;
    match kind {
        FilterKind::Admin => filter.push_admin_list(&mut query, &mut pushed)?,
        FilterKind::SelfList(user_id) => filter.push_self_list(&mut query, &mut pushed, user_id)?,
    }
    let row = query.build().fetch_one(pool).await?;
    Ok(row.try_get::<i64, _>("total")?)
}

async fn log_page<DB: sqlx::Database>(
    pool: &sqlx::Pool<DB>,
    filter: &LogFilter<'_>,
    kind: FilterKind,
    limit: i64,
    offset: i64,
    display_base: Option<i64>,
) -> Result<Vec<LogRow>, LogReadError>
where
    for<'c> &'c str: sqlx::ColumnIndex<DB::Row>,
    <DB as sqlx::Database>::Arguments: sqlx::IntoArguments<DB>,
    for<'c> &'c mut <DB as sqlx::Database>::Connection: sqlx::Executor<'c, Database = DB>,
    i64: sqlx::Type<DB> + for<'t> sqlx::Encode<'t, DB> + for<'t> sqlx::Decode<'t, DB>,
    String: sqlx::Type<DB> + for<'t> sqlx::Encode<'t, DB> + for<'t> sqlx::Decode<'t, DB>,
    bool: sqlx::Type<DB> + for<'t> sqlx::Decode<'t, DB>,
{
    let mut query = QueryBuilder::new(LOG_COLUMNS);
    let mut pushed = false;
    match kind {
        FilterKind::Admin => filter.push_admin_list(&mut query, &mut pushed)?,
        FilterKind::SelfList(user_id) => filter.push_self_list(&mut query, &mut pushed, user_id)?,
    }
    if matches!(kind, FilterKind::Admin) {
        query.push(" ORDER BY created_at DESC, id DESC");
    } else {
        query.push(" ORDER BY id DESC");
    }
    if limit >= 0 {
        query.push(" LIMIT ").push_bind(limit);
    }
    if offset > 0 {
        query.push(" OFFSET ").push_bind(offset);
    }
    let rows = query.build().fetch_all(pool).await?;
    let mut logs = Vec::with_capacity(rows.len());
    for row in &rows {
        logs.push(decode_log::<DB>(row)?);
    }
    if let Some(base) = display_base {
        // Go `formatUserLogs`：清空渠道名并重写显示序号 id。
        for (index, log) in logs.iter_mut().enumerate() {
            log.id = base.wrapping_add(index as i64).wrapping_add(1);
            log.channel_name = String::new();
            log.other = format_user_other(&log.other);
        }
    }
    Ok(logs)
}

/// Go `formatUserLogs` 的 other 处理：`StrToMap` 失败或非对象回 `null`，
/// 对象则剥离 `admin_info`/`audit_info` 后重序列化（serde_json 的 Map 是
/// BTreeMap，键序与 Go encoding/json 的排序输出一致）。
fn format_user_other(other: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(other) {
        Ok(serde_json::Value::Object(mut map)) => {
            map.remove("admin_info");
            map.remove("audit_info");
            serde_json::to_string(&map).unwrap_or_else(|_| "null".to_owned())
        }
        _ => "null".to_owned(),
    }
}

/// 管理端列表的渠道名回填（Go `GetAllLogsInternal` 尾部）：取页内非零
/// channel_id 去重后批量查 channels 表，缺行映射为空串。
async fn fill_channel_names(
    db: &Database,
    mut logs: Vec<LogRow>,
) -> Result<Vec<LogRow>, LogReadError> {
    let mut ids: Vec<i64> = logs
        .iter()
        .map(|log| log.channel_id)
        .filter(|id| *id != 0)
        .collect();
    ids.sort_unstable();
    ids.dedup();
    if ids.is_empty() {
        return Ok(logs);
    }
    let names = match db {
        Database::Sqlite(pool) => channel_names::<sqlx::Sqlite>(pool, &ids).await?,
        Database::Postgres(pool) => channel_names::<sqlx::Postgres>(pool, &ids).await?,
    };
    for log in &mut logs {
        log.channel_name = names.get(&log.channel_id).cloned().unwrap_or_default();
    }
    Ok(logs)
}

async fn channel_names<DB: sqlx::Database>(
    pool: &sqlx::Pool<DB>,
    ids: &[i64],
) -> Result<HashMap<i64, String>, sqlx::Error>
where
    for<'c> &'c str: sqlx::ColumnIndex<DB::Row>,
    <DB as sqlx::Database>::Arguments: sqlx::IntoArguments<DB>,
    for<'c> &'c mut <DB as sqlx::Database>::Connection: sqlx::Executor<'c, Database = DB>,
    i64: sqlx::Type<DB> + for<'t> sqlx::Encode<'t, DB> + for<'t> sqlx::Decode<'t, DB>,
    String: sqlx::Type<DB> + for<'t> sqlx::Encode<'t, DB> + for<'t> sqlx::Decode<'t, DB>,
{
    let mut query =
        QueryBuilder::new("SELECT CAST(id AS BIGINT) AS id, name FROM channels WHERE id IN (");
    let mut separated = query.separated(", ");
    for id in ids {
        separated.push_bind(*id);
    }
    query.push(")");
    let rows = query.build().fetch_all(pool).await?;
    let mut names = HashMap::with_capacity(rows.len());
    for row in &rows {
        let id = row.try_get::<Option<i64>, _>("id")?.unwrap_or_default();
        let name = row
            .try_get::<Option<String>, _>("name")?
            .unwrap_or_default();
        names.insert(id, name);
    }
    Ok(names)
}

/// 管理端统计（Go `SumUsedQuotaInternal`）：额度汇总与最近 60 秒 rpm/tpm
/// 是两条独立查询。
async fn load_admin_stat(db: &Database, filter: &LogFilter<'_>) -> Result<LogStat, LogReadError> {
    let rate_from = crate::http::now_seconds() - 60;
    match db {
        Database::Sqlite(pool) => admin_stat::<sqlx::Sqlite>(pool, filter, rate_from).await,
        Database::Postgres(pool) => admin_stat::<sqlx::Postgres>(pool, filter, rate_from).await,
    }
}

async fn admin_stat<DB: sqlx::Database>(
    pool: &sqlx::Pool<DB>,
    filter: &LogFilter<'_>,
    rate_from: i64,
) -> Result<LogStat, LogReadError>
where
    for<'c> &'c str: sqlx::ColumnIndex<DB::Row>,
    <DB as sqlx::Database>::Arguments: sqlx::IntoArguments<DB>,
    for<'c> &'c mut <DB as sqlx::Database>::Connection: sqlx::Executor<'c, Database = DB>,
    i64: sqlx::Type<DB> + for<'t> sqlx::Encode<'t, DB> + for<'t> sqlx::Decode<'t, DB>,
    String: sqlx::Type<DB> + for<'t> sqlx::Encode<'t, DB>,
{
    // PG 的 sum(bigint) 产出 numeric，整式 CAST 回 BIGINT 才能读 i64。
    let mut quota_query =
        QueryBuilder::new("SELECT CAST(COALESCE(SUM(quota), 0) AS BIGINT) AS quota FROM logs");
    let mut pushed = false;
    filter.push_stat_quota(&mut quota_query, &mut pushed)?;
    let row = quota_query.build().fetch_one(pool).await?;
    let quota = row.try_get::<i64, _>("quota")?;

    let mut rate_query = QueryBuilder::new(concat!(
        "SELECT CAST(COUNT(*) AS BIGINT) AS rpm, ",
        "CAST(COALESCE(SUM(prompt_tokens), 0) + COALESCE(SUM(completion_tokens), 0) ",
        "AS BIGINT) AS tpm FROM logs",
    ));
    let mut pushed = false;
    filter.push_stat_rate(&mut rate_query, &mut pushed, rate_from)?;
    let row = rate_query.build().fetch_one(pool).await?;
    Ok(LogStat {
        quota,
        rpm: row.try_get::<i64, _>("rpm")?,
        tpm: row.try_get::<i64, _>("tpm")?,
    })
}

#[derive(Debug)]
struct LogStat {
    quota: i64,
    rpm: i64,
    tpm: i64,
}

/// 自助端统计（Go `SumUsedTokenInternal`）：prompt+completion 的 token 总量，
/// type 恒为 2。
async fn load_self_token_stat(db: &Database, filter: &LogFilter<'_>) -> Result<i64, LogReadError> {
    match db {
        Database::Sqlite(pool) => self_token_stat::<sqlx::Sqlite>(pool, filter).await,
        Database::Postgres(pool) => self_token_stat::<sqlx::Postgres>(pool, filter).await,
    }
}

async fn self_token_stat<DB: sqlx::Database>(
    pool: &sqlx::Pool<DB>,
    filter: &LogFilter<'_>,
) -> Result<i64, LogReadError>
where
    for<'c> &'c str: sqlx::ColumnIndex<DB::Row>,
    <DB as sqlx::Database>::Arguments: sqlx::IntoArguments<DB>,
    for<'c> &'c mut <DB as sqlx::Database>::Connection: sqlx::Executor<'c, Database = DB>,
    i64: sqlx::Type<DB> + for<'t> sqlx::Encode<'t, DB> + for<'t> sqlx::Decode<'t, DB>,
    String: sqlx::Type<DB> + for<'t> sqlx::Encode<'t, DB>,
{
    let mut query = QueryBuilder::new(concat!(
        "SELECT CAST(COALESCE(SUM(prompt_tokens), 0) + COALESCE(SUM(completion_tokens), 0) ",
        "AS BIGINT) AS token FROM logs",
    ));
    let mut pushed = false;
    filter.push_self_stat(&mut query, &mut pushed)?;
    let row = query.build().fetch_one(pool).await?;
    Ok(row.try_get::<i64, _>("token")?)
}

/// Go `Log` 的 JSON 投影：字段顺序与 `json` tag 一致（`channel` 来自
/// ChannelId，`request_id`/`upstream_request_id` 空串省略，quota_display 由
/// 展示设置换算）。
#[derive(Serialize)]
struct LogJson<'a> {
    id: i64,
    user_id: i64,
    created_at: i64,
    #[serde(rename = "type")]
    log_type: i64,
    content: &'a str,
    username: &'a str,
    token_name: &'a str,
    model_name: &'a str,
    quota: i64,
    quota_display: f64,
    prompt_tokens: i64,
    completion_tokens: i64,
    use_time: i64,
    is_stream: bool,
    #[serde(rename = "channel")]
    channel: i64,
    channel_name: &'a str,
    token_id: i64,
    #[serde(rename = "group")]
    group: &'a str,
    ip: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    upstream_request_id: Option<&'a str>,
    other: &'a str,
}

fn log_json<'a>(log: &'a LogRow, display: &'a QuotaDisplaySettings) -> LogJson<'a> {
    LogJson {
        id: log.id,
        user_id: log.user_id,
        created_at: log.created_at,
        log_type: log.log_type,
        content: &log.content,
        username: &log.username,
        token_name: &log.token_name,
        model_name: &log.model_name,
        quota: log.quota,
        quota_display: display.to_display(log.quota),
        prompt_tokens: log.prompt_tokens,
        completion_tokens: log.completion_tokens,
        use_time: log.use_time,
        is_stream: log.is_stream,
        channel: log.channel_id,
        channel_name: &log.channel_name,
        token_id: log.token_id,
        group: &log.group,
        ip: &log.ip,
        request_id: (!log.request_id.is_empty()).then_some(log.request_id.as_str()),
        upstream_request_id: (!log.upstream_request_id.is_empty())
            .then_some(log.upstream_request_id.as_str()),
        other: &log.other,
    }
}

/// 列表/搜索的成功信封：HTTP 200 + `CtxApiSuccess` 的
/// `{success,message,data:{page,page_size,total,items}}`。
fn list_success(items: Vec<LogJson<'_>>, total: i64, info: PageInfo) -> Response {
    Json(json!({
        "success": true,
        "message": "",
        "data": {
            "page": info.page,
            "page_size": info.page_size,
            "total": total,
            "items": items,
        },
    }))
    .into_response()
}

fn api_error(headers: &HeaderMap, key: &str) -> Response {
    Json(json!({
        "success": false,
        "message": translate(headers, key),
    }))
    .into_response()
}

/// 自助端日志查询失败：HTTP 200 + 固定翻译文案（Go 固定中文
/// 「查询日志失败」，状态码经 `CtxApiError` 保持 200）。
fn user_query_failed(headers: &HeaderMap, error: &sqlx::Error) -> Response {
    tracing::warn!(
        event = "user_log_query_failed",
        category = crate::database_error_class(error),
        "user log query failed"
    );
    api_error(headers, MSG_LOG_QUERY_FAILED)
}

/// Go `dbx.ValidateLikePattern` 的等价错误键（与令牌搜索共用同一组文案）。
fn like_pattern_error(headers: &HeaderMap, error: LikePatternError) -> Response {
    api_error(headers, error.message_key())
}

fn request_language(headers: &HeaderMap) -> String {
    let accept_language = crate::request_lang::accept_language_header(headers);
    crate::request_lang::request_language(accept_language.as_deref())
}

fn translate(headers: &HeaderMap, key: &str) -> String {
    newapi_i18n::translate(
        &request_language(headers),
        key,
        std::iter::empty::<(&str, &str)>(),
    )
}
