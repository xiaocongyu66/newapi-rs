//! 只读查询端点 `GET /api/log/token` 与 `GET /api/usage/token/` 的 HTTP 适配器。
//!
//! Go 参考（`apps/api/`）：
//! - `internal/security/authenticate.go:267-342`（`TokenAuthReadOnly`，由
//!   `apps/server/src/auth::token_auth_read_only` 实现）；
//! - `internal/transport/handler/handle_logs.go:68-89`（`GetLogByKey`）；
//! - `internal/identity/manage_tokens.go:196-243`（`GetTokenUsage`）；
//! - `internal/transport/compose/register_api.go:61、375-384`（路由注册）。
//!
//! 两条路由的鉴权失败体只有 success/message（无 code），与 Go 中间件一致。
//! handler 自身按 Go 逐分支对照：`GetLogByKey` 的 `token_id` 缺失/非数字是 400
//! 固定文案，成功是 200 + 日志数组（无分页，且不校验 token_id 与已认证令牌的
//! 归属，Go 亦如此）；`GetTokenUsage` 自身再解析一次 Authorization（恰好两段、
//! 大小写不敏感的 Bearer），令牌查无此行经 `CtxApiErrorI18n` 返回 200 翻译文案。
//!
//! Go 在数据库错误分支会回传 `err.Error()` 原文；本端口按既有安全立场改用固定
//! 翻译文案与分类日志事件，状态码保持一致。

use std::collections::BTreeMap;

use axum::{
    Json,
    extract::{State, Uri},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
};
use newapi_identity::tokens::{TokenRecord, TokenRepository};
use serde::Serialize;
use serde_json::{Value, json};
use sqlx::Row;

use crate::AppState;

const MSG_TOKEN_GET_INFO_FAILED: &str = "token.get_info_failed";
const MSG_DATABASE_ERROR: &str = "common.database_error";

/// Go `handler.GetLogByKey`（`handle_logs.go:68-89`）。
pub async fn log_by_token(State(state): State<AppState>, uri: Uri, headers: HeaderMap) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    // Go `strconv.Atoi(c.Query("token_id"))`：缺失或非数字一律 400 固定文案。
    let Some(token_id) = token_id_query(&uri)
        .as_deref()
        .and_then(|value| value.parse::<i64>().ok())
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "message": "invalid token id",
            })),
        )
            .into_response();
    };
    match load_logs(&db, token_id).await {
        Ok(logs) => {
            let display = state.quota_display();
            Json(json!({
                "success": true,
                "data": logs.iter().map(|log| log_json(log, &display)).collect::<Vec<_>>(),
            }))
            .into_response()
        }
        Err(error) => {
            tracing::warn!(
                event = "log_by_token_query_failed",
                category = crate::database_error_class(&error),
                "log by token query failed"
            );
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "success": false,
                    "message": translate(&headers, MSG_DATABASE_ERROR),
                })),
            )
                .into_response()
        }
    }
}

/// Go `identity.GetTokenUsage`（`manage_tokens.go:196-243`）。
pub async fn token_usage(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Some(authorization) = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return usage_error(StatusCode::UNAUTHORIZED, "No Authorization header");
    };
    // Go `strings.Split(authHeader, " ")`：恰好两段且首段 bearer（大小写不敏感）。
    let mut parts = authorization.split(' ');
    let scheme = parts.next().unwrap_or_default();
    let token = parts.next();
    if token.is_none() || parts.next().is_some() || !scheme.eq_ignore_ascii_case("bearer") {
        return usage_error(StatusCode::UNAUTHORIZED, "Invalid Bearer token");
    }
    // 这里不再按 `-` 切分（Go 只剥 sk- 前缀），与中间件的 key 规整故意不同。
    let raw = token.unwrap_or_default();
    let key = raw.strip_prefix("sk-").unwrap_or(raw);
    match TokenRepository::new(db).by_key(key).await {
        Ok(Some(record)) => usage_success(&record),
        // Go `GetTokenByKey` 的所有错误（含查无此行）都经 `CtxApiErrorI18n`
        // 返回 200 + token.get_info_failed（manage_tokens.go:216-221）。
        Ok(None) => usage_lookup_failure(&headers),
        Err(error) => {
            tracing::warn!(
                event = "token_usage_lookup_failed",
                category = crate::database_error_class(&error),
                "token usage lookup failed"
            );
            usage_lookup_failure(&headers)
        }
    }
}

#[derive(Debug)]
struct LogRecord {
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

// Go `Log` 的列白名单；PG 的 INTEGER 列一律 CAST 提升为 BIGINT（`type`/`group`
// 是 SQL 关键字，需要引号）。按 id 降序与 GORM `Order("id desc")` 一致。
const LOG_BY_TOKEN_SQL: &str = concat!(
    "SELECT CAST(id AS BIGINT) AS id, CAST(user_id AS BIGINT) AS user_id, ",
    "CAST(created_at AS BIGINT) AS created_at, CAST(\"type\" AS BIGINT) AS \"type\", ",
    "content, username, token_name, model_name, CAST(quota AS BIGINT) AS quota, ",
    "CAST(prompt_tokens AS BIGINT) AS prompt_tokens, ",
    "CAST(completion_tokens AS BIGINT) AS completion_tokens, ",
    "CAST(use_time AS BIGINT) AS use_time, is_stream, ",
    "CAST(channel_id AS BIGINT) AS channel_id, channel_name, ",
    "CAST(token_id AS BIGINT) AS token_id, \"group\", ip, ",
    "request_id, upstream_request_id, other ",
    "FROM logs WHERE token_id = $1 ORDER BY id DESC"
);

macro_rules! decode_log {
    ($row:expr) => {{
        let row = $row;
        LogRecord {
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
        }
    }};
}

async fn load_logs(
    db: &newapi_storage::Database,
    token_id: i64,
) -> Result<Vec<LogRecord>, sqlx::Error> {
    match db {
        newapi_storage::Database::Sqlite(pool) => {
            let mut logs = Vec::new();
            for row in sqlx::query(LOG_BY_TOKEN_SQL)
                .bind(token_id)
                .fetch_all(pool)
                .await?
            {
                logs.push(decode_log!(row));
            }
            Ok(logs)
        }
        newapi_storage::Database::Postgres(pool) => {
            let mut logs = Vec::new();
            for row in sqlx::query(LOG_BY_TOKEN_SQL)
                .bind(token_id)
                .fetch_all(pool)
                .await?
            {
                logs.push(decode_log!(row));
            }
            Ok(logs)
        }
    }
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

fn log_json(
    log: &LogRecord,
    display: &newapi_identity::self_user::QuotaDisplaySettings,
) -> LogJson<'_> {
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

fn usage_success(token: &TokenRecord) -> Response {
    // Go `token.ExpiredTime == -1` → expires_at 0（manage_tokens.go:223-226）。
    let expires_at = if token.expired_time == -1 {
        0
    } else {
        token.expired_time
    };
    Json(json!({
        "code": true,
        "message": "ok",
        "data": {
            "object": "token_usage",
            "name": token.name,
            "total_granted": token.remain_quota + token.used_quota,
            "total_used": token.used_quota,
            "total_available": token.remain_quota,
            "unlimited_quota": token.unlimited_quota,
            // Go `GetModelLimitsMap`：空串是空 map，非空按逗号切分（含空段）；
            // Go 编码 map 按键排序，BTreeMap 与之一致。
            "model_limits": model_limits_map(&token.model_limits),
            "model_limits_enabled": token.model_limits_enabled,
            "expires_at": expires_at,
        }
    }))
    .into_response()
}

fn model_limits_map(raw: &str) -> Value {
    let map: BTreeMap<&str, bool> = if raw.is_empty() {
        BTreeMap::new()
    } else {
        raw.split(',').map(|limit| (limit, true)).collect()
    };
    json!(map)
}

fn usage_error(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(json!({
            "success": false,
            "message": message,
        })),
    )
        .into_response()
}

fn usage_lookup_failure(headers: &HeaderMap) -> Response {
    (
        StatusCode::OK,
        Json(json!({
            "success": false,
            "message": translate(headers, MSG_TOKEN_GET_INFO_FAILED),
        })),
    )
        .into_response()
}

/// Go/axum 查询参数解码对齐：`+` 为空格、`%XX` 解一个字节（与
/// `token_http` 的实现对齐）。
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

/// Go `c.Query("token_id")`：首个同名键的原值。
fn token_id_query(uri: &Uri) -> Option<String> {
    let query = uri.query()?;
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        (key == "token_id").then(|| percent_decode(value))
    })
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
