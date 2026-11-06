//! 登录成功审计日志（Go `usage.RecordLoginLog`，`type = LogTypeLogin = 7`）。
//!
//! Go 写库失败只记 SysLog、不影响响应；这里保持同一语义，仓储层不向
//! handler 传播日志失败。`request_id` 的形状对齐 Go `NewRequestId`：
//! `UTC 时间(14 位) + 纳秒 9 位 + 8 位进程前缀 + 8 位随机`；前缀在 Go 是
//! 主模块路径 SHA-256 的前 4 字节，Rust 进程内以固定模块名派生。

use newapi_storage::Database;
use serde_json::{Map, Value};

const LOG_TYPE_LOGIN: i64 = 7;
const NANOS_PER_SECOND: i128 = 1_000_000_000;

/// Go `ensureLogRequestId`：仅当调用方没有提供时生成。
pub fn new_request_id(now_nanos: i128) -> String {
    let seconds = now_nanos.div_euclid(NANOS_PER_SECOND) as i64;
    let nanos = now_nanos.rem_euclid(NANOS_PER_SECOND) as i64;
    let (year, month, day, hour, minute, second) = utc_civil(seconds);
    format!(
        "{year:04}{month:02}{day:02}{hour:02}{minute:02}{second:02}{nanos:09}{}{}",
        request_id_prefix(),
        random_suffix(),
    )
}

/// Go `requestIdPrefix`：进程内稳定；取模块标识 SHA-256 前 4 字节的 hex。
fn request_id_prefix() -> String {
    use sha2::Digest;
    use std::sync::LazyLock;
    static PREFIX: LazyLock<String> = LazyLock::new(|| {
        let digest = sha2::Sha256::digest(b"newapi-server");
        digest[..4]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    });
    PREFIX.clone()
}

fn random_suffix() -> String {
    use rand::Rng;
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    (0..8)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

/// Howard Hinnant civil_from_days（UTC），与 Go 的 UTC 分解一致。
fn utc_civil(epoch: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = epoch.div_euclid(86_400);
    let seconds = epoch.rem_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if month <= 2 { year + 1 } else { year };
    (
        year,
        month,
        day,
        (seconds / 3_600) as u32,
        ((seconds % 3_600) / 60) as u32,
        (seconds % 60) as u32,
    )
}

/// 写入 Go `LogTypeLogin` 审计行。`extra` 是 login_method/user_agent 等
/// 附加信息；`op` 字段由 action+params 组成，与 Go `buildOpField` 一致。
/// 失败仅记 `tracing::warn`，与 Go 的 SysLog 行为一致。
#[allow(clippy::too_many_arguments)]
pub async fn record_login_log(
    db: &Database,
    user_id: i64,
    username: &str,
    content: &str,
    ip: &str,
    action: &str,
    params: Map<String, Value>,
    extra: Map<String, Value>,
    now: i64,
) {
    let mut other = extra;
    let mut op = Map::new();
    op.insert("action".to_owned(), Value::String(action.to_owned()));
    if !params.is_empty() {
        op.insert("params".to_owned(), Value::Object(params));
    }
    other.insert("op".to_owned(), Value::Object(op));
    let other = serde_json::to_string(&Value::Object(other)).unwrap_or_default();

    let sql = "INSERT INTO logs (user_id, created_at, type, content, username, \
               token_name, model_name, quota, prompt_tokens, completion_tokens, \
               use_time, is_stream, ip, request_id, other) \
               VALUES ($1,$2,$3,$4,$5,'','',0,0,0,0,$6,$7,$8,$9)";
    let is_stream = false;
    let request_id = new_request_id(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_nanos() as i128)
            .unwrap_or(0),
    );
    let result = match db {
        Database::Sqlite(pool) => sqlx::query(sql)
            .bind(user_id)
            .bind(now)
            .bind(LOG_TYPE_LOGIN)
            .bind(content)
            .bind(username)
            .bind(is_stream)
            .bind(ip)
            .bind(&request_id)
            .bind(&other)
            .execute(pool)
            .await
            .map(|_| ()),
        Database::Postgres(pool) => sqlx::query(sql)
            .bind(user_id)
            .bind(now)
            .bind(LOG_TYPE_LOGIN)
            .bind(content)
            .bind(username)
            .bind(is_stream)
            .bind(ip)
            .bind(&request_id)
            .bind(&other)
            .execute(pool)
            .await
            .map(|_| ()),
    };
    if let Err(error) = result {
        // 不转述数据库错误文本；登录审计失败不能改变响应。
        tracing::warn!(
            event = "login_audit_failed",
            category = error_category(&error),
            "failed to record login log"
        );
    }
}

fn error_category(error: &sqlx::Error) -> &'static str {
    match error {
        sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed => "pool",
        sqlx::Error::Io(_) | sqlx::Error::WorkerCrashed => "io",
        _ => "database",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_id_matches_go_shape() {
        // Go: 14 位 UTC 时间 + 9 位纳秒 + 8 hex 前缀 + 8 随机 = 39 字符。
        let id = new_request_id(1_700_000_000_123_456_789);
        assert_eq!(id.len(), 39);
        assert!(id.starts_with("20231114221320"));
        assert!(id[23..31].chars().all(|c| c.is_ascii_hexdigit()));
        // 前缀在进程内稳定。
        assert_eq!(
            new_request_id(1_700_000_000_000_000_001)[23..31],
            id[23..31]
        );
    }

    #[test]
    fn utc_civil_boundaries() {
        assert_eq!(utc_civil(0), (1970, 1, 1, 0, 0, 0));
        assert_eq!(utc_civil(1_700_000_000), (2023, 11, 14, 22, 13, 20));
        assert_eq!(utc_civil(-1), (1969, 12, 31, 23, 59, 59));
    }
}
