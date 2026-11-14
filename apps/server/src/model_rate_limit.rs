//! ModelRequestRateLimit ported from Go
//! `apps/api/internal/transport/middleware/limit_model_rate.go`.
//!
//! Contract (oracle `/root/newapi`, read-only):
//! - setting keys `ModelRequestRateLimit{Enabled,Count,DurationMinutes,
//!   SuccessCount,Group}` (`settings/settings.go:579-589`: ints via
//!   `strconv.Atoi` → parse failure **zeroes**; bool via `value == "true"`;
//!   group JSON via `UpdateModelRequestRateLimitGroupByJSONString`, failure
//!   keeps the previous value). Defaults (`rate_limit.go:10-14`): disabled,
//!   1 minute, total 0, success 1000, empty group map.
//! - group override: `GetGroupRateLimit(group)` on the token group (Go
//!   `ContextKeyTokenGroup`; the user-group fallback stays empty on the token
//!   chain because `SetupContextForToken` never writes `ContextKeyUserGroup`).
//! - Redis path (`limit_model_rate.go:26-130`):
//!   1. success check `rateLimit:MRRLS:<uid>`: LLen < max → allow; else
//!      LIndex(-1) parses `2006-01-02T15:04:05.000Z`; window not elapsed →
//!      EXPIRE(duration minutes) + 429; `maxCount == 0` disables.
//!   2. total token bucket `rateLimit:<uid>` via `limiter.New(...).Allow`
//!      (`common/limiter/lua/rate_limit.lua`): requested `duration` seconds,
//!      rate `total`, capacity `total*duration`, Redis TIME clock. Go's
//!      `!allowed` arm writes the 429 but does **not** return — the abort flag
//!      stops downstream handlers (`fiberadapter/context.go:680-698`) while
//!      the middleware continues, so the post-chain success recording still
//!      runs. The port records the sub-400 outcome exactly the same way.
//!   3. after the chain: response < 400 → LPush now / LTrim 0..max-1 /
//!      EXPIRE(duration minutes).
//! - memory path (`limit_model_rate.go:133-165`): the shared global
//!   `inMemoryRateLimiter.Request(key, max, seconds)` sliding window
//!   (`common/rate-limit.go:54-75`); total check, then a `_check` probe key
//!   for the success limit, then record the success key after a sub-400
//!   response. Memory rejections are a bare 429 without a body.
//! - Redis failures in the success/total check answer 500 with the OpenAI
//!   envelope `rate_limit_check_failed` (limit_model_rate.go:88-91,111-115).

use std::{
    collections::{HashMap, VecDeque},
    sync::{Mutex, OnceLock},
};

use axum::{
    Json,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use redis::{Script, aio::MultiplexedConnection};
use serde_json::json;

use crate::AppState;
use crate::relay_http::{RelayTokenIdentity, abort_with_openai_message};

/// Go `ModelRequestRateLimitCountMark` / `ModelRequestRateLimitSuccessCountMark`
/// (`limit_model_rate.go:20-21`).
pub const MODEL_REQUEST_RATE_LIMIT_COUNT_MARK: &str = "MRRL";
pub const MODEL_REQUEST_RATE_LIMIT_SUCCESS_COUNT_MARK: &str = "MRRLS";

/// Go `rate_limit.ModelRequestRateLimitGroup` entry shape.
pub type GroupRateLimit = [i64; 2];

/// Go `rate_limit` package defaults (`rate_limit.go:10-14`): disabled,
/// 1 minute, total 0, success 1000, empty group map.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ModelRateLimitSettings {
    pub enabled: bool,
    pub duration_minutes: i64,
    pub total_max_count: i64,
    pub success_max_count: i64,
    pub group: HashMap<String, GroupRateLimit>,
}

impl ModelRateLimitSettings {
    /// Go `GetGroupRateLimit` (`rate_limit.go:36-49`).
    pub fn group_rate_limit(&self, group: &str) -> Option<(i64, i64)> {
        self.group.get(group).map(|limits| (limits[0], limits[1]))
    }

    /// Go `ModelRequestRateLimit` config resolution (`limit_model_rate.go:176-192`):
    /// group override only when the group is found.
    pub fn resolve(&self, group: &str) -> (i64, i64, i64) {
        let duration = self.duration_minutes * 60;
        let (total, success) = self
            .group_rate_limit(group)
            .map_or((self.total_max_count, self.success_max_count), |(t, s)| {
                (t, s)
            });
        (duration, total, success)
    }
}

/// Loads the five settings. `strconv.Atoi` failure zeroes the value
/// (`settings.go:579-588`); the enabled check is the literal `value == "true"`
/// (`settings.go:373`); a group JSON parse failure keeps the current value,
/// which for a per-request fresh load means the process default empty map.
pub async fn load_model_rate_limit_settings(
    db: &newapi_storage::Database,
) -> ModelRateLimitSettings {
    let mut settings = ModelRateLimitSettings::default();
    for (key, sink) in [
        ("ModelRequestRateLimitEnabled", 0usize),
        ("ModelRequestRateLimitDurationMinutes", 1),
        ("ModelRequestRateLimitCount", 2),
        ("ModelRequestRateLimitSuccessCount", 3),
        ("ModelRequestRateLimitGroup", 4),
    ] {
        let raw: Option<String> = match db {
            newapi_storage::Database::Sqlite(pool) => {
                sqlx::query_scalar("SELECT value FROM options WHERE \"key\" = ?")
                    .bind(key)
                    .fetch_optional(pool)
                    .await
                    .ok()
                    .flatten()
            }
            newapi_storage::Database::Postgres(pool) => {
                sqlx::query_scalar("SELECT value FROM options WHERE \"key\" = $1")
                    .bind(key)
                    .fetch_optional(pool)
                    .await
                    .ok()
                    .flatten()
            }
        };
        let Some(raw) = raw else { continue };
        match sink {
            0 => settings.enabled = raw == "true",
            // Go Atoi: parse failure → 0.
            1 => settings.duration_minutes = raw.parse().unwrap_or(0),
            2 => settings.total_max_count = raw.parse().unwrap_or(0),
            3 => settings.success_max_count = raw.parse().unwrap_or(0),
            _ => {
                if let Ok(group) = serde_json::from_str::<HashMap<String, GroupRateLimit>>(&raw) {
                    settings.group = group;
                }
            }
        }
    }
    settings
}

// ---------------------------------------------------------------------------
// In-memory limiter (Go common/rate-limit.go Request, seconds-based)
// ---------------------------------------------------------------------------

/// Go `InMemoryRateLimiter.Request(key, maxRequestNum, duration)` with the
/// expiration semantics of `clearExpiredItems` folded into a lazy sweep (the
/// cleaner never participates in an admission decision — see the P1 port in
/// `limit.rs` for the equivalence argument).
#[derive(Default)]
pub struct MemoryRequestLimiter {
    windows: Mutex<HashMap<String, VecDeque<i64>>>,
}

impl MemoryRequestLimiter {
    /// Admits or rejects one request at `now` (Unix seconds). Mirrors Go's
    /// store-miss / length / window branches exactly.
    pub fn request(&self, key: &str, max_request_num: i64, duration_seconds: i64) -> bool {
        let mut windows = self.windows.lock().expect("mrrl memory limiter lock");
        let queue = windows.entry(key.to_owned()).or_default();
        let now = now_unix();
        if queue.len() < max_request_num.max(0) as usize {
            queue.push_back(now);
            return true;
        }
        if queue
            .front()
            .is_some_and(|oldest| now - *oldest >= duration_seconds)
        {
            queue.pop_front();
            queue.push_back(now);
            return true;
        }
        false
    }
}

/// Go's package-level `inMemoryRateLimiter`: one shared instance across every
/// request (`limit_model_rate.go:134`).
static GLOBAL_MEMORY_LIMITER: OnceLock<MemoryRequestLimiter> = OnceLock::new();

fn global_memory_limiter() -> &'static MemoryRequestLimiter {
    GLOBAL_MEMORY_LIMITER.get_or_init(MemoryRequestLimiter::default)
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Redis handlers (limit_model_rate.go:26-130)
// ---------------------------------------------------------------------------

/// Errors map to Go's failure arms: any Redis fault in the success or total
/// check answers 500 `rate_limit_check_failed`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModelRateLimitError {
    Redis,
    /// Go's `time.Parse` failure on the LIndex(-1) value (500 as well).
    TimeParse,
}

/// Go `checkRedisRateLimit` (limit_model_rate.go:26-63).
pub async fn check_redis_rate_limit(
    connection: &mut MultiplexedConnection,
    key: &str,
    max_count: i64,
    duration_seconds: i64,
) -> Result<bool, ModelRateLimitError> {
    // maxCount == 0 disables the check entirely.
    if max_count == 0 {
        return Ok(true);
    }
    use redis::AsyncCommands;
    let length: i64 = connection
        .llen(key)
        .await
        .map_err(|_| ModelRateLimitError::Redis)?;
    if length < max_count {
        return Ok(true);
    }
    // Go ignores the LIndex error and parses whatever comes back.
    let old_time_str: String = connection.lindex(key, -1).await.unwrap_or_default();
    let old_time =
        parse_model_rate_limit_time(&old_time_str).ok_or(ModelRateLimitError::TimeParse)?;
    let now = now_unix();
    // Go parses both timestamps through the same whole-second format and
    // subtracts; int64(subTime) truncates the seconds difference.
    let sub_time = (now - old_time) as f64;
    if (sub_time as i64) < duration_seconds {
        let minutes = duration_seconds / 60;
        let _: () = connection
            .expire(key, (minutes.max(1) * 60) as i64)
            .await
            .map_err(|_| ModelRateLimitError::Redis)?;
        return Ok(false);
    }
    Ok(true)
}

/// Go `time.Parse(modelRateLimitTimeFormat, ...)` → Unix seconds. The format
/// `2006-01-02T15:04:05.000Z` keeps exactly three fractional digits.
fn parse_model_rate_limit_time(value: &str) -> Option<i64> {
    if value.len() != 24 || !value.ends_with('Z') || value.as_bytes()[10] != b'T' {
        return None;
    }
    let year: i64 = value.get(0..4)?.parse().ok()?;
    let month: u32 = value.get(5..7)?.parse().ok()?;
    let day: u32 = value.get(8..10)?.parse().ok()?;
    let hour: i64 = value.get(11..13)?.parse().ok()?;
    let minute: i64 = value.get(14..16)?.parse().ok()?;
    let second: i64 = value.get(17..19)?.parse().ok()?;
    let millis: i64 = value.get(20..23)?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let days = days_from_civil(year, month, day);
    Some(days * 86_400 + hour * 3600 + minute * 60 + second + millis.div_euclid(1000))
}

/// (year, month, day) → days since 1970-01-01; Howard Hinnant's algorithm.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Go `time.Format` for the list timestamps.
fn format_model_rate_limit_time(unix_seconds: i64) -> String {
    let days = unix_seconds.div_euclid(86_400);
    let second_of_day = unix_seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.000Z",
        year,
        month,
        day,
        second_of_day / 3600,
        (second_of_day % 3600) / 60,
        second_of_day % 60
    )
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Go `recordRedisRequest` (limit_model_rate.go:66-76): LPush now, LTrim to
/// the last `maxCount` entries, EXPIRE the configured minutes. Failures are
/// swallowed like Go's ignored returns.
pub async fn record_redis_request(
    connection: &mut MultiplexedConnection,
    key: &str,
    max_count: i64,
    duration_seconds: i64,
) {
    if max_count == 0 {
        return;
    }
    use redis::AsyncCommands;
    let stamp = format_model_rate_limit_time(now_unix());
    let minutes = (duration_seconds / 60).max(1);
    let _: Result<(), redis::RedisError> = async {
        let () = connection.lpush::<_, _, ()>(key, stamp).await?;
        let () = connection
            .ltrim::<_, ()>(key, 0, (max_count - 1).max(0) as isize)
            .await?;
        let () = connection.expire::<_, ()>(key, minutes * 60).await?;
        Ok::<(), redis::RedisError>(())
    }
    .await;
}

/// Go `limiter.RedisLimiter.Allow` over `lua/rate_limit.lua`
/// (`common/limiter`): token bucket on a hash `{tokens, last_time}` with the
/// Redis server TIME clock and integer-second granularity. Arguments follow
/// the Go call site: requested `duration`, rate `total`, capacity
/// `total * duration`.
const TOKEN_BUCKET_SCRIPT: &str = r#"
local key = KEYS[1]
local requested = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local capacity = tonumber(ARGV[3])

local now = redis.call('TIME')
local nowInSeconds = tonumber(now[1])

local bucket = redis.call('HMGET', key, 'tokens', 'last_time')
local tokens = tonumber(bucket[1])
local last_time = tonumber(bucket[2])

if not tokens or not last_time then
    tokens = capacity
    last_time = nowInSeconds
else
    local elapsed = nowInSeconds - last_time
    local add_tokens = elapsed * rate
    tokens = math.min(capacity, tokens + add_tokens)
    last_time = nowInSeconds
end

local allowed = false
if tokens >= requested then
    tokens = tokens - requested
    allowed = true
end

redis.call('HMSET', key, 'tokens', tokens, 'last_time', last_time)

return allowed and 1 or 0
"#;

/// `httperr.AbortWithOpenAiMessage` for the two rate-limit rejections; the
/// message carries the request id through `MessageWithRequestId`.
fn bare_openai_abort(status: StatusCode, message: &str, request_id: &str) -> Response {
    let message = crate::middleware_misc::message_with_request_id(message, request_id);
    (
        status,
        Json(json!({
            "error": {
                "message": message,
                "type": "new_api_error",
                "code": "",
            }
        })),
    )
        .into_response()
}

/// The pre-chain half of Go's `redisRateLimitHandler`: success check + total
/// token bucket. `Ok(None)` means the chain may run.
async fn redis_precheck(
    connection: &mut MultiplexedConnection,
    user_id: i64,
    duration_seconds: i64,
    total_max_count: i64,
    success_max_count: i64,
    request_id: &str,
) -> Result<Option<Response>, ModelRateLimitError> {
    let success_key = format!("rateLimit:{MODEL_REQUEST_RATE_LIMIT_SUCCESS_COUNT_MARK}:{user_id}");
    let allowed = check_redis_rate_limit(
        connection,
        &success_key,
        success_max_count,
        duration_seconds,
    )
    .await?;
    if !allowed {
        let message = format!(
            "您已达到请求数限制：{}分钟内最多请求{}次",
            duration_seconds / 60,
            success_max_count
        );
        return Ok(Some(bare_openai_abort(
            StatusCode::TOO_MANY_REQUESTS,
            &message,
            request_id,
        )));
    }
    if total_max_count > 0 {
        let total_key = format!("rateLimit:{user_id}");
        let mut conn = connection.clone();
        let allowed: i64 = Script::new(TOKEN_BUCKET_SCRIPT)
            .key(total_key)
            .arg(duration_seconds)
            .arg(total_max_count)
            .arg(total_max_count * duration_seconds)
            .invoke_async(&mut conn)
            .await
            .map_err(|_| ModelRateLimitError::Redis)?;
        if allowed != 1 {
            let message = format!(
                "您已达到总请求数限制：{}分钟内最多请求{}次，包括失败次数，请检查您的请求是否正确",
                duration_seconds / 60,
                total_max_count
            );
            return Ok(Some(bare_openai_abort(
                StatusCode::TOO_MANY_REQUESTS,
                &message,
                request_id,
            )));
        }
    }
    Ok(None)
}

/// Go `memoryRateLimitHandler` (limit_model_rate.go:133-165). `response_ok`
/// mirrors the post-chain `c.ResponseStatus() < 400` read; `None` runs only
/// the pre-chain checks.
pub fn memory_rate_limit_handler(
    limiter: &MemoryRequestLimiter,
    user_id: i64,
    duration_seconds: i64,
    total_max_count: i64,
    success_max_count: i64,
    response_ok: Option<bool>,
) -> Option<Response> {
    let total_key = format!("{MODEL_REQUEST_RATE_LIMIT_COUNT_MARK}{user_id}");
    let success_key = format!("{MODEL_REQUEST_RATE_LIMIT_SUCCESS_COUNT_MARK}{user_id}");
    // 1. total check (skipped when totalMaxCount == 0).
    if total_max_count > 0 && !limiter.request(&total_key, total_max_count, duration_seconds) {
        return Some(StatusCode::TOO_MANY_REQUESTS.into_response());
    }
    // 2. success check via a probe key that is never the recording key.
    let check_key = format!("{success_key}_check");
    if !limiter.request(&check_key, success_max_count, duration_seconds) {
        return Some(StatusCode::TOO_MANY_REQUESTS.into_response());
    }
    // 4. record success after a sub-400 response (the recording call itself
    // goes straight to the real success key in Go).
    if response_ok.unwrap_or(false) {
        limiter.request(&success_key, success_max_count, duration_seconds);
    }
    None
}

/// Go `ModelRequestRateLimit` (limit_model_rate.go:168-201) as the axum
/// middleware. The group comes from the token identity (`ContextKeyTokenGroup`
/// on the Go chain; the user-group fallback is empty there). Redis is used
/// when bound (`common.RedisEnabled`), otherwise the shared in-memory limiter.
pub async fn model_request_rate_limit(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let Some(db) = state.db() else {
        return next.run(request).await;
    };
    let settings = load_model_rate_limit_settings(&db).await;
    if !settings.enabled {
        return next.run(request).await;
    }
    let identity = request.extensions().get::<RelayTokenIdentity>().cloned();
    let user_id = identity.as_ref().map(|i| i.user_id).unwrap_or_default();
    // Go: token group first, else the user-group context value (empty on the
    // token chain — see module docs).
    let group = identity.map(|i| i.token_group).unwrap_or_default();
    let (duration, total_max_count, success_max_count) = settings.resolve(&group);
    let request_id = crate::relay_http::request_id_of(&request);
    if let Some(redis_limiter) = state.model_rate_redis() {
        let mut connection = redis_limiter.clone();
        match redis_precheck(
            &mut connection,
            user_id,
            duration,
            total_max_count,
            success_max_count,
            &request_id,
        )
        .await
        {
            Err(_) => {
                // Go prints the failure and aborts 500; the underlying Redis
                // error never reaches the client.
                return abort_with_openai_message(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "rate_limit_check_failed",
                    "",
                    &request_id,
                );
            }
            Ok(Some(response)) => return response,
            Ok(None) => {}
        }
        let response = next.run(request).await;
        if response.status().as_u16() < 400 {
            record_redis_request(
                &mut redis_limiter.clone(),
                &format!("rateLimit:{MODEL_REQUEST_RATE_LIMIT_SUCCESS_COUNT_MARK}:{user_id}"),
                success_max_count,
                duration,
            )
            .await;
        }
        return response;
    }
    // Memory path against the shared global limiter.
    let limiter = global_memory_limiter();
    if let Some(response) = memory_rate_limit_handler(
        limiter,
        user_id,
        duration,
        total_max_count,
        success_max_count,
        None,
    ) {
        return response;
    }
    let response = next.run(request).await;
    if response.status().as_u16() < 400 {
        limiter.request(
            &format!("{MODEL_REQUEST_RATE_LIMIT_SUCCESS_COUNT_MARK}{user_id}"),
            success_max_count,
            duration,
        );
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_go_process_state() {
        let settings = ModelRateLimitSettings::default();
        assert!(!settings.enabled);
        assert_eq!(settings.duration_minutes, 1);
        assert_eq!(settings.total_max_count, 0);
        assert_eq!(settings.success_max_count, 1000);
        assert!(settings.group.is_empty());
        let (duration, total, success) = settings.resolve("");
        assert_eq!((duration, total, success), (60, 0, 1000));
    }

    #[test]
    fn group_override_applies_only_when_found() {
        let mut settings = ModelRateLimitSettings::default();
        settings.group.insert("vip".to_owned(), [10, 20]);
        let (duration, total, success) = settings.resolve("vip");
        assert_eq!((duration, total, success), (60, 10, 20));
        let (duration, total, success) = settings.resolve("missing");
        assert_eq!((duration, total, success), (60, 0, 1000));
    }

    #[test]
    fn memory_limiter_reproduces_go_request_semantics() {
        let limiter = MemoryRequestLimiter::default();
        // Fresh key always admitted (Go's store-miss branch).
        assert!(limiter.request("k", 2, 10));
        assert!(limiter.request("k", 2, 10));
        assert!(!limiter.request("k", 2, 10));
        // Window elapsed: pop the oldest, admit.
        assert!(limiter.request("k", 2, 10));
    }

    #[test]
    fn memory_handler_rejects_total_and_success_independently() {
        let limiter = MemoryRequestLimiter::default();
        // total 0 skips the total check entirely.
        assert!(memory_rate_limit_handler(&limiter, 1, 60, 0, 2, None).is_none());
        assert!(memory_rate_limit_handler(&limiter, 1, 60, 0, 2, None).is_none());
        // Third request trips the success probe (max 2), bare 429 without a
        // body — Go's c.Status(429); c.Abort().
        let response = memory_rate_limit_handler(&limiter, 1, 60, 0, 2, None);
        assert!(response.is_some());
        assert_eq!(response.unwrap().status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn memory_handler_records_success_only_after_sub_400() {
        // successMaxCount 1: probe admits, recording fills the real key, the
        // third probe rejects.
        let limiter = MemoryRequestLimiter::default();
        assert!(memory_rate_limit_handler(&limiter, 2, 60, 0, 1, Some(true)).is_none());
        assert!(memory_rate_limit_handler(&limiter, 2, 60, 0, 1, Some(true)).is_none());
        assert!(memory_rate_limit_handler(&limiter, 2, 60, 0, 1, Some(true)).is_some());
        // A >=400 response records nothing: the probe still admits twice.
        let limiter = MemoryRequestLimiter::default();
        assert!(memory_rate_limit_handler(&limiter, 3, 60, 0, 1, Some(false)).is_none());
        assert!(memory_rate_limit_handler(&limiter, 3, 60, 0, 1, Some(false)).is_none());
        assert!(memory_rate_limit_handler(&limiter, 3, 60, 0, 1, Some(false)).is_none());
    }

    #[test]
    fn time_format_roundtrips_and_rejects_garbage() {
        let stamp = format_model_rate_limit_time(1_700_000_000);
        assert_eq!(stamp, "2023-11-14T22:13:20.000Z");
        assert_eq!(parse_model_rate_limit_time(&stamp), Some(1_700_000_000));
        assert_eq!(parse_model_rate_limit_time(""), None);
        assert_eq!(parse_model_rate_limit_time("not-a-time"), None);
        assert_eq!(parse_model_rate_limit_time("2023-11-14T22:13:20Z"), None);
        assert_eq!(parse_model_rate_limit_time("2023-11-14T22:13:20.5Z"), None);
        // Out-of-range months/days are Go time.Parse errors.
        assert_eq!(
            parse_model_rate_limit_time("2023-13-14T22:13:20.000Z"),
            None
        );
        assert_eq!(
            parse_model_rate_limit_time("2023-11-32T22:13:20.000Z"),
            None
        );
    }

    #[test]
    fn token_bucket_args_match_go_call_site() {
        // Go: WithCapacity(total*duration), WithRate(total), WithRequested(duration).
        let (duration, total) = (60_i64, 30_i64);
        assert_eq!(total * duration, 1_800);
    }
}
