//! Relay 入口管线：`TokenAuth` 完整版中间件、`InsightClientBan` 中间件与
//! `/v1`、`/v1beta`、`/v1/models` 的 relay 路由组接线。
//!
//! Go oracle：
//! - `apps/api/internal/security/authenticate.go:344-517`（`TokenAuth` +
//!   `SetupContextForToken`）
//! - `apps/api/internal/transport/middleware/insight_client_ban.go`
//! - `apps/api/internal/usage/user_insight_client_ban.go`（CheckClientBan）
//! - `apps/api/internal/transport/compose/register_relay.go`（路由组与链序）
//! - `apps/api/internal/transport/httperr/abort.go`（OpenAI 错误信封）
//!
//! 链序契约（Go 注册顺序 → 执行顺序）：
//! `/v1` 组：RouteTag → SystemPerformanceCheck → TokenAuth →
//! ModelRequestRateLimit → UserInsight → InsightClientBan → Distribute。
//! 本切片实现 TokenAuth 与 InsightClientBan；RateLimit / UserInsight /
//! Distribute 属其他切片，未接线（见交付报告遗留项）。axum `route_layer`
//! 后加先执行，故注册顺序为 Go 执行顺序的逆序。

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, get, post},
};
use newapi_i18n::translate;
use newapi_identity::{
    login::USER_STATUS_ENABLED,
    tokens::{TOKEN_STATUS_ENABLED, TokenRepository},
    users::UserProfileRepository,
};
use serde_json::{Value, json};

use crate::AppState;

const MSG_DATABASE_ERROR: &str = "common.database_error";
const MSG_TOKEN_INVALID: &str = "token.invalid";
const MSG_USER_BANNED: &str = "auth.user_banned";
const MSG_NO_AVAILABLE_CHANNEL: &str = "distributor.no_available_channel";
const MSG_CLIENT_BAN_GLOBAL: &str = "您使用的客户端已被站点管理员封禁";
const MSG_CLIENT_BAN_USER: &str = "该客户端已被管理员对您的账号禁用";

/// Go `user_insight_setting.client_ban_enabled` 的 option 键。
const CLIENT_BAN_ENABLED_OPTION: &str = "user_insight_setting.client_ban_enabled";
/// Go `user_insight_setting.blocked_clients` 的 option 键。
const BLOCKED_CLIENTS_OPTION: &str = "user_insight_setting.blocked_clients";
const OPTION_GET_SQL: &str = "SELECT value FROM options WHERE \"key\" = $1";

/// `TokenAuth` 写入的令牌身份（Go `SetupContextForToken` 的 c.Set 集合，
/// 加上分组门裁决结果）。token_key 是凭据，Debug 输出打码。
#[derive(Clone)]
pub struct RelayTokenIdentity {
    pub user_id: i64,
    pub token_id: i64,
    pub token_key: String,
    pub token_name: String,
    pub token_unlimited_quota: bool,
    pub token_remain_quota: i64,
    /// 令牌指定的分组（可空）。
    pub token_group: String,
    /// 用户所在分组。
    pub user_group: String,
    /// 分组门裁决后的实际使用分组。
    pub using_group: String,
    pub token_model_limit_enabled: bool,
    pub token_model_limit: String,
    pub token_auto_groups: Vec<String>,
    pub token_cross_group_retry: bool,
    /// 管理员通过 `key-<channelId>` 指定的渠道 ID（非管理员被 403 拦截）。
    pub specific_channel_id: Option<String>,
}

impl std::fmt::Debug for RelayTokenIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayTokenIdentity")
            .field("user_id", &self.user_id)
            .field("token_id", &self.token_id)
            .field("token_key", &"<redacted>")
            .field("using_group", &self.using_group)
            .finish_non_exhaustive()
    }
}

fn request_language(request: &Request) -> String {
    let accept_language = request
        .headers()
        .get("accept-language")
        .and_then(|v| v.to_str().ok());
    crate::request_lang::request_language(accept_language)
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

/// Go `common.MessageWithRequestId`。
fn message_with_request_id(message: &str, request_id: &str) -> String {
    if request_id.is_empty() {
        message.to_owned()
    } else {
        format!("{message} (request id: {request_id})")
    }
}

/// 请求 ID：Go `common.NewRequestId()` 生成 32 位随机 hex；本切片以时间戳 +
/// 原子计数构成可读且不重复的值（无随机源依赖）。
fn new_request_id() -> String {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    format!("{:016x}{:016x}", now, seq)
}

fn request_id_of(request: &Request) -> String {
    request
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(new_request_id)
}

/// Go `httperr.AbortWithOpenAiMessage`：`{"error": {message, type, code}}`。
pub fn abort_with_openai_message(
    status: StatusCode,
    message: &str,
    code: &str,
    request_id: &str,
) -> Response {
    (
        status,
        axum::Json(json!({
            "error": {
                "message": message_with_request_id(message, request_id),
                "type": "new_api_error",
                "code": code,
            }
        })),
    )
        .into_response()
}

/// Go `TokenAuth`（authenticate.go:344-432）。
pub async fn token_auth(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let language = request_language(&request);
    let request_id = request_id_of(&request);
    let Some(db) = state.db() else {
        return abort_with_openai_message(
            StatusCode::INTERNAL_SERVER_ERROR,
            &translate(
                &language,
                MSG_DATABASE_ERROR,
                std::iter::empty::<(&str, &str)>(),
            ),
            "",
            &request_id,
        );
    };

    let (path, query, headers) = (
        request.uri().path().to_owned(),
        request.uri().query().unwrap_or("").to_owned(),
        request.headers().clone(),
    );

    // 凭据提取（authenticate.go:346-396）。
    let mut auth_value = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();

    // WebSocket：Sec-WebSocket-Protocol 里取 openai-insecure-api-key.<sk>。
    let ws_protocol = headers
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !ws_protocol.is_empty() {
        for part in ws_protocol.split(',') {
            let part = part.trim();
            if let Some(key) = part.strip_prefix("openai-insecure-api-key.") {
                auth_value = format!("Bearer {key}");
                break;
            }
        }
    }
    // /v1/messages、/v1/models：x-api-key 兜底。
    if (path.contains("/v1/messages") || path.contains("/v1/models"))
        && let Some(anthropic_key) = headers.get("x-api-key").and_then(|v| v.to_str().ok())
        && !anthropic_key.is_empty()
    {
        auth_value = format!("Bearer {anthropic_key}");
    }
    // Gemini 路径：query key 与 x-goog-api-key 兜底。
    if path.starts_with("/v1beta/models")
        || path.starts_with("/v1beta/openai/models")
        || path.starts_with("/v1/models/")
    {
        let sk_query = query_key(&query);
        if !sk_query.is_empty() {
            auth_value = format!("Bearer {sk_query}");
        }
        if let Some(x_goog) = headers.get("x-goog-api-key").and_then(|v| v.to_str().ok())
            && !x_goog.is_empty()
        {
            auth_value = format!("Bearer {x_goog}");
        }
    }

    let mut key_value = auth_value;
    let mut specific_channel_candidate: Option<String> = None;
    if key_value.starts_with("Bearer ") || key_value.starts_with("bearer ") {
        key_value = key_value[7..].trim().to_owned();
    }
    if key_value.is_empty() || key_value == "midjourney-proxy" {
        let mut mj_key = headers
            .get("mj-api-secret")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        if mj_key.starts_with("Bearer ") || mj_key.starts_with("bearer ") {
            mj_key = mj_key[7..].trim().to_owned();
        }
        mj_key = mj_key.strip_prefix("sk-").unwrap_or(&mj_key).to_owned();
        let mut parts = mj_key.split('-');
        key_value = parts.next().unwrap_or("").to_owned();
    } else {
        let stripped = key_value
            .strip_prefix("sk-")
            .unwrap_or(&key_value)
            .to_owned();
        let mut parts = stripped.split('-');
        key_value = parts.next().unwrap_or("").to_owned();
        // 管理员的 specific channel 语法 `key-<id>`。
        specific_channel_candidate = parts.next().map(str::to_owned);
    }
    let key = key_value.as_str();
    if key.is_empty() {
        return abort_with_openai_message(
            StatusCode::UNAUTHORIZED,
            &translate(
                &language,
                MSG_TOKEN_INVALID,
                std::iter::empty::<(&str, &str)>(),
            ),
            "",
            &request_id,
        );
    }

    // Go `ValidateUserToken`（identity/token_store.go:188-226）。
    let token = match TokenRepository::new(db.clone()).by_key(key).await {
        Ok(Some(token)) => token,
        Ok(None) => {
            return abort_with_openai_message(
                StatusCode::UNAUTHORIZED,
                &translate(
                    &language,
                    MSG_TOKEN_INVALID,
                    std::iter::empty::<(&str, &str)>(),
                ),
                "",
                &request_id,
            );
        }
        Err(error) => {
            tracing::warn!(
                event = "token_auth_lookup_failed",
                category = crate::database_error_class(&error),
                "TokenAuth token lookup failed"
            );
            return abort_with_openai_message(
                StatusCode::INTERNAL_SERVER_ERROR,
                &translate(
                    &language,
                    MSG_DATABASE_ERROR,
                    std::iter::empty::<(&str, &str)>(),
                ),
                "",
                &request_id,
            );
        }
    };
    if token.status != TOKEN_STATUS_ENABLED
        || (token.expired_time != -1 && token.expired_time < now_unix())
        || (!token.unlimited_quota && token.remain_quota <= 0)
    {
        return abort_with_openai_message(
            StatusCode::UNAUTHORIZED,
            &translate(
                &language,
                MSG_TOKEN_INVALID,
                std::iter::empty::<(&str, &str)>(),
            ),
            "",
            &request_id,
        );
    }

    // IP 允许列表（authenticate.go:398-412）。
    let allow_ips_raw = token.allow_ips.clone().unwrap_or_default();
    let allow_ips: Vec<String> = allow_ips_raw
        .split(',')
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();
    if !allow_ips.is_empty() {
        let client_ip = client_ip_of(&state, request.headers(), request.extensions());
        let parsed = client_ip.parse::<IpAddr>();
        match parsed {
            Err(_) => {
                return abort_with_openai_message(
                    StatusCode::FORBIDDEN,
                    "无法解析客户端 IP 地址",
                    "",
                    &request_id,
                );
            }
            Ok(ip) => {
                let refs: Vec<&str> = allow_ips.iter().map(String::as_str).collect();
                if newapi_security::check_ip_allowlist(&refs, ip).is_err() {
                    return abort_with_openai_message(
                        StatusCode::FORBIDDEN,
                        "您的 IP 不在令牌允许访问的列表中",
                        "access_denied",
                        &request_id,
                    );
                }
            }
        }
    }

    // 用户状态与分组门（authenticate.go:415-451）。
    let profile = match UserProfileRepository::new(db.clone())
        .by_id(token.user_id)
        .await
    {
        Ok(Some(profile)) => profile,
        Ok(None) => {
            return abort_with_openai_message(
                StatusCode::INTERNAL_SERVER_ERROR,
                &translate(
                    &language,
                    MSG_DATABASE_ERROR,
                    std::iter::empty::<(&str, &str)>(),
                ),
                "",
                &request_id,
            );
        }
        Err(error) => {
            tracing::warn!(
                event = "token_auth_user_lookup_failed",
                category = crate::database_error_class(&error),
                "TokenAuth user lookup failed"
            );
            return abort_with_openai_message(
                StatusCode::INTERNAL_SERVER_ERROR,
                &translate(
                    &language,
                    MSG_DATABASE_ERROR,
                    std::iter::empty::<(&str, &str)>(),
                ),
                "",
                &request_id,
            );
        }
    };
    if profile.status != USER_STATUS_ENABLED {
        return abort_with_openai_message(
            StatusCode::FORBIDDEN,
            &translate(
                &language,
                MSG_USER_BANNED,
                std::iter::empty::<(&str, &str)>(),
            ),
            "",
            &request_id,
        );
    }

    let mut user_group = profile.group.clone();
    if !token.group.is_empty() {
        let settings = state.group_settings();
        let usable = settings.user_usable_groups(&user_group);
        if !usable.contains_key(&token.group) {
            return abort_with_openai_message(
                StatusCode::FORBIDDEN,
                &format!("无权访问 {} 分组", token.group),
                "",
                &request_id,
            );
        }
        if !settings.group_ratio.contains_key(&token.group) && token.group != "auto" {
            return abort_with_openai_message(
                StatusCode::FORBIDDEN,
                &format!("分组 {} 已被弃用", token.group),
                "",
                &request_id,
            );
        }
        user_group = token.group.clone();
    }

    // Go `SetupContextForToken`（authenticate.go:434-517）。
    let mut auto_groups: Vec<String> = Vec::new();
    if !token.auto_groups.is_empty() {
        if let Ok(list) = serde_json::from_str::<Vec<String>>(&token.auto_groups) {
            auto_groups = list;
        } else {
            tracing::warn!(
                event = "token_auto_groups_parse_failed",
                token_id = token.id
            );
        }
    }

    // specific channel 语法：非管理员一律 403。
    let mut specific_channel_id = None;
    if let Some(candidate) = specific_channel_candidate
        && !candidate.is_empty()
    {
        if profile.role >= crate::auth::ROLE_ADMIN_USER {
            specific_channel_id = Some(candidate);
        } else {
            return abort_with_openai_message(
                StatusCode::FORBIDDEN,
                "普通用户不支持指定渠道",
                "",
                &request_id,
            );
        }
    }

    let identity = RelayTokenIdentity {
        user_id: token.user_id,
        token_id: token.id,
        token_key: token.key.clone(),
        token_name: token.name.clone(),
        token_unlimited_quota: token.unlimited_quota,
        token_remain_quota: token.remain_quota,
        token_group: token.group.clone(),
        user_group: profile.group.clone(),
        using_group: user_group,
        token_model_limit_enabled: token.model_limits_enabled,
        token_model_limit: token.model_limits.clone(),
        token_auto_groups: auto_groups,
        token_cross_group_retry: token.cross_group_retry,
        specific_channel_id,
    };
    let mut request = request;
    request.extensions_mut().insert(identity);
    next.run(request).await
}

fn query_key(query: &str) -> String {
    for pair in query.split('&') {
        if let Some(value) = pair.strip_prefix("key=") {
            return value.to_owned();
        }
    }
    String::new()
}

fn client_ip_of(
    state: &AppState,
    headers: &HeaderMap,
    extensions: &axum::http::Extensions,
) -> String {
    let peer = extensions
        .get::<std::net::SocketAddr>()
        .map(|addr| addr.ip());
    let forwarded = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok());
    let real = headers.get("x-real-ip").and_then(|v| v.to_str().ok());
    state.client_ip(peer, forwarded, real)
}

/// Go `GetUserClientBanSet` 的 TTL 缓存（30 秒；触顶 4096 整体重建）。
/// 查询失败时沿用旧缓存，没有旧缓存则放行（宁漏封不可全站 403）。
/// 缓存条目：(封禁客户端集合, 过期时间戳)。
type UserBanCacheEntry = (HashSet<String>, i64);

static USER_BAN_CACHE: Mutex<Option<HashMap<i64, UserBanCacheEntry>>> = Mutex::new(None);

async fn load_user_client_ban_set(db: &newapi_storage::Database, user_id: i64) -> HashSet<String> {
    if user_id <= 0 {
        return HashSet::new();
    }
    let now = now_unix();
    // 锁只覆盖缓存读写：MutexGuard 不 Send，绝不能跨 await 持有。
    let cached = {
        let mut guard = USER_BAN_CACHE.lock().expect("ban cache lock");
        let cache = guard.get_or_insert_with(HashMap::new);
        match cache.get(&user_id) {
            Some((set, expires_at)) if *expires_at > now => Some(set.clone()),
            _ => None,
        }
    };
    if let Some(set) = cached {
        return set;
    }
    let loaded = query_user_client_bans(db, user_id).await;
    let mut guard = USER_BAN_CACHE.lock().expect("ban cache lock");
    let cache = guard.get_or_insert_with(HashMap::new);
    let set = match loaded {
        Ok(set) => set,
        Err(_) => {
            // 查询失败沿用旧缓存（没有旧缓存则放行）。
            if let Some((set, _)) = cache.get(&user_id) {
                return set.clone();
            }
            HashSet::new()
        }
    };
    if cache.len() >= newapi_relay::client_ban::USER_CLIENT_BAN_CACHE_CAPACITY {
        cache.clear();
    }
    cache.insert(
        user_id,
        (
            set.clone(),
            now + newapi_relay::client_ban::USER_CLIENT_BAN_CACHE_TTL,
        ),
    );
    set
}

async fn query_user_client_bans(
    db: &newapi_storage::Database,
    user_id: i64,
) -> Result<HashSet<String>, sqlx::Error> {
    const SQL: &str = "SELECT client FROM user_insight_client_bans WHERE user_id = $1";
    let mut set = HashSet::new();
    match db {
        newapi_storage::Database::Sqlite(pool) => {
            for row in sqlx::query_scalar::<_, String>(SQL)
                .bind(user_id)
                .fetch_all(pool)
                .await?
            {
                set.insert(row);
            }
        }
        newapi_storage::Database::Postgres(pool) => {
            for row in sqlx::query_scalar::<_, String>(SQL)
                .bind(user_id)
                .fetch_all(pool)
                .await?
            {
                set.insert(row);
            }
        }
    }
    Ok(set)
}

/// 读取 `client_ban_enabled` 与 `blocked_clients` 两个 option。
/// Go 把两者缓存在内存里随 ApplyOption 热更新；Rust 侧无内存镜像，
/// 中间件每请求读库（读方语义一致）。
async fn load_client_ban_settings(
    db: &newapi_storage::Database,
) -> Result<(bool, Vec<String>), sqlx::Error> {
    let mut enabled = false;
    let mut blocked = Vec::new();
    for (key, sink) in [
        (CLIENT_BAN_ENABLED_OPTION, 0usize),
        (BLOCKED_CLIENTS_OPTION, 1usize),
    ] {
        let raw: Option<String> = match db {
            newapi_storage::Database::Sqlite(pool) => {
                sqlx::query_scalar(OPTION_GET_SQL)
                    .bind(key)
                    .fetch_optional(pool)
                    .await?
            }
            newapi_storage::Database::Postgres(pool) => {
                sqlx::query_scalar(OPTION_GET_SQL)
                    .bind(key)
                    .fetch_optional(pool)
                    .await?
            }
        };
        match (sink, raw) {
            (0, Some(value)) => enabled = value.trim().eq_ignore_ascii_case("true"),
            (1, Some(value)) => {
                blocked = serde_json::from_str::<Vec<String>>(&value).unwrap_or_default();
            }
            _ => {}
        }
    }
    Ok((enabled, blocked))
}

fn header_map_lite(headers: &HeaderMap) -> newapi_relay::insight_client::HeaderMapLite {
    let mut map = HashMap::new();
    for (name, value) in headers.iter() {
        let key = name.as_str().to_lowercase();
        let value = value.to_str().unwrap_or_default().to_owned();
        map.entry(key).or_insert(value);
    }
    map
}

/// Go `InsightClientBan`（middleware/insight_client_ban.go）。识别只用请求头，
/// 不依赖画像分析开关；真正的总开关是 `client_ban_enabled`。必须挂在
/// TokenAuth 之后（单用户档封禁依赖身份）。
pub async fn insight_client_ban(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let Some(db) = state.db() else {
        return next.run(request).await;
    };
    let Ok((enabled, blocked)) = load_client_ban_settings(&db).await else {
        return next.run(request).await;
    };
    if !enabled {
        return next.run(request).await;
    }
    let headers = header_map_lite(request.headers());
    let client = newapi_relay::insight_client::resolve_client(&headers, "").id;
    if client.is_empty() {
        return next.run(request).await;
    }
    let user_id = request
        .extensions()
        .get::<RelayTokenIdentity>()
        .map(|identity| identity.user_id)
        .unwrap_or_default();
    let user_bans = load_user_client_ban_set(&db, user_id).await;
    let scope = newapi_relay::client_ban::check_client_ban(user_id, &client, &blocked, &user_bans);
    if scope.is_empty() {
        return next.run(request).await;
    }
    let path = request.uri().path();
    tracing::warn!(
        event = "insight_client_ban_rejected",
        user = user_id,
        client = client,
        scope = scope,
        path = path,
        "{}",
        newapi_relay::client_ban::ban_rejection_log(user_id, &client, scope, path)
    );
    let message = if scope == "user" {
        MSG_CLIENT_BAN_USER
    } else {
        MSG_CLIENT_BAN_GLOBAL
    };
    abort_with_openai_message(StatusCode::FORBIDDEN, message, "", &request_id_of(&request))
}

// ---------------------------------------------------------------------------
// 路由组
// ---------------------------------------------------------------------------

/// Go `SetRelayRouter` 的 relay 路由组。返回待 merge 的 Router；
/// 链序见模块注释。
pub fn relay_routes(state: AppState) -> Router<AppState> {
    // /v1 组（register_relay.go:749-853）：RouteTag → SystemPerformanceCheck →
    // TokenAuth → RateLimit → UserInsight → InsightClientBan → Distribute。
    // axum 后加先执行：先加 Ban 再加 TokenAuth ⇒ TokenAuth → Ban。
    let relay_v1 = Router::new()
        .route("/v1/messages", post(relay_entry_claude))
        .route("/v1/completions", post(relay_entry_openai))
        .route("/v1/chat/completions", post(relay_entry_openai))
        .route("/v1/responses", post(relay_entry_openai_responses))
        .route("/v1/responses/compact", post(relay_entry_openai_responses))
        .route("/v1/alpha/search", post(relay_entry_openai))
        .route("/v1/edits", post(relay_entry_image))
        .route("/v1/images/generations", post(relay_entry_image))
        .route("/v1/images/edits", post(relay_entry_image))
        .route("/v1/embeddings", post(relay_entry_embedding))
        .route("/v1/audio/transcriptions", post(relay_entry_audio))
        .route("/v1/audio/translations", post(relay_entry_audio))
        .route("/v1/audio/speech", post(relay_entry_audio))
        .route("/v1/rerank", post(relay_entry_rerank))
        .route("/v1/moderations", post(relay_entry_openai))
        .route("/v1/engines/{model}/embeddings", post(relay_entry_gemini))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            insight_client_ban,
        ))
        .route_layer(middleware::from_fn_with_state(state.clone(), token_auth));

    // /v1beta Gemini relay 组（register_relay.go:872-885）。
    let relay_gemini = Router::new()
        .route("/v1beta/models/{*path}", post(relay_entry_gemini))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            insight_client_ban,
        ))
        .route_layer(middleware::from_fn_with_state(state.clone(), token_auth));

    // /v1/models 与 /v1beta models 列表组（register_relay.go:699-740）：
    // 仅 RouteTag → TokenAuth，无 Ban / RateLimit。
    //
    // axum 0.8 的 matchit 不允许同一段位置 {model} 与 {*path} 并存，而
    // Go 在 /v1/models/ 前缀上有三个 handler：GET ""（ListModels）、
    // GET /:model（RetrieveModel）、POST /*path（Gemini relay）。Rust 侧
    // 统一收敛到 {*path} 通配（与 Gemini relay 组共用处理器形状），按
    // 方法/剩余段数分流：GET 零段=ListModels、GET 单段=RetrieveModel、
    // POST=Relay(Gemini)。URL 空间与 Go 完全一致。
    let models_routes = Router::new()
        .route("/v1/models", get(list_models_entry))
        .route("/v1/models/{*path}", any(models_path_dispatch))
        .route("/v1beta/models", get(list_models_entry))
        .route("/v1beta/openai/models", get(list_models_entry))
        .route_layer(middleware::from_fn_with_state(state, token_auth));

    models_routes.merge(relay_v1).merge(relay_gemini)
}

// ---------------------------------------------------------------------------
// 入口 handler
// ---------------------------------------------------------------------------

/// relay 入口的公共前半段：凭据身份 → relay info 构建 → 参数覆盖上下文。
/// 渠道选择（Go Distribute）属其他切片；本切片终点是对 Distribute 的
/// 拦截契约回放：模型无可用渠道时 503（Go distribute_channel.go:180）。
async fn relay_entry_core(request: Request, relay_format: &'static str) -> Response {
    let request_id = request_id_of(&request);
    let language = request_language(&request);
    let identity = request.extensions().get::<RelayTokenIdentity>().cloned();
    let path = request.uri().path().to_owned();
    let is_stream = false; // stream 判定属 dispatch 切片；命中分发前不影响契约

    let headers: Vec<(String, String)> = request
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|v| (k.as_str().to_owned(), v.to_owned()))
        })
        .collect();

    let body = match to_bytes(request.into_body(), 64 * 1024 * 1024).await {
        Ok(body) => body,
        Err(_) => {
            return abort_with_openai_message(
                StatusCode::BAD_REQUEST,
                "Invalid request body",
                "",
                &request_id,
            );
        }
    };
    let payload: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);

    let model = payload
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();

    let input = newapi_relay::relay_info::RelayInfoInput {
        request_start_time_ms: 0,
        token_group: identity
            .as_ref()
            .map(|i| i.token_group.clone())
            .unwrap_or_default(),
        user_group: identity
            .as_ref()
            .map(|i| i.user_group.clone())
            .unwrap_or_default(),
        request_id: request_id.clone(),
        user_id: identity.as_ref().map(|i| i.user_id).unwrap_or_default(),
        using_group: identity
            .as_ref()
            .map(|i| i.using_group.clone())
            .unwrap_or_default(),
        user_quota: identity
            .as_ref()
            .map(|i| i.token_remain_quota)
            .unwrap_or_default(),
        user_email: String::new(),
        origin_model_name: model.clone(),
        token_id: identity.as_ref().map(|i| i.token_id).unwrap_or_default(),
        token_key: identity
            .as_ref()
            .map(|i| i.token_key.clone())
            .unwrap_or_default(),
        token_unlimited: identity
            .as_ref()
            .map(|i| i.token_unlimited_quota)
            .unwrap_or_default(),
        path: path.clone(),
        request_uri: path,
        request_headers: headers,
        estimated_tokens: 0,
        user_setting_raw: Value::Null,
        relay_mode_fallback: 0,
        is_stream,
    };
    let mut info = match newapi_relay::relay_info::gen_relay_info(relay_format, &input, &payload) {
        Ok(info) => info,
        Err(_) => {
            return abort_with_openai_message(
                StatusCode::BAD_REQUEST,
                "invalid relay format",
                "",
                &request_id,
            );
        }
    };

    // 参数覆盖：无渠道（Distribute 未接线）时 ChannelMeta 为空 →
    // 上下文仍完整构建（user/model/retry 等字段与 Go 一致），无渠道级
    // operations 可应用。计费端口调用点：预扣费会话由 billing 切片在
    // Distribute 之后创建，这里保留调用位（trait 注入替身）。
    let _override_ctx = newapi_relay::param_override::build_param_override_context(&info);
    info.append_request_conversion(relay_format);

    // Distribute 拦截契约：无可用渠道。
    let group = info.using_group.clone();
    let message = translate(
        &language,
        MSG_NO_AVAILABLE_CHANNEL,
        [("Group", group), ("Model", model)],
    );
    abort_with_openai_message(
        StatusCode::SERVICE_UNAVAILABLE,
        &message,
        "model_not_found",
        &request_id,
    )
}

async fn relay_entry_openai(request: Request) -> Response {
    relay_entry_core(request, newapi_relay::relay_info::relay_format::OPENAI).await
}

async fn relay_entry_claude(request: Request) -> Response {
    relay_entry_core(request, newapi_relay::relay_info::relay_format::CLAUDE).await
}

async fn relay_entry_openai_responses(request: Request) -> Response {
    relay_entry_core(
        request,
        newapi_relay::relay_info::relay_format::OPENAI_RESPONSES,
    )
    .await
}

async fn relay_entry_image(request: Request) -> Response {
    relay_entry_core(
        request,
        newapi_relay::relay_info::relay_format::OPENAI_IMAGE,
    )
    .await
}

async fn relay_entry_embedding(request: Request) -> Response {
    relay_entry_core(request, newapi_relay::relay_info::relay_format::EMBEDDING).await
}

async fn relay_entry_audio(request: Request) -> Response {
    relay_entry_core(
        request,
        newapi_relay::relay_info::relay_format::OPENAI_AUDIO,
    )
    .await
}

async fn relay_entry_rerank(request: Request) -> Response {
    relay_entry_core(request, newapi_relay::relay_info::relay_format::RERANK).await
}

async fn relay_entry_gemini(request: Request) -> Response {
    relay_entry_core(request, newapi_relay::relay_info::relay_format::GEMINI).await
}

/// Go `/v1/models` 列表：渠道目录依赖（ratio/catalog 切片）未移植，路由
/// 与鉴权链先接线；handler 按键缺省回落 OpenAI 形状空列表的语义占位，
/// 契约测试只覆盖鉴权链。
async fn list_models_entry(request: Request) -> Response {
    let _ = token_auth_passed(&request);
    // Go ListModels 按头分流 Anthropic/Gemini/OpenAI 形状；目录切片未就绪前
    // 返回 OpenAI 形状空列表（success=true，object=list）。
    (
        StatusCode::OK,
        axum::Json(json!({"success": true, "data": [], "object": "list"})),
    )
        .into_response()
}

/// Go `RetrieveModel`：未知名返回 200 + error 信封（handle_model.go:329-352）。
/// 静态目录未移植，所有名字按未处理。
async fn retrieve_model_entry(request: Request) -> Response {
    let model = request
        .extensions()
        .get::<axum::extract::RawPathParams>()
        .and_then(|params| params.iter().next().map(|(_, seg)| seg.to_owned()))
        .unwrap_or_default();
    let _ = token_auth_passed(&request);
    (
        StatusCode::OK,
        axum::Json(json!({
            "error": {
                "message": format!("The model '{model}' does not exist"),
                "type": "invalid_request_error",
                "param": "model",
                "code": "model_not_found"
            }
        })),
    )
        .into_response()
}

/// `/v1/models/{*path}` 方法分流：GET = RetrieveModel（单段 = model 名），
/// POST = Relay(Gemini)（register_relay.go:714-721, 831-833）。
async fn models_path_dispatch(request: axum::extract::Request) -> Response {
    if request.method() == axum::http::Method::POST {
        relay_entry_gemini(request).await
    } else {
        retrieve_model_entry(request).await
    }
}

fn token_auth_passed(request: &Request) -> bool {
    request.extensions().get::<RelayTokenIdentity>().is_some()
}
