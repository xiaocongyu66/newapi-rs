//! `/api/token/*` management HTTP adapters.
//!
//! Go references:
//! - `apps/api/internal/identity/manage_tokens.go` (`GetAllTokens`,
//!   `SearchTokens`, `GetTokenAutoGroups`, `GetToken`, `GetTokenKey`,
//!   `AddToken`, `UpdateToken`, `DeleteToken`)
//! - `apps/api/internal/identity/token_store.go` (token record and key rules)
//! - `apps/api/internal/transport/compose/register_api.go:360-370` (routes)
//!
//! Every business outcome is HTTP 200 with the Go envelope; only the
//! `UserAuth` middleware produces 401/403. The one exception in the route
//! chain is `POST /api/token/:id/key`, which writes the three no-cache headers
//! for every outcome, including business errors.
//!
//! The raw token key is a credential. It is returned only by `/:id/key`; all
//! other responses carry [`newapi_identity::tokens::mask_token_key`] output.
//! Database error text and key values never enter a log line.

use std::collections::{BTreeMap, HashSet};

use axum::{
    Json,
    body::Bytes,
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use newapi_catalog::group_settings::GroupSettings;
use newapi_identity::{
    self_user::QuotaDisplaySettings,
    tokens::{
        self, LikePatternError, NewToken, TokenRecord, TokenRepository, TokenRuntimeSettings,
        TokenSearch, TokenUpdate, TOKEN_STATUS_ENABLED, TOKEN_STATUS_EXHAUSTED,
        TOKEN_STATUS_EXPIRED,
    },
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::AuthenticatedUser;
use crate::boundary_mw::disable_cache_headers;

const MSG_INVALID_PARAMS: &str = "common.invalid_params";
const MSG_NOT_FOUND: &str = "common.not_found";
const MSG_DATABASE_ERROR: &str = "common.database_error";
const MSG_NAME_TOO_LONG: &str = "token.name_too_long";
const MSG_QUOTA_NEGATIVE: &str = "token.quota_negative";
const MSG_QUOTA_EXCEED_MAX: &str = "token.quota_exceed_max";
const MSG_GENERATE_FAILED: &str = "token.generate_failed";
const MSG_EXPIRED_CANNOT_ENABLE: &str = "token.expired_cannot_enable";
const MSG_EXHAUSTED_CANNOT_ENABLE: &str = "token.exhausted_cannot_enable";
const MSG_AUTO_GROUPS_TOO_MANY: &str = "token.auto_groups_too_many";
const MSG_AUTO_GROUPS_DUPLICATE: &str = "token.auto_groups_duplicate";
const MSG_AUTO_GROUPS_INVALID: &str = "token.auto_groups_invalid";

// Go returns these as raw (untranslated) strings. Keys do not exist in
// `crates/i18n/locales` yet; they are listed in the delivery report.
const MSG_MAX_TOKENS_REACHED: &str = "token.max_tokens_reached";
const MSG_INVALID_QUOTA_VALUE: &str = "token.invalid_quota_value";
const MSG_SEARCH_TOO_MANY: &str = "token.search_too_many";

/// Go `common.GetPageQuery` accepts `p`, `page_size`, and the `ps`/`size`
/// compatibility aliases; unknown query keys are ignored.
#[derive(Debug, Default, Deserialize)]
struct PageQuery {
    p: Option<String>,
    page_size: Option<String>,
    ps: Option<String>,
    size: Option<String>,
    keyword: Option<String>,
    token: Option<String>,
    status_only: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PageInfo {
    page: i64,
    page_size: i64,
    offset: i64,
}

/// Go `strconv.Atoi`: optional sign plus decimal digits, no whitespace.
fn parse_i64(value: Option<&str>) -> Option<i64> {
    value.and_then(|value| value.parse::<i64>().ok())
}

fn page_info(query: &PageQuery) -> PageInfo {
    let mut page = parse_i64(query.p.as_deref()).unwrap_or(0);
    let mut page_size = parse_i64(query.page_size.as_deref()).unwrap_or(0);
    if page < 1 {
        let compat = parse_i64(query.p.as_deref()).unwrap_or(0);
        page = if compat != 0 { compat } else { 1 };
    }
    if page_size == 0 {
        if let Some(value) = parse_i64(query.ps.as_deref()) {
            if value != 0 {
                page_size = value;
            }
        }
        if page_size == 0 {
            if let Some(value) = parse_i64(query.size.as_deref()) {
                if value != 0 {
                    page_size = value;
                }
            }
        }
        if page_size == 0 {
            page_size = 10;
        }
    }
    if page_size > 100 {
        page_size = 100;
    }
    PageInfo {
        page,
        page_size,
        offset: page.saturating_sub(1).saturating_mul(page_size),
    }
}

/// Go `tokenAutoGroupsInput`: presence (even `null`) sets the field; only
/// `UpdateToken` distinguishes absent, `null`, and an explicit list.
#[derive(Debug, Default)]
struct AutoGroupsInput {
    set: bool,
    groups: Vec<String>,
}

impl<'de> Deserialize<'de> for AutoGroupsInput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Option::<Vec<String>>::deserialize(deserializer)?;
        Ok(Self {
            set: true,
            groups: value.unwrap_or_default(),
        })
    }
}

/// `identity.tokenRequest`: the embedded `Token` plus the outer
/// `remain_quota_display` (which shadows the embedded field) and
/// `auto_groups`. Fields are optional so JSON `null` behaves like Go's
/// zero-value assignment instead of a decode error.
// Some embedded `Token` fields are decoded only to reproduce Go's type
// errors; they never affect the management handlers.
#[allow(dead_code)]
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct TokenRequest {
    id: Option<i64>,
    user_id: Option<i64>,
    key: Option<String>,
    status: Option<i64>,
    name: Option<String>,
    created_time: Option<i64>,
    accessed_time: Option<i64>,
    expired_time: Option<i64>,
    remain_quota: Option<i64>,
    remain_quota_display: Option<f64>,
    unlimited_quota: Option<bool>,
    model_limits_enabled: Option<bool>,
    model_limits: Option<String>,
    allow_ips: Option<String>,
    used_quota: Option<i64>,
    used_quota_display: Option<f64>,
    group: Option<String>,
    cross_group_retry: Option<bool>,
    auto_groups: AutoGroupsInput,
}

/// Go `c.BindJSON(&request)`: empty/invalid JSON and a non-object top level
/// are errors, while `null` decodes as the zero value.
fn parse_token_request(body: &[u8]) -> Option<TokenRequest> {
    let value: Value = serde_json::from_slice(body).ok()?;
    match value {
        Value::Null => Some(TokenRequest::default()),
        Value::Object(object) => serde_json::from_value(Value::Object(object)).ok(),
        _ => None,
    }
}

/// `GET /api/token/`.
pub async fn list_tokens(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    Query(query): Query<PageQuery>,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let repository = TokenRepository::new(db);
    let info = page_info(&query);
    let tokens = match repository
        .list_for_user(auth_user.0.user_id, info.offset, info.page_size)
        .await
    {
        Ok(tokens) => tokens,
        Err(error) => return database_error(&headers, error),
    };
    // Go ignores a count failure (`total, _ := CountUserTokens(userId)`).
    let total = repository
        .count_for_user(auth_user.0.user_id)
        .await
        .unwrap_or(0);
    let display = state.quota_display();
    let items: Vec<Value> = tokens
        .iter()
        .map(|token| masked_token_json(token, display))
        .collect();
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

/// `GET /api/token/search`.
pub async fn search_tokens(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    Query(query): Query<PageQuery>,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let repository = TokenRepository::new(db);
    let info = page_info(&query);
    let mut keyword = query.keyword.clone().unwrap_or_default();
    let mut key = query.token.clone().unwrap_or_default();
    if let Some(stripped) = key.strip_prefix("sk-") {
        key = stripped.to_owned();
    }
    let runtime = match TokenRuntimeSettings::load(repository.database()).await {
        Ok(settings) => settings,
        Err(error) => return database_error(&headers, error),
    };
    // Go only counts when a fuzzy `%` wildcard is present.
    if keyword.contains('%') || key.contains('%') {
        let count = match repository.count_for_user(auth_user.0.user_id).await {
            Ok(count) => count,
            Err(error) => return database_error(&headers, error),
        };
        if count > runtime.max_user_tokens {
            return api_error(&headers, MSG_SEARCH_TOO_MANY);
        }
    }
    if !keyword.is_empty() {
        keyword = match tokens::sanitize_like_pattern(&keyword) {
            Ok(pattern) => pattern,
            Err(error) => return like_pattern_error(&headers, error),
        };
    }
    if !key.is_empty() {
        key = match tokens::sanitize_like_pattern(&key) {
            Ok(pattern) => pattern,
            Err(error) => return like_pattern_error(&headers, error),
        };
    }
    // Go `SearchUserTokens` clamps the page size independently of pageInfo.
    let limit = if info.page_size <= 0 || info.page_size > 100 {
        100
    } else {
        info.page_size
    };
    let offset = info.offset.max(0);
    let search = TokenSearch {
        keyword: &keyword,
        key: &key,
        offset,
        limit,
        max_tokens: runtime.max_user_tokens,
    };
    let (tokens, total) = match repository
        .search_for_user(auth_user.0.user_id, &search)
        .await
    {
        Ok(result) => result,
        Err(error) => return database_error(&headers, error),
    };
    let display = state.quota_display();
    let items: Vec<Value> = tokens
        .iter()
        .map(|token| masked_token_json(token, display))
        .collect();
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

/// `GET /api/token/auto-groups`.
pub async fn token_auto_groups(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let repository = TokenRepository::new(db);
    let runtime = match TokenRuntimeSettings::load(repository.database()).await {
        Ok(settings) => settings,
        Err(error) => return database_error(&headers, error),
    };
    let settings = match load_group_settings(repository.database()).await {
        Some(settings) => settings,
        None => return database_error_message(&headers),
    };
    let user_group = match resolve_user_group(&repository, &auth_user, &headers).await {
        Ok(group) => group,
        Err(response) => return response,
    };
    let usable = settings.user_usable_groups(&user_group);
    let mut seen = HashSet::new();
    let groups: Vec<&String> = runtime
        .auto_groups
        .iter()
        .filter(|group| {
            is_selectable_group(&usable, &settings, group.as_str())
                && seen.insert(group.as_str())
        })
        .collect();
    Json(json!({
        "success": true,
        "message": "",
        "data": {
            "groups": groups,
            "max_count": runtime.max_token_auto_groups,
        },
    }))
    .into_response()
}

/// `GET /api/token/:id`.
pub async fn get_token(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let id = match id.parse::<i64>() {
        Ok(id) => id,
        Err(_) => return api_error(&headers, MSG_INVALID_PARAMS),
    };
    let repository = TokenRepository::new(db);
    match repository
        .by_id_for_user(auth_user.0.user_id, id)
        .await
    {
        Ok(Some(token)) => success(Some(masked_token_json(&token, state.quota_display()))),
        Ok(None) => api_error(&headers, MSG_NOT_FOUND),
        Err(error) => database_error(&headers, error),
    }
}

/// `POST /api/token/:id/key`; Go installs `DisableCache` on this route, so
/// every outcome carries the three no-cache headers.
pub async fn get_token_key(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let mut response = get_token_key_inner(&state, &auth_user, &id, &headers).await;
    disable_cache_headers(&mut response);
    response
}

async fn get_token_key_inner(
    state: &AppState,
    auth_user: &AuthenticatedUser,
    id: &str,
    headers: &HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let id = match id.parse::<i64>() {
        Ok(id) => id,
        Err(_) => return api_error(headers, MSG_INVALID_PARAMS),
    };
    let repository = TokenRepository::new(db);
    match repository
        .by_id_for_user(auth_user.0.user_id, id)
        .await
    {
        // Only this endpoint returns the unmasked key.
        Ok(Some(token)) => success(Some(json!({ "key": token.key }))),
        Ok(None) => api_error(headers, MSG_NOT_FOUND),
        Err(error) => database_error(headers, error),
    }
}

/// `POST /api/token/`.
pub async fn add_token(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Some(request) = parse_token_request(&body) else {
        return api_error(&headers, MSG_INVALID_PARAMS);
    };
    let repository = TokenRepository::new(db);
    let runtime = match TokenRuntimeSettings::load(repository.database()).await {
        Ok(settings) => settings,
        Err(error) => return database_error(&headers, error),
    };
    let display = state.quota_display();
    let unlimited_quota = request.unlimited_quota.unwrap_or(false);
    let remain_quota = if unlimited_quota {
        request.remain_quota.unwrap_or(0)
    } else {
        let amount = request.remain_quota_display.unwrap_or(0.0);
        if !amount.is_finite() {
            return api_error(&headers, MSG_INVALID_QUOTA_VALUE);
        }
        tokens::quota_from_display(amount, display)
    };
    let name = request.name.clone().unwrap_or_default();
    if name.len() > 50 {
        return api_error(&headers, MSG_NAME_TOO_LONG);
    }
    if !unlimited_quota {
        if remain_quota < 0 {
            return api_error(&headers, MSG_QUOTA_NEGATIVE);
        }
        let max = tokens::max_quota_value(display.quota_per_unit);
        if remain_quota > max {
            return api_error_args(
                &headers,
                MSG_QUOTA_EXCEED_MAX,
                &[("Max", max.to_string())],
            );
        }
    }
    let count = match repository.count_for_user(auth_user.0.user_id).await {
        Ok(count) => count,
        Err(error) => return database_error(&headers, error),
    };
    if count >= runtime.max_user_tokens {
        return api_error_args(
            &headers,
            MSG_MAX_TOKENS_REACHED,
            &[("Max", runtime.max_user_tokens.to_string())],
        );
    }
    let group = request.group.clone().unwrap_or_default();
    let mut cross_group_retry = request.cross_group_retry.unwrap_or(false);
    let auto_groups = if group == "auto" {
        let settings = match load_group_settings(repository.database()).await {
            Some(settings) => settings,
            None => return database_error_message(&headers),
        };
        let user_group = match resolve_user_group(&repository, &auth_user, &headers).await {
            Ok(group) => group,
            Err(response) => return response,
        };
        match validate_auto_groups(
            &request.auto_groups.groups,
            &settings,
            &user_group,
            runtime.max_token_auto_groups,
            &headers,
        ) {
            Ok(stored) => stored,
            Err(response) => return response,
        }
    } else {
        cross_group_retry = false;
        String::new()
    };
    let Some(key) = tokens::generate_token_key() else {
        return api_error(&headers, MSG_GENERATE_FAILED);
    };
    let now = crate::http::now_seconds();
    let token = NewToken {
        user_id: auth_user.0.user_id,
        key,
        name,
        created_time: now,
        accessed_time: now,
        // GORM omits zero values that have a DB default, so an omitted
        // `expired_time` becomes the column default `-1`.
        expired_time: match request.expired_time.unwrap_or(0) {
            0 => -1,
            value => value,
        },
        remain_quota,
        unlimited_quota,
        model_limits_enabled: request.model_limits_enabled.unwrap_or(false),
        model_limits: request.model_limits.clone().unwrap_or_default(),
        allow_ips: request.allow_ips.clone(),
        group,
        cross_group_retry,
        auto_groups,
    };
    match repository.insert(&token).await {
        Ok(_) => success(None),
        Err(error) => database_error(&headers, error),
    }
}

/// `PUT /api/token/`.
pub async fn update_token(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    Query(query): Query<PageQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Some(request) = parse_token_request(&body) else {
        return api_error(&headers, MSG_INVALID_PARAMS);
    };
    let status_only = query
        .status_only
        .as_deref()
        .is_some_and(|value| !value.is_empty());
    let name = request.name.clone().unwrap_or_default();
    if name.len() > 50 {
        return api_error(&headers, MSG_NAME_TOO_LONG);
    }
    let unlimited_quota = request.unlimited_quota.unwrap_or(false);
    let remain_quota = request.remain_quota.unwrap_or(0);
    let display = state.quota_display();
    if !unlimited_quota {
        if remain_quota < 0 {
            return api_error(&headers, MSG_QUOTA_NEGATIVE);
        }
        let max = tokens::max_quota_value(display.quota_per_unit);
        if remain_quota > max {
            return api_error_args(
                &headers,
                MSG_QUOTA_EXCEED_MAX,
                &[("Max", max.to_string())],
            );
        }
    }
    let repository = TokenRepository::new(db);
    let user_id = auth_user.0.user_id;
    let id = request.id.unwrap_or(0);
    let existing = match repository.by_id_for_user(user_id, id).await {
        Ok(Some(token)) => token,
        Ok(None) => return api_error(&headers, MSG_NOT_FOUND),
        Err(error) => return database_error(&headers, error),
    };
    let status = request.status.unwrap_or(0);
    if status == TOKEN_STATUS_ENABLED {
        if existing.status == TOKEN_STATUS_EXPIRED
            && existing.expired_time <= crate::http::now_seconds()
            && existing.expired_time != -1
        {
            return api_error(&headers, MSG_EXPIRED_CANNOT_ENABLE);
        }
        if existing.status == TOKEN_STATUS_EXHAUSTED
            && existing.remain_quota <= 0
            && !existing.unlimited_quota
        {
            return api_error(&headers, MSG_EXHAUSTED_CANNOT_ENABLE);
        }
    }
    if status_only {
        match repository
            .update_status_for_user(user_id, id, status)
            .await
        {
            Ok(true) => {}
            Ok(false) => return api_error(&headers, MSG_NOT_FOUND),
            Err(error) => return database_error(&headers, error),
        }
    } else {
        let group = request.group.clone().unwrap_or_default();
        let mut cross_group_retry = request.cross_group_retry.unwrap_or(false);
        let auto_groups = if group != "auto" {
            // Go clears Auto state whenever the token leaves the auto group.
            cross_group_retry = false;
            String::new()
        } else if request.auto_groups.set {
            match load_group_settings(repository.database()).await {
                Some(settings) => {
                    let user_group =
                        match resolve_user_group(&repository, &auth_user, &headers).await {
                            Ok(group) => group,
                            Err(response) => return response,
                        };
                    let runtime =
                        match TokenRuntimeSettings::load(repository.database()).await {
                            Ok(runtime) => runtime,
                            Err(error) => return database_error(&headers, error),
                        };
                    match validate_auto_groups(
                        &request.auto_groups.groups,
                        &settings,
                        &user_group,
                        runtime.max_token_auto_groups,
                        &headers,
                    ) {
                        Ok(stored) => stored,
                        Err(response) => return response,
                    }
                }
                None => return database_error_message(&headers),
            }
        } else {
            existing.auto_groups.clone()
        };
        let update = TokenUpdate {
            name,
            expired_time: request.expired_time.unwrap_or(0),
            remain_quota,
            unlimited_quota,
            model_limits_enabled: request.model_limits_enabled.unwrap_or(false),
            model_limits: request.model_limits.clone().unwrap_or_default(),
            allow_ips: request.allow_ips.clone(),
            group,
            cross_group_retry,
            auto_groups,
        };
        match repository.update_for_user(user_id, id, &update).await {
            Ok(true) => {}
            Ok(false) => return api_error(&headers, MSG_NOT_FOUND),
            Err(error) => return database_error(&headers, error),
        }
    }
    match repository.by_id_for_user(user_id, id).await {
        Ok(Some(token)) => success(Some(masked_token_json(&token, display))),
        Ok(None) => api_error(&headers, MSG_NOT_FOUND),
        Err(error) => database_error(&headers, error),
    }
}

/// `DELETE /api/token/:id`.
pub async fn delete_token(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    // Go ignores the Atoi error, so a malformed id becomes 0 and then fails
    // the ownership lookup just like a missing row.
    let id = id.parse::<i64>().unwrap_or(0);
    let repository = TokenRepository::new(db);
    match repository.delete_for_user(auth_user.0.user_id, id).await {
        Ok(true) => success(None),
        Ok(false) => api_error(&headers, MSG_NOT_FOUND),
        Err(error) => database_error(&headers, error),
    }
}

fn masked_token_json(token: &TokenRecord, display: QuotaDisplaySettings) -> Value {
    json!({
        "id": token.id,
        "user_id": token.user_id,
        "key": tokens::mask_token_key(&token.key),
        "status": token.status,
        "name": token.name,
        "created_time": token.created_time,
        "accessed_time": token.accessed_time,
        "expired_time": token.expired_time,
        "remain_quota": token.remain_quota,
        "remain_quota_display": display.to_display(token.remain_quota),
        "unlimited_quota": token.unlimited_quota,
        "model_limits_enabled": token.model_limits_enabled,
        "model_limits": token.model_limits,
        "allow_ips": token.allow_ips,
        "used_quota": token.used_quota,
        "used_quota_display": display.to_display(token.used_quota),
        "group": token.group,
        "cross_group_retry": token.cross_group_retry,
        "auto_groups": auto_groups_json(&token.auto_groups),
    })
}

/// Go `buildMaskedTokenResponse`: empty or unparseable Auto state is `null`.
fn auto_groups_json(raw: &str) -> Value {
    match tokens::parse_auto_groups(raw) {
        Some(groups) if !groups.is_empty() => json!(groups),
        _ => Value::Null,
    }
}

async fn load_group_settings(db: &newapi_storage::Database) -> Option<GroupSettings> {
    match GroupSettings::load(db, &GroupSettings::default()).await {
        Ok(settings) => Some(settings),
        Err(error) => {
            tracing::warn!(
                event = "token_group_settings_load_failed",
                category = crate::database_error_class(&error),
                "token group settings load failed"
            );
            None
        }
    }
}

#[allow(clippy::result_large_err)]
async fn resolve_user_group(
    repository: &TokenRepository,
    auth_user: &AuthenticatedUser,
    headers: &HeaderMap,
) -> Result<String, Response> {
    if !auth_user.0.group.is_empty() {
        return Ok(auth_user.0.group.clone());
    }
    match repository.user_group(auth_user.0.user_id).await {
        Ok(Some(group)) => Ok(group),
        Ok(None) => Err(api_error(headers, MSG_NOT_FOUND)),
        Err(error) => Err(database_error(headers, error)),
    }
}

/// Go `IsUserSelectableGroup`: the pseudo groups are never selectable, and a
/// group must be both usable for this user and present in `GroupRatio`.
fn is_selectable_group(
    usable: &BTreeMap<String, String>,
    settings: &GroupSettings,
    group: &str,
) -> bool {
    !group.is_empty()
        && group != "auto"
        && usable.contains_key(group)
        && settings.group_ratio.contains_key(group)
}

/// Go `setTokenAutoGroups`; returns the value to persist.
#[allow(clippy::result_large_err)]
fn validate_auto_groups(
    groups: &[String],
    settings: &GroupSettings,
    user_group: &str,
    max_count: i64,
    headers: &HeaderMap,
) -> Result<String, Response> {
    if groups.is_empty() {
        return Ok(String::new());
    }
    if groups.len() as i64 > max_count {
        return Err(api_error_args(
            headers,
            MSG_AUTO_GROUPS_TOO_MANY,
            &[("Max", max_count.to_string())],
        ));
    }
    let usable = settings.user_usable_groups(user_group);
    let mut seen = HashSet::new();
    for group in groups {
        if !seen.insert(group.as_str()) {
            return Err(api_error_args(
                headers,
                MSG_AUTO_GROUPS_DUPLICATE,
                &[("Group", group.clone())],
            ));
        }
        if !is_selectable_group(&usable, settings, group.as_str()) {
            return Err(api_error_args(
                headers,
                MSG_AUTO_GROUPS_INVALID,
                &[("Group", group.clone())],
            ));
        }
    }
    Ok(tokens::serialize_auto_groups(groups))
}

fn success(data: Option<Value>) -> Response {
    match data {
        Some(data) => {
            Json(json!({ "success": true, "message": "", "data": data })).into_response()
        }
        None => Json(json!({ "success": true, "message": "" })).into_response(),
    }
}

fn api_error(headers: &HeaderMap, key: &str) -> Response {
    Json(json!({
        "success": false,
        "message": translate(headers, key),
    }))
    .into_response()
}

fn api_error_args(headers: &HeaderMap, key: &str, args: &[(&str, String)]) -> Response {
    Json(json!({
        "success": false,
        "message": translate_args(headers, key, args),
    }))
    .into_response()
}

fn like_pattern_error(headers: &HeaderMap, error: LikePatternError) -> Response {
    api_error(headers, error.message_key())
}

fn database_error(headers: &HeaderMap, error: sqlx::Error) -> Response {
    tracing::warn!(
        event = "token_database_operation_failed",
        category = crate::database_error_class(&error),
        "token database operation failed"
    );
    database_error_message(headers)
}

fn database_error_message(headers: &HeaderMap) -> Response {
    api_error(headers, MSG_DATABASE_ERROR)
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

fn translate_args(headers: &HeaderMap, key: &str, args: &[(&str, String)]) -> String {
    newapi_i18n::translate(
        &request_language(headers),
        key,
        args.iter().map(|(name, value)| (*name, value.as_str())),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_info_matches_go_defaults_and_aliases() {
        let empty = page_info(&PageQuery::default());
        assert_eq!(
            empty,
            PageInfo {
                page: 1,
                page_size: 10,
                offset: 0
            }
        );
        let explicit = page_info(&PageQuery {
            p: Some("3".to_owned()),
            page_size: Some("20".to_owned()),
            ..PageQuery::default()
        });
        assert_eq!(
            explicit,
            PageInfo {
                page: 3,
                page_size: 20,
                offset: 40
            }
        );
        // `ps` then `size` compatibility aliases.
        assert_eq!(
            page_info(&PageQuery {
                p: Some("0".to_owned()),
                ps: Some("5".to_owned()),
                ..PageQuery::default()
            })
            .page_size,
            5
        );
        assert_eq!(
            page_info(&PageQuery {
                size: Some("7".to_owned()),
                ..PageQuery::default()
            })
            .page_size,
            7
        );
        // Page size is capped at 100; page 0 falls back to 1.
        assert_eq!(
            page_info(&PageQuery {
                page_size: Some("1000".to_owned()),
                ..PageQuery::default()
            })
            .page_size,
            100
        );
    }

    #[test]
    fn auto_groups_input_distinguishes_absent_null_and_list() {
        let absent: TokenRequest = serde_json::from_str("{}").unwrap();
        assert!(!absent.auto_groups.set);

        let null: TokenRequest = serde_json::from_str(r#"{"auto_groups":null}"#).unwrap();
        assert!(null.auto_groups.set);
        assert!(null.auto_groups.groups.is_empty());

        let list: TokenRequest =
            serde_json::from_str(r#"{"auto_groups":["vip","default"]}"#).unwrap();
        assert!(list.auto_groups.set);
        assert_eq!(list.auto_groups.groups, vec!["vip", "default"]);
    }

    #[test]
    fn request_null_is_the_go_zero_value() {
        assert!(parse_token_request(b"null").is_some());
        assert!(parse_token_request(b"[]").is_none());
        assert!(parse_token_request(b"").is_none());
        assert!(parse_token_request(br#"{"status":"1"}"#).is_none());
    }

    #[test]
    fn masked_json_never_contains_the_raw_key() {
        let token = TokenRecord {
            id: 1,
            user_id: 2,
            key: "abcd1234efgh5678".to_owned(),
            status: 1,
            name: "n".to_owned(),
            created_time: 0,
            accessed_time: 0,
            expired_time: -1,
            remain_quota: 0,
            used_quota: 0,
            unlimited_quota: true,
            model_limits_enabled: false,
            model_limits: String::new(),
            allow_ips: None,
            group: "default".to_owned(),
            cross_group_retry: false,
            auto_groups: String::new(),
        };
        let body = masked_token_json(
            &token,
            QuotaDisplaySettings {
                quota_per_unit: 500_000.0,
                kind: newapi_identity::self_user::QuotaDisplayKind::Usd,
            },
        );
        assert_eq!(body["key"], json!("abcd**********5678"));
        assert_eq!(body["auto_groups"], Value::Null);
        assert!(!body.to_string().contains(&token.key));
    }
}
