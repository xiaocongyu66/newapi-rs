//! Transport middleware sweep: the remaining Go `transport/middleware` pieces
//! that prior slices did not cover. Every item states its Go oracle and the
//! exact contract it replicates; divergences are deliberate and documented.
//!
//! Go references (read-only oracle `/root/newapi`):
//! - `transport/middleware/assign_request_id.go` (`RequestId`)
//! - `transport/middleware/collect_stats.go` (`StatsMiddleware` / `GetStats`)
//! - `transport/middleware/check_performance.go` (`SystemPerformanceCheck`)
//! - `transport/middleware/geo_block.go` (`GeoBlock`) + `geoip/geoip.go`
//! - `transport/middleware/cache_response.go` (`Cache`)
//! - `transport/middleware/collect_user_insight.go` (`UserInsight`)
//! - `transport/middleware/convert_jimeng.go` / `convert_kling.go`
//! - `transport/compose/register_relay.go` (chain order), `main.go:218-221`
//!   (engine-level registration order)
//!
//! Chain-order contract (Go registration order → execution order):
//! engine level (main.go:218-221): RequestId → Version → I18n → GeoBlock.
//! `/v1` relay group (register_relay.go:71-76): RouteTag →
//! SystemPerformanceCheck → TokenAuth → ModelRequestRateLimit → UserInsight →
//! InsightClientBan → Distribute. axum layers added later run first, so
//! registration below is the reverse of Go's execution order.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json,
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

use crate::AppState;

// ---------------------------------------------------------------------------
// RequestId (assign_request_id.go)
// ---------------------------------------------------------------------------

/// Go `common.RequestIdKey` (`common/constants.go:186`).
pub const REQUEST_ID_HEADER: &str = "x-oneapi-request-id";

/// Go `common.NewRequestId()` (`common/utils.go:202`):
/// `GetTimeString() + requestIdPrefix + GetRandomString(8)` where
/// GetTimeString is UTC `20060102150405` + 9-digit nanosecond remainder and
/// GetRandomString(8) is 8 alphanumeric characters (`lo.RandomString`,
/// `common/str.go:30-35`). The build-info SHA prefix collapses to the random
/// fallback in Go tests; here both fixed segments are random, which preserves
/// the id's shape and uniqueness contract.
pub fn new_request_id() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let nanos = now.subsec_nanos();
    let (year, month, day) = civil_from_days((secs / 86_400) as i64);
    let second_of_day = secs % 86_400;
    let time_string = format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}{:09}",
        year,
        month,
        day,
        second_of_day / 3600,
        (second_of_day % 3600) / 60,
        second_of_day % 60,
        nanos,
    );
    format!("{time_string}{}{}", random_alnum(8), random_alnum(8))
}

/// Days since 1970-01-01 → (year, month, day); Howard Hinnant's algorithm.
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

const ALNUM_LEN: u8 = 62;

/// Go `GetRandomString(n)` over `lo.AlphanumericCharset` (62 chars).
fn random_alnum(n: usize) -> String {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut bytes = vec![0u8; n];
    SystemRandom::new()
        .fill(&mut bytes)
        .expect("system randomness unavailable");
    const CHARSET: &[u8; 62] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    bytes
        .iter()
        .map(|b| CHARSET[(*b % ALNUM_LEN) as usize] as char)
        .collect()
}

/// Go `RequestId` (assign_request_id.go:9-17): generate a fresh id, store it
/// on the request (`c.Set` + `c.SetContextValue`) and set the response header
/// before continuing. A request-supplied id is NOT honoured: Go always
/// generates a new one.
pub async fn request_id(request: Request, next: Next) -> Response {
    let id = new_request_id();
    let mut request = request;
    request.extensions_mut().insert(RequestId(id.clone()));
    let mut response = next.run(request).await;
    if let (Ok(name), Ok(value)) = (
        header::HeaderName::try_from(REQUEST_ID_HEADER),
        HeaderValue::from_str(&id),
    ) {
        response.headers_mut().insert(name, value);
    }
    response
}

/// Extension carrying the Go `common.RequestIdKey` value.
#[derive(Clone, Debug)]
pub struct RequestId(pub String);

impl RequestId {
    /// The id from extensions, or "" like Go's `GetString` on a missing key.
    pub fn from_request(request: &Request) -> String {
        request
            .extensions()
            .get::<RequestId>()
            .map(|id| id.0.clone())
            .unwrap_or_default()
    }
}

/// Go `common.MessageWithRequestId` (utils.go:211-215).
pub fn message_with_request_id(message: &str, request_id: &str) -> String {
    if request_id.is_empty() {
        message.to_owned()
    } else {
        format!("{message} (request id: {request_id})")
    }
}

// ---------------------------------------------------------------------------
// StatsMiddleware (collect_stats.go)
// ---------------------------------------------------------------------------

/// Go `globalStats.activeConnections`: one process-wide counter.
static ACTIVE_CONNECTIONS: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

/// Go `StatsMiddleware` (collect_stats.go:16-28): increment before the chain,
/// decrement when the middleware returns (Go's `defer` runs on return from
/// the middleware, i.e. after `c.Next()` completed).
pub async fn stats_middleware(request: Request, next: Next) -> Response {
    use std::sync::atomic::Ordering;
    ACTIVE_CONNECTIONS.fetch_add(1, Ordering::AcqRel);
    let response = next.run(request).await;
    ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::AcqRel);
    response
}

/// Go `GetStats()` (collect_stats.go:36-40) — the `active_connections` field.
pub fn get_stats() -> i64 {
    use std::sync::atomic::Ordering;
    ACTIVE_CONNECTIONS.load(Ordering::Acquire)
}

// ---------------------------------------------------------------------------
// SystemPerformanceCheck (check_performance.go)
// ---------------------------------------------------------------------------

/// Go `common.SystemStatus` (`common/system_monitor.go:24-28`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SystemStatus {
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub disk_usage: f64,
}

/// Port for Go `common.GetSystemStatus` (populated by the system monitor
/// goroutine). The default source stays at the Go init() zero state
/// (`system_monitor.go:32-34`): a monitor that has not reported yet.
pub trait SystemStatusSource: Send + Sync {
    fn status(&self) -> SystemStatus;
}

/// Go boot state: `latestSystemStatus` initialised to `SystemStatus{}`.
pub struct ZeroSystemStatus;

impl SystemStatusSource for ZeroSystemStatus {
    fn status(&self) -> SystemStatus {
        SystemStatus {
            cpu_usage: 0.0,
            memory_usage: 0.0,
            disk_usage: 0.0,
        }
    }
}

/// Go `common.PerformanceMonitorConfig` (`common/performance_config.go:6-11`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PerformanceMonitorConfig {
    pub enabled: bool,
    pub cpu_threshold: i64,
    pub memory_threshold: i64,
    pub disk_threshold: i64,
}

/// Go option keys (`usage/configure_perf.go:196-201` syncs
/// `performance_setting.*` into the config). Defaults
/// (`configure_perf.go:174-177`): enabled, 90 / 90 / 95.
pub const MONITOR_ENABLED_OPTION: &str = "performance_setting.monitor_enabled";
pub const MONITOR_CPU_THRESHOLD_OPTION: &str = "performance_setting.monitor_cpu_threshold";
pub const MONITOR_MEMORY_THRESHOLD_OPTION: &str = "performance_setting.monitor_memory_threshold";
pub const MONITOR_DISK_THRESHOLD_OPTION: &str = "performance_setting.monitor_disk_threshold";

pub const PERFORMANCE_MONITOR_DEFAULT: PerformanceMonitorConfig = PerformanceMonitorConfig {
    enabled: true,
    cpu_threshold: 90,
    memory_threshold: 90,
    disk_threshold: 95,
};

/// Loads the monitor config from the options table. Go keeps these in an
/// in-memory mirror refreshed by the settings registry (`updateConfigFromMap`:
/// int via `ParseInt`→`ParseFloat`, failure **keeps** the current value);
/// the Rust port reads the option rows per request with the same
/// keep-current-on-parse-failure semantics.
pub async fn load_performance_monitor_config(
    db: &newapi_storage::Database,
) -> PerformanceMonitorConfig {
    let mut config = PERFORMANCE_MONITOR_DEFAULT;
    for (key, sink) in [
        (MONITOR_ENABLED_OPTION, 0usize),
        (MONITOR_CPU_THRESHOLD_OPTION, 1),
        (MONITOR_MEMORY_THRESHOLD_OPTION, 2),
        (MONITOR_DISK_THRESHOLD_OPTION, 3),
    ] {
        let raw: Option<String> = read_option(db, key).await;
        let Some(raw) = raw else { continue };
        match sink {
            0 => {
                if let Some(value) = parse_go_bool(&raw) {
                    config.enabled = value;
                }
            }
            1 => config.cpu_threshold = parse_go_int_keep(&raw, config.cpu_threshold),
            2 => config.memory_threshold = parse_go_int_keep(&raw, config.memory_threshold),
            _ => config.disk_threshold = parse_go_int_keep(&raw, config.disk_threshold),
        }
    }
    config
}

/// `SELECT value FROM options` for one key; read errors behave like a missing
/// row (the callers' fail-open contracts).
async fn read_option(db: &newapi_storage::Database, key: &str) -> Option<String> {
    match db {
        newapi_storage::Database::Sqlite(pool) => {
            sqlx::query_scalar::<_, String>("SELECT value FROM options WHERE \"key\" = ?")
                .bind(key)
                .fetch_optional(pool)
                .await
                .ok()
                .flatten()
        }
        newapi_storage::Database::Postgres(pool) => {
            sqlx::query_scalar::<_, String>("SELECT value FROM options WHERE \"key\" = $1")
                .bind(key)
                .fetch_optional(pool)
                .await
                .ok()
                .flatten()
        }
    }
}

/// Go `strconv.ParseBool`'s accepted spellings (no trimming — Go parses the
/// raw option value).
fn parse_go_bool(value: &str) -> Option<bool> {
    match value {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

/// Go `strconv.Atoi` with the settings-registry keep-current policy: a failed
/// parse leaves the previous value untouched.
fn parse_go_int_keep(value: &str, current: i64) -> i64 {
    value.parse().unwrap_or(current)
}

/// Go `checkSystemPerformance` (check_performance.go:41-71): the first
/// strictly-above-zero-threshold breach wins, message and 503 status
/// verbatim. The code is Go `types.NewErrorWithStatusCode(err, code, 503)`'s
/// error code; the envelope type is the default-branch `"new_api_error"`
/// (`relaykit/types/error.go:207-213,238-242`). MaskSensitiveInfo is identity
/// for messages without URLs or tokens.
fn check_system_performance(
    config: PerformanceMonitorConfig,
    status: SystemStatus,
) -> Option<(&'static str, String)> {
    if !config.enabled {
        return None;
    }
    if config.cpu_threshold > 0 && status.cpu_usage as i64 > config.cpu_threshold {
        return Some((
            "system_cpu_overloaded",
            format!(
                "system cpu overloaded (current: {:.1}%, threshold: {}%)",
                status.cpu_usage, config.cpu_threshold
            ),
        ));
    }
    if config.memory_threshold > 0 && status.memory_usage as i64 > config.memory_threshold {
        return Some((
            "system_memory_overloaded",
            format!(
                "system memory overloaded (current: {:.1}%, threshold: {}%)",
                status.memory_usage, config.memory_threshold
            ),
        ));
    }
    if config.disk_threshold > 0 && status.disk_usage as i64 > config.disk_threshold {
        return Some((
            "system_disk_overloaded",
            format!(
                "system disk overloaded (current: {:.1}%, threshold: {}%)",
                status.disk_usage, config.disk_threshold
            ),
        ));
    }
    None
}

/// Go `SystemPerformanceCheck` (check_performance.go:14-38). Only the path
/// prefix selects the envelope shape: `/v1/messages*` speaks Claude, everything
/// else OpenAI. Both abort with the JSON error body and no further chain.
pub async fn system_performance_check(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let Some(db) = state.db() else {
        // Test path without a database: Go's in-memory config defaults apply
        // and the zero status passes every threshold.
        return next.run(request).await;
    };
    let config = load_performance_monitor_config(&db).await;
    let status = state.system_status_source().status();
    let Some((code, message)) = check_system_performance(config, status) else {
        return next.run(request).await;
    };
    let request_id = RequestId::from_request(&request);
    let message = message_with_request_id(&message, &request_id);
    // ToOpenAIError default branch (error.go:207-213):
    //   {message, type: "new_api_error", param: "", code: <error code>}
    // ToClaudeError default branch (error.go:238-242):
    //   {type: "new_api_error", message}
    let body = if request.uri().path().starts_with("/v1/messages") {
        json!({ "error": { "type": "new_api_error", "message": message } })
    } else {
        json!({
            "error": {
                "message": message,
                "type": "new_api_error",
                "param": "",
                "code": code,
            }
        })
    };
    (StatusCode::SERVICE_UNAVAILABLE, Json(body)).into_response()
}

// ---------------------------------------------------------------------------
// GeoBlock (geo_block.go + geoip/geoip.go)
// ---------------------------------------------------------------------------

/// Go `GeoBlockSetting` (`geoip/geoip.go:20-33`); defaults
/// (`geoip.go:35-39`): disabled, allow admin, blocking `CN`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeoBlockSetting {
    pub enabled: bool,
    pub allow_admin: bool,
    pub blocked_countries: Vec<String>,
}

impl Default for GeoBlockSetting {
    fn default() -> Self {
        Self {
            enabled: false,
            allow_admin: true,
            blocked_countries: vec!["CN".to_owned()],
        }
    }
}

impl GeoBlockSetting {
    /// Go `NormalizedBlockedCountries` (geoip.go:52-67): upper-cased, blank
    /// entries dropped, de-duplicated. Go trims each code before the blank
    /// test (`strings.ToUpper(strings.TrimSpace(code))`).
    pub fn normalized_blocked_countries(&self) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for code in &self.blocked_countries {
            let code = code.trim().to_uppercase();
            if code.is_empty() || !seen.insert(code.clone()) {
                continue;
            }
            out.push(code);
        }
        out
    }

    /// Go `BlocksCountry` (geoip.go:189-199): an empty country never blocks.
    pub fn blocks_country(&self, country: &str) -> bool {
        if country.is_empty() {
            return false;
        }
        self.normalized_blocked_countries()
            .iter()
            .any(|c| c == country)
    }
}

/// Option keys of the registered `geo_block_setting` (json tags).
pub const GEO_ENABLED_OPTION: &str = "geo_block_setting.enabled";
pub const GEO_ALLOW_ADMIN_OPTION: &str = "geo_block_setting.allow_admin";
pub const GEO_BLOCKED_COUNTRIES_OPTION: &str = "geo_block_setting.blocked_countries";

/// Loads the geo-block setting with the settings-registry semantics
/// (`updateConfigFromMap`: bool via `strconv.ParseBool`, failure keeps the
/// current value; list parse failure likewise). Missing rows keep the Go
/// struct defaults.
pub async fn load_geo_block_setting(db: &newapi_storage::Database) -> GeoBlockSetting {
    let mut setting = GeoBlockSetting::default();
    for (key, sink) in [
        (GEO_ENABLED_OPTION, 0usize),
        (GEO_ALLOW_ADMIN_OPTION, 1),
        (GEO_BLOCKED_COUNTRIES_OPTION, 2),
    ] {
        let Some(raw) = read_option(db, key).await else {
            continue;
        };
        match sink {
            0 => {
                if let Some(value) = parse_go_bool(&raw) {
                    setting.enabled = value;
                }
            }
            1 => {
                if let Some(value) = parse_go_bool(&raw) {
                    setting.allow_admin = value;
                }
            }
            _ => {
                if let Ok(list) = serde_json::from_str::<Vec<String>>(&raw) {
                    setting.blocked_countries = list;
                }
            }
        }
    }
    setting
}

/// Port for Go `geoCountryLookup` (`geo_block.go:22`, the test seam) backed in
/// production by `geoip.LookupCountry`. The production default mirrors Go's
/// deployment without `GEOIP_DB_PATH`: `EnsureReader` returns nil and
/// `LookupCountry` returns "" (fail-open, `geoip.go:139-146` and its test
/// `TestLookupCountryFailsOpenWhenManagedFileMissing`).
pub trait GeoCountryLookup: Send + Sync {
    fn lookup_country(&self, ip: &str) -> String;
}

/// Go `geoip.LookupCountry` with no database available: every IP resolves to
/// "" so the gate passes everything.
pub struct NoDatabaseCountryLookup;

impl GeoCountryLookup for NoDatabaseCountryLookup {
    fn lookup_country(&self, _ip: &str) -> String {
        String::new()
    }
}

/// Port for Go `security.GeoGateRole` (`authenticate.go:146-152`): resolve the
/// `Authorization` credential to the user's role, `-1` when unmatched. The
/// production default returns -1 for every header, matching a deployment where
/// no dashboard credential can be classified; the real credential resolver
/// (session + PAT paths) is owned by the identity/auth integration.
pub trait GeoGateRoleResolver: Send + Sync {
    fn role(&self, authorization: &str) -> i64;
}

/// Default: no credential ever classifies (`dashboardCredentialUnmatched`).
pub struct UnmatchedGeoGateRole;

impl GeoGateRoleResolver for UnmatchedGeoGateRole {
    fn role(&self, _authorization: &str) -> i64 {
        -1
    }
}

/// Go `common.RoleAdminUser` (`common/constants.go`).
pub const ROLE_ADMIN_USER: i64 = 10;

/// Go shell exemptions (geo_block.go:33-47), verbatim.
const GEO_GATE_SHELL_PREFIXES: [&str; 4] =
    ["/assets/", "/favicon", "/api/user/login", "/api/oauth"];
const GEO_GATE_SHELL_EXACT_PATHS: [&str; 3] = ["/404", "/sign-in", "/api/status"];
const GEO_GATE_API_PREFIXES: [&str; 4] = ["/api", "/mj", "/pg", "/v1"];

/// Go `geoGateShellAllowed` (geo_block.go:119-129).
pub fn geo_gate_shell_allowed(path: &str) -> bool {
    GEO_GATE_SHELL_EXACT_PATHS.contains(&path)
        || GEO_GATE_SHELL_PREFIXES.iter().any(|p| path.starts_with(p))
}

/// Go `geoGateAPIPath` (geo_block.go:200-207).
pub fn geo_gate_api_path(path: &str) -> bool {
    GEO_GATE_API_PREFIXES.iter().any(|p| path.starts_with(p))
}

/// Go `geoGateVerdictTTL` (geo_block.go:58): one minute.
const GEO_GATE_VERDICT_TTL_SECS: i64 = 60;
/// Go verdict-cache cap (geo_block.go:158,166): 4096 entries.
const GEO_GATE_CACHE_CAPACITY: usize = 4096;

type GeoGateCacheEntry = (bool, i64);

static GEO_GATE_CACHE: Mutex<Option<HashMap<String, GeoGateCacheEntry>>> = Mutex::new(None);

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

fn sha256_hex(bytes: &[u8]) -> String {
    use ring::digest;
    let digest = digest::digest(&digest::SHA256, bytes);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(digest.as_ref().len() * 2);
    for byte in digest.as_ref() {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Go `geoGateAdminCredential` (geo_block.go:133-173): hash the credential,
/// reuse a fresh verdict, otherwise resolve and store with Go's overflow
/// handling (drop expired entries first; full reset only while everything is
/// fresh). The lock never spans an await: Go's resolution is a blocking store
/// read too, so the injected resolver is sync.
fn geo_gate_admin_credential(credential: &str, resolver: &dyn GeoGateRoleResolver) -> bool {
    if credential.is_empty() {
        return false;
    }
    // The cache key is the credential hash, never the credential itself.
    let key = sha256_hex(credential.as_bytes());
    let now = now_unix();
    let cached = {
        let mut guard = GEO_GATE_CACHE.lock().expect("geo gate cache lock");
        let cache = guard.get_or_insert_with(HashMap::new);
        match cache.get(&key) {
            Some(&(allowed, at)) if now - at < GEO_GATE_VERDICT_TTL_SECS => Some(allowed),
            _ => None,
        }
    };
    if let Some(allowed) = cached {
        return allowed;
    }
    let allowed = resolver.role(credential) >= ROLE_ADMIN_USER;
    let mut guard = GEO_GATE_CACHE.lock().expect("geo gate cache lock");
    let cache = guard.get_or_insert_with(HashMap::new);
    if cache.len() > GEO_GATE_CACHE_CAPACITY {
        cache.retain(|_, &mut (_, at)| now - at < GEO_GATE_VERDICT_TTL_SECS);
    }
    if cache.len() > GEO_GATE_CACHE_CAPACITY {
        cache.clear();
        cache.insert(key, (allowed, now));
    } else {
        cache.insert(key, (allowed, now));
    }
    allowed
}

/// Go `GeoBlock` (geo_block.go:85-115). Mounted engine-level before every
/// route. Disabled → pass; country unknown / not blocked → pass; shell paths →
/// pass; admin credentials (when allowed) → pass; otherwise the "invisible"
/// rejection: 404 JSON for API prefixes, 302 `/404` for web pages.
pub async fn geo_block(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let Some(db) = state.db() else {
        // Test path without a database: Go's struct default has Enabled=false,
        // so the pass-through branch is the faithful behaviour.
        return next.run(request).await;
    };
    let setting = load_geo_block_setting(&db).await;
    if !setting.enabled {
        return next.run(request).await;
    }
    let client_ip = client_ip_of(&state, &request);
    let lookup = state.geo_country_lookup();
    let country = lookup.lookup_country(&client_ip);
    if !setting.blocks_country(&country) {
        return next.run(request).await;
    }
    let path = request.uri().path().to_owned();
    if geo_gate_shell_allowed(&path) {
        return next.run(request).await;
    }
    if setting.allow_admin {
        let authorization = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let resolver = state.geo_gate_role_resolver();
        if geo_gate_admin_credential(&authorization, resolver.as_ref()) {
            return next.run(request).await;
        }
    }
    // Go `rejectGeoBlocked` (geo_block.go:177-196): the audit log keeps the
    // real reason; the visitor only sees a missing page.
    tracing::warn!(
        event = "geo_block_rejected",
        client_ip = client_ip,
        path = path,
        method = request.method().as_str(),
        "geo block rejected"
    );
    if geo_gate_api_path(&path) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "success": false, "message": "page not found" })),
        )
            .into_response();
    }
    // Go c.Redirect(http.StatusFound, "/404"): the SPA 404 route. This port
    // ships no SPA, so the redirect target itself falls through to the JSON
    // fallback; the header contract (Location + 302) is identical.
    (StatusCode::FOUND, [("location", "/404")]).into_response()
}

fn client_ip_of(state: &AppState, request: &Request) -> String {
    let peer = request
        .extensions()
        .get::<std::net::SocketAddr>()
        .map(|addr| addr.ip());
    let forwarded = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok());
    let real = request
        .headers()
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok());
    state.client_ip(peer, forwarded, real)
}

// ---------------------------------------------------------------------------
// Cache (cache_response.go)
// ---------------------------------------------------------------------------

/// Go `hashContentVersion` (cache_response.go:22), verbatim.
pub const HASH_CONTENT_VERSION: &str =
    "b688f2fb5be447c25e5aa3bd063087a83db32a288bf6a4f35f2d8db310e40b14";

/// Go `cacheDirectives` (cache_response.go:13-18) + the root-path branch
/// (`cache_response.go:37-39`) + the one-week default
/// (`defaultDirective`, cache_response.go:26).
pub fn cache_directive(request_uri: &str) -> &'static str {
    if request_uri == "/" {
        "no-cache"
    } else if request_uri.starts_with("/static/") {
        "public, max-age=31536000, immutable"
    } else {
        "max-age=604800"
    }
}

/// Go `Cache` (cache_response.go:28-52) as a pure decision: the
/// `Cache-Control` directive plus the fixed `Cache-Version` stamp.
///
/// Wiring note: Go mounts this on the web router (`register_web.go:16`) that
/// serves the SPA bundle. This port has no static-asset router yet, so the
/// contract is exercised through unit tests and awaits the web slice; the
/// decision itself is byte-identical.
pub fn cache_headers_for(request_uri: &str) -> [(&'static str, &'static str); 2] {
    [
        ("Cache-Control", cache_directive(request_uri)),
        ("Cache-Version", HASH_CONTENT_VERSION),
    ]
}

// ---------------------------------------------------------------------------
// UserInsight (collect_user_insight.go)
// ---------------------------------------------------------------------------

/// Go `insightScanLimit` (collect_user_insight.go:17): 64 KiB body prefix.
pub const INSIGHT_SCAN_LIMIT: usize = 64 * 1024;

/// Go `usage.GetUserInsightSetting()` switches; option keys follow the
/// registered `user_insight_setting` json tags.
pub const USER_INSIGHT_ENABLED_OPTION: &str = "user_insight_setting.enabled";
pub const USER_INSIGHT_GENDER_INFERENCE_OPTION: &str =
    "user_insight_setting.gender_inference_enabled";
pub const USER_INSIGHT_SAMPLE_ENABLED_OPTION: &str = "user_insight_setting.sample_enabled";
pub const USER_INSIGHT_SAMPLE_KEEP_BODY_OPTION: &str = "user_insight_setting.sample_keep_body";

/// Go `insight.Options` subset the middleware passes down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InsightOptions {
    pub gender_inference: bool,
}

/// Port for Go `insight.Analyze` + `Result` (`usage/insight` package). The
/// analyzer domain is owned by the usage slice; this port fixes the
/// middleware-side contract: headers (lower-cased, first value wins like Go's
/// header copy), the body prefix, the request path, the options, and the
/// raw-body retention switch (`result.SetRawBody`).
pub trait InsightAnalyzer: Send + Sync {
    fn analyze(
        &self,
        headers: &HashMap<String, String>,
        body_prefix: &[u8],
        path: &str,
        options: InsightOptions,
    ) -> Option<Value>;
}

/// Go `UserInsight` (collect_user_insight.go:22-33): setting disabled → pass;
/// analysis failure never blocks. `SetRawBody` retention applies only when
/// both sample switches are on (collect_user_insight.go:43-45).
pub async fn user_insight(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let Some(db) = state.db() else {
        return next.run(request).await;
    };
    let (enabled, gender, sample, keep_body) = load_user_insight_setting(&db).await;
    if !enabled {
        return next.run(request).await;
    }
    let Some(analyzer) = state.insight_analyzer() else {
        // No analyzer bound: analysis cannot run; Go's contract is that an
        // analysis failure never blocks the request.
        return next.run(request).await;
    };
    // Go reads the body through the replayable storage so the relay pipeline
    // still sees the full request. The port buffers the body (bounded by the
    // relay chain's own 64 MiB ceiling in `relay_http`) and hands the bytes
    // back before continuing.
    let (mut parts, body) = request.into_parts();
    let bytes = match axum::body::to_bytes(body, INSIGHT_SCAN_LIMIT.max(64 * 1024 * 1024)).await {
        Ok(bytes) => bytes,
        Err(_) => {
            // Go logs a warning and analyses an empty prefix; the body read
            // error itself surfaces later in the pipeline.
            let request = Request::from_parts(parts, axum::body::Body::empty());
            return next.run(request).await;
        }
    };
    let prefix = &bytes[..bytes.len().min(INSIGHT_SCAN_LIMIT)];
    let headers: HashMap<String, String> = parts
        .headers
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|v| (k.as_str().to_lowercase(), v.to_owned()))
        })
        .collect();
    let path = parts.uri.path().to_owned();
    let _ = request_id;
    if let Some(mut result) = analyzer.analyze(
        &headers,
        prefix,
        &path,
        InsightOptions {
            gender_inference: gender,
        },
    ) {
        if sample && keep_body {
            // Go `result.SetRawBody(body)` keeps only the scanned prefix.
            if let Some(object) = result.as_object_mut() {
                object.insert(
                    "raw_body".to_owned(),
                    String::from_utf8_lossy(prefix).into_owned().into(),
                );
            }
        }
        parts.extensions.insert(InsightAnalysis(result));
    }
    let request = Request::from_parts(parts, axum::body::Body::from(bytes));
    next.run(request).await
}

/// Extension carrying the Go `constant.ContextKeyUserInsight` value.
#[derive(Clone, Debug)]
pub struct InsightAnalysis(pub Value);

/// Loads the four insight switches with ParseBool keep-current semantics.
/// Process defaults (`usage/user_insight_setting.go:59-77`): enabled,
/// gender inference and sampling are **true**; only `sample_keep_body`
/// defaults to false.
async fn load_user_insight_setting(db: &newapi_storage::Database) -> (bool, bool, bool, bool) {
    let mut switches = [true, true, true, false];
    for (key, sink) in [
        (USER_INSIGHT_ENABLED_OPTION, 0usize),
        (USER_INSIGHT_GENDER_INFERENCE_OPTION, 1),
        (USER_INSIGHT_SAMPLE_ENABLED_OPTION, 2),
        (USER_INSIGHT_SAMPLE_KEEP_BODY_OPTION, 3),
    ] {
        let Some(raw) = read_option(db, key).await else {
            continue;
        };
        if let Some(value) = parse_go_bool(&raw) {
            switches[sink] = value;
        }
    }
    (switches[0], switches[1], switches[2], switches[3])
}

// ---------------------------------------------------------------------------
// Jimeng / Kling request conversion (convert_jimeng.go / convert_kling.go)
// ---------------------------------------------------------------------------

/// Outcome of Go `JimengRequestConvert` / `KlingRequestConvert`'s request
/// rewrite: the unified body, the rewritten path, the `action` context value
/// and (Jimeng only) the fetch-by-id task id + relay mode + method.
#[derive(Clone, Debug, PartialEq)]
pub struct TaskConversion {
    /// Go `c.ReplaceBody(jsonData)` + `c.Set(common.KeyRequestBody, jsonData)`.
    pub body: Vec<u8>,
    /// Go `c.SetPath(...)`.
    pub path: String,
    /// Go `c.Set("action", constant.TaskActionTextGenerate)` — set only when
    /// the original request carries no image.
    pub action_text_generate: bool,
    /// Go `c.Set("task_id", ...)` (Jimeng fetch-by-id only).
    pub task_id: Option<String>,
    /// Go `c.Set("relay_mode", relayconstant.RelayModeVideoFetchByID)`.
    pub relay_mode_video_fetch_by_id: bool,
    /// Go `c.SetMethod(http.MethodGet)` (Jimeng fetch-by-id only).
    pub method_get: bool,
}

/// Go `constant.TaskActionTextGenerate` (`constant/task.go:15`).
pub const TASK_ACTION_TEXT_GENERATE: &str = "textGenerate";

/// Go `common.KeyRequestBody` (`common/gin.go:19`).
pub const KEY_REQUEST_BODY: &str = "key_request_body";

/// Go `relayconstant.RelayModeVideoFetchByID`
/// (`relay/constant/relay_mode.go`).
pub const RELAY_MODE_VIDEO_FETCH_BY_ID: i32 = 30;

/// The first image value Go's `image == ""` test treats as absent.
fn image_present(object: &serde_json::Map<String, Value>) -> bool {
    match object.get("image") {
        None => false,
        Some(Value::Null) => false,
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

/// Go `KlingRequestConvert` (convert_kling.go:10-48): an unparseable body
/// (including non-object JSON, which fails Go's unmarshal into
/// `map[string]interface{}`) or a marshal failure silently continues the
/// chain (`c.Next()` in both error arms), so those map to `None`.
pub fn kling_convert(body: &[u8]) -> Option<TaskConversion> {
    let original: Value = serde_json::from_slice(body).ok()?;
    let object = original.as_object()?;
    let model = object
        .get("model_name")
        .and_then(|v| v.as_str())
        .filter(|v| !v.is_empty())
        .or_else(|| object.get("model").and_then(|v| v.as_str()))
        .unwrap_or_default()
        .to_owned();
    let prompt = object
        .get("prompt")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();
    let unified = json!({ "model": model, "prompt": prompt, "metadata": original });
    Some(TaskConversion {
        body: serde_json::to_vec(&unified).ok()?,
        path: "/v1/video/generations".to_owned(),
        action_text_generate: !image_present(object),
        task_id: None,
        relay_mode_video_fetch_by_id: false,
        method_get: false,
    })
}

/// Go `JimengRequestConvert` (convert_jimeng.go:12-63) rewrite core.
/// `Err` carries Go's abort-with-OpenAI-envelope cases that arise after the
/// body parsed (fetch-by-id without a task id → 400).
fn jimeng_rewrite(
    object: &serde_json::Map<String, Value>,
    action: &str,
) -> Result<TaskConversion, &'static str> {
    let model = object
        .get("req_key")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();
    let prompt = object
        .get("prompt")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();
    let unified =
        json!({ "model": model, "prompt": prompt, "metadata": Value::Object(object.clone()) });
    let mut conversion = TaskConversion {
        body: serde_json::to_vec(&unified).map_err(|_| "Failed to marshal request body")?,
        path: "/v1/video/generations".to_owned(),
        action_text_generate: !image_present(object),
        task_id: None,
        relay_mode_video_fetch_by_id: false,
        method_get: false,
    };
    if action == "CVSync2AsyncGetResult" {
        let task_id = object
            .get("task_id")
            .and_then(|v| v.as_str())
            .filter(|v| !v.is_empty())
            .ok_or("task_id is required for CVSync2AsyncGetResult")?;
        conversion.path = format!("/v1/video/generations/{task_id}");
        conversion.task_id = Some(task_id.to_owned());
        conversion.relay_mode_video_fetch_by_id = true;
        conversion.method_get = true;
    }
    Ok(conversion)
}

/// Extracts a percent-decoded query parameter (Go `c.Query(name)` on the
/// Fiber adapter decodes the value).
fn query_param(query: &str, name: &str) -> Option<String> {
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=')?;
        if key != name {
            continue;
        }
        return Some(percent_decode(value));
    }
    None
}

/// Minimal `%XX` and `+` decoding (Fiber's `c.Query` decodes both).
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = bytes
                    .get(i + 1..i + 3)
                    .and_then(|h| std::str::from_utf8(h).ok())
                    .and_then(|s| u8::from_str_radix(s, 16).ok());
                match hex {
                    Some(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    None => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Async wrapper of Go `JimengRequestConvert` (convert_jimeng.go:12-63):
/// missing `Action` → 400, unparseable body → 400, marshal failure → 500,
/// fetch-by-id without task id → 400; the successful rewrite replaces the
/// body, exposes it through [`TaskConversionExtension`], and rewrites the
/// path/method via the extension (route-level path rewriting awaits the
/// video-task slice's entry handler).
pub async fn jimeng_request_convert(request: Request, next: Next) -> Response {
    let query = request.uri().query().unwrap_or("").to_owned();
    let request_id = RequestId::from_request(&request);
    let Some(action) = query_param(&query, "Action").filter(|a| !a.is_empty()) else {
        return crate::relay_http::abort_with_openai_message(
            StatusCode::BAD_REQUEST,
            "Action query parameter is required",
            "",
            &request_id,
        );
    };
    let (parts, body) = request.into_parts();
    let bytes = match axum::body::to_bytes(body, 64 * 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return crate::relay_http::abort_with_openai_message(
                StatusCode::BAD_REQUEST,
                "Invalid request body",
                "",
                &request_id,
            );
        }
    };
    // Go unmarshals into map[string]interface{}; non-object JSON fails here.
    let Ok(Value::Object(object)) = serde_json::from_slice::<Value>(&bytes) else {
        return crate::relay_http::abort_with_openai_message(
            StatusCode::BAD_REQUEST,
            "Invalid request body",
            "",
            &request_id,
        );
    };
    let conversion = match jimeng_rewrite(&object, &action) {
        Ok(conversion) => conversion,
        Err(message) => {
            let status = if message == "Failed to marshal request body" {
                StatusCode::INTERNAL_SERVER_ERROR
            } else {
                StatusCode::BAD_REQUEST
            };
            return crate::relay_http::abort_with_openai_message(status, message, "", &request_id);
        }
    };
    let mut request = Request::from_parts(parts, axum::body::Body::from(conversion.body.clone()));
    request
        .extensions_mut()
        .insert(TaskConversionExtension(conversion));
    next.run(request).await
}

/// Extension carrying the rewrite for the relay-task slice downstream.
#[derive(Clone, Debug)]
pub struct TaskConversionExtension(pub TaskConversion);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_id_has_go_shape() {
        let id = new_request_id();
        // GetTimeString is 23 chars (14 + 9), plus two 8-char random runs.
        assert_eq!(id.len(), 23 + 8 + 8, "unexpected id length: {id}");
        assert!(
            id.chars().take(23).all(|c| c.is_ascii_digit()),
            "time prefix must be numeric: {id}"
        );
        assert!(
            id[23..].chars().all(|c| c.is_ascii_alphanumeric()),
            "random segments must be alphanumeric: {}",
            &id[23..]
        );
        assert_ne!(id, new_request_id(), "ids must differ");
    }

    #[test]
    fn civil_from_days_matches_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        assert_eq!(civil_from_days(20_771), (2026, 11, 14));
    }

    #[test]
    fn message_with_request_id_matches_go() {
        assert_eq!(message_with_request_id("boom", ""), "boom");
        assert_eq!(
            message_with_request_id("boom", "id-1"),
            "boom (request id: id-1)"
        );
    }

    #[test]
    fn performance_thresholds_use_go_defaults_and_zero_gate() {
        let config = PERFORMANCE_MONITOR_DEFAULT;
        assert!(config.enabled);
        assert_eq!(
            (
                config.cpu_threshold,
                config.memory_threshold,
                config.disk_threshold
            ),
            (90, 90, 95)
        );
        let zero = SystemStatus {
            cpu_usage: 0.0,
            memory_usage: 0.0,
            disk_usage: 0.0,
        };
        assert_eq!(check_system_performance(config, zero), None);
        // Go's `int(status.CPUUsage)` truncates: 90.5 becomes 90 and does
        // not trip the strictly-greater comparison.
        let cpu = SystemStatus {
            cpu_usage: 90.5,
            memory_usage: 0.0,
            disk_usage: 0.0,
        };
        assert_eq!(check_system_performance(config, cpu), None);
        let cpu = SystemStatus {
            cpu_usage: 91.0,
            memory_usage: 0.0,
            disk_usage: 0.0,
        };
        assert_eq!(
            check_system_performance(config, cpu),
            Some((
                "system_cpu_overloaded",
                "system cpu overloaded (current: 91.0%, threshold: 90%)".to_owned()
            ))
        );
        let boundary = SystemStatus {
            cpu_usage: 90.0,
            memory_usage: 0.0,
            disk_usage: 0.0,
        };
        assert_eq!(check_system_performance(config, boundary), None);
        let disabled = PerformanceMonitorConfig {
            enabled: false,
            ..config
        };
        let all = SystemStatus {
            cpu_usage: 99.9,
            memory_usage: 99.9,
            disk_usage: 99.9,
        };
        assert_eq!(check_system_performance(disabled, all), None);
    }

    #[test]
    fn parse_go_bool_matches_strconv_parse_bool() {
        for value in ["1", "t", "T", "TRUE", "true", "True"] {
            assert_eq!(parse_go_bool(value), Some(true), "{value}");
        }
        for value in ["0", "f", "F", "FALSE", "false", "False"] {
            assert_eq!(parse_go_bool(value), Some(false), "{value}");
        }
        assert_eq!(parse_go_bool("yes"), None);
        assert_eq!(parse_go_bool(""), None);
        // ParseBool does not trim: whitespace fails.
        assert_eq!(parse_go_bool(" true "), None);
    }

    #[test]
    fn geo_shell_and_api_paths_match_go_tables() {
        for path in ["/404", "/sign-in", "/api/status"] {
            assert!(geo_gate_shell_allowed(path), "{path}");
        }
        for prefix_path in [
            "/assets/app.js",
            "/favicon.ico",
            "/api/user/login",
            "/api/user/login/2fa",
            "/api/oauth/state",
            "/api/oauth/github",
        ] {
            assert!(geo_gate_shell_allowed(prefix_path), "{prefix_path}");
        }
        // Exact-match discipline: /api/status/test stays blocked.
        assert!(!geo_gate_shell_allowed("/api/status/test"));
        for path in [
            "/api/status/test",
            "/v1/chat/completions",
            "/mj/submit/imagine",
            "/pg/chat/completions",
        ] {
            assert!(geo_gate_api_path(path), "{path}");
        }
        assert!(!geo_gate_api_path("/console/home"));
    }

    #[test]
    fn geo_block_setting_normalises_and_blocks() {
        let mut setting = GeoBlockSetting::default();
        assert!(setting.blocks_country("CN"));
        // Go's BlocksCountry compares verbatim; the upper-casing happens in
        // geoip.LookupCountry, so a lower-case country does not match.
        assert!(!setting.blocks_country("cn"));
        assert!(!setting.blocks_country(""));
        assert!(!setting.blocks_country("US"));
        setting.blocked_countries = vec![" cn ", "CN", "jp", ""]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(setting.normalized_blocked_countries(), vec!["CN", "JP"]);
    }

    #[test]
    fn geo_gate_admin_credential_caches_verdicts() {
        struct Fixed(i64);
        impl GeoGateRoleResolver for Fixed {
            fn role(&self, _a: &str) -> i64 {
                self.0
            }
        }
        let resolver = Fixed(ROLE_ADMIN_USER);
        // Unique credential per run avoids cross-test cache pollution.
        let credential = format!("Bearer admin-{}/{}", std::process::id(), now_unix());
        assert!(geo_gate_admin_credential(&credential, &resolver));
        // Cached verdict short-circuits (a changed resolver cannot flip it).
        assert!(geo_gate_admin_credential(&credential, &Fixed(-1)));
        let non_admin = format!("Bearer user-{}/{}", std::process::id(), now_unix());
        assert!(!geo_gate_admin_credential(&non_admin, &Fixed(-1)));
        assert!(!geo_gate_admin_credential("", &resolver));
    }

    #[test]
    fn cache_headers_follow_go_directive_table() {
        assert_eq!(
            cache_headers_for("/"),
            [
                ("Cache-Control", "no-cache"),
                ("Cache-Version", HASH_CONTENT_VERSION)
            ]
        );
        assert_eq!(
            cache_headers_for("/static/app.abc.js")[0].1,
            "public, max-age=31536000, immutable"
        );
        assert_eq!(cache_headers_for("/console")[0].1, "max-age=604800");
        assert_eq!(cache_headers_for("/staticx")[0].1, "max-age=604800");
    }

    #[test]
    fn kling_conversion_rewrites_body_path_and_action() {
        let body =
            br#"{"model_name":"kling-v1","prompt":"a cat","image":"data:image/png;base64,x"}"#;
        let conversion = kling_convert(body).expect("object body converts");
        assert_eq!(conversion.path, "/v1/video/generations");
        assert!(
            !conversion.action_text_generate,
            "image present keeps the original action"
        );
        let unified: Value = serde_json::from_slice(&conversion.body).unwrap();
        assert_eq!(unified["model"], "kling-v1");
        assert_eq!(unified["prompt"], "a cat");
        assert_eq!(unified["metadata"]["model_name"], "kling-v1");

        // No image → textGenerate action; model_name wins over model.
        let text = br#"{"model":"fallback","model_name":"kling-v1","prompt":"p"}"#;
        let conversion = kling_convert(text).unwrap();
        assert!(conversion.action_text_generate);
        assert_eq!(TASK_ACTION_TEXT_GENERATE, "textGenerate");
        let unified: Value = serde_json::from_slice(&conversion.body).unwrap();
        assert_eq!(unified["model"], "kling-v1");

        // Parse failure → Go's silent c.Next().
        assert!(kling_convert(b"not json").is_none());
        // Non-object JSON is Go's unmarshal-into-map error → None.
        assert!(kling_convert(b"[1,2]").is_none());
    }

    #[test]
    fn jimeng_rewrite_maps_submit_and_fetch() {
        let body: Value =
            serde_json::from_slice(br#"{"req_key":"jimeng-vgfm-l16","prompt":"cat","image":"x"}"#)
                .unwrap();
        let conversion =
            jimeng_rewrite(body.as_object().unwrap(), "CVSync2AsyncSubmitTask").unwrap();
        assert_eq!(conversion.path, "/v1/video/generations");
        assert!(!conversion.method_get);
        assert!(!conversion.action_text_generate);
        assert_eq!(KEY_REQUEST_BODY, "key_request_body");
        assert_eq!(RELAY_MODE_VIDEO_FETCH_BY_ID, 30);

        let text: Value = serde_json::from_slice(br#"{"req_key":"m","prompt":"p"}"#).unwrap();
        let conversion =
            jimeng_rewrite(text.as_object().unwrap(), "CVSync2AsyncSubmitTask").unwrap();
        assert!(conversion.action_text_generate);

        let fetch: Value =
            serde_json::from_slice(br#"{"req_key":"m","prompt":"p","task_id":"t-42"}"#).unwrap();
        let conversion =
            jimeng_rewrite(fetch.as_object().unwrap(), "CVSync2AsyncGetResult").unwrap();
        assert_eq!(conversion.path, "/v1/video/generations/t-42");
        assert!(conversion.method_get);
        assert_eq!(conversion.task_id.as_deref(), Some("t-42"));
        assert!(conversion.relay_mode_video_fetch_by_id);

        // Fetch without task id aborts 400 in Go.
        let missing: Value = serde_json::from_slice(br#"{"req_key":"m"}"#).unwrap();
        let message =
            jimeng_rewrite(missing.as_object().unwrap(), "CVSync2AsyncGetResult").unwrap_err();
        assert_eq!(message, "task_id is required for CVSync2AsyncGetResult");
    }

    #[test]
    fn query_param_decodes_like_fiber() {
        assert_eq!(
            query_param("Action=CVSync2AsyncSubmitTask&Version=2022-08-31", "Action"),
            Some("CVSync2AsyncSubmitTask".to_owned())
        );
        assert_eq!(query_param("a=b", "Action"), None);
        assert_eq!(
            query_param("Action=CV%20Sync", "Action"),
            Some("CV Sync".to_owned())
        );
        assert_eq!(query_param("Action=", "Action"), Some(String::new()));
    }
}
